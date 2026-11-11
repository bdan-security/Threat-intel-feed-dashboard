"""
CyberScraper - threat intel gatherer.

Pulls security news from RSS feeds, extracts IoCs, tags threat categories,
scores severity and stores everything in company_defense.db (next to this file).

Usage:
    python rules_scraper.py              # fetch new articles
    python rules_scraper.py --reprocess  # re-tag every stored article with the current rules
"""

import argparse
import ipaddress
import json
import re
import sqlite3
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

import feedparser
import requests
from bs4 import BeautifulSoup

DB_PATH = Path(__file__).resolve().with_name("company_defense.db")
SCHEMA_VERSION = 2
ENTRIES_PER_FEED = 20
REQUEST_TIMEOUT = 15
USER_AGENT = "Mozilla/5.0 (compatible; CyberScraper/2.0; RSS reader)"

# ==========================================
# 1. THE NEWS SOURCES
# ==========================================
FEEDS = {
    # Breaking News & Industry Updates
    "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
    "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
    "Dark Reading": "https://www.darkreading.com/rss.xml",
    "SecurityWeek": "https://www.securityweek.com/feed/",
    "The Record by Recorded Future": "https://therecord.media/feed/",
    "CyberScoop": "https://cyberscoop.com/feed/",
    "Help Net Security": "https://www.helpnetsecurity.com/feed/",

    # For CISOs & Security Leadership
    "CSO Online": "https://www.csoonline.com/feed/",
    "SC Media": "https://www.scmagazine.com/rss",
    "InfoSecurity Magazine": "https://www.infosecurity-magazine.com/rss/news/",
    "Cybercrime Magazine": "https://cybersecurityventures.com/feed/",

    # Expert Blogs & Independent Researchers
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "Schneier on Security": "https://www.schneier.com/feed/atom/",
    "Troy Hunt": "https://www.troyhunt.com/rss/",
    "Graham Cluley": "https://grahamcluley.com/feed/",

    # Government advisories, Deep Tech & Vulnerability Tracking
    "CISA Cybersecurity Advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "NCSC UK": "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
    "SANS Internet Storm Center": "https://isc.sans.edu/rssfeed_full.xml",
    "Ars Technica Security": "https://arstechnica.com/security/feed/",
}

# ==========================================
# 2. IOC PATTERNS
# ==========================================
_HEX_EDGE = r"(?<![A-Fa-f0-9]){body}(?![A-Fa-f0-9])"
IOC_PATTERNS = {
    # (?<![vV\w.]) avoids matching version strings such as "v1.2.3.4"
    "ipv4": r"(?<![vV\w.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\w.])",
    "sha256": _HEX_EDGE.format(body=r"[A-Fa-f0-9]{64}"),
    "sha1": _HEX_EDGE.format(body=r"[A-Fa-f0-9]{40}"),
    "md5": _HEX_EDGE.format(body=r"[A-Fa-f0-9]{32}"),
    "cve": r"\bCVE-\d{4}-\d{4,7}\b",
}

# Researchers "defang" indicators so they aren't clickable: 1.2.3[.]4, hxxp://
_REFANG = [
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}"), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\bhxxp", re.I), "http"),
]


def refang(text: str) -> str:
    for pattern, repl in _REFANG:
        text = pattern.sub(repl, text)
    return text


def extract_iocs(text: str) -> dict:
    """Find technical indicators. Returns {type: [sorted unique values]}."""
    text = refang(text)
    iocs = {}
    for ioc_type, pattern in IOC_PATTERNS.items():
        flags = re.I if ioc_type == "cve" else 0
        matches = set(re.findall(pattern, text, flags))
        if ioc_type == "cve":
            matches = {m.upper() for m in matches}
        elif ioc_type == "ipv4":
            # drop private, loopback, documentation and other non-routable ranges
            matches = {m for m in matches if ipaddress.ip_address(m).is_global}
        elif ioc_type in ("md5", "sha1", "sha256"):
            # drop all-digit strings (usually IDs, not hashes)
            matches = {m.lower() for m in matches if not m.isdigit()}
        if matches:
            iocs[ioc_type] = sorted(matches)
    return iocs


# ==========================================
# 3. THREAT CATEGORIES & PLAYBOOKS
# ==========================================
# Keywords are matched as whole words/phrases (case-insensitive), so "root"
# no longer fires on "rootkit" and "c2" no longer fires on "EC2".
THREAT_MATRIX = {
    "Ransomware": {
        "icon": "🔒",
        "keywords": ["ransomware", "ransom", "extortion", "double extortion", "lockbit",
                     "blackcat", "alphv", "akira", "clop", "cl0p", "play ransomware",
                     "black basta", "medusa", "qilin", "ransomhub", "scattered spider"],
        "playbook": [
            "Isolate affected subnets and hosts.",
            "Verify immutable / offline backups are intact and restorable.",
            "Block associated IPs and hashes on the firewall and EDR.",
            "Disable SMBv1 and review exposed RDP across the estate.",
        ],
    },
    "Vulnerability": {
        "icon": "🧩",
        "keywords": ["vulnerability", "vulnerabilities", "zero-day", "zero day", "0-day",
                     "remote code execution", "rce", "patch tuesday", "security update",
                     "flaw", "exploit", "exploited", "proof-of-concept", "poc", "cvss"],
        "playbook": [
            "Check asset inventory for the affected product and version.",
            "Apply vendor patches or mitigations, prioritising internet-facing systems.",
            "If actively exploited, hunt for indicators of past compromise before patching.",
            "Track remediation against the CISA KEV deadline where listed.",
        ],
    },
    "Data Breach": {
        "icon": "💾",
        "keywords": ["data breach", "breach", "leaked", "data leak", "exposed data",
                     "stolen data", "exfiltrated", "exfiltration", "compromised data"],
        "playbook": [
            "Confirm whether the organisation or its customers appear in the breached data.",
            "Rotate credentials and API keys that may have been exposed.",
            "Increase monitoring for follow-on phishing using the leaked data.",
            "Engage legal / DPO to assess notification duties (e.g. GDPR 72h).",
        ],
    },
    "Phishing": {
        "icon": "🎣",
        "keywords": ["phishing", "spear-phishing", "spearphishing", "smishing", "vishing",
                     "business email compromise", "bec", "malicious email", "lure"],
        "playbook": [
            "Block sender domains, URLs and attachments at the email gateway.",
            "Search mailboxes for the campaign and purge delivered messages.",
            "Warn staff with an example of the lure.",
            "Reset credentials for anyone who interacted with the message.",
        ],
    },
    "Authentication Attack": {
        "icon": "🔑",
        "keywords": ["brute-force", "brute force", "credential stuffing", "mfa bypass",
                     "mfa fatigue", "password spray", "password spraying", "session hijacking",
                     "account takeover", "stolen credentials", "infostealer logs"],
        "playbook": [
            "Force password resets for affected users.",
            "Enforce phishing-resistant MFA policies.",
            "Review identity provider (Entra ID / Okta) logs for anomalous sign-in geography.",
        ],
    },
    "Malware": {
        "icon": "🦠",
        "keywords": ["malware", "trojan", "infostealer", "stealer", "botnet", "backdoor",
                     "rootkit", "loader", "c2 server", "command-and-control",
                     "command and control", "cobalt strike", "rat", "spyware", "wiper"],
        "playbook": [
            "Add extracted SHA256 / MD5 hashes to the EDR blocklist.",
            "Quarantine infected endpoints.",
            "Hunt for persistence (Registry Run keys, scheduled tasks, services).",
        ],
    },
    "Nation-State / APT": {
        "icon": "🎯",
        "keywords": ["apt group", "apt actor", "apt actors", "nation-state", "state-sponsored", "state-backed", "espionage",
                     "volt typhoon", "salt typhoon", "lazarus", "fancy bear", "cozy bear",
                     "sandworm", "kimsuky", "midnight blizzard", "apt28", "apt29"],
        "playbook": [
            "Map the group's published TTPs to MITRE ATT&CK and check detection coverage.",
            "Hunt for the reported IoCs across logs going back 90+ days.",
            "Review exposure of edge devices (VPNs, firewalls, routers) the group targets.",
        ],
    },
    "DDoS": {
        "icon": "🌊",
        "keywords": ["ddos", "denial of service", "denial-of-service",
                     "amplification attack", "hacktivist"],
        "playbook": [
            "Enable WAF / CDN 'under attack' mode.",
            "Apply strict rate limiting on public endpoints.",
            "Geo-block traffic from regions with no legitimate users.",
        ],
    },
    "Supply Chain": {
        "icon": "🔗",
        "keywords": ["third-party", "supply chain", "supply-chain", "vendor breach",
                     "malicious package", "npm package", "pypi", "solarwinds"],
        "playbook": [
            "Revoke API keys / tokens associated with the affected vendor.",
            "Suspend vendor VPN / SSO access until cleared.",
            "Audit logs for lateral movement originating from vendor accounts.",
            "Check build systems for the affected package or version.",
        ],
    },
    "Privilege Escalation": {
        "icon": "⬆️",
        "keywords": ["privilege escalation", "elevation of privilege", "local privilege",
                     "root access", "system privileges", "domain admin"],
        "playbook": [
            "Patch vulnerable software / OS based on extracted CVEs.",
            "Audit local administrator and domain admin groups.",
            "Restrict privileged accounts from standard workstations.",
        ],
    },
}

_THREAT_REGEX = {
    name: re.compile(r"\b(?:" + "|".join(re.escape(k) for k in data["keywords"]) + r")\b", re.I)
    for name, data in THREAT_MATRIX.items()
}

# Severity: first matching level wins. Medium = any threat tag; otherwise Low.
SEVERITY_LEVELS = ["Critical", "High", "Medium", "Low"]
_SEVERITY_RULES = [
    ("Critical", re.compile(
        r"\b(?:zero[- ]day|0-day|actively exploited|exploited in the wild|in-the-wild|"
        r"under active exploitation|known exploited vulnerabilit(?:y|ies)|kev|emergency patch|"
        r"emergency directive|mass exploitation|worm(?:able)?)\b", re.I)),
    ("High", re.compile(
        r"\b(?:remote code execution|rce|critical (?:vulnerability|flaw|bug)|cvss (?:score )?(?:of )?(?:9|10)|"
        r"ransomware|data breach|nation-state|state-sponsored|supply[- ]chain attack|wiper|"
        r"authentication bypass|unauthenticated)\b", re.I)),
]


def categorize(text: str) -> list:
    return [name for name, rx in _THREAT_REGEX.items() if rx.search(text)]


def score_severity(text: str, threats: list, iocs: dict) -> str:
    for level, rx in _SEVERITY_RULES:
        if rx.search(text):
            return level
    if threats or iocs.get("cve"):
        return "Medium"
    return "Low"


def playbook_text(threats: list) -> str:
    blocks = []
    for name in threats:
        steps = THREAT_MATRIX[name]["playbook"]
        blocks.append(f"[{name.upper()}]\n" + "\n".join(f"{i}. {s}" for i, s in enumerate(steps, 1)))
    return "\n\n".join(blocks)


def analyse(title: str, summary: str, extra_text: str = "") -> dict:
    """Run every enrichment step over one article's text."""
    full_text = f"{title} {summary} {extra_text}"
    iocs = extract_iocs(full_text)
    threats = categorize(full_text)
    return {
        "iocs": json.dumps(iocs),
        "threat_tags": ",".join(threats),
        "playbooks": playbook_text(threats),
        "severity": score_severity(full_text, threats, iocs),
    }


# ==========================================
# 4. THE GATHERER
# ==========================================
def html_to_text(html: str) -> str:
    text = BeautifulSoup(html or "", "html.parser").get_text(" ")
    return re.sub(r"\s+", " ", text).strip()


def shorten(text: str, limit: int = 600) -> str:
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0]
    return cut.rstrip(".,;:") + "…"


def to_iso(value) -> str | None:
    """Turn a feed date (struct_time or RFC 822 / ISO string) into ISO-8601 UTC."""
    if value is None:
        return None
    try:
        if hasattr(value, "tm_year"):
            dt = datetime(*value[:6], tzinfo=timezone.utc)
        else:
            try:
                dt = parsedate_to_datetime(value)
            except (TypeError, ValueError):
                dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat(timespec="seconds")
    except (TypeError, ValueError, OverflowError):
        return None


def fetch_feed(site_name: str, url: str, per_feed: int) -> list:
    resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()
    feed = feedparser.parse(resp.content)
    if feed.bozo and not feed.entries:
        raise ValueError(f"unreadable feed ({feed.bozo_exception})")

    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    articles = []
    for entry in feed.entries[:per_feed]:
        link = entry.get("link", "").strip()
        if not link:
            continue
        title = html_to_text(entry.get("title", "No Title"))
        summary = html_to_text(entry.get("summary", ""))
        # Some feeds ship the full article body in <content>; scan it for IoCs too.
        content = " ".join(html_to_text(c.get("value", "")) for c in entry.get("content", []))
        if not summary:
            summary = content
        raw_date = entry.get("published", entry.get("updated", ""))
        published = to_iso(entry.get("published_parsed") or entry.get("updated_parsed")) or to_iso(raw_date)

        articles.append({
            "title": title,
            "url": link,
            "source": site_name,
            "date": raw_date or "Unknown Date",
            "published_at": published or now,
            "fetched_at": now,
            "summary": shorten(summary),
            **analyse(title, summary, content),
        })
    return articles


def run_news_gatherer(per_feed: int = ENTRIES_PER_FEED, verbose: bool = True):
    """Fetch every feed in parallel. Returns (articles, failures)."""
    articles, failures, seen = [], {}, set()
    if verbose:
        print(f"Fetching {len(FEEDS)} feeds...\n")

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(fetch_feed, name, url, per_feed): name for name, url in FEEDS.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                batch = future.result()
            except Exception as e:  # network errors, HTTP errors, bad XML
                failures[name] = str(e)[:200]
                if verbose:
                    print(f"[!] {name}: {failures[name]}")
                continue
            fresh = [a for a in batch if a["url"] not in seen]
            seen.update(a["url"] for a in fresh)
            articles.extend(fresh)
            if verbose:
                print(f"[*] {name}: {len(fresh)} entries")
    return articles, failures


# ==========================================
# 5. DATABASE STORAGE
# ==========================================
COLUMNS = ["title", "url", "source", "date", "published_at", "fetched_at",
           "summary", "iocs", "threat_tags", "playbooks", "severity"]


def connect(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """Open the database, creating or upgrading the schema as needed."""
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT, url TEXT UNIQUE, source TEXT, date TEXT, summary TEXT,
            iocs TEXT, threat_tags TEXT, playbooks TEXT
        )
    """)
    existing = {row[1] for row in conn.execute("PRAGMA table_info(intel)")}
    for col in ("date", "published_at", "fetched_at", "severity"):
        if col not in existing:
            conn.execute(f"ALTER TABLE intel ADD COLUMN {col} TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_intel_published ON intel(published_at)")

    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version < SCHEMA_VERSION:
        reprocess(conn)
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    conn.commit()
    return conn


def reprocess(conn: sqlite3.Connection) -> int:
    """Re-run tagging, IoC extraction and date parsing over every stored article."""
    rows = conn.execute("SELECT id, title, summary, date, published_at FROM intel").fetchall()
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for row_id, title, summary, raw_date, published_at in rows:
        enriched = analyse(title or "", summary or "")
        conn.execute(
            "UPDATE intel SET iocs=?, threat_tags=?, playbooks=?, severity=?, published_at=?, "
            "fetched_at=COALESCE(fetched_at, ?) WHERE id=?",
            (enriched["iocs"], enriched["threat_tags"], enriched["playbooks"], enriched["severity"],
             published_at or to_iso(raw_date) or now, now, row_id),
        )
    conn.commit()
    return len(rows)


def save_to_database(articles: list, db_path: Path = DB_PATH) -> int:
    if not articles:
        return 0
    conn = connect(db_path)
    placeholders = ", ".join("?" for _ in COLUMNS)
    new_articles = 0
    try:
        for a in articles:
            cur = conn.execute(
                f"INSERT OR IGNORE INTO intel ({', '.join(COLUMNS)}) VALUES ({placeholders})",
                [a[c] for c in COLUMNS],
            )
            new_articles += cur.rowcount
        conn.commit()
    finally:
        conn.close()
    return new_articles


def run(per_feed: int = ENTRIES_PER_FEED, verbose: bool = True) -> dict:
    """Fetch, enrich and store. Used by the CLI and by the dashboard's refresh button."""
    articles, failures = run_news_gatherer(per_feed, verbose)
    new = save_to_database(articles)
    if verbose:
        print(f"\n[+] {new} new articles added ({len(articles)} fetched, {len(failures)} feeds failed).")
        print(f"    Database: {DB_PATH}")
    return {"new": new, "fetched": len(articles), "failures": failures}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gather cyber threat intel from RSS feeds.")
    parser.add_argument("--reprocess", action="store_true",
                        help="re-tag every stored article with the current rules, then exit")
    parser.add_argument("--per-feed", type=int, default=ENTRIES_PER_FEED,
                        help=f"entries to read from each feed (default {ENTRIES_PER_FEED})")
    args = parser.parse_args()

    if args.reprocess:
        with connect() as c:
            print(f"[+] Reprocessed {reprocess(c)} articles in {DB_PATH}")
    else:
        run(args.per_feed)
