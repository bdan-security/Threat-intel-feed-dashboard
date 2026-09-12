import feedparser
import sqlite3
import re
import json
from bs4 import BeautifulSoup

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
    "Cyber Defense Magazine": "https://www.cyberdefensemagazine.com/feed/",
    "Cybercrime Magazine": "https://cybersecurityventures.com/feed/",
    
    # Expert Blogs & Independent Researchers
    "Krebs on Security": "https://krebsonsecurity.com/feed/",
    "Schneier on Security": "https://www.schneier.com/feed/atom/",
    "Troy Hunt": "https://www.troyhunt.com/rss/",
    "Graham Cluley": "https://grahamcluley.com/feed/",
    
    # Deep Tech & Vulnerability Tracking
    "CISA Cybersecurity Advisories": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "SANS Internet Storm Center": "https://isc.sans.edu/rssfeed_full.xml",
    "Ars Technica Security": "https://feeds.arstechnica.com/arstechnica/security",
}

# ==========================================
# 2. IOC REGEX PATTERNS & DEFENSE PLAYBOOKS
# ==========================================
IOC_PATTERNS = {
    "ipv4": r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
    "sha256": r'\b[A-Fa-f0-9]{64}\b',
    "md5": r'\b[A-Fa-f0-9]{32}\b',
    "cve": r'CVE-\d{4}-\d{4,7}'
}

THREAT_MATRIX = {
    "ransomware": {
        "keywords": ["ransomware", "encrypt", "extortion", "lockbit", "blackcat"],
        "playbook": "1. Isolate infected subnets. 2. Verify immutable backups. 3. Block associated IP/Hashes at the firewall/EDR. 4. Disable SMBv1 across the network."
    },
    "authentication_attack": {
        "keywords": ["authentication", "brute-force", "credential stuffing", "mfa bypass", "password spray"],
        "playbook": "1. Force global password resets for affected users. 2. Enforce strict MFA policies. 3. Review Active Directory/Okta logs for anomalous login geography."
    },
    "malware": {
        "keywords": ["malware", "trojan", "infostealer", "botnet", "c2", "beacon"],
        "playbook": "1. Ingest extracted SHA256/MD5 hashes into EDR blocklist. 2. Quarantine infected endpoints. 3. Hunt for persistence mechanisms (Registry Run keys, Scheduled Tasks)."
    },
    "ddos": {
        "keywords": ["ddos", "denial of service", "botnet swarm", "amplification attack"],
        "playbook": "1. Activate WAF 'Under Attack' mode (e.g., Cloudflare). 2. Implement strict rate limiting. 3. Geo-block traffic from irrelevant countries."
    },
    "third_party": {
        "keywords": ["third-party", "supply chain", "vendor breach", "api leak", "solarwinds"],
        "playbook": "1. Revoke API keys/tokens associated with the affected vendor. 2. Suspend vendor VPN/SSO access. 3. Audit logs for lateral movement originating from vendor accounts."
    },
    "privilege_escalation": {
        "keywords": ["privilege escalation", "root", "system privileges", "local admin", "bypass"],
        "playbook": "1. Patch vulnerable software/OS immediately based on extracted CVEs. 2. Audit local administrator groups. 3. Restrict use of privileged accounts on standard workstations."
    }
}

def extract_iocs(text):
    """Uses Regex to find technical indicators and returns them as a dictionary."""
    iocs = {}
    for ioc_type, pattern in IOC_PATTERNS.items():
        matches = list(set(re.findall(pattern, text))) 
        if matches:
            iocs[ioc_type] = matches
    return iocs

def categorize_and_defend(text):
    """Maps text to threats and outputs specific playbooks."""
    text_lower = text.lower()
    detected_threats = []
    recommended_playbooks = []

    for threat_name, data in THREAT_MATRIX.items():
        if any(keyword in text_lower for keyword in data["keywords"]):
            detected_threats.append(threat_name.replace("_", " ").title())
            recommended_playbooks.append(f"🛡️ [{threat_name.upper()}] {data['playbook']}")

    return detected_threats, recommended_playbooks

# ==========================================
# 3. THE GATHERER
# ==========================================
def get_article_summary(entry):
    summary = entry.get("summary", "")
    soup = BeautifulSoup(summary, "html.parser")
    return soup.get_text().strip()

def run_news_gatherer():
    articles = []
    seen_urls = set()
    print("Fetching, extracting IoCs, and generating playbooks...\n")

    for site_name, url in FEEDS.items():
        print(f"[*] Checking {site_name}...")
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries[:5]: 
                link = entry.get("link", "")
                if link in seen_urls: continue
                seen_urls.add(link)

                title = entry.get("title", "No Title")
                date = entry.get("published", entry.get("updated", "Unknown Date"))
                summary = get_article_summary(entry)
                full_text = title + " " + summary
                
                found_iocs = extract_iocs(full_text)
                threats, playbooks = categorize_and_defend(full_text)
                
                articles.append({
                    "title": title,
                    "url": link,
                    "source": site_name,
                    "date": date,
                    "summary": summary[:500] + "..." if len(summary) > 500 else summary,
                    "iocs": json.dumps(found_iocs), 
                    "threat_tags": ",".join(threats),
                    "playbooks": "\n\n".join(playbooks)
                })
        except Exception as e:
            print(f"[!] Failed to load {site_name}: {e}")
    return articles

# ==========================================
# 4. DATABASE STORAGE
# ==========================================
def save_to_database(articles):
    if not articles: return
    
    conn = sqlite3.connect('company_defense.db')
    cursor = conn.cursor()

    # Created with an explicit date column
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            title TEXT, url TEXT UNIQUE, source TEXT, date TEXT, summary TEXT,
            iocs TEXT, threat_tags TEXT, playbooks TEXT
        )
    ''')

    new_articles = 0
    for a in articles:
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO intel 
                (title, url, source, date, summary, iocs, threat_tags, playbooks)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (a['title'], a['url'], a['source'], a['date'], a['summary'], a['iocs'], a['threat_tags'], a['playbooks']))
            if cursor.rowcount > 0:
                new_articles += 1
        except Exception: 
            pass

    conn.commit()
    conn.close()
    print(f"\n[+] Success: {new_articles} new unique items added to Database.")

if __name__ == "__main__":
    found_articles = run_news_gatherer()
    save_to_database(found_articles)