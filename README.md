# CyberScraper

A lightweight threat-intelligence console. CyberScraper collects cybersecurity news from 19 RSS sources, extracts indicators of compromise, tags each article by threat category and severity, and presents everything in a Streamlit dashboard.

## Features

**Collection** (`rules_scraper.py`)
- Fetches 19 security news and advisory feeds in parallel (BleepingComputer, The Hacker News, Krebs on Security, CISA, NCSC UK, SANS ISC and more)
- Extracts IoCs: IPv4 addresses (public only), SHA256 / SHA1 / MD5 hashes and CVE IDs, including defanged indicators such as `1.2.3[.]4`
- Tags 10 threat categories (ransomware, vulnerability, data breach, phishing, malware, nation-state / APT and others) using whole-word keyword rules
- Scores severity as Critical, High, Medium or Low (for example zero-days and actively exploited flaws are Critical)
- Attaches a response playbook to each threat category
- Stores everything in a local SQLite database with de-duplication by URL

**Dashboard** (`dashboard.py`)
- 24-hour threat-posture banner and KPI tiles compared with the previous period
- Filterable intelligence feed (time window, severity, category, source, keyword / IoC search) with CSV export
- Analytics: daily volume by severity, threat categories, top sources, most-mentioned CVEs with NVD links
- Indicator explorer with CSV and plain-text blocklist export for EDR / firewall import
- **Sync now** button to fetch new articles without leaving the dashboard

## Getting started

Requires Python 3.10 or newer.

```bash
git clone https://github.com/bdan-security/Threat-intel-feed-dashboard.git
cd Threat-intel-feed-dashboard
pip install -r requirements.txt
```

Collect the first batch of articles:

```bash
python rules_scraper.py
```

Start the dashboard (run it from the project folder so the theme in `.streamlit/config.toml` is applied):

```bash
streamlit run dashboard.py
```

The database `company_defense.db` is created next to the scripts on first run.

## Scraper options

```bash
python rules_scraper.py --per-feed 30   # read more entries from each feed (default 20)
python rules_scraper.py --reprocess     # re-apply the current tagging rules to every stored article
```

To keep the data fresh, schedule `python rules_scraper.py` to run hourly with Windows Task Scheduler or cron.

## Customising

All rules live at the top of `rules_scraper.py`:

| What | Where |
|---|---|
| News sources | `FEEDS` |
| Threat categories, keywords and playbooks | `THREAT_MATRIX` |
| Severity rules | `_SEVERITY_RULES` |
| IoC patterns | `IOC_PATTERNS` |

After changing categories or severity rules, run `python rules_scraper.py --reprocess` to re-tag existing articles.

## Notes

- Severity and categories come from keyword rules applied to feed titles and summaries, so treat them as triage hints rather than verdicts. Always read the original article.
- IoCs are only found when they appear in the feed text. Most news feeds include just a summary, so many articles won't have any.
- Article content belongs to the original publishers. The database is excluded from the repository by `.gitignore`.
