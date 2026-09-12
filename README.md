# Threat Intelligence Feed & IOC Dashboard

A modular Python pipeline that aggregates RSS feeds from cybersecurity news outlets and official advisories (such as CISA, SANS ISC, and BleepingComputer), extracts technical Indicators of Compromise (IOCs) using regular expressions, and visualizes the data inside a Streamlit web interface.

## Overview

Staying informed about emerging threats often requires checking multiple websites and advisories manually. This project provides a local, automated pipeline to:
1. Collect recent articles and advisories across 19 curated security sources.
2. Scan article summaries for technical indicators (IPv4 addresses, SHA-256/MD5 hashes, and CVE identifiers).
3. Map threat keywords to actionable incident response checklists (ransomware, brute-force, malware, etc.).
4. Store records in a local SQLite database with duplicate URL prevention.
5. Provide a searchable, filterable dashboard built with Streamlit for review and triage.

## Architecture

The project is split into two decoupled scripts to separate data collection from the user interface:

- **`intel_ingestor.py` (Collection & Extraction):** Connects to RSS feeds using `feedparser`, parses HTML summaries with `BeautifulSoup`, runs regex filters to identify IOCs, and writes unique entries into `company_defense.db`.
- **`soc_dashboard.py` (Interface & Filtering):** Connects to the SQLite database via `pandas` and renders an interactive web dashboard in `streamlit`, allowing filtering by threat category or free-text IOC search.

## Extracted Indicators & Detection Logic

### 1. Regex Patterns
The ingestion engine scans text bodies using targeted regular expressions for:
- **IPv4 addresses:** Matches dotted-quad IP format (`0.0.0.0` - `255.255.255.255`).
- **Cryptographic Hashes:** 64-character hex strings (SHA-256) and 32-character hex strings (MD5).
- **Vulnerabilities:** Standard `CVE-YYYY-NNNN+` identifiers.

### 2. Threat Classification
Articles are categorized using keyword matching across categories such as:
- Ransomware
- Authentication / Credential Attacks
- Malware & C2 Infrastructure
- DDoS Attacks
- Third-Party / Supply Chain
- Privilege Escalation

Each category provides an operational triage checklist directly inside the dashboard.

## Installation & Setup

### Prerequisites
- Python 3.9 or higher

### 1. Clone the repository
```bash
git clone [https://github.com/bdan-security/Threat-intel-feed-dashboard.git](https://github.com/bdan-security/Threat-intel-feed-dashboard.git)
cd Threat-intel-feed-dashboard
```

2. Set up a virtual environment (recommended)

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

4. Install dependencies

```bash
pip install -r requirements.txt
```

Usage
Step 1: Ingest Threat Intelligence
Run the ingestion script to pull the latest entries into the database:

```bash
python intel_ingestor.py
```

Step 2: Launch the SOC Dashboard
Start the local Streamlit application:

```bash
streamlit run soc_dashboard.py
```

Open your browser at http://localhost:8501 to view and filter the collected intelligence.

Known Limitations & Planned Enhancements
Regex Edge Cases: Standard regex patterns can occasionally catch benign IP addresses (e.g., public DNS like 8.8.8.8) or version numbers formatted similarly to hashes.

Feed Coverage: Reliance on RSS summaries means only articles providing substantive summaries will yield complete IOC matches without scraping the full webpage.

Defanging: Future revisions will incorporate automatic IOC defanging (e.g., converting example[.]com or 192.168.1[.]1) to prevent accidental execution.
