# WebScanner — Web Vulnerability Scanner

A web-based vulnerability scanner built with Python Flask for educational purposes as part of an ATC Diploma project. Detects common web application security issues including SQL Injection, Cross-Site Scripting (XSS), and missing HTTP security headers — with real-time scan progress, detailed per-finding reports, and PDF export.

> **Ethical Use Only** — Only scan systems you own or have explicit written permission to test.  
> Recommended targets: [DVWA](https://github.com/digininja/DVWA), [OWASP WebGoat](https://github.com/WebGoat/WebGoat), [HackTheBox](https://www.hackthebox.com) (your own machines only).

---

## Features

| Module | Description |
|---|---|
| **SQL Injection** | Error-based, boolean-based, and time-based blind injection tests across URL parameters and form inputs |
| **XSS Detection** | Reflected Cross-Site Scripting detection using 23 curated payloads |
| **Security Headers** | Checks 7 critical HTTP headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection |
| **Smart Crawler** | Recursive link discovery up to 50 pages with form extraction and duplicate URL detection |
| **Detailed Reports** | Per-finding evidence, payload used, remediation steps, and educational context for every vulnerability |
| **PDF Export** | Download complete scan reports as branded PDFs with severity breakdown |
| **Real-time Progress** | Live log feed and animated progress bar during active scans |
| **Scan History** | Per-user history of all scans with status, findings count, and duration |

---

## Tech Stack

- **Backend:** Python 3 · Flask 3.0 · SQLAlchemy · Flask-Login · Flask-WTF (CSRF)
- **Database:** SQLite (via `instance/scanner.db`)
- **Scanning:** `requests` · BeautifulSoup4 (`html.parser`)
- **PDF Reports:** ReportLab
- **Frontend:** Bootstrap 5.3 · Bootstrap Icons · Inter font · Vanilla JS

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/ericalfonce/webscanner-final-project.git
cd webscanner-final-project
```

### 2. Create a virtual environment

```bash
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

> **Note:** `lxml` is not required — the scanner uses `html.parser` (built-in). `weasyprint` is not used — PDF generation uses `reportlab`.

### 4. Run the application

```bash
python run.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

---

## Usage

1. **Register** a new account or log in with the default test account
2. Click **New Scan** and enter a target URL (e.g. `http://localhost/dvwa`)
3. Select scan modules (SQLi, XSS, Headers) and depth (Quick / Full)
4. Click **Start Scan** — watch live progress in real time
5. View the full report when the scan completes
6. **Download PDF** for a shareable report

### Default Test Account

| Field | Value |
|---|---|
| Username | `testuser` |
| Password | `testpass123` |

---

## Scan Modes

| Mode | Pages Crawled | Scope | Estimated Time |
|---|---|---|---|
| **Quick** | Up to 10 | Headers + sample injection tests | 1–3 min |
| **Full** | Up to 50 | All modules, exhaustive payloads | 5–15 min |

---

## Project Structure

```
webscanner-final-project/
├── run.py                        # Entry point
├── requirements.txt
├── app/
│   ├── __init__.py               # App factory
│   ├── config.py                 # SCAN_REQUEST_TIMEOUT, SCAN_REQUEST_DELAY, SCAN_MAX_PAGES
│   ├── models.py                 # User, Scan, Finding, ScanLog
│   ├── auth/                     # Login & registration routes
│   ├── dashboard/                # Dashboard routes & views
│   ├── scanner/
│   │   ├── routes.py             # Scan runner (background thread)
│   │   ├── crawler.py            # Link + form crawler
│   │   ├── sqli_scanner.py       # SQL Injection module
│   │   ├── xss_scanner.py        # XSS module
│   │   ├── header_scanner.py     # Security headers module
│   │   └── reporter.py           # PDF report generator (ReportLab)
│   ├── static/css/style.css      # UI stylesheet
│   └── templates/                # Jinja2 HTML templates
└── data/payloads/
    ├── sqli_payloads.json        # 24 SQLi payloads
    └── xss_payloads.json         # 23 XSS payloads
```

---

## Configuration

Edit `app/config.py` to adjust scanner behaviour:

```python
SCAN_REQUEST_TIMEOUT = 10   # seconds per HTTP request
SCAN_REQUEST_DELAY   = 0.3  # polite delay between requests
SCAN_MAX_PAGES       = 50   # maximum pages crawled (full scan)
```

---

## Ethical Use — Important

> Scanning a system without authorization is illegal under computer crime laws in most jurisdictions.  
> This tool is intended **exclusively** for use on systems you own or have written permission to test.

Safe practice environments:
- [DVWA](https://github.com/digininja/DVWA) — Damn Vulnerable Web Application
- [OWASP WebGoat](https://github.com/WebGoat/WebGoat)
- [HackTheBox](https://www.hackthebox.com) — your own active machines
- [TryHackMe](https://tryhackme.com)

---

## Disclaimer

This tool was developed for **educational purposes** as part of an ATC Diploma in Information and Communication Technology. The authors are not responsible for any misuse or damage caused by this software.

---

*Arusha Technical College — Diploma in Information and Communication Technology*
