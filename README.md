# WebScanner — Educational Web Vulnerability Scanner

A diploma project for **Arusha Technical College** built with Python Flask.
Designed to help students learn about web application security by scanning intentionally vulnerable practice applications.

---

## Features

| Module | What it detects |
|--------|-----------------|
| **SQL Injection** | Error-based, Boolean-based, Time-based blind SQLi |
| **XSS** | Reflected Cross-Site Scripting in URL params & forms |
| **Security Headers** | 7 HTTP security headers (CSP, HSTS, X-Frame-Options, …) |

- Real-time scan progress with live log feed
- Educational "Learn More" section on every finding
- Severity ratings: High / Medium / Low / Informational
- PDF report download (via ReportLab)
- User authentication with bcrypt password hashing
- Scan history per user
- Mobile-responsive Bootstrap 5 UI

---

## Quick Start

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the app

```bash
python run.py
```

Then open **http://127.0.0.1:5000** in your browser.

### 3. Register & log in

Create an account on the Register page, then log in.

### 4. Start a scan

- Click **New Scan**
- Enter a target URL (e.g. `http://localhost/dvwa`)
- Select scan modules and depth
- Click **Start Scan**

---

## Ethical Use — IMPORTANT

> **Only scan systems you own or have explicit written permission to test.**
> Scanning without authorisation is illegal under computer crime laws in most countries.

Recommended practice targets:
- [DVWA](https://github.com/digininja/DVWA) — Damn Vulnerable Web Application
- [OWASP WebGoat](https://github.com/WebGoat/WebGoat)
- [HackTheBox](https://hackthebox.com) (your own machines only)
- [TryHackMe](https://tryhackme.com)

---

## Project Structure

```
vulnerability-scanner/
├── app/
│   ├── __init__.py          # Flask app factory
│   ├── config.py            # Configuration
│   ├── models.py            # SQLAlchemy models
│   ├── auth/                # Login, register, logout
│   ├── scanner/             # Crawler, SQLi, XSS, headers, reporter
│   ├── dashboard/           # Dashboard view
│   ├── templates/           # Jinja2 HTML templates
│   └── static/              # CSS & JS
├── data/
│   ├── payloads/            # SQLi & XSS payload lists (JSON)
│   └── educational/         # Vulnerability education data (JSON)
├── instance/
│   └── scanner.db           # SQLite database (auto-created)
├── requirements.txt
├── run.py                   # Entry point
└── README.md
```

---

## Configuration

Set environment variables to override defaults:

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | dev key | Flask session secret — **change in production** |
| `DATABASE_URL` | SQLite | Database URI |

---

## Tech Stack

- **Backend:** Python 3 · Flask 3.0 · SQLAlchemy · Flask-Login · Flask-WTF
- **Scanning:** requests · BeautifulSoup4
- **PDF Reports:** ReportLab
- **Frontend:** Bootstrap 5 · Bootstrap Icons · Vanilla JS
- **Database:** SQLite (switchable to PostgreSQL)

---

*Arusha Technical College — Diploma in Information and Communication Technology*
