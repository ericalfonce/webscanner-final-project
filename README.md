# WebScanner — Web Vulnerability Scanner

A web-based vulnerability scanner built with Python Flask for the ATC Diploma in Information and Communication Technology (2026). Detects common web application security issues — SQL Injection, Cross-Site Scripting (XSS), and missing HTTP security headers — with real-time scan progress, per-finding educational reports, and PDF export.

> **Ethical Use Only.** Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal under computer crime laws in most jurisdictions, including Tanzania's Cybercrimes Act 2015.

---

## Features

| Module | What It Does |
|---|---|
| **SQL Injection** | Error-based, boolean-based, and time-based blind injection tests across URL parameters and HTML form inputs (24 payloads) |
| **XSS Detection** | Reflected Cross-Site Scripting detection using 23 curated payloads; tests both URL params and form inputs |
| **Security Headers** | Checks 7 critical HTTP headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, X-XSS-Protection |
| **Smart Crawler** | Breadth-first link discovery up to 50 pages; extracts forms, URL parameters, and scopes crawl to the target domain |
| **Detailed Reports** | Per-finding evidence, payload used, remediation guidance, and educational context for every vulnerability |
| **PDF Export** | Download branded scan reports as PDF with severity breakdown (ReportLab) |
| **Real-time Progress** | Live log feed polled every 2 seconds; animated progress during active scans |
| **Scan History** | Per-user history of all scans with status, duration, and findings summary |
| **Quick / Full Modes** | Quick scan = 10 pages, 1–3 min. Full scan = up to 50 pages, 5–15 min |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3 · Flask 3.0 · Flask-Login · Flask-WTF (CSRF) |
| ORM | SQLAlchemy 2.x |
| Database | SQLite (`instance/scanner.db`) |
| Scanning | `requests` · BeautifulSoup4 (`html.parser`) |
| PDF | ReportLab 4.x |
| Frontend | Bootstrap 5.3 · Bootstrap Icons · Inter font · Vanilla JS |
| Auth | bcrypt (cost factor 12) |

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

> **Notes:**
> - `lxml` is not required — the scanner uses Python's built-in `html.parser`.
> - `weasyprint` is not used — PDF generation uses `reportlab`.
> - Tested on Python 3.12+ (Windows and Linux).

### 4. Run

```bash
python run.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser.

The database (`instance/scanner.db`) is created automatically on first run with two seeded test accounts.

---

## Usage

1. **Register** a new account or log in with a test account (see below)
2. Click **New Scan** in the navigation bar
3. Enter a target URL (e.g. `http://localhost/dvwa`)
4. Select scan modules: SQLi, XSS, Headers (or all three)
5. Choose scan depth: **Quick** or **Full**
6. Click **Start Scan** — live progress updates every 2 seconds
7. View the full report once the scan completes
8. Click **Download PDF** for a shareable report

### Test Accounts

| Username | Password | Notes |
|---|---|---|
| `testuser` | `testpass123` | Default seeded account |

---

## Scan Modes

| Mode | Pages Crawled | Crawl Depth | Est. Time |
|---|---|---|---|
| **Quick** | Up to 10 | 1 level | 1–3 min |
| **Full** | Up to 50 | 2 levels | 5–15 min |

---

## Architecture

### Application Factory Pattern

The app uses Flask's application factory (`create_app()` in `app/__init__.py`). Extensions (`SQLAlchemy`, `LoginManager`, `CSRFProtect`) are instantiated at module level and bound to the app inside the factory — this allows multiple app instances for testing and avoids circular imports.

### Background Thread Scan Runner

Scans run in a daemon thread (`threading.Thread`) so the HTTP response returns immediately and the browser can poll for progress. The thread pushes its own Flask app context manually (`app.app_context()`) since background threads don't inherit the request context. Progress is stored in `ScanLog` rows and the browser polls `/scanner/status/<id>` every 2 seconds via AJAX.

### Blueprint Structure

| Blueprint | URL Prefix | Responsibility |
|---|---|---|
| `auth_bp` | `/auth` | Login, registration, logout |
| `dashboard_bp` | `/` | Dashboard and index |
| `scanner_bp` | `/scanner` | Scan lifecycle, progress, results, PDF, history |

---

## Project Structure

```
webscanner-final-project/
├── run.py                          # Entry point — creates app and runs dev server
├── requirements.txt
├── README.md
│
├── app/
│   ├── __init__.py                 # App factory, extension init, blueprint registration
│   ├── config.py                   # DevelopmentConfig / ProductionConfig
│   ├── models.py                   # User, Scan, Finding, ScanLog (SQLAlchemy ORM)
│   │
│   ├── auth/
│   │   ├── routes.py               # /auth/register, /auth/login, /auth/logout
│   │   └── forms.py                # RegistrationForm, LoginForm (Flask-WTF)
│   │
│   ├── dashboard/
│   │   └── routes.py               # / (dashboard index)
│   │
│   ├── scanner/
│   │   ├── routes.py               # Scan runner + all /scanner/* routes
│   │   ├── crawler.py              # Breadth-first crawler (BFS, same-domain scoping)
│   │   ├── sqli_scanner.py         # SQL Injection: error / boolean / time-based
│   │   ├── xss_scanner.py          # XSS: reflected payload injection
│   │   ├── header_scanner.py       # 7 HTTP security headers
│   │   ├── analyzer.py             # Deduplication and severity sorting
│   │   └── reporter.py             # ReportLab PDF generation
│   │
│   ├── static/
│   │   └── css/style.css
│   │
│   └── templates/
│       ├── base.html               # Shared layout (Bootstrap 5.3)
│       ├── auth/                   # login.html, register.html
│       ├── dashboard/              # index.html
│       ├── scanner/                # new_scan.html, scan_progress.html, results.html, history.html
│       └── errors/                 # 404.html, 500.html
│
├── data/
│   ├── payloads/
│   │   ├── sqli_payloads.json      # 24 SQL Injection payloads
│   │   └── xss_payloads.json       # 23 XSS payloads
│   └── educational/
│       └── vuln_info.json          # Educational content per vulnerability type
│
└── instance/
    └── scanner.db                  # SQLite database (auto-created, git-ignored)
```

---

## Database Models

### `User`
| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | |
| `username` | String(64) | Unique |
| `email` | String(120) | Unique, stored lowercase |
| `password_hash` | String(256) | bcrypt, cost 12 |
| `created_at` | DateTime | UTC |

### `Scan`
| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | |
| `user_id` | FK → users | |
| `target_url` | String(2048) | |
| `scan_type` | String(20) | `quick` or `full` |
| `scan_modules` | String(100) | Comma-separated: `sqli,xss,headers` |
| `status` | String(20) | `pending` → `running` → `completed` / `failed` |
| `pages_crawled` | Integer | |
| `total_tests` | Integer | |
| `started_at` | DateTime | UTC |
| `completed_at` | DateTime | UTC |
| `error_message` | Text | Set on failure |

### `Finding`
| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | |
| `scan_id` | FK → scans | Cascade delete |
| `vuln_type` | String(20) | `sqli`, `xss`, `header` |
| `severity` | String(10) | `high`, `medium`, `low`, `info` |
| `title` | String(200) | |
| `affected_url` | String(2048) | |
| `affected_parameter` | String(200) | |
| `payload_used` | Text | Exact payload that triggered the finding |
| `evidence` | Text | Response snippet |
| `remediation` | Text | Fix guidance |
| `educational_info` | Text | JSON: learn-more links and explanation |

### `ScanLog`
| Column | Type | Notes |
|---|---|---|
| `id` | Integer PK | |
| `scan_id` | FK → scans | Cascade delete |
| `timestamp` | DateTime | UTC |
| `log_level` | String(10) | `info`, `warning`, `error` |
| `message` | Text | |

---

## API Endpoints

All routes require login unless marked public.

| Method | Path | Description |
|---|---|---|
| GET/POST | `/auth/register` | Register new account (public) |
| GET/POST | `/auth/login` | Log in (public) |
| GET | `/auth/logout` | Log out |
| GET | `/` | Dashboard |
| GET/POST | `/scanner/new` | New scan form + scan submission |
| GET | `/scanner/progress/<id>` | Live progress page |
| GET | `/scanner/status/<id>` | JSON status (polled every 2s by progress page) |
| GET | `/scanner/results/<id>` | Full scan results |
| GET | `/scanner/results/<id>/pdf` | Download PDF report |
| GET | `/scanner/history` | All user scans |
| POST | `/scanner/delete/<id>` | Delete a scan |

### `/scanner/status/<id>` response format

```json
{
  "status": "running",
  "pages_crawled": 7,
  "total_tests": 14,
  "findings_count": 3,
  "high_count": 1,
  "medium_count": 2,
  "low_count": 0,
  "logs": [
    {"level": "info", "message": "Testing: http://target/login", "time": "14:02:33"}
  ]
}
```

---

## Configuration

`app/config.py` — override any value by setting the corresponding environment variable:

| Setting | Default | Env Var | Description |
|---|---|---|---|
| `SECRET_KEY` | `dev-secret-key-...` | `SECRET_KEY` | Flask session secret — **must** be changed in production |
| `DATABASE_URL` | SQLite `instance/scanner.db` | `DATABASE_URL` | Any SQLAlchemy-compatible URI |
| `SCAN_REQUEST_TIMEOUT` | `10` | — | Seconds per HTTP request |
| `SCAN_REQUEST_DELAY` | `0.5` | — | Polite delay between requests (seconds) |
| `SCAN_MAX_PAGES` | `50` | — | Max pages crawled per full scan |
| `SCAN_CRAWL_DEPTH` | `2` | — | Max BFS depth |

For production, set `FLASK_ENV=production` to enable `ProductionConfig` (`DEBUG=False`).

---

## Scanner Modules

### SQL Injection (`sqli_scanner.py`)

Three detection techniques applied to every URL parameter and form input:

1. **Error-based** — injects payloads (`'`, `''`, `' OR '1'='1`, etc.) and checks the response for 20+ database error strings (`sql syntax`, `ora-`, `sqlite3`, `unclosed quotation mark`, etc.)
2. **Boolean-based** — compares response content length for true/false conditions (`AND 1=1` vs `AND 1=2`)
3. **Time-based blind** — measures response time after `SLEEP(3)` / `WAITFOR DELAY '0:0:3'` payloads; flags if delay ≥ 3 seconds

### XSS (`xss_scanner.py`)

Reflected XSS only. Injects 23 payloads into URL parameters and form fields and checks if the raw payload appears unescaped in the response HTML. Uses BeautifulSoup to parse the DOM and verify the payload isn't HTML-entity encoded.

### Security Headers (`header_scanner.py`)

Checks seven headers on the target's root URL:

| Header | Severity if Missing |
|---|---|
| `Content-Security-Policy` | High |
| `Strict-Transport-Security` | High |
| `X-Frame-Options` | Medium |
| `X-Content-Type-Options` | Low |
| `Referrer-Policy` | Low |
| `Permissions-Policy` | Low |
| `X-XSS-Protection` | Low |

### Crawler (`crawler.py`)

Breadth-first search (BFS) using `collections.deque`. Scopes all crawled links to the target domain. Extracts:
- All `<a href>` links
- All `<form>` actions with input field names (for injection testing)
- URL query parameters

---

## Security Implementation

- Passwords hashed with `bcrypt` (cost factor 12)
- All forms protected by CSRF tokens via `Flask-WTF`
- Users can only access their own scans (ownership check in `_get_user_scan`)
- All inputs validated server-side before scanning or DB write
- Scan targets validated as valid `http://` or `https://` URLs before crawling
- Generic error pages in production (no stack traces exposed)
- SQLAlchemy ORM used throughout — no raw SQL string interpolation

---

## Recommended Test Targets

| Target | Notes |
|---|---|
| [DVWA](https://github.com/digininja/DVWA) | Damn Vulnerable Web Application — best for SQLi + XSS |
| [OWASP WebGoat](https://github.com/WebGoat/WebGoat) | Java-based, wide vulnerability coverage |
| [HackTheBox](https://www.hackthebox.com) | Your own active machines only |
| [TryHackMe](https://tryhackme.com) | Guided vulnerable rooms |

---

## Known Limitations

- Reflected XSS only — stored and DOM-based XSS not detected
- Time-based SQLi detection can produce false positives on slow networks
- No JavaScript rendering (Selenium/Playwright not used) — JS-heavy SPAs may not be fully crawled
- SSL certificate verification disabled during scans to allow testing of dev/staging sites with self-signed certs
- Single-user SQLite — not suitable for multi-user production deployment without migrating to PostgreSQL

---

## Disclaimer

This tool was developed for **educational purposes** as part of an ATC Diploma in Information and Communication Technology. The authors are not responsible for any misuse or damage caused by this software. Use only on systems you own or have explicit written authorization to test.

---

*Arusha Technical College — Diploma in Information and Communication Technology — 2026*
