"""
SQL Injection Scanner Module
Detects SQL injection vulnerabilities using three techniques:
  1. Error-based  — look for database error messages in responses
  2. Boolean-based — compare responses for true/false conditions
  3. Time-based   — measure response time after SLEEP/WAITFOR payloads
"""

import json
import time
import logging
from pathlib import Path
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

import requests

logger = logging.getLogger(__name__)

# When a SQL injection payload breaks the query, the database often leaks
# its error message into the HTTP response. These are the tell-tale strings
# we look for — each one is specific to a different database engine.
DB_ERROR_PATTERNS = [
    "sql syntax",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_query",
    "ora-",
    "oracle error",
    "postgresql",
    "pg_query",
    "sqlite3",
    "sqlite_",
    "syntax error",
    "microsoft jet database",
    "odbc drivers error",
    "jdbc",
    "sqlstate",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql server",
    "invalid query",
    "db2 sql error",
    "division by zero",
    "supplied argument is not a valid mysql",
    "warning: mysql",
    "you have an error in your sql",
    "sql command not properly ended",
]

# If a response takes longer than this after we inject a SLEEP() payload,
# the database likely executed our delay command — that confirms SQLi.
TIME_THRESHOLD = 3.0


class SQLiScanner:
    """
    SQL Injection detection engine.
    Tests URL parameters and HTML form inputs.
    """

    def __init__(self, session, payloads_file, timeout=10, delay=0.5):
        self.session  = session
        self.timeout  = timeout
        self.delay    = delay
        self.findings = []
        self.logs     = []

        self.payloads = self._load_payloads(payloads_file)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def scan_page(self, page_info):
        """
        Scan a single page (PageInfo dict from crawler) for SQLi.
        Returns list of new finding dicts.
        """
        url    = page_info['url']
        params = page_info.get('params', {})
        forms  = page_info.get('forms', [])

        new_findings = []

        # Test URL query parameters
        if params:
            self._log(f"Testing URL params on: {url}")
            for param_name in params:
                for payload_entry in self.payloads:
                    finding = self._test_url_param(url, params, param_name, payload_entry)
                    if finding:
                        new_findings.append(finding)
                        self.findings.append(finding)
                        break   # found one vuln in this param — no need to keep trying more payloads
                time.sleep(self.delay)

        # Test HTML forms
        for form in forms:
            self._log(f"Testing form at: {form['action']}")
            for input_field in form['inputs']:
                for payload_entry in self.payloads:
                    finding = self._test_form_input(form, input_field, payload_entry)
                    if finding:
                        new_findings.append(finding)
                        self.findings.append(finding)
                        break
                time.sleep(self.delay)

        return new_findings

    # ------------------------------------------------------------------
    # URL parameter testing
    # ------------------------------------------------------------------

    def _test_url_param(self, url, params, param_name, payload_entry):
        """
        Inject a payload into a URL query parameter and check the response.
        Returns a finding dict if vulnerable, else None.
        """
        payload   = payload_entry['payload']
        technique = payload_entry.get('technique', 'error')

        # Build injected URL
        injected_params = dict(params)
        injected_params[param_name] = [payload]  # replace original value

        injected_url = self._build_url_with_params(url, injected_params)

        if technique == 'time':
            return self._time_based_test(injected_url, url, params, param_name, payload_entry)

        # Error-based / boolean-based
        try:
            start = time.time()
            resp  = self.session.get(injected_url, timeout=self.timeout)
            elapsed = time.time() - start
        except requests.exceptions.RequestException as e:
            self._log(f"Request error: {e}", level='error')
            return None

        body_lower = resp.text.lower()

        if technique == 'error' and self._has_db_error(body_lower):
            return self._make_finding(
                url=injected_url,
                parameter=param_name,
                payload=payload,
                technique='Error-based SQL Injection',
                evidence=self._extract_evidence(resp.text, body_lower),
                severity='high',
            )

        if technique == 'boolean':
            return self._boolean_test(url, params, param_name, payload_entry)

        return None

    def _boolean_test(self, url, params, param_name, payload_entry):
        """Compare true/false condition responses to detect Boolean-based SQLi."""
        true_payload  = payload_entry['payload']
        false_payload = payload_entry.get('false_payload')

        if not false_payload:
            return None

        try:
            # True condition
            true_params = dict(params)
            true_params[param_name] = [true_payload]
            true_url = self._build_url_with_params(url, true_params)
            r_true = self.session.get(true_url, timeout=self.timeout)

            time.sleep(self.delay)

            # False condition
            false_params = dict(params)
            false_params[param_name] = [false_payload]
            false_url = self._build_url_with_params(url, false_params)
            r_false = self.session.get(false_url, timeout=self.timeout)

        except requests.exceptions.RequestException:
            return None

        # If the true condition (OR 1=1) returns a noticeably different page
        # than the false condition (OR 1=2), the SQL logic is affecting the output
        # — which means the input is being executed as SQL, not treated as data.
        len_diff = abs(len(r_true.text) - len(r_false.text))
        if len_diff > 50:  # 50 chars is enough of a difference to be meaningful
            return self._make_finding(
                url=true_url,
                parameter=param_name,
                payload=true_payload,
                technique='Boolean-based SQL Injection',
                evidence=f"Response length difference: {len_diff} characters between true/false conditions.",
                severity='high',
            )

        return None

    def _time_based_test(self, injected_url, orig_url, params, param_name, payload_entry):
        """Send a time-delay payload and measure response time."""
        payload = payload_entry['payload']
        try:
            start   = time.time()
            self.session.get(injected_url, timeout=self.timeout + TIME_THRESHOLD + 2)
            elapsed = time.time() - start
        except requests.exceptions.Timeout:
            # A timeout itself is evidence of a delay — the server was sleeping so long
            # that requests gave up waiting. Treat it as a confirmed time-based hit.
            elapsed = self.timeout + TIME_THRESHOLD + 2

        except requests.exceptions.RequestException:
            return None

        if elapsed >= TIME_THRESHOLD:
            return self._make_finding(
                url=injected_url,
                parameter=param_name,
                payload=payload,
                technique='Time-based Blind SQL Injection',
                evidence=f"Response took {elapsed:.2f}s (threshold: {TIME_THRESHOLD}s). Server appears to have executed a delay function.",
                severity='high',
            )

        return None

    # ------------------------------------------------------------------
    # Form input testing
    # ------------------------------------------------------------------

    def _test_form_input(self, form, input_field, payload_entry):
        """Inject payload into a form field and submit."""
        payload   = payload_entry['payload']
        technique = payload_entry.get('technique', 'error')
        action    = form['action']
        method    = form['method']
        field_name = input_field['name']

        # Build form data with payload in the target field
        data = {}
        for inp in form['inputs']:
            data[inp['name']] = inp['value'] or ('test' if inp['name'] != field_name else payload)
        data[field_name] = payload

        try:
            if method == 'post':
                start = time.time()
                resp  = self.session.post(action, data=data, timeout=self.timeout)
                elapsed = time.time() - start
            else:
                start = time.time()
                resp  = self.session.get(action, params=data, timeout=self.timeout)
                elapsed = time.time() - start
        except requests.exceptions.RequestException as e:
            self._log(f"Form request error: {e}", level='error')
            return None

        body_lower = resp.text.lower()

        if technique == 'error' and self._has_db_error(body_lower):
            return self._make_finding(
                url=action,
                parameter=field_name,
                payload=payload,
                technique='Error-based SQL Injection (Form)',
                evidence=self._extract_evidence(resp.text, body_lower),
                severity='high',
            )

        if technique == 'time' and elapsed >= TIME_THRESHOLD:
            return self._make_finding(
                url=action,
                parameter=field_name,
                payload=payload,
                technique='Time-based Blind SQL Injection (Form)',
                evidence=f"Response took {elapsed:.2f}s.",
                severity='high',
            )

        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _has_db_error(self, body_lower):
        return any(pattern in body_lower for pattern in DB_ERROR_PATTERNS)

    def _extract_evidence(self, body, body_lower):
        """Return a short snippet of the body containing the error."""
        for pattern in DB_ERROR_PATTERNS:
            idx = body_lower.find(pattern)
            if idx != -1:
                start = max(0, idx - 80)
                end   = min(len(body), idx + 200)
                return '...' + body[start:end].strip() + '...'
        return body[:300]

    def _build_url_with_params(self, url, params):
        """Rebuild a URL replacing its query string with the given params dict."""
        parsed = urlparse(url)
        # parse_qs returns lists; flatten to single values for urlencode
        flat = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        new_query = urlencode(flat)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, ''))

    def _make_finding(self, url, parameter, payload, technique, evidence, severity):
        """Build a finding dict."""
        import json as _json

        edu = {
            'what': (
                "SQL Injection (SQLi) happens when an application builds a database query by gluing "
                "user input directly into a SQL string. The database can't tell the difference between "
                "the developer's intended SQL and the attacker's injected SQL — it just runs whatever it receives.\n\n"
                "Think of it like a printed form where you write your name, but an attacker writes "
                "'John; DROP TABLE users;--' instead. If the form is processed literally, the database follows those instructions."
            ),
            'attack_scenario': (
                f"The app likely builds a query similar to:\n"
                f"  SELECT * FROM table WHERE {parameter} = '[your input]'\n\n"
                f"We injected: {payload}\n\n"
                f"Technique used: {technique}\n\n"
                "What the database actually ran was a broken or manipulated query — "
                "which either leaked an error message (error-based), returned different data for true/false conditions "
                "(boolean-based), or paused execution for several seconds (time-based blind)."
            ),
            'vulnerable_code': (
                "# ❌ VULNERABLE — input concatenated directly into SQL string\n"
                f"query = \"SELECT * FROM users WHERE name='\" + {parameter} + \"'\"\n"
                "db.execute(query)\n\n"
                "# Attacker enters:  ' OR '1'='1\n"
                "# Resulting query:  SELECT * FROM users WHERE name='' OR '1'='1'\n"
                "# Effect:           Returns ALL users — authentication bypassed completely"
            ),
            'safe_code': (
                "# ✅ SAFE — parameterised query: input is always treated as data, never as SQL\n"
                f"query = \"SELECT * FROM users WHERE name = ?\"\n"
                f"db.execute(query, ({parameter},))\n\n"
                "# ORM approach (SQLAlchemy) — parameterises automatically:\n"
                f"User.query.filter_by(name={parameter}).first()"
            ),
            'real_impact': (
                "SQL Injection has caused some of the largest data breaches ever recorded:\n\n"
                "• 2008 — Heartland Payment Systems: 130 million credit card numbers stolen\n"
                "• 2011 — Sony Pictures: 1 million user accounts and internal data dumped\n"
                "• 2015 — TalkTalk UK: 157,000 customers' data exposed; £400,000 regulatory fine\n"
                "• 2017 — Equifax (contributing factor): 147 million people's personal records leaked\n\n"
                "Impact ranges from reading private data, bypassing login, altering records, "
                "deleting tables, to full server takeover via xp_cmdshell (SQL Server)."
            ),
            'fix': (
                "1. Parameterised queries / prepared statements — the single most important fix.\n"
                "   Never concatenate user input into SQL strings.\n\n"
                "2. Use an ORM (SQLAlchemy, Django ORM, Hibernate) — they parameterise automatically.\n\n"
                "3. Validate input: check type, length, and allowed character sets before it reaches the DB.\n\n"
                "4. Least-privilege DB accounts: your app user should have only SELECT/INSERT/UPDATE.\n"
                "   It should NEVER have DROP, CREATE, or admin privileges.\n\n"
                "5. Disable detailed DB error messages in production — they reveal schema details to attackers."
            ),
            'owasp': 'https://owasp.org/www-community/attacks/SQL_Injection',
            'cvss':  'CVSS 9.8 Critical — exploitable remotely, no authentication required, full data compromise possible',
        }

        self._log(f"[SQLI-HIGH] {technique} found in parameter '{parameter}' at {url}")

        return {
            'vuln_type':          'sqli',
            'severity':           severity,
            'title':              f'SQL Injection — {technique}',
            'description':        f'{technique} detected in parameter "{parameter}". The application appears to execute unsanitised user input as part of a SQL query.',
            'affected_url':       url,
            'affected_parameter': parameter,
            'payload_used':       payload,
            'evidence':           evidence[:1000],
            'remediation':        edu['fix'],
            'educational_info':   _json.dumps(edu),
        }

    def _load_payloads(self, payloads_file):
        """Load payloads from JSON file."""
        try:
            with open(payloads_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            self._log(f"Payloads file not found: {payloads_file}", level='error')
            return self._default_payloads()
        except json.JSONDecodeError as e:
            self._log(f"JSON decode error in payloads file: {e}", level='error')
            return self._default_payloads()

    def _default_payloads(self):
        """Fallback payloads if JSON file is missing."""
        return [
            {'payload': "'", 'technique': 'error'},
            {'payload': '"', 'technique': 'error'},
            {'payload': "' OR '1'='1", 'technique': 'boolean', 'false_payload': "' OR '1'='2"},
            {'payload': "' OR SLEEP(3)--", 'technique': 'time'},
        ]

    def _log(self, message, level='info'):
        entry = f"[SQLI] {message}"
        self.logs.append({'level': level, 'message': entry})
        logger.info(entry) if level == 'info' else logger.warning(entry)
