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
        Check if the payload appears unescaped in the response.
        We look for the raw payload (or key parts of it) in the raw HTML.
        We exclude cases where it's properly HTML-encoded.
        """
        # Direct raw reflection — most reliable check
        if payload in response_body:
            # Make sure it's not inside a comment or encoded
            # Use BeautifulSoup to check if it ended up as executable content
            return self._is_executable_context(payload, response_body)

        # Check without quotes (some servers strip quotes but keep the rest)
        stripped = payload.replace('"', '').replace("'", '')
        if len(stripped) > 10 and stripped in response_body:
            return True

        return False

    def _is_executable_context(self, payload, response_body):
        """
        Return True if the reflected payload could be executed.
        False if it's inside an HTML comment or properly escaped.
        """
        # Check if it's inside an HTML comment (not executable)
        comment_start = response_body.find('<!--')
        comment_end   = response_body.find('-->')
        payload_pos   = response_body.find(payload)

        if (comment_start != -1 and comment_end != -1 and
                comment_start < payload_pos < comment_end):
            return False

        # Check if HTML entity-encoded version is what appears (safe)
        encoded = html_module.escape(payload)
        if encoded in response_body and payload not in response_body:
            return False

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

        edu = {
            'what': 'Cross-Site Scripting (XSS) is a vulnerability where an attacker injects malicious scripts into web pages viewed by other users.',
            'how':  f'The payload `{payload}` was submitted via {context} `{parameter}` and was reflected in the server\'s response without being properly encoded. If a victim visits a crafted URL, the script executes in their browser.',
            'why':  'XSS can allow attackers to steal session cookies (account takeover), redirect users to phishing sites, log keystrokes, deface web pages, or perform actions on behalf of victims.',
            'fix':  'Always HTML-encode user input before displaying it in the page. Use a Content Security Policy (CSP) header. Validate and sanitise all input on the server side. Use modern frameworks that auto-escape output (e.g., Jinja2, React).',
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
