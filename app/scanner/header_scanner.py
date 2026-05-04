"""
Security Headers Scanner Module
Checks HTTP response headers for common security misconfigurations.
"""

import logging
import requests

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Header definitions
# ---------------------------------------------------------------------------

SECURITY_HEADERS = [
    {
        'name':        'X-Frame-Options',
        'description': 'Prevents the page from being embedded in iframes (Clickjacking protection).',
        'severity':    'medium',
        'expected':    ['DENY', 'SAMEORIGIN'],
        'missing_msg': 'X-Frame-Options header is missing. The site may be vulnerable to Clickjacking attacks.',
        'bad_msg':     'X-Frame-Options is set to ALLOWALL, which provides no Clickjacking protection.',
    },
    {
        'name':        'X-Content-Type-Options',
        'description': 'Prevents browsers from MIME-sniffing a response away from the declared content-type.',
        'severity':    'low',
        'expected':    ['nosniff'],
        'missing_msg': 'X-Content-Type-Options header is missing. Browsers may interpret files as a different MIME type.',
        'bad_msg':     None,
    },
    {
        'name':        'X-XSS-Protection',
        'description': 'Enables the browser\'s built-in XSS filter (legacy, but still useful for older browsers).',
        'severity':    'low',
        'expected':    ['1; mode=block', '1'],
        'missing_msg': 'X-XSS-Protection header is missing.',
        'bad_msg':     None,
    },
    {
        'name':        'Strict-Transport-Security',
        'description': 'Forces browsers to use HTTPS for all future requests (HSTS).',
        'severity':    'medium',
        'expected':    None,   # Just check presence
        'missing_msg': 'Strict-Transport-Security (HSTS) header is missing. Users could be downgraded to HTTP.',
        'bad_msg':     None,
    },
    {
        'name':        'Content-Security-Policy',
        'description': 'Defines approved sources of content, reducing XSS and data-injection risks.',
        'severity':    'medium',
        'expected':    None,
        'missing_msg': 'Content-Security-Policy (CSP) header is missing. The site has no content restriction policy.',
        'bad_msg':     None,
    },
    {
        'name':        'Referrer-Policy',
        'description': 'Controls how much referrer information is sent with requests.',
        'severity':    'low',
        'expected':    None,
        'missing_msg': 'Referrer-Policy header is missing. Sensitive URLs may be leaked to third parties.',
        'bad_msg':     None,
    },
    {
        'name':        'Permissions-Policy',
        'description': 'Controls which browser features (camera, microphone, etc.) can be used.',
        'severity':    'low',
        'expected':    None,
        'missing_msg': 'Permissions-Policy header is missing.',
        'bad_msg':     None,
    },
]

# Educational information for each header type
HEADER_EDUCATION = {
    'X-Frame-Options': {
        'what': 'X-Frame-Options tells the browser whether the page can be displayed inside an iframe.',
        'how':  'Attackers create a fake page with an invisible iframe over a real page. Users click on the real page thinking they are clicking the fake one — this is called Clickjacking.',
        'why':  'Without this header, attackers can trick users into clicking buttons or links without their knowledge, potentially causing unintended actions.',
        'fix':  'Add the response header: X-Frame-Options: DENY (or SAMEORIGIN if you need same-origin iframes).',
    },
    'X-Content-Type-Options': {
        'what': 'This header stops browsers from guessing (sniffing) the content type of a response.',
        'how':  'Browsers sometimes try to "guess" what type of file they received. An attacker could upload a file that looks like an image but contains JavaScript, and the browser might execute it.',
        'why':  'MIME-sniffing attacks can lead to XSS or other code execution vulnerabilities.',
        'fix':  'Add: X-Content-Type-Options: nosniff',
    },
    'X-XSS-Protection': {
        'what': 'This header enables the built-in XSS protection in older browsers (IE, older Chrome/Safari).',
        'how':  'Older browsers have a built-in XSS filter that detects and blocks some reflected XSS attacks. This header turns it on.',
        'why':  'While modern browsers have better protections, enabling this header provides a safety net for older browser users.',
        'fix':  'Add: X-XSS-Protection: 1; mode=block',
    },
    'Strict-Transport-Security': {
        'what': 'HSTS tells browsers to only communicate with the site using HTTPS — never plain HTTP.',
        'how':  'Without HSTS, attackers can perform Man-in-the-Middle attacks by intercepting HTTP requests and downgrading the connection from HTTPS to HTTP.',
        'why':  'Protects users from eavesdropping and Man-in-the-Middle attacks, especially on public Wi-Fi networks.',
        'fix':  'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
    },
    'Content-Security-Policy': {
        'what': 'CSP is a powerful header that tells browsers which sources of content (scripts, images, styles) are allowed to load.',
        'how':  'Without CSP, injected malicious scripts can load from anywhere. CSP acts as a whitelist — only approved sources are allowed.',
        'why':  'CSP is one of the most effective defenses against XSS attacks. It can completely block injected scripts if configured correctly.',
        'fix':  "Add: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' (adjust to your needs).",
    },
    'Referrer-Policy': {
        'what': 'Controls how much referrer information the browser sends when navigating between pages.',
        'how':  'When a user clicks a link, the browser sends the current page URL as the "Referer" header. This can leak sensitive URLs (e.g., password reset tokens).',
        'why':  'Prevents leaking sensitive information in URLs to third-party websites.',
        'fix':  'Add: Referrer-Policy: strict-origin-when-cross-origin',
    },
    'Permissions-Policy': {
        'what': 'Controls which browser APIs (camera, microphone, geolocation) can be used by the page.',
        'how':  'Malicious scripts or third-party content could try to access your camera or location. This header restricts those permissions.',
        'why':  'Reduces the attack surface by preventing unwanted access to powerful browser APIs.',
        'fix':  'Add: Permissions-Policy: geolocation=(), microphone=(), camera=()',
    },
}


class HeaderScanner:
    """Checks HTTP security headers for a given URL."""

    def __init__(self, session, timeout=10):
        self.session = session
        self.timeout = timeout
        self.findings = []
        self.logs = []

    def scan(self, url):
        """
        Fetch the URL headers and check each security header.
        Returns list of finding dicts.
        """
        self._log(f"Starting header scan for: {url}")
        headers = self._fetch_headers(url)

        if headers is None:
            self._log(f"Could not fetch headers for {url}", level='error')
            return []

        # Normalise header names to lower case for comparison
        lower_headers = {k.lower(): v for k, v in headers.items()}

        for hdr_def in SECURITY_HEADERS:
            self._check_header(url, hdr_def, lower_headers)

        self._log(f"Header scan complete — {len(self.findings)} findings.")
        return self.findings

    # ------------------------------------------------------------------
    def _fetch_headers(self, url):
        """Return response headers dict or None on error."""
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            return dict(resp.headers)
        except requests.exceptions.RequestException as e:
            self._log(f"Request error: {e}", level='error')
            return None

    def _check_header(self, url, hdr_def, lower_headers):
        """Evaluate a single security header and add a finding if needed."""
        name       = hdr_def['name']
        name_lower = name.lower()
        severity   = hdr_def['severity']
        expected   = hdr_def.get('expected')

        present = name_lower in lower_headers
        value   = lower_headers.get(name_lower, '')

        if not present:
            # Header is completely missing
            self._add_finding(
                url=url,
                header_name=name,
                severity=severity,
                issue='missing',
                message=hdr_def['missing_msg'],
                actual_value=None,
            )
        elif expected:
            # Header is present — check if value is acceptable
            value_ok = any(exp.lower() in value.lower() for exp in expected)
            if not value_ok and hdr_def.get('bad_msg'):
                self._add_finding(
                    url=url,
                    header_name=name,
                    severity=severity,
                    issue='misconfigured',
                    message=hdr_def['bad_msg'],
                    actual_value=value,
                )
        # else: header present and no expected value to check → OK

    def _add_finding(self, url, header_name, severity, issue, message, actual_value):
        """Record a header finding."""
        import json

        edu = HEADER_EDUCATION.get(header_name, {})
        title = (
            f"Missing Security Header: {header_name}"
            if issue == 'missing'
            else f"Misconfigured Security Header: {header_name}"
        )

        self.findings.append({
            'vuln_type':          'header',
            'severity':           severity,
            'title':              title,
            'description':        message,
            'affected_url':       url,
            'affected_parameter': header_name,
            'payload_used':       None,
            'evidence':           f"Actual value: {actual_value}" if actual_value else "Header not present in response.",
            'remediation':        edu.get('fix', 'Add the appropriate security header to your server configuration.'),
            'educational_info':   json.dumps(edu),
        })
        self._log(f"[{severity.upper()}] {title}")

    def _log(self, message, level='info'):
        entry = f"[HEADERS] {message}"
        self.logs.append({'level': level, 'message': entry})
        logger.info(entry) if level == 'info' else logger.warning(entry)
