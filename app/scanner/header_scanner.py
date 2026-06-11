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
        'what': (
            "X-Frame-Options tells the browser whether your page is allowed to be loaded inside an <iframe>.\n\n"
            "Without this header, any other website can silently embed your page inside their own page "
            "using an invisible iframe and position it so that clicks meant for the attacker's page "
            "actually hit your page — this attack is called Clickjacking."
        ),
        'attack_scenario': (
            "Attack: an attacker builds a page like:\n"
            "  <iframe src='https://your-bank.com/transfer' style='opacity:0; position:absolute; top:0; left:0; width:100%; height:100%'></iframe>\n"
            "  <button style='position:absolute; top:200px; left:300px'>Click to win a prize!</button>\n\n"
            "The victim sees a 'prize' button but clicks the invisible 'Transfer money' button on your site underneath. "
            "Because the victim is already logged in, the transfer goes through."
        ),
        'safe_code': (
            "# Nginx\nadd_header X-Frame-Options 'DENY' always;\n\n"
            "# Apache\nHeader always set X-Frame-Options 'DENY'\n\n"
            "# Flask (Flask-Talisman handles this automatically)\nfrom flask_talisman import Talisman\nTalisman(app)"
        ),
        'real_impact': (
            "Clickjacking has been used to:\n"
            "• Trick users into approving OAuth permissions for malicious apps\n"
            "• Force users to unknowingly like/share attacker content (Likejacking)\n"
            "• Initiate financial transfers on banking sites\n"
            "• Enable camera/microphone by clicking disguised permission dialogs"
        ),
        'fix': (
            "Add to every response:\n"
            "  X-Frame-Options: DENY\n\n"
            "Use DENY unless your site legitimately needs to be iframed by itself, in which case:\n"
            "  X-Frame-Options: SAMEORIGIN\n\n"
            "Modern alternative (more flexible):\n"
            "  Content-Security-Policy: frame-ancestors 'none'"
        ),
        'owasp': 'https://owasp.org/www-community/attacks/Clickjacking',
        'cvss':  'CVSS 4.3 Medium — requires victim interaction, but can trigger high-impact actions',
    },
    'X-Content-Type-Options': {
        'what': (
            "X-Content-Type-Options: nosniff tells the browser to strictly honour the Content-Type header "
            "the server sends and never 'sniff' (guess) the actual file type from its contents.\n\n"
            "Without this, browsers use heuristics to detect file types — a feature that attackers can exploit."
        ),
        'attack_scenario': (
            "Attack scenario:\n"
            "1. Attacker uploads a file called 'photo.jpg' to your site\n"
            "2. The file actually contains JavaScript code, not image data\n"
            "3. Server serves it with Content-Type: image/jpeg\n"
            "4. Without nosniff, older browsers detect the JS content and execute it as a script\n"
            "5. The attacker now has XSS via a seemingly innocent file upload"
        ),
        'safe_code': (
            "# Nginx\nadd_header X-Content-Type-Options 'nosniff' always;\n\n"
            "# Apache\nHeader always set X-Content-Type-Options 'nosniff'\n\n"
            "# Flask\n@app.after_request\ndef set_headers(response):\n    response.headers['X-Content-Type-Options'] = 'nosniff'\n    return response"
        ),
        'real_impact': (
            "MIME sniffing vulnerabilities are particularly dangerous in combination with file upload features. "
            "Any site that lets users upload files and then serves those files is potentially affected. "
            "This header is a quick, zero-tradeoff fix — enabling it has no negative side effects."
        ),
        'fix': "Add to every response: X-Content-Type-Options: nosniff\nThis is a single header with zero configuration. Just add it.",
        'owasp': 'https://owasp.org/www-community/attacks/MIME_sniffing',
        'cvss':  'CVSS 4.3 Low-Medium — enables other attacks, not directly exploitable alone',
    },
    'X-XSS-Protection': {
        'what': (
            "X-XSS-Protection enables a built-in reflected XSS filter in older browsers (Internet Explorer, "
            "old Chrome, old Safari). It detects and blocks certain obvious reflected XSS patterns.\n\n"
            "Modern browsers (Chrome 78+, Firefox, Edge) have deprecated this header in favour of "
            "Content-Security-Policy, but it still matters for users on older or embedded browsers."
        ),
        'attack_scenario': (
            "Without this header, older browsers that have the XSS filter available but not enabled "
            "will not automatically block reflected XSS patterns in URL parameters. "
            "A targeted attacker who knows the victim is on IE11 or an old mobile browser could "
            "craft a URL that exploits reflected XSS specifically because the filter is off."
        ),
        'safe_code': (
            "# Nginx\nadd_header X-XSS-Protection '1; mode=block' always;\n\n"
            "# Apache\nHeader always set X-XSS-Protection '1; mode=block'\n\n"
            "# Note: This is a legacy header. The real fix is CSP:\nadd_header Content-Security-Policy \"script-src 'self'\" always;"
        ),
        'real_impact': (
            "This header's impact is mostly historical — modern browsers have removed it. "
            "However, enabling it costs nothing and provides a safety net for:\n"
            "• Users on older corporate IE11 environments\n"
            "• Embedded WebView browsers in mobile apps\n"
            "• Legacy intranet applications\n\n"
            "Do NOT rely solely on this header. A Content-Security-Policy is the robust solution."
        ),
        'fix': (
            "Short term: Add X-XSS-Protection: 1; mode=block\n\n"
            "Long term (the real fix): Implement Content-Security-Policy.\n"
            "CSP makes this header redundant for modern browsers and is far more powerful."
        ),
        'owasp': 'https://owasp.org/www-community/attacks/xss/',
        'cvss':  'Informational — legacy header; real protection comes from CSP',
    },
    'Strict-Transport-Security': {
        'what': (
            "HTTP Strict Transport Security (HSTS) tells the browser to ONLY connect to your site "
            "over HTTPS — even if the user types 'http://' or clicks an http:// link.\n\n"
            "Once a browser sees this header, it will automatically upgrade all connections for "
            "max-age seconds — protecting users even when they don't type https:// explicitly."
        ),
        'attack_scenario': (
            "Without HSTS, an attacker on the same Wi-Fi (coffee shop, airport) can:\n"
            "1. Intercept the user's initial HTTP request (before they're redirected to HTTPS)\n"
            "2. Sit between the user and the server (SSL stripping / Man-in-the-Middle)\n"
            "3. Downgrade the connection: serve HTTP to the victim while talking HTTPS to your server\n"
            "4. Read all traffic in plaintext — passwords, session cookies, personal data\n\n"
            "Tool used in real attacks: sslstrip by Moxie Marlinspike"
        ),
        'safe_code': (
            "# Nginx\nadd_header Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload' always;\n\n"
            "# Apache\nHeader always set Strict-Transport-Security 'max-age=31536000; includeSubDomains; preload'\n\n"
            "# Flask-Talisman (handles HSTS automatically)\nTalisman(app, strict_transport_security=True,\n"
            "         strict_transport_security_max_age=31536000,\n"
            "         strict_transport_security_include_subdomains=True)"
        ),
        'real_impact': (
            "HSTS prevents a class of attack that is trivially easy on public networks:\n"
            "• Used in hotel and airport Wi-Fi attacks to capture credentials\n"
            "• SSL stripping attacks were common before HSTS was widespread\n"
            "• Google has required HSTS for all .google.com domains since 2010\n\n"
            "Without HSTS, your HTTPS padlock offers zero protection if a user is on a hostile network."
        ),
        'fix': (
            "Add to HTTPS responses only (not HTTP):\n"
            "  Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n\n"
            "max-age=31536000 = 1 year. Start with a shorter value (86400 = 1 day) to test first.\n"
            "includeSubDomains extends protection to all subdomains.\n"
            "preload submits your site to browser HSTS preload lists (hstspreload.org)."
        ),
        'owasp': 'https://owasp.org/www-community/controls/HTTP_Strict_Transport_Security_Cheat_Sheet',
        'cvss':  'CVSS 5.9 Medium — enables MITM attacks on hostile networks without HSTS',
    },
    'Content-Security-Policy': {
        'what': (
            "Content-Security-Policy (CSP) is the most powerful header for preventing XSS. "
            "It tells the browser exactly which sources it's allowed to load scripts, styles, "
            "images, and other resources from — and blocks everything else.\n\n"
            "A script injected by an attacker won't execute if the CSP doesn't whitelist its source. "
            "Think of it as a firewall for your page's content."
        ),
        'attack_scenario': (
            "Without CSP:\n"
            "• An attacker injects <script src='https://evil.com/steal.js'></script>\n"
            "• The browser happily loads and executes the remote script\n"
            "• The script logs keystrokes, steals cookies, exfiltrates form data\n\n"
            "With CSP (script-src 'self'):\n"
            "• Browser sees the injected script points to evil.com\n"
            "• evil.com is not in the whitelist — script is blocked, never downloaded"
        ),
        'safe_code': (
            "# Nginx — strict policy\n"
            "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' fonts.gstatic.com; frame-ancestors 'none'\" always;\n\n"
            "# Flask-Talisman\nTalisman(app, content_security_policy={\n"
            "    'default-src': \"'self'\",\n"
            "    'script-src': \"'self'\",\n"
            "    'style-src': \"'self' 'unsafe-inline'\",\n"
            "})"
        ),
        'real_impact': (
            "CSP is the industry-standard last line of defence against XSS:\n"
            "• Google, GitHub, Twitter, Facebook — all enforce strict CSPs\n"
            "• The 2018 British Airways Magecart attack injected a payment-skimming script;\n"
            "  a strict CSP would have blocked it\n"
            "• OWASP ranks missing CSP as a top misconfiguration\n\n"
            "Note: CSP does not replace input sanitisation — it is defence-in-depth."
        ),
        'fix': (
            "Start with a Report-Only policy to see what would break:\n"
            "  Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report\n\n"
            "Then enforce:\n"
            "  Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'\n\n"
            "Avoid 'unsafe-inline' and 'unsafe-eval' in script-src — they defeat most XSS protections.\n"
            "Use nonces or hashes instead: script-src 'nonce-{random}'."
        ),
        'owasp': 'https://owasp.org/www-community/controls/Content_Security_Policy',
        'cvss':  'CVSS 6.1+ — missing CSP allows XSS payloads to load external scripts unrestricted',
    },
    'Referrer-Policy': {
        'what': (
            "When a user clicks a link on your site, the browser automatically sends the current page URL "
            "as the 'Referer' header to the destination site. Referrer-Policy controls how much of that URL is shared.\n\n"
            "This matters because URLs often contain sensitive data: session tokens, user IDs, "
            "search terms, password reset tokens, document IDs."
        ),
        'attack_scenario': (
            "Example vulnerable URL: https://yoursite.com/reset-password?token=abc123secret\n\n"
            "If this page has a link to an analytics provider or social media button,\n"
            "the browser sends:\n"
            "  Referer: https://yoursite.com/reset-password?token=abc123secret\n\n"
            "The third-party site now has the password reset token. "
            "If the attacker controls that third party, they can reset your user's password."
        ),
        'safe_code': (
            "# Nginx\nadd_header Referrer-Policy 'strict-origin-when-cross-origin' always;\n\n"
            "# Apache\nHeader always set Referrer-Policy 'strict-origin-when-cross-origin'\n\n"
            "# Flask\n@app.after_request\ndef set_referrer(response):\n    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'\n    return response"
        ),
        'real_impact': (
            "Referrer leakage has enabled real attacks:\n"
            "• Login tokens in URLs sent to analytics providers — exposing user sessions\n"
            "• Internal document IDs leaked to CDN providers via Referer headers\n"
            "• Password reset links shared via Referer to third-party scripts on the same page\n\n"
            "This is especially dangerous on pages with third-party widgets (chat, analytics, ads)."
        ),
        'fix': (
            "Add: Referrer-Policy: strict-origin-when-cross-origin\n\n"
            "This sends the full URL for same-origin requests (helpful for analytics)\n"
            "but only the origin (e.g. https://yoursite.com) for cross-origin requests.\n\n"
            "If stricter privacy is needed:\n"
            "  Referrer-Policy: no-referrer"
        ),
        'owasp': 'https://owasp.org/www-project-secure-headers/',
        'cvss':  'CVSS 3.1 Low — information disclosure; impact depends on what is in the URL',
    },
    'Permissions-Policy': {
        'what': (
            "Permissions-Policy (formerly Feature-Policy) controls which browser APIs your page "
            "and any embedded third-party iframes are allowed to use: camera, microphone, "
            "geolocation, payment, USB, Bluetooth, and more.\n\n"
            "Without this header, third-party scripts or embedded content could request access to "
            "these powerful APIs — sometimes silently."
        ),
        'attack_scenario': (
            "Attack scenario without Permissions-Policy:\n"
            "1. Your page includes a third-party ad or chat widget\n"
            "2. The widget is compromised by an attacker\n"
            "3. The widget calls navigator.geolocation.getCurrentPosition() or navigator.mediaDevices.getUserMedia()\n"
            "4. The browser prompts the user to allow camera/location — and they might click Allow,\n"
            "   thinking it's from your site\n"
            "5. Attacker now receives the user's location or camera feed"
        ),
        'safe_code': (
            "# Nginx — disable all by default, enable only what you need\n"
            "add_header Permissions-Policy 'geolocation=(), microphone=(), camera=(), payment=(), usb=()' always;\n\n"
            "# If your site uses geolocation:\n"
            "add_header Permissions-Policy 'geolocation=(self), microphone=(), camera=()' always;"
        ),
        'real_impact': (
            "Permissions-Policy protects against:\n"
            "• Malicious third-party scripts silently accessing camera or microphone\n"
            "• Geolocation tracking via compromised ad networks\n"
            "• Payment API abuse by injected scripts on checkout pages\n\n"
            "This is especially important for sites embedding third-party widgets, chat tools, or advertisements."
        ),
        'fix': (
            "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()\n\n"
            "Start by disabling everything, then add back APIs your site actually needs:\n"
            "  Permissions-Policy: geolocation=(self), microphone=()\n\n"
            "'self' = only your own origin can use the API.\n"
            "'()' = nobody can use it (including iframes)."
        ),
        'owasp': 'https://owasp.org/www-project-secure-headers/',
        'cvss':  'CVSS 2.6 Low — enables third-party access to hardware APIs without user intent',
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
