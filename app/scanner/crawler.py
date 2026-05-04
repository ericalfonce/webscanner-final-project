"""
URL Crawler Module
Discovers pages and input fields on the target website.
Only follows links within the same domain (scope control).
"""

import time
import logging
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
from collections import deque

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


class Crawler:
    """
    Simple breadth-first web crawler.
    Discovers URLs and form inputs within the target domain.
    """

    def __init__(self, base_url, session, max_pages=50, max_depth=2,
                 delay=0.5, timeout=10):
        self.base_url  = base_url.rstrip('/')
        self.session   = session
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.delay     = delay
        self.timeout   = timeout

        parsed = urlparse(base_url)
        self.base_domain = parsed.netloc   # e.g. "testsite.com"
        self.base_scheme = parsed.scheme   # "http" or "https"

        # Results
        self.visited_urls: set       = set()
        self.pages: list             = []   # list of PageInfo dicts
        self.crawl_log: list         = []   # plain-text log entries

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def crawl(self):
        """
        Start crawling from base_url.
        Returns list of PageInfo dicts with 'url', 'params', 'forms'.
        """
        queue = deque()
        queue.append((self.base_url, 0))   # (url, depth)
        self.visited_urls.add(self.base_url)

        while queue and len(self.pages) < self.max_pages:
            url, depth = queue.popleft()
            self._log(f"Crawling [{depth}]: {url}")

            page_info = self._fetch_and_parse(url)
            if page_info is None:
                continue

            self.pages.append(page_info)

            # Don't recurse beyond max_depth
            if depth >= self.max_depth:
                continue

            # Enqueue discovered links
            for link in page_info['links']:
                norm = self._normalize_url(link)
                if norm and norm not in self.visited_urls and self._in_scope(norm):
                    self.visited_urls.add(norm)
                    queue.append((norm, depth + 1))

            time.sleep(self.delay)

        self._log(f"Crawl finished — {len(self.pages)} pages found.")
        return self.pages

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fetch_and_parse(self, url):
        """
        Fetch a single URL and extract links + forms.
        Returns a PageInfo dict or None on error.
        """
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            resp.raise_for_status()
        except requests.exceptions.Timeout:
            self._log(f"TIMEOUT: {url}", level='warning')
            return None
        except requests.exceptions.RequestException as e:
            self._log(f"ERROR fetching {url}: {e}", level='error')
            return None

        soup = BeautifulSoup(resp.text, 'html.parser')

        links  = self._extract_links(soup, url)
        forms  = self._extract_forms(soup, url)
        params = self._extract_url_params(url)

        return {
            'url':    url,
            'status': resp.status_code,
            'links':  links,
            'forms':  forms,
            'params': params,
        }

    def _extract_links(self, soup, base_url):
        """Return all href/src links found on the page."""
        links = set()
        tags = [
            ('a',      'href'),
            ('form',   'action'),
            ('script', 'src'),
            ('link',   'href'),
        ]
        for tag, attr in tags:
            for element in soup.find_all(tag, **{attr: True}):
                href = element.get(attr, '').strip()
                if href and not href.startswith(('javascript:', '#', 'mailto:', 'tel:')):
                    full = urljoin(base_url, href)
                    links.add(full)
        return list(links)

    def _extract_forms(self, soup, page_url):
        """
        Return a list of form descriptors.
        Each descriptor has: action, method, inputs (list of dicts).
        """
        forms = []
        for form in soup.find_all('form'):
            action = form.get('action', '').strip() or page_url
            action = urljoin(page_url, action)
            method = form.get('method', 'get').lower()

            inputs = []
            for inp in form.find_all(['input', 'textarea', 'select']):
                inp_type = inp.get('type', 'text').lower()
                inp_name = inp.get('name', '').strip()
                if inp_name and inp_type not in ('submit', 'reset', 'button', 'image', 'file'):
                    inputs.append({
                        'name':  inp_name,
                        'type':  inp_type,
                        'value': inp.get('value', ''),
                    })

            if inputs:  # only record forms that have testable inputs
                forms.append({
                    'action': action,
                    'method': method,
                    'inputs': inputs,
                })

        return forms

    def _extract_url_params(self, url):
        """Return URL query parameters as a dict of name→[values]."""
        parsed = urlparse(url)
        return parse_qs(parsed.query)

    def _normalize_url(self, url):
        """
        Normalise a URL — remove fragments, strip trailing slashes.
        Returns None if the URL is not valid HTTP(S).
        """
        try:
            p = urlparse(url)
            if p.scheme not in ('http', 'https'):
                return None
            # Remove fragment
            clean = urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ''))
            return clean.rstrip('/')
        except Exception:
            return None

    def _in_scope(self, url):
        """Return True only if the URL belongs to the same domain."""
        try:
            return urlparse(url).netloc == self.base_domain
        except Exception:
            return False

    def _log(self, message, level='info'):
        entry = f"[CRAWLER] {message}"
        self.crawl_log.append({'level': level, 'message': entry})
        if level == 'warning':
            logger.warning(entry)
        elif level == 'error':
            logger.error(entry)
        else:
            logger.info(entry)
