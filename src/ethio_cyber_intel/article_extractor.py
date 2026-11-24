"""Conservative article text extraction with robots.txt and same-site checks."""

from __future__ import annotations

import logging
import time
from urllib.robotparser import RobotFileParser
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from .config import request_timeout

logger = logging.getLogger(__name__)
USER_AGENT = "ETHIO-CYBER-INTEL/0.2 (+local research RSS reader)"


def clean_html(value: str | None) -> str:
    """Convert HTML or encoded text to normalized plain text."""
    if not value:
        return ""
    soup = BeautifulSoup(value, "html.parser")
    for node in soup(["script", "style", "noscript", "svg", "iframe"]):
        node.decompose()
    return " ".join(soup.get_text(" ", strip=True).split())


class ArticleExtractor:
    """Fetch only same-publisher public pages that robots.txt permits."""

    def __init__(self, *, session=None, timeout: float | None = None):
        self.session = session or requests.Session()
        self.timeout = timeout or request_timeout()
        self._robots: dict[str, RobotFileParser | None] = {}
        self._last_request: dict[str, float] = {}

    def _robots_for(self, origin: str) -> RobotFileParser | None:
        if origin in self._robots:
            return self._robots[origin]
        robots_url = origin.rstrip("/") + "/robots.txt"
        parser = RobotFileParser()
        parser.set_url(robots_url)
        try:
            response = self.session.get(
                robots_url, headers={"User-Agent": USER_AGENT}, timeout=self.timeout,
                allow_redirects=False,
            )
            if response.status_code == 404:
                parser.parse([])
                self._robots[origin] = parser
            elif 200 <= response.status_code < 300:
                parser.parse(response.text.splitlines())
                self._robots[origin] = parser
            else:
                logger.info("Cannot check robots.txt for %s (HTTP %s); skipping page", origin, response.status_code)
                self._robots[origin] = None
        except requests.RequestException:
            logger.info("Cannot fetch robots.txt for %s; skipping page", origin, exc_info=True)
            self._robots[origin] = None
        return self._robots[origin]

    def extract(self, url: str, *, allowed_hostname: str, delay_seconds: float = 0.5) -> str | None:
        """Return readable article text, or None if inaccessible or disallowed."""
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or not host or host != allowed_hostname.lower():
            return None
        origin = f"https://{host}"
        robots = self._robots_for(origin)
        if robots is None or not robots.can_fetch(USER_AGENT, url):
            return None

        remaining = delay_seconds - (time.monotonic() - self._last_request.get(host, 0.0))
        if remaining > 0:
            time.sleep(remaining)
        try:
            response = self.session.get(
                url, headers={"User-Agent": USER_AGENT}, timeout=self.timeout,
                allow_redirects=False,
            )
            response.raise_for_status()
        except requests.RequestException:
            logger.info("Could not fetch article page %s", url, exc_info=True)
            return None
        finally:
            self._last_request[host] = time.monotonic()
        if "html" not in response.headers.get("Content-Type", "").lower():
            return None
        soup = BeautifulSoup(response.content, "html.parser")
        for node in soup(["script", "style", "noscript", "svg", "iframe", "nav", "footer", "header"]):
            node.decompose()
        main = soup.find("article") or soup.find("main") or soup.body or soup
        text = " ".join(main.get_text(" ", strip=True).split())
        return text or None
