"""Conservative article text extraction with robots.txt and same-site checks."""

from __future__ import annotations

import logging
import re
import time
import unicodedata
from difflib import SequenceMatcher
from urllib.robotparser import RobotFileParser
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from .config import request_timeout
from .url_safety import is_public_https_url

logger = logging.getLogger(__name__)
USER_AGENT = "ETHIO-CYBER-INTEL/0.2 (+local research RSS reader)"
MIN_ARTICLE_TEXT_LENGTH = 250
_TITLE_WORD_RE = re.compile(r"[a-z0-9]+", re.IGNORECASE)


def clean_html(value: str | None) -> str:
    """Convert HTML or encoded text to normalized plain text."""
    if not value:
        return ""
    soup = BeautifulSoup(value, "html.parser")
    for node in soup(["script", "style", "noscript", "svg", "iframe"]):
        node.decompose()
    return " ".join(soup.get_text(" ", strip=True).split())


def _canonical_path(url: str) -> tuple[str, str] | None:
    """Return normalized host/path identity, excluding harmless query strings."""
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
        return None
    return parsed.hostname.lower(), parsed.path.rstrip("/") or "/"


def _title_matches(expected: str, observed: str) -> bool:
    """Conservatively compare feed and page headlines without requiring equality."""
    expected_norm = unicodedata.normalize("NFKC", expected).casefold()
    observed_norm = unicodedata.normalize("NFKC", observed).casefold()
    expected_words = set(_TITLE_WORD_RE.findall(expected_norm))
    observed_words = set(_TITLE_WORD_RE.findall(observed_norm))
    overlap = expected_words & observed_words
    coverage = len(overlap) / max(1, len(expected_words))
    sequence_ratio = SequenceMatcher(None, expected_norm, observed_norm).ratio()
    return len(overlap) >= 2 and max(coverage, sequence_ratio) >= 0.60


def _token_overlap(reference: str, candidate: str) -> float:
    """Measure whether a candidate body contains terms from known article text."""
    reference_tokens = set(_TITLE_WORD_RE.findall(unicodedata.normalize("NFKC", reference).casefold()))
    candidate_tokens = set(_TITLE_WORD_RE.findall(unicodedata.normalize("NFKC", candidate).casefold()))
    if not reference_tokens:
        return 0.0
    return len(reference_tokens & candidate_tokens) / len(reference_tokens)


class ArticleExtractor:
    """Fetch only same-publisher public pages that robots.txt permits."""

    def __init__(self, *, session=None, timeout: float | None = None):
        self._owns_session = session is None
        self.session = session if session is not None else requests.Session()
        self.timeout = timeout or request_timeout()
        self._robots: dict[str, RobotFileParser | None] = {}
        self._last_request: dict[str, float] = {}

    def close(self) -> None:
        """Close the internally created HTTP session, if owned by this instance."""
        if self._owns_session:
            self.session.close()

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

    def extract(
        self, url: str, *, allowed_hostname: str, expected_title: str | None = None,
        expected_description: str | None = None, delay_seconds: float = 0.5,
    ) -> str | None:
        """Return article text only when URL, page headline, and body agree.

        Missing identity evidence fails closed. RSS metadata remains available to
        the caller when extraction is declined.
        """
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        if (not is_public_https_url(url) or not host or host != allowed_hostname.lower()
                or not expected_title or not expected_title.strip()):
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

        canonical = soup.find("link", rel=lambda value: value and "canonical" in value)
        if canonical and canonical.get("href"):
            actual_identity = _canonical_path(url)
            canonical_identity = _canonical_path(canonical["href"])
            if actual_identity is None or canonical_identity != actual_identity:
                logger.info("Canonical URL does not match requested article URL: %s", url)
                return None

        page_titles = []
        for attrs in ({"property": "og:title"}, {"name": "twitter:title"}):
            node = soup.find("meta", attrs=attrs)
            if node and node.get("content"):
                page_titles.append(node["content"].strip())
        page_titles.extend(node.get_text(" ", strip=True) for node in soup.find_all("h1"))
        if soup.title:
            page_titles.append(soup.title.get_text(" ", strip=True))
        if not any(_title_matches(expected_title, title) for title in page_titles if title):
            logger.info("Page headline does not match RSS title; skipping extraction for %s", url)
            return None

        for node in soup(["script", "style", "noscript", "svg", "iframe", "nav", "footer", "header", "aside"]):
            node.decompose()

        # Prefer explicit article-body containers. Many publishers use <article>
        # for recommendation cards, so the first generic article element is not
        # evidence that it contains the requested report.
        candidates = []
        for selector in (
            '[itemprop="articleBody"]', "#articleBody", "#articlebody", "#article-body",
            ".article-body", ".articleBody", ".article-content", ".post-body", ".entry-content",
            ".story-body",
        ):
            candidates.extend(soup.select(selector))
        if not candidates:
            candidates.extend(
                node for node in soup.find_all("article")
                if _title_matches(expected_title, node.get_text(" ", strip=True))
            )

        matched_candidates = []
        expected_description = clean_html(expected_description)
        for candidate in candidates:
            text = " ".join(candidate.get_text(" ", strip=True).split())
            if len(text) < MIN_ARTICLE_TEXT_LENGTH:
                continue
            description_overlap = _token_overlap(expected_description, text) if expected_description else 0.0
            title_overlap = _token_overlap(expected_title, text)
            # A headline match on the page is not enough: recommendation cards
            # and ads can sit beside a valid headline. Prefer a body that also
            # corroborates the RSS lead/title, and reject low-overlap candidates.
            if expected_description:
                if description_overlap < 0.35 and title_overlap < 0.40:
                    continue
            elif title_overlap < 0.25:
                continue
            matched_candidates.append((description_overlap * 3.0 + title_overlap, len(text), text))
        if matched_candidates:
            # Prefer the strongest text match; ties prefer the more focused
            # container over a parent that may include unrelated page modules.
            matched_candidates.sort(key=lambda item: (-item[0], item[1]))
            return matched_candidates[0][2]
        logger.info("No sufficiently substantial article body matched %s", url)
        return None
