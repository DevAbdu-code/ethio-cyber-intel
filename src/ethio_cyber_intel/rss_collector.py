"""Fetch, parse, normalize, and optionally enrich RSS entries."""

from __future__ import annotations

import calendar
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse

import feedparser
import requests

from .article_extractor import ArticleExtractor, USER_AGENT, clean_html
from .config import request_timeout
from .language_detection import detect_article_language
from .rss_sources import FeedSource
from .url_safety import is_public_https_url

logger = logging.getLogger(__name__)
_REDIRECT_CODES = {301, 302, 303, 307, 308}
_MAX_FEED_REDIRECTS = 5


def _get_feed_response(http, url: str, timeout: float):
    """Follow a small number of redirects, revalidating every destination."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml",
    }
    current_url = url
    for redirect_count in range(_MAX_FEED_REDIRECTS + 1):
        response = http.get(current_url, headers=headers, timeout=timeout, allow_redirects=False)
        status = getattr(response, "status_code", 200)
        # Lightweight test doubles may omit an HTTP status. Real requests
        # responses always provide an integer status code.
        if not isinstance(status, int):
            response.raise_for_status()
            return response
        if status in _REDIRECT_CODES:
            location = getattr(response, "headers", {}).get("Location")
            target = urljoin(current_url, location or "")
            if redirect_count >= _MAX_FEED_REDIRECTS:
                raise requests.TooManyRedirects("RSS feed exceeded redirect limit")
            if not location or not is_public_https_url(target):
                raise requests.RequestException("RSS redirect target is not an allowed public HTTPS URL")
            close_response = getattr(response, "close", None)
            if callable(close_response):
                close_response()
            current_url = target
            continue
        if 300 <= status < 400:
            raise requests.RequestException(f"Unexpected RSS HTTP redirect status {status}")
        response.raise_for_status()
        return response
    raise requests.TooManyRedirects("RSS feed exceeded redirect limit")


def _published(entry: Any) -> str | None:
    """Convert a parsed RSS date to UTC ISO format; preserve missing as None."""
    parsed = entry.get("published_parsed") or entry.get("updated_parsed")
    if not parsed:
        return None
    try:
        value = datetime.fromtimestamp(calendar.timegm(parsed), tz=timezone.utc)
        return value.isoformat().replace("+00:00", "Z")
    except (OverflowError, TypeError, ValueError):
        return None


def normalize_entry(
    entry: Any,
    source: FeedSource,
    *,
    extractor: ArticleExtractor | None = None,
) -> dict[str, Any] | None:
    """Map a feed item to database fields; malformed entries are skipped."""
    title = clean_html(entry.get("title"))
    link = str(entry.get("link", "")).strip()
    parsed = urlparse(link)
    if (not title or parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username or parsed.password):
        return None
    description = clean_html(entry.get("summary") or entry.get("description"))
    content = ""
    content_validation_status = "not_available"
    for block in entry.get("content", []) or []:
        content = clean_html(block.get("value", ""))
        if content:
            content_validation_status = "rss_feed_entry"
            break
    if not content and extractor:
        try:
            content = extractor.extract(
                link, allowed_hostname=source.hostname, expected_title=title,
                expected_description=description,
                delay_seconds=source.delay_seconds,
            ) or ""
            if not content:
                content_validation_status = "extraction_rejected"
        except Exception:
            logger.warning("Optional article extraction failed for %s", link, exc_info=True)
            content_validation_status = "extraction_rejected"
        if content:
            content_validation_status = "page_identity_verified"
    detection = detect_article_language(
        title=title,
        description=description,
        content=content or None,
    )
    return {
        "title": title,
        "url": link,
        "source": source.name,
        "published_at": _published(entry),
        "language": detection.language,
        "language_confidence": detection.confidence,
        "language_method": detection.method,
        "language_reviewed": 0,
        "summary": description or None,
        "content": content or None,
        "content_validation_status": content_validation_status,
    }


def collect_source(
    source: FeedSource,
    *,
    session=None,
    extractor: ArticleExtractor | None = None,
    timeout: float | None = None,
) -> dict[str, Any]:
    """Fetch and parse one source, returning status and normalized articles."""
    result: dict[str, Any] = {
        "source": source.name, "url": source.url, "status": "error",
        "message": "", "entries_seen": 0, "articles": [],
    }
    if not source.enabled:
        result.update(status="disabled", message="Source disabled in configuration")
        return result
    if not is_public_https_url(source.url):
        result.update(status="invalid", message="Feed URL must be a public HTTPS endpoint without credentials")
        logger.warning("Rejected unsafe RSS URL for %s", source.name)
        return result
    owns_session = session is None
    http = session if session is not None else requests.Session()
    try:
        response = _get_feed_response(http, source.url, timeout or request_timeout())
        parsed_feed = feedparser.parse(response.content)
    except requests.Timeout:
        result["message"] = "Request timed out"
        logger.warning("RSS timeout for %s", source.name)
        return result
    except requests.RequestException as exc:
        result["message"] = f"Network error: {exc}"
        logger.warning("RSS request failed for %s: %s", source.name, exc)
        return result
    except Exception as exc:
        result["message"] = f"Feed parsing error: {exc}"
        logger.exception("RSS parsing failed for %s", source.name)
        return result
    finally:
        if owns_session:
            http.close()

    entries = list(parsed_feed.entries or [])
    result["entries_seen"] = len(entries)
    if getattr(parsed_feed, "bozo", False) and not entries:
        result["status"] = "invalid"
        result["message"] = "Response is not a valid RSS or Atom feed"
        return result
    if not entries and not getattr(parsed_feed, "version", ""):
        result["status"] = "invalid"
        result["message"] = "Response is not a recognizable RSS or Atom feed"
        return result

    normalized = []
    skipped = 0
    for entry in entries[: source.max_articles]:
        try:
            article = normalize_entry(entry, source, extractor=extractor)
            if article:
                normalized.append(article)
            else:
                skipped += 1
        except Exception:
            skipped += 1
            logger.warning("Skipping malformed RSS item from %s", source.name, exc_info=True)
    result["articles"] = normalized
    result["status"] = "ok_with_warning" if getattr(parsed_feed, "bozo", False) else "ok"
    result["message"] = f"Parsed {len(normalized)} entries"
    if skipped:
        result["message"] += f"; skipped {skipped} malformed entries"
    return result


def collect_all(
    sources: list[FeedSource], *, session=None, extractor: ArticleExtractor | None = None
) -> list[dict[str, Any]]:
    """Collect each source independently so one failure never stops the others."""
    results = []
    owns_session = session is None
    http = session if session is not None else requests.Session()
    try:
        for source in sources:
            try:
                results.append(collect_source(source, session=http, extractor=extractor))
            except Exception:
                logger.exception("Unexpected collection failure for %s", source.name)
                results.append({
                    "source": source.name, "url": source.url, "status": "error",
                    "message": "Unexpected collection error", "entries_seen": 0, "articles": [],
                })
        return results
    finally:
        if owns_session:
            http.close()
