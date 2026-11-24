"""Fetch, parse, normalize, and optionally enrich RSS entries."""

from __future__ import annotations

import calendar
import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import feedparser
import requests

from .article_extractor import ArticleExtractor, USER_AGENT, clean_html
from .config import request_timeout
from .language_detection import detect_article_language
from .rss_sources import FeedSource

logger = logging.getLogger(__name__)


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
    if not title or parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    description = clean_html(entry.get("summary") or entry.get("description"))
    content = ""
    for block in entry.get("content", []) or []:
        content = clean_html(block.get("value", ""))
        if content:
            break
    if not content and extractor:
        content = extractor.extract(
            link, allowed_hostname=source.hostname, delay_seconds=source.delay_seconds
        ) or ""
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
    http = session or requests.Session()
    try:
        response = http.get(
            source.url, headers={"User-Agent": USER_AGENT, "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml"},
            timeout=timeout or request_timeout(),
        )
        response.raise_for_status()
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
    for entry in entries[: source.max_articles]:
        article = normalize_entry(entry, source, extractor=extractor)
        if article:
            normalized.append(article)
    result["articles"] = normalized
    result["status"] = "ok_with_warning" if getattr(parsed_feed, "bozo", False) else "ok"
    result["message"] = f"Parsed {len(normalized)} entries"
    if len(normalized) < len(entries[: source.max_articles]):
        result["message"] += f"; skipped {len(entries[: source.max_articles]) - len(normalized)} malformed entries"
    return result


def collect_all(
    sources: list[FeedSource], *, session=None, extractor: ArticleExtractor | None = None
) -> list[dict[str, Any]]:
    """Collect each source independently so one failure never stops the others."""
    results = []
    for source in sources:
        try:
            results.append(collect_source(source, session=session, extractor=extractor))
        except Exception:
            logger.exception("Unexpected collection failure for %s", source.name)
            results.append({
                "source": source.name, "url": source.url, "status": "error",
                "message": "Unexpected collection error", "entries_seen": 0, "articles": [],
            })
    return results
