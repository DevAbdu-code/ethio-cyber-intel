"""Load and validate editable RSS source configuration."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from .config import feed_sources_path
from .url_safety import is_public_https_url

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class FeedSource:
    name: str
    url: str
    homepage: str
    enabled: bool = True
    verification_status: str = "pending_network_check"
    max_articles: int = 10
    delay_seconds: float = 0.5

    @property
    def hostname(self) -> str:
        return (urlparse(self.homepage).hostname or "").lower()


def load_sources(path: str | Path | None = None, *, enabled_only: bool = False) -> list[FeedSource]:
    """Load sources from JSON; invalid entries are logged and ignored."""
    config_path = Path(path) if path else feed_sources_path()
    try:
        raw_sources = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        logger.warning("RSS source configuration does not exist: %s", config_path)
        return []
    except (OSError, json.JSONDecodeError):
        logger.exception("Could not read RSS source configuration: %s", config_path)
        return []
    if not isinstance(raw_sources, list):
        logger.error("RSS source configuration must be a JSON list: %s", config_path)
        return []

    sources = []
    for item in raw_sources:
        try:
            source = FeedSource(
                name=str(item["name"]).strip(),
                url=str(item["url"]).strip(),
                homepage=str(item.get("homepage", item["url"])).strip(),
                enabled=bool(item.get("enabled", True)),
                verification_status=str(item.get("verification_status", "pending_network_check")),
                max_articles=max(1, min(50, int(item.get("max_articles", 10)))),
                delay_seconds=max(0.0, min(10.0, float(item.get("delay_seconds", 0.5)))),
            )
            if not source.name or not is_public_https_url(source.url) or not is_public_https_url(source.homepage):
                raise ValueError("name, public HTTPS feed URL, and homepage are required")
            if enabled_only and not source.enabled:
                continue
            sources.append(source)
        except (KeyError, TypeError, ValueError):
            logger.warning("Ignoring invalid RSS source config entry: %r", item)
    return sources
