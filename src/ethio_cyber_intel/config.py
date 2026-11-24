"""Environment-backed application configuration."""

from __future__ import annotations

import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def database_path() -> Path:
    """Return configured SQLite path, resolving relative values from project root."""
    raw_path = os.getenv("ETHIO_CYBER_DB_PATH", "data/ethio_cyber_intel.db")
    path = Path(raw_path).expanduser()
    return path if path.is_absolute() else PROJECT_ROOT / path


def seed_demo_enabled() -> bool:
    """Whether to insert sample data into a new, empty database."""
    return os.getenv("ETHIO_CYBER_SEED_DEMO", "true").strip().lower() in {
        "1", "true", "yes", "on"
    }


def feed_sources_path() -> Path:
    """Return RSS source configuration path."""
    raw_path = os.getenv("ETHIO_CYBER_FEEDS_FILE", "config/rss_sources.json")
    path = Path(raw_path).expanduser()
    return path if path.is_absolute() else PROJECT_ROOT / path


def request_timeout() -> float:
    """HTTP timeout in seconds for feeds and allowed article pages."""
    try:
        return max(1.0, float(os.getenv("ETHIO_CYBER_HTTP_TIMEOUT", "12")))
    except ValueError:
        return 12.0
