"""SQLite database setup and explicitly synthetic demonstration records."""

from __future__ import annotations

import hashlib
import logging
import re
import sqlite3
from pathlib import Path
from typing import Iterable

from .config import database_path

logger = logging.getLogger(__name__)

ARTICLES_TABLE_SCHEMA = """
CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,
    published_at TEXT,
    language TEXT NOT NULL CHECK (language IN ('en', 'am', 'om', 'und', 'mul')),
    language_confidence REAL CHECK (language_confidence IS NULL OR (language_confidence >= 0 AND language_confidence <= 1)),
    language_method TEXT,
    language_reviewed INTEGER NOT NULL DEFAULT 0 CHECK (language_reviewed IN (0, 1)),
    summary TEXT,
    content TEXT,
    content_fingerprint TEXT,
    threat_type TEXT NOT NULL DEFAULT 'Unclassified',
    report_status TEXT NOT NULL DEFAULT 'collected'
        CHECK (report_status IN ('demo', 'collected', 'verified_advisory')),
    is_demo INTEGER NOT NULL DEFAULT 0 CHECK (is_demo IN (0, 1)),
    fetched_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""

SCHEMA = ARTICLES_TABLE_SCHEMA + """
CREATE INDEX IF NOT EXISTS idx_articles_language ON articles(language);
CREATE INDEX IF NOT EXISTS idx_articles_published_at ON articles(published_at);
CREATE INDEX IF NOT EXISTS idx_articles_threat_type ON articles(threat_type);
CREATE UNIQUE INDEX IF NOT EXISTS idx_articles_live_fingerprint
    ON articles(content_fingerprint) WHERE content_fingerprint IS NOT NULL AND is_demo = 0;
"""

DEMO_ARTICLES = (
    {
        "title": "DEMO DATA: Example phishing awareness notice",
        "url": "https://example.org/demo/phishing-awareness-en",
        "source": "ETHIO-CYBER INTEL synthetic examples",
        "published_at": "2025-01-15T09:00:00Z",
        "language": "en",
        "summary": "Fictional example used to demonstrate the dashboard. This is not a real incident report.",
        "threat_type": "Phishing",
    },
    {
        "title": "DEMO DATA: የማስገር ጥንቃቄ ምሳሌ",
        "url": "https://example.org/demo/phishing-awareness-am",
        "source": "ETHIO-CYBER INTEL synthetic examples",
        "published_at": "2025-01-15T09:00:00Z",
        "language": "am",
        "summary": "ይህ ለዳሽቦርዱ ማሳያ የተዘጋጀ ሰው ሰራሽ ምሳሌ ነው፤ እውነተኛ የደህንነት ሪፖርት አይደለም።",
        "threat_type": "Phishing",
    },
    {
        "title": "DEMO DATA: Fakkeenya akeekkachiisa ergaa sobaa",
        "url": "https://example.org/demo/phishing-awareness-om",
        "source": "ETHIO-CYBER INTEL synthetic examples",
        "published_at": "2025-01-15T09:00:00Z",
        "language": "om",
        "summary": "Kun fakkeenya sirna agarsiisuuf qophaa'eedha; gabaasa dhugaa waa'ee miidhaa saayibarii miti.",
        "threat_type": "Phishing",
    },
)


def connect(db_path: str | Path | None = None) -> sqlite3.Connection:
    """Open a SQLite connection with row access and foreign key enforcement."""
    path = Path(db_path) if db_path is not None else database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _insert_demo_rows(connection: sqlite3.Connection, rows: Iterable[dict]) -> None:
    connection.executemany(
        """INSERT OR IGNORE INTO articles
           (title, url, source, published_at, language, summary, threat_type,
            report_status, is_demo)
           VALUES (:title, :url, :source, :published_at, :language, :summary,
                   :threat_type, 'demo', 1)""",
        rows,
    )


def initialize_database(
    db_path: str | Path | None = None, *, seed_demo: bool = True
) -> Path:
    """Create schema and seed synthetic data if requested and the store is empty."""
    path = Path(db_path) if db_path is not None else database_path()
    try:
        with connect(path) as connection:
            _migrate_articles_table(connection)
            connection.executescript(SCHEMA)
            count = connection.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
            if seed_demo and count == 0:
                _insert_demo_rows(connection, DEMO_ARTICLES)
                logger.info("Inserted %d synthetic demo articles", len(DEMO_ARTICLES))
            connection.execute(
                """UPDATE articles SET language_confidence = 1.0,
                          language_method = 'demo_labeled_example', language_reviewed = 1
                   WHERE is_demo = 1 AND language_confidence IS NULL
                     AND language_reviewed = 0 AND language_method IS NULL"""
            )
        return path
    except sqlite3.Error:
        logger.exception("Failed to initialize SQLite database at %s", path)
        raise


def _migrate_articles_table(connection: sqlite3.Connection) -> None:
    """Migrate article metadata and language constraint without losing records."""
    table = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='articles'"
    ).fetchone()
    if table is None:
        return
    columns = {row[1] for row in connection.execute("PRAGMA table_info(articles)")}
    old_sql = (table[0] or "").lower()
    required_columns = {
        "content_fingerprint", "fetched_at", "language_confidence",
        "language_method", "language_reviewed",
    }
    if "'mul'" in old_sql and required_columns.issubset(columns):
        return

    logger.info("Migrating articles table to language-aware schema")
    connection.execute("BEGIN IMMEDIATE")
    connection.execute("ALTER TABLE articles RENAME TO articles_legacy_migration")
    connection.execute(ARTICLES_TABLE_SCHEMA)
    preservable_columns = [
        "id", "title", "url", "source", "published_at", "language", "summary",
        "language_confidence", "language_method", "language_reviewed", "content",
        "content_fingerprint", "threat_type", "report_status", "is_demo", "fetched_at",
        "created_at",
    ]
    kept_columns = [column for column in preservable_columns if column in columns]
    column_sql = ", ".join(kept_columns)
    connection.execute(
        f"INSERT INTO articles ({column_sql}) SELECT {column_sql} FROM articles_legacy_migration"
    )
    old_count = connection.execute("SELECT COUNT(*) FROM articles_legacy_migration").fetchone()[0]
    new_count = connection.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
    if old_count != new_count:
        raise sqlite3.DatabaseError(
            f"Article migration count mismatch ({old_count} old, {new_count} migrated)"
        )
    connection.execute("DROP TABLE articles_legacy_migration")
    connection.execute(
        """UPDATE articles SET language_reviewed = 1,
                  language_method = 'legacy_existing_label'
           WHERE is_demo = 0 AND language IN ('en', 'am', 'om')
             AND language_method IS NULL"""
    )
    connection.commit()


def content_fingerprint(
    title: str | None, description: str | None, content: str | None
) -> str | None:
    """Hash normalized article text for exact-content duplicate detection."""
    text = " ".join([title or "", description or "", content or ""]).lower()
    text = " ".join(text.split())
    text = re.sub(r"[^\w\s]", " ", text, flags=re.UNICODE)
    text = " ".join(text.split())
    if len(text) < 40:
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def insert_live_articles(
    articles: Iterable[dict], db_path: str | Path | None = None
) -> dict[str, int]:
    """Insert live reports without changing existing rows; skip duplicates."""
    inserted = duplicate_url = duplicate_content = invalid = 0
    try:
        with connect(db_path) as connection:
            for article in articles:
                if not article.get("title") or not article.get("url") or not article.get("source"):
                    invalid += 1
                    continue
                values = dict(article)
                values.setdefault("published_at", None)
                values.setdefault("summary", None)
                values.setdefault("content", None)
                values["language"] = values.get("language") or "und"
                values.setdefault("language_confidence", None)
                values.setdefault("language_method", "not_detected")
                values.setdefault("language_reviewed", 0)
                values["threat_type"] = "Unclassified"
                values["report_status"] = "collected"
                values["is_demo"] = 0
                values["content_fingerprint"] = values.get("content_fingerprint") or content_fingerprint(
                    values.get("title"), values.get("summary"), values.get("content")
                )
                try:
                    connection.execute(
                        """INSERT INTO articles
                           (title, url, source, published_at, language, language_confidence,
                            language_method, language_reviewed, summary, content,
                            content_fingerprint, threat_type, report_status, is_demo)
                           VALUES (:title, :url, :source, :published_at, :language,
                                   :language_confidence, :language_method, :language_reviewed,
                                   :summary, :content, :content_fingerprint, :threat_type,
                                   :report_status, :is_demo)""",
                        values,
                    )
                    inserted += 1
                except sqlite3.IntegrityError:
                    found_url = connection.execute(
                        "SELECT 1 FROM articles WHERE url = ?", (values["url"],)
                    ).fetchone()
                    if found_url:
                        duplicate_url += 1
                    else:
                        duplicate_content += 1
        return {
            "inserted": inserted,
            "duplicate_url": duplicate_url,
            "duplicate_content": duplicate_content,
            "invalid": invalid,
        }
    except sqlite3.Error:
        logger.exception("Failed to insert live articles")
        raise
