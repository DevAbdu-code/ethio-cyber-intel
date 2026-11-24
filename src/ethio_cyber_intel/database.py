"""SQLite database setup and explicitly synthetic demonstration records."""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
from datetime import datetime, timezone
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

CLASSIFICATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS threat_classification_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
    language TEXT NOT NULL CHECK (language IN ('en', 'am', 'om', 'und', 'mul')),
    method TEXT NOT NULL,
    classifier_version TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('classified', 'unknown', 'human_reviewed')),
    classified_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_threat_runs_article_latest
    ON threat_classification_runs(article_id, id DESC);
CREATE TABLE IF NOT EXISTS threat_classification_labels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL REFERENCES threat_classification_runs(id) ON DELETE CASCADE,
    category TEXT NOT NULL CHECK (category IN (
        'phishing', 'malware', 'ransomware', 'vulnerability', 'data_breach',
        'ddos', 'cyber_espionage', 'credential_theft', 'other', 'unknown'
    )),
    confidence REAL CHECK (confidence IS NULL OR (confidence >= 0 AND confidence <= 1)),
    evidence_json TEXT NOT NULL DEFAULT '[]',
    UNIQUE (run_id, category)
);
CREATE INDEX IF NOT EXISTS idx_threat_labels_category ON threat_classification_labels(category);
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
            _initialize_classification_schema(connection)
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


def _initialize_classification_schema(connection: sqlite3.Connection) -> None:
    """Create append-only classification history tables in one transaction."""
    connection.execute("BEGIN IMMEDIATE")
    try:
        for statement in CLASSIFICATION_SCHEMA.split(";"):
            if statement.strip():
                connection.execute(statement)
        connection.commit()
    except sqlite3.Error:
        connection.rollback()
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


def save_classification(
    article_id: int,
    classification,
    db_path: str | Path | None = None,
) -> dict[str, int | bool | str]:
    """Append an automated classification unless a human review already exists."""
    result = classification.as_dict() if hasattr(classification, "as_dict") else dict(classification)
    try:
        with connect(db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            article = connection.execute(
                "SELECT id FROM articles WHERE id = ?", (article_id,)
            ).fetchone()
            if article is None:
                raise ValueError(f"Article {article_id} does not exist")
            reviewed = connection.execute(
                """SELECT 1 FROM threat_classification_runs
                   WHERE article_id = ? AND status = 'human_reviewed' LIMIT 1""",
                (article_id,),
            ).fetchone()
            if reviewed:
                return {"saved": False, "reason": "human_review_preserved"}
            cursor = connection.execute(
                """INSERT INTO threat_classification_runs
                   (article_id, language, method, classifier_version, status, classified_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    article_id, result.get("language", "und"), result["method"],
                    result.get("version", "unknown"), result["status"], result["classified_at"],
                ),
            )
            run_id = int(cursor.lastrowid)
            connection.executemany(
                """INSERT INTO threat_classification_labels
                   (run_id, category, confidence, evidence_json)
                   VALUES (?, ?, ?, ?)""",
                [
                    (
                        run_id, label["category"], label.get("confidence"),
                        json.dumps(label.get("evidence", []), ensure_ascii=False),
                    )
                    for label in result.get("categories", [])
                ],
            )
            return {"saved": True, "run_id": run_id, "status": result["status"]}
    except sqlite3.Error:
        logger.exception("Could not store classification for article %s", article_id)
        raise


def save_manual_classification(
    article_id: int,
    categories: Iterable[dict],
    *,
    language: str = "und",
    db_path: str | Path | None = None,
) -> int:
    """Append a human-reviewed label set; use `unknown` for an explicit no-match review."""
    labels = list(categories)
    if not labels:
        raise ValueError("Provide at least one reviewed category, including 'unknown' when appropriate")
    try:
        with connect(db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            if not connection.execute("SELECT 1 FROM articles WHERE id = ?", (article_id,)).fetchone():
                raise ValueError(f"Article {article_id} does not exist")
            cursor = connection.execute(
                """INSERT INTO threat_classification_runs
                   (article_id, language, method, classifier_version, status, classified_at)
                   VALUES (?, ?, 'human_review', 'manual', 'human_reviewed', ?)""",
                (article_id, language, datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")),
            )
            run_id = int(cursor.lastrowid)
            connection.executemany(
                """INSERT INTO threat_classification_labels
                   (run_id, category, confidence, evidence_json) VALUES (?, ?, NULL, ?)""",
                [
                    (run_id, label["category"], json.dumps(label.get("evidence", []), ensure_ascii=False))
                    for label in labels
                ],
            )
            return run_id
    except sqlite3.Error:
        logger.exception("Could not store manual classification for article %s", article_id)
        raise


def classify_pending_articles(db_path: str | Path | None = None) -> dict[str, int]:
    """Classify articles with no prior run, retaining all existing history."""
    from .threat_classification import classify_article

    try:
        with connect(db_path) as connection:
            articles = connection.execute(
                """SELECT a.id, a.title, a.summary, a.content, a.language
                   FROM articles AS a
                   WHERE NOT EXISTS (
                       SELECT 1 FROM threat_classification_runs AS r WHERE r.article_id = a.id
                   )
                   ORDER BY a.id"""
            ).fetchall()
        result = {"classified": 0, "unknown": 0, "skipped": 0}
        for row in articles:
            classification = classify_article(dict(row))
            saved = save_classification(int(row["id"]), classification, db_path)
            if not saved.get("saved"):
                result["skipped"] += 1
            elif classification.status == "unknown":
                result["unknown"] += 1
            else:
                result["classified"] += 1
        return result
    except sqlite3.Error:
        logger.exception("Could not classify pending articles")
        raise
