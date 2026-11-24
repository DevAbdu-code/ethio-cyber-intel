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

SEVERITY_SCHEMA = """
CREATE TABLE IF NOT EXISTS severity_assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
    severity TEXT NOT NULL CHECK (severity IN ('Critical','High','Medium','Low','Informational','Unknown')),
    explanation TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    method TEXT NOT NULL,
    assessed_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'externally_supported','preliminary_reported_claim','insufficient_evidence',
        'conflicting_evidence','human_reviewed'
    )),
    evidence_completeness_json TEXT NOT NULL,
    assessment_version TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_severity_article_latest
    ON severity_assessments(article_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_severity_level ON severity_assessments(severity);
"""

CORRELATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS correlation_pairs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id_a INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
    article_id_b INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    CHECK (article_id_a < article_id_b),
    UNIQUE (article_id_a, article_id_b)
);
CREATE TABLE IF NOT EXISTS correlation_assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pair_id INTEGER NOT NULL REFERENCES correlation_pairs(id) ON DELETE CASCADE,
    score REAL NOT NULL CHECK (score >= 0 AND score <= 1),
    matching_identifiers_json TEXT NOT NULL,
    shared_entities_json TEXT NOT NULL,
    shared_terms_json TEXT NOT NULL,
    similarity_methods_json TEXT NOT NULL,
    supporting_evidence_json TEXT NOT NULL,
    language_a TEXT NOT NULL,
    language_b TEXT NOT NULL,
    language_pair TEXT NOT NULL,
    explanation TEXT NOT NULL,
    correlated_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN (
        'Candidate','Human confirmed','Human rejected','Insufficient evidence'
    )),
    reviewer_note TEXT
);
CREATE INDEX IF NOT EXISTS idx_correlation_assessment_latest
    ON correlation_assessments(pair_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_correlation_status
    ON correlation_assessments(status);
"""

SUMMARY_SCHEMA = """
CREATE TABLE IF NOT EXISTS article_summaries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
    summary_language TEXT NOT NULL CHECK (summary_language IN ('en','am','om')),
    summary_text TEXT,
    summary_method TEXT NOT NULL,
    summary_status TEXT NOT NULL CHECK (summary_status IN (
        'original_extractive','insufficient_content','unsupported_language',
        'unsupported_translation','human_reviewed'
    )),
    supporting_evidence_json TEXT NOT NULL,
    method_version TEXT NOT NULL,
    created_at TEXT NOT NULL,
    source_text_fingerprint TEXT NOT NULL,
    source_text_used TEXT NOT NULL,
    summary_kind TEXT NOT NULL,
    key_intelligence_json TEXT NOT NULL,
    source_metadata_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_summaries_article_latest
    ON article_summaries(article_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_summaries_duplicate_check
    ON article_summaries(article_id, summary_language, source_text_fingerprint, method_version);
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
            _initialize_severity_schema(connection)
            _initialize_correlation_schema(connection)
            _initialize_summary_schema(connection)
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


def _initialize_severity_schema(connection: sqlite3.Connection) -> None:
    """Create the additive severity history schema transactionally."""
    connection.execute("BEGIN IMMEDIATE")
    try:
        for statement in SEVERITY_SCHEMA.split(";"):
            if statement.strip():
                connection.execute(statement)
        connection.commit()
    except sqlite3.Error:
        connection.rollback()
        raise


def _initialize_correlation_schema(connection: sqlite3.Connection) -> None:
    """Create correlation relationships and append-only decisions transactionally."""
    connection.execute("BEGIN IMMEDIATE")
    try:
        for statement in CORRELATION_SCHEMA.split(";"):
            if statement.strip():
                connection.execute(statement)
        connection.commit()
    except sqlite3.Error:
        connection.rollback()
        raise


def _initialize_summary_schema(connection: sqlite3.Connection) -> None:
    """Create summary history transactionally without modifying article rows."""
    connection.execute("BEGIN IMMEDIATE")
    try:
        for statement in SUMMARY_SCHEMA.split(";"):
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


def save_severity_assessment(
    article_id: int, assessment, db_path: str | Path | None = None,
) -> dict[str, int | bool | str]:
    """Append an automated assessment unless any human assessment exists."""
    result = assessment.as_dict() if hasattr(assessment, "as_dict") else dict(assessment)
    try:
        with connect(db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            if not connection.execute("SELECT 1 FROM articles WHERE id=?", (article_id,)).fetchone():
                raise ValueError(f"Article {article_id} does not exist")
            if connection.execute(
                "SELECT 1 FROM severity_assessments WHERE article_id=? AND status='human_reviewed' LIMIT 1",
                (article_id,),
            ).fetchone():
                return {"saved": False, "reason": "human_review_preserved"}
            cursor = connection.execute(
                """INSERT INTO severity_assessments
                   (article_id,severity,explanation,evidence_json,method,assessed_at,status,
                    evidence_completeness_json,assessment_version)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (article_id, result["severity"], result["explanation"],
                 json.dumps(result.get("evidence", []), ensure_ascii=False), result["method"],
                 result["assessed_at"], result["status"],
                 json.dumps(result.get("evidence_completeness", {}), ensure_ascii=False),
                 result.get("version", "1.0")),
            )
            return {"saved": True, "assessment_id": int(cursor.lastrowid), "severity": result["severity"]}
    except sqlite3.Error:
        logger.exception("Could not store severity assessment for article %s", article_id)
        raise


def save_manual_severity_assessment(
    article_id: int, *, severity: str, explanation: str, evidence: Iterable[dict],
    evidence_completeness: dict, db_path: str | Path | None = None,
) -> int:
    """Append a reviewed severity decision without deleting prior assessments."""
    try:
        with connect(db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            if not connection.execute("SELECT 1 FROM articles WHERE id=?", (article_id,)).fetchone():
                raise ValueError(f"Article {article_id} does not exist")
            cursor = connection.execute(
                """INSERT INTO severity_assessments
                   (article_id,severity,explanation,evidence_json,method,assessed_at,status,
                    evidence_completeness_json,assessment_version)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (article_id, severity, explanation, json.dumps(list(evidence), ensure_ascii=False),
                 "human_review", datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                 "human_reviewed", json.dumps(evidence_completeness, ensure_ascii=False), "manual"),
            )
            return int(cursor.lastrowid)
    except sqlite3.Error:
        logger.exception("Could not save manual severity review for article %s", article_id)
        raise


def assess_pending_articles(db_path: str | Path | None = None) -> dict[str, int]:
    """Assess articles with no existing severity history; keep all prior runs."""
    from .severity_assessment import assess_severity

    try:
        with connect(db_path) as connection:
            rows = connection.execute(
                """SELECT a.id,a.title,a.source,a.url,a.published_at,a.summary,a.content
                   FROM articles a WHERE NOT EXISTS
                   (SELECT 1 FROM severity_assessments s WHERE s.article_id=a.id)
                   ORDER BY a.id"""
            ).fetchall()
        counts = {"assessed": 0, "unknown": 0, "skipped": 0}
        for row in rows:
            assessment = assess_severity(dict(row))
            saved = save_severity_assessment(int(row["id"]), assessment, db_path)
            if not saved.get("saved"):
                counts["skipped"] += 1
            elif assessment.severity == "Unknown":
                counts["unknown"] += 1
            else:
                counts["assessed"] += 1
        return counts
    except sqlite3.Error:
        logger.exception("Could not assess pending article severity")
        raise


def save_correlation(result, db_path: str | Path | None = None) -> dict[str, int | bool | str]:
    """Append a candidate assessment without replacing any human decision."""
    value = result.as_dict() if hasattr(result, "as_dict") else dict(result)
    if value.get("status") not in {"Candidate", "Insufficient evidence"}:
        raise ValueError("Automated correlation status must be Candidate or Insufficient evidence")
    article_a, article_b = value.get("article_id_a"), value.get("article_id_b")
    if article_a is None or article_b is None or int(article_a) == int(article_b):
        raise ValueError("Correlation requires two distinct persisted article IDs")
    first, second = sorted((int(article_a), int(article_b)))
    try:
        with connect(db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            for article_id in (first, second):
                if not connection.execute("SELECT 1 FROM articles WHERE id=?", (article_id,)).fetchone():
                    raise ValueError(f"Article {article_id} does not exist")
            pair = connection.execute(
                "SELECT id FROM correlation_pairs WHERE article_id_a=? AND article_id_b=?",
                (first, second),
            ).fetchone()
            if pair is None:
                cursor = connection.execute(
                    "INSERT INTO correlation_pairs (article_id_a,article_id_b,created_at) VALUES (?,?,?)",
                    (first, second, value["correlated_at"]),
                )
                pair_id = int(cursor.lastrowid)
            else:
                pair_id = int(pair["id"])
            latest = connection.execute(
                "SELECT status FROM correlation_assessments WHERE pair_id=? ORDER BY id DESC LIMIT 1",
                (pair_id,),
            ).fetchone()
            if latest and latest["status"] in {"Human confirmed", "Human rejected"}:
                return {"saved": False, "reason": "human_review_preserved", "pair_id": pair_id}
            if latest and latest["status"] == value["status"] == "Candidate":
                return {"saved": False, "reason": "candidate_already_recorded", "pair_id": pair_id}
            cursor = connection.execute(
                """INSERT INTO correlation_assessments
                   (pair_id,score,matching_identifiers_json,shared_entities_json,shared_terms_json,
                    similarity_methods_json,supporting_evidence_json,language_a,language_b,language_pair,
                    explanation,correlated_at,status)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (pair_id, value["score"],
                 json.dumps(value.get("matching_identifiers", []), ensure_ascii=False),
                 json.dumps(value.get("shared_entities", []), ensure_ascii=False),
                 json.dumps(value.get("shared_terms", []), ensure_ascii=False),
                 json.dumps(value.get("similarity_methods", []), ensure_ascii=False),
                 json.dumps(value.get("supporting_evidence", []), ensure_ascii=False),
                 value["language_a"], value["language_b"], value["language_pair"],
                 value["explanation"], value["correlated_at"], value["status"]),
            )
            return {"saved": True, "assessment_id": int(cursor.lastrowid), "pair_id": pair_id}
    except sqlite3.Error:
        logger.exception("Could not store correlation assessment for article pair %s/%s", article_a, article_b)
        raise


def save_manual_correlation(
    article_id_a: int, article_id_b: int, *, decision: str, reviewer_note: str = "",
    db_path: str | Path | None = None,
) -> int:
    """Append a human-confirmed/rejected decision to a relationship history."""
    if decision not in {"Human confirmed", "Human rejected"}:
        raise ValueError("Human decision must be Human confirmed or Human rejected")
    first, second = sorted((int(article_id_a), int(article_id_b)))
    if first == second:
        raise ValueError("A report cannot be correlated with itself")
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        with connect(db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            for article_id in (first, second):
                if not connection.execute("SELECT 1 FROM articles WHERE id=?", (article_id,)).fetchone():
                    raise ValueError(f"Article {article_id} does not exist")
            pair = connection.execute(
                "SELECT id FROM correlation_pairs WHERE article_id_a=? AND article_id_b=?",
                (first, second),
            ).fetchone()
            if pair is None:
                pair_id = int(connection.execute(
                    "INSERT INTO correlation_pairs (article_id_a,article_id_b,created_at) VALUES (?,?,?)",
                    (first, second, now),
                ).lastrowid)
            else:
                pair_id = int(pair["id"])
            previous = connection.execute(
                "SELECT * FROM correlation_assessments WHERE pair_id=? ORDER BY id DESC LIMIT 1",
                (pair_id,),
            ).fetchone()
            prior_values = (
                (previous["score"], previous["matching_identifiers_json"], previous["shared_entities_json"],
                 previous["shared_terms_json"], previous["similarity_methods_json"],
                 previous["supporting_evidence_json"], previous["language_a"], previous["language_b"],
                 previous["language_pair"], previous["explanation"] + f" Human review decision: {decision}.")
                if previous else
                (0, "[]", "[]", "[]", "[]", "[]", "und", "und", "und ↔ und",
                 f"Human review decision: {decision}.")
            )
            cursor = connection.execute(
                """INSERT INTO correlation_assessments
                   (pair_id,score,matching_identifiers_json,shared_entities_json,shared_terms_json,
                    similarity_methods_json,supporting_evidence_json,language_a,language_b,language_pair,
                    explanation,correlated_at,status,reviewer_note)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (pair_id, *prior_values, now, decision, reviewer_note),
            )
            return int(cursor.lastrowid)
    except sqlite3.Error:
        logger.exception("Could not record human correlation decision for %s/%s", first, second)
        raise


def correlate_pending_articles(
    db_path: str | Path | None = None, *, article_limit: int = 300,
) -> dict[str, int]:
    """Compare a bounded recent article set; persist candidates only."""
    from .correlation import correlate_pair

    try:
        with connect(db_path) as connection:
            articles = [dict(row) for row in connection.execute(
                """SELECT id,title,source,url,published_at,language,summary,content
                   FROM articles WHERE is_demo=0
                   ORDER BY COALESCE(published_at,fetched_at) DESC,id DESC LIMIT ?""",
                (article_limit,),
            ).fetchall()]
        counts = {"compared": 0, "candidates": 0, "insufficient": 0, "saved": 0, "skipped": 0}
        for left_index, article_a in enumerate(articles):
            for article_b in articles[left_index + 1:]:
                counts["compared"] += 1
                result = correlate_pair(article_a, article_b)
                if result.status != "Candidate":
                    counts["insufficient"] += 1
                    continue
                counts["candidates"] += 1
                saved = save_correlation(result, db_path)
                if saved.get("saved"):
                    counts["saved"] += 1
                else:
                    counts["skipped"] += 1
        return counts
    except sqlite3.Error:
        logger.exception("Could not correlate article pairs")
        raise


def save_summary_result(article_id: int, summary, db_path: str | Path | None = None) -> dict[str, int | bool | str]:
    """Append an automated summary result, skipping duplicates and human reviews."""
    value = summary.as_dict() if hasattr(summary, "as_dict") else dict(summary)
    try:
        with connect(db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            if not connection.execute("SELECT 1 FROM articles WHERE id=?", (article_id,)).fetchone():
                raise ValueError(f"Article {article_id} does not exist")
            if connection.execute(
                """SELECT 1 FROM article_summaries WHERE article_id=? AND summary_language=?
                   AND summary_status='human_reviewed' LIMIT 1""",
                (article_id, value["summary_language"]),
            ).fetchone():
                return {"saved": False, "reason": "human_review_preserved"}
            duplicate = connection.execute(
                """SELECT id FROM article_summaries WHERE article_id=? AND summary_language=?
                   AND source_text_fingerprint=? AND summary_method=? AND method_version=? LIMIT 1""",
                (article_id, value["summary_language"], value["source_text_fingerprint"],
                 value["method"], value["method_version"]),
            ).fetchone()
            if duplicate:
                return {"saved": False, "reason": "duplicate_summary", "summary_id": int(duplicate["id"])}
            cursor = connection.execute(
                """INSERT INTO article_summaries
                   (article_id,summary_language,summary_text,summary_method,summary_status,
                    supporting_evidence_json,method_version,created_at,source_text_fingerprint,source_text_used,
                    summary_kind,key_intelligence_json,source_metadata_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (article_id, value["summary_language"], value.get("summary_text"), value["method"],
                 value["status"], json.dumps(value.get("supporting_evidence", []), ensure_ascii=False),
                 value["method_version"], value["created_at"], value["source_text_fingerprint"],
                 value["source_text_used"],
                 value["summary_kind"], json.dumps(value.get("key_intelligence", {}), ensure_ascii=False),
                 json.dumps(value.get("source_metadata", {}), ensure_ascii=False)),
            )
            return {"saved": True, "summary_id": int(cursor.lastrowid), "status": value["status"]}
    except sqlite3.Error:
        logger.exception("Could not save summary for article %s", article_id)
        raise


def save_manual_summary(
    article_id: int, *, summary_language: str, summary_text: str,
    source_text_fingerprint: str, source_text_used: str, supporting_evidence: Iterable[dict],
    key_intelligence: dict, source_metadata: dict, db_path: str | Path | None = None,
) -> int:
    """Append a human-reviewed summary; later automation cannot replace it."""
    try:
        with connect(db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            if not connection.execute("SELECT 1 FROM articles WHERE id=?", (article_id,)).fetchone():
                raise ValueError(f"Article {article_id} does not exist")
            cursor = connection.execute(
                """INSERT INTO article_summaries
                   (article_id,summary_language,summary_text,summary_method,summary_status,
                    supporting_evidence_json,method_version,created_at,source_text_fingerprint,source_text_used,
                    summary_kind,key_intelligence_json,source_metadata_json)
                   VALUES (?,?,?,'human_review','human_reviewed',?,?,?,?,?,'human-authored',?,?)""",
                (article_id, summary_language, summary_text,
                 json.dumps(list(supporting_evidence), ensure_ascii=False), "manual",
                 datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                 source_text_fingerprint, source_text_used, json.dumps(key_intelligence, ensure_ascii=False),
                 json.dumps(source_metadata, ensure_ascii=False)),
            )
            return int(cursor.lastrowid)
    except sqlite3.Error:
        logger.exception("Could not save human-reviewed summary for article %s", article_id)
        raise
