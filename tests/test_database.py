"""Tests for schema initialization and demo data integrity."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from src.ethio_cyber_intel.database import initialize_database


class DatabaseInitializationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_initialization_seeds_trilingual_demo_rows_once(self):
        initialize_database(self.db_path, seed_demo=True)
        initialize_database(self.db_path, seed_demo=True)
        with sqlite3.connect(self.db_path) as connection:
            rows = connection.execute(
                "SELECT language, report_status, is_demo, url FROM articles ORDER BY language"
            ).fetchall()
        self.assertEqual([row[0] for row in rows], ["am", "en", "om"])
        self.assertTrue(all(row[1] == "demo" and row[2] == 1 for row in rows))
        self.assertTrue(all("example.org/demo/" in row[3] for row in rows))

    def test_seed_can_be_disabled(self):
        initialize_database(self.db_path, seed_demo=False)
        with sqlite3.connect(self.db_path) as connection:
            count = connection.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
        self.assertEqual(count, 0)

    def test_article_url_is_unique(self):
        initialize_database(self.db_path, seed_demo=True)
        with self.assertRaises(sqlite3.IntegrityError):
            with sqlite3.connect(self.db_path) as connection:
                connection.execute(
                    """INSERT INTO articles
                       (title, url, source, language) VALUES (?, ?, ?, ?)""",
                    ("duplicate", "https://example.org/demo/phishing-awareness-en", "test", "en"),
                )

    def test_stage_one_database_migrates_without_losing_demo_rows(self):
        with sqlite3.connect(self.db_path) as connection:
            connection.executescript(
                """CREATE TABLE articles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL, url TEXT NOT NULL UNIQUE,
                    source TEXT NOT NULL, published_at TEXT,
                    language TEXT NOT NULL CHECK (language IN ('en','am','om')),
                    summary TEXT, content TEXT,
                    threat_type TEXT NOT NULL DEFAULT 'Unclassified',
                    report_status TEXT NOT NULL DEFAULT 'collected'
                        CHECK (report_status IN ('demo','collected','verified_advisory')),
                    is_demo INTEGER NOT NULL DEFAULT 0 CHECK (is_demo IN (0,1)),
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                INSERT INTO articles (title,url,source,published_at,language,summary,threat_type,report_status,is_demo)
                VALUES ('DEMO DATA: preserve me','https://example.org/demo/keep','demo','2025-01-15','en','demo summary','Phishing','demo',1);"""
            )
        initialize_database(self.db_path, seed_demo=True)
        with sqlite3.connect(self.db_path) as connection:
            row = connection.execute(
                "SELECT title, report_status, is_demo, fetched_at FROM articles WHERE url = ?",
                ("https://example.org/demo/keep",),
            ).fetchone()
            connection.execute(
                "INSERT INTO articles (title,url,source,language) VALUES (?,?,?,?)",
                ("Live item", "https://news.example.test/item", "source", "und"),
            )
        self.assertEqual(row[:3], ("DEMO DATA: preserve me", "demo", 1))

    def test_stage_two_database_migrates_fields_and_keeps_article_content(self):
        with sqlite3.connect(self.db_path) as connection:
            connection.executescript(
                """CREATE TABLE articles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL, url TEXT NOT NULL UNIQUE,
                    source TEXT NOT NULL, published_at TEXT,
                    language TEXT NOT NULL CHECK (language IN ('en','am','om','und')),
                    summary TEXT, content TEXT, content_fingerprint TEXT,
                    threat_type TEXT NOT NULL DEFAULT 'Unclassified',
                    report_status TEXT NOT NULL DEFAULT 'collected'
                        CHECK (report_status IN ('demo','collected','verified_advisory')),
                    is_demo INTEGER NOT NULL DEFAULT 0 CHECK (is_demo IN (0,1)),
                    fetched_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                INSERT INTO articles (id,title,url,source,language,summary,content,content_fingerprint)
                VALUES (42,'Existing live title','https://news.example.test/old','Existing Source','und','Saved description','Saved full article body','fingerprint-42');
                INSERT INTO articles (id,title,url,source,language,summary,content,content_fingerprint)
                VALUES (43,'Reviewed Oromo report','https://news.example.test/reviewed','Existing Source','om','Oromo text','Original body','fingerprint-43');"""
            )
        initialize_database(self.db_path, seed_demo=False)
        with sqlite3.connect(self.db_path) as connection:
            row = connection.execute(
                """SELECT id,title,url,source,language,summary,content,content_fingerprint,
                          language_confidence,language_method,language_reviewed
                   FROM articles WHERE id=42"""
            ).fetchone()
            reviewed = connection.execute(
                "SELECT language, language_confidence, language_method, language_reviewed FROM articles WHERE id=43"
            ).fetchone()
            connection.execute(
                "INSERT INTO articles (title,url,source,language) VALUES (?,?,?,?)",
                ("Mixed text", "https://news.example.test/mixed", "source", "mul"),
            )
        self.assertEqual(row[:8], (
            42, "Existing live title", "https://news.example.test/old", "Existing Source",
            "und", "Saved description", "Saved full article body", "fingerprint-42",
        ))
        self.assertEqual(row[8:], (None, None, 0))
        self.assertEqual(reviewed, ("om", None, "legacy_existing_label", 1))

    def test_reinitialization_preserves_manually_reviewed_language(self):
        initialize_database(self.db_path, seed_demo=False)
        article = {
            "title": "Reviewed report with enough text for a stable fingerprint",
            "url": "https://news.example.test/reviewed",
            "source": "Example source",
            "language": "und",
            "language_confidence": 0.0,
            "language_method": "insufficient_text",
        }
        from src.ethio_cyber_intel.database import insert_live_articles
        insert_live_articles([article], self.db_path)
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                """UPDATE articles SET language='om', language_confidence=0.99,
                          language_method='manual_review', language_reviewed=1 WHERE url=?""",
                (article["url"],),
            )
        initialize_database(self.db_path, seed_demo=False)
        with sqlite3.connect(self.db_path) as connection:
            row = connection.execute(
                "SELECT language, language_confidence, language_method, language_reviewed FROM articles WHERE url=?",
                (article["url"],),
            ).fetchone()
        self.assertEqual(row, ("om", 0.99, "manual_review", 1))

    def test_stage_four_migration_adds_history_without_changing_articles(self):
        initialize_database(self.db_path, seed_demo=False)
        from src.ethio_cyber_intel.database import connect, insert_live_articles
        insert_live_articles([{
            "title": "A ransomware incident exposed customer data in a data breach",
            "url": "https://news.example.test/classify",
            "source": "Test source", "language": "en", "summary": "Original description",
            "content": "Original body retained unchanged.",
        }], self.db_path)
        with connect(self.db_path) as connection:
            before = tuple(connection.execute(
                "SELECT title,url,source,summary,content FROM articles"
            ).fetchone())
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
        self.assertIn("threat_classification_runs", tables)
        self.assertIn("threat_classification_labels", tables)
        self.assertEqual(before[0], "A ransomware incident exposed customer data in a data breach")
        self.assertEqual(before[3:], ("Original description", "Original body retained unchanged."))

    def test_classification_history_multi_label_and_human_review_protection(self):
        from src.ethio_cyber_intel.database import (
            classify_pending_articles, connect, insert_live_articles, save_manual_classification,
        )
        from src.ethio_cyber_intel.dashboard_data import load_current_classifications
        initialize_database(self.db_path, seed_demo=False)
        insert_live_articles([{
            "title": "Ransomware encrypted files and exposed customer data in a data breach",
            "url": "https://news.example.test/multi", "source": "Test source", "language": "en",
        }], self.db_path)
        article_id = 1
        result = classify_pending_articles(self.db_path)
        self.assertEqual(result["classified"], 1)
        rows = load_current_classifications(self.db_path)
        self.assertTrue({"ransomware", "data_breach"}.issubset(set(rows["category"])))
        save_manual_classification(article_id, [{"category": "ransomware"}], language="en", db_path=self.db_path)
        with connect(self.db_path) as connection:
            prior_runs = connection.execute(
                "SELECT COUNT(*) FROM threat_classification_runs WHERE article_id=?", (article_id,)
            ).fetchone()[0]
        self.assertEqual(classify_pending_articles(self.db_path)["classified"], 0)
        self.assertEqual(prior_runs, 2)
        current = load_current_classifications(self.db_path)
        self.assertEqual(set(current["category"]), {"ransomware"})
        self.assertEqual(set(current["status"]), {"human_reviewed"})

    def test_stage_five_migration_and_assessment_history_preserve_article_and_human_review(self):
        from src.ethio_cyber_intel.database import (
            assess_pending_articles, connect, insert_live_articles,
            save_manual_severity_assessment, save_severity_assessment,
        )
        from src.ethio_cyber_intel.dashboard_data import load_current_severity_assessments
        from src.ethio_cyber_intel.severity_assessment import assess_severity

        initialize_database(self.db_path, seed_demo=False)
        insert_live_articles([{
            "title": "Article says a vulnerability could allow data exposure",
            "url": "https://news.example.test/severity", "source": "Test source",
            "language": "en", "summary": "Original summary", "content": "Original body",
        }], self.db_path)
        with connect(self.db_path) as connection:
            article = dict(connection.execute("SELECT * FROM articles").fetchone())
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
        self.assertIn("severity_assessments", tables)
        self.assertEqual(assess_pending_articles(self.db_path)["assessed"], 1)
        first = load_current_severity_assessments(self.db_path).iloc[0]
        self.assertEqual(first["severity"], "Medium")
        save_manual_severity_assessment(
            1, severity="Low", explanation="Reviewer rationale", evidence=[],
            evidence_completeness={"known_fields": 1, "total_fields": 8}, db_path=self.db_path,
        )
        blocked = save_severity_assessment(1, assess_severity(article), self.db_path)
        self.assertFalse(blocked["saved"])
        self.assertEqual(assess_pending_articles(self.db_path)["assessed"], 0)
        rows = load_current_severity_assessments(self.db_path)
        self.assertEqual(rows.iloc[0]["severity"], "Low")
        self.assertEqual(rows.iloc[0]["status"], "human_reviewed")
        with connect(self.db_path) as connection:
            after = dict(connection.execute("SELECT * FROM articles WHERE id=1").fetchone())
            history_count = connection.execute(
                "SELECT COUNT(*) FROM severity_assessments WHERE article_id=1"
            ).fetchone()[0]
        self.assertEqual(history_count, 2)
        self.assertEqual((after["title"], after["url"], after["summary"], after["content"]),
                         (article["title"], article["url"], article["summary"], article["content"]))


if __name__ == "__main__":
    unittest.main()
