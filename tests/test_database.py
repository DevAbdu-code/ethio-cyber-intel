"""Tests for schema initialization and demo data integrity."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from src.ethio_cyber_intel.database import (
    assess_pending_articles, classify_pending_articles, connect,
    detect_legacy_article_languages, initialize_database,
)
from src.ethio_cyber_intel.dashboard_data import load_article_detail


class DatabaseInitializationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_legacy_language_backfill_uses_feed_text_and_preserves_reviewed_rows(self):
        initialize_database(self.db_path, seed_demo=False)
        with sqlite3.connect(self.db_path) as connection:
            connection.executemany(
                """INSERT INTO articles (title,url,source,language,language_confidence,
                   language_method,language_reviewed,summary,report_status,is_demo)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                [
                    ("The vendor released an emergency security patch for customer accounts",
                     "https://example.test/legacy-language", "Example News", "und", None,
                     None, 0, "The company said the update fixes a security flaw affecting public users.",
                     "collected", 0),
                    ("Reviewed title", "https://example.test/reviewed", "Example News", "om", 0.91,
                     "human_reviewed", 1, "Reviewed label", "collected", 0),
                ],
            )

        stats = detect_legacy_article_languages(self.db_path)
        with sqlite3.connect(self.db_path) as connection:
            legacy = connection.execute(
                "SELECT language,language_confidence,language_method,language_reviewed FROM articles WHERE url=?",
                ("https://example.test/legacy-language",),
            ).fetchone()
            reviewed = connection.execute(
                "SELECT language,language_confidence,language_method,language_reviewed FROM articles WHERE url=?",
                ("https://example.test/reviewed",),
            ).fetchone()

        self.assertEqual(stats, {"scanned": 1, "updated": 1, "unknown": 0})
        self.assertEqual(legacy[0], "en")
        self.assertGreaterEqual(legacy[1], 0.60)
        self.assertEqual(legacy[2:], ("lexical_cues_en", 0))
        self.assertEqual(reviewed, ("om", 0.91, "human_reviewed", 1))

    def test_content_validation_migration_preserves_article_and_analysis_history(self):
        initialize_database(self.db_path, seed_demo=False)
        with connect(self.db_path) as connection:
            cursor = connection.execute(
                """INSERT INTO articles (title,url,source,language,summary,content,is_demo,report_status)
                   VALUES (?,?,?,?,?,?,0,'collected')""",
                ("Legacy article", "https://example.test/legacy-content", "Example News", "und",
                 "RSS description retained", "Old potentially unrelated page text"),
            )
            article_id = cursor.lastrowid
            run_id = connection.execute(
                """INSERT INTO threat_classification_runs
                   (article_id,language,method,classifier_version,status,classified_at)
                   VALUES (?,?,?,?,?,?)""",
                (article_id, "und", "test", "1", "unknown", "2026-01-01T00:00:00Z"),
            ).lastrowid
            connection.execute(
                "INSERT INTO threat_classification_labels (run_id,category,confidence,evidence_json) VALUES (?,?,?,?)",
                (run_id, "unknown", 0.0, "[]"),
            )
            connection.execute("ALTER TABLE articles DROP COLUMN content_validation_status")

        initialize_database(self.db_path, seed_demo=False)
        with connect(self.db_path) as connection:
            article = connection.execute(
                "SELECT title,summary,content,content_validation_status FROM articles WHERE id=?",
                (article_id,),
            ).fetchone()
            label_count = connection.execute(
                """SELECT COUNT(*) FROM threat_classification_labels l
                   JOIN threat_classification_runs r ON r.id=l.run_id WHERE r.article_id=?""",
                (article_id,),
            ).fetchone()[0]
            fk_violations = connection.execute("PRAGMA foreign_key_check").fetchall()
        self.assertEqual(tuple(article), (
            "Legacy article", "RSS description retained", "Old potentially unrelated page text",
            "legacy_unverified",
        ))
        self.assertEqual(label_count, 1)
        self.assertEqual(fk_violations, [])
        detail = load_article_detail(article_id, self.db_path)
        self.assertIsNone(detail["content"])
        self.assertEqual(detail["content_validation_status"], "legacy_unverified")

    def test_unverified_legacy_body_is_excluded_from_classification_and_severity(self):
        initialize_database(self.db_path, seed_demo=False)
        with connect(self.db_path) as connection:
            connection.execute(
                """INSERT INTO articles (title,url,source,language,summary,content,is_demo,report_status)
                   VALUES (?,?,?,?,?,?,0,'collected')""",
                ("Routine vendor update", "https://example.test/unverified-body", "Example News", "en",
                 "The vendor published a routine software update for its customers.",
                 "Ransomware campaign exploited CVE-2026-12345; CVSS score: 9.8."),
            )
        classify_pending_articles(self.db_path)
        assess_pending_articles(self.db_path)
        with connect(self.db_path) as connection:
            category = connection.execute(
                """SELECT l.category FROM threat_classification_labels l
                   JOIN threat_classification_runs r ON r.id=l.run_id LIMIT 1"""
            ).fetchone()[0]
            severity = connection.execute(
                "SELECT severity FROM severity_assessments LIMIT 1"
            ).fetchone()[0]
        self.assertEqual(category, "unknown")
        self.assertEqual(severity, "Unknown")

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

    def test_stage_six_migration_history_deduplication_and_human_decisions(self):
        from src.ethio_cyber_intel.correlation import correlate_pair
        from src.ethio_cyber_intel.database import (
            assess_pending_articles, classify_pending_articles, connect,
            correlate_pending_articles, insert_live_articles, save_correlation,
            save_manual_correlation,
        )
        from src.ethio_cyber_intel.dashboard_data import load_current_correlations

        initialize_database(self.db_path, seed_demo=False)
        insert_live_articles([
            {"title": "CVE-2026-55667 report details", "url": "https://news.test/a",
             "source": "Source A", "language": "en", "content": "CVE-2026-55667 report text."},
            {"title": "CVE-2026-55667 መረጃ", "url": "https://news.test/b",
             "source": "Source B", "language": "am", "content": "CVE-2026-55667 መረጃ።"},
            {"title": "CVE-2026-55667 odeeffannoo", "url": "https://news.test/c",
             "source": "Source C", "language": "om", "content": "CVE-2026-55667 odeeffannoo."},
        ], self.db_path)
        self.assertEqual(classify_pending_articles(self.db_path)["classified"], 3)
        self.assertEqual(assess_pending_articles(self.db_path)["unknown"], 3)
        with connect(self.db_path) as connection:
            before_articles = connection.execute("SELECT COUNT(*) FROM articles").fetchone()[0]
            before_labels = connection.execute("SELECT COUNT(*) FROM threat_classification_labels").fetchone()[0]
            before_severity = connection.execute("SELECT COUNT(*) FROM severity_assessments").fetchone()[0]
            article_rows = [dict(row) for row in connection.execute("SELECT * FROM articles ORDER BY id")]
            tables = {row[0] for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
        self.assertIn("correlation_pairs", tables)
        self.assertIn("correlation_assessments", tables)
        candidate_ab = correlate_pair(article_rows[0], article_rows[1])
        candidate_ac = correlate_pair(article_rows[0], article_rows[2])
        self.assertTrue(save_correlation(candidate_ab, self.db_path)["saved"])
        repeated = save_correlation(candidate_ab, self.db_path)
        self.assertEqual(repeated["reason"], "candidate_already_recorded")
        save_manual_correlation(1, 2, decision="Human confirmed", reviewer_note="Reviewed pair", db_path=self.db_path)
        self.assertFalse(save_correlation(candidate_ab, self.db_path)["saved"])
        self.assertTrue(save_correlation(candidate_ac, self.db_path)["saved"])
        save_manual_correlation(1, 3, decision="Human rejected", reviewer_note="Different events", db_path=self.db_path)
        self.assertFalse(save_correlation(candidate_ac, self.db_path)["saved"])
        initialize_database(self.db_path, seed_demo=False)
        current = load_current_correlations(self.db_path)
        status_by_pair = {(row.article_id_a, row.article_id_b): row.status for row in current.itertuples()}
        self.assertEqual(status_by_pair, {(1, 2): "Human confirmed", (1, 3): "Human rejected"})
        confirmed_row = current[current["status"] == "Human confirmed"].iloc[0]
        self.assertIn("CVE-2026-55667", confirmed_row["matching_identifiers_json"])
        self.assertGreater(confirmed_row["score"], 0)
        with connect(self.db_path) as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM articles").fetchone()[0], before_articles)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM threat_classification_labels").fetchone()[0], before_labels)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM severity_assessments").fetchone()[0], before_severity)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM correlation_pairs").fetchone()[0], 2)
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM correlation_assessments").fetchone()[0], 4)

    def test_correlation_batch_excludes_demo_articles(self):
        from src.ethio_cyber_intel.database import correlate_pending_articles
        initialize_database(self.db_path, seed_demo=True)
        result = correlate_pending_articles(self.db_path)
        self.assertEqual(result["compared"], 0)

    def test_stage_seven_summary_history_deduplication_and_human_protection(self):
        from src.ethio_cyber_intel.database import (
            assess_pending_articles, classify_pending_articles, connect,
            correlate_pending_articles, insert_live_articles, save_manual_summary,
            save_summary_result,
        )
        from src.ethio_cyber_intel.correlation import correlate_pair
        from src.ethio_cyber_intel.dashboard_data import load_summary_history
        from src.ethio_cyber_intel.summarization import source_fingerprint, summarize_article

        initialize_database(self.db_path, seed_demo=False)
        content = (
            "Researchers analyzed CVE-2026-88990, a security issue in a network service. "
            "The report says administrators should review the vendor guidance. "
            "No exploitation status was independently confirmed in this test text."
        )
        insert_live_articles([{
            "title": "Synthetic test report about a security issue",
            "url": "https://news.example.test/summary-one", "source": "Test publisher",
            "language": "en", "published_at": "2026-02-02T00:00:00Z", "content": content,
        }, {
            "title": "CVE-2026-88990 second language test report",
            "url": "https://news.example.test/summary-two", "source": "Test publisher",
            "language": "am", "content": "CVE-2026-88990 የደህንነት መረጃ።",
        }], self.db_path)
        classify_pending_articles(self.db_path)
        assess_pending_articles(self.db_path)
        correlate_pending_articles(self.db_path)
        article = {"id": 1, "title": "Synthetic test report about a security issue",
                   "source": "Test publisher", "url": "https://news.example.test/summary-one",
                   "language": "en", "published_at": "2026-02-02T00:00:00Z", "content": content}
        first_result = summarize_article(article)
        self.assertEqual(save_summary_result(1, first_result, self.db_path)["saved"], True)
        duplicate = save_summary_result(1, first_result, self.db_path)
        self.assertEqual(duplicate["reason"], "duplicate_summary")

        changed_content = content + " The final paragraph adds a separate synthetic source detail for history."
        with connect(self.db_path) as connection:
            connection.execute("UPDATE articles SET content=? WHERE id=1", (changed_content,))
            before = dict(connection.execute("SELECT * FROM articles WHERE id=1").fetchone())
            counts_before = {
                "classifications": connection.execute("SELECT COUNT(*) FROM threat_classification_runs").fetchone()[0],
                "severity": connection.execute("SELECT COUNT(*) FROM severity_assessments").fetchone()[0],
                "correlations": connection.execute("SELECT COUNT(*) FROM correlation_assessments").fetchone()[0],
            }
        changed = dict(article, content=changed_content)
        second_result = summarize_article(changed)
        self.assertNotEqual(first_result.source_text_fingerprint, second_result.source_text_fingerprint)
        self.assertTrue(save_summary_result(1, second_result, self.db_path)["saved"])
        save_manual_summary(
            1, summary_language="en", summary_text="Human-reviewed summary.",
            source_text_fingerprint=source_fingerprint(changed_content), source_text_used=changed_content,
            supporting_evidence=[],
            key_intelligence={}, source_metadata={"source": "Test publisher"}, db_path=self.db_path,
        )
        protected = save_summary_result(1, second_result, self.db_path)
        self.assertFalse(protected["saved"])
        self.assertEqual(protected["reason"], "human_review_preserved")
        initialize_database(self.db_path, seed_demo=False)
        history = load_summary_history(1, self.db_path)
        self.assertEqual(len(history), 3)
        self.assertEqual(history.iloc[0]["summary_status"], "human_reviewed")
        self.assertEqual(history.iloc[0]["source_text_used"], changed_content)
        with connect(self.db_path) as connection:
            after = dict(connection.execute("SELECT * FROM articles WHERE id=1").fetchone())
            counts_after = {
                "classifications": connection.execute("SELECT COUNT(*) FROM threat_classification_runs").fetchone()[0],
                "severity": connection.execute("SELECT COUNT(*) FROM severity_assessments").fetchone()[0],
                "correlations": connection.execute("SELECT COUNT(*) FROM correlation_assessments").fetchone()[0],
            }
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM article_summaries WHERE article_id=1").fetchone()[0], 3)
        self.assertEqual(after["content"], before["content"])
        self.assertEqual(counts_after, counts_before)


if __name__ == "__main__":
    unittest.main()
