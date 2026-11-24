"""Offline tests for RSS parsing, normalization, errors, and persistence."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import Mock

import requests

from src.ethio_cyber_intel.article_extractor import clean_html
from src.ethio_cyber_intel.database import initialize_database, insert_live_articles
from src.ethio_cyber_intel.rss_collector import collect_source, normalize_entry
from src.ethio_cyber_intel.rss_sources import FeedSource


FEED_XML = b"""<?xml version='1.0' encoding='UTF-8'?>
<rss version='2.0'><channel><title>Security Desk</title>
<item><title>  Example &lt;b&gt;security&lt;/b&gt; report  </title>
<link>https://news.example.test/report-1</link>
<description>&lt;p&gt;A sufficiently detailed description for repeatable tests. &amp;amp; more text.&lt;/p&gt;</description>
<pubDate>Tue, 14 Jan 2025 10:30:00 GMT</pubDate></item>
</channel></rss>"""


def source(**overrides):
    values = dict(
        name="Example Security News", url="https://news.example.test/feed.xml",
        homepage="https://news.example.test/", enabled=True,
        max_articles=10, delay_seconds=0,
    )
    values.update(overrides)
    return FeedSource(**values)


class RSSCollectorTests(unittest.TestCase):
    def test_html_cleanup_and_entry_normalization(self):
        self.assertEqual(clean_html("<p>Hello <b>security</b></p>\n <script>bad()</script>"), "Hello security")
        parsed = __import__("feedparser").parse(FEED_XML)
        article = normalize_entry(parsed.entries[0], source())
        self.assertEqual(article["title"], "Example security report")
        self.assertIn("sufficiently detailed description", article["summary"])
        self.assertEqual(article["published_at"], "2025-01-14T10:30:00Z")
        self.assertEqual(article["language"], "en")
        self.assertEqual(article["language_method"], "lexical_cues_en")
        self.assertGreaterEqual(article["language_confidence"], 0.60)
        self.assertEqual(article["url"], "https://news.example.test/report-1")
        self.assertEqual(article["content_validation_status"], "not_available")

    def test_normalized_rss_entry_receives_language_metadata(self):
        article = normalize_entry({
            "title": "የድርጅቱ ደህንነት ቡድን",
            "summary": "የማልዌር ስርጭትን እየመረመረ ነው።",
            "link": "https://news.example.test/amharic",
        }, source())
        self.assertEqual(article["language"], "am")
        self.assertEqual(article["language_method"], "ethiopic_script")
        self.assertGreaterEqual(article["language_confidence"], 0.60)
        self.assertEqual(article["language_reviewed"], 0)

    def test_rss_language_metadata_persists_with_original_content(self):
        article = normalize_entry({
            "title": "Qorannoon nageenyaa haleellaa saayibaraa mootummaa irratti raawwatame qorachaa jira.",
            "summary": "Odeeffannoon uummataa saamameera; tajaajilli qorannoo itti fufe.",
            "link": "https://news.example.test/oromo",
        }, source())
        with tempfile.TemporaryDirectory() as temporary:
            db_path = Path(temporary) / "rss.sqlite"
            initialize_database(db_path, seed_demo=False)
            stats = insert_live_articles([article], db_path)
            with sqlite3.connect(db_path) as connection:
                row = connection.execute(
                    "SELECT language, language_confidence, language_method, content, summary FROM articles"
                ).fetchone()
        self.assertEqual(stats["inserted"], 1)
        self.assertEqual(row[0], "om")
        self.assertGreaterEqual(row[1], 0.60)
        self.assertEqual(row[2], "lexical_cues_om")
        self.assertIsNone(row[3])
        self.assertIn("Odeeffannoon", row[4])

    def test_missing_date_is_preserved_as_none(self):
        item = {"title": "No date", "link": "https://news.example.test/no-date"}
        normalized = normalize_entry(item, source())
        self.assertIsNone(normalized["published_at"])

    def test_feed_response_parses_entries(self):
        session = Mock()
        session.get.return_value.content = FEED_XML
        session.get.return_value.raise_for_status.return_value = None
        result = collect_source(source(), session=session)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["entries_seen"], 1)
        self.assertEqual(len(result["articles"]), 1)

    def test_invalid_feed_is_reported_without_raising(self):
        session = Mock()
        session.get.return_value.content = b"<html><body>not a feed</body></html>"
        session.get.return_value.raise_for_status.return_value = None
        result = collect_source(source(), session=session)
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(result["articles"], [])

    def test_network_timeout_is_reported_without_raising(self):
        session = Mock()
        session.get.side_effect = requests.Timeout("timeout")
        result = collect_source(source(), session=session)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["message"], "Request timed out")

    def test_database_inserts_live_rows_and_detects_url_and_fingerprint_duplicates(self):
        with tempfile.TemporaryDirectory() as temporary:
            db_path = Path(temporary) / "articles.sqlite"
            initialize_database(db_path, seed_demo=True)
            first = {
                "title": "A useful cybersecurity update from a public source",
                "url": "https://news.example.test/report-a",
                "source": "Example Security News",
                "published_at": datetime(2025, 1, 14, tzinfo=timezone.utc).isoformat(),
                "language": "und",
                "summary": "The article contains enough unique explanatory text to produce a stable exact-content fingerprint for the duplicate check.",
                "content": None,
            }
            url_duplicate = dict(first)
            alternate_url_duplicate = dict(first, url="https://news.example.test/report-b")
            stats = insert_live_articles([first, url_duplicate, alternate_url_duplicate], db_path)
            self.assertEqual(stats["inserted"], 1)
            self.assertEqual(stats["duplicate_url"], 1)
            self.assertEqual(stats["duplicate_content"], 1)
            with sqlite3.connect(db_path) as connection:
                rows = connection.execute(
                    "SELECT source, is_demo, report_status, language, fetched_at FROM articles WHERE url = ?",
                    (first["url"],),
                ).fetchall()
                demo_count = connection.execute("SELECT COUNT(*) FROM articles WHERE is_demo = 1").fetchone()[0]
            self.assertEqual(rows[0][:4], ("Example Security News", 0, "collected", "und"))
            self.assertTrue(rows[0][4])
            self.assertEqual(demo_count, 3)


if __name__ == "__main__":
    unittest.main()
