"""Offline end-to-end workflow checks using temporary SQLite and mocked feeds."""

import sqlite3
from unittest.mock import Mock

import requests

from src.ethio_cyber_intel.database import (
    assess_pending_articles, classify_pending_articles, correlate_pending_articles,
    initialize_database, insert_live_articles, save_summary_result,
)
from src.ethio_cyber_intel.dashboard_data import (
    load_article_detail, load_articles, load_current_classifications,
    load_current_correlations, load_current_severity_assessments,
)
from src.ethio_cyber_intel.rss_collector import collect_all
from src.ethio_cyber_intel.rss_sources import FeedSource
from src.ethio_cyber_intel.summarization import summarize_article


EN_FEED = b"""<rss version='2.0'><channel><title>Test</title><item>
<title>CVE-2026-77777 security vulnerability advisory</title>
<link>https://news.example.test/en-report</link>
<description>The publisher reports a security vulnerability in its network product. Administrators are advised to review the vendor notice. No confirmed exploitation or service impact is stated.</description>
</item></channel></rss>"""
AM_FEED = """<rss version='2.0'><channel><title>Test</title><item>
<title>CVE-2026-77777 የደህንነት ሪፖርት</title>
<link>https://news.example.test/am-report</link>
<description>ይህ ሪፖርት የደህንነት ችግርን ይገልጻል። አንባቢዎች የአቅራቢውን መመሪያ እንዲመለከቱ ይመክራል። ስለ ተጠቃሚዎች ወይም የአገልግሎት መቋረጥ መረጃ አልተገለጸም።</description>
</item></channel></rss>""".encode()


def _response(content: bytes) -> Mock:
    value = Mock()
    value.content = content
    value.raise_for_status.return_value = None
    return value


def test_mocked_live_pipeline_collects_analyzes_correlates_and_summarizes(tmp_path):
    db_path = tmp_path / "pipeline.sqlite"
    initialize_database(db_path, seed_demo=False)
    session = Mock()
    session.get.side_effect = [
        requests.Timeout("isolated feed outage"), _response(EN_FEED), _response(AM_FEED),
    ]
    sources = [
        FeedSource("Offline", "https://offline.example.test/feed", "https://offline.example.test"),
        FeedSource("English source", "https://news.example.test/en-feed", "https://news.example.test"),
        FeedSource("Amharic source", "https://news.example.test/am-feed", "https://news.example.test"),
    ]

    feed_results = collect_all(sources, session=session)
    assert [item["status"] for item in feed_results] == ["error", "ok", "ok"]
    collected = [article for result in feed_results for article in result["articles"]]
    assert len(collected) == 2
    assert all(article["source"] and article["url"] for article in collected)
    assert all(article["published_at"] is None for article in collected)
    inserted = insert_live_articles(collected, db_path)
    assert inserted["inserted"] == 2
    assert insert_live_articles(collected, db_path)["duplicate_url"] == 2

    classification = classify_pending_articles(db_path)
    severity = assess_pending_articles(db_path)
    correlation = correlate_pending_articles(db_path)
    assert classification["classified"] + classification["unknown"] == 2
    assert severity["assessed"] + severity["unknown"] == 2
    assert correlation["compared"] == 1
    assert correlation["candidates"] == correlation["saved"] == 1

    articles = load_articles(db_path)
    labels = load_current_classifications(db_path)
    severities = load_current_severity_assessments(db_path)
    relationships = load_current_correlations(db_path)
    assert len(articles) == 2
    assert set(articles["is_demo"]) == {0}
    assert len(labels) >= 1
    assert len(severities) == 2
    assert relationships.iloc[0]["status"] == "Candidate"

    english_id = int(articles.loc[articles["language"] == "en", "id"].iloc[0])
    detail = load_article_detail(english_id, db_path)
    summary = summarize_article(detail)
    saved = save_summary_result(english_id, summary, db_path)
    assert summary.status in {"original_extractive", "insufficient_content"}
    assert saved.get("saved") or saved.get("reason") == "duplicate_summary"

    with sqlite3.connect(db_path) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []

