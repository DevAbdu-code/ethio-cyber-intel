"""Streamlit dashboard compatibility smoke test."""

from pathlib import Path

from streamlit.testing.v1 import AppTest


def test_dashboard_renders_language_summary_without_exception(tmp_path, monkeypatch):
    monkeypatch.setenv("ETHIO_CYBER_DB_PATH", str(tmp_path / "dashboard.sqlite"))
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    result = AppTest.from_file(str(app_path)).run()
    assert not result.exception
    assert any("English" in metric.label for metric in result.metric)
    assert any("Unknown classification" == metric.label for metric in result.metric)
    assert any("Language not assessed" == metric.label for metric in result.metric)
    assert any("Not classified" == metric.label for metric in result.metric)
    assert any("Severity not assessed" == metric.label for metric in result.metric)
    assert any("Summary not generated" == metric.label for metric in result.metric)
    assert any("Threat category distribution" in item.value for item in result.subheader)
    assert any("Detect language for legacy reports" in button.label for button in result.button)
    assert any("Classify pending reports" in button.label for button in result.button)
    assert any("Assess pending severity" in button.label for button in result.button)
    assert any("Critical and High priority reports" in item.value for item in result.subheader)


def test_dashboard_classifies_pending_demo_records(tmp_path, monkeypatch):
    monkeypatch.setenv("ETHIO_CYBER_DB_PATH", str(tmp_path / "dashboard.sqlite"))
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    result = AppTest.from_file(str(app_path)).run()
    button = next(item for item in result.button if item.label == "🏷️ Classify pending reports")
    button.click().run()
    assert not result.exception


def test_dashboard_legacy_language_action_updates_only_pending_labels(tmp_path, monkeypatch):
    import sqlite3

    db_path = tmp_path / "legacy-language-dashboard.sqlite"
    from src.ethio_cyber_intel.database import initialize_database
    initialize_database(db_path, seed_demo=False)
    with sqlite3.connect(db_path) as connection:
        connection.execute(
            """INSERT INTO articles (title,url,source,language,language_reviewed,summary,report_status,is_demo)
               VALUES (?,?,?,?,?,?,?,?)""",
            ("The vendor has released a security patch for the reported flaw and the affected users",
             "https://example.test/legacy", "Example News", "und", 0,
             "The update fixes a security flaw that was reported by researchers.", "collected", 0),
        )
    monkeypatch.setenv("ETHIO_CYBER_DB_PATH", str(db_path))
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    result = AppTest.from_file(str(app_path)).run()
    action = next(button for button in result.button if button.label == "🔤 Detect language for legacy reports")
    result = action.click().run()
    assert not result.exception
    assert any(metric.label == "Language not assessed" and metric.value == "0" for metric in result.metric)
    with sqlite3.connect(db_path) as connection:
        row = connection.execute(
            "SELECT language,language_method,language_reviewed FROM articles WHERE url=?",
            ("https://example.test/legacy",),
        ).fetchone()
    assert row == ("en", "lexical_cues_en", 0)


def test_dashboard_assesses_pending_severity(tmp_path, monkeypatch):
    monkeypatch.setenv("ETHIO_CYBER_DB_PATH", str(tmp_path / "dashboard.sqlite"))
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    result = AppTest.from_file(str(app_path)).run()
    button = next(button for button in result.button if button.label == "⚖️ Assess pending severity")
    button.click().run()
    assert not result.exception


def test_dashboard_correlates_and_human_confirms_candidate(tmp_path, monkeypatch):
    from src.ethio_cyber_intel.database import initialize_database, insert_live_articles

    db_path = tmp_path / "correlation.sqlite"
    initialize_database(db_path, seed_demo=False)
    insert_live_articles([
        {"title": "CVE-2026-99112 exposure report", "url": "https://example.test/en",
         "source": "Example EN", "language": "en"},
        {"title": "CVE-2026-99112 ሪፖርት", "url": "https://example.test/am",
         "source": "Example AM", "language": "am"},
    ], db_path)
    monkeypatch.setenv("ETHIO_CYBER_DB_PATH", str(db_path))
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    result = AppTest.from_file(str(app_path)).run()
    action = next(button for button in result.button if button.label == "🔗 Correlate collected reports")
    result = action.click().run()
    assert not result.exception
    assert any("Candidate relationships" == metric.label and metric.value == "1" for metric in result.metric)
    confirm = next(button for button in result.button if button.label == "Confirm related reports")
    result = confirm.click().run()
    assert not result.exception
    assert any("Human confirmed" == metric.label and metric.value == "1" for metric in result.metric)


def test_dashboard_summary_workspace_generates_and_displays_history(tmp_path, monkeypatch):
    from src.ethio_cyber_intel.database import initialize_database, insert_live_articles

    db_path = tmp_path / "summary.sqlite"
    initialize_database(db_path, seed_demo=False)
    content = (
        "Researchers reviewed a security issue affecting network software. "
        "The report identifies CVE-2026-99190 in its published details. "
        "The source recommends that administrators review vendor guidance. "
        "No independent exploitation confirmation is included in this test text."
    )
    insert_live_articles([{
        "title": "Synthetic article selected for summary test",
        "url": "https://example.test/summary", "source": "Synthetic source",
        "language": "en", "published_at": None, "content": content,
            "content_validation_status": "rss_feed_entry",
    }], db_path)
    monkeypatch.setenv("ETHIO_CYBER_DB_PATH", str(db_path))
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    result = AppTest.from_file(str(app_path)).run()
    assert not result.exception
    assert any("Evidence-Grounded Article Summary" in item.value for item in result.subheader)
    action = next(button for button in result.button if button.label == "Generate extractive summary")
    result = action.click().run()
    assert not result.exception
    visible = _app_visible_text(result)
    assert "**Generation status:** Summary available." in visible
    assert "Summary generation status:" not in visible
    assert any("Summary history (1 records)" in expander.label for expander in result.expander)
    assert any("Key Intelligence" in item.value for item in result.markdown)
    assert any("CVE identifiers" in table.value.to_string() for table in result.table)
    assert not result.json
    assert any(metric.label == "Summary created" and metric.value == "1" for metric in result.metric)


def _summary_article_fixture():
    return {
        "title": "Synthetic article selected for summary test",
        "url": "https://example.test/summary-language",
        "source": "Synthetic source",
        "language": "en",
        "published_at": None,
        "content": (
            "Researchers reviewed a security issue affecting network software. "
            "The report identifies CVE-2026-99190 in its published details. "
            "The source recommends that administrators review vendor guidance. "
            "No independent exploitation confirmation is included in this test text."
        ),
        "content_validation_status": "rss_feed_entry",
    }


def _app_visible_text(result):
    parts = []
    for name in ("markdown", "text", "info", "warning", "error", "success", "caption"):
        parts.extend(str(item.value) for item in getattr(result, name, []))
    return "\n".join(parts)


def test_dashboard_translation_request_offers_original_language_summary(tmp_path, monkeypatch):
    from src.ethio_cyber_intel.database import initialize_database, insert_live_articles, connect

    db_path = tmp_path / "summary-translation.sqlite"
    initialize_database(db_path, seed_demo=False)
    insert_live_articles([_summary_article_fixture()], db_path)
    monkeypatch.setenv("ETHIO_CYBER_DB_PATH", str(db_path))
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    result = AppTest.from_file(str(app_path)).run()
    language = next(item for item in result.selectbox if item.key == "summary_language")
    result = language.set_value("am").run()
    assert not result.exception
    assert "Translation is not available in the current baseline. The original-language summary can still be generated." in _app_visible_text(result)
    action = next(item for item in result.button if item.label == "Generate original-language summary (English)")
    result = action.click().run()
    assert not result.exception
    assert "**Generation status:** Summary available." in _app_visible_text(result)
    assert "Researchers reviewed a security issue affecting network software." in _app_visible_text(result)
    with connect(db_path) as connection:
        rows = connection.execute(
            "SELECT summary_language,summary_status,summary_text FROM article_summaries ORDER BY id"
        ).fetchall()
    assert len(rows) == 1
    assert rows[0][0:2] == ("en", "original_extractive")
    assert rows[0][2]


def test_dashboard_null_summary_text_does_not_render_nan_and_preserves_history(tmp_path, monkeypatch):
    from src.ethio_cyber_intel.database import initialize_database, insert_live_articles, connect, save_summary_result
    from src.ethio_cyber_intel.summarization import summarize_article

    db_path = tmp_path / "summary-null.sqlite"
    initialize_database(db_path, seed_demo=False)
    article = _summary_article_fixture()
    insert_live_articles([article], db_path)
    generated = summarize_article(dict(article, id=1))
    assert save_summary_result(1, generated, db_path)["saved"]
    unavailable = summarize_article(dict(article, id=1), requested_language="am")
    assert save_summary_result(1, unavailable, db_path)["saved"]
    monkeypatch.setenv("ETHIO_CYBER_DB_PATH", str(db_path))
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    result = AppTest.from_file(str(app_path)).run()
    assert not result.exception
    visible = _app_visible_text(result).casefold()
    assert "nan" not in visible
    assert "none" not in visible
    # The selector defaults to the source language; cross-language requests are
    # explicitly tested in test_dashboard_translation_request_offers_original_language_summary.
    assert "Researchers reviewed a security issue affecting network software." in _app_visible_text(result)
    with connect(db_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM article_summaries").fetchone()[0] == 2


def test_dashboard_hides_stale_automated_summary_until_updated_and_preserves_history(tmp_path, monkeypatch):
    from src.ethio_cyber_intel.database import initialize_database, insert_live_articles, connect, save_summary_result
    from src.ethio_cyber_intel.summarization import summarize_article

    db_path = tmp_path / "summary-stale-method.sqlite"
    initialize_database(db_path, seed_demo=False)
    article = _summary_article_fixture()
    insert_live_articles([article], db_path)
    prior = summarize_article(dict(article, id=1)).as_dict()
    prior["summary_text"] = "Older long summary that should not be mistaken for the current concise method."
    prior["method_version"] = "1.0"
    assert save_summary_result(1, prior, db_path)["saved"]
    monkeypatch.setenv("ETHIO_CYBER_DB_PATH", str(db_path))
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    result = AppTest.from_file(str(app_path)).run()
    assert not result.exception
    assert "Earlier history is preserved." in _app_visible_text(result)
    assert not any("Older long summary" in item.value for item in result.markdown)
    action = next(item for item in result.button if item.label == "Generate updated extractive summary")
    result = action.click().run()
    assert not result.exception
    assert "Researchers reviewed a security issue affecting network software." in _app_visible_text(result)
    with connect(db_path) as connection:
        rows = connection.execute(
            "SELECT method_version,summary_text FROM article_summaries ORDER BY id"
        ).fetchall()
    assert len(rows) == 2
    assert rows[0][0] == "1.0"
    assert rows[0][1].startswith("Older long summary")
    assert rows[1][0] == "2.0"
    assert rows[1][1] != rows[0][1]


def test_dashboard_never_labels_null_summary_as_available(tmp_path, monkeypatch):
    import json
    from src.ethio_cyber_intel.database import initialize_database, insert_live_articles, connect

    db_path = tmp_path / "summary-empty-success.sqlite"
    initialize_database(db_path, seed_demo=False)
    insert_live_articles([_summary_article_fixture()], db_path)
    with connect(db_path) as connection:
        connection.execute(
            """INSERT INTO article_summaries
               (article_id,summary_language,summary_text,summary_method,summary_status,
                supporting_evidence_json,method_version,created_at,source_text_fingerprint,
                source_text_used,summary_kind,key_intelligence_json,source_metadata_json)
               VALUES (1,'en',NULL,'extractive_sentence_ranking','original_extractive',
                       '[]','1.0','2026-01-01T00:00:00Z','legacy-fingerprint',?,'original_language_extractive','{}',?)""",
            (_summary_article_fixture()["content"], json.dumps({"source_language": "en"})),
        )
    monkeypatch.setenv("ETHIO_CYBER_DB_PATH", str(db_path))
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    result = AppTest.from_file(str(app_path)).run()
    assert not result.exception
    assert any(item.label == "Summary created" and item.value == "0" for item in result.metric)
    assert any(item.label == "Summary unavailable" and item.value == "1" for item in result.metric)
    visible = _app_visible_text(result).casefold()
    assert "summary not generated." in visible
    assert "summary available." not in visible
    assert "nan" not in visible


def test_dashboard_reports_summary_generation_failure(tmp_path, monkeypatch):
    import app as dashboard

    def fail_generation(*args, **kwargs):
        raise RuntimeError("synthetic generator failure")

    monkeypatch.setattr(dashboard, "summarize_article", fail_generation)
    result, error = dashboard._generate_summary_result(_summary_article_fixture(), "en")
    assert result is None
    assert isinstance(error, RuntimeError)
    assert dashboard._summary_status_label("generation_failed") == "Summary generation failed"


def test_changing_requested_language_does_not_replace_human_summary(tmp_path, monkeypatch):
    from src.ethio_cyber_intel.database import (
        initialize_database, insert_live_articles, connect, save_manual_summary,
    )
    from src.ethio_cyber_intel.summarization import source_fingerprint

    db_path = tmp_path / "summary-human-review.sqlite"
    initialize_database(db_path, seed_demo=False)
    article = _summary_article_fixture()
    insert_live_articles([article], db_path)
    save_manual_summary(
        1, summary_language="en", summary_text="Human-reviewed source summary.",
        source_text_fingerprint=source_fingerprint(article["content"]),
        source_text_used=article["content"], supporting_evidence=[],
        key_intelligence={}, source_metadata={"source_language": "en"}, db_path=db_path,
    )
    monkeypatch.setenv("ETHIO_CYBER_DB_PATH", str(db_path))
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    result = AppTest.from_file(str(app_path)).run()
    result = next(item for item in result.selectbox if item.key == "summary_language").set_value("am").run()
    assert not any(item.label.startswith("Generate") for item in result.button)
    assert "Human-reviewed English summary." in _app_visible_text(result)
    assert "Existing human-reviewed summary was preserved." not in _app_visible_text(result)
    assert "Human-reviewed source summary." in _app_visible_text(result)
    with connect(db_path) as connection:
        rows = connection.execute(
            "SELECT summary_language,summary_status,summary_text FROM article_summaries ORDER BY id"
        ).fetchall()
    assert len(rows) == 1
    assert rows[0][0:2] == ("en", "human_reviewed")
    assert rows[0][2] == "Human-reviewed source summary."
