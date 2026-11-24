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
    assert any("Evidence-grounded article summary" in item.value for item in result.subheader)
    action = next(button for button in result.button if button.label == "Generate extractive summary")
    result = action.click().run()
    assert not result.exception
    assert any("original_extractive" in expander.label for expander in result.expander)
    assert any(metric.label == "Summary created" and metric.value == "1" for metric in result.metric)
