"""Streamlit dashboard compatibility smoke test."""

from pathlib import Path

from streamlit.testing.v1 import AppTest


def test_dashboard_renders_language_summary_without_exception(tmp_path, monkeypatch):
    monkeypatch.setenv("ETHIO_CYBER_DB_PATH", str(tmp_path / "dashboard.sqlite"))
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    result = AppTest.from_file(str(app_path)).run()
    assert not result.exception
    assert any("English" in metric.label for metric in result.metric)
    assert any("Unknown or unclassified reports" == metric.label for metric in result.metric)
    assert any("Threat category distribution" in item.value for item in result.subheader)
    assert any("Classify pending reports" in button.label for button in result.button)
    assert any("Assess pending severity" in button.label for button in result.button)
    assert any("Critical and High priority reports" in item.value for item in result.subheader)


def test_dashboard_classifies_pending_demo_records(tmp_path, monkeypatch):
    monkeypatch.setenv("ETHIO_CYBER_DB_PATH", str(tmp_path / "dashboard.sqlite"))
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    result = AppTest.from_file(str(app_path)).run()
    result.button[1].click().run()
    assert not result.exception


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
