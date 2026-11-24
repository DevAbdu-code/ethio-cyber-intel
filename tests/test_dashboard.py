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


def test_dashboard_classifies_pending_demo_records(tmp_path, monkeypatch):
    monkeypatch.setenv("ETHIO_CYBER_DB_PATH", str(tmp_path / "dashboard.sqlite"))
    app_path = Path(__file__).resolve().parents[1] / "app.py"
    result = AppTest.from_file(str(app_path)).run()
    result.button[1].click().run()
    assert not result.exception
