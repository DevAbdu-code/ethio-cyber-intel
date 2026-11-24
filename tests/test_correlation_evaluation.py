from pathlib import Path

import pytest

from scripts.evaluate_correlation import evaluate


def test_empty_research_pairs_have_unavailable_metrics(tmp_path: Path):
    path = tmp_path / "empty.jsonl"
    path.write_text("# no adjudicated pairs\n", encoding="utf-8")
    report = evaluate(path)
    assert report["manually_reviewed_pairs"] == 0
    assert report["overall"]["f1"] is None
    assert report["overall"]["false_positive_rate"] is None
    assert all(value["precision"] is None for value in report["by_language_pair"].values())


def test_evaluation_requires_manual_review(tmp_path: Path):
    path = tmp_path / "unreviewed.jsonl"
    row = {
        "article_a": {"title": "synthetic A", "language": "en"},
        "article_b": {"title": "synthetic B", "language": "am"},
        "human_label": "unrelated_events", "manually_reviewed": False,
        "source_note": "unit test only",
    }
    import json
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="manually_reviewed"):
        evaluate(path)


def test_reviewed_synthetic_pair_metrics_use_requested_language_key(tmp_path: Path):
    import json
    path = tmp_path / "temporary-test-pair.jsonl"
    row = {
        "article_a": {"id": 1, "title": "CVE-2026-12345 report", "language": "en"},
        "article_b": {"id": 2, "title": "CVE-2026-12345 ሪፖርት", "language": "am"},
        "human_label": "same_incident", "manually_reviewed": True,
        "source_note": "Synthetic temporary test record; not research data",
    }
    path.write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")
    result = evaluate(path)
    assert result["overall"]["recall"] == 1.0
    assert result["by_language_pair"]["en-am"]["tp"] == 1
