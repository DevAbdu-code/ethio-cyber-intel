"""Evaluation tooling tests use an empty temporary file, never test fixtures."""

from pathlib import Path

import pytest

from scripts.evaluate_threat_classifier import evaluate


def test_empty_research_dataset_reports_no_metrics(tmp_path: Path):
    dataset = tmp_path / "empty.jsonl"
    dataset.write_text("# no reviewed examples yet\n", encoding="utf-8")
    report = evaluate(dataset)
    assert report["evaluated_examples"] == 0
    assert report["subset_accuracy"] is None
    assert report["micro"]["f1"] is None
    assert report["per_category"]["phishing"]["precision"] is None


def test_evaluation_rejects_unreviewed_rows(tmp_path: Path):
    dataset = tmp_path / "not-reviewed.jsonl"
    dataset.write_text(
        '{"text":"synthetic test phrase", "language":"en", "labels":["phishing"], "synthetic":true, '
        '"manually_reviewed":false, "source_note":"unit test"}\n', encoding="utf-8"
    )
    with pytest.raises(ValueError, match="manually_reviewed"):
        evaluate(dataset)
