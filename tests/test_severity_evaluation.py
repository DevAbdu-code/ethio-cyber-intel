from pathlib import Path

import pytest

from scripts.evaluate_severity import evaluate


def test_empty_evaluation_reports_metrics_unavailable(tmp_path: Path):
    path = tmp_path / "empty.jsonl"
    path.write_text("# intentionally empty\n", encoding="utf-8")
    result = evaluate(path)
    assert result["evaluated_examples"] == 0
    assert result["agreement"] is None
    assert result["macro_f1"] is None
    assert result["per_class"]["Critical"]["f1"] is None


def test_evaluation_rejects_non_reviewed_rows(tmp_path: Path):
    path = tmp_path / "unreviewed.jsonl"
    path.write_text(
        '{"text":"test-only phrase", "language":"en", "human_severity":"High", "synthetic":true, '
        '"manually_reviewed":false, "source_note":"unit test"}\n', encoding="utf-8"
    )
    with pytest.raises(ValueError, match="manually_reviewed"):
        evaluate(path)
