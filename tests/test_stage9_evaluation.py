import json
from pathlib import Path

import pytest

from scripts.evaluate_extraction import evaluate as evaluate_extraction
from scripts.evaluate_language import evaluate as evaluate_language
from scripts.evaluate_severity import evaluate as evaluate_severity
from scripts.evaluate_threat_classifier import evaluate as evaluate_threat
from scripts.run_research_evaluation import evaluate_all
from src.ethio_cyber_intel.evaluation_metrics import (
    classification_metrics, cohen_kappa, confusion_matrix, multilabel_metrics,
    read_jsonl, split_dataset, validate_unique,
)


def test_single_label_metrics_confusion_and_kappa_are_deterministic():
    actual = ["en", "am", "om", "om"]
    predicted = ["en", "am", "en", "om"]
    first = classification_metrics(actual, predicted, ("en", "am", "om"))
    assert first == classification_metrics(actual, predicted, ("en", "am", "om"))
    assert first["accuracy"] == 0.75
    assert first["confusion_matrix_rows_true_columns_predicted"]["om"]["en"] == 1
    assert cohen_kappa(confusion_matrix(actual, predicted, ("en", "am", "om")), ("en", "am", "om")) is not None


def test_empty_metrics_are_unavailable():
    scores = classification_metrics([], [], ("a", "b"))
    assert scores["accuracy"] is None
    assert scores["macro_f1"] is None
    assert multilabel_metrics([], [], ("phishing",))["micro"]["f1"] is None


def test_synthetic_and_research_rows_are_partitioned():
    result = split_dataset([{"synthetic": True}, {"synthetic": False}])
    assert len(result["synthetic"]) == len(result["research"]) == 1
    with pytest.raises(ValueError, match="synthetic"):
        split_dataset([{}])


def test_duplicate_research_record_ids_rejected():
    with pytest.raises(ValueError, match="Duplicate"):
        validate_unique([{"id": "a"}, {"id": "a"}], lambda row: row["id"], label="article")


def test_language_evaluator_does_not_report_synthetic_as_research():
    path = Path("evaluation/language_eval.jsonl")
    result = evaluate_language(path)
    assert result["independently_reviewed_real_records"] == 0
    assert result["research_metrics"] is None
    assert result["synthetic_sanity_check"]["examples"] == 15


def test_extraction_empty_dataset_and_human_review_gate(tmp_path: Path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("# none\n", encoding="utf-8")
    assert evaluate_extraction(empty)["research_metrics"] is None
    row = {"synthetic": True, "manually_reviewed": True, "review": {
        "identity_correct": True, "title_correct": True, "canonical_url_correct": True,
        "body_relevant": True, "source_attribution_correct": True}}
    empty.write_text(json.dumps(row) + "\n", encoding="utf-8")
    report = evaluate_extraction(empty)
    assert report["research_metrics"] is None
    assert report["synthetic_sanity_check"]["joint_valid_extraction_rate"] == 1.0


def test_severity_empty_dataset_retains_unknown_class_but_metrics_unavailable(tmp_path: Path):
    path = tmp_path / "empty.jsonl"
    path.write_text("# none\n", encoding="utf-8")
    result = evaluate_severity(path)
    assert result["accuracy"] is None
    assert result["per_class"]["Unknown"]["support"] == 0


def test_threat_multilabel_and_unknown_are_reported_separately(tmp_path: Path):
    path = tmp_path / "synthetic.jsonl"
    rows = [
        {"record_id": "s1", "synthetic": True, "manually_reviewed": True,
         "source_note": "synthetic test", "language": "en",
         "text": "Ransomware encrypted files and attackers stole customer records in a data breach.",
         "labels": ["ransomware", "data_breach"]},
        {"record_id": "s2", "synthetic": True, "manually_reviewed": True,
         "source_note": "synthetic test", "language": "en",
         "text": "The organization published its quarterly financial report today.",
         "labels": ["unknown"]},
    ]
    path.write_text("\n".join(json.dumps(row) for row in rows), encoding="utf-8")
    report = evaluate_threat(path)
    assert report["research_metrics"]["examples"] == 0
    sanity = report["synthetic_sanity_check"]
    assert sanity["per_category"]["ransomware"]["support"] == 1
    assert sanity["per_category"]["data_breach"]["support"] == 1
    assert "unknown" not in sanity["per_category"]
    assert sanity["unknown_abstention"]["meaning"].startswith("unknown is evaluated")


def test_threat_evaluation_rejects_missing_gold_labels(tmp_path: Path):
    path = tmp_path / "missing-label.jsonl"
    path.write_text(json.dumps({"synthetic": True, "manually_reviewed": True,
                                "language": "en", "text": "Example", "labels": []}) + "\n",
                    encoding="utf-8")
    with pytest.raises(ValueError, match="labels"):
        evaluate_threat(path)


def test_unified_evaluation_is_reproducible_and_db_independent():
    first = evaluate_all()
    second = evaluate_all()
    assert first == second
    assert not any(first["real_world_metrics_available"].values())
