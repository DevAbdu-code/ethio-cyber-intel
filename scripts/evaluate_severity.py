"""Evaluate severity decisions against manually reviewed JSONL labels."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ethio_cyber_intel.evaluation_metrics import (  # noqa: E402
    classification_metrics, read_jsonl, split_dataset, validate_research_provenance, validate_unique,
)
from src.ethio_cyber_intel.severity_assessment import SEVERITY_LEVELS, assess_severity  # noqa: E402

LANGUAGES = ("en", "am", "om", "und", "mul")


def _metric(tp: int, fp: int, fn: int, support: int) -> dict:
    if tp + fp + fn == 0:
        return {"precision": None, "recall": None, "f1": None, "support": support}
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4), "support": support}


def _evaluate_rows(rows: list[dict]) -> dict | None:
    if not rows:
        return None
    truth, predictions, languages = [], [], []
    for row in rows:
        article = {"title": row.get("text", ""), "source": row.get("source", "Evaluation source"),
                   "url": row.get("url"), "published_at": row.get("published_at")}
        truth.append(row["human_severity"])
        predictions.append(assess_severity(article, row.get("external_evidence")).severity)
        languages.append(row["language"])
    result = classification_metrics(truth, predictions, SEVERITY_LEVELS)
    result["by_language"] = {
        lang: classification_metrics([truth[i] for i, value in enumerate(languages) if value == lang],
                                     [predictions[i] for i, value in enumerate(languages) if value == lang],
                                     SEVERITY_LEVELS) if lang in languages else None
        for lang in LANGUAGES
    }
    # Ordinal agreement excludes Unknown rather than assigning it an invented rank.
    ordered = ["Critical", "High", "Medium", "Low", "Informational"]
    indices = [i for i, value in enumerate(truth) if value in ordered and predictions[i] in ordered]
    result["ordinal_agreement"] = round(sum(truth[i] == predictions[i] for i in indices) / len(indices), 4) if indices else None
    result["weighted_agreement"] = round(
        sum(1 - abs(ordered.index(truth[i]) - ordered.index(predictions[i])) / (len(ordered) - 1)
            for i in indices) / len(indices), 4
    ) if indices else None
    result["ordinal_weighted_kappa"] = _weighted_kappa([truth[i] for i in indices], [predictions[i] for i in indices], ordered)
    result["ordinal_examples"] = len(indices)
    result["unknown_involved_examples"] = len(rows) - len(indices)
    return result


def _weighted_kappa(actual: list[str], predicted: list[str], labels: tuple[str, ...]) -> float | None:
    n = len(actual)
    if not n:
        return None
    matrix = [[0] * len(labels) for _ in labels]
    for a, p in zip(actual, predicted):
        matrix[labels.index(a)][labels.index(p)] += 1
    observed = sum(matrix[i][j] * ((i-j) ** 2) / ((len(labels)-1) ** 2)
                   for i in range(len(labels)) for j in range(len(labels))) / n
    row = [sum(line) for line in matrix]
    col = [sum(matrix[i][j] for i in range(len(labels))) for j in range(len(labels))]
    expected = sum(row[i] * col[j] * ((i-j) ** 2) / ((len(labels)-1) ** 2)
                   for i in range(len(labels)) for j in range(len(labels))) / (n*n)
    return round(1 - observed / expected, 4) if expected else None


def evaluate(path: Path) -> dict:
    rows = read_jsonl(path)
    groups = split_dataset(rows)
    for index, row in enumerate(rows, 1):
        if row.get("manually_reviewed") is not True:
            raise ValueError(f"Record {index} must set manually_reviewed to true")
        if row.get("human_severity") not in SEVERITY_LEVELS:
            raise ValueError(f"Record {index} has unsupported human_severity")
        if row.get("language") not in LANGUAGES:
            raise ValueError(f"Record {index} has unsupported language")
        if not row.get("synthetic"):
            validate_research_provenance(row, index)
    validate_unique(groups["research"], lambda r: r.get("article_id") or r.get("record_id"), label="article")
    research = _evaluate_rows(groups["research"])
    synthetic = _evaluate_rows(groups["synthetic"])
    report = research or {"examples": 0, "accuracy": None, "macro_f1": None,
                          "cohen_kappa": None, "weighted_agreement": None,
                          "per_class": {s: {"precision": None, "recall": None, "f1": None, "support": 0} for s in SEVERITY_LEVELS},
                          "confusion_matrix_rows_true_columns_predicted": {s: {p: 0 for p in SEVERITY_LEVELS} for s in SEVERITY_LEVELS},
                          "by_language": {lang: None for lang in LANGUAGES}, "ordinal_agreement": None,
                          "ordinal_weighted_kappa": None, "ordinal_examples": 0, "unknown_involved_examples": 0}
    return {
        "dataset": str(path), "evaluated_examples": len(rows),
        "independently_reviewed_real_examples": len(groups["research"]),
        "research_metrics": research, "synthetic_sanity_check": synthetic,
        "agreement": report["accuracy"], "macro_f1": report["macro_f1"],
        "per_class": report["per_class"], "by_language": report["by_language"],
        "accuracy": report["accuracy"], "weighted_agreement": report["weighted_agreement"],
        "cohen_kappa": report["cohen_kappa"],
        "confusion_matrix_rows_human_columns_automated": report["confusion_matrix_rows_true_columns_predicted"],
        "ordinal_agreement": report["ordinal_agreement"],
        "ordinal_weighted_kappa": report["ordinal_weighted_kappa"],
        "ordinal_examples": report["ordinal_examples"],
        "unknown_involved_examples": report["unknown_involved_examples"],
        "interpretation": "No severity performance claim is supported by an empty or small convenience sample.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", nargs="?", type=Path, default=Path("evaluation/severity_eval.jsonl"))
    args = parser.parse_args()
    print(json.dumps(evaluate(args.dataset), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
