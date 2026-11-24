"""Evaluate multilabel threat rules; `unknown` is measured as abstention, not threat."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ethio_cyber_intel.evaluation_metrics import (  # noqa: E402
    binary_metrics, multilabel_metrics, read_jsonl, split_dataset,
    validate_research_provenance, validate_unique,
)
from src.ethio_cyber_intel.threat_classification import THREAT_CATEGORIES, classify_text  # noqa: E402

LANGUAGES = ("en", "am", "om")
THREAT_LABELS = tuple(label for label in THREAT_CATEGORIES if label != "unknown")


def _evaluate_rows(rows: list[dict]) -> dict | None:
    if not rows:
        return None
    actual, predicted, raw_actual, raw_predicted, languages = [], [], [], [], []
    for row in rows:
        truth = set(row["labels"])
        result = classify_text(title=row.get("text", ""), description=None, content=None,
                               language=row["language"])
        prediction = {label.category for label in result.categories}
        raw_actual.append(truth)
        raw_predicted.append(prediction)
        actual.append(truth - {"unknown"})
        predicted.append(prediction - {"unknown"})
        languages.append(row["language"])

    positive_metrics = multilabel_metrics(actual, predicted, THREAT_LABELS)
    positive_metrics["subset_accuracy"] = round(
        sum(a == p for a, p in zip(raw_actual, raw_predicted)) / len(rows), 4
    )
    unknown_tp = sum("unknown" in a and "unknown" in p for a, p in zip(raw_actual, raw_predicted))
    unknown_fp = sum("unknown" not in a and "unknown" in p for a, p in zip(raw_actual, raw_predicted))
    unknown_fn = sum("unknown" in a and "unknown" not in p for a, p in zip(raw_actual, raw_predicted))
    unknown_tn = len(rows) - unknown_tp - unknown_fp - unknown_fn
    positive_metrics["unknown_abstention"] = {
        **binary_metrics(unknown_tp, unknown_fp, unknown_fn, unknown_tn),
        "meaning": "unknown is evaluated as a separate abstention/no-supported-category outcome, not as a threat class",
        "system_abstention_rate": round(sum("unknown" in p for p in raw_predicted) / len(rows), 4),
    }
    positive_metrics["per_language"] = {}
    for language in LANGUAGES:
        indices = [i for i, value in enumerate(languages) if value == language]
        metrics = multilabel_metrics([actual[i] for i in indices], [predicted[i] for i in indices], THREAT_LABELS)
        metrics["examples"] = len(indices)
        metrics["subset_accuracy_including_unknown"] = (
            round(sum(raw_actual[i] == raw_predicted[i] for i in indices) / len(indices), 4) if indices else None
        )
        positive_metrics["per_language"][language] = metrics
    return positive_metrics


def evaluate(path: Path) -> dict:
    rows = read_jsonl(path)
    for index, row in enumerate(rows, 1):
        if row.get("manually_reviewed") is not True:
            raise ValueError(f"Record {index} must have manually_reviewed: true")
        if row.get("language") not in LANGUAGES:
            raise ValueError(f"Record {index} language must be one of {LANGUAGES}")
        labels = row.get("labels")
        if not isinstance(labels, list) or not labels or not set(labels).issubset(THREAT_CATEGORIES):
            raise ValueError(f"Record {index} must include supported non-empty labels")
        if "unknown" in labels and len(labels) != 1:
            raise ValueError(f"Record {index}: unknown must appear alone, not as a threat multilabel")
        if not isinstance(row.get("text"), str) or not row["text"].strip():
            raise ValueError(f"Record {index} requires non-empty reviewed text")
        if not row.get("source_note"):
            raise ValueError(f"Record {index} requires source_note provenance")
    groups = split_dataset(rows)
    for index, row in enumerate(groups["research"], 1):
        validate_research_provenance(row, index)
    validate_unique(groups["research"], lambda row: row.get("article_id") or row.get("record_id"), label="article")
    validate_unique(groups["synthetic"], lambda row: row.get("record_id") or row.get("source_note"), label="synthetic record")

    research_metrics = _evaluate_rows(groups["research"])
    synthetic_metrics = _evaluate_rows(groups["synthetic"])
    # Legacy top-level metric keys intentionally alias real reviewed results
    # only; they are None when no independent real evaluation exists.
    research_metrics = research_metrics or {
        "examples": 0, "subset_accuracy": None,
        "micro": {"precision": None, "recall": None, "f1": None, "tp": 0, "fp": 0, "fn": 0},
        "macro_f1": None, "per_category": {label: {"precision": None, "recall": None, "f1": None, "support": 0} for label in THREAT_LABELS},
        "unknown_abstention": None, "per_language": {language: None for language in LANGUAGES},
    }
    return {
        "dataset": str(path), "evaluated_examples": len(rows),
        "independently_reviewed_real_examples": len(groups["research"]),
        "research_metrics": research_metrics,
        "synthetic_sanity_check": synthetic_metrics,
        "subset_accuracy": research_metrics.get("subset_accuracy"),
        "micro": research_metrics.get("micro"),
        "macro_f1": research_metrics.get("macro_f1"),
        "per_category": research_metrics.get("per_category"),
        "unknown_design": "unknown is excluded from threat-category macro/micro scores and evaluated separately as an abstention outcome",
        "interpretation": "Synthetic sanity-check metrics are not field-performance estimates. Research metrics are unavailable without independently reviewed real examples.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", nargs="?", type=Path, default=Path("evaluation/threat_eval.jsonl"))
    args = parser.parse_args()
    print(json.dumps(evaluate(args.dataset), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
