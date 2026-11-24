"""Evaluate the rule baseline against a separately curated reviewed JSONL set."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ethio_cyber_intel.threat_classification import (  # noqa: E402
    THREAT_CATEGORIES, classify_text,
)

LANGUAGES = ("en", "am", "om")


def _scores(tp: int, fp: int, fn: int, support: int) -> dict:
    if support == 0 and tp + fp + fn == 0:
        return {"precision": None, "recall": None, "f1": None,
                "support": 0, "tp": 0, "fp": 0, "fn": 0}
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4), "support": support, "tp": tp, "fp": fp, "fn": fn}


def evaluate(path: Path) -> dict:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")]
    for index, row in enumerate(rows, start=1):
        if row.get("manually_reviewed") is not True:
            raise ValueError(f"Record {index} must have manually_reviewed: true")
        if row.get("language") not in LANGUAGES:
            raise ValueError(f"Record {index} language must be one of {LANGUAGES}")
        if not isinstance(row.get("labels"), list) or not row["labels"]:
            raise ValueError(f"Record {index} must include a non-empty labels array; use ['unknown'] when appropriate")
        if not set(row["labels"]).issubset(THREAT_CATEGORIES):
            raise ValueError(f"Record {index} includes unsupported categories")
        if not row.get("source_note"):
            raise ValueError(f"Record {index} must include source_note provenance")

    category_counts = {label: [0, 0, 0, 0] for label in THREAT_CATEGORIES}  # TP, FP, FN, support
    language_counts = {language: [0, 0, 0, 0] for language in LANGUAGES}
    exact_matches = 0
    for row in rows:
        truth = set(row["labels"])
        prediction = {item.category for item in classify_text(
            title=row.get("text", ""), description=None, content=None,
            language=row["language"],
        ).categories}
        exact_matches += prediction == truth
        for category in THREAT_CATEGORIES:
            tp = int(category in truth and category in prediction)
            fp = int(category not in truth and category in prediction)
            fn = int(category in truth and category not in prediction)
            item = category_counts[category]
            item[0] += tp; item[1] += fp; item[2] += fn; item[3] += int(category in truth)
        item = language_counts[row["language"]]
        item[0] += len(truth & prediction)
        item[1] += len(prediction - truth)
        item[2] += len(truth - prediction)
        item[3] += 1

    per_category = {label: _scores(*counts) for label, counts in category_counts.items()}
    per_language = {}
    for language, (tp, fp, fn, support) in language_counts.items():
        scores = _scores(tp, fp, fn, support)
        scores["examples"] = support
        per_language[language] = scores
    total_tp = sum(item[0] for item in category_counts.values())
    total_fp = sum(item[1] for item in category_counts.values())
    total_fn = sum(item[2] for item in category_counts.values())
    return {
        "dataset": str(path), "evaluated_examples": len(rows),
        "manually_reviewed_examples": len(rows),
        "subset_accuracy": round(exact_matches / len(rows), 4) if rows else None,
        "micro": _scores(total_tp, total_fp, total_fn, len(rows)),
        "per_category": per_category, "per_language": per_language,
        "multilabel_confusion_by_category": {
            label: {"tp": values[0], "fp": values[1], "fn": values[2],
                    "tn": len(rows) - values[0] - values[1] - values[2]}
            for label, values in category_counts.items()
        },
        "interpretation": "No research performance claim is supported by an empty or small convenience sample.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", nargs="?", type=Path,
                        default=Path("evaluation/threat_eval.jsonl"))
    args = parser.parse_args()
    print(json.dumps(evaluate(args.dataset), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
