"""Report transparent classification metrics for a manually labeled JSONL file."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ethio_cyber_intel.language_detection import detect_language  # noqa: E402

LABELS = ("en", "am", "om", "und", "mul")


def evaluate(path: Path) -> dict:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    confusion = {truth: {prediction: 0 for prediction in LABELS} for truth in LABELS}
    counts = {label: 0 for label in LABELS}
    correct = 0
    for row in rows:
        truth = row["label"]
        if truth not in LABELS:
            raise ValueError(f"Unsupported ground-truth label: {truth}")
        if row.get("labeling") != "manually_labeled":
            raise ValueError("Each evaluation record must be marked manually_labeled")
        prediction = detect_language(row.get("text", "")).language
        counts[truth] += 1
        confusion[truth][prediction] += 1
        correct += prediction == truth

    per_language = {}
    for label in LABELS:
        tp = confusion[label][label]
        predicted = sum(confusion[truth][label] for truth in LABELS)
        support = counts[label]
        precision = tp / predicted if predicted else 0.0
        recall = tp / support if support else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_language[label] = {
            "precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4), "support": support,
        }
    total = len(rows)
    return {
        "dataset": str(path),
        "records": total,
        "synthetic_records": sum(bool(row.get("synthetic")) for row in rows),
        "accuracy": round(correct / total, 4) if total else 0.0,
        "macro_precision": round(sum(item["precision"] for item in per_language.values()) / len(LABELS), 4),
        "macro_recall": round(sum(item["recall"] for item in per_language.values()) / len(LABELS), 4),
        "macro_f1": round(sum(item["f1"] for item in per_language.values()) / len(LABELS), 4),
        "per_language": per_language,
        "confusion_matrix_rows_true_columns_predicted": confusion,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", nargs="?", type=Path, default=Path("evaluation/language_eval.jsonl"))
    args = parser.parse_args()
    print(json.dumps(evaluate(args.dataset), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
