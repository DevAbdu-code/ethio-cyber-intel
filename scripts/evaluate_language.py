"""Evaluate language detection with synthetic and reviewed examples separated."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ethio_cyber_intel.evaluation_metrics import (  # noqa: E402
    classification_metrics, read_jsonl, split_dataset, validate_research_provenance, validate_unique,
)
from src.ethio_cyber_intel.language_detection import LANGUAGE_CODES, detect_language  # noqa: E402


def _evaluate_rows(rows: list[dict]) -> dict | None:
    if not rows:
        return None
    actual, predicted = [], []
    for row in rows:
        label = row.get("label")
        if label not in LANGUAGE_CODES:
            raise ValueError(f"Unsupported language label: {label!r}")
        text = row.get("text")
        if not isinstance(text, str):
            raise ValueError("Each language record requires text as a string")
        actual.append(label)
        predicted.append(detect_language(text).language)
    return classification_metrics(actual, predicted, LANGUAGE_CODES)


def evaluate(path: Path) -> dict:
    rows = read_jsonl(path)
    groups = split_dataset(rows)
    for index, row in enumerate(rows, 1):
        if row.get("labeling") not in {"manually_labeled", "adjudicated"}:
            raise ValueError(f"Record {index} requires a human label")
        if not row.get("source_note"):
            raise ValueError(f"Record {index} requires source_note provenance")
    research_rows = groups["research"]
    for index, row in enumerate(research_rows, 1):
        validate_research_provenance(row, index, article_keys=("article_id", "record_id"))

    # Synthetic rows do not receive a fabricated article identity. Use the
    # normalized text digest only to prevent repeated fixture rows.
    validate_unique(groups["synthetic"], lambda row: hashlib.sha256(
        " ".join(str(row.get("text", "")).split()).encode("utf-8")
    ).hexdigest(), label="synthetic text fingerprint")
    validate_unique(research_rows, lambda row: row.get("article_id") or row.get("record_id"), label="article")

    return {
        "dataset": str(path), "records": len(rows),
        "synthetic_records": len(groups["synthetic"]),
        "independently_reviewed_real_records": len(research_rows),
        "research_metrics": _evaluate_rows(research_rows),
        "synthetic_sanity_check": _evaluate_rows(groups["synthetic"]),
        "supported_labels": list(LANGUAGE_CODES),
        "interpretation": "Synthetic sanity-check metrics are not field-performance estimates. Research metrics are None when no independently reviewed real examples exist.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", nargs="?", type=Path, default=Path("evaluation/language_eval.jsonl"))
    args = parser.parse_args()
    print(json.dumps(evaluate(args.dataset), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
