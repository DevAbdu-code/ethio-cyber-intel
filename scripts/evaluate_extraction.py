"""Evaluate human-reviewed article extraction observations from JSONL."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from src.ethio_cyber_intel.evaluation_metrics import (  # noqa: E402
    read_jsonl, split_dataset, validate_research_provenance, validate_unique,
)

FIELDS = ("identity_correct", "title_correct", "canonical_url_correct", "body_relevant",
          "rss_fallback_appropriate", "ambiguous_page_rejected", "source_attribution_correct")


def _score(rows: list[dict]) -> dict | None:
    if not rows:
        return None
    scores = {}
    for field in FIELDS:
        values = [row["review"].get(field) for row in rows if row["review"].get(field) is not None]
        if any(not isinstance(value, bool) for value in values):
            raise ValueError(f"review.{field} must be boolean when supplied")
        scores[field] = {"correct_rate": round(sum(values) / len(values), 4) if values else None,
                         "reviewed_examples": len(values)}
    successful = [row for row in rows if all(row["review"].get(key) is True for key in
                  ("identity_correct", "title_correct", "canonical_url_correct", "body_relevant", "source_attribution_correct"))]
    scores["joint_valid_extraction_rate"] = round(len(successful) / len(rows), 4)
    scores["examples"] = len(rows)
    return scores


def evaluate(path: Path) -> dict:
    rows = read_jsonl(path)
    groups = split_dataset(rows)
    for i, row in enumerate(rows, 1):
        if row.get("manually_reviewed") is not True:
            raise ValueError(f"Record {i} must set manually_reviewed to true")
        if not isinstance(row.get("review"), dict):
            raise ValueError(f"Record {i} requires human review fields")
        if row.get("synthetic") is False:
            validate_research_provenance(row, i)
        if row.get("observation") is not None and not isinstance(row["observation"], dict):
            raise ValueError(f"Record {i} observation must be an object")
    validate_unique(groups["research"], lambda row: row.get("article_id") or row.get("record_id"), label="article")
    # Synthetic examples remain visible as a test-only sanity check.
    return {"dataset": str(path), "records": len(rows),
            "independently_reviewed_real_records": len(groups["research"]),
            "synthetic_records_excluded_from_research": len(groups["synthetic"]),
            "research_metrics": _score(groups["research"]),
            "synthetic_sanity_check": _score(groups["synthetic"]),
            "interpretation": "A returned body is not considered valid without human review of identity, title, canonical URL, relevance, and source attribution."}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", nargs="?", type=Path, default=Path("evaluation/extraction_eval.jsonl"))
    args = parser.parse_args()
    print(json.dumps(evaluate(args.dataset), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
