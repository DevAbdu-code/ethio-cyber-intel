"""Report human ratings for reviewed outputs of the extractive summarizer."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ethio_cyber_intel.summarization import (  # noqa: E402
    SUMMARY_METHOD_VERSION, SUPPORTED_SUMMARY_LANGUAGES, summarize_article,
)

RATING_FIELDS = (
    "factual_consistency", "important_information_coverage", "language_correctness",
    "readability", "usefulness",
)


def _aggregate(rows: list[dict]) -> dict:
    if not rows:
        return {"examples": 0, **{field: None for field in RATING_FIELDS},
                "unsupported_claim_rate": None, "unsupported_claims": 0, "claims": 0}
    result = {"examples": len(rows)}
    for field in RATING_FIELDS:
        result[field] = round(sum(row["ratings"][field] for row in rows) / len(rows), 4)
    claims = sum(row["claim_count"] for row in rows)
    unsupported = sum(row["unsupported_claim_count"] for row in rows)
    result.update({"unsupported_claim_rate": round(unsupported / claims, 4) if claims else None,
                   "unsupported_claims": unsupported, "claims": claims})
    return result


def evaluate(path: Path) -> dict:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")]
    normalized = []
    for index, row in enumerate(rows, 1):
        if row.get("manually_reviewed") is not True:
            raise ValueError(f"Example {index} must set manually_reviewed to true")
        if not row.get("source_note"):
            raise ValueError(f"Example {index} requires source provenance in source_note")
        article = row.get("article")
        if not isinstance(article, dict) or article.get("language") not in SUPPORTED_SUMMARY_LANGUAGES:
            raise ValueError(f"Example {index} needs a source article in en, am, or om")
        review = row.get("review", {})
        if review.get("method_version") != SUMMARY_METHOD_VERSION:
            raise ValueError(f"Example {index} was not reviewed against method version {SUMMARY_METHOD_VERSION}")
        generated = summarize_article(article)
        if generated.status != "original_extractive":
            raise ValueError(f"Example {index} does not have sufficient source content to evaluate")
        if review.get("summary_text") != generated.summary_text:
            raise ValueError(f"Example {index} reviewed summary does not match current deterministic output")
        ratings = review.get("ratings", {})
        for field in RATING_FIELDS:
            score = ratings.get(field)
            if not isinstance(score, (int, float)) or not 1 <= score <= 5:
                raise ValueError(f"Example {index} rating {field} must be between 1 and 5")
        claim_count = review.get("claim_count")
        unsupported_count = review.get("unsupported_claim_count")
        if not isinstance(claim_count, int) or not isinstance(unsupported_count, int):
            raise ValueError(f"Example {index} must include integer claim_count and unsupported_claim_count")
        if not 0 <= unsupported_count <= claim_count:
            raise ValueError(f"Example {index} claim counts are inconsistent")
        normalized.append({"language": article["language"], "ratings": ratings,
                           "claim_count": claim_count, "unsupported_claim_count": unsupported_count})
    by_language = {
        language: _aggregate([row for row in normalized if row["language"] == language])
        for language in SUPPORTED_SUMMARY_LANGUAGES
    }
    return {
        "dataset": str(path), "manually_reviewed_examples": len(normalized),
        "overall": _aggregate(normalized), "by_language": by_language,
        "interpretation": "Metrics are unavailable for an empty dataset and descriptive only for small or convenience samples.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", nargs="?", type=Path, default=Path("evaluation/summary_eval.jsonl"))
    args = parser.parse_args()
    print(json.dumps(evaluate(args.dataset), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
