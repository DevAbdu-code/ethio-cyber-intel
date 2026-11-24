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
from src.ethio_cyber_intel.evaluation_metrics import (  # noqa: E402
    read_jsonl, split_dataset, validate_research_provenance, validate_unique,
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
    rows = read_jsonl(path)
    groups = split_dataset(rows)
    normalized = {"research": [], "synthetic": []}
    for index, row in enumerate(rows, 1):
        if row.get("manually_reviewed") is not True:
            raise ValueError(f"Example {index} must set manually_reviewed to true")
        if row["synthetic"] is False:
            validate_research_provenance(row, index)
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
        source = article.get("content", "")
        summary_sentences = [s.strip() for s in generated.summary_text.splitlines() if s.strip()]
        evidence = list(generated.supporting_evidence)
        normalized["synthetic" if row["synthetic"] else "research"].append({
            "record_id": row.get("article_id") or row.get("record_id") or index,
            "language": article["language"], "ratings": ratings,
            "claim_count": claim_count, "unsupported_claim_count": unsupported_count,
            "traceable_summary_sentences": sum(sentence in source for sentence in summary_sentences),
            "summary_sentences": len(summary_sentences),
            "traceable_evidence_excerpts": sum(item.get("excerpt", "") in source for item in evidence),
            "evidence_excerpts": len(evidence),
        })
    validate_unique(groups["research"], lambda row: (row.get("article_id") or row.get("record_id"),
                    row.get("review", {}).get("method_version")), label="article/method summary")
    research = normalized["research"]
    synthetic = normalized["synthetic"]
    def trace_metrics(items: list[dict]) -> dict:
        def rate(numerator: str, denominator: str) -> float | None:
            den = sum(item[denominator] for item in items)
            return round(sum(item[numerator] for item in items) / den, 4) if den else None
        return {"examples": len(items), "source_sentence_preservation": rate("traceable_summary_sentences", "summary_sentences"),
                "evidence_traceability": rate("traceable_evidence_excerpts", "evidence_excerpts")}
    by_language = {language: _aggregate([row for row in research if row["language"] == language])
                   for language in SUPPORTED_SUMMARY_LANGUAGES}
    return {
        "dataset": str(path), "manually_reviewed_examples": len(research),
        "synthetic_examples_excluded_from_research": len(synthetic),
        "research_metrics": ({"human_ratings": _aggregate(research), **trace_metrics(research)} if research else None),
        "synthetic_sanity_check": ({"human_ratings": _aggregate(synthetic), **trace_metrics(synthetic)} if synthetic else None),
        "overall": _aggregate(research), "traceability": trace_metrics(research), "by_language": by_language,
        "interpretation": "Metrics are unavailable for an empty dataset and descriptive only for small or convenience samples.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", nargs="?", type=Path, default=Path("evaluation/summary_eval.jsonl"))
    args = parser.parse_args()
    print(json.dumps(evaluate(args.dataset), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
