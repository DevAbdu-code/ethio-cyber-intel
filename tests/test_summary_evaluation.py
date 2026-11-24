import json
from pathlib import Path

import pytest

from scripts.evaluate_summaries import RATING_FIELDS, evaluate
from src.ethio_cyber_intel.summarization import summarize_article


def test_empty_summary_evaluation_has_unavailable_metrics(tmp_path: Path):
    path = tmp_path / "empty.jsonl"
    path.write_text("# no human reviews\n", encoding="utf-8")
    result = evaluate(path)
    assert result["manually_reviewed_examples"] == 0
    assert result["overall"]["factual_consistency"] is None
    assert result["by_language"]["om"]["unsupported_claim_rate"] is None


def test_evaluator_requires_human_review_and_exact_method_output(tmp_path: Path):
    article = {
        "title": "Sample report", "source": "Synthetic test source",
        "url": "https://example.test/synthetic", "published_at": None, "language": "en",
        "content": (
            "Researchers reviewed a security issue in a network product. "
            "The report identifies CVE-2026-12345 in source text. "
            "The publisher recommends reviewing its available guidance."
        ),
    }
    summary = summarize_article(article)
    row = {
        "article": article, "manually_reviewed": True,
        "source_note": "Synthetic unit-test example, not research data",
        "review": {"method_version": "1.0", "summary_text": summary.summary_text,
                   "ratings": {field: 4 for field in RATING_FIELDS},
                   "claim_count": 2, "unsupported_claim_count": 0},
    }
    path = tmp_path / "reviewed-temp.jsonl"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    result = evaluate(path)
    assert result["overall"]["factual_consistency"] == 4.0
    assert result["by_language"]["en"]["examples"] == 1
    row["manually_reviewed"] = False
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="manually_reviewed"):
        evaluate(path)
