"""Evaluate candidate retrieval against manually adjudicated article pairs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.ethio_cyber_intel.correlation import correlate_pair  # noqa: E402

LABELS = ("same_incident", "related_different_events", "unrelated_events", "insufficient_evidence")
LANGUAGE_PAIRS = ("en-am", "en-om", "am-om")


def _binary_metrics(tp: int, fp: int, fn: int, tn: int, evaluated: int) -> dict:
    if evaluated == 0:
        return {"precision": None, "recall": None, "f1": None,
                "false_positive_rate": None, "support": 0}
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return {"precision": round(precision, 4), "recall": round(recall, 4),
            "f1": round(f1, 4), "false_positive_rate": round(fpr, 4),
            "support": evaluated, "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def _pair_key(language_a: str, language_b: str) -> str:
    order = {"en": 0, "am": 1, "om": 2}
    return "-".join(sorted((language_a, language_b), key=lambda value: order[value]))


def evaluate(path: Path) -> dict:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")]
    for index, row in enumerate(rows, 1):
        if row.get("manually_reviewed") is not True:
            raise ValueError(f"Pair {index} must set manually_reviewed to true")
        if row.get("human_label") not in LABELS:
            raise ValueError(f"Pair {index} has unsupported human_label")
        if not row.get("source_note"):
            raise ValueError(f"Pair {index} requires provenance in source_note")
        for side in ("article_a", "article_b"):
            article = row.get(side)
            if not isinstance(article, dict) or article.get("language") not in {"en", "am", "om"}:
                raise ValueError(f"Pair {index} needs article_a/article_b with language en, am, or om")
        pair_key = _pair_key(row["article_a"]["language"], row["article_b"]["language"])
        if pair_key not in LANGUAGE_PAIRS:
            raise ValueError(f"Pair {index} must use one of the cross-language pairs {LANGUAGE_PAIRS}")
    counts = {key: [0, 0, 0, 0] for key in LANGUAGE_PAIRS}  # TP, FP, FN, TN
    labels_by_truth = {label: {"examples": 0, "candidate_rate": 0} for label in LABELS}
    excluded_insufficient = 0
    for row in rows:
        left, right = row["article_a"], row["article_b"]
        pair_key = _pair_key(left["language"], right["language"])
        result = correlate_pair(left, right)
        candidate = result.status == "Candidate"
        truth = row["human_label"]
        aggregate = labels_by_truth[truth]
        aggregate["examples"] += 1
        aggregate["candidate_rate"] += int(candidate)
        if truth == "insufficient_evidence":
            excluded_insufficient += 1
            continue
        actual_related = truth in {"same_incident", "related_different_events"}
        index = 0 if actual_related and candidate else 1 if candidate else 2 if actual_related else 3
        counts[pair_key][index] += 1
    by_pair = {}
    for key, (tp, fp, fn, tn) in counts.items():
        by_pair[key] = _binary_metrics(tp, fp, fn, tn, tp + fp + fn + tn)
    tp = sum(values[0] for values in counts.values())
    fp = sum(values[1] for values in counts.values())
    fn = sum(values[2] for values in counts.values())
    tn = sum(values[3] for values in counts.values())
    evaluated = tp + fp + fn + tn
    for value in labels_by_truth.values():
        value["candidate_rate"] = round(value["candidate_rate"] / value["examples"], 4) if value["examples"] else None
    return {
        "dataset": str(path), "manually_reviewed_pairs": len(rows),
        "binary_target": "same_incident or related_different_events versus unrelated_events; insufficient_evidence excluded",
        "excluded_insufficient_evidence": excluded_insufficient,
        "overall": _binary_metrics(tp, fp, fn, tn, evaluated),
        "by_language_pair": by_pair,
        "human_label_support_and_candidate_rate": labels_by_truth,
        "candidate_confusion_matrix": {"rows_human_relatedness": {"related": {"candidate": tp, "not_candidate": fn},
                                                                      "unrelated": {"candidate": fp, "not_candidate": tn}}},
        "limitation": "The baseline retrieves candidate relationships; it does not decide whether reports are the exact same incident, assign attribution, or confirm facts.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", nargs="?", type=Path, default=Path("evaluation/correlation_eval.jsonl"))
    args = parser.parse_args()
    print(json.dumps(evaluate(args.dataset), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
