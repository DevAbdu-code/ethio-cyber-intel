"""Evaluate severity decisions against manually reviewed JSONL labels."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

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


def evaluate(path: Path) -> dict:
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")]
    for index, row in enumerate(rows, 1):
        if row.get("manually_reviewed") is not True:
            raise ValueError(f"Record {index} must set manually_reviewed to true")
        if row.get("human_severity") not in SEVERITY_LEVELS:
            raise ValueError(f"Record {index} has unsupported human_severity")
        if row.get("language") not in LANGUAGES:
            raise ValueError(f"Record {index} has unsupported language")
        if not row.get("source_note"):
            raise ValueError(f"Record {index} requires source provenance in source_note")
    matrix = {actual: {predicted: 0 for predicted in SEVERITY_LEVELS}
              for actual in SEVERITY_LEVELS}
    by_language = {language: {"examples": 0, "agreements": 0} for language in LANGUAGES}
    language_matrices = {
        language: {actual: {predicted: 0 for predicted in SEVERITY_LEVELS}
                   for actual in SEVERITY_LEVELS}
        for language in LANGUAGES
    }
    for row in rows:
        article = {
            "title": row.get("text", ""), "source": row.get("source", "Evaluation source"),
            "url": row.get("url"), "published_at": row.get("published_at"),
        }
        result = assess_severity(article, row.get("external_evidence"))
        truth, prediction = row["human_severity"], result.severity
        matrix[truth][prediction] += 1
        language_matrices[row["language"]][truth][prediction] += 1
        language = row["language"]
        by_language[language]["examples"] += 1
        by_language[language]["agreements"] += int(truth == prediction)

    per_class = {}
    f1_values = []
    for severity in SEVERITY_LEVELS:
        tp = matrix[severity][severity]
        fp = sum(matrix[actual][severity] for actual in SEVERITY_LEVELS if actual != severity)
        fn = sum(matrix[severity][predicted] for predicted in SEVERITY_LEVELS if predicted != severity)
        support = sum(matrix[severity].values())
        metric = _metric(tp, fp, fn, support)
        per_class[severity] = metric
        if metric["f1"] is not None:
            f1_values.append(metric["f1"])
    for language, values in by_language.items():
        count = values["examples"]
        values["agreement"] = round(values["agreements"] / count, 4) if count else None
        per_class = {}
        lang_f1 = []
        for severity in SEVERITY_LEVELS:
            lang_matrix = language_matrices[language]
            tp = lang_matrix[severity][severity]
            fp = sum(lang_matrix[actual][severity] for actual in SEVERITY_LEVELS if actual != severity)
            fn = sum(lang_matrix[severity][predicted] for predicted in SEVERITY_LEVELS if predicted != severity)
            support = sum(lang_matrix[severity].values())
            item = _metric(tp, fp, fn, support)
            per_class[severity] = item
            if item["f1"] is not None:
                lang_f1.append(item["f1"])
        values["macro_f1"] = round(sum(lang_f1) / len(lang_f1), 4) if lang_f1 else None
        values["per_class"] = per_class
        values["confusion_matrix"] = language_matrices[language]
    total = len(rows)
    agreements = sum(by_language[lang]["agreements"] for lang in LANGUAGES)
    return {
        "dataset": str(path), "evaluated_examples": total,
        "agreement": round(agreements / total, 4) if total else None,
        "macro_f1": round(sum(f1_values) / len(f1_values), 4) if f1_values else None,
        "per_class": per_class, "by_language": by_language,
        "confusion_matrix_rows_human_columns_automated": matrix,
        "interpretation": "No severity performance claim is supported by an empty or small convenience sample.",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", nargs="?", type=Path, default=Path("evaluation/severity_eval.jsonl"))
    args = parser.parse_args()
    print(json.dumps(evaluate(args.dataset), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
