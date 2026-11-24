"""Dependency-free, deterministic metrics and provenance validation helpers."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Callable, Iterable, Sequence


def read_jsonl(path: Path) -> list[dict]:
    """Read JSONL rows while ignoring blank lines and comment lines."""
    rows = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_number}: invalid JSON: {exc.msg}") from exc
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{line_number}: each JSONL record must be an object")
        rows.append(row)
    return rows


def validate_synthetic_flag(rows: Sequence[dict]) -> None:
    for index, row in enumerate(rows, 1):
        if not isinstance(row.get("synthetic"), bool):
            raise ValueError(f"Record {index} must explicitly set synthetic to true or false")


def split_dataset(rows: Sequence[dict]) -> dict[str, list[dict]]:
    """Partition examples so synthetic rows never contribute research metrics."""
    validate_synthetic_flag(rows)
    return {
        "synthetic": [row for row in rows if row["synthetic"]],
        "research": [row for row in rows if not row["synthetic"]],
    }


def validate_research_provenance(row: dict, index: int, *, article_keys: Sequence[str] = ("article_id", "record_id")) -> None:
    """Require minimum review and provenance metadata on non-synthetic rows."""
    if row.get("manually_reviewed") is not True:
        raise ValueError(f"Research record {index} must set manually_reviewed to true")
    if not any(row.get(key) not in (None, "") for key in article_keys):
        raise ValueError(f"Research record {index} requires an article_id or record_id")
    if not row.get("source"):
        raise ValueError(f"Research record {index} requires source")
    if not (row.get("source_url") or row.get("url")):
        raise ValueError(f"Research record {index} requires source_url or url")
    if not row.get("reviewer_decision"):
        raise ValueError(f"Research record {index} requires reviewer_decision")
    if not row.get("dataset_version"):
        raise ValueError(f"Research record {index} requires dataset_version")
    try:
        date.fromisoformat(str(row.get("review_date", "")))
    except ValueError as exc:
        raise ValueError(f"Research record {index} review_date must be ISO YYYY-MM-DD") from exc


def validate_unique(rows: Sequence[dict], key: Callable[[dict], object], *, label: str = "record") -> None:
    seen = set()
    for index, row in enumerate(rows, 1):
        value = key(row)
        if value in (None, "", (), frozenset()):
            raise ValueError(f"Record {index} is missing a stable {label} identifier")
        if value in seen:
            raise ValueError(f"Duplicate {label} identifier at record {index}: {value}")
        seen.add(value)


def _ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def confusion_matrix(actual: Sequence[str], predicted: Sequence[str], labels: Sequence[str]) -> dict[str, dict[str, int]]:
    if len(actual) != len(predicted):
        raise ValueError("actual and predicted must have equal lengths")
    matrix = {label: {prediction: 0 for prediction in labels} for label in labels}
    for truth, guess in zip(actual, predicted):
        if truth not in matrix or guess not in matrix:
            raise ValueError("actual/predicted contains a label outside the declared label set")
        matrix[truth][guess] += 1
    return matrix


def cohen_kappa(matrix: dict[str, dict[str, int]], labels: Sequence[str]) -> float | None:
    total = sum(sum(matrix[label].values()) for label in labels)
    if total == 0:
        return None
    observed = sum(matrix[label][label] for label in labels) / total
    row_marginal = {label: sum(matrix[label].values()) for label in labels}
    col_marginal = {label: sum(matrix[truth][label] for truth in labels) for label in labels}
    expected = sum(row_marginal[label] * col_marginal[label] for label in labels) / (total * total)
    if expected == 1:
        return None
    return round((observed - expected) / (1 - expected), 4)


def classification_metrics(actual: Sequence[str], predicted: Sequence[str], labels: Sequence[str]) -> dict:
    """Single-label metrics; undefined metrics remain None for empty support."""
    matrix = confusion_matrix(actual, predicted, labels)
    total = len(actual)
    per_class = {}
    f1_support = []
    weighted_f1 = 0.0
    for label in labels:
        tp = matrix[label][label]
        support = sum(matrix[label].values())
        predicted_count = sum(matrix[truth][label] for truth in labels)
        fp, fn = predicted_count - tp, support - tp
        precision = _ratio(tp, predicted_count)
        recall = _ratio(tp, support)
        if precision is None and support:
            precision = 0.0
        f1 = (round(2 * precision * recall / (precision + recall), 4)
              if precision is not None and recall is not None and precision + recall else
              0.0 if precision is not None and recall is not None else None)
        per_class[label] = {"precision": precision, "recall": recall, "f1": f1, "support": support,
                            "tp": tp, "fp": fp, "fn": fn}
        if support and f1 is not None:
            f1_support.append((f1, support))
            weighted_f1 += f1 * support
    total_support = sum(support for _, support in f1_support)
    return {
        "examples": total,
        "accuracy": _ratio(sum(actual[i] == predicted[i] for i in range(total)), total),
        "macro_f1": round(sum(value for value, _ in f1_support) / len(f1_support), 4) if f1_support else None,
        "macro_f1_classes": len(f1_support),
        "weighted_f1": round(weighted_f1 / total_support, 4) if total_support else None,
        "cohen_kappa": cohen_kappa(matrix, labels),
        "per_class": per_class,
        "confusion_matrix_rows_true_columns_predicted": matrix,
    }


def binary_metrics(tp: int, fp: int, fn: int, tn: int) -> dict:
    total = tp + fp + fn + tn
    if total == 0:
        return {"examples": 0, "precision": None, "recall": None, "f1": None,
                "false_positive_rate": None, "accuracy": None,
                "tp": 0, "fp": 0, "fn": 0, "tn": 0}
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    f1 = (round(2 * precision * recall / (precision + recall), 4)
          if precision is not None and recall is not None and precision + recall else
          0.0 if precision is not None and recall is not None else None)
    return {"examples": total, "precision": precision, "recall": recall, "f1": f1,
            "false_positive_rate": _ratio(fp, fp + tn), "accuracy": _ratio(tp + tn, total),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def multilabel_metrics(actual: Sequence[set[str]], predicted: Sequence[set[str]], labels: Sequence[str]) -> dict:
    """One-vs-rest multilabel metrics plus micro/macro F1 and exact subset accuracy."""
    if len(actual) != len(predicted):
        raise ValueError("actual and predicted must have equal lengths")
    per_label = {}
    totals = [0, 0, 0]
    supported_f1 = []
    for label in labels:
        tp = sum(label in truth and label in guess for truth, guess in zip(actual, predicted))
        fp = sum(label not in truth and label in guess for truth, guess in zip(actual, predicted))
        fn = sum(label in truth and label not in guess for truth, guess in zip(actual, predicted))
        support = sum(label in truth for truth in actual)
        scores = binary_metrics(tp, fp, fn, len(actual) - tp - fp - fn)
        per_label[label] = {"precision": scores["precision"], "recall": scores["recall"],
                            "f1": scores["f1"], "support": support,
                            "tp": tp, "fp": fp, "fn": fn, "tn": len(actual) - tp - fp - fn}
        totals[0] += tp; totals[1] += fp; totals[2] += fn
        if support and scores["f1"] is not None:
            supported_f1.append(scores["f1"])
    micro = binary_metrics(totals[0], totals[1], totals[2], 0)
    return {
        "examples": len(actual), "subset_accuracy": _ratio(sum(a == p for a, p in zip(actual, predicted)), len(actual)),
        "micro": {key: micro[key] for key in ("precision", "recall", "f1", "tp", "fp", "fn")},
        "macro_f1": round(sum(supported_f1) / len(supported_f1), 4) if supported_f1 else None,
        "macro_f1_categories": len(supported_f1), "per_category": per_label,
    }
