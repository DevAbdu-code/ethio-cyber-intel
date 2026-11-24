"""Run all Stage 9 evaluators and emit a deterministic unified JSON report."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.evaluate_correlation import evaluate as evaluate_correlation  # noqa: E402
from scripts.evaluate_extraction import evaluate as evaluate_extraction  # noqa: E402
from scripts.evaluate_language import evaluate as evaluate_language  # noqa: E402
from scripts.evaluate_severity import evaluate as evaluate_severity  # noqa: E402
from scripts.evaluate_summaries import evaluate as evaluate_summaries  # noqa: E402
from scripts.evaluate_threat_classifier import evaluate as evaluate_threat  # noqa: E402

DATASETS = {
    "language": ("language_eval.jsonl", evaluate_language),
    "threat": ("threat_eval.jsonl", evaluate_threat),
    "severity": ("severity_eval.jsonl", evaluate_severity),
    "correlation": ("correlation_eval.jsonl", evaluate_correlation),
    "summarization": ("summary_eval.jsonl", evaluate_summaries),
    "extraction": ("extraction_eval.jsonl", evaluate_extraction),
}


def evaluate_all(evaluation_dir: Path = ROOT / "evaluation") -> dict:
    reports = {name: evaluator(evaluation_dir / filename) for name, (filename, evaluator) in DATASETS.items()}
    return {"stage": 9, "purpose": "Research evaluation; synthetic checks are not field-performance evidence.",
            "datasets": {name: str(evaluation_dir / filename) for name, (filename, _) in DATASETS.items()},
            "reports": reports,
            "real_world_metrics_available": {name: bool(report.get("independently_reviewed_real_examples", report.get("independently_reviewed_real_records", report.get("manually_reviewed_pairs", 0)))) for name, report in reports.items()},
            "reproducibility": "Deterministic local evaluators; no database writes or network access."}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evaluation-dir", type=Path, default=ROOT / "evaluation")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = evaluate_all(args.evaluation_dir)
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
