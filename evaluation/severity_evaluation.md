# Severity evaluation dataset

`severity_eval.jsonl` is the separate research evaluation set and is currently empty. The evaluator therefore reports agreement and macro F1 as unavailable. Synthetic test fixtures remain under `tests/`; they are not research observations.

Add one JSON object per line only after human review, with this schema:

```json
{"text":"reviewed report excerpt", "language":"en", "human_severity":"Unknown", "manually_reviewed":true, "source_note":"Publisher, URL, access date, reviewer/provenance, and retention permission"}
```

Severity must be one of `Critical`, `High`, `Medium`, `Low`, `Informational`, or `Unknown`; language may be `en`, `am`, `om`, `und`, or `mul`. Optional `external_evidence` records must include verifiable source provenance and retrieval time. The evaluator reports per-class precision/recall/F1, macro F1, human/automated agreement, confusion matrix, and agreement by language. Evaluation records are not training data. Do not include fabricated reports or information that may not be retained.

Run `python scripts/evaluate_severity.py` from the project root.
