# Threat classification evaluation data

This file describes `threat_eval.jsonl`, a separate research evaluation dataset. It is currently empty; no classifier accuracy or other performance result is claimed. Synthetic unit test phrases are kept in `tests/` and must not be copied here as research observations.

Add one JSON object per line after a human reviewer has labeled it. Required shape:

```json
{"text":"reviewed report excerpt", "language":"en", "labels":["phishing"], "manually_reviewed":true, "source_note":"Publisher, URL, access date, and permission/provenance details"}
```

Supported language values are `en`, `am`, and `om`. Labels must use classifier category codes. Use `labels: ["unknown"]` only when the reviewer determined that no supported threat category applies. Multi-label reports should list every applicable category. Retain only text that may be lawfully stored, remove personal data, and record source provenance. Evaluation rows are not used for training.

Run `python scripts/evaluate_threat_classifier.py`. The report includes subset accuracy, micro and per-category precision/recall/F1, per-language micro scores, support, and one-vs-rest multilabel confusion counts. A small or convenience sample cannot establish real-world performance or language parity.
