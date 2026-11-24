# Correlation evaluation dataset

`correlation_eval.jsonl` is intentionally empty until article pairs can be manually adjudicated and retained with permission. Unit-test pairs under `tests/` are synthetic and are not research data.

Each row must include a `human_label` of `same_incident`, `related_different_events`, `unrelated_events`, or `insufficient_evidence`, plus both article objects, language codes (`en`, `am`, `om`), and a provenance `source_note`. Example schema (illustrative only; do not use as an observed report):

```json
{"article_a":{"id":1,"title":"...","language":"en","url":"https://...","published_at":"...","content":"..."},"article_b":{"id":2,"title":"...","language":"am","url":"https://...","published_at":"...","content":"..."},"human_label":"insufficient_evidence","manually_reviewed":true,"source_note":"Provenance, reviewer, access date, permission"}
```

The evaluator measures binary candidate retrieval, where same-incident and related-but-distinct pairs count as relevant candidates, unrelated pairs count as negatives, and insufficient-evidence pairs are reported but excluded from precision/recall/F1/FPR. It reports results by `en-am`, `en-om`, and `am-om` language pair. The four-way human label support and candidate rates are also included to make the distinction visible. This baseline does not predict exact same-event status. Evaluation data is not used for training.

Run `python scripts/evaluate_correlation.py` from the project root. An empty set yields unavailable (`null`) metrics.
