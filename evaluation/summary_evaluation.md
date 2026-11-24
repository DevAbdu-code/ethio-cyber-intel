# Summary evaluation dataset

`summary_eval.jsonl` is a separate, currently empty research evaluation set. Synthetic test passages are stored in `tests/` and are not evaluation observations.

For each example, include the permitted source article text and provenance, then evaluate the exact output from the current deterministic method version. Required fields:

```json
{"article":{"title":"...","source":"...","url":"https://...","published_at":"...","language":"en","content":"..."},"manually_reviewed":true,"source_note":"Source provenance, retention permission, access date, reviewer", "review":{"method_version":"1.0","summary_text":"exact generated output", "ratings":{"factual_consistency":5,"important_information_coverage":4,"language_correctness":5,"readability":4,"usefulness":4},"claim_count":3,"unsupported_claim_count":0}}
```

Use 1–5 human ratings and integer claim counts. `unsupported_claim_count` must not exceed `claim_count`. Amharic and Afaan Oromo should be reviewed by fluent readers; ratings should be independent where feasible. The evaluator verifies that each stored output matches the current deterministic method and reports mean human scores plus unsupported-claim rate overall and for English (`en`), Amharic (`am`), and Afaan Oromo (`om`). It does not automatically establish factuality or language correctness. Examples are not training data.

Run `python scripts/evaluate_summaries.py` from the project root. Empty datasets return unavailable (`null`) scores.
