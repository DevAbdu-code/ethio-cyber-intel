# Language evaluation data

## Stage 9 evaluation framework

Stage 9 adds a reproducible unified runner: `python scripts/run_research_evaluation.py`. It evaluates language, threat, severity, correlation, extraction, and summarization reports without database writes or network requests. Synthetic examples are partitioned from research data and never contribute to real-world metrics. The extraction dataset `extraction_eval.jsonl` is intentionally empty pending human review.

See [methodology](../docs/stage9_evaluation_methodology.md), [annotation guidelines](../docs/stage9_annotation_guidelines.md), [results template](../docs/stage9_results_template.md), and [limitations](../docs/stage9_limitations_and_validity.md). JSON schemas in `templates/` are instructional placeholders, not observations. Empty research datasets yield unavailable (`null`) metrics.

`language_eval.jsonl` is a small researcher-authored, manually labeled **synthetic sanity-check set**. Every row states that it is synthetic. None of its text is a collected cyber incident or a real-world dataset, and the detector does not train on it. Unit-test phrases live separately in `tests/fixtures/`.

Run the metrics script with:

```bash
python scripts/evaluate_language.py
```

The script reports accuracy, per-language precision/recall/F1 and support counts, macro averages, and a confusion matrix. The current sample is tiny and deliberately synthetic. Its metrics are implementation checks only and must not be presented as estimates of field performance or as evidence of equal accuracy across English, Amharic, and Afaan Oromo.

## Add manually labeled examples

Add one JSON object per line to `language_eval.jsonl` with `text`, `label` (`en`, `am`, `om`, `und`, or `mul`), `labeling: "manually_labeled"`, `synthetic` (`true` for researcher-authored examples, `false` only for a real source that has been reviewed and may legally be retained), and a `source_note`. For real examples, record provenance and permission in the note or an accompanying data card, remove sensitive personal data, and preserve the source separately according to its terms. Do not describe synthetic records as collected intelligence.
