# Stage 9 evaluation methodology

## Scope and evidence boundary

Stage 9 adds deterministic evaluation tooling for existing pipeline components. It does not train models, modify the operational database, or fetch network data. The evaluators consume JSONL and emit JSON. Synthetic examples are partitioned from independently reviewed examples; only non-synthetic, provenance-complete examples contribute to `research_metrics`. Empty research sets return `null`/unavailable metrics.

## Components and metrics

| Component | Measures | Important interpretation |
| --- | --- | --- |
| Language detection | Accuracy, per-label precision/recall/F1/support, macro F1, confusion matrix | All five labels (`en`, `am`, `om`, `und`, `mul`) are retained. |
| Threat labels | Per-category precision/recall/F1/support, macro/micro F1, subset accuracy, per-language results | `unknown` is an abstention outcome, excluded from threat-category macro/micro scores and separately measured. |
| Severity | Six-class accuracy, macro/weighted F1, per-class scores, confusion matrix, Cohen kappa | `Unknown` is a valid class. Ordinal agreement and quadratic weighted kappa use only the five ordered severity levels; Unknown-involved rows are reported separately. |
| Correlation | Precision, recall, F1, false-positive rate by cross-language pair | Target is candidate retrieval: same incident and related-but-different are relevant; unrelated is negative; insufficient evidence is excluded. Candidate retrieval does not establish exact incident identity. |
| Extraction | Human-reviewed identity/title/canonical URL/body relevance/fallback/ambiguity/source attribution rates and joint validity | Text presence alone never means valid extraction; a human checks source page and feed provenance. |
| Summarization | Human scores, unsupported-claim rate, source sentence preservation, evidence excerpt traceability by language | Extractive only; no translation or abstractive generation is evaluated. Human ratings remain required for factuality/readability. |

Macro F1 averages classes with at least one gold example (the report includes supported class counts); per-class precision may be null when a class has no predictions. Micro scores aggregate one-vs-rest counts. No confidence intervals or population-level inference are claimed for convenience samples. Cohen's kappa is null when expected agreement is 1. Weighted severity agreement is the observed agreement among adjacent ordinal categories, `1 - |rank difference| / 4`; quadratic weighted kappa is computed on known ordered levels only.

## Dataset classification and provenance

Every row must explicitly mark `synthetic`. Synthetic examples support software sanity checks only. Real research examples require a stable record/article ID, source and original URL, human review, reviewer decision, ISO review date, dataset version, and a source note documenting access and lawful retention. Duplicate records are rejected. Each dataset is versioned independently. Keep test fixtures in `tests/`; do not copy them into `evaluation/*_eval.jsonl`.

The existing language dataset has 15 researcher-authored synthetic records. It can report only a synthetic sanity check. Existing threat, severity, correlation, and summary evaluation files contain no reviewed examples. Extraction has no reviewed examples yet. Consequently, real-world component performance is unavailable.

## Reproducible execution

From repository root and the project virtual environment:

```bash
python scripts/run_research_evaluation.py
python scripts/run_research_evaluation.py --output /tmp/ethio-stage9-report.json
```

Individual evaluators accept an optional dataset path, for example `python scripts/evaluate_extraction.py evaluation/extraction_eval.jsonl`. Reports are deterministic for fixed input and code versions; generation timestamps are omitted. These scripts make no database writes and no network requests. Record repository commit, Python version, dataset version, reviewer protocol, and command alongside any publication.

## Extraction and summary review

Extraction reviewers compare each stored observation with the exact RSS entry and publisher page. Confirm article identity and headline, canonical URL, source attribution, and that body text discusses the same report. Record whether RSS fallback was appropriate and ambiguous page extraction was rejected. A non-empty but unrelated page body is a failure.

Summary reviewers inspect the exact source text, method version, output and excerpts. Rate factual consistency, information coverage, language correctness, readability and usefulness from 1–5; count claims and unsupported claims. Review Amharic and Afaan Oromo with fluent readers. Selected source sentences must be traceable verbatim. This system does not translate.
