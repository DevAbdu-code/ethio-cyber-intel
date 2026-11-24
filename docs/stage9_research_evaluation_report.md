# Stage 9 research evaluation report

## Scope

The evaluation runner was executed against the current JSONL datasets using the repository's `.venv` (Python 3.14.10). No models were trained, no network requests were made, and no database writes or migrations were performed.

## Dataset inventory and measured outputs

| Component | Synthetic examples | Independently reviewed real examples | Research metrics |
| --- | ---: | ---: | --- |
| Language detection | 15 | 0 | Unavailable |
| Threat classification | 0 | 0 | Unavailable |
| Severity | 0 | 0 | Unavailable |
| Correlation pairs | 0 | 0 | Unavailable |
| Summarization | 0 | 0 | Unavailable |
| Article extraction | 0 | 0 | Unavailable |

The 15 synthetic language examples produced 1.0000 accuracy on the synthetic sanity-check set. This is only a test of expected behavior on researcher-authored examples, not a real-world estimate. No research accuracy, precision, recall, F1, agreement, extraction correctness, or summary quality claim is supported by current datasets.

## Evaluation framework validation

The test suite exercises deterministic metric calculations, empty-data null behavior, synthetic/research separation, multilabel and abstention handling, severity Unknown inclusion, duplicate rejection, extraction review requirements, and repeated-run reproducibility. The complete suite reports **103 passed**. Python compilation and Git whitespace checks pass.

## Database safety observation

The configured SQLite database was opened read-only for an integrity check. `PRAGMA integrity_check` returned `ok`; it contains 46 articles (43 non-demo and 3 demo), 46 threat-classification runs, 46 severity assessments, 1 correlation pair/assessment, and 7 summary rows at inspection time. Stage 9 did not modify the database. These counts are a local snapshot, not an evaluation dataset.

## Conclusions

The evaluation framework is ready to accept permissioned, independently reviewed records using `evaluation/templates/`. It is not yet possible to assess field performance. Add real reviewed datasets with language coverage and reviewer adjudication before drawing conclusions about accuracy or language parity. See [methodology](stage9_evaluation_methodology.md), [annotation guidelines](stage9_annotation_guidelines.md), [results template](stage9_results_template.md), and [validity limitations](stage9_limitations_and_validity.md).
