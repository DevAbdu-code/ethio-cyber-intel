# Stage 9 limitations and threats to validity

- Research labels are currently absent for threat, severity, correlation, summary, and extraction. Their field metrics are unavailable. The 15 language records are explicitly synthetic and are not field-performance evidence.
- Research samples are not probability samples. Small or source-skewed datasets cannot establish population accuracy, language parity, or generalization to unseen publishers.
- Reviewer judgments may vary. Independent labeling, fluent language review, explicit adjudication, and reviewer agreement reporting are needed; the present evaluator does not calculate inter-rater reliability.
- Label taxonomy ambiguity, article selection bias, duplicate syndication, and permitted-retention constraints can bias the corpus.
- The rule-based language, threat, severity, and correlation components have known language coverage gaps. Metrics reflect the exact code and dataset version only.
- Threat `unknown` is an abstention outcome, not a threat type. Severity `Unknown` is a valid class and is kept in nominal metrics; ordinal metrics omit it and disclose the reduced sample.
- Correlation is binary candidate retrieval over related versus unrelated pairs. It cannot prove that two articles concern the same incident, nor establish actor attribution.
- Extraction adjudication depends on reviewer comparison with the source page and feed. Dynamic publisher pages and later edits can complicate reproducibility; retain retrieval snapshots only where permitted.
- Summaries are extractive and source-language only. Sentence overlap is not a full factuality metric; human ratings are subjective, and no translation support is claimed.
- Empty datasets produce null metrics. Null is not zero and must not be reported as evidence of failure or success.
- Evaluation scripts do not assess database integrity or system performance in this stage; those are covered by separate validation documentation.
