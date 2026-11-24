# Stage 9 annotation guidelines

## Shared protocol

1. Include public or otherwise permissioned reports only when retention is permitted. Keep source URL, publisher, access date, publication date if available, language, and a stable local identifier.
2. Set `synthetic: false` only for an actual source record. Research metrics accept only records with `manually_reviewed: true`, reviewer decision, ISO `review_date`, and `dataset_version`.
3. Reviewers must label the supplied text, not infer missing facts. Record uncertainty and use `Unknown`/`insufficient_evidence` where applicable.
4. Use two independent reviewers where feasible, then document adjudication. Do not treat automated outputs as gold labels.
5. Deduplicate records before annotation. Correlation pairs are unordered and must not appear twice.
6. Keep synthetic and manually authored test cases under `tests/`, never intermixed with real research metrics.
7. Remove personal/sensitive data not necessary to the research and preserve only content allowed by source terms and applicable law.

## Label-specific guidance

- **Language:** label the text actually evaluated as `en`, `am`, `om`, `und`, or `mul`. `und` means evidence is insufficient or unsupported; `mul` requires substantial evidence of multiple languages. For code-switching, note span-level rationale.
- **Threat classification:** apply all supported categories evidenced in the report. Use `unknown` alone when none can be assigned. This is not an incident truth judgment.
- **Severity:** use the system's six classes. Keep reported claims distinct from independently verified facts. A CVE mention alone does not determine severity; missing evidence remains Unknown.
- **Correlation:** choose `same_incident`, `related_different_events`, `unrelated_events`, or `insufficient_evidence`. Shared CVE, keywords, product or actor mention alone is not proof of a common incident or attribution. Record the specific cross-report evidence.
- **Extraction:** evaluate identity, headline, canonical URL, source, and article-body relevance against the publisher/feed source. Text returned by an extractor is not by itself a pass.
- **Summary:** assess only the exact current extractive output. Score factuality, coverage, language correctness, readability, usefulness; count claims and unsupported claims. Fluent Amharic/Afaan Oromo review is needed for those languages.

## Dataset versioning

Increment a dataset's semantic version when labels, inclusion criteria, or examples materially change. Keep a change log with record IDs added/removed and adjudication notes; do not overwrite an existing reviewer decision silently. Templates in `evaluation/templates/` are schemas, not observations. Replace every placeholder before adding a row to the relevant JSONL dataset.
