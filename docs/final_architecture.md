# ETHIO-CYBER INTEL: Final Architecture

## System context

ETHIO-CYBER INTEL is a local, CPU-oriented research prototype for collecting publicly available cybersecurity reports and presenting traceable, preliminary analyses in a Streamlit interface. Its current analytical methods are deterministic rules and extractive text selection; this implementation does not contain a trained multilingual AI model, translation service, or production threat-intelligence feed.

## End-to-end data flow

```text
Operator-configured public RSS/Atom feeds
  → source validation and feed requests
  → entry normalization and URL/content deduplication
  → optional publisher-page extraction
  → content identity validation
  → language detection
  → SQLite article store
  → threat category rules and severity evidence rules
  → cross-language candidate correlation
  → source-language extractive summaries
  → Streamlit dashboard and human review
```

Evaluation scripts and JSONL datasets are separate from operational collection and do not write to the database.

## Components and trust boundaries

1. **Source configuration — `config/rss_sources.json`, `rss_sources.py`.** An operator selects named feeds, entry limits, and request pacing. Configuration is trusted local input. A listed source is not thereby endorsed, fact-checked, or guaranteed to be reachable.
2. **Collection — `rss_collector.py`.** Feed requests use timeouts, bounded entry counts, per-source error handling, and URL/redirect checks. Each successful entry retains publisher title, description, link, source identity, and a parsed publication date where present. A malformed item or failed source does not discard independent valid feeds.
3. **Normalization and deduplication.** HTML is reduced to text, whitespace normalized, missing values represented without inventing metadata, and stable URL/content fingerprints prevent repeated inserts. LIVE collection is distinct from synthetic DEMO records. LIVE means collected from a source, not independently verified.
4. **Optional page extraction — `article_extractor.py`.** When RSS text is inadequate, the extractor checks robots rules, uses HTTPS and same-host restrictions, rate delay, timeout, and no page redirects. It prefers explicit body containers and validates page identity against the feed title/canonical URL. Rejected or ambiguous extraction falls back to the preserved RSS metadata/text; it is not represented as a verified article body.
5. **Language detection — `language_detection.py`.** Ethiopic-script evidence is used for Amharic; small lexical cues distinguish English and Afaan Oromo in Latin-script text. Output is `en`, `am`, `om`, `und`, or `mul`, with method and heuristic confidence. Afaan Oromo detection remains particularly uncertain and has no independent field validation.
6. **Persistence — `database.py`.** SQLite stores article provenance and distinct analysis histories. Foreign keys and uniqueness constraints protect relationships and duplicates. Migrations are additive/transactional and are tested on temporary databases; operational research data must be backed up before migration. Human-reviewed decisions are preserved against automatic replacement.
7. **Threat categorization — `threat_classification.py`.** Explainable multilingual keyword/phrase rules emit multi-label categories, matched evidence, method, status, and heuristic scores. Scores are not calibrated probabilities; an unknown result is allowed. Categories do not establish that a report is true.
8. **Severity triage — `severity_assessment.py`.** Documented conservative rules distinguish category from severity and retain evidence/explanations. Missing or conflicting evidence can yield `Unknown`. No CVE database is queried by the current dashboard; article statements remain reported claims unless an actual documented external verification is supplied.
9. **Correlation — `correlation.py`.** Precomputed identifiers/entities/terms support pairwise candidate discovery across English, Amharic, and Afaan Oromo. Explicit shared identifiers/entities are stronger signals; date and text overlap are supporting signals. Results are heuristic candidates, never proof of identical incidents or common actor attribution. Human decisions are appended to history.
10. **Summarization — `summarization.py`.** A CPU-only extractive baseline selects original source sentences and retains the source snapshot/excerpts. It does not paraphrase or translate. Unsupported requested languages and insufficient text produce explicit non-success statuses.
11. **Presentation and workflow — `dashboard_data.py`, `app.py`.** Streamlit separates LIVE from DEMO, shows processing states and evidence, supports source/language/category/severity filtering, and provides explicit actions for pending language detection, classification, severity, correlation, and summaries. Refreshing collects reports and runs the configured preliminary classification/severity workflow; correlation and summary generation are user-triggered. No result is silently promoted to human-verified intelligence.
12. **Evaluation — `evaluation/`, `scripts/`.** Evaluators consume labeled JSONL records independently of the operational database. Empty reviewed datasets return unavailable metrics. Synthetic tests and the 15 synthetic language examples do not estimate operational accuracy.

## Operating profile and limits

The intended deployment is a single-user local Streamlit application backed by SQLite. It has no authentication/authorization layer, scheduler, multi-tenant controls, or public-deployment hardening. RSS and extraction behavior depend on external network and publisher changes. Hostname DNS resolution/private-address validation and response-size caps remain limitations; dependency vulnerability scanning and a deployment security audit have not been completed. Correlation reduces repeated per-article work but remains pairwise and quadratic in the number of reports.

## Persisted data snapshot

The inspected local database was opened read-only on 2026-11-25. `PRAGMA integrity_check` returned `ok`; `PRAGMA foreign_key_check` returned no violations. It contains 46 articles (43 LIVE, 3 DEMO), 46 classification runs, 46 severity assessments, six correlation pairs and six correlation assessments, and seven summaries. The database was not modified for this delivery. Stored analysis counts indicate rows exist, not that labels were independently validated.
