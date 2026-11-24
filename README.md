# ETHIO-CYBER INTEL

A CPU-friendly research application for trilingual cyber threat intelligence aggregation and analysis. Stage 1 provides the Streamlit dashboard and SQLite store; Stage 2 adds configurable RSS collection and careful article extraction; Stage 3 adds conservative language detection; Stage 4 adds preliminary, explainable multi-label threat categorization; Stage 5 adds conservative evidence-based severity triage; Stage 6 adds candidate relationship discovery; Stage 7 adds evidence-grounded extractive summaries.

Collected reports are source-attributed but are not independently verified advisories. Automated threat labels, severity assessments, and correlation candidates are preliminary unless human reviewed. Their rule scores are not calibrated probabilities. Candidate relationships never prove that reports describe the same incident or share an actor.

## Requirements and installation

- Python 3.10 or newer
- pip
- Network access to configured publisher feeds for live RSS refreshes

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

The application uses Python, Streamlit, Pandas, Plotly, Feedparser, Requests, BeautifulSoup, and Pytest. Language detection uses the Python standard library; no model download, GPU, CUDA, or paid API is required.

## Launch and collect

```bash
source .venv/bin/activate
streamlit run app.py
```

Click **Refresh Intelligence** to check each enabled RSS source and collect new entries. A failed feed does not block other sources. Edit [`config/rss_sources.json`](config/rss_sources.json) to enable, disable, or change feed candidates. A configured feed is not necessarily available; the dashboard reports its status on refresh.

If the feed has no full article body, extraction is attempted only for same-host HTTPS pages allowed by the publisher's `robots.txt`. Requests are timed out, not redirected, and rate limited. The RSS title, description, URL, source, and publication date are retained when article-body extraction is unavailable.

## Stage 3: language detection

Supported labels:

| Code | Meaning |
| --- | --- |
| `en` | English |
| `am` | Amharic |
| `om` | Afaan Oromo |
| `und` | Unknown or insufficient evidence |
| `mul` | Mixed language |

The detector lives in `src/ethio_cyber_intel/language_detection.py`. It detects Amharic using Ethiopic Unicode-script evidence and uses a small, explicit set of English and Afaan Oromo lexical cues for Latin-script text. Clearly distinct language spans or a mixture of substantial script and lexical evidence can produce `mul`. Very short text, unsupported language text, and weak or conflicting evidence stay `und`.

Each result has a confidence score and method. The score measures strength of these rules; it is **not a calibrated probability**. Afaan Oromo uses the Latin alphabet, so distinguishing it from English through a small cue list is inherently uncertain. Oromo results require careful review and validation against a much larger, independently labeled and representative dataset before any reliability claim. This stage does not claim language parity or production-grade accuracy.

During RSS normalization, the detector prefers full article text when available and otherwise evaluates the title and description together. Existing records are not silently relabeled. New database fields store `language_confidence`, `language_method`, and `language_reviewed`; reviewed labels are preserved. Demo examples retain their explicit labels and are marked as demo-labeled examples.

The dashboard shows language filters, distribution, counts for all five labels, per-report confidence, and an uncertainty indication for unknown or low-confidence automatic labels.

## Evaluation

Run the small manually labeled synthetic sanity check:

```bash
source .venv/bin/activate
python scripts/evaluate_language.py
```

It reports accuracy, per-language precision, recall, F1, support counts, macro averages, and a confusion matrix. The separate [`evaluation/language_eval.jsonl`](evaluation/language_eval.jsonl) file contains 15 researcher-authored examples, all explicitly marked synthetic and manually labeled. These examples are not collected threat reports and do not estimate real-world accuracy. Unit-test examples are separately kept in `tests/fixtures/` and are not used by the evaluator.

To add examples, add one JSON object per line to the evaluation file with `text`, `label` (`en`, `am`, `om`, `und`, or `mul`), `labeling: "manually_labeled"`, `synthetic`, and a provenance `source_note`. For real source text, first document permission and provenance, remove sensitive personal data, and follow the source's retention terms. Do not represent synthetic text as observed intelligence.

## Stage 4: threat classification

The classifier supports multiple simultaneous labels for each report:

`phishing`, `malware`, `ransomware`, `vulnerability`, `data_breach`, `ddos`, `cyber_espionage`, `credential_theft`, `other`, and `unknown`.

`src/ethio_cyber_intel/threat_classification.py` implements a deterministic CPU-only multilingual keyword and phrase baseline. It emits the matched evidence, classifier method/version, classification status, UTC timestamp, and a per-category heuristic score. Scores are evidence-strength heuristics, **not calibrated probabilities**. Generic cyber terms may produce `other`; when no supported evidence is present, the result is `unknown`. The tool does not train a model and does not call a paid service. This is an explainable baseline, not advanced AI or an assertion that a report is true.

Language-specific rules are gated by the existing Stage 3 language label. Shared protocol/category terms may be matched for `und`; language-specific English, Amharic, or Oromo cues are not inferred merely from Latin script. `mul` permits cues for all three languages. English and Amharic rules have focused synthetic unit coverage, and a small number of Oromo rules use terminology found in the [ICT Development Office / Ethiopian Languages Research Center multilingual ICT glossary](https://oromianeconomist.com/wp-content/uploads/2017/08/ict-glossary-in-afaan-oromoo-amharic-and-tigarinya.pdf). This does **not** validate broad Afaan Oromo classification. Oromo phrase coverage is narrow, code-switching and inflection can cause misses, and all languages require human review. In particular, do not interpret category scores as comparable across languages.

The database stores append-only classification runs in `threat_classification_runs` and their multi-label evidence in `threat_classification_labels`; source article fields are preserved. The dashboard can classify pending reports explicitly, shows labels/evidence/method/heuristic confidence, provides category filters and charts, and distinguishes unclassified reports from a classifier `unknown` result. Human-reviewed labels are retained and suppress subsequent automatic classification for that article. “LIVE” describes source collection only; it does not mean the report or label was verified.

### Stage 4 evaluation

The separate [`evaluation/threat_eval.jsonl`](evaluation/threat_eval.jsonl) dataset is intentionally empty until manually reviewed examples are added. The evaluator reports exact multi-label subset accuracy, micro and per-category precision/recall/F1, per-language micro scores, supports, and one-vs-rest multilabel confusion counts. There are currently **zero research evaluation examples**, so no classification performance metrics are claimed. Synthetic unit tests live under `tests/` and are not evaluation data. The classifier does not train on evaluation examples.

Add one reviewed row per line (also see [`evaluation/threat_evaluation.md`](evaluation/threat_evaluation.md)):

```json
{"text":"reviewed report excerpt", "language":"om", "labels":["malware"], "manually_reviewed":true, "source_note":"Publisher, URL, access date, and permission/provenance details"}
```

Use language `en`, `am`, or `om`; list all applicable labels for multi-label incidents, or use `labels: ["unknown"]` when manual review finds no supported category. Retain only text that may be stored, remove personal data, and record provenance and permission. Do not label synthetic text as real evidence. Evaluate with:

```bash
python scripts/evaluate_threat_classifier.py
```

Small or convenience samples are exploratory and cannot establish real-world accuracy or parity among languages.

## Stage 5: evidence-based severity assessment

Severity is a prioritization dimension separate from Stage 4 threat categories. A report may be classified as ransomware while its severity is `Unknown`; a vulnerability category alone does not imply `Critical`, and a ransomware mention does not establish confirmed impact.

Supported levels are `Critical`, `High`, `Medium`, `Low`, `Informational`, and `Unknown`. `src/ethio_cyber_intel/severity_assessment.py` uses a documented deterministic policy rather than a learned model or probability:

- An article-reported CVSS score maps to the matching qualitative band but remains a `reported_claim`, with an explicit unverified explanation. A CVE identifier alone never raises severity.
- CVSS v3.x/v4 qualitative thresholds follow FIRST: 0.0 maps to Informational/None, 0.1–3.9 Low, 4.0–6.9 Medium, 7.0–8.9 High, and 9.0–10.0 Critical. CVSS describes vulnerability severity and should not be treated alone as full incident risk. See the [FIRST CVSS v3.1 specification](https://www.first.org/cvss/v3.1/specification-document) and [user guide](https://www.first.org/cvss/v3.1/user-guide).
- `High` may be assigned when an explicitly documented external source confirms exploitation and at least one impact, or provides a verified High CVSS score. `Critical` requires a verified Critical CVSS score; textual incident claims alone do not qualify.
- Confirmed exploitation without a confirmed impact, or a confirmed impact without known scale, is Medium. Article-reported exploitation, a reported proof of concept, or a reported/potential impact can also create Medium review priority, but the result remains preliminary and the claims are not independently verified.
- `Low` requires a verified or source-reported Low CVSS score. `Informational` requires an explicit informational/awareness notice without stronger evidence. Missing or insufficient evidence stays `Unknown`, never Low by default. Contradictory evidence returns Unknown with a conflict explanation.

Each assessment stores its explanation, evidence items, source attribution, article publication date and original URL, evidence completeness, method/version, status, and UTC timestamp. Extracted CVEs, CVSS values, product mentions, exploitation phrases, and impact phrases are attributed to the original article as reported claims. The classifier does not establish that a CVE exists, that a score is current, that a product is affected, or that a reported impact occurred.

Current text-pattern extraction is English-focused; it does not yet provide validated Amharic or Afaan Oromo exploitation/impact phrase coverage. The severity framework accepts language-neutral structured external evidence for any report, but no equal performance across languages is claimed. Language-specific evaluation is required before operational use.

No external CVE or exploitation lookup is currently performed, and no paid API is required. `assess_severity(article, external_evidence=...)` accepts future enrichment records only when a caller supplies `verification_status: "verified"`, a source name, source URL, and retrieval time. The caller must actually retrieve and check that source before marking it verified; merely adding a URL is insufficient. The current dashboard assessment action supplies article evidence only, so it cannot produce externally verified findings. Network failures and terms/rate limits remain the responsibility of any future permitted source adapter.

The database keeps append-only rows in `severity_assessments`; it preserves earlier automated assessments and does not replace an article's text or Stage 4 labels. Human-reviewed assessments become the current record and block later automated assessments for that article. The dashboard has severity filters and charts, a Critical/High priority table, explanations, source evidence, and a completeness summary. Automated assessment status is shown separately from the severity level.

### Stage 5 evaluation

The separate [`evaluation/severity_eval.jsonl`](evaluation/severity_eval.jsonl) dataset is currently empty. Thus agreement, per-class precision/recall, macro F1, confusion matrix counts, and per-language agreement are **unavailable**. Synthetic tests do not count as research evaluation. To add examples, use the schema and provenance instructions in [`evaluation/severity_evaluation.md`](evaluation/severity_evaluation.md), with a manually reviewed `human_severity`, language, source note, and `manually_reviewed: true`. Run:

```bash
python scripts/evaluate_severity.py
```

Small convenience samples are exploratory and cannot establish real-world severity performance or language parity.

## Stage 6: cross-language report correlation

The correlation engine compares articles in English (`en`), Amharic (`am`), and Afaan Oromo (`om`). Supported cross-language pairs are English–Amharic, English–Afaan Oromo, and Amharic–Afaan Oromo. `mul` and `und` articles can be compared, but do not receive the explicit cross-language candidate path unless a strong identifier/entity matches; they are not included in the three named language-pair evaluation groups.

`src/ethio_cyber_intel/correlation.py` extracts normalized CVE identifiers, explicitly labeled campaign IDs, and explicitly labeled malware family, actor, and product names. It can also accept curated entity metadata on an article record. Exact shared CVEs, campaign IDs, and malware-family mentions are strong candidate signals. Product/actor overlaps are weaker. Same-language character-trigram and normalized token overlap, shared threat-category context, and publication-date proximity are weak supporting signals only. Dates missing on either side do not contribute. Source identity and original URLs are retained as provenance, not treated as proof of common origin. Actor-name overlap records a mention match only; it makes no attribution.

The similarity score is a heuristic, not a probability. An exact identifier or explicit entity can produce a candidate, while direct lexical overlap alone does not create a cross-language candidate. Same-language text similarity can contribute to a candidate when it clears the documented threshold. The returned status is `Candidate` or `Insufficient evidence`; neither means confirmed same incident. Article publication time is used as a weak proxy because reported incident dates are not consistently extracted. No embedding model, GPU, paid API, external lookup, or newly added dependency is used.

Use **Correlate collected reports** to compare up to the 300 most recent LIVE reports. DEMO DATA is excluded. The dashboard shows related report details, identifiers/entities, terms, methods, evidence, score, and language pair; it also displays a small relationship graph. A reviewer can mark a candidate `Human confirmed` or `Human rejected`, with an optional note. A human decision is appended to history and blocks later automated replacement. “Human confirmed” means a reviewer accepted a relationship; it does not independently verify all report claims or attribution.

SQLite stores unique canonical article pairs in `correlation_pairs` and append-only candidate/review decisions in `correlation_assessments`. Re-running correlation avoids duplicate pair rows and does not append a repeated candidate assessment. A later human decision remains current; earlier automated and human decisions are preserved in history.

### Stage 6 evaluation

The separate [`evaluation/correlation_eval.jsonl`](evaluation/correlation_eval.jsonl) dataset is currently empty. Precision, recall, F1, false-positive rate, and results by English–Amharic, English–Afaan Oromo, and Amharic–Afaan Oromo are therefore **unavailable**. Add only permissioned, manually reviewed article pairs using the schema in [`evaluation/correlation_evaluation.md`](evaluation/correlation_evaluation.md). The evaluator measures candidate retrieval: same-incident and related-but-different pairs are relevant candidates, unrelated pairs are negatives, and insufficient-evidence pairs are reported separately and excluded from the binary metrics. It reports the four human-label supports and candidate rates but does not claim the baseline distinguishes the same event from a related event. Run:

```bash
python scripts/evaluate_correlation.py
```

Do not copy synthetic tests into the research evaluation dataset.

## Stage 7: evidence-grounded summarization

The summary baseline supports source-language extraction for articles labeled English (`en`), Amharic (`am`), and Afaan Oromo (`om`). It ranks source sentences with token-frequency centrality and small, transparent CVE/impact/exploitation evidence boosts, then returns selected sentences verbatim in the original order. It is deterministic, CPU-only, and does not use a language model.

**Extractive summary** means selected text copied directly from the source. This release does not generate a paraphrase or translate. If a requested output language differs from the detected source language, the result is saved with status `unsupported_translation` and no summary text. Unknown, mixed, or unsupported source languages return `unsupported_language`; source material below the minimum length or without enough sentence evidence returns `insufficient_content`. A dashboard language selector is available, but it does not imply translation capability. No paid translation API or multilingual generation model is used.

Every summary history row stores the article ID, requested/original summary language, exact source text used, source text fingerprint, selected source excerpts, source metadata (title, publication date, source, URL and detected language), summary method/version, status, key intelligence, and timestamp. The exact original source URL is preserved. Missing publication dates are shown as Unknown. CVEs are extracted only when present in source text. Product and malware names require explicit source labeling. Threat categories are copied from Stage 4 only when supplied and are labeled preliminary automated outputs. Impact and exploitation excerpts are marked as reported claims, not verified facts. Missing entities and claims remain “Not reported”; no actor attribution or CVE details are generated.

Current key-intelligence phrase extraction for impacts and exploitation is English-focused; only identifier extraction and explicitly labeled entities are more language-neutral. Sentence selection itself preserves English, Amharic, or Afaan Oromo text exactly, but this does not establish that a selected summary is readable, complete, or useful in those languages. Afaan Oromo and Amharic require review by fluent readers. We do not claim quality parity across languages.

**Local model practicality assessment:** no local model was added or benchmarked in this stage because extractive sentence selection satisfies the no-download, CPU-only baseline and avoids unvalidated generated text. A possible later translation adapter is QVAC TranslatePsy-AfriSLM: its publisher lists support for Amharic and Oromo and 4-bit variants, with the 0.8B model listed at about 0.7 GB and described as running on laptops without a GPU ([model details](https://qvac.tether.io/models/translatepsy), [model card](https://huggingface.co/qvac/TranslatePsy-AfriSLM-4B)). Those are publisher specifications, not ETHIO-CYBER INTEL measurements. It is a translation model, not a summarizer; its latency, peak RAM, CTI terminology fidelity, and pairwise quality on Amharic/Afaan Oromo cybersecurity text have not been tested here. It was therefore not installed or enabled. Any future adapter needs human-reviewed language-pair evaluation and a license/runtime review before use.

The dashboard’s **Evidence-grounded article summary** workspace selects an article and requested language, generates an extractive summary, and shows its status, key intelligence, supporting excerpts, source metadata, and source-text snapshot. It keeps prior summaries visible. Identical source text, language, method, and version are not written twice. A human-reviewed summary is preserved and blocks later automatic writes for that article/language. Summary status distinguishes original extractive output from unavailable translation and insufficient or unsupported input.

### Stage 7 evaluation

The separate [`evaluation/summary_eval.jsonl`](evaluation/summary_eval.jsonl) dataset is empty until reviewed examples are added. Factual consistency, important-information coverage, language correctness, readability, usefulness, and unsupported-claim rate are therefore **unavailable**. The evaluator reports ratings overall and separately for `en`, `am`, and `om`; Amharic/Afaan Oromo review should involve fluent readers, preferably independent reviewers. See [`evaluation/summary_evaluation.md`](evaluation/summary_evaluation.md) for the record schema and provenance rules. Evaluators rate the exact output from the recorded method version; the script does not itself determine factuality or readability. Run:

```bash
python scripts/evaluate_summaries.py
```

Do not copy synthetic unit-test text into the research dataset.

## Tests and compilation

```bash
source .venv/bin/activate
python -m pytest -v
python -m compileall -q app.py src tests scripts
```

RSS tests use mocked feeds and make no live network requests. The dashboard compatibility test uses a temporary SQLite database.

## Configuration and database

| Variable | Default | Description |
| --- | --- | --- |
| `ETHIO_CYBER_DB_PATH` | `data/ethio_cyber_intel.db` | SQLite database path |
| `ETHIO_CYBER_SEED_DEMO` | `true` | Seed clearly marked examples in an empty database |
| `ETHIO_CYBER_FEEDS_FILE` | `config/rss_sources.json` | RSS source JSON file |
| `ETHIO_CYBER_HTTP_TIMEOUT` | `12` | HTTP timeout in seconds |

Database initialization migrates the existing articles table transactionally, preserves row IDs and article content, and adds the `mul` language value plus confidence/method/review fields. SQLite requires a table migration to update the existing language `CHECK` constraint. The migration copies all existing columns and values into the updated table; it does not delete or recreate the database file. Existing language labels are not re-detected or overwritten. Legacy records without detection metadata remain marked `und`/not assessed until a later explicit review workflow.

## Data and scope limitations

- `collected` means received from a source, not verified as true.
- Missing publication dates remain empty; no dates or reports are fabricated.
- Exact URL/content fingerprints are checked for duplicates; paraphrase-level duplicates are not detected.
- Afaan Oromo cue coverage is small and may miss valid Oromo text or confuse overlapping vocabulary. Manually review uncertain labels and evaluate with diverse Oromo examples.
- Stage 4 classification is a hand-built phrase baseline, not a learned classifier. Coverage is incomplete, scores are uncalibrated, and the current threat evaluation dataset is empty.
- Stage 5 severity is a conservative report-evidence triage policy, not organizational risk scoring, incident validation, or calibrated prediction. Current dashboard assessments use article text only; no external source has been queried. Severity evaluation data is empty.
- Stage 6 correlation is candidate retrieval, not incident adjudication. Cross-language detection depends mainly on shared explicit identifiers/entity names and misses reports that paraphrase without such anchors. Direct word/character overlap is not cross-language semantic understanding. There are no manually reviewed research pairs, so performance is unmeasured.
- Stage 7 summaries are extractive and source-language only. Translation and abstractive generation are not implemented. Current impact/exploitation phrase extraction is English-focused, and the human evaluation set is empty.
- The current evaluation data is synthetic and too small to support research conclusions. Build a permissioned, manually reviewed corpus before reporting accuracy as a real-world result.
- Multilingual summaries are not part of this stage.

## Project layout

```text
app.py                                  Streamlit dashboard and refresh workflow
config/rss_sources.json                Editable RSS source candidates
evaluation/language_eval.jsonl         Separate synthetic labeled sanity-check data
scripts/evaluate_language.py           Metrics and confusion-matrix tool
src/ethio_cyber_intel/
  article_extractor.py                  robots-aware page extraction
  config.py                             Environment-backed settings
  dashboard_data.py                     SQLite dashboard queries
  database.py                           Schema, migrations, and inserts
  language_detection.py                 CPU-only language detection heuristics
  threat_classification.py              Evidence-producing multilingual rules baseline
  severity_assessment.py               Evidence-led severity triage rules
  correlation.py                        Explainable cross-language candidate matching
  summarization.py                      CPU-only extractive summary and evidence extraction
  rss_collector.py                      RSS fetching and normalization
  rss_sources.py                        RSS configuration validation
tests/                                  Offline tests and separate synthetic fixtures
evaluation/threat_eval.jsonl            Empty, manually reviewed research evaluation set
scripts/evaluate_threat_classifier.py   Multilabel evaluation metrics
evaluation/severity_eval.jsonl         Empty, manually reviewed severity evaluation set
scripts/evaluate_severity.py             Severity agreement and classification metrics
evaluation/correlation_eval.jsonl       Empty, manually reviewed article-pair evaluation set
scripts/evaluate_correlation.py          Candidate retrieval evaluation metrics
evaluation/summary_eval.jsonl            Empty, manually reviewed summary evaluation set
scripts/evaluate_summaries.py             Human-rating summary evaluation metrics
```
