# ETHIO-CYBER INTEL

A CPU-friendly research application for trilingual cyber threat intelligence aggregation and analysis. Stage 1 provides the Streamlit dashboard and SQLite store; Stage 2 adds configurable RSS collection and careful article extraction; Stage 3 adds conservative language detection; Stage 4 adds preliminary, explainable multi-label threat categorization.

Collected reports are source-attributed but are not independently verified advisories. Automated threat labels are preliminary rule matches, not verified intelligence or calibrated probabilities. No severity scoring or incident correlation is performed.

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
- The current evaluation data is synthetic and too small to support research conclusions. Build a permissioned, manually reviewed corpus before reporting accuracy as a real-world result.
- Threat classification, cross-language incident correlation, multilingual summaries, and severity scoring are not part of this stage.

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
  rss_collector.py                      RSS fetching and normalization
  rss_sources.py                        RSS configuration validation
tests/                                  Offline tests and separate synthetic fixtures
evaluation/threat_eval.jsonl            Empty, manually reviewed research evaluation set
scripts/evaluate_threat_classifier.py   Multilabel evaluation metrics
```
