# ETHIO-CYBER INTEL: Research Evaluation Report

**Evaluation date:** 2026-11-25  
**Scope:** Stages 1–7 implementation; no Stage 9 work  
**Project revision at evaluation start:** `1128ca7` (Stage 7 checkpoint)

## Project and research objectives

ETHIO-CYBER INTEL is a CPU-oriented research prototype for collecting public cybersecurity reports and presenting explainable language, threat-category, severity, cross-report relationship, and extractive-summary outputs. Its intended languages are English (`en`), Amharic (`am`), and Afaan Oromo (`om`). A collected report is source material, not verified intelligence. Candidate correlations are not confirmed incidents, severity is not threat category, and none of the rule scores are calibrated probabilities.

This evaluation checks whether the implementation can be reproduced and tested, inspects the available evaluation data, validates configured RSS feeds, checks the local SQLite file read-only, reviews high-impact security paths, and times selected CPU-only operations on the available records. It does not establish field accuracy or research efficacy.

## Architecture and methods

The Streamlit UI calls modules under `src/ethio_cyber_intel/`. RSS configuration is in `config/rss_sources.json`; `rss_collector.py` fetches and parses feeds, `article_extractor.py` optionally extracts same-host HTTPS article text subject to robots.txt, and `database.py` stores article and append-only analysis histories in SQLite. Language detection, threat categories, severity policy, correlation candidate generation, and source-language extractive summaries are separate deterministic modules. `dashboard_data.py` supplies dashboard queries. Evaluation scripts under `scripts/` read separate JSONL datasets under `evaluation/`.

The current methods are small rule-based/lexical baselines. The language detector combines Ethiopic script detection with lexical cues for Latin-script English and Oromo. Threat categories use language-gated keyword rules. Severity is a documented evidence policy. Correlation uses identifiers, explicitly named entities, lexical overlap, and date proximity to produce candidate links. Summarization selects source sentences; it does not translate or produce abstractive summaries.

## Datasets and provenance

| Dataset | Records | Provenance | Research metric status |
| --- | ---: | --- | --- |
| `language_eval.jsonl` | 15 | Researcher-authored, manually labeled synthetic sanity checks; 3 examples each for `en`, `am`, `om`, `und`, `mul` | Descriptive implementation check only |
| `threat_eval.jsonl` | 0 | Empty; reserved for manually reviewed, provenance-recorded reports | Unavailable |
| `severity_eval.jsonl` | 0 | Empty; reserved for manually reviewed severity labels | Unavailable |
| `correlation_eval.jsonl` | 0 | Empty; reserved for manually adjudicated article pairs | Unavailable |
| `summary_eval.jsonl` | 0 | Empty; reserved for human ratings of exact summary outputs | Unavailable |

Test fixtures are separate from `evaluation/`; they are synthetic and are not research examples. No real-world manually reviewed evaluation records were present. RSS smoke-check items described below were not saved to the database or evaluation datasets.

## Experimental setup

- OS/kernel: Kali Linux, `Linux-7.0.12-kali-amd64-x86_64-with-glibc2.43`.
- Python: 3.14.10; logical CPUs reported: 4.
- Installed key versions: Streamlit 1.67.0, pandas 3.1.1, Plotly 6.9.0, feedparser 6.0.14, BeautifulSoup 4.15.0, Requests 2.34.2, pytest 8.4.2.
- Tests use the existing local virtual environment and temporary databases where needed.
- Database inspection used SQLite URI `mode=ro`; no migration or write was run against the user's database.
- CPU timings used 40 existing non-demo article records, with Python `tracemalloc` peak allocations. This is a small, local microbenchmark, not a controlled benchmark or resident-memory measurement.
- RSS validation used the configured feed collector with persistence disabled. It fetched a capped number of entries per configured feed.

## Results

### Language detection

The evaluator reports **15/15 (100%) accuracy and macro F1 1.00**, with precision/recall/F1 of 1.00 for each supported or fallback label (`en`, `am`, `om`, `und`, `mul`), support 3 per label, and a diagonal confusion matrix. All 15 records are synthetic, researcher-authored examples. This result is not a real-world accuracy estimate; the sample is tiny and likely overlaps the detector's narrow lexical/script cues. It does not support a claim of Afaan Oromo reliability or parity.

### Threat classification

The manually reviewed research set has **0 examples**. Per-category, macro/micro, multilabel, and per-language metrics are unavailable. No comparison baseline was run because there is no labeled data on which to compare methods.

### Severity

The manually reviewed research set has **0 examples**. Agreement, per-class precision/recall, macro F1, confusion matrices, and results by language are unavailable.

### Cross-language correlation

The manually adjudicated pair set has **0 pairs**. Precision, recall, F1, false-positive rate, and all three language-pair results (`en-am`, `en-om`, `am-om`) are unavailable. Unit tests establish only expected behavior on synthetic cases, not candidate retrieval performance on real pairs. Candidate links must not be described as confirmed incidents.

### Summarization

There are **0 human-reviewed summary examples**. Factual consistency, coverage, unsupported-claim rate, language correctness, readability, and usefulness are unavailable. Only source-language extractive sentence selection exists. Translation and abstractive generation are not implemented.

## Dataset-free performance observations

Measured on the 40 stored non-demo records; elapsed time and Python-heap peak from `tracemalloc`:

| Operation | Workload | Elapsed | Peak traced allocation |
| --- | ---: | ---: | ---: |
| Language detection | 40 articles | 0.216 s | 279,540 B |
| Threat classification | 40 articles | 0.021 s | 303,324 B |
| Severity assessment | 40 articles | 0.085 s | 101,163 B |
| Pairwise correlation | 780 pairs | 6.686 s | 1,780,227 B |
| Summary generation | 0 eligible language-labeled articles | Not measurable | Not measurable |
| Dashboard AppTest startup | temporary DB, seeded demo rows | 5.737 s | 59,848,613 B |

All 40 non-demo database rows have stored content, but all currently carry language `und`, so none qualify for source-language summarization. Dashboard timing includes the Streamlit AppTest harness and first render against a temporary database, so it is not equivalent to production server startup. These measurements exclude interpreter baseline and native allocations and should not be generalized to other hosts or larger corpora. Pairwise correlation is quadratic in article count and will need a candidate-generation strategy before scaling.

The live collector completed a four-feed smoke check in 3.866 seconds in one external-network run. This wall time combines DNS, network, feed parse, and normalization and is not an RSS normalization-only benchmark.

## Interpretation and threats to validity

The evaluation data is insufficient for empirical claims about multilingual accuracy, classifier performance, severity agreement, correlation quality, or summary quality. Synthetic language examples are a smoke test, not a sampling frame. Rule-based cue coverage may favor hand-authored test phrasing; scripts and lexical cues do not capture dialect, spelling variation, code-switching, transliteration, or domain-specific paraphrases. Stored reports are source-selected and language metadata may be legacy `und`; they are not a representative corpus.

Feed content changes over time, and this report records one retrieval session rather than a durable corpus snapshot. Source publication claims are not independently verified. Runtime observations are host-specific and based on only 40 records. Dashboard rendering tests do not constitute accessibility, usability, or deployment testing.

## Research-readiness conclusion

The software is testable and the configured feeds were reachable and parseable during the recorded external-network smoke test. However, the research evaluation sets for Stages 4–7 are empty and only Stage 3 has a tiny synthetic sanity set. The prototype is suitable for continued controlled research and corpus-building, but it is **not ready for claims of validated trilingual performance or operational threat-intelligence accuracy**. A permissioned, manually reviewed, language-balanced real-world evaluation corpus and independent fluent review are prerequisites for such claims.
