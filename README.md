# ETHIO-CYBER INTEL

**Research title:** *Design and Development of a Trilingual AI-Driven Cyber Threat Intelligence Aggregation, Analysis, and Correlation Framework for Amharic, Afaan Oromo, and English.*

ETHIO-CYBER INTEL is a CPU-friendly research prototype that collects permitted public cybersecurity reports, preserves source provenance, and presents preliminary analysis for English, Amharic, and Afaan Oromo. It combines configurable RSS/Atom collection, conservative article extraction, SQLite histories, lightweight language detection, explainable threat categorization, evidence-based severity triage, cross-language candidate discovery, source-language extractive summaries, and a Streamlit dashboard.

> **Research and trust boundary:** LIVE means collected from a source; it does not mean independently verified. Automated labels and relationship candidates are preliminary. Rule scores are heuristic, not calibrated probabilities. Human review is required before treating results as validated intelligence. The current release is a prototype, not a production-ready service.

## 🎥 Project Walkthrough & Live Demo

Watch our system walkthroughs demonstrating live RSS threat ingestion, trilingual detection (English, Amharic, Afaan Oromo), cross-language correlation with explainable CVE matching, and evidence-grounded summaries:

### Team Members & Individual Demo Videos (INSA Weekend Cybersecurity Program)
- **[Abdurahman Habib — Watch Walkthrough Video](https://drive.google.com/file/d/17miKXEMzcX3u9njQLS4ZPjAICL8X5VTZ/view?usp=drive_link)**
- **[Yishak Addisu — Watch Walkthrough Video](https://drive.google.com/file/d/1g29LX_GpaHyCnv0HO-Z8HUZsS9Xcy5ir/view?usp=drive_link)**
- **Firaol Fetene** 

## Research motivation and contribution

Security reporting is spread across sources and languages, while local-language NLP resources and representative evaluation data are limited. The project provides a modular, auditable workflow that keeps uncertainty and provenance visible instead of silently converting missing evidence into claims. It is an integration and research-evaluation artifact; it does **not** establish superior analytic performance or trilingual parity. See the [final research paper](docs/final_research_paper.md), the [Stage 9 evaluation report](docs/stage9_research_evaluation_report.md), and the [Stage 10 system validation report](docs/system_validation_report.md). The earlier [research evaluation report](docs/research_evaluation_report.md) is a dated Stage 8 record.

## Features

- Configurable collection from public RSS/Atom feeds with per-source failure handling, normalization, dates, source attribution, and duplicate prevention.
- Optional publisher-page extraction constrained by HTTPS, same-host checks, robots policy, rate delay, timeouts, and article identity validation. Ambiguous content is rejected while RSS provenance is retained.
- Language labels `en`, `am`, `om`, `und`, and `mul`, with method and heuristic confidence.
- Explainable multi-label threat categories: phishing, malware, ransomware, vulnerability, data breach, DDoS, cyber espionage, credential theft, other, and unknown.
- Evidence-based severity triage: Critical, High, Medium, Low, Informational, or Unknown. Threat category and severity remain separate.
- Cross-language candidate relationships with evidence and human review history. Candidate does not mean same incident or shared attribution.
- Extractive summaries selected from source text, with source excerpts and summary history. Translation and abstractive generation are not implemented.
- Separate LIVE and synthetic DEMO records, plus processing-state, source, language, category, and severity dashboard views.
- Offline research evaluation scripts and documented annotation schemas. Empty research datasets remain unavailable, not scored as zero.

## Architecture

```text
Configured RSS/Atom feeds
  → collection and normalization
  → URL/content deduplication
  → optional article extraction and identity validation
  → language detection
  → SQLite article/provenance store
  → threat categorization and severity evidence assessment
  → cross-language relationship candidates
  → source-language extractive summaries
  → Streamlit dashboard and human review
```

Detailed component responsibilities and trust boundaries: [Final Architecture](docs/final_architecture.md). Configuration and operations: [Configuration](docs/configuration.md), [Installation](docs/installation.md), and [Troubleshooting](docs/troubleshooting.md).

## Technology stack

Python, Streamlit, SQLite, Pandas, Plotly, Feedparser, Requests, BeautifulSoup, and Pytest. No GPU/CUDA dependency, paid API, or large model download is required. The current analytics are deterministic heuristic baselines and do not use a trained ML classifier or LLM.

## Screenshots

No verified application screenshots are currently included. Add screenshots captured from an actual run here before publication; do not use mockups as evidence of implemented functionality.

## Installation

Python 3.10+ and pip are required. From the project root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

For an existing checkout with `.venv`:

```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Configuration

Feeds are configured in `config/rss_sources.json`; each source has a name, URL, enabled flag, item cap, and delay. Only add sources whose access and use are permitted, and review publisher terms, robots rules, and rate limits. A configured endpoint can be unavailable. The dashboard reports observed feed status when refreshed.

Environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `ETHIO_CYBER_DB_PATH` | `data/ethio_cyber_intel.db` | SQLite database location |
| `ETHIO_CYBER_SEED_DEMO` | `true` | Seed clearly marked examples into an empty database |
| `ETHIO_CYBER_FEEDS_FILE` | `config/rss_sources.json` | Feed configuration path |
| `ETHIO_CYBER_HTTP_TIMEOUT` | `12` | HTTP timeout in seconds |

Back up an existing database before applying application migrations. See [configuration](docs/configuration.md) and [backup/recovery instructions](docs/installation.md).

## Run the dashboard

```bash
source .venv/bin/activate
streamlit run app.py
```

Use **Refresh Intelligence** to collect configured feeds. Refresh runs preliminary classification and severity assessment for eligible pending records. Other actions are explicitly initiated in the dashboard: **Detect language for legacy reports**, **Classify pending reports**, **Assess pending severity**, **Correlate collected reports**, and **Generate extractive summary**. Do not interpret an automated result as human verification.

When network access is unavailable, use the built-in DEMO DATA to demonstrate dashboard navigation and status handling. Demo records are synthetic and are not real reports. The live-source check documented in the [system validation report](docs/system_validation_report.md) observed 4/4 feeds parse successfully on 2026-11-25, producing 40 normalized entries with persistence disabled. That dated check does not guarantee current reachability. Stage 10 integration tests use mocked feeds.

Step-by-step workflow and expected explanations for unknown results: [Demonstration Guide](docs/demonstration_guide.md).

## Testing and validation

```bash
source .venv/bin/activate
python -m pytest -v
python -m compileall -q app.py src tests scripts
git diff --check
python -m pip check
```

Tests use mocked network responses and temporary databases. They do not modify the operational SQLite data or verify current feed uptime.

## Research evaluation and reproducibility

Run all task evaluations or the unified report:

```bash
python scripts/evaluate_language.py
python scripts/evaluate_threat_classifier.py
python scripts/evaluate_severity.py
python scripts/evaluate_correlation.py
python scripts/evaluate_extraction.py
python scripts/evaluate_summaries.py
python scripts/run_research_evaluation.py
```

Reproduce the local correlation microbenchmark:

```bash
python scripts/benchmark_correlation.py --sizes 40 100 300 --repeats 3
```

The benchmark uses deterministic synthetic in-memory reports and does not represent real incident data or end-to-end throughput. Details and observations are in [Stage 10 integration report](docs/stage10_integration_report.md). Full instructions: [Reproducibility Guide](docs/reproducibility.md).

### Current evidence snapshot

- The local database was inspected read-only on 2026-11-25: 46 articles (43 LIVE, 3 DEMO); integrity check `ok`, no foreign-key violations. It also held 46 classification runs, 46 severity assessments, six correlation pairs/assessments, and seven summaries. These are stored result counts, not independent validation.
- `evaluation/language_eval.jsonl` contains 15 researcher-authored synthetic examples (three for each supported output label) and a 100% synthetic sanity-check result. This is **not** real-world accuracy.
- The threat, severity, correlation, extraction, and summary research datasets contain no eligible independently reviewed examples. Their performance metrics are unavailable.
- Correlation’s local synthetic benchmark recorded 7.03×, 8.30×, and 8.38× median in-memory candidate-generation speedups at 40, 100, and 300 reports respectively, with candidate counts unchanged in those fixtures. Pairwise complexity remains quadratic; see the benchmark report for scope.

### Dataset and provenance policy

Research datasets are distinct from test fixtures and operational records. Add only permissioned, appropriately retained examples with source identity, URL/provenance, language, reviewer decision, review date, dataset version, and inclusion rationale. Keep `synthetic: true` examples out of real-world metric calculations. Follow [annotation guidelines](docs/stage9_annotation_guidelines.md) and the templates under `evaluation/templates/`. Evaluation scripts do not create labels or ground truth.

## Limitations

- Afaan Oromo uses Latin script and is distinguished from English using limited lexical cues. Detection needs broad independent validation; no language parity claim is supported.
- Threat categories use hand-built rules, not a trained classifier. Severity is a preliminary evidence policy and does not query external CVE/KEV sources by default.
- Correlation finds candidates using shared identifiers/entities and lexical/date signals; it is not multilingual semantic understanding and does not prove same-event identity or attribution.
- Summaries are extractive and source-language only. There is no translation or abstractive generation.
- Feed access and publisher HTML are time-dependent. The documented successful feed check is dated; live extraction has not been exhaustively evaluated.
- Hostname DNS resolution/private-address validation and response-size limits remain incomplete. The dependency set has not undergone a vulnerability scan, and deployment security has not been audited.
- The local Streamlit/SQLite application has no authentication/authorization or multi-user deployment hardening. Do not expose it directly to the public internet.
- Evaluation data is insufficient for real-world effectiveness claims.

See [Known Limitations](docs/known_limitations.md), [Security and Ethics Review](docs/security_and_ethics_review.md), and the [final research paper](docs/final_research_paper.md).

## Ethics and safe scope

The platform is for defensive research using public, permitted reports. It does not execute attacks or bypass access controls. It preserves source attribution, distinguishes collected claims from verified evidence, and requires human review before validated intelligence claims. Researchers must follow source terms, robots policies, rate limits, privacy requirements, and applicable law; minimize personal data; and avoid unsupported actor attribution or impact statements.

## Project structure

```text
app.py                         Streamlit dashboard and user-triggered workflows
config/rss_sources.json        Operator-managed RSS/Atom sources
data/                          Local SQLite database (not a research dataset)
docs/                          Research paper, architecture, evaluation, and operating guides
evaluation/                    Separate research data and annotation templates
scripts/                       Evaluation and correlation benchmark commands
src/ethio_cyber_intel/         Collection, extraction, analysis, persistence, and dashboard modules
tests/                         Offline unit/integration tests and synthetic fixtures
requirements.txt               Runtime and test dependencies
```

## Delivery documents

- [Research paper](docs/final_research_paper.md)
- [Final architecture](docs/final_architecture.md)
- [Presentation outline](docs/final_presentation_outline.md)
- [Demonstration guide](docs/demonstration_guide.md)
- [Security and ethics review](docs/security_and_ethics_review.md)
- [Reproducibility guide](docs/reproducibility.md)
- [Evaluation methodology and results](docs/research_evaluation_report.md)
- [Known limitations](docs/known_limitations.md)

## Future work

Collect a permissioned, stratified multilingual corpus; obtain independent fluent review; evaluate baselines on fixed splits; examine source and language coverage; conduct extraction and summary quality studies; add DNS/private-address and response-size protections; perform dependency and deployment audits; and evaluate usability with analysts. These items require separate approval and evidence; they are not claimed as completed.
