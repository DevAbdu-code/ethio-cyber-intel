# Reproducibility Guide

This guide reproduces the offline research evaluation and technical checks without writing to the operational research database or converting test fixtures into research data.

Stage 10 integration tests mock all RSS responses and use `tmp_path` SQLite databases. They validate a feed outage beside successful feeds, normalization, missing/invalid dates, URL deduplication, language output, classification, severity, candidate correlation, summary handling, and temporary database integrity. They do not contact publishers. Actual database checks below are read-only.

## Environment

Validated environment: Kali Linux, Python 3.14.10, project virtual environment `.venv`. Dependencies are listed in `requirements.txt` and are not newly added by Stage 8.

```bash
cd ~/ethio-cyber-intel
source .venv/bin/activate
```

For a fresh setup, create the virtual environment and install the declared packages:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Re-run deterministic evaluation scripts

```bash
python scripts/evaluate_language.py
python scripts/evaluate_threat_classifier.py
python scripts/evaluate_severity.py
python scripts/evaluate_correlation.py
python scripts/evaluate_summaries.py
python scripts/evaluate_extraction.py
python scripts/run_research_evaluation.py
```

The language output is a **synthetic sanity check** from 15 researcher-authored rows. Threat, severity, correlation, summary, and extraction research datasets are currently empty, so their metrics should remain `null`/unavailable. Do not copy `tests/fixtures/` or unit-test cases into the research evaluation datasets. The unified runner is deterministic for the same source revision and dataset content, has no network or SQLite dependency, and only writes a file if `--output` is explicitly supplied.

### Add reviewed research examples

Use the JSON schemas in `evaluation/templates/`, the protocol in `docs/stage9_annotation_guidelines.md`, and the dataset instructions under `evaluation/`. Add one JSON object per line, retain only text permitted by its publisher/source, record provenance and permission, and set reviewer decision, review date, dataset version, and synthetic flag. For correlation, both articles in a pair must be manually adjudicated. For summaries, reviewers must assess the exact output and method version; Amharic/Afaan Oromo ratings should be completed by fluent reviewers. For extraction, compare output with the feed entry and canonical publisher page. Do not treat researcher-authored synthetic text as a real report. Keep test fixtures separate.

After adding data, rerun only the appropriate script first, inspect eligible research/synthetic counts and output, and report the sample size alongside every metric. The evaluators do not create labels or ground truth. Severity nominal scores include Unknown; ordinal weighted agreement excludes Unknown and reports its denominator. Threat `unknown` is treated separately as abstention. Correlation measures candidate retrieval, not same-incident proof.

## Automated checks

```bash
python -m pytest -v
python -m compileall -q app.py src tests scripts
git diff --check
python -m pip check
```

The `pip check` result only verifies installed dependency compatibility; it is not a dependency vulnerability scan. The full documented environment for the final delivery was Python 3.14.10 in `.venv`. Results should be recorded with the commit hash, Python/dependency versions, dataset versions, and exact command output.

The Stage 10 correlation microbenchmark uses deterministic synthetic inputs and tests only in-memory candidate generation. It does not write to SQLite or represent real incidents:

```bash
python scripts/benchmark_correlation.py --sizes 40 100 300 --repeats 3
```

The Stage 10 comparison loads the previous checked-in implementation for the before measurements and uses the same Python process, synthetic input generator, sizes, repetitions, and matching rules. See `docs/stage10_integration_report.md` for the recorded observations and limits. It is a local CPU microbenchmark, not a throughput promise.

RSS unit tests use mocked responses and do not contact publishers. To perform an optional live feed check, use the dashboard's **Refresh Intelligence** action or run the collector manually when network access is available. The current collector pipeline persists articles only when called through the dashboard workflow; do not use the live collector for a repeatability benchmark unless you explicitly intend collection. The Stage 8 verification used `collect_all(load_sources(...))` and did not call `insert_live_articles`, so it did not change SQLite data.

## Database integrity checks (read-only)

Run SQLite integrity checks without initialization or migration:

```bash
python - <<'PY'
import sqlite3
path = "data/ethio_cyber_intel.db"
db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
print(db.execute("PRAGMA integrity_check").fetchone()[0])
print(db.execute("PRAGMA foreign_key_check").fetchall())
db.close()
PY
```

Migration tests in `tests/test_database.py` use temporary databases. Do not run destructive migration experiments against a unique research database; make a verified backup or use a temporary copy.

For the final delivery snapshot (2026-11-25), the configured database was inspected in read-only mode: 46 article rows (43 LIVE and 3 DEMO), 46 classification runs, 46 severity assessments, six correlation pairs/assessments, and seven summaries. `integrity_check` returned `ok`; `foreign_key_check` returned no rows. These counts do not indicate that report content or analysis has been independently verified. No database initialization, migration, or write is part of the final documentation and verification work.

## Final delivery commands

From the repository root:

```bash
source .venv/bin/activate
python -m pytest -v
python -m compileall -q app.py src tests scripts
git diff --check
python -m pip check
python scripts/run_research_evaluation.py
python scripts/benchmark_correlation.py --sizes 40 100 300 --repeats 3
streamlit run app.py
```

Research evaluators read the JSONL files and do not access the operational database or the network. The correlation benchmark uses synthetic in-memory inputs. Do not run Streamlit refresh during an offline/reproducibility check unless you intend to collect and store live reports.

## Live feed reproducibility caveat

RSS responses change over time. The Stage 8 observation was on 2026-11-25, with all four configured feeds returning parseable responses and 40 capped normalized entries. This is a dated availability check, not a guarantee of future uptime or a retained research corpus. The sandbox environment failed DNS; the successful verification required an external-network execution. Feed retrieval and article extraction remain subject to source terms, robots rules, and rate limits.
