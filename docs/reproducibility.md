# Reproducibility Guide

This guide reproduces the Stage 8 checks without writing to the user's research database or converting test fixtures into research data.

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
```

The language output is a **synthetic sanity check** from 15 researcher-authored rows. The other four research datasets are empty, so their metrics should remain `null`/unavailable. Do not copy `tests/fixtures/` or unit-test cases into the research evaluation datasets.

### Add reviewed research examples

Use the schema instructions in `evaluation/README.md` and the stage-specific files under `evaluation/`. Add one JSON object per line, retain only text permitted by its publisher/source, record provenance and permission, and set the required manual-review fields. For correlation, both articles in a pair must be manually adjudicated. For summaries, reviewers must assess the exact saved output and method version; Amharic/Afaan Oromo ratings should be completed by fluent reviewers. Do not treat researcher-authored synthetic text as a real report. Keep test fixtures separate.

After adding data, rerun only the appropriate script first, inspect its `evaluated_examples`/support counts and output, and report the sample size alongside every metric. The evaluators do not create labels or ground truth.

## Automated checks

```bash
python -m pytest -v
python -m compileall -q app.py src tests scripts
git diff --check
```

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

## Live feed reproducibility caveat

RSS responses change over time. The Stage 8 observation was on 2026-11-25, with all four configured feeds returning parseable responses and 40 capped normalized entries. This is a dated availability check, not a guarantee of future uptime or a retained research corpus. The sandbox environment failed DNS; the successful verification required an external-network execution. Feed retrieval and article extraction remain subject to source terms, robots rules, and rate limits.
