# Installation and launch

## Supported local setup

The app is intended for a local CPU-only Linux environment. Python 3.10+ is required; verification in this repository currently uses Python 3.14.10 and the `.venv` environment. No GPU, model download, or API key is needed.

```bash
cd ~/ethio-cyber-intel
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
streamlit run app.py
```

For test and evaluation commands, keep the same environment activated:

```bash
python -m pytest -v
python -m compileall -q app.py src tests scripts
python scripts/run_research_evaluation.py
```

The app initializes its configured SQLite database when launched. Back up an existing database before updating to a release that changes schema. The application migrations are additive/preserving and covered with temporary database tests, but the backup remains the recovery point for local research data.

## Safe SQLite backup and restore

Use SQLite's online backup API while the app is stopped or idle. Replace the target paths with the configured database and a separate backup path; never place the backup over the source database.

```bash
python - <<'PY'
import sqlite3
source = sqlite3.connect("data/ethio_cyber_intel.db")
backup = sqlite3.connect("data/ethio_cyber_intel.backup.db")
source.backup(backup)
backup.close()
source.close()
PY
```

Before restore, stop Streamlit and preserve the current database file. Restore only from a verified backup by using SQLite's backup API in the reverse direction. Check `PRAGMA integrity_check` and `PRAGMA foreign_key_check` on the restored copy before using it.

For example, after preserving the current target as a separate file, restore the backup into the configured path:

```bash
python - <<'PY'
import sqlite3
backup = sqlite3.connect("data/ethio_cyber_intel.backup.db")
target = sqlite3.connect("data/ethio_cyber_intel.db")
backup.backup(target)
target.close()
backup.close()
PY
```

Then run the read-only integrity and foreign-key checks before restarting the app.
