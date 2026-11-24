# Configuration guide

Settings use environment variables. Paths relative to the repository root are resolved from the project directory.

| Variable | Default | Purpose |
| --- | --- | --- |
| `ETHIO_CYBER_DB_PATH` | `data/ethio_cyber_intel.db` | SQLite store path |
| `ETHIO_CYBER_SEED_DEMO` | `true` | Add synthetic demo rows only when the database has no articles |
| `ETHIO_CYBER_FEEDS_FILE` | `config/rss_sources.json` | Feed source configuration file |
| `ETHIO_CYBER_HTTP_TIMEOUT` | `12` | Network timeout in seconds (minimum 1) |

Example for a one-off local run:

```bash
export ETHIO_CYBER_DB_PATH="$PWD/data/ethio_cyber_intel.db"
export ETHIO_CYBER_SEED_DEMO=true
export ETHIO_CYBER_HTTP_TIMEOUT=12
streamlit run app.py
```

The app does not automatically load `.env`; set variables in the shell/service environment. Do not put secrets in the public source configuration. No secrets are currently required.

## RSS source list

`config/rss_sources.json` is an operator-controlled JSON array. Each record has `name`, `url`, `homepage`, `enabled`, `max_articles` (clamped to 1–50), and `delay_seconds` (clamped to 0–10). Feed and homepage URLs must use HTTPS, cannot contain user credentials, and obvious localhost/private literal-IP targets are rejected. Each redirect is checked the same way before it is followed. Redirect chains are limited to five hops. A source must remain public and permitted by its terms; feed retrieval has a timeout, while optional article-page extraction applies same-publisher host checks, robots rules, no redirects, a timeout, and per-host delay.

These guards do not resolve hostnames to inspect their DNS addresses. Keep the feed file writable only by trusted operators and do not use it to target internal services. RSS content and extracted reports are collected source material, not verified advisories.
