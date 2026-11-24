# System Validation Report

**Date:** 2026-11-25  
**Starting revision:** `1128ca7` (Stage 7)

## Automated verification

- `python -m pytest -v`: **83 passed in 6.33s**.
- `python -m compileall -q app.py src tests scripts`: **passed**.
- `git diff --check`: **passed**.
- `.venv/bin/python -m pip check`: **No broken requirements found**.
- Evaluation scripts: all five executed. Language produced synthetic-only metrics; threat, severity, correlation, and summary outputs correctly reported unavailable metrics for empty datasets.

Tests use mocked RSS responses and temporary database files; they do not need live feeds. Dashboard AppTest cases passed.

## Live RSS check

The configured feeds were fetched by the actual `collect_all` pipeline on 2026-11-25, with persistence disabled and each source capped at 10 stored entries:

| Source | Feed endpoint | HTTP / parser observation | Entries seen | Normalized |
| --- | --- | --- | ---: | ---: |
| CISA | `https://www.cisa.gov/rss.xml` | HTTP 200, `application/rss+xml`; collector `ok` | 10 | 10 |
| The Hacker News | `https://feeds.feedburner.com/TheHackersNews` | HTTP 200, `text/xml`; collector `ok` | 50 | 10 |
| BleepingComputer | `https://www.bleepingcomputer.com/feed/` | HTTP 200, `text/xml`; collector `ok` | 15 | 10 |
| Krebs on Security | `https://krebsonsecurity.com/feed/` | HTTP 200, response body parsed as RSS; collector `ok` | 10 | 10 |

**Total:** 4/4 parsed successfully; 40 normalized records; 3.866 seconds end-to-end for this run. This establishes reachability and parseability at the time of check only. It does not establish future availability, source terms, completeness, factual validity, or successful article-page extraction. No feed entries from this check were persisted.

The same collector run in the restricted sandbox failed DNS resolution for all four hosts. Thus ordinary app refresh depends on the host's network/DNS being available. The separate external check confirms the endpoints themselves were available during the approved run.

## SQLite integrity and migrations

The actual database was opened read-only using SQLite URI `mode=ro`:

- `PRAGMA integrity_check`: `ok`.
- `PRAGMA foreign_key_check`: 0 violations.
- Articles: 43 total (3 demo, 40 collected); 40 non-demo rows have stored content. Missing publication dates remain possible and are not imputed.
- Current `articles` language distribution: `am=1`, `en=1`, `om=1`, `und=40` (the three labeled rows are demo records).
- Actual database tables: `articles` only. Therefore no actual classification, severity, correlation, or summary history tables/rows were present to inspect in this snapshot.
- The user's database was not initialized, migrated, or modified during this inspection.

Automated database tests use temporary SQLite files and passed tests for Stage 1–7 migrations, record preservation, duplicate guards, append-only histories, and human-review protection. These test results validate the tested migration paths, not history data absent from the local database.

## Security and reliability review

### Findings and actions

1. **Robots.txt redirects were previously treated as a successful rules response.** Requests' `response.ok` includes 3xx statuses; with redirects disabled this could result in parsing an empty redirect body as permissive rules. Stage 8 changed the condition to accept only 2xx responses (while 404 retains the standard no-rules behavior) and added three tests for 3xx, server errors, and HTTPS/same-host restrictions.
2. **Article extraction is constrained** to HTTPS and the configured publisher hostname, disables redirects, checks robots.txt before fetching, sends a descriptive User-Agent, applies a timeout and per-host delay, and removes script/style/navigation-like elements from extracted text.
3. **Feed collection validates parser output, normalizes HTML and whitespace, applies request timeouts, and isolates source errors.** Its configured endpoints use HTTPS. Feed fetching follows HTTP redirects by Requests default; the source list is local configuration and should only contain trusted public publishers.
4. **Database access uses parameter binding for data values.** Schema/table identifiers are static in the inspected code. Foreign keys are enabled on connections. Duplicate URLs and non-demo content fingerprints are constrained in SQLite.
5. **UI rendering:** no `unsafe_allow_html=True` use was found. Article-derived content is rendered through Streamlit text/dataframe/JSON components. Markdown links are assembled from stored source URLs; retain the HTTPS/public-source configuration and avoid inserting untrusted local feeds.
6. **Configuration and secrets:** local `.env` and local feed overrides are ignored by Git. No paid API key configuration is required. Dependencies are version-range constrained in `requirements.txt`, but no lockfile, hash pinning, or vulnerability scanner is present; a full dependency CVE audit was not performed.

### Remaining security considerations

RSS URL configuration is operator-controlled; the loader accepts HTTP as well as HTTPS, and does not resolve/reject private-network addresses or URL userinfo. Do not expose feed configuration to untrusted users or point it at internal services. The application is a local research tool, not a hardened multi-user service. Network source terms, `robots.txt`, rate limits, and publisher permissions remain the operator's responsibility.

## Scope and limits

No threat model penetration test, deployment hardening assessment, accessibility audit, legal source-rights review, or full dependency CVE scan was performed. Live RSS validation proves only the observed feed response and parser outcome. The article extraction path's robots behavior has regression tests; no general live article extraction sweep was performed.

The Streamlit AppTest emitted non-fatal deprecation notices for `use_container_width`; the dashboard rendered without exceptions, but those calls should be updated before the installed Streamlit version removes that parameter.
