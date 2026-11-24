# Troubleshooting

## No articles arrive after refresh

- Check the dashboard's per-source status and message. One failed feed does not stop other sources.
- `Request timed out` or `Network error` can indicate DNS, proxy, firewall, or publisher availability problems. Retry later; the app does not fabricate missing reports.
- `Invalid` means configuration failed URL checks or the response was not recognizable RSS/Atom. Configure a public HTTPS feed and verify it in a browser or with an authorized request.
- If a feed redirects, every redirect must remain HTTPS and point to a public-looking host; private literal IPs, credentials, local hosts, and overlong redirect chains are rejected.
- A feed may parse but yield no valid entries. Inspect title, link, and publisher source fields; malformed entries are skipped and counted.

## Articles appear but content or language is unavailable

- The publisher may omit full text in RSS. Page extraction is optional and fails closed when robots.txt, same-host HTTPS, headline, canonical identity, or explicit body checks fail.
- RSS title, description, publication date (if supplied), source, and original URL remain available when page extraction is rejected.
- `und` means language evidence is insufficient or unsupported. It is not a failed article fetch and is not forced into English, Amharic, or Afaan Oromo.
- Legacy body text can be marked `legacy_unverified`; downstream analysis excludes it and falls back to source title/description.

## Analysis statuses

- **Unclassified / Not assessed / Not generated** means no corresponding history row exists.
- **Unknown** is an assessment result after processing, not the same as not assessed. Classification Unknown means no supported category had enough evidence; severity Unknown means available evidence did not support a level.
- **Candidate** correlation requires human review and does not prove a shared incident.
- Summary statuses such as insufficient content or unsupported translation are explicit; the current summarizer is extractive and does not translate.
- Automated classifications and severity are preliminary and do not verify source claims.

## Database errors or upgrades

Stop the app and take a separate SQLite backup before an upgrade. Check `PRAGMA integrity_check` and `PRAGMA foreign_key_check` on a read-only connection. Do not test migrations against the only copy of research data; the migration tests create temporary databases. If a backup restore is required, preserve the damaged file for diagnosis and follow [installation and recovery](installation.md).

## Test and evaluation environment

Activate `.venv` before running tests. System Python may not have Streamlit and other project packages. Use `python -m pytest -v`. Empty research evaluation datasets correctly return unavailable metrics; synthetic sanity-check examples are not real-world performance evidence.
