# Final Architecture (Stages 1–7)

```text
Public RSS / Atom feeds (operator-configured)
        |
        v
rss_sources.py --> rss_collector.py --> normalize_entry / clean_html
                                  |              |
                                  |              +--> optional ArticleExtractor
                                  |                   HTTPS + same-host + robots + delay
                                  v
                         language_detection.py
                                  |
                                  v
                        database.py / SQLite
                        articles + append-only histories
                                  |
        +-------------------------+-----------------------------+
        |                         |               |             |
        v                         v               v             v
 threat_classification   severity_assessment  correlation  summarization
        |                         |               |             |
        +-------------------------+---------------+-------------+
                                  |
                                  v
                   dashboard_data.py --> app.py (Streamlit)

evaluation/*.jsonl --> scripts/evaluate_*.py --> metrics / unavailable indicators
```

## Data flow and trust boundaries

1. Operators edit feed URLs and caps in `config/rss_sources.json`. The collector requests and parses feeds independently, normalizes each valid entry, preserves original source/date/URL data, and does not silently treat received reports as verified.
2. Optional page extraction follows a more restrictive path than feed retrieval: HTTPS-only, exact publisher host, robots.txt decision, timeout, rate delay, no redirects. Feed summary/content is retained when full-page extraction is unavailable.
3. Language detection returns a supported language or an explicit uncertain/unknown label. Its confidence is a heuristic score, not calibrated probability.
4. Article rows are stored in SQLite with unique URLs and a non-demo content fingerprint. DEMO rows are marked separately. Separate analysis tables preserve classification, severity, correlation, and summary histories when initialized by the app.
5. Analysis modules produce explainable outputs and evidence. Correlation produces candidates only; severity and category labels are distinct; summaries are extractive and source-language only.
6. Dashboard queries display source data and analysis history. Human review decisions are preserved by database guards and append-only history patterns.
7. Evaluation scripts read independent labeled JSONL datasets. Empty research sets result in unavailable metrics; they do not substitute synthetic unit tests.

## Deployment profile

The intended initial deployment is a local Streamlit application on CPU with SQLite storage. The current implementation is not a multi-tenant service, does not include access control, and has not been hardened for public internet exposure. Pairwise correlation currently compares up to a bounded set of recent reports in the dashboard and is quadratic within the compared set.
