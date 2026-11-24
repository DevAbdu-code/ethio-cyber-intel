# RSS, Extraction, Language, and Processing Pipeline Validation

**Validation date:** 2026-11-25

## Root causes

### Incorrect article body extraction

`ArticleExtractor.extract()` selected `soup.find("article")` before looking for publisher-specific article-body containers. The Hacker News page uses `<article>` elements for recommended/sponsored cards. Its first such element contained “11 Real Stories: How Identity Exposure…” (148 characters), while the requested Google Project Zero story was in `#articlebody` (5,012 characters). The RSS title, URL, source, publication date, and description for database article 18 were mutually consistent; only the stored extracted body was wrong.

### Legacy language metadata

The 40 pre-existing LIVE rows had `language='und'`, no detection method, no confidence, and no human review. This is the legacy “not processed” state, rather than 40 detector decisions. The prior article text is suspect and must not be used to infer language: on the sample, detection from stored text returned `und`, while using the source RSS title and description returned English.

### Analysis execution/status

Dashboard startup initializes/migrates and loads records but does not classify or assess all pending rows. **Refresh Intelligence** collects, inserts, and then runs classification and severity assessment for pending reports. The separate classify and assess buttons are also available for pending records. Correlation requires its own explicit action; summaries are generated for a selected article. Stored states are history rows, not inferred from whether a report exists.

## Fixes

- Page extraction now requires an expected RSS title, HTTPS same-host URL, allowed robots decision, matching canonical path when a canonical link exists, and a matching page headline. It prefers explicit article-body selectors and only accepts a `<article>` element when the article title matches. It no longer falls back to a generic `<main>` or the first `<article>`; ambiguous pages fall back to RSS metadata without full text.
- Content provenance is recorded as `rss_feed_entry`, `page_identity_verified`, `not_available`, or `legacy_unverified`.
- Historical body text is retained but marked `legacy_unverified`. The database migration is additive (`ALTER TABLE ... ADD COLUMN`) and downstream analysis queries use body text only for RSS-entry content or page-identity-verified extraction. Summary workspace warns and uses title/description for legacy rows.
- Legacy language detection is an explicit dashboard action and processes only LIVE rows that are still `und`, unreviewed, and have no detection method. It uses title and RSS description, not historical body text. Uncertain results remain `und`.
- Dashboard status metrics separate language not assessed from unknown after detection; automated classified, unknown, human-reviewed, and unclassified reports; and assessed, unassessed, and assessed-unknown severity. Correlation status counts remain explicit, including zero values.

## Live reproduction

The public THN page returned HTTP 200 and a canonical path matching the RSS URL. Its page title matched the RSS title. Running the revised extractor with robots checking and persistence disabled returned 5,012 characters beginning with the report's .NET Framework description; the unrelated recommendation was absent.

The existing database row was **not overwritten**. It still contains the earlier 148-character text, now marked `legacy_unverified`; `load_article_detail()` hides that text from summarization and supplies the RSS description. Historical classification/severity/summary records were not deleted or regenerated.

## Language backfill and actual database migration

Before language backfill, a read-only preview found 40 eligible rows: 39 outputs were `en` (`lexical_cues_en`) and one remained `und` (`unsupported_or_uncertain`). A pre-backfill SQLite backup was created at `data/ethio_cyber_intel.pre_language_backfill.20261125T013221.sqlite`. The backfill updated exactly those 40 rows and preserved all articles.

Before the schema migration, the post-backfill database was backed up to `data/ethio_cyber_intel.pre_content_validation.20261125T013948.sqlite`. The migration was first run on a temporary copy; counts for articles, classification runs, severity assessments, correlation pairs/assessments, and summaries were unchanged. The actual migration then added the status column without rebuilding `articles`:

| Table | Rows after migration |
| --- | ---: |
| articles | 46 (43 LIVE, 3 DEMO) |
| threat_classification_runs | 46 |
| severity_assessments | 46 |
| correlation_pairs | 1 |
| correlation_assessments | 1 |
| article_summaries | 5 |

Current article language distribution is 42 LIVE `en`, 1 LIVE `und`, plus the 3 labeled DEMO records (`en`, `am`, `om`). Article body status is 43 `legacy_unverified` and 3 `not_available` (DEMO records). Database integrity is `ok`; foreign-key violations: 0.

Current saved analysis state is 37 automated classified, 9 classifier-unknown, 0 unclassified; 46 severity assessments, including 25 assessed `Unknown`; and 1 correlation `Candidate` (not human-confirmed). There are 5 historical `unsupported_language` summaries. These existing decisions were preserved.

## Test coverage and limits

Regression tests cover THN-style related cards, mismatched headlines/canonical paths, fail-closed fallback to RSS metadata, preserved source title/URL/date, additive migration with classification history, review-safe language backfill, exclusion of legacy bodies from analysis, and dashboard status metrics.

Final verification: `python -m pytest -v` — **93 passed in 7.15s**; `python -m compileall -q app.py src tests scripts` — **passed**; `git diff --check` — **passed**. No dependencies were added.

Page layout varies by publisher. The extractor now fails closed when it cannot identify a sufficiently substantial, title-consistent body, so some valid pages may rely on their RSS description. This does not establish universal extraction accuracy. Existing unverified body text remains in SQLite for provenance/recovery but is excluded from new automated analysis. Replacing it requires an explicit, separately audited refresh workflow. The language detector remains heuristic; one LIVE item remains unknown. No categories or severity values were changed during this validation.
