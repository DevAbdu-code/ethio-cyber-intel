# Known Limitations and Research Gaps

## Evidence and evaluation data

- The only populated evaluation file is `language_eval.jsonl`, containing 15 researcher-authored synthetic examples (3 per label). Its perfect result is only a narrow implementation sanity check.
- Threat, severity, cross-language correlation, and summary evaluation datasets are empty. Their research metrics are unavailable.
- The stored local database has 43 article records but only the `articles` table; no analysis history tables exist in this snapshot. All 40 collected rows are currently language `und`. The database was inspected without writes.
- Existing reports are a convenience sample collected from configured publishers, not a representative dataset. Source claims have not been independently checked.

## Language and threat analysis

- Afaan Oromo detection relies on a small hand-built Latin-script cue list and must be validated against broader, manually reviewed text. English, Oromo, code-switching, spelling variation, and transliteration can be confused.
- Ethiopic script is a useful Amharic cue but does not itself establish the language for every script/loanword use.
- Threat classification is a keyword baseline, not a trained AI/ML classifier. Category coverage is incomplete, scores are heuristic, and no research performance claims are supported.
- Severity uses article claims unless real external evidence with provenance is supplied. The current app does not perform external vulnerability database lookups. The English-focused phrase rules have not been evaluated for the three languages.

## Correlation and summarization

- Cross-language correlation depends on shared identifiers or explicitly labeled entities; it does not provide multilingual semantic understanding. It identifies candidates, not same incidents or attribution.
- Pairwise correlation is quadratic; the 40-record benchmark required 6.686 seconds for 780 pairs on the recorded environment. Larger collections need indexing/candidate generation.
- Stage 10 reduces repeated signal extraction and candidate write transactions. A matched synthetic in-memory benchmark recorded about 7.0×–8.4× faster candidate generation at 40–300 reports with identical candidate counts; pairwise comparison remains quadratic and results do not establish production throughput.
- Summaries are source-language extractive selections. There is no translation or abstractive generation. Key intelligence phrase extraction (impact/exploitation) is English-focused. No eligible source-language-labeled records existed for a real-data summary benchmark.
- No human-rated summary examples exist; factuality, coverage, readability, usefulness, and language correctness are unmeasured.

## Collection, security, and operations

- Feed reachability is a dated observation; network and DNS failures can block live refresh. Feeds are capped, may omit items, and may change or fail without notice.
- Article extraction depends on publisher HTML and robots rules, uses only same-host HTTPS, and may return no body. A general live page-extraction validation was not performed.
- Feed URLs are operator configuration. The loader accepts both HTTP and HTTPS, does not reject private-address destinations or URL userinfo, and feed requests follow redirects. Do not expose source configuration to untrusted parties.
- SQLite is local storage with no multi-user authentication/authorization layer. No public deployment hardening or penetration test was performed.
- Dependency declarations are range constrained but not hash locked; no complete vulnerability audit was performed.
- Performance observations are local microbenchmarks, not resource guarantees. Memory values are Python traced allocations and not whole-process RSS. Dashboard startup was not separately measured.

## Research work required before performance claims

Build a permissioned and representative corpus; stratify by language, threat class, publisher, and time; use independent fluent reviewers; establish adjudication procedures; hold out a true test set; report confidence intervals and sample sizes; review false positives/negatives; compare baselines using identical splits; and version both data and methods. Do not claim trilingual parity before such evaluation.
