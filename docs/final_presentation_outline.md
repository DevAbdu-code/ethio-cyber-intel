# Academic / Technical Defense Presentation Outline

Suggested length: 12–15 minutes plus demonstration and questions. Use screenshots only after capturing them from a real dashboard run. This outline deliberately separates software verification from research performance.

## Slide 1 — Title

**Design and Development of a Trilingual AI-Driven Cyber Threat Intelligence Aggregation, Analysis, and Correlation Framework for Amharic, Afaan Oromo, and English**

- ETHIO-CYBER INTEL
- Presenter, department, supervisor, and institution: fill in locally.
- State that the delivered artifact is a CPU-oriented research prototype.

## Slide 2 — Introduction and motivation

- Public cybersecurity reporting is distributed across sources and may be published in multiple languages.
- Analysts need provenance, uncertainty, and a way to review possible related reports.
- Regional-language NLP resources are uneven; equal language performance cannot be assumed.

## Slide 3 — Problem statement

- Reports must be collected and normalized without losing publisher identity, URL, or publication date.
- Extracted text, source statements, and heuristic analysis can be wrong or incomplete.
- A tool must expose “unknown” and “candidate” states rather than force confident conclusions.

## Slide 4 — Objectives and research questions

- Build a modular local pipeline for collection and review.
- Provide conservative language/category/severity/correlation/summary baselines.
- Make evaluation reproducible and distinguish synthetic from human-reviewed data.
- RQ1 integration: supported at artifact level. RQ2 effectiveness: unavailable without independently reviewed data. RQ3 evidence-aware analyst utility: designed for, not yet user-study tested.

## Slide 5 — Background and research gap

- CTI sharing, structured representation, NLP-based CTI processing, and Ethiopian-language NLP are established research areas.
- The project’s scoped opportunity is integrating these workflow concerns for the three target languages in one locally runnable prototype.
- Clarify this is a scoped design motivation, not a systematic proof that no comparable platform exists.
- Mention key literature: NIST SP 800-150; OASIS STIX 2.1; Arazzi et al. (2025); Tonja et al. (2023).

## Slide 6 — Proposed solution and system architecture

Show the actual flow:

```text
RSS/Atom → normalize/deduplicate → optional validated extraction → language detect
→ SQLite → classify → assess evidence/severity → correlate candidates
→ extractive summary → dashboard and human review
```

Explain source provenance and the boundary between collected reports and verified advisories.

## Slide 7 — Technology stack and design choices

- Python, Streamlit, SQLite, Pandas, Plotly, Feedparser, Requests, BeautifulSoup, Pytest.
- CPU-only heuristics; no paid API, GPU/CUDA, or large model.
- Separate modules; append-only analysis histories; temporary DB and mocked network tests.

## Slide 8 — Demonstration workflow

- Launch the dashboard and identify LIVE vs DEMO.
- Refresh configured RSS sources (network permitting).
- Inspect metadata and validated/fallback article text.
- Review language and confidence; run pending classification and severity actions.
- Generate relationship candidates and inspect/review evidence.
- Generate an extractive summary and show source excerpts.
- Use [Demonstration Guide](demonstration_guide.md) for exact steps and offline fallback.

## Slide 9 — Implementation details

- Language: Ethiopic Unicode script evidence and limited English/Oromo lexical cues.
- Classification: explainable keyword/phrase multilabel rules.
- Severity: documented evidence rules; missing/conflicting support can remain Unknown.
- Correlation: normalized identifiers/entities plus supporting lexical/date signals; candidate only.
- Summary: source sentence selection; no paraphrase or translation.

## Slide 10 — Evaluation methodology

- Six task-specific datasets/evaluators: language, threat, severity, correlation, extraction, summary.
- Synthetic unit fixtures are not research data.
- Human-reviewed rows require provenance, reviewer decision/date, language, and dataset version.
- Use metrics only when there are eligible independent labels; use fluent reviewers for Oromo/Amharic judgments.

## Slide 11 — Verified results

- Read-only DB snapshot (2026-11-25): 46 articles (43 LIVE, 3 DEMO); integrity `ok`; no foreign-key violations.
- 113 tests, compileall, Git whitespace, and dependency consistency were verified at the Stage 10 checkpoint; rerun final commands for the current delivery.
- Language set: 15 synthetic examples, 100% on that sanity set only; not real-world accuracy.
- Other independent research metrics: unavailable because reviewed datasets are empty.
- Synthetic correlation benchmark: 7.03× / 8.30× / 8.38× median in-memory speedup at 40 / 100 / 300 reports; same fixture candidate counts; pairwise complexity remains quadratic.
- Historical live RSS check (2026-11-25): four feeds parsed, 40 normalized entries, no persistence; not a guarantee of current connectivity.

## Slide 12 — What differentiates the platform from a news aggregator

- Preserves article provenance and extraction validation state.
- Keeps LIVE reports distinct from synthetic demo records.
- Adds uncertainty-aware language and threat processing, severity evidence, cross-language candidate review, and extractive evidence excerpts.
- Stores analysis/review histories and exposes “not assessed,” “unknown,” and “candidate.”
- These are workflow differences, not evidence of more accurate intelligence.

## Slide 13 — Limitations and threats to validity

- No independent real-world labeled evaluation set; no trilingual parity claim.
- Afaan Oromo cue coverage is limited; English-focused portions of analysis remain.
- No translation, abstractive generation, external CVE/KEV lookup, or trained classifier.
- Correlation does not prove same incident or actor attribution.
- DNS/private-address validation, response-size caps, dependency vulnerability scan, and deployment audit remain open.
- Local single-user prototype; not production ready.

## Slide 14 — Ethics and future work

- Public permitted sources only; follow publisher terms, robots policy, rate limits, privacy, and applicable law.
- Human validation before treating outputs as intelligence; no offensive operations.
- Build permissioned, stratified reviewed corpora; perform fluent language review; security harden and audit before wider deployment.

## Slide 15 — Conclusion and questions

- The project delivers an integrated, traceable research prototype and reproducible evaluation scaffolding.
- The strongest verified outcomes are system integration, test coverage, data integrity, and local synthetic benchmark behavior.
- Analytic effectiveness remains an open empirical question.

### Presenter preparation

- Replace placeholders for presenter and institution.
- Rerun all final verification commands immediately before defense.
- Confirm which feed endpoints are reachable on the demonstration network.
- Do not show collected article text publicly if license/retention terms do not permit it.
- Present actual dashboard screenshots only; no screenshots are currently committed.
