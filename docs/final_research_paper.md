# Design and Development of a Trilingual AI-Driven Cyber Threat Intelligence Aggregation, Analysis, and Correlation Framework for Amharic, Afaan Oromo, and English

## Abstract

This paper documents the design and implementation of ETHIO-CYBER INTEL, a CPU-oriented research prototype for collecting publicly available cybersecurity reports and organizing them for review across English, Amharic, and Afaan Oromo. The system combines configurable RSS/Atom collection, conservative publisher-page extraction, provenance-preserving SQLite storage, heuristic language identification, explainable multi-label threat categorization, evidence-based severity triage, cross-language candidate correlation, extractive summaries, and a Streamlit dashboard. The implementation emphasizes traceability, uncertainty, separation of collected reports from verified advisories, and preservation of human review. It avoids paid services, GPU dependencies, and unsupported generated claims. Evaluation infrastructure covers language detection, classification, severity, correlation, extraction, and summaries. The available language evaluation contains 15 researcher-authored synthetic sanity examples and is not a field-performance estimate. The remaining reviewed evaluation datasets contain no eligible independent examples; corresponding real-world effectiveness metrics are unavailable. A dated local benchmark showed approximately 7.03×–8.38× lower in-memory correlation time after feature precomputation, with equal candidate counts on its deterministic synthetic fixtures. These observations are implementation-level results, not evidence of analytic accuracy or production capacity. The prototype demonstrates an integrated, auditable workflow, while independent multilingual validation, expanded security hardening, and fluent human review remain prerequisites for academic effectiveness claims or operational deployment.

**Keywords:** cyber threat intelligence; multilingual NLP; Amharic; Afaan Oromo; RSS; evidence provenance; correlation; extractive summarization; human review.

## 1. Introduction

Cyber threat intelligence (CTI) is distributed across advisories, security publications, vendor reports, and other public sources. Analysts must identify relevant claims, preserve context, and avoid confusing repeated coverage with independent confirmation. Language coverage adds another challenge: security information may be published in English and in regional languages whose computational resources and evaluation data are less abundant. This project examines the design of a small, local workflow for collecting and organizing reports in English, Amharic, and Afaan Oromo, while explicitly representing uncertainty.

The project is an engineering research artifact, not a validated operational intelligence service. The name and research title describe the intended trilingual scope; the implementation uses lightweight deterministic NLP and rule-based methods rather than a trained generative or classification model. This distinction is central to interpreting the results.

## 2. Background

NIST guidance on cyber threat information sharing emphasizes selecting useful sources, defining sharing goals and rules, and accounting for privacy and legal considerations (Johnson et al., 2016). STIX provides a standardized representation for exchanging structured cyber threat information; ETHIO-CYBER INTEL does not currently implement STIX serialization or exchange (OASIS, 2021). CVSS is a vulnerability-severity scoring system, not a complete measure of organizational or incident risk (FIRST, 2019); accordingly, this project keeps severity separate from threat category and preserves the provenance of score claims.

The broader NLP literature describes both the opportunity and limitations of applying text processing to CTI, including collection, analysis, relation extraction, and data-quality concerns (Arazzi et al., 2025). Research on Ethiopian-language NLP documents resource and tooling constraints across Amharic, Afaan Oromo, Tigrinya, and Wolaytta (Tonja et al., 2023). These sources motivate conservative language handling and evaluation by language rather than assuming equal performance.

## 3. Problem statement

Public cybersecurity reports can be difficult to search and compare when they are dispersed across feeds and languages. An integrated tool must retain source attribution, distinguish report claims from independently verified facts, and prevent a missing field or heuristic match from becoming a confident assertion. For Amharic and Afaan Oromo, data and tooling constraints further make unmeasured performance claims inappropriate. The engineering problem is therefore to build a modular, explainable collection and review workflow, and to make its limitations and evaluation gaps visible.

## 4. Research objectives and questions

### 4.1 Objectives

1. Design a CPU-friendly pipeline that collects permitted public cybersecurity reports and preserves provenance.
2. Implement conservative language detection, threat categorization, severity triage, candidate correlation, and extractive summarization as separate modules.
3. Provide a dashboard that distinguishes LIVE reports, DEMO data, not-assessed states, unknown results, preliminary automated outputs, and human review.
4. Provide reproducible evaluation tools and data protocols without conflating synthetic fixtures with reviewed research examples.

### 4.2 Research questions

- **RQ1:** Can the components be integrated into a local, provenance-preserving workflow without requiring paid services or GPU resources?
- **RQ2:** What are the components’ measured accuracy and quality across English, Amharic, and Afaan Oromo on independently reviewed data?
- **RQ3:** Can candidate correlation and summary evidence be presented in a way that supports human review without representing candidates or article claims as verified incidents?

RQ1 is answered at the software integration level. RQ2 remains unanswered because independent evaluation datasets are empty. RQ3 is addressed through the design and dashboard workflow but has not been evaluated in a user study.

## 5. Literature review and research gap

CTI sharing guidance and structured formats establish the importance of provenance, explicit representation, and agreed handling practices (Johnson et al., 2016; OASIS, 2021). NLP-based CTI surveys describe tasks that include collection, extraction, classification, and relationship analysis, while also discussing data-quality and ethical challenges (Arazzi et al., 2025). Separately, surveys of Ethiopian-language NLP describe uneven resources and tooling for local languages (Tonja et al., 2023).

The project’s scoped design opportunity is the integration of provenance-aware collection, uncertainty-preserving analysis, and human review for these three target languages in a small local platform. This is not a claim that no prior system or study has addressed the combination: a systematic literature review was not conducted. The implementation itself also does not establish a methodological advance in multilingual modeling. Its contribution is a reproducible software artifact and evaluation scaffolding that makes data gaps explicit.

## 6. Research methodology

The work followed an iterative software artifact development process. Components were separated by responsibility: source configuration and collection, normalization/extraction, language detection, database persistence, analysis modules, dashboard presentation, and offline evaluation. Tests exercise deterministic behavior and failure handling with mocked network responses and temporary databases. The configured research database was inspected read-only for this delivery.

The evaluation plan uses task-appropriate metrics: classification metrics for language identification; per-category and micro/macro measures for multilabel categorization; nominal and weighted agreement for severity; candidate retrieval metrics for correlation; human-reviewed identity/content checks for extraction; and traceability, coverage, unsupported claims, language correctness, readability, and usefulness for summaries. A metric is reported only when an eligible independently reviewed dataset is available. Test fixtures and synthetic sanity data are excluded from research estimates.

## 7. System requirements

### 7.1 Functional requirements

- Read multiple operator-configured public RSS/Atom sources and isolate source failures.
- Preserve source name, original URL, title, description/body, and publication time when supplied.
- Normalize article text, reject ambiguous page extraction, and prevent duplicate inserts.
- Represent supported languages (`en`, `am`, `om`) and uncertainty (`und`, `mul`).
- Generate explainable category labels, severity assessments, candidate relationships, and source-language extractive summaries.
- Preserve assessment history and human review; distinguish LIVE from DEMO records.
- Provide filters, evidence, status counts, and offline evaluation scripts.

### 7.2 Non-functional requirements

The prototype targets local CPU execution, modularity, source attribution, graceful handling of missing evidence, no paid API dependency, and reproducible tests. It is not designed as a multi-user or internet-exposed production service.

## 8. Proposed architecture

The architecture and component trust boundaries are described in [Final Architecture](final_architecture.md). In brief, configured public feeds pass through validation and RSS normalization, optional same-host article extraction and identity validation, language detection, and SQLite storage. Separate modules then provide keyword-based threat classification, evidence-based severity triage, pairwise correlation candidates, and extractive summaries. Streamlit presents those results with provenance and review states. Offline evaluation scripts read separate JSONL research datasets; empty datasets result in unavailable metrics.

## 9. Implementation and technologies

The application uses Python, Streamlit, SQLite, Pandas, Plotly, Feedparser, Requests, BeautifulSoup, and Pytest. The implementation is CPU-friendly and has no required GPU/CUDA model or paid API. Language detection combines Ethiopic Unicode script evidence with limited English/Afaan Oromo lexical cues. Threat categorization and severity use deterministic rules. Correlation uses normalized identifiers/entities and supporting lexical/date signals, with precomputed per-article features. Summarization selects source sentences and does not translate or generate paraphrases.

The system’s analysis outputs are preliminary machine-produced or rule-produced results. A source statement is not independently verified merely because it was collected, categorized, or summarized.

## 10. System evaluation methodology

The evaluation package contains separate scripts and templates for language, threat classification, severity, correlation, extraction, and summaries. Human-reviewed examples require provenance and review metadata; fluent reviewers are needed for credible Amharic and Afaan Oromo summary/language judgments. Synthetic test inputs remain under `tests/`; the language sanity dataset is explicitly marked synthetic. Correlation relevance is not equivalent to identical-incident identity: the evaluator’s labels distinguish same incident, related-but-different, unrelated, and insufficient evidence. Severity retains Unknown as an outcome. Extraction checks title, canonical URL, identity, relevant body content, and source attribution. Summary evaluation concerns the exact source and method version.

Reproduction commands and annotation controls are in [Reproducibility](reproducibility.md), [Stage 9 methodology](stage9_evaluation_methodology.md), and [annotation guidelines](stage9_annotation_guidelines.md).

## 11. Results

### 11.1 Software and data snapshot

On 2026-11-25, the configured SQLite database was checked read-only: 46 article records (43 LIVE and 3 DEMO), 46 classification runs, 46 severity assessments, six correlation pairs and six correlation assessments, and seven summary records. SQLite integrity returned `ok`; foreign-key checking returned no violations. These row counts indicate stored workflow records, not validated intelligence or human-reviewed analytical correctness. The database was not modified for this final delivery.

### 11.2 Research metrics

The language evaluation contains 15 researcher-authored synthetic examples, three for each of `en`, `am`, `om`, `und`, and `mul`. The recorded synthetic sanity-check accuracy is 100% on those 15 examples. The sample is deliberately small and synthetic; it must not be reported as real-world or language-specific field accuracy. Independently reviewed real-world language metrics are unavailable. The threat, severity, correlation, extraction, and summary research datasets contain no eligible independently reviewed examples; their effectiveness metrics are unavailable. No claim of multilingual parity, classifier quality, correlation precision, severity agreement, extraction quality, or summary usefulness is supported.

### 11.3 Correlation performance

The Stage 10 local benchmark used deterministic synthetic in-memory inputs, three repetitions, and identical candidate results before and after feature precomputation. Median elapsed time changed from 0.217869 to 0.031005 seconds for 40 reports (780 pairs; 7.03×), 1.420898 to 0.171169 seconds for 100 reports (4,950 pairs; 8.30×), and 13.038624 to 1.555743 seconds for 300 reports (44,850 pairs; 8.38×). A final one-sided rerun of the optimized candidate generator returned the same candidate counts (119, 807, 7,457) and medians of 0.048088, 0.172067, and 1.587320 seconds respectively. Because that rerun did not retime the pre-change version, it is a repeatability observation, not a new speedup estimate; runtime varies across runs. These measurements cover candidate generation only; pairwise comparisons remain quadratic. They do not measure memory/RSS, database persistence, dashboard latency, large-scale throughput, or analytical validity. See [Stage 10 integration report](stage10_integration_report.md).

### 11.4 RSS availability observation

The dated 2026-11-25 system validation recorded all four configured RSS endpoints returning parseable responses and 40 normalized entries with persistence disabled. This establishes only that one collection run succeeded at that time. Stage 10 integration testing used mocks and made no live feed request; current connectivity is therefore not guaranteed.

## 12. Discussion

The implementation demonstrates that collection, provenance, uncertainty states, histories, evidence presentation, and offline evaluation can be integrated in a lightweight local application. The result is most useful as a research prototype and review aid. Rule-based methods make decisions inspectable, but their lexical coverage, confidence calibration, and multilingual performance are unestablished. Correlation candidates can prioritize analyst attention but may miss paraphrased reports and must not be mistaken for incident adjudication. Extractive summaries preserve source sentences but may omit context and do not provide translation.

The principal research outcome is therefore the integrated artifact and its explicit evaluation boundary, not a claim that an AI system has achieved high trilingual accuracy. Independent, permissioned, language-balanced data and reviewer studies are necessary to answer RQ2 and assess RQ3 empirically.

## 13. Limitations

1. No independently reviewed real-world evaluation examples are available in the research datasets.
2. Fifteen synthetic language examples support only a narrow sanity check; they do not represent publisher language, code-switching, dialect, transliteration, or adversarial text.
3. Afaan Oromo and English share Latin script; the small lexical detector can confuse them. Amharic script evidence is not a full language model.
4. Threat classification is a keyword baseline, not a trained model; category confidence is heuristic and uncalibrated.
5. Severity is evidence triage, not risk quantification. No live CVE/KEV enrichment is performed by the dashboard.
6. Correlation is pairwise and lexical/entity anchored; it neither proves same incident nor supports actor attribution.
7. Summaries are extractive, source-language only, and not rated by human reviewers.
8. Feed availability is time-dependent; the live check is dated. General live article extraction quality was not exhaustively evaluated.
9. The application lacks authentication, authorization, public deployment hardening, and multi-user controls. DNS resolution/private-address validation and response-size caps remain open. A dependency vulnerability scan and deployment security audit have not been completed.
10. The performance benchmark is a microbenchmark with no memory or end-to-end service measurements.

## 14. Threats to validity

**Construct validity:** Heuristic outputs may not correspond to analyst judgments of language, severity, threat category, or incident relationship. “Related” and “same incident” are distinct constructs.

**Internal validity:** Rule and threshold choices were engineered and tested against limited fixtures; benchmark timing can vary by hardware and process conditions. No controlled model comparison was conducted.

**External validity:** A convenience set of four configured English-language publishers and synthetic examples cannot represent multilingual CTI sources, language variation, or operational deployments.

**Conclusion validity:** Small/empty reviewed samples prevent statistically meaningful effectiveness conclusions. No confidence intervals or inter-rater agreement can be calculated without reviewed data.

**Temporal validity:** RSS entries and publisher pages change. The dated feed check should not be interpreted as present or future uptime.

## 15. Ethical considerations

Collection is restricted to operator-configured public sources and remains subject to publisher terms, robots rules, rate limits, copyright, retention policies, and applicable law. The system retains URLs and source attribution. Reports are not independently verified by collection. Human review is required before treating labels, severity, or relationships as validated intelligence. No unauthorized access, exploit execution, or offensive operation is implemented. Researchers should minimize personal data, obtain permission where required, document provenance, and avoid publishing unsupported attribution or sensitive details.

## 16. Conclusion

ETHIO-CYBER INTEL provides an integrated local prototype for gathering, organizing, and reviewing public cybersecurity reports across English, Amharic, and Afaan Oromo. It makes source provenance, uncertainty, preliminary analysis, and human review visible, and provides reproducible evaluation tooling. Existing evidence supports software operation, regression coverage, database integrity, and a bounded synthetic correlation speed comparison; it does not support real-world analytic accuracy or trilingual parity. Academic conclusions about effectiveness require independently reviewed, permissioned, representative data and fluent human evaluation.

## 17. Future work

Before operational or empirical claims, priorities are: (1) create a permissioned, stratified dataset with fluent independent reviewers and adjudication; (2) evaluate language-specific false positives and negatives; (3) compare simple baselines on fixed splits; (4) measure summary faithfulness and readability; (5) validate extraction against reviewed publisher pages; (6) review feed terms and coverage; (7) add DNS/private-address controls and response-size limits; (8) perform dependency and deployment security audits; and (9) evaluate user workload and human-review utility. Any multilingual model or translation feature should be separately selected, licensed, resource-tested, and evaluated before integration.

## References

1. FIRST Special Interest Group. (2019). *Common Vulnerability Scoring System Version 3.1: Specification Document*. [FIRST](https://www.first.org/cvss/v3.1/specification-document).
2. Johnson, C., Badger, M., Waltermire, D., Snyder, J., & Skorupka, C. (2016). *Guide to Cyber Threat Information Sharing* (NIST SP 800-150). National Institute of Standards and Technology. [https://doi.org/10.6028/NIST.SP.800-150](https://doi.org/10.6028/NIST.SP.800-150).
3. Arazzi, Marco, Dincy R. Arikkat, Serena Nicolazzo, Antonino Nocera, Rafidha Rehman K.A., Vinod P., and Mauro Conti. (2025). NLP-based techniques for Cyber Threat Intelligence. *Computer Science Review, 58*, Article 100765. [https://doi.org/10.1016/j.cosrev.2025.100765](https://doi.org/10.1016/j.cosrev.2025.100765).
4. OASIS Cyber Threat Intelligence Technical Committee. (2021). *STIX Version 2.1, OASIS Standard*. [OASIS](https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html).
5. Tonja, A. L., Belay, T. D., Azime, I. A., Ayele, A. A., Mehamed, M. A., Kolesnikova, O., & Yimam, S. M. (2023). Natural language processing in Ethiopian languages: Current state, challenges, and opportunities. In *Proceedings of the Fourth Workshop on Resources for African Indigenous Languages (RAIL 2023)* (pp. 126–139). Association for Computational Linguistics. [https://doi.org/10.18653/v1/2023.rail-1.14](https://doi.org/10.18653/v1/2023.rail-1.14).
