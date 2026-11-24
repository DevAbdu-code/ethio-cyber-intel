# Stage 9 evaluation results (template)

**Commit:** unavailable until run  
**Python/runtime:** record exact versions  
**Dataset versions and counts:** record synthetic and independently reviewed counts separately  
**Evaluation command:** `python scripts/run_research_evaluation.py`

Use `Unavailable (n=0)` when a research dataset has no eligible reviewed records. Do not substitute synthetic scores.

| Component | Eligible research N | Metrics/results |
| --- | ---: | --- |
| Language | Unavailable | Accuracy, macro F1, per-label precision/recall/F1/support, 5×5 confusion matrix |
| Threat | Unavailable | Per-category scores, macro/micro F1, subset accuracy, by-language counts; `unknown` abstention separately |
| Severity | Unavailable | Accuracy, per-class scores, macro F1, weighted agreement, Cohen kappa, ordinal weighted kappa, 6×6 matrix |
| Correlation | Unavailable | Precision/recall/F1/FPR overall and for en-am, en-om, am-om; candidate label supports |
| Extraction | Unavailable | Identity/title/URL/body/fallback/ambiguity/source rates and joint validity |
| Summary | Unavailable | Human ratings, unsupported claim rate, evidence traceability and sentence preservation by language |

**Interpretation:** state sample imbalance, reviewer protocol, confidence limitations, and any unavailable language pairs/classes. Do not infer parity or production readiness from a small convenience sample.
