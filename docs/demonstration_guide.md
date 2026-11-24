# ETHIO-CYBER INTEL Demonstration Guide

This guide covers the current local dashboard without inventing intelligence. Reserve 8–12 minutes. The application uses SQLite at the configured path; this walkthrough does not require resetting or deleting that database.

## 1. Prepare and launch

From the repository root:

```bash
source .venv/bin/activate
python -m pip check
streamlit run app.py
```

Open the local URL printed by Streamlit. Use a read-only copy or a separate temporary database for rehearsal if you want to avoid changing operational records. Do not remove or recreate the existing database.

## 2. Identify record provenance

At the top of the dashboard review source status and processing counts. Locate the visibly separated **LIVE** intelligence and **DEMO DATA** sections. LIVE means collected from a publisher feed and is not independent confirmation. DEMO examples are synthetic and must not be described as real incidents. Use the source, original URL, title, and publication date to establish provenance.

## 3. Refresh configured RSS feeds (optional)

When network access and source permissions allow, click **Refresh Intelligence**. The dashboard attempts configured feeds independently and shows source status, successes, additions, and duplicate/error counts. A failed source should not prevent other feed results. Review feed/source status after refresh; do not say an endpoint is reachable unless this run shows success.

Do not repeatedly refresh during a defense. Respect configured delays, publisher terms, robots rules, and rate limits. The four feeds were successfully parsed in a dated 2026-11-25 validation, but that observation does not establish current connectivity.

### Offline fallback

If DNS or network access is unavailable, skip refresh. Use existing DEMO DATA to demonstrate dashboard layout and processing-state interpretation, while explicitly identifying those examples as synthetic. Do not create fake LIVE records. For collection failure handling, describe the mocked automated integration tests; do not represent those fixtures as feed observations.

## 4. Inspect a report and extraction status

Choose a row in the LIVE section (or clearly labeled DEMO section) and inspect title, publisher/source, original URL, publication date, description, and available body text. Explain whether text came from RSS or passed publisher-page identity checks. If extraction was ambiguous, blocked, or unavailable, the system retains RSS metadata and may show no validated full body. A returned string alone is not evidence that it belongs to the selected article.

Open the original publisher URL only when network access and the publisher terms permit. Compare the page title with the stored title when illustrating identity validation.

## 5. Review language detection

Read the language filter/distribution and each report’s language code, detection method, and confidence. The codes are `en`, `am`, `om`, `und`, and `mul`. Explain that confidence is heuristic, not a probability. `und` may mean insufficient evidence or unsupported text; do not force a label. Afaan Oromo shares Latin script with English and is detected using limited lexical cues, so independent review is particularly important.

If appropriate, click **Detect language for legacy reports**. It only processes eligible untouched LIVE rows and uses title plus RSS description; it does not fabricate a language. It can leave a report `und`.

## 6. Run threat classification

Click **Classify pending reports** if there are unclassified eligible reports. Review the resulting category, supporting matched terms, method, confidence, and status. Explain the categories as preliminary keyword/phrase matches. `unknown` is a deliberate no-supported-evidence outcome, not a claim that an article is safe. The automated labels are not human-verified.

## 7. Run severity assessment

Click **Assess pending severity** when assessment is appropriate. Inspect the severity level, rationale, evidence items, and evidence completeness. Emphasize that severity and threat category are different fields. A CVE identifier or ransomware mention alone does not establish critical impact. Missing or conflicting evidence can remain `Unknown`. Article statements remain reported claims; the current dashboard does not perform external CVE/KEV verification.

## 8. Review correlation candidates

Click **Correlate collected reports**. Inspect each candidate’s language pair, report titles, shared identifiers/entities/terms, score, and supporting explanation. The score is heuristic similarity, not probability. A shared CVE or keyword is not definitive proof of a shared incident. Use **Confirm related reports** or **Reject relationship** only when the reviewer has examined the evidence; those controls record reviewer decisions but do not establish source claims or actor attribution.

## 9. Inspect an extractive summary

In **Evidence-grounded article summary**, select the report and choose the original detected language when supported. Click **Generate extractive summary**. Compare the selected sentences with the source excerpts and article metadata. State clearly that the output is copied source text selected by a lightweight method, not a translation or generated paraphrase. An unsupported requested language, unknown language, or insufficient source content should produce a status rather than invented text. Review the summary history and duplicate/human-review handling if available.

## 10. Explain unknown and unavailable states

- **Not assessed / not classified:** no current result exists; it is not a negative finding.
- **Unknown:** the module ran but available evidence did not support a specific result.
- **Extraction rejected/unavailable:** content identity or access checks failed; RSS provenance remains.
- **Candidate:** possible relationship pending review; not a confirmed incident.
- **Unsupported translation:** cross-language summary output is not implemented.
- **Feed unavailable:** a current network/source failure, not evidence that no reports exist.

## 11. Close the demonstration

Summarize that the dashboard adds provenance, uncertainty, histories, evidence, and review workflow to feed aggregation. The research datasets have no independently reviewed real-world examples outside the synthetic language sanity set. Do not present synthetic metrics as operational accuracy or claim production readiness.

See the [Security and Ethics Review](security_and_ethics_review.md), [Final Architecture](final_architecture.md), and [Reproducibility Guide](reproducibility.md) for supporting detail.
