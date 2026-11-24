"""Streamlit dashboard for ETHIO-CYBER INTEL."""

from __future__ import annotations

import logging
import math
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from ethio_cyber_intel.article_extractor import ArticleExtractor  # noqa: E402
from ethio_cyber_intel.config import seed_demo_enabled  # noqa: E402
from ethio_cyber_intel.dashboard_data import (  # noqa: E402
    load_article_detail, load_articles, load_current_classifications,
    load_current_correlations, load_current_severity_assessments, load_current_summaries, load_summary_history,
)
from ethio_cyber_intel.database import (  # noqa: E402
    assess_pending_articles, classify_pending_articles, correlate_pending_articles,
    detect_legacy_article_languages, initialize_database, insert_live_articles,
    save_manual_correlation, save_summary_result,
)
from ethio_cyber_intel.language_detection import MIN_CONFIDENCE  # noqa: E402
from ethio_cyber_intel.rss_collector import collect_all  # noqa: E402
from ethio_cyber_intel.rss_sources import load_sources  # noqa: E402
from ethio_cyber_intel.summarization import (  # noqa: E402
    SUPPORTED_SUMMARY_LANGUAGES, summarize_article,
)
from ethio_cyber_intel.url_safety import is_public_web_url  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

LANGUAGE_NAMES = {
    "en": "English", "am": "Amharic", "om": "Afaan Oromo",
    "und": "Unknown", "mul": "Mixed language",
}
THREAT_NAMES = {
    "phishing": "Phishing", "malware": "Malware", "ransomware": "Ransomware",
    "vulnerability": "Vulnerability", "data_breach": "Data breach", "ddos": "DDoS",
    "cyber_espionage": "Cyber espionage", "credential_theft": "Credential theft",
    "other": "Other cyber threat", "unknown": "Unknown",
}
SEVERITY_LEVELS = ("Critical", "High", "Medium", "Low", "Informational", "Unknown")


def _attach_classifications(articles: pd.DataFrame, labels: pd.DataFrame) -> pd.DataFrame:
    """Attach labels from the latest saved run to display rows."""
    result = articles.copy()
    if result.empty:
        return result
    result["classification_categories"] = "Unclassified"
    result["classification_status"] = "unclassified"
    result["classification_method"] = "Not classified"
    result["classification_evidence"] = ""
    result["classification_confidence"] = "Not available"
    if labels.empty:
        return result
    import json
    row_by_id = {int(article_id): index for index, article_id in result["id"].items()}
    for article_id, group in labels.groupby("article_id"):
        idx = row_by_id.get(int(article_id))
        if idx is None:
            continue
        categories = group["category"].tolist()
        result.at[idx, "classification_categories"] = ", ".join(
            THREAT_NAMES.get(category, category) for category in categories
        )
        result.at[idx, "classification_status"] = group.iloc[0]["status"]
        result.at[idx, "classification_method"] = group.iloc[0]["method"]
        evidence, confidence = [], []
        for _, label in group.iterrows():
            try:
                terms = json.loads(label["evidence_json"] or "[]")
            except (TypeError, ValueError):
                terms = []
            if terms:
                evidence.append(f"{THREAT_NAMES.get(label['category'], label['category'])}: {', '.join(terms)}")
            if pd.notna(label["confidence"]):
                confidence.append(f"{THREAT_NAMES.get(label['category'], label['category'])} {label['confidence']:.2f}")
        result.at[idx, "classification_evidence"] = "; ".join(evidence) or "No matching evidence"
        result.at[idx, "classification_confidence"] = "; ".join(confidence) or "Human reviewed"
    return result


def _attach_severities(articles: pd.DataFrame, assessments: pd.DataFrame) -> pd.DataFrame:
    """Attach latest severity decisions and audit details for display only."""
    result = articles.copy()
    if result.empty:
        return result
    result["severity"] = "Unknown"
    result["severity_explanation"] = "No assessment recorded."
    result["severity_evidence"] = ""
    result["severity_method"] = "Not assessed"
    result["severity_status"] = "unassessed"
    result["evidence_completeness"] = "Not assessed"
    if assessments.empty:
        return result
    import json
    row_by_id = {int(article_id): index for index, article_id in result["id"].items()}
    for _, row in assessments.iterrows():
        idx = row_by_id.get(int(row["article_id"]))
        if idx is None:
            continue
        result.at[idx, "severity"] = row["severity"]
        result.at[idx, "severity_explanation"] = row["explanation"]
        result.at[idx, "severity_method"] = row["method"]
        result.at[idx, "severity_status"] = row["status"]
        try:
            evidence = json.loads(row["evidence_json"] or "[]")
            completeness = json.loads(row["evidence_completeness_json"] or "{}")
        except (TypeError, ValueError):
            evidence, completeness = [], {}
        result.at[idx, "severity_evidence"] = "; ".join(
            f"{item.get('type')}: {item.get('value')} [{item.get('evidentiary_status')}; {item.get('source_name')}; {item.get('source_url')}]"
            for item in evidence
        ) or "No severity evidence"
        fields = completeness.get("fields", {})
        missing = [name for name, known in fields.items() if not known]
        result.at[idx, "evidence_completeness"] = (
            f"{completeness.get('known_fields', 0)}/{completeness.get('total_fields', 0)} factors; "
            f"missing: {', '.join(missing) if missing else 'none'}"
        )
    return result


def _attach_summary_statuses(articles: pd.DataFrame, summaries: pd.DataFrame) -> pd.DataFrame:
    result = articles.copy()
    if result.empty:
        return result
    result["summary_status"] = "not_generated"
    result["summary_method"] = "Not generated"
    result["summary_language"] = None
    if summaries.empty:
        return result
    row_by_id = {int(article_id): index for index, article_id in result["id"].items()}
    for _, row in summaries.iterrows():
        idx = row_by_id.get(int(row["article_id"]))
        if idx is None:
            continue
        result.at[idx, "summary_status"] = row["summary_status"]
        result.at[idx, "summary_method"] = row["summary_method"]
        result.at[idx, "summary_language"] = row["summary_language"]
    return result


def _relationship_graph(correlations: pd.DataFrame) -> None:
    """Draw a small deterministic article-pair graph for visual inspection."""
    if correlations.empty:
        return
    pairs = correlations.head(25)
    article_meta = {}
    edges = []
    for _, row in pairs.iterrows():
        left, right = int(row["article_id_a"]), int(row["article_id_b"])
        article_meta[left] = (row["title_a"], row["article_language_a"])
        article_meta[right] = (row["title_b"], row["article_language_b"])
        edges.append((left, right))
    nodes = list(article_meta)
    points = {
        node: (math.cos(2 * math.pi * index / max(1, len(nodes))),
               math.sin(2 * math.pi * index / max(1, len(nodes))))
        for index, node in enumerate(nodes)
    }
    edge_x, edge_y = [], []
    for left, right in edges:
        edge_x.extend([points[left][0], points[right][0], None])
        edge_y.extend([points[left][1], points[right][1], None])
    figure = go.Figure()
    figure.add_trace(go.Scatter(x=edge_x, y=edge_y, mode="lines", line={"width": 1, "color": "#8b98a5"}, hoverinfo="skip"))
    figure.add_trace(go.Scatter(
        x=[points[node][0] for node in nodes], y=[points[node][1] for node in nodes],
        mode="markers+text", text=[str(node) for node in nodes], textposition="top center",
        marker={"size": 18, "color": [{"en": 0, "am": 1, "om": 2}.get(article_meta[node][1], 3) for node in nodes],
                "colorscale": "Viridis", "showscale": False},
        customdata=[[article_meta[node][0], article_meta[node][1]] for node in nodes],
        hovertemplate="Article ID %{text}<br>%{customdata[0]}<br>Language: %{customdata[1]}<extra></extra>",
    ))
    figure.update_layout(showlegend=False, height=360, margin={"l": 10, "r": 10, "t": 10, "b": 10},
                         xaxis={"visible": False}, yaxis={"visible": False})
    st.plotly_chart(figure, use_container_width=True)


def _safe_external_url(value: str) -> bool:
    return is_public_web_url(str(value))


def _render_correlations(correlations: pd.DataFrame, db_path: Path) -> None:
    st.subheader("Related reports: cross-language correlation")
    if correlations.empty:
        cols = st.columns(4)
        for col, label in zip(cols, ("Candidate relationships", "Human confirmed", "Human rejected", "Insufficient evidence")):
            col.metric(label, 0)
        st.info("No candidate or reviewed relationships are stored. Run correlation to compare collected reports.")
        return
    metric_cols = st.columns(4)
    for col, status in zip(metric_cols, ("Candidate", "Human confirmed", "Human rejected", "Insufficient evidence")):
        col.metric(status if status != "Candidate" else "Candidate relationships", int((correlations["status"] == status).sum()))

    pairs = ["All language pairs"] + sorted(correlations["language_pair"].dropna().unique().tolist())
    selected_pair = st.selectbox("Correlation language pair", pairs)
    visible = correlations if selected_pair == "All language pairs" else correlations[correlations["language_pair"] == selected_pair]
    active_relationships = visible[visible["status"] != "Human rejected"]
    graph_col, chart_col = st.columns(2)
    with graph_col:
        st.caption("Relationship graph (node labels are article IDs; edges indicate saved relationships, not confirmed incidents).")
        _relationship_graph(active_relationships)
    with chart_col:
        st.caption("Language distribution among reports in these relationships")
        language_counts = pd.concat([
            active_relationships[["article_id_a", "article_language_a"]].rename(columns={"article_id_a": "article_id", "article_language_a": "language"}),
            active_relationships[["article_id_b", "article_language_b"]].rename(columns={"article_id_b": "article_id", "article_language_b": "language"}),
        ]).drop_duplicates("article_id")["language"].value_counts().rename_axis("Language").reset_index(name="Reports")
        st.plotly_chart(px.bar(language_counts, x="Language", y="Reports", color="Language"), use_container_width=True)

    st.markdown("**Relationship details and human review**")
    import json
    for _, row in visible.iterrows():
        label = f"{row['status']} · {row['language_pair']} · score {row['score']:.2f} · reports {row['article_id_a']} / {row['article_id_b']}"
        with st.expander(label):
            st.text(f"Report A: {row['title_a']} — {row['source_a']} · {row['published_a'] or 'Date unknown'}")
            if _safe_external_url(row["url_a"]):
                st.link_button("Open original report A", row["url_a"])
            else:
                st.text(f"Original URL: {row['url_a']}")
            st.text(f"Report B: {row['title_b']} — {row['source_b']} · {row['published_b'] or 'Date unknown'}")
            if _safe_external_url(row["url_b"]):
                st.link_button("Open original report B", row["url_b"])
            else:
                st.text(f"Original URL: {row['url_b']}")
            st.text(row["explanation"])
            st.text(f"Similarity methods: {', '.join(json.loads(row['similarity_methods_json'])) or 'none'}")
            st.text(f"Shared identifiers: {json.loads(row['matching_identifiers_json']) or 'None'}")
            st.text(f"Shared entities: {json.loads(row['shared_entities_json']) or 'None'}")
            st.text(f"Shared terms: {', '.join(json.loads(row['shared_terms_json'])) or 'None'}")
            with st.expander("Supporting evidence"):
                st.json(json.loads(row["supporting_evidence_json"]))
            if row["reviewer_note"]:
                st.text(f"Reviewer note: {row['reviewer_note']}")
            if row["status"] == "Candidate":
                note = st.text_input("Review note", key=f"correlation_note_{row['pair_id']}")
                confirm_col, reject_col = st.columns(2)
                if confirm_col.button("Confirm related reports", key=f"correlation_confirm_{row['pair_id']}"):
                    save_manual_correlation(int(row["article_id_a"]), int(row["article_id_b"]),
                                            decision="Human confirmed", reviewer_note=note, db_path=db_path)
                    st.rerun()
                if reject_col.button("Reject relationship", key=f"correlation_reject_{row['pair_id']}"):
                    save_manual_correlation(int(row["article_id_a"]), int(row["article_id_b"]),
                                            decision="Human rejected", reviewer_note=note, db_path=db_path)
                    st.rerun()


def _render_summary_workspace(articles: pd.DataFrame, labels: pd.DataFrame, db_path: Path) -> None:
    st.subheader("Evidence-grounded article summary")
    if articles.empty:
        st.info("No stored articles are available to summarize.")
        return
    article_ids = articles["id"].astype(int).tolist()
    selected_id = st.selectbox(
        "Article", article_ids,
        format_func=lambda article_id: (
            f"{article_id} · {articles.loc[articles['id'] == article_id, 'title'].iloc[0]} "
            f"[{('DEMO DATA' if int(articles.loc[articles['id'] == article_id, 'is_demo'].iloc[0]) else 'LIVE')}]"
        ),
        key="summary_article_id",
    )
    selected_row = articles.loc[articles["id"] == selected_id].iloc[0]
    article_language = selected_row["language"]
    default_lang = article_language if article_language in SUPPORTED_SUMMARY_LANGUAGES else "en"
    language = st.selectbox(
        "Requested summary language", SUPPORTED_SUMMARY_LANGUAGES,
        index=SUPPORTED_SUMMARY_LANGUAGES.index(default_lang),
        format_func=lambda code: LANGUAGE_NAMES.get(code, code), key="summary_language",
    )
    st.caption("Original-language extractive summaries retain source sentences. Cross-language translation is not available in this baseline.")
    if int(selected_row["is_demo"]):
        st.warning("DEMO DATA: this source is synthetic and not a real intelligence report.")
    if selected_row.get("content_validation_status") == "legacy_unverified":
        st.warning("Stored full text is legacy and unverified. The summary workspace will use the source title and RSS description instead.")
    if st.button("Generate extractive summary", key="generate_summary"):
        try:
            detail = load_article_detail(int(selected_id), db_path)
            article_label_rows = labels.loc[labels["article_id"] == selected_id] if not labels.empty else pd.DataFrame()
            article_labels = article_label_rows["category"].tolist() if not article_label_rows.empty else []
            detail["threat_categories"] = article_labels
            detail["threat_category_status"] = article_label_rows.iloc[0]["status"] if not article_label_rows.empty else "unclassified"
            result = summarize_article(detail, requested_language=language)
            saved = save_summary_result(int(selected_id), result, db_path)
            st.session_state["summary_generation_message"] = (
                int(selected_id), language, result.status, saved
            )
            if saved.get("saved"):
                st.rerun()
        except Exception as exc:
            logger.exception("Summary generation failed for article %s", selected_id)
            st.error(f"Could not create summary: {exc}")
    message = st.session_state.get("summary_generation_message")
    if message and message[0] == int(selected_id) and message[1] == language:
        _, _, status, saved = message
        if saved.get("saved"):
            st.success(f"Summary status: {status.replace('_', ' ')}")
        elif saved.get("reason") == "duplicate_summary":
            st.info("This source text already has a summary with the same method and version.")
        elif saved.get("reason") == "human_review_preserved":
            st.warning("A human-reviewed summary exists for this article and language; automatic output was not saved.")
        else:
            st.info(f"Summary status: {status.replace('_', ' ')}")
    history = load_summary_history(int(selected_id), db_path)
    if history.empty:
        st.info("No summary history for this article yet.")
        return
    for _, row in history.iterrows():
        label = f"{row['summary_status']} · {LANGUAGE_NAMES.get(row['summary_language'], row['summary_language'])} · {row['created_at']}"
        with st.expander(label, expanded=True):
            st.caption(f"Summary type: {row['summary_kind']} · Method: {row['summary_method']} v{row['method_version']}")
            if row["summary_text"]:
                st.write(row["summary_text"])
            else:
                st.info("No summary text was produced for this status.")
            import json
            source_metadata = json.loads(row["source_metadata_json"] or "{}")
            source_language = source_metadata.get("source_language", "und")
            if row["summary_kind"] == "original_language_extractive":
                st.caption(f"Original-language extractive summary ({LANGUAGE_NAMES.get(source_language, source_language)}); this is not a translation.")
            elif row["summary_kind"] == "translation_unavailable":
                st.caption(f"Requested {LANGUAGE_NAMES.get(row['summary_language'], row['summary_language'])}; translation unavailable from {LANGUAGE_NAMES.get(source_language, source_language)}.")
            st.markdown("**Key intelligence (reported evidence)**")
            key_info = json.loads(row["key_intelligence_json"] or "{}")
            st.json(key_info)
            st.markdown("**Supporting source excerpts**")
            excerpts = json.loads(row["supporting_evidence_json"] or "[]")
            if excerpts:
                st.json(excerpts)
            else:
                st.info("No summary excerpts were selected.")
            st.markdown("**Original source metadata**")
            st.json(source_metadata)
            with st.expander("Exact source text used"):
                st.text(row["source_text_used"])
def _refresh(db_path: Path) -> None:
    sources = load_sources(enabled_only=True)
    if not sources:
        st.session_state["source_results"] = []
        st.error("No enabled RSS sources are configured. Check config/rss_sources.json.")
        return
    st.session_state["source_results"] = []
    with st.spinner(f"Checking {len(sources)} RSS sources…"):
        extractor = ArticleExtractor()
        try:
            results = collect_all(sources, extractor=extractor)
            # Keep per-source outcomes visible even when later persistence or
            # analysis work fails.
            st.session_state["source_results"] = results
            all_articles = [article for result in results for article in result["articles"]]
            stats = insert_live_articles(all_articles, db_path)
            classification_stats = classify_pending_articles(db_path)
            severity_stats = assess_pending_articles(db_path)
            st.session_state["source_results"] = results
            st.session_state["last_collection_stats"] = stats
            successful_sources = sum(result["status"] in {"ok", "ok_with_warning"} for result in results)
            if successful_sources:
                st.success(
                    f"Refresh finished: {successful_sources}/{len(results)} sources returned feeds; "
                    f"added {stats['inserted']} LIVE articles; skipped {stats['duplicate_url']} duplicate URLs and "
                    f"{stats['duplicate_content']} duplicate-content records."
                )
            else:
                st.warning("No RSS source returned a usable feed. Existing reports were left intact.")
            st.info(
                f"Preliminary keyword classification: {classification_stats['classified']} labeled, "
                f"{classification_stats['unknown']} unknown. These labels are not human verified."
            )
            st.info(
                f"Preliminary severity assessment: {severity_stats['assessed']} prioritized, "
                f"{severity_stats['unknown']} unknown."
            )
        except Exception:
            logger.exception("RSS refresh failed")
            st.error("Collection or processing did not complete. Check the RSS status table and application logs.")
        finally:
            extractor.close()


def main() -> None:
    st.set_page_config(page_title="ETHIO-CYBER INTEL", page_icon="🛡️", layout="wide")
    st.title("🛡️ ETHIO-CYBER INTEL")
    st.caption("Trilingual cyber threat intelligence research dashboard")

    try:
        db_path = initialize_database(seed_demo=seed_demo_enabled())
        articles = load_articles(db_path)
        labels = load_current_classifications(db_path)
        severity_rows = load_current_severity_assessments(db_path)
        summary_rows = load_current_summaries(db_path)
        correlation_rows = load_current_correlations(db_path)
    except Exception as exc:
        logger.exception("Dashboard could not load the local database")
        st.error(f"The local database could not be loaded: {exc}")
        st.stop()

    sources = load_sources()
    if "source_results" not in st.session_state:
        st.session_state["source_results"] = []
    if st.button("🔄 Refresh Intelligence", type="primary"):
        _refresh(db_path)
        try:
            articles = load_articles(db_path)
            labels = load_current_classifications(db_path)
            severity_rows = load_current_severity_assessments(db_path)
            summary_rows = load_current_summaries(db_path)
        except Exception as exc:
            logger.exception("Could not reload reports after collection")
            st.error(f"Reports were collected but could not be reloaded: {exc}")

    if st.button("🔤 Detect language for legacy reports"):
        try:
            with st.spinner("Detecting language from each report's title and RSS description…"):
                counts = detect_legacy_article_languages(db_path)
            st.success(
                f"Language detection checked {counts['scanned']} untouched legacy LIVE reports; "
                f"updated {counts['updated']}, still unknown {counts['unknown']}. "
                "Human-reviewed labels were preserved."
            )
            articles = load_articles(db_path)
        except Exception as exc:
            logger.exception("Legacy language detection failed")
            st.error(f"Could not detect language for legacy reports: {exc}")

    if st.button("🏷️ Classify pending reports"):
        try:
            with st.spinner("Applying transparent keyword rules…"):
                counts = classify_pending_articles(db_path)
            st.success(f"Processed pending reports: {counts['classified']} labeled, {counts['unknown']} unknown.")
            articles = load_articles(db_path)
            labels = load_current_classifications(db_path)
        except Exception as exc:
            logger.exception("Classification failed")
            st.error(f"Could not classify pending reports: {exc}")

    if st.button("⚖️ Assess pending severity"):
        try:
            with st.spinner("Assessing available evidence conservatively…"):
                counts = assess_pending_articles(db_path)
            st.success(f"Assessed {counts['assessed']} reports; {counts['unknown']} remain unknown.")
            articles = load_articles(db_path)
            severity_rows = load_current_severity_assessments(db_path)
        except Exception as exc:
            logger.exception("Severity assessment failed")
            st.error(f"Could not assess report severity: {exc}")

    if st.button("🔗 Correlate collected reports"):
        try:
            with st.spinner("Comparing recent LIVE reports using lightweight signals…"):
                counts = correlate_pending_articles(db_path)
            st.success(
                f"Compared {counts['compared']} report pairs; found {counts['candidates']} candidates, "
                f"saved {counts['saved']} new relationships."
            )
            correlation_rows = load_current_correlations(db_path)
        except Exception as exc:
            logger.exception("Cross-language correlation failed")
            st.error(f"Could not correlate reports: {exc}")

    articles = _attach_classifications(articles, labels)
    articles = _attach_severities(articles, severity_rows)
    articles = _attach_summary_statuses(articles, summary_rows)

    if st.session_state.get("source_results") is not None:
        rows = []
        statuses = {item["source"]: item for item in st.session_state["source_results"]}
        for source in sources:
            result = statuses.get(source.name)
            rows.append({
                "Source": source.name,
                "Status": result["status"] if result else ("Disabled" if not source.enabled else "Not checked this session"),
                "Items parsed": result["entries_seen"] if result else 0,
                "Message": result["message"] if result else source.verification_status,
                "Feed URL": source.url,
            })
        st.subheader("RSS source status")
        if rows:
            st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)

    if not articles.empty and articles["is_demo"].astype(bool).any():
        st.warning("DEMO DATA is synthetic. LIVE INTELLIGENCE consists of collected, source-attributed reports and is not independently verified.")

    live_count = int((articles["is_demo"] == 0).sum()) if not articles.empty else 0
    demo_count = int((articles["is_demo"] == 1).sum()) if not articles.empty else 0
    total, live_metric, demo_metric = st.columns(3)
    total.metric("Total reports", len(articles))
    live_metric.metric("Live collected", live_count)
    demo_metric.metric("Demo records", demo_count)
    st.subheader("Processing status")
    st.caption("Counts include both record types; synthetic DEMO DATA remains visibly separated from LIVE reports below.")
    if articles.empty:
        st.info("No reports are available for processing.")
    else:
        language_pending = int((
            (articles["language_method"].isna() | (articles["language_method"] == "not_detected"))
            & (articles["language_reviewed"] == 0)
        ).sum())
        language_unknown = int((
            (articles["language"] == "und") & articles["language_method"].notna()
            & (articles["language_method"] != "not_detected")
        ).sum())
        language_reviewed = int((articles["language_reviewed"] == 1).sum())
        status_cols = st.columns(3)
        status_cols[0].metric("Language not assessed", language_pending)
        status_cols[1].metric("Language assessed as unknown", language_unknown)
        status_cols[2].metric("Human-reviewed language labels", language_reviewed)

        legacy_content = int((articles["content_validation_status"] == "legacy_unverified").sum())
        st.metric("Legacy article text not validated", legacy_content)

        status_cols = st.columns(4)
        status_cols[0].metric("Automated classified", int((articles["classification_status"] == "classified").sum()))
        status_cols[1].metric("Human-reviewed classifications", int((articles["classification_status"] == "human_reviewed").sum()))
        status_cols[2].metric("Unknown classification", int((
            (articles["classification_status"] == "unknown")
            | (articles["classification_categories"] == THREAT_NAMES["unknown"])
        ).sum()))
        status_cols[3].metric("Not classified", int((articles["classification_status"] == "unclassified").sum()))

        severity_assessed = articles["severity_status"] != "unassessed"
        status_cols = st.columns(3)
        status_cols[0].metric("Severity assessed", int(severity_assessed.sum()))
        status_cols[1].metric("Severity not assessed", int((~severity_assessed).sum()))
        status_cols[2].metric("Assessed severity unknown", int(((articles["severity"] == "Unknown") & severity_assessed).sum()))

        summaries_created = articles["summary_status"].isin(["original_extractive", "human_reviewed"])
        summary_cols = st.columns(3)
        summary_cols[0].metric("Summary created", int(summaries_created.sum()))
        summary_cols[1].metric("Summary unavailable", int((~summaries_created & (articles["summary_status"] != "not_generated")).sum()))
        summary_cols[2].metric("Summary not generated", int((articles["summary_status"] == "not_generated").sum()))

    _render_correlations(correlation_rows, db_path)

    language_metrics = st.columns(5)
    for column, code in zip(language_metrics, ("en", "am", "om", "und", "mul")):
        count = int((articles["language"] == code).sum()) if not articles.empty else 0
        column.metric(LANGUAGE_NAMES[code], count)

    st.sidebar.header("Filters")
    def confidence_display(row):
        confidence = row["language_confidence"]
        if pd.isna(confidence):
            return "Not assessed"
        if confidence < MIN_CONFIDENCE and not row["language_reviewed"]:
            return f"Uncertain ({confidence:.2f})"
        return f"{confidence:.2f}"

    articles = articles.copy()
    if not articles.empty:
        articles["confidence_display"] = articles.apply(confidence_display, axis=1)
        articles["method_display"] = articles["language_method"].fillna("Not recorded")
    if not articles.empty:
        all_sources = sorted(articles["source"].dropna().unique().tolist())
        selected_sources = st.sidebar.multiselect("Source", all_sources, default=all_sources)
        source_values = sorted(articles["is_demo"].map({1: "DEMO DATA", 0: "LIVE"}).unique().tolist())
        record_types = st.sidebar.multiselect("Record type", source_values, default=source_values)
        language_values = sorted(articles["language"].dropna().unique().tolist())
        languages = st.sidebar.multiselect(
            "Language", language_values, default=language_values,
            format_func=lambda code: LANGUAGE_NAMES.get(code, code),
        )
        threat_values = sorted({category for value in articles["classification_categories"]
                                for category in value.split(", ")})
        selected_threats = st.sidebar.multiselect("Threat category", threat_values, default=threat_values)
        severity_values = [level for level in SEVERITY_LEVELS if level in set(articles["severity"])]
        selected_severities = st.sidebar.multiselect("Severity", severity_values, default=severity_values)
        filtered = articles[
            articles["source"].isin(selected_sources)
            & articles["is_demo"].map({1: "DEMO DATA", 0: "LIVE"}).isin(record_types)
            & articles["language"].isin(languages)
            & articles["classification_categories"].apply(
                lambda value: any(item in selected_threats for item in value.split(", "))
            )
            & articles["severity"].isin(selected_severities)
        ].copy()
        uncertain = filtered[
            (filtered["language"] == "und")
            | ((filtered["language_confidence"].fillna(0) < MIN_CONFIDENCE)
               & (filtered["language_reviewed"] == 0))
        ]
        if not uncertain.empty:
            st.info(f"{len(uncertain)} report(s) have unknown or low-confidence automatic language detection.")
        date_values = pd.to_datetime(filtered["published_at"], errors="coerce").dropna()
        if not date_values.empty:
            min_date = date_values.min().date()
            max_date = date_values.max().date()
            date_range = st.sidebar.date_input(
                "Publication date", value=(min_date, max_date), min_value=min_date, max_value=max_date
            )
            if isinstance(date_range, tuple) and len(date_range) == 2:
                published = pd.to_datetime(filtered["published_at"], errors="coerce").dt.date
                filtered = filtered[published.between(date_range[0], date_range[1]) | published.isna()]
    else:
        filtered = articles
        st.sidebar.info("No reports stored yet.")

    left, right = st.columns(2)
    with left:
        st.subheader("Reports by language")
        if filtered.empty:
            st.info("No reports match these filters.")
        else:
            language_counts = filtered["language"].map(LANGUAGE_NAMES).value_counts().rename_axis("Language").reset_index(name="Reports")
            st.plotly_chart(px.bar(language_counts, x="Language", y="Reports", color="Language"), use_container_width=True)
    with right:
        st.subheader("Reports by source")
        if filtered.empty:
            st.info("No report data to chart.")
        else:
            source_counts = filtered["source"].value_counts().rename_axis("Source").reset_index(name="Reports")
            st.plotly_chart(px.bar(source_counts, x="Source", y="Reports", color="Source"), use_container_width=True)

    threat_left, threat_right = st.columns(2)
    with threat_left:
        st.subheader("Threat category distribution")
        categories = [
            {"Category": category, "Report": int(row["id"])}
            for _, row in filtered.iterrows()
            if row["classification_categories"] != "Unclassified"
            for category in row["classification_categories"].split(", ")
        ] if not filtered.empty else []
        if categories:
            counts = pd.DataFrame(categories).groupby("Category").size().reset_index(name="Reports")
            st.plotly_chart(px.bar(counts, x="Category", y="Reports", color="Category"), use_container_width=True)
        else:
            st.info("No classified reports yet. Use Classify pending reports.")
    with threat_right:
        st.subheader("Language versus threat category")
        comparison = [
            {"Language": LANGUAGE_NAMES.get(row["language"], row["language"]), "Category": category}
            for _, row in filtered.iterrows()
            if row["classification_categories"] != "Unclassified"
            for category in row["classification_categories"].split(", ")
        ] if not filtered.empty else []
        if comparison:
            counts = pd.DataFrame(comparison).groupby(["Language", "Category"]).size().reset_index(name="Reports")
            st.plotly_chart(px.bar(counts, x="Language", y="Reports", color="Category", barmode="stack"), use_container_width=True)
        else:
            st.info("No classified reports available for comparison.")

    severity_left, severity_right = st.columns(2)
    with severity_left:
        st.subheader("Severity distribution")
        if filtered.empty:
            st.info("No reports to chart.")
        else:
            severity_counts = filtered["severity"].value_counts().reindex(SEVERITY_LEVELS, fill_value=0)
            severity_plot = severity_counts.rename_axis("Severity").reset_index(name="Reports")
            st.plotly_chart(px.bar(severity_plot, x="Severity", y="Reports", color="Severity"), use_container_width=True)
    with severity_right:
        st.subheader("Severity by language")
        if filtered.empty:
            st.info("No reports to compare.")
        else:
            severity_language = filtered.assign(
                Language=filtered["language"].map(LANGUAGE_NAMES)
            ).groupby(["Language", "severity"]).size().reset_index(name="Reports")
            st.plotly_chart(px.bar(severity_language, x="Language", y="Reports", color="severity", barmode="stack"), use_container_width=True)

    st.subheader("Severity by threat category")
    severity_category_rows = [
        {"Severity": row["severity"], "Threat category": category}
        for _, row in filtered.iterrows()
        if row["classification_categories"] != "Unclassified"
        for category in row["classification_categories"].split(", ")
    ] if not filtered.empty else []
    if severity_category_rows:
        grouped = pd.DataFrame(severity_category_rows).groupby(["Threat category", "Severity"]).size().reset_index(name="Reports")
        st.plotly_chart(px.bar(grouped, x="Threat category", y="Reports", color="Severity", barmode="stack"), use_container_width=True)
    else:
        st.info("No classified reports available for severity comparison.")

    st.subheader("Critical and High priority reports")
    priority = filtered[filtered["severity"].isin(["Critical", "High"])] if not filtered.empty else filtered
    if priority.empty:
        st.info("No reports currently meet the Critical or High evidence rules.")
    else:
        st.dataframe(priority[["title", "source", "published_at", "severity", "severity_status", "severity_explanation", "evidence_completeness", "url"]].rename(columns={
            "title": "Title", "source": "Source", "published_at": "Published", "severity": "Severity",
            "severity_status": "Assessment status", "severity_explanation": "Assessment explanation",
            "evidence_completeness": "Evidence completeness", "url": "Original URL",
        }), use_container_width=True, hide_index=True)

    st.subheader("Latest collected articles")
    live = filtered[filtered["is_demo"] == 0].sort_values("fetched_at", ascending=False) if not filtered.empty else filtered
    if live.empty:
        st.info("No live articles are available for the selected filters. Use Refresh Intelligence to check configured sources.")
    else:
        live_display = live.copy()
        live_display["language"] = live_display["language"].map(LANGUAGE_NAMES)
        live_display = live_display.rename(columns={
            "title": "Title", "source": "Source", "published_at": "Published",
            "language": "Language", "report_status": "Report status", "url": "Original URL",
            "content_validation_status": "Article text status",
            "fetched_at": "Collected at", "summary": "Description",
            "confidence_display": "Confidence", "method_display": "Detection method",
            "classification_categories": "Threat categories", "classification_confidence": "Category confidence (heuristic)",
            "classification_evidence": "Supporting evidence", "classification_method": "Classification method",
            "classification_status": "Classification status",
            "severity": "Severity", "severity_status": "Severity assessment status",
            "severity_explanation": "Severity explanation", "severity_evidence": "Severity supporting evidence",
            "severity_method": "Severity method", "evidence_completeness": "Evidence completeness",
            "summary_status": "Summary status",
        })
        st.dataframe(live_display[["Title", "Source", "Published", "Collected at", "Language", "Confidence", "Detection method", "Article text status", "Threat categories", "Category confidence (heuristic)", "Supporting evidence", "Classification method", "Classification status", "Severity", "Severity assessment status", "Severity explanation", "Severity supporting evidence", "Severity method", "Evidence completeness", "Summary status", "Report status", "Description", "Original URL"]], use_container_width=True, hide_index=True)

    demo = filtered[filtered["is_demo"] == 1] if not filtered.empty else filtered
    if not demo.empty:
        st.subheader("DEMO DATA")
        demo_display = demo.rename(columns={
            "title": "Title", "source": "Source", "published_at": "Published",
            "language": "Language", "url": "Original URL",
            "confidence_display": "Confidence", "method_display": "Detection method",
            "classification_categories": "Threat categories", "classification_confidence": "Category confidence (heuristic)",
            "classification_evidence": "Supporting evidence", "classification_method": "Classification method",
            "classification_status": "Classification status",
            "severity": "Severity", "severity_status": "Severity assessment status",
            "severity_explanation": "Severity explanation", "severity_evidence": "Severity supporting evidence",
            "severity_method": "Severity method", "evidence_completeness": "Evidence completeness",
            "summary_status": "Summary status",
        })
        demo_display["Language"] = demo_display["Language"].map(LANGUAGE_NAMES)
        st.dataframe(demo_display[["Title", "Source", "Published", "Language", "Confidence", "Detection method", "Threat categories", "Category confidence (heuristic)", "Supporting evidence", "Classification method", "Classification status", "Severity", "Severity assessment status", "Severity explanation", "Severity supporting evidence", "Severity method", "Evidence completeness", "Summary status", "Original URL"]], use_container_width=True, hide_index=True)

    _render_summary_workspace(articles, labels, db_path)

    st.caption("Collected reports are unverified source material. Threat categories, severity, correlation candidates, and summaries are separate analytical outputs; source claims are not thereby verified.")


if __name__ == "__main__":
    main()
