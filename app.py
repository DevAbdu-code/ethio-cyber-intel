"""Streamlit dashboard for ETHIO-CYBER INTEL."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from ethio_cyber_intel.article_extractor import ArticleExtractor  # noqa: E402
from ethio_cyber_intel.config import seed_demo_enabled  # noqa: E402
from ethio_cyber_intel.dashboard_data import (  # noqa: E402
    load_articles, load_current_classifications, load_current_severity_assessments,
)
from ethio_cyber_intel.database import (  # noqa: E402
    assess_pending_articles, classify_pending_articles, initialize_database, insert_live_articles,
)
from ethio_cyber_intel.language_detection import MIN_CONFIDENCE  # noqa: E402
from ethio_cyber_intel.rss_collector import collect_all  # noqa: E402
from ethio_cyber_intel.rss_sources import load_sources  # noqa: E402

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
    for article_id, group in labels.groupby("article_id"):
        indices = result.index[result["id"] == article_id]
        if len(indices) == 0:
            continue
        idx = indices[0]
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
    for _, row in assessments.iterrows():
        indices = result.index[result["id"] == row["article_id"]]
        if len(indices) == 0:
            continue
        idx = indices[0]
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


def _refresh(db_path: Path) -> None:
    sources = load_sources(enabled_only=True)
    if not sources:
        st.session_state["source_results"] = []
        st.error("No enabled RSS sources are configured. Check config/rss_sources.json.")
        return
    with st.spinner(f"Checking {len(sources)} RSS sources…"):
        try:
            results = collect_all(sources, extractor=ArticleExtractor())
            all_articles = [article for result in results for article in result["articles"]]
            stats = insert_live_articles(all_articles, db_path)
            classification_stats = classify_pending_articles(db_path)
            severity_stats = assess_pending_articles(db_path)
            st.session_state["source_results"] = results
            st.session_state["last_collection_stats"] = stats
            st.success(
                f"Refresh finished: added {stats['inserted']} live articles; "
                f"skipped {stats['duplicate_url']} duplicate URLs and "
                f"{stats['duplicate_content']} duplicate-content records."
            )
            st.info(
                f"Preliminary keyword classification: {classification_stats['classified']} labeled, "
                f"{classification_stats['unknown']} unknown. These labels are not human verified."
            )
            st.info(
                f"Preliminary severity assessment: {severity_stats['assessed']} prioritized, "
                f"{severity_stats['unknown']} unknown."
            )
        except Exception as exc:
            logger.exception("RSS refresh failed")
            st.error(f"Could not save collected reports: {exc}")


def main() -> None:
    st.set_page_config(page_title="ETHIO-CYBER INTEL", page_icon="🛡️", layout="wide")
    st.title("🛡️ ETHIO-CYBER INTEL")
    st.caption("Trilingual cyber threat intelligence research dashboard")

    try:
        db_path = initialize_database(seed_demo=seed_demo_enabled())
        articles = load_articles(db_path)
        labels = load_current_classifications(db_path)
        severity_rows = load_current_severity_assessments(db_path)
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
        except Exception as exc:
            logger.exception("Could not reload reports after collection")
            st.error(f"Reports were collected but could not be reloaded: {exc}")

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

    articles = _attach_classifications(articles, labels)
    articles = _attach_severities(articles, severity_rows)

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
    unknown_classifications = int((
        articles["classification_status"].isin(["unknown", "unclassified"])
        | articles["classification_categories"].eq(THREAT_NAMES["unknown"])
    ).sum()) if not articles.empty else 0
    st.metric("Unknown or unclassified reports", unknown_classifications)
    unknown_severity = int((articles["severity"] == "Unknown").sum()) if not articles.empty else 0
    st.metric("Unknown severity", unknown_severity)

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
            "fetched_at": "Collected at", "summary": "Description",
            "confidence_display": "Confidence", "method_display": "Detection method",
            "classification_categories": "Threat categories", "classification_confidence": "Category confidence (heuristic)",
            "classification_evidence": "Supporting evidence", "classification_method": "Classification method",
            "classification_status": "Classification status",
            "severity": "Severity", "severity_status": "Severity assessment status",
            "severity_explanation": "Severity explanation", "severity_evidence": "Severity supporting evidence",
            "severity_method": "Severity method", "evidence_completeness": "Evidence completeness",
        })
        st.dataframe(live_display[["Title", "Source", "Published", "Collected at", "Language", "Confidence", "Detection method", "Threat categories", "Category confidence (heuristic)", "Supporting evidence", "Classification method", "Classification status", "Severity", "Severity assessment status", "Severity explanation", "Severity supporting evidence", "Severity method", "Evidence completeness", "Report status", "Description", "Original URL"]], use_container_width=True, hide_index=True)

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
        })
        demo_display["Language"] = demo_display["Language"].map(LANGUAGE_NAMES)
        st.dataframe(demo_display[["Title", "Source", "Published", "Language", "Confidence", "Detection method", "Threat categories", "Category confidence (heuristic)", "Supporting evidence", "Classification method", "Classification status", "Severity", "Severity assessment status", "Severity explanation", "Severity supporting evidence", "Severity method", "Evidence completeness", "Original URL"]], use_container_width=True, hide_index=True)

    st.caption("Collected reports are unverified source material. Threat categories and severity assessments are separate. Automated severity is preliminary; only documented evidence marked verified is treated as verified, and human review is authoritative.")


if __name__ == "__main__":
    main()
