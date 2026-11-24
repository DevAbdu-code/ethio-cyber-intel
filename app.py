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
from ethio_cyber_intel.dashboard_data import load_articles  # noqa: E402
from ethio_cyber_intel.database import initialize_database, insert_live_articles  # noqa: E402
from ethio_cyber_intel.language_detection import MIN_CONFIDENCE  # noqa: E402
from ethio_cyber_intel.rss_collector import collect_all  # noqa: E402
from ethio_cyber_intel.rss_sources import load_sources  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

LANGUAGE_NAMES = {
    "en": "English", "am": "Amharic", "om": "Afaan Oromo",
    "und": "Unknown", "mul": "Mixed language",
}


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
            st.session_state["source_results"] = results
            st.session_state["last_collection_stats"] = stats
            st.success(
                f"Refresh finished: added {stats['inserted']} live articles; "
                f"skipped {stats['duplicate_url']} duplicate URLs and "
                f"{stats['duplicate_content']} duplicate-content records."
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
        except Exception as exc:
            logger.exception("Could not reload reports after collection")
            st.error(f"Reports were collected but could not be reloaded: {exc}")

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
        filtered = articles[
            articles["source"].isin(selected_sources)
            & articles["is_demo"].map({1: "DEMO DATA", 0: "LIVE"}).isin(record_types)
            & articles["language"].isin(languages)
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
        })
        st.dataframe(live_display[["Title", "Source", "Published", "Collected at", "Language", "Confidence", "Detection method", "Report status", "Description", "Original URL"]], use_container_width=True, hide_index=True)

    demo = filtered[filtered["is_demo"] == 1] if not filtered.empty else filtered
    if not demo.empty:
        st.subheader("DEMO DATA")
        demo_display = demo.rename(columns={
            "title": "Title", "source": "Source", "published_at": "Published",
            "language": "Language", "url": "Original URL",
            "confidence_display": "Confidence", "method_display": "Detection method",
        })
        demo_display["Language"] = demo_display["Language"].map(LANGUAGE_NAMES)
        st.dataframe(demo_display[["Title", "Source", "Published", "Language", "Confidence", "Detection method", "Original URL"]], use_container_width=True, hide_index=True)

    st.caption("Collected reports are unverified source material. This stage does not classify or validate claims as security advisories.")


if __name__ == "__main__":
    main()
