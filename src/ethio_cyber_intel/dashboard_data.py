"""Read-only queries used by the initial dashboard."""

from __future__ import annotations

import pandas as pd

from .database import connect


def load_articles(db_path=None) -> pd.DataFrame:
    """Load dashboard article fields from SQLite."""
    with connect(db_path) as connection:
        return pd.read_sql_query(
            """SELECT id, title, source, published_at, language, language_confidence,
                      language_method, language_reviewed, summary, threat_type,
                      report_status, is_demo, fetched_at, url
               FROM articles ORDER BY COALESCE(published_at, fetched_at) DESC, id DESC""",
            connection,
        )


def load_current_classifications(db_path=None) -> pd.DataFrame:
    """Load labels from each article's newest classification run."""
    with connect(db_path) as connection:
        return pd.read_sql_query(
            """WITH latest AS (
                   SELECT article_id, MAX(id) AS run_id
                   FROM threat_classification_runs GROUP BY article_id
               )
               SELECT r.id AS run_id, r.article_id, r.language, r.method, r.status,
                      r.classifier_version, r.classified_at, l.category,
                      l.confidence, l.evidence_json
               FROM latest AS x
               JOIN threat_classification_runs AS r ON r.id = x.run_id
               JOIN threat_classification_labels AS l ON l.run_id = r.id
               ORDER BY r.article_id, l.category""",
            connection,
        )
