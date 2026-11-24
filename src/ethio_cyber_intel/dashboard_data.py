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
