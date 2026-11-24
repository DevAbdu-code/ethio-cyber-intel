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


def load_current_severity_assessments(db_path=None) -> pd.DataFrame:
    """Load the latest severity history row for each report."""
    with connect(db_path) as connection:
        return pd.read_sql_query(
            """WITH latest AS (
                   SELECT article_id, MAX(id) AS assessment_id
                   FROM severity_assessments GROUP BY article_id
               )
               SELECT s.id AS assessment_id,s.article_id,s.severity,s.explanation,
                      s.evidence_json,s.method,s.assessed_at,s.status,
                      s.evidence_completeness_json,s.assessment_version
               FROM latest x JOIN severity_assessments s ON s.id=x.assessment_id
               ORDER BY s.article_id""",
            connection,
        )


def load_current_correlations(db_path=None) -> pd.DataFrame:
    """Load latest relationship decision plus source-attributed article details."""
    with connect(db_path) as connection:
        return pd.read_sql_query(
            """WITH latest AS (
                   SELECT pair_id, MAX(id) AS assessment_id
                   FROM correlation_assessments GROUP BY pair_id
               )
               SELECT p.id AS pair_id,p.article_id_a,p.article_id_b,
                      c.score,c.matching_identifiers_json,c.shared_entities_json,
                      c.shared_terms_json,c.similarity_methods_json,c.supporting_evidence_json,
                      c.language_a,c.language_b,c.language_pair,c.explanation,
                      c.correlated_at,c.status,c.reviewer_note,
                      a.title AS title_a,a.source AS source_a,a.url AS url_a,
                      a.published_at AS published_a,a.language AS article_language_a,
                      b.title AS title_b,b.source AS source_b,b.url AS url_b,
                      b.published_at AS published_b,b.language AS article_language_b
               FROM latest x
               JOIN correlation_assessments c ON c.id=x.assessment_id
               JOIN correlation_pairs p ON p.id=c.pair_id
               JOIN articles a ON a.id=p.article_id_a
               JOIN articles b ON b.id=p.article_id_b
               ORDER BY CASE c.status WHEN 'Candidate' THEN 0 ELSE 1 END,c.score DESC,c.id DESC""",
            connection,
        )
