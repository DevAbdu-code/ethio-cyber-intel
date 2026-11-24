"""Synthetic article pairs used only as unit tests, never as evaluation data."""

from src.ethio_cyber_intel.correlation import correlate_pair


def report(id_, title, language="en", **values):
    return {"id": id_, "title": title, "source": f"Synthetic source {id_}",
            "url": f"https://example.test/{id_}", "published_at": "2026-01-10T00:00:00Z",
            "language": language, **values}


def test_identical_cve_creates_cross_language_candidate():
    result = correlate_pair(report(4, "CVE-2026-43210 vulnerability analysis", "am"),
                            report(9, "CVE-2026-43210 security advisory", "en"))
    assert result.status == "Candidate"
    assert result.matching_identifiers == ({"type": "cve", "value": "CVE-2026-43210"},)
    assert result.article_id_a == 4
    assert result.article_id_b == 9
    assert result.language_pair == "am ↔ en"
    assert result.score >= 0.55


def test_shared_explicit_malware_family_links_afaan_oromo_and_english():
    result = correlate_pair(
        report(1, "Gabaasni malware family: TestFamily-X.", "om"),
        report(2, "Malware family: TestFamily-X. Systems affected.", "en"),
    )
    assert result.status == "Candidate"
    assert result.shared_entities == ({"type": "malware_family", "value": "testfamily-x"},)
    assert "not a confirmed common incident" in result.explanation


def test_unrelated_reports_do_not_become_candidates():
    result = correlate_pair(
        report(1, "Bank users receive fake payment phishing emails", "en"),
        report(2, "Hospital storage infrastructure has a scheduled maintenance outage", "en"),
    )
    assert result.status == "Insufficient evidence"
    assert result.score < 0.55


def test_missing_identifiers_do_not_create_cross_language_match_from_terms_alone():
    result = correlate_pair(
        report(1, "Cyber security incident affected enterprise services", "en"),
        report(2, "Cyber security incident affected enterprise services", "om"),
    )
    assert result.status == "Insufficient evidence"
    assert not result.matching_identifiers
    assert not result.shared_entities


def test_legacy_unverified_body_does_not_create_cross_language_correlation(tmp_path):
    from src.ethio_cyber_intel.database import correlate_pending_articles, initialize_database, insert_live_articles

    db_path = tmp_path / "legacy-body-correlation.sqlite"
    initialize_database(db_path, seed_demo=False)
    shared_body = "CVE-2026-99123 malware campaign affected an enterprise network. " * 12
    insert_live_articles([
        {"title": "Quarterly infrastructure update", "url": "https://example.test/live-en",
         "source": "Synthetic EN", "language": "en", "summary": "A routine service update was published.",
         "content": shared_body},
        {"title": "Tajaajila bulchiinsa naannoo", "url": "https://example.test/live-om",
         "source": "Synthetic OM", "language": "om", "summary": "Tajaajilli yeroo isaa irratti ibsame.",
         "content": shared_body},
    ], db_path)

    stats = correlate_pending_articles(db_path)

    assert stats["compared"] == 1
    assert stats["candidates"] == 0
    assert stats["saved"] == 0


def test_same_language_content_similarity_can_create_candidate_without_identifier():
    text = ("Attackers accessed a customer database and copied private records after "
            "compromising the organization's exposed cloud service during January.")
    result = correlate_pair(report(1, text, "en"), report(2, text, "en"))
    assert result.status == "Candidate"
    assert "same_language_character_trigram_jaccard" in result.similarity_methods


def test_short_or_empty_text_is_insufficient_evidence():
    result = correlate_pair(report(1, "Alert", "und"), report(2, "Notice", "und"))
    assert result.status == "Insufficient evidence"
    assert result.explanation
    assert result.correlated_at.endswith("Z")
