"""Synthetic severity fixtures for unit testing only; not research data."""

from src.ethio_cyber_intel.severity_assessment import assess_severity


def article(text, **values):
    return {"title": text, "source": "Synthetic test source", "url": "https://example.test/report",
            "published_at": "2026-01-01T00:00:00Z", **values}


def verified(kind, value, *, url="https://authority.example.test/item", name="Example authority", when="2026-01-01T00:00:00Z"):
    return {"type": kind, "value": value, "verification_status": "verified",
            "source_name": name, "source_url": url, "retrieved_at": when}


def test_confirmed_exploitation_plus_verified_impact_is_high():
    result = assess_severity(article("Report"), [
        verified("exploitation", "confirmed_exploitation"),
        verified("impact", "data_exposure"),
    ])
    assert result.severity == "High"
    assert result.status == "externally_supported"
    assert result.exploitation_status == "confirmed"
    assert result.impact_status == "confirmed"


def test_unconfirmed_exploitation_claim_is_medium_and_explicitly_unverified():
    result = assess_severity(article("A flaw is actively exploited in the wild"))
    assert result.severity == "Medium"
    assert result.status == "preliminary_reported_claim"
    exploitation = next(item for item in result.evidence if item["type"] == "exploitation")
    assert exploitation["evidentiary_status"] == "reported_claim"


def test_reported_cvss_maps_to_critical_but_never_claims_verification():
    result = assess_severity(article("CVE-2026-12345 CVSS v3.1: 9.8"))
    assert result.severity == "Critical"
    assert result.cve_ids == ("CVE-2026-12345",)
    assert result.cvss_score == 9.8
    assert all(item["evidentiary_status"] != "verified_external" for item in result.evidence)
    assert "not externally verified" in result.explanation


def test_documented_external_cve_score_is_marked_verified_with_provenance():
    result = assess_severity(article("CVE-2026-12345"), [verified("cvss", 9.8)])
    assert result.severity == "Critical"
    assert result.status == "externally_supported"
    score_evidence = next(item for item in result.evidence if item["type"] == "cvss")
    assert score_evidence["evidentiary_status"] == "verified_external"
    assert score_evidence["retrieved_at"]
    source_evidence = result.evidence[0]
    assert source_evidence["type"] == "source_metadata"
    assert source_evidence["value"]["published_at"] == "2026-01-01T00:00:00Z"


def test_conflicting_reported_and_verified_cvss_ratings_return_unknown():
    result = assess_severity(article("CVSS score 9.8"), [verified("cvss", 4.2)])
    assert result.severity == "Unknown"
    assert result.status == "conflicting_evidence"


def test_cve_without_score_or_impact_is_unknown():
    result = assess_severity(article("CVE-2026-12345 affects a product"))
    assert result.severity == "Unknown"
    assert result.cvss_score is None
    assert result.cve_ids == ("CVE-2026-12345",)


def test_cvss_version_number_alone_is_not_mistaken_for_a_score():
    result = assess_severity(article("The advisory uses CVSS v3.1"))
    assert result.severity == "Unknown"
    assert result.cvss_score is None


def test_confirmed_impact_requires_documented_external_evidence():
    reported = assess_severity(article("Customer data was exposed in a data breach"))
    assert reported.severity == "Medium"
    assert reported.impact_status == "reported"
    confirmed = assess_severity(article("Report"), [verified("impact", "data_exposure")])
    assert confirmed.impact_status == "confirmed"
    assert confirmed.severity == "Medium"  # scale remains unknown, so no unsupported Critical/High level


def test_potential_impact_is_not_confirmed():
    result = assess_severity(article("This flaw could allow attackers to expose customer records"))
    assert result.severity == "Medium"
    assert result.impact_status == "potential_only"


def test_proof_of_concept_is_review_priority_not_confirmed_exploitation():
    result = assess_severity(article("A proof-of-concept exploit was published"))
    assert result.severity == "Medium"
    assert result.exploitation_status == "proof_of_concept_reported"
    assert result.status == "preliminary_reported_claim"


def test_conflicting_evidence_returns_unknown():
    result = assess_severity(article("Exploitation observed, but no exploitation evidence is available"))
    assert result.severity == "Unknown"
    assert result.status == "conflicting_evidence"
    assert "conflicts" in result.explanation


def test_insufficient_evidence_and_missing_fields_are_unknown_not_safe():
    result = assess_severity({"title": "A report was published"})
    assert result.severity == "Unknown"
    assert result.evidence_completeness["ratio"] < 1
    assert "not evidence of safety" in result.explanation


def test_verified_cvss_requires_complete_source_provenance():
    incomplete = {"type": "cvss", "value": 9.8, "verification_status": "verified"}
    result = assess_severity(article("Report"), [incomplete])
    assert result.severity == "Unknown"
    cvss = next(item for item in result.evidence if item["type"] == "cvss")
    assert cvss["evidentiary_status"] == "reported_claim"


def test_informational_notice_is_not_a_threat_category():
    result = assess_severity(article("Security awareness notice: no known impact"))
    assert result.severity == "Informational"
