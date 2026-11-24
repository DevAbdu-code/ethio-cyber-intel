"""Synthetic classifier unit fixtures; these are not research evaluation data."""

from src.ethio_cyber_intel.threat_classification import (
    MIN_CATEGORY_CONFIDENCE, classify_text,
)


def _classify(text, language="en"):
    return classify_text(title=text, description=None, content=None, language=language)


def _categories(result):
    return {prediction.category for prediction in result.categories}


def test_phishing_classification():
    result = _classify("A phishing email campaign used a fake login page", "en")
    assert "phishing" in _categories(result)
    phishing = next(item for item in result.categories if item.category == "phishing")
    assert phishing.confidence >= MIN_CATEGORY_CONFIDENCE
    assert phishing.evidence


def test_malware_classification_in_english_amharic_and_oromo():
    assert "malware" in _categories(_classify("The trojan malware infected computers", "en"))
    assert "malware" in _categories(_classify("ማልዌር በኮምፒውተሮች ላይ ተገኝቷል", "am"))
    assert "malware" in _categories(_classify("qinqanii saayibaraa", "om"))


def test_ransomware_and_data_breach_are_multi_label():
    result = _classify(
        "Ransomware encrypted files and exposed customer data in a data breach", "en"
    )
    assert {"ransomware", "data_breach"}.issubset(_categories(result))


def test_vulnerability_classification():
    assert "vulnerability" in _categories(
        _classify("CVE-2025-12345 is an unpatched vulnerability", "en")
    )


def test_afaan_oromo_credential_theft_uses_language_specific_evidence():
    assert "credential_theft" in _categories(_classify("iggitaa saame", "om"))


def test_insufficient_or_uncertain_evidence_is_unknown():
    for text, language in (("security", "en"), ("hello world report", "und"), ("xyz abc test", "en")):
        result = _classify(text, language)
        assert _categories(result) == {"unknown"}
        assert result.status == "unknown"


def test_unknown_language_does_not_use_english_specific_phrases():
    assert _categories(_classify("fake login page", "und")) == {"unknown"}


def test_classification_contains_timestamp_method_and_heuristic_score():
    result = _classify("A phishing email was sent to employees", "en")
    assert result.method == "multilingual_keyword_rules"
    assert result.classified_at.endswith("Z")
    assert all(item.confidence is None or 0 <= item.confidence <= 1 for item in result.categories)
