"""Synthetic source excerpts for unit tests; they are not intelligence data."""

from src.ethio_cyber_intel.summarization import is_missing_summary_text, summarize_article
from src.ethio_cyber_intel.language_detection import detect_article_language


EN_TEXT = (
    "Researchers analyzed a vulnerability affecting network management software. "
    "The report identifies CVE-2026-13579 and describes the affected product as Example Router. "
    "The publisher says that administrators should review the vendor advisory and apply updates. "
    "No exploitation status was independently confirmed in this synthetic test text."
)
AM_TEXT = (
    "የደህንነት ቡድኑ በኔትወርክ ሶፍትዌር ላይ ያለ ችግርን መርምሯል። "
    "ሪፖርቱ CVE-2026-13579 የተባለውን መለያ በግልጽ ይጠቅሳል። "
    "አሳታሚው ተጠቃሚዎች የሶፍትዌር ማሻሻያውን እንዲመለከቱ ገልጿል። "
    "በዚህ ሰው ሰራሽ ሙከራ ጽሑፍ የብዝበዛ ሁኔታ አልተረጋገጠም።"
)
OM_TEXT = (
    "Qorattoonni rakkoo nageenyaa sooftiweerii neetworkii irratti argame qoratan. "
    "Gabaasni lakkoofsa CVE-2026-13579 fi oomisha miidhame ifatti ibsa. "
    "Maxxansaan fayyadamtoonni beeksisa dhaabbatichaa akka ilaalan dubbate. "
    "Barreeffama yaalii uumamaa kana keessatti odeeffannoon miidhaa mirkanaa'e hin jiru."
)


def make_article(language, content, **values):
    return {"id": 7, "title": "A clearly attributed report title", "source": "Synthetic test source",
            "url": "https://example.test/source-report", "published_at": "2026-02-01T12:00:00Z",
            "language": language, "content": content, **values}


def test_english_summary_is_verbatim_source_sentence_selection():
    result = summarize_article(make_article("en", EN_TEXT))
    assert result.status == "original_extractive"
    assert result.summary_language == "en"
    assert result.summary_text
    assert all(evidence["excerpt"] in EN_TEXT for evidence in result.supporting_evidence)
    assert result.summary_text == " ".join(item["excerpt"] for item in result.supporting_evidence)


def test_amharic_summary_preserves_original_script_and_source_sentences():
    result = summarize_article(make_article("am", AM_TEXT))
    assert result.status == "original_extractive"
    assert result.summary_language == "am"
    assert all(item["excerpt"] in AM_TEXT for item in result.supporting_evidence)
    assert any("CVE-2026-13579" in item["excerpt"] for item in result.supporting_evidence)


def test_afaan_oromo_summary_is_extractive_not_translated():
    result = summarize_article(make_article("om", OM_TEXT))
    assert result.status == "original_extractive"
    assert result.summary_kind == "original_language_extractive"
    assert all(item["excerpt"] in OM_TEXT for item in result.supporting_evidence)


def test_detected_amharic_and_oromo_feed_text_reaches_original_language_summarizer():
    for language, text in (("am", AM_TEXT), ("om", OM_TEXT)):
        detection = detect_article_language(title=None, description=text, content=None)
        assert detection.language == language
        result = summarize_article(make_article(language, None, summary=text))
        assert result.status == "original_extractive"
        assert result.summary_language == language
        assert all(item["excerpt"] in text for item in result.supporting_evidence)


def test_unsupported_source_language_returns_no_summary():
    result = summarize_article(make_article("und", EN_TEXT), requested_language="en")
    assert result.status == "unsupported_language"
    assert result.summary_text is None


def test_requested_other_language_is_not_misrepresented_as_translation():
    result = summarize_article(make_article("en", EN_TEXT), requested_language="am")
    assert result.status == "unsupported_translation"
    assert result.summary_text is None
    assert result.summary_kind == "translation_unavailable"


def test_insufficient_source_text_does_not_generate_summary():
    result = summarize_article(make_article("en", "A short note with too few source details."))
    assert result.status == "insufficient_content"
    assert result.summary_text is None


def test_missing_publication_date_is_unknown_and_never_fabricated():
    result = summarize_article(make_article("en", EN_TEXT, published_at=None))
    assert result.key_intelligence["publication_date"] == "Unknown"
    assert result.source_metadata["published_at"] is None


def test_key_intelligence_does_not_invent_products_or_malware_names():
    result = summarize_article(make_article("en", EN_TEXT))
    assert result.key_intelligence["cve_identifiers"]["value"] == ["CVE-2026-13579"]
    assert result.key_intelligence["affected_products"]["value"] == ["Example Router"]
    assert result.key_intelligence["malware_names"]["value"] == "Not reported"
    assert result.key_intelligence["source"] == "Synthetic test source"
    assert result.key_intelligence["original_url"] == "https://example.test/source-report"


def test_null_and_nan_fields_do_not_become_summary_source_text():
    import pandas as pd

    article = make_article("en", None, summary=pd.Series([None]).iloc[0], description="None")
    article["title"] = float("nan")
    article["language"] = float("nan")
    result = summarize_article(article)
    assert result.status == "unsupported_language"
    assert result.summary_text is None
    assert result.source_text_used == ""
    assert "nan" not in result.source_text_used.casefold()
    assert is_missing_summary_text(None)
    assert is_missing_summary_text(float("nan"))
    assert is_missing_summary_text(pd.Series([None]).iloc[0])
    assert is_missing_summary_text("NaN")


def test_missing_article_content_uses_available_description_without_null_strings():
    article = make_article("en", None, summary=EN_TEXT)
    result = summarize_article(article)
    assert result.source_text_used == EN_TEXT
    assert result.status == "original_extractive"
    assert result.summary_text
    assert "nan" not in result.summary_text.casefold()
    assert article["title"] not in result.summary_text
    assert result.source_metadata["text_used"] == "description"


def test_long_rss_description_produces_concise_verbatim_summary_and_drops_boilerplate():
    title = "CISA Adds Two Known Exploited Vulnerabilities to Catalog"
    description = (
        f"{title} mlove Nov 23, 2026 Release Date November 23, 2026 Description "
        "CISA has added two new vulnerabilities to its Known Exploited Vulnerabilities (KEV) Catalog, based on evidence of active exploitation. "
        "CVE-2026-133968 Project MONAI MONAI Label Path Traversal Vulnerability CVE-2026-134624 N-able Mail Assure SSRF Vulnerability "
        "These vulnerabilities are a frequent attack vector and pose significant risks to the federal enterprise. "
        "Binding Operational Directive BOD 26-04 requires agencies to prioritize remediation of high-risk vulnerabilities. "
        "CISA will continue to add vulnerabilities that meet its criteria. "
        "Aware of another exploited vulnerability? Submit it through the nomination form. Advisory Type Alert."
    )
    result = summarize_article(make_article("en", None, title=title, summary=description))
    assert result.status == "original_extractive"
    source_words = len(result.source_text_used.split())
    summary_words = len(result.summary_text.split())
    assert summary_words < source_words * 0.5
    assert summary_words <= 80
    assert len(result.supporting_evidence) <= 2
    assert all(item["excerpt"] in result.source_text_used for item in result.supporting_evidence)
    assert title not in result.summary_text
    assert "mlove" not in result.summary_text
    assert "Advisory Type" not in result.summary_text
    assert "CVE-2026-133968" in result.summary_text
    assert "CVE-2026-134624" in result.summary_text
    assert "active exploitation" in result.summary_text


def test_repeated_sentences_are_removed_from_extractive_evidence():
    repeated = "CISA reports active exploitation of CVE-2026-55555 in a vulnerable server product."
    text = " ".join([
        repeated,
        "The vendor released a security patch for affected customers this week.",
        repeated,
        "Organizations should review the source advisory for remediation details.",
    ])
    result = summarize_article(make_article("en", text))
    evidence = [item["excerpt"] for item in result.supporting_evidence]
    assert len(evidence) == len(set(evidence))


def test_cve_and_reported_impact_sentences_rank_as_evidence():
    text = (
        "A general software update was announced for customers in several regions. "
        "The report identifies CVE-2026-78881 and says attackers actively exploited the flaw. "
        "The incident exposed customer records after unauthorized access to the service. "
        "The publisher provides background information about its security program."
    )
    result = summarize_article(make_article("en", text))
    evidence = [item["excerpt"] for item in result.supporting_evidence]
    assert any("CVE-2026-78881" in sentence for sentence in evidence)
    assert any("exposed customer records" in sentence for sentence in evidence)
    assert all(item["evidence_types"] for item in result.supporting_evidence)


def test_summary_sentence_and_word_limits_bound_normal_output():
    text = " ".join(
        f"Analysts reviewed general security guidance for network administrators in region {index}."
        for index in range(12)
    )
    result = summarize_article(make_article("en", text))
    assert result.status == "original_extractive"
    assert len(result.supporting_evidence) <= 2
    assert len(result.summary_text.split()) <= 80


def test_missing_evidence_is_reported_without_invented_key_intelligence():
    text = (
        "Researchers reviewed general security guidance for network administrators. "
        "The publisher recommends checking available product documentation. "
        "No affected organization is identified in this synthetic test excerpt."
    )
    result = summarize_article(make_article("en", text))
    assert result.status == "original_extractive"
    for key in ("cve_identifiers", "affected_products", "malware_names", "reported_impact", "exploitation_claims"):
        assert result.key_intelligence[key]["value"] == "Not reported"
