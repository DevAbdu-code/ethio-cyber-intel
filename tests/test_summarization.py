"""Synthetic source excerpts for unit tests; they are not intelligence data."""

from src.ethio_cyber_intel.summarization import summarize_article


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
