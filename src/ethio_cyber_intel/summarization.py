"""Evidence-grounded, CPU-only extractive report summaries.

The baseline selects source sentences verbatim. It does not translate or
generate paraphrases. Language support therefore means sentence selection in
the detected source language, not fluent language generation.
"""

from __future__ import annotations

import hashlib
import math
import re
import unicodedata
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

SUPPORTED_SUMMARY_LANGUAGES = ("en", "am", "om")
SUMMARY_METHOD = "extractive_sentence_ranking"
SUMMARY_METHOD_VERSION = "2.0"
MIN_SOURCE_CHARACTERS = 100
MAX_SUMMARY_SENTENCES = 2
MAX_SUMMARY_WORDS = 80
_SPLIT_SENTENCE_RE = re.compile(r"(?<=[.!?።፧])\s+|\n+")
_TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_AFFECTED_RE = re.compile(r"\b(?:affected products?|products? affected)\s*(?::|=|\bas\b)\s*([^.;\n]{2,120})", re.I)
_MALWARE_RE = re.compile(r"\bmalware family\s*[:=]\s*([^.;\n]{2,80})", re.I)
_IMPACT_RE = re.compile(r"\b(?:data exposed|data breach|records leaked|service disrupted|service outage|unauthorized access|unauthorised access|systems compromised|pose significant risks?|risk to (?:the )?(?:federal )?enterprise|customer data exposed|information exposed)\b", re.I)
_EXPLOIT_RE = re.compile(r"\b(?:actively exploited|exploited in the wild|exploitation observed|proof[- ]of[- ]concept|\bPoC\b)\b", re.I)
_PRODUCT_RE = re.compile(r"\b(?:affected product|product affected|impacted product|product impacted)\s*(?::|=|\bas\b)\s*([^.;\n]{2,120})", re.I)
_BOILERPLATE_RE = re.compile(
    r"^(?:by\s+\S+|author\s*[:\-]|published\s*[:\-]|publication date\s*[:\-]|"
    r"release date\s*[:\-]|updated\s*[:\-]|advisory type\b|read more\b|"
    r"related articles?\b|subscribe\b|sign up\b|share this\b|follow us\b|"
    r"advertisement\b|©|all rights reserved\b|show ['\"]?key takeaways\b)", re.I,
)
_METADATA_MARKER_RE = re.compile(r"\b(?:release date|publication date|published by|advisory type)\b", re.I)
_EXPLOIT_CUES = (
    "actively exploited", "exploited in the wild", "active exploitation",
    "exploitation observed", "proof-of-concept", "proof of concept",
    "በብዝበዛ", "ተጋላጭነት ተጠቅመው",
)
_IMPACT_CUES = (
    "data exposed", "data breach", "records leaked", "service disrupted",
    "service outage", "unauthorized access", "unauthorised access",
    "systems compromised", "customer data", "information exposed",
    "pose significant risks", "risk to the federal enterprise", "risk to federal enterprise",
    "የመረጃ ጥሰት", "መረጃ ተጋለጠ", "ጉዳት ደረሰ",
    "odeeffannoo saaxil", "odeeffannoo hatame", "miidhaa geessise",
)
_LANGUAGE_CYBER_TERMS = {
    "en": (
    "cyber", "security", "vulnerability", "exploit", "malware", "ransomware",
    "phishing", "breach", "credential", "attacker", "threat actor", "attack",
    "compromised", "exposed", "patch", "zero-day", "kev catalog", "cve",
    ),
    "am": (
        "ተጋላጭነት", "የደህንነት", "ጥቃት", "ማልዌር", "ብዝበዛ", "የመረጃ ጥሰት",
        "የመረጃ ስርቆት", "የመለያ ጥሰት", "የሶፍትዌር ችግር", "የደህንነት ችግር",
        "የደህንነት ማሻሻያ", "cve", "kev",
    ),
    "om": (
        "haleellaa", "miidhaa", "saaxilamummaa", "rakkoo nageenyaa", "odeeffannoo",
        "saayibaraa", "balaa", "jeequmsa", "cve", "kev",
    ),
}
_CYBER_TERMS = tuple(term for terms in _LANGUAGE_CYBER_TERMS.values() for term in terms)
_EN_STOPWORDS = {
    "this", "that", "with", "from", "have", "been", "were", "after", "before",
    "the", "and", "for", "are", "was", "has", "had", "will", "would", "could",
    "about", "into", "their", "they", "them", "also", "than", "then", "which",
}
_AM_STOPWORDS = {
    "እና", "የ", "በ", "ለ", "ከ", "ወደ", "ላይ", "ውስጥ", "ነው", "ነበር", "እንደ",
    "ይህ", "ይህን", "ሁሉ", "ጋር", "ሲሆን", "እንዲሁም", "ወይም", "ብሎ", "ብለው",
}
_OM_STOPWORDS = {
    "fi", "kan", "kun", "dha", "ni", "hin", "akka", "irratti", "keessatti",
    "yeroo", "isa", "ishee", "isaan", "malee", "garuu", "irra", "jedhu",
    "jedhame", "ta'e", "ta'uu", "tokko", "sana", "isaanii", "miti",
}
_STOPWORDS_BY_LANGUAGE = {"en": _EN_STOPWORDS, "am": _AM_STOPWORDS, "om": _OM_STOPWORDS}


def source_fingerprint(text: str | None) -> str:
    """Fingerprint the exact normalized text used by the summary operation."""
    normalized = unicodedata.normalize("NFKC", text or "")
    normalized = " ".join(normalized.split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def is_missing_summary_text(value: Any) -> bool:
    """Return True for database/Pandas nulls and blank placeholder values."""
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip().casefold() in {"", "nan", "none", "<na>", "nat"}
    try:
        unequal_to_self = value != value
        if isinstance(unequal_to_self, bool):
            return unequal_to_self
        # Handles numpy.bool_ without importing NumPy/Pandas into the module.
        if type(unequal_to_self).__name__ == "bool_":
            return bool(unequal_to_self)
    except (TypeError, ValueError):
        pass
    return str(value).strip().casefold() in {"", "nan", "none", "<na>", "nat"}


def _clean_optional_text(value: Any) -> str:
    return "" if is_missing_summary_text(value) else str(value).strip()


def _usable_article_content(article: dict[str, Any]) -> str:
    status = _clean_optional_text(article.get("content_validation_status"))
    if status in {"legacy_unverified", "not_available", "extraction_rejected"}:
        return ""
    return _clean_optional_text(article.get("content"))


def _source_text(article: dict[str, Any]) -> str:
    content = _usable_article_content(article)
    if content:
        return content
    description = _clean_optional_text(article.get("summary"))
    if not description:
        description = _clean_optional_text(article.get("description"))
    # The title is metadata, not body text. Use it only when the source supplied
    # no description at all; otherwise it would be repeated as a summary sentence.
    return description or _clean_optional_text(article.get("title"))


def _sentence_tokens(sentence: str, language: str = "en") -> list[str]:
    stopwords = _STOPWORDS_BY_LANGUAGE.get(language, set())
    return [token.casefold() for token in _TOKEN_RE.findall(sentence)
            if len(token) > 1 and token.casefold() not in stopwords]


def _sentence_evidence_types(sentence: str) -> list[str]:
    """Identify literal evidence cues; labels do not assert independent verification."""
    folded = sentence.casefold()
    kinds = []
    if _CVE_RE.search(sentence):
        kinds.append("CVE identifier")
    if _EXPLOIT_RE.search(sentence) or any(cue in folded for cue in _EXPLOIT_CUES):
        kinds.append("Reported exploitation evidence")
    if _IMPACT_RE.search(sentence) or any(cue in folded for cue in _IMPACT_CUES):
        kinds.append("Reported impact evidence")
    if _PRODUCT_RE.search(sentence) or _AFFECTED_RE.search(sentence):
        kinds.append("Affected product")
    if _MALWARE_RE.search(sentence):
        kinds.append("Named malware family")
    if not kinds and any(term in folded for term in _CYBER_TERMS):
        kinds.append("Threat-related terminology")
    return kinds


def _strip_title_and_metadata(sentence: str, title: str) -> str:
    candidate = sentence.strip()
    title_removed = False
    clean_title = title.strip()
    if clean_title and candidate.casefold().startswith(clean_title.casefold()):
        remainder = candidate[len(clean_title):]
        if not remainder or remainder[0].isspace() or remainder[0] in ":|—-.,":
            candidate = remainder.lstrip(" \t:|—-.,")
            title_removed = True

    # Some publisher RSS descriptions flatten the page title, byline, date and
    # "Description" heading into one string. Remove only that recognizable
    # metadata prefix; retain the exact body text that follows the heading.
    marker = re.search(r"\bDescription\s*[:\-]?\s+", candidate, re.I)
    if marker and marker.start() < 300 and (title_removed or _METADATA_MARKER_RE.search(candidate[:marker.start()])):
        candidate = candidate[marker.end():].lstrip()
    candidate = re.sub(r"^(?:author|published|publication date|release date|updated)\s*[:\-]\s*", "", candidate, flags=re.I)
    return candidate.strip()


def _is_duplicate_sentence(
    sentence: str, selected_tokens: set[str], selected_text: str, language: str,
) -> bool:
    normalized = " ".join(_sentence_tokens(sentence, language))
    previous = " ".join(_sentence_tokens(selected_text, language))
    if normalized and normalized == previous:
        return True
    tokens = set(_sentence_tokens(sentence, language))
    if not tokens or not selected_tokens:
        return False
    overlap = len(tokens & selected_tokens) / len(tokens | selected_tokens)
    return overlap >= 0.82


def _rank_sentences(
    text: str,
    title: str = "",
    max_sentences: int = MAX_SUMMARY_SENTENCES,
    max_words: int = MAX_SUMMARY_WORDS,
    language: str = "en",
) -> list[str]:
    raw_sentences = [part.strip() for part in _SPLIT_SENTENCE_RE.split(text) if part.strip()]
    title_tokens = set(_sentence_tokens(title, language))
    candidates: list[tuple[int, str, list[str], set[str]]] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_sentences):
        sentence = _strip_title_and_metadata(raw, title)
        if not sentence or _BOILERPLATE_RE.match(sentence):
            continue
        tokens = _sentence_tokens(sentence, language)
        if len(sentence) < 25 or len(tokens) < 4:
            continue
        token_signature = " ".join(tokens)
        if token_signature in seen:
            continue
        seen.add(token_signature)
        candidates.append((index, sentence, tokens, set(tokens)))
    if len(candidates) < 2:
        return []

    frequencies = Counter(token for _, _, tokens, _ in candidates for token in tokens)
    scored: list[tuple[float, int, str, set[str], int, list[str]]] = []
    for index, sentence, tokens, token_set in candidates:
        folded = sentence.casefold()
        evidence = _sentence_evidence_types(sentence)
        term_hits = sum(1 for term in _LANGUAGE_CYBER_TERMS.get(language, _LANGUAGE_CYBER_TERMS["en"]) if term in folded)
        centrality = sum(1 + math.log(frequencies[token]) for token in tokens) / len(tokens)
        title_overlap = len(token_set & title_tokens) / max(1, len(title_tokens))
        score = 0.55 * centrality + min(3.0, term_hits * 0.8) + title_overlap * 0.7
        if "CVE identifier" in evidence:
            score += 5.0
        if "Reported exploitation evidence" in evidence:
            score += 3.5
        if "Reported impact evidence" in evidence:
            score += 3.2
        if "Affected product" in evidence:
            score += 2.0
        if "Named malware family" in evidence:
            score += 2.5
        # Named entities and product/version strings give useful context, but
        # lexical capitalization alone is not treated as verified entity data.
        if re.search(r"\b[A-Z][A-Za-z0-9.-]{2,}\b", sentence):
            score += 0.25
        # Count visible words rather than ranking tokens (which deliberately
        # omit stopwords), so the configured budget matches dashboard text.
        scored.append((score, index, sentence, token_set, len(_TOKEN_RE.findall(sentence)), evidence))

    chosen: list[tuple[int, str, set[str], int, list[str]]] = []
    word_total = 0
    for score, index, sentence, token_set, word_count, evidence in sorted(scored, key=lambda item: (-item[0], item[1])):
        if len(chosen) >= max_sentences:
            break
        if any(_is_duplicate_sentence(sentence, existing_tokens, existing_text, language)
               for _, existing_text, existing_tokens, _, _ in chosen):
            continue
        essential_evidence = any(kind in evidence for kind in (
            "CVE identifier", "Reported exploitation evidence", "Reported impact evidence",
            "Affected product", "Named malware family",
        ))
        if word_total + word_count > max_words and not essential_evidence:
            continue
        # Keep an evidence-bearing source sentence intact even if doing so
        # exceeds the soft word budget. Sentence text is never truncated.
        chosen.append((index, sentence, token_set, word_count, evidence))
        word_total += word_count
    return [sentence for _, sentence, _, _, _ in sorted(chosen, key=lambda item: item[0])]


def _key_intelligence(article: dict[str, Any], text: str) -> dict[str, Any]:
    cves = sorted({value.upper() for value in _CVE_RE.findall(text)})
    products = list(dict.fromkeys(match.strip() for match in _AFFECTED_RE.findall(text)))
    malware_names = list(dict.fromkeys(match.strip() for match in _MALWARE_RE.findall(text)))
    categories = article.get("threat_categories")
    if is_missing_summary_text(categories):
        categories = []
    category_status = _clean_optional_text(article.get("threat_category_status")) or "classified"
    if isinstance(categories, str):
        categories = [categories]
    if not isinstance(categories, (list, tuple, set)):
        categories = []
    categories = list(dict.fromkeys(
        str(value) for value in categories
        if not is_missing_summary_text(value) and str(value).casefold() != "unknown"
    ))
    sentences = [sentence.strip() for sentence in _SPLIT_SENTENCE_RE.split(text) if sentence.strip()]
    impact_claims = [sentence for sentence in sentences if _IMPACT_RE.search(sentence)]
    exploitation_claims = [sentence for sentence in sentences if _EXPLOIT_RE.search(sentence)]
    return {
        "threat_categories": {
            "value": categories or "Not reported",
            "provenance": (
                "Stage 4 human-reviewed labels; source claims remain unverified"
                if categories and category_status == "human_reviewed" else
                "Stage 4 automated labels; preliminary, not independently verified"
                if categories else "not found in supplied classification"
            ),
        },
        "cve_identifiers": {"value": cves or "Not reported", "provenance": "exact identifiers extracted from source text"},
        "affected_products": {"value": products or "Not reported", "provenance": "explicitly labeled product text only"},
        "malware_names": {"value": malware_names or "Not reported", "provenance": "explicitly labeled malware family text only"},
        "reported_impact": {"value": impact_claims or "Not reported", "provenance": "source excerpts; reported claims, not verified facts"},
        "exploitation_claims": {"value": exploitation_claims or "Not reported", "provenance": "source excerpts; reported claims, not verified facts"},
        "publication_date": _clean_optional_text(article.get("published_at")) or "Unknown",
        "source": _clean_optional_text(article.get("source")) or "Unknown",
        "original_url": _clean_optional_text(article.get("url")) or "Unknown",
        "article_title": _clean_optional_text(article.get("title")) or "Unknown",
    }


@dataclass(frozen=True)
class SummaryResult:
    article_id: int | None
    summary_language: str
    summary_text: str | None
    method: str
    status: str
    supporting_evidence: tuple[dict[str, Any], ...]
    method_version: str
    created_at: str
    source_text_fingerprint: str
    source_text_used: str
    summary_kind: str
    key_intelligence: dict[str, Any]
    source_metadata: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["supporting_evidence"] = list(self.supporting_evidence)
        return value


def summarize_article(
    article: dict[str, Any], *, requested_language: str | None = None,
) -> SummaryResult:
    """Summarize the article extractively only in its detected source language."""
    text = _source_text(article)
    source_language = _clean_optional_text(article.get("language")) or "und"
    requested = _clean_optional_text(requested_language) or source_language
    title = _clean_optional_text(article.get("title")) or None
    source = _clean_optional_text(article.get("source")) or None
    published_at = _clean_optional_text(article.get("published_at")) or None
    url = _clean_optional_text(article.get("url")) or None
    if requested not in SUPPORTED_SUMMARY_LANGUAGES:
        status = "unsupported_language"
        explanation = f"No summarization support is available for requested language '{requested}'."
        summary = None
        evidence = []
        kind = "unsupported"
    elif source_language not in SUPPORTED_SUMMARY_LANGUAGES:
        status = "unsupported_language"
        explanation = f"Source language '{source_language}' is unknown, mixed, or unsupported; no summary was generated."
        summary = None
        evidence = []
        kind = "unsupported"
    elif requested != source_language:
        status = "unsupported_translation"
        explanation = (
            f"Requested {requested} but source language is {source_language}. "
            "Extractive sentence selection does not translate; no translated summary was generated."
        )
        summary = None
        evidence = []
        kind = "translation_unavailable"
    elif len(" ".join(text.split())) < MIN_SOURCE_CHARACTERS:
        status = "insufficient_content"
        explanation = "Source text is too short for a reliable extractive summary. No summary was fabricated."
        summary = None
        evidence = []
        kind = "original_language_extractive"
    else:
        article_title = title or ""
        selected = _rank_sentences(text, title=article_title, language=source_language)
        if not selected:
            status = "insufficient_content"
            explanation = "Source text did not contain enough separable sentence evidence for summarization."
            summary = None
            evidence = []
            kind = "original_language_extractive"
        else:
            status = "original_extractive"
            summary = " ".join(selected)
            explanation = "Summary consists of verbatim source sentences selected by a CPU-only sentence-ranking baseline."
            evidence = [{
                "excerpt": sentence,
                "evidence_types": _sentence_evidence_types(sentence),
                "source_title": title,
                "source_name": source,
                "source_url": url,
                "source_language": source_language,
                "source_text_fingerprint": source_fingerprint(text),
            } for sentence in selected]
            kind = "original_language_extractive"
    return SummaryResult(
        article_id=int(article["id"]) if article.get("id") is not None else None,
        summary_language=requested, summary_text=summary, method=SUMMARY_METHOD,
        status=status, supporting_evidence=tuple(evidence), method_version=SUMMARY_METHOD_VERSION,
        created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        source_text_fingerprint=source_fingerprint(text), source_text_used=text, summary_kind=kind,
        key_intelligence=_key_intelligence({**article, "title": title, "source": source,
                                            "published_at": published_at, "url": url}, text),
        source_metadata={"title": title, "source": source,
                         "published_at": published_at, "original_url": url,
                         "source_language": source_language,
                         "text_used": (
                             "content" if _usable_article_content(article) else
                             "description" if _clean_optional_text(article.get("summary"))
                             or _clean_optional_text(article.get("description")) else "title"
                         ),
                         "content_validation_status": (
                             _clean_optional_text(article.get("content_validation_status")) or "not_recorded"
                         ),
                         "source_text_verification_status": (
                             _clean_optional_text(article.get("content_validation_status"))
                             if _usable_article_content(article) else
                             "legacy_unverified; RSS description used"
                             if _clean_optional_text(article.get("content_validation_status")) == "legacy_unverified" else
                             "RSS description used; page body not verified"
                             if _clean_optional_text(article.get("summary")) or _clean_optional_text(article.get("description")) else
                             "title only; page body not verified"
                         )},
    )
