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
SUMMARY_METHOD_VERSION = "1.0"
MIN_SOURCE_CHARACTERS = 100
_SPLIT_SENTENCE_RE = re.compile(r"(?<=[.!?።፧])\s+|\n+")
_TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_AFFECTED_RE = re.compile(r"\b(?:affected products?|products? affected)\s*(?::|=|\bas\b)\s*([^.;\n]{2,120})", re.I)
_MALWARE_RE = re.compile(r"\bmalware family\s*[:=]\s*([^.;\n]{2,80})", re.I)
_IMPACT_RE = re.compile(r"\b(?:data exposed|data breach|records leaked|service disrupted|service outage|unauthorized access|unauthorised access|systems compromised)\b", re.I)
_EXPLOIT_RE = re.compile(r"\b(?:actively exploited|exploited in the wild|exploitation observed|proof[- ]of[- ]concept|\bPoC\b)\b", re.I)
_STOPWORDS = {
    "this", "that", "with", "from", "have", "been", "were", "after", "before",
    "the", "and", "for", "are", "was", "has", "had", "will", "would", "could",
    "about", "into", "their", "they", "them", "also", "than", "then", "which",
}


def source_fingerprint(text: str | None) -> str:
    """Fingerprint the exact normalized text used by the summary operation."""
    normalized = unicodedata.normalize("NFKC", text or "")
    normalized = " ".join(normalized.split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def _source_text(article: dict[str, Any]) -> str:
    content = str(article.get("content") or "").strip()
    if content:
        return content
    title = str(article.get("title") or "").strip()
    description = str(article.get("summary") or article.get("description") or "").strip()
    return "\n".join(part for part in (title, description) if part)


def _sentence_tokens(sentence: str) -> list[str]:
    return [token.casefold() for token in _TOKEN_RE.findall(sentence)
            if len(token) > 1 and token.casefold() not in _STOPWORDS]


def _rank_sentences(text: str, max_sentences: int = 3) -> list[str]:
    sentences = [sentence.strip() for sentence in _SPLIT_SENTENCE_RE.split(text) if sentence.strip()]
    eligible = [(index, sentence) for index, sentence in enumerate(sentences)
                if len(sentence) >= 25 and len(_sentence_tokens(sentence)) >= 4]
    if len(eligible) < 2:
        return []
    frequencies = Counter(token for _, sentence in eligible for token in _sentence_tokens(sentence))
    scored = []
    for index, sentence in eligible:
        tokens = _sentence_tokens(sentence)
        centrality = sum(1 + math.log(frequencies[token]) for token in tokens) / math.sqrt(len(tokens))
        cve_bonus = 1.2 if _CVE_RE.search(sentence) else 0.0
        evidence_bonus = 0.45 if _IMPACT_RE.search(sentence) or _EXPLOIT_RE.search(sentence) else 0.0
        scored.append((centrality + cve_bonus + evidence_bonus, index, sentence))
    count = min(max_sentences, max(1, math.ceil(len(eligible) * 0.35)))
    chosen = sorted(scored, reverse=True)[:count]
    return [sentence for _, _, sentence in sorted(chosen, key=lambda item: item[1])]


def _key_intelligence(article: dict[str, Any], text: str) -> dict[str, Any]:
    cves = sorted({value.upper() for value in _CVE_RE.findall(text)})
    products = list(dict.fromkeys(match.strip() for match in _AFFECTED_RE.findall(text)))
    malware_names = list(dict.fromkeys(match.strip() for match in _MALWARE_RE.findall(text)))
    categories = article.get("threat_categories") or []
    category_status = article.get("threat_category_status") or "classified"
    if isinstance(categories, str):
        categories = [categories]
    categories = list(dict.fromkeys(str(value) for value in categories if value and value != "unknown"))
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
        "publication_date": article.get("published_at") or "Unknown",
        "source": article.get("source") or "Unknown",
        "original_url": article.get("url") or "Unknown",
        "article_title": article.get("title") or "Unknown",
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
    source_language = str(article.get("language") or "und")
    requested = requested_language or source_language
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
        selected = _rank_sentences(text)
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
            evidence = [{"excerpt": sentence, "source_text_fingerprint": source_fingerprint(text)}
                        for sentence in selected]
            kind = "original_language_extractive"
    return SummaryResult(
        article_id=int(article["id"]) if article.get("id") is not None else None,
        summary_language=requested, summary_text=summary, method=SUMMARY_METHOD,
        status=status, supporting_evidence=tuple(evidence), method_version=SUMMARY_METHOD_VERSION,
        created_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        source_text_fingerprint=source_fingerprint(text), source_text_used=text, summary_kind=kind,
        key_intelligence=_key_intelligence(article, text),
        source_metadata={"title": article.get("title"), "source": article.get("source"),
                         "published_at": article.get("published_at"), "original_url": article.get("url"),
                         "source_language": source_language, "text_used": "content" if article.get("content") else "title_and_description"},
    )
