"""Explainable candidate correlation for multilingual CTI reports.

Scores are heuristic similarity scores, not probabilities or proof of one
incident. Cross-language matching relies primarily on shared normalized IDs or
explicitly labeled entities; direct lexical/character overlap is weak evidence.
"""

from __future__ import annotations

import itertools
import re
import unicodedata
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

LANGUAGES = ("en", "am", "om", "und", "mul")
PAIR_CANDIDATE_THRESHOLD = 0.55

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_ENTITY_PATTERNS = {
    "malware_family": re.compile(r"\bmalware\s+family\s*[:=]\s*([^,.;\n]{2,80})", re.I),
    "threat_actor": re.compile(r"\bthreat\s+actor\s*[:=]\s*([^,.;\n]{2,80})", re.I),
    "campaign": re.compile(r"\bcampaign\s+(?:id|identifier)\s*[:=]\s*([^,.;\n]{2,80})", re.I),
    "product": re.compile(r"\b(?:affected\s+)?product\s*[:=]\s*([^,.;\n]{2,80})", re.I),
}
_TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)
_STOP_TERMS = {
    "this", "that", "with", "from", "have", "been", "were", "after", "before",
    "report", "reports", "article", "security", "cybersecurity", "cyber", "attack",
    "threat", "malware", "vulnerability", "incident", "system", "systems", "users",
    "their", "about", "into", "also", "will", "could", "would", "said", "says",
}


def _normalize(value: Any) -> str:
    value = unicodedata.normalize("NFKC", str(value or "")).casefold()
    return " ".join(re.sub(r"[^\w\s.-]", " ", value, flags=re.UNICODE).split())


def extract_signals(article: dict[str, Any]) -> dict[str, Any]:
    """Extract high-precision identifiers, explicitly tagged entities, and terms."""
    text = "\n".join(str(article.get(key) or "") for key in ("title", "summary", "content"))
    identifiers = {"cve": set(match.upper() for match in _CVE_RE.findall(text))}
    entities: dict[str, set[str]] = {key: set() for key in _ENTITY_PATTERNS}
    for kind, pattern in _ENTITY_PATTERNS.items():
        entities[kind].update(_normalize(match) for match in pattern.findall(text) if _normalize(match))
    supplied = article.get("entities") or {}
    if isinstance(supplied, dict):
        for kind in entities:
            values = supplied.get(kind, [])
            if isinstance(values, str):
                values = [values]
            entities[kind].update(_normalize(item) for item in values if _normalize(item))
    elif isinstance(supplied, (tuple, list)):
        entities["malware_family"].update(_normalize(item) for item in supplied if _normalize(item))
    if entities["campaign"]:
        identifiers["campaign"] = set(entities["campaign"])
    terms = {token for token in _TOKEN_RE.findall(_normalize(text))
             if len(token) >= 4 and token not in _STOP_TERMS and not token.startswith("cve")}
    normalized_text = _normalize(text)
    categories = article.get("threat_categories") or []
    if isinstance(categories, str):
        categories = [categories]
    return {
        "identifiers": identifiers, "entities": entities, "terms": terms,
        "text": normalized_text, "language": article.get("language") or "und",
        "categories": {str(value).casefold() for value in categories},
    }


def _char_ngrams(text: str, n: int = 3) -> set[str]:
    compact = re.sub(r"\s+", "", text)
    return {compact[index:index+n] for index in range(max(0, len(compact) - n + 1))}


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def _date_gap_days(left: Any, right: Any) -> int | None:
    try:
        a = datetime.fromisoformat(str(left).replace("Z", "+00:00"))
        b = datetime.fromisoformat(str(right).replace("Z", "+00:00"))
        if a.tzinfo is None:
            a = a.replace(tzinfo=timezone.utc)
        if b.tzinfo is None:
            b = b.replace(tzinfo=timezone.utc)
        return abs((a - b).days)
    except (TypeError, ValueError, OverflowError):
        return None


@dataclass(frozen=True)
class CorrelationResult:
    article_id_a: int | None
    article_id_b: int | None
    score: float
    status: str
    language_a: str
    language_b: str
    language_pair: str
    matching_identifiers: tuple[dict[str, Any], ...]
    shared_entities: tuple[dict[str, Any], ...]
    shared_terms: tuple[str, ...]
    similarity_methods: tuple[str, ...]
    supporting_evidence: tuple[dict[str, Any], ...]
    explanation: str
    correlated_at: str

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        for key in ("matching_identifiers", "shared_entities", "shared_terms", "similarity_methods", "supporting_evidence"):
            result[key] = list(result[key])
        return result


def correlate_pair(article_a: dict[str, Any], article_b: dict[str, Any]) -> CorrelationResult:
    """Compare two reports, returning a candidate or insufficient evidence."""
    signals_a, signals_b = extract_signals(article_a), extract_signals(article_b)
    matching_ids = []
    entities = []
    evidence = []
    methods = []
    score = 0.0

    for kind in sorted(signals_a["identifiers"]):
        shared = sorted(signals_a["identifiers"].get(kind, set()) & signals_b["identifiers"].get(kind, set()))
        for value in shared:
            matching_ids.append({"type": kind, "value": value})
            score += 0.68 if kind == "cve" else 0.64 if kind == "campaign" else 0.32
            methods.append("normalized_identifier_match")
            evidence.append({"signal": "shared_identifier", "type": kind, "value": value,
                             "article_urls": [article_a.get("url"), article_b.get("url")]})
    for kind in sorted(signals_a["entities"]):
        shared = sorted(signals_a["entities"][kind] & signals_b["entities"][kind])
        for value in shared:
            entities.append({"type": kind, "value": value})
            if kind not in {"campaign"}:
                score += {"malware_family": 0.58, "threat_actor": 0.48,
                          "product": 0.28}[kind]
            methods.append("explicit_entity_overlap")
            evidence.append({"signal": "shared_explicit_entity", "type": kind, "value": value,
                             "attribution": "mention overlap only; no actor attribution inferred"})

    shared_terms = sorted(signals_a["terms"] & signals_b["terms"])
    term_similarity = _jaccard(signals_a["terms"], signals_b["terms"])
    if shared_terms:
        score += min(0.28, term_similarity * 0.7)
        methods.append("normalized_term_overlap")
        evidence.append({"signal": "shared_terms", "values": shared_terms[:20],
                         "interpretation": "weak supporting signal; common terminology does not establish a common event"})
    same_language = signals_a["language"] == signals_b["language"] and signals_a["language"] in {"en", "am", "om"}
    char_similarity = 0.0
    if same_language and min(len(signals_a["text"]), len(signals_b["text"])) >= 40:
        char_similarity = _jaccard(_char_ngrams(signals_a["text"]), _char_ngrams(signals_b["text"]))
        if char_similarity:
            score += min(0.25, char_similarity * 0.35)
            methods.append("same_language_character_trigram_jaccard")
            evidence.append({"signal": "character_ngram_similarity", "value": round(char_similarity, 4),
                             "language": signals_a["language"], "interpretation": "same-language lexical similarity only"})
    shared_categories = sorted(signals_a["categories"] & signals_b["categories"])
    if shared_categories:
        score += 0.04
        methods.append("shared_threat_category_context")
        evidence.append({"signal": "shared_threat_categories", "values": shared_categories,
                         "interpretation": "weak context; categories do not identify an incident"})
    gap = _date_gap_days(article_a.get("published_at"), article_b.get("published_at"))
    if gap is not None and gap <= 3:
        score += 0.04
        methods.append("publication_time_proximity")
        evidence.append({"signal": "publication_dates", "gap_days": gap,
                         "dates": [article_a.get("published_at"), article_b.get("published_at")]})
    score = round(min(0.99, score), 4)
    has_strong_cross_language_signal = bool(matching_ids or entities)
    candidate = score >= PAIR_CANDIDATE_THRESHOLD and (same_language or has_strong_cross_language_signal)
    status = "Candidate" if candidate else "Insufficient evidence"
    if candidate:
        explanation = (
            "Candidate relationship based on explainable overlapping signals. It is not a confirmed common incident; human review is required."
        )
    else:
        explanation = (
            "Insufficient evidence for a candidate relationship. Missing identifiers or weak textual overlap are not treated as a match."
        )
    lang_a, lang_b = signals_a["language"], signals_b["language"]
    pair = " ↔ ".join(sorted((lang_a, lang_b)))
    ids_a, ids_b = article_a.get("id"), article_b.get("id")
    if ids_a is not None and ids_b is not None and int(ids_a) > int(ids_b):
        ids_a, ids_b = ids_b, ids_a
        lang_a, lang_b = lang_b, lang_a
    return CorrelationResult(
        article_id_a=int(ids_a) if ids_a is not None else None,
        article_id_b=int(ids_b) if ids_b is not None else None,
        score=score, status=status, language_a=lang_a, language_b=lang_b,
        language_pair=pair, matching_identifiers=tuple(matching_ids),
        shared_entities=tuple(entities), shared_terms=tuple(shared_terms[:20]),
        similarity_methods=tuple(dict.fromkeys(methods)), supporting_evidence=tuple(evidence),
        explanation=explanation,
        correlated_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )


def correlate_articles(articles: list[dict[str, Any]]) -> list[CorrelationResult]:
    """Return only candidate pairs from a small supplied batch."""
    results = []
    for first, second in itertools.combinations(articles, 2):
        if first.get("id") is not None and first.get("id") == second.get("id"):
            continue
        result = correlate_pair(first, second)
        if result.status == "Candidate":
            results.append(result)
    return results
