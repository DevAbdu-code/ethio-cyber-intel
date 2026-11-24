"""Small transparent language heuristics for English, Amharic, and Afaan Oromo.

Confidence values express rule strength, not calibrated probabilities. Oromo
lexical cues are intentionally conservative and need broader labeled validation.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import asdict, dataclass

LANGUAGE_CODES = ("en", "am", "om", "und", "mul")
MIN_CONFIDENCE = 0.60
MIXED_CONFIDENCE = 0.68

_TOKEN_RE = re.compile(r"[a-z]+(?:['’][a-z]+)?", re.IGNORECASE)
_ETHIOPIC_RE = re.compile(r"[\u1200-\u137F]")
_LATIN_RE = re.compile(r"[A-Za-z]")
_SENTENCE_RE = re.compile(r"[.!?;\n]+")

# High-specificity Afaan Oromo terms and common function words. This is a
# hand-built cue list, not a representative or validated Oromo corpus.
_OROMO_STRONG = {
    "keessatti", "keessaa", "irratti", "mootummaa", "odeeffannoo",
    "saayibaraa", "haleellaa", "nageenyaa", "nageenya", "dhuunfaa",
    "qorannoo", "dhaabbata", "dhaabbanni", "uummata", "uummataa",
    "tajaajila", "tajaajilli", "hawaasa", "qorachaa", "raawwatame",
    "raawwatameera", "saamameera", "saamame", "bulchiinsi", "akeekkachiise",
    "ykn", "uummanni", "cabsame", "hatame", "dhaabbate", "dhaabbateera",
    "odeeffannoon", "miidhaa", "naannoo", "dhimma", "dabalatee",
}
_OROMO_COMMON = {
    "fi", "akka", "kun", "sana", "isaanii", "jira", "hin", "yeroo",
    "tokko", "irra", "miti", "ni", "dha", "kan", "tahe", "ta'e",
    "ta'uu", "inni", "ishee", "garuu", "waliin", "hundaa", "booda",
}
_ENGLISH_CUES = {
    "the", "and", "for", "of", "to", "in", "on", "with", "was", "were",
    "has", "have", "had", "by", "from", "after", "before", "that", "which",
    "as", "at", "is", "are", "be", "this", "these", "those", "their",
    "they", "it", "its", "an", "a", "or", "but", "into", "about", "while",
    "against", "security", "users", "attackers", "researchers", "reported",
}


@dataclass(frozen=True)
class LanguageDetection:
    language: str
    confidence: float
    method: str

    def as_dict(self) -> dict[str, str | float]:
        return asdict(self)


def _result(language: str, confidence: float, method: str) -> LanguageDetection:
    return LanguageDetection(language, round(max(0.0, min(1.0, confidence)), 3), method)


def _latin_result(text: str) -> LanguageDetection:
    tokens = _TOKEN_RE.findall(text.lower())
    distinct = set(tokens)
    if len(tokens) < 3 or len("".join(tokens)) < 12:
        return _result("und", 0.0, "insufficient_text")

    strong_om = distinct & _OROMO_STRONG
    common_om = distinct & _OROMO_COMMON
    en_cues = distinct & _ENGLISH_CUES
    om_supported = len(strong_om) >= 2 or (len(strong_om) >= 1 and len(common_om) >= 2)
    en_supported = len(en_cues) >= 3 and len(tokens) >= 5

    if om_supported and en_supported:
        return _result("und", 0.42, "conflicting_lexical_cues")
    if om_supported:
        score = 0.70 + 0.045 * len(strong_om) + 0.018 * len(common_om)
        return _result("om", min(0.96, score), "lexical_cues_om")
    if en_supported:
        score = 0.61 + 0.035 * len(en_cues) + 0.006 * min(len(tokens), 15)
        return _result("en", min(0.91, score), "lexical_cues_en")
    return _result("und", 0.35, "unsupported_or_uncertain")


def detect_language(text: str | None) -> LanguageDetection:
    """Detect a supported language conservatively, returning label and rule score."""
    if not text or not text.strip():
        return _result("und", 0.0, "no_text")
    normalized = unicodedata.normalize("NFC", text)
    normalized = re.sub(r"\b(?:https?://|www\.)\S+", " ", normalized, flags=re.IGNORECASE)
    normalized = re.sub(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", " ", normalized)
    ethiopic_count = len(_ETHIOPIC_RE.findall(normalized))
    latin_count = len(_LATIN_RE.findall(normalized))
    all_script_letters = ethiopic_count + latin_count

    if ethiopic_count >= 3:
        latin_text = " ".join(_TOKEN_RE.findall(normalized.lower()))
        latin_detection = _latin_result(latin_text)
        latin_is_substantial = latin_count >= 16 and latin_detection.language in {"en", "om"} and latin_detection.confidence >= MIXED_CONFIDENCE
        if latin_is_substantial:
            return _result(
                "mul", min(0.94, 0.73 + min(ethiopic_count, 30) / 150 + latin_detection.confidence / 10),
                "mixed_script_and_lexical_cues",
            )
        ratio = ethiopic_count / max(1, all_script_letters)
        if ratio >= 0.55:
            confidence = 0.84 + min(0.14, ethiopic_count / 250)
            return _result("am", confidence, "ethiopic_script")

    # Separate confidently labeled sentence-like spans can indicate English /
    # Oromo code-switching. Each span must carry evidence on its own.
    span_results = [
        _latin_result(span)
        for span in _SENTENCE_RE.split(normalized)
        if len(_TOKEN_RE.findall(span)) >= 3
    ]
    span_languages = {item.language for item in span_results if item.confidence >= MIXED_CONFIDENCE}
    if {"en", "om"}.issubset(span_languages):
        return _result("mul", 0.78, "mixed_english_oromo_lexical_cues")

    latin_only = _ETHIOPIC_RE.sub(" ", normalized)
    detected = _latin_result(latin_only)
    if detected.confidence >= MIN_CONFIDENCE:
        return detected
    if all_script_letters < 12:
        return _result("und", 0.0, "insufficient_text")
    return detected


def detect_article_language(
    *, title: str | None, description: str | None, content: str | None
) -> LanguageDetection:
    """Prefer full article body; otherwise use title and description together."""
    selected = content.strip() if content and content.strip() else "\n".join(
        value.strip() for value in (title, description) if value and value.strip()
    )
    return detect_language(selected)
