"""Explainable multilingual keyword baseline for defensive CTI reports.

This is a deterministic rules baseline, not an ML model. Scores are heuristic
evidence-strength values, not calibrated probabilities. Language-specific
matching is gated by the upstream language label to avoid treating all Latin
text as English.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Iterable

CLASSIFIER_METHOD = "multilingual_keyword_rules"
CLASSIFIER_VERSION = "1.0"
MIN_CATEGORY_CONFIDENCE = 0.68
THREAT_CATEGORIES = (
    "phishing", "malware", "ransomware", "vulnerability", "data_breach",
    "ddos", "cyber_espionage", "credential_theft", "other", "unknown",
)
SUPPORTED_LANGUAGES = ("en", "am", "om", "mul", "und")

# Terms marked `shared` are protocol names or widely used technical terms.
# Oromo translations use the ICT Development Office / Ethiopian Languages
# Research Center glossary where that source has a direct equivalent.
_CUES: dict[str, dict[str, tuple[str, ...]]] = {
    "phishing": {
        "shared": ("phishing", "spear phishing", "phishing email", "phishing campaign"),
        "en": ("credential harvesting", "fake login page", "spoofed email"),
        "am": ("በረጅም ማጥመጃ", "ማንነት መስረቂያ"),
    },
    "malware": {
        "shared": ("malware", "malicious software", "trojan", "spyware", "botnet"),
        "en": ("computer virus", "worm infection", "remote access trojan"),
        "am": ("ማልዌር", "ተንኮል አዘል ሶፍትዌር", "ኮምፒውተር ቫይረስ"),
        "om": ("qinqanii", "qinqaanii maakiroo"),
    },
    "ransomware": {
        "shared": ("ransomware", "ransom demand", "ransom note"),
        "en": ("encrypted files", "files were encrypted", "data encrypted and held for ransom"),
        "am": ("ራንሰምዌር", "መረጃዎችን በመቆለፍ ክፍያ"),
    },
    "vulnerability": {
        "shared": ("zero-day", "zero day", "cve"),
        "en": ("vulnerability", "vulnerabilities", "security flaw", "unpatched flaw", "software flaw"),
        "am": ("ተጋላጭነት", "የደህንነት ችግር"),
    },
    "data_breach": {
        "shared": ("data breach", "data leak", "data exfiltration"),
        "en": ("exposed customer data", "leaked customer records", "personal information exposed", "stolen customer records"),
        "am": ("የውሂብ ጥሰት", "የደንበኞች መረጃ ተጋለጠ", "መረጃ ተሰረቀ"),
        "om": ("data breach", "deetaa saame", "odeeffannoo saame"),
    },
    "ddos": {
        "shared": ("ddos", "distributed denial of service", "denial-of-service", "denial of service attack"),
        "en": ("traffic flood attack",),
        "am": ("የአገልግሎት መከልከል",),
    },
    "cyber_espionage": {
        "shared": ("cyber espionage", "cyber-espionage"),
        "en": ("espionage campaign", "state-sponsored spying", "spying operation targeting"),
        "am": ("የሳይበር ስለላ",),
    },
    "credential_theft": {
        "shared": ("credential theft", "stolen credentials", "password theft", "credentials stolen", "credential harvesting"),
        "en": ("login credentials were stolen", "password stealing malware", "stole user passwords", "stolen access tokens"),
        "am": ("የይለፍ ቃል ተሰረቀ", "የመግቢያ መረጃ ተሰረቀ"),
        "om": ("iggitaa saame", "lakkadda gahiinsaa saame"),
    },
    "other": {
        "shared": ("cyber attack", "cyberattack", "cyber incident", "cybercrime"),
        "en": ("security incident", "network intrusion", "unauthorized network access", "computer hacking"),
        "am": ("የሳይበር ጥቃት", "የደህንነት ክስተት"),
        "om": ("haleellaa saayibaraa",),
    },
}

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


@dataclass(frozen=True)
class CategoryPrediction:
    category: str
    confidence: float | None
    evidence: tuple[str, ...]

    def as_dict(self) -> dict:
        result = asdict(self)
        result["evidence"] = list(self.evidence)
        return result


@dataclass(frozen=True)
class ThreatClassification:
    language: str
    categories: tuple[CategoryPrediction, ...]
    method: str
    status: str
    classified_at: str
    version: str = CLASSIFIER_VERSION

    def as_dict(self) -> dict:
        return {
            "language": self.language,
            "categories": [category.as_dict() for category in self.categories],
            "method": self.method,
            "status": self.status,
            "classified_at": self.classified_at,
            "version": self.version,
        }


def _matches(text: str, cues: Iterable[str]) -> list[str]:
    found: list[str] = []
    for cue in cues:
        cue_norm = unicodedata.normalize("NFKC", cue).casefold()
        if cue_norm == "cve":
            found.extend(match.group(0) for match in _CVE_RE.finditer(text))
        elif cue_norm and cue_norm in text and cue_norm not in found:
            found.append(cue_norm)
    return found


def _language_groups(language: str) -> tuple[str, ...]:
    if language in {"en", "am", "om"}:
        return ("shared", language)
    if language == "mul":
        return ("shared", "en", "am", "om")
    # Unknown language can only match universal technical terms. We never
    # reinterpret unknown Latin text as English.
    return ("shared",)


def classify_text(
    *, title: str | None, description: str | None, content: str | None,
    language: str = "und",
) -> ThreatClassification:
    """Return multi-label keyword predictions plus evidence and provenance."""
    language = language if language in SUPPORTED_LANGUAGES else "und"
    parts = [part.strip() for part in (title, description, content) if part and part.strip()]
    text = unicodedata.normalize("NFKC", "\n".join(parts)).casefold()
    text = re.sub(r"\b(?:https?://|www\.)\S+", " ", text)
    groups = _language_groups(language)
    predictions: list[CategoryPrediction] = []

    for category, language_cues in _CUES.items():
        evidence: list[str] = []
        for group in groups:
            evidence.extend(_matches(text, language_cues.get(group, ())))
        # Keep the evidence list deterministic and concise.
        evidence = list(dict.fromkeys(evidence))
        if evidence:
            score = min(0.94, 0.70 + 0.06 * (len(evidence) - 1))
            if score >= MIN_CATEGORY_CONFIDENCE:
                predictions.append(CategoryPrediction(category, round(score, 3), tuple(evidence)))

    # `other` is a fallback cyber category, not an additional label when a
    # more specific rule already matched.
    if any(prediction.category != "other" for prediction in predictions):
        predictions = [prediction for prediction in predictions if prediction.category != "other"]
    if not predictions:
        predictions = [CategoryPrediction("unknown", 0.0, ())]

    return ThreatClassification(
        language=language,
        categories=tuple(predictions),
        method=CLASSIFIER_METHOD,
        status="classified" if predictions[0].category != "unknown" else "unknown",
        classified_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )


def classify_article(article: dict) -> ThreatClassification:
    """Classify an article mapping returned by the article store."""
    return classify_text(
        title=article.get("title"),
        description=article.get("summary"),
        content=article.get("content"),
        language=article.get("language", "und"),
    )
