"""Evidence-led, explainable triage severity assessment.

This is a deterministic policy, not a risk model or probability. Article text is
treated only as a source-reported claim. External evidence is considered
verified only when a caller supplies source identity, URL, and retrieval time
with verification_status='verified'; this module performs no network lookup.
CVSS v3.x/v4 qualitative bands follow FIRST's published rating scale.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

SEVERITY_LEVELS = ("Critical", "High", "Medium", "Low", "Informational", "Unknown")
ASSESSMENT_METHOD = "evidence_policy_rules"
ASSESSMENT_VERSION = "1.0"

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_CVSS_VERSIONED_RE = re.compile(
    r"\bCVSS\s+v?(?:3(?:\.\d)?|4(?:\.0)?)(?:\s*:\s*|\s+score\b\s*[:=]?\s*|\s+)(10(?:\.0)?|[0-9](?:\.\d)?)\b", re.I
)
_CVSS_SIMPLE_RE = re.compile(
    r"\bCVSS(?:\s+(?:base\s+)?score)?\s*[:=]?\s*(10(?:\.0)?|[0-9](?:\.\d)?)\b", re.I
)
_EXPLOIT_POSITIVE = re.compile(r"\b(?:actively exploited|exploited in the wild|exploitation observed|confirmed exploitation|known exploited)\b", re.I)
_POC = re.compile(r"\b(?:proof[- ]of[- ]concept|\bpoc\b)\s*(?:exploit|code)?", re.I)
_EXPLOIT_NEGATIVE = re.compile(r"\b(?:not exploited|no exploitation evidence|no evidence of exploitation|not known to be exploited)\b", re.I)
_IMPACT_PATTERNS = {
    "data_exposure": re.compile(r"\b(?:data exposed|data breach|records leaked|data stolen|information exfiltrated)\b", re.I),
    "service_disruption": re.compile(r"\b(?:service disrupted|service outage|services unavailable|systems taken offline|operations disrupted)\b", re.I),
    "unauthorized_access": re.compile(r"\b(?:unauthorized access|unauthorised access|account compromise|systems compromised|intrusion confirmed)\b", re.I),
}
_POTENTIAL = re.compile(r"\b(?:could allow|may allow|potential(?:ly)? (?:expose|disrupt|compromise)|could lead to|risk of)\b", re.I)
_INFORMATIONAL = re.compile(r"\b(?:informational advisory|security awareness notice|no known impact)\b", re.I)
_NO_IMPACT = re.compile(r"\b(?:no confirmed impact|no data exposure|no service disruption|no unauthorized access)\b", re.I)
_PRODUCT_RE = re.compile(r"\b(?:affected product|products affected|product affected)\s*[:=]\s*([^.;\n]{2,100})", re.I)


@dataclass(frozen=True)
class SeverityAssessment:
    severity: str
    explanation: str
    evidence: tuple[dict[str, Any], ...]
    method: str
    assessed_at: str
    status: str
    evidence_completeness: dict[str, Any]
    exploitation_status: str
    impact_status: str
    cve_ids: tuple[str, ...]
    cvss_score: float | None
    affected_products: tuple[str, ...]
    version: str = ASSESSMENT_VERSION

    def as_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["evidence"] = list(self.evidence)
        value["cve_ids"] = list(self.cve_ids)
        value["affected_products"] = list(self.affected_products)
        return value


def _score_severity(score: float) -> str:
    if score == 0:
        return "Informational"
    if score < 4:
        return "Low"
    if score < 7:
        return "Medium"
    if score < 9:
        return "High"
    return "Critical"


def _valid_verified(item: dict[str, Any]) -> bool:
    source_url = urlparse(str(item.get("source_url") or ""))
    try:
        retrieved = datetime.fromisoformat(str(item.get("retrieved_at") or "").replace("Z", "+00:00"))
        has_timezone = retrieved.tzinfo is not None
    except ValueError:
        has_timezone = False
    return (
        item.get("verification_status") == "verified"
        and bool(item.get("source_name"))
        and source_url.scheme == "https" and bool(source_url.netloc)
        and has_timezone
    )


def _record_evidence(evidence: list[dict[str, Any]], *, kind: str, value: Any,
                     status: str, source: str, url: str | None, detail: str | None = None) -> None:
    record = {"type": kind, "value": value, "evidentiary_status": status,
              "source_name": source, "source_url": url}
    if detail:
        record["detail"] = detail
    evidence.append(record)


def assess_severity(article: dict[str, Any],
                    external_evidence: list[dict[str, Any]] | None = None) -> SeverityAssessment:
    """Assess a report conservatively; never equate absent evidence with safety.

    Optional external evidence records may contain `type` (`cvss`,
    `exploitation`, or `impact`), `value`, `verification_status`, source_name,
    source_url, retrieved_at, and optional detail/CVE/product. Merely passing
    an article citation does not make a record verified.
    """
    source = str(article.get("source") or "Unknown source")
    article_url = article.get("url")
    text = "\n".join(str(article.get(key) or "") for key in ("title", "summary", "content"))
    evidence: list[dict[str, Any]] = []
    conflicts: list[str] = []
    reported_exploit = bool(_EXPLOIT_POSITIVE.search(text))
    denied_exploit = bool(_EXPLOIT_NEGATIVE.search(text))
    poc = bool(_POC.search(text))
    if reported_exploit:
        _record_evidence(evidence, kind="exploitation", value="reported_exploitation",
                         status="reported_claim", source=source, url=article_url,
                         detail="The article reports exploitation; it has not been independently confirmed here.")
    if poc:
        _record_evidence(evidence, kind="exploitation", value="proof_of_concept_reported",
                         status="reported_claim", source=source, url=article_url)
    if denied_exploit:
        _record_evidence(evidence, kind="exploitation", value="no_exploitation_evidence_reported",
                         status="reported_claim", source=source, url=article_url)
    if reported_exploit and denied_exploit:
        conflicts.append("The article contains both exploitation and no-exploitation statements.")

    reported_impacts = []
    potential_impact = bool(_POTENTIAL.search(text))
    for impact, pattern in _IMPACT_PATTERNS.items():
        if pattern.search(text):
            reported_impacts.append(impact)
            _record_evidence(evidence, kind="impact", value=impact, status="reported_claim",
                             source=source, url=article_url,
                             detail="Impact is stated in the report and is not independently verified.")
    if potential_impact:
        _record_evidence(evidence, kind="impact", value="potential_impact_only",
                         status="reported_claim", source=source, url=article_url)

    cves = sorted(set(match.upper() for match in _CVE_RE.findall(text)))
    score_matches = list(_CVSS_VERSIONED_RE.finditer(text))
    score_spans = {match.span() for match in score_matches}
    score_matches += [match for match in _CVSS_SIMPLE_RE.finditer(text)
                      if not any(start <= match.start() < end for start, end in score_spans)]
    scores = [float(match.group(1)) for match in score_matches]
    if any(score > 10 for score in scores):
        conflicts.append("A reported CVSS score is outside the 0.0–10.0 range.")
        scores = [score for score in scores if score <= 10]
    for cve in cves:
        _record_evidence(evidence, kind="vulnerability_identifier", value=cve,
                         status="reported_claim", source=source, url=article_url,
                         detail="Identifier extracted from article text; existence and affected product were not checked.")
    for score in scores:
        _record_evidence(evidence, kind="cvss_score", value=score,
                         status="reported_claim", source=source, url=article_url,
                         detail="Score found in article text; no external score source was retrieved or checked.")
    if len(set(scores)) > 1:
        conflicts.append("The article contains conflicting CVSS scores.")
    products = [match.group(1).strip() for match in _PRODUCT_RE.finditer(text)]
    for product in products:
        _record_evidence(evidence, kind="affected_product", value=product,
                         status="reported_claim", source=source, url=article_url)

    validated = [item for item in (external_evidence or []) if _valid_verified(item)]
    unvalidated_external = [item for item in (external_evidence or []) if not _valid_verified(item)]
    for item in unvalidated_external:
        _record_evidence(evidence, kind=str(item.get("type", "external")),
                         value=item.get("value"), status="reported_claim",
                         source=str(item.get("source_name") or source),
                         url=item.get("source_url") or article_url,
                         detail="External evidence lacks verified status or complete source/retrieval provenance.")
    verified_scores: list[float] = []
    verified_exploitation = False
    verified_impacts: list[str] = []
    verified_products: list[str] = []
    external_cves: list[str] = []
    for item in validated:
        item_type = item.get("type")
        value = item.get("value")
        if item_type == "cvss":
            try:
                score = float(value)
            except (TypeError, ValueError):
                conflicts.append("Verified CVSS evidence contains a non-numeric score.")
                continue
            if not 0 <= score <= 10:
                conflicts.append("Verified CVSS score is outside the 0.0–10.0 range.")
                continue
            verified_scores.append(score)
        elif item_type == "exploitation" and value == "confirmed_exploitation":
            verified_exploitation = True
        elif item_type == "impact" and value in {"data_exposure", "service_disruption", "unauthorized_access"}:
            verified_impacts.append(str(value))
        elif item_type == "affected_product" and value:
            verified_products.append(str(value))
        if item.get("cve"):
            external_cves.append(str(item["cve"]).upper())
        evidence.append({
            "type": str(item_type or "external"), "value": value,
            "evidentiary_status": "verified_external",
            "source_name": str(item["source_name"]), "source_url": str(item["source_url"]),
            "retrieved_at": str(item["retrieved_at"]), "detail": item.get("detail"),
        })

    if len(set(verified_scores)) > 1:
        conflicts.append("Verified sources provide conflicting CVSS scores.")
    if verified_scores and scores and any(_score_severity(score) != _score_severity(verified_scores[0]) for score in scores):
        conflicts.append("The verified CVSS severity conflicts with a score reported in the article.")
    if verified_exploitation and denied_exploit:
        conflicts.append("Verified exploitation evidence conflicts with a report stating no exploitation evidence.")
    if _NO_IMPACT.search(text) and verified_impacts:
        conflicts.append("Verified impact evidence conflicts with a report stating no confirmed impact.")
    if len(set(verified_impacts)) > 1 and any(
        item.get("type") == "impact" and item.get("verification_status") == "verified"
        and item.get("value") == "no_confirmed_impact" for item in external_evidence or []
    ):
        conflicts.append("Verified impact evidence conflicts with a no-impact record.")

    cvss = verified_scores[0] if len(set(verified_scores)) == 1 else (scores[0] if len(set(scores)) == 1 else None)
    severity = "Unknown"
    status = "insufficient_evidence"
    explanation = "Severity is unknown because available evidence is insufficient; missing evidence is not evidence of safety."
    if conflicts:
        status = "conflicting_evidence"
        explanation = "Severity is unknown because evidence conflicts: " + " ".join(dict.fromkeys(conflicts))
    elif verified_scores and _score_severity(verified_scores[0]) == "Critical":
        severity = "Critical"
        status = "externally_supported"
        explanation = f"{severity} follows verified CVSS score {verified_scores[0]:.1f} from a documented external source. CVSS rates vulnerability severity, not full incident risk."
    elif verified_exploitation and verified_impacts:
        severity = "High"
        status = "externally_supported"
        explanation = "High priority follows documented confirmed exploitation plus at least one documented confirmed impact. No Critical rating is inferred without a verified Critical CVSS rating."
    elif verified_scores and _score_severity(verified_scores[0]) == "High":
        severity = "High"
        status = "externally_supported"
        explanation = f"High follows verified CVSS score {verified_scores[0]:.1f}; CVSS characterizes vulnerability severity, not full incident risk."
    elif verified_exploitation:
        severity = "Medium"
        status = "externally_supported"
        explanation = "Medium priority follows documented confirmed exploitation; no confirmed impact or Critical/High CVSS score is available."
    elif verified_impacts:
        severity = "Medium"
        status = "externally_supported"
        explanation = "Medium priority follows at least one documented confirmed impact. Impact scale and broader incident risk remain unknown without additional evidence."
    elif verified_scores:
        severity = _score_severity(verified_scores[0])
        status = "externally_supported"
        explanation = f"{severity} follows verified CVSS score {verified_scores[0]:.1f} from a documented external source. CVSS rates vulnerability severity, not full incident risk."
    elif scores and len(set(scores)) == 1:
        severity = _score_severity(scores[0])
        status = "preliminary_reported_claim"
        explanation = f"{severity} is a preliminary mapping of the article-reported CVSS score {scores[0]:.1f}; the score was not externally verified."
    elif reported_exploit or poc or reported_impacts or potential_impact:
        severity = "Medium"
        status = "preliminary_reported_claim"
        explanation = "Medium review priority is based on source-reported exploitation, proof-of-concept, or impact evidence. These claims were not independently verified."
    elif _INFORMATIONAL.search(text):
        severity = "Informational"
        status = "preliminary_reported_claim"
        explanation = "The source explicitly describes an informational or awareness notice and no stronger severity evidence was identified."

    known = {
        "source_identity": bool(article.get("source")),
        "publication_date": bool(article.get("published_at")),
        "original_url": bool(article_url),
        "exploitation_evidence": bool(reported_exploit or denied_exploit or poc or any(item.get("type") == "exploitation" for item in validated)),
        "impact_evidence": bool(reported_impacts or potential_impact or any(item.get("type") == "impact" for item in validated)),
        "cve_identifier": bool(cves or external_cves),
        "cvss_score": bool(scores or verified_scores),
        "affected_product": bool(products or verified_products),
    }
    complete_count = sum(known.values())
    completeness = {"known_fields": complete_count, "total_fields": len(known),
                    "ratio": round(complete_count / len(known), 3), "fields": known}
    evidence.insert(0, {
        "type": "source_metadata",
        "value": {"title": article.get("title"), "published_at": article.get("published_at")},
        "evidentiary_status": "source_attribution",
        "source_name": source, "source_url": article_url,
        "detail": "Original article provenance; it does not independently verify article claims.",
    })
    exploit_status = "confirmed" if verified_exploitation else (
        "reported" if reported_exploit else "proof_of_concept_reported" if poc else "no_evidence_reported" if denied_exploit else "unknown"
    )
    impact_status = "confirmed" if verified_impacts else (
        "reported" if reported_impacts else "potential_only" if potential_impact else "unknown"
    )
    assessed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return SeverityAssessment(
        severity=severity, explanation=explanation, evidence=tuple(evidence),
        method=ASSESSMENT_METHOD, assessed_at=assessed_at, status=status,
        evidence_completeness=completeness, exploitation_status=exploit_status,
        impact_status=impact_status, cve_ids=tuple(sorted(set(cves + external_cves))), cvss_score=cvss,
        affected_products=tuple(dict.fromkeys(products + verified_products)),
    )
