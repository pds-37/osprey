"""Shared deterministic, evidence-aware risk calculation for CLI and API.

Scores are normalized indicators over observed evidence, not CVSS values or
exploitability probabilities. Missing evidence is omitted from the composite
and retained as an explicit limitation.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
from typing import Optional, Tuple


@dataclass(frozen=True)
class RiskEvidence:
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    kev_listed: Optional[bool] = None
    version_status: str = "UNKNOWN"
    dependency_present: Optional[bool] = None
    exposure: str = "UNKNOWN"
    exposure_confidence: str = "UNKNOWN"
    auth_requirement: str = "UNKNOWN"
    processing_type: str = "UNKNOWN"
    reachability_status: str = "UNKNOWN"
    reachability_confidence: Optional[float] = None
    source_analysis_complete: Optional[bool] = None
    runtime_observed: Optional[bool] = None
    evidence_ids: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


@dataclass(frozen=True)
class RiskFactor:
    name: str
    weight: float
    score: Optional[float]
    description: str


@dataclass(frozen=True)
class RiskAssessment:
    score: Optional[float]
    risk_level: str
    decision: str
    factors: tuple[RiskFactor, ...]
    explanation: str
    limitations: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    evidence_coverage: float


_WEIGHTS = {
    "Vulnerability Severity": 0.20,
    "Network Exposure & Ingress": 0.25,
    "Untrusted Input Processing": 0.10,
    "Vulnerable Function Reachability": 0.25,
    "Runtime Presence": 0.05,
    "EPSS": 0.05,
    "CISA KEV": 0.05,
    "Affected Version Certainty": 0.05,
}
_SEVERITY_SCORES = {"CRITICAL": 90.0, "HIGH": 75.0, "MEDIUM": 50.0, "MODERATE": 50.0, "LOW": 25.0}


def parse_advisory_severity(advisory: dict) -> tuple[str, Optional[float]]:
    """Read only explicit numeric CVSS or categorical advisory severity values."""
    if not isinstance(advisory, dict):
        return "UNKNOWN", None
    severity = "UNKNOWN"
    cvss: Optional[float] = None
    database_specific = advisory.get("database_specific")
    if isinstance(database_specific, dict):
        label = database_specific.get("severity")
        if isinstance(label, str) and label.strip().upper() in _SEVERITY_SCORES:
            severity = label.strip().upper()
            if severity == "MODERATE":
                severity = "MEDIUM"
    severity_items = advisory.get("severity", [])
    if not isinstance(severity_items, list):
        severity_items = []
    for item in severity_items:
        if not isinstance(item, dict) or item.get("type") not in {"CVSS_V3", "CVSS_V4"}:
            continue
        raw_score = item.get("score")
        if isinstance(raw_score, str):
            try:
                raw_score = float(raw_score)
            except ValueError:
                continue
        parsed = _number(raw_score, 0.0, 10.0)
        if parsed is None:
            continue
        cvss = parsed
        if severity == "UNKNOWN":
            severity = (
                "CRITICAL" if parsed >= 9.0 else
                "HIGH" if parsed >= 7.0 else
                "MEDIUM" if parsed >= 4.0 else "LOW"
            )
        break
    return severity, cvss


def _number(value: object, low: float, high: float) -> Optional[float]:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        number = float(value)
    except (OverflowError, TypeError, ValueError):
        return None
    return number if math.isfinite(number) and low <= number <= high else None


def calculate_risk(evidence: RiskEvidence) -> RiskAssessment:
    """Calculate one deterministic assessment from normalized evidence."""
    if not isinstance(evidence, RiskEvidence):
        return RiskAssessment(
            score=None,
            risk_level="UNKNOWN",
            decision="UNKNOWN",
            factors=(),
            explanation="UNKNOWN: risk evidence could not be normalized safely.",
            limitations=("Risk evidence is malformed; no score or decision was inferred.",),
            evidence_ids=(),
            evidence_coverage=0.0,
        )
    supplied_limitations = evidence.limitations
    if isinstance(supplied_limitations, str):
        supplied_limitations = (supplied_limitations,)
    elif not isinstance(supplied_limitations, (tuple, list)):
        supplied_limitations = ()
    limitations = list(dict.fromkeys(str(item) for item in supplied_limitations if item))
    supplied_evidence_ids = evidence.evidence_ids
    if isinstance(supplied_evidence_ids, str):
        supplied_evidence_ids = (supplied_evidence_ids,)
    elif not isinstance(supplied_evidence_ids, (tuple, list)):
        supplied_evidence_ids = ()
    cvss = _number(evidence.cvss_score, 0.0, 10.0)
    if evidence.cvss_score is not None and cvss is None:
        limitations.append("CVSS evidence is malformed or outside the supported 0-10 range.")
    epss = _number(evidence.epss_score, 0.0, 1.0)
    if evidence.epss_score is not None and epss is None:
        limitations.append("EPSS evidence is malformed or outside the supported 0-1 range.")
    kev_listed = evidence.kev_listed
    if kev_listed is not None and not isinstance(kev_listed, bool):
        kev_listed = None
        limitations.append("CISA KEV evidence is malformed and is treated as unavailable.")
    runtime_observed = evidence.runtime_observed
    if runtime_observed is not None and not isinstance(runtime_observed, bool):
        runtime_observed = None
        limitations.append("Runtime presence evidence is malformed and is treated as unavailable.")

    severity = str(evidence.severity or "").strip().upper()
    severity_score = cvss * 10.0 if cvss is not None else _SEVERITY_SCORES.get(severity)
    if cvss is None and severity_score is not None:
        limitations.append("Numeric CVSS is unavailable; the advisory severity category is used as a coarse signal.")
    elif severity_score is None:
        limitations.append("Vulnerability severity and CVSS are unavailable or unsupported.")

    version_status = str(evidence.version_status or "UNKNOWN").strip().upper()
    if version_status not in {"AFFECTED", "NOT_AFFECTED", "UNKNOWN"}:
        limitations.append("Version certainty is unsupported; it is treated as UNKNOWN.")
        version_status = "UNKNOWN"

    dependency_present = evidence.dependency_present
    if dependency_present is not None and not isinstance(dependency_present, bool):
        limitations.append("Dependency presence evidence is malformed and is treated as UNKNOWN.")
        dependency_present = None

    if dependency_present is False or version_status == "NOT_AFFECTED":
        if dependency_present is False:
            factor = RiskFactor(
                name="Dependency Presence", weight=1.0, score=0.0,
                description="Explicit inventory evidence indicates the dependency is absent.",
            )
        else:
            factor = RiskFactor(
                name="Affected Version Certainty", weight=1.0, score=0.0,
                description="Version evidence explicitly places the installed version outside the affected range.",
            )
        return RiskAssessment(
            score=0.0,
            risk_level="LOW",
            decision="IGNORE",
            factors=(factor,),
            explanation="IGNORE: supplied inventory/version evidence explicitly indicates this finding does not apply.",
            limitations=tuple(dict.fromkeys(limitations)),
            evidence_ids=tuple(dict.fromkeys(str(item) for item in supplied_evidence_ids if item)),
            evidence_coverage=1.0,
        )

    exposure = str(evidence.exposure or "UNKNOWN").strip().upper().replace("-", "_")
    exposure_aliases = {
        "PUBLIC": "PUBLIC", "INTERNET_FACING": "PUBLIC", "EXTERNAL": "PUBLIC",
        "INTERNAL": "INTERNAL", "INTERNAL_NETWORK": "INTERNAL",
        "LOCAL": "LOCAL", "LOCALHOST_ONLY": "LOCAL", "ISOLATED": "LOCAL",
        "DEV_ONLY": "DEV_ONLY", "UNKNOWN": "UNKNOWN",
    }
    exposure = exposure_aliases.get(exposure, "UNKNOWN")
    if exposure == "UNKNOWN" and str(evidence.exposure or "UNKNOWN").strip().upper() not in {"UNKNOWN", ""}:
        limitations.append("Exposure evidence is unsupported and is treated as UNKNOWN.")

    processing = str(evidence.processing_type or "UNKNOWN").strip().upper()
    processing_scores = {
        "PARSER_UNTRUSTED_INPUT": 100.0,
        "PARSER": 100.0,
        "BUSINESS_LOGIC": 50.0,
        "BATCH_INTERNAL": 25.0,
        "ADMIN_ONLY": 15.0,
    }
    if processing not in processing_scores and processing != "UNKNOWN":
        limitations.append("Processing context is unsupported and is treated as UNKNOWN.")

    reachability = str(evidence.reachability_status or "UNKNOWN").strip().upper()
    if reachability not in {"REACHABLE", "NOT_REACHABLE", "UNKNOWN"}:
        limitations.append("Reachability status is unsupported and is treated as UNKNOWN.")
        reachability = "UNKNOWN"
    source_analysis_complete = evidence.source_analysis_complete
    if source_analysis_complete is not None and not isinstance(source_analysis_complete, bool):
        source_analysis_complete = None
        limitations.append("Source-analysis completeness is malformed and is treated as UNKNOWN.")
    if reachability == "NOT_REACHABLE" and (
        source_analysis_complete is False or (evidence.limitations and source_analysis_complete is not True)
    ):
        reachability = "UNKNOWN"
        limitations.append("Negative reachability is incomplete because source analysis has limitations.")

    reach_confidence = _number(evidence.reachability_confidence, 0.0, 1.0)
    if evidence.reachability_confidence is not None and reach_confidence is None:
        limitations.append("Reachability confidence is malformed; confidence-sensitive scoring is unavailable.")
    if reachability == "REACHABLE" and reach_confidence is None:
        limitations.append("A reachable status lacks usable confidence evidence.")
    elif reachability in {"REACHABLE", "NOT_REACHABLE"} and reach_confidence is not None and reach_confidence < 0.75:
        limitations.append("Reachability confidence is below the threshold used for confidence-sensitive prioritization.")
    if reachability == "NOT_REACHABLE" and reach_confidence is None:
        limitations.append("A NOT_REACHABLE status lacks usable confidence evidence and is not scored as negative evidence.")

    exposure_confidence = str(evidence.exposure_confidence or "UNKNOWN").strip().upper().replace("-", "_")
    confidence_supported = exposure_confidence in {"VERIFIED", "DECLARED", "USER_ASSERTED"}
    auth_requirement = str(evidence.auth_requirement or "UNKNOWN").strip().upper()
    if auth_requirement not in {"NONE", "OPTIONAL", "REQUIRED", "MFA_REQUIRED", "UNKNOWN"}:
        auth_requirement = "UNKNOWN"
        limitations.append("Authentication evidence is unsupported and is treated as UNKNOWN.")
    exposure_scores = {
        "PUBLIC": 100.0 if auth_requirement == "NONE" else (70.0 if auth_requirement in {"OPTIONAL", "REQUIRED", "MFA_REQUIRED"} else 60.0),
        "INTERNAL": 40.0,
        "LOCAL": 15.0,
    }
    exposure_score = exposure_scores.get(exposure) if confidence_supported else None
    if exposure in exposure_scores and not confidence_supported:
        limitations.append("Exposure category lacks a supported confidence/evidence label and is treated as UNKNOWN.")
    reach_score: Optional[float] = None
    if reachability == "REACHABLE" and reach_confidence is not None:
        reach_score = round(100.0 * reach_confidence, 1)
    elif reachability == "NOT_REACHABLE" and reach_confidence is not None and reach_confidence >= 0.75:
        # A bounded negative result lowers application-path evidence but does not erase package risk.
        reach_score = round(100.0 - 65.0 * reach_confidence, 1)

    factor_specs = [
        ("Vulnerability Severity", severity_score, "CVSS when supplied; otherwise a coarse advisory severity signal."),
        ("Network Exposure & Ingress", exposure_score, "Declared/user-asserted exposure context; route declarations do not establish Internet ingress."),
        ("Untrusted Input Processing", processing_scores.get(processing), "Observed or asserted processing context; this does not itself prove dependency use."),
        ("Vulnerable Function Reachability", reach_score, "A bounded negative result is limited to analyzed source and does not eliminate package-level risk."),
        ("Runtime Presence", 100.0 if runtime_observed is True else (0.0 if runtime_observed is False else None), "Runtime state is scored only when explicitly supplied; absent runtime evidence remains UNKNOWN."),
        ("EPSS", epss * 100.0 if epss is not None else None, "FIRST EPSS probability, when available; it is not an exploitability guarantee."),
        ("CISA KEV", 100.0 if kev_listed is True else (0.0 if kev_listed is False else None), "KEV membership only when catalog availability is known."),
        ("Affected Version Certainty", 100.0 if version_status == "AFFECTED" else (0.0 if version_status == "NOT_AFFECTED" else None), "Advisory version match state; UNKNOWN is not treated as safe."),
    ]
    factors = tuple(
        RiskFactor(name=name, weight=_WEIGHTS[name], score=score, description=description)
        for name, score, description in factor_specs
    )
    observed = [factor for factor in factors if factor.score is not None]
    observed_weight = sum(factor.weight for factor in observed)
    coverage = round(min(observed_weight, 1.0), 3)
    context_names = {
        "Network Exposure & Ingress", "Untrusted Input Processing",
        "Vulnerable Function Reachability", "Runtime Presence",
    }
    has_context = any(factor.name in context_names and factor.score is not None for factor in observed)
    if severity_score is not None and has_context and observed_weight:
        score = round(sum(f.weight * f.score for f in observed if f.score is not None) / observed_weight, 1)
        if score >= 80.0:
            risk_level = "CRITICAL"
        elif score >= 60.0:
            risk_level = "HIGH"
        elif score >= 40.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
    else:
        score = None
        risk_level = "UNKNOWN"
        limitations.append("Risk score is UNKNOWN because vulnerability evidence or application-context evidence is insufficient.")

    if dependency_present is None or version_status == "UNKNOWN":
        decision = "UNKNOWN"
        explanation = "UNKNOWN: dependency presence or affected-version certainty could not be established."
    elif severity_score is None and kev_listed is not True and not (epss is not None and epss >= 0.10):
        decision = "UNKNOWN"
        explanation = "UNKNOWN: vulnerability severity evidence is unavailable or malformed, and no explicit exploitation signal is available."
    elif (
        reachability == "REACHABLE"
        and reach_confidence is not None
        and reach_confidence >= 0.75
        and ((severity_score is not None and severity_score >= 90.0) or kev_listed is True or (epss is not None and epss >= 0.10))
    ):
        decision = "ACT NOW"
        triggers = []
        if severity_score is not None and severity_score >= 90.0:
            triggers.append("critical severity")
        if kev_listed is True:
            triggers.append("CISA KEV listing")
        if epss is not None and epss >= 0.10:
            triggers.append(f"EPSS {epss:.1%}")
        trigger_text = ", ".join(triggers)
        explanation = (
            "ACT NOW: the affected version is confirmed and supported source analysis links the application "
            f"to vulnerable functionality with {trigger_text}. This does not establish deployment or Internet exposure."
        )
    elif (severity_score is not None and severity_score >= 70.0) or kev_listed is True or (epss is not None and epss >= 0.10):
        decision = "PLAN"
        if reachability == "UNKNOWN":
            detail = "reachability could not be established from available evidence"
        elif reachability == "NOT_REACHABLE":
            detail = "bounded source analysis did not establish a path, while the package-level vulnerability remains"
        elif reach_confidence is not None and reach_confidence < 0.75:
            detail = "a supported source path exists, but its confidence is below the ACT NOW threshold"
        elif exposure == "UNKNOWN":
            detail = "a supported source path exists, but deployment exposure remains UNKNOWN"
        else:
            detail = "available evidence warrants remediation planning"
        explanation = f"PLAN: confirmed vulnerability evidence warrants remediation planning; {detail}."
    else:
        decision = "MONITOR"
        explanation = "MONITOR: the confirmed vulnerability signal is lower, and available contextual evidence does not meet a higher-priority rule."

    if exposure == "UNKNOWN":
        limitations.append("Exposure is UNKNOWN; static route evidence does not establish Internet exposure.")
    if reachability == "UNKNOWN":
        limitations.append("Reachability is UNKNOWN; no supported conclusion about vulnerable-function use is available.")
    if epss is None:
        limitations.append("EPSS is unavailable; it was not treated as zero.")
    if kev_listed is None:
        limitations.append("CISA KEV status is unavailable; it was not treated as false.")
    if version_status == "UNKNOWN":
        limitations.append("Affected-version certainty is UNKNOWN; the installed version is not treated as safe or affected.")

    return RiskAssessment(
        score=score,
        risk_level=risk_level,
        decision=decision,
        factors=factors,
        explanation=explanation,
        limitations=tuple(dict.fromkeys(limitations)),
        evidence_ids=tuple(dict.fromkeys(str(item) for item in supplied_evidence_ids if item)),
        evidence_coverage=coverage,
    )


def classify_risk(
    exposure_level: str,
    cvss_score: Optional[float],
    epss_score: Optional[float],
    in_cisa_kev: Optional[bool],
    severity: str = "UNKNOWN",
    reachability_status: str = "UNKNOWN",
    *,
    version_status: str = "UNKNOWN",
    reachability_confidence: Optional[float] = None,
    kev_available: Optional[bool] = None,
    exposure_confidence: str = "UNKNOWN",
) -> Tuple[str, str]:
    """Compatibility adapter for the CLI's existing two-value risk interface."""
    kev_listed = True if in_cisa_kev is True else (False if in_cisa_kev is False and kev_available is True else None)
    confidence = reachability_confidence
    if reachability_status == "REACHABLE" and confidence is None:
        confidence = 1.0
    assessment = calculate_risk(RiskEvidence(
        severity=severity,
        cvss_score=cvss_score,
        epss_score=epss_score,
        kev_listed=kev_listed,
        version_status=version_status,
        dependency_present=True,
        exposure=exposure_level,
        exposure_confidence=exposure_confidence,
        reachability_status=reachability_status,
        reachability_confidence=confidence,
        source_analysis_complete=True,
    ))
    return assessment.decision, assessment.explanation
