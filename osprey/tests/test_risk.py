"""Tests for the shared deterministic risk engine used by CLI and backend."""

from dataclasses import replace

import pytest

from osprey.risk import RiskEvidence, calculate_risk, classify_risk, parse_advisory_severity


def base_evidence(**updates):
    evidence = RiskEvidence(
        severity="CRITICAL",
        cvss_score=9.8,
        version_status="AFFECTED",
        dependency_present=True,
        exposure="UNKNOWN",
        exposure_confidence="UNKNOWN",
        reachability_status="UNKNOWN",
        source_analysis_complete=True,
    )
    return replace(evidence, **updates)


def test_critical_reachable_has_highest_priority():
    result = calculate_risk(base_evidence(
        exposure="PUBLIC", exposure_confidence="USER_ASSERTED",
        auth_requirement="NONE",
        reachability_status="REACHABLE", reachability_confidence=0.9,
        epss_score=0.12, kev_listed=True,
    ))
    assert result.decision == "ACT NOW"
    assert result.risk_level == "CRITICAL"
    assert result.score is not None
    assert "does not establish deployment or Internet exposure" in result.explanation


def test_critical_not_reachable_remains_a_package_risk():
    result = calculate_risk(base_evidence(
        reachability_status="NOT_REACHABLE", reachability_confidence=0.95,
    ))
    assert result.decision == "PLAN"
    assert result.score is not None
    assert result.risk_level != "LOW"
    assert "bounded negative" in next(f.description for f in result.factors if f.name == "Vulnerable Function Reachability")


def test_critical_unknown_reachability_preserves_unknown_context():
    result = calculate_risk(base_evidence())
    assert result.decision == "PLAN"
    assert result.risk_level == "UNKNOWN"
    assert result.score is None
    assert any("Reachability is UNKNOWN" in limitation for limitation in result.limitations)


def test_incomplete_analysis_cannot_claim_not_reachable():
    result = calculate_risk(base_evidence(
        reachability_status="NOT_REACHABLE", reachability_confidence=0.95,
        source_analysis_complete=False, limitations=("unresolved local import",),
    ))
    factor = next(f for f in result.factors if f.name == "Vulnerable Function Reachability")
    assert factor.score is None
    assert result.decision == "PLAN"
    assert any("Negative reachability is incomplete" in limitation for limitation in result.limitations)


def test_high_reachable_has_more_reachability_evidence_than_no_path():
    reachable = calculate_risk(base_evidence(
        severity="HIGH", cvss_score=8.1, exposure="PUBLIC",
        exposure_confidence="DECLARED", reachability_status="REACHABLE",
        reachability_confidence=0.9,
    ))
    negative = calculate_risk(base_evidence(
        severity="HIGH", cvss_score=8.1, exposure="PUBLIC",
        exposure_confidence="DECLARED", reachability_status="NOT_REACHABLE",
        reachability_confidence=0.95,
    ))
    reach_factor = lambda result: next(f.score for f in result.factors if f.name == "Vulnerable Function Reachability")
    assert reachable.decision == "PLAN"
    assert reach_factor(reachable) > reach_factor(negative)


def test_high_unknown_reachability_is_plan_with_limitation():
    result = calculate_risk(base_evidence(severity="HIGH", cvss_score=8.1))
    assert result.decision == "PLAN"
    assert any("Reachability is UNKNOWN" in limitation for limitation in result.limitations)


def test_kev_true_is_used_only_when_explicitly_available():
    result = calculate_risk(base_evidence(kev_listed=True, reachability_status="REACHABLE", reachability_confidence=0.9))
    assert result.decision == "ACT NOW"
    assert next(f.score for f in result.factors if f.name == "CISA KEV") == 100.0


def test_kev_unavailable_is_not_treated_as_false():
    result = calculate_risk(base_evidence(kev_listed=None))
    assert next(f.score for f in result.factors if f.name == "CISA KEV") is None
    assert any("not treated as false" in limitation for limitation in result.limitations)


def test_kev_false_is_distinct_from_unavailable():
    result = calculate_risk(base_evidence(kev_listed=False))
    assert next(f.score for f in result.factors if f.name == "CISA KEV") == 0.0


def test_explicit_kev_signal_can_prioritize_when_severity_is_missing():
    result = calculate_risk(base_evidence(severity="UNKNOWN", cvss_score=None, kev_listed=True))
    assert result.decision == "PLAN"
    assert result.risk_level == "UNKNOWN"
    assert result.score is None


def test_epss_available_contributes_to_factor():
    result = calculate_risk(base_evidence(epss_score=0.35))
    assert next(f.score for f in result.factors if f.name == "EPSS") == 35.0


def test_epss_unavailable_is_not_zero():
    result = calculate_risk(base_evidence(epss_score=None))
    assert next(f.score for f in result.factors if f.name == "EPSS") is None
    assert any("EPSS is unavailable" in limitation for limitation in result.limitations)


@pytest.mark.parametrize(("exposure", "expected"), [
    ("PUBLIC", 60.0), ("INTERNAL", 40.0), ("LOCAL", 15.0),
])
def test_known_exposure_categories_have_separate_factors(exposure, expected):
    result = calculate_risk(base_evidence(exposure=exposure, exposure_confidence="USER_ASSERTED"))
    assert next(f.score for f in result.factors if f.name == "Network Exposure & Ingress") == expected


@pytest.mark.parametrize(("auth_requirement", "expected"), [
    ("NONE", 100.0), ("REQUIRED", 70.0), ("UNKNOWN", 60.0),
])
def test_public_exposure_retains_authentication_evidence(auth_requirement, expected):
    result = calculate_risk(base_evidence(
        exposure="PUBLIC", exposure_confidence="USER_ASSERTED",
        auth_requirement=auth_requirement,
    ))
    assert next(f.score for f in result.factors if f.name == "Network Exposure & Ingress") == expected


def test_unknown_exposure_is_not_internal():
    result = calculate_risk(base_evidence(exposure="UNKNOWN", exposure_confidence="UNKNOWN"))
    assert next(f.score for f in result.factors if f.name == "Network Exposure & Ingress") is None
    assert any("Exposure is UNKNOWN" in limitation for limitation in result.limitations)


def test_public_exposure_without_supported_confidence_is_unknown():
    result = calculate_risk(base_evidence(exposure="PUBLIC", exposure_confidence="UNKNOWN"))
    assert next(f.score for f in result.factors if f.name == "Network Exposure & Ingress") is None
    assert any("confidence/evidence label" in limitation for limitation in result.limitations)


def test_confirmed_affected_version_is_separate_from_unknown_version():
    confirmed = calculate_risk(base_evidence(version_status="AFFECTED"))
    uncertain = calculate_risk(base_evidence(version_status="UNKNOWN"))
    assert next(f.score for f in confirmed.factors if f.name == "Affected Version Certainty") == 100.0
    assert uncertain.decision == "UNKNOWN"
    assert next(f.score for f in uncertain.factors if f.name == "Affected Version Certainty") is None


def test_unknown_dependency_presence_does_not_become_installed():
    result = calculate_risk(base_evidence(dependency_present=None))
    assert result.decision == "UNKNOWN"


def test_explicit_not_affected_version_is_ignored():
    result = calculate_risk(base_evidence(version_status="NOT_AFFECTED"))
    assert result.decision == "IGNORE"


def test_missing_optional_evidence_remains_unavailable():
    result = calculate_risk(RiskEvidence(
        severity="HIGH", version_status="AFFECTED", dependency_present=True,
        exposure="UNKNOWN", reachability_status="UNKNOWN",
    ))
    assert result.score is None
    assert result.risk_level == "UNKNOWN"
    assert result.decision == "PLAN"
    assert any("CVSS is unavailable" in limitation or "Numeric CVSS is unavailable" in limitation for limitation in result.limitations)


def test_low_severity_does_not_become_urgent_from_missing_evidence():
    result = calculate_risk(base_evidence(
        severity="LOW", cvss_score=3.0, exposure="INTERNAL",
        exposure_confidence="USER_ASSERTED", reachability_status="NOT_REACHABLE",
        reachability_confidence=0.95,
    ))
    assert result.decision == "MONITOR"


def test_combined_evidence_is_explainable_and_deterministic():
    evidence = base_evidence(
        exposure="PUBLIC", exposure_confidence="DECLARED",
        processing_type="PARSER_UNTRUSTED_INPUT",
        reachability_status="REACHABLE", reachability_confidence=0.95,
        epss_score=0.42, kev_listed=True, evidence_ids=("ev-route", "ev-call"),
    )
    first = calculate_risk(evidence)
    assert first == calculate_risk(evidence)
    assert first.evidence_ids == ("ev-route", "ev-call")
    assert len(first.factors) >= 7
    assert first.explanation


@pytest.mark.parametrize("bad_evidence", [None, {}, "invalid"])
def test_malformed_risk_evidence_fails_safely(bad_evidence):
    result = calculate_risk(bad_evidence)
    assert result.score is None
    assert result.risk_level == "UNKNOWN"
    assert result.decision == "UNKNOWN"
    assert result.limitations


def test_malformed_numeric_values_do_not_create_false_certainty():
    result = calculate_risk(base_evidence(
        cvss_score=99, epss_score=-1, reachability_status="REACHABLE",
        reachability_confidence=2, version_status="SOMETHING_ELSE",
    ))
    assert result.decision == "UNKNOWN"
    assert any("CVSS evidence is malformed" in limitation for limitation in result.limitations)
    assert any("EPSS evidence is malformed" in limitation for limitation in result.limitations)


@pytest.mark.parametrize("evidence", [
    base_evidence(
        exposure="PUBLIC", exposure_confidence="DECLARED",
        reachability_status="REACHABLE", reachability_confidence=0.9,
    ),
    base_evidence(severity="HIGH", cvss_score=8.1),
    base_evidence(
        reachability_status="NOT_REACHABLE", reachability_confidence=0.95,
    ),
])
def test_cli_backend_parity_for_same_normalized_evidence(evidence):
    shared = calculate_risk(evidence)
    cli_decision, cli_explanation = classify_risk(
        exposure_level=evidence.exposure,
        exposure_confidence=evidence.exposure_confidence,
        cvss_score=evidence.cvss_score,
        epss_score=evidence.epss_score,
        in_cisa_kev=evidence.kev_listed if evidence.kev_listed is not None else False,
        kev_available=evidence.kev_listed is not None,
        severity=evidence.severity,
        version_status=evidence.version_status,
        reachability_status=evidence.reachability_status,
        reachability_confidence=evidence.reachability_confidence,
    )
    assert (cli_decision, cli_explanation) == (shared.decision, shared.explanation)


def test_osv_severity_parser_does_not_invent_numeric_scores():
    assert parse_advisory_severity({"severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}]}) == ("UNKNOWN", None)
    assert parse_advisory_severity({"database_specific": {"severity": "HIGH"}}) == ("HIGH", None)
    assert parse_advisory_severity({"severity": [{"type": "CVSS_V3", "score": "8.1"}]}) == ("HIGH", 8.1)
