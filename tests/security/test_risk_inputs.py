"""Regression tests for malformed external numeric risk evidence."""

import math

import pytest

from osprey.risk import RiskEvidence, calculate_risk


@pytest.mark.parametrize("value", [10**1_000, math.nan, math.inf, -0.1, 10.1, "9.8", True])
def test_malformed_cvss_remains_unknown_without_raising(value):
    assessment = calculate_risk(RiskEvidence(cvss_score=value))

    assert assessment.decision == "UNKNOWN"
    assert assessment.risk_level == "UNKNOWN"
    assert assessment.score is None
    assert any("CVSS evidence is malformed" in item for item in assessment.limitations)


@pytest.mark.parametrize("value", [10**1_000, math.nan, math.inf, -0.1, 1.1, "0.9", True])
def test_malformed_epss_remains_unknown_without_raising(value):
    assessment = calculate_risk(RiskEvidence(epss_score=value))

    assert assessment.decision == "UNKNOWN"
    assert assessment.risk_level == "UNKNOWN"
    assert assessment.score is None
    assert any("EPSS evidence is malformed" in item for item in assessment.limitations)


def test_malformed_reachability_confidence_cannot_raise_priority():
    assessment = calculate_risk(RiskEvidence(
        reachability_status="REACHABLE",
        reachability_confidence=math.inf,
        source_analysis_complete=True,
    ))

    assert assessment.decision == "UNKNOWN"
    assert assessment.score is None
    assert any("Reachability confidence is malformed" in item for item in assessment.limitations)
