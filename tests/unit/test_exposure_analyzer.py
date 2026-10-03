"""Unit tests for Exposure Analyzer."""

from guardianos.exposure.analyzer import evaluate_component_exposure
from guardianos.exposure.models import (
    AuthRequirement,
    DataProcessingType,
    EndpointProfile,
    ExposureRating,
    NetworkExposure,
)
from guardianos.inventory.models import Component, DependencyState, Ecosystem


def test_high_exposure_for_internet_facing_parser():
    comp = Component(
        id="pkg:deb/debian/libheif@1.19.7",
        name="libheif",
        ecosystem=Ecosystem.DEBIAN,
        version="1.19.7",
        purl="pkg:deb/debian/libheif@1.19.7",
        state=DependencyState.RUNNING,
        application="image-service",
        environment="production"
    )

    ep = EndpointProfile(
        id="ep-1",
        path="POST /upload",
        service="image-service",
        network_exposure=NetworkExposure.INTERNET_FACING,
        auth_requirement=AuthRequirement.NONE,
        processing_type=DataProcessingType.PARSER_UNTRUSTED_INPUT,
        is_public=True,
        connected_components=["libheif"]
    )

    profile = evaluate_component_exposure(comp, [ep])

    assert profile.exposure_rating in [ExposureRating.CRITICAL_EXPOSURE, ExposureRating.HIGH_EXPOSURE]
    assert profile.network_exposure == NetworkExposure.INTERNET_FACING
    assert profile.auth_requirement == AuthRequirement.NONE
    assert any("Internet-facing" in r for r in profile.reasons)
    assert any("Untrusted Input Parser" in r for r in profile.reasons)


def test_low_exposure_for_internal_isolated_component():
    comp = Component(
        id="pkg:pypi/local-calc@1.0.0",
        name="local-calc",
        ecosystem=Ecosystem.PYPI,
        version="1.0.0",
        purl="pkg:pypi/local-calc@1.0.0",
        state=DependencyState.DECLARED,
        application="internal-analytics",
        environment="development"
    )

    profile = evaluate_component_exposure(comp, [])

    assert profile.exposure_rating in [ExposureRating.LOW_EXPOSURE, ExposureRating.MINIMAL_EXPOSURE]
    assert profile.network_exposure == NetworkExposure.LOCALHOST_ONLY
