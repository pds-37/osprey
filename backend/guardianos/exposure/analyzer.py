"""Runtime Exposure Analyzer engine evaluating real-world reachability."""

from typing import List
from guardianos.exposure.models import (
    AssetCriticality,
    AuthRequirement,
    DataProcessingType,
    EndpointProfile,
    ExposureProfile,
    ExposureRating,
    NetworkExposure,
)
from guardianos.inventory.models import Component


def evaluate_component_exposure(
    component: Component,
    matching_endpoints: List[EndpointProfile]
) -> ExposureProfile:
    """
    Determine whether a vulnerable component is genuinely exposed or shielded.
    """
    reasons: List[str] = []
    score = 0

    # Determine highest network exposure among connected endpoints
    has_internet = any(ep.network_exposure == NetworkExposure.INTERNET_FACING for ep in matching_endpoints)
    unauthenticated = any(ep.auth_requirement == AuthRequirement.NONE for ep in matching_endpoints)
    parser_role = any(ep.processing_type == DataProcessingType.PARSER_UNTRUSTED_INPUT for ep in matching_endpoints)
    

    # 1. Network Exposure
    if has_internet:
        score += 40
        reasons.append("Configured endpoint metadata labels at least one connected endpoint INTERNET_FACING.")
        network_exp = NetworkExposure.INTERNET_FACING
    elif matching_endpoints and all(ep.network_exposure != NetworkExposure.UNKNOWN for ep in matching_endpoints):
        score += 20
        reasons.append("Configured endpoint metadata reports non-public network exposure.")
        network_exp = NetworkExposure.INTERNAL_NETWORK
    elif matching_endpoints:
        network_exp = NetworkExposure.UNKNOWN
        reasons.append("UNKNOWN: endpoint network exposure is incomplete.")
    else:
        network_exp = NetworkExposure.UNKNOWN
        reasons.append("NOT OBSERVED: no endpoint observation is connected to this component.")

    # 2. Authentication Requirement
    if unauthenticated and has_internet:
        score += 30
        reasons.append("Configured endpoint metadata reports no authentication requirement.")
        auth_req = AuthRequirement.NONE
    elif unauthenticated:
        score += 15
        auth_req = AuthRequirement.NONE
    elif matching_endpoints and all(ep.auth_requirement != AuthRequirement.UNKNOWN for ep in matching_endpoints):
        auth_req = AuthRequirement.REQUIRED
        reasons.append("Configured endpoint metadata indicates authentication is required.")
    else:
        auth_req = AuthRequirement.UNKNOWN
        reasons.append("NOT OBSERVED: endpoint authentication requirements are unavailable.")

    # 3. Parser / Untrusted Input
    if parser_role:
        score += 20
        reasons.append("Configured endpoint metadata identifies untrusted-input parser processing.")
        proc_type = DataProcessingType.PARSER_UNTRUSTED_INPUT
    elif matching_endpoints and len({ep.processing_type for ep in matching_endpoints}) == 1:
        proc_type = matching_endpoints[0].processing_type
    else:
        proc_type = DataProcessingType.UNKNOWN

    # Classify exposure rating
    if score >= 85:
        rating = ExposureRating.CRITICAL_EXPOSURE
    elif score >= 60:
        rating = ExposureRating.HIGH_EXPOSURE
    elif score >= 35:
        rating = ExposureRating.MEDIUM_EXPOSURE
    elif score >= 15:
        rating = ExposureRating.LOW_EXPOSURE
    elif not matching_endpoints:
        rating = ExposureRating.UNKNOWN
    else:
        rating = ExposureRating.MINIMAL_EXPOSURE

    return ExposureProfile(
        component_purl=component.purl,
        component_name=component.name,
        application=component.application,
        environment=component.environment,
        network_exposure=network_exp,
        auth_requirement=auth_req,
        processing_type=proc_type,
        asset_criticality=AssetCriticality.UNKNOWN,
        is_privileged_runtime=None,
        agent_accessible=None,
        exposure_rating=rating,
        reasons=reasons,
        endpoints=matching_endpoints
    )
