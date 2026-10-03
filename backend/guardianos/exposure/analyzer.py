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
from guardianos.inventory.models import Component, DependencyState


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
    
    is_prod = (component.environment.lower() == "production")
    is_running = (component.state == DependencyState.RUNNING)

    # 1. Network Exposure
    if has_internet:
        score += 40
        reasons.append("Internet-facing: Endpoint is publicly accessible from the external Internet.")
        network_exp = NetworkExposure.INTERNET_FACING
    elif matching_endpoints:
        score += 20
        reasons.append("Internal network: Endpoint reachable within the internal VPC.")
        network_exp = NetworkExposure.INTERNAL_NETWORK
    else:
        network_exp = NetworkExposure.LOCALHOST_ONLY
        reasons.append("Local/Internal only: Component is not bound to public listening routes.")

    # 2. Authentication Requirement
    if unauthenticated and has_internet:
        score += 30
        reasons.append("Unauthenticated: Route accepts requests without authentication tokens or sessions.")
        auth_req = AuthRequirement.NONE
    elif unauthenticated:
        score += 15
        auth_req = AuthRequirement.NONE
    else:
        auth_req = AuthRequirement.REQUIRED
        reasons.append("Authentication required: Ingress requests must present authenticated identity credentials.")

    # 3. Parser / Untrusted Input
    if parser_role:
        score += 20
        reasons.append("Untrusted Input Parser: Component actively parses attacker-supplied binary image/file payloads.")
        proc_type = DataProcessingType.PARSER_UNTRUSTED_INPUT
    else:
        proc_type = DataProcessingType.BUSINESS_LOGIC

    # 4. Environment & Runtime State
    if is_prod and is_running:
        score += 15
        reasons.append("Active Production Workload: Component is executing in live production containers.")
    elif is_prod:
        score += 10
        reasons.append("Production image: Component is packaged into production container images.")

    # Classify exposure rating
    if score >= 85:
        rating = ExposureRating.CRITICAL_EXPOSURE
    elif score >= 60:
        rating = ExposureRating.HIGH_EXPOSURE
    elif score >= 35:
        rating = ExposureRating.MEDIUM_EXPOSURE
    elif score >= 15:
        rating = ExposureRating.LOW_EXPOSURE
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
        asset_criticality=AssetCriticality.TIER_1_HIGH if is_prod else AssetCriticality.TIER_2_MEDIUM,
        is_privileged_runtime=False,
        agent_accessible=True,
        exposure_rating=rating,
        reasons=reasons,
        endpoints=matching_endpoints
    )
