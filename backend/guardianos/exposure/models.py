"""Exposure Analyzer data models."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class NetworkExposure(str, Enum):
    UNKNOWN = "UNKNOWN"
    INTERNET_FACING = "INTERNET_FACING"
    INTERNAL_NETWORK = "INTERNAL_NETWORK"
    LOCALHOST_ONLY = "LOCALHOST_ONLY"
    ISOLATED = "ISOLATED"


class AuthRequirement(str, Enum):
    UNKNOWN = "UNKNOWN"
    NONE = "NONE"
    OPTIONAL = "OPTIONAL"
    REQUIRED = "REQUIRED"
    MFA_REQUIRED = "MFA_REQUIRED"


class DataProcessingType(str, Enum):
    UNKNOWN = "UNKNOWN"
    PARSER_UNTRUSTED_INPUT = "PARSER_UNTRUSTED_INPUT"
    BUSINESS_LOGIC = "BUSINESS_LOGIC"
    BATCH_INTERNAL = "BATCH_INTERNAL"
    ADMIN_ONLY = "ADMIN_ONLY"


class AssetCriticality(str, Enum):
    UNKNOWN = "UNKNOWN"
    TIER_0_CRITICAL = "TIER_0_CRITICAL"
    TIER_1_HIGH = "TIER_1_HIGH"
    TIER_2_MEDIUM = "TIER_2_MEDIUM"
    TIER_3_LOW = "TIER_3_LOW"


class ExposureRating(str, Enum):
    UNKNOWN = "UNKNOWN"
    CRITICAL_EXPOSURE = "CRITICAL_EXPOSURE"
    HIGH_EXPOSURE = "HIGH_EXPOSURE"
    MEDIUM_EXPOSURE = "MEDIUM_EXPOSURE"
    LOW_EXPOSURE = "LOW_EXPOSURE"
    MINIMAL_EXPOSURE = "MINIMAL_EXPOSURE"


class EndpointProfile(BaseModel):
    id: str = Field(..., description="Unique endpoint ID (e.g., ep-image-service-upload)")
    path: str = Field(..., description="HTTP Method and Route (e.g., POST /upload)")
    service: str = Field(..., description="Owning service or application")
    network_exposure: NetworkExposure = NetworkExposure.UNKNOWN
    auth_requirement: AuthRequirement = AuthRequirement.UNKNOWN
    processing_type: DataProcessingType = DataProcessingType.UNKNOWN
    is_public: Optional[bool] = None
    evidence_source: str = "USER_INPUT"
    evidence_ids: List[str] = Field(default_factory=list)
    connected_components: List[str] = Field(default_factory=list, description="Names of libraries directly invoked")


class ExposureProfile(BaseModel):
    component_purl: str
    component_name: str
    application: str
    environment: str
    network_exposure: NetworkExposure
    auth_requirement: AuthRequirement
    processing_type: DataProcessingType
    asset_criticality: AssetCriticality = AssetCriticality.UNKNOWN
    is_privileged_runtime: Optional[bool] = None
    agent_accessible: Optional[bool] = None
    exposure_rating: ExposureRating
    reasons: List[str] = Field(default_factory=list)
    endpoints: List[EndpointProfile] = Field(default_factory=list)
