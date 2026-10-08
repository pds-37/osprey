"""Exposure Analyzer API endpoints."""

from typing import List
from fastapi import Depends, HTTPException, status
from guardianos.exposure.models import EndpointProfile, ExposureProfile
from guardianos.exposure.service import exposure_service
from guardianos.api.security import SecuredAPIRouter
from guardianos.core.security import require_single_organization

router = SecuredAPIRouter(prefix="/exposure", tags=["Exposure Analyzer"], dependencies=[Depends(require_single_organization)])


@router.get("/endpoints", response_model=List[EndpointProfile])
async def list_endpoints():
    """List registered endpoint assertions; external ingress is not independently verified."""
    return exposure_service.list_endpoints()


@router.post("/endpoints", response_model=EndpointProfile, status_code=status.HTTP_201_CREATED)
async def register_endpoint(endpoint: EndpointProfile):
    """Register an endpoint and connect it in the Knowledge Graph."""
    return exposure_service.register_endpoint(endpoint)


@router.get("/{component_name}", response_model=ExposureProfile)
async def get_component_exposure(component_name: str):
    """Retrieve source observations and user assertions; public ingress is not independently verified."""
    profile = exposure_service.get_component_exposure(component_name)
    if not profile:
        raise HTTPException(
            status_code=404,
            detail=f"Component '{component_name}' not found in active inventory"
        )
    return profile
