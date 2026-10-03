"""Exposure Analyzer API endpoints."""

from typing import List
from fastapi import APIRouter, HTTPException, status
from guardianos.exposure.models import EndpointProfile, ExposureProfile
from guardianos.exposure.service import exposure_service

router = APIRouter(prefix="/exposure", tags=["Exposure Analyzer"])


@router.get("/endpoints", response_model=List[EndpointProfile])
async def list_endpoints():
    """List registered network endpoints and ingress routes."""
    return exposure_service.list_endpoints()


@router.post("/endpoints", response_model=EndpointProfile, status_code=status.HTTP_201_CREATED)
async def register_endpoint(endpoint: EndpointProfile):
    """Register an endpoint and connect it in the Knowledge Graph."""
    return exposure_service.register_endpoint(endpoint)


@router.get("/{component_name}", response_model=ExposureProfile)
async def get_component_exposure(component_name: str):
    """Retrieve runtime exposure profile distinguishing theoretical vs actually exposed reachability."""
    profile = exposure_service.get_component_exposure(component_name)
    if not profile:
        raise HTTPException(
            status_code=404,
            detail=f"Component '{component_name}' not found in active inventory"
        )
    return profile
