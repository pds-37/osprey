"""Patch Propagation API endpoints."""

from typing import List, Optional
from fastapi import Depends, HTTPException, Query, status
from guardianos.propagation.models import PatchPropagationRecord
from guardianos.propagation.service import propagation_service
from guardianos.api.security import SecuredAPIRouter
from guardianos.core.security import require_single_organization

router = SecuredAPIRouter(prefix="/patches", tags=["Patch Propagation"], dependencies=[Depends(require_single_organization)])


@router.get("/propagation", response_model=List[PatchPropagationRecord])
async def list_patch_propagation_records(
    component: Optional[str] = Query(None, description="Filter by component name")
):
    """Retrieve patch propagation status across all vulnerable components."""
    return propagation_service.list_records(component=component)


@router.post("/evaluate", response_model=List[PatchPropagationRecord], status_code=status.HTTP_200_OK)
async def trigger_propagation_evaluation():
    """Trigger real-time patch propagation lifecycle analysis."""
    return propagation_service.evaluate_all()


@router.get("/propagation/{component_name}", response_model=PatchPropagationRecord)
async def get_component_propagation(component_name: str):
    """Get single component patch propagation tracking status."""
    records = propagation_service.list_records(component=component_name)
    if not records:
        raise HTTPException(
            status_code=404,
            detail=f"No propagation record found for component {component_name}"
        )
    return records[0]
