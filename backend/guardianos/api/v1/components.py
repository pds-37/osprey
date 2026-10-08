"""Component Inventory API endpoints."""

from typing import Optional
from fastapi import Depends, HTTPException, Query, status
from guardianos.api.security import SecuredAPIRouter
from guardianos.core.security import CurrentUser, get_current_user, require_single_organization
from guardianos.inventory.models import Component, Ecosystem
from guardianos.inventory.service import inventory_service

router = SecuredAPIRouter(prefix="/components", tags=["Components"])


@router.get("", response_model=list[Component])
async def list_components(
    ecosystem: Optional[Ecosystem] = Query(None, description="Filter by ecosystem"),
    search: Optional[str] = Query(None, description="Search term in name or PURL"),
    application: Optional[str] = Query(None, description="Filter by application"),
    limit: int = Query(200, ge=1, le=1000),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Retrieve normalized inventory of software components."""
    return inventory_service.list_components(
        ecosystem=ecosystem,
        search=search,
        application=application,
        limit=limit,
        organization_id=current_user.org_id,
    )


@router.get("/detail", response_model=Component)
async def get_component(
    purl: str = Query(..., description="Package URL"),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Get single component by PURL."""
    comp = inventory_service.get_component(purl, organization_id=current_user.org_id)
    if not comp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Component {purl} not found")
    return comp


@router.get("/lineage")
async def get_component_lineage(
    purl: str = Query(..., description="Package URL"),
    current_user: CurrentUser = Depends(require_single_organization),
):
    """Retrieve full dependency lineage showing parent containers/apps."""
    lineage = inventory_service.get_component_lineage(purl)
    component = inventory_service.get_component(purl, organization_id=current_user.org_id)
    if not lineage.get("found") or not component:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Component {purl} not found")
    return lineage
