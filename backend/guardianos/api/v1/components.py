"""Component Inventory API endpoints."""

from typing import Optional
from fastapi import APIRouter, HTTPException, Query, status
from guardianos.inventory.models import Component, Ecosystem
from guardianos.inventory.service import inventory_service

router = APIRouter(prefix="/components", tags=["Components"])


@router.get("", response_model=list[Component])
async def list_components(
    ecosystem: Optional[Ecosystem] = Query(None, description="Filter by ecosystem"),
    search: Optional[str] = Query(None, description="Search term in name or PURL"),
    application: Optional[str] = Query(None, description="Filter by application"),
    limit: int = Query(200, ge=1, le=1000)
):
    """Retrieve normalized inventory of software components."""
    return inventory_service.list_components(
        ecosystem=ecosystem,
        search=search,
        application=application,
        limit=limit
    )


@router.get("/detail", response_model=Component)
async def get_component(purl: str = Query(..., description="Package URL")):
    """Get single component by PURL."""
    comp = inventory_service.get_component(purl)
    if not comp:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Component {purl} not found")
    return comp


@router.get("/lineage")
async def get_component_lineage(purl: str = Query(..., description="Package URL")):
    """Retrieve full dependency lineage showing parent containers/apps."""
    lineage = inventory_service.get_component_lineage(purl)
    if not lineage.get("found"):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Component {purl} not found")
    return lineage
