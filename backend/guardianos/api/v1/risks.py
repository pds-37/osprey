"""Contextual Risk API endpoints."""

from typing import List, Optional
from fastapi import Depends, Query, status
from guardianos.risk.models import ContextualRiskScore
from guardianos.risk.service import risk_service
from guardianos.api.security import SecuredAPIRouter
from guardianos.core.security import require_single_organization

router = SecuredAPIRouter(prefix="/risks", tags=["Contextual Risk"], dependencies=[Depends(require_single_organization)])


@router.get("", response_model=List[ContextualRiskScore])
async def list_risks(
    level: Optional[str] = Query(None, description="Filter by risk level (UNKNOWN, CRITICAL, HIGH, MEDIUM, LOW)")
):
    """Retrieve prioritized contextual risk findings with transparent explainability."""
    return risk_service.list_risks(level=level)


@router.get("/summary")
async def get_risk_summary():
    """Retrieve aggregated risk KPIs for executive dashboard visualization."""
    return risk_service.get_summary()


@router.post("/evaluate", response_model=List[ContextualRiskScore], status_code=status.HTTP_200_OK)
async def evaluate_risks():
    """Trigger complete contextual risk scoring across findings and attack paths."""
    return risk_service.evaluate_all()
