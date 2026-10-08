"""Audit Log API endpoints."""

from fastapi import Depends, Query
from guardianos.api.security import SecuredAPIRouter
from guardianos.core.security import require_single_organization
from guardianos.core.audit import AuditEvent, get_recent_audit_events

router = SecuredAPIRouter(prefix="/audit", tags=["Audit Logs"], dependencies=[Depends(require_single_organization)])


@router.get("/events", response_model=list[AuditEvent])
async def list_audit_events(limit: int = Query(100, ge=1, le=500)):
    """Retrieve recent operational audit events."""
    return get_recent_audit_events(limit=limit)
