"""Audit Log API endpoints."""

from fastapi import APIRouter, Query
from guardianos.core.audit import AuditEvent, get_recent_audit_events

router = APIRouter(prefix="/audit", tags=["Audit Logs"])


@router.get("/events", response_model=list[AuditEvent])
async def list_audit_events(limit: int = Query(100, ge=1, le=500)):
    """Retrieve recent operational audit events."""
    return get_recent_audit_events(limit=limit)
