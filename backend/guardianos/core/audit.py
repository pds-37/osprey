"""Audit logging service for tracking system changes and actions."""

import logging
from datetime import datetime, timezone
from typing import Any, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger("guardianos.audit")


class AuditEvent(BaseModel):
    id: str = Field(..., description="Unique event ID")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor: str = Field(..., description="User or system agent performing the action")
    action: str = Field(..., description="Action name (e.g., SBOM_INGESTED, REMEDIATION_APPROVED)")
    target_type: str = Field(..., description="Type of object affected (e.g., SBOM, Component, RemediationTask)")
    target_id: str = Field(..., description="Identifier of the target")
    details: dict[str, Any] = Field(default_factory=dict)
    ip_address: Optional[str] = None
    status: str = "SUCCESS"


# In-memory transient audit store (synced to DB in db layer)
_audit_log_buffer: list[AuditEvent] = []


def record_audit_event(
    action: str,
    target_type: str,
    target_id: str,
    actor: str = "system",
    details: Optional[dict[str, Any]] = None,
    ip_address: Optional[str] = None,
    status: str = "SUCCESS"
) -> AuditEvent:
    import uuid
    event = AuditEvent(
        id=str(uuid.uuid4()),
        timestamp=datetime.now(timezone.utc),
        actor=actor,
        action=action,
        target_type=target_type,
        target_id=target_id,
        details=details or {},
        ip_address=ip_address,
        status=status
    )
    _audit_log_buffer.append(event)
    logger.info(f"AUDIT: [{event.action}] by {event.actor} on {event.target_type}:{event.target_id} - status={event.status}")
    return event


def get_recent_audit_events(limit: int = 100) -> list[AuditEvent]:
    return sorted(_audit_log_buffer, key=lambda e: e.timestamp, reverse=True)[:limit]
