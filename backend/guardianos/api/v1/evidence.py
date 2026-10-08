"""Read-only evidence record lookup."""

from dataclasses import asdict

import re

from fastapi import Depends, HTTPException
from guardianos.api.security import SecuredAPIRouter
from guardianos.core.security import CurrentUser, get_current_user
from guardianos.storage.sqlite import state_store

from guardianos.storage.evidence import evidence_store

router = SecuredAPIRouter(prefix="/evidence", tags=["Evidence"])

_EVIDENCE_ID = re.compile(r"^ev-[0-9a-f]{24}$")


def _evidence_belongs_to_org(evidence_id: str, org_id: str) -> bool:
    """Authorize evidence only through a same-organization owning record."""
    def refs(value):
        if not isinstance(value, (list, tuple, set)):
            return ()
        return tuple(item for item in list(value)[:256] if isinstance(item, str))

    for payload in state_store.list("findings").values():
        if not isinstance(payload, dict) or payload.get("organization_id", "default-org") != org_id:
            continue
        references = set(refs(payload.get("evidence_ids")))
        provenance = payload.get("provenance_ids")
        if isinstance(provenance, dict):
            references.update(refs(list(provenance.values())))
        references.update(refs(payload.get("runtime_evidence_ids")))
        if evidence_id in references:
            return True
    for payload in state_store.list("components").values():
        if not isinstance(payload, dict) or payload.get("organization_id", "default-org") != org_id:
            continue
        if evidence_id in refs(payload.get("evidence_ids")):
            return True
    for payload in state_store.list("remediation_workflows").values():
        if not isinstance(payload, dict) or payload.get("org_id") != org_id:
            continue
        references = set(refs(payload.get("evidence_ids")))
        references.update(refs(payload.get("finding_evidence_ids")))
        if evidence_id in references:
            return True
    return False


@router.get("/{evidence_id}")
async def get_evidence(evidence_id: str, current_user: CurrentUser = Depends(get_current_user)):
    if not _EVIDENCE_ID.fullmatch(evidence_id) or not _evidence_belongs_to_org(evidence_id, current_user.org_id):
        raise HTTPException(status_code=404, detail="Evidence record not found")
    record = evidence_store.get(evidence_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Evidence record not found")
    data = asdict(record)
    data["type"] = record.type.value
    data["integrity_status"] = evidence_store.integrity_status(record)
    return data
