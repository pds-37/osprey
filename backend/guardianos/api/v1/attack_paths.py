"""Attack Path API endpoints."""

from typing import List, Optional
from fastapi import Depends, HTTPException, Query, status
from guardianos.attackpath.models import AttackPath
from guardianos.attackpath.service import attack_path_service
from guardianos.api.security import SecuredAPIRouter
from guardianos.core.security import require_single_organization

router = SecuredAPIRouter(prefix="/attack-paths", tags=["Attack Paths"], dependencies=[Depends(require_single_organization)])


@router.get("", response_model=List[AttackPath])
async def list_attack_paths(
    status: Optional[str] = Query(None, description="Filter by status (OPEN, CLOSED)")
):
    """List evidence-supported paths; ordinary scans may have no cloud path evidence."""
    return attack_path_service.list_paths(status=status)


@router.post("/recalculate", response_model=List[AttackPath], status_code=status.HTTP_200_OK)
async def recalculate_attack_paths():
    """Recalculate paths from available graph evidence and enabled fixtures."""
    return attack_path_service.recalculate_paths()


@router.get("/{path_id}", response_model=AttackPath)
async def get_attack_path_detail(path_id: str):
    """Retrieve details, step nodes, and evidence for a specific attack path."""
    path = attack_path_service.get_path(path_id)
    if not path:
        raise HTTPException(status_code=404, detail=f"Attack path '{path_id}' not found")
    return path
