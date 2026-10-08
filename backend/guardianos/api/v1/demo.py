"""Flagship Demo API endpoints."""

from fastapi import status
from fastapi import Depends
from guardianos.api.security import SecuredAPIRouter
from guardianos.core.security import require_single_organization
from guardianos.core.config import settings
from guardianos.core.security import UserRole, require_role
from guardianos.demo.scenario import run_flagship_demo

router = SecuredAPIRouter(prefix="/demo", tags=["Demo Fixtures"], dependencies=[Depends(require_single_organization)])


@router.post("/run", status_code=status.HTTP_200_OK, dependencies=[Depends(require_role(UserRole.ADMIN))])
async def execute_demo_scenario():
    """Run synthetic fixture data; this is not a live repository or runtime assessment."""
    result = run_flagship_demo()
    return result


@router.get("/status")
async def get_demo_status():
    """Describe the optional synthetic fixture scenario without presenting it as observed state."""
    return {
        "scenario_name": "Synthetic libheif / ImageMagick fixture",
        "fixture": True,
        "enabled": settings.ENABLE_DEMO_FIXTURES,
        "warning": "Values in this scenario are seeded demo data, not repository, cloud, deployment, or runtime observations.",
    }
