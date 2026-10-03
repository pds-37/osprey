"""Flagship Demo API endpoints."""

from fastapi import APIRouter, status
from guardianos.demo.scenario import run_flagship_demo

router = APIRouter(prefix="/demo", tags=["Flagship Demo"])


@router.post("/run", status_code=status.HTTP_200_OK)
async def execute_demo_scenario():
    """Trigger complete end-to-end GuardianOS v2 supply chain & attack path demonstration."""
    result = run_flagship_demo()
    return result


@router.get("/status")
async def get_demo_status():
    """Get status overview of the flagship demo scenario."""
    return {
        "scenario_name": "libheif / ImageMagick Supply Chain & Attack Path Walkthrough",
        "entry_point": "Internet -> POST /upload (Unauthenticated)",
        "affected_component": "libheif 1.19.7 via ImageMagick",
        "vulnerability": "CVE-2023-44398 (Heap buffer overflow RCE, CVSS 9.8)",
        "target_cloud_resource": "s3://customer-media-production",
        "remediation": "Upgrade libheif to 1.19.8 in container base image",
        "verification_result": "Attack Path CLOSED"
    }
