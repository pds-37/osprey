"""Vulnerability Intelligence API endpoints."""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from guardianos.intel.feed_data import vuln_registry
from guardianos.intel.models import VulnerabilityFinding, VulnerabilityRecord
from guardianos.intel.service import intel_service

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


@router.get("", response_model=List[VulnerabilityFinding])
async def list_vulnerability_findings(
    application: Optional[str] = Query(None, description="Filter by application"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, etc.)")
):
    """Retrieve discovered vulnerability findings across components."""
    return intel_service.list_findings(application=application, severity=severity)


@router.post("/scan", response_model=List[VulnerabilityFinding], status_code=status.HTTP_200_OK)
async def trigger_vulnerability_scan():
    """Trigger vulnerability matching against current inventory and correlate with Knowledge Graph."""
    findings = intel_service.scan_all_components()
    return findings


@router.get("/advisories", response_model=List[VulnerabilityRecord])
async def list_known_advisories():
    """List known security advisories in the intelligence database."""
    return vuln_registry.list_advisories()


@router.get("/advisories/{vuln_id}", response_model=VulnerabilityRecord)
async def get_advisory_detail(vuln_id: str):
    """Get single security advisory record by CVE or GHSA ID."""
    adv = vuln_registry.get_advisory(vuln_id)
    if not adv:
        raise HTTPException(status_code=404, detail=f"Advisory {vuln_id} not found")
    return adv


@router.get("/findings/{finding_id}", response_model=VulnerabilityFinding)
async def get_finding_detail(finding_id: str):
    """Get detailed vulnerability finding with component linkage."""
    finding = intel_service.get_finding(finding_id)
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding
