"""SBOM management API endpoints."""

import json
import logging
import os
from pathlib import Path
from typing import Optional
from fastapi import Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel, Field
from guardianos.api.security import SecuredAPIRouter
from guardianos.core.config import settings
from guardianos.core.security import (
    CurrentUser,
    UserRole,
    get_current_user,
    require_role,
    single_organization_context_allowed,
)
from guardianos.inventory.models import DependencyState, IngestionResult, SBOMDocument
from guardianos.inventory.service import inventory_service

logger = logging.getLogger(__name__)
router = SecuredAPIRouter(prefix="/sboms", tags=["SBOMs"])


class SBOMUploadRequest(BaseModel):
    content: dict = Field(..., description="Raw SBOM JSON content")
    application: str = Field("default-app", description="Target application name")
    environment: str = Field("unknown", description="Optional environment label; not runtime evidence")
    state: DependencyState = Field(DependencyState.UNKNOWN, description="UNKNOWN, DECLARED, LOCKED, or INSTALLED; RUNNING is rejected for SBOM input")


@router.post("/upload", response_model=IngestionResult, status_code=status.HTTP_201_CREATED)
async def upload_sbom_json(
    payload: SBOMUploadRequest,
    current_user: CurrentUser = Depends(require_role(UserRole.SECURITY_ENGINEER)),
):
    """Upload SBOM as JSON payload."""
    if payload.state == DependencyState.RUNNING:
        raise HTTPException(status_code=422, detail="An SBOM cannot establish that a dependency is running")
    try:
        raw_json = json.dumps(payload.content)
        result = inventory_service.ingest_sbom(
            raw_content=raw_json,
            application=payload.application,
            environment=payload.environment,
            default_state=payload.state,
            actor=current_user.username,
            organization_id=current_user.org_id,
        )
        return result
    except Exception as e:
        logger.warning("SBOM ingestion rejected (%s)", type(e).__name__)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SBOM could not be parsed or ingested"
        )


@router.post("/upload-file", response_model=IngestionResult, status_code=status.HTTP_201_CREATED)
async def upload_sbom_file(
    file: UploadFile = File(...),
    application: str = Form("default-app"),
    environment: str = Form("unknown"),
    state: str = Form("UNKNOWN"),
    current_user: CurrentUser = Depends(require_role(UserRole.SECURITY_ENGINEER)),
):
    """Upload SBOM as a file attachment (.json)."""
    try:
        content_bytes = await file.read(settings.MAX_REQUEST_BODY_BYTES + 1)
        if len(content_bytes) > settings.MAX_REQUEST_BODY_BYTES:
            raise HTTPException(status_code=413, detail="SBOM file exceeds configured size limit")
        raw_text = content_bytes.decode("utf-8")
        try:
            dep_state = DependencyState(state.upper())
        except ValueError:
            raise HTTPException(status_code=422, detail="state must be UNKNOWN, DECLARED, LOCKED, or INSTALLED")
        if dep_state == DependencyState.RUNNING:
            raise HTTPException(status_code=422, detail="An SBOM cannot establish that a dependency is running")
        result = inventory_service.ingest_sbom(
            raw_content=raw_text,
            application=application,
            environment=environment,
            default_state=dep_state,
            actor=current_user.username,
            organization_id=current_user.org_id,
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.warning("SBOM file ingestion rejected (%s)", type(e).__name__)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SBOM file could not be parsed or ingested"
        )


@router.get("", response_model=list[SBOMDocument])
async def list_sboms(current_user: CurrentUser = Depends(get_current_user)):
    """List all ingested SBOM documents."""
    return [item for item in inventory_service.list_sboms()
            if item.organization_id == current_user.org_id]


@router.post("/clear", status_code=status.HTTP_200_OK)
async def clear_inventory(
    current_user: CurrentUser = Depends(require_role(UserRole.ADMIN)),
):
    """Clear all inventory components, SBOMs, graph nodes, and vulnerability records."""
    from guardianos.intel.service import intel_service
    from guardianos.attackpath.service import attack_path_service
    from guardianos.remediation.service import remediation_service
    from guardianos.propagation.service import propagation_service
    from guardianos.risk.service import risk_service
    from guardianos.graph.builder import get_graph_store

    if not single_organization_context_allowed(current_user.org_id):
        raise HTTPException(status_code=409, detail="ENDPOINT_UNAVAILABLE_IN_MULTI_ORGANIZATION_MODE")
    inventory_service.clear()
    intel_service.clear()
    attack_path_service.clear()
    remediation_service.clear()
    propagation_service.clear()
    risk_service.clear()
    try:
        get_graph_store().clear()
    except Exception:
        pass
    return {"status": "cleared", "message": "Inventory, threats, graphs, and cache wiped successfully"}



class ScanWorkspaceRequest(BaseModel):
    path: Optional[str] = Field(None, description="Path to scan (defaults to project workspace)")
    app_name: Optional[str] = Field(None, description="Optional application name")
    environment: str = Field("unknown", description="Optional environment label; not runtime evidence")
    clear_existing: bool = Field(True, description="Clear previous inventory to isolate new scan results")


@router.post("/scan-local-manifests", response_model=IngestionResult, status_code=status.HTTP_201_CREATED)
async def scan_local_workspace(
    payload: Optional[ScanWorkspaceRequest] = None,
    current_user: CurrentUser = Depends(require_role(UserRole.SECURITY_ENGINEER)),
):
    """Scan a configured workspace using the shared Osprey parser and static analyzer."""
    if not single_organization_context_allowed(current_user.org_id):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="WORKSPACE_SCAN_REQUIRES_SINGLE_ORGANIZATION_MODE",
        )
    allowed_root = Path(settings.WORKSPACE_ROOT or os.getcwd()).expanduser().resolve()
    requested = Path(payload.path).expanduser() if payload and payload.path else Path(".")
    if not requested.is_absolute():
        requested = allowed_root / requested
    try:
        target_path = requested.resolve(strict=True)
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace path was not found")
    try:
        target_path.relative_to(allowed_root)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Workspace path is outside the configured scan root")
    if not target_path.is_dir():
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Workspace path must be a directory")

    from guardianos.inventory.scanner import scan_directory_manifests_with_analysis
    from guardianos.intel.service import intel_service

    app_name = payload.app_name if (payload and payload.app_name) else None
    env = payload.environment if (payload and payload.environment) else "unknown"
    clear_first = payload.clear_existing if (payload and payload.clear_existing is not None) else True

    if clear_first:
        if not single_organization_context_allowed(current_user.org_id):
            raise HTTPException(status_code=409, detail="CLEAR_EXISTING_REQUIRES_SINGLE_ORGANIZATION_MODE")
        from guardianos.attackpath.service import attack_path_service
        from guardianos.remediation.service import remediation_service
        from guardianos.propagation.service import propagation_service
        from guardianos.risk.service import risk_service
        from guardianos.graph.builder import get_graph_store

        inventory_service.clear()
        intel_service.clear()
        attack_path_service.clear()
        remediation_service.clear()
        propagation_service.clear()
        risk_service.clear()
        try:
            get_graph_store().clear()
        except Exception:
            pass

    try:
        result, manifests, source_analysis = scan_directory_manifests_with_analysis(
            target_dir=target_path,
            app_name=app_name,
            environment=env,
            actor=current_user.username,
            organization_id=current_user.org_id,
        )
        result.summary["manifests"] = manifests
        # Vulnerability matching and reachability are part of this normal scan flow.
        findings = intel_service.scan_all_components()
        scanned_purls = {component.purl for component in result.components}
        scanned_app = (
            result.components[0].application if result.components else (app_name or target_path.name)
        )
        analyzed_findings = []
        for finding in findings:
            if (finding.organization_id != current_user.org_id
                    or finding.component_purl not in scanned_purls
                    or finding.application != scanned_app):
                continue
            intel_service.analyze_finding_reachability(
                finding,
                source_analysis,
                analysis_type="workspace_reachability",
            )
            analyzed_findings.append(finding)
        result.summary["findings_analyzed"] = len(analyzed_findings)
        result.summary["reachability"] = {
            status_value: sum(1 for finding in analyzed_findings if finding.reachability_status == status_value)
            for status_value in ("REACHABLE", "NOT_REACHABLE", "UNKNOWN")
        }
        # Recalculate derived attack paths; remediation proposals are explicit.
        try:
            from guardianos.attackpath.service import attack_path_service
            attack_path_service.recalculate_paths()
        except Exception as err:
            logger.warning("Post-scan attack path generation failed (%s)", type(err).__name__)
        try:
            from guardianos.risk.service import risk_service
            risk_service.evaluate_all()
        except Exception as err:
            logger.warning("Post-scan risk evaluation failed (%s)", type(err).__name__)
        return result
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace path was not found")
    except ValueError as e:
        logger.warning("Workspace scan rejected (%s)", type(e).__name__)
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Workspace scan input is invalid")
    except Exception as e:
        logger.warning("Workspace scan failed (%s)", type(e).__name__)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Workspace scan failed")


@router.get("/{sbom_id}", response_model=SBOMDocument)
async def get_sbom(
    sbom_id: str,
    current_user: CurrentUser = Depends(get_current_user),
):
    """Get single SBOM document metadata."""
    doc = inventory_service.get_sbom(sbom_id)
    if not doc or doc.organization_id != current_user.org_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SBOM document not found")
    return doc
