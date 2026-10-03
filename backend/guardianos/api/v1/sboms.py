"""SBOM management API endpoints."""

import json
from typing import Optional
from fastapi import APIRouter, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel, Field
from guardianos.inventory.models import DependencyState, IngestionResult, SBOMDocument
from guardianos.inventory.service import inventory_service

router = APIRouter(prefix="/sboms", tags=["SBOMs"])


class SBOMUploadRequest(BaseModel):
    content: dict = Field(..., description="Raw SBOM JSON content")
    application: str = Field("default-app", description="Target application name")
    environment: str = Field("production", description="Environment: production, staging, development")
    state: DependencyState = Field(DependencyState.INSTALLED, description="DECLARED, INSTALLED, or RUNNING")


@router.post("/upload", response_model=IngestionResult, status_code=status.HTTP_201_CREATED)
async def upload_sbom_json(payload: SBOMUploadRequest):
    """Upload SBOM as JSON payload."""
    try:
        raw_json = json.dumps(payload.content)
        result = inventory_service.ingest_sbom(
            raw_content=raw_json,
            application=payload.application,
            environment=payload.environment,
            default_state=payload.state,
            actor="api-user"
        )
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to parse and ingest SBOM: {str(e)}"
        )


@router.post("/upload-file", response_model=IngestionResult, status_code=status.HTTP_201_CREATED)
async def upload_sbom_file(
    file: UploadFile = File(...),
    application: str = Form("default-app"),
    environment: str = Form("production"),
    state: str = Form("INSTALLED")
):
    """Upload SBOM as a file attachment (.json)."""
    try:
        content_bytes = await file.read()
        raw_text = content_bytes.decode("utf-8")
        dep_state = DependencyState(state.upper()) if state in DependencyState.__members__ else DependencyState.INSTALLED
        result = inventory_service.ingest_sbom(
            raw_content=raw_text,
            application=application,
            environment=environment,
            default_state=dep_state,
            actor=f"file-upload:{file.filename}"
        )
        return result
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to process SBOM file: {str(e)}"
        )


@router.get("", response_model=list[SBOMDocument])
async def list_sboms():
    """List all ingested SBOM documents."""
    return inventory_service.list_sboms()


@router.post("/clear", status_code=status.HTTP_200_OK)
async def clear_inventory():
    """Clear all inventory components, SBOMs, graph nodes, and vulnerability records."""
    from guardianos.intel.service import intel_service
    inventory_service.clear()
    intel_service.clear()
    return {"status": "cleared", "message": "Inventory and vulnerability cache wiped successfully"}



class ScanWorkspaceRequest(BaseModel):
    path: Optional[str] = Field(None, description="Path to scan (defaults to project workspace)")
    app_name: Optional[str] = Field(None, description="Optional application name")
    environment: str = Field("production", description="Target environment")
    clear_existing: bool = Field(True, description="Clear previous inventory to isolate new scan results")


@router.post("/scan-local-manifests", response_model=IngestionResult, status_code=status.HTTP_201_CREATED)
async def scan_local_workspace(payload: Optional[ScanWorkspaceRequest] = None):
    """Scan real package manifests (package.json, requirements.txt, Dockerfile, etc.) directly from any target folder."""
    import os
    from guardianos.inventory.scanner import scan_directory_manifests
    from guardianos.intel.service import intel_service
    
    target_path = payload.path if (payload and payload.path) else os.getcwd()
    app_name = payload.app_name if (payload and payload.app_name) else None
    env = payload.environment if (payload and payload.environment) else "production"
    clear_first = payload.clear_existing if (payload and payload.clear_existing is not None) else True

    if clear_first:
        inventory_service.clear()
        intel_service.clear()

    try:
        result, manifests = scan_directory_manifests(
            target_dir=target_path,
            app_name=app_name,
            environment=env
        )
        result.summary["manifests"] = manifests
        # Query vulnerabilities on all newly ingested real components
        intel_service.scan_all_components()
        return result
    except FileNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Scan error: {str(e)}")


@router.get("/{sbom_id}", response_model=SBOMDocument)
async def get_sbom(sbom_id: str):
    """Get single SBOM document metadata."""
    doc = inventory_service.get_sbom(sbom_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SBOM document not found")
    return doc
