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


@router.get("/{sbom_id}", response_model=SBOMDocument)
async def get_sbom(sbom_id: str):
    """Get single SBOM document metadata."""
    doc = inventory_service.get_sbom(sbom_id)
    if not doc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SBOM document not found")
    return doc
