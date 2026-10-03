"""Upstream changes API endpoints."""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field
from guardianos.upstream.models import CommitRecord
from guardianos.upstream.service import upstream_service

router = APIRouter(prefix="/upstream-changes", tags=["Upstream Changes"])


class AnalyzeCommitRequest(BaseModel):
    repository: str = Field(..., description="Target repository (e.g. strukturag/libheif)")
    commit_sha: str = Field(..., description="Commit hash")
    component_name: str = Field(..., description="Component package name")
    author: str = Field("unknown", description="Commit author")
    message: str = Field(..., description="Commit message header and description")
    diff_summary: str = Field("", description="Code diff patch snippet")
    files_changed: List[str] = Field(default_factory=list)
    potential_fixed_version: Optional[str] = None


@router.get("", response_model=List[CommitRecord])
async def list_upstream_changes(component: Optional[str] = Query(None, description="Filter by component name")):
    """List detected upstream commits and security-relevant changes."""
    return upstream_service.list_commits(component=component)


@router.post("/analyze", response_model=CommitRecord, status_code=status.HTTP_201_CREATED)
async def analyze_and_ingest_commit(payload: AnalyzeCommitRequest):
    """Analyze a new upstream commit for suspicious security-relevant changes."""
    record = upstream_service.ingest_commit(
        repository=payload.repository,
        commit_sha=payload.commit_sha,
        component_name=payload.component_name,
        author=payload.author,
        message=payload.message,
        diff_summary=payload.diff_summary,
        files_changed=payload.files_changed,
        potential_fixed_version=payload.potential_fixed_version
    )
    return record


@router.get("/{sha}", response_model=CommitRecord)
async def get_commit_detail(sha: str):
    """Get single commit record with signal breakdown."""
    record = upstream_service.get_commit(sha)
    if not record:
        raise HTTPException(status_code=404, detail=f"Commit {sha} not found")
    return record
