"""Evidence-backed static reachability analysis endpoints."""

from dataclasses import asdict
from pathlib import PurePosixPath

from fastapi import Depends, HTTPException
from pydantic import BaseModel, Field, model_validator

from guardianos.api.security import SecuredAPIRouter
from guardianos.core.security import CurrentUser, get_current_user
from guardianos.intel.service import intel_service
from osprey.analyzers.source import analyze_source_files
from guardianos.storage.evidence import evidence_store

router = SecuredAPIRouter(prefix="/analysis", tags=["Static Analysis"])


class ReachabilityRequest(BaseModel):
    finding_id: str = Field(..., min_length=1, max_length=300)
    source_files: dict[str, str] = Field(..., description="Relative source path to source text mapping")

    @model_validator(mode="after")
    def validate_source_bundle(self):
        allowed = {".py", ".js", ".jsx", ".ts", ".tsx", ".go"}
        if len(self.source_files) > 500:
            raise ValueError("source_files may contain at most 500 files")
        total = 0
        for raw_path, content in self.source_files.items():
            normalized = raw_path.replace("\\", "/")
            path = PurePosixPath(normalized)
            if path.is_absolute() or ".." in path.parts or ":" in (path.parts[0] if path.parts else ""):
                raise ValueError("source file paths must be relative and remain within the submitted bundle")
            if path.suffix.lower() not in allowed:
                raise ValueError(f"unsupported source file type: {path.suffix or '(none)'}")
            if not isinstance(content, str):
                raise ValueError("source file contents must be text")
            size = len(content.encode("utf-8", "replace"))
            if size > 1_000_000:
                raise ValueError("each source file must be at most 1 MB")
            total += size
        if total > 10_000_000:
            raise ValueError("submitted source bundle must be at most 10 MB")
        return self


@router.post("/reachability")
async def analyze_finding_reachability(
    payload: ReachabilityRequest,
    current_user: CurrentUser = Depends(get_current_user),
):
    finding = intel_service.get_finding(payload.finding_id)
    if finding is None or finding.organization_id != current_user.org_id:
        raise HTTPException(status_code=404, detail="Vulnerability finding not found")

    analysis = analyze_source_files(
        payload.source_files,
        [finding.component_name],
        evidence_store=evidence_store,
    )
    result = intel_service.analyze_finding_reachability(
        finding,
        analysis,
        analysis_type="submitted_source_bundle_reachability",
    )
    from guardianos.risk.service import risk_service
    risk_service.evaluate_all()

    return {
        "finding_id": finding.id,
        "vulnerability_id": finding.vulnerability_id,
        "component_purl": finding.component_purl,
        "package_status": finding.package_status,
        "analysis_provenance_id": finding.analysis_provenance_id,
        "provenance_ids": finding.provenance_ids,
        "runtime_state": finding.runtime_state,
        "runtime_evidence_ids": finding.runtime_evidence_ids,
        "runtime_limitations": finding.runtime_limitations,
        "reachability": {
            "status": result.status.value,
            "confidence": result.confidence,
            "path": list(result.path),
            "path_edges": [asdict(edge) for edge in result.path_edges],
            "reason": result.reason,
            "explanation": result.explanation,
            "limitations": list(result.limitations),
            "evidence_ids": list(result.evidence),
        },
        "exposures": [
            {
                "framework": item.framework,
                "method": item.method,
                "route": item.route,
                "file": item.file,
                "line": item.line,
                "confidence": item.confidence,
                "evidence_id": item.evidence_id,
            }
            for item in analysis.exposures
        ],
        "dependency_usages": [
            {
                "package": item.package,
                "file": item.file,
                "line": item.line,
                "symbol": item.symbol,
                "usage_type": item.usage_type,
                "confidence": item.confidence,
                "caller": item.caller,
                "evidence_id": item.evidence_id,
            }
            for item in analysis.usages
        ],
        "analysis_errors": analysis.errors,
    }
