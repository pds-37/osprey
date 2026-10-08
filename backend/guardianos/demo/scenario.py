"""Osprey's explicitly synthetic demo fixture scenario.

Simulates the complete lifecycle:
1. Upstream fix detection (Commit & Heuristics)
2. SBOM ingestion of vulnerable production workload (Discourse / image-service -> ImageMagick -> libheif 1.19.7)
3. Vulnerability intelligence matching (CVE-2023-44398)
4. Patch propagation tracking (Bottleneck identified at container base image rebuild)
5. Runtime exposure profiling (Public Internet POST /upload, no auth)
6. Attack path discovery (Internet -> Route -> Container -> libheif RCE -> IAM -> S3 Customer Data)
7. Contextual risk calculation (CRITICAL, 94.5, transparent reasons)
8. Deterministic evidence summary (fixture inputs only)
9. Remediation PR generation (Dockerfile upgrade)
10. Human approval gate
11. Simulated target-state display (not a deployment verification)
"""

from typing import Any, Dict, List
from fastapi import HTTPException
from guardianos.core.config import settings
from guardianos.ai.analyst import ai_analyst
from guardianos.attackpath.models import AttackPathStatus
from guardianos.attackpath.service import attack_path_service
from guardianos.exposure.service import exposure_service
from guardianos.exposure.models import AuthRequirement, DataProcessingType, EndpointProfile, NetworkExposure
from guardianos.intel.service import intel_service
from guardianos.inventory.models import DependencyState
from guardianos.inventory.service import inventory_service
from guardianos.propagation.service import propagation_service
from guardianos.remediation.models import RemediationStatus
from guardianos.remediation.service import remediation_service
from guardianos.risk.service import risk_service
from guardianos.upstream.service import upstream_service


def run_flagship_demo() -> Dict[str, Any]:
    """Execute an explicitly enabled, synthetic fixture scenario; it is not a live assessment."""
    if not settings.ENABLE_DEMO_FIXTURES:
        raise HTTPException(status_code=404, detail="Demo fixtures are disabled")
    # 0. Clean state
    inventory_service.clear()
    intel_service.clear()
    upstream_service.clear()
    propagation_service.clear()
    attack_path_service.clear()
    risk_service.clear()
    remediation_service.clear()
    exposure_service.clear()

    timeline: List[Dict[str, Any]] = []

    # STEP 1: Seeded commit text is passed to the heuristic; no repository is polled.
    commit = upstream_service.ingest_commit(
        repository="strukturag/libheif",
        commit_sha="e31a196ec2b07d6b38c353b3df8d3dbb4cfae977",
        component_name="libheif",
        author="Dirk Farin <dirk.farin@gmail.com>",
        message="Fix integer conversion in overlay calculation and add bounds check before memory allocation",
        diff_summary="@@ -421,7 +421,8 @@ int parse_overlay(struct heif_image* img) {\n- uint32_t alloc_sz = (uint32_t)(w * h * bpp);\n+ if (w > MAX_DIM || h > MAX_DIM) return -1;\n+ size_t alloc_sz = safe_multiply(w, h, bpp);\n+ char* buf = malloc(alloc_sz);",
        files_changed=["libheif/heif_image.cc", "libheif/box.cc"],
        potential_fixed_version="1.19.8"
    )
    timeline.append({
        "step": 1,
        "name": "Seeded Commit Heuristic",
        "description": "Heuristic classification of fixture commit text; no repository polling or commit provenance verification occurred.",
        "status": commit.classification.value,
        "confidence": commit.confidence,
        "signals": commit.detected_signals,
        "evidence": f"Commit {commit.commit_sha[:8]} in {commit.repository}"
    })

    # STEP 2: Explicitly synthetic SBOM input; its environment label is not runtime evidence.
    sbom_raw = """{
      "bomFormat": "CycloneDX",
      "specVersion": "1.4",
      "metadata": {
        "component": {
          "name": "image-service",
          "version": "2.4.0",
          "type": "application",
          "purl": "pkg:generic/image-service@2.4.0"
        }
      },
      "components": [
        {
          "name": "imagemagick",
          "version": "7.1.1-28",
          "type": "library",
          "purl": "pkg:deb/debian/imagemagick@7.1.1-28"
        },
        {
          "name": "libheif",
          "version": "1.19.7",
          "type": "library",
          "purl": "pkg:deb/debian/libheif@1.19.7"
        }
      ],
      "dependencies": [
        {
          "ref": "pkg:generic/image-service@2.4.0",
          "dependsOn": ["pkg:deb/debian/imagemagick@7.1.1-28"]
        },
        {
          "ref": "pkg:deb/debian/imagemagick@7.1.1-28",
          "dependsOn": ["pkg:deb/debian/libheif@1.19.7"]
        }
      ]
    }"""
    ingestion = inventory_service.ingest_sbom(
        raw_content=sbom_raw,
        application="image-service",
        environment="production",
        # This fixture provides an SBOM observation only; it is not live runtime evidence.
        default_state=DependencyState.INSTALLED,
        actor="demo-runner"
    )
    timeline.append({
        "step": 2,
        "name": "Synthetic SBOM Fixture",
        "description": "Normalized components and fixture SBOM relationships; no production inventory or workload was observed.",
        "components_count": ingestion.components_count
    })
    exposure_service.register_endpoint(EndpointProfile(
        id="demo:ep-media-upload",
        path="POST /upload",
        service="image-service",
        network_exposure=NetworkExposure.INTERNET_FACING,
        auth_requirement=AuthRequirement.NONE,
        processing_type=DataProcessingType.PARSER_UNTRUSTED_INPUT,
        is_public=True,
        connected_components=["imagemagick", "libheif"],
    ), demo_fixture=True)

    # STEP 3: Vulnerability Intelligence Matching
    findings = intel_service.scan_all_components()
    libheif_finding = next((f for f in findings if f.component_name == "libheif"), None)
    timeline.append({
        "step": 3,
        "name": "Fixture Vulnerability Correlation",
        "description": f"Correlated the synthetic libheif observation against available advisory data; this is not a live application finding. Result: {libheif_finding.vulnerability_id if libheif_finding else 'UNKNOWN'}.",
        "vulnerability_id": libheif_finding.vulnerability_id if libheif_finding else "UNKNOWN",
        "severity": libheif_finding.severity.value if libheif_finding else "UNKNOWN",
        "fixed_version": libheif_finding.fixed_version if libheif_finding else None
    })

    # STEP 4: Patch Propagation Tracking
    prop_records = propagation_service.evaluate_all(include_demo_fixtures=True)
    libheif_prop = next((p for p in prop_records if p.component_name == "libheif"), None)
    timeline.append({
        "step": 4,
        "name": "Simulated Patch Lifecycle",
        "description": libheif_prop.summary_explanation if libheif_prop else "No lifecycle record was produced.",
        "bottleneck_stage": libheif_prop.bottleneck_stage.value if libheif_prop and libheif_prop.bottleneck_stage else "UNKNOWN",
        "fixture": bool(libheif_prop and libheif_prop.fixture)
    })

    # STEP 5: Runtime Exposure Profiling
    exposure = exposure_service.get_component_exposure("libheif")
    timeline.append({
        "step": 5,
        "name": "Synthetic Endpoint Assertion",
        "description": "The demo fixture includes a POST /upload assertion; it is not a collected runtime or public-ingress observation.",
        "network_exposure": exposure.network_exposure.value if exposure else "UNKNOWN",
        "auth_requirement": exposure.auth_requirement.value if exposure else "UNKNOWN",
        "exposure_rating": exposure.exposure_rating.value if exposure else "UNKNOWN"
    })

    # STEP 6: Attack Path Traversal
    paths = attack_path_service.recalculate_paths(include_demo_fixtures=True)
    libheif_path = next((p for p in paths if "libheif" in p.name), None)
    timeline.append({
        "step": 6,
        "name": "Synthetic Path Fixture",
        "description": "The fixture displays a fictional Internet-to-storage path; no cloud or deployed-application evidence was collected.",
        "path_name": libheif_path.name if libheif_path else None,
        "entry_point": libheif_path.entry_point if libheif_path else None,
        "target_resource": libheif_path.target_resource if libheif_path else None,
        "status": libheif_path.status.value if libheif_path else "NOT_OBSERVED",
        "fixture": bool(libheif_path and libheif_path.fixture)
    })

    # STEP 7: Contextual Risk Calculation
    risks = risk_service.evaluate_all()
    libheif_risk = next((r for r in risks if r.component_name == "libheif"), None)
    timeline.append({
        "step": 7,
        "name": "Contextual Risk Scoring",
        "description": "Risk is UNKNOWN because the scenario's endpoint and path data are synthetic fixture inputs.",
        "risk_level": libheif_risk.risk_level.value if libheif_risk else "UNKNOWN",
        "composite_score": libheif_risk.composite_score if libheif_risk else None,
        "reasons": libheif_risk.reasons if libheif_risk else []
    })

    # STEP 8: Deterministic evidence summary over synthetic fixture records
    ai_report = ai_analyst.analyze_component("libheif")
    timeline.append({
        "step": 8,
        "name": "Evidence Summary (Demo Fixture)",
        "description": "Deterministic summary of synthetic fixture records; no model-generated findings or live observations.",
        "executive_summary": ai_report.executive_summary,
        "evidence_citations": ai_report.evidence_citations
    })

    # STEP 9: Remediation Plan & PR Proposal Generation
    tasks = remediation_service.generate_all_tasks()
    libheif_task = next((t for t in tasks if t.component_name == "libheif"), None)
    timeline.append({
        "step": 9,
        "name": "Remediation Recommendation",
        "description": f"Generated a version recommendation for the fixture; no repository diff, branch, or pull request was created.",
        "task_id": libheif_task.id if libheif_task else None,
        "status": libheif_task.status.value if libheif_task else "NOT_OBSERVED",
        "proposal_title": libheif_task.pull_request.title if libheif_task else None,
        "fixture": bool(libheif_task and libheif_task.fixture)
    })

    # STEP 10: Human Approval Gate
    if libheif_task:
        approved_task = remediation_service.approve_task(libheif_task.id, actor="demo-fixture-admin")
        approval_status = approved_task.status.value
        approval_actor = approved_task.approval_actor
    else:
        approved_task = None
        approval_status = "NOT_OBSERVED"
        approval_actor = None
    timeline.append({
        "step": 10,
        "name": "Synthetic Approval State",
        "description": "The fixture records a fictional approval state; it does not authorize a repository or deployment action.",
        "status": approval_status,
        "approval_actor": approval_actor
    })

    # STEP 11: Deployment Verification Rescan
    verified_task = remediation_service.verify_task(libheif_task.id, include_demo_fixtures=True) if libheif_task else None
    verified_path = attack_path_service.get_path(libheif_path.id) if libheif_path else None
    timeline.append({
        "step": 11,
        "name": "Simulated Target State",
        "description": "Synthetic fixture only: demonstrates a target-version and closed-path state; no deployment or real path closure was verified.",
        "status": verified_task.status.value if verified_task else "NOT_OBSERVED",
        "attack_path_status": verified_path.status.value if verified_path else "NOT_OBSERVED",
        "verification_message": (
            verified_task.verification_evidence.get("message", "SIMULATED FIXTURE: no deployment or real path closure was verified.")
            if verified_task else "NOT OBSERVED: no recommendation was generated because advisory/fix evidence was unavailable."
        )
    })

    return {
        "status": "DEMO_FIXTURE_COMPLETED",
        "fixture": True,
        "evidence_status": "SIMULATED_FIXTURE_DATA_NOT_LIVE_OBSERVATIONS",
        "scenario": "CVE-2023-44398 libheif Supply Chain & Attack Path Lifecycle",
        "remediation_verified": False,
        "simulated_fixture_verification": True,
        "attack_path_status": AttackPathStatus.CLOSED.value if verified_path else "NOT_OBSERVED",
        "timeline": timeline
    }
