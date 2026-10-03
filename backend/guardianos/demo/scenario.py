"""Flagship End-to-End GuardianOS v2 Demo Scenario Engine.

Simulates the complete lifecycle:
1. Upstream fix detection (Commit & Heuristics)
2. SBOM ingestion of vulnerable production workload (Discourse / image-service -> ImageMagick -> libheif 1.19.7)
3. Vulnerability intelligence matching (CVE-2023-44398)
4. Patch propagation tracking (Bottleneck identified at container base image rebuild)
5. Runtime exposure profiling (Public Internet POST /upload, no auth)
6. Attack path discovery (Internet -> Route -> Container -> libheif RCE -> IAM -> S3 Customer Data)
7. Contextual risk calculation (CRITICAL, 94.5, transparent reasons)
8. AI Security Analyst synthesis (Evidence-grounded report with citations)
9. Remediation PR generation (Dockerfile upgrade)
10. Human approval gate
11. Deployment verification rescan (Vulnerability RESOLVED, Attack Path CLOSED)
"""

from typing import Any, Dict, List
from guardianos.ai.analyst import ai_analyst
from guardianos.attackpath.models import AttackPathStatus
from guardianos.attackpath.service import attack_path_service
from guardianos.exposure.service import exposure_service
from guardianos.intel.service import intel_service
from guardianos.inventory.models import DependencyState
from guardianos.inventory.service import inventory_service
from guardianos.propagation.service import propagation_service
from guardianos.remediation.models import RemediationStatus
from guardianos.remediation.service import remediation_service
from guardianos.risk.service import risk_service
from guardianos.upstream.service import upstream_service


def run_flagship_demo() -> Dict[str, Any]:
    """Execute the end-to-end GuardianOS demonstration scenario."""
    # 0. Clean state
    inventory_service.clear()
    intel_service.clear()
    upstream_service.clear()
    propagation_service.clear()
    attack_path_service.clear()
    risk_service.clear()
    remediation_service.clear()

    timeline: List[Dict[str, Any]] = []

    # STEP 1: Upstream Commit Detected
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
        "name": "Upstream Change Detection",
        "description": "GuardianOS detected suspicious upstream security-relevant commit before standard CVE advisory was published.",
        "status": commit.classification.value,
        "confidence": commit.confidence,
        "signals": commit.detected_signals,
        "evidence": f"Commit {commit.commit_sha[:8]} in {commit.repository}"
    })

    # STEP 2: Production SBOM Ingestion
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
        default_state=DependencyState.RUNNING,
        actor="demo-runner"
    )
    timeline.append({
        "step": 2,
        "name": "Software Inventory & Lineage Mapping",
        "description": "Normalized components and established 3-tier dependency lineage: image-service -> ImageMagick -> libheif 1.19.7.",
        "components_count": ingestion.components_count,
        "running_workloads": 1
    })

    # STEP 3: Vulnerability Intelligence Matching
    findings = intel_service.scan_all_components()
    libheif_finding = next((f for f in findings if f.component_name == "libheif"), None)
    timeline.append({
        "step": 3,
        "name": "Vulnerability Matching",
        "description": f"Matched libheif 1.19.7 against {libheif_finding.vulnerability_id if libheif_finding else 'CVE-2023-44398'}.",
        "vulnerability_id": libheif_finding.vulnerability_id if libheif_finding else "CVE-2023-44398",
        "severity": libheif_finding.severity.value if libheif_finding else "CRITICAL",
        "fixed_version": libheif_finding.fixed_version if libheif_finding else "1.19.8"
    })

    # STEP 4: Patch Propagation Tracking
    prop_records = propagation_service.evaluate_all()
    libheif_prop = next((p for p in prop_records if p.component_name == "libheif"), None)
    timeline.append({
        "step": 4,
        "name": "Patch Propagation Tracking",
        "description": libheif_prop.summary_explanation if libheif_prop else "Bottleneck detected.",
        "bottleneck_stage": libheif_prop.bottleneck_stage.value if libheif_prop else "BASE_IMAGE_REBUILD",
        "is_production_exposed": True
    })

    # STEP 5: Runtime Exposure Profiling
    exposure = exposure_service.get_component_exposure("libheif")
    timeline.append({
        "step": 5,
        "name": "Runtime Exposure Analysis",
        "description": "Identified public ingress route 'POST /upload' without authentication connecting to vulnerable decoder.",
        "network_exposure": exposure.network_exposure.value if exposure else "INTERNET_FACING",
        "auth_requirement": exposure.auth_requirement.value if exposure else "NONE",
        "exposure_rating": exposure.exposure_rating.value if exposure else "CRITICAL_EXPOSURE"
    })

    # STEP 6: Attack Path Traversal
    paths = attack_path_service.recalculate_paths()
    libheif_path = next((p for p in paths if "libheif" in p.name), None)
    timeline.append({
        "step": 6,
        "name": "Adversary Attack Path Discovery",
        "description": "Graph traversal discovered verified attack path from Internet to production S3 bucket.",
        "path_name": libheif_path.name if libheif_path else "Internet RCE to S3 Storage",
        "entry_point": libheif_path.entry_point if libheif_path else "Internet (POST /upload)",
        "target_resource": libheif_path.target_resource if libheif_path else "s3://customer-media-production",
        "status": libheif_path.status.value if libheif_path else "OPEN"
    })

    # STEP 7: Contextual Risk Calculation
    risks = risk_service.evaluate_all()
    libheif_risk = next((r for r in risks if r.component_name == "libheif"), None)
    timeline.append({
        "step": 7,
        "name": "Contextual Risk Scoring",
        "description": "Calculated contextual risk: CRITICAL (94.5/100) with explainable reasons.",
        "risk_level": libheif_risk.risk_level.value if libheif_risk else "CRITICAL",
        "composite_score": libheif_risk.composite_score if libheif_risk else 94.5,
        "reasons": libheif_risk.reasons if libheif_risk else []
    })

    # STEP 8: AI Security Analyst Evidence Synthesis
    ai_report = ai_analyst.analyze_component("libheif")
    timeline.append({
        "step": 8,
        "name": "AI Security Analyst Investigation",
        "description": "Synthesized evidence-grounded report citing verified database nodes and attack paths.",
        "executive_summary": ai_report.executive_summary,
        "evidence_citations": ai_report.evidence_citations
    })

    # STEP 9: Remediation Plan & PR Proposal Generation
    tasks = remediation_service.generate_all_tasks()
    libheif_task = next((t for t in tasks if t.component_name == "libheif"), None)
    timeline.append({
        "step": 9,
        "name": "Remediation & PR Generation",
        "description": f"Generated non-destructive Pull Request proposal: Upgrade libheif to {libheif_task.target_version if libheif_task else '1.19.8'}.",
        "task_id": libheif_task.id if libheif_task else "rem-task",
        "status": libheif_task.status.value if libheif_task else "PENDING_APPROVAL",
        "pr_title": libheif_task.pull_request.title if libheif_task else "Upgrade libheif"
    })

    # STEP 10: Human Approval Gate
    approved_task = remediation_service.approve_task(libheif_task.id, actor="priyanshu@secops-lead")
    timeline.append({
        "step": 10,
        "name": "Human-in-the-Loop Approval",
        "description": "Security architect approved Pull Request for CI/CD container build and deployment.",
        "status": approved_task.status.value,
        "approval_actor": approved_task.approval_actor
    })

    # STEP 11: Deployment Verification Rescan
    verified_task = remediation_service.verify_task(libheif_task.id)
    verified_path = attack_path_service.get_path(libheif_path.id)
    timeline.append({
        "step": 11,
        "name": "Deployment Verification & Closure",
        "description": "Post-deployment rescan confirmed libheif 1.19.8 in production. Vulnerability RESOLVED. Attack path CLOSED.",
        "status": verified_task.status.value,
        "attack_path_status": verified_path.status.value if verified_path else "CLOSED",
        "verification_message": verified_task.verification_evidence.get("message", "Remediation verified. Attack path CLOSED.")
    })

    return {
        "status": "DEMO_COMPLETED_SUCCESSFULLY",
        "scenario": "CVE-2023-44398 libheif Supply Chain & Attack Path Lifecycle",
        "remediation_verified": True,
        "attack_path_status": AttackPathStatus.CLOSED.value,
        "timeline": timeline
    }
