from __future__ import annotations

import json
import gc
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(REPO_ROOT / "osprey" / "src"))

from osprey.analyzers.reachability import analyze_reachability
from osprey.analyzers.source import analyze_source_files
from osprey.core.evidence import EvidenceStore
from osprey.intel.cache import IntelCache
from osprey.remediation import apply_npm_proposal, create_proposal, verify_post_scan
from osprey.scanner import scan_workspace

FIXTURE = Path(__file__).resolve().parent
ADVISORY = {
    "id": "DEMO-OSPREY-0001",
    "summary": "Synthetic demonstration advisory; not a real vulnerability.",
    "details": "Fictional affected-version and symbol mapping for the offline Osprey walkthrough.",
    "affected": [{
        "package": {"ecosystem": "npm", "name": "demo-codec"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1.0"}]}],
        "ecosystem_specific": {"symbols": ["decodeUnsafe"]},
    }],
}


def _status(source: str) -> str:
    analysis = analyze_source_files({"case.js": source}, ["demo-codec"], EvidenceStore())
    result = analyze_reachability(analysis, package="demo-codec", vulnerable_symbols=["decodeUnsafe"])
    return result.status.value


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    with tempfile.TemporaryDirectory(prefix="osprey-phase10-demo-") as temp:
        workspace = Path(temp) / "workspace"
        cache_path = Path(temp) / "cache"
        shutil.copytree(FIXTURE, workspace, ignore=shutil.ignore_patterns("run_demo.py", "README.md"))
        os.environ["OSPREY_CACHE_DIR"] = str(cache_path)
        cache = IntelCache(cache_dir=cache_path, offline=True)
        cache_key = "npm:demo-codec@1.0.0"
        cache.set("osv", cache_key, [ADVISORY])
        cache.set("osv_coverage", cache_key, {"status": "COMPLETE", "observed_at": datetime.now(timezone.utc).isoformat()})
        fixed_key = "npm:demo-codec@1.1.0"
        cache.set("osv", fixed_key, [])
        cache.set("osv_coverage", fixed_key, {"status": "COMPLETE", "observed_at": datetime.now(timezone.utc).isoformat()})

        result = scan_workspace(workspace, offline=True)
        if not result.findings:
            print("No fixture finding was produced; stopping without a success claim.")
            del cache
            gc.collect()
            return 2
        finding = next((item for item in result.findings if Path(item.component.source_file).name == "package.json"), result.findings[0])
        print("BEFORE -> FINDING -> EVIDENCE")
        print(json.dumps({
            "fixture": "synthetic; not a real advisory",
            "components": len(result.components),
            "findings": len(result.findings),
            "vulnerability": finding.vulnerability_id,
            "dependency": finding.component.name,
            "version": finding.component.version,
            "version_status": finding.package_status.value,
            "reachability": finding.reachability.status.value,
            "risk_score": finding.risk_score,
            "risk_decision": finding.risk_tier,
            "evidence_ids": finding.evidence_ids,
            "advisory_coverage": result.advisory_coverage,
            "runtime": finding.runtime_state,
            "limitations": finding.risk_limitations + finding.runtime_limitations,
        }, indent=2, sort_keys=True))

        cases = {
            "reachable": workspace / "src" / "app.js",
            "not_reached_in_supported_file": workspace / "src" / "not-reached.js",
            "dynamic_behavior_unknown": workspace / "src" / "unknown.js",
        }
        observed = {name: _status(path.read_text(encoding="utf-8")) for name, path in cases.items()}
        print("\nIsolated static-analysis cases:")
        print(json.dumps(observed, indent=2, sort_keys=True))
        expected = {"reachable": "REACHABLE", "not_reached_in_supported_file": "NOT_REACHABLE", "dynamic_behavior_unknown": "UNKNOWN"}
        if observed != expected:
            print("Observed analyzer behavior differs from the fixture's expected case labels.")
            del cache
            gc.collect()
            return 3

        proposal = create_proposal(workspace, finding)
        print("\nRemediation proposal (read-only):")
        print(json.dumps({"proposal_id": proposal.proposal_id, "status": proposal.status,
                          "target_version": proposal.target_version, "files_to_change": proposal.files_to_change,
                          "limitations": proposal.limitations}, indent=2, sort_keys=True))
        if proposal.status != "PROPOSED":
            print("No eligible proposal; no file change was attempted.")
            del cache
            gc.collect()
            return 0
        if input("Type APPROVE to apply only this proposal to the temporary copy: ").strip() != "APPROVE":
            print("Approval not given; no file change was attempted.")
            return 0

        applied = apply_npm_proposal(workspace, proposal, approved=True, finding=finding)
        after = scan_workspace(workspace, offline=True)
        verification = verify_post_scan(proposal, after)
        print("\nREMEDIATION -> VERIFICATION")
        print(json.dumps({"apply": applied, "verification": verification}, indent=2, sort_keys=True))
        del cache
        gc.collect()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
