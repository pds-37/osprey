"""Command-line interface for Osprey using Typer and Rich.

CLI COMMANDS:
  osprey scan [PATH=.] [--detail] [--json] [--sarif FILE] [--sbom FILE] [--offline] [--fail-on act-now|plan]
  osprey explain FINDING_ID
  osprey init
  osprey demo

EXIT CODES:
  0: Success (no findings at or above --fail-on threshold)
  1: Policy failure (findings discovered at or above --fail-on)
  2: Tool error (invalid path, missing permissions, unexpected runtime error)
"""

from __future__ import annotations

import sys
import json
from dataclasses import asdict
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.text import Text

from osprey import __version__
from osprey.explain import explain_finding
from osprey.report import render_json_report, render_terminal_report
from osprey.sarif import export_sarif_json
from osprey.sbom import export_cyclonedx_json
from osprey.scanner import scan_workspace
from osprey.remediation import apply_npm_proposal, create_proposal, verify_post_scan
from osprey.copilot import CopilotContext, CopilotFact, EvidenceOnlyProvider, ProviderSelection, render_facts
from osprey.core.evidence import canonical_json, verify_record
from osprey.core.models import EvidenceType
from osprey.runtime import runtime_evidence_freshness
import hashlib

app = typer.Typer(
    name="osprey",
    help="Software supply chain intelligence with contextual exposure and deterministic risk triage.",
    add_completion=False,
)
err_console = Console(stderr=True)


def version_callback(value: bool) -> None:
    if value:
        print(f"Osprey v{__version__}")
        raise typer.Exit(0)


@app.callback()
def main(
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-v",
        help="Show Osprey version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """Software supply chain intelligence with contextual exposure and deterministic risk triage."""
    pass



SAMPLE_OSPREY_YAML = """# Osprey Configuration (osprey.yaml)
# Declare explicit exposure levels and package scopes to override automated inference.

# 1. Service-level overrides
services:
  # frontend:
  #   exposure: public
  #   reason: "Public facing single page application"
  # worker:
  #   exposure: internal
  #   reason: "Background job processor without external ingress"

# 2. Package-level overrides
packages:
  # requests:
  #   exposure: internal
  #   reason: "Only calls private internal microservices"
  # lodash:
  #   exposure: dev-only
  #   reason: "Only used in build scripts"
"""


@app.command(name="scan")
def scan_cmd(
    path: str = typer.Argument(".", help="Directory or workspace path to scan."),
    detail: bool = typer.Option(False, "--detail", "-d", help="Display all findings including MONITOR and IGNORE tiers."),
    json_output: bool = typer.Option(False, "--json", help="Output machine-readable JSON."),
    sarif: Optional[str] = typer.Option(None, "--sarif", help="File path to write SARIF 2.1.0 output for GitHub Code Scanning."),
    sbom: Optional[str] = typer.Option(None, "--sbom", help="File path to write CycloneDX 1.5 JSON SBOM."),
    offline: bool = typer.Option(False, "--offline", help="Run strictly offline using local threat cache without network calls."),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Exit with code 1 if findings meet or exceed this tier ('act-now' or 'plan').",
    ),
    debug: bool = typer.Option(False, "--debug", help="Enable verbose error tracebacks."),
) -> None:
    """Scan a folder, construct supply chain graph, and prioritize dependency vulnerabilities."""
    try:
        result = scan_workspace(target_path=path, offline=offline)

        # 1. Write SARIF if requested
        if sarif:
            sarif_text = export_sarif_json(result.findings, result.root_path)
            Path(sarif).write_text(sarif_text, encoding="utf-8")

        # 2. Write SBOM if requested
        if sbom:
            sbom_text = export_cyclonedx_json(result.app_name, result.components, result.findings)
            Path(sbom).write_text(sbom_text, encoding="utf-8")

        # 3. Render Output
        if json_output:
            print(render_json_report(result))
        else:
            render_terminal_report(result, detail=detail)

        # 4. Check policy threshold
        if fail_on:
            threshold = fail_on.strip().lower()
            act_now_count = sum(1 for f in result.findings if f.risk_tier == "ACT NOW")
            plan_count = sum(1 for f in result.findings if f.risk_tier == "PLAN")
            unknown_count = sum(1 for f in result.findings if f.risk_tier == "UNKNOWN")

            if threshold in ("act-now", "act_now"):
                if act_now_count > 0:
                    sys.exit(1)
            elif threshold == "plan":
                if (act_now_count + plan_count + unknown_count) > 0:
                    sys.exit(1)

        sys.exit(0)

    except FileNotFoundError as e:
        err_console.print(f"[bold red]Scan error:[/] {e}")
        sys.exit(2)
    except Exception as e:
        if debug:
            raise
        err_console.print(f"[bold red]Osprey scan error:[/] {e} (run with --debug for stack trace)")
        sys.exit(2)


@app.command(name="explain")
def explain_cmd(
    finding_id: str = typer.Argument(..., help="Vulnerability ID or alias (e.g. GHSA-xxxx, CVE-2023-xxxx)."),
    path: str = typer.Option(".", "--path", "-p", help="Workspace path to scan for context."),
    question: Optional[str] = typer.Option(None, "--question", "-q", help="Ask a read-only evidence-grounded question about the finding."),
    offline: bool = typer.Option(False, "--offline", help="Operate strictly offline from local cache."),
    debug: bool = typer.Option(False, "--debug", help="Enable verbose error tracebacks."),
) -> None:
    """Print the complete audit trail and evidence chain for a specific finding."""
    try:
        result = scan_workspace(target_path=path, offline=offline)
        if question is not None:
            if len(question) > 2_000:
                raise ValueError("question must not exceed 2000 characters")
            finding = next((item for item in result.findings if finding_id in {item.id, item.vulnerability_id, *item.aliases}), None)
            if finding is None:
                sys.exit(1)
            evidence_by_id = {record.id: record for record in result.evidence}
            verified_records = {
                evidence_id for evidence_id in dict.fromkeys(finding.evidence_ids)
                if evidence_id in evidence_by_id and verify_record(evidence_by_id[evidence_id]) is True
            }
            # Keep the CLI adapter on the same read-only selector and server-rendered facts.
            claims_list = []
            unknowns = []
            role_records = {
                role: evidence_by_id[evidence_id]
                for role, evidence_id in finding.provenance_ids.items()
                if evidence_id in verified_records
            }
            version_record = role_records.get("version") or next((
                evidence_by_id[evidence_id] for evidence_id in verified_records
                if evidence_by_id[evidence_id].type == EvidenceType.VERSION
                and evidence_by_id[evidence_id].metadata.get("advisory_id") == finding.vulnerability_id
            ), None)
            advisory_record = role_records.get("vulnerability_advisory") or next((
                evidence_by_id[evidence_id] for evidence_id in verified_records
                if evidence_by_id[evidence_id].type == EvidenceType.VULNERABILITY_ADVISORY
                and evidence_by_id[evidence_id].metadata.get("advisory_id") == finding.vulnerability_id
            ), None)
            matching_version = bool(
                version_record
                and version_record.type == EvidenceType.VERSION
                and version_record.metadata.get("advisory_id") == finding.vulnerability_id
                and version_record.metadata.get("observed_version") == finding.component.version
                and version_record.metadata.get("status") in {"AFFECTED", "NOT_AFFECTED", "UNKNOWN"}
            )
            matching_advisory = bool(
                advisory_record
                and advisory_record.type == EvidenceType.VULNERABILITY_ADVISORY
                and advisory_record.metadata.get("advisory_id") == finding.vulnerability_id
                and advisory_record.metadata.get("package") == finding.component.name
            )
            finding_refs = tuple(record.id for record, matches in ((version_record, matching_version), (advisory_record, matching_advisory)) if record and matches)
            if matching_version:
                status = version_record.metadata["status"]
                claims_list.append(CopilotFact("finding", f"Osprey recorded {finding.vulnerability_id} for package {finding.component.name}, observed version {finding.component.version}, with affected-version status {status}.", finding_refs))
            else:
                unknowns.append("Vulnerability and version evidence is UNKNOWN because no integrity-verified advisory/version record is linked.")
            reach_record = role_records.get("reachability") or next((
                evidence_by_id[evidence_id] for evidence_id in verified_records
                if evidence_by_id[evidence_id].type == EvidenceType.REACHABILITY
                and evidence_by_id[evidence_id].metadata.get("finding_id") == finding.id
            ), None)
            reach = reach_record.metadata.get("observed", {}) if reach_record and reach_record.type == EvidenceType.REACHABILITY else {}
            if reach_record is not None and isinstance(reach, dict) and reach_record.metadata.get("finding_id") == finding.id and reach.get("status") in {"REACHABLE", "NOT_REACHABLE", "UNKNOWN"}:
                safe_path = reach.get("path") if isinstance(reach.get("path"), list) else []
                path_text = " → ".join(str(item)[:200] for item in safe_path[:16] if isinstance(item, str)) or "UNKNOWN"
                confidence = reach.get("confidence")
                if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
                    confidence = "UNKNOWN"
                claims_list.append(CopilotFact("reachability", f"Static reachability is {reach['status']} with confidence {confidence}; path={path_text}.", (reach_record.id,)))
            else:
                unknowns.append("Static reachability is UNKNOWN because no integrity-verified reachability record is linked.")
            risk_record = role_records.get("risk") or next((
                evidence_by_id[evidence_id] for evidence_id in verified_records
                if evidence_by_id[evidence_id].type == EvidenceType.RISK
                and evidence_by_id[evidence_id].metadata.get("finding_id") == finding.id
            ), None)
            risk_payload = risk_record.metadata.get("observed", {}) if risk_record and risk_record.type == EvidenceType.RISK else {}
            assessment = risk_payload.get("assessment", {}) if isinstance(risk_payload, dict) else {}
            if risk_record is not None and isinstance(assessment, dict) and risk_record.metadata.get("finding_id") == finding.id and assessment.get("decision") in {"ACT NOW", "PLAN", "MONITOR", "IGNORE", "UNKNOWN"}:
                score = assessment.get("score")
                if not isinstance(score, (int, float)) or isinstance(score, bool) or not 0 <= score <= 100:
                    score = "UNKNOWN"
                claims_list.append(CopilotFact("risk", f"The shared deterministic risk engine recorded decision={assessment['decision']}; score={score}.", (risk_record.id,)))
            else:
                unknowns.append("Risk result is UNKNOWN because no integrity-verified risk assessment is linked.")
            runtime_states = {name: "UNKNOWN" for name in ("DECLARED", "LOCKED", "INSTALLED", "LOADED", "EXERCISED")}
            runtime_refs = []
            for evidence_id in verified_records:
                record = evidence_by_id[evidence_id]
                if record.type == EvidenceType.MANIFEST and record.metadata.get("component_purl") == finding.component.purl:
                    runtime_states["DECLARED"] = "OBSERVED"
                    runtime_refs.append(record.id)
                elif record.type == EvidenceType.LOCKFILE and record.metadata.get("component_purl") == finding.component.purl:
                    runtime_states["LOCKED"] = "OBSERVED"
                    runtime_refs.append(record.id)
                elif record.type == EvidenceType.INSTALLATION_OBSERVATION:
                    observed = record.metadata.get("observed", {})
                    if isinstance(observed, dict) and observed.get("component_purl") == finding.component.purl and observed.get("package_name") == finding.component.name and observed.get("version") == finding.component.installed_version:
                        runtime_states["INSTALLED"] = "OBSERVED"
                        runtime_refs.append(record.id)
                elif record.type == EvidenceType.RUNTIME_OBSERVATION:
                    observed = record.metadata.get("observed", {})
                    if not isinstance(observed, dict) or observed.get("package_name") != finding.component.name or observed.get("version") != finding.component.version:
                        continue
                    if observed.get("state") not in {"LOADED", "EXERCISED"} or observed.get("deterministic") is not True:
                        continue
                    if runtime_evidence_freshness(record.timestamp) != "CURRENT":
                        continue
                    if observed.get("state") == "LOADED":
                        runtime_states["LOADED"] = "OBSERVED"
                        runtime_refs.append(record.id)
                    elif observed.get("state") == "EXERCISED" and any(item in runtime_refs for item in observed.get("basis_evidence_ids", []) if isinstance(item, str)):
                        runtime_states["EXERCISED"] = "OBSERVED"
                        runtime_refs.append(record.id)
            if runtime_refs:
                claims_list.append(CopilotFact("runtime", "Runtime states: " + ", ".join(f"{key}={value}" for key, value in runtime_states.items()) + ". Missing observations remain UNKNOWN.", tuple(dict.fromkeys(runtime_refs))))
            if not runtime_refs:
                unknowns.append("Runtime state is UNKNOWN because no current integrity-verified runtime observation is linked.")
            unknowns.append("Remediation and verification state is UNKNOWN because this scan has no linked integrity-verified remediation event evidence.")
            claims = tuple(claims_list)
            limitations = tuple(finding.risk_limitations[:16]) + tuple(finding.runtime_limitations[:16])
            context_payload = {"finding_id": finding.id, "facts": [{"key": fact.key, "text": fact.text, "evidence_ids": list(fact.evidence_ids)} for fact in claims], "limitations": limitations}
            context = CopilotContext(
                finding_id=finding.id,
                context_hash=hashlib.sha256(canonical_json(context_payload).encode("utf-8")).hexdigest(),
                facts=claims,
                unknowns=tuple(unknowns),
                limitations=limitations,
                next_steps=(("review-advisory", "Review the advisory and version evidence."), ("inspect-source", "Review the static reachability path and its limitations."), ("collect-runtime", "Collect explicit runtime observations if runtime relevance matters."), ("review-remediation", "Review persisted remediation and verification records if they are available.")),
                security_confidence="Evidence-derived; see cited deterministic records.",
                runtime_states=tuple(runtime_states.items()),
            )
            provider = EvidenceOnlyProvider()
            rendered = render_facts(context, provider.select(question, context))
            output = {
                "mode": "EVIDENCE_ONLY_READ_ONLY",
                "finding_id": finding.id,
                "question": question,
                "summary": "Osprey's deterministic records support the following statements.",
                "claims": [{"text": fact.text, "evidence_ids": list(fact.evidence_ids)} for fact in rendered],
                "unknowns": list(context.unknowns),
                "limitations": list(context.limitations),
                "recommended_next_steps": [text for _, text in context.next_steps],
                "security_confidence": context.security_confidence,
                "ai_explanation_confidence": "UNKNOWN",
            }
            Console().print(Text(json.dumps(output, sort_keys=True, indent=2)))
            sys.exit(0)
        found = explain_finding(finding_id, result.findings, result.graph)
        if not found:
            sys.exit(1)
        sys.exit(0)
    except Exception as e:
        if debug:
            raise
        err_console.print(f"[bold red]Explain error:[/] {e}")
        sys.exit(2)


@app.command(name="remediate")
def remediate_cmd(
    finding_id: Optional[str] = typer.Argument(None, help="Finding ID to propose for; omit when applying by proposal ID."),
    path: str = typer.Option(".", "--path", "-p", help="Workspace path (proposal mode is read-only)."),
    apply: Optional[str] = typer.Option(None, "--apply", help="Apply this proposal ID after explicit --approve."),
    approve: bool = typer.Option(False, "--approve", help="Explicitly approve the requested local file change."),
) -> None:
    """Show a read-only proposal or apply an exact, still-current supported npm proposal."""
    try:
        root = Path(path).resolve(strict=True)
        before = scan_workspace(target_path=root, offline=True)
        findings = [f for f in before.findings if finding_id is None or f.id == finding_id]
        proposals = [create_proposal(root, finding) for finding in findings]
        if apply is None:
            if not findings:
                raise ValueError("finding was not present in the current scan")
            print(json.dumps([asdict(item) for item in proposals], sort_keys=True, indent=2))
            return
        if approve is not True:
            raise PermissionError("apply requires the explicit --approve flag")
        selected = next(((proposal, finding) for proposal, finding in zip(proposals, findings)
                         if proposal.proposal_id == apply), None)
        if selected is None:
            raise RuntimeError("STALE_PROPOSAL: proposal ID no longer matches current scan inputs")
        proposal, finding = selected
        result = apply_npm_proposal(root, proposal, approved=True, finding=finding)
        after = scan_workspace(target_path=root, offline=True)
        verification = verify_post_scan(proposal, after)
        result.update({"verification": verification["state"],
                       "verification_result": verification,
                       "post_scan_completed": True})
        print(json.dumps(result, sort_keys=True, indent=2))
    except Exception as exc:
        err_console.print(f"[bold red]Remediation error:[/] {exc}")
        raise typer.Exit(2)


@app.command(name="init")
def init_cmd(
    target: str = typer.Option(".", "--path", "-p", help="Directory where osprey.yaml should be written."),
    debug: bool = typer.Option(False, "--debug", help="Enable verbose error tracebacks."),
) -> None:
    """Initialize a default osprey.yaml configuration file with commented override templates."""
    try:
        out_path = Path(target) / "osprey.yaml"
        if out_path.exists():
            err_console.print(f"[bold yellow]osprey.yaml already exists at {out_path}[/]")
            return

        out_path.write_text(SAMPLE_OSPREY_YAML, encoding="utf-8")
        err_console.print(f"[bold green]Initialized osprey.yaml at {out_path}[/]")
    except Exception as e:
        if debug:
            raise
        err_console.print(f"[bold red]Init error:[/] {e}")
        sys.exit(2)


@app.command(name="demo")
def demo_cmd(
    offline: bool = typer.Option(False, "--offline", help="Run strictly offline using local threat cache without network calls."),
    debug: bool = typer.Option(False, "--debug", help="Enable verbose error tracebacks."),
) -> None:
    """Run Osprey against the bundled vulnerable Express and FastAPI sample app."""
    try:
        # Locate examples/vulnerable-app relative to package or repo root
        demo_dir = Path(__file__).resolve().parent.parent.parent / "examples" / "vulnerable-app"
        if not demo_dir.exists():
            # Alternative fallback: look in current working directory
            alt = Path("examples") / "vulnerable-app"
            if alt.exists():
                demo_dir = alt.resolve()

        if not demo_dir.exists():
            err_console.print(f"[bold red]Demo folder not found at {demo_dir}[/]")
            sys.exit(2)

        err_console.print("[dim]Scanning bundled vulnerable sample application...[/]\n")
        result = scan_workspace(target_path=demo_dir, offline=offline)
        render_terminal_report(result, detail=False)
        sys.exit(0)
    except Exception as e:
        if debug:
            raise
        err_console.print(f"[bold red]Demo error:[/] {e}")
        sys.exit(2)



if __name__ == "__main__":
    app()
