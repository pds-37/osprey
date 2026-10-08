"""Filesystem workspace scanner and vulnerability orchestrator.

GUARDRAILS:
- Read-only text parsing on target directory.
- Never executes, installs, or imports code from scanned project.
- Ignores node_modules, .git, venv, and build artifacts.
- Enforces strict network timeouts and fail-soft behavior.
"""

from __future__ import annotations

import logging
import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Set

import yaml

from osprey.exposure import (
    evaluate_exposure,
    map_component_to_service,
)
from osprey.fixes import determine_fix_status
from osprey.graph import SupplyChainGraph
from osprey.intel.cache import IntelCache
from osprey.intel.epss_kev import EpssKevClient
from osprey.intel.osv import OsvClient
from osprey.models import Component, ExposureInfo, Finding, Service
from osprey.parsers.docker import DockerParser
from osprey.parsers.npm import NpmParser
from osprey.parsers.pypi import PyPiParser
from osprey.risk import calculate_risk, parse_advisory_severity, RiskEvidence
from osprey import __version__
from osprey.core.evidence import EvidenceStore, canonical_json
from osprey.core.provenance import (
    record_analysis_limitations,
    record_analysis_run,
    record_reachability,
    record_risk_assessment,
)
from osprey.core.models import EvidenceType, VersionMatchStatus
from osprey.runtime import InstallationInspector, summarize_runtime_state
from osprey.filesystem import is_reparse_point, walk_workspace
from osprey.core.symbols import extract_osv_affected_records, extract_osv_vulnerable_symbols
from osprey.analyzers.reachability import analyze_reachability
from osprey.analyzers.source import SourceAnalysis, analyze_source_files

logger = logging.getLogger(__name__)

MAX_MANIFEST_FILES = 2_000
MAX_MANIFEST_FILE_BYTES = 20_000_000
MAX_MANIFEST_TOTAL_BYTES = 50_000_000
MAX_INVENTORY_COMPONENTS = 20_000

SKIP_DIRS: Set[str] = {
    "node_modules",
    ".git",
    "venv",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    ".next",
    ".cache",
    "target",
    ".idea",
    ".vscode",
}


@dataclass
class ScanResult:
    """Consolidated result of an Osprey workspace scan."""

    root_path: Path
    app_name: str
    components: List[Component]
    services: List[Service]
    findings: List[Finding]
    graph: SupplyChainGraph
    manifests: List[str]
    duration_seconds: float
    offline_mode: bool = False
    evidence: List[Any] = field(default_factory=list)
    source_analysis: SourceAnalysis | None = None
    analysis_provenance_id: str | None = None
    analysis_limitations_evidence_id: str | None = None
    advisory_coverage: Dict[str, str] = field(default_factory=dict)


def load_osprey_config(root_path: Path) -> Dict[str, Any]:
    """Load optional osprey.yaml configuration file for user-declared overrides."""
    root = root_path.resolve()
    config_file = root / "osprey.yaml"
    if not config_file.exists():
        config_file = root / ".osprey.yaml"
    if not config_file.exists():
        return {}

    try:
        if is_reparse_point(config_file):
            return {}
        resolved = config_file.resolve(strict=True)
        resolved.relative_to(root)
        if not resolved.is_file() or resolved.stat().st_size > 1_000_000:
            return {}
        content = resolved.read_text(encoding="utf-8", errors="replace")
        data = yaml.safe_load(content)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError, yaml.YAMLError, RecursionError) as e:
        logger.debug("Failed to read osprey.yaml (%s)", type(e).__name__)
        return {}


def _read_source_files(root_path: Path) -> tuple[dict[str, str], list[str]]:
    """Read a bounded source subset without following symlinks or executing code."""
    sources: dict[str, str] = {}
    errors: list[str] = []
    total_bytes = 0
    supported = {".py", ".js", ".jsx", ".ts", ".tsx", ".go"}
    for current_dir, _dirs, files, skipped in walk_workspace(root_path, skip_dirs=SKIP_DIRS, max_depth=4):
        if skipped:
            errors.append("Symlink, reparse-point, or outside-workspace source entries were skipped")
        for name in files:
            file_path = current_dir / name
            if file_path.suffix.lower() not in supported or file_path.is_symlink():
                continue
            try:
                resolved = file_path.resolve()
                relative = resolved.relative_to(root_path).as_posix()
                size = resolved.stat().st_size
                if size > 1_000_000:
                    errors.append(f"{relative}: source exceeds analyzer file-size limit")
                    continue
                if len(sources) >= 2000 or total_bytes + size > 20_000_000:
                    errors.append("Source scan reached the 2,000-file or 20 MB analysis bound")
                    return sources, errors
                content = resolved.read_text(encoding="utf-8", errors="replace")
                sources[relative] = content
                total_bytes += size
            except (OSError, ValueError) as exc:
                errors.append(f"{file_path.name}: source could not be read ({type(exc).__name__})")
    return sources, errors


def _advisory_vulnerable_symbols(
    raw_vuln: Dict[str, Any],
    *,
    package: str = "",
    ecosystem: str = "",
    vulnerability_id: str | None = None,
):
    """Retain only OSV symbols scoped to this affected package record."""
    return extract_osv_vulnerable_symbols(
        raw_vuln,
        package=package,
        ecosystem=ecosystem,
        vulnerability_id=vulnerability_id,
    )


def scan_workspace(
    target_path: str | Path = ".",
    offline: bool = False,
    timeout: float = 5.0,
    evidence_store: EvidenceStore | None = None,
) -> ScanResult:
    """Scan target workspace directory for components, correlate intel, and triage risk."""
    start_time = time.time()
    root_path = Path(target_path).resolve()
    if not root_path.exists():
        raise FileNotFoundError(f"Target path '{target_path}' does not exist (resolved: {root_path}).")

    app_name = root_path.name or "app"
    config = load_osprey_config(root_path)
    analysis_evidence_store = evidence_store or EvidenceStore()
    existing_evidence_ids = {record.id for record in analysis_evidence_store.list()}

    # 1. Initialize parsers
    npm_parser = NpmParser()
    pypi_parser = PyPiParser()
    docker_parser = DockerParser()

    discovered_components: List[Component] = []
    discovered_services: List[Service] = []
    manifest_files: List[str] = []

    # 2. Walk directory tree (max depth 4, skip ignored dirs)
    manifest_errors: list[str] = []
    manifest_count = 0
    manifest_bytes = 0
    manifest_limited = False

    def add_components(items: list[Component]) -> None:
        nonlocal manifest_limited
        remaining = MAX_INVENTORY_COMPONENTS - len(discovered_components)
        if remaining <= 0:
            manifest_errors.append("Inventory parsing reached its 20,000-component safety limit")
            manifest_limited = True
            return
        discovered_components.extend(items[:remaining])
        if len(items) > remaining or len(discovered_components) >= MAX_INVENTORY_COMPONENTS:
            manifest_errors.append("Inventory parsing reached its 20,000-component safety limit")
            manifest_limited = True

    for dir_path, _dirs, files, skipped in walk_workspace(root_path, skip_dirs=SKIP_DIRS, max_depth=4):
        if skipped:
            manifest_errors.append("Symlink, reparse-point, or outside-workspace manifest entries were skipped")
        for f in files:
            file_path = dir_path / f
            if not (docker_parser.detect(file_path) or npm_parser.detect(file_path) or pypi_parser.detect(file_path)):
                continue
            try:
                manifest_size = file_path.stat().st_size
            except OSError:
                manifest_errors.append("A manifest could not be inspected and was skipped")
                continue
            if manifest_size > MAX_MANIFEST_FILE_BYTES:
                manifest_errors.append("A manifest exceeded the 20 MB parser safety limit and was skipped")
                continue
            if manifest_count >= MAX_MANIFEST_FILES or manifest_bytes + manifest_size > MAX_MANIFEST_TOTAL_BYTES:
                manifest_errors.append("Manifest scanning reached its 2,000-file or 50 MB safety limit")
                manifest_limited = True
                break
            manifest_count += 1
            manifest_bytes += manifest_size
            # Relative manifest path
            try:
                rel_manifest = str(file_path.relative_to(root_path))
            except Exception:
                rel_manifest = file_path.name

            # Docker / Compose
            if docker_parser.detect(file_path):
                comps = docker_parser.parse(file_path)
                svcs = docker_parser.parse_services(file_path, workspace_root=root_path)
                if docker_parser.last_error:
                    manifest_errors.append(f"{rel_manifest}: {docker_parser.last_error}")
                if comps or svcs:
                    add_components(comps)
                    discovered_services.extend(svcs)
                    manifest_files.append(rel_manifest)
                if manifest_limited:
                    break
                continue

            # Node.js npm
            if npm_parser.detect(file_path):
                comps = npm_parser.parse(file_path)
                if npm_parser.last_error:
                    manifest_errors.append(f"{rel_manifest}: {npm_parser.last_error}")
                if comps:
                    add_components(comps)
                    manifest_files.append(rel_manifest)
                if manifest_limited:
                    break
                continue

            # Python PyPI
            if pypi_parser.detect(file_path):
                comps = pypi_parser.parse(file_path)
                if pypi_parser.last_error:
                    manifest_errors.append(f"{rel_manifest}: {pypi_parser.last_error}")
                if comps:
                    add_components(comps)
                    manifest_files.append(rel_manifest)
                if manifest_limited:
                    break
                continue
        if manifest_limited:
            break

    # Preserve same-package observations from distinct manifests and lockfiles.
    comp_map: Dict[str, Component] = {}
    for comp in discovered_components:
        comp_map.setdefault(comp.observation_id, comp)
    components = list(comp_map.values())

    installation_inspector = InstallationInspector(root_path)
    lockfile_names = {
        "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock",
        "poetry.lock", "pdm.lock", "uv.lock", "pipfile.lock", "cargo.lock", "go.sum",
    }
    for comp in components:
        source_path = Path(comp.source_file.replace("\\", "/"))
        source_name = source_path.name.lower()
        if source_name in lockfile_names:
            comp.locked_version = comp.version
        elif source_name in {
            "package.json", "pyproject.toml", "pipfile", "go.mod", "cargo.toml",
        } or source_name.startswith("requirements") and source_name.endswith(".txt"):
            comp.declared_version = comp.version
        installed = installation_inspector.inspect(
            comp.name,
            comp.ecosystem,
            manifest_directory=root_path / source_path.parent,
        )
        if installed is None:
            continue
        comp.installed_version = installed.version
        payload = {
            **installed.as_dict(),
            "component_purl": comp.purl,
            "observation_id": comp.observation_id,
        }
        record = analysis_evidence_store.add(
            evidence_type=EvidenceType.INSTALLATION_OBSERVATION,
            source=installed.source,
            location=installed.location,
            content=canonical_json(payload),
            confidence=1.0,
            metadata={
                "analyzer": "Osprey",
                "analyzer_version": __version__,
                "analysis_type": "bounded_installation_metadata_inspection",
                "observed": payload,
            },
        )
        comp.installation_evidence_id = record.id
        comp.evidence_ids.append(record.id)

    # Source parsing is bounded and read-only. It never imports or executes project code.
    source_files, source_errors = _read_source_files(root_path)
    source_analysis: SourceAnalysis = analyze_source_files(
        source_files,
        [component.name for component in components],
        analysis_evidence_store,
    )
    source_analysis.errors.extend(source_errors)
    source_analysis.errors.extend(manifest_errors)
    analysis_run = record_analysis_run(
        analysis_evidence_store,
        source_analysis,
        analysis_type="workspace_scan",
    )
    analysis_limitations_record = record_analysis_limitations(
        analysis_evidence_store,
        source_analysis.errors,
        analysis_run_id=analysis_run.id,
    )

    # Attach source-manifest evidence to each inventory observation.
    manifest_digests: dict[str, str] = {}
    for comp in components:
        if not comp.source_file:
            continue
        try:
            path = Path(comp.source_file)
            if not path.is_absolute():
                path = root_path / path
            path = path.resolve()
            relative = path.relative_to(root_path).as_posix()
            digest = manifest_digests.get(relative)
            if digest is None:
                raw_manifest = path.read_bytes()
                digest = hashlib.sha256(raw_manifest).hexdigest()
                manifest_digests[relative] = digest
            kind = EvidenceType.LOCKFILE if "lock" in path.name.lower() or path.suffix.lower() == ".lock" else EvidenceType.MANIFEST
            record = analysis_evidence_store.add(
                evidence_type=kind,
                source="workspace file scanner",
                location=relative,
                content_hash=digest,
                confidence=0.98,
                metadata={"component_purl": comp.purl, "observation_id": comp.observation_id},
            )
            comp.evidence_ids.append(record.id)
        except (OSError, ValueError):
            continue

    # Static route declarations prove application entrypoints, not external
    # routing. Keep the observation for context, but never label it PUBLIC.
    ambient_exposures = [
        ExposureInfo(
            level="unknown",
            confidence="inferred",
            evidence=f"Static {item.framework} {item.method} {item.route} at {item.file}:{item.line}; external routing and authentication are not observed",
        )
        for item in source_analysis.exposures
    ]

    # If services have exposed ports, add to ambient
    for svc in discovered_services:
        if svc.exposure:
            ambient_exposures.append(svc.exposure)

    # 4. Intelligence queries (OSV, CISA KEV, EPSS)
    cache = IntelCache(offline=offline)
    osv_client = OsvClient(cache=cache, timeout=timeout, offline=offline)
    epss_kev_client = EpssKevClient(cache=cache, timeout=timeout, offline=offline)

    osv_results = osv_client.query_components(components)
    advisory_coverage = {
        component.observation_id: osv_client.coverage_by_component.get(component.key, "UNAVAILABLE")
        for component in components
    }

    # Collect CVEs for KEV and EPSS lookup
    cve_set: Set[str] = set()
    for _comp_key, vulns in osv_results.items():
        for v in vulns:
            vid = v.get("id", "")
            if vid.startswith("CVE-"):
                cve_set.add(vid)
            for alias in v.get("aliases", []):
                if str(alias).startswith("CVE-"):
                    cve_set.add(str(alias))

    cve_list = list(cve_set)
    kev_catalog = epss_kev_client.get_cisa_kev_catalog()
    epss_scores = epss_kev_client.get_epss_scores(cve_list)

    # 5. Build Knowledge Graph & synthesize Findings
    graph = SupplyChainGraph(app_name=app_name)
    svc_node_ids = {}
    for svc in discovered_services:
        sid = graph.add_service(svc)
        svc_node_ids[svc.name] = sid

    findings: List[Finding] = []
    seen_vuln_keys: Set[str] = set()

    for comp in components:
        comp_vulns = osv_results.get(comp.key, [])
        owning_service = map_component_to_service(comp, discovered_services, root_path)
        comp_exposure = evaluate_exposure(
            component=comp,
            service=owning_service,
            ambient_exposures=ambient_exposures,
            overrides=config,
        )

        svc_id = svc_node_ids.get(owning_service.name) if owning_service else None
        graph.add_component(comp, service_id=svc_id)


        for raw_v in comp_vulns:
            vuln_id = raw_v.get("id", "VULN-UNKNOWN")
            vuln_key = f"{comp.observation_id}:{vuln_id}"
            if vuln_key in seen_vuln_keys:
                continue
            seen_vuln_keys.add(vuln_key)

            aliases = [str(a) for a in raw_v.get("aliases", [])]

            # Determine CVSS and severity
            severity, cvss_score = parse_advisory_severity(raw_v)

            # Check CISA KEV
            in_kev = vuln_id in kev_catalog or any(a in kev_catalog for a in aliases)

            # Check EPSS
            epss_val = epss_scores.get(vuln_id)
            if epss_val is None:
                for a in aliases:
                    if a in epss_scores:
                        epss_val = epss_scores[a]
                        break

            # Fix status
            fix_status = determine_fix_status(comp.version, raw_v, ecosystem=comp.ecosystem)

            vulnerable_symbols = _advisory_vulnerable_symbols(
                raw_v,
                package=comp.name,
                ecosystem=comp.ecosystem,
                vulnerability_id=vuln_id,
            )
            scoped_affected = [
                record for _index, record in extract_osv_affected_records(
                    raw_v,
                    package=comp.name,
                    ecosystem=comp.ecosystem,
                )
            ]
            scoped_fixed_versions = [
                str(event["fixed"])
                for affected in scoped_affected
                for version_range in affected.get("ranges", [])
                if isinstance(version_range, dict)
                for event in version_range.get("events", [])
                if isinstance(event, dict) and isinstance(event.get("fixed"), str)
            ]

            inference_evidence = analysis_evidence_store.add(
                evidence_type=EvidenceType.SOURCE_EXPOSURE if comp_exposure.confidence == "inferred" else EvidenceType.USER_INPUT,
                source="Osprey package-level exposure analysis",
                location=comp_exposure.evidence.split(":", 1)[0] or "workspace configuration",
                content=comp_exposure.evidence,
                confidence=0.65 if comp_exposure.confidence == "inferred" else 0.85,
                metadata={
                    "exposure_level": comp_exposure.level,
                    "confidence_label": comp_exposure.confidence,
                    "analyzer": "Osprey",
                    "analyzer_version": __version__,
                    "analysis_type": "package_exposure",
                },
            )
            advisory_json = canonical_json(raw_v)
            advisory_evidence = analysis_evidence_store.add(
                evidence_type=EvidenceType.VULNERABILITY_ADVISORY,
                source="OSV advisory data",
                location=vuln_id,
                content=advisory_json,
                confidence=0.95,
                metadata={
                    "component": comp.name,
                    "ecosystem": comp.ecosystem,
                    "observed_version": comp.version,
                    "advisory_source": "OSV",
                    "retrieval_mode": "offline_cache" if offline else "cache_or_network",
                },
            )
            version_record = analysis_evidence_store.add(
                evidence_type=EvidenceType.VERSION,
                source="OSV affected-version query",
                location=vuln_id,
                content=canonical_json({
                    "package": comp.name,
                    "ecosystem": comp.ecosystem,
                    "observed_version": comp.version,
                    "status": VersionMatchStatus.AFFECTED.value,
                    "query_returned_advisory_for_observed_version": True,
                    "affected": scoped_affected,
                    "fixed_versions": list(dict.fromkeys(scoped_fixed_versions)),
                }),
                confidence=0.95,
                metadata={
                    "analyzer": "Osprey",
                    "analyzer_version": __version__,
                    "analysis_type": "OSV_version_match",
                    "vulnerability_id": vuln_id,
                    "package": comp.name,
                    "ecosystem": comp.ecosystem,
                    "observed_version": comp.version,
                    "version_status": VersionMatchStatus.AFFECTED.value,
                    "matching_method": "OSV query returned this advisory for the observed package version",
                    "affected_records": scoped_affected,
                    "fixed_versions": list(dict.fromkeys(scoped_fixed_versions)),
                },
            )
            symbol_evidence = [
                analysis_evidence_store.add(
                    evidence_type=EvidenceType.VULNERABLE_SYMBOL,
                    source=symbol.source,
                    location=vuln_id,
                    content=canonical_json(asdict(symbol)),
                    confidence=symbol.confidence,
                    metadata={
                        "analyzer": "Osprey",
                        "analyzer_version": __version__,
                        "vulnerability_id": vuln_id,
                        "package": symbol.package,
                        "ecosystem": symbol.ecosystem,
                        "symbol": symbol.symbol,
                    },
                )
                for symbol in vulnerable_symbols
            ]
            reachability = analyze_reachability(
                source_analysis,
                package=comp.name,
                vulnerable_symbols=vulnerable_symbols,
                direct_dependency=False,
                ecosystem=comp.ecosystem,
                symbol_evidence_ids=[advisory_evidence.id] if vulnerable_symbols else [],
            )
            reachability_record, limitation_record = record_reachability(
                analysis_evidence_store,
                reachability,
                finding_id=vuln_key,
                analysis_run_id=analysis_run.id,
            )
            runtime_snapshot = summarize_runtime_state(
                analysis_evidence_store,
                package_name=comp.name,
                ecosystem=comp.ecosystem.lower(),
                version=comp.version,
                declared_observed=comp.declared_version is not None,
                locked_observed=comp.locked_version is not None,
                installed_observed=comp.installed_version is not None,
                finding_id=vuln_key,
            )
            external_evidence = [
                inference_evidence.id,
                advisory_evidence.id,
                version_record.id,
                analysis_run.id,
                reachability_record.id,
                *runtime_snapshot.evidence_ids,
                *(item.id for item in symbol_evidence),
            ]
            if limitation_record:
                external_evidence.append(limitation_record.id)
            if analysis_limitations_record:
                external_evidence.append(analysis_limitations_record.id)
            if epss_val is not None:
                external_evidence.append(analysis_evidence_store.add(
                    evidence_type=EvidenceType.EPSS,
                    source="FIRST EPSS lookup",
                    location=vuln_id,
                    content=str(epss_val),
                    confidence=0.85,
                    metadata={"score": epss_val},
                ).id)
            if epss_kev_client.kev_catalog_available:
                external_evidence.append(analysis_evidence_store.add(
                    evidence_type=EvidenceType.CISA_KEV,
                    source="CISA KEV catalog (live or cache)",
                    location=vuln_id,
                    content="listed" if in_kev else "not-listed",
                    confidence=0.8,
                    metadata={"listed": in_kev},
                ).id)

            # CLI uses the same evidence contract and calculation as the backend.
            risk_inputs = RiskEvidence(
                severity=severity,
                cvss_score=cvss_score,
                epss_score=epss_val,
                kev_listed=in_kev if epss_kev_client.kev_catalog_available else None,
                version_status=VersionMatchStatus.AFFECTED.value,
                dependency_present=True,
                exposure=comp_exposure.level,
                exposure_confidence=comp_exposure.confidence,
                reachability_status=reachability.status.value,
                reachability_confidence=reachability.confidence,
                source_analysis_complete=not bool(reachability.limitations),
                runtime_observed=True if runtime_snapshot.loaded_current else None,
                evidence_ids=tuple([*comp.evidence_ids, *external_evidence, *reachability.evidence]),
                limitations=tuple([*reachability.limitations, *runtime_snapshot.limitations]),
            )
            assessment = calculate_risk(risk_inputs)
            risk_record = record_risk_assessment(
                analysis_evidence_store,
                risk_inputs,
                assessment,
                finding_id=vuln_key,
            )
            risk_tier = assessment.decision
            firing_rule = assessment.explanation

            finding = Finding(
                id=vuln_key,
                vulnerability_id=vuln_id,
                component=comp,
                exposure=comp_exposure,
                fix_status=fix_status,
                risk_tier=risk_tier,
                firing_rule=firing_rule,
                service=owning_service,
                cvss_score=cvss_score,
                severity=severity,
                epss_score=epss_val,
                in_cisa_kev=in_kev,
                kev_available=epss_kev_client.kev_catalog_available,
                risk_score=assessment.score,
                risk_level=assessment.risk_level,
                risk_factors=[{
                    "name": factor.name,
                    "weight": factor.weight,
                    "score": factor.score,
                    "description": factor.description,
                } for factor in assessment.factors],
                risk_limitations=list(assessment.limitations),
                summary=raw_v.get("summary", ""),
                details=raw_v.get("details", ""),
                aliases=aliases,
                raw_vuln=raw_v,
                package_status=VersionMatchStatus.AFFECTED,
                reachability=reachability,
                evidence_ids=list(dict.fromkeys([
                    *comp.evidence_ids,
                    *external_evidence,
                    *reachability.evidence,
                    risk_record.id,
                ])),
                risk_inputs=asdict(risk_inputs),
                provenance_ids={
                    "vulnerability_advisory": advisory_evidence.id,
                    "version": version_record.id,
                    "analysis_run": analysis_run.id,
                    "reachability": reachability_record.id,
                    "risk": risk_record.id,
                    **({"reachability_limitations": limitation_record.id} if limitation_record else {}),
                    **({"analysis_limitations": analysis_limitations_record.id} if analysis_limitations_record else {}),
                    **({"vulnerable_symbols": symbol_evidence[0].id} if symbol_evidence else {}),
                },
                runtime_state=runtime_snapshot.states,
                runtime_evidence_ids=list(runtime_snapshot.evidence_ids),
                runtime_limitations=list(runtime_snapshot.limitations),
            )


            findings.append(finding)
            graph.add_finding(finding)

    # Sort findings by priority: ACT NOW -> PLAN -> MONITOR -> IGNORE
    priority_order = {"ACT NOW": 0, "PLAN": 1, "UNKNOWN": 2, "MONITOR": 3, "IGNORE": 4}
    findings.sort(key=lambda f: (priority_order.get(f.risk_tier, 99), f.component.name))

    duration = time.time() - start_time
    return ScanResult(
        root_path=root_path,
        app_name=app_name,
        components=components,
        services=discovered_services,
        findings=findings,
        graph=graph,
        manifests=manifest_files,
        duration_seconds=duration,
        offline_mode=offline,
        evidence=[
            record for record in analysis_evidence_store.list()
            if record.id not in existing_evidence_ids
            or any(record.id in finding.evidence_ids for finding in findings)
        ],
        source_analysis=source_analysis,
        analysis_provenance_id=analysis_run.id,
        analysis_limitations_evidence_id=(
            analysis_limitations_record.id if analysis_limitations_record else None
        ),
        advisory_coverage=advisory_coverage,
    )
