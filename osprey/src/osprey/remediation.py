"""Bounded, approval-gated npm dependency remediation helpers.

Only package.json and npm package-lock v2/v3 are supported. No package manager,
registry, project code, or lifecycle script is invoked by this module.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from osprey.core.evidence import canonical_json
from osprey.core.models import VersionMatchStatus
from osprey.core.versioning import compare_versions, evaluate_version
from osprey.fixes import extract_fixed_versions
from osprey.models import Finding


@dataclass(frozen=True)
class RemediationProposal:
    proposal_id: str
    finding_id: str
    vulnerability_id: str
    package: str
    current_version: str
    target_version: str | None
    target_reason: str
    package_manager: str
    manifest_path: str | None
    lockfile_path: str | None
    files_to_change: tuple[str, ...]
    input_hashes: dict[str, str]
    risk_before: dict[str, Any]
    expected_outcome: str
    status: str
    limitations: tuple[str, ...]
    evidence_ids: tuple[str, ...] = ()
    affected_records: tuple[dict[str, Any], ...] = ()


class RemediationApplyError(RuntimeError):
    def __init__(self, message: str, *, rollback_verified: bool,
                 files_attempted: tuple[str, ...], original_hashes: dict[str, str] | None = None,
                 modified_hashes: dict[str, str] | None = None):
        super().__init__(message)
        self.rollback_verified = rollback_verified
        self.files_attempted = files_attempted
        self.original_hashes = original_hashes or {}
        self.modified_hashes = modified_hashes or {}


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _strict_json(data: bytes) -> Any:
    def object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=object_from_pairs)


def _safe_relative(root: Path, candidate: Path) -> str | None:
    try:
        resolved_root = root.resolve(strict=True)
        # Reject symlinks, including symlinked parent directories.
        cursor = candidate
        while cursor != resolved_root and cursor != cursor.parent:
            if cursor.is_symlink():
                return None
            cursor = cursor.parent
        resolved = candidate.resolve(strict=True)
        return resolved.relative_to(resolved_root).as_posix()
    except (OSError, ValueError):
        return None


def _npm_range_allows(spec: str, candidate: str) -> bool:
    """Support exact, caret and tilde npm constraints; reject all other syntax."""
    match = re.fullmatch(r"\s*([~^]?)(v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\s*", spec)
    if not match:
        return False
    operator, base = match.groups()
    lo = compare_versions(candidate, base, "npm")
    if lo is None or lo < 0:
        return False
    if not operator:
        return lo == 0
    target = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:-.*)?", base)
    actual = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)(?:-.*)?", candidate)
    if not target or not actual:
        return False
    major, minor = int(target[1]), int(target[2])
    a_major, a_minor = int(actual[1]), int(actual[2])
    if operator == "~":
        return (a_major, a_minor) == (major, minor)
    if major:
        return a_major == major
    if minor:
        return a_major == 0 and a_minor == minor
    return a_major == 0 and a_minor == 0


def create_proposal(root_path: str | Path, finding: Finding) -> RemediationProposal:
    """Create a content-addressed proposal without writing into the workspace."""
    root = Path(root_path).resolve(strict=True)
    component = finding.component
    manifest_candidate = Path(component.source_file)
    if not manifest_candidate.is_absolute():
        manifest_candidate = root / manifest_candidate
    manifest_rel = _safe_relative(root, manifest_candidate)
    lock_candidate = manifest_candidate.parent / "package-lock.json"
    lock_rel = _safe_relative(root, lock_candidate)
    limitations: list[str] = []
    current_spec: str | None = None
    target: str | None = None
    records: list[dict[str, Any]] = []
    input_hashes: dict[str, str] = {}
    package_manager = "UNSUPPORTED"
    status = "UNSUPPORTED"
    expected = "No files changed; manual review is required."
    reason = "Target cannot be established from supported local evidence."

    if component.ecosystem.lower() == "npm" and manifest_rel and lock_rel:
        try:
            if (len(component.name) > 214
                    or not re.fullmatch(r"(?:@[a-z0-9._~-]+/)?[a-z0-9._~-]+", component.name.lower())
                    or len(finding.id) > 512 or len(finding.vulnerability_id) > 256):
                raise ValueError("package or finding identity is malformed")
            manifest_bytes = manifest_candidate.read_bytes()
            lock_bytes = lock_candidate.read_bytes()
            if len(manifest_bytes) > 2_000_000 or len(lock_bytes) > 20_000_000:
                raise ValueError("dependency metadata exceeds the supported size bound")
            manifest = _strict_json(manifest_bytes)
            lock = _strict_json(lock_bytes)
            if not isinstance(manifest, dict) or not isinstance(lock, dict):
                raise ValueError("npm metadata must be JSON objects")
            lock_version = lock.get("lockfileVersion")
            if lock_version not in (2, 3):
                raise ValueError("only npm package-lock v2/v3 is supported")
            sections = ("dependencies", "devDependencies", "optionalDependencies")
            declarations = [(section, manifest.get(section, {}).get(component.name))
                            for section in sections
                            if isinstance(manifest.get(section), dict)
                            and component.name in manifest[section]]
            if len(declarations) != 1 or not isinstance(declarations[0][1], str):
                raise ValueError("package must have exactly one direct npm dependency declaration")
            section, current_spec = declarations[0]
            packages = lock.get("packages")
            if not isinstance(packages, dict):
                raise ValueError("npm lockfile package map is unavailable")
            package_entry = packages.get(f"node_modules/{component.name}")
            if not isinstance(package_entry, dict):
                raise ValueError("direct dependency lock entry is unavailable")
            candidates = []
            records = [item for item in finding.raw_vuln.get("affected", [])
                       if isinstance(item, dict)
                       and isinstance(item.get("package"), dict)
                       and str(item["package"].get("name", "")).lower() == component.name.lower()
                       and str(item["package"].get("ecosystem", "")).lower() in {"", component.ecosystem.lower()}]
            if len(records) > 32 or len(canonical_json(records).encode("utf-8")) > 65_536:
                raise ValueError("scoped advisory evidence exceeds the supported bound")
            ranges = [r for item in records for r in item.get("ranges", []) if isinstance(r, dict)]
            exacts = [v for item in records for v in item.get("versions", []) if isinstance(v, str)]
            for candidate in extract_fixed_versions(finding.raw_vuln, component.ecosystem):
                if len(candidate) > 128:
                    continue
                result = evaluate_version(candidate, component.ecosystem, ranges=ranges,
                                          exact_versions=exacts)
                if (result.status == VersionMatchStatus.NOT_AFFECTED
                        and _npm_range_allows(current_spec, candidate)
                        and compare_versions(component.version, candidate, "npm") is not None
                        and compare_versions(component.version, candidate, "npm") < 0):
                    candidates.append(candidate)
            candidates.sort(key=lambda value: tuple(int(part) for part in re.match(
                r"v?(\d+)\.(\d+)\.(\d+)", value).groups()))
            target = next((value for value in candidates
                           if _lock_contains_target(packages, component.name, value)), None)
            package_manager = "npm"
            input_hashes = {manifest_rel: _hash(manifest_bytes), lock_rel: _hash(lock_bytes)}
            if target:
                status = "PROPOSED"
                reason = "Advisory fixed boundary is outside its affected ranges, compatible with the declared npm range, and already present in the lockfile."
                expected = "Update only the direct dependency range and npm lock root requirement; no install or scripts will run."
            else:
                status = "UNKNOWN"
                reason = "No advisory-provided, range-compatible fixed version is present in the lockfile."
                limitations.append("Osprey will not query registries or resolve/install packages to invent a target.")
        except (OSError, ValueError, TypeError, json.JSONDecodeError, RecursionError) as exc:
            limitations.append(f"npm proposal unavailable: {type(exc).__name__}")
            status = "UNSUPPORTED"
    else:
        limitations.append("Only npm package.json plus package-lock v2/v3 is supported for controlled apply.")

    changed = (manifest_rel, lock_rel) if status == "PROPOSED" else ()
    identity = {
        "finding_id": finding.id,
        "vulnerability_id": finding.vulnerability_id,
        "package": component.name,
        "current_version": component.version,
        "target_version": target,
        "package_manager": package_manager,
        "manifest_path": manifest_rel,
        "lockfile_path": lock_rel,
        "input_hashes": input_hashes,
        "affected_records": records if component.ecosystem.lower() == "npm" and manifest_rel and lock_rel else [],
        "evidence_ids": list(finding.evidence_ids),
        "status": status,
    }
    proposal_id = "rp-" + hashlib.sha256(canonical_json(identity).encode()).hexdigest()[:24]
    return RemediationProposal(
        proposal_id=proposal_id, finding_id=finding.id,
        vulnerability_id=finding.vulnerability_id, package=component.name,
        current_version=component.version, target_version=target,
        target_reason=reason, package_manager=package_manager,
        manifest_path=manifest_rel, lockfile_path=lock_rel,
        files_to_change=changed, input_hashes=input_hashes,
        risk_before={"score": finding.risk_score, "level": finding.risk_level,
                     "decision": finding.risk_tier},
        expected_outcome=expected, status=status,
        limitations=tuple(limitations),
        evidence_ids=tuple(finding.evidence_ids),
        affected_records=tuple(records) if component.ecosystem.lower() == "npm" and manifest_rel and lock_rel else (),
    )


def _lock_contains_target(packages: dict[str, Any], package: str, target: str) -> bool:
    prefix = "node_modules/"
    return any(
        isinstance(key, str) and (key == f"node_modules/{package}"
                                  or key.endswith(f"/node_modules/{package}"))
        and isinstance(value, dict) and value.get("version") == target
        for key, value in packages.items()
    )


def apply_npm_proposal(root_path: str | Path, proposal: RemediationProposal,
                       *, approved: bool, finding: Finding) -> dict[str, Any]:
    """Apply a proposal only after explicit approval and fresh-input validation.

    This edits only JSON values in package.json and package-lock.json. Files are
    atomically replaced and original bytes are restored if either write fails.
    """
    if approved is not True:
        raise PermissionError("explicit approval is required")
    if proposal.status != "PROPOSED" or proposal.package_manager != "npm" or not proposal.target_version:
        raise ValueError("proposal is not applicable")
    root = Path(root_path).resolve(strict=True)
    # Rebuild the proposal from the freshly scanned finding, so a caller cannot
    # alter the target or file set while retaining a previously issued ID.
    fresh = create_proposal(root, finding)
    if fresh.proposal_id != proposal.proposal_id or fresh != proposal:
        raise RuntimeError("STALE_PROPOSAL")
    names = (proposal.manifest_path, proposal.lockfile_path)
    if any(not name or Path(name).is_absolute() or ".." in Path(name).parts for name in names):
        raise ValueError("proposal paths are invalid")
    paths = [root / str(name) for name in names]
    if any(_safe_relative(root, path) != name for path, name in zip(paths, names)):
        raise ValueError("proposal path escaped workspace or traversed a symlink")
    before = {name: path.read_bytes() for name, path in zip(names, paths)}
    if any(len(before[name]) > maximum for name, maximum in zip(names, (2_000_000, 20_000_000))):
        raise ValueError("dependency metadata exceeds the supported size bound")
    if any(_hash(before[name]) != proposal.input_hashes.get(name) for name in names):
        raise RuntimeError("STALE_PROPOSAL")
    manifest = _strict_json(before[names[0]])
    lock = _strict_json(before[names[1]])
    if not isinstance(manifest, dict) or not isinstance(lock, dict):
        raise ValueError("malformed npm metadata")
    matching = [section for section in ("dependencies", "devDependencies", "optionalDependencies")
                if isinstance(manifest.get(section), dict) and proposal.package in manifest[section]]
    if len(matching) != 1 or not isinstance(manifest[matching[0]][proposal.package], str):
        raise RuntimeError("STALE_PROPOSAL")
    old_spec = manifest[matching[0]][proposal.package]
    if not _npm_range_allows(old_spec, proposal.target_version):
        raise ValueError("target no longer satisfies declared npm constraint")
    lock_packages = lock.get("packages")
    root_entry = lock_packages.get("") if isinstance(lock_packages, dict) else None
    direct_entry = lock_packages.get(f"node_modules/{proposal.package}") if isinstance(lock_packages, dict) else None
    target_entry = next((entry for key, entry in lock_packages.items()
                         if isinstance(key, str) and key.endswith(f"/node_modules/{proposal.package}")
                         and isinstance(entry, dict) and entry.get("version") == proposal.target_version), None) if isinstance(lock_packages, dict) else None
    if not isinstance(root_entry, dict) or not isinstance(direct_entry, dict) or not isinstance(target_entry, dict):
        raise RuntimeError("STALE_PROPOSAL")
    # Reuse the exact already-resolved package metadata from the lockfile; never
    # fetch or synthesize integrity/resolution fields.
    if direct_entry is not target_entry:
        direct_entry.clear()
        direct_entry.update(target_entry)
    root_deps = root_entry.get(matching[0])
    if not isinstance(root_deps, dict) or root_deps.get(proposal.package) != old_spec:
        raise RuntimeError("STALE_PROPOSAL")
    manifest[matching[0]][proposal.package] = _updated_constraint(old_spec, proposal.target_version)
    root_deps[proposal.package] = manifest[matching[0]][proposal.package]
    after = [json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
             json.dumps(lock, ensure_ascii=False, indent=2) + "\n"]
    changed_hashes: dict[str, str] = {}
    written: list[Path] = []
    try:
        for path, name, text in zip(paths, names, after):
            data = text.encode("utf-8")
            if data == before[name]:
                continue
            # Recheck immediately before replacement to reduce the proposal/apply
            # time-of-check/time-of-use window. The operation remains local, not a
            # filesystem lock or transactional guarantee.
            if _hash(path.read_bytes()) != proposal.input_hashes[name] or path.is_symlink():
                raise RuntimeError("STALE_PROPOSAL")
            fd, temp_name = tempfile.mkstemp(prefix=".osprey-remediate-", dir=str(path.parent))
            try:
                with os.fdopen(fd, "wb") as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
                if path.is_symlink() or _hash(path.read_bytes()) != proposal.input_hashes[name]:
                    raise RuntimeError("STALE_PROPOSAL")
                os.replace(temp_name, path)
            finally:
                if os.path.exists(temp_name):
                    os.unlink(temp_name)
            written.append(path)
            changed_hashes[name] = _hash(data)
    except Exception as exc:
        rollback_ok = True
        attempted = tuple(path.relative_to(root).as_posix() for path in written)
        for path, name in zip(paths, names):
            if path in written:
                try:
                    path.write_bytes(before[name])
                    rollback_ok = rollback_ok and _hash(path.read_bytes()) == _hash(before[name])
                except OSError:
                    rollback_ok = False
        raise RemediationApplyError(
            f"apply failed ({type(exc).__name__}); rollback {'verified' if rollback_ok else 'failed'}",
            rollback_verified=rollback_ok,
            files_attempted=attempted,
            original_hashes=dict(proposal.input_hashes),
            modified_hashes=dict(changed_hashes),
        ) from exc
    return {"status": "APPLIED", "files_changed": list(changed_hashes),
            "original_hashes": dict(proposal.input_hashes),
            "modified_hashes": changed_hashes,
            "target_version": proposal.target_version,
            "limitations": ["Dependency resolution, installation, runtime state, and exploitability were not verified."]}


def _updated_constraint(old: str, target: str) -> str:
    match = re.fullmatch(r"\s*([~^]?)v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\s*", old)
    return f"{match[1]}{target}" if match else target


def verify_post_scan(proposal: RemediationProposal, scan: Any) -> dict[str, Any]:
    """Compare the supported package state and vulnerability against a fresh scan.

    This deliberately reports UNKNOWN when the post-scan lacks target state or
    the retained advisory evidence cannot classify the proposed version.
    """
    package_observations = [item for item in scan.components if item.ecosystem.lower() == "npm"
                            and item.name.lower() == proposal.package.lower()]
    components = [item for item in package_observations
                  if item.version == proposal.target_version
                  and item.source_file.replace("\\", "/").endswith("package-lock.json")]
    coverage = {
        item.observation_id: getattr(scan, "advisory_coverage", {}).get(item.observation_id, "UNAVAILABLE")
        for item in package_observations
    }
    coverage_complete = bool(coverage) and all(value == "COMPLETE" for value in coverage.values())
    matching = [item for item in scan.findings
                if item.vulnerability_id == proposal.vulnerability_id
                and item.component.name.lower() == proposal.package.lower()]
    if matching:
        state = "FAILED"
        reason = "The post-remediation scan still reports the original vulnerability for this dependency."
    elif not components:
        state = "UNKNOWN"
        reason = "The post-remediation scan did not confirm the expected locked dependency version."
    elif not coverage_complete:
        state = "UNKNOWN"
        reason = "Post-remediation dependency state was observed, but advisory coverage was insufficient to establish that the original vulnerability condition is resolved."
    else:
        records = list(proposal.affected_records)
        ranges = [item for record in records for item in record.get("ranges", []) if isinstance(item, dict)]
        exact = [value for record in records for value in record.get("versions", []) if isinstance(value, str)]
        result = evaluate_version(proposal.target_version or "", "npm", ranges=ranges, exact_versions=exact)
        if result.status == VersionMatchStatus.AFFECTED:
            state = "FAILED"
            reason = "The proposed target remains inside the retained advisory affected range."
        elif result.status == VersionMatchStatus.NOT_AFFECTED:
            state = "VERIFIED"
            reason = "The fresh scan observed the target in the npm lockfile; retained advisory ranges classify it as not affected, and no equivalent affected copy was found in the analyzed scope."
        else:
            state = "UNKNOWN"
            reason = "Post-remediation dependency state was observed, but advisory coverage was insufficient to establish that the original vulnerability condition is resolved."
    risk_after = {"score": None, "level": "UNKNOWN", "decision": "UNKNOWN"}
    if matching:
        item = matching[0]
        risk_after = {"score": item.risk_score, "level": item.risk_level, "decision": item.risk_tier}
    before_score = proposal.risk_before.get("score")
    after_score = risk_after.get("score")
    delta = (round(after_score - before_score, 1)
             if isinstance(before_score, (int, float)) and not isinstance(before_score, bool)
             and isinstance(after_score, (int, float)) and not isinstance(after_score, bool)
             else None)
    return {
        "state": state,
        "reason": reason,
        "finding_id": proposal.finding_id,
        "vulnerability_id": proposal.vulnerability_id,
        "dependency": proposal.package,
        "expected_version": proposal.target_version,
        "observed_locked_versions": sorted({item.version for item in components}),
        "post_scan_completed": True,
        "matching_findings": [item.id for item in matching],
        "advisory_coverage": coverage,
        "risk_before": proposal.risk_before,
        "risk_after": risk_after,
        "risk_delta": delta,
        "decision_before": proposal.risk_before.get("decision", "UNKNOWN"),
        "decision_after": risk_after.get("decision", "UNKNOWN"),
        "scan_source_file_count": len(scan.source_analysis.files_scanned) if scan.source_analysis else 0,
        "limitations": [*proposal.limitations,
                        "Lockfile evidence does not prove installation, runtime use, production exposure, or exploitability."],
    }
