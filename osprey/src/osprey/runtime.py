"""Bounded installation inspection and explicit Python runtime instrumentation.

Workspace scanning never imports or executes target code. The instrumentation API
only observes modules already imported by its caller and wraps a function when the
caller explicitly opts in; it never launches an application or invokes that function.
"""

from __future__ import annotations

import importlib.metadata as importlib_metadata
import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, TypeVar

from osprey import __version__
from osprey.core.evidence import EvidenceStore, canonical_json, verify_record
from osprey.core.models import Evidence, EvidenceType, RuntimeObservationState


MAX_NODE_PACKAGE_JSON_BYTES = 262_144
MAX_PYTHON_METADATA_BYTES = 65_536
MAX_VENV_METADATA_ENTRIES = 10_000
_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
_MODULE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){0,15}$")
_SYMBOL_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_SAFE_CONTEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_SAFE_FINDING_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}$")
_SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]{0,127}$")
T = TypeVar("T", bound=Callable[..., Any])


def _canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def runtime_evidence_freshness(
    timestamp: str,
    *,
    now: datetime | None = None,
    max_age: timedelta = timedelta(hours=24),
) -> str:
    """Classify a runtime event timestamp without treating stale data as current."""
    if not isinstance(timestamp, str):
        return "INVALID"
    try:
        observed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        if observed.tzinfo is None:
            return "INVALID"
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None:
            return "INVALID"
        observed = observed.astimezone(timezone.utc)
        current = current.astimezone(timezone.utc)
        if observed > current + timedelta(minutes=5):
            return "FUTURE"
        if observed < current - max_age:
            return "STALE"
        return "CURRENT"
    except (TypeError, ValueError, OverflowError):
        return "INVALID"


def _valid_text(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"{label} is malformed")
    return value


@dataclass(frozen=True)
class InstallationObservation:
    package_name: str
    ecosystem: str
    version: str
    source: str
    location: str

    def as_dict(self) -> dict[str, str]:
        return {
            "package_name": self.package_name,
            "ecosystem": self.ecosystem,
            "version": self.version,
            "source": self.source,
            "location": self.location,
        }


class InstallationInspector:
    """Inspect known package metadata locations without importing packages."""

    def __init__(self, workspace: str | Path) -> None:
        self.workspace = Path(workspace).resolve(strict=True)
        self._node_cache: dict[tuple[str, str], InstallationObservation | None] = {}
        self._python_index: dict[str, InstallationObservation] | None = None

    def inspect(
        self,
        package_name: str,
        ecosystem: str,
        *,
        manifest_directory: str | Path | None = None,
    ) -> InstallationObservation | None:
        ecosystem_value = ecosystem.strip().lower()
        if ecosystem_value in {"npm", "node", "javascript", "typescript"}:
            return self._inspect_node(package_name, manifest_directory)
        if ecosystem_value in {"pypi", "python"}:
            index = self._get_python_index()
            return index.get(_canonical_name(package_name))
        return None

    def _ancestor_directories(self, start: str | Path | None) -> list[Path]:
        base = Path(start) if start is not None else self.workspace
        if not base.is_absolute():
            base = self.workspace / base
        try:
            base = base.resolve(strict=True)
            base.relative_to(self.workspace)
        except (OSError, ValueError):
            base = self.workspace
        if base.is_file():
            base = base.parent
        values: list[Path] = []
        for _ in range(9):
            values.append(base)
            if base == self.workspace or self.workspace not in base.parents:
                break
            base = base.parent
        return values

    def _inspect_node(
        self,
        package_name: str,
        manifest_directory: str | Path | None,
    ) -> InstallationObservation | None:
        if not isinstance(package_name, str) or len(package_name) > 220 or "\\" in package_name:
            return None
        parts = package_name.split("/")
        if package_name.startswith("@"):
            valid = len(parts) == 2 and bool(re.fullmatch(r"@[A-Za-z0-9._-]{1,100}", parts[0])) and bool(_PACKAGE_NAME.fullmatch(parts[1]))
        else:
            valid = len(parts) == 1 and bool(_PACKAGE_NAME.fullmatch(package_name))
        if not valid:
            return None
        cache_key = (package_name, str(manifest_directory or ""))
        if cache_key in self._node_cache:
            return self._node_cache[cache_key]

        for base in self._ancestor_directories(manifest_directory):
            package_json = base / "node_modules" / Path(*parts) / "package.json"
            try:
                if package_json.is_symlink() or any(part.is_symlink() for part in package_json.parents if part != self.workspace.parent):
                    continue
                resolved = package_json.resolve(strict=True)
                relative = resolved.relative_to(self.workspace).as_posix()
                if resolved.stat().st_size > MAX_NODE_PACKAGE_JSON_BYTES:
                    continue
                data = json.loads(resolved.read_text(encoding="utf-8"))
                observed_name = data.get("name") if isinstance(data, dict) else None
                version = data.get("version") if isinstance(data, dict) else None
                if (
                    isinstance(observed_name, str)
                    and observed_name == package_name
                    and isinstance(version, str)
                    and _SAFE_VERSION.fullmatch(version)
                ):
                    observation = InstallationObservation(
                        package_name=package_name,
                        ecosystem="npm",
                        version=version,
                        source="node_modules package.json",
                        location=relative,
                    )
                    self._node_cache[cache_key] = observation
                    return observation
            except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
                continue
        self._node_cache[cache_key] = None
        return None

    def _get_python_index(self) -> dict[str, InstallationObservation]:
        if self._python_index is not None:
            return self._python_index
        index: dict[str, InstallationObservation] = {}
        roots: set[Path] = set()
        for base in self._ancestor_directories(None):
            for venv_name in (".venv", "venv", "env"):
                root = base / venv_name
                if root.is_dir() and not root.is_symlink():
                    roots.add(root)
            # PEP 582 environments are explicit project-local package stores.
            py_packages = base / "__pypackages__"
            if py_packages.is_dir() and not py_packages.is_symlink():
                try:
                    for version_dir in sorted(py_packages.iterdir())[:32]:
                        candidate = version_dir / "lib"
                        if candidate.is_dir() and not candidate.is_symlink():
                            roots.add(candidate)
                except OSError:
                    pass

        metadata_paths: list[tuple[Path, str]] = []
        for root in sorted(roots, key=lambda path: str(path).casefold()):
            candidates = [root / "Lib" / "site-packages"]
            for lib_name in ("lib", "lib64"):
                lib = root / lib_name
                if lib.is_dir() and not lib.is_symlink():
                    try:
                        candidates.extend(path / "site-packages" for path in sorted(lib.glob("python*/"))[:32])
                    except OSError:
                        pass
            if root.name == "lib":  # PEP 582 __pypackages__/<version>/lib
                try:
                    candidates.extend(path for path in root.iterdir() if path.name.endswith(".dist-info"))
                except OSError:
                    pass
            for site_packages in candidates:
                if not site_packages.is_dir() or site_packages.is_symlink():
                    continue
                try:
                    for entry in sorted(site_packages.iterdir(), key=lambda path: path.name.casefold()):
                        if len(metadata_paths) >= MAX_VENV_METADATA_ENTRIES:
                            break
                        if entry.name.endswith(".dist-info") and entry.is_dir() and not entry.is_symlink():
                            metadata_paths.append((entry / "METADATA", str(root)))
                except OSError:
                    continue
        for metadata_path, root_text in metadata_paths:
            try:
                if metadata_path.is_symlink() or metadata_path.stat().st_size > MAX_PYTHON_METADATA_BYTES:
                    continue
                lines = metadata_path.read_text(encoding="utf-8", errors="replace").splitlines()
                name = next((line[5:].strip() for line in lines if line.lower().startswith("name: ")), None)
                version = next((line[9:].strip() for line in lines if line.lower().startswith("version: ")), None)
                if not name or not version or not _PACKAGE_NAME.fullmatch(name) or not _SAFE_VERSION.fullmatch(version):
                    continue
                relative = metadata_path.resolve(strict=True).relative_to(self.workspace).as_posix()
                index.setdefault(_canonical_name(name), InstallationObservation(
                    package_name=name,
                    ecosystem="pypi",
                    version=version,
                    source="project virtual-environment METADATA",
                    location=relative,
                ))
            except (OSError, ValueError):
                continue
        self._python_index = index
        return index


@dataclass(frozen=True)
class RuntimeStateSnapshot:
    states: dict[str, str]
    evidence_ids: tuple[str, ...]
    limitations: tuple[str, ...]
    loaded_current: bool


def summarize_runtime_state(
    store: EvidenceStore,
    *,
    package_name: str,
    ecosystem: str,
    version: str,
    declared_observed: bool = False,
    locked_observed: bool = False,
    installed_observed: bool = False,
    finding_id: str | None = None,
    now: datetime | None = None,
) -> RuntimeStateSnapshot:
    """Project validated, fresh process-local evidence onto one package finding."""
    statuses = {
        "DECLARED": "OBSERVED" if declared_observed else "UNKNOWN",
        "LOCKED": "OBSERVED" if locked_observed else "UNKNOWN",
        "INSTALLED": "OBSERVED" if installed_observed else "UNKNOWN",
        "LOADED": "UNKNOWN",
        "EXERCISED": "UNKNOWN",
    }
    matching: list[tuple[Evidence, dict[str, Any], str]] = []
    ids: list[str] = []
    limitations: list[str] = []
    wanted_package = _canonical_name(package_name)
    wanted_ecosystem = ecosystem.strip().lower()
    for record in store.list():
        if record.type != EvidenceType.RUNTIME_OBSERVATION:
            continue
        observed = record.metadata.get("observed") if isinstance(record.metadata, dict) else None
        if not isinstance(observed, dict):
            continue
        if (
            _canonical_name(str(observed.get("package_name", ""))) != wanted_package
            or str(observed.get("ecosystem", "")).lower() != wanted_ecosystem
            or observed.get("version") != version
            or (observed.get("finding_id") and observed.get("finding_id") != finding_id)
        ):
            continue
        if verify_record(record) is not True:
            limitations.append("Malformed or tampered runtime evidence was ignored.")
            continue
        state = observed.get("state")
        if state not in {RuntimeObservationState.LOADED.value, RuntimeObservationState.EXERCISED.value}:
            limitations.append("Runtime evidence with an unsupported state was ignored.")
            continue
        expected_collector = (
            "explicit_python_module_probe" if state == RuntimeObservationState.LOADED.value
            else "explicit_python_callable_probe"
        )
        if (
            record.metadata.get("collector") != expected_collector
            or observed.get("deterministic") is not True
            or isinstance(observed.get("process_id"), bool)
            or not isinstance(observed.get("process_id"), int)
            or observed.get("process_id", 0) < 1
            or not isinstance(observed.get("module_name"), str)
            or not _MODULE_NAME.fullmatch(observed.get("module_name", ""))
            or not isinstance(observed.get("environment"), str)
            or not _SAFE_CONTEXT.fullmatch(observed.get("environment", ""))
            or not isinstance(observed.get("version"), str)
            or not _SAFE_VERSION.fullmatch(observed.get("version", ""))
        ):
            limitations.append("Malformed runtime evidence was ignored.")
            continue
        freshness = runtime_evidence_freshness(record.timestamp, now=now)
        ids.append(record.id)
        matching.append((record, observed, freshness))
        if freshness != "CURRENT":
            limitations.append(f"Runtime evidence is {freshness.lower()}; current LOADED/EXERCISED state remains UNKNOWN.")

    current_loaded_ids: set[str] = set()
    loaded_current = False
    for record, observed, freshness in matching:
        if observed.get("state") == RuntimeObservationState.LOADED.value and freshness == "CURRENT":
            statuses["LOADED"] = "OBSERVED"
            loaded_current = True
            current_loaded_ids.add(record.id)
    for _record, observed, freshness in matching:
        if observed.get("state") != RuntimeObservationState.EXERCISED.value or freshness != "CURRENT":
            continue
        basis = observed.get("basis_evidence_ids")
        if isinstance(basis, list) and any(item in current_loaded_ids for item in basis):
            statuses["EXERCISED"] = "OBSERVED"
        else:
            limitations.append("EXERCISED evidence lacked a matching current LOADED evidence record.")
    if statuses["LOADED"] == "UNKNOWN":
        limitations.append("No current LOADED observation; runtime state is UNKNOWN, not NOT_PRESENT.")
    if statuses["EXERCISED"] == "UNKNOWN":
        limitations.append("No current EXERCISED observation; execution state is UNKNOWN, not NOT_EXERCISED.")
    return RuntimeStateSnapshot(
        states=statuses,
        evidence_ids=tuple(dict.fromkeys(ids)),
        limitations=tuple(dict.fromkeys(limitations)),
        loaded_current=loaded_current,
    )


@dataclass(frozen=True)
class _LoadedModule:
    module: ModuleType
    package_name: str
    version: str
    environment: str
    finding_id: str | None
    evidence: Evidence


class RuntimeInstrumentation:
    """Opt-in process-local Python module and callable observation helper."""

    def __init__(self, store: EvidenceStore, *, environment: str = "local") -> None:
        self.store = store
        self.environment = _valid_text(environment, _SAFE_CONTEXT, "runtime environment label")
        self._loaded: dict[str, _LoadedModule] = {}

    def observe_loaded_module(
        self,
        module_name: str,
        distribution_name: str,
        *,
        finding_id: str | None = None,
    ) -> Evidence:
        module_name = _valid_text(module_name, _MODULE_NAME, "module name")
        distribution_name = _valid_text(distribution_name, _PACKAGE_NAME, "distribution name")
        if finding_id is not None:
            finding_id = _valid_text(finding_id, _SAFE_FINDING_ID, "finding ID")
        module = sys.modules.get(module_name)
        if not isinstance(module, ModuleType) or module.__name__ != module_name:
            raise ValueError("module is not present in this process")
        origin = getattr(module, "__file__", None)
        if not isinstance(origin, str):
            raise ValueError("module origin is unavailable")
        try:
            module_path = Path(origin).resolve(strict=True)
            distributions = importlib_metadata.packages_distributions()
            top_level = module_name.split(".", 1)[0]
            mapped = distributions.get(top_level, [])
            matching = next((name for name in mapped if _canonical_name(name) == _canonical_name(distribution_name)), None)
            if matching is None:
                raise ValueError("module is not mapped to the requested installed distribution")
            dist = importlib_metadata.distribution(matching)
            if _canonical_name(dist.metadata.get("Name", "")) != _canonical_name(distribution_name):
                raise ValueError("installed distribution identity does not match")
            if not isinstance(dist.version, str) or not _SAFE_VERSION.fullmatch(dist.version):
                raise ValueError("installed distribution version is malformed")
            files = dist.files
            if files is None or len(files) > MAX_VENV_METADATA_ENTRIES:
                raise ValueError("installed distribution file list is unavailable or exceeds the safety bound")
            installed_files = {Path(dist.locate_file(item)).resolve() for item in files}
            if module_path not in installed_files:
                raise ValueError("module origin is not listed in installed distribution metadata")
        except (OSError, importlib_metadata.PackageNotFoundError) as exc:
            raise ValueError("installed package metadata could not validate the loaded module") from exc

        payload = {
            "state": RuntimeObservationState.LOADED.value,
            "package_name": dist.metadata.get("Name", distribution_name),
            "ecosystem": "pypi",
            "version": dist.version,
            "module_name": module_name,
            "process_id": os.getpid(),
            "runtime": f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "environment": self.environment,
            "deterministic": True,
            "finding_id": finding_id,
            "limitations": [
                "Observed in this instrumented process and environment only.",
                "This does not establish production deployment, exploitability, or Internet exposure.",
            ],
        }
        evidence = self.store.add(
            evidence_type=EvidenceType.RUNTIME_OBSERVATION,
            source="Osprey Python runtime instrumentation",
            location=f"process:{os.getpid()}/module:{module_name}",
            content=canonical_json(payload),
            confidence=1.0,
            metadata={
                "analyzer": "Osprey",
                "analyzer_version": __version__,
                "collector": "explicit_python_module_probe",
                "observed": payload,
            },
        )
        self._loaded[module_name] = _LoadedModule(
            module=module,
            package_name=payload["package_name"],
            version=dist.version,
            environment=self.environment,
            finding_id=finding_id,
            evidence=evidence,
        )
        return evidence

    def instrument_symbol(self, module_name: str, symbol: str) -> Callable[..., Any]:
        module_name = _valid_text(module_name, _MODULE_NAME, "module name")
        symbol = _valid_text(symbol, _SYMBOL_NAME, "symbol name")
        observed = self._loaded.get(module_name)
        if observed is None or sys.modules.get(module_name) is not observed.module:
            raise ValueError("module must be observed as loaded before symbol instrumentation")
        function = observed.module.__dict__.get(symbol)
        if not callable(function) or getattr(function, "__module__", None) != module_name:
            raise ValueError("symbol is not a callable defined by the observed module")

        @wraps(function)
        def wrapped(*args: Any, **kwargs: Any) -> Any:
            result = function(*args, **kwargs)
            payload = {
                "state": RuntimeObservationState.EXERCISED.value,
                "package_name": observed.package_name,
                "ecosystem": "pypi",
                "version": observed.version,
                "module_name": module_name,
                "symbol": symbol,
                "process_id": os.getpid(),
                "runtime": f"Python {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                "environment": observed.environment,
                "deterministic": True,
                "finding_id": observed.finding_id,
                "basis_evidence_ids": [observed.evidence.id],
                "limitations": [
                    "The explicitly wrapped callable returned in this instrumented process.",
                    "Arguments and return values are not captured.",
                    "This does not establish exploitability, production deployment, or Internet exposure.",
                ],
            }
            self.store.add(
                evidence_type=EvidenceType.RUNTIME_OBSERVATION,
                source="Osprey Python runtime instrumentation",
                location=f"process:{os.getpid()}/symbol:{module_name}.{symbol}",
                content=canonical_json(payload),
                confidence=1.0,
                metadata={
                    "analyzer": "Osprey",
                    "analyzer_version": __version__,
                    "collector": "explicit_python_callable_probe",
                    "observed": payload,
                },
            )
            return result

        return wrapped
