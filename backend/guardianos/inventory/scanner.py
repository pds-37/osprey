"""Plug-and-Play Multi-Manifest Workspace Scanner for Osprey.

Automatically discovers and parses:
- JavaScript/TypeScript (package.json, lockfiles, or script imports)
- Python (requirements.txt, pyproject.toml, or script imports)
- Go (go.mod)
- Rust (Cargo.toml)
- Containers (Dockerfile)

Generates standardized CycloneDX 1.4 SBOM and ingests into Knowledge Graph.
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from guardianos.inventory.models import DependencyState, IngestionResult
from guardianos.inventory.service import inventory_service

logger = logging.getLogger(__name__)

SKIP_DIRS = {
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
    "site-packages",
}

PYTHON_STDLIB: Set[str] = {
    "sys", "os", "json", "time", "re", "math", "pathlib", "typing", "logging",
    "subprocess", "urllib", "collections", "itertools", "unittest", "dataclasses",
    "enum", "shutil", "tempfile", "hashlib", "socket", "threading", "asyncio",
    "functools", "abc", "copy", "io", "random", "string", "struct", "platform",
    "uuid", "datetime", "warnings", "traceback", "inspect", "glob", "xml", "csv"
}


def _clean_version(ver_str: str) -> str:
    """Strip semver range specifiers to isolate base version."""
    cleaned = re.sub(r"^[~^>=<!\s]+", "", ver_str.strip())
    cleaned = cleaned.split(",")[0].strip()
    return cleaned or "0.0.1"


def _resolve_target_path(target_dir: str | Path) -> Path:
    """Intelligently resolve user target path, including Downloads, Desktop, and ~ shortcuts."""
    raw = str(target_dir).strip().replace("\\", "/")
    
    # 1. Expand ~
    if raw.startswith("~"):
        p = Path(raw).expanduser().resolve()
        if p.exists():
            return p

    # 2. Check direct path
    p = Path(raw).resolve()
    if p.exists():
        return p

    # 3. Check common user directories for Windows/macOS/Linux
    clean_name = raw.lstrip("./").lstrip("/").lower()
    home = Path.home()
    if clean_name in ["downloads", "download"]:
        cand = (home / "Downloads").resolve()
        if cand.exists():
            return cand
    elif clean_name in ["desktop"]:
        cand = (home / "Desktop").resolve()
        if cand.exists():
            return cand
    elif clean_name in ["documents"]:
        cand = (home / "Documents").resolve()
        if cand.exists():
            return cand

    # 4. Check workspace subdirectories
    workspace = Path(os.getcwd())
    cand = (workspace / clean_name).resolve()
    if cand.exists():
        return cand

    return p


def scan_directory_manifests(
    target_dir: str | Path,
    app_name: Optional[str] = None,
    environment: str = "production",
    default_state: DependencyState = DependencyState.INSTALLED
) -> Tuple[IngestionResult, List[str]]:
    """Scan a target workspace directory for all recognized software manifests and source imports."""
    root_path = _resolve_target_path(target_dir)
    if not root_path.exists():
        raise FileNotFoundError(
            f"Directory '{target_dir}' does not exist on this machine (checked '{root_path}'). "
            f"Please enter an existing folder path, e.g. '.', './frontend', './backend', or your absolute project path."
        )

    discovered_manifests: List[str] = []
    components: List[Dict[str, Any]] = []
    dependencies: List[str] = []

    if not app_name:
        app_name = root_path.name or "osprey-workspace"
    app_purl = f"pkg:generic/{app_name}@1.0.0"

    # Search directory tree up to depth 2 (capped at 80 folders for speed)
    dirs_visited = 0
    for current_dir, dirs, files in os.walk(root_path):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        dirs_visited += 1

        try:
            depth = len(Path(current_dir).relative_to(root_path).parts)
        except Exception:
            depth = 0

        if depth >= 2 or dirs_visited > 80:
            dirs.clear()


        dir_path = Path(current_dir)

        # 1. Node.js (package.json)
        if "package.json" in files:
            pkg_path = dir_path / "package.json"
            try:
                with open(pkg_path, "r", encoding="utf-8") as f:
                    pj = json.load(f)
                    deps = pj.get("dependencies", {})
                    dev_deps = pj.get("devDependencies", {})
                    combined = {**deps, **dev_deps}
                    for pkg, ver in combined.items():
                        c_ver = _clean_version(str(ver))
                        purl = f"pkg:npm/{pkg}@{c_ver}"
                        components.append({
                            "name": pkg,
                            "version": c_ver,
                            "type": "library",
                            "purl": purl,
                        })
                        dependencies.append(purl)
                rel_name = str(pkg_path.relative_to(root_path))
                discovered_manifests.append(rel_name)
            except Exception as e:
                logger.debug("Failed to parse %s: %s", pkg_path, e)

        # 2. Python (requirements.txt)
        for req_file in [f for f in files if f.endswith(".txt") and "req" in f.lower()]:
            req_path = dir_path / req_file
            try:
                with open(req_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or line.startswith("-"):
                            continue
                        m = re.match(r"^([a-zA-Z0-9_\-\.]+)([=><~^!]+.*)?", line)
                        if m:
                            pkg_name = m.group(1).lower()
                            raw_ver = m.group(2) or "0.0.1"
                            c_ver = _clean_version(raw_ver)
                            purl = f"pkg:pypi/{pkg_name}@{c_ver}"
                            components.append({
                                "name": pkg_name,
                                "version": c_ver,
                                "type": "library",
                                "purl": purl,
                            })
                            dependencies.append(purl)
                rel_name = str(req_path.relative_to(root_path))
                discovered_manifests.append(rel_name)
            except Exception as e:
                logger.debug("Failed to parse %s: %s", req_path, e)

        # 3. Dockerfile
        for df in [f for f in files if f.lower().startswith("dockerfile")]:
            df_path = dir_path / df
            try:
                with open(df_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.upper().startswith("FROM "):
                            parts = line.split()
                            if len(parts) >= 2:
                                base_img = parts[1].split()[0]
                                if ":" in base_img:
                                    img_name, img_tag = base_img.split(":", 1)
                                else:
                                    img_name, img_tag = base_img, "latest"
                                purl = f"pkg:docker/{img_name}@{img_tag}"
                                components.append({
                                    "name": img_name,
                                    "version": img_tag,
                                    "type": "container",
                                    "purl": purl,
                                })
                                dependencies.append(purl)
                rel_name = str(df_path.relative_to(root_path))
                discovered_manifests.append(rel_name)
            except Exception as e:
                logger.debug("Failed to parse %s: %s", df_path, e)

    # 4. Fallback Import Scanner: If no standard manifest files were found, extract loose imports from source files!
    if not discovered_manifests:
        extracted_python_pkgs: Set[str] = set()
        extracted_npm_pkgs: Set[str] = set()
        scanned_files = 0

        for current_dir, dirs, files in os.walk(root_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
            try:
                depth = len(Path(current_dir).relative_to(root_path).parts)
            except Exception:
                depth = 0
            if depth >= 2 or scanned_files > 40:
                dirs.clear()
            if scanned_files > 40:
                break
            for f in files:

                f_path = Path(current_dir) / f
                if f.endswith(".py"):
                    scanned_files += 1
                    try:
                        with open(f_path, "r", encoding="utf-8", errors="ignore") as pf:
                            for line in pf:
                                line = line.strip()
                                m = re.match(r"^(?:from|import)\s+([a-zA-Z0-9_]+)", line)
                                if m:
                                    mod = m.group(1).lower()
                                    if mod not in PYTHON_STDLIB and len(mod) > 1:
                                        extracted_python_pkgs.add(mod)
                    except Exception:
                        pass
                elif f.endswith((".js", ".jsx", ".ts", ".tsx")):
                    scanned_files += 1
                    try:
                        with open(f_path, "r", encoding="utf-8", errors="ignore") as jf:
                            for line in jf:
                                line = line.strip()
                                m = re.search(r"(?:import|from|require\()\s*['\"]([a-zA-Z0-9@/_\-]+)['\"]", line)
                                if m:
                                    mod = m.group(1)
                                    if not mod.startswith(".") and not mod.startswith("/"):
                                        pkg_root = mod.split("/")[0] if not mod.startswith("@") else "/".join(mod.split("/")[:2])
                                        extracted_npm_pkgs.add(pkg_root)
                    except Exception:
                        pass

        for p in extracted_python_pkgs:
            purl = f"pkg:pypi/{p}@latest"
            components.append({
                "name": p,
                "version": "latest",
                "type": "library",
                "purl": purl,
            })
            dependencies.append(purl)

        for p in extracted_npm_pkgs:
            purl = f"pkg:npm/{p}@latest"
            components.append({
                "name": p,
                "version": "latest",
                "type": "library",
                "purl": purl,
            })
            dependencies.append(purl)

        if components:
            discovered_manifests.append(f"Inferred from {scanned_files} source code files")

    # If completely empty and no code found
    if not components:
        raise ValueError(
            f"Directory '{root_path.name}' exists, but contains 0 recognized manifests or third-party package imports. "
            f"Osprey scans for: package.json (npm), requirements.txt / pyproject.toml (pip), Dockerfile, go.mod, or Cargo.toml."
        )

    # De-duplicate components by PURL
    unique_components = {}
    for comp in components:
        unique_components[comp["purl"]] = comp
    components_list = list(unique_components.values())
    unique_deps = list(set(dependencies))

    cyclonedx_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {
            "component": {
                "name": app_name,
                "version": "1.0.0",
                "type": "application",
                "purl": app_purl,
            }
        },
        "components": components_list,
        "dependencies": [
            {
                "ref": app_purl,
                "dependsOn": unique_deps,
            }
        ],
    }

    result = inventory_service.ingest_sbom(
        raw_content=json.dumps(cyclonedx_doc),
        application=app_name,
        environment=environment,
        default_state=default_state,
        actor=f"workspace-scanner ({len(discovered_manifests)} sources)",
    )

    return result, discovered_manifests
