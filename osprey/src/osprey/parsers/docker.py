"""Parser for container manifests: Dockerfile (FROM, EXPOSE) and docker-compose.yml.

Assumptions and Limitations:
- Extracts base container images as Docker components.
- Extracts EXPOSE statements and docker-compose published ports to establish service boundaries.
- Uses YAML safe loading for compose configurations.
"""

from __future__ import annotations

import re
from itertools import islice
from pathlib import Path
from typing import Any, Dict, List

import yaml

from osprey.models import Component, ExposureInfo, Service
from osprey.parsers.base import MAX_MANIFEST_COMPONENTS, make_purl, read_bounded_text

MAX_DOCKER_MANIFEST_BYTES = 2_000_000


def _within_root(root: Path, candidate: Path) -> bool:
    try:
        candidate.resolve(strict=True).relative_to(root.resolve(strict=True))
        return True
    except (OSError, ValueError):
        return False


class DockerParser:
    """Parser for Dockerfiles and docker-compose definitions."""

    name: str = "docker"

    def __init__(self) -> None:
        self.last_error: str | None = None

    def detect(self, path: Path) -> bool:
        name = path.name.lower()
        if "dockerfile" in name:
            return True
        if name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
            return True
        return False

    def parse(self, path: Path) -> List[Component]:
        """Extract container base image components."""
        self.last_error = None
        name = path.name.lower()
        if "dockerfile" in name:
            return self._parse_dockerfile_components(path)
        return self._parse_compose_components(path)

    def parse_services(self, path: Path, *, workspace_root: Path | None = None) -> List[Service]:
        """Extract Service boundaries with port configurations and exposure metadata."""
        name = path.name.lower()
        if "dockerfile" in name:
            return self._parse_dockerfile_service(path)
        return self._parse_compose_services(path, workspace_root=workspace_root)

    def _parse_dockerfile_components(self, path: Path) -> List[Component]:
        components: List[Component] = []
        try:
            lines = read_bounded_text(path, max_bytes=MAX_DOCKER_MANIFEST_BYTES).splitlines()
        except Exception:
            self.last_error = "Docker manifest could not be read"
            return []

        for line in lines:
            if len(components) >= MAX_MANIFEST_COMPONENTS:
                break
            line = line.strip()
            if line.upper().startswith("FROM "):
                parts = line.split()
                if len(parts) >= 2:
                    raw_image = parts[1].split()[0]
                    if ":" in raw_image:
                        img_name, tag = raw_image.split(":", 1)
                    else:
                        img_name, tag = raw_image, "latest"

                    # Normalize platform flags or digest references
                    if "@" in tag:
                        tag = tag.split("@")[0]

                    components.append(
                        Component(
                            name=img_name,
                            version=tag,
                            ecosystem="Docker",
                            purl=make_purl("docker", img_name, tag),
                            is_dev=False,
                            source_file=str(path),
                        )
                    )
        return components[:MAX_MANIFEST_COMPONENTS]

    def _parse_dockerfile_service(self, path: Path) -> List[Service]:
        ports: List[int] = []
        components = self._parse_dockerfile_components(path)
        copied_files: List[str] = []
        try:
            lines = read_bounded_text(path, max_bytes=MAX_DOCKER_MANIFEST_BYTES).splitlines()
            for line in lines:
                line = line.strip()
                if line.upper().startswith("EXPOSE "):
                    tokens = line.split()[1:]
                    for token in tokens:
                        p = re.sub(r"/.*$", "", token)
                        if p.isdigit():
                            ports.append(int(p))
                elif line.upper().startswith(("COPY ", "ADD ")):
                    parts = line.split()[1:]
                    if len(parts) >= 2:
                        for st in parts[:-1]:
                            c_st = st.strip("\"'").lstrip("./")
                            if c_st:
                                copied_files.append(c_st)
        except Exception:
            pass

        service_name = path.parent.name or "app"
        exposure = None
        if ports:
            exposure = ExposureInfo(
                level="unknown",
                confidence="inferred",
                evidence=f"{path.name} declares container port(s) {' '.join(str(p) for p in ports)}; external ingress is not observed",
            )

        return [
            Service(
                name=service_name,
                source_file=str(path),
                ports=ports,
                components=components,
                exposure=exposure,
                build_context=str(path.parent.resolve()),
                dockerfile_path=str(path.resolve()),
                copied_files=copied_files,
            )
        ]

    def _parse_compose_components(self, path: Path) -> List[Component]:
        components: List[Component] = []
        try:
            content = read_bounded_text(path, max_bytes=MAX_DOCKER_MANIFEST_BYTES)
            data = yaml.safe_load(content)
        except Exception:
            self.last_error = "Compose manifest could not be parsed"
            return []

        if not isinstance(data, dict):
            self.last_error = "Compose manifest has an invalid top-level shape"
            return []

        services: Dict[str, Any] = data.get("services", {}) or {}
        if not isinstance(services, dict):
            self.last_error = "Compose manifest has an invalid services section"
            return []
        for _sname, sdata in islice(services.items(), MAX_MANIFEST_COMPONENTS):
            if not isinstance(sdata, dict):
                continue
            image = sdata.get("image")
            if image and isinstance(image, str):
                if ":" in image:
                    img_name, tag = image.split(":", 1)
                else:
                    img_name, tag = image, "latest"
                components.append(
                    Component(
                        name=img_name,
                        version=tag,
                        ecosystem="Docker",
                        purl=make_purl("docker", img_name, tag),
                        is_dev=False,
                        source_file=str(path),
                    )
                )

        return components

    def _parse_compose_services(self, path: Path, *, workspace_root: Path | None = None) -> List[Service]:
        services: List[Service] = []
        try:
            content = read_bounded_text(path, max_bytes=MAX_DOCKER_MANIFEST_BYTES)
            data = yaml.safe_load(content)
        except Exception:
            self.last_error = "Compose manifest could not be parsed"
            return []

        if not isinstance(data, dict):
            self.last_error = "Compose manifest has an invalid top-level shape"
            return []

        raw_services: Dict[str, Any] = data.get("services", {}) or {}
        if not isinstance(raw_services, dict):
            self.last_error = "Compose manifest has an invalid services section"
            return []
        root = (workspace_root or path.parent).resolve(strict=True)
        for sname, sdata in islice(raw_services.items(), MAX_MANIFEST_COMPONENTS):
            if not isinstance(sdata, dict):
                continue

            ports: List[int] = []
            raw_ports = sdata.get("ports", []) or []
            for p in raw_ports:
                p_str = str(p)
                # Parse host:container or just port
                parts = p_str.split(":")
                port_num = parts[0].strip()
                if port_num.isdigit():
                    ports.append(int(port_num))

            build_val = sdata.get("build")
            build_context = None
            dockerfile_path = None
            copied_files: List[str] = []
            if isinstance(build_val, str):
                ctx_path = (path.parent / build_val).resolve()
                if _within_root(root, ctx_path):
                    build_context = str(ctx_path)
                df_cand = ctx_path / "Dockerfile"
                if build_context and _within_root(root, df_cand):
                    dockerfile_path = str(df_cand)
            elif isinstance(build_val, dict):
                ctx = build_val.get("context", ".")
                ctx_path = (path.parent / ctx).resolve()
                if _within_root(root, ctx_path):
                    build_context = str(ctx_path)
                df_name = build_val.get("dockerfile", "Dockerfile")
                df_cand = ctx_path / df_name
                if build_context and _within_root(root, df_cand):
                    dockerfile_path = str(df_cand)

            if dockerfile_path and _within_root(root, Path(dockerfile_path)):
                try:
                    df_lines = read_bounded_text(
                        Path(dockerfile_path), max_bytes=MAX_DOCKER_MANIFEST_BYTES
                    ).splitlines()
                    for line in df_lines:
                        line = line.strip()
                        if line.upper().startswith(("COPY ", "ADD ")):
                            parts = line.split()[1:]
                            if len(parts) >= 2:
                                for st in parts[:-1]:
                                    c_st = st.strip("\"'").lstrip("./")
                                    if c_st:
                                        copied_files.append(c_st)
                        elif not ports and line.upper().startswith("EXPOSE "):
                            tokens = line.split()[1:]
                            for token in tokens:
                                p = re.sub(r"/.*$", "", token)
                                if p.isdigit():
                                    ports.append(int(p))
                except Exception:
                    pass

            has_ports = len(ports) > 0
            if has_ports:
                exposure = ExposureInfo(
                    level="unknown",
                    confidence="inferred",
                    evidence=f"{path.name} service '{sname}' declares/publishes host port(s) {ports}; public routing is not observed",
                )
            else:
                exposure = ExposureInfo(
                    level="unknown",
                    confidence="inferred",
                    evidence=f"{path.name} service '{sname}' has no declared port mapping; ingress through other infrastructure is not observed",
                )

            services.append(
                Service(
                    name=sname,
                    source_file=str(path),
                    ports=ports,
                    exposure=exposure,
                    build_context=build_context,
                    dockerfile_path=dockerfile_path,
                    copied_files=copied_files,
                )
            )

        return services
