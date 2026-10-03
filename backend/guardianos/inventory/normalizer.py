"""Component normalizer and canonical ecosystem identity resolver."""

import re
from typing import Optional, Tuple
from guardianos.inventory.models import Ecosystem


ECOSYSTEM_MAP = {
    "pypi": Ecosystem.PYPI,
    "python": Ecosystem.PYPI,
    "pip": Ecosystem.PYPI,
    "npm": Ecosystem.NPM,
    "node": Ecosystem.NPM,
    "javascript": Ecosystem.NPM,
    "deb": Ecosystem.DEBIAN,
    "debian": Ecosystem.DEBIAN,
    "dpkg": Ecosystem.DEBIAN,
    "rpm": Ecosystem.RPM,
    "redhat": Ecosystem.RPM,
    "fedora": Ecosystem.RPM,
    "golang": Ecosystem.GO,
    "go": Ecosystem.GO,
    "maven": Ecosystem.MAVEN,
    "java": Ecosystem.MAVEN,
    "docker": Ecosystem.DOCKER,
    "oci": Ecosystem.DOCKER,
    "container": Ecosystem.DOCKER,
    "cargo": Ecosystem.CARGO,
    "rust": Ecosystem.CARGO,
}


def normalize_ecosystem(raw_name: Optional[str]) -> Ecosystem:
    """Normalize any raw ecosystem or package type string to canonical Ecosystem."""
    if not raw_name:
        return Ecosystem.GENERIC
    cleaned = raw_name.strip().lower()
    return ECOSYSTEM_MAP.get(cleaned, Ecosystem.GENERIC)


def build_canonical_purl(
    ecosystem: Ecosystem,
    name: str,
    version: str,
    namespace: Optional[str] = None
) -> str:
    """Construct a standard canonical Package URL (PURL)."""
    clean_name = name.strip()
    clean_version = version.strip() if version else "unknown"
    
    # Specific normalization rules per ecosystem
    if ecosystem == Ecosystem.PYPI:
        clean_name = re.sub(r"[-_.]+", "-", clean_name).lower()
        type_str = "pypi"
    elif ecosystem == Ecosystem.NPM:
        type_str = "npm"
        if namespace:
            clean_name = f"@{namespace.strip('@')}/{clean_name}"
    elif ecosystem == Ecosystem.DEBIAN:
        type_str = "deb"
        namespace = namespace or "debian"
    elif ecosystem == Ecosystem.RPM:
        type_str = "rpm"
    elif ecosystem == Ecosystem.GO:
        type_str = "golang"
    elif ecosystem == Ecosystem.MAVEN:
        type_str = "maven"
    elif ecosystem == Ecosystem.DOCKER:
        type_str = "docker"
    elif ecosystem == Ecosystem.CARGO:
        type_str = "cargo"
    else:
        type_str = "generic"

    if namespace and ecosystem != Ecosystem.NPM:
        return f"pkg:{type_str}/{namespace}/{clean_name}@{clean_version}"
    return f"pkg:{type_str}/{clean_name}@{clean_version}"


def parse_purl(purl: str) -> Tuple[Ecosystem, str, str, Optional[str]]:
    """Parse a PURL string into (Ecosystem, name, version, namespace)."""
    if not purl.startswith("pkg:"):
        # Not a valid purl, treat as generic identifier
        return Ecosystem.GENERIC, purl, "unknown", None
    
    without_prefix = purl[4:]  # remove 'pkg:'
    parts = without_prefix.split("/", 1)
    type_str = parts[0]
    rest = parts[1] if len(parts) > 1 else ""
    
    version = "unknown"
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
        
    namespace = None
    if "/" in rest:
        namespace, name = rest.rsplit("/", 1)
    else:
        name = rest

    ecosystem = normalize_ecosystem(type_str)
    return ecosystem, name, version, namespace
