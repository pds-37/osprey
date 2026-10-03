"""Universal SBOM auto-detection and parsing dispatcher."""

import json
from typing import Any, Dict, Union
from guardianos.inventory.cyclonedx import parse_cyclonedx
from guardianos.inventory.spdx import parse_spdx
from guardianos.inventory.syft import parse_syft
from guardianos.inventory.models import DependencyState, IngestionResult, SBOMFormat


def detect_sbom_format(data: Dict[str, Any]) -> SBOMFormat:
    """Intelligently detect format from raw JSON keys."""
    if "bomFormat" in data and data["bomFormat"] == "CycloneDX":
        return SBOMFormat.CYCLONEDX
    if "spdxVersion" in data:
        return SBOMFormat.SPDX
    if "artifacts" in data and ("schema" in data or "source" in data):
        return SBOMFormat.SYFT
    # Fallbacks by nested structures
    if "components" in data and "specVersion" in data:
        return SBOMFormat.CYCLONEDX
    if "packages" in data and "relationships" in data:
        return SBOMFormat.SPDX
    return SBOMFormat.UNKNOWN


def parse_sbom(
    raw_content: Union[str, bytes, Dict[str, Any]],
    application: str = "default-app",
    environment: str = "production",
    default_state: DependencyState = DependencyState.INSTALLED
) -> IngestionResult:
    """Parse any supported SBOM JSON into normalized IngestionResult."""
    if isinstance(raw_content, (str, bytes)):
        data = json.loads(raw_content)
    else:
        data = raw_content

    detected_format = detect_sbom_format(data)
    
    if detected_format == SBOMFormat.CYCLONEDX:
        return parse_cyclonedx(data, application=application, environment=environment, default_state=default_state)
    elif detected_format == SBOMFormat.SPDX:
        return parse_spdx(data, application=application, environment=environment, default_state=default_state)
    elif detected_format == SBOMFormat.SYFT:
        return parse_syft(data, application=application, environment=environment, default_state=default_state)
    else:
        raise ValueError("Unsupported or unrecognized SBOM format. Must be CycloneDX, SPDX, or Syft JSON.")
