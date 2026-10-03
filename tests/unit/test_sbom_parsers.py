"""Unit tests for SBOM multi-format parsers (CycloneDX, SPDX, Syft)."""

from guardianos.inventory.models import DependencyState, Ecosystem, SBOMFormat
from guardianos.inventory.parser import detect_sbom_format, parse_sbom


def test_cyclonedx_parser(sample_cyclonedx_json):
    result = parse_sbom(
        raw_content=sample_cyclonedx_json,
        application="media-service",
        environment="production",
        default_state=DependencyState.RUNNING
    )
    assert result.format == SBOMFormat.CYCLONEDX
    assert result.components_count == 4  # 1 root app + 3 libraries
    assert result.relationships_count == 3
    assert result.environment == "production"

    # Check root application
    app_comp = next((c for c in result.components if c.name == "image-processing-service"), None)
    assert app_comp is not None
    assert app_comp.state == DependencyState.RUNNING

    # Check dependencies
    fastapi_comp = next((c for c in result.components if c.name == "fastapi"), None)
    assert fastapi_comp is not None
    assert fastapi_comp.ecosystem == Ecosystem.PYPI
    assert fastapi_comp.version == "0.110.0"


def test_spdx_parser(sample_spdx_json):
    result = parse_sbom(
        raw_content=sample_spdx_json,
        application="discourse",
        environment="production",
        default_state=DependencyState.INSTALLED
    )
    assert result.format == SBOMFormat.SPDX
    assert result.components_count == 2
    assert result.relationships_count == 1

    libheif_comp = next((c for c in result.components if c.name == "libheif"), None)
    assert libheif_comp is not None
    assert libheif_comp.ecosystem == Ecosystem.DEBIAN
    assert libheif_comp.version == "1.19.7"
    assert libheif_comp.purl == "pkg:deb/debian/libheif@1.19.7"


def test_syft_parser(sample_syft_json):
    result = parse_sbom(
        raw_content=sample_syft_json,
        application="media-processor",
        environment="production",
        default_state=DependencyState.INSTALLED
    )
    assert result.format == SBOMFormat.SYFT
    # Root container image + 2 debian packages
    assert result.components_count == 3
    
    container_comp = next((c for c in result.components if c.ecosystem == Ecosystem.DOCKER), None)
    assert container_comp is not None
    assert container_comp.name == "prod-media-processor:v1.2.0"
    assert container_comp.state == DependencyState.RUNNING


def test_format_auto_detection(sample_cyclonedx_json, sample_spdx_json, sample_syft_json):
    import json
    assert detect_sbom_format(json.loads(sample_cyclonedx_json)) == SBOMFormat.CYCLONEDX
    assert detect_sbom_format(json.loads(sample_spdx_json)) == SBOMFormat.SPDX
    assert detect_sbom_format(json.loads(sample_syft_json)) == SBOMFormat.SYFT
