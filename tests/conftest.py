"""Pytest fixtures and configuration."""

import sys
import os
import json
import pytest

# Bundled advisories are explicit test fixtures; production does not load them by default.
os.environ.setdefault("ENABLE_DEMO_FIXTURES", "true")
os.environ.setdefault("ENVIRONMENT", "test")
os.environ["STATE_DB_PATH"] = ":memory:"

# Ensure backend directory is in sys.path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)
osprey_src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "osprey", "src"))
if osprey_src_path not in sys.path:
    sys.path.insert(0, osprey_src_path)

from guardianos.inventory.service import inventory_service


@pytest.fixture(autouse=True)
def trusted_test_admin():
    """Existing integration tests run as an explicit test admin, not anonymously."""
    from guardianos.api.app import app
    from guardianos.core.security import CurrentUser, UserRole, get_current_user

    app.dependency_overrides[get_current_user] = lambda: CurrentUser(username="test-admin", role=UserRole.ADMIN)
    yield
    app.dependency_overrides.pop(get_current_user, None)


@pytest.fixture(autouse=True)
def reset_service_state():
    """Clear service indexes and their test-local SQLite records before and after each test."""
    from guardianos.core.audit import clear_audit_events
    from guardianos.attackpath.service import attack_path_service
    from guardianos.exposure.service import exposure_service
    from guardianos.intel.service import intel_service
    from guardianos.propagation.service import propagation_service
    from guardianos.remediation.service import remediation_service
    from guardianos.risk.service import risk_service
    from guardianos.upstream.service import upstream_service

    services = (
        inventory_service, intel_service, exposure_service, attack_path_service,
        propagation_service, remediation_service, risk_service, upstream_service,
    )
    for service in services:
        service.clear()
    clear_audit_events()
    yield
    for service in services:
        service.clear()
    clear_audit_events()


@pytest.fixture
def sample_cyclonedx_json() -> str:
    """Sample CycloneDX 1.4 JSON containing application and libraries."""
    return json.dumps({
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
        "version": 1,
        "metadata": {
            "component": {
                "name": "image-processing-service",
                "version": "2.4.0",
                "type": "application",
                "bom-ref": "pkg:generic/image-processing-service@2.4.0"
            }
        },
        "components": [
            {
                "name": "fastapi",
                "version": "0.110.0",
                "type": "library",
                "purl": "pkg:pypi/fastapi@0.110.0",
                "bom-ref": "pkg:pypi/fastapi@0.110.0",
                "licenses": [{"license": {"id": "MIT"}}]
            },
            {
                "name": "starlette",
                "version": "0.36.3",
                "type": "library",
                "purl": "pkg:pypi/starlette@0.36.3",
                "bom-ref": "pkg:pypi/starlette@0.36.3",
                "licenses": [{"license": {"id": "BSD-3-Clause"}}]
            },
            {
                "name": "pydantic",
                "version": "2.6.4",
                "type": "library",
                "purl": "pkg:pypi/pydantic@2.6.4",
                "bom-ref": "pkg:pypi/pydantic@2.6.4"
            }
        ],
        "dependencies": [
            {
                "ref": "pkg:generic/image-processing-service@2.4.0",
                "dependsOn": [
                    "pkg:pypi/fastapi@0.110.0"
                ]
            },
            {
                "ref": "pkg:pypi/fastapi@0.110.0",
                "dependsOn": [
                    "pkg:pypi/starlette@0.36.3",
                    "pkg:pypi/pydantic@2.6.4"
                ]
            }
        ]
    })


@pytest.fixture
def sample_spdx_json() -> str:
    """Sample SPDX 2.3 JSON containing packages and relationships."""
    return json.dumps({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "discourse-app",
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-ImageMagick",
                "name": "imagemagick",
                "versionInfo": "7.1.1",
                "licenseConcluded": "Apache-2.0",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:deb/debian/imagemagick@7.1.1"
                    }
                ]
            },
            {
                "SPDXID": "SPDXRef-Package-libheif",
                "name": "libheif",
                "versionInfo": "1.19.7",
                "licenseConcluded": "LGPL-3.0",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": "pkg:deb/debian/libheif@1.19.7"
                    }
                ]
            }
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-Package-ImageMagick",
                "relatedSpdxElement": "SPDXRef-Package-libheif",
                "relationshipType": "DEPENDS_ON"
            }
        ]
    })


@pytest.fixture
def sample_syft_json() -> str:
    """Sample Syft JSON scanning a container image."""
    return json.dumps({
        "schema": {
            "version": "1.1.0",
            "url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-1.1.0.json"
        },
        "id": "syft-scan-prod-container",
        "source": {
            "type": "image",
            "target": "prod-media-processor:v1.2.0"
        },
        "artifacts": [
            {
                "id": "art-1",
                "name": "libheif",
                "version": "1.19.7",
                "type": "deb",
                "purl": "pkg:deb/debian/libheif@1.19.7",
                "licenses": [{"value": "LGPL-3.0"}]
            },
            {
                "id": "art-2",
                "name": "imagemagick",
                "version": "7.1.1-29",
                "type": "deb",
                "purl": "pkg:deb/debian/imagemagick@7.1.1-29",
                "licenses": [{"value": "Apache-2.0"}]
            }
        ],
        "artifactRelationships": [
            {
                "parent": "art-2",
                "child": "art-1",
                "type": "dependsOn"
            }
        ]
    })
