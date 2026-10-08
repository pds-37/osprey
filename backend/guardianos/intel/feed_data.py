"""Explicitly seeded demo advisories; production starts with no local mock records."""

from datetime import datetime, timezone
from typing import Dict, List
from guardianos.intel.models import (
    VulnerabilityRecord,
    VulnerabilitySeverity,
    VulnerabilitySource,
)
from guardianos.inventory.models import Ecosystem

# Seed dataset with high-impact supply chain and container vulnerabilities
DEFAULT_ADVISORIES: List[VulnerabilityRecord] = [
    VulnerabilityRecord(
        id="CVE-2023-44398",
        aliases=["GHSA-57v4-p725-x477"],
        summary="libheif heap-buffer-overflow in parse_overlay_image function leading to RCE",
        details="A heap-buffer-overflow vulnerability in libheif before 1.19.8 allows remote attackers to execute arbitrary code or cause Denial of Service via crafted HEIF image conversion triggered during image processing.",
        ecosystem=Ecosystem.DEBIAN,
        component_name="libheif",
        affected_version_ranges=["< 1.19.8", "<= 1.19.7"],
        introduced_versions=["0"],
        fixed_versions=["1.19.8"],
        severity=VulnerabilitySeverity.CRITICAL,
        cvss_score=9.8,
        cwe_ids=["CWE-122", "CWE-787"],
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2023-44398",
            "https://github.com/strukturag/libheif/commit/e31a196ec2b07d6b38c353b3df8d3dbb4cfae977"
        ],
        published_at=datetime(2023, 10, 1, 12, 0, tzinfo=timezone.utc),
        source=VulnerabilitySource.DEMO_FIXTURE
    ),
    VulnerabilityRecord(
        id="CVE-2022-44268",
        aliases=["GHSA-g72m-cv5v-x5q2"],
        summary="ImageMagick Arbitrary File Disclosure via crafted PNG image profile",
        details="ImageMagick 7.1.0-49 to 7.1.1-28 is vulnerable to Information Disclosure. When parsing a crafted PNG with a specific tEXt chunk, ImageMagick reads local file contents and embeds them into the resulting output image.",
        ecosystem=Ecosystem.DEBIAN,
        component_name="imagemagick",
        affected_version_ranges=["< 7.1.1-29"],
        introduced_versions=["0"],
        fixed_versions=["7.1.1-29"],
        severity=VulnerabilitySeverity.HIGH,
        cvss_score=7.5,
        cwe_ids=["CWE-200"],
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-44268"],
        published_at=datetime(2023, 2, 6, 0, 0, tzinfo=timezone.utc),
        source=VulnerabilitySource.DEMO_FIXTURE
    ),
    VulnerabilityRecord(
        id="CVE-2024-21626",
        aliases=["GHSA-xr7r-f8xq-vfvv"],
        summary="runc WORKDIR file descriptor leak enabling container breakout",
        details="In runc 1.1.11 and earlier, internal file descriptors to the host /sys/fs/cgroup and host root were leaked during process initiation, allowing container escape to host root filesystem.",
        ecosystem=Ecosystem.DOCKER,
        component_name="runc",
        affected_version_ranges=["<= 1.1.11"],
        introduced_versions=["0"],
        fixed_versions=["1.1.12"],
        severity=VulnerabilitySeverity.CRITICAL,
        cvss_score=9.9,
        cwe_ids=["CWE-403"],
        references=["https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv"],
        published_at=datetime(2024, 1, 31, 0, 0, tzinfo=timezone.utc),
        source=VulnerabilitySource.DEMO_FIXTURE
    ),
    VulnerabilityRecord(
        id="GHSA-w596-4wvx-j9j6",
        aliases=["CVE-2024-24762"],
        summary="Pydantic email-validator ReDoS leading to Denial of Service",
        details="In Pydantic when using EmailStr fields, specially crafted input can trigger catastrophic backtracking in email validation regex.",
        ecosystem=Ecosystem.PYPI,
        component_name="pydantic",
        affected_version_ranges=["< 2.6.0"],
        introduced_versions=["0"],
        fixed_versions=["2.6.0"],
        severity=VulnerabilitySeverity.MEDIUM,
        cvss_score=5.3,
        cwe_ids=["CWE-1333"],
        references=["https://github.com/pydantic/pydantic/security/advisories/GHSA-w596-4wvx-j9j6"],
        published_at=datetime(2024, 2, 1, 0, 0, tzinfo=timezone.utc),
        source=VulnerabilitySource.DEMO_FIXTURE
    )
]


class VulnerabilityFeedRegistry:
    """Stores advisory records; bundled records load only in explicit demo/test mode."""

    def __init__(self, include_demo_fixtures: bool | None = None) -> None:
        self.advisories: Dict[str, VulnerabilityRecord] = {}
        if include_demo_fixtures is None:
            from guardianos.core.config import settings
            include_demo_fixtures = settings.ENABLE_DEMO_FIXTURES
        if include_demo_fixtures:
            self.load_demo_fixtures()

    def load_demo_fixtures(self) -> None:
        for advisory in DEFAULT_ADVISORIES:
            self.register_advisory(advisory.model_copy(deep=True))

    def register_advisory(self, adv: VulnerabilityRecord) -> None:
        self.advisories[adv.id] = adv

    def get_advisory(self, vuln_id: str) -> VulnerabilityRecord | None:
        return self.advisories.get(vuln_id)

    def list_advisories(self) -> List[VulnerabilityRecord]:
        return list(self.advisories.values())

    def find_by_component(self, name: str, ecosystem: Ecosystem) -> List[VulnerabilityRecord]:
        clean_name = name.lower()
        matches = []
        for adv in self.advisories.values():
            if adv.component_name.lower() == clean_name:
                # If ecosystem matches or either is generic
                if adv.ecosystem == ecosystem or ecosystem == Ecosystem.GENERIC or adv.ecosystem == Ecosystem.GENERIC:
                    matches.append(adv)
        return matches


vuln_registry = VulnerabilityFeedRegistry()
