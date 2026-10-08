from osprey.core.models import VersionMatchStatus
from osprey.core.versioning import compare_versions, evaluate_version, is_version_affected


def _range(*events):
    return {"type": "SEMVER", "events": list(events)}


def test_introduced_and_fixed_boundaries_exclude_older_versions():
    ranges = [_range({"introduced": "2.0.0"}, {"fixed": "2.0.4"})]
    assert evaluate_version("1.5.0", "npm", ranges=ranges).status == VersionMatchStatus.NOT_AFFECTED
    assert evaluate_version("2.0.2", "npm", ranges=ranges).status == VersionMatchStatus.AFFECTED
    assert evaluate_version("2.0.4", "npm", ranges=ranges).status == VersionMatchStatus.NOT_AFFECTED


def test_multiple_osv_ranges_and_inclusive_last_affected():
    ranges = [
        _range({"introduced": "1.0.0"}, {"fixed": "1.0.2"}),
        _range({"introduced": "2.0.0"}, {"last_affected": "2.0.3"}),
    ]
    assert evaluate_version("2.0.3", "npm", ranges=ranges).status == VersionMatchStatus.AFFECTED
    assert evaluate_version("2.0.4", "npm", ranges=ranges).status == VersionMatchStatus.NOT_AFFECTED


def test_missing_introduction_is_unknown_not_all_previous_versions():
    ranges = [_range({"fixed": "2.0.4"})]
    assert evaluate_version("1.5.0", "npm", ranges=ranges).status == VersionMatchStatus.UNKNOWN
    assert is_version_affected("1.5.0", [], ["2.0.4"], ecosystem="npm") is False


def test_exact_versions_and_prerelease_ordering():
    assert evaluate_version("1.2.3", "npm", exact_versions=["1.2.3"]).status == VersionMatchStatus.AFFECTED
    assert evaluate_version("1.2.4", "npm", exact_versions=["1.2.3"], fixed_versions=["1.2.5"]).status == VersionMatchStatus.NOT_AFFECTED
    assert compare_versions("1.2.3-beta.2", "1.2.3-beta.10", "npm") == -1
    assert compare_versions("1.2.3-rc.1", "1.2.3", "npm") == -1


def test_pypi_and_debian_use_ecosystem_ordering():
    assert compare_versions("1.0rc1", "1.0", "PyPI") == -1
    assert compare_versions("1.0~rc1-1", "1.0-1", "Debian") == -1
    assert compare_versions("2:1.0-1", "1:9.9-9", "Debian") == 1


def test_unknown_ecosystem_comparison_is_conservative():
    assert compare_versions("1.0", "2.0", "unrecognized") is None
    assert evaluate_version("1.0", "unrecognized", ranges=[_range({"introduced": "0"}, {"fixed": "2.0.0"})]).status == VersionMatchStatus.UNKNOWN
