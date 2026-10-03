"""Unit tests for component normalizer and ecosystem resolution."""

from guardianos.inventory.models import Ecosystem
from guardianos.inventory.normalizer import (
    build_canonical_purl,
    normalize_ecosystem,
    parse_purl,
)


def test_normalize_ecosystem():
    assert normalize_ecosystem("pypi") == Ecosystem.PYPI
    assert normalize_ecosystem("Python") == Ecosystem.PYPI
    assert normalize_ecosystem("npm") == Ecosystem.NPM
    assert normalize_ecosystem("deb") == Ecosystem.DEBIAN
    assert normalize_ecosystem("debian") == Ecosystem.DEBIAN
    assert normalize_ecosystem("golang") == Ecosystem.GO
    assert normalize_ecosystem("maven") == Ecosystem.MAVEN
    assert normalize_ecosystem("docker") == Ecosystem.DOCKER
    assert normalize_ecosystem("cargo") == Ecosystem.CARGO
    assert normalize_ecosystem("nonexistent") == Ecosystem.GENERIC
    assert normalize_ecosystem(None) == Ecosystem.GENERIC


def test_build_canonical_purl():
    pypi_purl = build_canonical_purl(Ecosystem.PYPI, "Flask_App", "2.0.1")
    assert pypi_purl == "pkg:pypi/flask-app@2.0.1"

    deb_purl = build_canonical_purl(Ecosystem.DEBIAN, "libheif", "1.19.7")
    assert deb_purl == "pkg:deb/debian/libheif@1.19.7"

    npm_scoped = build_canonical_purl(Ecosystem.NPM, "core", "1.0.0", namespace="@babel")
    assert npm_scoped == "pkg:npm/@babel/core@1.0.0"


def test_parse_purl():
    eco, name, version, ns = parse_purl("pkg:deb/debian/libheif@1.19.7")
    assert eco == Ecosystem.DEBIAN
    assert name == "libheif"
    assert version == "1.19.7"
    assert ns == "debian"

    eco, name, version, ns = parse_purl("pkg:pypi/requests@2.31.0")
    assert eco == Ecosystem.PYPI
    assert name == "requests"
    assert version == "2.31.0"
