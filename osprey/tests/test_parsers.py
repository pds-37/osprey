"""Unit tests for npm, pypi, and docker manifest parsers."""

import json
from pathlib import Path

from osprey.parsers.docker import DockerParser
from osprey.parsers.npm import NpmParser
from osprey.parsers.pypi import PyPiParser


def test_npm_package_json_parser(tmp_path: Path):
    pj = tmp_path / "package.json"
    pj.write_text(
        json.dumps({
            "dependencies": {"express": "^4.17.1", "lodash": "4.17.20"},
            "devDependencies": {"mocha": "8.0.0", "typescript": "5.0.0"},
        })
    )

    parser = NpmParser()
    assert parser.detect(pj) is True
    comps = parser.parse(pj)

    assert len(comps) == 4
    prod = [c for c in comps if not c.is_dev]
    dev = [c for c in comps if c.is_dev]

    assert len(prod) == 2
    assert len(dev) == 2
    assert any(c.name == "express" and c.version == "4.17.1" for c in prod)
    assert any(c.name == "mocha" and c.version == "8.0.0" for c in dev)


def test_npm_package_lock_parser_v2_v3(tmp_path: Path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(
        json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "test-app"},
                "node_modules/express": {"version": "4.18.2"},
                "node_modules/mocha": {"version": "9.1.0", "dev": True},
            },
        })
    )

    parser = NpmParser()
    comps = parser.parse(lock)
    assert len(comps) == 2
    exp = next(c for c in comps if c.name == "express")
    assert exp.version == "4.18.2"
    assert exp.is_dev is False

    moc = next(c for c in comps if c.name == "mocha")
    assert moc.version == "9.1.0"
    assert moc.is_dev is True


def test_pypi_requirements_txt_parser(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("fastapi==0.95.0\nuvicorn>=0.20.0\n# comment\nrequests~=2.28.1; python_version >= '3.8'\n")

    parser = PyPiParser()
    assert parser.detect(req) is True
    comps = parser.parse(req)

    assert len(comps) == 3
    names = {c.name: c.version for c in comps}
    assert names["fastapi"] == "0.95.0"
    assert names["uvicorn"] == "0.20.0"
    assert names["requests"] == "2.28.1"
    assert all(not c.is_dev for c in comps)


def test_pypi_requirements_dev_parser(tmp_path: Path):
    req_dev = tmp_path / "requirements-dev.txt"
    req_dev.write_text("pytest==7.4.0\nruff==0.1.0\n")

    parser = PyPiParser()
    comps = parser.parse(req_dev)
    assert len(comps) == 2
    assert all(c.is_dev for c in comps)


def test_dockerfile_and_compose_parser(tmp_path: Path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM python:3.11-slim\nWORKDIR /app\nEXPOSE 8080 9000\n")

    dparser = DockerParser()
    assert dparser.detect(df) is True
    comps = dparser.parse(df)
    assert len(comps) == 1
    assert comps[0].name == "python"
    assert comps[0].version == "3.11-slim"

    svcs = dparser.parse_services(df)
    assert len(svcs) == 1
    assert svcs[0].ports == [8080, 9000]
    assert svcs[0].ports_declared is True
    assert svcs[0].exposure is not None
    assert svcs[0].exposure.level == "unknown"

    # docker-compose.yml
    dc = tmp_path / "docker-compose.yml"
    dc.write_text("""
version: '3'
services:
  api:
    image: node:18-alpine
    ports:
      - "3000:3000"
  worker:
    image: redis:alpine
""")
    dc_svcs = dparser.parse_services(dc)
    assert len(dc_svcs) == 2
    api_svc = next(s for s in dc_svcs if s.name == "api")
    worker_svc = next(s for s in dc_svcs if s.name == "worker")

    assert api_svc.ports_declared is True
    assert api_svc.exposure.level == "unknown"
    assert worker_svc.ports_declared is False
    assert worker_svc.exposure.level == "unknown"
