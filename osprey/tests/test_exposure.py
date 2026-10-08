"""Unit tests for package-level exposure inference rules."""

from pathlib import Path

from osprey.exposure import evaluate_exposure, scan_source_code_listeners
from osprey.models import Component, ExposureInfo, Service


def test_dev_only_exposure_rule():
    comp = Component(
        name="jest",
        version="29.0.0",
        ecosystem="npm",
        purl="pkg:npm/jest@29.0.0",
        is_dev=True,
        source_file="package.json",
    )
    ambient = [ExposureInfo(level="unknown", confidence="inferred", evidence="route observed; ingress unknown")]
    exp = evaluate_exposure(comp, ambient_exposures=ambient)

    assert exp.level == "dev-only"
    assert exp.confidence == "inferred"
    assert "dev-only" in exp.evidence


def test_container_port_does_not_prove_public_exposure():
    comp = Component(
        name="express",
        version="4.17.1",
        ecosystem="npm",
        purl="pkg:npm/express@4.17.1",
        is_dev=False,
    )
    svc = Service(
        name="web",
        ports=[8080],
        exposure=ExposureInfo(level="unknown", confidence="inferred", evidence="EXPOSE 8080; external ingress unknown"),
    )
    exp = evaluate_exposure(comp, service=svc)
    assert exp.level == "unknown"
    assert exp.confidence == "inferred"


def test_no_compose_port_mapping_does_not_prove_internal_exposure():
    comp = Component(
        name="redis-py",
        version="4.0.0",
        ecosystem="PyPI",
        purl="pkg:pypi/redis-py@4.0.0",
        is_dev=False,
    )
    svc = Service(
        name="worker",
        ports=[],
        exposure=ExposureInfo(level="unknown", confidence="inferred", evidence="no declared port mapping; other ingress unknown"),
    )
    exp = evaluate_exposure(comp, service=svc)
    assert exp.level == "unknown"
    assert exp.confidence == "inferred"


def test_unknown_exposure_default():
    comp = Component(
        name="cryptography",
        version="3.4.8",
        ecosystem="PyPI",
        purl="pkg:pypi/cryptography@3.4.8",
        is_dev=False,
    )
    exp = evaluate_exposure(comp, service=None, ambient_exposures=[])
    assert exp.level == "unknown"
    assert exp.confidence == "unknown"


def test_declared_override_rule():
    comp = Component(
        name="internal-tool",
        version="1.0.0",
        ecosystem="npm",
        purl="pkg:npm/internal-tool@1.0.0",
        is_dev=False,
    )
    overrides = {
        "packages": {
            "internal-tool": {
                "exposure": "internal",
                "reason": "Airgapped compliance cluster",
            }
        }
    }
    exp = evaluate_exposure(comp, overrides=overrides)
    assert exp.level == "internal"
    assert exp.confidence == "declared"
    assert "Airgapped compliance cluster" in exp.evidence


def test_scan_source_code_listeners(tmp_path: Path):
    server_file = tmp_path / "server.js"
    server_file.write_text("const app = express();\napp.listen(8080, () => console.log('online'));\n")

    py_file = tmp_path / "main.py"
    py_file.write_text("from fastapi import FastAPI\napp = FastAPI()\n@app.get('/health')\ndef health(): pass\n")

    exps = scan_source_code_listeners(tmp_path)
    assert len(exps) == 2
    assert all(e.level == "unknown" for e in exps)
    assert any("Node HTTP listener" in e.evidence for e in exps)
    assert any("FastAPI/Starlette" in e.evidence for e in exps)


def test_internal_worker_package_not_tagged_public(tmp_path: Path):
    """A vulnerable package used only by an internal worker must NOT be tagged public."""
    from osprey.exposure import map_component_to_service
    from osprey.risk import classify_risk

    worker_dir = tmp_path / "worker"
    worker_dir.mkdir()
    worker_req = worker_dir / "requirements.txt"
    worker_req.write_text("celery==5.2.0\n")

    web_dir = tmp_path / "web"
    web_dir.mkdir()
    web_pkg = web_dir / "package.json"
    web_pkg.write_text('{"dependencies": {"express": "4.17.1"}}')

    worker_svc = Service(
        name="internal-worker",
        source_file=str(tmp_path / "docker-compose.yml"),
        ports=[],
        exposure=ExposureInfo(level="unknown", confidence="inferred", evidence="no declared port mapping; other ingress unknown"),
        build_context=str(worker_dir.resolve()),
    )

    web_svc = Service(
        name="web-frontend",
        source_file=str(tmp_path / "docker-compose.yml"),
        ports=[8080],
        exposure=ExposureInfo(level="unknown", confidence="inferred", evidence="published ports [8080]; external ingress unknown"),
        build_context=str(web_dir.resolve()),
    )

    services = [web_svc, worker_svc]

    # Component inside worker
    worker_comp = Component(
        name="celery",
        version="5.2.0",
        ecosystem="PyPI",
        purl="pkg:pypi/celery@5.2.0",
        is_dev=False,
        source_file=str(worker_req.resolve()),
    )

    owning_svc = map_component_to_service(worker_comp, services, tmp_path)
    assert owning_svc is not None
    assert owning_svc.name == "internal-worker"

    # Ambient public exposure exists from the web frontend
    ambient = [web_svc.exposure]
    exposure = evaluate_exposure(worker_comp, service=owning_svc, ambient_exposures=ambient)

    # Must NOT be tagged public!
    assert exposure.level == "unknown"
    assert exposure.level != "public"

    # Unknown ingress and route-to-symbol state must not produce ACT NOW.
    tier, rule = classify_risk(
        exposure_level=exposure.level,
        exposure_confidence=exposure.confidence,
        cvss_score=9.8,  # Critical CVSS
        epss_score=0.45,
        in_cisa_kev=True,
        kev_available=True,
        version_status="AFFECTED",
    )
    assert tier == "PLAN"
    assert tier != "ACT NOW"
    assert "PLAN" in rule


def test_unproven_mapping_exposure_is_unknown_never_public(tmp_path: Path):
    """If mapping cannot be proven, exposure must be 'unknown', never 'public'."""
    from osprey.exposure import map_component_to_service

    unmapped_file = tmp_path / "somewhere_else" / "requirements.txt"
    unmapped_file.parent.mkdir(parents=True)
    unmapped_file.write_text("urllib3==1.26.5\n")

    web_svc = Service(
        name="web",
        source_file=str(tmp_path / "docker-compose.yml"),
        ports=[8080],
        exposure=ExposureInfo(level="unknown", confidence="inferred", evidence="published ports [8080]; external ingress unknown"),
        build_context=str((tmp_path / "web").resolve()),
    )

    comp = Component(
        name="urllib3",
        version="1.26.5",
        ecosystem="PyPI",
        purl="pkg:pypi/urllib3@1.26.5",
        is_dev=False,
        source_file=str(unmapped_file.resolve()),
    )

    owning_svc = map_component_to_service(comp, [web_svc], tmp_path)
    assert owning_svc is None  # Unproven

    # Evaluate exposure
    ambient = [web_svc.exposure]
    exp = evaluate_exposure(comp, service=owning_svc, ambient_exposures=ambient)

    # Must be unknown, never public
    assert exp.level == "unknown"
    assert exp.level != "public"
