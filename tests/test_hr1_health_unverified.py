"""HR-1 (register, owner 10-15): V3c reads health routes only for a service that builds a FastAPI/Flask/Starlette app
(exact AST call name). A service without one (05-r1 `gke-processor`: stdlib `http.server`, which served `/healthz`)
gets the report-only CONTAINER.HEALTH_ROUTE_UNVERIFIED instead of the blocking HEALTH_ROUTE_MISSING. Framework
services are judged exactly as before. No network, no credentials."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent.validators import ValidationContext  # noqa: E402
from developer_agent.validators.container import (ENTRYPOINT_MASKED_CODES, HEALTH_UNVERIFIED_CODE,  # noqa: E402
                                                  ContainerContractValidator, HealthRouteUnverifiedValidator)
from developer_agent.validators.step1 import build_step1_stack  # noqa: E402
from shared.artifact_ownership import Ownership  # noqa: E402

FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "hr1_05r1_gke_processor")
WEB = "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n"
MISSING = "CONTAINER.HEALTH_ROUTE_MISSING"


def _read(name):
    with open(os.path.join(FIXTURE, name + ".txt"), encoding="utf-8") as fh:
        return fh.read()


def _gke_05r1():
    """The captured 05-r1 `gke-processor` files (eval record 20261015-AC-2-3-6-fresh-record-b377559, run 05-r1)."""
    return {"apps/gke-processor/Procfile": _read("Procfile"), "apps/gke-processor/main.py": _read("main.py"),
            "apps/gke-processor/kubernetes/deployment.yaml": _read("kubernetes/deployment.yaml")}


def _cloudrun(svc="api"):
    return {"infra/workload/main.tf": f'module "compute" {{\n  source       = "../modules/compute-cloudrun"\n'
                                      f'  service_name = "{svc}"\n}}\n'}


def _ctx(files):
    return ValidationContext.build(files, ownership=lambda p: Ownership.LLM_AUTHORED if p.endswith(".py") or
                                   p.endswith("Procfile") else Ownership.PLATFORM_RENDERED,
                                   draft={k: v for k, v in files.items() if k.endswith(".py")})


def _blocking(files):
    return [(d.code, d.file) for d in ContainerContractValidator().validate(_ctx(files))]


def _unverified(files):
    return HealthRouteUnverifiedValidator().validate(_ctx(files))


def test_05r1_stdlib_http_server_is_unverified_not_blocking():
    files = _gke_05r1()
    assert "BaseHTTPRequestHandler" in files["apps/gke-processor/main.py"]   # the captured shape
    assert _blocking(files) == []
    got = _unverified(files)
    assert [(d.code, d.file, d.severity) for d in got] == [
        (HEALTH_UNVERIFIED_CODE, "apps/gke-processor/main.py", "warning")]
    assert "GET /healthz" in got[0].message and "gke-processor" in got[0].message


def test_05r1_through_the_step1_stack_is_report_only():
    stack = build_step1_stack(validate_client=None, verifier_factory=None)
    assert stack.mode_of("V3c-health-unverified") == "report_only"
    assert stack.mode_of("V3c") == "blocking"
    assert HEALTH_UNVERIFIED_CODE not in ENTRYPOINT_MASKED_CODES   # never masked/revealed: never blocking
    files = _gke_05r1()
    blocking = ContainerContractValidator().validate(_ctx(files))
    assert all(d.code != HEALTH_UNVERIFIED_CODE for d in blocking)


def test_fastapi_service_missing_route_still_blocks_unchanged():
    main = 'from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get("/")\ndef root():\n    return {}\n'
    files = {"apps/api/main.py": main, "apps/api/Procfile": WEB, **_cloudrun()}
    got = ContainerContractValidator().validate(_ctx(files))
    assert [(d.code, d.file, d.severity) for d in got] == [(MISSING, "apps/api/main.py", "error")]
    assert got[0].message == ("no route of service 'api' serves GET /health; its compute-cloudrun module's startup "
                              "probe (health_check_path) calls it")
    assert _unverified(files) == []


@pytest.mark.parametrize("main,procfile", [
    ('import flask\napp = flask.Flask(__name__)\n\n@app.route("/")\ndef r():\n    return "ok"\n',
     "web: gunicorn main:app\n"),
    ('from starlette.applications import Starlette\nfrom starlette.routing import Route\n\nasync def r(req):\n'
     '    return None\n\napp = Starlette(routes=[Route("/", r)])\n', WEB),
])
def test_flask_and_starlette_are_still_judged(main, procfile):
    files = {"apps/api/main.py": main, "apps/api/Procfile": procfile, **_cloudrun()}
    assert _blocking(files) == [(MISSING, "apps/api/main.py")]
    assert _unverified(files) == []
    served = main.replace('"/"', '"/health"')
    assert _blocking({**files, "apps/api/main.py": served}) == []


def test_valid_fastapi_with_health_is_unchanged():
    main = 'from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get("/health")\ndef h():\n    return {}\n'
    files = {"apps/api/main.py": main, "apps/api/Procfile": WEB, **_cloudrun()}
    assert _blocking(files) == []
    assert _unverified(files) == []


def test_non_framework_service_without_probe_is_not_reported():
    # no Kubernetes manifest and no compute-cloudrun block names the service: no probe known -> nothing, as before
    files = {k: v for k, v in _gke_05r1().items() if not k.endswith(".yaml")}
    assert _blocking(files) == []
    assert _unverified(files) == []
