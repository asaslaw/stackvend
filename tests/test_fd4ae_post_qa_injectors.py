"""FD-4AE (FD23-05, FD23-14a/b): no build-time / deploy-time rewrite of application code after the QA gate.

The terraform MCP used to rewrite app code in the deploy workspace (and Git-write some of it back) AFTER QA had
certified the unmodified code: a Starlette compat header prepended above `from __future__` (SyntaxError), a
`create_all` try/except inside `lifespan` calling an undefined `logger` (NameError at startup), a router aggregator
overwriting `routers/__init__.py`, pydantic BaseModel shadowing / un-commenting of contract schemas, a regex rename
of SQLAlchemy synonym columns, `(alembic upgrade head || true) &&` rewrites of authored Procfiles, and a hello-world
`main.py` when a service had no entrypoint. All deleted. These tests pin:

- Do No Harm: valid app files go through prepare_workspace and _build_and_push_container byte-identical, still
  compile, and are never queued for the Git writeback.
- A missing Procfile still gets the default, with a failing migration failing the start (no `|| true`).
- No entrypoint at all is a typed build failure (BUILD.ENTRYPOINT_MISSING), never a generated main.py.

Hermetic: no ADC, no network; the build stops at the (mocked) source staging step.
"""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from fd4g_support import load_tf_service  # noqa: E402

DELETED = (
    "inject_castor_runtime_compat",
    "inject_castor_schema_bootstrap",
    "synthesize_router_aggregator",
    "ensure_pydantic_orm_compatibility",
    "heal_commented_contract_schemas",
    "sanitize_sqlalchemy_model_synonyms",
)

# Valid application files, each one shaped like an input a deleted injector used to rewrite.
APP_FILES = {
    # compat header used to be prepended above the __future__ import; bootstrap inserted `logger` calls in lifespan
    "apps/api/main.py": (
        "from __future__ import annotations\n"
        "from contextlib import asynccontextmanager\n"
        "from fastapi import FastAPI\n"
        "from routers import router\n\n"
        "@asynccontextmanager\n"
        "async def lifespan(app):\n"
        "    print('startup')\n"
        "    yield\n\n"
        "app = FastAPI(lifespan=lifespan)\n"
        "app.include_router(router)\n\n"
        "@app.get('/health')\n"
        "def health():\n"
        "    return {'status': 'ok'}\n"
    ),
    # schema bootstrap triggered on database.py + models.py
    "apps/api/database.py": "ENGINE_URL = 'sqlite://'\n",
    # synonym curing renamed `org_id` -> `organization_id` (an `_id` alias that starts with the attr prefix)
    "apps/api/models.py": (
        "from sqlalchemy.orm import Mapped, mapped_column, synonym\n\n"
        "class Invoice:\n"
        "    __tablename__ = 'invoices'\n"
        "    org_id: Mapped[str] = mapped_column()\n"
        "    organization_id = synonym('org_id')\n"
    ),
    # the aggregator overwrote any routers/__init__.py without a `router =` assignment
    "apps/api/routers/__init__.py": "from .items import items_router as router  # noqa: F401\n",
    "apps/api/routers/items.py": (
        "from fastapi import APIRouter\n\n"
        "items_router = APIRouter(prefix='/api/v1/items')\n\n"
        "@items_router.get('/')\n"
        "def list_items():\n"
        "    return []\n"
    ),
    # contract healing un-commented this block, injected `from uuid import UUID` and shadowed BaseModel
    "apps/api/schemas.py": (
        '"""API schemas."""\n'
        "from pydantic import BaseModel\n\n"
        "# from typing import Optional\n"
        "# class Draft(BaseModel):\n"
        "#     note: str\n\n"
        "class Item(BaseModel):\n"
        "    id: str  # an UUID string\n"
    ),
    # the Procfile rewrite prepended `(alembic upgrade head || true) &&` when alembic.ini existed
    "apps/api/Procfile": "web: uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}\n",
    "apps/api/alembic.ini": "[alembic]\nscript_location = migrations\n",
}


@pytest.fixture
def tf(monkeypatch):
    mod = load_tf_service(monkeypatch)
    import importlib
    settings = sys.modules.get("shared.settings") or importlib.import_module("shared.settings")
    monkeypatch.setattr(settings, "get_platform_settings", lambda *a, **k: None)   # no Firestore (BOM defaults)
    return mod


def _svc(tf, tmp_path):
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="", workspace_base_dir=str(tmp_path),
                              firestore_client=MagicMock())
    svc.db = None
    svc.state_bucket = ""
    return svc


def _write(base, files):
    for rel, text in files.items():
        path = os.path.join(str(base), rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)


def _read(base, rel):
    with open(os.path.join(str(base), rel), "r", encoding="utf-8") as fh:
        return fh.read()


def _build_until_staging(tf, svc, ws):
    """Run _build_and_push_container through every pre-packaging step; stop at the mocked source staging."""
    staged = []

    def stage(**kwargs):
        staged.append(kwargs["object_name"])
        raise RuntimeError("stop after packaging (test)")

    with patch("google.auth.default", return_value=(MagicMock(), "p")), \
         patch("google.auth.transport.requests.AuthorizedSession"), \
         patch("google.cloud.storage.Client"), \
         patch.object(tf.TerraformService, "_stage_build_source", side_effect=stage):
        ok = svc._build_and_push_container("fd4ae-app", "child", str(ws), "img:tag")
    return ok, staged


def test_deleted_injectors_are_gone(tf):
    for name in DELETED:
        assert not hasattr(tf, name), name


def test_build_leaves_valid_app_code_byte_identical(tf, tmp_path):
    ws = tmp_path / "ws"
    _write(ws, APP_FILES)
    svc = _svc(tf, tmp_path / "base")
    ok, staged = _build_until_staging(tf, svc, ws)
    assert ok is False and staged, "the build must reach source staging (only the staging mock stops it)"
    for rel, text in APP_FILES.items():
        assert _read(ws, rel) == text, f"{rel} was rewritten after QA"
        if rel.endswith(".py"):
            compile(_read(ws, rel), rel, "exec")
    assert not os.path.exists(os.path.join(str(ws), "apps", "api", "app.py"))


def test_prepare_workspace_neither_rewrites_nor_writes_back_app_code(tf, tmp_path):
    svc = _svc(tf, tmp_path / "base")
    ws_dir = svc.prepare_workspace("fd4ae-app", "trace-fd4ae", dict(APP_FILES))
    for rel, text in APP_FILES.items():
        assert _read(ws_dir, rel) == text, f"{rel} was rewritten in the deploy workspace"
    healed = (getattr(svc, "_last_healed_files", {}) or {}).get("fd4ae-app", {}) or {}
    assert not [k for k in healed if k.startswith("apps/")], healed


def test_authored_procfile_is_never_rewritten_even_with_alembic(tf, tmp_path):
    ws = tmp_path / "ws"
    procfile = "web: gunicorn -k uvicorn.workers.UvicornWorker main:app\nworker: python worker.py\n"
    _write(ws, {"apps/api/main.py": "app = None\n", "apps/api/Procfile": procfile,
                "apps/api/alembic.ini": "[alembic]\n", "alembic.ini": "[alembic]\n", "Procfile": procfile})
    _build_until_staging(tf, _svc(tf, tmp_path / "base"), ws)
    assert _read(ws, "apps/api/Procfile") == procfile
    assert _read(ws, "Procfile") == procfile


def test_missing_procfile_default_fails_loudly_on_migration_failure(tf, tmp_path):
    assert tf.default_procfile_text(False) == "web: uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}\n"
    with_mig = tf.default_procfile_text(True)
    assert with_mig == "web: alembic upgrade head && uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}\n"
    assert "|| true" not in with_mig
    ws = tmp_path / "ws"
    _write(ws, {"apps/api/main.py": "app = None\n", "apps/api/alembic.ini": "[alembic]\n"})
    _build_until_staging(tf, _svc(tf, tmp_path / "base"), ws)
    assert _read(ws, "apps/api/Procfile") == with_mig


def test_no_entrypoint_is_a_typed_build_failure_not_a_hello_world(tf, tmp_path):
    ws = tmp_path / "ws"
    _write(ws, {"apps/api/requirements.txt": "fastapi\n"})
    svc = _svc(tf, tmp_path / "base")
    ok, staged = _build_until_staging(tf, svc, ws)
    assert ok is False and not staged
    assert svc._last_build_error.startswith("BUILD.ENTRYPOINT_MISSING: apps/api ")
    assert not os.path.exists(os.path.join(str(ws), "apps", "api", "main.py"))
    assert not os.path.exists(os.path.join(str(ws), "apps", "api", "Procfile"))


def test_authored_procfile_with_other_entry_module_is_not_failed(tf, tmp_path):
    """Negative test for the typed check: a Procfile naming its own module (no main.py) is valid and untouched."""
    ws = tmp_path / "ws"
    procfile = "web: uvicorn server:app --host 0.0.0.0 --port ${PORT:-8080}\n"
    _write(ws, {"apps/api/server.py": "app = None\n", "apps/api/Procfile": procfile,
                "apps/api/requirements.txt": "fastapi\n"})
    svc = _svc(tf, tmp_path / "base")
    ok, staged = _build_until_staging(tf, svc, ws)
    assert staged, svc._last_build_error
    assert _read(ws, "apps/api/Procfile") == procfile
    assert not os.path.exists(os.path.join(str(ws), "apps", "api", "main.py"))


def test_missing_routers_init_is_not_generated_after_qa(tf, tmp_path):
    """FD-4AE: no router aggregator. FD-4AE-c (Fable RT F1(a)): no generated package init either; `routers/` ships as
    QA ran it (a namespace package), the pre-QA package gate owns init injection."""
    ws = tmp_path / "ws"
    _write(ws, {"apps/api/main.py": "app = None\n", "apps/api/Procfile": "web: uvicorn main:app\n",
                "apps/api/routers/items.py": "router = None\n"})
    _build_until_staging(tf, _svc(tf, tmp_path / "base"), ws)
    assert not os.path.exists(os.path.join(str(ws), "apps", "api", "routers", "__init__.py"))
    assert _read(ws, "apps/api/routers/items.py") == "router = None\n"


# ------------------------------------------------------------------------------------------------ RT F1 / F3
# The comment block the platform renders into infra/workload/human_override.tf
# (developer_agent/terraform_engine.generate_human_override_tf_template, abridged to its compute examples).
HUMAN_OVERRIDE_TF = (
    "# Example 1: Override Cloud Run container scaling or timeouts in module \"compute\":\n"
    "#\n"
    "# module \"compute\" {\n"
    "#   min_instance_count = 2\n"
    "# }\n"
    "#\n"
    "# resource \"google_cloud_run_v2_service\" \"app\" {\n"
    "#   template {}\n"
    "# }\n"
)
FOUNDATION_TF = 'module "foundation" {\n  source     = "./infra/modules/workload-foundation"\n  project_id = var.project_id\n}\n'
COMPUTE_TF = FOUNDATION_TF + 'module "compute" {\n  source = "./infra/modules/compute-cloudrun"\n}\n'


def _ws_tf(tmp_path, files):
    ws = tmp_path / "ws"
    _write(ws, files)
    return str(ws)


@pytest.mark.parametrize("files,expected", [
    ({"main.tf": FOUNDATION_TF, "human_override.tf": HUMAN_OVERRIDE_TF}, False),      # Gate A plan 07 shape
    ({"main.tf": COMPUTE_TF, "human_override.tf": HUMAN_OVERRIDE_TF}, True),
    ({"main.tf": FOUNDATION_TF + 'module "api" {\n  source = "./infra/modules/compute-gke-autopilot"\n}\n'}, True),
    ({"main.tf": FOUNDATION_TF + 'resource "google_cloud_run_v2_service" "app" {\n  name = "a"\n}\n'}, True),
    ({"main.tf": FOUNDATION_TF + 'resource "kubernetes_deployment_v1" "app" {\n  metadata {}\n}\n'}, True),
    ({"main.tf": FOUNDATION_TF + 'resource "google_pubsub_topic" "compute_events" {\n  name = "compute"\n}\n'}, False),
    ({"main.tf": 'module "compute" {\n  source = \n'}, True),   # unparseable -> legacy scan fallback (logged)
    ({"README.md": 'module "compute" {}\n'}, False),
])
def test_workspace_declares_compute_reads_parsed_hcl_not_comments(tf, tmp_path, files, expected):
    assert tf.workspace_declares_compute(_ws_tf(tmp_path, files)) is expected


def _fake_module(monkeypatch, dotted):
    import importlib
    parent_name, leaf = dotted.rsplit(".", 1)
    fake = MagicMock(name=dotted)
    monkeypatch.setitem(sys.modules, dotted, fake)
    parent = sys.modules.get(parent_name)
    if parent is None and "." not in parent_name:
        parent = importlib.import_module(parent_name)
    if parent is not None:
        monkeypatch.setattr(parent, leaf, fake, raising=False)
    return fake


@pytest.fixture
def deploy_tf(tf, monkeypatch):
    _fake_module(monkeypatch, "google.cloud.secretmanager")
    _fake_module(monkeypatch, "google.auth.transport.requests")
    _fake_module(monkeypatch, "google.auth").default.return_value = (MagicMock(), "p")
    import httpx
    monkeypatch.setattr(httpx, "Client", MagicMock(name="httpx.Client"))
    return tf


def _deploy(tf, tmp_path, files, build=None):
    ws = _ws_tf(tmp_path, files)
    TS = tf.TerraformService
    svc = TS(project_id="mock-stackvend-project", workspace_base_dir=str(tmp_path / "base"), firestore_client=MagicMock())
    ok = {"success": True, "exit_code": 0, "stdout": "{}", "stderr": ""}
    patches = [patch.object(TS, "prepare_workspace", return_value=ws),
               patch.object(TS, "_run_subprocess", lambda self, cmd, *a, **k: dict(ok)),
               patch.object(TS, "_fetch_repo_files", return_value={}),
               patch.object(TS, "_ensure_binary", return_value="tofu"),
               patch.object(TS, "_ensure_provider_mirror", return_value="")]
    if build is not None:
        patches.append(patch.object(TS, "_build_and_push_container", build))
    for p in patches:
        p.start()
    try:
        return svc.deploy_workload(product_id="fd4ae-app", trace_id="t-fd4ae", hcl_files=dict(files),
                                   target_project_id="child-project-123")
    finally:
        for p in reversed(patches):
            p.stop()


def test_foundation_only_workload_with_commented_examples_builds_no_container(deploy_tf, tmp_path):
    build = MagicMock(return_value=False)
    res = _deploy(deploy_tf, tmp_path, {"main.tf": FOUNDATION_TF, "human_override.tf": HUMAN_OVERRIDE_TF,
                                        "apps/agent/requirements.txt": "google-adk\n", "agent.py": "x = 1\n"},
                  build=build)
    build.assert_not_called()
    assert "BUILD." not in str(res.get("error") or "")
    assert res.get("error_class") != "BUILD_CONTRACT"


def test_compute_module_still_builds(deploy_tf, tmp_path):
    build = MagicMock(return_value=True)
    _deploy(deploy_tf, tmp_path, {"main.tf": COMPUTE_TF, "apps/api/main.py": "app = None\n"}, build=build)
    build.assert_called_once()


def test_entrypoint_missing_is_typed_build_contract_failure_not_iac(deploy_tf, tmp_path):
    res = _deploy(deploy_tf, tmp_path, {"main.tf": COMPUTE_TF, "apps/api/requirements.txt": "fastapi\n"})
    assert res["status"] == "FAILED"
    assert res["error_class"] == "BUILD_CONTRACT"           # workflow: not IAC_DEFECT / "" -> no tf remediation
    assert res["error"].startswith("BUILD.ENTRYPOINT_MISSING: apps/api ")   # code survives the 120-char summary


# ------------------------------------------------------------------------------------------------ re-check F1b
def _topology(**kinds):
    import json
    return json.dumps({"schema": "service_topology/v1",
                       "intent": {"services": [{"name": n.replace("_", "-"), "kind": k} for n, k in kinds.items()]}})


BASTION_TF = FOUNDATION_TF + 'module "compute" {\n  source = "../modules/compute-gce-bastion"\n}\n'
BASTION_APP = {   # S3-r1 first-draft shape, valid pre-QA since S3B-1 (tests/test_s3_bastion_container_scope.py)
    "apps/ops-bastion/export_maintenance.py": "import json\n\n\ndef main():\n    print(json.dumps({}))\n",
    "apps/ops-bastion/config.py": "BUCKET = 'b'\n",
    "apps/ops-bastion/requirements.txt": "google-cloud-storage\n",
    "apps/ops-bastion/startup.sh": "#!/bin/bash\npython3 export_maintenance.py\n",
}
WORKER_APP = {    # Gate A 03 shape: gce-batch-worker with no Procfile and no main.py
    "apps/gce-batch-worker/worker.py": "import os\n\nprint(os.environ.get('JOB', ''))\n",
    "apps/gce-batch-worker/requirements.txt": "google-cloud-pubsub\n",
    "apps/gce-batch-worker/startup.sh": "#!/bin/bash\npython3 worker.py\n",
}
API_APP = {"apps/api/main.py": "app = None\n", "apps/api/Procfile": "web: uvicorn main:app\n"}


def _assert_untouched(ws, files, svc_dir):
    for rel, text in files.items():
        assert _read(ws, rel) == text, rel
    on_disk = sorted(os.path.relpath(os.path.join(r, f), str(ws)).replace(os.sep, "/")
                     for r, _, fs in os.walk(os.path.join(str(ws), svc_dir)) for f in fs)
    assert on_disk == sorted(files), on_disk   # no Procfile / .python-version / static/.gitkeep written


def _frozenset_literal(rel_path, name):
    """The literal of `NAME = frozenset({...})` at module level of a repo file (ast; the gateway package is not
    importable next to the terraform MCP's `shared`)."""
    import ast
    with open(os.path.join(REPO_ROOT, rel_path), encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    node = next(n for n in tree.body if isinstance(n, ast.Assign) and any(getattr(t, "id", None) == name for t in n.targets))
    return frozenset(ast.literal_eval(node.value.args[0]))


def test_non_container_kinds_match_the_gateway_container_validator(tf):
    gateway = _frozenset_literal("apps/orchestrator-gateway/developer_agent/validators/container.py", "NON_CONTAINER_KINDS")
    assert tf.NON_CONTAINER_KINDS == gateway == {"gce-bastion", "gce-worker"}


def test_bastion_only_workload_with_topology_builds_nothing(deploy_tf, tmp_path):
    files = {"main.tf": BASTION_TF, "infra/workload/topology.json": _topology(**{"ops-bastion": "gce-bastion"}),
             **BASTION_APP}
    build = MagicMock(return_value=False)
    res = _deploy(deploy_tf, tmp_path, files, build=build)
    build.assert_not_called()
    assert res.get("error_class") != "BUILD_CONTRACT" and "BUILD." not in str(res.get("error") or "")
    _assert_untouched(tmp_path / "ws", BASTION_APP, "apps/ops-bastion")


def test_bastion_only_without_topology_keeps_the_legacy_parsed_hcl_path(deploy_tf, tmp_path):
    """Documents the topology-free legacy behavior: parsed HCL declares compute, so the build runs and fails typed."""
    res = _deploy(deploy_tf, tmp_path, {"main.tf": BASTION_TF, **BASTION_APP})
    assert res["error_class"] == "BUILD_CONTRACT"
    assert res["error"].startswith("BUILD.ENTRYPOINT_MISSING: apps/ops-bastion ")


def test_cloudrun_plus_gce_worker_builds_api_and_leaves_worker_untouched(tf, tmp_path):
    ws = tmp_path / "ws"
    _write(ws, {"main.tf": COMPUTE_TF, **API_APP, **WORKER_APP,
                "infra/workload/topology.json": _topology(api="cloudrun", **{"gce-batch-worker": "gce-worker"})})
    svc = _svc(tf, tmp_path / "base")
    ok, staged = _build_until_staging(tf, svc, ws)
    assert staged, svc._last_build_error
    _assert_untouched(ws, WORKER_APP, "apps/gce-batch-worker")


def test_cloudrun_service_is_still_checked_next_to_a_gce_worker(tf, tmp_path):
    ws = tmp_path / "ws"
    _write(ws, {"main.tf": COMPUTE_TF, "apps/api/requirements.txt": "fastapi\n", **WORKER_APP,
                "infra/workload/topology.json": _topology(api="cloudrun", **{"gce-batch-worker": "gce-worker"})})
    svc = _svc(tf, tmp_path / "base")
    ok, staged = _build_until_staging(tf, svc, ws)
    assert ok is False and not staged
    assert svc._last_build_error.startswith("BUILD.ENTRYPOINT_MISSING: apps/api ")


def test_gce_worker_shipping_main_py_gets_no_procfile(tf, tmp_path):
    """Gate A 05 shape: the worker has its own main.py; it used to get a Procfile and an image nobody runs."""
    worker = {"apps/gce_worker/main.py": "print('job')\n", "apps/gce_worker/requirements.txt": "requests\n"}
    ws = tmp_path / "ws"
    _write(ws, {"main.tf": COMPUTE_TF, **API_APP, **worker,
                "infra/workload/topology.json": _topology(api="cloudrun", gce_worker="gce-worker")})
    svc = _svc(tf, tmp_path / "base")
    ok, staged = _build_until_staging(tf, svc, ws)
    assert staged, svc._last_build_error
    _assert_untouched(ws, worker, "apps/gce_worker")


def test_workspace_service_kinds_reads_the_topology(tf, tmp_path):
    kinds = {"api": "cloudrun", "gce-batch-worker": "gce-worker"}
    assert tf.workspace_service_kinds(_ws_tf(tmp_path / "a", {"infra/workload/topology.json": _topology(**kinds)})) == kinds
    assert tf.workspace_service_kinds(_ws_tf(tmp_path / "b", {"topology.json": _topology(**kinds)})) == kinds
    assert tf.workspace_service_kinds(_ws_tf(tmp_path / "c", {"main.tf": FOUNDATION_TF})) is None
    assert tf.workspace_service_kinds(_ws_tf(tmp_path / "d", {"topology.json": '{"schema": "other", "intent": {}}'})) is None
    assert tf.vm_service_dir("gce_batch_worker", kinds) == "gce-worker" and tf.vm_service_dir("api", kinds) is None


def test_other_build_failures_stop_typed_unattributed(deploy_tf, tmp_path):
    res = _deploy(deploy_tf, tmp_path, {"main.tf": COMPUTE_TF, "apps/api/main.py": "app = None\n"},
                  build=MagicMock(return_value=False))
    # DEPLOY-FAILURE-OWNER-ROUTER: a container build gives no typed owner -> UNKNOWN, operator stop; the build's own
    # text is kept after the class (it is no longer sent to the developer)
    assert res["status"] == "FAILED" and res["error_class"] == "DEPLOY_FAILURE_UNATTRIBUTED"
    assert res["operator_required"] is True and res["failure_route"]["phase"] == "build"
    assert "Engine error: Cloud Buildpack compilation failed for workload 'fd4ae-app'" in res["error"]
