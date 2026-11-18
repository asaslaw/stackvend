"""Step 2 S2-A A6 (register HS-09): V3c container contract replaces the HB-29 Procfile overwrite and /health
injection (gateway `enforce_container_contract` and the verifier twin). Exact parsers only (Procfile grammar, shlex,
ast). A missing Procfile is repaired by the persona that wrote the service (RepairTask.creates). Fakes stand in for the
LLM and for `tofu validate`; no network, no credentials."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import os
import sys

import pytest
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; OPEN-MODEL-SETTINGS)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent.repair_loop import Assembled, LoopContext, RepairLoop, render_repair_prompt  # noqa: E402
from developer_agent.validators import ValidationContext  # noqa: E402
from developer_agent.validators.base import ValidatorStack  # noqa: E402
from developer_agent.validators.container import (ContainerContractValidator,  # noqa: E402
                                                  MigrationInvocationValidator, is_port_ref, parse_command)
from developer_agent.validators.step1 import build_step1_stack  # noqa: E402
from shared.artifact_ownership import Ownership  # noqa: E402
from shared.diagnostics import AssemblyRecord, MemoryLedgerStore  # noqa: E402
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402

FASTAPI = 'from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get("/health")\ndef health():\n    return {"ok": True}\n'
FASTAPI_NO_HEALTH = 'from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get("/")\ndef root():\n    return {}\n'
WEB = "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n"


def _cloudrun(svc="api", extra=""):
    """A root-module compute-cloudrun block deploying `svc` (its startup probe calls health_check_path)."""
    return {"infra/workload/main.tf": f'module "compute" {{\n  source       = "../modules/compute-cloudrun"\n'
                                      f'  service_name = "{svc}"\n{extra}}}\n'}


def _ctx(files, llm=None):
    llm = set(files) if llm is None else set(llm)
    return ValidationContext.build(files, ownership=lambda p: Ownership.LLM_AUTHORED if p in llm
                                   else Ownership.PLATFORM_RENDERED, draft={k: files[k] for k in llm if k in files})


def _codes(files, llm=None):
    return sorted((d.code, d.file) for d in ContainerContractValidator().validate(_ctx(files, llm)))


# ------------------------------------------------------------------------------------------------ Do No Harm
@pytest.mark.parametrize("procfile", [WEB, "web: uvicorn main:app --host 0.0.0.0 --port ${PORT:-8080}\n",
                                      "web: uvicorn main:app --port=${PORT}\n",
                                      "web: python -m uvicorn main:app --host 0.0.0.0 --port $PORT\n",
                                      "web: gunicorn -k uvicorn.workers.UvicornWorker main:app\n",
                                      "web: gunicorn --bind 0.0.0.0:$PORT main:app\n",
                                      "web: gunicorn -b :${PORT:-8080} main:app\n"])
def test_valid_service_has_no_diagnostic(procfile):
    assert _codes({"apps/api/main.py": FASTAPI, "apps/api/Procfile": procfile}) == []


def test_flask_route_and_router_files_count_as_health():
    flask = ('from flask import Flask\napp = Flask(__name__)\n\n@app.route("/health")\ndef h():\n    return "ok"\n')
    assert _codes({"apps/w/app.py": flask, "apps/w/Procfile": "web: gunicorn app:app\n"}) == []
    router = 'from fastapi import APIRouter\nrouter = APIRouter()\n\n@router.get("/health")\ndef h():\n    return {}\n'
    assert _codes({"apps/api/main.py": FASTAPI_NO_HEALTH, "apps/api/routes.py": router,
                   "apps/api/Procfile": WEB}) == []
    added = FASTAPI_NO_HEALTH + 'app.add_api_route("/health", root)\n'
    assert _codes({"apps/api/main.py": added, "apps/api/Procfile": WEB}) == []


def test_python_file_web_process_reading_port_is_valid():
    for main in ('import os\nimport uvicorn\nfrom fastapi import FastAPI\napp = FastAPI()\n@app.get("/health")\n'
                 'def h():\n    return {}\nuvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))\n',
                 'from os import getenv as g\nfrom flask import Flask\napp = Flask(__name__)\n@app.route("/health")\n'
                 'def h():\n    return "ok"\napp.run(port=int(g("PORT", "8080")))\n',
                 'import os as m\nfrom flask import Flask\napp = Flask(__name__)\n@app.route("/health")\ndef h():\n'
                 '    return "ok"\napp.run(port=int(m.environ["PORT"]))\n'):
        assert _codes({"apps/api/main.py": main, "apps/api/Procfile": "web: python main.py\n"}) == []


def test_worker_unknown_launcher_platform_and_node_services_are_not_judged():
    assert _codes({"apps/w/main.py": "print(1)\n", "apps/w/Procfile": "worker: python main.py\n"}) == []
    assert _codes({"apps/s/app.py": "x = 1\n", "apps/s/Procfile": "web: streamlit run app.py\n"}) == []
    # platform-synthesized stub service (no LLM .py file) is out of scope
    assert _codes({"apps/stub/main.py": FASTAPI_NO_HEALTH}, llm=()) == []
    # a Node service has no .py file
    assert _codes({"apps/n/package.json": "{}", "apps/n/server.js": "x"}) == []
    # a star import keeps the attribute set open (never guessed)
    assert _codes({"apps/api/main.py": "from app_impl import *\n", "apps/api/app_impl.py": FASTAPI,
                   "apps/api/Procfile": WEB}) == []


# ------------------------------------------------------------------------------------------------ positives
def test_missing_procfile_is_entrypoint_missing_on_the_missing_path():
    assert _codes({"apps/api/main.py": FASTAPI}) == [("CONTAINER.ENTRYPOINT_MISSING", "apps/api/Procfile")]


@pytest.mark.parametrize("procfile", ["web: uvicorn apps.api.main:app --host 0.0.0.0 --port $PORT\n",
                                      "web: python apps/api/main.py\n", "web: uvicorn main:application --port $PORT\n",
                                      "# only a comment\n", "web: uvicorn 'main:app\n"])
def test_unresolvable_entrypoint(procfile):
    assert _codes({"apps/api/main.py": FASTAPI, "apps/api/Procfile": procfile}) == [
        ("CONTAINER.ENTRYPOINT_MISSING", "apps/api/Procfile")]


@pytest.mark.parametrize("procfile", ["web: uvicorn main:app --host 0.0.0.0 --port 8080\n",
                                      "web: uvicorn main:app\n", "web: hypercorn main:app\n",
                                      "web: gunicorn --bind 0.0.0.0:8080 main:app\n"])
def test_port_not_bound(procfile):
    assert _codes({"apps/api/main.py": FASTAPI, "apps/api/Procfile": procfile}) == [
        ("CONTAINER.PORT_NOT_BOUND", "apps/api/Procfile")]


def test_python_web_file_without_port_read_and_missing_health():
    main = 'import os\nfrom flask import Flask\napp = Flask(__name__)\nconfig = {}\napp.run(port=config.get("PORT"))\n'
    assert _codes({"apps/api/main.py": main, "apps/api/Procfile": "web: python main.py\n", **_cloudrun()}) == [
        ("CONTAINER.HEALTH_ROUTE_MISSING", "apps/api/main.py"), ("CONTAINER.PORT_NOT_BOUND", "apps/api/main.py")]


def test_health_text_in_a_comment_or_string_is_not_a_route():
    # substring tombstone: the deleted healer's regex accepted `def health_check`; only a real route counts now
    main = FASTAPI_NO_HEALTH + '# @app.get("/health")\nNOTE = \'@app.get("/health")\'\n\ndef health_check():\n    return 1\n'
    assert _codes({"apps/api/main.py": main, "apps/api/Procfile": WEB, **_cloudrun()}) == [
        ("CONTAINER.HEALTH_ROUTE_MISSING", "apps/api/main.py")]


def test_port_ref_grammar_is_exact():
    assert all(is_port_ref(t) for t in ("$PORT", "${PORT}", "${PORT:-8080}"))
    assert not any(is_port_ref(t) for t in ("8080", "$PORTX", "${PORT:-x}", "${PORT", "$port", "${HOSTPORT}"))
    assert parse_command(["uvicorn", "--host", "main:app", "x:y"]).target == "x:y"   # option value never the target


def test_migration_check_is_blocking_and_exact():
    # HS-40 (owner 10-19): blocking; the rule itself is unchanged (exact `alembic upgrade` argv pair in any process)
    files = {"apps/api/main.py": FASTAPI, "apps/api/alembic.ini": "[alembic]\n", "apps/api/Procfile": WEB}
    got = MigrationInvocationValidator().validate(_ctx(files))
    assert [(d.code, d.file, d.severity) for d in got] == [
        ("CONTAINER.MIGRATION_NOT_INVOKED", "apps/api/Procfile", "error")]
    files["apps/api/Procfile"] = WEB + "release: alembic upgrade head\n"   # HS-40 RT A2: release never runs
    assert [d.code for d in MigrationInvocationValidator().validate(_ctx(files))] == ["CONTAINER.MIGRATION_NOT_INVOKED"]
    files["apps/api/Procfile"] = "web: alembic upgrade head && uvicorn main:app --host 0.0.0.0 --port $PORT\n"
    assert MigrationInvocationValidator().validate(_ctx(files)) == []
    stack = build_step1_stack(validate_client=None, verifier_factory=None)
    assert stack.mode_of("V3c-migration") == "blocking"


# ------------------------------------------------------------------------------------------------ repair: create
class Persona:
    def __init__(self, *responses):
        self.responses, self.tasks = list(responses), []

    def __call__(self, task):
        self.tasks.append(task)
        return {"files": self.responses.pop(0) if self.responses else {}, "envelope_ok": True, "model": "m",
                "tokens_in": 10, "tokens_out": 10, "tokens_thoughts": 0}


def _loop(persona, llm_paths):
    st = ValidatorStack()
    st.register(ContainerContractValidator(), "blocking")

    def assemble(d):
        return Assembled(tree=dict(d), record=AssemblyRecord(), assembled_root={})
    return LoopContext(trace_id="t1", product_id="shop", assemble=assemble, stack=st,
                       ledger_store=MemoryLedgerStore(), settings=HallucinationStackSettings(),
                       attribution={p: "backend_worker" for p in llm_paths}, llm_draft_paths=set(llm_paths),
                       preexisting=set(), repair_fn=persona, model="m", available_providers=["google"])


def test_missing_procfile_is_created_by_the_service_persona():
    persona = Persona({"apps/api/Procfile": WEB})
    ctx = _loop(persona, {"apps/api/main.py"})
    tree, report = RepairLoop(ctx).run({"apps/api/main.py": FASTAPI})
    assert report.status == "PASS" and tree["apps/api/Procfile"] == WEB
    t = persona.tasks[0]
    assert t.persona == "backend_worker" and t.creates == ["apps/api/Procfile"]
    assert t.files_to_fix == {"apps/api/Procfile": ""}
    assert "CREATE (exception" in t.prompt()
    assert ctx.attribution["apps/api/Procfile"] == "backend_worker"


def test_create_is_never_offered_for_a_platform_only_service_and_prompts_without_creates_are_unchanged():
    from developer_agent.repair_loop import Router
    persona = Persona()
    ctx = _loop(persona, set())
    asm = Assembled(tree={"apps/stub/main.py": FASTAPI}, record=AssemblyRecord())
    from shared.diagnostics import Diagnostic, ErrorClass
    d = Diagnostic(tool="container", code="CONTAINER.ENTRYPOINT_MISSING", severity="error", file="apps/stub/Procfile",
                   message="m", source="precommit")
    assert Router(ctx, {}, asm).route(d).error_class is ErrorClass.PLATFORM_DEFECT
    from developer_agent.repair_loop import RepairTask
    t = RepairTask(persona="p", files_to_fix={"a.py": "x"}, diagnostics=[], read_only_context={}, iteration=1,
                   remaining_iterations=1, feedback="", max_output_tokens=4096)
    assert "CREATE" not in render_repair_prompt(t)


# ------------------------------------------------------------------------------------------------ tombstones
def _func_src(path, name):
    tree = ast.parse(open(os.path.join(REPO_ROOT, path)).read())
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(open(os.path.join(REPO_ROOT, path)).read(), node)
    return None


def test_hb29_branches_are_gone_and_kept_branches_remain():
    gw = _func_src("apps/orchestrator-gateway/developer_agent/handler.py", "enforce_container_contract")
    # FD-55 W5 (G23): the verifier twin is deleted; the developer stage's rule is the one container contract
    assert _func_src("apps/orchestrator-gateway/gatekeeper_agent/verifier.py", "enforce_container_contracts") is None
    for src in (gw,):
        tree = ast.parse(src)
        consts = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
        assert not any(c.endswith("/Procfile") or "Procfile" == c for c in consts)
        assert not any("uvicorn main:app" in c for c in consts)
        assert "3.13\n" in consts                               # .python-version pin kept
        names = {n.attr if isinstance(n, ast.Attribute) else getattr(n, "id", None) for n in ast.walk(tree)}
        assert "ensure_health_check_endpoint" not in names and "_find_fastapi_instantiation_end" not in names
    assert "standardize_requirements" in gw and ".gitkeep" in gw   # HB-28 and the static scaffold kept
    assert _func_src("apps/orchestrator-gateway/developer_agent/handler.py", "ensure_health_check_endpoint") is None


# ------------------------------------------------------------------------------------------------ FP review fixes (G-A)
K8S = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: stream-processor
spec:
  template:
    spec:
      containers:
      - name: stream-processor
        livenessProbe:
          httpGet:
            path: /healthz
        readinessProbe:
          httpGet:
            path: /ready
"""


def test_kubernetes_workload_uses_its_own_probe_paths():
    # G-A FP review (04-r1/04-r2/05-r1): a GKE service is probed on its manifest's paths, not on /health
    main = FASTAPI_NO_HEALTH + '\n@app.get("/healthz")\ndef hz():\n    return {}\n'
    llm = {"apps/stream-processor/main.py", "apps/stream-processor/Procfile"}
    files = {"apps/stream-processor/main.py": main, "apps/stream-processor/Procfile": WEB,
             "infra/workload/k8s/deployment.yaml": K8S}
    assert _codes(files, llm=llm) == [("CONTAINER.HEALTH_ROUTE_MISSING", "apps/stream-processor/main.py")]  # /ready
    files["apps/stream-processor/main.py"] = main + '\n@app.get("/ready")\ndef rd():\n    return {}\n'
    assert _codes(files, llm=llm) == []


def test_router_prefix_and_shared_library_dirs():
    # G-A FP review: APIRouter(prefix="/health") + @router.get("") serves /health; a library dir (02-r2 `common`,
    # no entrypoint) is not a deployed service
    health = ('from fastapi import APIRouter\nrouter = APIRouter(prefix="/health")\n\n@router.get("")\n'
              'def h():\n    return {}\n')
    assert _codes({"apps/api/main.py": FASTAPI_NO_HEALTH, "apps/api/api/health.py": health,
                   "apps/api/Procfile": WEB}) == []
    only_sub = health.replace('@router.get("")', '@router.get("/live")')
    assert _codes({"apps/api/main.py": FASTAPI_NO_HEALTH, "apps/api/api/health.py": only_sub,
                   "apps/api/Procfile": WEB, **_cloudrun()}) == [("CONTAINER.HEALTH_ROUTE_MISSING", "apps/api/main.py")]
    assert _codes({"apps/common/util.py": "x = 1\n", "apps/api/main.py": FASTAPI, "apps/api/Procfile": WEB}) == []


# ------------------------------------------------------------------------------------------------ code RT F2 (FP fixes)
HEALTH_ROUTER = 'from fastapi import APIRouter\nrouter = APIRouter()\n\n@router.get("")\ndef h():\n    return {}\n'


@pytest.mark.parametrize("main_tail, extra", [
    # (a) prefix given at include time, router imported from a service module (adv.py shape a)
    ('from routers.health import router\napp.include_router(router, prefix="/health")\n', {}),
    ('from routers.health import router as hr\napp.include_router(hr, prefix="/health")\n', {}),
    ('from routers import health\napp.include_router(health.router, prefix="/health")\n', {}),
    ('import routers.health as h\napp.include_router(h.router, prefix="/health")\n', {}),
    ('from .routers.health import router\napp.include_router(router, prefix="/health")\n', {}),
])
def test_include_router_prefix_is_resolved_one_level(main_tail, extra):
    files = {"apps/api/main.py": FASTAPI_NO_HEALTH + main_tail, "apps/api/routers/health.py": HEALTH_ROUTER,
             "apps/api/routers/__init__.py": "", "apps/api/Procfile": WEB, **_cloudrun(), **extra}
    assert _codes(files) == []


def test_include_router_positive_and_not_judged_shapes():
    base = {"apps/api/routers/health.py": HEALTH_ROUTER, "apps/api/Procfile": WEB, **_cloudrun()}
    # an include under /health/live serves /health/live only: /health is still missing (true positive kept)
    files = dict(base, **{"apps/api/main.py": FASTAPI_NO_HEALTH + 'from routers.health import router\n'
                                              'app.include_router(router, prefix="/health/live")\n'})
    assert _codes(files) == [("CONTAINER.HEALTH_ROUTE_MISSING", "apps/api/main.py")]
    # a non-literal prefix, a router from a library, or an include onto a router -> not judged (never guessed)
    for tail in ('from routers.health import router\nP = "/x"\napp.include_router(router, prefix=P)\n',
                 'from fastapi_health import health_router\napp.include_router(health_router)\n',
                 'from fastapi import APIRouter\nfrom routers.health import router\nouter = APIRouter()\n'
                 'outer.include_router(router, prefix="/health")\napp.include_router(outer)\n'):
        assert _codes(dict(base, **{"apps/api/main.py": FASTAPI_NO_HEALTH + tail})) == [], tail


@pytest.mark.parametrize("config", [
    'from pydantic_settings import BaseSettings\nclass S(BaseSettings):\n    port: int = 8080\nsettings = S()\n',
    'from pydantic_settings import BaseSettings\nfrom pydantic import Field\nclass S(BaseSettings):\n'
    '    listen: int = Field(8080, alias="PORT")\nsettings = S()\n',
    'import pydantic_settings\nclass Base(pydantic_settings.BaseSettings):\n    pass\nclass S(Base):\n'
    '    PORT: int = 8080\nsettings = S()\n',
    'import os\nPORT = int(os.environ.get("PORT", "8080"))\nclass _S:\n    port = PORT\nsettings = _S()\n',
])
def test_port_read_anywhere_in_the_service_counts(config):
    main = ('import uvicorn\nfrom config import settings\n' + FASTAPI +
            'if __name__ == "__main__":\n    uvicorn.run(app, host="0.0.0.0", port=settings.port)\n')
    files = {"apps/api/main.py": main, "apps/api/config.py": config, "apps/api/Procfile": "web: python main.py\n"}
    assert _codes(files) == []


def test_settings_port_with_a_prefix_or_unresolved_keys():
    main = 'import uvicorn\nfrom config import settings\n' + FASTAPI + 'uvicorn.run(app, port=settings.port)\n'
    prefixed = ('from pydantic_settings import BaseSettings, SettingsConfigDict\nclass S(BaseSettings):\n'
                '    model_config = SettingsConfigDict(env_prefix="APP_")\n    port: int = 8080\nsettings = S()\n')
    files = {"apps/api/main.py": main, "apps/api/config.py": prefixed, "apps/api/Procfile": "web: python main.py\n"}
    assert _codes(files) == [("CONTAINER.PORT_NOT_BOUND", "apps/api/main.py")]     # reads APP_PORT, not PORT
    files["apps/api/config.py"] = prefixed.replace('env_prefix="APP_"', "env_prefix=PREFIX")
    assert _codes(files) == []                                                       # not literal -> not judged


GKE_NAME_MISS = """apiVersion: apps/v1
kind: Deployment
metadata:
  name: stream-processor-deploy
spec:
  template:
    spec:
      containers:
      - name: app
        livenessProbe:
          httpGet:
            path: /healthz
"""


def test_health_requirement_comes_only_from_the_probe_that_calls_it():
    llm = {"apps/stream-processor/main.py", "apps/stream-processor/Procfile"}
    gke = {"apps/stream-processor/main.py": FASTAPI_NO_HEALTH + '@app.get("/healthz")\ndef hz():\n    return {}\n',
           "apps/stream-processor/Procfile": WEB, "infra/workload/k8s/deploy.yaml": GKE_NAME_MISS}
    assert _codes(gke, llm=llm) == []                                     # name miss: never the Cloud Run default
    no_probe = dict(gke, **{"infra/workload/k8s/deploy.yaml": K8S.split("        livenessProbe")[0]})
    assert _codes(no_probe, llm=llm) == []                                # a GKE workload without probes
    assert _codes({"apps/api/main.py": FASTAPI_NO_HEALTH, "apps/api/Procfile": WEB}) == []   # no probe known
    # the Cloud Run module's literal health_check_path is the requirement
    livez = _cloudrun(extra='  health_check_path = "/livez"\n')
    assert _codes({"apps/api/main.py": FASTAPI, "apps/api/Procfile": WEB, **livez}, llm={"apps/api/main.py"}) == [
        ("CONTAINER.HEALTH_ROUTE_MISSING", "apps/api/main.py")]
    served = FASTAPI_NO_HEALTH + '@app.get("/livez")\ndef lz():\n    return {}\n'
    assert _codes({"apps/api/main.py": served, "apps/api/Procfile": WEB, **livez}, llm={"apps/api/main.py"}) == []
    # a non-literal health_check_path, or a module for another service -> not judged
    for mod in (_cloudrun(extra="  health_check_path = var.hp\n"), _cloudrun(svc="other")):
        assert _codes({"apps/api/main.py": FASTAPI_NO_HEALTH, "apps/api/Procfile": WEB, **mod},
                      llm={"apps/api/main.py"}) == []
    # a module whose source is not compute-cloudrun does not probe
    ev = {"infra/workload/main.tf": 'module "compute" {\n  source = "../modules/compute-event-worker"\n'
                                    '  service_name = "api"\n}\n'}
    assert _codes({"apps/api/main.py": FASTAPI_NO_HEALTH, "apps/api/Procfile": WEB, **ev},
                  llm={"apps/api/main.py"}) == []


@pytest.mark.parametrize("main", [
    'from fastapi import FastAPI\ntry:\n    from factory import make\nexcept ImportError:\n    app = FastAPI()\n'
    'else:\n    app = make()\n@app.get("/health")\ndef h():\n    return {}\n',
    'from fastapi import FastAPI\nif True:\n    app = FastAPI()\n@app.get("/health")\ndef h():\n    return {}\n',
    'from fastapi import FastAPI\nwith open(__file__):\n    app = FastAPI()\n@app.get("/health")\ndef h():\n'
    '    return {}\n',
])
def test_app_bound_inside_module_level_try_if_with_is_found(main):
    # code RT F5 / mutation M8: top_level_names must look into module-level if/try/with bodies
    assert _codes({"apps/api/main.py": main, "apps/api/Procfile": WEB, **_cloudrun()}) == []


def test_app_bound_in_a_module_level_for_loop_is_reported_not_guessed():
    # adv.py shape e: a `for`-bound app is outside the exact grammar -> ENTRYPOINT_MISSING (negligible in LLM output)
    main = 'from fastapi import FastAPI\nfor _ in range(1):\n    app = FastAPI()\n'
    assert _codes({"apps/api/main.py": main, "apps/api/Procfile": WEB}) == [
        ("CONTAINER.ENTRYPOINT_MISSING", "apps/api/Procfile")]


# ------------------------------------------------------------------------------------------------ code RT F5 (M4, M12)
def _create_diag(path):
    from shared.diagnostics import Diagnostic
    return Diagnostic(tool="container", code="CONTAINER.ENTRYPOINT_MISSING", severity="error", file=path,
                      message="m", source="precommit")


@pytest.mark.parametrize("path", ["apps/../Procfile", "apps/api/../../Procfile", "/apps/api/Procfile",
                                  "apps/.git/Procfile", "apps/api/sub/Procfile", "infra/api/Procfile", "apps//Procfile"])
def test_route_create_rejects_unsafe_or_non_service_paths(path):
    # mutation M4 (dropping the apps/<svc>/<name> guard) must fail here; `apps/../x/main.py` is the adv.py shape
    from developer_agent.repair_loop import Router
    from shared.diagnostics import ErrorClass
    llm = {"apps/../x/main.py", "apps/api/main.py", "apps/.git/main.py", "apps/api/sub/main.py"}
    ctx = _loop(Persona(), llm)
    asm = Assembled(tree={p: FASTAPI for p in llm}, record=AssemblyRecord())
    r = Router(ctx, {p: FASTAPI for p in llm}, asm).route(_create_diag(path))
    assert r.error_class is ErrorClass.PLATFORM_DEFECT


def test_route_create_accepts_the_exact_service_procfile():
    from developer_agent.repair_loop import Router
    from shared.diagnostics import ErrorClass
    ctx = _loop(Persona(), {"apps/api/main.py"})
    asm = Assembled(tree={"apps/api/main.py": FASTAPI}, record=AssemblyRecord())
    r = Router(ctx, {"apps/api/main.py": FASTAPI}, asm).route(_create_diag("apps/api/Procfile"))
    assert r.error_class is ErrorClass.CODE_DEFECT and r.persona == "backend_worker"


def test_create_answered_under_a_different_key_is_an_out_of_scope_write():
    # mutation M12 (the _merge out-of-scope guard removed) must fail here: the persona may write exactly the offered
    # create key, never another new file
    persona = Persona({"apps/api/Procfile.txt": WEB}, {"apps/api/Procfile.txt": WEB})
    ctx = _loop(persona, {"apps/api/main.py"})
    ctx.settings = HallucinationStackSettings(repair_max_iterations_precommit=1)
    from shared.diagnostics import StageError
    with pytest.raises(StageError):
        RepairLoop(ctx).run({"apps/api/main.py": FASTAPI})
    assert ctx.events and all(e.reject_reason == "OUT_OF_SCOPE_WRITE" for e in ctx.events)
