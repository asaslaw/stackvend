"""FD55-W5c-PLAN-FACTS (D1 of the W5c paired check, owner 11-08 "fix it"): the whole-service CREATE round is given the
planned service's typed facts, and a service that round wrote must serve the POST path its planned Pub/Sub push
delivers to (CONTAINER.PUSH_ROUTE_MISSING), or the run stops typed.

* Facts: kind, role, purpose, `GET /health`, the push paths, the env keys, all from the typed topology.
* The check fires on the paired check's wrong-path service; the finding goes to the ordinary repair; still unmet ->
  RepairBudgetExhausted, never a second CREATE round.
* Silent (Do No Harm): the right path, a registration that may serve it but cannot be read statically, a service with no
  planned push, a service the round did not write, no typed plan. Valid trees are unchanged and cost no call.
* A registration that cannot serve POST on the path says nothing, so a repair cannot clear the finding by adding one.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import)

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

from developer_agent.repair_loop import Assembled, LoopContext, RepairLoop  # noqa: E402
from developer_agent.validators.base import ValidationContext, ValidatorStack  # noqa: E402
from developer_agent.validators.container import (ENTRYPOINT_CODE, PUSH_ROUTE_CODE,  # noqa: E402
                                                  PUSH_UNVERIFIED_CODE, ContainerContractValidator,
                                                  PlannedServiceCodeValidator, planned_push_route_findings,
                                                  planned_push_route_unverified, planned_service_facts,
                                                  post_route_state)
from shared.artifact_ownership import Ownership  # noqa: E402
from shared.diagnostics import AssemblyRecord, MemoryLedgerStore, RepairBudgetExhausted, StageError  # noqa: E402
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402
from shared.service_topology import validate_service_topology  # noqa: E402

PID = "shop"
SVC = "factory-worker"
PUSH = "/api/v1/factory/process-order"
MAIN = f"apps/{SVC}/main.py"
PROCFILE = f"apps/{SVC}/Procfile"
WEB = "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n"
FASTAPI = 'from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get("/health")\ndef health():\n    return {"ok": True}\n'
# the shape of the service all four paid runs of the paired check wrote: the system-prompt example's path
WRONG = FASTAPI + '\n\n@app.post("/api/v1/tasks/process")\ndef process_task():\n    return {"status": "ok"}\n'
RIGHT = FASTAPI + f'\n\n@app.post("{PUSH}")\ndef process_task():\n    return {{"status": "ok"}}\n'
DRAFT = {"apps/storefront/main.py": FASTAPI, "apps/storefront/Procfile": WEB}


def _service(main):
    return {MAIN: main, f"apps/{SVC}/requirements.txt": "fastapi\nuvicorn\n", PROCFILE: WEB}


def _topology(**kw):
    raw = {
        "services": [
            {"name": "storefront", "kind": "cloudrun", "purpose": "The public storefront."},
            {"name": SVC, "kind": "cloudrun", "purpose": "Fulfils orders and archives invoices."},
        ],
        "primary_service": "storefront",
        "edges": [],
        "resources": [
            {"type": "google_pubsub_topic", "logical_name": "orders_placed",
             "consumers": [{"service": "storefront", "env_key": "ORDERS_TOPIC"}]},
            {"type": "google_storage_bucket", "logical_name": "invoices",
             "consumers": [{"service": SVC, "env_key": "INVOICES_BUCKET"}]},
            {"type": "google_firestore_database", "logical_name": "default",
             "consumers": [{"service": SVC, "env_key": "FIRESTORE_DATABASE"}]},
        ],
        "pushes": [{"topic": "orders_placed", "service": SVC, "path": PUSH}],
    }
    raw.update(kw)
    vt, diags = validate_service_topology(raw, product_id=PID)
    assert vt is not None, [d.code for d in diags]
    return vt


def _answer(files):
    return {"files": files, "envelope_ok": True, "finish_reason": "STOP", "model": "m", "tokens_in": 10,
            "tokens_out": 10}


def _ctx(answers, *, topology, draft=DRAFT, planned=(SVC,), settings=None):
    calls = []
    st = ValidatorStack()
    st.register(PlannedServiceCodeValidator(planned, topology), "blocking")

    def assemble(d):
        return Assembled(tree=dict(d), record=AssemblyRecord(), assembled_root={})

    def repair(task):
        calls.append(task)
        return answers.pop(0) if answers else _answer({})
    ctx = LoopContext(trace_id="t1", product_id=PID, assemble=assemble, stack=st, ledger_store=MemoryLedgerStore(),
                      settings=settings or HallucinationStackSettings(),
                      attribution={p: "backend_worker" for p in draft}, llm_draft_paths=set(draft), preexisting=set(),
                      repair_fn=repair, model="m", available_providers=["google"], topology=topology)
    return ctx, calls


# ------------------------------------------------------------------------------------------------ the round's facts
def test_the_create_round_is_given_the_plan_facts():
    ctx, calls = _ctx([_answer(_service(RIGHT))], topology=_topology())
    tree, report = RepairLoop(ctx).run(dict(DRAFT))
    assert report.status == "PASS" and len(calls) == 1 and tree[MAIN] == RIGHT
    hint = calls[0].diagnostics[0]["hint"]
    prompt = calls[0].prompt()
    for fact in (f"POST {PUSH}", "GET /health", "INVOICES_BUCKET", "FIRESTORE_DATABASE", "orders_placed",
                 "Fulfils orders and archives invoices.", "cloudrun", "secondary"):
        assert fact in hint and fact in prompt, fact
    assert "ORDERS_TOPIC" not in hint      # another service's key
    assert "only paths accepted" in hint   # the whole-service instruction stays


def test_facts_of_a_service_with_no_planned_push_name_only_health_and_env():
    facts = planned_service_facts(_topology(pushes=[]), SVC, {})
    assert facts["must_serve"] == ["GET /health"] and "pubsub_pushes" not in facts
    assert facts["env_keys"] == ["FIRESTORE_DATABASE", "INVOICES_BUCKET"]


@pytest.mark.parametrize("topology,svc", [(None, SVC), (_topology(), "not-planned")])
def test_no_facts_when_the_plan_knows_nothing(topology, svc):
    assert planned_service_facts(topology, svc, {}) == {}


def _module(extra=""):
    return {"infra/workload/main.tf": f'module "compute_w" {{\n  source       = "../modules/compute-cloudrun"\n'
                                      f'  service_name = "{SVC}"\n{extra}}}\n'}


def test_without_a_typed_plan_there_are_no_facts_even_with_a_module_naming_the_service():
    assert planned_service_facts(None, SVC, _module('  health_check_path = "/ready"\n')) == {}


@pytest.mark.parametrize("files,expected", [
    (_module('  health_check_path = "/ready"\n'), ["GET /ready"]),   # the module's own literal path
    (_module(), ["GET /health"]),                                     # the module's default
    ({}, ["GET /health"]),                                            # no module: the Cloud Run default
])
def test_facts_take_the_health_path_from_the_module(files, expected):
    assert planned_service_facts(_topology(pushes=[]), SVC, files)["must_serve"] == expected


def test_facts_leave_out_a_non_literal_health_path():
    assert "must_serve" not in planned_service_facts(_topology(pushes=[]), SVC, _module("  health_check_path = var.h\n"))


def test_facts_add_the_typed_only_env_keys_on_the_typed_path_only():
    vt = _topology(pushes=[], resources=[
        {"type": "google_alloydb_instance", "logical_name": "ledger",
         "consumers": [{"service": SVC, "env_key": "LEDGER_DB_HOST", "attribute": "ip_address"}]}])
    assert vt.typed_only_env_keys(SVC) == ("LEDGER_PASSWORD_SECRET_ID",)
    assert "LEDGER_PASSWORD_SECRET_ID" not in planned_service_facts(vt, SVC, {}).get("env_keys", [])
    assert "LEDGER_PASSWORD_SECRET_ID" in planned_service_facts(vt, SVC, {}, typed_intent=True)["env_keys"]


def test_without_a_typed_plan_the_hint_is_as_before_and_nothing_is_judged():
    ctx, calls = _ctx([_answer(_service(WRONG))], topology=None)
    tree, report = RepairLoop(ctx).run(dict(DRAFT))
    assert report.status == "PASS" and len(calls) == 1
    assert "PLAN FACTS" not in calls[0].diagnostics[0]["hint"]


def test_f2_the_round_may_use_the_per_call_cap_and_later_rounds_are_sized_as_usual():
    s = HallucinationStackSettings()
    ctx, calls = _ctx([_answer(_service(WRONG)), _answer({MAIN: RIGHT})], topology=_topology(), settings=s)
    RepairLoop(ctx).run(dict(DRAFT))
    assert calls[0].max_output_tokens == s.repair_max_output_tokens
    assert calls[1].max_output_tokens < s.repair_max_output_tokens


# ------------------------------------------------------------------------------------------------ the check, in the loop
def test_the_wrong_path_service_of_the_paired_check_is_a_finding_and_the_ordinary_repair_fixes_it():
    ctx, calls = _ctx([_answer(_service(WRONG)), _answer({MAIN: RIGHT})], topology=_topology())
    tree, report = RepairLoop(ctx).run(dict(DRAFT))
    assert report.status == "PASS" and tree[MAIN] == RIGHT and len(calls) == 2
    assert [(x["code"], x["file"]) for x in calls[0].diagnostics] == [(ENTRYPOINT_CODE, PROCFILE)]
    second = calls[1]
    assert [(x["code"], x["file"]) for x in second.diagnostics] == [(PUSH_ROUTE_CODE, MAIN)]
    assert second.persona == "developer" and second.creates == [] and list(second.files_to_fix) == [MAIN]
    assert f"POST {PUSH}" in second.diagnostics[0]["message"] and f'@app.post("{PUSH}")' in second.diagnostics[0]["hint"]
    assert all(e.accepted for e in ctx.events)


def test_still_unmet_is_the_typed_budget_stop_and_never_a_second_create_round():
    ctx, calls = _ctx([_answer(_service(WRONG))], topology=_topology())   # later answers change nothing
    with pytest.raises(RepairBudgetExhausted) as ei:
        RepairLoop(ctx).run(dict(DRAFT))
    assert ei.value.exhausted_reason == "ITERATIONS"
    assert sorted({d.code for d in ei.value.report.diagnostics if d.severity == "error"}) == [PUSH_ROUTE_CODE]
    assert len(calls) == HallucinationStackSettings().repair_max_iterations_precommit   # no round beyond the budget
    assert [t.creates != [] for t in calls] == [True] + [False] * (len(calls) - 1)


@pytest.mark.parametrize("unrelated", [
    '\n\n@app.get("/jobs/{id}")\ndef job(id):\n    return {}\n',
    '\nimport requests\nsession = requests.Session()\nsession.mount("https://", object())\n',
])
def test_a_repair_cannot_clear_the_finding_by_adding_something_unrelated(unrelated):
    ctx, calls = _ctx([_answer(_service(WRONG)), _answer({MAIN: WRONG + unrelated})], topology=_topology())
    with pytest.raises(RepairBudgetExhausted) as ei:
        RepairLoop(ctx).run(dict(DRAFT))
    assert sorted({d.code for d in ei.value.report.diagnostics if d.severity == "error"}) == [PUSH_ROUTE_CODE]
    assert len(calls) == HallucinationStackSettings().repair_max_iterations_precommit


def test_a_round_still_without_the_service_keeps_the_named_stop():
    ctx, calls = _ctx([_answer({f"apps/{SVC}/requirements.txt": "fastapi\n"})], topology=_topology())
    with pytest.raises(StageError) as ei:
        RepairLoop(ctx).run(dict(DRAFT))
    assert "planned service has no code" in str(ei.value) and len(calls) == 1


# ------------------------------------------------------------------------------------------------ Do No Harm
INCLUDED = ('from fastapi import FastAPI\nimport routes\n\napp = FastAPI()\n\n\n'   # a router this reader cannot resolve
            '@app.get("/health")\ndef health():\n    return {}\n\n\napp.include_router(routes.router)\n')
DYNAMIC = ('import os\nfrom fastapi import FastAPI\n\napp = FastAPI()\nPATH = os.environ["P"]\n\n\n@app.get("/health")\n'
           'def health():\n    return {}\n\n\n@app.post(PATH)\ndef x():\n    return {}\n')
STDLIB = 'import os\nfrom http.server import HTTPServer\n\nPORT = os.environ["PORT"]\n'


@pytest.mark.parametrize("main", [RIGHT, INCLUDED, DYNAMIC])
def test_negative_right_path_and_unreadable_routes_are_silent(main):
    ctx, calls = _ctx([_answer(_service(main))], topology=_topology())
    tree, report = RepairLoop(ctx).run(dict(DRAFT))
    assert report.status == "PASS" and len(calls) == 1 and tree[MAIN] == main


@pytest.mark.parametrize("main,procfile", [(INCLUDED, WEB), (DYNAMIC, WEB), (STDLIB, "web: python main.py\n")])
def test_a_push_the_check_cannot_judge_is_recorded_report_only(main, procfile):
    files = dict(_service(main), **{PROCFILE: procfile})
    ctx, calls = _ctx([_answer(files)], topology=_topology())
    tree, report = RepairLoop(ctx).run(dict(DRAFT))
    assert report.status == "PASS" and len(calls) == 1 and tree[MAIN] == main   # never blocks, never repaired
    assert report.diagnostics == []
    assert [(d.code, d.severity, d.symbol, d.file) for d in report.report_only] == [
        (PUSH_UNVERIFIED_CODE, "warning", f"POST {PUSH}", MAIN)]
    assert PUSH in report.report_only[0].message and "orders_placed" in report.report_only[0].message


@pytest.mark.parametrize("main", [RIGHT, WRONG])
def test_negative_a_push_the_check_can_judge_is_not_unverified(main):
    assert planned_push_route_unverified(_vctx(_service(main)), _topology(), {SVC}) == []


def test_negative_the_blocking_list_never_carries_the_unverified_code():
    assert planned_push_route_findings(_vctx(_service(DYNAMIC)), _topology(), {SVC}) == []


@pytest.mark.parametrize("services,topology", [(set(), _topology()), ({SVC}, None), ({"storefront"}, _topology())])
def test_negative_unverified_out_of_scope_is_silent(services, topology):
    assert planned_push_route_unverified(_vctx(_service(DYNAMIC)), topology, services) == []


def test_negative_v3c_itself_never_reports_the_unverified_code():
    v = ContainerContractValidator(_topology())
    assert PUSH_UNVERIFIED_CODE not in {d.code for d in v.validate(_vctx(_service(DYNAMIC)))}


def test_negative_a_service_with_no_planned_push_is_silent():
    ctx, calls = _ctx([_answer(_service(WRONG))], topology=_topology(pushes=[]))
    tree, report = RepairLoop(ctx).run(dict(DRAFT))
    assert report.status == "PASS" and len(calls) == 1 and tree[MAIN] == WRONG


def test_negative_a_swarm_written_sibling_on_a_wrong_push_path_is_not_judged_when_a_round_ran():
    vt = _topology(resources=[
        {"type": "google_pubsub_topic", "logical_name": "orders_placed"},
        {"type": "google_pubsub_topic", "logical_name": "audit_events"},
    ], pushes=[{"topic": "orders_placed", "service": SVC, "path": PUSH},
               {"topic": "audit_events", "service": "storefront", "path": "/api/v1/audit"}])
    ctx, calls = _ctx([_answer(_service(RIGHT))], topology=vt)   # DRAFT's storefront does not serve /api/v1/audit
    tree, report = RepairLoop(ctx).run(dict(DRAFT))
    assert report.status == "PASS" and len(calls) == 1 and tree["apps/storefront/main.py"] == FASTAPI


def test_negative_a_service_the_round_did_not_write_is_not_judged():
    draft = dict(DRAFT, **_service(WRONG))    # the swarm wrote it: outside this check's scope
    ctx, calls = _ctx([], topology=_topology(), draft=draft)
    tree, report = RepairLoop(ctx).run(dict(draft))
    assert report.status == "PASS" and calls == [] and tree == draft


# ------------------------------------------------------------------------------------------------ the route reader
PATH_ = "/tasks/run"


def _files(main):
    return {MAIN: main}


FLASK_HEAD = 'from flask import Flask\n\napp = Flask(__name__)\n\n\n'
ROUTER_HEAD = 'from fastapi import APIRouter, FastAPI\n\napp = FastAPI()\n'
H = '\n\ndef h():\n    return {}\n'
STARLETTE = ('from starlette.applications import Starlette\nfrom starlette.routing import Host, Mount, Route\n\n'
             'def h(request):\n    return None\n\n\n')


@pytest.mark.parametrize("text", [
    FASTAPI + f'\n\n@app.post("{PATH_}")\ndef p():\n    return {{}}\n',
    FASTAPI + f'\n\n@app.api_route("{PATH_}", methods=["post", "PUT"])\ndef p():\n    return {{}}\n',
    FASTAPI + H + f'\n\napp.add_api_route("{PATH_}", h, methods=["POST"])\n',
    FLASK_HEAD + f'@app.route("{PATH_}", methods=("POST",))\ndef p():\n    return ""\n',
    FLASK_HEAD + f'def p():\n    return ""\n\n\napp.add_url_rule("{PATH_}", view_func=p, methods=["POST"])\n',
    STARLETTE + f'app = Starlette(routes=[Route("{PATH_}", h, methods=["POST"])])\n',
    ROUTER_HEAD + 'r = APIRouter(prefix="/tasks")\n\n\n@r.post("/run")\ndef p():\n    return {}\n\n\napp.include_router(r)\n',
    ROUTER_HEAD + 'r = APIRouter()\n\n\n@r.post("/run")\ndef p():\n    return {}\n\n\napp.include_router(r, prefix="/tasks")\n',
])
def test_post_route_state_true_when_a_route_serves_post_on_the_path(text):
    assert post_route_state(_files(text), SVC, PATH_) is True


@pytest.mark.parametrize("text", [
    FASTAPI,
    FASTAPI + '\n\n@app.post("/other")\ndef p():\n    return {}\n',
    FASTAPI + f'\n\n@app.get("{PATH_}")\ndef p():\n    return {{}}\n',                 # the path, not as POST
    FLASK_HEAD + f'@app.route("{PATH_}")\ndef p():\n    return ""\n',                  # Flask's default: GET only
    # F1: a route on a router that is never included (real POST 404)
    ROUTER_HEAD + 'r = APIRouter(prefix="/tasks")\n\n\n@r.post("/run")\ndef p():\n    return {}\n',
    ROUTER_HEAD + f'r = APIRouter()\n\n\ndef q():\n    return {{}}\n\n\nr.add_api_route("{PATH_}", q, methods=["POST"])\n',
    # F2: a trailing slash is a 307, a failed Pub/Sub delivery, whatever the method
    FASTAPI + f'\n\n@app.post("{PATH_}/")\ndef p():\n    return {{}}\n',
    FASTAPI + f'\n\n@app.get("{PATH_}/")\ndef p():\n    return {{}}\n',
    # F3: registrations that cannot serve POST on the path say nothing
    FASTAPI + '\n\n@app.get("/jobs/{id}")\ndef p(id):\n    return {}\n',
    FASTAPI + '\n\n@app.post("/jobs/{id}")\ndef p(id):\n    return {}\n',              # another literal first segment
    FASTAPI + '\n\n@app.post("/tasks/{a}/{b}")\ndef p(a, b):\n    return {}\n',        # another segment count
    FASTAPI + '\n\n@app.post("/{x}")\ndef p(x):\n    return {}\n',                      # a shorter template
    FASTAPI + '\n\n@app.get(PATH)\ndef p():\n    return {}\n',                         # any path, but GET
    FASTAPI + '\n\n@app.api_route("/{x:path}", methods=["GET"])\ndef p(x):\n    return {}\n',
    FASTAPI + H + '\n\napp.add_api_route("/health2", h)\n',                            # unknown methods, other path
    FASTAPI + '\n\n@app.api_route("/other", methods=METHODS)\ndef p():\n    return {}\n',
    STARLETTE + 'app = Starlette(routes=[Route("/health", h)])\n',
    FASTAPI + '\nimport requests\nrequests.Session().mount("https://", object())\n',
    FASTAPI + '\nimport requests\nsession = requests.Session()\nsession.mount("/", object())\n',
    FASTAPI + '\napp.mount("/static", object())\n',
    STARLETTE + 'app = Starlette(routes=[Mount("/static", h)])\n',
    FASTAPI + '\nimport requests\n\n\ndef call():\n    return requests.post("https://x", json={})\n',   # not a route
    ROUTER_HEAD + 'r = APIRouter(prefix="/other")\n\n\n@r.post("/run")\ndef p():\n    return {}\n\n\napp.include_router(r)\n',
])
def test_post_route_state_false_when_nothing_can_serve_post_on_the_path(text):
    assert post_route_state(_files(text), SVC, PATH_) is False


@pytest.mark.parametrize("text", [
    "def broken(:\n",                                                                  # does not parse
    STDLIB,                                                                            # no framework app (HR-1)
    FASTAPI + "\n\n@app.post(PATH)\ndef p():\n    return {}\n",                        # dynamic path
    FASTAPI + '\n\n@app.post("/tasks/{x}")\ndef p(x):\n    return {}\n',               # a template that may match
    FASTAPI + '\n\n@app.post("/{rest:path}")\ndef p(rest):\n    return {}\n',          # catch-all
    FLASK_HEAD + '@app.route("/tasks/<x>", methods=["POST"])\ndef p(x):\n    return ""\n',
    FLASK_HEAD + '@app.route("/<path:x>", methods=["POST"])\ndef p(x):\n    return ""\n',
    FASTAPI + f'\n\n@app.api_route("{PATH_}", methods=METHODS)\ndef p():\n    return {{}}\n',   # non-literal methods
    FASTAPI + f'\n\n@app.api_route("{PATH_}", **OPTS)\ndef p():\n    return {{}}\n',
    FASTAPI + H + f'\n\napp.add_api_route("{PATH_}", h)\n',                            # call form without methods
    FLASK_HEAD + 'from flask.views import MethodView\n\n\nclass V(MethodView):\n    pass\n\n\n'
                 f'app.add_url_rule("{PATH_}", view_func=V.as_view("v"))\n',
    STARLETTE + f'app = Starlette(routes=[Route("{PATH_}", h)])\n',
    # routers and sub-apps this reader cannot resolve
    FASTAPI + '\nimport routes\napp.include_router(routes.router)\n',
    ROUTER_HEAD + 'r = APIRouter(prefix=PREFIX)\n\n\n@r.post("/run")\ndef p():\n    return {}\n\n\napp.include_router(r)\n',
    ROUTER_HEAD + 'r = APIRouter()\n\n\n@r.post("/run")\ndef p():\n    return {}\n\n\napp.include_router(r, prefix=P)\n',
    ROUTER_HEAD + 'a = APIRouter()\nb = APIRouter()\na.include_router(b)\n',           # nested
    ROUTER_HEAD + 'r = APIRouter()\n\n\n@r.post("/run")\ndef p():\n    return {}\n\n\napp.include_router(r, **OPTS)\n',
    # an include onto an unknown or wrapped receiver is not resolved (real POST 200 on both)
    ROUTER_HEAD + 'parent = APIRouter(prefix="/tasks")\nr = APIRouter()\n\n\n@r.post("/run")\ndef p():\n    return {}\n\n\n'
                  'def wire(x):\n    x.include_router(r)\n\n\nwire(parent)\napp.include_router(parent)\n',
    'from fastapi import APIRouter, FastAPI\nimport extlib\n\napi = FastAPI()\napp = extlib.wrap(api)\n'
    'r = APIRouter(prefix="/tasks")\n\n\n@r.post("/run")\ndef p():\n    return {}\n\n\napp.include_router(r)\n',
    FASTAPI + '\napp.mount("/tasks", object())\n',
    FASTAPI + '\napp.mount("/", object())\n',
    FASTAPI + '\napp.mount(PREFIX, object())\n',
    STARLETTE + 'app = Starlette(routes=[Mount("/tasks", h)])\n',
    STARLETTE + 'app = Starlette(routes=[Host("x.example", h)])\n',
    FASTAPI + f'\nfrom fastapi.routing import APIRoute\nr = APIRoute("{PATH_}", object())\n',
    FLASK_HEAD + 'app.register_blueprint(bp)\n',
    FLASK_HEAD + 'from flask_restful import Api\napi = Api(app)\napi.add_resource(V, "/other")\n',
    FLASK_HEAD + 'from flask import Blueprint\nbp = Blueprint("b", __name__)\n',
    # F5: a route method as a plain value, a route decorator on a class
    FASTAPI + H + f'\n\napp.post("{PATH_}")(h)\n',
    FASTAPI + f'\npost = app.post\n\n\n@post("{PATH_}")\ndef p():\n    return {{}}\n',
    FLASK_HEAD + 'from flask_restx import Namespace, Resource\nns = Namespace("n")\n\n\n'
                 f'@ns.route("{PATH_}")\nclass R(Resource):\n    pass\n',
])
def test_post_route_state_none_when_it_cannot_be_decided(text):
    assert post_route_state(_files(text), SVC, PATH_) is None


def _vctx(files, owned=True):
    return ValidationContext.build(files, ownership=lambda _p: Ownership.LLM_AUTHORED if owned else None, draft=dict(files),
                                   assembly=AssemblyRecord(), iteration=2, product_id=PID, trace_id="t1", extras={})


@pytest.mark.parametrize("main,fires", [
    (WRONG, True),
    (RIGHT, False),
    (FASTAPI + f'\n\n@app.post("{PUSH}/")\ndef p():\n    return {{}}\n', True),    # a 307 is a failed Pub/Sub delivery
    (FASTAPI + f'\n\n@app.get("{PUSH}/")\ndef p():\n    return {{}}\n', True),     # and a GET is not a POST at all
    (FASTAPI + f'\n\n@app.get("{PUSH}")\ndef p():\n    return {{}}\n', True),      # the path exists, but not as POST
])
def test_the_firing_rule(main, fires):
    out = planned_push_route_findings(_vctx(_service(main)), _topology(), {SVC})
    assert [d.code for d in out] == ([PUSH_ROUTE_CODE] if fires else [])
    if fires:
        assert out[0].file == MAIN and out[0].symbol == f"POST {PUSH}" and out[0].severity == "error"


def test_the_check_finds_the_plan_name_of_an_underscore_directory():
    files = {k.replace(SVC, "factory_worker"): v for k, v in _service(WRONG).items()}
    assert [d.code for d in planned_push_route_findings(_vctx(files), _topology(), {"factory_worker"})] == [PUSH_ROUTE_CODE]


def test_the_finding_waits_for_the_web_entrypoint():
    files = dict(_service(WRONG), **{PROCFILE: "web: uvicorn nothing:app --port $PORT\n"})   # V3c's own finding
    assert planned_push_route_findings(_vctx(files), _topology(), {SVC}) == []


@pytest.mark.parametrize("services,topology", [(set(), _topology()), ({SVC}, None), ({"storefront"}, _topology())])
def test_out_of_scope_is_silent(services, topology):
    assert planned_push_route_findings(_vctx(_service(WRONG)), topology, services) == []


def test_v3c_itself_never_judges_the_push_path():
    v = ContainerContractValidator(_topology())
    assert PUSH_ROUTE_CODE not in {d.code for d in v.validate(_vctx(_service(WRONG)))}


def test_the_handler_gives_the_loop_the_runs_topology():
    with open(os.path.join(GATEWAY, "developer_agent", "handler.py"), encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id == "LoopContext"]
    assert len(calls) == 1
    value = next(kw.value for kw in calls[0].keywords if kw.arg == "topology")
    assert ast.unparse(value) == "inputs.compute_intent.topology"
