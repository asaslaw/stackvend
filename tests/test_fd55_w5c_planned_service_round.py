"""FD55-W5c (register FD55-W5c, owner 10-25): when the plan names a service the AI wrote no code for (V3c-planned,
CONTAINER.ENTRYPOINT_MISSING on apps/<svc>/Procfile), the developer is asked ONCE to write that whole service (one
CREATE round: apps/<svc>/main.py, requirements.txt and Procfile, offered empty) before the run stops.

* The round succeeds -> the service is in the tree (and the developer's own file from then on).
* Still missing after the round -> the same typed stop as before (PLATFORM_DEFECT, PLANNED_SERVICE_STOP_REASON), and
  never a second round.
* The round runs inside the loop's ordinary limits: a spent budget stops with the same RepairBudgetExhausted.
* Negatives: a tree with every planned service makes no repair call; a repair limited to given files (QA / deploy
  repair, `repairable_paths`) stops right away as before; a file the tree already holds is never offered.
* FD55-W5c-PLAN-FACTS: with a typed plan the round's hint carries the service's facts; the check on the written
  service is in test_fd55_w5c_plan_facts.py.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import)

import os
import sys

import pytest
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; OPEN-MODEL-SETTINGS)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from developer_agent.repair_loop import (PLANNED_SERVICE_STOP_REASON, Assembled, LoopContext,  # noqa: E402
                                         RepairLoop)
from developer_agent.validators.base import ValidatorStack  # noqa: E402
from developer_agent.validators.container import (ENTRYPOINT_CODE, PLANNED_SERVICE_CREATE_FILES,  # noqa: E402
                                                  PlannedServiceCodeValidator)
from shared.diagnostics import (AssemblyRecord, ErrorClass, MemoryLedgerStore, RepairBudgetExhausted,  # noqa: E402
                                RepairLedger, StageError)
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402
from shared.service_topology import validate_service_topology  # noqa: E402

PID = "shop"
FASTAPI = 'from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get("/health")\ndef health():\n    return {"ok": True}\n'
WEB = "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n"
DRAFT = {"apps/api/main.py": FASTAPI, "apps/api/Procfile": WEB}
WORKER_FILES = {"apps/worker/main.py": FASTAPI, "apps/worker/requirements.txt": "fastapi\nuvicorn\n",
                "apps/worker/Procfile": WEB}


def _answer(files):
    return {"files": files, "envelope_ok": True, "finish_reason": "STOP", "model": "m", "tokens_in": 10,
            "tokens_out": 10}


def _ctx(answers, *, planned=("worker",), tree_extra=None, ledger=None, settings=None, **kw):
    calls = []
    st = ValidatorStack()
    st.register(PlannedServiceCodeValidator(planned), "blocking")
    store = MemoryLedgerStore()
    if ledger is not None:
        store.save(ledger)

    def assemble(d):
        return Assembled(tree=dict(d, **(tree_extra or {})), record=AssemblyRecord(), assembled_root={})

    def repair(task):
        calls.append(task)
        return answers.pop(0) if answers else _answer({})
    ctx = LoopContext(trace_id="t1", product_id=PID, assemble=assemble, stack=st, ledger_store=store,
                      settings=settings or HallucinationStackSettings(),
                      attribution={p: "backend_worker" for p in DRAFT}, llm_draft_paths=set(DRAFT), preexisting=set(),
                      repair_fn=repair, model="m", available_providers=["google"], **kw)
    return ctx, calls


def test_the_create_files_are_the_planned_hint_files():
    assert set(PLANNED_SERVICE_CREATE_FILES) == {"main.py", "requirements.txt", "Procfile"}


def test_one_whole_service_round_that_writes_the_service_is_committed():
    ctx, calls = _ctx([_answer(dict(WORKER_FILES))])
    tree, report = RepairLoop(ctx).run(dict(DRAFT))
    assert report.status == "PASS"
    assert {k: tree[k] for k in WORKER_FILES} == WORKER_FILES
    assert len(calls) == 1
    task = calls[0]
    assert task.persona == "developer"
    assert task.creates == sorted(WORKER_FILES) and task.files_to_fix == {k: "" for k in WORKER_FILES}
    assert [(x["code"], x["file"]) for x in task.diagnostics] == [(ENTRYPOINT_CODE, "apps/worker/Procfile")]
    hint = task.diagnostics[0]["hint"]                              # the whole-service instruction (RT F7)
    assert "apps/worker/Procfile, apps/worker/main.py, apps/worker/requirements.txt" in hint
    assert "only paths accepted" in hint and "Python" in hint
    assert "CREATE (exception to the rules above)" in task.prompt()
    assert all(ctx.attribution[k] == "developer" and k in ctx.llm_draft_paths for k in WORKER_FILES)


def test_still_missing_after_the_round_is_the_same_typed_stop_and_no_second_round():
    ctx, calls = _ctx([_answer({"apps/worker/requirements.txt": "fastapi\n"})])   # no entry file written
    with pytest.raises(StageError) as ei:
        RepairLoop(ctx).run(dict(DRAFT))
    assert ei.value.error_class is ErrorClass.PLATFORM_DEFECT and len(calls) == 1
    assert PLANNED_SERVICE_STOP_REASON in str(ei.value) and "apps/worker/" in str(ei.value)


def test_a_rejected_round_answer_also_stops_without_a_second_round():
    ctx, calls = _ctx([{"files": {}, "envelope_ok": False, "finish_reason": "MAX_TOKENS", "model": "m"}])
    with pytest.raises(StageError) as ei:
        RepairLoop(ctx).run(dict(DRAFT))
    assert ei.value.error_class is ErrorClass.PLATFORM_DEFECT and len(calls) == 1
    assert PLANNED_SERVICE_STOP_REASON in str(ei.value)


def test_a_file_the_tree_already_holds_is_never_offered():
    ctx, calls = _ctx([_answer({"apps/worker/main.py": FASTAPI, "apps/worker/Procfile": WEB})],
                      tree_extra={"apps/worker/requirements.txt": "fastapi\n"})
    tree, report = RepairLoop(ctx).run(dict(DRAFT))
    assert report.status == "PASS" and len(calls) == 1
    assert calls[0].creates == ["apps/worker/Procfile", "apps/worker/main.py"]


def test_the_round_names_the_plan_facts_of_a_typed_plan():
    vt, diags = validate_service_topology(
        {"services": [{"name": "api", "kind": "cloudrun"}, {"name": "worker", "kind": "cloudrun", "purpose": "Does X."}],
         "primary_service": "api",
         "resources": [{"type": "google_storage_bucket", "logical_name": "b",
                        "consumers": [{"service": "worker", "env_key": "B_BUCKET"}]},
                       {"type": "google_pubsub_topic", "logical_name": "t"}],
         "pushes": [{"topic": "t", "service": "worker", "path": "/tasks/run"}]}, product_id=PID)
    assert vt is not None, [d.code for d in diags]
    served = FASTAPI + '\n\n@app.post("/tasks/run")\ndef run():\n    return {}\n'
    ctx, calls = _ctx([_answer(dict(WORKER_FILES, **{"apps/worker/main.py": served}))], topology=vt)
    _tree, report = RepairLoop(ctx).run(dict(DRAFT))
    assert report.status == "PASS" and len(calls) == 1
    hint = calls[0].diagnostics[0]["hint"]
    for fact in ("POST /tasks/run", "GET /health", "B_BUCKET", "Does X."):
        assert fact in hint and fact in calls[0].prompt(), fact


def test_budget_exhaustion_is_the_same_typed_error():
    ctx, calls = _ctx([_answer(dict(WORKER_FILES))], ledger=RepairLedger(trace_id="t1", tokens_in=489_990))
    with pytest.raises(RepairBudgetExhausted) as ei:
        RepairLoop(ctx).run(dict(DRAFT))
    assert ei.value.exhausted_reason == "TOKENS" and calls == []
    ctx, calls = _ctx([_answer(dict(WORKER_FILES))], ledger=RepairLedger(trace_id="t1", iteration=10))
    with pytest.raises(RepairBudgetExhausted) as ei:
        RepairLoop(ctx).run(dict(DRAFT))
    assert ei.value.exhausted_reason == "ITERATIONS" and calls == []


def test_negative_every_planned_service_present_makes_no_call():
    ctx, calls = _ctx([], planned=("api",))
    tree, report = RepairLoop(ctx).run(dict(DRAFT))
    assert report.status == "PASS" and calls == [] and tree == DRAFT


@pytest.mark.parametrize("paths", [frozenset(), frozenset({"apps/worker/Procfile"})])
def test_negative_a_repair_limited_to_given_files_stops_right_away_as_before(paths):
    ctx, calls = _ctx([_answer(dict(WORKER_FILES))], repairable_paths=paths)
    with pytest.raises(StageError) as ei:
        RepairLoop(ctx).run(dict(DRAFT))
    assert ei.value.error_class is ErrorClass.PLATFORM_DEFECT and calls == []
    assert PLANNED_SERVICE_STOP_REASON in str(ei.value)
