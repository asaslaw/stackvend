"""HS-40 (register row, owner 10-19): CONTAINER.MIGRATION_NOT_INVOKED (V3c-migration) is BLOCKING. A service that ships
apps/<svc>/alembic.ini must run `alembic upgrade` from a Procfile process; the finding names apps/<svc>/Procfile, so
the pre-commit repair loop fixes the Procfile before QA (a missing Procfile is one create with ENTRYPOINT_MISSING).
The rule itself is the report-only rule, unchanged. Fakes stand in for the LLM; no network, no credentials."""
import hermetic_guard  # noqa: F401  (first import)

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

from developer_agent.repair_loop import CREATE_FILE_CODES, Assembled, LoopContext, RepairLoop  # noqa: E402
from developer_agent.validators import ValidationContext  # noqa: E402
from developer_agent.validators.base import ValidatorStack  # noqa: E402
from developer_agent.validators.container import (MIGRATION_CODE, ContainerContractValidator,  # noqa: E402
                                                  MigrationInvocationValidator)
from developer_agent.validators.step1 import build_step1_stack  # noqa: E402
from shared.artifact_ownership import Ownership  # noqa: E402
from shared.diagnostics import AssemblyRecord, MemoryLedgerStore, RepairBudgetExhausted  # noqa: E402
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402

FASTAPI = 'from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get("/health")\ndef health():\n    return {"ok": True}\n'
WEB = "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n"
WEB_MIGRATE = "web: alembic upgrade head && uvicorn main:app --host 0.0.0.0 --port $PORT\n"
ALEMBIC = "[alembic]\nscript_location = migrations\n"


def _ctx(files, llm=None):
    llm = set(files) if llm is None else set(llm)
    return ValidationContext.build(files, ownership=lambda p: Ownership.LLM_AUTHORED if p in llm
                                   else Ownership.PLATFORM_RENDERED, draft={k: files[k] for k in llm if k in files})


def _found(files, llm=None):
    return [(d.code, d.file, d.severity) for d in MigrationInvocationValidator().validate(_ctx(files, llm))]


def test_registered_blocking_and_routed_as_a_procfile_create():
    stack = build_step1_stack(validate_client=None, verifier_factory=None)
    assert stack.mode_of("V3c-migration") == "blocking"
    assert MIGRATION_CODE == "CONTAINER.MIGRATION_NOT_INVOKED" and MIGRATION_CODE in CREATE_FILE_CODES


def test_finding_is_an_error_on_the_procfile_with_a_hint():
    files = {"apps/api/main.py": FASTAPI, "apps/api/alembic.ini": ALEMBIC, "apps/api/Procfile": WEB}
    (d,) = MigrationInvocationValidator().validate(_ctx(files))
    assert (d.code, d.file, d.severity, d.tool) == (MIGRATION_CODE, "apps/api/Procfile", "error", "container")
    assert "alembic upgrade head &&" in d.hint and "|| true" in d.hint and "apps/api/" in d.hint


def test_do_no_harm_valid_trees_get_no_finding_and_are_never_written():
    # negative tests: a Procfile that runs the migrations, or a service without alembic.ini -> no finding
    ok = {"apps/api/main.py": FASTAPI, "apps/api/alembic.ini": ALEMBIC, "apps/api/Procfile": WEB_MIGRATE}
    no_alembic = {"apps/api/main.py": FASTAPI, "apps/api/Procfile": WEB}
    for files in (ok, no_alembic):
        before = dict(files)
        assert _found(files) == []
        assert files == before
    # quoted/commented text is not an invocation: exact argv pair only (no substring test)
    commented = {"apps/api/main.py": FASTAPI, "apps/api/alembic.ini": ALEMBIC,
                 "apps/api/Procfile": "# web: alembic upgrade head\n" + WEB}
    assert [c for c, _, _ in _found(commented)] == [MIGRATION_CODE]
    # a platform-only service (no LLM-owned .py file) is out of scope, as before
    assert _found({"apps/stub/main.py": FASTAPI, "apps/stub/alembic.ini": ALEMBIC, "apps/stub/Procfile": WEB},
                  llm=set()) == []


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
    st.register(MigrationInvocationValidator(), "blocking")

    def assemble(d):
        return Assembled(tree=dict(d), record=AssemblyRecord(), assembled_root={})
    return LoopContext(trace_id="t1", product_id="shop", assemble=assemble, stack=st,
                       ledger_store=MemoryLedgerStore(), settings=HallucinationStackSettings(),
                       attribution={p: "backend_worker" for p in llm_paths}, llm_draft_paths=set(llm_paths),
                       preexisting=set(), repair_fn=persona, model="m", available_providers=["google"])


def test_repair_loop_fixes_an_existing_procfile_before_commit():
    draft = {"apps/api/main.py": FASTAPI, "apps/api/alembic.ini": ALEMBIC, "apps/api/Procfile": WEB}
    persona = Persona({"apps/api/Procfile": WEB_MIGRATE})
    tree, report = RepairLoop(_loop(persona, set(draft))).run(draft)
    assert report.status == "PASS" and tree["apps/api/Procfile"] == WEB_MIGRATE
    (t,) = persona.tasks
    assert t.persona == "backend_worker" and t.files_to_fix == {"apps/api/Procfile": WEB} and t.creates == []
    assert [x["code"] for x in t.diagnostics] == [MIGRATION_CODE]
    assert "alembic upgrade head &&" in (t.diagnostics[0]["hint"] or "")
    assert tree["apps/api/main.py"] == FASTAPI and tree["apps/api/alembic.ini"] == ALEMBIC   # nothing else touched


def test_missing_procfile_is_one_create_carrying_both_requirements():
    draft = {"apps/api/main.py": FASTAPI, "apps/api/alembic.ini": ALEMBIC}
    persona = Persona({"apps/api/Procfile": WEB_MIGRATE})
    tree, report = RepairLoop(_loop(persona, set(draft))).run(draft)
    assert report.status == "PASS" and tree["apps/api/Procfile"] == WEB_MIGRATE
    (t,) = persona.tasks
    assert t.creates == ["apps/api/Procfile"] and t.files_to_fix == {"apps/api/Procfile": ""}
    assert sorted(x["code"] for x in t.diagnostics) == ["CONTAINER.ENTRYPOINT_MISSING", MIGRATION_CODE]


def test_partial_fix_is_accepted_and_the_migration_finding_stays_blocking():
    # the create fixes ENTRYPOINT_MISSING but not the migration: progress (accepted), the same fingerprint remains
    draft = {"apps/api/main.py": FASTAPI, "apps/api/alembic.ini": ALEMBIC}
    persona = Persona({"apps/api/Procfile": WEB}, {"apps/api/Procfile": WEB_MIGRATE})
    tree, report = RepairLoop(_loop(persona, set(draft))).run(draft)
    assert len(persona.tasks) == 2
    assert [x["code"] for x in persona.tasks[1].diagnostics] == [MIGRATION_CODE]
    assert persona.tasks[1].files_to_fix == {"apps/api/Procfile": WEB} and persona.tasks[1].creates == []
    assert report.status == "PASS" and tree["apps/api/Procfile"] == WEB_MIGRATE


def test_unfixed_migration_blocks_the_commit():
    draft = {"apps/api/main.py": FASTAPI, "apps/api/alembic.ini": ALEMBIC, "apps/api/Procfile": WEB}
    persona = Persona()   # the model returns nothing
    with pytest.raises(RepairBudgetExhausted) as e:
        RepairLoop(_loop(persona, set(draft))).run(draft)
    assert [d.code for d in e.value.report.diagnostics] == [MIGRATION_CODE]


# ------------------------------------------------------------------------------------------------ HS-40 RT A1-A3
from developer_agent.validators.container import parse_command, runs_alembic_upgrade, server_segment  # noqa: E402

FASTAPI_NO_HEALTH = 'from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get("/")\ndef root():\n    return {}\n'
CLOUDRUN = {"infra/workload/main.tf": 'module "compute" {\n  source       = "../modules/compute-cloudrun"\n'
                                      '  service_name = "api"\n}\n'}


def _v3c(procfile, main=FASTAPI):
    files = {"apps/api/main.py": main, "apps/api/alembic.ini": ALEMBIC, "apps/api/Procfile": procfile, **CLOUDRUN}
    ctx = _ctx(files, llm={"apps/api/main.py", "apps/api/Procfile"})
    found = ContainerContractValidator().validate(ctx) + MigrationInvocationValidator().validate(ctx)
    return sorted(d.code for d in found)


def test_a1_v3c_judges_the_server_segment_of_a_chained_web_command():
    assert _v3c(WEB_MIGRATE) == []
    assert _v3c(WEB_MIGRATE, main=FASTAPI_NO_HEALTH) == ["CONTAINER.HEALTH_ROUTE_MISSING"]
    assert _v3c("web: alembic upgrade head && uvicorn main:app --host 0.0.0.0 --port 8080\n") == [
        "CONTAINER.PORT_NOT_BOUND"]
    assert _v3c("web: alembic upgrade head && uvicorn server:app --port $PORT\n") == ["CONTAINER.ENTRYPOINT_MISSING"]
    assert _v3c("web: alembic upgrade head ; uvicorn main:app --port $PORT\n") == []
    # the last segment is not one simple command -> not judged (as any unknown launcher)
    assert _v3c("web: alembic upgrade head && uvicorn main:app --port 8080 || echo down\n") == []
    assert _v3c("web: alembic upgrade head &&\n") == []


@pytest.mark.parametrize("cmd", [
    "uvicorn main:app --host 0.0.0.0 --port $PORT", "gunicorn -b 0.0.0.0:$PORT main:app", "python main.py",
    "python -m uvicorn main:app --port ${PORT:-8080}", "hypercorn main:app --bind 0.0.0.0:8080",
    "uvicorn main:app --port 8080 || true", "alembic upgrade head&&uvicorn main:app", "npm start", "",
])
def test_a1_negative_unchained_commands_parse_exactly_as_before(cmd):
    import shlex
    argv = shlex.split(cmd)
    assert server_segment(argv) is argv
    assert parse_command(server_segment(argv)) == parse_command(argv)


def test_a2_only_the_web_process_counts():
    base = {"apps/api/main.py": FASTAPI, "apps/api/alembic.ini": ALEMBIC}
    for extra in ("release: alembic upgrade head\n", "migrate: alembic upgrade head\n"):
        assert [c for c, _, _ in _found({**base, "apps/api/Procfile": WEB + extra})] == [MIGRATION_CODE]
    assert _found({**base, "apps/api/Procfile": "worker: celery -A app worker\n" + WEB_MIGRATE}) == []


@pytest.mark.parametrize("cmd,runs", [
    ("alembic upgrade head", True),
    ("alembic -c alembic.ini upgrade head", True),
    ("alembic --config=alembic.ini -n db2 upgrade head", True),
    ("alembic -x tenant=a -q --raiseerr upgrade head", True),
    ("python -m alembic upgrade head", True),
    ("alembic downgrade -1", False),
    ("alembic -c upgrade head", False),          # `upgrade` is -c's value here; `head` is the command
    ("alembic --verbose upgrade head", False),   # not an alembic global option: exact table only
    ("echo alembic-upgrade", False),
    ("(alembic upgrade head || true)", False),   # `(alembic` is not the token `alembic`
])
def test_a3_alembic_global_options_before_upgrade(cmd, runs):
    import shlex
    assert runs_alembic_upgrade(shlex.split(cmd)) is runs
