"""SCHEMAS-COLLISION (register row, owner 10-28): the Wave 0 contract registry and the lead plan agree on ONE home for
shared models, so a service can no longer hold both the platform's `schemas/` package and an AI `schemas.py` module.

- The registry owns `apps/<svc>/schemas/__init__.py` + `schemas/contracts.py` (and `contracts/` at the root); a plan
  that assigns one of them, or the module `apps/<svc>/schemas.py` their package would shadow, is refused and re-asked
  (exact path set, `contract_registry.reserved_assignments`; no text rule, no code rewrite).
- Plan-assigned `apps/<svc>/schemas/<name>.py` modules are re-exported by the registry's `schemas/__init__.py` render,
  so `from schemas import Name` resolves (the live 10-28 `EventAuditRecord` failure). Without such modules the render
  is byte-identical to before.
Hermetic: fake LLM client; the CPython oracle imports our own fixture trees in a guarded child interpreter."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import asyncio
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "apps" / "orchestrator-gateway"))

from developer_agent import contract_registry as CR  # noqa: E402
from developer_agent.contract_registry import SharedContractRegistry  # noqa: E402
from developer_agent.lead_orchestrator import (LEAD_ORCHESTRATOR_SYSTEM_PROMPT, LEAD_SCHEMAS_REASK,  # noqa: E402
                                               LeadDeveloperOrchestrator)
from developer_agent.swarm_dispatcher import WAVE0_SCHEMAS_RULE, SwarmDispatcher  # noqa: E402
from developer_agent.swarm_schemas import (JuniorPersona, JuniorTaskAssignment,  # noqa: E402
                                           LeadDeveloperDecompositionPlan, SwarmExecutionMode)
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; row SWARM-TOK-1)

SVC = "testplan01-d"
OLD_INIT = "from .contracts import *\n"   # the registry's service init before SCHEMAS-COLLISION


@pytest.fixture(autouse=True)
def _no_firestore():
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        yield


def task(tid, files, persona="BACKEND_ENGINEER", wave=2, deps=()):
    return {"task_id": tid, "persona": persona, "wave": wave, "assigned_files": list(files),
            "read_dependencies": list(deps), "task_objective": tid}


def plan_json(*tasks):
    return {"execution_mode": "STANDARD_SWARM", "shared_contracts": {}, "tasks": list(tasks)}


def jt(tid, files):
    return JuniorTaskAssignment(task_id=tid, persona=JuniorPersona.BACKEND_ENGINEER, wave=1,
                                assigned_files=list(files), task_objective=tid)


# ------------------------------------------------------------------------------------------- layout and reserved set
def test_registry_paths_are_exactly_what_the_registry_writes():
    for services in (["svc"], ["orders", "payments"], [" spaced ", ""]):
        written = SharedContractRegistry("p").extract_and_generate_contracts({}, services)
        assert set(written) == CR.registry_paths(services)


def test_reserved_paths_add_only_the_shadowed_modules():
    reserved = CR.reserved_paths(["a", "b"])
    assert reserved - CR.registry_paths(["a", "b"]) == {"apps/a/schemas.py", "apps/b/schemas.py", "contracts.py"}


def test_plan_services_matches_the_previous_inline_rule():
    tasks = [jt("t1", ["apps/x/main.py", "apps/y/a/b.py", "infra/workload/main.tf", "apps//z.py"])]
    assert CR.plan_services(tasks, "Prod_ID") == ["x", "y"]
    assert CR.plan_services([jt("t", ["Procfile"])], "Prod_ID") == ["prod-id"]   # no apps/ path: the product id


@pytest.mark.parametrize("path", [f"apps/{SVC}/schemas.py", f"apps/{SVC}/schemas/__init__.py",
                                  f"apps/{SVC}/schemas/contracts.py", f"./apps/{SVC}/schemas.py",
                                  "contracts/schemas.py", "contracts/__init__.py"])
def test_reserved_assignment_found(path):
    tasks = [jt("db", [f"apps/{SVC}/models.py", path])]
    assert CR.reserved_assignments(tasks, SVC) == [("db", path)]


@pytest.mark.parametrize("path", [f"apps/{SVC}/schemas/events.py", f"apps/{SVC}/models.py",
                                  f"apps/{SVC}/pkg/schemas.py", f"apps/{SVC}/schemas_v2.py", "schemas.py",
                                  f"apps/{SVC}/tests/test_schemas.py", f"apps/{SVC}/Schemas.py"])
def test_no_reserved_assignment(path):
    assert CR.reserved_assignments([jt("db", [f"apps/{SVC}/main.py", path])], SVC) == []


# ------------------------------------------------------------------------------------------- registry render
def test_render_without_schema_modules_is_byte_identical_to_before():
    reg = SharedContractRegistry("p")
    contracts = {"Item": "class Item(BaseModel):\n    name: str"}
    before = reg.extract_and_generate_contracts(contracts, ["a", "b"])
    after = reg.extract_and_generate_contracts(contracts, ["a", "b"],
                                               assigned_files=["apps/a/main.py", "apps/a/models.py", "Procfile"])
    assert before == after
    assert before["apps/a/schemas/__init__.py"] == before["apps/b/schemas/__init__.py"] == OLD_INIT
    assert CR.render_service_init() == OLD_INIT


def test_render_re_exports_the_plans_schema_modules_contracts_last():
    files = SharedContractRegistry("p").extract_and_generate_contracts({}, [SVC, "other"], assigned_files=[
        f"apps/{SVC}/schemas/events.py", f"./apps/{SVC}/schemas/audit.py", f"apps/{SVC}/schemas/sub/deep.py",
        f"apps/{SVC}/schemas/my-models.py", f"apps/{SVC}/schemas/class.py", f"apps/{SVC}/schemas/notes.md",
        f"apps/{SVC}/schemas/__init__.py", f"apps/{SVC}/schemas/contracts.py", "apps/other/models.py"])
    init = files[f"apps/{SVC}/schemas/__init__.py"]
    stmts = [ln for ln in init.splitlines() if not ln.startswith("#")]
    assert stmts == ["from .contracts import *", "from .audit import *", "from .events import *",
                     "from .contracts import *"]
    assert files["apps/other/schemas/__init__.py"] == OLD_INIT   # other services: unchanged
    compile(init, "__init__.py", "exec")


def test_dunder_stems_are_never_re_exported():
    """Review N2: `__main__.py` (or any dunder stem) is not a model module."""
    assert CR.schema_submodules(SVC, [f"apps/{SVC}/schemas/__main__.py", f"apps/{SVC}/schemas/__about__.py",
                                      f"apps/{SVC}/schemas/_private.py", f"apps/{SVC}/schemas/events.py"]) == [
        "_private", "events"]


# ------------------------------------------------------------------------------------------- final render (review F1)
def _swarm(assigned, produced):
    """Run the phased swarm with a fake junior that returns only `produced` of its assigned files."""
    from developer_agent.swarm_schemas import JuniorExecutionResult
    tasks = [JuniorTaskAssignment(task_id="db", persona=JuniorPersona.DATABASE_ENGINEER, wave=1,
                                  assigned_files=list(assigned), task_objective="db")]
    plan = LeadDeveloperDecompositionPlan(execution_mode=SwarmExecutionMode.STANDARD_SWARM, tasks=tasks)
    wave0 = SharedContractRegistry(SVC).extract_and_generate_contracts({}, [SVC], assigned_files=assigned)
    plan = plan.model_copy(update={"wave_0_contract_files": wave0})

    async def fake_worker(task, _plan, _deps, _model, trace_id=None):
        return JuniorExecutionResult(task_id=task.task_id, persona=task.persona, wave=task.wave,
                                     files={f: "x = 1\n" for f in produced}, consumed_tokens=1)

    dispatcher = SwarmDispatcher(genai_client=None)
    dispatcher.invoke_junior_worker = fake_worker
    tree = asyncio.run(dispatcher.execute_phased_junior_swarm(plan, "trace", SVC))
    return tree, wave0


def test_final_init_drops_a_schema_module_the_junior_omitted():
    events, audit = f"apps/{SVC}/schemas/events.py", f"apps/{SVC}/schemas/audit.py"
    tree, wave0 = _swarm([f"apps/{SVC}/models.py", events, audit], [f"apps/{SVC}/models.py", audit])
    init = tree[f"apps/{SVC}/schemas/__init__.py"]
    assert "from .events import *" in wave0[f"apps/{SVC}/schemas/__init__.py"]
    assert "events" not in init and "from .audit import *" in init
    assert init == CR.render_service_init(["audit"])


def test_final_init_is_byte_identical_when_every_module_is_produced():
    assigned = [f"apps/{SVC}/models.py", f"apps/{SVC}/schemas/events.py"]
    tree, wave0 = _swarm(assigned, assigned)
    assert {p: tree[p] for p in wave0} == wave0


def test_final_init_without_schema_modules_stays_the_old_init():
    tree, wave0 = _swarm([f"apps/{SVC}/models.py"], [f"apps/{SVC}/models.py"])
    assert tree[f"apps/{SVC}/schemas/__init__.py"] == OLD_INIT and {p: tree[p] for p in wave0} == wave0


# ------------------------------------------------------------------------------------------- CPython oracle
def _write(root, files):
    for rel, text in files.items():
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(text)


def _run(root, code):
    env = hermetic_guard.child_env(extra={"PYTHONDONTWRITEBYTECODE": "1"})
    r = subprocess.run([sys.executable, "-c", code], cwd=str(root), env=env, capture_output=True, text=True,
                       timeout=60)
    return r.returncode, r.stdout, r.stderr


EVENTS = ("from pydantic import BaseModel\n"            # the AI module's own (plain pydantic) BaseModel import
          "from schemas import BaseEventEnvelope\n"      # absolute import of a contract while the package initializes
          "from .contracts import StandardApiResponse\n\n\n"
          "class EventAuditRecord(BaseModel):\n    event_id: str\n")
HANDLERS = "from schemas import EventAuditRecord, BaseEventEnvelope, BaseModel\n"


def _service_tree(init):
    contract = SharedContractRegistry("p").extract_and_generate_contracts({}, [SVC])[f"apps/{SVC}/schemas/contracts.py"]
    return {"schemas/__init__.py": init, "schemas/contracts.py": contract, "schemas/events.py": EVENTS,
            "handlers.py": HANDLERS}


def test_live_case_reconstructed_old_init_fails_new_render_imports(tmp_path):
    """10-28 live: handlers.py `from schemas import EventAuditRecord`, the model in schemas/events.py, the package
    init re-exporting only the contracts -> ImportError. The new render (plan assigns schemas/events.py) imports."""
    old = tmp_path / "old"
    _write(old, _service_tree(OLD_INIT))
    rc, _out, err = _run(old, "import handlers")
    assert rc != 0 and "cannot import name 'EventAuditRecord'" in err

    new = tmp_path / "new"
    init = SharedContractRegistry("p").extract_and_generate_contracts(
        {}, [SVC], assigned_files=[f"apps/{SVC}/schemas/events.py"])[f"apps/{SVC}/schemas/__init__.py"]
    _write(new, _service_tree(init))
    rc, out, err = _run(new, "import handlers, schemas, schemas.contracts as c, schemas.events as e\n"
                             "print(schemas.BaseModel is c.BaseModel, schemas.EventAuditRecord is e.EventAuditRecord)")
    assert rc == 0, err
    assert out.split() == ["True", "True"]   # every contract name keeps its contract binding


def test_module_beside_the_package_is_never_imported(tmp_path):
    """Why the plan may not own `schemas.py`: CPython imports the regular package first, the module's names vanish."""
    files = _service_tree(OLD_INIT)
    files["schemas.py"] = "class OnlyInModule:\n    pass\n"
    _write(tmp_path, files)
    rc, _out, err = _run(tmp_path, "from schemas import OnlyInModule")
    assert rc != 0 and "cannot import name 'OnlyInModule'" in err


def test_a_tree_with_only_schemas_py_stays_valid(tmp_path):
    """Do No Harm: nothing here touches a tree; a service with only `schemas.py` (no registry package, e.g. the
    single-turn path) imports as before."""
    _write(tmp_path, {"schemas.py": "class OnlyInModule:\n    pass\n", "handlers.py": "from schemas import OnlyInModule\n"})
    rc, _out, err = _run(tmp_path, "import handlers")
    assert rc == 0, err


# ------------------------------------------------------------------------------------------- lead plan re-ask
class _Models:
    def __init__(self, answers, prompts):
        self.answers = list(answers)
        self.prompts = prompts

    def generate_content(self, model, contents, config):
        self.prompts.append(contents)
        r = MagicMock()
        r.text = json.dumps(self.answers.pop(0))
        r.candidates = []
        return r


def _decompose(answers, cascade=("gemini-3.8-flash", "gemini-2.5-flash")):
    prompts = []
    client = MagicMock()
    client.models = _Models(answers, prompts)
    lead = LeadDeveloperOrchestrator(genai_client=client, model_name=cascade[0], db=None, project_id="")
    with patch("developer_agent.lead_orchestrator.get_model_cascade_for_agent", return_value=list(cascade)):
        plan = lead.decompose_specification(product_id=SVC, spec_text="x" * 2000, task_dag=[{}, {}])
    return plan, prompts


GOOD = plan_json(task("db", [f"apps/{SVC}/models.py", f"apps/{SVC}/schemas/events.py"], "DATABASE_ENGINEER", 1),
                 task("api", [f"apps/{SVC}/main.py", f"apps/{SVC}/handlers.py"],
                      deps=[f"apps/{SVC}/schemas/events.py"]))


@pytest.mark.parametrize("bad_path", [f"apps/{SVC}/schemas.py", f"apps/{SVC}/schemas/__init__.py"])
def test_plan_owning_a_reserved_path_is_reasked_with_the_exact_paths(bad_path):
    """`schemas.py` (23 committed eval runs: names unimportable) and `schemas/__init__.py` (30 eval runs: the staging
    collision threw the whole swarm away) are both refused and re-asked on the next model."""
    bad = plan_json(task("db", [f"apps/{SVC}/models.py", bad_path], "DATABASE_ENGINEER", 1),
                    task("api", [f"apps/{SVC}/main.py"]))
    plan, prompts = _decompose([bad, GOOD])
    assert len(prompts) == 2
    assert prompts[1] == prompts[0] + LEAD_SCHEMAS_REASK.format(paths=json.dumps([bad_path]))
    assert "ERROR SCHEMAS.RESERVED_PATH_ASSIGNED" in prompts[1] and bad_path in prompts[1]
    assert [t.task_id for t in plan.tasks] == ["db", "api"] and not CR.reserved_assignments(plan.tasks, SVC)
    init = plan.wave_0_contract_files[f"apps/{SVC}/schemas/__init__.py"]
    assert "from .events import *" in init


def test_hcl_and_schemas_violations_send_both_notes_hcl_first():
    """Review N1: on the typed IaC intent path a plan with both violations gets both notes, the TI-3b one unchanged."""
    from developer_agent import iac_intent_contract as C
    from developer_agent.lead_orchestrator import LEAD_INTENT_REASK
    hcl = "infra/workload/main.tf"
    bad = plan_json(task("db", [f"apps/{SVC}/schemas.py"], "DATABASE_ENGINEER", 1),
                    task("iac", [hcl], "IAC_ENGINEER"))
    good = plan_json(task("db", [f"apps/{SVC}/schemas/events.py"], "DATABASE_ENGINEER", 1),
                     task("iac", [C.INTENT_PATH], "IAC_ENGINEER"))
    prompts = []
    client = MagicMock()
    client.models = _Models([bad, good], prompts)
    lead = LeadDeveloperOrchestrator(genai_client=client, model_name="gemini-3.8-flash", db=None, project_id="")
    with patch("developer_agent.lead_orchestrator.get_model_cascade_for_agent",
               return_value=["gemini-3.8-flash", "gemini-2.5-flash"]):
        plan = lead.decompose_specification(product_id=SVC, spec_text="x" * 2000, task_dag=[{}, {}],
                                            iac_intent_rule=C.lead_intent_rule())
    assert prompts[1] == (prompts[0] + LEAD_INTENT_REASK.format(paths=json.dumps([hcl]))
                          + LEAD_SCHEMAS_REASK.format(paths=json.dumps([f"apps/{SVC}/schemas.py"])))
    assert [t.assigned_files for t in plan.tasks] == [[f"apps/{SVC}/schemas/events.py"], [C.INTENT_PATH]]


def test_clean_plan_is_accepted_on_the_first_answer_with_no_reask():
    plan, prompts = _decompose([GOOD])
    assert len(prompts) == 1 and "SCHEMAS.RESERVED_PATH_ASSIGNED" not in prompts[0]
    assert plan.tasks[0].assigned_files == [f"apps/{SVC}/models.py", f"apps/{SVC}/schemas/events.py"]


def test_clean_plan_without_schema_modules_keeps_the_old_wave0_files():
    clean = plan_json(task("db", [f"apps/{SVC}/models.py"], "DATABASE_ENGINEER", 1), task("api", [f"apps/{SVC}/main.py"]))
    plan, prompts = _decompose([clean])
    assert len(prompts) == 1
    assert plan.wave_0_contract_files == SharedContractRegistry(SVC).extract_and_generate_contracts({}, [SVC])
    assert plan.wave_0_contract_files[f"apps/{SVC}/schemas/__init__.py"] == OLD_INIT


def test_every_model_owning_a_reserved_path_ends_in_the_deterministic_fallback():
    bad = plan_json(task("db", [f"apps/{SVC}/schemas.py"], "DATABASE_ENGINEER", 1))
    plan, prompts = _decompose([bad, bad])
    assert len(prompts) == 2
    assert plan.tasks and not CR.reserved_assignments(plan.tasks, SVC)
    assert plan.tasks[0].task_id == f"{SVC}-w1-db"   # the deterministic fallback


def test_deterministic_fallback_owns_no_reserved_path():
    lead = LeadDeveloperOrchestrator(genai_client=None, model_name="m", db=None, project_id="")
    for kw in ({}, {"iac_intent": True}, {"service_names": ("a", "b")}):
        fb = lead._build_deterministic_fallback_plan(product_id=SVC, iac_engine="OPENTOFU", vcs_provider="GITHUB", **kw)
        assert CR.reserved_assignments(fb.tasks, SVC) == []


# ------------------------------------------------------------------------------------------- junior contract
def _junior_prompt(plan):
    seen = []

    async def fake_call(prompt, sys_inst, model_name, trace_id=None, **_kw):
        seen.append(prompt)
        return {f: "x = 1\n" for f in plan.tasks[0].assigned_files}, 10

    dispatcher = SwarmDispatcher(genai_client=MagicMock())
    dispatcher._call_gemini_with_backoff = fake_call
    with patch("developer_agent.swarm_dispatcher.get_model_cascade_for_agent", return_value=["gemini-3.8-flash"]):
        asyncio.run(dispatcher.invoke_junior_worker(plan.tasks[0], plan, {}, "gemini-3.8-flash"))
    return seen[0]


def test_junior_anchor_states_the_schemas_home_only_with_wave0_files():
    t = jt("api", [f"apps/{SVC}/main.py"])
    without = LeadDeveloperDecompositionPlan(execution_mode=SwarmExecutionMode.STANDARD_SWARM, tasks=[t])
    p0 = _junior_prompt(without)
    assert WAVE0_SCHEMAS_RULE not in p0 and "schemas/" not in p0.split("=====\n\n", 1)[0]
    with_w0 = without.model_copy(update={"wave_0_contract_files": {f"apps/{SVC}/schemas/__init__.py": OLD_INIT}})
    p1 = _junior_prompt(with_w0)
    assert p1.count(WAVE0_SCHEMAS_RULE) == 1
    assert p1.replace(WAVE0_SCHEMAS_RULE, "") == p0   # the one added line; the rest byte-identical


def test_contract_texts_name_one_home():
    assert "`from schemas import Name`" in WAVE0_SCHEMAS_RULE and "no `schemas.py` module" in WAVE0_SCHEMAS_RULE
    assert "NEVER assign a module `apps/<service>/schemas.py`" in LEAD_ORCHESTRATOR_SYSTEM_PROMPT
    assert "`apps/<service>/schemas/<name>.py`" in LEAD_ORCHESTRATOR_SYSTEM_PROMPT
    from developer_agent.juniors.backend_worker import BACKEND_WORKER_PROMPT
    assert "`schemas.py`, `services.py`" not in BACKEND_WORKER_PROMPT
    assert "never write a `schemas.py` module" in BACKEND_WORKER_PROMPT
