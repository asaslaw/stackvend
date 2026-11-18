"""entrypoint-repair-hint (10-14): why CONTAINER.ENTRYPOINT_MISSING did not converge in the 10-13 fresh eval, and the
repair-loop contract fixes (no healer: nothing rewrites an AI file).

Recorded evidence (cassettes 20261013-FRESH-main-c329660-record): in 03-r1/r2/r3, 06-r2, 09-r1, 09-r3 the DevOps
persona answered the Procfile diagnostic correctly on every iteration (`web: uvicorn main:app --host 0.0.0.0 --port
$PORT`), but the candidate was rejected as NEW_FINGERPRINT because
  (a) fixing the entrypoint lets V3c evaluate the health route for the first time, and the backend's main.py served
      /healthz, not the compute-cloudrun module's /health: a revealed finding, counted as one the repair introduced;
  (b) all personas' answers were judged together: another persona's regression discarded the correct Procfile fix;
and the same rejection feedback went to every persona, so each retry was the same prompt and the same answer.
Fakes stand in for the LLM and for `tofu validate`; no network, no credentials."""
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

from developer_agent.repair_loop import Assembled, LoopContext, RepairLoop, accept  # noqa: E402
from developer_agent.validators import ValidationContext  # noqa: E402
from developer_agent.validators.base import ValidatorStack  # noqa: E402
from developer_agent.validators.container import (ENTRYPOINT_CODE, ENTRYPOINT_MASKED_CODES,  # noqa: E402
                                                  ContainerContractValidator)
from shared.artifact_ownership import Ownership  # noqa: E402
from shared.diagnostics import (AssemblyRecord, Diagnostic, MemoryLedgerStore,  # noqa: E402
                                RepairBudgetExhausted, ValidationReport)
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402

HEALTH = 'from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get("/health")\ndef health():\n    return {"ok": True}\n'
HEALTHZ = HEALTH.replace('"/health"', '"/healthz"')        # the recorded shape: Lead contract said GET /healthz
BAD = "web: uvicorn apps.api.main:app --host 0.0.0.0 --port $PORT\n"   # recorded shape: repo-root module path
WEB = "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n"
TF = "infra/workload/main.tf"
CLOUDRUN = 'module "compute" {\n  source       = "../modules/compute-cloudrun"\n  service_name = "api"\n}\n'
IAC = "infra/workload/iam.tf"
PERSONAS = {"apps/api/main.py": "BACKEND_ENGINEER", "apps/api/Procfile": "DEVOPS_ENGINEER", IAC: "IAC_ENGINEER"}


class FakeIaC:
    """Stands in for `tofu validate` on iam.tf: a file containing BROKEN has one error, NEW adds another."""

    id, tool = "Vfake", "tofu"

    def validate(self, ctx):
        text = ctx.files.get(IAC, "")
        out = []
        for word in ("BROKEN", "NEW"):
            if word in text:
                out.append(Diagnostic(tool="tofu", code="TF.FAKE_" + word, severity="error", file=IAC,
                                      message=word, source="precommit"))
        return out


class Personas:
    """Scripted answers per persona (a list per persona, popped per call); records every task."""

    def __init__(self, **answers):
        self.answers = {k: list(v) for k, v in answers.items()}
        self.tasks = []

    def __call__(self, task):
        self.tasks.append(task)
        queue = self.answers.get(task.persona) or [{}]
        files = queue.pop(0) if len(queue) > 1 else queue[0]
        return {"files": files, "envelope_ok": True, "finish_reason": "STOP", "model": "m",
                "tokens_in": 10, "tokens_out": 10, "tokens_thoughts": 0}


def _loop(repair_fn, settings=None):
    st = ValidatorStack()
    st.register(ContainerContractValidator(), "blocking")
    st.register(FakeIaC(), "blocking")

    def assemble(d):
        return Assembled(tree=dict(d), record=AssemblyRecord(), assembled_root={})
    return LoopContext(trace_id="t1", product_id="shop", assemble=assemble, stack=st,
                       ledger_store=MemoryLedgerStore(), settings=settings or HallucinationStackSettings(),
                       attribution=dict(PERSONAS), llm_draft_paths=set(PERSONAS), preexisting=set(),
                       repair_fn=repair_fn, model="m", available_providers=["google"])


def _codes(files):
    ctx = ValidationContext.build(files, ownership=lambda p: Ownership.LLM_AUTHORED if p.startswith("apps/")
                                  else Ownership.PLATFORM_RENDERED, draft=dict(files))
    return sorted((d.code, d.file) for d in ContainerContractValidator().validate(ctx))


def _rep(*diags):
    return ValidationReport(status="FAIL" if diags else "PASS", source="precommit", artifact_hash="h",
                            diagnostics=list(diags))


def _d(code, file):
    return Diagnostic(tool="container", code=code, severity="error", file=file, message="m", source="precommit")


def _asm(files):
    return Assembled(tree=dict(files), record=AssemblyRecord())


# ------------------------------------------------------------------------------------------------ the masking fact
def test_validator_masks_port_and_health_checks_behind_an_unresolved_entrypoint():
    """The fact accept() relies on: while the Procfile entrypoint does not resolve, V3c never evaluates the health
    route or the PORT binding of that process; once it resolves, they are evaluated (here: /health is missing)."""
    base = {"apps/api/main.py": HEALTHZ, TF: CLOUDRUN}
    assert _codes({**base, "apps/api/Procfile": BAD}) == [(ENTRYPOINT_CODE, "apps/api/Procfile")]
    assert _codes({**base, "apps/api/Procfile": WEB}) == [("CONTAINER.HEALTH_ROUTE_MISSING", "apps/api/main.py")]
    no_port = "web: uvicorn apps.api.main:app --host 0.0.0.0 --port 8080\n"
    assert _codes({**base, "apps/api/main.py": HEALTH, "apps/api/Procfile": no_port}) == [
        (ENTRYPOINT_CODE, "apps/api/Procfile")]
    assert _codes({**base, "apps/api/main.py": HEALTH, "apps/api/Procfile": no_port.replace("apps.api.", "")}) == [
        ("CONTAINER.PORT_NOT_BOUND", "apps/api/Procfile")]
    assert ENTRYPOINT_MASKED_CODES == {"CONTAINER.PORT_NOT_BOUND", "CONTAINER.HEALTH_ROUTE_MISSING",
                                       "CONTAINER.PUSH_ROUTE_MISSING"}   # + FD55-W5c-PLAN-FACTS


# ------------------------------------------------------------------------------------------------ accept(): unmasking
def test_finding_revealed_by_the_entrypoint_fix_is_accepted():
    a1, a2 = _asm({"apps/api/Procfile": BAD}), _asm({"apps/api/Procfile": WEB})
    prev = _rep(_d(ENTRYPOINT_CODE, "apps/api/Procfile"))
    for code, file in (("CONTAINER.HEALTH_ROUTE_MISSING", "apps/api/main.py"),
                       ("CONTAINER.PORT_NOT_BOUND", "apps/api/Procfile")):
        assert accept({}, {}, a1, a2, prev, _rep(_d(code, file)), set(), "x") == (True, None)


def test_revealed_finding_rule_negatives():
    a1, a2 = _asm({"apps/api/Procfile": BAD}), _asm({"apps/api/Procfile": WEB})
    entry = _d(ENTRYPOINT_CODE, "apps/api/Procfile")
    health = _d("CONTAINER.HEALTH_ROUTE_MISSING", "apps/api/main.py")
    other_fixed = _d("TF.X", TF)
    # no entrypoint finding before: a new missing health route is a real regression (e.g. the route was deleted)
    assert accept({}, {}, a1, a2, _rep(other_fixed), _rep(health), set(), "x") == (False, "NEW_FINGERPRINT")
    # the entrypoint finding is still there: nothing was unmasked
    still = _d(ENTRYPOINT_CODE, "apps/api/Procfile").model_copy(update={"message": "other process"})
    assert accept({}, {}, a1, a2, _rep(entry, other_fixed), _rep(still, health), set(), "x") == (
        False, "NEW_FINGERPRINT")
    # the entrypoint of another service was fixed: a finding in apps/api is not revealed by it
    other_svc = _d(ENTRYPOINT_CODE, "apps/web/Procfile")
    assert accept({}, {}, a1, a2, _rep(other_svc), _rep(health), set(), "x") == (False, "NEW_FINGERPRINT")
    # only the masked codes qualify: a syntax error in the service is never "revealed" by a Procfile fix
    py = _d("PY.UNDEFINED_NAME", "apps/api/main.py")
    assert accept({}, {}, a1, a2, _rep(entry), _rep(py), set(), "x") == (False, "NEW_FINGERPRINT")
    # a path outside apps/<svc>/ never qualifies
    assert accept({}, {}, a1, a2, _rep(entry), _rep(_d("CONTAINER.HEALTH_ROUTE_MISSING", "main.py")), set(),
                  "x") == (False, "NEW_FINGERPRINT")


# ------------------------------------------------------------------------------------------------ the loop
def test_recorded_09_r1_shape_converges():
    """09-r1: Procfile names the repo-root module path; main.py serves /healthz; the module probes /health. The
    DevOps fix is accepted (revealed health finding), then the backend persona adds /health -> PASS."""
    p = Personas(DEVOPS_ENGINEER=[{"apps/api/Procfile": WEB}], BACKEND_ENGINEER=[{"apps/api/main.py": HEALTH}])
    ctx = _loop(p)
    tree, report = RepairLoop(ctx).run({"apps/api/main.py": HEALTHZ, "apps/api/Procfile": BAD, TF: CLOUDRUN})
    assert report.status == "PASS" and tree["apps/api/Procfile"] == WEB and tree["apps/api/main.py"] == HEALTH
    assert [(e.persona, e.accepted) for e in ctx.events] == [("DEVOPS_ENGINEER", True), ("BACKEND_ENGINEER", True)]
    assert [t.persona for t in p.tasks] == ["DEVOPS_ENGINEER", "BACKEND_ENGINEER"]
    assert p.tasks[1].files_to_fix == {"apps/api/main.py": HEALTHZ}
    assert p.tasks[1].diagnostics[0]["code"] == "CONTAINER.HEALTH_ROUTE_MISSING"


def test_one_personas_regression_no_longer_discards_another_personas_fix():
    """03-r1 shape: IaC's answer adds a new error, DevOps' Procfile answer is right. DevOps' answer is kept, IaC's is
    rejected and only IaC gets feedback about its own answer; the DevOps persona is not asked again."""
    p = Personas(DEVOPS_ENGINEER=[{"apps/api/Procfile": WEB}],
                 IAC_ENGINEER=[{IAC: "NEW\n"}, {IAC: "fixed\n"}])
    ctx = _loop(p)
    tree, report = RepairLoop(ctx).run({"apps/api/main.py": HEALTH, "apps/api/Procfile": BAD, TF: CLOUDRUN,
                                        IAC: "BROKEN\n"})
    assert report.status == "PASS" and tree["apps/api/Procfile"] == WEB and tree[IAC] == "fixed\n"
    first = [(e.persona, e.accepted, e.reject_reason) for e in ctx.events if e.iteration == 1]
    assert first == [("DEVOPS_ENGINEER", True, None), ("IAC_ENGINEER", False, "NEW_FINGERPRINT")]
    second = [t for t in p.tasks if t.iteration == 2]
    assert [t.persona for t in second] == ["IAC_ENGINEER"]
    assert "TF.FAKE_NEW" in second[0].feedback and "CONTAINER" not in second[0].feedback


def test_joint_acceptance_is_unchanged_when_every_answer_is_good():
    p = Personas(DEVOPS_ENGINEER=[{"apps/api/Procfile": WEB}], IAC_ENGINEER=[{IAC: "fixed\n"}])
    ctx = _loop(p)
    tree, report = RepairLoop(ctx).run({"apps/api/main.py": HEALTH, "apps/api/Procfile": BAD, TF: CLOUDRUN,
                                        IAC: "BROKEN\n"})
    assert report.status == "PASS" and [e.accepted for e in ctx.events] == [True, True]
    assert {e.fingerprints_after == [] for e in ctx.events} == {True}


def test_a_bad_answer_alone_is_still_rejected_and_nothing_changes():
    """Do No Harm: a rejected persona's answer never reaches the draft (no AI file is rewritten or merged)."""
    p = Personas(IAC_ENGINEER=[{IAC: "NEW\n"}])
    ctx = _loop(p, HallucinationStackSettings(repair_max_iterations_precommit=1))
    with pytest.raises(RepairBudgetExhausted):
        RepairLoop(ctx).run({"apps/api/main.py": HEALTH, "apps/api/Procfile": WEB, TF: CLOUDRUN, IAC: "BROKEN\n"})
    assert [(e.accepted, e.reject_reason) for e in ctx.events] == [(False, "NEW_FINGERPRINT")]


def test_remaining_iterations_count_down_and_iteration_one_prompt_is_unchanged():
    p = Personas(IAC_ENGINEER=[{IAC: "NEW\n"}])
    ctx = _loop(p)
    with pytest.raises(RepairBudgetExhausted):
        RepairLoop(ctx).run({"apps/api/main.py": HEALTH, "apps/api/Procfile": WEB, TF: CLOUDRUN, IAC: "BROKEN\n"})
    assert [(t.iteration, t.remaining_iterations) for t in p.tasks] == [(1, 2), (2, 1), (3, 0)]
    # iteration 1 renders exactly as before this change (the recorded cassettes' repair keys stay valid)
    assert p.tasks[0].prompt().startswith("REPAIR TASK (step1-repair-v2) for persona IAC_ENGINEER, iteration 1 "
                                          "(2 remaining).")
    assert "FEEDBACK" not in p.tasks[0].prompt()


# ------------------------------------------------------------------------------------------------ measurement tool
def test_strip_repair_calls_keeps_generation_and_iteration_one():
    import json
    if REPO_ROOT not in sys.path:
        sys.path.insert(0, REPO_ROOT)
    from eval.tools.strip_repair_calls import REPAIR_SITE, strip
    from developer_agent.repair_loop import RepairTask

    def call(site, contents):
        return json.dumps({"type": "call", "site": site, "site_ordinal": 0, "request": {"contents": contents}})
    t1 = RepairTask(persona="DEVOPS_ENGINEER", files_to_fix={}, diagnostics=[], read_only_context={}, iteration=1,
                    remaining_iterations=2, feedback="", max_output_tokens=10)
    t2 = RepairTask(**{**t1.__dict__, "iteration": 2, "remaining_iterations": 1})
    lines = [json.dumps({"type": "meta"}), call("gen", "anything"), call(REPAIR_SITE, t1.prompt()),
             call(REPAIR_SITE, t2.prompt())]
    assert strip(lines, 1) == lines[:3]
    with pytest.raises(ValueError):
        strip([call(REPAIR_SITE, "not a repair prompt")], 1)


# ------------------------------------------------------------------------------------------------ Fable RT F1 (per process)
WORKER_BAD = "worker: python nothere.py\n"
WORKER_OK = "worker: python main.py\n"


def _diags(files):
    ctx = ValidationContext.build(files, ownership=lambda p: Ownership.LLM_AUTHORED if p.startswith("apps/")
                                  else Ownership.PLATFORM_RENDERED, draft=dict(files))
    return ContainerContractValidator().validate(ctx)


def _judge(before, after):
    return accept({}, {}, _asm(before), _asm(after), _rep(*_diags(before)), _rep(*_diags(after)), set(), "x")


def test_masking_is_per_process_web_is_checked_while_only_the_worker_is_broken():
    files = {"apps/api/main.py": HEALTHZ, TF: CLOUDRUN, "apps/api/Procfile": WEB + WORKER_BAD}
    got = sorted((d.code, d.file, d.symbol) for d in _diags(files))
    assert got == [(ENTRYPOINT_CODE, "apps/api/Procfile", "worker"),
                   ("CONTAINER.HEALTH_ROUTE_MISSING", "apps/api/main.py", None)]


def test_fixing_a_worker_line_does_not_exempt_a_removed_health_route():
    """RT F1 repro: worker line fixed AND the web route changed /health -> /healthz: a real regression."""
    before = {"apps/api/main.py": HEALTH, TF: CLOUDRUN, "apps/api/Procfile": WEB + WORKER_BAD}
    after = {"apps/api/main.py": HEALTHZ, TF: CLOUDRUN, "apps/api/Procfile": WEB + WORKER_OK}
    assert [d.code for d in _diags(after)] == ["CONTAINER.HEALTH_ROUTE_MISSING"]
    assert _judge(before, after) == (False, "NEW_FINGERPRINT")


def test_web_line_fix_reveals_missing_health_route_even_with_a_broken_worker():
    before = {"apps/api/main.py": HEALTHZ, TF: CLOUDRUN, "apps/api/Procfile": BAD + WORKER_BAD}
    after = {"apps/api/main.py": HEALTHZ, TF: CLOUDRUN, "apps/api/Procfile": WEB + WORKER_BAD}
    assert sorted(d.symbol for d in _diags(before)) == ["web", "worker"]
    assert _judge(before, after) == (True, None)


def test_file_level_entrypoint_finding_masks_web_and_two_broken_processes_have_two_fingerprints():
    from shared.diagnostics import fingerprint
    before = {"apps/api/main.py": HEALTHZ, TF: CLOUDRUN}                                  # no Procfile at all
    assert [(d.code, d.symbol) for d in _diags(before)] == [(ENTRYPOINT_CODE, None)]
    assert _judge(before, {**before, "apps/api/Procfile": WEB}) == (True, None)
    two = _diags({"apps/api/main.py": HEALTH, TF: CLOUDRUN, "apps/api/Procfile": BAD + WORKER_BAD})
    assert len(two) == 2 and len({fingerprint(d) for d in two}) == 2


def test_process_symbol_never_reaches_the_repair_prompt():
    p = Personas(DEVOPS_ENGINEER=[{"apps/api/Procfile": WEB}], BACKEND_ENGINEER=[{"apps/api/main.py": HEALTH}])
    ctx = _loop(p)
    RepairLoop(ctx).run({"apps/api/main.py": HEALTHZ, "apps/api/Procfile": BAD, TF: CLOUDRUN})
    assert all("symbol" not in d for d in p.tasks[0].diagnostics)
    assert '"symbol"' not in p.tasks[0].prompt()


# ------------------------------------------------------------------------------------------------ Fable RT F2 (strip tool)
def test_strip_tool_refuses_to_write_into_its_source_and_never_clobbers(tmp_path):
    import json
    if REPO_ROOT not in sys.path:
        sys.path.insert(0, REPO_ROOT)
    from eval.tools.strip_repair_calls import main
    src = tmp_path / "cas"
    src.mkdir()
    (src / "03-r1.jsonl").write_text(json.dumps({"type": "meta"}) + "\n")
    before = (src / "03-r1.jsonl").read_text()
    for out in (src, src / "sub", tmp_path / "cas" / "." / "sub" / ".."):
        with pytest.raises(SystemExit):
            main([str(src), "--out", str(out)])
    assert (src / "03-r1.jsonl").read_text() == before and not (src / "sub").exists()
    dst = tmp_path / "out"
    assert main([str(src), "--out", str(dst)]) == 0
    with pytest.raises(SystemExit):
        main([str(src), "--out", str(dst)])
    assert main([str(src), "--out", str(dst), "--force"]) == 0
