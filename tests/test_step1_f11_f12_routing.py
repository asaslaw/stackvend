"""Step 1 code RT F11 and F12 (docs/planning/wave2-step1-code-red-team-fable.md).

F11: an LLM-owned root file python-hcl2 cannot parse used to be exempt from V2a/V2b/V2c/V2d (V1a was report-only), so a
file `tofu validate` accepts could ship an `allUsers` grant unchecked. V1a-llm now blocks it (CODE_DEFECT, routed to
the persona with the parser's message); platform files stay report-only.

F12: `PATH.UNSAFE_KEY` / `GATE.UNSAFE_PATH_KEY` carried `file="<unsafe>"`, so the router typed a key the LLM wrote as
PLATFORM_DEFECT. A key the LLM wrote is now named exactly and repaired by a rename (RepairTask.renames); any other
unsafe key stays `<unsafe>` -> PLATFORM_DEFECT. Fakes stand in for the LLM and for `tofu validate`."""
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

from developer_agent.repair_loop import (Assembled, LoopContext, RepairLoop, RepairTask, accept,  # noqa: E402
                                         render_repair_prompt)
from developer_agent.validators import ValidationContext  # noqa: E402
from developer_agent.validators import policy_tables as T  # noqa: E402
from developer_agent.validators.base import ValidatorStack  # noqa: E402
from developer_agent.validators.step1 import (HclParseValidator, PathValidator, PolicyValidator,  # noqa: E402
                                              PythonSyntaxValidator, TofuValidateValidator, build_step1_stack)
from shared.artifact_ownership import Ownership  # noqa: E402
from shared.diagnostics import (AssemblyRecord, Diagnostic, ErrorClass, MemoryLedgerStore, StageError,  # noqa: E402
                                ValidationReport)
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402

W = "infra/workload/"
CUSTOM = W + "custom.tf"
PUBLIC = ('resource "google_cloud_run_v2_service_iam_member" "p" {\n  name = "api"\n  role = "roles/run.invoker"\n'
          '  member = "allUsers"\n}\n')
UNPARSEABLE_PUBLIC = PUBLIC + "}\n"            # python-hcl2 rejects the stray brace (tofu is faked to accept it)
PRIVATE = ('resource "google_cloud_run_v2_service_iam_member" "p" {\n  name = "api"\n  role = "roles/run.invoker"\n'
           '  member = "serviceAccount:${google_service_account.a.email}"\n}\n'
           'resource "google_service_account" "a" {\n  account_id = "a"\n}\n')


class PassTofu:
    """`tofu validate` that accepts everything (models a file tofu accepts and python-hcl2 rejects)."""

    def validate(self, files, *, iac_engine="OPENTOFU", trace_id=""):
        return {"status": "PASS", "diagnostics": []}


def _vctx(files, *, llm=(), draft=None):
    llm = set(llm)
    return ValidationContext.build(
        files, ownership=lambda p: Ownership.LLM_AUTHORED if p in llm else Ownership.PLATFORM_RENDERED,
        draft=draft or {}, extras={"available_providers": ["google"]}, trace_id="t")


def _stack():
    return build_step1_stack(validate_client=PassTofu(), verifier_factory=None, modes={"V8": "off"})


class Persona:
    def __init__(self, *responses):
        self.responses, self.tasks = list(responses), []

    def __call__(self, task):
        self.tasks.append(task)
        return {"files": self.responses.pop(0) if self.responses else {}, "envelope_ok": True, "model": "m",
                "tokens_in": 10, "tokens_out": 10, "tokens_thoughts": 0}


def _loop_ctx(persona, stack, *, llm_paths, attribution):
    def assemble(d):
        tree = dict(d)
        return Assembled(tree=tree, record=AssemblyRecord(),
                         assembled_root={k: v for k, v in tree.items() if k.endswith(".tf")})
    return LoopContext(trace_id="t1", product_id="shop", assemble=assemble, stack=stack,
                       ledger_store=MemoryLedgerStore(), settings=HallucinationStackSettings(),
                       attribution=dict(attribution), llm_draft_paths=set(llm_paths), preexisting=set(),
                       repair_fn=persona, model="m", available_providers=["google"])


# ------------------------------------------------------------------------------------------------ F11
def test_f11_unparseable_llm_root_file_blocks_even_when_tofu_accepts_it():
    # mutation checked: registering V1a-llm as "report_only" (the pre-F11 contract) -> status PASS -> this fails
    stack = _stack()
    assert stack.mode_of("V1a-llm") == "blocking" and stack.mode_of("V1a") == "report_only"
    report = stack.run(_vctx({CUSTOM: UNPARSEABLE_PUBLIC}, llm={CUSTOM}))
    assert report.status == "FAIL"
    errs = [d for d in report.diagnostics if d.severity == "error"]
    assert [(d.code, d.file, d.error_class) for d in errs] == [("HCL.PARSE_ERROR", CUSTOM, ErrorClass.CODE_DEFECT)]
    assert errs[0].hint == T.HINT_UNCHECKABLE and errs[0].line == 6 and "UnexpectedToken" in errs[0].detail
    assert not any(d.code == "HCL.PARSE_ERROR" for d in report.report_only)


def test_f11_negative_platform_files_stay_report_only_and_parseable_llm_files_are_silent():
    # Do No Harm: a platform-rendered file python-hcl2 rejects is measured only; a parseable LLM file gets no V1a-llm
    stack = _stack()
    report = stack.run(_vctx({W + "main.tf": "}\n", CUSTOM: PRIVATE}, llm={CUSTOM}))
    assert report.status == "PASS"
    assert [(d.code, d.file) for d in report.report_only if d.code == "HCL.PARSE_ERROR"] == [("HCL.PARSE_ERROR",
                                                                                             W + "main.tf")]
    assert HclParseValidator(llm_root_only=True).validate(_vctx({CUSTOM: PRIVATE}, llm={CUSTOM})) == []
    # an LLM file outside the root module is V7's (PATH.IAC_OUTSIDE_WORKLOAD_ROOT), not V1a-llm's
    assert HclParseValidator(llm_root_only=True).validate(_vctx({W + "sub/x.tf": "}\n"}, llm={W + "sub/x.tf"})) == []


def test_f11_unparseable_llm_file_is_routed_to_its_persona_and_repaired():
    # mutation checked: V1a-llm report_only -> the loop returns PASS at once with the allUsers grant, persona unused
    st = ValidatorStack()
    st.register(HclParseValidator(llm_root_only=True), "blocking")
    st.register(TofuValidateValidator(PassTofu()), "blocking")
    st.register(PolicyValidator(), "blocking")
    persona = Persona({CUSTOM: PUBLIC}, {CUSTOM: PRIVATE})
    ctx = _loop_ctx(persona, st, llm_paths={CUSTOM}, attribution={CUSTOM: "iac_worker"})
    tree, report = RepairLoop(ctx).run({CUSTOM: UNPARSEABLE_PUBLIC})
    assert report.status == "PASS" and tree[CUSTOM] == PRIVATE
    first = persona.tasks[0]
    assert first.persona == "iac_worker" and [x["code"] for x in first.diagnostics] == ["HCL.PARSE_ERROR"]
    assert first.diagnostics[0]["hint"] == T.HINT_UNCHECKABLE
    # once parseable, the hidden allUsers grant is visible (accepted: the file's visibility improved) and repaired
    assert [x["code"] for x in persona.tasks[1].diagnostics] == ["POLICY.PUBLIC_MEMBER"]
    assert [e.accepted for e in ctx.events] == [True, True]


# ------------------------------------------------------------------------------------------------ F12
UNSAFE = "apps/api/../api/main.py"
SAFE = "apps/api/main.py"
HANDLER = "def handler():\n    return 1\n"


def test_f12_v7_names_an_llm_key_and_keeps_other_unsafe_keys_anonymous():
    # mutation checked: file="<unsafe>" for every key (pre-F12) -> the first assertion fails
    files = {UNSAFE: HANDLER, "/etc/x.py": "x = 1\n", SAFE + "x": "y = 2\n"}
    got = PathValidator().validate(_vctx(files, llm={UNSAFE}, draft={UNSAFE: HANDLER}))
    assert sorted((d.code, d.file, d.hint) for d in got) == [
        ("PATH.UNSAFE_KEY", "<unsafe>", None), ("PATH.UNSAFE_KEY", UNSAFE, T.HINT_UNSAFE_KEY)]


def test_f12_gatekeeper_check_reports_every_unsafe_key_and_still_checks_safe_files():
    # mutation checked: restoring the early `return [GATE.UNSAFE_PATH_KEY "<unsafe>"]` -> fails (one finding only)
    from gatekeeper_agent.verifier import SynthesisVerifierAgent
    files = {UNSAFE: HANDLER, ".git/hooks/x.py": "x = 1\n", "apps/b/main.py": "def f(:\n"}
    got = SynthesisVerifierAgent(product_id="p").verify(dict(files))
    assert sorted((d.code, d.file) for d in got) == [
        ("GATE.PY_COMPILE_ERROR", "apps/b/main.py"), ("GATE.UNSAFE_PATH_KEY", ".git/hooks/x.py"),
        ("GATE.UNSAFE_PATH_KEY", UNSAFE)]


def _rename_stack():
    st = ValidatorStack()
    st.register(PathValidator(), "blocking")
    st.register(PythonSyntaxValidator(), "blocking")
    st.register(TofuValidateValidator(PassTofu()), "blocking")
    return st


def test_f12_unsafe_llm_key_is_repaired_by_a_rename():
    # mutation checked: routing PATH.UNSAFE_KEY by ownership (pre-F12: unattributable -> PLATFORM_DEFECT) ->
    # StageError instead of a repair -> this fails
    persona = Persona({SAFE: HANDLER})
    ctx = _loop_ctx(persona, _rename_stack(), llm_paths={UNSAFE}, attribution={UNSAFE: "backend_worker"})
    tree, report = RepairLoop(ctx).run({UNSAFE: HANDLER, W + "main.tf": ""})
    assert report.status == "PASS" and UNSAFE not in tree and tree[SAFE] == HANDLER
    task = persona.tasks[0]
    assert task.persona == "backend_worker" and task.renames == [UNSAFE] and list(task.files_to_fix) == [UNSAFE]
    assert task.diagnostics[0]["hint"] == T.HINT_UNSAFE_KEY and "RENAME" in task.prompt()
    assert ctx.events[0].accepted and SAFE in ctx.llm_draft_paths and ctx.attribution[SAFE] == "backend_worker"


def test_f12_unsafe_key_the_llm_did_not_write_stays_a_platform_defect():
    persona = Persona()
    ctx = _loop_ctx(persona, _rename_stack(), llm_paths=set(), attribution={})
    with pytest.raises(StageError) as ei:
        RepairLoop(ctx).run({UNSAFE: HANDLER})
    assert ei.value.report.error_class is ErrorClass.PLATFORM_DEFECT and persona.tasks == []


@pytest.mark.parametrize("returned", [
    {UNSAFE: HANDLER},                                   # returned the old key
    {SAFE: HANDLER, "apps/api/extra.py": "z = 1\n"},     # more new keys than renames
    {"apps/../x.py": HANDLER},                           # the new key is unsafe too
    {W + "main.tf": HANDLER},                            # the new key overwrites an existing file
    {},                                                  # dropped the file
])
def test_f12_invalid_renames_are_out_of_scope_writes(returned):
    task = RepairTask(persona="p", files_to_fix={UNSAFE: HANDLER}, diagnostics=[], read_only_context={}, iteration=1,
                      remaining_iterations=1, feedback="", max_output_tokens=100, renames=[UNSAFE])
    d2, why, _ = RepairLoop._merge({UNSAFE: HANDLER, W + "main.tf": ""}, [task],
                                   [{"envelope_ok": True, "files": returned}], None)
    assert (d2, why) == (None, "OUT_OF_SCOPE_WRITE")


def test_f12_a_rename_that_drops_a_python_symbol_is_a_preservation_violation():
    d = {UNSAFE: HANDLER + "def other():\n    return 2\n"}
    d2 = {SAFE: HANDLER}
    asm, asm2 = Assembled(tree=dict(d), record=AssemblyRecord()), Assembled(tree=dict(d2), record=AssemblyRecord())
    prev = ValidationReport(status="FAIL", source="precommit", artifact_hash="", diagnostics=[Diagnostic(
        tool="path", code="PATH.UNSAFE_KEY", severity="error", file=UNSAFE, message="m", source="precommit")])
    new = ValidationReport(status="PASS", source="precommit", artifact_hash="")
    assert accept(d, d2, asm, asm2, prev, new, set(), "x", ({UNSAFE}, {SAFE})) == (False, "PRESERVATION_VIOLATION")
    d3 = {SAFE: d[UNSAFE]}
    assert accept(d, d3, asm, Assembled(tree=dict(d3), record=AssemblyRecord()), prev, new, set(), "x",
                  ({UNSAFE}, {SAFE})) == (True, None)


def test_f12_prompt_without_renames_is_unchanged():
    # repair cassettes are keyed on the prompt: the rename section appears only when a task has renames
    task = RepairTask(persona="p", files_to_fix={CUSTOM: PUBLIC}, diagnostics=[], read_only_context={}, iteration=1,
                      remaining_iterations=1, feedback="", max_output_tokens=100)
    assert "RENAME" not in render_repair_prompt(task)
