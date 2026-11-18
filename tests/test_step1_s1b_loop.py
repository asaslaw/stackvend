"""Step 1 S1-B repair loop (lane 8B §4.3, §6, §7, §10; integration plan §S.6 step 7). Fakes stand in for the LLM
and for `tofu validate` (deterministic functions of the tree); the validators, routing, acceptance and ledger are the
real code. No network, no LLM."""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
import sys
from unittest.mock import patch

import pytest
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; OPEN-MODEL-SETTINGS)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent.repair_loop import Assembled, LoopContext, RepairLoop, accept  # noqa: E402
from developer_agent.validators.base import ValidatorStack  # noqa: E402
from developer_agent.validators.step1 import (AssemblyPreservationValidator, PolicyValidator,  # noqa: E402
                                              PythonSyntaxValidator, TofuValidateValidator)
from shared.diagnostics import (AssemblyRecord, Diagnostic, ErrorClass, MemoryLedgerStore,  # noqa: E402
                                RepairBudgetExhausted, RepairLedger, StageError, StoreUnavailable, ValidationReport)
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402

W = "infra/workload/"
MAIN = W + "main.tf"


# ------------------------------------------------------------------------------------------------ fakes
def _raw(path, text, needle, summary, length=None):
    start = text.index(needle)
    line = text[:start].count("\n") + 1
    return {"severity": "error", "summary": summary,
            "range": {"filename": path, "start": {"line": line, "byte": start},
                      "end": {"line": line, "byte": start + (length or len(needle))}}}


class FakeTofu:
    """Behaves like `tofu validate` on the fixtures: a stray `]` hides everything else (E1); otherwise every
    reference to an undeclared google_storage_bucket is reported."""

    def __init__(self):
        self.calls = 0

    def validate(self, files, *, iac_engine="OPENTOFU", trace_id=""):
        self.calls += 1
        diags = []
        for path, text in sorted(files.items()):
            if not path.endswith(".tf"):
                continue
            if "]]" in text:
                diags.append(_raw(path, text, "]]", "Missing newline after argument", 1))
                continue
            declared = {line.split('"')[3] for line in text.split("\n") if line.startswith('resource "google_storage_bucket"')}
            for ref in ("google_storage_bucket.a", "google_storage_bucket.b", "google_storage_bucket.c"):
                name = ref.split(".")[1]
                if ref in text and name not in declared:
                    diags.append(_raw(path, text, ref, "Reference to undeclared resource"))
            if "google_cloud_run_v2_service.api" in text:
                diags.append(_raw(path, text, "google_cloud_run_v2_service.api", "Reference to undeclared resource"))
        return {"status": "FAIL" if diags else "PASS", "diagnostics": diags}


class Unavailable:
    def validate(self, files, **kw):
        return {"status": "UNAVAILABLE", "reason": "server down"}


def _stack(client):
    st = ValidatorStack()
    st.register(TofuValidateValidator(client), "blocking")
    st.register(PolicyValidator(), "blocking")
    st.register(PythonSyntaxValidator(), "blocking")
    st.register(AssemblyPreservationValidator(), "blocking")
    return st


def _ctx(repair_fn, *, client=None, settings=None, ledger=None, record=None, drop=None, attribution=None):
    rec = record or AssemblyRecord()

    def assemble(d):
        tree = dict(d)
        root = {k: v for k, v in tree.items() if k.endswith(".tf")}
        if drop:
            root = {k: v.replace(drop, "") for k, v in root.items()}
        return Assembled(tree=tree, record=rec, assembled_root=root)
    return LoopContext(trace_id="t1", product_id="shop", assemble=assemble, stack=_stack(client or FakeTofu()),
                       ledger_store=ledger or MemoryLedgerStore(), settings=settings or HallucinationStackSettings(),
                       attribution=attribution or {MAIN: "iac_worker", "tests/test_x.py": "test_worker"},
                       llm_draft_paths={MAIN, "tests/test_x.py"}, preexisting=set(), repair_fn=repair_fn,
                       model="gemini-test", available_providers=["google"])


class Persona:
    """Returns scripted repairs per call; records every task it receives."""

    def __init__(self, *responses, tokens=(100, 200, 50)):
        self.responses = list(responses)
        self.tasks = []
        self.tokens = tokens

    def __call__(self, task):
        self.tasks.append(task)
        files = self.responses.pop(0) if self.responses else {}
        tin, tout, tth = self.tokens
        if files is None:
            return {"files": {}, "envelope_ok": False, "error": "JSONDecodeError", "model": "m",
                    "tokens_in": tin, "tokens_out": tout, "tokens_thoughts": tth}
        return {"files": files, "envelope_ok": True, "model": "m", "tokens_in": tin, "tokens_out": tout,
                "tokens_thoughts": tth}


BUCKETS = 'resource "google_storage_bucket" "a" {\n  name = "a"\n}\n'
REFS = 'output "x" {\n  value = [google_storage_bucket.a.name, google_storage_bucket.b.name]\n}\n'


# ------------------------------------------------------------------------------------------------ convergence
def test_converges_and_returns_the_validated_tree():
    broken = {MAIN: BUCKETS + REFS, "apps/x/main.py": "x = 1\n"}
    fixed = BUCKETS + 'resource "google_storage_bucket" "b" {\n  name = "b"\n}\n' + REFS
    persona = Persona({MAIN: fixed})
    ctx = _ctx(persona)
    tree, report = RepairLoop(ctx).run(broken)
    assert report.status == "PASS" and tree[MAIN] == fixed
    assert len(persona.tasks) == 1 and list(persona.tasks[0].files_to_fix) == [MAIN]
    assert persona.tasks[0].persona == "iac_worker"
    assert ctx.events[0].accepted and ctx.events[0].tokens_thoughts == 50
    led = ctx.ledger_store.load("t1")
    assert led.iteration == 1 and led.tokens_out == 250 and led.tokens_in == 100   # thoughts count as output (F7)


def test_e1_syntax_fix_unmasking_new_references_is_accepted():
    # RT E1: one stray `]` hides every semantic error; fixing it shows 2 undeclared references in the same file
    broken = {MAIN: 'output "y" {\n  value = [1]]\n}\n' + REFS}
    syntax_fixed = 'output "y" {\n  value = [1]\n}\n' + REFS
    full = syntax_fixed + BUCKETS + 'resource "google_storage_bucket" "b" {\n  name = "b"\n}\n'
    persona = Persona({MAIN: syntax_fixed}, {MAIN: full})
    ctx = _ctx(persona)
    tree, report = RepairLoop(ctx).run(broken)
    assert report.status == "PASS" and [e.accepted for e in ctx.events] == [True, True]


def test_e1_plus_an_unrelated_new_error_elsewhere_is_rejected():
    broken = {MAIN: 'output "y" {\n  value = [1]]\n}\n' + REFS, W + "other.tf": BUCKETS}
    candidate = {MAIN: 'output "y" {\n  value = [1]\n}\n' + REFS,
                 W + "other.tf": BUCKETS + 'output "z" {\n  value = google_storage_bucket.c.name\n}\n'}
    persona = Persona(candidate)
    ctx = _ctx(persona, settings=HallucinationStackSettings(repair_max_iterations_precommit=1),
               attribution={MAIN: "iac_worker", W + "other.tf": "iac_worker"})
    ctx.llm_draft_paths |= {W + "other.tf"}
    # the persona is only asked for main.tf; returning other.tf is out of scope -> rejected
    with pytest.raises(RepairBudgetExhausted):
        RepairLoop(ctx).run(broken)
    assert ctx.events[0].reject_reason == "OUT_OF_SCOPE_WRITE"


def test_accept_rule_table():
    def rep(*diags):
        return ValidationReport(status="FAIL" if diags else "PASS", source="precommit", artifact_hash="h",
                                diagnostics=list(diags))

    def d(code, file, block=None, symbol=None):
        return Diagnostic(tool="tofu", code=code, severity="error", file=file, block_address=block, symbol=symbol,
                          message="m", source="precommit")
    a_txt = 'output "y" {\n  value = [1]]\n}\n'
    b_txt = 'output "y" {\n  value = [1]\n}\n'
    asm1 = Assembled(tree={MAIN: a_txt, W + "o.tf": ""}, record=AssemblyRecord())
    asm2 = Assembled(tree={MAIN: b_txt, W + "o.tf": ""}, record=AssemblyRecord())
    syntax = d("TF.MISSING_NEWLINE_AFTER_ARGUMENT", MAIN)
    unmasked = [d("TF.REFERENCE_TO_UNDECLARED_RESOURCE", MAIN, "output.y", f"google_storage_bucket.{n}") for n in "abc"]
    assert accept({}, {}, asm1, asm2, rep(syntax), rep(*unmasked), set(), "opentofu 1.13.1") == (True, None)
    other = d("TF.REFERENCE_TO_UNDECLARED_RESOURCE", W + "o.tf", "output.z", "google_storage_bucket.c")
    assert accept({}, {}, asm1, asm2, rep(syntax), rep(*unmasked, other), set(), "x") == (False, "NEW_FINGERPRINT")
    assert accept({}, {}, asm1, asm1, rep(syntax), rep(syntax), set(), "x") == (False, "NO_IMPROVEMENT")
    # Python: PY.SYNTAX fixed, two undefined names appear in that file -> accepted (compile flips FAIL -> PASS)
    py1 = Assembled(tree={"apps/a.py": "def f(:\n"}, record=AssemblyRecord())
    py2 = Assembled(tree={"apps/a.py": "def f():\n    return x + y\n"}, record=AssemblyRecord())
    names = [Diagnostic(tool="pyflakes", code="PY.UNDEFINED_NAME", severity="error", file="apps/a.py", symbol=s,
                        message="m", source="precommit") for s in "xy"]
    assert accept({}, {}, py1, py2, rep(d("PY.SYNTAX", "apps/a.py")), rep(*names), set(), "x") == (True, None)


def test_preservation_violation_when_a_declaration_disappears():
    broken = {MAIN: BUCKETS + 'resource "google_storage_bucket" "keep" {\n  name = "k"\n}\n' + REFS}
    lossy = BUCKETS + 'resource "google_storage_bucket" "b" {\n  name = "b"\n}\n' + REFS   # "keep" dropped
    persona = Persona({MAIN: lossy})
    ctx = _ctx(persona, settings=HallucinationStackSettings(repair_max_iterations_precommit=1))
    with pytest.raises(RepairBudgetExhausted) as ei:
        RepairLoop(ctx).run(broken)
    assert ctx.events[0].reject_reason == "PRESERVATION_VIOLATION" and ei.value.exhausted_reason == "ITERATIONS"


def test_forbidden_or_platform_owned_blocks_may_be_removed():
    text = BUCKETS + 'resource "google_project_service" "run" {\n  service = "run.googleapis.com"\n}\n'
    persona = Persona({MAIN: BUCKETS})
    ctx = _ctx(persona)
    tree, report = RepairLoop(ctx).run({MAIN: text})
    assert report.status == "PASS" and ctx.events[0].removed_addresses == ["google_project_service.run"]


# ------------------------------------------------------------------------------------------------ stops
def test_identical_fingerprints_stop_with_no_progress():
    broken = {MAIN: BUCKETS + REFS}
    persona = Persona({MAIN: BUCKETS + REFS + "# same\n"}, {MAIN: BUCKETS + REFS + "# same again\n"})
    ctx = _ctx(persona, settings=HallucinationStackSettings(repair_max_iterations_precommit=3))
    with pytest.raises(RepairBudgetExhausted) as ei:
        RepairLoop(ctx).run(broken)
    assert ei.value.exhausted_reason in ("ITERATIONS", "NO_PROGRESS")
    assert ctx.events and not any(e.accepted for e in ctx.events)


def test_iterations_zero_is_a_typed_failure_without_llm_calls():
    persona = Persona()
    ctx = _ctx(persona, settings=HallucinationStackSettings(repair_max_iterations_precommit=0))
    with pytest.raises(RepairBudgetExhausted) as ei:
        RepairLoop(ctx).run({MAIN: BUCKETS + REFS})
    assert persona.tasks == [] and ei.value.error_class is ErrorClass.CODE_DEFECT
    assert {d.code for d in ei.value.report.diagnostics} == {"TF.REFERENCE_TO_UNDECLARED_RESOURCE"}


def test_unavailable_validation_costs_zero_llm_calls():
    persona = Persona()
    ctx = _ctx(persona, client=Unavailable())
    with pytest.raises(StageError) as ei:
        RepairLoop(ctx).run({MAIN: BUCKETS + REFS})
    assert ei.value.error_class is ErrorClass.GATE_UNAVAILABLE and persona.tasks == []


def test_platform_owned_and_dropped_findings_are_never_sent_to_a_persona():
    persona = Persona()
    ctx = _ctx(persona)
    ctx.llm_draft_paths = {"tests/test_x.py"}   # main.tf is platform-rendered in this run
    with pytest.raises(StageError) as ei:
        RepairLoop(ctx).run({MAIN: BUCKETS + REFS})
    assert ei.value.error_class is ErrorClass.PLATFORM_DEFECT and persona.tasks == []
    # an LLM declaration the assembly dropped without a record -> V2c + rule 5 -> PLATFORM_DEFECT
    persona2 = Persona()
    ctx2 = _ctx(persona2, drop='resource "google_storage_bucket" "a" {\n  name = "a"\n}\n')
    with pytest.raises(StageError) as ei2:
        RepairLoop(ctx2).run({MAIN: BUCKETS + 'output "x" {\n  value = google_storage_bucket.a.name\n}\n'})
    assert ei2.value.error_class is ErrorClass.PLATFORM_DEFECT and persona2.tasks == []
    assert "PLATFORM.ASSEMBLY_DROPPED_DECLARATION" in {d.code for d in ei2.value.report.diagnostics}


def test_reference_to_a_replaced_cloud_run_service_reaches_the_persona_with_the_exact_hint():
    rec = AssemblyRecord()
    rec.record("google_cloud_run_v2_service.api", "module.compute", "CLOUD_RUN_REPLACED_BY_MODULE", MAIN)
    text = BUCKETS + 'output "u" {\n  value = google_cloud_run_v2_service.api.uri\n}\n'
    fixed = BUCKETS + 'output "u" {\n  value = module.compute.service_uri\n}\n'
    persona = Persona({MAIN: fixed})
    ctx = _ctx(persona, record=rec)
    ctx_tree_with_module = dict({MAIN: text}, **{
        "infra/modules/compute-cloudrun/outputs.tf": 'output "service_uri" {\n  value = "x"\n}\n'
                                                       'output "service_name" {\n  value = "y"\n}\n',
        "infra/modules/compute-cloudrun/main.tf": 'resource "google_cloud_run_v2_service" "svc" {\n  name = "s"\n}\n',
        W + "root.tf": 'module "compute" {\n  source = "../modules/compute-cloudrun"\n}\n'})
    ctx.llm_draft_paths |= set()
    tree, report = RepairLoop(ctx).run(ctx_tree_with_module)
    hint = json.loads(persona.tasks[0].diagnostics[0]["hint"])
    action = hint.pop("action")   # R3c: the module manages a Cloud Run service -> rewire to its outputs
    assert hint == {"old": "google_cloud_run_v2_service.api", "new": "module.compute",
                    "outputs": ["service_name", "service_uri"]}
    assert action.startswith("Replace the reference with module.compute.<output>")
    assert report.status == "PASS"


# ------------------------------------------------------------------------------------------------ ledger
def test_ledger_refuses_at_budget_and_store_failure_is_gate_unavailable():
    persona = Persona()
    ledger = MemoryLedgerStore()
    ledger.save(RepairLedger(trace_id="t1", tokens_in=489_990))   # QA-REPAIR-BUDGET: the trace budget is 490_000
    ctx = _ctx(persona, ledger=ledger)
    with pytest.raises(RepairBudgetExhausted) as ei:
        RepairLoop(ctx).run({MAIN: BUCKETS + REFS})
    assert ei.value.exhausted_reason == "TOKENS" and persona.tasks == []

    class Broken(MemoryLedgerStore):
        def save(self, ledger):
            raise StoreUnavailable("firestore down")
    ctx2 = _ctx(Persona(), ledger=Broken())
    with pytest.raises(StageError) as ei2:
        RepairLoop(ctx2).run({MAIN: BUCKETS + REFS})
    assert ei2.value.error_class is ErrorClass.GATE_UNAVAILABLE


def test_total_iterations_are_per_trace_across_dispatches():
    ledger = MemoryLedgerStore()
    ledger.save(RepairLedger(trace_id="t1", iteration=10))   # QA-REPAIR-BUDGET: total 10
    persona = Persona()
    with pytest.raises(RepairBudgetExhausted) as ei:
        RepairLoop(_ctx(persona, ledger=ledger)).run({MAIN: BUCKETS + REFS})
    assert ei.value.exhausted_reason == "ITERATIONS" and persona.tasks == []


def test_reservations_sum_concurrent_personas_and_output_cap():
    text = BUCKETS + REFS
    persona = Persona({MAIN: text.replace("google_storage_bucket.b.name", "google_storage_bucket.a.name")},
                      {"tests/test_x.py": "def test_x():\n    pass\n"})
    ctx = _ctx(persona)
    tree, report = RepairLoop(ctx).run({MAIN: text, "tests/test_x.py": "def test_x(:\n"})
    assert report.status == "PASS" and sorted(t.persona for t in persona.tasks) == ["iac_worker", "test_worker"]
    for t in persona.tasks:
        size = sum(max(1, len(v) // 4) for v in t.files_to_fix.values())
        assert t.max_output_tokens == min(16_384, int(1.5 * size + 2048) + 2048) and t.thinking_budget == 2048


def test_envelope_invalid_counts_as_an_iteration():
    persona = Persona(None)
    ctx = _ctx(persona, settings=HallucinationStackSettings(repair_max_iterations_precommit=1))
    with pytest.raises(RepairBudgetExhausted):
        RepairLoop(ctx).run({MAIN: BUCKETS + REFS})
    assert ctx.events[0].reject_reason == "ENVELOPE_INVALID" and ctx.ledger_store.load("t1").iteration == 1


# ------------------------------------------------------------------------------------------------ syntax table
SYNTAX_CODES_JSON = os.path.join(GATEWAY, "developer_agent", "validators", "syntax_codes.json")
PROD_TOFU_190 = os.path.join(REPO_ROOT, "eval", ".tools", "tofu-1.9.0", "tofu")   # owner-verified (S.6 step 0), untracked


def _engine_version(tofu):
    import subprocess
    return json.loads(subprocess.run([tofu, "version", "-json"], capture_output=True, text=True).stdout)["terraform_version"]


def syntax_code_column(tofu, tooling_dir):
    """THE generator of a syntax_codes.json column: each SYNTAX_FIXTURES entry through the production /validate code
    path (ValidateService: init -backend=false, then the un-initialized `validate -json`) and tf_code(). Offline: the
    CLI config is filesystem_mirror-only (no `direct {}`) over an EMPTY mirror dir -- every fixture fails at parse,
    before any provider is needed, and a fixture that ever reached provider installation would come back UNAVAILABLE
    (asserted) instead of downloading anything."""
    sys.path.insert(0, os.path.join(REPO_ROOT, "mcp-servers", "terraform"))
    import validate_service as vs
    from developer_agent.validators.syntax_fixtures import SYNTAX_FIXTURES
    from developer_agent.validators.tofu_diagnostics import tf_code
    mirror = os.path.join(tooling_dir, "empty-mirror")
    os.makedirs(mirror, exist_ok=True)

    class B:
        os_arch = "darwin_arm64"

        def ensure(self, e):
            return tofu, ""
    svc = vs.ValidateService(str(tooling_dir), mirror_dir=mirror, binaries=B())
    column = {}
    for name, text in SYNTAX_FIXTURES.items():
        out = svc.validate({MAIN: text})
        assert out["status"] == "FAIL", (name, out["status"], out["reason"])
        column[name] = sorted({tf_code(x["summary"]) for x in out["diagnostics"] if x["severity"] == "error"})
    assert os.listdir(mirror) == []
    return column


def test_syntax_code_table_is_generated_data_and_matches_the_engine(tmp_path):
    from developer_agent.validators.syntax_fixtures import SYNTAX_FIXTURES
    data = json.load(open(SYNTAX_CODES_JSON))
    assert data["engines"] and all(set(cols) == set(SYNTAX_FIXTURES) for cols in data["engines"].values())
    from shutil import which
    tofu = which("tofu") or ("/opt/homebrew/bin/tofu" if os.path.exists("/opt/homebrew/bin/tofu") else None)
    if not tofu:
        pytest.skip("regeneration check needs a host tofu")
    ver = _engine_version(tofu)
    column = data["engines"].get(f"opentofu {ver}")
    if column is None:
        pytest.skip(f"no committed column for opentofu {ver}")
    assert syntax_code_column(tofu, tmp_path) == column


def test_syntax_code_table_has_the_production_engine_column():
    """The repair loop looks its syntax codes up by LoopContext.engine_label (default = the platform pin, opentofu
    1.9.0); a missing column silently disables the syntax-visibility acceptance rule for every production run."""
    import dataclasses
    from developer_agent import repair_loop
    from developer_agent.validators.syntax_fixtures import SYNTAX_FIXTURES
    label = next(f.default for f in dataclasses.fields(LoopContext) if f.name == "engine_label")
    assert label == "opentofu 1.9.0"
    column = json.load(open(SYNTAX_CODES_JSON))["engines"][label]
    assert set(column) == set(SYNTAX_FIXTURES)
    assert all(codes and all(c.startswith("TF.") for c in codes) for codes in column.values())
    assert repair_loop.SYNTAX_CODES[label] == {c for codes in column.values() for c in codes}


def test_syntax_code_1_9_0_column_regenerates_with_the_production_binary(tmp_path):
    if not os.access(PROD_TOFU_190, os.X_OK):
        pytest.skip("eval/.tools/tofu-1.9.0/tofu (owner-verified production engine, untracked) not present")
    assert _engine_version(PROD_TOFU_190) == "1.9.0"
    column = json.load(open(SYNTAX_CODES_JSON))["engines"]["opentofu 1.9.0"]
    assert syntax_code_column(PROD_TOFU_190, tmp_path) == column


# ------------------------------------------------------------------------------------------------ RT F5
def test_preservation_covers_resource_data_module_only():
    """Step 1 code RT F5 / lane 8B §6.2 rule 5: deleting a diagnosed (dangling) output is an accepted repair; deleting
    an undiagnosed resource, or a resource diagnosed with a non-removal code, is still PRESERVATION_VIOLATION.
    Mutation checked: restoring the all-keys diff in _merge makes the first assertion fail (PRESERVATION_VIOLATION)."""
    def rep(*diags):
        return ValidationReport(status="FAIL" if diags else "PASS", source="precommit", artifact_hash="h",
                                diagnostics=list(diags))
    d1 = {MAIN: BUCKETS + REFS}
    out_diag = Diagnostic(tool="tofu", code="TF.REFERENCE_TO_UNDECLARED_RESOURCE", severity="error", file=MAIN,
                          block_address="output.x", symbol="google_storage_bucket.b", message="m", source="precommit")
    asm1 = Assembled(tree=dict(d1), record=AssemblyRecord())
    # 1. the persona deletes the dangling output -> accepted
    d2 = {MAIN: BUCKETS}
    task = type("T", (), {"files_to_fix": {MAIN: d1[MAIN]}})()
    merged, why, removed = RepairLoop._merge(d1, [task], [{"envelope_ok": True, "files": d2}], rep(out_diag))
    assert why is None and removed == set()
    assert accept(d1, merged, asm1, Assembled(tree=dict(merged), record=AssemblyRecord()), rep(out_diag), rep(),
                  removed, "x") == (True, None)
    # 2. deleting the (diagnosed, non-removal code) resource instead -> rejected
    res_diag = Diagnostic(tool="tofu", code="TF.UNSUPPORTED_ATTRIBUTE", severity="error", file=MAIN,
                          block_address="google_storage_bucket.a", message="m", source="precommit")
    d3 = {MAIN: REFS}
    merged, why, removed = RepairLoop._merge(d1, [task], [{"envelope_ok": True, "files": d3}], rep(res_diag))
    assert removed == {"google_storage_bucket.a"}
    assert accept(d1, merged, asm1, Assembled(tree=dict(merged), record=AssemblyRecord()), rep(res_diag), rep(),
                  removed, "x") == (False, "PRESERVATION_VIOLATION")
