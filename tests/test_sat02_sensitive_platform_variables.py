"""SAT-02 / FD4BD-Q4 + FD4BD-SENS (owner OQ-6, 10-31): an AI output that exposes a platform secret is a repairable
pre-commit finding.

- Engine: the generated infra/workload/variables.tf declares the platform secrets (`oauth_client_secret`,
  `firebase_api_key`; terraform_engine.PLATFORM_SECRET_VARIABLES) `sensitive = true`. The render differs from before
  by exactly those two lines.
- OpenTofu's own validate then refuses a root output whose value is, or is derived from, one of them ("Output refers
  to sensitive values" -> TF.OUTPUT_REFERS_TO_SENSITIVE_VALUES). No text scan of output expressions anywhere.
- Routing (existing ownership rules, repair_loop.Router): in an AI file -> CODE_DEFECT for its author, with
  policy_tables.HINT_SENSITIVE_OUTPUT; deleting the output is a justified removal (REMOVAL_CODES); a repair that keeps
  it ends the run before commit (RepairBudgetExhausted). In a person's file -> BROWNFIELD_CONFLICT (typed stop, no
  LLM call).
- Do No Harm: an output of a non-sensitive variable, a tree without outputs and every other TF code keep today's
  routing and hints; the validator never changes the tree.

Hermetic: a fake V1b client stands in for /validate. The real-engine variants run the local `tofu` (built-in provider
only, no backend, no network) and skip without it; the production-column test (tofu 1.9.0 + provider mirror, untracked)
skips when that column is absent.
"""
import hermetic_guard  # noqa: F401  (first import)

import ast
import hashlib
import json
import os
import posixpath
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; OPEN-MODEL-SETTINGS)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TESTS = os.path.dirname(os.path.abspath(__file__))
for p in (GATEWAY, REPO_ROOT, TESTS, os.path.join(REPO_ROOT, "eval")):
    if p not in sys.path:
        sys.path.insert(0, p)

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent import terraform_engine as te  # noqa: E402
from developer_agent.repair_loop import (REMOVAL_CODES, Assembled, LoopContext, RepairLoop,  # noqa: E402
                                         Router, removal_justifications)
from developer_agent.validators import policy_tables as T  # noqa: E402
from developer_agent.validators.base import ValidatorStack  # noqa: E402
from developer_agent.validators.step1 import PLATFORM_SUPPLIED_VARIABLES, TofuValidateValidator  # noqa: E402
from developer_agent.validators.tofu_diagnostics import map_raw_diagnostic, tf_code  # noqa: E402
from fd4atc_render import without_fd4atc  # noqa: E402
from shared.artifact_ownership import Ownership  # noqa: E402
from shared.diagnostics import (AssemblyRecord, Diagnostic, ErrorClass, MemoryLedgerStore,  # noqa: E402
                                RepairBudgetExhausted, StageError, artifact_hash)
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402
from visible_rename_render import pre_visible_rename  # noqa: E402

W = "infra/workload/"
CODE = T.SENSITIVE_OUTPUT_CODE
SENSITIVE_LINE = "  sensitive   = true\n"
SUMMARY = "Output refers to sensitive values"   # OpenTofu's summary (local tofu 1.13.1; 1.9.0 per the FD-4BD probe)
VARIABLES = te.generate_golden_variables_tf("shop", "acme/shop")

EXPOSING = 'output "fb" {\n  value = var.firebase_api_key\n}\n'
DERIVED = 'output "oauth" {\n  value = "secret=${upper(var.oauth_client_secret)}"\n}\n'
MARKED = 'output "fb" {\n  value     = var.firebase_api_key\n  sensitive = true\n}\n'
MARKED_OTHER = MARKED.replace('"fb"', '"fb_marked"')
PLAIN = 'output "region" {\n  value = var.region\n}\n'
TOPIC = 'resource "terraform_data" "t" {\n  input = var.product_id\n}\n'
TEAM = 'resource "terraform_data" "team" {\n  input = var.region\n}\n'
USES_SECRET = 'resource "terraform_data" "auth" {\n  input = length(var.oauth_client_secret)\n}\n'


# ================================================================================================ engine
def _variables_renders():
    return {
        "variables": te.generate_golden_variables_tf("shop", "acme/shop"),
        "variables:private": te.generate_golden_variables_tf(
            "shop", "acme/shop", allow_unauthenticated=False, enable_direct_iap=True,
            authorized_invoker_members=["domain:example.com"]),
    }


# the pins of tests/test_lane14_pr0b_regulated.py PRE_PR0B_STANDARD_RENDER_SHA256 before this change (same normalization)
_BEFORE_SHA256 = {
    "variables": "104d1b199f3679272c2423d61ae1bd900f5ddae159061422aa45e5b78bf9b196",
    "variables:private": "0eaffcbee25a760822f8f48824a012f31bbd71cc12082bdb1e64b298779fbd97",
}


def _pin(text):
    return hashlib.sha256(without_fd4atc(pre_visible_rename(text)).encode("utf-8")).hexdigest()


def test_engine_declares_every_platform_secret_sensitive_and_nothing_else():
    renders = dict(_variables_renders())
    renders["branch"] = te.generate_golden_variables_tf("shop", "acme/shop", github_default_branch="trunk",
                                                        region="europe-west1")
    for label, text in renders.items():
        declared = {n: b for blk in hcl2.loads(text)["variable"] for n, b in blk.items()}
        assert {n for n, b in declared.items() if b.get("sensitive") is True} == set(te.PLATFORM_SECRET_VARIABLES)
        for name in te.PLATFORM_SECRET_VARIABLES:
            assert (declared[name]["default"], declared[name]["type"]) in (("", "string"), ("", "${string}")), (label, name)


def test_engine_variables_change_is_exactly_the_two_sensitive_lines():
    """Deliberate golden update: removing the two `sensitive = true` lines gives the previous render byte for byte."""
    for label, text in _variables_renders().items():
        assert text.count(SENSITIVE_LINE) == 2, label
        for name in te.PLATFORM_SECRET_VARIABLES:
            block = text.split(f'variable "{name}" {{\n', 1)[1].split("}\n", 1)[0]
            assert block.endswith('  default     = ""\n' + SENSITIVE_LINE), (label, name)
        assert _pin(text.replace(SENSITIVE_LINE, "")) == _BEFORE_SHA256[label], label


def _module_constant(rel, name):
    tree = ast.parse(Path(REPO_ROOT, rel).read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(f"{rel}: {name}")


def test_secret_name_lists_agree_engine_service_compliance_gate_and_step1():
    names = tuple(te.PLATFORM_SECRET_VARIABLES)
    assert names == ("oauth_client_secret", "firebase_api_key")
    assert tuple(_module_constant("mcp-servers/terraform/service.py", "PLATFORM_SECRET_TFVARS")) == names
    assert tuple(_module_constant("mcp-servers/terraform/compliance_gate.py", "PLATFORM_SECRET_VARIABLE_NAMES")) == names
    assert set(names) <= PLATFORM_SUPPLIED_VARIABLES   # step1's superset (variables the platform always supplies)


# ================================================================================================ the code
def test_the_code_is_tofu_diagnostics_naming_of_the_engine_summary():
    assert CODE == tf_code(SUMMARY) == "TF.OUTPUT_REFERS_TO_SENSITIVE_VALUES"


def _raw(path, text, name):
    """The diagnostic OpenTofu emits (range = the output block's header `output "<name>"`, as recorded from
    `tofu validate -json`; filename rewritten to the repository key, as validate_service.repo_key_for does)."""
    header = f'output "{name}"'
    line_no = next(i for i, ln in enumerate(text.splitlines(), 1) if ln.startswith(header))
    start = len("".join(text.splitlines(keepends=True)[:line_no - 1]).encode("utf-8"))
    return {"severity": "error", "summary": SUMMARY,
            "detail": "To reduce the risk of accidentally exporting sensitive data that was intended to be only "
                      "internal, OpenTofu requires that any root module output containing sensitive data be "
                      "explicitly marked as sensitive, to confirm your intent.",
            "range": {"filename": path, "start": {"line": line_no, "column": 1, "byte": start},
                      "end": {"line": line_no, "column": len(header) + 1, "byte": start + len(header)}},
            "snippet": {"code": header + " {"}}


def test_the_mapped_diagnostic_names_the_output_block_and_no_symbol():
    text = TOPIC + EXPOSING
    d, target = map_raw_diagnostic(_raw(W + "custom_outputs.tf", text, "fb"), {W + "custom_outputs.tf": text})
    assert (d.code, d.file, d.line, d.block_address, d.symbol, target, d.error_class) == (
        CODE, W + "custom_outputs.tf", 4, "output.fb", None, None, ErrorClass.CODE_DEFECT)


# ================================================================================================ V1b engines
class FakeValidate:
    """Hermetic stand-in for /validate: an output (parsed with python-hcl2) whose value reads one of the variables the
    tree declares sensitive, and which is not itself sensitive, gets the engine's diagnostic. Test double only."""

    def __init__(self):
        self.calls = 0

    def validate(self, tree, iac_engine="OPENTOFU", trace_id=None):
        self.calls += 1
        sensitive, outputs = set(), []
        for path, text in sorted(tree.items()):
            if not (path.startswith(W) and path.endswith(".tf") and "/" not in path[len(W):]):
                continue
            doc = hcl2.loads(text)
            for blk in doc.get("variable", []):
                sensitive |= {n for n, b in blk.items() if b.get("sensitive") is True}
            for blk in doc.get("output", []):
                outputs += [(path, text, n, b) for n, b in blk.items()]
        diags = [_raw(path, text, n) for path, text, n, b in outputs if b.get("sensitive") is not True
                 and any(f"var.{v}" in json.dumps(b.get("value")) for v in sensitive)]
        return {"status": "FAIL" if diags else "PASS", "diagnostics": diags}


def _tofu_bin():
    pinned = os.environ.get("STACKVEND_PINNED_TOFU", "")
    if pinned and os.access(pinned, os.X_OK):
        return pinned
    return shutil.which("tofu")


class RealTofuValidate:
    """The real engine on the tree's root module (built-in provider only, no backend, no network), with filenames
    rewritten to repository keys the way validate_service.repo_key_for does."""

    def __init__(self, tofu, work):
        self.tofu, self.work, self.calls = tofu, Path(work), 0

    def validate(self, tree, iac_engine="OPENTOFU", trace_id=None):
        self.calls += 1
        root = self.work / f"run{self.calls}"
        root.mkdir(parents=True)
        for path, text in tree.items():
            if path.startswith(W) and path.endswith(".tf") and "/" not in path[len(W):]:
                (root / path[len(W):]).write_text(text, encoding="utf-8")
        env = dict(os.environ, TF_IN_AUTOMATION="1", CHECKPOINT_DISABLE="1", TF_INPUT="0")
        init = subprocess.run([self.tofu, "init", "-backend=false", "-no-color", "-input=false"], cwd=root,
                              capture_output=True, text=True, env=env, timeout=120)
        assert init.returncode == 0, init.stderr
        r = subprocess.run([self.tofu, "validate", "-json", "-no-color"], cwd=root, capture_output=True, text=True,
                           env=env, timeout=120)
        out = json.loads(r.stdout)
        for x in out.get("diagnostics") or []:
            rng = x.get("range") or {}
            if rng.get("filename"):
                rng["filename"] = posixpath.normpath(posixpath.join(W, rng["filename"]))
        return {"status": "PASS" if out.get("valid") else "FAIL", "diagnostics": out.get("diagnostics") or []}


@pytest.fixture(params=["fake", "tofu"])
def engine(request, tmp_path):
    if request.param == "fake":
        return FakeValidate()
    tofu = _tofu_bin()
    if not tofu:
        pytest.skip("needs tofu on PATH or STACKVEND_PINNED_TOFU")
    return RealTofuValidate(tofu, tmp_path)


# ================================================================================================ routing / loop
class Persona:
    def __init__(self, *responses):
        self.responses, self.tasks = list(responses), []

    def __call__(self, task):
        self.tasks.append(task)
        return {"files": self.responses.pop(0) if self.responses else {}, "envelope_ok": True, "model": "m",
                "tokens_in": 10, "tokens_out": 10, "tokens_thoughts": 0}


def _loop_ctx(draft, client, persona=None, *, prior_llm=None, preexisting_files=None):
    st = ValidatorStack()
    st.register(TofuValidateValidator(client), "blocking")
    platform = {W + "variables.tf": VARIABLES}

    def assemble(d):
        tree = dict(platform)
        tree.update(preexisting_files or {})
        tree.update(d)
        return Assembled(tree=tree, record=AssemblyRecord(), assembled_root={})
    return LoopContext(trace_id="t1", product_id="shop", assemble=assemble, stack=st,
                       ledger_store=MemoryLedgerStore(), settings=HallucinationStackSettings(),
                       attribution={p: "iac_worker" for p in draft}, llm_draft_paths=set(draft),
                       preexisting=set(preexisting_files or ()), prior_llm=dict(prior_llm or {}),
                       preexisting_files=dict(preexisting_files or {}), repair_fn=persona, model="m",
                       available_providers=["google"])


AI = W + "custom_outputs.tf"


@pytest.mark.parametrize("bad", [EXPOSING, DERIVED], ids=["direct", "derived"])
@pytest.mark.parametrize("fixed", [TOPIC, TOPIC + MARKED], ids=["output-removed", "output-marked-sensitive"])
def test_ai_output_exposing_a_platform_secret_is_repaired_with_the_hint(engine, bad, fixed):
    draft = {AI: TOPIC + bad}
    persona = Persona({AI: fixed})
    tree, report = RepairLoop(_loop_ctx(draft, engine, persona)).run(dict(draft))
    assert report.status == "PASS" and tree[AI] == fixed and tree[W + "variables.tf"] == VARIABLES
    (t,) = persona.tasks
    assert t.persona == "iac_worker" and list(t.files_to_fix) == [AI]
    (diag,) = t.diagnostics
    assert (diag["code"], diag["file"], diag["block"], diag["hint"]) == (
        CODE, AI, "output." + ("fb" if bad is EXPOSING else "oauth"), T.HINT_SENSITIVE_OUTPUT)
    assert T.HINT_SENSITIVE_OUTPUT in t.prompt()


def test_a_repair_that_keeps_the_exposing_output_stops_the_run_before_commit(engine):
    draft = {AI: TOPIC + EXPOSING}
    persona = Persona({AI: TOPIC + EXPOSING})   # returns the same output
    with pytest.raises(RepairBudgetExhausted) as e:
        RepairLoop(_loop_ctx(draft, engine, persona)).run(dict(draft))
    assert e.value.exhausted_reason in ("NO_PROGRESS", "ITERATIONS")
    assert [(d.code, d.file, d.block_address) for d in e.value.report.diagnostics] == [(CODE, AI, "output.fb")]
    assert e.value.report.error_class is ErrorClass.CODE_DEFECT


def test_a_persons_output_exposing_a_platform_secret_is_a_typed_stop_with_no_llm_call(engine):
    human = {W + "team.tf": TEAM + EXPOSING}
    persona = Persona()
    ctx = _loop_ctx({W + "custom.tf": TOPIC}, engine, persona, preexisting_files=human)
    with pytest.raises(StageError) as e:
        RepairLoop(ctx).run({W + "custom.tf": TOPIC})
    assert not isinstance(e.value, RepairBudgetExhausted) and persona.tasks == []
    assert e.value.report.error_class is ErrorClass.BROWNFIELD_CONFLICT
    assert [(d.code, d.file, d.block_address, d.error_class) for d in e.value.report.diagnostics] == [
        (CODE, W + "team.tf", "output.fb", ErrorClass.BROWNFIELD_CONFLICT)]
    assert "BROWNFIELD_CONFLICT" in str(e.value)


def test_router_sends_an_ai_output_to_its_author_and_a_persons_output_to_the_operator():
    ai_text, human_text, prior_text = TOPIC + EXPOSING, TOPIC + DERIVED, TOPIC + EXPOSING
    draft = {AI: ai_text}
    pre = {W + "team.tf": human_text, W + "old_llm.tf": prior_text}
    ctx = _loop_ctx(draft, FakeValidate(), prior_llm={W + "old_llm.tf": "dev_worker"}, preexisting_files=pre)
    tree = {W + "variables.tf": VARIABLES, **pre, **draft}
    router = Router(ctx, draft, Assembled(tree=tree, record=AssemblyRecord()))
    assert router.ownership(W + "team.tf") is Ownership.USER_OWNED
    got = {}
    for path, name in ((AI, "fb"), (W + "team.tf", "oauth"), (W + "old_llm.tf", "fb")):
        d, _ = map_raw_diagnostic(_raw(path, tree[path], name), tree)
        got[path] = router.route(d)
    assert (got[AI].error_class, got[AI].persona, got[AI].draft_path, got[AI].hint) == (
        ErrorClass.CODE_DEFECT, "iac_worker", AI, T.HINT_SENSITIVE_OUTPUT)
    assert (got[W + "old_llm.tf"].error_class, got[W + "old_llm.tf"].persona, got[W + "old_llm.tf"].hint) == (
        ErrorClass.CODE_DEFECT, "dev_worker", T.HINT_SENSITIVE_OUTPUT)
    assert got[W + "team.tf"].error_class is ErrorClass.BROWNFIELD_CONFLICT and got[W + "team.tf"].persona is None


def test_deleting_the_exposing_output_is_a_justified_removal():
    assert CODE in REMOVAL_CODES
    d = {AI: TOPIC + EXPOSING}
    d2 = {AI: TOPIC}
    prev = FakeValidate().validate({W + "variables.tf": VARIABLES, **d})
    diags = [map_raw_diagnostic(r, d)[0] for r in prev["diagnostics"]]
    from shared.diagnostics import ValidationReport
    report = ValidationReport(status="FAIL", source="precommit", diagnostics=diags,
                              artifact_hash=artifact_hash(d))
    asm = Assembled(tree=dict(d), record=AssemblyRecord(), assembled_root=dict(d))
    asm2 = Assembled(tree=dict(d2), record=AssemblyRecord(), assembled_root=dict(d2))
    assert removal_justifications(d, d2, asm, asm2, report, {"output.fb"}) == {"output.fb": "REMOVAL_CODE:" + CODE}
    # Do No Harm: an output without the finding still has no justification (removing it stays a violation)
    assert removal_justifications(d, d2, asm, asm2, report, {"output.other"}) == {}


# ================================================================================================ Do No Harm
def test_negative_an_output_of_a_non_sensitive_variable_and_secret_use_in_resources_pass_untouched(engine):
    draft = {AI: TOPIC + PLAIN + USES_SECRET + MARKED}
    persona = Persona()
    before = artifact_hash(dict(draft))
    tree, report = RepairLoop(_loop_ctx(draft, engine, persona)).run(dict(draft))
    assert report.status == "PASS" and persona.tasks == [] and engine.calls == 1
    assert tree == {W + "variables.tf": VARIABLES, **draft} and artifact_hash(dict(draft)) == before


def test_negative_other_tofu_codes_keep_their_routing_and_hints():
    draft = {AI: TOPIC + PLAIN}
    ctx = _loop_ctx(draft, FakeValidate())
    router = Router(ctx, draft, Assembled(tree={W + "variables.tf": VARIABLES, **draft}, record=AssemblyRecord()))
    for code, hint in (("TF.UNSUPPORTED_ARGUMENT", None), ("TF.INVALID_EXPRESSION", "keep me"),
                       ("TF.OUTPUT_REFERS_TO_SENSITIVE_VALUE", None)):   # a near name is not this code
        d = Diagnostic(tool="tofu", code=code, severity="error", file=AI, line=5, block_address="output.region",
                       message="m", source="precommit", hint=hint)
        r = router.route(d)
        assert (r.error_class, r.persona, r.hint) == (ErrorClass.CODE_DEFECT, "iac_worker", hint), code


def test_negative_the_hint_is_only_shown_with_this_finding():
    # the repair prompt template is unchanged; the hint text reaches a prompt only through this code's diagnostic
    import developer_agent.repair_loop as rl
    assert rl.REPAIR_PROMPT_VERSION == "step1-repair-v2"
    assert T.HINT_SENSITIVE_OUTPUT not in Path(rl.__file__).read_text(encoding="utf-8")


# ================================================================================================ real engine
def test_real_engine_the_generated_variables_validate_and_only_exposing_outputs_fail(tmp_path):
    tofu = _tofu_bin()
    if not tofu:
        pytest.skip("needs tofu on PATH or STACKVEND_PINNED_TOFU")
    eng = RealTofuValidate(tofu, tmp_path)
    for label, text in _variables_renders().items():
        assert eng.validate({W + "variables.tf": text, W + "custom.tf": TOPIC + USES_SECRET + PLAIN})[
            "status"] == "PASS", label
    res = eng.validate({W + "variables.tf": VARIABLES, AI: TOPIC + EXPOSING + DERIVED + MARKED_OTHER + PLAIN})
    got = sorted((d["summary"], d["range"]["filename"], d["range"]["start"]["line"]) for d in res["diagnostics"])
    text = TOPIC + EXPOSING + DERIVED + MARKED_OTHER + PLAIN
    assert got == sorted([(SUMMARY, AI, text.splitlines().index('output "fb" {') + 1),
                          (SUMMARY, AI, text.splitlines().index('output "oauth" {') + 1)])
    assert {tf_code(d["summary"]) for d in res["diagnostics"]} == {CODE}
    # without `sensitive = true` (the render before this change) the same outputs validate: the finding is new
    before = VARIABLES.replace(SENSITIVE_LINE, "")
    assert eng.validate({W + "variables.tf": before, AI: text})["status"] == "PASS"


@pytest.fixture(scope="module")
def prod_runner(tmp_path_factory):
    prod_tofu = os.path.join(REPO_ROOT, "eval", ".tools", "tofu-1.9.0", "tofu")
    prod_mirror = os.path.join(REPO_ROOT, "eval", ".tofu-mirror-prod")
    if not (os.access(prod_tofu, os.X_OK) and os.path.isdir(prod_mirror)):
        pytest.skip("production column eval/.tools/tofu-1.9.0/tofu + eval/.tofu-mirror-prod (untracked) not present")
    from stackvend_eval.tofu_runner import TofuRunner
    r = TofuRunner(tmp_path_factory.mktemp("sat02-tofu"), Path(prod_mirror), tofu_bin=prod_tofu)
    if not r.mirror_ready:
        pytest.skip(f"production mirror not verified: {r.mirror_manifest['status']}")
    return r


_TFTEST = """mock_provider "google" {}
mock_provider "google-beta" {}
variables {
  project_id          = "shop-p-123456"
  oauth_client_secret = "sat02-test-only-secret"
  firebase_api_key    = "sat02-test-only-browser-key"
}
run "plan" {
  command = plan
}
"""


@pytest.mark.parametrize("env_map", [False, True], ids=["static-env", "env-vars-map"])
def test_real_engine_production_root_validates_and_compute_plans_with_the_value_masked(prod_runner, env_map):
    """Production tofu 1.9.0 + provider mirror (offline): the generated root with the two sensitive variables
    validates, and a mock-provider plan of module "compute" (static FIREBASE_API_KEY env + a dynamic env map that
    carries the key) passes and never prints the key (FD-4BD follow-up probe, kept as a test)."""
    override = {"FIREBASE_API_KEY": "var.firebase_api_key"} if env_map else None
    main = te.generate_golden_main_tf("shop", "cloudrun", "a shop", env_vars_override=override)
    tree = {}
    for root, _dirs, fnames in os.walk(os.path.join(REPO_ROOT, "infra", "modules")):
        for fn in fnames:
            if fn.endswith(".tf"):
                full = os.path.join(root, fn)
                tree[os.path.relpath(full, REPO_ROOT)] = Path(full).read_text(encoding="utf-8")
    full_tree = dict(tree)
    full_tree.update({W + "main.tf": main, W + "variables.tf": VARIABLES,
                      W + "outputs.tf": te.generate_golden_outputs_tf("shop", "cloudrun"),
                      W + "moved.tf": te.generate_golden_moved_tf("shop", "cloudrun")})
    res = prod_runner.validate_tree(full_tree, f"full-{env_map}", plan=False)
    assert res.get("validate_ok") is True, res
    compute = main.split('module "compute" {', 1)[1].split("\n}\n", 1)[0]
    compute = ('module "compute" {' + compute + "\n}\n").replace(
        "module.foundation.workload_sa_email", '"wl-sa@shop-p-123456.iam.gserviceaccount.com"').replace(
        "  depends_on = [module.foundation]\n", "")
    solo = dict(tree)
    solo.update({W + "main.tf": compute, W + "variables.tf": VARIABLES,
                 W + "outputs.tf": 'output "service_uri" {\n  value = module.compute.service_uri\n}\n'})
    res = prod_runner.validate_tree(solo, f"solo-{env_map}", plan=False)
    assert res.get("validate_ok") is True, res
    wd = prod_runner.work_root / "trees" / f"solo-{env_map}" / "infra" / "workload"
    (wd / "sat02.tftest.hcl").write_text(_TFTEST, encoding="utf-8")
    r = prod_runner._run(["test", "-filter=sat02.tftest.hcl", "-no-color", "-verbose"], cwd=wd)
    out = r.stdout + r.stderr
    assert r.returncode == 0 and "1 passed, 0 failed" in out, out[-3000:]
    assert "sat02-test-only-browser-key" not in out and "sat02-test-only-secret" not in out
