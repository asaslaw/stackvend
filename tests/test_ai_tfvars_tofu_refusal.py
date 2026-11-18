"""AI-TFVARS-REFUSED / AI-TOFU-REFUSED (owner 10-29): step-1 validator V2n (validators/iac_file_kinds.py, blocking).

* An AI-written variables file OpenTofu loads by itself in the deploy's root module (`terraform.tfvars.json`,
  `*.auto.tfvars`, `*.auto.tfvars.json` in infra/workload/ or at the repository root, and a repository-root
  `terraform.tfvars`) is POLICY.TFVARS_NOT_ALLOWED, repaired by returning it with no variable in it.
* An AI-written `.tofu` / `.tofu.json` file anywhere is POLICY.TOFU_FILE_NOT_ALLOWED, repaired by a rename to `.tf`.

Exact path rules on the run's own ownership classification (invariant 2); nothing is rewritten (invariant 1: every
validator call below checks the input is unchanged). Negative tests (Do No Harm): trees without such files, platform
rendered / vendored / human files, names OpenTofu does not load, nested directories and emptied variables files give
no finding.
"""
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

from developer_agent import deploy_repair, qa_repair  # noqa: E402
from developer_agent.access_resolution import ResolvedAccess  # noqa: E402
from developer_agent.assembly import assemble_root_module  # noqa: E402
from developer_agent.repair_loop import (RENAME_CODES, RENAME_ONLY_CODES, Assembled, LoopContext,  # noqa: E402
                                         RepairLoop, Router)
from developer_agent.validators import ValidationContext  # noqa: E402
from developer_agent.validators import iac_file_kinds as K  # noqa: E402
from developer_agent.validators import policy_tables as T  # noqa: E402
from developer_agent.validators.access_idp import AccessIdpValidator  # noqa: E402
from developer_agent.validators.base import ValidatorStack  # noqa: E402
from developer_agent.validators.iac_intent import IacHclPathValidator  # noqa: E402
from developer_agent.validators.step1 import build_step1_stack  # noqa: E402
from shared.artifact_ownership import Ownership  # noqa: E402
from shared.diagnostics import AssemblyRecord, ErrorClass, MemoryLedgerStore, RepairBudgetExhausted, artifact_hash  # noqa: E402
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402

W = "infra/workload/"
TFVARS, TOFU = K.TFVARS_CODE, K.TOFU_CODE
ACCESS_HCL = ('allow_unauthenticated      = true\nenable_direct_iap          = false\n'
              'authorized_invoker_members = ["allUsers"]\noauth_client_secret        = "x"\n')
ACCESS_JSON = '{"allow_unauthenticated": true, "firebase_api_key": "k"}'
TOPIC_TF = 'resource "google_pubsub_topic" "t" {\n  name = "t"\n}\n'
VAR_TF = 'variable "m" {\n  type    = list(string)\n  default = []\n}\n'


def _ctx(files, *, own=None, rendered=(), vendored=(), draft=None, committed=None):
    files = dict(files)
    own = own or (lambda p: Ownership.LLM_AUTHORED)
    return ValidationContext.build(files, ownership=own, rendered=frozenset(rendered), vendored=frozenset(vendored),
                                   draft=dict(files if draft is None else draft), trace_id="t",
                                   extras={"preexisting_files": dict(committed or {})})


def _run(files, intent_mode=False, **kw):
    ctx = _ctx(files, **kw)
    before = artifact_hash(dict(files))
    got = K.IacFileKindValidator(intent_mode=intent_mode).validate(ctx)
    assert artifact_hash(dict(ctx.files)) == before and artifact_hash(dict(files)) == before   # never writes
    return got


def _found(ds):
    return sorted((d.code, d.file) for d in ds)


# ------------------------------------------------------------------------------------------------ AI-TFVARS-REFUSED
TFVARS_PATHS = [W + "terraform.tfvars.json", W + "access.auto.tfvars", W + "access.auto.tfvars.json",
                W + "stackvend-access.auto.tfvars.json",   # the deploy's own file name, written by the AI
                "terraform.tfvars.json", "x.auto.tfvars", "x.auto.tfvars.json", "terraform.tfvars"]


@pytest.mark.parametrize("path", TFVARS_PATHS)
def test_ai_variables_file_opentofu_loads_is_refused_naming_the_file(path):
    (d,) = _run({path: ACCESS_JSON if path.endswith(".json") else ACCESS_HCL, W + "custom.tf": TOPIC_TF})
    assert (d.code, d.file, d.line, d.severity, d.error_class) == (TFVARS, path, 1, "error", ErrorClass.CODE_DEFECT)
    assert d.hint == T.HINT_TFVARS_NOT_ALLOWED and path in d.message and d.source == "precommit"


def test_every_ai_variables_file_is_reported_once_and_a_platform_render_never():
    files = {p: (ACCESS_JSON if p.endswith(".json") else ACCESS_HCL) for p in TFVARS_PATHS}
    files[W + "terraform.tfvars"] = ACCESS_HCL   # platform-rendered (an AI copy is removed at assembly)
    assert _found(_run(files, rendered={W + "terraform.tfvars"})) == sorted((TFVARS, p) for p in TFVARS_PATHS)


@pytest.mark.parametrize("path,text", [(W + "a.auto.tfvars", "allow_unauthenticated = \n"),
                                       (W + "a.auto.tfvars", 'svc {\n  x = 1\n}\n'),          # a block: not empty
                                       (W + "a.auto.tfvars.json", "{not json"),
                                       (W + "a.auto.tfvars.json", "[]"),
                                       (W + "a.auto.tfvars.json", ""),                       # empty JSON: unparseable
                                       (W + "terraform.tfvars.json", '{"m": ["allUsers"]}')])
def test_unparseable_or_non_empty_variables_files_stay_findings(path, text):
    assert _found(_run({path: text})) == [(TFVARS, path)]


@pytest.mark.parametrize("path,text", [(W + "a.auto.tfvars", ""), (W + "a.auto.tfvars", "  \n"),
                                       (W + "a.auto.tfvars", "# emptied\n// by the repair\n"),
                                       (W + "a.auto.tfvars.json", "{}"), (W + "terraform.tfvars.json", " { } \n"),
                                       ("terraform.tfvars", "")])
def test_negative_a_variables_file_that_sets_no_variable_is_no_finding(path, text):
    # the repair outcome (the AI cannot delete a file): parsed to an empty object, it sets nothing
    assert _run({path: text}) == []


@pytest.mark.parametrize("path", [W + "terraform.tfvars.example", W + "values.tfvars", W + "auto.tfvars",
                                  W + "x.auto.tfvars.bak", W + "modules/m/x.auto.tfvars",
                                  W + "modules/m/terraform.tfvars.json", "apps/svc/terraform.tfvars.json",
                                  "apps/svc/a.auto.tfvars", "infra/terraform.tfvars", "infra/x.auto.tfvars",
                                  W + "terraform.tfvars"])
def test_negative_names_or_directories_opentofu_does_not_load_are_not_judged(path):
    # infra/workload/terraform.tfvars: the assembly removes an AI copy (PLATFORM_PATH_RESERVED); not this row
    assert _run({path: ACCESS_HCL}) == []


# ------------------------------------------------------------------------------------------------ AI-TOFU-REFUSED
TOFU_PATHS = [W + "edge.tofu", W + "edge.tofu.json", W + "modules/front/main.tofu", "infra/modules/acme/x.tofu",
              "main.tofu", "apps/svc/notes.tofu"]


@pytest.mark.parametrize("path", TOFU_PATHS)
def test_ai_tofu_file_anywhere_is_refused(path):
    (d,) = _run({path: TOPIC_TF if not path.endswith(".json") else '{"resource": {}}'})
    assert (d.code, d.file, d.line, d.error_class) == (TOFU, path, 1, ErrorClass.CODE_DEFECT)
    assert d.hint == T.HINT_TOFU_FILE_NOT_ALLOWED and path in d.message


def test_an_empty_tofu_file_is_still_refused_because_it_shadows_the_same_named_tf():
    files = {W + "edge.tf": TOPIC_TF, W + "edge.tofu": ""}
    assert _found(_run(files)) == [(TOFU, W + "edge.tofu")]


def test_negative_vendored_and_platform_tofu_files_are_not_judged():
    # FD-4CX inspects registered-module files (.tofu included) at registration; vendored files are the platform's
    files = {"infra/modules/acme/main.tofu": TOPIC_TF, W + "platform.tofu": TOPIC_TF}
    own = {"infra/modules/acme/main.tofu": Ownership.PLATFORM_VENDORED, W + "platform.tofu": Ownership.PLATFORM_RENDERED}
    assert _run(files, own=own.get, vendored={"infra/modules/acme/main.tofu"}) == []
    assert _run(files, own=lambda p: Ownership.LLM_AUTHORED, vendored={"infra/modules/acme/main.tofu"},
                rendered={W + "platform.tofu"}) == []


@pytest.mark.parametrize("path", [W + "tofu.md", W + "x.tofu.bak", W + "x.tofuxyz", W + "notes_tofu.tf"])
def test_negative_other_suffixes_are_not_tofu_files(path):
    assert _run({path: "x"}) == []


# ------------------------------------------------------------------------------------------------ ownership
@pytest.mark.parametrize("own", [Ownership.USER_OWNED, Ownership.PLATFORM_RENDERED, Ownership.PLATFORM_VENDORED, None],
                         ids=["user-owned", "rendered", "vendored", "unattributable"])
def test_negative_files_the_ai_did_not_write_are_left_alone(own):
    # a pre-existing human file (USER_OWNED under infra/workload/, unattributable at the repository root) is the
    # human's: the platform never repairs or deletes it
    files = {p: ACCESS_HCL for p in TFVARS_PATHS if not p.endswith(".json")}
    files.update({p: TOPIC_TF for p in TOFU_PATHS if not p.endswith(".json")})
    assert _run(files, own=lambda p: own) == []


def test_llm_document_ownership_counts_as_the_ai():
    assert _found(_run({W + "x.tofu": TOPIC_TF}, own=lambda p: Ownership.LLM_DOCUMENT)) == [(TOFU, W + "x.tofu")]


def test_negative_a_valid_tree_without_such_files_is_unchanged():
    files = {W + "custom.tf": TOPIC_TF, W + "variables.tf": VAR_TF, W + "terraform.tfvars": ACCESS_HCL,
             W + "custom.tf.json": "{}", W + "human.tf": "", W + "README.md": "x", "apps/svc/main.py": "x = 1\n",
             "apps/svc/requirements.txt": "fastapi\n", W + "iac_intent.json": '{"schema": "iac_intent/v1"}',
             "infra/modules/compute-cloudrun/main.tf": TOPIC_TF}
    assert _run(files) == []


def test_python_hcl2_missing_is_unavailable_never_a_pass(monkeypatch):
    import builtins
    real = builtins.__import__

    def no_hcl2(name, *a, **kw):
        if name == "hcl2":
            raise ImportError("no hcl2")
        return real(name, *a, **kw)
    monkeypatch.setattr(builtins, "__import__", no_hcl2)
    st = ValidatorStack()
    st.register(K.IacFileKindValidator(), "blocking")
    report = st.run(_ctx({W + "a.auto.tfvars": ""}))
    assert report.status == "UNAVAILABLE" and report.tools_unavailable == ["V2n"]
    # a tree without a variables file never needs the parser
    assert st.run(_ctx({W + "custom.tf": TOPIC_TF})).status == "PASS"


# ------------------------------------------------------------------------------------------------ deploy facts
def _service_constant(name):
    tree = ast.parse(open(os.path.join(REPO_ROOT, "mcp-servers", "terraform", "service.py")).read())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise AssertionError(name)


def test_the_deploys_own_access_file_is_the_same_file_kind_and_secret_keys_are_root_variables():
    # FD-4DT: the deploy renders exactly such an auto-loaded file at the root; FD-4BD: these keys lose to any variables
    # file. The row exists because an AI file of this kind competes with both.
    assert K.is_auto_loaded_variables_file(W + _service_constant("PLATFORM_ACCESS_VARS_FILE"))
    assert set(_service_constant("PLATFORM_SECRET_TFVARS")) == {"oauth_client_secret", "firebase_api_key"}


# ------------------------------------------------------------------------------------------------ generate mode
def test_generate_mode_path_rule_does_not_cover_these_files_and_v2n_does():
    # V-IAC-PATH (intent mode) refuses only AI `.tf` / `.tf.json` under infra/: these kinds were not refused there
    draft = {W + "a.auto.tfvars": ACCESS_HCL, W + "terraform.tfvars.json": ACCESS_JSON, W + "edge.tofu": TOPIC_TF,
             W + "iac_intent.json": '{"schema": "iac_intent/v1"}'}
    assert IacHclPathValidator().validate(_ctx(draft)) == []
    assert [d.code for d in IacHclPathValidator().validate(_ctx({W + "edge.tf": TOPIC_TF}))] == [
        "PATH.IAC_HCL_NOT_ALLOWED"]
    assert _found(_run(draft)) == [(TFVARS, W + "a.auto.tfvars"), (TFVARS, W + "terraform.tfvars.json"),
                                   (TOFU, W + "edge.tofu")]


def test_v2n_is_blocking_after_v2l_in_every_mode():
    off = build_step1_stack(validate_client=None, verifier_factory=None)
    gen = build_step1_stack(validate_client=None, verifier_factory=None, iac_intent=object())
    for stack in (off, gen):
        assert stack.mode_of("V2n") == "blocking"
        assert stack.ids.index("V2n") == stack.ids.index("V2l") + 1
        assert stack.ids.index("V2l") == stack.ids.index("V2j") + 1   # FD-4AQ W4 pin unchanged
    assert "V-IAC-PATH" in gen.ids and "V-IAC-PATH" not in off.ids


# ------------------------------------------------------------------------------------------------ routing / repair
def _loop_ctx(draft, persona=None, *, stack=None, prior_llm=None, preexisting_files=None):
    st = stack or ValidatorStack()
    if stack is None:
        st.register(K.IacFileKindValidator(), "blocking")

    def assemble(d):
        tree = dict(preexisting_files or {})
        tree.update(d)
        return Assembled(tree=tree, record=AssemblyRecord(), assembled_root={})
    return LoopContext(trace_id="t1", product_id="shop", assemble=assemble, stack=st,
                       ledger_store=MemoryLedgerStore(), settings=HallucinationStackSettings(),
                       attribution={p: "iac_worker" for p in draft}, llm_draft_paths=set(draft),
                       preexisting=set(preexisting_files or ()), prior_llm=dict(prior_llm or {}),
                       preexisting_files=dict(preexisting_files or {}), repair_fn=persona, model="m",
                       available_providers=["google"])


class Persona:
    def __init__(self, *responses):
        self.responses, self.tasks = list(responses), []

    def __call__(self, task):
        self.tasks.append(task)
        return {"files": self.responses.pop(0) if self.responses else {}, "envelope_ok": True, "model": "m",
                "tokens_in": 10, "tokens_out": 10, "tokens_thoughts": 0}


def test_tofu_is_a_rename_code_and_tfvars_is_an_ordinary_file_repair():
    assert TOFU in RENAME_ONLY_CODES and TOFU in RENAME_CODES and TFVARS not in RENAME_CODES


def test_router_sends_both_codes_to_the_author_and_a_prior_run_tofu_file_is_a_stop():
    draft = {W + "a.auto.tfvars": ACCESS_HCL, W + "edge.tofu": TOPIC_TF}
    ctx = _loop_ctx(draft)
    router = Router(ctx, draft, Assembled(tree=dict(draft), record=AssemblyRecord()))
    for d in _run(draft):
        r = router.route(d)
        assert (r.error_class, r.persona, r.draft_path, r.hint) == (ErrorClass.CODE_DEFECT, "iac_worker", d.file,
                                                                    d.hint)
    # CONSTRUCTED STATE (RT F2): the provenance store records only root .tf files, so no real run has a prior_llm
    # entry for these kinds (test_provenance_never_records_these_kinds). If one existed: the variables file is repaired
    # in place; a .tofu file cannot be renamed (only this run's keys are), so the run stops (as for *.tf.json)
    prior = {W + "old.auto.tfvars": ACCESS_HCL, W + "old.tofu": TOPIC_TF}
    ctx = _loop_ctx({}, prior_llm={p: "iac_worker" for p in prior}, preexisting_files=prior)
    router = Router(ctx, {}, Assembled(tree=dict(prior), record=AssemblyRecord()))
    got = {d.code: router.route(d) for d in _run(prior, own=router.ownership)}
    assert (got[TFVARS].error_class, got[TFVARS].persona, got[TFVARS].draft_path) == (
        ErrorClass.CODE_DEFECT, "iac_worker", W + "old.auto.tfvars")
    assert got[TOFU].error_class is ErrorClass.PLATFORM_DEFECT


def test_negative_router_ownership_leaves_a_human_auto_tfvars_alone():
    human = {W + "team.auto.tfvars": ACCESS_HCL, W + "team.tofu": TOPIC_TF}
    ctx = _loop_ctx({}, preexisting_files=human)
    router = Router(ctx, {}, Assembled(tree=dict(human), record=AssemblyRecord()))
    assert router.ownership(W + "team.auto.tfvars") is Ownership.USER_OWNED
    assert _run(human, own=router.ownership) == []


@pytest.mark.parametrize("path,fixed", [(W + "access.auto.tfvars", ""), (W + "access.auto.tfvars.json", "{}"),
                                        (W + "terraform.tfvars.json", "{}"), ("x.auto.tfvars", "# moved\n")])
def test_repair_loop_returns_the_variables_file_emptied_and_accepts_it(path, fixed):
    draft = {path: ACCESS_JSON if path.endswith(".json") else ACCESS_HCL, W + "custom.tf": TOPIC_TF}
    persona = Persona({path: fixed})
    tree, report = RepairLoop(_loop_ctx(draft, persona)).run(dict(draft))
    assert report.status == "PASS" and tree[path] == fixed and tree[W + "custom.tf"] == TOPIC_TF
    (t,) = persona.tasks
    assert t.persona == "iac_worker" and list(t.files_to_fix) == [path] and t.renames == []
    (diag,) = t.diagnostics
    assert (diag["code"], diag["file"], diag["hint"]) == (TFVARS, path, T.HINT_TFVARS_NOT_ALLOWED)
    assert T.HINT_TFVARS_NOT_ALLOWED in t.prompt()


def test_repair_loop_renames_the_tofu_file_to_tf_and_accepts_it():
    draft = {W + "edge.tofu": TOPIC_TF}
    persona = Persona({W + "edge.tf": TOPIC_TF})
    tree, report = RepairLoop(_loop_ctx(draft, persona)).run(dict(draft))
    assert report.status == "PASS" and tree == {W + "edge.tf": TOPIC_TF}
    (t,) = persona.tasks
    assert t.renames == [W + "edge.tofu"] and t.diagnostics[0]["hint"] == T.HINT_TOFU_FILE_NOT_ALLOWED


@pytest.mark.parametrize("draft,code", [({W + "a.auto.tfvars": ACCESS_HCL}, TFVARS),
                                        ({W + "edge.tofu": TOPIC_TF}, TOFU)])
def test_a_repair_that_keeps_the_file_stops_the_run_at_pre_commit(draft, code):
    with pytest.raises(RepairBudgetExhausted) as e:
        RepairLoop(_loop_ctx(draft, Persona())).run(dict(draft))
    assert [d.code for d in e.value.report.diagnostics] == [code]


def test_negative_a_tree_without_such_files_passes_the_loop_untouched():
    draft = {W + "custom.tf": TOPIC_TF, W + "values.tfvars": ACCESS_HCL}
    persona = Persona()
    tree, report = RepairLoop(_loop_ctx(draft, persona)).run(dict(draft))
    assert report.status == "PASS" and persona.tasks == [] and tree == draft


# ------------------------------------------------------------------------------------------------ with V2l
def test_private_workload_gets_both_the_file_refusal_and_the_module_call_finding_in_one_report():
    # FD-4CX-b V2l keeps reading AI root variable files (defense in depth); V2n refuses the file itself
    resolved = ResolvedAccess(mode="PRIVATE_IAM", invoker_members=("group:ops@example.com",), app_admin_emails=(),
                              source="compliance_flags")
    edge = VAR_TF + 'module "edge" {\n  source  = "../modules/acme-run"\n  members = var.m\n}\n'
    draft = {W + "edge.tf": edge, W + "m.auto.tfvars": 'm = ["allUsers"]\n'}
    st = ValidatorStack()
    st.register(AccessIdpValidator(resolved), "blocking")
    st.register(K.IacFileKindValidator(), "blocking")
    persona = Persona({W + "m.auto.tfvars": "", W + "edge.tf": edge})
    tree, report = RepairLoop(_loop_ctx(draft, persona, stack=st)).run(dict(draft))
    assert report.status == "PASS" and tree[W + "m.auto.tfvars"] == ""
    (t,) = persona.tasks
    assert sorted((x["code"], x["file"]) for x in t.diagnostics) == [
        ("POLICY.PUBLIC_PRINCIPAL_IN_MODULE_CALL", W + "edge.tf"), (TFVARS, W + "m.auto.tfvars")]


# ------------------------------------------------------------------------------------------------ RT F1: committed bytes
HUMAN_REPO = {"terraform.tfvars": ACCESS_HCL, "apps/x.tofu": TOPIC_TF, "apps/x/main.py": "x = 1\n",
              W + "iac_intent.json": '{"schema": "iac_intent/v1"}', W + "team.auto.tfvars": ACCESS_HCL}


def _validate_draft(draft, committed, intent_mode=False):
    """RepairLoop.validate on `draft` with the committed repository files (the real context: draft keys are
    LLM-authored, committed files pre-existing, preexisting_files passed to the validators)."""
    st = ValidatorStack()
    st.register(K.IacFileKindValidator(intent_mode=intent_mode), "blocking")
    ctx = _loop_ctx(draft, stack=st, preexisting_files=committed)
    asm = ctx.assemble(dict(draft))
    report, _ = RepairLoop(ctx).validate(draft, asm, 0)
    return report


@pytest.mark.parametrize("make_draft", [qa_repair.repair_draft, deploy_repair.repair_draft],
                         ids=["qa-repair", "deploy-intent-repair"])
def test_negative_repair_drafts_holding_a_persons_committed_files_have_no_finding(make_draft):
    draft = make_draft(HUMAN_REPO)
    assert {"terraform.tfvars", "apps/x.tofu"} <= set(draft)   # echoed into the draft: LLM_AUTHORED by key
    report = _validate_draft(draft, HUMAN_REPO, intent_mode=make_draft is deploy_repair.repair_draft)
    assert report.status == "PASS" and report.diagnostics == []


@pytest.mark.parametrize("make_draft", [qa_repair.repair_draft, deploy_repair.repair_draft],
                         ids=["qa-repair", "deploy-intent-repair"])
def test_a_changed_or_new_ai_file_in_a_repair_draft_is_still_a_finding(make_draft):
    draft = make_draft(HUMAN_REPO)
    draft["terraform.tfvars"] = ACCESS_HCL + 'enable_direct_iap = true\n'   # changed by the AI
    draft["new.auto.tfvars.json"] = ACCESS_JSON                              # new
    draft["apps/x.tofu"] = TOPIC_TF + "# edited\n"                         # changed
    report = _validate_draft(draft, HUMAN_REPO)
    assert sorted((d.code, d.file) for d in report.diagnostics) == sorted([
        (TOFU, "apps/x.tofu"), (TFVARS, "new.auto.tfvars.json"), (TFVARS, "terraform.tfvars")])


def test_negative_an_unchanged_echo_in_a_regeneration_is_no_finding_and_a_new_one_is():
    committed = {"terraform.tfvars": ACCESS_HCL, W + "custom.tf": TOPIC_TF}
    draft = {"terraform.tfvars": ACCESS_HCL, W + "custom.tf": TOPIC_TF}
    assert _validate_draft(draft, committed).status == "PASS"
    assert _found(_run(draft, committed=committed)) == []
    assert _found(_run(draft, committed={})) == [(TFVARS, "terraform.tfvars")]


def test_provenance_never_records_these_kinds():
    # RT F2: only root .tf files are LLM IaC paths (what the provenance store records), so a committed AI file of
    # these kinds is the user's on the next run
    draft = {W + "custom.tf": TOPIC_TF, W + "extra.tf": TOPIC_TF.replace('"t"', '"u"'), W + "a.auto.tfvars": ACCESS_HCL,
             W + "terraform.tfvars.json": ACCESS_JSON, W + "edge.tofu": TOPIC_TF, "x.auto.tfvars": ACCESS_HCL}
    res = assemble_root_module(dict(draft), llm_paths=set(draft), preexisting=set(), root_keys=set())
    assert all(p.endswith(".tf") for p in res.llm_iac_paths) and W + "extra.tf" in res.llm_iac_paths


# ------------------------------------------------------------------------------------------------ RT F4: intent .tofu
TWO_BLOCKS = TOPIC_TF + 'resource "google_pubsub_topic" "u" {\n  name = "u"\n}\n'


def test_intent_mode_names_every_dropped_tofu_declaration():
    got = _run({W + "edge.tofu": TWO_BLOCKS}, intent_mode=True)
    assert sorted((d.code, d.file, d.block_address, d.line) for d in got) == [
        (TOFU, W + "edge.tofu", "google_pubsub_topic.t", 1), (TOFU, W + "edge.tofu", "google_pubsub_topic.u", 4)]
    assert {d.hint for d in got} == {T.HINT_TOFU_FILE_NOT_ALLOWED_INTENT}
    assert "iac_intent.json" not in T.HINT_TOFU_FILE_NOT_ALLOWED_INTENT
    for path, text in [(W + "a.tofu.json", '{"resource": {}}'), (W + "b.tofu", "not { hcl"), (W + "c.tofu", "")]:
        (d,) = _run({path: text}, intent_mode=True)
        assert (d.code, d.block_address, d.hint) == (TOFU, None, T.HINT_TOFU_FILE_NOT_ALLOWED_INTENT)


def test_intent_mode_tofu_repair_returns_the_new_tf_key_empty_and_is_accepted():
    st = ValidatorStack()
    st.register(K.IacFileKindValidator(intent_mode=True), "blocking")
    st.register(IacHclPathValidator(), "blocking")
    draft = {W + "edge.tofu": TWO_BLOCKS}
    persona = Persona({W + "edge.tf": ""})
    tree, report = RepairLoop(_loop_ctx(draft, persona, stack=st)).run(dict(draft))
    assert report.status == "PASS" and tree == {W + "edge.tf": ""}
    (t,) = persona.tasks
    assert t.renames == [W + "edge.tofu"] and len(t.diagnostics) == 2


def test_v2n_gets_the_intent_mode_from_the_stack():
    def v2n(stack):
        (reg,) = [r for r in stack._regs if r.validator.id == "V2n"]
        return reg.validator.intent_mode
    assert v2n(build_step1_stack(validate_client=None, verifier_factory=None)) is False
    assert v2n(build_step1_stack(validate_client=None, verifier_factory=None, iac_intent=object())) is True


def test_off_mode_tofu_hint_renames_in_the_same_directory():
    assert "in the same directory" in T.HINT_TOFU_FILE_NOT_ALLOWED
    assert "directly under infra/workload" not in T.HINT_TOFU_FILE_NOT_ALLOWED


def test_ownership_is_not_asked_for_paths_of_other_kinds():
    asked = []

    def own(p):
        asked.append(p)
        return Ownership.LLM_AUTHORED
    _run({W + "custom.tf": TOPIC_TF, "apps/x/main.py": "x", W + "a.auto.tfvars": ACCESS_HCL}, own=own)
    assert asked == [W + "a.auto.tfvars"]
