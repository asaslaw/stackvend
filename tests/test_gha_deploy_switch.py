import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

"""GHA-DEPLOY-SWITCH (register row GHA-DEPLOY-SWITCH, owner 10-30; brief SAT-34; OQ-37 = deploy time, OQ-38 = accept):
a per-workload switch for the GitHub Actions deploy path (default on).

Chain under test:
- shared.github_identity: GITHUB_ACTIONS_DEPLOY_FIELD / github_actions_deploy_enabled (missing = on, never coerced).
- infra/modules/workload-foundation/base: input enable_github_actions_deploy (bool, default true); `count` on the pool,
  provider, deployer SA, WIF binding and every deployer grant; moved blocks X -> X[0]; outputs one(...). The edits are
  exactly tests/gha_switch_render.EDITS (undoing them gives main 3dfe3f73 byte for byte). OpenTofu's own semantics of
  the moved pattern (no change with the switch on; exactly the counted resources destroyed with it off) are checked
  offline on a terraform_data model; the real module with a mock provider is fixtures/fd4at/fd4at.tftest.hcl (needs a
  provider mirror: tests/test_fd4at_ci_least_privilege.py).
- terraform_engine / Express: on (default) renders byte-identically (pinned sha256 from the R1-WIF base); off forwards
  the input and declares the root variable (default false).
- handler: off on a GitHub workload -> no deploy workflow, the tree's deploy-*.yml listed for deletion (typed), the
  foundation rendered off; Serverless Git ignores the switch; an invalid record value is a typed refusal.
- gateway main.py: the deletions reach commit_and_open_pr(files_to_delete=...) only when there are any.
- tf-applier (service.py): gha_deploy_tfvar / root_declares_variable (deploy-time value; typed stops).
- vending redeploy: no deploy secrets when off.
- Control Center: create (GitHub only, re-create keeps the stored value), PATCH (admin, audited), details field.
"""
import ast
import hashlib
import json
import os
import shutil
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO, "apps", "orchestrator-gateway")
for _p in (GATEWAY, REPO, os.path.dirname(__file__)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from shared import github_identity as gi  # noqa: E402
from gha_switch_render import EDITS, without_gha_switch  # noqa: E402

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

MOD = os.path.join(REPO, "infra", "modules", "workload-foundation", "base")
CC_MOD = os.path.join(REPO, "apps", "control-center", "infra", "modules", "workload-foundation", "base")
FIX = os.path.join(REPO, "tests", "fixtures", "gha_switch")
SWITCHED = {  # every GitHub Actions deploy resource: type -> names
    "google_iam_workload_identity_pool": {"github_pool"},
    "google_iam_workload_identity_pool_provider": {"github_provider"},
    "google_service_account": {"github_deployer"},
    "google_service_account_iam_member": {"github_wif_binding", "deployer_runtime_sa_user", "deployer_build_sa_user"},
    "google_project_iam_member": {"deployer_run_source_developer", "deployer_logging_viewer",
                                  "deployer_container_developer"},
}
LINE = "  enable_github_actions_deploy = var.enable_github_actions_deploy\n"
TOFU = shutil.which("tofu")


def te():
    from developer_agent import terraform_engine
    return terraform_engine


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


# ------------------------------------------------------------------------------------------------ the record value
def test_recorded_switch_missing_is_on_and_only_bools_count():
    assert gi.GITHUB_ACTIONS_DEPLOY_FIELD == "github_actions_deploy"
    assert gi.github_actions_deploy_enabled(None) is True
    assert gi.github_actions_deploy_enabled(True) is True
    assert gi.github_actions_deploy_enabled(False) is False
    for bad in ("false", "true", 0, 1, [], {}, MagicMock()):
        with pytest.raises(gi.GitHubActionsDeploySwitchInvalid):
            gi.github_actions_deploy_enabled(bad)


# ------------------------------------------------------------------------------------------------ golden module
@pytest.mark.parametrize("name", sorted(EDITS))
def test_module_edits_are_exactly_the_pinned_pairs(name):
    """Do No Harm: undoing exactly the pinned edits gives the base module file (main 3dfe3f73) byte for byte, and
    every edit is present once (tests/gha_switch_render.py is what older pins use)."""
    now = _read(os.path.join(MOD, name))
    text = now
    for before, after in reversed(EDITS[name]):   # FD-7L 2b: a later edit (the build-SA grant) is undone first
        assert text.count(after) == 1, after[:80]
        text = text.replace(after, before, 1)
    assert without_gha_switch(name, now) == text == _read(os.path.join(FIX, f"pre_gha_{name}.txt"))


def test_only_the_switched_files_changed_and_copies_are_identical():
    import ast as _ast
    disk = {n: _read(os.path.join(MOD, n)) for n in os.listdir(MOD) if n.endswith(".tf")}
    assert {n: _read(os.path.join(CC_MOD, n)) for n in os.listdir(CC_MOD) if n.endswith(".tf")} == disk
    for rel in ("shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared",
                "mcp-servers/terraform/shared"):
        tree = _ast.parse(_read(os.path.join(REPO, rel, "builtin_modules_payload.py")))
        node = next(n for n in tree.body if isinstance(n, _ast.AnnAssign) and n.target.id == "BUILTIN_MODULE_FILES")
        assert _ast.literal_eval(node.value)["workload-foundation/base"] == disk, rel


def _module_doc():
    out = {"resource": {}, "moved": [], "locals": {}, "variable": {}, "output": {}}
    for n in sorted(os.listdir(MOD)):
        if not n.endswith(".tf"):
            continue
        doc = hcl2.loads(_read(os.path.join(MOD, n)))
        for block in doc.get("resource", []):
            for t, named in block.items():
                for name, body in named.items():
                    out["resource"][(t, name)] = body
        out["moved"] += doc.get("moved", [])
        for block in doc.get("locals", []):
            out["locals"].update(block)
        for block in doc.get("variable", []):
            out["variable"].update(block)
        for block in doc.get("output", []):
            out["output"].update(block)
    return out


def test_every_deploy_resource_and_only_those_is_counted_by_the_switch():
    doc = _module_doc()
    counted = {k for k, body in doc["resource"].items() if body.get("count") == "${local.github_actions_deploy_count}"}
    assert counted == {(t, n) for t, names in SWITCHED.items() for n in names}
    for k in counted:
        assert doc["resource"][k]["count"] == "${local.github_actions_deploy_count}", k
    assert doc["locals"]["github_actions_deploy_count"] == "${var.enable_github_actions_deploy ? 1 : 0}"
    v = doc["variable"]["enable_github_actions_deploy"]
    assert v["default"] is True and v["nullable"] is False and v["type"] in ("${bool}", "bool")
    # nothing outside the switched set references a switched resource (it would fail with count = 0)
    for k, body in doc["resource"].items():
        if k in counted:
            continue
        text = json.dumps(body)
        assert not any(f"{t}.{n}" in text for t, names in SWITCHED.items() for n in names), k


def test_moved_blocks_keep_every_existing_instance_as_index_zero():
    doc = _module_doc()
    pairs = {(m["from"], m["to"]) for m in doc["moved"]}
    expected = {(f"${{{t}.{n}}}", f"${{{t}.{n}[0]}}") for t, names in SWITCHED.items() for n in names}
    assert pairs == expected


def test_outputs_are_null_when_off_and_the_same_value_when_on():
    out = _module_doc()["output"]
    assert out["deployer_sa_email"]["value"] == "${one(google_service_account.github_deployer[*].email)}"
    assert out["wif_pool_name"]["value"] == "${one(google_iam_workload_identity_pool.github_pool[*].name)}"
    assert out["wif_provider_name"]["value"] == \
        "${one(google_iam_workload_identity_pool_provider.github_provider[*].name)}"


def test_developer_prompt_contract_does_not_advertise_the_input():
    from developer_agent import contract_inspector as ci
    try:
        contract = ci.get_golden_module_contract("workload-foundation/base", force_refresh=True)
    finally:
        ci._CONTRACT_CACHE.pop("workload-foundation/base", None)
    assert "enable_github_actions_deploy" not in contract
    assert "enable_github_actions_deploy" in ci._EMBEDDED_MODULE_CONTRACTS["workload-foundation/base"]["inputs"]


# ------------------------------------------------------------------------------------------------ OpenTofu semantics
_TOY_BEFORE = """resource "terraform_data" "pool" {
  input = "pool"
}

resource "terraform_data" "deployer_role" {
  input = terraform_data.pool.output
}

resource "terraform_data" "runtime" {
  input = "runtime"
}
"""
_TOY_AFTER = """variable "enable_github_actions_deploy" {
  type     = bool
  default  = true
  nullable = false
}

locals {
  github_actions_deploy_count = var.enable_github_actions_deploy ? 1 : 0
}

moved {
  from = terraform_data.pool
  to   = terraform_data.pool[0]
}

moved {
  from = terraform_data.deployer_role
  to   = terraform_data.deployer_role[0]
}

resource "terraform_data" "pool" {
  count = local.github_actions_deploy_count
  input = "pool"
}

resource "terraform_data" "deployer_role" {
  count = local.github_actions_deploy_count
  input = terraform_data.pool[0].output
}

resource "terraform_data" "runtime" {
  input = "runtime"
}
"""


def _tofu(cwd, *args):
    env = hermetic_guard.child_env(extra={"TF_IN_AUTOMATION": "1", "TF_DATA_DIR": os.path.join(cwd, ".tfdata")})
    res = subprocess.run([TOFU, *args], cwd=cwd, env=env, capture_output=True, text=True, timeout=300)
    assert res.returncode == 0, res.stdout + res.stderr
    return res.stdout


def _toy_root(root_extra, switch):
    arg = "" if switch is None else f"  enable_github_actions_deploy = {str(switch).lower()}\n"
    return f'module "foundation" {{\n  source = "./mod"\n{arg}}}\n' + root_extra


def _toy_state(module):
    """A v4 state fixture with the three toy resources as written by OpenTofu 1.13 for the config before the switch
    (`module` = "module.foundation", or None for the legacy root); written here, never by `tofu apply`."""
    prefix = f"{module}." if module else ""
    resources = []
    for name, value, deps in (("deployer_role", "pool", [f"{prefix}terraform_data.pool"]), ("pool", "pool", None),
                              ("runtime", "runtime", None)):
        inst = {"schema_version": 0,
                "attributes": {"id": f"00000000-0000-0000-0000-00000000000{len(resources)}",
                               "input": {"value": value, "type": "string"},
                               "output": {"value": value, "type": "string"}, "triggers_replace": None},
                "sensitive_attributes": []}
        if deps:
            inst["dependencies"] = deps
        res = {"mode": "managed", "type": "terraform_data", "name": name,
               "provider": 'provider["terraform.io/builtin/terraform"]', "instances": [inst]}
        if module:
            res = dict({"module": module}, **res)
        resources.append(res)
    return {"version": 4, "terraform_version": "1.9.0", "serial": 1,
            "lineage": "00000000-0000-0000-0000-0000000000aa", "outputs": {}, "resources": resources,
            "check_results": None}


def _plan_actions(cwd):
    _tofu(cwd, "plan", "-input=false", "-no-color", "-refresh=false", "-out=tfplan")
    plan = json.loads(_tofu(cwd, "show", "-json", "tfplan"))
    return {rc["address"]: tuple(rc["change"]["actions"]) for rc in plan.get("resource_changes", [])}


@pytest.mark.skipif(not TOFU, reason="needs a local OpenTofu; uses only the built-in terraform_data (no provider)")
@pytest.mark.parametrize("legacy_root", [False, True], ids=["module-state", "legacy-root-state"])
def test_tofu_moved_to_index_zero_plans_no_change_on_and_exact_destroys_off(tmp_path, legacy_root):
    """The module's pattern on OpenTofu itself (plan only, state fixture): state written by the module before the
    switch (or, legacy, by the root before the foundation module existed, with the root moved.tf chain into the
    module) plans NO change with the switch on (default or explicit true), and with it off destroys exactly the
    counted resources, nothing else."""
    cwd = str(tmp_path)
    os.makedirs(os.path.join(cwd, "mod"))
    with open(os.path.join(cwd, "mod", "main.tf"), "w") as f:
        f.write(_TOY_AFTER)
    with open(os.path.join(cwd, "terraform.tfstate"), "w") as f:
        json.dump(_toy_state(None if legacy_root else "module.foundation"), f)
    root_moved = "".join(f"\nmoved {{\n  from = terraform_data.{n}\n  to   = module.foundation.terraform_data.{n}\n}}\n"
                         for n in ("pool", "deployer_role", "runtime")) if legacy_root else ""
    with open(os.path.join(cwd, "main.tf"), "w") as f:
        f.write(_toy_root(root_moved, None))
    _tofu(cwd, "init", "-input=false", "-no-color", "-backend=false")
    for switch in (None, True):
        with open(os.path.join(cwd, "main.tf"), "w") as f:
            f.write(_toy_root(root_moved, switch))
        actions = _plan_actions(cwd)
        assert {a for a, act in actions.items() if act != ("no-op",)} == set(), actions
        assert set(actions) == {"module.foundation.terraform_data.pool[0]",
                                "module.foundation.terraform_data.deployer_role[0]",
                                "module.foundation.terraform_data.runtime"}
    with open(os.path.join(cwd, "main.tf"), "w") as f:
        f.write(_toy_root(root_moved, False))
    actions = _plan_actions(cwd)
    assert {a: act for a, act in actions.items() if act != ("no-op",)} == {
        "module.foundation.terraform_data.pool[0]": ("delete",),
        "module.foundation.terraform_data.deployer_role[0]": ("delete",)}


# ------------------------------------------------------------------------------------------------ renders
def _renders(**kw):
    from developer_agent.handler import generate_service_workflow  # noqa: F401 (same import order as R1-WIF)
    from shared.express_synthesizer import ExpressHCLSynthesizer
    from rt14_bastion_zone_render import without_rt14_bastion_zone   # RT14-F1: bastion zone read, undone exactly
    out = {f"main.tf:{a}": without_rt14_bastion_zone(
        te().generate_golden_main_tf("r1wif-app", a, "", env_vars_override={}, **kw))
           for a in ("cloudrun", "gke-autopilot", "event-worker", "gce-bastion", "foundation-only")}
    out["variables.tf:default"] = te().generate_golden_variables_tf("r1wif-app", "acme/r1wif-app",
                                                                   region="us-central1", **kw)
    out["variables.tf:private"] = te().generate_golden_variables_tf(
        "r1wif-app", "acme/r1wif-app", allow_unauthenticated=False, enable_direct_iap=True,
        authorized_invoker_members=["user:a@example.com"], region="europe-west1", **kw)
    files = ExpressHCLSynthesizer(db=None).synthesize_workload(product_id="r1wif-app", project_id="r1wif-proj",
                                                               region="us-central1",
                                                               github_repo_full_name="acme/r1wif-app", **kw)
    out.update({f"express:{k}": v for k, v in files.items() if k.startswith("infra/workload/")})
    return out


def _base_shas():
    from test_r1_wif_default_branch import BASE_RENDER_SHA256
    return {k: v for k, v in BASE_RENDER_SHA256.items() if not k.startswith("workflow:")}


@pytest.mark.parametrize("kw", [{}, {"github_actions_deploy": True}])
def test_switch_on_renders_are_byte_identical_to_the_base(kw):
    assert {k: _sha(v) for k, v in _renders(**kw).items()} == _base_shas()


def test_switch_off_adds_exactly_the_forward_and_the_root_variable():
    on = _renders()
    off = _renders(github_actions_deploy=False)
    assert te().GHA_DEPLOY_SWITCH_LINE == LINE
    from shared import express_synthesizer as es
    assert es.GHA_DEPLOY_SWITCH_LINE == te().GHA_DEPLOY_SWITCH_LINE
    assert es.GHA_DEPLOY_SWITCH_VARIABLE_BLOCK == te().GHA_DEPLOY_SWITCH_VARIABLE_BLOCK
    block = te().GHA_DEPLOY_SWITCH_VARIABLE_BLOCK
    for k in on:
        if k.endswith("main.tf") or k.startswith("main.tf:"):
            assert off[k].count(LINE) == 1 and off[k].replace(LINE, "", 1) == on[k], k
            foundation = next(b["foundation"] for b in hcl2.loads(off[k])["module"] if "foundation" in b)
            assert foundation["enable_github_actions_deploy"] == "${var.enable_github_actions_deploy}", k
        elif "variables.tf" in k:
            assert off[k].count(block) == 1 and off[k].replace(block, "", 1) == on[k], k
            declared = {n: b for blk in hcl2.loads(off[k])["variable"] for n, b in blk.items()}
            assert declared["enable_github_actions_deploy"]["default"] is False, k
        else:
            assert off[k] == on[k], k


@pytest.mark.parametrize("bad", [None, 0, "false", MagicMock()])
def test_a_switch_that_is_not_a_bool_is_refused_by_every_render(bad):
    with pytest.raises(ValueError):
        te().generate_golden_main_tf("r1wif-app", "cloudrun", "", env_vars_override={}, github_actions_deploy=bad)
    with pytest.raises(ValueError):
        te().generate_golden_variables_tf("r1wif-app", "acme/r1wif-app", region="us-central1",
                                          github_actions_deploy=bad)
    from shared.express_synthesizer import ExpressHCLSynthesizer
    with pytest.raises(ValueError):
        ExpressHCLSynthesizer(db=None).synthesize_workload(product_id="r1wif-app", project_id="p",
                                                           github_repo_full_name="acme/r1wif-app",
                                                           github_actions_deploy=bad)


def test_express_copies_are_identical():
    texts = {_read(os.path.join(REPO, rel, "express_synthesizer.py"))
             for rel in ("shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared")}
    assert len(texts) == 1


# ------------------------------------------------------------------------------------------------ developer
def handler():
    from developer_agent import handler as h
    return h


def test_gha_workflow_paths_are_exactly_the_generated_deploy_files():
    tree = {".github/workflows/deploy-api.yml": "", ".github/workflows/deploy-web-ui.yml": "",
            ".github/workflows/ci.yml": "", ".github/workflows/deploy-x.yaml": "",
            ".github/workflows/sub/deploy-y.yml": "", "apps/deploy-z.yml": "", ".github/workflows/deploy-.yml": "",
            "docs/.github/workflows/deploy-a.yml": "", "README.md": ""}
    assert handler().gha_workflow_paths(tree) == [".github/workflows/deploy-api.yml",
                                                  ".github/workflows/deploy-web-ui.yml"]
    assert handler().gha_workflow_paths({}) == []


def test_recorded_switch_in_the_developer():
    rec = handler().DeveloperAgent._recorded_gha_deploy
    assert rec("p", None) is True and rec("p", True) is True and rec("p", False) is False
    from gate_errors import PlatformDefectError
    for bad in ("false", 1, {}):
        with pytest.raises(PlatformDefectError) as ei:
            rec("p", bad)
        assert getattr(ei.value, "reason", None) == "GHA_DEPLOY_SWITCH_INVALID"


def test_assembly_passes_the_switch_to_every_root_render_and_guards_both_workflow_sites():
    src = _read(os.path.join(GATEWAY, "developer_agent", "handler.py"))
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef) and n.name == "_assemble_tree")
    calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call) and getattr(c.func, "id", None) in
             ("generate_golden_main_tf", "generate_golden_variables_tf")]
    assert len(calls) == 4
    for c in calls:
        v = {k.arg: k.value for k in c.keywords}.get("github_actions_deploy")
        assert isinstance(v, ast.Name) and v.id == "gha_deploy_on"
    seg = ast.get_source_segment(src, fn)
    assert seg.count("gha_deploy_on") >= 7   # assignment, deletions, 2 workflow guards, 4 renders
    assert handler().AssemblyInputs.__dataclass_fields__["github_actions_deploy"].default is True


class _Doc:
    def __init__(self, pid, data):
        self.id = pid
        self._data = data
        self.exists = data is not None

    def to_dict(self):
        return dict(self._data or {})


def _fake_firestore(record):
    """workloads/<pid> = `record`; every other document does not exist; every query is empty."""
    def collection(name):
        col = MagicMock()
        col.document.side_effect = lambda pid: SimpleNamespace(
            get=lambda: _Doc(pid, record if name == "workloads" else None),
            collection=lambda sub: collection(sub), set=MagicMock(), update=MagicMock())
        col.stream.return_value = []
        col.where.return_value.stream.return_value = []
        col.where.return_value.limit.return_value.stream.return_value = []
        return col
    db = MagicMock()
    db.collection.side_effect = collection
    return SimpleNamespace(Client=lambda *a, **k: db)


def _generate(record, tree):
    from _lane19_fake_genai import FakeGenaiClient, canned_workload_files
    import google
    import google.cloud
    fake = _fake_firestore(record)
    fake_genai = MagicMock()   # google.genai (+ .types) stand-in; the fake client below answers
    with patch.dict(sys.modules, {"google.cloud.firestore": fake, "google.genai": fake_genai,
                                  "google.genai.types": fake_genai.types}), \
            patch.object(google.cloud, "firestore", fake, create=True), \
            patch.object(google, "genai", fake_genai, create=True), \
            patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false", "GITHUB_ORG": "example-org"}):
        dev = handler().DeveloperAgent(project_id="test-proj")
        dev.genai_client = FakeGenaiClient(files=canned_workload_files("ghaapp"))
        with patch.object(dev, "fetch_existing_repo_files", return_value=dict(tree)):
            files = dev.generate_code_files(product_id="ghaapp", spec_text="FastAPI app", task_dag=[],
                                            trace_id="trace-gha", allow_unauthenticated=True,
                                            architect_compute_intent={"target_compute_services": ["ghaapp"]},
                                            enable_direct_iap=False, domain_restricted_sharing=False)
    return files, dev.stack_run("trace-gha").get("gha_workflow_deletions")


TREE = {".github/workflows/deploy-ghaapp.yml": "name: old\n", ".github/workflows/ci.yml": "name: ci\n"}
RECORD = {"project_id": "ghaapp-1234", "project_number": "123456789012", "vcs_provider": "GITHUB",
          "github_repo": "example-org/ghaapp"}


def test_developer_switch_off_writes_no_workflow_and_lists_the_old_ones():
    files, deletions = _generate(dict(RECORD, github_actions_deploy=False), TREE)
    assert not [p for p in files if p.startswith(".github/workflows/")]
    assert deletions == [".github/workflows/deploy-ghaapp.yml"]
    assert files["infra/workload/main.tf"].count(LINE) == 1
    assert files["infra/workload/variables.tf"].count(te().GHA_DEPLOY_SWITCH_VARIABLE_BLOCK) == 1


@pytest.mark.parametrize("value", [None, True], ids=["missing", "true"])
def test_developer_switch_on_is_today(value):
    """Do No Harm: missing / true -> the deploy workflows are generated, nothing is deleted, no switch in the root."""
    record = dict(RECORD) if value is None else dict(RECORD, github_actions_deploy=value)
    files, deletions = _generate(record, TREE)
    assert ".github/workflows/deploy-ghaapp.yml" in files
    assert deletions == []
    assert "enable_github_actions_deploy" not in files["infra/workload/main.tf"]
    assert "enable_github_actions_deploy" not in files["infra/workload/variables.tf"]


def test_developer_serverless_git_ignores_the_switch():
    files, deletions = _generate(dict(RECORD, vcs_provider="SERVERLESS_GIT", github_repo="serverless-git/ghaapp.git",
                                      github_actions_deploy=False), TREE)
    assert deletions == []
    assert "enable_github_actions_deploy" not in files["infra/workload/main.tf"]


def test_gateway_passes_deletions_only_when_there_are_any():
    src = _read(os.path.join(GATEWAY, "main.py"))
    tree = ast.parse(src)
    helper = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                  and n.name == "_developer_gha_workflow_deletions")
    from typing import Any, List, Optional
    ns = {"Any": Any, "Optional": Optional, "List": List}
    exec(compile(ast.Module(body=[helper], type_ignores=[]), "main.py", "exec"), ns)  # noqa: S102 - repo code
    f = ns["_developer_gha_workflow_deletions"]
    assert f(SimpleNamespace(stack_run=lambda t: {"gha_workflow_deletions": ["a.yml"]}), "t") == ["a.yml"]
    assert f(SimpleNamespace(stack_run=lambda t: {"gha_workflow_deletions": []}), "t") == []
    assert f(SimpleNamespace(stack_run=lambda t: {}), "t") == []
    assert f(MagicMock(), "t") == []   # a mock agent (tests): no deletion
    assert f(SimpleNamespace(), "t") == []
    assert f(SimpleNamespace(stack_run=lambda t: {"gha_workflow_deletions": [1]}), "t") == []
    call = next(c for c in ast.walk(tree) if isinstance(c, ast.Call) and getattr(c.func, "attr", "") ==
                "commit_and_open_pr" and any(k.arg is None for k in c.keywords))
    starred = next(k.value for k in call.keywords if k.arg is None)
    assert "files_to_delete" in ast.unparse(starred) and "gha_deletions" in ast.unparse(starred)


# ------------------------------------------------------------------------------------------------ tf-applier
def _svc():
    tf = os.path.join(REPO, "mcp-servers", "terraform")
    if tf not in sys.path:
        sys.path.insert(0, tf)
    import service
    return service


ROOT_ON = {"main.tf": 'module "foundation" {\n  source = "./modules/workload-foundation/base"\n}\n',
           "variables.tf": 'variable "project_id" {\n  type = string\n}\n'}
ROOT_OFF = dict(ROOT_ON, **{"variables.tf": ROOT_ON["variables.tf"] + '\nvariable "enable_github_actions_deploy" {\n'
                                                                   '  type    = bool\n  default = false\n}\n'})


def test_tfvar_on_without_declaration_is_no_key():
    """Do No Harm: every workload before the switch (missing / true, root without the variable): no tfvars key."""
    s = _svc()
    for rec in (None, True):
        assert s.gha_deploy_tfvar(rec, "GITHUB", ROOT_ON) == (None, None)
        assert s.gha_deploy_tfvar(rec, None, ROOT_ON) == (None, None)


def test_tfvar_follows_the_record_for_a_root_that_declares_it():
    s = _svc()
    assert s.gha_deploy_tfvar(False, "GITHUB", ROOT_OFF) == ("false", None)
    assert s.gha_deploy_tfvar(True, "GITHUB", ROOT_OFF) == ("true", None)    # toggled back on: next deploy
    assert s.gha_deploy_tfvar(None, "GITHUB", ROOT_OFF) == ("true", None)


def test_tfvar_off_without_declaration_is_a_typed_stop():
    s = _svc()
    value, stop = s.gha_deploy_tfvar(False, "GITHUB", ROOT_ON)
    assert value is None and stop[0] == "APPLY.GHA_DEPLOY_SWITCH_NOT_IN_IAC"
    value, stop = s.gha_deploy_tfvar(False, "GITHUB", dict(ROOT_ON, **{"broken.tf": "resource {"}))
    assert value is None and stop[0] == "APPLY.GHA_DEPLOY_SWITCH_NOT_IN_IAC"


def test_tfvar_invalid_value_is_a_typed_stop_and_serverless_git_ignores_it():
    s = _svc()
    for bad in ("false", 0, {}):
        value, stop = s.gha_deploy_tfvar(bad, "GITHUB", ROOT_OFF)
        assert value is None and stop[0] == "GHA_DEPLOY_SWITCH_INVALID"
    assert s.gha_deploy_tfvar(False, "SERVERLESS_GIT", ROOT_ON) == (None, None)
    assert s.gha_deploy_tfvar("junk", "serverless_git", ROOT_ON) == (None, None)


def test_root_declares_variable_reads_root_files_only():
    s = _svc()
    assert s.root_declares_variable(ROOT_OFF, "enable_github_actions_deploy") is True
    assert s.root_declares_variable(ROOT_ON, "enable_github_actions_deploy") is False
    nested = dict(ROOT_ON, **{"modules/x/variables.tf": 'variable "enable_github_actions_deploy" {}\n'})
    assert s.root_declares_variable(nested, "enable_github_actions_deploy") is False
    commented = dict(ROOT_ON, **{"c.tf": '# variable "enable_github_actions_deploy" {}\n'})
    assert s.root_declares_variable(commented, "enable_github_actions_deploy") is False
    assert s.root_declares_variable(dict(ROOT_ON, **{"b.tf": "resource {"}), "x") is None


# ------------------------------------------------------------------------------------------------ vending
def test_vending_skips_the_deploy_secrets_only_when_off():
    src = _read(os.path.join(REPO, "apps", "project-vending", "vending.py"))
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_gha_deploy_secrets_skip")
    ns = {"Any": object, "GITHUB_ACTIONS_DEPLOY_FIELD": gi.GITHUB_ACTIONS_DEPLOY_FIELD,
          "github_actions_deploy_enabled": gi.github_actions_deploy_enabled, "logger": MagicMock()}
    fn.decorator_list = []
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "vending.py", "exec"), ns)  # noqa: S102 - repo code
    skip = ns["_gha_deploy_secrets_skip"]
    assert skip("p", None) is False and skip("p", True) is False
    assert skip("p", False) is True and skip("p", "false") is True
    writer = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_write_deploy_secrets")
    assert "if github_repo and not gha_skip:" in ast.get_source_segment(src, writer)
    for name in ("redeploy_workload", "vend_all"):   # OQ-15: both write through the one code path
        fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == name)
        assert any(isinstance(c, ast.Call) and getattr(c.func, "attr", "") == "_write_deploy_secrets"
                   for c in ast.walk(fn)), name


# ------------------------------------------------------------------------------------------------ Control Center
from test_l19_11_access_intake import ADMIN_H, MANAGER_H, FakeDB as CcFakeDB, _client, cc  # noqa: E402,F401


def _cc_create(wl, monkeypatch, body=None, initial=None):
    fake_db = CcFakeDB(initial)
    client = _client(wl, monkeypatch, fake_db)
    publisher = MagicMock()
    publisher.publish.return_value.result.return_value = "msg-1"
    settings = __import__("routes.settings", fromlist=["x"]).PlatformSettings()
    with patch.dict(os.environ, {"GITHUB_OWNER": "example-org", "MANAGED_WORKLOADS_FOLDER_ID": "111111111111"}), \
            patch.object(wl, "get_pubsub_publisher", return_value=publisher), \
            patch.object(wl, "get_platform_settings", return_value=settings):
        r = client.post("/api/workloads", json={"product_id": "shop-app", "spec_content": "a shop", **(body or {})},
                        headers=ADMIN_H)
    return r, fake_db


@pytest.mark.parametrize("body, stored", [({}, True), ({"github_actions_deploy": True}, True),
                                          ({"github_actions_deploy": False}, False)])
def test_cc_create_stores_the_switch_for_a_new_github_workload(cc, monkeypatch, body, stored):
    _, wl = cc
    r, fake_db = _cc_create(wl, monkeypatch, dict(body, vcs_provider="GITHUB"))
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"]["github_actions_deploy"] is stored


def test_cc_create_serverless_git_refuses_off_and_stores_nothing(cc, monkeypatch):
    _, wl = cc
    r, fake_db = _cc_create(wl, monkeypatch, {"vcs_provider": "SERVERLESS_GIT", "github_actions_deploy": False})
    assert r.status_code == 422 and "GHA_DEPLOY_SWITCH_NOT_GITHUB" in r.text
    assert "workloads/shop-app" not in fake_db
    r, fake_db = _cc_create(wl, monkeypatch, {"vcs_provider": "SERVERLESS_GIT"})
    assert r.status_code == 200, r.text
    assert "github_actions_deploy" not in fake_db["workloads/shop-app"]


@pytest.mark.parametrize("stored", [True, False, None])
def test_cc_recreate_keeps_the_stored_switch_and_refuses_a_different_answer(cc, monkeypatch, stored):
    _, wl = cc
    rec = {"product_id": "shop-app", "status": "ACTIVE", "vcs_provider": "GITHUB"}
    if stored is not None:
        rec["github_actions_deploy"] = stored
    initial = {"workloads/shop-app": rec}
    r, fake_db = _cc_create(wl, monkeypatch, {"vcs_provider": "GITHUB"}, initial=initial)
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"].get("github_actions_deploy") == stored   # unchanged, never written
    effective = True if stored is None else stored
    r, fake_db = _cc_create(wl, monkeypatch, {"vcs_provider": "GITHUB", "github_actions_deploy": not effective},
                            initial=initial)
    assert r.status_code == 409 and "GHA_DEPLOY_SWITCH_CHANGE_NEEDS_PATCH" in r.text
    assert fake_db["workloads/shop-app"].get("github_actions_deploy") == stored


def _patch_switch(wl, monkeypatch, initial, enabled, headers=ADMIN_H):
    fake_db = CcFakeDB(initial)
    client = _client(wl, monkeypatch, fake_db)
    r = client.patch("/api/workloads/shop-app/github-actions-deploy", json={"enabled": enabled}, headers=headers)
    return r, fake_db


def test_cc_patch_writes_the_switch_and_an_audit_entry(cc, monkeypatch):
    _, wl = cc
    initial = {"workloads/shop-app": {"product_id": "shop-app", "vcs_provider": "GITHUB"}}
    r, fake_db = _patch_switch(wl, monkeypatch, initial, False)
    assert r.status_code == 200, r.text
    assert r.json()["github_actions_deploy"] is False and r.json()["previous"] is None
    doc = fake_db["workloads/shop-app"]
    assert doc["github_actions_deploy"] is False and doc["github_actions_deploy_updated_by"] == "admin@example.com"
    audits = [v for k, v in fake_db.items() if k.startswith("workloads/shop-app/audit_logs/")]
    assert len(audits) == 1 and audits[0]["action"] == "GITHUB_ACTIONS_DEPLOY_CHANGED"
    assert audits[0]["previous"] is None and audits[0]["new"] is False
    assert fake_db.commits == 1   # one batch: the value and its audit entry together


def test_cc_patch_refusals(cc, monkeypatch):
    _, wl = cc
    sg = {"workloads/shop-app": {"product_id": "shop-app", "vcs_provider": "SERVERLESS_GIT"}}
    r, fake_db = _patch_switch(wl, monkeypatch, sg, False)
    assert r.status_code == 422 and "GHA_DEPLOY_SWITCH_NOT_GITHUB" in r.text
    assert "github_actions_deploy" not in fake_db["workloads/shop-app"]
    r, _ = _patch_switch(wl, monkeypatch, {}, False)
    assert r.status_code == 404
    gh = {"workloads/shop-app": {"product_id": "shop-app"}}
    r, fake_db = _patch_switch(wl, monkeypatch, gh, False, headers=MANAGER_H)
    assert r.status_code in (401, 403)
    assert "github_actions_deploy" not in fake_db["workloads/shop-app"]


def test_cc_switch_reader(cc):
    _, wl = cc
    assert wl._gha_deploy_switch({}, "GITHUB") is True
    assert wl._gha_deploy_switch({"github_actions_deploy": False}, "GITHUB") is False
    assert wl._gha_deploy_switch({"github_actions_deploy": False}, "SERVERLESS_GIT") is True
    assert wl._gha_deploy_switch({"github_actions_deploy": "no"}, "GITHUB") is None


def test_cc_express_reads_the_switch_from_the_record(cc, monkeypatch):
    _, wl = cc
    monkeypatch.setattr(wl, "db", CcFakeDB({"workloads/a": {"github_actions_deploy": False},
                                            "workloads/b": {}, "workloads/c": {"github_actions_deploy": "off"}}))
    assert wl._express_gha_deploy("a", "GITHUB") == (False, None)
    assert wl._express_gha_deploy("b", "GITHUB") == (True, None)
    assert wl._express_gha_deploy("missing", "GITHUB") == (True, None)
    assert wl._express_gha_deploy("c", "GITHUB")[1][0] == "GHA_DEPLOY_SWITCH_INVALID"
    assert wl._express_gha_deploy("a", "SERVERLESS_GIT") == (True, None)
    broken = MagicMock()
    broken.collection.return_value.document.return_value.get.side_effect = RuntimeError("down")
    monkeypatch.setattr(wl, "db", broken)
    assert wl._express_gha_deploy("a", "GITHUB")[1][0] == "GHA_DEPLOY_SWITCH_UNAVAILABLE"


def test_cc_express_synthesis_passes_the_switch_only_when_off():
    """Do No Harm: the Express synthesize call is unchanged while the switch is on (no new keyword)."""
    src = _read(os.path.join(REPO, "apps", "control-center", "routes", "workloads.py"))
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef)
              and n.name == "execute_express_provisioning")
    call = next(c for c in ast.walk(fn) if isinstance(c, ast.Call) and getattr(c.func, "attr", "") ==
                "synthesize_workload")
    assert "github_actions_deploy" not in {k.arg for k in call.keywords if k.arg}
    starred = [ast.unparse(k.value) for k in call.keywords if k.arg is None]
    assert starred == ["{} if gha_deploy else {'github_actions_deploy': False}"]


def _workspace_with_module(tmp_path, rel, files):
    d = tmp_path / rel
    d.mkdir(parents=True)
    for n, t in files.items():
        (d / n).write_text(t, encoding="utf-8")
    return str(tmp_path)


@pytest.mark.parametrize("rel", ["infra/modules/workload-foundation/base", "modules/workload-foundation/base"])
def test_self_heal_import_address_has_index_zero_for_the_switched_module(tmp_path, rel):
    """OQ-38: turning the switch back on within Google's 30-day pool retention goes through the existing WIF
    undelete + import self-heal; the import address must be the counted instance ([0]) of today's module."""
    s = _svc()
    ws = _workspace_with_module(tmp_path, rel, {n: _read(os.path.join(MOD, n)) for n in os.listdir(MOD)
                                                if n.endswith(".tf")})
    assert s.foundation_module_address(ws, "google_iam_workload_identity_pool", "github_pool") == \
        "module.foundation.google_iam_workload_identity_pool.github_pool[0]"
    assert s.foundation_module_address(ws, "google_iam_workload_identity_pool_provider", "github_provider") == \
        "module.foundation.google_iam_workload_identity_pool_provider.github_provider[0]"
    assert s.foundation_module_address(ws, "google_service_account", "github_deployer") == \
        "module.foundation.google_service_account.github_deployer[0]"
    assert s.foundation_module_address(ws, "google_service_account", "workload_sa") == \
        "module.foundation.google_service_account.workload_sa"


def test_self_heal_import_address_unchanged_for_a_module_vendored_before_the_switch(tmp_path):
    """Do No Harm: a workload whose repository still vendors the module from before the switch (IaC outdated) keeps
    today's address; an unreadable module or no module keeps it too."""
    s = _svc()
    pre = {n: _read(os.path.join(FIX, f"pre_gha_{n}.txt")) for n in ("wif.tf", "iam.tf", "variables.tf")}
    ws = _workspace_with_module(tmp_path / "a", "infra/modules/workload-foundation/base", pre)
    assert s.foundation_module_address(ws, "google_iam_workload_identity_pool", "github_pool") == \
        "module.foundation.google_iam_workload_identity_pool.github_pool"
    assert s.foundation_module_address(str(tmp_path / "none"), "google_service_account", "github_deployer") == \
        "module.foundation.google_service_account.github_deployer"
    broken = _workspace_with_module(tmp_path / "b", "infra/modules/workload-foundation/base", {"wif.tf": "resource {"})
    assert s.foundation_module_address(broken, "google_iam_workload_identity_pool", "github_pool") == \
        "module.foundation.google_iam_workload_identity_pool.github_pool"


# ------------------------------------------------------------------------------------------------ RT SAT-16/34 fixes
def test_rt_f5_recreate_with_an_unreadable_document_and_an_answer_is_503(cc, monkeypatch):
    _, wl = cc
    monkeypatch.setattr(wl, "_stored_workload_doc", lambda pid: None)
    initial = {"workloads/shop-app": {"product_id": "shop-app", "status": "ACTIVE", "vcs_provider": "GITHUB"}}
    r, fake_db = _cc_create(wl, monkeypatch, {"vcs_provider": "GITHUB", "github_actions_deploy": False},
                            initial=initial)
    assert r.status_code == 503 and "GHA_DEPLOY_SWITCH_UNAVAILABLE" in r.text
    assert "github_actions_deploy" not in fake_db["workloads/shop-app"]
    r, fake_db = _cc_create(wl, monkeypatch, {"vcs_provider": "GITHUB"}, initial=initial)   # no answer: as before
    assert r.status_code == 200, r.text
    assert "github_actions_deploy" not in fake_db["workloads/shop-app"]


def test_rt_f5_stored_invalid_value_with_an_answer_stays_409(cc, monkeypatch):
    _, wl = cc
    initial = {"workloads/shop-app": {"product_id": "shop-app", "status": "ACTIVE", "vcs_provider": "GITHUB",
                                      "github_actions_deploy": "off"}}
    r, _ = _cc_create(wl, monkeypatch, {"vcs_provider": "GITHUB", "github_actions_deploy": True}, initial=initial)
    assert r.status_code == 409 and "GHA_DEPLOY_SWITCH_CHANGE_NEEDS_PATCH" in r.text


def _agent_with_record(record=None, error=None):
    agent = handler().DeveloperAgent.__new__(handler().DeveloperAgent)
    db = MagicMock()
    get = db.collection.return_value.document.return_value.get
    if error is not None:
        get.side_effect = error
    else:
        get.return_value = _Doc("shop", record)
    agent.db = db
    # RT14-13 RT F1: the tree read also records the base head commit; a fixed one here (no backend read)
    agent._base_source = lambda product_id: type("_Head", (), {"head_sha": lambda self, branch: "0" * 40})()
    return agent


@pytest.mark.parametrize("record, branch", [
    ({"default_branch": "prod"}, "prod"),
    ({"default_branch": "release/v1.2-rc"}, "release/v1.2-rc"),
    ({"default_branch": "main"}, "main"),
    ({}, "main"),                                   # no recorded branch: main, as before
    (None, "main"),                                 # no record
    ({"default_branch": "bad branch"}, "main"),     # not a plain branch name: main (logged), never rewritten
    ({"default_branch": 7}, "main"),
])
def test_rt_f2_existing_tree_is_read_from_the_recorded_branch(record, branch):
    """RT F2: the developer's existing tree (incremental context, switch-off deletions) is the workload's recorded
    branch (FD-4CI-b-R1), main only when none is recorded."""
    agent = _agent_with_record(record)
    seen = {}
    with patch.object(handler().DeveloperAgent, "fetch_branch_files",
                      lambda self, product_id, branch_name="main": seen.setdefault("b", branch_name) and {}):
        agent.fetch_existing_repo_files("shop")
    assert seen["b"] == branch


def test_rt_f2_unreadable_record_or_no_store_reads_main():
    # RT14-28 (owner 11-14): an unreadable record is typed WORKLOAD_RECORD_UNREADABLE (was "main", logged); no store
    # client (eval harness) still reads main.
    from developer_agent.errors import WORKLOAD_RECORD_UNREADABLE, DeveloperStageError
    with pytest.raises(DeveloperStageError) as ei, patch.object(handler(), "WORKLOAD_RECORD_RETRY_WAIT_S", 0):
        _agent_with_record(error=RuntimeError("down"))._recorded_workload_branch("shop")
    assert ei.value.error_class == WORKLOAD_RECORD_UNREADABLE
    agent = handler().DeveloperAgent.__new__(handler().DeveloperAgent)
    agent.db = None
    assert agent._recorded_workload_branch("shop") == "main"
