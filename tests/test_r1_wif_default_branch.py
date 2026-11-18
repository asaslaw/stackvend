import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

"""FD-4CI-b-R1-WIF (register row FD-4CI-b-R1-WIF, owner 10-28): the workload foundation's GitHub Actions identity
federation trusts the workload's recorded default branch instead of only refs/heads/main.

Chain under test:
- infra/modules/workload-foundation/base: typed input github_default_branch (default "main", not nullable), validated
  with the platform's branch grammar (shared.settings.is_branch_name); the condition renders
  `assertion.ref == 'refs/heads/<branch>'` exactly. Semantic plan contract (main, feature branch, refused values):
  tests/fixtures/fd4at/fd4at.tftest.hcl via tests/test_fd4at_ci_least_privilege.py; here: the grammar is the same as
  is_branch_name on a corpus (Python mirror, and OpenTofu's own evaluation when a local tofu is available), and an
  upgrade with main changes nothing but the input (real-parser diff vs the base module, pinned below).
- developer_agent.terraform_engine: generate_golden_main_tf / generate_golden_variables_tf forward the branch only
  when it is not main; for main every render is byte-identical to the base (sha256 pinned from 9af503c4 + main
  70f4a0d1); anything that is not a plain branch name is refused.
- handler._assemble_tree passes AssemblyInputs.deploy_branch (workflow_branch of the recorded branch) to both renders.
- tf-applier's root tfvars and vending's redeploy secret names: mcp-servers/terraform/test_service.py::test_r1_wif_*
  and tests/test_flexible_folders.py::test_r1wif_*.
"""
import ast
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO, "apps", "orchestrator-gateway")
for _p in (GATEWAY, REPO):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from shared.settings import is_branch_name  # noqa: E402

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

MOD = os.path.join(REPO, "infra", "modules", "workload-foundation", "base")
FIXTURES = os.path.join(REPO, "tests", "fixtures", "r1_wif")
VAR = "var.github_default_branch"

# The module's three validation conditions, exactly (hcl2 renders each as "${...}").
CONDITIONS = [
    '${can(regex("^[A-Za-z0-9._/-]{1,100}$", var.github_default_branch)) && var.github_default_branch != "HEAD"}',
    '${!can(regex("^[-/.]", var.github_default_branch)) && !can(regex("[/.]$", var.github_default_branch)) && '
    '!can(regex("\\\\.\\\\.", var.github_default_branch))}',
    '${!can(regex("//", var.github_default_branch)) && !can(regex("/\\\\.", var.github_default_branch)) && '
    '!can(regex("\\\\.lock(/|$)", var.github_default_branch))}',
]

# sha256 of the renders at the base (9af503c4 merged with main 70f4a0d1, before this change).
BASE_RENDER_SHA256 = {
    "main.tf:cloudrun": "76278a05ba5325e7a2b1fd8340f96a646192fe3177423c7bd2c7a1793e5f6365",
    "main.tf:event-worker": "b6254359a65b48b0038217c58c3d7c1a870cc429fd9cdda3154d0ad6ab9c9aa3",
    "main.tf:foundation-only": "ed165f8751f21aa1f085e912de70b3955e4ec886d91514392cfb81fb586781fa",
    "main.tf:gce-bastion": "05ddcef8c1897edc136f01f6a2aeaefdef7ec905842cc67a5a512be99bad5c14",
    "main.tf:gke-autopilot": "369bd7dab073edb8f6cb167d296e582bb13fb10643fee0693156895371e76a0c",
    # SAT-02 / FD4BD-SENS (deliberate): the two variables.tf renders gained exactly `sensitive   = true` on
    # oauth_client_secret and firebase_api_key; without those two lines they are the base renders
    # (7ce18e64... / b59118db..., re-derived by test_sat02_variables_pins_differ_by_exactly_the_two_sensitive_lines).
    "variables.tf:default": "6171557163ef2228dbbf858ce2ae4e79671539038f128a6bb802f3a73a5dc909",
    "variables.tf:private": "d3f90f434f9730f313147d493203d3afe63144155fbc0d7bcf7d83c321efa498",
    # GHA-FIREBASE-ENV-NO-BLANK (deliberate): the FIREBASE_* pair left the Cloud Run deploy flag; the former pin
    # 4b2d5967... is today's render with exactly that pair put back (tests/test_gha_firebase_env_no_blank.py).
    "workflow:cloudrun": "e4faa6c916b0349975a5a152fd7745418ee9a425a30bc525e61bae40ee7219d5",
    "workflow:event-worker": "d76443c95a36369d0e5420f5c2ecaf9626e4269a36f35b95b1f7d95a9275f4f6",
    "workflow:gce-bastion": "5986bf05b36f69d31b2f08f76ec534858adb3dc4428755fefb02d72aa93f7a02",
    "workflow:gke-autopilot": "97d27d9bcc9b175a2eab56df87ba401ba44d12b0d8de17a886c3663c2a9f88ef",
    "express:infra/workload/main.tf": "e9672a729406ef6216daf172c15c0394dfea8157327f473dc27e4b93da436873",
    "express:infra/workload/outputs.tf": "ce4f8b0e461aa6c399755b20a53e486fdbfd3de0c982e07277c0e949ab10e061",
    "express:infra/workload/variables.tf": "20e2a4d576fe6ad867b1bfcd990c77b64270ae59862ecce5d0139c4864098480",
    "express:infra/workload/versions.tf": "05dc2e335e81992eed083b82ad9fdee5f1f78691bdc99bc6e4d6b60358756d91",
}
ARCHETYPES = ("cloudrun", "gke-autopilot", "event-worker", "gce-bastion", "foundation-only")

FOUNDATION_ARG_LINE = "  github_default_branch = var.github_default_branch\n"
ROOT_VARIABLE_BLOCK = (
    '\nvariable "github_default_branch" {\n'
    '  description = "The workload\'s recorded default branch, the one branch the WIF condition accepts '
    '(FD-4CI-b-R1-WIF). Supplied by the platform at apply time."\n'
    "  type        = string\n"
    '  default     = "{branch}"\n'
    "}\n"
)

VALID = ["main", "develop", "release/v1.2_rc-1", "feature/x", "a", "x" * 100, "head", "HEADS", "feature/HEAD",
         "a.b", "v1.0", "a/b/c", "_x", "x_", "a-b"]
INVALID = ["", "HEAD", "main' || true || '", "feature/*", "a..b", "x.lock", "x.lock/y", "feature/.hidden", ".x",
           "-x", "/x", "x/", "x.", "a//b", "x" * 101, "a b", "a\nb", "ü", "a:b", "a~b", "a^b", "a?b", "a[b", "a\\b",
           "a@{b", "a'b", 'a"b', "a\n", "main\n", "x.lock\n"]


def te():
    from developer_agent import terraform_engine
    return terraform_engine


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _variables():
    with open(os.path.join(MOD, "variables.tf"), encoding="utf-8") as f:
        doc = hcl2.load(f)
    return {n: body for block in doc["variable"] for n, body in block.items()}


def _mirror(v):
    """The module's three conditions, term by term, in Python `re`. RT F2: RE2's `^` / `$` (no multi-line flag) are
    start / end of text; Python's `$` also matches before a final newline, so the mirror uses `\\A` / `\\Z`."""
    import re
    return (bool(re.search(r"\A[A-Za-z0-9._/-]{1,100}\Z", v)) and v != "HEAD"
            and not re.search(r"\A[-/.]", v) and not re.search(r"[/.]\Z", v) and not re.search(r"\.\.", v)
            and not re.search(r"//", v) and not re.search(r"/\.", v) and not re.search(r"\.lock(/|\Z)", v))


def _corpus():
    rng = random.Random(20261028)
    alphabet = "aZ09._-/HEADlock*' :~\n"
    fuzz = {"".join(rng.choice(alphabet) for _ in range(rng.randint(1, 9))) for _ in range(4000)}
    return VALID + INVALID + sorted(fuzz)


# ------------------------------------------------------------------------------------------------ module input
def test_module_input_is_typed_defaulted_and_validated_with_the_branch_grammar():
    v = _variables()["github_default_branch"]
    assert v["type"] == "${string}" or v["type"] == "string"
    assert v["default"] == "main" and v["nullable"] is False
    assert [val["condition"] for val in v["validation"]] == CONDITIONS


def test_module_input_block_is_exactly_the_pinned_addition():
    """tests/r1_wif_render.py (used by older byte-identity pins of variables.tf) is the block, once; removing it gives
    the base file byte for byte."""
    from r1_wif_render import MODULE_VARIABLE_BLOCK, without_r1_wif
    from gha_switch_render import without_gha_switch   # GHA-DEPLOY-SWITCH: its own input, undone exactly
    with open(os.path.join(MOD, "variables.tf"), encoding="utf-8") as f:
        now = without_gha_switch("variables.tf", f.read())
    with open(os.path.join(FIXTURES, "pre_r1_wif_variables.tf.txt"), encoding="utf-8") as f:
        assert now.count(MODULE_VARIABLE_BLOCK) == 1 and without_r1_wif(now) == f.read()


def test_validation_grammar_equals_is_branch_name_on_a_corpus():
    """The HCL rule (mirrored term by term) refuses / accepts exactly what shared.settings.is_branch_name does."""
    diff = [v for v in _corpus() if _mirror(v) != is_branch_name(v)]
    assert diff == []
    assert all(is_branch_name(v) for v in VALID) and not any(is_branch_name(v) for v in INVALID)


def test_condition_renders_the_branch_into_one_exact_ref_clause():
    provider = _blocks(os.path.join(MOD, "wif.tf"))[
        ("resource", "google_iam_workload_identity_pool_provider", "github_provider")]
    cond = provider["attribute_condition"]
    assert cond == ("assertion.repository == '${var.github_repo_full_name}'${local.wif_repository_id_clause} && "
                    "assertion.ref == 'refs/heads/${var.github_default_branch}' && "
                    "assertion.event_name in ['push','workflow_dispatch']")
    # exactly one place reads the input, as an exact equality operand (no startsWith / matches / wildcard)
    assert cond.count(VAR) == 1 and "startsWith" not in cond and "matches" not in cond and "*" not in cond


def _blocks(path, normalize=lambda t: t):
    with open(path, encoding="utf-8") as f:
        doc = hcl2.loads(normalize(f.read()))
    out = {}
    for kind in ("resource", "variable", "locals", "output", "data"):
        for block in doc.get(kind, []):
            for k, body in block.items():
                if kind == "resource":
                    for n, b in body.items():
                        out[(kind, k, n)] = b
                else:
                    out[(kind, k)] = body
    return out


@pytest.mark.parametrize("name", ["wif.tf", "variables.tf"])
def test_upgrade_with_main_changes_only_the_input(name):
    """Do No Harm (existing workloads, IaC outdated -> Upgrade IaC with main): versus the base module (fixture =
    9af503c4), the only parsed differences are the new input and the ref clause, and the ref clause with the input's
    default ("main") is the base text byte for byte, so the plan has no change."""
    from gha_switch_render import without_gha_switch   # GHA-DEPLOY-SWITCH: its own edits, undone exactly
    pre = _blocks(os.path.join(FIXTURES, f"pre_r1_wif_{name}.txt"))
    now = _blocks(os.path.join(MOD, name), normalize=lambda t: without_gha_switch(name, t))
    changed = {k for k in set(pre) | set(now) if pre.get(k) != now.get(k)}
    if name == "variables.tf":
        assert changed == {("variable", "github_default_branch")} and ("variable", "github_default_branch") not in pre
    else:
        key = ("resource", "google_iam_workload_identity_pool_provider", "github_provider")
        assert changed == {key}
        p, n = dict(pre[key]), dict(now[key])
        assert n.pop("attribute_condition").replace("${var.github_default_branch}", "main") == \
            p.pop("attribute_condition")
        assert p == n


def test_cc_copy_and_payload_entries_equal_the_module():
    rels = ["shared/builtin_modules_payload.py", "apps/control-center/shared/builtin_modules_payload.py",
            "apps/orchestrator-gateway/shared/builtin_modules_payload.py",
            "mcp-servers/terraform/shared/builtin_modules_payload.py"]
    disk = {n: open(os.path.join(MOD, n), encoding="utf-8").read() for n in os.listdir(MOD) if n.endswith(".tf")}
    cc = os.path.join(REPO, "apps", "control-center", "infra", "modules", "workload-foundation", "base")
    assert {n: open(os.path.join(cc, n), encoding="utf-8").read() for n in os.listdir(cc) if n.endswith(".tf")} == disk
    for rel in rels:
        with open(os.path.join(REPO, rel), encoding="utf-8") as f:
            tree = ast.parse(f.read())
        node = next(n for n in tree.body if isinstance(n, ast.AnnAssign) and n.target.id == "BUILTIN_MODULE_FILES")
        assert ast.literal_eval(node.value)["workload-foundation/base"] == disk, rel


_TOFU = os.environ.get("STACKVEND_PINNED_TOFU") or shutil.which("tofu")


@pytest.mark.skipif(not _TOFU, reason="needs a local OpenTofu (STACKVEND_PINNED_TOFU or tofu on PATH); no providers")
def test_tofu_evaluates_the_module_conditions_like_is_branch_name(tmp_path):
    """OpenTofu's own regex (RE2) and operators on the exact condition text: same verdicts as is_branch_name."""
    corpus = [v for v in _corpus() if "$" not in v and "%" not in v]
    cond = " && ".join(f"({c[2:-1].replace(VAR, 'b')})" for c in CONDITIONS)
    expr = f"jsonencode([for b in {json.dumps(corpus)} : {cond}])\n"
    env = hermetic_guard.child_env(extra={"TF_IN_AUTOMATION": "1", "TF_DATA_DIR": str(tmp_path / "tfdata")})
    res = subprocess.run([_TOFU, "console"], cwd=str(tmp_path), input=expr, env=env, capture_output=True, text=True,
                         timeout=300)
    assert res.returncode == 0, res.stdout + res.stderr
    verdicts = json.loads(json.loads(res.stdout.strip()))
    assert len(verdicts) == len(corpus)
    assert [v for v, ok in zip(corpus, verdicts) if ok != is_branch_name(v)] == []


# ------------------------------------------------------------------------------------------------ renders
def _renders(**branch):
    from developer_agent.handler import generate_service_workflow
    from shared.express_synthesizer import ExpressHCLSynthesizer
    from rt14_bastion_zone_render import without_rt14_bastion_zone   # RT14-F1: bastion zone read, undone exactly
    out = {f"main.tf:{a}": without_rt14_bastion_zone(
        te().generate_golden_main_tf("r1wif-app", a, "", env_vars_override={}, **branch))
           for a in ARCHETYPES}
    out["variables.tf:default"] = te().generate_golden_variables_tf("r1wif-app", "acme/r1wif-app", region="us-central1",
                                                                   **branch)
    out["variables.tf:private"] = te().generate_golden_variables_tf(
        "r1wif-app", "acme/r1wif-app", allow_unauthenticated=False, enable_direct_iap=True,
        authorized_invoker_members=["user:a@example.com"], region="europe-west1", **branch)
    for a in ("cloudrun", "event-worker", "gke-autopilot", "gce-bastion"):
        out[f"workflow:{a}"] = generate_service_workflow("api", "r1wif-app", "r1wif-proj", "123", archetype=a,
                                                         region="us-central1")
    files = ExpressHCLSynthesizer(db=None).synthesize_workload(product_id="r1wif-app", project_id="r1wif-proj",
                                                               region="us-central1",
                                                               github_repo_full_name="acme/r1wif-app")
    out.update({f"express:{k}": v for k, v in files.items() if k.startswith("infra/workload/")})
    return out


@pytest.mark.parametrize("branch", [{}, {"github_default_branch": "main"}])
def test_main_renders_are_byte_identical_to_the_base(branch):
    assert {k: _sha(v) for k, v in _renders(**branch).items()} == BASE_RENDER_SHA256


def test_sat02_variables_pins_differ_by_exactly_the_two_sensitive_lines():
    before = {"variables.tf:default": "7ce18e642930f0d318a633213567c7755400812e769402b87d99ab45e3279137",
              "variables.tf:private": "b59118db8be3381b2033085742def71adc4b0321ef7acc3689d0b767ded13865"}
    renders = _renders()
    for k, sha in before.items():
        assert renders[k].count("  sensitive   = true\n") == 2, k
        assert _sha(renders[k].replace("  sensitive   = true\n", "")) == sha, k


@pytest.mark.parametrize("branch", ["develop", "release/v1.2_rc-1"])
def test_a_recorded_branch_adds_exactly_the_forward_and_the_root_variable(branch):
    main = _renders()
    other = _renders(github_default_branch=branch)
    block = ROOT_VARIABLE_BLOCK.replace("{branch}", branch)
    for k in main:
        if k.startswith("main.tf:"):
            assert other[k].count(FOUNDATION_ARG_LINE) == 1, k
            assert other[k].replace(FOUNDATION_ARG_LINE, "", 1) == main[k], k
            foundation = next(b["foundation"] for b in hcl2.loads(other[k])["module"] if "foundation" in b)
            assert foundation["github_default_branch"] == "${var.github_default_branch}"
        elif k.startswith("variables.tf:"):
            assert other[k].count(block) == 1, k
            assert other[k].replace(block, "", 1) == main[k], k
            declared = {n: b for blk in hcl2.loads(other[k])["variable"] for n, b in blk.items()}
            assert declared["github_default_branch"]["default"] == branch
        else:
            assert other[k] == main[k], k   # workflows (their own branch argument) and Express roots: unchanged


@pytest.mark.parametrize("bad", INVALID + [None, 7])
def test_a_value_that_is_not_a_branch_name_is_refused_by_both_renders(bad):
    with pytest.raises(ValueError):
        te().generate_golden_main_tf("r1wif-app", "cloudrun", "", env_vars_override={}, github_default_branch=bad)
    with pytest.raises(ValueError):
        te().generate_golden_variables_tf("r1wif-app", "acme/r1wif-app", region="us-central1",
                                          github_default_branch=bad)
    with pytest.raises(ValueError):
        te().wif_default_branch(bad)


def test_wif_default_branch():
    assert te().wif_default_branch("main") is None
    assert te().wif_default_branch("develop") == "develop"


def test_assembly_passes_the_deploy_branch_to_both_root_renders():
    """handler._assemble_tree: every generate_golden_main_tf / generate_golden_variables_tf call passes
    github_default_branch=inputs.deploy_branch (AssemblyInputs.deploy_branch = workflow_branch(recorded branch), the
    same branch the deploy workflows trigger on)."""
    with open(os.path.join(GATEWAY, "developer_agent", "handler.py"), encoding="utf-8") as f:
        tree = ast.parse(f.read())
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_assemble_tree")
    calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
             and c.func.id in ("generate_golden_main_tf", "generate_golden_variables_tf")]
    assert sorted(c.func.id for c in calls) == ["generate_golden_main_tf"] * 2 + ["generate_golden_variables_tf"] * 2
    for c in calls:
        kw = {k.arg: k.value for k in c.keywords}
        v = kw.get("github_default_branch")
        assert isinstance(v, ast.Attribute) and v.attr == "deploy_branch" and getattr(v.value, "id", None) == "inputs"


def test_developer_prompt_contract_does_not_advertise_the_input():
    """The input is platform-only (contract_inspector._PLATFORM_ONLY_INPUTS): the prompt contract is unchanged; the
    embedded contract lists it (CI-5 parity with variables.tf)."""
    from developer_agent import contract_inspector as ci
    try:
        contract = ci.get_golden_module_contract("workload-foundation/base", force_refresh=True)
    finally:
        ci._CONTRACT_CACHE.pop("workload-foundation/base", None)
    assert "github_default_branch" not in contract
    assert "github_default_branch" in ci._EMBEDDED_MODULE_CONTRACTS["workload-foundation/base"]["inputs"]
