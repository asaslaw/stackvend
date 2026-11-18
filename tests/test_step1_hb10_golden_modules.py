"""Step 1 extra scope (orchestrator 10-12): HB-10 strip_invalid_hcl_blocks never strips golden-module blocks, and the
apply-time copy of the HA-10 stem purge no longer deletes auxiliary .tf files (register HS-08). Do-No-Harm: a valid
vendored golden module that references var.project_number / google_billing_budget is byte-identical after
prepare_workspace; the AI's auxiliary files survive. FD-55 W6a (register FD55-W6a): prepare_workspace no longer runs
HB-10 or the rest of the per-file chain on any file, so the AI's custom.tf is byte-identical too."""
import hermetic_guard  # noqa: F401  (first import)

import importlib.util
import os
import shutil
import sys

import pytest
from unittest.mock import MagicMock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")


@pytest.fixture(scope="module")
def svc_mod():
    if TF_DIR not in sys.path:
        sys.path.insert(0, TF_DIR)
    spec = importlib.util.spec_from_file_location("stackvend_tf_service_step1", os.path.join(TF_DIR, "service.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# A budget-style golden module (FD-4BG shape): valid HCL whose blocks match HB-10's substring rules.
BUDGET_MAIN = '''data "google_project" "this" {
  project_id = var.project_id
}

resource "google_billing_budget" "budget" {
  billing_account = var.billing_account
  display_name    = "budget-${var.project_number}"
  amount {
    specified_amount {
      units = "100"
    }
  }
}

output "budget_id" {
  value = google_billing_budget.budget.id
}
'''


@pytest.mark.parametrize("rel,golden", [
    ("infra/modules/compute-cloudrun/main.tf", True),
    ("infra/modules/workload-foundation/base/wif.tf", True),
    ("modules/storage-bucket/main.tf", True),
    ("infra/modules/not-a-golden-module/main.tf", False),
    ("infra/modules/workload-foundation/main.tf", False),     # the golden module is workload-foundation/base
    ("infra/workload/custom.tf", False),
    ("custom.tf", False),
    ("infra/modules/compute-cloudrun", False),               # the directory itself, not a file inside it
])
def test_golden_module_membership_is_exact(svc_mod, rel, golden):
    assert svc_mod.is_golden_module_file(rel) is golden


def test_hb10_still_strips_llm_custom_tf_but_never_golden_module_files(svc_mod, monkeypatch):
    # a golden module name outside the builtin payload (the HA-31 payload alignment is deleted by FD-55 W6d anyway)
    monkeypatch.setattr(svc_mod, "_GOLDEN_MODULE_NAMES", (("budget-guard",),))
    s = svc_mod.TerraformService(project_id="test-proj", db=MagicMock())  # never a real Firestore client
    files = {
        "main.tf": 'module "foundation" {\n  source = "./infra/modules/budget-guard"\n}\n',
        "infra/modules/budget-guard/main.tf": BUDGET_MAIN,
        "custom.tf": 'resource "google_billing_budget" "llm" {\n  billing_account = "x"\n}\n',
        "storage.tf": 'resource "google_storage_bucket" "uploads" {\n  name = "u"\n}\n',
    }
    ws = s.prepare_workspace(product_id="budgetapp", trace_id="trace-hb10", hcl_files=files)
    try:
        with open(os.path.join(ws, "infra/modules/budget-guard/main.tf")) as fh:
            assert fh.read() == BUDGET_MAIN                         # golden: byte-identical (Do No Harm)
        with open(os.path.join(ws, "custom.tf")) as fh:
            assert fh.read() == files["custom.tf"]                 # FD55-W6a: HB-10 no longer strips custom.tf
        assert os.path.exists(os.path.join(ws, "storage.tf"))        # HS-08: aux file not purged at apply time
        with open(os.path.join(ws, "storage.tf")) as fh:
            assert 'resource "google_storage_bucket" "uploads"' in fh.read()
    finally:
        shutil.rmtree(ws, ignore_errors=True)


def test_apply_time_stem_purge_is_gone(svc_mod):
    src = open(os.path.join(TF_DIR, "service.py")).read()
    assert "os.remove(fpath)" not in src and "canonical_workload_stems" not in src   # tombstone


# ------------------------------------------------------------------------- HS-08 extension (Step 1 code RT F2)
def _payload():
    """{"<module>/<file>": text} of the built-in payload service.py aligns vendored modules to (HA-31)."""
    sys.path.insert(0, TF_DIR)
    from shared.builtin_modules_payload import BUILTIN_MODULE_FILES
    return {f"{m}/{f}": t for m, files in BUILTIN_MODULE_FILES.items() for f, t in files.items()}


def _real_golden_files():
    out = {}
    base = os.path.join(REPO_ROOT, "infra", "modules")
    for root, _dirs, names in os.walk(base):
        for n in names:
            if n.endswith(".tf"):
                full = os.path.join(root, n)
                rel = "infra/modules/" + os.path.relpath(full, base).replace(os.sep, "/")
                with open(full) as fh:
                    out[rel] = fh.read()
    return out


def test_no_apply_time_healer_edits_a_real_golden_module_file(svc_mod):
    """HS-08 extension (owner-approved 10-12): no apply-time healer edits a real golden module file. FD-55 W6d
    (register FD55-W6b+W6d): the HA-31 payload refresh is deleted too, so after prepare_workspace every vendored
    golden file equals its committed (vendored) bytes, whether or not the payload differs (a difference is only
    reported, PLATFORM.VENDORED_MODULE_STALE). FD-55 W6a: the per-file chain is deleted, so the LLM custom.tf is
    written as committed too."""
    golden = _real_golden_files()
    assert len(golden) > 50
    s = svc_mod.TerraformService(project_id="test-proj", db=MagicMock())
    files = dict(golden)
    files["infra/workload/main.tf"] = 'module "compute" {\n  source = "../modules/compute-cloudrun"\n}\n'
    files["infra/workload/custom.tf"] = 'resource "google_billing_budget" "llm" {\n  billing_account = "x"\n}\n'
    ws = s.prepare_workspace(product_id="goldenapp", trace_id="trace-hs08", hcl_files=files)
    try:
        changed = []
        for rel, text in sorted(golden.items()):
            if not svc_mod.is_golden_module_file(rel):
                continue
            p = os.path.join(ws, rel)
            if not os.path.exists(p):
                changed.append(rel + " (missing)")
                continue
            with open(p, newline="") as fh:
                if fh.read() != text:
                    changed.append(rel)
        assert changed == []
        with open(os.path.join(ws, "infra/workload/custom.tf")) as fh:
            assert fh.read() == files["infra/workload/custom.tf"]   # FD55-W6a: no HB-10 strip
    finally:
        shutil.rmtree(ws, ignore_errors=True)


# Valid HCL that triggers the apply-time per-file chain (deletion_protection injection, variable default synthesis,
# service_url rewrite, provider version bump, AST delimiter curing input) -- none of which may touch a golden file.
CHAIN_TRIGGER_MODULE = '''variable "image" {
  type = string
}

resource "google_cloud_run_v2_service" "svc" {
  name     = "svc"
  location = var.region
  template {
    containers {
      image = var.image
    }
  }
}

output "url" {
  value = module.upstream.service_url
}
'''


def test_per_file_chain_skips_golden_files_outside_the_payload(svc_mod, monkeypatch):
    """HS-08 extension: the per-file chain itself (not only the HA-31 alignment, deleted by FD-55 W6d) leaves golden
    files alone. Uses a golden module name that is not in the payload, so an alignment could not mask an edit. Mutation checked:
    service.py at the pre-fix commit injects `deletion_protection = false` / a variable default -> this test fails."""
    monkeypatch.setattr(svc_mod, "_GOLDEN_MODULE_NAMES", (("guard-mod",),))
    s = svc_mod.TerraformService(project_id="test-proj", db=MagicMock())
    files = {"infra/workload/main.tf": 'module "g" {\n  source = "../modules/guard-mod"\n}\n',
             "infra/modules/guard-mod/main.tf": CHAIN_TRIGGER_MODULE,
             "infra/workload/custom.tf": CHAIN_TRIGGER_MODULE}
    ws = s.prepare_workspace(product_id="chainapp", trace_id="trace-hs08b", hcl_files=files)
    try:
        with open(os.path.join(ws, "infra/modules/guard-mod/main.tf")) as fh:
            assert fh.read() == CHAIN_TRIGGER_MODULE
        with open(os.path.join(ws, "infra/workload/custom.tf")) as fh:
            assert fh.read() == CHAIN_TRIGGER_MODULE          # FD55-W6a: the per-file chain is deleted for every file
    finally:
        shutil.rmtree(ws, ignore_errors=True)


@pytest.mark.parametrize("public", [True, False])
def test_workload_ingress_comes_from_the_typed_decision_after_the_skip(svc_mod, public):
    """Owner check with the HS-08 extension (10-12): public ingress for a workload is decided by the compliance
    `allow_unauthenticated` decision -> golden root render (variable default + module argument) -> compute-cloudrun's
    count-gated allUsers member; no apply-time rewrite is involved. A public decision deploys public, a private one
    stays private (invoker members only), and prepare_workspace leaves the compute-cloudrun module untouched."""
    pytest.importorskip("hcl2")
    import hcl2
    gw = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
    if gw not in sys.path:
        sys.path.insert(0, gw)
    from developer_agent.terraform_engine import generate_golden_main_tf, generate_golden_variables_tf
    main = generate_golden_main_tf("shop", "cloudrun", "api", allow_unauthenticated=public)
    variables = generate_golden_variables_tf("shop", "o/shop", allow_unauthenticated=public)
    compute = next(m["compute"] for m in hcl2.loads(main)["module"] if "compute" in m)
    assert compute["allow_unauthenticated"] == "${var.allow_unauthenticated}"
    var = next(v["allow_unauthenticated"] for v in hcl2.loads(variables)["variable"] if "allow_unauthenticated" in v)
    assert var["default"] is public
    golden = _real_golden_files()
    mod = {k: v for k, v in golden.items() if k.startswith("infra/modules/compute-cloudrun/")}
    res = hcl2.loads(mod["infra/modules/compute-cloudrun/main.tf"])["resource"]
    members = [b for r in res for t, named in r.items() if t == "google_cloud_run_v2_service_iam_member"
               for b in named.values()]
    public_member = next(b for b in members if b.get("member") == "allUsers")
    assert public_member["count"] == "${var.allow_unauthenticated ? 1 : 0}"
    s = svc_mod.TerraformService(project_id="test-proj", db=MagicMock())
    files = dict(mod, **{"infra/workload/main.tf": main, "infra/workload/variables.tf": variables})
    ws = s.prepare_workspace(product_id="shop", trace_id=f"trace-ingress-{public}", hcl_files=files)
    try:
        for rel, text in mod.items():
            with open(os.path.join(ws, rel)) as fh:
                assert fh.read() == text                           # FD-55 W6d: applied as committed (no refresh)
        with open(os.path.join(ws, "infra/workload/variables.tf")) as fh:
            v2 = next(v["allow_unauthenticated"] for v in hcl2.loads(fh.read())["variable"]
                      if "allow_unauthenticated" in v)
        assert v2["default"] is public                             # the decision survives apply-time preparation
    finally:
        shutil.rmtree(ws, ignore_errors=True)
