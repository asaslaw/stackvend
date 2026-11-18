"""TI-2h: the `orchestration-composer` golden module passes `tofu validate` at the production provider set.

Its `gcs_bucket` output read `config[0].gcs_bucket`, an attribute google 6.35.0's `google_composer_environment` does not
have, so every workload that vended the module failed validate. The schema's equivalent is the computed
`config[0].dag_gcs_prefix` (the environment's Cloud Storage bucket, as its DAGs prefix `gs://<bucket>/dags`). The
output keeps its name and description.

Real-engine tests use the owner-verified production column (tofu 1.9.0 + google 6.35.0 filesystem mirror, untracked):
`eval/.tools/tofu-1.9.0/tofu` + `eval/.tofu-mirror-prod` in the checkout, or wherever `STACKVEND_PROD_TOFU` /
`STACKVEND_PROD_MIRROR` point. They skip with a reason when it is not on this machine. Everything runs offline
(`init -backend=false`, mirror only)."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import hashlib
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EVAL_DIR = os.path.join(REPO_ROOT, "eval")
if EVAL_DIR not in sys.path:
    sys.path.insert(0, EVAL_DIR)

MOD = "orchestration-composer"
MODULE_DIRS = [os.path.join(REPO_ROOT, "infra", "modules", MOD),
               os.path.join(REPO_ROOT, "apps", "control-center", "infra", "modules", MOD)]
PAYLOADS = [os.path.join(REPO_ROOT, p, "builtin_modules_payload.py") for p in (
    "shared", "mcp-servers/terraform/shared", "apps/orchestrator-gateway/shared", "apps/control-center/shared")]
OLD_VALUE = "google_composer_environment.environment.config[0].gcs_bucket"
NEW_VALUE = "google_composer_environment.environment.config[0].dag_gcs_prefix"
DESCRIPTION = 'description = "The Cloud Storage prefix/bucket used by the environment."'

PROD_TOFU = os.environ.get("STACKVEND_PROD_TOFU") or os.path.join(EVAL_DIR, ".tools", "tofu-1.9.0", "tofu")
PROD_MIRROR = os.environ.get("STACKVEND_PROD_MIRROR") or os.path.join(EVAL_DIR, ".tofu-mirror-prod")


def _disk_module(d=MODULE_DIRS[0]):
    return {fn: open(os.path.join(d, fn)).read() for fn in sorted(os.listdir(d)) if fn.endswith(".tf")}


def _payload(path):
    tree = ast.parse(open(path).read())
    node = next(n for n in tree.body
                if isinstance(n, ast.AnnAssign) and getattr(n.target, "id", None) == "BUILTIN_MODULE_FILES")
    return ast.literal_eval(node.value)


# ------------------------------------------------------------------------------------------------ static (no tofu)
def test_gcs_bucket_output_reads_the_current_schema_attribute_in_both_module_copies():
    for d in MODULE_DIRS:
        out = open(os.path.join(d, "outputs.tf")).read()
        assert 'output "gcs_bucket" {' in out, d          # name kept (fix, never remove)
        assert DESCRIPTION in out, d                       # meaning kept
        assert NEW_VALUE in out and OLD_VALUE not in out, d


def test_both_module_copies_are_identical():
    assert _disk_module(MODULE_DIRS[0]) == _disk_module(MODULE_DIRS[1])


def test_payload_composer_entry_equals_the_module_on_disk_in_all_four_copies():
    disk = _disk_module()
    for p in PAYLOADS:
        entry = _payload(p)[MOD]
        assert entry == disk, p
        assert NEW_VALUE in entry["outputs.tf"] and OLD_VALUE not in entry["outputs.tf"], p


def test_the_four_payload_copies_are_byte_identical():
    digests = {p: hashlib.sha256(open(p, "rb").read()).hexdigest() for p in PAYLOADS}
    assert len(set(digests.values())) == 1, digests


def test_contract_still_advertises_the_gcs_bucket_output():
    src = open(os.path.join(REPO_ROOT, "apps", "orchestrator-gateway", "developer_agent",
                            "contract_inspector.py")).read()
    tree = ast.parse(src)
    contracts = None
    for n in ast.walk(tree):
        if isinstance(n, ast.Dict):
            keys = [k.value for k in n.keys if isinstance(k, ast.Constant)]
            if MOD in keys:
                contracts = ast.literal_eval(n)
                break
    assert contracts is not None
    assert "gcs_bucket" in contracts[MOD]["outputs"]


# ------------------------------------------------------------------------------------------------ production engine
@pytest.fixture(scope="module")
def validate(tmp_path_factory):
    """The production /validate column (tofu 1.9.0 + google 6.35.0 mirror), run like the eval harness's V1b."""
    if not (os.access(PROD_TOFU, os.X_OK) and os.path.isdir(PROD_MIRROR)):
        pytest.skip("production column (tofu 1.9.0 + eval/.tofu-mirror-prod, untracked) not present; set "
                    "STACKVEND_PROD_TOFU / STACKVEND_PROD_MIRROR to run")
    pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")
    from stackvend_eval.tofu_runner import TofuRunner
    from stackvend_eval.validate_client import validate_tree_raw
    runner = TofuRunner(tmp_path_factory.mktemp("tofu"), Path(PROD_MIRROR), tofu_bin=PROD_TOFU)
    if not runner.mirror_ready:
        pytest.skip(f"production mirror not verified: {runner.mirror_manifest['status']}")
    counter = {"n": 0}

    def run(tree):
        counter["n"] += 1
        out = validate_tree_raw(runner, tree, label=f"t{counter['n']}", engine_version="1.9.0", providers={})
        assert out["status"] in ("PASS", "FAIL"), out
        return out["status"], [d for d in out["diagnostics"] if d.get("severity") == "error"]
    return run


def _as_root(files):
    return {f"infra/workload/{fn}": body for fn, body in files.items()}


WORKLOAD_MAIN = '''variable "project_id" {
  type = string
}

module "composer" {
  source     = "../modules/orchestration-composer"
  project_id = var.project_id
  product_id = "shop"
}

output "composer_bucket" {
  value = module.composer.gcs_bucket
}
'''


@pytest.mark.parametrize("copy", MODULE_DIRS, ids=["infra", "control-center"])
def test_module_validates_as_a_root_module_at_the_production_set(validate, copy):
    status, errors = validate(_as_root(_disk_module(copy)))
    assert (status, errors) == ("PASS", [])


@pytest.mark.parametrize("payload", PAYLOADS, ids=lambda p: os.path.relpath(p, REPO_ROOT))
def test_vended_payload_module_validates_when_a_workload_reads_gcs_bucket(validate, payload):
    files = {f"infra/modules/{MOD}/{fn}": body for fn, body in _payload(payload)[MOD].items()}
    files["infra/workload/main.tf"] = WORKLOAD_MAIN
    status, errors = validate(files)
    assert (status, errors) == ("PASS", [])


def test_old_attribute_is_rejected_at_the_production_set(validate):
    """The test discriminates: the pre-fix output fails exactly where TI-2 found it."""
    files = _disk_module()
    files["outputs.tf"] = files["outputs.tf"].replace(NEW_VALUE, OLD_VALUE)
    status, errors = validate(_as_root(files))
    assert status == "FAIL"
    assert [(e["summary"], e["range"]["filename"]) for e in errors] == [
        ("Unsupported attribute", "infra/workload/outputs.tf")]
