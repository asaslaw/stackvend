"""FD-4AZ (owner scope A, D5 10-16): golden data-store modules default to deletion protection ON; a spec can still opt
out explicitly.

- database-cloudsql / -spanner / -bigtable: `deletion_protection` default true.
- storage-bucket: `prevent_destroy` default true (so `force_destroy = !var.prevent_destroy` is false).
- workload-foundation/base: `firestore_delete_protection` default true (also the iac_upgrade_engine foundation template).
- database-alloydb: unchanged. google 6.35.0 (the production provider set) has no `deletion_protection` on
  google_alloydb_cluster (only `deletion_policy` DEFAULT/FORCE), see docs/handoff/fd-4az-report.md.

Real-engine tests use the production column (eval/.tools/tofu-1.9.0/tofu + eval/.tofu-mirror-prod, untracked) and
skip with a reason when it is not on this machine. `tofu test` runs plan-only against mock providers (no GCP, no apply),
under the TofuRunner network sandbox.
"""
import hermetic_guard  # noqa: F401  (first import)

import importlib.util
import os
import shutil
import sys
from pathlib import Path

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in (REPO_ROOT, os.path.join(REPO_ROOT, "eval")):
    if p not in sys.path:
        sys.path.insert(0, p)

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

MODULE_TREES = ["infra/modules", "apps/control-center/infra/modules"]
PAYLOAD_DIRS = ["shared", "apps/orchestrator-gateway/shared", "apps/control-center/shared", "mcp-servers/terraform/shared"]
PROD_TOFU = os.path.join(REPO_ROOT, "eval", ".tools", "tofu-1.9.0", "tofu")
PROD_MIRROR = os.path.join(REPO_ROOT, "eval", ".tofu-mirror-prod")

# module -> (variable, resource address, attribute, value with the default, value with the explicit opt-out)
PROTECTED = {
    "database-cloudsql": ("deletion_protection", "google_sql_database_instance.instance", "deletion_protection",
                          "true", "false"),
    "database-spanner": ("deletion_protection", "google_spanner_database.database[0]", "deletion_protection",
                         "true", "false"),
    "database-bigtable": ("deletion_protection", "google_bigtable_instance.instance", "deletion_protection",
                          "true", "false"),
    "storage-bucket": ("prevent_destroy", "google_storage_bucket.bucket", "force_destroy", "false", "true"),
    "workload-foundation/base": ("firestore_delete_protection", "google_firestore_database.database",
                                 "delete_protection_state", '"DELETE_PROTECTION_ENABLED"',
                                 '"DELETE_PROTECTION_DISABLED"'),
}
# Extra inputs a module needs so the protected resource is planned (all fake, plan-only against mocks).
EXTRA_VARS = {
    # FD-CSQL: the module now refuses (precondition) an instance with neither a private network nor a public IP.
    "database-cloudsql": {"project_id": '"fd4az-test"', "private_network_id": '"projects/fd4az-test/global/networks/vpc"'},
    # No CMEK key: FD-4AZ-b1 made encryption_config conditional, so the default (kms_key_name = null) plans.
    "database-spanner": {"project_id": '"fd4az-test"', "product_id": '"fd4az"', "database_name": '"appdb"'},
    "database-bigtable": {"project_id": '"fd4az-test"', "product_id": '"fd4az"'},
    "storage-bucket": {"project_id": '"fd4az-test"'},
    "workload-foundation/base": {"project_id": '"fd4az-test"', "product_id": '"fd4az"',
                                 "github_repo_full_name": '"acme/fd4az"'},
}


def _variables(path):
    with open(path, encoding="utf-8") as f:
        doc = hcl2.load(f)
    return {name: body for block in doc.get("variable", []) for name, body in block.items()}


def _payload(rel_dir):
    ns = {}
    rel = os.path.join(rel_dir, "builtin_modules_payload.py")
    with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as f:
        exec(compile(f.read(), rel, "exec"), ns)  # noqa: S102 - repo-owned data module
    return ns["BUILTIN_MODULE_FILES"]


# ------------------------------------------------------------------------------------------------ defaults (static)
@pytest.mark.parametrize("tree", MODULE_TREES)
@pytest.mark.parametrize("mod", sorted(PROTECTED))
def test_protection_variable_defaults_to_protective(tree, mod):
    var = PROTECTED[mod][0]
    body = _variables(os.path.join(REPO_ROOT, tree, mod, "variables.tf"))[var]
    assert body["type"] in ("bool", "${bool}")
    assert body["default"] is True, f"{tree}/{mod}: {var} must default to true (FD-4AZ)"


def test_storage_bucket_force_destroy_is_the_negation_of_prevent_destroy():
    with open(os.path.join(REPO_ROOT, "infra/modules/storage-bucket/main.tf"), encoding="utf-8") as f:
        doc = hcl2.load(f)
    bucket = doc["resource"][0]["google_storage_bucket"]["bucket"]
    assert bucket["force_destroy"] == "${!var.prevent_destroy}"


@pytest.mark.parametrize("mod", ["database-cloudsql", "database-spanner", "database-bigtable", "database-alloydb",
                                 "storage-bucket", "workload-foundation/base"])
def test_module_trees_are_identical(mod):
    for fn in sorted(os.listdir(os.path.join(REPO_ROOT, MODULE_TREES[0], mod))):
        a = Path(REPO_ROOT, MODULE_TREES[0], mod, fn).read_text(encoding="utf-8")
        b = Path(REPO_ROOT, MODULE_TREES[1], mod, fn).read_text(encoding="utf-8")
        assert a == b, f"{mod}/{fn} differs between {MODULE_TREES[0]} and {MODULE_TREES[1]}"


@pytest.mark.parametrize("rel_dir", PAYLOAD_DIRS)
@pytest.mark.parametrize("mod", sorted(PROTECTED) + ["database-alloydb"])
def test_payload_entry_equals_disk_in_every_copy(rel_dir, mod):
    payload = _payload(rel_dir)[mod]
    disk_dir = os.path.join(REPO_ROOT, "infra/modules", mod)
    assert set(payload) == {f for f in os.listdir(disk_dir) if f.endswith(".tf")}
    for fn, text in payload.items():
        assert text == Path(disk_dir, fn).read_text(encoding="utf-8"), f"{rel_dir}: {mod}/{fn} != disk"


@pytest.mark.parametrize("rel_dir", PAYLOAD_DIRS)
def test_iac_upgrade_engine_foundation_template_defaults_firestore_protection_on(rel_dir):
    path = os.path.join(REPO_ROOT, rel_dir, "iac_upgrade_engine.py")
    spec = importlib.util.spec_from_file_location("fd4az_upgrade_" + rel_dir.replace("/", "_").replace("-", "_"), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    files = mod._get_foundation_embedded_modules()
    variables_tf = files["infra/modules/workload-foundation/base/variables.tf"]
    doc = hcl2.loads(variables_tf)
    body = {n: b for blk in doc["variable"] for n, b in blk.items()}["firestore_delete_protection"]
    assert body["default"] is True
    # The template's database.tf still maps the flag both ways, so an explicit false still disables it.
    db_tf = files["infra/modules/workload-foundation/base/database.tf"]
    assert 'var.firestore_delete_protection ? "DELETE_PROTECTION_ENABLED" : "DELETE_PROTECTION_DISABLED"' in db_tf


# ------------------------------------------------------------------------------------------------ real engine
@pytest.fixture(scope="module")
def runner(tmp_path_factory):
    if not (os.access(PROD_TOFU, os.X_OK) and os.path.isdir(PROD_MIRROR)):
        pytest.skip("production column eval/.tools/tofu-1.9.0/tofu + eval/.tofu-mirror-prod (untracked) not present")
    from stackvend_eval.tofu_runner import TofuRunner
    r = TofuRunner(tmp_path_factory.mktemp("fd4az-tofu"), Path(PROD_MIRROR), tofu_bin=PROD_TOFU)
    if not r.mirror_ready:
        pytest.skip(f"production mirror not verified: {r.mirror_manifest['status']}")
    return r


def _copy_module(mod, dest):
    shutil.copytree(os.path.join(REPO_ROOT, "infra/modules", mod), dest)


def _init(runner, wd):
    r = runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-2000:]


# database-cloudsql and database-alloydb were strict xfails here until FD-4AZ-b1 fixed their google 6.x schema breaks.
@pytest.mark.parametrize("mod", [
    "database-cloudsql", "database-alloydb", "database-spanner", "database-bigtable", "storage-bucket", "workload-foundation/base",
])
def test_module_validates_at_production_set(runner, tmp_path, mod):
    wd = tmp_path / "m"
    _copy_module(mod, wd)
    _init(runner, wd)
    r = runner._run(["validate", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-2000:]


@pytest.mark.parametrize("mod", sorted(PROTECTED))
def test_default_is_protective_and_explicit_opt_out_is_honoured(runner, tmp_path, mod):
    """Plan-only `tofu test` with mock providers: no variable -> protected; explicit opt-out -> unprotected."""
    var, address, attr, protected, unprotected = PROTECTED[mod]
    wd = tmp_path / "m"
    _copy_module(mod, wd)
    extra = "\n".join(f"  {k} = {v}" for k, v in EXTRA_VARS[mod].items())
    opt_out_value = "false"  # every module's opt-out is an explicit `false` on its protection variable
    # Plan only the protected resource (and what it depends on): other module resources need realistic computed
    # values (e.g. a service-account name format) that mock providers do not produce.
    target = f"  plan_options {{\n    target = [{address.split('[')[0]}]\n  }}\n"
    mocks = 'mock_provider "google" {}\n' + ('mock_provider "random" {}\n' if mod == "database-cloudsql" else "")
    test = (
        mocks + "\n" +
        f"variables {{\n{extra}\n}}\n\n"
        'run "default_is_protective" {\n  command = plan\n' + target +
        f"  assert {{\n    condition     = {address}.{attr} == {protected}\n"
        f'    error_message = "{mod}: default must be protective"\n  }}\n}}\n\n'
        'run "explicit_opt_out_is_honoured" {\n  command = plan\n' + target +
        f"  variables {{\n    {var} = {opt_out_value}\n  }}\n"
        f"  assert {{\n    condition     = {address}.{attr} == {unprotected}\n"
        f'    error_message = "{mod}: explicit opt-out must be honoured"\n  }}\n}}\n'
    )
    (wd / "fd4az_tests").mkdir()
    (wd / "fd4az_tests" / "fd4az.tftest.hcl").write_text(test, encoding="utf-8")
    _init(runner, wd)
    r = runner._run(["test", "-test-directory=fd4az_tests", "-filter=fd4az_tests/fd4az.tftest.hcl", "-no-color"],
                    cwd=wd)
    out = r.stdout + r.stderr
    assert r.returncode == 0, out[-3000:]
    assert "2 passed, 0 failed" in out, out[-3000:]
