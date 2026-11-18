"""FD-4AZ-b follow-ups (seen-not-fixed items from docs/handoff/fd-4az-report.md).

b1: golden modules that were broken at the production provider set (google 6.35.0):
    - database-cloudsql: `require_ssl` (removed in google 6.0) -> `ip_configuration.ssl_mode = "ENCRYPTED_ONLY"`
      (every connection must use TLS).
    - database-alloydb: top-level `network` (removed in google 6.0) -> `network_config { network = var.network }`.
    - database-spanner: `encryption_config` is only emitted when a CMEK key is given (an empty block failed the
      provider's "one of kms_key_name/kms_key_names" check at plan time); unchanged when a key is given.

Real-engine tests use the production column (eval/.tools/tofu-1.9.0/tofu + eval/.tofu-mirror-prod, untracked) and
skip with a reason when it is not on this machine. `tofu test` runs plan-only against mock providers (no GCP, no
apply), under the TofuRunner network sandbox.
"""
import hermetic_guard  # noqa: F401  (first import)

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
B1_MODULES = ["database-cloudsql", "database-alloydb", "database-spanner"]
PROD_TOFU = os.path.join(REPO_ROOT, "eval", ".tools", "tofu-1.9.0", "tofu")
PROD_MIRROR = os.path.join(REPO_ROOT, "eval", ".tofu-mirror-prod")
FAKE_KEY = "projects/fd4azb-test/locations/us-central1/keyRings/r/cryptoKeys/k"


def _main(tree, mod):
    with open(os.path.join(REPO_ROOT, tree, mod, "main.tf"), encoding="utf-8") as f:
        return hcl2.load(f)


def _resource(doc, rtype, name):
    for block in doc.get("resource", []):
        if rtype in block and name in block[rtype]:
            return block[rtype][name]
    raise KeyError(f"{rtype}.{name}")


def _payload(rel_dir):
    ns = {}
    rel = os.path.join(rel_dir, "builtin_modules_payload.py")
    with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as f:
        exec(compile(f.read(), rel, "exec"), ns)  # noqa: S102 - repo-owned data module
    return ns["BUILTIN_MODULE_FILES"]


# ------------------------------------------------------------------------------------------------ b1 static
@pytest.mark.parametrize("tree", MODULE_TREES)
def test_b1_cloudsql_requires_tls_via_ssl_mode(tree):
    inst = _resource(_main(tree, "database-cloudsql"), "google_sql_database_instance", "instance")
    ipc = inst["settings"][0]["ip_configuration"][0]
    assert "require_ssl" not in ipc, "require_ssl was removed in google 6.0"
    # FD-CSQL (F4/F8): ssl_mode and the public IP switch are module variables now; read their defaults.
    assert ipc["ssl_mode"] == "${var.ssl_mode}" and ipc["ipv4_enabled"] == "${var.enable_public_ip}"
    with open(os.path.join(REPO_ROOT, tree, "database-cloudsql", "variables.tf"), encoding="utf-8") as f:
        variables = {n: b for block in hcl2.load(f).get("variable", []) for n, b in block.items()}
    assert variables["ssl_mode"]["default"] == "ENCRYPTED_ONLY"
    assert variables["enable_public_ip"]["default"] is False


@pytest.mark.parametrize("tree", MODULE_TREES)
def test_b1_alloydb_network_lives_in_network_config(tree):
    cluster = _resource(_main(tree, "database-alloydb"), "google_alloydb_cluster", "cluster")
    assert "network" not in cluster, "top-level network was removed in google 6.0"
    assert cluster["network_config"] == [{"network": "${var.network}"}]


@pytest.mark.parametrize("tree", MODULE_TREES)
def test_b1_spanner_encryption_config_only_with_a_key(tree):
    db = _resource(_main(tree, "database-spanner"), "google_spanner_database", "database")
    assert "encryption_config" not in db, "a static encryption_config block fails at plan without a key"
    dyn = db["dynamic"][0]["encryption_config"]
    assert dyn["for_each"] == "${var.kms_key_name != null ? [1] : []}"
    assert dyn["content"] == [{"kms_key_name": "${var.kms_key_name}"}]


@pytest.mark.parametrize("rel_dir", PAYLOAD_DIRS)
@pytest.mark.parametrize("mod", B1_MODULES)
def test_b1_payload_entry_equals_disk(rel_dir, mod):
    payload = _payload(rel_dir)[mod]
    for tree in MODULE_TREES:
        disk_dir = os.path.join(REPO_ROOT, tree, mod)
        assert set(payload) == {f for f in os.listdir(disk_dir) if f.endswith(".tf")}
        for fn, text in payload.items():
            assert text == Path(disk_dir, fn).read_text(encoding="utf-8"), f"{rel_dir}: {mod}/{fn} != {tree}"


# ------------------------------------------------------------------------------------------------ b1 real engine
@pytest.fixture(scope="module")
def runner(tmp_path_factory):
    if not (os.access(PROD_TOFU, os.X_OK) and os.path.isdir(PROD_MIRROR)):
        pytest.skip("production column eval/.tools/tofu-1.9.0/tofu + eval/.tofu-mirror-prod (untracked) not present")
    from stackvend_eval.tofu_runner import TofuRunner
    r = TofuRunner(tmp_path_factory.mktemp("fd4azb-tofu"), Path(PROD_MIRROR), tofu_bin=PROD_TOFU)
    if not r.mirror_ready:
        pytest.skip(f"production mirror not verified: {r.mirror_manifest['status']}")
    return r


def _tofu_test(runner, wd, mod, test_hcl):
    shutil.copytree(os.path.join(REPO_ROOT, "infra/modules", mod), wd)
    (wd / "fd4azb_tests").mkdir()
    (wd / "fd4azb_tests" / "fd4azb.tftest.hcl").write_text(test_hcl, encoding="utf-8")
    r = runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-2000:]
    r = runner._run(["validate", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-2000:]
    r = runner._run(["test", "-test-directory=fd4azb_tests", "-filter=fd4azb_tests/fd4azb.tftest.hcl", "-no-color"],
                    cwd=wd)
    return r.returncode, r.stdout + r.stderr


def test_b1_cloudsql_plans_with_tls_required(runner, tmp_path):
    test = '''mock_provider "google" {}
mock_provider "random" {}

variables {
  project_id         = "fd4azb-test"
  private_network_id = "projects/fd4azb-test/global/networks/vpc"
}

run "tls_required" {
  command = plan
  plan_options {
    target = [google_sql_database_instance.instance]
  }
  assert {
    condition     = google_sql_database_instance.instance.settings[0].ip_configuration[0].ssl_mode == "ENCRYPTED_ONLY"
    error_message = "Cloud SQL must require TLS"
  }
}
'''
    rc, out = _tofu_test(runner, tmp_path / "m", "database-cloudsql", test)
    assert rc == 0 and "1 passed, 0 failed" in out, out[-3000:]


def test_b1_alloydb_plans_with_network_config(runner, tmp_path):
    test = '''mock_provider "google" {}
mock_provider "random" {}

variables {
  project_id = "fd4azb-test"
  product_id = "fd4azb"
  network    = "projects/123/global/networks/vpc"
}

run "network_config" {
  command = plan
  plan_options {
    target = [google_alloydb_cluster.cluster]
  }
  assert {
    condition     = google_alloydb_cluster.cluster.network_config[0].network == "projects/123/global/networks/vpc"
    error_message = "AlloyDB network must come from var.network via network_config"
  }
}
'''
    rc, out = _tofu_test(runner, tmp_path / "m", "database-alloydb", test)
    assert rc == 0 and "1 passed, 0 failed" in out, out[-3000:]


def test_b1_spanner_plans_without_a_key_and_keeps_a_given_key(runner, tmp_path):
    test = f'''mock_provider "google" {{}}

variables {{
  project_id    = "fd4azb-test"
  product_id    = "fd4azb"
  database_name = "appdb"
}}

run "no_key_plans_without_encryption_config" {{
  command = plan
  plan_options {{
    target = [google_spanner_database.database]
  }}
  assert {{
    condition     = length(google_spanner_database.database[0].encryption_config) == 0
    error_message = "no CMEK key -> no encryption_config block"
  }}
}}

run "given_key_is_kept" {{
  command = plan
  plan_options {{
    target = [google_spanner_database.database]
  }}
  variables {{
    kms_key_name = "{FAKE_KEY}"
  }}
  assert {{
    condition     = length(google_spanner_database.database[0].encryption_config) == 1
    error_message = "a CMEK key -> exactly one encryption_config block"
  }}
  assert {{
    condition     = google_spanner_database.database[0].encryption_config[0].kms_key_name == "{FAKE_KEY}"
    error_message = "the given CMEK key must be used unchanged"
  }}
}}
'''
    rc, out = _tofu_test(runner, tmp_path / "m", "database-spanner", test)
    assert rc == 0 and "2 passed, 0 failed" in out, out[-3000:]


# ------------------------------------------------------------------------------------------------ b2 (service.py)
TF_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")

# Cloud Run service + job and two data stores (a resource and a golden module call), all `deletion_protection = true`.
MIXED = '''resource "google_cloud_run_v2_service" "api" {
  name                = "api"
  location            = var.region
  deletion_protection = true
  template {
    containers {
      image = var.image
    }
  }
}

resource "google_cloud_run_v2_job" "migrate" {
  name                = "migrate"
  location            = var.region
  deletion_protection = true # platform replaces jobs
  template {
    template {
      containers {
        image = var.image
      }
    }
  }
}

resource "google_sql_database_instance" "db" {
  name                = "db"
  database_version    = "POSTGRES_15"
  region              = var.region
  deletion_protection = true
  settings {
    tier = "db-f1-micro"
  }
}

module "spanner" {
  source              = "../modules/database-spanner"
  project_id          = var.project_id
  deletion_protection = true
}
'''
_SVC_TRUE = '  location            = var.region\n  deletion_protection = true\n  template {\n    containers'
_SVC_FALSE = '  location            = var.region\n  deletion_protection = false\n  template {\n    containers'
_JOB_TRUE = 'deletion_protection = true # platform replaces jobs'
_JOB_FALSE = 'deletion_protection = false # platform replaces jobs'
# MIXED with the Cloud Run service / job set to false and the data stores still true (an input, not an expectation:
# FD-55 W6a deleted the flip that used to produce it).
MIXED_CLOUD_RUN_OFF = MIXED.replace(_SVC_TRUE, _SVC_FALSE, 1).replace(_JOB_TRUE, _JOB_FALSE, 1)

# Valid files where no Cloud Run block has `deletion_protection = true`: must stay byte-identical.
NO_CLOUD_RUN_TRUE = {
    "cloud_run_false_data_store_true": MIXED_CLOUD_RUN_OFF,
    "cloud_run_without_the_argument": '''resource "google_cloud_run_v2_service" "api" {
  name     = "api"
  location = var.region
  template {
    containers {
      image = var.image
      # deletion_protection = true (a comment is not an argument)
    }
  }
}

resource "google_bigtable_instance" "bt" {
  name                = "bt"
  deletion_protection = true
  cluster {
    cluster_id = "bt-c1"
    zone       = "us-central1-b"
  }
}''',
    "cloud_run_non_literal": '''resource "google_cloud_run_v2_service" "api" {
  name                = "api"
  location            = var.region
  deletion_protection = var.protect_api
  template {
    containers {
      image = var.image
    }
  }
}

resource "google_spanner_database" "db" {
  instance            = "i"
  name                = "appdb"
  deletion_protection = true
}
''',
}


@pytest.fixture(scope="module")
def svc_mod():
    import importlib.util
    if TF_DIR not in sys.path:
        sys.path.insert(0, TF_DIR)
    spec = importlib.util.spec_from_file_location("stackvend_tf_service_fd4azb", os.path.join(TF_DIR, "service.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _prepare(svc_mod, tmp_path, text, name="infra/workload/custom.tf"):
    from unittest.mock import MagicMock
    s = svc_mod.TerraformService(project_id="test-proj", db=MagicMock(), workspace_base_dir=str(tmp_path / "ws"))
    ws = s.prepare_workspace(product_id="fd4azb", trace_id="trace-fd4azb", hcl_files={name: text})
    return Path(ws, name).read_text(encoding="utf-8")


# FD-55 W6a (register FD55-W6a, A5): the apply-time Cloud Run deletion_protection add / flip (and its FD-4AZ-b2
# parser-scoped helper _cloud_run_deletion_protection_off) is DELETED. prepare_workspace writes every .tf byte-identical:
# the Cloud Run service / job keep the committed value (true, false, a variable or absent) exactly as the data stores
# always did. A mutant re-adding the add or the flip fails the byte-identity below.
def test_b2_helper_is_deleted(svc_mod):
    assert not hasattr(svc_mod.TerraformService, "_cloud_run_deletion_protection_off")
    assert not hasattr(svc_mod.TerraformService, "_CLOUD_RUN_PROTECTION_OFF_TYPES")


NO_ARGUMENT = '''resource "google_cloud_run_v2_service" "api" {
  name     = "api"
  location = var.region
  template {
    containers {
      image = var.image
    }
  }
}
'''


@pytest.mark.parametrize("case", ["mixed", "no_argument"] + sorted(NO_CLOUD_RUN_TRUE))
def test_b2_prepare_workspace_writes_every_protection_value_as_committed(svc_mod, tmp_path, case):
    text = {"mixed": MIXED, "no_argument": NO_ARGUMENT}.get(case) or NO_CLOUD_RUN_TRUE[case]
    assert _prepare(svc_mod, tmp_path, text) == text


# ------------------------------------------------------------------------------------------------ b3 (Express)
EXPRESS_COPIES = ["shared", "apps/orchestrator-gateway/shared", "apps/control-center/shared"]


def _express(rel_dir):
    import importlib.util
    path = os.path.join(REPO_ROOT, rel_dir, "express_synthesizer.py")
    spec = importlib.util.spec_from_file_location("fd4azb_express_" + rel_dir.replace("/", "_").replace("-", "_"), path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.ExpressHCLSynthesizer()


def _cloudsql_module_body(rel_dir, params):
    m_block, _ = _express(rel_dir)._generate_module_instance(
        module_id="database-cloudsql", instance_key="main_pg", instance_name="main_pg", product_id="fd4azb",
        params=params, has_vpc=False)
    return hcl2.loads(m_block)["module"][0]["database_main_pg"]


def test_b3_express_replicas_are_identical():
    texts = {Path(REPO_ROOT, d, "express_synthesizer.py").read_text(encoding="utf-8") for d in EXPRESS_COPIES}
    assert len(texts) == 1


@pytest.mark.parametrize("rel_dir", EXPRESS_COPIES)
@pytest.mark.parametrize("params", [{}, {"database_version": "POSTGRES_15"}, {"deletion_protection": True},
                                    {"deletion_protection": "false"}, {"deletion_protection": None}],
                         ids=["no_params", "other_params", "explicit_true", "string_is_not_an_opt_out", "none"])
def test_b3_express_cloudsql_is_protected_by_default(rel_dir, params):
    body = _cloudsql_module_body(rel_dir, params)
    assert "deletion_protection" not in body  # the module default applies ...
    with open(os.path.join(REPO_ROOT, "infra/modules/database-cloudsql/variables.tf"), encoding="utf-8") as f:
        var = {n: b for blk in hcl2.load(f)["variable"] for n, b in blk.items()}["deletion_protection"]
    assert var["default"] is True  # ... and it is protective (FD-4AZ)


@pytest.mark.parametrize("rel_dir", EXPRESS_COPIES)
def test_b3_express_cloudsql_explicit_opt_out_is_honoured(rel_dir):
    body = _cloudsql_module_body(rel_dir, {"deletion_protection": False})
    assert body["deletion_protection"] is False


def test_b3_express_workload_main_tf_has_no_cloudsql_opt_out():
    files = _express("shared").synthesize_workload(
        product_id="fd4azb-express", project_id="fd4azb-express-1234", region="us-central1",
        module_instances=[{"module_id": "compute-cloudrun", "instance_name": "api", "parameters": {}},
                          {"module_id": "database-cloudsql", "instance_name": "main_pg", "parameters": {}}],
        state_bucket="fd4azb-tfstate")
    doc = hcl2.loads(files["infra/workload/main.tf"])
    mods = {n: b for blk in doc["module"] for n, b in blk.items()}
    assert "deletion_protection" not in mods["database_main_pg"]


# ------------------------------------------------------------------------------------------------ b4 (comment only)
def test_b4_human_override_template_example_does_not_model_protection_off():
    """The human_override.tf template's env-var example no longer carries an unrelated `deletion_protection = false`
    line (comment-only). Read statically (ast) so the gateway's import graph is not loaded here."""
    import ast
    path = os.path.join(REPO_ROOT, "apps/orchestrator-gateway/developer_agent/terraform_engine.py")
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "generate_human_override_tf_template")
    ret = next(n for n in ast.walk(fn) if isinstance(n, ast.Return))
    text = ast.literal_eval(ret.value)
    assert "Example 2: Override environment variables on a Cloud Run service" in text
    assert "deletion_protection" not in text
    assert all(line.startswith("#") for line in text.splitlines() if line.strip())  # still comment-only
