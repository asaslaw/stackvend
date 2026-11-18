"""TI-5-G3b (register, owner 10-24): the security-kms golden module grants the service agents the Service Usage identity
API does not return from the dedicated data source Google documents for them (closed table): Cloud Storage
(`data "google_storage_project_service_account"`; the identity API returns no email for storage.googleapis.com,
hashicorp/terraform-provider-google#19970). BigQuery (the bq-<number>@bigquery-encryption account, data
"google_bigquery_default_service_account") is HELD for the owner: through the exact API table its data source would
add bigquery.googleapis.com to every security-kms caller's enabled APIs (regulated workloads included), so the
module refuses bigquery today. Every other service keeps `google_project_service_identity`; a value the module
cannot grant is refused by the variable's validation. The storage grant is an instance of service_agents, which
crypto_key_name depends_on. Then the held TI-5-G3 prompt line lands (grant service agents through
`service_agent_services`).

Static checks always run; the production column (tofu 1.9.0 + the production mirror, outbound network denied, mocked
providers, plan only) runs where the untracked engine is present (STACKVEND_PROD_TOFU / STACKVEND_PROD_MIRROR), as
tests/test_lane14_pr0b_regulated.py. Do No Harm: with no dedicated agent requested the plan is byte-identical to the
module before G3b (tests/fixtures/ti5_g3b/security-kms-main.pre-g3b.tf.txt)."""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
import shutil
import subprocess
import sys

import hcl2
import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

MODULE = os.path.join(REPO_ROOT, "infra", "modules", "security-kms")
PRE_G3B_MAIN = os.path.join(REPO_ROOT, "tests", "fixtures", "ti5_g3b", "security-kms-main.pre-g3b.tf.txt")
PROD_TOFU = os.environ.get("STACKVEND_PROD_TOFU") or os.path.join(REPO_ROOT, "eval", ".tools", "tofu-1.9.0", "tofu")
PROD_MIRROR = os.environ.get("STACKVEND_PROD_MIRROR") or os.path.join(REPO_ROOT, "eval", ".tofu-mirror-prod")
SANDBOX_EXEC = "/usr/bin/sandbox-exec"
SANDBOX_PROFILE = "(version 1)(allow default)(deny network-outbound (remote ip))"
GCS, BQ = "storage.googleapis.com", "bigquery.googleapis.com"
# the regulated platform path (terraform_engine.CMEK_SERVICE_AGENTS) + the CMEK golden modules' services
GRANTABLE = {"aiplatform.googleapis.com", "alloydb.googleapis.com", "artifactregistry.googleapis.com",
             "container.googleapis.com", "firestore.googleapis.com", "pubsub.googleapis.com", "redis.googleapis.com",
             "run.googleapis.com", "secretmanager.googleapis.com", "spanner.googleapis.com", "sqladmin.googleapis.com",
             GCS}   # secretmanager: Opus re-check 10-24 (Secret Manager CMEK docs: identity-API service agent)


def _hcl(name):
    with open(os.path.join(MODULE, name), encoding="utf-8") as fh:
        return hcl2.load(fh)


def test_storage_agent_comes_from_its_documented_data_source_and_the_rest_from_the_identity_api():
    main = _hcl("main.tf")
    data = {(t, n): b for blk in main.get("data", []) for t, bodies in blk.items() for n, b in bodies.items()}
    assert set(data) == {("google_storage_project_service_account", "gcs")}   # BigQuery: held for the owner
    assert "local.gcs_agent_requested" in str(data[("google_storage_project_service_account", "gcs")]["count"])
    locs = {k: v for blk in main["locals"] for k, v in blk.items()}
    assert locs["dedicated_agent_services"] == [GCS]
    dm = str(locs["dedicated_agent_members"])   # typed `member` attribute only: no email is assembled
    assert "data.google_storage_project_service_account.gcs[0].member" in dm
    assert "serviceAccount:" not in dm
    res = {(t, n): b for blk in main["resource"] for t, bodies in blk.items() for n, b in bodies.items()}
    fe = str(res[("google_project_service_identity", "agents")]["for_each"])
    assert "setsubtract" in fe and "local.dedicated_agent_services" in fe
    member = str(res[("google_kms_crypto_key_iam_member", "service_agents")]["member"])
    assert "local.dedicated_agent_members[each.key]" in member
    assert "google_project_service_identity.agents[each.key].member" in member


def test_crypto_key_name_waits_for_every_service_agent_grant_the_storage_one_included():
    outs = {n: b for blk in _hcl("outputs.tf")["output"] for n, b in blk.items()}
    assert "google_kms_crypto_key_iam_member.service_agents" in str(outs["crypto_key_name"]["depends_on"])


def test_validation_lists_exactly_the_grantable_services():
    var = {n: b for blk in _hcl("variables.tf")["variable"] for n, b in blk.items()}["service_agent_services"]
    cond = str(var["validation"][0]["condition"])
    assert {tok for tok in GRANTABLE if tok in cond} == GRANTABLE
    assert cond.count("googleapis.com") == len(GRANTABLE)


def test_gate_allowed_items_mirror_the_module_validation_exactly():
    """Opus re-check (d): the typed gate refuses a service the module cannot grant (IAC.INVALID_VALUE) before tofu
    validate would; the gate's item set is the module's validation list, exactly (parity)."""
    from shared import iac_intent as ii
    items = ii.MODULE_ARG_CLASS_BY_MODULE[("security-kms", "service_agent_services")]["allowed_items"]
    assert set(items) == GRANTABLE and len(items) == len(GRANTABLE)
    art = ii.load_artifacts()
    assert set(art.module("security-kms")["variables"]["service_agent_services"]["allowed_items"]) == GRANTABLE

    def gate(services):
        doc = {"schema": "iac_intent/v1", "outputs": [], "resources": [],
               "modules": [{"module": "security-kms", "name": "k", "args": {"service_agent_services": services}}]}
        return ii.validate_intent(doc, art, ii.IntentContext())
    assert gate([GCS, "secretmanager.googleapis.com"]).ok and gate([]).ok
    for bad in (["compute.googleapis.com"], [GCS, BQ]):
        res = gate(bad)
        assert not res.ok and "IAC.INVALID_VALUE" in {d.code for d in res.diagnostics}, bad


def test_payload_and_control_center_copies_carry_the_module():
    for fname in ("main.tf", "variables.tf"):
        with open(os.path.join(MODULE, fname), encoding="utf-8") as fh:
            disk = fh.read()
        with open(os.path.join(REPO_ROOT, "apps", "control-center", "infra", "modules", "security-kms", fname),
                  encoding="utf-8") as fh:
            assert fh.read() == disk
        for rel in ("shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared",
                    "mcp-servers/terraform/shared"):
            ns = {}
            with open(os.path.join(REPO_ROOT, rel, "builtin_modules_payload.py"), encoding="utf-8") as fh:
                exec(compile(fh.read(), rel, "exec"), ns)  # noqa: S102 - repo-owned data module
            assert ns["BUILTIN_MODULE_FILES"]["security-kms"][fname] == disk, (rel, fname)


def test_catalog_marks_the_data_source_count_as_driven_by_the_literal_only_list():
    from shared import iac_intent as ii
    cat = ii.load_artifacts().module("security-kms")
    drivers = cat["count_drivers"]["service_agent_services"]
    assert "data.google_storage_project_service_account.gcs.count" in drivers
    assert cat["variables"]["service_agent_services"]["count_driver"]


def test_iac_prompt_carries_the_cmek_service_agent_rule():
    from shared import iac_intent as ii
    from developer_agent.juniors.iac_worker import build_iac_intent_worker_prompt
    prompt = build_iac_intent_worker_prompt(ii.load_artifacts())
    assert "pass its crypto_key_name output to the CMEK input" in prompt
    assert ("service_agent_services (e.g.\nstorage.googleapis.com for a bucket); never grant a service agent on the key "
            "yourself.") in prompt
    cmek_line = prompt.split("CMEK: ", 1)[1].split("\n\n", 1)[0]
    assert "bigquery" not in cmek_line   # BigQuery: held for the owner
    assert "service_agent_services (list of aiplatform.googleapis.com|" in prompt   # the gate's closed item set


# ------------------------------------------------------------------------------------------- production column
MOCKS = """mock_provider "google" {
  mock_resource "google_kms_crypto_key" {
    defaults = {
      id = "projects/mock-proj/locations/us-central1/keyRings/mock-proj-docs/cryptoKeys/docs-cmek"
    }
  }
  mock_data "google_storage_project_service_account" {
    defaults = {
      email_address = "service-123456789012@gs-project-accounts.iam.gserviceaccount.com"
      member        = "serviceAccount:service-123456789012@gs-project-accounts.iam.gserviceaccount.com"
    }
  }
  mock_data "google_bigquery_default_service_account" {
    defaults = {
      email  = "bq-123456789012@bigquery-encryption.iam.gserviceaccount.com"
      member = "serviceAccount:bq-123456789012@bigquery-encryption.iam.gserviceaccount.com"
    }
  }
}
mock_provider "google-beta" {
  mock_resource "google_project_service_identity" {
    defaults = {
      email  = "service-123456789012@gcp-sa-mock.iam.gserviceaccount.com"
      member = "serviceAccount:service-123456789012@gcp-sa-mock.iam.gserviceaccount.com"
    }
  }
}
run "plan" {
  command = plan
}
"""


def _root(services):
    return ('terraform {\n  required_providers {\n    google      = { source = "hashicorp/google" }\n'
            '    google-beta = { source = "hashicorp/google-beta" }\n  }\n}\n'
            'module "k" {\n  source                 = "../modules/security-kms"\n  project_id             = "mock-proj"\n'
            '  location               = "us-central1"\n  keyring_name           = "docs"\n  key_name               = "docs-cmek"\n'
            '  workload_sa_email      = "sa-shop@mock-proj.iam.gserviceaccount.com"\n'
            f'  service_agent_services = {json.dumps(services)}\n}}\n'
            'output "crypto_key_name" {\n  value = module.k.crypto_key_name\n}\n')


def _tofu_root(tmp_path, services, main_tf=None):
    if not (os.access(PROD_TOFU, os.X_OK) and os.path.isdir(PROD_MIRROR) and os.path.exists(SANDBOX_EXEC)):
        pytest.skip("production column (tofu 1.9.0 + production mirror + sandbox-exec) not present")
    mod = tmp_path / "modules" / "security-kms"
    shutil.copytree(MODULE, mod)
    if main_tf is not None:
        (mod / "main.tf").write_text(main_tf)
    root = tmp_path / "root"
    (root / "tests").mkdir(parents=True)
    (root / "main.tf").write_text(_root(services))
    (root / "tests" / "plan.tftest.hcl").write_text(MOCKS)
    rc = tmp_path / "tofu.tfrc"
    rc.write_text('provider_installation {\n  filesystem_mirror {\n    path    = %s\n    include = ["*/*/*"]\n  }\n}\n'
                  % json.dumps(PROD_MIRROR))
    home = tmp_path / "home"
    home.mkdir()
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TF_CLI_CONFIG_FILE": str(rc), "CHECKPOINT_DISABLE": "1",
           "TF_IN_AUTOMATION": "1", "TF_INPUT": "0"}

    def tofu(*args, ok=True):
        assert args[0] in ("init", "validate", "test")
        r = subprocess.run([SANDBOX_EXEC, "-p", SANDBOX_PROFILE, PROD_TOFU, *args], cwd=str(root), env=env,
                           capture_output=True, text=True, timeout=600)
        if ok:
            assert r.returncode == 0, (args[0], (r.stdout + r.stderr)[-3000:])
        return r
    tofu("init", "-backend=false", "-input=false", "-no-color")
    return tofu


def _plan(tmp_path, services, main_tf=None):
    """Verbose plan text of a root calling security-kms (main.tf replaced by `main_tf` when given)."""
    tofu = _tofu_root(tmp_path, services, main_tf)
    tofu("validate", "-no-color")
    out = tofu("test", "-test-directory=tests", "-no-color", "-verbose").stdout
    assert "1 passed, 0 failed" in out, out
    return out


def _grants(plan):
    """address -> planned member of every service-agent grant."""
    out, addr = {}, None
    for line in plan.splitlines():
        s = line.strip()
        if s.startswith("# module.k.google_kms_crypto_key_iam_member.service_agents["):
            addr = s[2:].split(" ")[0]
        elif addr and s.startswith("+ member"):
            out[addr] = s.split("=", 1)[1].strip().strip('"')
            addr = None
    return out


def test_production_column_storage_grant_uses_the_documented_account(tmp_path):
    plan = _plan(tmp_path, [GCS, "run.googleapis.com"])
    g = 'module.k.google_kms_crypto_key_iam_member.service_agents["%s"]'
    assert _grants(plan) == {
        g % GCS: "serviceAccount:service-123456789012@gs-project-accounts.iam.gserviceaccount.com",
        g % "run.googleapis.com": "serviceAccount:service-123456789012@gcp-sa-mock.iam.gserviceaccount.com"}
    assert f'google_project_service_identity.agents["{GCS}"]' not in plan
    assert 'google_project_service_identity.agents["run.googleapis.com"]' in plan


def test_production_column_secret_manager_agent_comes_from_the_identity_api(tmp_path):
    """Secret Manager CMEK docs: the agent service-<n>@gcp-sa-secretmanager is created with
    `gcloud beta services identity create --service secretmanager.googleapis.com` (the identity API)."""
    sm = "secretmanager.googleapis.com"
    plan = _plan(tmp_path, [sm])
    assert _grants(plan) == {f'module.k.google_kms_crypto_key_iam_member.service_agents["{sm}"]':
                             "serviceAccount:service-123456789012@gcp-sa-mock.iam.gserviceaccount.com"}
    assert f'google_project_service_identity.agents["{sm}"]' in plan
    assert "google_storage_project_service_account" not in plan


@pytest.mark.parametrize("service", ["compute.googleapis.com", BQ])   # BigQuery: held for the owner
def test_production_column_a_service_the_module_cannot_grant_is_refused_at_validate(tmp_path, service):
    tofu = _tofu_root(tmp_path, [service])
    r = tofu("validate", "-no-color", ok=False)
    assert r.returncode != 0 and "service_agent_services: the module grants only" in (r.stdout + r.stderr)


@pytest.mark.parametrize("services", [[], ["run.googleapis.com"],
                                      ["artifactregistry.googleapis.com", "firestore.googleapis.com",
                                       "run.googleapis.com"],
                                      ["container.googleapis.com", "pubsub.googleapis.com"]])
def test_production_column_no_dedicated_agent_plans_byte_identical_to_the_module_before_g3b(tmp_path, services):
    """Do No Harm: the regulated platform path (CMEK_SERVICE_AGENTS never names storage) and every intent
    without a dedicated agent plan exactly as before (same addresses, same values, no data source read)."""
    with open(PRE_G3B_MAIN, encoding="utf-8") as fh:
        before = _plan(tmp_path / "before", services, main_tf=fh.read())
    after = _plan(tmp_path / "after", services)
    assert after == before
    assert "google_storage_project_service_account" not in after
    assert "google_bigquery_default_service_account" not in after
