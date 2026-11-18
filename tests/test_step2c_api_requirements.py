"""Step 2 S2-C (docs/planning/wave2-step2-plan.md rev 2 §3.3; register HS-63/HS-30): one exact resource-type /
golden-module-source -> API table (shared/api_requirements.{json,py}) for the gateway's additional_apis and the
terraform server's REST batchEnable. Drift tests, exact-rule tests, substring tombstones, parity of the three copies,
and the two consumers."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import glob
import json
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TF_MCP = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway + terraform server requirement) not installed")

from shared.api_requirements import (TABLE_PATH, additional_apis, load_table, module_dir,  # noqa: E402
                                     required_apis)

W = "infra/workload/"
TABLE = load_table()

# Every API id the table may use (reviewed list; a typo or an invented id fails the test, plan §3.3 C1).
KNOWN_API_IDS = {
    "aiplatform.googleapis.com", "alloydb.googleapis.com", "artifactregistry.googleapis.com",
    "bigquery.googleapis.com", "bigtableadmin.googleapis.com", "billingbudgets.googleapis.com",
    "cloudbuild.googleapis.com", "cloudfunctions.googleapis.com", "cloudkms.googleapis.com",
    "cloudresourcemanager.googleapis.com", "cloudscheduler.googleapis.com", "cloudtasks.googleapis.com",
    "composer.googleapis.com", "compute.googleapis.com", "container.googleapis.com", "dataflow.googleapis.com",
    "discoveryengine.googleapis.com", "dns.googleapis.com", "eventarc.googleapis.com", "firestore.googleapis.com",
    "iam.googleapis.com", "iap.googleapis.com", "identitytoolkit.googleapis.com", "logging.googleapis.com",
    "monitoring.googleapis.com", "pubsub.googleapis.com", "redis.googleapis.com", "run.googleapis.com",
    "secretmanager.googleapis.com", "servicenetworking.googleapis.com", "serviceusage.googleapis.com",
    "spanner.googleapis.com", "sqladmin.googleapis.com", "storage.googleapis.com", "vpcaccess.googleapis.com",
    "workflows.googleapis.com",
}

# Types in the 27 recorded eval drafts + assembled trees (GB0 = step2a e17c7b1 replay, extracted 2026-10-13 with
# python-hcl2; golden-module types are checked from infra/modules directly below).
R2C_CORPUS_RESOURCE_TYPES = {
    "google_artifact_registry_repository", "google_billing_budget", "google_cloud_run_v2_service",
    "google_cloud_run_v2_service_iam_member", "google_cloud_scheduler_job", "google_compute_firewall",
    "google_compute_global_address", "google_compute_instance_from_template", "google_compute_instance_template",
    "google_compute_network", "google_compute_router", "google_compute_router_nat", "google_compute_subnetwork",
    "google_container_cluster", "google_firestore_database", "google_project_iam_member", "google_project_service",
    "google_project_service_identity", "google_pubsub_subscription", "google_pubsub_subscription_iam_member",
    "google_pubsub_topic", "google_pubsub_topic_iam_member", "google_secret_manager_secret",
    "google_secret_manager_secret_iam_member", "google_secret_manager_secret_version", "google_service_account",
    "google_service_account_iam_member", "google_service_networking_connection", "google_sql_database",
    "google_sql_database_instance", "google_sql_user", "google_storage_bucket", "google_storage_bucket_iam_member",
    "google_storage_notification", "google_vpc_access_connector", "kubernetes_deployment",
    "kubernetes_horizontal_pod_autoscaler_v2", "kubernetes_manifest", "kubernetes_namespace", "kubernetes_service",
    "kubernetes_service_account", "random_id", "random_password",
}
R2C_CORPUS_DATA_TYPES = {"google_client_config", "google_project", "google_storage_project_service_account"}
R2C_CORPUS_MODULE_DIRS = {"base", "cloud_build", "compute-cloudrun", "compute-event-worker", "compute-gke-autopilot",
                          "workflows"}

# Lane 15 plan rev 2 (f669066) §4.1 resource allow-list and §4.3 data-source allow-list.
LANE15_RESOURCE_ALLOW_LIST = {
    "google_pubsub_topic", "google_pubsub_subscription", "google_pubsub_schema", "google_pubsub_topic_iam_member",
    "google_pubsub_subscription_iam_member", "google_storage_bucket", "google_storage_bucket_iam_member",
    "google_storage_notification", "google_secret_manager_secret", "google_secret_manager_secret_version",
    "google_secret_manager_secret_iam_member", "google_sql_database_instance", "google_sql_database", "google_sql_user",
    "google_redis_instance", "google_bigquery_dataset", "google_bigquery_table", "google_bigquery_dataset_iam_member",
    "google_cloud_scheduler_job", "google_cloud_tasks_queue", "google_cloud_tasks_queue_iam_member",
    "google_eventarc_trigger", "google_kms_key_ring", "google_kms_crypto_key", "google_kms_crypto_key_iam_member",
    "google_monitoring_alert_policy", "google_monitoring_notification_channel", "google_logging_metric",
    "google_compute_network", "google_compute_subnetwork", "google_compute_router", "google_compute_router_nat",
    "google_compute_firewall", "google_compute_global_address", "google_service_networking_connection",
    "google_vpc_access_connector", "google_compute_instance", "google_compute_instance_template",
    "google_compute_instance_from_template", "google_service_account", "google_service_account_iam_member",
    "google_project_iam_member", "google_project_service_identity", "google_cloud_run_v2_service_iam_member",
    "random_id", "random_password",
}
LANE15_DATA_ALLOW_LIST = {
    "google_project", "google_compute_zones", "google_compute_network", "google_compute_subnetwork",
    "google_compute_default_service_account", "google_storage_project_service_account", "google_netblock_ip_ranges",
    "google_service_account", "google_client_openid_userinfo",
}

# Today's (pre-S2-C) gateway inference: 8 `startswith` prefixes (terraform_engine.py infer_additional_apis_from_custom_tf
# at e17c7b1), pinned here for the superset property.
OLD_GATEWAY_PREFIXES = {
    "google_storage_": "storage.googleapis.com", "google_pubsub_": "pubsub.googleapis.com",
    "google_secret_manager_": "secretmanager.googleapis.com", "google_redis_": "redis.googleapis.com",
    "google_cloud_scheduler_": "cloudscheduler.googleapis.com", "google_eventarc_": "eventarc.googleapis.com",
    "google_workflows_": "workflows.googleapis.com", "google_cloud_tasks_": "cloudtasks.googleapis.com",
}


def _golden_files():
    return {os.path.relpath(p, REPO_ROOT): open(p).read()
            for p in sorted(glob.glob(os.path.join(REPO_ROOT, "infra", "modules", "**", "*.tf"), recursive=True))}


def _blocks(text):
    import hcl2
    doc = hcl2.loads(text)
    for kind in ("resource", "data"):
        for entry in doc.get(kind) or []:
            for typ in entry:
                yield kind, typ


# ================================================================================================ the table
def test_every_api_id_is_known_and_rows_are_sorted_lists():
    rows = [TABLE["base_apis"], TABLE["foundation_base_apis"], TABLE["kubernetes"]["apis"]]
    for section in ("resource_types", "data_types", "modules"):
        rows += list(TABLE[section].values())
    for row in rows:
        assert isinstance(row, list) and row == sorted(set(row))
        assert set(row) <= KNOWN_API_IDS, set(row) - KNOWN_API_IDS


def test_every_golden_module_type_and_directory_has_a_row_and_module_rows_cover_their_types():
    per_dir = {}
    for path, text in _golden_files().items():
        d = os.path.basename(os.path.dirname(path))
        for kind, typ in _blocks(text):
            table = TABLE["resource_types"] if kind == "resource" else TABLE["data_types"]
            assert typ in table, f"{path}: {kind} {typ} has no row"
            per_dir.setdefault(d, set()).update(table[typ])
    assert set(per_dir) <= set(TABLE["modules"]), set(per_dir) - set(TABLE["modules"])
    for d, apis in per_dir.items():
        assert apis <= set(TABLE["modules"][d]), (d, apis - set(TABLE["modules"][d]))


def test_corpus_and_lane15_types_have_rows():
    assert R2C_CORPUS_RESOURCE_TYPES | LANE15_RESOURCE_ALLOW_LIST <= set(TABLE["resource_types"])
    assert R2C_CORPUS_DATA_TYPES | LANE15_DATA_ALLOW_LIST <= set(TABLE["data_types"])
    assert R2C_CORPUS_MODULE_DIRS <= set(TABLE["modules"])


def test_foundation_base_apis_are_the_foundation_module_default():
    import hcl2
    doc = hcl2.loads(open(os.path.join(REPO_ROOT, "infra", "modules", "workload-foundation", "base",
                                       "variables.tf")).read())
    default = next(v["base_apis"]["default"] for v in doc["variable"] if "base_apis" in v)
    assert TABLE["foundation_base_apis"] == sorted(default)


def test_kubernetes_rule_is_todays_signature_list_as_exact_values():
    k8s = TABLE["kubernetes"]
    assert set(k8s["api_versions"]) == {"v1", "apps/v1"}
    assert set(k8s["kinds"]) == {"Deployment", "Service", "HorizontalPodAutoscaler", "StatefulSet", "DaemonSet",
                                 "Ingress"}
    assert k8s["apis"] == ["compute.googleapis.com", "container.googleapis.com"]


@pytest.mark.parametrize("copy_dir", [os.path.join(GATEWAY, "shared"), os.path.join(TF_MCP, "shared")])
def test_the_service_copies_are_byte_identical(copy_dir):
    for name in ("api_requirements.py", "api_requirements.json"):
        assert open(os.path.join(copy_dir, name), "rb").read() == \
            open(os.path.join(REPO_ROOT, "shared", name), "rb").read(), (copy_dir, name)


# ================================================================================================ exact rules
def test_base_trio_is_always_required():
    assert set(required_apis({}).apis) == set(TABLE["base_apis"])


def test_exact_types_modules_and_tf_json():
    tf = {
        W + "main.tf": ('module "foundation" {\n  source = "../modules/workload-foundation/base"\n}\n'
                        'module "compute" {\n  source = "../modules/compute-gke-autopilot/"\n}\n'),
        W + "custom.tf": 'resource "google_redis_instance" "c" {\n  name = "c"\n}\n'
                         'data "google_compute_zones" "z" {}\n',
        W + "extra.tf.json": json.dumps({"resource": {"google_kms_key_ring": {"k": {"name": "k"}}}}),
    }
    req = required_apis(tf)
    assert {"container.googleapis.com", "compute.googleapis.com", "redis.googleapis.com", "cloudkms.googleapis.com",
            "firestore.googleapis.com"} <= set(req.apis)
    assert req.sources["redis.googleapis.com"] == ("resource:google_redis_instance",)
    assert "module:compute-gke-autopilot" in req.sources["container.googleapis.com"]
    assert req.unknown == () and req.unparseable_files == ()


def test_substring_tombstones_comments_strings_and_names_never_count():
    tf = {W + "custom.tf": ('# google_compute_instance google_sql compute-gke-autopilot\n'
                            'resource "google_pubsub_topic" "google_storage_bucket" {\n'
                            '  name   = "google_container_cluster"\n'
                            '  labels = { note = "module ../modules/database-cloudsql" }\n}\n')}
    assert set(required_apis(tf).apis) == set(TABLE["base_apis"]) | {"pubsub.googleapis.com"}


def test_unknown_types_remote_and_unknown_modules_are_reported_never_guessed():
    tf = {W + "custom.tf": ('resource "google_kms_ekm_connection" "e" {\n  name = "e"\n}\n'
                            'data "google_kms_secret" "s" {\n  crypto_key = "k"\n  ciphertext = "c"\n}\n'
                            'module "remote" {\n  source = "git::https://example.com/m.git"\n}\n'
                            'module "local_new" {\n  source = "./modules/not-golden"\n}\n')}
    req = required_apis(tf)
    assert "cloudkms.googleapis.com" not in req.apis
    assert set(req.unknown) == {(W + "custom.tf", "resource:google_kms_ekm_connection"),
                                (W + "custom.tf", "data:google_kms_secret"),
                                (W + "custom.tf", "module:git::https://example.com/m.git"),
                                (W + "custom.tf", "module:not-golden")}


def test_unparseable_files_are_reported():
    req = required_apis({W + "bad.tf": 'resource "x" "y" {\n  a = [1]]\n}\n', W + "bad.tf.json": "{nope"},
                        {"k8s/bad.yaml": "a: [1\n"})
    assert set(req.unparseable_files) == {W + "bad.tf", W + "bad.tf.json", "k8s/bad.yaml"}


def test_kubernetes_yaml_by_exact_apiversion_or_kind_only():
    deploy = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: w\n"
    assert "container.googleapis.com" in required_apis({}, {"k8s/d.yaml": deploy}).apis
    multi = "---\nfoo: bar\n---\nkind: Service\n"
    assert "container.googleapis.com" in required_apis({}, {"k8s/s.yaml": multi}).apis
    workflow = "name: ci\non: push\njobs:\n  b:\n    runs-on: ubuntu\n    env:\n      NOTE: 'kind: Deployment'\n"
    assert "container.googleapis.com" not in required_apis({}, {".github/workflows/ci.yml": workflow}).apis
    assert "container.googleapis.com" not in required_apis({}, {"x.yaml": "apiVersion: apps/v1beta1\n"}).apis


@pytest.mark.parametrize("source,want", [
    ("../modules/compute-cloudrun", "compute-cloudrun"), ("./modules/x/", "x"), ("../modules/a/../b", "b"),
    ("git::https://x/y", None), ("registry/x/y", None), ("${var.m}", None), (None, None), ("../", None),
])
def test_module_dir_is_the_last_component_of_a_literal_local_source(source, want):
    assert module_dir(source) == want


def test_superset_of_todays_gateway_inference():
    """Every API the old 8-prefix gateway inference emitted for a known type is still enabled by the foundation
    (its base_apis default) or listed in additional_apis."""
    for typ in sorted(TABLE["resource_types"]):
        old = {api for prefix, api in OLD_GATEWAY_PREFIXES.items() if typ.startswith(prefix)}
        req = required_apis({W + "custom.tf": f'resource "{typ}" "x" {{}}\n'})
        enabled = set(TABLE["foundation_base_apis"]) | set(additional_apis(req))
        assert old <= enabled, (typ, old - enabled)


def test_additional_apis_drop_what_the_foundation_and_vending_already_enable():
    req = required_apis({W + "custom.tf": 'resource "google_storage_bucket" "b" {}\n'
                                          'resource "google_redis_instance" "r" {}\n'})
    assert additional_apis(req) == ["redis.googleapis.com"]


# ================================================================================================ gateway (C0 / C1)
def test_gateway_inference_is_the_table_over_the_root_module_incl_golden_module_calls():
    from developer_agent.terraform_engine import infer_additional_apis_from_custom_tf
    root = {W + "main.tf": 'module "compute" {\n  source = "../modules/compute-gke-autopilot"\n}\n',
            W + "custom.tf": 'resource "google_vpc_access_connector" "c" {}\n'
                             'resource "google_sql_database_instance" "db" {}\n',
            W + "README.md": "google_kms_key_ring"}
    assert infer_additional_apis_from_custom_tf(root) == [
        "compute.googleapis.com", "container.googleapis.com", "sqladmin.googleapis.com", "vpcaccess.googleapis.com"]
    assert infer_additional_apis_from_custom_tf(None) == [] and infer_additional_apis_from_custom_tf({}) == []
    # legacy single-text callers: one custom.tf
    assert infer_additional_apis_from_custom_tf('resource "google_redis_instance" "r" {}\n') == ["redis.googleapis.com"]


def test_gateway_tombstone_no_prefix_inference_left():
    src = open(os.path.join(GATEWAY, "developer_agent", "terraform_engine.py")).read()
    fn = next(n for n in ast.walk(ast.parse(src))
              if isinstance(n, ast.FunctionDef) and n.name == "infer_additional_apis_from_custom_tf")
    calls = {c.func.attr for c in ast.walk(fn) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)}
    assert "startswith" not in calls
    names = {c.func.id for c in ast.walk(fn) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}
    assert {"required_apis", "additional_apis"} <= names


def test_handler_passes_the_root_module_files_not_the_bespoke_text():
    src = open(os.path.join(GATEWAY, "developer_agent", "handler.py")).read()
    call = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                and n.func.id == "infer_additional_apis_from_custom_tf")
    assert isinstance(call.args[0], ast.DictComp)


def test_platform_owned_hint_promise_holds_for_every_known_type():
    """C0: HINT_PLATFORM_OWNED says the platform enables the APIs of the types and golden modules the AI declares,
    from an exact table, and reports unknown types. For every row, a root module declaring that type gets its APIs
    enabled (foundation base_apis or additional_apis); an unknown type is reported by V2g."""
    from developer_agent.terraform_engine import infer_additional_apis_from_custom_tf
    from developer_agent.validators import policy_tables as T
    assert "exact table" in T.HINT_PLATFORM_OWNED and "reported, not guessed" in T.HINT_PLATFORM_OWNED
    enabled_by_foundation = set(TABLE["foundation_base_apis"]) | set(TABLE["base_apis"])
    for typ, row in TABLE["resource_types"].items():
        got = set(infer_additional_apis_from_custom_tf({W + "custom.tf": f'resource "{typ}" "x" {{}}\n'}))
        assert set(row) <= got | enabled_by_foundation, typ
    for d, row in TABLE["modules"].items():
        got = set(infer_additional_apis_from_custom_tf({W + "main.tf": f'module "m" {{\n  source = "../modules/{d}"\n}}\n'}))
        assert set(row) <= got | enabled_by_foundation, d


def test_v2g_reports_unknown_types_and_unparseable_root_files():
    from developer_agent.validators import ValidationContext
    from developer_agent.validators.step1 import ApiCoverageValidator, build_step1_stack
    from shared.artifact_ownership import Ownership
    files = {W + "main.tf": 'module "compute" {\n  source = "../modules/compute-cloudrun"\n}\n',
             W + "custom.tf": 'resource "google_kms_ekm_connection" "e" {}\nresource "google_pubsub_topic" "t" {}\n',
             W + "broken.tf": 'resource "x" "y" {\n  a = [1]]\n}\n',
             "infra/modules/compute-cloudrun/main.tf": 'resource "google_mystery_thing" "z" {}\n'}
    ctx = ValidationContext.build(files, ownership=lambda p: Ownership.LLM_AUTHORED, vendored=frozenset(), draft={},
                                  assembly=None, extras={}, trace_id="t")
    got = sorted((d.code, d.file, d.detail) for d in ApiCoverageValidator().validate(ctx))
    assert got == [("IAC.API_SCAN_UNPARSEABLE", W + "broken.tf", None),
                   ("IAC.API_UNKNOWN_FOR_TYPE", W + "custom.tf", "resource:google_kms_ekm_connection")]
    assert build_step1_stack(validate_client=None, verifier_factory=None).mode_of("V2g") == "report_only"
