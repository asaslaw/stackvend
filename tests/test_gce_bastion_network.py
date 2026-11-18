"""gce-bastion-network (F1 + F2 of docs/handoff/gce-bastion-startup-report.md): a gce-bastion reaches Google APIs.

Before: the bastion VM sat on `var.network = "default"` with no external IP, no Cloud NAT and no Private Google Access
(default-VPC subnets have PGA off; a folder with compute.skipDefaultNetworkCreation has no default VPC at all), its SA
held only log / metric writer, and the topology's resource bindings on it were dropped. Now, by the compute-gce-worker
L10-u2 / L10-v mechanisms:
- network: the workload's existing subnetwork (`workload_subnetwork_ref`), else its own VPC + subnet with PGA on the
  IPAM fact `var.subnet_cidr` (asked for by `primary_network_purposes`); no NAT, no external IP, no internet;
- settings: the topology's resource bindings on the bastion as instance metadata attributes (`settings`);
- access: one own-SA grant per consumed resource (`worker_access`, the WORKER_RESOURCE_ACCESS roles).
Do No Harm: with neither topology nor facts the rendered main.tf is byte-identical (the PR-0b pin), the module's new
inputs default to the old network / metadata, and no prompt text changes (a gce-bastion still has no `env_vars`, so
`env_for` and the topology contract rule are unchanged). Hermetic."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import hashlib
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import hcl2  # noqa: E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: put eval/.deps on PYTHONPATH; this file must not skip", pytrace=False)

from developer_agent import terraform_engine as te  # noqa: E402
from fd4atc_render import without_fd4atc  # noqa: E402  (FD-4AT-c pin normalization)
from visible_rename_render import pre_visible_rename  # noqa: E402  (VISIBLE-RENAME pin normalization)
from developer_agent.contract_inspector import _EMBEDDED_MODULE_CONTRACTS  # noqa: E402
from developer_agent.platform_facts import (  # noqa: E402
    PURPOSE_CONNECTOR,
    PURPOSE_SUBNET,
    NetworkFacts,
    has_existing_network,
    required_network_purposes,
)
from developer_agent.topology_wiring import (  # noqa: E402
    primary_network_purposes,
    render_gce_bastion_code_lines,
    topology_contract_rule,
    vm_startup_script_expr,
)
from shared import service_topology as st  # noqa: E402

MODULE = "compute-gce-bastion"
MODULE_DIR = os.path.join(REPO_ROOT, "infra", "modules", MODULE)
PRE_CHANGE_BASTION_MAIN_SHA256 = "66c60e93f287ec4ffe48151c90f3b2624b8d906e4d3b44982d2cd43c466fdced"   # PR-0b pin
SCRIPT = "#!/bin/bash\necho export\n"
FACTS = NetworkFacts(product_id="shop", region="us-central1", subnet_cidr="10.40.0.0/24", source="memory")
CONNECTOR_ONLY = NetworkFacts(product_id="shop", region="us-central1", connector_cidr="10.8.0.0/28", source="memory")
VPC_MODULE = ('module "net" {\n  source              = "../modules/networking-vpc"\n  project_id          = '
              'var.project_id\n  primary_subnet_cidr = var.subnet_cidr\n}\n')
SUBNET_RESOURCE = ('resource "google_compute_subnetwork" "private" {\n  name          = "p"\n  network       = "n"\n'
                   '  ip_cidr_range = var.subnet_cidr\n}\n')


def sha(text):
    # FD-4AT-c: the pin predates the foundation module's github_repository_id line (tests/fd4atc_render.py).
    # VISIBLE-RENAME (owner 10-26): ... and the StackVend header comment (tests/visible_rename_render.py).
    # RT14-F1: ... and the root zone read + `zone` input of a bastion render (tests/rt14_bastion_zone_render.py).
    from rt14_bastion_zone_render import without_rt14_bastion_zone
    text = without_rt14_bastion_zone(text)
    return hashlib.sha256(without_fd4atc(pre_visible_rename(text)).encode("utf-8")).hexdigest()


def main_tf(files=None, service_name="ops-bastion", **kw):
    return te.generate_golden_main_tf("shop", "gce-bastion", "", service_name=service_name, app_files=files, **kw)


def compute_body(text):
    return [m for m in hcl2.loads(text)["module"] if "compute" in m][0]["compute"]


def topo(services, primary, resources=()):
    return {"services": list(services), "primary_service": primary, "edges": [], "resources": list(resources)}


def res(type_, logical, *consumers):
    return {"type": type_, "logical_name": logical,
            "consumers": [{"service": s, "env_key": k} for s, k in consumers]}


def ok(raw):
    vt, diags = st.validate_service_topology(raw, product_id="shop")
    assert vt is not None, [(d.code, d.message) for d in diags]
    return vt


# Gate B S3 shape: a nightly export bastion writing to a bucket and reading a token from Secret Manager.
S3 = ok(topo([{"name": "ops-bastion", "kind": "gce-bastion", "purpose": "nightly export"}], "ops-bastion", [
    res("google_storage_bucket", "ops_reports", ("ops-bastion", "OPS_REPORTS_BUCKET")),
    res("google_secret_manager_secret", "ops_token", ("ops-bastion", "OPS_TOKEN_SECRET")),
    res("google_sql_database_instance", "db", ("ops-bastion", "DB_CONNECTION")),
]))


# ------------------------------------------------------------------------------------------- Do No Harm (renders)
@pytest.mark.parametrize("files", [None, {}, {"apps/ops-bastion/main.py": "x = 1\n"}])
def test_no_topology_no_facts_renders_byte_identical(files):
    assert sha(main_tf(files)) == PRE_CHANGE_BASTION_MAIN_SHA256
    assert sha(main_tf(files, topology=None, network_facts=None)) == PRE_CHANGE_BASTION_MAIN_SHA256


def test_startup_script_only_renders_exactly_the_gbs1_line():
    files = {"apps/ops-bastion/startup.sh": SCRIPT}
    assert render_gce_bastion_code_lines("ops-bastion", files) == \
        f"\n  startup_script = {vm_startup_script_expr(files, 'ops-bastion')}\n"


def test_facts_without_a_subnet_render_no_network_line():
    assert sha(main_tf({}, network_facts=CONNECTOR_ONLY)) == PRE_CHANGE_BASTION_MAIN_SHA256


@pytest.mark.parametrize("archetype", ["cloudrun", "gke-autopilot", "event-worker"])
def test_other_archetypes_ignore_topology_and_facts(archetype):
    base = te.generate_golden_main_tf("shop", archetype, "", service_name="api", app_files={})
    assert te.generate_golden_main_tf("shop", archetype, "", service_name="api", app_files={},
                                      topology=S3, network_facts=FACTS) == base


def test_a_topology_whose_primary_is_not_the_bastion_adds_nothing():
    vt = ok(topo([{"name": "api", "kind": "cloudrun"}], "api",
                 [res("google_storage_bucket", "b", ("api", "B_BUCKET"))]))
    assert render_gce_bastion_code_lines("ops-bastion", {}, topology=vt) == ""
    assert render_gce_bastion_code_lines("api", {}, topology=vt) == ""   # not a gce-bastion


# ------------------------------------------------------------------------------------------- network
def test_subnet_fact_gives_the_bastion_its_own_pga_subnet():
    body = compute_body(main_tf({}, network_facts=FACTS))
    assert body["subnet_cidr"] == "${var.subnet_cidr}"
    assert "use_existing_subnetwork" not in body and "subnetwork_id" not in body


@pytest.mark.parametrize("text,ref", [
    (VPC_MODULE, "${module.net.primary_subnetwork_id}"),
    (SUBNET_RESOURCE, "${google_compute_subnetwork.private.id}"),
])
def test_the_workload_subnetwork_wins_over_an_own_subnet(text, ref):
    body = compute_body(main_tf({"infra/workload/network.tf": text}, network_facts=FACTS))
    assert body["use_existing_subnetwork"] is True and body["subnetwork_id"] == ref
    assert "subnet_cidr" not in body


def test_primary_network_purposes_only_for_a_bastion():
    assert primary_network_purposes("gce-bastion") == frozenset({PURPOSE_SUBNET})
    for a in ("cloudrun", "gke-autopilot", "event-worker", "foundation-only", None, ""):
        assert primary_network_purposes(a) == frozenset()


def test_the_platform_bastion_block_is_not_an_existing_network_allocation():
    # Deliberately not in platform_facts.ALLOCATION_ATTRIBUTES (unlike compute-gce-worker): an existing bastion
    # workload is not switched to reuse-only (which would pin a legacy bastion on the default VPC and turn V2h into a
    # measurement for its AI code). A regeneration asks for WORKLOAD_SUBNET again (primary_network_purposes) and the
    # IPAM ledger returns this product's own record, so the own subnet keeps its range.
    for text in (main_tf({}, network_facts=FACTS), main_tf({})):
        tree = {"infra/workload/main.tf": text}
        assert required_network_purposes(tree) == frozenset() and not has_existing_network(tree)
    assert PURPOSE_CONNECTOR not in primary_network_purposes("gce-bastion")


# ------------------------------------------------------------------------------------------- settings + access
def test_s3_bindings_become_metadata_settings_and_own_sa_grants():
    body = compute_body(main_tf({}, topology=S3, network_facts=FACTS))
    assert body["settings"] == {
        "DB_CONNECTION": "${google_sql_database_instance.db.connection_name}",
        "OPS_REPORTS_BUCKET": "${google_storage_bucket.ops_reports.name}",
        "OPS_TOKEN_SECRET": "${google_secret_manager_secret.ops_token.secret_id}",
    }
    assert body["storage_buckets"] == ["${google_storage_bucket.ops_reports.name}"]
    assert body["secrets"] == ["${google_secret_manager_secret.ops_token.secret_id}"]
    # Cloud SQL has no resource-level grant in WORKER_RESOURCE_ACCESS: setting only, no list input
    assert not {"pubsub_topics", "pubsub_subscriptions", "bigquery_datasets"} & set(body)


def test_another_services_bindings_never_reach_the_bastion():
    vt = ok(topo([{"name": "ops-bastion", "kind": "gce-bastion"}], "ops-bastion",
                 [res("google_storage_bucket", "b")]))   # declared, consumed by nobody
    assert render_gce_bastion_code_lines("ops-bastion", {}, topology=vt) == ""


def test_resource_env_is_unchanged_and_bindings_are_the_same_values():
    assert S3.resource_env("ops-bastion") == {} and S3.env_for("ops-bastion") == {}
    assert sorted(S3.resource_bindings("ops-bastion")) == ["DB_CONNECTION", "OPS_REPORTS_BUCKET", "OPS_TOKEN_SECRET"]
    vt = ok(topo([{"name": "api", "kind": "cloudrun"}], "api",
                 [res("google_storage_bucket", "b", ("api", "B_BUCKET"))]))
    assert vt.resource_env("api") == vt.resource_bindings("api") == {"B_BUCKET": "google_storage_bucket.b.name"}


def test_no_prompt_text_changes_for_a_bastion_with_bindings():
    rule = topology_contract_rule(S3)
    assert "OPS_REPORTS_BUCKET" not in rule and "metadata" not in rule
    assert st.CAPABILITIES["gce-bastion"].accepts_env_vars is False


def test_metadata_keys_cannot_collide_with_platform_keys():
    # EnvKey is upper-case; the platform's metadata keys are lower-case and merged last in the module
    for k in S3.resource_bindings("ops-bastion"):
        assert k == k.upper() and k not in ("startup-script", "enable-oslogin")


# ------------------------------------------------------------------------------------------- module
def _module(name):
    with open(os.path.join(MODULE_DIR, name), encoding="utf-8") as f:
        return f.read()


def test_module_new_inputs_default_to_the_old_behavior():
    variables = {k: v for b in hcl2.loads(_module("variables.tf"))["variable"] for k, v in b.items()}
    assert variables["network"]["default"] == "default" and variables["subnetwork"]["default"] == ""
    assert variables["subnet_cidr"]["default"] == "" and variables["use_existing_subnetwork"]["default"] is False
    assert variables["subnetwork_id"]["default"] == "" and variables["settings"]["default"] == {}
    for v in ("storage_buckets", "pubsub_topics", "pubsub_subscriptions", "secrets", "bigquery_datasets"):
        assert variables[v]["default"] == []


def test_module_has_no_external_ip_no_nat_and_pga_on_its_own_subnet():
    doc = hcl2.loads(_module("main.tf"))
    types = {t for b in doc["resource"] for t in b}
    assert not {"google_compute_router", "google_compute_router_nat", "google_compute_address"} & types
    inst = [b["google_compute_instance"]["bastion"] for b in doc["resource"] if "google_compute_instance" in b][0]
    assert all("access_config" not in ni for ni in inst["network_interface"])
    sub = [b["google_compute_subnetwork"]["bastion"] for b in doc["resource"] if "google_compute_subnetwork" in b][0]
    assert sub["private_ip_google_access"] is True and sub["ip_cidr_range"] == "${var.subnet_cidr}"
    assert sub["count"] == "${local.own_network}"
    assert "secondary_ip_range" in str(sub["lifecycle"])     # golden-module subnetwork lifecycle rule


# ------------------------------------------------------------------------------------------- end to end (handler)
S3_CUSTOM = ('resource "google_storage_bucket" "ops_reports" {\n  name                        = "${var.product_id}-ops"\n'
             '  location                    = var.region\n  uniform_bucket_level_access = true\n}\n\n'
             'resource "google_secret_manager_secret" "ops_token" {\n  secret_id = "ops-token"\n'
             '  replication {\n    auto {}\n  }\n}\n')
S3_DRAFT = {"apps/ops-bastion/startup.sh": "#!/bin/bash\necho nightly export\n", "infra/workload/custom.tf": S3_CUSTOM}


def _generate(draft, provider, existing=None):
    """generate_code_files on a fixed draft through the hallucination stack (lane 11 e2e harness shape)."""
    from unittest.mock import MagicMock, patch

    from developer_agent import handler as h
    from developer_agent import hallucination_runtime as hr
    from shared.diagnostics import MemoryLedgerStore, MemoryProvenanceStore
    from shared.hallucination_stack import HallucinationStackSettings

    class Client:
        def ready(self, iac_engine="OPENTOFU"):
            return {"ready": True, "providers": ["google", "google-beta", "random"], "engine": "OPENTOFU",
                    "engine_version": "1.9.0"}

        def validate(self, files, *, iac_engine="OPENTOFU", trace_id=""):
            return {"status": "PASS", "diagnostics": []}

    class NoLLM:
        class models:  # noqa: N801
            @staticmethod
            def generate_content(*a, **k):
                raise AssertionError("unexpected LLM call")

    rt = hr.HallucinationRuntime(ledger_store=MemoryLedgerStore(), provenance_store=MemoryProvenanceStore(),
                                 validate_client=Client(), source="test", facts_provider=provider,
                                 settings=HallucinationStackSettings(repair_max_iterations_precommit=0))
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GEMINI_API_KEY": ""}):
        agent = h.DeveloperAgent(project_id="")
    agent.genai_client = NoLLM()
    agent.attach_stack_runtime(rt)
    plan = MagicMock()
    plan.execution_mode = [m for m in h.SwarmExecutionMode if m != h.SwarmExecutionMode.SOLO_FAST_PATH][0]
    plan.tasks = [MagicMock()]
    d = dict(draft)

    class FakeDispatcher:
        def __init__(self, *a, **k):
            self.last_file_attribution = {p: "iac_worker" if p.endswith(".tf") else "backend_worker" for p in d}
            self.envelope_checks = [{"ok": True, "error": None}]

        async def execute_phased_junior_swarm(self, *a, **k):
            return dict(d)

    rec = {"schema": "architect_compute_intent/v2", "target_compute_services": list(S3.names), "bundle_id": None,
           "compute_archetype": S3.archetype, "service_topology": S3.as_record()}
    with patch.object(h, "LeadDeveloperOrchestrator") as lead, patch.object(h, "SwarmDispatcher", FakeDispatcher), \
            patch.object(agent, "fetch_existing_repo_files", return_value=dict(existing or {})), \
            patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GCP_PROJECT": ""}), \
            patch("google.cloud.firestore.Client", side_effect=RuntimeError("no Firestore in tests")), \
            patch("shared.settings.get_platform_settings",  # FD-4AK: the IPAM pool read is strict; state the settings
                  return_value=__import__("shared.settings", fromlist=["x"]).PlatformSettings()):
        lead.return_value.decompose_specification.return_value = plan
        files = agent.generate_code_files(product_id="shop", spec_text="nightly export bastion", task_dag=[],
                                          trace_id="trace-gbn", architect_compute_intent=rec,
                                          allow_unauthenticated=True, enable_direct_iap=False,
                                          domain_restricted_sharing=False)
    return agent, files


S3_DB = ('resource "google_sql_database_instance" "db" {\n  name             = "${var.product_id}-db"\n'
         '  database_version = "POSTGRES_15"\n  region           = var.region\n  settings {\n'
         '    tier = "db-f1-micro"\n  }\n}\n')


def test_e2e_s3_bastion_gets_its_subnet_fact_settings_and_grants():
    from developer_agent import platform_facts as PF
    provider = PF.MemoryFactsProvider()
    draft = dict(S3_DRAFT, **{"infra/workload/custom.tf": S3_CUSTOM + "\n" + S3_DB})
    agent, files = _generate(draft, provider)
    assert agent.last_validation_report.status == "PASS"
    assert list(provider.ledger) == [("shop", PF.PURPOSE_SUBNET)]
    body = compute_body(files["infra/workload/main.tf"])
    assert body["subnet_cidr"] == "${var.subnet_cidr}"
    assert body["settings"]["OPS_REPORTS_BUCKET"] == "${google_storage_bucket.ops_reports.name}"
    assert body["storage_buckets"] == ["${google_storage_bucket.ops_reports.name}"]
    assert body["secrets"] == ["${google_secret_manager_secret.ops_token.secret_id}"]
    assert "startup_script" in body
    declared = {n for b in hcl2.loads(files["infra/workload/variables.tf"])["variable"] for n in b}
    assert "subnet_cidr" in declared
    assert hcl2.loads(files["infra/workload/terraform.tfvars"])["subnet_cidr"] == provider.ledger[("shop",
                                                                                                    PF.PURPOSE_SUBNET)]
    assert files["infra/workload/custom.tf"].startswith(S3_CUSTOM)   # the AI file is not edited


def test_payload_copies_and_embedded_contract_equal_the_module():
    paths = ["shared/builtin_modules_payload.py", "mcp-servers/terraform/shared/builtin_modules_payload.py",
             "apps/orchestrator-gateway/shared/builtin_modules_payload.py",
             "apps/control-center/shared/builtin_modules_payload.py"]
    for p in paths:
        with open(os.path.join(REPO_ROOT, p), encoding="utf-8") as f:
            d = ast.literal_eval(ast.parse(f.read()).body[-1].value)
        for name in ("main.tf", "variables.tf", "outputs.tf"):
            assert d[MODULE][name] == _module(name), (p, name)
            with open(os.path.join(REPO_ROOT, "apps", "control-center", "infra", "modules", MODULE, name),
                      encoding="utf-8") as f:
                assert f.read() == _module(name)
    declared = {k for b in hcl2.loads(_module("variables.tf"))["variable"] for k in b}
    assert set(_EMBEDDED_MODULE_CONTRACTS[MODULE]["inputs"]) == declared
