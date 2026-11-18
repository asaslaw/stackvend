"""platform-db-connector-wiring: the platform renders a Cloud Run service's `vpc_access_connector` at generation from
typed facts (the architect's `resources[].consumers` edge to a private Cloud SQL / Redis instance + the exact network
references of the AI's root-module IaC), so the deploy-time HA-13 phase 5 never has anything to add.

Fixtures are trimmed copies of real eval trees (Gate A 20261018 `08-r1` / `08-r3`, Gate B `S5-r1` / `S5-r3`).
Do No Harm: every case without such an edge, or without exactly one connector on that network, renders byte-identical
to the code before this change. Hermetic, offline."""
import hermetic_guard  # noqa: F401  (first import)

import ast
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
    pytest.fail("python-hcl2 missing: install apps/orchestrator-gateway/requirements.txt or put eval/.deps on "
                "PYTHONPATH; this file is acceptance evidence and must not skip", pytrace=False)

from developer_agent import terraform_engine as te  # noqa: E402
from fd4atc_render import without_fd4atc  # noqa: E402  (FD-4AT-c pin normalization)
from developer_agent.assembly import CUSTOM_TF  # noqa: E402
from developer_agent.topology_wiring import exact_reference, topology_vpc_connector  # noqa: E402
from shared.diagnostics import AssemblyRecord  # noqa: E402
from shared.service_topology import validate_service_topology  # noqa: E402

W = "infra/workload/"
MAIN_TF = W + "main.tf"
SVC = "test-08-cloudsql-postgres"

# Gate A 08-r1 (connector `network` = the VPC's `.name`; Cloud SQL private_network = the VPC's `.id`)
CUSTOM_08 = '''resource "google_compute_network" "private_network" {
  name                    = "${var.product_id}-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_global_address" "private_ip_address" {
  name          = "${var.product_id}-private-ip"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.private_network.id
}

resource "google_service_networking_connection" "private_vpc_connection" {
  network                 = google_compute_network.private_network.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_ip_address.name]
}

resource "google_vpc_access_connector" "connector" {
  name          = "cr-conn"
  region        = var.region
  ip_cidr_range = var.connector_cidr
  network       = google_compute_network.private_network.name
}

resource "google_sql_database_instance" "postgres" {
  name             = "${var.product_id}-pg-inst"
  database_version = "POSTGRES_15"
  region           = var.region
  depends_on       = [google_service_networking_connection.private_vpc_connection]

  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.private_network.id
    }
  }
  deletion_protection = false
}

resource "google_secret_manager_secret" "postgres_db_credentials" {
  secret_id = "postgres-db-credentials"
  replication {
    auto {}
  }
}
'''

# Gate B S5-r1 (connector on a `subnet { name }` of the VPC; Redis authorized_network = the VPC's `.id`)
CUSTOM_S5 = '''resource "google_redis_instance" "quote_cache" {
  name               = "quote-cache"
  memory_size_gb     = 1
  authorized_network = google_compute_network.vpc.id
}

resource "google_compute_network" "vpc" {
  name                    = "vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "connector_subnet" {
  name          = "connector-sub"
  ip_cidr_range = var.connector_cidr
  region        = var.region
  network       = google_compute_network.vpc.id
}

resource "google_vpc_access_connector" "connector" {
  name   = var.vpc_connector_name
  region = var.region
  subnet {
    name = google_compute_subnetwork.connector_subnet.name
  }
}
'''

# Gate B S5-r3 (no VPC resource: both sides on the same input variable)
CUSTOM_S5_VAR = '''resource "google_vpc_access_connector" "connector" {
  name          = "quote-vpc-conn"
  region        = var.region
  network       = var.network_id
  ip_cidr_range = var.connector_cidr
}

resource "google_redis_instance" "quote_cache" {
  name               = "quote-cache"
  memory_size_gb     = 1
  authorized_network = var.network_id
}
'''

SQL_CONSUMER = {"type": "google_sql_database_instance", "logical_name": "postgres",
                "consumers": [{"service": SVC, "env_key": "DB_HOST", "attribute": "private_ip_address"}]}
SECRET_CONSUMER = {"type": "google_secret_manager_secret", "logical_name": "postgres_db_credentials",
                   "consumers": [{"service": SVC, "env_key": "DB_SECRET_ID", "attribute": "secret_id"}]}
REDIS_CONSUMER = {"type": "google_redis_instance", "logical_name": "quote_cache",
                  "consumers": [{"service": SVC, "env_key": "REDIS_HOST", "attribute": "host"}]}


def vt_of(resources=(), services=((SVC, "cloudrun"),), primary=SVC):
    raw = {"services": [{"name": n, "kind": k} for n, k in services], "primary_service": primary, "edges": [],
           "resources": list(resources)}
    vt, diags = validate_service_topology(raw, product_id="p", file="t")
    assert vt is not None, [(d.code, d.message) for d in diags]
    return vt


def tree(custom):
    return {CUSTOM_TF: custom, MAIN_TF: "# platform main.tf (previous render)\n"}


def compute_body(text, label="compute"):
    for m in hcl2.loads(text).get("module", []):
        if label in m:
            return m[label]
    return None


# ------------------------------------------------------------------------------------------------ exact reference
@pytest.mark.parametrize("value,expected", [
    ("${google_compute_network.vpc.id}", ("google_compute_network", "vpc", "id")),
    ("${var.network_id}", ("var", "network_id")),
    ("${module.network.network_id}", ("module", "network", "network_id")),
    ("default", None),                                    # literal
    ("${var.a}-${var.b}", None),                          # template with two interpolations
    ("x-${var.a}", None),                                 # template with text
    ("${google_compute_network.vpc[0].id}", None),        # index
    ("${element(var.networks, 0)}", None),                # call
    (None, None), (3, None),
])
def test_exact_reference_reads_only_one_bare_traversal(value, expected):
    assert exact_reference(value) == expected


# ------------------------------------------------------------------------------------------------ the typed rule
def test_ex08_cloud_sql_private_ip_consumer_gets_the_connector_on_the_instance_network():
    vt = vt_of([SQL_CONSUMER, SECRET_CONSUMER])
    assert topology_vpc_connector(vt, SVC, tree(CUSTOM_08)) == "google_vpc_access_connector.connector.id"


def test_s5_redis_consumer_gets_the_connector_on_a_subnet_of_the_authorized_network():
    vt = vt_of([REDIS_CONSUMER])
    assert topology_vpc_connector(vt, SVC, tree(CUSTOM_S5)) == "google_vpc_access_connector.connector.id"


def test_same_input_variable_is_the_same_network():
    vt = vt_of([REDIS_CONSUMER])
    assert topology_vpc_connector(vt, SVC, tree(CUSTOM_S5_VAR)) == "google_vpc_access_connector.connector.id"


def test_redis_port_consumer_also_needs_the_route():
    vt = vt_of([dict(REDIS_CONSUMER, consumers=[{"service": SVC, "env_key": "REDIS_PORT", "attribute": "port"}])])
    assert topology_vpc_connector(vt, SVC, tree(CUSTOM_S5)) == "google_vpc_access_connector.connector.id"


# ---- negative: nothing is rendered without the typed facts (Do No Harm)
def test_no_consumer_edge_no_connector_even_when_both_are_declared():
    assert topology_vpc_connector(vt_of([SECRET_CONSUMER]), SVC, tree(CUSTOM_08)) is None
    assert topology_vpc_connector(vt_of([]), SVC, tree(CUSTOM_08)) is None


def test_cloud_sql_connection_name_consumer_needs_no_vpc_route():
    explicit = dict(SQL_CONSUMER, consumers=[{"service": SVC, "env_key": "DB_CONN", "attribute": "connection_name"}])
    default = dict(SQL_CONSUMER, consumers=[{"service": SVC, "env_key": "DB_CONN"}])   # catalog default attribute
    assert topology_vpc_connector(vt_of([explicit]), SVC, tree(CUSTOM_08)) is None
    assert topology_vpc_connector(vt_of([default]), SVC, tree(CUSTOM_08)) is None


def test_another_service_consumer_does_not_wire_this_service():
    vt = vt_of([dict(SQL_CONSUMER, consumers=[{"service": "worker", "env_key": "DB_HOST",
                                               "attribute": "private_ip_address"}])],
               services=((SVC, "cloudrun"), ("worker", "cloudrun")))
    assert topology_vpc_connector(vt, SVC, tree(CUSTOM_08)) is None
    assert topology_vpc_connector(vt, "worker", tree(CUSTOM_08)) == "google_vpc_access_connector.connector.id"


def test_two_connectors_on_the_network_are_never_chosen_between():
    second = CUSTOM_08 + '''
resource "google_vpc_access_connector" "connector_b" {
  name          = "cr-conn-b"
  region        = var.region
  ip_cidr_range = var.connector_cidr
  network       = google_compute_network.private_network.id
}
'''
    assert topology_vpc_connector(vt_of([SQL_CONSUMER]), SVC, tree(second)) is None


def test_connector_on_another_network_is_not_wired():
    other = CUSTOM_08.replace("network       = google_compute_network.private_network.name",
                              "network       = google_compute_network.other.name") + '''
resource "google_compute_network" "other" {
  name                    = "other"
  auto_create_subnetworks = false
}
'''
    assert topology_vpc_connector(vt_of([SQL_CONSUMER]), SVC, tree(other)) is None


def test_no_connector_no_wiring():
    start = CUSTOM_08.index('resource "google_vpc_access_connector"')
    end = CUSTOM_08.index('resource "google_sql_database_instance"')
    no_conn = CUSTOM_08[:start] + CUSTOM_08[end:]
    assert "google_vpc_access_connector" not in no_conn
    assert topology_vpc_connector(vt_of([SQL_CONSUMER]), SVC, tree(no_conn)) is None


@pytest.mark.parametrize("meta", ["count = 1", "for_each = toset([\"a\"])"])
def test_indexed_connector_is_not_wired(meta):
    indexed = CUSTOM_08.replace('  name          = "cr-conn"\n', f'  {meta}\n  name          = "cr-conn"\n')
    assert topology_vpc_connector(vt_of([SQL_CONSUMER]), SVC, tree(indexed)) is None


def test_literal_networks_are_never_compared():
    lit = CUSTOM_08.replace("network       = google_compute_network.private_network.name", 'network       = "vpc"')
    lit = lit.replace("private_network = google_compute_network.private_network.id", 'private_network = "vpc"')
    assert topology_vpc_connector(vt_of([SQL_CONSUMER]), SVC, tree(lit)) is None


def test_consumed_resource_not_declared_or_declared_twice():
    assert topology_vpc_connector(vt_of([SQL_CONSUMER]), SVC, tree(CUSTOM_S5)) is None
    twice = {CUSTOM_TF: CUSTOM_08, W + "db.tf": 'resource "google_sql_database_instance" "postgres" {\n  name = "x"\n}\n'}
    assert topology_vpc_connector(vt_of([SQL_CONSUMER]), SVC, twice) is None


def test_unparseable_root_file_and_nested_files_are_not_read():
    assert topology_vpc_connector(vt_of([SQL_CONSUMER]), SVC, {CUSTOM_TF: CUSTOM_08 + "\nresource {\n"}) is None
    assert topology_vpc_connector(vt_of([SQL_CONSUMER]), SVC, {W + "sub/custom.tf": CUSTOM_08}) is None


def test_legacy_path_and_non_cloudrun_service_get_nothing():
    assert topology_vpc_connector(None, SVC, tree(CUSTOM_08)) is None
    vt = vt_of([dict(SQL_CONSUMER, consumers=[{"service": "jobs", "env_key": "DB_HOST",
                                               "attribute": "private_ip_address"}])],
               services=((SVC, "cloudrun"), ("jobs", "event-worker")))
    assert topology_vpc_connector(vt, "jobs", tree(CUSTOM_08)) is None


# ------------------------------------------------------------------------------------------------ rendering
ARCHETYPES = ("cloudrun", "gke-autopilot", "gce-bastion", "event-worker", "foundation-only", "unknown-archetype")


@pytest.mark.parametrize("archetype", ARCHETYPES)
def test_main_tf_without_connector_is_byte_identical(archetype):
    """Do No Harm: the new keyword left at None renders exactly what the call without it renders."""
    for kw in ({}, {"service_name": SVC, "custom_tf_content": CUSTOM_08, "env_vars_override": {"A": "var.a"}}):
        assert te.generate_golden_main_tf("p", archetype, "", **kw) == \
            te.generate_golden_main_tf("p", archetype, "", vpc_access_connector=None, **kw)


GOLDEN_DIR = os.path.join(os.path.dirname(__file__), "fixtures", "pdcw_main_render")
TOPOLOGY_ENV = {"DB_HOST": "google_sql_database_instance.postgres.private_ip_address",
                "DB_SECRET_ID": "google_secret_manager_secret.postgres_db_credentials.secret_id"}


@pytest.mark.parametrize("golden,kw", [
    ("main_cloudrun_default.tf.golden", {}),
    ("main_cloudrun_topology.tf.golden", {"service_name": SVC, "env_vars_override": TOPOLOGY_ENV,
                                          "scaling_override": {"min_instances": 0, "max_instances": 3,
                                                               "cpu_idle": True}}),
])
def test_main_tf_without_connector_equals_mains_render(golden, kw):
    """RT F4: the golden files are main's (15e3d3c) `generate_golden_main_tf` output, captured once from a main export;
    the branch's render with no connector must equal them byte for byte (a template edit cannot pass by changing both
    sides). With the connector it is main's render plus exactly one line."""
    expected = open(os.path.join(GOLDEN_DIR, golden)).read()
    # FD-4AT-c: the goldens predate the foundation module's github_repository_id line (tests/fd4atc_render.py).
    assert without_fd4atc(te.generate_golden_main_tf("p", "cloudrun", "", **kw)) == expected
    assert without_fd4atc(te.generate_golden_main_tf("p", "cloudrun", "", vpc_access_connector=None, **kw)) == expected
    ref = "google_vpc_access_connector.connector.id"
    wired = without_fd4atc(te.generate_golden_main_tf("p", "cloudrun", "", vpc_access_connector=ref, **kw))
    assert wired.replace(f"  vpc_access_connector  = {ref}\n", "", 1) == expected


def test_main_tf_with_connector_sets_exactly_the_module_input():
    ref = "google_vpc_access_connector.connector.id"
    base = te.generate_golden_main_tf("p", "cloudrun", "", service_name=SVC, env_vars_override={"A": "var.a"})
    wired = te.generate_golden_main_tf("p", "cloudrun", "", service_name=SVC, env_vars_override={"A": "var.a"},
                                       vpc_access_connector=ref)
    assert wired.replace(f"  vpc_access_connector  = {ref}\n", "", 1) == base   # one added line, nothing else
    b0, b1 = compute_body(base), compute_body(wired)
    assert "vpc_access_connector" not in b0
    assert b1.pop("vpc_access_connector") == "${" + ref + "}"
    assert {k: v for k, v in b1.items() if not k.startswith("__")} == {k: v for k, v in b0.items()
                                                                       if not k.startswith("__")}


@pytest.mark.parametrize("bad", ["google_vpc_access_connector.c.name", "google_vpc_access_connector.c[0].id",
                                 'x"\n  evil = 1', "module.c.id", "google_vpc_access_connector.c.id.x"])
def test_connector_line_is_a_closed_grammar(bad):
    with pytest.raises(ValueError):
        te.vpc_connector_line(bad)
    assert te.vpc_connector_line(None) == ""


def _reconcile(files, vt):
    te.reconcile_multi_service_declarations(
        files=files, product_id="p", spec_text="", archetype=vt.archetype, assembly_record=AssemblyRecord(),
        llm_iac_paths=[CUSTOM_TF], target_services=list(vt.names), topology=vt)
    return files


def test_secondary_cloud_run_consumer_gets_the_connector_in_services_tf():
    vt = vt_of([dict(SQL_CONSUMER, consumers=[{"service": "api", "env_key": "DB_HOST",
                                               "attribute": "private_ip_address"}])],
               services=((SVC, "cloudrun"), ("api", "cloudrun")))
    files = _reconcile({CUSTOM_TF: CUSTOM_08, "apps/api/main.py": "x = 1\n", f"apps/{SVC}/main.py": "x = 1\n"}, vt)
    body = compute_body(files[te.SERVICES_TF], "compute_api")
    assert body["vpc_access_connector"] == "${google_vpc_access_connector.connector.id}"


def test_secondary_without_consumer_renders_as_before():
    vt = vt_of([], services=((SVC, "cloudrun"), ("api", "cloudrun")))
    files = _reconcile({CUSTOM_TF: CUSTOM_08, "apps/api/main.py": "x = 1\n", f"apps/{SVC}/main.py": "x = 1\n"}, vt)
    assert "vpc_access_connector" not in files[te.SERVICES_TF]


def test_handler_renders_the_primary_connector_from_the_topology():
    """The one handler call site: the primary's main.tf render passes topology_vpc_connector(vt, primary, <view>)
    (FD4DK-3: the assembled files without the AI's relocated draft keys)."""
    src = open(os.path.join(GATEWAY, "developer_agent", "handler.py")).read()
    calls = [n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Call)
             and getattr(n.func, "id", None) == "generate_golden_main_tf"]
    wired = [c for c in calls if any(k.arg == "vpc_access_connector" for k in c.keywords)]
    assert len(wired) == 1
    kw = next(k for k in wired[0].keywords if k.arg == "vpc_access_connector")
    assert ("topology_vpc_connector(vt, vt.primary.name, {p: t for p, t in files.items() "
            "if p not in assembly.relocated_draft_paths})") in ast.unparse(kw.value)


# ------------------------------------------------------------------------------------------------ HA-13 phases 5/6 deleted
HCL_UTILS_REPLICAS = ("shared/hcl_utils.py", "apps/orchestrator-gateway/shared/hcl_utils.py",
                      "apps/orchestrator-gateway/developer_agent/hcl_utils.py", "mcp-servers/terraform/hcl_utils.py",
                      "mcp-servers/terraform/shared/hcl_utils.py")


@pytest.mark.parametrize("rel", HCL_UTILS_REPLICAS)
def test_phases_5_and_6_are_deleted_in_every_replica(rel):
    src = open(os.path.join(REPO_ROOT, rel)).read()
    for marker in (".vpc_access_connector -> ", "active_connector_ref", "Cloud Run Database Environment Auto-Wiring",
                   ".env_vars.DATABASE_URL -> ", "synthesized_db_url", "postgresql+asyncpg://"):
        assert marker not in src, marker


def test_ex08_platform_render_is_byte_identical_at_deploy(monkeypatch, tmp_path):
    """The generation output on 08 (platform main.tf with the connector + the AI's custom.tf) reaches the deploy
    workspace byte-identical: the connector is already there, and no DATABASE_URL is added. (It used to pass through
    the deploy-time auto-wiring, which FD-55 W6b deleted; now the real prepare_workspace is the check.)"""
    from unittest.mock import MagicMock
    from fd4g_support import load_tf_service
    vt = vt_of([SQL_CONSUMER, SECRET_CONSUMER])
    files = tree(CUSTOM_08)
    main = te.generate_golden_main_tf("p", "cloudrun", "", service_name=SVC,
                                      env_vars_override=dict(vt.env_for(SVC)),
                                      vpc_access_connector=topology_vpc_connector(vt, SVC, files))
    files = {"main.tf": main, "custom.tf": CUSTOM_08}
    tf = load_tf_service(monkeypatch)
    svc = tf.TerraformService(project_id="p", db=MagicMock(), workspace_base_dir=str(tmp_path / "ws"))
    ws = svc.prepare_workspace(product_id="pdcw08", trace_id="trace-pdcw08", hcl_files=dict(files))
    for rel, text in files.items():
        with open(os.path.join(ws, rel), encoding="utf-8", newline="") as fh:
            assert fh.read() == text, rel
    assert compute_body(main)["vpc_access_connector"] == "${google_vpc_access_connector.connector.id}"
