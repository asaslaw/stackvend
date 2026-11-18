"""FD-4AA / FD-4Z (proposed register rows, not approved): HA-13 graph phases, HC-19 via HA-13, and the apply-time
HA-14 caller no longer touch valid HCL, and never merge or delete distinct resources.

* ``hcl_utils.auto_wire_network_graph_dependencies`` (x5): phases 1-4 deleted (multi-VPC convergence, subnet dedup
  on (network, CIDR), connector -> subnet rewrite, network attribute rewiring + PSA ``depends_on`` (HC-19), sql_user
  password / ``random_password`` synthesis). Phase 0 (parser-gated, register row 7) and the function itself were
  deleted by FD-55 W6b (register FD55-W6b+W6d); the fixtures are pinned through prepare_workspace. The additive Cloud Run
  connector / DATABASE_URL phases 5/6 are deleted by platform-db-connector-wiring (proposed rows PDCW-1 / PDCW-2):
  the connector is rendered at generation from typed facts (tests/test_platform_db_connector_wiring.py), and the
  credential-less DATABASE_URL has no replacement.
* Generation: FD-55 W4 deleted ``preflight_validator.self_correct_hcl`` and with it the Phase 0 call (none left).
* Apply (``TerraformService.prepare_workspace``): the ``deduplicate_semantic_hcl_blocks`` sweep (HA-14) is deleted.
* HC-11 / HA-11: report-only since HS-68, deleted in S2-F with HB-13 (tests/test_fd23_12b_deploy_heal.py).

Hermetic: pure functions plus one ``prepare_workspace`` into tmp_path (no backend, no subprocess, no network).
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import importlib.util
import os
import sys
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
REPLICAS = [
    "shared/hcl_utils.py",
    "apps/orchestrator-gateway/developer_agent/hcl_utils.py",
    "apps/orchestrator-gateway/shared/hcl_utils.py",
    "mcp-servers/terraform/hcl_utils.py",
    "mcp-servers/terraform/shared/hcl_utils.py",
]

# Distinct resources that the deleted phases merged or deleted: two VPCs with the same GCP name in two projects,
# subnets with the same CIDR on different VPCs in different regions, two connectors with the same GCP name in two
# regions on different VPCs, a Cloud SQL instance on the second VPC through a variable, and its PSA peering.
DISTINCT_CUSTOM_TF = '''resource "google_compute_network" "vpc" {
  project                 = var.project_id
  name                    = "app-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_network" "shared_vpc" {
  project                 = var.network_project_id
  name                    = "app-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "app_primary" {
  project       = var.project_id
  name          = "app-subnet"
  region        = var.region
  ip_cidr_range = "10.20.0.0/24"
  network       = google_compute_network.vpc.id
}

resource "google_compute_subnetwork" "app_secondary" {
  project       = var.network_project_id
  name          = "app-subnet"
  region        = var.secondary_region
  ip_cidr_range = "10.20.0.0/24"
  network       = google_compute_network.shared_vpc.id
}

resource "google_vpc_access_connector" "primary" {
  project       = var.project_id
  name          = "app-conn"
  region        = var.region
  ip_cidr_range = "10.8.0.0/28"
  network       = google_compute_network.vpc.name
}

resource "google_vpc_access_connector" "secondary" {
  project       = var.network_project_id
  name          = "app-conn"
  region        = var.secondary_region
  ip_cidr_range = "10.9.0.0/28"
  network       = google_compute_network.shared_vpc.name
}

resource "google_compute_global_address" "psa_range" {
  project       = var.network_project_id
  name          = "psa-range"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = 16
  network       = google_compute_network.shared_vpc.id
}

resource "google_service_networking_connection" "psa" {
  network                 = google_compute_network.shared_vpc.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.psa_range.name]
}

resource "google_sql_database_instance" "db" {
  project          = var.network_project_id
  name             = "app-db"
  region           = var.secondary_region
  database_version = "POSTGRES_15"
  depends_on       = [google_service_networking_connection.psa]
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled    = false
      private_network = var.shared_network_id
    }
  }
}
'''

DISTINCT_VARIABLES_TF = '''variable "network_project_id" {
  type = string
}

variable "secondary_region" {
  type = string
}

variable "shared_network_id" {
  type = string
}
'''

RESOURCE_ADDRESSES = [
    ("google_compute_network", "vpc"), ("google_compute_network", "shared_vpc"),
    ("google_compute_subnetwork", "app_primary"), ("google_compute_subnetwork", "app_secondary"),
    ("google_vpc_access_connector", "primary"), ("google_vpc_access_connector", "secondary"),
    ("google_compute_global_address", "psa_range"), ("google_service_networking_connection", "psa"),
    ("google_sql_database_instance", "db"),
]

# Example 08 shape (C4 10-18: phases 5/6 fired on 08-r1 / 08-r3 before PDCW): a main.tf whose module.compute has no
# connector or DATABASE_URL; the AI declares the VPC, connector and Cloud SQL in custom.tf.
EX08_MAIN_TF = '''module "compute" {
  source          = "./infra/modules/compute-cloudrun"
  project_id      = var.project_id
  region          = var.region
  service_name    = "billing-api"
  container_image = var.container_image
  env_vars = merge(var.env_vars, {
    "PROJECT_ID" = var.project_id
  })
}
'''

EX08_CUSTOM_TF = '''resource "google_compute_network" "vpc" {
  name                    = "billing-vpc"
  auto_create_subnetworks = false
}

resource "google_vpc_access_connector" "connector" {
  name          = "billing-conn"
  region        = var.region
  ip_cidr_range = "10.8.0.0/28"
  network       = google_compute_network.vpc.name
}

resource "google_sql_database_instance" "postgres" {
  name             = "billing-db"
  database_version = "POSTGRES_15"
  region           = var.region
  settings {
    tier = "db-f1-micro"
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.vpc.id
    }
  }
}

resource "google_sql_database" "billing" {
  name     = "billing"
  instance = google_sql_database_instance.postgres.name
}

resource "google_sql_user" "app" {
  name     = "app"
  instance = google_sql_database_instance.postgres.name
  password = var.db_password
}
'''


def _load(rel):
    name = "fd4aa_" + rel.replace("/", "_").replace("-", "_").replace(".py", "")
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO_ROOT, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module", params=REPLICAS)
def hu(request):
    return _load(request.param)


def _resource_addresses(hcl2_mod, text):
    doc = hcl2_mod.loads(text)
    return sorted((t, n) for blk in doc.get("resource", []) for t, named in blk.items() for n in named)


# ----------------------------------------------------------------------------------------------- hcl_utils x5
def test_auto_wire_and_its_phase0_are_deleted(hu):
    """FD-55 W6b (register FD55-W6b+W6d): the last phase (0, the parser-gated orphaned depends_on repair) went with
    its last caller (prepare_workspace), and with it the function. The FD-4AA / PDCW fixtures below are now pinned
    through prepare_workspace: committed bytes reach the workspace (Do No Harm)."""
    for name in ("auto_wire_network_graph_dependencies", "heal_orphaned_root_resource_syntax",
                 "heal_orphaned_resource_syntax"):
        assert not hasattr(hu, name), name


def test_distinct_fixture_is_valid_hcl_with_every_resource():
    hcl2 = pytest.importorskip("hcl2")
    assert _resource_addresses(hcl2, DISTINCT_CUSTOM_TF) == sorted(RESOURCE_ADDRESSES)


def test_deleted_graph_helpers_are_gone(hu):
    src = open(hu.__file__, encoding="utf-8").read()
    for marker in ("canonical_vpc_label", "Converged redundant VPC", "Deduplicated redundant subnetwork",
                   "Auto-synthesized 'random_password.db_password'", "Injected depends_on = ["):
        assert marker not in src, marker


# ----------------------------------------------------------------------------------------------- call sites
def _func(path, name):
    tree = ast.parse(open(path, encoding="utf-8").read())
    return next(n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name)


def _called_names(fn):
    out = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            f = n.func
            out.add(f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None)
    return out


def test_generation_calls_no_phase0_after_fd55_w4():
    """FD-55 W4 (FD55-W4): the generation-time self_correct_hcl (which held the parser-gated Phase 0 call) is deleted;
    no gateway module calls the HA-13 graph wiring or the Phase 0 repair any more (apply: deleted by W6b)."""
    for rel in ("preflight_validator.py", "handler.py"):
        tree = ast.parse(open(os.path.join(REPO_ROOT, "apps/orchestrator-gateway/developer_agent", rel)).read())
        called = _called_names(tree)
        assert "auto_wire_network_graph_dependencies" not in called, rel
        assert "heal_orphaned_root_resource_syntax" not in called, rel


def test_prepare_workspace_no_longer_calls_ha14():
    fn = _func(os.path.join(TF_DIR, "service.py"), "prepare_workspace")
    called = _called_names(fn)
    assert "deduplicate_semantic_hcl_blocks" not in called
    assert "deduplicate_semantic_hcl_resources" not in called
    assert "auto_wire_network_graph_dependencies" not in called  # FD-55 W6b: Phase 0 deleted with the function


@pytest.fixture(scope="module")
def svc_mod():
    if TF_DIR not in sys.path:
        sys.path.insert(0, TF_DIR)
    spec = importlib.util.spec_from_file_location("stackvend_tf_service_fd4aa", os.path.join(TF_DIR, "service.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_prepare_workspace_keeps_every_distinct_resource(svc_mod, tmp_path, caplog):
    """The apply site: the multi-VPC tree reaches the workspace byte-identical, with every resource and every network
    value as written; neither HA-13 nor HA-14 acts (FD55-W6a deleted the other rewrites, W6b the HA-13 remainder)."""
    import logging
    caplog.set_level(logging.INFO)
    hcl2 = pytest.importorskip("hcl2")
    s = svc_mod.TerraformService(project_id="test-proj", db=MagicMock(), workspace_base_dir=str(tmp_path / "ws"))
    files = {"infra/workload/custom.tf": DISTINCT_CUSTOM_TF, "infra/workload/variables.tf": DISTINCT_VARIABLES_TF}
    ws = s.prepare_workspace(product_id="fd4aa", trace_id="trace-fd4aa", hcl_files=dict(files))
    out = open(os.path.join(ws, "infra/workload/custom.tf"), encoding="utf-8").read()
    assert out == DISTINCT_CUSTOM_TF
    assert _resource_addresses(hcl2, out) == sorted(RESOURCE_ADDRESSES)
    doc = {(t, n): b for blk in hcl2.loads(out)["resource"] for t, named in blk.items() for n, b in named.items()}
    assert doc[("google_sql_database_instance", "db")]["settings"][0]["ip_configuration"][0]["private_network"] \
        == "${var.shared_network_id}"
    assert doc[("google_compute_subnetwork", "app_secondary")]["network"] == "${google_compute_network.shared_vpc.id}"
    assert doc[("google_vpc_access_connector", "secondary")]["network"] == "${google_compute_network.shared_vpc.name}"
    for (t, n), body in doc.items():  # every network / CIDR value exactly as written
        src = next(b for blk in hcl2.loads(DISTINCT_CUSTOM_TF)["resource"] for tt, named in blk.items()
                   for nn, b in named.items() if (tt, nn) == (t, n))
        for key in ("network", "ip_cidr_range", "region", "project", "name"):
            assert body.get(key) == src.get(key), (t, n, key)
    msgs = [r.getMessage() for r in caplog.records]
    assert not [m for m in msgs if "Semantic Deduplication" in m or "Network Auto-Wiring" in m]


@pytest.mark.parametrize("case", ["ex08", "ex08_explicit_wiring", "no_vpc", "golden_module_paths"])
def test_prepare_workspace_keeps_the_ex08_roots_byte_identical(svc_mod, tmp_path, case):
    """PDCW-1 / PDCW-2 fixtures (formerly run through auto_wire x5): no connector, DATABASE_URL or DB_HOST is added
    at apply, an explicit wiring is never overwritten, golden module paths are never wired; every file reaches the
    workspace byte-identical (FD-55 W6b)."""
    explicit_main = EX08_MAIN_TF.replace(
        '  service_name    = "billing-api"\n',
        '  service_name    = "billing-api"\n  vpc_access_connector = var.connector_id\n',
    ).replace('"PROJECT_ID" = var.project_id', '"DATABASE_URL" = var.database_url')
    no_vpc_custom = 'resource "google_vpc_access_connector"' + EX08_CUSTOM_TF.split(
        'resource "google_vpc_access_connector"', 1)[1]
    files = {
        "ex08": {"infra/workload/main.tf": EX08_MAIN_TF, "infra/workload/custom.tf": EX08_CUSTOM_TF},
        "ex08_explicit_wiring": {"main.tf": explicit_main, "custom.tf": EX08_CUSTOM_TF},
        "no_vpc": {"main.tf": EX08_MAIN_TF, "custom.tf": no_vpc_custom},
        "golden_module_paths": {"infra/modules/x/main.tf": EX08_MAIN_TF, "infra/modules/y/main.tf": EX08_CUSTOM_TF},
    }[case]
    s = svc_mod.TerraformService(project_id="test-proj", db=MagicMock(), workspace_base_dir=str(tmp_path / "ws"))
    ws = s.prepare_workspace(product_id="fd4aa", trace_id="trace-fd4aa-ex08", hcl_files=dict(files))
    for rel, text in files.items():
        with open(os.path.join(ws, rel), encoding="utf-8", newline="") as fh:
            assert fh.read() == text, rel
