"""Wave 1 lane 8 (FD-44, FD-4U, FD-4AY): tombstone, negative and import-tripwire tests.

Deleted (all five byte-identical hcl_utils.py replicas): is_valid_ipv4_cidr, sanitize_cidr_declarations,
strip_balanced_block, sanitize_hcl_wif, plus the CIDR step of auto_wire Phase 0 and the gateway copy of
sanitize_hcl_triggers (developer_agent/handler.py). heal_orphaned_resource_syntax (FD-47) was NOT deleted here:
register row 7 (owner 10-12) kept it until the FD-53 repair loop was live; FD-55 W6b deleted it (register
FD55-W6b+W6d, tests/test_fd55_w6bd_no_writeback.py). They rewrote VALID HCL (security-visible:
/32 and 0.0.0.0/0 CIDRs, a stricter WIF attribute_condition, golden modules).

- Tombstones: the names must not come back in any replica.
- Negative tests (Invariant 1): valid input through what remains is byte-identical.
- Import tripwire (red-team F6/H6): no tracked runtime/test module may import or reference a deleted name,
  and mcp-servers/terraform/service.py + applier.py must import. This FAILS until lane 6 removes the
  service.py / test_service.py uses; that is the intended merge gate (lane 6 merges before lane 8).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)
import ast
import importlib.util
import os
import subprocess
import sys
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

HCL_UTILS_REPLICAS = [
    "shared/hcl_utils.py",
    "apps/orchestrator-gateway/shared/hcl_utils.py",
    "apps/orchestrator-gateway/developer_agent/hcl_utils.py",
    "mcp-servers/terraform/hcl_utils.py",
    "mcp-servers/terraform/shared/hcl_utils.py",
]
DELETED_HCL_UTILS_NAMES = (
    "is_valid_ipv4_cidr",
    "sanitize_cidr_declarations",
    "strip_balanced_block",
    "sanitize_hcl_wif",
)
HANDLER = "apps/orchestrator-gateway/developer_agent/handler.py"


def _load_replica(rel_path: str):
    name = "lane8_" + rel_path.replace("/", "_").replace("-", "_").replace(".py", "")
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO_ROOT, rel_path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _tracked_python_files():
    out = subprocess.run(
        ["git", "ls-files", "*.py"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    # docs/ holds historical review probes (evidence scripts run by hand against old commits); never imported.
    return [p for p in out if not p.startswith("docs/") and p != "tests/test_lane8_deletions.py"]


def _references(tree: ast.AST, names) -> list:
    """Code references only (imports, names, attributes, definitions); strings and comments are ignored."""
    hits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            hits += [(node.lineno, a.name) for a in node.names if a.name in names]
        elif isinstance(node, ast.Name) and node.id in names:
            hits.append((node.lineno, node.id))
        elif isinstance(node, ast.Attribute) and node.attr in names:
            hits.append((node.lineno, node.attr))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in names:
            hits.append((node.lineno, node.name))
    return hits


class TestTombstones(unittest.TestCase):
    def test_deleted_names_absent_in_every_hcl_utils_replica(self):
        for rel in HCL_UTILS_REPLICAS:
            mod = _load_replica(rel)
            for name in DELETED_HCL_UTILS_NAMES:
                self.assertFalse(hasattr(mod, name), f"{name} came back in {rel}")
            self.assertFalse(hasattr(mod, "ipaddress"), f"unused ipaddress import came back in {rel}")

    def test_gateway_handler_has_no_trigger_or_wif_rewriter(self):
        with open(os.path.join(REPO_ROOT, HANDLER), encoding="utf-8") as f:
            tree = ast.parse(f.read())
        names = set(DELETED_HCL_UTILS_NAMES) | {"sanitize_hcl_triggers"}
        self.assertEqual(_references(tree, names), [])

    def test_no_hardcoded_replacement_cidrs_in_hcl_utils(self):
        # The deleted sanitizer injected these literals (Invariant 3). HD-14 in preflight_validator /
        # service.py still injects them for undeclared variables: FD-4AL / FD-53 phase 6, not this test.
        for rel in HCL_UTILS_REPLICAS:
            with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as f:
                text = f.read()
            for literal in ("10.10.0.0/24", "10.8.0.0/28"):
                self.assertNotIn(literal, text, f"{literal} in {rel}")

    def test_no_owner_identifiers_in_lane8_files(self):
        owned = HCL_UTILS_REPLICAS + [
            "apps/orchestrator-gateway/developer_agent/preflight_validator.py",
            "shared/agent_evaluator.py",
            "apps/orchestrator-gateway/shared/agent_evaluator.py",
            "apps/control-center/shared/agent_evaluator.py",
            "mcp-servers/terraform/shared/agent_evaluator.py",
            "infra/modules/workload-foundation/base/variables.tf",
            "infra/modules/database-cloudsql/main.tf",
            "infra/modules/database-cloudsql/variables.tf",
            "infra/modules/database-cloudsql/outputs.tf",
        ]
        for rel in owned:
            with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as f:
                text = f.read()
            from owner_identifiers import find  # FD-12: identifiers held as SHA-256 digests only
            hits = find(text, {"owner_org", "owner_handle", "private_repo", "domain_a"})
            self.assertEqual(hits, [], f"owner identifier(s) in {rel}")


_TF_SERVICE_MOD = None


def _tf_service_module():
    global _TF_SERVICE_MOD
    if _TF_SERVICE_MOD is None:
        tf_dir = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
        if tf_dir not in sys.path:
            sys.path.insert(0, tf_dir)
        spec = importlib.util.spec_from_file_location("stackvend_tf_service_lane8_dnh", os.path.join(tf_dir, "service.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _TF_SERVICE_MOD = mod
    return _TF_SERVICE_MOD


class TestDoNoHarmNegatives(unittest.TestCase):
    """Valid input -> byte-identical output through the post-generation entry point that remains: the apply side's
    TerraformService.prepare_workspace (FD-55 W1 deleted deduplicate_semantic_hcl_blocks; W6b deleted
    auto_wire_network_graph_dependencies, the hcl_utils entry point these cases used to run through)."""

    def setUp(self):
        import tempfile
        from unittest.mock import MagicMock

        self._tmp = tempfile.TemporaryDirectory()
        mod = _tf_service_module()
        self.svc = mod.TerraformService(project_id="lane8-dnh", db=MagicMock(), workspace_base_dir=self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def _assert_identity(self, files):
        ws = self.svc.prepare_workspace(product_id="lane8-dnh", trace_id="trace-lane8-dnh", hcl_files=dict(files))
        for rel, text in files.items():
            with open(os.path.join(ws, rel), encoding="utf-8", newline="") as fh:
                self.assertEqual(fh.read(), text, rel)

    def test_cidr_valid_edge_values_untouched(self):
        files = {
            "infra/workload/variables.tf": '''variable "subnet_cidr" {
  description = "Allocation for the app subnet"
  type        = string
  default     = "10.0.0.0/30"
  validation {
    condition     = can(cidrnetmask(var.subnet_cidr))
    error_message = "must be a CIDR"
  }
}

variable "legacy_cidr" {
  type    = string
  default = "testplan02-a-subnet-cidr"
}
''',
            "infra/workload/custom.tf": '''resource "google_compute_network" "vpc" {
  name                    = "app-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "host" {
  name          = "host-sn"
  ip_cidr_range = "10.0.0.1/32"
  region        = var.region
  network       = google_compute_network.vpc.id
}

resource "google_compute_firewall" "lb_health" {
  name          = "allow-any"
  network       = google_compute_network.vpc.name
  source_ranges = ["0.0.0.0/0", "10.1.2.3"]
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
}
''',
        }
        self._assert_identity(files)

    def test_valid_multiline_depends_on_untouched(self):
        files = {
            "infra/workload/custom.tf": '''resource "google_compute_network" "vpc_network" {
  name = "app-vpc"
}

resource "google_vpc_access_connector" "conn" {
  name          = "app-conn"
  region        = var.region
  ip_cidr_range = "10.8.0.0/28"
  network       = google_compute_network.vpc_network.name
  depends_on = [
    google_compute_network.vpc_network,
    google_compute_network.vpc_network
  ]
}
'''
        }
        self._assert_identity(files)

    def test_wif_stricter_condition_byte_identical(self):
        # fd27 probe section A: a stricter condition (ref pinned) + attribute.ref mapping + unrelated display_name.
        files = {
            "infra/workload/custom.tf": '''resource "google_iam_workload_identity_pool" "pool" {
  project                   = var.project_id
  workload_identity_pool_id = "gh-pool"
}

resource "google_service_account" "deployer" {
  account_id   = "deployer"
  display_name = "Production deployer SA"
}

resource "google_iam_workload_identity_pool_provider" "gh" {
  project                            = var.project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "gh"
  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.ref"        = "assertion.ref"
  }
  attribute_condition = "assertion.repository == 'acme/app' && assertion.ref == 'refs/heads/main'"
  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_project_service" "apis" {
  for_each = toset(["iamcredentials.googleapis.com", "sts.googleapis.com"])
  project  = var.project_id
  service  = each.value
}
'''
        }
        self._assert_identity(files)


class TestImportTripwire(unittest.TestCase):
    def test_no_tracked_module_references_a_deleted_hcl_utils_function(self):
        offenders = []
        for rel in _tracked_python_files():
            with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as f:
                try:
                    tree = ast.parse(f.read())
                except SyntaxError:
                    continue
            for lineno, name in _references(tree, set(DELETED_HCL_UTILS_NAMES)):
                offenders.append(f"{rel}:{lineno} {name}")
        self.assertEqual(offenders, [], "callers of deleted lane 8 healers remain (lane 6 must land first)")

    def test_no_module_imports_trigger_rewriter_from_gateway_handler(self):
        offenders = []
        for rel in _tracked_python_files():
            with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as f:
                try:
                    tree = ast.parse(f.read())
                except SyntaxError:
                    continue
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and (node.module or "").endswith("handler"):
                    if any(a.name == "sanitize_hcl_triggers" for a in node.names):
                        offenders.append(f"{rel}:{node.lineno}")
        self.assertEqual(offenders, [])

    def test_terraform_server_and_applier_import(self):
        # Hermetic: a fresh interpreter with the caller's (ADC-disabled) environment; nothing is called.
        tf_dir = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
        code = "import service, applier; print('ok')"
        env = hermetic_guard.child_env(drop=("PYTHONPATH",))   # Layer 0 + the guard shim only
        env["PYTHONPATH"] = os.pathsep.join(p for p in (tf_dir, env.get("PYTHONPATH", "")) if p)
        res = subprocess.run(
            [sys.executable, "-c", code], cwd=tf_dir, env=env, capture_output=True, text=True, timeout=120
        )
        self.assertEqual(res.returncode, 0, res.stderr[-2000:])
        self.assertIn("ok", res.stdout)


if __name__ == "__main__":
    unittest.main()
