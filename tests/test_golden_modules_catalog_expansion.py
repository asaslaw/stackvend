"""
Unit Tests for Golden Parameterized Modules Catalog Expansion:
- Dynamic and Embedded Contract Grounding (contract_inspector.py)
- Pure Intent-Based Vendoring (Option A in terraform_engine.py)
- Verification of all 12 Tier 1 Serverless and Tier 2 Heavy Stateful Modules
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest
from unittest.mock import patch

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_PATH = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
if GATEWAY_PATH not in sys.path:
    sys.path.insert(0, GATEWAY_PATH)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from developer_agent.contract_inspector import (
    get_golden_module_contract,
    get_all_active_module_contracts,
    _EMBEDDED_MODULE_CONTRACTS,
)
from developer_agent.terraform_engine import (
    get_canonical_module_files,
    vendor_terraform_modules,
)


class TestGoldenModulesCatalogExpansion(unittest.TestCase):
    """Verifies catalog expansion, contract inspector, and intent-based vendoring."""

    def test_all_catalog_modules_exist_on_disk(self):
        """Verifies that all Tier 1 and Tier 2 modules exist on disk with valid .tf files."""
        expected_modules = [
            # Tier 1 Serverless
            "storage-bucket",
            "messaging-pubsub",
            "security-secret",
            "tasks-queue",
            "scheduling-cron",
            "analytics-bigquery",
            "event-trigger",
            "observability-alerts",
            "workload_auth",
            "workflows-dag",
            "security-kms",
            "dns-record",
            # Tier 2 Heavy Stateful
            "database-cloudsql",
            "cache-redis",
            "database-spanner",
            "database-alloydb",
            "database-bigtable",
            "ai-vertex-endpoint",
            "orchestration-composer",
            "compute-gke-autopilot",
        ]
        canonical_files = get_canonical_module_files()
        for mod in expected_modules:
            has_main = f"infra/modules/{mod}/main.tf" in canonical_files
            has_vars = f"infra/modules/{mod}/variables.tf" in canonical_files
            has_outs = f"infra/modules/{mod}/outputs.tf" in canonical_files
            self.assertTrue(has_main, f"Missing main.tf for module: {mod}")
            self.assertTrue(has_vars, f"Missing variables.tf for module: {mod}")
            self.assertTrue(has_outs, f"Missing outputs.tf for module: {mod}")

    def test_contract_inspector_disk_and_embedded_fallback(self):
        """Verifies contract inspector generates valid ground truth contracts from disk and fallback."""
        # 1. Test live disk inspection
        contract = get_golden_module_contract("storage-bucket", force_refresh=True)
        self.assertIn("Golden Module Contract: `storage-bucket`", contract)
        self.assertIn("bucket_name", contract)
        self.assertIn("uniform_bucket_level_access", contract)

        # 2. Test embedded fallback when filesystem unmounted
        with patch("developer_agent.contract_inspector.get_platform_modules_path", return_value=None):
            fallback_contract = get_golden_module_contract("database-cloudsql", force_refresh=True)
            self.assertIn("Golden Module Contract: `database-cloudsql`", fallback_contract)
            self.assertIn("instance_connection_name", fallback_contract)
            self.assertIn("deletion_protection", fallback_contract)

            fallback_spanner = get_golden_module_contract("database-spanner", force_refresh=True)
            self.assertIn("Golden Module Contract: `database-spanner`", fallback_spanner)
            self.assertIn("processing_units", fallback_spanner)

            fallback_alloydb = get_golden_module_contract("database-alloydb", force_refresh=True)
            self.assertIn("Golden Module Contract: `database-alloydb`", fallback_alloydb)
            self.assertIn("cluster_id", fallback_alloydb)

            fallback_bigtable = get_golden_module_contract("database-bigtable", force_refresh=True)
            self.assertIn("Golden Module Contract: `database-bigtable`", fallback_bigtable)
            self.assertIn("num_nodes", fallback_bigtable)

            fallback_vertex = get_golden_module_contract("ai-vertex-endpoint", force_refresh=True)
            self.assertIn("Golden Module Contract: `ai-vertex-endpoint`", fallback_vertex)
            self.assertIn("endpoint_name", fallback_vertex)

            fallback_composer = get_golden_module_contract("orchestration-composer", force_refresh=True)
            self.assertIn("Golden Module Contract: `orchestration-composer`", fallback_composer)
            self.assertIn("environment_size", fallback_composer)

        # 3. Test combined active contracts contains all modules
        all_contracts = get_all_active_module_contracts()
        self.assertIn("storage-bucket", all_contracts)
        self.assertIn("messaging-pubsub", all_contracts)
        self.assertIn("analytics-bigquery", all_contracts)
        self.assertIn("database-cloudsql", all_contracts)
        self.assertIn("cache-redis", all_contracts)
        self.assertIn("database-spanner", all_contracts)
        self.assertIn("database-alloydb", all_contracts)
        self.assertIn("database-bigtable", all_contracts)
        self.assertIn("ai-vertex-endpoint", all_contracts)
        self.assertIn("orchestration-composer", all_contracts)

    def test_pure_intent_based_vendoring_cleanliness(self):
        """
        Verifies Option A Pure Intent-Based Vendoring:
        Supplemental modules are NEVER vendored unless explicitly invoked in HCL.
        """
        # Case 1: Simple Cloud Run workload without supplemental modules
        files = {
            "infra/workload/main.tf": """
module "foundation" {
  source = "../modules/workload-foundation/base"
}
module "compute" {
  source = "../modules/compute-cloudrun"
}
"""
        }
        vendor_terraform_modules(files, selected_archetype="cloudrun")

        # Must have foundation and compute
        self.assertTrue(any(k.startswith("infra/modules/workload-foundation/base/") for k in files))
        self.assertTrue(any(k.startswith("infra/modules/compute-cloudrun/") for k in files))

        # Must NOT have any uninvoked supplemental modules
        self.assertFalse(any(k.startswith("infra/modules/storage-bucket/") for k in files))
        self.assertFalse(any(k.startswith("infra/modules/messaging-pubsub/") for k in files))
        self.assertFalse(any(k.startswith("infra/modules/database-cloudsql/") for k in files))
        self.assertFalse(any(k.startswith("infra/modules/compute-gke-autopilot/") for k in files))

        # Case 2: Workload invoking storage-bucket in main.tf
        files_with_storage = {
            "infra/workload/main.tf": """
module "foundation" {
  source = "../modules/workload-foundation/base"
}
module "compute" {
  source = "../modules/compute-cloudrun"
}
module "uploads" {
  source = "../modules/storage-bucket"
  bucket_name_suffix = "uploads"
}
"""
        }
        vendor_terraform_modules(files_with_storage, selected_archetype="cloudrun")
        self.assertTrue(any(k.startswith("infra/modules/storage-bucket/") for k in files_with_storage))
        self.assertFalse(any(k.startswith("infra/modules/messaging-pubsub/") for k in files_with_storage))

        # Case 3: Workload where human adds cron in human.tf (Milestone 27 synergy)
        files_with_human = {
            "infra/workload/main.tf": """
module "foundation" {
  source = "../modules/workload-foundation/base"
}
module "compute" {
  source = "../modules/compute-cloudrun"
}
""",
            "infra/workload/human.tf": """
module "nightly_sync" {
  source = "../modules/scheduling-cron"
  schedule = "0 2 * * *"
}
"""
        }
        vendor_terraform_modules(files_with_human, selected_archetype="cloudrun")
        self.assertTrue(any(k.startswith("infra/modules/scheduling-cron/") for k in files_with_human))
        self.assertFalse(any(k.startswith("infra/modules/storage-bucket/") for k in files_with_human))

        # Case 4: Workload where human adds Tier 2 Spanner database in human.tf
        files_with_spanner = {
            "infra/workload/main.tf": """
module "foundation" {
  source = "../modules/workload-foundation/base"
}
module "compute" {
  source = "../modules/compute-cloudrun"
}
""",
            "infra/workload/human.tf": """
module "app_db" {
  source = "../modules/database-spanner"
  database_name = "customers"
}
"""
        }
        vendor_terraform_modules(files_with_spanner, selected_archetype="cloudrun")
        self.assertTrue(any(k.startswith("infra/modules/database-spanner/") for k in files_with_spanner))
        self.assertFalse(any(k.startswith("infra/modules/database-alloydb/") for k in files_with_spanner))
        self.assertFalse(any(k.startswith("infra/modules/database-bigtable/") for k in files_with_spanner))


if __name__ == "__main__":
    unittest.main()
