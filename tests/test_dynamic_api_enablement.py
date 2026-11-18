"""
Project Castor: Unit Tests for Dynamic Google Cloud API Auto-Enablement
Verifies:
1. Dynamic extraction of cloudscheduler.googleapis.com, eventarc.googleapis.com, workflows.googleapis.com, and iap.googleapis.com from HCL source.
2. Default foundation APIs in project-vending include cloudscheduler.googleapis.com and eventarc.googleapis.com.
3. Fallback behaviors when minimal HCL is supplied.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest
from unittest.mock import MagicMock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TERRAFORM_MCP_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
VENDING_DIR = os.path.join(REPO_ROOT, "apps", "project-vending")

for p in [TERRAFORM_MCP_DIR, VENDING_DIR]:
    if p not in sys.path:
        sys.path.insert(0, p)

for m in [
    'httpx', 'fastapi', 'google', 'google.auth', 'googleapiclient',
    'googleapiclient.discovery', 'googleapiclient.errors', 'google.cloud',
    'google.cloud.firestore', 'google.cloud.storage', 'google.cloud.secretmanager',
    'google.cloud.cloudquotas_v1', 'github', 'jwt'
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

import service as tf_service


class TestDynamicApiEnablement(unittest.TestCase):
    """Test suite for dynamic API detection and project vending foundation expansions."""

    def test_extract_apis_detects_cloud_scheduler(self):
        """Verifies that google_cloud_scheduler resources yield cloudscheduler.googleapis.com."""
        hcl_files = {
            "custom.tf": (
                'resource "google_cloud_scheduler_job" "reconciliation_job" {\n'
                '  name             = "nightly-reconciler"\n'
                '  schedule         = "0 2 * * *"\n'
                '  time_zone        = "America/New_York"\n'
                '  attempt_deadline = "320s"\n'
                '}\n'
            )
        }
        apis = tf_service.extract_apis_from_hcl(hcl_files)
        self.assertIn("cloudscheduler.googleapis.com", apis)
        self.assertIn("serviceusage.googleapis.com", apis)
        self.assertIn("iam.googleapis.com", apis)

    def test_extract_apis_detects_eventarc_and_workflows(self):
        """Verifies that google_eventarc and google_workflows resources yield their respective APIs."""
        hcl_files = {
            "main.tf": 'resource "google_eventarc_trigger" "primary" { name = "event-trigger" }\n',
            "workflows.tf": 'resource "google_workflows_workflow" "order_flow" { name = "order-flow" }\n',
        }
        apis = tf_service.extract_apis_from_hcl(hcl_files)
        self.assertIn("eventarc.googleapis.com", apis)
        self.assertIn("workflows.googleapis.com", apis)

    def test_extract_apis_detects_iap_and_compute(self):
        """Verifies that google_iap and google_compute resources yield iap and compute APIs."""
        hcl_files = {
            "iap.tf": 'resource "google_iap_web_backend_service_iam_member" "member" {}\n',
            "compute.tf": 'resource "google_compute_backend_service" "be" {}\n'
        }
        apis = tf_service.extract_apis_from_hcl(hcl_files)
        self.assertIn("iap.googleapis.com", apis)
        self.assertIn("compute.googleapis.com", apis)

    def test_extract_apis_has_no_run_firestore_default(self):
        """S2-C C1b (register HS-63): the "default to Cloud Run + Firestore" rule is deleted -- both are in the
        workload foundation's base_apis and the vending list. An empty workspace needs only the base trio."""
        apis = tf_service.extract_apis_from_hcl({})
        self.assertEqual(apis, ["cloudresourcemanager.googleapis.com", "iam.googleapis.com",
                                "serviceusage.googleapis.com"])

    # ------------------------------------------------------------------ S2-C C1b (register HS-63)
    def test_extract_apis_is_the_shared_exact_table(self):
        from shared.api_requirements import required_apis
        tf = {"infra/workload/custom.tf": 'resource "google_redis_instance" "r" {}\nresource "google_kms_key_ring" "k" {}\n',
              "infra/workload/main.tf": 'module "compute" {\n  source = "../modules/compute-gke-autopilot"\n}\n'}
        yml = {"k8s/d.yaml": "apiVersion: apps/v1\nkind: Deployment\n"}
        self.assertEqual(tf_service.extract_apis_from_hcl(tf, yml), list(required_apis(tf, yml).apis))
        src = open(os.path.join(TERRAFORM_MCP_DIR, "service.py")).read()
        import ast
        fn = next(n for n in ast.walk(ast.parse(src))
                  if isinstance(n, ast.FunctionDef) and n.name == "extract_apis_from_hcl")
        names = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
        self.assertIn("required_apis", names)
        self.assertNotIn("combined_hcl", names)   # tombstone: no scan over the concatenated text

    def test_extract_apis_substring_tombstone(self):
        hcl_files = {"custom.tf": '# google_compute_instance and compute-gke-autopilot in a comment\n'
                                  'resource "google_pubsub_topic" "google_sql" {\n  name = "google_container"\n}\n'}
        apis = tf_service.extract_apis_from_hcl(hcl_files, {"x.yaml": "note: 'kind: Deployment'\n"})
        self.assertEqual(apis, ["cloudresourcemanager.googleapis.com", "iam.googleapis.com", "pubsub.googleapis.com",
                                "serviceusage.googleapis.com"])

    def test_extract_apis_legacy_remainder_only_for_an_unparseable_file(self):
        """A legacy committed file python-hcl2 cannot parse keeps today's per-file coverage (logged
        IAC.API_SCAN_UNPARSEABLE) until S2-F F6; a parseable sibling is read exactly."""
        hcl_files = {"bad.tf": 'resource "google_sql_database_instance" "db" {\n  settings = [1]]\n}\n',
                     "ok.tf": '# google_redis mentioned only in a comment\nresource "google_storage_bucket" "b" {}\n'}
        with self.assertLogs("mcp-terraform-server", level="WARNING") as logs:
            apis = tf_service.extract_apis_from_hcl(hcl_files)
        self.assertIn("sqladmin.googleapis.com", apis)          # legacy scan of bad.tf
        self.assertIn("storage.googleapis.com", apis)
        self.assertNotIn("redis.googleapis.com", apis)          # ok.tf is exact: a comment is not a type
        self.assertTrue(any("IAC.API_SCAN_UNPARSEABLE bad.tf" in m for m in logs.output))

    def test_extract_apis_unknown_type_is_logged_not_guessed(self):
        with self.assertLogs("mcp-terraform-server", level="WARNING") as logs:
            apis = tf_service.extract_apis_from_hcl({"c.tf": 'resource "google_kms_ekm_connection" "e" {}\n'})
        self.assertNotIn("cloudkms.googleapis.com", apis)
        self.assertTrue(any("IAC.API_UNKNOWN_FOR_TYPE" in m and "google_kms_ekm_connection" in m for m in logs.output))

    def test_golden_modules_alone_keep_todays_api_set(self):
        """Plan §3.3 C1b: a workspace with only a golden module call + the vendored module files yields exactly
        today's set for compute-cloudrun / compute-gke-autopilot / database-cloudsql / cache-redis, minus the
        run+firestore default (only ever added when no compute/db API was found). One documented difference: the
        old scan found vpcaccess.googleapis.com in compute-cloudrun only because the text "google_vpc_access_connector"
        appears in a variable DESCRIPTION; the module declares no connector (a declared connector's own row adds it)."""
        substring_artifacts = {"compute-cloudrun": {"vpcaccess.googleapis.com"}}
        for mod in ("compute-cloudrun", "compute-gke-autopilot", "database-cloudsql", "cache-redis"):
            tf = {"infra/workload/main.tf": f'module "m" {{\n  source = "../modules/{mod}"\n}}\n'}
            mdir = os.path.join(REPO_ROOT, "infra", "modules", mod)
            for f in sorted(os.listdir(mdir)):
                if f.endswith(".tf"):
                    tf[f"infra/modules/{mod}/{f}"] = open(os.path.join(mdir, f)).read()
            old = {"serviceusage.googleapis.com", "iam.googleapis.com", "cloudresourcemanager.googleapis.com"}
            for text in tf.values():
                old |= tf_service._legacy_extract_apis_from_text(text)
            new = set(tf_service.extract_apis_from_hcl(tf))
            self.assertEqual(new, old - substring_artifacts.get(mod, set()), (mod, sorted(new ^ old)))

    def test_terraform_server_pins_the_gateways_parser_versions(self):
        def pins(path):
            out = {}
            for line in open(path):
                req = line.split("#", 1)[0].strip()
                if "==" in req:
                    name, ver = req.split("==", 1)
                    out[name.strip().lower()] = ver.strip()
            return out
        gw = pins(os.path.join(REPO_ROOT, "apps", "orchestrator-gateway", "requirements.txt"))
        tf = pins(os.path.join(TERRAFORM_MCP_DIR, "requirements.txt"))
        for dist in ("python-hcl2", "lark", "regex", "pyyaml"):
            self.assertIn(dist, gw)
            self.assertEqual(tf.get(dist), gw[dist], dist)

    def test_vending_source_declares_cloudscheduler_and_eventarc(self):
        """Verifies that vending.py source includes cloudscheduler and eventarc in foundation_apis."""
        vending_path = os.path.join(VENDING_DIR, "vending.py")
        with open(vending_path, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn('"cloudscheduler.googleapis.com"', content)
        self.assertIn('"eventarc.googleapis.com"', content)


if __name__ == "__main__":
    unittest.main()
