"""
Unit Tests for Tier 3 Compliance Agent Evaluation, Remediation, and Governance Gate.
Tests coverage:
1. evaluate_policy_invariants:
   - Returns empty list when plan satisfies all policies (fast path < 50ms)
   - Detects constraints/compute.vmExternalIpAccess violations
   - Detects constraints/iam.disableServiceAccountKeyCreation violations
   - Detects constraints/storage.uniformBucketLevelAccess violations
2. remediate_conflicts:
   - Injects STEP-01B-VPC-NAT into task DAG
   - Appends Tier 3 Compliance Safety Remediation notes to plan markdown
3. _determine_approval_requirement:
   - ON_COMPLIANCE_CONFLICT policy triggers approval ONLY when conflicts exist
   - ALWAYS policy triggers approval even on clean plans
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_PATH = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
if GATEWAY_PATH not in sys.path:
    sys.path.insert(1, GATEWAY_PATH)

for m in [
    'httpx', 'fastapi', 'fastapi.responses', 'google', 'google.genai',
    'google.genai.types', 'google.cloud', 'google.cloud.firestore',
    'google.cloud.storage', 'google.cloud.logging', 'google.cloud.pubsub_v1',
    'github', 'jwt'
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

from compliance_agent.handler import ComplianceAgentHandler


class TestComplianceAgentRemediation(unittest.TestCase):
    def setUp(self):
        self.agent = ComplianceAgentHandler(compliance_server_url="http://mock-server")
        self.agent._db = MagicMock()

    def test_evaluate_policy_invariants_fast_path_clean_plan(self):
        """Verifies clean compliant plan evaluates in < 50ms with 0 conflicts."""
        policy_matrix = {
            "disallow_vm_external_ip": True,
            "disallow_default_network": True,
            "enforce_uniform_bucket_level_access": True,
            "disable_sa_key_creation": True,
            "require_os_login": True,
        }
        plan_markdown = """
# Architecture Plan: Secure Private Cloud Run & Storage
- Custom VPC with private subnets
- Cloud NAT and Cloud Router for private outbound egress
- Google Storage Bucket with uniform_bucket_level_access = true
- Workload Identity Federation for IAM authentication
- Compute instances configured with enable-oslogin = TRUE and IAP SSH
"""
        task_dag = [
            {"step_id": "STEP-01-APIS", "title": "Enable APIs", "description": "Enable run, storage"},
            {"step_id": "STEP-02-VPC", "title": "Provision Custom VPC", "description": "Declare custom vpc and subnets with Cloud NAT"},
            {"step_id": "STEP-03-STORAGE", "title": "Provision GCS Bucket", "description": "Declare bucket with uniform_bucket_level_access = true"},
        ]

        t0 = time.perf_counter()
        conflicts = self.agent.evaluate_policy_invariants(policy_matrix, plan_markdown, task_dag)
        elapsed_ms = (time.perf_counter() - t0) * 1000

        self.assertEqual(len(conflicts), 0)
        self.assertLess(elapsed_ms, 50.0)

    def test_evaluate_policy_invariants_detects_violations(self):
        """Verifies detection of VM public IPs, static SA keys, and bucket ACLs."""
        policy_matrix = {
            "disallow_vm_external_ip": True,
            "disable_sa_key_creation": True,
            "enforce_uniform_bucket_level_access": True,
        }
        plan_markdown = """
# Architecture Plan: Legacy Worker
- Provisions a compute instance VM with access_config for public IP
- Generates a google_service_account_key for Jenkins access
- Uses google_storage_bucket_acl for object ACL permissions
"""
        task_dag = [
            {"step_id": "STEP-01-APIS", "title": "Enable APIs", "description": "Enable compute, storage"},
            {"step_id": "STEP-02-VM", "title": "Provision VM", "description": "Declare google_compute_instance with public ip"},
            {"step_id": "STEP-03-KEY", "title": "Create SA Key", "description": "Create google_service_account_key"},
            {"step_id": "STEP-04-BUCKET", "title": "Create Bucket ACL", "description": "Declare google_storage_bucket_acl"},
        ]

        conflicts = self.agent.evaluate_policy_invariants(policy_matrix, plan_markdown, task_dag)
        self.assertEqual(len(conflicts), 3)
        self.assertTrue(any("vmExternalIpAccess" in c for c in conflicts))
        self.assertTrue(any("disableServiceAccountKeyCreation" in c for c in conflicts))
        self.assertTrue(any("uniformBucketLevelAccess" in c for c in conflicts))

    def test_remediate_conflicts_dag_and_plan_injection(self):
        """Verifies remediate_conflicts injects STEP-01B-VPC-NAT and compliance callouts."""
        conflicts = [
            "Folder enforces constraints/compute.vmExternalIpAccess. Public IPs on VMs are prohibited; workload must use Private IPs with Cloud NAT and IAP SSH Bastion.",
            "Folder enforces constraints/iam.disableServiceAccountKeyCreation. Static service account keys are prohibited; Workload Identity Federation must be used.",
            "Folder enforces constraints/storage.uniformBucketLevelAccess. Bucket ACLs are prohibited; Uniform Bucket-Level Access must be enabled.",
        ]
        initial_plan = "# My Architecture Plan\n- Direct VM deployment"
        initial_dag = [
            {"step_id": "STEP-01-APIS", "title": "APIs"},
            {"step_id": "STEP-06-COMPUTE", "title": "Compute", "depends_on": ["STEP-01-APIS"]},
        ]
        policy_matrix = {
            "disallow_vm_external_ip": True,
            "disable_sa_key_creation": True,
            "enforce_uniform_bucket_level_access": True,
        }

        remediated_plan, remediated_dag = self.agent.remediate_conflicts(
            conflicts=conflicts,
            plan_markdown=initial_plan,
            task_dag=initial_dag,
            policy_matrix=policy_matrix,
        )

        # Verify STEP-01B-VPC-NAT injected and compute depends on it
        step_ids = [t["step_id"] for t in remediated_dag]
        self.assertIn("STEP-01B-VPC-NAT", step_ids)
        compute_task = next(t for t in remediated_dag if t["step_id"] == "STEP-06-COMPUTE")
        self.assertIn("STEP-01B-VPC-NAT", compute_task["depends_on"])

        # Verify plan callouts added
        self.assertIn("Tier 3 Compliance Safety Remediation", remediated_plan)
        self.assertIn("constraints/compute.vmExternalIpAccess", remediated_plan)
        self.assertIn("constraints/iam.disableServiceAccountKeyCreation", remediated_plan)
        self.assertIn("constraints/storage.uniformBucketLevelAccess", remediated_plan)

    def test_determine_approval_requirement_governance(self):
        """Verifies approval requirement respects governance settings."""
        # 1. Clean plan + ON_COMPLIANCE_CONFLICT policy -> False
        mock_settings = MagicMock()
        mock_settings.governance.require_plan_approval = False
        mock_settings.governance.plan_approval_policy = "ON_COMPLIANCE_CONFLICT"

        with patch("shared.settings.get_platform_settings", return_value=mock_settings):
            req_approval = self.agent._determine_approval_requirement(has_policy_conflicts=False)
            self.assertFalse(req_approval)

        # 2. Conflicted plan + ON_COMPLIANCE_CONFLICT policy -> True
        with patch("shared.settings.get_platform_settings", return_value=mock_settings):
            req_approval = self.agent._determine_approval_requirement(has_policy_conflicts=True)
            self.assertTrue(req_approval)

        # 3. Clean plan + ALWAYS policy -> True
        mock_settings.governance.plan_approval_policy = "ALWAYS"
        with patch("shared.settings.get_platform_settings", return_value=mock_settings):
            req_approval = self.agent._determine_approval_requirement(has_policy_conflicts=False)
            self.assertTrue(req_approval)


if __name__ == "__main__":
    unittest.main()
