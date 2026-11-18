"""
Unit Tests for Tier 1 GCP Organization Policy Dynamic Harvesting.
Tests orgpolicy.googleapis.com/v2 queries, CRM v3 fallback, and policy matrix assembly.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

import importlib.util

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

for m in [
    'httpx', 'fastapi', 'fastapi.responses', 'google', 'google.genai',
    'google.genai.types', 'google.cloud', 'google.cloud.firestore',
    'google.cloud.storage', 'google.cloud.logging', 'google.cloud.pubsub_v1',
    'github', 'jwt'
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

spec = importlib.util.spec_from_file_location(
    "compliance_service_module",
    os.path.join(REPO_ROOT, "mcp-servers", "compliance", "service.py")
)
compliance_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compliance_mod)
ComplianceService = compliance_mod.ComplianceService


class TestOrgPolicyHarvester(unittest.TestCase):
    def setUp(self):
        self.service = ComplianceService(project_id="castor-test-project")

    def test_harvest_folder_policies_with_v2_data(self):
        """Verifies policy matrix extraction from simulated Org Policy v2 responses."""
        mock_policies = [
            {
                "name": "folders/12345/policies/compute.vmExternalIpAccess",
                "spec": {
                    "rules": [{"enforce": True}]
                }
            },
            {
                "name": "folders/12345/policies/storage.uniformBucketLevelAccess",
                "spec": {
                    "rules": [{"enforce": True}]
                }
            },
            {
                "name": "folders/12345/policies/iam.allowedPolicyMemberDomains",
                "spec": {
                    "rules": [{"values": {"allowedValues": ["directoryCustomers/my-customer-id"]}}]
                }
            }
        ]

        mock_res = MagicMock()
        mock_res.status_code = 200
        mock_res.json.return_value = {"policies": mock_policies}

        mock_session = MagicMock()
        mock_session.get.return_value = mock_res

        with patch.object(self.service, "_get_session", return_value=mock_session):
            matrix = self.service.harvest_folder_policies("folders/12345")
            self.assertTrue(matrix["disallow_vm_external_ip"])
            self.assertTrue(matrix["enforce_uniform_bucket_level_access"])
            self.assertTrue(matrix["domain_restricted_sharing"])
            self.assertEqual(matrix["allowed_domains"], ["directoryCustomers/my-customer-id"])
            self.assertFalse(matrix["allow_unauthenticated"])
            self.assertTrue(matrix["has_constraints"])

    def test_harvest_folder_policies_fallback_when_empty(self):
        """Verifies graceful fallback mode when folder has zero constraints or query fails."""
        mock_res = MagicMock()
        mock_res.status_code = 404
        mock_res.json.return_value = {}

        mock_session = MagicMock()
        mock_session.get.return_value = mock_res
        mock_session.post.return_value = mock_res

        with patch.object(self.service, "_get_session", return_value=mock_session):
            matrix = self.service.harvest_folder_policies("folders/empty")
            self.assertFalse(matrix["has_constraints"])
            self.assertFalse(matrix["disallow_vm_external_ip"])
            self.assertTrue(matrix["allow_unauthenticated"])

    def test_harvest_folder_policies_with_crm_v3_fallback(self):
        """Verifies fallback to CRM v3 when v2 returns no policies."""
        mock_v2_res = MagicMock()
        mock_v2_res.status_code = 200
        mock_v2_res.json.return_value = {"policies": []}

        def mock_crm_post(url, json=None, timeout=None):
            resp = MagicMock()
            if json and json.get("constraint") == "constraints/compute.skipDefaultNetworkCreation":
                resp.status_code = 200
                resp.json.return_value = {
                    "booleanPolicy": {"enforced": True}
                }
            else:
                resp.status_code = 404
                resp.json.return_value = {}
            return resp

        mock_session = MagicMock()
        mock_session.get.return_value = mock_v2_res
        mock_session.post.side_effect = mock_crm_post

        with patch.object(self.service, "_get_session", return_value=mock_session):
            matrix = self.service.harvest_folder_policies("12345")
            self.assertTrue(matrix["disallow_default_network"])
            self.assertTrue(matrix["has_constraints"])


if __name__ == "__main__":
    unittest.main()
