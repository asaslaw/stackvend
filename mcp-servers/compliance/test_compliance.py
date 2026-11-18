"""
Unit tests for Compliance MCP Server using standard unittest
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from service import ComplianceService


class TestComplianceService(unittest.TestCase):
    def setUp(self):
        self.service = ComplianceService(project_id="test-project")

    # compliance-profile-explicit: spec words never choose the profile; they only produce advisory suggestions.
    # (The full decision tests live in tests/test_compliance_profile_explicit.py.)
    def test_standard_spec_has_no_suggestions(self):
        res = self.service.suggest_profiles_from_spec("Deploy a simple FastAPI customer portal on Cloud Run", "STANDARD")
        self.assertEqual(res, [])

    def test_hipaa_words_are_only_a_suggestion(self):
        res = self.service.suggest_profiles_from_spec("We need to store HIPAA patient electronic health records (ePHI)",
                                                      "STANDARD")
        self.assertEqual([s["profile"] for s in res], ["HIPAA"])
        decision = self.service.resolve_profile(None, {"is_assured_workload": False})
        self.assertEqual(decision["profile"], "STANDARD")

    def test_explicit_profile_is_the_decision(self):
        decision = self.service.resolve_profile("FEDRAMP_HIGH", {"is_assured_workload": False})
        self.assertEqual((decision["profile"], decision["profile_source"]), ("FEDRAMP_HIGH", "EXPLICIT_REQUEST"))

    def test_gdpr_words_are_only_a_suggestion(self):
        res = self.service.suggest_profiles_from_spec("European customer data processing with GDPR data sovereignty",
                                                      "STANDARD")
        self.assertEqual([s["profile"] for s in res], ["EU_REGIONS_AND_SUPPORT"])

    def test_hipaa_requirements(self):
        reqs = self.service.get_compliance_requirements("HIPAA")
        self.assertTrue(reqs["requires_cmek"])
        self.assertTrue(reqs["requires_audit_logging"])
        self.assertEqual(len(reqs["mandated_tasks"]), 2)
        step_ids = [t["step_id"] for t in reqs["mandated_tasks"]]
        self.assertIn("STEP-03B-KMS-CMEK", step_ids)
        self.assertIn("STEP-03C-AUDIT-LOGGING", step_ids)

    def test_standard_requirements(self):
        reqs = self.service.get_compliance_requirements("STANDARD")
        self.assertFalse(reqs["requires_cmek"])
        self.assertEqual(len(reqs["mandated_tasks"]), 0)

    def test_hcl_compliance_evaluation_pass(self):
        # Lane 14 PR-0: parser-based engine. A KMS key merely existing no longer satisfies CMEK; each CMEK-capable
        # resource must use one, and HIPAA also needs the DATA_READ/DATA_WRITE audit config.
        hcl = {
            "main.tf": """
resource "google_kms_crypto_key" "key" {
  name     = "workload-cmek"
  key_ring = "keyring"
}
resource "google_project_iam_audit_config" "all" {
  project = "p"
  service = "allServices"
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }
}
resource "google_cloud_run_v2_service" "app" {
  location = "us-central1"
  template {
    encryption_key = google_kms_crypto_key.key.id
  }
}
"""
        }
        eval_res = self.service.evaluate_hcl_compliance(hcl, "HIPAA")
        self.assertTrue(eval_res["compliant"])
        self.assertEqual(len(eval_res["violations"]), 0)

    def test_hcl_compliance_evaluation_violation_missing_cmek(self):
        hcl = {
            "main.tf": """
resource "google_cloud_run_v2_service" "app" {
  location = "us-central1"
}
"""
        }
        eval_res = self.service.evaluate_hcl_compliance(hcl, "HIPAA")
        self.assertFalse(eval_res["compliant"])
        self.assertTrue(any("CMEK" in v for v in eval_res["violations"]))

    def test_pci_dss_load_balancer_and_neg_injection(self):
        """Verifies that PCI-DSS and private ingress injects Serverless NEG and HTTPS Load Balancer tasks."""
        reqs = self.service.get_compliance_requirements("PCI_DSS")
        self.assertTrue(reqs["requires_load_balancer"])
        self.assertTrue(reqs["enforce_private_ingress"])
        step_ids = [t["step_id"] for t in reqs["mandated_tasks"]]
        self.assertIn("STEP-06B-SERVERLESS-NEG", step_ids)
        self.assertIn("STEP-06C-HTTPS-LOAD-BALANCER", step_ids)

    def test_inspect_org_policies_domain_restricted(self):
        """Verifies detection of constraints/iam.allowedPolicyMemberDomains."""
        class MockResponse:
            def __init__(self, data, status_code=200):
                self._data = data
                self.status_code = status_code
            def json(self):
                return self._data

        class MockSession:
            def post(self, url, json=None, timeout=5.0):
                constraint = (json or {}).get("constraint", "")
                if constraint == "constraints/iam.allowedPolicyMemberDomains":
                    return MockResponse({
                        "listPolicy": {
                            "allowedValues": ["mycompany.com", "partner.org", "is:principalSet://..."]
                        }
                    })
                return MockResponse({})

        self.service._session = MockSession()
        res = self.service.inspect_org_policies("folders/123456789")
        self.assertTrue(res["domain_restricted_sharing"])
        self.assertFalse(res["allow_unauthenticated"])
        self.assertIn("mycompany.com", res["allowed_domains"])
        self.assertIn("partner.org", res["allowed_domains"])
        self.assertNotIn("is:principalSet://...", res["allowed_domains"])

    def test_inspect_org_policies_open(self):
        """Verifies standard open org without domain restrictions."""
        class MockSession:
            def post(self, url, json=None, timeout=5.0):
                raise Exception("Not found")

        self.service._session = MockSession()
        res = self.service.inspect_org_policies("folders/999999")
        self.assertFalse(res["domain_restricted_sharing"])
        self.assertTrue(res["allow_unauthenticated"])
        self.assertEqual(res["allowed_domains"], [])

    def test_inspect_org_policies_private_ingress(self):
        """Verifies detection of constraints/run.allowedIngress."""
        class MockResponse:
            def __init__(self, data, status_code=200):
                self._data = data
                self.status_code = status_code
            def json(self):
                return self._data

        class MockSession:
            def post(self, url, json=None, timeout=5.0):
                constraint = (json or {}).get("constraint", "")
                if constraint == "constraints/run.allowedIngress":
                    return MockResponse({
                        "listPolicy": {
                            "allowedValues": ["INGRESS_TRAFFIC_INTERNAL_ONLY"]
                        }
                    })
                return MockResponse({})

        self.service._session = MockSession()
        res = self.service.inspect_org_policies("folders/123456789")
        self.assertTrue(res["enforce_private_ingress"])


if __name__ == "__main__":
    unittest.main()
