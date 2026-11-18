"""
Unit tests for Compliance Agent Handler
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from compliance_agent.handler import ComplianceAgentHandler
from compliance_agent.schemas import ComplianceAuditRequest


class TestComplianceAgentHandler(unittest.TestCase):
    def setUp(self):
        # Lane 17 PR-1a: the compliance engine runs in-process only on explicit request (never a fallback).
        self.handler = ComplianceAgentHandler(compliance_server_url="http://localhost:8080", mode="inprocess")
        self.sample_dag = [
            {"step_id": "STEP-01-APIS", "title": "Enable APIs", "depends_on": []},
            {"step_id": "STEP-02-DB-REGISTRY", "title": "Create Database", "depends_on": ["STEP-01-APIS"]},
            {"step_id": "STEP-03-IAM", "title": "Create Service Accounts", "depends_on": ["STEP-01-APIS"]},
            {"step_id": "STEP-04-APP-CODE", "title": "Generate Code", "depends_on": ["STEP-03-IAM"]},
            {"step_id": "STEP-06-COMPUTE", "title": "Deploy Cloud Run", "depends_on": ["STEP-04-APP-CODE"]},
        ]

    def test_standard_fast_pass_through(self):
        req = ComplianceAuditRequest(
            product_id="my-web-app",
            spec_text="Deploy a basic internal reporting dashboard",
            task_dag=self.sample_dag,
        )
        res = self.handler.audit_and_enrich(req)
        self.assertEqual(res.compliance_profile, "STANDARD")
        self.assertFalse(res.is_regulated)
        self.assertEqual(len(res.injected_tasks), 0)
        self.assertEqual(len(res.enriched_dag), len(self.sample_dag))
        self.assertEqual(res.status, "PASSED")

    def test_hipaa_enrichment(self):
        req = ComplianceAuditRequest(
            product_id="patient-portal",
            spec_text="HIPAA compliant portal storing patient electronic health records (ePHI)",
            compliance_profile="HIPAA",  # compliance-profile-explicit: chosen explicitly, never from spec words
            task_dag=self.sample_dag,
        )
        res = self.handler.audit_and_enrich(req)
        self.assertEqual(res.compliance_profile, "HIPAA")
        self.assertTrue(res.is_regulated)
        self.assertTrue(res.requires_cmek)
        self.assertGreater(len(res.injected_tasks), 0)
        self.assertGreater(len(res.enriched_dag), len(self.sample_dag))

        # Verify KMS task injected
        step_ids = [s["step_id"] for s in res.enriched_dag]
        self.assertIn("STEP-03B-KMS-CMEK", step_ids)

        # Verify downstream tasks depend on CMEK
        code_step = next(s for s in res.enriched_dag if s["step_id"] == "STEP-04-APP-CODE")
        self.assertIn("STEP-03B-KMS-CMEK", code_step["depends_on"])

    def test_domain_restricted_sharing_enrichment(self):
        req = ComplianceAuditRequest(
            product_id="enterprise-app",
            spec_text="Deploy enterprise billing service with domain-restricted sharing policy",
            task_dag=self.sample_dag,
            plan_markdown="# Enterprise Plan\n\n## 3. Security, IAM & Governance Assessment",
        )
        res = self.handler.audit_and_enrich(req)
        self.assertTrue(res.domain_restricted_sharing)
        self.assertFalse(res.allow_unauthenticated)
        self.assertIn("Domain-Restricted Sharing", res.plan_markdown)

    def test_private_ingress_enrichment(self):
        req = ComplianceAuditRequest(
            product_id="internal-worker",
            spec_text="Backend worker with no public IP and private ingress internal only",
            task_dag=self.sample_dag,
        )
        res = self.handler.audit_and_enrich(req)
        self.assertTrue(res.enforce_private_ingress)
        step_ids = [s["step_id"] for s in res.enriched_dag]
        self.assertIn("STEP-06B-SERVERLESS-NEG", step_ids)
        self.assertIn("STEP-06C-HTTPS-LOAD-BALANCER", step_ids)


if __name__ == "__main__":
    unittest.main()
