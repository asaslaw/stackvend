"""
Tests for Automated Workload Implementation Plans in docs/planning/
Verifies:
1. Architect Agent produces deterministic docs/planning/<file>.md and 7-section plan markdown.
2. Compliance Agent enriches Section 3 (Security & Governance).
3. Developer Agent injects docs/planning/<file>.md into the child repo files dictionary and PR description.
4. Control Center returns plans from /api/workloads/{product_id}/plans.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Ensure mocks for third-party libs if not installed in host environment
try:
    import pydantic
except ImportError:
    class MockBaseModel:
        def __init__(self, **kwargs):
            for k, v in self.__class__.__dict__.items():
                if not k.startswith('_') and not callable(v):
                    default_val = getattr(v, 'default', v)
                    if default_val is not Ellipsis:
                        setattr(self, k, default_val)
            for k, v in kwargs.items():
                setattr(self, k, v)
        def model_dump(self):
            return {k: v for k, v in self.__dict__.items() if not k.startswith('_')}

    class MockFieldInfo:
        def __init__(self, default=None, default_factory=None):
            self.default = default if default is not None else (default_factory() if default_factory else None)

    mock_pydantic = MagicMock()
    mock_pydantic.BaseModel = MockBaseModel
    mock_pydantic.Field = lambda default=None, default_factory=None, **kwargs: MockFieldInfo(default, default_factory)
    mock_pydantic.EmailStr = str
    sys.modules['pydantic'] = mock_pydantic

for m in [
    'httpx', 'fastapi', 'fastapi.responses', 'google', 'google.genai',
    'google.genai.types', 'google.cloud', 'google.cloud.firestore',
    'google.cloud.storage', 'google.cloud.logging', 'google.cloud.pubsub_v1',
    'github', 'jwt'
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_PATH = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
CONTROL_CENTER_PATH = os.path.join(REPO_ROOT, "apps", "control-center")

if GATEWAY_PATH not in sys.path:
    sys.path.insert(0, GATEWAY_PATH)
if CONTROL_CENTER_PATH not in sys.path:
    sys.path.insert(0, CONTROL_CENTER_PATH)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)


class TestAutomatedWorkloadImplementationPlans(unittest.TestCase):

    def test_architect_generates_standard_plan_markdown_and_path(self):
        """Architect Agent must create deterministic docs/planning/ path and 7-section Markdown."""
        from architect_agent.handler import ArchitectAgent
        from architect_agent.schemas import ArchitecturePlan, TaskItem

        agent = ArchitectAgent(project_id="test-platform-project", location="us-central1")
        plan = ArchitecturePlan(
            product_id="test-billing-service",
            summary="Billing service with Stripe integration",
            architecture_overview="FastAPI microservice with Firestore ledger",
            project_tier=1,
            estimated_complexity="MEDIUM",
            requires_human_approval=False,
            risk_assessment="Low blast radius",
            code_tasks=[
                TaskItem(task_id="TASK-01", title="FastAPI routes", target_files=["apps/service/main.py"], description="Stripe webhook")
            ],
            infra_tasks=[
                TaskItem(task_id="TASK-02", title="Terraform Cloud Run", target_files=["infra/workload/main.tf"], description="Cloud Run v2")
            ]
        )

        path, md = agent.generate_implementation_plan_markdown(
            plan=plan,
            trace_id="tr-test-001",
            product_id="test-billing-service",
            spec_text="Initial workload build for billing service",
        )

        self.assertEqual(path, "docs/planning/0001-initial-workload-architecture.md")
        self.assertIn("# Implementation Plan: Initial Workload Architecture for test-billing-service", md)
        self.assertIn("## 1. Executive Summary & Requirements", md)
        self.assertIn("## 2. Architecture & Topology Design", md)
        self.assertIn("## 3. Security, IAM & Governance Assessment", md)
        self.assertIn("## 4. Component Manifest & Proposed Changes", md)
        self.assertIn("## 5. Sequenced Build Plan (Task DAG)", md)
        self.assertIn("## 6. Verification & Automated Test Strategy", md)
        self.assertIn("## 7. Rollback & Blast Radius Assessment", md)
        self.assertIn("```mermaid", md)

        feat_path, feat_md = agent.generate_implementation_plan_markdown(
            plan=plan,
            trace_id="tr-test-002",
            product_id="test-billing-service",
            spec_text="Add Redis cache and OAuth2 authentication",
        )
        self.assertTrue(feat_path.startswith("docs/planning/"))
        self.assertTrue("feat" in feat_path)
        self.assertIn("## 1. Executive Summary", feat_md)

    @hermetic_guard.unavailable("compliance_agent.handler.httpx.Client", "Compliance MCP server")
    def test_compliance_enriches_plan_markdown(self):
        """Compliance Agent enriches Section 3 with compliance profile, CMEK, and audit logs."""
        from compliance_agent.handler import ComplianceAgentHandler
        from compliance_agent.schemas import ComplianceAuditRequest

        # Lane 17 PR-1a: the compliance engine runs in-process only on explicit request (never a fallback).
        handler = ComplianceAgentHandler(compliance_server_url="http://mock-compliance", mode="inprocess")
        base_plan_md = """# Implementation Plan: Test Service

## 1. Executive Summary & Requirements
- Problem Statement: Test service

## 3. Security, IAM & Governance Assessment
- Identity: sa-test
"""

        req = ComplianceAuditRequest(
            product_id="test-patient-portal",
            spec_text="Patient medical records with HIPAA requirements",
            compliance_profile="HIPAA",  # compliance-profile-explicit: chosen explicitly, never from spec words
            task_dag=[],
            plan_markdown=base_plan_md,
            plan_file_path="docs/planning/0001-initial-workload-architecture.md",
        )

        with patch.object(handler, "_persist_audit_record"):
            res = handler.audit_and_enrich(req)

            self.assertIsNotNone(res.plan_markdown)
            self.assertIn("Compliance Profile", res.plan_markdown)
            self.assertIn("HIPAA", res.plan_markdown)
            self.assertIn("Cloud KMS CMEK Encryption", res.plan_markdown)
            self.assertIn("Dedicated Audit Logging", res.plan_markdown)
            self.assertEqual(res.plan_file_path, "docs/planning/0001-initial-workload-architecture.md")

    def test_developer_agent_injects_plan_into_child_repo_files(self):
        """Developer Agent ensures docs/planning/<file>.md is in generated files dictionary."""
        from developer_agent.handler import DeveloperAgent

        # Lane 19 L19-3b (owner register row 27a): fake LLM instead of the deleted template fallback.
        from _lane19_fake_genai import FakeGenaiClient, canned_workload_files
        dev_agent = DeveloperAgent()
        dev_agent.genai_client = FakeGenaiClient(files=canned_workload_files("test-workload"))
        plan_md = "# Custom Implementation Plan\n\n## 1. Executive Summary\nTest details\n"
        plan_path = "docs/planning/0001-initial-workload-architecture.md"

        with patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false"}), \
                patch.object(dev_agent, "fetch_existing_repo_files", return_value={}):
            files = dev_agent.generate_code_files(
                product_id="test-workload",
                spec_text="Implement payment gateway",
                task_dag=[],
                plan_markdown=plan_md,
                plan_file_path=plan_path, allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False
            )

            self.assertIn(plan_path, files)
            self.assertEqual(files[plan_path], plan_md)

    def test_developer_agent_enforces_deterministic_golden_workflow(self):
        """Developer Agent purges LLM-hallucinated workflows and guarantees golden CI/CD template."""
        from developer_agent.handler import DeveloperAgent
        import json

        dev_agent = DeveloperAgent()
        hallucinated_files = {
            "apps/testsvc/main.py": "print('hello')",
            ".github/workflows/deploy-testsvc.yml": """
name: Deploy testsvc
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: |
          gcloud run deploy ${SERVICE_NAME} \\
            --image ${{ REGION }}-docker.pkg.dev/repo/img \\
            --source apps/${SERVICE_NAME}
""",
            ".github/workflows/deploy.yml": "invalid monolithic workflow",
        }

        mock_response = MagicMock()
        mock_response.text = json.dumps({"files": hallucinated_files})

        with patch.object(dev_agent, "genai_client") as mock_client:
            mock_client.models.generate_content.return_value = mock_response
            files = dev_agent.generate_code_files(
                product_id="testsvc",
                spec_text="Build test service",
                task_dag=[], allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False
            )

            # Monolithic workflow must be pruned
            self.assertNotIn(".github/workflows/deploy.yml", files)

            # Service workflow must exist and be deterministic golden template
            wf_path = ".github/workflows/deploy-testsvc.yml"
            self.assertIn(wf_path, files)
            wf_content = files[wf_path]

            # Verify golden template features
            self.assertIn("name: Deploy testsvc to Cloud Run", wf_content)
            self.assertIn('--source "apps/${APP_NAME}"', wf_content)
            self.assertIn("--allow-unauthenticated", wf_content)
            self.assertIn('--service-account "${GCP_WORKLOAD_SA}"', wf_content)
            # Ensure bare ${{ REGION }} expression parser crash is absent
            self.assertNotIn("${{ REGION }}", wf_content)
        # FD-55 W1 (FD55-W1): the gateway's sanitize_github_workflow had no production caller and is deleted (the
        # workflow above is the platform render); its direct-call case went with it.

    def test_control_center_plans_logic(self):
        """Control Center returns synthesized baseline plan when database is empty."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("schemas", os.path.join(CONTROL_CENTER_PATH, "schemas.py"))
        cc_schemas = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cc_schemas)

        plan_item = cc_schemas.WorkloadPlanItem(
            filename="0001-initial-workload-architecture.md",
            file_path="docs/planning/0001-initial-workload-architecture.md",
            title="Initial Workload Architecture for test-workload",
            status="PLANNED",
            tier=1,
            created_at="2026-09-05T00:00:00Z",
            trace_id="baseline-init",
            url="https://github.com/example-org/castor-test-workload/blob/main/docs/planning/0001-initial-workload-architecture.md",
            markdown="# Plan Markdown",
        )
        response = cc_schemas.WorkloadPlansResponse(
            product_id="test-workload",
            total_plans=1,
            plans=[plan_item],
        )

        self.assertEqual(response.product_id, "test-workload")
        self.assertEqual(response.total_plans, 1)
        self.assertTrue(response.plans[0].file_path.startswith("docs/planning/"))
        self.assertEqual(response.plans[0].filename, "0001-initial-workload-architecture.md")

    def test_feature_request_record_has_plan_links(self):
        """FeatureRequestRecord schema supports plan_filename, plan_file_path, and plan_github_url."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("schemas", os.path.join(CONTROL_CENTER_PATH, "schemas.py"))
        cc_schemas = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cc_schemas)

        fr = cc_schemas.FeatureRequestRecord(
            request_id="feat-billing-100",
            product_id="billing-service",
            project_id="castor-billing",
            title="Add Stripe webhooks",
            description="Process subscription payments",
            change_type=cc_schemas.FeatureChangeType.FEATURE_ENHANCEMENT,
            priority=cc_schemas.FeatureRequestPriority.HIGH,
            target_components="apps/service/main.py",
            submitted_by="admin@castor.dev",
            created_at="2026-09-06T10:00:00Z",
            plan_filename="2026-09-06-feat-stripe-webhooks.md",
            plan_file_path="docs/planning/2026-09-06-feat-stripe-webhooks.md",
            plan_github_url="https://github.com/example-org/castor-billing-service/blob/main/docs/planning/2026-09-06-feat-stripe-webhooks.md",
        )

        dumped = fr.model_dump() if hasattr(fr, "model_dump") else (fr.dict() if hasattr(fr, "dict") else fr.__dict__)
        self.assertEqual(fr.plan_filename, "2026-09-06-feat-stripe-webhooks.md")
        self.assertEqual(fr.plan_file_path, "docs/planning/2026-09-06-feat-stripe-webhooks.md")
        self.assertIn("github.com", fr.plan_github_url)
        self.assertEqual(dumped["plan_filename"], "2026-09-06-feat-stripe-webhooks.md")
        self.assertEqual(dumped["plan_file_path"], "docs/planning/2026-09-06-feat-stripe-webhooks.md")

    def test_control_center_ui_template_contains_planning_links(self):
        """Verify Control Center UI template renders header, overview, plans section, and feature card planning links."""
        template_path = os.path.join(CONTROL_CENTER_PATH, "templates", "dashboard.html")
        if os.path.exists(template_path):
            with open(template_path, "r", encoding="utf-8") as f:
                content = f.read()
        else:
            main_py_path = os.path.join(CONTROL_CENTER_PATH, "main.py")
            with open(main_py_path, "r", encoding="utf-8") as f:
                content = f.read()

        # 1. Top action bar contains docs/planning/ link
        self.assertIn("docs/planning/ ↗", content)
        self.assertIn("/tree/main/docs/planning", content)

        # 2. Workload Overview metadata card contains Browse docs/planning/
        self.assertIn("Browse docs/planning/ ↗", content)

        # 3. Child Workload Implementation Plans section header contains GitHub docs/planning/
        self.assertIn("GitHub docs/planning/ ↗", content)

        # 4. Feature Queue card header contains plan link
        self.assertIn("getPlanUrlForFeature(fr)", content)

        # 5. Feature card action bar contains direct View Architecture Plan ↗ anchor link to child repo
        self.assertIn("View Architecture Plan ↗", content)
        self.assertIn(":href=\"getPlanUrlForFeature(fr)\"", content)
    def test_workload_details_response_dynamic_vcs(self):
        """WorkloadDetailsResponse schema supports vcs_provider and git_clone_url."""
        import importlib.util
        spec = importlib.util.spec_from_file_location("schemas", os.path.join(CONTROL_CENTER_PATH, "schemas.py"))
        cc_schemas = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cc_schemas)

        details = cc_schemas.WorkloadDetailsResponse(
            product_id="test-serverless-wl",
            project_id="castor-test",
            status="ACTIVE",
            budget_ceiling_monthly_usd=50.0,
            vcs_provider="SERVERLESS_GIT",
            git_clone_url="https://castor-git-server.a.run.app/git/test-serverless-wl.git",
        )
        self.assertEqual(details.vcs_provider, "SERVERLESS_GIT")
        self.assertEqual(details.git_clone_url, "https://castor-git-server.a.run.app/git/test-serverless-wl.git")

    def test_control_center_serverless_git_dynamic_bindings(self):
        """Verify Control Center UI template renders Serverless Git badges, raw markdown links, and clone commands."""
        template_path = os.path.join(CONTROL_CENTER_PATH, "templates", "dashboard.html")
        workload_routes_path = os.path.join(CONTROL_CENTER_PATH, "routes", "workloads.py")
        content = ""
        for p in [os.path.join(CONTROL_CENTER_PATH, "main.py"), template_path, workload_routes_path]:
            if os.path.exists(p):
                with open(p, "r", encoding="utf-8") as f:
                    content += "\n" + f.read()

        # 1. Dynamic repository title and clone command
        self.assertIn("Serverless Git Repo", content)
        self.assertIn("copyGitCloneCommand", content)
        self.assertIn("gitCloneCopied", content)
        self.assertIn("scrollToPlans", content)
        self.assertIn("child-workload-plans", content)

        # 2. Raw markdown plan exposer for private serverless git
        self.assertIn("/raw", content)
        # FD-4N (lane 4): the route decorator now also carries its authorization policy, so match the path only.
        self.assertIn('@router.get("/api/workloads/{product_id}/plans/{filename}/raw"', content)
        self.assertIn("📄 Raw Markdown", content)


if __name__ == "__main__":
    unittest.main()

