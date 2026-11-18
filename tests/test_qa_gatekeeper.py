"""
Project Castor: Automated Test Suite for Autonomous QA Gatekeeper & Dual-Lens Audit Pipeline
Tests:
1. Stage 1: moved to the isolated QA sandbox job (row L3-PRB-d; see the note below)
2. Stage 2: Dual-Lens Audit Panel (Security Lens with contextual ingress, Task DAG Adherence Lens, Coordinator)
3. Stage 3: Lead Release Gatekeeper (Governance rules, Auto-Merge gating, Markdown Release Certificates, Multi-VCS)
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import os
import shutil
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Ensure paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_DIR = os.path.join(BASE_DIR, "apps", "orchestrator-gateway")
CONTROL_CENTER_DIR = os.path.join(BASE_DIR, "apps", "control-center")

for p in (GATEWAY_DIR, CONTROL_CENTER_DIR, BASE_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

from shared.qa_audit_schemas import (
    AdherenceLensResult,
    CompositeAuditReport,
    DeterministicGateReport,
    ReleaseGateDecision,
    SecurityLensResult,
)
from qa_auditor.security_lens import (
    evaluate_security_lens,
    _deterministic_security_heuristic,
)
from qa_auditor.adherence_lens import (
    evaluate_adherence_lens,
    _deterministic_adherence_heuristic,
)
from qa_auditor.coordinator import DualLensAuditorCoordinator
from release_gatekeeper import (
    evaluate_release_decision,
    generate_release_certificate,
    post_release_certificate_to_vcs,
)


# Stage 1 (the old qa-runner in-process runner: pytest, bandit, HCL brace count, zero-Dockerfile, AST, pruned diff)
# was deleted by register row L3-PRB-d. Its checks live in the isolated QA sandbox job and are covered there:
# tests/test_qa_sandbox_job.py (Dockerfile, syntax, bandit, pytest, layout), the gateway <-> job loop in
# tests/test_lane3_prb_qa_contract.py, and the tombstone in tests/test_lane3_prb_rad.py. The HCL brace check was
# deleted by row 19l (the job has none).


@hermetic_guard.unavailable("google.genai.Client", "Gemini")
class TestDualLensAuditPanel(unittest.TestCase):
    """Verifies Stage 2 Security Lens and Task DAG Adherence Lens."""

    def test_security_lens_contextual_ingress_public_app(self):
        """Verifies that allUsers on Cloud Run is PERMITTED when allow_unauthenticated is True."""
        sample_diff = """
--- a/infra/main.tf
+++ b/infra/main.tf
+resource "google_cloud_run_v2_service_iam_member" "public_access" {
+  project  = "castor-prod"
+  location = "us-central1"
+  name     = "web-frontend"
+  role     = "roles/run.invoker"
+  member   = "allUsers"
+}
"""
        # When allow_unauthenticated is True
        res_public = _deterministic_security_heuristic(
            git_diff=sample_diff,
            allow_unauth=True,
            requires_vpc=False,
        )
        self.assertTrue(res_public.passed)
        self.assertEqual(len(res_public.critical_vulnerabilities), 0)
        self.assertTrue(any("roles/run.invoker for allUsers" in flag for flag in res_public.compliance_flags))

        # When allow_unauthenticated is False (Private app)
        res_private = _deterministic_security_heuristic(
            git_diff=sample_diff,
            allow_unauth=False,
            requires_vpc=True,
        )
        self.assertFalse(res_private.passed)
        self.assertTrue(any("allUsers" in crit for crit in res_private.critical_vulnerabilities))

    def test_security_lens_blocks_public_database_ingress(self):
        """Verifies that 0.0.0.0/0 on database is blocked even if allow_unauthenticated is True."""
        db_diff = """
--- a/infra/database.tf
+++ b/infra/database.tf
+resource "google_sql_database_instance" "master" {
+  settings {
+    ip_configuration {
+      authorized_networks {
+        value = "0.0.0.0/0"
+      }
+    }
+  }
+}
"""
        res = _deterministic_security_heuristic(
            git_diff=db_diff,
            allow_unauth=True,  # Even if public app, database must NOT be public
            requires_vpc=False,
        )
        self.assertFalse(res.passed)
        self.assertTrue(any("public database ingress" in crit for crit in res.critical_vulnerabilities))

    def test_security_lens_blocks_primitive_iam_roles(self):
        """Verifies that roles/owner or roles/editor are blocked."""
        iam_diff = """
+resource "google_project_iam_member" "bad_role" {
+  role   = "roles/owner"
+  member = "serviceAccount:test@castor.iam.gserviceaccount.com"
+}
"""
        res = _deterministic_security_heuristic(
            git_diff=iam_diff,
            allow_unauth=False,
            requires_vpc=False,
        )
        self.assertFalse(res.passed)
        self.assertTrue(any("roles/owner" in crit for crit in res.critical_vulnerabilities))

    def test_adherence_lens_detects_missing_target_files(self):
        """Verifies that omitting a task's target files drops adherence score."""
        tasks = [
            {
                "task_id": "task-backend-01",
                "title": "FastAPI Health Endpoint",
                "target_files": ["apps/payment/main.py"],
                "acceptance_criteria": ["Exposes GET /health", "Returns 200 OK"],
            },
            {
                "task_id": "task-database-02",
                "title": "Firestore Index Configuration",
                "target_files": ["infra/firestore_indexes.tf"],
                "acceptance_criteria": ["Declares composite index for created_at DESC"],
            },
        ]
        # Diff only implements task-backend-01
        diff = """
--- a/apps/payment/main.py
+++ b/apps/payment/main.py
+@app.get("/health")
+def health():
+    return {"status": "ok"}
"""
        res = _deterministic_adherence_heuristic(git_diff=diff, tasks=tasks)
        self.assertFalse(res.passed)
        self.assertLess(res.instruction_adherence_score, 0.95)
        self.assertEqual(len(res.missed_directives), 1)
        self.assertIn("task-database-02", res.missed_directives[0])

    def test_coordinator_parallel_dispatch_and_composite_report(self):
        """Verifies DualLensAuditorCoordinator combines Stage 1 and Stage 2 into CompositeAuditReport."""
        coordinator = DualLensAuditorCoordinator(timeout_seconds=5.0)

        determ_report = DeterministicGateReport(
            passed=True,
            pytest_success=True,
            pytest_passed_count=10,
            pytest_failed_count=0,
            coverage_percentage=100.0,
            bandit_passed=True,
            hcl_syntax_passed=True,
            zero_dockerfile_passed=True,
            ast_syntax_passed=True,
            git_diff_pruned="diff --git a/apps/svc/main.py b/apps/svc/main.py\n+print('hello')",
        )

        tasks = [
            {
                "task_id": "task-01",
                "title": "Service Implementation",
                "target_files": ["apps/svc/main.py"],
                "acceptance_criteria": ["Initializes service"],
            }
        ]

        # FD-4F DL-2 (lane 13): Stage 2 is a real judge call that fails closed; the keyword heuristic no longer
        # substitutes a pass when the judge is unreachable. A typed passing judge reply stands in for Vertex.
        from fd4f_support import judge_reply
        from qa_auditor.platform_facts import build_platform_facts

        with patch("qa_auditor.judge.call", judge_reply()):
            sec_res, adh_res, comp_rep = coordinator.evaluate_stage_two(
                git_diff=determ_report.git_diff_pruned,
                determ_report=determ_report,
                task_dag=tasks,
                pytest_logs="10 passed in 1.2s",
                ingress_policy={"allow_unauthenticated": True},
                platform_facts=build_platform_facts(None, "off", tasks),
            )

        self.assertIsInstance(comp_rep, CompositeAuditReport)
        self.assertTrue(comp_rep.passed)
        self.assertGreaterEqual(comp_rep.overall_soundness_score, 0.95)
        self.assertEqual(len(comp_rep.blocking_reasons), 0)


class TestLeadReleaseGatekeeper(unittest.TestCase):
    """Verifies Stage 3 Release Gatekeeper decisions, governance policies, and certificates."""

    def test_auto_merge_approved_when_clean_and_hitl_off(self):
        """Verifies auto_merge is approved when all gates pass and require_human_code_review is False."""
        determ = {"passed": True}
        sec = {"passed": True, "critical_vulnerabilities": []}
        adh = {"passed": True, "instruction_adherence_score": 1.0, "grounding_score": 1.0, "missed_directives": []}
        policy = {"require_human_code_review": False, "auto_merge": True}

        decision = evaluate_release_decision(
            determ_report=determ,
            sec_report=sec,
            adh_report=adh,
            workload_policy=policy,
            product_id="test-product",
            branch_name="feature/billing",
            commit_sha="c1a2b3d4",
        )

        self.assertTrue(decision.is_approved)
        self.assertFalse(decision.requires_human_intervention)
        self.assertEqual(decision.recommended_action, "AUTO_MERGE")
        self.assertIn("APPROVED FOR AUTONOMOUS MERGE", decision.release_certificate_markdown)

    def test_blocked_for_hitl_review_when_human_review_required(self):
        """Verifies PR is left open for human review when require_human_code_review is True."""
        determ = {"passed": True}
        sec = {"passed": True, "critical_vulnerabilities": []}
        adh = {"passed": True, "instruction_adherence_score": 0.98, "grounding_score": 1.0, "missed_directives": []}
        policy = {"require_human_code_review": True, "auto_merge": False}

        decision = evaluate_release_decision(
            determ_report=determ,
            sec_report=sec,
            adh_report=adh,
            workload_policy=policy,
            product_id="test-product",
            branch_name="feature/billing",
            commit_sha="c1a2b3d4",
        )

        self.assertFalse(decision.is_approved)
        self.assertTrue(decision.requires_human_intervention)
        self.assertEqual(decision.recommended_action, "BLOCK_FOR_HITL_REVIEW")
        self.assertIn("PENDING HUMAN OPERATOR APPROVAL", decision.release_certificate_markdown)

    def test_rejected_when_adherence_below_threshold(self):
        """Verifies release is rejected on a missed directive (JUDGE-GATE-ENUMERATED-FINDINGS: the listed finding is the
        reason, the 0.85 score is informational)."""
        determ = {"passed": True}
        sec = {"passed": True, "critical_vulnerabilities": []}
        adh = {
            "passed": False,
            "instruction_adherence_score": 0.85,
            "missed_directives": ["Omitted required VPC Connector in main.tf"],
        }
        policy = {"require_human_code_review": False, "auto_merge": True}

        decision = evaluate_release_decision(
            determ_report=determ,
            sec_report=sec,
            adh_report=adh,
            workload_policy=policy,
            product_id="test-product",
            branch_name="feature/billing",
        )

        self.assertFalse(decision.is_approved)
        self.assertEqual(decision.recommended_action, "AUTO_REJECT")
        self.assertEqual(decision.blocking_reasons, ["Missed Directive: Omitted required VPC Connector in main.tf"])
        self.assertIn("REJECTED BY RELEASE GATEKEEPER", decision.release_certificate_markdown)

    def test_multi_vcs_post_comment_resilience(self):
        """Verifies post_release_certificate_to_vcs handles VCSProvider safely."""
        with patch("release_gatekeeper.VCSProviderFactory") as mock_factory:
            mock_provider = MagicMock()
            mock_factory.get_provider.return_value = mock_provider

            res = post_release_certificate_to_vcs(
                full_repo_name="org/repo",
                pr_number=42,
                markdown_content="## Release Certificate",
                product_id="test-prod",
            )
            self.assertTrue(res)
            mock_provider.post_pull_request_comment.assert_called_once_with(
                "org/repo", 42, "## Release Certificate"
            )


if __name__ == "__main__":
    unittest.main()
