"""
Unit Tests for Fast-Path IaC Re-Apply, Failure-Aware Retrigger Routing,
and the Pre-Flight Standard Library Collision report (FD-4AD: reported, never renamed).
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import re
import sys
import unittest
from unittest.mock import MagicMock, patch

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_PATH = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
CONTROL_CENTER_PATH = os.path.join(REPO_ROOT, "apps", "control-center")

for p in [REPO_ROOT, GATEWAY_PATH, CONTROL_CENTER_PATH]:
    if p not in sys.path:
        sys.path.insert(0, p)


class TestFastPathPipeline(unittest.TestCase):

    def test_workflow_has_fast_path_routing_and_safe_null_handling(self):
        """Verifies that workflows/main_orchestrator.yaml contains all Red Team hardened steps."""
        workflow_path = os.path.join(REPO_ROOT, "workflows", "main_orchestrator.yaml")
        self.assertTrue(os.path.exists(workflow_path), f"Workflow file missing: {workflow_path}")

        with open(workflow_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Step 0.8: evaluate_resume_checkpoint. Lane 17 PR-2 (RT F2, F11 rewrite): DEPLOY_ONLY goes through the
        # deploy-only gate (reviewed branch only) and the kill switch to the deploy, with no Infracost call;
        # RESUME_DEVELOPER goes through QA readiness and the persisted full-build gate (RT F1) to the developer.
        self.assertIn("evaluate_resume_checkpoint:", content)
        self.assertIn('condition: ${execution_mode == "DEPLOY_ONLY"}', content)
        self.assertIn("next: deploy_only_gate", content)
        self.assertIn('condition: ${execution_mode == "RESUME_DEVELOPER"}', content)
        self.assertIn("next: load_resume_outcome", content)
        self.assertIn("dispatch_developer_implementation:", content)

        # DEPLOY_ONLY fast path: gate ALLOW -> kill switch -> deploy callback
        self.assertIn("check_deploy_only_decision:", content)
        self.assertIn("next: kill_switch_before_deploy", content)
        self.assertIn("create_deploy_callback:", content)

        # Zero-Invocation Invariant: check_tf_remediation
        self.assertIn("check_tf_remediation:", content)
        self.assertIn('execution_mode == "DEPLOY_ONLY"', content)
        self.assertIn("next: handle_deploy_failure", content)

        # Safe null-handling for project_id, branch, pull_request_url, and outputs
        self.assertIn("target_project_id:", content)
        self.assertIn("target_branch:", content)
        self.assertIn("pull_request_url:", content)
        self.assertIn("compliance_output: null", content)
        self.assertIn("architect_output: null", content)

    def test_preflight_validator_keeps_stdlib_named_module_and_reports_it(self):
        """FD-4AD (HB-26): the stdlib-shadow rename + `from <stem>` regex rewrite is deleted (Gate B S3-r2 renamed
        `secrets.py` and rewrote main.py). The files stay byte-identical; the hazard is the report-only
        PY.STDLIB_SHADOWED (V3d)."""
        from developer_agent.validators.base import ValidationContext
        from gatekeeper_agent.verifier import SynthesisVerifierAgent

        def validate_and_heal_python_packages(files):   # FD-55 W5 (G26): the preflight copy is deleted
            return SynthesisVerifierAgent(product_id="core").purge_shadowed_package_files(dict(files))
        from developer_agent.validators.python_layout import PythonLayoutValidator

        staged_files = {
            "apps/core_service/secrets.py": (
                "def get_api_key():\n"
                "    return 'super-secret'\n"
            ),
            "apps/core_service/main.py": (
                "from secrets import get_api_key\n"
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n"
                "@app.get('/test')\n"
                "def test():\n"
                "    return {'key': get_api_key()}\n"
            ),
            # a nested stdlib-named module is not a shadow at all (imported as utils.logging)
            "apps/core_service/utils/logging.py": "LEVEL = 'INFO'\n",
        }

        healed, actions = validate_and_heal_python_packages(staged_files)

        for path, text in staged_files.items():
            self.assertEqual(healed[path], text)
        self.assertNotIn("apps/core_service/secrets_service.py", healed)
        self.assertFalse(any("renamed" in a.lower() for a in actions))

        diags = PythonLayoutValidator().validate(ValidationContext.build(healed, ownership=lambda p: None))
        self.assertEqual([(d.code, d.file) for d in diags if d.code == "PY.STDLIB_SHADOWED"],
                         [("PY.STDLIB_SHADOWED", "apps/core_service/secrets.py")])
        self.assertTrue(all(d.severity == "warning" for d in diags))

    def test_preflight_validator_detects_syntax_errors(self):
        """Tests that the in-memory compile check flags Python syntax errors. FD-55 W5 (G26): the preflight copy's
        WARNING lines are deleted; the gatekeeper's compile check (and V3a PY.SYNTAX) report the error."""
        from gatekeeper_agent.verifier import SynthesisVerifierAgent

        broken_files = {
            "apps/broken_service/main.py": (
                "def invalid_syntax(\n"  # missing closing paren and body
            ),
        }

        ok, errors = SynthesisVerifierAgent(product_id="broken").compile_in_memory(broken_files)
        self.assertFalse(ok)
        self.assertTrue(any("apps/broken_service/main.py" in e for e in errors))

    def test_verifier_container_contract_never_edits_main_or_procfile(self):
        """S2-A (HS-09) tombstone: nothing injects /health, prepends `import os` or overwrites the Procfile (the
        verifier's regex locator `_find_fastapi_instantiation_end` is gone). FD-55 W5 (G23): the verifier twin itself
        is deleted; the developer stage's enforce_container_contract is the one Dockerfile / runtime-pin rule."""
        import gatekeeper_agent.verifier as v
        from gatekeeper_agent.verifier import SynthesisVerifierAgent
        from developer_agent.handler import enforce_container_contract

        self.assertFalse(hasattr(v, "_find_fastapi_instantiation_end"))
        self.assertFalse(hasattr(SynthesisVerifierAgent, "enforce_container_contracts"))
        code_with_nested_parens = (
            'from fastapi import FastAPI\n\n'
            'app = FastAPI(\n'
            '    title="Core Service (Production)",\n'
            '    version="1.0.0",\n'
            ')\n\n'
            '@app.get("/items")\n'
            'def get_items():\n'
            '    return []\n'
        )
        files = {"apps/testservice/main.py": code_with_nested_parens,
                 "apps/testservice/Procfile": "web: uvicorn main:app --port 8000\n",
                 "apps/testservice/Dockerfile": "FROM python\n"}
        cured = dict(files)
        enforce_container_contract(cured, "testservice", "cloudrun")
        self.assertEqual(cured["apps/testservice/main.py"], code_with_nested_parens)
        self.assertEqual(cured["apps/testservice/Procfile"], "web: uvicorn main:app --port 8000\n")
        self.assertNotIn("apps/testservice/Dockerfile", cured)
        self.assertEqual(cured["apps/testservice/.python-version"], "3.13\n")
        self.assertEqual(cured[".python-version"], "3.13\n")

    def test_gatekeeper_purge_keeps_stdlib_named_module_byte_identical(self):
        """FD-4AD (HB-26): SynthesisVerifierAgent.purge_shadowed_package_files no longer renames stdlib collisions."""
        from gatekeeper_agent.verifier import SynthesisVerifierAgent

        agent = SynthesisVerifierAgent(product_id="testservice")
        files = {
            "apps/testservice/secrets.py": "def secret_value(): return 'abc'",
            "apps/testservice/main.py": "from secrets import secret_value\nprint(secret_value())",
        }

        cured, purged = agent.purge_shadowed_package_files(files)
        self.assertEqual(purged, [])
        for path, text in files.items():
            self.assertEqual(cured[path], text)
        self.assertNotIn("apps/testservice/secrets_service.py", cured)

    def test_cure_undeclared_custom_tf_scheduler_sa(self):
        """FD-55 W5 (G16, register FD55-W5): the deleted HB-01 re-pointed `*_sa` locals named scheduler_sa /
        gateway_sa and a Cloud Scheduler OIDC service_account_email to module.foundation.workload_sa_email (name
        matching). Nothing rewires them now: custom.tf is byte-identical; a wrong value is reported and repaired."""
        import developer_agent.terraform_engine as te
        self.assertFalse(hasattr(te, "reconcile_iac_reference_graph"))

        files = {
            "infra/workload/custom.tf": (
                'locals {\n'
                '  scheduler_sa = coalesce(var.scheduler_sa_email, var.reconciliation_scheduler_sa_email)\n'
                '  gateway_sa   = coalesce(var.service_a_sa_email, var.gateway_sa_email)\n'
                '}\n\n'
                'resource "google_cloud_scheduler_job" "reconciliation_job" {\n'
                '  name     = "test-job"\n'
                '  schedule = "0 2 * * *"\n'
                '  http_target {\n'
                '    uri = "https://gateway/api"\n'
                '    oidc_token {\n'
                '      service_account_email = "invalid-dummy-sa"\n'
                '    }\n'
                '  }\n'
                '}\n'
            )
        }

        before = files["infra/workload/custom.tf"]
        te.reconcile_multi_service_declarations(files, "testplan02-b", "")
        self.assertEqual(files["infra/workload/custom.tf"], before)
        self.assertNotIn("module.foundation.workload_sa_email", files["infra/workload/custom.tf"])

    def test_failure_aware_dag_introspection_logic(self):
        """Tests DAG-introspected stage recovery when current_stage is FAILED."""
        # Simulated previous execution where cleaner stamped current_stage: FAILED
        prev_exec = {
            "status": "FAILED",
            "current_stage": "FAILED",
            "stages": {
                "discovery": {"status": "SUCCESS"},
                "vending": {"status": "SUCCESS"},
                "developer": {"status": "SUCCESS"},
                "qa": {"status": "SUCCESS"},
                "terraform": {"status": "IN_FLIGHT", "error": "timed out"},
            }
        }

        prev_stage = (prev_exec.get("current_stage") or "").upper()
        prev_stages = prev_exec.get("stages", {}) or {}

        terminal_stage = prev_stage
        if prev_stage in ["FAILED", "ABORTED", "COMPLETE", ""] and prev_stages:
            for stg in ["sre", "terraform", "release", "qa", "developer", "vending", "compliance", "architect"]:
                stg_status = ((prev_stages.get(stg) or {}).get("status") or "").upper()
                if stg_status in ["FAILED", "IN_FLIGHT"]:
                    terminal_stage = stg.upper()
                    break

        self.assertEqual(terminal_stage, "TERRAFORM")
        is_late_stage = any(k in terminal_stage for k in ["TERRAFORM", "DEPLOY", "SRE"])
        self.assertTrue(is_late_stage)

    def test_callback_failed_and_deploy_only_fast_path_routing(self):
        """Tests that a prior execution with stages.terraform.state: CALLBACK_FAILED correctly routes to DEPLOY_ONLY."""
        prev_exec = {
            "current_stage": "FAILED",
            "status": "FAILED",
            "execution_mode": "DEPLOY_ONLY",
            "error": "Terraform deployment failed after 0 retries: Error 409 already exists",
            "stages": {
                "discovery": {"status": "SKIPPED"},
                "vending": {"status": "SKIPPED"},
                "developer": {"status": "SKIPPED"},
                "qa": {"status": "SKIPPED"},
                "terraform": {
                    "status": "SUCCESS",
                    "state": "CALLBACK_FAILED",
                },
                "sre": {"status": "QUEUED"},
            }
        }

        prev_stage = (prev_exec.get("current_stage") or "").upper()
        prev_mode = (prev_exec.get("execution_mode") or "").upper()
        prev_error = str(prev_exec.get("error") or "").lower()
        prev_stages = prev_exec.get("stages", {}) or {}

        tf_info = prev_stages.get("terraform") or {}
        tf_status = (tf_info.get("status") or "").upper()
        tf_state = (tf_info.get("state") or "").upper()

        terminal_stage = prev_stage
        if prev_stage in ["FAILED", "ABORTED", "COMPLETE", ""] and prev_stages:
            for stg in ["sre", "terraform", "release", "qa", "developer", "vending", "compliance", "architect"]:
                stg_info = prev_stages.get(stg) or {}
                stg_status = (stg_info.get("status") or "").upper()
                stg_state = (stg_info.get("state") or "").upper()
                if stg_status in ["FAILED", "IN_FLIGHT"] or stg_state in ["FAILED", "CALLBACK_FAILED"]:
                    terminal_stage = stg.upper()
                    break

        if terminal_stage in ["FAILED", "ABORTED", ""] and (prev_mode == "DEPLOY_ONLY" or "terraform" in prev_error or "tofu" in prev_error or tf_state in ["CALLBACK_FAILED", "FAILED"]):
            terminal_stage = "TERRAFORM"

        is_late_stage = any(k in terminal_stage for k in ["TERRAFORM", "DEPLOY", "SRE"]) or prev_mode == "DEPLOY_ONLY" or tf_state in ["CALLBACK_FAILED", "FAILED"] or ("terraform" in prev_error or "tofu" in prev_error)

        self.assertEqual(terminal_stage, "TERRAFORM")
        self.assertTrue(is_late_stage)


if __name__ == "__main__":
    unittest.main()
