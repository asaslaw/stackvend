"""
Project Castor: Unit Tests for Gatekeeper Hardening & Pipeline Resilience
Tests:
1. Contract Registry line-by-line commenting for multi-line contracts (eliminating bare syntax errors).
2-6. FD-4AD / S2-A tombstones + Do No Harm: hyphenated / monorepo imports, multi-line `with`, bare HTTP routes,
     requirement pruning / pin softening, flat-module purge and the GCE URI cure no longer rewrite valid input; each
     input comes back byte-identical (typed diagnostics report the genuine hazards).
7. Pub/Sub primary topic vs DLQ disambiguation in Deterministic Bridge.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest

# Ensure paths
GATEWAY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "orchestrator-gateway"))
if GATEWAY_DIR not in sys.path:
    sys.path.insert(0, GATEWAY_DIR)

from developer_agent.contract_registry import SharedContractRegistry
import importlib.util
from developer_agent.validators.base import ValidationContext
from developer_agent.validators.python_layout import PythonLayoutValidator
from gatekeeper_agent.verifier import SynthesisVerifierAgent
from developer_agent.terraform_engine import extract_custom_resource_env_vars


class TestGatekeeperHardening(unittest.TestCase):
    """Test suite for anti-hallucination gatekeeper and pipeline hardening."""

    def test_contract_registry_multiline_commenting(self):
        """Verifies that multi-line contract notes are commented on every single line."""
        registry = SharedContractRegistry("testplan01-a")
        shared_contracts = {
            "api_routes": "GET /health -> HealthStatus\nPOST /api/v1/events -> {'status': 'published'}\nPOST /api/v1/tasks/process -> {'status': 'processed'}"
        }
        files = registry.extract_and_generate_contracts(shared_contracts, ["testplan01-a"])
        contract_py = files["contracts/schemas.py"]

        # Ensure no bare unquoted POST statements exist in the file
        for line in contract_py.splitlines():
            stripped = line.strip()
            if stripped.startswith("POST ") or stripped.startswith("GET "):
                self.fail(f"Found bare unquoted REST route in Python code: '{line}'")

        # Ensure every line of the route notes is commented
        self.assertIn("# GET /health -> HealthStatus", contract_py)
        self.assertIn("# POST /api/v1/events -> {'status': 'published'}", contract_py)
        self.assertIn("# POST /api/v1/tasks/process -> {'status': 'processed'}", contract_py)

    @staticmethod
    def _v3d(files):
        return [(d.code, d.file) for d in PythonLayoutValidator().validate(
            ValidationContext.build(files, ownership=lambda p: None))]

    def test_hyphenated_monorepo_imports_are_reported_not_rewritten(self):
        """FD-4AD (HB-31 rest): pre_ast_normalize / ContainerImportTransformer are deleted. A hyphenated
        `apps.<svc-name>` import is a SyntaxError: verify_and_cure returns the file byte-identical and fails with the
        compiler's error (PY.SYNTAX in the developer stage), which the AI repairs."""
        self.assertIsNone(importlib.util.find_spec("gatekeeper_agent.ast_transformer"))  # FD-55 W1 (X9): module deleted
        bad_code = (
            "import os\n"
            "from apps.testplan01-a.models import EventAuditRecord\n"
            "from apps.testplan01-a.schemas.contracts import BaseEventEnvelope\n"
            "\n"
            "def handler(event: EventAuditRecord) -> BaseEventEnvelope:\n"
            "    return BaseEventEnvelope(event_id=event.event_id, event_type='test')\n"
        )
        files = {"apps/testplan01-a/main.py": bad_code}
        cured, passed, errors = SynthesisVerifierAgent("testplan01-a").verify_and_cure(dict(files),
                                                                                       product_id="testplan01-a")
        self.assertFalse(passed)
        self.assertEqual(cured["apps/testplan01-a/main.py"], bad_code)
        self.assertTrue(any("apps/testplan01-a/main.py" in e for e in errors))

    def test_multiline_with_and_bare_http_routes_are_left_for_repair(self):
        """S2-A (HS-13) / FD-4AD tombstones: no syntax healer or import normalizer remains; both inputs come back
        byte-identical through verify_and_cure (PY.SYNTAX reports them)."""
        self.assertIsNone(importlib.util.find_spec("gatekeeper_agent.ast_transformer"))  # FD-55 W1 (X9): module deleted
        unparenthesized = (
            "def test_clients():\n"
            "    with patch('google.cloud.pubsub_v1.PublisherClient') as mock_pubsub,\n"
            "         patch('google.cloud.storage.Client') as mock_storage:\n"
            "        pass\n"
        )
        raw_routes = (
            "# Route signatures\n"
            "POST /api/v1/events -> {'status': 'published', 'message_id': str}\n"
            "GET /health -> {'status': 'healthy'}\n"
        )
        files = {"apps/svc/tests/test_clients.py": unparenthesized, "apps/svc/routes.py": raw_routes}
        cured, passed, _ = SynthesisVerifierAgent("svc").verify_and_cure(dict(files), product_id="svc")
        self.assertFalse(passed)
        for path, text in files.items():
            self.assertEqual(cured[path], text)

    def test_valid_decorators_and_multi_item_with_are_byte_identical_through_verify_and_cure(self):
        """Do-No-Harm (HS-13): a valid FastAPI app with decorators and a parenthesized multi-item `with` passes
        verify_and_cure unchanged."""
        main = (
            "from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get('/health')\ndef health():\n"
            "    with (open(__file__) as a,\n          open(__file__) as b):\n        return {'ok': bool(a and b)}\n"
        )
        files = {"apps/svc/main.py": main, "apps/svc/requirements.txt": "fastapi>=0.110.0\n"}
        cured, passed, errors = SynthesisVerifierAgent("svc").verify_and_cure(dict(files), product_id="svc")
        self.assertTrue(passed, errors)
        self.assertEqual(cured["apps/svc/main.py"], main)

    def test_syntax_broken_file_is_byte_identical_with_or_without_monorepo_imports(self):
        """RT F7 path: a syntax-broken file goes through verify_and_cure unchanged. FD-4AD: one with an `apps.<svc>.`
        import is unchanged too (the HB-31 import-line rewrite is deleted)."""
        broken = "from fastapi import FastAPI\napp = FastAPI()\n\n@app.get('/x')\ndef x(:\n    return 1\n"
        for text in (broken, "from apps.svc.models import M\n" + broken):
            cured, passed, _ = SynthesisVerifierAgent("svc").verify_and_cure({"apps/svc/main.py": text},
                                                                             product_id="svc")
            self.assertFalse(passed)
            self.assertEqual(cured["apps/svc/main.py"], text)

    def test_requirements_are_never_pruned_or_softened(self):
        """FD-4AD (HB-28) Do No Harm: lines naming `contracts` / `schemas` / `tests` and exact Google SDK pins are the
        AI's; a requirements.txt that already names every proven need (fastapi) is returned byte-identical."""
        verifier = SynthesisVerifierAgent("testplan01-a")
        reqs = (
            "fastapi>=0.110.0\n"
            "contracts\n"
            "schemas\n"
            "tests\n"
            "google-cloud-pubsub==2.28.1\n"
            "google-cloud-storage==2.19.0\n"
        )
        files = {
            "apps/testplan01-a/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "apps/testplan01-a/requirements.txt": reqs,
        }
        reconciled = verifier.reconcile_service_requirements(dict(files))
        self.assertEqual(reconciled, files)

    def test_requirements_keep_user_pins_beside_a_needed_distribution(self):
        """FD-4AD (HB-28): a user `pydantic==1.10.13` is never joined by a conflicting `pydantic>=2.6.0`, and no base
        pins (pytest, jinja2, ...) are prepended; only an AST-proven missing distribution is appended."""
        reqs = "pydantic==1.10.13\n# pinned on purpose\nfastapi==0.99.1"   # no trailing newline
        files = {
            "apps/api/main.py": "from fastapi import FastAPI\nfrom pydantic import BaseModel\nimport yaml\napp = FastAPI()\n",
            "apps/api/requirements.txt": reqs,
        }
        out = SynthesisVerifierAgent("api").reconcile_service_requirements(dict(files))
        self.assertEqual(out["apps/api/requirements.txt"], reqs + "\nPyYAML>=6.0.1\n")
        self.assertEqual(out["apps/api/main.py"], files["apps/api/main.py"])

    def test_pubsub_topic_disambiguation_prioritizes_inbound_over_dlq(self):
        """Verifies that primary topic (not dlq) is wired as PUBSUB_TOPIC_ID when both exist."""
        custom_tf = """
resource "google_pubsub_topic" "dlq" {
  name    = "${var.topic_name}-dlq"
  project = var.project_id
}

resource "google_pubsub_topic" "inbound" {
  name    = var.topic_name
  project = var.project_id
}

resource "google_storage_bucket" "raw_events" {
  name    = "${var.project_id}-raw-events-store"
  project = var.project_id
}
"""
        env_vars = extract_custom_resource_env_vars(custom_tf)

        # Primary topic MUST be inbound, not dlq!
        self.assertEqual(env_vars["PUBSUB_TOPIC_ID"], "google_pubsub_topic.inbound.name")
        # DLQ topic MUST be wired separately
        self.assertEqual(env_vars["PUBSUB_DLQ_TOPIC_ID"], "google_pubsub_topic.dlq.name")
        # Bucket must be wired
        self.assertEqual(env_vars["GCS_BUCKET_NAME"], "google_storage_bucket.raw_events.name")

    def test_try_fallback_pseudo_labels_are_left_for_repair(self):
        """S2-A (HS-13) tombstone: `heal_try_fallback_labels` is gone (and FD-4AD removed pre_ast_normalize)."""
        self.assertIsNone(importlib.util.find_spec("gatekeeper_agent.ast_transformer"))  # FD-55 W1 (X9): module deleted

    def test_try_fallback_workload_is_reported_not_cured(self):
        """S2-A (HS-13) tombstone: the PR #17 shape (pseudo-label `try_fallback:`) is no longer cured between repair
        iterations; verify_and_cure leaves the file's syntax as written and fails with the compiler's error, which the
        developer stage reports as PY.SYNTAX for the AI to repair."""
        verifier = SynthesisVerifierAgent("testplan01-a")
        main = """
import sys
from fastapi import FastAPI

try:
    from .routers import router
try_fallback:
    pass
except ImportError:
    from routers import router

app = FastAPI()
app.include_router(router)
"""
        files = {"apps/testplan01-a/main.py": main,
                 "apps/testplan01-a/requirements.txt": "fastapi>=0.110.0\nuvicorn>=0.28.0\n"}
        cured, passed, errors = verifier.verify_and_cure(files, product_id="testplan01-a")
        self.assertFalse(passed)
        self.assertIn("try_fallback:", cured["apps/testplan01-a/main.py"])
        self.assertEqual(cured["apps/testplan01-a/main.py"], main)
        self.assertTrue(any("apps/testplan01-a/main.py" in e for e in errors))

    def test_purge_shadowed_package_files_is_add_only(self):
        """FD-4AD (HB-27): flat modules beside a package dir are never deleted any more; only missing `__init__.py`
        files are added, every input stays byte-identical, and V3d reports the conflict (report-only)."""
        verifier = SynthesisVerifierAgent("testplan01-a")
        files = {
            "apps/testplan01-a/main.py": "from routers.events import router\n",
            "apps/testplan01-a/routers.py": "from fastapi import APIRouter\nrouter = APIRouter()\n",
            "apps/testplan01-a/routers/events.py": "from fastapi import APIRouter\nrouter = APIRouter()\n",
            "apps/testplan01-a/routers/tasks.py": "from fastapi import APIRouter\nrouter = APIRouter()\n",
            "apps/testplan01-a/services.py": "class LegacyService: pass\n",
            "apps/testplan01-a/services/pubsub.py": "class PubSubService: pass\n",
            "apps/testplan01-a/config.py": "ENV = 'production'\n",
        }

        cured, purged = verifier.purge_shadowed_package_files(dict(files))

        self.assertEqual(purged, [])
        for path, text in files.items():
            self.assertEqual(cured[path], text, path)
        self.assertEqual(sorted(set(cured) - set(files)), [
            "apps/__init__.py", "apps/testplan01-a/__init__.py", "apps/testplan01-a/routers/__init__.py",
            "apps/testplan01-a/services/__init__.py"])
        self.assertEqual(sorted(c for c in self._v3d(cured) if c[0] == "PY.MODULE_PACKAGE_CONFLICT"), [
            ("PY.MODULE_PACKAGE_CONFLICT", "apps/testplan01-a/routers.py"),
            ("PY.MODULE_PACKAGE_CONFLICT", "apps/testplan01-a/services.py")])

    def test_purge_shadowed_package_files_pure_additive_policy(self):
        """No Git deletions and (FD-4AD) no in-memory drops either: the flat file stays, the package init is added."""
        verifier = SynthesisVerifierAgent("testplan01-a")
        files = {
            "apps/testplan01-a/main.py": "from routers.events import router\n",
            "apps/testplan01-a/routers.py": "# Flat shadowed file\n",
            "apps/testplan01-a/routers/events.py": "from fastapi import APIRouter\nrouter = APIRouter()\n",
        }
        existing_paths = [
            "apps/testplan01-a/routers.py",
            "apps/testplan01-a/services.py",
            "apps/testplan01-a/README.md",
        ]
        cured, purged = verifier.purge_shadowed_package_files(files, existing_paths=existing_paths)
        self.assertEqual(cured["apps/testplan01-a/routers.py"], "# Flat shadowed file\n")
        self.assertIn("apps/testplan01-a/routers/__init__.py", cured)
        self.assertEqual(purged, [])

    def test_purge_shadowed_package_files_preserves_human_code_pure_additive(self):
        """Verifies that existing human-authored code in brownfield repo is untouched (never deleted)."""
        verifier = SynthesisVerifierAgent("testplan01-a")
        files = {
            "apps/testplan01-a/main.py": "from routers.events import router\n",
            "apps/testplan01-a/routers/events.py": "from fastapi import APIRouter\nrouter = APIRouter()\n",
        }
        existing_paths = ["apps/testplan01-a/routers.py"]
        cured, purged = verifier.purge_shadowed_package_files(
            files,
            existing_paths=existing_paths,
        )
        # Package init created for disambiguation
        self.assertIn("apps/testplan01-a/routers/__init__.py", cured)
        # No Git deletion requested
        self.assertEqual(purged, [])

    def test_canonical_pypi_catalog_compute_and_extended_sdks(self):
        """Verifies that Google Cloud Compute, Run, AI Platform, and Kubernetes SDKs resolve from imports."""
        from gatekeeper_agent.pypi_catalog import resolve_import_to_pypi
        self.assertEqual(resolve_import_to_pypi("google.cloud.compute"), "google-cloud-compute>=1.18.0")
        self.assertEqual(resolve_import_to_pypi("google.cloud.compute_v1"), "google-cloud-compute>=1.18.0")
        self.assertEqual(resolve_import_to_pypi("google.cloud.run_v2"), "google-cloud-run>=0.10.0")
        self.assertEqual(resolve_import_to_pypi("google.cloud.aiplatform"), "google-cloud-aiplatform>=1.42.0")
        self.assertEqual(resolve_import_to_pypi("google.cloud.discoveryengine"), "google-cloud-discoveryengine>=0.11.0")
        self.assertEqual(resolve_import_to_pypi("kubernetes"), "kubernetes>=29.0.0")

    def test_gatekeeper_adds_compute_dependency_to_the_importing_service_only(self):
        """An import 'from google.cloud import compute_v1' appends google-cloud-compute to that service's
        requirements.txt (AST + closed-world catalog). FD-4AD: the root requirements.txt is no longer rewritten or
        mirrored (byte-identical)."""
        verifier = SynthesisVerifierAgent("testplan03-a")
        files = {
            "apps/testplan03-a/main.py": "from routers.jobs import router\n",
            "apps/testplan03-a/routers/jobs.py": "from google.cloud import compute_v1\nclient = compute_v1.InstancesClient()\n",
            "apps/testplan03-a/requirements.txt": "fastapi>=0.110.0\nuvicorn[standard]>=0.28.0\n",
            "requirements.txt": "fastapi>=0.110.0\n",
        }
        cured_files = verifier.reconcile_service_requirements(dict(files))
        self.assertEqual(cured_files["apps/testplan03-a/requirements.txt"],
                         files["apps/testplan03-a/requirements.txt"] + "google-cloud-compute>=1.18.0\n")
        self.assertEqual(cured_files["requirements.txt"], files["requirements.txt"])

    def test_preflight_validator_no_longer_mirrors_root_sdks(self):
        """FD-4AD (HB-33): root google-cloud-* lines are not copied into a service that does not import them."""
        # FD-55 W5 (G28): the preflight copy is deleted; the add-only contract itself is the one rule
        from gatekeeper_agent.requirements_contract import (
            append_missing_requirements as validate_and_heal_python_requirements)
        files = {
            "apps/testplan03-a/main.py": "print('hello')\n",
            "apps/testplan03-a/requirements.txt": "fastapi>=0.110.0\n",
            "requirements.txt": "fastapi>=0.110.0\ngoogle-cloud-compute>=1.18.0\n",
        }
        healed, actions = validate_and_heal_python_requirements(dict(files))
        self.assertEqual(healed, files)
        self.assertEqual(actions, [])

    def test_gce_resource_uri_cure_is_deleted_and_code_is_byte_identical(self):
        """FD-4AD (HB-30): the cure rewrote bare `global/networks/...` literals into an f-string with an undefined
        `{project_id}` (NameError at run time). It is deleted; verify_and_cure returns the file byte-identical."""
        self.assertFalse(hasattr(SynthesisVerifierAgent, "cure_gce_resource_uris"))
        code = '''
from google.cloud import compute_v1

def build_instance(zone: str, net: str):
    network_interface = compute_v1.NetworkInterface()
    network_interface.network = net if "/" in net else f"global/networks/{net}"
    legacy_net = "global/networks/default"
    legacy_sub = "regions/us-central1/subnetworks/default-sub"
    return network_interface, legacy_net, legacy_sub
'''
        files = {"apps/testplan03-a/services/compute_service.py": code,
                 "apps/testplan03-a/requirements.txt": "google-cloud-compute>=1.18.0\n"}
        cured, passed, errors = SynthesisVerifierAgent("testplan03-a").verify_and_cure(dict(files),
                                                                                       product_id="testplan03-a")
        self.assertTrue(passed, errors)
        self.assertEqual(cured["apps/testplan03-a/services/compute_service.py"], code)
        self.assertEqual(cured["apps/testplan03-a/requirements.txt"], files["apps/testplan03-a/requirements.txt"])

    def test_developer_execute_request_accepts_null_task_dag(self):
        """Verifies DeveloperExecuteRequest AST declares task_dag as Optional with default_factory=list."""
        main_py_path = os.path.join(GATEWAY_DIR, "main.py")
        with open(main_py_path, "r", encoding="utf-8") as f:
            code = f.read()

        import ast
        tree = ast.parse(code)
        found_class = False
        task_dag_is_optional = False

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "DeveloperExecuteRequest":
                found_class = True
                for stmt in node.body:
                    if isinstance(stmt, ast.AnnAssign) and getattr(stmt.target, "id", None) == "task_dag":
                        ann_str = ast.unparse(stmt.annotation)
                        self.assertIn("Optional", ann_str)
                        val_str = ast.unparse(stmt.value) if stmt.value else ""
                        self.assertIn("default_factory=list", val_str)
                        task_dag_is_optional = True

        self.assertTrue(found_class, "DeveloperExecuteRequest class not found in main.py")
        self.assertTrue(task_dag_is_optional, "task_dag in DeveloperExecuteRequest must be Optional with default_factory=list")

        # Runtime model instantiation. Self-contained: the gateway is loaded by path through the shared hermetic
        # loader (real web stack, no project env, so no Gemini / Firestore client is built at import), not through a
        # `main` module some earlier test may or may not have imported already.
        import pytest
        from fd4f_support import load_gateway

        with pytest.MonkeyPatch.context() as mp:
            gateway = load_gateway(mp, name="gatekeeper_hardening_gw_main")
            req1 = gateway.DeveloperExecuteRequest(product_id="testplan03-a", task_dag=None)
            self.assertEqual(req1.task_dag, [])


if __name__ == "__main__":
    unittest.main()

