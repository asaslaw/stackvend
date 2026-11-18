"""
Unit Tests for Anti-Hallucination via Constrained Generation & In-Loop Pre-Flight Validation.
Tests coverage:
1. contract_inspector:
   - get_golden_module_contract extracts declared variables and outputs from infra/modules/compute-cloudrun
   - get_all_active_module_contracts extracts core module contracts
2. schemas:
   - parse_iac_spec correctly deserializes WorkloadIaCSpec, AdditionalServiceSpec, StorageBucketSpec, PubSubTopicSpec
3. preflight_validator: the add-only Python contracts, k8s placeholder hydration and the remaining (W1) dead bodies.
   FD-55 W4 (register FD55-W4) deleted the HD-15 regex pre-flight, self_correct_hcl and the generation-time HCL
   rewriters (naming, timeouts, duplicate GKE cluster, WI bindings, self-references) with their cases here; the
   typed replacements are tested with their validators (tests/test_fd55_w4_name_check.py, test_step2b_hcl_chain.py).
4. DeveloperAgent integration:
   - generate_code_files incorporates build_developer_system_prompt
   - generate_code_files executes pre-flight validation
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_PATH = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
if GATEWAY_PATH not in sys.path:
    sys.path.insert(0, GATEWAY_PATH)
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

from developer_agent.contract_inspector import (
    get_golden_module_contract,
    get_all_active_module_contracts,
)
from developer_agent.schemas import (
    WorkloadIaCSpec,
    AdditionalServiceSpec,
    StorageBucketSpec,
    PubSubTopicSpec,
    parse_iac_spec,
)
from developer_agent.preflight_validator import (
    hydrate_kubernetes_manifests,
)
# FD-55 W5 (G26 / G28): the preflight copies of the add-only package / requirements contracts are deleted; these cases
# now exercise the one remaining rule of each (the gatekeeper's, run on every assembled tree).
from gatekeeper_agent.requirements_contract import append_missing_requirements as validate_and_heal_python_requirements
from gatekeeper_agent.verifier import SynthesisVerifierAgent as _GatekeeperForPackages


def validate_and_heal_python_packages(files):
    return _GatekeeperForPackages(product_id="testplan01-a").purge_shadowed_package_files(dict(files))
from developer_agent.terraform_engine import (
    generate_golden_main_tf,
    generate_golden_variables_tf,
)
from developer_agent.prompt import build_developer_system_prompt
from developer_agent.handler import DeveloperAgent, generate_service_workflow


class TestContractInspector(unittest.TestCase):
    """Verifies dynamic contract inspection from infra/modules."""

    def test_get_golden_module_contract_compute_cloudrun(self):
        contract = get_golden_module_contract("compute-cloudrun")
        self.assertIn("### Golden Module Contract: `compute-cloudrun`", contract)
        self.assertIn("Allowed Inputs", contract)
        self.assertIn("Allowed Outputs", contract)
        self.assertIn("module.<name>.service_uri", contract)
        self.assertIn("module.<name>.service_name", contract)
        self.assertIn("project_id", contract)

    def test_get_all_active_module_contracts(self):
        contracts = get_all_active_module_contracts()
        self.assertIn("compute-cloudrun", contracts)
        self.assertIn("workload-foundation/base", contracts)

    def test_build_developer_system_prompt_injects_contracts(self):
        prompt = build_developer_system_prompt()
        self.assertIn("DYNAMIC GOLDEN MODULE CONTRACTS", prompt)
        self.assertIn("compute-cloudrun", prompt)


class TestIaCSchemas(unittest.TestCase):
    """Verifies typed Pydantic WorkloadIaCSpec parsing."""

    def test_parse_iac_spec_valid(self):
        raw_data = {
            "compute_archetype": "cloudrun",
            "additional_services": [
                {
                    "name": "red",
                    "relative_path": "apps/red",
                    "allow_unauthenticated": False,
                    "enable_direct_iap": True,
                    "authorized_invoker_members": ["user:dev@example.com"],
                }
            ],
            "storage_buckets": [
                {"name_suffix": "uploads", "versioning_enabled": True}
            ],
            "pubsub_topics": [
                {"topic_name": "events", "enable_dead_letter": True}
            ]
        }
        spec = parse_iac_spec(raw_data)
        self.assertEqual(spec.compute_archetype, "cloudrun")
        self.assertEqual(len(spec.additional_services), 1)
        self.assertEqual(spec.additional_services[0].name, "red")
        self.assertTrue(spec.additional_services[0].enable_direct_iap)
        self.assertEqual(len(spec.storage_buckets), 1)
        self.assertEqual(spec.storage_buckets[0].name_suffix, "uploads")
        self.assertEqual(len(spec.pubsub_topics), 1)
        self.assertEqual(spec.pubsub_topics[0].topic_name, "events")

    def test_parse_iac_spec_empty_or_invalid(self):
        spec = parse_iac_spec(None)
        self.assertEqual(spec.compute_archetype, "cloudrun")
        self.assertEqual(len(spec.additional_services), 0)


class TestDeveloperAgentPreflightIntegration(unittest.TestCase):
    """Verifies that DeveloperAgent.generate_code_files passes preflight gate."""

    def setUp(self):
        # Lane 19 L19-3b (owner register row 27a): the template fallback is deleted, so the LLM seam is faked with
        # a canned workload that includes LLM-written infra/workload/custom.tf; the preflight gate must still pass.
        from _lane19_fake_genai import FakeGenaiClient, canned_workload_files
        self.agent = DeveloperAgent()
        self.agent.genai_client = FakeGenaiClient(files=canned_workload_files("preflighttest", extra={
            "infra/workload/custom.tf": (
                'resource "google_storage_bucket" "uploads" {\n'
                '  project                     = var.project_id\n'
                '  name                        = "${var.project_id}-uploads"\n'
                '  location                    = var.region\n'
                '  uniform_bucket_level_access = true\n'
                '}\n'
            ),
        }))

    def test_generate_code_files_passes_preflight_cleanly(self):
        with patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false"}), \
                patch.object(self.agent, "fetch_existing_repo_files", return_value={}):
            files = self.agent.generate_code_files(
                product_id="preflighttest",
                spec_text="simple internal web service with direct iap",
                task_dag=[], allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False
            )
            # FD-55 W4: the regex HCL pre-flight is deleted (V1b judges the tree); the requirements contract stays
            # FD-4AD (HB-28 deleted): the AI's requirements.txt is kept as written (no base pins such as jinja2 are
            # prepended); the add-only contract appends only AST-proven needs, so the canned file is a byte prefix.
            from _lane19_fake_genai import canned_workload_files
            canned = canned_workload_files("preflighttest")["apps/preflighttest/requirements.txt"]
            req_content = files.get("apps/preflighttest/requirements.txt", "")
            self.assertTrue(req_content.startswith(canned), req_content)
            self.assertNotIn("jinja2", req_content)


class TestPythonRequirementsPreflightGate(unittest.TestCase):
    """Verifies that missing critical python dependencies are caught and auto-healed in pre-flight."""

    def test_auto_heals_missing_jinja2_when_templates_imported(self):
        files = {
            "apps/myapp/main.py": """
from fastapi import FastAPI
from fastapi.templating import Jinja2Templates
app = FastAPI()
templates = Jinja2Templates(directory="templates")
""",
            "apps/myapp/requirements.txt": """fastapi>=0.110.0
uvicorn[standard]>=0.28.0
pydantic>=2.6.0
""",
        }
        healed, actions = validate_and_heal_python_requirements(files)
        self.assertEqual(len(actions), 1)
        self.assertIn("jinja2>=3.1.5", actions[0])
        self.assertIn("jinja2>=3.1.5", healed["apps/myapp/requirements.txt"])

    def test_auto_heals_missing_multipart_when_form_used(self):
        files = {
            "apps/myapp/main.py": """
from fastapi import FastAPI, Form
app = FastAPI()
@app.post("/login")
def login(username: str = Form(...)):
    return {"user": username}
""",
            "apps/myapp/requirements.txt": "fastapi>=0.110.0\n",
        }
        healed, actions = validate_and_heal_python_requirements(files)
        self.assertEqual(len(actions), 1)
        self.assertIn("python-multipart>=0.0.20", actions[0])
        self.assertIn("python-multipart>=0.0.20", healed["apps/myapp/requirements.txt"])

    def test_hb28_standardize_requirements_is_deleted(self):
        """FD-4AD (HB-28): the base-manifest merge (9 prepended pins, user pins for those names dropped) is gone."""
        import developer_agent.handler as handler_mod
        self.assertFalse(hasattr(handler_mod, "standardize_requirements"))

    def test_substring_triggers_no_longer_inject_requirements(self):
        """FD-4AD (HB-33) Do No Harm: `File` in a comment / an unrelated identifier, `EmailStr` in a string and
        `compute_v1` in a docstring are not imports; the requirements.txt is returned byte-identical."""
        files = {
            "apps/myapp/main.py": (
                '"""Talks to compute_v1 later; EmailStr is documented elsewhere."""\n'
                "from fastapi import FastAPI\n"
                "File = open  # File handle alias\n"
                "app = FastAPI()\n"
                "NOTE = 'uses Jinja2Templates in v2'\n"
            ),
            "apps/myapp/requirements.txt": "fastapi>=0.110.0\n",
        }
        healed, actions = validate_and_heal_python_requirements(dict(files))
        self.assertEqual(healed, files)
        self.assertEqual(actions, [])

    def test_validate_and_heal_python_packages_generates_inits(self):
        files = {
            "apps/testplan01-a/main.py": "from routers.events import router\n",
            "apps/testplan01-a/routers/events.py": "from fastapi import APIRouter\nrouter = APIRouter()\n",
            "apps/testplan01-a/services/worker.py": "class Worker: pass\n",
        }
        healed, actions = validate_and_heal_python_packages(files)
        self.assertIn("apps/testplan01-a/routers/__init__.py", healed)
        self.assertIn("apps/testplan01-a/services/__init__.py", healed)
        self.assertIn("apps/testplan01-a/__init__.py", healed)
        self.assertEqual(actions, [])   # the gatekeeper rule returns no action list (nothing is ever purged)

    def test_validate_and_heal_python_packages_keeps_flat_module_beside_package(self):
        """FD-4AD (HB-27): the flat-module purge is deleted (Gate A 01-r3 lost the AI's schemas.py); only the missing
        package init is added and every input is byte-identical."""
        files = {
            "apps/testplan01-a/main.py": "from routers.events import router\n",
            "apps/testplan01-a/routers.py": "from fastapi import APIRouter\nrouter = APIRouter()\n",
            "apps/testplan01-a/routers/events.py": "from fastapi import APIRouter\nrouter = APIRouter()\n",
        }
        healed, actions = validate_and_heal_python_packages(dict(files))
        for path, text in files.items():
            self.assertEqual(healed[path], text)
        self.assertIn("apps/testplan01-a/routers/__init__.py", healed)
        self.assertFalse(any("purged" in a.lower() for a in actions))

    def test_validate_and_heal_python_packages_no_longer_vendors_root_assets(self):
        """FD-4AD (HB-32): root / apps/shared files are not copied into services (flat copies landed beside a
        same-stem package and replaced the AI's file)."""
        files = {
            "contracts/schemas.py": "class Event: pass\n",
            "scripts/package.json": "{}\n",
            "apps/shared/db.py": "DB = None\n",
            "apps/api/main.py": "import os\n",
            "apps/api/schemas/__init__.py": "",
            "apps/api/schemas/event.py": "class Event: pass\n",
        }
        healed, actions = validate_and_heal_python_packages(dict(files))
        for path, text in files.items():
            self.assertEqual(healed[path], text)
        added = sorted(set(healed) - set(files))
        self.assertTrue(all(p.endswith("/__init__.py") for p in added), added)
        for p in ("apps/api/schemas.py", "apps/api/contracts/schemas.py", "apps/api/package.json", "apps/api/db.py"):
            self.assertNotIn(p, healed)

    def test_hydrate_kubernetes_manifests_placeholders_and_images(self):
        """Verifies k8s manifests have ${PROJECT_ID} hydrated with the real project; concrete images stay (FD-4AF)."""
        deployment_yaml = (
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "metadata:\n"
            "  name: stream-worker\n"
            "spec:\n"
            "  template:\n"
            "    spec:\n"
            "      containers:\n"
            "      - name: worker\n"
            "        image: stream-apps/stream-worker:latest\n"
            "        env:\n"
            "        - name: PROJECT_ID\n"
            "          value: ${PROJECT_ID}\n"
        )
        sa_yaml = (
            "apiVersion: v1\n"
            "kind: ServiceAccount\n"
            "metadata:\n"
            "  name: worker-sa\n"
            "  annotations:\n"
            "    iam.gke.io/gcp-service-account: worker-sa@${PROJECT_ID}.iam.gserviceaccount.com\n"
        )
        files = {
            "k8s/deployment.yaml": deployment_yaml,
            "k8s/serviceaccount.yaml": sa_yaml,
        }
        # FD-4AF: ${PROJECT_ID} is the vended child project (never the product ID); the concrete image is kept.
        healed, actions = hydrate_kubernetes_manifests(files, product_id="testplan04-a", service_name="worker",
                                                       project_id="testplan04-a-1f2e3d")
        self.assertTrue(len(actions) > 0)
        self.assertNotIn("${PROJECT_ID}", healed["k8s/deployment.yaml"])
        self.assertIn("value: testplan04-a-1f2e3d", healed["k8s/deployment.yaml"])
        self.assertIn("image: stream-apps/stream-worker:latest", healed["k8s/deployment.yaml"])
        self.assertNotIn("${PROJECT_ID}", healed["k8s/serviceaccount.yaml"])
        self.assertIn("worker-sa@testplan04-a-1f2e3d.iam.gserviceaccount.com", healed["k8s/serviceaccount.yaml"])

    def test_parameterize_gke_autopilot_module_compute(self):
        """Verifies generate_golden_main_tf dynamically wires custom VPC and subnet into compute-gke-autopilot."""
        custom_tf = (
            'resource "google_compute_network" "custom_vpc" {\n'
            '  name = "custom-vpc"\n'
            '}\n'
            'resource "google_compute_subnetwork" "custom_subnet" {\n'
            '  name    = "custom-subnet"\n'
            '  network = google_compute_network.custom_vpc.id\n'
            '}\n'
        )
        main_tf = generate_golden_main_tf(
            product_id="testplan04-a",
            archetype="gke-autopilot",
            custom_tf_content=custom_tf,
        )
        self.assertIn("source     = \"../modules/compute-gke-autopilot\"", main_tf)
        self.assertIn("network    = google_compute_network.custom_vpc.name", main_tf)
        self.assertIn("subnetwork = google_compute_subnetwork.custom_subnet.name", main_tf)

    def test_generate_golden_variables_tf_has_network_and_subnetwork(self):
        """Verifies generate_golden_variables_tf declares network and subnetwork with resilient defaults."""
        vars_tf = generate_golden_variables_tf(product_id="testplan04-a")
        self.assertIn('variable "network"', vars_tf)
        self.assertIn('default     = "default"', vars_tf)
        self.assertIn('variable "subnetwork"', vars_tf)

    def test_generate_service_workflow_no_continue_on_error(self):
        """Verifies generate_service_workflow does NOT contain continue-on-error: true in auth step."""
        wf = generate_service_workflow(
            product_id="testplan04-a",
            service_name="worker",
            archetype="gke-autopilot",
        )
        self.assertNotIn("continue-on-error: true", wf)
        self.assertIn("google-github-actions/auth@v2", wf)
        self.assertIn("Deploy to GKE Autopilot Cluster", wf)

    def test_generate_golden_variables_tf_has_labels(self):
        """Verifies generate_golden_variables_tf declares variable labels with map(string) type."""
        vars_tf = generate_golden_variables_tf(product_id="testplan05-a")
        self.assertIn('variable "labels"', vars_tf)
        self.assertIn('type        = map(string)', vars_tf)
        self.assertIn('default     = {}', vars_tf)


if __name__ == "__main__":
    unittest.main()

