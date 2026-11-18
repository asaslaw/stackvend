"""
Tests for Architect Agent Schema Decoupling, Native Structured Outputs & Token Pruning (Plan 13).
Verifies:
1. ArchitecturePlanDAG decouples structured fields from large markdown strings.
2. ArchitecturePlan maintains 100% downstream backward compatibility by subclassing ArchitecturePlanDAG.
3. ArchitectAgent.decompose() configures native response_schema=ArchitecturePlanDAG, max_output_tokens=16384, temperature=0.1.
4. Python generates the 7-section implementation plan markdown deterministically in ~2ms.
5. Critical logging triggers if model generation fails or fallback is engaged.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import logging
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
            for cls in reversed(self.__class__.__mro__):
                for k, v in cls.__dict__.items():
                    if not k.startswith('_') and not callable(v):
                        default_val = getattr(v, 'default', v)
                        if default_val is not Ellipsis:
                            setattr(self, k, default_val)
            for k, v in kwargs.items():
                setattr(self, k, v)

        def model_dump(self):
            res = {}
            for k, v in self.__dict__.items():
                if not k.startswith('_'):
                    if hasattr(v, 'model_dump'):
                        res[k] = v.model_dump()
                    elif isinstance(v, list):
                        res[k] = [item.model_dump() if hasattr(item, 'model_dump') else item for item in v]
                    else:
                        res[k] = v
            return res

    class MockFieldInfo:
        def __init__(self, default=None, default_factory=None):
            self.default = default if default is not None else (default_factory() if default_factory else None)

    mock_pydantic = MagicMock()
    mock_pydantic.BaseModel = MockBaseModel
    mock_pydantic.Field = lambda default=None, default_factory=None, **kwargs: MockFieldInfo(default, default_factory)
    mock_pydantic.EmailStr = str
    mock_pydantic.ValidationError = ValueError
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

if GATEWAY_PATH not in sys.path:
    sys.path.insert(0, GATEWAY_PATH)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from architect_agent.schemas import (
    ArchitecturePlanDAG,
    ArchitecturePlan,
    TaskItem,
    TaskCategory,
    TaskPriority,
    SequencedBuildPlan,
    BuildPlanStep,
    BuildStepCategory,
    BuildStepStatus,
    ArchitectDecompositionResult,
)
from architect_agent.handler import ArchitectAgent


class TestArchitectStructuredOutputs(unittest.TestCase):
    def setUp(self):
        self.sample_dag_dict = {
            "product_id": "structured-test-svc",
            "project_tier": 1,
            "summary": "Deploy high-throughput structured test service",
            "architecture_overview": "Cloud Run v2 microservice with Firestore state and Artifact Registry repo.",
            "infra_tasks": [
                {
                    "task_id": "INFRA-01",
                    "title": "Provision Cloud Run & IAM",
                    "category": "INFRA",
                    "target_files": ["infra/workload/main.tf"],
                    "description": "Create Terraform resources.",
                    "acceptance_criteria": ["Terraform plan valid"],
                    "depends_on": [],
                    "assigned_agent": "gcp-devops",
                    "priority": "HIGH",
                }
            ],
            "code_tasks": [
                {
                    "task_id": "CODE-01",
                    "title": "Implement FastAPI Handlers",
                    "category": "CODE",
                    "target_files": ["main.py", "requirements.txt"],
                    "description": "FastAPI service with health endpoints.",
                    "acceptance_criteria": ["GET / returns 200 OK"],
                    "depends_on": ["INFRA-01"],
                    "assigned_agent": "developer",
                    "priority": "HIGH",
                }
            ],
            "estimated_complexity": "MEDIUM",
            "requires_human_approval": False,
            "risk_assessment": "Standard low-risk autonomous rollout.",
            # lane 10 (FD-51): every architect answer carries the typed service topology
            "service_topology": {"services": [{"name": "structured-test-svc", "kind": "cloudrun"}],
                                 "primary_service": "structured-test-svc", "edges": [], "resources": []},
        }

    def test_schema_decoupling(self):
        """Verify ArchitecturePlanDAG contains no markdown fields, while ArchitecturePlan maintains them."""
        # 1. ArchitecturePlanDAG validates without plan_markdown or plan_file_path
        plan_dag = ArchitecturePlanDAG(**self.sample_dag_dict)
        dag_dict = plan_dag.model_dump()
        self.assertNotIn("plan_markdown", dag_dict)
        self.assertNotIn("plan_file_path", dag_dict)
        self.assertEqual(plan_dag.product_id, "structured-test-svc")
        self.assertEqual(len(plan_dag.infra_tasks), 1)
        self.assertEqual(len(plan_dag.code_tasks), 1)

        # 2. ArchitecturePlan subclasses ArchitecturePlanDAG and defaults empty strings
        plan = ArchitecturePlan(**dag_dict)
        self.assertTrue(isinstance(plan, ArchitecturePlanDAG))
        self.assertEqual(plan.plan_markdown, "")
        self.assertEqual(plan.plan_file_path, "")
        self.assertEqual(plan.product_id, "structured-test-svc")

        # 3. ArchitecturePlanDAG schema enforces required fields via json_schema_extra
        schema = ArchitecturePlanDAG.model_json_schema()
        expected_required = [
            "product_id",
            "summary",
            "architecture_overview",
            "infra_tasks",
            "code_tasks",
            "target_compute_services",
            "compute_archetype",  # architect-compute-archetype (owner Q1, 10-13): typed primary compute kind
            "service_topology",   # lane 10 (FD-51): typed per-service topology
            "iac_engine",
        ]
        self.assertEqual(schema.get("required"), expected_required)

    def test_decompose_with_mock_gemini_client(self):
        """Verify decompose configures native response_schema=ArchitecturePlanDAG and populates markdown."""
        # The Gemini 3.x request shape (temperature, 16,384) is asserted below: pin that model explicitly (the
        # settings default is gemini-4-carbon since DEFAULT-MODEL-GEMINI-4-CARBON; its shape: test_gemini_4_carbon).
        agent = ArchitectAgent(project_id="test-project", model_name="gemini-3.8-flash")
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = json.dumps(self.sample_dag_dict)
        mock_client.models.generate_content.return_value = mock_response
        agent.genai_client = mock_client
        agent.db = MagicMock()  # lane 10: the gated compute-intent record write is fatal; an in-memory stand-in

        with patch("architect_agent.handler.logger") as mock_logger:
            result = agent.decompose(
                spec_text="Build a high-performance order processor",
                product_id="order-processor",
                trace_id="trace-test-13",
            )

            # Assert model was invoked with response_schema=ArchitecturePlanDAG
            self.assertTrue(mock_client.models.generate_content.called)
            from google.genai import types
            if hasattr(types.GenerateContentConfig, "call_args") and types.GenerateContentConfig.call_args:
                cfg_kwargs = types.GenerateContentConfig.call_args.kwargs
                self.assertEqual(cfg_kwargs.get("response_schema"), ArchitecturePlanDAG)
                self.assertEqual(cfg_kwargs.get("max_output_tokens"), 16384)
                self.assertEqual(cfg_kwargs.get("temperature"), 0.1)
                self.assertEqual(cfg_kwargs.get("response_mime_type"), "application/json")
            else:
                call_kwargs = mock_client.models.generate_content.call_args.kwargs
                config = call_kwargs.get("config")
                self.assertIsNotNone(config)
                self.assertEqual(getattr(config, "response_schema", None), ArchitecturePlanDAG)
                self.assertEqual(getattr(config, "max_output_tokens", None), 16384)
                self.assertEqual(getattr(config, "temperature", None), 0.1)

            # Assert result contains valid ArchitecturePlan and rendered markdown
            self.assertIsInstance(result, ArchitectDecompositionResult)
            self.assertEqual(result.product_id, "structured-test-svc")
            self.assertTrue(result.plan_file_path.startswith("docs/planning/"))
            self.assertIn("## 1. Executive Summary & Requirements", result.plan_markdown)
            self.assertIn("## 2. Architecture & Topology Design", result.plan_markdown)
            self.assertIn("## 3. Security, IAM & Governance Assessment", result.plan_markdown)
            self.assertIn("## 4. Component Manifest & Proposed Changes", result.plan_markdown)
            self.assertIn("## 5. Sequenced Build Plan (Task DAG)", result.plan_markdown)
            self.assertIn("## 6. Verification & Automated Test Strategy", result.plan_markdown)
            self.assertIn("## 7. Rollback & Blast Radius Assessment", result.plan_markdown)

            # Critical fallback alert should NOT be logged on successful DAG parsing
            for call in mock_logger.critical.call_args_list:
                self.assertNotIn("ARCHITECT_FALLBACK_TRIGGERED", str(call))

    def test_critical_fallback_alert_on_parse_error(self):
        """Verify that syntax errors or generation failures trigger logger.critical."""
        agent = ArchitectAgent(project_id="test-project")
        mock_client = MagicMock()
        mock_response = MagicMock()
        # Malformed truncated JSON that triggers parse error
        mock_response.text = '{"product_id": "bad-json", "summary": "incomplete...'
        mock_client.models.generate_content.return_value = mock_response
        agent.genai_client = mock_client

        from architect_agent.topology_gate import TopologyInvalidError
        with patch("architect_agent.handler.logger") as mock_logger:
            # Lane 10 (FD-51, plan §5.2): the deterministic fallback plan carries no model topology, so it never
            # passes the topology gate: the stage fails typed (ARCHITECT_DEFECT) instead of shipping a generic plan.
            with self.assertRaises(TopologyInvalidError) as ctx:
                agent.decompose(
                    spec_text="Deploy an invalid spec",
                    product_id="bad-workload",
                    trace_id="trace-err-13",
                )

            # Assert critical alert was logged
            critical_msgs = [str(c.args[0]) for c in mock_logger.critical.call_args_list]
            self.assertTrue(any("ARCHITECT_FALLBACK_TRIGGERED" in m and "bad-workload" in m for m in critical_msgs))
            body = ctx.exception.to_body()
            self.assertEqual(body["error_class"], "ARCHITECT_DEFECT")
            self.assertEqual(ctx.exception.http_status, 422)
            self.assertEqual([d["code"] for d in body["diagnostics"]], ["TOPOLOGY.MISSING"])

            # The fallback plan itself is unchanged (it is still built and logged, never returned)
            plan = agent._fallback_plan("bad-workload", "Deploy an invalid spec")
            self.assertEqual(plan.product_id, "bad-workload")
            self.assertTrue(len(plan.infra_tasks) + len(plan.code_tasks) >= 2)

    def test_ipam_failure_leaves_no_cidr_and_no_fallback_literal(self):
        """Row IPAM-1: a typed IPAM error leaves the plan without a range (no '10.100.1.0/28' guess); the developer
        stage resolves the range from the ledger and fails closed itself."""
        import shared.ipam as ipam_mod
        agent = ArchitectAgent(project_id="test-project")
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = json.dumps(self.sample_dag_dict)
        mock_client.models.generate_content.return_value = mock_response
        agent.genai_client = mock_client
        agent.db = MagicMock()
        down = ipam_mod.IPAMUnavailable("ledger read failed: ServiceUnavailable")
        from shared.settings import PlatformSettings   # FD-4AK: the pool read is strict; state the settings
        with patch.object(ipam_mod.CastorIPAMEngine, "allocate_next_cidr", side_effect=down) as alloc, \
                patch("shared.settings.get_platform_settings", return_value=PlatformSettings()), \
                patch("architect_agent.handler.logger") as mock_logger:
            result = agent.decompose(
                spec_text="Build an order processor that reaches Cloud SQL through a VPC connector",
                product_id="order-processor",
                trace_id="trace-ipam-1",
            )
        self.assertTrue(alloc.called)
        self.assertIsNone(result.architecture_plan.assigned_cidr_block)
        self.assertTrue(result.architecture_plan.requires_vpc)   # RT F3: the VPC decision survives an IPAM failure
        errors = [str(c.args[0]) for c in mock_logger.error.call_args_list]
        self.assertTrue(any("IPAM.UNAVAILABLE" in m and "no fallback" in m for m in errors))
        steps = (result.sequenced_build_plan.steps if result.sequenced_build_plan else [])
        self.assertFalse([s for s in steps if "10.100.1.0/28" in (s.description or "")])

    def _decompose_with(self, spec_text, alloc_patch, settings_patch=True):
        import shared.ipam as ipam_mod
        agent = ArchitectAgent(project_id="test-project")
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = json.dumps(self.sample_dag_dict)
        mock_client.models.generate_content.return_value = mock_response
        agent.genai_client = mock_client
        agent.db = MagicMock()
        from shared.settings import PlatformSettings   # FD-4AK: the pool read is strict; state the settings
        settings_ctx = (patch("shared.settings.get_platform_settings", return_value=PlatformSettings())
                        if settings_patch else patch.dict(os.environ, {}))
        with patch.object(ipam_mod.CastorIPAMEngine, "allocate_next_cidr", **alloc_patch) as alloc, settings_ctx:
            result = agent.decompose(spec_text=spec_text, product_id="order-processor", trace_id="trace-ipam-1b")
        return result, alloc

    def test_ipam_success_plan_is_unchanged(self):
        """Do No Harm (RT F3): a successful allocation gives the same plan fields as before (requires_vpc true,
        the allocated range)."""
        import shared.ipam as ipam_mod
        rec = ipam_mod.CidrAllocationRecord(cidr_block="10.100.0.16/28", sanitized_id="10_100_0_16_28",
                                            product_id="order-processor")
        result, alloc = self._decompose_with(
            "Build an order processor that reaches Cloud SQL through a VPC connector", {"return_value": rec})
        self.assertTrue(alloc.called)
        self.assertTrue(result.architecture_plan.requires_vpc)
        self.assertEqual(result.architecture_plan.assigned_cidr_block, "10.100.0.16/28")

    # FD-4BZ RT F2: the architect reads the IPAM pool from platform settings through the developer's reader.
    _VPC_SPEC = "Build an order processor that reaches Cloud SQL through a VPC connector"

    def _decompose_with_settings(self, settings):
        import shared.ipam as ipam_mod
        rec = ipam_mod.CidrAllocationRecord(cidr_block="10.100.0.16/28", sanitized_id="10_100_0_16_28",
                                            product_id="order-processor")
        with patch("shared.settings.get_platform_settings", return_value=settings) as gps:
            result, alloc = self._decompose_with(self._VPC_SPEC, {"autospec": True, "return_value": rec},
                                                 settings_patch=False)
        return result, alloc, gps

    def test_ipam_pool_default_settings_are_the_historic_pool(self):
        """Do No Harm (F2): with default settings the architect's engine uses exactly the old pool (the engine's
        default supernet) and the old fixed /28, so it allocates identical ranges."""
        import shared.ipam as ipam_mod
        from shared.settings import PlatformSettings
        result, alloc, gps = self._decompose_with_settings(PlatformSettings())
        self.assertTrue(gps.called)
        engine = alloc.call_args.args[0]
        self.assertEqual(engine.supernet_cidr, ipam_mod.CastorIPAMEngine().supernet_cidr)
        self.assertEqual(engine.supernet_cidr, "10.100.0.0/16")
        self.assertEqual(alloc.call_args.kwargs["prefix_len"], 28)
        self.assertEqual(result.architecture_plan.assigned_cidr_block, "10.100.0.16/28")

    def test_ipam_pool_default_settings_allocate_identical_ranges_on_a_ledger(self):
        """Do No Harm (F2), real allocator: the settings-driven engine and the old `CastorIPAMEngine()` + /28 give
        the same ranges, in the same order, on the same ledger."""
        import shared.ipam as ipam_mod
        from shared.settings import PlatformSettings
        try:
            from developer_agent.platform_facts import load_ipam_pool
        except ImportError:  # pragma: no cover
            self.skipTest("platform_facts not importable")
        from ipam_fake_firestore import FakeFirestore, fake_transactional
        with patch("shared.settings.get_platform_settings", return_value=PlatformSettings()):
            pool = load_ipam_pool("test-project")
        calls = [("a", "SERVERLESS_VPC_CONNECTOR"), ("b", "WORKLOAD_SUBNET"), ("c", "HYBRID"),
                 ("a", "SERVERLESS_VPC_CONNECTOR"), ("d", "SERVERLESS_VPC_CONNECTOR")]

        def run(make_engine, prefix):
            db = FakeFirestore()
            eng = make_engine(db)
            eng.allocate_next_cidr("seed", purpose="WORKLOAD_SUBNET", prefix_len=24)   # an occupied /24 first
            return [eng.allocate_next_cidr(p, purpose=u, prefix_len=prefix, region="global").cidr_block
                    for p, u in calls]

        old = run(lambda db: ipam_mod.CastorIPAMEngine(db=db, transactional=fake_transactional), 28)
        new = run(lambda db: ipam_mod.CastorIPAMEngine(db=db, supernet_cidr=pool.supernet,
                                                       transactional=fake_transactional), pool.connector_prefix)
        self.assertEqual(old, new)
        self.assertEqual(old, ["10.100.1.0/28", "10.100.1.16/28", "10.100.1.32/28", "10.100.1.0/28",
                               "10.100.1.48/28"])

    def test_ipam_pool_follows_non_default_settings(self):
        """F2: a configured pool (supernet, connector prefix) reaches the architect's allocation, as it does the
        developer's."""
        from shared.settings import PlatformSettings
        s = PlatformSettings()
        s.orchestration.ipam_supernet_cidr = "10.64.0.0/20"
        s.orchestration.ipam_connector_prefix = 27
        _result, alloc, _gps = self._decompose_with_settings(s)
        engine = alloc.call_args.args[0]
        self.assertEqual(engine.supernet_cidr, "10.64.0.0/20")
        self.assertEqual(alloc.call_args.kwargs["prefix_len"], 27)

    def test_ipam_pool_unusable_settings_fail_closed(self):
        """F2 fail-closed: settings that cannot give a pool leave the plan without a range (no fallback literal),
        exactly like an IPAM outage, and nothing is allocated."""
        broken = MagicMock()
        broken.orchestration.ipam_supernet_cidr = "not-a-cidr"
        broken.orchestration.ipam_connector_prefix = 28
        broken.orchestration.ipam_subnet_prefix = 24
        broken.orchestration.default_gcp_region = "us-central1"
        result, alloc, _gps = self._decompose_with_settings(broken)
        self.assertFalse(alloc.called)
        self.assertTrue(result.architecture_plan.requires_vpc)
        self.assertIsNone(result.architecture_plan.assigned_cidr_block)

    def test_architect_and_developer_share_one_pool_reader(self):
        """F2: one helper, used by both stages."""
        import architect_agent.handler as arch_src
        import developer_agent.handler as dev_handler
        from developer_agent import platform_facts
        self.assertIs(dev_handler.load_ipam_pool, platform_facts.load_ipam_pool)
        src = open(arch_src.__file__, encoding="utf-8").read()
        self.assertIn("from developer_agent.platform_facts import load_ipam_pool", src)
        self.assertNotIn("CastorIPAMEngine()", src)
        self.assertNotIn("prefix_len=28", src)

    def test_no_vpc_spec_never_touches_ipam_or_requires_vpc(self):
        """Negative (RT F3): a spec without a VPC need keeps the model's requires_vpc (false) and never allocates."""
        result, alloc = self._decompose_with("Build a high-performance order processor",
                                             {"side_effect": AssertionError("must not allocate")})
        self.assertFalse(alloc.called)
        self.assertFalse(result.architecture_plan.requires_vpc)
        self.assertIsNone(result.architecture_plan.assigned_cidr_block)

    def test_vpc_step_names_the_ipam_variable_when_no_range_was_assigned(self):
        agent = ArchitectAgent(project_id="test-project")
        spec = "Deploy a FastAPI service reaching Cloud SQL through a VPC connector."
        plan = agent._generate_sequenced_build_plan(product_id="vpc-svc", trace_id="t-1", spec_text=spec)
        vpc = next(s for s in plan.steps if s.step_id == "STEP-VPC")
        self.assertIn("var.connector_cidr", vpc.description)
        self.assertNotIn("10.100.", vpc.description)
        # Do No Harm: with an IPAM-assigned range the step text is exactly as before
        plan2 = agent._generate_sequenced_build_plan(product_id="vpc-svc", trace_id="t-2", spec_text=spec,
                                                     assigned_cidr="10.100.0.16/28")
        vpc2 = next(s for s in plan2.steps if s.step_id == "STEP-VPC")
        self.assertEqual(vpc2.description, "Provision isolated VPC network and Serverless VPC Access Connector with "
                                           "assigned IPAM CIDR block (ip_cidr_range = '10.100.0.16/28').")

    def test_seed_email_none_when_omitted(self):
        """Verify that when no email is specified in spec, seed_email is None and no personal email is seeded."""
        agent = ArchitectAgent(project_id="test-project")
        plan = agent._generate_sequenced_build_plan(
            product_id="no-email-svc",
            trace_id="trace-no-email",
            spec_text="Deploy a FastAPI service with Firestore database.",
        )
        app_code_step = next((s for s in plan.steps if s.step_id == "STEP-APP-CODE"), None)
        self.assertIsNotNone(app_code_step)
        self.assertNotRegex(app_code_step.description, r"[\w.+-]+@[\w-]+\.[\w.]+")  # no e-mail seeded
        self.assertNotIn("seed user", app_code_step.description)

    def test_seed_email_included_when_requested(self):
        """Verify that when an email is explicitly in spec, it is included in the build step."""
        agent = ArchitectAgent(project_id="test-project")
        plan = agent._generate_sequenced_build_plan(
            product_id="email-svc",
            trace_id="trace-email",
            spec_text="Deploy a FastAPI service for lead_developer@company.org with Firestore.",
        )
        app_code_step = next((s for s in plan.steps if s.step_id == "STEP-APP-CODE"), None)
        self.assertIsNotNone(app_code_step)
        self.assertIn("seed user 'lead_developer@company.org'", app_code_step.description)

    def test_architecture_plan_dag_schema_compiles_cleanly(self):
        """Verify ArchitecturePlanDAG compiles cleanly without integer enum validation errors."""
        schema_dict = ArchitecturePlanDAG.model_json_schema()
        self.assertIn("project_tier", schema_dict["properties"])
        self.assertEqual(schema_dict["properties"]["project_tier"].get("type"), "integer")
        # Ensure enum is NOT present on project_tier (which triggers OpenAPI proto string type error)
        self.assertNotIn("enum", schema_dict["properties"]["project_tier"])
        # Ensure ge/le extra fields are NOT present (which trigger extra_forbidden in google-genai)
        self.assertNotIn("ge", schema_dict["properties"]["project_tier"])
        self.assertNotIn("le", schema_dict["properties"]["project_tier"])

    def test_project_tier_coercion_and_clamping(self):
        """Verify that project_tier safely coerces strings and clamps out-of-range values."""
        self.assertEqual(ArchitecturePlanDAG(product_id="p", project_tier=1).project_tier, 1)
        self.assertEqual(ArchitecturePlanDAG(product_id="p", project_tier=2).project_tier, 2)
        self.assertEqual(ArchitecturePlanDAG(product_id="p", project_tier=3).project_tier, 3)
        self.assertEqual(ArchitecturePlanDAG(product_id="p", project_tier="2").project_tier, 2)
        self.assertEqual(ArchitecturePlanDAG(product_id="p", project_tier=99).project_tier, 3)
        self.assertEqual(ArchitecturePlanDAG(product_id="p", project_tier=0).project_tier, 1)
        self.assertEqual(ArchitecturePlanDAG(product_id="p", project_tier=None).project_tier, 1)
        self.assertEqual(ArchitecturePlanDAG(product_id="p", project_tier="invalid").project_tier, 1)


if __name__ == "__main__":
    unittest.main()
