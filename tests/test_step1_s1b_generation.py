"""Step 1 S1-B wired into DeveloperAgent.generate_code_files / commit_and_open_pr (HS-03/HS-04/HS-05/HS-06): the
validated tree is the committed tree, failures are typed, readiness and budget are checked before any LLM call, an
unconfigured stack on Cloud Run fails closed. Fakes for the LLM draft and for /validate; no network."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

try:  # RT fix 3: acceptance evidence must fail loudly, never skip silently or depend on collection order
    import hcl2  # noqa: F401,E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: install apps/orchestrator-gateway/requirements.txt (python-hcl2==7.3.1) or put "
                "the vendored eval/.deps on PYTHONPATH; this file is acceptance evidence and must not skip",
                pytrace=False)

from developer_agent import hallucination_runtime as hr  # noqa: E402
from shared.diagnostics import (ErrorClass, MemoryLedgerStore, MemoryProvenanceStore, RepairBudgetExhausted,  # noqa: E402
                                RepairLedger, StageError, artifact_hash)
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402

W = "infra/workload/"
DRAFT = {
    W + "main.tf": 'resource "google_storage_bucket" "uploads" {\n  name     = "${var.product_id}-uploads"\n'
                   '  location = var.region\n  uniform_bucket_level_access = true\n}\n',   # S2-B V2e: compliant
    "apps/shop/main.py": "from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get('/health')\ndef health():\n"
                         "    return {'ok': True}\n",
    "apps/shop/requirements.txt": "fastapi>=0.110.0\nuvicorn>=0.28.0\n",
    "apps/shop/Procfile": "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n",
}


@pytest.fixture(autouse=True)
def _virtual_ready_wait():
    """Step 1 follow-up (owner 10-13): the gate polls /validate/ready for up to validate_ready_wait_s (180 s). The
    not-ready tests here keep that production default but run it on a virtual clock (no real sleeping)."""
    now = [0.0]

    def sleep(s):
        now[0] += s
    with patch.object(hr, "_sleep", sleep), patch.object(hr, "_clock", lambda: now[0]):
        yield now


class Client:
    def __init__(self, status="PASS", ready=True, diags=None):
        self.status, self.is_ready, self.diags = status, ready, diags or []
        self.validated = []

    def ready(self, iac_engine="OPENTOFU"):
        return {"ready": self.is_ready, "providers": ["google", "google-beta", "kubernetes", "random"],
                "engine": "OPENTOFU", "engine_version": "1.9.0", "reason": "" if self.is_ready else "warming up"}

    def validate(self, files, *, iac_engine="OPENTOFU", trace_id=""):
        self.validated.append(dict(files))
        return {"status": self.status, "diagnostics": self.diags}


class _NoCallGenaiClient:
    """Step1 merge (lane 19 row 27a): generate_code_files now fails LLM_UNAVAILABLE without a client, before the
    lead or the swarm runs. These tests fake the lead + dispatcher (the draft is fixed), so the agent gets a client
    that must never be called: any model call is a test failure, exactly like the old `genai_client = None`."""

    class models:  # noqa: N801 - mirrors google.genai.Client().models
        @staticmethod
        def generate_content(*a, **k):
            raise AssertionError("unexpected LLM call: the draft comes from the fake dispatcher")


def _runtime(client, settings=None, ledger=None):
    return hr.HallucinationRuntime(ledger_store=ledger or MemoryLedgerStore(), provenance_store=MemoryProvenanceStore(),
                                   validate_client=client, settings=settings or HallucinationStackSettings(),
                                   source="test")


def _agent(runtime=None):
    from developer_agent import handler as h
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GEMINI_API_KEY": ""}):
        agent = h.DeveloperAgent(project_id="")
    agent.genai_client = _NoCallGenaiClient()  # lane 19 (27a): None now raises LLM_UNAVAILABLE first
    if runtime is not None:
        agent.attach_stack_runtime(runtime)
    return agent


def _generate(agent, draft=None, trace="trace-s1b", lead_calls=None):
    from developer_agent import handler as h
    plan = MagicMock()
    plan.execution_mode = [m for m in h.SwarmExecutionMode if m != h.SwarmExecutionMode.SOLO_FAST_PATH][0]
    plan.tasks = [MagicMock()]
    d = dict(draft or DRAFT)

    class FakeDispatcher:
        def __init__(self, *a, **k):
            self.last_file_attribution = {p: "iac_worker" if p.endswith(".tf") else "backend_worker" for p in d}
            self.envelope_checks = [{"ok": True, "error": None}]

        async def execute_phased_junior_swarm(self, *a, **k):
            return dict(d)

    with patch.object(h, "LeadDeveloperOrchestrator") as lead, patch.object(h, "SwarmDispatcher", FakeDispatcher), \
            patch.object(agent, "fetch_existing_repo_files", return_value={}), \
            patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GCP_PROJECT": ""}), \
            patch("google.cloud.firestore.Client", side_effect=RuntimeError("no Firestore in tests")):
        lead.return_value.decompose_specification.return_value = plan
        try:
            # a pipeline trace carries the architect's typed compute record (RT fix 2: none -> COMPUTE_INTENT_MISSING)
            return agent.generate_code_files(product_id="shop", spec_text="FastAPI uploads service", task_dag=[],
                                             trace_id=trace, architect_compute_intent={"target_compute_services": ["shop"]}, allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False)
        finally:
            if lead_calls is not None:
                lead_calls.append(lead.return_value.decompose_specification.call_count)


def _commit(agent, files, trace="trace-s1b"):
    from _fake_vcs import fake_vcs_commit  # FD-4F A9 (Q-E): no token is a typed failure; commit through a fake VCS
    with fake_vcs_commit(agent), \
            patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GCP_PROJECT": ""}), \
            patch("google.cloud.firestore.Client", side_effect=RuntimeError("no Firestore in tests")):
        return agent.commit_and_open_pr(product_id="shop", files=dict(files), trace_id=trace)


def test_validated_tree_is_the_committed_tree():
    client = Client()
    agent = _agent(_runtime(client))
    files = _generate(agent)
    report = agent.last_validation_report
    assert report.status == "PASS" and report.artifact_hash == artifact_hash(files)
    assert client.validated and all(k.startswith("infra/") for k in client.validated[0])
    assert agent.last_envelope_checks == [{"ok": True, "error": None}]
    assert _commit(agent, files)["status"] == "COMMITTED"
    tampered = dict(files, **{"apps/shop/extra.py": "x = 1\n"})
    with pytest.raises(StageError) as ei:
        _commit(agent, tampered)
    assert ei.value.error_class is ErrorClass.PLATFORM_DEFECT


def test_failure_is_typed_and_no_repair_without_budget():
    diag = {"severity": "error", "summary": "Reference to undeclared resource",
            "range": {"filename": W + "custom.tf", "start": {"line": 3, "byte": 0}, "end": {"line": 3, "byte": 1}}}
    agent = _agent(_runtime(Client(status="FAIL", diags=[diag]),
                            settings=HallucinationStackSettings(repair_max_iterations_precommit=0)))
    with pytest.raises(RepairBudgetExhausted) as ei:
        _generate(agent)
    assert ei.value.error_class is ErrorClass.CODE_DEFECT
    assert agent.last_validation_report.status == "FAIL"


def test_not_ready_and_exhausted_budget_stop_before_any_llm_call():
    calls = []
    with pytest.raises(StageError) as ei:
        _generate(_agent(_runtime(Client(ready=False))), lead_calls=calls)
    assert ei.value.error_class is ErrorClass.GATE_UNAVAILABLE and calls == [0]
    ledger = MemoryLedgerStore()
    ledger.save(RepairLedger(trace_id="trace-s1b", iteration=5, exhausted_reason="ITERATIONS"))
    calls = []
    with pytest.raises(RepairBudgetExhausted):
        _generate(_agent(_runtime(Client(), ledger=ledger)), lead_calls=calls)
    assert calls == [0]


def test_unconfigured_stack_fails_closed_on_cloud_run_and_is_off_elsewhere():
    agent = _agent()
    with patch.dict(os.environ, {"K_SERVICE": "orchestrator-gateway-service"}):
        with pytest.raises(StageError) as ei:
            agent._hallucination_stack_gate("shop", "t")
    assert ei.value.error_class is ErrorClass.GATE_UNAVAILABLE
    with patch.dict(os.environ, {"K_SERVICE": ""}):
        assert agent._hallucination_stack_gate("shop", "t") is None


def test_gateway_startup_attaches_the_firestore_and_http_runtime():
    import ast
    src = open(os.path.join(GATEWAY, "main.py")).read()
    tree = ast.parse(src)
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "attr", None) == "attach_stack_runtime"]
    assert calls, "main.py must attach the hallucination-stack runtime to its DeveloperAgent"
    text = ast.get_source_segment(src, calls[0])
    for name in ("FirestoreLedgerStore", "FirestoreProvenanceStore", "HttpValidateClient", 'source="gateway"'):
        assert name in text


def test_host_binary_probe_is_gone():
    # FD-55 W4: the in-loop HCL pre-flight (preflight_validate_terraform) is deleted altogether; V1b is the compiler tier
    from developer_agent import preflight_validator as pv
    assert not hasattr(pv, "preflight_validate_terraform")


def test_a_client_whose_ready_raises_is_an_unavailable_gate_never_a_pass():
    class Broken(Client):
        def ready(self, iac_engine="OPENTOFU"):
            raise TypeError("ready() signature drift")

    calls = []
    with pytest.raises(StageError) as ei:
        _generate(_agent(_runtime(Broken())), lead_calls=calls)
    assert ei.value.error_class is ErrorClass.GATE_UNAVAILABLE and calls == [0]


# ------------------------------------------------------------------------------------- Step 1 code RT F1
BUCKET_BLOCK = DRAFT[W + "main.tf"]


def _healer_patches(h, drop):
    """A healer that runs after the S1-A/HB-04/HB-01 snapshot: the generation-time gatekeeper cure (FD-55 W4 deleted
    the HD-15 / self_correct_hcl seam this used). The fake removes the AI bucket from every root .tf file when `drop`
    (an unrecorded R-class strip)."""
    import contextlib

    def verify_and_cure(self, files, product_id=None, **kw):
        out = dict(files)
        if drop:
            for k, v in files.items():
                if k.startswith(W) and k.endswith(".tf") and BUCKET_BLOCK.strip() in v:
                    out[k] = v.replace(BUCKET_BLOCK.strip(), "")
        return out, True, []
    return patch.object(h.SynthesisVerifierAgent, "verify_and_cure", verify_and_cure), contextlib.nullcontext()


def test_v2c_sees_a_declaration_dropped_by_a_later_healer():
    """RT F1: V2c compares the draft with the FINAL root module, so a draft resource that an R-class healer running
    after the S1-A/HB-04/HB-01 snapshot deletes (unrecorded) is a typed PLATFORM_DEFECT, never a silent pass.
    Mutation checked: feeding V2c the pre-healer snapshot again (meta["assembled_root"] = assembled_root_pre_healers)
    makes this test fail (status PASS)."""
    from developer_agent import handler as h
    p1, p2 = _healer_patches(h, drop=True)
    agent = _agent(_runtime(Client()))
    with p1, p2, pytest.raises(StageError) as ei:
        _generate(agent)
    assert ei.value.error_class is ErrorClass.PLATFORM_DEFECT
    dropped = [d for d in ei.value.report.diagnostics if d.code == "PLATFORM.ASSEMBLY_DROPPED_DECLARATION"]
    assert [d.block_address for d in dropped] == ["google_storage_bucket.uploads"]


def test_v2c_negative_no_healer_drop_no_diagnostic():
    from developer_agent import handler as h
    p1, p2 = _healer_patches(h, drop=False)
    agent = _agent(_runtime(Client()))
    with p1, p2:
        files = _generate(agent)
    report = agent.last_validation_report
    assert report.status == "PASS" and report.artifact_hash == artifact_hash(files)
    assert not [d for d in report.diagnostics if d.code == "PLATFORM.ASSEMBLY_DROPPED_DECLARATION"]
