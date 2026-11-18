"""
FD-4BO / FD-4BP: undefined names in the orchestrator gateway (pyflakes F821 class, umbrella FD-4AH).

FD-4BO  apps/orchestrator-gateway/main.py used ``re`` without importing it:
        * PlanApprovalRequest.parse_cost_delta raised NameError for any string cost -> HTTP 500 on
          /events/plan-approval-request instead of parsing "$12.50/mo" to 12.5;
        * release_promote raised NameError (swallowed) before post_release_certificate_to_vcs, so the release
          certificate was never handed to the VCS layer.
FD-4BP  architect_agent/handler.py ArchitectAgent.decompose read ``raw_json`` (a local of _single_turn_decompose):
        NameError swallowed -> the architect stage trace (and its consensus telemetry) was never written.
Also:   architect_agent/red_team_critic.py used ``os`` in its import fallback without importing it.

Hermetic: gateway main is loaded by path with PROJECT_ID unset and a fake db; the architect gets a fake genai client
and an in-memory Firestore fake. Nothing here builds a cloud client or touches the network.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import builtins
import importlib.util
import json
import os
import symtable
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GW_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
if GW_DIR not in sys.path:
    sys.path.insert(0, GW_DIR)


# ============================================================================================ static check
_BUILTINS = set(dir(builtins)) | {"__file__", "__name__", "__doc__", "__spec__", "__package__", "__loader__",
                                  "__builtins__", "__path__", "__annotations__", "__module__", "__qualname__",
                                  "__class__"}


def _undefined_globals(path):
    """{(scope_name, name)} for names a scope reads as globals that the module never binds (pyflakes F821-like)."""
    with open(path, encoding="utf-8") as fh:
        top = symtable.symtable(fh.read(), path, "exec")
    bound = {s.get_name() for s in top.get_symbols() if s.is_assigned() or s.is_imported() or s.is_namespace()}

    def _global_assigns(tab):
        for s in tab.get_symbols():
            if s.is_declared_global() and s.is_assigned():
                bound.add(s.get_name())
        for ch in tab.get_children():
            _global_assigns(ch)

    _global_assigns(top)
    found = set()

    def _walk(tab):
        for s in tab.get_symbols():
            name = s.get_name()
            if s.is_referenced() and (s.is_global() or tab.get_type() == "module") \
                    and name not in bound and name not in _BUILTINS:
                found.add((tab.get_name(), name))
        for ch in tab.get_children():
            _walk(ch)

    _walk(top)
    return found


def test_gateway_main_has_no_undefined_names():
    assert _undefined_globals(os.path.join(GW_DIR, "main.py")) == set()


def test_architect_decompose_reads_no_undefined_names():
    found = _undefined_globals(os.path.join(GW_DIR, "architect_agent", "handler.py"))
    assert not {n for scope, n in found if scope == "decompose"}, found


def test_red_team_critic_import_fallback_has_os():
    found = _undefined_globals(os.path.join(GW_DIR, "architect_agent", "red_team_critic.py"))
    assert ("get_model_cascade_for_agent", "os") not in found


def test_static_check_detects_an_undefined_name(tmp_path):
    """Negative control: the checker must flag a name that is read but never bound, and accept a bound one."""
    p = tmp_path / "m.py"
    p.write_text("import os\n\ndef f():\n    return os.sep + re.escape('x')\n")
    assert _undefined_globals(str(p)) == {("f", "re")}


# ============================================================================================ FD-4BO behaviour
@pytest.fixture()
def gw(monkeypatch):
    from fd4g_support import real_modules

    real_modules(monkeypatch)
    for k in ("PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "GCP_PROJECT", "GEMINI_API_KEY", "GOOGLE_API_KEY", "K_SERVICE",
              "REGION", "GITHUB_OWNER"):
        monkeypatch.delenv(k, raising=False)
    spec = importlib.util.spec_from_file_location("fd4bo_gw_main", os.path.join(GW_DIR, "main.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    yield mod
    mod.app.dependency_overrides.clear()


def _plan_req(mod, cost):
    return mod.PlanApprovalRequest(product_id="p1", callback_url="https://workflowexecutions.example/cb",
                                   cost_delta_monthly=cost)


@pytest.mark.parametrize("cost,expected", [
    ("$12.50/mo", 12.5),
    ("12.5", 12.5),
    ("-3", -3.0),
    ("n/a", 0.0),      # nothing numeric left -> 0.0 (existing contract)
    ("1-2", 0.0),      # strips to "1-2", float() fails -> 0.0 (existing contract)
])
def test_plan_approval_cost_string_parses(gw, cost, expected):
    assert _plan_req(gw, cost).cost_delta_monthly == expected


@pytest.mark.parametrize("cost,expected", [(7, 7.0), (7.25, 7.25), (None, 0.0)])
def test_plan_approval_cost_non_string_unchanged(gw, cost, expected):
    """Do No Harm: the numeric / None paths never touched ``re`` and must behave exactly as before."""
    assert _plan_req(gw, cost).cost_delta_monthly == expected


def test_plan_approval_endpoint_accepts_string_cost(gw):
    from fastapi.testclient import TestClient

    fake_db = MagicMock()
    gw.db = fake_db
    client = TestClient(gw.app)
    r = client.post("/events/plan-approval-request", json={
        "product_id": "p1", "trace_id": "t1", "callback_url": "https://workflowexecutions.example/cb",
        "cost_delta_monthly": "$12.50/mo",
    })
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "SUCCESS"
    record = fake_db.collection.return_value.document.return_value.set.call_args_list[0].args[0]
    assert record["cost_delta_monthly"] == 12.5


def _gate_decision(approved=True):
    return SimpleNamespace(
        is_approved=approved,
        recommended_action="AUTO_MERGE" if approved else "BLOCK_FOR_HITL_REVIEW",
        blocking_reasons=[],
        release_certificate_markdown="## Release Certificate\nPASS",
        model_dump=lambda: {"is_approved": approved},
    )


def _wire_release(gw, monkeypatch, merged, vcs_provider="GITHUB"):
    dev = MagicMock()
    dev.get_full_repo_name.return_value = "acme/p1-repo"
    monkeypatch.setattr(gw, "developer_agent", dev)
    # FD-4BB: the release merges the PR-ledger entry through the provider (DeveloperAgent.merge_pull_request is gone).
    merge = MagicMock(return_value={"status": "MERGED", "merged": True} if merged else {"status": "FAILED", "merged": False})
    monkeypatch.setattr(gw, "_release_vcs", lambda kind, pid, repo: MagicMock(merge_pull_request=merge))
    monkeypatch.setattr(gw, "evaluate_release_decision", lambda **kw: _gate_decision(True))
    # FD-4F 19e (lane 13, owner-approved): auto-merge needs commit-bound QA evidence for this trace. The evidence
    # binding itself is tested in tests/test_fd4f_release_evidence.py; here a store holds passing evidence and the
    # binding check is satisfied, so this test keeps asserting only the FD-4BO certificate hand-off.
    from fd4f_support import FakeDB

    evidence_db = FakeDB()
    evidence_db.docs["qa_test_runs/t1"] = {"passed": True, "security_lens": {"passed": True},
                                           "adherence_lens": {"passed": True},
                                           "commit_sha": "a" * 40}  # FD-4P: QA tested the ledger commit
    evidence_db.docs["workloads/p1"] = {"require_human_code_review": False, "vcs_provider": vcs_provider}
    from shared import vcs_ledger
    vcs_ledger.record_created(
        evidence_db, provider=vcs_provider, repo_full_name="acme/p1-repo",
        repo_id=9 if vcs_provider == "GITHUB" else None, product_id="p1", trace_id="t1",
        origin=vcs_ledger.ORIGIN_DEVELOPER, branch="feature/x", base_branch="main", head_sha="a" * 40,
        pr_number=42 if vcs_provider == "GITHUB" else None,
        pr_url="https://github.com/acme/p1-repo/pull/42" if vcs_provider == "GITHUB" else None)
    import google.cloud.firestore as fs_mod
    monkeypatch.setattr(fs_mod, "Client", lambda *a, **kw: evidence_db)
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project")  # release_promote reads the store only with a project
    monkeypatch.setattr(gw, "_qa_evidence_problems", lambda *a, **kw: [])
    poster = MagicMock(return_value=True)
    monkeypatch.setattr(gw, "post_release_certificate_to_vcs", poster)
    return poster


def test_release_promote_hands_certificate_to_vcs_with_pr_number(gw, monkeypatch):
    """FD-4P (S14): the PR number comes from the PR ledger, never from a URL regex."""
    poster = _wire_release(gw, monkeypatch, True)
    out = gw.release_promote(gw.ReleasePromoteRequest(product_id="p1", branch_name="feature/x", trace_id="t1"))
    assert out["auto_merged"] is True
    poster.assert_called_once()
    kw = poster.call_args.kwargs
    assert kw["pr_number"] == 42
    assert kw["full_repo_name"] == "acme/p1-repo"
    assert kw["markdown_content"] == "## Release Certificate\nPASS"


def test_release_promote_branch_url_gives_no_pr_number(gw, monkeypatch):
    """Serverless Git has no PR objects: the ledger has no PR number, the poster gets None and skips (its existing
    contract). A merge that did not complete is not a merge (HITL card)."""
    poster = _wire_release(gw, monkeypatch, False, vcs_provider="SERVERLESS_GIT")
    out = gw.release_promote(gw.ReleasePromoteRequest(product_id="p1", branch_name="feature/x", trace_id="t1"))
    assert out["auto_merged"] is False and out["approval_id"]
    poster.assert_called_once()
    assert poster.call_args.kwargs["pr_number"] is None


# ============================================================================================ FD-4BP behaviour
class _FakeDoc:
    def __init__(self, store, path):
        self.store, self.path = store, path

    def get(self):
        return SimpleNamespace(exists=False, to_dict=lambda: {})

    def set(self, data, merge=False):
        self.store.setdefault(self.path, []).append(data)

    def collection(self, name):
        return _FakeColl(self.store, f"{self.path}/{name}")


class _FakeColl:
    def __init__(self, store, path):
        self.store, self.path = store, path

    def document(self, doc_id):
        return _FakeDoc(self.store, f"{self.path}/{doc_id}")


class _FakeFirestoreClient:
    def __init__(self, store):
        self.store = store

    def collection(self, name):
        return _FakeColl(self.store, name)


@pytest.fixture()
def architect(monkeypatch):
    for k in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "PROJECT_ID"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ENABLE_DUAL_ARCHITECT_CONSENSUS", "false")
    from architect_agent import handler as h

    store = {}
    fake_fs = SimpleNamespace(Client=lambda *a, **kw: _FakeFirestoreClient(store))
    import google.cloud
    monkeypatch.setattr(sys.modules["google.cloud"], "firestore", fake_fs, raising=False)
    monkeypatch.setitem(sys.modules, "google.cloud.firestore", fake_fs)
    monkeypatch.setattr(h.ArchitectAgent, "persist_build_plan_to_firestore", lambda self, *a, **kw: True)
    monkeypatch.setattr(h.ArchitectAgent, "persist_implementation_plan_to_firestore", lambda self, *a, **kw: True)
    monkeypatch.setattr(h, "get_model_cascade_for_agent", lambda *a, **kw: ["fake-model"])
    monkeypatch.setattr(h, "build_architect_system_prompt", lambda **kw: "RENDERED ARCHITECT PROMPT")
    # No legacy Vertex SDK init (it would look up ADC): `import vertexai` raises ImportError -> fallback mode.
    monkeypatch.setitem(sys.modules, "vertexai", None)

    agent = h.ArchitectAgent(project_id="")
    agent.project_id = "mock-stackvend-project"  # enables the stage-trace branch (the Firestore client is the fake)
    agent.genai_client = None
    agent.model = None
    agent.spec_decomposer = None
    return h, agent, store


def _architect_trace(store, trace):
    return store.get(f"pipeline_executions/{trace}/stage_traces/architect")


def test_architect_stage_trace_written_with_raw_model_output(architect):
    h, agent, store = architect
    raw = json.dumps({**json.loads(agent._fallback_plan("p2", "Build a todo API on Cloud Run").model_dump_json()),
                      "service_topology": {"services": [{"name": "p2", "kind": "cloudrun"}],   # lane 10
                                           "primary_service": "p2"}})
    client = MagicMock()
    client.models.generate_content.return_value = SimpleNamespace(text=raw, candidates=[], usage_metadata=None)
    agent.genai_client = client

    agent.decompose(spec_text="Build a todo API on Cloud Run", product_id="p2", trace_id="t2")

    writes = _architect_trace(store, "t2")
    assert writes, f"architect stage trace was not written; store keys: {sorted(store)}"
    payload = writes[0]
    assert payload["stage_name"] == "architect"
    assert payload["trace_id"] == "t2"
    assert payload["agent_output"] == raw
    assert payload["rendered_prompt"] == "RENDERED ARCHITECT PROMPT"


def test_architect_stage_trace_falls_back_to_plan_json_without_model(architect):
    """No model output (deterministic fallback plan): the trace keeps the original fallback contract -- plan JSON and
    the static system prompt."""
    h, agent, store = architect
    # Lane 10 (plan §5.2): the fallback plan fails the topology gate typed; the stage trace is still written first.
    with pytest.raises(h.GateUnavailableError):   # lane 10 RT F7: no model answered -> unavailable
        agent.decompose(spec_text="Build a todo API on Cloud Run", product_id="p3", trace_id="t3")

    writes = _architect_trace(store, "t3")
    assert writes, f"architect stage trace was not written; store keys: {sorted(store)}"
    payload = writes[0]
    assert json.loads(payload["agent_output"])["product_id"] == "p3"
    assert payload["rendered_prompt"] == h.ARCHITECT_SYSTEM_PROMPT
    assert payload["topology_error"]["reason"] == "ARCHITECT_NO_MODEL_RESPONSE"
