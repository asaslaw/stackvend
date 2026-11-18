"""RT14-23 (full-scope red-team 11-14, owner "fix both high and medium before launch"): the swarm's FinOps circuit
breaker is a typed developer stop (SWARM_TOKEN_ENVELOPE_EXCEEDED). It was a plain Exception, so the handler's broad
swarm `except` swallowed it and ran the unmetered single-turn build instead. Plan: docs/planning/rt14-developer-qa-context-plan.md.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import ast
import asyncio
import os
import sys
from unittest.mock import patch

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO, "apps", "orchestrator-gateway"))
sys.path.insert(0, os.path.dirname(__file__))

from developer_agent import handler as H  # noqa: E402
from developer_agent.errors import (  # noqa: E402
    ERROR_CLASSES,
    SWARM_TOKEN_ENVELOPE_EXCEEDED,
    DeveloperStageError,
)
from developer_agent.handler import DeveloperAgent  # noqa: E402
from developer_agent.swarm_dispatcher import SwarmDispatcher  # noqa: E402
from developer_agent.swarm_schemas import (  # noqa: E402
    FinOpsCircuitBreakerError,
    JuniorExecutionResult,
    JuniorPersona,
    JuniorTaskAssignment,
    LeadDeveloperDecompositionPlan,
    PoisonedContractEscalationError,
    SwarmExecutionMode,
)

HANDLER_SRC = os.path.join(REPO, "apps", "orchestrator-gateway", "developer_agent", "handler.py")


class _Models:
    def __init__(self, text):
        self.text = text
        self.calls = 0

    def generate_content(self, model=None, contents=None, config=None):
        from types import SimpleNamespace
        self.calls += 1
        return SimpleNamespace(text=self.text, candidates=[], usage_metadata=None)


class _Client:
    def __init__(self, text='{"files": {"apps/a/main.py": "x"}}'):
        self.models = _Models(text)


@pytest.fixture(autouse=True)
def _no_firestore():
    with patch("google.cloud.firestore.Client", side_effect=RuntimeError("no Firestore in this test")):
        yield


@pytest.fixture(autouse=True)
def _platform_region(monkeypatch):
    """Not about regions (tests/test_lane19_no_template.py's fixture): the platform-region answer, no record read."""
    from developer_agent import terraform_engine as _engine
    monkeypatch.setattr(H, "resolve_workload_region",
                        lambda db=None, product_id=None, **kw: _engine.resolve_workload_region(db, **kw))


def _agent(client):
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": ""}):
        a = DeveloperAgent()
    a.model_name = "model-a"
    a.genai_client = client
    return a


def _plan(envelope=350_000):
    return LeadDeveloperDecompositionPlan(
        execution_mode=SwarmExecutionMode.STANDARD_SWARM, iac_engine="OPENTOFU", vcs_provider="GITHUB",
        max_swarm_token_envelope=envelope,
        tasks=[JuniorTaskAssignment(task_id="t1", persona=JuniorPersona.BACKEND_ENGINEER, wave=1,
                                    assigned_files=["apps/a/main.py"], task_objective="x")])


def _run(agent):
    with patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "true"}), \
            patch.object(agent, "fetch_existing_repo_files", return_value={}), \
            patch.object(agent, "update_build_step_status"), \
            patch.object(H, "get_model_cascade_for_agent", return_value=["model-a"]), \
            patch.object(H, "wait_for_rate_limit_cooldown", return_value=True):
        return agent.generate_code_files(product_id="noapp", spec_text="An app", task_dag=[],
                                         allow_unauthenticated=True, enable_direct_iap=False,
                                         domain_restricted_sharing=False)


def test_breaker_is_a_typed_developer_stop():
    err = FinOpsCircuitBreakerError("over")
    assert isinstance(err, DeveloperStageError)
    assert err.error_class == SWARM_TOKEN_ENVELOPE_EXCEEDED and SWARM_TOKEN_ENVELOPE_EXCEEDED in ERROR_CLASSES


def test_dispatcher_trip_raises_the_typed_class():
    d = SwarmDispatcher(genai_client=None)

    async def worker(*a, **k):
        return JuniorExecutionResult(task_id="t1", persona=JuniorPersona.BACKEND_ENGINEER, wave=1,
                                     files={"apps/a/main.py": "x"}, consumed_tokens=20_000)

    d.invoke_junior_worker = worker
    with pytest.raises(DeveloperStageError) as e:
        asyncio.run(d.execute_phased_junior_swarm(_plan(envelope=10_000), "trace", "noapp"))
    assert e.value.error_class == SWARM_TOKEN_ENVELOPE_EXCEEDED


def test_tripped_breaker_never_falls_back_to_the_single_turn_build():
    client = _Client()
    agent = _agent(client)
    with patch.object(H.LeadDeveloperOrchestrator, "decompose_specification", return_value=_plan()), \
            patch.object(SwarmDispatcher, "execute_phased_junior_swarm",
                         side_effect=FinOpsCircuitBreakerError("FinOps Circuit Breaker Tripped")):
        with pytest.raises(DeveloperStageError) as e:
            _run(agent)
    assert e.value.error_class == SWARM_TOKEN_ENVELOPE_EXCEEDED
    assert client.models.calls == 0          # the unmetered single-turn path never ran


def test_do_no_harm_other_swarm_errors_still_fall_back():
    """Negative test: a non-budget swarm error (here a poisoned contract) keeps today's single-turn fallback."""
    client = _Client()
    agent = _agent(client)
    with patch.object(H.LeadDeveloperOrchestrator, "decompose_specification", return_value=_plan()), \
            patch.object(SwarmDispatcher, "execute_phased_junior_swarm",
                         side_effect=PoisonedContractEscalationError("junior output unusable")):
        try:
            _run(agent)
        except DeveloperStageError as e:   # the canned single-turn answer may not be a full workload
            assert e.error_class != SWARM_TOKEN_ENVELOPE_EXCEEDED
    assert client.models.calls > 0


def _swarm_try(tree):
    """The try statement whose body calls `execute_phased_junior_swarm` (the swarm attempt in generate_code_files)."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and any(
                isinstance(n, ast.Attribute) and n.attr == "execute_phased_junior_swarm"
                for b in node.body for n in ast.walk(b)):
            return node
    return None


def test_guard_typed_stops_are_reraised_before_the_broad_except():
    """Mechanism guard (AST, no text matching): in the swarm attempt, DeveloperStageError (every typed developer stop,
    the breaker included) and stage_deadline.STOP_ERRORS are re-raised by handlers placed BEFORE `except Exception`."""
    tree = ast.parse(open(HANDLER_SRC, encoding="utf-8").read())
    node = _swarm_try(tree)
    assert node is not None
    names = []
    for h in node.handlers:
        t = h.type
        names.append(ast.unparse(t) if t is not None else "<bare>")
    broad = names.index("Exception")
    reraise = {ast.unparse(h.type) for h in node.handlers[:broad]
               if any(isinstance(s, ast.Raise) and s.exc is None for s in h.body)}
    assert {"DeveloperStageError", "stage_deadline.STOP_ERRORS"} <= reraise
