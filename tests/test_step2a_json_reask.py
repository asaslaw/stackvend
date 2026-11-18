"""Step 2 S2-A A1/A2 (register HS-61, HS-12): invalid JSON from an LLM is re-asked with the parser's exact message
(V6, JSON.OUTPUT_INVALID) instead of being re-sent blindly (swarm juniors) or regex-patched (single-turn HB-50); three
invalid answers stop with a typed CODE_DEFECT. Fakes stand in for the LLM; no network, no credentials."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import asyncio
import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from developer_agent.swarm_dispatcher import JSON_REASK, SwarmDispatcher  # noqa: E402
from developer_agent.swarm_schemas import (JuniorPersona, JuniorTaskAssignment,  # noqa: E402
                                           LeadDeveloperDecompositionPlan, PoisonedContractEscalationError,
                                           SwarmExecutionMode)
from shared.diagnostics import ErrorClass, StageError  # noqa: E402

VALID = json.dumps({"files": {"apps/api/main.py": "import re\nP = re.compile(r'\\d+')\nS = 'caf\u00e9\\n'\n"}})
INVALID = '{"files": {"apps/api/main.py": "P = re.compile(r\'\\d+\')"}}'   # \d is not a JSON escape


class FakeModels:
    def __init__(self, texts):
        self.texts, self.calls, self.models = list(texts), [], []

    def generate_content(self, model, contents, config):
        self.calls.append(contents)
        self.models.append(model)
        text = self.texts.pop(0)
        if isinstance(text, Exception):
            raise text
        return SimpleNamespace(text=text, candidates=[SimpleNamespace(finish_reason="STOP")],
                               usage_metadata=SimpleNamespace(total_token_count=10))


def _task():
    t = JuniorTaskAssignment(task_id="task-api", persona=JuniorPersona.BACKEND_ENGINEER, wave=1,
                             assigned_files=["apps/api/main.py"], task_objective="api")
    return t, LeadDeveloperDecompositionPlan(execution_mode=SwarmExecutionMode.STANDARD_SWARM, tasks=[t])


def _run(texts, cascade=()):
    models = FakeModels(texts)
    d = SwarmDispatcher(genai_client=SimpleNamespace(models=models))
    task, plan = _task()
    with patch("developer_agent.swarm_dispatcher.get_model_cascade_for_agent", return_value=list(cascade)), \
            patch("shared.settings.get_platform_settings", side_effect=RuntimeError("no settings in tests")), \
            patch("developer_agent.swarm_dispatcher.resolve_junior_prompt", return_value="sys"), \
            patch("asyncio.sleep", new_callable=AsyncMock):
        try:
            return asyncio.run(d.invoke_junior_worker(task, plan, {}, "m")), models, d
        except (StageError, PoisonedContractEscalationError) as e:
            return e, models, d


def test_valid_envelope_is_sent_once_and_parsed_unchanged():
    """Do No Harm: a valid envelope (with \\\\d and an escaped unicode char) -> one request, no re-ask."""
    res, models, d = _run([VALID])
    assert res.status == "SUCCEEDED" and len(models.calls) == 1
    assert res.files == json.loads(VALID)["files"]
    assert "JSON.OUTPUT_INVALID" not in models.calls[0]
    assert [c["ok"] for c in d.envelope_checks] == [True]


def test_invalid_json_is_re_asked_with_the_parser_message():
    res, models, d = _run([INVALID, VALID])
    assert res.status == "SUCCEEDED" and len(models.calls) == 2
    second = models.calls[1]
    assert second.startswith(models.calls[0])                      # same request, plus the typed re-ask
    assert "ERROR JSON.OUTPUT_INVALID" in second and "Invalid \\escape" in second and "line 1 column" in second
    assert [c["ok"] for c in d.envelope_checks] == [False, True]


def test_every_attempt_invalid_is_a_typed_code_defect_never_a_silent_drop():
    res, models, _ = _run([INVALID] * 4)
    assert isinstance(res, StageError) and len(models.calls) == 4
    assert res.error_class is ErrorClass.CODE_DEFECT
    [diag] = res.report.diagnostics
    assert diag.code == "JSON.OUTPUT_INVALID" and diag.file == "<junior:task-api>" and "Invalid \\escape" in diag.message


def test_handler_reraises_typed_swarm_failures_and_hb50_regex_is_gone():
    src = open(os.path.join(GATEWAY, "developer_agent", "handler.py")).read()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "generate_code_files")
    seg = ast.get_source_segment(src, fn)
    # HB-50 tombstone: no regex substitution of backslashes in the single-turn JSON path
    subs = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            and n.func.attr == "sub" and isinstance(n.func.value, ast.Name) and n.func.value.id == "re"]
    assert not any("\\\\" in (ast.get_source_segment(src, s) or "") for s in subs)
    assert "JSON_REASK_PREVIOUS_ATTEMPT.format" in seg
    handlers = [h for n in ast.walk(fn) if isinstance(n, ast.Try) for h in n.handlers]
    assert any(isinstance(h.type, ast.Name) and h.type.id == "StageError" and any(isinstance(x, ast.Raise)
               for x in ast.walk(h)) for h in handlers)
    assert "{error}" in JSON_REASK


# ------------------------------------------------------------------------------------------------ code RT F3 / F4
def test_re_ask_goes_to_the_model_that_produced_the_error_and_notes_never_stack():
    res, models, d = _run([INVALID, INVALID, VALID], cascade=["m2", "m3"])
    assert res.status == "SUCCEEDED" and models.models == ["m", "m", "m"]       # same model, no cascade on V6
    first, second, third = models.calls
    assert second.startswith(first) and third.startswith(first)
    assert second.count("ERROR JSON.OUTPUT_INVALID") == 1 and third.count("ERROR JSON.OUTPUT_INVALID") == 1
    assert third == second                                                       # replaced, not appended
    # F4: each re-ask is recorded for the run record
    assert [(r["kind"], r["task_id"], r["attempt"], r["model"]) for r in d.junior_reasks] == [
        ("junior_reask", "task-api", 1, "m"), ("junior_reask", "task-api", 2, "m")]
    assert all("Invalid \\escape" in r["error"] and r["files"] == ["apps/api/main.py"] for r in d.junior_reasks)


def test_a_transient_failure_still_cascades():
    res, models, _ = _run([RuntimeError("boom"), VALID], cascade=["m2"])
    assert res.status == "SUCCEEDED" and models.models == ["m", "m2"]


def test_mixed_invalid_and_other_failures_escalate_not_typed():
    # mutation M5 (typed failure on >= 1 invalid attempt) must fail here: only ALL-invalid is JSON.OUTPUT_INVALID
    res, models, _ = _run([INVALID, RuntimeError("boom"), RuntimeError("boom"), RuntimeError("boom")])
    assert isinstance(res, PoisonedContractEscalationError) and len(models.calls) == 4


def test_handler_records_junior_reasks_as_repair_events():
    from developer_agent.handler import DeveloperAgent
    from shared.diagnostics import RepairEvent
    agent = DeveloperAgent.__new__(DeveloperAgent)
    agent._last_junior_reasks = [{"kind": "junior_reask", "task_id": "t", "persona": "backend_engineer",
                                  "attempt": 1, "model": "m", "files": ["apps/api/main.py"], "error": "E"}]
    [ev] = agent._junior_reask_events("trace", "shop")
    assert isinstance(ev, RepairEvent) and ev.kind == "junior_reask" and ev.task_id == "t" and ev.attempt == 1
    assert ev.codes == ["JSON.OUTPUT_INVALID"] and ev.detail == "E" and ev.accepted is False
    assert ev.reject_reason == "ENVELOPE_INVALID" and ev.persona == "backend_engineer"
    # a repair-loop event keeps its old shape (kind defaults to "repair")
    assert RepairEvent(trace_id="t", product_id="p", iteration=1, source="precommit", persona="p", files=[], codes=[],
                       fingerprints_before=[], fingerprints_after=[], accepted=True, model="m").kind == "repair"


def _single_turn(texts):
    from developer_agent.handler import DeveloperAgent
    no_cloud = RuntimeError("no cloud clients in this test")
    models = FakeModels(texts)
    with patch("google.cloud.firestore.Client", side_effect=no_cloud), \
            patch("google.genai.Client", return_value=SimpleNamespace(models=models)), \
            patch("google.auth.default", side_effect=no_cloud), \
            patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false"}), \
            patch("developer_agent.handler.get_model_cascade_for_agent", return_value=["m1", "m2", "m3"]), \
            patch("shared.settings.get_platform_settings", side_effect=no_cloud), \
            patch.object(DeveloperAgent, "fetch_github_token", return_value=""), \
            patch.object(DeveloperAgent, "fetch_existing_repo_files", return_value={}):
        agent = DeveloperAgent(project_id="test-proj")
        agent.model_name = "m1"
        agent.genai_client = SimpleNamespace(models=models)
        files = agent.generate_code_files(product_id="api", spec_text="Build an API",
                                          task_dag=[{"step_id": "STEP-06-COMPUTE", "title": "x", "depends_on": []}], allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False)
    return files, models


def test_single_turn_invalid_json_is_re_asked_with_the_parser_message_behaviourally():
    """HS-12 behavioural test (code RT F3): first answer invalid, second valid -> the second request (next model of
    the cascade) carries the parser's message about the previous attempt, and its files are used."""
    files, models = _single_turn([INVALID, VALID])
    assert len(models.calls) == 2 and models.models[:2] == ["m1", "m2"]
    first, second = models.calls
    assert second.startswith(first)
    assert second.count("ERROR JSON.OUTPUT_INVALID") == 1 and "the previous attempt's response" in second
    assert "Invalid \\escape" in second
    assert files["apps/api/main.py"] == json.loads(VALID)["files"]["apps/api/main.py"]


def test_single_turn_notes_are_replaced_not_stacked():
    files, models = _single_turn([INVALID, INVALID, VALID])
    assert len(models.calls) == 3 and models.models == ["m1", "m2", "m3"]
    assert models.calls[2].count("ERROR JSON.OUTPUT_INVALID") == 1 and models.calls[2] == models.calls[1]
    assert files["apps/api/main.py"] == json.loads(VALID)["files"]["apps/api/main.py"]


@pytest.fixture(autouse=True)
def _fd7m_a_no_record_region(monkeypatch):
    """FD-7M-a (SAT-23 RT F1): these tests build developer agents without a Firestore client while the test env
    configures a project, which the dispatch now refuses (REGION_UNAVAILABLE: the recorded region cannot be read).
    They are not about regions: keep the platform-region answer they always had (the record-region paths are covered
    by tests/test_fd7m_a_regions_gw.py)."""
    from developer_agent import handler as _handler
    from developer_agent import terraform_engine as _engine
    monkeypatch.setattr(_handler, "resolve_workload_region",
                        lambda db=None, product_id=None, **kw: _engine.resolve_workload_region(db, **kw))
