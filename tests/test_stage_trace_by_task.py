"""STAGE-TRACE-BY-TASK (owner 11-13): one stage-trace record per junior task.

11-13 ex08: the wave 1 `task-domain-schemas` and wave 2 `task-backend-api` tasks were both BACKEND_ENGINEER, and the
wave 2 trace overwrote the wave 1 one (`developer_junior_backend_engineer`), so per-task evidence was lost. Each task
now has `developer_task_<task_id>`; the persona record the Control Center's agent view reads is kept as before.

Hermetic: in-memory Firestore stand-in.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys

from fd4f_support import FakeDB

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GW_DIR = os.path.join(REPO, "apps", "orchestrator-gateway")
if GW_DIR not in sys.path:
    sys.path.insert(0, GW_DIR)

from developer_agent.swarm_dispatcher import SwarmDispatcher, junior_task_trace_doc_id  # noqa: E402
from developer_agent.swarm_schemas import (JuniorExecutionResult, JuniorPersona,  # noqa: E402
                                           JuniorTaskAssignment)

PFX = "pipeline_executions/tr-1/stage_traces/"


def _task(task_id, wave, files):
    return JuniorTaskAssignment(task_id=task_id, persona=JuniorPersona.BACKEND_ENGINEER, wave=wave,
                                assigned_files=list(files), task_objective="build it")


def _result(task, files, seconds):
    return JuniorExecutionResult(task_id=task.task_id, persona=task.persona, wave=task.wave, files=files,
                                 consumed_tokens=100, duration_seconds=seconds, rendered_prompt=f"prompt {task.task_id}")


def test_two_tasks_of_one_persona_keep_two_records():
    db = FakeDB()
    disp = SwarmDispatcher(genai_client=None, model_name="m", db=db)
    t1 = _task("task-domain-schemas", 1, ["apps/a/schemas/models.py"])
    t2 = _task("task-backend-api", 2, ["apps/a/main.py"])
    disp._persist_junior_stage_trace("tr-1", t1, _result(t1, {"apps/a/schemas/models.py": "x"}, 167.18))
    disp._persist_junior_stage_trace("tr-1", t2, _result(t2, {"apps/a/main.py": "y"}, 202.72))
    one = db.docs[PFX + "developer_task_task-domain-schemas"]
    two = db.docs[PFX + "developer_task_task-backend-api"]
    assert one["duration_seconds"] == 167.18 and one["task_id"] == "task-domain-schemas" and one["wave"] == 1
    assert two["duration_seconds"] == 202.72 and two["rendered_prompt"] == "prompt task-backend-api"
    assert "models.py" in one["agent_output"] and "main.py" in two["agent_output"]


def test_negative_persona_record_is_kept_as_before():
    """The Control Center's agent view reads developer_junior_<persona>: still written, the persona's latest task."""
    db = FakeDB()
    disp = SwarmDispatcher(genai_client=None, model_name="m", db=db)
    t1 = _task("task-a", 1, ["a.py"])
    t2 = _task("task-b", 2, ["b.py"])
    disp._persist_junior_stage_trace("tr-1", t1, _result(t1, {"a.py": "1"}, 1.0))
    disp._persist_junior_stage_trace("tr-1", t2, _result(t2, {"b.py": "2"}, 2.0))
    persona = db.docs[PFX + "developer_junior_backend_engineer"]
    assert persona["task_id"] == "task-b" and persona["subagent_persona"] == "BACKEND_ENGINEER"
    for key in ("trace_id", "stage_name", "rendered_prompt", "agent_output", "created_at", "output_tokens",
                "duration_seconds", "is_few_shot_candidate"):
        assert key in persona, key
    assert persona["stage_name"] == "developer"


def test_task_ids_that_are_not_plain_get_a_hashed_document_id():
    assert junior_task_trace_doc_id("task-qa-tests") == "developer_task_task-qa-tests"
    for weird in ("a/b", "..", "", "x" * 300, "tést"):
        doc = junior_task_trace_doc_id(weird)
        assert doc.startswith("developer_task_sha256_") and "/" not in doc
    assert junior_task_trace_doc_id("a/b") != junior_task_trace_doc_id("a/c")


def test_negative_no_db_or_trace_writes_nothing():
    db = FakeDB()
    t = _task("task-a", 1, ["a.py"])
    SwarmDispatcher(genai_client=None, model_name="m", db=None)._persist_junior_stage_trace("tr-1", t,
                                                                                             _result(t, {}, 1.0))
    SwarmDispatcher(genai_client=None, model_name="m", db=db)._persist_junior_stage_trace(None, t, _result(t, {}, 1.0))
    assert db.docs == {}
