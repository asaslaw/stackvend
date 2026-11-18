"""PLAN-CONTRACT-CHECK W2 (plan sections 2.1, 3.3, 8.3): the gateway's wiring for the architect plan contract check.

- `main._architect_vcs_kind(product_id)`: the workload's VCS kind by `_workload_vcs_kind`'s rule; every unreadable
  case (no product id, no governance store, no record, read error) is None, never a guess and never an exception.
- `main._architect_decompose_body` passes that value to `ArchitectAgent.decompose(vcs_kind=...)`.
- `DualArchitectConsensusEngine._draft_plan_json(plan, subject=None)`: with no subject the text is byte-identical to
  the consensus remediation turn's text before this change (Do No Harm); with a subject the trailer names it.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import logging
import os
import sys
from types import SimpleNamespace

import pytest

from fd4f_support import FakeDB, gw  # noqa: F401  (gw is a fixture)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GW_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
if GW_DIR not in sys.path:
    sys.path.insert(0, GW_DIR)


# ------------------------------------------------------------------ _architect_vcs_kind
def _db_with(product_id="app", record=None):
    db = FakeDB()
    if record is not None:
        db.docs[f"workloads/{product_id}"] = record
    return db


def test_vcs_kind_no_governance_store_is_none(gw, monkeypatch, caplog):
    monkeypatch.setattr(gw, "db", None)
    with caplog.at_level(logging.WARNING):
        assert gw._architect_vcs_kind("app") is None
    assert "no governance store" in caplog.text


def test_vcs_kind_missing_record_is_none_not_github(gw, monkeypatch):
    # _workload_vcs_kind({}) would say GITHUB; a missing record is unknown, never the default.
    db = _db_with()
    monkeypatch.setattr(gw, "db", db)
    assert gw._architect_vcs_kind("app") is None
    assert db.writes == []


def test_vcs_kind_read_error_is_none(gw, monkeypatch, caplog):
    db = _db_with(record={"vcs_provider": "GITHUB"})
    db.fail_reads = True
    monkeypatch.setattr(gw, "db", db)
    with caplog.at_level(logging.WARNING):
        assert gw._architect_vcs_kind("app") is None
    assert "unreadable" in caplog.text


def test_vcs_kind_record_none_from_reader_is_none(gw, monkeypatch):
    monkeypatch.setattr(gw, "db", FakeDB())
    monkeypatch.setattr(gw, "_read_workload", lambda gdb, pid: None)
    assert gw._architect_vcs_kind("app") is None


@pytest.mark.parametrize("pid", [None, "", 7])
def test_vcs_kind_no_product_id_is_none_and_reads_nothing(gw, monkeypatch, pid):
    calls = []
    monkeypatch.setattr(gw, "db", FakeDB())
    monkeypatch.setattr(gw, "_read_workload", lambda gdb, p: calls.append(p) or {})
    assert gw._architect_vcs_kind(pid) is None
    assert calls == []


@pytest.mark.parametrize("record, expected", [
    ({}, "GITHUB"),                                   # absent value => GITHUB (the default everywhere)
    ({"vcs_provider": None}, "GITHUB"),
    ({"vcs_provider": ""}, "GITHUB"),
    ({"vcs_provider": "GITHUB"}, "GITHUB"),
    ({"vcs_provider": "SERVERLESS_GIT"}, "SERVERLESS_GIT"),
    ({"vcs_provider": " serverless_git "}, "SERVERLESS_GIT"),   # _workload_vcs_kind's own normalisation
    ({"vcs_provider": "GITLAB"}, None),               # invalid => None
    ({"vcs_provider": 5}, None),
])
def test_vcs_kind_follows_the_workload_rule(gw, monkeypatch, record, expected):
    db = _db_with(record=record)
    monkeypatch.setattr(gw, "db", db)
    assert gw._architect_vcs_kind("app") == expected
    assert gw._architect_vcs_kind("app") == gw._workload_vcs_kind(record)
    assert db.writes == []                            # read-only


def test_vcs_kind_reads_the_named_workload_only(gw, monkeypatch):
    db = FakeDB()
    db.docs["workloads/other"] = {"vcs_provider": "SERVERLESS_GIT"}
    db.docs["workloads/app"] = {"vcs_provider": "GITHUB"}
    monkeypatch.setattr(gw, "db", db)
    assert gw._architect_vcs_kind("app") == "GITHUB"
    assert gw._architect_vcs_kind("other") == "SERVERLESS_GIT"
    assert gw._architect_vcs_kind("missing") is None


# ------------------------------------------------------------------ _architect_decompose_body
class _FakeArchitect:
    calls = []

    def __init__(self, *a, **kw):
        pass

    def decompose(self, **kw):
        _FakeArchitect.calls.append(kw)
        plan = SimpleNamespace(requires_human_approval=False, risk_assessment="low", model_dump=lambda: {"p": 1})
        return SimpleNamespace(trace_id=kw.get("trace_id"), product_id=kw.get("product_id"), task_dag=[],
                               infra_plan={}, markdown_summary="", plan_markdown="", plan_file_path=None,
                               architecture_plan=plan, compute_intent=None, consensus_telemetry=None)


@pytest.fixture()
def fake_architect(monkeypatch):
    import architect_agent.handler as handler_mod
    _FakeArchitect.calls = []
    monkeypatch.setattr(handler_mod, "ArchitectAgent", _FakeArchitect)
    return _FakeArchitect


@pytest.mark.parametrize("record, expected", [
    ({"vcs_provider": "SERVERLESS_GIT"}, "SERVERLESS_GIT"),
    ({}, "GITHUB"),
    (None, None),                                     # no record
])
def test_decompose_body_passes_the_vcs_kind(gw, monkeypatch, fake_architect, record, expected):
    monkeypatch.setattr(gw, "db", _db_with(record=record))
    req = gw.ArchitectDecomposeRequest(trace_id="tr-1", product_id="app", spec_text="spec")
    out = gw._architect_decompose_body(req)
    assert out["status"] == "SUCCESS"
    assert len(fake_architect.calls) == 1
    assert "vcs_kind" in fake_architect.calls[0]
    assert fake_architect.calls[0]["vcs_kind"] == expected


def test_decompose_body_without_store_passes_none(gw, monkeypatch, fake_architect):
    monkeypatch.setattr(gw, "db", None)
    req = gw.ArchitectDecomposeRequest(trace_id="tr-1", product_id="app", spec_text="spec")
    gw._architect_decompose_body(req)
    assert fake_architect.calls[0]["vcs_kind"] is None


def test_decompose_body_read_error_still_runs_the_architect(gw, monkeypatch, fake_architect):
    db = _db_with(record={"vcs_provider": "GITHUB"})
    db.fail_reads = True
    monkeypatch.setattr(gw, "db", db)
    req = gw.ArchitectDecomposeRequest(trace_id="tr-1", product_id="app", spec_text="spec")
    assert gw._architect_decompose_body(req)["status"] == "SUCCESS"
    assert fake_architect.calls[0]["vcs_kind"] is None


# ------------------------------------------------------------------ _draft_plan_json(plan, subject=None)
def _engine():
    from architect_agent.consensus_engine import DualArchitectConsensusEngine
    return DualArchitectConsensusEngine


def _text_before_this_change(text: str) -> str:
    """The consensus remediation turn's draft block exactly as it was before PLAN-CONTRACT-CHECK."""
    return (
        "\n\n--- DRAFT PLAN (typed JSON of the plan the critique is about) ---\n"
        f"{text}\n"
        "Return this plan with only the changes the critical faults above require; keep every other task, step, "
        "service and resource as it is.\n"
        "--- END DRAFT PLAN ---"
    )


_DICT_PLAN = {"infra_tasks": [{"task_id": "INFRA-01", "target_files": ["infra/workload/main.tf"]}], "b": [1, 2]}


def test_draft_plan_json_default_is_byte_identical_for_a_dict():
    eng = _engine()
    expected = _text_before_this_change(json.dumps(_DICT_PLAN, sort_keys=True, default=str))
    assert eng._draft_plan_json(_DICT_PLAN) == expected
    assert eng._draft_plan_json(_DICT_PLAN, subject=None) == expected
    assert eng._draft_plan_json(_DICT_PLAN, None) == expected


def test_draft_plan_json_default_is_byte_identical_for_a_typed_plan():
    from pydantic import BaseModel

    class _Plan(BaseModel):
        plan_id: str = "p-1"
        infra_tasks: list = [{"task_id": "INFRA-01", "target_files": ["cloudbuild.yaml"]}]
        plan_markdown: str = "# not sent"
        plan_file_path: str = "docs/plan.md"

    eng = _engine()
    p = _Plan()
    text = json.dumps(p.model_dump(mode="json", exclude={"plan_markdown", "plan_file_path"}),
                      sort_keys=True, default=str)
    assert eng._draft_plan_json(p) == _text_before_this_change(text)
    assert "not sent" not in eng._draft_plan_json(p)


def test_draft_plan_json_with_subject_names_the_contract():
    eng = _engine()
    out = eng._draft_plan_json(_DICT_PLAN, subject="the platform plan contract above")
    text = json.dumps(_DICT_PLAN, sort_keys=True, default=str)
    assert out == (
        "\n\n--- DRAFT PLAN (typed JSON of the plan the platform plan contract above is about) ---\n"
        f"{text}\n"
        "Return this plan with only the changes the platform plan contract above requires; keep every other task, "
        "step, service and resource as it is.\n"
        "--- END DRAFT PLAN ---"
    )
    assert "critique" not in out and "critical faults" not in out


def test_draft_plan_json_unserialisable_plan_still_returns_empty():
    class _Bad:
        def model_dump(self, **kw):
            raise TypeError("test double")

    eng = _engine()
    assert eng._draft_plan_json(_Bad()) == ""
    assert eng._draft_plan_json(_Bad(), subject="the platform plan contract above") == ""


def test_remediation_turn_brief_is_unchanged(monkeypatch):
    """The consensus remediation turn still calls the renderer with no subject (its prompt is byte-identical)."""
    eng = _engine()
    seen = []
    real = eng._draft_plan_json

    def spy(plan, *a, **kw):
        seen.append((a, kw))
        return real(plan, *a, **kw)

    monkeypatch.setattr(eng, "_draft_plan_json", staticmethod(spy))
    critique = SimpleNamespace(findings=[])          # the turn reads only `findings`
    briefs = []
    arch = SimpleNamespace(decompose=lambda **kw: briefs.append(kw["remediation_brief"]) or SimpleNamespace(
        architecture_plan=_DICT_PLAN))
    obj = eng.__new__(eng)
    obj._execute_remediation_turn(_DICT_PLAN, critique, "spec", arch, "app", "tr-1")
    assert seen == [((), {})]
    assert _text_before_this_change(json.dumps(_DICT_PLAN, sort_keys=True, default=str)) in briefs[0]
