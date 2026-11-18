"""RT14-30 (full-scope red-team 11-14): the architect's Firestore records are replaced, never deep-merged.

`pipeline_executions/{trace}.architect_compute_intent` was written with `set(..., merge=True)`. Firestore deep-merges
maps under merge=True, and a topology without push edges omits `pushes` (canonical form), so a REWORK from a push
topology to a pull topology kept the earlier `pushes` beside the new sha256: the approved run then failed with
TOPOLOGY.RECORD_SHA_MISMATCH. Every architect write of a nested map now uses a field-path merge (each listed field is
replaced as a whole), and the stage-trace document deletes this stage's optional fields that a run does not write.

The fake below applies Firestore's documented set() semantics and first builds the real client's write protobuf from
the same payload (google.cloud.firestore_v1._helpers), so a payload the real client would refuse fails here too.
Hermetic: no network, no real client.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import copy
import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GW_DIR = os.path.join(REPO, "apps", "orchestrator-gateway")
ARCH_DIR = os.path.join(GW_DIR, "architect_agent")
for p in (GW_DIR, REPO):
    if p not in sys.path:
        sys.path.insert(0, p)

from google.cloud.firestore_v1 import _helpers as fs_helpers  # noqa: E402
from google.cloud.firestore_v1.field_path import parse_field_path  # noqa: E402
from google.cloud.firestore_v1.transforms import DELETE_FIELD  # noqa: E402
from shared.service_topology import topology_from_record  # noqa: E402

PATH = "/api/v1/tasks/process"
EVENTS = {"type": "google_pubsub_topic", "logical_name": "events", "purpose": "events",
          "consumers": [{"service": "shop", "env_key": "EVENTS_TOPIC", "attribute": "id"}]}
PUSH_TOPO = {"services": [{"name": "shop", "kind": "cloudrun"}], "primary_service": "shop", "edges": [],
             "resources": [EVENTS], "pushes": [{"topic": "events", "service": "shop", "path": PATH}]}
PULL_TOPO = {"services": [{"name": "shop", "kind": "cloudrun"}], "primary_service": "shop", "edges": [],
             "resources": [EVENTS]}
BASE = {"product_id": "shop", "summary": "s", "architecture_overview": "o", "infra_tasks": [], "code_tasks": [],
        "target_compute_services": ["shop"], "compute_archetype": "cloudrun", "iac_engine": "tofu"}


def _deep_merge(dst, src):
    for k, v in src.items():
        if v is DELETE_FIELD:
            dst.pop(k, None)
        elif isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_merge(dst[k], v)
        else:
            dst[k] = copy.deepcopy(v)


class FirestoreSemantics:
    """In-memory documents with Firestore set() semantics: merge=False replaces the document, merge=True deep-merges
    maps, merge=[field paths] replaces exactly those fields (a DELETE_FIELD value removes one)."""

    def __init__(self):
        self.docs = {}

    def collection(self, c, prefix=""):
        store = self

        class _Doc:
            def __init__(self, path):
                self.path = path

            def set(self, data, merge=False):
                # the real client's own validation of the payload (raises ValueError on an invalid merge path)
                full = f"projects/p/databases/(default)/documents/{self.path}"
                if merge:
                    fs_helpers.pbs_for_set_with_merge(full, data, merge)
                else:
                    fs_helpers.pbs_for_set_no_merge(full, data)
                doc = store.docs.setdefault(self.path, {})
                if merge is True:
                    _deep_merge(doc, data)
                elif merge:
                    for raw in merge:
                        parts = parse_field_path(raw)
                        src, dst = data, doc
                        for part in parts[:-1]:
                            src = src[part]
                            dst = dst.setdefault(part, {})
                        v = src[parts[-1]]
                        if v is DELETE_FIELD:
                            dst.pop(parts[-1], None)
                        else:
                            dst[parts[-1]] = copy.deepcopy(v)
                else:
                    store.docs[self.path] = copy.deepcopy(data)

            def get(self):
                d = store.docs.get(self.path)
                return SimpleNamespace(exists=d is not None, to_dict=lambda: copy.deepcopy(d))

            def collection(self, sub):
                return store.collection(sub, prefix=f"{self.path}/")

        return SimpleNamespace(document=lambda d: _Doc(f"{prefix}{c}/{d}"))


class _Client:
    def __init__(self, plan):
        self.plan = plan
        self.models = SimpleNamespace(generate_content=self._gen)

    def _gen(self, model, contents, config):
        return SimpleNamespace(text=json.dumps(self.plan), candidates=[], usage_metadata=None)


@pytest.fixture()
def architect(monkeypatch):
    for k in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "PROJECT_ID", "K_SERVICE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ENABLE_DUAL_ARCHITECT_CONSENSUS", "false")
    fake_fs = SimpleNamespace(Client=lambda *a, **kw: MagicMock(), Increment=lambda n: ("INC", n))
    import google.cloud  # noqa: F401
    monkeypatch.setattr(sys.modules["google.cloud"], "firestore", fake_fs, raising=False)
    monkeypatch.setitem(sys.modules, "google.cloud.firestore", fake_fs)
    from architect_agent import handler as h
    monkeypatch.setattr(h.ArchitectAgent, "persist_build_plan_to_firestore", lambda self, *a, **kw: True)
    monkeypatch.setattr(h.ArchitectAgent, "persist_implementation_plan_to_firestore", lambda self, *a, **kw: True)
    monkeypatch.setattr(h, "get_model_cascade_for_agent", lambda *a, **kw: ["model-a"])
    monkeypatch.setattr(h, "build_architect_system_prompt", lambda **kw: "SYS")
    monkeypatch.setitem(sys.modules, "vertexai", None)
    agent = h.ArchitectAgent(project_id="")
    agent.project_id = "p"
    agent.db = FirestoreSemantics()
    agent.model_name = "model-a"
    agent.model = None
    agent.spec_decomposer = None
    return h, agent


def _decompose(agent, topo, **kw):
    agent.genai_client = _Client({**BASE, "service_topology": topo})
    return agent.decompose(spec_text="Build a shop", product_id="shop", trace_id="tr-30", **kw)


def test_rework_from_push_to_pull_leaves_no_stale_pushes_and_the_sha_matches(architect):
    h, agent = architect
    first = _decompose(agent, PUSH_TOPO)
    assert first.compute_intent["service_topology"]["intent"]["pushes"]
    second = _decompose(agent, PULL_TOPO, human_feedback="Use a pull subscription instead of the push endpoint.")
    stored = agent.db.docs["pipeline_executions/tr-30"]["architect_compute_intent"]
    assert stored == second.compute_intent
    assert "pushes" not in stored["service_topology"]["intent"]
    vt, diags = topology_from_record(stored["service_topology"], product_id="shop")
    assert vt is not None and not [d for d in diags if d.severity == "error"], diags
    # the old write mode on the same two payloads: the stale push survives next to the new sha256 (the defect)
    old = {}
    _deep_merge(old, {"architect_compute_intent": first.compute_intent})
    _deep_merge(old, {"architect_compute_intent": second.compute_intent})
    assert old["architect_compute_intent"]["service_topology"]["intent"].get("pushes")
    _, old_diags = topology_from_record(old["architect_compute_intent"]["service_topology"], product_id="shop")
    assert "TOPOLOGY.RECORD_SHA_MISMATCH" in {d.code for d in old_diags}


def test_negative_other_run_fields_are_kept(architect):
    """Do No Harm: only the architect's own field is replaced; the rest of the run document is untouched."""
    h, agent = architect
    agent.db.docs["pipeline_executions/tr-30"] = {"status": "RUNNING", "stages": {"vending": {"status": "OK"}}}
    res = _decompose(agent, PULL_TOPO)
    doc = agent.db.docs["pipeline_executions/tr-30"]
    assert doc["status"] == "RUNNING" and doc["stages"]["vending"] == {"status": "OK"}
    assert doc["architect_compute_intent"] == res.compute_intent


def test_rt_f4_rework_without_a_repair_clears_the_earlier_attempts_repair_events(architect):
    """RT F4: `stages.architect.repair_events` is this run's list, always written ([] without a repair turn), so a
    REWORK that needed no repair never shows the previous attempt's events; other stages are untouched."""
    h, agent = architect
    agent.db.docs["pipeline_executions/tr-30"] = {"stages": {"architect": {"repair_events": [{"iteration": 1}]},
                                                             "vending": {"status": "OK"}}}
    _decompose(agent, PULL_TOPO, human_feedback="Use a pull subscription instead of the push endpoint.")
    doc = agent.db.docs["pipeline_executions/tr-30"]
    assert doc["stages"]["architect"]["repair_events"] == []
    assert doc["stages"]["vending"] == {"status": "OK"}


def test_stage_trace_drops_an_earlier_runs_optional_fields(architect):
    h, agent = architect
    plan = SimpleNamespace(model_dump_json=lambda: "{}")
    agent._write_architect_stage_trace("tr-30", plan, None, "t0", topology_error={"reason": "ARCHITECT_TOPOLOGY_INVALID"})
    path = "pipeline_executions/tr-30/stage_traces/architect"
    assert agent.db.docs[path]["topology_error"]["reason"] == "ARCHITECT_TOPOLOGY_INVALID"
    agent.db.docs[path]["rating"] = "THUMBS_UP"          # written by the Control Center, not the architect
    agent._write_architect_stage_trace("tr-30", plan, None, "t1")
    doc = agent.db.docs[path]
    assert "topology_error" not in doc and doc["created_at"] == "t1" and doc["stage_name"] == "architect"
    assert doc["rating"] == "THUMBS_UP"


def test_no_nested_map_is_written_with_merge_true_in_the_architect_package():
    """Guard: `set(..., merge=True)` deep-merges maps, which keeps stale keys. In the architect package only the
    implementation-plan records (whole flat documents) may use it."""
    bad = []
    for f in sorted(os.listdir(ARCH_DIR)):
        if not f.endswith(".py") or f.startswith("test_"):
            continue
        tree = ast.parse(open(os.path.join(ARCH_DIR, f), encoding="utf-8").read())
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "set"):
                continue
            merge = next((k.value for k in node.keywords if k.arg == "merge"), None)
            if not (isinstance(merge, ast.Constant) and merge.value is True):
                continue
            collections = {a.value for n in ast.walk(node.func.value) if isinstance(n, ast.Call)
                           and isinstance(n.func, ast.Attribute) and n.func.attr == "collection"
                           for a in n.args if isinstance(a, ast.Constant)}
            if "implementation_plans" not in collections:
                bad.append(f"{f}:{node.lineno}")
    assert bad == [], f"merge=True write of an architect record (use merge=[field paths]): {bad}"
