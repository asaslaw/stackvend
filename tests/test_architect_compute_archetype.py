"""Typed `compute_archetype` on the architect's structured output (owner Q1, 2026-10-13; faithful-hd01-hd02 §5).

The architect's LLM response schema (`ArchitecturePlanDAG`) carries `compute_archetype` as an exact enum equal to
`developer_agent/compute_intent.py` ARCHETYPES. Covers: enum parity with the resolver; the schema accepts every value
and rejects anything else (no case folding, no synonyms); the field is required in the LLM response schema (also
after google-genai's conversion); an off-enum answer is re-asked through the model cascade and, when no model gives
a valid one, fails typed (ARCHITECT_COMPUTE_ARCHETYPE_INVALID) - never a default, never the deterministic plan; the
resolver uses the field when present and raises on an unknown value; records written before the field (absent or
null) keep the bundle_id-table path unchanged.

Hermetic: fake genai client (no network), no project id (no Firestore client is built), prompt builder stubbed."""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
import sys
import typing
from types import SimpleNamespace
from unittest.mock import MagicMock

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

from pydantic import ValidationError  # noqa: E402

from architect_agent import schemas as arch_schemas  # noqa: E402
from architect_agent.schemas import (  # noqa: E402
    COMPUTE_ARCHETYPES,
    COMPUTE_INTENT_RECORD_SCHEMA,
    ArchitecturePlan,
    ArchitecturePlanDAG,
    compute_intent_record,
)
from developer_agent import compute_intent as ci  # noqa: E402

BASE = {"product_id": "p", "summary": "s", "architecture_overview": "o", "infra_tasks": [], "code_tasks": [],
        "target_compute_services": ["p"], "iac_engine": "tofu"}


def topology_for(arch, name="p"):
    """Lane 10: every architect answer carries a service_topology whose primary kind is the archetype."""
    if arch == "foundation-only":
        return {"services": [], "primary_service": None, "edges": [], "resources": []}
    return {"services": [{"name": name, "kind": arch}], "primary_service": name, "edges": [], "resources": []}
OFF_ENUM = ("k8s", "gke", "Cloud Run", "CLOUDRUN", "cloud-run", "cloud_run", "event_worker", "gce", "vm", "none",
            "", " cloudrun", "cloudrun ", 1, ["cloudrun"], {"kind": "cloudrun"})


# ------------------------------------------------------------------------------------------------ enum parity
def test_architect_enum_equals_the_resolver_archetypes_exactly():
    assert tuple(typing.get_args(arch_schemas.ComputeArchetype)) == COMPUTE_ARCHETYPES == ci.ARCHETYPES
    ann = ArchitecturePlanDAG.model_fields["compute_archetype"].annotation
    literal = [a for a in typing.get_args(ann) if typing.get_origin(a) is typing.Literal][0]
    assert tuple(typing.get_args(literal)) == ci.ARCHETYPES
    # every golden compute module has an archetype, and foundation-only is the only one without a module
    assert set(ci.ARCHETYPES) == set(ci.MODULE_DIR_ARCHETYPE.values()) | {"foundation-only"}


# ------------------------------------------------------------------------------------------------ schema
@pytest.mark.parametrize("arch", ci.ARCHETYPES)
def test_schema_accepts_each_enum_value_and_the_record_copies_it(arch):
    for model in (ArchitecturePlanDAG, ArchitecturePlan):
        plan = model(**BASE, compute_archetype=arch)
        assert plan.compute_archetype == arch
    rec = compute_intent_record(ArchitecturePlan(**BASE, compute_archetype=arch))
    assert rec["compute_archetype"] == arch and rec["schema"] == COMPUTE_INTENT_RECORD_SCHEMA


@pytest.mark.parametrize("bad", OFF_ENUM, ids=repr)
def test_schema_rejects_unknown_values(bad):
    for model in (ArchitecturePlanDAG, ArchitecturePlan):
        with pytest.raises(ValidationError):
            model(**BASE, compute_archetype=bad)


@pytest.mark.parametrize("bad", ("k8s", "Cloud Run", ""))
def test_record_builder_refuses_an_unknown_value_in_a_dict(bad):
    with pytest.raises(ValueError):
        compute_intent_record({**BASE, "compute_archetype": bad})


def test_llm_response_schema_requires_the_field_with_the_exact_enum():
    js = ArchitecturePlanDAG.model_json_schema()
    assert "compute_archetype" in js["required"]
    prop = js["properties"]["compute_archetype"]
    enums = [b["enum"] for b in prop["anyOf"] if "enum" in b]
    assert enums == [list(ci.ARCHETYPES)]


def test_genai_converted_response_schema_keeps_required_and_enum():
    t = pytest.importorskip("google.genai._transformers")
    client = MagicMock()
    client.vertexai = True
    schema = t.t_schema(client, ArchitecturePlanDAG).model_dump(exclude_none=True)
    assert "compute_archetype" in schema["required"]
    assert schema["properties"]["compute_archetype"]["enum"] == list(ci.ARCHETYPES)


def test_prompt_documents_every_enum_value():
    from architect_agent.prompt import ARCHITECT_SYSTEM_PROMPT
    assert "`compute_archetype`" in ARCHITECT_SYSTEM_PROMPT
    for arch in ci.ARCHETYPES:
        assert f"`{arch}`" in ARCHITECT_SYSTEM_PROMPT
    assert '"compute_archetype": "' + " | ".join(ci.ARCHETYPES) + '"' in ARCHITECT_SYSTEM_PROMPT


# ------------------------------------------------------------------------------------------------ resolver
@pytest.mark.parametrize("arch", ci.ARCHETYPES)
def test_resolver_uses_the_field_when_present(arch):
    rec = compute_intent_record(ArchitecturePlan(**{**BASE, "target_compute_services": ["api", "edge"]},
                                                 compute_archetype=arch, bundle_id="private-gke-microservices"))
    intent = ci.resolve_compute_intent("p", rec)
    assert (intent.archetype, intent.archetype_source, intent.source) == (arch, "architect.compute_archetype",
                                                                           "architect")
    assert intent.service_names == (() if arch == "foundation-only" else ("api", "edge"))


@pytest.mark.parametrize("bad", ("k8s", "Cloud Run", "", 7))
def test_resolver_raises_on_an_unknown_value_never_defaults(bad):
    for bundle in (None, "private-gke-microservices"):
        with pytest.raises(ci.InvalidComputeIntentError):
            ci.resolve_compute_intent("p", {"target_compute_services": ["p"], "bundle_id": bundle,
                                            "compute_archetype": bad})


# R3d-recorded records (faithful-hd01-hd02 §2): written before the field existed. Absent and null must resolve
# exactly as before (bundle_id table, then the Cloud Run contract).
OLD_RECORDS = [
    ({"target_compute_services": ["test-01-event-router"], "bundle_id": "event-driven-microservice"},
     ("cloudrun", ("test-01-event-router",), "architect.bundle_id:event-driven-microservice")),
    ({"target_compute_services": ["public-gateway", "internal-core"], "bundle_id": None},
     ("cloudrun", ("public-gateway", "internal-core"), "architect.target_compute_services")),
    ({"target_compute_services": ["stream-processor"], "bundle_id": "private-gke-microservices"},
     ("gke-autopilot", ("stream-processor",), "architect.bundle_id:private-gke-microservices")),
    ({"target_compute_services": ["test-08-cloudsql-postgres"], "bundle_id": "secure-three-tier-web"},
     ("cloudrun", ("test-08-cloudsql-postgres",), "architect.bundle_id:secure-three-tier-web")),
]


@pytest.mark.parametrize("old,expected", OLD_RECORDS)
def test_old_records_without_the_field_keep_the_bundle_table_path(old, expected):
    for rec in (old, {**old, "compute_archetype": None}, {**old, "schema": COMPUTE_INTENT_RECORD_SCHEMA}):
        intent = ci.resolve_compute_intent("p", rec)
        assert (intent.archetype, intent.service_names, intent.archetype_source) == expected


def test_old_plan_dict_without_the_field_validates_to_none():
    plan = ArchitecturePlan(**{**BASE, "bundle_id": "private-gke-microservices"})
    assert plan.compute_archetype is None
    rec = compute_intent_record(plan)
    assert rec["compute_archetype"] is None
    assert ci.resolve_compute_intent("p", rec).archetype == "gke-autopilot"


def test_no_record_still_resolves_to_the_recorded_platform_default():
    intent = ci.resolve_compute_intent("my_app", None)
    assert (intent.archetype, intent.service_names, intent.source) == ("cloudrun", ("my-app",), "platform-default")


# ------------------------------------------------------------------------------------------------ handler re-ask
@pytest.fixture()
def architect(monkeypatch):
    for k in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "PROJECT_ID", "K_SERVICE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ENABLE_DUAL_ARCHITECT_CONSENSUS", "false")
    # in-memory Firestore stand-in: any client the code under test builds is a MagicMock (never a real client)
    fake_fs = SimpleNamespace(Client=lambda *a, **kw: MagicMock(), Increment=lambda n: ("INC", n))
    import google.cloud  # noqa: F401
    monkeypatch.setattr(sys.modules["google.cloud"], "firestore", fake_fs, raising=False)
    monkeypatch.setitem(sys.modules, "google.cloud.firestore", fake_fs)
    from architect_agent import handler as h
    monkeypatch.setattr(h.ArchitectAgent, "persist_build_plan_to_firestore", lambda self, *a, **kw: True)
    monkeypatch.setattr(h.ArchitectAgent, "persist_implementation_plan_to_firestore", lambda self, *a, **kw: True)
    monkeypatch.setattr(h, "get_model_cascade_for_agent", lambda *a, **kw: ["model-a", "model-b"])
    monkeypatch.setattr(h, "build_architect_system_prompt", lambda **kw: "RENDERED ARCHITECT PROMPT")
    monkeypatch.setitem(sys.modules, "vertexai", None)
    agent = h.ArchitectAgent(project_id="")
    agent.project_id = ""
    agent.model_name = "model-a"
    agent.genai_client = None
    agent.model = None
    agent.spec_decomposer = None
    return h, agent


def _client(answers):
    """Fake genai client: model name -> JSON text (dict answers are serialized)."""
    calls = []

    def generate_content(model, contents, config):
        calls.append(model)
        ans = answers[model]
        return SimpleNamespace(text=ans if isinstance(ans, str) else json.dumps(ans), candidates=[],
                               usage_metadata=None)

    client = MagicMock()
    client.models.generate_content.side_effect = generate_content
    return client, calls


def _decompose(agent):
    return agent.decompose(spec_text="Build a bastion host", product_id="p", trace_id="t-1")


@pytest.mark.parametrize("arch", ci.ARCHETYPES)
def test_valid_answer_reaches_the_plan_and_the_record(architect, arch):
    h, agent = architect
    agent.genai_client, calls = _client({"model-a": {**BASE, "compute_archetype": arch,
                                                     "service_topology": topology_for(arch)}})
    res = _decompose(agent)
    assert calls == ["model-a"]
    assert res.architecture_plan.compute_archetype == arch
    assert res.compute_intent["compute_archetype"] == arch
    assert res.compute_intent["service_topology"]["archetype"] == arch     # lane 10: v2 record


def test_off_enum_answer_is_re_asked_through_the_cascade(architect, monkeypatch):
    h, agent = architect
    agent.genai_client, calls = _client({"model-a": {**BASE, "compute_archetype": "Cloud Run"},
                                         "model-b": {**BASE, "compute_archetype": "gce-bastion",
                                                     "service_topology": topology_for("gce-bastion")}})
    fallback = []
    monkeypatch.setattr(agent, "_fallback_plan", lambda *a: fallback.append(a))
    res = _decompose(agent)
    assert calls == ["model-a", "model-b"]
    assert res.architecture_plan.compute_archetype == "gce-bastion" and fallback == []


def test_every_model_off_enum_fails_typed_never_the_deterministic_plan(architect, monkeypatch):
    h, agent = architect
    agent.genai_client, calls = _client({"model-a": {**BASE, "compute_archetype": "k8s"},
                                         "model-b": {**BASE, "compute_archetype": "CLOUDRUN"}})
    fallback = []
    monkeypatch.setattr(agent, "_fallback_plan", lambda *a: fallback.append(a))
    with pytest.raises(h.ArchitectOutputInvalidError) as ei:
        _decompose(agent)
    assert calls == ["model-a", "model-b"] and fallback == []
    err = ei.value
    assert err.http_status == 502 and err.reason == "ARCHITECT_COMPUTE_ARCHETYPE_INVALID"
    body = err.to_body()
    assert body["error_class"] == "GATE_UNAVAILABLE" and body["status"] == "FAILED"
    assert body["details"]["rejections"] == [{"model": "model-a", "compute_archetype": "'k8s'"},
                                             {"model": "model-b", "compute_archetype": "'CLOUDRUN'"}]


def test_legacy_model_off_enum_answer_also_fails_typed(architect, monkeypatch):
    h, agent = architect
    agent.genai_client = None
    agent.model = MagicMock()
    agent.model.generate_content.return_value = SimpleNamespace(text=json.dumps({**BASE, "compute_archetype": "vm"}))
    fallback = []
    monkeypatch.setattr(agent, "_fallback_plan", lambda *a: fallback.append(a))
    with pytest.raises(h.ArchitectOutputInvalidError):
        _decompose(agent)
    assert fallback == []


@pytest.mark.parametrize("answer", [dict(BASE), {**BASE, "compute_archetype": None}],
                         ids=["absent", "null"])
def test_absent_or_null_answer_keeps_the_bundle_path(architect, answer):
    """A plan without compute_archetype: lane 10's topology states the kind (record v2); a record without a
    topology (written before lane 10) keeps the bundle_id-table path unchanged."""
    h, agent = architect
    agent.genai_client, calls = _client({"model-a": {**answer, "bundle_id": "private-gke-microservices",
                                                     "service_topology": topology_for("gke-autopilot")}})
    res = _decompose(agent)
    assert calls == ["model-a"] and res.architecture_plan.compute_archetype is None
    assert res.compute_intent["compute_archetype"] == "gke-autopilot"
    legacy = {k: v for k, v in res.compute_intent.items() if k not in ("service_topology", "topology_provenance")}
    legacy.update(schema=COMPUTE_INTENT_RECORD_SCHEMA, compute_archetype=None)
    intent = ci.resolve_compute_intent("p", legacy)
    assert (intent.archetype, intent.archetype_source) == ("gke-autopilot",
                                                           "architect.bundle_id:private-gke-microservices")


def test_violation_helper_is_exact_membership_only():
    from architect_agent.handler import _compute_archetype_violation as v
    assert v({"compute_archetype": "cloudrun"}) is None
    assert v({"compute_archetype": None}) is None and v({}) is None and v(None) is None and v([1]) is None
    assert v({"compute_archetype": "Cloudrun"}) == "'Cloudrun'"
    assert v({"compute_archetype": 3}) == "3"
