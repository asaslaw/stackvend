"""ACCESS-INTERNAL-SERVICE-ADVISORY (register row of the same name): the plan-time warning
`ACCESS.INTERNAL_SERVICE_PUBLIC` and its line on the plan approval card.

In a Public app every Cloud Run service is public. A service that only a Pub/Sub push calls (example 06's
`warehouse-fulfillment`, found live) therefore accepts anonymous requests. Until the per-service fix ships, the
compliance stage names each such service from typed facts only (access record mode, compliance decision, the
architect's validated topology); the pre-build gate copies the warning onto the ARCHITECTURAL_PLAN approval card and the
Control Center shows it. Report only: never a gate reason, never a model call, never a spec keyword.

Hermetic: the gateway loaded by path with no project, fake Firestore stores, the real topology validator and
`resolve_compute_intent`. No network.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import copy
import os
import sys
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from fd4f_support import FakeDB as GwFakeDB
from test_compliance_bundle import (  # noqa: F401  (fixtures + helpers reused, not redefined)
    GW_DIR,
    REPO_ROOT,
    _FakeHttpx,
    _handler,
    _req,
    _resp,
    _v2,
    gw,
)

CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
TRACE = "t1"
PID = "widget-factory"
CODE = "ACCESS.INTERNAL_SERVICE_PUBLIC"
FULFIL_PATH = "/api/v1/fulfillment/process"


# ------------------------------------------------------------------------------------------- topology shapes
def _topic(name, consumers):
    return {"type": "google_pubsub_topic", "logical_name": name, "purpose": "events",
            "consumers": [{"service": s, "env_key": k, "attribute": None} for s, k in consumers]}


def raw_topology(services, primary, edges=(), resources=(), pushes=()):
    return {"services": [{"name": n, "kind": k} for n, k in services], "primary_service": primary,
            "edges": [{"caller": a, "callee": b, "protocol": p} for a, b, p in edges],
            "resources": [copy.deepcopy(r) for r in resources],
            "pushes": [{"topic": t, "service": s, "path": p} for t, s, p in pushes]}


def validated(raw):
    from shared.service_topology import validate_service_topology

    vt, diags = validate_service_topology(raw, product_id=PID)
    assert vt is not None, [(d.code, d.message) for d in diags]
    return vt


def record(raw):
    vt = validated(raw)
    return {"schema": "architect_compute_intent/v2", "target_compute_services": list(vt.names), "bundle_id": None,
            "compute_archetype": vt.archetype, "service_topology": vt.as_record()}


# example 06: the storefront publishes orders; the topic pushes to the fulfillment worker, which no
# service calls over http.
EX06 = raw_topology(
    [("storefront", "cloudrun"), ("warehouse-fulfillment", "cloudrun")], "storefront",
    resources=[_topic("orders_placed", [("storefront", "ORDERS_TOPIC")]),
               {"type": "google_storage_bucket", "logical_name": "invoices", "purpose": "invoices",
                "consumers": [{"service": "warehouse-fulfillment", "env_key": "INVOICES_BUCKET", "attribute": None}]}],
    pushes=[("orders_placed", "warehouse-fulfillment", FULFIL_PATH)])
# example 01: one Cloud Run service that receives its own topic's push (it is the entrypoint)
EX01 = raw_topology([("event-router", "cloudrun")], "event-router",
                    resources=[_topic("events", [("event-router", "EVENTS_TOPIC")])],
                    pushes=[("events", "event-router", "/events/process")])
# example 02: a public gateway calling an internal core over http, no push
EX02 = raw_topology([("public-gateway", "cloudrun"), ("internal-core", "cloudrun")], "public-gateway",
                    edges=[("public-gateway", "internal-core", "http")])
# example 09: one internal admin service (its workload is Private: Google sign-in)
EX09 = raw_topology([("admin-portal", "cloudrun")], "admin-portal")
# a push target that another service also calls over http: browsers / siblings reach it on purpose
HTTP_CALLEE = raw_topology(
    [("public-gateway", "cloudrun"), ("internal-core", "cloudrun")], "public-gateway",
    edges=[("public-gateway", "internal-core", "http")],
    resources=[_topic("jobs", [("public-gateway", "JOBS_TOPIC")])],
    pushes=[("jobs", "internal-core", "/jobs")])


# ============================================================================ 1. the rule (pure, typed facts only)
def _advisories(raw):
    from compliance_agent.access_advisory import internal_service_advisories

    return internal_service_advisories(validated(raw))


def test_ex06_shape_gives_exactly_one_advisory_for_the_fulfillment_worker():
    [adv] = _advisories(EX06)
    assert adv["code"] == CODE and adv["service"] == "warehouse-fulfillment"
    assert adv["delivered_by"] == ["PUBSUB_PUSH"] and adv["push_topics"] == ["orders_placed"]
    assert adv["push_paths"] == [FULFIL_PATH] and adv["access_mode"] == "PUBLIC_APP"
    assert adv["message"].startswith("warehouse-fulfillment will be reachable from the internet: in the plan only "
                                     "Pub/Sub push calls it, but this workload is Public")
    assert "Choose Private to make every service private (the main service too)." in adv["message"]


@pytest.mark.parametrize("raw", [EX01, EX02, EX09], ids=["ex01", "ex02", "ex09"])
def test_examples_01_02_09_give_none(raw):
    assert _advisories(raw) == []


def test_the_entrypoint_and_an_http_callee_are_excluded():
    assert _advisories(EX01) == []           # the push target is the entrypoint
    assert _advisories(HTTP_CALLEE) == []    # the push target is an http callee


def test_entrypoint_by_position_behind_a_non_cloud_run_primary():
    """With a GKE primary the http entrypoint is the first Cloud Run service; only the other push target is named."""
    raw = raw_topology([("cluster", "gke-autopilot"), ("w1", "cloudrun"), ("w2", "cloudrun")], "cluster",
                       resources=[_topic("a", [("cluster", "A_TOPIC")]), _topic("b", [("cluster", "B_TOPIC")])],
                       pushes=[("a", "w1", "/a"), ("b", "w2", "/b")])
    assert validated(raw).http_entrypoint == "w1"
    assert [a["service"] for a in _advisories(raw)] == ["w2"]


def test_two_topics_to_one_service_give_one_advisory():
    raw = copy.deepcopy(EX06)
    raw["resources"].append(_topic("returns", [("storefront", "RETURNS_TOPIC")]))
    raw["pushes"].append({"topic": "returns", "service": "warehouse-fulfillment", "path": "/returns"})
    [adv] = _advisories(raw)
    assert adv["push_topics"] == ["orders_placed", "returns"] and adv["push_paths"] == [FULFIL_PATH, "/returns"]


def test_no_topology_gives_none():
    from compliance_agent.access_advisory import internal_service_advisories

    assert internal_service_advisories(None) == []


def _fake_topology(**over):
    vt = validated(EX06)
    base = dict(names=vt.names, http_entrypoint=vt.http_entrypoint, intent=vt.intent, pushes=vt.pushes, kind=vt.kind)
    base.update(over)
    return SimpleNamespace(**base)


@pytest.mark.parametrize("over", [
    {"pushes": (SimpleNamespace(topic="orders_placed", service="ghost", path="/x"),)},
    {"pushes": (SimpleNamespace(topic=None, service="warehouse-fulfillment", path="/x"),)},
    {"kind": lambda n: "event-worker"},
    {"http_entrypoint": "ghost"},
    {"intent": SimpleNamespace(edges=(SimpleNamespace(caller="storefront", callee="ghost", protocol="http"),))},
], ids=["unknown push service", "push without topic", "push to a non-Cloud-Run kind", "unknown entrypoint",
        "edge to an unknown service"])
def test_malformed_topology_facts_fail_loudly(over):
    from compliance_agent.access_advisory import AccessAdvisoryError, internal_service_advisories

    with pytest.raises(AccessAdvisoryError):
        internal_service_advisories(_fake_topology(**over))
    with pytest.raises(AccessAdvisoryError):
        internal_service_advisories(SimpleNamespace(names=("a",)))  # not a validated topology


def test_access_mode_is_read_as_an_exact_enum():
    from compliance_agent.access_advisory import AccessAdvisoryError, access_mode_of

    assert access_mode_of(None) is None
    for mode in ("PUBLIC_APP", "PRIVATE_IAM", "PRIVATE_IAP"):
        assert access_mode_of({"mode": mode}) == mode
    for bad in ("PUBLIC_APP", ["PUBLIC_APP"], {}, {"mode": "public_app"}, {"mode": "PUBLIC"}, {"mode": None}):
        with pytest.raises(AccessAdvisoryError):
            access_mode_of(bad)


def test_modes_equal_the_shared_access_enum():
    from compliance_agent import access_advisory as aa
    from developer_agent import access_resolution as ar
    from shared.access_policy import AccessMode

    assert aa.MODES == ar.MODES == {m.value for m in AccessMode}
    assert (aa.PUBLIC_APP, aa.PRIVATE_IAM, aa.PRIVATE_IAP) == (ar.PUBLIC_APP, ar.PRIVATE_IAM, ar.PRIVATE_IAP)


@pytest.mark.parametrize("mode, allow, iap, public", [
    ("PUBLIC_APP", True, False, True),
    ("PRIVATE_IAM", True, False, False),
    ("PRIVATE_IAP", True, False, False),
    (None, True, False, False),             # no access record: no warning (plan §8.1)
    ("PUBLIC_APP", False, False, False),    # a private decision: the developer stops (ACCESS_COMPLIANCE_CONFLICT)
    ("PUBLIC_APP", True, True, False),
    ("PUBLIC_APP", "true", False, False),   # exact booleans only
])
def test_only_a_public_record_under_a_public_decision_is_public(mode, allow, iap, public):
    from compliance_agent.access_advisory import workload_is_public

    assert workload_is_public(mode, allow_unauthenticated=allow, enable_direct_iap=iap) is public


def test_the_rule_reads_no_specification_text():
    """Invariant 2: no keyword matching. The phrase the spec used ("internal ingress") is deliberately not detected."""
    import inspect

    from compliance_agent import access_advisory

    src = inspect.getsource(access_advisory)
    code = src.split('"""', 2)[2]  # skip the module docstring, which explains the decision
    assert "spec" not in code.replace("_spec", "") and "internal ingress" not in code


# ============================================================================ 2. the compliance stage
class _PipelineDb:
    """pipeline_executions/{trace}.architect_compute_intent, counting reads (the compliance handler's store)."""

    def __init__(self, rec=None, *, missing=False, fail=None):
        self.rec, self.missing, self.fail, self.reads = rec, missing, fail, 0

    def collection(self, name):
        assert name == "pipeline_executions"
        return self

    def document(self, doc_id):
        assert doc_id == TRACE
        return self

    def get(self):
        self.reads += 1
        if self.fail:
            raise self.fail
        data = None if self.missing else {"architect_compute_intent": self.rec}
        return SimpleNamespace(exists=data is not None, to_dict=lambda: data)


def _reader(mode, calls=None):
    def read(pid):
        assert pid == PID
        if calls is not None:
            calls.append(pid)
        return mode
    return read


def _audit(monkeypatch, *, mode="PUBLIC_APP", raw=EX06, answer=None, store=True, req_kw=None, calls=None, **db_kw):
    ch, h, fake, persisted = _handler(monkeypatch, lambda *a: _resp(200, answer or _v2()),
                                      workload_access_reader=_reader(mode, calls))
    db = _PipelineDb(record(raw) if raw is not None else None, **db_kw)
    if store:
        h.project_id = "mock-stackvend-project"
        h._db = db
    monkeypatch.setattr(h, "remediate_conflicts", lambda *a, **k: pytest.fail("no model call for an advisory"))
    res = h.audit_and_enrich(_req(product_id=PID, trace_id=TRACE, spec="a widget shop", policy_matrix=None,
                                  **(req_kw or {})))
    return res, persisted, db


def test_stage_reports_the_ex06_advisory_and_persists_it(monkeypatch):
    res, persisted, db = _audit(monkeypatch)
    assert res.status == "PASSED" and res.requires_human_approval is False   # report only: no approval forced
    assert [a["service"] for a in res.access_advisories] == ["warehouse-fulfillment"]
    [saved] = [p["args"][0] for p in persisted]
    assert saved["access_advisories"] == res.access_advisories and db.reads == 1


@pytest.mark.parametrize("raw", [EX01, EX02, EX09], ids=["ex01", "ex02", "ex09"])
def test_stage_reports_none_for_examples_01_02_09(monkeypatch, raw):
    res, persisted, _ = _audit(monkeypatch, raw=raw)
    assert res.access_advisories == [] and persisted[0]["args"][0]["access_advisories"] == []


@pytest.mark.parametrize("mode", ["PRIVATE_IAM", "PRIVATE_IAP", None])
def test_private_modes_and_no_record_read_nothing_and_report_none(monkeypatch, mode):
    res, persisted, db = _audit(monkeypatch, mode=mode)
    assert res.access_advisories == [] and persisted[0]["args"][0]["access_advisories"] == [] and db.reads == 0


def test_private_decision_reports_none_and_reads_no_access_record(monkeypatch):
    """A Public record under a private compliance decision deploys nothing public (the developer refuses it)."""
    calls = []
    res, _, db = _audit(monkeypatch, answer=_v2(allow_unauthenticated=False, is_regulated=True), calls=calls)
    assert res.access_advisories == [] and db.reads == 0 and calls == []


def test_no_reader_reports_none(monkeypatch):
    """Direct callers (the eval harness) pass no reader: no advisory, nothing read."""
    ch, h, _, _ = _handler(monkeypatch, lambda *a: _resp(200, _v2()))
    db = _PipelineDb(record(EX06))
    h.project_id, h._db = "mock-stackvend-project", db
    res = h.audit_and_enrich(_req(product_id=PID, trace_id=TRACE, spec="a widget shop", policy_matrix=None))
    assert res.access_advisories == [] and db.reads == 0


def test_off_pipeline_caller_without_a_store_reports_none(monkeypatch):
    res, _, db = _audit(monkeypatch, store=False)
    assert res.access_advisories == [] and db.reads == 0


def test_enriched_path_carries_the_advisory_too(monkeypatch):
    answer = _v2(profile="HIPAA", profile_source="EXPLICIT_REQUEST", requested_profile="HIPAA", is_regulated=True,
                 requires_cmek=True)
    res, persisted, _ = _audit(monkeypatch, answer=answer, req_kw={"compliance_profile": "HIPAA"})
    assert res.status == "ENRICHED"
    assert [a["service"] for a in res.access_advisories] == ["warehouse-fulfillment"]
    assert persisted[0]["args"][0]["access_advisories"] == res.access_advisories


@pytest.mark.parametrize("kw, error, reason", [
    (dict(missing=True), "GateUnavailableError", "ACCESS_ADVISORY_FACTS_UNAVAILABLE"),
    (dict(raw=None), "GateUnavailableError", "ACCESS_ADVISORY_FACTS_UNAVAILABLE"),
    (dict(fail=RuntimeError("firestore down")), "GateUnavailableError", "ACCESS_ADVISORY_FACTS_UNAVAILABLE"),
], ids=["no execution document", "no record", "read failure"])
def test_unreadable_facts_on_the_pipeline_fail_loudly(monkeypatch, kw, error, reason):
    import gate_errors

    with pytest.raises(getattr(gate_errors, error)) as ei:
        _audit(monkeypatch, **kw)
    assert ei.value.reason == reason and ei.value.stage == "compliance"


def test_malformed_record_is_a_platform_defect(monkeypatch):
    import gate_errors

    ch, h, _, persisted = _handler(monkeypatch, lambda *a: _resp(200, _v2()),
                                   workload_access_reader=_reader("PUBLIC_APP"))
    bad = record(EX06)
    bad["service_topology"] = dict(bad["service_topology"], sha256="0" * 64)   # drift: the record does not re-validate
    h.project_id, h._db = "mock-stackvend-project", _PipelineDb(bad)
    with pytest.raises(gate_errors.PlatformDefectError) as ei:
        h.audit_and_enrich(_req(product_id=PID, trace_id=TRACE, spec="a widget shop", policy_matrix=None))
    assert ei.value.reason == "ACCESS_ADVISORY_FACTS_INVALID" and persisted == []


def test_pipeline_gate_without_a_store_fails_loudly(monkeypatch):
    import gate_errors

    ch, h, _, _ = _handler(monkeypatch, lambda *a: _resp(200, _v2()), require_remote_engine=True,
                           workload_access_reader=_reader("PUBLIC_APP"))
    with pytest.raises(gate_errors.GateUnavailableError) as ei:
        h.audit_and_enrich(_req(product_id=PID, trace_id=TRACE, spec="a widget shop", policy_matrix=None))
    assert ei.value.details["failure"] == "NO_STORE"


# ============================================================================ 3. the gateway route reads the record
def _route(gw, monkeypatch, workload_doc, rec=None):
    import compliance_agent.handler as ch

    monkeypatch.setattr(ch, "httpx", _FakeHttpx(lambda *a: _resp(200, _v2())))
    monkeypatch.setenv("COMPLIANCE_SERVER_URL", "http://compliance.invalid")
    persisted = []
    monkeypatch.setattr(ch.ComplianceAgentHandler, "_persist_audit_record", lambda self, r: persisted.append(r))
    monkeypatch.setattr(ch.ComplianceAgentHandler, "_determine_approval_requirement", lambda self, c: c)
    pipeline = _PipelineDb(rec)
    orig = ch.ComplianceAgentHandler.__init__

    def init(self, *a, **k):
        # COMPLIANCE-FOLLOWS-ARCHITECT-MODEL: the agent's model is the architect settings model (the legacy client
        # path resolves it at construction): serve the settings defaults instead of a store read
        import importlib
        from unittest.mock import patch
        st = importlib.import_module("shared.settings")
        with patch.object(st, "get_platform_settings", lambda *a, **k: st.PlatformSettings()):
            orig(self, *a, **k)
        self.project_id, self._db = "mock-stackvend-project", pipeline

    monkeypatch.setattr(ch.ComplianceAgentHandler, "__init__", init)
    store = GwFakeDB()
    if workload_doc is not None:
        store.docs[f"workloads/{PID}"] = workload_doc
    monkeypatch.setattr(gw, "db", store)
    r = TestClient(gw.app).post("/agent/compliance/audit", json={
        "product_id": PID, "trace_id": TRACE, "spec_text": "a widget shop", "task_dag": [],
        "policy_matrix": {"has_constraints": False}})
    return r, persisted, pipeline


def test_route_reads_the_stored_mode_and_returns_the_advisory(gw, monkeypatch):
    r, persisted, pipeline = _route(gw, monkeypatch, {"access": {"mode": "PUBLIC_APP"}}, record(EX06))
    assert r.status_code == 200, r.text
    [adv] = r.json()["access_advisories"]
    assert adv["code"] == CODE and adv["service"] == "warehouse-fulfillment"
    assert persisted[0]["access_advisories"] == r.json()["access_advisories"]


@pytest.mark.parametrize("doc", [None, {"status": "ACTIVE"}, {"access": {"mode": "PRIVATE_IAP"}}],
                         ids=["no workload document", "no access record", "private record"])
def test_route_without_a_public_record_returns_none_and_reads_no_plan(gw, monkeypatch, doc):
    r, _, pipeline = _route(gw, monkeypatch, doc, record(EX06))
    assert r.status_code == 200, r.text
    assert r.json()["access_advisories"] == [] and pipeline.reads == 0


@pytest.mark.parametrize("access", ["PUBLIC_APP", {"mode": "public"}, {"invoker_principals": []}],
                         ids=["not an object", "unknown mode", "no mode"])
def test_route_refuses_a_malformed_access_record(gw, monkeypatch, access):
    r, persisted, pipeline = _route(gw, monkeypatch, {"access": access}, record(EX06))
    assert r.status_code == 503, r.text
    assert "ACCESS_ADVISORY_FACTS_INVALID" in r.text and persisted == [] and pipeline.reads == 0


def test_route_read_failure_is_gate_unavailable(gw):
    import gate_errors

    store = GwFakeDB()
    store.fail_reads = True
    with pytest.raises(gate_errors.GateUnavailableError) as ei:
        gw._read_workload_access_mode(store, PID)
    assert ei.value.reason == "ACCESS_ADVISORY_FACTS_UNAVAILABLE"
    assert gw._read_workload_access_mode(None, PID) is None


# ============================================================================ 4. the pre-build gate copies it to the card
CB = "https://workflowexecutions.googleapis.com/v1/callbacks/cb1"
ADV = {"code": CODE, "service": "warehouse-fulfillment", "delivered_by": ["PUBSUB_PUSH"],
       "push_topics": ["orders_placed"], "push_paths": [FULFIL_PATH], "access_mode": "PUBLIC_APP",
       "message": "warehouse-fulfillment will be reachable from the internet."}


REASON = "ACCESS_INTERNAL_SERVICE_PUBLIC"
CARD = f"approval_requests/appr-plan-{TRACE}-0"
LOW_COST = {"requires_human_approval": False, "monthly_cost_delta_usd": 1.0, "monthly_cost_estimate": "+$1.00/mo"}
OVER_BUDGET = {"requires_human_approval": True, "monthly_cost_delta_usd": 900.0, "monthly_cost_estimate": "+$900.00/mo"}


def _gate(gw, compliance_extra, *, operator_requested=True, finops=LOW_COST, db=None):
    db = db or GwFakeDB()
    db.docs.setdefault(f"workloads/{PID}", {"product_id": PID})
    gw.app.dependency_overrides[gw.get_governance_db] = lambda: db
    body = {"trace_id": TRACE, "product_id": PID, "callback_url": CB, "rework_cycle": 0,
            "compliance": {"requires_human_approval": False, "has_policy_conflicts": False,
                           "allow_unauthenticated": True, **compliance_extra},
            "finops": dict(finops), "finops_error": "", "policy_harvest_status": "SUCCESS",
            "operator_requested": operator_requested, "spec_doc_id": "", "task_dag": []}
    return TestClient(gw.app).post("/events/pre-build-gate", json=body), db


def _decide(gw, db, decision):
    """What the Control Center does: write the decision on the card, then deliver the workflow callback's check."""
    db.docs[CARD]["status"] = decision
    return TestClient(gw.app).post("/events/pre-build-gate/decision", json={
        "trace_id": TRACE, "product_id": PID, "approval_id": f"appr-plan-{TRACE}-0", "decision": decision})


def test_pure_gate_reason_only_for_a_non_empty_list():
    import workflow_gates as wg

    base = {"requires_human_approval": False, "has_policy_conflicts": False}
    for advisories in (None, [], "x", {"a": 1}):
        extra = {} if advisories is None else {"access_advisories": advisories}
        assert wg.evaluate_pre_build_gate(compliance={**base, **extra}, finops=LOW_COST) == ("PASS", [])
    assert wg.evaluate_pre_build_gate(compliance={**base, "access_advisories": [ADV]}, finops=LOW_COST) == (
        "AWAIT_APPROVAL", [REASON])
    assert wg.evaluate_pre_build_gate(compliance={**base, "access_advisories": [ADV]}, finops=OVER_BUDGET) == (
        "AWAIT_APPROVAL", ["FINOPS_THRESHOLD", REASON])
    assert REASON == wg.REASON_ACCESS_INTERNAL_SERVICE_PUBLIC and REASON in wg.PRE_BUILD_REASONS


def test_ex06_advisory_pauses_the_run_with_the_reason_on_the_card(gw):
    r, db = _gate(gw, {"access_advisories": [ADV]}, operator_requested=False)
    assert r.status_code == 200, r.text
    assert r.json() == {"status": "SUCCESS", "decision": "AWAIT_APPROVAL", "gate_reasons": [REASON],
                        "approval_id": f"appr-plan-{TRACE}-0"}
    card = db.docs[CARD]
    assert card["approval_type"] == "ARCHITECTURAL_PLAN" and card["status"] == "PENDING"
    assert card["gate_reasons"] == [REASON]
    assert card["risk_assessment"] == ("Pre-build gate: ACCESS_INTERNAL_SERVICE_PUBLIC (reachable from the internet "
                                       "although only Pub/Sub push calls them: warehouse-fulfillment)")
    assert card["access_advisories"] == [{k: ADV[k] for k in ("code", "service", "message", "delivered_by",
                                                              "push_topics", "push_paths")}]
    assert db.docs[f"pipeline_executions/{TRACE}"]["state"] == "AWAITING_PLAN_APPROVAL"
    assert db.docs[f"workloads/{PID}"]["last_prebuild_gate"]["gate_reasons"] == [REASON]


def test_ex06_compliance_answer_to_card_end_to_end(gw, monkeypatch):
    """The compliance route's own body, passed on unchanged as the workflow does, pauses the run."""
    r, _, _ = _route(gw, monkeypatch, {"access": {"mode": "PUBLIC_APP"}}, record(EX06))
    g, db = _gate(gw, {k: v for k, v in r.json().items() if k == "access_advisories"}, operator_requested=False)
    assert g.json()["decision"] == "AWAIT_APPROVAL" and g.json()["gate_reasons"] == [REASON]
    assert [a["service"] for a in db.docs[CARD]["access_advisories"]] == ["warehouse-fulfillment"]


def test_combined_with_finops_threshold_is_one_pause_with_both_reasons(gw):
    r, db = _gate(gw, {"access_advisories": [ADV]}, operator_requested=False, finops=OVER_BUDGET)
    assert r.json()["decision"] == "AWAIT_APPROVAL" and r.json()["gate_reasons"] == ["FINOPS_THRESHOLD", REASON]
    assert [p for p in db.docs if p.startswith("approval_requests/")] == [CARD]
    card = db.docs[CARD]
    assert card["risk_assessment"].startswith("Pre-build gate: FINOPS_THRESHOLD, ACCESS_INTERNAL_SERVICE_PUBLIC (")
    assert card["cost_delta_monthly"] == "+$900.00/mo"


@pytest.mark.parametrize("extra", [{}, {"access_advisories": None}, {"access_advisories": []}],
                         ids=["absent", "null", "empty"])
@pytest.mark.parametrize("operator_requested, finops, want", [
    (False, LOW_COST, ("PASS", [])),
    (True, LOW_COST, ("AWAIT_APPROVAL", ["OPERATOR_REQUESTED"])),
    (False, OVER_BUDGET, ("AWAIT_APPROVAL", ["FINOPS_THRESHOLD"])),
    (True, OVER_BUDGET, ("AWAIT_APPROVAL", ["OPERATOR_REQUESTED", "FINOPS_THRESHOLD"])),
], ids=["pass", "plan approval on", "finops", "both"])
def test_no_advisory_leaves_the_decision_unchanged(gw, extra, operator_requested, finops, want):
    """Do No Harm: without an advisory the decision, the reasons and the card's gate line are exactly today's."""
    r, db = _gate(gw, extra, operator_requested=operator_requested, finops=finops)
    decision, reasons = want
    assert r.json() == {"status": "SUCCESS", "decision": decision, "gate_reasons": reasons,
                        "approval_id": f"appr-plan-{TRACE}-0" if reasons else ""}
    if reasons:
        assert db.docs[CARD]["risk_assessment"] == "Pre-build gate: " + ", ".join(reasons)
        assert db.docs[CARD]["access_advisories"] == []
    else:
        assert not [p for p in db.docs if p.startswith("approval_requests/")]


@pytest.mark.parametrize("decision", ["APPROVED", "REJECTED", "REWORK"])
def test_decisions_behave_as_for_any_plan_approval(gw, decision):
    """Approve / reject / rework go through the same decision route as an over-budget plan, with the same result."""
    outcomes = []
    for extra, finops in (({"access_advisories": [ADV]}, LOW_COST), ({}, OVER_BUDGET)):
        _, db = _gate(gw, extra, operator_requested=False, finops=finops)
        r = _decide(gw, db, decision)
        assert r.status_code == 200, r.text
        gate = dict(db.docs[f"workloads/{PID}"]["last_prebuild_gate"])
        assert gate.pop("decided_at") and gate.pop("gate_reasons")
        outcomes.append((r.json(), gate))
    assert outcomes[0] == outcomes[1]
    assert outcomes[0][0] == {"status": "SUCCESS", "decision": decision} and outcomes[0][1]["status"] == decision


@pytest.mark.parametrize("extra", [{}, {"access_advisories": None}, {"access_advisories": []}],
                         ids=["absent", "null", "empty"])
def test_gate_without_advisories_writes_an_empty_list(gw, extra):
    r, db = _gate(gw, extra)
    assert r.status_code == 200 and db.docs[f"approval_requests/appr-plan-{TRACE}-0"]["access_advisories"] == []


@pytest.mark.parametrize("bad", ["x", [ADV] * 51, ["x"], [dict(ADV, code="OTHER")], [dict(ADV, service="")],
                                 [dict(ADV, push_paths="/x")]],
                         ids=["not a list", "too many", "not an object", "unknown code", "no service",
                              "list field not a list"])
def test_gate_refuses_malformed_advisories(gw, bad):
    r, db = _gate(gw, {"access_advisories": bad})
    assert r.status_code == 422 and r.json()["detail"]["reason"] == "ACCESS_ADVISORIES_INVALID"
    assert not [p for p in db.docs if p.startswith("approval_requests/")]


def test_gateway_and_cc_codes_equal_the_advisory_code(gw):
    import workflow_gates
    from compliance_agent import access_advisory

    from_cc = _cc_approvals()
    assert workflow_gates.ACCESS_ADVISORY_CODES == from_cc.ACCESS_ADVISORY_CODES == (access_advisory.CODE,)


# ============================================================================ 5. the Control Center card
def _cc_approvals():
    if CC_DIR not in sys.path:
        sys.path.insert(0, CC_DIR)
    os.environ.setdefault("GOOGLE_OAUTH_CLIENT_ID", "access-advisory-test.apps.example.com")
    from routes import approvals

    return approvals


def _cc_list(monkeypatch, card):
    approvals = _cc_approvals()
    store = GwFakeDB()
    store.docs["approval_requests/appr-plan-t1-0"] = card
    monkeypatch.setattr(approvals, "db", store)
    req = SimpleNamespace(state=SimpleNamespace(user_email="admin@example.com", user_role="ADMIN",
                                                auth_method="session", assigned_workloads=[PID]),
                          headers={}, path_params={})
    monkeypatch.setattr(approvals, "workload_scope", lambda request: SimpleNamespace(all=True, allows=lambda p: True))
    [item] = approvals.list_pending_approvals(req)
    return item


def _plan_card(**over):
    card = {"approval_id": "appr-plan-t1-0", "approval_type": "ARCHITECTURAL_PLAN", "product_id": PID,
            "trace_id": TRACE, "status": "PENDING", "cost_delta_monthly": "+$1.00/mo",
            "risk_assessment": "Pre-build gate: OPERATOR_REQUESTED", "gate_reasons": ["OPERATOR_REQUESTED"],
            "requested_at": "2026-11-10T00:00:00+00:00"}
    card.update(over)
    return card


def test_cc_route_shows_the_advisory_on_the_plan_card(monkeypatch):
    item = _cc_list(monkeypatch, _plan_card(access_advisories=[ADV]))
    assert item.access_advisories == [{"code": CODE, "service": "warehouse-fulfillment", "message": ADV["message"]}]
    assert item.access_advisories_unreadable is False


def test_cc_card_from_the_gate_shows_the_reason_and_the_block(gw, monkeypatch):
    """The card the gateway wrote for the ex06 pause, read through the CC approvals route."""
    _, db = _gate(gw, {"access_advisories": [ADV]}, operator_requested=False)
    item = _cc_list(monkeypatch, db.docs[CARD])
    assert item.approval_type.value == "ARCHITECTURAL_PLAN" and item.gate_reasons == [REASON]
    assert item.risk_assessment.startswith("Pre-build gate: ACCESS_INTERNAL_SERVICE_PUBLIC")
    assert [a["service"] for a in item.access_advisories] == ["warehouse-fulfillment"]
    html = open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8").read()
    assert 'x-text="item.risk_assessment ||' in html   # the card's gate line renders the reason


@pytest.mark.parametrize("over", [{}, {"access_advisories": []}], ids=["legacy card", "no advisory"])
def test_cc_route_shows_nothing_new_without_advisories(monkeypatch, over):
    item = _cc_list(monkeypatch, _plan_card(**over))
    assert item.access_advisories == [] and item.access_advisories_unreadable is False


@pytest.mark.parametrize("bad", ["x", [dict(ADV, code="OTHER")], [dict(ADV, message=7)], [dict(ADV, service="")]],
                         ids=["not a list", "unknown code", "message not text", "no service"])
def test_cc_route_marks_a_malformed_copy_unreadable_never_empty(monkeypatch, bad):
    item = _cc_list(monkeypatch, _plan_card(access_advisories=bad))
    assert item.access_advisories == [] and item.access_advisories_unreadable is True


def test_cc_other_card_types_show_nothing(monkeypatch):
    item = _cc_list(monkeypatch, _plan_card(approval_type="PULL_REQUEST", access_advisories=[ADV]))
    assert item.access_advisories == [] and item.access_advisories_unreadable is False


def _template_block():
    html = open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8").read()
    start = html.index('data-testid="approval-access-advisories"')
    tpl = html.rindex("<template", 0, start)
    return html[tpl:html.index("</div>\n                                </template>", start)]


def test_cc_template_renders_the_advisory_messages_as_text():
    block = _template_block()
    assert ("x-if=\"item.approval_type === 'ARCHITECTURAL_PLAN' && ((item.access_advisories && "
            "item.access_advisories.length > 0) || item.access_advisories_unreadable)\"") in block
    assert 'x-for="adv in (item.access_advisories || [])"' in block and 'x-text="adv.message"' in block
    assert "x-html" not in block   # plain text only
    assert 'x-show="item.access_advisories_unreadable"' in block


def test_cc_template_renders_nothing_new_without_advisories():
    """The block is the only new markup and it is guarded by a non-empty list (or an unreadable copy)."""
    html = open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8").read()
    block = _template_block()
    assert html.count('data-testid="approval-access-advisories"') == 1
    assert html.count("access_advisories") == block.count("access_advisories") > 0   # nothing outside the guard
    assert "length > 0" in block


# ============================================================================ 6. the cap (review finding 6)
def _many_workers(n):
    services = [("storefront", "cloudrun")] + [(f"worker-{i:02d}", "cloudrun") for i in range(n)]
    topics = [_topic(f"t{i:02d}", [("storefront", f"T{i:02d}_TOPIC")]) for i in range(n)]
    return raw_topology(services, "storefront", resources=topics,
                        pushes=[(f"t{i:02d}", f"worker-{i:02d}", "/work") for i in range(n)])


def test_cap_constants_are_one_value():
    import workflow_gates
    from compliance_agent import access_advisory

    assert access_advisory.MAX_ADVISORIES == workflow_gates.MAX_ACCESS_ADVISORIES == 50


def test_more_push_only_services_than_the_cap_still_pause_with_a_count(gw, monkeypatch):
    """A plan the topology accepts (no service limit) never fails the run: the stage caps the list at the source and
    counts the rest; the gate pauses; the card says how many more."""
    res, persisted, _ = _audit(monkeypatch, raw=_many_workers(53))
    assert len(res.access_advisories) == 50 and res.access_advisories_omitted == 3
    assert [a["service"] for a in res.access_advisories][:2] == ["worker-00", "worker-01"]
    rec = persisted[0]["args"][0]
    assert len(rec["access_advisories"]) == 50 and rec["access_advisories_omitted"] == 3
    r, db = _gate(gw, {"access_advisories": res.access_advisories, "access_advisories_omitted": 3},
                  operator_requested=False)
    assert r.status_code == 200, r.text
    assert r.json()["decision"] == "AWAIT_APPROVAL" and r.json()["gate_reasons"] == [REASON]
    card = db.docs[CARD]
    assert len(card["access_advisories"]) == 50 and card["access_advisories_omitted"] == 3
    assert card["risk_assessment"].endswith("worker-49 and 3 more)")
    item = _cc_list(monkeypatch, card)
    assert len(item.access_advisories) == 50 and item.access_advisories_omitted == 3
    assert ("x-text=\"'And ' + item.access_advisories_omitted + ' more Cloud Run services in the same situation.'\""
            in _template_block())


def test_at_the_cap_nothing_is_omitted(monkeypatch):
    res, _, _ = _audit(monkeypatch, raw=_many_workers(50))
    assert len(res.access_advisories) == 50 and res.access_advisories_omitted == 0


@pytest.mark.parametrize("omitted, listed", [(-1, 50), (True, 50), ("3", 50), (3, 1)],
                         ids=["negative", "bool", "text", "count without a full list"])
def test_gate_refuses_a_malformed_count(gw, omitted, listed):
    r, db = _gate(gw, {"access_advisories": [ADV] * listed, "access_advisories_omitted": omitted})
    assert r.status_code == 422 and r.json()["detail"]["reason"] == "ACCESS_ADVISORIES_INVALID"
    assert not [p for p in db.docs if p.startswith("approval_requests/")]


@pytest.mark.parametrize("omitted", [-1, True, "3"], ids=["negative", "bool", "text"])
def test_cc_marks_a_malformed_count_unreadable(monkeypatch, omitted):
    item = _cc_list(monkeypatch, _plan_card(access_advisories=[ADV], access_advisories_omitted=omitted))
    assert item.access_advisories == [] and item.access_advisories_unreadable is True
