"""PRIVATE-INGRESS-EARLY-STOP (owner 11-08): the typed stop at the compliance stage.

A compliance decision that requires internal-only ingress (spec wording, org policy or profile) cannot be satisfied on a
Cloud Run service in this release, so the run stops at the compliance stage (before vending and the developer) instead
of failing at apply every time. Plans with no Cloud Run service, and runs without the flag, are unchanged.

Hermetic: the real compliance server through FastAPI's TestClient, the gateway loaded by path, a fake Firestore.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import copy
import glob
import os

import pytest
from fastapi.testclient import TestClient

from test_compliance_bundle import (  # noqa: F401  (fixtures + helpers reused, not redefined)
    REPO_ROOT,
    _FakeHttpx,
    _handler,
    _req,
    _resp,
    _server_respond,
    _v2,
    gw,
    server,
)
from test_lane14_compliance_gate import FakeDB, FakeRunner, _svc, _wire_gate, compliance, plan, rc, tf  # noqa: F401
from test_lane17_workflow_sim import VEND, Fleet, assert_failed, calls, run, workflow  # noqa: F401

EXAMPLES_DIR = os.path.join(REPO_ROOT, "documentation", "examples")
EXAMPLE_02 = os.path.join(EXAMPLES_DIR, "02-multi-cloudrun-vpc-mesh.md")
TRACE = "t1"
PID = "orders"
ERROR_CLASS = "COMPLIANCE.PRIVATE_INGRESS_UNSUPPORTED"
NEG_LB = [{"step_id": "STEP-06B-SERVERLESS-NEG", "title": "NEG"}, {"step_id": "STEP-06C-HTTPS-LOAD-BALANCER", "title": "LB"}]


# ------------------------------------------------------------------------------------------------- fakes
class _Doc:
    def __init__(self, data, *, fail=None):
        self.data = data
        self.fail = fail

    @property
    def exists(self):
        return self.data is not None

    def to_dict(self):
        return self.data


class FakeDb:
    """pipeline_executions/{trace}.architect_compute_intent, counting reads."""

    def __init__(self, record=None, *, doc_missing=False, fail=None):
        self.record = record
        self.doc_missing = doc_missing
        self.fail = fail
        self.reads = 0

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
        return _Doc(None if self.doc_missing else {"architect_compute_intent": self.record})


def topology_record(services, primary, edges=()):
    from shared.service_topology import validate_service_topology

    raw = {"services": [{"name": n, "kind": k} for n, k in services], "primary_service": primary,
           "edges": [{"caller": a, "callee": b, "protocol": p} for a, b, p in edges], "resources": []}
    vt, diags = validate_service_topology(raw, product_id=PID)
    assert vt is not None, [(d.code, d.message) for d in diags]
    return {"schema": "architect_compute_intent/v2", "target_compute_services": list(vt.names),
            "bundle_id": None, "compute_archetype": vt.archetype, "service_topology": vt.as_record()}


CLOUD_RUN_PLAN = topology_record([("public-gateway", "cloudrun"), ("internal-core", "cloudrun")], "public-gateway",
                                 [("public-gateway", "internal-core", "http")])


def _store(h, record=CLOUD_RUN_PLAN, **kw):
    """Put the handler on a pipeline: a project and a store holding the architect's compute record."""
    db = FakeDb(record, **kw)
    h.project_id = "mock-stackvend-project"
    h._db = db
    return db


def _no_remediation(monkeypatch, h):
    monkeypatch.setattr(h, "remediate_conflicts",
                        lambda *a, **k: pytest.fail("the stop must come before the only model call of this stage"))


def _flag_answer(**over):
    base = dict(is_regulated=True, enforce_private_ingress=True, allow_unauthenticated=True, mandated_tasks=list(NEG_LB))
    base.update(over)
    return _v2(**base)


# ----------------------------------------------------------------------------- 1. the stop fires, one source at a time
SOURCE_CASES = [
    ("spec wording", dict(spec="an orders API with private ingress", compliance_profile=None),
     "SPEC_WORDING", ["the specification wording ('private ingress')"]),
    ("profile", dict(spec="a todo app", compliance_profile="PCI_DSS"),
     "COMPLIANCE_PROFILE", ["the PCI_DSS compliance profile"]),
    ("org policy", dict(spec="a todo app", compliance_profile=None, policy_matrix={"enforce_private_ingress": True}),
     "ORG_POLICY", ["the organization policy on the folder (constraints/run.allowedIngress)"]),
]


@pytest.mark.parametrize("label, kw, source, named", SOURCE_CASES, ids=[c[0] for c in SOURCE_CASES])
def test_stop_fires_for_a_cloud_run_plan_from_each_source(monkeypatch, server, label, kw, source, named):
    import gate_errors

    ch, h, fake, persisted = _handler(monkeypatch, _server_respond(server))
    db = _store(h)
    _no_remediation(monkeypatch, h)
    with pytest.raises(gate_errors.PrivateIngressUnsupportedError) as err:
        h.audit_and_enrich(_req(product_id=PID, trace_id=TRACE, **kw))
    e = err.value
    assert e.error_class.value == ERROR_CLASS and e.stage == "compliance" and e.reason == "PRIVATE_INGRESS_UNSUPPORTED"
    assert e.http_status == 409
    body = e.to_body()
    assert body["error_class"] == ERROR_CLASS and body["stage"] == "compliance" and body["passed"] is False
    assert body["summary"].startswith(f"{ERROR_CLASS}: This release cannot make Cloud Run services internal-only")
    assert "before anything was built or changed" in body["summary"]
    assert "public-gateway, internal-core" in body["summary"]
    for phrase in named:
        assert phrase in body["summary"]
    assert "IAM only" in body["summary"] and "planned" in body["summary"]
    assert source in body["details"]["requested_by"]
    assert body["details"]["cloud_run_services"] == ["public-gateway", "internal-core"]
    assert db.reads == 1
    [saved] = [p["args"][0] for p in persisted]  # recorded before the stop, so the apply gate keeps seeing the flag
    assert saved["enforce_private_ingress"] is True and saved["status"] == "FAILED" and saved["summary"] == e.message
    assert len(fake.calls) == 1  # only the compliance server's decision; no vending, no developer, no model


def test_all_sources_are_named_when_several_ask(monkeypatch, server):
    import gate_errors

    _, h, _, _ = _handler(monkeypatch, _server_respond(server))
    _store(h)
    _no_remediation(monkeypatch, h)
    with pytest.raises(gate_errors.PrivateIngressUnsupportedError) as err:
        h.audit_and_enrich(_req(product_id=PID, trace_id=TRACE, spec="internal only, no public ip",
                                compliance_profile="PCI_DSS", policy_matrix={"enforce_private_ingress": True}))
    assert set(err.value.details["requested_by"]) == {"SPEC_WORDING", "ORG_POLICY", "COMPLIANCE_PROFILE"}
    assert err.value.details["spec_terms"] == ["no public ip", "internal only"]


def test_stop_needs_no_server_report_of_the_source(monkeypatch):
    """A compliance server that does not report the source yet (additive field): the stop still fires."""
    import gate_errors

    _, h, _, _ = _handler(monkeypatch, lambda *a: _resp(200, _flag_answer()))
    _store(h)
    _no_remediation(monkeypatch, h)
    with pytest.raises(gate_errors.PrivateIngressUnsupportedError) as err:
        h.audit_and_enrich(_req(product_id=PID, trace_id=TRACE, spec="a todo app", policy_matrix=None))
    assert err.value.details["requested_by"] == []
    assert "did not report which input" in str(err.value)


def test_legacy_record_with_a_cloud_run_primary_fires(monkeypatch, server):
    import gate_errors

    _, h, _, _ = _handler(monkeypatch, _server_respond(server))
    _store(h, {"schema": "architect_compute_intent/v1", "target_compute_services": ["api"], "bundle_id": None,
               "compute_archetype": "cloudrun"})
    _no_remediation(monkeypatch, h)
    with pytest.raises(gate_errors.PrivateIngressUnsupportedError) as err:
        h.audit_and_enrich(_req(product_id=PID, trace_id=TRACE, spec="internal only api", policy_matrix=None))
    assert err.value.details["cloud_run_services"] == ["api"]


def test_gke_primary_with_a_cloud_run_secondary_fires(monkeypatch, server):
    """The legacy record's contract: service_names[1:] are Cloud Run secondaries whatever the primary is."""
    import gate_errors

    _, h, _, _ = _handler(monkeypatch, _server_respond(server))
    _store(h, {"schema": "architect_compute_intent/v1", "target_compute_services": ["cluster", "edge"],
               "bundle_id": None, "compute_archetype": "gke-autopilot"})
    _no_remediation(monkeypatch, h)
    with pytest.raises(gate_errors.PrivateIngressUnsupportedError) as err:
        h.audit_and_enrich(_req(product_id=PID, trace_id=TRACE, spec="internal only stream", policy_matrix=None))
    assert err.value.details["cloud_run_services"] == ["edge"]


# ------------------------------------------------------------------------------- 2. negatives: unchanged behaviour
def test_flag_off_with_a_cloud_run_plan_is_unchanged_and_reads_nothing(monkeypatch, server):
    _, h, _, persisted = _handler(monkeypatch, _server_respond(server))
    db = _store(h)
    res = h.audit_and_enrich(_req(product_id=PID, trace_id=TRACE, spec="a simple public todo app", policy_matrix=None))
    assert res.status == "PASSED" and res.enforce_private_ingress is False
    assert db.reads == 0  # no new read for runs without the flag
    assert len(persisted) == 1


NON_CLOUD_RUN = [
    ("gke topology", lambda: topology_record([("stream", "gke-autopilot")], "stream")),
    ("vm topology", lambda: topology_record([("box", "gce-bastion")], "box")),
    ("event-worker topology (a Cloud Run job, not a service)", lambda: topology_record([("worker", "event-worker")], "worker")),
    ("gke legacy", lambda: {"schema": "architect_compute_intent/v1", "target_compute_services": [],
                            "bundle_id": None, "compute_archetype": "gke-autopilot"}),
    ("foundation-only legacy", lambda: {"schema": "architect_compute_intent/v1", "target_compute_services": [],
                                        "bundle_id": None, "compute_archetype": "foundation-only"}),
    ("event-worker legacy", lambda: {"schema": "architect_compute_intent/v1", "target_compute_services": [],
                                     "bundle_id": None, "compute_archetype": "event-worker"}),
    ("vm legacy", lambda: {"schema": "architect_compute_intent/v1", "target_compute_services": [],
                           "bundle_id": None, "compute_archetype": "gce-bastion"}),
]


@pytest.mark.parametrize("label, make", NON_CLOUD_RUN, ids=[c[0] for c in NON_CLOUD_RUN])
def test_flag_on_without_a_cloud_run_service_continues(monkeypatch, server, label, make):
    _, h, _, persisted = _handler(monkeypatch, _server_respond(server))
    db = _store(h, make())
    res = h.audit_and_enrich(_req(product_id=PID, trace_id=TRACE, spec="a stream processor, internal only",
                                  policy_matrix=None))
    assert res.enforce_private_ingress is True and res.status == "ENRICHED"
    assert db.reads == 1 and len(persisted) == 1  # the decision is recorded exactly as before


def test_off_pipeline_caller_keeps_todays_behaviour(monkeypatch, server):
    """No project / store (the eval harness, local runs): the stop is not evaluated; the apply gate still is."""
    _, h, _, persisted = _handler(monkeypatch, _server_respond(server))
    res = h.audit_and_enrich(_req(product_id=PID, trace_id=TRACE, spec="internal only api", policy_matrix=None))
    assert res.enforce_private_ingress is True and len(persisted) == 1


@pytest.mark.parametrize("kw, failure", [
    ({"record": None}, "ValueError"),
    ({"record": {}}, "ValueError"),
    ({"doc_missing": True}, "ValueError"),
    ({"record": {"compute_archetype": "not-a-kind"}}, "InvalidComputeIntentError"),
    ({"fail": ConnectionError("firestore")}, "ConnectionError"),
])
def test_unreadable_compute_record_fails_closed(monkeypatch, server, kw, failure):
    """Could not check is never "no Cloud Run": typed GATE_UNAVAILABLE at the compliance stage, nothing persisted."""
    import gate_errors

    _, h, _, persisted = _handler(monkeypatch, _server_respond(server))
    _store(h, **kw)
    with pytest.raises(gate_errors.GateUnavailableError) as err:
        h.audit_and_enrich(_req(product_id=PID, trace_id=TRACE, spec="internal only api", policy_matrix=None))
    assert err.value.reason == "COMPLIANCE_COMPUTE_INTENT_UNAVAILABLE" and err.value.stage == "compliance"
    assert err.value.details["failure"] == failure and persisted == []


def test_pipeline_gate_without_a_store_fails_closed(monkeypatch, server):
    """Includes a Firestore client that cannot be built: `db` swallows that to None."""
    import compliance_agent.handler as ch
    import gate_errors

    _, h, _, persisted = _handler(monkeypatch, _server_respond(server), require_remote_engine=True)
    h.project_id = "mock-stackvend-project"
    monkeypatch.setattr(ch.ComplianceAgentHandler, "db", property(lambda self: None))
    with pytest.raises(gate_errors.GateUnavailableError) as err:
        h.audit_and_enrich(_req(product_id=PID, trace_id=TRACE, spec="internal only api", policy_matrix=None))
    assert err.value.reason == "COMPLIANCE_COMPUTE_INTENT_UNAVAILABLE" and err.value.details["failure"] == "NO_STORE"
    assert persisted == []


@pytest.mark.parametrize("remote", [True, False])
def test_empty_trace_id_fails_closed_when_there_is_a_store(monkeypatch, server, remote):
    import gate_errors

    _, h, _, persisted = _handler(monkeypatch, _server_respond(server), require_remote_engine=remote)
    db = _store(h)
    with pytest.raises(gate_errors.GateUnavailableError) as err:
        h.audit_and_enrich(_req(product_id=PID, trace_id="", spec="internal only api", policy_matrix=None))
    assert err.value.reason == "COMPLIANCE_COMPUTE_INTENT_UNAVAILABLE" and err.value.details["failure"] == "NO_TRACE"
    assert db.reads == 0 and persisted == []


# ----------------------------------------------------------------------------------- 3. the route and the workflow
def test_route_answers_409_with_the_typed_body(gw, monkeypatch):
    import compliance_agent.handler as ch

    monkeypatch.setenv("COMPLIANCE_SERVER_URL", "http://compliance.invalid")
    monkeypatch.setattr(ch, "httpx", _FakeHttpx(lambda *a: _resp(200, _flag_answer(private_ingress_sources=["ORG_POLICY"],
                                                                                   policy_matrix={"has_constraints": True}))))
    persisted = []
    monkeypatch.setattr(ch.ComplianceAgentHandler, "_persist_audit_record", lambda self, *a, **k: persisted.append(a))
    monkeypatch.setattr(ch.ComplianceAgentHandler, "_planned_cloud_run_services", lambda self, req: ["public-gateway"])
    writes = []

    class _Stages:
        def collection(self, name):
            assert name == "pipeline_executions"
            return self

        def document(self, doc_id):
            self.doc_id = doc_id
            return self

        def set(self, data, merge=False):
            writes.append((self.doc_id, data, merge))

    monkeypatch.setattr(gw, "db", _Stages())
    monkeypatch.setattr(gw, "_resolve_compliance_selection", lambda *a, **k: (None, None))
    r = TestClient(gw.app).post("/agent/compliance/audit", json={
        "product_id": PID, "trace_id": TRACE, "spec_text": "a todo app", "task_dag": [{"step_id": "STEP-01-APIS"}],
        "policy_matrix": {"has_constraints": False}})
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["error_class"] == ERROR_CLASS and body["stage"] == "compliance" and body["passed"] is False
    assert body["reason"] == "PRIVATE_INGRESS_UNSUPPORTED"
    assert "constraints/run.allowedIngress" in body["summary"]
    assert len(persisted) == 1
    assert writes == [(TRACE, {"stages": {"compliance": {"status": "FAILED", "error_class": ERROR_CLASS,
                                                         "summary": body["summary"]}}}, True)]


class _StageStore:
    """pipeline_executions/{trace}: records the merge, or raises it."""

    def __init__(self, fail=None):
        self.fail, self.writes = fail, []

    def collection(self, name):
        assert name == "pipeline_executions"
        return self

    def document(self, doc_id):
        self.doc_id = doc_id
        return self

    def set(self, data, merge=False):
        if self.fail:
            raise self.fail
        self.writes.append((self.doc_id, data, merge))


def _post_audit(gw, monkeypatch, store):
    monkeypatch.setenv("COMPLIANCE_SERVER_URL", "http://compliance.invalid")
    monkeypatch.setattr(gw, "db", store)
    monkeypatch.setattr(gw, "_resolve_compliance_selection", lambda *a, **k: (None, None))
    return TestClient(gw.app).post("/agent/compliance/audit", json={
        "product_id": PID, "trace_id": TRACE, "spec_text": "a todo app", "task_dag": [{"step_id": "STEP-01-APIS"}],
        "policy_matrix": {"has_constraints": False}})


def test_route_still_answers_409_when_the_stage_write_fails(gw, monkeypatch):
    import compliance_agent.handler as ch

    monkeypatch.setattr(ch, "httpx", _FakeHttpx(lambda *a: _resp(200, _flag_answer())))
    monkeypatch.setattr(ch.ComplianceAgentHandler, "_persist_audit_record", lambda self, *a, **k: None)
    monkeypatch.setattr(ch.ComplianceAgentHandler, "_planned_cloud_run_services", lambda self, req: ["public-gateway"])
    r = _post_audit(gw, monkeypatch, _StageStore(fail=ConnectionError("firestore")))
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["error_class"] == ERROR_CLASS and body["stage"] == "compliance" and body["passed"] is False


@pytest.mark.parametrize("stage, writes", [("compliance", 1), (None, 0)])
def test_route_writes_the_stage_only_for_a_compliance_stage_gate_error(gw, monkeypatch, stage, writes):
    import compliance_agent.handler as ch
    import gate_errors

    def boom(self, req):
        raise gate_errors.GateUnavailableError("could not check", reason="COMPLIANCE_COMPUTE_INTENT_UNAVAILABLE", stage=stage)

    monkeypatch.setattr(ch.ComplianceAgentHandler, "audit_and_enrich", boom)
    store = _StageStore()
    r = _post_audit(gw, monkeypatch, store)
    assert r.status_code == 503, r.text
    assert len(store.writes) == writes
    if writes:
        assert store.writes[0][1]["stages"]["compliance"]["status"] == "FAILED"
        assert store.writes[0][1]["stages"]["compliance"]["summary"] == "could not check"


@pytest.mark.parametrize("db_store, failure", [(None, "NO_STORE"), ({"__raise_set__": True}, "WRITE")])
def test_persist_refusals_name_the_compliance_stage(monkeypatch, server, db_store, failure):
    import compliance_agent.handler as ch
    import gate_errors

    _, h, _, _ = _handler(monkeypatch, _server_respond(server), require_remote_engine=True)
    monkeypatch.setattr(h, "_persist_audit_record", ch.ComplianceAgentHandler._persist_audit_record.__get__(h))
    monkeypatch.setattr(ch.ComplianceAgentHandler, "db", property(lambda self: FakeDB(db_store) if db_store else None))
    with pytest.raises(gate_errors.GateUnavailableError) as err:
        h._persist_audit_record({"product_id": PID, "trace_id": TRACE, "compliance_profile": "STANDARD", "policy_matrix": {}})
    assert err.value.reason == "COMPLIANCE_PERSIST_FAILED" and err.value.stage == "compliance"
    assert err.value.details["failure"] == failure


def test_workflow_ends_failed_typed_and_never_vends(workflow):
    summary = "This release cannot make Cloud Run services internal-only"
    fleet = Fleet(**{"/agent/compliance/audit": (409, {
        "status": "FAILED", "passed": False, "error_class": ERROR_CLASS, "stage": "compliance",
        "reason": "PRIVATE_INGRESS_UNSUPPORTED", "summary": summary, "errors": [summary], "diagnostics": []})})
    res, _ = run(workflow, fleet)
    assert_failed(res, ERROR_CLASS, stage="compliance")
    assert res.error["reason"] == "PRIVATE_INGRESS_UNSUPPORTED" and summary in res.error["message"]
    for later in ("/agent/developer/execute", "/events/pre-build-gate", VEND, "/agent/qa/verify", "/agent/release/promote"):
        assert not calls(res, later), later


def test_live_standard_workload_is_still_refused_on_fast_path_after_the_stop(monkeypatch, tf, compliance, tmp_path):
    """The stop records the decision first. Without that, a live STANDARD workload keeps its flag-off decision and a
    Fast-Path apply passes with public ingress."""
    from types import SimpleNamespace

    store = {
        f"workloads/{PID}": {"compliance_profile": "STANDARD", "compliance_decision": {
            "profile": "STANDARD", "profile_source": "DEFAULT_STANDARD", "requested_profile": None,
            "enable_direct_iap": False, "allow_unauthenticated": True, "enforce_private_ingress": False,
            "allowed_locations": []}},
        f"pipeline_executions/{TRACE}": {"architect_compute_intent": copy.deepcopy(CLOUD_RUN_PLAN)},
    }
    cloud_run = plan(rc("google_cloud_run_v2_service", "svc", {"name": "svc", "iap_enabled": False,
                                                               "ingress": "INGRESS_TRAFFIC_ALL"}))
    cg = _wire_gate(monkeypatch, tf, compliance)
    svc, ws = _svc(tf, tmp_path, store)

    before = FakeRunner(cloud_run)
    monkeypatch.setattr(svc, "_run_subprocess", before)
    assert svc._compliance_gated_apply(PID, "fastpath-before", ws, "OPENTOFU")["success"] is True  # flag off: passes

    import compliance_agent.handler as ch
    import gate_errors

    _, h, _, _ = _handler(monkeypatch, _server_respond(SimpleNamespace(client=compliance.client)))
    monkeypatch.setattr(h, "_persist_audit_record", ch.ComplianceAgentHandler._persist_audit_record.__get__(h))
    h.project_id, h._db = "mock-stackvend-project", FakeDB(store)
    with pytest.raises(gate_errors.PrivateIngressUnsupportedError):
        h.audit_and_enrich(_req(product_id=PID, trace_id=TRACE, spec="make it internal only", policy_matrix=None))
    assert store[f"workloads/{PID}"]["compliance_decision"]["enforce_private_ingress"] is True

    after = FakeRunner(cloud_run)
    monkeypatch.setattr(svc, "_run_subprocess", after)
    with pytest.raises(cg.ComplianceGateRefused) as refused:
        svc._compliance_gated_apply(PID, "fastpath-after", ws, "OPENTOFU")
    assert refused.value.result["error_class"] == "COMPLIANCE_VIOLATION" and "apply" not in after.calls
    assert "PRIVATE_INGRESS_NOT_SET" in str(refused.value.result)


# ------------------------------------------------------------------------------- 4. the server's report (additive)
def test_server_report_of_the_sources_never_changes_the_decision(server):
    def post(spec, **kw):
        return server.client.post("/inspect-folder", json={"folder_id": "", "spec_text": spec, **kw}).json()

    plain = post("a simple public todo app")
    assert plain["enforce_private_ingress"] is False and plain["private_ingress_sources"] == []
    worded = post("an api that is internal only")
    assert worded["enforce_private_ingress"] is True and worded["private_ingress_sources"] == ["SPEC_WORDING"]
    assert worded["private_ingress_spec_terms"] == ["internal only"]
    pci = post("a todo app", compliance_profile="PCI_DSS")
    assert pci["enforce_private_ingress"] is True and pci["private_ingress_sources"] == ["COMPLIANCE_PROFILE"]


def test_server_reports_the_org_policy_source(server, monkeypatch):
    monkeypatch.setattr(server.main.service, "inspect_org_policies", lambda folder_id: {
        "enforce_private_ingress": True, "has_constraints": True})
    body = server.client.post("/inspect-folder", json={"folder_id": "", "spec_text": "a todo app"}).json()
    assert body["enforce_private_ingress"] is True and body["private_ingress_sources"] == ["ORG_POLICY"]


def test_unknown_source_names_are_dropped():
    from compliance_agent.private_ingress import known_sources

    assert known_sources(["ORG_POLICY", "NOT_A_SOURCE", 7]) == ["ORG_POLICY"]
    assert known_sources("ORG_POLICY") == []


def test_source_names_match_between_server_and_gateway(server):
    from compliance_agent import private_ingress as gw_pi

    assert gw_pi.SOURCE_SPEC_WORDING == server.service.PRIVATE_INGRESS_SOURCE_SPEC
    assert gw_pi.SOURCE_ORG_POLICY == server.service.PRIVATE_INGRESS_SOURCE_ORG_POLICY
    assert gw_pi.SOURCE_PROFILE == server.service.PRIVATE_INGRESS_SOURCE_PROFILE


# ------------------------------------------------------------------------------- 5. shipped examples cannot regress
def test_no_shipped_example_contains_a_private_ingress_keyword(server):
    """An example can be uploaded whole as the specification, so the whole file is scanned, with the live list."""
    files = glob.glob(os.path.join(EXAMPLES_DIR, "*.md"))
    assert len(files) >= 10
    keywords = server.service.PRIVATE_INGRESS_KEYWORDS
    assert keywords  # the imported list, not a copy
    hits = [(os.path.basename(p), k) for p in files for k in keywords if k in open(p, encoding="utf-8").read().lower()]
    assert hits == []


def test_example_02_asks_for_nothing_this_release_cannot_build(server):
    """The rewritten example: no private-ingress or IAP intent from its own text, and it still names the real protection."""
    text = open(EXAMPLE_02, encoding="utf-8").read()
    intent = server.service.derive_ingress_intent(text)
    assert intent == {"domain_restricted_sharing": False, "enforce_private_ingress": False, "enable_direct_iap": False,
                      "deny_unauthenticated": False}
    lowered = text.lower()
    assert "internal-and-cloud-load-balancing" not in lowered
    assert "identity token" in lowered and "authenticated callers only" in lowered
    assert text.count("https://service-b.orders.example") >= 4  # the fixed audience, in the prompt and the description
    assert "k_service" not in lowered and "project number" not in lowered  # no audience derived from the request or URL
    assert "must never use the `host` header or any other request field" in lowered


def test_stop_helper_reads_the_cloud_run_services_of_a_real_topology():
    from compliance_agent.private_ingress import cloud_run_services
    from developer_agent.compute_intent import resolve_compute_intent

    intent = resolve_compute_intent(PID, topology_record(
        [("gateway", "cloudrun"), ("edge", "cloudrun"), ("worker", "event-worker")], "gateway",
        [("gateway", "worker", "pubsub")]), {}, None)
    assert cloud_run_services(intent) == ["gateway", "edge"]
