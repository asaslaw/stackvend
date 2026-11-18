"""compliance-profile-explicit (10-18): the compliance profile is an explicit, typed selection, never spec keywords.

Found by release prep (docs/handoff/release-preview-prep-report.md §3 on release-preview-prep): the profile was chosen
by spec words ("patient", "credit card", "europe", ...). With the lane 14 PR-0 plan gate enforcing profiles at apply,
an ordinary spec that mentions such a word (documentation/examples/06: "mock credit card authorizations") would be
classified PCI_DSS and refused. Now:

  profile = Assured Workloads folder regime, else the explicit `compliance_profile` (CC create form / intake event /
            workflow args / stored `workloads/{pid}.requested_compliance_profile`), else STANDARD (DEFAULT_STANDARD).
  spec words -> advisory `profile_suggestions` only; they never change the decision.
  invalid value -> typed 422 at every entry point (CC, Pub/Sub intake, gateway route, compliance server).

Hermetic: the real compliance server through FastAPI's TestClient, the gateway loaded by path with no project, fake
Firestore. No network.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import copy
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from test_compliance_bundle import (  # noqa: F401  (fixtures + helpers reused, not redefined)
    COMPLIANCE_DIR,
    GW_DIR,
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

CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
EXAMPLE_06 = os.path.join(REPO_ROOT, "documentation", "examples", "06-ecommerce-widget-factory.md")

# One ordinary spec per former keyword profile: each used to be classified regulated by its words alone.
KEYWORD_SPECS = {
    "HIPAA": "a clinic appointment scheduler; patient names are shown on the calendar",
    "FEDRAMP_MODERATE": "a public dashboard of local government open data",
    "FEDRAMP_HIGH": "a classified-ads board for a small town newspaper",
    "EU_REGIONS_AND_SUPPORT": "a travel blog about trains across europe",
    "PCI_DSS": "a storefront demo; a Stripe mock key validates mock credit card authorizations",
}


# ============================================================================ 1. the exact regression
@pytest.mark.parametrize("former, spec", sorted(KEYWORD_SPECS.items()))
def test_keyword_bearing_standard_spec_stays_standard_at_the_server(server, former, spec):
    body = server.client.post("/inspect-folder", json={"folder_id": "", "spec_text": spec}).json()
    assert body["profile"] == "STANDARD" and body["profile_source"] == "DEFAULT_STANDARD"
    assert body["requested_profile"] is None
    assert body["requires_cmek"] is False and body["requires_audit_logging"] is False
    assert body["is_regulated"] is False and body["mandated_tasks"] == []
    # ...and the words are surfaced as advice only.
    assert former in [s["profile"] for s in body["profile_suggestions"]]


def test_example_06_is_standard_end_to_end_through_the_gateway(monkeypatch, server):
    """documentation/examples/06 mentions "mock credit card authorizations": it was PCI_DSS (CMEK + private ingress +
    load balancer injected, then refused at apply by PR-0). It is an ordinary STANDARD workload."""
    spec = open(EXAMPLE_06).read()
    _, h, _, persisted = _handler(monkeypatch, _server_respond(server))
    res = h.audit_and_enrich(_req(spec=spec, policy_matrix=None))
    assert res.compliance_profile == "STANDARD" and res.status == "PASSED" and res.injected_tasks == []
    assert res.compliance_profile_source == "DEFAULT_STANDARD"
    assert [a["profile"] for a in res.profile_advisories] == ["PCI_DSS"]
    (rec,) = persisted
    # Integration (FD-4R R-6 seam): the persist takes one complete v2 record.
    assert rec["args"][0]["compliance_profile"] == "STANDARD" and rec["args"][0]["profile_source"] == "DEFAULT_STANDARD"


# ============================================================================ 2. explicit profile -> that profile
@pytest.mark.parametrize("profile", ["HIPAA", "FEDRAMP_MODERATE", "FEDRAMP_HIGH", "CJIS", "EU_REGIONS_AND_SUPPORT",
                                     "PCI_DSS"])
def test_explicit_profile_is_the_decision_whatever_the_spec_says(server, profile):
    for spec in ("a simple public todo app", KEYWORD_SPECS["PCI_DSS"]):
        body = server.client.post("/inspect-folder", json={"folder_id": "", "spec_text": spec,
                                                           "compliance_profile": profile}).json()
        assert body["profile"] == profile and body["profile_source"] == "EXPLICIT_REQUEST"
        assert body["requested_profile"] == profile and body["is_regulated"] is True
        assert body["requires_cmek"] is True
        assert profile not in [s["profile"] for s in body["profile_suggestions"]]


def test_explicit_hipaa_through_the_gateway_is_hipaa_and_recorded_as_explicit(monkeypatch, server):
    _, h, fake, persisted = _handler(monkeypatch, _server_respond(server))
    res = h.audit_and_enrich(_req(spec="a simple public todo app", policy_matrix=None, compliance_profile="HIPAA"))
    assert res.compliance_profile == "HIPAA" and res.requires_cmek is True and res.status == "ENRICHED"
    assert res.compliance_profile_source == "EXPLICIT_REQUEST"
    assert {"STEP-03B-KMS-CMEK", "STEP-03C-AUDIT-LOGGING"} <= {t["step_id"] for t in res.injected_tasks}
    assert fake.calls[0]["json"]["compliance_profile"] == "HIPAA"
    (rec,) = persisted
    assert rec["args"][0]["profile_source"] == "EXPLICIT_REQUEST" and rec["args"][0]["requested_profile"] == "HIPAA"


def test_stored_selection_is_recorded_as_workload_selection(monkeypatch, server):
    _, h, _, persisted = _handler(monkeypatch, _server_respond(server))
    res = h.audit_and_enrich(_req(spec="a todo app", policy_matrix=None, compliance_profile="PCI_DSS",
                                  compliance_profile_origin="WORKLOAD_SELECTION"))
    assert res.compliance_profile == "PCI_DSS" and res.compliance_profile_source == "WORKLOAD_SELECTION"
    assert persisted[0]["args"][0]["profile_source"] == "WORKLOAD_SELECTION"


def test_persisted_decision_carries_the_source(monkeypatch, server):
    """The real `_persist_audit_record`: the decision the PR-0 gate and PR-0b read records where it came from."""
    import compliance_agent.handler as ch

    store = {}
    _, h, _, _ = _handler(monkeypatch, _server_respond(server))
    monkeypatch.setattr(h, "_persist_audit_record",
                        ch.ComplianceAgentHandler._persist_audit_record.__get__(h))
    h._db = _FakeDB(store)
    h.audit_and_enrich(_req(spec=KEYWORD_SPECS["HIPAA"], policy_matrix=None))
    decision = store["workloads/hipaa-claims"]["compliance_decision"]
    assert decision["profile"] == "STANDARD" and decision["profile_source"] == "DEFAULT_STANDARD"
    assert decision["requested_profile"] is None
    audit = store["workloads/hipaa-claims/compliance_audits/t1"]
    assert [a["profile"] for a in audit["profile_advisories"]] == ["HIPAA"]

    h.audit_and_enrich(_req(spec="a todo app", policy_matrix=None, compliance_profile="HIPAA"))
    decision = store["workloads/hipaa-claims"]["compliance_decision"]
    assert (decision["profile"], decision["profile_source"], decision["requested_profile"]) == (
        "HIPAA", "EXPLICIT_REQUEST", "HIPAA")


def test_folder_regime_still_wins_and_a_different_request_is_flagged(server, monkeypatch):
    monkeypatch.setattr(server.main.service, "inspect_parent_folder", lambda folder_id: {
        "folder_id": folder_id, "is_assured_workload": True, "compliance_regime": "FEDRAMP_HIGH"})
    monkeypatch.setattr(server.main.service, "inspect_org_policies", lambda folder_id: {"has_constraints": False})
    body = server.client.post("/inspect-folder", json={"folder_id": "folders/1", "spec_text": "a todo app",
                                                       "compliance_profile": "HIPAA"}).json()
    assert body["profile"] == "FEDRAMP_HIGH" and body["profile_source"] == "ASSURED_WORKLOADS_FOLDER"
    assert body["requested_profile"] == "HIPAA"
    assert any(s["profile"] == "HIPAA" and "folder" in s["advisory"] for s in body["profile_suggestions"])
    body = server.client.post("/inspect-folder", json={"folder_id": "folders/1", "spec_text": "a todo app"}).json()
    assert body["profile"] == "FEDRAMP_HIGH" and body["profile_source"] == "ASSURED_WORKLOADS_FOLDER"


def test_an_unmapped_folder_regime_no_longer_falls_back_to_spec_words(server, monkeypatch):
    # Before: an Assured Workloads regime outside the mapped list fell back to the KEYWORD profile.
    monkeypatch.setattr(server.main.service, "inspect_parent_folder", lambda folder_id: {
        "folder_id": folder_id, "is_assured_workload": True, "compliance_regime": "IL4"})
    monkeypatch.setattr(server.main.service, "inspect_org_policies", lambda folder_id: {"has_constraints": False})
    # Owner decision 10-18 (CP-10): and it is not a silent STANDARD either: a typed refusal.
    for requested in (None, "HIPAA"):
        r = server.client.post("/inspect-folder", json={"folder_id": "folders/1", "compliance_profile": requested,
                                                        "spec_text": KEYWORD_SPECS["HIPAA"]})
        assert r.status_code == 422 and r.json()["detail"]["error_class"] == "UNMAPPED_ASSURED_WORKLOADS_REGIME"


# ============================================================================ 3. invalid value -> typed 422
INVALID = ["hipaa", " HIPAA", "HIPAA ", "PCI", "EU", "FEDRAMP", "HIPPA", "standard", 7, ["HIPAA"], {"p": "HIPAA"}]


@pytest.mark.parametrize("value", INVALID, ids=[repr(v) for v in INVALID])
def test_server_refuses_an_invalid_profile_with_422(server, value):
    r = server.client.post("/inspect-folder", json={"folder_id": "", "spec_text": "a todo app",
                                                    "compliance_profile": value})
    assert r.status_code == 422, r.text


@pytest.mark.parametrize("value", INVALID, ids=[repr(v) for v in INVALID])
def test_gateway_route_refuses_an_invalid_profile_with_a_typed_422(gw, monkeypatch, value):
    import compliance_agent.handler as ch

    fake = _FakeHttpx(lambda *a: _resp(200, _v2()))
    monkeypatch.setattr(ch, "httpx", fake)
    monkeypatch.setenv("COMPLIANCE_SERVER_URL", "http://compliance.invalid")
    r = TestClient(gw.app).post("/agent/compliance/audit", json={
        "product_id": "todo", "trace_id": "t1", "spec_text": "a todo app", "task_dag": [],
        "compliance_profile": value})
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert detail["error_class"] == "INVALID_COMPLIANCE_PROFILE" and "HIPAA" in detail["allowed"]
    assert fake.calls == []  # refused before the compliance server is asked


def test_gateway_handler_refuses_an_invalid_profile_before_any_call(monkeypatch):
    from compliance_agent.profiles import InvalidComplianceProfile

    _, h, fake, persisted = _handler(monkeypatch, lambda *a: _resp(200, _v2()))
    with pytest.raises(InvalidComplianceProfile):
        h.audit_and_enrich(_req(compliance_profile="hipaa"))
    assert fake.calls == [] and persisted == []


@pytest.mark.parametrize("value", INVALID, ids=[repr(v) for v in INVALID])
def test_intake_refuses_an_invalid_profile_with_422(value):
    import intake_policy

    for channel in (None, "control_center_form", "google_docs"):
        payload = {"product_id": "p", "trace_id": "t", "compliance_profile": value}
        if channel:
            payload["source_channel"] = channel
        with pytest.raises(intake_policy.IntakeRejected) as ei:
            intake_policy.validate_intake(payload)
        assert ei.value.status_code == 422 and ei.value.status == "SUPPRESSED:INVALID_COMPLIANCE_PROFILE"


def test_intake_accepts_a_valid_or_absent_profile_unchanged():
    import intake_policy

    for payload in ({"product_id": "p", "source_channel": "control_center_form", "compliance_profile": "HIPAA"},
                    {"product_id": "p", "source_channel": "control_center_form"},
                    {"product_id": "p", "compliance_profile": ""},
                    {"product_id": "p"}):
        assert intake_policy.validate_intake(copy.deepcopy(payload)) == payload


def _cc_schemas(monkeypatch):
    from fd4g_support import load_module

    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    return load_module(monkeypatch, "cpe_cc_schemas", os.path.join(CC_DIR, "schemas.py"))


@pytest.mark.parametrize("value", INVALID, ids=[repr(v) for v in INVALID])
def test_control_center_create_refuses_an_invalid_profile(monkeypatch, value):
    from pydantic import ValidationError

    schemas = _cc_schemas(monkeypatch)
    with pytest.raises(ValidationError):
        schemas.CreateWorkloadRequest(product_id="p", compliance_profile=value)


def test_control_center_create_accepts_exact_values_and_empty_means_unset(monkeypatch):
    schemas = _cc_schemas(monkeypatch)
    assert schemas.CreateWorkloadRequest(product_id="p").compliance_profile is None
    assert schemas.CreateWorkloadRequest(product_id="p", compliance_profile="").compliance_profile is None
    assert schemas.CreateWorkloadRequest(product_id="p", compliance_profile="HIPAA").compliance_profile.value == "HIPAA"


# ============================================================================ 4. the advisory never changes the decision
ADVISORY_SPECS = list(KEYWORD_SPECS.values()) + [
    "HIPAA PHI patient electronic health records (ePHI)",
    "Classified DoD IL5 workload with ITAR data residency requirements",
    "checkout service that stores payment card data (PCI-DSS)",
    open(EXAMPLE_06).read(),
]


@pytest.mark.parametrize("requested", [None, "HIPAA", "PCI_DSS", "STANDARD"])
def test_the_decision_is_the_same_with_or_without_the_advisory_terms(server, monkeypatch, requested):
    def decide(spec):
        body = server.client.post("/inspect-folder", json={"folder_id": "", "spec_text": spec,
                                                           "compliance_profile": requested}).json()
        body.pop("profile_suggestions")
        return body

    baseline = [decide(spec) for spec in ADVISORY_SPECS]
    # Every advisory term list emptied: the suggestions vanish, the decision does not move.
    monkeypatch.setattr(server.service, "ADVISORY_PROFILE_TERMS", {k: [] for k in server.service.ADVISORY_PROFILE_TERMS})
    assert [decide(spec) for spec in ADVISORY_SPECS] == baseline
    # Every advisory term list maximal (any word of any spec suggests every profile): still no movement.
    monkeypatch.setattr(server.service, "ADVISORY_PROFILE_TERMS",
                        {k: sorted({w for s in ADVISORY_SPECS for w in s.lower().split() if w.isalpha()})
                         for k in server.service.ADVISORY_PROFILE_TERMS})
    assert [decide(spec) for spec in ADVISORY_SPECS] == baseline
    for body in baseline:
        assert body["profile"] == (requested or "STANDARD")


def test_the_profile_decision_does_not_take_spec_text(server):
    import inspect

    params = list(inspect.signature(server.service.ComplianceService.resolve_profile).parameters)
    assert params == ["self", "requested_profile", "folder_check"]
    assert not hasattr(server.service.ComplianceService, "detect_spec_compliance")
    assert not hasattr(server.service, "COMPLIANCE_KEYWORD_MAP")


# ============================================================================ 5. one vocabulary, one stored value
def test_every_copy_of_the_profile_vocabulary_is_the_plan_gates(server, monkeypatch):
    from compliance_agent import profiles

    gate = server.service.plan_gate.KNOWN_PROFILES
    assert profiles.KNOWN_PROFILES == gate
    assert {p.value for p in _cc_schemas(monkeypatch).ComplianceProfile} == gate
    assert set(server.service.FOLDER_REGIME_PROFILES) <= gate
    assert set(server.service.ADVISORY_PROFILE_TERMS) <= gate
    svc = server.service.ComplianceService(project_id="")
    assert {svc.get_compliance_requirements(p)["profile"] for p in gate} == gate
    assert server.service.PROFILE_SOURCES == profiles.SERVER_PROFILE_SOURCES


class _FakeDoc:
    def __init__(self, store, path):
        self.store, self.path = store, path

    def get(self):
        if self.store.get("__raise__"):
            raise RuntimeError("firestore down")
        data = self.store.get(self.path)
        return SimpleNamespace(exists=data is not None, to_dict=lambda: copy.deepcopy(data))

    def set(self, data, merge=False):
        if self.store.get("__raise__"):
            raise RuntimeError("firestore down")
        new = dict(self.store.get(self.path) or {}) if merge else {}
        new.update(copy.deepcopy(data))
        self.store[self.path] = new

    def collection(self, name):
        return _FakeCollection(self.store, f"{self.path}/{name}")


class _FakeCollection:
    def __init__(self, store, path):
        self.store, self.path = store, path

    def document(self, doc_id):
        return _FakeDoc(self.store, f"{self.path}/{doc_id}")


class _FakeDB:
    def __init__(self, store):
        self.store = store

    def collection(self, name):
        return _FakeCollection(self.store, name)

    def batch(self):
        return _FakeBatch(self.store)


class _FakeBatch:
    """WriteBatch: buffered sets applied on commit(), all or nothing."""

    def __init__(self, store):
        self.store, self.ops = store, []

    def set(self, ref, data, merge=False):
        self.ops.append((ref, data, merge))

    def commit(self):
        if self.store.get("__raise__"):
            raise RuntimeError("firestore down")
        for ref, data, merge in self.ops:
            ref.set(data, merge=merge)


def test_gateway_selection_explicit_is_stored_and_later_runs_reuse_it(gw):
    store = {"workloads/shop": {"status": "ACTIVE"}}
    db = _FakeDB(store)
    assert gw._resolve_compliance_selection(db, "shop", "PCI_DSS") == ("PCI_DSS", "EXPLICIT_REQUEST")
    assert store["workloads/shop"] == {"status": "ACTIVE", "requested_compliance_profile": "PCI_DSS"}
    # A retrigger / SRE / refactor run carries no profile: the stored selection applies (no silent downgrade).
    assert gw._resolve_compliance_selection(db, "shop", "") == ("PCI_DSS", "WORKLOAD_SELECTION")
    assert gw._resolve_compliance_selection(db, "shop", None) == ("PCI_DSS", "WORKLOAD_SELECTION")
    # An explicit stricter value replaces it (a less strict one needs an admin approval: CP-11 tests below).
    assert gw._resolve_compliance_selection(db, "shop", "FEDRAMP_HIGH") == ("FEDRAMP_HIGH", "EXPLICIT_REQUEST")
    assert gw._resolve_compliance_selection(db, "shop", None) == ("FEDRAMP_HIGH", "WORKLOAD_SELECTION")


def test_gateway_selection_absent_everywhere_is_none(gw):
    assert gw._resolve_compliance_selection(_FakeDB({}), "new", None) == (None, None)
    assert gw._resolve_compliance_selection(None, "new", None) == (None, None)
    assert gw._resolve_compliance_selection(None, "new", "HIPAA") == ("HIPAA", "EXPLICIT_REQUEST")


def test_gateway_selection_fails_closed(gw):
    from compliance_agent.profiles import InvalidComplianceProfile
    from gate_errors import GateUnavailableError

    with pytest.raises(GateUnavailableError):
        gw._resolve_compliance_selection(_FakeDB({"__raise__": True}), "shop", None)  # unreadable
    with pytest.raises(GateUnavailableError):
        gw._resolve_compliance_selection(_FakeDB({"__raise__": True}), "shop", "HIPAA")  # unwritable
    with pytest.raises(GateUnavailableError) as ei:
        gw._resolve_compliance_selection(_FakeDB({"workloads/shop": {"requested_compliance_profile": "hipaa"}}),
                                         "shop", None)  # corrupt stored value: never STANDARD
    assert ei.value.details["error_class"] == "INVALID_COMPLIANCE_PROFILE"
    with pytest.raises(InvalidComplianceProfile):
        gw._resolve_compliance_selection(_FakeDB({}), "shop", "PCI")


def test_gateway_route_passes_the_stored_selection_to_the_server(gw, monkeypatch, server):
    import compliance_agent.handler as ch

    seen = []
    monkeypatch.setattr(ch, "httpx", _FakeHttpx(_server_respond(server, seen)))
    monkeypatch.setenv("COMPLIANCE_SERVER_URL", "http://compliance.invalid")
    monkeypatch.setattr(ch.ComplianceAgentHandler, "_persist_audit_record", lambda self, *a, **k: None)
    monkeypatch.setattr(ch.ComplianceAgentHandler, "_determine_approval_requirement", lambda self, c: c)
    # (lane 19 L19-8: the compliance handler no longer collects principals; nothing to stub)
    monkeypatch.setattr(gw, "db", _FakeDB({"workloads/shop": {"requested_compliance_profile": "HIPAA"}}))
    r = TestClient(gw.app).post("/agent/compliance/audit", json={
        "product_id": "shop", "trace_id": "t1", "spec_text": "a todo app", "task_dag": [],
        "policy_matrix": {"has_constraints": False}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["compliance_profile"] == "HIPAA" and body["compliance_profile_source"] == "WORKLOAD_SELECTION"
    assert body["profile_advisories"] == []


def test_workflow_passes_the_explicit_profile_to_the_audit():
    import yaml

    wf = yaml.safe_load(open(os.path.join(REPO_ROOT, "workflows", "main_orchestrator.yaml")))
    found = []

    def walk(node):
        if isinstance(node, dict):
            if "audit_compliance" in node:
                found.append(node["audit_compliance"]["try"]["args"]["body"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(wf)
    (body,) = found
    assert body["compliance_profile"] == '${default(map.get(args, "compliance_profile"), "")}'


def _load_compliance_gate(monkeypatch):
    from fd4g_support import load_module

    return load_module(monkeypatch, "cpe_compliance_gate",
                       os.path.join(REPO_ROOT, "mcp-servers", "terraform", "compliance_gate.py"))


def _v3_decision(profile, requested, source="EXPLICIT_REQUEST", **extra):
    return dict({"profile": profile, "profile_source": source, "requested_profile": requested,
                 "enable_direct_iap": False, "allow_unauthenticated": True, "enforce_private_ingress": False,
                 "allowed_locations": []}, **extra)


def test_pr0_gate_reads_the_same_explicit_value(monkeypatch):
    cg = _load_compliance_gate(monkeypatch)
    # A current decision (written by the audit) whose selection is still the workload's: used unchanged (Do No Harm).
    for doc in ({"compliance_decision": _v3_decision("HIPAA", "HIPAA"), "requested_compliance_profile": "HIPAA"},
                {"compliance_decision": _v3_decision("STANDARD", None, "DEFAULT_STANDARD")},
                {"compliance_decision": _v3_decision("FEDRAMP_HIGH", None, "ASSURED_WORKLOADS_FOLDER")},
                {"compliance_decision": _v3_decision("FEDRAMP_HIGH", "HIPAA", "ASSURED_WORKLOADS_FOLDER"),
                 "requested_compliance_profile": "HIPAA"}):
        db = _FakeDB({"workloads/p": copy.deepcopy(doc)})
        assert cg.load_decision(db, "p") == (doc["compliance_decision"], "WORKLOAD_DECISION")
    # No audit yet (e.g. Express): the explicit selection, never STANDARD.
    db = _FakeDB({"workloads/p": {"requested_compliance_profile": "PCI_DSS"}})
    assert cg.load_decision(db, "p") == ({"profile": "PCI_DSS"}, "WORKLOAD_SELECTION")
    # The selection outranks a bare legacy compliance_profile (no decision map).
    db = _FakeDB({"workloads/p": {"requested_compliance_profile": "STANDARD", "compliance_profile": "PCI_DSS"}})
    assert cg.load_decision(db, "p") == ({"profile": "STANDARD"}, "WORKLOAD_SELECTION")
    # ...and with no selection the legacy field is still read (unchanged).
    assert cg.load_decision(_FakeDB({"workloads/p": {"compliance_profile": "CJIS"}}), "p") == (
        {"profile": "CJIS"}, "WORKLOAD_PROFILE")
    # Nothing explicit anywhere: STANDARD, recorded as such (unchanged).
    assert cg.load_decision(_FakeDB({"workloads/p": {"status": "ACTIVE"}}), "p") == (
        {"profile": "STANDARD"}, "DEFAULT_STANDARD")
    assert cg.load_decision(_FakeDB({}), "p") == ({"profile": "STANDARD"}, "DEFAULT_STANDARD")


LEGACY_PCI = {"profile": "PCI_DSS", "enable_direct_iap": True, "allow_unauthenticated": False,
              "enforce_private_ingress": True, "allowed_locations": ["in:us-locations"], "is_regulated": True}


def test_rt_f1a_legacy_keyword_decision_is_rebased_keeping_ingress(monkeypatch):
    """Example 06 on an existing install: a pre-change keyword decision (no profile_source) must not be enforced."""
    cg = _load_compliance_gate(monkeypatch)
    db = _FakeDB({"workloads/p": {"compliance_profile": "PCI_DSS", "compliance_decision": copy.deepcopy(LEGACY_PCI)}})
    decision, source = cg.load_decision(db, "p")
    assert source == "LEGACY_DECISION_REBASED" and decision["profile"] == "STANDARD"
    # The ingress flags and allowed locations survive (they only ever restrict).
    assert {k: decision[k] for k in ("enable_direct_iap", "allow_unauthenticated", "enforce_private_ingress",
                                     "allowed_locations")} == {k: LEGACY_PCI[k] for k in (
        "enable_direct_iap", "allow_unauthenticated", "enforce_private_ingress", "allowed_locations")}
    # With a stored selection, the selection is the profile.
    db = _FakeDB({"workloads/p": {"requested_compliance_profile": "HIPAA", "compliance_decision": copy.deepcopy(LEGACY_PCI)}})
    assert cg.load_decision(db, "p")[0]["profile"] == "HIPAA"


def test_rt_f1b_decision_for_another_selection_stops_the_apply(monkeypatch):
    """Audit wrote HIPAA, then the selection became STANDARD (e.g. the next audit 503'd after the selection write)."""
    cg = _load_compliance_gate(monkeypatch)
    doc = {"requested_compliance_profile": "STANDARD", "compliance_decision": _v3_decision("HIPAA", "HIPAA")}
    with pytest.raises(cg.DecisionStale):
        cg.load_decision(_FakeDB({"workloads/p": copy.deepcopy(doc)}), "p")
    calls = []

    class _Client:
        def evaluate(self, body):
            calls.append(body)
            raise AssertionError("the server must not be asked")

    out = cg.gate_plan(db=_FakeDB({"workloads/p": copy.deepcopy(doc)}), product_id="p", trace_id="t",
                       plan_json={"resource_changes": []}, client=_Client())
    assert out["passed"] is False and out["result"]["error_class"] == "COMPLIANCE_UNAVAILABLE"
    assert out["result"]["compliance_gate"]["failure"] == "DECISION_STALE"
    assert "run a full build" in out["result"]["error"] and calls == []


def test_rt_f1c_deploy_window_standard_decision_is_not_fail_open(monkeypatch):
    """New CC stored HIPAA; an old gateway/server (no profile_source) recorded STANDARD. The gate must enforce HIPAA."""
    cg = _load_compliance_gate(monkeypatch)
    old = {"profile": "STANDARD", "enable_direct_iap": False, "allow_unauthenticated": True,
           "enforce_private_ingress": False, "allowed_locations": []}
    db = _FakeDB({"workloads/p": {"requested_compliance_profile": "HIPAA", "compliance_profile": "STANDARD",
                                  "compliance_decision": old}})
    decision, source = cg.load_decision(db, "p")
    assert (decision["profile"], source) == ("HIPAA", "LEGACY_DECISION_REBASED")
    # A current decision made for that selection is used as is.
    db = _FakeDB({"workloads/p": {"requested_compliance_profile": "HIPAA",
                                  "compliance_decision": _v3_decision("HIPAA", "HIPAA")}})
    assert cg.load_decision(db, "p")[1] == "WORKLOAD_DECISION"


def test_gateway_decision_written_now_is_read_back_unchanged_by_the_gate(monkeypatch, server):
    """End to end on one store: CC selection -> audit decision -> PR-0 gate reads the same profile."""
    import compliance_agent.handler as ch

    store = {"workloads/hipaa-claims": {"requested_compliance_profile": "HIPAA"}}
    _, h, _, _ = _handler(monkeypatch, _server_respond(server))
    monkeypatch.setattr(h, "_persist_audit_record", ch.ComplianceAgentHandler._persist_audit_record.__get__(h))
    h._db = _FakeDB(store)
    h.audit_and_enrich(_req(spec="a todo app", policy_matrix=None, compliance_profile="HIPAA",
                            compliance_profile_origin="WORKLOAD_SELECTION"))
    cg = _load_compliance_gate(monkeypatch)
    decision, source = cg.load_decision(_FakeDB(store), "hipaa-claims")
    assert (decision["profile"], source) == ("HIPAA", "WORKLOAD_DECISION")


# ============================================================================ RT F2: exact Assured Workloads match
class _AWSession:
    def __init__(self, workloads):
        self.workloads = workloads

    def get(self, url, timeout=None, **kw):
        return SimpleNamespace(status_code=200, json=lambda: {"workloads": self.workloads})


def test_rt_f2_an_unrelated_assured_workloads_folder_does_not_match(server, monkeypatch):
    monkeypatch.setenv("ORGANIZATION_ID", "123456789")   # RT14-33: the organization the workloads are listed in
    svc = server.service.ComplianceService(project_id="")
    svc._session = _AWSession([
        {"displayName": "hipaa-wl", "complianceRegime": "HIPAA",
         "resourceSettings": [{"resourceId": "999999", "resourceType": "CONSUMER_FOLDER"}]},
        {"displayName": "keyring", "complianceRegime": "FEDRAMP_HIGH",
         "resourceSettings": [{"resourceId": "123456", "resourceType": "ENCRYPTION_KEYS_PROJECT"}]},
    ])
    # Before: the `or` matched the first workload with any CONSUMER_FOLDER, for every folder.
    assert svc.inspect_parent_folder("folders/123456")["is_assured_workload"] is False
    assert svc.inspect_parent_folder("folders/555")["is_assured_workload"] is False
    hit = svc.inspect_parent_folder("folders/999999")
    assert hit["is_assured_workload"] is True and hit["compliance_regime"] == "HIPAA"
    # An explicit stricter request is not overridden by another folder's regime.
    decision = svc.resolve_profile("FEDRAMP_HIGH", svc.inspect_parent_folder("folders/123456"))
    assert (decision["profile"], decision["profile_source"]) == ("FEDRAMP_HIGH", "EXPLICIT_REQUEST")


# ============================================================================ RT F3 / F4
def test_rt_f3_no_firestore_on_cloud_run_raises(gw, monkeypatch):
    from gate_errors import GateUnavailableError

    monkeypatch.setenv("K_SERVICE", "orchestrator-gateway-service")
    for raw in (None, "", "HIPAA"):
        with pytest.raises(GateUnavailableError) as ei:
            gw._resolve_compliance_selection(None, "shop", raw)
        assert ei.value.details["failure"] == "NO_STORE"
    monkeypatch.delenv("K_SERVICE")
    assert gw._resolve_compliance_selection(None, "shop", None) == (None, None)  # off Cloud Run (tests, local)


def _intake_with(gw, monkeypatch, db, payload):
    import base64
    import json as _json
    import types

    import google.cloud.firestore as fs_mod

    monkeypatch.setattr(fs_mod, "Client", lambda *a, **k: db)
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project")
    monkeypatch.setenv("REGION", "us-central1")   # FALLBACK-URLS: dispatch needs REGION (no default)
    created = []

    class _Exec:
        def __init__(self, argument=None):
            self.argument = argument

    class _Client:
        def workflow_path(self, *a):
            return "projects/p/locations/r/workflows/w"

        def create_execution(self, parent=None, execution=None):
            created.append(execution)
            return types.SimpleNamespace(name=parent + "/executions/e-1")

    mod = types.SimpleNamespace(ExecutionsClient=_Client, Execution=_Exec)
    monkeypatch.setitem(sys.modules, "google.cloud.workflows", types.SimpleNamespace(executions_v1=mod))
    monkeypatch.setitem(sys.modules, "google.cloud.workflows.executions_v1", mod)
    monkeypatch.setitem(sys.modules, "google.cloud.workflows_v1", types.SimpleNamespace())
    monkeypatch.setattr(gw, "resolve_service_url", lambda name, *a, **k: f"https://{name}.example.run.app")
    env = {"message": {"data": base64.b64encode(_json.dumps(payload).encode()).decode(), "messageId": "m1"}}
    return TestClient(gw.app).post("/events/pubsub-intake", json=env), created


def test_rt_f4_intake_stores_the_selection_before_dispatch(gw, monkeypatch):
    from fd4f_support import FakeDB

    db = FakeDB()
    r, created = _intake_with(gw, monkeypatch, db, {"product_id": "shop", "trace_id": "tr-cp1",
                                                     "compliance_profile": "PCI_DSS"})
    assert r.status_code == 200, r.text
    assert db.docs["workloads/shop"]["requested_compliance_profile"] == "PCI_DSS" and len(created) == 1
    # Negative: an event without a profile writes no selection (an earlier one is kept).
    db2 = FakeDB()
    r, created = _intake_with(gw, monkeypatch, db2, {"product_id": "shop", "trace_id": "tr-cp2"})
    # (OSS-D23: the new product's document now carries only the private platform default access record.)
    assert r.status_code == 200 and len(created) == 1
    assert "requested_compliance_profile" not in db2.docs.get("workloads/shop", {})


def test_rt_f4_intake_selection_write_failure_is_503_not_dropped(gw, monkeypatch):
    from fd4f_support import FakeDB

    db = FakeDB()
    db.fail_writes = True
    r, created = _intake_with(gw, monkeypatch, db, {"product_id": "shop", "trace_id": "tr-cp3",
                                                     "compliance_profile": "HIPAA"})
    assert r.status_code == 503 and created == []
    r, created = _intake_with(gw, monkeypatch, FakeDB(), {"trace_id": "tr-cp4", "compliance_profile": "HIPAA"})
    assert r.status_code == 422 and created == []


def test_control_center_create_stores_and_sends_the_selection(monkeypatch):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    # CC config resolves the OAuth client id at import (Firestore) unless it is pinned by env.
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from routes import workloads as wl_routes
    from schemas import CreateWorkloadRequest

    monkeypatch.setattr(cc_db, "_db_client", False)  # "no Firestore" for every lazy lookup (the routes use a fake)
    from build_admission_support import admit_every_build
    admit_every_build(monkeypatch, wl_routes)   # BUILD-ADMISSION-QUEUE: a MagicMock store holds no build slots

    def run(**kw):
        mock_db = MagicMock()
        doc = MagicMock()
        mock_db.collection().document.return_value = doc
        monkeypatch.setattr(wl_routes, "db", mock_db)
        publisher = MagicMock()
        publisher.publish.return_value.result.return_value = "msg-1"
        monkeypatch.setattr(wl_routes, "project_id", "mock-stackvend-project", raising=False)
        request = MagicMock()
        request.state.user_email = "admin@example.com"
        request.state.user_role = "ADMIN"
        with patch.dict(os.environ, {"GITHUB_OWNER": "example-org", "MANAGED_WORKLOADS_FOLDER_ID": "111111111111"}), \
             patch("routes.workloads.get_pubsub_publisher", return_value=publisher), \
             patch("routes.workloads.get_platform_settings",  # FD-4AK: an unreadable settings doc now refuses (503)
                   return_value=__import__("routes.settings", fromlist=["x"]).PlatformSettings()):
            wl_routes.create_workload(CreateWorkloadRequest(product_id="shop-app", spec_content="a shop", **kw), request)
        import json as _json
        record = doc.set.call_args_list[0][0][0]
        payload = _json.loads(publisher.publish.call_args[0][1].decode("utf-8"))
        return record, payload

    record, payload = run(compliance_profile="HIPAA")
    assert record["requested_compliance_profile"] == "HIPAA" and payload["compliance_profile"] == "HIPAA"
    record, payload = run()
    assert "requested_compliance_profile" not in record and "compliance_profile" not in payload


# ============================================================================ owner decisions 10-18 (CP-8..CP-11)
def _aw_folder(server, monkeypatch, regime):
    monkeypatch.setattr(server.main.service, "inspect_parent_folder", lambda folder_id: {
        "folder_id": folder_id, "is_assured_workload": True, "compliance_regime": regime})
    monkeypatch.setattr(server.main.service, "inspect_org_policies", lambda folder_id: {"has_constraints": False})


def test_strictness_table_is_one_table_everywhere(server, monkeypatch):
    from compliance_agent import profiles

    cc = _cc_schemas(monkeypatch)
    assert profiles.PROFILE_STRICTNESS == server.service.PROFILE_STRICTNESS == cc.PROFILE_STRICTNESS
    assert set(profiles.PROFILE_STRICTNESS) == server.service.plan_gate.KNOWN_PROFILES
    for a in profiles.PROFILE_STRICTNESS:
        assert profiles.at_least_as_strict(a, a) and profiles.at_least_as_strict(a, "STANDARD")
        for b in profiles.PROFILE_STRICTNESS:
            assert profiles.at_least_as_strict(a, b) == server.service.at_least_as_strict(a, b)
            assert profiles.is_downgrade(a, b) == cc.profile_is_downgrade(a, b), (a, b)
    us = ["STANDARD", "PCI_DSS", "HIPAA", "FEDRAMP_MODERATE", "CJIS", "FEDRAMP_HIGH"]
    for lo, hi in zip(us, us[1:]):
        assert profiles.at_least_as_strict(hi, lo) and not profiles.at_least_as_strict(lo, hi)
    for p in us[1:]:  # EU vs US region family: incomparable both ways
        assert not profiles.at_least_as_strict("EU_REGIONS_AND_SUPPORT", p)
        assert not profiles.at_least_as_strict(p, "EU_REGIONS_AND_SUPPORT")


@pytest.mark.parametrize("regime, requested, winner, source", [
    ("HIPAA", "FEDRAMP_HIGH", "FEDRAMP_HIGH", "EXPLICIT_REQUEST"),         # the request is stricter
    ("FEDRAMP_HIGH", "HIPAA", "FEDRAMP_HIGH", "ASSURED_WORKLOADS_FOLDER"),  # the folder is stricter
    ("CJIS", "FEDRAMP_MODERATE", "CJIS", "ASSURED_WORKLOADS_FOLDER"),
    ("HIPAA", "STANDARD", "HIPAA", "ASSURED_WORKLOADS_FOLDER"),            # an explicit STANDARD never weakens a folder
    ("EU_REGIONS_AND_SUPPORT", "STANDARD", "EU_REGIONS_AND_SUPPORT", "ASSURED_WORKLOADS_FOLDER"),
])
def test_cp8_folder_vs_request_the_stricter_wins_with_a_note(server, monkeypatch, regime, requested, winner, source):
    _aw_folder(server, monkeypatch, regime)
    body = server.client.post("/inspect-folder", json={"folder_id": "folders/1", "spec_text": "a todo app",
                                                       "compliance_profile": requested}).json()
    assert (body["profile"], body["profile_source"], body["requested_profile"]) == (winner, source, requested)
    (note,) = [s for s in body["profile_suggestions"] if s.get("folder_regime")]
    assert note["folder_regime"] == regime and note["profile"] == requested
    assert regime in note["advisory"] and requested in note["advisory"] and winner in note["advisory"]


def test_cp8_the_gateway_accepts_and_records_the_stricter_request(monkeypatch, server):
    _aw_folder(server, monkeypatch, "HIPAA")
    _, h, _, persisted = _handler(monkeypatch, _server_respond(server))
    res = h.audit_and_enrich(_req(spec="a todo app", policy_matrix=None, folder_id="folders/1",
                                  compliance_profile="FEDRAMP_HIGH"))
    assert res.compliance_profile == "FEDRAMP_HIGH" and res.compliance_profile_source == "EXPLICIT_REQUEST"
    assert [a["folder_regime"] for a in res.profile_advisories if a.get("folder_regime")] == ["HIPAA"]
    assert persisted[0]["args"][0]["profile_advisories"] == res.profile_advisories   # R-6 record seam


def test_cp8_negative_same_profile_or_no_request_has_no_note(server, monkeypatch):
    _aw_folder(server, monkeypatch, "HIPAA")
    for requested in (None, "HIPAA"):
        body = server.client.post("/inspect-folder", json={"folder_id": "folders/1", "spec_text": "a todo app",
                                                           "compliance_profile": requested}).json()
        assert body["profile"] == "HIPAA" and body["profile_source"] == "ASSURED_WORKLOADS_FOLDER"
        assert not [s for s in body["profile_suggestions"] if s.get("folder_regime")]


@pytest.mark.parametrize("regime, requested", [("EU_REGIONS_AND_SUPPORT", "HIPAA"), ("HIPAA", "EU_REGIONS_AND_SUPPORT")])
def test_cp8_incomparable_pair_is_a_typed_refusal(server, monkeypatch, regime, requested):
    _aw_folder(server, monkeypatch, regime)
    r = server.client.post("/inspect-folder", json={"folder_id": "folders/1", "spec_text": "a todo app",
                                                    "compliance_profile": requested})
    assert r.status_code == 422 and r.json()["detail"]["error_class"] == "COMPLIANCE_PROFILE_CONFLICT"


@pytest.mark.parametrize("regime", ["IL4", "ITAR", "NONE", None, "COMPLIANCE_REGIME_UNSPECIFIED"])
def test_cp10_unmapped_regime_is_refused_through_the_gateway(gw, server, monkeypatch, regime):
    """Remote path end to end: the server's typed 422 becomes the route's typed 422 (never a silent STANDARD)."""
    import compliance_agent.handler as ch

    _aw_folder(server, monkeypatch, regime)
    monkeypatch.setattr(ch, "httpx", _FakeHttpx(_server_respond(server)))
    monkeypatch.setenv("COMPLIANCE_SERVER_URL", "http://compliance.invalid")
    persisted = []
    monkeypatch.setattr(ch.ComplianceAgentHandler, "_persist_audit_record", lambda self, *a, **k: persisted.append(a))
    r = TestClient(gw.app).post("/agent/compliance/audit", json={
        "product_id": "todo", "trace_id": "t1", "spec_text": "a todo app", "task_dag": [], "folder_id": "folders/1"})
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["error_class"] == "UNMAPPED_ASSURED_WORKLOADS_REGIME" and persisted == []


@pytest.mark.parametrize("error_class", ["UNMAPPED_ASSURED_WORKLOADS_REGIME", "COMPLIANCE_PROFILE_CONFLICT"])
def test_cp8_cp10_refusals_in_process_are_typed(monkeypatch, tmp_path, error_class):
    """The explicit in-process mode passes the engine's typed refusal on (not COMPLIANCE_UNAVAILABLE)."""
    import compliance_agent.handler as ch
    from compliance_agent.profiles import ComplianceProfileRefused

    engine = tmp_path / "service.py"
    engine.write_text(
        "class ProfileRefused(Exception):\n"
        "    def __init__(self, c, d):\n"
        "        super().__init__(c)\n"
        "        self.error_class, self.detail = c, d\n"
        "class ComplianceService:\n"
        "    def __init__(self, project_id=None):\n"
        "        pass\n"
        "    def inspect_folder(self, *a, **k):\n"
        f"        raise ProfileRefused({error_class!r}, 'refused')\n")
    monkeypatch.setattr(ch, "compliance_server_service_py", lambda: engine)
    _, h, _, persisted = _handler(monkeypatch, lambda *a: _resp(200, _v2()), mode="inprocess")
    with pytest.raises(ComplianceProfileRefused) as ei:
        h.audit_and_enrich(_req(spec="a todo app", policy_matrix=None))
    assert ei.value.error_class == error_class and persisted == []


def _cc_create(monkeypatch, *, existing=None, **kw):
    """CC create_workload with a fake store; returns (response or HTTPException, store)."""
    from fastapi import HTTPException
    from fd4f_support import FakeDB

    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from routes import workloads as wl_routes
    from schemas import CreateWorkloadRequest

    monkeypatch.setattr(cc_db, "_db_client", False)
    store = FakeDB()
    if existing is not None:
        store.docs["workloads/shop-app"] = dict(existing)
    monkeypatch.setattr(wl_routes, "db", store)
    publisher = MagicMock()
    publisher.publish.return_value.result.return_value = "msg-1"
    request = MagicMock()
    request.state.user_email = "admin@example.com"
    request.state.user_role = "ADMIN"
    with patch.dict(os.environ, {"GITHUB_OWNER": "example-org", "MANAGED_WORKLOADS_FOLDER_ID": "111111111111"}), \
         patch("routes.workloads.get_pubsub_publisher", return_value=publisher), \
         patch("routes.workloads.get_platform_settings",  # FD-4AK: an unreadable settings doc now refuses (503)
                   return_value=__import__("routes.settings", fromlist=["x"]).PlatformSettings()), \
         patch("routes.workloads.execute_express_provisioning", lambda **k: None):
        try:
            resp = wl_routes.create_workload(CreateWorkloadRequest(product_id="shop-app", spec_content="a shop", **kw),
                                             request)
        except HTTPException as he:
            return he, store
    return resp, store


@pytest.mark.parametrize("profile", ["HIPAA", "FEDRAMP_MODERATE", "FEDRAMP_HIGH", "CJIS", "EU_REGIONS_AND_SUPPORT",
                                     "PCI_DSS"])
def test_cp9_express_with_a_regulated_profile_is_refused_at_create(monkeypatch, profile):
    out, store = _cc_create(monkeypatch, creation_mode="EXPRESS", compliance_profile=profile)
    assert getattr(out, "status_code", None) == 422
    assert out.detail["error_class"] == "EXPRESS_REGULATED_PROFILE_UNSUPPORTED"
    assert store.writes == []  # nothing registered, nothing provisioned


@pytest.mark.parametrize("kw", [{"creation_mode": "EXPRESS"},
                                {"creation_mode": "EXPRESS", "compliance_profile": "STANDARD"},
                                {"creation_mode": "AGENT", "compliance_profile": "HIPAA"}])
def test_cp9_negative_express_standard_and_agent_regulated_are_accepted(monkeypatch, kw):
    out, store = _cc_create(monkeypatch, **kw)
    assert out.product_id == "shop-app"
    assert store.docs["workloads/shop-app"].get("requested_compliance_profile") == kw.get("compliance_profile")


def test_cp11_cc_resubmit_with_a_downgrade_needs_an_admin_card(monkeypatch):
    out, store = _cc_create(monkeypatch, existing={"requested_compliance_profile": "HIPAA"},
                            compliance_profile="STANDARD")
    assert out.status_code == 409 and out.detail["error_class"] == "COMPLIANCE_DOWNGRADE_REQUIRES_APPROVAL"
    card = store.docs[f"approval_requests/{out.detail['approval_id']}"]
    assert (card["approval_type"], card["status"], card["from_profile"], card["to_profile"]) == (
        "COMPLIANCE_PROFILE_DOWNGRADE", "PENDING", "HIPAA", "STANDARD")
    assert store.docs["workloads/shop-app"] == {"requested_compliance_profile": "HIPAA"}  # unchanged
    # Negative: an upgrade, the same profile, or a first choice needs no card.
    for existing, new in (({"requested_compliance_profile": "HIPAA"}, "FEDRAMP_HIGH"),
                          ({"requested_compliance_profile": "HIPAA"}, "HIPAA"),
                          ({"requested_compliance_profile": "STANDARD"}, "PCI_DSS"), ({}, "STANDARD")):
        out, store = _cc_create(monkeypatch, existing=existing, compliance_profile=new)
        assert out.product_id == "shop-app", (existing, new)
        assert not [k for k in store.docs if k.startswith("approval_requests/")]


@pytest.mark.parametrize("stored, requested, needs_card", [
    ("HIPAA", "STANDARD", True), ("FEDRAMP_HIGH", "HIPAA", True), ("HIPAA", "EU_REGIONS_AND_SUPPORT", True),
    ("PCI_DSS", "STANDARD", True),
    ("HIPAA", "FEDRAMP_HIGH", False), ("STANDARD", "HIPAA", False), (None, "PCI_DSS", False), ("CJIS", "CJIS", False),
])
def test_cp11_gateway_downgrade_is_refused_until_approved(gw, stored, requested, needs_card):
    from fd4f_support import FakeDB
    from gate_errors import OperatorActionRequiredError

    db = FakeDB()
    db.docs["workloads/shop"] = {"requested_compliance_profile": stored} if stored else {"status": "ACTIVE"}
    if needs_card:
        for _ in range(2):  # a retry finds the same card and is refused again
            with pytest.raises(OperatorActionRequiredError) as ei:
                gw._resolve_compliance_selection(db, "shop", requested, trace_id="t1")
            assert ei.value.reason == "COMPLIANCE_DOWNGRADE_REQUIRES_APPROVAL"
        (card,) = [v for k, v in db.docs.items() if k.startswith("approval_requests/")]
        assert (card["from_profile"], card["to_profile"], card["status"]) == (stored, requested, "PENDING")
        assert db.docs["workloads/shop"]["requested_compliance_profile"] == stored  # not stored before approval
    else:
        assert gw._resolve_compliance_selection(db, "shop", requested) == (requested, "EXPLICIT_REQUEST")
        assert db.docs["workloads/shop"]["requested_compliance_profile"] == requested
        assert not [k for k in db.docs if k.startswith("approval_requests/")]


def test_cp11_gateway_route_refusal_is_a_typed_409(gw, monkeypatch):
    from fd4f_support import FakeDB

    db = FakeDB()
    db.docs["workloads/shop"] = {"requested_compliance_profile": "HIPAA"}
    monkeypatch.setattr(gw, "db", db)
    r = TestClient(gw.app).post("/agent/compliance/audit", json={
        "product_id": "shop", "trace_id": "t1", "spec_text": "a todo app", "task_dag": [],
        "compliance_profile": "STANDARD"})
    assert r.status_code == 409, r.text
    body = r.json()
    assert body["error_class"] == "OPERATOR_ACTION_REQUIRED" and body["reason"] == "COMPLIANCE_DOWNGRADE_REQUIRES_APPROVAL"
    assert body["details"]["approval_id"].startswith("appr-cpdown-shop-")


def test_cp11_intake_downgrade_starts_no_pipeline(gw, monkeypatch):
    from fd4f_support import FakeDB

    db = FakeDB()
    db.docs["workloads/shop"] = {"requested_compliance_profile": "HIPAA"}
    r, created = _intake_with(gw, monkeypatch, db, {"product_id": "shop", "trace_id": "tr-cpd",
                                                     "compliance_profile": "STANDARD"})
    assert r.status_code == 200 and r.json()["status"] == "SUPPRESSED:COMPLIANCE_DOWNGRADE_REQUIRES_APPROVAL"
    assert created == [] and db.docs["workloads/shop"]["requested_compliance_profile"] == "HIPAA"
    assert db.docs[f"approval_requests/{r.json()['approval_id']}"]["status"] == "PENDING"


def _cc_decide(monkeypatch, store, record, decision, role="ADMIN"):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from routes import approvals
    from schemas import ApprovalDecisionRequest, UserRole

    monkeypatch.setattr(cc_db, "_db_client", False)
    monkeypatch.setattr(approvals, "db", store)
    request = MagicMock()
    request.state.user_role = UserRole(role)
    return approvals._decide("appr-x", record, ApprovalDecisionRequest(decision=decision), request,
                             "admin@example.com", "2026-10-18T00:00:00+00:00")


def test_cp11_admin_approval_applies_the_downgrade_and_the_next_run_proceeds(gw, monkeypatch):
    from fastapi import HTTPException
    from fd4f_support import FakeDB
    from gate_errors import OperatorActionRequiredError

    db = FakeDB()
    db.docs["workloads/shop"] = {"requested_compliance_profile": "HIPAA"}
    with pytest.raises(OperatorActionRequiredError) as ei:
        gw._resolve_compliance_selection(db, "shop", "STANDARD")
    record = db.docs[f"approval_requests/{ei.value.details['approval_id']}"]
    non_admin = [r for r in ("MANAGER", "VIEWER", "DEVELOPER", "OPERATOR") if r in _cc_roles(monkeypatch)]
    for role in non_admin:  # only an administrator decides
        with pytest.raises(HTTPException) as he:
            _cc_decide(monkeypatch, db, record, "APPROVED", role=role)
        assert he.value.status_code == 403
    assert db.docs["workloads/shop"]["requested_compliance_profile"] == "HIPAA"
    out = _cc_decide(monkeypatch, db, record, "APPROVED")
    assert out["status"] == "APPROVED" and db.docs["workloads/shop"]["requested_compliance_profile"] == "STANDARD"
    # The re-run with the same explicit value now proceeds (no downgrade left).
    assert gw._resolve_compliance_selection(db, "shop", "STANDARD") == ("STANDARD", "EXPLICIT_REQUEST")
    # Approving the same card again is stale (the selection is no longer HIPAA).
    with pytest.raises(HTTPException) as he:
        _cc_decide(monkeypatch, db, record, "APPROVED")
    assert he.value.status_code == 409


def _cc_roles(monkeypatch):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    from schemas import UserRole

    return {r.value for r in UserRole} - {"ADMIN"}


def test_cp11_rejection_keeps_the_regulated_profile(gw, monkeypatch):
    from fd4f_support import FakeDB
    from gate_errors import OperatorActionRequiredError

    db = FakeDB()
    db.docs["workloads/shop"] = {"requested_compliance_profile": "PCI_DSS"}
    with pytest.raises(OperatorActionRequiredError) as ei:
        gw._resolve_compliance_selection(db, "shop", "STANDARD")
    key = f"approval_requests/{ei.value.details['approval_id']}"
    out = _cc_decide(monkeypatch, db, db.docs[key], "REJECTED")
    assert out["status"] == "REJECTED" and db.docs["workloads/shop"]["requested_compliance_profile"] == "PCI_DSS"
    db.docs[key].update(out)
    with pytest.raises(OperatorActionRequiredError):  # still refused: the card stays REJECTED
        gw._resolve_compliance_selection(db, "shop", "STANDARD")
