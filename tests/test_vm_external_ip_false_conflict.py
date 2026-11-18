"""VM-EXTERNAL-IP-FALSE-CONFLICT: the "no external VM IPs" plan conflict applies only to a plan that can have a VM.

The check reads the plan's prose, so a plan with no VM could raise it. That forced a plan approval and injected a NAT
step that renders nothing. The architect's typed compute record now decides "no VM" for the compute it lists. A plan
with a VM in that record, a GKE plan, and any run whose record cannot be read get exactly the decision the prose check
gives them. A VM written outside the record is the known limit (see the test named test_limit_...).

Hermetic: the gateway loaded by path, a fake server answer and a fake Firestore.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

from types import SimpleNamespace

import pytest

from test_compliance_bundle import _handler, _req, _resp, _v2, gw  # noqa: F401  (fixtures + helpers reused)
from test_private_ingress_early_stop import PID, TRACE, _store, topology_record

NAT_STEP = "STEP-01B-VPC-NAT"
CONFLICT = ("Folder enforces constraints/compute.vmExternalIpAccess. Public IPs on VMs are prohibited; workload must use "
            "Private IPs with Cloud NAT and IAP SSH Bastion.")
MATRIX = {"disallow_vm_external_ip": True, "has_constraints": True}
DAG = [{"step_id": "STEP-01-APIS", "title": "APIs"},
       {"step_id": "STEP-06-COMPUTE", "title": "Compute", "depends_on": ["STEP-01-APIS"]}]
# Prose that trips the check with no VM in the plan: "bastion" next to "external ip".
NO_VM_PROSE = "# Plan\nOne Cloud Run service; no bastion is needed. The load balancer has a global external IP."
VM_PROSE = "# Plan\nA GCE vm instance with a public ip for the batch worker."
GKE_PROSE = "# Plan\nA private GKE cluster. GCE nodes keep a public ip for debugging."


def _legacy(**over):
    return {"schema": "architect_compute_intent/v1", "target_compute_services": [PID], "bundle_id": None,
            "compute_archetype": None, **over}


NO_VM_RECORDS = {
    "cloud_run": topology_record([("api", "cloudrun")], "api"),
    "cloud_run_pair": topology_record([("gw", "cloudrun"), ("core", "cloudrun")], "gw", [("gw", "core", "http")]),
    "cloud_run_and_event_worker": topology_record([("api", "cloudrun"), ("jobs", "event-worker")], "api",
                                                  [("api", "jobs", "pubsub")]),
    "legacy_cloud_run": _legacy(compute_archetype="cloudrun"),
    "legacy_event_worker": _legacy(compute_archetype="event-worker"),
    "legacy_foundation_only": _legacy(compute_archetype="foundation-only", target_compute_services=[]),
    "legacy_cloud_run_bundle": _legacy(bundle_id="secure-three-tier-web"),
}
VM_RECORDS = {
    # example 03's shape
    "cloud_run_launches_gce_worker": topology_record([("api", "cloudrun"), ("batch", "gce-worker")], "api",
                                                     [("api", "batch", "launch")]),
    "gce_bastion": topology_record([("jump", "gce-bastion")], "jump"),
    "legacy_gce_bastion": _legacy(compute_archetype="gce-bastion"),
}
GKE_RECORDS = {
    "gke": topology_record([("apps", "gke-autopilot")], "apps"),
    "gke_behind_cloud_run": topology_record([("apps", "gke-autopilot"), ("web", "cloudrun")], "apps"),
    "legacy_gke": _legacy(compute_archetype="gke-autopilot"),
    "legacy_gke_bundle": _legacy(bundle_id="private-gke-microservices"),
}
# Neither is a statement that the plan has no VM.
UNSTATED_RECORDS = {"legacy_names_only": _legacy(), "legacy_empty_list": _legacy(target_compute_services=[])}


def _audit(monkeypatch, *, record=None, store=True, plan=NO_VM_PROSE, matrix=None, trace_id=TRACE, **store_kw):
    """The full compliance stage. Returns (response, persisted decision, fake store or None)."""
    _, h, _, persisted = _handler(monkeypatch, lambda *a: _resp(200, _v2(policy_matrix=dict(matrix or MATRIX))))
    db = _store(h, record, **store_kw) if store else None
    res = h.audit_and_enrich(_req(product_id=PID, trace_id=trace_id, spec="a batch system",
                                  policy_matrix=dict(matrix or MATRIX), plan_markdown=plan,
                                  task_dag=[dict(t) for t in DAG]))
    return res, persisted[-1]["args"][0], db


def _stable(res, saved):
    """The whole decision, minus the two clock fields of the persisted record."""
    return res.model_dump(), {k: v for k, v in saved.items() if k not in ("decided_at", "timestamp")}


def _assert_conflict_decision(res):
    assert res.policy_conflicts == [CONFLICT] and res.has_policy_conflicts is True
    assert res.requires_human_approval is True and res.status == "ENRICHED" and res.is_regulated is True
    ids = [t["step_id"] for t in res.enriched_dag]
    assert ids == ["STEP-01-APIS", NAT_STEP, "STEP-06-COMPUTE"]
    compute = next(t for t in res.enriched_dag if t["step_id"] == "STEP-06-COMPUTE")
    assert compute["depends_on"] == ["STEP-01-APIS", NAT_STEP]
    assert "Tier 3 Compliance Safety Remediation" in res.plan_markdown


# ------------------------------------------------------------------------------------------------ 1. no VM in the plan
@pytest.mark.parametrize("name", NO_VM_RECORDS)
def test_no_vm_plan_has_no_conflict_no_card_no_nat_step(monkeypatch, gw, name):
    res, saved, db = _audit(monkeypatch, record=NO_VM_RECORDS[name])
    assert res.policy_conflicts == [] and res.has_policy_conflicts is False
    assert res.requires_human_approval is False and res.status == "PASSED" and res.is_regulated is False
    assert res.enriched_dag == DAG and NAT_STEP not in str(res.model_dump())
    assert "Tier 3 Compliance Safety Remediation" not in res.plan_markdown
    assert saved["has_policy_conflicts"] is False and saved["policy_conflicts"] == []
    assert db.reads == 1


@pytest.mark.parametrize("plan", [
    "# Plan\nCloud Run API. Also a google_compute_instance license server with an access_config external ip.",
    "# Plan\nCloud Run API. A google_compute_instance_template for a MIG; access_config gives each VM a public ip.",
], ids=["instance_in_custom_tf", "template_in_custom_tf"])
def test_limit_the_record_cannot_see_a_vm_written_outside_the_typed_compute(monkeypatch, gw, plan):
    """The stated limit, pinned (F2-1, register row): the record lists the platform's compute only, so these plans lose
    the plan-level conflict. V2e refuses the access_config in the generated HCL (test_step2b_hcl_chain.py)."""
    res, _, _ = _audit(monkeypatch, record=NO_VM_RECORDS["cloud_run"], plan=plan)
    assert res.policy_conflicts == [] and res.requires_human_approval is False and res.status == "PASSED"


def test_no_vm_plan_keeps_every_other_conflict(monkeypatch, gw):
    """Only this conflict is decided by the typed record: a real static-key conflict on the same plan still stands."""
    matrix = {**MATRIX, "disable_sa_key_creation": True}
    res, _, _ = _audit(monkeypatch, record=NO_VM_RECORDS["cloud_run"], matrix=matrix,
                       plan=NO_VM_PROSE + "\nCreates a google_service_account_key for the job.")
    assert len(res.policy_conflicts) == 1 and "disableServiceAccountKeyCreation" in res.policy_conflicts[0]
    assert res.requires_human_approval is True
    assert NAT_STEP not in [t["step_id"] for t in res.enriched_dag]


# --------------------------------------------------------- 2. VM and GKE plans: the same decision the prose check gives
@pytest.mark.parametrize("name", VM_RECORDS)
def test_vm_plan_raises_the_conflict_and_injects_the_nat_step(monkeypatch, gw, name):
    res, _, db = _audit(monkeypatch, record=VM_RECORDS[name], plan=VM_PROSE)
    _assert_conflict_decision(res)
    assert db.reads == 1


@pytest.mark.parametrize("name", GKE_RECORDS)
def test_gke_plan_whose_prose_trips_the_check_still_conflicts(monkeypatch, gw, name):
    res, _, _ = _audit(monkeypatch, record=GKE_RECORDS[name], plan=GKE_PROSE)
    _assert_conflict_decision(res)


@pytest.mark.parametrize("record, plan", [(r, VM_PROSE) for r in VM_RECORDS.values()]
                         + [(r, GKE_PROSE) for r in GKE_RECORDS.values()],
                         ids=[*VM_RECORDS, *GKE_RECORDS])
def test_vm_and_gke_decisions_are_identical_to_the_prose_check_alone(monkeypatch, gw, record, plan):
    """The prose check alone is the behaviour before this change (no typed answer offered)."""
    typed = _stable(*_audit(monkeypatch, record=record, plan=plan)[:2])
    _, h, _, persisted = _handler(monkeypatch, lambda *a: _resp(200, _v2(policy_matrix=dict(MATRIX))))
    original = h.evaluate_policy_invariants
    monkeypatch.setattr(h, "evaluate_policy_invariants", lambda m, p, d, typed_compute_has_no_vm=None: original(m, p, d))
    res = h.audit_and_enrich(_req(product_id=PID, trace_id=TRACE, spec="a batch system", policy_matrix=dict(MATRIX),
                                  plan_markdown=plan, task_dag=[dict(t) for t in DAG]))
    assert typed == _stable(res, persisted[-1]["args"][0])


@pytest.mark.parametrize("record", [*VM_RECORDS.values(), *GKE_RECORDS.values(), *NO_VM_RECORDS.values()],
                         ids=[*VM_RECORDS, *GKE_RECORDS, *NO_VM_RECORDS])
def test_plan_the_prose_check_passes_never_reads_the_record(monkeypatch, gw, record):
    """Private VMs behind Cloud NAT were no conflict before and are none now, with no extra store read."""
    res, _, db = _audit(monkeypatch, record=record, plan="# Plan\nA GCE vm instance on a private subnet; Cloud NAT.")
    assert res.has_policy_conflicts is False and res.status == "PASSED"
    assert db.reads == 0


def test_policy_off_never_reads_the_record(monkeypatch, gw):
    res, _, db = _audit(monkeypatch, record=VM_RECORDS["gce_bastion"], plan=VM_PROSE,
                        matrix={"disallow_vm_external_ip": False, "has_constraints": False})
    assert res.has_policy_conflicts is False and db.reads == 0


# ----------------------------------------------------------------------- 3. "could not check" never clears the conflict
@pytest.mark.parametrize("name", UNSTATED_RECORDS)
def test_a_defaulted_archetype_does_not_clear_the_conflict(monkeypatch, gw, name):
    res, _, _ = _audit(monkeypatch, record=UNSTATED_RECORDS[name])
    _assert_conflict_decision(res)


@pytest.mark.parametrize("kw", [
    dict(doc_missing=True),
    dict(record=None),
    dict(record={}),
    dict(fail=RuntimeError("firestore down")),
    dict(record=_legacy(compute_archetype="mainframe")),                    # outside the enum: the resolver raises
    dict(record={**NO_VM_RECORDS["cloud_run"], "service_topology": {"sha256": "drift"}}),  # the resolver refuses it
], ids=["no_document", "no_record", "empty_record", "read_failed", "bad_archetype", "bad_topology"])
def test_an_unreadable_record_keeps_the_conflict(monkeypatch, gw, kw):
    res, _, _ = _audit(monkeypatch, **kw)
    _assert_conflict_decision(res)


def test_no_store_keeps_the_conflict(monkeypatch, gw):
    """The eval harness and local runs have no store on purpose."""
    res, _, _ = _audit(monkeypatch, store=False)
    _assert_conflict_decision(res)


def test_no_trace_keeps_the_conflict(monkeypatch, gw):
    res, _, db = _audit(monkeypatch, record=NO_VM_RECORDS["cloud_run"], trace_id="")
    _assert_conflict_decision(res)
    assert db.reads == 0


# ---------------------------------------------------------------------------------------------- 4. the typed question
def _intent(archetype, *kinds, source="architect.service_topology"):
    names = tuple(f"s{i}" for i in range(len(kinds)))
    by_name = dict(zip(names, kinds))
    return SimpleNamespace(archetype=archetype, service_names=names, archetype_source=source, topology=object(),
                           kind_of=by_name.get)


@pytest.mark.parametrize("intent, expected", [
    (_intent("cloudrun", "cloudrun"), True),
    (_intent("cloudrun", "cloudrun", "event-worker"), True),
    (_intent("foundation-only"), True),
    (_intent("cloudrun", "cloudrun", "gce-worker"), False),
    (_intent("gce-bastion", "gce-bastion"), False),
    (_intent("gke-autopilot", "gke-autopilot"), False),
    (_intent("gke-autopilot", "gke-autopilot", "cloudrun"), False),
    (_intent("cloudrun", "cloudrun", "a-kind-added-later"), False),
    (_intent("a-kind-added-later", "a-kind-added-later"), False),
], ids=["cloudrun", "cloudrun_event_worker", "foundation", "gce_worker", "bastion", "gke", "gke_cloudrun",
        "unknown_secondary", "unknown_primary"])
def test_typed_compute_has_no_vm(gw, intent, expected):
    from compliance_agent.vm_presence import typed_compute_has_no_vm

    assert typed_compute_has_no_vm(intent) is expected


def test_callback_is_only_asked_when_the_prose_check_would_conflict(gw):
    import compliance_agent.handler as ch

    asked = []

    def answer():
        asked.append(1)
        return True

    check = ch.ComplianceAgentHandler.evaluate_policy_invariants
    assert check(None, dict(MATRIX), "# Plan\nOne Cloud Run service.", [], typed_compute_has_no_vm=answer) == [] and not asked
    assert check(None, dict(MATRIX), NO_VM_PROSE, [], typed_compute_has_no_vm=answer) == [] and asked == [1]
    assert check(None, dict(MATRIX), NO_VM_PROSE, []) == [CONFLICT]
