"""QA-STAGE2-POLICY (owner 10-27): the security judge's ingress policy comes from the workload's access record and
the persisted compliance decision (access_resolution.resolve_access, most restrictive wins), never from the
top-level workloads/{pid}.allow_unauthenticated / enable_direct_iap / requires_vpc fields nothing writes. A missing or
unusable record stops QA with GATE_UNAVAILABLE QA_ACCESS_POLICY (fail closed)."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import pytest

import fd4f_support  # noqa: F401  (puts the gateway dir on sys.path)
from fd4f_support import (QA_IAP_ACCESS, SHA_A, SHA_B, FakeBackend, FakeDB, FakeQAClient, backend_factory,
                          judge_reply, passing_outcome, seed_compliance_decision)

import qa_auditor.judge as judge_mod  # noqa: E402

PUBLIC = {"mode": "PUBLIC_APP", "sign_in": {"google": "BYO"}, "tenant_isolation_required": True, "source": "intake"}
IAM = {"mode": "PRIVATE_IAM", "invoker_principals": ["serviceAccount:caller@p.iam.gserviceaccount.com"],
       "sign_in": {"google": "DISABLED"}, "source": "operator_hitl"}
BRANCH = "castor/app-1"
DAG = [{"task_id": "t1", "title": "svc"}]


@pytest.fixture()
def gw(monkeypatch):
    mod = fd4f_support.load_gateway(monkeypatch, "qa_policy_gw")
    yield mod
    mod.app.dependency_overrides.clear()


def _db(workload, *, decision=None):
    db = FakeDB()
    db.docs["workloads/app"] = workload
    db.docs["pipeline_executions/tr-1"] = {"stages": {"architect": {"details": {"task_dag": DAG}},
                                                      "compliance": {"summary": "ok"}}}
    if decision is not None:
        seed_compliance_decision(db, **decision)
    return db


def _policy(gw, db):
    return gw._fetch_pipeline_context_for_qa("app", "tr-1", db)["ingress_policy"]


# ------------------------------------------------------------------ resolution
def test_private_iap_record(gw):
    pol = _policy(gw, _db({"access": dict(QA_IAP_ACCESS)}, decision={}))
    assert pol == {"access_mode": "PRIVATE_IAP", "access_source": "workload_record", "allow_unauthenticated": False,
                   "enable_direct_iap": True, "invoker_principal_count": 1}


def test_public_app_record(gw):
    pol = _policy(gw, _db({"access": dict(PUBLIC)},
                          decision={"allow_unauthenticated": True, "enable_direct_iap": False}))
    assert pol["access_mode"] == "PUBLIC_APP" and pol["allow_unauthenticated"] is True
    assert pol["enable_direct_iap"] is False


def test_private_iam_record(gw):
    pol = _policy(gw, _db({"access": dict(IAM)},
                          decision={"allow_unauthenticated": False, "enable_direct_iap": False}))
    assert pol["access_mode"] == "PRIVATE_IAM" and pol["allow_unauthenticated"] is False
    assert pol["enable_direct_iap"] is False


def test_no_record_public_decision_is_public_from_compliance_flags(gw):
    pol = _policy(gw, _db({}, decision={"allow_unauthenticated": True, "enable_direct_iap": False}))
    assert pol["access_mode"] == "PUBLIC_APP" and pol["access_source"] == "compliance_flags"


def test_never_written_top_level_fields_are_ignored(gw):
    # the old source: a top-level allow_unauthenticated=True must not open a PRIVATE_IAP workload
    pol = _policy(gw, _db({"allow_unauthenticated": True, "enable_direct_iap": False, "requires_vpc": True,
                           "access": dict(QA_IAP_ACCESS)}, decision={}))
    assert pol["access_mode"] == "PRIVATE_IAP" and pol["allow_unauthenticated"] is False
    assert "requires_vpc" not in pol


# ------------------------------------------------------------------ fail closed
@pytest.mark.parametrize("workload,decision,failure", [
    ({"access": dict(QA_IAP_ACCESS)}, None, "COMPLIANCE_DECISION_UNAVAILABLE"),            # no compliance decision
    ({}, {"allow_unauthenticated": False, "enable_direct_iap": True}, "ACCESS_POLICY_INCOMPLETE"),  # private, no record
    ({"access": {"mode": "PRIVATE_IAP", "sign_in": {"google": "DISABLED"}, "source": "intake"}}, {},
     "ACCESS_POLICY_INCOMPLETE"),                                                         # no principals
    ({"access": {"mode": "NOPE"}}, {}, "ACCESS_POLICY_INVALID"),                          # unparseable record
    ({"access": dict(PUBLIC)}, {"allow_unauthenticated": False, "enable_direct_iap": True},
     "ACCESS_COMPLIANCE_CONFLICT"),                                                       # most restrictive wins
    ({"access": dict(QA_IAP_ACCESS), "access_widening_approval": {"by": "x"}}, {}, "ACCESS_WIDENING_UNAPPROVED"),
])
def test_missing_or_unusable_record_fails_closed(gw, workload, decision, failure):
    with pytest.raises(gw.GateUnavailableError) as ei:
        _policy(gw, _db(workload, decision=decision))
    assert ei.value.reason == "QA_ACCESS_POLICY" and ei.value.details["failure"] == failure


def test_decision_of_another_product_fails_closed(gw):
    db = _db({"access": dict(QA_IAP_ACCESS)}, decision={})
    db.docs["workloads/app/compliance_audits/tr-1"]["product_id"] = "other"
    with pytest.raises(gw.GateUnavailableError) as ei:
        _policy(gw, db)
    assert ei.value.reason == "QA_ACCESS_POLICY"


def test_run_qa_without_a_decision_is_gate_unavailable_and_no_judge_runs(gw, monkeypatch):
    calls = []
    monkeypatch.setattr(judge_mod, "call", lambda p, m, **k: calls.append(p) or judge_reply()(p, m))
    db = _db({"access": dict(QA_IAP_ACCESS)}, decision=None)
    backend = FakeBackend({BRANCH: {"apps/app/main.py": b"x = 1\n"}, "main": {}}, {BRANCH: SHA_A, "main": SHA_B})
    req = gw.QAVerifyRequest(trace_id="tr-1", product_id="app", branch_name=BRANCH)
    with pytest.raises(gw.GateUnavailableError) as ei:
        gw.run_qa(req, client=FakeQAClient(passing_outcome()), source_backend_factory=backend_factory(backend),
                  evidence_db=db)
    assert ei.value.reason == "QA_ACCESS_POLICY" and calls == []
    assert db.docs["qa_test_runs/tr-1"]["passed"] is False


# ------------------------------------------------------------------ the security prompt
def _prompts(monkeypatch, policy):
    from qa_auditor.adherence_lens import evaluate_adherence_lens
    from qa_auditor.security_lens import evaluate_security_lens

    seen = []
    monkeypatch.setattr(judge_mod, "call", lambda p, m, **k: seen.append(p) or judge_reply()(p, m))
    monkeypatch.setattr(judge_mod.secrets, "token_hex", lambda n: "f" * (2 * n))
    evaluate_security_lens("+x", ingress_policy=policy, model_name="m")
    evaluate_adherence_lens("+x", task_dag=DAG, model_name="m")
    return seen


def test_iap_prompt_states_the_real_mode(gw, monkeypatch):
    pol = _policy(gw, _db({"access": dict(QA_IAP_ACCESS)}, decision={}))
    sec, _ = _prompts(monkeypatch, pol)
    assert "- Access Mode: PRIVATE_IAP" in sec
    assert "- Allow Unauthenticated Web Ingress: False" in sec
    assert "- Identity-Aware Proxy In Front Of The Service: True" in sec
    assert "Requires Dedicated VPC" not in sec
    assert "is NOT the workload's setting" in sec


def test_public_prompt_permits_all_users(gw, monkeypatch):
    pol = _policy(gw, _db({"access": dict(PUBLIC)}, decision={"allow_unauthenticated": True,
                                                              "enable_direct_iap": False}))
    sec, _ = _prompts(monkeypatch, pol)
    assert "- Access Mode: PUBLIC_APP" in sec and "- Allow Unauthenticated Web Ingress: True" in sec


def test_policy_does_not_change_the_adherence_request(gw, monkeypatch):
    iap = _policy(gw, _db({"access": dict(QA_IAP_ACCESS)}, decision={}))
    pub = _policy(gw, _db({"access": dict(PUBLIC)}, decision={"allow_unauthenticated": True,
                                                              "enable_direct_iap": False}))
    _, adh_iap = _prompts(monkeypatch, iap)
    _, adh_pub = _prompts(monkeypatch, pub)
    assert adh_iap == adh_pub


def test_non_boolean_policy_values_read_as_restrictive(monkeypatch):
    sec, _ = _prompts(monkeypatch, {"access_mode": 7, "allow_unauthenticated": "true", "enable_direct_iap": 1})
    assert "- Access Mode: UNKNOWN" in sec and "- Allow Unauthenticated Web Ingress: False" in sec
    assert "- Identity-Aware Proxy In Front Of The Service: False" in sec
