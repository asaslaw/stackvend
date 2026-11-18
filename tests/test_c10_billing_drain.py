"""C10 (owner 11-07 "B"): billing-alert-drain-job and shared/billing_alerts.py.

Must-haves (design review F10, F13-F15): delivery claim + per-period latch (duplicate delivery,
re-sent alert with a new message id), ack only after a verified enforcer outcome, no ack on failure (redelivery ->
DLQ), payload trust (install billing account, exact budget mapping), the workload's breach policy honoured by the real
enforcer engine (HITL -> card, never scale-to-zero), enforcement switch off -> today's outcome (no ack).
Hermetic: in-memory Firestore and REST fakes (tests/c10_fakes.py); no google client is built.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import os
import sys
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
DRAIN_DIR = os.path.join(REPO, "apps", "billing-alert-drain")
FINOPS_DIR = os.path.join(REPO, "apps", "finops-enforcer")
for p in (HERE, REPO):
    if p not in sys.path:
        sys.path.insert(0, p)

import c10_fakes as F  # noqa: E402


def _load(name, directory, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(directory, filename))
    mod = importlib.util.module_from_spec(spec)
    added = directory not in sys.path
    if added:
        sys.path.append(directory)   # release_info (byte-identical copies everywhere)
    try:
        spec.loader.exec_module(mod)
    finally:
        if added:
            sys.path.remove(directory)
    return mod


with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_APPLICATION_CREDENTIALS": "/nonexistent/c10-adc.json"}):
    drain = _load("c10_billing_drain_main", DRAIN_DIR, "main.py")
    enf = _load("c10_enforcer", FINOPS_DIR, "enforcer.py")
    # Not patch.dict(sys.modules, ...): on exit it would also drop every module main.py imported for the first time
    # (fastapi, pydantic, ...), and a second import of pydantic later in the session gives other tests duplicate
    # model classes. Only the `enforcer` alias is set and removed.
    _prior_enforcer = sys.modules.get("enforcer")
    sys.modules["enforcer"] = enf
    try:
        enf_main = _load("c10_enforcer_main", FINOPS_DIR, "main.py")
    finally:
        if _prior_enforcer is None:
            sys.modules.pop("enforcer", None)
        else:
            sys.modules["enforcer"] = _prior_enforcer

from shared import billing_alerts as BA  # noqa: E402



HOST = "mock-stackvend-project"
ACCT ="01ABCD-234567-89EF01"
ROOT = "111111111111"
JOB_PATH = f"projects/{HOST}/locations/us-central1/jobs/finops-budget-enforcer-job"
ENV = {"PROJECT_ID": HOST, "REGION": "us-central1", "CLOUD_RUN_EXECUTION": "drain-exec-1",
       "BILLING_ALERTS_SUBSCRIPTION": f"projects/{HOST}/subscriptions/billing-alerts-push-subscription",
       "FINOPS_ENFORCER_JOB": "finops-budget-enforcer-job", "BILLING_ACCOUNT_ID": f"billingAccounts/{ACCT}",
       "BILLING_BREACH_ENFORCEMENT": "true"}
WORKLOAD = {"product_id": "shop-app", "project_id": "shop-app-1", "budget_ceiling_monthly_usd": 100.0,
            "budget_breach_policy": "AUTONOMOUS_SCALE_TO_ZERO"}


def _db(**workload):
    db = F.FakeDB()
    db.put("workloads", "shop-app", dict(WORKLOAD, **workload))
    return db


def _alert(cost, mid="m-1", account=ACCT, budget_id="", name="budget-shop-app", period="2026-11-01T07:00:00Z",
           ack_id=None):
    attrs = {"billingAccountId": account, "schemaVersion": "1.0"}
    if budget_id:
        attrs["budgetId"] = budget_id
    return F.message(mid, F.b64({"budgetDisplayName": name, "costAmount": cost, "costIntervalStart": period}), attrs,
                     ack_id=ack_id)


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


def _enforcer_records(db, outcome):
    """on_run: the enforcer execution writes its run record (what finops-budget-enforcer-job does)."""
    def on_run(body):
        rest.execution = f"{JOB_PATH}/executions/finops-budget-enforcer-job-x{len(db.ops)}"
        db.put("finops-budget-enforcer-job_runs", rest.execution.rsplit("/", 1)[-1], {"outcome": outcome})
    rest = F.FakeRest(on_run=on_run)
    return rest


def _run(db, rest, env=None, clock=None):
    clock = clock or Clock()
    return drain.run(dict(ENV, **(env or {})), database=db, session=rest, clock=clock, sleep=clock.sleep)


def _acked(rest):
    return [c[1]["ackIds"][0] for c in rest.calls if c[0] == "acknowledge"]


def _runs(rest):
    return [c[1] for c in rest.calls if c[0] == "run"]


# ------------------------------------------------------------------------------------------------ breach path
def test_breach_runs_the_enforcer_with_overrides_and_acks_only_after_the_verified_outcome():
    db = _db()
    rest = _enforcer_records(db, "QUARANTINED")
    rest.queue = [_alert(120.0)]
    code, summary = _run(db, rest)
    assert code == 0 and summary["outcome"] == "COMPLETED"
    [body] = _runs(rest)
    env = {e["name"]: e["value"] for e in body["overrides"]["containerOverrides"][0]["env"]}
    assert env == {"FINOPS_ENFORCE_PRODUCT_ID": "shop-app", "FINOPS_ENFORCE_TARGET_PROJECT_ID": "shop-app-1",
                   "FINOPS_ENFORCE_SPEND_AMOUNT": "120.0", "FINOPS_ENFORCE_BUDGET_AMOUNT": "100.0",
                   "FINOPS_ENFORCE_POLICY": "AUTONOMOUS_SCALE_TO_ZERO", "FINOPS_ENFORCE_TRACE_ID": "billing-alert-m-1"}
    verbs = rest.verbs()
    # lease extended before processing; the ack comes after the enforcer's run record was read
    assert verbs.index("modifyAckDeadline") < verbs.index("run") < verbs.index("acknowledge")
    assert _acked(rest) == ["ack-m-1"]
    assert db.doc("billing_alert_deliveries", "m-1")["status"] == "DONE"
    latch = db.doc("workloads", "shop-app")[BA.LATCH_FIELD]
    assert (latch["period"], latch["threshold"], latch["outcome"]) == ("2026-11", 100.0, "QUARANTINED")
    assert db.doc("workloads", "shop-app")["current_spend_usd"] == 120.0
    assert summary["enforcements"][0]["outcome"] == "QUARANTINED"


def test_duplicate_delivery_of_the_same_message_is_acked_without_side_effects():
    db = _db()
    rest = _enforcer_records(db, "QUARANTINED")
    rest.queue = [_alert(120.0)]
    assert _run(db, rest)[0] == 0
    db.docs[("workloads", "shop-app")].pop(BA.LATCH_FIELD)   # even without the latch, the claim stops it
    rest.calls.clear()
    rest.queue = [_alert(120.0)]
    code, summary = _run(db, rest, env={"CLOUD_RUN_EXECUTION": "drain-exec-2"})
    assert code == 0 and summary["by_status"] == {"DUPLICATE_DELIVERY": 1}
    assert _runs(rest) == [] and _acked(rest) == ["ack-m-1"]


def test_re_sent_alert_with_a_new_message_id_never_enforces_twice():
    db = _db()
    rest = _enforcer_records(db, "HITL_CONFIRMATION_PENDING")
    rest.queue = [_alert(120.0, mid="m-1"), _alert(130.0, mid="m-2")]
    code, summary = _run(db, rest)
    assert code == 0 and len(_runs(rest)) == 1
    assert summary["by_status"] == {"QUARANTINE_EXECUTED": 1, "ALREADY_ENFORCED": 1}
    assert _acked(rest) == ["ack-m-1", "ack-m-2"]
    assert db.doc("workloads", "shop-app")["current_spend_usd"] == 130.0   # spend still recorded


def test_a_new_period_or_threshold_re_arms_the_latch():
    db = _db()
    rest = _enforcer_records(db, "QUARANTINED")
    rest.queue = [_alert(120.0, mid="m-1"), _alert(120.0, mid="m-2", period="2026-12-01T08:00:00Z")]
    _run(db, rest)
    assert len(_runs(rest)) == 2
    db.docs[("workloads", "shop-app")]["buffer_ceiling_usd"] = 115.0     # an approved buffer ceiling
    rest.queue = [_alert(120.0, mid="m-3", period="2026-12-01T08:00:00Z")]
    _run(db, rest, env={"CLOUD_RUN_EXECUTION": "drain-exec-2"})
    assert len(_runs(rest)) == 3


@pytest.mark.parametrize("outcome", ["FAILED", "INVALID_REQUEST", "NOT_CONFIGURED", "RUNNING"])
def test_enforcer_failure_is_not_acked_and_a_redelivery_retries(outcome):
    db = _db()
    rest = _enforcer_records(db, outcome)
    rest.queue = [_alert(120.0)]
    code, summary = _run(db, rest)
    assert code == 1 and summary["outcome"] == "COMPLETED_WITH_ERRORS"
    assert _acked(rest) == [] and summary["not_acked"][0]["code"] == "QUARANTINE_FAILED"
    assert [c for c in rest.calls if c[0] != "pull"][-1] == \
        ("modifyAckDeadline", {"ackIds": ["ack-m-1"], "ackDeadlineSeconds": 600})   # held out, not acked
    assert db.doc("billing_alert_deliveries", "m-1")["status"] == "FAILED"
    assert BA.LATCH_FIELD not in db.doc("workloads", "shop-app")
    # Pub/Sub redelivers the message to a later run; this time the enforcer succeeds
    ok = _enforcer_records(db, "QUARANTINED")
    ok.queue = [_alert(120.0, ack_id="ack-m-1b")]
    code, summary = _run(db, ok, env={"CLOUD_RUN_EXECUTION": "drain-exec-2"})
    assert code == 0 and _acked(ok) == ["ack-m-1b"] and db.doc("billing_alert_deliveries", "m-1")["status"] == "DONE"


def test_a_message_not_processed_is_not_retried_in_the_same_run():
    db = _db()
    rest = _enforcer_records(db, "FAILED")
    rest.queue = [_alert(120.0), _alert(120.0, ack_id="ack-again")]
    _run(db, rest)
    assert len(_runs(rest)) == 1 and _acked(rest) == []
    assert ("modifyAckDeadline", {"ackIds": ["ack-again"], "ackDeadlineSeconds": 600}) in rest.calls


def test_enforcer_run_refused_or_no_outcome_is_not_acked():
    db = _db()
    rest = F.FakeRest(run_status=403)
    rest.queue = [_alert(120.0)]
    code, summary = _run(db, rest)
    assert code == 1 and _acked(rest) == [] and summary["not_acked"][0]["code"] == "QUARANTINE_FAILED"
    # the execution starts but never writes an outcome and never completes: bounded wait, then not acked
    rest = F.FakeRest(execution=f"{JOB_PATH}/executions/finops-budget-enforcer-job-zz", exec_complete=False)
    rest.queue = [_alert(120.0, mid="m-9")]
    clock = Clock()
    code, summary = _run(db, rest, env={"CLOUD_RUN_EXECUTION": "drain-exec-2"}, clock=clock)
    assert code == 1 and _acked(rest) == [] and clock.t >= drain.ENFORCER_WAIT_S
    # the lease was extended while waiting
    assert sum(1 for v in rest.verbs() if v == "modifyAckDeadline") >= 1 + drain.ENFORCER_WAIT_S // drain.EXTEND_EVERY_S


def test_execution_finished_without_a_run_record_is_not_acked():
    db = _db()
    rest = F.FakeRest(execution=f"{JOB_PATH}/executions/finops-budget-enforcer-job-q", exec_complete=True)
    rest.queue = [_alert(120.0)]
    code, summary = _run(db, rest)
    assert code == 1 and _acked(rest) == []


def test_enforcement_switched_off_keeps_todays_outcome_no_ack():
    db = _db()
    rest = _enforcer_records(db, "QUARANTINED")
    rest.queue = [_alert(120.0)]
    code, summary = _run(db, rest, env={"BILLING_BREACH_ENFORCEMENT": "false"})
    assert code == 1 and _runs(rest) == [] and _acked(rest) == []
    assert summary["not_acked"][0]["code"] == "ENFORCEMENT_DISABLED"
    assert db.doc("workloads", "shop-app")["current_spend_usd"] == 120.0


def test_enforcement_flag_must_be_exact():
    db = _db()
    rest = F.FakeRest()
    rest.queue = [_alert(120.0)]
    code, summary = _run(db, rest, env={"BILLING_BREACH_ENFORCEMENT": "yes"})
    assert code == 1 and summary["outcome"] == "FAILED" and rest.calls == []


# ------------------------------------------------------------------------------------------------ trust + ack rules
@pytest.mark.parametrize("account", ["", "99ZZZZ-000000-000000", "billingAccounts/99ZZZZ-000000-000000"])
def test_wrong_or_missing_billing_account_is_ignored_with_zero_writes_and_acked(account):
    db = _db()
    rest = F.FakeRest()
    rest.queue = [_alert(500.0, account=account)]
    code, summary = _run(db, rest)
    assert code == 0 and summary["by_status"] == {"IGNORED": 1} and _acked(rest) == ["ack-m-1"]
    assert "current_spend_usd" not in db.doc("workloads", "shop-app") and _runs(rest) == []


def test_recorded_budget_id_must_match_the_attribute():
    db = _db(billing_budget_id="b-123")
    rest = F.FakeRest()
    rest.queue = [_alert(500.0, budget_id="b-999")]          # display name matches, budget id does not
    assert _run(db, rest)[1]["by_status"] == {"IGNORED": 1}
    assert "current_spend_usd" not in db.doc("workloads", "shop-app")
    rest = _enforcer_records(db, "QUARANTINED")
    rest.queue = [_alert(500.0, mid="m-2", budget_id="b-123", name="anything")]   # exact budget id lookup
    assert _run(db, rest, env={"CLOUD_RUN_EXECUTION": "drain-exec-2"})[1]["by_status"] == {"QUARANTINE_EXECUTED": 1}


@pytest.mark.parametrize("name", ["budget-", "budget-shop", "shop-app", "budget-shop-app-extra", "BUDGET-shop-app"])
def test_display_name_fallback_is_exact(name):
    db = _db()
    rest = F.FakeRest()
    rest.queue = [_alert(500.0, name=name)]
    assert _run(db, rest)[1]["by_status"] == {"IGNORED": 1}


@pytest.mark.parametrize("data", ["not-base64!", F.b64([1, 2]), F.b64({"costAmount": "lots"})])
def test_unparseable_is_recorded_then_acked_with_a_typed_log(data, caplog):
    """RT finding 5: the forensic record (what the dead-letter queue used to keep) is written before the ack."""
    db = _db()
    rest = F.FakeRest()
    rest.queue = [F.message("m-1", data, {"billingAccountId": ACCT})]
    code, summary = _run(db, rest)
    assert code == 0 and summary["by_status"] == {"UNPARSEABLE": 1} and _acked(rest) == ["ack-m-1"]
    assert summary["unparseable"] == ["m-1"]
    rec = db.doc("billing_alert_deliveries", "m-1")
    assert rec["status"] == "UNPARSEABLE" and rec["attributes"] == {"billingAccountId": ACCT}
    assert rec["data_prefix"] == data[:200]
    writes = {op[1][0] for op in db.ops if op[0] in ("set", "create", "update")}
    assert writes == {"billing_alert_deliveries", "billing-alert-drain-job_runs", "billing-alert-drain-job_leases"}
    assert "current_spend_usd" not in db.doc("workloads", "shop-app")
    assert "BILLING_ALERT_UNPARSEABLE" in caplog.text


def test_under_and_warning_thresholds_are_processed_and_acked():
    db = _db()
    rest = F.FakeRest()
    rest.queue = [_alert(50.0, mid="m-1"), _alert(85.0, mid="m-2")]
    code, summary = _run(db, rest)
    assert code == 0 and summary["by_status"] == {"UNDER_THRESHOLD": 1, "WARNING_THRESHOLD": 1}
    assert _acked(rest) == ["ack-m-1", "ack-m-2"] and _runs(rest) == []
    assert db.coll("billing_alerts")["budget-warning-shop-app-2026-11"]["code"] == "BUDGET_WARNING_THRESHOLD"


def test_missing_config_is_not_configured_exit_3():
    for key in drain.REQUIRED_ENV:
        code, summary = drain.run({k: v for k, v in ENV.items() if k != key}, database=_db(), session=F.FakeRest())
        assert code == 3 and summary["outcome"] == "NOT_CONFIGURED" and key in summary["missing"]


def test_run_cap_keeps_the_job_inside_its_timeout():
    db = _db()
    rest = F.FakeRest()
    rest.queue = [_alert(10.0, mid=f"m-{i}") for i in range(drain.MAX_MESSAGES_PER_RUN + 5)]
    summary = _run(db, rest)[1]
    assert summary["handled"] == drain.MAX_MESSAGES_PER_RUN and len(rest.queue) == 5


def test_pull_failure_is_a_failed_run():
    class Broken(F.FakeRest):
        def post(self, url, json=None, timeout=None):
            return F.Resp(403, {})
    code, summary = _run(_db(), Broken())
    assert code == 1 and summary["outcome"] == "FAILED" and "PUBSUB_PULL_FAILED" in summary["error"]


def test_enforced_statuses_match_the_enforcer():
    assert BA.ENFORCED_STATUSES == enf_main.ENFORCED_STATUSES


# ------------------------------------------------------------------------------------------------ policy via the engine
def _crm():
    crm = MagicMock(name="crm")
    projects = crm.projects.return_value

    def get_ancestry(projectId, body):
        call = MagicMock()
        call.execute.return_value = {"ancestor": [{"resourceId": {"type": "project", "id": projectId}},
                                                  {"resourceId": {"type": "folder", "id": ROOT}}]}
        return call

    def get(projectId):
        call = MagicMock()
        call.execute.return_value = {"projectNumber": "222" if projectId == "shop-app-1" else "999"}
        return call

    projects.getAncestry.side_effect = get_ancestry
    projects.get.side_effect = get
    return crm


@pytest.mark.parametrize("policy, outcome", [("HITL_CONFIRMATION_REQUIRED", "HITL_CONFIRMATION_PENDING"),
                                             ("ALERT_ONLY", "ALERTED_ONLY")])
def test_the_workload_policy_is_honoured_by_the_real_engine(monkeypatch, policy, outcome):
    """HITL -> a BUDGET_BREACH approval card and NO scale-to-zero (the engine the enforcer job runs)."""
    monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", ROOT)
    monkeypatch.setenv("PROJECT_ID", HOST)
    db = _db(budget_breach_policy=policy)
    run_service = MagicMock(name="run")
    engine = enf.FinopsBudgetEnforcer(project_id=HOST, firestore_client=db, run_service=run_service,
                                      compute_service=MagicMock(), sql_service=MagicMock(),
                                      container_service=MagicMock(), billing_service=MagicMock(), crm_service=_crm(),
                                      advisor=SimpleNamespace(available=False))

    def on_run(body):
        execution_id = "finops-budget-enforcer-job-h1"
        rest.execution = f"{JOB_PATH}/executions/{execution_id}"
        env = {e["name"]: e["value"] for e in body["overrides"]["containerOverrides"][0]["env"]}
        env.update(PROJECT_ID=HOST, CLOUD_RUN_EXECUTION=execution_id)
        enf_main.run_batch(env, engine)          # what the execution does with these overrides

    rest = F.FakeRest(on_run=on_run)
    rest.queue = [_alert(120.0)]
    code, summary = _run(db, rest)
    assert code == 0 and summary["enforcements"][0]["outcome"] == outcome and _acked(rest) == ["ack-m-1"]
    run_service.projects.assert_not_called()      # nothing scaled to zero
    cards = [v for v in db.coll("approval_requests").values() if v.get("approval_type") == "BUDGET_BREACH"]
    assert len(cards) == (1 if policy == "HITL_CONFIRMATION_REQUIRED" else 0)
    # a re-sent alert (new message id) opens no second card
    rest.queue = [_alert(140.0, mid="m-2")]
    _run(db, rest, env={"CLOUD_RUN_EXECUTION": "drain-exec-2"})
    assert len([v for v in db.coll("approval_requests").values() if v.get("approval_type") == "BUDGET_BREACH"]) \
        == len(cards)


def test_default_policy_is_unchanged_scale_to_zero():
    db = _db()
    db.docs[("workloads", "shop-app")].pop("budget_breach_policy")
    rest = _enforcer_records(db, "QUARANTINED")
    rest.queue = [_alert(120.0)]
    _run(db, rest)
    env = {e["name"]: e["value"] for e in _runs(rest)[0]["overrides"]["containerOverrides"][0]["env"]}
    assert env["FINOPS_ENFORCE_POLICY"] == "AUTONOMOUS_SCALE_TO_ZERO"


# ------------------------------------------------------------------------------------------------ RT findings 2, 3, 9
def test_an_empty_pull_with_a_backlog_does_not_end_the_run():
    """RT finding 2: Pub/Sub may answer a pull with nothing although messages wait; only 3 empty pulls in a row end
    the run."""
    db = _db()
    rest = F.FakeRest()
    rest.pull_script = [[], [_alert(50.0)], [], [], []]
    code, summary = _run(db, rest)
    assert code == 0 and summary["handled"] == 1 and _acked(rest) == ["ack-m-1"]
    assert [c[1]["maxMessages"] for c in rest.calls if c[0] == "pull"] == [drain.PULL_BATCH] * 5


def test_a_batch_is_handled_one_message_at_a_time():
    db = _db()
    rest = F.FakeRest()
    rest.queue = [_alert(10.0, mid=f"m-{i}") for i in range(12)]
    code, summary = _run(db, rest)
    assert code == 0 and summary["handled"] == 12 and len(_acked(rest)) == 12


def test_leftover_batch_messages_are_released_at_the_run_cap(monkeypatch):
    monkeypatch.setattr(drain, "MAX_MESSAGES_PER_RUN", 3)
    db = _db()
    rest = F.FakeRest()
    rest.queue = [_alert(10.0, mid=f"m-{i}") for i in range(5)]
    summary = _run(db, rest)[1]
    assert summary["handled"] == 3 and summary["released"] == 2
    assert ("modifyAckDeadline", {"ackIds": ["ack-m-3", "ack-m-4"], "ackDeadlineSeconds": 0}) in rest.calls


def test_a_refusal_is_not_a_month_latch_but_is_re_asked_after_24_hours():
    """RT finding 3: REFUSED (often a configuration state) is retried once a day, not latched for the month."""
    db = _db()
    rest = _enforcer_records(db, "REFUSED")
    rest.queue = [_alert(120.0, mid="m-1")]
    assert _run(db, rest)[1]["by_status"] == {"REFUSED": 1}
    w = db.doc("workloads", "shop-app")
    assert BA.LATCH_FIELD not in w and w[BA.REFUSAL_FIELD]["outcome"] == "REFUSED"
    # a re-sent alert an hour later: not asked again
    refused_at = datetime.fromisoformat(w[BA.REFUSAL_FIELD]["at"])
    data, cost = BA.decode_billing_notification(_alert(130.0, mid="m-2")["message"]["data"])
    enforcer = MagicMock()
    out = BA.process_billing_notification(db, data, cost, {"billingAccountId": ACCT}, lambda: enforcer,
                                          install_billing_account=ACCT, now=refused_at + timedelta(hours=1))
    assert out["status"] == "ALREADY_REFUSED" and not enforcer.quarantine_workload.called
    # 25 hours later the enforcer is asked again (a fixed configuration takes effect)
    enforcer.quarantine_workload.return_value = {"status": "QUARANTINED"}
    out = BA.process_billing_notification(db, data, cost, {"billingAccountId": ACCT}, lambda: enforcer,
                                          install_billing_account=ACCT, now=refused_at + timedelta(hours=25))
    assert out["status"] == "QUARANTINE_EXECUTED" and enforcer.quarantine_workload.call_count == 1
    assert db.doc("workloads", "shop-app")[BA.LATCH_FIELD]["outcome"] == "QUARANTINED"


def test_only_enforced_outcomes_latch():
    for outcome in BA.ENFORCED_STATUSES:
        assert BA.latch_matches({"period": "2026-11", "threshold": 100.0, "outcome": outcome}, "2026-11", 100.0)
    for outcome in ("REFUSED", "FAILED", "", None):
        assert not BA.latch_matches({"period": "2026-11", "threshold": 100.0, "outcome": outcome}, "2026-11", 100.0)


def test_an_expired_ack_id_is_counted_not_fatal():
    """RT finding 9: exactly-once PERMANENT_FAILURE_INVALID_ACK_ID on an ack is a WARNING; pull failures stay fatal."""
    db = _db()
    rest = F.FakeRest()
    rest.queue = [_alert(10.0, mid="m-1"), _alert(10.0, mid="m-2")]
    rest.expired_ack_ids = {"ack-m-1"}
    code, summary = _run(db, rest)
    assert code == 0 and summary["handled"] == 2 and summary["ack_expired"] >= 1
    assert db.doc("billing_alert_deliveries", "m-1")["status"] == "DONE"
    assert _acked(rest)[-1] == "ack-m-2"


def _billing_reading(account):
    """RT14-05: a billing client whose read-back shows `account` (the restore checks the relink)."""
    billing = MagicMock(name="billing")
    billing.projects.return_value.getBillingInfo.return_value.execute.return_value = {
        "billingAccountName": account}
    return billing


def test_restore_clears_the_breach_latch_so_a_new_breach_acts_again(monkeypatch):
    """RT finding 6: the enforcer's restore re-arms enforcement for the same month."""
    monkeypatch.setenv("MANAGED_WORKLOADS_FOLDER_ID", ROOT)
    monkeypatch.setenv("PROJECT_ID", HOST)
    db = _db(status="BILLING_UNLINKED", root_billing_account="billingAccounts/" + ACCT)   # recorded at unlink
    latch = {"period": "2026-11", "threshold": 100.0, "outcome": "BILLING_UNLINKED", "at": "2026-11-10T00:00:00+00:00"}
    db.docs[("workloads", "shop-app")][BA.LATCH_FIELD] = latch
    db.docs[("workloads", "shop-app")][BA.REFUSAL_FIELD] = dict(latch, outcome="REFUSED")
    engine = enf.FinopsBudgetEnforcer(project_id=HOST, firestore_client=db, run_service=MagicMock(),
                                      compute_service=MagicMock(), sql_service=MagicMock(),
                                      container_service=MagicMock(),
                                      billing_service=_billing_reading("billingAccounts/" + ACCT), crm_service=_crm(),
                                      advisor=SimpleNamespace(available=False))
    out = engine.restore_workload(product_id="shop-app", target_project_id="shop-app-1")
    assert out["status"] == "BILLING_RESTORED"
    w = db.doc("workloads", "shop-app")
    assert w[BA.LATCH_FIELD] is None and w[BA.REFUSAL_FIELD] is None and w["status"] == "ACTIVE"
    data, cost = BA.decode_billing_notification(_alert(150.0, mid="m-9")["message"]["data"])
    enforcer = MagicMock()
    enforcer.quarantine_workload.return_value = {"status": "QUARANTINED"}
    res = BA.process_billing_notification(db, data, cost, {"billingAccountId": ACCT}, lambda: enforcer,
                                          install_billing_account=ACCT)
    assert res["status"] == "QUARANTINE_EXECUTED" and enforcer.quarantine_workload.call_count == 1
