"""SECRET-INITIAL-VERSION red-team hardening (docs/planning/secret-initial-version-rt.md, 11-10).

F1: the plan JSON the terraform server returns (`generate_plan` `raw_plan_json`, stored by tf-applier in Firestore)
masks every value the engine marks sensitive, by the engine's own typed marks (never names); the real-engine fixture is
an OpenTofu 1.9.0 re-plan (`show -json`) of a 64-character random_password, a value derived from it, a module's
password, a sensitive root variable and output, and a sensitive module argument.
F2: the gated apply never adds the golden module's random first version over a secret that already has an enabled
version (Pass 0 / 409 adoption), checked through the Secret Manager REST API; an unreadable answer is a typed stop.
F3: database passwords that golden database modules generate are never topology secrets (architect contract).
Owner 11-10: warning-only; one policy point (SECRET_ADVISORY_PAUSES_PLAN, False) decides it.
F9: the CC card block for the secret advisories. Hermetic.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import)

import copy
import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
for p in (os.path.dirname(__file__), REPO_ROOT, os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")):
    if p not in sys.path:
        sys.path.insert(0, p)

from test_lane14_compliance_gate import FakeDB as TfFakeDB  # noqa: E402
from test_lane14_compliance_gate import HIPAA_DECISION, FakeRunner, _svc, _wire_gate  # noqa: E402

FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "secret_initial_version", "replan_tofu190.json")
PASS = {"gate_contract_version": 1, "decision": "PASS", "violations": []}


@pytest.fixture()
def tf(monkeypatch):
    from fd4g_support import load_tf_service

    return load_tf_service(monkeypatch)


def _redaction(tf):
    return tf.plan_redaction


def _guard(tf):
    return tf.secret_generation_guard


# ------------------------------------------------------------------------------------------------ F1 plan JSON
def _fixture_secrets(plan):
    """The values the fixture's engine marks sensitive (read from the raw fixture, independent of the code)."""
    out = {"rootvar-secret-value", "child-literal-secret", "child-default-secret"}
    for rc in plan["resource_changes"]:
        if rc["type"] == "random_password":
            out |= {rc["change"]["before"]["result"], rc["change"]["before"]["bcrypt_hash"]}
    return out


def test_real_replan_json_carries_secrets_and_the_masked_copy_none(tf):
    plan = json.load(open(FIXTURE))
    assert plan["terraform_version"] == "1.9.0"
    secrets = _fixture_secrets(plan)
    raw = json.dumps(plan)
    assert all(s in raw for s in secrets)   # the engine writes them in clear text (prior_state, before/after, ...)
    red = _redaction(tf).redact_plan_json(plan)
    text = json.dumps(red)
    assert [s for s in secrets if s in text] == []
    assert json.dumps(plan) == raw   # the input is never changed
    for plain in ("plain-name", "plain-output", "child-literal-label", "child-label", '"two"'):
        assert plain in text, plain   # Do No Harm: what the engine does not mark is unchanged
    # the structure is kept: the same keys, addresses and actions
    assert [rc["address"] for rc in red["resource_changes"]] == [rc["address"] for rc in plan["resource_changes"]]
    assert [rc["change"]["actions"] for rc in red["resource_changes"]] == \
        [rc["change"]["actions"] for rc in plan["resource_changes"]]
    assert red["resource_changes"][0]["change"]["before"]["result"] == "(sensitive value)"


def _secret_version_and_sql_password_plan():
    """A google 6.35.0-shaped re-plan: the golden module's version (secret_data is provider-sensitive) and a Cloud SQL
    user password, both no-op, with the engine's marks; and a plain bucket."""
    gen = "G" * 64
    sql = "P" * 32
    return {"format_version": "1.2", "configuration": {"root_module": {}},
            "resource_changes": [
                {"address": "module.order_signing_secret.google_secret_manager_secret_version.generated[0]",
                 "type": "google_secret_manager_secret_version", "name": "generated", "index": 0,
                 "module_address": "module.order_signing_secret",
                 "change": {"actions": ["no-op"], "before": {"secret_data": gen, "deletion_policy": "ABANDON"},
                            "after": {"secret_data": gen, "deletion_policy": "ABANDON"},
                            "before_sensitive": {"secret_data": True}, "after_sensitive": {"secret_data": True}}},
                {"address": "module.db.google_sql_user.app", "type": "google_sql_user", "name": "app",
                 "module_address": "module.db",
                 "change": {"actions": ["no-op"], "before": {"name": "app", "password": sql},
                            "after": {"name": "app", "password": sql},
                            "before_sensitive": {"password": True}, "after_sensitive": {"password": True}}},
                {"address": "google_storage_bucket.b", "type": "google_storage_bucket", "name": "b",
                 "change": {"actions": ["no-op"], "before": {"name": "bkt"}, "after": {"name": "bkt"},
                            "before_sensitive": {}, "after_sensitive": {}}}],
            "prior_state": {"values": {"root_module": {"child_modules": [
                {"address": "module.order_signing_secret", "resources": [
                    {"address": "module.order_signing_secret.random_password.initial[0]",
                     "values": {"result": gen, "length": 64}, "sensitive_values": {"result": True}}]},
                {"address": "module.db", "resources": [
                    {"address": "module.db.google_sql_user.app", "values": {"name": "app", "password": sql},
                     "sensitive_values": {"password": True}}]}]}}},
            "planned_values": {"root_module": {}}}, gen, sql


def test_generated_key_and_cloud_sql_password_are_masked(tf):
    plan, gen, sql = _secret_version_and_sql_password_plan()
    text = json.dumps(_redaction(tf).redact_plan_json(plan))
    assert gen not in text and sql not in text
    assert '"name": "bkt"' in text and '"deletion_policy": "ABANDON"' in text and '"name": "app"' in text


def test_negative_a_plan_without_marks_is_returned_unchanged(tf):
    plan = {"format_version": "1.2", "configuration": {"root_module": {"variables": {"x": {"default": "a"}}}},
            "variables": {"x": {"value": "a"}},
            "resource_changes": [{"address": "google_storage_bucket.b", "change": {
                "actions": ["create"], "before": None, "after": {"name": "b", "labels": {"k": "v"}},
                "after_unknown": {"id": True}, "before_sensitive": False, "after_sensitive": {"labels": {}}}}],
            "output_changes": {"o": {"actions": ["create"], "before": None, "after": "v", "after_sensitive": False}},
            "planned_values": {"outputs": {"o": {"sensitive": False, "value": "v"}}, "root_module": {
                "resources": [{"address": "google_storage_bucket.b", "values": {"name": "b"},
                               "sensitive_values": {}}]}}}
    assert _redaction(tf).redact_plan_json(plan) == plan


def test_generate_plan_returns_the_masked_json(tf, monkeypatch, tmp_path):
    plan, gen, sql = _secret_version_and_sql_password_plan()
    svc = tf.TerraformService(project_id="host", state_bucket="b", workspace_base_dir=str(tmp_path / "ws"),
                              firestore_client=TfFakeDB({}))
    ok = {"success": True, "exit_code": 0, "stderr": ""}
    runs = iter([dict(ok, stdout="init"), dict(ok, stdout="{}"), dict(ok, stdout="Plan"),
                 dict(ok, stdout=json.dumps(plan))])
    monkeypatch.setattr(svc, "_ensure_binary", lambda *a, **k: "tofu")
    monkeypatch.setattr(svc, "_run_subprocess", lambda *a, **k: next(runs))
    res = svc.generate_plan("auth-service", "trace-siv", {"main.tf": "# x"}, iac_engine="OPENTOFU")
    assert res["status"] == "PLAN_READY", res
    text = json.dumps(res["raw_plan_json"])
    assert gen not in text and sql not in text and '"name": "bkt"' in text
    assert res["resource_changes"]["add"] == 0   # the summary reads the unmasked plan as before


# ------------------------------------------------------------------------------------------------ F2 adoption
def _adopted_plan(*, version_actions=("create",), secret_actions=("no-op",), module="module.order_signing_secret"):
    return {"format_version": "1.2", "configuration": {"root_module": {}}, "resource_changes": [
        {"address": f"{module}.google_secret_manager_secret.secret", "mode": "managed",
         "type": "google_secret_manager_secret", "name": "secret", "module_address": module,
         "change": {"actions": list(secret_actions),
                    "before": {"project": "child-1", "secret_id": "order-signing-secret"},
                    "after": {"project": "child-1", "secret_id": "order-signing-secret"}}},
        {"address": f"{module}.random_password.initial[0]", "mode": "managed", "type": "random_password",
         "name": "initial", "index": 0, "module_address": module, "change": {"actions": ["create"]}},
        {"address": f"{module}.google_secret_manager_secret_version.generated[0]", "mode": "managed",
         "type": "google_secret_manager_secret_version", "name": "generated", "index": 0, "module_address": module,
         "change": {"actions": list(version_actions), "before": None, "after": {"deletion_policy": "ABANDON"}}}]}


def test_pure_rule_finds_only_a_generated_version_over_an_existing_secret(tf):
    g = _guard(tf)
    [pair] = g.generated_versions_over_existing_secrets(_adopted_plan())
    assert pair["project"] == "child-1" and pair["secret_id"] == "order-signing-secret"
    assert pair["version_address"].endswith("google_secret_manager_secret_version.generated[0]")
    # a secret created by the same apply has no version to shadow; a version already in state is not created
    assert g.generated_versions_over_existing_secrets(_adopted_plan(secret_actions=("create",))) == []
    assert g.generated_versions_over_existing_secrets(_adopted_plan(version_actions=("no-op",))) == []
    assert g.generated_versions_over_existing_secrets({"resource_changes": []}) == []
    assert g.generated_versions_over_existing_secrets(None) == []
    assert g.versions_url("child-1", "order-signing-secret") == (
        "https://secretmanager.googleapis.com/v1/projects/child-1/secrets/order-signing-secret/versions"
        "?filter=state%3AENABLED&pageSize=1")
    assert g.enabled_versions(200, {}) == 0 and g.enabled_versions(200, {"versions": [{"name": "v/1"}]}) == 1
    assert g.enabled_versions(403, {}) is None and g.enabled_versions(200, None) is None
    assert g.enabled_versions(200, {"versions": "x"}) is None


class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


def _gated(monkeypatch, tf, tmp_path, plan_json, answer):
    calls = []
    _wire_gate(monkeypatch, tf, None, calls, status=200, payload=PASS)
    store = copy.deepcopy(HIPAA_DECISION)
    svc, ws = _svc(tf, tmp_path, store)
    runner = FakeRunner(plan_json)
    monkeypatch.setattr(svc, "_run_subprocess", runner)
    monkeypatch.setattr(svc, "_child_credentials", lambda project, scoped=True: f"creds-{project}")
    gets = []

    class _Session:
        def __init__(self, creds):
            self.creds = creds

        def get(self, url, timeout=None):
            gets.append((self.creds, url))
            if isinstance(answer, Exception):
                raise answer
            return answer

    patcher = patch("google.auth.transport.requests.AuthorizedSession", _Session)
    patcher.start()
    return svc, ws, runner, store, gets, patcher


def test_an_existing_value_refuses_the_apply_typed(monkeypatch, tf, tmp_path):
    svc, ws, runner, store, gets, p = _gated(monkeypatch, tf, tmp_path, _adopted_plan(),
                                             _Resp(200, {"versions": [{"name": "v/1", "state": "ENABLED"}]}))
    try:
        with pytest.raises(tf.SecretGenerationRefused) as ei:
            svc._compliance_gated_apply("claims", "t-siv", ws, "OPENTOFU")
    finally:
        p.stop()
    assert isinstance(ei.value, tf.DestroyBlocked)   # every DestroyBlocked handler returns .result
    r = ei.value.result
    assert r["code"] == "APPLY.SECRET_GENERATION_WOULD_SHADOW_EXISTING" and r["operator_required"] is True
    assert r["error_class"] == "SECRET_GENERATION_WOULD_SHADOW_EXISTING" and "order-signing-secret" in r["error"]
    assert runner.calls == ["plan", "show"]   # nothing applied
    assert gets == [("creds-child-1", tf.secret_generation_guard.versions_url("child-1", "order-signing-secret"))]
    ev = store["workloads/claims/compliance_audits/t-siv"]["enforcement"]
    assert ev["gate"] == "secret_generation" and ev["code"] == r["code"]


def test_an_existing_secret_without_versions_applies(monkeypatch, tf, tmp_path):
    svc, ws, runner, _store, gets, p = _gated(monkeypatch, tf, tmp_path, _adopted_plan(), _Resp(200, {}))
    try:
        res = svc._compliance_gated_apply("claims", "t", ws, "OPENTOFU")
    finally:
        p.stop()
    assert res["success"] is True and runner.calls == ["plan", "show", "apply"] and len(gets) == 1


@pytest.mark.parametrize("answer", [_Resp(403, {"error": {}}), _Resp(200, ValueError("not json")),
                                    RuntimeError("network")], ids=["403", "not json", "exception"])
def test_unreadable_versions_are_a_typed_stop_never_a_pass(monkeypatch, tf, tmp_path, answer):
    svc, ws, runner, _store, _gets, p = _gated(monkeypatch, tf, tmp_path, _adopted_plan(), answer)
    try:
        with pytest.raises(tf.SecretGenerationRefused) as ei:
            svc._compliance_gated_apply("claims", "t", ws, "OPENTOFU")
    finally:
        p.stop()
    assert ei.value.result["code"] == "APPLY.SECRET_VERSIONS_UNREADABLE"
    assert ei.value.result["operator_required"] is True and runner.calls == ["plan", "show"]


@pytest.mark.parametrize("plan", [
    _adopted_plan(secret_actions=("create",)),        # a new secret (the normal first deploy)
    _adopted_plan(version_actions=("no-op",)),         # the version is already in state (every later deploy)
    {"format_version": "1.2", "configuration": {"root_module": {}}, "resource_changes": []},   # flag false: no version
], ids=["new secret", "version in state", "no generated version"])
def test_negative_no_check_and_no_call_without_the_adoption_case(monkeypatch, tf, tmp_path, plan):
    svc, ws, runner, _store, gets, p = _gated(monkeypatch, tf, tmp_path, plan, RuntimeError("must not be called"))
    try:
        res = svc._compliance_gated_apply("claims", "t", ws, "OPENTOFU")
    finally:
        p.stop()
    assert res["success"] is True and gets == [] and runner.calls == ["plan", "show", "apply"]


# ------------------------------------------------------------------------------------------------ F3 contract
def test_database_passwords_are_never_topology_secrets():
    from shared import iac_intent as II
    from shared import service_topology as ST

    line = ST.SECRET_CONTRACT_LINE
    assert ST.SECRET_CONTRACT_LINE in ST.render_topology_contract()
    for t in ST.DATABASE_PASSWORD_TYPES:
        assert f"`{t}`" in line and t in ST.BOOTSTRAP_CATALOG
    assert "never a `google_secret_manager_secret` resource" in line and "do not list it" in line
    art = II.load_artifacts()
    realizing = {t: [m for (m, rt) in II.REALIZATION_EXPORTS if rt == t] for t in ST.DATABASE_PASSWORD_TYPES}
    for t, mods in realizing.items():
        assert mods, t
        for m in mods:   # the realizing golden module generates the password and keeps it in its own secret
            declares = set(art.module(m)["declares_types"])
            assert {"random_password", "google_secret_manager_secret"} <= declares, (t, m)


# ------------------------------------------------------------------------------------------------ HOLD policy point
def _topology_vt():
    from shared import service_topology as ST

    raw = {"services": [{"name": "svc", "kind": "cloudrun"}], "primary_service": "svc",
           "resources": [{"type": "google_secret_manager_secret", "logical_name": "stripe_key",
                          "initial_value": "operator", "consumers": [{"service": "svc", "env_key": "STRIPE_KEY"}]}]}
    vt, _d = ST.validate_service_topology(raw, product_id="p")
    return vt


def test_one_policy_point_turns_the_pause_into_a_warning(monkeypatch):
    import workflow_gates as wg

    adv = wg.secret_advisories(_topology_vt())
    base = {"requires_human_approval": False, "has_policy_conflicts": False}
    fin = {"requires_human_approval": False, "monthly_cost_delta_usd": 1.0}
    assert wg.SECRET_ADVISORY_PAUSES_PLAN is False   # owner 11-10: warning-only
    assert wg.evaluate_pre_build_gate(compliance=base, finops=fin, secret_advisories=adv) == ("PASS", [])
    monkeypatch.setattr(wg, "SECRET_ADVISORY_PAUSES_PLAN", True)   # the one switch, should the owner change it
    assert wg.evaluate_pre_build_gate(compliance=base, finops=fin, secret_advisories=adv) == (
        "AWAIT_APPROVAL", ["SECRET_CREATED_EMPTY"])
    assert adv[0]["message"].startswith("The platform creates stripe_key without a value")
    assert "unless the workload's own infrastructure adds one" in adv[0]["message"]


def test_warning_only_keeps_the_advisories_on_the_gate_decision(monkeypatch):
    """The default (owner 11-10: warning-only) through the real route."""
    from fastapi.testclient import TestClient

    from fd4f_support import FakeDB, load_gateway
    gw = load_gateway(monkeypatch)
    vt = _topology_vt()
    db = FakeDB()
    db.docs["workloads/p"] = {"product_id": "p"}
    db.docs["pipeline_executions/t-w"] = {"architect_compute_intent": {
        "schema": "architect_compute_intent/v2", "service_topology": vt.as_record()}}
    gw.app.dependency_overrides[gw.get_governance_db] = lambda: db
    try:
        r = TestClient(gw.app).post("/events/pre-build-gate", json={
            "trace_id": "t-w", "product_id": "p", "callback_url": "https://workflowexecutions.googleapis.com/v1/cb",
            "rework_cycle": 0, "compliance": {"requires_human_approval": False, "has_policy_conflicts": False},
            "finops": {"requires_human_approval": False, "monthly_cost_delta_usd": 1.0}, "finops_error": "",
            "policy_harvest_status": "SUCCESS", "operator_requested": False, "spec_doc_id": "", "task_dag": []})
    finally:
        gw.app.dependency_overrides.clear()
    assert r.json()["decision"] == "PASS"
    gate = db.docs["pipeline_executions/t-w"]["prebuild_gate"]
    assert [a["code"] for a in gate["secret_advisories"]] == ["SECRET.OPERATOR_VALUE_REQUIRED"]


# ------------------------------------------------------------------------------------------------ F9 CC card block
def _cc_approvals():
    if CC_DIR not in sys.path:
        sys.path.insert(0, CC_DIR)
    os.environ.setdefault("GOOGLE_OAUTH_CLIENT_ID", "secret-advisory-test.apps.example.com")
    from routes import approvals

    return approvals


def _cc_item(monkeypatch, card):
    from fd4f_support import FakeDB

    approvals = _cc_approvals()
    store = FakeDB()
    store.docs["approval_requests/appr-plan-t1-0"] = card
    monkeypatch.setattr(approvals, "db", store)
    req = SimpleNamespace(state=SimpleNamespace(user_email="admin@example.com", user_role="ADMIN",
                                                auth_method="session", assigned_workloads=["p"]),
                          headers={}, path_params={})
    monkeypatch.setattr(approvals, "workload_scope", lambda request: SimpleNamespace(all=True, allows=lambda p: True))
    [item] = approvals.list_pending_approvals(req)
    return item


def _card(**over):
    card = {"approval_id": "appr-plan-t1-0", "approval_type": "ARCHITECTURAL_PLAN", "product_id": "p",
            "trace_id": "t1", "status": "PENDING", "cost_delta_monthly": "+$1.00/mo",
            "risk_assessment": "Pre-build gate: SECRET_CREATED_EMPTY", "gate_reasons": ["SECRET_CREATED_EMPTY"],
            "requested_at": "2026-11-10T00:00:00+00:00"}
    card.update(over)
    return card


ADV = {"code": "SECRET.OPERATOR_VALUE_REQUIRED", "secret": "stripe_key", "services": ["svc"],
       "message": "The platform creates stripe_key without a value."}


def test_cc_codes_equal_the_gateway_codes():
    import workflow_gates as wg

    assert _cc_approvals().SECRET_ADVISORY_CODES == wg.SECRET_ADVISORY_CODES


def test_cc_card_shows_the_secret_block(monkeypatch):
    item = _cc_item(monkeypatch, _card(secret_advisories=[ADV], secret_advisories_omitted=0))
    assert item.secret_advisories == [{"code": ADV["code"], "secret": "stripe_key", "message": ADV["message"]}]
    assert item.secret_advisories_unreadable is False
    html = open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8").read()
    start = html.index('data-testid="approval-secret-advisories"')
    block = html[html.rindex("<template", 0, start):html.index("</template>\n\n", start)]
    assert 'x-text="adv.message"' in block and "x-html" not in block and "{{" not in block


@pytest.mark.parametrize("over", [{}, {"secret_advisories": []}], ids=["legacy card", "no advisory"])
def test_cc_card_unchanged_without_advisories(monkeypatch, over):
    item = _cc_item(monkeypatch, _card(**over))
    assert item.secret_advisories == [] and item.secret_advisories_unreadable is False


@pytest.mark.parametrize("bad", ["x", [dict(ADV, code="OTHER")], [dict(ADV, message=7)], [dict(ADV, secret="")]],
                         ids=["not a list", "unknown code", "message not text", "no secret"])
def test_cc_card_marks_a_malformed_copy_unreadable(monkeypatch, bad):
    item = _cc_item(monkeypatch, _card(secret_advisories=bad))
    assert item.secret_advisories == [] and item.secret_advisories_unreadable is True
