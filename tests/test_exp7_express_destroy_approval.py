"""EXP-7 (register row, owner 10-19): an Express deploy refuses a plan that deletes or replaces a resource already in
state -> DESTROY_REQUIRES_APPROVAL listing the addresses; the workload is FAILED with that reason; the operator approves
by re-submitting with exactly those addresses in `approved_removals`. A replacement of a TAINTED resource
(`action_reason == replace_because_tainted`) stays allowed. Agent-mode deploys (no `refuse_destroy`) are unchanged.

The plan fixture `fixtures/exp7_tofu190_plan.json` is real OpenTofu 1.9.0 `show -json` output (terraform_data, local
state, no apply). Hermetic: fake `_run_subprocess`, dict-backed Firestore, compliance server stubbed to PASS.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import)

import copy
import json
import os
import sys
from unittest.mock import MagicMock

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from test_lane14_compliance_gate import (HIPAA_DECISION, FakeDB, FakeRunner, _replace, _svc,  # noqa: E402
                                         _wire_gate)

FIXTURE = json.load(open(os.path.join(os.path.dirname(__file__), "fixtures", "exp7_tofu190_plan.json")))
PASS = {"gate_contract_version": 1, "decision": "PASS", "violations": []}


@pytest.fixture()
def tf(monkeypatch):
    from fd4g_support import load_tf_service

    return load_tf_service(monkeypatch)


def _changes(*names):
    """resource_changes of the tofu 1.9.0 fixture, by resource name (deposed entries included with their name)."""
    return [c for c in FIXTURE["resource_changes"] if c["name"] in names]


def _plan(*names):
    return {"format_version": "1.2", "configuration": {"root_module": {}},   # FD-4AW-b: real show -json has it
            "resource_changes": copy.deepcopy(_changes(*names))}


def _gated(monkeypatch, tf, tmp_path, plan_json, policy, store=None):
    calls = []
    _wire_gate(monkeypatch, tf, None, calls, status=200, payload=PASS)
    store = copy.deepcopy(HIPAA_DECISION) if store is None else store
    svc, ws = _svc(tf, tmp_path, store)
    runner = FakeRunner(plan_json)
    monkeypatch.setattr(svc, "_run_subprocess", runner)
    return svc, ws, runner, calls, store


# --------------------------------------------------------------------------------------------- tofu 1.9.0 contract
def test_tofu_190_emits_the_typed_action_reasons_this_relies_on():
    by = {(c["address"], c.get("deposed")): (c["change"]["actions"], c.get("action_reason"))
          for c in FIXTURE["resource_changes"]}
    assert FIXTURE["terraform_version"] == "1.9.0"
    assert by[("terraform_data.tainted", None)] == (["delete", "create"], "replace_because_tainted")
    assert by[("terraform_data.rep", None)] == (["delete", "create"], "replace_because_cannot_update")
    assert by[("terraform_data.cbd", None)] == (["create", "delete"], "replace_because_cannot_update")
    assert by[("terraform_data.gone", None)] == (["delete"], "delete_because_no_resource_config")
    assert by[("terraform_data.dep", "00000001")] == (["delete"], None)
    assert by[("terraform_data.upd", None)] == (["update"], None)
    assert by[("terraform_data.new", None)] == (["create"], None)
    assert by[("terraform_data.keep", None)] == (["no-op"], None)


# --------------------------------------------------------------------------------------------- pure decision
def test_removals_requiring_approval_on_the_real_plan(tf):
    got = tf.removals_requiring_approval(FIXTURE)
    assert [(r["address"], r.get("deposed")) for r in got] == [
        ("terraform_data.cbd", None), ("terraform_data.dep", "00000001"), ("terraform_data.gone", None),
        ("terraform_data.rep", None)]   # tainted replace, update, create, no-op are not removals


def test_negative_create_in_place_and_tainted_need_no_approval(tf):
    for names in (("new",), ("upd",), ("keep",), ("tainted",), ("new", "upd", "keep", "tainted")):
        assert tf.destroy_approval_refusal("p", "t", _plan(*names), tf.DestroyPolicy()) is None, names
    assert tf.destroy_approval_refusal("p", "t", {}, tf.DestroyPolicy()) is None


def test_tainted_exemption_is_only_for_a_replacement(tf):
    # a tainted object removed from the configuration is a plain delete -> still needs approval
    gone_tainted = {"resource_changes": [{"address": "terraform_data.x", "type": "terraform_data", "name": "x",
                                          "change": {"actions": ["delete"]}, "action_reason": "replace_because_tainted"}]}
    res = tf.destroy_approval_refusal("p", "t", gone_tainted, tf.DestroyPolicy())
    assert res is not None and res["removal_addresses"] == ["terraform_data.x"]


@pytest.mark.parametrize("names,addresses", [
    (("gone",), ["terraform_data.gone"]),
    (("rep",), ["terraform_data.rep"]),
    (("cbd",), ["terraform_data.cbd"]),
    (("dep",), ["terraform_data.dep"]),
])
def test_delete_and_replace_are_refused_with_the_addresses(tf, names, addresses):
    res = tf.destroy_approval_refusal("p", "t1", _plan(*names), tf.DestroyPolicy())
    assert res["status"] == "FAILED" and res["error_class"] == "DESTROY_REQUIRES_APPROVAL"
    assert res["removal_addresses"] == addresses and res["error"].startswith("DESTROY_REQUIRES_APPROVAL: ")
    assert res["product_id"] == "p" and res["trace_id"] == "t1"


def test_approval_must_match_exactly(tf):
    p = _plan("gone", "rep", "tainted", "new")
    exact = frozenset({"terraform_data.gone", "terraform_data.rep"})
    assert tf.destroy_approval_refusal("p", "t", p, tf.DestroyPolicy(exact)) is None
    for approved in ({"terraform_data.gone"}, exact | {"terraform_data.other"}, set(),
                     {"terraform_data.gone", "terraform_data.rep", "terraform_data.tainted"}):
        res = tf.destroy_approval_refusal("p", "t", p, tf.DestroyPolicy(frozenset(approved)))
        assert res is not None and res["removal_addresses"] == sorted(exact), approved
        assert res["approved_removals"] == sorted(approved)


def test_a_removal_without_an_address_can_never_be_approved(tf):
    p = {"resource_changes": [{"type": "t", "change": {"actions": ["delete"]}}]}
    assert tf.destroy_approval_refusal("p", "t", p, tf.DestroyPolicy(frozenset())) is not None


# --------------------------------------------------------------------------------------------- gated apply
def test_gated_apply_refuses_before_any_apply_and_writes_evidence(monkeypatch, tf, tmp_path):
    svc, ws, runner, calls, store = _gated(monkeypatch, tf, tmp_path, _plan("gone", "new"), tf.DestroyPolicy())
    with pytest.raises(tf.DestroyBlocked) as ei:
        svc._compliance_gated_apply("claims", "t-exp7", ws, "OPENTOFU", destroy_policy=tf.DestroyPolicy())
    assert ei.value.result["error_class"] == "DESTROY_REQUIRES_APPROVAL"
    assert ei.value.result["removal_addresses"] == ["terraform_data.gone"]
    assert runner.calls == ["plan", "show"] and calls == []   # nothing applied; compliance server not asked
    assert not os.path.exists(os.path.join(ws, tf.compliance_gate.GATE_PLAN_FILE))
    ev_doc = store["workloads/claims/compliance_audits/t-exp7"]["enforcement"]
    assert ev_doc["gate"] == "destroy_approval" and ev_doc["error_class"] == "DESTROY_REQUIRES_APPROVAL"


@pytest.mark.parametrize("names,approved", [
    (("new", "upd", "keep"), frozenset()),                       # create / in-place unaffected
    (("tainted",), frozenset()),                                  # tainted replacement allowed
    (("gone", "rep"), frozenset({"terraform_data.gone", "terraform_data.rep"})),   # exact approval
])
def test_gated_apply_applies_when_allowed(monkeypatch, tf, tmp_path, names, approved):
    svc, ws, runner, calls, store = _gated(monkeypatch, tf, tmp_path, _plan(*names), None)
    res = svc._compliance_gated_apply("claims", "t", ws, "OPENTOFU", destroy_policy=tf.DestroyPolicy(approved))
    assert res["success"] is True and runner.calls == ["plan", "show", "apply"] and len(calls) == 1
    audit = store.get("workloads/claims/compliance_audits/t") or {}
    ev_doc = audit.get("destroy_approval") or {}
    if approved:
        # EXP-7 RT B2: an approved deletion is audited before the apply, next to (not inside) the gate's evidence
        assert ev_doc.get("gate") == "destroy_approval" and ev_doc.get("verified") is True
        assert ev_doc["approved_removals"] == sorted(approved) and len(ev_doc["plan_digest"]) == 64
        assert sorted(r["address"] for r in ev_doc["destroy_approved"]) == sorted(approved)
        assert "approved_removals" not in (audit.get("enforcement") or {})
    else:
        assert ev_doc == {}   # nothing removed -> no approval evidence


def test_agent_mode_no_policy_is_unchanged(monkeypatch, tf, tmp_path):
    """Do No Harm: without a destroy policy (every Agent deploy) a plain delete/replace applies exactly as before."""
    svc, ws, runner, calls, _ = _gated(monkeypatch, tf, tmp_path, _plan("gone", "rep", "cbd", "dep"), None)
    assert svc._compliance_gated_apply("claims", "t", ws, "OPENTOFU")["success"] is True
    assert runner.calls == ["plan", "show", "apply"] and len(calls) == 1


def test_destroy_blocked_still_wins_over_an_approval(monkeypatch, tf, tmp_path):
    """A deletion-protected store stays DESTROY_BLOCKED (FD-4AZ / FD-4CG); approved_removals never overrides it."""
    change = _replace("google_artifact_registry_repository", {"repository_id": "r"})
    plan_json = {"format_version": "1.2", "configuration": {"root_module": {}}, "resource_changes": [change]}
    svc, ws, runner, _, _ = _gated(monkeypatch, tf, tmp_path, plan_json, None)
    policy = tf.DestroyPolicy(frozenset({change["address"]}))
    with pytest.raises(tf.DestroyBlocked) as ei:
        svc._compliance_gated_apply("claims", "t", ws, "OPENTOFU", destroy_policy=policy)
    assert ei.value.result["error_class"] == "DESTROY_BLOCKED" and "apply" not in runner.calls


def test_deploy_workload_threads_the_policy_to_every_gated_apply(tf):
    import ast

    tree = ast.parse(open(tf.__file__).read())
    impl = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_deploy_workload_impl"][0]
    gated = [c for c in ast.walk(impl) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
             and c.func.attr == "_compliance_gated_apply"]
    # FD-55 W6c: the IdP-block bypass retry (A49) was the 4th call site; CLOUDSQL-CREATE-OWN-OPERATION adds the retry
    # after adopting this deploy's own Cloud SQL instance (it forwards the same policy)
    assert len(gated) == 4
    for c in gated:
        kw = {k.arg: k.value for k in c.keywords}
        assert isinstance(kw.get("destroy_policy"), ast.Name) and kw["destroy_policy"].id == "destroy_policy"


def test_refusal_reaches_the_deploy_result_typed(monkeypatch, tf, tmp_path):
    svc = tf.TerraformService(project_id="host", state_bucket="b", workspace_base_dir=str(tmp_path / "ws"),
                              firestore_client=FakeDB({}))
    seen = {}

    def impl(**kw):
        seen.update(kw)
        raise tf.DestroyBlocked(tf.destroy_approval_refusal("claims", "t1", _plan("gone"), kw["destroy_policy"]))

    monkeypatch.setattr(svc, "_deploy_workload_impl", impl)
    monkeypatch.setattr(svc, "_sync_feature_requests", lambda **kw: None)
    res = svc.deploy_workload(product_id="claims", trace_id="t1", destroy_policy=tf.DestroyPolicy())
    assert res["error_class"] == "DESTROY_REQUIRES_APPROVAL" and res["status"] == "FAILED"
    assert seen["destroy_policy"] == tf.DestroyPolicy()


# --------------------------------------------------------------------------------------------- /deploy endpoint
@pytest.fixture()
def tf_main(monkeypatch, tmp_path):
    from test_fd4g_terraform_workspace import _load_tf_module

    return _load_tf_module(monkeypatch, str(tmp_path), "main.py", "exp7_tf_main")


def test_deploy_endpoint_agent_body_passes_no_policy(tf_main):
    from fastapi.testclient import TestClient

    tf_main.service.deploy_workload = MagicMock(return_value={"status": "SUCCESS", "service_url": "https://x"})
    r = TestClient(tf_main.app).post("/deploy", json={"product_id": "app", "trace_id": "t1"})
    assert r.status_code == 200
    assert tf_main.service.deploy_workload.call_args.kwargs["destroy_policy"] is None


def test_deploy_endpoint_express_refusal_is_a_typed_409(tf_main):
    from fastapi.testclient import TestClient

    refusal = {"status": "FAILED", "error_class": "DESTROY_REQUIRES_APPROVAL", "error": "DESTROY_REQUIRES_APPROVAL: x",
               "removal_addresses": ["module.worker_a.google_pubsub_topic.t"], "destroy_requires_approval": [],
               "approved_removals": []}
    tf_main.service.deploy_workload = MagicMock(return_value=refusal)
    r = TestClient(tf_main.app).post("/deploy", json={"product_id": "app", "trace_id": "t1", "refuse_destroy": True,
                                                      "approved_removals": ["a.b"]})
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["error_class"] == "DESTROY_REQUIRES_APPROVAL"
    assert detail["removal_addresses"] == ["module.worker_a.google_pubsub_topic.t"]
    policy = tf_main.service.deploy_workload.call_args.kwargs["destroy_policy"]
    assert policy.approved_removals == frozenset({"a.b"})


def test_deploy_endpoint_rejects_approvals_without_refuse_destroy(tf_main):
    from fastapi.testclient import TestClient

    tf_main.service.deploy_workload = MagicMock()
    r = TestClient(tf_main.app).post("/deploy", json={"product_id": "app", "approved_removals": ["a.b"]})
    assert r.status_code == 422
    tf_main.service.deploy_workload.assert_not_called()


# --------------------------------------------------------------------------------------------- Control Center
def _route(monkeypatch, tf_status=200, tf_json=None):
    from fd4f_support import FakeDB as CCFakeDB

    cc_dir = os.path.join(REPO, "apps", "control-center")
    if cc_dir not in sys.path:
        monkeypatch.syspath_prepend(cc_dir)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from routes import workloads as wl

    monkeypatch.setattr(cc_db, "_db_client", False)
    store = CCFakeDB()
    monkeypatch.setattr(wl, "db", store)
    vending = MagicMock()
    vending.return_value.status_code = 200
    vending.return_value.json.return_value = {"project_id": "castor-exp-1", "github_repo": "org/exp-repo"}
    monkeypatch.setattr(wl, "make_vending_request", vending)
    tfm = MagicMock()
    tfm.return_value.status_code = tf_status
    tfm.return_value.json.return_value = tf_json if tf_json is not None else {"status": "SUCCESS",
                                                                             "service_url": "https://x.run.app"}
    monkeypatch.setattr(wl, "make_terraform_request", tfm)
    factory = MagicMock()
    monkeypatch.setattr(wl, "VCSProviderFactory", factory)
    return wl, store, tfm


def _run(wl, **kw):
    wl.execute_express_provisioning(
        product_id="exp-app", target_project_id="castor-exp-1", clean_vcs_provider="GITHUB",
        full_github_repo="org/exp-repo", target_branch="main", target_folder=None, budget=50.0,
        clean_engine="OPENTOFU", is_sandbox=False, admin_email="admin@example.com",
        module_instances=[{"module_id": "compute-cloudrun", "instance_name": "api", "parameters": {}}],
        include_vpc=False, trace_id="tr-exp7", region="us-central1", **kw)   # FD-7M-a: as create passes it


def test_cc_express_deploy_sends_the_typed_field_and_approvals(monkeypatch):
    wl, store, tfm = _route(monkeypatch)
    _run(wl, approved_removals=["module.compute_api.google_cloud_run_v2_service.svc"])
    body = tfm.call_args.kwargs["json_body"]
    assert tfm.call_args.kwargs["path"] == "/deploy"
    assert body["refuse_destroy"] is True
    assert body["approved_removals"] == ["module.compute_api.google_cloud_run_v2_service.svc"]
    assert store.docs["workloads/exp-app"]["status"] == "ACTIVE"   # a deploy that succeeds is unchanged


def test_cc_express_refusal_marks_the_workload_failed_with_the_addresses(monkeypatch):
    addrs = ["module.worker_orders.google_pubsub_topic.t", "module.worker_orders.google_cloud_run_v2_job.j"]
    detail = {"error_class": "DESTROY_REQUIRES_APPROVAL", "error": "DESTROY_REQUIRES_APPROVAL: ...",
              "removal_addresses": addrs, "destroy_requires_approval": [], "approved_removals": []}
    wl, store, tfm = _route(monkeypatch, tf_status=409, tf_json={"detail": detail})
    _run(wl)
    wdoc = store.docs["workloads/exp-app"]
    assert wdoc["status"] == "FAILED" and wdoc["failure_reason"].startswith("DESTROY_REQUIRES_APPROVAL: ")
    assert wdoc["destroy_requires_approval"]["removal_addresses"] == sorted(addrs)
    pe = store.docs["pipeline_executions/tr-exp7"]
    assert pe["status"] == "FAILED" and pe["error_class"] == "DESTROY_REQUIRES_APPROVAL"
    assert pe["stages"]["terraform"]["status"] == "FAILED"


def test_cc_negative_an_untyped_409_is_not_read_as_a_refusal(monkeypatch):
    """A 409 whose detail is not the typed EXP-7 object (e.g. a string) is not read as a refusal. EXP-8: it is
    still a failed deploy (EXPRESS_DEPLOY_FAILED, HTTP 409), no longer ACTIVE."""
    wl, store, tfm = _route(monkeypatch, tf_status=409, tf_json={"detail": "DESTROY_REQUIRES_APPROVAL somewhere"})
    _run(wl)
    assert store.docs["workloads/exp-app"]["status"] == "FAILED"
    assert store.docs["pipeline_executions/tr-exp7"]["error_class"] == "EXPRESS_DEPLOY_FAILED"
    assert "destroy_requires_approval" not in store.docs["workloads/exp-app"]


def test_cc_approved_removals_is_express_only(monkeypatch):
    from fastapi import HTTPException

    wl, store, tfm = _route(monkeypatch)
    from schemas import CreateWorkloadRequest

    assert CreateWorkloadRequest(product_id="a").approved_removals is None
    request = MagicMock()
    request.state.user_email = "admin@example.com"
    request.state.user_role = "ADMIN"
    with pytest.raises(HTTPException) as ei:
        wl.create_workload(CreateWorkloadRequest(product_id="shop-app", spec_content="a shop",
                                                 approved_removals=["a.b"]), request)
    assert ei.value.status_code == 422 and ei.value.detail["error_class"] == "APPROVED_REMOVALS_EXPRESS_ONLY"
    assert store.docs == {} and not tfm.called


def test_b2_cc_records_who_approved_which_removals(monkeypatch):
    wl, store, tfm = _route(monkeypatch)
    _run(wl, approved_removals=["b.y", "a.x"])
    rec = store.docs["workloads/exp-app"]["destroy_approval"]
    assert rec["approved_removals"] == ["a.x", "b.y"] and rec["approved_by"] == "admin@example.com"
    assert rec["trace_id"] == "tr-exp7" and rec["approved_at"]
    wl2, store2, _ = _route(monkeypatch)
    _run(wl2)                                       # no approval -> nothing recorded
    assert "destroy_approval" not in store2.docs["workloads/exp-app"]


def test_b4_a_later_success_clears_the_refusal_marker(monkeypatch):
    detail = {"error_class": "DESTROY_REQUIRES_APPROVAL", "error": "x", "removal_addresses": ["a.x"]}
    wl, store, tfm = _route(monkeypatch, tf_status=409, tf_json={"detail": detail})
    _run(wl)
    assert store.docs["workloads/exp-app"]["destroy_requires_approval"]["removal_addresses"] == ["a.x"]
    tfm.return_value.status_code = 200
    tfm.return_value.json.return_value = {"status": "SUCCESS", "service_url": "https://x.run.app"}
    _run(wl, approved_removals=["a.x"])
    doc = store.docs["workloads/exp-app"]
    assert doc["status"] == "ACTIVE" and not doc["destroy_requires_approval"]


def _deploy_infra(monkeypatch, wl_doc):
    wl, store, tfm = _route(monkeypatch)
    store.docs["workloads/exp-app"] = dict(wl_doc, project_id="castor-exp-1", github_repo="org/exp-repo",
                                           default_branch="main")
    monkeypatch.setattr(wl, "verify_workload_access", lambda *a, **k: True)
    monkeypatch.setattr(wl, "get_pubsub_publisher", lambda *a, **k: None, raising=False)
    # settings-toggles ST-1: deploy-infra reads maintenance mode strictly before any side effect; maintenance off here
    monkeypatch.setattr(wl, "get_platform_settings", lambda **k: wl_settings_off())
    request = MagicMock()
    request.state.user_email = "admin@example.com"
    return wl, store, request


def wl_settings_off():
    from types import SimpleNamespace
    return SimpleNamespace(governance=SimpleNamespace(maintenance_mode=False))


def test_b1_deploy_only_of_an_express_workload_with_an_open_refusal_is_refused(monkeypatch):
    from fastapi import HTTPException

    refusal = {"removal_addresses": ["module.worker_a.google_pubsub_topic.t"], "trace_id": "tr-1"}
    wl, store, request = _deploy_infra(monkeypatch, {"creation_mode": "EXPRESS", "destroy_requires_approval": refusal})
    with pytest.raises(HTTPException) as ei:
        wl.deploy_workload_infra("exp-app", request)
    assert ei.value.status_code == 409 and ei.value.detail["error_class"] == "DESTROY_REQUIRES_APPROVAL"
    assert ei.value.detail["removal_addresses"] == ["module.worker_a.google_pubsub_topic.t"]
    assert "deployment_lock" not in store.docs["workloads/exp-app"]   # refused before the lock / any dispatch


@pytest.mark.parametrize("wl_doc", [
    {"creation_mode": "EXPRESS", "destroy_requires_approval": None},    # cleared (B4)
    {"creation_mode": "EXPRESS"},
    {"creation_mode": "AGENT", "destroy_requires_approval": {"removal_addresses": ["a.x"]}},
])
def test_b1_negative_deploy_only_otherwise_unchanged(monkeypatch, wl_doc):
    wl, store, request = _deploy_infra(monkeypatch, wl_doc)
    try:
        wl.deploy_workload_infra("exp-app", request)
    except Exception as e:   # later dispatch steps are not under test; the guard must not be what stops it
        assert getattr(e, "detail", None) is None or "DESTROY_REQUIRES_APPROVAL" not in str(e.detail)
    # The guard let the request reach the lock (this request's trace took it); with no publisher the dispatch then
    # fails as DEPLOY_DISPATCH_UNAVAILABLE and releases its own lock (deploy-dispatch-fixes).
    lock = store.docs["workloads/exp-app"]["deployment_lock"]
    assert lock["trace_id"].startswith("fastpath-exp-app-")
    assert lock["release_reason"] == "DEPLOY_DISPATCH_UNAVAILABLE"
