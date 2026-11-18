"""EXP-6: an Express re-submit must not rename an event worker that OpenTofu already manages.

- shared.express_synthesizer.express_name_suffix_plan: the typed name plan ({module_id, module_key, name_suffix})
  synthesize_workload renders; refuse_worker_renames compares it with the plan stored on the workload record
  (express_deployed_name_plan, written before /deploy). A changed suffix at the same module address ->
  ExpressWorkerRenameRefusedError (EXPRESS_WORKER_RENAME_REFUSED). A record without a deployed plan: tracked
  (created by EXP-6 code) -> never refused; untracked (pre-EXP-6) or a malformed plan -> a request that could rename
  is refused (EXPRESS_WORKER_RENAME_UNVERIFIABLE).
- CC create_workload refuses at request time (409, typed error_class) before any write, vending or approval card.
  A first create and an unchanged re-submit behave as before.
- execute_express_provisioning records the plan before /deploy; if it cannot, nothing is deployed.
"""
import hermetic_guard  # noqa: F401  (first import)

import hashlib
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

import shared.express_synthesizer as xs  # noqa: E402

MOD = "compute-event-worker"
PLAN_FIELD = "express_deployed_name_plan"
TRACKED_FIELD = "express_name_plan_tracked"


def _inst(mid, name, params=None):
    return {"module_id": mid, "instance_name": name, "parameters": params or {}}


def _e(key, suffix, mid=MOD):
    return {"module_id": mid, "module_key": key, "name_suffix": suffix}


def _plan(instances, pid="shop-app"):
    return xs.express_name_suffix_plan(instances, pid)


# ------------------------------------------------------------------------------------------------ name plan
def test_field_names_are_the_ones_the_route_writes():
    assert xs.EXPRESS_DEPLOYED_NAME_PLAN_FIELD == PLAN_FIELD and xs.EXPRESS_NAME_PLAN_TRACKED_FIELD == TRACKED_FIELD


def test_replicas_are_identical():
    digests = {hashlib.sha256(open(os.path.join(REPO_ROOT, p, "express_synthesizer.py"), "rb").read()).hexdigest()
               for p in ("shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared")}
    assert len(digests) == 1


@pytest.mark.parametrize("instances", [
    [_inst(MOD, "orders")],
    [_inst("compute-cloudrun", "api"), _inst(MOD, "orders")],
    [_inst(MOD, "orders"), _inst(MOD, "billing"), _inst("compute-cloudrun", "api")],
    [_inst(MOD, ""), _inst(MOD, "")],
    [_inst("compute-cloudrun", "api")],
    [],
])
def test_plan_matches_what_synthesis_renders(instances):
    """The stored plan is the rendered one: same module keys, same name_suffix (absent = None)."""
    main_tf = xs.ExpressHCLSynthesizer().synthesize_workload(
        product_id="shop-app", project_id="p-1", module_instances=instances)["infra/workload/main.tf"]
    rendered = {}
    for block in hcl2.loads(main_tf).get("module", []):
        for key, body in block.items():
            if str(body.get("source", "")).rstrip("/").endswith(MOD):
                rendered[key.removeprefix("worker_")] = body.get("name_suffix")  # module "worker_<key>"
    plan = _plan(instances)
    assert {p["module_key"]: p["name_suffix"] for p in plan} == rendered
    assert all(p["module_id"] == MOD for p in plan)


def test_single_worker_plan_has_no_suffix_and_several_have_their_names():
    assert _plan([_inst(MOD, "orders")]) == [_e("orders", None)]
    assert _plan([_inst(MOD, "orders"), _inst(MOD, "Billing_Jobs")]) == [_e("orders", "orders"),
                                                                         _e("Billing_Jobs", "billing-jobs")]


def test_plan_raises_the_synthesis_refusals():
    with pytest.raises(xs.ExpressModuleNameCollisionError):
        _plan([_inst(MOD, "jobs"), _inst(MOD, "JOBS")])


# ------------------------------------------------------------------------------------------------ refuse_worker_renames
@pytest.mark.parametrize("new", [[_e("orders", None)], [_e("a", "a"), _e("b", "b")], []])
def test_first_create_is_never_refused(new):
    xs.refuse_worker_renames(None, new)


@pytest.mark.parametrize("deployed,new", [
    ([_e("orders", None)], [_e("orders", None)]),                               # unchanged single
    ([_e("a", "a"), _e("b", "b")], [_e("a", "a"), _e("b", "b")]),               # unchanged pair
    ([_e("a", "a"), _e("b", "b")], [_e("a", "a"), _e("b", "b"), _e("c", "c")]),  # add a worker
    ([_e("a", "a"), _e("b", "b")], [_e("a", "a"), _e("c", "c")]),               # remove one, add another
    ([], [_e("a", "a"), _e("b", "b")]),                                         # no worker before
    ([_e("orders", None)], [_e("api", None, mid="compute-cloudrun")]),          # other module ids not compared
])
def test_negative_unchanged_or_added_workers_are_not_refused(deployed, new):
    xs.refuse_worker_renames({PLAN_FIELD: deployed}, new)


@pytest.mark.parametrize("deployed,new,old_s,new_s", [
    ([_e("orders", None)], [_e("orders", "orders"), _e("billing", "billing")], None, "orders"),  # the RT F2 case
    ([_e("a", "a"), _e("b", "b")], [_e("a", None)], "a", None),                                 # 2 -> 1
    ([_e("a", "x")], [_e("a", "a"), _e("b", "b")], "x", "a"),                                   # suffix change
])
def test_a_suffix_change_at_the_same_address_is_refused(deployed, new, old_s, new_s):
    with pytest.raises(xs.ExpressWorkerRenameRefusedError) as err:
        xs.refuse_worker_renames({PLAN_FIELD: deployed, TRACKED_FIELD: True}, new)
    assert err.value.reason == "EXPRESS_WORKER_RENAME_REFUSED"
    assert isinstance(err.value, xs.ExpressSynthesisRefused)
    assert (err.value.old_suffix, err.value.new_suffix) == (old_s, new_s)


def test_tracked_record_without_a_deployed_plan_is_not_refused():
    xs.refuse_worker_renames({TRACKED_FIELD: True}, [_e("a", "a"), _e("b", "b")])


def test_untracked_record_refuses_only_a_request_that_gives_a_suffix():
    legacy = {"status": "ACTIVE", "creation_mode": "EXPRESS"}
    xs.refuse_worker_renames(legacy, [_e("orders", None)])  # as before EXP-6
    xs.refuse_worker_renames(legacy, [])
    with pytest.raises(xs.ExpressWorkerRenameUnverifiableError) as err:
        xs.refuse_worker_renames(legacy, [_e("a", "a"), _e("b", "b")])
    assert err.value.reason == "EXPRESS_WORKER_RENAME_UNVERIFIABLE"
    assert isinstance(err.value, xs.ExpressWorkerRenameRefusedError)
    # RT F4: the remedy is an unchanged re-submit first (it records the names), never "at most one worker"
    assert "unchanged once" in str(err.value) and "at most one" not in str(err.value)


# ------------------------------------------------------------------------------------------------ merge_name_plans
@pytest.mark.parametrize("record,new,expected", [
    (None, [_e("a", None)], [_e("a", None)]),
    ({TRACKED_FIELD: True}, [_e("a", "a"), _e("b", "b")], [_e("a", "a"), _e("b", "b")]),
    ({PLAN_FIELD: [_e("a", "a"), _e("b", "b")]}, [_e("a", "a"), _e("c", "c")],
     [_e("a", "a"), _e("b", "b"), _e("c", "c")]),                       # a removed worker stays until deployed
    ({PLAN_FIELD: [_e("orders", None)]}, [_e("orders", None)], [_e("orders", None)]),  # unchanged
    ({PLAN_FIELD: "garbage"}, [_e("a", None)], [_e("a", None)]),           # malformed contributes nothing
])
def test_merge_name_plans_is_the_union(record, new, expected):
    assert xs.merge_name_plans(record, new) == expected


def test_tracked_must_be_exactly_true():
    with pytest.raises(xs.ExpressWorkerRenameUnverifiableError):
        xs.refuse_worker_renames({TRACKED_FIELD: "true"}, [_e("a", "a"), _e("b", "b")])


@pytest.mark.parametrize("stored", [None, {}, {"a": None}, [None], [{"module_id": MOD, "module_key": "a"}, 3],
                                    [{"module_id": MOD, "module_key": "a", "name_suffix": 1}],
                                    [{"module_id": MOD, "module_key": 1, "name_suffix": None}],
                                    [_e("a", None), _e("a", "a")]])
def test_a_malformed_stored_plan_fails_closed(stored):
    with pytest.raises(xs.ExpressWorkerRenameUnverifiableError):
        xs.refuse_worker_renames({PLAN_FIELD: stored, TRACKED_FIELD: True}, [_e("a", None)])
    xs.refuse_worker_renames({PLAN_FIELD: stored}, [])  # nothing to rename


# ------------------------------------------------------------------------------------------------ CC create_workload
def _cc(monkeypatch, existing=None, fail_reads=False):
    from fd4f_support import FakeDB

    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from routes import workloads as wl

    monkeypatch.setattr(cc_db, "_db_client", False)
    store = FakeDB()
    if existing is not None:
        store.docs["workloads/shop-app"] = dict(existing)
    store.fail_reads = fail_reads
    monkeypatch.setattr(wl, "db", store)
    vending = MagicMock()
    vending.return_value.status_code = 200
    vending.return_value.json.return_value = {"project_id": "shop-app-1", "github_repo": "org/shop-app"}
    monkeypatch.setattr(wl, "make_vending_request", vending)
    tf = MagicMock()
    tf.return_value.status_code = 200
    tf.return_value.json.return_value = {"status": "SUCCESS", "service_url": ""}
    monkeypatch.setattr(wl, "make_terraform_request", tf)
    factory = MagicMock()
    monkeypatch.setattr(wl, "VCSProviderFactory", factory)
    return wl, store, vending, tf


def _create(wl, instances, provision=False, **kw):
    from fastapi import HTTPException
    from schemas import CreateWorkloadRequest

    request = MagicMock()
    request.state.user_email = "admin@example.com"
    request.state.user_role = "ADMIN"
    request.state.auth_method = "session"   # FD-4CS: a verified CC caller, listed by the private access default
    patches = [patch.dict(os.environ, {"GITHUB_OWNER": "example-org", "MANAGED_WORKLOADS_FOLDER_ID": "111111111111"}),
               patch("routes.workloads.get_pubsub_publisher", return_value=MagicMock()),
               patch("routes.workloads.get_platform_settings",  # FD-4AK: an unreadable settings doc now refuses (503)
                     return_value=__import__("routes.settings", fromlist=["x"]).PlatformSettings())]
    if not provision:
        patches.append(patch("routes.workloads.execute_express_provisioning", lambda **k: None))
    for p in patches:
        p.start()
    try:
        return wl.create_workload(CreateWorkloadRequest(product_id="shop-app", creation_mode="EXPRESS",
                                                        module_instances=instances, **kw), request)
    except HTTPException as he:
        return he
    finally:
        for p in reversed(patches):
            p.stop()


TWO = [_inst(MOD, "orders"), _inst(MOD, "billing")]
ONE = [_inst(MOD, "orders")]


def test_first_create_is_accepted_and_tracked(monkeypatch):
    wl, store, _, _ = _cc(monkeypatch)
    out = _create(wl, TWO)
    assert out.product_id == "shop-app"
    assert store.docs["workloads/shop-app"][TRACKED_FIELD] is True
    # RT F1: the names are stored in the create write itself, before any background step
    assert store.docs["workloads/shop-app"][PLAN_FIELD] == [_e("orders", "orders"), _e("billing", "billing")]
    assert [w[0] for w in store.writes].count("workloads/shop-app") == 1


def test_second_submit_while_the_first_is_provisioning_is_refused(monkeypatch):
    """RT F1 (S2): the first create is still provisioning (no /deploy yet); a rename is already refused."""
    wl, store, _, _ = _cc(monkeypatch)
    assert _create(wl, ONE).product_id == "shop-app"  # background task not run
    out = _create(wl, TWO)
    assert out.status_code == 409 and out.detail["error_class"] == "EXPRESS_WORKER_RENAME_REFUSED"


def test_failed_deploy_then_rename_is_refused(monkeypatch):
    """RT F2 (S1c/S1d): a re-submit without the worker whose /deploy fails keeps the worker's names stored."""
    wl, store, _, tf = _cc(monkeypatch, {"status": "ACTIVE", TRACKED_FIELD: True, PLAN_FIELD: [_e("orders", None)]})
    tf.return_value.status_code = 500
    assert _create(wl, [_inst("compute-cloudrun", "api")], provision=True).product_id == "shop-app"
    tf.assert_called_once()
    assert store.docs["workloads/shop-app"][PLAN_FIELD] == [_e("orders", None)]
    out = _create(wl, TWO)
    assert out.status_code == 409 and out.detail["error_class"] == "EXPRESS_WORKER_RENAME_REFUSED"


def test_failed_deploy_of_a_removal_and_addition_keeps_the_union(monkeypatch):
    wl, store, _, tf = _cc(monkeypatch, {"status": "ACTIVE", TRACKED_FIELD: True,
                                         PLAN_FIELD: [_e("a", "a"), _e("b", "b")]})
    tf.return_value.status_code = 500
    _create(wl, [_inst(MOD, "a"), _inst(MOD, "c")], provision=True)
    assert store.docs["workloads/shop-app"][PLAN_FIELD] == [_e("a", "a"), _e("b", "b"), _e("c", "c")]
    out = _create(wl, [_inst(MOD, "b")])  # b alone would lose its suffix
    assert out.status_code == 409


def test_successful_deploy_prunes_removed_workers(monkeypatch):
    wl, store, _, tf = _cc(monkeypatch, {"status": "ACTIVE", TRACKED_FIELD: True, PLAN_FIELD: [_e("orders", None)]})
    assert _create(wl, [_inst("compute-cloudrun", "api")], provision=True).product_id == "shop-app"
    assert store.docs["workloads/shop-app"][PLAN_FIELD] == []
    assert _create(wl, TWO).product_id == "shop-app"  # orders was destroyed by that deploy: no rename


def test_resubmit_that_renames_the_deployed_worker_is_refused_before_any_side_effect(monkeypatch):
    existing = {"status": "ACTIVE", "creation_mode": "EXPRESS", TRACKED_FIELD: True,
                PLAN_FIELD: [_e("orders", None)], "requested_compliance_profile": "STANDARD"}
    wl, store, vending, tf = _cc(monkeypatch, existing)
    out = _create(wl, TWO)
    assert out.status_code == 409 and out.detail["error_class"] == "EXPRESS_WORKER_RENAME_REFUSED"
    assert "'orders'" in out.detail["detail"]
    assert store.writes == [] and store.docs["workloads/shop-app"] == existing
    vending.assert_not_called()
    tf.assert_not_called()


def test_rename_refusal_comes_before_the_cp11_approval_card(monkeypatch):
    """The CP-11 downgrade guard writes an approval card; the rename refusal is checked first (no write at all)."""
    existing = {"status": "ACTIVE", PLAN_FIELD: [_e("orders", None)], "requested_compliance_profile": "HIPAA"}
    wl, store, _, _ = _cc(monkeypatch, existing)
    out = _create(wl, TWO, compliance_profile="STANDARD")
    assert out.status_code == 409 and out.detail["error_class"] == "EXPRESS_WORKER_RENAME_REFUSED"
    assert store.writes == []


def test_negative_unchanged_resubmit_is_accepted_and_not_retracked(monkeypatch):
    existing = {"status": "ACTIVE", PLAN_FIELD: [_e("orders", None)]}
    wl, store, _, _ = _cc(monkeypatch, existing)
    out = _create(wl, ONE)
    assert out.product_id == "shop-app"
    assert TRACKED_FIELD not in store.docs["workloads/shop-app"]
    assert store.docs["workloads/shop-app"][PLAN_FIELD] == [_e("orders", None)]


def test_legacy_record_single_worker_accepted_two_workers_refused(monkeypatch):
    wl, store, _, _ = _cc(monkeypatch, {"status": "ACTIVE", "creation_mode": "EXPRESS"})
    assert _create(wl, ONE).product_id == "shop-app"
    wl, store, _, _ = _cc(monkeypatch, {"status": "ACTIVE", "creation_mode": "EXPRESS"})
    out = _create(wl, TWO)
    assert out.status_code == 409 and out.detail["error_class"] == "EXPRESS_WORKER_RENAME_UNVERIFIABLE"
    assert store.writes == []


def test_tracked_record_never_deployed_accepts_two_workers(monkeypatch):
    """e.g. the first attempt was refused by synthesis (EXP-5) before /deploy."""
    wl, store, _, _ = _cc(monkeypatch, {"status": "FAILED", TRACKED_FIELD: True})
    assert _create(wl, TWO).product_id == "shop-app"


def test_a_failed_read_with_event_workers_is_a_503_and_without_them_is_unchanged(monkeypatch):
    wl, store, _, _ = _cc(monkeypatch, fail_reads=True)
    out = _create(wl, TWO)
    assert out.status_code == 503 and store.writes == []
    wl, store, _, _ = _cc(monkeypatch, fail_reads=True)
    out = _create(wl, [_inst("compute-cloudrun", "api")])
    # FD-4CS: without event workers the EXP-6 guard is still skipped, but the OSS-D23 access default now applies to
    # Express too and cannot tell whether the workload is new: 503, nothing written (as for Agent mode).
    assert out.status_code == 503 and store.writes == []


def test_a_request_whose_own_plan_is_refused_is_left_to_synthesis(monkeypatch):
    """Unchanged from EXP-5: a collision is recorded by the hcl_synthesis stage, not refused at request time."""
    wl, store, _, _ = _cc(monkeypatch, {"status": "ACTIVE"})
    assert _create(wl, [_inst(MOD, "jobs"), _inst(MOD, "JOBS")]).product_id == "shop-app"


def test_agent_mode_is_not_checked(monkeypatch):
    from schemas import CreateWorkloadRequest  # noqa: F401  (schemas importable once _cc ran)

    wl, store, _, _ = _cc(monkeypatch, {"status": "ACTIVE", "creation_mode": "EXPRESS"})
    request = MagicMock()
    request.state.user_email = "admin@example.com"
    request.state.user_role = "ADMIN"
    with patch.dict(os.environ, {"GITHUB_OWNER": "example-org", "MANAGED_WORKLOADS_FOLDER_ID": "111111111111"}), \
         patch("routes.workloads.get_pubsub_publisher", return_value=MagicMock()), \
         patch("routes.workloads.get_platform_settings",  # FD-4AK: an unreadable settings doc now refuses (503)
               return_value=__import__("routes.settings", fromlist=["x"]).PlatformSettings()):
        out = wl.create_workload(CreateWorkloadRequest(product_id="shop-app", creation_mode="AGENT",
                                                       spec_content="x", module_instances=TWO), request)
    assert out.product_id == "shop-app" and TRACKED_FIELD not in store.docs["workloads/shop-app"]


# ------------------------------------------------------------------------------------------------ deploy path
def test_create_deploy_then_resubmit_with_a_second_worker_is_refused(monkeypatch):
    """End to end: a first create records the deployed plan before /deploy; the 1 -> 2 re-submit is then refused."""
    wl, store, _, tf = _cc(monkeypatch)
    seen = {}
    tf.side_effect = lambda **k: (seen.setdefault("plan", store.docs["workloads/shop-app"].get(PLAN_FIELD)),
                                  tf.return_value)[1]
    assert _create(wl, ONE, provision=True).product_id == "shop-app"
    assert seen["plan"] == [_e("orders", None)]  # recorded before /deploy was called
    assert store.docs["workloads/shop-app"]["status"] == "ACTIVE"
    tf.side_effect = None
    tf.reset_mock()
    out = _create(wl, TWO)
    assert out.status_code == 409 and out.detail["error_class"] == "EXPRESS_WORKER_RENAME_REFUSED"
    tf.assert_not_called()
    # unchanged re-submit still goes through
    assert _create(wl, ONE, provision=True).product_id == "shop-app"
    tf.assert_called_once()


def test_a_failed_narrowing_write_keeps_the_wider_names_and_does_not_fail_the_deploy(monkeypatch):
    """RT F1/F2: the post-/deploy narrowing can only over-refuse when it fails, so it is logged, not a failure."""
    existing = {"status": "ACTIVE", TRACKED_FIELD: True, PLAN_FIELD: [_e("orders", None)]}
    wl, store, _, tf = _cc(monkeypatch, existing)
    real = xs.express_name_suffix_plan
    calls = []

    def flaky(instances, pid):
        calls.append(1)
        if len(calls) > 1:
            raise RuntimeError("store down")
        return real(instances, pid)

    monkeypatch.setattr(wl, "express_name_suffix_plan", flaky)
    assert _create(wl, ONE + [_inst("compute-cloudrun", "api")], provision=True).product_id == "shop-app"
    tf.assert_called_once()
    doc = store.docs["workloads/shop-app"]
    assert doc["status"] == "ACTIVE" and doc[PLAN_FIELD] == [_e("orders", None)]


def test_no_pre_deploy_failure_path_remains():
    with open(os.path.join(CC_DIR, "routes", "workloads.py"), encoding="utf-8") as f:
        assert "EXPRESS_NAME_PLAN_NOT_RECORDED" not in f.read()


def test_a_refused_synthesis_records_no_deployed_plan(monkeypatch):
    wl, store, _, tf = _cc(monkeypatch)
    _create(wl, [_inst(MOD, "jobs"), _inst(MOD, "JOBS")], provision=True)
    tf.assert_not_called()
    assert PLAN_FIELD not in store.docs["workloads/shop-app"]
    assert store.docs["workloads/shop-app"][TRACKED_FIELD] is True
