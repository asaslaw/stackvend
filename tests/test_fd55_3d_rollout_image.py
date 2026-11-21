"""FD55-3D (register FOLLOWUPS-1025, owner 10-25): after a deploy with a fresh container build, the post-apply rollout
rolls exactly the Cloud Run services in the applied state, each to exactly the image the apply set for it
(`template[0].containers[0].image` from `tofu show -json`). No image is derived from folder or service names and
there is no `:latest` fallback. A state or a service image that cannot be read stops the deploy typed
(ROLLOUT_IMAGE_UNREADABLE, operator_required; OQ-10's recommended answer) and nothing is rolled.

* Multi-service `api` / `api-worker` (the FD55-IMG overlap) gets each its own applied image.
* A service that is not in the state is not rolled, even with an `apps/<name>` folder.
* Negatives: a single-service deploy whose applied image is today's choice makes the same rollout call as before;
  no build or a failed apply never reads the state and rolls nothing; the FD-4DE primary-URL rule is unchanged.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib
import json
import types
from unittest.mock import MagicMock

import pytest

from fd4g_support import load_tf_service  # noqa: E402

PID = "shop"
CHILD = "child-proj-123"
REGION = "us-central1"
AR = f"{REGION}-docker.pkg.dev/{CHILD}/{PID}"
TODAY_IMAGE = f"{AR}/app:latest"          # the deploy's image_tag (the image the build pushed)
SHOW = ["terraform", "show", "-json"]


@pytest.fixture
def tf(monkeypatch):
    mod = load_tf_service(monkeypatch)
    settings = importlib.import_module("shared.settings")
    monkeypatch.setattr(settings, "_SETTINGS_CACHE", settings.PlatformSettings())
    monkeypatch.setattr(settings, "_LAST_FETCH_TIME", float("inf"))
    return mod


@pytest.fixture(autouse=True)
def _no_gcp(monkeypatch):
    import google.auth
    import google.auth.transport.requests as gatr
    sess = MagicMock(name="session")
    sess.get.return_value = types.SimpleNamespace(status_code=404, json=lambda: {}, text="")
    sess.post.return_value = types.SimpleNamespace(status_code=404, json=lambda: {}, text="")
    monkeypatch.setattr(google.auth, "default", lambda *a, **k: (MagicMock(valid=True, token="t"), "p"))
    monkeypatch.setattr(gatr, "AuthorizedSession", lambda *a, **k: sess)


def _cr(name, image, *, location=REGION, project=CHILD, address=None, mode="managed",
        rtype="google_cloud_run_v2_service"):
    values = {"name": name, "location": location, "project": project,
              "template": [{"containers": [{"image": image}] if image is not None else []}]}
    return {"address": address or f"google_cloud_run_v2_service.{name.replace('-', '_')}", "mode": mode,
            "type": rtype, "name": name, "values": values}


def _state(resources, children=None):
    root = {"resources": resources}
    if children is not None:
        root["child_modules"] = children
    return {"format_version": "1.0", "values": {"root_module": root}}


def _svc(tf, tmp_path, *, state, apps=(), build=True, apply_ok=True, show_ok=True, db=None,
         outputs=json.dumps({"service_url": {"value": "https://shop-x.a.run.app"}})):
    svc = tf.TerraformService(project_id="castor-parent", state_bucket="", workspace_base_dir=str(tmp_path),
                              firestore_client=MagicMock(name="firestore"))
    svc.db = db
    svc.state_bucket = ""
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "main.tf").write_text('resource "google_cloud_run_v2_service" "app" {\n  name = "shop"\n}\n')
    if build:
        (ws / "main.py").write_text("print('hi')\n")
    for app in apps:
        (ws / "apps" / app).mkdir(parents=True)
        (ws / "apps" / app / "main.py").write_text("print('a')\n")
    calls = {"rollout": [], "cmds": []}

    def _rollout(**k):
        calls["rollout"].append(k)
        return True, f"{k['service_name']}-00002", f"https://{k['service_name']}-x.a.run.app"

    def _subp(cmd, **kwargs):
        calls["cmds"].append(list(cmd))
        if "output" in cmd:
            return {"success": True, "returncode": 0, "stdout": outputs, "stderr": ""}
        if cmd == SHOW:
            if not show_ok:
                return {"success": False, "returncode": 1, "stdout": "", "stderr": "Error: state unreadable"}
            body = state if isinstance(state, str) else json.dumps(state)
            return {"success": True, "returncode": 0, "stdout": body, "stderr": ""}
        if "apply" in cmd and not apply_ok:
            return {"success": False, "returncode": 1, "stdout": "", "stderr": "Error: boom"}
        return {"success": True, "returncode": 0, "stdout": "Apply complete!", "stderr": ""}

    svc._fetch_repo_files = lambda *a, **k: {}
    svc.prepare_workspace = lambda *a, **k: str(ws)
    svc._build_and_push_container = lambda *a, **k: True
    svc._ensure_provider_mirror = lambda *a, **k: "/nonexistent/terraform.rc"
    svc._compliance_gate_check = lambda *a, **k: {"passed": True, "evidence": {}}
    svc._validate_no_engine_downgrade = lambda *a, **k: None
    # FD-102: the outputs URL is recorded only when the Cloud Run listing confirms it (it does here)
    svc._list_cloud_run_services = lambda *a, **k: (
        [{"name": "projects/p/locations/us-central1/services/shop", "uri": "https://shop-x.a.run.app"}], None)
    svc._rollout_cloud_run_revision = _rollout
    svc._run_subprocess = _subp
    return svc, calls


def _deploy(svc):
    return svc.deploy_workload(product_id=PID, trace_id="trace-3d", target_project_id=CHILD,
                               hcl_files={"main.tf": 'resource "google_cloud_run_v2_service" "app" {}'})


def _rolled(calls):
    return [(k["service_name"], k["region"], k["image_tag"]) for k in calls["rollout"]]


# ------------------------------------------------------------------------------------------------ pure reader
def test_reader_takes_every_cloud_run_service_of_root_and_child_modules(tf):
    state = _state([_cr("api", f"{AR}/app:latest"),
                    {"address": "google_cloud_run_v2_job.jobs", "mode": "managed", "type": "google_cloud_run_v2_job",
                     "values": {"name": "jobs", "location": REGION}},
                    _cr("ext", "x/ext:1", mode="data", address="data.google_cloud_run_v2_service.ext")],
                   children=[{"address": "module.worker", "resources": [
                       _cr("api-worker", f"{AR}/api-worker:latest", address="module.worker.google_cloud_run_v2_service.this")],
                       "child_modules": [{"address": "module.worker.module.inner", "resources": [
                           _cr("inner", "x/inner:2", location="europe-west1")]}]}])
    services, unreadable = tf.applied_cloud_run_services(state)
    assert unreadable == []
    assert [(s["name"], s["location"], s["image"]) for s in services] == [
        ("api", REGION, f"{AR}/app:latest"), ("api-worker", REGION, f"{AR}/api-worker:latest"),
        ("inner", "europe-west1", "x/inner:2")]
    assert services[1]["address"] == "module.worker.google_cloud_run_v2_service.this"


def test_reader_reports_services_without_a_readable_image(tf):
    no_template = _cr("b", "x")
    no_template["values"].pop("template")
    services, unreadable = tf.applied_cloud_run_services(_state([
        _cr("a", None), no_template, _cr("c", ""), _cr("", "x/d:1", address="google_cloud_run_v2_service.d"),
        _cr("e", "x/e:1", location=None), _cr("ok", "x/ok:1")]))
    assert [s["name"] for s in services] == ["ok"]
    assert unreadable == ["google_cloud_run_v2_service.a", "google_cloud_run_v2_service.b",
                          "google_cloud_run_v2_service.c", "google_cloud_run_v2_service.d",
                          "google_cloud_run_v2_service.e"]


def test_reader_empty_state_has_no_services(tf):
    assert tf.applied_cloud_run_services({"format_version": "1.0"}) == ([], [])
    assert tf.applied_cloud_run_services(_state([])) == ([], [])


@pytest.mark.parametrize("state", [[], "x", {"values": []}, {"values": {"root_module": []}},
                                   {"values": {"root_module": {"resources": {}}}},
                                   {"values": {"root_module": {"resources": ["x"]}}},
                                   {"values": {"root_module": {"child_modules": {}}}}])
def test_reader_refuses_a_state_of_the_wrong_shape(tf, state):
    with pytest.raises(tf.AppliedStateUnreadable):
        tf.applied_cloud_run_services(state)


# ------------------------------------------------------------------------------------------------ deploy
def test_api_and_api_worker_each_get_their_own_applied_image(tf, tmp_path):
    """The FD55-IMG overlap: `api` carries the default app image, `api-worker` its own; the old name rules rolled
    `api` to `<ar>/api:latest` (an image the apply never set)."""
    state = _state([_cr("api-worker", f"{AR}/api-worker:latest"), _cr("api", f"{AR}/app:latest")])
    svc, calls = _svc(tf, tmp_path, state=state, apps=("api", "api-worker"))
    res = _deploy(svc)
    assert res["status"] == "SUCCESS", res
    assert _rolled(calls) == [("api", REGION, f"{AR}/app:latest"), ("api-worker", REGION, f"{AR}/api-worker:latest")]
    assert all(k["target_project_id"] == CHILD for k in calls["rollout"])


def test_a_service_not_in_the_state_is_not_rolled(tf, tmp_path):
    svc, calls = _svc(tf, tmp_path, state=_state([_cr(PID, TODAY_IMAGE)]), apps=("worker", "common"))
    res = _deploy(svc)
    assert res["status"] == "SUCCESS"
    assert _rolled(calls) == [(PID, REGION, TODAY_IMAGE)]


def test_the_service_is_rolled_in_its_applied_location(tf, tmp_path):
    svc, calls = _svc(tf, tmp_path, state=_state([_cr(PID, TODAY_IMAGE, location="europe-west1")]))
    assert _deploy(svc)["status"] == "SUCCESS"
    assert _rolled(calls) == [(PID, "europe-west1", TODAY_IMAGE)]


def test_no_cloud_run_service_in_the_state_rolls_nothing(tf, tmp_path):
    svc, calls = _svc(tf, tmp_path, state=_state([]))
    res = _deploy(svc)
    assert res["status"] == "SUCCESS" and calls["rollout"] == []
    assert "error_class" not in res


@pytest.mark.parametrize("kw", [
    {"show_ok": False},
    {"state": "not json"},
    {"state": json.dumps(["not", "an", "object"])},
    {"state": _state([_cr(PID, TODAY_IMAGE), _cr("api-worker", None)])},
    {"state": _state([_cr(PID, TODAY_IMAGE, project="someone-else")]), "cls": "ROLLOUT_SERVICE_OUTSIDE_TARGET"},
])
def test_an_unreadable_applied_image_is_a_typed_stop_and_nothing_is_rolled(tf, tmp_path, kw):
    """OQ-10: never a `:latest` or name-derived fallback; the deploy is FAILED for an operator. RT F4: a service in
    another project has its own class; the message says the apply succeeded and the services keep their revision."""
    kw = dict({"state": _state([_cr(PID, TODAY_IMAGE)])}, **kw)
    cls = kw.pop("cls", "ROLLOUT_IMAGE_UNREADABLE")
    db = MagicMock(name="firestore")
    db.collection.return_value.document.return_value.get.return_value = types.SimpleNamespace(
        exists=False, to_dict=lambda: {})
    svc, calls = _svc(tf, tmp_path, db=db, **kw)
    synced = []
    svc._sync_feature_requests = lambda **k: synced.append(k)
    res = _deploy(svc)
    assert res["status"] == "FAILED"
    assert res["error_class"] == cls == getattr(tf, cls) and res["operator_required"] is True
    assert res["error"].startswith(f"{cls}: ")
    assert "succeeded" in res["error"] and "keep their previous revision until the deploy is re-run" in res["error"]
    assert calls["rollout"] == []
    sets = [c.args[0] for c in db.collection.return_value.document.return_value.set.call_args_list]
    assert any(s.get("status") == "FAILED" and s.get("error_class") == cls for s in sets)
    assert any(s.get("status") == "FAILED" and "deployed_at" in s for s in sets)
    assert synced and synced[-1]["is_successful_deploy"] is False
    assert synced[-1]["error_msg"] == res["error"]


def test_negative_single_service_rollout_call_is_unchanged(tf, tmp_path):
    """Do No Harm: the single-service case whose applied image is today's choice (the built image) makes exactly the
    call the old rules made: the product's service, the workload region, the built image."""
    svc, calls = _svc(tf, tmp_path, state=_state([_cr(PID, TODAY_IMAGE)]))
    res = _deploy(svc)
    assert res["status"] == "SUCCESS" and "error_class" not in res
    assert calls["rollout"] == [{"target_project_id": CHILD, "service_name": PID, "region": REGION,
                                 "image_tag": TODAY_IMAGE}]


def test_negative_no_build_reads_no_state_and_rolls_nothing(tf, tmp_path):
    svc, calls = _svc(tf, tmp_path, state=_state([_cr(PID, TODAY_IMAGE)]), build=False)
    res = _deploy(svc)
    assert res["status"] == "SUCCESS" and calls["rollout"] == []
    assert SHOW not in calls["cmds"]


def test_negative_failed_apply_reads_no_state_and_rolls_nothing(tf, tmp_path):
    svc, calls = _svc(tf, tmp_path, state=_state([_cr(PID, TODAY_IMAGE)]), apply_ok=False)
    res = _deploy(svc)
    assert res["status"] == "FAILED" and res.get("error_class") != tf.ROLLOUT_IMAGE_UNREADABLE
    assert calls["rollout"] == [] and SHOW not in calls["cmds"]


# ------------------------------------------------------------------------------------------------ RT F1
def test_rt_f1_only_images_of_the_builds_repository_are_rolled(tf, tmp_path):
    """A service on a fixed image (a public image, or another repository whose name only starts like this one) keeps
    its revision and is listed in `rollout_skipped`; the build's own images are rolled."""
    state = _state([_cr(PID, TODAY_IMAGE), _cr("admin", "us-docker.pkg.dev/cloudrun/container/hello"),
                    _cr("other", f"{REGION}-docker.pkg.dev/{CHILD}/{PID}-other/app:latest"),
                    _cr("eu", f"europe-west1-docker.pkg.dev/{CHILD}/{PID}/app:latest")])
    svc, calls = _svc(tf, tmp_path, state=state)
    res = _deploy(svc)
    assert res["status"] == "SUCCESS" and "error_class" not in res
    assert _rolled(calls) == [(PID, REGION, TODAY_IMAGE)]
    assert res["rollout_skipped"] == ["google_cloud_run_v2_service.admin", "google_cloud_run_v2_service.eu",
                                      "google_cloud_run_v2_service.other"]


def test_rt_f1_the_prefix_is_the_builds_image_repository(tf):
    prefix = tf.rollout_repository_prefix(REGION, CHILD, PID)
    assert prefix == f"{AR}/" and TODAY_IMAGE.startswith(prefix)


def test_rt_f1_negative_no_skipped_service_adds_no_field(tf, tmp_path):
    svc, calls = _svc(tf, tmp_path, state=_state([_cr(PID, TODAY_IMAGE), _cr("worker", f"{AR}/worker:latest")]))
    res = _deploy(svc)
    assert res["status"] == "SUCCESS" and "rollout_skipped" not in res and len(calls["rollout"]) == 2


# ------------------------------------------------------------------------------------------------ RT F3
def test_rt_f3_the_state_read_has_its_own_budget_after_the_deploys_ran_out(tf, tmp_path):
    """The deploy's own budget is spent when the state is read: the read still runs (with its fixed budget) and the
    successful apply is reported SUCCESS."""
    svc, calls = _svc(tf, tmp_path, state=_state([_cr(PID, TODAY_IMAGE)]))
    seen = []
    inner = svc._run_subprocess

    def _subp(cmd, **kw):
        if cmd == SHOW:
            seen.append(svc._deploy_time_left())
        return inner(cmd, **kw)
    svc._run_subprocess = _subp
    res = svc.deploy_workload(product_id=PID, trace_id="trace-3d", target_project_id=CHILD, time_budget_s=0.0,
                              hcl_files={"main.tf": 'resource "google_cloud_run_v2_service" "app" {}'})
    assert res["status"] == "SUCCESS", res
    assert len(seen) == 1 and 0 < seen[0] <= tf.ROLLOUT_STATE_READ_BUDGET_S
    assert _rolled(calls) == [(PID, REGION, TODAY_IMAGE)]


def test_rt_f3_the_deploys_deadline_is_restored_and_an_earlier_timeout_still_refuses(tf, tmp_path):
    svc = tf.TerraformService(project_id="host-project", state_bucket="", workspace_base_dir=str(tmp_path),
                              firestore_client=MagicMock(name="firestore"))
    slot = svc._tofu_timeout_slot()
    slot.in_deploy, slot.message, slot.deadline, slot.budget_s = True, None, 5.0, 1470.0
    svc_run = svc._run_subprocess
    svc._run_subprocess = lambda cmd, **k: {"success": True, "stdout": "{}", "left": svc._deploy_time_left()}
    out = svc._run_with_own_budget(SHOW, str(tmp_path), "OPENTOFU", 30.0)
    assert 0 < out["left"] <= 30.0 and (slot.deadline, slot.budget_s) == (5.0, 1470.0)
    svc._run_subprocess = svc_run   # the real one: a deploy that already timed out starts nothing more
    slot.message = "TOFU_TIMEOUT: an earlier command timed out"
    refused = svc._run_with_own_budget(SHOW, str(tmp_path), "OPENTOFU", 30.0)
    assert refused["error_class"] == tf.TOFU_TIMEOUT and refused["success"] is False
    slot.in_deploy, slot.message, slot.deadline, slot.budget_s = False, None, None, None


def test_fd4de_primary_url_rule_is_unchanged(tf, tmp_path):
    """The primary service's rolled `uri` still replaces the outputs URL; another service's does not."""
    svc, calls = _svc(tf, tmp_path, state=_state([_cr(PID, TODAY_IMAGE), _cr("worker", f"{AR}/worker:latest")]),
                      outputs="{}")
    res = _deploy(svc)
    assert res["status"] == "SUCCESS"
    assert res["service_url"] == f"https://{PID}-x.a.run.app"
