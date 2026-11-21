"""FD-4DE (fail-loudly policy rule 1.4): a deploy never fabricates a service URL, and a failed startup probe is never
reported as a successful deploy.

* The URL is the apply's own output, else the Cloud Run v2 API `uri` of the child project's service (REST through
  AuthorizedSession). When neither gives one, `service_url` is "" and `service_url_unknown_reason` is typed; the
  result's warnings carry SERVICE_URL_UNKNOWN. No address is built from product / project ids (behavior check on the
  whole result, the workload record and the sign-in domain list; no source grep).
* Do No Harm: a URL in the outputs is reported unchanged and the API is not asked.
* The startup-probe override is gone: such an apply stays FAILED (tests/test_callbacks_and_lifecycle.py also pins it).
* Consumers: the deploy summary line, the Control Center workload schemas and the architecture diagram render
  "unknown" (never a made-up address).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib
import json
import os
import sys
import types
from unittest.mock import MagicMock

import pytest

from fd4g_support import load_tf_service  # noqa: E402

CC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", "control-center"))

PID = "shop"
CHILD = "child-proj-123"
REAL_URI = "https://shop-k3j2h1-uc.a.run.app"
REAL_DET = "https://shop-424242.us-central1.run.app"


@pytest.fixture
def tf(monkeypatch):
    mod = load_tf_service(monkeypatch)
    # the compile-time PlatformSettings defaults from the settings cache (as tests/platform_settings_defaults.py), so
    # the deploy's settings reads never try a Firestore client
    settings = importlib.import_module("shared.settings")
    monkeypatch.setattr(settings, "_SETTINGS_CACHE", settings.PlatformSettings())
    monkeypatch.setattr(settings, "_LAST_FETCH_TIME", float("inf"))
    return mod


@pytest.fixture(autouse=True)
def _no_gcp(monkeypatch):
    """No credential and no session reach Google: every other REST step of the deploy (API enablement, Cloud Run
    pre-checks) gets a 404 from a fake session; the tests that need the listing fake it themselves."""
    import google.auth
    import google.auth.transport.requests as gatr
    sess = MagicMock(name="session")
    sess.get.return_value = types.SimpleNamespace(status_code=404, json=lambda: {}, text="")
    sess.post.return_value = types.SimpleNamespace(status_code=404, json=lambda: {}, text="")
    monkeypatch.setattr(google.auth, "default", lambda *a, **k: (MagicMock(valid=True, token="t"), "p"))
    monkeypatch.setattr(gatr, "AuthorizedSession", lambda *a, **k: sess)


def _new(tf, tmp_path):
    svc = tf.TerraformService(project_id="castor-parent", state_bucket="", workspace_base_dir=str(tmp_path),
                              firestore_client=MagicMock(name="firestore"))
    svc.db = None
    svc.state_bucket = ""
    return svc


def _state(*names):
    """FD55-3D: the `tofu show -json` of an applied state holding one Cloud Run service per name."""
    return json.dumps({"format_version": "1.0", "values": {"root_module": {"resources": [
        {"address": f"google_cloud_run_v2_service.{n}", "mode": "managed", "type": "google_cloud_run_v2_service",
         "name": n, "values": {"name": n, "location": "us-central1", "project": CHILD,
                               "template": [{"containers": [{"image": f"us-central1-docker.pkg.dev/{CHILD}/"
                                                                       f"{PID}/{n}:latest"}]}]}}
        for n in names]}}})


def _svc(tf, tmp_path, *, outputs="{}", listing=None, rollout=(False, "", ""), db=None, state=None):
    """A TerraformService whose deploy reaches a successful apply of a container workload in tmp_path. `listing` is
    what _list_cloud_run_services returns (None = must not be called). `state` is the applied state JSON the
    post-apply rollout reads (FD55-3D; default: the one `shop` service)."""
    state = _state(PID) if state is None else state
    svc = _new(tf, tmp_path)
    svc.db = db
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "main.tf").write_text('resource "google_cloud_run_v2_service" "app" {\n  name = "shop"\n}\n')
    (ws / "main.py").write_text("print('hi')\n")
    calls = {"list": [], "rollout": []}

    def _list(project, region):
        calls["list"].append((project, region))
        if listing is None:
            raise AssertionError("the Cloud Run API must not be asked")
        return listing

    def _rollout(**k):
        calls["rollout"].append(k["service_name"])
        return rollout

    def _subp(cmd, **kwargs):
        if "output" in cmd:
            return {"success": True, "returncode": 0, "stdout": outputs, "stderr": ""}
        if cmd == ["terraform", "show", "-json"]:
            return {"success": True, "returncode": 0, "stdout": state, "stderr": ""}
        return {"success": True, "returncode": 0, "stdout": "Apply complete!", "stderr": ""}

    svc._fetch_repo_files = lambda *a, **k: {}
    svc.prepare_workspace = lambda *a, **k: str(ws)
    svc._build_and_push_container = lambda *a, **k: True
    svc._ensure_provider_mirror = lambda *a, **k: "/nonexistent/terraform.rc"
    svc._compliance_gate_check = lambda *a, **k: {"passed": True, "evidence": {}}
    svc._validate_no_engine_downgrade = lambda *a, **k: None
    svc._list_cloud_run_services = _list
    svc._rollout_cloud_run_revision = _rollout
    svc._run_subprocess = _subp
    return svc, calls


def _deploy(svc):
    return svc.deploy_workload(product_id=PID, trace_id="trace-fd4de", target_project_id=CHILD,
                               hcl_files={"main.tf": 'resource "google_cloud_run_v2_service" "app" {}'})


# ------------------------------------------------------------------------------------------------ pure picker
def test_pick_one_service_is_the_workloads_service(tf):
    svc = [{"name": "projects/p/locations/r/services/anything", "uri": REAL_URI}]
    assert tf.pick_cloud_run_service_url(svc, ("shop",)) == (REAL_URI, None)


def test_pick_by_exact_name_among_several(tf):
    svcs = [{"name": "projects/p/locations/r/services/worker", "uri": "https://worker-x.a.run.app"},
            {"name": "projects/p/locations/r/services/shop", "uri": REAL_URI}]
    assert tf.pick_cloud_run_service_url(svcs, ("shop", "castor-shop")) == (REAL_URI, None)
    assert tf.pick_cloud_run_service_url(svcs, ("nope", "shop")) == (REAL_URI, None)


def test_pick_several_without_the_name_is_ambiguous(tf):
    svcs = [{"name": "projects/p/locations/r/services/a", "uri": "https://a-x.a.run.app"},
            {"name": "projects/p/locations/r/services/b", "uri": "https://b-x.a.run.app"}]
    # a prefix / substring of a name is not a match (exact names only)
    assert tf.pick_cloud_run_service_url(svcs, ("shop", "sho", "")) == ("", tf.SERVICE_URL_AMBIGUOUS)


def test_pick_no_service_with_a_uri_is_not_found(tf):
    assert tf.pick_cloud_run_service_url([], ("shop",)) == ("", tf.SERVICE_URL_NOT_FOUND)
    no_uri = [{"name": "projects/p/locations/r/services/shop", "uri": ""}, {"name": "x"}, "junk"]
    assert tf.pick_cloud_run_service_url(no_uri, ("shop",)) == ("", tf.SERVICE_URL_NOT_FOUND)


# ------------------------------------------------------------------------------------------------ API listing
class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


def _with_session(monkeypatch, answers):
    seen = []
    sess = MagicMock()

    def _get(url, params=None, timeout=None):
        seen.append((url, dict(params or {})))
        return answers.pop(0)
    sess.get.side_effect = _get
    monkeypatch.setattr("google.auth.default", lambda *a, **k: (MagicMock(), "p"))
    monkeypatch.setattr("google.auth.transport.requests.AuthorizedSession", lambda creds: sess)
    return seen


def test_listing_reads_every_page_of_the_child_region(tf, tmp_path, monkeypatch):
    seen = _with_session(monkeypatch, [_Resp(200, {"services": [{"name": "a"}], "nextPageToken": "t2"}),
                                       _Resp(200, {"services": [{"name": "b"}]})])
    svcs, reason = _new(tf, tmp_path)._list_cloud_run_services(CHILD, "europe-west1")
    assert reason is None and [s["name"] for s in svcs] == ["a", "b"]
    assert seen[0][0] == f"https://run.googleapis.com/v2/projects/{CHILD}/locations/europe-west1/services"
    assert "pageToken" not in seen[0][1] and seen[1][1]["pageToken"] == "t2"


@pytest.mark.parametrize("answer", [_Resp(403, {}), _Resp(500, {}), _Resp(200, ValueError("bad json")),
                                    _Resp(200, ["not", "a", "dict"])])
def test_listing_failures_are_api_unavailable(tf, tmp_path, monkeypatch, answer):
    _with_session(monkeypatch, [answer])
    out = _new(tf, tmp_path)._list_cloud_run_services(CHILD, "us-central1")
    assert out == (None, tf.SERVICE_URL_API_UNAVAILABLE)


def test_listing_without_a_credential_is_api_unavailable(tf, tmp_path, monkeypatch):
    def _no_adc(*a, **k):
        raise RuntimeError("no ADC")
    monkeypatch.setattr("google.auth.default", _no_adc)
    out = _new(tf, tmp_path)._list_cloud_run_services(CHILD, "us-central1")
    assert out == (None, tf.SERVICE_URL_API_UNAVAILABLE)


def test_listing_longer_than_the_bound_is_not_complete(tf, tmp_path, monkeypatch):
    pages = [_Resp(200, {"services": [{"name": f"s{i}", "uri": "https://x"}], "nextPageToken": f"t{i}"})
             for i in range(tf._CLOUD_RUN_LIST_MAX_PAGES)]
    _with_session(monkeypatch, pages)
    out = _new(tf, tmp_path)._list_cloud_run_services(CHILD, "us-central1")
    assert out == (None, tf.SERVICE_URL_API_UNAVAILABLE)


# ------------------------------------------------------------------------------------------------ deploy
def test_url_from_outputs_is_reported_unchanged_once_the_api_confirms_it(tf, tmp_path):
    """Do No Harm: today's real URL (the apply's output) is the same URL after FD-4DE. FD-102: it is recorded only
    once the Cloud Run listing (one, shared) confirms it (tests/test_fd102_service_url_confirmed.py)."""
    listing = ([{"name": f"projects/{CHILD}/locations/us-central1/services/shop", "uri": REAL_URI}], None)
    svc, calls = _svc(tf, tmp_path, outputs=json.dumps({"service_url": {"value": REAL_URI}}), listing=listing)
    res = _deploy(svc)
    assert res["status"] == "SUCCESS" and res["service_url"] == REAL_URI
    assert res["service_url_unknown_reason"] is None and calls["list"] == [(CHILD, "us-central1")]
    assert not [w for w in res.get("warnings") or [] if w.get("code") == tf.SERVICE_URL_UNKNOWN]


def test_url_from_the_cloud_run_api_when_the_outputs_name_none(tf, tmp_path):
    listing = ([{"name": f"projects/{CHILD}/locations/us-central1/services/shop", "uri": REAL_URI}], None)
    svc, calls = _svc(tf, tmp_path, listing=listing)
    res = _deploy(svc)
    assert res["status"] == "SUCCESS" and res["service_url"] == REAL_URI
    assert res["service_url_unknown_reason"] is None
    assert calls["list"] and calls["list"][0][0] == CHILD


@pytest.mark.parametrize("listing,reason", [
    ((None, "CLOUD_RUN_API_UNAVAILABLE"), "CLOUD_RUN_API_UNAVAILABLE"),
    (([], None), "CLOUD_RUN_SERVICE_NOT_FOUND"),
    (([{"name": "projects/p/locations/r/services/a", "uri": "https://a-1.example.test"},
       {"name": "projects/p/locations/r/services/b", "uri": "https://b-1.example.test"}], None),
     "CLOUD_RUN_SERVICE_AMBIGUOUS"),
])
def test_no_url_is_unknown_with_a_typed_reason_never_a_built_address(tf, tmp_path, listing, reason):
    db = MagicMock(name="firestore")
    db.collection.return_value.document.return_value.get.return_value = types.SimpleNamespace(
        exists=False, to_dict=lambda: {})
    svc, _ = _svc(tf, tmp_path, listing=listing, db=db)
    res = _deploy(svc)
    assert res["status"] == "SUCCESS"
    assert res["service_url"] == "" and res["service_url_unknown_reason"] == reason
    warn = [w for w in res.get("warnings") or [] if w.get("code") == tf.SERVICE_URL_UNKNOWN]
    assert len(warn) == 1 and warn[0]["reason"] == reason
    # behavior, not a source grep: nothing in the result names a run.app host
    assert "run.app" not in json.dumps(res, default=str)
    # the workload record says unknown (and why), never an address
    wl_sets = [c for c in db.collection.return_value.document.return_value.set.call_args_list
               if "deployed_at" in c.args[0]]
    assert wl_sets and wl_sets[-1].args[0]["service_url"] == ""
    assert wl_sets[-1].args[0]["service_url_unknown_reason"] == reason
    assert all("run.app" not in json.dumps(c.args[0], default=str)
               for c in db.collection.return_value.document.return_value.set.call_args_list)


def test_primary_rollout_uri_fills_an_unknown_url(tf, tmp_path):
    svc, calls = _svc(tf, tmp_path, listing=(None, "CLOUD_RUN_API_UNAVAILABLE"),
                      rollout=(True, "shop-00002", REAL_URI))
    res = _deploy(svc)
    assert "shop" in calls["rollout"]
    assert res["service_url"] == REAL_URI and res["service_url_unknown_reason"] is None
    assert not [w for w in res.get("warnings") or [] if w.get("code") == tf.SERVICE_URL_UNKNOWN]


def test_another_services_rollout_never_fills_an_unknown_url(tf, tmp_path):
    svc, calls = _svc(tf, tmp_path, listing=(None, "CLOUD_RUN_API_UNAVAILABLE"), state=_state(PID, "worker"))
    ws = tmp_path / "ws"
    (ws / "apps" / "worker").mkdir(parents=True)
    (ws / "apps" / "worker" / "main.py").write_text("print('w')\n")
    svc._rollout_cloud_run_revision = lambda **k: (
        calls["rollout"].append(k["service_name"]) or
        ((True, "w-1", "https://worker-1.example.test") if k["service_name"] == "worker" else (False, "", "")))
    res = _deploy(svc)
    assert "worker" in calls["rollout"]
    assert res["service_url"] == "" and res["service_url_unknown_reason"] == "CLOUD_RUN_API_UNAVAILABLE"


def test_no_container_build_expects_no_url_and_asks_nothing(tf, tmp_path):
    svc, calls = _svc(tf, tmp_path, listing=None)
    os.remove(tmp_path / "ws" / "main.py")      # foundation-only: nothing to build, no URL expected
    res = _deploy(svc)
    assert res["status"] == "SUCCESS" and res["service_url"] == "" and res["service_url_unknown_reason"] is None
    assert calls["list"] == []


def _public_app_svc(tf, tmp_path, monkeypatch, *, listing, outputs="{}"):
    """A PUBLIC_APP deploy (sign-in domain step runs) with a fake Identity Platform config API; returns
    (svc, calls, patched) where `patched` collects every authorizedDomains PATCH."""
    workload = types.SimpleNamespace(exists=True, to_dict=lambda: {
        "project_id": CHILD, "access": {   # FD-4DT: every deploy validates the record, so it is a complete one
            "mode": "PUBLIC_APP", "invoker_principals": [], "app_admin_emails": [],
            "public_api_routes": ["GET /api/config"],
            "sign_in": {"google": "BYO", "email_password": False, "additional_authorized_domains": []},
            "tenant_isolation_required": False, "source": "intake"}})
    db = MagicMock(name="firestore")
    db.collection.return_value.document.return_value.get.return_value = workload
    svc, calls = _svc(tf, tmp_path, listing=listing, db=db, outputs=outputs)
    svc._resolve_workload_web_key = lambda *a, **k: ("test-web-key", "987654")
    creds = MagicMock(valid=True, token="test-token")
    monkeypatch.setattr("google.auth.default", lambda *a, **k: (creds, "p"))
    patched = []

    class _Client:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url, headers=None):
            return types.SimpleNamespace(status_code=200, json=lambda: {"authorizedDomains": []}, text="")

        def patch(self, url, headers=None, json=None):
            patched.append(json["authorizedDomains"])
            return types.SimpleNamespace(status_code=200, text="")
    import httpx
    monkeypatch.setattr(httpx, "Client", _Client)
    return svc, calls, patched


def _codes(res, code):
    return [w for w in res.get("warnings") or [] if w.get("code") == code]


def test_signin_domains_are_the_hosts_the_api_lists_never_built_ones(tf, tmp_path, monkeypatch):
    """PUBLIC_APP: the authorized domains are localhost, the firebaseapp domain, the reported URL and every `uri` /
    `urls` host the Cloud Run API lists; no <pid>-<number> host is built from ids."""
    listing = ([{"name": f"projects/{CHILD}/locations/us-central1/services/shop", "uri": REAL_URI,
                 "urls": [REAL_DET, REAL_URI]}], None)
    svc, calls, patched = _public_app_svc(tf, tmp_path, monkeypatch, listing=listing)
    res = _deploy(svc)
    assert res["status"] == "SUCCESS" and res["service_url"] == REAL_URI
    assert len(calls["list"]) == 1                      # one listing shared by the URL lookup and the domain step
    assert patched, "the authorized domains were not written"
    domains = set(patched[-1])
    assert {"shop-k3j2h1-uc.a.run.app", "shop-424242.us-central1.run.app", "localhost",
            f"{CHILD}.firebaseapp.com"} <= domains
    assert not any("987654" in d for d in domains)      # never <pid>-<project number> built from ids
    assert _codes(res, tf.SIGNIN_DOMAINS_INCOMPLETE) == []   # RT N1 negative: a working listing warns nothing


def test_signin_domains_listing_failure_is_a_typed_warning(tf, tmp_path, monkeypatch):
    """RT N1: the listing fails in the sign-in step (URL from the outputs): the known hosts are still authorized and
    the result carries SIGNIN_DOMAINS_INCOMPLETE with the typed reason; the deploy stays SUCCESS. FD-102: the
    outputs URL cannot be confirmed without the listing, so it is reported unknown (CLOUD_RUN_API_UNAVAILABLE)."""
    svc, calls, patched = _public_app_svc(
        tf, tmp_path, monkeypatch, listing=(None, "CLOUD_RUN_API_UNAVAILABLE"),
        outputs=json.dumps({"service_url": {"value": REAL_URI}}))
    res = _deploy(svc)
    assert res["status"] == "SUCCESS" and res["service_url"] == ""
    assert res["service_url_unknown_reason"] == "CLOUD_RUN_API_UNAVAILABLE"
    warn = _codes(res, tf.SIGNIN_DOMAINS_INCOMPLETE)
    assert len(warn) == 1 and warn[0]["reason"] == "CLOUD_RUN_API_UNAVAILABLE"
    assert [w["reason"] for w in _codes(res, tf.SERVICE_URL_UNKNOWN)] == ["CLOUD_RUN_API_UNAVAILABLE"]
    assert len(calls["list"]) == 1                      # the one failed listing is not retried
    # the run.app host still reaches the list through the raw-output loop (FD-146, out of FD-102's scope)
    assert {"shop-k3j2h1-uc.a.run.app", "localhost", f"{CHILD}.firebaseapp.com"} <= set(patched[-1])
    assert not any("987654" in d for d in patched[-1])


def _write_topology(tmp_path, tf, kinds):
    services = [{"name": name, "kind": kind} for name, kind in kinds.items()]
    (tmp_path / "ws" / "topology.json").write_text(json.dumps(
        {"schema": tf.TOPOLOGY_RECORD_SCHEMA, "intent": {"primary_service": next(iter(kinds)), "services": services}}))


@pytest.mark.parametrize("kinds", [{"shop": "gke-autopilot"}, {"shop": "event-worker"},
                                   {"shop": "gke-autopilot", "jobs": "event-worker", "vm": "gce-worker"}])
def test_topology_without_a_cloudrun_service_expects_no_url(tf, tmp_path, kinds):
    """RT F1: GKE / event-worker (Cloud Run job) kinds build a container but create no Cloud Run service: no lookup,
    no unknown reason, no warning (as a deploy with nothing to build)."""
    svc, calls = _svc(tf, tmp_path, listing=None)
    _write_topology(tmp_path, tf, kinds)
    assert tf.workspace_service_kinds(str(tmp_path / "ws")) == kinds
    res = _deploy(svc)
    assert res["status"] == "SUCCESS" and res["service_url"] == "" and res["service_url_unknown_reason"] is None
    assert calls["list"] == [] and _codes(res, tf.SERVICE_URL_UNKNOWN) == []


def test_topology_with_a_cloudrun_service_still_asks_the_api(tf, tmp_path):
    """RT F1 negative: a typed `cloudrun` service (next to a non-service kind) still gets its URL from the API."""
    listing = ([{"name": f"projects/{CHILD}/locations/us-central1/services/shop", "uri": REAL_URI}], None)
    svc, calls = _svc(tf, tmp_path, listing=listing)
    _write_topology(tmp_path, tf, {"shop": "cloudrun", "jobs": "event-worker"})
    res = _deploy(svc)
    assert res["service_url"] == REAL_URI and res["service_url_unknown_reason"] is None and calls["list"]


def test_topology_expects_service_url_rule(tf):
    assert tf.topology_expects_service_url(None) is True              # no typed topology: legacy behavior
    assert tf.topology_expects_service_url({"a": "cloudrun"}) is True
    assert tf.topology_expects_service_url({"a": "gke-autopilot", "b": "event-worker"}) is False
    assert tf.topology_expects_service_url({}) is False


def test_failed_startup_probe_apply_is_failed(tf, tmp_path):
    svc, calls = _svc(tf, tmp_path, listing=([{"name": "x/shop", "uri": REAL_URI}], None))
    svc._run_subprocess = lambda cmd, **k: (
        {"success": False, "returncode": 1, "stdout": "",
         "stderr": "Error: The user-provided container failed the configured startup probe checks"}
        if "apply" in cmd else {"success": True, "returncode": 0, "stdout": "{}" if "output" in cmd else "",
                                "stderr": ""})
    res = _deploy(svc)
    assert res["status"] == "FAILED" and not res.get("service_url")
    assert calls["list"] == [] and not hasattr(svc, "_reconcile_cloud_run_service")


# ------------------------------------------------------------------------------------------------ consumers
def test_deploy_summary_says_unknown_with_the_reason(tf):
    assert tf.deploy_url_summary({"service_url": REAL_URI}) == REAL_URI
    assert tf.deploy_url_summary({"service_url": "", "service_url_unknown_reason": "CLOUD_RUN_SERVICE_NOT_FOUND"}) \
        == "unknown (CLOUD_RUN_SERVICE_NOT_FOUND)"
    assert tf.deploy_url_summary({"service_url": ""}) == "N/A" and tf.deploy_url_summary(None) == "N/A"


@pytest.fixture
def cc_modules(monkeypatch):
    monkeypatch.syspath_prepend(CC_DIR)
    for name in ("schemas", "diagram"):
        monkeypatch.delitem(sys.modules, name, raising=False)
    import diagram
    import schemas
    return diagram, schemas


@pytest.mark.parametrize("data,expect", [
    ({"service_url": "", "service_url_unknown_reason": "CLOUD_RUN_API_UNAVAILABLE"},
     "URL unknown: CLOUD_RUN_API_UNAVAILABLE"),
    ({}, "URL unknown"),
    ({"service_url_unknown_reason": 'x"]; click A evil'}, "URL unknown"),   # not a typed token: not shown
])
def test_diagram_renders_unknown_never_a_made_up_address(cc_modules, data, expect):
    diagram, _ = cc_modules
    out = diagram.ArchitectureDiagramEngine()._generate_child_workload_diagram("shop", data, {})
    assert expect in out.mermaid_code and "run.app" not in out.mermaid_code
    assert "evil" not in out.mermaid_code


def test_diagram_keeps_a_real_url(cc_modules):
    diagram, _ = cc_modules
    out = diagram.ArchitectureDiagramEngine()._generate_child_workload_diagram("shop", {"service_url": REAL_URI}, {})
    assert REAL_URI in out.mermaid_code


def test_cc_workload_schemas_carry_the_unknown_reason(cc_modules):
    _, schemas = cc_modules
    for model in (schemas.WorkloadSummary, schemas.WorkloadDetailsResponse):
        assert "service_url_unknown_reason" in model.model_fields
        assert model.model_fields["service_url_unknown_reason"].default is None
