"""FD-102 (security hotfix 0.9.1-preview.2, register SEC-HOTFIX-SERVICE-URL-CONFIRMED): the terraform server records
only a Run-API-confirmed service URL, and both raw-output producers write strings only.

* `confirm_cloud_run_service_url(value, listed)`: a `str` of printable characters that, after removing at most one
  trailing '/', equals the `uri` or one of the `urls` of a service in the complete listing; the API's own string is
  returned. Anything else is "" with CLOUD_RUN_URL_NOT_CONFIRMED; a failed listing is CLOUD_RUN_API_UNAVAILABLE.
* `deploy_workload`: confirmation right after the outputs read (one listing per deploy, shared), before the sign-in
  domain step and every write; an unconfirmed output records "" with its reason and the SERVICE_URL_UNKNOWN warning,
  and is never replaced by a URL picked from the listing; no listing for a failed deploy. Do No Harm: a confirmed
  URL is reported exactly as before (tests/test_fd4de_service_url.py), the primary service's rollout `uri` (API)
  still fills an unknown URL.
* `apply_infrastructure` (test-only caller) takes the same rule.
* tf-applier (`applier.py`) and the Shared-install worker (`main.py` `run_deploy_in_background`): the outcome's
  `outputs` is `{"service_url": <confirmed str or "">}` after `outcome.update(res)`, so the Terraform output map never
  reaches the callback or `pipeline_executions.outputs.service_url`.
Hermetic: fake listings, fake Firestore, captured callbacks; no network, no cloud client.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import types
from unittest.mock import MagicMock, patch

import pytest

from test_fd4de_service_url import (  # noqa: F401  (pytest fixtures reused by name)
    CHILD, PID, REAL_DET, REAL_URI, _codes, _deploy, _no_gcp, _public_app_svc, _svc, tf)
from test_fd4g_terraform_workspace import (  # noqa: F401  (pytest fixtures reused by name)
    _isolated_tf_service, _no_network, _patched_applier, base, sent_callbacks, tf_main)

LISTING = [{"name": f"projects/{CHILD}/locations/us-central1/services/shop", "uri": REAL_URI,
            "urls": [REAL_DET, REAL_URI]}]
HOSTILE = "https://evil.example.test"
CONTROL = ["\n", "\r", "\t", "\x1b", "\x00", "\x7f", "\u0085", " "]


# ------------------------------------------------------------------------------------------------ pure helper
def test_confirmed_value_returns_the_listed_string(tf):
    confirm = tf.confirm_cloud_run_service_url
    assert confirm(REAL_URI, LISTING) == (REAL_URI, None)
    assert confirm(REAL_DET, LISTING) == (REAL_DET, None)               # one of `urls`
    assert confirm(REAL_URI + "/", LISTING) == (REAL_URI, None)         # at most one trailing '/' removed
    listed_with_slash = [{"name": "x", "uri": REAL_URI + "/"}]
    assert confirm(REAL_URI, listed_with_slash) == (REAL_URI + "/", None)   # the API's string, as listed


@pytest.mark.parametrize("value", [{"value": REAL_URI}, {}, [], [REAL_URI], None, 7, 1.5, True, b"https://x",
                                   ""])
def test_non_string_values_are_not_confirmed(tf, value):
    assert tf.confirm_cloud_run_service_url(value, LISTING) == ("", tf.SERVICE_URL_NOT_CONFIRMED)
    # the type check comes first: a failed listing does not change the reason of a value that is not a URL string
    assert tf.confirm_cloud_run_service_url(value, None) == ("", tf.SERVICE_URL_NOT_CONFIRMED)


@pytest.mark.parametrize("ch", CONTROL)
def test_control_characters_are_refused_even_when_the_rest_is_listed(tf, ch):
    for value in (REAL_URI + ch, ch + REAL_URI, REAL_URI[:8] + ch + REAL_URI[8:]):
        # a listing that (absurdly) holds the same string still does not confirm it
        listed = LISTING + [{"name": "y", "uri": value}]
        assert tf.confirm_cloud_run_service_url(value, listed) == ("", tf.SERVICE_URL_NOT_CONFIRMED)


@pytest.mark.parametrize("value", [HOSTILE, REAL_URI + "//", REAL_URI + "x", REAL_URI.upper(), REAL_URI[:-1],
                                   REAL_URI + "/health", "http://" + REAL_URI[len("https://"):],
                                   "https://user@" + REAL_URI[len("https://"):]])
def test_unlisted_values_are_not_confirmed(tf, value):
    assert tf.confirm_cloud_run_service_url(value, LISTING) == ("", tf.SERVICE_URL_NOT_CONFIRMED)


def test_failed_listing_is_api_unavailable(tf):
    assert tf.confirm_cloud_run_service_url(REAL_URI, None) == ("", tf.SERVICE_URL_API_UNAVAILABLE)


def test_junk_listing_entries_never_confirm(tf):
    junk = ["https://x", {"uri": None}, {"uri": 3, "urls": "https://y"}, {"urls": [None, {}, HOSTILE + "\n"]}]
    assert tf.confirm_cloud_run_service_url("https://x", junk) == ("", tf.SERVICE_URL_NOT_CONFIRMED)
    assert tf.confirm_cloud_run_service_url("https://y", junk) == ("", tf.SERVICE_URL_NOT_CONFIRMED)


def test_new_reason_is_typed_and_registered(tf):
    assert tf.SERVICE_URL_NOT_CONFIRMED == "CLOUD_RUN_URL_NOT_CONFIRMED"
    assert tf.SERVICE_URL_NOT_CONFIRMED in tf.SERVICE_URL_UNKNOWN_REASONS
    assert tf.SERVICE_URL_API_UNAVAILABLE == "CLOUD_RUN_API_UNAVAILABLE"   # the existing reason is reused


# ------------------------------------------------------------------------------------------------ deploy
def _db():
    db = MagicMock(name="firestore")
    db.collection.return_value.document.return_value.get.return_value = types.SimpleNamespace(
        exists=False, to_dict=lambda: {})
    return db


def _workload_sets(db):
    return [c.args[0] for c in db.collection.return_value.document.return_value.set.call_args_list
            if "deployed_at" in c.args[0]]


def test_output_equal_to_a_listed_url_is_recorded_as_the_api_string(tf, tmp_path):
    db = _db()
    svc, calls = _svc(tf, tmp_path, outputs=json.dumps({"service_url": {"value": REAL_DET + "/"}}),
                      listing=(LISTING, None), db=db)
    res = _deploy(svc)
    assert res["status"] == "SUCCESS" and res["service_url"] == REAL_DET and res["service_url_unknown_reason"] is None
    assert calls["list"] == [(CHILD, "us-central1")]
    assert _workload_sets(db)[-1]["service_url"] == REAL_DET


@pytest.mark.parametrize("value", [{"a": REAL_URI}, [REAL_URI], 42, HOSTILE, REAL_URI + "\n", REAL_URI + " "])
def test_unconfirmed_output_records_unknown_and_is_never_replaced(tf, tmp_path, value):
    """Non-`str`, unlisted or control characters: "" with CLOUD_RUN_URL_NOT_CONFIRMED and the SERVICE_URL_UNKNOWN
    warning; the one listed service (which the FD-4DE picker would choose) is NOT substituted."""
    db = _db()
    svc, calls = _svc(tf, tmp_path, outputs=json.dumps({"service_url": {"value": value}}),
                      listing=(LISTING, None), db=db)
    res = _deploy(svc)
    assert res["status"] == "SUCCESS"
    assert res["service_url"] == "" and res["service_url_unknown_reason"] == tf.SERVICE_URL_NOT_CONFIRMED
    assert [w["reason"] for w in _codes(res, tf.SERVICE_URL_UNKNOWN)] == [tf.SERVICE_URL_NOT_CONFIRMED]
    assert len(calls["list"]) == 1
    rec = _workload_sets(db)[-1]
    assert rec["service_url"] == "" and rec["service_url_unknown_reason"] == tf.SERVICE_URL_NOT_CONFIRMED
    # every recorded `service_url` (workload record, audit record, feature requests) is the unknown ""
    recorded = [c.args[0]["service_url"] for c in db.collection.return_value.document.return_value.set.call_args_list
                if "service_url" in c.args[0]]
    assert recorded and set(recorded) == {""}


@pytest.mark.parametrize("key", ["service_url", "service_uri", "url"])
def test_every_url_output_name_takes_the_rule(tf, tmp_path, key):
    svc, _ = _svc(tf, tmp_path, outputs=json.dumps({key: {"value": HOSTILE}}), listing=(LISTING, None))
    res = _deploy(svc)
    assert res["service_url"] == "" and res["service_url_unknown_reason"] == tf.SERVICE_URL_NOT_CONFIRMED


def test_listing_failure_records_unknown_for_an_output_url(tf, tmp_path):
    svc, calls = _svc(tf, tmp_path, outputs=json.dumps({"service_url": {"value": REAL_URI}}),
                      listing=(None, "CLOUD_RUN_API_UNAVAILABLE"))
    res = _deploy(svc)
    assert res["status"] == "SUCCESS" and res["service_url"] == ""
    assert res["service_url_unknown_reason"] == tf.SERVICE_URL_API_UNAVAILABLE
    assert [w["reason"] for w in _codes(res, tf.SERVICE_URL_UNKNOWN)] == [tf.SERVICE_URL_API_UNAVAILABLE]
    assert len(calls["list"]) == 1


def test_non_string_output_stays_not_confirmed_when_the_listing_also_fails(tf, tmp_path):
    svc, _ = _svc(tf, tmp_path, outputs=json.dumps({"service_url": {"value": {"a": REAL_URI}}}),
                  listing=(None, "CLOUD_RUN_API_UNAVAILABLE"))
    res = _deploy(svc)
    assert res["service_url"] == "" and res["service_url_unknown_reason"] == tf.SERVICE_URL_NOT_CONFIRMED


def test_no_listing_for_a_failed_deploy(tf, tmp_path):
    svc, calls = _svc(tf, tmp_path, outputs=json.dumps({"service_url": {"value": REAL_URI}}),
                      listing=(LISTING, None))
    svc._run_subprocess = lambda cmd, **k: (
        {"success": False, "returncode": 1, "stdout": "", "stderr": "Error: boom"} if "apply" in cmd
        else {"success": True, "returncode": 0, "stdout": json.dumps({"service_url": {"value": REAL_URI}})
              if "output" in cmd else "", "stderr": ""})
    res = _deploy(svc)
    assert res["status"] == "FAILED" and not res.get("service_url") and calls["list"] == []


def test_primary_rollout_uri_still_fills_an_unconfirmed_url(tf, tmp_path):
    """The rollout `uri` is the Cloud Run API's own answer: accepted (as FD-4DE)."""
    svc, calls = _svc(tf, tmp_path, outputs=json.dumps({"service_url": {"value": HOSTILE}}),
                      listing=(LISTING, None), rollout=(True, "shop-00002", REAL_URI))
    res = _deploy(svc)
    assert "shop" in calls["rollout"]
    assert res["service_url"] == REAL_URI and res["service_url_unknown_reason"] is None


def test_signin_domain_step_sees_only_a_confirmed_host(tf, tmp_path, monkeypatch):
    """PUBLIC_APP: an unconfirmed output host is not authorized for sign-in; the listed hosts are."""
    svc, calls, patched = _public_app_svc(tf, tmp_path, monkeypatch, listing=(LISTING, None),
                                          outputs=json.dumps({"service_url": {"value": HOSTILE}}))
    res = _deploy(svc)
    assert res["service_url"] == "" and res["service_url_unknown_reason"] == tf.SERVICE_URL_NOT_CONFIRMED
    assert patched and "evil.example.test" not in patched[-1]
    assert {"shop-k3j2h1-uc.a.run.app", "shop-424242.us-central1.run.app"} <= set(patched[-1])
    assert len(calls["list"]) == 1                      # the confirmation's listing is the domain step's too


def test_signin_domain_step_gets_the_confirmed_url(tf, tmp_path, monkeypatch):
    svc, _, patched = _public_app_svc(tf, tmp_path, monkeypatch, listing=(LISTING, None),
                                      outputs=json.dumps({"service_url": {"value": REAL_URI}}))
    res = _deploy(svc)
    assert res["service_url"] == REAL_URI and "shop-k3j2h1-uc.a.run.app" in patched[-1]


# ------------------------------------------------------------------------------------------------ apply_infrastructure
def _infra(tf, tmp_path, outputs, listing, target=CHILD):
    svc = tf.TerraformService(project_id="castor-parent", state_bucket="", workspace_base_dir=str(tmp_path),
                              firestore_client=MagicMock(name="firestore"))
    svc.db = None
    listed = []
    svc.apply_plan = lambda **k: {"status": "APPLIED", "outputs": outputs}
    svc._resolve_region = lambda: "us-central1"
    svc._list_cloud_run_services = lambda project, region: listed.append((project, region)) or listing
    synced = {}
    svc._sync_feature_requests = lambda **k: synced.update(k)
    svc.apply_infrastructure(product_id=PID, trace_id="t-infra", target_project_id=target)
    return synced, listed


@pytest.mark.parametrize("target", [None, ""])
def test_apply_infrastructure_without_a_target_project_builds_no_project_id(tf, tmp_path, caplog, target):
    """R2: no project id is derived from the product id; nothing is listed and the URL is unknown (typed warning)."""
    caplog.set_level("WARNING")
    synced, listed = _infra(tf, tmp_path, {"url": {"value": REAL_URI}}, (LISTING, None), target=target)
    assert synced["service_url"] is None and listed == []
    assert any("SERVICE_URL_UNKNOWN (CLOUD_RUN_API_UNAVAILABLE)" in r.getMessage() for r in caplog.records)


def test_apply_infrastructure_takes_the_same_rule(tf, tmp_path):
    synced, listed = _infra(tf, tmp_path, {"url": {"value": REAL_URI + "/"}}, (LISTING, None))
    assert synced["service_url"] == REAL_URI and listed == [(CHILD, "us-central1")]
    for value, listing in ((HOSTILE, (LISTING, None)), ({"x": 1}, (LISTING, None)), (REAL_URI + "\r", (LISTING, None)),
                           (REAL_URI, (None, "CLOUD_RUN_API_UNAVAILABLE"))):
        synced, _ = _infra(tf, tmp_path, {"url": {"value": value}}, listing)
        assert synced["service_url"] is None, value
    synced, listed = _infra(tf, tmp_path, {}, (LISTING, None))     # no URL output: nothing is listed
    assert synced["service_url"] is None and listed == []


# ------------------------------------------------------------------------------------------------ raw-output producers
RAW_MAP = {"service_url": {"value": HOSTILE, "type": "string", "sensitive": False},
           "db": {"value": "(sensitive value)", "type": "string", "sensitive": True}}


class _FakeDb:
    def __init__(self):
        self.sets = []

    def collection(self, name):
        db = self

        class _Doc:
            def __init__(self, doc_id):
                self.doc_id = doc_id

            def set(self, data, merge=False):
                db.sets.append((name, self.doc_id, data))

            def get(self):
                return types.SimpleNamespace(exists=False, to_dict=lambda: {})

        return types.SimpleNamespace(document=lambda doc_id: _Doc(doc_id))


def _run_outputs(fdb, trace):
    return [d["outputs"] for c, doc, d in fdb.sets if c == "pipeline_executions" and doc == trace and "outputs" in d]


@pytest.mark.parametrize("result,expected", [
    ({"status": "SUCCESS", "service_url": REAL_URI, "outputs": RAW_MAP}, REAL_URI),
    ({"status": "SUCCESS", "service_url": "", "service_url_unknown_reason": "CLOUD_RUN_URL_NOT_CONFIRMED",
      "outputs": RAW_MAP}, ""),
    ({"status": "FAILED", "error": "boom", "outputs": RAW_MAP}, ""),
])
def test_shared_install_worker_never_forwards_the_raw_output_map(tf_main, sent_callbacks, result, expected):
    fdb = _FakeDb()
    tf_main.service.db = fdb
    tf_main.service.deploy_workload = MagicMock(return_value=result)
    req = tf_main.AsyncDeployRequest(product_id="app", trace_id="t-fd102-main", callback_url="http://127.0.0.1:9/cb")
    with patch.object(tf_main, "trigger_tf_applier_job", return_value=False):
        tf_main.run_deploy_in_background(req)
    last = sent_callbacks[-1]
    assert last["outputs"] == {"service_url": expected}
    assert "evil.example.test" not in json.dumps(last["outputs"])
    recorded = _run_outputs(fdb, "t-fd102-main")
    assert recorded == ([{"service_url": expected}] if expected else []), recorded
    assert "evil.example.test" not in json.dumps([d for _, _, d in fdb.sets], default=str)


@pytest.mark.parametrize("result,code,expected", [
    ({"status": "SUCCESS", "service_url": REAL_URI, "outputs": RAW_MAP}, 0, REAL_URI),
    ({"status": "FAILED", "error": "boom", "outputs": RAW_MAP}, 1, ""),
])
def test_tf_applier_never_forwards_the_raw_output_map(monkeypatch, base, sent_callbacks, result, code, expected):
    applier = _patched_applier(monkeypatch, base, f"fd102_tf_applier_{code}", MagicMock(return_value=result))
    monkeypatch.setenv("PRODUCT_ID", "app")
    with pytest.raises(SystemExit) as ei:
        applier.run_job()
    assert ei.value.code == code
    last = sent_callbacks[-1]
    assert last["outputs"] == {"service_url": expected}
    assert "evil.example.test" not in json.dumps(last["outputs"])


def test_callback_outputs_helper(tf):
    assert tf.callback_outputs({"service_url": REAL_URI, "outputs": RAW_MAP}) == {"service_url": REAL_URI}
    for res in ({}, None, {"service_url": None}, {"service_url": {"value": REAL_URI}}, {"service_url": [REAL_URI]}):
        assert tf.callback_outputs(res) == {"service_url": ""}
