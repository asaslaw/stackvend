"""SAT-31 RT M1 (Fable 11-01): the Shared-install RunJob dispatch of /deploy-async classifies every failure by type,
HTTP status and the API's own JSON status body (never message text):

* a refusal the API made itself (nothing started) -> `outcome_unknown` False; 429 / 503 (SDK ResourceExhausted, or
  ServiceUnavailable / REST 429 / 503 carrying the API's status body) are retried at most 3 times after 2 / 4 / 8 s;
* an ambiguous failure (timeout, gateway answer without the API body, gRPC UNAVAILABLE, Unknown, Internal, Aborted,
  Cancelled) -> `outcome_unknown` True, never retried, and never followed by the REST RunJob.

Negatives: the success paths (SDK first try, REST first try) send exactly one RunJob, sleep never.
Hermetic: run_v2 / requests / google.auth are patched; sleeping is recorded, not done.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

from unittest.mock import MagicMock, patch

import pytest
import requests
from google.api_core import exceptions as gax

from test_fd4g_terraform_workspace import _isolated_tf_service, base, sent_callbacks  # noqa: F401
from test_fd7l_5a_dispatch import CALLBACK, tf_main  # noqa: F401


@pytest.fixture
def kit(monkeypatch, tf_main):
    monkeypatch.setenv("ENABLE_TF_APPLIER_JOB", "true")
    monkeypatch.setenv("REGION", "us-central1")
    slept = []
    monkeypatch.setattr(tf_main, "RUN_JOB_SLEEP", slept.append)
    req = tf_main.AsyncDeployRequest(product_id="app", trace_id="t1", callback_url=CALLBACK)
    return tf_main, slept, req


def _resp(status, body=None):
    r = MagicMock()
    r.status_code = status
    r.text = "x"
    if body is None:
        r.json.side_effect = ValueError("no json")
    else:
        r.json.return_value = body
    return r


def _api(status_code, status):
    return {"error": {"code": status_code, "message": "m", "status": status}}


def _run(tf_main, req, sdk_effects=None, rest_effects=None):
    """sdk_effects: None = SDK not installed; else run_job side effects. rest_effects: requests.post side effects."""
    run_v2 = MagicMock()
    client = run_v2.JobsClient.return_value
    if sdk_effects is not None:
        client.run_job.side_effect = sdk_effects
    creds = MagicMock()
    creds.token = "test-only-token"
    post = MagicMock(side_effect=rest_effects or [AssertionError("REST must not be called")])
    with patch.dict("sys.modules", {"google.cloud.run_v2": run_v2 if sdk_effects is not None else None}), \
            patch("google.auth.default", return_value=(creds, "p")), \
            patch("google.auth.transport.requests.Request"), patch("requests.post", post):
        try:
            return tf_main.trigger_tf_applier_job(req), client.run_job, post
        except tf_main.rd.TfApplierDispatchFailed as e:
            return e, client.run_job, post


def _ok_op():
    op = MagicMock()
    op.operation.name = "operations/1"
    return op


# ------------------------------------------------------------------------------------------------ SDK
def test_sdk_success_first_try_sends_one_runjob_and_never_sleeps(kit):
    tf_main, slept, req = kit
    out, run_job, post = _run(tf_main, req, sdk_effects=[_ok_op()])
    assert out is True and run_job.call_count == 1 and post.call_count == 0 and slept == []


def test_sdk_quota_refusal_is_retried_with_backoff(kit):
    tf_main, slept, req = kit
    out, run_job, post = _run(tf_main, req, sdk_effects=[gax.ResourceExhausted("q"), gax.ResourceExhausted("q"),
                                                         _ok_op()])
    assert out is True and run_job.call_count == 3 and slept == [2.0, 4.0] and post.call_count == 0


def test_sdk_quota_refusal_exhausted_stops_after_three_retries_in_all(kit):
    """Re-check F1: 3 retries in all (4 RunJobs, 14 s of backoff); the same quota is not retried again via REST."""
    tf_main, slept, req = kit
    out, run_job, post = _run(tf_main, req, sdk_effects=[gax.ResourceExhausted("q")] * 4)
    assert isinstance(out, tf_main.rd.TfApplierDispatchFailed) and out.outcome_unknown is False
    assert out.cause == "RUN_JOB_FAILED" and out.upstream_status == 429
    assert run_job.call_count == 4 and slept == [2.0, 4.0, 8.0] and post.call_count == 0


@pytest.mark.parametrize("exc", [gax.PermissionDenied("x"), gax.NotFound("x"), gax.InvalidArgument("x"),
                                 gax.FailedPrecondition("x"), gax.Unauthenticated("x")])
def test_sdk_refusal_is_not_retried_and_rest_may_start_it(kit, exc):
    tf_main, slept, req = kit
    out, run_job, post = _run(tf_main, req, sdk_effects=[exc], rest_effects=[_resp(200, {"name": "op"})])
    assert out is True and run_job.call_count == 1 and post.call_count == 1 and slept == []


@pytest.mark.parametrize("exc", [gax.DeadlineExceeded("x"), gax.Unknown("x"), gax.InternalServerError("x"),
                                 gax.Aborted("x"), gax.Cancelled("x"), gax.ServiceUnavailable("grpc unavailable"),
                                 ConnectionResetError("reset"), RuntimeError("other")])
def test_sdk_ambiguous_failure_is_never_followed_by_a_second_runjob(kit, sent_callbacks, exc):
    tf_main, slept, req = kit
    out, run_job, post = _run(tf_main, req, sdk_effects=[exc])
    assert isinstance(out, tf_main.rd.TfApplierDispatchFailed)
    assert out.outcome_unknown is True and out.cause == "RUN_JOB_FAILED"
    assert run_job.call_count == 1 and post.call_count == 0 and slept == []


def test_sdk_unavailable_on_the_default_grpc_transport_is_ambiguous(kit):
    """Re-check F2: on gRPC, ServiceUnavailable.response is the RpcError (no JSON body), so it is never retried."""
    tf_main, slept, req = kit
    rpc_error = MagicMock(spec=["code", "details"])          # a grpc.RpcError has no .json()
    out, run_job, post = _run(tf_main, req, sdk_effects=[gax.ServiceUnavailable("x", response=rpc_error)])
    assert isinstance(out, tf_main.rd.TfApplierDispatchFailed) and out.outcome_unknown is True
    assert run_job.call_count == 1 and post.call_count == 0 and slept == []


def test_sdk_unavailable_with_the_api_status_body_is_retried(kit):
    tf_main, slept, req = kit
    exc = gax.ServiceUnavailable("x", response=_resp(503, _api(503, "UNAVAILABLE")))
    out, run_job, post = _run(tf_main, req, sdk_effects=[exc, _ok_op()])
    assert out is True and run_job.call_count == 2 and slept == [2.0] and post.call_count == 0


def test_sdk_client_not_built_falls_through_to_rest(kit):
    tf_main, slept, req = kit
    run_v2 = MagicMock()
    run_v2.JobsClient.side_effect = RuntimeError("no credentials")
    creds = MagicMock()
    creds.token = "test-only-token"
    with patch.dict("sys.modules", {"google.cloud.run_v2": run_v2}), \
            patch("google.auth.default", return_value=(creds, "p")), \
            patch("google.auth.transport.requests.Request"), \
            patch("requests.post", return_value=_resp(200, {"name": "op"})) as post:
        assert tf_main.trigger_tf_applier_job(req) is True
    assert post.call_count == 1


# ------------------------------------------------------------------------------------------------ REST
def test_rest_success_first_try_sends_one_runjob(kit):
    tf_main, slept, req = kit
    out, _, post = _run(tf_main, req, rest_effects=[_resp(200, {"name": "op"})])
    assert out is True and post.call_count == 1 and slept == []


def test_rest_429_with_the_api_body_is_retried_three_times_then_typed(kit):
    tf_main, slept, req = kit
    out, _, post = _run(tf_main, req, rest_effects=[_resp(429, _api(429, "RESOURCE_EXHAUSTED"))] * 4)
    assert isinstance(out, tf_main.rd.TfApplierDispatchFailed) and out.outcome_unknown is False
    assert post.call_count == 4 and slept == [2.0, 4.0, 8.0] and out.upstream_status == 429


def test_rest_503_with_the_api_body_then_success(kit):
    tf_main, slept, req = kit
    out, _, post = _run(tf_main, req, rest_effects=[_resp(503, _api(503, "UNAVAILABLE")),
                                                    _resp(200, {"name": "op"})])
    assert out is True and post.call_count == 2 and slept == [2.0]


@pytest.mark.parametrize("answer,unknown", [
    (_resp(503), True),                                       # a front end, no API body: may hide a start
    (_resp(504), True),
    (_resp(502, {"not": "the api body"}), True),
    (_resp(429), False),                                      # 4xx without the API body: refused, not retried
    (_resp(500, _api(500, "INTERNAL")), False),               # the API's own refusal
    (_resp(429, _api(429, "UNAVAILABLE")), False),            # status and API status disagree: not retried
    (_resp(403, _api(403, "PERMISSION_DENIED")), False),
])
def test_rest_non_retryable_answers_are_typed_once(kit, answer, unknown):
    tf_main, slept, req = kit
    out, _, post = _run(tf_main, req, rest_effects=[answer, AssertionError("retried")])
    assert isinstance(out, tf_main.rd.TfApplierDispatchFailed) and out.outcome_unknown is unknown
    assert post.call_count == 1 and slept == []


@pytest.mark.parametrize("exc,unknown", [(requests.exceptions.ConnectTimeout("x"), False),
                                         (requests.exceptions.ReadTimeout("x"), True),
                                         (requests.exceptions.ConnectionError("x"), True)])
def test_rest_transport_failures_are_never_retried(kit, exc, unknown):
    tf_main, slept, req = kit
    out, _, post = _run(tf_main, req, rest_effects=[exc, AssertionError("retried")])
    assert isinstance(out, tf_main.rd.TfApplierDispatchFailed) and out.outcome_unknown is unknown
    assert post.call_count == 1 and slept == []


def test_rest_without_credentials_sends_nothing(kit):
    tf_main, slept, req = kit
    with patch.dict("sys.modules", {"google.cloud.run_v2": None}), \
            patch("google.auth.default", side_effect=RuntimeError("no adc")), \
            patch("requests.post") as post:
        with pytest.raises(tf_main.rd.TfApplierDispatchFailed) as ei:
            tf_main.trigger_tf_applier_job(req)
    assert ei.value.outcome_unknown is False and post.call_count == 0


def test_run_deploy_reports_the_typed_failure_with_the_classification(kit, sent_callbacks):
    tf_main, slept, req = kit
    with patch.dict("sys.modules", {"google.cloud.run_v2": MagicMock(**{
            "JobsClient.return_value.run_job.side_effect": gax.DeadlineExceeded("x")})}):
        tf_main.run_deploy_in_background(req)
    tf_main.service.deploy_workload.assert_not_called()
    assert sent_callbacks[-1]["error_class"] == "TF_APPLIER_DISPATCH_FAILED"
    assert sent_callbacks[-1]["outcome_unknown"] is True and sent_callbacks[-1]["operator_required"] is True
