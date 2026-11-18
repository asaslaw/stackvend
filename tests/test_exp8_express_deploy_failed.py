"""EXP-8: every Express `/deploy` outcome other than HTTP 200 makes the terraform stage, the pipeline and the workload
FAILED with a typed reason: the response's `detail.error_class` when it has one (the terraform service now sends the
deploy result's own error_class for Express deploys: DESTROY_BLOCKED, COMPLIANCE_*, STATE_LOCKED, ...), else
EXPRESS_DEPLOY_FAILED with the HTTP status (None when there was no response). Message text is never read. A 200 is
unchanged (ACTIVE). EXP-7's DESTROY_REQUIRES_APPROVAL refusal goes through the same recorder.

Hermetic: dict-backed Firestore, terraform/vending calls mocked (harness shared with the EXP-7 tests).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import)

import ast
import inspect
import os
import sys
import textwrap
from unittest.mock import MagicMock

import httpx
import pytest

sys.path.insert(0, os.path.dirname(__file__))

from test_exp7_express_destroy_approval import _route, _run  # noqa: E402

PE, WL = "pipeline_executions/tr-exp7", "workloads/exp-app"


def _assert_failed(store, error_class, http_status):
    pe, wdoc = store.docs[PE], store.docs[WL]
    stage = pe["stages"]["terraform"]
    assert stage["status"] == "FAILED" and stage["error_class"] == error_class and stage["summary"]
    assert stage.get("http_status") == http_status
    assert pe["status"] == "FAILED" and pe["current_stage"] == "FAILED" and pe["error_class"] == error_class
    assert pe["error_message"] == stage["summary"]
    assert wdoc["status"] == "FAILED" and wdoc["failure_reason"].startswith(f"{error_class}: ")
    assert "service_url" not in wdoc                     # nothing ACTIVE-looking was written
    assert "outputs" not in pe or "service_url" not in pe["outputs"]


# ------------------------------------------------------------------------------------- each failure class -> FAILED
@pytest.mark.parametrize("status,body,error_class", [
    (500, {"detail": {"error_class": "DESTROY_BLOCKED", "error": "Terraform deployment failed: DESTROY_BLOCKED: x"}},
     "DESTROY_BLOCKED"),
    (500, {"detail": {"error_class": "COMPLIANCE_VIOLATION", "error": "refused"}}, "COMPLIANCE_VIOLATION"),
    (500, {"detail": {"error_class": "COMPLIANCE_UNAVAILABLE", "error": "refused"}}, "COMPLIANCE_UNAVAILABLE"),
    (500, {"detail": {"error_class": "STATE_LOCKED", "error": "STATE_LOCKED: held"}}, "STATE_LOCKED"),
    # a tofu error with no typed class in the result
    (500, {"detail": {"error_class": None, "error": "Terraform deployment failed: Error: ..."}}, "EXPRESS_DEPLOY_FAILED"),
    # an older terraform service (string detail): the class is NOT read out of the text
    (500, {"detail": "Terraform deployment failed: DESTROY_BLOCKED: the plan deletes"}, "EXPRESS_DEPLOY_FAILED"),
    (409, {"detail": "A deployment is in progress"}, "EXPRESS_DEPLOY_FAILED"),
    (422, {"detail": [{"loc": ["body", "product_id"], "msg": "field required"}]}, "EXPRESS_DEPLOY_FAILED"),
    # the real UnsafePathError handler answers 400 with a string detail (mcp-servers/terraform/main.py)
    (400, {"detail": "unsafe path: product_id"}, "EXPRESS_DEPLOY_FAILED"),
    # any typed class on any status passes through as-is
    (400, {"detail": {"error_class": "SOME_TYPED_CLASS", "error": "x"}}, "SOME_TYPED_CLASS"),
    # an error_class that is not an identifier is not a type
    (500, {"detail": {"error_class": "Terraform deployment failed", "error": "x"}}, "EXPRESS_DEPLOY_FAILED"),
    (500, {"detail": {"error_class": 7, "error": "x"}}, "EXPRESS_DEPLOY_FAILED"),
    (502, {"unexpected": True}, "EXPRESS_DEPLOY_FAILED"),
])
def test_every_non_200_is_a_failed_stage_pipeline_and_workload(monkeypatch, status, body, error_class):
    wl, store, tfm = _route(monkeypatch, tf_status=status, tf_json=body)
    _run(wl)
    _assert_failed(store, error_class, status)


def test_a_non_json_error_body_is_express_deploy_failed_with_the_status(monkeypatch):
    wl, store, tfm = _route(monkeypatch, tf_status=503)
    tfm.return_value.json.side_effect = ValueError("not json")
    _run(wl)
    _assert_failed(store, "EXPRESS_DEPLOY_FAILED", 503)
    assert "503" in store.docs[PE]["error_message"]


@pytest.mark.parametrize("exc", [httpx.ConnectError("refused"), httpx.RemoteProtocolError("eof"), RuntimeError("x")])
def test_a_raised_call_is_failed_with_no_status(monkeypatch, exc):
    wl, store, tfm = _route(monkeypatch)
    tfm.side_effect = exc
    _run(wl)
    _assert_failed(store, "EXPRESS_DEPLOY_FAILED", None)
    assert type(exc).__name__ in store.docs[PE]["error_message"]


@pytest.mark.parametrize("exc", [httpx.ReadTimeout("t"), httpx.ConnectTimeout("t"), httpx.WriteTimeout("t"),
                                 httpx.PoolTimeout("t")])
def test_rt_m1_a_timed_out_call_is_outcome_unknown(monkeypatch, exc):
    """The apply may still finish server-side: a typed class of its own, decided by exception type."""
    wl, store, tfm = _route(monkeypatch)
    tfm.side_effect = exc
    _run(wl)
    _assert_failed(store, "EXPRESS_DEPLOY_OUTCOME_UNKNOWN", None)
    assert type(exc).__name__ in store.docs[PE]["error_message"]


def test_rt_m1_a_timeout_message_alone_is_not_a_timeout(monkeypatch):
    """Negative: a non-timeout exception whose text says "timed out" stays EXPRESS_DEPLOY_FAILED."""
    wl, store, tfm = _route(monkeypatch)
    tfm.side_effect = RuntimeError("Read timed out (TimeoutException)")
    _run(wl)
    _assert_failed(store, "EXPRESS_DEPLOY_FAILED", None)


def test_rt_m1_the_client_waits_the_terraform_services_own_limit(monkeypatch):
    import re as _re

    wl, store, tfm = _route(monkeypatch)
    _run(wl)
    assert tfm.call_args.kwargs["timeout"] == wl.EXPRESS_DEPLOY_TIMEOUT_SECONDS == 1800.0
    tf_main_tf = open(os.path.join(os.path.dirname(__file__), "..", "infra", "platform", "main.tf")).read()
    # the platform's Cloud Run request timeout (shared by the services, incl. mcp-terraform-server)
    assert _re.search(r'timeout\s*=\s*"1800s"', tf_main_tf)


def test_no_terraform_service_is_failed_not_active(monkeypatch):
    wl, store, tfm = _route(monkeypatch)
    tfm.return_value = None
    _run(wl)
    _assert_failed(store, "EXPRESS_DEPLOY_FAILED", None)


def test_a_failure_keeps_an_open_refusal_marker(monkeypatch):
    """EXP-7 RT B1's DEPLOY_ONLY guard reads the marker: only a successful deploy may clear it."""
    detail = {"error_class": "DESTROY_REQUIRES_APPROVAL", "error": "x", "removal_addresses": ["a.x"]}
    wl, store, tfm = _route(monkeypatch, tf_status=409, tf_json={"detail": detail})
    _run(wl)
    tfm.return_value.status_code = 500
    tfm.return_value.json.return_value = {"detail": {"error_class": "STATE_LOCKED", "error": "held"}}
    _run(wl)
    _assert_failed(store, "STATE_LOCKED", 500)
    assert store.docs[WL]["destroy_requires_approval"]["removal_addresses"] == ["a.x"]


def test_rt_m1_a_success_after_a_failure_clears_the_failure_reason(monkeypatch):
    wl, store, tfm = _route(monkeypatch, tf_status=500, tf_json={"detail": {"error_class": "STATE_LOCKED"}})
    _run(wl)
    assert store.docs[WL]["failure_reason"].startswith("STATE_LOCKED: ")
    tfm.return_value.status_code = 200
    tfm.return_value.json.return_value = {"status": "SUCCESS", "service_url": "https://x.run.app"}
    _run(wl)
    assert store.docs[WL]["status"] == "ACTIVE" and store.docs[WL]["failure_reason"] is None


def test_the_exp7_refusal_uses_the_same_recorder(monkeypatch):
    detail = {"error_class": "DESTROY_REQUIRES_APPROVAL", "error": "x", "removal_addresses": ["b.y", "a.x"],
              "approved_removals": []}
    wl, store, tfm = _route(monkeypatch, tf_status=409, tf_json={"detail": detail})
    calls = []
    real = wl._record_express_terraform_failed
    monkeypatch.setattr(wl, "_record_express_terraform_failed", lambda *a, **k: (calls.append(a[2]), real(*a, **k)))
    _run(wl)
    assert calls == ["DESTROY_REQUIRES_APPROVAL"]
    _assert_failed(store, "DESTROY_REQUIRES_APPROVAL", None)
    assert store.docs[PE]["destroy_requires_approval"]["removal_addresses"] == ["a.x", "b.y"]
    wdoc = store.docs[WL]["destroy_requires_approval"]
    assert wdoc["removal_addresses"] == ["a.x", "b.y"] and wdoc["trace_id"] == "tr-exp7" and wdoc["refused_at"]


# ------------------------------------------------------------------------------------------- success unchanged
def test_negative_a_200_is_unchanged_active(monkeypatch):
    wl, store, tfm = _route(monkeypatch)
    _run(wl)
    pe, wdoc = store.docs[PE], store.docs[WL]
    assert wdoc["status"] == "ACTIVE" and wdoc["service_url"] == "https://x.run.app"
    assert wdoc.get("failure_reason") is None
    assert pe["status"] == "COMPLETED" and pe["current_stage"] == "ACTIVE"
    assert pe["stages"]["terraform"]["status"] == "SUCCESS" and "error_class" not in pe["stages"]["terraform"]
    assert pe["outputs"]["service_url"] == "https://x.run.app"


def test_negative_a_200_with_an_unreadable_body_is_still_active(monkeypatch):
    wl, store, tfm = _route(monkeypatch)
    tfm.return_value.json.side_effect = ValueError("not json")
    _run(wl)
    assert store.docs[WL]["status"] == "ACTIVE" and store.docs[WL]["service_url"] == ""


# ----------------------------------------------------------------------------- typed only: no message matching
_TEXT_METHODS = {"startswith", "endswith", "find", "rfind", "index", "rindex", "search", "match", "fullmatch",
                 "findall", "lower", "upper", "casefold", "split", "partition", "strip"}


_CONTAINER_LITERALS = (ast.Set, ast.Tuple, ast.List, ast.Dict)


def _assert_no_text_matching(fn):
    """RT m2: any `in` / `not in` must test membership in a literal set/tuple/list/dict, so a substring test with a
    variable needle (`needle in text`) fails too."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops):
            sides = [node.left, *node.comparators]
            assert not any(isinstance(s, ast.Constant) and isinstance(s.value, str) for s in sides), \
                f"{fn.__name__}: substring test at line {node.lineno}"
            for op, right in zip(node.ops, node.comparators):
                if isinstance(op, (ast.In, ast.NotIn)):
                    assert isinstance(right, _CONTAINER_LITERALS), \
                        f"{fn.__name__}: `in` against a non-literal at line {node.lineno}"
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in _TEXT_METHODS, f"{fn.__name__}: .{node.func.attr}() at line {node.lineno}"
        if isinstance(node, ast.Name):
            assert node.id != "re", f"{fn.__name__}: regex use at line {node.lineno}"


def test_classification_reads_typed_fields_only(monkeypatch):
    wl, _, _ = _route(monkeypatch)
    for fn in (wl._express_deploy_failure, wl._destroy_approval_refusal, wl._record_express_deploy_failure,
               wl._record_express_terraform_failed, wl._record_express_destroy_refusal):
        _assert_no_text_matching(fn)


def test_the_provisioning_deploy_step_branches_on_status_and_types_only(monkeypatch):
    """The /deploy handling in execute_express_provisioning decides on status_code, the typed refusal and the typed
    failure helper; no string constant is searched for anywhere in the function."""
    wl, _, _ = _route(monkeypatch)
    tree = ast.parse(inspect.getsource(wl.execute_express_provisioning))
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops):
            sides = [node.left, *node.comparators]
            assert not any(isinstance(s, ast.Constant) and isinstance(s.value, str) for s in sides)
    calls = {n.func.id for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert {"_express_deploy_failure", "_record_express_deploy_failure", "_record_express_destroy_refusal",
            "_destroy_approval_refusal"} <= calls


# ------------------------------------------------------------------------- terraform service /deploy (typed 500)
@pytest.fixture()
def tf_main(monkeypatch, tmp_path):
    from test_fd4g_terraform_workspace import _load_tf_module

    return _load_tf_module(monkeypatch, str(tmp_path), "main.py", "exp8_tf_main")


@pytest.mark.parametrize("result,error_class", [
    ({"status": "FAILED", "error_class": "DESTROY_BLOCKED", "error": "DESTROY_BLOCKED: x"}, "DESTROY_BLOCKED"),
    ({"status": "FAILED", "error_class": "COMPLIANCE_VIOLATION", "error": "v"}, "COMPLIANCE_VIOLATION"),
    ({"status": "FAILED", "error": "Error: tofu apply"}, None),
    ({"status": "FAILED", "error_class": "", "stderr": "boom"}, None),
])
def test_express_deploy_failure_is_a_typed_500(tf_main, result, error_class):
    from fastapi.testclient import TestClient

    tf_main.service.deploy_workload = MagicMock(return_value=result)
    r = TestClient(tf_main.app).post("/deploy", json={"product_id": "app", "trace_id": "t1", "refuse_destroy": True})
    assert r.status_code == 500
    detail = r.json()["detail"]
    assert detail["error_class"] == error_class and detail["error"].startswith("Terraform deployment failed: ")


def test_negative_agent_deploy_failure_keeps_the_string_detail(tf_main):
    from fastapi.testclient import TestClient

    tf_main.service.deploy_workload = MagicMock(return_value={"status": "FAILED", "error_class": "DESTROY_BLOCKED",
                                                              "error": "DESTROY_BLOCKED: x"})
    r = TestClient(tf_main.app).post("/deploy", json={"product_id": "app", "trace_id": "t1"})
    assert r.status_code == 500 and r.json()["detail"] == "Terraform deployment failed: DESTROY_BLOCKED: x"


def test_end_to_end_the_cc_reads_the_terraform_service_typed_500(tf_main, monkeypatch):
    """The real /deploy response object, fed to the Control Center's classifier."""
    from fastapi.testclient import TestClient

    tf_main.service.deploy_workload = MagicMock(return_value={"status": "FAILED", "error_class": "DESTROY_BLOCKED",
                                                              "error": "DESTROY_BLOCKED: x"})
    resp = TestClient(tf_main.app).post("/deploy", json={"product_id": "app", "refuse_destroy": True})
    wl, _, _ = _route(monkeypatch)
    failure = wl._express_deploy_failure(resp)
    assert failure["error_class"] == "DESTROY_BLOCKED" and failure["http_status"] == 500
    tf_main.service.deploy_workload = MagicMock(side_effect=RuntimeError("tofu crashed"))
    resp = TestClient(tf_main.app).post("/deploy", json={"product_id": "app", "refuse_destroy": True})
    failure = wl._express_deploy_failure(resp)
    assert failure["error_class"] == "EXPRESS_DEPLOY_FAILED" and failure["http_status"] == 500


def test_rt_m2_the_guard_catches_a_variable_needle():
    def mutant(detail):
        _needle = "LOCK"
        if _needle in detail:
            return "STATE_LOCKED"
        return None

    def legit(code):
        return code in ("A", "B")

    with pytest.raises(AssertionError):
        _assert_no_text_matching(mutant)
    _assert_no_text_matching(legit)
