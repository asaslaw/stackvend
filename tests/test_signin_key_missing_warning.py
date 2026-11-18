"""FD-55 W3 / AQ-3 review follow-up F3: a PUBLIC_APP deploy whose web sign-in key could not be created or read carries
a typed SIGNIN_KEY_MISSING warning in its deploy result (a warning, never a failure: the deploy goes on with
firebase_api_key "" exactly as before).

Negative tests (Do No Harm): a PUBLIC_APP deploy that gets its key, and every non-public deploy (no key is asked for),
return no `warnings` key; a result without warnings is returned as the same object.

Hermetic: the cloud fakes of tests/test_fd4aq_w1_no_host_secret.py (no repo fetch, no ADC, no network); every OpenTofu
command is a fake that "times out" at once (AQ-5), so the deploy returns its FAILED result without running anything.
"""
import hermetic_guard  # noqa: F401  (first import)

import logging

import pytest

from test_fd4aq_w1_no_host_secret import (  # noqa: F401  (fixture `tf` reused by name)
    PROJECT, PUBLIC, _Cloud, _db, _fake_cloud, _Resp, _service, tf)

_TIMEOUT_MESSAGE = "TOFU_TIMEOUT: test engine stopped here"


class _NoKeyString(_Cloud):
    """The key exists but its key string cannot be read (403)."""

    def respond(self, method, url, body=None):
        if url.endswith("/keyString"):
            self.calls.append((method, url, body))
            return _Resp(403, {})
        return super().respond(method, url, body)


class _NoCreate(_Cloud):
    """No `stackvend-web` key and its creation is refused (403)."""

    def respond(self, method, url, body=None):
        if url.endswith("/keys/stackvend-web") and method == "GET":
            self.calls.append((method, url, body))
            return _Resp(404, {})
        if "/keys?keyId=stackvend-web" in url and method == "POST":
            self.calls.append((method, url, body))
            return _Resp(403, {})
        return super().respond(method, url, body)


def _deploy(tf, monkeypatch, tmp_path, db, cloud):
    _fake_cloud(monkeypatch, cloud)
    svc = _service(tf, monkeypatch, tmp_path, db)

    def _timed_out(*a, **k):   # every OpenTofu command "times out" (AQ-5): nothing more runs, the deploy returns
        slot = svc._tofu_timeout_slot()
        slot.message = getattr(slot, "message", None) or _TIMEOUT_MESSAGE
        return svc._tofu_timeout_result(slot.message)

    monkeypatch.setattr(svc, "_run_subprocess", _timed_out)
    return svc.deploy_workload(product_id="shop", trace_id="t-f3", target_project_id=PROJECT, branch="main",
                               iac_engine="OPENTOFU")


@pytest.mark.parametrize("cloud_cls", [_NoKeyString, _NoCreate], ids=["key-string-unreadable", "create-refused"])
def test_public_deploy_without_its_key_carries_the_typed_warning(tf, monkeypatch, tmp_path, caplog, cloud_cls):
    caplog.set_level(logging.WARNING, logger="mcp-terraform-server")
    res = _deploy(tf, monkeypatch, tmp_path, _db(PUBLIC), cloud_cls())
    assert (res["status"], res["error_class"]) == ("FAILED", "TOFU_TIMEOUT")   # unchanged by the warning
    assert res["warnings"] == [{
        "code": "SIGNIN_KEY_MISSING",
        "message": f"SIGNIN_KEY_MISSING: the web sign-in key 'stackvend-web' of project '{PROJECT}' could not be "
                   f"created or read (the deploy log names the step). The public app was deployed without it, so its "
                   f"Google sign-in does not work until a later deploy gets the key."}]
    assert sum("SIGNIN_KEY_MISSING" in r.getMessage() for r in caplog.records) == 1


def test_public_deploy_with_its_key_has_no_warnings(tf, monkeypatch, tmp_path):
    res = _deploy(tf, monkeypatch, tmp_path, _db(PUBLIC), _Cloud())
    assert res["status"] == "FAILED" and "warnings" not in res


@pytest.mark.parametrize("record", [{"project_id": PROJECT, "access": {"mode": "PRIVATE_IAP"}},
                                    {"project_id": PROJECT}], ids=["private", "no-record"])
def test_non_public_deploy_has_no_warnings(tf, monkeypatch, tmp_path, record):
    cloud = _NoKeyString()
    res = _deploy(tf, monkeypatch, tmp_path, _db(record), cloud)
    assert cloud.hosts("apikeys.googleapis.com") == []        # no key is asked for, so none can be missing
    assert "warnings" not in res


def test_a_result_without_warnings_is_the_same_object(tf):
    result = {"status": "SUCCESS", "service_url": "https://x"}
    assert tf.TerraformService._with_deploy_warnings(result, {}) is result
    assert tf.TerraformService._with_deploy_warnings(result, {"warnings": []}) is result
    w = {"code": "SIGNIN_KEY_MISSING", "message": "m"}
    out = tf.TerraformService._with_deploy_warnings(result, {"warnings": [w]})
    assert out == {"status": "SUCCESS", "service_url": "https://x", "warnings": [w]} and "warnings" not in result
