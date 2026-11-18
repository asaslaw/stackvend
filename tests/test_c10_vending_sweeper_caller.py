"""C10 (RT finding 1): the sandbox-workload-sweeper-job persona is in vending's SANDBOX_TTL_CALLERS only.

POST /projects/{id}/decommission accepts DESTRUCTIVE_CALLERS + SANDBOX_TTL_CALLERS, and a caller that is only a TTL
caller may request action_class SANDBOX_TTL and nothing else. Every other destructive-class route (runner identity
mode, managed-tag backfill, sandbox lifecycle) keeps DESTRUCTIVE_CALLERS = the Control Center. Hermetic fakes only.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

import destructive_guard_fakes as f

AUD = "https://project-repo-vending-service-abc-uc.a.run.app"
SWEEPER = "sa-stackvend-sandbox-sweeper@mock-stackvend-project.iam.gserviceaccount.com"
TOKENS = {
    "cc": {"iss": "https://accounts.google.com", "aud": AUD, "email": f.CC_SA, "email_verified": True},
    "sweeper": {"iss": "https://accounts.google.com", "aud": AUD, "email": SWEEPER, "email_verified": True},
    "other": {"iss": "https://accounts.google.com", "aud": AUD, "email": f.OTHER_SA, "email_verified": True},
}
VENDING_MAIN = f.load_vending_main()


def fake_verifier(token, audiences):
    if token not in TOKENS:
        raise ValueError("bad token")
    return dict(TOKENS[token])


class _Storage:
    def bucket(self, name):
        class _Blob:
            def __init__(self, path):
                self.name = path

            def exists(self):
                return False

        class _Bucket:
            def blob(self, path):
                return _Blob(path)
        return _Bucket()


@pytest.fixture(autouse=True)
def _settings_without_firestore(monkeypatch):
    import importlib
    live = importlib.import_module("shared.settings")
    live.invalidate_settings_cache()
    monkeypatch.setattr(live, "get_platform_settings", lambda *a, **k: live.PlatformSettings())
    yield
    live.invalidate_settings_cache()


@pytest.fixture
def world(monkeypatch):
    vmain = VENDING_MAIN
    monkeypatch.setenv("DESTRUCTIVE_CALLERS", f.CC_SA)
    monkeypatch.setenv("SANDBOX_TTL_CALLERS", f"{f.CC_SA},{SWEEPER}")
    monkeypatch.setenv("VENDING_SERVICE_URL", AUD)
    monkeypatch.setenv("TEST_MODE", "true")   # must not bypass anything
    sdb, scrm = f.make_world(sandbox=True)
    ctx = f.make_ctx(sdb, scrm, ttl_callers=frozenset({f.CC_SA, SWEEPER}))
    ctx.dns = scrm
    eng = vmain.ProjectRepoVendingEngine(platform_project_id=f.HOST, firestore_client=sdb, crm_service=MagicMock(),
                                         storage_client=_Storage(), guard_context=ctx)
    eng.tfstate_bucket = "castor-tfstate-test"
    monkeypatch.setattr(vmain, "vending_engine", eng)
    monkeypatch.setattr(vmain, "CALLER_TOKEN_VERIFIER", fake_verifier)
    return sdb, scrm, TestClient(vmain.app)


def _h(token):
    return {"Authorization": f"Bearer {token}"}


def test_sweeper_decommissions_an_expired_sandbox(world):
    sdb, scrm, client = world
    r = client.post(f"/projects/{f.PID}/decommission", headers=_h("sweeper"), json={"action_class": "SANDBOX_TTL"})
    assert r.status_code == 200, r.text
    assert scrm.mutating_calls() == [("delete_project", f.NUMBER)]


def test_sweeper_may_not_request_a_project_decommission(world):
    sdb, scrm, client = world
    r = client.post(f"/projects/{f.PID}/decommission", headers=_h("sweeper"),
                    json={"action_class": "PROJECT_DECOMMISSION", "approval_id": f.APPROVAL})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "CALLER_NOT_ALLOWED"
    assert scrm.calls == []


@pytest.mark.parametrize("method, path, body", [
    ("GET", "/runner-identity/mode", None),
    ("POST", "/runner-identity/mode", {"mode": "PLATFORM"}),
    ("POST", "/guard/managed-tag/backfill", {}),
    ("POST", "/guard/cc-log-reader/backfill", {}),     # RT14-31 / D4
    ("POST", f"/projects/{f.PID}/lifecycle", {"action": "EXTEND", "ttl_days": 7}),
    ("GET", "/runner-identity/status", None),
])
def test_sweeper_is_not_a_destructive_caller_anywhere_else(world, method, path, body):
    sdb, scrm, client = world
    r = client.request(method, path, headers=_h("sweeper"), json=body)
    assert r.status_code == 403, (path, r.status_code, r.text)
    assert r.json()["detail"]["code"] == "CALLER_NOT_ALLOWED"
    assert scrm.mutating_calls() == []


def test_cc_keeps_both_classes_and_an_unlisted_caller_is_refused(world):
    sdb, scrm, client = world
    r = client.post(f"/projects/{f.PID}/decommission", headers=_h("other"), json={"action_class": "SANDBOX_TTL"})
    assert r.status_code == 403 and r.json()["detail"]["code"] == "CALLER_NOT_ALLOWED"
    r = client.post(f"/projects/{f.PID}/decommission", headers=_h("cc"), json={"action_class": "SANDBOX_TTL"})
    assert r.status_code == 200, r.text
