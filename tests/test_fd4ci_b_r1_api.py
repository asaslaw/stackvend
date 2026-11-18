"""FD-4CI-b-R1-API (owner 10-28): the workload create API refuses an explicit ``target_branch`` that is not a valid
branch name with 422, using the same typed check as Settings > Default GitHub Branch (``shared.settings.is_branch_name``,
which refuses ``HEAD``).

Entry points that take a caller-supplied branch:
* ``POST /api/workloads`` (form, API and Express share ``CreateWorkloadRequest``): explicit value checked, never
  rewritten; omitted / ``null`` / ``""`` keeps today's resolution (recorded branch -> setting -> main), and a recorded
  branch is never re-checked.
* ``POST /api/workloads/{pid}/deploy-to-folder`` (promotion; creates the branch in the repository): checked after the
  route's existing strip; empty after the strip is still "prod".
Unchanged (no caller branch reaches git or a workflow): retrigger and deploy-infra (a branch other than the recorded
one is already a 400) and the gateway intake (the Drive intake carries no branch; an event is forwarded unchanged).
Hermetic: in-memory fakes only (no Firestore, no network).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

TESTS = os.path.dirname(__file__)
REPO_ROOT = os.path.abspath(os.path.join(TESTS, ".."))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
GW_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (TESTS, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from shared import settings as S  # noqa: E402
from test_l19_11_access_intake import ADMIN_H, FakeDB, _client, _create, cc  # noqa: F401,E402  (cc: fixture)

VALID = ["main", "trunk", "develop", "release/1.0", "feature/a_b-c", "v2.1", "A1",
         "head", "Head", "HEADS", "feature/HEAD", "HEAD-1"]
# Every string shape test_fd4dj_wiring.test_other_values_are_not_branch_names refuses, except "" (absent on the API).
INVALID = ["HEAD", "@", " ", "main ", " main", "-x", "/x", "x/", "x.", "a..b", "a//b", ".hidden", "a/.b", "x.lock",
           "a/b.lock", "feat:x", "a b", "a'b", 'a"b', "a\nb", "ü", "a@{b", "x" * 101]
NOT_STRINGS = [1, True, ["main"], {"name": "main"}]
REFUSAL = "is not a valid Git branch name"


@pytest.fixture(autouse=True)
def _fresh_cache():
    S.invalidate_settings_cache()
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        yield
    S.invalidate_settings_cache()


def test_the_test_lists_match_the_shared_check():
    assert all(S.is_branch_name(v) for v in VALID)
    assert not any(S.is_branch_name(v) for v in INVALID + NOT_STRINGS)


def test_schema_uses_the_shared_check_not_a_copy(cc):
    schemas, _ = cc
    assert schemas.is_branch_name is __import__("shared.settings", fromlist=["x"]).is_branch_name


# ================================================================================================ create: schema
@pytest.mark.parametrize("name", VALID)
def test_schema_accepts_a_branch_name_as_sent(cc, name):
    schemas, _ = cc
    assert schemas.CreateWorkloadRequest(product_id="x", target_branch=name).target_branch == name


@pytest.mark.parametrize("absent", [None, ""])
def test_schema_leaves_an_absent_branch_absent(cc, absent):
    """Negative: omitted / null / "" are not checked and not changed (the route resolves them as before)."""
    schemas, _ = cc
    assert schemas.CreateWorkloadRequest(product_id="x", target_branch=absent).target_branch == absent
    assert schemas.CreateWorkloadRequest(product_id="x").target_branch is None


@pytest.mark.parametrize("bad", INVALID)
def test_schema_refuses_a_value_that_is_not_a_branch_name(cc, bad):
    schemas, _ = cc
    with pytest.raises(schemas.ValidationError) as ei:
        schemas.CreateWorkloadRequest(product_id="x", target_branch=bad)
    msg = str(ei.value)
    assert REFUSAL in msg and "HEAD" in msg and "Settings > Default GitHub Branch" in msg


# ================================================================================================ create: HTTP
def _record(fake_db):
    return fake_db.get("workloads/shop-app")


@pytest.mark.parametrize("bad", INVALID + NOT_STRINGS)
def test_create_refuses_an_invalid_branch_with_422_before_any_side_effect(cc, monkeypatch, bad):
    _, wl = cc
    r, fake_db, payload = _create(wl, monkeypatch, {"target_branch": bad})
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert any(d["loc"][-1] == "target_branch" for d in detail), detail
    if isinstance(bad, str):
        assert any(REFUSAL in d["msg"] for d in detail), detail
    assert _record(fake_db) is None and fake_db.writes == [] and payload is None


@pytest.mark.parametrize("bad", ["HEAD", "a b", "-x"])
def test_express_create_refuses_an_invalid_branch_with_422(cc, monkeypatch, bad):
    _, wl = cc
    calls = []
    monkeypatch.setattr(wl, "execute_express_provisioning", lambda **k: calls.append(k))
    r, fake_db, _ = _create(wl, monkeypatch, {"target_branch": bad, "creation_mode": "EXPRESS", "module_instances": [
        {"module_id": "compute-cloudrun", "instance_name": "api", "parameters": {}}]})
    assert r.status_code == 422, r.text
    assert calls == [] and _record(fake_db) is None


@pytest.mark.parametrize("name", ["staging", "release/1.0", "HEAD-1"])
def test_create_accepts_a_branch_name_and_records_it(cc, monkeypatch, name):
    _, wl = cc
    r, fake_db, payload = _create(wl, monkeypatch, {"target_branch": name})
    assert r.status_code == 200, r.text
    assert r.json()["default_branch"] == _record(fake_db)["default_branch"] == name
    assert payload["target_branch"] == payload["default_branch"] == name


@pytest.mark.parametrize("body", [{}, {"target_branch": None}, {"target_branch": ""}])
def test_create_without_a_branch_resolves_as_before(cc, monkeypatch, body):
    """Negative: an absent branch is the setting (default main) on a new workload, exactly as before."""
    _, wl = cc
    r, fake_db, payload = _create(wl, monkeypatch, body)
    assert r.status_code == 200, r.text
    assert _record(fake_db)["default_branch"] == payload["target_branch"] == "main"


@pytest.mark.parametrize("recorded", ["develop", "legacy branch", "HEAD"])
def test_recreate_without_a_branch_keeps_any_recorded_branch(cc, monkeypatch, recorded):
    """Existing recorded branches are untouched: a re-create without a branch keeps the stored value as it is, even
    one that would be refused as an explicit value (the API check applies only to what the caller sends)."""
    _, wl = cc
    initial = {"workloads/shop-app": {"product_id": "shop-app", "default_branch": recorded, "status": "ACTIVE"}}
    r, fake_db, payload = _create(wl, monkeypatch, {}, initial=initial)
    assert r.status_code == 200, r.text
    assert _record(fake_db)["default_branch"] == payload["target_branch"] == recorded


# ================================================================================================ promote (deploy-to-folder)
SRC = {"workloads/src-app": {"product_id": "src-app", "status": "ACTIVE", "github_repo": "example-org/src-app",
                             "default_branch": "main"}}


def _promote(wl, monkeypatch, branch):
    import folders

    monkeypatch.setattr(folders, "_default_get_folder", lambda name: {"name": name, "parent": "organizations/1"})
    monkeypatch.setattr(wl, "get_caller_main_module", lambda: SimpleNamespace())
    created = []
    monkeypatch.setattr(wl, "create_or_verify_branch", lambda **k: created.append(k))
    fake_db = FakeDB(SRC)
    client = _client(wl, monkeypatch, fake_db)
    publisher = MagicMock()
    publisher.publish.return_value.result.return_value = "msg-1"
    with patch.dict(os.environ, {"MANAGED_WORKLOADS_FOLDER_ID": "111111111111"}), \
         patch.object(wl, "get_pubsub_publisher", return_value=publisher), \
         patch.object(wl, "get_platform_settings", return_value=S.PlatformSettings()):
        r = client.post("/api/workloads/src-app/deploy-to-folder", headers=ADMIN_H,
                        json={"destination_folder_id": "folders/111111111111", "new_product_id": "src-app-prod",
                              "target_branch": branch})
    return r, fake_db, created


# The route strips the promotion branch (unchanged), so padded valid names ("main ") stay accepted there.
@pytest.mark.parametrize("bad", [b for b in INVALID if b.strip() and not S.is_branch_name(b.strip())]
                         + ["  a b  ", " HEAD "] + NOT_STRINGS)
def test_promote_refuses_an_invalid_branch_with_422_before_creating_it(cc, monkeypatch, bad):
    _, wl = cc
    r, fake_db, created = _promote(wl, monkeypatch, bad)
    assert r.status_code == 422, r.text
    if isinstance(bad, str):
        assert any(REFUSAL in d["msg"] for d in r.json()["detail"]), r.text
    assert created == [] and "workloads/src-app-prod" not in fake_db


@pytest.mark.parametrize("sent, branch", [("prod", "prod"), ("release/1.0", "release/1.0"), (" staging ", "staging"),
                                          ("", "prod"), ("   ", "prod")])
def test_promote_with_a_branch_name_or_nothing_behaves_as_before(cc, monkeypatch, sent, branch):
    """Negative: names accepted today (after the route's strip) and the empty value ("prod") are unchanged."""
    _, wl = cc
    r, fake_db, created = _promote(wl, monkeypatch, sent)
    assert r.status_code == 200, r.text
    assert [c["branch_name"] for c in created] == [branch]
    assert fake_db["workloads/src-app-prod"]["default_branch"] == branch


# ================================================================================================ unchanged entry points
def test_gateway_intake_forwards_the_event_branch_unchanged(monkeypatch):
    """Negative: the gateway intake is not changed (an existing workload's event, e.g. a retrigger carrying its
    recorded branch, is never refused for its branch here)."""
    from fd4g_support import load_module

    ip = load_module(monkeypatch, "r1api_intake_policy", os.path.join(GW_DIR, "intake_policy.py"))
    event = {"product_id": "shop-app", "source_channel": "control_center_form", "trace_id": "t-1",
             "target_branch": "legacy branch"}
    assert ip.validate_intake(dict(event)) == event
