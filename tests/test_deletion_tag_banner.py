"""
DELETION-TAG-BANNER (owner 11-11): the missing deletion-safety tag is impossible to miss in the Control Center.

routes/install_status.py derives ONE state from the same typed Settings cards (MANAGED_TAG_NOT_SET_UP,
MANAGED_TAG_BACKFILL_PENDING, GUARD_STATUS_UNAVAILABLE) and gives it to every signed-in user:
- GET /api/deletion-safety/status (AUTHENTICATED; no project lists, no organization id), cached 60 s per instance;
- install-warnings (ADMIN) carries the same object as `deletion_safety`, so an admin page load reads vending once.
NOT_SET_UP -> warning banner + a note on the new-workload forms; BACKFILL_PENDING -> a lighter banner; SET_UP (vending
confirmed the tag) -> nothing; vending unavailable or malformed -> a neutral "Couldn't check" banner, never SET_UP.
The dashboard renders the server's texts and treats any unexpected answer as "couldn't check" (static checks: no JS
engine in the hermetic suite). FastAPI TestClient on the real router with the authz dependency; vending is a fake.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(BASE_DIR, "apps", "control-center")
for _p in (BASE_DIR, CC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_saved_client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
os.environ["GOOGLE_OAUTH_CLIENT_ID"] = "deletion-tag-banner-test.apps.googleusercontent.com"
try:
    from routes import install_status as ist  # noqa: E402
finally:
    if _saved_client_id is None:
        os.environ.pop("GOOGLE_OAUTH_CLIENT_ID", None)
    else:
        os.environ["GOOGLE_OAUTH_CLIENT_ID"] = _saved_client_id

PROJ = "mock-stackvend-project"
ORG = "organizations/111111111111"
DASHBOARD = Path(CC_DIR) / "templates" / "dashboard.html"
STATUS = "/api/deletion-safety/status"
WARNINGS = "/api/settings/install-warnings"

CANNOT_DELETE = ("StackVend can't delete or decommission the projects it creates until an organization Tag "
                 "Administrator (roles/resourcemanager.tagAdmin) re-runs apply.sh apply.")


class _Resp:
    def __init__(self, status, body):
        self.status_code, self._b, self.text = status, body, str(body)

    def json(self):
        return self._b


class FakeVending:
    def __init__(self, status=None, status_code=200, backfill=None):
        self.status, self.status_code, self.backfill, self.calls = status, status_code, backfill, []

    def __call__(self, method, path, json_body=None, timeout=60.0, request=None):
        self.calls.append((method, path))
        if path == "/guard/managed-tag":
            return _Resp(self.status_code, self.status)
        if path == "/guard/managed-tag/backfill":
            return _Resp(200, self.backfill or {"results": [], "counts": {}, "truncated": False})
        raise AssertionError(path)


def _status(configured, untagged=(), candidates=()):
    return {"tag_configured": configured, "managed_tag_value": "tagValues/7" if configured else None,
            "managed_folder_configured": True, "organization_id": ORG,
            "required_role": "roles/resourcemanager.tagAdmin", "vended_projects": [],
            "untagged_vended": [{"product_id": p, "project_id": f"{p}-a1b2"} for p in untagged],
            "backfill_candidates": list(candidates), "unprovenanced_workloads": [], "truncated": False}


@pytest.fixture
def make_client(monkeypatch):
    monkeypatch.setattr(ist, "PROJECT_ID", PROJ)
    monkeypatch.setattr(ist, "billing_status_provider", lambda request: {"configured": False})
    ist.clear_deletion_safety_cache()

    def _make(vending, role="ADMIN"):
        monkeypatch.setattr(ist, "vending_requester", vending)
        app = FastAPI()

        @app.middleware("http")
        async def _auth(request: Request, call_next):
            request.state.user_email, request.state.user_role, request.state.auth_method = "u@example.com", role, "iap"
            return await call_next(request)

        app.include_router(ist.router)
        return TestClient(app)
    yield _make
    ist.clear_deletion_safety_cache()


def _get(client, path=STATUS):
    r = client.get(path)
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------- server: state + texts
def test_not_set_up_banner_for_admin_and_viewer(make_client):
    v = FakeVending(_status(False, untagged=("shop-api",)))
    admin = _get(make_client(v, role="ADMIN"))
    assert admin["state"] == "NOT_SET_UP"
    assert admin["banner"] == {"level": "warning", "title": "Deletion safety is not set up",
                               "message": f"{CANNOT_DELETE} Details in Settings."}
    assert admin["form_note"] == ("Deletion safety is not set up: StackVend can't delete or decommission the project "
                                  "this creates until an organization Tag Administrator re-runs apply.sh apply. You "
                                  "can still submit.")
    ist.clear_deletion_safety_cache()
    viewer = _get(make_client(v, role="VIEWER"))
    assert viewer["state"] == "NOT_SET_UP" and viewer["banner"]["level"] == "warning"
    assert viewer["banner"]["message"] == (f"{CANNOT_DELETE} Ask an administrator to fix it; the details are in "
                                           "Settings.")
    # Every signed-in role, and nothing about projects or the organization leaks to non-admins.
    assert set(viewer) == {"state", "pending_count", "banner", "form_note"}
    assert "shop-api" not in str(viewer) and ORG not in str(viewer)
    assert _get(make_client(v, role="WORKLOAD_MANAGER"))["state"] == "NOT_SET_UP"


def test_backfill_pending_is_a_lighter_banner_and_no_form_note(make_client):
    v = FakeVending(_status(True, untagged=("shop-api", "blog", "byo"), candidates=("shop-api", "blog")))
    admin = _get(make_client(v))
    assert admin["state"] == "BACKFILL_PENDING" and admin["pending_count"] == 2
    assert admin["banner"]["level"] == "notice"
    assert admin["banner"]["message"] == ("2 project(s) created before the deletion safety tag existed are untagged, "
                                          "so StackVend can't decommission them yet. Tag them with one click in "
                                          "Settings (Bind deletion safety tag).")
    assert admin["form_note"] is None  # new projects get the tag at vend time
    ist.clear_deletion_safety_cache()
    viewer = _get(make_client(v, role="VIEWER"))
    assert viewer["banner"]["message"].endswith("Ask an administrator to tag them; the button is in Settings.")


def test_set_up_shows_nothing(make_client):
    body = _get(make_client(FakeVending(_status(True))))
    assert body == {"state": "SET_UP", "pending_count": 0, "banner": None, "form_note": None}


@pytest.mark.parametrize("vending", [
    FakeVending({"detail": {"code": "CALLERS_UNCONFIGURED", "detail": "x"}}, status_code=503),
    lambda **kw: None,                                                   # VENDING_SERVICE_URL unset
    lambda **kw: (_ for _ in ()).throw(RuntimeError("down")),            # unreachable
    FakeVending(["not", "an", "object"]),                                # malformed body
    FakeVending({**_status(False), "untagged_vended": "shop-api"}),      # contract drift (RT F3)
    FakeVending({**_status(True), "backfill_candidates": "shop-api"}),   # contract drift on a tagged install
])
def test_unavailable_or_malformed_is_neutral_never_set_up(make_client, vending):
    for role in ("ADMIN", "VIEWER"):
        ist.clear_deletion_safety_cache()
        body = _get(make_client(vending, role=role))
        assert body["state"] == "UNAVAILABLE"
        assert body["banner"]["level"] == "neutral"
        assert body["banner"]["title"] == "Couldn't check deletion safety status"
        assert "can't say whether StackVend can delete" in body["banner"]["message"]
        assert body["form_note"].startswith("Couldn't check deletion safety status")


def test_install_warnings_carries_the_same_state_with_one_vending_call(make_client):
    v = FakeVending(_status(False, untagged=("shop-api",)))
    body = _get(make_client(v), WARNINGS)
    assert [w["code"] for w in body["warnings"]] == ["MANAGED_TAG_NOT_SET_UP"]
    assert body["deletion_safety"]["state"] == "NOT_SET_UP"
    assert body["deletion_safety"]["banner"]["message"] == f"{CANNOT_DELETE} Details in Settings."
    assert v.calls == [("GET", "/guard/managed-tag")]
    bad = _get(make_client(lambda **kw: None), WARNINGS)
    assert [w["code"] for w in bad["warnings"]] == ["GUARD_STATUS_UNAVAILABLE"]
    assert bad["deletion_safety"]["state"] == "UNAVAILABLE"


def test_status_is_cached_but_unavailable_is_retried_and_backfill_clears(make_client):
    v = FakeVending(_status(False))
    c = make_client(v, role="VIEWER")
    assert _get(c)["state"] == "NOT_SET_UP" and _get(c)["state"] == "NOT_SET_UP"
    assert v.calls == [("GET", "/guard/managed-tag")]  # second page load served from the cache
    # An unavailable answer is never cached: the next page load asks vending again.
    ist.clear_deletion_safety_cache()
    down = FakeVending({"detail": {"code": "X", "detail": "y"}}, status_code=503)
    c = make_client(down, role="VIEWER")
    assert _get(c)["state"] == "UNAVAILABLE" and _get(c)["state"] == "UNAVAILABLE"
    assert len(down.calls) == 2
    # An admin's fresh install-warnings read refreshes the cache; the backfill clears it.
    ok = FakeVending(_status(True))
    admin = make_client(ok)
    assert _get(admin, WARNINGS)["deletion_safety"]["state"] == "SET_UP"
    assert _get(admin)["state"] == "SET_UP" and ok.calls == [("GET", "/guard/managed-tag")]
    assert admin.post("/api/settings/managed-tag/backfill").status_code == 200
    assert _get(admin)["state"] == "SET_UP"
    assert ok.calls.count(("GET", "/guard/managed-tag")) == 2


class BlockingVending(FakeVending):
    """Holds every vending read until `release` is set (a slow managed-tag scan)."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.release, self.entered = threading.Event(), threading.Event()

    def __call__(self, method, path, json_body=None, timeout=60.0, request=None):
        self.entered.set()
        assert self.release.wait(10)
        return super().__call__(method, path, json_body, timeout, request)


def _viewer_request():
    return SimpleNamespace(state=SimpleNamespace(user_email="u@example.com", user_role="VIEWER", auth_method="iap"))


def _concurrent_reads(n=8):
    results = []
    lock = threading.Lock()

    def _one():
        body = ist.get_deletion_safety_status_api(_viewer_request())
        with lock:
            results.append(body["state"])
    threads = [threading.Thread(target=_one) for _ in range(n)]
    for t in threads:
        t.start()
    return threads, results


@pytest.mark.parametrize("status,status_code,state", [
    (_status(False), 200, "NOT_SET_UP"),
    ({"detail": {"code": "X", "detail": "y"}}, 503, "UNAVAILABLE"),
])
def test_concurrent_misses_make_one_vending_call(make_client, monkeypatch, status, status_code, state):
    """RT F1: a slow scan is single-flighted; requests queued behind it reuse its answer (UNAVAILABLE included, for
    that round only: the next page load asks vending again)."""
    v = BlockingVending(status, status_code=status_code)
    monkeypatch.setattr(ist, "vending_requester", v)
    threads, results = _concurrent_reads(8)
    assert v.entered.wait(5)
    time.sleep(0.3)  # let the other requests queue behind the in-flight read
    v.release.set()
    for t in threads:
        t.join(10)
    assert results == [state] * 8
    assert v.calls == [("GET", "/guard/managed-tag")]
    ist.get_deletion_safety_status_api(_viewer_request())
    assert len(v.calls) == (1 if state != "UNAVAILABLE" else 2)  # UNAVAILABLE is never cached across page loads


def test_cache_entry_is_stamped_before_the_vending_call(make_client, monkeypatch):
    """RT F2: the 60 s bound counts from before the (possibly slow) read."""
    clock = {"t": 1000.0}
    monkeypatch.setattr(ist, "time", SimpleNamespace(monotonic=lambda: clock["t"]))

    def slow(method, path, json_body=None, timeout=60.0, request=None):
        clock["t"] += 50.0
        return FakeVending(_status(False))(method, path, json_body, timeout, request)
    monkeypatch.setattr(ist, "vending_requester", slow)
    ist.get_deletion_safety_status_api(_viewer_request())
    clock["t"] += 11.0  # 61 s after the read started, 11 s after it returned
    assert ist._ds_cache_get() is None


def test_backfill_clears_after_vending_returns_and_drops_in_flight_reads(make_client, monkeypatch):
    """RT F3: a status read during the backfill cannot re-cache the pre-backfill state."""
    pre = _status(True, untagged=("shop-api",), candidates=("shop-api",))
    admin = make_client(FakeVending(pre))

    def backfill_with_concurrent_read(method, path, json_body=None, timeout=60.0, request=None):
        if path == "/guard/managed-tag/backfill":
            # A viewer page load lands while vending is binding tags: it sees (and would cache) the old state.
            assert ist.get_deletion_safety_status_api(_viewer_request())["state"] == "BACKFILL_PENDING"
            return _Resp(200, {"results": [], "counts": {"TAGGED": 1}, "truncated": False})
        return _Resp(200, pre)
    monkeypatch.setattr(ist, "vending_requester", backfill_with_concurrent_read)
    assert admin.post("/api/settings/managed-tag/backfill").status_code == 200
    assert ist._ds_cache_get() is None
    # A read that started before a clear never writes its answer back.
    epoch, started = ist._ds_epoch_now(), time.monotonic()
    ist.clear_deletion_safety_cache()
    ist._ds_cache_put("SET_UP", 0, started, epoch)
    assert ist._ds_cache_get() is None


def test_dashboard_status_reads_time_out_to_couldnt_check():
    """RT F5: a hung read is aborted after 45 s; the callers' catch sets the "couldn't check" state."""
    html = _html()
    timed = _js_block(html, "async fetchDeletionSafetyTimed(url) {")
    assert "new AbortController()" in timed and "setTimeout(() => ctrl.abort(), 45000)" in timed
    assert "fetch(url, { signal: ctrl.signal })" in timed and "clearTimeout(timer)" in timed
    assert "this.fetchDeletionSafetyTimed('/api/settings/install-warnings')" in _js_block(
        html, "async fetchInstallWarnings() {")


def test_unknown_state_is_unavailable():
    assert ist.deletion_safety("SOMETHING_ELSE", 3, True)["state"] == "UNAVAILABLE"


def test_status_route_needs_a_signed_in_user(make_client):
    app = FastAPI()
    app.include_router(ist.router)
    assert TestClient(app).get(STATUS).status_code == 401


# ---------------------------------------------------------------- dashboard (static)
def _html():
    return DASHBOARD.read_text(encoding="utf-8")


def _js_block(html, start, end_marker="\n                },\n"):
    i = html.index(start)
    return html[i:html.index(end_marker, i) + len(end_marker)]


def test_dashboard_banner_is_global_and_renders_server_text():
    html = _html()
    banner = html[html.index("<!-- DELETION-TAG-BANNER (owner 11-11)"):html.index("<!-- Top Navigation Header -->")]
    # Above the header, outside every tab section: shown on every page.
    assert html.index("data-deletion-safety-banner") < html.index("<header")
    assert '<template x-if="deletionSafetyBanner">' in banner
    assert 'x-text="deletionSafetyBanner.title"' in banner and 'x-text="deletionSafetyBanner.message"' in banner
    assert "deletionSafetyBanner.level === 'warning'" in banner and "deletionSafetyBanner.level === 'notice'" in banner
    # Admins jump to the Settings card; the collapse is per session and has no "dismiss forever".
    assert "userRole === 'ADMIN' && !deletionSafetyCollapsed\" @click=\"openDeletionSafetySettings()\"" in banner
    assert "Hide for this session" in banner and "localStorage" not in banner
    jump = _js_block(html, "openDeletionSafetySettings() {")
    assert "this.activeTab = 'settings'" in jump and "this.settingsTab = 'params'" in jump
    assert '[data-install-warning="MANAGED_TAG_NOT_SET_UP"]' in jump
    toggle = _js_block(html, "toggleDeletionSafetyBanner() {")
    assert "sessionStorage" in toggle and "localStorage" not in toggle


def test_dashboard_unexpected_answer_is_couldnt_check_never_all_good():
    html = _html()
    setter = _js_block(html, "setDeletionSafety(ds) {")
    assert "states.includes(ds.state)" in setter
    assert "ds.state === 'SET_UP' ? ds.banner === null : text(ds.banner)" in setter
    assert "this.deletionSafety.failed = !ok;" in setter
    getter = _js_block(html, "get deletionSafetyBanner() {")
    assert "if (d.failed) return { level: 'neutral', title: \"Couldn't check deletion safety status\"" in getter
    # Every failed read path marks the status failed (no silent "nothing to show").
    load = _js_block(html, "async loadDeletionSafety() {")
    assert "this.fetchDeletionSafetyTimed('/api/deletion-safety/status')" in load
    assert "this.setDeletionSafety(res.ok ? await res.json() : null)" in load
    assert "this.setDeletionSafety(null);" in load
    warn = _js_block(html, "async fetchInstallWarnings() {")
    assert "this.setDeletionSafety(data.deletion_safety);" in warn and warn.count("this.setDeletionSafety(null);") == 2


def test_dashboard_reads_the_status_once_per_page_load():
    html = _html()
    init = _js_block(html, "async init() {", "\n                    // Periodic poll")
    assert init.count("this.loadDeletionSafety();") == 1
    assert "fetchInstallWarnings" not in init  # admins: loadDeletionSafety IS the install-warnings read
    assert "if (this.userRole === 'ADMIN') return this.fetchInstallWarnings();" in _js_block(
        html, "async loadDeletionSafety() {")


def test_dashboard_submit_forms_carry_the_inline_note():
    html = _html()
    assert html.count("data-deletion-safety-form-note") == 2
    for modal_close in ("showNewWorkloadModal = false", "showDeployToFolderModal = false"):
        footer = html.index(f'<button type="button" @click="{modal_close}" class="px-4 py-2')
        note = html.rindex("data-deletion-safety-form-note", 0, footer)
        assert footer - note < 800  # right above the submit row
        assert 'x-show="deletionSafetyFormNote"' in html[note - 200:note]
    getter = _js_block(html, "get deletionSafetyFormNote() {")
    assert "if (d.failed) return \"Couldn't check deletion safety status" in getter
