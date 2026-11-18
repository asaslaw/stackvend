"""
Lane 18 v3 (owner rule 10-18) in the Control Center: Settings shows warnings instead of the install failing.

(b) MANAGED_TAG_NOT_SET_UP: "Deletion safety tag not set up: StackVend cannot decommission projects until a Tag
    Administrator re-runs apply.sh apply", the exact role and organization, and the StackVend-vended projects that are
    untagged (from vending's GET /guard/managed-tag, called with the CC's own identity);
(c) MANAGED_TAG_BACKFILL_PENDING + the admin action POST /api/settings/managed-tag/backfill (executed by vending);
    workloads without provenance are only listed;
(d) CC_BILLING_VIEWER_MISSING (old install step A4): the exact gcloud command for the CC service account.
FastAPI TestClient on the real router with the authz dependency; vending and the billing probe are test doubles.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
from pathlib import Path

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(BASE_DIR, "apps", "control-center")
for _p in (BASE_DIR, CC_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

_saved_client_id = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
os.environ["GOOGLE_OAUTH_CLIENT_ID"] = "lane18-v3-test.apps.googleusercontent.com"
try:
    from routes import install_status as ist  # noqa: E402
finally:
    if _saved_client_id is None:
        os.environ.pop("GOOGLE_OAUTH_CLIENT_ID", None)
    else:
        os.environ["GOOGLE_OAUTH_CLIENT_ID"] = _saved_client_id

PROJ = "mock-stackvend-project"
ORG = "organizations/111111111111"
ADMIN = "owner@example.com"


class _Resp:
    def __init__(self, status, body):
        self.status_code, self._b, self.text = status, body, str(body)

    def json(self):
        return self._b


class FakeVending:
    def __init__(self, status=None, backfill=None, status_code=200):
        self.status, self.backfill, self.status_code, self.calls = status, backfill, status_code, []

    def __call__(self, method, path, json_body=None, timeout=60.0, request=None):
        self.calls.append((method, path, json_body))
        if path == "/guard/managed-tag":
            return _Resp(self.status_code, self.status)
        if path == "/guard/managed-tag/backfill":
            return _Resp(200, self.backfill) if self.backfill is not None else _Resp(
                503, {"detail": {"code": "GUARD_UNCONFIGURED", "detail": "tag not set up"}})
        raise AssertionError(path)


def _status(configured, untagged=(), candidates=(), unprov=(), org=ORG, folder=True):
    return {"tag_configured": configured, "managed_tag_value": "tagValues/7" if configured else None,
            "managed_folder_configured": folder, "organization_id": org,
            "required_role": "roles/resourcemanager.tagAdmin",
            "vended_projects": [], "untagged_vended": [{"product_id": p, "project_id": f"{p}-a1b2"} for p in untagged],
            "backfill_candidates": list(candidates),
            "unprovenanced_workloads": [{"product_id": p, "project_id": f"{p}-x"} for p in unprov], "truncated": False}


def _billing(configured=True, access=True, account="01ABCD-23EF45-6789AB"):
    return {"configured": configured, "has_billing_access": access, "billing_account_id": account}


@pytest.fixture
def make_client(monkeypatch):
    monkeypatch.setattr(ist, "PROJECT_ID", PROJ)

    def _make(vending, billing=None, role="ADMIN"):
        monkeypatch.setattr(ist, "vending_requester", vending)
        monkeypatch.setattr(ist, "billing_status_provider", lambda request: billing or _billing())
        app = FastAPI()

        @app.middleware("http")
        async def _auth(request: Request, call_next):
            request.state.user_email, request.state.user_role, request.state.auth_method = ADMIN, role, "iap"
            return await call_next(request)

        app.include_router(ist.router)
        return TestClient(app)
    return _make


def _by_code(resp):
    assert resp.status_code == 200, resp.text
    return {w["code"]: w for w in resp.json()["warnings"]}


def test_tag_not_set_up_card_names_role_org_and_untagged_projects(make_client):
    v = FakeVending(_status(False, untagged=("shop-api", "blog")))
    w = _by_code(make_client(v).get("/api/settings/install-warnings"))["MANAGED_TAG_NOT_SET_UP"]
    assert w["message"].startswith("Deletion safety tag not set up: StackVend cannot decommission projects until "
                                   "a Tag Administrator re-runs apply.sh apply")
    assert w["role"] == "roles/resourcemanager.tagAdmin" and w["organization_id"] == ORG
    assert ORG in w["message"]
    assert w["fix"] == ["gcloud organizations add-iam-policy-binding 111111111111 --member=user:<TAG_ADMIN_EMAIL> "
                        "--role=roles/resourcemanager.tagAdmin", f"PROJECT_ID={PROJ} bash scripts/apply.sh apply"]
    assert [p["product_id"] for p in w["projects"]] == ["shop-api", "blog"]
    assert w["fix_where"] == _apply_where(PROJ)  # CC-APPLY-WHERE: a note under the commands, never a command
    assert "action" not in w  # nothing to run until the tag exists
    assert v.calls == [("GET", "/guard/managed-tag", None)]


def test_tag_not_set_up_without_organization_says_what_to_set(make_client):
    w = _by_code(make_client(FakeVending(_status(False, org="", folder=False))).get(
        "/api/settings/install-warnings"))["MANAGED_TAG_NOT_SET_UP"]
    assert "organization_id and castor_managed_workloads_folder_id must be set" in w["message"]
    assert w["fix"] == [f"PROJECT_ID={PROJ} bash scripts/apply.sh apply"]
    assert w["fix_where"] == _apply_where(PROJ)


def _apply_where(project):
    return ("Run it from the root of the StackVend folder you installed from: it holds "
            f"infra/platform/{project}.tfvars (keep a copy; the installer's last step prints the command to back it "
            f"up to gs://castor-tfstate-{project}/platform/).")


def test_apply_where_sentence_and_dashboard_render():
    """CC-APPLY-WHERE (owner 11-03): every Control Center apply.sh fix says where to run it (wording only)."""
    import config
    assert config.apply_where(PROJ) == _apply_where(PROJ)
    assert config.apply_where("") == _apply_where("<project_id>")
    html = (Path(__file__).resolve().parents[1] / "apps/control-center/templates/dashboard.html").read_text()
    card = html[html.index("<!-- Lane 18 v3: install warnings"):]
    card = card[:card.index("</template>", card.index('x-for="cmd in (w.fix || [])"') + 1) + 400]
    assert 'x-show="w.fix_where" x-text="w.fix_where"' in card
    assert 'x-text="upgrades.version?.platform?.apply_where"' in html
    assert 'x-text="upgrades.upgrade?.button?.apply_where"' in html


def test_tag_configured_with_pending_backfill_offers_the_action(make_client):
    st = _status(True, untagged=("shop-api", "legacy"), candidates=("shop-api",), unprov=("byo",))
    codes = _by_code(make_client(FakeVending(st)).get("/api/settings/install-warnings"))
    assert "MANAGED_TAG_NOT_SET_UP" not in codes
    pend = codes["MANAGED_TAG_BACKFILL_PENDING"]
    assert [p["product_id"] for p in pend["projects"]] == ["shop-api"]  # only vending's candidates
    assert pend["action"] == {"method": "POST", "path": "/api/settings/managed-tag/backfill",
                              "label": "Bind deletion safety tag"}
    unprov = codes["PROJECTS_WITHOUT_PROVENANCE"]
    assert unprov["severity"] == "info" and [p["product_id"] for p in unprov["projects"]] == ["byo"]
    assert "action" not in unprov  # never tagged automatically


def test_all_set_up_shows_nothing(make_client):
    r = make_client(FakeVending(_status(True))).get("/api/settings/install-warnings")
    assert _by_code(r) == {}


def test_vending_unavailable_is_a_warning_not_an_error(make_client):
    v = FakeVending({"detail": {"code": "CALLERS_UNCONFIGURED", "detail": "x"}}, status_code=503)
    w = _by_code(make_client(v).get("/api/settings/install-warnings"))["GUARD_STATUS_UNAVAILABLE"]
    assert "CALLERS_UNCONFIGURED" in w["message"] and "deletes stay refused" in w["message"]
    for broken in (lambda **kw: None, lambda **kw: (_ for _ in ()).throw(RuntimeError("down"))):
        codes = _by_code(make_client(broken).get("/api/settings/install-warnings"))
        assert "GUARD_STATUS_UNAVAILABLE" in codes


def test_cc_billing_viewer_missing_gives_the_exact_fix(make_client):
    codes = _by_code(make_client(FakeVending(_status(True)), billing=_billing(access=False)).get(
        "/api/settings/install-warnings"))
    w = codes["CC_BILLING_VIEWER_MISSING"]
    member = f"serviceAccount:sa-stackvend-control-center@{PROJ}.iam.gserviceaccount.com"
    assert w["member"] == member and w["role"] == "roles/billing.viewer"
    assert w["fix"] == [f"gcloud billing accounts add-iam-policy-binding 01ABCD-23EF45-6789AB --member={member} "
                        "--role=roles/billing.viewer"]
    # No billing account configured, or access present: no card.
    for b in (_billing(configured=False, access=False), _billing(access=True)):
        assert "CC_BILLING_VIEWER_MISSING" not in _by_code(
            make_client(FakeVending(_status(True)), billing=b).get("/api/settings/install-warnings"))


def test_backfill_action_goes_through_vending_with_the_admin(make_client):
    v = FakeVending(_status(True), backfill={"results": [], "counts": {"TAGGED": 2}, "truncated": False})
    r = make_client(v).post("/api/settings/managed-tag/backfill")
    assert r.status_code == 200 and r.json()["counts"] == {"TAGGED": 2}
    assert v.calls == [("POST", "/guard/managed-tag/backfill", {"operator_email": ADMIN})]


def test_backfill_refusal_is_surfaced_as_502(make_client):
    r = make_client(FakeVending(_status(False))).post("/api/settings/managed-tag/backfill")
    assert r.status_code == 502 and r.json()["code"] == "GUARD_UNCONFIGURED"


def test_expired_sandboxes_are_listed_for_the_owner_never_as_will_be_tagged(make_client):
    """RT F2: vending excludes expired auto-delete sandboxes from the candidates; the CC shows them, no action."""
    st = _status(True, untagged=("shop-api", "old-sbx"), candidates=("shop-api",))
    st["sandbox_expired_untagged"] = [{"product_id": "old-sbx", "project_id": "old-sbx-a1b2"}]
    codes = _by_code(make_client(FakeVending(st)).get("/api/settings/install-warnings"))
    assert [p["product_id"] for p in codes["MANAGED_TAG_BACKFILL_PENDING"]["projects"]] == ["shop-api"]
    exp = codes["MANAGED_TAG_SANDBOXES_EXPIRED"]
    assert exp["severity"] == "info" and "action" not in exp
    assert [p["product_id"] for p in exp["projects"]] == ["old-sbx"]
    assert "owner decision" in exp["projects_label"]


@pytest.mark.parametrize("drift", [
    {"organization_id": "111111111111"},            # no "organizations/" prefix (RT F3 crash 1)
    {"untagged_vended": ["not-a-dict"]},            # non-dict entry (RT F3 crash 2)
    {"untagged_vended": "shop-api"},
    {"backfill_candidates": "shop-api"},
    {"unprovenanced_workloads": [1, 2]},
    {"organization_id": 42},
    {"sandbox_expired_untagged": {"a": 1}},
])
def test_vending_contract_drift_never_500s(make_client, drift):
    st = {**_status(False, untagged=("shop-api",)), **drift}
    r = make_client(FakeVending(st)).get("/api/settings/install-warnings")
    assert r.status_code == 200
    codes = _by_code(r)
    if drift == {"organization_id": "111111111111"}:
        # Not a crash any more: the malformed org is simply not offered as a command target.
        w = codes["MANAGED_TAG_NOT_SET_UP"]
        assert w["organization_id"] == "" and "must be set" in w["message"]
    else:
        assert "GUARD_STATUS_UNAVAILABLE" in codes
    # Same drift on an install that has the tag.
    st2 = {**_status(True, untagged=("shop-api",), candidates=("shop-api",)), **drift}
    assert make_client(FakeVending(st2)).get("/api/settings/install-warnings").status_code == 200


def test_truncated_scan_is_shown_on_the_card(make_client):
    st = {**_status(False, untagged=("shop-api",)), "truncated": True, "max_records": 200}
    w = _by_code(make_client(FakeVending(st)).get("/api/settings/install-warnings"))["MANAGED_TAG_NOT_SET_UP"]
    assert "Only the first 200 records were checked" in w["message"]
    st = _status(True, untagged=("shop-api",), candidates=("shop-api",))
    w = _by_code(make_client(FakeVending(st)).get("/api/settings/install-warnings"))["MANAGED_TAG_BACKFILL_PENDING"]
    assert "120 s" in w["message"] and "safe" in w["message"] and "Only the first" not in w["message"]


def test_routes_are_admin_only(make_client):
    c = make_client(FakeVending(_status(False)), role="VIEWER")
    assert c.get("/api/settings/install-warnings").status_code == 403
    assert c.post("/api/settings/managed-tag/backfill").status_code == 403
