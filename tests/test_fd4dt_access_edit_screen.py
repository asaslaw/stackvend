"""FD-4DT (A) + (B): the Control Center's access-editing screen and the personal Google account warning.

(A) After create, an administrator changes who may use an app from the workload's page (card "Who may use this
app"): it reads the record with the new read-only, admin-only ``GET /api/workloads/{pid}/access`` and saves with the
existing ``PATCH /api/workloads/{pid}/access`` (L19-11 / L19-F4, unchanged). A 422 ``ACCESS_WIDENING_UNCONFIRMED`` is
shown to the administrator, who confirms it explicitly (``confirm_widening: true``); other errors are shown as sent.
After a save the card says how the change applies (FD-4DT: Fast-Path Deploy applies a private record; Public and widenings need a Full Swarm Rebuild).

(B) For Private (IAP), a ``user:`` member at ``gmail.com`` / ``googlemail.com`` gets a warning (never a block), in the
create form and in the edit card. A typed check on the parsed member (exact ``user:`` kind, the email's domain part
compared whole); no other kind and no other mode is flagged.

Hermetic: the GET runs on the real workloads router with the in-memory Firestore fake of test_l19_11_access_intake;
the template is checked statically; the warning function is also executed with a local JavaScript engine when one is
on the machine (node, or JavaScriptCore through osascript), fed through stdin (no file, no network).
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import os
import shutil
import subprocess

import pytest

from test_l19_11_access_intake import (  # noqa: F401,E402  (cc is a fixture)
    ADMIN_H, MANAGER_H, VIEWER_H, FakeDB, _client, cc)

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DASHBOARD = os.path.join(REPO, "apps", "control-center", "templates", "dashboard.html")
PID = "shop-app"
IAP_RECORD = {"mode": "PRIVATE_IAP", "invoker_principals": ["user:ana@example.com", "group:staff@example.com"],
              "app_admin_emails": [], "public_api_routes": [],
              "sign_in": {"google": "DISABLED", "email_password": False, "additional_authorized_domains": []},
              "tenant_isolation_required": None, "source": "intake"}
WARNING_HEAD = "Identity-Aware Proxy admits only accounts of your Google Cloud organization; "
WARNING_TAIL = (" is a personal Google account and will be refused. List an organization account, or choose "
                "Private: IAM callers only.")


@pytest.fixture(scope="module")
def html():
    with open(DASHBOARD, encoding="utf-8") as f:
        return f.read()


def _method(html, name):
    """The body of one Alpine component method (`name(...) {` up to the next method at the same indent)."""
    start = html.index("\n                " + name + "(")
    end = html.index("\n                },\n", start)
    return html[start:end + len("\n                },")]


def _panel(html):
    start = html.index('data-testid="workload-access-panel"')
    end = html.index("<!-- Workload Details Live In-Flight HUD Banner -->", start)
    return html[start:end]


# ============================================================================ (A) GET /api/workloads/{pid}/access
def _get(wl, monkeypatch, initial, headers=ADMIN_H, fake_db=None):
    fake_db = fake_db or FakeDB(initial)
    client = _client(wl, monkeypatch, fake_db)
    return client.get(f"/api/workloads/{PID}/access", headers=headers), fake_db


def test_get_returns_the_stored_record_exactly_and_writes_nothing(cc, monkeypatch):
    _, wl = cc
    initial = {f"workloads/{PID}": {"product_id": PID, "access": IAP_RECORD,
                                    "access_updated_at": "2026-10-28T10:00:00+00:00",
                                    "access_updated_by": "admin@example.com"}}
    r, fake_db = _get(wl, monkeypatch, initial)
    assert r.status_code == 200, r.text
    assert r.json() == {"product_id": PID, "access": IAP_RECORD, "access_valid": True,
                        "access_updated_at": "2026-10-28T10:00:00+00:00", "access_updated_by": "admin@example.com",
                        "access_widening_pending": False}
    assert fake_db.writes == [] and fake_db.commits == 0 and dict(fake_db) == initial


@pytest.mark.parametrize("record, valid", [
    (None, False),                                                  # no record yet (ACCESS_POLICY_INCOMPLETE)
    ({"mode": "PRIVATE_IAP", "invoker_principals": ["ana@example.com"]}, False),   # unprefixed: invalid
    ("PRIVATE_IAP", False),                                         # not a map
])
def test_get_reports_a_missing_or_invalid_record_as_not_valid(cc, monkeypatch, record, valid):
    _, wl = cc
    doc = {"product_id": PID} if record is None else {"product_id": PID, "access": record}
    r, _ = _get(wl, monkeypatch, {f"workloads/{PID}": doc})
    assert r.status_code == 200, r.text
    assert r.json()["access"] == record and r.json()["access_valid"] is valid


@pytest.mark.parametrize("flag, pending", [
    ({"set_by": "admin@example.com"}, True),
    ("garbage", True),         # a malformed flag is pending (the gateway's rule: present and non-null)
    (None, False),             # explicit null: nothing pending
])
def test_get_reports_a_pending_widening_by_the_gateway_rule(cc, monkeypatch, flag, pending):
    _, wl = cc
    doc = {"product_id": PID, "access": IAP_RECORD, "access_widening_approval": flag}
    r, _ = _get(wl, monkeypatch, {f"workloads/{PID}": doc})
    assert r.status_code == 200 and r.json()["access_widening_pending"] is pending


@pytest.mark.parametrize("headers, code", [(MANAGER_H, 403), (VIEWER_H, 403), ({}, 401)])
def test_get_is_admin_only(cc, monkeypatch, headers, code):
    _, wl = cc
    r, fake_db = _get(wl, monkeypatch, {f"workloads/{PID}": {"product_id": PID, "access": IAP_RECORD}},
                      headers=headers)
    assert r.status_code == code, r.text
    assert "invoker_principals" not in r.text and fake_db.writes == []


def test_get_unknown_workload_is_404(cc, monkeypatch):
    _, wl = cc
    r, _ = _get(wl, monkeypatch, {})
    assert r.status_code == 404


def test_get_unreadable_store_is_503(cc, monkeypatch):
    _, wl = cc

    class _Unreadable(FakeDB):
        def collection(self, name):
            raise RuntimeError("store down")

    r, _ = _get(wl, monkeypatch, None, fake_db=_Unreadable({}))
    assert r.status_code == 503


def test_the_widening_refusal_carries_the_fields_the_screen_reads(cc, monkeypatch, html):
    """Front and back agree: the 422 body has exactly the keys saveWorkloadAccess reads."""
    _, wl = cc
    fake_db = FakeDB({f"workloads/{PID}": {"product_id": PID, "access": IAP_RECORD}})
    client = _client(wl, monkeypatch, fake_db)
    r = client.patch(f"/api/workloads/{PID}/access", headers=ADMIN_H,
                     json={"mode": "PRIVATE_IAP", "invoker_principals": IAP_RECORD["invoker_principals"]
                           + ["user:bo@example.com"]})
    assert r.status_code == 422
    detail = r.json()["detail"]
    assert detail["error_class"] == "ACCESS_WIDENING_UNCONFIRMED" and fake_db.writes == []
    save = _method(html, "async saveWorkloadAccess")
    for key in ("error_class", "changes", "previous_mode", "new_mode"):
        assert key in detail and f"detail.{key}" in save, key


# ============================================================================ (A) the screen (template)
def test_the_card_is_admin_only_and_not_on_the_platform_workload(html):
    panel_at = html.index('data-testid="workload-access-panel"')
    opener = html[html.rindex("<template", 0, panel_at):panel_at]
    assert ('x-if="userRole === \'ADMIN\' && workloadDetails && !workloadDetails.is_castor && '
            'workloadDetails.status !== \'DECOMMISSIONED\' && workloadDetails.status !== \'ARCHIVED\'"') in opener
    # the record is only read for administrators, and saving refuses for anyone else client-side too
    assert "if (!pid || this.userRole !== 'ADMIN') return;" in _method(html, "async fetchWorkloadAccess")
    assert "pid !== this.selectedWorkloadId || this.userRole !== 'ADMIN')" in _method(html, "async saveWorkloadAccess")
    # loaded with the details
    loader = _method(html, "async loadWorkloadDetails")
    assert "await this.fetchWorkloadAccess();" in loader


def test_the_card_reads_the_new_get_and_shows_mode_and_members(html):
    fetch = _method(html, "async fetchWorkloadAccess")
    assert "fetch('/api/workloads/' + encodeURIComponent(pid) + '/access')" in fetch
    panel = _panel(html)
    assert "accessModeLabel(workloadAccess.access.mode)" in panel
    assert "workloadAccess.access.invoker_principals" in panel
    assert "workloadAccess.access_widening_pending" in panel
    assert "startEditWorkloadAccess()" in panel and "Edit access" in panel


def test_the_edit_form_matches_the_create_form_component(html):
    panel = _panel(html)
    for mode in ("PRIVATE_IAP", "PRIVATE_IAM", "PUBLIC_APP"):
        assert f"editWorkloadAccess.mode = '{mode}'" in panel
    for label in ("Private: Google sign-in (IAP)", "Private: IAM callers only",
                  "Does this app handle money, personal data, or other customers' data? *",
                  "People and groups allowed (one per line) *"):
        assert label in panel, label
    assert 'x-model="editWorkloadAccess.principals_text"' in panel
    assert "editWorkloadAccess.tenant_isolation_required = true" in panel
    # one answer builder for both forms (the create form's is unchanged in behavior)
    assert "return this.buildAccessIntakeFrom(this.newWorkloadAccess);" in _method(html, "buildAccessIntake")
    assert "this.buildAccessIntakeFrom(this.editWorkloadAccess)" in _method(html, "async saveWorkloadAccess")


def test_edit_prefills_the_current_record(html):
    start = _method(html, "startEditWorkloadAccess")
    assert "principals_text: principals.join('\\n')" in start
    assert "rec.tenant_isolation_required" in start
    assert "mode: mode" in start


def test_save_calls_the_existing_patch_unconfirmed_first(html):
    save = _method(html, "async saveWorkloadAccess")
    assert "fetch('/api/workloads/' + encodeURIComponent(pid) + '/access', {" in save
    assert "method: 'PATCH'" in save and "JSON.stringify(body)" in save
    assert "confirm_widening: confirmWidening === true" in save
    panel = _panel(html)
    assert '@click="saveWorkloadAccess(false)"' in panel      # Save: never confirms on its own
    assert '@click="saveWorkloadAccess(true)"' in panel       # only the explicit confirmation button does
    assert panel.count("saveWorkloadAccess(true)") == 1


def test_save_asks_to_confirm_a_widening_and_explains_the_plan_approval(html):
    save = _method(html, "async saveWorkloadAccess")
    assert "res.status === 422" in save
    assert "detail.error_class === 'ACCESS_WIDENING_UNCONFIRMED' && confirmWidening !== true" in save
    assert "this.workloadAccessWidening = {" in save
    panel = _panel(html)
    confirm = panel[panel.index('data-testid="workload-access-widening-confirm"'):]
    confirm = confirm[:confirm.index('data-testid="workload-access-error"')]
    assert 'x-show="workloadAccessWidening"' in panel
    assert "next run waits for a plan approval" in confirm
    assert "Confirm widening and save" in confirm and '@click="saveWorkloadAccess(true)"' in confirm


def test_other_errors_are_shown_verbatim(html):
    save = _method(html, "async saveWorkloadAccess")
    assert "this.workloadAccessError = 'HTTP ' + res.status + ': ' + (await this.accessErrorText(res));" in save
    assert "typeof detail === 'string' ? detail : JSON.stringify(detail)" in save
    err = _method(html, "async accessErrorText")
    assert "typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)" in err
    assert 'x-text="workloadAccessError"' in _panel(html)


SAVED_WIDENING = ("Saved. This change widens access: relaunch the workload with Full Swarm Rebuild, which waits for a "
                  "plan approval in Approvals before any code is generated. Fast-Path Deploy is refused until that "
                  "approval.")
SAVED_PUBLIC = ("Saved. A change to or from Public, or to a Public app, applies on the next Full Swarm Rebuild "
                "(Relaunch, then Full Swarm Rebuild).")
SAVED_PRIVATE = ("Saved. Relaunch the workload to apply it: Fast-Path Deploy (or Auto, after a successful run) applies "
                 "the new access list without regenerating code.")
# FD-4DT (access applies on Fast-Path): (previous mode, new mode, plan approval forced) -> notice
SAVED_NOTICE_CASES = [
    ("PRIVATE_IAP", "PRIVATE_IAP", False, SAVED_PRIVATE),     # members removed
    ("PRIVATE_IAP", "PRIVATE_IAM", False, SAVED_PRIVATE),     # IAP -> IAM (narrowing)
    ("PRIVATE_IAM", "PRIVATE_IAP", True, SAVED_WIDENING),     # IAM -> IAP (widening)
    ("PRIVATE_IAP", "PRIVATE_IAP", True, SAVED_WIDENING),     # member added
    (None, "PRIVATE_IAP", True, SAVED_WIDENING),              # first record
    ("PRIVATE_IAP", "PUBLIC_APP", True, SAVED_WIDENING),      # to Public (widening)
    ("PUBLIC_APP", "PRIVATE_IAP", False, SAVED_PUBLIC),       # from Public (narrowing, regenerates the app)
    ("PUBLIC_APP", "PUBLIC_APP", False, SAVED_PUBLIC),        # a Public app's settings
]


def test_after_a_save_the_card_says_when_the_change_applies(html):
    save = _method(html, "async saveWorkloadAccess")
    assert ("this.workloadAccessSavedNotice = this.accessSavedNotice(previousMode, newMode, "
            "data.plan_approval_forced === true);") in save
    # the previous mode is the record the card showed before the save (read before the reload below)
    assert ("const previousMode = (this.workloadAccess && this.workloadAccess.access) ? "
            "this.workloadAccess.access.mode : null;") in save
    assert save.index("const previousMode") < save.index("await this.fetchWorkloadAccess();")
    notice = _method(html, "accessSavedNotice")
    for text in (SAVED_WIDENING, SAVED_PUBLIC, SAVED_PRIVATE):
        assert f"'{text}'" in notice
    assert "keeps the old list" not in html and "next full relaunch of this workload" not in html
    assert 'x-text="workloadAccessSavedNotice"' in _panel(html)


def test_saved_notice_executes_the_table(html):
    cmd, emit = _js_runner()
    if cmd is None:
        pytest.skip("no local JavaScript engine (node or osascript); the static checks above still apply")
    obj = "var o = {\n%s\n};\n" % _method(html, "accessSavedNotice").strip().rstrip(",")
    cases = json.dumps([[p, n, f] for p, n, f, _ in SAVED_NOTICE_CASES])
    body = (obj + "var cases = %s;\n" % cases
            + emit % "JSON.stringify(cases.map(function (c) { return o.accessSavedNotice(c[0], c[1], c[2]); }))"
            + ";\n")
    out = subprocess.run(cmd, input=body, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout.strip().splitlines()[-1]) == [want for *_, want in SAVED_NOTICE_CASES]


# ============================================================================ (B) personal Google account warning
def test_warning_is_bound_in_the_create_form_and_the_edit_card(html):
    create = html[html.index("Who may use this app *"):html.index("<!-- EXPRESS MODE: Visual Resource Builder -->")]
    assert ('x-for="email in personalGoogleAccountEmails(newWorkloadAccess.mode, newWorkloadAccess.principals_text)"'
            in create)
    assert 'x-text="iapPersonalAccountWarning(email)"' in create
    panel = _panel(html)
    assert ('x-for="email in personalGoogleAccountEmails(editWorkloadAccess.mode, editWorkloadAccess.principals_text)"'
            in panel)
    # a warning, never a block: the submit paths do not consult it
    for name in ("async submitNewWorkload", "async saveWorkloadAccess"):
        assert "personalGoogleAccountEmails" not in _method(html, name), name


def test_warning_text_is_exact(html):
    fn = _method(html, "iapPersonalAccountWarning")
    assert f"'{WARNING_HEAD}' + email" in fn
    assert f"+ '{WARNING_TAIL}'" in fn


def test_warning_check_is_typed_not_a_pattern(html):
    fn = _method(html, "personalGoogleAccountEmails")
    assert "if (mode !== 'PRIVATE_IAP') return [];" in fn
    assert "if (!member.startsWith('user:')) continue;" in fn
    assert "const at = email.lastIndexOf('@');" in fn
    assert "const domain = email.slice(at + 1).toLowerCase();" in fn
    assert "const personalDomains = ['gmail.com', 'googlemail.com'];" in fn
    assert "personalDomains.includes(domain)" in fn
    for pattern_api in ("RegExp", ".match(", ".test(", ".search(", "endsWith", "indexOf('gmail"):
        assert pattern_api not in fn, pattern_api


# The same table, executed with a JavaScript engine when the machine has one.
WARNING_CASES = [
    ("PRIVATE_IAP", "user:ana@gmail.com", ["ana@gmail.com"]),
    ("PRIVATE_IAP", "user:bo@googlemail.com", ["bo@googlemail.com"]),
    ("PRIVATE_IAP", "user:Cy@Gmail.COM", ["Cy@Gmail.COM"]),                     # domains are case-insensitive
    ("PRIVATE_IAP", "group:staff@example.com\n  user:ana@gmail.com  \nuser:ana@gmail.com", ["ana@gmail.com"]),
    # negatives: other modes
    ("PRIVATE_IAM", "user:ana@gmail.com", []),
    ("PUBLIC_APP", "user:ana@gmail.com", []),
    # negatives: other kinds
    ("PRIVATE_IAP", "group:fans@gmail.com", []),
    ("PRIVATE_IAP", "domain:gmail.com", []),
    ("PRIVATE_IAP", "serviceAccount:x@gmail.com", []),
    ("PRIVATE_IAP", "User:ana@gmail.com", []),                                  # kinds are exact
    # negatives: organization emails and look-alikes (the domain part is compared whole)
    ("PRIVATE_IAP", "user:ana@example.com", []),
    ("PRIVATE_IAP", "user:ana@gmail.com.example.com", []),
    ("PRIVATE_IAP", "user:ana@notgmail.com", []),
    ("PRIVATE_IAP", "user:ana@mail.gmail.com", []),
    ("PRIVATE_IAP", "user:@gmail.com", []),
    ("PRIVATE_IAP", "user:gmail.com", []),
    ("PRIVATE_IAP", "", []),
]


def _js_runner():
    if shutil.which("node"):
        return ["node", "-"], "process.stdout.write(%s)"
    if shutil.which("osascript"):
        return ["osascript", "-l", "JavaScript", "-"], "%s"
    return None, None


def test_warning_function_executes_the_table(html):
    cmd, emit = _js_runner()
    if cmd is None:
        pytest.skip("no local JavaScript engine (node or osascript); the static checks above still apply")
    obj = "var o = {\n%s,\n%s\n};\n" % (_method(html, "personalGoogleAccountEmails").strip().rstrip(","),
                                       _method(html, "iapPersonalAccountWarning").strip().rstrip(","))
    cases = json.dumps([[m, p] for m, p, _ in WARNING_CASES])
    body = (obj + "var cases = %s;\n" % cases
            + emit % "JSON.stringify({r: cases.map(function (c) { return o.personalGoogleAccountEmails(c[0], c[1]); }),"
                     " w: o.iapPersonalAccountWarning('ana@gmail.com')})" + ";\n")
    out = subprocess.run(cmd, input=body, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    got = json.loads(out.stdout.strip().splitlines()[-1])
    assert got["r"] == [want for _, _, want in WARNING_CASES]
    assert got["w"] == WARNING_HEAD + "ana@gmail.com" + WARNING_TAIL


def test_review_f1_save_targets_the_loaded_workload_only():
    """Review F1: Save PATCHes the workload whose record the card loaded and refuses when the selection changed."""
    html = open(os.path.join(REPO, "apps", "control-center", "templates", "dashboard.html")).read()
    start = html.index("async saveWorkloadAccess(confirmWidening)")
    body = html[start:start + 600]
    assert "const pid = this.workloadAccessFor;" in body
    assert "pid !== this.selectedWorkloadId" in body and "this.cancelEditWorkloadAccess(); return;" in body
    assert "const pid = this.selectedWorkloadId;" not in body
    load = html[html.index("async loadWorkloadDetails()"):][:400]
    assert "this.workloadAccessFor !== this.selectedWorkloadId" in load and "this.isEditingWorkloadAccess = false" in load


def test_review_n1_card_hidden_on_decommissioned_or_archived():
    html = open(os.path.join(REPO, "apps", "control-center", "templates", "dashboard.html")).read()
    assert ("userRole === 'ADMIN' && workloadDetails && !workloadDetails.is_castor && workloadDetails.status !== "
            "'DECOMMISSIONED' && workloadDetails.status !== 'ARCHIVED'") in html
