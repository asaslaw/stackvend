"""FD-4DJ (FD-4CI remainder).

(1) Settings that are still not read say so: every stored-only field in the settings model. None of them has a
    reader; if one gets a reader, the label must change with it (test below). Default GitHub Branch, FinOps Agent
    Model and Auto-Harmonize Legacy C-Extension Wheels are wired since FD-4DJ wiring (rows FD-4CI-b-R1, FD-4CI-b-R2,
    FD-4DJ-HARMONIZE, owner 10-28): their labels describe what they do (tests/test_fd4dj_wiring.py covers the
    behaviour).
(2) FD-4CI-b-3d (register FOLLOWUPS-1025, owner 10-25): the emergency per-instance copy of a grant Firestore did not
    save is cleared as soon as that user's access is saved / changed / revoked through the same instance, and kept only
    when the instance could not reach Firestore at all (typed google.api_core errors), not when Firestore refused the
    write. The failed-grant log line names the administrator and the role.
Hermetic: in-memory fakes only (no Firestore, no network).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import logging
import os
import re
import sys

import pytest
from google.api_core import exceptions as gexc

TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

from test_fd4ci_b3_settings_fixes import (  # noqa: E402
    REPO_ROOT, S, _html, _ref, users,  # noqa: F401  (users: fixture)
)


def _http_error():
    from fastapi import HTTPException
    return HTTPException


def _grant(users, email="new@example.com", role="VIEWER"):
    return users.ru.add_approved_user(users.schemas.AddUserRequest(email=email, role=role), users.req)


def _copy(users, email="hank@example.com", role="WORKLOAD_MANAGER"):
    """An emergency copy left by an earlier grant that could not reach Firestore."""
    users.ru.MOCK_AUTHORIZED_USERS[email] = users.schemas.UserAccessRecord(
        email=email, role=role, added_at="2026-10-01", added_by="admin@example.com", is_active=True)


# ================================================================================ (2) FD-4CI-b-3d grant copies
UNREACHABLE = [gexc.ServiceUnavailable("x"), gexc.DeadlineExceeded("x"), gexc.GatewayTimeout("x"),
               gexc.RetryError("x", cause=None), gexc.RetryError("x", cause=gexc.ServiceUnavailable("x"))]
REFUSED = [gexc.PermissionDenied("x"), gexc.InvalidArgument("x"), gexc.FailedPrecondition("x"),
           gexc.ResourceExhausted("x"), gexc.InternalServerError("x"), RuntimeError("x"), ValueError("x"),
           gexc.RetryError("x", cause=gexc.ResourceExhausted("x"))]


def _err_id(e):
    cause = getattr(e, "cause", None)
    return f"{type(e).__name__}-{type(cause).__name__}" if isinstance(e, gexc.RetryError) else type(e).__name__


@pytest.mark.parametrize("err", UNREACHABLE, ids=_err_id)
def test_grant_that_could_not_reach_firestore_keeps_the_emergency_copy(users, err):
    users.db.fail_commit = err
    with pytest.raises(_http_error()) as ei:
        _grant(users)
    assert ei.value.status_code == 503 and ei.value.detail["code"] == "USER_ACCESS_NOT_STORED"
    assert "only on this Control Center instance" in ei.value.detail["message"]
    assert users.ru.MOCK_AUTHORIZED_USERS["new@example.com"].role == users.schemas.UserRole.VIEWER
    assert "authorized_users/new@example.com" not in users.db.docs


@pytest.mark.parametrize("err", REFUSED, ids=_err_id)
def test_grant_that_firestore_refused_keeps_no_copy(users, err):
    users.db.fail_commit = err
    with pytest.raises(_http_error()) as ei:
        _grant(users)
    msg = ei.value.detail["message"]
    assert ei.value.status_code == 503 and ei.value.detail["code"] == "USER_ACCESS_NOT_STORED"
    assert "was not saved" in msg and "instance" not in msg  # no claim that it works anywhere
    assert "new@example.com" not in users.ru.MOCK_AUTHORIZED_USERS
    assert "authorized_users/new@example.com" not in users.db.docs and users.db.audit() == []


def test_a_refused_newer_grant_also_drops_an_older_copy(users):
    _copy(users, role="WORKLOAD_MANAGER")  # an older grant during an outage
    users.db.fail_commit = gexc.PermissionDenied("x")
    with pytest.raises(_http_error()):
        _grant(users, email="hank@example.com", role="VIEWER")
    assert "hank@example.com" not in users.ru.MOCK_AUTHORIZED_USERS  # the older, wider copy cannot resurface


def test_saved_grant_clears_the_stale_copy(users):
    _copy(users)
    rec = _grant(users, email="hank@example.com", role="VIEWER")
    assert rec.role == users.schemas.UserRole.VIEWER
    assert users.db.docs["authorized_users/hank@example.com"]["role"] == "VIEWER"
    assert "hank@example.com" not in users.ru.MOCK_AUTHORIZED_USERS


def test_saved_change_clears_the_stale_copy(users):
    s = users.schemas
    _copy(users, email="old@example.com", role="ADMIN")
    users.ru.update_user_workloads("old@example.com", s.UpdateUserWorkloadsRequest(assigned_workloads=["b"]), users.req)
    assert users.db.docs["authorized_users/old@example.com"]["assigned_workloads"] == ["b"]
    assert "old@example.com" not in users.ru.MOCK_AUTHORIZED_USERS


def test_revoke_clears_the_copy_as_before(users):
    _copy(users, email="old@example.com")
    users.ru.remove_approved_user("old@example.com", users.req)
    assert "old@example.com" not in users.ru.MOCK_AUTHORIZED_USERS


# ---- negatives: nothing else changes
@pytest.mark.parametrize("fail", ["reads", "commit"])
def test_change_that_was_not_saved_leaves_the_copy_alone(users, fail):
    s = users.schemas
    _copy(users, email="old@example.com")
    setattr(users.db, f"fail_{fail}", gexc.PermissionDenied("x") if fail == "commit" else True)
    with pytest.raises(_http_error()) as ei:
        users.ru.update_user_workloads("old@example.com", s.UpdateUserWorkloadsRequest(assigned_workloads=["z"]),
                                       users.req)
    assert ei.value.status_code == 503
    assert users.ru.MOCK_AUTHORIZED_USERS["old@example.com"].role == s.UserRole.WORKLOAD_MANAGER


def test_change_of_an_unknown_user_is_404_and_leaves_the_copy_alone(users):
    s = users.schemas
    _copy(users)  # a grant that never reached Firestore has no Firestore record
    with pytest.raises(_http_error()) as ei:
        users.ru.update_user_workloads("hank@example.com", s.UpdateUserWorkloadsRequest(assigned_workloads=["z"]),
                                       users.req)
    assert ei.value.status_code == 404 and "hank@example.com" in users.ru.MOCK_AUTHORIZED_USERS


def test_saves_never_touch_other_users_copies(users):
    s = users.schemas
    _copy(users, email="hank@example.com")
    _grant(users, email="new@example.com")
    users.ru.update_user_workloads("old@example.com", s.UpdateUserWorkloadsRequest(assigned_workloads=["b"]), users.req)
    assert set(users.ru.MOCK_AUTHORIZED_USERS) == {"hank@example.com"}


def test_the_owner_install_entry_is_restored_not_dropped(users):
    ru, s = users.ru, users.schemas
    ru.MOCK_AUTHORIZED_USERS["owner@example.com"] = s.UserAccessRecord(  # an emergency copy over the owner's entry
        email="owner@example.com", role="VIEWER", added_at="x", added_by="admin@example.com", is_active=True)
    _grant(users, email="owner@example.com", role="ADMIN")
    rec = ru.MOCK_AUTHORIZED_USERS["owner@example.com"]
    assert rec.model_dump() == ru.bootstrap_registry_record("owner@example.com").model_dump()
    assert rec.role == s.UserRole.ADMIN and rec.added_by == "system-init"


def test_no_firestore_the_registry_is_still_the_store(users, monkeypatch):
    monkeypatch.setattr(users.ru, "db", None)
    rec = _grant(users, email="gina@example.com", role="WORKLOAD_MANAGER")
    assert users.ru.MOCK_AUTHORIZED_USERS["gina@example.com"] is rec


def test_install_time_registry_entry_is_unchanged():
    sys.path.insert(0, os.path.join(REPO_ROOT, "apps", "control-center"))
    import auth
    rec = auth.bootstrap_registry_record("owner@example.com")
    assert rec.model_dump() == {"email": "owner@example.com", "role": auth.UserRole.ADMIN, "assigned_workloads": [],
                                "added_at": "2026-08-30T10:00:00Z", "added_by": "system-init", "is_active": True}


@pytest.mark.parametrize("err,needle", [(gexc.ServiceUnavailable("x"), "Firestore unreachable"),
                                        (gexc.PermissionDenied("x"), "Firestore refused the write")])
def test_failed_grant_log_names_the_admin_and_the_role(users, caplog, err, needle):
    users.db.fail_commit = err
    with caplog.at_level(logging.ERROR, logger="control-center-users"), pytest.raises(_http_error()):
        _grant(users, role="WORKLOAD_MANAGER")
    (line,) = [r.getMessage() for r in caplog.records if "new@example.com" in r.getMessage()]
    assert "admin@example.com" in line and "WORKLOAD_MANAGER" in line and needle in line


def test_docs_describe_when_the_copy_is_kept_and_cleared():
    ref = _ref()
    assert "could not reach Firestore at all" in ref and "A grant that Firestore refused keeps no such copy" in ref
    assert "removed as soon as that user's access is saved, changed or revoked" in ref


# ================================================================================ (1) settings still not read
def _help_after(html: str, label: str) -> str:
    """The help text that follows a Settings field's label."""
    tail = html.split(label, 1)[1]
    return re.search(r"<p class=\"text-\[10px\][^\"]*\">(.*?)</p>", tail, re.S).group(1)


@pytest.mark.parametrize("label,needle", [
    ("Default GitHub Branch</label>", "its repository is created with it"),
    ("FinOps Agent Model</label>", "recommendation on each budget-breach approval card"),
    ("Auto-Harmonize Legacy C-Extension Wheels</span>", "Off: those old pins are kept as written"),
])
def test_wired_settings_page_labels_describe_the_behaviour(label, needle):
    """FD-4DJ wiring: the three settings are read now; the page says what they do, not 'Not used'."""
    text = _help_after(_html(), label)
    assert not text.startswith("Not used") and needle in text


def test_harmonize_help_text_names_the_bom_precedence():
    text = _help_after(_html(), "Auto-Harmonize Legacy C-Extension Wheels</span>")
    assert "changes nothing" not in text.split("(by default")[0] and "always relaxes" not in text
    assert "unless Centrally Governed Package Versions lists the package" in text  # the BOM bound wins
    assert "relives" not in _html()


def test_branch_label_states_the_identity_federation_accepts_the_branch():
    """FD-4CI-b-R1-WIF closed the gap FD-4DJ labelled (WIF accepted only main): the page, the model and
    settings-reference.md now say the identity federation accepts the workload's branch, and none of them still calls
    it refused / not covered."""
    page = _help_after(_html(), "Default GitHub Branch</label>")
    model = S.OrchestrationSettings.model_fields["default_branch"].description
    ref = " ".join(_ref().split("#### Default GitHub Branch", 1)[1].split("####", 1)[0].split())
    assert "identity federation accepts its branch" in page
    assert "identity-federation condition accepts its recorded branch" in model
    assert "identity-federation condition accepts its recorded branch" in ref
    for text in (page, model, ref):
        assert "Not covered yet" not in text and "refused" not in text and "accepts only main" not in text


def test_harmonize_text_names_the_bom_precedence_everywhere():
    desc = S.RuntimeSettings.model_fields["auto_harmonize_wheels"].description
    assert "unless package_versions" in desc and "by default all four are listed" in desc
    assert "by default all four are listed" in _ref().split("#### Auto-Harmonize Legacy C-Extension Wheels", 1)[1]
    # and the default package list really holds all four
    assert {"numpy", "scipy", "pandas", "asyncpg"} <= set(S.RuntimeSettings().package_versions)


UNREAD = {  # (section model, field): what the description must start with
    ("OrchestrationSettings", "default_folder_id"): "Not used at present",
    ("OrchestrationSettings", "default_terraform_timeout_seconds"): "Not used at present",
    ("OrchestrationSettings", "max_pipeline_retries"): "Not used at present",
    ("OrchestrationSettings", "max_vending_timeout_seconds"): "Not used at present",
    ("OrchestrationSettings", "high_memory_container_mb"): "Not used at present",
    ("OrchestrationSettings", "high_cpu_container"): "Not used at present",
    ("RuntimeSettings", "artifact_registry_virtual_repo"): "Not used at present",
}


def _model(name):
    return getattr(S, name)


@pytest.mark.parametrize("model,field", sorted(UNREAD), ids=lambda x: str(x))
def test_settings_model_description_says_not_used(model, field):
    desc = _model(model).model_fields[field].description
    assert desc.startswith(UNREAD[(model, field)]), (model, field, desc)


def test_used_settings_are_not_labelled_unused():
    """Negative: the label is only on fields with no reader; a wired field (for example the lock timeout) keeps its
    normal description."""
    for model, field in [("OrchestrationSettings", "terraform_lock_timeout_seconds"),
                         ("AgentModelSettings", "architect_model"), ("RuntimeSettings", "cloud_build_timeout_seconds")]:
        assert not _model(model).model_fields[field].description.startswith("Not used"), field


WIRED = {  # FD-4DJ wiring (owner 10-28): (section model, field) -> the register row its description starts with
    ("OrchestrationSettings", "default_branch"): "FD-4CI-b-R1:",
    ("AgentModelSettings", "finops_model"): "FD-4CI-b-R2:",
    ("RuntimeSettings", "auto_harmonize_wheels"): "FD-4DJ-HARMONIZE:",
}


@pytest.mark.parametrize("model,field", sorted(WIRED), ids=lambda x: str(x))
def test_wired_settings_model_descriptions_name_their_row(model, field):
    desc = _model(model).model_fields[field].description
    assert desc.startswith(WIRED[(model, field)]) and "Not used" not in desc, (model, field, desc)


# Fields with a unique key name: no platform code outside the settings model and the Settings page may read them.
# (default_branch is also the per-workload branch field, so it is checked through its labels above, not here.)
_UNIQUE_UNREAD = sorted({f for (_m, f) in UNREAD} - {"default_branch"})
_SCAN_DIRS = ("apps", "mcp-servers", "agents", "shared", "workflows", "infra")
# The seven byte-identical settings-model copies define the fields; they are the only files skipped.
_SETTINGS_MODEL_COPIES = {os.path.join(*p.split("/")) for p in (
    "shared/settings.py", "apps/control-center/shared/settings.py", "apps/orchestrator-gateway/shared/settings.py",
    "apps/project-vending/shared/settings.py", "apps/spec-ingestion/shared/settings.py",
    "mcp-servers/terraform/shared/settings.py", "apps/finops-enforcer/shared/settings.py",
    "apps/billing-alert-drain/shared/settings.py")}  # C10: the drain job's copy (byte-identical, test_c10_platform_tf)
# Known non-readers: the GCP Folders tab's save answers with a `default_folder_id` response key (it writes the folder
# registry, not this setting).
_ALLOWED = {(os.path.join("apps", "control-center", "routes", "settings.py"), "default_folder_id"):
            '"default_folder_id": clean_fid'}


def _platform_files():
    for top in _SCAN_DIRS:
        for root, dirs, files in os.walk(os.path.join(REPO_ROOT, top)):
            dirs[:] = [d for d in dirs if d not in ("node_modules", ".terraform", "__pycache__", "tests")]
            for f in files:
                path = os.path.join(root, f)
                if not f.endswith((".py", ".yaml", ".yml", ".js", ".tf")) or f.startswith("test_") \
                        or os.path.relpath(path, REPO_ROOT) in _SETTINGS_MODEL_COPIES:
                    continue
                yield path


def test_settings_labelled_not_used_really_have_no_reader():
    """If one of these settings gets a reader, its 'Not used' label (page, model, settings-reference) must change in
    the same change."""
    hits = []
    for path in _platform_files():
        try:
            text = open(path, encoding="utf-8").read()
        except (UnicodeDecodeError, OSError):
            continue
        rel = os.path.relpath(path, REPO_ROOT)
        for f in _UNIQUE_UNREAD:
            allowed = _ALLOWED.get((rel, f))
            if allowed:
                assert text.count(f) == 1 and allowed in text, (rel, f)  # only the known response key
                continue
            if f in text:
                hits.append((rel, f))
    assert hits == []


def test_settings_reference_known_gaps_after_the_wiring():
    """FD-4DJ wiring: FinOps Agent Model and Auto-Harmonize are no longer gaps; FD-4CI-b-R1-WIF: nor is Default GitHub
    Branch (the identity federation accepts the workload's branch)."""
    gaps = _ref().split("## Known gaps between the page and the platform", 1)[1]
    assert "**Default GitHub Branch**" not in gaps and "identity-federation" not in gaps
    for gone in ("is not used yet", "**FinOps Agent Model** is not used",
                 "**Auto-Harmonize Legacy C-Extension Wheels** is not read"):
        assert gone not in gaps
