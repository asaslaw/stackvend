"""WORKLOAD-REPO-NAME (10-27, seen live): the Workloads Catalog was empty on both dev installs.

The Express create path stored the vending service's whole repository result (a dict) in `workloads/{id}.github_repo`
instead of the repository's full name. WorkloadSummary.github_repo is a string, so the list route's validation failed
and the route returned an empty list for every workload. The fix is typed at both ends:

* Express stores the repository's full name (`_stored_repo_name` of the vending result).
* The Control Center readers take a string as is and a stored repository result's `full_name`, so records already
  written as a dict list and open again without editing the data.

Hermetic: the CC routes on an in-memory Firestore fake.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)
import inspect
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

from fd4f_support import FakeDB

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")

VENDED = {"clone_url": "https://example.invalid/o/rc-app.git", "full_name": "o/rc-app", "html_url": "",
          "repo_name": "rc-app", "repository_id": 7, "reused_existing": False, "status": "REPO_VENDED",
          "vcs_provider": "GITHUB"}


def _routes(monkeypatch, store):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from routes import workloads as wl_routes

    monkeypatch.setattr(cc_db, "_db_client", False)
    monkeypatch.setattr(wl_routes, "db", store)
    return wl_routes


def _admin():
    from authz import UserRole
    request = MagicMock()
    request.state.user_email = "admin@example.com"
    request.state.user_role = UserRole.ADMIN
    request.state.assigned_workloads = []
    return request


@pytest.mark.parametrize("value,want", [
    ("o/app", "o/app"),
    ("", None),
    (None, None),
    (VENDED, "o/rc-app"),
    ({"repo_name": "rc-app"}, None),          # no full_name: nothing guessed
    ({"full_name": 7}, None),
    (["o/app"], None),
])
def test_stored_repo_name_is_typed(monkeypatch, value, want):
    wl = _routes(monkeypatch, FakeDB())
    assert wl._stored_repo_name(value) == want


def test_catalog_lists_every_workload_when_one_record_holds_a_repository_result(monkeypatch):
    store = FakeDB()
    store.docs["workloads/rc-express"] = {"product_id": "rc-express", "project_id": "rc-express-1a2b",
                                          "status": "ACTIVE", "github_repo": VENDED}
    store.docs["workloads/plain-app"] = {"product_id": "plain-app", "project_id": "plain-app", "status": "ACTIVE",
                                         "github_repo": "o/plain-app"}
    store.docs["workloads/no-repo"] = {"product_id": "no-repo", "project_id": "no-repo", "status": "PROVISIONED"}
    wl = _routes(monkeypatch, store)
    listed = {w.product_id: w.github_repo for w in wl.list_workloads(_admin())}
    assert listed == {"rc-express": "o/rc-app", "plain-app": "o/plain-app", "no-repo": None}


def test_negative_string_records_are_listed_unchanged(monkeypatch):
    store = FakeDB()
    store.docs["workloads/a"] = {"product_id": "a", "project_id": "a", "status": "ACTIVE", "github_repo": "o/a"}
    wl = _routes(monkeypatch, store)
    assert [(w.product_id, w.github_repo) for w in wl.list_workloads(_admin())] == [("a", "o/a")]
    assert store.docs["workloads/a"]["github_repo"] == "o/a"     # read only: nothing is rewritten


def test_details_open_for_a_record_holding_a_repository_result(monkeypatch):
    store = FakeDB()
    store.docs["workloads/rc-express"] = {"product_id": "rc-express", "project_id": "rc-express-1a2b",
                                          "status": "ACTIVE", "github_repo": dict(VENDED)}
    wl = _routes(monkeypatch, store)
    with patch.object(wl, "verify_workload_access", lambda *a, **k: None), \
         patch.object(wl, "fetch_workload_state_from_gcs", return_value=None):
        details = wl.get_workload_details("rc-express", _admin())
    assert details.github_repo == "o/rc-app"
    assert store.docs["workloads/rc-express"]["github_repo"] == VENDED   # the stored record is not edited


def test_express_stores_the_full_name_not_the_vending_result(monkeypatch):
    wl = _routes(monkeypatch, FakeDB())
    src = inspect.getsource(wl.execute_express_provisioning)
    assert 'vended_repo = _stored_repo_name(v_data.get("github_repo"))' in src
    assert 'vended_repo = v_data["github_repo"]' not in src
