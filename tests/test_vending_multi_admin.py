"""
Unit tests for Multi-Admin & Workload Creator roles/viewer IAM auto-binding in Project Vending.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VENDING_DIR = os.path.join(REPO_ROOT, "apps", "project-vending")
if VENDING_DIR not in sys.path:
    sys.path.insert(0, VENDING_DIR)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

for m in [
    'httpx', 'fastapi', 'google', 'google.auth', 'googleapiclient',
    'googleapiclient.discovery', 'googleapiclient.errors', 'google.cloud',
    'google.cloud.firestore', 'google.cloud.storage', 'google.cloud.secretmanager',
    'github', 'jwt'
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

from vending import ProjectRepoVendingEngine
from destructive_guard_fakes import FakeChildIAM  # noqa: E402


class TestVendingMultiAdmin(unittest.TestCase):
    """Verifies that project vending assigns roles/viewer to every platform ADMIN (exact role; lane 19 L19-12)."""

    def setUp(self):
        self.mock_db = MagicMock()
        self.mock_crm = MagicMock()
        self.mock_billing = MagicMock()
        self.mock_secret = MagicMock()
        self.mock_storage = MagicMock()

        self.engine = ProjectRepoVendingEngine(
            platform_project_id="test-platform-proj",
            firestore_client=self.mock_db,
            secret_client=self.mock_secret,
            crm_service=self.mock_crm,
            billing_service=self.mock_billing,
            storage_client=self.mock_storage,
            iam_client=FakeChildIAM(),   # RT14-31: the vend-time Control Center log-reader grant
        )

    @patch.dict(os.environ, {"ADMIN_USER_EMAIL": "env-admin@example.com,secondary-admin@example.com"})
    def test_get_platform_admin_members(self):
        """Lane 19 L19-12 (FD-4I I10/I11): only exact ADMIN records; env admins and creator fields grant nothing."""
        docs = []
        for email, role in (("db-admin@example.com", "ADMIN"), ("viewer@example.com", "VIEWER"),
                            ("non@example.com", "NON_ADMIN"), ("pending@example.com", "ADMIN_PENDING"),
                            ("sub@example.com", "SUBADMIN"), ("spaced@example.com", " admin ")):
            d = MagicMock()
            d.id = email
            d.to_dict.return_value = {"email": email, "role": role, "is_active": True}
            docs.append(d)

        self.mock_db.collection.return_value.stream.return_value = docs

        members = self.engine.get_platform_admin_members()

        self.assertEqual(members, ["user:db-admin@example.com", "user:spaced@example.com"])
        for absent in ("env-admin", "secondary-admin", "operator", "viewer", "non", "pending", "sub"):
            self.assertNotIn(f"user:{absent}@example.com", members)

    @patch.dict(os.environ, {"ADMIN_USER_EMAIL": "env-only-admin@example.com"})
    def test_vend_gcp_project_binds_roles_viewer(self):
        admin = MagicMock()
        admin.id = "primary-admin@example.com"
        admin.to_dict.return_value = {"email": "primary-admin@example.com", "role": "ADMIN", "is_active": True}
        self.mock_db.collection.return_value.stream.return_value = [admin]
        self.mock_crm.projects().create().execute.return_value = {"name": "operations/create-1"}
        # the finished create operation's response names the project number (VENDING-READ-TRANSIENT, OQ-28)
        self.mock_crm.operations().get().execute.return_value = {"name": "operations/create-1", "done": True,
                                                                  "response": {"name": "projects/123456789012"}}
        self.mock_crm.projects().getIamPolicy().execute.return_value = {"bindings": []}
        self.mock_billing.projects().updateBillingInfo().execute.return_value = {"billingEnabled": True}

        saved_policies = []
        def record_set_iam(resource, body):
            saved_policies.append(body.get("policy", {}))
            m = MagicMock()
            m.execute.return_value = body.get("policy", {})
            return m

        self.mock_crm.projects().setIamPolicy = record_set_iam

        res = self.engine.vend_gcp_project(
            product_id="multi-admin-app",
            trace_id="tr-admin-789",
            folder_id="folders/123",
            billing_account_id="00AA11-22BB33",
        )

        self.assertEqual(res["status"], "PROJECT_VENDED")
        self.assertGreater(len(saved_policies), 0)
        viewer_bindings = [b for b in saved_policies[0].get("bindings", []) if b.get("role") == "roles/viewer"]
        self.assertEqual(len(viewer_bindings), 1)
        self.assertIn("user:primary-admin@example.com", viewer_bindings[0]["members"])
        self.assertNotIn("user:env-only-admin@example.com", viewer_bindings[0]["members"])  # env grants nothing

    def test_vend_all_greenfield_calls_vend_github_repo(self):
        """Greenfield workload with matching product_id and repo_name must call vend_github_repo."""
        mock_doc = MagicMock()
        mock_doc.exists = True
        mock_doc.to_dict.return_value = {
            "product_id": "anothertester",
            "project_id": "anothertester",
            "github_repo": "example-org/anothertester",
            "default_branch": "main",
            "status": "PROVISIONING",
            "folder_id": "folders/123",
        }
        self.mock_db.collection().document().get.return_value = mock_doc

        with patch.object(self.engine, "vend_gcp_project", return_value={"project_id": "anothertester"}), \
             patch.object(self.engine, "vend_github_repo", return_value={
                 "status": "REPO_VENDED",
                 "repo_name": "anothertester",
                 "full_name": "example-org/anothertester",
                 "html_url": "https://github.com/example-org/anothertester",
                 "reused_existing": False,
             }) as mock_vend:

            res = self.engine.vend_all(
                product_id="anothertester",
                trace_id="tr-greenfield-123",
                folder_id="folders/123",
            )

            mock_vend.assert_called_once_with(
                "anothertester",
                github_owner=None,
                vcs_provider=None,
                repo_identifier="example-org/anothertester",
                initial_branch="main",   # FD-4CI-b-R1: the recorded branch is passed to the provider
                recorded_identity=None,  # GITHUB-REPO-NAME-NO-PREFIX: the workload's own repository record (none)
                claim=True,              # GITHUB-REPO-NAME-NO-PREFIX RT F1: the name is claimed before the create
            )
            self.assertEqual(res["status"], "WORKLOAD_VENDED")
            self.assertEqual(res["github_repo"]["full_name"], "example-org/anothertester")
            self.assertFalse(res["github_repo"]["reused_existing"])

# ============================================================================ lane 19 L19-12 (FD-4I)
import pytest  # noqa: E402

from shared.access_policy import PlatformRole, parse_platform_role  # noqa: E402


def _vending_engine():
    db, sm = MagicMock(), MagicMock()
    return ProjectRepoVendingEngine(platform_project_id="host-p", firestore_client=db, secret_client=sm,
                                    crm_service=MagicMock(), billing_service=MagicMock(), storage_client=MagicMock())


ROLE_TABLE = ["ADMIN", "admin", " admin ", "Admin", "NON_ADMIN", "ADMIN_PENDING", "SUBADMIN", "ADMINS", "VIEWER",
              "WORKLOAD_MANAGER", "", None, 0, "A D M I N"]


@pytest.mark.parametrize("raw", ROLE_TABLE)
def test_vending_role_check_matches_parse_platform_role(raw):
    eng = _vending_engine()
    assert eng.is_platform_admin_role(raw) is (parse_platform_role(raw) is PlatformRole.ADMIN)


def test_vending_admin_members_exact_role_only_no_env_no_creator(monkeypatch):
    monkeypatch.setenv("ADMIN_USER_EMAIL", "env@example.com")
    monkeypatch.setenv("ADMIN_EMAIL", "env2@example.com")
    eng = _vending_engine()
    docs = []
    for email, role, active in (("a@example.com", "ADMIN", True), ("b@example.com", "NON_ADMIN", True),
                                ("c@example.com", "ADMIN_PENDING", True), ("d@example.com", "SUBADMIN", True),
                                ("e@example.com", "ADMIN", False)):
        d = MagicMock()
        d.id = email
        d.to_dict.return_value = {"email": email, "role": role, "is_active": active}
        docs.append(d)
    eng.db.collection.return_value.stream.return_value = docs
    assert eng.get_platform_admin_members() == ["user:a@example.com"]


def test_vending_fetch_oauth_credentials_fails_closed(monkeypatch):
    monkeypatch.setenv("OAUTH_CLIENT_ID", "env-id")
    monkeypatch.setenv("OAUTH_CLIENT_SECRET", "env-secret")
    eng = _vending_engine()
    eng.secret_client.access_secret_version.side_effect = RuntimeError("denied")
    with pytest.raises(RuntimeError) as ei:
        eng.fetch_oauth_credentials()
    assert "env-" not in str(ei.value)
    empty = MagicMock()
    empty.payload.data = b"  "
    eng.secret_client.access_secret_version.side_effect = None
    eng.secret_client.access_secret_version.return_value = empty
    with pytest.raises(RuntimeError):
        eng.fetch_oauth_credentials()
    eng.platform_project_id = ""
    with pytest.raises(RuntimeError):
        eng.fetch_oauth_credentials()


def test_vending_fetch_oauth_credentials_happy_path_unchanged():
    eng = _vending_engine()
    ok = MagicMock()
    ok.payload.data = b"value-1\n"
    eng.secret_client.access_secret_version.return_value = ok
    assert eng.fetch_oauth_credentials() == {"client_id": "value-1", "client_secret": "value-1"}


if __name__ == "__main__":
    unittest.main()

