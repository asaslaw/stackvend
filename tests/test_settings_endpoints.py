"""
Project Castor: Unit Tests for Control Center Platform Settings Endpoints
Tests GET /api/settings, PUT /api/settings, POST /api/settings/reset-defaults, role authorization, and audit trail generation.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import os
import sys
import unittest
from unittest.mock import MagicMock, patch

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
cc_dir = os.path.join(repo_root, "apps", "control-center")
sys.path.insert(0, repo_root)
sys.path.insert(0, cc_dir)

# Mock external cloud clients and frameworks before imports if needed
for mod in [
    "google", "google.auth", "google.auth.transport", "google.auth.transport.requests",
    "google.oauth2", "google.oauth2.id_token", "googleapiclient", "google.cloud",
    "google.cloud.firestore", "google.cloud.storage", "google.cloud.logging",
    "google.cloud.logging_v2", "google.cloud.pubsub_v1", "starlette", "starlette.middleware",
    "starlette.middleware.base"
]:
    if mod not in sys.modules:
        sys.modules[mod] = MagicMock()


class MockHTTPException(Exception):
    def __init__(self, status_code: int, detail: str = ""):
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"{status_code}: {detail}")


def mock_decorator(*args, **kwargs):
    def inner(fn):
        return fn
    return inner


mock_app = MagicMock()
mock_app.get = mock_decorator
mock_app.post = mock_decorator
mock_app.put = mock_decorator
mock_app.delete = mock_decorator
mock_app.patch = mock_decorator

mock_fastapi = MagicMock()
mock_fastapi.HTTPException = MockHTTPException
mock_fastapi.FastAPI = lambda *args, **kwargs: mock_app
mock_fastapi.Request = MagicMock
mock_fastapi.Response = MagicMock
sys.modules["fastapi"] = mock_fastapi

mock_responses = MagicMock()
mock_responses.HTMLResponse = MagicMock
mock_responses.JSONResponse = MagicMock
mock_responses.RedirectResponse = MagicMock
sys.modules["fastapi.responses"] = mock_responses

try:
    import pydantic
except ImportError:
    class MockFieldInfo:
        def __init__(self, default=None, default_factory=None):
            self.default = default
            self.default_factory = default_factory
        def get_value(self):
            if self.default_factory is not None:
                return self.default_factory()
            return self.default

    class MockBaseModel:
        def __init__(self, **kwargs):
            for cls in reversed(self.__class__.__mro__):
                for k, v in cls.__dict__.items():
                    if not k.startswith('_') and not callable(v):
                        default_val = v.get_value() if isinstance(v, MockFieldInfo) else v
                        if default_val is not Ellipsis:
                            setattr(self, k, default_val)
            for k, v in kwargs.items():
                curr = getattr(self, k, None)
                if isinstance(curr, MockBaseModel) and isinstance(v, dict):
                    setattr(self, k, curr.__class__(**v))
                else:
                    setattr(self, k, v)

        def model_dump(self):
            res = {}
            for k, v in self.__dict__.items():
                if not k.startswith('_'):
                    if hasattr(v, 'model_dump'):
                        res[k] = v.model_dump()
                    elif isinstance(v, list):
                        res[k] = [item.model_dump() if hasattr(item, 'model_dump') else item for item in v]
                    elif isinstance(v, dict):
                        res[k] = {ik: (iv.model_dump() if hasattr(iv, 'model_dump') else iv) for ik, iv in v.items()}
                    else:
                        res[k] = v
            return res

        def dict(self):
            return self.model_dump()

    mock_pydantic = MagicMock()
    mock_pydantic.BaseModel = MockBaseModel
    mock_pydantic.Field = lambda default=None, default_factory=None, **kwargs: MockFieldInfo(default=default, default_factory=default_factory)
    mock_pydantic.EmailStr = str
    sys.modules['pydantic'] = mock_pydantic

_cc_main_spec = importlib.util.spec_from_file_location("cc_main", os.path.join(cc_dir, "main.py"))
cc_main = importlib.util.module_from_spec(_cc_main_spec)
_cc_main_spec.loader.exec_module(cc_main)

from shared.settings import PlatformSettings, invalidate_settings_cache


class TestSettingsEndpoints(unittest.TestCase):
    def setUp(self):
        invalidate_settings_cache()

    def tearDown(self):
        invalidate_settings_cache()

    def test_get_settings_endpoint(self):
        # FD-4AK: a fresh install (no settings document) reads as the defaults; an unreadable or invalid document is
        # a 503 now (tests/test_fd4ak_settings_fail_closed.py), so this test states the "no document" store explicitly.
        absent = MagicMock()
        absent.exists = False
        fake_client = MagicMock()
        fake_client.collection.return_value.document.return_value.get.return_value = absent
        with patch("google.cloud.firestore.Client", return_value=fake_client):
            res = cc_main.get_settings_api(force=True)
        self.assertIsInstance(res, PlatformSettings)
        self.assertEqual(res.finops.default_monthly_budget_usd, 40.0)
        self.assertEqual(res.orchestration.terraform_lock_timeout_seconds, 180)

    def test_update_settings_admin_required(self):
        payload = PlatformSettings()
        payload.finops.default_monthly_budget_usd = 60.0

        mock_req = MagicMock()
        mock_req.state.user_role = cc_main.UserRole.VIEWER
        mock_req.state.user_email = "viewer@example.com"

        # When not in test mode, non-admin should raise 403
        with patch.dict(os.environ, {"TEST_MODE": ""}):
            with self.assertRaises(MockHTTPException) as ctx:
                cc_main.update_settings_api(payload, mock_req)
            self.assertEqual(ctx.exception.status_code, 403)

    def test_update_settings_success_and_audit(self):
        mock_req = MagicMock()
        mock_req.state.user_role = cc_main.UserRole.ADMIN
        mock_req.state.user_email = "admin@example.com"

        new_settings = PlatformSettings()
        new_settings.finops.default_monthly_budget_usd = 85.0
        new_settings.orchestration.terraform_lock_timeout_seconds = 240

        mock_db = MagicMock()
        mock_firestore_doc = MagicMock()
        mock_db.collection.return_value.document.return_value = mock_firestore_doc
        from settings_write_fake import wire_settings_writes
        wire_settings_writes(mock_db, mock_firestore_doc, source=lambda: (False, None))   # FD-4CI-b-R3: no document
        with patch.object(cc_main, "db", mock_db):
            res = cc_main.update_settings_api(new_settings, mock_req)

            self.assertEqual(res.finops.default_monthly_budget_usd, 85.0)
            self.assertEqual(res.orchestration.terraform_lock_timeout_seconds, 240)
            self.assertEqual(res.updated_by, "admin@example.com")
            self.assertIsNotNone(res.updated_at)
            self.assertEqual(len(res.audit_log), 1)
            self.assertEqual(res.audit_log[0].admin_email, "admin@example.com")
            self.assertIn("finops.default_monthly_budget_usd", res.audit_log[0].changed_fields)
            self.assertIn("orchestration.terraform_lock_timeout_seconds", res.audit_log[0].changed_fields)

            mock_db.collection.assert_called_with("system_config")
            mock_firestore_doc.set.assert_called_once()

    def test_reset_defaults_endpoint(self):
        mock_req = MagicMock()
        mock_req.state.user_role = cc_main.UserRole.ADMIN
        mock_req.state.user_email = "admin@example.com"

        mock_db = MagicMock()
        mock_firestore_doc = MagicMock()
        mock_db.collection.return_value.document.return_value = mock_firestore_doc
        with patch.object(cc_main, "db", mock_db):
            res = cc_main.reset_settings_defaults_api(mock_req)

            self.assertEqual(res.finops.default_monthly_budget_usd, 40.0)
            self.assertEqual(res.version, 2)
            self.assertEqual(len(res.audit_log), 1)
            self.assertEqual(res.audit_log[0].action, "RESET_DEFAULTS")

    def test_get_vcs_status_endpoint_no_credentials(self):
        mock_req = MagicMock()
        mock_mgr = MagicMock()
        mock_mgr._get_credentials.return_value = {
            "app_id": "",
            "installation_id": "",
            "private_key": "",
            "pat": "",
        }
        with patch.object(cc_main, "get_token_manager", return_value=mock_mgr), \
             patch.object(cc_main, "get_github_token", return_value=""), \
             patch.dict(os.environ, {"GITHUB_PAT": "", "GITHUB_TOKEN": "", "GITHUB_APP_ID": "", "GITHUB_APP_PRIVATE_KEY": "", "VCS_PROVIDER": "GITHUB"}, clear=True):
            res = cc_main.get_vcs_status_api(mock_req)
            self.assertEqual(res["provider"], "GITHUB")
            self.assertEqual(res["ui_icon"], "🐙")
            self.assertFalse(res["is_healthy"])
            self.assertFalse(res["has_credentials"])
            self.assertIn("No GitHub credentials", res["error_message"])

    def test_get_vcs_status_endpoint_github_healthy(self):
        mock_req = MagicMock()
        import json
        rl_payload = json.dumps({
            "resources": {
                "core": {
                    "limit": 5000,
                    "remaining": 4985,
                    "reset": 1800000000,
                }
            }
        }).encode("utf-8")
        user_payload = json.dumps({"login": "castor-bot[bot]"}).encode("utf-8")

        mock_rl_response = MagicMock()
        mock_rl_response.status = 200
        mock_rl_response.read.return_value = rl_payload
        mock_rl_response.__enter__.return_value = mock_rl_response

        mock_user_response = MagicMock()
        mock_user_response.status = 200
        mock_user_response.read.return_value = user_payload
        mock_user_response.__enter__.return_value = mock_user_response

        with patch.object(cc_main, "get_github_token", return_value="ghp_mock_token_123"), \
             patch("urllib.request.urlopen", side_effect=[mock_rl_response, mock_user_response]), \
             patch.dict(os.environ, {"GITHUB_PAT": "ghp_mock_token_123", "VCS_PROVIDER": "GITHUB"}):
            res = cc_main.get_vcs_status_api(mock_req)
            self.assertEqual(res["provider"], "GITHUB")
            self.assertTrue(res["is_healthy"])
            self.assertTrue(res["has_credentials"])
            self.assertEqual(res["rate_limit"]["limit"], 5000)
            self.assertEqual(res["rate_limit"]["remaining"], 4985)
            self.assertEqual(res["authenticated_as"], "castor-bot[bot]")

    def _vcs_status_with_owner(self, owner_answer):
        """GITHUB-ORG-ONLY: rate limit + /user answer healthy, then `owner_answer` for GET /users/{owner}."""
        import json
        responses = []
        for payload in ({"resources": {"core": {"limit": 5000, "remaining": 4985, "reset": 1800000000}}},
                        {"login": "stackvend-app[bot]"}):
            r = MagicMock()
            r.status = 200
            r.read.return_value = json.dumps(payload).encode("utf-8")
            r.__enter__.return_value = r
            responses.append(r)
        if isinstance(owner_answer, Exception):
            responses.append(owner_answer)
        else:
            r = MagicMock()
            r.status = 200
            r.read.return_value = json.dumps(owner_answer).encode("utf-8")
            r.__enter__.return_value = r
            responses.append(r)
        settings_mod = sys.modules[cc_main.get_vcs_status_api.__module__]
        with patch.object(cc_main, "get_github_token", return_value="ghs_mock_token"), \
             patch.object(settings_mod, "get_default_github_owner", return_value="someone"), \
             patch("urllib.request.urlopen", side_effect=responses) as opened, \
             patch.dict(os.environ, {"GITHUB_PAT": "ghs_mock_token", "VCS_PROVIDER": "GITHUB"}):
            res = cc_main.get_vcs_status_api(MagicMock())
        self.assertEqual(opened.call_args_list[2].args[0].full_url, "https://api.github.com/users/someone")
        return res

    def test_get_vcs_status_personal_account_owner_is_a_typed_error(self):
        res = self._vcs_status_with_owner({"login": "someone", "type": "User"})
        self.assertFalse(res["is_healthy"])
        self.assertEqual(res["target_owner_type"], "User")
        self.assertEqual(res["error_code"], "GITHUB_OWNER_NOT_ORGANIZATION")
        self.assertIn("GitHub VCS needs an organization", res["error_message"])
        self.assertIn("personal GitHub account", res["error_message"])

    def test_get_vcs_status_unknown_owner_is_a_typed_error(self):
        import urllib.error
        res = self._vcs_status_with_owner(urllib.error.HTTPError("u", 404, "Not Found", {}, None))
        self.assertFalse(res["is_healthy"])
        self.assertEqual(res["target_owner_type"], "NOT_FOUND")
        self.assertEqual(res["error_code"], "GITHUB_OWNER_NOT_ORGANIZATION")

    def test_get_vcs_status_organization_owner_stays_healthy(self):
        res = self._vcs_status_with_owner({"login": "someone", "type": "Organization"})
        self.assertTrue(res["is_healthy"])
        self.assertEqual(res["target_owner_type"], "Organization")
        self.assertEqual(res["error_code"], "")

    def test_get_vcs_status_owner_lookup_failure_gives_no_verdict(self):
        import urllib.error
        res = self._vcs_status_with_owner(urllib.error.HTTPError("u", 500, "err", {}, None))
        self.assertTrue(res["is_healthy"])
        self.assertEqual(res["target_owner_type"], "")
        self.assertEqual(res["error_code"], "")

    def test_get_vcs_status_endpoint_serverless_git(self):
        mock_req = MagicMock()
        # FD-05 B-12: the route reads the import-time constant routes.settings.PROJECT_ID (from config) before
        # os.environ, so patch that binding (patching only the env failed alone and depended on run order).
        settings_mod = sys.modules[cc_main.get_vcs_status_api.__module__]
        with patch.dict(os.environ, {"VCS_PROVIDER": "SERVERLESS_GIT", "PROJECT_ID": "my-gcp-proj"}), \
                patch.object(settings_mod, "PROJECT_ID", "my-gcp-proj"):
            res = cc_main.get_vcs_status_api(mock_req)
            self.assertEqual(res["provider"], "SERVERLESS_GIT")
            self.assertEqual(res["ui_icon"], "☁️")
            self.assertTrue(res["is_healthy"])
            self.assertEqual(res["auth_mode"], "GCP_IAM")
            self.assertEqual(res["target_owner"], "my-gcp-proj")

    def test_platform_settings_vcs_provider_dynamic_default(self):
        from shared.settings import PlatformSettings, GovernanceSettings

        # When VCS_PROVIDER is set to SERVERLESS_GIT in container environment
        with patch.dict(os.environ, {"VCS_PROVIDER": "SERVERLESS_GIT"}):
            settings = PlatformSettings()
            self.assertEqual(settings.vcs_provider, "SERVERLESS_GIT")
            self.assertEqual(settings.governance.vcs_provider, "SERVERLESS_GIT")

        # When VCS_PROVIDER is unset, defaults to GITHUB
        with patch.dict(os.environ, {}, clear=True):
            settings_default = PlatformSettings()
            self.assertEqual(settings_default.vcs_provider, "GITHUB")
            self.assertEqual(settings_default.governance.vcs_provider, "GITHUB")

        # When Firestore explicitly overrides vcs_provider
        settings_override = PlatformSettings(governance={"vcs_provider": "SERVERLESS_GIT"})
        self.assertEqual(settings_override.vcs_provider, "SERVERLESS_GIT")


if __name__ == "__main__":
    unittest.main()
