"""FALLBACK-URLS (fail-loudly 1.4, invariant 3), Control Center side: the Serverless Git server URL comes only from a
typed source (GIT_SERVER_URL / CASTOR_GIT_SERVER_URL env set by the platform Terraform, the platform setting
governance.git_server_url, or a Cloud Run Admin API lookup); unknown -> None and the details API reports
GIT_SERVER_URL_UNKNOWN, never a URL built from the project id and a fixed region. Hermetic: no network, no ADC.
(The details endpoint itself is covered end to end in cc_portal_harness.py, test_get_workload_details_serverless_git.)
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
from types import SimpleNamespace

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")

GIT_URL = "https://castor-git-server-abc123-uc.a.run.app"


@pytest.fixture
def rs(monkeypatch):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    monkeypatch.setattr(cc_db, "_db_client", False)
    from routes import settings as mod
    monkeypatch.delenv("GIT_SERVER_URL", raising=False)
    monkeypatch.delenv("CASTOR_GIT_SERVER_URL", raising=False)
    monkeypatch.setattr(mod, "_CACHED_GIT_SERVER_URL", None)
    monkeypatch.setattr(mod, "get_platform_settings",
                        lambda *a, **k: SimpleNamespace(git_server_url=None, governance=SimpleNamespace(git_server_url=None)))
    lookups = []

    def _no_lookup(service):
        lookups.append(service)
        return None
    monkeypatch.setattr(mod, "_discover_cloud_run_service_url", _no_lookup)
    monkeypatch.setattr(mod, "_test_lookups", lookups, raising=False)
    return mod


def test_negative_the_env_url_is_used_unchanged(rs, monkeypatch):
    monkeypatch.setenv("GIT_SERVER_URL", GIT_URL + "/")
    assert rs.get_git_server_url() == GIT_URL
    assert rs._test_lookups == []                            # a configured URL needs no lookup


def test_castor_git_server_url_env_wins(rs, monkeypatch):
    monkeypatch.setenv("GIT_SERVER_URL", "https://other.example.test")
    monkeypatch.setenv("CASTOR_GIT_SERVER_URL", GIT_URL)
    assert rs.get_git_server_url() == GIT_URL


def test_the_platform_setting_is_used_when_env_is_unset(rs, monkeypatch):
    monkeypatch.setattr(rs, "get_platform_settings",
                        lambda *a, **k: SimpleNamespace(git_server_url=GIT_URL + "/", governance=None))
    assert rs.get_git_server_url() == GIT_URL and rs._test_lookups == []


def test_the_cloud_run_lookup_is_used_and_cached(rs, monkeypatch):
    calls = []

    def _found(service):
        calls.append(service)
        return GIT_URL
    monkeypatch.setattr(rs, "_discover_cloud_run_service_url", _found)
    assert rs.get_git_server_url() == GIT_URL
    assert rs.get_git_server_url() == GIT_URL
    assert calls == ["castor-git-server"]                    # the real service name, looked up once


def test_unknown_url_is_none_never_a_guessed_one(rs, monkeypatch):
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project")
    assert rs.get_git_server_url() is None
    assert rs._test_lookups == ["castor-git-server"]


def test_unreadable_platform_settings_fall_through_to_the_lookup_not_a_guess(rs, monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("settings store down")
    monkeypatch.setattr(rs, "get_platform_settings", _boom)
    assert rs.get_git_server_url() is None


def test_the_lookup_off_cloud_run_never_calls_the_api(monkeypatch):
    """The real `_discover_cloud_run_service_url` does nothing without K_SERVICE (no ADC, no network)."""
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    from routes import settings as mod
    monkeypatch.delenv("K_SERVICE", raising=False)
    assert mod._discover_cloud_run_service_url("castor-git-server") is None


def test_no_fabricated_git_server_url_is_left_in_the_details_route():
    src = open(os.path.join(CC_DIR, "routes", "workloads.py"), encoding="utf-8").read()
    assert "castor-git-server-{" not in src and ".us-central1.run.app" not in src
    assert "http://castor-git-server:8080" not in src
    html = open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8").read()
    assert "window.location.origin + '/git/'" not in html    # the dashboard copies only the API's clone URL
