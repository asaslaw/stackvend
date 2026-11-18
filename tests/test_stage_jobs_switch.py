"""STAGE-JOB-RUNNER red team N1: the stage-runner rollback switch is a runtime setting (no code edit, no deploy, no
apply): env STAGE_JOBS_ENABLED on the gateway, else Firestore governance/stage_jobs.enabled (written by
scripts/stage-jobs-switch.sh), else the release default. /health reports it; the workflow reads /health before every
stage (sim tests in tests/test_long_stage_callback_workflow.py cover both paths). Hermetic."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import io
import json
import os
import sys

import pytest
from fastapi.testclient import TestClient

from fd4f_support import FakeDB, gw  # noqa: F401  (gw is a fixture)

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GW_DIR = os.path.join(REPO, "apps", "orchestrator-gateway")
if GW_DIR not in sys.path:
    sys.path.insert(0, GW_DIR)

import stage_jobs  # noqa: E402

_spec = importlib.util.spec_from_file_location("stage_jobs_switch_cli",
                                               os.path.join(REPO, "scripts", "common", "stage_jobs_switch.py"))
cli = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cli)


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.delenv("STAGE_JOBS_ENABLED", raising=False)
    stage_jobs._switch_cache.clear()
    yield
    stage_jobs._switch_cache.clear()


def _health(gw, db):
    gw.app.dependency_overrides[gw.get_governance_db] = lambda: db
    return TestClient(gw.app).get("/health").json()


def test_default_is_the_release_default(gw):
    h = _health(gw, FakeDB())
    assert h["stage_jobs_enabled"] is stage_jobs.STAGE_JOBS_DEFAULT_ENABLED and h["stage_jobs_switch"] == "DEFAULT"


def test_setting_off_turns_the_jobs_off_without_a_deploy(gw):
    db = FakeDB()
    db.docs["governance/stage_jobs"] = {"enabled": False, "set_by": "op@example.com"}
    h = _health(gw, db)
    assert h["stage_jobs_enabled"] is False and h["stage_jobs_switch"] == "SETTING"


def test_env_wins_over_the_setting(gw, monkeypatch):
    db = FakeDB()
    db.docs["governance/stage_jobs"] = {"enabled": False}
    monkeypatch.setenv("STAGE_JOBS_ENABLED", "true")
    h = _health(gw, db)
    assert h["stage_jobs_enabled"] is True and h["stage_jobs_switch"] == "ENV"


def test_malformed_setting_is_the_default(gw):
    db = FakeDB()
    db.docs["governance/stage_jobs"] = {"enabled": "false"}
    assert _health(gw, db)["stage_jobs_switch"] == "DEFAULT"


def test_unreadable_setting_keeps_the_default_and_says_so(gw):
    db = FakeDB()
    db.fail_reads = True
    h = _health(gw, db)
    assert h["stage_jobs_enabled"] is stage_jobs.STAGE_JOBS_DEFAULT_ENABLED
    assert h["stage_jobs_switch"] == "ERROR"


def test_read_error_keeps_the_last_good_value_not_the_default():
    """N7: an operator's "off" survives a Firestore read error (never 15 s of "on")."""
    db = FakeDB()
    db.docs["governance/stage_jobs"] = {"enabled": False}
    t = [100.0]
    assert stage_jobs.stage_jobs_switch(db, clock=lambda: t[0]) == {"enabled": False, "source": "SETTING"}
    db.fail_reads = True
    t[0] += stage_jobs.SWITCH_CACHE_S + 1
    assert stage_jobs.stage_jobs_switch(db, clock=lambda: t[0]) == {"enabled": False, "source": "CACHED"}
    t[0] += stage_jobs.SWITCH_CACHE_S + 1
    assert stage_jobs.stage_jobs_switch(db, clock=lambda: t[0])["enabled"] is False
    db.fail_reads = False
    db.docs["governance/stage_jobs"] = {"enabled": True}
    t[0] += stage_jobs.SWITCH_CACHE_S + 1
    assert stage_jobs.stage_jobs_switch(db, clock=lambda: t[0]) == {"enabled": True, "source": "SETTING"}


def test_setting_is_cached_briefly():
    db = FakeDB()
    db.docs["governance/stage_jobs"] = {"enabled": False}
    t = [100.0]
    assert stage_jobs.stage_jobs_switch(db, clock=lambda: t[0])["enabled"] is False
    db.docs["governance/stage_jobs"] = {"enabled": True}
    assert stage_jobs.stage_jobs_switch(db, clock=lambda: t[0])["enabled"] is False
    t[0] += stage_jobs.SWITCH_CACHE_S + 1
    assert stage_jobs.stage_jobs_switch(db, clock=lambda: t[0])["enabled"] is True


# ------------------------------------------------------------------------------------------------ operator CLI
class Http:
    def __init__(self, answers):
        self.answers, self.calls = list(answers), []

    def __call__(self, method, url, body=None):
        self.calls.append((method, url, json.loads(body) if body else None))
        return self.answers.pop(0)


def test_cli_off_writes_the_setting_the_gateway_reads():
    http = Http([(200, {"fields": {"enabled": {"booleanValue": False}}})])
    rc = cli.main(["set", "--project", "p1", "--state", "off", "--set-by", "op@example.com", "--token-stdin"],
                  http_factory=lambda token, project: http, stdin=io.StringIO("tok\n"))
    assert rc == 0
    method, url, body = http.calls[0]
    assert method == "PATCH"
    assert url.startswith("https://firestore.googleapis.com/v1/projects/p1/databases/(default)/documents/"
                          f"{stage_jobs.SWITCH_COLLECTION}/{stage_jobs.SWITCH_DOCUMENT}?")
    assert body["fields"]["enabled"] == {"booleanValue": False}
    assert body["fields"]["set_by"] == {"stringValue": "op@example.com"}


def test_cli_fails_loudly_on_a_refused_write_or_no_token():
    http = Http([(403, {"error": "denied"})])
    assert cli.main(["set", "--project", "p1", "--state", "off", "--token-stdin"],
                    http_factory=lambda t, p: http, stdin=io.StringIO("tok\n")) == 1
    assert cli.main(["status", "--project", "p1", "--token-stdin"], http_factory=lambda t, p: Http([]),
                    stdin=io.StringIO("\n")) == 1


def test_cli_status(capsys):
    assert cli.main(["status", "--project", "p1", "--token-stdin"], http_factory=lambda t, p: Http([(404, None)]),
                    stdin=io.StringIO("tok\n")) == 0
    assert "unset" in capsys.readouterr().out



def test_health_reads_the_switch_with_a_short_timeout_and_never_fails(gw):
    """N8: the switch read is bounded (2 s); a timeout is reported, /health still answers 200."""
    seen = {}

    class SlowDoc:
        def get(self, timeout=None):
            seen["timeout"] = timeout
            raise TimeoutError("Deadline Exceeded")

    class SlowCol:
        def document(self, name):
            return SlowDoc()

    class SlowDB:
        def collection(self, name):
            return SlowCol()
    gw.app.dependency_overrides[gw.get_governance_db] = lambda: SlowDB()
    r = TestClient(gw.app).get("/health")
    assert r.status_code == 200 and r.json()["stage_jobs_switch"] == "ERROR"
    assert seen["timeout"] == stage_jobs.SWITCH_READ_TIMEOUT_S == 2.0
