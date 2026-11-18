"""VENDING-POLL-TRANSIENT (register row, owner 10-30): vending polls long-running operations (Resource Manager
project / folder create, Service Usage batchEnable) with operations.get, an idempotent read. A poll that fails with a
TRANSIENT error (TimeoutError incl. socket.timeout, ConnectionError subclasses, HttpError 429/500/502/503/504) is polled
again within the existing deadline and backoff; anything else fails at once, unchanged. Typed by exception class and
HTTP status only, never by message text.

Live failure this covers (second dev install, 10-30): one CRM poll raised TimeoutError ("The read operation timed out", ssl
read inside httplib2) and failed the whole vend although the project was created.

Negative: a clean first poll is unchanged (one call, no sleep, no warning); a not-done-then-done poll keeps its backoff.
Hermetic: the Resource Manager and Service Usage clients are fakes; the clock is fake."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import logging
import os
import socket
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

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

import vending  # noqa: E402
from vending import ProjectRepoVendingEngine  # noqa: E402


class HttpError(Exception):
    """Shape of googleapiclient.errors.HttpError (resp.status from the httplib2 Response). Patched in as
    vending.HttpError, because other test modules may have stubbed googleapiclient out before this one runs."""

    def __init__(self, status, content=b""):
        super().__init__(f"<HttpError {status}>")
        self.resp = SimpleNamespace(status=status, reason="r")
        self.content = content


class ServerNotFoundError(Exception):
    """Shape of httplib2.ServerNotFoundError (an HttpLib2Error, not an OSError): DNS failure, not transient."""


_HttpError = HttpError
_ServerNotFoundError = ServerNotFoundError


class _Clock:
    def __init__(self):
        self.now = 1000.0
        self.sleeps = []

    def time(self):
        return self.now

    def sleep(self, s):
        self.sleeps.append(s)
        self.now += s


class _Call:
    def __init__(self, fn):
        self.fn = fn

    def execute(self):
        return self.fn()


class _Ops:
    """operations().get(name).execute() answers the next scripted item (an exception is raised); the last item
    repeats. Counts calls."""

    def __init__(self, *script):
        self.script = list(script)
        self.calls = 0

    def operations(self):
        return self

    def get(self, name):
        def run():
            self.calls += 1
            item = self.script.pop(0) if len(self.script) > 1 else self.script[0]
            if isinstance(item, BaseException):
                raise item
            return item
        return _Call(run)


DONE = {"name": "operations/cp.1", "done": True, "response": {"name": "projects/123"}}
NOT_DONE = {"name": "operations/cp.1"}


@pytest.fixture(autouse=True)
def _fakes():
    clock = _Clock()
    with patch.object(vending, "time", SimpleNamespace(time=clock.time, sleep=clock.sleep)), \
            patch.object(vending, "HttpError", _HttpError):
        yield clock


def _engine(crm):
    return ProjectRepoVendingEngine(platform_project_id="host-platform", firestore_client=MagicMock(),
                                    secret_client=MagicMock(), crm_service=crm, billing_service=MagicMock(),
                                    storage_client=MagicMock())


# ------------------------------------------------------------------------------------------------ classifier
@pytest.mark.parametrize("err", [
    TimeoutError("The read operation timed out"),
    socket.timeout("timed out"),
    ConnectionResetError(54, "Connection reset by peer"),
    ConnectionAbortedError(),
    ConnectionRefusedError(),
    BrokenPipeError(),
    _HttpError(429), _HttpError(500), _HttpError(502), _HttpError(503), _HttpError(504),
])
def test_transient_errors_are_typed_by_class_and_status(err):
    assert vending._is_transient_poll_error(err) is True


@pytest.mark.parametrize("err", [
    _HttpError(400), _HttpError(401), _HttpError(403), _HttpError(404), _HttpError(409), _HttpError(501),
    _HttpError(None), _ServerNotFoundError("Unable to find the server"), ValueError("x"), OSError("disk"),
    # no message-text matching: these messages read like a timeout / reset but their classes are not transient
    RuntimeError("The read operation timed out"), Exception("Connection reset by peer 503"),
])
def test_non_transient_errors_are_not_retried(err):
    assert vending._is_transient_poll_error(err) is False


def test_classifier_is_safe_when_httperror_is_stubbed_out():
    with patch.object(vending, "HttpError", MagicMock()):
        assert vending._is_transient_poll_error(_HttpError(503)) is False
        assert vending._is_transient_poll_error(TimeoutError()) is True


# ------------------------------------------------------------------------------------------------ CRM wait
def test_negative_clean_first_poll_is_unchanged(_fakes, caplog):
    crm = _Ops(DONE)
    with caplog.at_level(logging.WARNING, logger=vending.logger.name):
        assert _engine(crm)._wait_for_crm_operation("operations/cp.1") == DONE
    assert crm.calls == 1
    assert _fakes.sleeps == []
    assert "VENDING_POLL_TRANSIENT" not in caplog.text


def test_negative_not_done_then_done_keeps_backoff(_fakes):
    crm = _Ops(NOT_DONE, NOT_DONE, DONE)
    assert _engine(crm)._wait_for_crm_operation("operations/cp.1") == DONE
    assert crm.calls == 3
    assert _fakes.sleeps == [1.0, 1.5]


def test_one_transient_timeout_then_done_succeeds(_fakes, caplog):
    crm = _Ops(TimeoutError("The read operation timed out"), DONE)
    with caplog.at_level(logging.WARNING, logger=vending.logger.name):
        assert _engine(crm)._wait_for_crm_operation("operations/cp.1") == DONE
    assert crm.calls == 2
    assert _fakes.sleeps == [1.0]   # the existing backoff, unchanged
    warn = [r for r in caplog.records if "VENDING_POLL_TRANSIENT" in r.getMessage()]
    assert len(warn) == 1 and warn[0].levelno == logging.WARNING
    assert "TimeoutError" in warn[0].getMessage()
    assert "read operation" not in warn[0].getMessage()   # class name only, never the message text


def test_connection_reset_then_done_succeeds():
    crm = _Ops(ConnectionResetError(54, "reset"), NOT_DONE, DONE)
    assert _engine(crm)._wait_for_crm_operation("operations/cp.1") == DONE
    assert crm.calls == 3


@pytest.mark.parametrize("status", [429, 500, 502, 503, 504])
def test_http_5xx_or_429_then_done_succeeds(status, caplog):
    crm = _Ops(_HttpError(status), DONE)
    with caplog.at_level(logging.WARNING, logger=vending.logger.name):
        assert _engine(crm)._wait_for_crm_operation("operations/cp.1") == DONE
    assert crm.calls == 2
    assert f"HttpError {status}" in caplog.text


def test_repeated_transient_until_deadline_is_a_typed_timeout(_fakes):
    first = TimeoutError("t")
    crm = _Ops(first, ConnectionResetError(), _HttpError(503))   # the 503 repeats until the deadline
    with pytest.raises(TimeoutError) as ei:
        _engine(crm)._wait_for_crm_operation("operations/cp.1", max_wait_seconds=60)
    assert "timed out after 60s" in str(ei.value)
    assert "last poll error: HttpError" in str(ei.value)
    assert isinstance(ei.value.__cause__, _HttpError)
    assert crm.calls > 3
    assert sum(_fakes.sleeps) >= 60
    assert max(_fakes.sleeps) == 5.0   # existing backoff cap


def test_not_done_until_deadline_is_the_same_timeout_as_before(_fakes):
    crm = _Ops(NOT_DONE)
    with pytest.raises(TimeoutError) as ei:
        _engine(crm)._wait_for_crm_operation("operations/cp.1", max_wait_seconds=10)
    assert str(ei.value) == "GCP project creation operation 'operations/cp.1' timed out after 10s"
    assert ei.value.__cause__ is None


@pytest.mark.parametrize("status", [400, 403, 404])
def test_non_transient_http_error_fails_at_once(_fakes, status):
    err = _HttpError(status)
    crm = _Ops(err, DONE)
    with pytest.raises(_HttpError) as ei:
        _engine(crm)._wait_for_crm_operation("operations/cp.1")
    assert ei.value is err   # raised unchanged: vend_gcp_project's HttpError handling still sees it
    assert crm.calls == 1
    assert _fakes.sleeps == []


def test_non_transient_transport_error_fails_at_once(_fakes):
    crm = _Ops(_ServerNotFoundError("Unable to find the server at cloudresourcemanager.googleapis.com"), DONE)
    with pytest.raises(_ServerNotFoundError):
        _engine(crm)._wait_for_crm_operation("operations/cp.1")
    assert crm.calls == 1


def test_operation_error_still_raises_runtime_error(_fakes):
    crm = _Ops({"name": "operations/cp.1", "done": True, "error": {"code": 7, "message": "denied"}})
    with pytest.raises(RuntimeError, match="GCP Project creation operation failed"):
        _engine(crm)._wait_for_crm_operation("operations/cp.1")
    assert crm.calls == 1


def test_transient_then_operation_error_raises_runtime_error():
    crm = _Ops(TimeoutError(), {"name": "operations/cp.1", "done": True, "error": {"code": 7}})
    with pytest.raises(RuntimeError, match="GCP Project creation operation failed"):
        _engine(crm)._wait_for_crm_operation("operations/cp.1")
    assert crm.calls == 2


def test_create_folder_survives_a_transient_poll():
    crm = MagicMock()
    ops = _Ops(TimeoutError(), {"name": "operations/cf.1", "done": True, "response": {"name": "folders/42"}})
    crm.folders().create().execute.return_value = {"name": "operations/cf.1"}
    crm.operations.side_effect = ops.operations
    res = _engine(crm).create_folder("team-a", parent_folder_id="folders/1")
    assert "folders/42" in str(res)
    assert ops.calls == 2
    assert crm.folders().create.call_count == 2   # the create call itself (plus the setup call above) is not retried


# ------------------------------------------------------------------------------------------------ Service Usage wait
class _ServiceUsage(_Ops):
    def __init__(self, *script):
        super().__init__(*script)
        self.batches, self.enabled = [], []

    def services(self):
        return self

    def batchEnable(self, parent, body):
        def run():
            self.batches.append(list(body["serviceIds"]))
            return {"name": "operations/acf.1"}
        return _Call(run)

    def enable(self, name):
        def run():
            self.enabled.append(name)
            return {}
        return _Call(run)


def test_service_usage_transient_poll_then_done_is_enabled_without_fallback():
    su = _ServiceUsage(TimeoutError(), _HttpError(503), {"name": "operations/acf.1", "done": True})
    r = _engine(MagicMock()).enable_child_apis("child-1", serviceusage=su)
    assert r["status"] == "ENABLED" and r["failed"] == []
    assert su.calls == 3
    assert len(su.batches) == 1 and su.enabled == []


def test_negative_service_usage_clean_poll_is_unchanged(_fakes):
    su = _ServiceUsage({"name": "operations/acf.1", "done": True})
    r = _engine(MagicMock()).enable_child_apis("child-1", serviceusage=su)
    assert r["status"] == "ENABLED"
    assert su.calls == 1 and _fakes.sleeps == [] and su.enabled == []


def test_service_usage_transient_until_deadline_is_pending():
    su = _ServiceUsage(TimeoutError())
    r = _engine(MagicMock()).enable_child_apis("child-1", serviceusage=su)
    assert r["status"] == "PENDING" and r["failed"] == []
    assert su.enabled == []


def test_service_usage_non_transient_poll_error_takes_the_per_api_fallback():
    su = _ServiceUsage(_HttpError(403))
    r = _engine(MagicMock()).enable_child_apis("child-1", serviceusage=su)
    assert su.calls == 1
    assert len(su.enabled) == len(r["requested"])   # every id enabled on its own
    assert r["status"] == "ENABLED" and r["failed"] == []
