"""FD-7L Phase 2a (SAT-27): mcp-servers/terraform/runner_credentials.py -- brokered credentials, the per-workspace local
metadata endpoint, the tofu environment allow-list, the signed-provenance target check and the mode log line.

Plan rev 3 section 2.4 and section 6 "Runner". Hermetic: a fake broker, a fake clock, a real loopback HTTP server for
the endpoint, real short-lived local processes for SIGINT; signatures with tests/fd7l_fakes.py's real RSA key.
"""
import hermetic_guard  # noqa: E402  (must stay the first import: tests/hermetic_guard.py)

import http.client
import json
import logging
import os
import signal
import subprocess
import sys
import time

import pytest

from fd4g_support import load_module, real_modules
import fd7l_fakes as fk

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO, "mcp-servers", "terraform")
CHILD = "claims-prod-1a2b"
PRODUCT = "claims"
DEPLOYER = f"stackvend-deployer@{CHILD}.iam.gserviceaccount.com"
BUCKET = f"{CHILD}-tfstate"
NONCE = "n" * 43                         # test value only
SESSION_KEY = "a" * 64 + "." + "s" * 43  # test value only
TOKEN = "ya29.test-only-deployer-token"  # test value only


@pytest.fixture
def rc(monkeypatch):
    real_modules(monkeypatch)
    monkeypatch.syspath_prepend(TF_DIR)
    return load_module(monkeypatch, "runner_credentials", os.path.join(TF_DIR, "runner_credentials.py"))


@pytest.fixture
def ri():
    from shared import runner_identity
    return runner_identity


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t


class FakeBroker:
    """deployer_token answers a 1 h token (expiry from the fake clock) unless `down` is set."""

    def __init__(self, rc, ri, clock, lifetime=3600.0):
        self.rc, self.ri, self.clock, self.lifetime = rc, ri, clock, lifetime
        self.down = False
        self.calls = 0

    def deployer_token(self, session_key):
        assert session_key == SESSION_KEY
        self.calls += 1
        if self.down:
            raise self.ri.RunnerIdentityError(self.rc.RUNNER_BROKER_UNAVAILABLE, "down", http_status=503)
        return f"{TOKEN}-{self.calls}", self.clock() + self.lifetime, {}


def _creds(rc, ri, clock=None, broker=None):
    clock = clock or Clock()
    broker = broker or FakeBroker(rc, ri, clock)
    return rc.BrokeredCredentials(broker, SESSION_KEY, project_id=CHILD, deployer_email=DEPLOYER, clock=clock), \
        broker, clock


# ------------------------------------------------------------------------------------------------ env allow-list
PINNED_NEVER = ["GITHUB_TOKEN", "RUNNER_NONCE", "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_OAUTH_ACCESS_TOKEN",
                "GOOGLE_CREDENTIALS", "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT",
                "GCE_METADATA_ROOT", "GCE_METADATA_HOST", "GCE_METADATA_IP", "TF_LOG", "TF_LOG_PATH",
                "TF_LOG_PROVIDER", "KUBECONFIG", "KUBE_CONFIG_PATH", "KUBE_TOKEN", "PROJECT_ID", "TFSTATE_BUCKET",
                "K_SERVICE", "CLOUD_RUN_JOB", "CLOUD_RUN_EXECUTION", "GOOGLE_BILLING_PROJECT",
                "GOOGLE_CLOUD_QUOTA_PROJECT", "SESSION_SECRET", "HOME", "TF_CLI_ARGS", "TF_CLI_ARGS_init"]


def test_tofu_base_env_inherits_exactly_the_allow_list(rc):
    environ = {name: "x" for name in PINNED_NEVER}
    environ.update(PATH="/usr/bin", LANG="C.UTF-8", TMPDIR="/tmp", TF_IN_AUTOMATION="1", TF_INPUT="0")
    out = rc.tofu_base_env(environ)
    assert out == {"PATH": "/usr/bin", "LANG": "C.UTF-8", "TMPDIR": "/tmp", "TF_IN_AUTOMATION": "1", "TF_INPUT": "0"}
    assert rc.tofu_base_env({}) == {}


# ------------------------------------------------------------------------------------------------ broker client
class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body

    def json(self):
        return self._body


def _client(rc, answers, sleeps=None):
    posts = []

    def post(url, json=None, headers=None, timeout=None):
        posts.append((url, json, headers))
        status, body = answers.pop(0)
        if isinstance(status, Exception):
            raise status
        return _Resp(status, body)

    client = rc.BrokerClient("https://vending.example.run.app", id_token=lambda aud: "id-token", post=post,
                             sleep=(sleeps.append if sleeps is not None else (lambda s: None)))
    return client, posts


def test_redeem_retries_an_unbound_dispatch_then_returns_record_and_session_key(rc, caplog):
    sleeps = []
    client, posts = _client(rc, [(409, {"detail": {"code": "RUNNER_DISPATCH_NOT_BOUND"}}),
                                 (503, {"detail": {"code": "X"}}),
                                 (200, {"record": {"product_id": PRODUCT}, "session_key": SESSION_KEY})], sleeps)
    with caplog.at_level(logging.DEBUG):
        record, key = client.redeem(NONCE, "projects/h/locations/r/jobs/tf-applier/executions/e1")
    assert record == {"product_id": PRODUCT} and key == SESSION_KEY and len(sleeps) == 2
    assert posts[0][0] == "https://vending.example.run.app/runner/redeem"
    assert posts[0][2] == {"Authorization": "Bearer id-token"}
    assert NONCE not in caplog.text and SESSION_KEY not in caplog.text


@pytest.mark.parametrize("answer,code", [
    ((409, {"detail": {"code": "RUNNER_NONCE_SPENT"}}), "RUNNER_NONCE_SPENT"),
    ((403, {"detail": {"code": "RUNNER_EXECUTION_MISMATCH"}}), "RUNNER_EXECUTION_MISMATCH"),
    ((410, {}), "RUNNER_BROKER_REFUSED"),
])
def test_redeem_refusal_is_the_brokers_typed_code_without_retry(rc, ri, answer, code):
    sleeps = []
    client, posts = _client(rc, [answer], sleeps)
    with pytest.raises(ri.RunnerIdentityError) as ei:
        client.redeem(NONCE, "e")
    assert ei.value.code == code and len(posts) == 1 and not sleeps


def test_broker_outage_is_runner_broker_unavailable_after_bounded_attempts(rc, ri):
    client, posts = _client(rc, [(ConnectionError("x"), None)] * rc.REDEEM_ATTEMPTS)
    with pytest.raises(ri.RunnerIdentityError) as ei:
        client.redeem(NONCE, "e")
    assert ei.value.code == rc.RUNNER_BROKER_UNAVAILABLE and len(posts) == rc.REDEEM_ATTEMPTS


# SAT-52: vending reads a just-started execution as not running yet -> bounded backoff, then the redeem proceeds.
_NOT_YET = (409, {"detail": {"code": "RUNNER_EXECUTION_NOT_YET_RUNNING", "stage": "runner-identity",
                             "detail": "the execution has not started running yet; retry shortly"}})


def test_redeem_retries_not_yet_running_then_proceeds(rc, caplog):
    sleeps = []
    client, posts = _client(rc, [_NOT_YET, _NOT_YET,
                                 (200, {"record": {"product_id": PRODUCT}, "session_key": SESSION_KEY})], sleeps)
    with caplog.at_level(logging.DEBUG):
        record, key = client.redeem(NONCE, "projects/h/locations/r/jobs/tf-applier/executions/e1")
    assert record == {"product_id": PRODUCT} and key == SESSION_KEY and len(posts) == 3
    assert sleeps == list(rc.REDEEM_NOT_YET_RUNNING_DELAYS_S[:2])
    assert caplog.text.count("RUNNER_EXECUTION_NOT_YET_RUNNING (runner-redeem)") == 2   # each retry is logged
    assert NONCE not in caplog.text and SESSION_KEY not in caplog.text


def test_redeem_not_yet_running_past_the_budget_is_typed(rc, ri):
    delays = rc.REDEEM_NOT_YET_RUNNING_DELAYS_S
    assert sum(delays) <= 90 < ri.REDEEM_WINDOW_SECONDS and rc.NOT_YET_RUNNING_STATUS == 409
    sleeps = []
    client, posts = _client(rc, [_NOT_YET] * (len(delays) + 1), sleeps)
    with pytest.raises(ri.RunnerIdentityError) as ei:
        client.redeem(NONCE, "e")
    assert (ei.value.code, ei.value.http_status, ei.value.stage) == \
        ("RUNNER_EXECUTION_NOT_YET_RUNNING", 409, "runner-redeem")
    assert f"after {len(delays)} retries" in ei.value.detail
    assert len(posts) == len(delays) + 1 and sleeps == list(delays)


@pytest.mark.parametrize("answer,code", [
    ((403, {"detail": {"code": "RUNNER_EXECUTION_NOT_RUNNING"}}), "RUNNER_EXECUTION_NOT_RUNNING"),   # ended
    ((403, {"detail": {"code": "RUNNER_EXECUTION_NOT_YET_RUNNING"}}), "RUNNER_EXECUTION_NOT_YET_RUNNING"),  # no 409
    ((409, {"detail": {"code": "RUNNER_EXECUTION_NOT_RUNNING"}}), "RUNNER_EXECUTION_NOT_RUNNING"),
    ((409, {"detail": "RUNNER_EXECUTION_NOT_YET_RUNNING"}), "RUNNER_BROKER_REFUSED"),   # message text: never classified
])
def test_redeem_only_the_typed_not_yet_running_409_is_retried(rc, ri, answer, code):
    sleeps = []
    client, posts = _client(rc, [answer], sleeps)
    with pytest.raises(ri.RunnerIdentityError) as ei:
        client.redeem(NONCE, "e")
    assert ei.value.code == code and ei.value.http_status == answer[0] and len(posts) == 1 and not sleeps


def test_redeem_not_yet_running_does_not_spend_the_unbound_budget(rc):
    """The two budgets are separate: NOT_YET_RUNNING retries, then NOT_BOUND retries, then the record."""
    client, posts = _client(rc, [_NOT_YET] * 3 + [(409, {"detail": {"code": "RUNNER_DISPATCH_NOT_BOUND"}})]
                            * (rc.REDEEM_ATTEMPTS - 1)
                            + [(200, {"record": {"product_id": PRODUCT}, "session_key": SESSION_KEY})])
    assert client.redeem(NONCE, "e")[1] == SESSION_KEY and len(posts) == 3 + rc.REDEEM_ATTEMPTS


def test_redeem_of_an_execution_that_ended_between_retries_is_the_ended_code_at_once(rc, ri):
    """SAT-52 RT LOW (retry gap): not-yet retries, then vending reads the execution as ended -> the broker's typed
    ended refusal (403 RUNNER_EXECUTION_NOT_RUNNING) at once: no further sleep, never reported as not-yet-running."""
    sleeps = []
    client, posts = _client(rc, [_NOT_YET, _NOT_YET, (403, {"detail": {"code": "RUNNER_EXECUTION_NOT_RUNNING"}}),
                                 (200, {"record": {"product_id": PRODUCT}, "session_key": SESSION_KEY})], sleeps)
    with pytest.raises(ri.RunnerIdentityError) as ei:
        client.redeem(NONCE, "e")
    assert (ei.value.code, ei.value.http_status, ei.value.stage) == \
        ("RUNNER_EXECUTION_NOT_RUNNING", 403, "runner-redeem")
    assert len(posts) == 3 and sleeps == list(rc.REDEEM_NOT_YET_RUNNING_DELAYS_S[:2])


class _StepClock:
    """A monotonic clock each sleep advances (plus a fixed cost per broker call)."""

    def __init__(self, per_read=0.0):
        self.t, self.per_read = 1000.0, per_read

    def __call__(self):
        self.t += self.per_read
        return self.t

    def sleep(self, s):
        self.t += s


def test_redeem_loop_guard_caps_calls_and_fails_loudly(rc, ri, monkeypatch):
    """SAT-52 RT LOW loop guard (calls): the worst interleaving of the retry budgets makes exactly
    REDEEM_MAX_CALLS calls and raises a typed error; a loop that could exceed the cap (budgets raised past it) still
    stops at REDEEM_MAX_CALLS with the last refusal's typed code."""
    delays = rc.REDEEM_NOT_YET_RUNNING_DELAYS_S
    connect = rc.REDEEM_CONNECT_RETRY_DELAYS_S
    assert rc.REDEEM_MAX_CALLS == len(delays) + len(connect) + rc.REDEEM_ATTEMPTS
    assert (rc.REDEEM_MAX_CALLS - len(connect)) * rc.BROKER_TIMEOUT_S + sum(delays) \
        + (rc.REDEEM_ATTEMPTS - 1) * rc.REDEEM_RETRY_DELAY_S <= rc.REDEEM_TOTAL_BUDGET_S < ri.REDEEM_WINDOW_SECONDS
    unbound = (409, {"detail": {"code": "RUNNER_DISPATCH_NOT_BOUND"}})
    client, posts = _client(rc, [(_connect_timeout(), None)] * len(connect) + [_NOT_YET] * len(delays)
                            + [unbound] * rc.REDEEM_ATTEMPTS)
    with pytest.raises(ri.RunnerIdentityError) as ei:
        client.redeem(NONCE, "e")
    assert ei.value.code == "RUNNER_DISPATCH_NOT_BOUND" and len(posts) == rc.REDEEM_MAX_CALLS
    monkeypatch.setattr(rc, "REDEEM_ATTEMPTS", 100)          # the backstop: the call cap alone ends the loop
    monkeypatch.setattr(rc, "REDEEM_MAX_CALLS", 5)
    client, posts = _client(rc, [unbound] * 10)
    with pytest.raises(ri.RunnerIdentityError) as ei:
        client.redeem(NONCE, "e")
    assert (ei.value.code, ei.value.http_status, ei.value.stage) == ("RUNNER_DISPATCH_NOT_BOUND", 409, "runner-redeem")
    assert "no redeem after 5 calls" in ei.value.detail and len(posts) == 5


@pytest.mark.parametrize("first", [_NOT_YET, (503, {"detail": {"code": "X"}})])
def test_redeem_loop_guard_caps_total_time_and_fails_loudly(rc, ri, first):
    """SAT-52 RT LOW loop guard (time): slow broker answers use up REDEEM_TOTAL_BUDGET_S before the call budget does;
    the retry that would end past it is not slept and the last refusal's typed code is raised."""
    clock = _StepClock(per_read=rc.REDEEM_TOTAL_BUDGET_S / 3)
    sleeps = []
    posts = []

    def post(url, json=None, headers=None, timeout=None):
        posts.append(url)
        return _Resp(*first)

    def sleep(s):
        sleeps.append(s)
        clock.sleep(s)

    client = rc.BrokerClient("https://vending.example.run.app", id_token=lambda aud: "id-token", post=post,
                             sleep=sleep, clock=clock)
    with pytest.raises(ri.RunnerIdentityError) as ei:
        client.redeem(NONCE, "e")
    want = ("RUNNER_EXECUTION_NOT_YET_RUNNING", 409) if first is _NOT_YET else (rc.RUNNER_BROKER_UNAVAILABLE, 503)
    assert (ei.value.code, ei.value.http_status, ei.value.stage) == want + ("runner-redeem",)
    assert "retry budget" in ei.value.detail and len(posts) < rc.REDEEM_MAX_CALLS
    assert len(sleeps) == len(posts) - 1           # the over-budget retry was never slept


def test_redeem_of_a_running_execution_is_one_call_without_sleep(rc):
    """SAT-52 RT LOW negative test: the happy path is unchanged -- one call, no sleep, the record and session key."""
    sleeps = []
    client, posts = _client(rc, [(200, {"record": {"product_id": PRODUCT}, "session_key": SESSION_KEY})], sleeps)
    assert client.redeem(NONCE, "e") == ({"product_id": PRODUCT}, SESSION_KEY)
    assert len(posts) == 1 and sleeps == []


# RUNNER-REDEEM-CONNECT-RETRY: a connection that was never established is retried with backoff; nothing else gains a
# retry. The exceptions are built the way requests' HTTPAdapter.send builds them.
def _connect_timeout():
    import requests
    from urllib3.exceptions import ConnectTimeoutError, MaxRetryError
    return requests.exceptions.ConnectTimeout(MaxRetryError(None, "/runner/redeem", ConnectTimeoutError(None, "u", "t")))


def _connection_refused():
    import requests
    from urllib3.exceptions import MaxRetryError, NewConnectionError
    return requests.exceptions.ConnectionError(MaxRetryError(None, "/runner/redeem", NewConnectionError(None, "refused")))


def _read_timeout():
    import requests
    return requests.exceptions.ReadTimeout("read timed out")


def _dropped_after_send():
    import requests
    from urllib3.exceptions import ProtocolError
    return requests.exceptions.ConnectionError(ProtocolError("Connection aborted.", ConnectionResetError(54, "reset")))


_REDEEMED = (200, {"record": {"product_id": PRODUCT}, "session_key": SESSION_KEY})


@pytest.mark.parametrize("failure", [_connect_timeout, _connection_refused])
def test_redeem_retries_a_connection_never_established_then_succeeds(rc, caplog, failure):
    sleeps = []
    client, posts = _client(rc, [(failure(), None), (failure(), None), _REDEEMED], sleeps)
    with caplog.at_level(logging.DEBUG):
        assert client.redeem(NONCE, "e") == ({"product_id": PRODUCT}, SESSION_KEY)
    assert len(posts) == 3 and sleeps == list(rc.REDEEM_CONNECT_RETRY_DELAYS_S[:2])
    assert caplog.text.count("the request never reached vending") == 2              # each retry is logged
    assert NONCE not in caplog.text and SESSION_KEY not in caplog.text


def test_redeem_connect_retries_exhausted_raise_todays_typed_error(rc, ri):
    delays = rc.REDEEM_CONNECT_RETRY_DELAYS_S
    sleeps = []
    client, posts = _client(rc, [(_connect_timeout(), None)] * (len(delays) + 1) + [_REDEEMED], sleeps)
    with pytest.raises(ri.RunnerIdentityError) as ei:
        client.redeem(NONCE, "e")
    assert (ei.value.code, ei.value.http_status, ei.value.stage) == (rc.RUNNER_BROKER_UNAVAILABLE, 503, "runner-redeem")
    assert ei.value.detail.startswith("/runner/redeem: ConnectTimeout")
    assert len(posts) == len(delays) + 1 and sleeps == list(delays)


@pytest.mark.parametrize("answer", [
    (_read_timeout, None), (_dropped_after_send, None), (500, {}), (503, {"detail": {"code": "X"}}),
])
def test_redeem_a_request_that_may_have_reached_vending_gains_no_connect_retry(rc, ri, answer):
    """Vending's redeem is single use and not idempotent, so these get none of the connect budget: only the attempts
    and flat delay they had before this change."""
    first = answer[0]() if callable(answer[0]) else answer[0]
    sleeps = []
    client, posts = _client(rc, [(first, answer[1])] * (rc.REDEEM_ATTEMPTS + 1), sleeps)
    with pytest.raises(ri.RunnerIdentityError) as ei:
        client.redeem(NONCE, "e")
    assert ei.value.code == rc.RUNNER_BROKER_UNAVAILABLE and len(posts) == rc.REDEEM_ATTEMPTS
    assert sleeps == [rc.REDEEM_RETRY_DELAY_S] * (rc.REDEEM_ATTEMPTS - 1)


@pytest.mark.parametrize("refusal,code", [
    ((409, {"detail": {"code": "RUNNER_NONCE_SPENT"}}), "RUNNER_NONCE_SPENT"),
    ((403, {"detail": {"code": "RUNNER_EXECUTION_MISMATCH"}}), "RUNNER_EXECUTION_MISMATCH"),
    ((410, {"detail": {"code": "RUNNER_NONCE_EXPIRED"}}), "RUNNER_NONCE_EXPIRED"),
])
def test_redeem_refusal_after_a_connect_retry_is_raised_at_once(rc, ri, refusal, code):
    sleeps = []
    client, posts = _client(rc, [(_connect_timeout(), None), refusal, _REDEEMED], sleeps)
    with pytest.raises(ri.RunnerIdentityError) as ei:
        client.redeem(NONCE, "e")
    assert ei.value.code == code and len(posts) == 2 and sleeps == [rc.REDEEM_CONNECT_RETRY_DELAYS_S[0]]


def _timed_client(rc, clock, seconds_per_call, answers):
    posts, sleeps = [], []

    def post(url, json=None, headers=None, timeout=None):
        posts.append(timeout)
        clock.t += seconds_per_call
        status, body = answers.pop(0)
        if isinstance(status, Exception):
            raise status
        return _Resp(status, body)

    def sleep(s):
        sleeps.append(s)
        clock.sleep(s)

    return rc.BrokerClient("https://vending.example.run.app", id_token=lambda aud: "id-token", post=post, sleep=sleep,
                           clock=clock), posts, sleeps


def test_redeem_connect_outage_fits_the_time_budget_and_the_redeem_window(rc, ri):
    """Every call uses its full connect timeout: the longest connect-only redeem, on a fake clock."""
    delays = rc.REDEEM_CONNECT_RETRY_DELAYS_S
    clock = _StepClock()
    start = clock.t
    client, posts, sleeps = _timed_client(rc, clock, rc.BROKER_TIMEOUT_S,
                                          [(_connect_timeout(), None)] * (len(delays) + 1))
    with pytest.raises(ri.RunnerIdentityError) as ei:
        client.redeem(NONCE, "e")
    assert ei.value.code == rc.RUNNER_BROKER_UNAVAILABLE and sleeps == list(delays)
    assert clock.t - start == 275.0 == (len(delays) + 1) * rc.BROKER_TIMEOUT_S + sum(delays)
    assert clock.t - start < rc.REDEEM_TOTAL_BUDGET_S < ri.REDEEM_WINDOW_SECONDS
    assert set(posts) == {rc.BROKER_TIMEOUT_S}                                     # the timeout itself is unchanged


def test_redeem_connect_retry_past_the_time_budget_is_not_slept(rc, ri):
    clock = _StepClock()
    client, posts, sleeps = _timed_client(rc, clock, 100.0, [(_connect_timeout(), None)] * 6)
    with pytest.raises(ri.RunnerIdentityError) as ei:
        client.redeem(NONCE, "e")
    assert (ei.value.code, ei.value.http_status, ei.value.stage) == (rc.RUNNER_BROKER_UNAVAILABLE, 503, "runner-redeem")
    assert "retry budget" in ei.value.detail
    assert len(posts) == 4 and sleeps == list(rc.REDEEM_CONNECT_RETRY_DELAYS_S[:3])


def test_a_connect_failure_gains_no_retry_on_any_other_broker_route(rc, ri):
    for call in (lambda c: c.deployer_token(SESSION_KEY), lambda c: c.repo_token(SESSION_KEY)):
        client, posts = _client(rc, [(_connect_timeout(), None)])
        with pytest.raises(ri.RunnerIdentityError) as ei:
            call(client)
        assert ei.value.code == rc.RUNNER_BROKER_UNAVAILABLE and len(posts) == 1
    sleeps = []
    client, posts = _client(rc, [(_connect_timeout(), None)] * rc.SIGN_RESULT_ATTEMPTS, sleeps)
    with pytest.raises(ri.RunnerIdentityError):
        client.sign_result(SESSION_KEY, "f" * 64)
    assert len(posts) == rc.SIGN_RESULT_ATTEMPTS and sleeps == [rc.REDEEM_RETRY_DELAY_S] * (rc.SIGN_RESULT_ATTEMPTS - 1)


# Other root tests leave `requests` holding an older import of urllib3 than sys.modules, so the check against the real
# libraries runs in a fresh interpreter (hermetic child env); only loopback is contacted.
_CLASSIFIER_CHECK = r"""
import socket, sys, threading
sys.path.insert(0, sys.argv[1])
import requests
import runner_credentials as rc

session = requests.Session()
session.trust_env = False                                 # the hermetic guard's proxy sentinel must not apply

def outcome(port):
    try:
        session.post(f"http://127.0.0.1:{port}/runner/redeem", json={}, timeout=0.3, allow_redirects=False)
    except requests.exceptions.RequestException as e:
        return type(e).__name__, rc._connection_never_established(e)
    raise SystemExit("the call did not fail")

with socket.socket() as probe:
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
assert outcome(closed_port) == ("ConnectionError", True)  # refused: never connected
with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    listener.listen(4)
    port = listener.getsockname()[1]
    assert outcome(port) == ("ReadTimeout", False)        # accepted by the backlog, no answer

    def hang_up():
        conn, _addr = listener.accept()                   # the silent connection of the read-timeout call
        conn.close()
        conn, _addr = listener.accept()
        conn.recv(65536)
        conn.close()

    server = threading.Thread(target=hang_up)
    server.start()
    assert outcome(port) == ("ConnectionError", False)    # dropped after the request was sent
    server.join(5)
print("CLASSIFIER_OK")
"""


def test_connection_classifier_against_the_installed_requests():
    proc = subprocess.run([sys.executable, "-c", _CLASSIFIER_CHECK, TF_DIR], env=hermetic_guard.child_env(),
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0 and "CLASSIFIER_OK" in proc.stdout, proc.stderr[-3000:]


def test_connection_classifier_of_built_errors(rc):
    assert rc._connection_never_established(_connect_timeout()) is True
    assert rc._connection_never_established(_connection_refused()) is True
    assert rc._connection_never_established(_read_timeout()) is False
    assert rc._connection_never_established(_dropped_after_send()) is False
    assert rc._connection_never_established(ConnectionError("x")) is False     # builtin: not a requests outcome


def test_deployer_token_parses_google_expiry_and_never_returns_the_token_in_meta(rc):
    client, _posts = _client(rc, [(200, {"access_token": TOKEN, "expire_time": "2026-11-01T12:00:00.123456789Z",
                                         "project_id": CHILD})])
    token, expiry, meta = client.deployer_token(SESSION_KEY)
    assert token == TOKEN and "access_token" not in meta
    assert expiry <= time.time() + 3600


def test_sign_result_posts_the_fingerprint_and_retries_only_an_unavailable_broker(rc, ri, caplog):
    """FD-7L 5b (SAT-37): /runner/result with the session key and the result fingerprint; an unavailable broker is
    retried (vending answers the same fingerprint again unchanged); the answer must echo the fingerprint."""
    sleeps, fp = [], "f" * 64
    client, posts = _client(rc, [(503, {"detail": {"code": "X"}}),
                                 (200, {"status": "SIGNED", "result_sha256": fp})], sleeps)
    with caplog.at_level(logging.DEBUG):
        assert client.sign_result(SESSION_KEY, fp) is None
    assert [p[0] for p in posts] == ["https://vending.example.run.app/runner/result"] * 2
    assert posts[-1][1] == {"session_key": SESSION_KEY, "result_sha256": fp} and len(sleeps) == 1
    assert SESSION_KEY not in caplog.text


@pytest.mark.parametrize("answers,code,attempts", [
    ([(409, {"detail": {"code": "RUNNER_RESULT_ALREADY_SIGNED"}})], "RUNNER_RESULT_ALREADY_SIGNED", 1),
    ([(401, {"detail": {"code": "RUNNER_SESSION_ENDED"}})], "RUNNER_SESSION_ENDED", 1),
    ([(200, {"status": "SIGNED", "result_sha256": "0" * 64})], "RUNNER_BROKER_UNAVAILABLE", 1),
    ([(503, {})] * 3, "RUNNER_BROKER_UNAVAILABLE", 3),
])
def test_sign_result_refusals_are_typed(rc, ri, answers, code, attempts):
    client, posts = _client(rc, list(answers))
    with pytest.raises(ri.RunnerIdentityError) as ei:
        client.sign_result(SESSION_KEY, "f" * 64)
    assert ei.value.code == code and len(posts) == attempts and rc.SIGN_RESULT_ATTEMPTS == 3


def test_broker_url_must_be_https(rc, ri):
    with pytest.raises(ri.RunnerIdentityError) as ei:
        rc.BrokerClient("http://vending")
    assert ei.value.code == rc.RUNNER_IDENTITY_NOT_READY


# ------------------------------------------------------------------------------------------------ credentials
def test_credentials_carry_the_child_quota_project_and_hide_the_session_key(rc, ri):
    creds, _broker, _clock = _creds(rc, ri)
    headers = {}
    creds.before_request(None, "GET", "https://x", headers)
    assert headers == {"authorization": f"Bearer {TOKEN}-1", "x-goog-user-project": CHILD}
    assert SESSION_KEY not in repr(creds) and SESSION_KEY not in str(creds)
    assert [k for k, v in vars(creds).items() if v == SESSION_KEY] == ["_BrokeredCredentials__session_key"]


def test_fake_clock_three_hour_apply_refreshes_at_least_twice(rc, ri):
    creds, broker, clock = _creds(rc, ri)
    endpoint = rc.LocalMetadataEndpoint(creds, interrupt=lambda p, s: None)
    for _ in range(int(3 * 3600 / rc.TICK_S)):
        endpoint.tick()
        clock.t += rc.TICK_S
    assert endpoint.failure is None
    assert creds.refresh_count >= 3            # first mint + at least two refreshes
    assert creds.seconds_left() > rc.REFRESH_BEFORE_EXPIRY_S - rc.TICK_S


def test_broker_outage_shorter_than_the_remaining_lifetime_does_not_stop_the_apply(rc, ri):
    creds, broker, clock = _creds(rc, ri)
    endpoint = rc.LocalMetadataEndpoint(creds, interrupt=lambda p, s: pytest.fail("interrupted"))
    creds.current_token()
    clock.t += 3600 - rc.REFRESH_BEFORE_EXPIRY_S + 1     # inside the refresh window
    broker.down = True
    outage_end = clock.t + 20 * 60                      # 20 min: shorter than the ~30 min left
    while clock.t < outage_end:
        endpoint.tick()
        clock.t += rc.TICK_S
    broker.down = False
    endpoint.tick()
    assert endpoint.failure is None and creds.seconds_left() > 3000
    # retries were bounded: at most one broker call per RETRY_INTERVAL_S during the outage
    assert broker.calls <= 2 + int(20 * 60 / rc.RETRY_INTERVAL_S) + 1


def test_broker_outage_longer_than_the_lifetime_is_typed_and_interrupts_tofu(rc, ri):
    creds, broker, clock = _creds(rc, ri)
    signals = []
    endpoint = rc.LocalMetadataEndpoint(creds, interrupt=lambda p, s: signals.append((p, s)))
    proc = type("P", (), {"pid": 4242, "poll": lambda self: None})()
    endpoint.attach(proc)
    creds.current_token()
    broker.down = True
    for _ in range(int(3600 / rc.TICK_S) + 2):
        endpoint.tick()
        clock.t += rc.TICK_S
    assert endpoint.failure is not None and endpoint.failure.code == rc.RUNNER_BROKER_UNAVAILABLE
    assert signals == [(proc, signal.SIGINT)]
    status, body, _ = endpoint.answer("/computeMetadata/v1/instance/service-accounts/default/token",
                                      {"Metadata-Flavor": "Google"})
    assert status == 503 and body == rc.RUNNER_BROKER_UNAVAILABLE
    late = type("P", (), {"pid": 4343, "poll": lambda self: None})()
    endpoint.attach(late)                                     # a command started after the failure: interrupted at once
    assert signals[-1] == (late, signal.SIGINT)


def test_real_sigint_reaches_the_attached_process_group(rc, ri):
    creds, broker, clock = _creds(rc, ri)
    endpoint = rc.LocalMetadataEndpoint(creds)
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True,
                            env=hermetic_guard.child_env())
    try:
        endpoint.attach(proc)
        endpoint.abort(ri.RunnerIdentityError(rc.RUNNER_BROKER_UNAVAILABLE, "test", http_status=503))
        assert proc.wait(timeout=10) == -signal.SIGINT
    finally:
        if proc.poll() is None:
            proc.kill()


# ------------------------------------------------------------------------------------------------ metadata endpoint
def _get(host, path, headers=None):
    h, port = host.split(":")
    conn = http.client.HTTPConnection(h, int(port), timeout=5)   # direct: never through a proxy
    conn.request("GET", path, headers=headers if headers is not None else {"Metadata-Flavor": "Google"})
    resp = conn.getresponse()
    out = resp.status, resp.read().decode(), dict(resp.getheaders())
    conn.close()
    return out


def test_metadata_endpoint_serves_only_the_deployer(rc, ri):
    creds, _broker, _clock = _creds(rc, ri, clock=time.time)
    endpoint = rc.LocalMetadataEndpoint(creds).start(ticker=False)
    try:
        host = endpoint.host
        assert host.startswith("127.0.0.1:")
        sa = "/computeMetadata/v1/instance/service-accounts/default"
        status, body, hdrs = _get(host, f"{sa}/token?scopes=https://www.googleapis.com/auth/cloud-platform")
        assert status == 200 and hdrs.get("Metadata-Flavor") == "Google"
        tok = json.loads(body)
        assert tok["access_token"].startswith(TOKEN) and tok["token_type"] == "Bearer" and tok["expires_in"] > 3000
        assert _get(host, f"{sa}/email")[:2] == (200, DEPLOYER)
        assert _get(host, "/computeMetadata/v1/project/project-id")[:2] == (200, CHILD)
        assert json.loads(_get(host, f"{sa}/?recursive=true")[1])["email"] == DEPLOYER
        assert _get(host, "/")[0] == 200 and _get(host, "/computeMetadata/v1/")[0] == 200
        assert _get(host, f"{sa}/identity?audience=https://x")[:2] == (404, rc.IDENTITY_TOKEN_NOT_SERVED)
        assert _get(host, "/computeMetadata/v1/universe/universe-domain")[0] == 404
        assert _get(host, "/computeMetadata/v1beta1/instance/service-accounts/default/token")[0] == 404
        assert _get(host, "/computeMetadata/v1/instance/service-accounts/other@x/token")[0] == 404
        assert _get(host, f"{sa}/token", headers={})[0] == 403                                  # no header
        assert _get(host, f"{sa}/token", headers={"Metadata-Flavor": "google"})[0] == 403        # exact value
        assert _get(host, f"{sa}/token", headers={"Metadata-Flavor": "Google",
                                                  "X-Forwarded-For": "1.2.3.4"})[0] == 403
        h, port = host.split(":")
        conn = http.client.HTTPConnection(h, int(port), timeout=5)
        conn.request("POST", f"{sa}/token", body=b"", headers={"Metadata-Flavor": "Google"})
        assert conn.getresponse().status == 405
        conn.close()
    finally:
        endpoint.stop()


# ------------------------------------------------------------------------------------------------ target check
def _signed(ri, product=PRODUCT, project=CHILD, key=None, signer=None, doc_product=None, **over):
    rec = ri.new_runner_identity_record(product_id=product, project_id=project, project_number="123456789",
                                        state_bucket=f"{project}-tfstate", status="READY",
                                        updated_at="2026-11-01T00:00:00Z",
                                        repository={"provider": "GITHUB", "full_name": "Acme/claims", "id": "42"})
    rec.update(over)
    key = key or fk.BROKER_KEY
    return ri.sign_record(ri.provenance_doc_path(doc_product or product), rec, signer_email=signer or fk.BROKER,
                          signed_at="2026-11-01T00:00:00Z", sign_blob=key.sign)


def _dispatch(**over):
    d = {"product_id": PRODUCT, "project_id": CHILD, "project_number": "123456789", "deployer_email": DEPLOYER,
         "state_bucket": BUCKET, "trace_id": "t-1", "branch": "main", "mode": "deploy"}
    d.update(over)
    return d


def _verify(rc, ri, raw, dispatch=None, workload=None):
    return rc.verify_run_target(dispatch or _dispatch(), provenance={"project_id": CHILD, "runner_identity": raw},
                                workload=workload, expected_signer=fk.BROKER, certs=fk.certs_for())


def test_signed_ready_record_that_agrees_is_accepted_with_its_key_id(rc, ri):
    rec, key_id = _verify(rc, ri, _signed(ri), workload={
        "project_id": CHILD, "github_repository_identity": {"full_name": "acme/Claims", "repository_id": "42"}})
    assert rec["deployer_email"] == DEPLOYER and key_id == fk.BROKER_KEY.key_id


@pytest.mark.parametrize("case", ["unsigned", "field_change", "path_swap", "wrong_signer", "forged_signed_by"])
def test_untrustworthy_records_are_runner_record_unsigned(rc, ri, case):
    raw = _signed(ri)
    if case == "unsigned":
        raw = {k: v for k, v in raw.items() if k != "signature"}
    elif case == "field_change":
        raw = dict(raw, state_bucket=f"{CHILD}-tfstate-abcdef")
    elif case == "path_swap":
        raw = _signed(ri, doc_product="other-product")
    elif case == "wrong_signer":
        raw = _signed(ri, key=fk.OTHER_KEY, signer=fk.CC)
    elif case == "forged_signed_by":
        raw = _signed(ri, key=fk.OTHER_KEY)                  # claims the broker, signed with another key
    with pytest.raises(ri.RunnerIdentityError) as ei:
        _verify(rc, ri, raw)
    assert ei.value.code in ("RUNNER_RECORD_UNSIGNED", "RUNNER_RECORD_KEY_RETIRED")
    if case != "forged_signed_by":
        assert ei.value.code == "RUNNER_RECORD_UNSIGNED"


@pytest.mark.parametrize("field,value", [("project_id", "other-proj-123"), ("project_number", "9"),
                                         ("deployer_email", "x@y.iam.gserviceaccount.com"),
                                         ("state_bucket", "other-bucket")])
def test_dispatch_record_that_disagrees_with_provenance_is_a_target_mismatch(rc, ri, field, value):
    with pytest.raises(ri.RunnerIdentityError) as ei:
        _verify(rc, ri, _signed(ri), dispatch=_dispatch(**{field: value}))
    assert ei.value.code == rc.RUNNER_TARGET_MISMATCH


@pytest.mark.parametrize("workload", [
    {"project_id": "another-proj-1"},
    {"github_repository_identity": {"full_name": "Acme/other", "repository_id": "42"}},
    {"github_repository_identity": {"full_name": "Acme/claims", "repository_id": "43"}},
])
def test_workload_record_that_disagrees_is_a_target_mismatch(rc, ri, workload):
    with pytest.raises(ri.RunnerIdentityError) as ei:
        _verify(rc, ri, _signed(ri), workload=workload)
    assert ei.value.code == rc.RUNNER_TARGET_MISMATCH


def test_missing_or_not_ready_record_is_not_ready(rc, ri):
    with pytest.raises(ri.RunnerIdentityError) as ei:
        rc.verify_run_target(_dispatch(), provenance={"project_id": CHILD}, workload=None,
                             expected_signer=fk.BROKER, certs=fk.certs_for())
    assert ei.value.code == rc.RUNNER_IDENTITY_NOT_READY
    with pytest.raises(ri.RunnerIdentityError) as ei:
        _verify(rc, ri, _signed(ri, status="MIGRATING"))
    assert ei.value.code == rc.RUNNER_IDENTITY_NOT_READY


class _Session:
    def __init__(self, status, body):
        self.status, self.body, self.calls = status, body, []

    def get(self, url, params=None, timeout=None):
        self.calls.append((url, params))
        return _Resp(self.status, self.body)


def test_state_bucket_owner_check(rc, ri):
    ok = _Session(200, {"projectNumber": "123456789"})
    rc.check_state_bucket_owner(ok, BUCKET, "123456789")
    assert ok.calls == [(f"https://storage.googleapis.com/storage/v1/b/{BUCKET}", {"fields": "projectNumber"})]
    for session in (_Session(200, {"projectNumber": "987"}), _Session(403, {}), _Session(404, {})):
        with pytest.raises(ri.RunnerIdentityError) as ei:
            rc.check_state_bucket_owner(session, BUCKET, "123456789")
        assert ei.value.code == rc.STATE_BUCKET_NOT_OWNED


def test_execution_name_and_missing_config(rc, ri):
    env = {"PROJECT_ID": "host-p", "CLOUD_RUN_JOB": "tf-applier", "CLOUD_RUN_EXECUTION": "tf-applier-abc"}
    assert rc.execution_name(env, "us-central1") == \
        "projects/host-p/locations/us-central1/jobs/tf-applier/executions/tf-applier-abc"
    for missing in ("PROJECT_ID", "CLOUD_RUN_JOB", "CLOUD_RUN_EXECUTION"):
        with pytest.raises(ri.RunnerIdentityError) as ei:
            rc.execution_name({k: v for k, v in env.items() if k != missing}, "us-central1")
        assert ei.value.code == rc.RUNNER_IDENTITY_NOT_READY
    with pytest.raises(ri.RunnerIdentityError):
        rc.execution_name(env, None)


# ------------------------------------------------------------------------------------------------ mode log (R10)
def test_mode_log_line_names_mode_source_key_and_brokering(rc, caplog):
    with caplog.at_level(logging.INFO, logger="tf-runner-identity"):
        rec = rc.log_mode(run="deploy", product_id=PRODUCT, trace_id="t-1", key_id="k1", brokered=True,
                          mode="PER_WORKLOAD", environ={"STACKVEND_TF_RUNNER_IDENTITY": "PER_WORKLOAD"})
    assert rec["mode"] == "PER_WORKLOAD" and rec["mode_label"] == "Per workload" and rec["brokered"] is True
    assert rec["mode_source"] == "env:STACKVEND_TF_RUNNER_IDENTITY" and rec["provenance_key_id"] == "k1"
    assert "RUNNER_IDENTITY_MODE {" in caplog.text
    assert rc.mode_log_record(run="deploy", product_id=None, trace_id=None, key_id=None, brokered=False,
                              mode="PLATFORM", environ={})["mode"] == "PLATFORM"
    bad = rc.mode_log_record(run="deploy", product_id=None, trace_id=None, key_id=None, brokered=False,
                             mode=None, mode_error="RUNNER_IDENTITY_MODE_INVALID",
                             environ={"STACKVEND_TF_RUNNER_IDENTITY": "bogus"})
    assert bad["mode"] is None and bad["mode_error"] == "RUNNER_IDENTITY_MODE_INVALID"
