"""FD-30 isolation guard (red-team B1-B4, H8). Every check runs in a fresh `python -I` subprocess so that no guard
is ever installed in the pytest process. Offline: all probes are refused before any connection is attempted."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EVAL = ROOT / "eval"

CHILD_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent-home", "LANG": "C.UTF-8",
             "GOOGLE_APPLICATION_CREDENTIALS": "/nonexistent/adc-disabled.json", "PROJECT_ID": ""}


def _exact_child_env(env):
    """``hermetic_guard.child_env()`` kwargs that give the child exactly ``env`` plus the guard's Layer 0 and inherit
    nothing else from the pytest process (this child must see a minimal, credential-less env)."""
    want = hermetic_guard.hermetic_env(env)
    guarded = set(hermetic_guard.FORCED_ENV) | set(hermetic_guard.SECRET_ENV) | {"PYTHONPATH"}
    return {"drop": tuple(k for k in os.environ if k not in want or k == "PYTHONPATH"),
            "extra": {k: v for k, v in want.items() if k not in guarded}}

SCRIPT = r'''
import json, sys
sys.path.insert(0, {eval_dir!r})
from stackvend_eval.state import RunState
from stackvend_eval.guard import Guard
from stackvend_eval.canary import run_canary
skip = {skip!r}
st = RunState()
g = Guard(st, allow_hosts=[])
if "process" not in skip: g.install_process_guard()
if "grpc" not in skip: g.install_grpc_guard()
if "sockets" not in skip: g.install_socket_guard()
if "clients" not in skip: g.install_client_guards()
if "auth" not in skip: g.install_auth_guard()
if "seal" not in skip: g.seal_genai()
print(json.dumps(run_canary(g, expect_genai_sealed="seal" not in skip)))
'''


# RT finding 1a: resolver entry points other than getaddrinfo, and sendmsg.
NEW_SOCKET_PROBES = ("socket_gethostbyname", "socket_gethostbyname_ex", "socket_gethostbyaddr", "socket_getnameinfo",
                     "socket_sendmsg")
NEW_SOCKET_IDENTITY = ("socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyname_ex", "socket.gethostbyaddr",
                       "socket.getnameinfo", "socket.socket.connect", "socket.socket.connect_ex",
                       "socket.socket.sendto", "socket.socket.sendmsg")


def _canary(skip=(), extra_env=None):
    env = dict(CHILD_ENV, **(extra_env or {}))
    r = subprocess.run([sys.executable, "-I", "-c", SCRIPT.format(eval_dir=str(EVAL), skip=list(skip))],
                       capture_output=True, text=True, env=hermetic_guard.child_env(**_exact_child_env(env)), timeout=180)
    assert r.returncode == 0, r.stderr[-3000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


def _outcomes(res):
    return {p["probe"]: p["outcome"] for p in res["probes"]}


def test_full_guard_blocks_every_probe():
    res = _canary()
    out = _outcomes(res)
    assert res["ok"], res
    assert all(v == "blocked" for v in out.values()), out  # all client libraries are installed in this venv
    assert all(res["identity"].values())
    assert res["env_problems"] == [] and res["emulator_vars_set"] == []
    for probe in ("grpc_aio_secure_channel", "multiprocessing_spawn", "os_posix_spawn", "os_system",
                  "localhost_listener_raw_connect", "httpx_firestore", "firestore_client", "second_genai_client",
                  *NEW_SOCKET_PROBES):
        assert out[probe] == "blocked"
    for name in NEW_SOCKET_IDENTITY:
        assert res["identity"][name] is True, name


def test_canary_detects_a_missing_process_guard():
    res = _canary(skip=["process"])
    out = _outcomes(res)
    assert not res["ok"]
    assert out["os_system"] == "not_blocked" and out["subprocess_run"] == "not_blocked"
    assert not res["identity"]["_posixsubprocess.fork_exec"]


def test_canary_detects_missing_grpc_and_socket_guards():
    res = _canary(skip=["grpc", "sockets"])
    out = _outcomes(res)
    assert not res["ok"]
    assert out["grpc_aio_secure_channel"] != "blocked"
    assert out["localhost_listener_raw_connect"] != "blocked"
    for probe in NEW_SOCKET_PROBES:  # the probes are real: without the socket guard they are not blocked
        assert out[probe] != "blocked", probe
    assert not any(res["identity"][n] for n in NEW_SOCKET_IDENTITY)


def test_canary_fails_when_an_emulator_variable_is_set():
    res = _canary(extra_env={"FIRESTORE_EMULATOR_HOST": "127.0.0.1:8080"})
    assert not res["ok"] and "FIRESTORE_EMULATOR_HOST is set" in res["env_problems"]
    assert _outcomes(res)["firestore_client"] == "blocked"  # no emulator escape hatch (B2)


def test_canary_fails_when_real_adc_is_reachable():
    res = _canary(extra_env={"GOOGLE_APPLICATION_CREDENTIALS": os.path.expanduser("~/x.json")})
    assert not res["ok"]


def test_allowlist_admits_only_resolved_vertex_addresses():
    code = r'''
import sys, socket
sys.path.insert(0, {eval_dir!r})
from stackvend_eval.state import RunState
from stackvend_eval.guard import Guard
from stackvend_eval.errors import EvalEgressBlocked
stub = lambda host, port, *a, **k: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.7", 443))]
g = Guard(RunState(), allow_hosts=["aiplatform.googleapis.com"], resolver=stub)
g.install_socket_guard()
assert socket.getaddrinfo("aiplatform.googleapis.com", 443)[0][4][0] == "203.0.113.7"
assert g._ip_allowed(("203.0.113.7", 443), socket.AF_INET)
assert not g._ip_allowed(("203.0.113.8", 443), socket.AF_INET)
for host in ("oauth2.googleapis.com", "firestore.googleapis.com", "us-central1-aiplatform.googleapis.com"):
    try:
        socket.getaddrinfo(host, 443)
        raise SystemExit("not blocked: " + host)
    except EvalEgressBlocked:
        pass
print("ok")
'''.format(eval_dir=str(EVAL))
    r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True,
                       env=hermetic_guard.child_env(**_exact_child_env(CHILD_ENV)), timeout=60)
    assert r.returncode == 0 and r.stdout.strip() == "ok", r.stdout + r.stderr


def test_every_resolver_and_sendmsg_admit_only_the_vertex_host():
    """RT finding 1a: gethostbyname/_ex, gethostbyaddr, getnameinfo and sendmsg go through the same allowlist as
    getaddrinfo/connect. The stub resolves the Vertex host to loopback, so nothing leaves the machine."""
    code = r"""
import sys, socket, types
sys.path.insert(0, {eval_dir!r})
early = types.ModuleType("early_alias")              # `from socket import gethostbyname` bound before install
early.gethostbyname = socket.gethostbyname
early.getnameinfo = socket.getnameinfo
sys.modules["early_alias"] = early
from stackvend_eval.state import RunState
from stackvend_eval.guard import Guard
from stackvend_eval.errors import EvalEgressBlocked
VERTEX = "aiplatform.googleapis.com"
stub = lambda host, port, *a, **k: [(socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("127.0.0.1", port or 0))]
st = RunState()
g = Guard(st, allow_hosts=[VERTEX], resolver=stub)
g.install_socket_guard()

def blocked(fn, *args):
    before = len(st.events)
    try:
        fn(*args)
    except EvalEgressBlocked:
        return len(st.events) == before + 1
    return False

for host in ("firestore.googleapis.com", "oauth2.googleapis.com", "secretmanager.googleapis.com", "localhost",
             "us-central1-aiplatform.googleapis.com", "127.0.0.1"):
    for fn in (socket.gethostbyname, socket.gethostbyname_ex, socket.gethostbyaddr, early.gethostbyname):
        assert blocked(fn, host), (fn.__name__, host)
    for fn in (socket.getnameinfo, early.getnameinfo):
        assert blocked(fn, (host, 443), 0), ("getnameinfo", host)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
assert blocked(s.sendmsg, [b"x"], [], 0, ("127.0.0.1", 9))   # IP not learned from an allowed lookup yet
assert socket.gethostbyname(VERTEX) == "127.0.0.1"
assert socket.gethostbyname_ex(VERTEX)[2] == ["127.0.0.1"]
assert socket.gethostbyaddr(VERTEX)[2] == ["127.0.0.1"]
assert socket.getnameinfo((VERTEX, 443), 0) == (VERTEX, "443")
assert s.sendmsg([b"x"], [], 0, ("127.0.0.1", 9)) == 1       # learned IP: admitted (local discard port)
assert blocked(s.sendmsg, [b"x"], [], 0, ("127.0.0.2", 9))
s.close()
u = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
assert blocked(u.sendmsg, [b"x"], [], 0, "/var/run/syslog")
u.close()
print("ok")
""".format(eval_dir=str(EVAL))
    r = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True,
                       env=hermetic_guard.child_env(**_exact_child_env(CHILD_ENV)), timeout=60)
    assert r.returncode == 0 and r.stdout.strip() == "ok", r.stdout + r.stderr
