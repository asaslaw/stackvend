"""Canary self-test (red-team H8): prove the *guard* blocks each egress class, not merely missing credentials.

Every probe that constructs a client passes explicit AnonymousCredentials and an explicit project, so only the
guard can stop it. A probe passes when it raised AND the guard recorded a new event for it (the exception may be
wrapped by a library, e.g. httpx.ConnectError, so the cause chain is searched). Probes that would be dangerous if
the guard were broken (fork/exec) are identity checks: the attribute must be the guard's wrapper.

The canary runs in the generation child after guard installation and before any product import. Any failure ->
the child exits with isolation_guard_ineffective before spending anything.
"""
from __future__ import annotations

import asyncio
import os
import socket
from typing import Any, Callable, Dict, List, Optional

from .errors import EvalGuardBlocked
from .guard import EMULATOR_VARS, GUARD_MARK, OS_PROCESS_FUNCS, SOCKET_RESOLVER_FUNCS, SOCKET_SEND_METHODS, Guard

CANARY_PROJECT = "eval-canary-project"


def _chain_has_guard_error(exc: BaseException) -> bool:
    seen = set()
    cur: Optional[BaseException] = exc
    while cur is not None and id(cur) not in seen:
        if isinstance(cur, EvalGuardBlocked):
            return True
        seen.add(id(cur))
        cur = cur.__cause__ or cur.__context__
    return False


def _anon():
    from google.auth.credentials import AnonymousCredentials
    return AnonymousCredentials()


def _probe_firestore():
    from google.cloud import firestore
    firestore.Client(project=CANARY_PROJECT, credentials=_anon())


def _probe_storage():
    from google.cloud import storage
    storage.Client(project=CANARY_PROJECT, credentials=_anon())


def _probe_pubsub():
    from google.cloud import pubsub_v1
    pubsub_v1.PublisherClient(credentials=_anon())


def _probe_secretmanager():
    from google.cloud import secretmanager
    secretmanager.SecretManagerServiceClient(credentials=_anon())


def _probe_vertexai_init():
    import vertexai
    vertexai.init(project=CANARY_PROJECT, location="us-central1", credentials=_anon())


def _probe_grpc_secure():
    import grpc
    grpc.secure_channel("pubsub.googleapis.com:443", grpc.ssl_channel_credentials())


def _probe_grpc_insecure():
    import grpc
    grpc.insecure_channel("localhost:1")


def _probe_grpc_aio_secure():
    import grpc
    import grpc.aio
    grpc.aio.secure_channel("pubsub.googleapis.com:443", grpc.ssl_channel_credentials())


def _probe_grpc_aio_insecure():
    import grpc.aio
    grpc.aio.insecure_channel("localhost:1")


def _probe_socket_firestore():
    socket.create_connection(("firestore.googleapis.com", 443), timeout=2)


def _probe_socket_metadata():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    try:
        s.connect(("169.254.169.254", 80))
    finally:
        s.close()


def _probe_localhost_listener_resolve():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    try:
        socket.create_connection(("127.0.0.1", srv.getsockname()[1]), timeout=2)
    finally:
        srv.close()


def _probe_localhost_listener_raw():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    c.settimeout(2)
    try:
        c.connect(("127.0.0.1", srv.getsockname()[1]))
    finally:
        c.close()
        srv.close()


def _probe_unix_socket():
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        c.connect("/var/run/docker.sock")
    finally:
        c.close()


# RT finding 1a: the non-getaddrinfo resolver entry points and sendmsg. Targets are local only (no DNS, no
# off-host packet even if the guard were missing): `localhost` names and a UDP datagram to 127.0.0.1:9 (discard).
def _probe_gethostbyname():
    socket.gethostbyname("localhost")


def _probe_gethostbyname_ex():
    socket.gethostbyname_ex("localhost")


def _probe_gethostbyaddr():
    socket.gethostbyaddr("localhost")


def _probe_getnameinfo():
    socket.getnameinfo(("127.0.0.1", 9), socket.NI_NUMERICHOST | socket.NI_NUMERICSERV)


def _probe_sendmsg():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.sendmsg([b"stackvend-eval-canary"], [], 0, ("127.0.0.1", 9))
    finally:
        s.close()


def _probe_httpx():
    import httpx
    httpx.get("https://firestore.googleapis.com/", timeout=3)


def _probe_requests():
    import requests
    requests.get("https://api.github.com/", timeout=3)


def _probe_google_auth_default():
    import google.auth
    google.auth.default()


def _probe_second_genai_client():
    from google import genai
    genai.Client(api_key="eval-canary-not-a-key")


def _probe_os_system():
    os.system("true")


def _probe_posix_spawn():
    os.posix_spawn("/usr/bin/true", ["true"], dict(os.environ))


def _probe_subprocess():
    import subprocess
    subprocess.run(["/usr/bin/true"], check=False)


def _probe_asyncio_subprocess():
    async def _go():
        p = await asyncio.create_subprocess_exec("/usr/bin/true")
        await p.wait()
    asyncio.run(_go())


def _probe_multiprocessing_spawn():
    import multiprocessing
    p = multiprocessing.get_context("spawn").Process(target=os.getpid)
    try:
        p.start()
    finally:
        try:
            if p.is_alive():
                p.terminate()
        except Exception:
            pass


BEHAVIOR_PROBES: Dict[str, Callable[[], Any]] = {
    "firestore_client": _probe_firestore,
    "storage_client": _probe_storage,
    "pubsub_client": _probe_pubsub,
    "secretmanager_client": _probe_secretmanager,
    "vertexai_init": _probe_vertexai_init,
    "grpc_secure_channel": _probe_grpc_secure,
    "grpc_insecure_channel": _probe_grpc_insecure,
    "grpc_aio_secure_channel": _probe_grpc_aio_secure,
    "grpc_aio_insecure_channel": _probe_grpc_aio_insecure,
    "socket_firestore_googleapis": _probe_socket_firestore,
    "socket_metadata_server": _probe_socket_metadata,
    "localhost_listener_via_resolver": _probe_localhost_listener_resolve,
    "localhost_listener_raw_connect": _probe_localhost_listener_raw,
    "unix_socket_connect": _probe_unix_socket,
    "socket_gethostbyname": _probe_gethostbyname,
    "socket_gethostbyname_ex": _probe_gethostbyname_ex,
    "socket_gethostbyaddr": _probe_gethostbyaddr,
    "socket_getnameinfo": _probe_getnameinfo,
    "socket_sendmsg": _probe_sendmsg,
    "httpx_firestore": _probe_httpx,
    "requests_github": _probe_requests,
    "google_auth_default": _probe_google_auth_default,
    "second_genai_client": _probe_second_genai_client,
    "os_system": _probe_os_system,
    "os_posix_spawn": _probe_posix_spawn,
    "subprocess_run": _probe_subprocess,
    "asyncio_subprocess": _probe_asyncio_subprocess,
    "multiprocessing_spawn": _probe_multiprocessing_spawn,
}


def _identity_probes() -> Dict[str, bool]:
    import _posixsubprocess
    import pty
    out = {"_posixsubprocess.fork_exec": getattr(_posixsubprocess.fork_exec, GUARD_MARK, False)}
    for name in OS_PROCESS_FUNCS:
        fn = getattr(os, name, None)
        if fn is not None:
            out[f"os.{name}"] = bool(getattr(fn, GUARD_MARK, False))
    for name in ("spawn", "fork"):
        out[f"pty.{name}"] = bool(getattr(getattr(pty, name), GUARD_MARK, False))
    for name in SOCKET_RESOLVER_FUNCS:
        out[f"socket.{name}"] = bool(getattr(getattr(socket, name), GUARD_MARK, False))
    for name in SOCKET_SEND_METHODS:
        if hasattr(socket.socket, name):
            out[f"socket.socket.{name}"] = bool(getattr(getattr(socket.socket, name), GUARD_MARK, False))
    import subprocess  # binds _fork_exec at import time: must have been rebound if imported before the guard
    if hasattr(subprocess, "_fork_exec"):
        out["subprocess._fork_exec"] = bool(getattr(subprocess._fork_exec, GUARD_MARK, False))
    return out


def run_canary(guard: Guard, *, expect_genai_sealed: bool = True) -> Dict[str, Any]:
    results: List[Dict[str, Any]] = []
    for name, fn in BEHAVIOR_PROBES.items():
        if name == "second_genai_client" and not expect_genai_sealed:
            continue
        before = len(guard.state.events)
        outcome = "not_blocked"
        err = None
        try:
            fn()
        except ImportError as e:  # library not installed -> that egress class cannot exist in this venv
            outcome, err = "library_absent", repr(e)[:160]
        except BaseException as e:  # noqa: BLE001
            err = repr(e)[:200]
            new_events = len(guard.state.events) > before
            outcome = "blocked" if (_chain_has_guard_error(e) or new_events) and new_events else "failed_other"
        results.append({"probe": name, "outcome": outcome, "error": err})
    # second_genai_client invalidates the run by design; that marker is canary noise, so clear it.
    guard.state.invalid_reasons[:] = [r for r in guard.state.invalid_reasons if r != "unmetered_llm_client"]
    identity = _identity_probes()
    env_problems = Guard.env_problems()
    emulator_vars_set = [v for v in EMULATOR_VARS if os.environ.get(v)]
    ok = (all(r["outcome"] in ("blocked", "library_absent") for r in results)
          and all(identity.values()) and not env_problems)
    return {"ok": ok, "probes": results, "identity": identity, "env_problems": env_problems,
            "emulator_vars_set": emulator_vars_set, "guards_installed": list(guard.installed)}
