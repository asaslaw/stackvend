"""In-process isolation guard for the generation child (plan §3.2, hardened per red-team B1-B4, H7, H8).

Layer 0 (credential minimization, B1) lives in the parent/child env: the child gets
GOOGLE_APPLICATION_CREDENTIALS=/nonexistent/adc-disabled.json, an empty CLOUDSDK_CONFIG and an empty HOME, and the
only credential in the process is a short-lived access token held by the harness's own genai client. So every
unguarded product path fails closed on credentials alone. This module is Layer 2: it makes the remaining paths
fail closed *regardless of credentials*:

- process creation: ALL denied (fork_exec / posix_spawn / system / popen / fork / exec* / spawn* / pty)  (B3)
- gRPC: every channel constructor (sync + aio choke points)                                          (B4)
- sockets: every resolver entry point (getaddrinfo, gethostbyname, gethostbyname_ex, gethostbyaddr, getnameinfo)
  admits only the Vertex hostnames, and connect/connect_ex/sendto/sendmsg admit only the IPs those lookups
  returned (no oauth2: tokens can't refresh)
- client constructors: Firestore (no emulator escape hatch, B2), Storage, Pub/Sub, Secret Manager, legacy vertexai
- google.auth.default(): denied
- google.genai.Client(): sealed after the harness builds its own (metered) client

Install order (H7): process -> grpc -> sockets -> clients/auth -> [harness builds its genai client] -> seal_genai
-> canary -> product import. Every refusal records an event in RunState and raises an EvalGuardBlocked subclass.
"""
from __future__ import annotations

import importlib.abc
import importlib.machinery
import ipaddress
import os
import socket
import sys
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from .errors import EvalClientBlocked, EvalEgressBlocked, EvalProcessBlocked
from .state import RunState

GUARD_MARK = "_stackvend_eval_guard"
EMULATOR_VARS = ("FIRESTORE_EMULATOR_HOST", "PUBSUB_EMULATOR_HOST", "DATASTORE_EMULATOR_HOST",
                 "STORAGE_EMULATOR_HOST", "SPANNER_EMULATOR_HOST", "BIGTABLE_EMULATOR_HOST")
DISABLED_ADC = "/nonexistent/adc-disabled.json"

# os-level process creation entry points (B3). Missing names on a platform are skipped.
OS_PROCESS_FUNCS = (
    "system", "popen", "fork", "forkpty", "posix_spawn", "posix_spawnp",
    "execv", "execve", "execl", "execle", "execlp", "execlpe", "execvp", "execvpe",
    "spawnv", "spawnve", "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnvp", "spawnvpe",
)

# Every resolver entry point in `socket` and every socket method that names a destination (RT finding 1a).
SOCKET_RESOLVER_FUNCS = ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "gethostbyaddr", "getnameinfo")
SOCKET_SEND_METHODS = ("connect", "connect_ex", "sendto", "sendmsg")

# module -> list of "Class.method" / "function" attributes whose call must be refused (client constructors).
CLIENT_TARGETS: Dict[str, List[str]] = {
    "google.cloud.firestore_v1.base_client": ["BaseClient.__init__"],
    "google.cloud.storage.client": ["Client.__init__"],
    "google.cloud.pubsub_v1.publisher.client": ["Client.__init__"],
    "google.cloud.pubsub_v1.subscriber.client": ["Client.__init__"],
    "google.cloud.secretmanager_v1.services.secret_manager_service.client": ["SecretManagerServiceClient.__init__"],
    "google.cloud.aiplatform.initializer": ["_Config.init"],
    "vertexai.generative_models._generative_models": ["_GenerativeModel.__init__"],
    "google.api_core.grpc_helpers": ["create_channel"],
    "google.api_core.grpc_helpers_async": ["create_channel"],
}


def _is_guarded(fn: Any) -> bool:
    return bool(getattr(fn, GUARD_MARK, False))


def _mark(fn: Callable) -> Callable:
    setattr(fn, GUARD_MARK, True)
    return fn


def _resolve(module: Any, dotted: str) -> Tuple[Any, str]:
    parts = dotted.split(".")
    owner = module
    for p in parts[:-1]:
        owner = getattr(owner, p)
    return owner, parts[-1]


class Guard:
    def __init__(self, state: RunState, allow_hosts: Iterable[str] = (), resolver: Optional[Callable] = None):
        self.state = state
        self.allow_hosts: Set[str] = {h.lower().rstrip(".") for h in allow_hosts}
        self.allowed_ips: Set[str] = set()
        self._resolver = resolver  # test hook: replaces the real getaddrinfo for allowlisted hosts only
        self.installed: List[str] = []
        self._finder: Optional[importlib.abc.MetaPathFinder] = None

    # ------------------------------------------------------------------------------------------------ util
    def _block(self, exc_type: type, kind: str, detail: Any) -> None:
        self.state.record(kind, detail, stack=True)
        raise exc_type(f"stackvend-eval guard blocked {kind}: {detail}")

    # ------------------------------------------------------------------------------------- process (B3)
    def install_process_guard(self) -> None:
        guard = self

        def deny(name: str) -> Callable:
            def _denied(*args: Any, **kwargs: Any) -> Any:
                summary = repr(args[:2])[:200]
                guard._block(EvalProcessBlocked, "process_blocked", {"call": name, "args": summary})
            return _mark(_denied)

        import _posixsubprocess  # Popen, multiprocessing spawn/forkserver, asyncio subprocesses all land here
        replaced: Dict[int, Tuple[Callable, Callable]] = {}  # id -> (original kept alive, guard)
        if not _is_guarded(_posixsubprocess.fork_exec):
            orig = _posixsubprocess.fork_exec
            replaced[id(orig)] = (orig, deny("_posixsubprocess.fork_exec"))
            _posixsubprocess.fork_exec = replaced[id(orig)][1]
        for name in OS_PROCESS_FUNCS:
            fn = getattr(os, name, None)
            if fn is not None and not _is_guarded(fn):
                new = deny(f"os.{name}")
                replaced[id(fn)] = (fn, new)
                setattr(os, name, new)
        import pty
        for name in ("spawn", "fork"):
            if hasattr(pty, name) and not _is_guarded(getattr(pty, name)):
                new = deny(f"pty.{name}")
                replaced[id(getattr(pty, name))] = (getattr(pty, name), new)
                setattr(pty, name, new)
        # Modules imported earlier may hold their own reference (subprocess binds `_fork_exec` at import;
        # `from os import system` style imports): rebind every module global that IS one of the originals.
        for mod in list(sys.modules.values()):
            d = getattr(mod, "__dict__", None)
            if not isinstance(d, dict):
                continue
            for k, v in list(d.items()):
                if id(v) in replaced and replaced[id(v)][0] is v:
                    d[k] = replaced[id(v)][1]
        self.installed.append("process")

    # ---------------------------------------------------------------------------------------- grpc (B4)
    def install_grpc_guard(self) -> None:
        try:
            import grpc
            import grpc._channel
            import grpc.aio
            import grpc.aio._channel
        except Exception:  # grpc not installed: nothing can open a channel
            self.installed.append("grpc(absent)")
            return
        guard = self

        def deny(name: str) -> Callable:
            def _denied(*args: Any, **kwargs: Any) -> Any:
                target = args[1] if name.endswith("__init__") and len(args) > 1 else (args[0] if args else kwargs.get("target"))
                guard._block(EvalEgressBlocked, "grpc_blocked", {"call": name, "target": str(target)[:120]})
            return _mark(_denied)

        for mod, attr in ((grpc._channel.Channel, "__init__"), (grpc.aio._channel.Channel, "__init__"),
                          (grpc, "secure_channel"), (grpc, "insecure_channel"),
                          (grpc.aio, "secure_channel"), (grpc.aio, "insecure_channel")):
            if not _is_guarded(getattr(mod, attr)):
                setattr(mod, attr, deny(f"{getattr(mod, '__name__', mod)}.{attr}"))
        self.installed.append("grpc")

    # ------------------------------------------------------------------------------------------ sockets
    def _host_allowed(self, host: Any) -> bool:
        if isinstance(host, bytes):
            host = host.decode("ascii", "ignore")
        return host is not None and str(host).lower().rstrip(".") in self.allow_hosts

    def _ip_allowed(self, address: Any, family: int) -> bool:
        if family not in (socket.AF_INET, socket.AF_INET6):
            return False  # AF_UNIX and anything else: no local daemons either
        try:
            ip = str(ipaddress.ip_address(address[0]))
        except Exception:
            return False
        return ip in self.allowed_ips

    def _remember_ips(self, ips: Iterable[Any]) -> None:
        for ip in ips:
            try:
                self.allowed_ips.add(str(ipaddress.ip_address(ip)))
            except Exception:
                pass

    def _stub_ips(self, host: Any) -> List[str]:
        """Test hook: answer the non-getaddrinfo resolver calls from the getaddrinfo stub (no real DNS)."""
        return [e[4][0] for e in self._resolver(host, None, socket.AF_INET)]

    def install_socket_guard(self) -> None:
        guard = self
        real_getaddrinfo = socket.getaddrinfo
        if _is_guarded(real_getaddrinfo):
            return
        real_gethostbyname, real_gethostbyname_ex = socket.gethostbyname, socket.gethostbyname_ex
        real_gethostbyaddr, real_getnameinfo = socket.gethostbyaddr, socket.getnameinfo

        def refuse_host(op: str, host: Any, **extra: Any) -> None:
            if not guard._host_allowed(host):
                guard._block(EvalEgressBlocked, "egress_blocked", {"op": op, "host": str(host)[:120], **extra})

        def getaddrinfo(host, port, *args, **kwargs):  # noqa: ANN001
            refuse_host("getaddrinfo", host, port=port)
            res = (guard._resolver or real_getaddrinfo)(host, port, *args, **kwargs)
            guard._remember_ips(entry[4][0] for entry in res)
            return res

        # RT finding 1a: the other resolver entry points go through the same hostname allowlist.
        def gethostbyname(host):  # noqa: ANN001
            refuse_host("gethostbyname", host)
            ip = guard._stub_ips(host)[0] if guard._resolver else real_gethostbyname(host)
            guard._remember_ips([ip])
            return ip

        def gethostbyname_ex(host):  # noqa: ANN001
            refuse_host("gethostbyname_ex", host)
            res = (str(host), [], guard._stub_ips(host)) if guard._resolver else real_gethostbyname_ex(host)
            guard._remember_ips(res[2])
            return res

        def gethostbyaddr(host):  # noqa: ANN001
            # Reverse lookups are never needed on the generation path: only an allowlisted *hostname* is admitted.
            refuse_host("gethostbyaddr", host)
            res = (str(host), [], guard._stub_ips(host)) if guard._resolver else real_gethostbyaddr(host)
            guard._remember_ips(res[2])
            return res

        def getnameinfo(sockaddr, flags):  # noqa: ANN001
            host = sockaddr[0] if isinstance(sockaddr, tuple) and sockaddr else None
            refuse_host("getnameinfo", host)
            if guard._resolver:
                return (str(host), str(sockaddr[1]))
            return real_getnameinfo(sockaddr, flags)

        resolver_fns = {"getaddrinfo": (real_getaddrinfo, getaddrinfo),
                        "gethostbyname": (real_gethostbyname, gethostbyname),
                        "gethostbyname_ex": (real_gethostbyname_ex, gethostbyname_ex),
                        "gethostbyaddr": (real_gethostbyaddr, gethostbyaddr),
                        "getnameinfo": (real_getnameinfo, getnameinfo)}
        replaced: Dict[int, Tuple[Any, Callable]] = {}
        for name, (orig, wrapper) in resolver_fns.items():
            setattr(socket, name, _mark(wrapper))
            replaced[id(orig)] = (orig, wrapper)
        # `from socket import gethostbyname` style references bound before install (and the `_socket` builtins the
        # socket module re-exports): rebind every module global that IS one of the originals.
        for mod in list(sys.modules.values()):
            d = getattr(mod, "__dict__", None)
            if not isinstance(d, dict):
                continue
            for k, v in list(d.items()):
                if id(v) in replaced and replaced[id(v)][0] is v:
                    d[k] = replaced[id(v)][1]

        base = socket.socket
        real_connect, real_connect_ex, real_sendto = base.connect, base.connect_ex, base.sendto
        real_sendmsg = getattr(base, "sendmsg", None)

        def connect(self, address):  # noqa: ANN001
            if not guard._ip_allowed(address, self.family):
                guard._block(EvalEgressBlocked, "egress_blocked", {"op": "connect", "address": str(address)[:80]})
            return real_connect(self, address)

        def connect_ex(self, address):  # noqa: ANN001
            if not guard._ip_allowed(address, self.family):
                guard._block(EvalEgressBlocked, "egress_blocked", {"op": "connect_ex", "address": str(address)[:80]})
            return real_connect_ex(self, address)

        def sendto(self, data, *args):  # noqa: ANN001
            address = args[-1] if args else None
            if address is not None and not guard._ip_allowed(address, self.family):
                guard._block(EvalEgressBlocked, "egress_blocked", {"op": "sendto", "address": str(address)[:80]})
            return real_sendto(self, data, *args)

        def sendmsg(self, buffers, *args):  # noqa: ANN001  (buffers[, ancdata[, flags[, address]]])
            address = args[2] if len(args) > 2 else None
            if address is not None and not guard._ip_allowed(address, self.family):
                guard._block(EvalEgressBlocked, "egress_blocked", {"op": "sendmsg", "address": str(address)[:80]})
            return real_sendmsg(self, buffers, *args)

        base.connect = _mark(connect)
        base.connect_ex = _mark(connect_ex)
        base.sendto = _mark(sendto)
        if real_sendmsg is not None:
            base.sendmsg = _mark(sendmsg)
        self.installed.append("sockets")

    # --------------------------------------------------------------------------------- client ctors (B2)
    def _patch_module(self, module: Any, attrs: List[str]) -> None:
        guard = self
        for dotted in attrs:
            try:
                owner, name = _resolve(module, dotted)
            except AttributeError:
                continue
            current = getattr(owner, name)
            if _is_guarded(current):
                continue
            label = f"{module.__name__}.{dotted}"

            def _denied(*args: Any, _label: str = label, **kwargs: Any) -> Any:
                guard._block(EvalClientBlocked, "client_blocked", {"call": _label})
            setattr(owner, name, _mark(_denied))

    def install_client_guards(self) -> None:
        for modname, attrs in CLIENT_TARGETS.items():
            if modname in sys.modules:
                self._patch_module(sys.modules[modname], attrs)
        guard = self

        class _Finder(importlib.abc.MetaPathFinder):
            def find_spec(self, name, path, target=None):  # noqa: ANN001
                if name not in CLIENT_TARGETS:
                    return None
                spec = importlib.machinery.PathFinder.find_spec(name, path, target)
                if spec is None or spec.loader is None or not hasattr(spec.loader, "exec_module"):
                    return spec
                real_loader = spec.loader

                class _Loader(importlib.abc.Loader):
                    def create_module(self, s):  # noqa: ANN001
                        return real_loader.create_module(s)

                    def exec_module(self, module):  # noqa: ANN001
                        real_loader.exec_module(module)
                        guard._patch_module(module, CLIENT_TARGETS[name])

                spec.loader = _Loader()
                return spec

        if self._finder is None:
            self._finder = _Finder()
            sys.meta_path.insert(0, self._finder)
        self.installed.append("clients")

    def install_auth_guard(self) -> None:
        guard = self
        try:
            import google.auth
            import google.auth._default
        except Exception:
            return

        def default(*args: Any, **kwargs: Any) -> Any:
            guard._block(EvalClientBlocked, "client_blocked", {"call": "google.auth.default"})
        default = _mark(default)
        google.auth.default = default
        google.auth._default.default = default
        self.installed.append("auth")

    def seal_genai(self) -> None:
        """After the harness built its own client: any further genai.Client() is unmetered -> refuse."""
        guard = self
        import google.genai.client as gclient
        import google.genai as genai_pkg
        if _is_guarded(gclient.Client.__init__):
            return

        def _denied(*args: Any, **kwargs: Any) -> Any:
            guard.state.invalidate("unmetered_llm_client", "product constructed its own google.genai.Client")
            guard._block(EvalClientBlocked, "client_blocked", {"call": "google.genai.Client.__init__"})
        gclient.Client.__init__ = _mark(_denied)
        if getattr(genai_pkg, "Client", None) is not gclient.Client:
            genai_pkg.Client.__init__ = gclient.Client.__init__
        self.installed.append("genai_sealed")

    # ---------------------------------------------------------------------------------------- env checks
    @staticmethod
    def env_problems(environ: Optional[Dict[str, str]] = None) -> List[str]:
        env = os.environ if environ is None else environ
        problems = [f"{v} is set" for v in EMULATOR_VARS if env.get(v)]
        if env.get("GOOGLE_APPLICATION_CREDENTIALS") != DISABLED_ADC:
            problems.append("GOOGLE_APPLICATION_CREDENTIALS is not the disabled sentinel")
        for v in ("GOOGLE_CLOUD_PROJECT", "GCP_PROJECT", "GCLOUD_PROJECT", "GITHUB_TOKEN", "GITHUB_PAT",
                  "GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_OAUTH_ACCESS_TOKEN"):
            if env.get(v):
                problems.append(f"{v} is set")
        if env.get("PROJECT_ID"):
            problems.append("PROJECT_ID is non-empty")
        return problems

    def install_all(self) -> None:
        """Everything except seal_genai (which must run after the harness client is built)."""
        self.install_process_guard()
        self.install_grpc_guard()
        self.install_socket_guard()
        self.install_client_guards()
        self.install_auth_guard()
