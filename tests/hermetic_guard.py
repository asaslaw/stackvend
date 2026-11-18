"""
Hermetic test guard (Wave 1 lane 2: FD-05 non-hermetic group, FD-60 prerequisite).

Makes a test process behave like a machine with NO credentials and NO network, whatever the developer's machine has
(real ADC in ~/.config/gcloud, a gcloud login, git credential helpers, API keys in the shell). Plan and red-team:
docs/implemented/wave1-lane2-tests-ci-plan.md, docs/implemented/wave1-lane2-plan-red-team.md.

Installed by:
  * the repo-root conftest.py (every pytest run under the repo: tests/, mcp-servers/*, apps/*),
  * the first import of every tests/test_*.py (``import hermetic_guard``), so ``python -m unittest`` and
    ``python tests/test_x.py`` (which never load conftest.py) are guarded too. tests/test_hermetic_guard.py enforces it,
  * every Python child process of a guarded process: Layer 0 puts tests/hermetic_child/ first on PYTHONPATH, whose
    sitecustomize.py installs this module before the child runs anything (then chains to the next sitecustomize).
    Violations in such a child are blocked there and forwarded to the parent pytest (STACKVEND_HERMETIC_CHILD_LOG),
    which fails the test that spawned it. ``python -I``/``-E``/``-S`` children ignore PYTHONPATH: they only get
    Layer 0 (the harnesses that use ``-I`` check their own NETWORK_ATTEMPTS).

Layers (all idempotent; the audit hook is process-wide and cannot be removed, so it consults ``state.enabled``):
  0. Environment, forced at install: ADC path -> non-existent file, empty CLOUDSDK_CONFIG, loopback HTTP(S)/gRPC proxy
     sentinel (http://127.0.0.1:9) inherited by every child (curl/git/tofu/gcloud/gRPC honour it), git credential
     helpers and global/system config disabled, API keys / tokens popped. Re-applied to every child process env.
  1. Audit hook, in-process sockets: DNS (getaddrinfo, gethostbyname[_ex], gethostbyaddr, getnameinfo) and
     connect/sendto/sendmsg to anything but loopback/AF_UNIX raise (an OSError subclass, i.e. exactly what an offline
     machine produces) and are recorded. Event loops whose C code does its own DNS/connect without audit events
     (uvloop/libuv) are replaced by the audited asyncio loop (Layer 3).
  2. Audit hook, processes: gcloud/gsutil/bq/kubectl/gh/curl/wget/docker/helm/ssh, git network sub-commands with a
     non-file, non-loopback remote, mutating tofu/terraform sub-commands and ``python -m unittest`` children are
     refused before spawn; every other child gets the Layer-0 security settings injected (even when the caller built
     its env from scratch or cleared os.environ; a caller-built env keeps its own choices otherwise).
  3. Credential + client choke points, patched when the REAL module is imported (meta-path hook; never eagerly
     imported here, so tests that stub ``google.*`` through sys.modules keep working): every ``default`` binding,
     the gcloud well-known ADC file lookup, the GCE metadata probe, google-cloud-core clients (GCS, BigQuery, ...),
     gRPC channels, google-genai clients, PyGithub requesters and uvloop (asyncio loop instead). Opening a real
     credential store under the real home directory (~/.config/gcloud, ~/.git-credentials, ~/.config/gh, ~/.netrc,
     ~/.kube, ~/.docker/config.json) is refused by the audit hook as a last line of defence (covers bindings taken before the guard existed).

Blocking is unconditional. Whether a recorded violation also FAILS the test is decided by the root conftest
(see FAIL_KINDS and tests/hermetic_known_leaks.py). Firestore keeps its own FD-08 guard in the root conftest.

Escape hatches: none inside the suite. ``@pytest.mark.live`` tests are skipped unless ``--run-live``; even then the
guard stays on unless STACKVEND_ALLOW_NETWORK=1 (CI never sets either).

Threat model (code red-team finding 8): this guard is a SAFETY NET FOR MISTAKES, NOT A SANDBOX FOR HOSTILE CODE. It
stops code under test from accidentally using the developer's credentials or the network. A deliberately hostile test
can still get around it, e.g. ``bash -lc "gcloud ..."`` or a compound ``sh -c`` (the argv rules are a proxy; the child
still runs with Layer 0, i.e. an empty CLOUDSDK_CONFIG and the proxy sentinel), reading the real ADC file through a
non-Python child (``cat``) or a ``python -I`` child, flipping ``state().enabled``, ctypes, or constructing
``uvloop.loop.Loop`` (the C base class) directly. The only complete answer is OS isolation: CI runs every pytest
invocation in a loopback-only network namespace (.github/scripts/run-offline.sh); macOS has no equivalent. Do NOT
answer these with more argv parsing (anti-heuristic rule, AGENTS.md invariant 2).
"""
import atexit
import importlib.abc
import importlib.machinery
import ipaddress
import json
import os
import shlex
import socket
import sys
import tempfile
import traceback
import urllib.parse

_STATE_ATTR = "_stackvend_hermetic_guard_state"
PROXY_SENTINEL_HOST = "127.0.0.1"
PROXY_SENTINEL_PORT = 9  # RFC 863 discard port: nothing listens there, so proxied egress fails fast and is recorded
PROXY_SENTINEL = f"http://{PROXY_SENTINEL_HOST}:{PROXY_SENTINEL_PORT}"
ADC_DISABLED_PATH = "/nonexistent/adc-disabled.json"
# Python children: this directory goes first on PYTHONPATH; its sitecustomize.py installs the guard in the child.
CHILD_SHIM_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hermetic_child")
# A guarded child appends its violations (JSON lines) to this file; the parent pytest attributes them to the running
# test.
CHILD_LOG_ENV = "STACKVEND_HERMETIC_CHILD_LOG"
_GCLOUD_DIR_PREFIX = "hermetic-gcloud-config-"
_CHILD_FLAG_ATTR = "_stackvend_hermetic_child"  # set on sys by tests/hermetic_child/sitecustomize.py

# Kinds of recorded events. FAIL_KINDS fail the test that caused them (root conftest); others are informational.
FAIL_KINDS = frozenset({"socket", "dns", "subprocess", "client", "credential-file"})
INFO_KINDS = frozenset({"adc", "firestore", "uvloop"})

FORCED_ENV = {
    "NO_GCE_CHECK": "True",
    "GCE_METADATA_HOST": f"{PROXY_SENTINEL_HOST}:{PROXY_SENTINEL_PORT}",
    "GCE_METADATA_IP": f"{PROXY_SENTINEL_HOST}:{PROXY_SENTINEL_PORT}",
    "HTTP_PROXY": PROXY_SENTINEL,
    "HTTPS_PROXY": PROXY_SENTINEL,
    "ALL_PROXY": PROXY_SENTINEL,
    "http_proxy": PROXY_SENTINEL,
    "https_proxy": PROXY_SENTINEL,
    "all_proxy": PROXY_SENTINEL,
    "grpc_proxy": PROXY_SENTINEL,
    "NO_PROXY": "localhost,127.0.0.1,::1",
    "no_proxy": "localhost,127.0.0.1,::1",
    # http(s) stays allowed so a test can clone from a server it runs on loopback (lane 3's smart-HTTP test); any
    # other host goes through the proxy sentinel (libcurl honours http(s)_proxy / NO_PROXY), and argv URLs to a
    # non-loopback host are refused before spawn. ssh/git:// are never allowed.
    "GIT_ALLOW_PROTOCOL": "file:http:https",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_ASKPASS": "/usr/bin/false",
    "SSH_ASKPASS": "/usr/bin/false",
    "CHECKPOINT_DISABLE": "1",
}
# The TEST PROCESS's own environment only (install()): forced / defaulted on os.environ. Never injected into an env a
# test built for a child: such an env says exactly what the child should see (e.g. "no PROJECT_ID"), and adding mock
# project ids changes what the child does (cross-lane merge simulation: lane 5's apply.sh tests, lane 7's eval canary).
PROCESS_FORCED_ENV = {"CLOUDSDK_CORE_PROJECT": "mock-stackvend-project"}
DEFAULT_ENV = {  # tests may legitimately override them
    "PROJECT_ID": "mock-stackvend-project",
    "GCP_PROJECT": "mock-stackvend-project",
    "GOOGLE_CLOUD_PROJECT": "mock-stackvend-project",
    "DEFAULT_REGION": "us-central1",
    "TEST_MODE": "true",
}
# GIT_CONFIG_GLOBAL=/dev/null (Layer 0) drops the developer's identity; local test repos still need one to commit.
# Defaulted everywhere Layer 0 goes, because Layer 0 is what removed it.
GIT_IDENTITY_ENV = {
    "GIT_AUTHOR_NAME": "Hermetic Test",
    "GIT_AUTHOR_EMAIL": "hermetic-test@example.invalid",
    "GIT_COMMITTER_NAME": "Hermetic Test",
    "GIT_COMMITTER_EMAIL": "hermetic-test@example.invalid",
}
SECRET_ENV = (
    "GITHUB_TOKEN", "GITHUB_PAT", "GH_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_APP_ID", "GITHUB_APP_PRIVATE_KEY",
    "GOOGLE_API_KEY", "GEMINI_API_KEY", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "INFRACOST_API_KEY",
    "GOOGLE_CREDENTIALS", "GOOGLE_CLOUD_KEYFILE_JSON", "GOOGLE_OAUTH_ACCESS_TOKEN",
    "CLOUDSDK_AUTH_ACCESS_TOKEN", "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE", "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
    "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT",
)
BLOCKED_BINARIES = frozenset({
    "gcloud", "gsutil", "bq", "kubectl", "gke-gcloud-auth-plugin", "gh", "curl", "wget", "docker", "helm",
    "ssh", "scp", "sftp", "rsync",
})
GIT_NETWORK_SUBCOMMANDS = frozenset({"clone", "fetch", "pull", "push", "ls-remote", "submodule", "remote", "archive"})
IAC_MUTATING_SUBCOMMANDS = frozenset({
    "apply", "destroy", "import", "state", "force-unlock", "refresh", "taint", "untaint", "login", "logout",
})
# git global options that consume the next argv element.
_GIT_OPTS_WITH_VALUE = frozenset({"-c", "-C", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--config-env"})
# Credential stores under the REAL home directory that must never be read by a test.
_HOME_CREDENTIAL_PATHS = (
    ".config/gcloud", ".git-credentials", ".config/git/credentials", ".config/gh", ".netrc", ".kube",
    ".docker/config.json", ".aws", ".azure",
)
_EMULATOR_ENV = ("STORAGE_EMULATOR_HOST", "PUBSUB_EMULATOR_HOST", "FIRESTORE_EMULATOR_HOST",
                 "BIGTABLE_EMULATOR_HOST", "DATASTORE_EMULATOR_HOST", "SPANNER_EMULATOR_HOST")


# ----------------------------------------------------------------------------------------------- blocked errors
class HermeticGuardError(Exception):
    """Marker base: every error raised by the guard is also an instance of this."""


class HermeticNetworkBlocked(HermeticGuardError, ConnectionRefusedError):
    pass


class HermeticDNSBlocked(HermeticGuardError, socket.gaierror):
    pass


class HermeticSubprocessBlocked(HermeticGuardError, PermissionError):
    pass


class HermeticCredentialFileBlocked(HermeticGuardError, PermissionError):
    pass


class HermeticClientBlocked(HermeticGuardError, RuntimeError):
    pass


# ----------------------------------------------------------------------------------------------- shared state
class _State:
    def __init__(self):
        self.installed = False
        self.enabled = True
        self.current = "<session>"  # nodeid (or "<collect:path>") the root conftest is currently running
        self.records = []  # dicts: kind, detail, nodeid, stack
        self.cred_prefixes = ()
        self.adc_error_cls = None
        self.gcloud_config_dir = None
        self.child_log_path = None  # file this process's guarded children forward their violations to (we read it)
        self.child_log_offset = 0
        self.forward_path = None  # this process is a guarded child: append our violations to the parent's file


def state():
    st = getattr(sys, _STATE_ATTR, None)
    if st is None:
        st = _State()
        setattr(sys, _STATE_ATTR, st)
    return st


def record(kind, detail, stack=True):
    st = state()
    rec = {
        "kind": kind,
        "detail": str(detail)[:400],
        "nodeid": st.current,
        "stack": "".join(traceback.format_stack(limit=14)[:-2]) if stack else "",
    }
    st.records.append(rec)
    if st.forward_path and kind in FAIL_KINDS:  # info kinds (adc, firestore) stay local: they feed per-file ratchets
        _forward(st.forward_path, rec)


def _forward(path, rec):
    """Guarded child -> parent pytest: one JSON line per violation (O_APPEND: concurrent children do not interleave)."""
    line = json.dumps({"kind": rec["kind"], "detail": f"[child pid {os.getpid()}: {' '.join(sys.argv)[:120]}] "
                                                      f"{rec['detail']}", "stack": rec["stack"][-2000:]}) + "\n"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, line.encode("utf-8", "replace"))
        finally:
            os.close(fd)
    except OSError:
        pass  # the parent is gone; the violation was still blocked here


def start_child_log():
    """Called by the root conftest (the pytest process): guarded children report into a file this process reads."""
    st = state()
    if st.child_log_path is None:
        fd, st.child_log_path = tempfile.mkstemp(prefix="hermetic-child-log-", suffix=".jsonl")
        os.close(fd)
        st.child_log_offset = 0
        atexit.register(_remove_quietly, st.child_log_path)
    os.environ[CHILD_LOG_ENV] = st.child_log_path
    return st.child_log_path


def ingest_child_records():
    """Move violations forwarded by guarded children into this process's records, attributed to ``state().current``
    (the test or module that was running when the root conftest calls this). Returns the number ingested."""
    st = state()
    if not st.child_log_path:
        return 0
    try:
        with open(st.child_log_path, "rb") as fh:
            fh.seek(st.child_log_offset)
            data = fh.read()
    except OSError:
        return 0
    end = data.rfind(b"\n") + 1  # a partially written last line is read next time
    st.child_log_offset += end
    n = 0
    for raw in data[:end].splitlines():
        try:
            item = json.loads(raw)
        except ValueError:
            continue
        st.records.append({"kind": str(item.get("kind", "subprocess")), "detail": str(item.get("detail", ""))[:400],
                           "nodeid": st.current, "stack": str(item.get("stack", ""))})
        n += 1
    return n


def _remove_quietly(path, is_dir=False):
    import shutil

    try:
        shutil.rmtree(path) if is_dir else os.unlink(path)
    except OSError:
        pass


def records_for(nodeid, kinds=FAIL_KINDS, since=0):
    return [r for r in state().records[since:] if r["nodeid"] == nodeid and r["kind"] in kinds]


# ----------------------------------------------------------------------------------------------- host helpers
# This machine's own name: socket.getfqdn() (http.server, logging, email) resolves it; that is not egress.
try:
    _LOCAL_NAMES = frozenset(n.lower() for n in {socket.gethostname()} if n)
except OSError:
    _LOCAL_NAMES = frozenset()

def is_loopback_host(host):
    if host is None:
        return True  # bind-style / unconnected
    if isinstance(host, bytes):
        host = host.decode("ascii", "ignore")
    host = str(host).strip().strip("[]")
    if not host:
        return True
    low = host.lower()
    if low == "localhost" or low.endswith(".localhost") or low in _LOCAL_NAMES:
        return True
    try:
        ip = ipaddress.ip_address(low.split("%", 1)[0])
    except ValueError:
        return False
    return ip.is_loopback or ip.is_unspecified


def _grpc_target_host(target):
    """'dns:///h:443' / 'h:443' / '[::1]:50051' / 'unix:/path' -> host (None for unix sockets)."""
    t = target.decode() if isinstance(target, bytes) else str(target)
    if t.startswith(("unix:", "unix-abstract:")):
        return None
    if "://" in t:
        t = t.split("://", 1)[1].lstrip("/")
    elif t.startswith("dns:"):
        t = t[4:].lstrip("/")
    if t.startswith("["):
        return t[1:t.index("]")] if "]" in t else t
    return t.rsplit(":", 1)[0] if t.count(":") == 1 else t


# ----------------------------------------------------------------------------------------------- Layer 0
def hermetic_env(base):
    """Return a copy of mapping ``base`` with the Layer-0 settings applied (forced keys set, secrets removed)."""
    env = dict(base)
    _apply_env(env)
    return env


def _shim_dir():
    return CHILD_SHIM_DIR if os.path.isfile(os.path.join(CHILD_SHIM_DIR, "sitecustomize.py")) else None


def _has_shim(env):
    shim = _shim_dir()
    return shim is None or shim in (env.get("PYTHONPATH") or "").split(os.pathsep)


def _gcloud_config_ok(value):
    """A child may use its own gcloud config dir (a test's stub config), never the developer's real one."""
    st = state()
    if not st.gcloud_config_dir:
        return True
    if not value:
        return False
    if value == st.gcloud_config_dir:
        return True
    real = os.path.realpath(value)
    return not any(real == os.path.realpath(p) or real.startswith(os.path.realpath(p) + os.sep)
                   or os.path.realpath(p).startswith(real + os.sep) for p in st.cred_prefixes)


def _adc_path_ok(value):
    """GOOGLE_APPLICATION_CREDENTIALS a test may hand its child: the disabled path, a path that does not exist (a
    negative probe, e.g. lane 7's eval canary), or a fake key the test wrote under the temp dir. Never an existing
    file elsewhere (that could be the developer's real ADC or a service-account key)."""
    if not value:
        return False
    if value == ADC_DISABLED_PATH:
        return True
    real = os.path.realpath(value)
    if not os.path.exists(real):
        return True
    tmp = os.path.realpath(tempfile.gettempdir())
    return real.startswith(tmp + os.sep) and not any(real.startswith(os.path.realpath(p)) for p in state().cred_prefixes)


def _apply_env(env, process=False):
    """Layer 0 into ``env``. ``process=True`` (install(): the test process's own os.environ) also forces / defaults
    the mock project settings; a child env built by a test only gets the security settings."""
    st = state()
    for k in SECRET_ENV:
        env.pop(k, None)
    for k, v in FORCED_ENV.items():
        env[k] = v
    if process or not _adc_path_ok(env.get("GOOGLE_APPLICATION_CREDENTIALS")):
        env["GOOGLE_APPLICATION_CREDENTIALS"] = ADC_DISABLED_PATH
    if not _gcloud_config_ok(env.get("CLOUDSDK_CONFIG")):
        env["CLOUDSDK_CONFIG"] = st.gcloud_config_dir
    _disable_git_credential_helpers(env)
    if not _has_shim(env):
        rest = [p for p in (env.get("PYTHONPATH") or "").split(os.pathsep) if p]
        env["PYTHONPATH"] = os.pathsep.join([_shim_dir()] + rest)
    log = st.child_log_path or st.forward_path
    if log:
        env.setdefault(CHILD_LOG_ENV, log)
    for k, v in GIT_IDENTITY_ENV.items():
        env.setdefault(k, v)
    if process:
        env.update(PROCESS_FORCED_ENV)
        for k, v in DEFAULT_ENV.items():
            env.setdefault(k, v)


def _git_config_entries(env):
    try:
        n = int(env.get("GIT_CONFIG_COUNT") or 0)
    except ValueError:
        n = 0
    return n, [(env.get(f"GIT_CONFIG_KEY_{i}"), env.get(f"GIT_CONFIG_VALUE_{i}")) for i in range(n)]


def _git_helpers_disabled(env):
    """credential.helper= (empty: resets the helper list) is the LAST credential.helper entry of GIT_CONFIG_*."""
    n, entries = _git_config_entries(env)
    helpers = [v for k, v in entries if (k or "").lower() == "credential.helper"]
    return bool(helpers) and helpers[-1] == ""


def _disable_git_credential_helpers(env):
    """Append ``credential.helper=`` to the caller's GIT_CONFIG_* entries (a test may pass its own, e.g.
    http.extraHeader for a loopback git server; overwriting entry 0 would drop it)."""
    if _git_helpers_disabled(env):
        return
    n, _ = _git_config_entries(env)
    env[f"GIT_CONFIG_KEY_{n}"] = "credential.helper"
    env[f"GIT_CONFIG_VALUE_{n}"] = ""
    env["GIT_CONFIG_COUNT"] = str(n + 1)


def _env_is_hermetic(env):
    st = state()
    if any(k in env for k in SECRET_ENV):
        return False
    if any(env.get(k) != v for k, v in FORCED_ENV.items()):
        return False
    if not (_has_shim(env) and _git_helpers_disabled(env) and _adc_path_ok(env.get("GOOGLE_APPLICATION_CREDENTIALS"))):
        return False
    return _gcloud_config_ok(env.get("CLOUDSDK_CONFIG"))


def child_env(drop=(), extra=None):
    """Env for a child process started by a test: the current env + Layer 0, minus ``drop``, plus ``extra``.

    ``extra`` may not override Layer-0 keys (a test cannot re-enable the network for a child).
    """
    env = hermetic_env(os.environ)
    for k in drop:
        env.pop(k, None)
    for k, v in (extra or {}).items():
        if k in FORCED_ENV or k in SECRET_ENV or k == "PYTHONPATH":
            raise ValueError(f"hermetic_guard.child_env: {k} is controlled by the guard")
        env[k] = v
    if not _has_shim(env):  # drop=("PYTHONPATH",) drops other entries (an interim sitecustomize), never the guard
        env["PYTHONPATH"] = _shim_dir()
    return env


class UnavailableInTests(ConnectionError):
    """Raised by test doubles from ``unavailable()``: the dependency behaves as on an offline, credential-less host."""


class _Unavailable:
    """Context manager / function decorator / TestCase class decorator; resolves its target lazily at entry.

    Resolution imports the longest importable module prefix and then walks attributes, so it works even when the
    FD-05A sys.modules sandbox has detached ``pkg.child`` attributes (mock.patch("google.genai.Client") would fail
    with "module 'google' has no attribute 'genai'" there).
    """

    def __init__(self, target, what=None):
        self.target = target
        self.what = what or target
        self._patcher = None

    def _resolve(self):
        import importlib

        parts = self.target.split(".")
        errors = []
        for i in range(len(parts) - 1, 0, -1):
            try:
                obj = importlib.import_module(".".join(parts[:i]))
                for attr in parts[i:-1]:
                    obj = getattr(obj, attr)
            except (ImportError, AttributeError) as e:
                errors.append(f"{'.'.join(parts[:i])}: {e!r}")
                continue
            return obj, parts[-1]
        raise ImportError(f"hermetic_guard.unavailable: cannot resolve {self.target!r} ({'; '.join(errors)})")

    def __enter__(self):
        from unittest import mock

        try:
            owner, attr = self._resolve()
        except ImportError:
            # The target's module cannot be imported in this test's world (a test stubbed a parent package such as
            # google.auth through sys.modules): product code cannot import it either, so nothing real can be built.
            return None
        double = mock.MagicMock(side_effect=UnavailableInTests(f"{self.what} is unavailable in tests"))
        self._patcher = mock.patch.object(owner, attr, new=double)
        return self._patcher.__enter__()

    def __exit__(self, *exc):
        patcher, self._patcher = self._patcher, None
        return patcher.__exit__(*exc) if patcher is not None else False

    def __call__(self, obj):
        import functools

        if isinstance(obj, type):
            for name, member in list(vars(obj).items()):
                if name.startswith("test") and callable(member):
                    setattr(obj, name, _Unavailable(self.target, self.what)(member))
            return obj

        @functools.wraps(obj)
        def wrapper(*args, **kwargs):
            with _Unavailable(self.target, self.what):
                return obj(*args, **kwargs)

        return wrapper


def unavailable(target, what=None):
    """Test double for "this client cannot be built here" (Gemini, GCS, a remote MCP server...): replaces ``target``
    with a callable raising UnavailableInTests, which is what an offline, credential-less host produces. Use it
    instead of letting product code hit the guard (that fails the test).

    Works as a context manager, a function decorator or a TestCase class decorator (no extra mock argument):
    ``with hermetic_guard.unavailable("google.genai.Client", "Gemini"): agent = DeveloperAgent(...)``

    Caveat (code-RT finding 6): the target is resolved by walking attributes, so a path through a module attribute
    patches the module the attribute points to, process-wide, for the duration: ``unavailable("pkg.mod.httpx.Client")``
    replaces the GLOBAL ``httpx.Client`` (Starlette's TestClient subclasses it), exactly like patching
    ``pkg.mod.shutil.which`` patches ``shutil.which``. Do not combine such a target with TestClient in the same test.
    """
    return _Unavailable(target, what)


def run_python_child(args, **kwargs):
    """subprocess.run([sys.executable, *args]) with a hermetic env (unless the caller passes one built by child_env)."""
    import subprocess

    kwargs.setdefault("env", child_env())
    return subprocess.run([sys.executable, *args], **kwargs)


# ----------------------------------------------------------------------------------------------- Layer 1/2 hook
def _proc_block_reason(argv):
    """Return why spawning ``argv`` (list of str) must be refused, or None."""
    if not argv:
        return None
    exe = os.path.basename(str(argv[0]))
    if exe in ("sh", "bash", "zsh", "dash") and "-c" in argv[1:]:
        cmd = argv[argv.index("-c") + 1] if argv.index("-c") + 1 < len(argv) else ""
        try:
            inner = shlex.split(cmd)
        except ValueError:
            inner = cmd.split()
        return _proc_block_reason(inner)
    if exe in BLOCKED_BINARIES:
        return f"'{exe}' can reach the network or the developer's cloud login"
    if exe == "env" and len(argv) > 1:
        rest = [a for a in argv[1:] if "=" not in a and not a.startswith("-")]
        return _proc_block_reason(rest)
    if exe == "git":
        i = 1
        while i < len(argv) and argv[i].startswith("-"):
            opt = argv[i].split("=", 1)[0]
            i += 2 if (opt in _GIT_OPTS_WITH_VALUE and "=" not in argv[i]) else 1
        sub = argv[i] if i < len(argv) else ""
        if sub in GIT_NETWORK_SUBCOMMANDS:
            for a in argv[i + 1:]:
                if "://" in a and not a.startswith("file://"):
                    try:  # a server the test runs on loopback is not egress (parsed, not pattern-matched)
                        if is_loopback_host(urllib.parse.urlsplit(a).hostname) and urllib.parse.urlsplit(a).hostname:
                            continue
                    except ValueError:
                        pass
                    return f"git {sub} to a network remote ({a.split('@')[-1]})"
                if "@" in a and ":" in a.split("@", 1)[1] and not os.path.exists(a):
                    return f"git {sub} to an scp-style remote ({a.split('@')[-1]})"
        return None
    if exe in ("tofu", "terraform"):
        subs = [a for a in argv[1:] if not a.startswith("-")]
        if subs and subs[0] in IAC_MUTATING_SUBCOMMANDS:
            return f"'{exe} {subs[0]}' mutates real state"
        return None
    if exe.startswith("python") or str(argv[0]) == sys.executable:
        args = list(argv[1:])
        for j, a in enumerate(args):
            if a == "-m" and j + 1 < len(args) and args[j + 1].split(".")[0] == "unittest":
                return "'python -m unittest' bypasses conftest.py (use pytest)"
    return None


def _argv_from(args):
    if isinstance(args, (str, bytes)):
        s = args.decode() if isinstance(args, bytes) else args
        try:
            return shlex.split(s)
        except ValueError:
            return s.split()
    try:
        return [os.fsdecode(a) if isinstance(a, (bytes, os.PathLike)) else str(a) for a in args]
    except TypeError:
        return [str(args)]


def _ensure_child_env(env):
    """Inject Layer 0 into a child's env: the dict the caller passed, or os.environ when the child inherits it."""
    target = env if env is not None else os.environ
    if _env_is_hermetic(target):
        return
    try:
        _apply_env(target)
    except TypeError:
        pass  # immutable mapping: the proxy/ADC settings already exported in os.environ still apply to most tools


def _check_open(path):
    st = state()
    if not st.cred_prefixes or isinstance(path, int):
        return
    try:
        p = os.fsdecode(path)
    except TypeError:
        return
    if not p.startswith(st.cred_prefixes):
        return
    if st.gcloud_config_dir and p.startswith(st.gcloud_config_dir):
        return
    record("credential-file", p)
    raise HermeticCredentialFileBlocked(f"hermetic guard: tests may not read real credential store {p}")


def _audit_hook(event, args):
    st = getattr(sys, _STATE_ATTR, None)
    if st is None or not st.enabled:
        return
    if event == "open":
        _check_open(args[0])
        return
    if event.startswith("socket."):
        # gethostbyname_ex raises the "socket.gethostbyname" event (CPython socketmodule.c).
        if event == "socket.getaddrinfo" or event == "socket.gethostbyname" or event == "socket.gethostbyname_ex":
            host = args[0]
            if not is_loopback_host(host):
                record("dns", host)
                raise HermeticDNSBlocked(socket.EAI_NONAME, f"hermetic guard: DNS lookup of {host!r} blocked")
        elif event == "socket.gethostbyaddr":
            if not is_loopback_host(args[0]):
                record("dns", args[0])
                raise HermeticDNSBlocked(socket.EAI_NONAME, f"hermetic guard: reverse DNS of {args[0]!r} blocked")
        elif event == "socket.getnameinfo":  # (sockaddr,)
            sockaddr = args[0]
            host = sockaddr[0] if isinstance(sockaddr, tuple) and sockaddr else sockaddr
            if not is_loopback_host(host):
                record("dns", f"getnameinfo {sockaddr!r}")
                raise HermeticDNSBlocked(socket.EAI_NONAME, f"hermetic guard: getnameinfo of {sockaddr!r} blocked")
        elif event in ("socket.connect", "socket.sendto", "socket.sendmsg"):
            sock, address = args[0], args[1]
            if getattr(sock, "family", None) == getattr(socket, "AF_UNIX", object()) or not isinstance(address, tuple):
                return
            host, port = address[0], address[1] if len(address) > 1 else None
            if is_loopback_host(host):
                if port == PROXY_SENTINEL_PORT and str(host) in (PROXY_SENTINEL_HOST, "localhost", "::1"):
                    record("socket", f"egress through the proxy sentinel {host}:{port} (an HTTP(S)/gRPC client "
                                     f"tried to reach a non-loopback host)")
                    raise HermeticNetworkBlocked(f"hermetic guard: proxied egress blocked ({host}:{port})")
                return
            record("socket", f"{event} {address!r}")
            raise HermeticNetworkBlocked(f"hermetic guard: connection to {address!r} blocked")
        return
    if event == "subprocess.Popen":  # (executable, args, cwd, env)
        _check_spawn(args[0], args[1], args[3])
    elif event == "os.system":  # (command,)
        _check_spawn(None, args[0], None)
    elif event in ("os.posix_spawn", "os.exec"):  # (path, argv, env)
        _check_spawn(args[0], args[1], args[2] if len(args) > 2 else None)
    elif event == "os.spawn":  # (mode, path, args, env)
        _check_spawn(args[1], args[2], args[3] if len(args) > 3 else None)


def _check_spawn(executable, args, env):
    argv = _argv_from(args) if args is not None else []
    candidates = [argv]
    if executable is not None:
        exe = os.fsdecode(executable)
        if not argv or os.path.basename(exe) != os.path.basename(argv[0]):
            candidates.append([exe] + argv[1:])
    for cand in candidates:
        reason = _proc_block_reason(cand)
        if reason:
            record("subprocess", " ".join(cand)[:300])
            raise HermeticSubprocessBlocked(f"hermetic guard: refused to spawn {cand[:3]}: {reason}")
    if env is None or isinstance(env, dict):
        _ensure_child_env(env)


# ----------------------------------------------------------------------------------------------- Layer 3 patches
def _live_default_credentials_error(module_exceptions=None):
    """The DefaultCredentialsError class callers catch right now.

    Not cached: the FD-05A sys.modules sandbox (tests/conftest.py) drops and re-imports pure-Python packages such as
    google.auth between test modules, and every re-import creates a NEW DefaultCredentialsError class object.
    """
    def _ok(cls):
        return isinstance(cls, type) and issubclass(cls, Exception)  # not a MagicMock stub

    base = getattr(module_exceptions, "DefaultCredentialsError", None)
    if not _ok(base):
        base = getattr(sys.modules.get("google.auth.exceptions"), "DefaultCredentialsError", None)
    if not _ok(base):
        try:
            from google.auth import exceptions as live  # google.auth is being imported already

            base = live.DefaultCredentialsError
        except Exception:
            base = None
    return base if _ok(base) else Exception


def _adc_error(module_exceptions=None):
    """HermeticCredentialsBlocked, rebuilt whenever the live DefaultCredentialsError is a different class object
    (code-RT finding 1: a class cached once went stale after the first sandbox rollback, so
    ``except DefaultCredentialsError`` stopped catching the guard's error, depending on file order)."""
    st = state()
    base = _live_default_credentials_error(module_exceptions)
    if st.adc_error_cls is None or not issubclass(st.adc_error_cls, base):

        class HermeticCredentialsBlocked(HermeticGuardError, base):
            """google.auth.default() under the hermetic guard (a DefaultCredentialsError: code degrades as with no ADC)."""

        st.adc_error_cls = HermeticCredentialsBlocked
    return st.adc_error_cls


def _blocked_default(*_a, **_k):
    record("adc", "google.auth.default()", stack=False)
    raise _adc_error()("hermetic guard: real Google credentials (ADC) are disabled in tests; mock google.auth.default")


async def _blocked_default_async(*_a, **_k):
    _blocked_default()


_blocked_default._hermetic = True
_blocked_default_async._hermetic = True


def _patch_google_auth(module):
    _adc_error(getattr(module, "exceptions", None))
    if not getattr(getattr(module, "default", None), "_hermetic", False):
        module.default = _blocked_default


def _patch_google_auth_default(module):
    _adc_error(getattr(module, "exceptions", None))
    module.default = _blocked_default


def _patch_google_auth_default_async(module):
    if hasattr(module, "default_async"):
        module.default_async = _blocked_default_async


def _patch_cloud_sdk(module):
    module.get_application_default_credentials_path = lambda: ADC_DISABLED_PATH
    module.get_config_path = lambda: state().gcloud_config_dir or "/nonexistent/gcloud-config-disabled"
    module.get_project_id = lambda: None


def _patch_gce_metadata(module):
    def _not_on_gce(*_a, **_k):
        return False

    async def _not_on_gce_async(*_a, **_k):
        return False

    for name in ("is_on_gce", "ping", "detect_gce_residency_linux"):
        if hasattr(module, name):
            setattr(module, name, _not_on_gce)
    for name in ("is_on_gce_async", "ping_async"):
        if hasattr(module, name):
            setattr(module, name, _not_on_gce_async)


def _block_init(cls, label, allow=None):
    real_init = cls.__init__
    if getattr(real_init, "_hermetic", False):
        return

    def guarded_init(self, *args, **kwargs):
        if allow is not None and allow(self, args, kwargs):
            return real_init(self, *args, **kwargs)
        record("client", label)
        raise HermeticClientBlocked(f"hermetic guard: constructing a real {label} is blocked in tests; mock it "
                                    f"(e.g. patch the class where the code under test looks it up)")

    guarded_init._hermetic = True
    guarded_init.__wrapped__ = real_init
    cls.__init__ = guarded_init


def _emulator_configured():
    return any(is_loopback_host((os.environ.get(k) or "").rsplit(":", 1)[0]) and os.environ.get(k)
               for k in _EMULATOR_ENV)


def _patch_cloud_client(module):
    cls = getattr(module, "Client", None)
    if cls is None:
        return

    def allow(self, _args, _kwargs):
        mod = type(self).__module__
        # Firestore has its own FD-08 guard (root conftest) with its own policy; never double-handle it.
        return mod.startswith("google.cloud.firestore") or _emulator_configured()

    real_init = cls.__init__
    if getattr(real_init, "_hermetic", False):
        return

    def guarded_init(self, *args, **kwargs):
        if allow(self, args, kwargs):
            return real_init(self, *args, **kwargs)
        label = f"{type(self).__module__}.{type(self).__name__}"
        record("client", label)
        raise HermeticClientBlocked(f"hermetic guard: constructing a real {label} is blocked in tests; mock it")

    guarded_init._hermetic = True
    guarded_init.__wrapped__ = real_init
    cls.__init__ = guarded_init


def _wrap_channel_fn(module, name, label):
    fn = getattr(module, name, None)
    if fn is None or getattr(fn, "_hermetic", False):
        return

    def guarded(target, *args, **kwargs):
        if not is_loopback_host(_grpc_target_host(target)):
            record("client", f"{label}({target!r})")
            raise HermeticClientBlocked(f"hermetic guard: gRPC channel to {target!r} blocked in tests")
        return fn(target, *args, **kwargs)

    guarded._hermetic = True
    guarded.__wrapped__ = fn
    setattr(module, name, guarded)


def _patch_grpc_helpers(module):
    _wrap_channel_fn(module, "create_channel", f"{module.__name__}.create_channel")


def _patch_grpc(module):
    _wrap_channel_fn(module, "secure_channel", f"{module.__name__}.secure_channel")
    _wrap_channel_fn(module, "insecure_channel", f"{module.__name__}.insecure_channel")


def _patch_genai_client(module):
    for clsname in ("Client", "AsyncClient"):
        cls = getattr(module, clsname, None)
        if isinstance(cls, type):
            _block_init(cls, f"google.genai.{clsname}")


def _patch_pygithub_requester(module):
    cls = getattr(module, "Requester", None)
    if isinstance(cls, type):
        _block_init(cls, "PyGithub client (github.Requester)")


def _patch_uvloop(module):
    """uvloop/libuv resolves DNS and connects in C: no ``socket.*`` audit event fires, so Layer 1 cannot see it
    (code-RT finding 2, probe P7: a real SYN left the host and nothing was recorded). Under the guard no libuv loop
    is ever built: the package entry points hand out the standard asyncio loop instead, whose DNS/connect ARE audited
    (uvicorn ``loop="auto"``, ``uvloop.run``, ``uvloop.install``/``EventLoopPolicy`` keep working, so a test serving
    an app on loopback still passes; cross-lane merge simulation, lane 3). Constructing ``uvloop.Loop`` directly,
    which cannot be substituted, is blocked and fails the test. Substitutions are recorded as info ("uvloop")."""
    import asyncio

    def _note(what):
        record("uvloop", f"uvloop.{what} -> asyncio loop (hermetic guard)", stack=False)

    loop_cls = getattr(module, "Loop", None)
    if isinstance(loop_cls, type) and not getattr(loop_cls.__init__, "_hermetic", False):
        def guarded_init(self, *_a, **_k):
            record("client", "uvloop.Loop()")
            raise HermeticClientBlocked("hermetic guard: constructing uvloop.Loop is blocked in tests (libuv does DNS "
                                        "and connect() below the audit hook); use asyncio or uvloop.new_event_loop")

        guarded_init._hermetic = True
        loop_cls.__init__ = guarded_init
    real_new_event_loop = getattr(module, "new_event_loop", None)

    def new_event_loop(*_a, **_k):
        _note("new_event_loop")
        return asyncio.new_event_loop()

    def run(main, *, loop_factory=None, debug=None, **run_kwargs):
        if loop_factory in (None, real_new_event_loop, new_event_loop):
            loop_factory = new_event_loop
        _note("run")
        return asyncio.run(main, debug=debug, loop_factory=loop_factory, **run_kwargs)

    class EventLoopPolicy(asyncio.DefaultEventLoopPolicy):
        def new_event_loop(self):
            _note("EventLoopPolicy")
            return super().new_event_loop()

    def install(*_a, **_k):
        _note("install")
        asyncio.set_event_loop_policy(EventLoopPolicy())

    for name, fn in (("new_event_loop", new_event_loop), ("run", run), ("install", install),
                     ("EventLoopPolicy", EventLoopPolicy)):
        fn._hermetic = True
        setattr(module, name, fn)


PATCHES = {
    "google.auth": _patch_google_auth,
    "google.auth._default": _patch_google_auth_default,
    "google.auth._default_async": _patch_google_auth_default_async,
    "google.auth._cloud_sdk": _patch_cloud_sdk,
    "google.auth.compute_engine._metadata": _patch_gce_metadata,
    "google.cloud.client": _patch_cloud_client,
    "google.api_core.grpc_helpers": _patch_grpc_helpers,
    "google.api_core.grpc_helpers_async": _patch_grpc_helpers,
    "grpc": _patch_grpc,
    "grpc.aio": _patch_grpc,
    "google.genai.client": _patch_genai_client,
    "github.Requester": _patch_pygithub_requester,
    "uvloop": _patch_uvloop,
}


def _apply_patch(name, module):
    if not hasattr(module, "__spec__"):  # MagicMock / stub module installed by a test: nothing real to patch
        return
    try:
        PATCHES[name](module)
    except Exception as e:  # never break an import because of the guard; the audit hook still blocks egress
        record("client", f"hermetic guard could not patch {name}: {e!r}", stack=False)


class _GuardFinder(importlib.abc.MetaPathFinder):
    """Patches PATCHES[name] right after the REAL module executes (again on every re-import)."""

    _hermetic_guard_finder = True

    def find_spec(self, name, path, target=None):
        if name not in PATCHES:
            return None
        spec = importlib.machinery.PathFinder.find_spec(name, path, target)
        if spec is None or spec.loader is None or not hasattr(spec.loader, "exec_module"):
            return spec
        real_loader = spec.loader

        class _Loader(importlib.abc.Loader):
            def create_module(self, s):
                return real_loader.create_module(s)

            def exec_module(self, module):
                real_loader.exec_module(module)
                _apply_patch(name, module)

        spec.loader = _Loader()
        return spec


# ----------------------------------------------------------------------------------------------- install
def _real_home_dirs():
    homes = set()
    try:
        import pwd

        homes.add(pwd.getpwuid(os.getuid()).pw_dir)
    except Exception:
        pass
    if os.environ.get("HOME"):
        homes.add(os.environ["HOME"])
    return {os.path.realpath(h) for h in homes} | homes


def _inherited_gcloud_dir():
    """A guarded parent's empty gcloud config dir (children reuse it instead of creating one each)."""
    d = os.environ.get("CLOUDSDK_CONFIG") or ""
    if (os.path.basename(d.rstrip(os.sep)).startswith(_GCLOUD_DIR_PREFIX) and os.path.isdir(d)
            and os.path.realpath(os.path.dirname(d.rstrip(os.sep))) == os.path.realpath(tempfile.gettempdir())):
        return d
    return None


def install():
    """Install the guard in this process (idempotent). Safe to call before or after pytest starts."""
    st = state()
    if st.installed:
        return st
    prefixes = []
    for home in sorted(_real_home_dirs()):
        for rel in _HOME_CREDENTIAL_PATHS:
            prefixes.append(os.path.join(home, rel))
    st.cred_prefixes = tuple(prefixes)
    st.gcloud_config_dir = _inherited_gcloud_dir()
    if st.gcloud_config_dir is None:
        st.gcloud_config_dir = tempfile.mkdtemp(prefix=_GCLOUD_DIR_PREFIX)
        owner = os.getpid()  # a fork()ed child must not delete the dir its parent still uses
        atexit.register(lambda: os.getpid() == owner and _remove_quietly(st.gcloud_config_dir, is_dir=True))
    st.forward_path = os.environ.get(CHILD_LOG_ENV) or None
    # A Python child installed by tests/hermetic_child/sitecustomize.py keeps the env its parent test gave it
    # (security settings only); the mock project defaults are for the test process itself.
    _apply_env(os.environ, process=not getattr(sys, _CHILD_FLAG_ATTR, False))
    if not any(getattr(f, "_hermetic_guard_finder", False) for f in sys.meta_path):
        sys.meta_path.insert(0, _GuardFinder())
    for name in PATCHES:
        mod = sys.modules.get(name)
        if mod is not None:
            _apply_patch(name, mod)
    sys.addaudithook(_audit_hook)
    st.installed = True
    st.enabled = True
    return st


install()
