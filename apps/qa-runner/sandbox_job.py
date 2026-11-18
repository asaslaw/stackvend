"""
StackVend QA sandbox job: the entrypoint of the isolated `qa-sandbox-test-runner` Cloud Run job.

    python3 -m sandbox_job [--index-url <url>]
        (TF / deploy: command=/cnb/lifecycle/launcher, args=python3,-m,sandbox_job[,--index-url,<Artifact Registry
        PyPI remote .../simple/>]; the index arrives on argv only, row L3-PRB-g)

FD-4F option A, lane 3 PR-B. Plan: docs/implemented/wave2-lane13-fd4f-hardened-plan.md section 4 B1 (+ review H2/H4/H5/
H8/H9/H10, red-team F2). The gateway side of the contract is fixed in apps/orchestrator-gateway/qa_job_client.py
(`QAJobClient.run`, `classify`, `StaticV1`, `ReportV1`); this module implements exactly that contract.

Identity: this container IS the sandbox. It runs LLM-generated code as `sa-castor-qa-sandbox` (zero roles; with egress
Phase 2, row L3-PRB-g, exactly one: artifactregistry.reader on the PyPI remote repository), holds no credential beyond the metadata-server token
any code in the container can mint, writes no Firestore, sends no callback. It touches exactly three signed URLs handed to it by the
gateway as per-execution env overrides:
    QA_SOURCE_URL       GET   source.tar.gz (deterministic tar.gz of the commit, built by the gateway)
    QA_STATIC_PUT_URL   PUT   static.json   create-only (x-goog-if-generation-match: 0), BEFORE untrusted code runs
    QA_REPORT_PUT_URL   PUT   report.json   create-only, after dependency install, import smoke and pytest
plus QA_SOURCE_SHA256, QA_NONCE, QA_TRACE_ID, QA_COMMIT_SHA, QA_PRODUCT_ID, QA_DEADLINE_SECONDS. The only other
network access is the package index (dependency install + one reachability probe, red-team F2) and, when the index
comes from `--index-url` (Artifact Registry behind the deny-all VPC, row L3-PRB-g), one metadata-server token request.

Same-uid hardening (PR-B security red-team, docs/planning/lane3-prb-sandbox-job-code-red-team-fable.md): the job makes
itself non-dumpable first (F4), parses requirements.txt as PEP 508 names in the static phase and hands pip argv only
(F1), runs pytest with plugin autoload off and an explicit `-p` allow-list (F2, row L3-PRB-f), SIGKILLs every other
process of its uid after each untrusted step (F3), re-verifies the tree before each service (F5), and bounds every
HTTP attempt by the Cloud Run task budget (F9).

Exit codes (qa_job_client.py EXIT_*; anything else, e.g. 1 = interpreter crash or 137 = OOM, is GATE_UNAVAILABLE):
    0  pass: static.json passed AND report.json passed
    10 CODE_DEFECT: checks ran and the code failed them (static.json, plus report.json when static passed)
    11 RUNNER_ERROR: toolchain / input / download / sha / extract / PUT failure, package index unreachable, or the
       deadline expired while NO untrusted code was running (F2a)
    12 TIMEOUT_DEFECT: the job's own deadline expired while UNTRUSTED code was running (report.json says so)

Fail closed everywhere: any unexpected exception (any BaseException) exits 11 and writes nothing further. Nothing here
reads TEST_MODE; tests inject the toolchain and the HTTP transport.
"""

import ast
import base64
import codecs
import gzip
import hashlib
import http.client
import io
import json
import logging
import os
import posixpath
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

# `packaging` is the PEP 508 parser pip and pytest themselves use (declared in apps/qa-runner/requirements.txt).
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
from shared.path_safety import GIT_RESERVED, UnsafePathError, validate_relpath, validate_trace_id

logger = logging.getLogger("qa-sandbox-job")

# Bumped whenever the job <-> gateway contract changes. Recorded in static.json.toolchain["job_contract"].
JOB_CONTRACT_VERSION = "1"

EXIT_PASS, EXIT_CODE_DEFECT, EXIT_RUNNER_ERROR, EXIT_TIMEOUT_DEFECT = 0, 10, 11, 12

# Gateway caps (qa_job_client.py): artifacts > 2 MiB are treated as missing; <= 200 diagnostics; fields <= 2048 chars.
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_DIAGNOSTICS = 200
MAX_FIELD_CHARS = 2048
MAX_DIAG_FILE_CHARS = 512
MAX_CODE_CHARS = 64
LOGS_TAIL_CHARS = 20000
# Source archive caps (same as the gateway's qa_source.py normalize_archive).
MAX_MEMBERS = 10_000
MAX_TOTAL_BYTES = 100 * 1024 * 1024
MAX_SOURCE_DOWNLOAD_BYTES = MAX_TOTAL_BYTES + 32 * 1024 * 1024
MAX_MEMBER_NAME_CHARS = 1023
MAX_TOOL_OUTPUT_BYTES = 32 * 1024 * 1024  # bandit JSON / junit XML read caps
# The gateway sends JOB_INTERNAL_DEADLINE_S = 780 (task timeout 900 s); anything above this is refused.
MAX_DEADLINE_S = 860
# Cloud Run task timeout (= qa_job_client.JOB_TASK_TIMEOUT_S, pinned by the contract test). Every HTTP attempt is
# bounded by what is left of it minus a margin, so a report.json PUT after a late timeout cannot overrun the task
# (red-team F9: that would turn a CODE_DEFECT timeout into GATE_UNAVAILABLE).
TASK_TIMEOUT_S = 900
TASK_BUDGET_MARGIN_S = 15
TOOLCHAIN_CHECK_TIMEOUT_S = 120
HTTP_TIMEOUT_S = 60
HTTP_ATTEMPTS = 3
INDEX_PROBE_TIMEOUT_S = 10

REQUIRED_INPUTS = (
    "QA_SOURCE_URL", "QA_SOURCE_SHA256", "QA_STATIC_PUT_URL", "QA_REPORT_PUT_URL", "QA_NONCE", "QA_TRACE_ID",
    "QA_COMMIT_SHA", "QA_PRODUCT_ID", "QA_DEADLINE_SECONDS",
)
# Exactly the headers the gateway signs into the PUT URLs (qa_job_client.CREATE_ONLY_HEADERS).
CREATE_ONLY_HEADERS = {"x-goog-if-generation-match": "0", "content-type": "application/json"}

DEFAULT_INDEX_URL = "https://pypi.org/simple"
JOB_DIR = os.path.dirname(os.path.abspath(__file__))

# Row L3-PRB-g (FD-4BR, egress Phase 2): the job's only egress is Private Google Access, so the index is the
# platform's Artifact Registry PyPI remote, named by the job template's args (`--index-url <AR .../simple/>`, never
# env or the tree). Artifact Registry needs a credential: the sandbox SA's access token from the metadata server
# (untrusted code can mint the same token, so handing it to the trusted pip adds no exposure). It reaches pip only
# through a 0600 netrc file named by `NETRC=` in the trusted pip's env (requests' documented override), written in the
# service's fresh trusted directory right before and removed right after the trusted pip steps, so it is never in the
# untrusted steps' $HOME; the probe sends it as Basic auth with Artifact Registry's documented user name.
INDEX_ARG = "--index-url"
INDEX_NETRC_NAME = "pip-index.netrc"
METADATA_TOKEN_URL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
METADATA_HEADERS = {"Metadata-Flavor": "Google"}
AR_BASIC_AUTH_USER = "oauth2accesstoken"
# OAuth 2 bearer token characters (RFC 6750 b64token): anything else could break the .netrc grammar.
_TOKEN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~+/=")
MAX_TOKEN_CHARS = 4096

# H4 (a LINT for the literal pattern, not a boundary; red-team F2): hook implementations that can rewrite or drop
# test outcomes. Defining one in workload-authored pytest code (conftest.py, a module named by pytest_plugins, a
# module star-imported by either) or touching pytest's pluginmanager anywhere in the tree is a CODE_DEFECT. Fixtures
# and every other hook stay allowed. Indirection beyond that (exec, getattr tricks) is a residual equal in power to a
# vacuous test; plugin wheels are handled by autoload-off + the allow-list below (row L3-PRB-f).
OUTCOME_HOOKS = frozenset({
    "pytest_runtest_makereport", "pytest_report_teststatus", "pytest_runtest_logreport", "pytest_sessionfinish",
    "pytest_terminal_summary", "pytest_collection_modifyitems", "pytest_runtest_protocol", "pytest_runtest_call",
    "pytest_pyfunc_call",
})

# Interpreter variables passed by exact name to TRUSTED tool subprocesses (bandit, pip, venv creation) when present:
# buildpack images locate the runtime's packages through them. Not secrets. Same names as lane 3's runner.py.
TOOL_ENV_PASSTHROUGH = ("PATH", "PYTHONPATH", "PYTHONUSERBASE", "PYTHONHOME", "VIRTUAL_ENV", "LD_LIBRARY_PATH")
# The only control-plane variable an UNTRUSTED subprocess may inherit (shared-library lookup of the interpreter).
UNTRUSTED_ENV_PASSTHROUGH = ("LD_LIBRARY_PATH",)
# Plan section 2.6 fixed values (same constants as lane 3's runner.py SANDBOX_ENV_FIXED, minus git).
SANDBOX_ENV_FIXED = {
    "LANG": "C.UTF-8",
    "PYTHONHASHSEED": "0",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTEST_ADDOPTS": "-p no:cacheprovider",
    # Row L3-PRB-f: no `pytest11` entry point loads by itself; the job passes `-p <module>` for allow-listed plugins.
    "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    # Red-team F11: RLIMIT_AS is virtual; glibc reserves an arena per thread, so cap the arenas.
    "MALLOC_ARENA_MAX": "2",
}
# Row L3-PRB-f: pytest plugins loaded (`-p <module>` from the distribution's own `[pytest11]` entry point) when the
# distribution is installed in the service venv. Toolchain.required_pytest_plugin_dists must be present (exit 11).
OPTIONAL_PYTEST_PLUGIN_DISTS = frozenset({"pytest-asyncio", "anyio", "pytest-mock"})
RLIMIT_AS_BYTES = 3 * 1024 ** 3
RLIMIT_NPROC_COUNT = 512
# pytest's documented exit codes (pytest.ExitCode): 2 INTERRUPTED (e.g. pytest.exit, collection errors), 3
# INTERNAL_ERROR, 4 USAGE_ERROR (e.g. a conftest that fails to import), 5 NO_TESTS_COLLECTED.
PYTEST_EXIT_INTERRUPTED, PYTEST_EXIT_INTERNAL_ERROR, PYTEST_EXIT_USAGE_ERROR, PYTEST_EXIT_NO_TESTS = 2, 3, 4, 5
# Row QA-PYTEST-CRASH: pytest's junitxml plugin records an internal error (its `pytest_internalerror` hook) as one
# synthetic testcase with exactly these classname / name attributes, no `file` attribute, and pytest's own crash
# report as the text of its <error>. It is not a test: it is reported as PYTEST.INTERNAL_ERROR, never counted.
JUNIT_INTERNAL_ERROR_CASE = ("pytest", "internal")
# Row QA-PYTEST-CRASH: the codes of a pytest run that stopped before or instead of running the tests (typed by exit
# code and junit structure only). The gateway's QA-REPAIR-ON-CRASH routes exactly these to a repair of the service's
# test setup (developer_agent/qa_repair.py CRASH_CODES). PYTEST.REPORT_INVALID (an unreadable junit on any other exit,
# a signal, os._exit, exit 0 with failures listed) is not one of them: that is usually the app's or a test's doing.
# A crash diagnostic names its service through `file` = `apps/<svc>/requirements.txt` (the service's typed scope).
PYTEST_INTERNAL_ERROR_CODE = "PYTEST.INTERNAL_ERROR"   # exit 3 or the junit's synthetic internal-error case
PYTEST_SESSION_ERROR_CODE = "PYTEST.SESSION_ERROR"     # exit 2 / 4 with a readable junit that lists no failing test
PYTEST_STARTUP_ERROR_CODE = "PYTEST.STARTUP_ERROR"     # exit 2 / 3 / 4 before pytest wrote any junit report
PYTEST_CRASH_CODES = frozenset({PYTEST_INTERNAL_ERROR_CODE, PYTEST_SESSION_ERROR_CODE, PYTEST_STARTUP_ERROR_CODE})
PYTEST_STOPPED_EXIT_CODES = frozenset({PYTEST_EXIT_INTERRUPTED, PYTEST_EXIT_INTERNAL_ERROR, PYTEST_EXIT_USAGE_ERROR})
# QA-REPAIR-SETUP-ERROR: a junit testcase whose first bad child is <error> (pytest writes <error> for an error outside
# the test's own call: a fixture's setup or teardown, or the test module's collection; <failure> for the test itself).
# Typed by the XML tag only, never by the message. The gateway routes it to a repair of the service's test setup plus
# the test file (developer_agent/qa_repair.py SETUP_ERROR_CODES; parity: tests/test_qa_repair_setup_error.py).
PYTEST_SETUP_ERROR_CODE = "PY.TEST_SETUP_ERROR"
PYTEST_SETUP_ERROR_CODES = frozenset({PYTEST_SETUP_ERROR_CODE})
TEST_FAILED_CODE = "PY.TEST_FAILED"
# QA-REPAIR-MISSING-MODULE-SETUP: the job's own pytest plugin (qa_missing_module_plugin.py, beside this file). The job
# copies it into the service's fresh venv (trusted, after pip) and loads it for the pytest step only through
# PYTEST_PLUGINS (never on argv; the plugin removes the variable again when it is imported). When collecting a node or
# setting a test up raises, it writes the `name` of the first ModuleNotFoundError on the exception's chain to
# `<junit>.missing-module`; the job reads that as untrusted (missing_module_fact) and adds it as `missing_module` to
# the run's PY.TEST_SETUP_ERROR diagnostics. Without the file every diagnostic is exactly as before.
MISSING_MODULE_PLUGIN = "qa_missing_module_plugin"
MISSING_MODULE_FACT_SUFFIX = ".missing-module"   # parity: qa_missing_module_plugin.FACT_SUFFIX
PYTEST_PLUGINS_ENV = "PYTEST_PLUGINS"
# How much of the pytest log head a crash diagnostic reads for pytest's first output block: an INTERNALERROR traceback
# is one block (every line is prefixed) of often 5-30 KB, and its last line is the exception.
CRASH_LOG_HEAD_BYTES = 256 * 1024


# ------------------------------------------------------------------------------------------------------------------
# Errors
# ------------------------------------------------------------------------------------------------------------------
class RunnerError(RuntimeError):
    """Anything that is not the code's fault -> exit 11 (GATE_UNAVAILABLE at the gateway)."""


class DeadlineExpired(RuntimeError):
    def __init__(self, what: str, untrusted: bool):
        self.what, self.untrusted = what, untrusted
        super().__init__(f"deadline expired during {what}")


# ------------------------------------------------------------------------------------------------------------------
# Redaction (exact values only, no patterns): the signed URLs are bearer capabilities for this run's objects.
# ------------------------------------------------------------------------------------------------------------------
class Redactor:
    def __init__(self) -> None:
        self._secrets: List[str] = []

    def add(self, value: Optional[str]) -> None:
        if value and value not in self._secrets:
            self._secrets.append(value)
            self._secrets.sort(key=len, reverse=True)  # longest first: a URL that contains another is fully hidden

    def __call__(self, text: Any) -> str:
        out = text if isinstance(text, str) else str(text)
        for s in self._secrets:
            out = out.replace(s, "[REDACTED]")
        return out


# ------------------------------------------------------------------------------------------------------------------
# Inputs
# ------------------------------------------------------------------------------------------------------------------
def _is_hex(value: str, length: int) -> bool:
    return len(value) == length and all(c in "0123456789abcdef" for c in value)


def _is_http_url(value: str) -> bool:
    return value.startswith("https://") or value.startswith("http://")


@dataclass(frozen=True)
class JobInputs:
    source_url: str
    source_sha256: str
    static_put_url: str
    report_put_url: str
    nonce: str
    trace_id: str
    commit_sha: str
    product_id: str
    deadline_s: int

    @classmethod
    def from_environ(cls, environ: Dict[str, str]) -> "JobInputs":
        """Reads every QA_* input once, validates it, and REMOVES all QA_* names from `environ` (plan B1 step 2).
        Raises RunnerError naming the bad variable (never its value: three of them are bearer URLs)."""
        raw = {k: (environ.get(k) or "") for k in REQUIRED_INPUTS}
        for k in [k for k in list(environ) if k.startswith("QA_")]:
            environ.pop(k, None)
        missing = [k for k, v in raw.items() if not v.strip()]
        if missing:
            raise RunnerError(f"missing job inputs: {', '.join(missing)}")
        for k in ("QA_SOURCE_URL", "QA_STATIC_PUT_URL", "QA_REPORT_PUT_URL"):
            if not _is_http_url(raw[k]):
                raise RunnerError(f"{k} is not an http(s) URL")
        if len({raw["QA_SOURCE_URL"], raw["QA_STATIC_PUT_URL"], raw["QA_REPORT_PUT_URL"]}) != 3:
            raise RunnerError("the three signed URLs must be distinct")
        if not _is_hex(raw["QA_SOURCE_SHA256"], 64):
            raise RunnerError("QA_SOURCE_SHA256 is not 64 lowercase hex")
        if not _is_hex(raw["QA_NONCE"], 32):
            raise RunnerError("QA_NONCE is not 32 lowercase hex")
        if not _is_hex(raw["QA_COMMIT_SHA"], 40):
            raise RunnerError("QA_COMMIT_SHA is not 40 lowercase hex")
        try:
            validate_trace_id(raw["QA_TRACE_ID"])
        except UnsafePathError as e:
            raise RunnerError(f"invalid job input: {e.reason}") from e
        if len(raw["QA_PRODUCT_ID"]) > 256:  # used for logging only (repr); the gateway owns product_id semantics
            raise RunnerError("QA_PRODUCT_ID is too long")
        try:
            deadline_s = int(raw["QA_DEADLINE_SECONDS"])
        except ValueError as e:
            raise RunnerError("QA_DEADLINE_SECONDS is not an integer") from e
        if not 1 <= deadline_s <= MAX_DEADLINE_S:
            raise RunnerError(f"QA_DEADLINE_SECONDS must be 1..{MAX_DEADLINE_S}")
        return cls(
            source_url=raw["QA_SOURCE_URL"], source_sha256=raw["QA_SOURCE_SHA256"],
            static_put_url=raw["QA_STATIC_PUT_URL"], report_put_url=raw["QA_REPORT_PUT_URL"], nonce=raw["QA_NONCE"],
            trace_id=raw["QA_TRACE_ID"], commit_sha=raw["QA_COMMIT_SHA"], product_id=raw["QA_PRODUCT_ID"],
            deadline_s=deadline_s,
        )


# ------------------------------------------------------------------------------------------------------------------
# Signed-URL transport (stdlib only; no proxies, no redirects: a signed URL never redirects)
# ------------------------------------------------------------------------------------------------------------------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


class HttpTransport:
    def __init__(self, sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic):
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
        self._sleep = sleep
        self._clock = clock

    def _attempt(self, req: urllib.request.Request, timeout: float, max_bytes: int) -> Tuple[int, bytes]:
        try:
            with self._opener.open(req, timeout=timeout) as res:
                body = res.read(max_bytes + 1)
                return res.status, body
        except urllib.error.HTTPError as e:
            return e.code, b""

    def _left(self, deadline: Optional[float], method: str) -> Optional[float]:
        if deadline is None:
            return None
        left = deadline - self._clock()
        if left <= 0:
            raise RunnerError(f"{method}: no task time left (task timeout {TASK_TIMEOUT_S}s)")
        return left

    def request(self, method: str, url: str, *, data: Optional[bytes] = None, headers: Optional[Dict[str, str]] = None,
                max_bytes: int = 1024 * 1024, timeout: float = HTTP_TIMEOUT_S, attempts: int = HTTP_ATTEMPTS,
                deadline: Optional[float] = None) -> Tuple[int, bytes]:
        """(status, body). Retries only transport errors and 429/5xx; raises RunnerError when every attempt failed
        at the transport level, or when `deadline` (monotonic; the task budget) has passed. Every attempt's timeout
        and every back-off sleep is bounded by what is left before `deadline`. Never logs the URL."""
        last_exc: Optional[BaseException] = None
        for i in range(attempts):
            left = self._left(deadline, method)
            req = urllib.request.Request(url, data=data, method=method, headers=dict(headers or {}))
            try:
                status, body = self._attempt(req, timeout if left is None else min(timeout, left), max_bytes)
            except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as e:
                last_exc = e
            else:
                if status != 429 and status < 500:
                    return status, body
                last_exc = None
                if i == attempts - 1:
                    return status, body
            if i < attempts - 1:
                backoff = min(2.0 * (i + 1), 5.0)
                left = self._left(deadline, method)
                self._sleep(backoff if left is None else min(backoff, left))
        raise RunnerError(f"{method} failed after {attempts} attempts: {type(last_exc).__name__}")

    def get(self, url: str, max_bytes: int, deadline: Optional[float] = None) -> bytes:
        status, body = self.request("GET", url, max_bytes=max_bytes, deadline=deadline)
        if status != 200:
            raise RunnerError(f"source GET returned HTTP {status}")
        if len(body) > max_bytes:
            raise RunnerError(f"source archive exceeds {max_bytes} bytes")
        if not body:
            raise RunnerError("source archive is empty")
        return body

    def put_create_only(self, url: str, data: bytes, what: str, deadline: Optional[float] = None) -> None:
        # Retries only transport errors / 429 / 5xx. If an earlier attempt was in fact stored, the retry gets 412 and
        # the run ends as a runner error: create-only never lets a second writer win (fail closed).
        status, _ = self.request("PUT", url, data=data, headers=CREATE_ONLY_HEADERS, attempts=HTTP_ATTEMPTS,
                                 deadline=deadline)
        if status == 412:
            logger.error(f"{what} PUT precondition failed: the object already exists",
                         extra={"security_event": "qa_artifact_precondition"})
            raise RunnerError(f"{what} already exists (HTTP 412)")
        if status not in (200, 201):
            raise RunnerError(f"{what} PUT returned HTTP {status}")

    def probe(self, url: str, deadline: Optional[float] = None, headers: Optional[Dict[str, str]] = None) -> bool:
        try:
            status, _ = self.request("GET", url, max_bytes=1024 * 1024, timeout=INDEX_PROBE_TIMEOUT_S, attempts=2,
                                     deadline=deadline, headers=headers)
        except RunnerError:
            return False
        return status == 200


# ------------------------------------------------------------------------------------------------------------------
# Toolchain (runner-owned config; tests inject a toolchain with a local index / stub bandit)
# ------------------------------------------------------------------------------------------------------------------
@dataclass
class Toolchain:
    python: str = sys.executable
    bandit_argv: Sequence[str] = (sys.executable, "-m", "bandit")
    bandit_ini: str = os.path.join(JOB_DIR, "qa_bandit.ini")
    pytest_ini: str = os.path.join(JOB_DIR, "qa_pytest.ini")
    constraints: str = os.path.join(JOB_DIR, "qa_toolchain_constraints.txt")
    test_packages: Sequence[str] = ("pytest", "pytest-timeout")
    pytest_extra_args: Sequence[str] = ("--timeout=60",)
    # Row L3-PRB-f: plugin distributions the runner's own pytest arguments need (`--timeout` is pytest-timeout's);
    # each must be installed in the venv and is loaded with `-p` (autoload is off). Missing -> exit 11.
    required_pytest_plugin_dists: Sequence[str] = ("pytest-timeout",)
    # QA-REPAIR-MISSING-MODULE-SETUP: the platform's pytest plugin file (MISSING_MODULE_PLUGIN); None = not loaded
    missing_module_plugin: Optional[str] = os.path.join(JOB_DIR, f"{MISSING_MODULE_PLUGIN}.py")
    index_url: str = DEFAULT_INDEX_URL
    pip_timeout_s: int = 30
    pip_retries: int = 3
    apply_rlimits: bool = True
    # Production process hardening (Linux). Hermetic tests on a developer's machine turn both off: the uid-wide sweep
    # would SIGKILL every other process of the developer's uid, and PR_SET_DUMPABLE would change the pytest process.
    harden_process: bool = True
    sweep_uid_processes: bool = True
    # Row L3-PRB-g: set only by `--index-url` on argv (toolchain_from_argv). Off = the pre-Phase-2 behaviour.
    index_auth_metadata: bool = False
    metadata_token_url: str = METADATA_TOKEN_URL

    def index_probe_url(self) -> str:
        # PEP 503 project page of pip itself: `<index>/pip/` (Artifact Registry: `.../<repo>/simple/pip/`).
        return self.index_url.rstrip("/") + "/pip/"


def validate_index_url(url: str) -> str:
    """The argv index URL: https, a host, no user info, query or fragment (the credential goes through .netrc)."""
    parts = urllib.parse.urlsplit(url)
    if (parts.scheme != "https" or not parts.hostname or parts.username is not None or parts.password is not None
            or parts.query or parts.fragment or not parts.path.startswith("/")):
        raise RunnerError(f"{INDEX_ARG} must be an https index URL without credentials, query or fragment")
    return url


def toolchain_from_argv(argv: Sequence[str]) -> Optional[Toolchain]:
    """Row L3-PRB-g: the job's only argument is `--index-url <url>` (the job template's args; never env, never the
    tree). No argument -> None (the caller keeps the default toolchain, unchanged). Anything else -> RunnerError."""
    args = list(argv)
    if not args:
        return None
    if len(args) != 2 or args[0] != INDEX_ARG:
        raise RunnerError(f"unexpected job arguments (expected nothing or {INDEX_ARG} <url>)")
    return Toolchain(index_url=validate_index_url(args[1]), index_auth_metadata=True)


def fetch_index_token(net: "HttpTransport", url: str, deadline: Optional[float]) -> str:
    """The job SA's access token from the metadata server (Cloud Run: always reachable, not subject to VPC egress)."""
    status, body = net.request("GET", url, headers=METADATA_HEADERS, max_bytes=64 * 1024,
                               timeout=INDEX_PROBE_TIMEOUT_S, attempts=2, deadline=deadline)
    if status != 200:
        raise RunnerError(f"metadata token request returned HTTP {status}")
    try:
        token = json.loads(body.decode("utf-8"))["access_token"]
    except (ValueError, KeyError, TypeError, UnicodeDecodeError) as e:
        raise RunnerError(f"metadata token response is malformed: {type(e).__name__}") from None
    if not isinstance(token, str) or not 0 < len(token) <= MAX_TOKEN_CHARS or not set(token) <= _TOKEN_CHARS:
        raise RunnerError("metadata token response is malformed: access_token")
    return token


def index_auth_headers(token: str) -> Dict[str, str]:
    raw = f"{AR_BASIC_AUTH_USER}:{token}".encode("ascii")
    return {"Authorization": "Basic " + base64.b64encode(raw).decode("ascii")}


def _register_index_token(redact: "Redactor", token: str) -> None:
    """Exact-value redaction of the token and (FD-4BR RT F9, defence in depth) of its Basic auth header value."""
    redact.add(token)
    header = index_auth_headers(token)["Authorization"]
    redact.add(header)
    redact.add(header.split(" ", 1)[1])  # the base64 credential alone


def _index_token_source(net: "HttpTransport", tc: "Toolchain", redact: "Redactor",
                        deadline: Optional[float]) -> Callable[[str], str]:
    """Per-service token fetch (RT F3). No usable token for a service is a platform fault: RunnerError (exit 11),
    never a diagnostic charged to the workload."""
    def fetch(service_rel: str) -> str:
        try:
            token = fetch_index_token(net, tc.metadata_token_url, deadline)
        except RunnerError as e:
            raise RunnerError(f"package index credential unavailable for {service_rel}: {e}") from None
        _register_index_token(redact, token)
        return token
    return fetch


def write_index_netrc(directory: str, index_url: str, token: str) -> str:
    """The trusted pip's netrc (`NETRC=<path>`): `<directory>/pip-index.netrc`, created exclusively (an existing
    file or symlink is removed first, never followed), mode 0600. Returns the path."""
    path = os.path.join(directory, INDEX_NETRC_NAME)
    remove_index_netrc(path)
    host = urllib.parse.urlsplit(index_url).hostname
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(f"machine {host} login {AR_BASIC_AUTH_USER} password {token}\n")
    return path


def remove_index_netrc(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def _sha256_file(path: str) -> str:
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def _tool_env(work: "Workdir", extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    env = {k: os.environ[k] for k in TOOL_ENV_PASSTHROUGH if os.environ.get(k)}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    env.update({"HOME": work.home, "TMPDIR": work.tmp, "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1"})
    env.update(extra or {})
    return env


def _untrusted_env(work: "Workdir", venv_bin: str, pythonpath: str) -> Dict[str, str]:
    """Plan section 2.6 allow-list. No QA_*, GOOGLE_*, PROJECT_ID, K_*, CLOUD_RUN_* or anything else."""
    env = {k: os.environ[k] for k in UNTRUSTED_ENV_PASSTHROUGH if os.environ.get(k)}
    env.update(SANDBOX_ENV_FIXED)
    env.update({
        "PATH": f"{venv_bin}:/usr/local/bin:/usr/bin:/bin",
        "HOME": work.home,
        "TMPDIR": work.tmp,
        "PYTHONPATH": pythonpath,
    })
    return env


def _rlimit_preexec() -> None:  # pragma: no cover - runs in the child, Linux only
    import resource

    resource.setrlimit(resource.RLIMIT_AS, (RLIMIT_AS_BYTES, RLIMIT_AS_BYTES))
    resource.setrlimit(resource.RLIMIT_NPROC, (RLIMIT_NPROC_COUNT, RLIMIT_NPROC_COUNT))


# ------------------------------------------------------------------------------------------------------------------
# Process hardening (Linux kernel interfaces only: prctl, /proc/<pid>/status; no argv or name guessing)
# ------------------------------------------------------------------------------------------------------------------
PR_GET_DUMPABLE, PR_SET_DUMPABLE = 3, 4


def harden_process() -> None:
    """Red-team F4: make the job process non-dumpable, so same-uid untrusted code cannot read /proc/<job>/environ
    (the initial env block still holds the three signed URLs after `environ.pop`), /proc/<job>/fd, mem or maps, nor
    ptrace the job. Children reset to dumpable on execve, so untrusted steps are unaffected. No-op off Linux.
    Raises RunnerError if the kernel refuses (-> exit 11: never a run with a readable job environment)."""
    if not sys.platform.startswith("linux"):
        return
    import ctypes

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        rc = libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        now = libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0)
    except (OSError, AttributeError) as e:
        raise RunnerError(f"prctl unavailable: {type(e).__name__}") from e
    if rc != 0 or now != 0:
        raise RunnerError(f"prctl(PR_SET_DUMPABLE, 0) failed (errno {ctypes.get_errno()})")


@dataclass(frozen=True)
class ProcInfo:
    pid: int
    ppid: int
    uid: int  # real uid
    zombie: bool


def list_proc(proc_root: str = "/proc") -> List[ProcInfo]:
    """Every process visible in /proc, from the documented `/proc/<pid>/status` format (`PPid:`, `Uid:` real
    first, `State:`). Processes that vanish while listing are skipped; an unreadable /proc is a RunnerError."""
    try:
        entries = os.listdir(proc_root)
    except OSError as e:
        raise RunnerError(f"cannot list {proc_root}: {type(e).__name__}") from e
    out = []
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(os.path.join(proc_root, entry, "status"), "r", encoding="utf-8", errors="replace") as f:
                fields = {}
                for line in f:
                    key, sep, value = line.partition(":")
                    if sep:
                        fields[key] = value.strip()
            out.append(ProcInfo(int(entry), int(fields["PPid"]), int(fields["Uid"].split()[0]),
                                fields.get("State", "").startswith(("Z", "X"))))
        except (OSError, KeyError, ValueError, IndexError):
            continue
    return out


def _reap_children() -> None:
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def kill_stray_processes(*, list_processes: Callable[[], List[ProcInfo]] = list_proc,
                         kill: Callable[[int, int], None] = os.kill, me: Optional[int] = None,
                         uid: Optional[int] = None, sleep: Callable[[float], None] = time.sleep,
                         rounds: int = 100) -> Set[int]:
    """Red-team F3: SIGKILL every process whose real uid is the job's, except the job itself, its ancestors and
    PID 1, until none is left (a process that called setsid() has left the step's process group, so killpg alone
    misses it). Zombies are skipped (and the job's own are reaped). Returns the pids signalled. Raises RunnerError
    if processes survive `rounds` rounds (fail closed: the next step would share the container with them)."""
    me = os.getpid() if me is None else me
    uid = os.getuid() if uid is None else uid
    procs = {p.pid: p for p in list_processes()}
    keep = {me, 1}
    pid = me
    while pid in procs and procs[pid].ppid > 0 and procs[pid].ppid not in keep:
        pid = procs[pid].ppid
        keep.add(pid)
    signalled: Set[int] = set()
    for _ in range(rounds):
        targets = sorted(p.pid for p in procs.values() if p.uid == uid and p.pid not in keep and not p.zombie)
        if not targets:
            return signalled
        for t in targets:
            try:
                kill(t, signal.SIGKILL)
                signalled.add(t)
            except ProcessLookupError:
                pass
            except PermissionError:
                pass  # still listed next round; RunnerError if it never goes away
        _reap_children()
        sleep(0.01)
        procs = {p.pid: p for p in list_processes()}
    raise RunnerError("processes left by untrusted code survived SIGKILL")


def sweep_uid_processes() -> None:
    """Production sweep after every untrusted step (Linux; on other platforms killpg is all there is)."""
    if sys.platform.startswith("linux"):
        kill_stray_processes()


@dataclass
class ProcResult:
    returncode: int
    output: str


class Workdir:
    """mkdtemp with no request-derived path component (FD-4G QR-3)."""

    def __init__(self) -> None:
        self.root = tempfile.mkdtemp(prefix="qa-")
        self.src = os.path.join(self.root, "src")
        self.home = os.path.join(self.root, "home")
        self.tmp = os.path.join(self.root, "tmp")
        self.out = os.path.join(self.root, "out")  # trusted tools' logs; per-service files live in mkdtemp dirs
        for d in (self.src, self.home, self.tmp, self.out):
            os.makedirs(d, mode=0o700)

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


class Runner:
    """Runs one subprocess in its own session, bounded by the shared deadline; kills the whole process group, and
    after every UNTRUSTED step (also on its deadline) runs `sweep` (production: `sweep_uid_processes`)."""

    def __init__(self, deadline: float, redact: Redactor, clock: Callable[[], float] = time.monotonic,
                 apply_rlimits: bool = True, sweep: Optional[Callable[[], None]] = None):
        self.deadline, self.redact, self.clock, self.apply_rlimits = deadline, redact, clock, apply_rlimits
        self.sweep = sweep

    def remaining(self) -> float:
        return self.deadline - self.clock()

    def run(self, argv: Sequence[str], *, env: Dict[str, str], cwd: str, untrusted: bool, what: str,
            log_path: str, timeout_cap: Optional[float] = None) -> ProcResult:
        remaining = self.remaining()
        if remaining <= 0:
            # Nothing is running right now, so this is never a TIMEOUT_DEFECT (red-team F2a): exit 11.
            raise DeadlineExpired(what, untrusted=False)
        timeout = remaining if timeout_cap is None else min(remaining, timeout_cap)
        preexec = _rlimit_preexec if (untrusted and self.apply_rlimits and sys.platform.startswith("linux")) else None
        with open(log_path, "wb") as log:
            try:
                proc = subprocess.Popen(
                    list(argv), cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                    start_new_session=True, preexec_fn=preexec,
                )
            except OSError as e:
                raise RunnerError(f"could not start {what}: {type(e).__name__}") from e
            try:
                rc = proc.wait(timeout=max(0.1, timeout))
            except subprocess.TimeoutExpired:
                self._kill_group(proc)
                proc.wait()
                if timeout_cap is not None and timeout < remaining:
                    raise RunnerError(f"{what} exceeded its {timeout_cap:.0f}s limit")
                raise DeadlineExpired(what, untrusted)
            finally:
                self._kill_group(proc)  # leftovers a test started in the background never outlive the step
                if untrusted and self.sweep is not None:
                    self.sweep()  # ... not even when they left the group with setsid() (red-team F3)
        return ProcResult(rc, self.redact(_tail_file(log_path, LOGS_TAIL_CHARS)))

    @staticmethod
    def _kill_group(proc: subprocess.Popen) -> None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass


def _tail_file(path: str, chars: int) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - chars * 4))
            data = f.read()
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")[-chars:]


def _head_file(path: str, max_bytes: int) -> str:
    """The first whole lines of a log (at most `max_bytes`): a line cut by the read limit is dropped, so a value the
    Redactor hides (a signed URL has no newline) is never split before redaction."""
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes + 1)
    except OSError:
        return ""
    if len(data) > max_bytes:
        data = data[:max_bytes]
        data = data[:data.rfind(b"\n") + 1]
    return data.decode("utf-8", errors="replace")


def first_output_block(text: str, limit: int = MAX_FIELD_CHARS) -> str:
    """QA-START-MSG: the first non-empty block of a tool's output as written (lines up to the first blank line). When
    it is longer than `limit`, its first line and as many of its last lines as fit are kept (pytest's error headline
    and its final `E ...` line). No line content is interpreted."""
    lines: List[str] = []
    for line in text.splitlines():
        if line.strip():
            lines.append(line.rstrip())
        elif lines:
            break
    block = "\n".join(lines)
    if len(block) <= limit or len(lines) < 2:
        return block[:limit]
    head, tail, used = lines[0][:limit // 2], [], 0
    budget = limit - len(head) - len("\n...\n")
    for line in reversed(lines[1:]):
        if used + len(line) + 1 > budget:
            break
        tail.insert(0, line)
        used += len(line) + 1
    return head + "\n...\n" + "\n".join(tail) if tail else head


def toolchain_self_check(tc: Toolchain, work: Workdir, runner: Runner) -> Dict[str, str]:
    """Plan section 3: missing bandit / pip / venv -> exit 11 before any input is read (never a pass)."""
    versions: Dict[str, str] = {"python": ".".join(str(v) for v in sys.version_info[:3]), "job_contract": JOB_CONTRACT_VERSION,
                                "uid": str(os.getuid())}  # red-team F4: the Stage B smoke proves the job is not root
    try:
        import venv  # noqa: F401
    except ImportError as e:
        raise RunnerError("the venv module is missing") from e
    if not hasattr(tarfile, "data_filter"):  # extractall(filter="data"): 3.12+ (or a 3.11.4+ backport)
        raise RunnerError("this interpreter has no tarfile data filter")
    for name, argv in (("bandit", list(tc.bandit_argv) + ["--version"]), ("pip", [tc.python, "-m", "pip", "--version"])):
        res = runner.run(argv, env=_tool_env(work), cwd=work.tmp, untrusted=False, what=f"{name} --version",
                         log_path=os.path.join(work.out, f"selfcheck-{name}.log"), timeout_cap=TOOLCHAIN_CHECK_TIMEOUT_S)
        if res.returncode != 0:
            raise RunnerError(f"toolchain self-check failed: {name} exited {res.returncode}")
        first = res.output.strip().splitlines()[0] if res.output.strip() else ""
        versions[name] = first[:200]
    for name, path in (("bandit_ini", tc.bandit_ini), ("pytest_ini", tc.pytest_ini), ("constraints", tc.constraints)):
        try:
            versions[f"{name}_sha256"] = _sha256_file(path)
        except OSError as e:
            raise RunnerError(f"runner-owned config {name} is missing") from e
    toolchain_pins(tc.constraints)  # row QA-TOOLCHAIN-PINS: a malformed constraints file is exit 11, before any input
    return versions


# ------------------------------------------------------------------------------------------------------------------
# Diagnostics (lane 8 section B3 field names; the gateway adds source/iteration/fingerprint)
# ------------------------------------------------------------------------------------------------------------------
def _capped(value: Optional[str], limit: int = MAX_FIELD_CHARS) -> Optional[str]:
    if value is None:
        return None
    return value if len(value) <= limit else value[:limit]


def diag(tool: str, code: str, message: str, *, file: Optional[str] = None, line: Optional[int] = None,
         severity: str = "error", detail: Optional[str] = None, missing_module: Optional[str] = None) -> Dict[str, Any]:
    """One diagnostic. QA-REPAIR-MISSING-MODULE: `missing_module` (an import smoke's typed fact) is present only when it
    is exactly a module name (is_module_name), so every other diagnostic keeps exactly its seven keys."""
    if file is not None and len(file) > MAX_DIAG_FILE_CHARS:
        file = None
    out = {
        "tool": tool[:MAX_CODE_CHARS], "code": code[:MAX_CODE_CHARS], "severity": severity, "file": file,
        "line": line if isinstance(line, int) and not isinstance(line, bool) else None,
        "message": _capped(message) or "(no message)", "detail": _capped(detail),
    }
    if is_module_name(missing_module):
        out["missing_module"] = missing_module
    return out


def _errors(diags: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [d for d in diags if d["severity"] == "error"]


def fit_artifact(art: Dict[str, Any], redact: Optional[Redactor] = None) -> bytes:
    """Serialize within the gateway's 2 MiB cap: cap the count, then drop details, then halve, then trim logs.
    Every diagnostic text field and the log tail go through exact-value redaction of the signed URLs first."""
    art = dict(art)
    diags = list(art.get("diagnostics") or [])
    if redact is not None:
        diags = [{k: (redact(v) if isinstance(v, str) and k in ("message", "detail", "file") else v)
                  for k, v in d.items()} for d in diags]
        if isinstance(art.get("logs_tail"), str):
            art["logs_tail"] = redact(art["logs_tail"])
    if len(diags) > MAX_DIAGNOSTICS:
        diags, art["diagnostics_truncated"] = diags[:MAX_DIAGNOSTICS], True
    art["diagnostics"] = diags

    def enc() -> bytes:
        return json.dumps(art, sort_keys=True, ensure_ascii=False).encode("utf-8")

    data = enc()
    if len(data) > MAX_ARTIFACT_BYTES and any(d.get("detail") for d in diags):
        art["diagnostics"] = diags = [dict(d, detail=None) for d in diags]
        art["diagnostics_truncated"] = True
        data = enc()
    while len(data) > MAX_ARTIFACT_BYTES and len(diags) > 1:
        art["diagnostics"] = diags = diags[: len(diags) // 2]
        art["diagnostics_truncated"] = True
        data = enc()
    if len(data) > MAX_ARTIFACT_BYTES and art.get("logs_tail"):
        art["logs_tail"] = ""
        data = enc()
    if len(data) > MAX_ARTIFACT_BYTES:
        raise RunnerError("artifact cannot be made to fit the 2 MiB cap")
    return data


# ------------------------------------------------------------------------------------------------------------------
# Source archive: verify, check members, extract
# ------------------------------------------------------------------------------------------------------------------
def extract_source(archive: bytes, expected_sha256: str, dest: str) -> Dict[str, int]:
    """sha256 check, regular files only, FD-4G `validate_relpath`, caps; then extractall(filter="data") as a second
    layer, then an lstat check of every extracted file. Returns {relpath: size}. Any problem -> RunnerError."""
    if hashlib.sha256(archive).hexdigest() != expected_sha256:
        raise RunnerError("source archive sha256 mismatch")
    limit = MAX_TOTAL_BYTES + 64 * 1024 * 1024
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(archive)) as gz:
            raw = gz.read(limit + 1)
            if len(raw) > limit:
                raise RunnerError("source archive decompresses beyond the size cap")
            gz.read(1)  # trailer (CRC32 + ISIZE) verification
    except RunnerError:
        raise
    except Exception as e:
        raise RunnerError(f"corrupt source archive: {type(e).__name__}") from e
    try:
        tf = tarfile.open(fileobj=io.BytesIO(raw), mode="r:")
        members = tf.getmembers()
    except Exception as e:
        raise RunnerError(f"unreadable source tar: {type(e).__name__}") from e
    if not members:
        raise RunnerError("source archive has no members")
    if len(members) > MAX_MEMBERS:
        raise RunnerError(f"source archive has {len(members)} members (cap {MAX_MEMBERS})")
    sizes: Dict[str, int] = {}
    total = 0
    for m in members:
        if not m.isreg():
            raise RunnerError(f"non-regular archive member (type {m.type!r})")
        if len(m.name) > MAX_MEMBER_NAME_CHARS:
            raise RunnerError("archive member name too long")
        try:
            validate_relpath(m.name, reserved=GIT_RESERVED)
        except UnsafePathError as e:
            raise RunnerError(f"unsafe archive member: {e.reason}") from e
        if m.name in sizes:
            raise RunnerError("duplicate archive member")
        total += m.size
        if total > MAX_TOTAL_BYTES:
            raise RunnerError("source archive exceeds the uncompressed size cap")
        sizes[m.name] = m.size
    # A file and a directory with the same path ("a" and "a/b") cannot both exist on disk.
    for name in sizes:
        parts = name.split("/")
        for i in range(1, len(parts)):
            if "/".join(parts[:i]) in sizes:
                raise RunnerError("archive member is both a file and a directory")
    try:
        tf.extractall(dest, members=members, filter="data")
    except Exception as e:
        raise RunnerError(f"extraction failed: {type(e).__name__}") from e
    dest_real = os.path.realpath(dest)
    for name, size in sizes.items():
        path = os.path.join(dest, name)
        try:
            st = os.lstat(path)
        except OSError as e:
            raise RunnerError("extracted file missing") from e
        if not stat.S_ISREG(st.st_mode) or st.st_size != size:
            raise RunnerError("extracted file differs from its archive member")
        if not os.path.realpath(path).startswith(dest_real + os.sep):
            raise RunnerError("extracted file resolves outside the workspace")
    return sizes


def hash_tree(src: str, files: Iterable[str]) -> Dict[str, str]:
    """{relpath: sha256} of the extracted tree, taken before anything from it runs (red-team F5)."""
    return {rel: _sha256_file(os.path.join(src, rel)) for rel in files}


def check_tree_unchanged(src: str, baseline: Dict[str, str]) -> List[Dict[str, Any]]:
    """Red-team F5: before a service's dynamic phase, every extracted file must still be the same regular file with
    the same sha256, and untrusted code of an earlier step must not have added a Python file or a symlink (either
    could be collected or imported by this service's pytest). Other new files (a test's sqlite db, outputs) are fine.
    """
    diags = []
    for rel, digest in sorted(baseline.items()):
        path = os.path.join(src, rel)
        try:
            st = os.lstat(path)
            same = stat.S_ISREG(st.st_mode) and _sha256_file(path) == digest
        except OSError:
            same = False
        if not same:
            diags.append(diag("pytest", "PY.TREE_MODIFIED",
                              "a source file was changed or removed by code that ran in an earlier QA step", file=rel))
    for dirpath, dirnames, filenames in os.walk(src):
        for name in sorted(dirnames + filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, src).replace(os.sep, "/")
            if rel in baseline:
                continue
            if os.path.islink(full) or (name.endswith(".py") and name in filenames):
                diags.append(diag("pytest", "PY.TREE_MODIFIED",
                                  "a Python file or symlink was added by code that ran in an earlier QA step",
                                  file=rel))
    return diags


# ------------------------------------------------------------------------------------------------------------------
# Static phase (no untrusted code runs here)
# ------------------------------------------------------------------------------------------------------------------
@dataclass
class Service:
    name: str
    rel: str  # apps/<name>
    test_roots: List[str]  # repo-relative directories
    requirements: List[str] = field(default_factory=list)  # PEP 508 strings accepted by check_requirements


@dataclass
class Layout:
    services: List[Service]
    diagnostics: List[Dict[str, Any]]


def _listing(items: Sequence[str], limit: int = 10) -> str:
    shown = ", ".join(items[:limit])
    return shown + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


def discover_layout(files: Iterable[str]) -> Layout:
    """H8 / owner Q-B (a): a service is `apps/<svc>/` with a `requirements.txt`; its tests are `apps/<svc>/tests/`.
    A legacy root `tests/` runs with the single service's venv; with more than one service it is ambiguous.

    Row L3-PRB-a (explicit first-contact verdicts, CODE_DEFECT back to the developer): no Python service at all
    (e.g. a Node-only workload) or no tests -> PY.NO_TESTS; root `tests/` with more than one service ->
    PY.TEST_LAYOUT. Each diagnostic names what the job found (set facts from the archive listing), so the developer's
    QA repair rounds (rows 19o, QA-RETRIES) get an actionable message."""
    files = set(files)
    names = sorted({p.split("/")[1] for p in files if p.startswith("apps/") and p.count("/") == 2
                    and p.endswith("/requirements.txt")})
    services = []
    for n in names:
        rel = f"apps/{n}"
        roots = [f"{rel}/tests"] if any(p.startswith(f"{rel}/tests/") for p in files) else []
        services.append(Service(n, rel, roots))
    diags: List[Dict[str, Any]] = []
    root_tests = sorted(p for p in files if p.startswith("tests/"))
    if root_tests:
        if len(services) == 1:
            services[0].test_roots.append("tests")
        elif len(services) > 1:
            diags.append(diag("pytest", "PY.TEST_LAYOUT",
                              "ambiguous root tests/ in a multi-service repo: put each service's tests under "
                              "apps/<service>/tests/", file="tests",
                              detail=f"services: {_listing([s.rel for s in services])}; "
                                     f"root tests/ files: {_listing(root_tests)}"))
    if not services:
        other = sorted({f"apps/{p.split('/')[1]}" for p in files if p.startswith("apps/") and p.count("/") >= 2})
        found = (f"apps/ directories without a requirements.txt (not Python services): {_listing(other)}"
                 if other else "no apps/<service>/ directory")
        diags.append(diag("pytest", "PY.NO_TESTS",
                          "no Python service found (expected apps/<service>/requirements.txt); QA needs at least one "
                          "Python service with pytest tests (a Node-only workload has none)", detail=found))
    elif not any(s.test_roots for s in services) and not diags:
        diags.append(diag("pytest", "PY.NO_TESTS",
                          "no tests found (expected apps/<service>/tests/ or, for a single service, tests/)",
                          detail=f"services without tests: {_listing([s.rel for s in services])}"))
    return Layout(services, diags)


def check_syntax(src: str, py_files: Sequence[str]) -> Tuple[Dict[str, ast.AST], List[Dict[str, Any]]]:
    trees: Dict[str, ast.AST] = {}
    diags = []
    for rel in py_files:
        with open(os.path.join(src, rel), "rb") as f:
            data = f.read()
        try:
            trees[rel] = ast.parse(data, filename=rel)
        except SyntaxError as e:
            diags.append(diag("python", "PY.SYNTAX", f"{type(e).__name__}: {e.msg}", file=rel, line=e.lineno))
        except (ValueError, RecursionError, MemoryError) as e:
            diags.append(diag("python", "PY.SYNTAX", f"{type(e).__name__}: source cannot be parsed", file=rel))
    return trees, diags


def check_zero_dockerfile(files: Iterable[str]) -> List[Dict[str, Any]]:
    """Same rule as developer_agent/handler.is_prohibited_container_file (invariant 4)."""
    out = []
    for rel in sorted(files):
        fname = os.path.basename(rel).lower()
        if fname == "dockerfile" or fname.startswith("dockerfile.") or fname == ".dockerignore":
            out.append(diag("policy", "POLICY.DOCKERFILE",
                            "Dockerfiles are not allowed: workloads build with Cloud Buildpacks (Procfile, "
                            "requirements.txt)", file=rel))
    return out


def _strip_requirements_comment(line: str) -> str:
    """pip's requirements-file comment rule: `#` at the start of a line or after whitespace starts a comment."""
    for i, ch in enumerate(line):
        if ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
    return line


# Row QA-CHECK-REQUIREMENTS-ENCODING: pip's own pattern for an encoding comment, a bytes pattern
# (`pip._internal.req.req_file.PEP263_ENCODING_RE`; parity test on the installed pip).
PIP_PEP263_ENCODING_RE = re.compile(rb"coding[:=]\s*([-\w.]+)")


def pip_reads_other_text(data: bytes) -> bool:
    """True when pip would decode these valid UTF-8 bytes into anything but the text this job checks. pip's own rule
    (`_decode_req_file`): a BOM wins, else the codec named by a `#` comment matching its pattern in the first two lines.
    Two views of those lines: the file as committed, and the file as the deploy's `sanitize_wheel_requirements` writes
    it back (`splitlines` rejoined with newlines, comments kept, so a comment behind a form feed moves up to line 2).
    A declaration of a codec that reads the same text is harmless and stays valid (`# -*- coding: utf-8 -*-`); one pip
    could not decode with at all (an unknown or non-text codec) breaks the image build, so it counts too."""
    if data.startswith(codecs.BOM_UTF8):   # pip's BOM branch comes first, and it decodes as UTF-8 (as this job does)
        return False
    rejoined = "\n".join(data.decode("utf-8").splitlines()).encode("utf-8")
    for view in (data, rejoined):
        for line in view.split(b"\n")[:2]:
            match = PIP_PEP263_ENCODING_RE.search(line) if line[0:1] == b"#" else None
            if match is None:
                continue
            try:
                if view.decode(match.group(1).decode("ascii")) != view.decode("utf-8"):
                    return True
            except (LookupError, UnicodeError):
                return True
            break   # pip stops at the first declaration
    return False


def check_requirements(src: str, services: Sequence[Service]) -> List[Dict[str, Any]]:
    """Red-team F1 (row L3-PRB-e): every non-comment line of `apps/<svc>/requirements.txt` must be a PEP 508 *name*
    requirement (name, extras, version specifiers, marker), parsed with `packaging.requirements.Requirement`, the
    parser pip uses. Paths, URLs (`name @ url`), `-e`, `-r`/`-c` and every other pip option or `--hash` are
    rejected with POLICY.REQUIREMENTS_LINE, because pip honours them regardless of `--only-binary=:all:` and
    would run a build backend from the tree inside the trusted install step. Accepted requirements are stored on the
    service and passed to pip as argv (never `-r`). Static phase: nothing runs. Not REQ.*: the gateway treats REQ.*
    as an index problem unless the index was proven reachable (qa_job_client.classify)."""
    diags = []
    for svc in services:
        rel = f"{svc.rel}/requirements.txt"
        svc.requirements = []
        try:
            with open(os.path.join(src, rel), "rb") as f:
                data = f.read()
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            diags.append(diag("policy", "POLICY.REQUIREMENTS_LINE", "requirements.txt is not UTF-8", file=rel))
            continue
        if pip_reads_other_text(data):   # row QA-CHECK-REQUIREMENTS-ENCODING
            diags.append(diag("policy", "POLICY.REQUIREMENTS_LINE",
                              "requirements.txt declares an encoding that makes pip read something other than the "
                              "UTF-8 text checked here: remove the encoding comment", file=rel, line=1))
            continue
        for lineno, raw in enumerate(text.splitlines(), 1):
            line = _strip_requirements_comment(raw).strip()
            if not line:
                continue
            try:
                req: Optional[Requirement] = Requirement(line)
            except InvalidRequirement:
                req = None
            if req is None or req.url is not None:
                diags.append(diag(
                    "policy", "POLICY.REQUIREMENTS_LINE",
                    "requirements.txt must contain PEP 508 name requirements only (e.g. `fastapi>=0.110`): no paths, "
                    "URLs, -e, -r/-c or other pip options, no --hash", file=rel, line=lineno, detail=raw[:200]))
                continue
            svc.requirements.append(str(req))
    return diags


def toolchain_pins(constraints_path: str) -> Dict[str, List[str]]:
    """Row QA-TOOLCHAIN-PINS: {canonical PEP 503 name: [pin, ...]} of the runner-owned `qa_toolchain_constraints.txt`,
    parsed with `packaging.requirements.Requirement` (pip's comment rule, then one requirement per line). The file is
    the platform's, so a line that is not a plain name pin (unparsable, a URL, extras or a marker) or an unreadable
    file is a RunnerError (exit 11), never a workload failure."""
    try:
        with open(constraints_path, "rb") as f:
            text = f.read().decode("utf-8")
    except (OSError, UnicodeDecodeError) as e:
        raise RunnerError("runner-owned config constraints is unreadable") from e
    pins: Dict[str, List[str]] = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = _strip_requirements_comment(raw).strip()
        if not line:
            continue
        try:
            req = Requirement(line)
        except InvalidRequirement as e:
            raise RunnerError(f"runner-owned config constraints line {lineno} is not a PEP 508 requirement") from e
        if req.url is not None or req.extras or req.marker is not None:
            raise RunnerError(f"runner-owned config constraints line {lineno} is not a plain name pin")
        pins.setdefault(canonicalize_name(req.name), []).append(str(req))
    return pins


def split_toolchain_pinned(requirements: Sequence[str],
                           pins: Dict[str, List[str]]) -> Tuple[List[str], List[Tuple[str, str]]]:
    """Row QA-TOOLCHAIN-PINS ("toolchain wins"): (kept, dropped). A workload requirement whose canonical name equals a
    pinned toolchain package is dropped from the QA install (the toolchain's pin was installed in step 2a); every
    other requirement is kept unchanged and in order. `requirements` are check_requirements' validated PEP 508
    strings. dropped = [(workload requirement, toolchain pin(s))]."""
    kept: List[str] = []
    dropped: List[Tuple[str, str]] = []
    for line in requirements:
        name = canonicalize_name(Requirement(line).name)
        if name in pins:
            dropped.append((line, ", ".join(pins[name])))
        else:
            kept.append(line)
    return kept, dropped


def toolchain_replacements(requirements: Sequence[str], pins: Dict[str, List[str]],
                           preinstalled: Sequence[str]) -> List[str]:
    """Row QA-PYTEST-CRASH: the toolchain pins step 2b installs in place of dropped workload requirements. For each
    pinned package the workload names (canonical PEP 503 name, first mention first) that step 2a does not install
    (`preinstalled` = Toolchain.test_packages), its pin(s): a pinned pytest plugin (pytest-asyncio) is installed at
    the toolchain's version instead of the workload's, never left out. pytest and pytest-timeout are installed by 2a,
    so nothing is added for them (unchanged)."""
    pre = {canonicalize_name(Requirement(p).name) for p in preinstalled}
    out: List[str] = []
    seen: Set[str] = set()
    for line in requirements:
        name = canonicalize_name(Requirement(line).name)
        if name in pins and name not in pre and name not in seen:
            seen.add(name)
            out.extend(pins[name])
    return out


def _literal_strings(node: ast.AST) -> Optional[List[str]]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.List, ast.Tuple)) and all(isinstance(e, ast.Constant) and isinstance(e.value, str)
                                                       for e in node.elts):
        return [e.value for e in node.elts]
    return None


def _bound_names(tree: ast.AST) -> Iterable[Tuple[str, int]]:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield node.name, node.lineno
        elif isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                for sub in ast.walk(t):
                    if isinstance(sub, ast.Name):
                        yield sub.id, node.lineno
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                yield (a.asname or a.name.split(".")[0]), node.lineno


def _outcome_hook_findings(rel: str, tree: ast.AST) -> List[Dict[str, Any]]:
    out = []
    for name, line in _bound_names(tree):
        if name in OUTCOME_HOOKS:
            out.append(diag("pytest", "PYTEST.OUTCOME_HOOK", f"pytest hook {name} can rewrite test outcomes",
                            file=rel, line=line))
    for node in ast.walk(tree):  # @pytest.hookimpl(specname="pytest_runtest_makereport") under another name
        if isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg == "specname":
                    vals = _literal_strings(kw.value)
                    if vals is None or any(v in OUTCOME_HOOKS for v in vals):
                        out.append(diag("pytest", "PYTEST.OUTCOME_HOOK",
                                        "hookimpl specname names an outcome-rewriting hook (or is not a literal)",
                                        file=rel, line=node.lineno))
    return out


def _module_files(name: str, files: Iterable[str]) -> List[str]:
    """Every in-tree file that `import <name>` could load from ANY sys.path entry pytest or PYTHONPATH may add
    (rootdir, a test package's basedir, the service dir, ...): path-component suffix match of `a/b.py` or
    `a/b/__init__.py` (red-team F2: a superset of what pytest can import from the tree)."""
    parts = name.split(".")
    if not name or not all(parts):
        return []
    tails = (parts[:-1] + [parts[-1] + ".py"], parts + ["__init__.py"])
    found = []
    for f in files:
        fp = f.split("/")
        if any(len(fp) >= len(t) and fp[-len(t):] == t for t in tails):
            found.append(f)
    return sorted(found)


def _relative_module_files(rel: str, level: int, module: Optional[str], files: set) -> List[str]:
    """`from .x import *` in `rel`: resolved against the file's own package directory, exactly."""
    base = rel.split("/")[:-1]
    if level - 1 > len(base):
        return []
    base = base[: len(base) - (level - 1)]
    if module:
        parts = base + module.split(".")
        cands = ["/".join(parts) + ".py", "/".join(parts + ["__init__.py"])]
    else:  # `from . import *`: the package itself
        cands = ["/".join(base + ["__init__.py"])]
    return [c for c in cands if c in files]


def _star_import_files(rel: str, tree: ast.AST, files: set) -> List[str]:
    out: List[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(a.name == "*" for a in node.names):
            if node.level:
                out += _relative_module_files(rel, node.level, node.module, files)
            elif node.module:
                out += _module_files(node.module, files)
    return out


def _pluginmanager_findings(rel: str, tree: ast.AST) -> List[Dict[str, Any]]:
    """`config.pluginmanager.register(...)` (or import_plugin, consider_*) inside an allowed hook or a fixture
    registers an outcome-rewriting plugin at runtime (red-team F2 PoC 3b). Any access is flagged, tree-wide."""
    out = []
    for node in ast.walk(tree):
        hit = (isinstance(node, ast.Attribute) and node.attr == "pluginmanager") or (
            isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr"
            and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and node.args[1].value == "pluginmanager")
        if hit:
            out.append(diag("pytest", "PYTEST.OUTCOME_HOOK",
                            "workload code must not use pytest's pluginmanager (it can register outcome-rewriting "
                            "plugins at runtime)", file=rel, line=getattr(node, "lineno", None)))
    return out


def check_pytest_hooks(trees: Dict[str, ast.AST], services: Sequence[Service]) -> List[Dict[str, Any]]:
    """H4, with a real parser (a lint for the literal pattern; red-team F2): workload-authored pytest code (every
    conftest.py, every in-tree module named by a `pytest_plugins` assignment anywhere in the tree, resolved
    tree-wide, and, transitively, every in-tree module either of them star-imports) must not implement an
    outcome-rewriting hook; no file may touch pytest's pluginmanager. Fixtures and other hooks stay allowed."""
    del services  # resolution is tree-wide now (kept in the signature for callers)
    files = set(trees)
    scan = {rel for rel in trees if os.path.basename(rel) == "conftest.py"}
    diags: List[Dict[str, Any]] = []
    for rel, tree in sorted(trees.items()):
        for node in getattr(tree, "body", []):
            targets = []
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets, value = [node.target], node.value
            if not any(isinstance(t, ast.Name) and t.id == "pytest_plugins" for t in targets):
                continue
            names = _literal_strings(value)
            if names is None:
                diags.append(diag("pytest", "PYTEST.OUTCOME_HOOK",
                                  "pytest_plugins must be a literal string or list of strings", file=rel,
                                  line=node.lineno))
                continue
            for n in names:
                scan.update(_module_files(n, files))
    todo = sorted(scan)
    while todo:  # star imports pull the imported module's names into the plugin's namespace
        rel = todo.pop()
        for dep in _star_import_files(rel, trees[rel], files):
            if dep not in scan:
                scan.add(dep)
                todo.append(dep)
    for rel in sorted(scan):
        diags.extend(_outcome_hook_findings(rel, trees[rel]))
    for rel, tree in sorted(trees.items()):
        diags.extend(_pluginmanager_findings(rel, tree))
    return diags


# ------------------------------------------------------------------------------------------------------------------
# Authentication structure (row QA-AUTH-STATIC-CHECK)
# ------------------------------------------------------------------------------------------------------------------
# Three narrow rules over the parsed trees. Each is proven by structure and import resolution, never by what an
# identifier or a string is called. There is no override, so a rule that cannot prove its case stays silent: this is a
# lint for three literal shapes, not a review of an application's authentication.
SEC_UNVERIFIED_DECODE = "SEC.UNVERIFIED_TOKEN_DECODE"
SEC_AUTH_OFF_BY_DEFAULT = "SEC.AUTH_OFF_BY_DEFAULT"
SEC_LITERAL_BEARER = "SEC.LITERAL_BEARER_TOKEN"
# Same tuple as developer_agent/deploy_repair.py PLATFORM_TREE_PREFIXES (the job cannot import the gateway; parity:
# tests/test_qa_auth_static_check.py): files the platform writes, which a QA repair can never change.
PLATFORM_TREE_PREFIXES = ("infra/", ".github/")

# Index of the positional `options` parameter of the libraries' decode functions.
_OPTIONS_DECODERS = {"jwt.decode": 3, "jwt.api_jwt.decode": 3, "jose.jwt.decode": 3}
# google.auth.jwt.decode(token, certs=None, verify=True, ...): index of the positional `verify` parameter.
_GOOGLE_JWT_DECODE, _GOOGLE_VERIFY_INDEX = "google.auth.jwt.decode", 2
_UNVERIFIED_READERS = frozenset({"jose.jwt.get_unverified_claims", "jose.jws.get_unverified_claims"})
_KEYED_VERIFIERS = frozenset(set(_OPTIONS_DECODERS) | {_GOOGLE_JWT_DECODE})  # verify only when given a key or certs
_SELF_VERIFYING = frozenset({
    "google.oauth2.id_token.verify_token", "google.oauth2.id_token.verify_oauth2_token",
    "google.oauth2.id_token.verify_firebase_token", "firebase_admin.auth.verify_id_token",
})

_ENV_READERS = frozenset({"os.getenv", "os.environ.get"})
_TRUTHY_ENV_DEFAULTS = frozenset({"1", "true", "yes", "on", "y", "t"})
_STR_NORMALIZERS = {"lower": str.lower, "upper": str.upper, "strip": str.strip, "casefold": str.casefold}
_MAX_FLAG_EXPR_DEPTH = 32  # a flag expression deeper than this proves nothing (and never recurses far)

_HTTP_EXCEPTIONS = frozenset({"fastapi.HTTPException", "fastapi.exceptions.HTTPException",
                              "starlette.exceptions.HTTPException"})
_REFUSAL_EXCEPTIONS = frozenset({"werkzeug.exceptions.Unauthorized", "werkzeug.exceptions.Forbidden"})
_ABORT_CALLS = frozenset({"flask.abort", "werkzeug.exceptions.abort"})
_REFUSAL_STATUS_CODES = frozenset({401, 403})
_REFUSAL_STATUS_NAMES = frozenset({
    f"{module}.{name}" for module in ("fastapi.status", "starlette.status")
    for name in ("HTTP_401_UNAUTHORIZED", "HTTP_403_FORBIDDEN")
} | {"http.HTTPStatus.UNAUTHORIZED", "http.HTTPStatus.FORBIDDEN"})

_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
_FUNCTION_NODES = (ast.FunctionDef, ast.AsyncFunctionDef)


def is_workload_test_file(rel: str) -> bool:
    """The repository's test-path rule (deploy/vendor_shared.py `_is_test_file`, same four clauses; the job cannot
    import it, parity: tests/test_qa_auth_static_check.py)."""
    name = rel.rsplit("/", 1)[-1]
    return name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py" or "/tests/" in f"/{rel}"


@dataclass(eq=False)
class _Scope:
    node: ast.AST
    parent: Optional["_Scope"]
    # name -> how it is bound here: ("import", dotted), ("def", node), ("value", expr) or ("other", None).
    bindings: Dict[str, List[Tuple[str, Any]]] = field(default_factory=dict)

    @property
    def is_class(self) -> bool:
        return isinstance(self.node, ast.ClassDef)


def _scope_nodes(scope_node: ast.AST) -> Iterable[ast.AST]:
    """Every node of one scope, parents before children, without entering a nested def, lambda or class. Iterative:
    a deep but parseable expression must not raise RecursionError here."""
    stack = list(ast.iter_child_nodes(scope_node))
    while stack:
        node = stack.pop()
        yield node
        if not isinstance(node, _SCOPE_NODES):
            stack.extend(ast.iter_child_nodes(node))


def _statement_lists(scope_node: ast.AST) -> Iterable[List[ast.stmt]]:
    """Every statement list of one scope (block bodies, else and finally branches, except handlers)."""
    for node in [scope_node, *_scope_nodes(scope_node)]:
        if node is not scope_node and isinstance(node, _SCOPE_NODES):
            continue
        for name in ("body", "orelse", "finalbody"):
            block = getattr(node, name, None)
            if isinstance(block, list) and block and isinstance(block[0], ast.stmt):
                yield block


def _contains(nodes: Iterable[ast.AST], kinds: Any) -> bool:
    return any(isinstance(n, kinds) for top in nodes for n in ast.walk(top))


class _AuthFile:
    """One parsed file: lexical scopes and import resolution for the three rules."""

    def __init__(self, tree: ast.AST, in_tree: Callable[[str], bool]):
        self.in_tree = in_tree
        self.poisoned: Set[str] = set()  # a `global` / `nonlocal` name can be rebound from anywhere: never proven
        self.module = _Scope(tree, None)
        self.scopes = [self.module]
        todo = [self.module]
        while todo:
            scope = todo.pop()
            for child in self._bind(scope):
                inner = _Scope(child, scope)
                self.scopes.append(inner)
                todo.append(inner)

    def _bind(self, scope: _Scope) -> List[ast.AST]:
        def add(name: str, kind: str, payload: Any = None) -> None:
            scope.bindings.setdefault(name, []).append((kind, payload))

        children: List[ast.AST] = []
        simple_targets: Set[int] = set()
        for node in _scope_nodes(scope.node):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.asname:
                        add(a.asname, "import", a.name)
                    else:
                        add(a.name.split(".")[0], "import", a.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                for a in node.names:
                    if a.name == "*":
                        continue
                    if node.level == 0 and node.module:
                        add(a.asname or a.name, "import", f"{node.module}.{a.name}")
                    else:
                        add(a.asname or a.name, "other")
            elif isinstance(node, _SCOPE_NODES):
                if not isinstance(node, ast.Lambda):
                    add(node.name, "def", node)
                children.append(node)
            elif isinstance(node, (ast.Global, ast.Nonlocal)):
                self.poisoned.update(node.names)
            elif isinstance(node, ast.arg):
                add(node.arg, "other")
            elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                add(node.targets[0].id, "value", node.value)
                simple_targets.add(id(node.targets[0]))
            elif isinstance(node, ast.AnnAssign) and node.value is not None and isinstance(node.target, ast.Name):
                add(node.target.id, "value", node.value)
                simple_targets.add(id(node.target))
            elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and id(node) not in simple_targets:
                add(node.id, "other")
            elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
                add(node.name, "other")
            elif isinstance(node, ast.MatchMapping) and node.rest:
                add(node.rest, "other")
        return children

    def owner(self, name: str, scope: _Scope) -> Optional[_Scope]:
        """The scope a Name read in `scope` resolves to (class bodies are invisible from inside their methods)."""
        if name in self.poisoned:
            return None
        current: Optional[_Scope] = scope
        while current is not None:
            if name in current.bindings and (current is scope or not current.is_class):
                return current
            current = current.parent
        return None

    def single(self, name: str, scope: _Scope, kind: str) -> Any:
        """The payload of `name` when it has exactly one binding and that binding is of `kind`, else None."""
        found = self.owner(name, scope)
        bindings = found.bindings[name] if found is not None else []
        return bindings[0][1] if len(bindings) == 1 and bindings[0][0] == kind else None

    def dotted(self, expr: ast.AST, scope: _Scope) -> Optional[str]:
        """The absolute dotted name `expr` refers to through imports (aliases and from-imports included), or None for
        anything else: a local object, a name also bound another way, or a module the workload ships itself."""
        attrs: List[str] = []
        while isinstance(expr, ast.Attribute):
            attrs.append(expr.attr)
            expr = expr.value
        if not isinstance(expr, ast.Name):
            return None
        found = self.owner(expr.id, scope)
        if found is None or any(kind != "import" for kind, _ in found.bindings[expr.id]):
            return None
        targets = {target for _, target in found.bindings[expr.id]}
        if len(targets) != 1:
            return None
        target = targets.pop()
        if self.in_tree(target.split(".")[0]):
            return None
        return ".".join([target] + attrs[::-1])

    def literal(self, expr: Optional[ast.AST], scope: _Scope) -> Optional[ast.AST]:
        """`expr`, following one Name to its single assignment."""
        if isinstance(expr, ast.Name):
            return self.single(expr.id, scope, "value")
        return expr


def _keyword(call: ast.Call, name: str) -> Optional[ast.AST]:
    return next((k.value for k in call.keywords if k.arg == name), None)


def _argument(call: ast.Call, index: int, name: str) -> Optional[ast.AST]:
    return call.args[index] if len(call.args) > index else _keyword(call, name)


def _is_false(expr: Optional[ast.AST]) -> bool:
    return isinstance(expr, ast.Constant) and expr.value is False


def _dict_entry(mapping: Optional[ast.AST], key: str) -> Optional[ast.AST]:
    if isinstance(mapping, ast.Dict):
        for k, v in zip(mapping.keys, mapping.values):
            if isinstance(k, ast.Constant) and k.value == key:
                return v
    return None


def _skips_verification(f: _AuthFile, call: ast.Call, api: Optional[str], scope: _Scope) -> bool:
    if api in _UNVERIFIED_READERS:
        return True
    if api == _GOOGLE_JWT_DECODE:
        return _is_false(f.literal(_argument(call, _GOOGLE_VERIFY_INDEX, "verify"), scope))
    if api in _OPTIONS_DECODERS:
        options = f.literal(_argument(call, _OPTIONS_DECODERS[api], "options"), scope)
        # `verify=False` is PyJWT 1.x's spelling of the same request (a workload can pin an old version).
        return (_is_false(f.literal(_keyword(call, "verify"), scope))
                or _is_false(f.literal(_dict_entry(options, "verify_signature"), scope)))
    return False


def _verifies_token(f: _AuthFile, call: ast.Call, token: str, scope: _Scope) -> bool:
    """`call` checks the signature of exactly the expression `token` (`ast.dump` text): a verifying API, the same first
    argument, a key or certs given, and every verification setting either absent or a literal that keeps it on."""
    api = f.dotted(call.func, scope)
    if not call.args or ast.dump(call.args[0]) != token or _skips_verification(f, call, api, scope):
        return False
    if api in _SELF_VERIFYING:
        return True
    if api not in _KEYED_VERIFIERS:
        return False
    key = _argument(call, 1, "certs" if api == _GOOGLE_JWT_DECODE else "key")
    if key is None or (isinstance(key, ast.Constant) and not key.value):
        return False
    if api == _GOOGLE_JWT_DECODE:
        verify = _argument(call, _GOOGLE_VERIFY_INDEX, "verify")
        return verify is None or (isinstance(verify, ast.Constant) and verify.value is True)
    verify = _keyword(call, "verify")
    options = _argument(call, _OPTIONS_DECODERS[api], "options")
    return (verify is None or (isinstance(verify, ast.Constant) and verify.value is True)) and (
        options is None or isinstance(options, ast.Dict))


def _direct_call(stmt: ast.stmt) -> Optional[ast.Call]:
    value = stmt.value if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.Return, ast.Expr)) else None
    value = value.value if isinstance(value, ast.Await) else value
    return value if isinstance(value, ast.Call) else None


def _peeked_call(value: ast.AST) -> Optional[ast.AST]:
    """The call behind `x = decode(...)`, `x = decode(...)["iss"]` or `x = decode(...).get("iss")`."""
    if isinstance(value, ast.Subscript):
        return value.value
    if isinstance(value, ast.Call) and isinstance(value.func, ast.Attribute) and value.func.attr == "get":
        return value.func.value
    return value


def _peek_then_verify(f: _AuthFile, scope: _Scope, block: List[ast.stmt], index: int, call: ast.Call) -> bool:
    """A proven peek (`x = <unverified decode of T>`, for example to read `iss` and pick the key). True only when:
    a later statement of the same block verifies exactly T (directly or as the body of a `try` whose every handler
    re-raises), nothing between the two can return or rebind T, and `x` is not read after the verifying statement."""
    stmt = block[index]
    if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
        return False
    if not call.args or not isinstance(call.args[0], (ast.Name, ast.Attribute)):
        return False
    peek, token = stmt.targets[0].id, ast.dump(call.args[0])
    root = call.args[0]
    while isinstance(root, ast.Attribute):
        root = root.value
    if not isinstance(root, ast.Name):
        return False

    def interferes(s: ast.stmt) -> bool:
        return _contains([s], (ast.Return, ast.Yield, ast.YieldFrom)) or any(
            isinstance(n, ast.Name) and n.id == root.id and isinstance(n.ctx, ast.Store) for n in ast.walk(s))

    for later in block[index + 1:]:
        verified = False
        if isinstance(later, ast.Try):
            if later.handlers and all(isinstance(h.body[-1], ast.Raise) for h in later.handlers):
                for inner in later.body:
                    inner_call = _direct_call(inner)
                    if inner_call is not None and _verifies_token(f, inner_call, token, scope):
                        verified = True
                        break
                    if interferes(inner):
                        return False
        else:
            later_call = _direct_call(later)
            verified = later_call is not None and _verifies_token(f, later_call, token, scope)
        if verified:
            end = later.end_lineno or later.lineno
            return not any(isinstance(n, ast.Name) and n.id == peek and isinstance(n.ctx, ast.Load)
                           and n.lineno > end for n in _scope_nodes(scope.node))
        if interferes(later):
            return False
    return False


def _unverified_decode_findings(rel: str, f: _AuthFile) -> List[Dict[str, Any]]:
    out = []
    for scope in f.scopes:
        found = {}
        for node in _scope_nodes(scope.node):
            if isinstance(node, ast.Call):
                api = f.dotted(node.func, scope)
                if api is not None and _skips_verification(f, node, api, scope):
                    found[id(node)] = (node, api)
        for block in (_statement_lists(scope.node) if found else ()):
            for i, stmt in enumerate(block):
                candidate = _peeked_call(stmt.value) if isinstance(stmt, ast.Assign) else None
                if id(candidate) in found and _peek_then_verify(f, scope, block, i, candidate):
                    del found[id(candidate)]
        for node, api in found.values():
            out.append(diag("ast", SEC_UNVERIFIED_DECODE,
                            f"{api} reads a token without checking its signature, so anyone can forge its claims. "
                            "Verify the signature, issuer and audience with the library's verifying call before "
                            "trusting any claim.", file=rel, line=node.lineno))
    return out


class _FlagDefaults:
    """Module-level flags proven to read an environment variable whose literal default is truthy, and the value of an
    expression when those variables are unset (None = not proven)."""

    def __init__(self, f: _AuthFile):
        self.f = f
        self.values: Dict[str, Any] = {}
        for stmt in f.module.node.body:
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                target, value = stmt.targets[0], stmt.value
            elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                target, value = stmt.target, stmt.value
            else:
                continue
            if not isinstance(target, ast.Name) or target.id in f.poisoned or len(f.module.bindings[target.id]) != 1:
                continue
            default = self.evaluate(value, f.module, True) if self._reads_env_or_flag(value) else None
            if default:  # a flag proven to default to on (False, "" and unproven values are not flags)
                self.values[target.id] = default

    def _reads_env_or_flag(self, value: ast.AST) -> bool:
        return any((isinstance(n, ast.Call) and self.f.dotted(n.func, self.f.module) in _ENV_READERS)
                   or (isinstance(n, ast.Name) and n.id in self.values) for n in ast.walk(value))

    def _is_flag(self, name: str, scope: _Scope) -> bool:
        return name in self.values and self.f.owner(name, scope) is self.f.module

    def uses_flag(self, expr: ast.AST, scope: _Scope) -> bool:
        return any(isinstance(n, ast.Name) and self._is_flag(n.id, scope) for n in ast.walk(expr))

    def only_flags(self, expr: ast.AST, scope: _Scope) -> bool:
        """`expr` reads nothing but proven flags (no request, argument or other state can change it)."""
        return all(self._is_flag(n.id, scope) or (n.id == "bool" and self.f.owner("bool", scope) is None)
                   for n in ast.walk(expr) if isinstance(n, ast.Name))

    def evaluate(self, expr: ast.AST, scope: _Scope, env: bool = False, depth: int = 0) -> Any:
        """`env` allows reading the environment (module-level flag definitions only)."""
        if depth > _MAX_FLAG_EXPR_DEPTH:
            return None

        def recur(e: ast.AST) -> Any:
            return self.evaluate(e, scope, env, depth + 1)

        if isinstance(expr, ast.Constant):
            return expr.value if isinstance(expr.value, (str, int)) else None
        if isinstance(expr, ast.Name):
            return self.values[expr.id] if self._is_flag(expr.id, scope) else None
        if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.Not):
            value = recur(expr.operand)
            return None if value is None else not value
        if isinstance(expr, ast.BoolOp):
            values = [recur(v) for v in expr.values]
            settles = isinstance(expr.op, ast.Or)  # the operand truth value that decides the operator
            if any(v is not None and bool(v) is settles for v in values):
                return settles
            return None if any(v is None for v in values) else not settles
        if isinstance(expr, ast.Compare) and len(expr.ops) == 1:
            return self._compare(recur(expr.left), expr.ops[0], expr.comparators[0])
        if isinstance(expr, ast.Call):
            return self._call(expr, scope, env, recur)
        return None

    def _call(self, call: ast.Call, scope: _Scope, env: bool, recur: Callable[[ast.AST], Any]) -> Any:
        if env and self.f.dotted(call.func, scope) in _ENV_READERS:
            default = _argument(call, 1, "default")
            if not isinstance(default, ast.Constant):
                return None
            value = default.value
            proven = (isinstance(value, str) and value.strip().lower() in _TRUTHY_ENV_DEFAULTS) or value is True \
                or (type(value) is int and value == 1)
            return value if proven else None
        if isinstance(call.func, ast.Name) and call.func.id == "bool" and self.f.owner("bool", scope) is None:
            value = recur(call.args[0]) if len(call.args) == 1 and not call.keywords else None
            return None if value is None else bool(value)
        if isinstance(call.func, ast.Attribute) and call.func.attr in _STR_NORMALIZERS and not call.args \
                and not call.keywords:
            value = recur(call.func.value)
            return _STR_NORMALIZERS[call.func.attr](value) if isinstance(value, str) else None
        return None

    @staticmethod
    def _compare(left: Any, op: ast.cmpop, right: ast.AST) -> Any:
        if left is None:
            return None
        if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(right, ast.Constant):
            return (left == right.value) is isinstance(op, ast.Eq)
        if isinstance(op, (ast.In, ast.NotIn)) and isinstance(right, (ast.Tuple, ast.List, ast.Set)) and all(
                isinstance(e, ast.Constant) for e in right.elts):
            return (left in [e.value for e in right.elts]) is isinstance(op, ast.In)
        return None


def _is_refusal_status(f: _AuthFile, expr: Optional[ast.AST], scope: _Scope) -> bool:
    if isinstance(expr, ast.Constant):
        return type(expr.value) is int and expr.value in _REFUSAL_STATUS_CODES
    return expr is not None and f.dotted(expr, scope) in _REFUSAL_STATUS_NAMES


def _is_refusal(f: _AuthFile, stmt: ast.AST, scope: _Scope) -> bool:
    """`stmt` itself raises an HTTP 401 or 403 through a framework API resolved by import."""
    if isinstance(stmt, ast.Raise) and stmt.exc is not None:
        exc = stmt.exc
        api = f.dotted(exc.func if isinstance(exc, ast.Call) else exc, scope)
        if api in _REFUSAL_EXCEPTIONS:
            return True
        return isinstance(exc, ast.Call) and api in _HTTP_EXCEPTIONS and _is_refusal_status(
            f, _argument(exc, 0, "status_code"), scope)
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call) \
            and f.dotted(stmt.value.func, scope) in _ABORT_CALLS:
        return _is_refusal_status(f, _argument(stmt.value, 0, "code"), scope)
    return False


def _refuses_any_way(f: _AuthFile, block: Sequence[ast.stmt], scope: _Scope) -> bool:
    """The block can raise (any exception) or abort, so its path may still refuse the request."""
    return _contains(block, ast.Raise) or any(
        isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and f.dotted(n.value.func, scope) in _ABORT_CALLS
        for top in block for n in ast.walk(top))


def _off_by_default_origin(f: _AuthFile, flags: _FlagDefaults, scope: _Scope) -> Optional[ast.If]:
    """The `if` that proves this function's HTTP 401/403 is off by default, or None. All of these must hold:
    1. the function itself raises at least one 401/403, and with the flags at their defaults EVERY one of them is
       unreachable (in the branch a flag test rules out, or after a flag-guarded `return`);
    2. the branch taken by default contains no `raise` or abort (a default path that still refuses is no bypass);
    3. at least one of those raises also depends on something other than the flags (a credential check, an except
       handler). A raise that depends on the flags alone is a kill switch: turning the flag off refuses everybody."""
    refusals = sum(1 for n in _scope_nodes(scope.node) if _is_refusal(f, n, scope))
    if not refusals:
        return None
    dead = 0
    origin: Optional[ast.If] = None

    def scan(block: Sequence[ast.stmt], dead_by: Optional[ast.If], conditional: bool) -> None:
        nonlocal dead, origin
        for stmt in block:
            if _is_refusal(f, stmt, scope):
                if dead_by is not None:
                    dead += 1
                    if conditional and origin is None:
                        origin = dead_by
            elif isinstance(stmt, ast.If):
                value = flags.evaluate(stmt.test, scope) if flags.uses_flag(stmt.test, scope) else None
                inner_conditional = conditional or value is None or not flags.only_flags(stmt.test, scope)
                live = None if value is None else (stmt.body if value else stmt.orelse)
                proven = live is not None and not _refuses_any_way(f, live, scope)
                scan(stmt.body, dead_by or (stmt if proven and not value else None), inner_conditional)
                scan(stmt.orelse, dead_by or (stmt if proven and value else None), inner_conditional)
                if proven and live and isinstance(live[-1], ast.Return):
                    dead_by = dead_by or stmt  # the default path left the function: the rest of this block is off
            elif isinstance(stmt, ast.Try):
                scan(stmt.body, dead_by, conditional)
                for handler in stmt.handlers:
                    scan(handler.body, dead_by, True)
                scan(stmt.orelse, dead_by, conditional)
                scan(stmt.finalbody, dead_by, conditional)
            elif isinstance(stmt, (ast.For, ast.AsyncFor, ast.While)):
                scan(stmt.body, dead_by, True)
                scan(stmt.orelse, dead_by, True)
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                scan(stmt.body, dead_by, conditional)

    scan(scope.node.body, None, False)
    return origin if dead == refusals else None


def _auth_off_by_default_findings(rel: str, f: _AuthFile) -> List[Dict[str, Any]]:
    flags = _FlagDefaults(f)
    if not flags.values:
        return []
    out = []
    for scope in f.scopes:
        if isinstance(scope.node, _FUNCTION_NODES):
            origin = _off_by_default_origin(f, flags, scope)
            if origin is not None:
                names = sorted({n.id for n in ast.walk(origin.test)
                                if isinstance(n, ast.Name) and n.id in flags.values})
                out.append(diag("ast", SEC_AUTH_OFF_BY_DEFAULT,
                                f"{scope.node.name} can only refuse a request (HTTP 401/403) when {', '.join(names)} is "
                                "off, and that flag reads an environment variable that defaults to on, so the check "
                                "is disabled unless someone sets the variable. Make enforcement the default.",
                                file=rel, line=origin.lineno))
    return out


def _bearer_value(value: ast.AST) -> Optional[ast.AST]:
    """The expression x of exactly f"Bearer {x}", or None."""
    if isinstance(value, ast.JoinedStr) and len(value.values) == 2:
        head, tail = value.values
        if isinstance(head, ast.Constant) and head.value == "Bearer " and isinstance(tail, ast.FormattedValue):
            return tail.value
    return None


def _authorization_values(scope: _Scope) -> Iterable[ast.AST]:
    """The values written to an Authorization header in this scope: `{"Authorization": v}` or `h["Authorization"] = v`."""
    def is_header(key: Any) -> bool:
        return isinstance(key, ast.Constant) and isinstance(key.value, str) and key.value.lower() == "authorization"

    for node in _scope_nodes(scope.node):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                if is_header(key):
                    yield value
        elif isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Subscript) and is_header(target.slice):
                    yield node.value


def _called_function(f: _AuthFile, call: ast.Call, scope: _Scope) -> Optional[ast.AST]:
    """The function of this file `call` runs: a plain name bound by exactly one `def`, or `<first parameter>.m(...)`
    in a method whose own class defines `m` exactly once."""
    if isinstance(call.func, ast.Name):
        return f.single(call.func.id, scope, "def")
    if isinstance(call.func, ast.Attribute) and isinstance(call.func.value, ast.Name) \
            and isinstance(scope.node, _FUNCTION_NODES) and scope.parent is not None and scope.parent.is_class:
        params = scope.node.args.posonlyargs + scope.node.args.args
        if params and params[0].arg == call.func.value.id:
            bindings = scope.parent.bindings.get(call.func.attr, [])
            if len(bindings) == 1 and bindings[0][0] == "def":
                return bindings[0][1]
    return None


def _literal_returns(f: _AuthFile, fn: ast.AST) -> Iterable[ast.Return]:
    """The `return` statements of `fn` whose value is a non-blank string literal (or a name bound exactly once to such
    a literal). An empty string is how a client says "no token"; it is not a made-up credential."""
    scope = next(s for s in f.scopes if s.node is fn)
    for node in _scope_nodes(fn):
        if isinstance(node, ast.Return):
            value = f.literal(node.value, scope)
            if isinstance(value, ast.Constant) and isinstance(value.value, str) and value.value.strip():
                yield node


def _literal_bearer_findings(rel: str, f: _AuthFile) -> List[Dict[str, Any]]:
    out = []
    for scope in f.scopes:
        for value in _authorization_values(scope):
            token = _bearer_value(value)
            token = f.literal(token, scope) if isinstance(token, ast.Name) else token
            token = token.value if isinstance(token, ast.Await) else token
            fn = _called_function(f, token, scope) if isinstance(token, ast.Call) else None
            for ret in (_literal_returns(f, fn) if isinstance(fn, _FUNCTION_NODES) else ()):
                out.append(diag("ast", SEC_LITERAL_BEARER,
                                f"{fn.name} returns a string literal here, and its result is sent as the Bearer token "
                                f"in the Authorization header at line {value.lineno}. Never send a made-up credential: "
                                "fail the call instead, or read the token from the platform's credentials.",
                                file=rel, line=ret.lineno))
    return out


def check_auth_structure(trees: Dict[str, ast.AST]) -> List[Dict[str, Any]]:
    """QA-AUTH-STATIC-CHECK: the three rules above over every parsed non-test file the workload owns (a file that does
    not parse has its PY.SYNTAX finding and is not in `trees`). Error severity: the normal QA repair route."""
    files = set(trees)
    known: Dict[str, bool] = {}

    def in_tree(module: str) -> bool:
        if module not in known:
            known[module] = bool(_module_files(module, files))
        return known[module]

    out: List[Dict[str, Any]] = []
    for rel, tree in sorted(trees.items()):
        if is_workload_test_file(rel) or rel.startswith(PLATFORM_TREE_PREFIXES):
            continue
        f = _AuthFile(tree, in_tree)
        findings = (_unverified_decode_findings(rel, f) + _auth_off_by_default_findings(rel, f)
                    + _literal_bearer_findings(rel, f))
        seen: Set[Tuple[str, Optional[int]]] = set()
        for d in sorted(findings, key=lambda d: (d["line"] or 0, d["code"])):
            if (d["code"], d["line"]) not in seen:
                seen.add((d["code"], d["line"]))
                out.append(d)
    return out


def run_bandit(tc: Toolchain, work: Workdir, runner: Runner) -> List[Dict[str, Any]]:
    """H4/H5: runner-owned ini (skips B101,B104), --ignore-nosec; block on HIGH severity with MEDIUM+ confidence;
    MEDIUM severity is reported as a warning. A missing / unreadable JSON report is a runner error, never a pass."""
    report = os.path.join(work.out, "bandit.json")
    argv = list(tc.bandit_argv) + ["-r", work.src, "-f", "json", "-o", report, "-q", "--ignore-nosec",
                                   "--ini", tc.bandit_ini]
    res = runner.run(argv, env=_tool_env(work), cwd=work.tmp, untrusted=False, what="bandit",
                     log_path=os.path.join(work.out, "bandit.log"))
    if res.returncode not in (0, 1):
        raise RunnerError(f"bandit exited {res.returncode}")
    try:
        if os.path.getsize(report) > MAX_TOOL_OUTPUT_BYTES:
            raise RunnerError("bandit report too large")
        with open(report, "rb") as f:
            data = json.loads(f.read().decode("utf-8"))
        results = data["results"]
        if not isinstance(results, list):
            raise ValueError("results is not a list")
    except RunnerError:
        raise
    except (OSError, ValueError, KeyError, TypeError) as e:
        raise RunnerError(f"bandit produced no usable JSON report: {type(e).__name__}") from e
    if res.returncode == 1 and not results:
        raise RunnerError("bandit exited 1 without results")
    diags = []
    src_real = os.path.realpath(work.src)
    for r in results:
        if not isinstance(r, dict):
            raise RunnerError("bandit result is not an object")
        sev, conf = str(r.get("issue_severity", "")).upper(), str(r.get("issue_confidence", "")).upper()
        if sev == "HIGH" and conf in ("MEDIUM", "HIGH"):
            severity = "error"
        elif sev in ("HIGH", "MEDIUM"):
            severity = "warning"
        else:
            continue
        fname = str(r.get("filename", ""))
        real = os.path.realpath(fname)
        rel = os.path.relpath(real, src_real) if real.startswith(src_real + os.sep) else None
        line = r.get("line_number")
        test_id = str(r.get("test_id") or "UNKNOWN")
        diags.append(diag("bandit", f"BANDIT.{test_id}",
                          f"{r.get('test_name', '')}: {r.get('issue_text', '')} (severity {sev}, confidence {conf})",
                          file=rel, line=line if isinstance(line, int) else None, severity=severity))
    return diags


def _python_version_mismatches(src: str, services: Sequence[Service]) -> str:
    """H9: recorded, never blocking."""
    job = f"{sys.version_info[0]}.{sys.version_info[1]}"
    out = []
    for s in services:
        p = os.path.join(src, s.rel, ".python-version")
        try:
            with open(p, "r", encoding="utf-8", errors="replace") as f:
                want = f.read(64).strip()
        except OSError:
            continue
        if want and want.split(".")[:2] != job.split("."):
            out.append(f"{s.rel}:{want[:16]}")
    return ",".join(out)


# ------------------------------------------------------------------------------------------------------------------
# Dynamic phase (untrusted code: import smoke + pytest; dependency install is trusted pip, wheels only)
# ------------------------------------------------------------------------------------------------------------------
def _safe_rel(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        return validate_relpath(value)
    except UnsafePathError:
        return None


def is_internal_error_case(case: ET.Element) -> bool:
    """Row QA-PYTEST-CRASH: pytest's synthetic internal-error testcase (JUNIT_INTERNAL_ERROR_CASE, no `file`, an
    <error> child). Decided by the junit's structure only; a real test always carries `file` in xunit1."""
    return ((case.get("classname"), case.get("name")) == JUNIT_INTERNAL_ERROR_CASE and case.get("file") is None
            and any(c.tag == "error" for c in case))


def parse_junit(path: str, missing_module: Optional[str] = None) -> Tuple[int, int, List[Dict[str, Any]], List[str]]:
    """(total, failed, diagnostics, internal_errors) from a pytest junit XML (xunit1: carries file/line). Raises
    ValueError. `internal_errors` = the crash report text of each synthetic internal-error case (row QA-PYTEST-CRASH):
    those cases are not tests, so they are neither counted nor reported as PY.TEST_FAILED. QA-REPAIR-SETUP-ERROR: a
    case whose first bad child is <error> is PY.TEST_SETUP_ERROR, one whose first is <failure> PY.TEST_FAILED; both
    count as failed. QA-REPAIR-MISSING-MODULE-SETUP: `missing_module` (the run's fact, missing_module_fact) is added to
    every PY.TEST_SETUP_ERROR diagnostic; None (the default) leaves every diagnostic exactly as before."""
    if os.path.getsize(path) > MAX_TOOL_OUTPUT_BYTES:
        raise ValueError("junit report too large")
    root = ET.parse(path).getroot()
    total = failed = 0
    diags = []
    internal: List[str] = []
    for case in root.iter("testcase"):
        if is_internal_error_case(case):
            internal.append(next(c for c in case if c.tag == "error").text or "")
            continue
        total += 1
        bad = [c for c in case if c.tag in ("failure", "error")]
        if not bad:
            continue
        failed += 1
        b = bad[0]
        line = case.get("line")
        try:
            line_no = int(line) + 1 if line is not None else None  # pytest locations are 0-based
        except ValueError:
            line_no = None
        name = ".".join(x for x in (case.get("classname"), case.get("name")) if x)
        # QA-REPAIR-SETUP-ERROR: the first bad child's tag decides the code (<error>: outside the test's own call)
        code = PYTEST_SETUP_ERROR_CODE if b.tag == "error" else TEST_FAILED_CODE
        diags.append(diag("pytest", code, f"{name}: {b.get('message') or b.tag}",
                          file=_safe_rel(case.get("file")), line=line_no, detail=b.text,
                          missing_module=missing_module if code == PYTEST_SETUP_ERROR_CODE else None))
    return total, failed, diags, internal


# RT14-17 (owner 11-14): a test pytest did not execute to a verdict -- a <skipped> testcase without <failure>/<error>
# (pytest.skip, skipif, a module-level skip, and xfail, which pytest's junit reports as <skipped type="pytest.xfail">).
ALL_TESTS_SKIPPED_CODE = "PY.ALL_TESTS_SKIPPED"
MAX_SKIP_REASONS = 20


def junit_skips(path: str) -> List[str]:
    """RT14-17: one entry per skipped testcase of a pytest junit XML (the reason pytest wrote: the <skipped> message,
    else its type), in report order. Decided by the junit's structure only: a testcase with a <skipped> child and no
    <failure>/<error> child; pytest's synthetic internal-error case is not a test (parse_junit's rule). Raises
    ValueError / ET.ParseError like parse_junit (the caller has already parsed the same file)."""
    if os.path.getsize(path) > MAX_TOOL_OUTPUT_BYTES:
        raise ValueError("junit report too large")
    out: List[str] = []
    for case in ET.parse(path).getroot().iter("testcase"):
        if is_internal_error_case(case) or any(c.tag in ("failure", "error") for c in case):
            continue
        skipped = next((c for c in case if c.tag == "skipped"), None)
        if skipped is None:
            continue
        name = ".".join(x for x in (case.get("classname"), case.get("name")) if x)
        out.append(f"{name}: {skipped.get('message') or skipped.get('type') or 'skipped'}")
    return out


def pytest_crash_diag(code: str, svc_rel: str, returncode: int, log_path: str, redact: "Redactor",
                      crash_report: Optional[str], output: str) -> Dict[str, Any]:
    """Row QA-PYTEST-CRASH: the diagnostic of a pytest run that crashed. The message leads with pytest's own first
    output block (QA-START-MSG's helpers: whole lines of the log head, redacted before cutting, bounded); the detail
    is the END of pytest's crash report (the junit's internal-error text, else pytest's output), where the exception
    is, redacted before it is cut. Quoted as written, never interpreted."""
    first = first_output_block(redact(_head_file(log_path, CRASH_LOG_HEAD_BYTES)), MAX_FIELD_CHARS - 256)
    what = "crashed with an internal error" if code == PYTEST_INTERNAL_ERROR_CODE else "stopped with a session error"
    tail = f"pytest {what} for {svc_rel}: exit {returncode}; pytest's crash report in detail"
    message = f"{first}\n({tail})" if first else tail
    report = redact(crash_report) if crash_report else output
    return diag("pytest", code, message, file=service_scope_file(svc_rel),
                detail=report[-MAX_FIELD_CHARS:] if report else None)


def service_scope_file(svc_rel: str) -> str:
    """Row QA-PYTEST-CRASH: the `file` of a crash diagnostic = the service's requirements.txt (every QA service has
    one, discover_layout), so the gateway can scope the test-setup repair to that service."""
    return f"{svc_rel}/requirements.txt"


@dataclass
class DynamicResult:
    diagnostics: List[Dict[str, Any]] = field(default_factory=list)
    tests_total: int = 0
    tests_failed: int = 0
    tests_skipped: int = 0          # RT14-17: counted in tests_total, never as a pass
    logs: List[str] = field(default_factory=list)
    timed_out: bool = False


def _venv_site_packages(venv_dir: str) -> List[str]:
    out = []
    for lib in ("lib", "lib64"):
        base = os.path.join(venv_dir, lib)
        try:
            names = sorted(os.listdir(base))
        except OSError:
            continue
        for n in names:
            sp = os.path.join(base, n, "site-packages")
            if n.startswith("python") and os.path.isdir(sp) and os.path.realpath(sp) not in map(os.path.realpath, out):
                out.append(sp)
    return out


def _is_dotted_identifier(value: str) -> bool:
    return bool(value) and all(part.isidentifier() for part in value.split("."))


# Procfile-only services (procfile-worker-build, RT F3 of FD-4AE-c): a service without `main.py` (e.g. a GKE
# `worker: python consumer.py`) gets the import smoke of the module its Procfile starts. Exact parse, no regex: the
# Procfile line rules are those of the pre-commit V3c `parse_procfile` and the server option tables are V3c's
# `VALUE_OPTIONS` (apps/orchestrator-gateway/developer_agent/validators/container.py; this container has no gateway
# package, so tests/test_procfile_worker_qa.py pins those). The launcher reading is this job's own: it also judges
# `python -m <mod>` and `-W`/`-X` value flags (V3c does not) and refuses a script in a subdirectory and
# --app-dir / --chdir / --pythonpath (V3c reads them). Converging the parsers into one replicated shared/procfile.py
# is a follow-up (procfile-worker RT F3). A command this cannot read exactly is not judged: no smoke.
# Like the `main.py` guard, only a module the service ships is smoked (Gate B S3: a VM bastion's stale
# `web: uvicorn main:app` Procfile without main.py is not turned into a QA failure).
MAX_PROCFILE_BYTES = 64 * 1024
PROCFILE_PYTHONS = frozenset({"python", "python3"})
PROCFILE_PYTHON_VALUE_FLAGS = frozenset({"-W", "-X"})      # interpreter flags that take a separate value
PROCFILE_SERVERS: Dict[str, frozenset] = {                # = container.VALUE_OPTIONS (options with a separate value)
    "uvicorn": frozenset({"--host", "--port", "--uds", "--fd", "--workers", "--loop", "--http", "--ws", "--lifespan",
                          "--interface", "--env-file", "--log-config", "--log-level", "--root-path",
                          "--limit-concurrency", "--backlog", "--limit-max-requests", "--timeout-keep-alive",
                          "--timeout-graceful-shutdown", "--ssl-keyfile", "--ssl-certfile", "--ssl-keyfile-password",
                          "--ssl-version", "--ssl-cert-reqs", "--ssl-ca-certs", "--ssl-ciphers", "--app-dir",
                          "--reload-dir", "--reload-include", "--reload-exclude", "--reload-delay",
                          "--forwarded-allow-ips", "--header", "--h11-max-incomplete-event-size",
                          "--ws-max-size", "--ws-max-queue", "--ws-ping-interval", "--ws-ping-timeout"}),
    "gunicorn": frozenset({"-b", "--bind", "-w", "--workers", "-k", "--worker-class", "-t", "--timeout", "-c",
                           "--config", "--threads", "--chdir", "--log-level", "--access-logfile", "--error-logfile",
                           "--graceful-timeout", "--keep-alive", "--max-requests", "--max-requests-jitter", "-n",
                           "--name", "--pythonpath", "-e", "--env", "--worker-connections", "--backlog", "-u", "-g",
                           "--user", "--group", "--forwarded-allow-ips", "--limit-request-line"}),
    "hypercorn": frozenset({"-b", "--bind", "-w", "--workers", "-k", "--worker-class", "-c", "--config",
                            "--root-path", "--log-level", "--access-logfile", "--error-logfile", "--keep-alive",
                            "--graceful-timeout", "--backlog", "--certfile", "--keyfile"}),
}
PROCFILE_IMPORT_ROOT_OPTIONS = frozenset({"--app-dir", "--chdir", "--pythonpath"})   # move the import root: not judged
# The import smoke of both shapes (`main`, or a Procfile's module). The module name arrives on argv, never inside the
# code string: `importlib.import_module(sys.argv[1])`, which was the whole Procfile smoke (IMPORT_BY_ARGV; `main` used
# `import main`) before QA-REPAIR-MISSING-MODULE added one typed fact. When the import raises, the first
# ModuleNotFoundError on the exception's chain (its explicit cause, else its implicit context, the order a traceback
# prints them; at most 32 links) has its `name` attribute, the module
# Python could not find, written to the path in argv[2]; then the exception is re-raised unchanged (same traceback,
# same exit status). This is the exception's own attribute, never read from the traceback text. The code under test
# runs in this process and could write the file itself, so the job reads it as untrusted (missing_module_fact: a
# regular file, size-capped, exact module-name shape) and the gateway maps it only through its closed catalog.
# RT F1 (Do No Harm): the imported module sees exactly the argv of the old smoke. The program reads argv[1:3] and then
# sets `sys.argv[1:] = argv[3:]`: the caller passes the old smoke's own arguments after the two
# (import_smoke_argv: none for `main`, whose old smoke was `python -c "import main"` -> ['-c']; the module for a
# Procfile module, whose old smoke was IMPORT_BY_ARGV -> ['-c', module]).
IMPORT_SMOKE_BY_ARGV = (
    "import importlib, sys\n"
    "_module, _fact = sys.argv[1], sys.argv[2]\n"
    "sys.argv[1:] = sys.argv[3:]\n"
    "def _missing(exc):\n"
    "    e, n = exc, 0\n"
    "    while e is not None and n < 32:\n"
    "        if isinstance(e, ModuleNotFoundError) and isinstance(e.name, str):\n"
    "            return e.name\n"
    "        e, n = (e.__cause__ if e.__cause__ is not None else None if e.__suppress_context__ else e.__context__), n + 1\n"
    "    return None\n"
    "try:\n"
    "    importlib.import_module(_module)\n"
    "except BaseException as exc:\n"
    "    name = _missing(exc)\n"
    "    if name is not None:\n"
    "        try:\n"
    "            with open(_fact, 'x', encoding='utf-8') as f:\n"
    "                f.write(name)\n"
    "        except Exception:\n"
    "            pass\n"
    "    raise\n"
)
MAX_MODULE_NAME_CHARS = 200   # parity: qa_job_client.MAX_MODULE_NAME_CHARS, qa_repair.MAX_MODULE_NAME_CHARS


def import_smoke_argv(python: str, module: str, fact: str, *, procfile: bool) -> List[str]:
    """RT F1: the import smoke's command. After the module and the fact path come the arguments the old smoke gave
    the imported module (IMPORT_SMOKE_BY_ARGV restores them as argv[1:]): none for `main` (`python -c "import main"`),
    the module for a Procfile module (IMPORT_BY_ARGV: `python -c ... <module>`)."""
    return [python, "-c", IMPORT_SMOKE_BY_ARGV, module, fact, *([module] if procfile else [])]


def is_module_name(value: Any) -> bool:
    """A dotted Python module name: ASCII identifiers joined by dots, at most MAX_MODULE_NAME_CHARS characters.
    Parity: qa_job_client.is_module_name and qa_repair.is_module_name (tests/test_qa_repair_missing_module.py)."""
    return (isinstance(value, str) and 0 < len(value) <= MAX_MODULE_NAME_CHARS and value.isascii()
            and all(part.isidentifier() for part in value.split(".")))


# Why a fact file was not used (read_missing_module_fact; RT F3 of QA-REPAIR-MISSING-MODULE-SETUP). No file at all is
# the normal case (no missing module) and has no reason.
FACT_NOT_REGULAR = "not a regular file (a symlink, FIFO, directory or other special file)"
FACT_UNREADABLE = "unreadable"
FACT_TOO_LARGE = "larger than the module-name cap"
FACT_NOT_UTF8 = "not UTF-8"
FACT_NOT_MODULE_NAME = "not a module name"


def read_missing_module_fact(path: str) -> Tuple[Optional[str], Optional[str]]:
    """(module name, None) for a valid fact at `path`; (None, None) when there is no file; (None, reason) when a file
    exists but fails the read rules: not a regular file (never followed through a symlink, never blocked on a FIFO),
    unreadable, larger than the cap, not UTF-8, or not exactly a module name. The reason is one of the FACT_*
    constants, never the file's content. Never raises."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except FileNotFoundError:
        return None, None
    except OSError:
        # ELOOP (a symlink under O_NOFOLLOW) or ENXIO and friends (special files): not a file the job reads
        return None, (FACT_NOT_REGULAR if os.path.lexists(path) else FACT_UNREADABLE)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None, FACT_NOT_REGULAR
        raw = os.read(fd, MAX_MODULE_NAME_CHARS + 1)
    except OSError:
        return None, FACT_UNREADABLE
    finally:
        os.close(fd)
    if len(raw) > MAX_MODULE_NAME_CHARS:
        return None, FACT_TOO_LARGE
    try:
        name = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, FACT_NOT_UTF8
    return (name, None) if is_module_name(name) else (None, FACT_NOT_MODULE_NAME)


def missing_module_fact(path: str) -> Optional[str]:
    """The module name the import smoke (IMPORT_SMOKE_BY_ARGV) or the pytest plugin wrote to `path`, or None
    (read_missing_module_fact's rules). Never raises."""
    return read_missing_module_fact(path)[0]


def missing_module_fact_logged(path: str, svc_rel: str, what: str, res: "DynamicResult") -> Optional[str]:
    """RT F3: missing_module_fact, plus one report-log line (and a job-log warning) naming the reason when a fact file
    exists but was dropped. Never the file's content."""
    name, reason = read_missing_module_fact(path)
    if reason is not None:
        note = f"== {svc_rel}: note: the {what} missing-module fact was dropped ({reason})"
        res.logs.append(note)
        logger.warning(note)
    return name


# install_missing_module_plugin's outcomes (RT F2: a skip for an installed entry is logged; switched off is not)
PLUGIN_INSTALLED = "installed"
PLUGIN_OFF = "off"
PLUGIN_SHADOWED_BY_REQUIREMENT = "shadowed_by_requirement"


def install_missing_module_plugin(venv_dir: str, tc: Toolchain) -> str:
    """QA-REPAIR-MISSING-MODULE-SETUP: copy the platform's plugin file (Toolchain.missing_module_plugin) into the venv's
    site-packages as `<MISSING_MODULE_PLUGIN>.py`. Trusted, after pip and before any untrusted code runs in the venv.
    PLUGIN_INSTALLED; PLUGIN_OFF when switched off; PLUGIN_SHADOWED_BY_REQUIREMENT (not loaded: today's run) when an
    installed requirement already has an entry of that name (create-only, never followed through a symlink). Any
    other failure is the platform's: RunnerError."""
    if tc.missing_module_plugin is None:
        return PLUGIN_OFF
    site = _venv_site_packages(venv_dir)
    if not site:
        raise RunnerError("the QA venv has no site-packages directory for the missing-module plugin")
    try:
        with open(tc.missing_module_plugin, "rb") as f:
            data = f.read()
        if _names_module(os.listdir(site[0]), MISSING_MODULE_PLUGIN):
            return PLUGIN_SHADOWED_BY_REQUIREMENT
        fd = os.open(os.path.join(site[0], f"{MISSING_MODULE_PLUGIN}.py"),
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    except FileExistsError:
        return PLUGIN_SHADOWED_BY_REQUIREMENT
    except OSError as e:
        raise RunnerError(f"the missing-module plugin could not be installed in the QA venv ({type(e).__name__})")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except OSError as e:
        raise RunnerError(f"the missing-module plugin could not be written to the QA venv ({type(e).__name__})")
    return PLUGIN_INSTALLED


def _names_module(entries: Iterable[str], module: str) -> bool:
    """True when a directory listing has an entry Python could import as top-level `module` (`module`, a package
    directory, or `module.<suffix>`: a source, bytecode or extension module file)."""
    return any(e == module or e.startswith(f"{module}.") for e in entries)


def missing_module_plugin_env(svc_dir: str) -> Dict[str, str]:
    """QA-REPAIR-MISSING-MODULE-SETUP: the pytest step's extra environment that loads the installed plugin
    ({PYTEST_PLUGINS: <module>}), or {} when the service directory (the first entries of sys.path for
    `python -m pytest` there) has an entry of that module name, which pytest would import instead of the platform's
    file. Read right before pytest runs, after the import smoke."""
    try:
        entries = os.listdir(svc_dir)
    except OSError:
        return {}
    return {} if _names_module(entries, MISSING_MODULE_PLUGIN) else {PYTEST_PLUGINS_ENV: MISSING_MODULE_PLUGIN}


def procfile_processes(text: str) -> Dict[str, str]:
    """{process: command}: `<name>: <command>` lines, blank and `#` lines skipped (= container.parse_procfile)."""
    procs: Dict[str, str] = {}
    for raw in text.split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, sep, cmd = line.partition(":")
        if not sep or not name.strip() or not cmd.strip() or " " in name.strip():
            continue
        procs.setdefault(name.strip(), cmd.strip())
    return procs


def _server_entry_module(server: str, args: Sequence[str]) -> Optional[str]:
    value_opts = PROCFILE_SERVERS[server]
    target: Optional[str] = None
    i = 0
    while i < len(args):
        tok = args[i]
        if tok.startswith("-"):
            opt, eq, _ = tok.partition("=")
            if opt in PROCFILE_IMPORT_ROOT_OPTIONS:
                return None
            if not eq and opt in value_opts:
                i += 1
        elif target is None:
            target = tok
        i += 1
    if target is None:
        return None
    module = target.partition(":")[0]
    return module if _is_dotted_identifier(module) else None


def procfile_entry_module(command: str) -> Optional[str]:
    """The module a Procfile command starts: `python[3] <file>.py` (a file in the service dir) -> `<file>`,
    `python[3] -m <mod>` -> `<mod>`, `uvicorn|gunicorn|hypercorn <mod>[:<app>]` (also via `python -m`) -> `<mod>`;
    None for anything else (not judged)."""
    try:
        argv = shlex.split(command)
    except ValueError:
        return None
    if not argv:
        return None
    head = posixpath.basename(argv[0])
    if head in PROCFILE_SERVERS:
        return _server_entry_module(head, argv[1:])
    if head not in PROCFILE_PYTHONS:
        return None
    rest = list(argv[1:])
    while rest and rest[0].startswith("-") and rest[0] != "-m":
        if rest[0] == "-c":
            return None
        rest = rest[2:] if rest[0] in PROCFILE_PYTHON_VALUE_FLAGS else rest[1:]
    if len(rest) >= 2 and rest[0] == "-m":
        if rest[1] in PROCFILE_SERVERS:
            return _server_entry_module(rest[1], rest[2:])
        return rest[1] if _is_dotted_identifier(rest[1]) else None
    if rest and rest[0].endswith(".py"):
        stem = rest[0][:-len(".py")]
        return stem if stem.isidentifier() else None
    return None


def _module_source_exists(svc_dir: str, module: str) -> bool:
    """`<mod>.py` or `<mod>/__init__.py` under the service dir (the parallel of the `main.py` guard: QA smokes an
    entry module the service ships). A Procfile naming a missing module gets no check here; today nothing catches it
    before runtime when a sibling has a main.py (V3c skips such a worker: follow-up PWB-3)."""
    base = os.path.join(svc_dir, *module.split("."))
    return os.path.isfile(base + ".py") or os.path.isfile(os.path.join(base, "__init__.py"))


def procfile_entry_modules(svc_dir: str) -> List[str]:
    """The distinct entry modules of `<svc_dir>/Procfile` that the service ships, in Procfile order ([] without a
    readable Procfile)."""
    path = os.path.join(svc_dir, "Procfile")
    if os.path.islink(path) or not os.path.isfile(path):
        return []
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_PROCFILE_BYTES + 1)
        if len(raw) > MAX_PROCFILE_BYTES:
            return []
        text = raw.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return []
    out: List[str] = []
    for command in procfile_processes(text).values():
        module = procfile_entry_module(command)
        if module is not None and module not in out and _module_source_exists(svc_dir, module):
            out.append(module)
    return out


def pytest_plugin_args(venv_dir: str, tc: Toolchain) -> List[str]:
    """Row L3-PRB-f: with PYTEST_DISABLE_PLUGIN_AUTOLOAD=1, `-p <module>` for each `[pytest11]` entry point of an
    allow-listed distribution installed in the venv (read from the installed `entry_points.txt` metadata by the job:
    nothing is imported or executed). Every Toolchain.required_pytest_plugin_dists must be present, else
    RunnerError (the platform's toolchain is broken; never charged to the workload).
    REQUIREMENTS-ASYNC-TEST-PLUGIN: when the pytest-asyncio distribution's plugin is loaded, also
    `-o asyncio_mode=auto` (ASYNCIO_AUTO_MODE_ARGS): the runner's own `-c` ini ignores the workload's pytest config, and
    pytest-asyncio's default strict mode fails every unmarked `async def` test. Decided by the installed distribution
    only; without it the arguments are exactly as before."""
    found = installed_pytest_plugins(venv_dir, tc)
    args: List[str] = []
    for dist in sorted(found):
        for module in found[dist]:
            args += ["-p", module]
    if canonicalize_name(ASYNCIO_PLUGIN_DIST) in found:
        args += list(ASYNCIO_AUTO_MODE_ARGS)
    return args


# REQUIREMENTS-ASYNC-TEST-PLUGIN: the async test plugin whose presence selects pytest-asyncio's auto mode
ASYNCIO_PLUGIN_DIST = "pytest-asyncio"
ASYNCIO_AUTO_MODE_ARGS = ("-o", "asyncio_mode=auto")


def installed_pytest_plugins(venv_dir: str, tc: Toolchain) -> Dict[str, List[str]]:
    """{canonical distribution: [plugin module, ...]} of the allow-listed pytest plugins installed in the venv
    (pytest_plugin_args' facts, Row L3-PRB-f). Raises RunnerError when a required plugin is missing."""
    import configparser

    allowed = {canonicalize_name(d) for d in (*OPTIONAL_PYTEST_PLUGIN_DISTS, *tc.required_pytest_plugin_dists)}
    found: Dict[str, List[str]] = {}
    for sp in _venv_site_packages(venv_dir):
        for entry in sorted(os.listdir(sp)):
            if not entry.endswith(".dist-info"):
                continue
            dist = canonicalize_name(entry[: -len(".dist-info")].split("-", 1)[0])
            if dist not in allowed:
                continue
            cp = configparser.ConfigParser(interpolation=None, delimiters=("=",))
            cp.optionxform = str  # type: ignore[assignment]
            try:
                with open(os.path.join(sp, entry, "entry_points.txt"), "r", encoding="utf-8") as f:
                    cp.read_file(f)
            except (OSError, configparser.Error, UnicodeDecodeError):
                continue
            if cp.has_section("pytest11"):
                for _, value in sorted(cp.items("pytest11")):
                    module = value.strip()
                    if _is_dotted_identifier(module):  # `module:attr` values are not plugins pytest can `-p`
                        found.setdefault(dist, []).append(module)
    missing = [d for d in tc.required_pytest_plugin_dists if canonicalize_name(d) not in found]
    if missing:
        raise RunnerError(f"the pinned pytest plugin(s) {', '.join(missing)} are not installed in the QA venv")
    return found


def run_service(svc: Service, tc: Toolchain, work: Workdir, runner: Runner, res: DynamicResult,
                index_token_source: Optional[Callable[[str], str]] = None) -> None:
    svc_dir = os.path.join(work.src, svc.rel)
    # Fresh, unpredictable directories per service, created after every earlier untrusted step was swept: code that
    # ran for an earlier service cannot pre-plant this venv (a .pth would run inside the trusted pip), its junit, or
    # a local archive that pip would resolve a bare requirement name against (pip's cwd is an empty directory).
    svc_work = tempfile.mkdtemp(prefix="svc-", dir=work.root)
    venv_dir = os.path.join(svc_work, "venv")
    pip_cwd = os.path.join(svc_work, "pip-cwd")
    os.makedirs(pip_cwd, mode=0o700)
    log = lambda step: os.path.join(svc_work, f"{step}.log")  # noqa: E731

    # 1. Fresh venv, no system site-packages, no pip inside it (trusted).
    r = runner.run([tc.python, "-m", "venv", "--without-pip", venv_dir], env=_tool_env(work), cwd=work.tmp,
                   untrusted=False, what="venv", log_path=log("venv"))
    if r.returncode != 0:
        raise RunnerError(f"venv creation failed for {svc.rel}")
    venv_python = os.path.join(venv_dir, "bin", "python")
    venv_bin = os.path.dirname(venv_python)

    # 2. Trusted pip, wheels only, the runner's exact pins as constraints. Requirements arrive as validated PEP 508
    #    name strings on argv (never `-r`: red-team F1), so no path, URL, editable or pip option from the tree exists
    #    and no build backend can run. 2a. The platform's test toolchain first: if THAT cannot install, the platform
    #    is broken (exit 11), not the workload. 2b. The workload's requirements, constrained by the same pins, minus
    #    any requirement for a package the toolchain pins (row QA-TOOLCHAIN-PINS: the toolchain's version is used and
    #    a note is logged; the committed requirements.txt and the deployed app are untouched). Row QA-PYTEST-CRASH: a
    #    dropped pinned package that 2a does not install (a pytest plugin) is installed in 2b at the toolchain's pin.
    pins = toolchain_pins(tc.constraints)
    requirements, toolchain_dropped = split_toolchain_pinned(svc.requirements, pins)
    requirements += toolchain_replacements(svc.requirements, pins, tc.test_packages)   # row QA-PYTEST-CRASH
    for workload_req, pin in toolchain_dropped:
        note = (f"== {svc.rel}: note: QA used the toolchain's {pin} instead of the workload's {workload_req} "
                f"({svc.rel}/requirements.txt and the deployed app are unchanged)")
        res.logs.append(note)
        logger.info(note)
    pip = [tc.python, "-m", "pip", "--python", venv_python, "install", "--isolated", "--no-input",
           "--disable-pip-version-check", "--no-color", "--only-binary=:all:", "--index-url", tc.index_url,
           "--timeout", str(tc.pip_timeout_s), "--retries", str(tc.pip_retries), "-c", tc.constraints]
    pip_env = _tool_env(work, {"PIP_CONFIG_FILE": os.devnull})
    # Row L3-PRB-g: the index credential exists only while the trusted pip steps run (no untrusted step overlaps:
    # every earlier untrusted step was swept), in this service's fresh directory, never in the untrusted $HOME.
    # FD-4BR RT F3: a fresh token per service, fetched right before its netrc (the task may run 900 s; a token
    # fetched once at the static phase could expire before a later service's pip).
    netrc_path: Optional[str] = None
    if index_token_source is not None:
        netrc_path = write_index_netrc(svc_work, tc.index_url, index_token_source(svc.rel))
        pip_env["NETRC"] = netrc_path
    try:
        r = runner.run([*pip, *tc.test_packages], env=pip_env, cwd=pip_cwd, untrusted=False,
                       what="pip install (test toolchain)", log_path=log("pip-toolchain"))
        if r.returncode != 0:
            raise RunnerError(f"the pinned test toolchain could not be installed (pip exit {r.returncode})")
        if requirements:
            r = runner.run([*pip, *requirements], env=pip_env, cwd=pip_cwd, untrusted=False, what="pip install",
                           log_path=log("pip"))
            res.logs.append(f"== {svc.rel}: pip install (exit {r.returncode})\n{r.output[-4000:]}")
            if r.returncode != 0:
                res.diagnostics.append(diag(
                    "pip", "REQ.UNRESOLVABLE",
                    f"pip could not install {svc.rel}/requirements.txt with the QA toolchain (no matching wheel or "
                    "version, or a conflict with the pinned test toolchain)", file=f"{svc.rel}/requirements.txt",
                    detail=r.output[-MAX_FIELD_CHARS:]))
                return
    finally:
        if netrc_path is not None:
            remove_index_netrc(netrc_path)
    # Read before any untrusted code runs in this venv (the import smoke could otherwise edit the metadata).
    plugin_args = pytest_plugin_args(venv_dir, tc)
    fact_plugin = install_missing_module_plugin(venv_dir, tc)   # QA-REPAIR-MISSING-MODULE-SETUP

    env = _untrusted_env(work, venv_bin, svc_dir)
    # 3. Import smoke (D14): the real interpreter imports the service entry module. Untrusted.
    # QA-REPAIR-MISSING-MODULE: each smoke gets a fresh fact path in this service's own directory (missing_module_fact)
    if os.path.isfile(os.path.join(svc_dir, "main.py")):
        fact = os.path.join(svc_work, "import-fact-main")
        r = runner.run(import_smoke_argv(venv_python, "main", fact, procfile=False), env=env, cwd=svc_dir,
                       untrusted=True, what=f"import smoke {svc.rel}", log_path=log("import"))
        res.logs.append(f"== {svc.rel}: import main (exit {r.returncode})\n{r.output[-4000:]}")
        if r.returncode != 0:
            res.diagnostics.append(diag("python", "PY.IMPORT_FAILED", f"`import main` failed for {svc.rel}",
                                        file=f"{svc.rel}/main.py", detail=r.output[-MAX_FIELD_CHARS:],
                                        missing_module=missing_module_fact_logged(fact, svc.rel, "import smoke", res)))
            return
    else:
        # Procfile-only service (no main.py, e.g. `worker: python consumer.py`): the same blocking smoke on the
        # module(s) its Procfile starts. Read by this trusted job from the tree re-verified before this service.
        for k, module in enumerate(procfile_entry_modules(svc_dir)):
            fact = os.path.join(svc_work, f"import-fact-{k}")
            r = runner.run(import_smoke_argv(venv_python, module, fact, procfile=True), env=env, cwd=svc_dir,
                           untrusted=True, what=f"import smoke {svc.rel}", log_path=log("import"))
            res.logs.append(f"== {svc.rel}: import {module} (exit {r.returncode})\n{r.output[-4000:]}")
            if r.returncode != 0:
                res.diagnostics.append(diag("python", "PY.IMPORT_FAILED", f"`import {module}` failed for {svc.rel}",
                                            file=f"{svc.rel}/Procfile", detail=r.output[-MAX_FIELD_CHARS:],
                                            missing_module=missing_module_fact_logged(fact, svc.rel, "import smoke",
                                                                                      res)))
                return

    # 4. pytest with the runner-owned ini (-c: the tree's pytest.ini / pyproject / setup.cfg addopts are ignored).
    if not svc.test_roots:
        return
    junit = os.path.join(svc_work, "junit.xml")
    argv = [venv_python, "-m", "pytest", "-c", tc.pytest_ini, "--rootdir", work.src, "--confcutdir", work.src,
            "--junitxml", junit, "-q", *plugin_args, *tc.pytest_extra_args,
            *[os.path.join(work.src, t) for t in svc.test_roots]]
    # QA-REPAIR-MISSING-MODULE-SETUP: the platform's plugin rides on the environment only (argv is unchanged)
    plugin_env = missing_module_plugin_env(svc_dir) if fact_plugin == PLUGIN_INSTALLED else {}
    not_loaded = ("the service directory has" if fact_plugin == PLUGIN_INSTALLED and not plugin_env else
                  "an installed requirement ships" if fact_plugin == PLUGIN_SHADOWED_BY_REQUIREMENT else None)
    if not_loaded is not None:   # RT F2: both skips are logged (fail-loudly policy section 2); switched off is not
        note = (f"== {svc.rel}: note: the missing-module plugin was not loaded ({not_loaded} an entry named "
                f"{MISSING_MODULE_PLUGIN})")
        res.logs.append(note)
        logger.warning(note)
    r = runner.run(argv, env=dict(env, **plugin_env), cwd=svc_dir, untrusted=True, what=f"pytest {svc.rel}",
                   log_path=log("pytest"))
    res.logs.append(f"== {svc.rel}: pytest (exit {r.returncode})\n{r.output}")
    if r.returncode == 5:
        res.diagnostics.append(diag("pytest", "PY.NO_TESTS", f"pytest collected no tests for {svc.rel}",
                                    file=svc.test_roots[0]))
        return
    try:
        total, failed, cases, internal = parse_junit(
            junit, missing_module_fact_logged(junit + MISSING_MODULE_FACT_SUFFIX, svc.rel, "pytest", res)
            if plugin_env else None)
    except (OSError, ValueError, ET.ParseError) as e:
        message = f"pytest exited {r.returncode} without a readable junit report ({type(e).__name__})"
        if r.returncode > 0 and not os.path.lexists(junit):
            # QA-START-MSG: pytest stopped before it wrote a junit report (exit 2/3/4: usage error, conftest import
            # error, internal error), so its own first error block leads the message. Selected by exit code and
            # junit absence only; the output is quoted as written (redacted), never interpreted.
            first = first_output_block(runner.redact(_head_file(log("pytest"), 4 * MAX_FIELD_CHARS)),
                                       MAX_FIELD_CHARS - 256)
            if first:
                message = (f"{first}\n(pytest stopped before writing a junit report for {svc.rel}: exit {r.returncode}; "
                           "full output in detail)")
        if r.returncode in PYTEST_STOPPED_EXIT_CODES and not os.path.lexists(junit):
            # Row QA-PYTEST-CRASH: pytest stopped at startup (usage error, conftest import error, internal error)
            # before it wrote any junit: typed by exit code and junit absence; scoped to the service.
            res.diagnostics.append(diag("pytest", PYTEST_STARTUP_ERROR_CODE, message,
                                        file=service_scope_file(svc.rel), detail=r.output[-MAX_FIELD_CHARS:]))
        else:
            res.diagnostics.append(diag("pytest", "PYTEST.REPORT_INVALID", message,
                                        detail=r.output[-MAX_FIELD_CHARS:]))
        return
    try:
        skips = junit_skips(junit)
    except (OSError, ValueError, ET.ParseError) as e:   # the same file parse_junit just read: not expected
        res.diagnostics.append(diag("pytest", "PYTEST.REPORT_INVALID",
                                    f"the junit report of {svc.rel} could not be re-read ({type(e).__name__})"))
        return
    res.tests_total += total
    res.tests_failed += failed
    res.tests_skipped += len(skips)
    res.diagnostics.extend(cases)
    if internal or r.returncode == PYTEST_EXIT_INTERNAL_ERROR:
        # Row QA-PYTEST-CRASH: pytest itself crashed (exit 3 / the junit's synthetic internal-error case, typed by
        # exit code and junit structure): its own crash output, not "pytest.internal: internal error" without it.
        res.diagnostics.append(pytest_crash_diag(PYTEST_INTERNAL_ERROR_CODE, svc.rel, r.returncode, log("pytest"),
                                                 runner.redact, internal[0] if internal else None, r.output))
        return
    if r.returncode == 0 and failed == 0:
        if total == 0:
            res.diagnostics.append(diag("pytest", "PY.NO_TESTS", f"pytest ran no tests for {svc.rel}"))
        elif len(skips) == total:
            # RT14-17: every test of the service was skipped (or xfail): nothing was verified, so it is not a pass.
            more = f"\n... and {len(skips) - MAX_SKIP_REASONS} more" if len(skips) > MAX_SKIP_REASONS else ""
            res.diagnostics.append(diag(
                "pytest", ALL_TESTS_SKIPPED_CODE, f"all {total} test(s) of {svc.rel} were skipped; none ran to a verdict",
                file=svc.test_roots[0], detail="\n".join(skips[:MAX_SKIP_REASONS]) + more))
        return
    if r.returncode == 0:
        res.diagnostics.append(diag("pytest", "PYTEST.REPORT_INVALID",
                                    f"pytest exited 0 but its report lists {failed} failure(s) for {svc.rel}"))
    elif not cases and r.returncode in (PYTEST_EXIT_INTERRUPTED, PYTEST_EXIT_USAGE_ERROR):
        # Row QA-PYTEST-CRASH: pytest stopped (interrupted / usage error) after writing a junit that lists no failing
        # test: its own first error block leads the message (typed by exit code and junit content only).
        res.diagnostics.append(pytest_crash_diag(PYTEST_SESSION_ERROR_CODE, svc.rel, r.returncode, log("pytest"),
                                                 runner.redact, None, r.output))
    elif not cases:
        res.diagnostics.append(diag("pytest", "PY.TEST_FAILED", f"pytest exited {r.returncode} for {svc.rel}",
                                    detail=r.output[-MAX_FIELD_CHARS:]))


# ------------------------------------------------------------------------------------------------------------------
# The job
# ------------------------------------------------------------------------------------------------------------------
def _list_files(src: str) -> List[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames.sort()
        for fn in sorted(filenames):
            out.append(os.path.relpath(os.path.join(dirpath, fn), src).replace(os.sep, "/"))
    return out


def run_job(environ: Optional[Dict[str, str]] = None, *, toolchain: Optional[Toolchain] = None,
            transport: Optional[HttpTransport] = None, clock: Callable[[], float] = time.monotonic) -> int:
    """One QA run. Returns the exit code; raises nothing the caller must handle except BaseException (main())."""
    environ = os.environ if environ is None else environ
    tc = toolchain or Toolchain()
    # 0. Non-dumpable before anything else (red-team F4): no same-uid process can read our environ/fds or ptrace us.
    if tc.harden_process:
        try:
            harden_process()
        except RunnerError as e:
            logger.error(f"QA job hardening failed: {e}")
            return EXIT_RUNNER_ERROR
    net = transport or HttpTransport()
    redact = Redactor()
    start = clock()
    task_deadline = start + TASK_TIMEOUT_S - TASK_BUDGET_MARGIN_S
    sweep = sweep_uid_processes if tc.sweep_uid_processes else None
    work = Workdir()
    try:
        # 1. Toolchain self-check, before any input is read.
        runner = Runner(start + TOOLCHAIN_CHECK_TIMEOUT_S * 2, redact, clock, tc.apply_rlimits, sweep)
        try:
            versions = toolchain_self_check(tc, work, runner)
        except (RunnerError, DeadlineExpired) as e:
            logger.error(f"QA toolchain unavailable: {e}")
            return EXIT_RUNNER_ERROR
        # 2. Inputs, read once and removed from the environment.
        try:
            inputs = JobInputs.from_environ(environ)
        except RunnerError as e:
            logger.error(f"QA job inputs invalid: {e}")
            return EXIT_RUNNER_ERROR
        for u in (inputs.source_url, inputs.static_put_url, inputs.report_put_url):
            redact.add(u)
        runner = Runner(start + inputs.deadline_s, redact, clock, tc.apply_rlimits, sweep)
        logger.info(f"QA run trace={inputs.trace_id} product={inputs.product_id!r} commit={inputs.commit_sha}")
        return _run(inputs, tc, net, work, runner, versions, redact, task_deadline)
    except RunnerError as e:
        logger.error(f"QA runner error: {redact(e)}")
        return EXIT_RUNNER_ERROR
    except DeadlineExpired as e:  # only reachable outside untrusted code (handled inside _run otherwise)
        logger.error(f"QA deadline expired outside untrusted code: {e.what}")
        return EXIT_RUNNER_ERROR
    finally:
        work.cleanup()


def _run(inputs: JobInputs, tc: Toolchain, net: HttpTransport, work: Workdir, runner: Runner,
         versions: Dict[str, str], redact: Redactor, task_deadline: Optional[float] = None) -> int:
    # 3. Download + verify + extract.
    archive = net.get(inputs.source_url, MAX_SOURCE_DOWNLOAD_BYTES, deadline=task_deadline)
    if runner.remaining() <= 0:
        raise DeadlineExpired("download", untrusted=False)
    extract_source(archive, inputs.source_sha256, work.src)
    del archive
    files = _list_files(work.src)
    baseline = hash_tree(work.src, files)

    # 4. Static phase: nothing from the tree has executed yet, so static.json is authentic.
    py_files = [f for f in files if f.endswith(".py")]
    trees, diags = check_syntax(work.src, py_files)
    diags += check_zero_dockerfile(files)
    layout = discover_layout(files)
    diags += layout.diagnostics
    diags += check_requirements(work.src, layout.services)
    diags += check_pytest_hooks(trees, layout.services)
    diags += check_auth_structure(trees)
    diags += run_bandit(tc, work, runner)
    if runner.remaining() <= 0:
        raise DeadlineExpired("static checks", untrusted=False)
    toolchain = dict(versions)
    mismatch = _python_version_mismatches(work.src, layout.services)
    if mismatch:
        toolchain["python_version_mismatch"] = mismatch
    static_passed = not _errors(diags)
    index_token: Optional[str] = None
    if static_passed and tc.index_auth_metadata:
        # Row L3-PRB-g: Artifact Registry needs the job SA's token; no token = the index is unreachable (exit 11).
        try:
            index_token = fetch_index_token(net, tc.metadata_token_url, task_deadline)
        except RunnerError as e:
            logger.error(f"package index credential unavailable: {e}")
        if index_token is not None:
            _register_index_token(redact, index_token)
            index_reachable = net.probe(tc.index_probe_url(), deadline=task_deadline,
                                        headers=index_auth_headers(index_token))
        else:
            index_reachable = False
    else:
        index_reachable = net.probe(tc.index_probe_url(), deadline=task_deadline) if static_passed else None
    static = {
        "schema_version": 1, "nonce": inputs.nonce, "passed": static_passed, "diagnostics": diags,
        "diagnostics_truncated": False, "index_reachable": index_reachable, "toolchain": toolchain,
    }
    net.put_create_only(inputs.static_put_url, fit_artifact(static, redact), "static.json", deadline=task_deadline)
    logger.info(f"static phase: passed={static_passed} diagnostics={len(diags)} index_reachable={index_reachable}")
    if not static_passed:
        return EXIT_CODE_DEFECT
    if index_reachable is not True:
        logger.error("package index unreachable: dependency install would be unclassifiable (red-team F2)")
        return EXIT_RUNNER_ERROR

    # 5-6. Dynamic phase per service, one shared deadline.
    res = DynamicResult()
    try:
        for svc in layout.services:
            modified = check_tree_unchanged(work.src, baseline)  # red-team F5: earlier steps' code changed the tree
            if modified:
                res.diagnostics.extend(modified)
                break
            if index_token is None:
                run_service(svc, tc, work, runner, res)
            else:
                run_service(svc, tc, work, runner, res,
                            index_token_source=_index_token_source(net, tc, redact, task_deadline))
    except DeadlineExpired as e:
        if not e.untrusted:
            raise
        res.timed_out = True
        res.diagnostics.append(diag("pytest", "PY.TEST_TIMEOUT",
                                    f"the QA deadline ({inputs.deadline_s}s) expired during {e.what}"))
    errors = _errors(res.diagnostics)
    # RT14-17: a pass needs at least one test that ran to a verdict (skipped / xfail tests are not passes)
    passed = not res.timed_out and not errors and res.tests_total - res.tests_skipped > 0
    if not passed and not errors:
        res.diagnostics.append(diag("pytest", "PY.NO_TESTS", "no test ran"))
    report = {
        "schema_version": 1, "nonce": inputs.nonce, "passed": passed, "diagnostics": res.diagnostics,
        "diagnostics_truncated": False, "tests_total": res.tests_total, "tests_failed": res.tests_failed,
        "tests_skipped": res.tests_skipped,
        "logs_tail": redact("\n".join(res.logs))[-LOGS_TAIL_CHARS:],
    }
    # 7. report.json (create-only).
    net.put_create_only(inputs.report_put_url, fit_artifact(report, redact), "report.json", deadline=task_deadline)
    logger.info(f"dynamic phase: passed={passed} tests={res.tests_total} failed={res.tests_failed} "
                f"skipped={res.tests_skipped} timed_out={res.timed_out}")
    if res.timed_out:
        return EXIT_TIMEOUT_DEFECT
    return EXIT_PASS if passed else EXIT_CODE_DEFECT


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Any BaseException (incl. SystemExit / KeyboardInterrupt) is a runner error: exit 11, nothing more written.
    `argv` (default sys.argv[1:]): nothing, or `--index-url <url>` (row L3-PRB-g; toolchain_from_argv)."""
    try:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s",
                            stream=sys.stdout)
        release_info.log_release("qa-sandbox-test-runner")  # FD-7C P3a: one stackvend.release line per run
        try:
            tc = toolchain_from_argv(sys.argv[1:] if argv is None else argv)
        except RunnerError as e:
            logger.error(f"QA job arguments invalid: {e}")
            return EXIT_RUNNER_ERROR
        if tc is None:
            return run_job()
        return run_job(toolchain=tc)
    except BaseException as e:  # noqa: BLE001 - fail closed on everything (review H2)
        try:
            logger.error(f"QA job crashed: {type(e).__name__}")
        except BaseException:  # noqa: BLE001
            pass
        return EXIT_RUNNER_ERROR


if __name__ == "__main__":
    code = main()
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    finally:
        os._exit(code)
