"""
FD-4F (Option A): gateway-side client for the isolated `qa-sandbox-test-runner` Cloud Run job.

The gateway stages the commit-bound source tarball in GCS, hands the job only short-lived signed URLs, runs one
execution, and classifies the outcome from data the job cannot forge alone (review H2):
    execution counts + task exit code (read with the gateway's own credentials)
    AND static.json (written create-only BEFORE untrusted code runs)
    AND report.json (create-only, nonce-bound).

Job exit-code contract (apps/qa-runner/sandbox_job.py, PR-B):
    0  = pass
    10 = CODE_DEFECT     checks ran and the code failed them
    11 = RUNNER_ERROR    toolchain / download / sha / extract / PUT / deadline outside untrusted code / index unreachable
    12 = TIMEOUT_DEFECT  the job's own deadline expired while UNTRUSTED code was running
    anything else (1 = interpreter crash, 137 = OOM kill, signals) = GATE_UNAVAILABLE

The client is inert until QA_* config exists (set by Terraform at Stage A): `QAJobConfig.from_env()` returns None
and the gateway answers GATE_UNAVAILABLE. Nothing here reads TEST_MODE (D1); tests inject fakes.
"""

import hashlib
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Callable, Dict, List, Literal, Optional

from pydantic import (BaseModel, ConfigDict, StrictBool, StrictInt, ValidationError, field_validator, model_serializer,
                      model_validator)

from gate_errors import ErrorClass, GateUnavailableError
from shared.path_safety import validate_trace_id

logger = logging.getLogger("castor-qa-job-client")

RUN_API = "https://run.googleapis.com/v2"
MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_DIAGNOSTICS = 200
MAX_FIELD_CHARS = 2048
JOB_TASK_TIMEOUT_S = 900
JOB_INTERNAL_DEADLINE_S = 780
QUEUE_GRACE_S = 180
GET_URL_TTL_S = 20 * 60
PUT_URL_TTL_S = 25 * 60
IDENTITY_CACHE_S = 300
CREATE_ONLY_HEADERS = {"x-goog-if-generation-match": "0", "content-type": "application/json"}

EXIT_PASS, EXIT_CODE_DEFECT, EXIT_RUNNER_ERROR, EXIT_TIMEOUT_DEFECT = 0, 10, 11, 12

# Row L3-PRB-r: the PR-B job contract that pipeline-start readiness proves before any spend.
#   * the container args start with the job's entrypoint (= apps/qa-runner/Procfile) and end with the index
#     (`expected_job_args`, = infra/platform/qa_sandbox.tf `args`, row L3-PRB-g);
#   * the job carries JOB_CONTRACT_LABEL == JOB_CONTRACT_VERSION, set in the SAME `gcloud run jobs update/deploy` call
#     that ships the image (scripts/deploy-services.sh). The version equals
#     apps/qa-runner/sandbox_job.JOB_CONTRACT_VERSION (the gateway image does not contain the job; tests pin all four).
JOB_CONTRACT_VERSION = "1"
JOB_CONTRACT_LABEL = "stackvend-qa-job-contract"
JOB_CONTRACT_ARGS = ("python3", "-m", "sandbox_job")

# Row L3-PRB-g (FD-4BR, egress Phase 2): the job's egress contract, = infra/platform/qa_sandbox_egress.tf (network,
# Artifact Registry PyPI remote) + qa_sandbox.tf (vpc_access, args); tests pin both sides. The job must send ALL egress
# into the deny-all sandbox network, and its args must be the entrypoint + `--index-url <that remote>` (argv only:
# the template carries no env). Both verify_job_identity (dispatch, QA_JOB_DRIFT) and readiness (QA_JOB_NOT_READY)
# require it.
# Transition (RT F2, until C3b): the gateway accepts EXACTLY ONE of two complete shapes, so the egress apply flips the
# job in one Run API update with no readiness 503 window on either side:
#   legacy = args == JOB_CONTRACT_ARGS (exactly) AND no vpcAccess (absent or {}): the pre-Phase-2 job, unchanged;
#   egress = everything else, checked strictly (full args + ALL_TRAFFIC on the sandbox network, no connector).
# Any mix (new args without vpcAccess, vpcAccess with the legacy args, a partial vpcAccess, ...) is the egress shape
# with misses -> refused, typed. C3b (later, after both installs report egress_lockdown: true) deletes the legacy branch.
QA_SANDBOX_NETWORK = "castor-qa-sandbox"
QA_PYPI_REPOSITORY = "castor-pypi-remote"
JOB_VPC_EGRESS = "ALL_TRAFFIC"
JOB_INDEX_ARG = "--index-url"
JOB_SHAPE_LEGACY, JOB_SHAPE_EGRESS = "legacy", "egress"


def job_shape(job: Dict[str, Any]) -> str:
    """RT F2: 'legacy' only for exactly the L3-PRB-r job (args == entrypoint, no vpcAccess); otherwise 'egress'."""
    tmpl = job["template"]["template"]
    containers = tmpl.get("containers") or []
    args = containers[0].get("args") if len(containers) == 1 and isinstance(containers[0], dict) else None
    if args == list(JOB_CONTRACT_ARGS) and tmpl.get("vpcAccess") in (None, {}):
        return JOB_SHAPE_LEGACY
    return JOB_SHAPE_EGRESS


# Row HOST-VPC-EGRESS (internal-ingress plan §3.5): the host platform network that every other host service and job
# uses for Direct VPC egress (= infra/platform host_network.tf `google_compute_network.host`). The QA job runs
# untrusted generated code, so it must never join it: on that network it would be an internal source for every
# internal-only host service. Refused in both checks (QA_JOB_DRIFT), whatever the job's shape.
HOST_PLATFORM_NETWORK = "stackvend-host"


def network_name(value: Any) -> Optional[str]:
    """The network's name from a Run API `networkInterfaces[].network` value: the bare name, or the relative resource
    name `projects/<project>/global/networks/<name>` (any project spelling). Anything else -> None (not a name)."""
    if not isinstance(value, str) or not value:
        return None
    parts = value.split("/")
    if len(parts) == 1:
        return value
    if len(parts) == 5 and parts[0] == "projects" and parts[2:4] == ["global", "networks"] and parts[1] and parts[4]:
        return parts[4]
    return None


def host_network_interfaces(job: Dict[str, Any]) -> List[str]:
    """The task template's network values that name the host platform network (normally [])."""
    tmpl = job["template"]["template"]
    vpc = tmpl.get("vpcAccess") if isinstance(tmpl.get("vpcAccess"), dict) else {}
    nics = vpc.get("networkInterfaces") if isinstance(vpc.get("networkInterfaces"), list) else []
    return [n["network"] for n in nics
            if isinstance(n, dict) and network_name(n.get("network")) == HOST_PLATFORM_NETWORK]


def expected_index_url(config: "QAJobConfig") -> str:
    """The Artifact Registry PyPI remote's PEP 503 index (TF local.qa_pypi_index_url)."""
    return f"https://{config.region}-python.pkg.dev/{config.project_id}/{QA_PYPI_REPOSITORY}/simple/"


def expected_job_args(config: "QAJobConfig") -> List[str]:
    return [*JOB_CONTRACT_ARGS, JOB_INDEX_ARG, expected_index_url(config)]


def expected_networks(config: "QAJobConfig") -> List[str]:
    """The two spellings the Run API accepts for the same network (TF sets the resource id); nothing else."""
    return [f"projects/{config.project_id}/global/networks/{QA_SANDBOX_NETWORK}", QA_SANDBOX_NETWORK]


# ------------------------------------------------------------------------------
# Untrusted artifact schemas (the job's output is untrusted data; the gateway is the trust boundary)
# ------------------------------------------------------------------------------
def _cap(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    return value if len(value) <= MAX_FIELD_CHARS else value[:MAX_FIELD_CHARS] + "...[truncated]"


MAX_MODULE_NAME_CHARS = 200   # parity: apps/qa-runner/sandbox_job.MAX_MODULE_NAME_CHARS, qa_repair


def is_module_name(value: Any) -> bool:
    """A dotted Python module name: ASCII identifiers joined by dots, at most MAX_MODULE_NAME_CHARS characters
    (the QA job's rule, sandbox_job.is_module_name; parity: tests/test_qa_repair_missing_module.py)."""
    return (isinstance(value, str) and 0 < len(value) <= MAX_MODULE_NAME_CHARS and value.isascii()
            and all(part.isidentifier() for part in value.split(".")))


class DiagnosticIn(BaseModel):
    """Lane 8 §B3 field names; source/iteration/fingerprint are set by the gateway, never by the job."""

    model_config = ConfigDict(extra="forbid")
    tool: str
    code: str
    severity: Literal["error", "warning"]
    file: Optional[str] = None
    line: Optional[StrictInt] = None
    message: str
    detail: Optional[str] = None
    # QA-REPAIR-MISSING-MODULE: the import smoke's typed fact (apps/qa-runner/sandbox_job.IMPORT_SMOKE_BY_ARGV), the
    # `name` of the ModuleNotFoundError that failed the import. Optional: an older job never sends it, and a dump
    # leaves it out when absent (_omit_absent_fact), so every other diagnostic is exactly as before.
    # QA-REPAIR-MISSING-MODULE-SETUP: the same fact on PY.TEST_SETUP_ERROR, from the job's pytest plugin
    # (apps/qa-runner/qa_missing_module_plugin.py): a ModuleNotFoundError in a test's collection or setup.
    missing_module: Optional[str] = None

    @field_validator("missing_module")
    @classmethod
    def _module_name(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and not is_module_name(v):
            raise ValueError("missing_module is not a module name")
        return v

    @model_serializer(mode="wrap")
    def _omit_absent_fact(self, handler: Any) -> Dict[str, Any]:
        data = handler(self)
        if data.get("missing_module") is None:
            data.pop("missing_module", None)
        return data

    @field_validator("tool", "code")
    @classmethod
    def _short(cls, v: str) -> str:
        if not v or len(v) > 64:
            raise ValueError("tool/code must be 1..64 chars")
        return v

    @field_validator("file")
    @classmethod
    def _file(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and len(v) > 512:
            raise ValueError("file path too long")
        return v

    @field_validator("message", "detail")
    @classmethod
    def _capped(cls, v: Optional[str]) -> Optional[str]:
        return _cap(v)

    @property
    def namespace(self) -> str:
        return self.code.split(".", 1)[0]


class _Artifact(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1]
    nonce: str
    passed: StrictBool
    diagnostics: List[DiagnosticIn] = []
    diagnostics_truncated: StrictBool = False

    @model_validator(mode="before")
    @classmethod
    def _truncate(cls, data: Any) -> Any:
        if isinstance(data, dict) and isinstance(data.get("diagnostics"), list) and len(data["diagnostics"]) > MAX_DIAGNOSTICS:
            data = dict(data)
            data["diagnostics"] = data["diagnostics"][:MAX_DIAGNOSTICS]
            data["diagnostics_truncated"] = True
        return data


class StaticV1(_Artifact):
    """Written by the job BEFORE any untrusted code runs."""

    index_reachable: Optional[StrictBool] = None
    toolchain: Dict[str, str] = {}


class ReportV1(_Artifact):
    """Written after dependency install, import smoke and pytest."""

    tests_total: StrictInt = 0
    tests_failed: StrictInt = 0
    # RT14-17: skipped / xfail testcases, counted in tests_total but never as passes (absent from an older job = 0)
    tests_skipped: StrictInt = 0
    logs_tail: str = ""

    @field_validator("logs_tail")
    @classmethod
    def _logs(cls, v: str) -> str:
        return v[-20000:]


# ------------------------------------------------------------------------------
# Config and outcome
# ------------------------------------------------------------------------------
@dataclass(frozen=True)
class QAJobConfig:
    project_id: str
    region: str
    job_name: str
    staging_bucket: str
    sandbox_sa: str

    REQUIRED_ENV = ("PROJECT_ID", "REGION", "QA_JOB_NAME", "QA_STAGING_BUCKET", "QA_SANDBOX_SA")

    @classmethod
    def from_env(cls, env: Optional[Dict[str, str]] = None) -> Optional["QAJobConfig"]:
        env = os.environ if env is None else env
        vals = [(env.get(k) or "").strip() for k in cls.REQUIRED_ENV]
        if not all(vals):
            return None
        return cls(*vals)

    @property
    def job_path(self) -> str:
        return f"projects/{self.project_id}/locations/{self.region}/jobs/{self.job_name}"


@dataclass
class QAOutcome:
    passed: bool
    error_class: Optional[ErrorClass]
    summary: str
    diagnostics: List[Dict[str, Any]] = field(default_factory=list)
    static: Optional[Dict[str, Any]] = None
    report: Optional[Dict[str, Any]] = None
    exit_code: Optional[int] = None
    reason: Optional[str] = None
    execution_name: str = ""
    nonce: str = ""


def _unavailable(summary: str, reason: str, **kw: Any) -> QAOutcome:
    return QAOutcome(passed=False, error_class=ErrorClass.GATE_UNAVAILABLE, summary=summary, reason=reason, **kw)


def _parse_duration_s(value: Any) -> Optional[float]:
    if not isinstance(value, str) or not value.endswith("s"):
        return None
    try:
        return float(value[:-1])
    except ValueError:
        return None


def _load_artifact(model: type, raw: Optional[bytes], nonce: str) -> Optional[_Artifact]:
    if raw is None or len(raw) > MAX_ARTIFACT_BYTES:
        return None
    try:
        art = model.model_validate(json.loads(raw.decode("utf-8")))
    except (ValueError, ValidationError, UnicodeDecodeError):
        return None
    if art.nonce != nonce:
        return None
    return art


def classify(
    execution: Dict[str, Any],
    tasks: List[Dict[str, Any]],
    static_raw: Optional[bytes],
    report_raw: Optional[bytes],
    nonce: str,
    platform_owned: Optional[Callable[[str], bool]] = None,
) -> QAOutcome:
    """Review H2 precedence (first match wins) + red-team F2 (REQ.* needs a reachable index) + F3 (platform paths)."""
    if not execution.get("completionTime"):
        return _unavailable("QA execution did not complete", "NOT_COMPLETE")
    if int(execution.get("cancelledCount", 0) or 0) > 0 or int(execution.get("retriedCount", 0) or 0) > 0:
        return _unavailable("QA execution was cancelled or retried", "CANCELLED_OR_RETRIED")

    static = _load_artifact(StaticV1, static_raw, nonce)
    if static is None:
        return _unavailable("static.json missing, oversized, invalid or nonce mismatch", "STATIC_INVALID")

    if len(tasks) != 1:
        return _unavailable(f"expected exactly 1 task, got {len(tasks)}", "TASK_COUNT")
    last = tasks[0].get("lastAttemptResult")
    if not isinstance(last, dict):
        return _unavailable("task has no attempt result", "NO_ATTEMPT_RESULT")
    if last.get("termSignal"):
        return _unavailable(f"task killed by signal {last.get('termSignal')}", "SIGNAL")

    succeeded = int(execution.get("succeededCount", 0) or 0)
    failed = int(execution.get("failedCount", 0) or 0)
    exit_code = int(last.get("exitCode", 0) or 0)  # proto3 JSON omits exitCode when it is 0
    if exit_code == 0 and not (succeeded == 1 and failed == 0):
        return _unavailable("exit code 0 without a succeeded task", "COUNTS_MISMATCH", exit_code=exit_code)
    if exit_code != 0 and failed != 1:
        return _unavailable(f"exit code {exit_code} without exactly one failed task", "COUNTS_MISMATCH", exit_code=exit_code)

    report = _load_artifact(ReportV1, report_raw, nonce)
    common = {"static": static.model_dump(), "report": report.model_dump() if report else None, "exit_code": exit_code}

    if exit_code in (EXIT_CODE_DEFECT, EXIT_TIMEOUT_DEFECT):
        if static.passed and report is None:
            return _unavailable("exit 10/12 with a passing static phase but no valid report.json", "REPORT_INVALID", **common)
        diags = list(static.diagnostics) + (list(report.diagnostics) if report else [])
        if any(d.namespace == "REQ" for d in diags) and static.index_reachable is not True:
            return _unavailable("dependency diagnostics while the package index was not proven reachable", "INDEX_UNREACHABLE", **common)
        if platform_owned is not None and any(d.file and platform_owned(d.file) for d in diags):
            return QAOutcome(
                passed=False, error_class=ErrorClass.PLATFORM_DEFECT, reason="PLATFORM_OWNED_PATH",
                summary="QA found defects in platform-owned files", diagnostics=[d.model_dump() for d in diags], **common,
            )
        if not diags:
            return _unavailable("exit 10/12 without any diagnostic", "NO_DIAGNOSTICS", **common)
        # A warning never blocks, so it is not the cause while an error is present.
        cause = next((d for d in diags if d.severity == "error"), diags[0])
        return QAOutcome(
            passed=False, error_class=ErrorClass.CODE_DEFECT,
            summary=f"QA failed: {len(diags)} diagnostic(s); first: {cause.code} {cause.message[:200]}",
            diagnostics=[d.model_dump() for d in diags], **common,
        )

    if exit_code == EXIT_PASS:
        # Lane 3 PR-B RT F7: the gateway is the trust boundary, so a pass also needs >= 1 test and 0 failures in the
        # report itself (the job guarantees both; a job that does not is not trusted to have run the tests).
        # RT14-17: >= 1 test that RAN (skipped / xfail are not passes), and a skipped count within the total.
        if (not static.passed or report is None or not report.passed or report.tests_total < 1
                or report.tests_failed != 0 or report.tests_skipped < 0
                or report.tests_total - report.tests_skipped < 1):
            return _unavailable("exit 0 disagrees with static.json/report.json", "VERDICT_MISMATCH", **common)
        return QAOutcome(passed=True, error_class=None, summary=f"QA passed: {pass_count_text(report)}, static checks clean",
                         **common)

    return _unavailable(f"QA runner error (exit {exit_code})", "RUNNER_ERROR", **common)


def pass_count_text(report: Any) -> str:
    """RT14-17: "<passed>/<ran> tests" (+ " (<n> skipped)" when any were): a skipped or xfail test is never counted as
    passed. With no skipped test the text is exactly the earlier "<total - failed>/<total> tests"."""
    total, failed, skipped = report.tests_total, report.tests_failed, report.tests_skipped
    ran = total - skipped
    return f"{ran - failed}/{ran} tests" + (f" ({skipped} skipped)" if skipped else "")


# ------------------------------------------------------------------------------
# Default GCS store (lazy import; tests inject a fake with the same three methods)
# ------------------------------------------------------------------------------
class GcsStore:
    def __init__(self, bucket: str, credentials: Any):
        from google.cloud import storage

        self._creds = credentials
        self._bucket = storage.Client(credentials=credentials, project=None).bucket(bucket)

    def upload(self, name: str, data: bytes, content_type: str) -> None:
        self._bucket.blob(name).upload_from_string(data, content_type=content_type, if_generation_match=0)

    def download(self, name: str, max_bytes: int) -> Optional[bytes]:
        blob = self._bucket.get_blob(name)
        if blob is None:
            return None
        if blob.size is None or blob.size > max_bytes:
            logger.error(f"QA artifact {name} is {blob.size} bytes (cap {max_bytes}); treated as missing")
            return None
        return blob.download_as_bytes()

    def sign(self, name: str, method: str, ttl_s: int, headers: Optional[Dict[str, str]] = None) -> str:
        from google.auth.transport.requests import Request

        if not self._creds.valid:
            self._creds.refresh(Request())
        return self._bucket.blob(name).generate_signed_url(
            version="v4",
            expiration=timedelta(seconds=ttl_s),
            method=method,
            headers=headers or None,
            service_account_email=getattr(self._creds, "service_account_email", None),
            access_token=self._creds.token,
        )


# ------------------------------------------------------------------------------
# Client
# ------------------------------------------------------------------------------
class QAJobClient:
    def __init__(
        self,
        config: QAJobConfig,
        session: Any,
        store: Any,
        *,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        poll_interval_s: float = 10.0,
        platform_owned: Optional[Callable[[str], bool]] = None,
    ):
        self.config = config
        self.session = session
        self.store = store
        self.sleep = sleep
        self.clock = clock
        self.poll_interval_s = poll_interval_s
        self.platform_owned = platform_owned
        self._identity_ok_until = 0.0
        self._readiness_ok_until = 0.0
        self.egress_lockdown: Optional[bool] = None  # set by a passing readiness (RT F2 transition visibility)

    # -- H3: the job must be the zero-permission sandbox before any code is staged ---------------------------
    def _get_job(self) -> Dict[str, Any]:
        try:
            res = self.session.get(f"{RUN_API}/{self.config.job_path}", timeout=30)
        except Exception as e:
            raise GateUnavailableError(f"QA job lookup failed: {type(e).__name__}", reason="QA_JOB_LOOKUP") from e
        if res.status_code != 200:
            raise GateUnavailableError(f"QA job lookup returned HTTP {res.status_code}", reason="QA_JOB_LOOKUP")
        try:
            job = res.json()
            tmpl = job["template"]["template"]
            if not isinstance(job, dict) or not isinstance(tmpl, dict):
                raise TypeError("job or task template is not an object")
        except Exception as e:
            raise GateUnavailableError(f"QA job has no task template: {e}", reason="QA_JOB_LOOKUP") from e
        return job

    def verify_job_identity(self) -> None:
        if self.clock() < self._identity_ok_until:
            return
        job = self._get_job()
        self._check_identity(job)
        # Row L3-PRB-g: no code is staged for a job that could reach the internet or use another index, except the
        # complete legacy shape during the transition (RT F2; removed by C3b).
        misses = self._shape_misses(job)
        if misses:
            logger.error(f"qa job egress drift: {misses}", extra={"security_event": "qa_job_drift"})
            raise GateUnavailableError(
                f"qa job identity drift: {', '.join(misses)}", reason="QA_JOB_DRIFT",
                details={"drift": misses, **self._egress_details(job)},
            )
        self._identity_ok_until = self.clock() + IDENTITY_CACHE_S

    def verify_job_readiness(self) -> None:
        """Row L3-PRB-r: pipeline-start proof that the job can run the PR-B contract (one Run API GET, cached like
        H3): the identity check above, args == expected_job_args (row L3-PRB-g: entrypoint + `--index-url`), the
        egress contract (vpcAccess.egress ALL_TRAFFIC on the sandbox network), and the contract label set when the
        image shipped. Any miss -> GateUnavailableError (503), so a run whose job predates PR-B or the egress apply
        (or drifted) stops before vending. Readiness also primes the dispatch cache, so it checks everything
        verify_job_identity checks."""
        if self.clock() < self._readiness_ok_until:
            return
        job = self._get_job()
        self._check_identity(job)
        not_ready = self._shape_misses(job)
        lockdown = job_shape(job) == JOB_SHAPE_EGRESS and not not_ready
        labels = job.get("labels")
        found = labels.get(JOB_CONTRACT_LABEL) if isinstance(labels, dict) else None
        if found != JOB_CONTRACT_VERSION:
            not_ready.append(f"labels.{JOB_CONTRACT_LABEL}")
        if not_ready:
            logger.error(f"qa job contract not ready: {not_ready}", extra={"security_event": "qa_job_not_ready"})
            raise GateUnavailableError(
                f"QA job does not carry the sandbox job contract ({', '.join(not_ready)}); the run stops before "
                "vending. Ship the qa-runner image with its trigger / deploy-services.sh (they set the label)",
                reason="QA_JOB_NOT_READY",
                details={"not_ready": not_ready, "expected_contract": JOB_CONTRACT_VERSION,
                         "found_contract": found if isinstance(found, str) else None,
                         **self._egress_details(job)},
            )
        # Log only (owner rule 10-18: no Settings warning); C3b waits until both installs report true.
        self.egress_lockdown = lockdown
        logger.info(f"qa job ready: shape={job_shape(job)} egress_lockdown={lockdown}")
        now = self.clock()
        self._identity_ok_until = self._readiness_ok_until = now + IDENTITY_CACHE_S

    def _shape_misses(self, job: Dict[str, Any]) -> List[str]:
        """[] for the complete legacy shape (transition, RT F2) or a complete egress shape; else the misses."""
        if job_shape(job) == JOB_SHAPE_LEGACY:
            return []
        return self._egress_misses(job)

    def _egress_misses(self, job: Dict[str, Any]) -> List[str]:
        """Row L3-PRB-g: [] when the task template sends ALL egress into the sandbox network and its args are the
        entrypoint + the Artifact Registry index; otherwise the names of what differs (exact values, no parsing)."""
        tmpl = job["template"]["template"]
        misses = []
        containers = tmpl.get("containers") or []
        args = containers[0].get("args") if len(containers) == 1 and isinstance(containers[0], dict) else None
        if not isinstance(args, list) or args != expected_job_args(self.config):
            misses.append("args")
        vpc = tmpl.get("vpcAccess")
        vpc = vpc if isinstance(vpc, dict) else {}
        if vpc.get("egress") != JOB_VPC_EGRESS:
            misses.append("vpcAccess.egress")
        nics = vpc.get("networkInterfaces")
        if (not isinstance(nics, list) or len(nics) != 1 or not isinstance(nics[0], dict)
                or nics[0].get("network") not in expected_networks(self.config)):
            misses.append("vpcAccess.network")
        if vpc.get("connector"):
            misses.append("vpcAccess.connector")  # a Serverless VPC Access connector is not the sandbox network
        return misses

    def _egress_details(self, job: Dict[str, Any]) -> Dict[str, Any]:
        """What was expected and found (job config, no secrets), so an operator can see why without a gcloud call."""
        tmpl = job["template"]["template"]
        vpc = tmpl.get("vpcAccess") if isinstance(tmpl.get("vpcAccess"), dict) else {}
        nics = vpc.get("networkInterfaces") if isinstance(vpc.get("networkInterfaces"), list) else []
        shape = job_shape(job)
        return {
            "job_shape": shape,
            "egress_lockdown": False,  # only ever in error details: a refused job is never locked down
            # Re-check R3: the args expected for the shape that was found (legacy keeps its entrypoint args).
            "expected_args": list(JOB_CONTRACT_ARGS) if shape == JOB_SHAPE_LEGACY else expected_job_args(self.config),
            "expected_vpc_egress": JOB_VPC_EGRESS,
            "expected_network": expected_networks(self.config)[0],
            "found_vpc_egress": vpc.get("egress") if isinstance(vpc.get("egress"), str) else None,
            "found_networks": [n.get("network") for n in nics if isinstance(n, dict) and isinstance(n.get("network"), str)],
        }

    def _check_identity(self, job: Dict[str, Any]) -> None:
        tmpl = job["template"]["template"]
        on_host = host_network_interfaces(job)
        if on_host:   # before everything else: a job on the host network is refused whatever else it carries
            logger.error(f"qa job on the host platform network: {on_host}", extra={"security_event": "qa_job_drift"})
            raise GateUnavailableError(
                f"qa job identity drift: vpcAccess.network is the host platform network {HOST_PLATFORM_NETWORK}; "
                "the QA sandbox job must never join it", reason="QA_JOB_DRIFT",
                details={"drift": ["vpcAccess.host_network"], "found_networks": on_host,
                         "forbidden_network": HOST_PLATFORM_NETWORK},
            )
        drift = []
        if tmpl.get("serviceAccount") != self.config.sandbox_sa:
            drift.append("serviceAccount")
        if int(tmpl.get("maxRetries", 0) or 0) != 0:
            drift.append("maxRetries")
        containers = tmpl.get("containers") or []
        if len(containers) != 1 or containers[0].get("env"):
            drift.append("containers/env")
        timeout_s = _parse_duration_s(tmpl.get("timeout"))
        if timeout_s is None or timeout_s > JOB_TASK_TIMEOUT_S:
            drift.append("timeout")
        if drift:
            logger.error(f"qa job identity drift: {drift}", extra={"security_event": "qa_job_drift"})
            raise GateUnavailableError(f"qa job identity drift: {', '.join(drift)}", reason="QA_JOB_DRIFT")

    def _execution_prefix(self) -> str:
        return f"{self.config.job_path}/executions/"

    def _cancel(self, execution_name: str) -> None:
        try:
            self.session.post(f"{RUN_API}/{execution_name}:cancel", json={}, timeout=30)
        except Exception as e:
            logger.error(f"QA execution cancel failed for {execution_name}: {e}")

    def run(
        self,
        *,
        tar_bytes: bytes,
        commit_sha: str,
        trace_id: str,
        product_id: str,
        deadline: float,
    ) -> QAOutcome:
        """Stage, run one execution, wait (bounded by `deadline`, a clock() value), classify. Never raises a pass."""
        validate_trace_id(trace_id)
        self.verify_job_identity()

        nonce = secrets.token_hex(16)
        prefix = f"runs/{trace_id}/{nonce}"
        src_name, static_name, report_name = f"{prefix}/source.tar.gz", f"{prefix}/static.json", f"{prefix}/report.json"
        try:
            self.store.upload(src_name, tar_bytes, "application/gzip")
            get_url = self.store.sign(src_name, "GET", GET_URL_TTL_S)
            static_url = self.store.sign(static_name, "PUT", PUT_URL_TTL_S, CREATE_ONLY_HEADERS)
            report_url = self.store.sign(report_name, "PUT", PUT_URL_TTL_S, CREATE_ONLY_HEADERS)
        except Exception as e:
            return _unavailable(f"QA staging failed: {type(e).__name__}: {e}", "STAGING", nonce=nonce)

        env = {
            "QA_SOURCE_URL": get_url,
            "QA_SOURCE_SHA256": hashlib.sha256(tar_bytes).hexdigest(),
            "QA_STATIC_PUT_URL": static_url,
            "QA_REPORT_PUT_URL": report_url,
            "QA_NONCE": nonce,
            "QA_TRACE_ID": trace_id,
            "QA_COMMIT_SHA": commit_sha,
            "QA_PRODUCT_ID": product_id,
            "QA_DEADLINE_SECONDS": str(JOB_INTERNAL_DEADLINE_S),
        }
        body = {
            "overrides": {
                "containerOverrides": [{"env": [{"name": k, "value": v} for k, v in sorted(env.items())]}],
                "taskCount": 1,
                "timeout": f"{JOB_TASK_TIMEOUT_S}s",
            }
        }
        try:
            res = self.session.post(f"{RUN_API}/{self.config.job_path}:run", json=body, timeout=60)
        except Exception as e:
            return _unavailable(f"QA job run request failed: {type(e).__name__}", "RUN_API", nonce=nonce)
        if res.status_code not in (200, 201):
            return _unavailable(f"QA job run returned HTTP {res.status_code}", "RUN_API", nonce=nonce)
        try:
            execution_name = res.json()["metadata"]["name"]
        except Exception:
            return _unavailable("QA job run response has no execution name", "RUN_API", nonce=nonce)
        if not isinstance(execution_name, str) or not execution_name.startswith(self._execution_prefix()):
            return _unavailable("QA job run returned an unexpected execution name", "RUN_API", nonce=nonce)

        poll_deadline = min(deadline, self.clock() + JOB_TASK_TIMEOUT_S + QUEUE_GRACE_S)
        execution: Dict[str, Any] = {}
        while True:
            try:
                ex_res = self.session.get(f"{RUN_API}/{execution_name}", timeout=30)
                if ex_res.status_code == 200:
                    execution = ex_res.json()
            except Exception as e:
                logger.warning(f"QA execution poll error ({type(e).__name__}); retrying until deadline")
            if execution.get("completionTime"):
                break
            if self.clock() >= poll_deadline:
                self._cancel(execution_name)
                return _unavailable("QA execution did not finish before the deadline", "DEADLINE",
                                    execution_name=execution_name, nonce=nonce)
            self.sleep(self.poll_interval_s)

        try:
            t_res = self.session.get(f"{RUN_API}/{execution_name}/tasks", timeout=30)
            tasks = t_res.json().get("tasks", []) if t_res.status_code == 200 else None
        except Exception:
            tasks = None
        if tasks is None:
            return _unavailable("could not read QA task results", "TASKS_API", execution_name=execution_name, nonce=nonce)

        try:
            static_raw = self.store.download(static_name, MAX_ARTIFACT_BYTES)
            report_raw = self.store.download(report_name, MAX_ARTIFACT_BYTES)
        except Exception as e:
            return _unavailable(f"could not read QA artifacts: {type(e).__name__}", "ARTIFACTS",
                                execution_name=execution_name, nonce=nonce)

        outcome = classify(execution, tasks, static_raw, report_raw, nonce, self.platform_owned)
        outcome.execution_name = execution_name
        outcome.nonce = nonce
        if outcome.error_class == ErrorClass.GATE_UNAVAILABLE:
            logger.error(f"QA gate unavailable for trace {trace_id}: {outcome.reason}: {outcome.summary}")
        return outcome


def build_default_client() -> Optional[QAJobClient]:
    """Production wiring. None (-> GATE_UNAVAILABLE) unless every QA_* setting is present."""
    config = QAJobConfig.from_env()
    if config is None:
        return None
    import google.auth
    from google.auth.transport.requests import AuthorizedSession

    creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    return QAJobClient(config, AuthorizedSession(creds), GcsStore(config.staging_bucket, creds))
