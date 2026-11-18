"""Typed diagnostics for the hallucination stack (Wave 2 C0a; integration plan §1.1, lane 8B plan §4).

Every validator returns `Diagnostic`s; a run of the validator stack is one `ValidationReport`; a stage that stops
raises a `StageError` carrying its report. One `ErrorClass` vocabulary for every lane (no IAC_DEFECT, no
TOPOLOGY_CONFLICT). Nothing here performs I/O, calls an LLM or reads TEST_MODE.

Also defined here (Step 1 RT F2/F3/F6/F7, integration findings I-19..I-21): the per-trace `RepairLedger` and its
`LedgerStore` protocol, the IaC `ProvenanceStore` protocol, in-memory store implementations (harness child and unit
tests; production uses Firestore implementations injected at gateway startup), and the `AssemblyRecord` produced by
every assembly of the developer's root module.

Root `shared/` is the single source of truth; service copies are byte-identical (deploy/vendor_shared.py).
"""
from __future__ import annotations

import hashlib
import threading
from enum import Enum
from typing import Annotated, Any, Dict, List, Literal, Mapping, Optional, Protocol, Tuple

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

__all__ = [
    "Tool", "Source", "ErrorClass", "Route", "ROUTE", "PRECEDENCE", "HTTP_STATUS", "DIAGNOSTIC_CLASSES",
    "Diagnostic", "fingerprint", "artifact_hash", "derive_error_class", "ValidationReport", "StageError",
    "RepairBudgetExhausted", "StoreUnavailable", "RepairEvent", "CheckpointRecord", "RepairLedger", "LedgerStore",
    "MemoryLedgerStore", "ProvenanceEntry", "ProvenanceStore", "MemoryProvenanceStore", "Segment", "ReplaceReason",
    "DropReason", "AssemblyRecord", "MESSAGE_CAP", "HINT_CAP", "SNIPPET_MAX_LINES", "MAX_ERROR_DIAGNOSTICS",
]

Tool = Literal["hcl2", "tofu", "topology", "facts", "policy", "schema", "ruff", "pyflakes", "ast", "pip",
               "pytest", "bandit", "judge", "yaml", "pydantic", "path", "platform", "container", "gatekeeper"]
Source = Literal["architect", "precommit", "apply", "qa"]

MESSAGE_CAP = 2048          # bytes of message / detail kept (verbatim prefix)
HINT_CAP = 4096             # bytes of platform-supplied hint kept
SNIPPET_MAX_LINES = 11
MAX_ERROR_DIAGNOSTICS = 200  # a report keeps at most this many error diagnostics (then `truncated`)


class ErrorClass(str, Enum):
    # diagnostic classes (may appear on a Diagnostic; ordered by PRECEDENCE)
    CODE_DEFECT = "CODE_DEFECT"                  # a generated artifact fails a deterministic check -> developer repair
    ARCHITECT_DEFECT = "ARCHITECT_DEFECT"        # architect output still invalid after its bounded repair -> DLQ
    BROWNFIELD_CONFLICT = "BROWNFIELD_CONFLICT"  # request conflicts with the existing workload -> operator
    PLATFORM_DEFECT = "PLATFORM_DEFECT"          # defect in a platform-owned file/fact/payload -> DLQ
    # report/stage classes
    GATE_UNAVAILABLE = "GATE_UNAVAILABLE"        # a required validator, gate, tool or store could not run -> DLQ
    # operator classes (lane 6 / lane 17)
    STATE_LOCKED = "STATE_LOCKED"
    DEPLOY_TIMEOUT = "DEPLOY_TIMEOUT"
    QUOTA_EXHAUSTED = "QUOTA_EXHAUSTED"
    GCE_STOCKOUT = "GCE_STOCKOUT"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    DESTROY_BLOCKED = "DESTROY_BLOCKED"
    # workflow terminal classes (lane 17)
    POLICY_REJECTED = "POLICY_REJECTED"
    GATE_TIMEOUT = "GATE_TIMEOUT"
    KILL_SWITCH_ACTIVE = "KILL_SWITCH_ACTIVE"
    CONTRACT_VIOLATION = "CONTRACT_VIOLATION"
    RELEASE_FAILED = "RELEASE_FAILED"
    DEPLOY_FAILED = "DEPLOY_FAILED"
    DEPENDENCY_FAILED = "DEPENDENCY_FAILED"
    UNHANDLED = "UNHANDLED"


class Route(str, Enum):
    DEVELOPER_REPAIR = "DEVELOPER_REPAIR"
    OPERATOR = "OPERATOR"
    DLQ = "DLQ"


_OPERATOR_CLASSES = (ErrorClass.BROWNFIELD_CONFLICT, ErrorClass.STATE_LOCKED, ErrorClass.DEPLOY_TIMEOUT,
                     ErrorClass.QUOTA_EXHAUSTED, ErrorClass.GCE_STOCKOUT, ErrorClass.PERMISSION_DENIED,
                     ErrorClass.DESTROY_BLOCKED)
ROUTE: Mapping[ErrorClass, Route] = {
    c: (Route.DEVELOPER_REPAIR if c is ErrorClass.CODE_DEFECT else Route.OPERATOR if c in _OPERATOR_CLASSES
        else Route.DLQ)
    for c in ErrorClass
}
PRECEDENCE: Tuple[ErrorClass, ...] = (ErrorClass.GATE_UNAVAILABLE, ErrorClass.PLATFORM_DEFECT,
                                      ErrorClass.BROWNFIELD_CONFLICT, ErrorClass.ARCHITECT_DEFECT,
                                      ErrorClass.CODE_DEFECT)
HTTP_STATUS: Mapping[ErrorClass, int] = {
    ErrorClass.GATE_UNAVAILABLE: 503, ErrorClass.PLATFORM_DEFECT: 503, ErrorClass.BROWNFIELD_CONFLICT: 409,
    ErrorClass.ARCHITECT_DEFECT: 422, ErrorClass.CODE_DEFECT: 422,
}
DIAGNOSTIC_CLASSES = frozenset({ErrorClass.CODE_DEFECT, ErrorClass.ARCHITECT_DEFECT,
                                ErrorClass.BROWNFIELD_CONFLICT, ErrorClass.PLATFORM_DEFECT})

DiagnosticCode = Annotated[str, StringConstraints(pattern=r"^[A-Z][A-Z0-9]*(\.[A-Z0-9_]+)+$")]


def _cap(text: Optional[str], limit: int) -> Optional[str]:
    if text is None:
        return None
    raw = text.encode("utf-8")
    if len(raw) <= limit:
        return text
    return raw[:limit].decode("utf-8", errors="ignore")


class Diagnostic(BaseModel):
    """One finding of one validator. `message`/`detail` are the tool's own text (capped, never rewritten)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool: Tool
    code: DiagnosticCode
    severity: Literal["error", "warning"]
    error_class: ErrorClass = ErrorClass.CODE_DEFECT
    file: str
    line: Optional[int] = None
    column: Optional[int] = None
    end_line: Optional[int] = None
    block_address: Optional[str] = None
    attribute_path: Optional[str] = None
    symbol: Optional[str] = None
    message: str
    detail: Optional[str] = None
    snippet: Optional[str] = None
    hint: Optional[str] = None
    source: Source
    iteration: int = 0

    @field_validator("error_class")
    @classmethod
    def _diagnostic_class(cls, v: ErrorClass) -> ErrorClass:
        if v not in DIAGNOSTIC_CLASSES:
            raise ValueError(f"{v.value} is a report/stage class, not a diagnostic class")
        return v

    @field_validator("message", "detail", mode="before")
    @classmethod
    def _cap_message(cls, v: Any) -> Any:
        return _cap(v, MESSAGE_CAP) if isinstance(v, str) else v

    @field_validator("hint", mode="before")
    @classmethod
    def _cap_hint(cls, v: Any) -> Any:
        return _cap(v, HINT_CAP) if isinstance(v, str) else v

    @field_validator("snippet", mode="before")
    @classmethod
    def _cap_snippet(cls, v: Any) -> Any:
        if isinstance(v, str):
            return "\n".join(v.split("\n")[:SNIPPET_MAX_LINES])
        return v


def fingerprint(d: Diagnostic) -> str:
    """Identity of a finding across iterations. No line numbers (lane 8 RT F12): an edit above a block must not make
    an unchanged finding look new."""
    parts = [d.tool, d.code, d.file, d.block_address or "", d.attribute_path or "", d.symbol or ""]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def artifact_hash(files: Mapping[str, str]) -> str:
    """sha256 over sorted (path, sha256(content)) pairs: the identity of a validated or committed tree."""
    h = hashlib.sha256()
    for path in sorted(files):
        content = files[path]
        data = content.encode("utf-8") if isinstance(content, str) else bytes(content)
        h.update(path.encode("utf-8"))
        h.update(b"\0")
        h.update(hashlib.sha256(data).hexdigest().encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def derive_error_class(status: str, diagnostics: List[Diagnostic]) -> Optional[ErrorClass]:
    """UNAVAILABLE -> GATE_UNAVAILABLE; FAIL -> the first class of PRECEDENCE among error diagnostics; PASS -> None."""
    if status == "UNAVAILABLE":
        return ErrorClass.GATE_UNAVAILABLE
    if status == "PASS":
        return None
    present = {d.error_class for d in diagnostics if d.severity == "error"}
    for c in PRECEDENCE:
        if c in present:
            return c
    return None


class ValidationReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: Literal["PASS", "FAIL", "UNAVAILABLE"]
    error_class: Optional[ErrorClass] = None
    source: Source
    artifact_hash: str
    tools_ran: List[str] = Field(default_factory=list)
    tools_unavailable: List[str] = Field(default_factory=list)
    diagnostics: List[Diagnostic] = Field(default_factory=list)   # blocking validators' findings
    report_only: List[Diagnostic] = Field(default_factory=list)   # measured, never block, never repaired
    truncated: bool = False
    repair_iteration: int = 0
    duration_ms: int = 0

    @model_validator(mode="after")
    def _derive(self) -> "ValidationReport":
        errors = [d for d in self.diagnostics if d.severity == "error"]
        if self.status == "PASS" and errors:
            raise ValueError("a PASS report cannot carry error diagnostics")
        if self.status == "FAIL" and not errors:
            raise ValueError("a FAIL report needs at least one error diagnostic")
        derived = derive_error_class(self.status, self.diagnostics)
        if self.error_class is None:
            object.__setattr__(self, "error_class", derived)
        elif self.error_class != derived:
            raise ValueError(f"error_class {self.error_class} != derived {derived}")
        return self

    def error_fingerprints(self) -> List[str]:
        return sorted({fingerprint(d) for d in self.diagnostics if d.severity == "error"})


class StageError(Exception):
    """Base of every typed stage failure; the gateway maps `error_class` through HTTP_STATUS."""

    def __init__(self, report: ValidationReport, message: str = ""):
        self.report = report
        super().__init__(message or f"{report.error_class.value if report.error_class else report.status}: "
                                    f"{len(report.diagnostics)} diagnostic(s)")

    @property
    def error_class(self) -> Optional[ErrorClass]:
        return self.report.error_class


ExhaustedReason = Literal["ITERATIONS", "TOKENS", "WALL_CLOCK", "NO_PROGRESS"]


class RepairBudgetExhausted(StageError):
    """The per-trace repair budget is used up, or a repair round reproduced the previous error set exactly.
    Carries the last report; the gateway maps it to HTTP 409 (zero further LLM spend)."""

    def __init__(self, report: ValidationReport, exhausted_reason: ExhaustedReason, message: str = ""):
        self.exhausted_reason = exhausted_reason
        super().__init__(report, message or f"repair budget exhausted ({exhausted_reason}); last report "
                                            f"{report.error_class.value if report.error_class else report.status}")


class StoreUnavailable(Exception):
    """A ledger/provenance store could not be read or written: the stage stops with GATE_UNAVAILABLE."""


class RepairEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str
    product_id: str
    iteration: int
    source: Source
    persona: str
    files: List[str]
    codes: List[str]
    fingerprints_before: List[str]
    fingerprints_after: List[str]
    accepted: bool
    reject_reason: Optional[Literal["NO_IMPROVEMENT", "NEW_FINGERPRINT", "PRESERVATION_VIOLATION",
                                    "OUT_OF_SCOPE_WRITE", "ENVELOPE_INVALID", "NO_PROGRESS",
                                    "REQUIREMENTS_ADDITION_REFUSED"]] = None
    removed_addresses: List[str] = Field(default_factory=list)
    # R3c: why each removed address was allowed (repair_loop.removal_justifications); absent = not allowed
    removal_reasons: Dict[str, str] = Field(default_factory=dict)
    model: str
    # SLOW-CALL-FALLBACK (owner 11-13): why `model` (the model that answered) is not the repair model: TIMEOUT /
    # TRANSIENT_<code> (developer_agent/llm_transport.py CallWalk); None = the repair model answered
    model_fallback: Optional[str] = None
    tokens_in: int = 0
    tokens_out: int = 0
    tokens_thoughts: int = 0
    duration_ms: int = 0
    # Step 2a code RT F4: a swarm junior's typed JSON re-ask (HS-61) is recorded in the same list so its cost is
    # visible; it is bounded by the junior's own retries and never counted against the repair budget.
    kind: Literal["repair", "junior_reask"] = "repair"
    task_id: Optional[str] = None
    attempt: Optional[int] = None
    detail: Optional[str] = None


class CheckpointRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str
    checkpoint: Literal["C0_raw", "C1_first_pass", "C2_generated", "C3_committed"]
    artifact_hash: str
    storage_uri: Optional[str] = None


class RepairLedger(BaseModel):
    """Per-trace repair budget state (Firestore pipeline_executions/{trace}.repair in production).
    `tokens_out` includes thinking tokens (Step 1 RT F7); `reserved_tokens` tracks in-flight reservations."""

    model_config = ConfigDict(extra="forbid")

    trace_id: str
    iteration: int = 0
    tokens_in: int = 0
    tokens_out: int = 0
    reserved_tokens: int = 0
    wall_clock_ms: int = 0
    dispatches: int = 0
    last_fingerprints: List[str] = Field(default_factory=list)
    exhausted_reason: Optional[ExhaustedReason] = None

    @property
    def tokens_spent(self) -> int:
        return self.tokens_in + self.tokens_out


class LedgerStore(Protocol):
    def load(self, trace_id: str) -> Optional[RepairLedger]: ...

    def save(self, ledger: RepairLedger) -> None: ...  # raises StoreUnavailable


class MemoryLedgerStore:
    """In-memory LedgerStore (eval harness child, unit tests). Stores copies, never the caller's object."""

    def __init__(self) -> None:
        self._data: Dict[str, RepairLedger] = {}
        self._lock = threading.Lock()

    def load(self, trace_id: str) -> Optional[RepairLedger]:
        with self._lock:
            led = self._data.get(trace_id)
            return led.model_copy(deep=True) if led is not None else None

    def save(self, ledger: RepairLedger) -> None:
        with self._lock:
            self._data[ledger.trace_id] = ledger.model_copy(deep=True)


class ProvenanceEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    persona: str
    trace_id: str
    sha256: str


class ProvenanceStore(Protocol):
    def load(self, product_id: str) -> Dict[str, ProvenanceEntry]: ...  # raises StoreUnavailable

    def save(self, product_id: str, entries: Dict[str, ProvenanceEntry]) -> None: ...  # raises StoreUnavailable


class MemoryProvenanceStore:
    def __init__(self) -> None:
        self._data: Dict[str, Dict[str, ProvenanceEntry]] = {}
        self._lock = threading.Lock()

    def load(self, product_id: str) -> Dict[str, ProvenanceEntry]:
        with self._lock:
            return {k: v.model_copy() for k, v in self._data.get(product_id, {}).items()}

    def save(self, product_id: str, entries: Dict[str, ProvenanceEntry]) -> None:
        with self._lock:
            self._data[product_id] = {k: v.model_copy() for k, v in entries.items()}


class Segment(BaseModel):
    """One appended draft file inside an assembled file: assembled lines start..end (1-based, inclusive) are the
    draft file's lines starting at draft_start_line (diagnostic back-mapping to the persona that wrote it)."""

    model_config = ConfigDict(extra="forbid")

    assembled_path: str
    start_line: int
    end_line: int
    draft_path: str
    draft_start_line: int = 1


ReplaceReason = Literal["CLOUD_RUN_REPLACED_BY_MODULE", "GKE_CLUSTER_REPLACED_BY_MODULE",
                        "PLATFORM_ROOT_DECLARATION", "PRIOR_DECLARATION", "PLATFORM_RESYNTHESIZED"]
# Whole draft files the platform removed at assembly. PLATFORM_PATH_RESERVED: the path is rendered by the platform
# only (infra/workload/terraform.tfvars, lane 11 RT2 G1), so an LLM-authored file there is never committed.
DropReason = Literal["PLATFORM_PATH_RESERVED"]


class AssemblyRecord(BaseModel):
    """What one assembly of the developer's root module did to the LLM's IaC (Step 1 S1-A contract).

    Block keys: "<type>.<name>" (resource), "data.<type>.<name>", "module.<name>", "variable.<name>",
    "output.<name>", "provider.<name>" / "provider.<name>.<alias>", "terraform", "local.<name>"."""

    model_config = ConfigDict(extra="forbid")

    trace_id: str = ""
    iteration: int = 0
    relocated: Dict[str, str] = Field(default_factory=dict)     # draft path -> assembled path
    segments: List[Segment] = Field(default_factory=list)
    replaced: Dict[str, str] = Field(default_factory=dict)      # draft key -> platform address
    replaced_reason: Dict[str, ReplaceReason] = Field(default_factory=dict)
    replaced_from: Dict[str, str] = Field(default_factory=dict)  # draft key -> draft path it was removed from
    dropped: Dict[str, DropReason] = Field(default_factory=dict)  # draft path -> why the whole file was removed
    # RT14-12: repository blocks (the repository's custom.tf, not this run's AI draft) the platform found where it
    # replaces the AI's blocks of the same kind, and kept unchanged (a person's google_cloud_run_v2_service): key -> path
    kept_repository: Dict[str, str] = Field(default_factory=dict)

    def record(self, key: str, target: str, reason: ReplaceReason, draft_path: str = "") -> None:
        self.replaced[key] = target
        self.replaced_reason[key] = reason
        if draft_path:
            self.replaced_from[key] = draft_path

    def drop(self, path: str, reason: DropReason) -> None:
        self.dropped[path] = reason

    def draft_location(self, assembled_path: str, line: int) -> Optional[Tuple[str, int]]:
        """(draft path, draft line) for an assembled line inside a segment; None outside every segment."""
        for s in self.segments:
            if s.assembled_path == assembled_path and s.start_line <= line <= s.end_line:
                return s.draft_path, s.draft_start_line + (line - s.start_line)
        return None
