"""Validator host skeleton (Wave 2 C0a; integration plan §1.7, lane 8B plan §2-§3).

A validator reads artifacts and returns `Diagnostic`s. It never writes, never calls an LLM, never reads TEST_MODE,
and decides findings only with real parsers or exact tables (Invariant 2). `ValidatorStack` runs every registered
validator on every iteration and folds the results into one `ValidationReport`, so the LLM sees all problems at once.

Modes: "blocking" (an error fails the report), "report_only" (measured in `report.report_only`, never blocks, never
repaired), "off". Defaults live with each registration; `validator_modes` overrides per validator id.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Dict, FrozenSet, List, Literal, Mapping, Optional, Protocol, Tuple, Union

from shared.artifact_ownership import Ownership
from shared.diagnostics import (MAX_ERROR_DIAGNOSTICS, AssemblyRecord, Diagnostic, Source, Tool, ValidationReport,
                                artifact_hash)

Mode = Literal["off", "report_only", "blocking"]
MODES = ("off", "report_only", "blocking")


class ValidatorUnavailable(Exception):
    """A validator could not run (tool missing, service down). Never a pass: a blocking validator that raises this
    makes the report UNAVAILABLE (GATE_UNAVAILABLE, zero LLM spend)."""


# ------------------------------------------------------------------------------------------------- value views
@dataclass(frozen=True)
class LiteralV:
    value: Any


@dataclass(frozen=True)
class RefV:
    address: str


@dataclass(frozen=True)
class CallV:
    fn: str
    args: Tuple["ValueView", ...] = ()


@dataclass(frozen=True)
class ExprV:
    raw: str   # a legacy HCL expression that is neither a literal nor a plain reference (python-hcl2 "${...}")


ValueView = Union[LiteralV, RefV, CallV, ExprV]


@dataclass(frozen=True)
class ResourceView:
    kind: Literal["resource", "data", "module"]
    type: str                    # resource/data type; "" for modules
    name: str
    file: str
    attributes: Mapping[str, Any]
    line: Optional[int]
    end_line: Optional[int]
    ownership: Optional[Ownership]

    @property
    def address(self) -> str:
        if self.kind == "module":
            return f"module.{self.name}"
        if self.kind == "data":
            return f"data.{self.type}.{self.name}"
        return f"{self.type}.{self.name}"


# ------------------------------------------------------------------------------------------------- context
@dataclass(frozen=True)
class ValidationContext:
    files: Mapping[str, str]
    ownership: Callable[[str], Optional[Ownership]]
    vendored: FrozenSet[str] = frozenset()
    rendered: FrozenSet[str] = frozenset()
    draft: Mapping[str, str] = field(default_factory=dict)
    assembly: Optional[AssemblyRecord] = None
    source: Source = "precommit"
    iteration: int = 0
    product_id: str = ""
    trace_id: str = ""
    extras: Mapping[str, Any] = field(default_factory=dict)   # e.g. {"available_providers": [...]}

    @staticmethod
    def build(files: Mapping[str, str], **kw: Any) -> "ValidationContext":
        return ValidationContext(files=MappingProxyType(dict(files)), **kw)


class Validator(Protocol):
    id: str
    tool: Tool

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]: ...


# ------------------------------------------------------------------------------------------------- the stack
@dataclass
class _Registration:
    validator: Any
    default_mode: Mode


class ValidatorStack:
    def __init__(self, modes: Optional[Mapping[str, Mode]] = None,
                 classify: Optional[Callable[[Diagnostic, ValidationContext], Diagnostic]] = None):
        self._regs: List[_Registration] = []
        self._modes: Dict[str, Mode] = dict(modes or {})
        for vid, m in self._modes.items():
            if m not in MODES:
                raise ValueError(f"validator {vid}: unknown mode {m!r}")
        self._classify = classify

    def register(self, validator: Any, default_mode: Mode) -> None:
        if default_mode not in MODES:
            raise ValueError(f"validator {validator.id}: unknown mode {default_mode!r}")
        if any(r.validator.id == validator.id for r in self._regs):
            raise ValueError(f"validator {validator.id} registered twice")
        self._regs.append(_Registration(validator, default_mode))

    def mode_of(self, validator_id: str) -> Mode:
        for r in self._regs:
            if r.validator.id == validator_id:
                return self._modes.get(validator_id, r.default_mode)
        raise KeyError(validator_id)

    @property
    def ids(self) -> List[str]:
        return [r.validator.id for r in self._regs]

    def run(self, ctx: ValidationContext) -> ValidationReport:
        t0 = time.monotonic()
        blocking: List[Diagnostic] = []
        report_only: List[Diagnostic] = []
        ran: List[str] = []
        unavailable: List[str] = []
        blocking_unavailable = False
        for r in self._regs:
            mode = self._modes.get(r.validator.id, r.default_mode)
            if mode == "off":
                continue
            try:
                found = list(r.validator.validate(ctx))
            except Exception:  # noqa: BLE001 - ValidatorUnavailable or a validator bug: never a pass
                unavailable.append(r.validator.id)
                blocking_unavailable = blocking_unavailable or mode == "blocking"
                continue
            ran.append(r.validator.id)
            if mode == "blocking":
                blocking.extend(self._classify(d, ctx) if self._classify else d for d in found)
            else:
                report_only.extend(found)
        errors = [d for d in blocking if d.severity == "error"]
        truncated = len(errors) > MAX_ERROR_DIAGNOSTICS
        if truncated:
            keep = set(map(id, errors[:MAX_ERROR_DIAGNOSTICS]))
            blocking = [d for d in blocking if d.severity != "error" or id(d) in keep]
        status = "UNAVAILABLE" if blocking_unavailable else ("FAIL" if errors else "PASS")
        return ValidationReport(
            status=status, source=ctx.source, artifact_hash=artifact_hash(ctx.files), tools_ran=ran,
            tools_unavailable=unavailable, diagnostics=[] if status == "UNAVAILABLE" else blocking,
            report_only=report_only, truncated=truncated, repair_iteration=ctx.iteration,
            duration_ms=int((time.monotonic() - t0) * 1000))
