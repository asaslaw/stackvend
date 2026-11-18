"""V-ENV (RUNTIME-ENV-CONTRACT-CHECK, owner 11-10, report only for launch): an environment variable a service's code
reads that the platform does not set on that service.

| id    | code                      | default mode | when |
| V-ENV | ENV.READ_NOT_PROVIDED     | report_only  | a topology Cloud Run service's non-test code reads NAME (`os.getenv` / `os.environ.get` / `os.environ[...]`, NAME a constant) and the platform's typed env set for that service (`topology_wiring.callee_env_names`) is known and does not hold NAME |
| V-ENV | ENV.PROVIDED_SET_UNKNOWN  | report_only  | one per workload: a service whose code reads a constant NAME has no known env set (not a Cloud Run service, a variables file may set `var.env_vars`, an override file declares its module) |

The facts and their limits: developer_agent/runtime_env_facts.py. Both codes are warnings with the service's file and
line; the default the code gives is reported as written, never judged (Invariant 2).

Policy point (the one place to change): RUNTIME_ENV_MODE. "report_only" (today): every finding is a warning in
`report.report_only`; it never blocks, never reaches a repair prompt or a repair seed, never changes pass/fail
(fail-loudly policy §2, validator roll-out); the developer stage also copies the findings to the workload record
(`workloads/{product_id}.runtime_env_advisories`, shown on the Control Center workload page). "blocking" (a later
owner decision, its own register row): the validator registers blocking and ENV.READ_NOT_PROVIDED becomes an error
(CODE_DEFECT), which fails the report and goes to the repair loop like any other code finding.
ENV.PROVIDED_SET_UNKNOWN is a fact about the platform, not the code: it stays a warning in every mode, so an unknown
set never blocks. (A per-run `validator_modes` override changes only where the findings are listed, not their
severity: use RUNTIME_ENV_MODE.)
"""
from __future__ import annotations

from typing import Any, List, Optional

try:
    from shared.diagnostics import Diagnostic, ErrorClass
except ImportError:  # pragma: no cover
    from ...shared.diagnostics import Diagnostic, ErrorClass  # type: ignore

from ..runtime_env_facts import PROVIDED_SET_UNKNOWN, Finding, runtime_env_findings
from ..topology_wiring import deployed_view
from .base import Mode, ValidationContext

VALIDATOR_ID = "V-ENV"
RUNTIME_ENV_MODE: Mode = "report_only"   # the policy point (see the module docstring)


def to_diagnostic(f: Finding, iteration: int = 0, blocking: bool = False) -> Diagnostic:
    hint = None
    if f.code != PROVIDED_SET_UNKNOWN:
        hint = (f"Read {f.name} only if the platform sets it on '{f.service}' (an edge or resource binding of the "
                "architect's plan, or a variable the Cloud Run module always sets), or use a name it does set.")
    severity = "error" if blocking and f.code != PROVIDED_SET_UNKNOWN else "warning"
    return Diagnostic(tool="ast", code=f.code, severity=severity, error_class=ErrorClass.CODE_DEFECT,
                      source="precommit", file=f.file, line=f.line, symbol=f.name, message=f.message,
                      detail=f.reason, hint=hint, iteration=iteration)


class RuntimeEnvContractValidator:
    id, tool = VALIDATOR_ID, "ast"

    def __init__(self, topology: Optional[Any], blocking: bool = False):
        self.topology = topology
        self.blocking = blocking

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        # the env set is judged on the tree the build deploys: a repository variables / override file the build does
        # not rewrite (`preexisting_files`, RepairLoop.validate) makes it unknown (topology_wiring.deployed_view)
        deployed = deployed_view(ctx.files, ctx.extras.get("preexisting_files"))
        return [to_diagnostic(f, ctx.iteration, self.blocking)
                for f in runtime_env_findings(self.topology, ctx.files, deployed_files=deployed)]


def register(stack: Any, topology: Optional[Any]) -> None:
    blocking = RUNTIME_ENV_MODE == "blocking"
    stack.register(RuntimeEnvContractValidator(topology, blocking=blocking), RUNTIME_ENV_MODE)
