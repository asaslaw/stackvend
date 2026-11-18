"""V-PLAN-TARGETS (register row PLAN-TARGET-FILES; live ex09-1115, 11-15): a DAG target file the developer must write
is missing from the assembled tree.

The required set is developer_agent.plan_targets.required_plan_targets (exact paths of the architect's task DAG; the
tasks the platform answers and the paths the developer may not write are left out there). Each one whose exact path is
not in the assembled tree (the draft, the repository's files and the platform's renders) is PLAN.TARGET_FILE_MISSING:
error, CODE_DEFECT, `file` = the missing path. It is a file to create (repair_loop.CREATE_FILE_CODES), routed by
repair_loop.Router._route_plan_target_create to the persona that wrote another target of the same DAG task, so the
developer's own repair loop writes it before commit instead of the QA judge sending the whole build back.

A target the repository already holds (the loop's `preexisting_files`) is present. A target the draft holds but the
assembled tree lacks (the platform's assembly removed it) and a path that is a
directory of the tree, or lies under a tree file, are not reported (developer_agent.plan_targets.missing_plan_targets).
Registered by the developer handler only on a full build (no QA / deploy repair: those may edit only the files they
were given, and the tree they repair already passed this check). Read-only; exact path membership only (Invariant 2):
no file content is read, nothing is rewritten.
"""
from __future__ import annotations

import json
from typing import Any, List, Sequence

try:
    from shared.diagnostics import Diagnostic, ErrorClass
except ImportError:  # pragma: no cover
    from ...shared.diagnostics import Diagnostic, ErrorClass  # type: ignore

from ..plan_targets import PlanTarget, missing_plan_targets

CODE = "PLAN.TARGET_FILE_MISSING"
VALIDATOR_ID = "V-PLAN-TARGETS"
MAX_LISTED_SIBLINGS = 12


def target_hint(target: PlanTarget) -> str:
    """The create hint: platform facts only (the exact path, the DAG task id, its other target paths)."""
    task = f"task {target.task_id}" if target.task_id else "a task"
    siblings = list(target.siblings[:MAX_LISTED_SIBLINGS])
    also = f" (its other target files: {json.dumps(siblings)})" if siblings else ""
    return (f"The architect's plan ({task}{also}) names this exact path as a file of the build, and the QA reviewer "
            f"checks that it exists. Write it at exactly this path with the content that task asks of it. If that "
            f"code already lives in another file of the service, keep that file and make this one the module the "
            f"plan names (it may import from the other file); never create an import cycle.")


class PlanTargetValidator:
    id, tool = VALIDATOR_ID, "schema"

    def __init__(self, targets: Sequence[PlanTarget] = ()):
        self.targets = tuple(targets)

    def validate(self, ctx: Any) -> List[Diagnostic]:
        out: List[Diagnostic] = []
        # RT F1: the repository's files (the assembled tree does not carry its app files; the commit keeps them)
        repository = (getattr(ctx, "extras", None) or {}).get("preexisting_files") or {}
        for t in missing_plan_targets(self.targets, ctx.files, ctx.draft, repository):
            out.append(Diagnostic(tool="schema", code=CODE, severity="error", error_class=ErrorClass.CODE_DEFECT,
                                  file=t.path, source="precommit", iteration=ctx.iteration,
                                  message=f"{t.path} is a target file of the architect's plan"
                                          f"{f' (task {t.task_id})' if t.task_id else ''} and is not in the build",
                                  hint=target_hint(t)))
        return out


def register(stack: Any, targets: Sequence[PlanTarget]) -> None:
    """Registered only with at least one required target (none: the stack is unchanged)."""
    if targets:
        stack.register(PlanTargetValidator(targets), "blocking")


__all__ = ["CODE", "VALIDATOR_ID", "PlanTargetValidator", "register", "target_hint"]
