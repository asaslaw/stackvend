"""Lane 10 (FD-51) precommit validator V-T3: compute declared by the LLM (plan R2 §9).

On the typed-topology path every compute service is rendered by the platform (`module "compute"` in main.tf and
`module "compute_<service>"` blocks synthesized from the topology). Compute that this run's LLM IaC declares itself
- a golden compute module under any other label (`compute_service_must`, `compute_service_account`, ...: eval
baseline FD-30, 13/24 committed trees), a `google_cloud_run_v2_service` or a `google_container_cluster` - is a
phantom service: `TOPOLOGY.COMPUTE_DECLARED_BY_LLM`, CODE_DEFECT, repaired by the IaC persona (the fix is a
deletion). Exact checks only: the block kind / resource type, and the module `source` resolved to
`infra/modules/<golden compute dir>` (parent equality, set membership). Never mutates; registered only when the run
has a topology. `google_cloud_run_v2_job` is deliberately not flagged (a scheduled batch Job the spec asks for has no
topology kind yet; open question in the lane 10 report).
RT14-F3: a `google_cloud_run_v2_service` the multi-service reconcile kept as the repository's own (exactly its
(path, key) in AssemblyRecord.kept_repository, RT14-12) is not flagged: it is a person's service, not this run's
phantom compute, and deleting it is exactly what RT14-12 stopped. Exact pair equality; nothing else changes.
"""
from __future__ import annotations

import posixpath
from typing import Any, List

try:
    from shared.diagnostics import Diagnostic, ErrorClass
    from shared.service_topology import KIND_FOR_MODULE_DIR
except ImportError:  # pragma: no cover
    from ...shared.diagnostics import Diagnostic, ErrorClass  # type: ignore
    from ...shared.service_topology import KIND_FOR_MODULE_DIR  # type: ignore

from .base import ValidationContext
from .step1 import _llm_blocks

LLM_COMPUTE_RESOURCE_TYPES = frozenset({"google_cloud_run_v2_service", "google_container_cluster"})
CODE = "TOPOLOGY.COMPUTE_DECLARED_BY_LLM"


def _golden_compute_dir(source: Any, declaring_path: str) -> bool:
    if not isinstance(source, str) or "${" in source or not source.startswith(("./", "../")):
        return False
    parent, base = posixpath.split(posixpath.normpath(posixpath.join(posixpath.dirname(declaring_path), source)))
    return parent == "infra/modules" and base in KIND_FOR_MODULE_DIR


class LlmComputeValidator:
    id, tool = "V-T3", "topology"

    def __init__(self, topology: Any):
        self.topology = topology
        self.platform_labels = frozenset(topology.label(n) for n in topology.names)

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        out: List[Diagnostic] = []
        services = ", ".join(f"{n} ({self.topology.kind(n)})" for n in self.topology.names) or "none"
        hint = (f"Compute is rendered by the platform from the service topology (services: {services}). Delete this "
                f"block; reference a service through module.<label> outputs only if an edge wires it.")
        kept = dict(getattr(ctx.assembly, "kept_repository", None) or {})   # RT14-F3: key -> path
        for path, b in _llm_blocks(ctx):
            if b.kind == "resource" and kept.get(b.key) == path:
                continue   # RT14-F3: the repository's own Cloud Run service, kept by RT14-12
            common = dict(file=path, line=b.start, end_line=b.end, block_address=b.key, iteration=ctx.iteration,
                          source="precommit", severity="error", error_class=ErrorClass.CODE_DEFECT, tool="topology",
                          code=CODE, hint=hint)
            if b.kind == "module" and b.labels and b.labels[0] not in self.platform_labels and \
                    _golden_compute_dir((b.body or {}).get("source"), path):
                out.append(Diagnostic(message=f"module \"{b.labels[0]}\" deploys compute that is not in the "
                                              f"service topology", **common))
            elif b.kind == "resource" and len(b.labels) >= 2 and b.labels[0] in LLM_COMPUTE_RESOURCE_TYPES:
                out.append(Diagnostic(message=f"{b.labels[0]}.{b.labels[1]} deploys compute that is not in the "
                                              f"service topology", **common))
        return out


WORKER_SCRIPT_CODE = "TOPOLOGY.WORKER_SCRIPT_MISSING"


class WorkerScriptValidator:
    """V-T6 (lane 10 RT F7): every gce-worker secondary needs its code, `apps/<worker>/startup.sh`, with at least one
    non-whitespace character. Exact path lookup in the assembled tree; without it the template would carry the module
    default (power off at once): a VM that boots and dies. CODE_DEFECT, routed as a file to create
    (repair_loop.CREATE_FILE_CODES) to the persona that wrote the worker's code; nobody did -> PLATFORM_DEFECT."""
    id, tool = "V-T6", "topology"

    def __init__(self, topology: Any):
        self.workers = tuple(s.name for s in topology.secondaries if s.kind == "gce-worker")

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        out: List[Diagnostic] = []
        for name in self.workers:
            path = f"apps/{name}/startup.sh"
            text = ctx.files.get(path)
            if isinstance(text, str) and text.strip():
                continue
            out.append(Diagnostic(
                tool="topology", code=WORKER_SCRIPT_CODE, severity="error", error_class=ErrorClass.CODE_DEFECT,
                file=path, iteration=ctx.iteration, source="precommit",
                message=f"gce-worker '{name}' has no startup script: {path} is "
                        f"{'missing' if text is None else 'empty'}",
                hint=f"Write {path}: the bash script every '{name}' VM runs at boot (Debian 12, no external IP: "
                     f"Google APIs only); it powers the VM off when done."))
        return out


def register(stack: Any, topology: Any) -> None:
    """Blocking when the run has a topology; nothing otherwise (the legacy path is unchanged)."""
    if topology is not None:
        stack.register(LlmComputeValidator(topology), "blocking")
        if any(s.kind == "gce-worker" for s in topology.secondaries):
            stack.register(WorkerScriptValidator(topology), "blocking")


__all__ = ["LlmComputeValidator", "WorkerScriptValidator", "register", "CODE", "WORKER_SCRIPT_CODE",
           "LLM_COMPUTE_RESOURCE_TYPES"]
