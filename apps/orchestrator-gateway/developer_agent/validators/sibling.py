"""V2f: sibling Cloud Run URL wiring (Step 2 S2-D, register HS-65; plan rev 2 §3.4 D1 (5)/(6)).

The generator binds a sibling's `service_uri` only under the exact env keys the caller's code reads
(`sibling_wiring.plan_sibling_wiring`). These validators re-derive the same plan on the assembled tree, for every
compute-cloudrun caller (main.tf's `module "compute"` and every secondary module in the bespoke root files), so what
the narrowing did not bind is visible in the run record:

| id       | code                       | when                                                                  | mode        |
| V2f      | IAC.SIBLING_URI_UNBOUND    | a sibling exists and the caller reads none of its four keys, or the   | report_only |
|          |                            | caller has no code (detail.reason: not_read / no_token_match /        |             |
|          |                            | caller_unresolved; candidate keys and unmatched URI reads listed);    |             |
|          |                            | or the sibling has for_each/count (not_addressable, code RT F6)       |             |
| V2f-not- | IAC.SIBLING_URI_UNBOUND    | the plan binds a key the caller's code reads exactly, but the         | blocking    |
| written  |                            | caller's env_vars does not carry it (not_written, code RT F2; owner   | (HS-65b)    |
|          |                            | row HS-65b): routed like any finding (AI file -> repair)              |             |
| V2f-cycle| IAC.SIBLING_URI_CYCLE      | services read each other's URL keys (A->B->A, or a ring), or a read   | blocking    |
|          |                            | closes a loop with an env_vars reference already written in HCL       |             |
|          |                            | (code RT F1): the platform binds none of those read edges (AGENTS     |             |
|          |                            | invariant 6); one diagnostic per reading Python file, routed to its   |             |
|          |                            | author                                                                |             |

Pure readers: no writes, no LLM, decisions by python-hcl2 structure and the exact env-read set only.
"""
from __future__ import annotations

import json
from typing import List, Optional, Tuple

try:
    from shared.diagnostics import Diagnostic
except ImportError:  # pragma: no cover
    from ...shared.diagnostics import Diagnostic  # type: ignore

from ..assembly import NON_BESPOKE_ROOT, WORKLOAD, bespoke_root_text, index_blocks
from ..sibling_wiring import (REASON_CALLER_UNRESOLVED, REASON_NOT_WRITTEN, _is_cloud_run_module_source,
                              compute_cloudrun_modules, literal_string, module_env_refs, plan_sibling_wiring)
from .base import ValidationContext

MAIN_TF = WORKLOAD + "main.tf"


def _is_root_tf(path: str) -> bool:
    return path.startswith(WORKLOAD) and path.endswith(".tf") and "/" not in path[len(WORKLOAD):]


def _callers(ctx: ValidationContext) -> List[Tuple[str, str, Optional[str], int, int]]:
    """(file, module label, caller service or None, start, end) for every compute-cloudrun caller module."""
    out: List[Tuple[str, str, Optional[str], int, int]] = []
    for b in index_blocks(ctx.files.get(MAIN_TF) or "") or []:
        if b.kind == "module" and b.labels and b.labels[0] == "compute" and \
                _is_cloud_run_module_source((b.body or {}).get("source")):
            out.append((MAIN_TF, "compute", literal_string((b.body or {}).get("service_name")), b.start, b.end))
    for path in sorted(p for p in ctx.files if _is_root_tf(p) and p not in NON_BESPOKE_ROOT):
        text = ctx.files.get(path)
        if isinstance(text, str):
            for m in compute_cloudrun_modules(text):
                out.append((path, m.label, m.service, m.start, m.end))
    return out


class SiblingUriValidator:
    """`cycles=True` -> V2f-cycle. Otherwise `not_written` selects the IAC.SIBLING_URI_UNBOUND findings: True ->
    only reason=not_written (V2f-not-written, blocking, register HS-65b); False -> only the other reasons (V2f,
    report-only); None -> both (direct callers and tests)."""
    id, tool = "V2f", "platform"

    def __init__(self, cycles: bool = False, not_written: Optional[bool] = None):
        self.cycles = cycles
        self.not_written = not_written
        if cycles:
            self.id = "V2f-cycle"
        elif not_written:
            self.id = "V2f-not-written"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        callers = _callers(ctx)
        if not callers:
            return []
        bespoke = bespoke_root_text(ctx.files)
        out: List[Diagnostic] = []
        seen: set = set()
        for path, label, service, start, end in callers:
            plan = plan_sibling_wiring(bespoke, ctx.files, service, caller_module=label,
                                       main_tf=ctx.files.get(MAIN_TF))
            if self.cycles:
                for w in plan.withheld:
                    for f in w["files"]:
                        key = (f, w["key"])
                        if key in seen:
                            continue
                        seen.add(key)
                        others = [s for s in w["cycle"] if s != w["caller"]]
                        refs = (f" The loop also uses these references written in Terraform: "
                                f"{'; '.join(w['hcl_refs'])}." if w.get("hcl_refs") else "")
                        out.append(Diagnostic(
                            tool="platform", code="IAC.SIBLING_URI_CYCLE", severity="error", source="precommit",
                            file=f, symbol=w["key"], iteration=ctx.iteration,
                            message=(f"services {', '.join(w['cycle'])} read each other's service URL "
                                     f"({w['caller']} reads {w['key']}); a Cloud Run URL is a Terraform output, so "
                                     f"binding these reads would make a dependency cycle. {w['key']} is not set."
                                     + refs),
                            detail=json.dumps(w, sort_keys=True),
                            hint=(f"Break the mutual dependency: {w['caller']} and {', '.join(others)} must not both "
                                  "read the other's URL from the environment. Keep the read in one direction only "
                                  "(the other side can be called by it, or use a Pub/Sub topic), then return the "
                                  "whole file.")))
                continue
            written = module_env_refs(ctx.files.get(path)).get(label, {})
            for key, ref in (sorted(plan.bindings.items()) if self.not_written is not False else []):
                want = tuple(ref.split("."))
                if written.get(key) == want:
                    continue
                detail = {"caller": plan.caller, "sibling_module": ".".join(want[:2]), "key": key,
                          "reason": REASON_NOT_WRITTEN, "candidate_keys": [key], "unmatched_uri_reads": []}
                out.append(Diagnostic(
                    tool="platform", code="IAC.SIBLING_URI_UNBOUND", severity="error", source="precommit",
                    file=path, line=start or None, end_line=end or None, block_address=f"module.{label}",
                    symbol=".".join(want[:2]), iteration=ctx.iteration,
                    message=(f"module.{label}: the code of {plan.caller} reads {key}, but the module's env_vars "
                             f"does not set it to {ref}"),
                    detail=json.dumps(detail, sort_keys=True),
                    hint=f'Set "{key}" = {ref} in module.{label} env_vars.'))
            for u in (plan.unbound if not self.not_written else []):
                if u["reason"] == REASON_CALLER_UNRESOLVED:
                    msg = (f"module.{label}: no Python code under apps/<service>/ for service "
                           f"{service or '(unresolved)'}, so {u['sibling']}'s URL ({u['sibling_module']}.service_uri) "
                           "is not bound into its environment")
                else:
                    msg = (f"module.{label}: the code of {u['caller']} reads none of "
                           f"{', '.join(u['candidate_keys'])}, so {u['sibling']}'s URL is not bound into its "
                           "environment")
                out.append(Diagnostic(
                    tool="platform", code="IAC.SIBLING_URI_UNBOUND", severity="error", source="precommit",
                    file=path, line=start or None, end_line=end or None, block_address=f"module.{label}",
                    symbol=u["sibling_module"], iteration=ctx.iteration, message=msg,
                    detail=json.dumps(u, sort_keys=True),
                    hint=(f"To receive {u['sibling']}'s URL, read exactly one of {', '.join(u['candidate_keys'])} "
                          "with os.environ / os.getenv or a pydantic BaseSettings field.")))
        return out
