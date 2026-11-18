"""TI-3 (typed IaC plan §2.7, §4 TI-3): precommit validators of the typed-intent path. Registered only when the
developer dispatch runs in intent mode (build_step1_stack(iac_intent=...)); with mode "off" none is registered.

| id            | code(s)                                                    | mode     |
| :------------ | :--------------------------------------------------------- | :------- |
| V-IAC         | the intent gate's findings: JSON.OUTPUT_INVALID, IAC.*, TOPOLOGY.CYCLE, FACT.MISSING (PLATFORM_DEFECT), IAC.INTENT_MISSING, IAC.REALIZATION_EXPORT_MISSING | blocking |
| V-IAC-PATH    | PATH.IAC_HCL_NOT_ALLOWED (an AI-written .tf / .tf.json under infra/; never dropped silently) | blocking |
| V-IAC-RENDER  | PLATFORM.INTENT_GATE_GAP (defense in depth: a policy table hit in the rendered custom.tf.json can only be a gate gap) | blocking |

The gate itself runs in the assembly (it must pass before anything is rendered); V-IAC reports exactly what that
gate found for the assembled tree (repair_loop.Assembled.iac_intent), so the finding and the render are one decision.
Exact checks only; nothing here mutates the tree.
"""
from __future__ import annotations

import json
from typing import Any, List

try:
    from shared import iac_intent as II
    from shared.diagnostics import Diagnostic, ErrorClass
except ImportError:  # pragma: no cover
    from ...shared import iac_intent as II  # type: ignore
    from ...shared.diagnostics import Diagnostic, ErrorClass  # type: ignore

from ..assembly import index_blocks
from ..iac_intent_contract import IAC_HCL_NOT_ALLOWED_CODE, INTENT_PATH, RENDER_PATH, is_ai_iac_hcl_path
from . import policy_tables as T
from .base import ValidationContext, ValidatorUnavailable

GATE_GAP_CODE = "PLATFORM.INTENT_GATE_GAP"
HINT_IAC_HCL = ("With the typed IaC intent the platform renders all Terraform. Move every block of this file into "
                "infra/workload/iac_intent.json (a golden-module instance or an allowed resource) and return this file "
                "with empty content.")
_FORBIDDEN_KEYS = frozenset({"count", "for_each", "provider", "provisioner", "connection", "dynamic"})


def _d(**kw: Any) -> Diagnostic:
    kw.setdefault("source", "precommit")
    kw.setdefault("severity", "error")
    return Diagnostic(**kw)


class IntentGateValidator:
    id, tool = "V-IAC", "schema"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        asm = ctx.extras.get("iac_intent")
        if asm is None:   # registered on the intent path only: the assembly must have run the gate
            raise ValidatorUnavailable("the typed IaC intent gate did not run on this tree")
        return [d.model_copy(update={"iteration": ctx.iteration}) for d in asm.diagnostics]


class IacHclPathValidator:
    """A non-empty `.tf` / `.tf.json` file under infra/ that this run's LLM wrote (the draft) is refused, one finding
    per top-level block (so a repair that empties the file has a diagnosed justification for each removed block,
    repair_loop.REMOVAL_CODES), or one per file when it does not parse as HCL / is a .tf.json file."""

    id, tool = "V-IAC-PATH", "path"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        out: List[Diagnostic] = []
        for path in sorted(ctx.draft):
            text = ctx.draft.get(path)
            if not is_ai_iac_hcl_path(path) or not isinstance(text, str) or not text.strip():
                continue
            common = dict(tool="path", code=IAC_HCL_NOT_ALLOWED_CODE, file=path, iteration=ctx.iteration,
                          hint=HINT_IAC_HCL, error_class=ErrorClass.CODE_DEFECT)
            blocks = index_blocks(text) if path.endswith(".tf") else None
            if not blocks:
                out.append(_d(message=f"{path}: the AI may not write Terraform files under infra/ (typed IaC intent)",
                              **common))
                continue
            for b in blocks:
                for k in b.keys:
                    out.append(_d(block_address=k, line=b.start, end_line=b.end,
                                  message=f"{k} is declared in Terraform; with the typed IaC intent it belongs in "
                                          f"{INTENT_PATH}", **common))
        return out


class RenderedIntentPolicyValidator:
    """Defense in depth (plan §2.7 V2): the rendered custom.tf.json against the exact policy tables V2a applies to
    HCL. The intent gate makes every one of these inexpressible, so a hit is a gate gap: PLATFORM_DEFECT (counted;
    target 0), never routed to the AI."""

    id, tool = "V-IAC-RENDER", "policy"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        text = ctx.files.get(RENDER_PATH)
        asm = ctx.extras.get("iac_intent")
        if not isinstance(text, str) or asm is None or RENDER_PATH not in (asm.rendered or ()):
            return []
        try:
            doc = json.loads(text)
        except ValueError:
            return [self._gap("the rendered custom.tf.json is not JSON", None, ctx)]
        out: List[Diagnostic] = []
        out += [self._gap(f"top-level key {k!r} in the render", None, ctx) for k in sorted(doc)
                if k not in ("//", "module", "resource", "output")]

        # RT F4: a meta-argument is meaningful only at body depth (module.<name>.<key>, resource.<type>.<name>.<key>);
        # deeper keys are data (labels, metadata, nested block bodies the gate walked against the schema). `//`
        # (provenance) is refused everywhere below the top level.
        bodies = [(f"module.{n}", b) for n, b in sorted((doc.get("module") or {}).items())]
        bodies += [(f"{t}.{n}", b) for t, named in sorted((doc.get("resource") or {}).items())
                   for n, b in sorted((named or {}).items())]
        for addr, body in bodies:
            for k in sorted(body if isinstance(body, dict) else ()):
                if k in _FORBIDDEN_KEYS:
                    out.append(self._gap(f"meta-argument {k!r} in {addr}", addr, ctx))

        def walk(v: Any, where: str) -> None:
            if isinstance(v, dict):
                for k, x in v.items():
                    if k == "//":
                        out.append(self._gap(f"comment key '//' at {where}", None, ctx))
                    walk(x, f"{where}/{k}")
            elif isinstance(v, list):
                for i, x in enumerate(v):
                    walk(x, f"{where}/{i}")
        for kind in ("module", "resource", "output"):
            walk(doc.get(kind) or {}, f"/{kind}")
        # TI-3j: the platform's own API-only resources (exact table bodies, shared.iac_intent.api_only_resources) are
        # the one platform-owned type the render may hold; any other google_project_service stays a gate gap.
        platform_api_only = {(t, n): b for svc in II.API_ONLY_SERVICES for t, n, b in II.api_only_resources(svc)}
        for rtype, named in sorted((doc.get("resource") or {}).items()):
            for name, body in sorted((named or {}).items()):
                addr = f"{rtype}.{name}"
                if platform_api_only.get((rtype, name)) == body:
                    continue
                if (rtype in T.FORBIDDEN_RESOURCE_TYPES or rtype.endswith(T.AUTHORITATIVE_IAM_SUFFIXES)
                        or rtype in T.PLATFORM_OWNED_TYPES):
                    out.append(self._gap(f"{rtype} is forbidden / platform-owned", addr, ctx))
                if rtype.endswith(T.IAM_TYPE_SUFFIXES) and isinstance(body, dict):
                    role = body.get("role")
                    if role in T.PRIVILEGED_ROLES or (rtype, role) in T.PLATFORM_OWNED_BINDINGS:
                        out.append(self._gap(f"role {role} on {rtype}", addr, ctx))
                    elif rtype in II.PROJECT_WIDE_GRANT_TYPES and role in II.PROJECT_WIDE_DENIED_ROLES:
                        # OVERBROAD-SECRET-GRANT: the gate refuses it (IAC.PROJECT_WIDE_GRANT); a hit is a gate gap
                        out.append(self._gap(f"project-wide role {role} on {rtype}", addr, ctx))
                    if body.get("member") in T.PUBLIC_MEMBERS:
                        out.append(self._gap(f"public member on {rtype}", addr, ctx))
        return out

    @staticmethod
    def _gap(what: str, block: Any, ctx: ValidationContext) -> Diagnostic:
        return _d(tool="policy", code=GATE_GAP_CODE, file=RENDER_PATH, block_address=block, iteration=ctx.iteration,
                  error_class=ErrorClass.PLATFORM_DEFECT,
                  message=f"intent gate gap: {what} (the gate must make this inexpressible)")


def register(stack: Any, iac_intent: Any) -> None:
    """Register the intent-path validators (build_step1_stack(iac_intent=...)); `iac_intent` is the run's
    iac_intent_contract.IntentRun (None registers nothing)."""
    if iac_intent is None:
        return
    stack.register(IntentGateValidator(), "blocking")
    stack.register(IacHclPathValidator(), "blocking")
    stack.register(RenderedIntentPolicyValidator(), "blocking")
