"""DEPLOY-FAILURE-OWNER-ROUTER (register row DEPLOY-FAILURE-OWNER-ROUTER, owner 11-13; plan
docs/planning/deploy-failure-owner-router-plan.md): who can change what made a deploy fail?

Every failed deploy result gets one route record (`failure_route`) with an owner:

- DEVELOPER           every error diagnostic of `validate -json` / `plan -json` is in a file the developer wrote, or the
                      result carries the typed class IAC_DEFECT. The result is left unchanged (the workflow's bounded
                      developer remediation, as before).
- PLATFORM_DEFECT     an error diagnostic in a vendored golden-module file, a platform-rendered root file or a root file
                      the deploy wrote itself.
- OPERATOR_REQUIRED   an error diagnostic in a user-owned file (human*.tf, Terraform override files, legacy custom.tf
                      beside an intent).
- PROVIDER_TRANSIENT  the gated plan failed and the identical read-only re-plan succeeded (exit status of two runs of
                      the same command: the only typed transient evidence the engine gives).
- UNKNOWN             nothing typed says who can fix it (no file, an unattributable path, unparseable output, no engine
                      diagnostics: init, container build, the apply phase, ...).

A non-DEVELOPER result gets `error_class` (the owner; UNKNOWN -> DEPLOY_FAILURE_UNATTRIBUTED) and
`operator_required: true` (WF-OPERATOR-FLAG): the workflow stops for the operator and keeps the class
(workflows/main_orchestrator.yaml check_deploy_status -> handle_operator_deploy_failure). The workflow is unchanged.

Mixed owners: DEVELOPER only when EVERY error diagnostic is developer-owned; otherwise the first of
PLATFORM_DEFECT > OPERATOR_REQUIRED > UNKNOWN present (a non-developer error survives any developer rewrite).

Typed fields only (AGENTS.md invariant 2): the JSON line `type`, `diagnostic.severity`, `range.filename`, `range.start`,
`address` (display only), exit status, exact manifest / payload paths and exact basenames. No summary or detail text is
ever read for a decision. Pure functions (the only file-system read is `os.path.realpath` of a diagnostic's file inside
the workspace, to follow the workspace's `modules` symlinks).
"""
from __future__ import annotations

import hashlib
import json
import os
import posixpath
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

DEVELOPER = "DEVELOPER"
PLATFORM_DEFECT = "PLATFORM_DEFECT"
OPERATOR_REQUIRED = "OPERATOR_REQUIRED"
PROVIDER_TRANSIENT = "PROVIDER_TRANSIENT"
UNKNOWN = "UNKNOWN"
OWNERS = (DEVELOPER, PLATFORM_DEFECT, OPERATOR_REQUIRED, PROVIDER_TRANSIENT, UNKNOWN)
# precedence among non-developer owners of one failure's diagnostics (mixed-owner rule)
NON_DEVELOPER_PRECEDENCE = (PLATFORM_DEFECT, OPERATOR_REQUIRED, UNKNOWN)

# The deploy result's error_class per non-developer owner (none of them is in the workflow's operator list: the
# `operator_required` flag routes them; a non-empty class other than IAC_DEFECT can never reach increment_tf_retry).
ERROR_CLASS_BY_OWNER = {
    PLATFORM_DEFECT: "PLATFORM_DEFECT",
    OPERATOR_REQUIRED: "OPERATOR_REQUIRED",
    PROVIDER_TRANSIENT: "PROVIDER_TRANSIENT",
    UNKNOWN: "DEPLOY_FAILURE_UNATTRIBUTED",
}
ROUTER_ERROR_CLASSES = frozenset(ERROR_CLASS_BY_OWNER.values())
CODE_BY_OWNER = {
    PLATFORM_DEFECT: "APPLY.PLATFORM_DEFECT",
    OPERATOR_REQUIRED: "APPLY.OPERATOR_REQUIRED",
    PROVIDER_TRANSIENT: "APPLY.PROVIDER_TRANSIENT",
    UNKNOWN: "APPLY.FAILURE_UNATTRIBUTED",
}
ACTION_BY_OWNER = {
    PLATFORM_DEFECT: "the failing configuration is the platform's; a developer rewrite cannot change it. A StackVend "
                     "fix is needed (a relaunch fails the same way)",
    OPERATOR_REQUIRED: "the failing configuration is a person's file; change it in the repository, then relaunch",
    PROVIDER_TRANSIENT: "the failed plan did not fail again on an identical re-plan (this plan applied nothing; an "
                        "earlier pass of the same deploy may have). Re-run the deploy (Fast-Path Deploy)",
    UNKNOWN: "nothing typed names who can fix it, so it is not sent to the developer. Read the engine error",
}

IAC_DEFECT = "IAC_DEFECT"   # service.IAC_DEFECT_ERROR_CLASS: the server's own developer-owned refusals
FAILURE_ROUTE_FIELD = "failure_route"
# pipeline_executions/{trace} field the gateway's remediation guard reads (apps/orchestrator-gateway/gate_errors.py
# DEPLOY_FAILURE_ROUTE_FIELD; parity test)
STAGE_ROUTE_FIELD_PATH = "stages.terraform." + FAILURE_ROUTE_FIELD

PHASE_VALIDATE, PHASE_PLAN, PHASE_APPLY = "validate", "plan", "apply"
PHASE_INIT, PHASE_BUILD, PHASE_PREPARE, PHASE_UNKNOWN = "init", "build", "prepare", "unknown"
# The apply phase has no typed diagnostics (plan §3): its owner. One line to change if the owner decides otherwise.
APPLY_PHASE_OWNER = UNKNOWN

# Bases (why the owner was chosen; typed reasons, never engine text)
BASIS_DIAGNOSTICS = "ENGINE_JSON_DIAGNOSTICS"
BASIS_TYPED_CLASS = "TYPED_CLASS"
BASIS_PLAN_NOT_REPRODUCED = "PLAN_NOT_REPRODUCED"
BASIS_NO_DIAGNOSTICS = "NO_ERROR_DIAGNOSTICS"
BASIS_UNPARSEABLE = "ENGINE_OUTPUT_UNPARSEABLE"
BASIS_CLASSIFY_TIMED_OUT = "CLASSIFY_TIMED_OUT"
BASIS_CLASSIFY_NOT_RUN = "CLASSIFY_NOT_RUN"
BASIS_NO_ENGINE_RESULT = "NO_ENGINE_DIAGNOSTICS"
BASIS_APPLY_UNATTRIBUTED = "APPLY_UNATTRIBUTED"

# Per-finding reasons
R_NO_LOCATION = "NO_LOCATION"
R_USER_OWNED = "USER_OWNED_FILE"
R_GOLDEN_MODULE = "GOLDEN_MODULE"
R_PLATFORM_RENDERED = "PLATFORM_RENDERED"
R_SERVER_WRITTEN = "SERVER_WRITTEN"
R_WORKLOAD_IAC = "WORKLOAD_IAC"
R_INTENT_ENTRY = "INTENT_ENTRY"
R_PLATFORM_FILE = "PLATFORM_FILE"
R_UNATTRIBUTED = "UNATTRIBUTED"
R_UNPARSED = "UNPARSED"

WORKLOAD_PREFIX = "infra/workload/"
# Parity: shared/artifact_ownership.PLATFORM_RENDERED_FLOOR minus the non-Terraform topology.json
# (tests/test_deploy_failure_owner_router.py). The MCP image does not ship artifact_ownership.
PLATFORM_RENDERED_FLOOR = frozenset({"infra/workload/main.tf", "infra/workload/variables.tf",
                                     "infra/workload/outputs.tf", "infra/workload/moved.tf",
                                     "infra/workload/services.tf"})
MAX_FINDINGS = 20
SUMMARY_CAP = 300


def error_digest(text: Any) -> Optional[str]:
    """sha256 (hex) of the UTF-8 bytes of a deploy result's error text; None for no text. The gateway compares it with
    the workflow's `tf_remediation_context` (exact pairing of a route with the failure it describes)."""
    if not isinstance(text, str) or not text:
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def remediation_text(result: Mapping[str, Any]) -> str:
    """The text the callback delivers as `error` for a failed result (tf-applier / in-process deploy: the result's
    error, else stderr, else stdout); "" when none (the callers then add their own fallback, which never matches)."""
    for key in ("error", "stderr", "stdout"):
        val = result.get(key)
        if isinstance(val, str) and val:
            return val
    return ""


def error_diagnostics_from_stream(stdout: Any) -> Optional[List[Dict[str, Any]]]:
    """The error diagnostics of a `tofu plan -json` stream (one JSON object per line, `type` "diagnostic"). None when
    no line is a JSON object (not a machine-readable stream)."""
    if not isinstance(stdout, str):
        return None
    parsed_any = False
    out: List[Dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if not isinstance(msg, dict):
            continue
        parsed_any = True
        diag = msg.get("diagnostic")
        if msg.get("type") == "diagnostic" and isinstance(diag, dict) and diag.get("severity") == "error":
            out.append(diag)
    return out if parsed_any else None


def error_diagnostics_from_validate(stdout: Any) -> Optional[List[Dict[str, Any]]]:
    """The error diagnostics of `tofu validate -json` (one JSON document with a `diagnostics` list); None when it is
    not such a document."""
    try:
        doc = json.loads(stdout) if isinstance(stdout, str) else None
    except ValueError:
        return None
    diags = doc.get("diagnostics") if isinstance(doc, dict) else None
    if not isinstance(diags, list):
        return None
    return [d for d in diags if isinstance(d, dict) and d.get("severity") == "error"]


def _range_of(diag: Mapping[str, Any]) -> Tuple[str, Optional[int]]:
    rng = diag.get("range") if isinstance(diag.get("range"), dict) else {}
    fname = rng.get("filename") if isinstance(rng.get("filename"), str) else ""
    start = rng.get("start") if isinstance(rng.get("start"), dict) else {}
    line = start.get("line") if isinstance(start.get("line"), int) else None
    return fname, line


def workspace_relpath(fname: str, workspace_dir: str) -> str:
    """The diagnostic file's path relative to the workspace after following symlinks (the deploy links `modules` and
    `../modules` to the workspace's `infra/modules`; OpenTofu reports a module reached through `../modules` by its
    resolved ABSOLUTE path), posix; the normalised name when it resolves outside the workspace or the workspace is not
    an absolute path."""
    norm = posixpath.normpath(fname.replace(os.sep, "/"))
    if not (workspace_dir and os.path.isabs(workspace_dir)):
        return norm
    root = os.path.realpath(workspace_dir)
    real = os.path.realpath(fname if os.path.isabs(fname) else os.path.join(workspace_dir, fname))
    if real == root or not real.startswith(root + os.sep):
        return norm
    return os.path.relpath(real, root).replace(os.sep, "/")


def manifest_repo_path(fname: str, manifest: Iterable[str]) -> Optional[str]:
    """The repository path of a workspace file, by exact manifest membership (the deploy flattens infra/workload/ into
    the workspace root, subdirectories kept): infra/workload/<fname> when the manifest holds it, else None."""
    cand = WORKLOAD_PREFIX + fname
    return cand if cand in frozenset(manifest) else None


def legacy_finding_owner(fname: str, *, workspace_dir: str, manifest: Iterable[str],
                         is_golden: Callable[[str], bool], user_owned: Callable[[str], bool]) -> Tuple[str, str, str]:
    """(owner, reason, shown path) of one diagnostic file on a workspace WITHOUT a typed intent (the AI writes HCL)."""
    if not fname:
        return UNKNOWN, R_NO_LOCATION, "<unlocated>"
    manifest = frozenset(manifest)
    rel = workspace_relpath(fname, workspace_dir)
    if user_owned(fname) or user_owned(rel):
        return OPERATOR_REQUIRED, R_USER_OWNED, manifest_repo_path(rel, manifest) or rel
    if is_golden(rel):
        return PLATFORM_DEFECT, R_GOLDEN_MODULE, rel
    repo = manifest_repo_path(rel, manifest)
    if repo is None:
        if "/" not in rel and not rel.startswith(".") and rel not in manifest:
            return PLATFORM_DEFECT, R_SERVER_WRITTEN, "<workspace>/" + rel   # backend.tf, tfvars, access var file
        return UNKNOWN, R_UNATTRIBUTED, rel
    if repo in PLATFORM_RENDERED_FLOOR:
        return PLATFORM_DEFECT, R_PLATFORM_RENDERED, repo
    return DEVELOPER, R_WORKLOAD_IAC, repo


def _finding(owner: str, reason: str, file: str, line: Optional[int], diag: Mapping[str, Any]) -> Dict[str, Any]:
    summary = diag.get("summary") if isinstance(diag.get("summary"), str) else ""
    address = diag.get("address") if isinstance(diag.get("address"), str) else None
    return {"owner": owner, "reason": reason, "file": file, "line": line, "address": address,
            "summary": summary[:SUMMARY_CAP]}


def _aggregate(findings: List[Dict[str, Any]], phase: str, basis: str) -> Dict[str, Any]:
    owners = {f["owner"] for f in findings}
    if not findings:
        owner, basis = UNKNOWN, BASIS_NO_DIAGNOSTICS
    elif owners == {DEVELOPER}:
        owner = DEVELOPER
    else:
        owner = next(o for o in NON_DEVELOPER_PRECEDENCE if o in owners)
    # the deciding findings first (the gateway and the error text show the first one)
    ordered = sorted(findings, key=lambda f: (f["owner"] != owner, OWNERS.index(f["owner"])))
    return route(owner, phase, basis, ordered)


def route(owner: str, phase: str, basis: str, findings: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    findings = list(findings or [])
    return {"owner": owner, "phase": phase, "basis": basis,
            "error_class": ERROR_CLASS_BY_OWNER.get(owner),
            "findings": findings[:MAX_FINDINGS], "findings_truncated": len(findings) > MAX_FINDINGS}


def route_from_legacy_diagnostics(diags: Optional[List[Dict[str, Any]]], *, phase: str, workspace_dir: str,
                                  manifest: Iterable[str], is_golden: Callable[[str], bool],
                                  user_owned: Callable[[str], bool]) -> Dict[str, Any]:
    if diags is None:
        return route(UNKNOWN, phase, BASIS_UNPARSEABLE)
    manifest = frozenset(manifest)
    findings = []
    for d in diags:
        fname, line = _range_of(d)
        owner, reason, shown = legacy_finding_owner(fname, workspace_dir=workspace_dir, manifest=manifest,
                                                    is_golden=is_golden, user_owned=user_owned)
        findings.append(_finding(owner, reason, shown, line, d))
    return _aggregate(findings, phase, BASIS_DIAGNOSTICS)


def route_from_report(report: Optional[Mapping[str, Any]], *, phase: str,
                      raw_diags: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """The route of an intent workspace's typed report (service.apply_validation_report, unchanged): CODE_DEFECT (an
    intent entry) -> DEVELOPER; BROWNFIELD_CONFLICT -> OPERATOR_REQUIRED; PLATFORM_DEFECT on an unlocated / unparsed
    diagnostic -> UNKNOWN, on any other file -> PLATFORM_DEFECT. `raw_diags` (same order) adds the engine's address."""
    if not isinstance(report, Mapping) or report.get("status") != "FAIL":
        return route(UNKNOWN, phase, BASIS_UNPARSEABLE)
    findings = []
    errors = [d for d in report.get("diagnostics") or [] if isinstance(d, dict) and d.get("severity") == "error"]
    raws = [d for d in raw_diags or [] if isinstance(d, dict)]
    for i, d in enumerate(errors):
        cls, file = d.get("error_class"), d.get("file") or "<unlocated>"
        if d.get("code") == "TF.UNPARSED_APPLY_ERROR":
            owner, reason = UNKNOWN, R_UNPARSED
        elif cls == "CODE_DEFECT":
            owner, reason = DEVELOPER, R_INTENT_ENTRY
        elif cls == "BROWNFIELD_CONFLICT":
            owner, reason = OPERATOR_REQUIRED, R_USER_OWNED
        elif file == "<unlocated>":
            owner, reason = UNKNOWN, R_NO_LOCATION
        else:
            owner, reason = PLATFORM_DEFECT, R_PLATFORM_FILE
        raw = raws[i] if i < len(raws) and len(raws) == len(errors) else {}
        f = _finding(owner, reason, file, d.get("line") if isinstance(d.get("line"), int) else None,
                     {"summary": d.get("message") or "", "address": raw.get("address") or d.get("block_address")})
        findings.append(f)
    return _aggregate(findings, phase, BASIS_DIAGNOSTICS)


def route_of_typed_result(result: Mapping[str, Any], phase: str) -> Dict[str, Any]:
    """A result that already has a typed class keeps it: IAC_DEFECT (not flagged) is DEVELOPER, every other typed class
    is not the developer's (its own workflow route is unchanged)."""
    cls = result.get("error_class")
    if cls == IAC_DEFECT and result.get("operator_required") is not True:
        r = route(DEVELOPER, phase, BASIS_TYPED_CLASS)
    else:
        r = route(OPERATOR_REQUIRED if result.get("operator_required") is True else UNKNOWN, phase, BASIS_TYPED_CLASS)
        r["error_class"] = cls if isinstance(cls, str) else None
    return r


def _headline(r: Mapping[str, Any]) -> str:
    f = (r.get("findings") or [None])[0]
    if not f:
        return ""
    where = f["file"] + (f":{f['line']}" if f.get("line") else "")
    return (f"{f['address']} in {where}" if f.get("address") else where) + f" ({f['reason']})"


def apply_route(result: Mapping[str, Any], r: Mapping[str, Any]) -> Dict[str, Any]:
    """The deploy result with its route. DEVELOPER and typed results: unchanged apart from the route record. Every
    other owner: the typed class, `operator_required: true`, a code, and the error text led by class, phase, owner and
    the first deciding finding (the engine's original text kept after it)."""
    out = dict(result)
    out[FAILURE_ROUTE_FIELD] = dict(r)
    owner = r.get("owner")
    if owner == DEVELOPER or r.get("basis") == BASIS_TYPED_CLASS:
        return out
    cls = ERROR_CLASS_BY_OWNER[owner]
    head = _headline(r)
    original = remediation_text(result)
    out.update(
        error_class=cls, operator_required=True, code=CODE_BY_OWNER[owner],
        error=(f"{cls} ({r.get('phase')} failed; owner {owner}; {r.get('basis')})"
               + (f": {head}" if head else "") + f". {ACTION_BY_OWNER[owner]}."
               + (f" Engine error: {original}" if original else "")))
    return out
