"""V2l (FD-4AQ W4, register AQ-4, owner 10-25, blocking): AI-written Terraform may not set up Google sign-in itself.

The Identity Platform sign-in configuration (and its client secret) is the platform's (register row 27b; rows 42/46
for private workloads). This validator runs the lane 19 report-only `access_policy_validator.validate` on the
LLM-owned IaC files of the run and keeps exactly the codes register row AQ-4 approves, as blocking, repairable
findings (the repair loop sends them back to the AI):

| id  | code                                  | when |
| V2l | POLICY.IDP_CONFIG_IN_IAC              | a `resource` of an Identity Platform IdP/config type (`access_policy_validator.IDP_RESOURCE_TYPES`), any workload |
| V2l | POLICY.IDP_CONFIG_IN_IAC              | a `module` whose `source` names the golden `workload_auth` module in a PRIVATE_IAP / PRIVATE_IAM workload |
| V2l | POLICY.IDP_SECRET_READER_FORBIDDEN    | shared sign-in client mode only: an IAM `role` that can read the sign-in secret (exact role table) or a custom role listing `firebaseauth.configs.get` |
| V2l | POLICY.PUBLIC_PRINCIPAL_IN_MODULE_CALL | FD-4CX-b (owner 10-29): a PRIVATE_IAP / PRIVATE_IAM workload whose AI-written `module` call (golden, registered or workload-local module) passes an exact `allUsers` / `allAuthenticatedUsers` literal in an argument (a string, or a string or key inside a literal list / object) |
| V2l | POLICY.UNCHECKABLE_FILE               | FD-4CX-b RT F2, PRIVATE_* only: an LLM-owned root variable file OpenTofu loads by itself (`terraform.tfvars.json`, `*.auto.tfvars`, `*.auto.tfvars.json`) that does not parse |

FD-4CX-b on the typed-intent path (generate mode): the AI writes no HCL there, and its module instances
(`infra/workload/iac_intent.json` `modules[]`, golden catalog modules only) are rendered by the platform into
`infra/workload/custom.tf.json`. The same exact check runs on the `module` blocks of that render (what deploys), and
a finding is reported on the intent file at the instance's address (`module.<name>`) when the renderer's provenance
map says the block is an intent entry; a public principal in a rendered module block that is NOT an intent entry is
the platform's own and is reported as PLATFORM_DEFECT (never sent to the AI, never a pass). A render that does not
parse is reported twice on purpose: here (`POLICY.UNCHECKABLE_FILE`, PLATFORM_DEFECT: this check could not run) and
by V-IAC-RENDER (`PLATFORM.INTENT_GATE_GAP`). Both stop the run as platform defects; keep both.

FD-4CX-b variable values (RT F2): in a PRIVATE_* workload, `var.NAME` in a module call resolves the way OpenTofu does
at the root: the platform's `infra/workload/terraform.tfvars`, then the LLM-owned root variable files OpenTofu also
loads by itself (`terraform.tfvars.json`, then every `*.auto.tfvars` / `*.auto.tfvars.json` in file-name order), each
later file replacing a variable's whole value, then the variable default. An LLM-owned one of those files that does
not parse is a repairable `POLICY.UNCHECKABLE_FILE` on that file (its values cannot be shown private), never a skip.
Without such a file (every workload today) nothing changes. Since AI-TFVARS-REFUSED (owner 10-29) such an AI file is
itself a blocking finding (V2n, `POLICY.TFVARS_NOT_ALLOWED`, validators/iac_file_kinds.py; a file equal to the
committed one is the person's and not judged there), so no run commits one the AI wrote or changed; this
reading is kept on purpose as defense in depth: V2n's mode can be overridden per validator id, and while the file
exists the module-call finding still names the exact argument the file makes public (both go back in one repair).

Not wired here (no owner row): `POLICY.PUBLIC_PRINCIPAL_FORBIDDEN` (V2a's `POLICY.PUBLIC_MEMBER` covers IAM members
today), `POLICY.ACCESS_POLICY_MISMATCH` (platform tfvars, not AI output) and `POLICY.UNCHECKABLE_FILE` for `.tf`
files (V1a-llm reports an unparseable LLM `.tf` file).

Provenance, never text: only files whose ownership is LLM-owned are passed (platform-vendored golden modules such as
`workload_auth` itself, platform-rendered files and the human architect's files are never judged), and a finding on a
block the platform synthesized inside an LLM file (`ctx.extras["platform_addresses"]`) is dropped, as in V2a/V2j.
Decisions are the lane 19 validator's exact parsed checks (python-hcl2 / json; no regex). Inputs are never mutated.

The run's access facts come from the developer's resolved access (`access_resolution.ResolvedAccess`): the mode
(record, else the compliance flags) and, only when an access record exists, its Google sign-in mode. Without access
facts (direct callers) only the mode-independent resource-type check runs.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Dict, List, Mapping, Optional, Tuple

import json
import posixpath

try:
    from shared import iac_intent as II
    from shared.diagnostics import Diagnostic, ErrorClass
except ImportError:  # pragma: no cover
    from ...shared import iac_intent as II  # type: ignore
    from ...shared.diagnostics import Diagnostic, ErrorClass  # type: ignore

from .. import access_policy_validator as apv
from ..assembly import index_blocks
from ..iac_intent_contract import INTENT_PATH, RENDER_PATH
from . import policy_tables as T
from .base import ValidationContext, ValidatorUnavailable
from .step1 import LLM_OWNED, _d

AQ4_CODES = frozenset({"POLICY.IDP_CONFIG_IN_IAC", "POLICY.IDP_SECRET_READER_FORBIDDEN"})
FD4CXB_CODES = frozenset({apv.MODULE_PUBLIC_PRINCIPAL_CODE})   # FD-4CX-b (owner 10-29)
KEPT_CODES = AQ4_CODES | FD4CXB_CODES
_HINTS = {
    "POLICY.IDP_CONFIG_IN_IAC": T.HINT_IDP_CONFIG,
    "POLICY.IDP_SECRET_READER_FORBIDDEN": T.HINT_IDP_SECRET_READER,
    apv.MODULE_PUBLIC_PRINCIPAL_CODE: T.HINT_PUBLIC_PRINCIPAL_IN_MODULE_CALL,
}
_IAC_SUFFIXES = (".tf", ".tf.json")
_ROOT_DIR = apv.ROOT_DIR
_ROOT_TFVARS_JSON = _ROOT_DIR + "/terraform.tfvars.json"
_AUTO_TFVARS_SUFFIXES = (".auto.tfvars", ".auto.tfvars.json")
UNCHECKABLE_CODE = "POLICY.UNCHECKABLE_FILE"


def root_variable_files(paths: Any) -> List[str]:
    """The root variable files OpenTofu loads by itself after `terraform.tfvars`, in its precedence order:
    `terraform.tfvars.json`, then `*.auto.tfvars` / `*.auto.tfvars.json` sorted by file name (exact names; root
    directory only)."""
    root = [p for p in paths if isinstance(p, str) and posixpath.dirname(p) == _ROOT_DIR]
    auto = sorted(p for p in root if p.endswith(_AUTO_TFVARS_SUFFIXES))
    return ([_ROOT_TFVARS_JSON] if _ROOT_TFVARS_JSON in root else []) + auto
_ROOT_TFVARS = apv.ROOT_TFVARS


class _AccessFacts:
    """The attributes `access_policy_validator.validate` reads, built from the run's resolved access."""

    def __init__(self, mode: Optional[str], google: Optional[str]):
        self.mode = mode
        self.sign_in = SimpleNamespace(google=google)
        self.allow_unauthenticated = mode == "PUBLIC_APP"
        self.enable_direct_iap = mode == "PRIVATE_IAP"

    @staticmethod
    def invoker_members() -> List[str]:
        return []


def access_facts(resolved: Any) -> _AccessFacts:
    """`_AccessFacts` from an `access_resolution.ResolvedAccess` (or None): its exact mode string and, when the run
    has an access record, the record's `sign_in.google` value. Nothing is guessed: an absent value stays None."""
    if resolved is None:
        return _AccessFacts(None, None)
    mode = getattr(resolved, "mode", None)
    google = getattr(getattr(getattr(resolved, "policy", None), "sign_in", None), "google", None)
    return _AccessFacts(mode if isinstance(mode, str) else None, getattr(google, "value", google))


class AccessIdpValidator:
    id, tool = "V2l", "policy"

    def __init__(self, access: Any = None):
        self.facts = access_facts(access)

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        out = self._validate_llm_iac(ctx)
        out += self._validate_intent_render(ctx)
        return out

    def _validate_llm_iac(self, ctx: ValidationContext) -> List[Diagnostic]:
        llm_iac = {p: ctx.files[p] for p in sorted(ctx.files)
                   if p.endswith(_IAC_SUFFIXES) and p not in ctx.rendered and ctx.ownership(p) in LLM_OWNED}
        if not llm_iac:
            return []
        files: Dict[str, str] = dict(llm_iac)
        if _ROOT_TFVARS in ctx.files:          # bare var.NAME references at the root resolve through it
            files[_ROOT_TFVARS] = ctx.files[_ROOT_TFVARS]
        out: List[Diagnostic] = []
        tfvars = self._root_tfvars(ctx, out)
        try:
            found = apv.validate(files, self.facts, tfvars=tfvars)
        except apv.HclUnavailable as e:
            raise ValidatorUnavailable(str(e)) from e
        platform = set(ctx.extras.get("platform_addresses") or ())
        lines: Dict[str, Dict[str, Tuple[int, int]]] = {}
        for f in found:
            code, path, address = f.get("code"), f.get("file"), f.get("block_address") or None
            if code not in KEPT_CODES or path not in llm_iac:
                continue
            if address and (path, address) in platform:
                continue
            start, end = self._block_lines(lines, path, llm_iac[path]).get(address or "", (None, None))
            out.append(_d(tool="policy", code=code, file=path, line=start, end_line=end, block_address=address,
                          attribute_path=f.get("attribute_path"), iteration=ctx.iteration,
                          message=str(f.get("message") or code), hint=_HINTS[code]))
        return out

    def _root_tfvars(self, ctx: ValidationContext, out: List[Diagnostic]) -> Optional[Dict[str, Any]]:
        """RT F2: the root variable values OpenTofu will use, when the AI wrote a root variable file it loads by itself
        (PRIVATE_* only; None = no such file, the lane 19 validator reads terraform.tfvars itself as before).
        An unparseable LLM-owned variable file is appended to `out` as a repairable finding."""
        if self.facts.mode not in apv.PRIVATE_MODES:
            return None
        llm_vars = [p for p in root_variable_files(ctx.files)
                    if p not in ctx.rendered and ctx.ownership(p) in LLM_OWNED and isinstance(ctx.files[p], str)]
        if not llm_vars:
            return None
        try:
            import hcl2  # python-hcl2 (gateway requirement)
        except ImportError as e:
            raise ValidatorUnavailable("python-hcl2 is not installed; variable files cannot be checked") from e
        merged: Dict[str, Any] = {}
        if isinstance(ctx.files.get(_ROOT_TFVARS), str):
            try:   # the platform's own file: unparseable = no values (lane 19 reports it, as before)
                merged.update(hcl2.loads(ctx.files[_ROOT_TFVARS]) or {})
            except Exception:  # noqa: BLE001
                pass
        for p in llm_vars:
            try:
                doc = json.loads(ctx.files[p]) if p.endswith(".json") else hcl2.loads(ctx.files[p])
                if not isinstance(doc, dict):
                    raise ValueError("top-level value is not an object")
            except Exception as e:  # noqa: BLE001 - the parser's message is the finding
                out.append(_d(tool="policy", code=UNCHECKABLE_CODE, file=p, iteration=ctx.iteration,
                              message=f"{p}: cannot parse this variables file for the private-access check "
                                      f"({type(e).__name__}), so its values cannot be shown private",
                              hint=T.HINT_UNCHECKABLE_VARIABLES_FILE))
                continue
            merged.update(doc)   # OpenTofu: a later file replaces a variable's whole value
        return merged

    def _validate_intent_render(self, ctx: ValidationContext) -> List[Diagnostic]:
        """FD-4CX-b on the typed-intent path: the module blocks the platform rendered from the AI's intent. Runs only
        when this iteration's assembly rendered RENDER_PATH from the intent (exact provenance, never a path guess)."""
        asm = ctx.extras.get("iac_intent")
        text = ctx.files.get(RENDER_PATH)
        if (self.facts.mode not in apv.PRIVATE_MODES or asm is None or not isinstance(text, str)
                or RENDER_PATH not in (getattr(asm, "rendered", None) or ())):
            return []
        try:
            found = apv.validate({RENDER_PATH: text}, self.facts)
        except apv.HclUnavailable as e:   # pragma: no cover - the render is JSON; kept for the typed contract
            raise ValidatorUnavailable(str(e)) from e
        provenance = getattr(asm, "provenance", None) or {}
        out: List[Diagnostic] = []
        for f in found:
            code, address = f.get("code"), f.get("block_address") or ""
            if code == "POLICY.UNCHECKABLE_FILE":   # the platform's own render does not parse: never a pass
                out.append(_d(tool="policy", code=code, file=RENDER_PATH, iteration=ctx.iteration,
                              error_class=ErrorClass.PLATFORM_DEFECT, message=str(f.get("message") or code)))
                continue
            if code not in FD4CXB_CODES or not address.startswith("module."):
                continue
            entry = provenance.get(II._ptr("module", address[len("module."):]))   # the renderer's own pointer
            if entry is None:   # a module block the platform rendered itself: its defect, never the AI's repair
                out.append(_d(tool="policy", code=code, file=RENDER_PATH, block_address=address,
                              attribute_path=f.get("attribute_path"), iteration=ctx.iteration,
                              error_class=ErrorClass.PLATFORM_DEFECT, message=str(f.get("message") or code)))
                continue
            # the intent gate's grammar: a JSON pointer relative to the entry (validators anchor findings this way)
            pointer = II._ptr("args", *f["location"])
            out.append(_d(tool="policy", code=code, file=INTENT_PATH, block_address=address,
                          attribute_path=pointer, iteration=ctx.iteration,
                          message=f"{f.get('message') or code} (intent entry {entry}{pointer})", hint=_HINTS[code]))
        return out

    @staticmethod
    def _block_lines(cache: Dict[str, Dict[str, Tuple[int, int]]], path: str, text: str
                     ) -> Mapping[str, Tuple[int, int]]:
        if path not in cache:
            spans: Dict[str, Tuple[int, int]] = {}
            if path.endswith(".tf"):
                for b in index_blocks(text) or []:
                    for key in b.keys:
                        spans.setdefault(key, (b.start or None, b.end or None))
            cache[path] = spans
        return cache[path]
