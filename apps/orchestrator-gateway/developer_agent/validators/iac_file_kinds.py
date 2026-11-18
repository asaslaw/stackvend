"""V2n (register rows AI-TFVARS-REFUSED and AI-TOFU-REFUSED, owner 10-29, blocking): file kinds OpenTofu loads by itself
that the AI may not write.

| id  | code                          | when |
| V2n | POLICY.TFVARS_NOT_ALLOWED     | an LLM-owned variables file OpenTofu loads by itself in the deploy's root module: `terraform.tfvars.json`, `*.auto.tfvars`, `*.auto.tfvars.json` in `infra/workload/` or at the repository root, or `terraform.tfvars` at the repository root; any workload, any mode |
| V2n | POLICY.TOFU_FILE_NOT_ALLOWED  | an LLM-owned `*.tofu` / `*.tofu.json` file anywhere in the tree; any workload, any mode |

Why (AI-TFVARS-REFUSED): the platform owns the workload's root variable values. It renders
`infra/workload/terraform.tfvars` (an AI copy at that path is removed at assembly, PLATFORM_PATH_RESERVED) and, at
deploy, `stackvend-access.auto.tfvars.json` from the access record. OpenTofu also loads `terraform.tfvars.json` and
every `*.auto.tfvars` / `*.auto.tfvars.json` of the root module by itself, AFTER `terraform.tfvars`, so an AI-written
one could set the platform's access variables (`allow_unauthenticated`, `enable_direct_iap`,
`authorized_invoker_members`) whenever the deploy renders no access file (no record, PUBLIC_APP, Express), and the
platform secret keys (`oauth_client_secret`, `firebase_api_key`, which reach OpenTofu as `TF_VAR_*` environment
variables and lose to any variables file) in every workload. The deploy's root module is the repository root: the
terraform server writes every committed file at its repository path and copies `infra/workload/*` to the root
(`prepare_workspace`, `deploy_workload`), and it merges a repository-root `terraform.tfvars` into the root
`terraform.tfvars`, so the same names at the repository root are refused too. Nested directories are not the root
module and OpenTofu loads no variables file there, so they are not judged (`terraform.tfvars.example` and other
names OpenTofu does not load are never refused).

Why (AI-TOFU-REFUSED): OpenTofu loads `*.tofu` / `*.tofu.json` like `.tf` files, and a `.tofu` file replaces the
`.tf` file of the same name, but every pre-commit check reads `.tf` (and the rendered `.tf.json`) only.

Provenance, never content guessing (invariant 2): a finding needs exact path rules (directory + exact basename or
suffix) AND LLM ownership by the run's own classification (`ctx.ownership`); a platform-rendered (`ctx.rendered`) or
vendored file is never judged. A file the human architect committed (USER_OWNED: pre-existing and not recorded as the
AI's; a repository-root file the platform did not write classifies as unattributable) is left alone: the platform
never repairs or deletes a user's files, and a human may set root variables on purpose (as in `human.tf`). The IaC
provenance store records only root `.tf` files (`assembly.llm_iac_paths`), so a file of these kinds that an earlier
AI run committed is the user's on the next run.

Committed bytes (Opus RT F1): the QA repair and the deploy's intent repair put every committed file outside `infra/`
and `.github/` into the draft (`qa_repair.repair_draft`, `deploy_repair.repair_draft`), and a regeneration can echo a
committed file, so such a file classifies as LLM_AUTHORED although the AI did not change it. A file whose text is
exactly the committed text (`ctx.extras["preexisting_files"]`, the repository files `RepairLoop.validate` passes) is
not judged: what deploys is what a person committed. A changed or new file is judged.

Repair (the AI cannot delete files): a variables file is repaired by returning it with no variable in it (empty
content, `{}` for a `.json` one): python-hcl2 / `json` parse it to an empty object, which sets nothing, so it is no
finding (the parse is the decision; an unparseable file stays a finding). A `.tofu` file is repaired by a rename to a
`.tf` key in the same directory (`repair_loop.RENAME_ONLY_CODES`, the FD-4AW-a mechanism for `*.tf.json`); an empty
`.tofu` file is still a finding, because it would still replace a `.tf` file of the same name. With the typed IaC
intent the AI writes no Terraform, so the rename returns the new `.tf` key empty and the file's declarations are not
kept: each top-level block is then its own finding (block address and line, as V-IAC-PATH reports an AI `.tf`), so
every dropped declaration is named in the report (one finding per file when it does not parse as HCL, or for
`.tofu.json`). Nothing is rewritten here (invariant 1).
"""
from __future__ import annotations

import json
import posixpath
from typing import Any, List

try:
    from shared.diagnostics import Diagnostic
except ImportError:  # pragma: no cover
    from ...shared.diagnostics import Diagnostic  # type: ignore

from ..assembly import index_blocks
from . import policy_tables as T
from .base import ValidationContext, ValidatorUnavailable
from .step1 import LLM_OWNED, _d

TFVARS_CODE = "POLICY.TFVARS_NOT_ALLOWED"
TOFU_CODE = "POLICY.TOFU_FILE_NOT_ALLOWED"
CODES = frozenset({TFVARS_CODE, TOFU_CODE})

# The deploy's root module: the repository root, and infra/workload/ (flattened into it by deploy_workload).
WORKLOAD_ROOT_DIR = "infra/workload"
REPO_ROOT_DIR = ""
ROOT_MODULE_DIRS = (REPO_ROOT_DIR, WORKLOAD_ROOT_DIR)
# OpenTofu's own variables-file names (exact basename / exact suffix), loaded without any -var-file flag.
TFVARS_JSON_NAME = "terraform.tfvars.json"
TFVARS_NAME = "terraform.tfvars"   # platform-rendered at infra/workload/; merged by the deploy at the repo root
AUTO_TFVARS_SUFFIXES = (".auto.tfvars", ".auto.tfvars.json")
TOFU_SUFFIXES = (".tofu", ".tofu.json")


def is_auto_loaded_variables_file(path: Any) -> bool:
    """True for a variables file OpenTofu (or the deploy's tfvars merge) loads by itself in the deploy's root module:
    exact directory (repository root or infra/workload/) and exact OpenTofu names."""
    if not isinstance(path, str):
        return False
    directory, base = posixpath.split(path)
    if directory not in ROOT_MODULE_DIRS:
        return False
    if base == TFVARS_JSON_NAME or base.endswith(AUTO_TFVARS_SUFFIXES):
        return True
    # infra/workload/terraform.tfvars is the platform's own render (an AI copy is removed at assembly)
    return directory == REPO_ROOT_DIR and base == TFVARS_NAME


def is_tofu_file(path: Any) -> bool:
    """True for an OpenTofu-only configuration file (exact suffixes), in any directory."""
    return isinstance(path, str) and posixpath.basename(path).endswith(TOFU_SUFFIXES)


def sets_no_variable(path: str, text: str) -> bool:
    """True when the file parses (python-hcl2 for HCL, `json` for `.json`) to an empty object: it sets no variable.
    False for any other parse result and for a file that does not parse. Raises ValidatorUnavailable when python-hcl2
    is not installed (never a pass)."""
    if path.endswith(".json"):
        try:
            return json.loads(text) == {}
        except ValueError:
            return False
    try:
        import hcl2  # python-hcl2 (gateway requirement)
    except ImportError as e:
        raise ValidatorUnavailable("python-hcl2 is not installed; variables files cannot be checked") from e
    try:
        return hcl2.loads(text) == {}
    except Exception:  # noqa: BLE001 - an unparseable file is not shown empty: it stays a finding
        return False


class IacFileKindValidator:
    id, tool = "V2n", "policy"

    def __init__(self, intent_mode: bool = False):
        self.intent_mode = intent_mode   # build_step1_stack(iac_intent=...): the typed-intent path

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        committed = ctx.extras.get("preexisting_files") or {}
        out: List[Diagnostic] = []
        for path in sorted(ctx.files):
            tfvars, tofu = is_auto_loaded_variables_file(path), is_tofu_file(path)
            if not (tfvars or tofu):   # the cheap exact path rules first (RT F6)
                continue
            if path in ctx.rendered or path in ctx.vendored or ctx.ownership(path) not in LLM_OWNED:
                continue
            text = ctx.files[path]
            if isinstance(committed.get(path), str) and committed[path] == text:
                continue   # RT F1: exactly the committed bytes (a person's file echoed into the draft)
            if tfvars:
                if isinstance(text, str) and sets_no_variable(path, text):
                    continue
                out.append(_d(tool="policy", code=TFVARS_CODE, file=path, line=1, iteration=ctx.iteration,
                              message=f"{path} is a variables file OpenTofu loads by itself; the platform owns the "
                                      f"workload's root variable values, so the AI may not write one",
                              hint=T.HINT_TFVARS_NOT_ALLOWED))
            else:
                out.extend(self._tofu(ctx, path, text))
        return out

    def _tofu(self, ctx: ValidationContext, path: str, text: Any) -> List[Diagnostic]:
        message = (f"{path} is an OpenTofu-only configuration file (.tofu / .tofu.json), which the platform's checks "
                   f"do not read, so the AI may not write one")
        if not self.intent_mode:
            return [_d(tool="policy", code=TOFU_CODE, file=path, line=1, iteration=ctx.iteration, message=message,
                       hint=T.HINT_TOFU_FILE_NOT_ALLOWED)]
        hint = T.HINT_TOFU_FILE_NOT_ALLOWED_INTENT
        blocks = index_blocks(text) if isinstance(text, str) and not path.endswith(".json") else None
        if not blocks:
            return [_d(tool="policy", code=TOFU_CODE, file=path, line=1, iteration=ctx.iteration,
                       message=message + "; with the typed IaC intent its declarations are not kept", hint=hint)]
        return [_d(tool="policy", code=TOFU_CODE, file=path, line=b.start, end_line=b.end, block_address=k,
                   iteration=ctx.iteration, hint=hint,
                   message=f"{k} is declared in {path}, an OpenTofu-only file; with the typed IaC intent the AI "
                           f"writes no Terraform, so this declaration is not kept")
                for b in blocks for k in b.keys]


def register(stack: Any, intent_mode: bool = False) -> None:
    stack.register(IacFileKindValidator(intent_mode=intent_mode), "blocking")
