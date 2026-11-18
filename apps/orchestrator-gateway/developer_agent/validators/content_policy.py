"""HCL content policy (FD-4AW / FD-4AW-a, blocking): generated workload Terraform may not execute code on the platform.

FD-4G closed path attacks; its red-team (Q-9) noted that an AI-written root module could still run a program on the
apply runner (a `provisioner`, a `connection` session, `data "external"`), pull in a provider the platform does not
offer (`null_resource`, `local_file`, `data "http"`, ...), fetch and run a remote module, remap a provider source, or
read another state (`terraform_remote_state`). This validator refuses those constructs before commit, so the repair loop
sends them back to the AI. It never rewrites anything. (The AI writing at a human-architect file name, `human.tf` /
`*_override.tf`, is V7's PATH.USER_OWNED_NAME_WRITTEN_BY_LLM in step1.py, FD-4AW-a F2.)

| id   | code                                     | default mode |
| V2j  | POLICY.PROVISIONER_FORBIDDEN (any `provisioner` block in any `resource`, `terraform_data` included) | blocking |
| V2j  | POLICY.CONNECTION_FORBIDDEN (any `connection` block: resource level or inside a provisioner) | blocking |
| V2j  | POLICY.EXTERNAL_DATA_FORBIDDEN (`data "external" ...`)                                      | blocking |
| V2j  | POLICY.REMOTE_STATE_FORBIDDEN (`data "terraform_remote_state" ...`, FD-4AW-a F5)            | blocking |
| V2j  | POLICY.IMPLICIT_PROVIDER_NOT_AVAILABLE (the provider a resource/data block belongs to is not in the validate service's provider set) | blocking |
| V2j  | POLICY.MODULE_SOURCE_NOT_LOCAL (a `module` whose `source` is not a local directory of this run's vendored platform files or under infra/workload/, or that sets `version`; FD-4AW-a F3) | blocking |
| V2j  | POLICY.PROVIDER_SOURCE_MISMATCH (a `required_providers` entry whose `source` is not the platform's exact source for that local name; FD-4AW-a F4) | blocking |
| V2j  | POLICY.JSON_IAC_NOT_CHECKABLE (an LLM-owned root `*.tf.json` the platform did not render; FD-4AW-a F1) | blocking |

Decisions are made on python-hcl2's parse tree only (AGENTS.md invariant 2), over the same LLM-owned root blocks V2d
reads (`step1._llm_blocks`: LLM-owned `infra/workload/*.tf`, platform-synthesized blocks excluded):

* A nested block is a python-hcl2 body entry whose element carries the parser's `__start_line__` meta. Attributes
  never carry it, so an attribute that happens to be named `provisioner` / `connection` is not a block (OpenTofu
  rejects it as an unsupported argument; V1b reports that).
* The provider a `resource`/`data` block belongs to is Terraform's documented rule applied to the parsed labels: the
  `provider` meta-argument's local name when present (`provider = x` or `provider = x.alias` -> `x`), else the type
  label's prefix before the first `_` (the whole label when it has none): `null_resource` -> `null`,
  `google_storage_bucket` -> `google`, `random_id` -> `random`, `external` -> `external`. This is the language's own
  rule on a typed label, not text guessing. V2j does not report blocks of OpenTofu's built-in `terraform` provider
  under this code (`policy_tables.BUILTIN_PROVIDERS`), and since FD-4CW (owner row FD-4CW-Q2) V2d accepts it too, so
  a plain `terraform_data` block passes; `data "terraform_remote_state"` is still always refused
  (POLICY.REMOTE_STATE_FORBIDDEN).
* python-hcl2 renders the HCL keywords `null` / `true` / `false` inside an expression as Python's `None` / `True` /
  `False` (`provider = null.x` parses as `"${None.x}"`); `step1.HCL2_KEYWORD_RENDERING` maps those exact renderings
  back (`step1.block_provider`, shared with V2d).
  Provider local names are lower case, so no real provider name collides with a rendering.
* Module sources: Terraform's own rule is that a local path source begins with `./` or `../` and takes no `version`
  (any other source is fetched by `tofu init`). V2j accepts only such a literal whose `posixpath.normpath` against
  infra/workload/ is a directory holding one of this run's vendored platform files directly (`ctx.vendored`: golden
  modules, composite bundles; `../modules` or `../` are not module directories, FD-4AW-r R1) or a directory strictly
  under infra/workload/. FD-4CB-b: the developer stage never vendors the host platform's own `workflows` module
  (shared/host_platform_modules.py), so `../modules/workflows` fails this rule; such a finding (exact resolved
  directory infra/modules/<host module>) carries a hint naming the workload module `workflows-dag` instead.
* Provider sources: `policy_tables.PLATFORM_PROVIDER_SOURCES` is the exact {local name: source} table of the validate
  service's pinned set; `PLATFORM_PROVIDER_SOURCE_FORMS` also accepts the exact fully-qualified forms
  `registry.opentofu.org/...` / `registry.terraform.io/...` (FD-4AW-r R2). An entry without `source` (or the legacy version-string form) uses Terraform's implied
  `hashicorp/<local name>`, which equals the table for every platform provider; other local names are V2d's.
* `*.tf.json` is valid OpenTofu that none of the HCL validators read, so an LLM-owned root `*.tf.json` is refused as
  not checkable unless the platform rendered it (`ctx.rendered`, e.g. the typed-intent renderer's custom.tf.json).

Like V2d, the validator raises `ValidatorUnavailable` when the validate service did not report its provider set: a
missing set is never a pass. Overlap note (FD-4CW Q1): this code names every `resource`/`data` block of an unavailable
provider, so a repair sees each block to change; V2d (`POLICY.PROVIDER_NOT_AVAILABLE`) skips those block kinds
(`step1.PER_BLOCK_PROVIDER_KINDS`) and judges only `provider` blocks and `required_providers` keys, so a block gets
one diagnostic. build_step1_stack refuses a V2j mode weaker than V2d's.
"""
from __future__ import annotations

import posixpath
from typing import Any, Iterable, List, Mapping, Optional, Tuple

try:
    from shared.diagnostics import Diagnostic
except ImportError:  # pragma: no cover
    from ...shared.diagnostics import Diagnostic  # type: ignore

from ..assembly import WORKLOAD
from . import policy_tables as T
from .base import ValidationContext, ValidatorUnavailable
# block_provider (with HCL2_KEYWORD_RENDERING) lives in step1 since FD-4CW, so V2d and V2j name the same provider
from .step1 import LLM_OWNED, _d, _literal, _llm_blocks, block_provider
_WORKLOAD_DIR = WORKLOAD.rstrip("/")
_LOCAL_SOURCE_PREFIXES = ("./", "../")   # Terraform's local-path module source rule (exact prefixes)
_MODULES_DIR = "infra/modules"           # where the platform vendors golden modules (FD-4CB-b hint only)
_TF_JSON = ".tf.json"


def _nested_blocks(body: Any, name: str) -> Iterable[Tuple[Optional[str], Mapping]]:
    """(label, body) of every nested `name { }` / `name "label" { }` block of a python-hcl2 body, in source order.

    Unlabeled blocks are list elements carrying `__start_line__`; one-label blocks are list elements mapping the label
    to a body carrying it. Anything without the parser's line meta is an attribute value, not a block."""
    entries = body.get(name) if isinstance(body, Mapping) else None
    if not isinstance(entries, list):
        return
    for entry in entries:
        if not isinstance(entry, Mapping):
            continue
        if "__start_line__" in entry:
            yield None, entry
            continue
        for label, inner in entry.items():
            if not label.startswith("__") and isinstance(inner, Mapping) and "__start_line__" in inner:
                yield label, inner


def module_source_ok(body: Mapping, vendored: Iterable[str]) -> bool:
    """True when a module block's source is a local directory of vendored platform files or under infra/workload/
    (exact rule, see module docstring)."""
    if "version" in body:
        return False
    source = _literal(body.get("source"))
    if source is None or not source.startswith(_LOCAL_SOURCE_PREFIXES):
        return False
    target = posixpath.normpath(posixpath.join(_WORKLOAD_DIR, source))
    if target.startswith(WORKLOAD):
        return True
    # FD-4AW-r R1: the target must itself be a module directory, i.e. hold a vendored file directly (`../modules` or
    # `../` merely contain vendored modules further down and are not one)
    return any(posixpath.dirname(p) == target for p in vendored)


def host_platform_module(body: Mapping) -> Optional[str]:
    """FD-4CB-b: the module id when a module block's literal local source resolves (the same `posixpath.normpath`
    against infra/workload/ as module_source_ok) to exactly infra/modules/<id> for a host-platform module the developer
    stage never vendors (policy_tables.HINT_HOST_PLATFORM_MODULE keys == shared.host_platform_modules
    .NOT_VENDORED_TO_WORKLOADS); None otherwise. Only chooses the hint of a finding module_source_ok already makes."""
    source = _literal(body.get("source"))
    if source is None or not source.startswith(_LOCAL_SOURCE_PREFIXES):
        return None
    parent, name = posixpath.split(posixpath.normpath(posixpath.join(_WORKLOAD_DIR, source)))
    return name if parent == _MODULES_DIR and name in T.HINT_HOST_PLATFORM_MODULE else None


def provider_source_mismatches(body: Mapping) -> List[Tuple[str, Any]]:
    """(local name, declared source) of every `required_providers` entry of a `terraform` block whose source is not the
    platform's exact source for that local name. Local names outside the table are V2d's (PROVIDER_NOT_AVAILABLE)."""
    out: List[Tuple[str, Any]] = []
    for rp in body.get("required_providers") or []:
        if not isinstance(rp, Mapping):
            continue
        for local, spec in rp.items():
            if local.startswith("__") or local not in T.PLATFORM_PROVIDER_SOURCES:
                continue
            if not isinstance(spec, Mapping) or "source" not in spec:
                continue   # Terraform's implied source hashicorp/<local> == the table
            if _literal(spec.get("source")) not in T.PLATFORM_PROVIDER_SOURCE_FORMS[local]:
                out.append((local, spec.get("source")))
    return out


def _is_root_tf_json(path: str) -> bool:
    return path.startswith(WORKLOAD) and path.endswith(_TF_JSON) and "/" not in path[len(WORKLOAD):]


class ContentPolicyValidator:
    id, tool = "V2j", "policy"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        available = ctx.extras.get("available_providers")
        if available is None:
            raise ValidatorUnavailable("the validate service did not report its provider set")
        allowed = set(available) | T.BUILTIN_PROVIDERS
        out: List[Diagnostic] = []
        for path in sorted(ctx.files):
            if _is_root_tf_json(path) and path not in ctx.rendered and ctx.ownership(path) in LLM_OWNED:
                out.append(_d(tool="policy", code="POLICY.JSON_IAC_NOT_CHECKABLE", file=path, line=1,
                              iteration=ctx.iteration,
                              message=f"{path} is Terraform JSON, which the platform's policy checks do not read",
                              hint=T.HINT_JSON_IAC_NOT_CHECKABLE))
        for path, b in _llm_blocks(ctx):
            body = b.body or {}

            def add(code: str, line: Any, message: str, hint: str) -> None:
                out.append(_d(tool="policy", code=code, file=path, line=line if isinstance(line, int) else b.start,
                              block_address=b.key, iteration=ctx.iteration, message=message, hint=hint))

            if b.kind == "resource":
                for _, conn in _nested_blocks(body, "connection"):
                    add("POLICY.CONNECTION_FORBIDDEN", conn.get("__start_line__"),
                        f"{b.key} declares a connection block", T.HINT_CONNECTION_FORBIDDEN)
                for p_type, prov in _nested_blocks(body, "provisioner"):
                    add("POLICY.PROVISIONER_FORBIDDEN", prov.get("__start_line__"),
                        f'{b.key} declares provisioner "{p_type}"', T.HINT_PROVISIONER_FORBIDDEN)
                    for _, conn in _nested_blocks(prov, "connection"):
                        add("POLICY.CONNECTION_FORBIDDEN", conn.get("__start_line__"),
                            f'{b.key} provisioner "{p_type}" declares a connection block',
                            T.HINT_CONNECTION_FORBIDDEN)
            if b.kind == "data" and b.labels and b.labels[0] == T.EXTERNAL_DATA_SOURCE_TYPE:
                add("POLICY.EXTERNAL_DATA_FORBIDDEN", b.start, f"{b.key} runs an external program",
                    T.HINT_EXTERNAL_DATA_FORBIDDEN)
            if b.kind == "data" and b.labels and b.labels[0] == T.REMOTE_STATE_DATA_SOURCE_TYPE:
                add("POLICY.REMOTE_STATE_FORBIDDEN", b.start, f"{b.key} reads another Terraform state",
                    T.HINT_REMOTE_STATE_FORBIDDEN)
            if b.kind == "module" and not module_source_ok(body, ctx.vendored):
                host_module = host_platform_module(body)   # FD-4CB-b: same code, the exact host-module hint
                add("POLICY.MODULE_SOURCE_NOT_LOCAL", b.start,
                    f"{b.key} source {body.get('source')!r} is not a local platform module"
                    + (" (it sets version)" if "version" in body else "")
                    + (f" (`{host_module}` is the host platform's own module, not offered to workloads)"
                       if host_module else ""),
                    T.HINT_HOST_PLATFORM_MODULE[host_module] if host_module else T.HINT_MODULE_SOURCE_NOT_LOCAL)
            if b.kind == "terraform":
                for local, source in provider_source_mismatches(body):
                    add("POLICY.PROVIDER_SOURCE_MISMATCH", b.start,
                        f'required_providers "{local}" has source {source!r}; the platform\'s "{local}" is '
                        f'{T.PLATFORM_PROVIDER_SOURCES[local]!r}',
                        T.HINT_PROVIDER_SOURCE_MISMATCH.format(
                            sources=", ".join(f"{k} = {v}" for k, v in sorted(T.PLATFORM_PROVIDER_SOURCES.items()))))
            provider = block_provider(b.kind, b.labels, body)
            if provider is not None and provider not in allowed:
                add("POLICY.IMPLICIT_PROVIDER_NOT_AVAILABLE", b.start,
                    f'{b.key} belongs to provider "{provider}", which is not available to the platform',
                    T.HINT_IMPLICIT_PROVIDER.format(provider=provider, providers=", ".join(sorted(set(available)))))
        return out
