"""GCP resource-name validators (FD-55 W4, register FD55-W4; replaces the generation-time name rewriters HB-17,
HD-14 and HB-23, which invented `coalesce(...)` defaults, clamped connector names and shortened service-account ids).

| id          | code             | default mode | what it checks |
| V2k         | IAC.NAME_INVALID | blocking     | a name attribute of an exact (type, attribute) row of NAME_RULES whose value is a template (`"${var.product_id}-x"`, `local.prefix`) that resolves completely from platform-known values: var.product_id / var.region / var.project_id (the values the deploy writes into the root terraform.tfvars), the string values of the platform-rendered infra/workload/terraform.tfvars, and the workload's own locals that are themselves such templates. A template with any other part (a function call, an AI variable, a resource attribute, count.index, a directive) is not judged: nothing is guessed |
| V2k-literal | IAC.NAME_INVALID | blocking (FD55-W4-LIT, owner 10-25) | a literal name of a row the provider does NOT check at `tofu validate` (google_vpc_access_connector.name); every other row's literal is already a V1b diagnostic (the provider's ValidateFunc) |

Why: `tofu validate` never evaluates variables, so a provider ValidateFunc sees a templated name only at plan / apply,
after the commit. Resolving the template with the exact values the deploy supplies moves that finding to the repair
loop. Rules are exact data: the provider's own messages (google 6.35.0, the production provider set; offline
`tofu validate` evidence in docs/handoff/fd-55-w24-report.md) and, for the connector, the API's connector-id rule the
deleted HB-17 step 3b enforced. Nothing is rewritten; the AI fixes the name.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:
    from shared.artifact_ownership import Ownership
    from shared.diagnostics import Diagnostic
except ImportError:  # pragma: no cover
    from ...shared.artifact_ownership import Ownership  # type: ignore
    from ...shared.diagnostics import Diagnostic  # type: ignore

from ..assembly import index_blocks
from .base import ValidationContext
from .step1 import TFVARS, _d, _is_root_tf, _llm_blocks

CODE = "IAC.NAME_INVALID"
MAX_LOCAL_DEPTH = 8

# ------------------------------------------------------------------------------------------------ the rules (data)
# A check is one of: ("regex", pattern) fullmatch | ("length", min, max) | ("charset", allowed) |
# ("first", allowed) | ("last", allowed) | ("gcs_length",) (3-63 characters; with dots up to 222 and each
# dot-separated part at most 63) | ("not_prefix", prefix).
_LOWER = "abcdefghijklmnopqrstuvwxyz"
_DIGITS = "0123456789"
_GCE_NAME = ("regex", r"(?:[a-z](?:[-a-z0-9]{0,61}[a-z0-9])?)")
_RFC1035 = ("regex", r"[a-z]([-a-z0-9]*[a-z0-9])?")


@dataclass(frozen=True)
class NameRule:
    checks: Tuple[Tuple[Any, ...], ...]
    provider_validates_literal: bool   # True: the provider's ValidateFunc reports a bad literal at `tofu validate`
    source: str


_PROVIDER = "google 6.35.0 ValidateFunc (offline tofu validate message)"
NAME_RULES: Mapping[Tuple[str, str], NameRule] = {
    **{(t, "name"): NameRule((_GCE_NAME,), True, _PROVIDER) for t in (
        "google_compute_address", "google_compute_disk", "google_compute_firewall",
        "google_compute_global_network_endpoint_group", "google_compute_instance_template", "google_compute_network",
        "google_compute_region_network_endpoint_group", "google_compute_router", "google_compute_security_policy",
        "google_compute_subnetwork")},
    ("google_compute_instance", "name"): NameRule((("length", 1, 63), _RFC1035), True, _PROVIDER),
    ("google_compute_router_nat", "name"): NameRule((("length", 2, 63), _RFC1035), True, _PROVIDER),
    ("google_service_account", "account_id"): NameRule((("length", 6, 30), _RFC1035), True, _PROVIDER),
    ("google_redis_instance", "name"): NameRule((("regex", r"[a-z][a-z0-9-]{0,39}[a-z0-9]"),), True, _PROVIDER),
    ("google_spanner_instance", "name"): NameRule((("regex", r"[a-z][-a-z0-9]*[a-z0-9]"),), True, _PROVIDER),
    ("google_project_iam_custom_role", "role_id"): NameRule((("regex", r"[a-zA-Z0-9_\.]{3,64}"),), True, _PROVIDER),
    ("google_container_cluster", "name"): NameRule(
        (("length", 0, 40), ("charset", _LOWER + _DIGITS + "-"), ("first", _LOWER), ("last", _LOWER + _DIGITS)),
        True, _PROVIDER),
    ("google_storage_bucket", "name"): NameRule(
        (("charset", _LOWER + _DIGITS + "-_."), ("first", _LOWER + _DIGITS), ("last", _LOWER + _DIGITS),
         ("gcs_length",), ("not_prefix", "goog")), True, _PROVIDER),   # the provider's "google"-misspelling
    # check is fuzzy and is not reproduced (V1b / plan still report it; fewer findings here, never a false one)
    ("google_bigquery_dataset", "dataset_id"): NameRule(
        (("charset", _LOWER + _LOWER.upper() + _DIGITS + "_"),), True, _PROVIDER),
    ("google_vpc_access_connector", "name"): NameRule(
        (("regex", r"[a-z][-a-z0-9]{0,23}[a-z0-9]"),), False,
        "Serverless VPC Access connector id rule (the provider does not check it at validate)"),
}


def _violation(check: Tuple[Any, ...], value: str) -> Optional[str]:
    kind = check[0]
    if kind == "regex":
        return None if re.fullmatch(check[1], value) else f"must match ^{check[1]}$"
    if kind == "length":
        lo, hi = check[1], check[2]
        return None if lo <= len(value) <= hi else f"must be {lo}-{hi} characters long"
    if kind == "charset":
        return None if all(c in check[1] for c in value) else "contains a character the name does not allow"
    if kind == "first":
        return None if value[:1] and value[0] in check[1] else "must start with an allowed character"
    if kind == "last":
        return None if value[-1:] and value[-1] in check[1] else "must end with a letter or a number"
    if kind == "gcs_length":
        parts_ok = all(len(p) <= 63 for p in value.split("."))
        ok = 3 <= len(value) <= (222 if "." in value else 63) and parts_ok
        return None if ok else ("must contain 3-63 characters (names containing dots up to 222, each dot-separated "
                                "part at most 63)")
    if kind == "not_prefix":
        return None if not value.startswith(check[1]) else f'must not begin with "{check[1]}"'
    raise ValueError(f"unknown name check {kind!r}")


def rule_violations(rule: NameRule, value: str) -> List[str]:
    return [v for v in (_violation(c, value) for c in rule.checks) if v is not None]


# ------------------------------------------------------------------------------------------------ template resolution
def _identifier(name: str) -> bool:
    """An HCL identifier (letters, digits, `_`, `-`; not starting with a digit or `-`)."""
    return bool(name) and (name[0].isalpha() or name[0] == "_") and all(c.isalnum() or c in "_-" for c in name)


def resolve_template(value: Any, variables: Mapping[str, str], locals_: Mapping[str, Any],
                     _depth: int = 0) -> Optional[str]:
    """The exact string a python-hcl2 rendered value evaluates to when every interpolation is `var.<name>` with
    <name> in `variables` or `local.<name>` whose value resolves the same way; None for anything else (a function
    call, an attribute or index of a reference, a template directive `%{`, an escaped `$${`, an unknown name)."""
    if not isinstance(value, str) or "%{" in value or "$${" in value:
        return None
    out: List[str] = []
    i = 0
    while True:
        j = value.find("${", i)
        if j < 0:
            out.append(value[i:])
            return "".join(out)
        out.append(value[i:j])
        k = value.find("}", j + 2)
        if k < 0:
            return None
        kind, dot, name = value[j + 2:k].strip().partition(".")
        if not dot or not _identifier(name):
            return None
        if kind == "var":
            got = variables.get(name)
        elif kind == "local" and _depth < MAX_LOCAL_DEPTH and name in locals_:
            got = resolve_template(locals_[name], variables, locals_, _depth + 1)
        else:
            return None
        if got is None:
            return None
        out.append(got)
        i = k + 1


def _root_locals(ctx: ValidationContext) -> Dict[str, Any]:
    """Every local of the root module (all root .tf files); a name declared twice is left out (V1b reports it)."""
    seen: Dict[str, List[Any]] = {}
    for path in sorted(ctx.files):
        if not _is_root_tf(path) or not isinstance(ctx.files[path], str):
            continue
        for b in index_blocks(ctx.files[path]) or []:
            if b.kind == "locals":
                for name, value in (b.body or {}).items():
                    if not name.startswith("__"):
                        seen.setdefault(name, []).append(value)
    return {n: v[0] for n, v in seen.items() if len(v) == 1}


def _rendered_tfvars(ctx: ValidationContext) -> Dict[str, str]:
    """String values of the platform-rendered infra/workload/terraform.tfvars (the AI's copy is removed at assembly,
    PLATFORM_PATH_RESERVED); literals only. Fable RT F3: only when the router classifies the file exactly
    PLATFORM_RENDERED; an unattributable (None), AI-authored or pre-existing tfvars is no value source."""
    text = ctx.files.get(TFVARS)
    if not isinstance(text, str) or ctx.ownership(TFVARS) is not Ownership.PLATFORM_RENDERED:
        return {}
    try:
        import hcl2
        doc = hcl2.loads(text)
    except Exception:  # noqa: BLE001 - unparseable: no value known (fewer findings, never a guess)
        return {}
    return {k: v for k, v in doc.items() if isinstance(v, str) and "${" not in v}


class NameTemplateValidator:
    """V2k / V2k-literal (see the module docstring)."""

    def __init__(self, platform_values: Optional[Mapping[str, str]] = None, *, literals: bool = False):
        # platform_values: exact deploy values (product_id, region, project_id) supplied by the developer stage;
        # a missing or empty value is unknown
        self.platform_values = {k: v for k, v in (platform_values or {}).items() if isinstance(v, str) and v}
        self.literals = literals
        self.id = "V2k-literal" if literals else "V2k"
        self.tool = "policy"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        variables = dict(_rendered_tfvars(ctx))
        variables.update(self.platform_values)   # the deploy's platform keys win over the workload tfvars (FD-4BV)
        locals_ = _root_locals(ctx) if not self.literals else {}
        out: List[Diagnostic] = []
        for path, b in _llm_blocks(ctx):
            if b.kind != "resource" or len(b.labels) < 2:
                continue
            for (rtype, attr), rule in NAME_RULES.items():
                if rtype != b.labels[0] or attr not in (b.body or {}):
                    continue
                raw = b.body[attr]
                if not isinstance(raw, str):
                    continue
                templated = "${" in raw
                if self.literals:
                    if templated or rule.provider_validates_literal:
                        continue
                    value = raw
                else:
                    if not templated:
                        continue
                    value = resolve_template(raw, variables, locals_)
                    if value is None:
                        continue
                bad = rule_violations(rule, value)
                if not bad:
                    continue
                shown = f'"{value}"' + ("" if not templated else f" ({len(value)} characters, from {raw!r} with "
                                                                      "the platform's values)")
                out.append(_d(tool="policy", code=CODE, file=path, line=b.start, end_line=b.end,
                              block_address=b.key, attribute_path=attr, iteration=ctx.iteration,
                              severity="error",
                              message=f"{b.key}.{attr} is {shown}: GCP rejects it ({'; '.join(bad)})",
                              detail=f"rule source: {rule.source}",
                              hint=("Write a name that satisfies the rule after the platform's values are filled in "
                                    "(shorten the fixed part; var.product_id, var.region and var.project_id are fixed "
                                    "for this workload). The platform never shortens or rewrites a name.")))
        return out


def register(stack: Any, platform_values: Optional[Mapping[str, str]] = None) -> None:
    stack.register(NameTemplateValidator(platform_values), "blocking")
    stack.register(NameTemplateValidator(literals=True), "blocking")   # FD55-W4-LIT (owner 10-25)


__all__ = ["CODE", "NAME_RULES", "NameRule", "NameTemplateValidator", "register", "resolve_template",
           "rule_violations"]
