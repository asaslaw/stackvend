"""Platform-fact validators (Wave 2 lane 11 near-term; codes are lane 11's canonical set, integration plan I-6).

| id          | code                              | default mode | what it checks |
| V2h         | POLICY.CIDR_LITERAL               | blocking     | an allocation attribute (exact table `platform_facts.ALLOCATION_ATTRIBUTES`) whose value is a CIDR literal, or exactly `var.X` / `local.X` where the AI's own `X` holds a CIDR literal |
|             | POLICY.CIDR_FACT_MISMATCH         | blocking     | an allocation attribute that references the OTHER purpose's fact variable (e.g. a connector on `var.subnet_cidr`) |
|             | POLICY.CIDR_NOT_ALLOCATED         | blocking (PLATFORM_DEFECT) | a CIDR literal where the platform holds no allocation for that purpose (the AI cannot fix it) |
|             | POLICY.CIDR_FACT_REUSED           | blocking     | two or more allocation attributes of one purpose that are exactly `var.<fact>` (both would get the same range: an overlap at apply); the hint gives each its own `cidrsubnet(var.subnet_cidr, newbits, i)` |
| V2h-secondary | POLICY.CIDR_LITERAL_SECONDARY   | report_only  | GKE `secondary_ip_range` literals (no platform fact yet: lane 11 owner question Q10) |

TI-5-R2 P5: an allocation attribute that takes an address of its range (`platform_facts.ADDRESS_ATTRIBUTE_VALUES`:
networking-vpc `psa_address`) gets a hint with the exact expressions (`cidrhost(var.psa_cidr, 0)` and its
`psa_prefix_length`) instead of `var.<fact>`, never counts as a whole-range reuse, and set to exactly `var.<fact>`
(the range itself) is POLICY.CIDR_FACT_MISMATCH with that hint.

Rules read python-hcl2 values only: a literal is a string with no `${` (python-hcl2 renders every expression as
`"${...}"`, the convention of `step1._literal`); a CIDR is whatever `ipaddress.ip_network` parses; a reference is an
exact equality with `"${var.<name>}"` / `"${local.<name>}"` built from the names the AI declared. Nothing is matched by
substring or regex, nothing is rewritten. Each diagnostic names the exact platform variable to use (hint).

Existing workloads (the repository already declares network allocations): their ranges are pinned by live state and
adopted by lane 11's migration (RT F3), so every finding is downgraded to a warning (measured, never repaired).
"""
from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Mapping, Optional, Tuple

try:
    from shared.diagnostics import Diagnostic, ErrorClass
except ImportError:  # pragma: no cover
    from ...shared.diagnostics import Diagnostic, ErrorClass  # type: ignore

from ..assembly import Block
from ..platform_facts import (FACT_VARIABLE, PURPOSE_CONNECTOR, PURPOSE_SUBNET, PURPOSES, SECONDARY_RANGE_BLOCKS,
                              FactsHolder, NetworkFacts, address_attribute_value, allocation_attributes_for)
from .base import ValidationContext
from .step1 import _d, _literal, _llm_blocks

CODE_LITERAL = "POLICY.CIDR_LITERAL"
CODE_MISMATCH = "POLICY.CIDR_FACT_MISMATCH"
CODE_NOT_ALLOCATED = "POLICY.CIDR_NOT_ALLOCATED"
CODE_SECONDARY = "POLICY.CIDR_LITERAL_SECONDARY"
CODE_REUSED = "POLICY.CIDR_FACT_REUSED"

HINT_USE_FACT = ('Set {attr} = var.{var} . The platform declares variable "{var}" in infra/workload/variables.tf and '
                 'supplies its value ({value}, allocated for this workload by the platform IPAM) in terraform.tfvars. '
                 'Never write a CIDR literal and never declare your own variable or local for an IP range.')
HINT_USE_FACT_SPLIT = ('Set {attr} = cidrsubnet(var.{var}, {newbits}, {index}) . The platform declares variable "{var}" in '
                       'infra/workload/variables.tf and supplies its value ({value}, allocated for this workload by the '
                       'platform IPAM) in terraform.tfvars. {total} allocation attributes need this range ({all}), so '
                       'each takes its own part: indexes 0 to {last} in that order, never the same one twice. Never '
                       'write a CIDR literal and never declare your own variable or local for an IP range.')
HINT_ONE_CONNECTOR = (' Only one connector range is allocated per workload ({total} connectors here): keep one '
                      'google_vpc_access_connector and point every service at it.')
HINT_DELETE_HOLDER = (' Delete {holder} (its value {literal} is a hardcoded CIDR) unless another block still needs it; '
                      'if one does, point that block at var.{var} too.')
HINT_MISMATCH = ('{attr} of {rtype} needs the {purpose_word} range: set {attr} = var.{var} ({value}); var.{wrong} is '
                 'the {wrong_word} range.')
# TI-5-R2 P5: an allocation attribute that takes an ADDRESS of its fact range (platform_facts.ADDRESS_ATTRIBUTE_VALUES,
# networking-vpc `psa_address`): the hint names the exact expressions instead of var.<fact>
HINT_USE_ADDRESS = ('Set {assignments} . The platform declares variable "{var}" in infra/workload/variables.tf and '
                    'supplies its value ({value}, allocated for this workload by the platform IPAM) in '
                    'terraform.tfvars. Never write an IP address or CIDR literal and never declare your own variable or '
                    'local for an IP range.')
HINT_MISMATCH_ADDRESS = ('{attr} of {rtype} needs the {purpose_word} range ({value}): set {assignments}; var.{wrong} '
                         'is the {wrong_word} range.')
PURPOSE_WORD = {"WORKLOAD_SUBNET": "workload subnet", "SERVERLESS_VPC_CONNECTOR": "VPC connector (/28)",
                "PRIVATE_SERVICES_ACCESS": "Private Services Access"}   # TI-5-F4
HINT_REUSED_SUBNET = ('{n} allocation attributes need var.{var} ({value}); used as is, this one overlaps the others '
                      'at apply. Give each its own part of the allocation: set {attr} = '
                      'cidrsubnet(var.{var}, {newbits}, {index}) here ({others}). Never write a CIDR literal and '
                      'never declare another variable for an IP range.')
HINT_REUSED_CONNECTOR = ('{n} allocation attributes need var.{var} ({value}), but a Serverless VPC Access connector '
                         'needs its own /28 and the platform allocates one connector range per workload: keep one '
                         'google_vpc_access_connector on var.{var} and point every service at that connector '
                         '({others}).')
HINT_SECONDARY = ("GKE secondary ranges are not platform facts yet (owner question Q10); this literal is measured "
                  "only.")


def is_cidr_literal(value: Any) -> Optional[str]:
    """The literal string when `value` is a literal that parses as an IP network, else None."""
    lit = _literal(value)
    if lit is None:
        return None
    try:
        ipaddress.ip_network(lit.strip(), strict=False)
    except ValueError:
        return None
    return lit


def _holders(ctx: ValidationContext) -> Tuple[Dict[str, Tuple[str, Block]], Dict[str, Tuple[str, Block, Any]]]:
    """The AI's own variables (name -> (path, block)) and locals (name -> (path, block, value))."""
    variables: Dict[str, Tuple[str, Block]] = {}
    locals_: Dict[str, Tuple[str, Block, Any]] = {}
    for path, b in _llm_blocks(ctx):
        if b.kind == "variable" and b.labels:
            variables.setdefault(b.labels[0], (path, b))
        elif b.kind == "locals":
            for name, value in (b.body or {}).items():
                if not name.startswith("__"):
                    locals_.setdefault(name, (path, b, value))
    return variables, locals_


class CidrFactValidator:
    """V2h: allocation attributes must reference the platform's IPAM fact variables."""

    id, tool = "V2h", "policy"

    def __init__(self, facts: Any, *, existing_network: bool = False):
        # `facts`: NetworkFacts, None, or a FactsHolder whose current facts are read at validate time (code RT F4:
        # the developer stage resolves facts per repair iteration, inside assemble())
        self._facts_source = facts
        self.existing_network = existing_network

    @property
    def facts(self) -> Optional[NetworkFacts]:
        src = self._facts_source
        return src.facts if isinstance(src, FactsHolder) else src

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        variables, locals_ = _holders(ctx)
        fact_vars = {FACT_VARIABLE[p]: p for p in PURPOSES}
        facts = self.facts
        out: List[Diagnostic] = []
        direct: Dict[str, List[Tuple[str, Block, str]]] = {}   # purpose -> attributes that are exactly var.<fact>
        # every allocation attribute per purpose, in file/block order: its position is the attribute's cidrsubnet
        # index when several attributes share one fact (code RT F5), so literal and reuse hints never collide
        slots: Dict[str, List[Tuple[str, Block, str]]] = {}
        for path, b in _llm_blocks(ctx):
            for attr, purpose in sorted(allocation_attributes_for(b.kind, b.labels, b.body).items()):
                if attr in (b.body or {}):
                    slots.setdefault(purpose, []).append((path, b, attr))
        for purpose in PURPOSES:
            for i, (path, b, attr) in enumerate(slots.get(purpose) or []):
                d = self._check(path, b, attr, purpose, b.body[attr], variables, locals_, fact_vars, ctx,
                                slot=(i, slots[purpose]))
                if d is not None:
                    out.append(d)
                elif (facts is not None and facts.value_for(purpose) is not None
                      and address_attribute_value(b.kind, b.labels, b.body, attr) is None
                      and b.body[attr] == f"${{var.{FACT_VARIABLE[purpose]}}}"):
                    direct.setdefault(purpose, []).append((path, b, attr))
        for purpose in PURPOSES:
            out.extend(self._reused(purpose, direct.get(purpose) or [], slots.get(purpose) or [], facts, ctx))
        out.sort(key=lambda d: (d.file, d.line or 0, d.attribute_path or "", d.code))
        return out

    def _reused(self, purpose: str, items: List[Tuple[str, Block, str]], slots: List[Tuple[str, Block, str]],
                facts: Optional[NetworkFacts], ctx: ValidationContext) -> List[Diagnostic]:
        """POLICY.CIDR_FACT_REUSED (code RT F5): one fact, several allocation attributes -> the same range twice."""
        # a whole-range reference overlaps every other attribute of the same purpose (reference or literal)
        if not items or len(slots) < 2 or facts is None:
            return []
        var, value, n = FACT_VARIABLE[purpose], facts.value_for(purpose), len(slots)
        newbits = max(1, (n - 1).bit_length())
        position = {(p, b.key, a): i for i, (p, b, a) in enumerate(slots)}
        out: List[Diagnostic] = []
        for path, b, attr in items:
            others = ", ".join(f"{ob.key}.{oa}" for op, ob, oa in slots if (op, ob.key, oa) != (path, b.key, attr))
            if purpose == PURPOSE_SUBNET:
                hint = HINT_REUSED_SUBNET.format(n=n, var=var, value=value, attr=attr, newbits=newbits,
                                                 index=position[(path, b.key, attr)], others="the others: " + others)
            else:
                hint = HINT_REUSED_CONNECTOR.format(n=n, var=var, value=value, others="the others: " + others)
            out.append(self._finish(_d(
                tool="policy", code=CODE_REUSED,
                message=f"{b.key}.{attr} uses var.{var} ({value}) as is, but {others} need(s) the same range",
                detail=f"purpose={purpose} variable=var.{var} allocated={value} uses={n}", hint=hint,
                file=path, line=b.start, end_line=b.end, block_address=b.key, attribute_path=attr,
                iteration=ctx.iteration)))
        return out

    def _check(self, path: str, b: Block, attr: str, purpose: str, value: Any,
               variables: Mapping[str, Tuple[str, Block]], locals_: Mapping[str, Tuple[str, Block, Any]],
               fact_vars: Mapping[str, str], ctx: ValidationContext,
               slot: Tuple[int, List[Tuple[str, Block, str]]] = (0, [])) -> Optional[Diagnostic]:
        common = dict(file=path, line=b.start, end_line=b.end, block_address=b.key, attribute_path=attr,
                      iteration=ctx.iteration)
        var = FACT_VARIABLE[purpose]
        address = address_attribute_value(b.kind, b.labels, b.body, attr)   # TI-5-R2 P5
        assignments = (" and ".join(f"{a} = {e}" for a, e in ((attr, address[0]),) + tuple(address[1]))
                       if address is not None else None)
        allocated = self.facts.value_for(purpose) if self.facts is not None else None
        platform_declared = set(self.facts.variables()) if self.facts is not None else set()
        literal = is_cidr_literal(value)
        holder = None
        if (assignments and allocated is not None and var in platform_declared
                and value == f"${{var.{var}}}"):
            # TI-5-R2 P5 (RT 11-07 F2): the whole range in an address input (networking-vpc psa_address) only fails
            # the module's own validation at plan; exact equality, the rule's convention
            return self._finish(_d(
                tool="policy", code=CODE_MISMATCH,
                message=f"{b.key}.{attr} is var.{var}, the whole {PURPOSE_WORD[purpose]} range; it takes the "
                        f"range's network address",
                hint=HINT_USE_ADDRESS.format(assignments=assignments, var=var, value=allocated), **common))
        if literal is None and isinstance(value, str):
            for name in variables:
                if value == f"${{var.{name}}}" and name not in platform_declared:
                    lit = is_cidr_literal((variables[name][1].body or {}).get("default"))
                    if lit is not None:
                        literal, holder = lit, f'variable "{name}"'
                    break
            else:
                for name, (_p, _b, lval) in locals_.items():
                    if value == f"${{local.{name}}}":
                        lit = is_cidr_literal(lval)
                        if lit is not None:
                            literal, holder = lit, f"local.{name}"
                        break
            if literal is None:
                for other, other_purpose in fact_vars.items():
                    if (other_purpose != purpose and other in platform_declared and allocated is not None
                            and value == f"${{var.{other}}}"):
                        rtype = b.labels[0] if b.labels else b.key
                        hint = (HINT_MISMATCH_ADDRESS.format(attr=attr, rtype=rtype, assignments=assignments,
                                                             purpose_word=PURPOSE_WORD[purpose], value=allocated,
                                                             wrong=other, wrong_word=PURPOSE_WORD[other_purpose])
                                if assignments else
                                HINT_MISMATCH.format(attr=attr, rtype=rtype, purpose_word=PURPOSE_WORD[purpose],
                                                     var=var, value=allocated, wrong=other,
                                                     wrong_word=PURPOSE_WORD[other_purpose]))
                        return self._finish(_d(
                            tool="policy", code=CODE_MISMATCH,
                            message=f"{b.key}.{attr} references var.{other}, the platform's "
                                    f"{PURPOSE_WORD[other_purpose]} range",
                            hint=hint, **common))
        if literal is None:
            return None
        where = f" (through {holder})" if holder else ""
        if allocated is None and self.existing_network:
            # nothing is allocated for an existing network on purpose: the literal is the live, pinned range
            return self._finish(_d(
                tool="policy", code=CODE_LITERAL,
                message=f"{b.key}.{attr} is the hardcoded CIDR {literal}{where}",
                detail=f"purpose={purpose} variable=var.{var} allocated=none", **common))
        if allocated is None:
            return self._finish(_d(
                tool="policy", code=CODE_NOT_ALLOCATED, error_class=ErrorClass.PLATFORM_DEFECT,
                message=f"{b.key}.{attr} is the hardcoded CIDR {literal}{where} and the platform holds no "
                        f"{PURPOSE_WORD[purpose]} allocation for this workload",
                detail=f"purpose={purpose}", **common))
        index, same = slot
        if assignments:   # TI-5-R2 P5: an address of the range (networking-vpc psa_address)
            hint = HINT_USE_ADDRESS.format(assignments=assignments, var=var, value=allocated)
        elif purpose == PURPOSE_SUBNET and len(same) > 1:
            hint = HINT_USE_FACT_SPLIT.format(attr=attr, var=var, value=allocated, index=index, total=len(same),
                                              newbits=max(1, (len(same) - 1).bit_length()), last=len(same) - 1,
                                              all=", ".join(f"{sb.key}.{sa}" for _p, sb, sa in same))
        else:
            hint = HINT_USE_FACT.format(attr=attr, var=var, value=allocated)
            if len(same) > 1 and purpose == PURPOSE_CONNECTOR:
                hint += HINT_ONE_CONNECTOR.format(total=len(same))
        if holder:
            hint += HINT_DELETE_HOLDER.format(holder=holder, literal=literal, var=var)
        return self._finish(_d(
            tool="policy", code=CODE_LITERAL,
            message=f"{b.key}.{attr} is the hardcoded CIDR {literal}{where}; IP ranges are platform IPAM facts",
            detail=f"purpose={purpose} variable=var.{var} allocated={allocated}", hint=hint, **common))

    def _finish(self, d: Diagnostic) -> Diagnostic:
        if not self.existing_network:
            return d
        # existing workload: the range is pinned by live state (adopted by lane 11's migration), never re-allocated
        return d.model_copy(update={"severity": "warning", "error_class": ErrorClass.CODE_DEFECT,
                                    "message": d.message + " (existing network: pinned, measured only)"})


class CidrSecondaryLiteralValidator:
    """V2h-secondary (report-only): GKE secondary range literals; no platform fact yet (lane 11 Q10)."""

    id, tool = "V2h-secondary", "policy"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        out: List[Diagnostic] = []
        for path, b in _llm_blocks(ctx):
            if b.kind != "resource" or not b.labels or b.labels[0] not in SECONDARY_RANGE_BLOCKS:
                continue
            block_name, attr = SECONDARY_RANGE_BLOCKS[b.labels[0]]
            nested = (b.body or {}).get(block_name)
            for i, sub in enumerate(nested if isinstance(nested, list) else []):
                lit = is_cidr_literal((sub or {}).get(attr)) if isinstance(sub, dict) else None
                if lit is None:
                    continue
                out.append(_d(tool="policy", code=CODE_SECONDARY, severity="warning", file=path,
                              line=(sub.get("__start_line__") or b.start), end_line=sub.get("__end_line__") or b.end,
                              block_address=b.key, attribute_path=f"{block_name}[{i}].{attr}",
                              message=f"{b.key}.{block_name}[{i}].{attr} is the hardcoded CIDR {lit}",
                              hint=HINT_SECONDARY, iteration=ctx.iteration))
        return out


def register(stack: Any, facts: Any, *, existing_network: bool = False) -> None:
    stack.register(CidrFactValidator(facts, existing_network=existing_network), "blocking")
    stack.register(CidrSecondaryLiteralValidator(), "report_only")


__all__ = ["CidrFactValidator", "CidrSecondaryLiteralValidator", "register", "is_cidr_literal", "CODE_LITERAL",
           "CODE_MISMATCH", "CODE_NOT_ALLOCATED", "CODE_REUSED", "CODE_SECONDARY"]
