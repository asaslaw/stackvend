"""Platform-owned network facts for the developer stage (Wave 2 lane 11 near-term, FD-52 / FD-4AK / FD-4AL).

The AI must never invent an IP range (AGENTS.md invariant 3: CIDRs come from IPAM). This module turns the platform's
IPAM allocations for one workload into **typed inputs the AI must reference**:

* `NetworkFacts` - the allocated ranges (`subnet_cidr`, `connector_cidr`) and the region they were allocated in;
* `render_fact_variables(facts)` - `variable "subnet_cidr"` / `variable "connector_cidr"` blocks the platform appends to
  its rendered `infra/workload/variables.tf` (no default, a `cidrnetmask` validation);
* `render_fact_tfvars(facts)` - the values, written into the platform-rendered `infra/workload/terraform.tfvars`
  (the terraform server keeps every key of that file it does not own itself: `deploy_workload`'s tfvars merge);
* `ALLOCATION_ATTRIBUTES` - the exact (block kind, type / module path, attribute) table that says which attribute
  must reference which fact variable. `validators/platform_facts.py` checks it (`POLICY.CIDR_LITERAL`).

Variable names are the canonical lane 11 names (integration plan I-6): `var.subnet_cidr`, `var.connector_cidr`.

Which facts a run needs is read from the parsed draft (exact resource types / module path, `required_network_purposes`),
never guessed from text. Allocation is done by a facts provider on the hallucination-stack runtime:
`MemoryFactsProvider` here (eval harness, unit tests: an in-memory ledger, deterministic), `FirestoreFactsProvider` in
`stack_clients.py` (production: the IPAM ledger `cidr_allocations` through `shared.ipam.CastorIPAMEngine`, the
transactional allocator the architect also uses (FD-4BZ); fail-closed). Lane 11b's vending-time allocation replaces
the provider's allocation step; the validator and the rendered variables stay.

Nothing here edits AI code. Every function except the providers' `resolve` is pure.
"""
from __future__ import annotations

import ipaddress
import posixpath
from dataclasses import dataclass, field, replace
from typing import Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Tuple

from pydantic import BaseModel, ConfigDict, field_validator

WORKLOAD = "infra/workload/"

PURPOSE_SUBNET = "WORKLOAD_SUBNET"
PURPOSE_CONNECTOR = "SERVERLESS_VPC_CONNECTOR"
# TI-5-F4 (owner 10-21): the Private Services Access range of the platform-rendered network (typed-intent path:
# iac_intent_contract.intent_network_purposes asks for it). TI-5-R2 P5 (owner 10-25): on the classic path only an AI
# networking-vpc call that sets `psa_address` needs it (OPTIONAL_ALLOCATION_ATTRIBUTES). Last in PURPOSES so the
# allocation order of the two older purposes is unchanged.
PURPOSE_PSA = "PRIVATE_SERVICES_ACCESS"
PURPOSES: Tuple[str, ...] = (PURPOSE_SUBNET, PURPOSE_CONNECTOR, PURPOSE_PSA)
# TI-5-F4: prefix length of a PSA range. Google Cloud needs an allocated range of at least /24, and each service that
# peers through it (AlloyDB, Cloud SQL) uses a /24 of it; a /20 holds 16 /24s. TI-5-R2 P1 (owner 10-25): the platform
# setting `orchestration.ipam_psa_prefix` (16..24) decides it; this is its default (and the pool's when built bare).
PSA_PREFIX = 20

# purpose -> the platform variable that carries its allocated range (canonical lane 11 names, integration I-6)
FACT_VARIABLE: Mapping[str, str] = {PURPOSE_SUBNET: "subnet_cidr", PURPOSE_CONNECTOR: "connector_cidr",
                                    PURPOSE_PSA: "psa_cidr"}
FACT_PURPOSE: Mapping[str, str] = {v: k for k, v in FACT_VARIABLE.items()}
FACT_DESCRIPTION: Mapping[str, str] = {
    PURPOSE_SUBNET: "Workload subnet range allocated by the platform IPAM (platform-owned; never a literal)",
    PURPOSE_CONNECTOR: "Serverless VPC Access connector range allocated by the platform IPAM (platform-owned; /28)",
    PURPOSE_PSA: "Private Services Access range allocated by the platform IPAM (platform-owned; never a literal)",
}

# The golden network module, addressed exactly as a root-module call resolves its local source.
NETWORK_MODULE_DIR = "infra/modules/networking-vpc"
# FD-4BH: the golden Serverless VPC Access connector module (its connector_cidr is the IPAM connector range).
CONNECTOR_MODULE_DIR = "infra/modules/networking-vpc-connector"

# Exact allocation-attribute table: (kind, type-or-module-dir) -> {attribute: purpose}. An attribute listed here
# allocates address space for this workload, so its value must be the platform's fact variable.
ALLOCATION_ATTRIBUTES: Mapping[Tuple[str, str], Mapping[str, str]] = {
    ("resource", "google_compute_subnetwork"): {"ip_cidr_range": PURPOSE_SUBNET},
    ("resource", "google_vpc_access_connector"): {"ip_cidr_range": PURPOSE_CONNECTOR},
    # TI-5-R2 P5: + the network address of the Private Services Access range (with psa_prefix_length)
    ("module", NETWORK_MODULE_DIR): {"primary_subnet_cidr": PURPOSE_SUBNET, "psa_address": PURPOSE_PSA},
    ("module", CONNECTOR_MODULE_DIR): {"connector_cidr": PURPOSE_CONNECTOR},   # FD-4BH golden connector module
    ("module", "infra/modules/compute-gce-worker"): {"subnet_cidr": PURPOSE_SUBNET},   # lane 10 L10-u
}
# TI-5-R2 P5 (owner 10-25): allocation attributes that are optional inputs: their purpose is needed only when the
# block sets them (present and not null). networking-vpc's `psa_address` defaults to null (Google allocates the
# range), so a network call without it asks for its subnet only, exactly as before.
OPTIONAL_ALLOCATION_ATTRIBUTES: Mapping[Tuple[str, str], FrozenSet[str]] = {
    ("module", NETWORK_MODULE_DIR): frozenset({"psa_address"}),
}
# TI-5-R2 P5: allocation attributes that take an address of the fact range, not the range itself -> the exact value
# (the expressions the typed-intent render uses, shared/iac_intent _PLATFORM_NETWORK_PSA_ARGS) and the companion
# inputs that must be set with it. Read by the V2h hint only.
ADDRESS_ATTRIBUTE_VALUES: Mapping[Tuple[str, str], Mapping[str, Tuple[str, Tuple[Tuple[str, str], ...]]]] = {
    ("module", NETWORK_MODULE_DIR): {
        "psa_address": ("cidrhost(var.psa_cidr, 0)",
                        (("psa_prefix_length", 'tonumber(element(split("/", var.psa_cidr), 1))'),)),
    },
}
# GKE pods/services secondary ranges: no platform fact yet (lane 11 owner question Q10), so report-only.
SECONDARY_RANGE_BLOCKS: Mapping[str, Tuple[str, str]] = {
    "google_compute_subnetwork": ("secondary_ip_range", "ip_cidr_range"),
}


class FactsUnavailable(Exception):
    """The facts provider could not read or allocate (Firestore error, pool exhausted, contention). Never a pass:
    the developer stage stops with GATE_UNAVAILABLE."""


def _cidr(value: str) -> str:
    net = ipaddress.ip_network(value, strict=True)   # a host-bit CIDR is not an allocation
    return str(net)


class NetworkFacts(BaseModel):
    """The IPAM allocations of one workload, as the developer stage renders them."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    product_id: str
    region: str
    subnet_cidr: Optional[str] = None
    connector_cidr: Optional[str] = None
    psa_cidr: Optional[str] = None            # TI-5-F4 typed-intent network; TI-5-R2 P5 classic psa_address
    source: str = "ipam"                      # "ipam" (ledger) | "memory" (harness / tests)

    @field_validator("subnet_cidr", "connector_cidr", "psa_cidr")
    @classmethod
    def _valid_cidr(cls, v: Optional[str]) -> Optional[str]:
        return None if v is None else _cidr(v)

    def value_for(self, purpose: str) -> Optional[str]:
        return {PURPOSE_SUBNET: self.subnet_cidr, PURPOSE_CONNECTOR: self.connector_cidr,
                PURPOSE_PSA: self.psa_cidr}.get(purpose)

    def variables(self) -> Dict[str, str]:
        """Declared fact variable -> allocated value, in a fixed order."""
        out: Dict[str, str] = {}
        for p in PURPOSES:
            v = self.value_for(p)
            if v is not None:
                out[FACT_VARIABLE[p]] = v
        return out

    def restricted_to(self, names: Iterable[str]) -> Optional["NetworkFacts"]:
        """These facts limited to the given fact variable names (None when nothing is left)."""
        keep = set(names)
        values = {n: v for n, v in self.variables().items() if n in keep}
        if not values:
            return None
        return NetworkFacts(product_id=self.product_id, region=self.region, source=self.source, **values)


class FactsHolder:
    """The facts of the current repair-loop iteration (code RT F4): `assemble()` resolves them for the draft it
    assembles and the V2h validator reads the same object, so the rendered declarations and the rule always agree.
    Facts only grow within a dispatch."""

    def __init__(self, facts: Optional[NetworkFacts] = None):
        self.facts = facts


def normalize_product_id(product_id: str) -> str:
    """The ledger key, normalized exactly as `shared.ipam.CastorIPAMEngine` does (strip + lower; code RT F6.2)."""
    return str(product_id).strip().lower()


# ------------------------------------------------------------------------------------------------ rendering
def render_fact_variables(facts: Optional[NetworkFacts]) -> str:
    """HCL appended to the platform's variables.tf ("" when there are no facts, so the render is byte-identical)."""
    if facts is None or not facts.variables():
        return ""
    out = ["", "# Platform network facts (IPAM). Values are supplied in terraform.tfvars by the platform; reference",
           "# these variables, never a CIDR literal."]
    for p in PURPOSES:
        if facts.value_for(p) is None:
            continue
        name = FACT_VARIABLE[p]
        out += [
            f'variable "{name}" {{',
            f'  description = "{FACT_DESCRIPTION[p]}"',
            "  type        = string",
            "  validation {",
            f"    condition     = can(cidrnetmask(var.{name}))",
            f'    error_message = "{name} must be an IPv4 CIDR allocated by the platform IPAM."',
            "  }",
            "}",
            "",
        ]
    return "\n".join(out)


def render_fact_tfvars(facts: Optional[NetworkFacts]) -> List[str]:
    """terraform.tfvars lines (same alignment as the developer's other platform tfvars lines)."""
    if facts is None:
        return []
    return [f'{name:<26} = "{value}"' for name, value in facts.variables().items()]


# ------------------------------------------------------------------------------------------------ draft reading
def module_dir(source: object) -> Optional[str]:
    """A root-module call's literal local source resolved against infra/workload/ (exact path arithmetic)."""
    if not isinstance(source, str) or "${" in source or not source.startswith(("./", "../")):
        return None
    return posixpath.normpath(posixpath.join(WORKLOAD, source))


def _is_root_tf(path: str) -> bool:
    return path.startswith(WORKLOAD) and path.endswith(".tf") and "/" not in path[len(WORKLOAD):]


def required_network_purposes(files: Mapping[str, str], *, paths: Optional[Iterable[str]] = None) -> FrozenSet[str]:
    """Purposes whose allocation attributes appear in the given root-module files (exact block types / module path,
    python-hcl2). A file python-hcl2 cannot parse contributes nothing (V1a-llm reports it)."""
    from .assembly import index_blocks

    wanted = set(paths) if paths is not None else None
    found = set()
    for path in sorted(files):
        if not _is_root_tf(path) or (wanted is not None and path not in wanted):
            continue
        text = files[path]
        if not isinstance(text, str):
            continue
        for b in index_blocks(text) or []:
            key = _allocation_key(b.kind, b.labels, b.body)
            optional = OPTIONAL_ALLOCATION_ATTRIBUTES.get(key, frozenset()) if key else frozenset()
            for attr_purposes in _allocation_table_for(b.kind, b.labels, b.body):
                # TI-5-R2 P5: an optional attribute counts only when the block sets it
                found.update(p for a, p in attr_purposes.items()
                             if a not in optional or (b.body or {}).get(a) is not None)
    return frozenset(found)


def _allocation_key(kind: str, labels: Sequence[str], body: Mapping) -> Optional[Tuple[str, str]]:
    """The ALLOCATION_ATTRIBUTES key of a block (resource type / resolved local module directory), else None."""
    if kind == "resource" and labels:
        return ("resource", labels[0])
    if kind == "module":
        d = module_dir((body or {}).get("source"))
        return ("module", d) if d else None
    return None


def _allocation_table_for(kind: str, labels: Sequence[str], body: Mapping) -> List[Mapping[str, str]]:
    key = _allocation_key(kind, labels, body)
    t = ALLOCATION_ATTRIBUTES.get(key) if key else None
    return [t] if t else []


def address_attribute_value(kind: str, labels: Sequence[str], body: Mapping,
                            attr: str) -> Optional[Tuple[str, Tuple[Tuple[str, str], ...]]]:
    """TI-5-R2 P5: (exact value, companion inputs) when `attr` of this block takes an address of its fact range
    (ADDRESS_ATTRIBUTE_VALUES), else None (the attribute takes the range itself, var.<fact>)."""
    key = _allocation_key(kind, labels, body)
    return (ADDRESS_ATTRIBUTE_VALUES.get(key) or {}).get(attr) if key else None


def allocation_attributes_for(kind: str, labels: Sequence[str], body: Mapping) -> Mapping[str, str]:
    tables = _allocation_table_for(kind, labels, body)
    return tables[0] if tables else {}


def committed_fact_values(existing_files: Optional[Mapping[str, str]]) -> Dict[str, str]:
    """Fact variable -> value in the repository's committed platform tfvars (`infra/workload/terraform.tfvars`, parsed
    with python-hcl2). Empty when the file is absent or carries no fact variable (a workload generated before facts).
    An unparseable committed tfvars raises FactsUnavailable: the pinned values cannot be read, so nothing is guessed."""
    text = (existing_files or {}).get(WORKLOAD + "terraform.tfvars")
    if not isinstance(text, str) or not text.strip():
        return {}
    import hcl2
    try:
        doc = hcl2.loads(text)
    except Exception as e:  # noqa: BLE001 - python-hcl2 raises lark errors
        raise FactsUnavailable(f"IPAM.COMMITTED_TFVARS_UNREADABLE: {type(e).__name__}: {e}") from e
    out: Dict[str, str] = {}
    for p in PURPOSES:
        name = FACT_VARIABLE[p]
        if name in doc:
            value = doc[name]
            try:
                out[name] = _cidr(value) if isinstance(value, str) else ""
            except ValueError:
                out[name] = ""
            if not out[name]:
                raise FactsUnavailable(f"IPAM.COMMITTED_TFVARS_UNREADABLE: {name} = {value!r} is not a CIDR")
    return out


def has_existing_network(existing_files: Optional[Mapping[str, str]]) -> bool:
    """True when the repository already declares network allocations (an existing workload): its ranges are pinned by
    live state and are adopted by lane 11's migration, never re-allocated here (lane 11 RT F3)."""
    return bool(existing_files) and bool(required_network_purposes(existing_files))


# ------------------------------------------------------------------------------------------------ allocation
def next_free_block(supernet: str, prefix_len: int, occupied: Iterable[str]) -> Optional[str]:
    """First /prefix_len block of the supernet that overlaps no occupied range (the IPAM engine's order)."""
    pool = ipaddress.ip_network(supernet, strict=True)
    taken = [ipaddress.ip_network(c, strict=False) for c in occupied]
    for cand in pool.subnets(new_prefix=prefix_len):
        if not any(cand.overlaps(o) for o in taken):
            return str(cand)
    return None


@dataclass(frozen=True)
class IpamPool:
    """The allocation parameters, read from platform settings (`orchestration.ipam_*`, `default_gcp_region`)."""

    supernet: str
    subnet_prefix: int
    connector_prefix: int
    region: str
    psa_prefix: int = PSA_PREFIX              # TI-5-F4; TI-5-R2 P1: orchestration.ipam_psa_prefix

    def prefix_for(self, purpose: str) -> int:
        if purpose == PURPOSE_PSA:
            return self.psa_prefix
        return self.subnet_prefix if purpose == PURPOSE_SUBNET else self.connector_prefix

    def for_region(self, region: Optional[str]) -> "IpamPool":
        """FD-7M-a: this pool with the workload's region (the region the IPAM ledger records carry). None / "" or the
        same region -> this pool unchanged (a workload in the default region allocates exactly as before)."""
        if not region or region == self.region:
            return self
        return replace(self, region=str(region))

    @staticmethod
    def from_settings(settings: object) -> "IpamPool":
        orch = getattr(settings, "orchestration")
        return IpamPool(supernet=str(orch.ipam_supernet_cidr), subnet_prefix=int(orch.ipam_subnet_prefix),
                        connector_prefix=int(orch.ipam_connector_prefix), region=str(orch.default_gcp_region),
                        psa_prefix=int(orch.ipam_psa_prefix))


def load_ipam_pool(project_id: Optional[str] = None) -> IpamPool:
    """The platform IPAM pool from platform settings: the one reader both the architect and the developer stage use
    (FD-4BZ RT F2), so the two stages draw from the same supernet with the same configured prefixes.

    FD-4AK: the read is strict -- an unreadable or invalid settings document raises a typed
    PlatformSettingsUnavailable (never the compile-time pool); a missing document (fresh install) is the defaults
    (10.100.0.0/16, connector /28, PSA /20; a stored document without `ipam_psa_prefix` gets the /20 default from the
    settings model). Raises whatever an unusable settings object raises; each caller fails closed on
    that (no range)."""
    from shared.settings import get_platform_settings
    return IpamPool.from_settings(get_platform_settings(project_id=project_id, strict=True))


@dataclass
class MemoryFactsProvider:
    """Deterministic in-memory IPAM ledger (eval harness, unit tests). Same allocation order as the IPAM engine."""

    ledger: Dict[Tuple[str, str], str] = field(default_factory=dict)   # (product_id, purpose) -> CIDR
    name: str = "memory"

    def resolve(self, product_id: str, purposes: Iterable[str], *, pool: IpamPool,
                project_id: str = "", allocate: bool = True) -> NetworkFacts:
        """`allocate=False` (existing network): reuse this product's records only, never add one."""
        product_id = normalize_product_id(product_id)
        wanted = set(purposes)
        values: Dict[str, str] = {}
        for p in PURPOSES:
            if p not in wanted:
                continue
            key = (product_id, p)
            if key not in self.ledger and not allocate:
                continue
            if key not in self.ledger:
                got = next_free_block(pool.supernet, pool.prefix_for(p), self.ledger.values())
                if got is None:
                    raise FactsUnavailable(f"IPAM.POOL_EXHAUSTED: no free /{pool.prefix_for(p)} in {pool.supernet}")
                self.ledger[key] = got
            values[FACT_VARIABLE[p]] = self.ledger[key]
        return NetworkFacts(product_id=product_id, region=pool.region, source="memory", **values)
