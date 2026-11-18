"""
StackVend compliance enforcement engine (lane 14 PR-0, FD-4S): the checks that make the compliance agent's
"Enforced" lines true.

One typed check table, evaluated over PARSED data only:
  * `evaluate_plan`  - `tofu show -json <plan>` output (the enforcing point: the terraform MCP / tf-applier call
                       `/evaluate-plan` after `tofu plan` and before every apply).
  * `evaluate_hcl`   - python-hcl2 parse of the HCL files (pre-commit, advisory; replaces the old substring body of
                       `/evaluate-hcl`). Unparsable HCL is `PARSE_ERROR`, never a guess.

No substring or regex matching anywhere in this module: resource types, attribute paths, roles, members, ingress
values and locations are compared with `==` / set membership; KMS key names and Terraform references are split
positionally.

What is checked (and only this):
  * CMEK (`requires_cmek` of the profile): every resource of a type in `CMEK_ATTRIBUTE_PATHS` sets its CMEK attribute
    to a KMS crypto-key name, or (when the value is only known after apply) to an expression whose references resolve
    to a `google_kms_crypto_key` resource or data source.
  * Audit logging (`requires_audit_logging`): a `google_project_iam_audit_config` for `allServices` with DATA_READ and
    DATA_WRITE.
  * Regions (regulated profiles only): every `location` / `region` / `zone` is inside the profile's `allowed_regions`
    (intersected with the folder's `gcp.resourceLocations` when the stored decision carries it). STANDARD's literal
    `allowed_regions` is a planning default, not a control, and is never enforced (invariant 3).
  * Ingress (from the stored compliance decision, any profile): Direct IAP on every Cloud Run v2 service when the
    decision enabled it; no `allUsers` invoker (and no `invoker_iam_disabled`) when unauthenticated access is not
    allowed; private ingress when the decision requires it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

GATE_CONTRACT_VERSION = 1

DECISION_PASS = "PASS"
DECISION_VIOLATION = "VIOLATION"
DECISION_REFUSED = "REFUSED"

ERROR_COMPLIANCE_VIOLATION = "COMPLIANCE_VIOLATION"
ERROR_UNKNOWN_PROFILE = "UNKNOWN_PROFILE"
ERROR_UNRESOLVED_LOCATION_GROUP = "UNRESOLVED_LOCATION_GROUP"
ERROR_PLAN_INVALID = "PLAN_INVALID"
ERROR_PARSE = "PARSE_ERROR"
ERROR_PARSER_UNAVAILABLE = "PARSER_UNAVAILABLE"

# Exact profile vocabulary the gate accepts (the profiles `ComplianceService.get_compliance_requirements` defines).
# `get_compliance_requirements` maps an unknown value to STANDARD; the gate refuses it instead (UNKNOWN_PROFILE).
KNOWN_PROFILES = frozenset({
    "STANDARD", "HIPAA", "FEDRAMP_MODERATE", "FEDRAMP_HIGH", "CJIS", "EU_REGIONS_AND_SUPPORT", "PCI_DSS",
})
REGULATED_PROFILES = KNOWN_PROFILES - {"STANDARD"}

# CMEK attribute per CMEK-capable resource type (google provider schema paths). Each entry is a list of alternative
# paths; a resource passes when every leaf of at least one alternative passes. An int selects that block element,
# "*" means every element of the block list.
CMEK_ATTRIBUTE_PATHS: Dict[str, Tuple[Tuple[Any, ...], ...]] = {
    "google_storage_bucket": (("encryption", 0, "default_kms_key_name"),),
    "google_artifact_registry_repository": (("kms_key_name",),),
    "google_firestore_database": (("cmek_config", 0, "kms_key_name"),),
    "google_sql_database_instance": (("encryption_key_name",),),
    "google_bigquery_dataset": (("default_encryption_configuration", 0, "kms_key_name"),),
    "google_bigquery_table": (("encryption_configuration", 0, "kms_key_name"),),
    "google_pubsub_topic": (("kms_key_name",),),
    "google_compute_disk": (("disk_encryption_key", 0, "kms_key_self_link"),),
    "google_redis_instance": (("customer_managed_key",),),
    "google_container_cluster": (("database_encryption", 0, "key_name"),),
    "google_cloud_run_v2_service": (("template", 0, "encryption_key"),),
    "google_spanner_database": (("encryption_config", 0, "kms_key_name"),),
    "google_logging_project_bucket_config": (("cmek_settings", 0, "kms_key_name"),),
    "google_secret_manager_secret": (
        ("replication", 0, "auto", 0, "customer_managed_encryption", 0, "kms_key_name"),
        ("replication", 0, "user_managed", 0, "replicas", "*", "customer_managed_encryption", 0, "kms_key_name"),
    ),
}
KMS_KEY_RESOURCE_TYPE = "google_kms_crypto_key"

AUDIT_CONFIG_TYPE = "google_project_iam_audit_config"
AUDIT_ALL_SERVICES = "allServices"
AUDIT_REQUIRED_LOG_TYPES = frozenset({"DATA_READ", "DATA_WRITE"})

CLOUD_RUN_V2_SERVICE = "google_cloud_run_v2_service"
RUN_INVOKER_ROLE = "roles/run.invoker"
PUBLIC_MEMBERS = frozenset({"allUsers"})
RUN_IAM_MEMBER_TYPES = frozenset({"google_cloud_run_v2_service_iam_member", "google_cloud_run_service_iam_member"})
RUN_IAM_BINDING_TYPES = frozenset({"google_cloud_run_v2_service_iam_binding", "google_cloud_run_service_iam_binding"})
RUN_IAM_POLICY_TYPES = frozenset({"google_cloud_run_v2_service_iam_policy", "google_cloud_run_service_iam_policy"})
PRIVATE_INGRESS_VALUES = frozenset({"INGRESS_TRAFFIC_INTERNAL_ONLY", "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER"})

LOCATION_ATTRIBUTES = ("location", "region", "zone")
NON_REGIONAL_LOCATIONS = frozenset({"global"})
# RT14-36 (data residency): resource types whose location is named by another attribute, exact type -> attributes.
# A Spanner instance's `config` is its instance configuration: "regional-<region>" (or the resource name
# "projects/<p>/instanceConfigs/regional-<region>") names one region; any other configuration (multi-region such as
# nam3 / eur3) names no single region, so it is checked as itself and is in no allowed set (refused, never guessed).
# The terraform server projects these attributes too (mcp-servers/terraform/compliance_gate.PROJECTED_TYPE_ATTRIBUTES).
TYPE_LOCATION_ATTRIBUTES: Dict[str, Tuple[str, ...]] = {"google_spanner_instance": ("config",)}
SPANNER_REGIONAL_CONFIG_PREFIX = "regional-"

# Versioned region table used to resolve zones and `in:<group>` values of gcp.resourceLocations. An unknown group is
# refused (UNRESOLVED_LOCATION_GROUP), never guessed. Update the version when the table changes.
LOCATION_TABLE_VERSION = "2026-10-13"
GCP_REGIONS = frozenset({
    "us-central1", "us-east1", "us-east4", "us-east5", "us-south1", "us-west1", "us-west2", "us-west3", "us-west4",
    "northamerica-northeast1", "northamerica-northeast2", "northamerica-south1",
    "southamerica-east1", "southamerica-west1",
    "europe-central2", "europe-north1", "europe-north2", "europe-southwest1", "europe-west1", "europe-west2",
    "europe-west3", "europe-west4", "europe-west6", "europe-west8", "europe-west9", "europe-west10", "europe-west12",
    "asia-east1", "asia-east2", "asia-northeast1", "asia-northeast2", "asia-northeast3", "asia-south1", "asia-south2",
    "asia-southeast1", "asia-southeast2", "australia-southeast1", "australia-southeast2",
    "me-central1", "me-central2", "me-west1", "africa-south1",
})
LOCATION_GROUPS: Dict[str, frozenset] = {
    "in:us-locations": frozenset({
        "us-central1", "us-east1", "us-east4", "us-east5", "us-south1", "us-west1", "us-west2", "us-west3", "us-west4",
    }),
    "in:eu-locations": frozenset({
        "europe-central2", "europe-north1", "europe-north2", "europe-southwest1", "europe-west1", "europe-west3",
        "europe-west4", "europe-west8", "europe-west9", "europe-west10", "europe-west12",
    }),
    "in:europe-locations": frozenset({
        "europe-central2", "europe-north1", "europe-north2", "europe-southwest1", "europe-west1", "europe-west2",
        "europe-west3", "europe-west4", "europe-west6", "europe-west8", "europe-west9", "europe-west10",
        "europe-west12",
    }),
}
LOCATION_GROUP_PREFIX = "in:"
LOCATION_GROUP_SUFFIX = "-locations"
LOCATION_IS_PREFIX = "is:"

MAX_REFERENCE_DEPTH = 16


class PlanInvalid(ValueError):
    """The plan JSON does not have the `tofu show -json` shape the gate needs."""


class LocationGroupUnresolved(ValueError):
    """A gcp.resourceLocations value is not in the versioned table."""


@dataclass
class Violation:
    code: str
    address: str
    attribute: str = ""
    detail: str = ""

    def as_dict(self) -> Dict[str, str]:
        return {"code": self.code, "address": self.address, "attribute": self.attribute, "detail": self.detail}


@dataclass
class PlannedResource:
    address: str
    module_path: Tuple[str, ...]
    rtype: str
    name: str
    after: Dict[str, Any]
    after_unknown: Any


@dataclass
class Leaf:
    value: Any
    unknown: bool
    path: Tuple[Any, ...]


@dataclass
class GateResult:
    decision: str
    error_class: Optional[str]
    profile: str
    requirements: Dict[str, Any] = field(default_factory=dict)
    checks_run: List[str] = field(default_factory=list)
    violations: List[Violation] = field(default_factory=list)
    resources_evaluated: int = 0
    detail: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "gate_contract_version": GATE_CONTRACT_VERSION,
            "decision": self.decision,
            "error_class": self.error_class,
            "profile": self.profile,
            "requirements": self.requirements,
            "checks_run": list(self.checks_run),
            "violations": [v.as_dict() for v in self.violations],
            "resources_evaluated": self.resources_evaluated,
            "location_table_version": LOCATION_TABLE_VERSION,
            "detail": self.detail,
        }


# --------------------------------------------------------------------------------------------------------------
# Positional parsers (no regex)
# --------------------------------------------------------------------------------------------------------------

def is_kms_crypto_key_name(value: Any) -> bool:
    """`projects/<p>/locations/<l>/keyRings/<r>/cryptoKeys/<k>` (optionally `/cryptoKeyVersions/<v>`), positional."""
    if not isinstance(value, str) or not value:
        return False
    parts = value.split("/")
    if len(parts) not in (8, 10):
        return False
    if (parts[0], parts[2], parts[4], parts[6]) != ("projects", "locations", "keyRings", "cryptoKeys"):
        return False
    if len(parts) == 10 and parts[8] != "cryptoKeyVersions":
        return False
    return all(parts[i] for i in range(1, len(parts), 2))


def zone_region(value: str) -> Optional[str]:
    """`<region>-<letter>` -> region when <region> is in the table; else None."""
    head, sep, tail = value.rpartition("-")
    if sep and len(tail) == 1 and tail.isalpha() and head in GCP_REGIONS:
        return head
    return None


def spanner_config_location(value: str) -> str:
    """RT14-36: the region a Spanner instance configuration names (`regional-<region>`, bare or as
    `projects/<p>/instanceConfigs/regional-<region>`, with <region> in GCP_REGIONS); any other configuration is returned
    as written (lower-cased), which normalize_location keeps as itself and no allowed set contains."""
    name = value.strip().lower()
    parts = name.split("/")
    if len(parts) == 4 and parts[0] == "projects" and parts[1] and parts[2] == "instanceconfigs" and parts[3]:
        name = parts[3]
    if name.startswith(SPANNER_REGIONAL_CONFIG_PREFIX) and name[len(SPANNER_REGIONAL_CONFIG_PREFIX):] in GCP_REGIONS:
        return name[len(SPANNER_REGIONAL_CONFIG_PREFIX):]
    return name


_LOCATION_VALUE_PARSERS = {("google_spanner_instance", "config"): spanner_config_location}


def normalize_location(value: str) -> Optional[str]:
    """Region for a regional/zonal value, the lower-cased value for anything else; None for non-regional values."""
    loc = value.strip().lower()
    if loc in NON_REGIONAL_LOCATIONS:
        return None
    if loc in GCP_REGIONS:
        return loc
    return zone_region(loc) or loc


def resolve_org_allowed_locations(values: Sequence[str]) -> frozenset:
    """gcp.resourceLocations allowed values -> region set. Raises LocationGroupUnresolved on an unknown group."""
    out: set = set()
    for raw in values:
        if not isinstance(raw, str) or not raw:
            raise LocationGroupUnresolved(f"invalid allowed location value {raw!r}")
        val = raw.strip()
        if val.startswith(LOCATION_GROUP_PREFIX):
            if val in LOCATION_GROUPS:
                out |= LOCATION_GROUPS[val]
                continue
            middle = val[len(LOCATION_GROUP_PREFIX):]
            if middle.endswith(LOCATION_GROUP_SUFFIX):
                region = middle[: -len(LOCATION_GROUP_SUFFIX)]
                if region in GCP_REGIONS:
                    out.add(region)
                    continue
            raise LocationGroupUnresolved(f"location group {val!r} is not in table {LOCATION_TABLE_VERSION}")
        if val.startswith(LOCATION_IS_PREFIX):
            val = val[len(LOCATION_IS_PREFIX):]
        norm = normalize_location(val)
        if norm is not None:
            out.add(norm)
    return frozenset(out)


def _ref_segments(ref: str) -> List[str]:
    """Split a Terraform reference positionally; an index suffix (`name[0]`, `name["k"]`) is dropped per segment."""
    segs: List[str] = []
    for seg in ref.split("."):
        bracket = seg.find("[")
        segs.append(seg if bracket < 0 else seg[:bracket])
    return segs


def _is_kms_reference(segs: Sequence[str]) -> bool:
    if len(segs) >= 2 and segs[0] == KMS_KEY_RESOURCE_TYPE:
        return True
    return len(segs) >= 3 and segs[0] == "data" and segs[1] == KMS_KEY_RESOURCE_TYPE


def parse_module_address(module_address: str) -> Tuple[str, ...]:
    """`module.a["x"].module.b[0]` -> ("a", "b"). Raises PlanInvalid on any other shape."""
    if not module_address:
        return ()
    names: List[str] = []
    i, n = 0, len(module_address)
    prefix = "module."
    while i < n:
        if not module_address.startswith(prefix, i):
            raise PlanInvalid(f"bad module address {module_address!r}")
        i += len(prefix)
        start = i
        while i < n and module_address[i] not in ".[":
            i += 1
        if i == start:
            raise PlanInvalid(f"bad module address {module_address!r}")
        names.append(module_address[start:i])
        if i < n and module_address[i] == "[":
            in_quote = False
            while i < n:
                ch = module_address[i]
                if ch == '"':
                    in_quote = not in_quote
                elif ch == "]" and not in_quote:
                    i += 1
                    break
                i += 1
            else:
                raise PlanInvalid(f"bad module address {module_address!r}")
        if i < n:
            if module_address[i] != ".":
                raise PlanInvalid(f"bad module address {module_address!r}")
            i += 1
    return tuple(names)


# --------------------------------------------------------------------------------------------------------------
# Configuration index (references), shared by the plan and HCL adapters
# --------------------------------------------------------------------------------------------------------------

class ConfigIndex:
    """Reads `configuration` from `tofu show -json`: expressions, module calls, outputs, provider region."""

    def __init__(self, configuration: Any, variables: Any):
        self.root = (configuration or {}).get("root_module") if isinstance(configuration, dict) else None
        self.provider_config = (configuration or {}).get("provider_config") if isinstance(configuration, dict) else None
        self.variables = variables if isinstance(variables, dict) else {}

    def _module(self, path: Sequence[str]) -> Optional[Dict[str, Any]]:
        mod = self.root
        for name in path:
            if not isinstance(mod, dict):
                return None
            call = (mod.get("module_calls") or {}).get(name)
            if not isinstance(call, dict):
                return None
            mod = call.get("module")
        return mod if isinstance(mod, dict) else None

    def _call(self, path: Sequence[str]) -> Optional[Dict[str, Any]]:
        if not path:
            return None
        parent = self._module(path[:-1])
        if not isinstance(parent, dict):
            return None
        call = (parent.get("module_calls") or {}).get(path[-1])
        return call if isinstance(call, dict) else None

    def expression(self, module_path: Sequence[str], rtype: str, name: str, path: Sequence[Any]) -> Optional[Dict[str, Any]]:
        mod = self._module(module_path)
        if not isinstance(mod, dict):
            return None
        node: Any = None
        for res in mod.get("resources") or []:
            if isinstance(res, dict) and res.get("mode", "managed") == "managed" and res.get("type") == rtype and res.get("name") == name:
                node = res.get("expressions")
                break
        for step in path:
            if isinstance(step, int):
                if not isinstance(node, list) or not node:
                    return None
                node = node[step] if step < len(node) else (node[0] if len(node) == 1 else None)
            else:
                if not isinstance(node, dict):
                    return None
                node = node.get(step)
            if node is None:
                return None
        return node if isinstance(node, dict) else None

    def references_resolve_to_kms(self, module_path: Sequence[str], refs: Any, depth: int = 0) -> bool:
        if depth > MAX_REFERENCE_DEPTH or not isinstance(refs, list) or not refs:
            return False
        for ref in refs:
            if not isinstance(ref, str):
                continue
            segs = _ref_segments(ref)
            if _is_kms_reference(segs):
                return True
            if len(segs) >= 2 and segs[0] == "var" and module_path:
                call = self._call(module_path)
                expr = ((call or {}).get("expressions") or {}).get(segs[1])
                if isinstance(expr, dict) and self.references_resolve_to_kms(
                    tuple(module_path[:-1]), expr.get("references"), depth + 1
                ):
                    return True
            if len(segs) >= 3 and segs[0] == "module":
                child = tuple(module_path) + (segs[1],)
                mod = self._module(child)
                out = ((mod or {}).get("outputs") or {}).get(segs[2])
                expr = (out or {}).get("expression") if isinstance(out, dict) else None
                if isinstance(expr, dict) and self.references_resolve_to_kms(child, expr.get("references"), depth + 1):
                    return True
        return False

    def root_variable_value(self, ref: str) -> Optional[str]:
        segs = _ref_segments(ref)
        if len(segs) == 2 and segs[0] == "var":
            val = (self.variables.get(segs[1]) or {}).get("value") if isinstance(self.variables.get(segs[1]), dict) else None
            return val if isinstance(val, str) else None
        return None

    def expression_string_value(self, module_path: Sequence[str], expr: Optional[Dict[str, Any]]) -> Optional[str]:
        """A known string for an expression: a constant, or exactly one root-module `var.x` reference."""
        if not isinstance(expr, dict):
            return None
        if isinstance(expr.get("constant_value"), str):
            return expr["constant_value"]
        refs = expr.get("references")
        if module_path or not isinstance(refs, list) or not refs:
            return None
        values = {self.root_variable_value(r) for r in refs if isinstance(r, str)}
        values.discard(None)
        return values.pop() if len(values) == 1 else None

    def provider_default_region(self) -> Optional[str]:
        """The google provider's `region`, when every google / google-beta provider config resolves to one value."""
        if not isinstance(self.provider_config, dict):
            return None
        regions = set()
        for key, conf in self.provider_config.items():
            if not isinstance(conf, dict) or conf.get("name") not in ("google", "google-beta"):
                continue
            expr = (conf.get("expressions") or {}).get("region")
            val = self.expression_string_value((), expr)
            if val is None:
                return None
            regions.add(val)
        return regions.pop() if len(regions) == 1 else None


# --------------------------------------------------------------------------------------------------------------
# Leaf walking
# --------------------------------------------------------------------------------------------------------------

def _walk(after: Any, unknown: Any, path: Sequence[Any], done: Tuple[Any, ...] = ()) -> List[Leaf]:
    if not path:
        return [Leaf(after, unknown is True, done)]
    step, rest = path[0], path[1:]
    if unknown is True:
        return [Leaf(None, True, done + tuple(path))]
    if step == "*":
        if not isinstance(after, list) or not after:
            return [Leaf(None, False, done + tuple(path))]
        leaves: List[Leaf] = []
        unk_list = unknown if isinstance(unknown, list) else []
        for i, item in enumerate(after):
            leaves.extend(_walk(item, unk_list[i] if i < len(unk_list) else None, rest, done + (i,)))
        return leaves
    if isinstance(step, int):
        if not isinstance(after, list) or len(after) <= step:
            unk_item = unknown[step] if isinstance(unknown, list) and len(unknown) > step else None
            if unk_item is True:
                return [Leaf(None, True, done + tuple(path))]
            return [Leaf(None, False, done + tuple(path))]
        unk_item = unknown[step] if isinstance(unknown, list) and len(unknown) > step else None
        return _walk(after[step], unk_item, rest, done + (step,))
    unk_child = unknown.get(step) if isinstance(unknown, dict) else None
    child = after.get(step) if isinstance(after, dict) else None
    if child is None and unk_child is not True:
        return [Leaf(None, False, done + tuple(path))]
    return _walk(child, unk_child, rest, done + (step,))


def _path_str(path: Sequence[Any]) -> str:
    return ".".join(str(p) for p in path)


# --------------------------------------------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------------------------------------------

def _check_cmek(res: PlannedResource, config: ConfigIndex) -> Optional[Violation]:
    alternatives = CMEK_ATTRIBUTE_PATHS.get(res.rtype)
    if not alternatives:
        return None
    first_failure: Optional[Violation] = None
    for path in alternatives:
        leaves = _walk(res.after, res.after_unknown, path)
        failure: Optional[Violation] = None
        for leaf in leaves:
            if leaf.unknown:
                expr = config.expression(res.module_path, res.rtype, res.name, leaf.path)
                if not (isinstance(expr, dict) and config.references_resolve_to_kms(res.module_path, expr.get("references"))):
                    failure = Violation("CMEK_UNVERIFIABLE", res.address, _path_str(leaf.path),
                                        "value known only after apply and not traceable to a google_kms_crypto_key")
                    break
            elif leaf.value in (None, ""):
                failure = Violation("CMEK_MISSING", res.address, _path_str(leaf.path),
                                    "the profile requires a customer-managed encryption key")
                break
            elif not is_kms_crypto_key_name(leaf.value):
                failure = Violation("CMEK_INVALID_KEY", res.address, _path_str(leaf.path),
                                    "value is not a Cloud KMS crypto key name")
                break
        if failure is None:
            return None
        if first_failure is None:
            first_failure = failure
    return first_failure


def _check_audit_logging(resources: Sequence[PlannedResource]) -> Optional[Violation]:
    for res in resources:
        if res.rtype != AUDIT_CONFIG_TYPE or res.after.get("service") != AUDIT_ALL_SERVICES:
            continue
        log_types = set()
        for cfg in res.after.get("audit_log_config") or []:
            if isinstance(cfg, dict) and isinstance(cfg.get("log_type"), str):
                log_types.add(cfg["log_type"])
        if AUDIT_REQUIRED_LOG_TYPES <= log_types:
            return None
    return Violation("AUDIT_LOGGING_NOT_CONFIGURED", "(plan)", AUDIT_CONFIG_TYPE,
                     "the profile requires a google_project_iam_audit_config for allServices with DATA_READ and DATA_WRITE")


def _resource_locations(res: PlannedResource, config: ConfigIndex) -> List[Tuple[str, Optional[str]]]:
    """(attribute, value-or-None-if-unverifiable) for each location attribute the resource has."""
    out: List[Tuple[str, Optional[str]]] = []
    for attr in LOCATION_ATTRIBUTES + TYPE_LOCATION_ATTRIBUTES.get(res.rtype, ()):
        parse = _LOCATION_VALUE_PARSERS.get((res.rtype, attr))   # RT14-36: e.g. a Spanner instance configuration
        unk = res.after_unknown.get(attr) if isinstance(res.after_unknown, dict) else None
        if unk is True:
            expr = config.expression(res.module_path, res.rtype, res.name, (attr,))
            if expr is None:
                out.append((attr, config.provider_default_region() if attr == "region" else None))
            else:
                val = config.expression_string_value(res.module_path, expr)
                out.append((attr, parse(val) if parse is not None and isinstance(val, str) and val else val))
            continue
        val = res.after.get(attr) if isinstance(res.after, dict) else None
        if isinstance(val, str) and val:
            out.append((attr, parse(val) if parse is not None else val))
    return out


def _check_regions(res: PlannedResource, config: ConfigIndex, allowed: frozenset) -> List[Violation]:
    violations = []
    for attr, val in _resource_locations(res, config):
        if val is None:
            violations.append(Violation("LOCATION_UNVERIFIABLE", res.address, attr,
                                        "location known only after apply; a regulated profile needs it at plan time"))
            continue
        region = normalize_location(val)
        if region is not None and region not in allowed:
            violations.append(Violation("REGION_NOT_ALLOWED", res.address, attr,
                                        f"{val!r} is outside the allowed regions {sorted(allowed)}"))
    return violations


def _members_of(res: PlannedResource) -> Tuple[List[Any], bool]:
    """(members, unverifiable) for a Cloud Run IAM resource granting roles/run.invoker; ([], False) otherwise."""
    after, unk = res.after, res.after_unknown if isinstance(res.after_unknown, dict) else {}
    if res.rtype in RUN_IAM_MEMBER_TYPES:
        if after.get("role") != RUN_INVOKER_ROLE:
            return [], unk.get("role") is True
        return ([after.get("member")], unk.get("member") is True)
    if res.rtype in RUN_IAM_BINDING_TYPES:
        if after.get("role") != RUN_INVOKER_ROLE:
            return [], unk.get("role") is True
        return (list(after.get("members") or []), unk.get("members") is True)
    if res.rtype in RUN_IAM_POLICY_TYPES:
        if unk.get("policy_data") is True:
            return [], True
        try:
            policy = json.loads(after.get("policy_data") or "{}")
        except (TypeError, ValueError):
            return [], True
        members: List[Any] = []
        for binding in policy.get("bindings") or [] if isinstance(policy, dict) else []:
            if isinstance(binding, dict) and binding.get("role") == RUN_INVOKER_ROLE:
                members.extend(binding.get("members") or [])
        return members, False
    return [], False


def _check_ingress(resources: Sequence[PlannedResource], ingress: Dict[str, Any]) -> Tuple[List[str], List[Violation]]:
    checks: List[str] = []
    violations: List[Violation] = []
    want_iap = ingress.get("enable_direct_iap") is True
    deny_public = ingress.get("allow_unauthenticated") is False
    want_private = ingress.get("enforce_private_ingress") is True
    if want_iap:
        checks.append("DIRECT_IAP")
    if deny_public:
        checks.append("NO_PUBLIC_INVOKER")
    if want_private:
        checks.append("PRIVATE_INGRESS")
    for res in resources:
        if res.rtype == CLOUD_RUN_V2_SERVICE:
            if want_iap and res.after.get("iap_enabled") is not True:
                violations.append(Violation("IAP_NOT_ENABLED", res.address, "iap_enabled",
                                            "the compliance decision enabled Direct IAP"))
            if deny_public and res.after.get("invoker_iam_disabled") is True:
                violations.append(Violation("PUBLIC_INVOKER", res.address, "invoker_iam_disabled",
                                            "invoker IAM check disabled; unauthenticated access is not allowed"))
            if want_private and res.after.get("ingress") not in PRIVATE_INGRESS_VALUES:
                violations.append(Violation("PRIVATE_INGRESS_NOT_SET", res.address, "ingress",
                                            f"ingress {res.after.get('ingress')!r}; the decision requires internal ingress"))
        if deny_public:
            members, unverifiable = _members_of(res)
            if unverifiable:
                violations.append(Violation("PUBLIC_INVOKER_UNVERIFIABLE", res.address, "member",
                                            "invoker members known only after apply"))
            elif any(m in PUBLIC_MEMBERS for m in members if isinstance(m, str)):
                violations.append(Violation("PUBLIC_INVOKER", res.address, "member",
                                            "allUsers holds roles/run.invoker; unauthenticated access is not allowed"))
    return checks, violations


def _evaluate_resources(
    resources: List[PlannedResource],
    config: ConfigIndex,
    *,
    profile: str,
    requirements: Dict[str, Any],
    ingress: Dict[str, Any],
    org_allowed_locations: Sequence[str],
) -> GateResult:
    result = GateResult(decision=DECISION_PASS, error_class=None, profile=profile, resources_evaluated=len(resources))
    requires_cmek = bool(requirements.get("requires_cmek")) and profile in REGULATED_PROFILES
    requires_audit = bool(requirements.get("requires_audit_logging")) and profile in REGULATED_PROFILES
    allowed: Optional[frozenset] = None
    if profile in REGULATED_PROFILES:
        allowed = frozenset(str(r).lower() for r in (requirements.get("allowed_regions") or []))
        if org_allowed_locations:
            try:
                allowed = allowed & resolve_org_allowed_locations(org_allowed_locations)
            except LocationGroupUnresolved as e:
                result.decision, result.error_class, result.detail = DECISION_REFUSED, ERROR_UNRESOLVED_LOCATION_GROUP, str(e)
                return result
    result.requirements = {
        "requires_cmek": requires_cmek,
        "requires_audit_logging": requires_audit,
        "allowed_regions": sorted(allowed) if allowed is not None else None,
        "enable_direct_iap": ingress.get("enable_direct_iap") is True,
        "allow_unauthenticated": ingress.get("allow_unauthenticated") is not False,
        "enforce_private_ingress": ingress.get("enforce_private_ingress") is True,
    }
    if requires_cmek:
        result.checks_run.append("CMEK")
        for res in resources:
            v = _check_cmek(res, config)
            if v:
                result.violations.append(v)
    if requires_audit:
        result.checks_run.append("AUDIT_LOGGING")
        v = _check_audit_logging(resources)
        if v:
            result.violations.append(v)
    if allowed is not None:
        result.checks_run.append("REGIONS")
        for res in resources:
            result.violations.extend(_check_regions(res, config, allowed))
    checks, ingress_violations = _check_ingress(resources, ingress)
    result.checks_run.extend(checks)
    result.violations.extend(ingress_violations)
    if result.violations:
        result.decision, result.error_class = DECISION_VIOLATION, ERROR_COMPLIANCE_VIOLATION
        result.detail = f"{len(result.violations)} compliance violation(s) for profile {profile}"
    else:
        result.detail = f"plan satisfies profile {profile} ({', '.join(result.checks_run) or 'no checks required'})"
    return result


def _refused(profile: str, error_class: str, detail: str) -> GateResult:
    return GateResult(decision=DECISION_REFUSED, error_class=error_class, profile=profile, detail=detail)


# --------------------------------------------------------------------------------------------------------------
# Plan adapter (enforcing)
# --------------------------------------------------------------------------------------------------------------

def planned_resources(plan: Any) -> List[PlannedResource]:
    if not isinstance(plan, dict) or not isinstance(plan.get("format_version"), str):
        raise PlanInvalid("not a `tofu show -json` plan (format_version missing)")
    changes = plan.get("resource_changes", [])
    if changes is None:
        changes = []
    if not isinstance(changes, list):
        raise PlanInvalid("resource_changes is not a list")
    out: List[PlannedResource] = []
    for rc in changes:
        if not isinstance(rc, dict):
            raise PlanInvalid("resource_changes entry is not an object")
        if rc.get("mode") != "managed":
            continue
        change = rc.get("change")
        if not isinstance(change, dict):
            raise PlanInvalid(f"{rc.get('address')}: change missing")
        actions = change.get("actions")
        if not isinstance(actions, list):
            raise PlanInvalid(f"{rc.get('address')}: actions missing")
        if actions == ["delete"]:
            continue
        after = change.get("after")
        if not isinstance(after, dict):
            raise PlanInvalid(f"{rc.get('address')}: planned values missing")
        rtype, name = rc.get("type"), rc.get("name")
        if not isinstance(rtype, str) or not isinstance(name, str):
            raise PlanInvalid("resource_changes entry without type/name")
        out.append(PlannedResource(
            address=str(rc.get("address") or f"{rtype}.{name}"),
            module_path=parse_module_address(rc.get("module_address") or ""),
            rtype=rtype,
            name=name,
            after=after,
            after_unknown=change.get("after_unknown") or {},
        ))
    return out


def evaluate_plan(
    plan: Any,
    *,
    profile: str,
    requirements: Dict[str, Any],
    ingress: Optional[Dict[str, Any]] = None,
    org_allowed_locations: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    if profile not in KNOWN_PROFILES:
        return _refused(str(profile), ERROR_UNKNOWN_PROFILE, f"profile {profile!r} is not a known compliance profile").as_dict()
    try:
        resources = planned_resources(plan)
    except PlanInvalid as e:
        return _refused(profile, ERROR_PLAN_INVALID, str(e)).as_dict()
    config = ConfigIndex(plan.get("configuration"), plan.get("variables"))
    return _evaluate_resources(
        resources, config, profile=profile, requirements=requirements,
        ingress=dict(ingress or {}), org_allowed_locations=list(org_allowed_locations or []),
    ).as_dict()


# --------------------------------------------------------------------------------------------------------------
# HCL adapter (advisory, pre-commit)
# --------------------------------------------------------------------------------------------------------------

def _hcl_expression_reference(value: Any) -> Optional[str]:
    """`${a.b.c}` holding exactly one traversal -> "a.b.c"; anything else -> None."""
    if not isinstance(value, str) or not (value.startswith("${") and value.endswith("}")):
        return None
    inner = value[2:-1].strip()
    segs = inner.split(".")
    if len(segs) < 2:
        return None
    for seg in segs:
        core = seg.split("[", 1)[0]
        if not core or not all(ch.isalnum() or ch in "_-" for ch in core):
            return None
    return inner


def _hcl_to_after(value: Any) -> Tuple[Any, Any, Any]:
    """(after, after_unknown, expressions) analogues of a parsed HCL value."""
    if isinstance(value, dict):
        after, unk, expr = {}, {}, {}
        for k, v in value.items():
            if not isinstance(k, str) or k.startswith("__"):
                continue
            a, u, e = _hcl_to_after(v)
            after[k], expr[k] = a, e
            if u:
                unk[k] = u
        return after, unk, expr
    if isinstance(value, list) and value and all(isinstance(x, dict) for x in value):
        parts = [_hcl_to_after(x) for x in value]
        return [p[0] for p in parts], [p[1] for p in parts], [p[2] for p in parts]
    if isinstance(value, str) and value.startswith("${"):
        ref = _hcl_expression_reference(value)
        return None, True, {"references": [ref] if ref else []}
    return value, None, {"constant_value": value}


def hcl_planned_resources(hcl_files: Dict[str, str]) -> Tuple[List[PlannedResource], ConfigIndex]:
    """Parses every file with python-hcl2. Raises ImportError (no parser) or ValueError (parse error)."""
    import hcl2  # python-hcl2, pinned in requirements.txt (same pin as the gateway)

    resources: List[PlannedResource] = []
    config_resources: List[Dict[str, Any]] = []
    for fname in sorted(hcl_files):
        try:
            parsed = hcl2.loads(hcl_files[fname] or "")
        except Exception as e:
            raise ValueError(f"{fname}: {type(e).__name__}: {e}") from e
        for block in parsed.get("resource") or []:
            if not isinstance(block, dict):
                continue
            for rtype, named in block.items():
                if not isinstance(named, dict):
                    continue
                for name, body in named.items():
                    after, unk, expr = _hcl_to_after(body if isinstance(body, dict) else {})
                    resources.append(PlannedResource(f"{rtype}.{name}", (), rtype, name, after, unk))
                    config_resources.append({"mode": "managed", "type": rtype, "name": name, "expressions": expr})
    return resources, ConfigIndex({"root_module": {"resources": config_resources}}, {})


def evaluate_hcl(
    hcl_files: Dict[str, str],
    *,
    profile: str,
    requirements: Dict[str, Any],
    ingress: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Advisory pre-commit check. `*_UNVERIFIABLE` findings (values known only at plan time, e.g. `var.region`) are
    reported in `unverified`, not as violations: the plan gate decides them."""
    if profile not in KNOWN_PROFILES:
        return {"compliant": False, "violations": [f"UNKNOWN_PROFILE: {profile!r}"], "unverified": [], "findings": [],
                "error_class": ERROR_UNKNOWN_PROFILE, "summary": f"Unknown compliance profile {profile!r}."}
    try:
        resources, config = hcl_planned_resources(hcl_files or {})
    except ImportError:
        return {"compliant": False, "violations": ["PARSER_UNAVAILABLE: python-hcl2 is not installed"], "unverified": [],
                "findings": [], "error_class": ERROR_PARSER_UNAVAILABLE, "summary": "HCL parser unavailable."}
    except ValueError as e:
        return {"compliant": False, "violations": [f"PARSE_ERROR: {e}"], "unverified": [], "findings": [],
                "error_class": ERROR_PARSE, "summary": "HCL could not be parsed; nothing was evaluated."}
    res = _evaluate_resources(resources, config, profile=profile, requirements=requirements,
                              ingress=dict(ingress or {}), org_allowed_locations=[])
    if res.decision == DECISION_REFUSED:
        return {"compliant": False, "violations": [f"{res.error_class}: {res.detail}"], "unverified": [], "findings": [],
                "error_class": res.error_class, "summary": res.detail}
    definite = [v for v in res.violations if not v.code.endswith("_UNVERIFIABLE")]
    unverified = [v for v in res.violations if v.code.endswith("_UNVERIFIABLE")]
    return {
        "compliant": not definite,
        "violations": [f"{v.code}: {v.address} {v.attribute} - {v.detail}" for v in definite],
        "unverified": [f"{v.code}: {v.address} {v.attribute}" for v in unverified],
        "findings": [v.as_dict() for v in res.violations],
        "error_class": ERROR_COMPLIANCE_VIOLATION if definite else None,
        "summary": ("Compliance validation passed." if not definite
                    else f"Found {len(definite)} compliance violations.")
        + (f" {len(unverified)} value(s) can only be verified by the plan gate." if unverified else ""),
    }
