"""Adopting Google Cloud resources that already exist, from the plan (FD-4CY W7; proposed register row FD55-W7).

A deploy can meet a resource the configuration wants to create although it already exists in the workload project
(a lost state, an interrupted earlier apply, a resource made by hand). Before W7 the deploy guessed which resource that
was: regex scans of the `.tf` text, fixed connector and secret names or the product id filled in
for anything built from a variable, and imports at a root address even when the block lived inside a module.

Here every name and every address comes from OpenTofu's own saved plan (`tofu show -json`, the plan the compliance
gate checked and the apply applied):
  * the address is a `resource_changes[].address` whose `change.actions` is exactly `["create"]`;
  * the import id is built from that change's planned attributes (`change.after`): the resource's own name attributes
    (`name`, `secret_id`, `account_id`, ...), its `project` and its `location` / `region`. An attribute the plan does
    not know yet (`change.after_unknown`) or a planned `project` other than the workload project means the resource is
    not adopted; nothing is guessed in its place.

Two callers:
  * `pre_apply_candidates` (Pass 0, before the apply): the planned creates of the types the old Pass 0 pre-imported
    (Cloud Run services, Secret Manager secrets, service accounts, subnetworks), each with the exact REST URL that tells
    whether the resource already exists. The caller GETs that URL and imports only on HTTP 200.
  * `conflict_addresses` + `resolve_import` (after a failed apply): OpenTofu prints one diagnostic per failed resource
    with its exact address (`with <address>,`). A diagnostic that carries Google's conflict status (HTTP 409 /
    ALREADY_EXISTS) and names a planned create is adopted at that address with the id from the plan. A conflict that
    cannot be adopted that way is returned as unresolved and the deploy fails typed (APPLY_ADOPTION_UNRESOLVED).

Only the conflict STATUS is read from the error text (Google's status code tokens); no name, id, region or address is
taken from it except the diagnostic's address, which must equal a planned address exactly.

RT14-01 (FD-4Q / OQ-9b): `legacy_subnet_purge_trigger` and the subnet CIDR orphan purge (case B) it gated are DELETED.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

ERROR_APPLY_ADOPTION_UNRESOLVED = "APPLY_ADOPTION_UNRESOLVED"
ADOPTION_STAGE = "apply_adoption"

# Google's conflict status as the provider prints it: the REST status (`googleapi: Error 409: ...`), the gRPC / API
# status names, and the provider's "already exists" message. Only the status is read; never a name.
_CONFLICT_STATUS_TOKENS = ("Error 409", "ALREADY_EXISTS", "alreadyExists", "AlreadyExists", "already exists")
_DIAGNOSTIC_BORDER = "╷│╵ "   # OpenTofu's diagnostic frame characters (top, side, bottom) and spaces


@dataclass(frozen=True)
class ImportRule:
    """How one resource type's import id is built from its planned attributes.

    `name_attrs`: planned attributes that must be known, non-empty strings (in template order).
    `location_attr`: the planned `location` / `region` attribute, or None for a global / project-level resource.
    `template`: the provider's documented import id, formatted with `project`, `location` and the name attributes.
    `exists_url`: for Pass 0 types only, the REST URL whose HTTP 200 means the resource exists (same fields)."""
    name_attrs: Tuple[str, ...]
    location_attr: Optional[str]
    template: str
    exists_url: Optional[str] = None


IMPORT_RULES: Dict[str, ImportRule] = {
    "google_cloud_run_v2_service": ImportRule(
        ("name",), "location", "projects/{project}/locations/{location}/services/{name}",
        "https://run.googleapis.com/v2/projects/{project}/locations/{location}/services/{name}"),
    "google_cloud_run_service": ImportRule(
        ("name",), "location", "locations/{location}/namespaces/{project}/services/{name}",
        "https://run.googleapis.com/v2/projects/{project}/locations/{location}/services/{name}"),
    "google_secret_manager_secret": ImportRule(
        ("secret_id",), None, "projects/{project}/secrets/{secret_id}",
        "https://secretmanager.googleapis.com/v1/projects/{project}/secrets/{secret_id}"),
    "google_service_account": ImportRule(
        ("account_id",), None, "projects/{project}/serviceAccounts/{account_id}@{project}.iam.gserviceaccount.com",
        "https://iam.googleapis.com/v1/projects/{project}/serviceAccounts/{account_id}@{project}.iam.gserviceaccount.com"),
    "google_compute_subnetwork": ImportRule(
        ("name",), "region", "projects/{project}/regions/{location}/subnetworks/{name}",
        "https://compute.googleapis.com/compute/v1/projects/{project}/regions/{location}/subnetworks/{name}"),
    "google_artifact_registry_repository": ImportRule(
        ("repository_id",), "location", "projects/{project}/locations/{location}/repositories/{repository_id}"),
    "google_firestore_database": ImportRule(("name",), None, "projects/{project}/databases/{name}"),
    "google_iam_workload_identity_pool": ImportRule(
        ("workload_identity_pool_id",), None,
        "projects/{project}/locations/global/workloadIdentityPools/{workload_identity_pool_id}"),
    "google_iam_workload_identity_pool_provider": ImportRule(
        ("workload_identity_pool_id", "workload_identity_pool_provider_id"), None,
        "projects/{project}/locations/global/workloadIdentityPools/{workload_identity_pool_id}"
        "/providers/{workload_identity_pool_provider_id}"),
    "google_identity_platform_config": ImportRule((), None, "projects/{project}/config"),
    "google_identity_platform_default_supported_idp_config": ImportRule(
        ("idp_id",), None, "projects/{project}/defaultSupportedIdpConfigs/{idp_id}"),
    "google_pubsub_topic": ImportRule(("name",), None, "projects/{project}/topics/{name}"),
    "google_pubsub_subscription": ImportRule(("name",), None, "projects/{project}/subscriptions/{name}"),
    "google_storage_bucket": ImportRule(("name",), None, "{name}"),
    "google_cloud_scheduler_job": ImportRule(
        ("name",), "region", "projects/{project}/locations/{location}/jobs/{name}"),
    "google_compute_region_network_endpoint_group": ImportRule(
        ("name",), "region", "projects/{project}/regions/{location}/networkEndpointGroups/{name}"),
    "google_compute_global_forwarding_rule": ImportRule(
        ("name",), None, "projects/{project}/global/forwardingRules/{name}"),
    "google_vpc_access_connector": ImportRule(
        ("name",), "region", "projects/{project}/locations/{location}/connectors/{name}"),
    "google_compute_network": ImportRule(("name",), None, "projects/{project}/global/networks/{name}"),
    "google_compute_global_address": ImportRule(("name",), None, "projects/{project}/global/addresses/{name}"),
    # CLOUDSQL-CREATE-OWN-OPERATION (register row, awaiting owner): an instance name is project-scoped, so a 409 on
    # the planned create in the workload project names the workload's own instance (e.g. a create the provider stopped
    # waiting for in an earlier run, ex08-g13). Also the import id of cloudsql_create_recovery's adoption.
    "google_sql_database_instance": ImportRule(("name",), None, "projects/{project}/instances/{name}"),
}

# Pass 0 (before the apply): the types the old proactive discovery pre-imported. Every other type is adopted only
# from a typed conflict after the apply.
PRE_APPLY_TYPES = frozenset({
    "google_cloud_run_v2_service", "google_cloud_run_service", "google_secret_manager_secret",
    "google_service_account", "google_compute_subnetwork",
})
# Undelete before import (A52, kept): a soft-deleted pool / provider holds its id for 30 days and answers 409.
WIF_UNDELETE_TYPES = frozenset({"google_iam_workload_identity_pool", "google_iam_workload_identity_pool_provider"})
# A bucket name is global: a 409 can name another project's bucket. Adopt only a bucket of the workload project.
OWNER_CHECK_TYPES = frozenset({"google_storage_bucket"})


@dataclass(frozen=True)
class Resolved:
    address: str
    type: str
    import_id: str
    exists_url: Optional[str]


def _resource_changes(plan_json: Optional[Mapping[str, Any]]) -> List[Mapping[str, Any]]:
    if not isinstance(plan_json, Mapping):
        return []
    changes = plan_json.get("resource_changes")
    return [rc for rc in changes if isinstance(rc, Mapping)] if isinstance(changes, list) else []


def planned_creates(plan_json: Optional[Mapping[str, Any]]) -> Dict[str, Mapping[str, Any]]:
    """{address: resource_change} for every managed resource the plan creates (actions exactly ["create"])."""
    out: Dict[str, Mapping[str, Any]] = {}
    for rc in _resource_changes(plan_json):
        change = rc.get("change") if isinstance(rc.get("change"), Mapping) else {}
        address = rc.get("address")
        if rc.get("mode", "managed") == "managed" and change.get("actions") == ["create"] and isinstance(address, str):
            out[address] = rc
    return out


def planned_addresses(plan_json: Optional[Mapping[str, Any]]) -> Dict[str, List[str]]:
    """{address: actions} for every resource change of the plan."""
    out: Dict[str, List[str]] = {}
    for rc in _resource_changes(plan_json):
        change = rc.get("change") if isinstance(rc.get("change"), Mapping) else {}
        if isinstance(rc.get("address"), str):
            out[rc["address"]] = list(change.get("actions") or [])
    return out


def _known_str(after: Mapping[str, Any], unknown: Mapping[str, Any], attr: str) -> Tuple[Optional[str], str]:
    """(value, "") for a known non-empty string attribute, else (None, why)."""
    if unknown.get(attr) is True:
        return None, f"planned `{attr}` is not known until apply"
    value = after.get(attr)
    if isinstance(value, str) and value:
        return value, ""
    return None, f"planned `{attr}` is not a known string"


_GOOGLE_PROVIDERS = ("google", "google-beta")


def _provider_default_pins(plan_json: Optional[Mapping[str, Any]], expr_key: str, var_name: str, value: str) -> bool:
    """True when the plan's own provider configuration makes `value` the default of `expr_key` for every google /
    google-beta provider configuration (root, aliases and module-level blocks): each sets `expr_key` to exactly
    `var.<var_name>` or to the constant `value`, at least one root block exists, and the plan's input variable
    `<var_name>` is `value`. Read from `configuration.provider_config` and `variables` of `tofu show -json` (typed fields); anything
    missing or different is False (fail closed)."""
    if not isinstance(plan_json, Mapping) or not value:
        return False
    config = plan_json.get("configuration")
    providers = config.get("provider_config") if isinstance(config, Mapping) else None
    variables = plan_json.get("variables")
    var = variables.get(var_name) if isinstance(variables, Mapping) else None
    if not isinstance(providers, Mapping) or not isinstance(var, Mapping) or var.get("value") != value:
        return False
    google = [pc for pc in providers.values() if isinstance(pc, Mapping) and pc.get("name") in _GOOGLE_PROVIDERS]
    # A module's `required_providers` entry without a provider block of its own (no `expressions`, has
    # `module_address`) carries no configuration: the module inherits its parent's, which is checked here too.
    google = [pc for pc in google if not (pc.get("module_address") and "expressions" not in pc)]
    if not [pc for pc in google if not pc.get("module_address")]:
        return False   # no root google provider block: the default would come from the environment
    for pc in google:
        exprs = pc.get("expressions") if isinstance(pc.get("expressions"), Mapping) else {}
        expr = exprs.get(expr_key)
        if not isinstance(expr, Mapping):
            return False
        if not (expr.get("references") == [f"var.{var_name}"] and "constant_value" not in expr) and not (
                set(expr) == {"constant_value"} and expr.get("constant_value") == value):
            return False
    return True


def provider_default_project(plan_json: Optional[Mapping[str, Any]], project_id: str) -> bool:
    return _provider_default_pins(plan_json, "project", "project_id", project_id)


def provider_default_region(plan_json: Optional[Mapping[str, Any]], region: str) -> bool:
    return _provider_default_pins(plan_json, "region", "region", region)


def resolve_import(rc: Mapping[str, Any], project_id: str, region: str,
                   plan_json: Optional[Mapping[str, Any]] = None) -> Tuple[Optional[Resolved], str]:
    """(Resolved, "") with the exact import id for a planned create, or (None, reason). Never guesses: the name
    attributes must be known strings in the plan; a known planned project must be the workload project. A `project`
    the plan does not know (the block does not set it: the provider's Optional + Computed default) is the workload
    project only when the plan's provider configuration pins it there (`provider_default_project`). The same holds
    for a `region` attribute (`provider_default_region`). A required `location` that is not known is a refusal."""
    rtype = rc.get("type")
    address = rc.get("address")
    rule = IMPORT_RULES.get(rtype) if isinstance(rtype, str) else None
    if rule is None:
        return None, f"no import rule for resource type `{rtype}`"
    if not project_id:
        return None, "no workload project"
    change = rc.get("change") if isinstance(rc.get("change"), Mapping) else {}
    after = change.get("after") if isinstance(change.get("after"), Mapping) else {}
    unknown = change.get("after_unknown") if isinstance(change.get("after_unknown"), Mapping) else {}
    fields: Dict[str, str] = {}
    planned_project = after.get("project")
    if unknown.get("project") is True or planned_project in (None, ""):
        if not provider_default_project(plan_json, project_id):
            return None, ("planned `project` is not known and the provider configuration does not pin it to the "
                          "workload project")
    elif planned_project != project_id:
        return None, f"planned `project` is `{planned_project}`, not the workload project"
    fields["project"] = project_id
    if rule.location_attr:
        attr = rule.location_attr
        loc = after.get(attr)
        if unknown.get(attr) is True or loc in (None, ""):
            if attr != "region":
                return None, f"planned `{attr}` is not known until apply"
            if not provider_default_region(plan_json, region):
                return None, ("planned `region` is not known and the provider configuration does not pin it to the "
                              "workload region")
            loc = region
        elif not isinstance(loc, str):
            return None, f"planned `{attr}` is not a string"
        fields["location"] = loc
    for attr in rule.name_attrs:
        value, why = _known_str(after, unknown, attr)
        if value is None:
            return None, why
        fields[attr] = value
    import_id = rule.template.format(**fields)
    exists_url = rule.exists_url.format(**fields) if rule.exists_url else None
    return Resolved(str(address), str(rtype), import_id, exists_url), ""


def pre_apply_candidates(plan_json: Optional[Mapping[str, Any]], project_id: str,
                         region: str) -> List[Resolved]:
    """Pass 0: the planned creates of PRE_APPLY_TYPES with an exact import id and existence URL. A create whose id
    cannot be built from the plan is left to the apply (and to the typed conflict adoption if it then conflicts)."""
    out: List[Resolved] = []
    for address, rc in planned_creates(plan_json).items():
        if rc.get("type") not in PRE_APPLY_TYPES:
            continue
        resolved, _ = resolve_import(rc, project_id, region, plan_json)
        if resolved is not None and resolved.exists_url:
            out.append(resolved)
    return out


def _diagnostic_blocks(text: str) -> List[List[str]]:
    """OpenTofu's ERROR diagnostics, one list of frame-stripped lines per `Error:` header. A `Warning:` header also
    ends the current block (RT F5-2: a warning's text is never read as part of the error before it); warning blocks
    are dropped."""
    blocks: List[Tuple[str, List[str]]] = []
    for raw in (text or "").splitlines():
        line = raw.strip(_DIAGNOSTIC_BORDER)
        if line.startswith(("Error: ", "Warning: ")):
            blocks.append((line.split(":", 1)[0], [line]))
        elif blocks:
            blocks[-1][1].append(line)
    return [lines for kind, lines in blocks if kind == "Error"]


def conflict_addresses(apply_output: str) -> Tuple[List[str], int]:
    """(addresses, conflicts_without_address) of the diagnostics that report Google's conflict status. The address is
    the diagnostic's own `with <address>,` line, verbatim; the caller matches it exactly against the plan."""
    addresses: List[str] = []
    no_address = 0
    for block in _diagnostic_blocks(apply_output):
        if not any(tok in line for line in block for tok in _CONFLICT_STATUS_TOKENS):
            continue
        found = [ln[len("with "):-1] for ln in block if ln.startswith("with ") and ln.endswith(",")]
        if not found:
            no_address += 1
        for addr in found:
            if addr not in addresses:
                addresses.append(addr)
    return addresses, no_address


def plan_conflicts(apply_output: str, plan_json: Optional[Mapping[str, Any]], project_id: str,
                   region: str) -> Tuple[List[Resolved], List[Dict[str, str]]]:
    """(adoptable, unresolved) for the conflicts of a failed apply against the plan that apply applied."""
    addresses, no_address = conflict_addresses(apply_output)
    creates = planned_creates(plan_json)
    all_planned = planned_addresses(plan_json)
    adoptable: List[Resolved] = []
    unresolved: List[Dict[str, str]] = []
    if no_address:
        unresolved.append({"address": "", "reason": f"{no_address} conflict diagnostic(s) name no resource address"})
    for addr in addresses:
        if addr in creates:
            resolved, why = resolve_import(creates[addr], project_id, region, plan_json)
            if resolved is None:
                unresolved.append({"address": addr, "reason": why})
            else:
                adoptable.append(resolved)
        elif addr in all_planned:
            unresolved.append({"address": addr,
                               "reason": f"the plan does not create it (actions {all_planned[addr]})"})
        elif plan_json is None:
            unresolved.append({"address": addr, "reason": "no readable plan for the failed apply"})
        else:
            unresolved.append({"address": addr, "reason": "address is not in the applied plan"})
    return adoptable, unresolved


def bucket_owner_matches(bucket_json: Mapping[str, Any], project_json: Mapping[str, Any]) -> bool:
    """A bucket belongs to the workload project: its `projectNumber` equals the project's `projectNumber` (both typed
    REST fields; storage v1 bucket and Resource Manager v1 project)."""
    b = str(bucket_json.get("projectNumber") or "")
    p = str(project_json.get("projectNumber") or "")
    return bool(b) and b == p


# RT14-01: `legacy_subnet_purge_trigger` is DELETED with the subnet orphan purge (case B) it gated (FD-4Q / OQ-9b).


def unresolved_summary(unresolved: Iterable[Mapping[str, str]]) -> str:
    return "; ".join(f"{u.get('address') or '(no address)'}: {u.get('reason')}" for u in unresolved)
