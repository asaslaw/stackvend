"""
Project Castor: Express Golden & Registered Module Synthesizer
==============================================================
Deterministic Infrastructure-as-Code synthesizer that produces clean,
multi-instance OpenTofu/Terraform configurations without executing LLM agents.

Key Architectural Guarantees:
1. Clean IaC-First Layout: Zero dummy apps/ scaffolding.
2. Multi-Instance: Allows declaring multiple Cloud Run services, databases,
   topics, and custom enterprise modules.
3. Modular Vendoring: Copies only the required module definitions into
   infra/modules/<module_id>/ for complete hermetic reproducibility.
4. Production-Ready Defaults: Cloud Run defaults to public starter image
   (us-docker.pkg.dev/cloudrun/container/hello) ensuring immediate 200 OK applies.
"""

import ipaddress
import os
import re
import json
import logging
from typing import Dict, List, Any, Optional

try:
    from shared.builtin_modules_provider import get_platform_modules_path, get_builtin_modules
    from shared.builtin_modules_payload import BUILTIN_MODULE_FILES
except ImportError:
    try:
        from builtin_modules_provider import get_platform_modules_path, get_builtin_modules
        from builtin_modules_payload import BUILTIN_MODULE_FILES
    except ImportError:
        def get_platform_modules_path():
            candidates = [
                os.path.abspath(os.path.join(os.path.dirname(__file__), "../infra/modules")),
                os.path.abspath(os.path.join(os.path.dirname(__file__), "../../infra/modules")),
                os.path.abspath("infra/modules"),
            ]
            for c in candidates:
                if os.path.isdir(c):
                    return c
            return None

        def get_builtin_modules(force_refresh=False):
            return []

        BUILTIN_MODULE_FILES = {}

try:   # FD-4CX: no stub fallback (a missing checker fails the synthesis loudly)
    from shared.module_exposure import (RegisteredModulePublicExposureError, check_registered_module,
                                        modules_under, PUBLIC_MEMBERS, REGISTERED_MODULE_PUBLIC_EXPOSURE)
except ImportError:
    from module_exposure import (RegisteredModulePublicExposureError, check_registered_module,  # type: ignore
                                 modules_under, PUBLIC_MEMBERS, REGISTERED_MODULE_PUBLIC_EXPOSURE)

logger = logging.getLogger("castor-express-synthesizer")

# FD-7L install mode (shared/runner_identity.py MODE_ENV / MODES). FD-7L-F4: the Control Center passes the OPERATIVE
# mode (shared.runner_identity.runner_identity_mode(), which also reads the signed Settings record) as
# synthesize_workload(runner_identity_mode=...); without it (this module's gateway copy has no runner_identity replica)
# only the install declaration is read here. Exact tokens only; unset or blank = PLATFORM ("Shared").
RUNNER_IDENTITY_MODE_ENV = "STACKVEND_TF_RUNNER_IDENTITY"
RUNNER_IDENTITY_MODES = ("PLATFORM", "PER_WORKLOAD")


class ExpressRunnerIdentityModeInvalid(ValueError):
    """STACKVEND_TF_RUNNER_IDENTITY holds an unknown value (typed: RUNNER_IDENTITY_MODE_INVALID)."""
    reason = "RUNNER_IDENTITY_MODE_INVALID"


def _platform_owns_backend(operative_mode: Optional[str] = None) -> bool:
    """True on a Per-workload install: the runner writes backend.tf from vending's provenance record (plan 2.6), so
    Express commits none. False on a Shared install (backend.tf committed exactly as before). `operative_mode`: the
    caller's runner_identity_mode() result (FD-7L-F4); None = the install declaration (env)."""
    if operative_mode is not None:
        if operative_mode not in RUNNER_IDENTITY_MODES:
            raise ExpressRunnerIdentityModeInvalid(f"runner identity mode {operative_mode!r}; expected one of "
                                                   f"{', '.join(RUNNER_IDENTITY_MODES)}")
        return operative_mode == "PER_WORKLOAD"
    value = (os.environ.get(RUNNER_IDENTITY_MODE_ENV) or "").strip()
    if not value:
        return False
    if value not in RUNNER_IDENTITY_MODES:
        raise ExpressRunnerIdentityModeInvalid(f"{RUNNER_IDENTITY_MODE_ENV}={value!r}; expected one of "
                                               f"{', '.join(RUNNER_IDENTITY_MODES)}")
    return value == "PER_WORKLOAD"

# FD-CSQL: golden database modules that live on a private IP. Each needs a VPC with Private Services Access, so
# Express vendors networking-vpc (PSA on by default) and wires its network_id into the database. The VPC's subnet
# range is the platform IPAM fact var.subnet_cidr (AGENTS.md invariant 3), never the module's default literal.
PRIVATE_NETWORK_DB_MODULES = ("database-cloudsql", "database-alloydb")

# EXP-2: every module block emits its source as the canonical line `  source = "../modules/<name>"` followed by a
# blank line. The deploy path (terraform MCP deploy_workload) rewrites exactly that text to `./infra/modules/` when it
# flattens infra/workload/ into the workspace root; an aligned `source      = ...` is not rewritten. The blank line
# keeps the file `tofu fmt`-clean (fmt aligns only contiguous arguments).
# EXP-1: every module output the root reads is an output the vendored module declares (tests/
# test_express_validate_end_to_end.py audits this and runs `tofu validate` on each configuration).

# EXP-4: modules whose resource names derive from product_id plus an optional name-suffix input (module_id -> input
# name). With one instance Express passes no suffix, so the names are those the module has always produced. With
# several, every instance passes its own instance name (lowercase, `_` -> `-`) as the suffix, which keeps the Cloud
# Run job, Pub/Sub topic and subscription names apart. Two instances whose suffixes are equal would still collide at
# apply (`validate` cannot see it): Express refuses them with ExpressModuleNameCollisionError.
NAME_SUFFIX_MODULES = {"compute-event-worker": "name_suffix"}
RFC1123_LABEL_MAX = 63
# EXP-4 (RT F1): the resource names a suffixed NAME_SUFFIX_MODULES instance gets, as the module builds them
# (`<prefix><product_id, _ -> ->-<suffix>`; prefixes pinned against the module text in
# tests/test_exp4_event_worker_suffix.py), with each name's maximum length. Cloud Run job ID: 63, the RFC 1123 label
# maximum (neither the provider schema nor the repo states the API limit, so the label maximum is used). Pub/Sub topic
# and subscription IDs: 255 (Google's documented limit; also not stated in the provider schema). With the job name at
# most 63, the Pub/Sub names stay far below 255, so the job name is the binding limit.
NAME_SUFFIX_RESOURCE_NAMES = {
    "compute-event-worker": (
        ("Cloud Run job", "worker-", 63),
        ("Pub/Sub topic", "events-", 255),
        ("Pub/Sub subscription", "worker-sub-", 255),
    ),
}
_RFC1123_LABEL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")


class ExpressSynthesisRefused(ValueError):
    """Express refuses to synthesize the requested workload. `reason` is a stable code (the CC route records it on
    the failed hcl_synthesis stage; never parsed from the message)."""

    reason = "EXPRESS_SYNTHESIS_REFUSED"


class ExpressModuleNameCollisionError(ExpressSynthesisRefused):
    """Two instances of a NAME_SUFFIX_MODULES module would get the same name suffix, so their resources collide."""

    reason = "EXPRESS_MODULE_NAME_COLLISION"

    def __init__(self, module_id: str, name_suffix: str, instance_names: List[str]):
        self.module_id = module_id
        self.name_suffix = name_suffix
        self.instance_names = list(instance_names)
        super().__init__(
            f"Express '{module_id}' instances {', '.join(repr(n) for n in self.instance_names)} would all use the "
            f"name suffix '{name_suffix}', so their resource names collide. Give each instance a distinct name."
        )


class ExpressInvalidNameSuffixError(ExpressSynthesisRefused):
    """An instance name of a NAME_SUFFIX_MODULES module does not give an RFC 1123 label to use as its name suffix."""

    reason = "EXPRESS_INVALID_NAME_SUFFIX"

    def __init__(self, module_id: str, instance_name: str, name_suffix: str):
        self.module_id = module_id
        self.instance_name = instance_name
        self.name_suffix = name_suffix
        super().__init__(
            f"Express '{module_id}' instance {instance_name!r} gives the name suffix {name_suffix!r}, which is not an "
            f"RFC 1123 label (1-{RFC1123_LABEL_MAX} lowercase letters, digits or hyphens, starting and ending with a "
            f"letter or digit). Rename the instance."
        )


class ExpressResourceNameTooLongError(ExpressSynthesisRefused):
    """A suffixed NAME_SUFFIX_MODULES instance would get a resource name longer than that resource's limit."""

    reason = "EXPRESS_RESOURCE_NAME_TOO_LONG"

    def __init__(self, module_id: str, instance_name: str, resource: str, resource_name: str, limit: int):
        self.module_id = module_id
        self.instance_name = instance_name
        self.resource = resource
        self.resource_name = resource_name
        self.limit = limit
        super().__init__(
            f"Express '{module_id}' instance {instance_name!r} would get the {resource} name {resource_name!r} "
            f"({len(resource_name)} characters; the limit is {limit}). Use a shorter instance name or product ID."
        )


class ExpressAccessPolicyIncompleteError(ExpressSynthesisRefused):
    """FD-4CS: the workload's access record is private but lists nobody (for example the platform default with no
    verified submitter). Nothing is rendered until an administrator lists who may use it (never guessed, never public)."""

    reason = "ACCESS_POLICY_INCOMPLETE"

    def __init__(self, mode: str):
        self.mode = mode
        super().__init__(
            f"The workload's access record ({mode}) lists nobody who may use it. An administrator lists the members "
            f"(PATCH /api/workloads/<product_id>/access); then submit the Express workload again."
        )


class ExpressAccessConflictError(ExpressSynthesisRefused):
    """FD-4CS: a compute-cloudrun instance parameter that the workload access record owns says something else."""

    reason = "EXPRESS_ACCESS_CONFLICT"

    def __init__(self, instance_name: str, parameter: str):
        self.instance_name = instance_name
        self.parameter = parameter
        super().__init__(
            f"Express compute-cloudrun instance {instance_name!r} sets {parameter!r}, which differs from the "
            f"workload's access record. Who may use the services is set by the workload's `access` (for a public "
            f"service, `access.mode` = PUBLIC_APP); remove {parameter!r} from the instance parameters."
        )


class ExpressRegisteredModuleExposureError(ExpressSynthesisRefused):
    """FD-4CX: a private workload (access record PRIVATE_IAP / PRIVATE_IAM) uses a registered module whose own files
    grant public access (shared/module_exposure.py), so the record could not keep the workload private."""

    reason = REGISTERED_MODULE_PUBLIC_EXPOSURE

    def __init__(self, cause: RegisteredModulePublicExposureError):
        self.module_id = cause.module_id
        self.findings = list(cause.findings)
        super().__init__(
            f"{cause} This workload's access record is private, so it cannot use '{cause.module_id}' until the "
            f"module is fixed (Settings > Modules)."
        )


class ExpressRegisteredModuleParameterError(ExpressSynthesisRefused):
    """FD-4CX (RT F3i): on a private access record, an instance parameter of a registered module is a public principal
    (exactly `allUsers` / `allAuthenticatedUsers`, or a list containing one)."""

    reason = REGISTERED_MODULE_PUBLIC_EXPOSURE

    def __init__(self, module_id: str, instance_name: str, parameter: str, members: List[str]):
        self.module_id = module_id
        self.instance_name = instance_name
        self.parameter = parameter
        self.members = list(members)
        super().__init__(
            f"{REGISTERED_MODULE_PUBLIC_EXPOSURE}: Express '{module_id}' instance {instance_name!r} sets {parameter!r} "
            f"to {', '.join(self.members)}, but this workload's access record is private. Who may use the workload is "
            f"set by its access record; remove {parameter!r} from the instance parameters (or choose Public)."
        )


# FD-4CS: the compute-cloudrun arguments the workload access record decides (the same keys the Agent path writes as
# platform-owned tfvars). An instance parameter may repeat the record's value; any other value is refused.
ACCESS_OWNED_PARAMETERS = ("allow_unauthenticated", "enable_direct_iap", "authorized_invoker_members")


# GHA-DEPLOY-SWITCH (register row GHA-DEPLOY-SWITCH): the foundation argument and root variable of a GitHub workload
# whose GitHub Actions deploy switch is off; the same text as developer_agent.terraform_engine's
# GHA_DEPLOY_SWITCH_LINE / GHA_DEPLOY_SWITCH_VARIABLE_BLOCK (tests/test_gha_deploy_switch.py pins the parity).
GHA_DEPLOY_SWITCH_LINE = "  enable_github_actions_deploy = var.enable_github_actions_deploy\n"
GHA_DEPLOY_SWITCH_VARIABLE_BLOCK = """
variable "enable_github_actions_deploy" {
  description = "The workload's GitHub Actions deploy switch (GHA-DEPLOY-SWITCH): false = no WIF pool, provider or deployer service account. Supplied by the platform at apply time."
  type        = bool
  default     = false
}
"""


def _hcl_string(value: str) -> str:
    """A quoted HCL string literal for `value`: JSON escaping plus HCL's template escapes (`$${`, `%%{`), so a member
    is always a literal and never a template."""
    return json.dumps(value).replace("${", "$${").replace("%{", "%%{")


def express_access_arguments(module_instances: Optional[List[Any]], access: Optional[Any]) -> Optional[List[tuple]]:
    """FD-4CS: the (argument, HCL value) pairs every compute-cloudrun instance gets from the workload access record.

    `access` is the workload's ``shared.access_policy.AccessPolicy`` (read through its public attributes only:
    ``mode``, ``is_complete``, ``allow_unauthenticated``, ``enable_direct_iap``, ``invoker_members()``), or None when
    the workload has no record (an Express workload created before FD-4CS): None is returned and the services keep
    their previous rendering. PUBLIC_APP -> ``allow_unauthenticated = true``; PRIVATE_IAP -> private, Direct IAP, the
    listed members; PRIVATE_IAM -> private, the listed members, no IAP. Raises ``ExpressAccessPolicyIncompleteError``
    for a private record with no members and ``ExpressAccessConflictError`` when an instance parameter in
    ``ACCESS_OWNED_PARAMETERS`` differs from the record (exact value comparison)."""
    if access is None:
        return None
    mode = getattr(getattr(access, "mode", None), "value", None) or str(getattr(access, "mode", ""))
    public = access.allow_unauthenticated is True
    expected = {
        "allow_unauthenticated": public,
        "enable_direct_iap": (not public) and access.enable_direct_iap is True,
        "authorized_invoker_members": [] if public else sorted(access.invoker_members()),
    }
    for mod_id, _key, inst_name, params in _plan_instances(list(module_instances or [])):
        if mod_id != "compute-cloudrun":
            continue
        for name in ACCESS_OWNED_PARAMETERS:
            if name not in params:
                continue
            value = params[name]
            if name == "authorized_invoker_members":
                same = (isinstance(value, list) and all(isinstance(m, str) for m in value)
                        and sorted(value) == expected[name])
            else:
                same = value is expected[name]
            if not same:
                raise ExpressAccessConflictError(inst_name, name)
    if not access.is_complete:   # after the conflict check, so a create can refuse a conflict before it waits
        raise ExpressAccessPolicyIncompleteError(mode)
    if public:
        return [("allow_unauthenticated", "true")]
    members = "[" + ", ".join(_hcl_string(m) for m in expected["authorized_invoker_members"]) + "]"
    return [
        ("allow_unauthenticated", "false"),
        ("enable_direct_iap", "true" if expected["enable_direct_iap"] else "false"),
        ("authorized_invoker_members", members),
    ]


def _is_rfc1123_label(text: str) -> bool:
    return (0 < len(text) <= RFC1123_LABEL_MAX and set(text) <= _RFC1123_LABEL_CHARS
            and text[0] != "-" and text[-1] != "-")


def _instance_module_id(inst: Any) -> str:
    return ((inst.get("module_id") if isinstance(inst, dict) else getattr(inst, "module_id", "")) or "").strip()


def _sanitize_ident(name: str) -> str:
    """Sanitizes an instance name into a safe Terraform identifier."""
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", name.strip())
    if not cleaned or not cleaned[0].isalpha():
        cleaned = f"res_{cleaned}"
    return cleaned.strip("_")


def _plan_instances(instances: List[Any]) -> List[tuple]:
    """(module_id, unique HCL key, instance name, parameters) for every instance Express renders as a module block,
    in request order. Instances without a module_id and networking-vpc (rendered as the top-level network) are
    skipped. The instance name falls back to the key."""
    planned: List[tuple] = []
    seen_keys = set()
    for idx, inst in enumerate(instances):
        if isinstance(inst, dict):
            mod_id = inst.get("module_id", "").strip()
            inst_name = inst.get("instance_name", "").strip()
            params = inst.get("parameters") or {}
        else:
            mod_id = getattr(inst, "module_id", "").strip()
            inst_name = getattr(inst, "instance_name", "").strip()
            params = getattr(inst, "parameters", None) or {}

        if not mod_id:
            continue

        # Skip networking-vpc if already generated as top-level network
        if mod_id == "networking-vpc":
            continue

        # Ensure unique module key in HCL
        raw_key = _sanitize_ident(inst_name or f"{mod_id}_{idx+1}")
        key = raw_key
        suffix = 2
        while key in seen_keys:
            key = f"{raw_key}_{suffix}"
            suffix += 1
        seen_keys.add(key)
        planned.append((mod_id, key, inst_name or key, params))
    return planned


def _name_suffixes(planned: List[tuple], product_id: str) -> Dict[str, str]:
    """EXP-4: {HCL key: name suffix} for NAME_SUFFIX_MODULES modules requested more than once. A module requested
    once gets no entry (no suffix; its names are unchanged). The suffix is the instance name as Express already
    writes it in comments and descriptions (lowercase, `_` -> `-`). Raises ExpressInvalidNameSuffixError when that
    is not an RFC 1123 label, ExpressResourceNameTooLongError when a resulting resource name
    (NAME_SUFFIX_RESOURCE_NAMES) exceeds its limit, and ExpressModuleNameCollisionError when two instances share a
    suffix."""
    base = product_id.replace("_", "-")
    out: Dict[str, str] = {}
    for module_id in NAME_SUFFIX_MODULES:
        group = [(key, name) for mid, key, name, _ in planned if mid == module_id]
        if len(group) < 2:
            continue
        by_suffix: Dict[str, List[str]] = {}
        for key, name in group:
            suffix = name.replace("_", "-").lower()
            if not _is_rfc1123_label(suffix):
                raise ExpressInvalidNameSuffixError(module_id, name, suffix)
            for resource, prefix, limit in NAME_SUFFIX_RESOURCE_NAMES.get(module_id, ()):
                resource_name = f"{prefix}{base}-{suffix}"
                if len(resource_name) > limit:
                    raise ExpressResourceNameTooLongError(module_id, name, resource, resource_name, limit)
            by_suffix.setdefault(suffix, []).append(name)
            out[key] = suffix
        for suffix, names in by_suffix.items():
            if len(names) > 1:
                raise ExpressModuleNameCollisionError(module_id, suffix, names)
    return out


# EXP-6: a re-submit of an existing Express workload must not rename a NAME_SUFFIX_MODULES instance that OpenTofu
# may already manage. The rename changes the resource names at the same module address, so OpenTofu replaces the
# Cloud Run job, Pub/Sub topic and subscription, and the topic's undelivered messages are lost. The workload record
# keeps, as typed data, the names OpenTofu may manage for the workload (EXPRESS_DEPLOYED_NAME_PLAN_FIELD: a list of
# {module_id, module_key, name_suffix}; a list, so a Firestore merge replaces it whole). An accepted request ADDS its
# names (merge_name_plans, in the create write, so a request still provisioning or a failed /deploy is covered); a
# successful /deploy narrows the field to exactly the deployed names. A record created by this code carries
# EXPRESS_NAME_PLAN_TRACKED_FIELD = True from its first create, so "no stored names" then means "no event worker was
# ever accepted". A record without either field predates EXP-6 (or is not an Express record).
EXPRESS_DEPLOYED_NAME_PLAN_FIELD = "express_deployed_name_plan"
EXPRESS_NAME_PLAN_TRACKED_FIELD = "express_name_plan_tracked"


class ExpressWorkerRenameRefusedError(ExpressSynthesisRefused):
    """A re-submit would change the name suffix of an instance OpenTofu may manage at the same module address."""

    reason = "EXPRESS_WORKER_RENAME_REFUSED"

    def __init__(self, module_id: str, module_key: str, old_suffix: Optional[str], new_suffix: Optional[str]):
        self.module_id = module_id
        self.module_key = module_key
        self.old_suffix = old_suffix
        self.new_suffix = new_suffix
        super().__init__(
            f"Express '{module_id}' instance '{module_key}' may already be deployed with "
            f"{_describe_suffix(old_suffix)}; this request gives it {_describe_suffix(new_suffix)}. That renames its "
            "Cloud Run job, Pub/Sub topic and subscription, so OpenTofu would replace them and the topic's "
            "undelivered messages would be lost. Keep the existing workers as they are, or use a new product ID."
        )


class ExpressWorkerRenameUnverifiableError(ExpressWorkerRenameRefusedError):
    """The existing workload record has no readable deployed name plan, and the request could rename a worker."""

    reason = "EXPRESS_WORKER_RENAME_UNVERIFIABLE"

    def __init__(self, why: str):
        self.why = why
        self.module_id = self.module_key = self.old_suffix = self.new_suffix = None
        ValueError.__init__(
            self,
            f"This workload already exists and {why}, so StackVend cannot check that the request keeps its existing "
            "event worker names. A worker rename would replace its Cloud Run job, Pub/Sub topic and subscription "
            "(undelivered messages lost). Re-submit the current configuration unchanged once (this records its "
            "names), then add workers; or use a new product ID."
        )


def _describe_suffix(suffix: Optional[str]) -> str:
    return "no name suffix" if suffix is None else f"the name suffix '{suffix}'"


def express_name_suffix_plan(module_instances: Optional[List[Any]], product_id: str) -> List[Dict[str, Any]]:
    """EXP-6: the name plan synthesize_workload renders for these instances, as typed data:
    [{module_id, module_key, name_suffix (None = no suffix)}] for every NAME_SUFFIX_MODULES instance, in request
    order. Same planning functions as synthesize_workload, so it raises the same ExpressSynthesisRefused errors
    (collision, invalid suffix, name too long)."""
    clean_pid = product_id.strip().lower().replace("_", "-")
    planned = _plan_instances(module_instances or [])
    suffixes = _name_suffixes(planned, clean_pid)
    return [{"module_id": mid, "module_key": key, "name_suffix": suffixes.get(key)}
            for mid, key, _, _ in planned if mid in NAME_SUFFIX_MODULES]


def express_primary_service_output(module_instances: Optional[List[Any]]) -> Optional[str]:
    """EXPRESS-SERVICE-URL (10-27): the root output name that holds the workload's primary Cloud Run URL, as typed
    data: the `compute_<key>_uri` output `_generate_module_instance` renders for the FIRST compute-cloudrun instance
    in request order (same `_plan_instances` keys synthesize_workload uses). None when no instance is a Cloud Run
    service. Express never renders a `service_url` / `service_uri` root output, so the deploy result's generic
    service_url is empty for Express; the caller reads this exact output instead."""
    for mod_id, key, _, _ in _plan_instances(module_instances or []):
        if mod_id == "compute-cloudrun":
            return f"compute_{key}_uri"
    return None


def _parse_name_plan(stored: Any) -> Optional[Dict[tuple, Optional[str]]]:
    """{(module_id, module_key): name_suffix} for a well-formed stored plan; None for anything else."""
    if not isinstance(stored, list):
        return None
    out: Dict[tuple, Optional[str]] = {}
    for entry in stored:
        if not isinstance(entry, dict):
            return None
        mid, key, suffix = entry.get("module_id"), entry.get("module_key"), entry.get("name_suffix")
        if type(mid) is not str or type(key) is not str or not (suffix is None or type(suffix) is str):
            return None
        if (mid, key) in out:
            return None
        out[(mid, key)] = suffix
    return out


def merge_name_plans(existing_record: Optional[Dict[str, Any]], new_plan: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """EXP-6 (RT F1/F2): the stored names to keep once `new_plan` is accepted: the existing record's well-formed
    stored plan followed by the `new_plan` entries it does not have. Call only after refuse_worker_renames accepted
    `new_plan` (shared entries are then equal). A missing or malformed stored plan contributes nothing."""
    stored = (existing_record or {}).get(EXPRESS_DEPLOYED_NAME_PLAN_FIELD)
    parsed = _parse_name_plan(stored) if stored is not None else None
    merged = [dict(e) for e in stored] if parsed is not None else []
    known = set(parsed or {})
    for entry in new_plan:
        ident = (entry["module_id"], entry["module_key"])
        if ident not in known:
            known.add(ident)
            merged.append(dict(entry))
    return merged


def refuse_worker_renames(existing_record: Optional[Dict[str, Any]], new_plan: List[Dict[str, Any]]) -> None:
    """EXP-6: raises ExpressWorkerRenameRefusedError when `new_plan` (express_name_suffix_plan) gives an instance
    that the existing workload record's deployed plan has at the same (module_id, module_key) a different name
    suffix. `existing_record` None = first create (never refused). Without stored names: a tracked record never had
    an event worker accepted (never refused); an untracked one (pre-EXP-6) can only hold unsuffixed workers, so a
    request that gives any instance a suffix is refused (ExpressWorkerRenameUnverifiableError). A malformed stored
    plan refuses any request with a NAME_SUFFIX_MODULES instance. Instances added or removed are not renames."""
    if existing_record is None or not new_plan:
        return
    if EXPRESS_DEPLOYED_NAME_PLAN_FIELD in existing_record:
        deployed = _parse_name_plan(existing_record.get(EXPRESS_DEPLOYED_NAME_PLAN_FIELD))
        if deployed is None:
            raise ExpressWorkerRenameUnverifiableError("its stored deployed name plan is not readable")
        for entry in new_plan:
            ident = (entry["module_id"], entry["module_key"])
            if ident in deployed and deployed[ident] != entry["name_suffix"]:
                raise ExpressWorkerRenameRefusedError(
                    entry["module_id"], entry["module_key"], deployed[ident], entry["name_suffix"])
        return
    if existing_record.get(EXPRESS_NAME_PLAN_TRACKED_FIELD) is True:
        return
    if any(entry["name_suffix"] is not None for entry in new_plan):
        raise ExpressWorkerRenameUnverifiableError("its record predates name-plan tracking")


class ExpressHCLSynthesizer:
    """
    Deterministic synthesizer for Express Golden and Enterprise Registered Workloads.
    Generates infra/workload/ configuration and vendors selected modules.
    """

    def __init__(self, db: Optional[Any] = None):
        self.db = db

    def synthesize_workload(
        self,
        product_id: str,
        project_id: str,
        region: str = "us-central1",
        github_repo_full_name: str = "",
        module_instances: Optional[List[Dict[str, Any]]] = None,
        state_bucket: str = "",
        include_vpc: bool = False,
        vcs_provider: str = "GITHUB",
        iac_engine: str = "OPENTOFU",
        subnet_cidr: Optional[str] = None,
        access: Optional[Any] = None,
        github_actions_deploy: bool = True,
        runner_identity_mode: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Synthesizes a complete workload file map ready for VCS commit.
        Returns a Dict[relative_path, content].

        `github_actions_deploy` (GHA-DEPLOY-SWITCH): False (a GitHub workload whose switch is off) forwards
        `var.enable_github_actions_deploy` (declared with default false) to the foundation, so it has no WIF pool,
        provider or deployer service account. True = the previous rendering, byte for byte. Never coerced.

        `access` (FD-4CS): the workload's access record (``AccessPolicy``) that decides how every Cloud Run service is
        exposed (``express_access_arguments``); None (a workload with no record) keeps the previous rendering.

        `subnet_cidr` (FD-CSQL): the IPAM WORKLOAD_SUBNET allocation for this workload. Used only when an instance
        needs a private network (`requires_private_network`): the VPC subnet then reads `var.subnet_cidr` and the
        value is written to infra/workload/terraform.tfvars. Without it the variable has no value and plan stops
        with "No value for required variable" (fail closed; never a literal range).
        """
        if not isinstance(github_actions_deploy, bool):
            raise ValueError(f"github_actions_deploy must be a bool: {github_actions_deploy!r}")
        clean_pid = product_id.strip().lower().replace("_", "-")
        target_proj = project_id.strip()
        instances = module_instances or []

        # If no instances specified, provide a default Cloud Run gateway
        if not instances:
            instances = [
                {
                    "module_id": "compute-cloudrun",
                    "instance_name": "gateway",
                    "parameters": {},
                }
            ]

        # EXP-4: name suffixes for repeated NAME_SUFFIX_MODULES instances; fails closed (ExpressSynthesisRefused) on a
        # suffix collision, a suffix that is not an RFC 1123 label or a resulting resource name that is too long,
        # before anything is rendered.
        planned = _plan_instances(instances)
        name_suffixes = _name_suffixes(planned, clean_pid)
        # FD-4CS: the access record's Cloud Run arguments; refuses (before anything is rendered) an incomplete record
        # or an instance parameter that contradicts it.
        access_args = express_access_arguments(instances, access)

        # FD-CSQL: a private-IP database forces the VPC (with Private Services Access) and the IPAM subnet fact.
        private_net = self.requires_private_network(instances)
        fact_cidr = None
        if private_net and subnet_cidr:
            fact_cidr = str(ipaddress.ip_network(str(subnet_cidr).strip(), strict=True))

        # Check if VPC networking was explicitly requested as an instance or via toggle
        has_vpc = private_net or include_vpc or any(
            (inst.get("module_id") if isinstance(inst, dict) else getattr(inst, "module_id", "")) == "networking-vpc"
            for inst in instances
        )

        files: Dict[str, str] = {}

        # 1. Root .gitignore
        files[".gitignore"] = self._generate_gitignore()

        # 2. versions.tf
        files["infra/workload/versions.tf"] = self._generate_versions_tf(iac_engine)

        # 3. variables.tf
        files["infra/workload/variables.tf"] = self._generate_variables_tf(
            clean_pid, region, github_repo_full_name
        ) + ("" if github_actions_deploy else GHA_DEPLOY_SWITCH_VARIABLE_BLOCK)   # GHA-DEPLOY-SWITCH
        if private_net:
            files["infra/workload/variables.tf"] += self._generate_subnet_fact_variable_tf()
            if fact_cidr:
                files["infra/workload/terraform.tfvars"] = f'subnet_cidr = "{fact_cidr}"\n'

        # 4. backend.tf (FD-7L Phase 3, plan 2.6 / row FD-7L-d: on a Per-workload install the platform always writes
        # the backend into the deploy workspace, from vending's provenance record, so Express commits none)
        if state_bucket and not _platform_owns_backend(runner_identity_mode):
            files["infra/workload/backend.tf"] = self._generate_backend_tf(
                state_bucket, clean_pid
            )

        # 5. Vendor foundation module files
        self._vendor_foundation_module(files)

        # 6. Vendor VPC module if included
        if has_vpc:
            self._vendor_module_files("networking-vpc", files)

        # 7. Synthesize main.tf & outputs.tf and vendor all instance modules
        registered: set = set()   # FD-4CX: the instance modules vendored from the registered-module catalog
        main_tf, outputs_tf = self._synthesize_main_and_outputs(
            product_id=clean_pid,
            instances=instances,
            has_vpc=has_vpc,
            files=files,
            private_net=private_net,
            planned=planned,
            name_suffixes=name_suffixes,
            access_args=access_args,
            registered=registered,
            github_actions_deploy=github_actions_deploy,   # GHA-DEPLOY-SWITCH
        )
        # FD-4CX: a private access record never deploys a registered module that grants public access by itself
        # (no record = an Express workload created before FD-4CS: unchanged; PUBLIC_APP: public is the record's own
        # answer).
        if access is not None and access.allow_unauthenticated is not True:
            for mod_id, mod_files in modules_under(files, registered).items():
                try:
                    check_registered_module(mod_id, mod_files)
                except RegisteredModulePublicExposureError as exposure:
                    raise ExpressRegisteredModuleExposureError(exposure) from exposure
            # RT F3i: an instance parameter that hands a registered module a public principal (exact literal string,
            # or a string element of a list) would open it whatever the module's own files say
            for mod_id, _key, inst_name, params in planned:
                if mod_id not in registered:
                    continue
                for name in sorted(params):
                    value = params[name]
                    items = value if isinstance(value, list) else [value]
                    public = sorted({v for v in items if isinstance(v, str) and v in PUBLIC_MEMBERS})
                    if public:
                        raise ExpressRegisteredModuleParameterError(mod_id, inst_name, name, public)
        files["infra/workload/main.tf"] = main_tf
        files["infra/workload/outputs.tf"] = outputs_tf

        # 8. README.md
        files["README.md"] = self._generate_readme(clean_pid, instances, has_vpc)

        return files

    @staticmethod
    def requires_private_network(module_instances: Optional[List[Any]]) -> bool:
        """True when an instance is a private-IP golden database (PRIVATE_NETWORK_DB_MODULES): the workload then
        needs a VPC with Private Services Access and the IPAM WORKLOAD_SUBNET fact (`subnet_cidr`)."""
        return any(_instance_module_id(inst) in PRIVATE_NETWORK_DB_MODULES for inst in (module_instances or []))

    def allocate_subnet_cidr(
        self, product_id: str, project_id: str, region: str, *, supernet_cidr: str, prefix_len: int
    ) -> Optional[str]:
        """FD-CSQL: the IPAM WORKLOAD_SUBNET range for this workload (ledger `cidr_allocations` via self.db, the
        same engine and ledger the architect stage uses; an existing allocation for the workload is reused). The
        pool (supernet, prefix) is the platform setting the caller passes. Returns None, logged, when there is no
        Firestore client or the allocation fails (fail closed: synthesize_workload then leaves var.subnet_cidr
        without a value)."""
        if not self.db:
            logger.error(f"IPAM: no Firestore client; no subnet range for Express workload '{product_id}'")
            return None
        try:
            try:
                from shared.ipam import CastorIPAMEngine
            except ImportError:
                from ipam import CastorIPAMEngine  # type: ignore
            clean = product_id.strip().lower().replace("_", "-")
            rec = CastorIPAMEngine(db=self.db, supernet_cidr=supernet_cidr).allocate_next_cidr(
                product_id=product_id,
                purpose="WORKLOAD_SUBNET",
                prefix_len=prefix_len,
                region=region,
                project_id=project_id,
                network_name=f"{clean}-vpc",
                subnet_name=f"{clean}-vpc-{region}-subnet",
            )
            logger.info(f"IPAM allocated {rec.cidr_block} (WORKLOAD_SUBNET) for Express workload '{product_id}'")
            return rec.cidr_block
        except Exception as e:
            logger.error(f"IPAM allocation failed for Express workload '{product_id}': {e}")
            return None

    @staticmethod
    def _generate_subnet_fact_variable_tf() -> str:
        """The IPAM subnet fact, declared the way the developer stage's platform_facts.render_fact_variables does."""
        return """
# Platform network facts (IPAM). The value is supplied in terraform.tfvars by the platform; never a CIDR literal.
variable "subnet_cidr" {
  description = "Workload subnet range allocated by the platform IPAM (platform-owned; never a literal)"
  type        = string
  validation {
    condition     = can(cidrnetmask(var.subnet_cidr))
    error_message = "subnet_cidr must be an IPv4 CIDR allocated by the platform IPAM."
  }
}
"""

    def _generate_gitignore(self) -> str:
        return """# OpenTofu / Terraform
.terraform/
.terraform.lock.hcl
*.tfstate
*.tfstate.*
crash.log
crash.*.log
override.tf
override.tf.json
*_override.tf
*_override.tf.json

# Environment & secrets
.env
.env.*
*.secret
"""

    def _generate_versions_tf(self, engine: str = "OPENTOFU") -> str:
        return """terraform {
  required_version = ">= 1.9.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0.0, < 7.0.0"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = ">= 6.0.0, < 7.0.0"
    }
  }
}
"""

    def _generate_variables_tf(
        self, product_id: str, region: str, github_repo: str
    ) -> str:
        return f"""variable "project_id" {{
  description = "Target GCP Child Project ID"
  type        = string
}}

variable "region" {{
  description = "GCP Region for regional infrastructure"
  type        = string
  default     = "{region}"
}}

variable "product_id" {{
  description = "Workload Product ID slug"
  type        = string
  default     = "{product_id}"
}}

variable "github_repo_full_name" {{
  description = "Full GitHub repository name (owner/repo) for WIF authentication"
  type        = string
  default     = "{github_repo}"
}}

variable "github_repository_id" {{
  description = "GitHub numeric repository id for the WIF condition (FD-4AT-c). Supplied by the platform at apply time; empty = not pinned."
  type        = string
  default     = ""
}}
"""

    def _generate_backend_tf(self, bucket: str, product_id: str) -> str:
        return f"""terraform {{
  backend "gcs" {{
    bucket = "{bucket}"
    prefix = "workloads/{product_id}"
  }}
}}
"""

    def _vendor_foundation_module(self, files: Dict[str, str]) -> None:
        """Vendors the base workload-foundation module into infra/modules/workload-foundation/base/"""
        modules_dir = get_platform_modules_path()
        foundation_disk_dir = (
            os.path.join(modules_dir, "workload-foundation", "base")
            if modules_dir
            else None
        )

        disk_found = False
        if foundation_disk_dir and os.path.isdir(foundation_disk_dir):
            try:
                for fname in sorted(os.listdir(foundation_disk_dir)):
                    if fname.endswith(".tf"):
                        fpath = os.path.join(foundation_disk_dir, fname)
                        with open(fpath, "r", encoding="utf-8") as f:
                            files[f"infra/modules/workload-foundation/base/{fname}"] = f.read()
                disk_found = True
            except Exception as e:
                logger.warning(f"Failed to read foundation from disk {foundation_disk_dir}: {e}")

        if not disk_found:
            # EXP-1 (RT F1): no module tree on disk -> the built-in payload, which is byte-identical to the module on
            # disk and parity-tested (tests/test_lane8_payload_parity.py). The hand-written third copy that used to
            # live here had drifted (outputs, delete protection, repository ID). Fail closed when both are missing.
            payload = BUILTIN_MODULE_FILES.get("workload-foundation/base") or {}
            if not payload:
                raise RuntimeError(
                    "workload-foundation/base is unavailable (no module tree on disk and no built-in payload)"
                )
            prefix = "infra/modules/workload-foundation/base/"
            for key in [k for k in files if k.startswith(prefix)]:   # drop a partial read from disk
                del files[key]
            for fname, content in sorted(payload.items()):
                files[f"{prefix}{fname}"] = content

    def _vendor_module_files(self, module_id: str, files: Dict[str, str],
                             registered: Optional[set] = None) -> None:
        """Vendors an individual module (built-in golden or custom) into infra/modules/<module_id>/. FD-4CX: a module
        read from the registered catalog (Firestore `custom_modules`, step 3) is added to `registered` when given."""
        target_prefix = f"infra/modules/{module_id}/"

        # Check if already vendored
        if any(k.startswith(target_prefix) for k in files):
            return

        # 1. Try local filesystem
        modules_dir = get_platform_modules_path()
        if modules_dir:
            mod_path = os.path.join(modules_dir, module_id)
            if os.path.isdir(mod_path):
                try:
                    found_any = False
                    for fname in sorted(os.listdir(mod_path)):
                        if fname.endswith(".tf"):
                            fpath = os.path.join(mod_path, fname)
                            if os.path.isfile(fpath):
                                with open(fpath, "r", encoding="utf-8") as f:
                                    files[f"{target_prefix}{fname}"] = f.read()
                                found_any = True
                    if found_any:
                        return
                except Exception as e:
                    logger.warning(f"Error copying module {module_id} from disk: {e}")

        # 2. Try embedded payloads
        if module_id in BUILTIN_MODULE_FILES:
            for fname, content in BUILTIN_MODULE_FILES[module_id].items():
                files[f"{target_prefix}{fname}"] = content
            return

        # 3. Try Firestore custom_modules collection
        if self.db:
            try:
                doc = self.db.collection("custom_modules").document(module_id).get()
                if doc.exists:
                    cdata = doc.to_dict() or {}
                    hcl_dict = cdata.get("hcl_files") or {}
                    for fname, content in hcl_dict.items():
                        files[f"{target_prefix}{fname}"] = content
                    if hcl_dict:
                        if registered is not None:
                            registered.add(module_id)
                        return
            except Exception as e:
                logger.warning(f"Could not load custom module {module_id} from Firestore: {e}")

        logger.warning(f"Could not resolve source files for module '{module_id}'.")

    def _synthesize_main_and_outputs(
        self,
        product_id: str,
        instances: List[Any],
        has_vpc: bool,
        files: Dict[str, str],
        private_net: bool = False,
        planned: Optional[List[tuple]] = None,
        name_suffixes: Optional[Dict[str, str]] = None,
        access_args: Optional[List[tuple]] = None,
        registered: Optional[set] = None,
        github_actions_deploy: bool = True,
    ) -> (str, str):
        """Generates main.tf and outputs.tf blocks. `planned` / `name_suffixes` (EXP-4) are computed from `instances`
        when not given. `access_args` (FD-4CS): see `express_access_arguments`. `github_actions_deploy`
        (GHA-DEPLOY-SWITCH): False adds GHA_DEPLOY_SWITCH_LINE to the foundation; True = byte-identical."""
        main_blocks: List[str] = [
            """provider "google" {
  project               = var.project_id
  region                = var.region
  user_project_override = true
  billing_project       = var.project_id
}

provider "google-beta" {
  project               = var.project_id
  region                = var.region
  user_project_override = true
  billing_project       = var.project_id
}

# ------------------------------------------------------------------------------
# Foundation (APIs, WIF, IAM, Firestore, Registry)
# ------------------------------------------------------------------------------
module "foundation" {
  source = "../modules/workload-foundation/base"

  project_id            = var.project_id
  region                = var.region
  product_id            = var.product_id
  github_repo_full_name = var.github_repo_full_name
  github_repository_id  = var.github_repository_id
""" + ("" if github_actions_deploy else GHA_DEPLOY_SWITCH_LINE) + """}"""
        ]

        outputs_blocks: List[str] = [
            """output "workload_sa_email" {
  description = "Runtime service account email"
  value       = module.foundation.workload_sa_email
}

output "artifact_registry_repository" {
  description = "Workload Artifact Registry Docker repository ID"
  value       = module.foundation.docker_repo_id
}"""
        ]

        # Networking module
        if has_vpc and private_net:
            # FD-CSQL: subnet on the IPAM fact; Private Services Access stays on (module default) for the database.
            main_blocks.append(
                """# ------------------------------------------------------------------------------
# Enterprise VPC Networking (Private Services Access for the private-IP database)
# ------------------------------------------------------------------------------
module "network" {
  source = "../modules/networking-vpc"

  project_id          = var.project_id
  region              = var.region
  network_name        = "${var.product_id}-vpc"
  primary_subnet_cidr = var.subnet_cidr
  depends_on          = [module.foundation]
}"""
            )
            outputs_blocks.append(
                """output "vpc_network_name" {
  description = "VPC Network Name"
  value       = module.network.network_name
}"""
            )
        elif has_vpc:
            main_blocks.append(
                """# ------------------------------------------------------------------------------
# Enterprise VPC Networking
# ------------------------------------------------------------------------------
module "network" {
  source = "../modules/networking-vpc"

  project_id   = var.project_id
  region       = var.region
  network_name = "${var.product_id}-vpc"
  depends_on   = [module.foundation]
}"""
            )
            outputs_blocks.append(
                """output "vpc_network_name" {
  description = "VPC Network Name"
  value       = module.network.network_name
}"""
            )

        # Instance iteration
        if planned is None:
            planned = _plan_instances(instances)
        if name_suffixes is None:
            name_suffixes = _name_suffixes(planned, product_id)
        for mod_id, key, inst_name, params in planned:
            # Vendor module source files (FD-4CX: `registered` collects the ids read from the registered catalog)
            self._vendor_module_files(mod_id, files, registered=registered)

            # Generate module block and outputs
            m_block, o_block = self._generate_module_instance(
                module_id=mod_id,
                instance_key=key,
                instance_name=inst_name,
                product_id=product_id,
                params=params,
                has_vpc=has_vpc,
                name_suffix=name_suffixes.get(key),
                access_args=access_args,
            )
            main_blocks.append(m_block)
            if o_block:
                outputs_blocks.append(o_block)

        main_content = "\n\n".join(main_blocks) + "\n"
        outputs_content = "\n\n".join(outputs_blocks) + "\n"
        return main_content, outputs_content

    def _generate_module_instance(
        self,
        module_id: str,
        instance_key: str,
        instance_name: str,
        product_id: str,
        params: Dict[str, Any],
        has_vpc: bool,
        name_suffix: Optional[str] = None,
        access_args: Optional[List[tuple]] = None,
    ) -> (str, str):
        """Constructs the HCL module block and outputs for a specific instance. `name_suffix` (EXP-4) is set only for
        a repeated NAME_SUFFIX_MODULES module (see _name_suffixes). `access_args` (FD-4CS): the access record's
        compute-cloudrun arguments (`express_access_arguments`); None keeps the `allow_unauthenticated` parameter."""
        clean_name = instance_name.replace("_", "-").lower()

        if module_id == "compute-cloudrun":
            starter_img = params.get("container_image") or "us-docker.pkg.dev/cloudrun/container/hello"
            allow_unauth = "true" if params.get("allow_unauthenticated", True) else "false"
            health_path = params.get("health_check_path", "/")

            # One contiguous argument run with `=` aligned to the longest name (tofu fmt layout). Without an access
            # record the text is exactly the pre-FD-4CS block.
            args = [
                ("project_id", "var.project_id"),
                ("region", "var.region"),
                ("product_id", "var.product_id"),
                ("service_name", f'"${{var.product_id}}-{clean_name}"'),
                ("service_account_email", "module.foundation.workload_sa_email"),
                ("container_image", f'"{starter_img}"'),
                ("health_check_path", f'"{health_path}"'),
            ]
            args.extend(access_args if access_args is not None else [("allow_unauthenticated", allow_unauth)])
            args.append(("depends_on", "[module.foundation]"))
            width = max(len(k) for k, _ in args)
            arg_lines = "\n".join(f"  {k.ljust(width)} = {v}" for k, v in args)
            m_block = f"""# Compute Service: {clean_name}
module "compute_{instance_key}" {{
  source = "../modules/compute-cloudrun"

{arg_lines}
}}"""
            o_block = f"""output "compute_{instance_key}_uri" {{
  description = "Cloud Run URI for {clean_name}"
  value       = module.compute_{instance_key}.service_uri
}}"""
            return m_block, o_block

        elif module_id == "database-cloudsql":
            db_version = params.get("database_version", "POSTGRES_16")
            db_tier = params.get("tier", "db-f1-micro")
            db_name = params.get("database_name", f"{clean_name}_db".replace("-", "_"))
            # FD-4AZ-b3: deletion protection follows the module default (true). Only an explicit
            # `"deletion_protection": false` in the Express instance parameters opts out.
            opt_out = (
                "\n  deletion_protection  = false" if params.get("deletion_protection") is False else ""
            )

            # FD-CSQL: private IP on the workload VPC (forced by requires_private_network). Module-level depends_on
            # on module.network waits for its Private Services Access connection before the instance is created.
            m_block = f"""# Database: {clean_name}
module "database_{instance_key}" {{
  source = "../modules/database-cloudsql"

  project_id           = var.project_id
  region               = var.region
  instance_name_suffix = "{clean_name}"
  database_version     = "{db_version}"
  tier                 = "{db_tier}"
  database_name        = "{db_name}"{opt_out}
  private_network_id   = module.network.network_id
  workload_sa_email    = module.foundation.workload_sa_email
  depends_on           = [module.foundation, module.network]
}}"""
            o_block = f"""output "database_{instance_key}_connection_name" {{
  description = "Cloud SQL connection name for {clean_name}"
  value       = module.database_{instance_key}.instance_connection_name
}}"""
            return m_block, o_block

        elif module_id == "storage-bucket":
            m_block = f"""# Storage Bucket: {clean_name}
module "storage_{instance_key}" {{
  source = "../modules/storage-bucket"

  project_id         = var.project_id
  region             = var.region
  bucket_name_suffix = "{clean_name}"
  workload_sa_email  = module.foundation.workload_sa_email
  depends_on         = [module.foundation]
}}"""
            o_block = f"""output "storage_{instance_key}_bucket_name" {{
  description = "Bucket name for {clean_name}"
  value       = module.storage_{instance_key}.bucket_name
}}"""
            return m_block, o_block

        elif module_id == "messaging-pubsub":
            m_block = f"""# Pub/Sub Messaging: {clean_name}
module "messaging_{instance_key}" {{
  source = "../modules/messaging-pubsub"

  project_id        = var.project_id
  topic_name_suffix = "{clean_name}"
  workload_sa_email = module.foundation.workload_sa_email
  depends_on        = [module.foundation]
}}"""
            o_block = f"""output "messaging_{instance_key}_topic_id" {{
  description = "Pub/Sub Topic ID for {clean_name}"
  value       = module.messaging_{instance_key}.topic_id
}}"""
            return m_block, o_block

        elif module_id == "compute-event-worker":
            starter_img = params.get("container_image") or "us-docker.pkg.dev/cloudrun/container/hello"
            # EXP-1: compute-event-worker is a Pub/Sub topic + Cloud Run job. It has no service_name input (its
            # names derive from product_id) and no service_uri output; the root output is the job name.
            # EXP-4: with several event workers each passes its name_suffix; a single one passes none (unchanged).
            suffix_line = f'\n  name_suffix           = "{name_suffix}"' if name_suffix else ""
            m_block = f"""# Event Worker: {clean_name}
module "worker_{instance_key}" {{
  source = "../modules/compute-event-worker"

  project_id            = var.project_id
  region                = var.region
  product_id            = var.product_id{suffix_line}
  service_account_email = module.foundation.workload_sa_email
  container_image       = "{starter_img}"
  depends_on            = [module.foundation]
}}"""
            o_block = f"""output "worker_{instance_key}_job_name" {{
  description = "Cloud Run job name for event worker {clean_name}"
  value       = module.worker_{instance_key}.job_name
}}"""
            return m_block, o_block

        else:
            # Generic module handling (supports custom registered enterprise modules)
            # Arguments are collected as (name, value) pairs first and written with `=` padded to the longest name
            # in the block (EXP-1 RT F4: the canonical `tofu fmt` layout of one contiguous argument run).
            args = [("project_id", "var.project_id")]
            # Add standard parameters if relevant
            for p_k, p_v in params.items():
                if isinstance(p_v, bool):
                    v_str = "true" if p_v else "false"
                elif isinstance(p_v, (int, float)):
                    v_str = str(p_v)
                elif isinstance(p_v, str):
                    v_str = f'"{p_v}"'
                elif isinstance(p_v, (dict, list)):
                    v_str = json.dumps(p_v)
                else:
                    v_str = f'"{p_v}"'
                args.append((str(p_k), v_str))

            if module_id == "database-alloydb":
                # FD-CSQL (F6): AlloyDB needs a VPC network ID with Private Services Access (forced by
                # requires_private_network) and a product_id for its cluster name. Explicit parameters win.
                if "network" not in params:
                    args.append(("network", "module.network.network_id"))
                if "product_id" not in params:
                    args.append(("product_id", "var.product_id"))
                args.append(("depends_on", "[module.foundation, module.network]"))
            else:
                args.append(("depends_on", "[module.foundation]"))
            width = max(len(k) for k, _ in args)
            lines = [
                f'# Registered Module: {module_id} ({clean_name})',
                f'module "mod_{instance_key}" {{',
                f'  source = "../modules/{module_id}"',
                "",
            ]
            lines.extend(f"  {k.ljust(width)} = {v}" for k, v in args)
            lines.append("}")
            m_block = "\n".join(lines)
            o_block = ""
            return m_block, o_block

    def _generate_readme(
        self, product_id: str, instances: List[Any], has_vpc: bool
    ) -> str:
        lines = [
            f"# {product_id}",
            "",
            "> ⚡ **Provisioned via StackVend Express Registered Modules**",
            "",
            "This repository contains deterministic Infrastructure as Code managed by StackVend.",
            "",
            "## Architecture Overview",
            "- **Foundation Module**: Core Google Cloud APIs, Workload Identity Federation (WIF) deployer pool, Artifact Registry, Firestore database, and Workload Service Account.",
        ]
        if has_vpc:
            lines.append("- **Networking Module**: Enterprise Virtual Private Cloud (VPC) with Private Google Access subnets.")

        lines.append("### Active Workload Modules")
        for inst in instances:
            if isinstance(inst, dict):
                mid = inst.get("module_id", "custom")
                iname = inst.get("instance_name", "default")
            else:
                mid = getattr(inst, "module_id", "custom")
                iname = getattr(inst, "instance_name", "default")
            lines.append(f"- `{mid}` (Instance: `{iname}`)")

        lines.extend([
            "",
            "## Repository Structure",
            "```",
            "infra/",
            "├── modules/       # Vendored hermetic golden and custom modules",
            "└── workload/      # Root OpenTofu / Terraform deployment configuration",
            "    ├── main.tf",
            "    ├── variables.tf",
            "    ├── outputs.tf",
            "    ├── backend.tf",
            "    └── versions.tf",
            "```",
            "",
            "## Autonomous Agentic Extensibility",
            "This workload is registered in the StackVend Control Center. When new features or application logic",
            "are needed, StackVend's autonomous multi-agent swarm can be triggered to inspect `infra/workload/main.tf`",
            "and scaffold application code directly in `apps/<service_name>/`.",
        ])
        return "\n".join(lines) + "\n"
