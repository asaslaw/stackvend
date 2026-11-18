"""Typed IaC intent v1: schema, gate and renderer (typed-IaC lane TI-2; INERT: no caller, mode stays "off").

Plan: docs/planning/typed-iac-intent-plan.md §2.2-§2.5 and §4 TI-2, as amended by its Fable RT
(docs/planning/typed-iac-intent-plan-red-team-fable.md F4-F8). Builder report: docs/handoff/ti2-intent-core-report.md.

What this module is. The AI will (from TI-3) fill a typed document `infra/workload/iac_intent.json` instead of writing
HCL: instances of the AI-instantiable golden modules (args derived from each module's variables.tf, data file
`iac_intent/module_catalog.json`) plus extra resources of an allow-listed set of types (`iac_intent/allowed_types.json`)
whose arguments are walked against the pinned provider schema (`iac_intent/provider_schema_slice.json`, built offline
from the production mirror). References are typed objects, never `${...}` strings. The platform renders the HCL
(`custom.tf.json`, plus `intent_facts.tf.json` when a platform data-source fact is used).

Design rules kept here (every one is tested in tests/test_typed_iac_ti2_*.py):
- No heuristics: every check is a schema walk, an exact table, or a closed grammar (AGENTS.md invariant 2).
- FD-4AW (the renderer is an exfiltration surface): `${` reaches the output ONLY from a Ref / Member / Call, assembled
  from grammar-checked identifiers, catalog / schema names and the platform's own fact expressions. Every literal
  string is template-escaped (`${` -> `$${`, `%{` -> `%%{`); strings and object keys inside a Call are HCL string
  literals with full escaping. No `count`, `for_each`, `provider`, `provisioner`, `connection`, `dynamic` or nested
  `//` key can be expressed; `//` (provenance) is emitted at the top level only.
- Facts, secrets and topology-owned values are not AI arguments: FACT-class module variables are rendered by the
  platform, SECRET-class variables are never rendered in v1 (the module default / its own generator is used), so no
  module `count` can see an unknown value from them (RT F4; static rule in scripts/build_iac_catalog.py).
- A missing or inconsistent artifact is IntentGateUnavailable (GATE_UNAVAILABLE), never a pass.
- Owner answers (Q-TI-3/4/5/7/9) are DATA in allowed_types.json: a different answer is a data edit.

Pure apart from reading the four artifacts. Root `shared/` is the source of truth; apps/orchestrator-gateway/shared/
carries a byte-identical copy (deploy/vendor_shared.py).
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, List, Literal, Mapping, Optional, Sequence, Set, Tuple, Union

from pydantic import (AfterValidator, BaseModel, ConfigDict, Field, StrictBool, StrictFloat, StrictInt, StrictStr,
                      StringConstraints, ValidationError)
from typing import Annotated

try:  # TI-3: the gateway imports this module at start-up now; typing.TypeAliasType is stdlib from Python 3.12
    from typing import TypeAliasType  # type: ignore[attr-defined]
except ImportError:  # pragma: no cover - Python < 3.12 (pydantic's own dependency)
    from typing_extensions import TypeAliasType

try:
    from shared.diagnostics import Diagnostic, ErrorClass
    from shared.service_topology import (BOOTSTRAP_CATALOG, HCL_IDENT_PATTERN, INITIAL_VALUES, MODULE_ONLY_ATTRIBUTES,
                                         PROVIDER_TYPE_PATTERN, PUSH_PATH_PATTERN, SECRET_RESOURCE_TYPE,
                                         SERVICE_NAME_PATTERN, push_path_ok, strongly_connected_components)
except ImportError:  # pragma: no cover - package-relative import inside a vendored copy
    from .diagnostics import Diagnostic, ErrorClass  # type: ignore
    from .service_topology import (BOOTSTRAP_CATALOG, HCL_IDENT_PATTERN, INITIAL_VALUES,  # type: ignore
                                   MODULE_ONLY_ATTRIBUTES, PROVIDER_TYPE_PATTERN, PUSH_PATH_PATTERN,
                                   SECRET_RESOURCE_TYPE, SERVICE_NAME_PATTERN, push_path_ok,
                                   strongly_connected_components)

__all__ = [
    "SCHEMA_ID", "INTENT_PATH", "RENDER_PATH", "FACTS_RENDER_PATH", "DATA_DIR", "ARTIFACT_FILES", "FACTS",
    "PLAN_KNOWN_FACTS", "SERVICE_AGENT_FACTS", "MODULE_ARG_CLASS", "ARG_CLASSES", "RESOURCE_META_ARGUMENTS",
    "MODULE_META_ARGUMENTS", "IntentGateUnavailable", "Artifacts", "load_artifacts", "check_ready_parity",
    "IacIntent", "ModuleInstance", "ExtraResource", "IntentOutput", "Lifecycle", "Ref", "Member", "Call", "Value",
    "IntentContext", "default_facts", "GateResult", "ValidatedIntent", "validate_intent", "RenderResult",
    "render_intent", "render_parsed_for_shadow", "canonical_intent_json", "intent_sha256", "response_json_schema",
    "parse_type_constraint", "escape_template", "hcl_string_literal", "REALIZATION_EXPORTS", "intent_realizations",
    "REALIZATION_REQUIRED_ARGS", "GENERATED_SECRET_MODULE", "GENERATED_SECRET_ARG", "GENERATED_SECRET_VERSION_TYPE",
    "MODULE_ARG_CLASS_BY_MODULE", "PLATFORM_NETWORK_MODULE", "PLATFORM_NETWORK_MODULE_ID", "PLATFORM_CONNECTOR_TYPE",
    "PLATFORM_CONNECTOR_NAME", "PLATFORM_CONNECTOR_REF", "PLATFORM_CONNECTOR_MODULE", "PLATFORM_CONNECTOR_MODULE_ID",
    "PLATFORM_CONNECTOR_LEGACY_ADDRESS", "NETWORK_FACT_EXPRS", "ZONE_FACT_EXPR",
    "platform_network_facts", "platform_zone_facts", "NOT_YET_WIRED_MODULES", "NETWORK_WIRING_FACTS",
]

SCHEMA_ID = "iac_intent/v1"
INTENT_PATH = "infra/workload/iac_intent.json"
RENDER_PATH = "infra/workload/custom.tf.json"
FACTS_RENDER_PATH = "infra/workload/intent_facts.tf.json"
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "iac_intent")
ARTIFACT_FILES = ("module_catalog.json", "allowed_types.json", "provider_schema_slice.json", "MANIFEST")
MODULE_SOURCE_PREFIX = "../modules/"
_FILE = INTENT_PATH

# ------------------------------------------------------------------------------------------------ fact table (exact)
# fact -> the platform's own HCL expression (None = not available unless the platform context supplies one: lane 11
# network facts). `data` lists the platform data sources the expression needs (rendered into FACTS_RENDER_PATH, a
# platform file; the AI can never declare a data source). RT F5: project_number + Google service agents.
_PROJECT_DATA = "data.google_project.stackvend_intent_project"
_GCS_AGENT_DATA = "data.google_storage_project_service_account.stackvend_intent_gcs"
FACTS: Dict[str, Dict[str, Any]] = {
    "project_id": {"expr": "var.project_id"},
    "region": {"expr": "var.region"},
    "product_id": {"expr": "var.product_id"},
    "workload_sa_email": {"expr": "module.foundation.workload_sa_email", "service_account": True},
    "workload_sa_member": {"expr": 'format("serviceAccount:%s", module.foundation.workload_sa_email)'},
    "docker_repo_id": {"expr": "module.foundation.docker_repo_id"},
    "database_name": {"expr": "module.foundation.database_name"},
    "container_image": {"expr": "var.container_image"},
    "project_number": {"expr": _PROJECT_DATA + ".number", "data": ("google_project",)},
    "gcs_service_agent": {"expr": _GCS_AGENT_DATA + ".email_address",
                          "data": ("google_storage_project_service_account",), "service_agent": True},
    "pubsub_service_agent": {"expr": 'format("service-%s@gcp-sa-pubsub.iam.gserviceaccount.com", '
                                     + _PROJECT_DATA + ".number)", "data": ("google_project",), "service_agent": True},
    # TI-5c (register TI-5c): the lane-11 network facts. They have no expression in this static table (so the IaC
    # prompt and the default context are unchanged); the developer stage supplies them through IntentContext.facts
    # (iac_intent_contract.intent_context) when the workload's IPAM facts exist. `platform: "network"` = using the
    # fact makes the renderer emit the platform network (PLATFORM_NETWORK_MODULE) into FACTS_RENDER_PATH.
    "network": {"expr": None, "owner": "lane 11", "platform": "network"},
    # Vertex AI endpoint peering takes projects/<project NUMBER>/global/networks/<name> (provider docs, 6.35.0).
    "network_by_project_number": {"expr": None, "owner": "lane 11", "data": ("google_project",),
                                  "platform": "network"},
    "subnetwork": {"expr": None, "owner": "lane 11", "platform": "network"},
    "connector_id": {"expr": None, "owner": "lane 11"},
    "zone": {"expr": None, "owner": "lane 11", "data": ("google_compute_zones",)},
    "kubernetes_namespace": {"expr": None, "owner": "topology (GKE)"},
}
FactName = Literal[tuple(FACTS)]  # type: ignore[valid-type]
SERVICE_AGENT_FACTS = tuple(sorted(f for f, v in FACTS.items() if v.get("service_agent")))
ServiceAgentFact = Literal[SERVICE_AGENT_FACTS]  # type: ignore[valid-type]
_PLATFORM_DATA_BLOCKS = {
    "google_project": ("stackvend_intent_project", {"project_id": "${var.project_id}"}),
    "google_storage_project_service_account": ("stackvend_intent_gcs", {"project": "${var.project_id}"}),
    # TI-5c: the zones of the workload's region (no status filter: the sorted list only changes when Google adds a
    # zone, so the chosen zone is stable; a zone literal would hardcode a region, AGENTS.md invariant 3)
    "google_compute_zones": ("stackvend_intent_zones", {"project": "${var.project_id}", "region": "${var.region}"}),
}

# ------------------------------------------------------------------------------------------------ platform network
# TI-5c (register TI-5c): the platform's network on the intent path (lane-11-owned; never expressible by the AI). It
# is rendered into FACTS_RENDER_PATH only when an intent entry uses a `platform: "network"` fact, from the golden
# networking-vpc module on the IPAM subnet fact (var.subnet_cidr) with Private Services Access (Cloud SQL / Redis /
# AlloyDB / Vertex peering), plus one Serverless VPC Access connector on the IPAM connector fact (var.connector_cidr)
# when the context says a Cloud Run service needs it (IntentContext.vpc_connector). Every value is a platform
# variable or a fixed platform label: no CIDR, region or zone literal (AGENTS.md invariant 3). Each child project
# holds one workload, so the fixed names never collide.
# FD-4BH (golden VPC connector): the connector is a call of the golden networking-vpc-connector module
# (module.stackvend_connector), no longer a raw google_vpc_access_connector.stackvend_connector. A `moved` block in the
# same platform file moves a connector rendered before FD-4BH (PLATFORM_CONNECTOR_LEGACY_ADDRESS) into the module, so
# its plan is a move with no change (same name, network, range, machine type and instance counts). The AI still never
# declares a connector (lane11_owned type; the module is platform_only in the catalog).
PLATFORM_NETWORK_MODULE = "stackvend_network"
PLATFORM_NETWORK_MODULE_ID = "networking-vpc"
PLATFORM_CONNECTOR_TYPE = "google_vpc_access_connector"
PLATFORM_CONNECTOR_NAME = "stackvend_connector"
PLATFORM_CONNECTOR_LEGACY_ADDRESS = f"{PLATFORM_CONNECTOR_TYPE}.{PLATFORM_CONNECTOR_NAME}"   # the TI-5c raw render
PLATFORM_CONNECTOR_MODULE = PLATFORM_CONNECTOR_NAME
PLATFORM_CONNECTOR_MODULE_ID = "networking-vpc-connector"
PLATFORM_CONNECTOR_REF = f"module.{PLATFORM_CONNECTOR_MODULE}.id"
_NET = "module." + PLATFORM_NETWORK_MODULE
NETWORK_FACT_EXPRS: Mapping[str, str] = {
    "network": _NET + ".network_id",
    "network_by_project_number": ('format("projects/%s/global/networks/%s", ' + _PROJECT_DATA + ".number, "
                                  + _NET + ".network_name)"),
    "subnetwork": _NET + ".primary_subnetwork_id",
}
ZONE_FACT_EXPR = "element(sort(data.google_compute_zones.stackvend_intent_zones.names), 0)"
_PLATFORM_NETWORK_BODY = {
    "source": MODULE_SOURCE_PREFIX + PLATFORM_NETWORK_MODULE_ID,
    "project_id": "${var.project_id}",
    "region": "${var.region}",
    "network_name": "stackvend-vpc",
    "primary_subnet_cidr": "${var.subnet_cidr}",
    "enable_private_service_access": True,
    "depends_on": ["module.foundation"],
}
_PLATFORM_CONNECTOR_BODY = {
    "source": MODULE_SOURCE_PREFIX + PLATFORM_CONNECTOR_MODULE_ID,
    "name": "stackvend-conn",
    "project_id": "${var.project_id}",
    "region": "${var.region}",
    "network": "${" + _NET + ".network_name}",
    "connector_cidr": "${var.connector_cidr}",
    "min_instances": 2,
    "max_instances": 3,
    "depends_on": ["module.foundation", _NET],
}
# The connector's address inside the golden module (infra/modules/networking-vpc-connector/main.tf)
_PLATFORM_CONNECTOR_MOVED = {"from": PLATFORM_CONNECTOR_LEGACY_ADDRESS,
                             "to": f"module.{PLATFORM_CONNECTOR_MODULE}.{PLATFORM_CONNECTOR_TYPE}.connector"}
# TI-5-F4 (owner 10-21): the Private Services Access range of the platform network is the workload's IPAM fact
# var.psa_cidr (developer_agent.platform_facts PURPOSE_PSA), passed to networking-vpc as its network address and
# prefix length; rendered only when the context holds that fact (IntentContext.psa_range). Without it the module keeps
# Google's automatic allocation, so a network rendered before TI-5-F4 never gets it (no live range move).
_PLATFORM_NETWORK_PSA_ARGS = {
    "psa_address": "${cidrhost(var.psa_cidr, 0)}",
    "psa_prefix_length": '${tonumber(element(split("/", var.psa_cidr), 1))}',
}


# Catalog modules the typed-intent path does not wire to their consumers yet. While a module is listed, the gate
# refuses it with the removable IAC.MODULE_FACT_UNAVAILABLE (its network / zone facts count as missing for it), and a
# topology resource only it could realize stays on the legacy path (iac_intent_contract.not_wired_types,
# IAC.TYPE_NOT_WIRED_YET; a sticky workload stops typed before any LLM call). Owner 10-21 (TI-5c-a) held AlloyDB,
# Vertex AI endpoints and Bigtable here; TI-5-R2 (owner 10-21) made them typed topology resources with consumer
# edges (shared/service_topology.BOOTSTRAP_CATALOG, REALIZATION_EXPORTS below), so the set is empty. The mechanism
# stays for a future module.
NOT_YET_WIRED_MODULES: FrozenSet[str] = frozenset()
# The facts a not-yet-wired module cannot receive (the platform-network and zone facts, exact names)
NETWORK_WIRING_FACTS: FrozenSet[str] = frozenset({"network", "network_by_project_number", "subnetwork", "zone"})


def platform_network_facts() -> Dict[str, str]:
    """TI-5c: the network facts the developer stage adds to IntentContext.facts when the workload holds the IPAM
    WORKLOAD_SUBNET fact (their expressions name PLATFORM_NETWORK_MODULE, which the renderer then emits)."""
    return dict(NETWORK_FACT_EXPRS)


def platform_zone_facts() -> Dict[str, str]:
    """TI-5c: the zone fact (a platform data source on var.region; no IPAM fact needed)."""
    return {"zone": ZONE_FACT_EXPR}
# Facts whose rendered value is known at PLAN time on a first apply (RT F4 static rule). var.* are root inputs.
# workload_sa_email: google 6.35.0 plans google_service_account.email from account_id + project (offline real-provider
# `tofu plan`, 2026-10-18, report §3: `member = "serviceAccount:sa-…@….iam.gserviceaccount.com"` on create).
PLAN_KNOWN_FACTS = frozenset({"project_id", "region", "product_id", "workload_sa_email"})

# ------------------------------------------------------------------------------------------------ module arg classes
# Exact table over every variable name of the AI-instantiable golden modules (the catalog builder fails on a name
# that is missing here; tests/test_typed_iac_ti2_catalog.py). Classes (plan §2.3 + RT F8):
#   FACT     rendered by the platform from `fact`; the AI cannot set it (IAC.PLATFORM_OWNED_ARGUMENT)
#   SECRET   never set by the AI (IAC.SECRET_ARGUMENT); v1 policy "omit": the platform does not render it either, so
#            the module's own default / generator applies (database-cloudsql FD-4AX random_password, alloydb's
#            random_password, security-secret without an initial version) and no count sees an unknown value
#   REF_ONLY the AI must pass a Ref of one of `refs` (kind[:detail])
#   AI       literal or Ref, type-checked against the variable's type; literal-only when it drives a count/for_each
#   HELD     never set by the AI until the named register row lands (IAC.ARGUMENT_HELD); the module default applies
#   PUSH     PUSH-SUB-RENDER (owner 10-28): messaging-pubsub `push`, exactly the closed form {"service": <service Ref,
#            output service_uri>, "path": "/<path>", "service_account_email": <typed push identity>}; the platform
#            renders the module's object (endpoint = service URL + path, OIDC identity, audience = service URL)
#   TOPOLOGY SECRET-INITIAL-VERSION (owner 11-10): rendered by the platform from the architect's typed topology
#            (IntentContext.generated_secrets); the AI can never set it (IAC.PLATFORM_OWNED_ARGUMENT) and the IaC
#            prompt does not list it; a literal, so a count it drives is known at plan time
ARG_CLASSES = ("FACT", "SECRET", "REF_ONLY", "AI", "HELD", "PUSH", "TOPOLOGY")
# SECRET-INITIAL-VERSION: the golden module that renders a topology secret's random first version, its input, and the
# version resource type an intent may not add to a secret whose plan states initial_value (_Gate.secret_values)
GENERATED_SECRET_MODULE = "security-secret"
GENERATED_SECRET_ARG = "generate_initial_version"
GENERATED_SECRET_VERSION_TYPE = "google_secret_manager_secret_version"
_SA_REFS = ("fact:workload_sa_email", "resource_attr:google_service_account.email")
MODULE_ARG_CLASS: Dict[str, Dict[str, Any]] = {
    # FACT
    "project_id": {"class": "FACT", "fact": "project_id"},
    "region": {"class": "FACT", "fact": "region"},
    "location": {"class": "FACT", "fact": "region"},
    "product_id": {"class": "FACT", "fact": "product_id"},
    "workload_sa_email": {"class": "FACT", "fact": "workload_sa_email"},
    "network": {"class": "FACT", "fact": "network"},
    "authorized_network": {"class": "FACT", "fact": "network"},
    "zone": {"class": "FACT", "fact": "zone"},
    "private_network_id": {"class": "FACT", "fact": "network"},     # database-cloudsql (fd-csql-private-network)
    # SECRET
    "db_password": {"class": "SECRET", "policy": "omit"},
    "secret_data": {"class": "SECRET", "policy": "omit"},
    "initial_user_password": {"class": "SECRET", "policy": "omit"},
    # TOPOLOGY (SECRET-INITIAL-VERSION): security-secret's random first version, from service_topology initial_value
    GENERATED_SECRET_ARG: {"class": "TOPOLOGY", "topology": "initial_value"},
    # REF_ONLY
    "target_uri": {"class": "REF_ONLY", "refs": ("service:service_uri",)},
    "destination_run_service_name": {"class": "REF_ONLY", "refs": ("service:service_name",)},
    "service_account_email": {"class": "REF_ONLY", "refs": _SA_REFS},
    "service_account": {"class": "REF_ONLY", "refs": _SA_REFS},
    # TI-5-G3 (owner 10-24): crypto_key_name, which waits for the key's grants (security-kms outputs.tf depends_on),
    # not crypto_key_id (the key only): an encrypted resource is never created before its key grant.
    "kms_key_name": {"class": "REF_ONLY", "refs": ("module_output:security-kms.crypto_key_name",)},
}
# Owner decision (row FD-4AZ-b1, Cloud SQL "still refuses unencrypted connections"): ssl_mode is AI-settable only to
# the two encrypted modes (the module is restricted to the same two on fd-csql-private-network).
MODULE_ARG_CLASS["ssl_mode"] = {"class": "AI", "allowed_values": ("ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED")}
# Lane 14 PR-0b security-kms inputs (integration, compliance-integration): the module's own validation allows exactly
# these two levels; enable_apis / service_agent_services drive for_each, so the AI class makes them literal-only.
MODULE_ARG_CLASS["protection_level"] = {"class": "AI", "allowed_values": ("SOFTWARE", "HSM")}
# TI-3 RT F3(b): zero public IPs. database-cloudsql's enable_public_ip is never true from an intent (the module default
# false stays; a literal false is accepted, anything else is IAC.INVALID_VALUE / IAC.LITERAL_REQUIRED).
MODULE_ARG_CLASS["enable_public_ip"] = {"class": "AI", "allowed_values": (False,)}
_ALLOWED_VALUES_HINT = {
    "ssl_mode": "Owner decision FD-4AZ-b1: unencrypted connections stay refused.",
    "enable_public_ip": "Platform mandate: zero public IPs. Omit enable_public_ip (it is always false).",
}
MODULE_ARG_CLASS["enable_apis"] = {"class": "AI"}
MODULE_ARG_CLASS["service_agent_services"] = {"class": "AI"}
# SCHEDULING-CRON-AUDIENCE (owner 11-14): scheduling-cron `audience`, the OIDC token audience (a literal such as the
# exact audience constant the target verifies; null keeps the target URI). The module validates it.
for _ai in ("ack_deadline_seconds", "alert_name_suffix", "auth_enabled", "bucket_name_suffix", "cluster_id",
            "audience",
            "column_families", "config", "cpu_count", "database_name", "database_version", "dataset_id", "db_user",
            "ddl_statements", "delete_contents_on_destroy", "deletion_protection", "description", "display_name",
            "duration", "enable_dead_letter", "enable_subscription", "endpoint_name", "environment_name",
            "environment_size", "event_type", "filter", "grant_workload_secret_access", "http_method",
            "image_version", "instance_id", "instance_name_suffix", "job_name_suffix", "key_name", "keyring_name",
            "labels", "lifecycle_delete_age_days", "managed_zone", "max_attempts", "max_concurrent_dispatches",
            "max_dispatches_per_second", "memory_size_gb", "message_retention_duration", "notification_channels",
            "num_nodes", "prevent_destroy", "processing_units", "queue_name_suffix", "record_name", "record_type",
            "rotation_period", "rrdatas", "schedule", "secret_id", "source_contents", "storage_type",
            "table_name",
            "threshold_value", "tier", "time_zone", "topic_name_suffix", "transit_encryption_mode",
            "trigger_name_suffix", "ttl", "uniform_bucket_level_access", "versioning_enabled",
            "workflow_name_suffix"):
    MODULE_ARG_CLASS[_ai] = {"class": "AI"}
# TI-5c: exact (module id, variable) overrides of MODULE_ARG_CLASS, read first by scripts/build_iac_catalog.py. The
# Vertex AI endpoint's `network` takes the project NUMBER form of the network name, not the network id.
MODULE_ARG_CLASS_BY_MODULE: Dict[Tuple[str, str], Dict[str, Any]] = {
    ("ai-vertex-endpoint", "network"): {"class": "FACT", "fact": "network_by_project_number"},
    # TI-5-G3d (owner 10-25): BigQuery's CMEK agent (the bq-<number> encryption account) is not grantable by
    # security-kms until TI-5-G3c, so a CMEK BigQuery dataset is refused by the gate, never planned without its grant.
    ("analytics-bigquery", "kms_key_name"): {
        "class": "HELD", "row": "TI-5-G3c",
        "reason": "a CMEK BigQuery dataset needs the BigQuery encryption account granted on the key, which the "
                  "security-kms module cannot grant yet; omit kms_key_name (Google-managed encryption)"},
    # TI-5-G3d (owner 10-25): the services security-kms can grant (its variables.tf validation, exactly;
    # tests/test_ti5_g3b_kms_gcs_agent.py checks parity), so a wrong name is a typed gate finding, not a tofu error.
    ("security-kms", "service_agent_services"): {"class": "AI", "allowed_items": (
        "aiplatform.googleapis.com", "alloydb.googleapis.com", "artifactregistry.googleapis.com",
        "container.googleapis.com", "firestore.googleapis.com", "pubsub.googleapis.com", "redis.googleapis.com",
        "run.googleapis.com", "secretmanager.googleapis.com", "spanner.googleapis.com", "sqladmin.googleapis.com",
        "storage.googleapis.com")},
    # PUSH-SUB-RENDER (owner 10-28): a push subscription to the workload's own Cloud Run service, typed (_Gate.push_arg)
    ("messaging-pubsub", "push"): {"class": "PUSH"},
    # RT14-36 (owner 11-14, data residency): the Spanner instance configuration is regional-<workload region>, set by
    # the module from its FACT `region`; the AI can never choose it (a multi-region or other-region configuration).
    ("database-spanner", "config"): {
        "class": "HELD", "row": "RT14-36",
        "reason": "the platform sets the Spanner instance configuration to regional-<workload region> so the data "
                  "stays in the workload's region; omit config"},
}

RESOURCE_META_ARGUMENTS = frozenset({"count", "for_each", "provider", "provisioner", "connection", "lifecycle",
                                     "depends_on", "dynamic", "//"})
MODULE_META_ARGUMENTS = frozenset({"source", "version", "count", "for_each", "providers", "depends_on", "//"})
_COMPUTE_OUTPUTS = {"compute-cloudrun": frozenset({"service_uri", "service_name", "service_id"})}

# ------------------------------------------------------------------------------------------------ closed grammars
HclIdent = Annotated[str, StringConstraints(pattern=HCL_IDENT_PATTERN)]
ServiceName = Annotated[str, StringConstraints(pattern=SERVICE_NAME_PATTERN)]
ProviderType = Annotated[str, StringConstraints(pattern=PROVIDER_TYPE_PATTERN)]
ModuleId = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{1,62}$")]
FunctionName = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9]{1,30}$")]
ATTR_PATH_PATTERN = r"^[a-z_][a-z0-9_]*(\.[a-z_][a-z0-9_]*|\[[0-9]{1,4}\])*$"
AttrPath = Annotated[str, StringConstraints(pattern=ATTR_PATH_PATTERN)]
EXISTING_ADDRESS_PATTERN = (r"^(module\.[a-z][a-z0-9_]{0,62}|[a-z][a-z0-9_]{2,80}\.[a-z_][a-z0-9_-]{0,62})"
                            r"(\.[a-z_][a-z0-9_]*)*$")
# RT TI-2 F4: the first segment of an `existing` address is a module call or a provider resource type, never a
# reserved HCL root (a var./local./path./... "address" would render `${var.secret}` from a user-owned file).
EXISTING_RESERVED_ROOTS = frozenset({"var", "local", "locals", "path", "terraform", "self", "each", "count", "data",
                                     "output", "provider", "providers", "variable", "resource", "moved", "import",
                                     "ephemeral", "action", "check", "removed", "run"})


def _existing_root_ok(v: str) -> str:
    if v.split(".", 1)[0] in EXISTING_RESERVED_ROOTS:
        raise ValueError(f"{v.split('.', 1)[0]!r} is not a module or a resource type")
    return v


ExistingAddress = Annotated[str, StringConstraints(pattern=EXISTING_ADDRESS_PATTERN), AfterValidator(_existing_root_ok)]
# TI-3j: a Google API service name (closed grammar; membership in API_ONLY_SERVICES is the gate's typed check)
API_SERVICE_PATTERN = r"^[a-z][a-z0-9-]{0,62}\.googleapis\.com$"
ApiServiceName = Annotated[str, StringConstraints(pattern=API_SERVICE_PATTERN)]
_RE_ATTR_SEG = re.compile(r"\.?([a-z_][a-z0-9_]*)|\[([0-9]{1,4})\]")


class _M(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class _Aliased(BaseModel):
    """RT TI-2 F3: models whose wire names are aliases ($ref / $member / $fn / $args / schema) accept ONLY the alias,
    so {"ref": ...}, {"fn": ...}, {"member": ...} or "schema_id" stay plain data (or are refused), never synonyms."""
    model_config = ConfigDict(extra="forbid", populate_by_name=False, frozen=True)


class ModuleOutputRef(_M):
    kind: Literal["module_output"]
    module: HclIdent = Field(description="Name of a module instance in this intent")
    output: HclIdent = Field(description="One of that golden module's outputs")


class ResourceAttrRef(_M):
    kind: Literal["resource_attr"]
    type: ProviderType
    name: HclIdent
    attr: AttrPath = Field(description="Schema attribute path, e.g. id, name, push_config[0].push_endpoint")


class FactRef(_M):
    kind: Literal["fact"]
    fact: FactName  # type: ignore[valid-type]


class ServiceRef(_M):
    kind: Literal["service"]
    service: ServiceName
    output: Literal["service_uri", "service_name", "service_id"]


class ExistingRef(_M):
    kind: Literal["existing"]
    address: ExistingAddress = Field(description="Brownfield only: an exact address of a user-owned legacy file")


RefTarget = Annotated[Union[ModuleOutputRef, ResourceAttrRef, FactRef, ServiceRef, ExistingRef],
                      Field(discriminator="kind")]


class Ref(_Aliased):
    ref: RefTarget = Field(alias="$ref")


class MemberServiceAccount(_M):
    service_account: Ref


class MemberServiceAgent(_M):
    service_agent: ServiceAgentFact  # type: ignore[valid-type]


# GKE-WI-INTENT (ex04-1115b, register GKE-WI-INTENT): the Kubernetes service account a GKE pod runs as, as the member
# of a Workload Identity grant. Exact Kubernetes grammars: a namespace is an RFC 1123 label, a service account name an
# RFC 1123 DNS subdomain. Neither can hold `$`, `{`, `/`, `[` or `]`, so the rendered template
# "serviceAccount:${var.project_id}.svc.id.goog[<namespace>/<name>]" has no other interpolation and no other principal.
K8S_NAMESPACE_PATTERN = r"^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$"
K8S_SERVICE_ACCOUNT_PATTERN = r"^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$"
K8S_SERVICE_ACCOUNT_MAX = 253
# GKE-WI-INTENT: the one (type, role) a GKE member is valid on, and the golden compute module whose cluster creates the
# project's Workload Identity pool (<project_id>.svc.id.goog). The pool exists only once such a cluster exists, so the
# grant is rendered with depends_on on that cluster's compute module.
GKE_WI_RESOURCE_TYPE = "google_service_account_iam_member"
GKE_WI_ROLE = "roles/iam.workloadIdentityUser"
GKE_COMPUTE_MODULE_ID = "compute-gke-autopilot"
GKE_WI_POOL_SUFFIX = ".svc.id.goog"
GKE_WI_UNAVAILABLE_CODE = "IAC.GKE_WORKLOAD_IDENTITY_UNAVAILABLE"
GKE_WI_PAIRING_CODE = "IAC.GKE_WORKLOAD_IDENTITY_PAIRING"
GKE_WI_NAMESPACE_CODE = "IAC.GKE_WORKLOAD_IDENTITY_NAMESPACE"
# RT F6: the system namespaces the deploy never applies to (exact copy of mcp-servers/terraform/k8s_manifest_apply.py
# PROTECTED_NAMESPACES; parity: tests/test_gke_wi_intent_network.py). A grant to a KSA there is refused.
K8S_PROTECTED_NAMESPACES = frozenset({
    "kube-system", "kube-public", "kube-node-lease", "gke-managed-system", "gke-gmp-system", "gke-managed-cim",
    "gmp-system", "gmp-public", "config-management-system", "config-management-monitoring", "istio-system",
})


def gke_wi_hint(namespace: str = "<namespace>", name: str = "<Kubernetes service account>") -> str:
    """GKE-WI-INTENT: the exact intent entry that lets one Kubernetes service account act as a Google service account
    (the gate's hint, the IaC context line and V-K8S-WI's hint on an intent tree)."""
    entry = {"type": GKE_WI_RESOURCE_TYPE, "name": "<label>", "arguments": {
        "service_account_id": {"$ref": {"kind": "resource_attr", "type": "google_service_account",
                                        "name": "<the account>", "attr": "name"}},
        "role": GKE_WI_ROLE,
        "member": {"$member": {"gke_service_account": {"namespace": namespace, "name": name}}}}}
    return ("A GKE pod acts as a Google service account only through this exact entry: " + json.dumps(entry)
            + ". Use the namespace and name of the ServiceAccount in k8s/*.yaml whose iam.gke.io/gcp-service-account "
              "annotation names that account.")


GKE_WI_HINT = gke_wi_hint()


def gke_compute_modules(ctx: "IntentContext") -> Tuple[str, ...]:
    """GKE-WI-INTENT: the root module addresses of the topology's GKE Autopilot services (IntentContext.services,
    exact module id), sorted; () = the workload has no GKE cluster."""
    return tuple(sorted(addr for addr, mid in ctx.services.values() if mid == GKE_COMPUTE_MODULE_ID))


class GkeServiceAccount(_M):
    namespace: Annotated[str, StringConstraints(pattern=K8S_NAMESPACE_PATTERN)]
    name: Annotated[str, StringConstraints(pattern=K8S_SERVICE_ACCOUNT_PATTERN, max_length=K8S_SERVICE_ACCOUNT_MAX)]


class MemberGkeServiceAccount(_M):
    gke_service_account: GkeServiceAccount


class Member(_Aliased):
    """The ONLY way to write an IAM `member` (renders "serviceAccount:${...}")."""
    # GKE-WI-INTENT: a GKE member renders "serviceAccount:${var.project_id}.svc.id.goog[<namespace>/<name>]" (the
    # docstring above is the JSON schema's description: kept byte-identical)
    member: Union[MemberServiceAccount, MemberServiceAgent, MemberGkeServiceAccount] = Field(alias="$member")


class Call(_Aliased):
    fn: FunctionName = Field(alias="$fn")
    args: List["Value"] = Field(alias="$args")


Value = TypeAliasType("Value", Annotated[  # type: ignore[misc]
    Union[Ref, Member, Call, Dict[str, "Value"], List["Value"], StrictBool, StrictInt, StrictFloat, StrictStr, None],
    Field(union_mode="left_to_right")])
Call.model_rebuild()


class ModuleAddress(_M):
    module: HclIdent


class _ResourceKey(_M):
    type: ProviderType
    name: HclIdent


class ResourceAddress(_M):
    resource: _ResourceKey


IntentAddress = Union[ModuleAddress, ResourceAddress]


class Lifecycle(_M):
    prevent_destroy: Optional[StrictBool] = None
    ignore_changes: List[AttrPath] = Field(default_factory=list)


class ModuleInstance(_M):
    module: ModuleId = Field(description="An AI-instantiable golden module id from the catalog")
    name: HclIdent = Field(description="Rendered address module.<name>; unique in the intent")
    realizes: Optional[HclIdent] = Field(None, description="Topology resource logical_name this instance implements")
    args: Dict[str, Value] = Field(default_factory=dict)  # type: ignore[valid-type]


class ExtraResource(_M):
    type: ProviderType = Field(description="An allow-listed resource type")
    name: HclIdent
    realizes: Optional[HclIdent] = None
    arguments: Dict[str, Value] = Field(default_factory=dict)  # type: ignore[valid-type]
    lifecycle: Optional[Lifecycle] = None
    depends_on: List[IntentAddress] = Field(default_factory=list)


class IntentOutput(_M):
    name: HclIdent
    value: Ref
    description: Optional[Annotated[str, StringConstraints(max_length=300)]] = None


class ApiOnlyEntry(_M):
    """TI-3j: enable one allow-listed Google API (API_ONLY_SERVICES) and grant the workload service account that
    API's exact table role(s), with no infrastructure resource. The AI names the API only; the roles, the member
    (the platform's workload SA fact) and the addresses are platform data."""
    service: ApiServiceName = Field(description="An API of the API-only allow-list, e.g. aiplatform.googleapis.com")


class IacIntent(_Aliased):
    schema_id: Literal["iac_intent/v1"] = Field(alias="schema")
    modules: List[ModuleInstance] = Field(default_factory=list)
    resources: List[ExtraResource] = Field(default_factory=list)
    outputs: List[IntentOutput] = Field(default_factory=list)
    api_only: List[ApiOnlyEntry] = Field(default_factory=list)   # TI-3j (omitted from the canonical form when empty)


# ------------------------------------------------------------------------------------------------ API-only (TI-3j)
# Register TI-3j (owner 10-21): a spec may enable an allow-listed Google API plus its exact scoped workload role, with
# no infrastructure resource. EXACT table (additions by PR + test only, tests/test_ti3j_api_only.py): API -> address
# label and {exact predefined role -> address label}. Every role is granted to the workload runtime service account
# (the platform fact workload_sa_email) at project level; no admin / owner / editor role, no PRIVILEGED_ROLES member,
# no impersonation role. Each row's justification:
#   aiplatform  Gemini / Vertex AI online prediction from workload code (spec 07, service-coverage-1021 cat. d).
#               Vertex AI User is the documented role for generateContent / predict and is already on role_allow.
#   documentai  Document AI processDocument on an existing processor. Document AI API User is the process-only role
#               (no processor create / delete, unlike documentai.editor / admin).
#   speech      Speech-to-Text recognize. Cloud Speech Client is the recognize-only role of the v2 API (v1 checks no
#               role); speech.editor / admin also manage recognizers.
#   translate   Cloud Translation translateText. Cloud Translation API User is the call-only role (cloudtranslate
#               .editor / admin also manage glossaries and models).
#   vision, language, texttospeech (TI-3j-c, owner 10-25): ENABLE-ONLY rows (API_ONLY_ENABLE_ONLY). Cloud Vision,
#               Natural Language and Text-to-Speech have no predefined IAM role (read-only role check 11-07: `gcloud
#               iam roles list` finds none for language / texttospeech; for vision only roles/visionai.*, the separate
#               Vision AI product); a call needs only the API enabled in the project, so the row grants nothing.
# Not in the table (TI-3j-b, owner 10-25: later / no for now): compute / container without resources (enabling
# compute grants the default compute SA Editor unless the org policy iam.automaticIamGrantsForDefaultServiceAccounts
# holds).
# Rendered by the platform into RENDER_PATH (never by the AI; google_project_service stays not expressible as a type):
#   google_project_service.stackvend_api_<label> (disable_on_destroy = false, as the foundation's apis.tf) and one
#   google_project_iam_member.stackvend_api_<role label> per role, member = the workload SA fact, depending on it.
API_ONLY_SERVICES: Mapping[str, Mapping[str, Any]] = {
    "aiplatform.googleapis.com": {"label": "aiplatform", "roles": {"roles/aiplatform.user": "aiplatform_user"}},
    "documentai.googleapis.com": {"label": "documentai",
                                  "roles": {"roles/documentai.apiUser": "documentai_api_user"}},
    "speech.googleapis.com": {"label": "speech", "roles": {"roles/speech.client": "speech_client"}},
    "translate.googleapis.com": {"label": "translate",
                                 "roles": {"roles/cloudtranslate.user": "cloudtranslate_user"}},
    "vision.googleapis.com": {"label": "vision", "roles": {}},              # TI-3j-c: enable only
    "language.googleapis.com": {"label": "language", "roles": {}},          # TI-3j-c: enable only
    "texttospeech.googleapis.com": {"label": "texttospeech", "roles": {}},  # TI-3j-c: enable only
}
# TI-3j-c: the rows that grant no role (exactly these; any other row grants its exact role, tests/test_ti3j_api_only.py)
API_ONLY_ENABLE_ONLY: FrozenSet[str] = frozenset({"vision.googleapis.com", "language.googleapis.com",
                                                  "texttospeech.googleapis.com"})
API_ONLY_ADDRESS_PREFIX = "stackvend_api_"
API_ONLY_SERVICE_TYPE = "google_project_service"
API_ONLY_IAM_TYPE = "google_project_iam_member"
API_ONLY_ENTRY_PREFIX = "api_only."   # address of an api_only entry in diagnostics (block_address) and repairs
API_ONLY_DUPLICATE_GRANT = "IAC.DUPLICATE_GRANT"   # TI-3j-d: an AI grant an api_only entry already renders
__all__ += ["ApiOnlyEntry", "API_ONLY_SERVICES", "API_SERVICE_PATTERN", "API_ONLY_ENTRY_PREFIX", "api_only_addresses",
            "api_only_services", "api_only_resources", "API_ONLY_DUPLICATE_GRANT", "API_ONLY_ENABLE_ONLY"]


# OVERBROAD-SECRET-GRANT (owner 11-14, ex08-1114 §5.3): roles that AI-written (developer-owned) IaC may never grant at
# PROJECT level, whatever the member. A project-level secret role reaches every secret of the child project (the
# platform's own included); its compliant form is the same role on the one secret (google_secret_manager_secret_iam_
# member with secret_id = a Ref to that secret, or a golden database module's grant_workload_secret_access). A
# project-level IAM-admin role lets the workload rewrite who may act in the project; workload IaC never needs it.
# Exact role strings, compared with set membership (no substring / prefix matching). Disjoint from every role_allow
# table entry of a project-level type (tests/test_overbroad_secret_grant.py), so the finding is the reason, never a
# second code next to IAC.ROLE_NOT_ALLOWED. Platform-rendered grants (golden modules, api_only) are not AI-written and
# are not judged here. The classic HCL path applies the same table (validators/policy_tables, POLICY.PROJECT_WIDE_GRANT).
PROJECT_WIDE_GRANT_CODE = "IAC.PROJECT_WIDE_GRANT"
PROJECT_WIDE_GRANT_TYPES: FrozenSet[str] = frozenset({"google_project_iam_member", "google_project_iam_binding",
                                                     "google_project_iam_policy"})
PROJECT_WIDE_SECRET_ROLES: FrozenSet[str] = frozenset({
    "roles/secretmanager.secretAccessor", "roles/secretmanager.secretVersionManager",
    "roles/secretmanager.secretVersionAdder", "roles/secretmanager.admin",
})
PROJECT_WIDE_IAM_ADMIN_ROLES: FrozenSet[str] = frozenset({
    "roles/resourcemanager.projectIamAdmin", "roles/iam.securityAdmin", "roles/iam.roleAdmin",
    "roles/iam.serviceAccountAdmin", "roles/iam.serviceAccountKeyAdmin",
})
PROJECT_WIDE_DENIED_ROLES: FrozenSet[str] = PROJECT_WIDE_SECRET_ROLES | PROJECT_WIDE_IAM_ADMIN_ROLES
HINT_PROJECT_WIDE_SECRET = (
    "{role} at project level reaches every secret in the project. Grant an allowed role "
    "(roles/secretmanager.secretAccessor to read) on the one secret the workload reads: a "
    "google_secret_manager_secret_iam_member whose secret_id is a reference to that secret "
    "(google_secret_manager_secret.<name>.secret_id, or a security-secret module's secret_id); for a golden database "
    "module's password secret set grant_workload_secret_access = true on that module instead. Delete this "
    "project-level grant.")
HINT_PROJECT_WIDE_IAM_ADMIN = ("{role} at project level lets the workload change who can act in the project; "
                               "workload IaC never grants it. Delete this resource (and every reference to it).")
__all__ += ["PROJECT_WIDE_GRANT_CODE", "PROJECT_WIDE_GRANT_TYPES", "PROJECT_WIDE_SECRET_ROLES",
            "PROJECT_WIDE_IAM_ADMIN_ROLES", "PROJECT_WIDE_DENIED_ROLES", "project_wide_grant_hint"]


def project_wide_grant_hint(role: str) -> str:
    """The compliant alternative for a PROJECT_WIDE_DENIED_ROLES grant (exact table membership)."""
    tpl = HINT_PROJECT_WIDE_SECRET if role in PROJECT_WIDE_SECRET_ROLES else HINT_PROJECT_WIDE_IAM_ADMIN
    return tpl.format(role=role)


def _is_workload_sa_member(value: Any) -> bool:
    """TI-3j-d: the typed member is exactly the workload service account fact (the member api_only renders)."""
    m = value.member if isinstance(value, Member) else None
    ref = m.service_account.ref if isinstance(m, MemberServiceAccount) else None
    return isinstance(ref, FactRef) and ref.fact == "workload_sa_email"


def api_only_addresses(service: str) -> Tuple[str, ...]:
    """The root addresses the platform renders for one allow-listed API-only service (service first)."""
    return tuple(f"{t}.{n}" for t, n, _b in api_only_resources(service))


def api_only_resources(service: str, facts: Optional[Mapping[str, str]] = None
                       ) -> Tuple[Tuple[str, str, Dict[str, Any]], ...]:
    """(type, name, JSON-syntax body) of everything the platform renders for one allow-listed API-only service, from
    the table and the platform's own fact expressions only (default_facts() when `facts` is None). The renderer and
    the rendered-policy check (validators/iac_intent.py V-IAC-RENDER) share this one definition."""
    row = API_ONLY_SERVICES[service]
    facts = default_facts() if facts is None else facts
    project = "${" + facts["project_id"] + "}"
    svc_name = API_ONLY_ADDRESS_PREFIX + row["label"]
    out: List[Tuple[str, str, Dict[str, Any]]] = [
        (API_ONLY_SERVICE_TYPE, svc_name, {"project": project, "service": escape_template(service),
                                           "disable_on_destroy": False})]
    for role, label in sorted(row["roles"].items()):
        out.append((API_ONLY_IAM_TYPE, API_ONLY_ADDRESS_PREFIX + label, {
            "project": project, "role": escape_template(role),
            "member": "serviceAccount:${" + facts["workload_sa_email"] + "}",
            "depends_on": [f"{API_ONLY_SERVICE_TYPE}.{svc_name}"]}))
    return tuple(out)


def api_only_services(intent: Optional[IacIntent]) -> Tuple[str, ...]:
    """The allow-listed API-only services a (gate-clean) intent enables, sorted."""
    return tuple(sorted({e.service for e in (intent.api_only if intent is not None else ())
                         if e.service in API_ONLY_SERVICES}))


# ------------------------------------------------------------------------------------------------ artifacts
class IntentGateUnavailable(RuntimeError):
    """A required artifact (catalog, allow-list, schema slice, MANIFEST) is missing, malformed or inconsistent, or the
    validate service's provider versions differ from the slice. Class GATE_UNAVAILABLE: never a pass."""
    error_class = ErrorClass.GATE_UNAVAILABLE

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code


@dataclass(frozen=True)
class Artifacts:
    data_dir: str
    catalog: Mapping[str, Any]
    allowed: Mapping[str, Any]
    schema_slice: Mapping[str, Any]
    manifest: Mapping[str, Any]

    def answer(self, question: str) -> str:
        return str((self.allowed.get("owner_answers") or {}).get(question, {}).get("answer", ""))

    @property
    def allowed_types(self) -> Dict[str, Mapping[str, Any]]:
        """Types listed AND gated on an owner question answered `yes` (Q-TI-3/4/5 are data)."""
        return {t: spec for t, spec in (self.allowed.get("types") or {}).items()
                if self.answer(spec.get("question", "")) == "yes"}

    @property
    def functions(self) -> FrozenSet[str]:
        return frozenset((self.allowed.get("functions") or {}).get("allowed") or ())

    @property
    def ai_modules(self) -> Tuple[str, ...]:
        return tuple(self.catalog.get("ai_instantiable") or ())

    def module(self, module_id: str) -> Optional[Mapping[str, Any]]:
        return (self.catalog.get("modules") or {}).get(module_id) if module_id in self.ai_modules else None

    def resource_schema(self, rtype: str) -> Optional[Mapping[str, Any]]:
        entry = (self.schema_slice.get("resource_schemas") or {}).get(rtype)
        return entry.get("block") if entry else None

    def not_expressible_owner(self, rtype: str) -> Optional[str]:
        ne = self.allowed.get("not_expressible") or {}
        for owner in ("platform_owned", "forbidden", "topology_owned", "lane11_owned"):
            if rtype in (ne.get(owner) or ()):
                return owner
        if any(rtype.endswith(s) for s in ne.get("forbidden_type_suffixes") or ()):
            return "forbidden"
        return None


_ART_CACHE: Dict[str, Artifacts] = {}
_ART_LOCK = threading.Lock()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_artifacts(data_dir: Optional[str] = None) -> Artifacts:
    """The four artifacts (cached per directory). Missing / malformed / inconsistent -> IntentGateUnavailable."""
    d = os.path.abspath(data_dir or DATA_DIR)
    with _ART_LOCK:
        if d in _ART_CACHE:
            return _ART_CACHE[d]
        texts: Dict[str, str] = {}
        for name in ARTIFACT_FILES:
            path = os.path.join(d, name)
            try:
                with open(path, encoding="utf-8") as fh:
                    texts[name] = fh.read()
            except OSError as exc:
                raise IntentGateUnavailable("GATE.IAC_INTENT_ARTIFACT_MISSING", f"{path}: {exc.strerror or exc}")
        try:
            docs = {n: json.loads(t) for n, t in texts.items()}
        except ValueError as exc:
            raise IntentGateUnavailable("GATE.IAC_INTENT_ARTIFACT_MALFORMED", str(exc))
        catalog, allowed, sl, man = (docs["module_catalog.json"], docs["allowed_types.json"],
                                     docs["provider_schema_slice.json"], docs["MANIFEST"])
        ps, mc = man.get("provider_schema") or {}, man.get("module_catalog") or {}
        problems = []
        if sl.get("providers") != ps.get("providers") or sl.get("engine") != ps.get("engine"):
            problems.append("slice provider/engine versions differ from MANIFEST")
        if ps.get("provider_schema_slice_sha256") != _sha256_text(texts["provider_schema_slice.json"]):
            problems.append("provider_schema_slice.json sha256 differs from MANIFEST")
        if mc.get("sha256") != _sha256_text(texts["module_catalog.json"]):
            problems.append("module_catalog.json sha256 differs from MANIFEST")
        art = Artifacts(d, catalog, allowed, sl, man)
        missing = sorted(t for t in art.allowed_types if art.resource_schema(t) is None)
        if missing:
            problems.append(f"allow-listed types without a schema: {missing}")
        if problems:
            raise IntentGateUnavailable("GATE.IAC_INTENT_ARTIFACT_INCONSISTENT", "; ".join(problems))
        _ART_CACHE[d] = art
        return art


def check_ready_parity(art: Artifacts, ready_provider_versions: Optional[Mapping[str, Any]]) -> None:
    """Runtime parity (plan §2.5, RT F8): every slice provider version must be present in the validate service's
    `/validate/ready.provider_versions` ({"hashicorp/google": ["6.35.0", ...]}). Compared by VERSION (never by mirror
    sha, which differs per os_arch). A mismatch or an absent report is GATE_UNAVAILABLE."""
    if not isinstance(ready_provider_versions, Mapping):
        raise IntentGateUnavailable("GATE.IAC_SCHEMA_PARITY", "validate service reported no provider_versions")
    for prov, ver in sorted(((art.manifest.get("provider_schema") or {}).get("providers") or {}).items()):
        have = ready_provider_versions.get(prov)
        have = [have] if isinstance(have, str) else list(have or ())
        if ver not in have:
            raise IntentGateUnavailable("GATE.IAC_SCHEMA_PARITY", f"{prov} {ver} not served by validate (has {have})")


# ------------------------------------------------------------------------------------------------ context
_ADDR_RE = re.compile(r"^module\.[a-z][a-z0-9_]{0,62}$")
# platform-owned expressions (defense in depth); TI-5c: `/` for the Vertex network path format string
_FACT_EXPR_RE = re.compile(r'^[a-z][a-zA-Z0-9_.()",%@ :/-]*$')


def default_facts() -> Dict[str, str]:
    """The facts every golden root provides today (main.tf / variables.tf / the foundation module / FACTS_RENDER_PATH).
    Lane-11 facts are added by the caller when a network exists."""
    return {f: v["expr"] for f, v in FACTS.items() if v.get("expr")}


@dataclass(frozen=True)
class IntentContext:
    """Platform-side facts the gate checks the intent against (never LLM text)."""
    facts: Mapping[str, str] = field(default_factory=default_facts)
    services: Mapping[str, Tuple[str, str]] = field(default_factory=dict)        # name -> (module address, module id)
    topology_resources: Mapping[str, str] = field(default_factory=dict)          # logical_name -> resource type
    service_reads: Tuple[Tuple[str, str], ...] = ()                               # (service, logical) env bindings
    existing_addresses: FrozenSet[str] = frozenset()
    reserved_module_names: FrozenSet[str] = frozenset({"foundation", "compute"})
    platform_output_names: FrozenSet[str] = frozenset()
    # TI-3 merge gate (10-20): root addresses the platform reserves, e.g. the `from` side of its moved.tf (legacy
    # addresses moved into module.foundation). An intent entry there passes `validate` but fails `tofu plan`
    # ("Moved object still exists"): IAC.DUPLICATE_ADDRESS.
    reserved_addresses: FrozenSet[str] = frozenset()
    # TI-5c: a Cloud Run service of the topology consumes a private-network resource (Cloud SQL / Redis), so the
    # platform network render carries the VPC connector (on the IPAM connector fact). Needs the network facts.
    vpc_connector: bool = False
    # TI-5-F4: the workload holds the IPAM Private Services Access fact (var.psa_cidr), so the platform network takes
    # its PSA range from it instead of Google's automatic allocation. Needs the network facts.
    psa_range: bool = False
    # Catalog modules the intent path does not wire yet (NOT_YET_WIRED_MODULES, read when the context is built; empty
    # since TI-5-R2)
    unwired_modules: FrozenSet[str] = field(default_factory=lambda: NOT_YET_WIRED_MODULES)
    # TI5-ALLOYDB-SECRET-BIND (owner 10-27): logical_name -> the catalog attributes the services read (ValidatedTopology
    # .realization_needs). A realizing module instance that leaves a REALIZATION_REQUIRED_ARGS argument out gets the
    # table's literal from the renderer (e.g. grant_workload_secret_access = true when the password secret id is bound).
    topology_attributes: Mapping[str, Tuple[str, ...]] = field(default_factory=dict)
    # SECRET-INITIAL-VERSION (owner 11-10): logical_name -> the architect's stated initial_value ("random" /
    # "operator") of the topology's secrets that state one (an absent value is not listed), and the secrets that get the
    # platform's random first version in this run (developer_agent.iac_intent_contract.secret_generation: stated
    # "random" and new to the repository, or already generated). Both empty = the gate and render are as before.
    secret_initial_values: Mapping[str, str] = field(default_factory=dict)
    generated_secrets: FrozenSet[str] = frozenset()

    def __post_init__(self) -> None:
        for f, expr in self.facts.items():
            if f not in FACTS or not isinstance(expr, str) or not _FACT_EXPR_RE.match(expr) or "${" in expr:
                raise ValueError(f"invalid platform fact {f!r}")
        if self.vpc_connector and "network" not in self.facts:
            raise ValueError("vpc_connector needs the platform network facts")
        if self.psa_range and "network" not in self.facts:
            raise ValueError("psa_range needs the platform network facts")
        for s, (addr, _mid) in self.services.items():
            if not re.match(SERVICE_NAME_PATTERN, s) or not _ADDR_RE.match(addr):
                raise ValueError(f"invalid service binding {s!r} -> {addr!r}")
        for logical, value in self.secret_initial_values.items():   # SECRET-INITIAL-VERSION
            if self.topology_resources.get(logical) != SECRET_RESOURCE_TYPE or value not in INITIAL_VALUES:
                raise ValueError(f"invalid secret initial value {logical!r} -> {value!r}")
        for logical in self.generated_secrets:
            if self.topology_resources.get(logical) != SECRET_RESOURCE_TYPE:
                raise ValueError(f"generated secret {logical!r} is not a topology secret")


# ------------------------------------------------------------------------------------------------ diagnostics
def _diag(code: str, path: str, message: str, *, hint: Optional[str] = None, tool: str = "schema",
          cls: ErrorClass = ErrorClass.CODE_DEFECT, block: Optional[str] = None,
          symbol: Optional[str] = None) -> Diagnostic:
    # TI-3: `symbol` names the topology resource of a realization finding, so two such findings at "/" keep distinct
    # fingerprints (shared.diagnostics.fingerprint) in the repair loop
    return Diagnostic(tool=tool, code=code, severity="error", error_class=cls, file=_FILE, attribute_path=path or "/",
                      block_address=block, symbol=symbol, message=message, hint=hint, source="precommit")


def _ptr(*parts: Any) -> str:
    return "".join("/" + str(p).replace("~", "~0").replace("/", "~1") for p in parts)


# ------------------------------------------------------------------------------------------------ type constraints
_TYPE_TOKEN = re.compile(r"\s*(\w+|[(){}\[\]=,])")


def parse_type_constraint(text: str) -> Any:
    """HCL type constraint (variables.tf `type`) -> the provider schema's cty JSON shape ("string", ["list", T], ...).
    `any` -> "dynamic". A closed recursive-descent grammar; raises ValueError on anything else."""
    toks = [m.group(1) for m in _TYPE_TOKEN.finditer(text or "")]
    if "".join(toks) != re.sub(r"\s+", "", text or ""):
        raise ValueError(f"unparseable type constraint {text!r}")
    pos = 0

    def take(expect: Optional[str] = None) -> str:
        nonlocal pos
        if pos >= len(toks) or (expect is not None and toks[pos] != expect):
            raise ValueError(f"type constraint {text!r}: expected {expect!r}")
        pos += 1
        return toks[pos - 1]

    def ty() -> Any:
        name = take()
        if name in ("string", "number", "bool"):
            return name
        if name == "any":
            return "dynamic"
        if name in ("list", "set", "map"):
            take("(")
            inner = ty()
            take(")")
            return [name, inner]
        if name == "optional":
            take("(")
            inner = ty()
            if toks[pos] == ",":          # optional(T, default)
                raise ValueError("optional() defaults are not supported in the catalog")
            take(")")
            return inner
        if name == "tuple":
            take("(")
            take("[")
            items = []
            while toks[pos] != "]":
                items.append(ty())
                if toks[pos] == ",":
                    take(",")
            take("]")
            take(")")
            return ["tuple", items]
        if name == "object":
            take("(")
            take("{")
            fields: Dict[str, Any] = {}
            while toks[pos] != "}":
                key = take()
                take("=")
                fields[key] = ty()
                if toks[pos] == ",":
                    take(",")
            take("}")
            take(")")
            return ["object", fields]
        raise ValueError(f"unknown type {name!r} in {text!r}")

    out = ty()
    if pos != len(toks):
        raise ValueError(f"trailing tokens in type constraint {text!r}")
    return out


def _is_expr(v: Any) -> bool:
    return isinstance(v, (Ref, Member, Call))


def _contains_expr(v: Any) -> bool:
    if _is_expr(v):
        return True
    if isinstance(v, dict):
        return any(_contains_expr(x) for x in v.values())
    if isinstance(v, list):
        return any(_contains_expr(x) for x in v)
    return False


def _num_string(s: str) -> bool:
    try:
        float(s)
        return True
    except ValueError:
        return False


def _cty_accepts(ty: Any, v: Any) -> bool:
    """Literal `v` converts to cty type `ty` under OpenTofu's conversion rules (lenient: only definite mismatches
    are False; an expression is never judged here)."""
    if v is None or _contains_expr(v) or ty == "dynamic":
        return True
    if ty == "string":
        return isinstance(v, (str, bool, int, float))
    if ty == "number":
        return (isinstance(v, (int, float)) and not isinstance(v, bool)) or (isinstance(v, str) and _num_string(v))
    if ty == "bool":
        return isinstance(v, bool) or v in ("true", "false")
    if isinstance(ty, list) and ty:
        kind = ty[0]
        if kind in ("list", "set"):
            return isinstance(v, list) and all(_cty_accepts(ty[1], x) for x in v)
        if kind == "map":
            return isinstance(v, dict) and all(_cty_accepts(ty[1], x) for x in v.values())
        if kind == "object":
            fields = ty[1] if len(ty) > 1 and isinstance(ty[1], dict) else {}
            return isinstance(v, dict) and all(k in fields and _cty_accepts(fields[k], x) for k, x in v.items())
        if kind == "tuple":
            items = ty[1] if len(ty) > 1 else []
            return isinstance(v, list) and len(v) == len(items) and all(_cty_accepts(t, x) for t, x in zip(items, v))
    return True


def _type_label(ty: Any) -> str:
    return ty if isinstance(ty, str) else json.dumps(ty, separators=(",", ":"))


# ------------------------------------------------------------------------------------------------ gate
@dataclass(frozen=True)
class ValidatedIntent:
    """Only `validate_intent` constructs this (token guard): the renderer's public entry accepts nothing else."""
    intent: IacIntent
    artifacts: Artifacts
    context: IntentContext
    sha256: str
    _token: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        if self._token is not _TOKEN:
            raise TypeError("ValidatedIntent is constructed only by validate_intent")


_TOKEN = object()


@dataclass(frozen=True)
class GateResult:
    diagnostics: Tuple[Diagnostic, ...]
    intent: Optional[IacIntent]
    validated: Optional[ValidatedIntent]

    @property
    def ok(self) -> bool:
        return self.validated is not None

    @property
    def codes(self) -> Tuple[str, ...]:
        return tuple(sorted({d.code for d in self.diagnostics}))


def canonical_intent_json(intent: IacIntent) -> str:
    doc = intent.model_dump(mode="json", by_alias=True)
    if not doc.get("api_only"):   # TI-3j: an intent without API-only entries keeps its pre-TI-3j sha256
        doc.pop("api_only", None)
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def intent_sha256(intent: IacIntent) -> str:
    return _sha256_text(canonical_intent_json(intent))


_RESERVED_KEY_FORMS = {"$ref": Ref, "$member": Member, "$fn": Call, "$args": Call}


def _key_problem(key: str) -> Optional[str]:
    if key.startswith("$"):
        return "keys starting with '$' are reserved for $ref / $member / $fn"
    if "${" in key or "%{" in key:
        return "keys cannot contain '${' or '%{' (no templated keys)"
    if key == "//":
        return "'//' is reserved (comment key)"
    return None


class _Gate:
    def __init__(self, intent: IacIntent, art: Artifacts, ctx: IntentContext):
        self.i, self.art, self.ctx = intent, art, ctx
        self.diags: List[Diagnostic] = []
        self.modules = {m.name: m for m in intent.modules}
        self.resources = {(r.type, r.name): r for r in intent.resources}
        self.edges: Set[Tuple[str, str]] = set()
        self.allowed = art.allowed_types

    def add(self, *a: Any, **k: Any) -> None:
        self.diags.append(_diag(*a, **k))

    # ---------------------------------------------------------------------------- PUSH-SUB-RENDER
    def module_node(self, name: str, output: Optional[str] = None) -> str:
        """The cycle-check node of module.<name> (or of one of its outputs): a messaging-pubsub instance with `push`
        is two nodes, its topic part (module.<name>) and its push subscription (module.<name>.push, which depends on
        the topic part and on the pushed-to service). Every other module, and a module without `push`, is one node."""
        m = self.modules.get(name)
        if m is not None and _has_push(m) and (output is None or output in PUSH_SUBSCRIPTION_OUTPUTS):
            return push_node(name)
        return "module." + name

    def push_arg(self, n: int, m: ModuleInstance, val: Any, p: str) -> None:
        """PUSH-SUB-RENDER (owner 10-28): the closed `push` form of a messaging-pubsub instance. Its references are
        resolved from the push node (module.<name>.push), so the service it pushes to may itself read the topic."""
        if not (isinstance(val, dict) and set(val) == set(PUSH_ARG_KEYS)):
            self.add("IAC.PUSH_INVALID", p, "push is exactly " + PUSH_FORM_TEXT,
                     hint="The platform renders the push endpoint, the OIDC token and its audience from these three.")
            return
        self.values(val, p, push_node(m.name))   # unknown service / resource / fact -> its typed finding
        svc = val["service"]
        if not (isinstance(svc, Ref) and isinstance(svc.ref, ServiceRef) and svc.ref.output == "service_uri"):
            self.add("IAC.PUSH_INVALID", _ptr_join(p, "service"),
                     'push.service is a service Ref: {"$ref": {"kind": "service", "service": "<topology service>", '
                     '"output": "service_uri"}}')
        elif svc.ref.service in self.ctx.services and self.ctx.services[svc.ref.service][1] != PUSH_IDENTITY_MODULE:
            self.add("IAC.PUSH_TARGET_NOT_ALLOWED", _ptr_join(p, "service"),
                     f"service {svc.ref.service!r} is a {self.ctx.services[svc.ref.service][1]}: push goes only to a "
                     f"{PUSH_IDENTITY_MODULE} service of this workload")
        path = val["path"]
        if not push_path_ok(path):
            self.add("IAC.PUSH_INVALID", _ptr_join(p, "path"),
                     "push.path is a literal URL path that starts with / (e.g. \"/api/v1/tasks/process\"; letters, "
                     "digits and ._~!&'()*+,;=/- only; no empty, \".\" or \"..\" segment)")
        email = val["service_account_email"]
        if not (isinstance(email, Ref) and not isinstance(email.ref, ExistingRef)
                and _target_ok(email, PUSH_IDENTITY_SHAPES, self.modules, self.ctx)):
            self.add("IAC.TARGET_REF_REQUIRED", _ptr_join(p, "service_account_email"),
                     "push.service_account_email signs the push token: it takes only a Ref to the fact "
                     "workload_sa_email or to google_service_account.<name>.email of this intent")
        if m.args.get("enable_subscription", True) is False:
            self.add("IAC.PUSH_INVALID", _ptr("modules", n, "args", "enable_subscription"),
                     "push needs the module's subscription: omit enable_subscription (or set it to true)")

    # ---------------------------------------------------------------------------- S0b: reserved keys / finiteness
    def scan_values(self, v: Any, path: str) -> None:
        if isinstance(v, dict):
            for k, x in v.items():
                prob = _key_problem(k)
                if prob:
                    form = _RESERVED_KEY_FORMS.get(k)
                    detail = None
                    if form is not None:
                        try:
                            form.model_validate(v)
                        except ValidationError as exc:
                            detail = "; ".join(f"{_loc(e['loc'])}: {e['msg']}" for e in exc.errors()[:5])
                    self.add("IAC.RESERVED_KEY", _ptr_join(path, k),
                             f"invalid object key {k!r}: {prob}" + (f" (malformed {k} form: {detail})" if detail else ""),
                             hint='A reference is {"$ref": {"kind": ..., ...}}, a member {"$member": {...}}, '
                                  'a function call {"$fn": name, "$args": [...]}.')
                self.scan_values(x, _ptr_join(path, k))
        elif isinstance(v, list):
            for n, x in enumerate(v):
                self.scan_values(x, _ptr_join(path, n))
        elif isinstance(v, float) and not math.isfinite(v):
            self.add("IAC.INVALID_VALUE", path, "non-finite number")
        elif isinstance(v, Call):
            for n, x in enumerate(v.args):
                self.scan_values(x, _ptr_join(path, "$args", n))
        elif isinstance(v, Member) and isinstance(v.member, MemberServiceAccount):
            pass

    # ---------------------------------------------------------------------------- refs
    def ref(self, r: Ref, path: str, src: str) -> Optional[Dict[str, Any]]:
        """Resolve one Ref; record its edge; return {sensitive, sa} or None (diagnostic added)."""
        t = r.ref
        if isinstance(t, ModuleOutputRef):
            m = self.modules.get(t.module)
            if m is None:
                self.add("IAC.UNKNOWN_REFERENCE", path, f"no module instance named {t.module!r} in the intent")
                return None
            cat = self.art.module(m.module)
            outs = (cat or {}).get("outputs") or {}
            if t.output not in outs:
                self.add("IAC.UNKNOWN_OUTPUT", path, f"golden module {m.module!r} has no output {t.output!r}",
                         hint="outputs: " + ", ".join(sorted(outs)))
                return None
            self.edges.add((src, self.module_node(t.module, t.output)))   # PUSH-SUB-RENDER: per output part
            return {"sensitive": bool(outs[t.output].get("sensitive")), "module_id": m.module}
        if isinstance(t, ResourceAttrRef):
            if (t.type, t.name) not in self.resources:
                self.add("IAC.UNKNOWN_REFERENCE", path, f"no resource {t.type}.{t.name} in the intent")
                return None
            block = self.art.resource_schema(t.type)
            if block is None:
                return None   # the TYPE_NOT_ALLOWED diagnostic is on the resource itself
            sens = self.attr_path(block, t.attr, path, t.type)
            if sens is None:
                return None
            self.edges.add((src, f"{t.type}.{t.name}"))
            return {"sensitive": sens, "sa": t.type == "google_service_account" and t.attr == "email"}
        if isinstance(t, FactRef):
            if t.fact not in self.ctx.facts:
                self.add("FACT.MISSING", path, f"fact {t.fact!r} is not available in this workload",
                         tool="facts", cls=ErrorClass.PLATFORM_DEFECT)
                return None
            return {"sensitive": False, "sa": bool(FACTS[t.fact].get("service_account")), "fact": t.fact}
        if isinstance(t, ServiceRef):
            svc = self.ctx.services.get(t.service)
            if svc is None:
                self.add("IAC.UNKNOWN_REFERENCE", path, f"no topology service named {t.service!r}",
                         hint="services: " + ", ".join(sorted(self.ctx.services)))
                return None
            outs = _COMPUTE_OUTPUTS.get(svc[1], frozenset())
            if t.output not in outs:
                self.add("IAC.UNKNOWN_OUTPUT", path, f"service {t.service!r} ({svc[1]}) has no output {t.output!r}")
                return None
            self.edges.add((src, "service." + t.service))
            return {"sensitive": False, "service_output": t.output}
        if isinstance(t, ExistingRef):
            base = _existing_base(t.address)
            if base not in self.ctx.existing_addresses:
                self.add("IAC.UNKNOWN_REFERENCE", path, f"{t.address!r} is not an address of a user-owned file")
                return None
            return {"sensitive": False}
        return None  # pragma: no cover

    def attr_path(self, block: Mapping[str, Any], attr: str, path: str, rtype: str) -> Optional[bool]:
        """Walk `attr` through the schema (RT F6: [i] only on nesting_mode list blocks / list attributes)."""
        segs = [(m.group(1), m.group(2)) for m in _RE_ATTR_SEG.finditer(attr)]
        cur_block: Optional[Mapping[str, Any]] = block
        cur_type: Any = None
        need_index: Optional[str] = None
        sensitive = False
        for name, idx in segs:
            if idx is not None:
                if need_index == "list" or (isinstance(cur_type, list) and cur_type[0] in ("list", "tuple")):
                    need_index = None
                    if isinstance(cur_type, list) and cur_type[0] == "list":
                        cur_type = cur_type[1]
                    continue
                if need_index == "set" or (isinstance(cur_type, list) and cur_type[0] == "set"):
                    self.add("IAC.NOT_INDEXABLE", path, f"{rtype}.{attr}: a set cannot be indexed",
                             hint="Reference a single-valued attribute instead; set elements have no index.")
                    return None
                self.add("IAC.NOT_INDEXABLE", path, f"{rtype}.{attr}: this value has no index")
                return None
            if need_index:
                self.add("IAC.INDEX_REQUIRED" if need_index == "list" else "IAC.NOT_INDEXABLE", path,
                         f"{rtype}.{attr}: block is a {need_index}; " +
                         ("index it, e.g. [0]" if need_index == "list" else "a set block cannot be traversed"))
                return None
            if cur_type is not None:
                if cur_type == "dynamic" or (isinstance(cur_type, list) and cur_type[0] == "map"):
                    cur_type = "dynamic" if cur_type == "dynamic" else cur_type[1]
                    continue
                if isinstance(cur_type, list) and cur_type[0] == "object" and name in (cur_type[1] or {}):
                    cur_type = cur_type[1][name]
                    continue
                self.add("IAC.UNKNOWN_ATTRIBUTE", path, f"{rtype}.{attr}: {name!r} is not an attribute here")
                return None
            if cur_block is None:  # pragma: no cover
                return None
            attrs, blocks = cur_block.get("attributes") or {}, cur_block.get("block_types") or {}
            if name in attrs:
                a = attrs[name]
                sensitive = sensitive or bool(a.get("sensitive"))
                cur_type = a.get("type", "dynamic")
                if isinstance(cur_type, list) and cur_type and cur_type[0] == "nested_type":
                    cur_type = "dynamic"
                cur_block = None
            elif name in blocks:
                b = blocks[name]
                mode = b.get("nesting_mode")
                cur_block = b.get("block") or {}
                need_index = "list" if mode == "list" else ("set" if mode == "set" else None)
            else:
                self.add("IAC.UNKNOWN_ATTRIBUTE", path, f"{rtype} has no attribute {attr!r}",
                         hint="attributes: " + ", ".join(sorted(attrs)[:40]))
                return None
        if need_index == "list" or (cur_block is not None and cur_type is None and segs):
            # a whole block (object / list of objects) is a legal value; nothing more to check
            return sensitive
        return sensitive

    def values(self, v: Any, path: str, src: str, *, member_ok: bool = False) -> None:
        """Walk a value: resolve every Ref, check every Call function, and refuse a Member outside `member`."""
        if isinstance(v, Ref):
            self.ref(v, path, src)
        elif isinstance(v, Member):
            if not member_ok:
                self.add("IAC.MEMBER_NOT_ALLOWED_HERE", path, "a $member is only valid as the `member` of an IAM type")
                return
            m = v.member
            if isinstance(m, MemberServiceAccount):
                info = self.ref(m.service_account, _ptr_join(path, "$member", "service_account"), src)
                t = m.service_account.ref
                if isinstance(t, ExistingRef):
                    parts = t.address.split(".")
                    if info is not None and not (len(parts) == 3 and parts[0] == "google_service_account"
                                                 and parts[2] == "email"):
                        self.add("IAC.MEMBER_NOT_SERVICE_ACCOUNT", path, "an existing service-account reference "
                                 "must be exactly google_service_account.<name>.email")
                elif info is not None and not info.get("sa"):
                    self.add("IAC.MEMBER_NOT_SERVICE_ACCOUNT", path,
                             "service_account must reference the workload SA fact or a google_service_account .email")
            elif isinstance(m, MemberGkeServiceAccount):
                # GKE-WI-INTENT: where it may appear (type + role) is checked by iam(); here: a GKE cluster exists
                if not gke_compute_modules(self.ctx):
                    self.add(GKE_WI_UNAVAILABLE_CODE, path,
                             "a gke_service_account member needs a GKE Autopilot service in this workload's topology "
                             "(its cluster creates the Workload Identity pool)",
                             hint="Remove this entry: the workload has no GKE cluster.")
                if m.gke_service_account.namespace in K8S_PROTECTED_NAMESPACES:
                    self.add(GKE_WI_NAMESPACE_CODE, _ptr_join(path, "$member", "gke_service_account", "namespace"),
                             f"namespace {m.gke_service_account.namespace!r} is a system namespace the platform never "
                             "deploys to", hint="Use the namespace of the workload's own ServiceAccount manifest.")
            elif m.service_agent not in self.ctx.facts:
                self.add("FACT.MISSING", path, f"fact {m.service_agent!r} is not available", tool="facts",
                         cls=ErrorClass.PLATFORM_DEFECT)
        elif isinstance(v, Call):
            if v.fn not in self.art.functions:
                self.add("IAC.FUNCTION_NOT_ALLOWED", path, f"function {v.fn!r} is not in the v1 Call set",
                         hint="allowed: " + ", ".join(sorted(self.art.functions)))
            for n, x in enumerate(v.args):
                self.values(x, _ptr_join(path, "$args", n), src)
        elif isinstance(v, dict):
            for k, x in v.items():
                self.values(x, _ptr_join(path, k), src)
        elif isinstance(v, list):
            for n, x in enumerate(v):
                self.values(x, _ptr_join(path, n), src)

    # ---------------------------------------------------------------------------- S1
    def names(self) -> None:
        seen: Dict[str, str] = {}
        for n, m in enumerate(self.i.modules):
            p, addr = _ptr("modules", n, "name"), "module." + m.name
            if m.name in self.ctx.reserved_module_names or m.name.startswith("compute_") or (
                    addr in self.ctx.reserved_addresses) or m.name in (PLATFORM_NETWORK_MODULE,   # TI-5c
                                                                       PLATFORM_CONNECTOR_MODULE):   # FD-4BH
                self.add("IAC.DUPLICATE_ADDRESS", p, f"module.{m.name} is a platform-rendered address")
            if addr in seen:
                self.add("IAC.DUPLICATE_ADDRESS", p, f"{addr} is declared twice (also at {seen[addr]})")
            seen.setdefault(addr, p)
        for n, r in enumerate(self.i.resources):
            p, addr = _ptr("resources", n, "name"), f"{r.type}.{r.name}"
            if addr in seen:
                self.add("IAC.DUPLICATE_ADDRESS", p, f"{addr} is declared twice (also at {seen[addr]})")
            if addr in self.ctx.existing_addresses:
                self.add("IAC.DUPLICATE_ADDRESS", p, f"{addr} is already declared in a user-owned file",
                         hint='Reference it with {"$ref": {"kind": "existing", "address": ...}} instead.')
            if addr in self.ctx.reserved_addresses:
                self.add("IAC.DUPLICATE_ADDRESS", p, f"{addr} is an address the platform reserves (its moved.tf "
                         "moves it into module.foundation, which already declares it)",
                         hint="Remove this entry: the workload foundation already provides it (for example the "
                              "workload service account's Firestore, Logging, Pub/Sub publisher and Storage object "
                              "grants). If a different resource is needed, give it another name.")
            seen.setdefault(addr, p)
        outs: Dict[str, str] = {}
        for n, o in enumerate(self.i.outputs):
            p = _ptr("outputs", n, "name")
            if o.name in outs or o.name in self.ctx.platform_output_names:
                self.add("IAC.DUPLICATE_ADDRESS", p, f"output {o.name!r} is declared twice or by the platform")
            outs.setdefault(o.name, p)

    def realization(self) -> None:
        by: Dict[str, List[Tuple[str, str]]] = {}
        entries = [(_ptr("modules", n), m.realizes, None, m.module) for n, m in enumerate(self.i.modules)]
        entries += [(_ptr("resources", n), r.realizes, r.type, None) for n, r in enumerate(self.i.resources)]
        for p, logical, rtype, mid in entries:
            if logical is None:
                continue
            want = self.ctx.topology_resources.get(logical)
            if want is None:
                self.add("IAC.UNKNOWN_REALIZATION", p + "/realizes", f"no topology resource named {logical!r}",
                         symbol=logical)
                continue
            by.setdefault(logical, []).append((p, logical))
            declares = set(((self.art.module(mid) or {}).get("declares_types") or ())) if mid else {rtype}
            if want not in declares:
                self.add("IAC.REALIZATION_TYPE_MISMATCH", p + "/realizes",
                         f"topology resource {logical!r} is a {want}; this entry does not declare one", symbol=logical)
        for logical in sorted(self.ctx.topology_resources):
            hits = by.get(logical, [])
            if not hits:
                self.add("IAC.TOPOLOGY_RESOURCE_UNREALIZED", "/",
                         f"topology resource {logical!r} ({self.ctx.topology_resources[logical]}) has no intent entry "
                         "with realizes = that name", symbol=logical)
            elif len(hits) > 1:
                self.add("IAC.DUPLICATE_REALIZATION", hits[1][0] + "/realizes",
                         f"topology resource {logical!r} is realized more than once", symbol=logical)

    # ---------------------------------------------------------------------------- SECRET-INITIAL-VERSION
    def secret_values(self) -> None:
        """The first version of a topology secret whose plan states initial_value belongs to the platform (random) or
        to an operator: (1) a secret that gets the platform's random version is realized by a GENERATED_SECRET_MODULE
        instance (the module renders it); (2) no intent version resource (GENERATED_SECRET_VERSION_TYPE) writes to such
        a secret. Typed Ref targets only (the realizing entry's module / resource name), never names or values. No
        stated value -> no finding (the gate is as before)."""
        if not self.ctx.secret_initial_values and not self.ctx.generated_secrets:
            return
        realizing: Dict[Tuple[str, str], str] = {}   # ("module", name) / (type, name) -> realized logical name
        for n, m in enumerate(self.i.modules):
            if m.realizes:
                realizing[("module", m.name)] = m.realizes
                if m.realizes in self.ctx.generated_secrets and m.module != GENERATED_SECRET_MODULE:
                    self.add("IAC.SECRET_REALIZATION_MODULE_REQUIRED", _ptr("modules", n, "module"),
                             f"topology secret {m.realizes!r} gets the platform's random first version, which only "
                             f"the golden module {GENERATED_SECRET_MODULE} renders", symbol=m.realizes,
                             hint=f"Realize it with the golden module {GENERATED_SECRET_MODULE}.")
        for n, r in enumerate(self.i.resources):
            if r.realizes:
                realizing[(r.type, r.name)] = r.realizes
                if r.realizes in self.ctx.generated_secrets:
                    self.add("IAC.SECRET_REALIZATION_MODULE_REQUIRED", _ptr("resources", n, "realizes"),
                             f"topology secret {r.realizes!r} gets the platform's random first version, which only "
                             f"the golden module {GENERATED_SECRET_MODULE} renders", symbol=r.realizes,
                             hint=f"Replace this resource with a {GENERATED_SECRET_MODULE} module instance that "
                                  f"realizes {r.realizes!r}.")
        stated = set(self.ctx.secret_initial_values) | set(self.ctx.generated_secrets)
        for n, r in enumerate(self.i.resources):
            if r.type != GENERATED_SECRET_VERSION_TYPE:
                continue
            target = r.arguments.get("secret")
            t = target.ref if isinstance(target, Ref) else None
            if isinstance(t, ModuleOutputRef):
                logical = realizing.get(("module", t.module))
            elif isinstance(t, ResourceAttrRef):
                logical = realizing.get((t.type, t.name))
            else:
                logical = None
            if logical in stated:
                who = ("the platform creates its random first version"
                       if logical in self.ctx.generated_secrets else "an operator adds its value")
                self.add("IAC.SECRET_VERSION_PLATFORM_OWNED", _ptr("resources", n, "arguments", "secret"),
                         f"topology secret {logical!r} gets no version from the intent: {who}", symbol=logical,
                         hint="Remove this secret version (and a random_password used only by it).")

    # ---------------------------------------------------------------------------- S2/S3 modules
    def module_entry(self, n: int, m: ModuleInstance) -> None:
        base, src = _ptr("modules", n), "module." + m.name
        cat = self.art.module(m.module)
        if cat is None:
            self.add("IAC.MODULE_UNKNOWN", base + "/module", f"{m.module!r} is not an AI-instantiable golden module",
                     hint="modules: " + ", ".join(self.art.ai_modules))
            return
        cvars = cat.get("variables") or {}
        for key, val in m.args.items():
            p = _ptr("modules", n, "args", key)
            var = cvars.get(key)
            if key in MODULE_META_ARGUMENTS:
                self.add("IAC.META_ARGUMENT_NOT_ALLOWED", p, f"{key!r} cannot be set on a module instance")
                continue
            if var is None:
                self.add("IAC.UNKNOWN_ARGUMENT", p, f"golden module {m.module!r} has no variable {key!r}",
                         hint="variables: " + ", ".join(sorted(k for k, v in cvars.items() if v["class"] in
                                                               ("AI", "REF_ONLY", "PUSH"))))
                continue
            cls = var["class"]
            if cls == "FACT":
                self.add("IAC.PLATFORM_OWNED_ARGUMENT", p, f"{key!r} is rendered by the platform (fact {var['fact']})")
                continue
            if cls == "SECRET":
                self.add("IAC.SECRET_ARGUMENT", p, f"{key!r} is a secret: the platform/module generates it")
                continue
            if cls == "TOPOLOGY":   # SECRET-INITIAL-VERSION: decided by the architect's plan, rendered by the platform
                self.add("IAC.PLATFORM_OWNED_ARGUMENT", p,
                         f"{key!r} is rendered by the platform from the plan's service topology ({var['topology']})",
                         hint=f"Remove {key!r} from this module instance.")
                continue
            if cls == "HELD":   # TI-5-G3b: not available until the named register row lands
                self.add("IAC.ARGUMENT_HELD", p, f"{m.module}.{key} is not available yet ({var['row']}): "
                         + var["reason"], hint=f"Remove {key!r} from this module instance.")
                continue
            if cls == "PUSH":   # PUSH-SUB-RENDER: the closed push form (its own refs, cycle node and findings)
                self.push_arg(n, m, val, p)
                continue
            self.values(val, p, src)
            if not var.get("sensitive") and self.sensitive_refs(val):      # RT TI-2b R1 (F7 for module variables)
                self.add("IAC.SENSITIVE_IN_PLAIN_ATTRIBUTE", p,
                         f"{m.module}.{key} is not a sensitive variable: a secret value (e.g. random_password.result) "
                         "would be shown in plans and state as plain text")
                continue
            if cls == "REF_ONLY":
                if not isinstance(val, Ref):
                    self.add("IAC.REF_REQUIRED", p, f"{key!r} takes a reference of: {', '.join(var['refs'])}")
                elif not _ref_kind_ok(val, var["refs"], self.modules):
                    self.add("IAC.REF_KIND_NOT_ALLOWED", p, f"{key!r} takes a reference of: {', '.join(var['refs'])}")
                continue
            allowed_values = var.get("allowed_values")
            if allowed_values is not None:
                shown = ", ".join(json.dumps(a) if not isinstance(a, str) else a for a in allowed_values)
                if _contains_expr(val):
                    self.add("IAC.LITERAL_REQUIRED", p, f"{key!r} must be a literal, one of: " + shown)
                elif not any(type(val) is type(a) and val == a for a in allowed_values):   # type-exact (0 != false)
                    self.add("IAC.INVALID_VALUE", p, f"{key!r} must be one of: " + shown,
                             hint=_ALLOWED_VALUES_HINT.get(key))
                continue
            if var.get("count_driver") and _contains_expr(val):
                self.add("IAC.LITERAL_REQUIRED", p,
                         f"{key!r} decides how many resources the module creates, so it must be a literal "
                         "(known at plan time)")
                continue
            allowed_items = var.get("allowed_items")   # TI-5-G3b: exact item set of a literal list
            if allowed_items is not None and isinstance(val, list):
                bad = [x for x in val if not (isinstance(x, str) and x in allowed_items)]
                if bad:
                    self.add("IAC.INVALID_VALUE", p, f"{key!r} items must be among: " + ", ".join(allowed_items)
                             + f"; not allowed: {', '.join(json.dumps(x) for x in bad)}")
                    continue
            try:
                ty = parse_type_constraint(var.get("hcl_type") or "any")
            except ValueError:  # pragma: no cover - catalog builder rejects these
                ty = "dynamic"
            if not _cty_accepts(ty, val):
                self.add("IAC.TYPE_MISMATCH", p, f"{key!r} is {var.get('hcl_type')}; got {type(val).__name__}")
        unwired = m.module in self.ctx.unwired_modules   # not wired to its consumers (NOT_YET_WIRED_MODULES)
        unavailable = sorted(k for k, v in cvars.items() if v["class"] == "FACT" and v.get("has_default")
                             and (v["fact"] not in self.ctx.facts or (unwired and v["fact"] in NETWORK_WIRING_FACTS)))
        if unavailable:   # TI-3 RT F3: the module would render with its default network / zone, never the workload's
            self.add("IAC.MODULE_FACT_UNAVAILABLE", base + "/module",
                     f"golden module {m.module!r} needs the platform fact(s) "
                     + ", ".join(sorted({cvars[k]['fact'] for k in unavailable}))
                     + f" (for {', '.join(unavailable)}), which this workload does not provide yet",
                     hint="The platform cannot wire this module's network or zone yet: remove this entry; the module "
                          "is not available on the typed-intent path.")
        for key, var in sorted(cvars.items()):
            if var.get("has_default"):
                continue
            if var["class"] == "FACT":
                if var["fact"] not in self.ctx.facts:
                    self.add("FACT.MISSING", base, f"required fact {var['fact']!r} for {key!r} is not available",
                             tool="facts", cls=ErrorClass.PLATFORM_DEFECT)
            elif var["class"] in ("AI", "REF_ONLY") and key not in m.args:
                self.add("IAC.MISSING_REQUIRED_ARGUMENT", base + "/args",
                         f"golden module {m.module!r} requires {key!r}")

    # ---------------------------------------------------------------------------- S2/S3 resources
    def resource_entry(self, n: int, r: ExtraResource) -> None:
        base, src = _ptr("resources", n), f"{r.type}.{r.name}"
        spec = self.allowed.get(r.type)
        if spec is None:
            owner = self.art.not_expressible_owner(r.type)
            why = {"platform_owned": "owned by the workload foundation", "forbidden": "forbidden",
                   "topology_owned": "owned by the service topology (compute / invokers)",
                   "lane11_owned": "owned by the platform network (lane 11)"}.get(owner or "", "not on the allow-list")
            hint = "Use a golden module instance or an allow-listed type: " + ", ".join(sorted(self.allowed))
            if r.type == API_ONLY_SERVICE_TYPE:   # TI-3j/3i (Fable F1): the typed way to keep an API the code calls
                hint = ("The platform enables the APIs of every module and resource. An API the code only calls is an "
                        "api_only entry ({\"api_only\": [{\"service\": \"<API>\"}]}) when it is one of: "
                        + ", ".join(sorted(API_ONLY_SERVICES)) + ". " + hint)
            self.add("IAC.TYPE_NOT_ALLOWED", base + "/type", f"{r.type} is {why}", hint=hint)
            return
        block = self.art.resource_schema(r.type) or {}
        self.block(r.arguments, block, base + "/arguments", r.type, "", spec, src, top=True)
        for key, val in sorted((spec.get("forced") or {}).items()):
            if key in r.arguments and r.arguments[key] != val:
                self.add("IAC.FORCED_VALUE", _ptr_join(base + "/arguments", key),
                         f"{r.type}.{key} is always {json.dumps(val)} (platform policy)")
        iam = spec.get("iam")
        if iam:
            self.iam(r, base, iam, src)
        if r.lifecycle:
            for k, ic in enumerate(r.lifecycle.ignore_changes):
                first = ic.split(".", 1)[0].split("[", 1)[0]
                if first not in (block.get("attributes") or {}) and first not in (block.get("block_types") or {}):
                    self.add("IAC.UNKNOWN_ATTRIBUTE", _ptr(*_split(base), "lifecycle", "ignore_changes", k),
                             f"{r.type} has no attribute {first!r}")
        for k, dep in enumerate(r.depends_on):
            p = _ptr("resources", n, "depends_on", k)
            if isinstance(dep, ModuleAddress):
                if dep.module not in self.modules:
                    self.add("IAC.UNKNOWN_REFERENCE", p, f"no module instance named {dep.module!r}")
                else:   # PUSH-SUB-RENDER: depends_on a whole module waits for its push subscription too
                    self.edges.add((src, self.module_node(dep.module)))
            else:
                key = (dep.resource.type, dep.resource.name)
                if key not in self.resources:
                    self.add("IAC.UNKNOWN_REFERENCE", p, f"no resource {key[0]}.{key[1]} in the intent")
                else:
                    self.edges.add((src, f"{key[0]}.{key[1]}"))

    def block(self, body: Mapping[str, Any], schema: Mapping[str, Any], path: str, rtype: str, rule_path: str,
              spec: Mapping[str, Any], src: str, *, top: bool = False) -> None:
        attrs, blocks = schema.get("attributes") or {}, schema.get("block_types") or {}
        dyn = set(spec.get("dynamic_attributes") or ()) if top else set()
        fact_attrs = self.art.allowed.get("fact_attributes") or {}
        for key, val in body.items():
            p, rp = _ptr_join(path, key), (f"{rule_path}.{key}" if rule_path else key)
            if key in RESOURCE_META_ARGUMENTS:
                self.add("IAC.META_ARGUMENT_NOT_ALLOWED", p, f"{key!r} cannot be expressed in an intent",
                         hint="Write one entry per instance; use `lifecycle` / `depends_on` on the entry itself.")
                continue
            if key in attrs:
                a = attrs[key]
                if rp in (spec.get("refused_attributes") or ()) or a.get("write_only"):
                    self.add("IAC.ATTRIBUTE_NOT_ALLOWED", p, f"{rtype}.{rp} cannot be expressed in intent v1 (a "
                             "write-only twin of a secret attribute: a generated secret goes in the sensitive "
                             "attribute itself)", hint="Use secret_data / password with a random_password .result.")
                    continue
                if a.get("computed") and not a.get("optional") and not a.get("required"):
                    self.add("IAC.COMPUTED_ONLY_ATTRIBUTE", p, f"{rtype}.{rp} is computed by the provider")
                    continue
                member_ok = top and key == "member" and bool(spec.get("iam"))
                self.values(val, p, src, member_ok=member_ok)
                if key in dyn:
                    self.dynamic_paths(val, p, rp, spec, src)
                    continue
                if key in fact_attrs and key not in dyn:
                    self.fact_only(val, p, rtype, rp, tuple(fact_attrs[key]))
                elif rp in (spec.get("service_ref_only") or ()):
                    if not _is_service_url(val):
                        self.add("IAC.SERVICE_REF_REQUIRED", p,
                                 f"{rtype}.{rp} takes only a service URL: a service reference (kind service, output "
                                 'service_uri) or {"$fn": "format", "$args": ["%s/<path>", <that reference>]}')
                elif rp in (spec.get("random_password_only") or ()):
                    if not _has_random_password_ref(val):
                        self.add("IAC.SECRET_LITERAL", p, f"{rtype}.{rp} must come from a random_password .result")
                elif rp in (spec.get("module_output_ref") or {}):
                    if not _module_output_ok(val, spec["module_output_ref"][rp], self.modules):
                        self.add("IAC.REF_KIND_NOT_ALLOWED", p,
                                 f"{rtype}.{rp} must reference " + " or ".join(
                                     f"module {mid} output {o}" for mid, o in spec["module_output_ref"][rp]))
                elif rp in (spec.get("target_ref_only") or {}):
                    shapes = spec["target_ref_only"][rp]
                    if not _target_ok(val, shapes, self.modules, self.ctx):
                        self.add("IAC.TARGET_REF_REQUIRED", p,
                                 f"{rtype}.{rp} names an IAM target / data destination / identity / key: it takes only "
                                 "a reference to something this intent declares: " + _shapes_text(shapes),
                                 hint="A literal could name a resource outside this workload (another project, the "
                                      "deployer service account, a platform secret).")
                if not a.get("sensitive") and key not in dyn and self.sensitive_refs(val):
                    self.add("IAC.SENSITIVE_IN_PLAIN_ATTRIBUTE", p,
                             f"{rtype}.{rp} is not a sensitive attribute: a secret value (e.g. random_password.result) "
                             "would be shown in plans and state as plain text",
                             hint="Store generated secrets in google_secret_manager_secret_version.secret_data.")
                pattern = (spec.get("patterns") or {}).get(rp)
                if pattern and isinstance(val, str) and not re.match(pattern, val):
                    self.add("IAC.INVALID_VALUE", p, f"{rtype}.{rp} must match {pattern}")
                ty = a.get("type", "dynamic")
                if isinstance(ty, list) and ty and ty[0] == "nested_type":
                    ty = "dynamic"
                if val is None and a.get("required"):
                    self.add("IAC.MISSING_REQUIRED_ARGUMENT", p, f"{rtype}.{rp} is required (null given)")
                elif not isinstance(val, Member) and not _cty_accepts(ty, val):
                    self.add("IAC.TYPE_MISMATCH", p, f"{rtype}.{rp} is {_type_label(ty)}; got {type(val).__name__}")
                continue
            if key in blocks:
                if rp in (spec.get("refused_blocks") or ()):
                    self.add("IAC.BLOCK_NOT_ALLOWED", p, f"{rtype}.{rp} cannot be expressed in intent v1 (no "
                             "allow-listed producer for its destination, or ingestion from outside the workload)")
                    continue
                b = blocks[key]
                mode, inner = b.get("nesting_mode"), b.get("block") or {}
                items = val if isinstance(val, list) else [val]
                if (mode in ("single", "group") and not isinstance(val, dict)) or \
                        not all(isinstance(x, dict) for x in items):
                    self.add("IAC.TYPE_MISMATCH", p, f"{rtype}.{rp} is a nested block: give an object"
                             + ("" if mode in ("single", "group") else " or a list of objects"))
                    continue
                mx = int(b.get("max_items") or 0)
                if mx and len(items) > mx:
                    self.add("IAC.MAX_ITEMS_EXCEEDED", p, f"{rtype}.{rp} allows at most {mx} block(s)")
                for k, item in enumerate(items):
                    ip = _ptr_join(p, k) if isinstance(val, list) else p
                    self.block(item, inner, ip, rtype, rp, spec, src)
                continue
            self.add("IAC.UNKNOWN_ARGUMENT", p, f"{rtype} has no argument or block {rp!r}",
                     hint="arguments: " + ", ".join(sorted(k for k, a in attrs.items()
                                                           if a.get("required") or a.get("optional"))[:40])
                     + ("; blocks: " + ", ".join(sorted(blocks)[:20]) if blocks else ""))
        forced = (spec.get("forced") or {}) if top else {}
        for key, a in sorted(attrs.items()):
            if a.get("required") and key not in body and key not in forced:
                self.add("IAC.MISSING_REQUIRED_ARGUMENT", path, f"{rtype}.{rule_path + '.' if rule_path else ''}{key}"
                         " is required")
        for key, b in sorted(blocks.items()):
            if int(b.get("min_items") or 0) >= 1 and key not in body:
                self.add("IAC.MISSING_REQUIRED_BLOCK", path, f"{rtype} requires block "
                         f"{rule_path + '.' if rule_path else ''}{key}")

    def sensitive_refs(self, v: Any) -> bool:
        """True when `v` contains a reference to a sensitive value (schema attribute / module output). Quiet: a
        reference that does not resolve is reported by `values` already."""
        if isinstance(v, Ref):
            t = v.ref
            if isinstance(t, ResourceAttrRef) and (t.type, t.name) in self.resources:
                block = self.art.resource_schema(t.type)
                if block is None:
                    return False
                mark = len(self.diags)
                sens = self.attr_path(block, t.attr, "/", t.type)
                del self.diags[mark:]
                return bool(sens)
            if isinstance(t, ModuleOutputRef) and t.module in self.modules:
                cat = self.art.module(self.modules[t.module].module) or {}
                return bool(((cat.get("outputs") or {}).get(t.output) or {}).get("sensitive"))
            return False
        if isinstance(v, Call):
            return any(self.sensitive_refs(a) for a in v.args)
        if isinstance(v, dict):
            return any(self.sensitive_refs(x) for x in v.values())
        if isinstance(v, list):
            return any(self.sensitive_refs(x) for x in v)
        return False

    def dynamic_paths(self, val: Any, path: str, rule_path: str, spec: Mapping[str, Any], src: str) -> None:
        """Exact-path rules below a cty `dynamic` attribute (kubernetes_manifest.manifest; RT F8: no schema walk)."""
        rules = spec.get("fact_only_paths") or {}

        def walk(v: Any, p: str, rp: str) -> None:
            if rp in rules:
                self.fact_only(v, p, "kubernetes_manifest", rp, tuple(rules[rp]))
            if isinstance(v, dict) and not _is_expr(v):
                for k, x in v.items():
                    walk(x, _ptr_join(p, k), f"{rp}.{k}")
            elif isinstance(v, list):
                for k, x in enumerate(v):
                    walk(x, _ptr_join(p, k), f"{rp}[*]")
        walk(val, path, rule_path)

    def fact_only(self, val: Any, path: str, rtype: str, rp: str, facts: Tuple[str, ...]) -> None:
        if not (isinstance(val, Ref) and isinstance(val.ref, FactRef) and val.ref.fact in facts):
            self.add("IAC.FACT_REQUIRED", path, f"{rtype}.{rp} takes only the platform fact(s) {', '.join(facts)}",
                     hint='e.g. {"$ref": {"kind": "fact", "fact": "%s"}}' % facts[0])

    # ---------------------------------------------------------------------------- S5 IAM
    def iam(self, r: ExtraResource, base: str, iam: Mapping[str, Any], src: str) -> None:
        roles = set((self.art.allowed.get("role_allow") or {}).get(iam["role_table"]) or ())
        role = r.arguments.get("role")
        member = r.arguments.get("member")
        gke_member = isinstance(member, Member) and isinstance(member.member, MemberGkeServiceAccount)
        if gke_member or (r.type == GKE_WI_RESOURCE_TYPE and role == GKE_WI_ROLE):
            # GKE-WI-INTENT: exactly one pairing, typed both ways: the Workload Identity role on one service account
            # with a GKE member, and a GKE member only with that role on that type (never on the allow-list alone)
            if not (gke_member and r.type == GKE_WI_RESOURCE_TYPE and role == GKE_WI_ROLE):
                self.add(GKE_WI_PAIRING_CODE, _ptr_join(base + "/arguments", "member" if gke_member else "role"),
                         f"{GKE_WI_ROLE} and a gke_service_account member go together, only on {GKE_WI_RESOURCE_TYPE}",
                         hint=GKE_WI_HINT)
            return
        if r.type in PROJECT_WIDE_GRANT_TYPES and isinstance(role, str) and role in PROJECT_WIDE_DENIED_ROLES:
            # OVERBROAD-SECRET-GRANT: the typed reason (and its scoped alternative), instead of the generic refusal
            self.add(PROJECT_WIDE_GRANT_CODE, _ptr_join(base + "/arguments", "role"),
                     f"{r.type}.{r.name} grants {role} on the whole project", hint=project_wide_grant_hint(role))
        elif "role" in r.arguments and (not isinstance(role, str) or role not in roles):
            self.add("IAC.ROLE_NOT_ALLOWED", _ptr_join(base + "/arguments", "role"),
                     f"role {role!r} is not allowed on {r.type}", hint="allowed: " + ", ".join(sorted(roles)))
        if "member" in r.arguments and not isinstance(r.arguments["member"], Member):
            self.add("IAC.MEMBER_NOT_TYPED", _ptr_join(base + "/arguments", "member"),
                     "an IAM member is written only as {\"$member\": {\"service_account\": <$ref>}} or "
                     "{\"$member\": {\"service_agent\": <fact>}}")

    # ---------------------------------------------------------------------------- S4 cycles + outputs
    def outputs(self) -> None:
        for n, o in enumerate(self.i.outputs):
            self.ref(o.value, _ptr("outputs", n, "value"), "output." + o.name)

    def cycles(self) -> None:
        pushing = sorted(m.name for m in self.i.modules if _has_push(m))   # PUSH-SUB-RENDER: two nodes each
        nodes = sorted({"module." + m for m in self.modules} | {f"{t}.{n}" for t, n in self.resources}
                       | {"service." + s for s in self.ctx.services} | {push_node(m) for m in pushing})
        edges = set(e for e in self.edges if not e[0].startswith("output."))
        edges |= {(push_node(m), "module." + m) for m in pushing}   # the subscription reads the topic
        realizer: Dict[str, str] = {}
        for m in self.i.modules:
            if m.realizes:
                # PUSH-SUB-RENDER: a realized subscription is the push node of a pushing instance
                sub = (_has_push(m) and self.ctx.topology_resources.get(m.realizes) == PUSH_SUBSCRIPTION_TYPE)
                realizer[m.realizes] = push_node(m.name) if sub else "module." + m.name
        for r in self.i.resources:
            if r.realizes:
                realizer[r.realizes] = f"{r.type}.{r.name}"
        for svc, logical in self.ctx.service_reads:
            if logical in realizer and svc in self.ctx.services:
                edges.add(("service." + svc, realizer[logical]))
        # PUSH-TO-PRIVATE: the service's module takes the push identity (a google_service_account it then depends on)
        for svc, _addr, key, _expr in _push_pairs(self.i, self.ctx):
            if key in nodes:   # a google_service_account of the intent (a fact key is never a node)
                edges.add(("service." + svc, key))
        # GKE-WI-INTENT (RT F5): a GKE Workload Identity grant is rendered with depends_on its cluster's compute module
        gke_services = sorted(s for s, (_a, mid) in self.ctx.services.items() if mid == GKE_COMPUTE_MODULE_ID)
        for r in self.i.resources:
            member = r.arguments.get("member")
            if isinstance(member, Member) and isinstance(member.member, MemberGkeServiceAccount):
                edges |= {(f"{r.type}.{r.name}", "service." + s) for s in gke_services}
        for comp in strongly_connected_components(nodes, sorted(edges)):
            if len(comp) > 1 or (comp[0], comp[0]) in edges:
                svc = any(c.startswith("service.") for c in comp)
                self.add("TOPOLOGY.CYCLE" if svc else "IAC.REFERENCE_CYCLE", "/",
                         "reference cycle: " + " -> ".join(sorted(comp)), tool="topology" if svc else "schema")

    def run(self) -> None:
        for n, m in enumerate(self.i.modules):
            for k, v in m.args.items():
                self.scan_values(v, _ptr("modules", n, "args", k))
        for n, r in enumerate(self.i.resources):
            for k, v in r.arguments.items():
                self.scan_values(v, _ptr("resources", n, "arguments", k))
        self.names()
        self.realization()
        self.secret_values()
        for n, m in enumerate(self.i.modules):
            self.module_entry(n, m)
        for n, r in enumerate(self.i.resources):
            self.resource_entry(n, r)
        self.api_only()
        self.outputs()
        self.cycles()

    # ---------------------------------------------------------------------------- TI-3j API-only entries
    def api_only(self) -> None:
        """Exact table membership (IAC.API_NOT_ALLOWED), one entry per API, and the platform's rendered addresses
        never collide with an intent resource or a user-owned / reserved address (IAC.DUPLICATE_ADDRESS)."""
        seen: Dict[str, str] = {}
        rendered: Dict[str, str] = {}
        for n, e in enumerate(self.i.api_only):
            p = _ptr("api_only", n, "service")
            if e.service not in API_ONLY_SERVICES:
                self.add("IAC.API_NOT_ALLOWED", p, f"{e.service} is not on the API-only allow-list",
                         hint="API-only entries: " + ", ".join(sorted(API_ONLY_SERVICES)) + ". Remove this entry; "
                              "any other API is enabled by the platform from the resources and modules that need it.")
                continue
            if e.service in seen:
                self.add("IAC.DUPLICATE_ADDRESS", p, f"{e.service} is listed twice (also at {seen[e.service]})")
                continue
            seen[e.service] = p
            for addr in api_only_addresses(e.service):
                rendered[addr] = p
                if addr in self.ctx.existing_addresses or addr in self.ctx.reserved_addresses:
                    self.add("IAC.DUPLICATE_ADDRESS", p, f"{addr} (rendered for {e.service}) is already declared")
        for n, r in enumerate(self.i.resources):
            addr = f"{r.type}.{r.name}"
            if addr in rendered:
                self.add("IAC.DUPLICATE_ADDRESS", _ptr("resources", n, "name"),
                         f"{addr} is the address the platform renders for the api_only entry at {rendered[addr]}",
                         hint="Give this resource another name.")
        # TI-3j-d (owner 10-25): an AI project grant of a role an api_only entry already grants the workload service
        # account is refused (two non-authoritative members of one binding: removing either later removes the binding
        # the other expects). Exact typed comparison only: the type, the role string, the member's exact fact.
        granted = {role: seen[svc] for svc in seen for role in API_ONLY_SERVICES[svc]["roles"]}
        for n, r in enumerate(self.i.resources):
            role = r.arguments.get("role")
            if (r.type == API_ONLY_IAM_TYPE and isinstance(role, str) and role in granted
                    and f"{r.type}.{r.name}" not in rendered   # refused above as the rendered address already
                    and _is_workload_sa_member(r.arguments.get("member"))):
                self.add(API_ONLY_DUPLICATE_GRANT, _ptr("resources", n),
                         f"{r.type}.{r.name} grants {role} to the workload service account, which the api_only "
                         f"entry at {granted[role]} already grants",
                         hint="Delete this resource: the platform renders this grant for the api_only entry.")


def _split(ptr: str) -> List[str]:
    return [p.replace("~1", "/").replace("~0", "~") for p in ptr.split("/")[1:]]


def _ptr_join(base: str, *parts: Any) -> str:
    return base + _ptr(*parts)


def _loc(loc: Sequence[Any]) -> str:
    return _ptr(*loc) if loc else "/"


def _existing_base(address: str) -> str:
    parts = address.split(".")
    return ".".join(parts[:2])


def _ref_kind_ok(val: Ref, refs: Sequence[str], modules: Mapping[str, ModuleInstance]) -> bool:
    t = val.ref
    for spec in refs:
        kind, _, detail = spec.partition(":")
        if kind != t.kind:
            continue
        if kind == "fact" and t.fact == detail:
            return True
        if kind == "service" and t.output == detail:
            return True
        if kind == "resource_attr" and f"{t.type}.{t.attr}" == detail:
            return True
        if kind == "module_output":
            mid, _, out = detail.partition(".")
            m = modules.get(t.module)
            if m is not None and m.module == mid and t.output == out:
                return True
        if kind == "existing":
            return True
    return False


_URL_PATH_RE = re.compile(r"^%s(/[A-Za-z0-9._~!$&'()*+,;=:@/-]*)?$")


def _is_service_url(v: Any) -> bool:
    """A topology service URL: the ServiceRef itself, or format("%s/<literal path>", ServiceRef)."""
    def svc(x: Any) -> bool:
        return isinstance(x, Ref) and isinstance(x.ref, ServiceRef) and x.ref.output == "service_uri"
    if svc(v):
        return True
    return (isinstance(v, Call) and v.fn == "format" and len(v.args) == 2 and isinstance(v.args[0], str)
            and bool(_URL_PATH_RE.match(v.args[0])) and v.args[0].count("%") == 1 and svc(v.args[1]))


def _target_ok(v: Any, shapes: Sequence[Sequence[str]], modules: Mapping[str, ModuleInstance],
               ctx: "IntentContext") -> bool:
    """RT TI-2 F1/F2: the value is exactly one Ref of a listed shape (no literal, no Call, no other kind)."""
    if not isinstance(v, Ref):
        return False
    t = v.ref
    for shape in shapes:
        kind = shape[0]
        if kind == "resource_attr" and isinstance(t, ResourceAttrRef) and (t.type, t.attr) == (shape[1], shape[2]):
            return True
        if kind == "module_output" and isinstance(t, ModuleOutputRef):
            m = modules.get(t.module)
            if m is not None and (m.module, t.output) == (shape[1], shape[2]):
                return True
        if kind == "fact" and isinstance(t, FactRef) and t.fact == shape[1]:
            return True
        if kind == "resource_attr" and isinstance(t, ExistingRef):
            parts = t.address.split(".")
            if len(parts) == 3 and (parts[0], parts[2]) == (shape[1], shape[2]):
                return True
    return False


def _shapes_text(shapes: Sequence[Sequence[str]]) -> str:
    out = []
    for s in shapes:
        out.append({"resource_attr": f"{s[1]}.<name>.{s[2] if len(s) > 2 else ''}",
                    "module_output": f"module <{s[1]}>.{s[2] if len(s) > 2 else ''}",
                    "fact": f"fact {s[1]}"}[s[0]])
    return ", ".join(out)


def _has_random_password_ref(v: Any) -> bool:
    if isinstance(v, Ref):
        return isinstance(v.ref, ResourceAttrRef) and v.ref.type == "random_password" and v.ref.attr == "result"
    if isinstance(v, Call):
        return any(_has_random_password_ref(a) for a in v.args)
    if isinstance(v, dict):
        return any(_has_random_password_ref(x) for x in v.values())
    if isinstance(v, list):
        return any(_has_random_password_ref(x) for x in v)
    return False


def _module_output_ok(v: Any, allowed: Sequence[Sequence[str]], modules: Mapping[str, ModuleInstance]) -> bool:
    if not (isinstance(v, Ref) and isinstance(v.ref, ModuleOutputRef)):
        return False
    m = modules.get(v.ref.module)
    return m is not None and any(m.module == mid and v.ref.output == out for mid, out in allowed)


def validate_intent(doc: Any, art: Optional[Artifacts] = None, ctx: Optional[IntentContext] = None) -> GateResult:
    """S0-S5 of plan §2.7. `doc` is the JSON text or the decoded object. Never raises on bad input (typed
    diagnostics); raises IntentGateUnavailable when the artifacts are unusable."""
    art = art or load_artifacts()
    ctx = ctx or IntentContext()
    if isinstance(doc, (str, bytes)):
        try:
            doc = json.loads(doc)
        except ValueError as exc:
            return GateResult((_diag("JSON.OUTPUT_INVALID", "/", f"not JSON: {exc}", tool="pydantic"),), None, None)
    try:
        intent = IacIntent.model_validate(doc)
    except ValidationError as exc:
        diags = tuple(_diag("JSON.OUTPUT_INVALID", _loc(e["loc"]), f"{e['msg']}", tool="pydantic")
                      for e in exc.errors()[:50])
        return GateResult(diags, None, None)
    g = _Gate(intent, art, ctx)
    g.run()
    uniq: Dict[Tuple[str, str, str], Diagnostic] = {}
    for d in g.diags:
        uniq.setdefault((d.attribute_path or "", d.code, d.message), d)
    diags = tuple(uniq[k] for k in sorted(uniq))
    if diags:
        return GateResult(diags, intent, None)
    return GateResult((), intent, ValidatedIntent(intent, art, ctx, intent_sha256(intent), _TOKEN))


# ------------------------------------------------------------------------------------------------ topology exports
# TI-3 (plan §2.6, register TI-3d): what a consumer of a topology resource is bound to when an intent entry realizes
# it. Exact table: (golden module id, topology resource type) -> {topology catalog attribute (service_topology
# BOOTSTRAP_CATALOG): the module output whose value is exactly that attribute of the module's own resource}. Every row
# is checked against the module's outputs.tf with python-hcl2 (tests/test_typed_iac_ti3_contract.py): the output's
# value is `<type>.<label>.<attribute>`, unconditional. An attribute without a row is not bound through that module.
REALIZATION_EXPORTS: Mapping[Tuple[str, str], Mapping[str, str]] = {
    ("storage-bucket", "google_storage_bucket"): {"name": "bucket_name"},
    ("messaging-pubsub", "google_pubsub_topic"): {"name": "topic_name", "id": "topic_id"},
    ("security-secret", "google_secret_manager_secret"): {"secret_id": "secret_id"},
    ("cache-redis", "google_redis_instance"): {"host": "host", "port": "port"},
    # CLOUDSQL-PASSWORD-BINDING (owner 11-14, P3-b): password_secret_id as for AlloyDB below
    # (google_secret_manager_secret.db_password.secret_id)
    ("database-cloudsql", "google_sql_database_instance"): {"connection_name": "instance_connection_name",
                                                            "private_ip_address": "private_ip_address",
                                                            "password_secret_id": "secret_id_password"},
    ("analytics-bigquery", "google_bigquery_dataset"): {"dataset_id": "dataset_id"},
    # TI-5-R2 (owner 10-21): the three modules the owner held on 10-21 (TI-5c-a) until their consumers were wired
    # TI-5-R2 P3 (owner 10-25): password_secret_id (service_topology.MODULE_ONLY_ATTRIBUTES) is the module's
    # Secret Manager secret of the initial user's password, google_secret_manager_secret.<label>.secret_id
    ("database-alloydb", "google_alloydb_instance"): {"ip_address": "ip_address",
                                                      "password_secret_id": "secret_id_password"},
    ("ai-vertex-endpoint", "google_vertex_ai_endpoint"): {"id": "endpoint_id", "name": "endpoint_name"},
    ("database-bigtable", "google_bigtable_instance"): {"name": "instance_id"},
}
# TI-5-R2 P3: module arguments a realizing module instance must set (exact literal) when a service reads the attribute:
# (module id, topology type) -> {catalog attribute: {variable: literal}}. A secret id is only useful with read access:
# every Cloud Run service runs as the workload service account (the module's FACT workload_sa_email), and the module
# grants it roles/secretmanager.secretAccessor on that one secret only when grant_workload_secret_access is true (as
# database-cloudsql). Missing -> IAC.REALIZATION_ARGUMENT_REQUIRED (the fix is to set it, never to delete the entry).
REALIZATION_REQUIRED_ARGS: Mapping[Tuple[str, str], Mapping[str, Mapping[str, Any]]] = {
    ("database-alloydb", "google_alloydb_instance"): {"password_secret_id": {"grant_workload_secret_access": True}},
    ("database-cloudsql", "google_sql_database_instance"): {   # CLOUDSQL-PASSWORD-BINDING (owner 11-14)
        "password_secret_id": {"grant_workload_secret_access": True}},
}


def realization_required_args(module_id: str, rtype: str, attrs: Iterable[str]) -> Dict[str, Any]:
    """TI-5-R2 P3: {variable: literal} a `module_id` instance realizing `rtype` must set when services read `attrs`."""
    row = REALIZATION_REQUIRED_ARGS.get((module_id, rtype)) or {}
    out: Dict[str, Any] = {}
    for a in sorted(set(attrs)):
        out.update(row.get(a) or {})
    return dict(sorted(out.items()))


def intent_realizations(intent: IacIntent, needed: Mapping[str, Tuple[str, Iterable[str]]]
                        ) -> Tuple[Dict[str, Dict[str, str]], Tuple[Diagnostic, ...]]:
    """TI-3: {logical: {catalog attribute: HCL expression}} for the topology resources a gate-clean intent realizes,
    plus IAC.REALIZATION_EXPORT_MISSING for each consumed attribute the realizing entry cannot provide and (TI-5-R2
    P3) IAC.REALIZATION_ARGUMENT_REQUIRED for each REALIZATION_REQUIRED_ARGS argument a realizing module instance
    does not set to its exact literal. `needed` = {logical: (topology type, consumed catalog attributes)}. An extra
    resource of the topology type exports every catalog attribute of that type except MODULE_ONLY_ATTRIBUTES
    (`<type>.<name>.<attribute>`, a schema attribute); a module instance exports exactly its REALIZATION_EXPORTS row
    (`module.<name>.<output>`). Pure; the gate has already checked `realizes`."""
    out: Dict[str, Dict[str, str]] = {}
    diags: List[Diagnostic] = []
    entries: List[Tuple[str, str, Dict[str, str]]] = []
    for n, m in enumerate(intent.modules):
        if m.realizes and m.realizes in needed:
            rtype, attrs = needed[m.realizes][0], tuple(needed[m.realizes][1])
            row = REALIZATION_EXPORTS.get((m.module, rtype)) or {}
            entries.append((_ptr("modules", n, "realizes"), m.realizes,
                            {a: f"module.{m.name}.{o}" for a, o in row.items()}))
            for var, want in realization_required_args(m.module, rtype, attrs).items():   # TI-5-R2 P3
                # TI5-ALLOYDB-SECRET-BIND: left out = the platform renders the literal (_Renderer, ctx.topology_
                # attributes); only a different value the intent states is a finding
                if var not in m.args:
                    continue
                got = m.args.get(var)
                if not (type(got) is type(want) and got == want):   # type-exact literal (1 != true)
                    diags.append(_diag("IAC.REALIZATION_ARGUMENT_REQUIRED", _ptr("modules", n, "args"),
                                       f"topology resource {m.realizes!r} ({rtype}) is read by a service, which needs "
                                       f"{var} = {json.dumps(want)} on this {m.module} module", symbol=m.realizes,
                                       hint=f"Set \"{var}\": {json.dumps(want)} in this module's args (keep the "
                                            "entry): the workload service account then gets read access to it."))
    module_only = MODULE_ONLY_ATTRIBUTES
    for n, r in enumerate(intent.resources):
        if r.realizes and r.realizes in needed and r.type == needed[r.realizes][0]:
            entries.append((_ptr("resources", n, "realizes"), r.realizes,
                            {a: f"{r.type}.{r.name}.{a}" for a, _t in BOOTSTRAP_CATALOG.get(r.type, ())
                             if a not in module_only.get(r.type, ())}))   # TI-5-R2 P3: no such schema attribute
    for path, logical, exports in entries:
        out[logical] = dict(sorted(exports.items()))
        rtype, attrs = needed[logical]
        for a in sorted(set(attrs) - set(exports)):
            via = sorted(mid for (mid, t), row in REALIZATION_EXPORTS.items() if t == rtype and a in row)
            if a in module_only.get(rtype, ()):
                hint = f"Realize it with the golden module {', '.join(via)}."
            else:
                hint = (f"Realize it with a resource of type {rtype}"
                        + (f" or the golden module {', '.join(via)}" if via else "") + ".")
            diags.append(_diag("IAC.REALIZATION_EXPORT_MISSING", path,
                               f"topology resource {logical!r} ({rtype}) is read as {a!r} by a service and this entry "
                               "has no output for it", symbol=logical, hint=hint))
    return out, tuple(diags)


# ------------------------------------------------------------------------------------------------ PUSH-TO-PRIVATE
# Register PUSH-TO-PRIVATE (owner 10-27): a Pub/Sub push subscription of the workload whose endpoint is a topology
# Cloud Run service (push_config.push_endpoint: service_ref_only, so a ServiceRef or format("%s/<path>", ServiceRef))
# and whose OIDC token is signed by a typed identity (push_config.oidc_token.service_account_email: target_ref_only,
# the fact workload_sa_email or a google_service_account .email) is that service's push identity. The platform passes
# it to that service's golden compute-cloudrun module (input `push_service_accounts`), which admits exactly it when
# the service is private. Read from the gate-clean intent's typed objects only (no HCL / string inspection).
PUSH_SUBSCRIPTION_TYPE = "google_pubsub_subscription"
PUSH_IDENTITY_MODULE = "compute-cloudrun"
__all__ += ["PUSH_SUBSCRIPTION_TYPE", "PUSH_IDENTITY_MODULE", "push_identities"]


def _single_block(v: Any) -> Optional[Mapping[str, Any]]:
    """A nested block value of a gate-clean intent: an object, or a list holding exactly one object."""
    if isinstance(v, list) and len(v) == 1:
        v = v[0]
    return v if isinstance(v, dict) else None


def _push_target(endpoint: Any) -> Optional[str]:
    """The topology service a push endpoint names (the _is_service_url shapes), else None."""
    if not _is_service_url(endpoint):
        return None
    ref = endpoint if isinstance(endpoint, Ref) else endpoint.args[1]
    return ref.ref.service


def _push_identity(email: Any, facts: Mapping[str, str]) -> Optional[Tuple[str, str]]:
    """(stable key, HCL expression) of a push OIDC identity of the two target_ref_only shapes, else None. The key is
    known at plan (the module's for_each key); the expression may be computed."""
    if not isinstance(email, Ref):
        return None
    t = email.ref
    if isinstance(t, FactRef) and t.fact == "workload_sa_email" and facts.get(t.fact):
        return f"fact.{t.fact}", facts[t.fact]
    if isinstance(t, ResourceAttrRef) and t.type == "google_service_account" and t.attr == "email":
        return f"{t.type}.{t.name}", f"{t.type}.{t.name}.{t.attr}"
    return None


def push_identities(v: "ValidatedIntent") -> Dict[str, Dict[str, str]]:
    """{compute-cloudrun module address: {identity key: HCL email expression}} for the push subscriptions of a
    gate-clean intent (sorted; {} without one). A subscription without an OIDC token, or pushing to a service that is
    not a compute-cloudrun module of the topology, contributes nothing. Two subscriptions signed by the same identity
    to the same service give one entry (one IAM member each, never two resources for one binding)."""
    if not isinstance(v, ValidatedIntent):
        raise TypeError("push_identities takes the ValidatedIntent returned by validate_intent")
    out: Dict[str, Dict[str, str]] = {}
    for _svc, address, key, expr in _push_pairs(v.intent, v.context):
        out.setdefault(address, {})[key] = expr
    return {a: dict(sorted(m.items())) for a, m in sorted(out.items())}


def _push_pairs(intent: IacIntent, ctx: "IntentContext") -> List[Tuple[str, str, str, str]]:
    """(service, compute-cloudrun module address, identity key, HCL email expression) per push subscription of the
    intent that names a typed identity and a compute-cloudrun topology service (see push_identities)."""
    out: List[Tuple[str, str, str, str]] = []
    for r in intent.resources:
        if r.type != PUSH_SUBSCRIPTION_TYPE:
            continue
        push = _single_block(r.arguments.get("push_config"))
        if push is None:
            continue
        svc = _push_target(push.get("push_endpoint"))
        oidc = _single_block(push.get("oidc_token"))
        ident = _push_identity(oidc.get("service_account_email"), ctx.facts) if oidc is not None else None
        if svc is None or ident is None or svc not in ctx.services:
            continue
        address, module_id = ctx.services[svc]
        if module_id == PUSH_IDENTITY_MODULE:
            out.append((svc, address, ident[0], ident[1]))
    for m in intent.modules:   # PUSH-SUB-RENDER: a messaging-pubsub instance's typed `push`
        push = m.args.get(PUSH_ARG) if _has_push(m) else None
        if not isinstance(push, dict):
            continue
        target = push.get("service")
        svc = (target.ref.service if isinstance(target, Ref) and isinstance(target.ref, ServiceRef)
               and target.ref.output == "service_uri" else None)
        ident = _push_identity(push.get("service_account_email"), ctx.facts)
        if svc is None or ident is None or svc not in ctx.services:
            continue
        address, module_id = ctx.services[svc]
        if module_id == PUSH_IDENTITY_MODULE:
            out.append((svc, address, ident[0], ident[1]))
    return out


# ------------------------------------------------------------------------------------------------ PUSH-SUB-RENDER
# Register PUSH-SUB-RENDER (owner 10-28): a Pub/Sub push subscription to the workload's own Cloud Run service is declared
# on the topic's messaging-pubsub module instance as the closed form `push` = {"service": <service Ref, output
# service_uri>, "path": "/<literal path>", "service_account_email": <the push identity: the fact workload_sa_email or
# google_service_account.<name>.email of the intent>}. The platform renders the module's `push` object: endpoint =
# "${<service module>.service_uri}<path>", the OIDC identity, audience = the service URL; the identity is that
# service's push identity (push_identities, PUSH-TO-PRIVATE). The cycle check splits a pushing instance into its topic
# part and its subscription (module.<name>.push -> the service), so a service that publishes to the topic it is pushed
# from is acyclic, as in Terraform's own graph. A hand-written google_pubsub_subscription stays accepted.
PUSH_MODULE = "messaging-pubsub"
PUSH_ARG = "push"
PUSH_ARG_KEYS = ("path", "service", "service_account_email")
# RT F1 (10-28): no `@` / `:` (no authority- or port-like text after the service URL); segments: push_path_ok. Both are
# defined in shared/service_topology.py (PUSH-PLAN-CHECK: the topology's push edges apply the same rule) and imported.
PUSH_SUBSCRIPTION_OUTPUTS = frozenset({"subscription_name", "subscription_id"})
PUSH_IDENTITY_SHAPES = (("fact", "workload_sa_email"), ("resource_attr", "google_service_account", "email"))
PUSH_FORM_TEXT = ('{"service": {"$ref": {"kind": "service", "service": "<topology service>", "output": "service_uri"}}, '
                  '"path": "/<path>", "service_account_email": <Ref to the fact workload_sa_email or to '
                  'google_service_account.<name>.email>}')
__all__ += ["PUSH_MODULE", "PUSH_ARG", "PUSH_ARG_KEYS", "PUSH_PATH_PATTERN", "PUSH_FORM_TEXT", "push_path_ok"]


def _has_push(m: ModuleInstance) -> bool:
    return m.module == PUSH_MODULE and PUSH_ARG in m.args


def push_node(name: str) -> str:
    """The cycle-check node of the push subscription of module.<name> (never an HCL address)."""
    return f"module.{name}.push"


# ------------------------------------------------------------------------------------------------ rendering
def escape_template(s: str) -> str:
    """A literal string as an HCL template that evaluates to exactly `s` (JSON syntax: every string is a template)."""
    return s.replace("${", "$${").replace("%{", "%%{")


_HCL_ESC = {"\\": "\\\\", '"': '\\"', "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def hcl_string_literal(s: str) -> str:
    """A native-syntax HCL quoted string that evaluates to exactly `s` (used inside ${...} only)."""
    out = []
    for ch in escape_template(s):
        if ch in _HCL_ESC:
            out.append(_HCL_ESC[ch])
        elif ord(ch) < 0x20 or ord(ch) == 0x7f:
            out.append("\\u%04x" % ord(ch))
        else:
            out.append(ch)
    return '"' + "".join(out) + '"'


@dataclass(frozen=True)
class RenderResult:
    files: Mapping[str, str]                 # path -> rendered JSON text (custom.tf.json [+ intent_facts.tf.json])
    provenance: Mapping[str, str]            # rendered JSON pointer -> intent JSON pointer
    intent_sha256: str
    facts_used: Tuple[str, ...]
    functions_used: Tuple[str, ...]
    platform_modules: Tuple[str, ...] = ()   # TI-5c: golden modules the platform render calls (vendored with the intent's)


class _Renderer:
    def __init__(self, intent: IacIntent, art: Artifacts, ctx: IntentContext):
        self.i, self.art, self.ctx = intent, art, ctx
        self.modules = {m.name: m for m in intent.modules}
        self.facts: Set[str] = set()
        self.fns: Set[str] = set()

    def ref_expr(self, r: Ref) -> str:
        t = r.ref
        if isinstance(t, ModuleOutputRef):
            return f"module.{t.module}.{t.output}"
        if isinstance(t, ResourceAttrRef):
            return f"{t.type}.{t.name}.{t.attr}"
        if isinstance(t, FactRef):
            return self.fact_expr(t.fact)
        if isinstance(t, ServiceRef):
            return f"{self.ctx.services[t.service][0]}.{t.output}"
        if isinstance(t, ExistingRef):
            return t.address
        raise TypeError(type(t))  # pragma: no cover

    def fact_expr(self, fact: str) -> str:
        expr = self.ctx.facts.get(fact)
        if not expr:
            raise ValueError(f"fact {fact!r} unavailable")   # the gate reports FACT.MISSING first
        self.facts.add(fact)
        return expr

    def member_template(self, m: Member) -> str:
        inner = m.member
        if isinstance(inner, MemberGkeServiceAccount):   # GKE-WI-INTENT: the project's pool, the typed KSA
            ksa = inner.gke_service_account
            return ("serviceAccount:${" + self.fact_expr("project_id") + "}" + GKE_WI_POOL_SUFFIX
                    + f"[{ksa.namespace}/{ksa.name}]")
        expr = (self.ref_expr(inner.service_account) if isinstance(inner, MemberServiceAccount)
                else self.fact_expr(inner.service_agent))
        return "serviceAccount:${" + expr + "}"

    def native(self, v: Any) -> str:
        """Value as a native-syntax HCL expression (inside ${...})."""
        if isinstance(v, Ref):
            return self.ref_expr(v)
        if isinstance(v, Member):
            return '"' + self.member_template(v) + '"'
        if isinstance(v, Call):
            if v.fn not in self.art.functions:
                raise ValueError(f"function {v.fn!r} not allowed")
            self.fns.add(v.fn)
            return v.fn + "(" + ", ".join(self.native(a) for a in v.args) + ")"
        if isinstance(v, bool):
            return "true" if v else "false"
        if v is None:
            return "null"
        if isinstance(v, int):
            return str(v)
        if isinstance(v, float):
            if not math.isfinite(v):
                raise ValueError("non-finite number")
            return json.dumps(v)
        if isinstance(v, str):
            return hcl_string_literal(v)
        if isinstance(v, list):
            return "[" + ", ".join(self.native(x) for x in v) + "]"
        if isinstance(v, dict):
            return "{" + ", ".join(f"{hcl_string_literal(_safe_key(k))} = {self.native(x)}"
                                   for k, x in sorted(v.items())) + "}"
        raise TypeError(type(v))  # pragma: no cover

    def expr(self, v: Any) -> Any:
        """Value in JSON-syntax expression context."""
        if isinstance(v, Ref):
            return "${" + self.ref_expr(v) + "}"
        if isinstance(v, Member):
            return self.member_template(v)
        if isinstance(v, Call):
            return "${" + self.native(v) + "}"
        if isinstance(v, str):
            return escape_template(v)
        if isinstance(v, float) and not math.isfinite(v):
            raise ValueError("non-finite number")
        if isinstance(v, list):
            return [self.expr(x) for x in v]
        if isinstance(v, dict):
            return {_safe_key(k): self.expr(x) for k, x in v.items()}
        return v

    def push_value(self, v: Any) -> Dict[str, Any]:
        """PUSH-SUB-RENDER: the messaging-pubsub `push` object from the closed intent form (_Gate.push_arg)."""
        svc, email, path = (v.get("service"), v.get("service_account_email"), v.get("path")) if isinstance(
            v, dict) else (None, None, None)
        if not (isinstance(svc, Ref) and isinstance(svc.ref, ServiceRef) and svc.ref.output == "service_uri"
                and isinstance(email, Ref) and push_path_ok(path)
                and set(v) == set(PUSH_ARG_KEYS)):
            raise ValueError("push is not the closed push form")
        uri = "${" + self.ref_expr(svc) + "}"
        return {"audience": uri, "endpoint": uri + escape_template(path), "service_account_email": self.expr(email)}

    def body(self, args: Mapping[str, Any], schema: Mapping[str, Any]) -> Dict[str, Any]:
        """Resource body: attributes as expressions, nested blocks as objects (schema-directed)."""
        blocks = schema.get("block_types") or {}
        out: Dict[str, Any] = {}
        for k, v in args.items():
            if k in RESOURCE_META_ARGUMENTS:
                raise ValueError(f"meta-argument {k!r}")
            if k in blocks:
                inner = blocks[k].get("block") or {}
                out[k] = [self.body(x, inner) for x in v] if isinstance(v, list) else self.body(v, inner)
            else:
                out[_safe_key(k)] = self.expr(v)
        return out

    def render(self) -> RenderResult:
        sha = intent_sha256(self.i)
        prov: Dict[str, str] = {}
        doc: Dict[str, Any] = {"//": f"Rendered by StackVend from {INTENT_PATH} (intent_sha256={sha}). Do not edit: "
                                     "change the intent instead."}
        mods: Dict[str, Any] = {}
        for n, m in enumerate(self.i.modules):
            cat = self.art.module(m.module)
            if cat is None:
                raise ValueError(f"module {m.module!r} not in the catalog")
            body: Dict[str, Any] = {"source": MODULE_SOURCE_PREFIX + m.module}
            for var, meta in sorted((cat.get("variables") or {}).items()):
                if meta["class"] == "FACT" and meta["fact"] in self.ctx.facts:
                    body[var] = "${" + self.fact_expr(meta["fact"]) + "}"
                    if FACTS[meta["fact"]].get("platform") == "network":
                        # TI-5c: the module waits for the whole platform network (its Private Services Access
                        # peering is not referenced by the network id, and Cloud SQL / AlloyDB / Vertex need it)
                        body["depends_on"] = ["module." + PLATFORM_NETWORK_MODULE]
            for k, v in m.args.items():
                if k in MODULE_META_ARGUMENTS or k not in (cat.get("variables") or {}):
                    raise ValueError(f"module argument {k!r}")
                body[k] = self.push_value(v) if (m.module, k) == (PUSH_MODULE, PUSH_ARG) else self.expr(v)
            if m.realizes and m.realizes in self.ctx.topology_resources:   # TI5-ALLOYDB-SECRET-BIND
                need = realization_required_args(m.module, self.ctx.topology_resources[m.realizes],
                                                 self.ctx.topology_attributes.get(m.realizes, ()))
                for var, want in need.items():
                    if var not in m.args and var in (cat.get("variables") or {}):
                        body[var] = want
            # SECRET-INITIAL-VERSION: the platform's random first version of a topology secret (gate-checked: the AI
            # never sets the TOPOLOGY-class input, and a generated secret is realized by GENERATED_SECRET_MODULE)
            if m.realizes in self.ctx.generated_secrets and m.module == GENERATED_SECRET_MODULE:
                if GENERATED_SECRET_ARG not in (cat.get("variables") or {}):   # stale catalog: never render silently
                    raise ValueError(f"module {m.module!r} has no variable {GENERATED_SECRET_ARG!r} in the catalog")
                body[GENERATED_SECRET_ARG] = True
            mods[m.name] = body
            prov[_ptr("module", m.name)] = _ptr("modules", n)
        res: Dict[str, Dict[str, Any]] = {}
        allowed = self.art.allowed_types
        for n, r in enumerate(self.i.resources):
            spec = allowed.get(r.type)
            schema = self.art.resource_schema(r.type)
            if spec is None or schema is None:
                raise ValueError(f"type {r.type!r} not allowed")
            body = self.body(r.arguments, schema)
            for k, v in sorted((spec.get("forced") or {}).items()):
                body[k] = v
            if r.lifecycle and (r.lifecycle.prevent_destroy is not None or r.lifecycle.ignore_changes):
                lc: Dict[str, Any] = {}
                if r.lifecycle.prevent_destroy is not None:
                    lc["prevent_destroy"] = r.lifecycle.prevent_destroy
                if r.lifecycle.ignore_changes:
                    lc["ignore_changes"] = list(r.lifecycle.ignore_changes)
                body["lifecycle"] = lc
            deps = [("module." + d.module) if isinstance(d, ModuleAddress)
                    else f"{d.resource.type}.{d.resource.name}" for d in r.depends_on]
            member = r.arguments.get("member")
            if isinstance(member, Member) and isinstance(member.member, MemberGkeServiceAccount):
                # GKE-WI-INTENT: the Workload Identity pool exists only once the GKE cluster exists
                deps += [a for a in gke_compute_modules(self.ctx) if a not in deps]
            if deps:
                body["depends_on"] = deps
            res.setdefault(r.type, {})[r.name] = body
            prov[_ptr("resource", r.type, r.name)] = _ptr("resources", n)
            for k in r.arguments:
                prov[_ptr("resource", r.type, r.name, k)] = _ptr("resources", n, "arguments", k)
        self.api_only(res, prov)   # TI-3j
        outs: Dict[str, Any] = {}
        for n, o in enumerate(self.i.outputs):
            body = {"value": "${" + self.ref_expr(o.value) + "}"}
            if self._sensitive(o.value):
                body["sensitive"] = True
            if o.description:
                body["description"] = escape_template(o.description)
            outs[o.name] = body
            prov[_ptr("output", o.name)] = _ptr("outputs", n)
        if mods:
            doc["module"] = mods
        if res:
            doc["resource"] = res
        if outs:
            doc["output"] = outs
        files = {RENDER_PATH: _dump(doc)}
        data_needed = sorted({d for f in self.facts for d in (FACTS[f].get("data") or ())})
        network = any(FACTS[f].get("platform") == "network" for f in self.facts)
        platform_modules: Tuple[str, ...] = ()
        if data_needed or network:
            data_doc: Dict[str, Any] = {"//": f"Platform facts for {RENDER_PATH} (intent_sha256={sha}). Do not edit."}
            if data_needed:
                data_doc["data"] = {t: {_PLATFORM_DATA_BLOCKS[t][0]: dict(_PLATFORM_DATA_BLOCKS[t][1])}
                                    for t in data_needed}
            if network:   # TI-5c: the platform network (and its VPC connector) that the network facts name
                data_doc["module"] = {PLATFORM_NETWORK_MODULE: json.loads(json.dumps(_PLATFORM_NETWORK_BODY))}
                if self.ctx.psa_range:   # TI-5-F4: the PSA range is the workload's IPAM fact
                    data_doc["module"][PLATFORM_NETWORK_MODULE].update(_PLATFORM_NETWORK_PSA_ARGS)
                platform_modules = (PLATFORM_NETWORK_MODULE_ID,)
                if self.ctx.vpc_connector:   # FD-4BH: the golden connector module + the move from the TI-5c address
                    data_doc["module"][PLATFORM_CONNECTOR_MODULE] = json.loads(json.dumps(_PLATFORM_CONNECTOR_BODY))
                    data_doc["moved"] = [dict(_PLATFORM_CONNECTOR_MOVED)]
                    platform_modules = (PLATFORM_NETWORK_MODULE_ID, PLATFORM_CONNECTOR_MODULE_ID)
            files[FACTS_RENDER_PATH] = _dump(data_doc)
        return RenderResult(files, prov, sha, tuple(sorted(self.facts)), tuple(sorted(self.fns)), platform_modules)

    def api_only(self, res: Dict[str, Dict[str, Any]], prov: Dict[str, str]) -> None:
        """TI-3j: per API-only entry, the API (google_project_service) and its exact table role(s) for the workload
        SA (google_project_iam_member), from platform data only: the table, the project_id and workload_sa_email
        facts. The AI's entry contributes only the (allow-listed) service name."""
        for n, e in enumerate(self.i.api_only):
            if e.service not in API_ONLY_SERVICES:
                raise ValueError(f"API {e.service!r} not on the API-only allow-list")
            facts = {f: self.fact_expr(f) for f in ("project_id", "workload_sa_email")}
            for rtype, name, body in api_only_resources(e.service, facts):
                if name in res.get(rtype, {}):
                    raise ValueError(f"address {rtype}.{name} rendered twice")
                res.setdefault(rtype, {})[name] = body
                prov[_ptr("resource", rtype, name)] = _ptr("api_only", n)

    def _sensitive(self, r: Ref) -> bool:
        t = r.ref
        if isinstance(t, ModuleOutputRef):
            m = self.modules.get(t.module)
            cat = self.art.module(m.module) if m else None
            return bool(((cat or {}).get("outputs") or {}).get(t.output, {}).get("sensitive"))
        if isinstance(t, ResourceAttrRef):
            g = _Gate(self.i, self.art, self.ctx)
            block = self.art.resource_schema(t.type)
            return bool(block and g.attr_path(block, t.attr, "/", t.type))
        return False


def _safe_key(k: str) -> str:
    if _key_problem(k):
        raise ValueError(f"reserved object key {k!r}")
    return k


def _dump(doc: Mapping[str, Any]) -> str:
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def render_intent(v: ValidatedIntent) -> RenderResult:
    """Deterministic render of a gate-clean intent (plan §2.7 R)."""
    if not isinstance(v, ValidatedIntent):
        raise TypeError("render_intent takes the ValidatedIntent returned by validate_intent")
    return _Renderer(v.intent, v.artifacts, v.context).render()


def render_parsed_for_shadow(intent: IacIntent, art: Artifacts, ctx: IntentContext) -> RenderResult:
    """SHADOW / EVAL ONLY (TI-2 gate precision, metric (d)): render a parsed intent the gate may have rejected, to ask
    the compiler whether it agrees. Still grammar-safe (pydantic patterns, escaped literals, reserved keys refused,
    only allow-listed types / catalog modules / Call functions, no meta-arguments); semantic checks are skipped. Never
    used on a product path."""
    return _Renderer(intent, art, ctx).render()


# ------------------------------------------------------------------------------------------------ Gemini schema
def response_json_schema(art: Optional[Artifacts] = None) -> Dict[str, Any]:
    """`response_json_schema` for Gemini structured output (lane 15 F13 spike, TI-2): the pydantic schema with the
    data-driven enums (catalog module ids, allow-listed types, Call functions) injected. The platform parse
    (validate_intent) stays the hard gate whatever the API accepts."""
    art = art or load_artifacts()
    schema = IacIntent.model_json_schema(by_alias=True)
    defs = schema.get("$defs") or {}
    defs["ModuleInstance"]["properties"]["module"]["enum"] = list(art.ai_modules)
    defs["ExtraResource"]["properties"]["type"]["enum"] = sorted(art.allowed_types)
    defs["Call"]["properties"]["$fn"]["enum"] = sorted(art.functions)
    defs["ApiOnlyEntry"]["properties"]["service"]["enum"] = sorted(API_ONLY_SERVICES)   # TI-3j
    return schema
