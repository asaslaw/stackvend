"""Typed per-service topology (FD-51 / lane 10; FD-50 `services` / `edges` / `resources` schema).

The architect states the workload's compute as a typed `ServiceTopologyIntent`: every service with its compute
kind, which service is the primary (`module "compute"`), the directed calls between services (`edges`) and the
resources each service reads from its environment (`resources[].consumers`). One deterministic validator,
`validate_service_topology`, checks it and returns `shared.diagnostics.Diagnostic`s; nothing here heals, renames,
drops or reorders anything (AGENTS.md invariants 1, 2 and 6). The renderers only accept a `ValidatedTopology`, which
only the validator constructs.

Plan: docs/planning/wave2-lane10-dag-wiring-plan.md R2 (§3, §4), RT docs/planning/wave2-lane10-plan-red-team-fable.md.

Design rules kept here:
- Names are closed grammars (`ServiceName`, `EnvKey`, `HclIdent`, `ProviderType`). Every HCL reference this module
  produces (`ValidatedTopology.env_for`) is assembled ONLY from validated identifiers, an allow-listed output /
  attribute name and fixed punctuation: no value from the LLM, Firestore or a repository is ever emitted verbatim
  (RT F2). The persisted topology is data; it is never an HCL source.
- Cycles: Tarjan's strongly connected components, hand-written (graphlib has no SCC API); every cycle is reported
  once with its path (Invariant 6). Never healed.
- Brownfield: `existing` is the typed list of compute modules already in the workload repository
  (`ExistingComputeEntry`, built by an exact python-hcl2 / json parse in the developer). A topology that removes,
  re-kinds, renames or re-primaries existing compute is refused (BROWNFIELD_CONFLICT) before any LLM call.
- `sha256` is drift detection only, never an authority.

Pure: no I/O, no LLM, no TEST_MODE. Root `shared/` is the source of truth; service copies are byte-identical
(deploy/vendor_shared.py).
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import (Annotated, Any, Dict, FrozenSet, Iterable, List, Literal, Mapping, Optional, Sequence, Tuple,
                    get_args)

from pydantic import BaseModel, Field, StringConstraints, ValidationError

try:
    from shared.diagnostics import Diagnostic, ErrorClass
except ImportError:  # pragma: no cover - package-relative import inside a vendored copy
    from .diagnostics import Diagnostic, ErrorClass  # type: ignore

__all__ = [
    "SERVICE_NAME_PATTERN", "ENV_KEY_PATTERN", "HCL_IDENT_PATTERN", "PROVIDER_TYPE_PATTERN", "ComputeKind",
    "COMPUTE_KINDS", "FOUNDATION_ONLY", "ARCHETYPES", "KindCapability", "CAPABILITIES", "MODULE_DIR",
    "KIND_FOR_MODULE_DIR", "RESERVED_ENV_KEYS", "BOOTSTRAP_CATALOG", "Scaling", "ServiceSpec", "ServiceEdge",
    "ResourceBinding", "ResourceSpec", "ServiceTopologyIntent", "ExistingComputeEntry", "ValidatedTopology",
    "validate_service_topology", "strongly_connected_components", "canonical_topology_json", "topology_sha256",
    "TOPOLOGY_RECORD_SCHEMA", "render_topology_contract", "service_label", "TOPOLOGY_JSON_PATH",
    "topology_from_record", "render_topology_json", "topology_owned_tree", "VmSpec", "WORKER_RESOURCE_ACCESS",
    "MACHINE_TYPE_PATTERN", "worker_short_name", "FOUNDATION_PROVIDED", "CATALOG_NOTES", "MODULE_ONLY_ATTRIBUTES",
    "TYPED_IMPLIED_ATTRIBUTES", "MODULE_ONLY_ATTRIBUTE_NOTES", "PushEdge", "PUSH_PATH_PATTERN", "push_path_ok",
    "PUSH_TOPIC_TYPE", "PUSH_CALLEE_KIND", "PUSH_CONTRACT_LINE",
    "SECRET_RESOURCE_TYPE", "INITIAL_VALUE_RANDOM", "INITIAL_VALUE_OPERATOR", "INITIAL_VALUES", "INITIAL_VALUE_TYPES",
    "SECRET_CONTRACT_LINE", "GENERATED_SECRET_LENGTH", "GENERATED_SECRET_ATTRIBUTES", "DATABASE_PASSWORD_TYPES",
]

# ------------------------------------------------------------------------------------------------ closed grammars
SERVICE_NAME_PATTERN = r"^[a-z]([a-z0-9-]{0,38}[a-z0-9])?$"    # RFC 1123 label, <= 40 chars (RT F10: 1 char ok)
ENV_KEY_PATTERN = r"^[A-Z][A-Z0-9_]{0,62}$"
HCL_IDENT_PATTERN = r"^[a-z][a-z0-9_]{0,62}$"
PROVIDER_TYPE_PATTERN = r"^[a-z][a-z0-9_]{2,80}$"
MACHINE_TYPE_PATTERN = r"^[a-z][a-z0-9]{1,9}-[a-z0-9]{1,20}(-[a-z0-9]{1,20}){0,2}$"   # e.g. e2-micro, n2-standard-2
# PUSH-SUB-RENDER RT F1 (10-28): the closed push path grammar (no `?`, `#`, `{`, `%`, `@`, `:`, spaces or newlines);
# segments: push_path_ok. Defined here so the topology's push edges (PUSH-PLAN-CHECK) and the typed intent's `push`
# (shared/iac_intent.py imports both) apply the one rule.
PUSH_PATH_PATTERN = r"^/[A-Za-z0-9._~!&'()*+,;=/-]{0,255}$"



def push_path_ok(path: Any) -> bool:
    """RT F1: a literal URL path of the closed push grammar: charset and length by PUSH_PATH_PATTERN (first char `/`),
    and no empty, `.` or `..` segment ("/" and one trailing "/" are allowed; "//" anywhere, "/./", "/../" are not)."""
    if not (isinstance(path, str) and re.fullmatch(PUSH_PATH_PATTERN, path)):
        return False
    segs = path[1:].split("/")
    if segs[-1] == "":   # "/" itself, or a trailing slash
        segs = segs[:-1]
    return all(s and s not in (".", "..") for s in segs)


# SECRET-INITIAL-VERSION (owner 11-10): who supplies a topology secret's value, typed (never guessed from its name,
# AGENTS.md invariant 2). "random": the workload itself makes and uses the value (a signing, HMAC or encryption key no
# outside system issues); on typed infrastructure the platform creates a random first version at deploy (golden
# security-secret generate_initial_version, rendered by shared/iac_intent.py). "operator": a credential an outside
# system issues; created empty, and the pre-build gate names it on the plan approval card. Absent: created empty, as
# before this field existed (named on the card too). Only SECRET_RESOURCE_TYPE may carry it.
SECRET_RESOURCE_TYPE = "google_secret_manager_secret"
INITIAL_VALUE_RANDOM = "random"
INITIAL_VALUE_OPERATOR = "operator"
INITIAL_VALUES: Tuple[str, ...] = (INITIAL_VALUE_RANDOM, INITIAL_VALUE_OPERATOR)
InitialValue = Literal["random", "operator"]
INITIAL_VALUE_TYPES: FrozenSet[str] = frozenset({SECRET_RESOURCE_TYPE})
# The generated value: this many letters and digits (infra/modules/security-secret random_password.initial length;
# a test pins the equality)
GENERATED_SECRET_LENGTH = 64
# The catalog attributes a service may read from a "random" secret: exactly what the golden security-secret module
# exports (shared/iac_intent.REALIZATION_EXPORTS row; a test pins the equality), since only it renders the version
GENERATED_SECRET_ATTRIBUTES: FrozenSet[str] = frozenset({"secret_id"})

ServiceName = Annotated[str, StringConstraints(pattern=SERVICE_NAME_PATTERN)]
EnvKey = Annotated[str, StringConstraints(pattern=ENV_KEY_PATTERN)]
HclIdent = Annotated[str, StringConstraints(pattern=HCL_IDENT_PATTERN)]
ProviderType = Annotated[str, StringConstraints(pattern=PROVIDER_TYPE_PATTERN)]
MachineType = Annotated[str, StringConstraints(pattern=MACHINE_TYPE_PATTERN)]

# Compute kinds = the golden compute modules. The kinds that can be the primary, plus "foundation-only", equal
# developer_agent/compute_intent.py ARCHETYPES (tests/test_service_topology.py guards the parity with the architect
# enum). `gce-worker` (lane 10 L10-v) is secondary only: an instance template a Cloud Run service launches VMs from.
ComputeKind = Literal["cloudrun", "event-worker", "gke-autopilot", "gce-bastion", "gce-worker"]
COMPUTE_KINDS: Tuple[str, ...] = tuple(get_args(ComputeKind))
FOUNDATION_ONLY = "foundation-only"

TOPOLOGY_RECORD_SCHEMA = "service_topology/v1"


# ------------------------------------------------------------------------------------------------ capability matrix
@dataclass(frozen=True)
class KindCapability:
    """What a golden compute module can do (data; tests cross-check it against infra/modules/compute-*/)."""
    module_dir: str                      # infra/modules/<module_dir>
    exports: Tuple[str, ...]             # the module's outputs
    accepts_env_vars: bool               # the module declares an `env_vars` input (an edge caller must)
    allowed_as_secondary: bool
    max_per_workload: Optional[int]      # None: unbounded
    callee_protocol: Optional[str]       # the edge protocol this kind serves as a callee, else None
    callee_outputs: Tuple[Tuple[str, str], ...] = ()   # (env suffix, module output) bound on the caller per edge
    allowed_as_primary: bool = True
    can_launch: bool = False             # may be the caller of a `launch` edge (starts gce-worker VMs)
    can_call: bool = True                # may be the caller of any edge (RT F1: a gce-worker holds no invoker /
                                         # publisher grant, so an http / pubsub call from it could only 403)


CAPABILITIES: Mapping[str, KindCapability] = {
    "cloudrun": KindCapability(
        module_dir="compute-cloudrun", exports=("service_name", "service_uri", "service_id", "iap_enabled"),
        accepts_env_vars=True, allowed_as_secondary=True, max_per_workload=None, callee_protocol="http",
        callee_outputs=(("URL", "service_uri"), ("AUDIENCE", "service_uri")), can_launch=True),
    # Its topic / subscription / job names derive from product_id (infra/modules/compute-event-worker/main.tf), so
    # at most one per workload, as the primary OR as a secondary (RT F3).
    "event-worker": KindCapability(
        module_dir="compute-event-worker",
        exports=("job_name", "job_id", "topic_name", "topic_id", "subscription_name"),
        accepts_env_vars=False, allowed_as_secondary=True, max_per_workload=1, callee_protocol="pubsub",
        callee_outputs=(("TOPIC", "topic_name"),)),
    "gke-autopilot": KindCapability(
        module_dir="compute-gke-autopilot",
        exports=("cluster_name", "cluster_endpoint", "cluster_id", "cluster_ca_certificate"),
        accepts_env_vars=False, allowed_as_secondary=False, max_per_workload=1, callee_protocol=None),
    "gce-bastion": KindCapability(
        module_dir="compute-gce-bastion",
        exports=("instance_id", "instance_name", "instance_self_link", "bastion_sa_email"),
        accepts_env_vars=False, allowed_as_secondary=False, max_per_workload=1, callee_protocol=None),
    # An instance template (no VM at rest). Its caller gets the template self-link, the zone and the instance-name
    # prefix its launch grant is limited to (never a URL: L10-e); `env_vars` become instance metadata attributes.
    "gce-worker": KindCapability(
        module_dir="compute-gce-worker",
        exports=("instance_template_self_link", "instance_template_name", "instance_name_prefix", "zone",
                 "service_account_email"),
        accepts_env_vars=True, allowed_as_secondary=True, max_per_workload=None, callee_protocol="launch",
        callee_outputs=(("INSTANCE_TEMPLATE", "instance_template_self_link"), ("ZONE", "zone"),
                        ("NAME_PREFIX", "instance_name_prefix")),
        allowed_as_primary=False, can_call=False),
}
ARCHETYPES: Tuple[str, ...] = tuple(k for k in COMPUTE_KINDS if CAPABILITIES[k].allowed_as_primary) + (FOUNDATION_ONLY,)
MODULE_DIR: Mapping[str, str] = {k: c.module_dir for k, c in CAPABILITIES.items()}
KIND_FOR_MODULE_DIR: Mapping[str, str] = {v: k for k, v in MODULE_DIR.items()}
# The one kind that serves each edge protocol as a callee (a test guards that it is one per protocol).
PROTOCOL_CALLEE_KIND: Mapping[str, str] = {c.callee_protocol: k for k, c in CAPABILITIES.items() if c.callee_protocol}

# AC-4: exact hint per protocol for an env-key clash found on an edge whose callee kind is wrong (fixed text; only the
# validated key and the validator's own origin path are filled in).
_EDGE_KEY_HINT: Mapping[str, str] = {
    "pubsub": "a pubsub edge already gives the caller {key} (the platform creates that topic); drop the other "
              "binding ({other}) or set a different env_key_base on this edge.",
    "http": "an http edge already gives the caller {key} (the callee service's URL); drop the other binding "
            "({other}) or set a different env_key_base on this edge.",
    "launch": "a launch edge already gives the caller {key} (the worker's launch settings); drop the other binding "
              "({other}) or set a different env_key_base on this edge.",
}


def _caller_can_bind(caller_kind: str, protocol: str) -> bool:
    """The caller-side edge checks of `validate_service_topology` (EDGE_CALLER_UNSUPPORTED,
    LAUNCH_CALLER_UNSUPPORTED, EDGE_CALLER_NO_ENV_INPUT), all passing: the caller would receive the edge's keys."""
    cap = CAPABILITIES[caller_kind]
    return cap.can_call and (protocol != "launch" or cap.can_launch) and cap.accepts_env_vars

# Environment keys a Cloud Run service already gets from the platform: the `env` names of
# infra/modules/compute-cloudrun/main.tf, literal or emitted by a one-name dynamic block (GOOGLE_CLOUD_PROJECT,
# CLOUDRUN-GOOGLE-CLOUD-PROJECT-ENV; cross-checked by tests), Cloud Run's own runtime variables, and the project id
# keys the platform's resource wiring sets. A topology may not bind them.
RESERVED_ENV_KEYS = frozenset({
    "PROJECT_ID", "ENVIRONMENT", "GOOGLE_CLIENT_ID", "FIREBASE_API_KEY", "FIREBASE_AUTH_DOMAIN",
    "PORT", "K_SERVICE", "K_REVISION", "K_CONFIGURATION", "GCP_PROJECT_ID", "GOOGLE_CLOUD_PROJECT",
})

# Interim resource type catalog (plan §3.4; lane 15b replaces it with the provider schema): type -> attributes a
# consumer may bind, with their primitive type. The first attribute is the default. Anything else is
# TOPOLOGY.RESOURCE_TYPE_UNKNOWN: the architect describes it in a service's `purpose` instead.
BOOTSTRAP_CATALOG: Mapping[str, Tuple[Tuple[str, str], ...]] = {
    "google_storage_bucket": (("name", "string"),),
    "google_pubsub_topic": (("name", "string"), ("id", "string")),
    "google_pubsub_subscription": (("name", "string"),),
    "google_secret_manager_secret": (("secret_id", "string"), ("id", "string")),
    "google_redis_instance": (("host", "string"), ("port", "number")),
    # CLOUDSQL-PASSWORD-BINDING (owner 11-14, P3-b): password_secret_id = the Secret Manager secret id of the database
    # user's password (golden database-cloudsql output secret_id_password); a MODULE_ONLY_ATTRIBUTES attribute,
    # appended so the default attribute (connection_name) is unchanged.
    "google_sql_database_instance": (("connection_name", "string"), ("private_ip_address", "string"),
                                     ("password_secret_id", "string")),
    "google_firestore_database": (("name", "string"),),
    "google_bigquery_dataset": (("dataset_id", "string"),),
    # TI-5-R2 (owner 10-21): AlloyDB, Vertex AI endpoints and Bigtable are typed topology resources, so a service
    # that reads one gets its env binding (and, for the private-network ones, the VPC connector) from the platform.
    # Attributes = exactly what the golden module exports unconditionally (shared/iac_intent.REALIZATION_EXPORTS).
    # TI-5-R2 P3 (owner 10-25): password_secret_id = the Secret Manager secret id of the AlloyDB initial user's
    # password (golden database-alloydb output secret_id_password); a MODULE_ONLY_ATTRIBUTES attribute.
    "google_alloydb_instance": (("ip_address", "string"), ("password_secret_id", "string")),
    "google_vertex_ai_endpoint": (("id", "string"), ("name", "string")),
    "google_bigtable_instance": (("name", "string"),),
}
# TI-5-R2 P3: catalog attributes that are NOT provider-schema attributes of their type: only the golden module that
# realizes the type on the typed-intent path exports them (shared/iac_intent.REALIZATION_EXPORTS). Exact table. On
# the classic path (no realizations) a consumer of one is bound to nothing (a `<type>.<logical>.<attribute>` reference
# would not exist) and validation warns (TOPOLOGY.BINDING_TYPED_ONLY); an extra resource of the type never exports one.
MODULE_ONLY_ATTRIBUTES: Mapping[str, FrozenSet[str]] = {
    "google_alloydb_instance": frozenset({"password_secret_id"}),
    "google_sql_database_instance": frozenset({"password_secret_id"}),   # CLOUDSQL-PASSWORD-BINDING (owner 11-14)
}
# TI5-ALLOYDB-SECRET-BIND (owner 10-27): on the typed-intent path, every service that consumes a resource of one of
# these types (any attribute, env-var kinds) also reads these MODULE_ONLY_ATTRIBUTES attributes, whatever the
# architect listed, so the app can sign in to its database. The env key is `<env_base(logical_name)>_<suffix>`
# (validated identifiers only). A service that already reads the attribute keeps its own key; a derived key that is
# already bound on the service, or is not unique there, or is not a valid name, is not bound (never shadows a
# binding). Exact table. The classic path (no realizations) binds nothing for it, exactly as before.
# CLOUDSQL-PASSWORD-BINDING (owner 11-14, P3-b): Cloud SQL (Postgres and MySQL: one golden module, database-cloudsql)
# the same way; a test pins that every DATABASE_PASSWORD_TYPES type has a row here.
TYPED_IMPLIED_ATTRIBUTES: Mapping[str, Tuple[Tuple[str, str], ...]] = {
    "google_alloydb_instance": (("password_secret_id", "PASSWORD_SECRET_ID"),),
    "google_sql_database_instance": (("password_secret_id", "PASSWORD_SECRET_ID"),),
}
# TI5-ALLOYDB-SECRET-BIND: what the typed-path developer contract tells the app about a module-only attribute it reads
# (exact table; MODULE_ONLY_ATTRIBUTES entries only).
MODULE_ONLY_ATTRIBUTE_NOTES: Mapping[Tuple[str, str], str] = {
    ("google_alloydb_instance", "password_secret_id"):
        "the Secret Manager secret id (in the project PROJECT_ID) of the password of the AlloyDB user `postgres`; "
        "read its `latest` version with the Secret Manager API and sign in as `postgres` with it",
    # CLOUDSQL-PASSWORD-BINDING (owner 11-14): the user and the database are the realizing database-cloudsql
    # module's db_user and database_name (infra/modules/database-cloudsql/variables.tf, defaults app_user / app_db)
    ("google_sql_database_instance", "password_secret_id"):
        "the Secret Manager secret id (in the project PROJECT_ID) of the password of the Cloud SQL database user that "
        "the realizing database-cloudsql module creates (its `db_user`, `app_user` unless the infrastructure sets "
        "another); read its `latest` version with the Secret Manager API and sign in as that user with it to the "
        "module's database (its `database_name`, `app_db` unless the infrastructure sets another) (never a "
        "password literal or a default)",
}
# TI-5-R2: one exact usage note per catalog type the architect could confuse with something else (rendered into the
# topology contract next to the type; types without a note render exactly as before).
CATALOG_NOTES: Mapping[str, str] = {
    "google_alloydb_instance": "password_secret_id is the Secret Manager secret id of the postgres user's password "
                               "(typed infrastructure only)",
    "google_sql_database_instance": "password_secret_id is the Secret Manager secret id of the database user's "
                                    "password (typed infrastructure only)",
    "google_vertex_ai_endpoint": "only for a model the workload deploys to its own endpoint; Gemini and other "
                                 "Google models are called through the Vertex AI API and are never a resource",
}

# Catalog types whose one workload instance the workload foundation itself declares (fresh 10-14 regression report;
# validators/policy_tables.py FOUNDATION_CLASSIFICATION: the (default) Firestore database is platform-owned). A
# topology resource of such a type IS the foundation's instance: its consumers are bound to the foundation's output
# (catalog attribute -> exact `module.foundation` output, infra/modules/workload-foundation/base/outputs.tf) and the
# IaC contract does not ask the AI to declare it (POLICY.PLATFORM_OWNED_TYPE would make it delete the block while the
# rendered binding still referenced it). Exact type table: no logical-name or attribute guessing.
FOUNDATION_PROVIDED: Mapping[str, Mapping[str, str]] = {
    "google_firestore_database": {"name": "module.foundation.database_name"},
}

# A gce-worker reads resources with its OWN service account (L10-v): catalog type -> (compute-gce-worker list input,
# attribute passed). The module grants one exact role per entry (storage.objectUser, pubsub.publisher,
# pubsub.subscriber, secretmanager.secretAccessor, bigquery.dataEditor). Types without a resource-level grant here
# (Firestore, Redis, Cloud SQL) are TOPOLOGY.WORKER_RESOURCE_UNSUPPORTED for a worker consumer.
WORKER_RESOURCE_ACCESS: Mapping[str, Tuple[str, str]] = {
    "google_storage_bucket": ("storage_buckets", "name"),
    "google_pubsub_topic": ("pubsub_topics", "name"),
    "google_pubsub_subscription": ("pubsub_subscriptions", "name"),
    "google_secret_manager_secret": ("secrets", "secret_id"),
    "google_bigquery_dataset": ("bigquery_datasets", "dataset_id"),
}


# ------------------------------------------------------------------------------------------------ wire models
# The architect's LLM response schema nests these (ArchitecturePlanDAG.service_topology). No extra="forbid" on the
# wire models (Gemini schema conversion); the persisted form is the validated canonical dump.
class Scaling(BaseModel):
    min_instances: int = Field(0, ge=0, le=100, description="Minimum instances (Cloud Run)")
    max_instances: int = Field(10, ge=1, le=1000, description="Maximum instances (Cloud Run)")
    cpu_always_allocated: bool = Field(False, description="True only when the spec asks for always-on CPU")


class VmSpec(BaseModel):
    machine_type: MachineType = Field("e2-micro", description="GCE machine type, e.g. e2-micro")
    spot: bool = Field(True, description="Spot provisioning (default true)")
    disk_size_gb: int = Field(10, ge=10, le=2000, description="Boot disk size in GB")


class ServiceSpec(BaseModel):
    name: ServiceName = Field(description="Service name: lower-case letters, digits, '-'; starts with a letter; <= 40 chars")
    kind: ComputeKind = Field(description="cloudrun | event-worker | gke-autopilot | gce-bastion | gce-worker")
    purpose: str = Field("", max_length=300, description="One sentence: what this service does")
    scaling: Optional[Scaling] = Field(None, description="Only when the specification states scaling")
    vm: Optional[VmSpec] = Field(None, description="gce-worker only, when the specification states the VM shape")


class ServiceEdge(BaseModel):
    caller: ServiceName = Field(description="The service that calls")
    callee: ServiceName = Field(description="The service that is called")
    protocol: Literal["http", "pubsub", "launch"] = Field(
        "http", description="http: callee is cloudrun; pubsub: callee is the event-worker; launch: callee is a gce-worker")
    env_key_base: Optional[EnvKey] = Field(None, description="Env var prefix on the caller (default: callee name upper-cased, '-' -> '_')")


# PUSH-PLAN-CHECK (owner 10-28): "this workload's Pub/Sub topic pushes to its cloudrun service S at path P", typed.
# The topic is a `google_pubsub_topic` topology resource (by logical_name), the callee a cloudrun service of the
# topology; one push per topic (the golden messaging-pubsub module has one subscription). The developer's pre-commit
# check (validators/push_plan.py) then requires the typed intent to declare that push. The path is a plain string on
# the wire (a bad path is the typed finding TOPOLOGY.PUSH_PATH_INVALID, not a schema error).
PUSH_TOPIC_TYPE = "google_pubsub_topic"
PUSH_CALLEE_KIND = "cloudrun"


class PushEdge(BaseModel):
    topic: HclIdent = Field(description="logical_name of the google_pubsub_topic resource whose subscription pushes")
    service: ServiceName = Field(description="The cloudrun service the push subscription delivers to")
    path: str = Field(max_length=256, description="The service's URL path that receives the push, e.g. /tasks/process")


class ResourceBinding(BaseModel):
    service: ServiceName = Field(description="The service that reads the resource from its environment")
    env_key: EnvKey = Field(description="The exact environment variable name the service reads")
    attribute: Optional[HclIdent] = Field(None, description="Resource attribute (default: the catalog's first attribute)")


class ResourceSpec(BaseModel):
    type: ProviderType = Field(description="Terraform resource type, e.g. google_storage_bucket")
    logical_name: HclIdent = Field(description="Terraform resource name, e.g. uploads")
    purpose: str = Field("", max_length=300)
    consumers: List[ResourceBinding] = Field(default_factory=list)
    initial_value: Optional[InitialValue] = Field(
        None, description="google_secret_manager_secret only, always set there: 'random' when the workload itself "
                          "makes and uses the value (a signing, HMAC or encryption key no outside system issues; the "
                          "platform stores a random first version), 'operator' when it holds a credential an outside "
                          "system issues (an operator adds it). Omit for every other type.")


class ServiceTopologyIntent(BaseModel):
    services: List[ServiceSpec] = Field(description="Every compute service; [] means foundation-only (no compute)")
    primary_service: Optional[ServiceName] = Field(description="The service deployed on module \"compute\"; null only when services is []")
    edges: List[ServiceEdge] = Field(default_factory=list, description="Directed service-to-service calls; must be acyclic")
    resources: List[ResourceSpec] = Field(default_factory=list, description="Resources services read from env")
    pushes: List[PushEdge] = Field(default_factory=list, description="Pub/Sub push subscriptions to a cloudrun "
                                                                      "service of this workload; [] when none")


# ------------------------------------------------------------------------------------------------ brownfield facts
@dataclass(frozen=True)
class ExistingComputeEntry:
    """One golden compute module call found in the workload repository (exact parse; developer side)."""
    address: str                     # "module.compute", "module.compute_api", "module.bundle.module.app"
    label: str                       # the block's own label
    kind: str                        # COMPUTE_KINDS member (from the resolved golden module directory)
    file: str                        # declaring file (repo-relative)
    root: bool                       # declared in a root-module file of infra/workload/ (not nested)
    service_name: Optional[str] = None   # deployed Cloud Run name when it is a literal or var.product_id
    service_name_expr: Optional[str] = None  # the raw parsed value when it is anything else (diagnostics only)
    indexed: bool = False                # the block has `count` / `for_each` (state addresses are module.x[...])


# ------------------------------------------------------------------------------------------------ helpers
def service_label(name: str, is_primary: bool) -> str:
    """Module label of a topology service: `compute` for the primary, `compute_<name with - -> _>` otherwise."""
    return "compute" if is_primary else "compute_" + name.replace("-", "_")


def worker_short_name(name: str) -> str:
    """The 25-character id stem of a gce-worker, exactly as infra/modules/compute-gce-worker/main.tf `local.short`
    computes it: `replace(substr(name, 0, 25), "/-+$/", "")`."""
    return name[:25].rstrip("-")


def env_base(name: str) -> str:
    return name.upper().replace("-", "_")


def canonical_topology_json(intent: ServiceTopologyIntent) -> str:
    """Canonical JSON of the intent (sorted keys, no whitespace variance): the hashed and persisted form. An absent
    `vm` (every service that is not a gce-worker with a stated shape) is omitted, so a topology without one hashes
    exactly as before the gce-worker kind existed. Likewise an empty `pushes` (PUSH-PLAN-CHECK) is omitted, so a
    topology without a push edge hashes and persists exactly as before. SECRET-INITIAL-VERSION: an absent
    `initial_value` is omitted too, so a topology without one hashes and persists exactly as before."""
    data = intent.model_dump(mode="json")
    for s in data.get("services") or []:
        if s.get("vm") is None:
            s.pop("vm", None)
    if not data.get("pushes"):
        data.pop("pushes", None)
    for r in data.get("resources") or []:
        if r.get("initial_value") is None:
            r.pop("initial_value", None)
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def topology_sha256(intent: ServiceTopologyIntent) -> str:
    return hashlib.sha256(canonical_topology_json(intent).encode("utf-8")).hexdigest()


def strongly_connected_components(nodes: Sequence[str], edges: Iterable[Tuple[str, str]]) -> List[List[str]]:
    """Tarjan's SCC (iterative), deterministic: nodes and successors visited in the given / sorted order.
    Returns every component (singletons included), each in discovery order."""
    succ: Dict[str, List[str]] = {n: [] for n in nodes}
    for a, b in edges:
        if a in succ and b in succ and b not in succ[a]:
            succ[a].append(b)
    for n in succ:
        succ[n].sort()
    index: Dict[str, int] = {}
    low: Dict[str, int] = {}
    on_stack: Dict[str, bool] = {}
    stack: List[str] = []
    out: List[List[str]] = []
    counter = 0
    for root in nodes:
        if root in index:
            continue
        work: List[Tuple[str, int]] = [(root, 0)]
        while work:
            v, i = work.pop()
            if i == 0:
                index[v] = low[v] = counter
                counter += 1
                stack.append(v)
                on_stack[v] = True
            recurse = False
            children = succ[v]
            while i < len(children):
                w = children[i]
                i += 1
                if w not in index:
                    work.append((v, i))
                    work.append((w, 0))
                    recurse = True
                    break
                if on_stack.get(w):
                    low[v] = min(low[v], index[w])
            if recurse:
                continue
            if low[v] == index[v]:
                comp: List[str] = []
                while True:
                    w = stack.pop()
                    on_stack[w] = False
                    comp.append(w)
                    if w == v:
                        break
                out.append(list(reversed(comp)))
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[v])
    return out


def _cycle_path(component: Sequence[str], edges: Iterable[Tuple[str, str]]) -> List[str]:
    """The shortest closed path through the smallest node of a strongly connected component (BFS over sorted
    successors inside the component): deterministic, e.g. ["api", "core", "api"]."""
    members = set(component)
    succ: Dict[str, List[str]] = {n: [] for n in members}
    for a, b in edges:
        if a in members and b in members and b not in succ[a]:
            succ[a].append(b)
    for n in succ:
        succ[n].sort()
    start = min(members)
    prev: Dict[str, str] = {}
    queue: List[str] = []
    for w in succ[start]:
        if w not in prev:
            prev[w] = start
            queue.append(w)
    while queue:
        v = queue.pop(0)
        if start in succ[v]:
            path = [v]
            while path[-1] != start:
                path.append(prev[path[-1]])
            return list(reversed(path)) + [start]
        for w in succ[v]:
            if w not in prev and w != start:
                prev[w] = v
                queue.append(w)
    return sorted(members) + [start]  # unreachable for a real SCC (> 1 node)


# ------------------------------------------------------------------------------------------------ validated topology
_TOKEN = object()


@dataclass(frozen=True)
class ValidatedTopology:
    """A topology that passed `validate_service_topology`. Construct only through the validator."""
    intent: ServiceTopologyIntent
    product_id: str
    sha256: str
    _token: Any = field(default=None, repr=False, compare=False)
    # TI-3 (typed IaC intent, register TI-3d): None = today's binding (`<type>.<logical>.<attribute>`, the address the
    # IaC declares). A mapping = the intent path: {logical: {catalog attribute: expression}} from the gate-clean intent
    # (shared/iac_intent.intent_realizations); a resource with no entry there is bound to nothing (its unrealized slot
    # is the intent gate's finding), so the platform never renders a reference to an address that does not exist.
    realizations: Optional[Mapping[str, Mapping[str, str]]] = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._token is not _TOKEN:
            raise TypeError("ValidatedTopology is constructed only by validate_service_topology")

    def with_realizations(self, realizations: Mapping[str, Mapping[str, str]]) -> "ValidatedTopology":
        """TI-3: the same validated topology, bound to an intent's realizations (see `realizations`)."""
        return ValidatedTopology(self.intent, self.product_id, self.sha256, self._token,
                                 {k: dict(v) for k, v in realizations.items()})

    def _resource_ref(self, rtype: str, logical: str, attr: str) -> Optional[str]:
        """The expression a consumer of `<rtype>.<logical>` reading `attr` is bound to (None = not bound)."""
        foundation = FOUNDATION_PROVIDED.get(rtype, {}).get(attr)
        if foundation:
            return foundation
        if self.realizations is None:
            if attr in MODULE_ONLY_ATTRIBUTES.get(rtype, ()):
                return None   # TI-5-R2 P3: classic path, no such schema attribute (TOPOLOGY.BINDING_TYPED_ONLY)
            return f"{rtype}.{logical}.{attr}"
        return (self.realizations.get(logical) or {}).get(attr)

    # -- services
    @property
    def services(self) -> Tuple[ServiceSpec, ...]:
        return tuple(self.intent.services)

    @property
    def names(self) -> Tuple[str, ...]:
        """Primary first, then the secondaries in the architect's order."""
        p = self.intent.primary_service
        return tuple(([p] if p else []) + [s.name for s in self.intent.services if s.name != p])

    @property
    def primary(self) -> Optional[ServiceSpec]:
        return self.spec(self.intent.primary_service) if self.intent.primary_service else None

    @property
    def archetype(self) -> str:
        return self.primary.kind if self.primary else FOUNDATION_ONLY

    @property
    def secondaries(self) -> Tuple[ServiceSpec, ...]:
        p = self.intent.primary_service
        return tuple(s for s in self.intent.services if s.name != p)

    def secondaries_of_kind(self, kind: str) -> Tuple[str, ...]:
        return tuple(s.name for s in self.secondaries if s.kind == kind)

    def spec(self, name: str) -> Optional[ServiceSpec]:
        for s in self.intent.services:
            if s.name == name:
                return s
        return None

    def kind(self, name: str) -> Optional[str]:
        s = self.spec(name)
        return s.kind if s else None

    def label(self, name: str) -> str:
        return service_label(name, name == self.intent.primary_service)

    @property
    def http_entrypoint(self) -> Optional[str]:
        """The service the QA probe targets: the primary when it is Cloud Run, else the first Cloud Run service."""
        if self.primary and self.primary.kind == "cloudrun":
            return self.primary.name
        for s in self.intent.services:
            if s.kind == "cloudrun":
                return s.name
        return None

    # -- wiring
    def edge_env(self, caller: str) -> Dict[str, str]:
        """Env bindings on `caller` from its outgoing edges: `<BASE>_URL` / `<BASE>_AUDIENCE` =
        `module.<callee label>.service_uri` (http), `<BASE>_TOPIC` = `module.<callee label>.topic_name` (pubsub).
        Assembled only from validated identifiers and the capability table."""
        out: Dict[str, str] = {}
        for e in self.intent.edges:
            if e.caller != caller:
                continue
            cap = CAPABILITIES[self.kind(e.callee) or ""]
            base = e.env_key_base or env_base(e.callee)
            for suffix, output in cap.callee_outputs:
                out[f"{base}_{suffix}"] = f"module.{self.label(e.callee)}.{output}"
        return dict(sorted(out.items()))

    def resource_env(self, service: str) -> Dict[str, str]:
        """Env bindings on `service` from `resources[].consumers`: `<env_key>` = `<type>.<logical>.<attribute>`
        (`tostring(...)` for non-string catalog attributes); a FOUNDATION_PROVIDED type binds its exact
        `module.foundation` output instead."""
        if not CAPABILITIES[self.kind(service) or "cloudrun"].accepts_env_vars:
            return {}   # TOPOLOGY.BINDING_NOT_RENDERED (warning): e.g. GKE env lives in k8s manifests
        return self.resource_bindings(service)

    def resource_bindings(self, service: str) -> Dict[str, str]:
        """`service`'s `resources[].consumers` bindings as `resource_env` renders them, whatever the kind's env
        input (gce-bastion-network: a gce-bastion gets them as instance metadata attributes)."""
        out: Dict[str, str] = {}
        for r in self.intent.resources:
            attrs = dict(BOOTSTRAP_CATALOG.get(r.type, ()))
            default_attr = BOOTSTRAP_CATALOG[r.type][0][0] if r.type in BOOTSTRAP_CATALOG else None
            for c in r.consumers:
                if c.service != service:
                    continue
                attr = c.attribute or default_attr
                ref = self._resource_ref(r.type, r.logical_name, attr)
                if ref is None:   # TI-3: not realized by the intent (gate finding): nothing is bound
                    continue
                out[c.env_key] = ref if attrs.get(attr) == "string" else f"tostring({ref})"
        if self.realizations is not None:   # TI5-ALLOYDB-SECRET-BIND: typed path only
            for svc, rtype, logical, attr, key in self.implied_consumers():
                if svc != service:
                    continue
                ref = self._resource_ref(rtype, logical, attr)
                if ref is not None:
                    out[key] = ref if dict(BOOTSTRAP_CATALOG[rtype]).get(attr) == "string" else f"tostring({ref})"
        return dict(sorted(out.items()))

    def implied_consumers(self) -> Tuple[Tuple[str, str, str, str, str], ...]:
        """TI5-ALLOYDB-SECRET-BIND (owner 10-27): the typed-path bindings the platform adds to the architect's
        consumers (TYPED_IMPLIED_ATTRIBUTES), as (service, type, logical, attribute, env key), in resource order. Only
        env-var kinds; only a service that consumes the resource and does not already read the attribute; the key is
        `<env_base(logical)>_<suffix>` and is skipped when it is not a valid name, is already bound on the service (an
        edge or a consumer key) or is derived twice there. Pure function of the validated intent."""
        explicit: Dict[str, set] = {}
        for svc in self.names:
            explicit[svc] = set(self.edge_env(svc)) | {c.env_key for r in self.intent.resources for c in r.consumers
                                                        if c.service == svc}
        cand: List[Tuple[str, str, str, str, str]] = []
        for r in self.intent.resources:
            for attr, suffix in TYPED_IMPLIED_ATTRIBUTES.get(r.type, ()):
                key = f"{env_base(r.logical_name)}_{suffix}"
                for svc in dict.fromkeys(c.service for c in r.consumers):
                    if not CAPABILITIES[self.kind(svc) or "cloudrun"].accepts_env_vars:
                        continue
                    if any(c.service == svc and c.attribute == attr for c in r.consumers):
                        continue   # the architect's own key for it wins
                    cand.append((svc, r.type, r.logical_name, attr, key))
        derived: Dict[Tuple[str, str], int] = {}
        for svc, _t, _l, _a, key in cand:
            derived[(svc, key)] = derived.get((svc, key), 0) + 1
        return tuple(x for x in cand if _env_key_ok(x[4]) and x[4] not in RESERVED_ENV_KEYS
                     and x[4] not in explicit.get(x[0], set()) and derived[(x[0], x[4])] == 1)

    def typed_only_bindings(self, service: str) -> Dict[str, Tuple[str, str]]:
        """TI-5-R2 P3 + TI5-ALLOYDB-SECRET-BIND: {env key: (type, attribute)} on `service` for the bindings that read a
        MODULE_ONLY_ATTRIBUTES attribute: the architect's consumers of one and the implied_consumers. Bound only on the
        typed-intent path (by the realizing golden module's output)."""
        if not CAPABILITIES[self.kind(service) or "cloudrun"].accepts_env_vars:
            return {}
        out = {c.env_key: (r.type, c.attribute) for r in self.intent.resources for c in r.consumers
               if c.service == service and c.attribute is not None
               and c.attribute in MODULE_ONLY_ATTRIBUTES.get(r.type, ())}
        out.update({key: (rtype, attr) for svc, rtype, _l, attr, key in self.implied_consumers() if svc == service})
        return dict(sorted(out.items()))

    def typed_binding_notes(self, service: str) -> Dict[str, str]:
        """TI5-ALLOYDB-SECRET-BIND: {env key: MODULE_ONLY_ATTRIBUTE_NOTES note} for `service`'s typed_only_bindings
        that have a note (the typed-path developer contract states what the key holds)."""
        return {k: MODULE_ONLY_ATTRIBUTE_NOTES[ta] for k, ta in self.typed_only_bindings(service).items()
                if ta in MODULE_ONLY_ATTRIBUTE_NOTES}

    def typed_only_env_keys(self, service: str) -> Tuple[str, ...]:
        """TI-5-R2 P3: the env keys on `service` whose binding reads a MODULE_ONLY_ATTRIBUTES attribute (the architect's
        and, TI5-ALLOYDB-SECRET-BIND, the implied ones). Bound only on the typed-intent path (by the realizing golden
        module's output), so an unbound topology's env_for omits them; the developer contract of the typed path lists
        them (topology_wiring.topology_contract_rule)."""
        return tuple(self.typed_only_bindings(service))

    def env_for(self, service: str) -> Dict[str, str]:
        """Everything the topology binds on `service` (edges, then resources; disjoint by validation)."""
        env = self.edge_env(service)
        env.update(self.resource_env(service))
        return dict(sorted(env.items()))

    def declared_resources(self) -> Tuple[Tuple[str, str], ...]:
        """The resources the workload IaC declares (custom.tf): every topology resource except FOUNDATION_PROVIDED
        types, which module.foundation declares."""
        return tuple((r.type, r.logical_name) for r in self.intent.resources if r.type not in FOUNDATION_PROVIDED)

    def realization_needs(self) -> Dict[str, Tuple[str, Tuple[str, ...]]]:
        """TI-3: {logical: (type, catalog attributes the platform binds)} for every resource the workload IaC declares
        (declared_resources): the consumers' attributes, plus the gce-worker grant attribute (WORKER_RESOURCE_ACCESS)
        when a gce-worker consumes it, plus (TI5-ALLOYDB-SECRET-BIND) the implied_consumers' attributes. The intent's
        realizing entry must export each of them."""
        out: Dict[str, Tuple[str, Tuple[str, ...]]] = {}
        implied = self.implied_consumers()
        for r in self.intent.resources:
            if r.type in FOUNDATION_PROVIDED:
                continue
            default_attr = BOOTSTRAP_CATALOG[r.type][0][0] if r.type in BOOTSTRAP_CATALOG else None
            attrs = {c.attribute or default_attr for c in r.consumers} - {None}
            attrs |= {a for _s, t, lg, a, _k in implied if (t, lg) == (r.type, r.logical_name)}
            if r.type in WORKER_RESOURCE_ACCESS and any(self.kind(c.service) == "gce-worker" for c in r.consumers):
                attrs.add(WORKER_RESOURCE_ACCESS[r.type][1])
            out[r.logical_name] = (r.type, tuple(sorted(attrs)))
        return out

    def secret_initial_values(self) -> Dict[str, Optional[str]]:
        """SECRET-INITIAL-VERSION: {logical: initial_value or None} for every SECRET_RESOURCE_TYPE resource the
        workload IaC declares, in resource order (validated data only)."""
        return {r.logical_name: r.initial_value for r in self.intent.resources
                if r.type == SECRET_RESOURCE_TYPE and r.type not in FOUNDATION_PROVIDED}

    def foundation_resources(self) -> Tuple[Tuple[str, str], ...]:
        """The topology resources the workload foundation provides (FOUNDATION_PROVIDED types)."""
        return tuple((r.type, r.logical_name) for r in self.intent.resources if r.type in FOUNDATION_PROVIDED)

    def foundation_outputs(self) -> Tuple[str, ...]:
        """The module.foundation outputs the FOUNDATION_PROVIDED resources' catalog attributes bind (sorted)."""
        return tuple(sorted({FOUNDATION_PROVIDED[t].get(a, "") for t, _ in self.foundation_resources()
                             for a, _ in BOOTSTRAP_CATALOG.get(t, ())} - {""}))

    def worker_access(self, worker: str) -> Dict[str, List[str]]:
        """compute-gce-worker list inputs for `worker`'s own-SA grants: input -> sorted unique references
        `<type>.<logical>.<attribute>` (WORKER_RESOURCE_ACCESS; validated identifiers only)."""
        out: Dict[str, set] = {}
        for r in self.intent.resources:
            if r.type not in WORKER_RESOURCE_ACCESS or not any(c.service == worker for c in r.consumers):
                continue
            var, attr = WORKER_RESOURCE_ACCESS[r.type]
            ref = self._resource_ref(r.type, r.logical_name, attr)
            if ref is not None:   # TI-3: an unrealized resource is granted nothing (gate finding)
                out.setdefault(var, set()).add(ref)
        return {k: sorted(v) for k, v in sorted(out.items())}

    def launchers(self, worker: str) -> Tuple[str, ...]:
        """The services with a launch edge to `worker` (validated: cloudrun only)."""
        return tuple(sorted({e.caller for e in self.intent.edges if e.protocol == "launch" and e.callee == worker}))

    @property
    def pushes(self) -> Tuple[PushEdge, ...]:
        """PUSH-PLAN-CHECK: the validated push edges (topic resource -> cloudrun service at path), in the architect's
        order; () when the topology declares none."""
        return tuple(self.intent.pushes)

    def canonical_dict(self) -> Dict[str, Any]:
        return json.loads(canonical_topology_json(self.intent))

    def as_record(self) -> Dict[str, Any]:
        """The persisted form (inside architect_compute_intent): data only, never an HCL source."""
        return {"schema": TOPOLOGY_RECORD_SCHEMA, "intent": self.canonical_dict(), "sha256": self.sha256,
                "archetype": self.archetype, "service_names": list(self.names),
                "http_entrypoint": self.http_entrypoint}


# ------------------------------------------------------------------------------------------------ validator
def _diag(code: str, message: str, *, cls: ErrorClass, file: str, source: str, path: str = "",
          severity: str = "error", detail: Optional[str] = None, hint: Optional[str] = None,
          symbol: Optional[str] = None) -> Diagnostic:
    return Diagnostic(tool="topology", code=code, severity=severity, error_class=cls, file=file,
                      block_address=path or None, message=message, detail=detail, hint=hint, symbol=symbol,
                      source=source)


def _loc(loc: Sequence[Any]) -> str:
    out = ""
    for part in loc:
        out += f"[{part}]" if isinstance(part, int) else (f".{part}" if out else str(part))
    return out


def validate_service_topology(
    raw: Any,
    *,
    product_id: str,
    existing: Optional[Sequence[ExistingComputeEntry]] = None,
    approved_removals: Iterable[str] = (),
    file: str = "architect:service_topology",
    source: str = "architect",
    expected_archetype: Optional[str] = None,
) -> Tuple[Optional[ValidatedTopology], List[Diagnostic]]:
    """Validate a topology (a `ServiceTopologyIntent`, its dict form, or None) and return
    `(ValidatedTopology | None, diagnostics)`. Errors -> no ValidatedTopology. Diagnostics are sorted by
    `(code, block_address)`; the input is never changed.

    `existing` (developer side): the compute modules already in the repository; mismatches are BROWNFIELD_CONFLICT.
    `expected_archetype`: the plan's separately stated `compute_archetype`; a different primary kind is an
    architect defect (TOPOLOGY.ARCHETYPE_MISMATCH), never resolved by picking one.
    """
    A = ErrorClass.ARCHITECT_DEFECT
    B = ErrorClass.BROWNFIELD_CONFLICT
    diags: List[Diagnostic] = []

    def add(code: str, message: str, path: str = "", cls: ErrorClass = A, **kw: Any) -> None:
        diags.append(_diag(code, message, cls=cls, file=file, source=source, path=path, **kw))

    if raw is None:
        add("TOPOLOGY.MISSING", "the plan has no service_topology",
            hint="Return service_topology with every compute service, its kind, the primary and the edges.")
        return None, _sorted(diags)
    try:
        intent = raw if isinstance(raw, ServiceTopologyIntent) else ServiceTopologyIntent.model_validate(raw)
    except ValidationError as e:
        for err in e.errors():
            add("TOPOLOGY.SCHEMA_INVALID", f"{_loc(err.get('loc', ()))}: {err.get('msg', 'invalid')}",
                path=_loc(err.get("loc", ())))
        return None, _sorted(diags)

    names = [s.name for s in intent.services]
    kinds = {s.name: s.kind for s in intent.services}
    seen: set = set()
    for i, n in enumerate(names):
        if n in seen:
            add("TOPOLOGY.DUPLICATE_SERVICE", f"service '{n}' is listed more than once", path=f"services[{i}].name")
        seen.add(n)

    primary = intent.primary_service
    if not intent.services:
        if primary is not None:
            add("TOPOLOGY.PRIMARY_WITHOUT_SERVICES", f"primary_service '{primary}' is set but services is []",
                path="primary_service")
    elif primary is None:
        add("TOPOLOGY.PRIMARY_MISSING", "services is not empty but primary_service is null", path="primary_service")
    elif primary not in kinds:
        add("TOPOLOGY.PRIMARY_UNKNOWN", f"primary_service '{primary}' is not a listed service", path="primary_service")

    if expected_archetype is not None:
        actual = kinds.get(primary or "", FOUNDATION_ONLY) if intent.services else FOUNDATION_ONLY
        if actual != expected_archetype:
            add("TOPOLOGY.ARCHETYPE_MISMATCH",
                f"compute_archetype is '{expected_archetype}' but service_topology's primary kind is '{actual}'",
                path="primary_service", hint="compute_archetype must equal the primary service's kind "
                                             "('foundation-only' when services is []).")

    for i, s in enumerate(intent.services):
        cap = CAPABILITIES[s.kind]
        if s.name != primary and primary in kinds and not cap.allowed_as_secondary:
            add("TOPOLOGY.KIND_NOT_ALLOWED_AS_SECONDARY",
                f"service '{s.name}' has kind '{s.kind}', which can only be the primary", path=f"services[{i}].kind")
        if s.name == primary and not cap.allowed_as_primary:
            add("TOPOLOGY.KIND_NOT_ALLOWED_AS_PRIMARY",
                f"service '{s.name}' has kind '{s.kind}', which can only be a secondary", path="primary_service",
                hint="A gce-worker is launched by a cloudrun service; make that service the primary.")
        if s.vm is not None and s.kind != "gce-worker":
            add("TOPOLOGY.VM_SHAPE_NOT_ALLOWED", f"service '{s.name}' has kind '{s.kind}'; only a gce-worker has `vm`",
                path=f"services[{i}].vm")
    workers = sorted({s.name for s in intent.services if s.kind == "gce-worker"})
    for i, a in enumerate(workers):
        for b in workers[i + 1:]:
            sa, sb = worker_short_name(a), worker_short_name(b)
            if sa == sb or b.startswith(a + "-") or a.startswith(b + "-") or sb.startswith(sa + "-") or \
                    sa.startswith(sb + "-"):
                add("TOPOLOGY.WORKER_NAME_COLLISION",
                    f"gce-workers '{a}' and '{b}' collide: the same 25-character resource id ('gcew-{sa}' / "
                    f"'gcew-{sb}') or nested name prefixes (their launch grant prefixes would overlap)",
                    path="services", symbol=f"{a},{b}", hint="Give each gce-worker a name that is not a prefix of "
                                                             "another and differs within its first 25 characters.")
    for kind, cap in CAPABILITIES.items():
        count = sum(1 for s in intent.services if s.kind == kind)
        if cap.max_per_workload is not None and count > cap.max_per_workload:
            add("TOPOLOGY.KIND_COUNT_EXCEEDED",
                f"{count} services have kind '{kind}'; at most {cap.max_per_workload} per workload", path="services",
                symbol=kind)

    # edges
    graph: List[Tuple[str, str]] = []
    edge_keys: set = set()
    callee_unsupported: List[int] = []   # AC-4: edges whose ONLY defect is the callee's kind (see the env-key pass)
    for i, e in enumerate(intent.edges):
        p = f"edges[{i}]"
        bad = False
        for end in ("caller", "callee"):
            if getattr(e, end) not in kinds:
                add("TOPOLOGY.EDGE_UNKNOWN_SERVICE", f"{end} '{getattr(e, end)}' is not a listed service",
                    path=f"{p}.{end}")
                bad = True
        if bad:
            continue
        if e.caller == e.callee:
            add("TOPOLOGY.SELF_EDGE", f"service '{e.caller}' calls itself", path=p)
            continue
        key = (e.caller, e.callee, e.protocol)
        if key in edge_keys:
            add("TOPOLOGY.DUPLICATE_EDGE", f"edge {e.caller} -> {e.callee} ({e.protocol}) is listed more than once",
                path=p)
            continue
        edge_keys.add(key)
        callee_cap = CAPABILITIES[kinds[e.callee]]
        if callee_cap.callee_protocol != e.protocol:
            add("TOPOLOGY.EDGE_CALLEE_UNSUPPORTED",
                f"a '{e.protocol}' edge cannot target '{e.callee}' (kind '{kinds[e.callee]}'); "
                f"http edges target cloudrun services, pubsub edges target the event-worker, launch edges target a "
                f"gce-worker", path=f"{p}.callee")
            if _caller_can_bind(kinds[e.caller], e.protocol):
                callee_unsupported.append(i)
            continue
        if not CAPABILITIES[kinds[e.caller]].can_call:
            add("TOPOLOGY.EDGE_CALLER_UNSUPPORTED",
                f"'{e.caller}' (kind '{kinds[e.caller]}') cannot be the caller of an {e.protocol} edge; a worker "
                f"reaches other services only through declared resources", path=f"{p}.caller")
            continue
        if e.protocol == "launch" and not CAPABILITIES[kinds[e.caller]].can_launch:
            add("TOPOLOGY.LAUNCH_CALLER_UNSUPPORTED",
                f"'{e.caller}' (kind '{kinds[e.caller]}') cannot launch gce-worker '{e.callee}'; only a cloudrun "
                f"service launches workers", path=f"{p}.caller")
            continue
        if not CAPABILITIES[kinds[e.caller]].accepts_env_vars:
            add("TOPOLOGY.EDGE_CALLER_NO_ENV_INPUT",
                f"caller '{e.caller}' (kind '{kinds[e.caller]}') has no env_vars input, so it cannot be wired",
                path=f"{p}.caller")
            continue
        graph.append((e.caller, e.callee))

    launched = {e.callee for e in intent.edges if e.protocol == "launch" and (e.caller, e.callee) in graph}
    for i, s in enumerate(intent.services):
        if s.kind == "gce-worker" and s.name != primary and s.name not in launched:
            add("TOPOLOGY.WORKER_NOT_LAUNCHED",
                f"gce-worker '{s.name}' has no launch edge from a cloudrun service, so nothing can start it",
                path=f"services[{i}]", hint="Add an edge {caller: <cloudrun service>, callee: "
                                            f"'{s.name}', protocol: launch}}.")

    unique_names = list(dict.fromkeys(names))
    for comp in strongly_connected_components(unique_names, graph):
        if len(comp) > 1:
            path = _cycle_path(comp, graph)
            add("TOPOLOGY.CYCLE", "service calls form a cycle: " + " -> ".join(path), path="edges",
                detail=json.dumps(path), hint="Route one direction through Pub/Sub (pubsub edge to the "
                                              "event-worker) or invert the call; Invariant 6 forbids A->B->A.")

    # resources
    res_keys: set = set()
    bindings: Dict[str, Dict[str, str]] = {}   # service -> env key -> origin
    for i, r in enumerate(intent.resources):
        p = f"resources[{i}]"
        if (r.type, r.logical_name) in res_keys:
            add("TOPOLOGY.DUPLICATE_RESOURCE", f"resource {r.type}.{r.logical_name} is listed more than once", path=p)
        res_keys.add((r.type, r.logical_name))
        if r.type not in BOOTSTRAP_CATALOG:
            add("TOPOLOGY.RESOURCE_TYPE_UNKNOWN",
                f"resource type '{r.type}' is not one of {sorted(BOOTSTRAP_CATALOG)}", path=f"{p}.type",
                hint="List only catalog types in resources; describe anything else in a service's purpose.")
            continue
        # SECRET-INITIAL-VERSION: who supplies the value is a secret's fact only. On a secret, absent is valid and adds
        # no finding (a record written before the field keeps its meaning, and the topology repair prompt, which lists
        # every finding, stays byte-identical); the pre-build gate names such a secret (SECRET.VALUE_SOURCE_UNSTATED).
        if r.initial_value is not None and r.type not in INITIAL_VALUE_TYPES:
            add("TOPOLOGY.INITIAL_VALUE_NOT_APPLICABLE",
                f"initial_value is set on {r.type}.{r.logical_name}; only {sorted(INITIAL_VALUE_TYPES)} take one",
                path=f"{p}.initial_value", hint="Remove initial_value from this resource.")
        attrs = [a for a, _ in BOOTSTRAP_CATALOG[r.type]]
        for j, c in enumerate(r.consumers):
            cp = f"{p}.consumers[{j}]"
            if (r.initial_value == INITIAL_VALUE_RANDOM and r.type in INITIAL_VALUE_TYPES
                    and (c.attribute or attrs[0]) not in GENERATED_SECRET_ATTRIBUTES):
                add("TOPOLOGY.SECRET_ATTRIBUTE_NOT_GENERATED",
                    f"{c.env_key} reads '{c.attribute}' of {r.type}.{r.logical_name}, whose first version the platform "
                    f"generates; such a secret exports only {sorted(GENERATED_SECRET_ATTRIBUTES)}",
                    path=f"{cp}.attribute", hint="Read secret_id (omit attribute).")
            if c.service not in kinds:
                add("TOPOLOGY.RESOURCE_CONSUMER_UNKNOWN", f"consumer '{c.service}' is not a listed service",
                    path=f"{cp}.service")
                continue
            if c.attribute is not None and c.attribute not in attrs:
                add("TOPOLOGY.RESOURCE_ATTRIBUTE_UNSUPPORTED",
                    f"attribute '{c.attribute}' of {r.type} is not one of {attrs}", path=f"{cp}.attribute")
                continue
            if kinds[c.service] == "gce-worker" and r.type not in WORKER_RESOURCE_ACCESS:
                add("TOPOLOGY.WORKER_RESOURCE_UNSUPPORTED",
                    f"gce-worker '{c.service}' cannot be granted access to {r.type}; a worker reads only "
                    f"{sorted(WORKER_RESOURCE_ACCESS)}", path=f"{cp}.service")
                continue
            if not CAPABILITIES[kinds[c.service]].accepts_env_vars:
                add("TOPOLOGY.BINDING_NOT_RENDERED",
                    f"'{c.service}' (kind '{kinds[c.service]}') has no env_vars input; {c.env_key} is not rendered "
                    f"by the platform", path=cp, severity="warning")
                continue
            if c.attribute is not None and c.attribute in MODULE_ONLY_ATTRIBUTES.get(r.type, ()):
                add("TOPOLOGY.BINDING_TYPED_ONLY",
                    f"{c.env_key} reads '{c.attribute}' of {r.type}, which only the golden module exports: it is "
                    f"bound when the workload's infrastructure is typed (generate mode), not on the classic path",
                    path=f"{cp}.attribute", severity="warning")
            bindings.setdefault(c.service, {}).setdefault(c.env_key, cp)

    # PUSH-PLAN-CHECK: push edges (topic resource -> cloudrun service at a closed-grammar path), one per topic
    topic_types = {r.logical_name: r.type for r in intent.resources}
    pushed: Dict[str, int] = {}
    for i, e in enumerate(intent.pushes):
        p = f"pushes[{i}]"
        if topic_types.get(e.topic) != PUSH_TOPIC_TYPE:
            add("TOPOLOGY.PUSH_TOPIC_UNKNOWN",
                f"push topic '{e.topic}' is not a listed {PUSH_TOPIC_TYPE} resource", path=f"{p}.topic",
                symbol=e.topic, hint=f"Set topic to the logical_name of a {PUSH_TOPIC_TYPE} entry of resources (add "
                                     "that resource if the workload has none).")
        elif e.topic in pushed:
            add("TOPOLOGY.DUPLICATE_PUSH",
                f"topic '{e.topic}' pushes more than once (pushes[{pushed[e.topic]}] and {p}); a topic has one push "
                f"subscription", path=p, symbol=e.topic)
        else:
            pushed[e.topic] = i
        if e.service not in kinds:
            add("TOPOLOGY.PUSH_UNKNOWN_SERVICE", f"push service '{e.service}' is not a listed service",
                path=f"{p}.service", symbol=e.service)
        elif kinds[e.service] != PUSH_CALLEE_KIND:
            add("TOPOLOGY.PUSH_TARGET_UNSUPPORTED",
                f"a push cannot target '{e.service}' (kind '{kinds[e.service]}'); pushes go to a "
                f"{PUSH_CALLEE_KIND} service of this workload", path=f"{p}.service", symbol=e.service,
                hint="The event-worker reads its own pull subscription: describe that with a pubsub edge instead.")
        if not push_path_ok(e.path):
            add("TOPOLOGY.PUSH_PATH_INVALID",
                f"push path {e.path!r} is not a literal URL path that starts with / (letters, digits and "
                "._~!&'()*+,;=/- only; no empty, \".\" or \"..\" segment)", path=f"{p}.path",
                hint="Use the exact endpoint path of the service that receives the push, e.g. /api/v1/tasks/process.")

    # env keys: edges + bindings, per caller
    edge_owner: Dict[Tuple[str, str], int] = {}   # (caller, key) -> index of the valid edge that bound it (AC-4)
    for i, e in enumerate(intent.edges):
        if (e.caller, e.callee) not in graph:
            continue
        base = e.env_key_base or env_base(e.callee)
        for suffix, _ in CAPABILITIES[kinds[e.callee]].callee_outputs:
            key = f"{base}_{suffix}"
            owner = bindings.setdefault(e.caller, {})
            if key in owner:
                add("TOPOLOGY.ENV_KEY_COLLISION",
                    f"'{e.caller}' would receive {key} twice (edges[{i}] and {owner[key]})", path=f"edges[{i}]",
                    symbol=key)
            else:
                owner[key] = f"edges[{i}]"
                edge_owner[(e.caller, key)] = i
    # AC-4 (10-14 06-r1): an edge rejected only as EDGE_CALLEE_UNSUPPORTED still states its protocol, and that
    # protocol fixes the keys the caller would receive (the callee_outputs of the one kind serving it). A clash with
    # another binding of the caller is reported now, beside the kind defect, instead of after the kind is repaired.
    # Exact: the same key derivation as above; the keys are only checked, never registered (no follow-on findings).
    # The finding is emitted exactly as the pass above will emit it once the kind is fixed (same path, message and
    # symbol, so the same fingerprint): edges are registered in index order, so when the owner is a LATER edge j > i,
    # edge i would register first and edge j would be the one reported (Opus RT F1).
    for i in callee_unsupported:
        e = intent.edges[i]
        base = e.env_key_base or env_base(e.callee)
        owner = bindings.get(e.caller, {})
        for suffix, _ in CAPABILITIES[PROTOCOL_CALLEE_KIND[e.protocol]].callee_outputs:
            key = f"{base}_{suffix}"
            if key in owner:
                j = edge_owner.get((e.caller, key))
                at, other = (f"edges[{j}]", f"edges[{i}]") if j is not None and j > i else (f"edges[{i}]", owner[key])
                add("TOPOLOGY.ENV_KEY_COLLISION",
                    f"'{e.caller}' would receive {key} twice ({at} and {other})", path=at,
                    symbol=key, hint=_EDGE_KEY_HINT[e.protocol].format(key=key, other=other))
    for i, r in enumerate(intent.resources):
        for j, c in enumerate(r.consumers):
            cp = f"resources[{i}].consumers[{j}]"
            owner = bindings.get(c.service, {})
            if c.env_key in owner and owner[c.env_key] != cp:
                add("TOPOLOGY.ENV_KEY_COLLISION",
                    f"'{c.service}' would receive {c.env_key} twice ({owner[c.env_key]} and {cp})", path=cp,
                    symbol=c.env_key)
    for svc, keys in bindings.items():
        for key, origin in keys.items():
            if key in RESERVED_ENV_KEYS:
                add("TOPOLOGY.ENV_KEY_RESERVED", f"{key} on '{svc}' is set by the platform itself", path=origin,
                    symbol=key)
            elif not _env_key_ok(key):
                add("TOPOLOGY.SCHEMA_INVALID", f"derived env key '{key}' on '{svc}' is not a valid name", path=origin)

    # brownfield guard (developer): existing compute must survive unchanged
    if existing:
        _brownfield(intent, kinds, primary, product_id, list(existing), set(approved_removals),
                    lambda code, msg, path="", **kw: add(code, msg, path, cls=B, **kw))

    if any(d.severity == "error" for d in diags):
        return None, _sorted(diags)
    vt = ValidatedTopology(intent=intent, product_id=product_id, sha256=topology_sha256(intent), _token=_TOKEN)
    return vt, _sorted(diags)


def _env_key_ok(key: str) -> bool:
    return re.fullmatch(ENV_KEY_PATTERN, key) is not None


def _brownfield(intent: ServiceTopologyIntent, kinds: Mapping[str, str], primary: Optional[str], product_id: str,
                existing: List[ExistingComputeEntry], approved: set, add: Any) -> None:
    """Every existing compute module must map to a topology service at the address the platform renders, with the
    same kind and deployed name. Mapping is by exact label: root `compute` = primary; root `compute_<x>` = the
    service named x ('_' -> '-'). Anything else (nested in a local composite, Express `worker_<k>` / `mod_<k>`,
    bundle labels) cannot be pinned by the topology renderer: refused, never re-addressed (RT F1)."""
    for ent in sorted(existing, key=lambda x: x.address):
        if ent.address in approved:
            continue
        if ent.indexed:   # RT F5: the renderer emits an un-indexed block; module.x["k"] would be replaced
            add("TOPOLOGY.LEGACY_SHAPE_UNSUPPORTED",
                f"existing compute {ent.address} ({ent.kind}, {ent.file}) uses count/for_each; the topology renders "
                f"one un-indexed module per service", symbol=ent.address,
                hint="Operator: migrate or decommission this module before regenerating with a service topology.")
            continue
        if not ent.root or not (ent.label == "compute" or ent.label.startswith("compute_")):
            add("TOPOLOGY.LEGACY_SHAPE_UNSUPPORTED",
                f"existing compute {ent.address} ({ent.kind}, {ent.file}) is not at an address the topology "
                f"renders (module \"compute\" or module \"compute_<service>\" in a root file)", symbol=ent.address,
                hint="Operator: migrate or decommission this module before regenerating with a service topology.")
            continue
        if ent.label == "compute":
            name = primary
            if not intent.services:
                add("TOPOLOGY.COMPUTE_REMOVED", f"existing {ent.address} ({ent.kind}) would be removed: the new "
                    f"topology has no services", symbol=ent.address)
                continue
        else:
            name = ent.label[len("compute_"):].replace("_", "-")
            if name not in kinds:
                add("TOPOLOGY.COMPUTE_REMOVED", f"existing {ent.address} ({ent.kind}) has no service '{name}' in "
                    f"the new topology", symbol=ent.address,
                    hint="Removing a deployed service needs decommission (FD-4Q). Re-plan with every existing "
                         f"service kept: {_existing_summary(existing)}.")
                continue
            if name == primary:
                add("TOPOLOGY.PRIMARY_CHANGED", f"existing secondary {ent.address} would become the primary "
                    f"module.compute", symbol=ent.address)
                continue
        if name is None or name not in kinds:
            continue
        if kinds[name] != ent.kind:
            add("TOPOLOGY.KIND_CHANGED", f"existing {ent.address} is '{ent.kind}' but the topology makes '{name}' a "
                f"'{kinds[name]}'", symbol=ent.address)
            continue
        if ent.kind == "cloudrun":
            if ent.service_name is None:
                add("TOPOLOGY.LEGACY_NAME_EXPR_UNSUPPORTED", f"existing {ent.address} service_name is "
                    f"{ent.service_name_expr!r}, not a literal or var.product_id", symbol=ent.address)
            elif ent.service_name != name:
                add("TOPOLOGY.DEPLOYED_NAME_CHANGED", f"existing {ent.address} deploys Cloud Run service "
                    f"'{ent.service_name}' but the topology names it '{name}' (a rename replaces the live service)",
                    symbol=ent.address)


def _existing_summary(existing: Sequence[ExistingComputeEntry]) -> str:
    """The existing services as the operator / a re-plan must keep them (exact labels; no inference)."""
    out = []
    for e in sorted(existing, key=lambda x: x.address):
        name = e.service_name or (e.label[len("compute_"):].replace("_", "-") if e.label.startswith("compute_")
                                  else e.label)
        out.append(f"{e.address}={e.kind}:{name}")
    return ", ".join(out)


def _sorted(diags: List[Diagnostic]) -> List[Diagnostic]:
    return sorted(diags, key=lambda d: (d.code, d.block_address or "", d.symbol or "", d.message))


# ------------------------------------------------------------------------------------------------ record / review file
TOPOLOGY_JSON_PATH = "infra/workload/topology.json"


def topology_from_record(record: Any, *, product_id: str, file: str = "architect_compute_intent.service_topology",
                         source: str = "precommit", existing: Optional[Sequence[ExistingComputeEntry]] = None
                         ) -> Tuple[Optional[ValidatedTopology], List[Diagnostic]]:
    """Re-validate a persisted topology record (`ValidatedTopology.as_record()` form). The record is data: its intent
    is validated again (and against `existing` when given); its sha256 must equal the recomputed one (drift
    detection only, never an authority). Any mismatch is a PLATFORM_DEFECT: the platform wrote what it reads."""
    P = ErrorClass.PLATFORM_DEFECT
    if not isinstance(record, Mapping) or record.get("schema") != TOPOLOGY_RECORD_SCHEMA or \
            not isinstance(record.get("intent"), Mapping):
        return None, [_diag("TOPOLOGY.RECORD_INVALID", f"not a {TOPOLOGY_RECORD_SCHEMA} record", cls=P, file=file,
                            source=source)]
    vt, diags = validate_service_topology(record["intent"], product_id=product_id, existing=existing, file=file,
                                          source=source)
    if vt is not None and record.get("sha256") != vt.sha256:
        return None, _sorted(diags + [_diag("TOPOLOGY.RECORD_SHA_MISMATCH",
                                            "the persisted topology's sha256 differs from its content", cls=P,
                                            file=file, source=source)])
    return vt, diags


def render_topology_json(vt: ValidatedTopology) -> str:
    """`infra/workload/topology.json`: the review artifact committed with the workload (canonical JSON)."""
    return json.dumps(vt.as_record(), sort_keys=True, indent=2) + "\n"


def topology_owned_tree(files: Mapping[str, Any], product_id: str = "") -> bool:
    """True when the tree carries a valid platform-rendered topology.json: its service-to-service wiring comes from
    the topology's edges only (lane 10), so the HB-05 sibling discovery must not re-add sibling URLs. A mode switch
    that can only make a cure do LESS (never a source of HCL): a missing / invalid file keeps today's behavior."""
    text = files.get(TOPOLOGY_JSON_PATH) if hasattr(files, "get") else None
    if not isinstance(text, str):
        return False
    try:
        rec = json.loads(text)
    except ValueError:
        return False
    vt, _ = topology_from_record(rec, product_id=product_id or "workload", file=TOPOLOGY_JSON_PATH)
    return vt is not None


# ------------------------------------------------------------------------------------------------ prompt contract
# PUSH-PLAN-CHECK (owner 10-28): the one contract line about push edges (a constant, so a test can remove it exactly
# and compare the rest of the contract with recorded architect calls).
PUSH_CONTRACT_LINE = (
    "   - `pushes`: only when the specification says a Pub/Sub push subscription delivers a topic's messages to an "
    "endpoint of one of this workload's `cloudrun` services: one entry per such topic with `topic` (the "
    f"`logical_name` of its `{PUSH_TOPIC_TYPE}` resource), `service` (the `cloudrun` service) and `path` (the exact "
    "endpoint path, starting with `/`, e.g. `/api/v1/tasks/process`); at most one per topic. The platform then "
    "requires that push subscription in the infrastructure. A pull subscription or the event-worker is never a push; "
    "otherwise `[]`.\n")
# SECRET-INITIAL-VERSION (owner 11-10): the architect contract line for a secret's initial_value
# Red-team F3: the catalog types whose golden module generates the database user's password and keeps it in its own
# Secret Manager secret (database-cloudsql since FD-4AX, database-alloydb since TI-5-R2 P3; a test pins that both
# modules declare random_password and google_secret_manager_secret). Such a password is never a topology secret.
DATABASE_PASSWORD_TYPES: Tuple[str, ...] = ("google_sql_database_instance", "google_alloydb_instance")
SECRET_CONTRACT_LINE = (
    f"   - Every `{SECRET_RESOURCE_TYPE}` resource sets `initial_value`: `{INITIAL_VALUE_RANDOM}` when the workload "
    "itself makes and uses the value (a signing, HMAC or encryption key that no outside system issues): the platform "
    f"stores {GENERATED_SECRET_LENGTH} random letters and digits as its first version at deploy; "
    f"`{INITIAL_VALUE_OPERATOR}` when it holds a credential an outside system issues (an API key, token or password "
    "for another service): it is created empty and an operator adds the value. Never set `initial_value` on any "
    "other type. The password of a database the plan lists ("
    + ", ".join(f"`{t}`" for t in DATABASE_PASSWORD_TYPES)
    + ") is never a `" + SECRET_RESOURCE_TYPE + "` resource, even when the specification names a secret for its "
    "credentials: the platform's database module generates that password and keeps it in its own secret, so do not "
    "list it.\n")


def render_topology_contract() -> str:
    """The architect's `service_topology` contract, rendered from the capability matrix and the catalog (data,
    never hand-copied)."""
    rows = []
    for kind, cap in CAPABILITIES.items():
        role = ("primary or secondary" if cap.allowed_as_secondary else "primary only") if cap.allowed_as_primary \
            else "secondary only"
        count = "any number" if cap.max_per_workload is None else f"at most {cap.max_per_workload} per workload"
        callee = {"http": "callee of http edges", "pubsub": "callee of pubsub edges",
                  "launch": "callee of launch edges"}.get(cap.callee_protocol or "", "never an edge callee")
        caller = "can call others (has env vars)" if cap.accepts_env_vars else "cannot call others (no env vars)"
        if cap.can_launch:
            caller += "; can launch gce-workers"
        rows.append(f"     * `{kind}`: {role}; {count}; {callee}; {caller}.")
    catalog = ", ".join(f"`{t}` ({'/'.join(a for a, _ in attrs)}"
                        + (f"; {CATALOG_NOTES[t]}" if t in CATALOG_NOTES else "") + ")"
                        for t, attrs in BOOTSTRAP_CATALOG.items())
    return (
        "### SERVICE TOPOLOGY (`service_topology`, always set)\n"
        "Describe the workload's compute as typed data. The platform renders all compute and all service-to-service "
        "wiring from it; it never reads the specification text for this.\n"
        "   - `services`: every compute service the specification asks the platform to deploy, each with `name` "
        "(lower-case letters, digits and '-', starts with a letter, at most 40 characters), `kind` and a one-line "
        "`purpose`. Add `scaling` only when the specification states instance counts. `[]` means no compute "
        "(foundation-only).\n"
        "   - Kinds:\n" + "\n".join(rows) + "\n"
        "   - `primary_service`: the service deployed on module \"compute\"; its kind MUST equal `compute_archetype`; "
        "null only when `services` is []. `target_compute_services` lists the same names, primary first.\n"
        "   - `edges`: one entry per caller -> callee call (`protocol` `http` to a cloudrun callee, `pubsub` to the "
        "event-worker). The caller receives `<BASE>_URL` and `<BASE>_AUDIENCE` (http) or `<BASE>_TOPIC` (pubsub); "
        "`<BASE>` is `env_key_base` or the callee name upper-cased with '-' as '_'. Edges MUST be acyclic: never "
        "A -> B and B -> A; route one direction through Pub/Sub or invert the call. GKE and gce-bastion workloads are "
        "reached through their own networking, never through an edge.\n"
        "   - VM workers the app starts on demand (e.g. ephemeral Spot VMs running a batch script): one `gce-worker` "
        "service each (never the primary; add `vm` {machine_type, spot, disk_size_gb} only when the specification "
        "states the VM shape) and a `launch` edge from the cloudrun service that starts it; that caller receives "
        "`<BASE>_INSTANCE_TEMPLATE`, `<BASE>_ZONE` and `<BASE>_NAME_PREFIX`. A worker reads resources like a service "
        "but is never an edge caller; worker names must not be prefixes of each other.\n"
        f"   - `resources`: only these types: {catalog}. Give each the Terraform `logical_name` the IaC will use and, "
        "per service that reads it, `consumers` with the exact environment variable name (`env_key`). Anything "
        "else is described in a service's `purpose`. Resources are never services.\n"
        + SECRET_CONTRACT_LINE + PUSH_CONTRACT_LINE +
        "   - Single-service default: one `cloudrun` service named after `product_id`, no edges.\n"
    )
