"""Lane 10 (FD-51): inter-service wiring rendered from the typed service topology. THE LANE-10 HB-05 SEAM.

Closes FD-40 (mutual `service_uri` cycle), FD-41 (shared-noun URL misrouting), FD-42 (`service_uri` on a GKE/GCE
callee), FD-43 (env key from an interpolated service_name) and FD-45 (alias substring match) on the topology path:
a caller receives another service's URL / topic ONLY for an edge the architect declared and the one validator
accepted (acyclic, callee kind serves the protocol, caller kind accepts env vars, keys collision-free).

Coordination (Step 2 plan §5.3): HB-05 (`terraform_engine.extract_custom_resource_env_vars`) and its verifier twin
are narrowed by Step 2 S2-D to exact env reads. Lane 10 touches HB-05 in exactly one place: the keyword
`include_siblings` (default True = today's behavior). On the topology path every caller of HB-05 passes
`include_siblings=False`, so HB-05 contributes only its non-sibling bindings (buckets, topics, secrets, Redis,
Firestore) and the sibling section - whatever S2-D makes of it - never runs. All topology wiring lives here.

Pure functions; no I/O, no LLM. Every value emitted comes from `ValidatedTopology.env_for` (validated identifiers
only) or from HB-05's non-sibling section (unchanged).
"""
from __future__ import annotations

import base64
import json
import posixpath
import re
import sys
from typing import TYPE_CHECKING, Any, Dict, FrozenSet, List, Mapping, Optional, Tuple

if TYPE_CHECKING:  # typing only: this module must import wherever terraform_engine does (e.g. the terraform MCP
    from shared.service_topology import ValidatedTopology  # test imports terraform_engine as a top-level module)


def _hb05():
    try:
        from .terraform_engine import extract_custom_resource_env_vars
    except ImportError:  # pragma: no cover
        from developer_agent.terraform_engine import extract_custom_resource_env_vars
    return extract_custom_resource_env_vars


def topology_env_vars(vt: ValidatedTopology, service: str, bespoke_hcl: Optional[str],
                      app_files: Optional[Mapping[str, str]], *, caller_service: Optional[str],
                      allow_unauthenticated: Optional[bool] = None,
                      deployed_files: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    """The env bindings of one topology service: HB-05's non-sibling bindings (exactly as today, same caller
    argument as today's call site) plus the topology's own edge and resource bindings, which win on a shared key
    (they are explicit and validated). Never another service's URL unless an edge says so.
    `deployed_files` (SIBLING-AUDIENCE-GETENV-DEFAULT RT F1): the tree the build deploys (this render's files over the
    repository files it does not rewrite); read ONLY by the audience decision (the callee's code and env facts), never
    by HB-05. None = `app_files`."""
    env = dict(_hb05()(bespoke_hcl, dict(app_files) if app_files is not None else None,
                       caller_service=caller_service, include_siblings=False))
    env.update(vt.env_for(service))
    # SIBLING-AUDIENCE-BINDING: an http edge's `<BASE>_AUDIENCE` holds the one fixed audience the callee's own code
    # verifies (audience_facts, ast facts only), on a public workload only (`allow_unauthenticated is True`: Cloud Run
    # checks no token); every other case keeps the edge's service_uri byte-identical.
    # SIBLING-AUDIENCE-GETENV-DEFAULT: an `os.getenv(NAME, L)` audience binds L only when the platform sets no NAME
    # on the callee (callee_env_names, asked lazily per edge).
    view = deployed_files if deployed_files is not None else app_files
    for decision in _audience_facts().edge_audience_decisions(
            vt, service, env, view, allow_unauthenticated=allow_unauthenticated,
            callee_env_names=lambda callee: callee_env_names(vt, callee, app_files, deployed_files=deployed_files)):
        env[decision.env_key] = decision.value
    return dict(sorted(env.items()))


# SIBLING-AUDIENCE-GETENV-DEFAULT: the env name mcp-servers/terraform/service.py `_rollout_cloud_run_revision` upserts
# into every rolled-out Cloud Run revision (pinned by tests/test_sibling_audience_binding.py).
DEPLOY_NONCE_ENV = "CASTOR_DEPLOY_NONCE"
# OpenTofu's own variables-file rule (mcp-servers/terraform/service.py is_auto_loaded_tfvars_name, plus the root
# terraform.tfvars the deploy merges): a file with one of these names may set the root `var.env_vars`, which every
# platform compute-cloudrun call merges into its env (format_hcl_env_vars: `merge(var.env_vars, {...})`).
_TFVARS_NAMES = ("terraform.tfvars", "terraform.tfvars.json")
_TFVARS_SUFFIXES = (".auto.tfvars", ".auto.tfvars.json")
_ROOT_ENV_VARIABLE = "env_vars"


def deployed_view(files: Mapping[str, str], existing_files: Optional[Mapping[str, str]]) -> Dict[str, str]:
    """SIBLING-AUDIENCE-GETENV-DEFAULT RT F1: the tree the build deploys, as far as the assembly knows it: `files`
    (this render, which the commit writes) over every repository file it does not rewrite (the commit deletes nothing
    unasked, so OpenTofu and the container build still see those). An app file the later orphan pass may delete is
    kept in the view: more files can only keep the URL, or show a verifying call the deployed code no longer makes
    (then the caller's audience is not checked at all)."""
    view = {p: t for p, t in (existing_files or {}).items() if isinstance(p, str) and isinstance(t, str)}
    view.update(files)
    return view


def callee_env_names(vt: ValidatedTopology, callee: str, app_files: Optional[Mapping[str, str]],
                     deployed_files: Optional[Mapping[str, str]] = None) -> Tuple[Optional[FrozenSet[str]], str]:
    """(every env name the platform's IaC and deploy set on the Cloud Run service `callee`, "") or (None, why) when
    that set is not known. Typed facts only:
    - Cloud Run's own and the golden module's literal `env` names, and the deploy workflow's `--update-env-vars`
      names: `RESERVED_ENV_KEYS` of vt's own service_topology copy (cross-checked against compute-cloudrun's main.tf
      by tests/test_service_topology.py), plus DEPLOY_NONCE_ENV;
    - the module's `env_vars` input, which both render sites (handler `_topology_primary_overrides` for the primary,
      terraform_engine `reconcile_multi_service_declarations` for a secondary) take from `topology_env_vars`: the
      topology's own bindings (`vt.env_for(callee)`: edges, consumer and implied resource bindings) and HB-05's
      non-sibling keys. HB-05's keys depend on its arguments, so the union over every argument a render site or the
      gatekeeper's HB-05 cure (verifier.reconcile_iac_environment_contracts: custom.tf only) passes is taken: a
      superset, which can only keep more URLs;
    - `var.env_vars` (merged into every platform module call): unknown when any variables file in the tree may set
      it (an unparseable one included), or a root file other than the platform's renders redeclares the variable.
    Unknown, too, when a root .tf / .tf.json file other than the platform's renders declares the callee's module
    label (a repository file the platform does not render over, services_tf_skip_addresses, or an override file),
    when the callee is not a Cloud Run service, or when there is no tree.
    The variables-file and declaration checks read `deployed_files` (deployed_view: repository files the build does
    not rewrite included, RT F1); HB-05 reads both maps (the render sites pass `app_files`). None = `app_files`."""
    if app_files is None:
        return None, "no tree"
    if vt.kind(callee) != "cloudrun":
        return None, f"'{callee}' is not a Cloud Run service"
    reserved = getattr(sys.modules.get(type(vt).__module__), "RESERVED_ENV_KEYS", None)
    if reserved is None:  # pragma: no cover - vt is always a shared.service_topology.ValidatedTopology
        return None, "no reserved env keys"
    try:
        import hcl2
        from .assembly import CUSTOM_TF, PLATFORM_RENDERED_ROOT, bespoke_root_text, index_blocks
        from .terraform_engine import SERVICES_TF
    except ImportError:  # pragma: no cover - imported as a top-level module
        try:
            import hcl2
            from developer_agent.assembly import CUSTOM_TF, PLATFORM_RENDERED_ROOT, bespoke_root_text, index_blocks
            from developer_agent.terraform_engine import SERVICES_TF
        except ImportError as exc:
            return None, f"{type(exc).__name__}"
    files = dict(app_files)
    view = dict(deployed_files) if deployed_files is not None else files
    for path in sorted(p for p in view if isinstance(p, str)):
        text = view[path]
        name = posixpath.basename(path)
        if name in _TFVARS_NAMES or name.endswith(_TFVARS_SUFFIXES):
            try:
                values = json.loads(text) if name.endswith(".json") else hcl2.loads(text)
            except Exception as exc:  # noqa: BLE001 - any parser failure: the file's variables are not known
                return None, f"{path} is not parseable ({type(exc).__name__})"
            if not isinstance(values, dict) or _ROOT_ENV_VARIABLE in values:
                return None, f"{path} may set var.{_ROOT_ENV_VARIABLE}"
        root_file = path.startswith("infra/workload/") and "/" not in path[len("infra/workload/"):]
        if not root_file or path in PLATFORM_RENDERED_ROOT or path == SERVICES_TF:
            continue
        label = vt.label(callee)
        if path.endswith(".tf.json"):
            try:
                doc = json.loads(text) if isinstance(text, str) else None
            except ValueError:
                return None, f"{path} is not parseable"
            if not isinstance(doc, dict):
                return None, f"{path} is not parseable"
            modules, variables = doc.get("module", {}), doc.get("variable", {})
            if not isinstance(modules, dict) or not isinstance(variables, dict):
                return None, f"{path} is not parseable"
            declared = {("module", k) for k in modules} | {("variable", k) for k in variables}
        elif path.endswith(".tf"):
            blocks = index_blocks(text) if isinstance(text, str) else None
            if blocks is None:
                return None, f"{path} is not parseable"
            declared = {(b.kind, b.labels[0]) for b in blocks if b.labels}
        else:
            continue
        if ("module", label) in declared:
            return None, f"{path} declares module.{label}"
        if ("variable", _ROOT_ENV_VARIABLE) in declared:
            return None, f"{path} declares var.{_ROOT_ENV_VARIABLE}"
    names = set(reserved) | {DEPLOY_NONCE_ENV} | set(vt.env_for(callee))
    try:
        for tree in ([files] if view is files else [files, view]):
            texts = {bespoke_root_text(tree), bespoke_root_text({p: t for p, t in tree.items() if p != SERVICES_TF}),
                     tree.get(CUSTOM_TF) if isinstance(tree.get(CUSTOM_TF), str) else ""}
            for text in sorted(texts):
                for caller_service in (None, callee):
                    names |= set(_hb05()(text or None, dict(tree), caller_service=caller_service,
                                         include_siblings=False))
    except Exception as exc:  # noqa: BLE001 - HB-05 could not say: the set is not known
        return None, f"HB-05 failed ({type(exc).__name__})"
    return frozenset(names), ""


def _audience_facts():
    try:
        from . import audience_facts
    except ImportError:  # pragma: no cover - imported as a top-level module (terraform MCP tests)
        try:
            import audience_facts  # type: ignore[no-redef]
        except ImportError:
            from developer_agent import audience_facts  # type: ignore[no-redef]
    return audience_facts


def render_event_worker_block(vt: ValidatedTopology, name: str, kms_key_reference: Optional[str] = None) -> str:
    """`module "compute_<name>"` for an event-worker SECONDARY (RT F3: one per workload; its topic, subscription and
    job names derive from product_id). Only the module's declared inputs; the image follows the secondary-service
    convention (`/app:` -> `/<name>:`). `name` is a validated ServiceName. Lane 14 PR-0b: `kms_key_reference` (the
    platform's own `module.cmek.crypto_key_name`, regulated profiles only) sets the module's CMEK input; None =
    unchanged."""
    if vt.kind(name) != "event-worker" or name == vt.intent.primary_service:
        raise ValueError(f"'{name}' is not an event-worker secondary of the topology")
    kms_line = f"  kms_key_name          = {kms_key_reference}\n" if kms_key_reference else ""
    return f"""module "{vt.label(name)}" {{
  source                = "../modules/compute-event-worker"
  project_id            = var.project_id
  region                = var.region
  product_id            = var.product_id
  service_account_email = module.foundation.workload_sa_email
  container_image       = replace(var.container_image, "/app:", "/{name}:")
  cpu_limit             = var.cpu_limit
  memory_limit          = var.memory_limit
{kms_line}
  depends_on = [module.foundation]
}}"""


GCE_WORKER_STARTUP_SCRIPT = "apps/{name}/startup.sh"   # the worker's code: the VMs' startup script (exact path)
WORKLOAD_SUBNET = "WORKLOAD_SUBNET"                     # platform_facts.PURPOSE_SUBNET (lane 11 canonical purpose)


_HCL_LABEL = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]*$")   # an HCL identifier (closed grammar for emitted labels)
NETWORK_MODULE_DIR = "infra/modules/networking-vpc"


def workload_subnetwork_ref(files: Optional[Mapping[str, str]]) -> Optional[str]:
    """The workload's own subnetwork, as an exact HCL reference, or None (L10-u2). Candidates are the blocks of the
    root module (infra/workload/*.tf) that hold the IPAM WORKLOAD_SUBNET fact by the exact lane-11 allocation table
    (`platform_facts.ALLOCATION_ATTRIBUTES`): a `google_compute_subnetwork` resource -> `.id`, or a call of the golden
    `networking-vpc` module -> `.primary_subnetwork_id` (its output). compute-gce-worker calls never count. Several
    candidates: the one whose allocation attribute is exactly `var.subnet_cidr` first, then file / address order
    (deterministic; V2h already reports a reused fact). No name is guessed."""
    try:
        from .assembly import index_blocks
        from .platform_facts import PURPOSE_SUBNET, allocation_attributes_for, module_dir
    except ImportError:  # pragma: no cover
        from developer_agent.assembly import index_blocks
        from developer_agent.platform_facts import PURPOSE_SUBNET, allocation_attributes_for, module_dir
    cands = []
    for path in sorted(files or {}):
        text = (files or {}).get(path)
        if not (path.startswith("infra/workload/") and path.endswith(".tf") and "/" not in path[len("infra/workload/"):]
                and isinstance(text, str)):
            continue
        for b in index_blocks(text) or []:
            attrs = allocation_attributes_for(b.kind, b.labels, b.body)
            subnet_attrs = [a for a, purpose in attrs.items() if purpose == PURPOSE_SUBNET]
            if not subnet_attrs or not b.labels or not all(_HCL_LABEL.match(x) for x in b.labels):
                continue
            if b.kind == "resource" and b.labels[0] == "google_compute_subnetwork" and len(b.labels) == 2:
                ref = f"google_compute_subnetwork.{b.labels[1]}.id"
            elif b.kind == "module" and module_dir((b.body or {}).get("source")) == NETWORK_MODULE_DIR:
                ref = f"module.{b.labels[0]}.primary_subnetwork_id"
            else:
                continue
            exact = any((b.body or {}).get(a) == "${var.subnet_cidr}" for a in subnet_attrs)
            cands.append((not exact, path, b.key, ref))
    return sorted(cands)[0][3] if cands else None


def vm_startup_script_expr(files: Optional[Mapping[str, str]], name: Optional[str]) -> Optional[str]:
    """`base64decode("<b64>")` of a VM service's own startup script, `apps/<name>/startup.sh` (exact path, no name
    guessing), or None when it is missing or whitespace-only. base64 is a closed alphabet, so no repository text
    reaches HCL verbatim (lane 10 RT F2). Used by the gce-worker block and the gce-bastion primary."""
    if not name:
        return None
    script = (files or {}).get(GCE_WORKER_STARTUP_SCRIPT.format(name=name))
    if not (isinstance(script, str) and script.strip()):
        return None
    return f'base64decode("{base64.b64encode(script.encode("utf-8")).decode("ascii")}")'


def render_gce_bastion_code_lines(service_name: Optional[str], files: Optional[Mapping[str, str]], *,
                                  topology: Optional["ValidatedTopology"] = None, subnet_fact: bool = False) -> str:
    """Extra `module "compute"` argument lines for a gce-bastion primary, the gce-worker mechanisms (lane 10):
    - `startup_script` (gce-bastion-startup) = its own `apps/<service>/startup.sh` (base64, see vm_startup_script_expr);
    - network (gce-bastion-network, L10-u2 model): the workload's existing subnetwork when it has one
      (`workload_subnetwork_ref`), else its own VPC + subnet with Private Google Access on the IPAM fact
      `var.subnet_cidr` when the platform declared that fact (`subnet_fact`), else nothing (the module's legacy
      var.network / var.subnetwork; never a reference to an undeclared variable);
    - `settings` (instance metadata) = the topology's resource bindings on the service (`resource_bindings`: validated
      env keys -> validated references), and one own-SA grant per consumed resource (`worker_access`, the
      WORKER_RESOURCE_ACCESS roles). Only for a topology whose primary is this gce-bastion.
    "" when there is nothing to pass: the bastion block stays byte-identical to before. A gce-bastion still takes no
    `env_vars` and is never an edge caller (CAPABILITIES accepts_env_vars=False)."""
    lines: List[str] = []
    script_expr = vm_startup_script_expr(files, service_name)
    if script_expr is not None:
        lines.append(f"  startup_script = {script_expr}")
    existing_subnet = workload_subnetwork_ref(files) if files else None
    if existing_subnet is not None:
        lines += ["  use_existing_subnetwork = true", f"  subnetwork_id           = {existing_subnet}"]
    elif subnet_fact:
        lines.append("  subnet_cidr             = var.subnet_cidr")
    vt = topology
    if (vt is not None and service_name and service_name == vt.intent.primary_service
            and vt.kind(service_name) == "gce-bastion"):
        settings = vt.resource_bindings(service_name)
        if settings:
            lines.append("  settings = {")
            lines += [f'    "{k}" = {v}' for k, v in sorted(settings.items())]
            lines.append("  }")
        for var, refs in vt.worker_access(service_name).items():
            lines.append(f"  {var:<23} = [{', '.join(refs)}]")
    if not lines:
        return ""
    return "\n" + "\n".join(lines) + "\n"


def primary_network_purposes(archetype: Optional[str]) -> FrozenSet[str]:
    """IPAM purposes the platform's primary compute block needs (gce-bastion-network: a gce-bastion's own subnet,
    WORKLOAD_SUBNET; it joins the workload's subnetwork instead when one exists, which holds the same fact)."""
    return frozenset({WORKLOAD_SUBNET}) if archetype == "gce-bastion" else frozenset()


# ---- private-network route of a Cloud Run service (platform-db-connector-wiring; replaces HA-13 phase 5) ----------
# A consumed resource type that lives on a VPC: type -> (provider-schema path of its network attribute, the catalog
# attributes (shared/service_topology.BOOTSTRAP_CATALOG) that are addresses on that network). Cloud SQL's
# `connection_name` is not one: it is reached through the Cloud SQL connector, not a VPC route.
PRIVATE_NETWORK_RESOURCES: Mapping[str, Tuple[Tuple[str, ...], FrozenSet[str]]] = {
    "google_sql_database_instance": (("settings", "ip_configuration", "private_network"),
                                     frozenset({"private_ip_address"})),
    "google_redis_instance": (("authorized_network",), frozenset({"host", "port"})),
}
# Intent path (TI-5c, TI-5-R2): the topology types whose realizing golden module is always on the platform network
# (a FACT network input the AI cannot set) and reached through a private address, so every Cloud Run consumer needs the
# platform VPC connector. Exact type set: Cloud SQL and Redis (above), AlloyDB (private IP over Private Services
# Access) and a Vertex AI endpoint (peered to the platform network, so its predictions are served privately).
# Bigtable is not VPC-bound (Google API endpoint): its consumers get their env binding only. The legacy HCL rule
# (topology_vpc_connector without the platform render) reads CLASSIC_PRIVATE_NETWORK_ATTRS (TI-5-R2 P4) below.
INTENT_PRIVATE_NETWORK_TYPES: FrozenSet[str] = frozenset(PRIVATE_NETWORK_RESOURCES) | frozenset(
    {"google_alloydb_instance", "google_vertex_ai_endpoint"})
# TI-5-R2 P4 (owner 10-25, FOLLOWUPS-1025): the classic path (agent-written Terraform, topology_vpc_connector without
# the platform render) wires a consumer of AlloyDB or a private Vertex AI endpoint by the same exact network rule as
# Cloud SQL / Redis. Type -> the catalog attributes (shared/service_topology.BOOTSTRAP_CATALOG) a consumer reaches over
# the VPC: AlloyDB's `ip_address` (private IP over Private Services Access); every attribute of a Vertex AI endpoint
# (`id` / `name`: an endpoint peered to a network serves its predictions on that network only). How each type names
# its network: _classic_network_identity.
ALLOYDB_INSTANCE_TYPE, ALLOYDB_CLUSTER_TYPE = "google_alloydb_instance", "google_alloydb_cluster"
VERTEX_ENDPOINT_TYPE = "google_vertex_ai_endpoint"
CLASSIC_PRIVATE_NETWORK_ATTRS: Mapping[str, FrozenSet[str]] = {
    **{t: spec[1] for t, spec in PRIVATE_NETWORK_RESOURCES.items()},
    ALLOYDB_INSTANCE_TYPE: frozenset({"ip_address"}),
    VERTEX_ENDPOINT_TYPE: frozenset({"id", "name"}),
}
VPC_CONNECTOR_TYPE = "google_vpc_access_connector"
_NETWORK_ATTRS = frozenset({"id", "name", "self_link"})   # every attribute that names the same network / subnetwork


def _parser_helpers():
    try:
        from .sibling_wiring import HclUnavailable, _data, _kids, _traversal
    except ImportError:  # pragma: no cover
        from developer_agent.sibling_wiring import HclUnavailable, _data, _kids, _traversal
    return HclUnavailable, _data, _kids, _traversal


def exact_reference(value: Any) -> Optional[Tuple[str, ...]]:
    """The traversal of a python-hcl2 attribute value that is exactly one bare reference (`"${a.b.c}"` ->
    ("a", "b", "c")), read with the HCL parser's own grammar (sibling_wiring._traversal). A literal, a template with
    text or several interpolations, a call, an index or a splat -> None."""
    if not (isinstance(value, str) and value.startswith("${") and value.endswith("}")):
        return None
    hcl_unavailable, _data, _kids, _traversal = _parser_helpers()
    try:
        import hcl2  # python-hcl2==7.3.1 (requirements.txt)
    except ImportError as e:  # pragma: no cover - environment
        raise hcl_unavailable("python-hcl2 is not installed") from e
    try:
        tree = hcl2.parses(f"x = {value[2:-1]}\n")
    except Exception:  # noqa: BLE001 - not one expression (e.g. "${a}-${b}"): no reference
        return None
    body = next((c for c in _kids(tree) if _data(c) == "body"), None)
    items = [k for k in (_kids(body) if body is not None else []) if _data(k) != "new_line_or_comment"]
    if len(items) != 1 or _data(items[0]) != "attribute":
        return None
    attrs = items
    return _traversal(_kids(attrs[0])[-1])


def _network_identity(value: Any) -> Optional[Tuple[str, ...]]:
    """What a network attribute points at, when that is exact: a declared VPC (`google_compute_network.<n>.id` /
    `.name` / `.self_link`, or the same of a `data` source), one input variable, or one module output. The same
    identity = the same network. Anything else (a literal, a call) -> None: never compared."""
    t = exact_reference(value)
    if t is None:
        return None
    if len(t) == 3 and t[0] == "google_compute_network" and t[2] in _NETWORK_ATTRS:
        return ("google_compute_network", t[1])
    if len(t) == 4 and t[:2] == ("data", "google_compute_network") and t[3] in _NETWORK_ATTRS:
        return ("data.google_compute_network", t[2])
    if len(t) == 2 and t[0] == "var":
        return t
    if len(t) == 3 and t[0] == "module":
        return t
    return None


def _nested(body: Mapping, path: Tuple[str, ...]) -> Any:
    """The value at `path` through single nested blocks (python-hcl2 renders a block as a list of dicts); None when a
    step is missing or a block repeats."""
    cur: Any = body
    for i, key in enumerate(path):
        if not isinstance(cur, Mapping):
            return None
        cur = cur.get(key)
        if i < len(path) - 1:
            if isinstance(cur, list):
                if len(cur) != 1:
                    return None
                cur = cur[0]
    return cur


def _root_resources(files: Optional[Mapping[str, str]]) -> Dict[Tuple[str, str], List[Mapping]]:
    """(type, name) -> bodies of every `resource` block of the root module (infra/workload/*.tf, exact parse).
    A root file python-hcl2 cannot parse contributes nothing (its resources are invisible here, e.g. a second
    connector in it is not counted); that file fails V1b `tofu validate` and the repair loop re-assembles (RT F7)."""
    try:
        from .assembly import index_blocks
    except ImportError:  # pragma: no cover
        from developer_agent.assembly import index_blocks
    out: Dict[Tuple[str, str], List[Mapping]] = {}
    for path in sorted(files or {}):
        text = (files or {}).get(path)
        if not (path.startswith("infra/workload/") and path.endswith(".tf") and "/" not in path[len("infra/workload/"):]
                and isinstance(text, str)):
            continue
        for b in index_blocks(text) or []:
            if b.kind == "resource" and len(b.labels) == 2:
                out.setdefault((b.labels[0], b.labels[1]), []).append(b.body or {})
    return out


_CLUSTER_REF_ATTRS = frozenset({"id", "name"})   # google_alloydb_cluster attributes that are its full resource name
# The provider's documented form of a Vertex AI endpoint's `network` (projects/{project number}/global/networks/
# {network name}): exactly these template parts, read with the HCL parser (_template_parts).
_VERTEX_NETWORK_LITERALS = ("projects/", "/global/networks/")


def _template_parts(value: Any) -> Optional[List[Any]]:
    """A python-hcl2 string value as its template parts, read with the HCL parser's own grammar (the value re-parsed as
    one quoted template): each part is the literal text (str) or the traversal of one interpolation (tuple). None when
    it does not parse as one template, or an interpolation is not a plain traversal."""
    if not isinstance(value, str):
        return None
    hcl_unavailable, _data, _kids, _traversal = _parser_helpers()
    try:
        import hcl2  # python-hcl2==7.3.1 (requirements.txt)
    except ImportError as e:  # pragma: no cover - environment
        raise hcl_unavailable("python-hcl2 is not installed") from e
    try:
        tree = hcl2.parses("x = " + json.dumps(value) + "\n")
    except Exception:  # noqa: BLE001 - not one template: no parts
        return None
    body = next((c for c in _kids(tree) if _data(c) == "body"), None)
    items = [k for k in (_kids(body) if body is not None else []) if _data(k) != "new_line_or_comment"]
    if len(items) != 1 or _data(items[0]) != "attribute":
        return None
    node = _kids(items[0])[-1]
    while _data(node) == "expr_term" and len(_kids(node)) == 1:
        node = _kids(node)[0]
    if _data(node) != "string":
        return None
    parts: List[Any] = []
    for part in getattr(node, "children", []):
        if _data(part) != "string_part":
            continue
        kids = getattr(part, "children", [])
        if len(kids) != 1:
            return None
        if _data(kids[0]) is None:                     # literal text (a lark Token)
            parts.append(str(kids[0]))
            continue
        if _data(kids[0]) != "interpolation":
            return None
        inner = _kids(kids[0])
        t = _traversal(inner[0]) if len(inner) == 1 else None
        if t is None:
            return None
        parts.append(t)
    return parts


def _vertex_network_identity(value: Any) -> Optional[Tuple[str, ...]]:
    """The network a classic `google_vertex_ai_endpoint.network` names, when exact: one bare reference
    (_network_identity), or exactly the template `projects/${data.google_project.<p>.number}/global/networks/${<VPC>.
    name}` where <VPC> is a declared `google_compute_network` or its data source. Anything else -> None."""
    ident = _network_identity(value)
    if ident is not None:
        return ident
    parts = _template_parts(value)
    if parts is None or len(parts) != 4 or (parts[0], parts[2]) != _VERTEX_NETWORK_LITERALS:
        return None
    project, net = parts[1], parts[3]
    if not (isinstance(project, tuple) and len(project) == 4 and project[:2] == ("data", "google_project")
            and project[3] == "number"):
        return None
    if isinstance(net, tuple) and len(net) == 3 and net[0] == "google_compute_network" and net[2] == "name":
        return ("google_compute_network", net[1])
    if isinstance(net, tuple) and len(net) == 4 and net[:2] == ("data", "google_compute_network") and net[3] == "name":
        return ("data.google_compute_network", net[2])
    return None


def _classic_network_identity(typ: str, body: Mapping,
                              resources: Mapping[Tuple[str, str], List[Mapping]]) -> Optional[Tuple[str, ...]]:
    """The exact network of a root-module resource of a CLASSIC_PRIVATE_NETWORK_ATTRS type, else None:
    Cloud SQL / Redis: their network attribute (PRIVATE_NETWORK_RESOURCES); TI-5-R2 P4: an AlloyDB instance by its
    `cluster` (exactly `google_alloydb_cluster.<c>.id` / `.name`, that cluster declared once) and the cluster's
    `network_config { network }` (LEGACY_PRIVATE_NETWORK_RESOURCES); a Vertex AI endpoint by its `network`
    (_vertex_network_identity). Nothing is matched by name or substring."""
    if typ in PRIVATE_NETWORK_RESOURCES:
        return _network_identity(_nested(body, PRIVATE_NETWORK_RESOURCES[typ][0]))
    if typ == ALLOYDB_INSTANCE_TYPE:
        ref = exact_reference(body.get("cluster"))
        if ref is None or len(ref) != 3 or ref[0] != ALLOYDB_CLUSTER_TYPE or ref[2] not in _CLUSTER_REF_ATTRS:
            return None
        clusters = resources.get((ALLOYDB_CLUSTER_TYPE, ref[1])) or []
        if len(clusters) != 1:
            return None
        return _network_identity(_nested(clusters[0], LEGACY_PRIVATE_NETWORK_RESOURCES[ALLOYDB_CLUSTER_TYPE]))
    if typ == VERTEX_ENDPOINT_TYPE:
        return _vertex_network_identity(body.get("network"))
    return None


def private_network_consumers(vt: Optional["ValidatedTopology"]) -> FrozenSet[str]:
    """TI-5c: the Cloud Run (`cloudrun`) services of the topology that consume (typed consumer edge, any attribute) a
    resource of an INTENT_PRIVATE_NETWORK_TYPES type (Cloud SQL / Redis; TI-5-R2: AlloyDB / Vertex AI endpoint). On
    the intent path those resources have a private address only (TI-3g: no public IP), so every consumer needs the
    VPC connector, whatever it reads."""
    if vt is None:
        return frozenset()
    out = set()
    for r in vt.intent.resources:
        if r.type not in INTENT_PRIVATE_NETWORK_TYPES:
            continue
        for c in r.consumers:
            if vt.kind(c.service) == "cloudrun":
                out.add(c.service)
    return frozenset(out)


def _platform_connector_rendered(files: Optional[Mapping[str, str]]) -> bool:
    """TI-5c: the platform's own intent-path network render (shared/iac_intent FACTS_RENDER_PATH, JSON) declares the
    platform VPC connector at its exact address (json.loads + exact keys; never a text match).
    FD-4BH: that connector is the golden module call `module.stackvend_connector` (II.PLATFORM_CONNECTOR_MODULE) whose
    source is exactly `../modules/networking-vpc-connector`, the address II.PLATFORM_CONNECTOR_REF names."""
    try:
        from shared import iac_intent as II
    except ImportError:  # pragma: no cover
        return False
    text = (files or {}).get(II.FACTS_RENDER_PATH)
    if not isinstance(text, str):
        return False
    try:
        doc = json.loads(text)
    except ValueError:
        return False
    mods = doc.get("module") if isinstance(doc, dict) else None
    call = mods.get(II.PLATFORM_CONNECTOR_MODULE) if isinstance(mods, dict) else None
    return isinstance(call, dict) and call.get("source") == II.MODULE_SOURCE_PREFIX + II.PLATFORM_CONNECTOR_MODULE_ID


def topology_vpc_connector(vt: Optional["ValidatedTopology"], service: str,
                           files: Optional[Mapping[str, str]]) -> Optional[str]:
    """The `vpc_access_connector` input of a Cloud Run topology service (`google_vpc_access_connector.<c>.id`), or None.

    The platform renders it from typed facts only (replaces HA-13 phase 5, which added the first declared connector to
    every compute-cloudrun module at deploy). All of these must hold:
    1. `service` is a `cloudrun` service of the topology and a typed consumer (`resources[].consumers`, env_key) of a
       CLASSIC_PRIVATE_NETWORK_ATTRS type through one of its listed attributes (Cloud SQL `private_ip_address`, Redis
       `host` / `port`; TI-5-R2 P4: AlloyDB `ip_address`, a Vertex AI endpoint `id` / `name`);
    2. that resource is declared once in the root module at exactly `<type>.<logical_name>` and its network has an
       exact identity (_classic_network_identity: the network attribute of Cloud SQL / Redis / a Vertex AI endpoint,
       an AlloyDB instance's cluster's `network_config.network`);
    3. exactly one root-module `google_vpc_access_connector` (no count / for_each) is on one of those networks: its
       `network`, or the `network` of the `google_compute_subnetwork` its `subnet { name }` references, has the same
       identity; its `region` / `project` are absent or exactly `var.region` / `var.project_id` (FD4DK-3, as on the
       legacy path).
    No connector, two connectors, or anything inexact -> None (nothing is chosen on a guess; V2h reports a second
    connector range). No name is read.

    FD4DK-3: `files` is the assembled root module WITHOUT the AI's relocated draft keys
    (assembly.AssemblyResult.relocated_draft_paths: their text already lives in custom.tf, so the full tree would hold
    every declaration in them twice and rule 2 / 3 would see a duplicate); both callers pass that view.

    TI-5c (intent path): when the tree holds the platform's own network render with its VPC connector
    (_platform_connector_rendered: the intent realized a Cloud SQL / Redis consumed by a Cloud Run service), every
    such consumer (private_network_consumers) gets that connector; the private resource's network is the platform's
    by construction (a FACT input the AI cannot set). Without that render this function is unchanged."""
    if vt is None or vt.kind(service) != "cloudrun":
        return None
    if _platform_connector_rendered(files):
        try:
            from shared.iac_intent import PLATFORM_CONNECTOR_REF
        except ImportError:  # pragma: no cover
            return None
        return PLATFORM_CONNECTOR_REF if service in private_network_consumers(vt) else None
    try:
        from shared.service_topology import BOOTSTRAP_CATALOG
    except ImportError:  # pragma: no cover - vt exists only when shared.service_topology imported
        return None
    consumed: List[Tuple[str, str]] = []
    for r in vt.intent.resources:
        attrs = CLASSIC_PRIVATE_NETWORK_ATTRS.get(r.type)   # TI-5-R2 P4: + AlloyDB, Vertex AI endpoint
        if attrs is None or r.type not in BOOTSTRAP_CATALOG:
            continue
        default_attr = BOOTSTRAP_CATALOG[r.type][0][0]
        if any(c.service == service and (c.attribute or default_attr) in attrs for c in r.consumers):
            consumed.append((r.type, r.logical_name))
    if not consumed:
        return None
    resources = _root_resources(files)
    networks = set()
    for typ, name in consumed:
        bodies = resources.get((typ, name)) or []
        if len(bodies) != 1:
            continue
        ident = _classic_network_identity(typ, bodies[0], resources)
        if ident is not None:
            networks.add(ident)
    return _one_connector_on(networks, resources)


def _one_connector_on(networks: set, resources: Mapping[Tuple[str, str], List[Mapping]]) -> Optional[str]:
    """Rule 3 of topology_vpc_connector (shared with legacy_vpc_connector, FD-4DK): the one root-module
    `google_vpc_access_connector` (no count / for_each) whose `network`, or the `network` of the
    `google_compute_subnetwork` its `subnet { name }` references, has an identity in `networks`; None for no
    network, no connector or two. The connector's `region` and `project` must also be absent (the provider's,
    var.region / var.project_id) or exactly `var.region` / `var.project_id`: the region and project every platform
    Cloud Run module deploys to (a connector serves only its own region; one in another project needs grants the
    platform does not render; FD-4DK RT F7). FD4DK-3: the topology rule checks this too (it was legacy-only)."""
    if not networks:
        return None
    matches = []
    for (typ, name), bodies in sorted(resources.items()):
        if typ != VPC_CONNECTOR_TYPE or len(bodies) != 1:
            continue
        body = bodies[0]
        ident = _network_identity(body.get("network"))
        if ident is None:
            sub = exact_reference(_nested(body, ("subnet", "name")))
            if sub is not None and len(sub) == 3 and sub[0] == "google_compute_subnetwork" and sub[2] in _NETWORK_ATTRS:
                sub_bodies = resources.get(("google_compute_subnetwork", sub[1])) or []
                if len(sub_bodies) == 1:
                    ident = _network_identity(sub_bodies[0].get("network"))
        if ident in networks:
            matches.append((name, body))
    if len(matches) != 1:
        return None
    name, body = matches[0]
    if "count" in body or "for_each" in body or not _HCL_LABEL.match(name):
        return None
    if any(k in body and exact_reference(body.get(k)) != ("var", v)
           for k, v in (("region", "region"), ("project", "project_id"))):
        return None
    return f"{VPC_CONNECTOR_TYPE}.{name}.id"


# FD-4DK (legacy path): the root-module resource types that have only a private address on a VPC network, with the
# path of their network attribute. Cloud SQL and Redis as on the topology path (PRIVATE_NETWORK_RESOURCES); AlloyDB
# by its cluster's `network_config { network }` (an AlloyDB instance is reachable on its private IP only, over Private
# Services Access of that network). Exact types and paths; nothing else is read.
LEGACY_PRIVATE_NETWORK_RESOURCES: Mapping[str, Tuple[str, ...]] = {
    **{t: spec[0] for t, spec in PRIVATE_NETWORK_RESOURCES.items()},
    "google_alloydb_cluster": ("network_config", "network"),
}


def legacy_vpc_connector(files: Optional[Mapping[str, str]]) -> Optional[str]:
    """FD-4DK: the `vpc_access_connector` input of every platform-rendered Cloud Run module of a LEGACY workload (no
    service topology: `module.compute` in main.tf and HB-04's `module.compute_<x>` secondaries), or None.

    The legacy path has no per-service consumer edge: its env bridge (HB-05, extract_custom_resource_env_vars) binds
    the workload's resources to every service alike. So the facts are the workload's, read from its parsed root-module
    IaC exactly like rules 2 and 3 of topology_vpc_connector:
    1. at least one LEGACY_PRIVATE_NETWORK_RESOURCES resource (Cloud SQL `settings.ip_configuration.private_network`,
       Redis `authorized_network`, AlloyDB cluster `network_config.network`), declared once at its address, whose
       network attribute has an exact identity (_network_identity: the VPC resource / data source, one var.X, one
       module output);
    2. exactly one root-module connector (no count / for_each) on one of those networks (_one_connector_on), whose
       `region` / `project` are absent or exactly `var.region` / `var.project_id`.
    Golden-module databases (`database-cloudsql` / `database-alloydb` / `cache-redis` module calls) are not read here
    (FD-4DK RT F2: their network is a module input, and a module output's id and name are different identities); V2m
    reports such a database when nothing reaches it.
    No private resource, no connector, two connectors, a literal network or region, or an unparseable file -> None
    (byte-identical render). No name is read. The connector's default egress (compute-cloudrun `vpc_egress`
    PRIVATE_RANGES_ONLY) routes only private-range traffic, so a service that does not use the database is
    unaffected."""
    resources = _root_resources(files)
    networks = set()
    for (typ, _name), bodies in sorted(resources.items()):
        path = LEGACY_PRIVATE_NETWORK_RESOURCES.get(typ)
        if path is None or len(bodies) != 1:
            continue
        ident = _network_identity(_nested(bodies[0], path))
        if ident is not None:
            networks.add(ident)
    return _one_connector_on(networks, resources)


def render_gce_worker_block(vt: ValidatedTopology, name: str, files: Optional[Mapping[str, str]] = None) -> str:
    """`module "compute_<name>"` for a gce-worker (lane 10 L10-s/t/u/v): the compute-gce-worker instance template.
    Every value is a validated identifier, a typed number/bool, a platform variable, or base64 (closed alphabet) of
    the worker's own `apps/<name>/startup.sh`: no repository text is emitted into HCL verbatim (RT F2).
    - metadata (`env_vars`): the worker's topology env (its resource bindings / outgoing edges), like a service's env;
    - launch grant: the workload runtime SA (every Cloud Run service runs as it) when a launch edge targets it;
    - resource access: one grant per consumed resource on the worker's own SA (WORKER_RESOURCE_ACCESS);
    - network (L10-u2): the workload's existing subnetwork when it has one (`workload_subnetwork_ref`), else its own
      VPC + subnet on the IPAM fact `var.subnet_cidr`."""
    if vt.kind(name) != "gce-worker" or name == vt.intent.primary_service:
        raise ValueError(f"'{name}' is not a gce-worker secondary of the topology")
    spec = vt.spec(name)
    lines = [
        f'module "{vt.label(name)}" {{',
        '  source                          = "../modules/compute-gce-worker"',
        "  project_id                      = var.project_id",
        "  region                          = var.region",
        "  product_id                      = var.product_id",
        f'  worker_name                     = "{name}"',
    ]
    existing_subnet = workload_subnetwork_ref(files)
    if existing_subnet is not None:
        lines += ["  use_existing_subnetwork         = true", f"  subnetwork_id                   = {existing_subnet}"]
    else:
        lines.append("  subnet_cidr                     = var.subnet_cidr")
    if spec is not None and spec.vm is not None:
        lines += [f'  machine_type                    = "{spec.vm.machine_type}"',
                  f"  spot                            = {'true' if spec.vm.spot else 'false'}",
                  f"  disk_size_gb                    = {int(spec.vm.disk_size_gb)}"]
    script_expr = vm_startup_script_expr(files, name)
    if script_expr is not None:
        lines.append(f"  startup_script                  = {script_expr}")
    env = vt.env_for(name)   # validated EnvKey -> validated reference; not merged with the services' var.env_vars
    if env:
        lines.append("  env_vars = {")
        lines += [f'    "{k}" = {v}' for k, v in sorted(env.items())]
        lines.append("  }")
    if vt.launchers(name):
        lines.append("  launcher_service_account_emails = [module.foundation.workload_sa_email]")
    for var, refs in vt.worker_access(name).items():
        lines.append(f"  {var:<31} = [{', '.join(refs)}]")
    lines += ["", "  depends_on = [module.foundation]", "}"]
    return "\n".join(lines)


def render_secondary_worker_block(vt: ValidatedTopology, name: str, files: Optional[Mapping[str, str]] = None,
                                  kms_key_reference: Optional[str] = None) -> str:
    """The platform block of a non-Cloud-Run secondary: event-worker or gce-worker (HB-04 topology branch).
    `kms_key_reference` (lane 14 PR-0b) reaches the event-worker only: the gce-worker module has no resource type the
    compliance plan gate's CMEK table covers."""
    if vt.kind(name) == "gce-worker":
        return render_gce_worker_block(vt, name, files)
    return render_event_worker_block(vt, name, kms_key_reference)


def topology_network_purposes(vt: Optional["ValidatedTopology"]) -> FrozenSet[str]:
    """IPAM purposes the topology's own platform blocks need (a gce-worker subnet: WORKLOAD_SUBNET)."""
    if vt is not None and any(s.kind == "gce-worker" for s in vt.secondaries):
        return frozenset({WORKLOAD_SUBNET})
    return frozenset()


def topology_scaling(vt: ValidatedTopology, service: str, default_min: int, default_max: int) -> Dict[str, object]:
    """Scaling of a Cloud Run topology service: the architect's typed `scaling` when stated, else today's values
    (the residual spec-text scaling stays until its follow-up FD; plan F8 / owner Q3)."""
    spec = vt.spec(service)
    if spec is not None and spec.scaling is not None:
        return {"min_instances": spec.scaling.min_instances, "max_instances": spec.scaling.max_instances,
                "cpu_idle": not spec.scaling.cpu_always_allocated, "from_topology": True}
    return {"min_instances": default_min, "max_instances": default_max, "cpu_idle": None, "from_topology": False}


def health_path() -> str:
    """The path the compute-cloudrun module's startup probe calls (its `health_check_path` default, which the platform
    never overrides). Single source: validators/container.HEALTH_PATH (tests check it against the module)."""
    try:
        from .validators.container import HEALTH_PATH
    except ImportError:  # pragma: no cover
        from developer_agent.validators.container import HEALTH_PATH
    return HEALTH_PATH


def cloudrun_probe_services(compute_intent: object) -> List[str]:
    """AC-2: the services the platform renders with the compute-cloudrun module, read from typed facts only: on the
    topology path every service of kind `cloudrun`; on the legacy single-archetype path every service when the
    archetype is `cloudrun`, else the Cloud Run secondaries (`ComputeIntent.secondary_services`: `service_names[1:]`
    are Cloud Run services for every archetype and get the canonical compute-cloudrun module; none for
    foundation-only)."""
    vt = getattr(compute_intent, "topology", None)
    if vt is not None:
        return [n for n in vt.names if vt.kind(n) == "cloudrun"]
    if getattr(compute_intent, "archetype", None) == "cloudrun":
        return list(getattr(compute_intent, "service_names", ()) or ())
    return list(getattr(compute_intent, "secondary_services", ()) or ())


def non_cloudrun_services(compute_intent: object) -> List[str]:
    """DIRECT-IAP-SKILL-VERIFY: the workload's services `cloudrun_probe_services` does not name, from the same typed
    facts: on a mixed workload these are not rendered with compute-cloudrun, so no Direct IAP sits in front of them."""
    cloud_run = set(cloudrun_probe_services(compute_intent))
    return [n for n in (getattr(compute_intent, "service_names", ()) or ()) if n not in cloud_run]


def health_probe_rule(services: Optional[List[str]]) -> str:
    """AC-2 lead-prompt line: the platform's startup probe path for the Cloud Run services; "" when there are none
    (that prompt stays byte-identical)."""
    names = [s for s in (services or []) if s]
    if not names:
        return ""
    path = health_path()
    return (f"PLATFORM PROBE: the platform's Cloud Run startup probe calls `GET {path}` on "
            f"{', '.join(f'`{n}`' for n in names)}; each of these services must serve `GET {path}` returning 200 "
            f"(other health routes may be added, never instead). Copy this line into every task that writes these "
            f"services' routes.")


def gke_manifest_clause(name: str, plan_paths: Tuple[str, ...] = ()) -> str:
    """PWB-4 contract clause for a gke-autopilot service: the platform renders only the cluster and applies exactly the
    repository-root `k8s/*.yaml` (validators/container.K8sWorkloadValidator checks it); the image placeholder is the
    FD-4AF `${ARTIFACT_REGISTRY}` token (preflight_validator.K8S_MANIFEST_PLACEHOLDERS).

    PWB-4b (paid check 27b4623e, 04-r1/04-r3): the swarm never receives the static developer prompt that lists the
    FD-4AF placeholders, so 2 of 3 GKE drafts invented `${WORKLOAD_SA_EMAIL}` for the Workload Identity annotation and
    hydration stopped the stage (K8S.PLACEHOLDER_UNRESOLVED). The clause therefore names the exact placeholder set
    (single source: K8S_MANIFEST_PLACEHOLDERS) where the swarm reads it.

    MANIFEST-PATH-DEFERS-TO-DAG (owner 11-15): `plan_paths` = the applied manifest paths the architect's task DAG names
    for this service (plan_targets.dag_manifest_paths), so the generated file and the plan agree; () = the platform's
    own `k8s/<name>.yaml`, the clause byte-identical to before."""
    try:
        from .preflight_validator import K8S_MANIFEST_PLACEHOLDERS
    except ImportError:  # pragma: no cover
        from developer_agent.preflight_validator import K8S_MANIFEST_PLACEHOLDERS  # type: ignore
    tokens = ", ".join(f"`${{{t}}}`" for t in K8S_MANIFEST_PLACEHOLDERS)
    paths = [p for p in plan_paths if isinstance(p, str) and p]
    if len(paths) == 1:
        where = f"`{paths[0]}` (the manifest the architect's plan names for it; repository root; the "
    elif paths:
        where = (f"the architect's plan's manifests {', '.join(f'`{p}`' for p in paths)} (write each of them; "
                 f"repository root; the ")
    else:
        where = f"`k8s/{name}.yaml` (repository root; the "
    holder = "one of them holds " if len(paths) > 1 else ""
    return (f"; it runs on the platform's GKE Autopilot cluster only through {where}"
            f"platform applies exactly `k8s/*.yaml`): {holder}a Deployment named `{name}` whose container `{name}` uses "
            f"`image: ${{ARTIFACT_REGISTRY}}/{name}:latest` (the image the platform builds from `apps/{name}/`); "
            f"the only placeholders the platform substitutes in these manifests are exactly {tokens}, and any other "
            f"`$` in an `image:` or `iam.gke.io/gcp-service-account` value stops the build (write a Google service "
            f"account email as `<account>@${{PROJECT_ID}}.iam.gserviceaccount.com`)")


def topology_contract_rule(vt: Optional["ValidatedTopology"], iac_intent: bool = False,
                           generated_secrets: Optional[FrozenSet[str]] = None,
                           manifest_paths: Optional[Mapping[str, Tuple[str, ...]]] = None) -> str:
    """Developer / lead prompt block (plan §7.3 step 7): which services exist, where their code lives and the exact
    env keys the platform binds on each, so generated code reads the keys the wiring provides (the platform binds
    `<BASE>_URL` etc. only for declared edges and never guesses aliases). Empty for no topology and for a single
    service without edges or resources (that prompt stays byte-identical), unless that service is gke-autopilot (PWB-4:
    its manifest clause is a contract V3c-k8s enforces).
    TI-3: `iac_intent=True` (typed-intent mode only) replaces the two IaC-address lines (declare in custom.tf / do not
    declare the foundation's types) by the intent slots (iac_intent_contract.topology_slot_lines); False = unchanged.
    SECRET-INITIAL-VERSION (typed-intent mode only): one line per env key bound to a secret whose plan states
    initial_value (iac_intent_contract.secret_note_lines; none without the field), and `generated_secrets` (the
    dispatch's IntentRun.generated_secrets; None = no repository) for the slot lines.
    MANIFEST-PATH-DEFERS-TO-DAG: `manifest_paths` (plan_targets.dag_manifest_paths) names a gke-autopilot service's
    manifests after the architect's plan (gke_manifest_clause); None or a service without one = byte-identical."""
    if vt is None or (len(vt.names) <= 1 and not vt.intent.edges and not vt.intent.resources
                      and not any(vt.kind(n) == "gke-autopilot" for n in vt.names)):
        return ""
    lines = ["SERVICE TOPOLOGY CONTRACT (from the architect's typed plan; the platform renders all compute and wiring):"]
    for name in vt.names:
        env = vt.env_for(name)
        if iac_intent:   # TI-5-R2 P3: keys the realizing golden module binds on the typed path only
            env.update({k: "" for k in vt.typed_only_env_keys(name)})
        role = "primary" if name == vt.intent.primary_service else "secondary"
        if vt.kind(name) == "gce-worker":
            line = (f"- `{name}` (gce-worker, {role}): a VM the launcher starts on demand from an instance template; "
                    f"its code is the startup script `{GCE_WORKER_STARTUP_SCRIPT.format(name=name)}` (bash, runs as "
                    f"root on Debian 12 with no external IP: Google APIs only, no package downloads; power off when "
                    f"done)")
            if env:
                line += ("; read these instance metadata attributes (metadata server, "
                         "`computeMetadata/v1/instance/attributes/<KEY>`), with exactly these names: "
                         + ", ".join(sorted(env)))
            lines.append(line + ".")
            continue
        line = f"- `{name}` ({vt.kind(name)}, {role}): its code lives in `apps/{name}/`"
        launches = [e.callee for e in vt.intent.edges if e.protocol == "launch" and e.caller == name]
        if env:
            line += "; read these environment variables, with exactly these names: " + ", ".join(sorted(env))
        if vt.kind(name) == "cloudrun":  # AC-2: the compute-cloudrun module's startup probe path
            line += f"; it must serve `GET {health_path()}` returning 200 (the platform's startup probe)"
        if vt.kind(name) == "gke-autopilot":  # PWB-4: the cluster runs nothing until a manifest runs the image
            line += gke_manifest_clause(name, tuple((manifest_paths or {}).get(name, ())))
        if launches:
            line += ("; it starts gce-worker VMs with the Compute Engine API instances.insert (zone `<BASE>_ZONE`, "
                     "sourceInstanceTemplate `<BASE>_INSTANCE_TEMPLATE`, an instance name that starts with "
                     "`<BASE>_NAME_PREFIX`; any other name or zone is denied; then poll `instances.get` on the name "
                     "you chose, because operation polling is denied) for: " + ", ".join(sorted(launches)))
        lines.append(line + ".")
    lines.append("- Never declare a compute module, a google_cloud_run_v2_service or a google_container_cluster for "
                 "these services: the platform declares them (module \"compute\" and module \"compute_<service>\"). "
                 "Do not add services that are not listed.")
    if iac_intent:
        try:
            from .iac_intent_contract import secret_note_lines, topology_slot_lines
        except ImportError:  # pragma: no cover
            from developer_agent.iac_intent_contract import secret_note_lines, topology_slot_lines
        return "\n".join(lines + typed_binding_note_lines(vt) + secret_note_lines(vt)
                         + topology_slot_lines(vt, generated_secrets=generated_secrets))
    if vt.declared_resources():
        lines.append("- Declare these resources in infra/workload/custom.tf with exactly these addresses: "
                     + ", ".join(f"{t}.{n}" for t, n in vt.declared_resources()) + ".")
    if vt.foundation_resources():
        # fresh 10-14 regression report: these resources are bound to module.foundation outputs (shared/
        # service_topology.FOUNDATION_PROVIDED); asking the AI to declare them contradicted POLICY.PLATFORM_OWNED_TYPE
        types_ = sorted({t for t, _ in vt.foundation_resources()})
        outs = ", ".join(vt.foundation_outputs())
        lines.append(f"- Do not declare {', '.join(types_)}: the workload foundation (module.foundation) already "
                     f"declares it, and every environment variable the platform binds for it is {outs}. Where your "
                     f"IaC needs it (e.g. an output), reference {outs}.")
    return "\n".join(lines)


def typed_binding_note_lines(vt: Optional["ValidatedTopology"]) -> List[str]:
    """TI5-ALLOYDB-SECRET-BIND (typed-intent contract only): one line per service env key that reads a module-only
    attribute with a note (shared/service_topology.MODULE_ONLY_ATTRIBUTE_NOTES, exact table), so the app knows what
    the key holds (e.g. the AlloyDB password secret id). [] when no such key is bound (the contract is unchanged)."""
    if vt is None:
        return []
    return [f"- `{key}` on `{name}` is {note}." for name in vt.names
            for key, note in vt.typed_binding_notes(name).items()]


def workflow_services(vt: ValidatedTopology) -> List[str]:
    """CI workflow targets on the topology path: every topology service, primary first (kind from the topology). A
    gce-worker gets none: its instance template is IaC and its code is the template's startup script (L10-v)."""
    return [n for n in vt.names if vt.kind(n) != "gce-worker"]
