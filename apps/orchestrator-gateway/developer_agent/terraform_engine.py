"""
Project Castor: Golden Terraform Foundation & Archetype Engine
Implements deterministic, modular Terraform generation, module vendoring,
and declarative state migration (moved.tf) across all Castor workloads.
"""

import ast
import json
import logging
import os
import re
import unicodedata
from typing import Any, Dict, FrozenSet, Iterable, List, Mapping, Optional, Set, Tuple

logger = logging.getLogger("castor-terraform-engine")

VALID_ARCHETYPES = ["cloudrun", "gce-bastion", "gke-autopilot", "event-worker"]

try:
    from shared.github_identity import resolve_repo_identity
except ImportError:
    try:
        from .github_identity import resolve_repo_identity
    except ImportError:
        try:
            from github_identity import resolve_repo_identity
        except ImportError:
            def resolve_repo_identity(repo, default_owner=None, product_id=None):
                owner = default_owner or os.getenv("GITHUB_ORG") or os.getenv("GITHUB_OWNER")
                if not owner:  # FD-4AY: no built-in owner (shared.github_identity unavailable)
                    raise RuntimeError("No GitHub owner configured: set GITHUB_ORG")
                if repo and "/" in repo:
                    parts = repo.split("/", 1)
                    return parts[0], parts[1], repo
                clean_pid = (product_id or "workload").lower().replace("_", "-")
                repo_name = repo or clean_pid   # GITHUB-REPO-NAME-NO-PREFIX: shared default_repository_name
                return owner, repo_name, f"{owner}/{repo_name}"

# Step 1 S1-A: exact block ranges and the only edit primitives HB-04/HB-01 may use on LLM files.
try:
    from .assembly import (append_text, bespoke_root_text, block_text, index_blocks, index_blocks_with_skipped,
                           splice_block)
except ImportError:
    try:
        from assembly import (append_text, bespoke_root_text, block_text, index_blocks, index_blocks_with_skipped,
                              splice_block)
    except ImportError:
        from developer_agent.assembly import (append_text, bespoke_root_text, block_text, index_blocks,
                                              index_blocks_with_skipped, splice_block)

# Step 2 S2-D (HS-65): HB-05's sibling service_uri wiring, narrowed to exact env reads (pure functions).
try:
    from .sibling_wiring import CLOUD_RUN_MODULE_DIR, _is_cloud_run_module_source, plan_sibling_wiring
except ImportError:
    try:
        from sibling_wiring import CLOUD_RUN_MODULE_DIR, _is_cloud_run_module_source, plan_sibling_wiring
    except ImportError:
        from developer_agent.sibling_wiring import CLOUD_RUN_MODULE_DIR, _is_cloud_run_module_source, plan_sibling_wiring

# Lane 10 (FD-51): topology wiring (the one lane-10 module; it imports this module lazily, so no cycle).
try:
    from .topology_wiring import (render_gce_bastion_code_lines, render_secondary_worker_block, topology_env_vars,
                                  topology_scaling, topology_vpc_connector)
except ImportError:
    try:
        from topology_wiring import (render_gce_bastion_code_lines, render_secondary_worker_block, topology_env_vars,
                                     topology_scaling, topology_vpc_connector)
    except ImportError:
        from developer_agent.topology_wiring import (render_gce_bastion_code_lines, render_secondary_worker_block,
                                                     topology_env_vars, topology_scaling, topology_vpc_connector)

# (S1-A, HS-01) HB-01 no longer calls the HA-14 semantic dedupe; its import here is gone with the call.


# HD-01 / HD-02 (FD-4X, FD-4AC, FD21-08) deleted: `detect_compute_archetype` (archetype from spec keywords) and
# `detect_requested_service_count` / `detect_requested_service_names` (service names and counts from spec-prose regexes,
# padded with `service-N`). The archetype and the service set now come only from typed facts:
# developer_agent/compute_intent.py `resolve_compute_intent` (architect plan fields, pinned existing compute).


# HB-04 app-directory filter (lane 10 deletes it with HB-04); no longer used to read spec prose.
NON_SERVICE_NOUNS = {
    "topic", "topics", "bucket", "buckets", "collection", "collections",
    "database", "databases", "table", "tables", "dataset", "datasets",
    "secret", "secrets", "subscription", "subscriptions", "queue", "queues",
    "disk", "disks", "volume", "volumes", "pool", "pools", "repo", "repos",
    "repository", "repositories", "policy", "policies", "group", "groups",
    "role", "roles", "account", "accounts", "key", "keys", "certificate", "certificates",
    "rule", "rules", "schedule", "schedules", "metric", "metrics", "alert", "alerts",
    "file", "files", "folder", "folders", "network", "networks", "subnet", "subnets",
    "vpc", "vpcs", "connector", "connectors", "router", "routers",
    "common", "commons", "shared", "contract", "contracts", "lib", "libs", "pkg", "pkgs",
    "model", "models", "schema", "schemas", "util", "utils", "__init__.py", "__pycache__",
    "static", "templates", "assets", "docs", "documentation", "test", "tests",
}


# HB-02 (FD-4Y): the block kinds this extractor has always returned. Its callers (HB-01's declared-symbol set, HB-03,
# HB-05's custom-resource scan, resolve_service_archetype, the gatekeeper's secondary-module env cure) were written
# against exactly these kinds; variable/provider/terraform/moved/import blocks are still not returned (unchanged).
_EXTRACTED_BLOCK_KINDS = ("resource", "module", "output", "data", "locals")


def extract_hcl_blocks(hcl_text: str) -> List[Dict[str, Any]]:
    """
    Top-level `resource`, `module`, `output`, `data` and `locals` blocks of one HCL text, in file order.
    Returns list of dicts with keys: block_type, type_label, name_label, raw_text.

    HB-02 (FD-4Y): built on python-hcl2 (assembly.index_blocks, exact `with_meta` line ranges) instead of a line regex
    plus raw `{`/`}` counting. `raw_text` is the block's exact whole lines (a substring of `hcl_text`), so braces in
    strings or heredocs, and `resource ...` lines inside heredocs, no longer cut short or invent blocks.
    A text python-hcl2 cannot parse yields [] (nothing is guessed from it; V1a / `tofu validate` report the syntax
    error and it goes to the repair loop). A block python-hcl2 accepts but cannot range (a Terraform-invalid label
    count, of any kind: `index_blocks_with_skipped` reports it as skipped, FD-4Y RT F6) also yields [] for the whole
    text. A missing python-hcl2 raises assembly.HclUnavailable (deployment defect).
    """
    if not hcl_text:
        return []
    got = index_blocks_with_skipped(hcl_text)
    if got is None or got[1]:   # unparseable, or an entry python-hcl2 accepts that is no block (F6): never partial
        return []
    index = got[0]
    blocks: List[Dict[str, Any]] = []
    for b in index:
        if b.kind not in _EXTRACTED_BLOCK_KINDS:
            continue
        if b.start < 1 or b.end < b.start:  # no exact range: the whole text is unavailable, never a partial list
            return []
        if b.kind in ("resource", "data"):
            type_label, name_label = b.labels
        elif b.kind == "locals":
            type_label, name_label = "locals", ""
        else:
            type_label, name_label = "", b.labels[0]
        blocks.append({
            "block_type": b.kind,
            "type_label": type_label,
            "name_label": name_label,
            "raw_text": block_text(hcl_text, b),
        })
    return blocks


# CLOUD_RUN_MODULE_DIR and _is_cloud_run_module_source (Step 1 F6) moved verbatim to sibling_wiring.py (S2-D), which
# both HB-04 and HB-05 use; they are imported above and stay importable from this module.

# TI-1 (typed IaC plan §4): on the topology path the platform's secondary compute blocks live in their own
# platform-rendered file (shared/artifact_ownership.PLATFORM_RENDERED_FLOOR), never inside the AI's custom.tf.
SERVICES_TF = "infra/workload/services.tf"
SERVICES_TF_HEADER = "# Rendered by StackVend on every run: the topology's secondary services. Do not edit."


def topology_secondary_labels(topology: Any) -> List[str]:
    """Module labels of the topology's secondaries, in render order (Cloud Run, then event-worker, then gce-worker):
    exactly the blocks HB-04's topology branch renders (`ValidatedTopology.label`)."""
    names = (list(topology.secondaries_of_kind("cloudrun")) + list(topology.secondaries_of_kind("event-worker"))
             + list(topology.secondaries_of_kind("gce-worker")))
    return [topology.label(n) for n in names]


def services_tf_skip_addresses(files: Mapping[str, str], existing_files: Optional[Mapping[str, str]]) -> FrozenSet[str]:
    """TI-1: exact root addresses of golden compute modules that a repository file still in the tree (byte-identical,
    before assembly) declares. services.tf itself is excluded: it is the platform's own render and is re-rendered.
    A topology secondary at one of these addresses is not rendered into services.tf (no duplicate declaration)."""
    try:
        from .compute_intent import existing_compute_entries
    except ImportError:
        try:
            from compute_intent import existing_compute_entries
        except ImportError:
            from developer_agent.compute_intent import existing_compute_entries
    kept = {p: t for p, t in (existing_files or {}).items()
            if p != SERVICES_TF and isinstance(t, str) and files.get(p) == t}
    entries, _ = existing_compute_entries(kept)
    return frozenset(e.address for e in entries if e.root)


def services_tf_root_keys(topology: Any, skip: Optional[FrozenSet[str]] = None) -> Set[str]:
    """TI-1: the keys services.tf declares this run (S1-A root keys: an AI copy is a recorded
    PLATFORM_ROOT_DECLARATION). Empty without a topology."""
    if topology is None:
        return set()
    return {f"module.{label}" for label in topology_secondary_labels(topology)} - set(skip or ())


def reconcile_multi_service_declarations(
    files: Dict[str, str],
    product_id: str,
    spec_text: str,
    archetype: str = "cloudrun",
    allow_unauthenticated: bool = True,
    enable_direct_iap: bool = False,
    authorized_invoker_members: Optional[List[str]] = None,
    target_services: Optional[List[str]] = None,
    *,
    assembly_record: Optional[Any] = None,
    llm_iac_paths: Optional[List[str]] = None,
    topology: Optional[Any] = None,
    services_tf_skip: Optional[FrozenSet[str]] = None,
    regulated: Optional[Any] = None,
    default_min_instances: int = 0,
    typed_iac: bool = False,
    planned_out: Optional[List[str]] = None,
    push_identities: Optional[Mapping[str, Mapping[str, str]]] = None,
    legacy_vpc_connector: Optional[str] = None,
    relocated_draft_paths: Iterable[str] = (),
    deployed_files: Optional[Mapping[str, str]] = None,
    repository_keys: Iterable[str] = (),
    app_admin_emails: Optional[Iterable[str]] = None,
) -> None:
    """
    APP-ADMIN-IAP-CONTRACT: `app_admin_emails` not None (a Direct IAP Cloud Run workload) adds
    `STACKVEND_APP_ADMIN_EMAILS = jsonencode(var.app_admin_emails)` to the `env_vars` of every Cloud Run secondary this
    call synthesizes (event-worker / gce-worker secondaries are not Cloud Run services). None = today's output, byte
    for byte.

    RT14-12: `repository_keys` (the block keys of the REPOSITORY's infra/workload/custom.tf, as committed before this
    build: handler.repository_custom_tf_keys) protects a person's blocks there. A google_cloud_run_v2_service whose key
    is in it is never spliced out of custom.tf, never replaced by a compute module and never counted as a service to
    synthesize: it is kept byte-identical and reported (AssemblyRecord.kept_repository, a warning). Only Cloud Run
    services of this run's AI draft are replaced, as before. () = today's output, byte for byte.

    SIBLING-AUDIENCE-GETENV-DEFAULT RT F1: `deployed_files` (topology_wiring.deployed_view: the tree the build deploys)
    is forwarded to topology_env_vars, which reads it ONLY for the audience decision; every other input of this render
    (bespoke_hcl, HB-05, the connector view) is unchanged. None = today's output, byte for byte.

    FD4DK-3: `relocated_draft_paths` (assembly.AssemblyResult.relocated_draft_paths: the AI's draft files at platform
    paths whose text the assembly already appended to custom.tf, still keyed until the golden render) are left out of
    the files topology_vpc_connector reads, so a database / connector / subnet the AI wrote in main.tf counts once.
    Nothing else reads that view. () = today's output, byte for byte.

    FD-4DK: `legacy_vpc_connector` (topology_wiring.legacy_vpc_connector: the workload's one connector on the network
    of a private Cloud SQL / Redis / AlloyDB its root-module IaC declares, e.g. `google_vpc_access_connector.c.id`)
    sets the `vpc_access_connector` input of every Cloud Run secondary synthesized WITHOUT a topology (the legacy
    path). Ignored with `topology` (topology_vpc_connector decides there). None = today's output, byte for byte.

    PUSH-TO-PRIVATE: `push_identities` ({compute-cloudrun module address: {key: email expression}}, the typed
    intent's push identities, iac_intent_contract.IntentAssembly.push_identities) sets the `push_service_accounts`
    input of each topology Cloud Run secondary it names. None / {} = today's output, byte for byte.

    FD-55 W5 RT F2: `planned_out` (a list the caller owns) receives the Cloud Run services this call synthesizes or
    keeps as the primary, exactly the set the deleted placeholder app was written for (the primary unless it is
    `product_id`, then every secondary compute module it renders, including one the AI declared as
    `module "compute_<x>"` on the legacy path); the caller feeds them to V3c-planned. None = nothing recorded.

    FD-4CI-b: `default_min_instances` is the min_instances of a secondary Cloud Run service whose spec states no
    minimum (the platform's Enforce Scale-to-Zero setting: 0 when on, 1 when off). 0 = today's output, byte for byte.

    Lane 14 PR-0b: with `regulated` (compliance_profile.RegulatedControls requiring CMEK) every platform-synthesized
    secondary compute module also gets the workload key (`module.cmek.crypto_key_name`); None = unchanged.

    Reconciles Cloud Run service declarations for multi-service workloads (HB-04; lane 10 replaces it with the typed
    topology). Lane 10 (FD-51): with `topology` (a shared.service_topology.ValidatedTopology) the secondary set is
    EXACTLY the topology's Cloud Run + event-worker secondaries (no app-directory or LLM-label union: FD-4AC), each
    secondary's env comes from topology_wiring.topology_env_vars (edges only: FD-40/41/42/43/45) and its scaling
    from the topology when stated. Without `topology` nothing changes. Step 1 S1-A (register HS-01) made it
    APPEND-ONLY:
    1. If N services are requested, the platform synthesizes the canonical compute-cloudrun module for every
       secondary service (no app code is written: FD-55 W5) and APPENDS it to custom.tf; a module key the LLM
       already declared is replaced in place by the synthesized text (recorded PLATFORM_RESYNTHESIZED).
    2. Every LLM `google_cloud_run_v2_service` block (in custom.tf and in every auxiliary LLM .tf file) is replaced by
       a compute module (RT14-12: never one the repository's custom.tf already declares, see `repository_keys`): removed by its exact python-hcl2 line range and recorded in the AssemblyRecord as
       CLOUD_RUN_REPLACED_BY_MODULE -> module.compute_<label> when that module is synthesized for the exactly equal
       label, else module.compute. References to it are NOT rewritten (the repair loop fixes them with the hint).
    3. Nothing else is removed, rewritten or deduplicated: the former foundation-type, SA-name, role-substring,
       IAP-substring, budget/alert-keyword and output strips, the `.service_url` rewrite and the custom.tf rebuild
       from regex-recognized blocks are deleted (eval baseline: they deleted 72/72 LLM declarations that dangled).
    TI-1 (typed IaC plan §4): with `topology`, step 1 renders every secondary into the platform's own
    infra/workload/services.tf (rewritten whole each run; module addresses unchanged) instead of appending to
    custom.tf. A secondary whose exact address is in `services_tf_skip` (services_tf_skip_addresses: a repository
    file still in the tree declares it) is not rendered again. The in-place replacement of a key found in an LLM
    file is unchanged. Without `topology` nothing changes.
    FD55-W2 (register TI-4a): `typed_iac` (a typed-intent run, TI-3: no AI-authored HCL) skipped the HB-01 reference
    reconciler. FD-55 W5 deleted HB-01 (reconcile_iac_reference_graph) on every run, so `typed_iac` changes nothing
    here any more; it stays in the signature for its callers.
    """
    is_non_cr_primary = archetype in ("gke-autopilot", "gce-bastion", "event-worker", "foundation-only")
    relocated_drafts = frozenset(relocated_draft_paths or ())   # FD4DK-3: topology_vpc_connector's view only
    custom_key = "infra/workload/custom.tf"
    ai_paths = [p for p in (llm_iac_paths if llm_iac_paths is not None else [custom_key])
                if isinstance(files.get(p), str)]
    # TI-1: a prior run's services.tf (repository file) is the platform's own earlier render, replaced below; it is
    # never an input of this render (the env wiring reads only bespoke IaC).
    bespoke_hcl = bespoke_root_text(files if topology is None else
                                    {p: t for p, t in files.items() if p != SERVICES_TF})

    # Check distinct microservice subdirectories under apps/ early (Ground Truth)
    app_dirs = []
    if files:
        for path in sorted(files.keys()):
            m = re.match(r"^apps/([^/]+)/", path)
            if m:
                s_cand = m.group(1).lower()
                clean_s = s_cand.replace("_", "-")
                if s_cand in NON_SERVICE_NOUNS or clean_s in NON_SERVICE_NOUNS or s_cand.endswith(".py"):
                    continue
                if clean_s == product_id.lower().replace("_", "-"):
                    continue
                if any(f"apps/{m.group(1)}/{ep}" in files for ep in ("main.py", "app.py", "server.js", "main.go", "index.js", "main.ts", "app.ts", "Procfile", "package.json")):
                    if clean_s not in app_dirs:
                        app_dirs.append(clean_s)

    # HD-02 replacement: the requested service set is the typed compute intent (compute_intent.resolve_compute_intent:
    # architect `target_compute_services` + pinned existing compute), never spec prose. requested_names[0] is the
    # workload on module.compute; requested_names[1:] are Cloud Run secondaries.
    requested_names: List[str] = []
    for s in target_services or []:
        clean = str(s).strip().lower().replace("_", "-")
        if clean and clean not in requested_names:
            requested_names.append(clean)
    requested_count = max(len(requested_names), len(app_dirs))

    # LLM service declarations, found by exact python-hcl2 block ranges in every LLM root-module file.
    # Services are declared by compute modules and google_cloud_run_v2_service resources only (exact types):
    # IAM members are never service names (they used to become phantom secondary services).
    cr_resources: List[Any] = []        # (path, Block) of LLM google_cloud_run_v2_service blocks
    service_labels: List[str] = []      # labels of LLM compute modules + Cloud Run services, in file order
    # RT14-12: Cloud Run services the repository's custom.tf declares (a person's, or a prior build's) stay as they are
    kept_cr_keys = _repository_cloud_run_keys(files, custom_key, repository_keys, assembly_record)
    for path in ai_paths:
        text = files[path]
        for b in index_blocks(text) or []:
            if b.kind == "resource" and b.labels and b.labels[0] == "google_cloud_run_v2_service":
                if path == custom_key and b.key in kept_cr_keys:
                    continue   # RT14-12: a repository block, not this run's draft: kept, never a service to synthesize
                cr_resources.append((path, b))
                service_labels.append(b.labels[1])
            elif b.kind == "module" and b.labels and b.labels[0] not in ("compute", "foundation") and \
                    _is_cloud_run_module_source((b.body or {}).get("source")):
                # Step 1 code RT F6: decided by the exact `source` value (the module directory is the golden
                # compute-cloudrun module), not by "compute" in the label or "cloudrun" anywhere in the block text,
                # which counted e.g. a compute-gke-autopilot / compute-event-worker module as a Cloud Run service.
                service_labels.append(b.labels[0])

    primary_svc = None
    worker_secondaries: List[str] = []
    if topology is not None:
        # LANE 10 topology branch: the typed service set only.
        secondary_service_names = list(topology.secondaries_of_kind("cloudrun"))
        worker_secondaries = list(topology.secondaries_of_kind("event-worker")) + list(topology.secondaries_of_kind("gce-worker"))
        if topology.primary is not None and topology.primary.kind == "cloudrun":
            primary_svc = topology.primary.name
        if not secondary_service_names and not worker_secondaries:
            _replace_cloud_run_resources(files, cr_resources, set(), assembly_record, kept_cr_keys)
            return
        needed_extra_services = len(secondary_service_names)
    elif is_non_cr_primary:
        # For non-Cloud Run primary archetypes (e.g. GKE Autopilot), module.compute in main.tf is NOT Cloud Run.
        # Typed contract: requested_names[0] is the workload the primary (cluster / VM / job) runs; only
        # requested_names[1:] are Cloud Run secondaries (e.g. an edge gateway). Without a typed list (legacy callers)
        # the LLM's own app directories are the secondaries, as before.
        candidate_services = requested_names[1:] if requested_names else app_dirs
        if not candidate_services and not service_labels:
            _replace_cloud_run_resources(files, cr_resources, set(), assembly_record, kept_cr_keys)
            return

        needed_extra_services = len(candidate_services)
        secondary_service_names = list(candidate_services)
    else:
        if requested_count <= 1:
            # Single service: main.tf's module.compute is the sole platform compute; every LLM Cloud Run service
            # resource is replaced by it (recorded), every other LLM block stays byte-identical.
            _replace_cloud_run_resources(files, cr_resources, set(), assembly_record, kept_cr_keys)
            return

        # Multi-service requested (e.g. requested_count = 2)
        primary_svc = requested_names[0] if requested_names else (app_dirs[0] if app_dirs else product_id)

        # Extract names for secondary services, strictly excluding primary_svc
        secondary_service_names = [s for s in requested_names[1:] if s != primary_svc]
        for s in app_dirs:
            if s != primary_svc and s not in secondary_service_names:
                secondary_service_names.append(s)
        for label in service_labels:
            # Exact label prefix of the platform's own module naming (module "compute_<name>"). The pre-Step-1 code
            # tested the prefix after replacing "_" with "-", so a synthesized compute_x module re-entering on a
            # later assembly became a phantom "compute-x" service; S1-A requires re-assembly to be idempotent.
            clean_name = label.lower()
            if clean_name.startswith("compute_"):
                clean_name = clean_name[len("compute_"):]
            clean_name = clean_name.replace("_", "-")
            if clean_name not in (product_id.lower(), "compute", "app", primary_svc) and clean_name not in secondary_service_names:
                secondary_service_names.append(clean_name)

        # Every secondary is named (typed list, app dirs, LLM compute modules): nothing is padded with `service-N`.
        needed_extra_services = len(secondary_service_names)

        # G14 (HB-04c) DELETED (FD-55 W5): the regex rewrite of main.tf's `service_name` / `/<old>:` image path to
        # primary_svc. main.tf is the platform's render (generate_golden_main_tf, written after this call), so the
        # rewrite never reached a committed file.

    # Build canonical module blocks for each secondary service
    scaling = extract_scaling_from_spec(spec_text, default_min_instances=default_min_instances)
    min_inst = scaling.get("min_instances", 0)
    max_inst = scaling.get("max_instances", 10)

    canonical_modules = []
    secondary_cmek_line = f"  encryption_key        = {CMEK_KEY_REFERENCE}\n" if _wants_cmek(regulated) else ""
    secondary_iap_line = iap_project_number_line(allow_unauthenticated, enable_direct_iap)   # IAP-GATE-KNOWN-MEMBER
    for s_name in secondary_service_names[:needed_extra_services]:
        clean_s_name = s_name.replace("_", "-")
        gcp_svc_name = clean_s_name
        if len(gcp_svc_name) > 60:
            gcp_svc_name = gcp_svc_name[:60].rstrip("-")

        # Extract custom resource environment variables specific to this secondary service
        # (guarantees cycle prevention: never injects own service_uri)
        s_min, s_max, s_cpu_idle = min_inst, max_inst, "true"
        s_connector_line = ""
        if topology is not None:
            # lane 10: edges only (no sibling discovery); scaling from the topology when the architect stated it
            svc_env = topology_env_vars(topology, clean_s_name, bespoke_hcl, files, caller_service=clean_s_name,
                                        allow_unauthenticated=allow_unauthenticated,   # SIBLING-AUDIENCE-BINDING
                                        deployed_files=deployed_files)   # SIBLING-AUDIENCE-GETENV-DEFAULT RT F1
            # platform-db-connector-wiring: the connector to a private resource this service consumes ("" = none)
            s_connector_line = vpc_connector_line(topology_vpc_connector(
                topology, clean_s_name, {p: t for p, t in files.items() if p not in relocated_drafts}))   # FD4DK-3
            sc = topology_scaling(topology, clean_s_name, min_inst, max_inst)
            s_min, s_max = sc["min_instances"], sc["max_instances"]
            if sc["cpu_idle"] is not None:
                s_cpu_idle = "true" if sc["cpu_idle"] else "false"
        else:
            svc_env = extract_custom_resource_env_vars(bespoke_hcl, files, caller_service=clean_s_name)
            s_connector_line = vpc_connector_line(legacy_vpc_connector)   # FD-4DK: "" for None (unchanged)
        svc_env_vars_expr = format_hcl_env_vars(with_app_admin_env(svc_env, app_admin_emails))   # APP-ADMIN
        s_label = f"compute_{clean_s_name.replace('-', '_')}"
        s_push_line = (push_service_accounts_line((push_identities or {}).get(f"module.{s_label}"))
                       if topology is not None else "")

        mod_block = f"""module "{s_label}" {{
  source                = "../modules/compute-cloudrun"
  project_id            = var.project_id
  region                = var.region
  product_id            = var.product_id
  service_name          = {hcl_quoted(gcp_svc_name)}
  service_account_email = module.foundation.workload_sa_email
  container_image       = replace(var.container_image, "/app:", {hcl_quoted("/" + clean_s_name + ":")})
  oauth_client_id       = var.oauth_client_id
  firebase_api_key      = var.firebase_api_key
  firebase_auth_domain  = var.firebase_auth_domain
  min_instances         = {s_min}
  max_instances         = {s_max}
  cpu_idle              = {s_cpu_idle}
  allow_unauthenticated = var.allow_unauthenticated
  enable_direct_iap     = var.enable_direct_iap
  authorized_invoker_members = var.authorized_invoker_members
{secondary_iap_line}{s_push_line}  cpu_limit             = var.cpu_limit
  memory_limit          = var.memory_limit
{s_connector_line}  env_vars              = {svc_env_vars_expr}
{secondary_cmek_line}
  depends_on = [module.foundation]
}}"""
        canonical_modules.append(mod_block)
    for w_name in worker_secondaries:   # lane 10: the one event-worker secondary (RT F3) and every gce-worker (L10-v)
        canonical_modules.append(render_secondary_worker_block(
            topology, w_name, files, kms_key_reference=CMEK_KEY_REFERENCE if _wants_cmek(regulated) else None))

    # G15 (HB-04d) DELETED (FD-55 W5, register FD55-W5): the placeholder app ("Hello World" FastAPI main.py + Procfile
    # + .python-version + requirements.txt) written for a planned service with no code, which deployed as if it
    # worked. Nothing is written for it now: V3c-planned (validators/container.py PlannedServiceCodeValidator,
    # planned set = planned_cloud_run_services below, plus `planned_out`) reports CONTAINER.ENTRYPOINT_MISSING on
    # apps/<svc>/Procfile. RT F2: the services the stub covered are recorded here, from the names this call renders.
    if planned_out is not None:
        stub_scope = ([primary_svc] if primary_svc and primary_svc != product_id else []) + \
            [s.replace("_", "-") for s in secondary_service_names[:needed_extra_services]]
        planned_out.extend(n for n in dict.fromkeys(stub_scope) if n not in planned_out)

    # Append-only: a synthesized module whose key the LLM already declared replaces that block in place (platform
    # owns its compute modules: PLATFORM_RESYNTHESIZED); otherwise it is appended to custom.tf (legacy path) or, on
    # the topology path (TI-1), rendered into services.tf.
    services_blocks: List[str] = []
    synthesized_labels = set()
    for mod_block in canonical_modules:
        label = mod_block.split('"', 2)[1]
        synthesized_labels.add(label)
        key = f"module.{label}"
        hit = None
        for path in ai_paths:
            for b in index_blocks(files[path]) or []:
                if b.kind == "module" and b.labels and b.labels[0] == label:
                    hit = (path, b)
                    break
            if hit:
                break
        if hit:
            splice_block(files, hit[0], hit[1], mod_block, assembly_record)
            if assembly_record is not None:
                assembly_record.record(key, key, "PLATFORM_RESYNTHESIZED", hit[0])
        elif topology is None:
            append_text(files, custom_key, mod_block)
        elif key in (services_tf_skip or ()):
            logger.info(f"TI-1: {key} is declared by a repository file; not rendered into {SERVICES_TF}")
        else:
            services_blocks.append(mod_block)
    if topology is not None and (services_blocks or SERVICES_TF in files):
        # TI-1: the whole file is the platform's render (a prior run's services.tf is replaced, never appended to)
        files[SERVICES_TF] = "\n\n".join([SERVICES_TF_HEADER] + [b.rstrip("\n") for b in services_blocks]) + "\n"
    _replace_cloud_run_resources(files, cr_resources, synthesized_labels, assembly_record, kept_cr_keys)


def planned_cloud_run_services(archetype: str, product_id: str, target_services: Iterable[str],
                               topology: Optional[Any] = None) -> Tuple[str, ...]:
    """FD-55 W5 (register FD55-W5): the Cloud Run services of a multi-service plan whose code must exist under
    `apps/<service>/`: exactly the services the deleted HB-04 placeholder app (G15) was written for, from typed facts
    only. With `topology` (lane 10): the cloudrun primary (unless it is named `product_id`) and every cloudrun
    secondary, when the topology has any secondary (cloudrun, event-worker or gce-worker). Without: the typed service
    list `target_services` (compute_intent.service_names) when it names more than one service: on a Cloud Run
    primary archetype the first (unless it is `product_id`) and the others; on a gke-autopilot / gce-bastion /
    event-worker primary only the others (the secondaries). foundation-only / none / empty: none. Order kept,
    duplicates dropped. V3c-planned (validators/container.py) reports each one that has no entrypoint file."""
    if archetype in ("foundation-only", "none", "empty"):
        return ()
    names: List[str] = []
    if topology is not None:
        secondaries = list(topology.secondaries_of_kind("cloudrun"))
        workers = list(topology.secondaries_of_kind("event-worker")) + list(topology.secondaries_of_kind("gce-worker"))
        if not secondaries and not workers:
            return ()
        primary = topology.primary
        if primary is not None and primary.kind == "cloudrun" and primary.name != product_id:
            names.append(primary.name)
        names.extend(secondaries)
    else:
        requested: List[str] = []
        for s in target_services or []:
            clean = str(s).strip().lower().replace("_", "-")
            if clean and clean not in requested:
                requested.append(clean)
        if len(requested) <= 1:
            return ()
        if archetype in ("gke-autopilot", "gce-bastion", "event-worker"):
            names.extend(requested[1:])
        else:
            if requested[0] != product_id:
                names.append(requested[0])
            names.extend(requested[1:])
    return tuple(dict.fromkeys(n for n in names if n))


def _repository_cloud_run_keys(files: Mapping[str, str], custom_key: str, repository_keys: Iterable[str],
                                assembly_record: Optional[Any]) -> FrozenSet[str]:
    """RT14-12: the google_cloud_run_v2_service keys of the tree's custom.tf that the repository's custom.tf already
    declared (`repository_keys`), each recorded as kept (AssemblyRecord.kept_repository) and logged. Exact keys of
    the python-hcl2 block index; empty when custom.tf is absent or `repository_keys` is empty."""
    repo = frozenset(repository_keys or ())
    if not repo or not isinstance(files.get(custom_key), str):
        return frozenset()
    kept = frozenset(b.key for b in (index_blocks(files[custom_key]) or [])
                     if b.kind == "resource" and b.labels and b.labels[0] == "google_cloud_run_v2_service"
                     and b.key in repo)
    for key in sorted(kept):
        if assembly_record is not None:
            assembly_record.kept_repository[key] = custom_key
        logger.warning(f"RT14-12: {key} in {custom_key} is a repository Cloud Run service (not this build's draft); "
                       f"kept unchanged, not replaced by a compute module")
    return kept


def _replace_cloud_run_resources(files: Dict[str, str], cr_resources: List[Any], synthesized_labels: set,
                                 assembly_record: Optional[Any], kept_keys: FrozenSet[str] = frozenset()) -> None:
    """Remove every LLM google_cloud_run_v2_service block (exact range) and record what replaces it: the compute
    module synthesized for the exactly equal label, else the primary module.compute (Step 1 RT F3, owner 2).
    RT14-12: a block of custom.tf whose key is in `kept_keys` (the repository's own, _repository_cloud_run_keys) is
    never removed."""
    for path in sorted({p for p, _ in cr_resources}):
        # re-index the file as it is now (earlier splices may have moved lines) and splice bottom-up
        current = [b for b in (index_blocks(files[path]) or [])
                   if b.kind == "resource" and b.labels and b.labels[0] == "google_cloud_run_v2_service"
                   and not (path == "infra/workload/custom.tf" and b.key in kept_keys)]
        for b in sorted(current, key=lambda x: x.start, reverse=True):
            splice_block(files, path, b, None, assembly_record)
            label = b.labels[1]
            target = f"module.compute_{label}" if f"compute_{label}" in synthesized_labels else "module.compute"
            if assembly_record is not None:
                assembly_record.record(b.key, target, "CLOUD_RUN_REPLACED_BY_MODULE", path)
            logger.info(f"S1-A: replaced LLM Cloud Run service {b.key} in {path} by {target} (recorded)")


# G16 HB-01 `reconcile_iac_reference_graph` DELETED (FD-55 W5, register FD55-W5): in the AI's custom.tf it re-pointed
# `*_sa` locals (names containing scheduler_sa / gateway_sa / core_processor_sa) and Cloud Scheduler
# `service_account_email` values to module.foundation.workload_sa_email, and Pub/Sub push endpoints / audiences to
# `module.compute_<x>.service_uri` when `<x>` was a substring of the subscription's label or text (name matching).
# A wrong reference is reported instead (V1b `tofu validate`, the sibling / topology validators) and the AI repairs it.


def get_platform_modules_path() -> Optional[str]:
    """Finds the platform infra/modules directory on the filesystem if available."""
    # Try relative to this file: apps/orchestrator-gateway/developer_agent/../../..
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../"))
    infra_modules = os.path.join(base_dir, "infra", "modules")
    if os.path.isdir(infra_modules):
        return infra_modules
    return None


def get_canonical_module_files() -> Dict[str, str]:
    """
    Loads all canonical module files from disk if available, or returns embedded
    production-grade fallback definitions.

    FD-4CB-b (owner 10-24): the golden modules the developer stage can vend into a workload. A module in
    shared.host_platform_modules.NOT_VENDORED_TO_WORKLOADS (`workflows`: the host platform's own orchestrator / SRE
    workflows, whose main.tf reads files that exist only in the StackVend repo; FD-4CB-c `cloud_build`: the host
    platform's own CI service account and build triggers) is never returned, so it is never
    vendored and a workload `module` block sourcing it is refused by V2j (POLICY.MODULE_SOURCE_NOT_LOCAL). Exact
    module-directory names (first path segment under infra/modules/); `workflows-dag` is a different directory and
    stays. The host platform's own use (infra/platform/main.tf) reads infra/modules/ directly and is unaffected.
    """
    from shared.host_platform_modules import NOT_VENDORED_TO_WORKLOADS  # no fallback: never silently vend it

    modules: Dict[str, str] = {}
    mod_path = get_platform_modules_path()

    if mod_path and os.path.isdir(mod_path):
        for root, dirs, files_in_dir in os.walk(mod_path):
            tf_files = [f for f in files_in_dir if f.endswith(".tf")]
            if tf_files:
                rel_dir = os.path.relpath(root, mod_path)
                if rel_dir.split(os.sep)[0] in NOT_VENDORED_TO_WORKLOADS:
                    continue
                for fname in tf_files:
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8") as f:
                            modules[f"infra/modules/{rel_dir}/{fname}"] = f.read()
                    except Exception as e:
                        logger.warning(f"Failed to read module file {fpath}: {e}")

    if modules:
        return modules

    # Embedded fallback definitions if running without platform directory mounted
    return _get_embedded_modules()


def _get_embedded_modules() -> Dict[str, str]:
    """Provides embedded canonical modules as resilient fallback (FD-4CB-b: same exclusion as above)."""
    from shared.host_platform_modules import NOT_VENDORED_TO_WORKLOADS  # no fallback: never silently vend it

    modules: Dict[str, str] = {}
    try:
        from shared.builtin_modules_payload import BUILTIN_MODULE_FILES
        for mod_id, fdict in BUILTIN_MODULE_FILES.items():
            if mod_id.split("/")[0] in NOT_VENDORED_TO_WORKLOADS:
                continue
            for fname, fcontent in fdict.items():
                modules[f"infra/modules/{mod_id}/{fname}"] = fcontent
    except Exception as e:
        logger.warning(f"Could not load embedded BUILTIN_MODULE_FILES: {e}")
    return modules


def vendor_composite_bundle(files: Dict[str, str], bundle_id: str) -> bool:
    """
    Vendors a composite bundle into infra/bundles/<bundle_id>/
    and cascades its underlying modules into infra/modules/.
    """
    clean_id = bundle_id.strip().lower()
    built = None
    try:
        from shared.builtin_bundles_payload import get_builtin_bundle
        built = get_builtin_bundle(clean_id)
    except Exception:
        try:
            from builtin_bundles_payload import get_builtin_bundle
            built = get_builtin_bundle(clean_id)
        except Exception:
            pass

    bundle_record = None
    if built:
        bundle_record = built
    else:
        try:
            from google.cloud import firestore
            client = firestore.Client()
            doc = client.collection("custom_bundles").document(clean_id).get()
            if doc.exists:
                from shared.bundle_schema import CompositeBundleRecord
                bundle_record = CompositeBundleRecord(**doc.to_dict())
        except Exception as e:
            logger.debug(f"Could not load custom bundle {clean_id}: {e}")

    if not bundle_record:
        return False

    prefix = f"infra/bundles/{clean_id}/"
    for fname, fcontent in bundle_record.hcl_files.items():
        files[f"{prefix}{fname}"] = fcontent

    manifest = {
        "bundle_id": clean_id,
        "name": bundle_record.name,
        "version": bundle_record.version_tag or "1.0.0",
        "commit_sha": bundle_record.commit_sha,
        "source_type": bundle_record.source_type.value if hasattr(bundle_record.source_type, "value") else str(bundle_record.source_type),
        "source_url": bundle_record.source_url,
        "modules_included": bundle_record.modules_included,
        "supported_engines": bundle_record.supported_engines,
        "default_engine": bundle_record.default_engine,
        "resource_footprint": bundle_record.resource_footprint,
    }
    files[f"{prefix}.castor-bundle.json"] = json.dumps(manifest, indent=2)

    # Cascade vendoring of composed Golden Modules
    canonical_files = get_canonical_module_files()
    for mod_name in bundle_record.modules_included:
        for path, content in canonical_files.items():
            if path.startswith(f"infra/modules/{mod_name}/"):
                files[path] = content

    return True


def local_source_dir(source: Any, kind: str) -> Optional[str]:
    """FD-55 W5 (plan G20 HD-39 CONVERT): the directory a module call's literal `source` names right after its first
    exact `<kind>` path component (`kind` = "modules" or "bundles"), for a LOCAL source only (`./...` or `../...`;
    leading `.`/`..` components skipped). "../modules/workload-foundation/base" -> "workload-foundation",
    "./infra/modules/x" -> "x", "../../modules/x" -> "x"; a registry / git / interpolated source, or a path with no
    exact `<kind>` component (e.g. "../my_modules/x"), -> None."""
    if not isinstance(source, str) or "${" in source or not source.startswith(("./", "../")):
        return None
    parts = [p for p in source.split("/") if p not in ("", ".")]
    while parts and parts[0] == "..":
        parts.pop(0)
    for i, part in enumerate(parts[:-1]):
        if part == kind:
            return parts[i + 1]
    return None


def _module_sources_of(path: str, text: Any) -> List[str]:
    """The literal `source` values of the top-level module calls of one root-module file: python-hcl2 for `.tf`
    (assembly.index_blocks; comments are not code), json for `.tf.json` (`module` object, or a list of them). A file
    that does not parse yields none (V1a / V1b report it; nothing is read from its text)."""
    if not isinstance(text, str):
        return []
    out: List[str] = []
    if path.endswith(".tf"):
        for b in index_blocks(text) or []:
            src = (b.body or {}).get("source") if b.kind == "module" else None
            if isinstance(src, str):
                out.append(src)
    elif path.endswith(".tf.json"):
        try:
            doc = json.loads(text)
        except ValueError:
            return []
        mods = doc.get("module") if isinstance(doc, dict) else None
        for group in (mods if isinstance(mods, list) else [mods]):
            for body in (group.values() if isinstance(group, dict) else []):
                for b in (body if isinstance(body, list) else [body]):
                    if isinstance(b, dict) and isinstance(b.get("source"), str):
                        out.append(b["source"])
    return out


def referenced_local_dirs(files: Mapping[str, Any], kind: str, *, skip_prefixes: Iterable[str] = ()) -> Set[str]:
    """FD-55 W5 (HD-39): every `local_source_dir(source, kind)` of a module call in a `.tf` / `.tf.json` file of
    `files` outside `skip_prefixes`, by parser (replaces the `source = "...modules/<x>"` regexes, which also read
    commented-out lines and any `*modules/` substring)."""
    skip = tuple(skip_prefixes)
    found: Set[str] = set()
    for fpath, fcontent in files.items():
        if not fpath.endswith((".tf", ".tf.json")) or (skip and fpath.startswith(skip)):
            continue
        for src in _module_sources_of(fpath, fcontent):
            name = local_source_dir(src, kind)
            if name:
                found.add(name)
    return found


def vendor_terraform_modules(
    files: Dict[str, str],
    selected_archetype: str = "cloudrun",
    selected_bundle: Optional[str] = None,
    intent_modules: Iterable[str] = (),
) -> None:
    """
    Vendors canonical foundation, compute archetype modules, and composite bundles
    into the child repository under infra/modules/ and infra/bundles/.

    TI-3 (typed IaC plan §3 "Vendoring"): `intent_modules` = the exact golden-module ids the gate-clean typed intent
    instantiates (iac_intent_contract.IntentAssembly.modules); they are vendored like an invoked module. Empty (mode
    "off") = unchanged.
    FD-55 W5 (register FD55-W5; plan G20 HD-39 CONVERT): an invoked bundle / module is the exact local `source` of a
    module call found by parser (referenced_local_dirs: python-hcl2 for `.tf`, json for `.tf.json`), never a regex
    over the text: a commented-out `source` line vendors nothing.
    """
    # 0. Check and vendor composite bundles if requested or invoked
    invoked_bundles = set()
    if selected_bundle:
        invoked_bundles.add(selected_bundle.strip().lower())
    invoked_bundles |= {b.lower() for b in referenced_local_dirs(files, "bundles",
                                                                 skip_prefixes=("infra/bundles/", "infra/modules/"))}

    for b_id in invoked_bundles:
        vendor_composite_bundle(files, b_id)

    canonical_files = get_canonical_module_files()

    archetype_dir_map = {
        "cloudrun": "compute-cloudrun",
        "gke-autopilot": "compute-gke-autopilot",
        "gce-bastion": "compute-gce-bastion",
        "event-worker": "compute-event-worker",
    }
    active_compute_dir = archetype_dir_map.get(selected_archetype, f"compute-{selected_archetype}")

    # Invoked modules: the exact local module sources of every Terraform file outside infra/modules/ (a vendored
    # bundle's own `../../modules/<x>` calls included, as before), by parser
    invoked_modules = referenced_local_dirs(files, "modules", skip_prefixes=("infra/modules/",))
    invoked_modules.update(intent_modules)   # TI-3: exact catalog ids from the typed intent (no text scan)

    for path, content in canonical_files.items():
        rel = path.replace("infra/modules/", "", 1)
        # 1. Foundation is mandatory for all workloads
        if rel.startswith("workload-foundation/"):
            files[path] = content
            continue

        # If foundation-only, skip compute
        if selected_archetype in ("foundation-only", "none", "empty"):
            mod_name = rel.split("/")[0]
            if mod_name in invoked_modules:
                files[path] = content
            continue

        # 2. Selected compute archetype is mandatory
        if active_compute_dir and rel.startswith(active_compute_dir + "/"):
            files[path] = content
            continue

        # 3. Supplemental modules: ONLY if explicitly invoked
        mod_name = rel.split("/")[0]
        if mod_name in invoked_modules:
            files[path] = content

    # 4. Check if any invoked modules are custom DIRECT_CODE modules from Firestore
    known_disk_mods = {p.replace("infra/modules/", "").split("/")[0] for p in canonical_files.keys()}
    custom_invoked = [m for m in invoked_modules if m not in known_disk_mods]
    if custom_invoked:
        try:
            from google.cloud import firestore
            client = firestore.Client()
            for c_mod in custom_invoked:
                doc = client.collection("custom_modules").document(c_mod).get()
                if doc.exists:
                    c_data = doc.to_dict() or {}
                    hcl_files = c_data.get("hcl_files", {})
                    for fname, fcontent in hcl_files.items():
                        files[f"infra/modules/{c_mod}/{fname}"] = fcontent
        except Exception as e:
            logger.debug(f"Could not load custom module files for vendoring: {e}")

    # 5. Verification audit: ensure every invoked module has its files populated
    for mod_name in invoked_modules:
        has_file = any(p.startswith(f"infra/modules/{mod_name}/") for p in files.keys())
        if not has_file:
            # Attempt to pull from canonical_files directly
            for path, content in canonical_files.items():
                if path.startswith(f"infra/modules/{mod_name}/"):
                    files[path] = content
                    has_file = True
            if has_file:
                logger.info(f"Auto-vendored missing invoked module '{mod_name}' from canonical catalog.")
            else:
                logger.warning(f"Invoked module '{mod_name}' could not be resolved from canonical catalog or Firestore.")




def detect_cloudrun_scaling_parameters(spec_text: str, default_min_instances: int = 0) -> Dict[str, any]:
    """
    Autonomously extracts Cloud Run scaling and CPU allocation preferences
    from natural language requirements or functional specifications across
    the quad-channel intake (Forms, Docs, Chat, Pub/Sub).

    FD-4CI-b: `default_min_instances` is the minimum when the spec states none (the platform's Enforce
    Scale-to-Zero setting: 0 when on, 1 when off). A stated minimum (including an explicit zero) always wins; the
    detection itself is unchanged. 0 = today's result.
    """
    if not spec_text:
        return {"min_instances": default_min_instances, "max_instances": 10, "cpu_idle": True}

    text_lower = spec_text.lower()

    # 1. Min instances detection
    min_instances = default_min_instances
    if re.search(r"\b(scale to zero|min(?:imum)?\s*instances?\s*[:=]?\s*0)\b", text_lower):
        min_instances = 0
    else:
        # Check patterns like "minimum instances: 2", "min instances 3", "min_instances = 2", "minimum instance 1"
        m = re.search(r"\b(?:minimum|min)(?:_|\s*)instances?\s*[:=]?\s*(\d+)\b", text_lower)
        if m:
            min_instances = int(m.group(1))
        else:
            # Check patterns like "2 warm instances", "1 hot instance", "keep 2 warm"
            m_warm = re.search(r"\b(\d+)\s*(?:warm|hot|live)\s*instances?\b", text_lower)
            if m_warm:
                min_instances = int(m_warm.group(1))
            else:
                m_keep = re.search(r"\bkeep\s*(\d+)\s*(?:instances?\s*)?(?:warm|hot|live)\b", text_lower)
                if m_keep:
                    min_instances = int(m_keep.group(1))
                elif any(phrase in text_lower for phrase in [
                    "always live", "always hot", "keep hot", "keep warm", "hot instance",
                    "hot runtime", "always-on", "always on runtime"
                ]):
                    min_instances = 1

    # 2. Max instances detection
    max_instances = 10
    m_max = re.search(r"\b(?:maximum|max)(?:_|\s*)(?:instances?\s*[:=]?\s*(\d+)|(?:of\s+)?(\d+)\s*instances?)\b", text_lower)
    if m_max:
        max_instances = int(m_max.group(1) or m_max.group(2))

    # 3. CPU idle / throttling detection
    cpu_idle = True
    always_cpu_indicators = [
        "always allocated cpu",
        "cpu always allocated",
        "always-allocated cpu",
        "cpu always-allocated",
        "no cpu throttling",
        "disable cpu throttling",
        "cpu throttling: false",
        "cpu-throttling: false",
        "cpu_throttling = false",
        "cpu_throttling: false",
        "cpu_idle = false",
        "cpu_idle: false",
        "unthrottled cpu",
        "continuous cpu",
    ]
    if any(indicator in text_lower for indicator in always_cpu_indicators):
        cpu_idle = False

    return {
        "min_instances": min_instances,
        "max_instances": max_instances,
        "cpu_idle": cpu_idle,
    }


extract_scaling_from_spec = detect_cloudrun_scaling_parameters


def extract_custom_resource_env_vars(
    custom_tf_content: Optional[str] = None,
    app_files: Optional[Dict[str, str]] = None,
    caller_service: Optional[str] = None,
    caller_module: Optional[str] = None,
    main_tf: Optional[str] = None,
    include_siblings: bool = True,
) -> Dict[str, str]:
    """
    Extracts custom resource and compute module references from custom.tf to deterministically
    wire into the Cloud Run compute container's environment variables.

    LANE 10 SEAM (FD-51; developer_agent/topology_wiring.py): `include_siblings=False` (the typed-topology path)
    skips the sibling section entirely: `plan_sibling_wiring` is not called (an empty plan instead), so no sibling
    binding is added and sibling targets do not trigger the universal project ids; inter-service URLs then come only
    from topology edges. The default keeps S2-D's behavior (lane 10 deletes the section with HB-05).

    RED TEAM GUARDS:
    1. Binds safe upstream resources (buckets, pubsub topics, secrets, redis, firestore).
    2. Sibling compute-cloudrun modules (Step 2 S2-D, HS-65; sibling_wiring.plan_sibling_wiring): a sibling's
       service_uri is bound only under <TOKEN>_URL/_URI/_ENDPOINT/_AUDIENCE keys that the caller's OWN code reads
       exactly (os.environ / os.getenv / BaseSettings fields). Siblings are found by the exact module `source`; there is
       no all-files fallback, no shared-noun or generic-alias guess. Mutual reads (A->B->A) are not bound: the
       validator reports them (IAC.SIBLING_URI_CYCLE) so the AI repairs them (AGENTS invariant 6).
    3. Strictly excludes self-referential cycles: caller_service never receives its own service_uri.
    4. Strictly excludes downstream consumers (e.g. google_pubsub_subscription, triggers)
       to avoid circular dependencies with module.compute.service_uri.
    5. Scans Python code in app_files with compiler AST to discover environment variable keys (non-sibling sections:
       unchanged file selection and collector).
    `caller_module` is the caller's module label ("compute" for main.tf's primary), when known; `main_tf` (when known)
    lets the cycle check see env references written in HCL that point at module.compute (code RT F1).
    """
    env_vars: Dict[str, str] = {}
    if not custom_tf_content:
        return env_vars

    blocks = extract_hcl_blocks(custom_tf_content)
    custom_buckets = []
    custom_topics = []
    custom_secrets = []
    custom_redis = []
    custom_databases = []

    for b in blocks:
        b_type = b.get("block_type")
        t_lbl = b.get("type_label", "")
        n_lbl = b.get("name_label", "")
        raw = b.get("raw_text", "")
        if not n_lbl:
            continue

        if b_type == "resource":
            if t_lbl == "google_storage_bucket":
                custom_buckets.append(n_lbl)
            elif t_lbl == "google_pubsub_topic":
                custom_topics.append(n_lbl)
            elif t_lbl == "google_secret_manager_secret":
                custom_secrets.append(n_lbl)
            elif t_lbl == "google_redis_instance":
                custom_redis.append(n_lbl)
            elif t_lbl == "google_firestore_database":
                if n_lbl not in ("database", "default"):
                    custom_databases.append(n_lbl)

    # S2-D: sibling discovery (exact module source), self-exclusion, exact env-read binding and the cycle check.
    # Lane 10 seam (F4 rule 1): no sibling discovery on the topology path (no plan: no bindings, no targets).
    sibling_bindings, sibling_targets = {}, []
    if include_siblings:
        sibling_plan = plan_sibling_wiring(custom_tf_content, app_files, caller_service, caller_module=caller_module,
                                           main_tf=main_tf)
        sibling_bindings, sibling_targets = sibling_plan.bindings, sibling_plan.targets

    # Inspect Python files to discover exact environment variable keys requested in backend code (non-sibling
    # sections 1-5 only). Their file selection is unchanged by S2-D: the primary module's callers passed no
    # caller_service before S2-D, so for them the selection still starts from "no caller".
    legacy_caller = None if caller_module in ("compute", "app") else caller_service
    app_code_text = ""
    app_env_keys = set()
    if app_files:
        relevant_files = []
        if legacy_caller:
            clean_cs = legacy_caller.replace("_", "-").lower()
            relevant_files = [
                (p, content) for p, content in app_files.items()
                if p.endswith(".py") and f"apps/{clean_cs}/" in p.replace("_", "-").lower()
            ]
        if not relevant_files:
            relevant_files = [
                (p, content) for p, content in app_files.items()
                if p.endswith(".py")
            ]

        app_code_text = "\n".join(c for _, c in relevant_files)

        for path, code in relevant_files:
            try:
                tree = ast.parse(code)
                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        if (isinstance(node.func, ast.Attribute) and 
                            node.func.attr in ('getenv', 'get') and 
                            node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                            app_env_keys.add(node.args[0].value)
                    elif isinstance(node, ast.Subscript):
                        if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                            app_env_keys.add(node.slice.value)
            except Exception:
                pass

    # 1. Wire Cloud Storage Buckets
    if custom_buckets:
        primary_bucket = custom_buckets[0]
        ref = f"google_storage_bucket.{primary_bucket}.name"
        # Canonical contracts
        env_vars["GCS_BUCKET_NAME"] = ref
        # Check app code for common variants
        if "RAW_EVENTS_BUCKET" in app_code_text or "RAW_EVENTS_BUCKET" in app_env_keys:
            env_vars["RAW_EVENTS_BUCKET"] = ref
        if "BUCKET_NAME" in app_code_text or "BUCKET_NAME" in app_env_keys:
            env_vars["BUCKET_NAME"] = ref
        if "STORAGE_BUCKET" in app_code_text or "STORAGE_BUCKET" in app_env_keys:
            env_vars["STORAGE_BUCKET"] = ref
        if "AUDIT_BUCKET" in app_code_text or "audit" in primary_bucket.lower():
            env_vars["AUDIT_BUCKET_NAME"] = ref

    # 2. Wire Pub/Sub Topics
    if custom_topics:
        # Prioritize primary/inbound topic over dead-letter queue (DLQ)
        non_dlq_topics = [
            t for t in custom_topics
            if not any(dlq_sub in t.lower() for dlq_sub in ("dlq", "dead_letter", "dead-letter", "failed", "retry"))
        ]
        primary_topic = non_dlq_topics[0] if non_dlq_topics else custom_topics[0]
        ref = f"google_pubsub_topic.{primary_topic}.name"
        # Canonical contracts
        env_vars["PUBSUB_TOPIC_ID"] = ref
        if "TOPIC_NAME" in app_code_text or "TOPIC_NAME" in app_env_keys:
            env_vars["TOPIC_NAME"] = ref
        if "PUBSUB_TOPIC_NAME" in app_code_text or "PUBSUB_TOPIC_NAME" in app_env_keys:
            env_vars["PUBSUB_TOPIC_NAME"] = ref
        if "EVENTS_TOPIC" in app_code_text or "event" in primary_topic.lower():
            env_vars["EVENTS_TOPIC_ID"] = ref

        # If a dead-letter queue topic is also declared, wire it explicitly
        dlq_candidates = [
            t for t in custom_topics
            if any(dlq_sub in t.lower() for dlq_sub in ("dlq", "dead_letter", "dead-letter"))
        ]
        if dlq_candidates:
            dlq_ref = f"google_pubsub_topic.{dlq_candidates[0]}.name"
            env_vars["PUBSUB_DLQ_TOPIC_ID"] = dlq_ref
            if "DLQ_TOPIC_ID" in app_code_text or "DLQ_TOPIC_ID" in app_env_keys:
                env_vars["DLQ_TOPIC_ID"] = dlq_ref

    # 3. Wire Secret Manager Secrets
    for sec in custom_secrets:
        key = f"SECRET_{sec.upper().replace('-', '_')}"
        env_vars[key] = f"google_secret_manager_secret.{sec}.secret_id"

    # 4. Wire Redis Instances
    if custom_redis:
        primary_redis = custom_redis[0]
        env_vars["REDIS_HOST"] = f"google_redis_instance.{primary_redis}.host"
        env_vars["REDIS_PORT"] = f"tostring(google_redis_instance.{primary_redis}.port)"

    # 5. Wire Firestore Database if bespoke
    if custom_databases:
        env_vars["FIRESTORE_DATABASE"] = f"google_firestore_database.{custom_databases[0]}.name"

    # 6. Wire Inter-Service Compute URLs & Audiences: only the exact keys the caller's own code reads (S2-D, HS-65).
    #    Unbound siblings and withheld mutual reads are reported by validators V2f (IAC.SIBLING_URI_UNBOUND /
    #    IAC.SIBLING_URI_CYCLE), which re-derive them from the same plan.
    env_vars.update(sibling_bindings)

    # 7. Universal Project IDs if custom resources are present (a sibling compute module counts, as before S2-D)
    if env_vars or (include_siblings and sibling_targets):
        env_vars["GCP_PROJECT_ID"] = "var.project_id"
        env_vars["PROJECT_ID"] = "var.project_id"

    return env_vars


def infer_additional_apis_from_custom_tf(root_files: Any) -> List[str]:
    """
    The workload's terraform.tfvars `additional_apis` (enabled by the foundation's google_project_service.apis).

    S2-C (register HS-63/HS-30): computed by the exact type / golden-module-source table
    (shared/api_requirements.{json,py}), the same function the terraform server's batchEnable uses, over the
    root-module .tf/.tf.json files: AI files and platform renders, so main.tf's module calls count by their exact
    source. The 8-prefix `startswith` inference is deleted. Result = required APIs minus what the foundation's
    base_apis and project vending already enable. A type with no row is not guessed (V2g reports it).

    `root_files`: {path: text} of the root module; a single string is treated as one custom.tf (legacy callers).
    """
    if not root_files:
        return []
    files = {"infra/workload/custom.tf": root_files} if isinstance(root_files, str) else dict(root_files)
    from shared.api_requirements import additional_apis, required_apis  # no fallback: never enable APIs on a guess
    return additional_apis(required_apis({p: t for p, t in files.items() if p.endswith((".tf", ".tf.json"))}))


def vpc_connector_line(connector_ref: Optional[str]) -> str:
    """The compute-cloudrun `vpc_access_connector` input line for a connector reference from
    topology_wiring.topology_vpc_connector (`google_vpc_access_connector.<label>.id`); "" for None (byte-identical
    render). Anything that is not exactly that reference shape is refused (closed grammar for emitted HCL).
    FD-4BH: the typed-intent platform connector is the golden module call, so its reference
    (shared.iac_intent.PLATFORM_CONNECTOR_REF, `module.stackvend_connector.id`) is accepted too, by exact equality."""
    if connector_ref is None:
        return ""
    try:
        from shared.iac_intent import PLATFORM_CONNECTOR_REF
    except ImportError:  # pragma: no cover - the gateway image always carries shared/iac_intent.py
        PLATFORM_CONNECTOR_REF = None
    if PLATFORM_CONNECTOR_REF is not None and connector_ref == PLATFORM_CONNECTOR_REF:
        return f"  vpc_access_connector  = {connector_ref}\n"
    parts = connector_ref.split(".")
    if not (len(parts) == 3 and parts[0] == "google_vpc_access_connector" and parts[2] == "id"
            and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", parts[1])):
        raise ValueError(f"not a connector reference: {connector_ref!r}")
    return f"  vpc_access_connector  = {connector_ref}\n"


# PUSH-TO-PRIVATE (owner 10-27): the closed grammar of a push identity rendered into a compute-cloudrun module call:
# key = "fact.<fact>" or "google_service_account.<label>" (shared.iac_intent.push_identities), value = a dotted
# reference (the platform fact expression or google_service_account.<label>.email).
_PUSH_KEY_RE = re.compile(r"(fact\.[a-z][a-z0-9_]*|google_service_account\.[A-Za-z_][A-Za-z0-9_-]*)")
_PUSH_EXPR_RE = re.compile(r"[a-z][a-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_-]*)+")


def hcl_quoted(value: str) -> str:
    """RT14-08: `value` as a native-syntax HCL quoted string that evaluates to exactly `value`
    (shared.iac_intent.hcl_string_literal: quote, backslash, control characters and the `${` / `%{` template sequences
    escaped). Every value a platform renderer of this module writes between quotes goes through it, so no value can
    close the string and add HCL (tests/test_rt14_iac_render.py pins this structurally). A value with none of
    those characters renders byte-identically to the former '"' + value + '"'. No fallback: a missing encoder is a
    deployment defect and must crash, never render unescaped. RT14-F4: the guard reads f-string interpolations and
    json.dumps calls (lists go through hcl_quoted_list); a value joined by `+` or `.format` is not checked by it."""
    from shared.iac_intent import hcl_string_literal
    if not isinstance(value, str):
        raise TypeError(f"hcl_quoted takes a string, not {type(value).__name__}")
    return hcl_string_literal(value)


def hcl_quoted_list(values: Iterable[str]) -> str:
    """RT14-F4: an HCL tuple of hcl_quoted strings, `["a", "b"]`. For ASCII values without `${` / `%{` it is
    byte-identical to the former json.dumps(list(values)) (same ", " separator, same escapes); a non-string item is
    refused (TypeError), never rendered."""
    return "[" + ", ".join(hcl_quoted(v) for v in values) + "]"


def wif_default_branch(branch: Any) -> Optional[str]:
    """FD-4CI-b-R1-WIF: the workload's branch for the workload-foundation WIF condition, or None for "main" (the
    module default: every render stays byte-identical). Any other value must be a plain branch name
    (shared.settings.is_branch_name, the grammar the module validates again); anything else is refused (ValueError),
    never rewritten. Callers pass handler.workflow_branch(<recorded default_branch>), the deploy workflows' branch."""
    if branch == "main":
        return None
    try:
        from shared.settings import is_branch_name
    except ImportError:  # pragma: no cover - the gateway image always carries shared/settings.py
        is_branch_name = None
    if is_branch_name is None or not is_branch_name(branch):
        raise ValueError(f"not a plain branch name for the WIF condition: {branch!r}")
    return branch


# GHA-DEPLOY-SWITCH (register row GHA-DEPLOY-SWITCH, owner 10-30): the workload's GitHub Actions deploy switch
# (workloads/{pid}.github_actions_deploy, missing = on). Off: the root forwards the root variable to the foundation
# (no WIF pool / provider / sa-gh-deployer) and declares it with default false; tf-applier writes the record's value
# into the root tfvars at every deploy (mcp-servers/terraform/service.py recorded_github_actions_deploy). On: the
# root renders byte-identically to before (no forward, no variable; the module default is on).
GHA_DEPLOY_SWITCH_VARIABLE = "enable_github_actions_deploy"
GHA_DEPLOY_SWITCH_LINE = "  enable_github_actions_deploy = var.enable_github_actions_deploy\n"
GHA_DEPLOY_SWITCH_VARIABLE_BLOCK = """
variable "enable_github_actions_deploy" {
  description = "The workload's GitHub Actions deploy switch (GHA-DEPLOY-SWITCH): false = no WIF pool, provider or deployer service account. Supplied by the platform at apply time."
  type        = bool
  default     = false
}
"""


def _gha_deploy_on(github_actions_deploy: Any) -> bool:
    """True (switch on) or False (off); anything that is not a bool is refused (ValueError), never coerced."""
    if not isinstance(github_actions_deploy, bool):
        raise ValueError(f"github_actions_deploy must be a bool: {github_actions_deploy!r}")
    return github_actions_deploy


def gha_deploy_switch_line(github_actions_deploy: Any = True) -> str:
    """GHA-DEPLOY-SWITCH: the foundation module argument for a switched-off workload; "" when on (byte-identical)."""
    return "" if _gha_deploy_on(github_actions_deploy) else GHA_DEPLOY_SWITCH_LINE


def gha_deploy_switch_variable_block(github_actions_deploy: Any = True) -> str:
    """GHA-DEPLOY-SWITCH: the root variable declaration for a switched-off workload; "" when on (byte-identical)."""
    return "" if _gha_deploy_on(github_actions_deploy) else GHA_DEPLOY_SWITCH_VARIABLE_BLOCK


# IAP-GATE-KNOWN-MEMBER: the compute-cloudrun module grants the workload project's IAP service agent roles/run.invoker,
# and that member contains the project number. A data source inside the module is read only at apply on a first deploy
# (every module call has depends_on = [module.foundation], and the foundation has changes pending then), so the member
# was unknown in the plan and the compliance gate correctly refused it. This data source sits in the root module, where
# it has no depends_on, so OpenTofu reads it at plan time (the same read workload-foundation already does at plan for
# the deployer's Cloud Build grant); project_number passes the value to the module. Direct IAP only: every other render
# stays byte-identical. Same project, same number: a workload already deployed keeps the same member string.
IAP_PROJECT_DATA_ADDRESS = "data.google_project.stackvend_iap_project"
IAP_PROJECT_DATA_BLOCK = """
# IAP-GATE-KNOWN-MEMBER: read at plan time (no depends_on), so the IAP agent's invoker member is a known value in the
# plan the compliance gate checks.
data "google_project" "stackvend_iap_project" {
  project_id = var.project_id
}
"""


# RT14-F1 (RT14-35 hardening, the IAP-GATE-KNOWN-MEMBER rule): the gce-bastion VM's zone. The module's own
# google_compute_zones read sits inside a module call with depends_on = [module.foundation], so OpenTofu defers it to
# apply whenever the foundation has a pending change; `zone` forces replacement of the VM, and the regulated plan gate
# cannot resolve an unknown location. This root data source has no depends_on, so it is read at plan (Compute API is
# enabled at vending) and the zone is always known. Same rule as the module fallback and the typed zone fact
# (shared/iac_intent.py ZONE_FACT_EXPR): first zone of var.region in sorted order, no status filter. Its own name, so
# it never collides with the typed intent's stackvend_intent_zones. gce-bastion only: every other render is unchanged.
BASTION_ZONES_DATA_ADDRESS = "data.google_compute_zones.stackvend_bastion_zones"
BASTION_ZONE_LINE = f"  zone       = element(sort({BASTION_ZONES_DATA_ADDRESS}.names), 0)\n"
BASTION_ZONES_DATA_BLOCK = """
# RT14-F1: read at plan time (no depends_on), so the bastion VM's zone is a known value in every plan.
data "google_compute_zones" "stackvend_bastion_zones" {
  project = var.project_id
  region  = var.region
}
"""


def _direct_iap_on(allow_unauthenticated: Any, enable_direct_iap: Any) -> bool:
    """The module's own condition for the IAP agent's invoker grant (!allow_unauthenticated && enable_direct_iap)."""
    return not allow_unauthenticated and bool(enable_direct_iap)


def iap_project_number_line(allow_unauthenticated: Any, enable_direct_iap: Any) -> str:
    """IAP-GATE-KNOWN-MEMBER: the compute-cloudrun `project_number` input of a Direct IAP service ("" otherwise)."""
    if not _direct_iap_on(allow_unauthenticated, enable_direct_iap):
        return ""
    return f"  project_number        = {IAP_PROJECT_DATA_ADDRESS}.number\n"


def iap_project_data_block(allow_unauthenticated: Any, enable_direct_iap: Any, has_cloud_run_module: bool) -> str:
    """IAP-GATE-KNOWN-MEMBER: the root data source behind iap_project_number_line ("" without a Direct IAP Cloud Run
    module in this root)."""
    return IAP_PROJECT_DATA_BLOCK if has_cloud_run_module and _direct_iap_on(allow_unauthenticated, enable_direct_iap) else ""


def push_service_accounts_line(identities: Optional[Mapping[str, str]]) -> str:
    """The compute-cloudrun `push_service_accounts` input for the push identities of one service
    (iac_intent_contract.IntentAssembly.push_identities[<module address>]); "" for None / {} (byte-identical render).
    Anything outside the closed key / reference grammar is refused."""
    if not identities:
        return ""
    rows = []
    for key, expr in sorted(identities.items()):
        if not (isinstance(key, str) and _PUSH_KEY_RE.fullmatch(key) and isinstance(expr, str)
                and _PUSH_EXPR_RE.fullmatch(expr)):
            raise ValueError(f"not a push identity: {key!r} = {expr!r}")
        rows.append(f"    {hcl_quoted(key)} = {expr}\n")   # RT14-F4
    return "  push_service_accounts = {\n" + "".join(rows) + "  }\n"


# APP-ADMIN-IAP-CONTRACT (owner 11-16): a Direct IAP Cloud Run workload's root declares `variable "app_admin_emails"`
# (its default: shared.access_policy.effective_app_admin_emails of the access record, resolved by the developer) and
# every compute-cloudrun module call the platform renders sets STACKVEND_APP_ADMIN_EMAILS from it. The renderers take
# the list as `app_admin_emails`; None (every other workload) = today's output, byte for byte.
APP_ADMIN_EMAILS_VARIABLE = "app_admin_emails"
APP_ADMIN_EMAILS_ENV = "STACKVEND_APP_ADMIN_EMAILS"
APP_ADMIN_EMAILS_ENV_EXPR = f"jsonencode(var.{APP_ADMIN_EMAILS_VARIABLE})"


class AppAdminEnvCollision(ValueError):
    """A compute-cloudrun module's env bindings already use the platform-owned STACKVEND_APP_ADMIN_EMAILS key
    (APP-ADMIN-IAP-CONTRACT). The developer handler reports it typed (PlatformDefectError APP_ADMIN_ENV_COLLISION)."""


def with_app_admin_env(env: Dict[str, str], app_admin_emails: Optional[Iterable[str]]) -> Dict[str, str]:
    """`env` (a compute-cloudrun module's {key: HCL expression} bindings) plus the platform's admin env when
    `app_admin_emails` is not None; None returns `env` itself (unchanged). The key is platform-owned: a binding that
    already uses it is refused (AppAdminEnvCollision), never overwritten or dropped."""
    if app_admin_emails is None:
        return env
    if APP_ADMIN_EMAILS_ENV in env:
        raise AppAdminEnvCollision(f"{APP_ADMIN_EMAILS_ENV} is platform-set (APP-ADMIN-IAP-CONTRACT); a binding "
                                   "already uses it")
    return dict(env, **{APP_ADMIN_EMAILS_ENV: APP_ADMIN_EMAILS_ENV_EXPR})


def app_admin_variable_block(app_admin_emails: Optional[Iterable[str]]) -> str:
    """The root `variable "app_admin_emails"` block for variables.tf ("" for None). Its default is the exact list, each
    address validated as an email (shared.access_policy.validate_email, lower-cased, no duplicates) and rendered through
    hcl_quoted_list; anything else is refused (ValueError), never rendered."""
    if app_admin_emails is None:
        return ""
    from shared.access_policy import validate_email
    emails = list(app_admin_emails)
    if any(not isinstance(e, str) or validate_email(e) != e for e in emails) or len(set(emails)) != len(emails):
        raise ValueError("app_admin_emails must be distinct lower-case email addresses")
    description = ("App administrators of this Direct IAP workload, from its access settings (APP-ADMIN-IAP-CONTRACT). "
                   f"The platform sets them on every Cloud Run service as {APP_ADMIN_EMAILS_ENV} (a JSON list).")
    return f"""
variable {hcl_quoted(APP_ADMIN_EMAILS_VARIABLE)} {{
  description = {hcl_quoted(description)}
  type        = list(string)
  default     = {hcl_quoted_list(emails)}
}}
"""


def format_hcl_env_vars(env_dict: Dict[str, str]) -> str:
    """Formats a dictionary into an HCL merge(var.env_vars, { ... }) expression."""
    if not env_dict:
        return "var.env_vars"
    lines = ["merge(var.env_vars, {"]
    for k, v in sorted(env_dict.items()):
        lines.append(f'    {hcl_quoted(k)} = {v}')   # RT14-08: the key is a quoted HCL string
    lines.append("  })")
    return "\n".join(lines)


# FD-4AL: the region a workload is vended and applied in. There is no per-workload region on the workload record
# today, so it is the platform setting `orchestration.default_gcp_region` -- the same source the terraform server's
# runtime tfvars `region` uses (mcp-servers/terraform/service.py resolve_platform_region). The developer resolves it
# ONCE per dispatch (resolve_workload_region, DeveloperAgent.generate_code_files) and passes it to every renderer.
# WORKLOAD_REGION_DEFAULT is that setting's SCHEMA default (shared.settings.OrchestrationSettings, the documented value
# when the settings document has none), read from the schema rather than restated: it is only the default of the
# renderers' `region` parameter for direct callers (eval harness, unit tests). "" when shared.settings is not
# importable; a renderer then raises RegionUnavailable instead of rendering a region.


class RegionUnavailable(RuntimeError):
    """No platform region is configured (settings `orchestration.default_gcp_region`, $REGION, $DEFAULT_REGION)."""


def _settings_module() -> Any:
    try:
        from shared import settings as settings_mod
    except ImportError:
        try:
            from ..shared import settings as settings_mod   # type: ignore[no-redef]
        except (ImportError, ValueError):
            return None
    return settings_mod


def _schema_default_region() -> str:
    mod = _settings_module()
    return str(getattr(mod.OrchestrationSettings(), "default_gcp_region", "") or "") if mod is not None else ""


WORKLOAD_REGION_DEFAULT = _schema_default_region()


def _settings_region(db: Any) -> tuple:
    """(`orchestration.default_gcp_region` of system_config/platform_settings read through the caller's Firestore
    client `db`, consulted, cause). Same contract as mcp-servers/terraform/service.py `_settings_region`
    (FD-4AL RT F1: no client with a configured project is a failed store; only a process with no project at all --
    the eval harness child -- or a non-snapshot object has no settings store)."""
    mod = _settings_module()
    if mod is None:
        return "", False, ""
    if db is None:
        if os.getenv("PROJECT_ID") or os.getenv("GOOGLE_CLOUD_PROJECT"):
            return "", True, "no settings Firestore client although a project is configured"
        return "", False, ""
    try:
        snap = db.collection("system_config").document("platform_settings").get()
        exists = getattr(snap, "exists", None)
        if exists is False:
            return WORKLOAD_REGION_DEFAULT, True, ""
        data = snap.to_dict() if exists is True else None
        if not isinstance(data, dict):
            return "", False, ""
        orch = data.get("orchestration")
        region = mod.OrchestrationSettings(**(orch if isinstance(orch, dict) else {})).default_gcp_region
    except Exception as settings_err:  # noqa: BLE001 - unreadable = no setting ($REGION / $DEFAULT_REGION next)
        cause = f"settings document unreadable/invalid: {type(settings_err).__name__}: {settings_err}"
        logger.warning(f"Could not read the platform region setting: {cause}")
        return "", True, cause
    if not isinstance(region, str) or not region:
        return "", True, "settings default_gcp_region is blank"
    return region, True, ""


class RegionNotApproved(RuntimeError):
    """FD-7M-a: the workload's recorded region (workloads/{product_id}.region) is not in the install's approved
    deployable regions (shared.settings.workload_region). Developer error_class REGION_NOT_APPROVED (the terraform
    server's class of the same name); never answered with another region."""

    error_class = "REGION_NOT_APPROVED"

    def __init__(self, message: str, *, region: Any = None, approved: Iterable[str] = ()):
        self.region = region
        self.approved = list(approved)
        super().__init__(message)


def _workload_record_region(db: Any, product_id: str) -> Any:
    """FD-7M-a: workloads/{product_id}.region as stored, read with the caller's Firestore client. None when the record
    does not exist or has no region (a workload created before FD-7M-a: it follows the platform region, owner OQ-24),
    and when `db` gives a non-snapshot answer (no settings store, as `_settings_region`). A failed read ->
    RegionUnavailable (the workload's region is unknown; never the platform default instead)."""
    try:
        snap = db.collection("workloads").document(product_id).get()
    except Exception as read_err:  # noqa: BLE001 - unreadable record = unknown region (typed)
        raise RegionUnavailable(f"workload record workloads/{product_id} unreadable: "
                                f"{type(read_err).__name__}: {read_err}") from read_err
    if getattr(snap, "exists", None) is not True:
        return None
    data = snap.to_dict()
    if not isinstance(data, dict):
        raise RegionUnavailable(f"workload record workloads/{product_id} unreadable: not a document")
    return data.get("region")


def _approval_orchestration(db: Any) -> Dict[str, Any]:
    """FD-7M-a: the stored `orchestration` mapping of system_config/platform_settings (the approved deployable regions
    live there), read with the caller's client. No document = {} (the schema defaults: [default_gcp_region]). A read
    error, a non-snapshot answer or a non-mapping value -> RegionUnavailable (approval cannot be checked)."""
    try:
        snap = db.collection("system_config").document("platform_settings").get()
        exists = getattr(snap, "exists", None)
        if exists is False:
            return {}
        data = snap.to_dict() if exists is True else None
    except Exception as read_err:  # noqa: BLE001 - unreadable settings = approval unknown (typed)
        raise RegionUnavailable(f"settings document unreadable/invalid: {type(read_err).__name__}: {read_err}") \
            from read_err
    if not isinstance(data, dict):
        raise RegionUnavailable("settings document unreadable/invalid: no settings answer for the approved regions")
    orch = data.get("orchestration")
    if orch is None:
        return {}
    if not isinstance(orch, dict):
        raise RegionUnavailable("settings document unreadable/invalid: orchestration is not a mapping")
    return orch


def resolve_workload_region(db: Any = None, product_id: Optional[str] = None, *, stage: str = "developer") -> str:
    """The region a workload is rendered / checked in.

    The configured platform region: Platform Settings `orchestration.default_gcp_region` read with the caller's
    Firestore client (`_settings_region`), then $REGION / $DEFAULT_REGION, then -- only when there is no settings
    store at all (no project configured and no client: the eval harness child) -- the schema default
    (WORKLOAD_REGION_DEFAULT). An unreadable/invalid settings document, a blank stored value, or a missing client on a
    configured install, with no env -> RegionUnavailable (developer error_class REGION_UNAVAILABLE) naming the cause.

    FD-7M-a: with a `product_id` (and a client), the workload's recorded region wins, through the one settings helper
    `shared.settings.workload_region`: no recorded region -> the platform region above (byte-identical to before);
    a recorded region in the approved list -> it; anything else -> RegionNotApproved (REGION_NOT_APPROVED). A record or
    settings read that fails while a region must be checked -> RegionUnavailable."""
    region, consulted, cause = _settings_region(db)
    region = region or os.getenv("REGION", "") or os.getenv("DEFAULT_REGION", "")
    if not region and not consulted:
        region = WORKLOAD_REGION_DEFAULT
    if not region:
        raise RegionUnavailable(f"{cause or 'no platform region configured'} "
                                "(settings default_gcp_region; REGION and DEFAULT_REGION unset)")
    if not product_id:
        return region
    if db is None:
        # SAT-23 RT F1 (= the terraform server's _settings_orchestration): a configured install without a client
        # cannot read the recorded region; never the platform default instead. Only a process with no project at all
        # (the eval harness child) has no store and keeps the platform region.
        if os.getenv("PROJECT_ID") or os.getenv("GOOGLE_CLOUD_PROJECT"):
            raise RegionUnavailable(f"no Firestore client although a project is configured: the recorded region of "
                                    f"workloads/{product_id} cannot be read")
        return region
    record_region = _workload_record_region(db, product_id)
    if record_region is None:
        return region
    mod = _settings_module()
    if mod is None or not hasattr(mod, "workload_region"):
        raise RegionUnavailable("the settings contract (workload_region) is not importable")
    orchestration = dict(_approval_orchestration(db))
    if not orchestration.get("default_gcp_region"):
        # SAT-23 RT F2 (= the terraform server): a blank / missing stored default is FD-4AL's "no setting", so the
        # record path approves the same default region the legacy path renders in (the FD-4AL region above).
        orchestration["default_gcp_region"] = region
    try:
        resolved = mod.workload_region(record_region, orchestration, default_region=region, stage=stage)
    except mod.RegionNotApproved as not_approved:
        raise RegionNotApproved(str(not_approved), region=not_approved.region,
                                approved=not_approved.approved) from not_approved
    except (TypeError, ValueError) as invalid:   # an invalid stored orchestration (pydantic: ValueError)
        raise RegionUnavailable(f"settings document unreadable/invalid: {type(invalid).__name__}: {invalid}") \
            from invalid
    if not isinstance(resolved, str) or not resolved:
        raise RegionUnavailable("settings default_gcp_region is blank")
    return resolved


def _render_region(region: Optional[str]) -> str:
    """The region a renderer writes: the caller's, else the schema default (direct callers); never ""."""
    resolved = region or WORKLOAD_REGION_DEFAULT
    if not resolved:
        raise RegionUnavailable("no region passed and the settings schema is not importable")
    return resolved

# ------------------------------------------------------------------------------------------------------------------
# Lane 14 PR-0b: regulated-profile controls (developer_agent/compliance_profile.py decides WHEN; this renders WHAT).
# ------------------------------------------------------------------------------------------------------------------
CMEK_MODULE_LABEL = "cmek"
CMEK_KEY_REFERENCE = "module.cmek.crypto_key_name"   # security-kms output, known at plan time (see that module)
CMEK_KEY_NAME = "workload-cmek"                      # key ring "<project_id>-workload-cmek", key "workload-cmek"
CMEK_ROTATION_PERIOD = "7776000s"                    # 90 days
# Exact golden-module directory -> the Google APIs whose service agents encrypt with the key when the platform wires
# the key into that module (each needs roles/cloudkms.cryptoKeyEncrypterDecrypter before the resource is created).
CMEK_SERVICE_AGENTS: Dict[str, tuple] = {
    "base": ("artifactregistry.googleapis.com", "firestore.googleapis.com"),   # workload-foundation/base
    "compute-cloudrun": ("run.googleapis.com",),
    "compute-event-worker": ("pubsub.googleapis.com", "run.googleapis.com"),
    "compute-gke-autopilot": ("container.googleapis.com",),
}
_ARCHETYPE_MODULE_DIR = {"cloudrun": "compute-cloudrun", "gke-autopilot": "compute-gke-autopilot",
                         "gce-bastion": "compute-gce-bastion", "event-worker": "compute-event-worker"}


def _wants_cmek(regulated: Any) -> bool:
    return regulated is not None and bool(getattr(regulated, "cmek", False))


def cmek_service_agent_services(archetype: str, root_files: Optional[Dict[str, str]] = None) -> List[str]:
    """Sorted APIs whose agents need the key: the foundation, the primary archetype's module (unknown archetypes
    render compute-cloudrun, as generate_golden_main_tf does), and every module call in the root module's bespoke
    files (platform secondaries in custom.tf) by the exact directory of its literal local source (python-hcl2)."""
    from shared.api_requirements import module_dir

    dirs = {"base"}
    if archetype not in ("foundation-only", "none", "empty"):
        dirs.add(_ARCHETYPE_MODULE_DIR.get(archetype, "compute-cloudrun"))
    for path, text in sorted((root_files or {}).items()):
        if not (isinstance(text, str) and path.startswith("infra/workload/") and path.endswith(".tf")
                and "/" not in path[len("infra/workload/"):] and path != "infra/workload/main.tf"):
            continue
        for b in index_blocks(text) or []:
            if b.kind == "module":
                d = module_dir((b.body or {}).get("source"))
                if d in CMEK_SERVICE_AGENTS:
                    dirs.add(d)
    return sorted({api for d in dirs for api in CMEK_SERVICE_AGENTS.get(d, ())})


def render_cmek_module_block(regulated: Any, service_agent_services: List[str]) -> str:
    """`module "cmek"` (golden security-kms): one key per workload in the workload region, 90-day rotation, the
    service agents of `service_agent_services` granted cryptoKeyEncrypterDecrypter, the APIs enabled by the module."""
    services = hcl_quoted_list(service_agent_services)   # RT14-F4
    # Owner option Q3 (compliance_profile.HSM_PROFILES, empty by default): SOFTWARE renders no line (module default).
    level = getattr(regulated, "protection_level", "SOFTWARE")
    level_line = f"\n  protection_level       = {hcl_quoted(level)}" if level != "SOFTWARE" else ""   # RT14-F4
    return f"""
# ------------------------------------------------------------------------------
# Tier 0: Customer-Managed Encryption Key (compliance profile {regulated.profile}; lane 14 PR-0b)
# ------------------------------------------------------------------------------
module "{CMEK_MODULE_LABEL}" {{
  source                 = "../modules/security-kms"
  project_id             = var.project_id
  location               = var.region
  keyring_name           = "{CMEK_KEY_NAME}"
  key_name               = "{CMEK_KEY_NAME}"
  rotation_period        = "{CMEK_ROTATION_PERIOD}"{level_line}
  enable_apis            = true
  service_agent_services = {services}
}}
"""


def generate_golden_main_tf(
    product_id: str,
    archetype: str = "cloudrun",
    spec_text: str = "",
    allow_unauthenticated: bool = True,
    enable_direct_iap: bool = False,
    authorized_invoker_members: Optional[List[str]] = None,
    service_name: Optional[str] = None,
    custom_tf_content: Optional[str] = None,
    app_files: Optional[Dict[str, str]] = None,
    env_vars_override: Optional[Dict[str, str]] = None,
    scaling_override: Optional[Dict[str, Any]] = None,
    regulated: Optional[Any] = None,
    topology: Optional[Any] = None,
    network_facts: Optional[Any] = None,
    vpc_access_connector: Optional[str] = None,
    default_min_instances: int = 0,
    push_service_accounts: Optional[Mapping[str, str]] = None,
    github_default_branch: str = "main",
    github_actions_deploy: bool = True,
    cloud_run_secondaries: bool = False,
    app_admin_emails: Optional[Iterable[str]] = None,
) -> str:
    """
    Generates deterministic infra/workload/main.tf instantiating the vendored
    workload-foundation/base module and selected compute archetype submodule.
    Autonomously extracts scaling and CPU allocation parameters from spec_text.
    Auto-wires custom resource references from custom.tf into container env_vars.

    Lane 10 (FD-51): on the typed-topology path the caller passes `env_vars_override` (the primary's bindings from
    developer_agent/topology_wiring.topology_env_vars: no sibling discovery) and, when the architect stated it,
    `scaling_override` ({min_instances, max_instances, cpu_idle}). Both None = today's output, byte for byte.

    Lane 14 PR-0b: `regulated` (compliance_profile.RegulatedControls, None for STANDARD) adds `module "cmek"`, wires
    `module.cmek.crypto_key_name` into the foundation (Artifact Registry + Firestore) and the primary compute module,
    and turns on the foundation's Data Access audit config. None = today's output, byte for byte.

    gce-bastion-network: for a gce-bastion primary, `topology` (the ValidatedTopology) adds its resource bindings as
    instance metadata settings and its own-SA resource grants, and `network_facts` (platform_facts.NetworkFacts)
    holding the WORKLOAD_SUBNET fact gives it its own subnet with Private Google Access (or the workload's existing
    subnetwork, read from `app_files`). Both None = today's output, byte for byte. Other archetypes ignore them.

    platform-db-connector-wiring: `vpc_access_connector` (topology_wiring.topology_vpc_connector: the one connector on
    the network of a private resource the primary consumes by a typed edge, e.g. `google_vpc_access_connector.c.id`;
    FD-4DK, legacy path: topology_wiring.legacy_vpc_connector) sets the cloudrun primary's `vpc_access_connector`
    input. None = today's output, byte for byte.

    FD-4CI-b: `default_min_instances` is the primary Cloud Run service's min_instances when neither the architect's
    scaling nor the spec states a minimum (Enforce Scale-to-Zero: 0 on, 1 off). 0 = today's output, byte for byte.

    PUSH-TO-PRIVATE: `push_service_accounts` (the typed intent's push identities of module.compute,
    shared.iac_intent.push_identities) sets the cloudrun primary's `push_service_accounts` input
    (push_service_accounts_line). None / {} = today's output, byte for byte.

    FD-4CI-b-R1-WIF: `github_default_branch` (the deploy workflows' branch) other than "main" forwards
    `var.github_default_branch` to the foundation's WIF condition (wif_default_branch: plain branch names only).
    "main" = today's output, byte for byte.

    GHA-DEPLOY-SWITCH: `github_actions_deploy` False (the workload's switch is off) forwards
    `var.enable_github_actions_deploy` to the foundation (GHA_DEPLOY_SWITCH_LINE: no WIF pool / provider / deployer).
    True = today's output, byte for byte.

    IAP-GATE-KNOWN-MEMBER: for a Direct IAP cloudrun primary, or a root that also holds Cloud Run secondaries
    (`cloud_run_secondaries`, what reconcile_multi_service_declarations rendered), the root reads the project number
    at plan time and passes it to the compute-cloudrun modules. Not Direct IAP = today's output, byte for byte.

    RT14-F1: a gce-bastion primary gets a root google_compute_zones read (BASTION_ZONES_DATA_BLOCK, no depends_on)
    and its `zone` input from it, so the VM's zone is known at plan. Other archetypes = today's output, byte for byte.

    APP-ADMIN-IAP-CONTRACT: `app_admin_emails` not None (a Direct IAP Cloud Run workload; the list itself is declared by
    generate_golden_variables_tf) adds `STACKVEND_APP_ADMIN_EMAILS = jsonencode(var.app_admin_emails)` to the
    `env_vars` of the compute-cloudrun primary (the cloudrun archetype and the default fallback alike). None = today's
    output, byte for byte.
    """
    clean_pid = product_id.lower().replace("_", "-")
    iap_line = iap_project_number_line(allow_unauthenticated, enable_direct_iap)
    iap_data_block = iap_project_data_block(allow_unauthenticated, enable_direct_iap,
                                            archetype == "cloudrun" or cloud_run_secondaries)
    bastion_zone_block = BASTION_ZONES_DATA_BLOCK if archetype == "gce-bastion" else ""   # RT14-F1
    branch_line = ("  github_default_branch = var.github_default_branch\n"
                   if wif_default_branch(github_default_branch) is not None else "")
    branch_line += gha_deploy_switch_line(github_actions_deploy)
    cmek = _wants_cmek(regulated)
    cmek_line = f"  encryption_key        = {CMEK_KEY_REFERENCE}\n" if cmek else ""
    connector_line = vpc_connector_line(vpc_access_connector)
    push_line = push_service_accounts_line(push_service_accounts)
    resolved_svc_name = hcl_quoted(service_name) if service_name else "var.product_id"
    clean_s_name = service_name.replace("_", "-") if service_name else ""
    if clean_s_name and clean_s_name not in (clean_pid, f"castor-{clean_pid}", "compute", "app"):
        image_expr = f'replace(var.container_image, "/app:", {hcl_quoted("/" + clean_s_name + ":")})'
    else:
        image_expr = "var.container_image"

    # S2-D: the primary module's own service is the caller (None -> resolved from the service inventory, or unbound).
    # Lane 10: the typed-topology path passes the primary's edge bindings instead (no sibling discovery).
    custom_env = (dict(env_vars_override) if env_vars_override is not None
                  else extract_custom_resource_env_vars(custom_tf_content, app_files, caller_service=service_name or None,
                                                        caller_module="compute"))
    env_vars_expr = format_hcl_env_vars(custom_env)

    compute_block = ""
    if archetype == "cloudrun":
        scaling = (dict(scaling_override) if scaling_override
                   else detect_cloudrun_scaling_parameters(spec_text, default_min_instances=default_min_instances))
        min_inst = scaling["min_instances"]
        max_inst = scaling["max_instances"]
        cpu_idle_val = "true" if scaling["cpu_idle"] else "false"
        cloudrun_env_expr = format_hcl_env_vars(with_app_admin_env(custom_env, app_admin_emails))   # APP-ADMIN

        compute_block = f"""module "compute" {{
  source                = "../modules/compute-cloudrun"
  project_id            = var.project_id
  region                = var.region
  product_id            = var.product_id
  service_name          = {resolved_svc_name}
  service_account_email = module.foundation.workload_sa_email
  container_image       = {image_expr}
  oauth_client_id       = var.oauth_client_id
  firebase_api_key      = var.firebase_api_key
  firebase_auth_domain  = var.firebase_auth_domain
  min_instances         = {min_inst}
  max_instances         = {max_inst}
  cpu_idle              = {cpu_idle_val}
  allow_unauthenticated = var.allow_unauthenticated
  enable_direct_iap     = var.enable_direct_iap
  authorized_invoker_members = var.authorized_invoker_members
{iap_line}{push_line}  cpu_limit             = var.cpu_limit
  memory_limit          = var.memory_limit
{connector_line}  env_vars              = {cloudrun_env_expr}
{cmek_line}
  depends_on = [module.foundation]
}}"""
    elif archetype == "gce-bastion":
        # gce-bastion-startup: its `apps/<service>/startup.sh` as the VM startup script ("" without one: unchanged).
        # gce-bastion-network: its subnet (existing, or own on the IPAM fact) + topology settings and grants.
        subnet_fact = network_facts is not None and getattr(network_facts, "subnet_cidr", None) is not None
        bastion_code = render_gce_bastion_code_lines(service_name, app_files, topology=topology,
                                                     subnet_fact=subnet_fact)
        compute_block = f"""module "compute" {{
  source     = "../modules/compute-gce-bastion"
  project_id = var.project_id
  region     = var.region
{BASTION_ZONE_LINE}  product_id = var.product_id
{bastion_code}
  depends_on = [module.foundation]
}}"""
    elif archetype == "gke-autopilot":
        custom_net = ""
        custom_sub = ""
        if custom_tf_content:
            net_match = re.search(r'resource\s+"google_compute_network"\s+"([^"]+)"', custom_tf_content)
            if net_match:
                custom_net = f"google_compute_network.{net_match.group(1)}.name"
            sub_match = re.search(r'resource\s+"google_compute_subnetwork"\s+"([^"]+)"', custom_tf_content)
            if sub_match:
                custom_sub = f"google_compute_subnetwork.{sub_match.group(1)}.name"

        net_attr = f"\n  network    = {custom_net}" if custom_net else "\n  network    = var.network"
        sub_attr = f"\n  subnetwork = {custom_sub}" if custom_sub else "\n  subnetwork = var.subnetwork"

        gke_cmek_attr = f"\n  database_encryption_key = {CMEK_KEY_REFERENCE}" if cmek else ""
        compute_block = f"""module "compute" {{
  source     = "../modules/compute-gke-autopilot"
  project_id = var.project_id
  region     = var.region
  product_id = var.product_id{net_attr}{sub_attr}{gke_cmek_attr}

  depends_on = [module.foundation]
}}"""
    elif archetype == "event-worker":
        worker_cmek_line = f"  kms_key_name          = {CMEK_KEY_REFERENCE}\n" if cmek else ""
        compute_block = f"""module "compute" {{
  source                = "../modules/compute-event-worker"
  project_id            = var.project_id
  region                = var.region
  product_id            = var.product_id
  service_account_email = module.foundation.workload_sa_email
  container_image       = var.container_image
{worker_cmek_line}
  depends_on = [module.foundation]
}}"""
    elif archetype in ("foundation-only", "none", "empty"):
        compute_block = ""
    else:
        # Default fallback to cloudrun
        scaling = detect_cloudrun_scaling_parameters(spec_text, default_min_instances=default_min_instances)
        min_inst = scaling["min_instances"]
        max_inst = scaling["max_instances"]
        cpu_idle_val = "true" if scaling["cpu_idle"] else "false"

        compute_block = f"""module "compute" {{
  source                = "../modules/compute-cloudrun"
  project_id            = var.project_id
  region                = var.region
  product_id            = var.product_id
  service_name          = {hcl_quoted("castor-" + clean_pid)}
  service_account_email = module.foundation.workload_sa_email
  container_image       = var.container_image
  oauth_client_id       = var.oauth_client_id
  firebase_api_key      = var.firebase_api_key
  firebase_auth_domain  = var.firebase_auth_domain
  min_instances         = {min_inst}
  max_instances         = {max_inst}
  cpu_idle              = {cpu_idle_val}
  allow_unauthenticated = var.allow_unauthenticated
  authorized_invoker_members = var.authorized_invoker_members
  cpu_limit             = var.cpu_limit
  memory_limit          = var.memory_limit
  env_vars              = {format_hcl_env_vars(with_app_admin_env(custom_env, app_admin_emails))}
{cmek_line}
  depends_on = [module.foundation]
}}"""

    # Lane 14 PR-0b: the key module and the foundation's regulated inputs ("" for STANDARD: byte-identical).
    cmek_section = (render_cmek_module_block(regulated, cmek_service_agent_services(archetype, app_files))
                    if cmek else "")
    foundation_regulated = ""
    if cmek:
        foundation_regulated += f"  kms_key_name          = {CMEK_KEY_REFERENCE}\n"
    if regulated is not None and bool(getattr(regulated, "audit_logging", False)):
        foundation_regulated += "  enable_data_access_audit_logs = true\n"
        # Owner option Q2 (compliance_profile.AUDIT_LOG_TYPES): the module default (DATA_READ, DATA_WRITE) renders no line.
        log_types = tuple(getattr(regulated, "audit_log_types", ()) or ())
        if log_types and log_types != ("DATA_READ", "DATA_WRITE"):
            foundation_regulated += f"  data_access_log_types = {hcl_quoted_list(log_types)}\n"   # RT14-F4

    k8s_provider_req = ""
    k8s_provider_block = ""
    if archetype == "gke-autopilot":
        k8s_provider_req = """    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.20.0"
    }
"""
        k8s_provider_block = """
# ------------------------------------------------------------------------------
# Kubernetes Provider Configuration (GKE Autopilot)
# ------------------------------------------------------------------------------
data "google_client_config" "default" {}

provider "kubernetes" {
  host                   = "https://${module.compute.cluster_endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(module.compute.cluster_ca_certificate)
}
"""

    compute_section = f"""
# ------------------------------------------------------------------------------
# Tier 2: Compute Archetype ({archetype})
# ------------------------------------------------------------------------------
{compute_block}
""" if compute_block else ""

    return f"""# ==============================================================================
# STACKVEND: WORKLOAD INFRASTRUCTURE (DETERMINISTIC GOLDEN FOUNDATION)
# ==============================================================================
# Instantiates canonical vendored foundation and compute modules.
# Any bespoke additions (Storage, Pub/Sub, Redis) are declared in custom.tf.
# ==============================================================================

terraform {{
  required_version = ">= 1.5.0"
  required_providers {{
    google = {{
      source  = "hashicorp/google"
      version = ">= 6.0.0, < 7.0.0"
    }}
    google-beta = {{
      source  = "hashicorp/google-beta"
      version = ">= 6.0.0, < 7.0.0"
    }}
{k8s_provider_req}  }}
}}

provider "google" {{
  project               = var.project_id
  region                = var.region
  user_project_override = true
  billing_project       = var.project_id
}}

provider "google-beta" {{
  project               = var.project_id
  region                = var.region
  user_project_override = true
  billing_project       = var.project_id
}}
{cmek_section}
# ------------------------------------------------------------------------------
# Tier 1: Canonical Base Foundation (APIs, WIF, IAM, Firestore, Registry)
# ------------------------------------------------------------------------------
module "foundation" {{
  source                = "../modules/workload-foundation/base"
  project_id            = var.project_id
  region                = var.region
  product_id            = var.product_id
  github_repo_full_name = var.github_repo_full_name
  github_repository_id  = var.github_repository_id
{branch_line}  additional_apis       = var.additional_apis
{foundation_regulated}}}
{iap_data_block}{bastion_zone_block}{compute_section}{k8s_provider_block}"""


# FD4BD-SENS (SAT-02): the platform secrets the deploy passes to OpenTofu only as TF_VAR_* environment variables
# (mcp-servers/terraform/service.py PLATFORM_SECRET_TFVARS, compliance_gate.PLATFORM_SECRET_VARIABLE_NAMES; parity
# pinned by tests/test_sat02_sensitive_platform_variables.py). generate_golden_variables_tf declares exactly these
# `sensitive = true`: plan/apply output masks them, and OpenTofu itself refuses a root output that exposes them
# ("Output refers to sensitive values", repair_loop.SENSITIVE_OUTPUT_CODE).
PLATFORM_SECRET_VARIABLES = ("oauth_client_secret", "firebase_api_key")


def generate_golden_variables_tf(
    product_id: str,
    default_repo: str = "",
    allow_unauthenticated: bool = True,
    enable_direct_iap: bool = False,
    authorized_invoker_members: Optional[List[str]] = None,
    region: Optional[str] = None,
    github_default_branch: str = "main",
    github_actions_deploy: bool = True,
    app_admin_emails: Optional[Iterable[str]] = None,
) -> str:
    """Generates deterministic infra/workload/variables.tf. `region` (FD-4AL): the `var.region` default, the workload
    region the developer resolved (None = the settings schema default, for direct callers).
    `github_default_branch` (FD-4CI-b-R1-WIF): other than "main", declares `github_default_branch` with that branch as
    its default (wif_default_branch: plain branch names only; tf-applier supplies the recorded value at apply time).
    "main" = today's output, byte for byte.
    `github_actions_deploy` (GHA-DEPLOY-SWITCH): False declares `enable_github_actions_deploy` (default false;
    tf-applier supplies the record's value at apply time). True = today's output, byte for byte.
    `app_admin_emails` (APP-ADMIN-IAP-CONTRACT): not None declares `variable "app_admin_emails"` with that exact list as
    its default (app_admin_variable_block), right after `authorized_invoker_members`. The default is the only value:
    no tfvars key is rendered and no deploy supplies one, so a root that does not declare it never receives it.
    None = today's output, byte for byte."""
    admin_block = app_admin_variable_block(app_admin_emails)
    wif_branch = wif_default_branch(github_default_branch)
    branch_block = ("" if wif_branch is None else f"""
variable "github_default_branch" {{
  description = "The workload's recorded default branch, the one branch the WIF condition accepts (FD-4CI-b-R1-WIF). Supplied by the platform at apply time."
  type        = string
  default     = {hcl_quoted(wif_branch)}
}}
""")
    branch_block += gha_deploy_switch_variable_block(github_actions_deploy)
    region_val = _render_region(region)
    clean_pid = product_id.lower().replace("_", "-")
    _, _, repo_val = resolve_repo_identity(default_repo, product_id=product_id)
    allow_unauth_str = "true" if allow_unauthenticated else "false"
    enable_iap_str = "true" if enable_direct_iap else "false"
    members_json = hcl_quoted_list(authorized_invoker_members or [])   # RT14-F4
    return f"""variable "project_id" {{
  description = "Target GCP Child Project ID"
  type        = string
}}

variable "region" {{
  description = "GCP Region"
  type        = string
  default     = {hcl_quoted(region_val)}
}}

variable "product_id" {{
  description = "Workload Product ID"
  type        = string
  default     = {hcl_quoted(clean_pid)}
}}

variable "github_repo_full_name" {{
  description = "Full GitHub repository name (owner/repo) for WIF authentication"
  type        = string
  default     = {hcl_quoted(repo_val)}
}}

variable "github_repository_id" {{
  description = "GitHub numeric repository id for the WIF condition (FD-4AT-c). Supplied by the platform at apply time; empty = not pinned."
  type        = string
  default     = ""
}}
{branch_block}
variable "container_image" {{
  description = "Container image URL"
  type        = string
  default     = ""
}}

variable "oauth_client_id" {{
  description = "Google OAuth 2.0 Web Client ID from host platform"
  type        = string
  default     = ""
}}

variable "oauth_client_secret" {{
  description = "Google OAuth 2.0 Client Secret from host platform"
  type        = string
  default     = ""
  sensitive   = true
}}

variable "firebase_api_key" {{
  description = "Firebase Browser API Key"
  type        = string
  default     = ""
  sensitive   = true
}}

variable "firebase_auth_domain" {{
  description = "Firebase Auth Domain"
  type        = string
  default     = ""
}}

variable "allow_unauthenticated" {{
  description = "Allow unauthenticated public access to the Cloud Run service"
  type        = bool
  default     = {allow_unauth_str}
}}

variable "enable_direct_iap" {{
  description = "Whether to enable native Direct Identity-Aware Proxy (IAP) on Cloud Run when allow_unauthenticated is false"
  type        = bool
  default     = {enable_iap_str}
}}

variable "authorized_invoker_members" {{
  description = "List of authorized IAM members when unauthenticated access is disabled"
  type        = list(string)
  default     = {members_json}
}}
{admin_block}
variable "additional_apis" {{
  description = "Extra GCP APIs requested by custom extensions"
  type        = list(string)
  default     = []
}}

variable "cpu_limit" {{
  description = "CPU limit for container"
  type        = string
  default     = "1000m"
}}

variable "memory_limit" {{
  description = "Memory limit for container"
  type        = string
  default     = "512Mi"
}}

variable "env_vars" {{
  description = "Custom environment variables to pass to the container"
  type        = map(string)
  default     = {{}}
}}

variable "service_name" {{
  description = "Workload primary service name"
  type        = string
  default     = {hcl_quoted(clean_pid)}
}}

variable "network" {{
  description = "VPC network name"
  type        = string
  default     = "default"
}}

variable "subnetwork" {{
  description = "VPC subnetwork name"
  type        = string
  default     = ""
}}

variable "labels" {{
  description = "Common labels to apply to all resources"
  type        = map(string)
  default     = {{}}
}}
"""


def generate_golden_outputs_tf(product_id: str, archetype: str = "cloudrun") -> str:
    """Generates deterministic infra/workload/outputs.tf."""
    compute_outputs = ""
    if archetype == "cloudrun":
        compute_outputs = """output "service_uri" {
  description = "HTTPS URI of the deployed Cloud Run service"
  value       = module.compute.service_uri
}

output "service_name" {
  description = "Name of the Cloud Run service"
  value       = module.compute.service_name
}
"""
    elif archetype == "gce-bastion":
        compute_outputs = """output "bastion_name" {
  description = "Compute Engine bastion instance name"
  value       = module.compute.instance_name
}

output "bastion_self_link" {
  description = "Compute Engine bastion URI"
  value       = module.compute.instance_self_link
}
"""
    elif archetype == "gke-autopilot":
        compute_outputs = """output "cluster_name" {
  description = "GKE Autopilot cluster name"
  value       = module.compute.cluster_name
}

output "cluster_endpoint" {
  description = "GKE Autopilot cluster control plane endpoint"
  value       = module.compute.cluster_endpoint
}
"""
    elif archetype == "event-worker":
        compute_outputs = """output "job_name" {
  description = "Cloud Run Job name"
  value       = module.compute.job_name
}

output "topic_name" {
  description = "Pub/Sub Topic name"
  value       = module.compute.topic_name
}
"""
    elif archetype in ("foundation-only", "none", "empty"):
        compute_outputs = ""

    return f"""# ==============================================================================
# STACKVEND: WORKLOAD OUTPUTS
# ==============================================================================

output "workload_sa_email" {{
  description = "Workload runtime service account email"
  value       = module.foundation.workload_sa_email
}}

output "deployer_sa_email" {{
  description = "CI/CD deployer service account email"
  value       = module.foundation.deployer_sa_email
}}

output "wif_provider_name" {{
  description = "Workload Identity Provider resource name"
  value       = module.foundation.wif_provider_name
}}

output "docker_repo_id" {{
  description = "Artifact Registry Docker repository ID"
  value       = module.foundation.docker_repo_id
}}

output "database_name" {{
  description = "Firestore database name"
  value       = module.foundation.database_name
}}

{compute_outputs}
"""


def generate_golden_moved_tf(product_id: str, archetype: str = "cloudrun") -> str:
    """
    Generates declarative moved.tf blocks to ensure zero-downtime, zero-destruction
    upgrades for brownfield workloads migrating from monolithic main.tf to modules.
    Terraform natively ignores moved {} blocks when provisioning greenfield workloads.
    """
    compute_moves = ""
    if archetype == "cloudrun":
        compute_moves = """moved {
  from = google_cloud_run_v2_service.app
  to   = module.compute.google_cloud_run_v2_service.app
}

moved {
  from = google_cloud_run_v2_service_iam_member.public_access
  to   = module.compute.google_cloud_run_v2_service_iam_member.public_access[0]
}
"""
    elif archetype in ("foundation-only", "none", "empty"):
        compute_moves = ""

    return f"""# ==============================================================================
# STACKVEND: DECLARATIVE STATE MIGRATION GUARDS
# ==============================================================================
# Ensures zero-destruction upgrades for existing production workloads.
# Terraform renames resource addresses in remote state without recreating live resources.
# For new workloads with an empty state file, Terraform silently ignores these blocks.
# ==============================================================================

moved {{
  from = google_firestore_database.database
  to   = module.foundation.google_firestore_database.database
}}

moved {{
  from = google_artifact_registry_repository.docker_repo
  to   = module.foundation.google_artifact_registry_repository.docker_repo
}}

moved {{
  from = google_service_account.workload_sa
  to   = module.foundation.google_service_account.workload_sa
}}

moved {{
  from = google_project_iam_member.workload_datastore_user
  to   = module.foundation.google_project_iam_member.workload_datastore_user
}}

moved {{
  from = google_project_iam_member.workload_log_writer
  to   = module.foundation.google_project_iam_member.workload_log_writer
}}

moved {{
  from = google_iam_workload_identity_pool.github_pool
  to   = module.foundation.google_iam_workload_identity_pool.github_pool
}}

moved {{
  from = google_iam_workload_identity_pool_provider.github_provider
  to   = module.foundation.google_iam_workload_identity_pool_provider.github_provider
}}

moved {{
  from = google_service_account.github_deployer
  to   = module.foundation.google_service_account.github_deployer
}}

moved {{
  from = google_service_account_iam_member.github_wif_binding
  to   = module.foundation.google_service_account_iam_member.github_wif_binding
}}

moved {{
  from = google_project_iam_member.deployer_run_admin
  to   = module.foundation.google_project_iam_member.deployer_run_admin
}}

moved {{
  from = google_project_iam_member.deployer_artifact_admin
  to   = module.foundation.google_project_iam_member.deployer_artifact_admin
}}

moved {{
  from = google_project_iam_member.deployer_sa_user
  to   = module.foundation.google_project_iam_member.deployer_sa_user
}}

moved {{
  from = google_project_iam_member.deployer_build_editor
  to   = module.foundation.google_project_iam_member.deployer_build_editor
}}

moved {{
  from = google_project_iam_member.deployer_storage_admin
  to   = module.foundation.google_project_iam_member.deployer_storage_admin
}}

{compute_moves}
"""


# HB-03 `extract_bespoke_custom_resources` DELETED (FD-55 W1, register FD55-W1): no production caller (the Step 1
# assembly contract splices blocks instead); it dropped AI blocks by name lists and rewired references by regex.


# RT14-08: the Firestore id grammar the index renderers accept (Firestore "Constraints on collections, documents, and
# fields": an id is valid UTF-8 of at most 1,500 bytes; a collection id has no "/", is not "." or "..", and does not
# match __.*__). The platform also refuses control characters (they cannot come from a real query and are the shape of
# an injection attempt). Query scopes are the scanner's two values, exactly.
FIRESTORE_ID_MAX_BYTES = 1500
FIRESTORE_QUERY_SCOPES = ("COLLECTION", "COLLECTION_GROUP")


class FirestoreIndexIdInvalid(ValueError):
    """RT14-08: a Firestore collection id, field path or query scope the app code queries is outside the grammar the
    platform renders into infra/workload/indexes.tf. Stage: developer assembly (step 7, composite indexes), before any
    commit; the developer handler raises it as DeveloperStageError(FIRESTORE_INDEX_ID_INVALID). Never rendered, never
    skipped silently."""

    error_class = "FIRESTORE_INDEX_ID_INVALID"
    stage = "developer.assembly.firestore_indexes"


def _firestore_id_problem(value: Any, *, collection: bool) -> Optional[str]:
    """Why `value` is not a renderable Firestore collection id (`collection`) or field path; None when it is."""
    if not isinstance(value, str) or not value:
        return "is empty or not a string"
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return "is not valid UTF-8"
    if size > FIRESTORE_ID_MAX_BYTES:
        return f"is {size} bytes (Firestore allows at most {FIRESTORE_ID_MAX_BYTES})"
    if any(unicodedata.category(ch) == "Cc" for ch in value):
        return "contains a control character"
    if collection:
        if "/" in value:
            return "contains '/' (a collection id cannot)"
        if value in (".", ".."):
            return "is '.' or '..' (a collection id cannot be)"
        if len(value) >= 4 and value.startswith("__") and value.endswith("__"):
            return "matches __.*__ (reserved by Firestore)"
    return None


def validate_firestore_index_requirements(requirements: List[Any]) -> None:
    """RT14-08: refuse (FirestoreIndexIdInvalid) any requirement whose collection id, query scope or field path is
    outside the grammar above. Every valid requirement passes unchanged (nothing is rewritten)."""
    for req in requirements or []:
        coll = getattr(req, "collection_id", "default")
        problem = _firestore_id_problem(coll, collection=True)
        if problem:
            raise FirestoreIndexIdInvalid(f"Firestore collection id {coll!r} {problem}; its composite index cannot be "
                                          f"rendered into infra/workload/indexes.tf")
        scope = getattr(req, "query_scope", "COLLECTION")
        if scope not in FIRESTORE_QUERY_SCOPES:
            raise FirestoreIndexIdInvalid(f"Firestore query scope {scope!r} of collection {coll!r} is not one of "
                                          f"{', '.join(FIRESTORE_QUERY_SCOPES)}")
        for f in getattr(req, "fields", []) or []:
            fp = getattr(f, "field_path", "")
            problem = _firestore_id_problem(fp, collection=False)
            if problem:
                raise FirestoreIndexIdInvalid(f"Firestore field path {fp!r} of collection {coll!r} {problem}; its "
                                              f"composite index cannot be rendered into infra/workload/indexes.tf")


def generate_golden_indexes_tf(
    requirements: List[Any],
    project_id_var: str = "var.project_id",
) -> Optional[str]:
    """
    Generates deterministic infra/workload/indexes.tf for all required Firestore composite indexes.
    Adheres strictly to the Single-Generator contract and sets depends_on = [module.foundation].
    RT14-08: every requirement is validated first (validate_firestore_index_requirements: FirestoreIndexIdInvalid),
    and every collection id, query scope and field path is written through hcl_quoted, so a name taken from app code
    can never close its string and add HCL to this platform-owned file. A valid name renders byte-identically.
    """
    if not requirements:
        return None
    validate_firestore_index_requirements(requirements)

    resource_blocks: List[str] = []
    seen_names = set()

    for req in requirements:
        coll = getattr(req, "collection_id", "default")
        scope = getattr(req, "query_scope", "COLLECTION")
        fields = getattr(req, "fields", [])

        # Resource naming: idx_<clean_coll>_<field_slug>
        clean_coll = re.sub(r"[^a-zA-Z0-9_]", "_", coll.lower())
        field_slugs = []
        for f in fields:
            fp = getattr(f, "field_path", "field")
            field_slugs.append(re.sub(r"[^a-zA-Z0-9_]", "_", fp.lower()))
        combined_slug = f"idx_{clean_coll}_{'_'.join(field_slugs)}"[:55].rstrip("_")

        resource_name = combined_slug
        counter = 1
        while resource_name in seen_names:
            counter += 1
            resource_name = f"{combined_slug[:50]}_{counter}"
        seen_names.add(resource_name)

        field_lines: List[str] = []
        for f in fields:
            fp = getattr(f, "field_path", "")
            mode = getattr(f, "mode", "ORDER")
            order = getattr(f, "order", "ASCENDING")
            if mode == "ARRAY" or order == "CONTAINS":
                field_lines.append(
                    f'  fields {{\n    field_path   = {hcl_quoted(fp)}\n    array_config = "CONTAINS"\n  }}'
                )
            else:
                ord_val = "DESCENDING" if "DESC" in str(order).upper() else "ASCENDING"
                field_lines.append(
                    f'  fields {{\n    field_path = {hcl_quoted(fp)}\n    order      = "{ord_val}"\n  }}'
                )

        fields_hcl = "\n\n".join(field_lines)

        block = f"""resource "google_firestore_index" "{resource_name}" {{
  project     = {project_id_var}
  database    = "(default)"
  collection  = {hcl_quoted(coll)}
  query_scope = {hcl_quoted(scope)}

{fields_hcl}

  depends_on = [module.foundation]
}}"""
        resource_blocks.append(block)

    header = (
        "# ==============================================================================\n"
        "# STACKVEND: GOOGLE CLOUD FIRESTORE COMPOSITE INDEXES\n"
        "# Deterministically extracted via Python AST query scanner.\n"
        "# Guarantees runtime compound queries execute without FailedPrecondition (400) errors.\n"
        "# ==============================================================================\n\n"
    )
    return header + "\n\n".join(resource_blocks) + "\n"


def generate_firestore_indexes_json(requirements: List[Any]) -> str:
    """
    Generates deterministic firestore.indexes.json for local emulator, Firebase CLI,
    and developer testing synchronization. RT14-08: the same id grammar as indexes.tf (FirestoreIndexIdInvalid).
    """
    validate_firestore_index_requirements(requirements)
    indexes_list = []
    for req in requirements:
        coll = getattr(req, "collection_id", "default")
        scope = getattr(req, "query_scope", "COLLECTION")
        fields = getattr(req, "fields", [])

        fields_list = []
        for f in fields:
            fp = getattr(f, "field_path", "")
            mode = getattr(f, "mode", "ORDER")
            order = getattr(f, "order", "ASCENDING")
            if mode == "ARRAY" or order == "CONTAINS":
                fields_list.append({"fieldPath": fp, "arrayConfig": "CONTAINS"})
            else:
                ord_val = "DESCENDING" if "DESC" in str(order).upper() else "ASCENDING"
                fields_list.append({"fieldPath": fp, "order": ord_val})

        indexes_list.append({
            "collectionGroup": coll,
            "queryScope": scope,
            "fields": fields_list,
        })

    data = {
        "indexes": indexes_list,
        "fieldOverrides": [],
    }
    return json.dumps(data, indent=2) + "\n"


def generate_human_tf_template() -> str:
    """
    Generates baseline infra/workload/human.tf template for additive custom GCP infrastructure.
    This file is strictly owned by human architects/developers and is preserved across automated builds.
    """
    return (
        "# ==============================================================================\n"
        "# StackVend: Human Architect & Custom Infrastructure Additions\n"
        "# ==============================================================================\n"
        "# This file is reserved for human architects, operators, and custom modules.\n"
        "# Unlike main.tf, this file is NEVER overwritten by StackVend agents.\n"
        "#\n"
        "# Use this file to declare additive GCP resources such as:\n"
        "# - google_storage_bucket\n"
        "# - google_pubsub_topic / google_pubsub_subscription\n"
        "# - google_secret_manager_secret\n"
        "# - google_sql_database_instance\n"
        "# - Bespoke IAM roles or custom module invocations\n"
        "#\n"
        "# Example:\n"
        "# resource \"google_storage_bucket\" \"workload_assets\" {\n"
        "#   name                        = \"${var.product_id}-assets\"\n"
        "#   location                    = var.region\n"
        "#   uniform_bucket_level_access = true\n"
        "# }\n"
        "# ==============================================================================\n"
    )


def generate_human_override_tf_template() -> str:
    """
    Generates baseline infra/workload/human_override.tf template.
    Uses Terraform's native override mechanism (*_override.tf) to override arguments
    in main.tf without touching or forking the platform-owned file.
    """
    return (
        "# ==============================================================================\n"
        "# StackVend: Human Architect Configuration Overrides\n"
        "# ==============================================================================\n"
        "# This file uses Terraform's native override mechanism (*_override.tf).\n"
        "# Any block or attribute defined here merges over top of resources and modules\n"
        "# declared in main.tf.\n"
        "#\n"
        "# Unlike main.tf, this file is NEVER overwritten by StackVend agents.\n"
        "#\n"
        "# Example 1: Override Cloud Run container scaling or timeouts in module \"compute\":\n"
        "#\n"
        "# module \"compute\" {\n"
        "#   min_instance_count = 2\n"
        "#   timeout_seconds    = 600\n"
        "# }\n"
        "#\n"
        "# Example 2: Override environment variables on a Cloud Run service:\n"
        "#\n"
        "# resource \"google_cloud_run_v2_service\" \"app\" {\n"
        "#   template {\n"
        "#     containers {\n"
        "#       env {\n"
        "#         name  = \"FEATURE_FLAG_ENABLED\"\n"
        "#         value = \"true\"\n"
        "#       }\n"
        "#     }\n"
        "#   }\n"
        "# }\n"
        "# ==============================================================================\n"
    )


def generate_infra_readme(product_id: str, archetype: str = "cloudrun") -> str:
    """
    Generates comprehensive documentation for infra/workload/ explaining governance boundaries
    between platform-managed golden files and human-owned extension points.
    """
    return f"""# Infrastructure Configuration: `{product_id}`

This directory contains the Terraform configuration managed by **StackVend** alongside human engineering extensions.

---

## 🏛️ Governance Model: Paved Road vs. Human Extensions

StackVend uses a strict separation of concerns to guarantee platform security and zero build regressions while giving human architects full flexibility:

| File | Owner | Automated Build Behavior | Purpose |
| :--- | :---: | :---: | :--- |
| **`main.tf`** | 🤖 **StackVend** | **REGENERATED on every build** | Core baseline: APIs, Workload Identity Federation (WIF), Service Accounts, container runtime contracts, Org Policy compliance. **Do not edit directly** if you want your changes to persist across automated builds. |
| **`variables.tf`** | 🤖 **StackVend** | **REGENERATED on every build** | Platform standard input variables (`product_id`, `region`, `container_image`, etc.). |
| **`outputs.tf`** | 🤖 **StackVend** | **REGENERATED on every build** | Platform standard outputs (`service_uri`, `wif_provider_name`, etc.). |
| **`moved.tf`** | 🤖 **StackVend** | **REGENERATED on every build** | State migration blocks for zero-downtime architectural refactors. |
| **`terraform.tfvars`**| 🤖 **StackVend** | **REGENERATED on every build** | Container resource sizing and domain restriction invoker lists. |
| **`human.tf`** | 👤 **Human Architect** | **PRESERVED VERBATIM (Never touched)** | **Additive Custom Resources**: Use this file to add Cloud Storage buckets, BigQuery datasets, Cloud SQL instances, Pub/Sub topics, or custom IAM roles. |
| **`human_override.tf`**| 👤 **Human Architect** | **PRESERVED VERBATIM (Never touched)** | **Configuration Overrides**: Uses Terraform native `*_override.tf` semantics to override specific attributes in `main.tf` (e.g. min/max instances, timeouts, VPC connectors). |
| **`custom.tf`** | 🤖 / 👤 Shared | **EDITED by builds** | Shared with the AI developer: a build may rewrite it, adds or refreshes its own `module "compute_<service>"` blocks, and removes a block that declares an address the files above already declare. Your other blocks, Cloud Run services included, are kept. Put resources only you own in `human.tf`. |

---

## 🛠️ How to Add Custom Infrastructure

### 1. Adding New GCP Resources (`human.tf`)
Declare any standard Terraform resource in `human.tf`:

```hcl
resource "google_storage_bucket" "workload_storage" {{
  name                        = "${{var.product_id}}-storage"
  location                    = var.region
  uniform_bucket_level_access = true
}}
```

### 2. Overriding Baseline Configuration (`human_override.tf`)
Terraform loads files ending with `_override.tf` **last** and merges them into the definitions from `main.tf`.

To change instance scaling on the primary compute service without touching `main.tf`:

```hcl
module "compute" {{
  min_instance_count = 2
  max_instance_count = 50
}}
```

### 3. Deploying Changes
- **Git Push**: Commits pushed to `main` branch trigger deployment via your CI/CD pipeline or StackVend.
- **Redeploy Workload**: When redeploying a decommissioned workload, StackVend applies all files directly from Git—including your `human.tf` and `human_override.tf`.
- **Feature Builds / Launch Build**: StackVend regenerates `main.tf` to keep foundation security up to date, while pulling your `human.tf` and `human_override.tf` directly from Git and preserving them untouched.
"""

