"""
Project Castor: Developer Agent Implementation Handler
Invokes Vertex AI Gemini to generate application & infrastructure code,
commits files atomically to the GitHub repository, and opens Pull Requests.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, replace
import functools
import logging
import os
import runtime_env  # G1: on_cloud_run() = service or stage-runner job (never K_SERVICE alone)
import posixpath
import random
import re
import shutil
import subprocess  # noqa: F401 - RT14-10: git runs through run_git; tests patch subprocess.run via this name
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple

import httpx
import jwt
from github import Github, GithubException, InputGitTreeElement

# FD-4G: no ImportError fallback -- a missing path guard must crash at boot, never fail open.
from shared.path_safety import GIT_RESERVED, UnsafePathError, safe_join, validate_relpath
# RT14-10 (owner 11-14): the git CLI helpers that keep the GitHub credential off every command line and out of errors.
from shared.providers.github_provider import git_auth_env, git_secret_values, run_git, without_git_secrets

# Lane 19 (owner register row 27a): typed developer failures; no ImportError fallback (a missing class must crash).
from .errors import (ACCESS_POLICY_REQUIRED, ACCESS_POLICY_UNAVAILABLE, ACCESS_WIDENING_UNAPPROVED,
                     FIRESTORE_INDEX_ID_INVALID, LLM_OUTPUT_INVALID, LLM_UNAVAILABLE, REGION_NOT_APPROVED,
                     REGION_UNAVAILABLE, REGISTERED_MODULE_PUBLIC_EXPOSURE, WORKLOAD_RECORD_UNREADABLE,
                     DeveloperStageError)
# SLOW-CALL-FALLBACK (owner 11-13): per-call timeout + fallback walk of the single-turn call; who wrote what
from .llm_transport import (DEFAULT_CALL_TIMEOUTS, TIMEOUT, CallPurpose, CallWalk, active_stage_bound,
                            call_timeout_s, ledger_abandoned_sink, model_provenance_record)
from shared.hallucination_stack import repair_call_max_output_tokens, repair_call_thinking_budget
# FD-4CX: the public-exposure check of registered (non-golden) modules (no stub fallback)
from shared.module_exposure import RegisteredModulePublicExposureError, check_registered_module, modules_under
# L19-F4: the one-shot widening flag on workloads/{pid} (shared.access_policy.ACCESS_WIDENING_APPROVAL_FIELD; pinned)
ACCESS_WIDENING_APPROVAL_FIELD = "access_widening_approval"
# APP-ADMIN-DEFAULT: the typed app administrator record a Direct IAP Cloud Run build writes on workloads/{pid}
# (_app_admin_outcome; shared.access_policy.APP_ADMIN_CONTRACT_FIELD, pinned) and its one warning code.
APP_ADMIN_CONTRACT_FIELD = "app_admin_contract"
APP_ADMIN_ENV_COLLISION = "APP_ADMIN_ENV_COLLISION"   # PlatformDefectError reason (_assemble_tree_typed)
APP_ADMIN_NONE_CONFIGURED = "APP_ADMIN.NONE_CONFIGURED"
# Lane 19 L19-2 (FD-4I): access is explicit typed data (see access_resolution.py; no stub fallback).
from .access_resolution import ResolvedAccess, resolve_access

try:
    from shared.vcs_provider import VCSProviderFactory
except ImportError:
    try:
        from ..shared.vcs_provider import VCSProviderFactory
    except ImportError:
        try:
            from vcs_provider import VCSProviderFactory
        except ImportError:
            VCSProviderFactory = None

# FD-4F A9 (FS-1/FS-2, plan wave2-lane13 A9): hard package imports. The former ImportError chain ended in stub
# gates (e.g. sanitizers -> identity, scan_firestore_queries -> []), so a broken import silently disabled the
# pre-flight gates; a missing module now crashes the import. FD-55 W4: the HCL pre-flight / naming / sweep fixers
# imported here are deleted (preflight_validator tombstone).
from .prompt import DEVELOPER_SYSTEM_PROMPT, build_developer_system_prompt, direct_iap_auth_rule, with_app_auth_rule
from . import app_provenance   # SAT-49 F4: app-code provenance and unchanged orphan files
from . import plan_targets   # PLAN-TARGET-FILES / MANIFEST-PATH-DEFERS-TO-DAG: the DAG's exact target paths
from .preflight_validator import (
    ManifestHydrationError,
    hydrate_kubernetes_manifests,
    is_kubernetes_manifest_path,
)
from .lead_orchestrator import LeadDeveloperOrchestrator
from .swarm_dispatcher import FILES_REASK_PREVIOUS_ATTEMPT, JSON_REASK_PREVIOUS_ATTEMPT, SwarmDispatcher
from .swarm_schemas import SwarmExecutionMode, LeadDeveloperDecompositionPlan
from .terraform_engine import (
    AppAdminEnvCollision,
    FirestoreIndexIdInvalid,
    generate_firestore_indexes_json,
    generate_golden_indexes_tf,
    generate_golden_main_tf,
    generate_golden_moved_tf,
    generate_golden_outputs_tf,
    generate_golden_variables_tf,
    generate_human_override_tf_template,
    generate_human_tf_template,
    generate_infra_readme,
    get_canonical_module_files,
    referenced_local_dirs,
    infer_additional_apis_from_custom_tf,
    planned_cloud_run_services,
    reconcile_multi_service_declarations,
    vendor_terraform_modules,
    extract_scaling_from_spec,
    RegionNotApproved,
    RegionUnavailable,
    WORKLOAD_REGION_DEFAULT,
    _workload_record_region,
    resolve_workload_region,
)
from .firestore_scanner import scan_firestore_queries
from .workflow_validator import (
    WorkflowValidationError,
    validate_all_staged_workflows,
    validate_github_workflow_yaml,
)

# Step 1 S1-A (register HS-01/HS-08): the root-module assembly contract and the hallucination-stack runtime
# (stores, V1b client, settings). Hard imports: no stand-in exists.
try:
    from .assembly import assemble_root_module, bespoke_root_text, platform_root_keys, repository_custom_tf_keys
    from .compute_intent import (ComputeIntent, TopologyGuardError, normalize_service_name,
                                 resolve_compute_intent)
    from .topology_wiring import (cloudrun_probe_services, deployed_view, health_probe_rule, legacy_vpc_connector,
                                  non_cloudrun_services, primary_network_purposes, topology_contract_rule, topology_env_vars,
                                  topology_network_purposes, topology_scaling, topology_vpc_connector,
                                  workflow_services)
    from .hallucination_runtime import get_runtime, wait_for_validate_ready
    from .platform_facts import (FACT_PURPOSE, FactsHolder, FactsUnavailable, committed_fact_values,
                                 has_existing_network, load_ipam_pool, render_fact_tfvars, render_fact_variables,
                                 required_network_purposes)
    from . import iac_intent_contract as intent_contract   # TI-3 typed IaC intent (mode "generate" only)
    from . import deploy_repair   # TI-5-R3: the deploy's typed report on the remediation dispatch
    from . import qa_repair   # QA-FEEDBACK: QA's typed findings on a QA retry dispatch
except ImportError:
    from developer_agent.assembly import (assemble_root_module, bespoke_root_text, platform_root_keys,
                                          repository_custom_tf_keys)
    from developer_agent.compute_intent import (ComputeIntent, TopologyGuardError, normalize_service_name,
                                                resolve_compute_intent)
    from developer_agent.topology_wiring import (cloudrun_probe_services, deployed_view, health_probe_rule,
                                                 legacy_vpc_connector,
                                                 non_cloudrun_services, primary_network_purposes, topology_contract_rule,
                                                 topology_env_vars, topology_network_purposes, topology_scaling,
                                                 topology_vpc_connector, workflow_services)
    from developer_agent.hallucination_runtime import get_runtime, wait_for_validate_ready
    from developer_agent.platform_facts import (FACT_PURPOSE, FactsHolder, FactsUnavailable,  # noqa: F401
                                                committed_fact_values, has_existing_network, load_ipam_pool,
                                                render_fact_tfvars, render_fact_variables, required_network_purposes)
    from developer_agent import iac_intent_contract as intent_contract   # TI-3
    from developer_agent import deploy_repair   # TI-5-R3
    from developer_agent import qa_repair   # QA-FEEDBACK
try:  # lane 10 (FD-51): the platform-owned topology review file
    from shared.service_topology import TOPOLOGY_JSON_PATH, render_topology_json
except ImportError:  # pragma: no cover
    from ..shared.service_topology import TOPOLOGY_JSON_PATH, render_topology_json  # type: ignore
try:
    from shared.diagnostics import (Diagnostic, ErrorClass, ProvenanceEntry, RepairBudgetExhausted, RepairEvent,
                                    StageError, StoreUnavailable, ValidationReport, artifact_hash)
except ImportError:
    from ..shared.diagnostics import (Diagnostic, ErrorClass, ProvenanceEntry, RepairBudgetExhausted,  # type: ignore
                                      RepairEvent, StageError, StoreUnavailable, ValidationReport, artifact_hash)

# FD-4CI-b-R1-WIF-SHARED: branch_secret_suffix / repository_shared_with_other_workload (one rule with vending).
try:
    from shared.github_identity import (GITHUB_ACTIONS_DEPLOY_FIELD, branch_secret_suffix, get_default_github_owner,
                                        github_actions_deploy_enabled, repository_shared_with_other_workload,
                                        resolve_repo_identity)
except ImportError:
    try:
        from .github_identity import (GITHUB_ACTIONS_DEPLOY_FIELD, branch_secret_suffix, get_default_github_owner,
                                      github_actions_deploy_enabled, repository_shared_with_other_workload,
                                      resolve_repo_identity)
    except ImportError:
        try:
            from github_identity import (GITHUB_ACTIONS_DEPLOY_FIELD, branch_secret_suffix,
                                         get_default_github_owner, github_actions_deploy_enabled,
                                         repository_shared_with_other_workload, resolve_repo_identity)
        except ImportError:
            # FD-4CI-b-R1-WIF-SHARED unavailable: a shared repository's workflow on a non-main branch is refused
            # (generate_service_workflow); main and own-repository workflows are unaffected.
            branch_secret_suffix = repository_shared_with_other_workload = None
            # GHA-DEPLOY-SWITCH unavailable: a workload whose record carries the switch is refused
            # (DeveloperAgent._recorded_gha_deploy); a record without it is on (today).
            GITHUB_ACTIONS_DEPLOY_FIELD = "github_actions_deploy"
            github_actions_deploy_enabled = None
            def get_default_github_owner():  # FD-4AY: no built-in owner (shared.github_identity unavailable)
                owner = os.getenv("GITHUB_ORG") or os.getenv("GITHUB_DEPLOYMENTS_ORG") or os.getenv("GITHUB_OWNER")
                if not owner:
                    raise RuntimeError("No GitHub owner configured: set GITHUB_ORG")
                return owner
            def resolve_repo_identity(repo, default_owner=None, product_id=None):
                owner = default_owner or get_default_github_owner()
                if repo and "/" in repo:
                    parts = repo.split("/", 1)
                    return parts[0], parts[1], repo
                clean_pid = (product_id or "workload").lower().replace("_", "-")
                repo_name = repo or clean_pid   # GITHUB-REPO-NAME-NO-PREFIX: shared default_repository_name
                return owner, repo_name, f"{owner}/{repo_name}"

try:
    from shared.github_resilience import (
        GitHubTokenManager,
        get_github_token,
        get_github_client,
        github_retry_with_backoff,
        GitHubRateLimitExceededError,
    )
except ImportError:
    try:
        from .github_resilience import (
            GitHubTokenManager,
            get_github_token,
            get_github_client,
            github_retry_with_backoff,
            GitHubRateLimitExceededError,
        )
    except ImportError:
        try:
            from github_resilience import (
                GitHubTokenManager,
                get_github_token,
                get_github_client,
                github_retry_with_backoff,
                GitHubRateLimitExceededError,
            )
        except ImportError:
            pass

# FD-4F A9 (FS-3): one hard import of the pre-commit verifier (the old chain ended in `SynthesisVerifierAgent = None`,
# which skipped every pre-commit gate). Typed gate outcomes come from the gateway's gate_errors (same sys.path root).
from gatekeeper_agent.verifier import SynthesisVerifierAgent
from gate_errors import GateError, GateFailedError, GateUnavailableError, MainMovedError, PlatformDefectError
import stage_deadline   # STAGE-DEADLINE: cooperative stop, per-call bound, orphan guard (gateway root module)

try:
    from shared.resource_sizing import (
        ContainerSizingProfile,
        calculate_container_sizing,
        resolve_workload_sizing,
    )
except ImportError:
    try:
        from .shared.resource_sizing import (
            ContainerSizingProfile,
            calculate_container_sizing,
            resolve_workload_sizing,
        )
    except ImportError:
        try:
            from resource_sizing import (
                ContainerSizingProfile,
                calculate_container_sizing,
                resolve_workload_sizing,
            )
        except ImportError:
            from dataclasses import dataclass
            @dataclass(frozen=True)
            class ContainerSizingProfile:
                tier: int = 1
                memory_limit: str = "512Mi"
                cpu_limit: str = "1000m"
                gcloud_cpu: str = "1"
                initial_delay_secs: int = 2
                failure_threshold: int = 20
                matched_packages: list = None
                matched_intents: list = None
            def resolve_workload_sizing(*args, **kwargs):
                return ContainerSizingProfile(matched_packages=[], matched_intents=[])
            def calculate_container_sizing(*args, **kwargs):
                return ContainerSizingProfile(matched_packages=[], matched_intents=[])

# FD-4CI-b: platform compute defaults + the Thinking Budget setting
from .platform_compute import (apply_platform_container_baseline, resolve_platform_compute_defaults,
                               default_min_instances as platform_default_min_instances)
from shared.settings import thinking_budget_of

logger = logging.getLogger("castor-developer-agent")
logging.basicConfig(level=logging.INFO)

# The root tfvars the platform renders per run in _assemble_tree (never the LLM's: lane 11 RT2 G1).
_PLATFORM_TFVARS = "infra/workload/terraform.tfvars"

try:  # Argon compat (owner 10-14): per-model-family request rules; identity for Gemini <= 3.x
    from shared.gemini_model_config import (Purpose, ThinkingControl, adapt_generate_config_kwargs,
                                            max_output_tokens_for, resolve_model_family, thinking_config_for)
except ImportError:  # pragma: no cover
    from ..shared.gemini_model_config import (Purpose, ThinkingControl, adapt_generate_config_kwargs,  # type: ignore
                                              max_output_tokens_for, resolve_model_family, thinking_config_for)


def _reserved_thinking_tokens(model, thinking_budget):
    """FD-4CI-b RT F6: the thinking budget only reserves output room on a model that receives it (budget family, or
    an unknown id, as thinking_config_for sends it); a thinking-level model (Argon) never gets a budget: 0."""
    fam = resolve_model_family(model)
    return thinking_budget if fam is None or fam.thinking is ThinkingControl.BUDGET else 0

try:
    from shared.settings import get_model_cascade_for_agent
    from shared.cooldown_manager import (
        is_rate_limit_error,
        is_model_deprecated_error,
        wait_for_rate_limit_cooldown,
    )
except ImportError:
    try:
        from ..shared.settings import get_model_cascade_for_agent
        from ..shared.cooldown_manager import (
            is_rate_limit_error,
            is_model_deprecated_error,
            wait_for_rate_limit_cooldown,
        )
    except ImportError:
        def get_model_cascade_for_agent(agent_name, project_id=None):
            return [os.getenv("GEMINI_MODEL") or "gemini-4-carbon", "gemini-4-argon"]
        def is_rate_limit_error(e):
            return "429" in str(e) or "resource_exhausted" in str(e).lower()
        def is_model_deprecated_error(e):
            return "404" in str(e) or "not found" in str(e).lower()
        def wait_for_rate_limit_cooldown(*args, **kwargs):
            import time
            time.sleep(60)
            return True


# HB-43 gateway copy `sanitize_github_workflow` / `_deduplicate_env_block` DELETED (FD-55 W1, register FD55-W1): no
# production caller (the platform renders the workflows; the terraform server keeps its own apply-time copy).


# HB-42 `sanitize_python_paths` DELETED (FD-4AD): regex rewrites of `apps/<svc>/static|templates` literals,
# `os.path.join("apps", ...)` and `from apps.<svc>.<mod> import` lines in valid Python. It ran only in the direct-commit
# fallback below, AFTER validation, on the tree the hallucination stack had validated. The fallback now commits the
# validated bytes exactly.


# `detect_workload_services` lives in workload_inventory.py so the V3c validator can use the same inventory without
# importing this module (Step 2a code RT F10); the name stays importable from here for existing callers and tests.
try:
    from .workload_inventory import detect_workload_services
except ImportError:  # pragma: no cover - module loaded outside its package
    try:
        from developer_agent.workload_inventory import detect_workload_services  # type: ignore
    except ImportError:
        from workload_inventory import detect_workload_services  # type: ignore


# HB-29 `ensure_health_check_endpoint` (regex /health injection) DELETED in Step 2 S2-A (register HS-09): a missing
# GET /health is CONTAINER.HEALTH_ROUTE_MISSING (validators/container.py, V3c) and the AI adds the route.


# HB-28 `standardize_requirements` DELETED (FD-4AD): it prepended 9 base pins (incl. `pytest`, `pydantic>=2.6.0` beside
# a user `pydantic==1.10`), dropped every user line for those names (Gate A 01-r3: `fastapi>=0.110.0,<1.0.0` lost its
# cap), dropped every line whose name matched any local `.py` stem in the tree, and wrote a requirements.txt into Node
# services. The add-only requirements contract (gatekeeper_agent/requirements_contract.py, run by the verifier's
# reconcile_service_requirements) appends only proven needs.


# PLAN-TARGET-FILES: archetypes whose assembly keeps no application code (the same exact set _assemble_tree uses)
NO_APP_CODE_ARCHETYPES = ("foundation-only", "none", "empty")


def dispatch_plan_targets(inputs: Any, qa_plan: Any, deploy_plan: Any) -> Tuple[Any, ...]:
    """PLAN-TARGET-FILES: the DAG target files this dispatch's stack checks (plan_targets.required_plan_targets), only
    on a full build: () on a QA or deploy repair (each may edit only the files it was given, and the tree it repairs
    already passed this check) and on an archetype whose assembly keeps no application code."""
    if qa_plan is not None or deploy_plan is not None:
        return ()
    intent = inputs.compute_intent
    if getattr(intent, "archetype", None) in NO_APP_CODE_ARCHETYPES:
        return ()
    return plan_targets.required_plan_targets(inputs.task_dag, service_names=getattr(intent, "service_names", None))


def dag_manifest_paths(task_dag: Any, topology: Any) -> Dict[str, Tuple[str, ...]]:
    """MANIFEST-PATH-DEFERS-TO-DAG: plan_targets.dag_manifest_paths over the topology's gke-autopilot services (exact
    typed kind); {} without a topology or a gke service."""
    if topology is None:
        return {}
    gke = [n for n in topology.names if topology.kind(n) == "gke-autopilot"]
    return plan_targets.dag_manifest_paths(task_dag, gke) if gke else {}


# FD-55 W5 (register FD55-W5; plan G21 / G23 / G24 "one Dockerfile rule"): the exact basenames the Buildpacks-only
# mandate (AGENTS invariant 4) removes from a workload tree, case-insensitive. The gatekeeper twin
# (`basename.startswith("dockerfile")`, which also removed e.g. `dockerfile-notes.md`) and the third purge after the
# pre-flight check are deleted; this is the one rule.
def is_prohibited_container_file(path: str) -> bool:
    """True for `Dockerfile`, `Dockerfile.<anything>` and `.dockerignore` (exact basename, any directory, any case)."""
    base = posixpath.basename(path).lower()
    return base == "dockerfile" or base.startswith("dockerfile.") or base == ".dockerignore"


# FD-55 W5 G21 `static_mount_dirs` (the AST `StaticFiles(directory="<literal>")` rule) moved to shared/static_mounts.py
# (FD55-A8-CONVERT, owner 10-27) so the deploy workspace (terraform MCP prepare_workspace) uses the same rule; the
# name stays importable from this module.
from shared.static_mounts import static_mount_dirs, static_placeholder_files  # noqa: E402,F401


def enforce_container_contract(files: Dict[str, str], product_id: str, archetype: str = "cloudrun",
                               topology: Any = None) -> None:
    """
    Platform half of the GCP-Native Buildpack Container Contract across all services (the ONE container-contract
    rule of the developer stage; FD-55 W5 folded the gatekeeper twin and the later purge / runtime-pin copies into it):
    1. Removes every Dockerfile / `.dockerignore` (is_prohibited_container_file; Buildpacks exclusivity, AGENTS
       invariant 4).
    2. Pins `.python-version` (3.13) in every deployed service in apps/*/ and the root. The deployed services are
       detect_workload_services plus, with a `topology` (lane 10 ValidatedTopology), every `apps/<dir>/` the topology
       names as a container service (validators/container.is_topology_container_service, PWB-3: the same typed rule V3c
       and the build use). FD-55 W5 RT F1: a Procfile-only topology worker beside a `main.py` sibling is built and
       deployed, but detect_workload_services drops it as a skeleton; the deleted verifier twin had pinned it.
    3. Adds `<dir>/.gitkeep` (empty, add-only) for each directory a service's Python code mounts with
       `StaticFiles(directory="<dir>")` (static_mount_dirs, AST) when that directory holds no file yet, so the mount
       does not fail at start-up. Nothing else is scaffolded.
    The HB-28 requirements rewrite (`standardize_requirements`) was DELETED in FD-4AD: requirements.txt is the AI's;
    the verifier's add-only contract appends proven needs only.
    The Procfile overwrite and the /health injection (HB-29) were DELETED in Step 2 S2-A (register HS-09): the AI's
    Procfile is kept as written and V3c (validators/container.py) reports a missing/unbound entrypoint or health route
    as CONTAINER.* diagnostics that the AI repairs.
    """
    # 1. Remove every Dockerfile / .dockerignore anywhere in the repository (one exact basename rule)
    for k in list(files.keys()):
        if is_prohibited_container_file(k):
            del files[k]

    # Foundation-only workloads have no compute services or container contracts
    if archetype in ("foundation-only", "none", "empty"):
        return

    # 2. Discover all microservices
    services = list(detect_workload_services(files, product_id))
    if topology is not None:   # FD-55 W5 RT F1: every topology container service too (PWB-3 rule, as V3c)
        try:
            from .validators.container import is_topology_container_service
        except ImportError:  # pragma: no cover - module loaded outside its package
            from developer_agent.validators.container import is_topology_container_service  # type: ignore
        for d in sorted({p.split("/")[1] for p in files if p.startswith("apps/") and p.count("/") >= 2}):
            if d and d not in services and is_topology_container_service(topology, d):
                services.append(d)

    for svc in services:
        prefix = f"apps/{svc}"

        # A. Enforce .python-version
        files[f"{prefix}/.python-version"] = "3.13\n"

        # B. (HB-29 Procfile overwrite DELETED, S2-A / HS-09: the AI's Procfile is parsed by V3c, never overwritten)

        # C. (HB-28 requirements rewrite DELETED, FD-4AD: the AI's requirements.txt is kept; add-only in the verifier)

        # D. Static directory placeholder, add-only, only for a directory the code really mounts (AST). The HB-29
        #    /health injection that ran here is DELETED (S2-A / HS-09).
        #    One rule with the deploy workspace (shared/static_mounts.static_placeholder_files, FD55-A8-CONVERT).
        service_files = {k[len(prefix) + 1:]: v for k, v in files.items() if k.startswith(f"{prefix}/")}
        for rel in static_placeholder_files(service_files):
            files[f"{prefix}/{rel}"] = ""

    # Ensure root .python-version is also pinned
    files[".python-version"] = "3.13\n"


# HD-03 `resolve_service_archetype` DELETED (FD-55 W8, register FD55-W8; plan G19): a CI workflow's compute kind on
# the no-topology path was guessed from the AI's custom.tf / main.tf (a module or resource whose label or
# `service_name` / `name` matched the directory, then a `compute-*` substring of the module text or the resource
# type) and, on a GKE workload, from name substrings (`gateway`, `edge`, `api`, `ingress`, `storefront`, `web` ->
# Cloud Run). DeveloperAgent._service_kind now reads the typed compute intent only, on both paths.


def _is_branch_name(value: Any) -> bool:
    """settings.is_branch_name (FD-4CI-b-R1); False when the settings module is not importable."""
    try:
        from shared.settings import is_branch_name
    except Exception:  # noqa: BLE001
        return False
    return is_branch_name(value)


def workflow_branch(recorded: Any) -> str:
    """FD-4CI-b-R1: the branch the generated deploy workflows trigger on -- the workload's recorded default_branch.
    No recorded branch (a workload from before branches were recorded) -> "main", as before. A recorded value that is
    not a plain branch name is never written into a workflow: "main", logged."""
    if recorded is None or recorded == "":
        return "main"
    if recorded == "main" or _is_branch_name(recorded):
        return recorded
    logger.error(f"DEFAULT_BRANCH_INVALID: recorded branch {recorded!r} is not a plain branch name; the deploy "
                 "workflows trigger on main.")
    return "main"


def deploy_workflow_branch(recorded: Any, read_branch: Any) -> str:
    """RT14-28: the deploy workflows' branch. The record's branch when this read found one (workflow_branch); else the
    branch the dispatch's tree was read from (`read_branch`, recorded by the same rule at the tree read), so a record
    read that failed and was passed over never turns into "main"; with neither, workflow_branch(recorded) ("main")."""
    if isinstance(recorded, str) and recorded:
        return workflow_branch(recorded)
    if isinstance(read_branch, str) and read_branch:
        return read_branch
    return workflow_branch(recorded)


GHA_WORKFLOW_DIR = ".github/workflows"

# RT14-13: the stack-run field holding what this dispatch read of the base branch -- {"branch", "files", "complete"}
# (a build's own tree read) or {"branch", "base_sha"} (a QA repair: the base its tested commit was cut from).
BASE_SNAPSHOT_FIELD = "base_snapshot"

# RT14-28 RT F3: reads of workloads/{product_id} before WORKLOAD_RECORD_UNREADABLE (the commit-time read ends a 20-60
# minute build, so one transient store error must not discard it); waits RETRY_WAIT_S x attempt between reads.
WORKLOAD_RECORD_READ_ATTEMPTS = 3
WORKLOAD_RECORD_RETRY_WAIT_S = 0.5


class BaseTreeRead(dict):
    """RT14-13 RT F2: the files of the developer's base tree read (a plain dict to every caller), carrying `branch`
    (the base branch read) and `snapshot` (BASE_SNAPSHOT_FIELD's value for the commit's base check). The record travels
    with the value, because one agent instance serves concurrent dispatches: never bare instance attributes."""

    def __init__(self, files: Optional[Mapping[str, str]], *, branch: str, snapshot: Dict[str, Any]):
        super().__init__(files or {})
        self.branch = branch
        self.snapshot = snapshot


def _is_commit_sha(value: Any) -> bool:
    """A full 40-character lowercase hex git SHA (qa_source.is_commit_sha, the gates' exact rule)."""
    from qa_source import is_commit_sha
    return is_commit_sha(value)


def gha_workflow_paths(tree: Mapping[str, Any]) -> List[str]:
    """GHA-DEPLOY-SWITCH: the deploy workflow files in `tree` -- exactly the paths generate_service_workflow's files
    are written to (`.github/workflows/deploy-<name>.yml`, directly in that directory). A switched-off workload's
    commit deletes them. Path components are compared exactly; file contents are never read."""
    out = []
    for path in sorted(tree):
        parts = path.split("/") if isinstance(path, str) else []
        if (len(parts) == 3 and "/".join(parts[:2]) == GHA_WORKFLOW_DIR and parts[2].startswith("deploy-")
                and parts[2].endswith(".yml") and len(parts[2]) > len("deploy-.yml")):
            out.append(path)
    return out


WORKLOAD_SA_ID_STEM_MAX = 20


def workload_sa_account_id(product_id: str) -> str:
    """SA-ACCOUNT-ID-TRIM: the workload runtime service account id exactly as the golden module computes it
    (infra/modules/workload-foundation/base/iam.tf):
    `"sa-${replace(substr(replace(var.product_id, "_", "-"), 0, 20), "/-+$/", "")}"` -- underscores to dashes, the
    first 20 characters, trailing dashes dropped. A cut that does not end in '-' is returned unchanged."""
    return "sa-" + product_id.replace("_", "-")[:WORKLOAD_SA_ID_STEM_MAX].rstrip("-")


def generate_service_workflow(
    service_name: str,
    product_id: str,
    project_id: str = "",
    project_number: str = "",
    archetype: str = "cloudrun",
    allow_unauthenticated: bool = True,
    memory_limit: str = "512Mi",
    cpu_limit: str = "1",
    min_instances: int = 0,
    max_instances: int = 10,
    region: Optional[str] = None,
    branch: str = "main",
    branch_secrets: bool = False,
) -> str:
    """
    Generates an isolated GitHub Actions CI/CD workflow for a microservice
    with path filtering (on.push.paths: ['apps/<service_name>/**']).
    Embeds target GCP project ID and project number as resilient fallbacks for WIF authentication.
    Dynamically aligns build & deployment steps according to the compute archetype.
    Injects dynamic memory and CPU resource limits to prevent Out-Of-Memory container termination.
    Preserves autoscaling bounds and custom environment variables configured by Terraform.
    `region` (FD-4AL): the workload region the developer resolved (None = the settings schema default, for direct
    callers); it is the workflow's REGION.
    `branch` (FD-4CI-b-R1): the workload's branch, the workflow's on.push.branches entry. "main" renders exactly as
    before; another plain branch name (settings.is_branch_name) is written single-quoted; anything else is refused
    (ValueError) -- the caller resolves the branch with workflow_branch().
    `branch_secrets` (FD-4CI-b-R1-WIF-SHARED): the workload shares its GitHub repository with another workload
    (DeveloperAgent._deploy_secrets_branch_named, the same decision vending's redeploy makes when it writes the
    secrets). On a branch other than main the workflow then reads the branch-named secrets GCP_PROJECT_ID_<B> /
    WIF_PROVIDER_<B> / WIF_SERVICE_ACCOUNT_<B> (<B> = shared.github_identity.branch_secret_suffix) first, then
    everything it read before, in the same order. False, or branch "main": rendered exactly as before.
    """
    if branch != "main" and not _is_branch_name(branch):
        raise ValueError(f"not a plain branch name for a workflow trigger: {branch!r}")
    branch_yaml = "main" if branch == "main" else f"'{branch}'"
    pid_first = wif_first = sa_first = ""
    if branch_secrets and branch != "main":
        if branch_secret_suffix is None:
            raise RuntimeError("shared.github_identity is not importable: the branch-named deploy secrets of a "
                               "shared repository cannot be rendered")
        sfx = branch_secret_suffix(branch)
        pid_first = f"secrets.GCP_PROJECT_ID_{sfx} || "
        wif_first = f"secrets.WIF_PROVIDER_{sfx} || "
        sa_first = f"secrets.WIF_SERVICE_ACCOUNT_{sfx} || "
    region_val = region or WORKLOAD_REGION_DEFAULT
    if not region_val:
        raise RegionUnavailable("no region passed and the settings schema is not importable")
    clean_svc = service_name.lower().replace("_", "-")
    clean_pid = product_id.lower().replace("_", "-")
    resolved_pid = project_id or clean_pid
    wif_default = (
        f"projects/{project_number}/locations/global/workloadIdentityPools/castor-gh-pool/providers/github-provider"
        if project_number
        else f"projects/{resolved_pid}/locations/global/workloadIdentityPools/castor-gh-pool/providers/github-provider"
    )
    sa_default = f"sa-gh-deployer@{resolved_pid}.iam.gserviceaccount.com"
    workload_sa_default = f"{workload_sa_account_id(clean_pid)}@{resolved_pid}.iam.gserviceaccount.com"

    setup_gcloud_step = """      - name: Set up Cloud SDK
        if: steps.auth.outcome == 'success'
        uses: google-github-actions/setup-gcloud@v2"""

    # Archetype-specific deployment step
    if archetype == "gce-bastion":
        # FD-4AT-b (owner 10-20): CI never applies Terraform. The repo has no state backend (tf-applier writes it into
        # its own workspace), and the least-privilege CI deployer holds no infrastructure roles. Logged no-op, exit 0.
        deploy_step = """      - name: Deploy Infrastructure via Terraform
        if: steps.auth.outcome == 'success'
        run: |
          echo "Infrastructure is applied by the platform's tf-applier, which owns the Terraform state. Nothing to apply from CI."
          exit 0"""
        workflow_title = f"Deploy {clean_svc} (GCE Bastion)"
    elif archetype == "event-worker":
        deploy_step = f"""      - name: Deploy Cloud Run Job Worker
        if: steps.auth.outcome == 'success'
        run: |
          gcloud run jobs deploy ${{SERVICE_NAME}} \\
            --source "apps/${{APP_NAME}}" \\
            --region ${{REGION}} \\
            --service-account "${{GCP_WORKLOAD_SA}}" \\
            --update-env-vars=PROJECT_ID=${{PROJECT_ID}},GCP_PROJECT_ID=${{PROJECT_ID}}"""
        workflow_title = f"Deploy {clean_svc} Event Worker"
    elif archetype == "gke-autopilot":
        setup_gcloud_step += """
        with:
          install_components: 'gke-gcloud-auth-plugin'"""
        deploy_step = f"""      - name: Deploy to GKE Autopilot Cluster
        if: steps.auth.outcome == 'success'
        run: |
          if ! gcloud container clusters describe gke-{clean_pid} --region ${{REGION}} >/dev/null 2>&1; then
            echo "GKE Autopilot cluster 'gke-{clean_pid}' is still being provisioned by OpenTofu. Skipping workflow run until cluster is ready."
            exit 0
          fi
          gcloud container clusters get-credentials gke-{clean_pid} --region ${{REGION}}
          if [ -d "k8s" ]; then kubectl apply -f k8s/; fi"""
        workflow_title = f"Deploy {clean_svc} to GKE Autopilot"
    else:
        # Default: Cloud Run
        # GHA-FIREBASE-ENV-NO-BLANK (owner 11-13): the deploy sets only the project id pair. FIREBASE_API_KEY /
        # FIREBASE_AUTH_DOMAIN are written by Terraform alone (compute-cloudrun env, from the terraform server's web
        # key and auth domain for a PUBLIC_APP); no platform step creates GitHub secrets for them, so naming them here
        # overwrote Terraform's values with "" on every CI deploy. --update-env-vars merges, so they are kept.
        auth_flag = "--allow-unauthenticated" if allow_unauthenticated else "--no-allow-unauthenticated"
        deploy_step = f"""      - name: Build and Deploy to Cloud Run
        if: steps.auth.outcome == 'success'
        run: |
          gcloud run deploy ${{SERVICE_NAME}} \\
            --source "apps/${{APP_NAME}}" \\
            --region ${{REGION}} \\
            --platform managed \\
            {auth_flag} \\
            --memory "${{MEMORY_LIMIT}}" \\
            --cpu "${{CPU_LIMIT}}" \\
            --min-instances {min_instances} \\
            --max-instances {max_instances} \\
            --service-account "${{GCP_WORKLOAD_SA}}" \\
            --update-env-vars=PROJECT_ID=${{PROJECT_ID}},GCP_PROJECT_ID=${{PROJECT_ID}}"""
        workflow_title = f"Deploy {clean_svc} to Cloud Run"

    wf_raw = f"""name: {workflow_title}

on:
  push:
    branches:
      - {branch_yaml}
    paths:
      - 'apps/{clean_svc}/**'
      - '.github/workflows/deploy-{clean_svc}.yml'
  workflow_dispatch:

env:
  PROJECT_ID: ${{{{ {pid_first}vars.GCP_PROJECT_ID || secrets.GCP_PROJECT_ID || '{resolved_pid}' }}}}
  SERVICE_NAME: {clean_svc}
  APP_NAME: {clean_svc}
  REGION: {region_val}
  MEMORY_LIMIT: {memory_limit}
  CPU_LIMIT: {cpu_limit}
  GCP_WORKLOAD_SA: "${{{{ secrets.GCP_WORKLOAD_SA || secrets.GCP_WORKLOAD_SA_EMAIL || '{workload_sa_default}' }}}}"

jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write

    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Authenticate to Google Cloud
        id: auth
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: "${{{{ {wif_first}secrets.WIF_PROVIDER || secrets.GCP_WIF_PROVIDER || (vars.GCP_PROJECT_NUMBER != '' && format('projects/{{0}}/locations/global/workloadIdentityPools/castor-gh-pool/providers/github-provider', vars.GCP_PROJECT_NUMBER)) || '{wif_default}' }}}}"
          service_account: "${{{{ {sa_first}secrets.WIF_SERVICE_ACCOUNT || secrets.GCP_DEPLOYER_SA || (vars.GCP_PROJECT_ID != '' && format('sa-gh-deployer@{{0}}.iam.gserviceaccount.com', vars.GCP_PROJECT_ID)) || '{sa_default}' }}}}"

{setup_gcloud_step}

      - name: Sanitize workspace package shadows
        if: steps.auth.outcome == 'success'
        run: |
          python3 -c "
          import os, glob
          for py_file in glob.glob('apps/{clean_svc}/**/*.py', recursive=True):
              if not py_file.endswith('__init__.py') and os.path.isfile(py_file):
                  stem = py_file[:-3]
                  if os.path.isdir(stem) and any(f.endswith('.py') for f in os.listdir(stem)):
                      os.remove(py_file)
          " || true

{deploy_step}
"""
    return wf_raw


class _VendoringRecorder(dict):
    """A dict that records every key written into it (FD-4AB: provenance of platform-vendored files)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.written: Set[str] = set()

    def __setitem__(self, key, value):
        self.written.add(key)
        super().__setitem__(key, value)

    def update(self, *args, **kwargs):
        for key, value in dict(*args, **kwargs).items():
            self[key] = value

    def setdefault(self, key, default=None):
        if key not in self:
            self[key] = default
        return self[key]


def vendor_platform_files(files: Dict[str, str], archetype: str,
                          intent_modules: Any = ()) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Run vendor_terraform_modules and return (files, platform_files).

    platform_files is the exact {path: content} the platform vendored in this run (golden modules, composite bundles).
    Those files are platform-owned: post-generation healers must never change them (FD-4AB). Keys are validated.
    TI-3: `intent_modules` = the golden modules a gate-clean typed intent instantiates (exact ids); () = unchanged.
    """
    recorder = _VendoringRecorder(files)
    vendor_terraform_modules(recorder, archetype,
                             **({"intent_modules": tuple(intent_modules)} if intent_modules else {}))
    vendored = dict(recorder)
    platform_files = {validate_relpath(k): vendored[k] for k in sorted(recorder.written)}
    return vendored, platform_files


def refuse_public_registered_modules(platform_files: Mapping[str, str], files: Mapping[str, str],
                                     existing_files: Optional[Mapping[str, str]] = None) -> None:
    """FD-4CX: raise DeveloperStageError(REGISTERED_MODULE_PUBLIC_EXPOSURE) for a private workload when
    1. a registered (non-golden) module the platform vendored in this run grants public access by itself
       (shared/module_exposure.py; parsed, no text search), or
    2. (RT F1) the tree calls a non-golden local module that has no files in this run's tree (`files`: the catalog
       read in vendoring failed, or the module was removed from Settings) while the workload repository
       (`existing_files`) still holds files for it: the deploy would reuse those older files unchecked.

    Registered modules are exactly the `infra/modules/<id>/` directories in `platform_files` (what this run's
    vendoring wrote: vendor_terraform_modules step 4 reads them from `custom_modules`) whose id is not a golden module
    (get_canonical_module_files). Golden modules are never inspected; the AI's own files are not platform files (V2a
    judges them). Module calls come from the parser (referenced_local_dirs, exact ids; calls inside infra/modules/
    are not read). A called id with no files anywhere is left to V2j (POLICY.MODULE_SOURCE_NOT_LOCAL, repairable):
    nothing could deploy it. The caller runs this only for a private workload."""
    prefix = "infra/modules/"
    golden = {p[len(prefix):].split("/")[0] for p in get_canonical_module_files() if p.startswith(prefix)}
    invoked = referenced_local_dirs(files, "modules", skip_prefixes=(prefix,)) - golden
    missing = invoked - set(modules_under(files, invoked))
    stale = sorted(set(modules_under(existing_files or {}, missing)))
    if stale:
        raise DeveloperStageError(
            REGISTERED_MODULE_PUBLIC_EXPOSURE,
            f"this private workload calls module(s) {stale} whose files were not read from Settings > Modules in "
            f"this run (catalog unreadable or module removed) while the workload repository still holds older files "
            f"for them, so they cannot be checked for public access; nothing is committed.")
    vendored = {p[len(prefix):].split("/")[0] for p in platform_files if p.startswith(prefix)}
    for mod_id, mod_files in modules_under(platform_files, vendored - golden).items():
        try:
            check_registered_module(mod_id, mod_files)
        except RegisteredModulePublicExposureError as e:
            raise DeveloperStageError(REGISTERED_MODULE_PUBLIC_EXPOSURE,
                                      f"{e.detail} This workload is private, so it cannot use '{mod_id}' until the "
                                      f"module is fixed (Settings > Modules).") from e


def restore_platform_files(files: Dict[str, str], platform_files: Dict[str, str]) -> Dict[str, str]:
    """Single exit choke point (FD-4AB): reset every vendored file to its vendored content; log any healer drift."""
    drifted = sorted(k for k, v in platform_files.items() if files.get(k) != v)
    if drifted:
        logger.warning(f"Post-generation healers changed platform-owned files {drifted}; restored vendored content.")
    restored = dict(files)
    restored.update(platform_files)
    return restored


def deploy_platform_values(product_id: str, region: Any, target_project_id: Any) -> Dict[str, str]:
    """FD-55 W4 (V2k): the values the deploy writes for the platform's root variables (terraform MCP
    deploy_workload `platform_tfvars`: product_id = product_id.lower().replace("_", "-"), region = the platform region
    both stages resolve (FD-4AL), project_id = the vended project). An unknown value is left out (never guessed)."""
    out = {"product_id": str(product_id).lower().replace("_", "-")} if product_id else {}
    if isinstance(region, str) and region:
        out["region"] = region
    if isinstance(target_project_id, str) and target_project_id:
        out["project_id"] = target_project_id
    return out


# FD-4P: what the provider's PR-creation call reported about the PR it created (API response fields only). The
# gateway writes the PR ledger entry from these and refuses one whose head is not the workload repository.
PR_IDENTITY_KEYS = ("pr_number", "pull_request_url", "head_ref", "head_sha", "head_repo_full_name", "head_repo_id",
                    "base_ref", "base_repo_full_name", "base_repo_id")


def _pr_identity_from_pull(pr: Any) -> Dict[str, Any]:
    """RT F3: the same PR_IDENTITY_KEYS read from a PyGithub PullRequest (the handler's fallback paths)."""
    head, base = getattr(pr, "head", None), getattr(pr, "base", None)
    head_repo, base_repo = getattr(head, "repo", None), getattr(base, "repo", None)
    return {"pr_number": getattr(pr, "number", None), "pull_request_url": getattr(pr, "html_url", None),
            "head_ref": getattr(head, "ref", None), "head_sha": getattr(head, "sha", None),
            "head_repo_full_name": getattr(head_repo, "full_name", None), "head_repo_id": getattr(head_repo, "id", None),
            "base_ref": getattr(base, "ref", None), "base_repo_full_name": getattr(base_repo, "full_name", None),
            "base_repo_id": getattr(base_repo, "id", None)}


def _created_pr_number(value: Any) -> Optional[int]:
    """Code RT F1: the PR number exactly as the provider's PR-creation call returned it (a positive int), else None.
    Never parsed from a URL and never defaulted (the CC refuses to merge a GitHub approval without it)."""
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value



@dataclass(frozen=True)
class AssemblyInputs:
    """Everything the post-draft assembly reads besides the draft itself (resolved once per developer dispatch)."""
    product_id: Any
    spec_text: Any
    trace_id: Any
    task_dag: Any
    plan_markdown: Any
    plan_file_path: Any
    domain_restricted_sharing: Any
    allowed_domains: Any
    allow_unauthenticated: Any
    enable_direct_iap: Any
    target_compute_services: Any
    compute_intent: Any            # compute_intent.ComputeIntent (HD-01/HD-02 replacement)
    existing_files: Any
    prior_llm: Any
    llm_draft_paths: Any
    swarm_attribution: Any
    target_project_id: Any
    project_number: Any
    workload_vcs: Any
    stored_repo: Any
    auth_invokers: Any
    # lane 11 near-term: the workload's IPAM network facts (platform_facts.NetworkFacts) or None. None renders
    # byte-identically to before (no fact variables, no fact tfvars).
    network_facts: Any = None
    # lane 14 PR-0b: compliance_profile.RegulatedControls for a regulated stored profile, None for STANDARD (renders
    # byte-identically to before).
    regulated: Any = None
    # FD-4AL: the workload region resolved once per dispatch (resolve_workload_region). None (direct callers) renders
    # the settings schema default.
    region: Any = None
    # FD-4AF-r: True only on the step-1 repair-loop path (_run_hallucination_stack), where the blocking validator
    # V-K8S-PH reports an unknown k8s manifest placeholder as a repairable finding. False (legacy path): it raises.
    defer_k8s_unresolved: bool = False
    # TI-3: the dispatch's iac_intent_contract.IntentRun on the typed-intent path; None (mode "off") assembles
    # byte-identically to before.
    iac_intent: Any = None
    # FD-4CI-b: platform_compute.PlatformComputeDefaults (Enforce Scale-to-Zero, Default Container Memory / vCPU)
    # resolved once per dispatch; None (direct callers) or the defaults assemble byte-identically to before.
    compute_defaults: Any = None
    # FD-4AQ W4 (register AQ-4): the run's access_resolution.ResolvedAccess for the step-1 validator V2l (read only by
    # the validator; the assembly never reads it). None = V2l's mode-independent check only.
    run_access: Any = None
    # FD-4CI-b-R1: the branch the generated deploy workflows trigger on (workflow_branch of the workload's recorded
    # default_branch). "main" (direct callers, workloads without a recorded branch) renders byte-identically to before.
    deploy_branch: str = "main"
    # FD-4CI-b-R1-WIF-SHARED: the workload shares its GitHub repository with another workload
    # (DeveloperAgent._deploy_secrets_branch_named); its workflows on a non-main branch read the branch-named deploy
    # secrets first. False (direct callers, main, a workload on its own repository) renders byte-identically to before.
    deploy_secrets_branch_named: bool = False
    # GHA-DEPLOY-SWITCH: the workload's GitHub Actions deploy switch (workloads/{pid}.github_actions_deploy, missing =
    # on). True (direct callers, every workload before the switch) assembles byte-identically to before. False on a
    # GitHub workload: no deploy workflows, the existing ones are deleted by the commit, and the foundation is
    # rendered without the WIF pool / provider / deployer. Serverless Git ignores it.
    github_actions_deploy: bool = True
    # DIRECT-IAP-SKILL-VERIFY: the dispatch's Direct IAP app rule (generate_code_files resolves it once), for the repair
    # prompts. "" (direct callers, every workload without a Direct IAP Cloud Run service) = byte-identical prompts.
    app_auth_rule: str = ""
    # APP-ADMIN-IAP-CONTRACT (owner 11-16): the app administrators the render declares (`variable "app_admin_emails"`
    # and STACKVEND_APP_ADMIN_EMAILS on every platform Cloud Run module), set exactly when app_auth_rule is (same gate:
    # a Direct IAP Cloud Run workload); the run's ResolvedAccess.effective_app_admin_emails. None (direct callers,
    # every other workload) = byte-identical renders.
    app_admin_emails: Optional[Tuple[str, ...]] = None
    # SLOW-CALL-FALLBACK (owner 11-13): the stage deadline of the repair calls (absolute time.monotonic(); None = no
    # stage bound, each call keeps its per-call cap). Set by generate_code_files(deadline=...).
    llm_deadline: Optional[float] = None
    # RT F5: the active stage deadline's stop (G7 `stage_deadline.current().exceeded`); None = LlmStageBudgetExhausted
    llm_stage_stop: Any = None


class DeveloperAgent:
    # DEFAULT-MODEL-GEMINI-4-CARBON (owner 11-11): the model this agent leads with. An explicit model (constructor
    # argument or assignment) wins; otherwise the settings model of the developer role (models.developer_model, read
    # through the cached platform settings at each use, so a Settings change applies without a restart). The
    # GEMINI_MODEL env no longer outranks the settings: it used to be put first in every cascade it was not part of.
    @property
    def model_name(self) -> str:
        explicit = getattr(self, "_explicit_model_name", None)
        if explicit:
            return explicit
        cascade = get_model_cascade_for_agent("developer", project_id=getattr(self, "project_id", None) or None)
        return cascade[0]

    @model_name.setter
    def model_name(self, value: Optional[str]) -> None:
        self._explicit_model_name = value or None

    def __init__(
        self,
        project_id: Optional[str] = None,
        location: Optional[str] = None,
        model_name: Optional[str] = None,
        github_owner: Optional[str] = None,
    ):
        self.project_id = project_id or os.getenv("PROJECT_ID") or os.getenv("GOOGLE_CLOUD_PROJECT") or ""
        self.location = location or os.getenv("GEMINI_LOCATION") or os.getenv("VERTEX_LOCATION", "global")
        self.model_name = model_name   # None: the settings developer model (the model_name property)
        self.github_owner = github_owner or get_default_github_owner()
        self.genai_client = None
        self.db = None
        # Step 1: per-trace records (AssemblyRecord, LLM IaC paths, personas) for commit-time consumers; the
        # instance serves concurrent requests, so records are keyed by trace id, never kept as bare attributes.
        self._stack_runs: Dict[str, Dict[str, Any]] = {}
        self._stack_last_trace: Optional[str] = None
        if self.project_id:
            try:
                from google.cloud import firestore
                self.db = firestore.Client(project=self.project_id)
            except Exception as e:
                logger.debug(f"Could not initialize firestore Client on DeveloperAgent: {e}")

        try:
            from google import genai
            gemini_api_key = os.getenv("GEMINI_API_KEY")
            if gemini_api_key:
                self.genai_client = genai.Client(api_key=gemini_api_key)
            elif self.project_id:
                self.genai_client = genai.Client(vertexai=True, project=self.project_id, location=self.location)
                # RT F3: no settings read at construction (the gateway builds this agent at import)
                logger.info("Initialized google-genai Vertex AI for Developer Agent (model: "
                            f"'{getattr(self, '_explicit_model_name', None) or 'settings developer_model'}')")
        except Exception as e:
            logger.warning(f"Could not initialize google-genai Client: {e}")

    # ------------------------------------------------------------------------------------- Step 1 run records
    _STACK_RUNS_MAX = 64

    def _record_stack(self, trace_id: Optional[str], **fields: Any) -> None:
        key = trace_id or "_no_trace"
        runs = self.__dict__.setdefault("_stack_runs", {})
        runs.setdefault(key, {}).update(fields)
        self._stack_last_trace = key
        while len(runs) > self._STACK_RUNS_MAX:
            runs.pop(next(iter(runs)))

    def stack_run(self, trace_id: Optional[str]) -> Dict[str, Any]:
        return dict(self.__dict__.get("_stack_runs", {}).get(trace_id or "_no_trace", {}))

    def stack_runtime(self) -> Any:
        """The hallucination-stack runtime this agent uses: the one gateway startup attached to this instance
        (main.py), else the process runtime (eval harness child: configure_for_harness), else unconfigured."""
        return self.__dict__.get("_stack_runtime_override") or get_runtime()

    def attach_stack_runtime(self, runtime: Any) -> None:
        self.__dict__["_stack_runtime_override"] = runtime

    # ------------------------------------------------------------------------- Step 1 IaC provenance (I-20)
    @staticmethod
    def _sha256(text: str) -> str:
        import hashlib
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

    def _load_prior_llm(self, product_id: str, existing_files: Dict[str, str]) -> Dict[str, str]:
        """{path: persona} of repository IaC files a previous run's LLM wrote, recognized by exact path + sha256
        (ProvenanceStore). A file with no record or a changed sha256 (a person edited it) is not listed: it is the
        user's (never repaired, never deleted). A store that cannot be read stops the stage before any LLM call."""
        store = self.stack_runtime().provenance_store
        if store is None or not existing_files:
            return {}
        try:
            entries = store.load(product_id)
        except StoreUnavailable as e:
            report = ValidationReport(status="UNAVAILABLE", source="precommit", artifact_hash="",
                                      tools_unavailable=["provenance_store"])
            raise StageError(report, f"IaC provenance store unavailable: {e}") from e
        # PROVENANCE-HISTORY (IaC part): every version of the path the platform committed on any branch, not only the
        # last write (which may be an unmerged branch's); no history (no store, unreadable): the single-sha check
        history = self._load_iac_history(product_id)
        prior: Dict[str, str] = {}
        for path in set(entries or {}) | set(history):
            content = existing_files.get(path)
            if not isinstance(content, str):
                continue
            entry = (entries or {}).get(path)
            sha = self._sha256(content)
            if (entry is not None and sha == entry.sha256) or sha in history.get(path, ()):
                prior[path] = entry.persona if entry is not None else "iac_worker"
        return prior

    def _load_iac_history(self, product_id: str) -> Dict[str, List[str]]:
        """workloads/{product_id}.iac_provenance_history (app_provenance.IAC_HISTORY_FIELD); {} without a store or
        on a read failure (logged: the prior-LLM check is then the single-sha check, the safe direction)."""
        store = getattr(self.stack_runtime(), "app_provenance_store", None)
        loader = getattr(store, "load_iac_history", None)
        if not callable(loader):
            return {}
        try:
            return loader(product_id)
        except app_provenance.AppProvenanceUnavailable as e:
            logger.warning(f"IaC provenance history unreadable for '{product_id}' ({e}); only the last recorded "
                           f"version of each AI IaC file is recognized in this run")
            return {}

    def _write_iac_history(self, product_id: str, entries: Mapping[str, Any]) -> None:
        """PROVENANCE-HISTORY (IaC part): append the versions this commit recorded in iac_provenance to the
        append-only history (re-read right before the write). Never fails the commit; an unreadable stored history is
        never rewritten, and a history over APP_PROVENANCE_SHAS_MAX versions is not written (logged)."""
        store = getattr(self.stack_runtime(), "app_provenance_store", None)
        if not callable(getattr(store, "load_iac_history", None)) or not entries:
            return
        try:
            stored = store.load_iac_history(product_id)
            history = app_provenance.iac_history_after_commit(stored, {p: e.sha256 for p, e in entries.items()})
            versions = sum(len(h) for h in history.values())
            if versions > app_provenance.APP_PROVENANCE_SHAS_MAX:
                logger.error(f"IAC_PROVENANCE_HISTORY_NOT_RECORDED for '{product_id}': {versions} versions, more "
                             f"than {app_provenance.APP_PROVENANCE_SHAS_MAX}; the stored history is kept")
                return
            store.save_iac_history(product_id, history)
        except app_provenance.AppProvenanceUnavailable as e:
            logger.error(f"IAC_PROVENANCE_HISTORY_NOT_RECORDED for '{product_id}' ({e})")

    def _write_iac_provenance(self, product_id: str, trace_id: Optional[str], files: Dict[str, str]) -> None:
        """After a successful commit: record {path: persona, trace, sha256} for every LLM-authored root IaC file of
        this run (and carry forward the prior LLM files still committed unchanged). A write failure is logged and
        leaves those files unrecorded, i.e. user-owned on the next run (the safe direction: never repaired/deleted)."""
        store = self.stack_runtime().provenance_store
        run = self.stack_run(trace_id)
        if store is None or not run:
            return
        attribution = run.get("attribution") or {}
        entries: Dict[str, Any] = {}
        for path in run.get("llm_iac_paths") or []:
            if isinstance(files.get(path), str):
                entries[path] = ProvenanceEntry(persona=attribution.get(path) or "iac_worker",
                                                trace_id=trace_id or "", sha256=self._sha256(files[path]))
        for path, persona in (run.get("prior_llm") or {}).items():
            if path not in entries and isinstance(files.get(path), str):
                entries[path] = ProvenanceEntry(persona=persona, trace_id=trace_id or "",
                                                sha256=self._sha256(files[path]))
        try:
            store.save(product_id, entries)
            self._record_stack(trace_id, provenance_written=sorted(entries))
            self._write_iac_history(product_id, entries)   # PROVENANCE-HISTORY (IaC part)
        except StoreUnavailable as e:
            logger.error(f"IaC provenance not recorded for '{product_id}' ({e}); its LLM IaC files will be treated "
                         f"as user-owned on the next run")

    # ------------------------------------------------------------------- SAT-49 F4 app provenance / orphan files
    def _load_app_provenance(self, product_id: str, trace_id: Optional[str], stack_on: bool,
                             tree_complete: bool) -> None:
        """Before any LLM call: the workload's app provenance record into this dispatch's run record (always reset,
        so an earlier dispatch of the trace on this instance never leaks in). No store or no stack -> OFF; an
        unreadable record -> APP_PROVENANCE_UNAVAILABLE (nothing is removed by this run; logged and persisted)."""
        store = getattr(self.stack_runtime(), "app_provenance_store", None)
        status, prior, error = app_provenance.STATUS_OFF, None, None
        if store is not None and stack_on:
            try:
                prior = store.load(product_id)
                status = app_provenance.STATUS_CHECKED if prior else app_provenance.STATUS_NO_RECORD
            except app_provenance.AppProvenanceUnavailable as e:
                status, error = app_provenance.STATUS_UNAVAILABLE, str(e)[:300]
                logger.error(f"APP_PROVENANCE_UNAVAILABLE for '{product_id}' ({e}): this run removes no earlier "
                             f"build's files")
        self._record_stack(trace_id, app_provenance_prior=prior, app_orphan_deletions=[], app_orphan_carry={},
                           app_orphans={"status": status, "error": error}, app_tree_complete=tree_complete is True)

    def _decide_app_orphans(self, inputs: "AssemblyInputs", tree: Dict[str, str]) -> None:
        """After the stack validated `tree`: the earlier build's unchanged orphan files this commit deletes
        (app_provenance.find_orphans), recorded for the gateway (stack_run.app_orphan_deletions) and persisted."""
        run = self.stack_run(inputs.trace_id)
        prior = run.get("app_provenance_prior")
        state = run.get("app_orphans") or {}
        if not prior:
            decision = {"status": state.get("status") or app_provenance.STATUS_OFF, "deleted": [], "kept": {},
                        "carry": {}, "blocked_by": None, "error": state.get("error")}
        else:
            decision = app_provenance.find_orphans(prior, inputs.existing_files or {}, tree,
                                                   tree_complete=run.get("app_tree_complete") is True)
            decision["error"] = None
        if prior and run.get("app_full_build") is not True:   # INCREMENTAL-CHANGE-NO-ORPHAN-DELETE (owner 11-14)
            decision = app_provenance.incremental_decision(decision)
        carried = [p for p in (run.get("app_carried_deletions") or []) if isinstance(p, str)]
        if carried:   # QA-REPAIR-KEEPS-ORPHAN-DELETIONS
            decision = self._carry_orphan_deletions(inputs, tree, prior or {}, decision, carried)
        record = app_provenance.summary(decision)
        # PROVENANCE-HISTORY: the start tree's version of each recorded path, which the per-path bound never evicts
        pins = app_provenance.start_tree_pins(prior or {}, inputs.existing_files or {})
        base_pins = pins if run.get("app_start_is_default_branch") is True else {}
        self._record_stack(inputs.trace_id, app_orphan_deletions=list(decision["deleted"]),
                           app_orphan_carry=dict(decision["carry"]), app_orphans=record, app_provenance_pins=pins,
                           app_provenance_base_pins=base_pins)
        if record["status"] == app_provenance.STATUS_OFF:
            return
        logger.info(f"APP_ORPHANS for '{inputs.product_id}': {record['status']}, delete {record['deleted']}, "
                    f"keep {record['kept_count']}")
        db = getattr(self, "db", None)
        if db is None or not inputs.trace_id:
            return
        try:
            db.collection("pipeline_executions").document(inputs.trace_id).set(
                {"stages": {"developer": {"app_orphans": record}}}, merge=True)
        except Exception as pe:  # noqa: BLE001 - telemetry only: never changes the stage outcome
            logger.warning(f"Could not persist the orphan file decision for {inputs.trace_id}: {type(pe).__name__}")

    def _carry_orphan_deletions(self, inputs: "AssemblyInputs", tree: Dict[str, str], record: Mapping[str, Any],
                                decision: Dict[str, Any], carried: List[str]) -> Dict[str, Any]:
        """QA-REPAIR-KEEPS-ORPHAN-DELETIONS (PROVENANCE-HISTORY note, owner 11-13): the orphan deletions of the commit
        this QA repair starts from (recorded with that exact commit, forwarded with QA's feedback) are deleted again
        in this commit, which branches from the default branch. Never re-derived from the tested tree: each carried
        path is kept only when the default branch (read now, completely) still holds it with bytes that are one of
        its recorded platform versions (app_provenance.platform_written) and this repair's tree does not write it.
        Anything else is dropped (logged): a person's change on the default branch since, an unreadable branch."""
        try:
            base = self.fetch_existing_repo_files(inputs.product_id) or {}
            status = getattr(self, "last_tree_status", None)
        except Exception as e:  # noqa: BLE001 - no evidence: nothing is carried (kept, never a wrong deletion)
            logger.warning(f"APP_ORPHANS for '{inputs.product_id}': carried deletions not used (default branch "
                           f"unreadable: {type(e).__name__})")
            return dict(decision, carried=[], carried_dropped=sorted(carried))
        complete = isinstance(status, dict) and status.get("complete") is True
        keep = sorted({p for p in carried if complete and p not in tree and app_provenance.is_app_path(p)
                       and app_provenance.platform_written(record.get(p), base.get(p))})
        dropped = sorted(set(carried) - set(keep))
        if dropped:
            logger.warning(f"APP_ORPHANS for '{inputs.product_id}': carried deletions not repeated (not provably "
                           f"the platform's on the default branch, or written by this repair): {dropped}")
        return dict(decision, deleted=sorted(set(decision.get("deleted") or []) | set(keep)), carried=keep,
                    carried_dropped=dropped)

    def _write_app_provenance(self, product_id: str, trace_id: Optional[str], files: Dict[str, str]) -> None:
        """After a successful commit of exactly the tree the stack validated (hash equality): append this run's LLM
        application files' committed versions to the workload's record (app_provenance.record_for_commit;
        PROVENANCE-HISTORY: append-only, every stored entry kept, whatever branch this commit went to). The stored
        record is read again right before the write, so another dispatch's versions written meanwhile survive. Any
        other commit records nothing. Never fails the commit; logged APP_PROVENANCE_NOT_RECORDED (the stored record
        stays exactly as it is, and this commit's versions are not platform-written later: kept) when the stored record
        cannot be read (a write built without it would drop history), the result is over a bound
        (app_provenance.record_too_large), or the write fails."""
        store = getattr(self.stack_runtime(), "app_provenance_store", None)
        run = self.stack_run(trace_id)
        if store is None or not run.get("validated_hash"):
            return
        if artifact_hash({k: v for k, v in files.items() if isinstance(v, str)}) != run["validated_hash"]:
            return
        try:
            stored = store.load(product_id)
        except app_provenance.AppProvenanceUnavailable as e:
            logger.error(f"APP_PROVENANCE_NOT_RECORDED for '{product_id}' ({e}): the stored record could not be read, "
                         f"so it is not rewritten; this commit's files are not recorded")
            return
        llm_paths = run.get("llm_draft_paths") or []
        entries = app_provenance.record_for_commit(llm_paths, files, trace_id or "", stored,
                                                   run.get("app_provenance_pins") or {},
                                                   run.get("app_provenance_base_pins") or {})
        too_large = app_provenance.record_too_large(entries)
        if too_large:
            logger.error(f"APP_PROVENANCE_NOT_RECORDED for '{product_id}': {too_large}; the stored record is kept as "
                         f"it is and this commit's files are not recorded")
            return
        try:
            store.save(product_id, entries)
            self._record_stack(trace_id, app_provenance_written=sorted(
                p for p in set(llm_paths) if app_provenance.is_app_path(p) and isinstance(files.get(p), str)))
        except app_provenance.AppProvenanceUnavailable as e:
            logger.error(f"APP_PROVENANCE_NOT_RECORDED for '{product_id}' ({e}); the next run removes only files "
                         f"that match the earlier record")

    def _last_run_field(self, name: str) -> Any:
        last = self.__dict__.get("_stack_last_trace")
        return self.__dict__.get("_stack_runs", {}).get(last, {}).get(name) if last else None

    @property
    def last_validation_report(self) -> Any:
        return self._last_run_field("validation_report")

    @property
    def last_repair_events(self) -> Any:
        return self._last_run_field("repair_events")

    @property
    def last_envelope_checks(self) -> Any:
        return self._last_run_field("envelope_checks")

    @property
    def last_assembled_tree(self) -> Any:
        """The tree the most recent `_assemble_tree` produced (eval harness, single-run use)."""
        return self._last_run_field("assembled_tree")

    @property
    def last_assembly_record(self) -> Any:
        """The AssemblyRecord of the most recent generate_code_files call (eval harness, single-run use)."""
        last = self.__dict__.get("_stack_last_trace")
        return self.__dict__.get("_stack_runs", {}).get(last, {}).get("assembly_record") if last else None

    def fetch_github_token(self) -> str:
        """Retrieves active GitHub token from cached GitHubTokenManager, environment, or Secret Manager."""
        cached = get_github_token(self.project_id)
        if cached:
            return cached

        static_token = os.getenv("GITHUB_TOKEN") or os.getenv("GITHUB_PAT")
        if static_token:
            return static_token

        try:
            from google.cloud import secretmanager
            client = secretmanager.SecretManagerServiceClient()
            name = f"projects/{self.project_id}/secrets/castor-github-app-private-key/versions/latest"
            resp = client.access_secret_version(request={"name": name})
            payload_str = resp.payload.data.decode("utf-8").strip()

            clean_str = payload_str.replace("“", '"').replace("”", '"').replace("‘", "'").replace("’", "'")
            clean_str = clean_str.replace("—", "-").replace("–", "-")

            # Check for PAT
            pat_match = re.search(r'["\']?(?:pat|personal_access_token|github_token)["\']?\s*:\s*["\']?([a-zA-Z0-9_]+)["\']?', clean_str)
            if pat_match:
                return pat_match.group(1)

            # Otherwise mint JIT token
            app_id_match = re.search(r'["\']?app_id["\']?\s*:\s*["\']?(\d+)["\']?', clean_str)
            inst_id_match = re.search(r'["\']?installation_id["\']?\s*:\s*["\']?(\d+)["\']?', clean_str)
            pem_match = re.search(r'(-----BEGIN [A-Z\s]+PRIVATE KEY-----[\s\S]+?-----END [A-Z\s]+PRIVATE KEY-----)', clean_str)

            if app_id_match and inst_id_match and pem_match:
                app_id = app_id_match.group(1)
                inst_id = inst_id_match.group(1)
                private_key = pem_match.group(1).strip()
                now = int(time.time())
                payload = {"iat": now - 60, "exp": now + 600, "iss": str(app_id)}
                encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256")
                headers = {"Authorization": f"Bearer {encoded_jwt}", "Accept": "application/vnd.github+json"}
                url = f"https://api.github.com/app/installations/{inst_id}/access_tokens"
                with httpx.Client(timeout=15.0) as http_client:
                    r = http_client.post(url, headers=headers)
                    r.raise_for_status()
                    return r.json().get("token", "")
        except Exception as e:
            logger.warning(f"Could not retrieve GitHub token for Developer Agent: {e}")

        return ""

    def get_github_token(self) -> str:
        """Alias for fetch_github_token."""
        return self.fetch_github_token()

    def update_build_step_status(
        self,
        product_id: str,
        trace_id: Optional[str],
        step_id: str,
        status: str,
        output_summary: Optional[str] = None,
    ) -> None:
        """Updates the live execution status of an individual build plan step in Firestore."""
        if not trace_id or not self.project_id:
            return
        try:
            from datetime import datetime, timezone
            from google.cloud import firestore
            db = firestore.Client(project=self.project_id)
            doc_ref = db.collection("build_plans").document(trace_id)
            doc = doc_ref.get()
            if doc.exists:
                plan_data = doc.to_dict() or {}
                steps = plan_data.get("steps", [])
                for s in steps:
                    if s.get("step_id") == step_id:
                        s["status"] = status
                        if output_summary:
                            s["output_summary"] = output_summary
                        if status == "COMPLETED":
                            s["completed_at"] = datetime.now(timezone.utc).isoformat()
                        elif status == "IN_PROGRESS":
                            s["started_at"] = datetime.now(timezone.utc).isoformat()
                doc_ref.set({"steps": steps, "status": "EXECUTING"}, merge=True)
                db.collection("workloads").document(product_id).collection("build_plans").document(trace_id).set({"steps": steps, "status": "EXECUTING"}, merge=True)
        except Exception as e:
            logger.debug(f"Could not update step status in Firestore: {e}")

    @github_retry_with_backoff(max_retries=3, initial_wait=2.0)
    def fetch_existing_repo_files(self, product_id: str) -> Dict[str, str]:
        """Fetches existing source files from the workload's branch to preserve human/prior commits.
        RT SAT-16/34 F2: the branch is the workload's recorded default_branch (FD-4CI-b-R1, the branch its deploy
        workflows and release pull requests use; workflow_branch: a value that is not a plain branch name is main,
        logged); "main" only when none is recorded. RT14-28: an unreadable record is a typed
        WORKLOAD_RECORD_UNREADABLE (was "main", logged). RT14-13 RT F2: returns a BaseTreeRead (a dict of the files)
        carrying the branch read and the start snapshot; nothing is kept on the shared instance."""
        branch = self._recorded_workload_branch(product_id)
        # RT14-13 RT F1: the base head commit, read BEFORE the tree, so the commit's base check compares exact archive
        # bytes at this commit with the current head (the tree read below leaves out `.git*` paths, binaries and files
        # past its cap, and decodes leniently). Read first, it can only be older than the tree, never newer.
        base_sha = self._read_base_head(product_id, branch)
        files = self.fetch_branch_files(product_id=product_id, branch_name=branch)
        # RT14-13: the start-of-build view of the base branch (what this build read), for the commit's base check
        status = getattr(self, "last_tree_status", None)
        snapshot = {"branch": branch, "files": dict(files or {}),
                    "complete": isinstance(status, dict) and status.get("complete") is True}
        if base_sha:
            snapshot["base_sha"] = base_sha
        return BaseTreeRead(files, branch=branch, snapshot=snapshot)

    def _record_base_read(self, trace_id: Optional[str], read: Any) -> None:
        """RT14-28 / RT14-13 (RT F2): records, under this dispatch's trace, the branch its tree was read from (the
        commit refuses another, BASE_BRANCH_CHANGED) and what it read of the base (the commit's base check). A read
        that is not this agent's own (a plain dict: eval replay, a test double) records nothing."""
        if isinstance(read, BaseTreeRead):
            self._record_stack(trace_id, base_branch=read.branch, **{BASE_SNAPSHOT_FIELD: read.snapshot})

    def _read_base_head(self, product_id: str, branch: str) -> Optional[str]:
        """RT14-13 RT F1: the head commit of the base branch at the build's tree read; None when it cannot be read
        (logged; the build start never fails on it, and the commit's base check then uses the tree read's view)."""
        from qa_source import BranchFetchError
        try:
            return self._base_source(product_id).head_sha(branch)
        except BranchFetchError as e:
            logger.warning(f"BASE_HEAD_UNREAD: the head of '{branch}' of '{product_id}' could not be read at the tree "
                           f"read ({type(e).__name__}: {e}); the commit's base check compares with the tree read")
            return None

    def _workload_record(self, product_id: str) -> Optional[Dict[str, Any]]:
        """RT14-28: workloads/{product_id} as a dict; None without a store client (eval harness, tests) or without a
        record. A store error is DeveloperStageError WORKLOAD_RECORD_UNREADABLE: the base branch and VCS provider of
        the workload are then unknown, and nothing is read from or committed to a guessed branch. RT F3: read up to
        WORKLOAD_RECORD_READ_ATTEMPTS times (short waits, each failure logged) before raising."""
        db = getattr(self, "db", None)
        if not db:
            return None
        for attempt in range(1, WORKLOAD_RECORD_READ_ATTEMPTS + 1):
            try:
                snap = db.collection("workloads").document(product_id).get()
                data = snap.to_dict() if getattr(snap, "exists", False) is True else None
                return data if isinstance(data, dict) else None
            except Exception as e:  # noqa: BLE001 - retried, then typed below (never "main" by guess)
                if attempt >= WORKLOAD_RECORD_READ_ATTEMPTS:
                    raise DeveloperStageError(
                        WORKLOAD_RECORD_UNREADABLE,
                        f"workloads/{product_id} unreadable after {attempt} attempts: {type(e).__name__}") from None
                logger.warning(f"workloads/{product_id} read {attempt}/{WORKLOAD_RECORD_READ_ATTEMPTS} failed "
                               f"({type(e).__name__}); retrying")
                time.sleep(WORKLOAD_RECORD_RETRY_WAIT_S * attempt)
        return None   # unreachable: the last failed attempt raises

    def _recorded_workload_branch(self, product_id: str) -> str:
        """workflow_branch(workloads/{product_id}.default_branch); "main" without a store client, a record or a
        recorded branch (the branch every workload used before branches were recorded). RT14-28: an unreadable record
        raises DeveloperStageError WORKLOAD_RECORD_UNREADABLE."""
        data = self._workload_record(product_id)
        recorded = data.get("default_branch") if isinstance(data, dict) else None
        return workflow_branch(recorded if isinstance(recorded, str) else None)

    def _record_qa_repair_base(self, product_id: str, trace_id: Optional[str], feedback: Any) -> None:
        """RT14-13: a QA repair writes the tested tree again, so its base check compares with the base commit the
        tested commit was cut from (`base_head_sha` the commit recorded, forwarded by the gateway only for exactly
        QA's commit). A record without it (written before RT14-13) cannot be checked: logged, nothing recorded."""
        sha = feedback.get(qa_repair.BASE_HEAD_SHA_FIELD) if isinstance(feedback, Mapping) else None
        if not _is_commit_sha(sha):
            logger.warning(f"BASE_SNAPSHOT_UNAVAILABLE: the QA repair of '{product_id}' (trace {trace_id}) has no "
                           "recorded base commit (a commit made before RT14-13); its base branch is not checked")
            return
        self._record_stack(trace_id, **{BASE_SNAPSHOT_FIELD: {"branch": self._recorded_workload_branch(product_id),
                                                              "base_sha": sha}})

    def _base_source(self, product_id: str) -> Any:
        """RT14-13: the commit-bound source backend of the workload (qa_source: GitHub REST or the git server)."""
        from qa_source import backend_for
        return backend_for(self, product_id)

    def _check_base_unmoved(self, product_id: str, trace_id: Optional[str], to_write: Mapping[str, str],
                            to_delete: Sequence[str]) -> Optional[str]:
        """RT14-13 (owner 11-14): never overwrite a person's commit made on the base branch during the build.

        The commit writes this build's files onto a branch cut from the base branch's CURRENT head. A path that changed
        on the base since this build read it (presence or bytes), and that this commit would set to anything other
        than its current content (or delete), would silently revert that change: the commit stops with MainMovedError
        BASE_BRANCH_MOVED naming the paths; nothing is written. Paths this commit does not write keep the base's
        current content (unchanged behaviour). The base the build read is the snapshot recorded for the trace: the
        base head commit at this build's tree read (first build; RT F1: compared by its exact archive, and an
        unmoved head is no change; the tree read's own lossy view is used only when no commit was recorded or the
        commit cannot be archived off GitHub, i.e. the git server, which archives the head only), or the base commit
        a QA repair's tested commit was cut from. No snapshot
        (a direct caller, the IaC upgrade, a tree not read by this agent) -> not checked, None. Returns the base head
        commit the check saw (recorded with the commit). Reading the base fails -> GATE_UNAVAILABLE, never unchecked.
        Exact path and byte comparison only."""
        snap = self.stack_run(trace_id).get(BASE_SNAPSHOT_FIELD) if trace_id else None
        if not isinstance(snap, dict) or not isinstance(snap.get("branch"), str):
            return None
        from qa_source import BranchFetchError, EmptyArchiveError, normalize_archive

        branch = snap["branch"]

        def tree_at(backend: Any, sha: str) -> Dict[str, bytes]:
            got, archive = backend.archive(branch, sha)
            if got != sha:
                raise BranchFetchError(f"archive of '{branch}' is {got}, expected {sha}")
            try:
                return normalize_archive(archive, strip_top_dir=backend.strip_top_dir)
            except EmptyArchiveError:
                return {}

        try:
            backend = self._base_source(product_id)
            now_sha = backend.head_sha(branch)
            now = tree_at(backend, now_sha)
        except BranchFetchError as e:
            raise GateUnavailableError(
                f"the base branch '{branch}' could not be read to check it for changes made during the build: {e}. "
                "Nothing was committed.", reason="BASE_TREE_UNREADABLE", stage="developer",
                details={"product_id": product_id, "branch": branch}) from e
        # RT F1: the start is the recorded base commit (exact archive bytes, like `now`); the tree read's view is only
        # the fallback where that commit's archive cannot be read (the git server archives the head only).
        start: Optional[Dict[str, bytes]] = None
        if "base_sha" in snap:
            if snap["base_sha"] == now_sha:
                return now_sha          # the base has not moved since this build read it / the tested commit was cut
            try:
                start = tree_at(backend, snap["base_sha"])
            except BranchFetchError as e:
                if not isinstance(snap.get("files"), dict):     # a QA repair: no other record of the earlier base
                    raise MainMovedError(
                        f"the base branch '{branch}' moved from {snap['base_sha']} to {now_sha} during the build and "
                        f"the earlier base cannot be read to check what changed ({e}). Nothing was committed; re-run "
                        "the workload.", reason="BASE_BRANCH_MOVED", stage="developer",
                        details={"product_id": product_id, "branch": branch, "base_sha": snap["base_sha"],
                                 "head_sha": now_sha}) from e
                if getattr(backend, "provider", None) == "GITHUB":
                    # GitHub archives any commit, so this is a read failure; the lossy tree view is never compared
                    raise GateUnavailableError(
                        f"the base branch '{branch}' moved from {snap['base_sha']} to {now_sha} during the build and "
                        f"the earlier base could not be read to check what changed: {e}. Nothing was committed.",
                        reason="BASE_TREE_UNREADABLE", stage="developer",
                        details={"product_id": product_id, "branch": branch, "base_sha": snap["base_sha"],
                                 "head_sha": now_sha}) from e
                logger.warning(f"Base '{branch}' of '{product_id}' moved from {snap['base_sha']} to {now_sha}; the "
                               f"earlier commit cannot be archived ({e}); comparing with the build's tree read")
        if start is None:
            start = {p: c.encode("utf-8") for p, c in (snap.get("files") or {}).items() if isinstance(c, str)}
        conflicts = []
        for path in sorted(set(to_write) | set(to_delete)):
            ours = to_write[path].encode("utf-8") if isinstance(to_write.get(path), str) else None
            if start.get(path) != now.get(path) and ours != now.get(path):
                conflicts.append(path)
        if conflicts:
            logger.error(f"BASE_BRANCH_MOVED: '{product_id}' (trace {trace_id}): {len(conflicts)} path(s) changed on "
                         f"'{branch}' during the build would be overwritten: {conflicts[:20]}")
            raise MainMovedError(
                f"{len(conflicts)} file(s) changed on the base branch '{branch}' during the build, and this commit "
                f"would overwrite them: {conflicts[:20]}. Nothing was committed; re-run the workload so the build "
                "starts from the current code.", reason="BASE_BRANCH_MOVED", stage="developer",
                details={"product_id": product_id, "branch": branch, "head_sha": now_sha, "paths": conflicts[:50],
                         "path_count": len(conflicts)})
        if start != now:
            logger.warning(f"Base branch '{branch}' of '{product_id}' changed during the build (head {now_sha}); none "
                           "of the changed paths is written by this commit, so they are kept")
        return now_sha

    def _commit_base(self, product_id: str, trace_id: Optional[str]) -> Tuple[str, Optional[str]]:
        """RT14-28: (base branch, VCS provider name) of a commit, resolved from the workload record with the same rule
        as the tree read (workflow_branch). An unreadable record is WORKLOAD_RECORD_UNREADABLE (was: "main" and the
        default provider, silently). When this dispatch recorded the branch its tree was read from (`base_branch` of
        the trace's stack run) and the record now names another one, the commit stops typed (MAIN_MOVED,
        BASE_BRANCH_CHANGED): a tree read from one branch is never committed against another."""
        data = self._workload_record(product_id)
        recorded = data.get("default_branch") if isinstance(data, dict) else None
        branch = workflow_branch(recorded if isinstance(recorded, str) else None)
        vcs_name = getattr(self, "vcs_provider", None)
        stored_vcs = data.get("vcs_provider") if isinstance(data, dict) else None
        if not vcs_name and isinstance(stored_vcs, str) and stored_vcs:
            vcs_name = stored_vcs
        read_from = self.stack_run(trace_id).get("base_branch") if trace_id else None
        if isinstance(read_from, str) and read_from != branch:
            raise MainMovedError(
                f"the workload's base branch changed from '{read_from}' (the branch this build read) to '{branch}' "
                "during the build. Nothing was committed; re-run the workload.",
                reason="BASE_BRANCH_CHANGED", stage="developer",
                details={"product_id": product_id, "read_from": read_from, "recorded": branch})
        return branch, vcs_name

    @github_retry_with_backoff(max_retries=3, initial_wait=2.0)
    def fetch_branch_files(self, product_id: str, branch_name: str = "main") -> Dict[str, str]:
        """Fetches source files from a specific branch for Gatekeeper/QA audits and incremental context.

        Lane 10 RT F1: `self.last_tree_status` = {"complete", "truncated", "error"} of the returned tree (the
        returned dict is unchanged); the topology path refuses an incomplete tree of a built product."""
        self.last_tree_status = {"complete": False, "truncated": False, "error": "not fetched"}
        full_repo_name = self.get_full_repo_name(product_id)
        vcs_name = getattr(self, "vcs_provider", None)
        if not vcs_name and hasattr(self, "db") and self.db:
            try:
                w_doc = self.db.collection("workloads").document(product_id).get()
                if w_doc.exists:
                    wdata = w_doc.to_dict() or {}
                    vcs_name = wdata.get("vcs_provider")
            except Exception:
                pass
        if not vcs_name and full_repo_name and "serverless-git" in full_repo_name.lower():
            vcs_name = "SERVERLESS_GIT"

        if VCSProviderFactory is not None:
            try:
                vcs = VCSProviderFactory.get_provider(
                    provider_name=vcs_name,
                    default_owner=self.github_owner,
                    project_id=self.project_id,
                    product_id=product_id,
                    full_repo_name=full_repo_name,
                )
                tree_files = vcs.fetch_file_tree(full_repo_name, branch=branch_name)
                status = getattr(vcs, "last_tree_status", None)
                self.last_tree_status = dict(status) if isinstance(status, dict) else None
                if tree_files:
                    return tree_files
            except Exception as e:
                self.last_tree_status = {"complete": False, "truncated": False, "error": f"{type(e).__name__}: {e}"[:300]}
                logger.debug(f"VCSProvider fetch_file_tree notice for branch '{branch_name}' ({e}); trying direct PyGithub.")

        if vcs_name == "SERVERLESS_GIT" or (full_repo_name and "serverless-git" in full_repo_name.lower()):
            return {}

        token = self.fetch_github_token()
        if not token:
            self.last_tree_status = {"complete": False, "truncated": False, "error": "no GitHub token"}
            return {}
        try:
            gh = Github(token)
            repo = gh.get_repo(full_repo_name)
            files: Dict[str, str] = {}
            tree = repo.get_git_tree(branch_name, recursive=True)
            for item in tree.tree:
                if item.type == "blob" and not item.path.startswith(".git"):
                    # Only fetch text/code files
                    if not item.path.endswith((".png", ".jpg", ".jpeg", ".ico", ".tar.gz", ".zip")):
                        blob = repo.get_git_blob(item.sha)
                        import base64
                        decoded = base64.b64decode(blob.content).decode("utf-8", errors="ignore")
                        files[item.path] = decoded
            logger.info(f"Fetched {len(files)} files from branch '{branch_name}' of GitHub repo '{full_repo_name}'.")
            self.last_tree_status = {"complete": getattr(tree, "truncated", False) is not True,
                                     "truncated": getattr(tree, "truncated", False) is True, "error": None}
            return files
        except Exception as e:
            self.last_tree_status = {"complete": False, "truncated": False, "error": f"{type(e).__name__}: {e}"[:300]}
            logger.debug(f"Could not fetch files from branch '{branch_name}' for '{full_repo_name}': {e}")
            return {}

    def _resolve_run_access(self, product_id: str, trace_id: Optional[str], task_dag: Any, access: Any,
                            allow_unauthenticated: Optional[bool], enable_direct_iap: Optional[bool],
                            domain_restricted_sharing: Optional[bool], allowed_domains: Optional[List[str]],
                            ) -> Tuple[ResolvedAccess, bool, List[str]]:
        """Lane 19 L19-2 (FD-4I I7/I9/I11/I12): the run's access facts from typed data only.

        Record first (request ``access``, else ``workloads/{pid}.access``); without a record, the compliance
        decision's typed flags give the mode (the gateway-resolved persisted decision, FD-4R R-6). Spec keywords and
        task-dag contents are never read. ``allowed_domains`` (org-policy values) is passed through for the record but
        never becomes an IAM member."""
        workload_access = None
        w_dict: Any = None   # APP-ADMIN-DEFAULT: the document read below (None = not read: no verified submitter)
        if self.db is not None and product_id:
            # L19-F4 RT R3: the workload document is read whenever a client exists, also when the request carries
            # `access` (a direct caller), so a pending widening flag is always seen. The request record still wins as
            # the source; the stored one is used only without it. No client (eval harness): unchanged.
            try:
                w_doc = self.db.collection("workloads").document(product_id).get()
                w_dict = (w_doc.to_dict() or {}) if getattr(w_doc, "exists", False) else {}
            except Exception as e:  # noqa: BLE001 - cannot tell whether a record / flag exists: refuse (fail closed)
                raise DeveloperStageError(ACCESS_POLICY_UNAVAILABLE,
                                          f"workloads/{product_id} unreadable: {type(e).__name__}") from None
            if isinstance(w_dict, dict) and w_dict.get(ACCESS_WIDENING_APPROVAL_FIELD) is not None:
                # L19-F4: an administrator widened the record and no plan approval has cleared the one-shot flag
                # (this run passed the gate before the PATCH, a resume, or a direct call): never build it.
                raise DeveloperStageError(
                    ACCESS_WIDENING_UNAPPROVED,
                    f"workloads/{product_id}.access was widened and the widening is not approved yet; run a "
                    "full build so the pre-build gate asks for plan approval (ACCESS_WIDENED)")
            if access is None:
                workload_access = w_dict.get("access") if isinstance(w_dict, dict) else None
        elif access is None:
            if runtime_env.on_cloud_run():
                # On Cloud Run the record store must be reachable; never treat "no client" as "no record".
                raise DeveloperStageError(ACCESS_POLICY_UNAVAILABLE, "no Firestore client to read workloads/{pid}.access")

        # Integration with FD-4R R-6 (one source): the compliance flags come only from the persisted decision the
        # gateway resolved (generate_code_files raises COMPLIANCE_DECISION_MISSING before this point when any is not
        # a bool). The developer-side fallbacks FD-4I had for direct callers without flags (the exact
        # STEP-03D-DIRECT-IAP step id, a typed `domain_restricted_sharing` task field, the compliance_audits/{trace}
        # read) are therefore deleted, like R-6's own; a direct caller with no record and no IAP flag is refused.
        if access is None and workload_access is None and not isinstance(enable_direct_iap, bool):
            raise DeveloperStageError(ACCESS_POLICY_REQUIRED,
                                      "no access record and no typed compliance decision (enable_direct_iap)")
        domain_restricted_sharing = domain_restricted_sharing is True

        resolved = resolve_access(access=access, workload_access=workload_access,
                                  allow_unauthenticated=allow_unauthenticated, enable_direct_iap=enable_direct_iap,
                                  domain_restricted_sharing=domain_restricted_sharing,
                                  workload_doc=w_dict)   # APP-ADMIN-DEFAULT: its verified submitter only
        logger.info(f"Access for '{product_id}' (trace {trace_id or '-'}): mode={resolved.mode} "
                    f"source={resolved.source} invokers={len(resolved.invoker_members)}")
        return resolved, domain_restricted_sharing, list(allowed_domains or [])

    def _resolve_compute_intent(self, product_id: str, trace_id: Optional[str],
                                architect_compute_intent: Optional[Dict[str, Any]],
                                existing_files: Optional[Dict[str, str]],
                                target_compute_services: Optional[List[str]]) -> "ComputeIntent":
        """The architect's typed compute record: from the request (workflow / harness), else the record the architect
        persisted on `pipeline_executions/{trace_id}`; then `resolve_compute_intent` (pins existing compute)."""
        record = architect_compute_intent if isinstance(architect_compute_intent, dict) else None
        if record is None and self.db and trace_id:
            try:
                doc = self.db.collection("pipeline_executions").document(trace_id).get()
                if doc.exists:
                    rec = (doc.to_dict() or {}).get("architect_compute_intent")
                    record = rec if isinstance(rec, dict) else None
            except Exception as e:  # noqa: BLE001 - recorded below as a platform-default intent, never silent
                logger.error(f"Architect compute intent for trace '{trace_id}' could not be read: {e}")
        # TI-3i: the plan's typed API list (exact grammar), read only to judge entries a repair dropped
        self._record_stack(trace_id, plan_required_apis=list(intent_contract.plan_required_apis(record)))
        if isinstance(record, dict) and record.get("service_topology") is not None:
            self._refuse_incomplete_tree(product_id, trace_id, existing_files)
        try:
            intent = resolve_compute_intent(product_id, record, existing_files or {}, target_compute_services)
        except TopologyGuardError as tg:
            # Lane 10 (FD-51): the recorded service topology conflicts with the repository's existing compute
            # (BROWNFIELD_CONFLICT -> operator) or is itself inconsistent (PLATFORM_DEFECT). Typed, before any LLM
            # call; never repaired, pinned or merged silently.
            report = ValidationReport(status="FAIL", source="precommit", artifact_hash="", diagnostics=tg.diagnostics)
            self._record_stack(trace_id, validation_report=report)
            raise StageError(report, f"TOPOLOGY_GUARD: {tg}") from tg
        if intent.source == "platform-default":
            if trace_id:
                # RT fix 2 (FH-7): a pipeline trace with neither the architect's record nor existing compute stops
                # here -- typed, before any LLM spend -- instead of building a default Cloud Run service.
                raise StageError(
                    ValidationReport(status="FAIL", source="precommit", artifact_hash="", diagnostics=[Diagnostic(
                        tool="platform", code="PLATFORM.COMPUTE_INTENT_MISSING", severity="error",
                        error_class=ErrorClass.PLATFORM_DEFECT, file="<trace>", source="precommit",
                        message=(f"trace '{trace_id}': no architect compute intent (request body and "
                                 f"pipeline_executions/{trace_id}.architect_compute_intent both empty) and no "
                                 f"existing compute in the repository of '{product_id}'"))]),
                    f"COMPUTE_INTENT_MISSING: trace '{trace_id}' has no architect compute record and '{product_id}' "
                    f"has no existing compute; refusing the platform default")
            logger.warning(f"No architect compute intent and no existing compute for '{product_id}' (no trace): "
                           f"platform default {intent.archetype} {list(intent.service_names)}")
        if intent.conflicts or intent.rejected_names:
            logger.warning(f"Compute intent for '{product_id}': pinned existing compute overrides {list(intent.conflicts)}; "
                           f"rejected service names {list(intent.rejected_names)}")
        self._record_stack(trace_id, compute_intent=intent.as_record())
        if self.db and trace_id:
            # RT fix 2 (FH-8): the compute plan the developer used is visible on the execution record (merge).
            try:
                self.db.collection("pipeline_executions").document(trace_id).set(
                    {"developer_compute_intent": intent.as_record()}, merge=True)
            except Exception as e:  # noqa: BLE001 - best-effort operator visibility; the run uses the typed intent
                logger.error(f"Developer compute intent for trace '{trace_id}' could not be persisted: {e}")
        return intent

    def _refuse_incomplete_tree(self, product_id: str, trace_id: Optional[str],
                                existing_files: Optional[Dict[str, str]]) -> None:
        """Lane 10 RT F1: the brownfield guard sees the repository only through the fetched tree. On a topology run,
        a truncated tree, or a failed / partial fetch of a product that was built before (non-empty partial tree, or
        a committed topology on workloads/{pid}), stops the developer before any LLM call
        (`TOPOLOGY.EXISTING_TREE_UNAVAILABLE`, PLATFORM_DEFECT) instead of reading missing files as "no compute".
        A tree status the provider did not report (None) keeps the previous behavior."""
        status = getattr(self, "last_tree_status", None)
        if not isinstance(status, dict) or status.get("complete") is True:
            return
        built = bool(status.get("truncated")) or bool(existing_files)
        if not built and self.db:
            try:
                doc = self.db.collection("workloads").document(product_id).get()
                built = bool(getattr(doc, "exists", False) and isinstance(doc.to_dict(), dict)
                             and (doc.to_dict() or {}).get("service_topology"))
            except Exception as e:  # noqa: BLE001 - cannot tell: refuse (fail closed on a topology run)
                logger.error(f"workloads/{product_id} unreadable while checking the repository tree: {e}")
                built = True
        if not built:
            return
        why = "truncated" if status.get("truncated") else f"fetch failed ({status.get('error')})"
        report = ValidationReport(status="FAIL", source="precommit", artifact_hash="", diagnostics=[Diagnostic(
            tool="topology", code="TOPOLOGY.EXISTING_TREE_UNAVAILABLE", severity="error",
            error_class=ErrorClass.PLATFORM_DEFECT, file="<repository>", source="precommit",
            message=(f"the repository tree of '{product_id}' is incomplete ({why}); its existing compute cannot be "
                     f"guarded, so the typed topology is not applied"))])
        self._record_stack(trace_id, validation_report=report)
        raise StageError(report, f"TOPOLOGY_GUARD: repository tree of '{product_id}' incomplete ({why})")

    @property
    def last_compute_intent(self) -> Any:
        """The typed compute intent of the most recent generate_code_files call (eval harness, single-run use)."""
        return self._last_run_field("compute_intent")

    def _resolve_regulated_controls(self, product_id: str, compliance_decision: Optional[Dict[str, Any]] = None,
                                    region: Optional[str] = None) -> Any:
        """Lane 14 PR-0b: the regulated-profile controls to render. None for STANDARD / absent. Before any LLM call: a
        profile the platform cannot render IaC for (unknown profile, platform region outside the profile) is a typed
        DeveloperStageError.

        Integration with FD-4R R-6 (Fable RT F3): on the pipeline the gateway passes `compliance_decision`, the SAME
        persisted v2 compliance record it resolved for the developer's ingress (fail closed with 503 when absent), and
        the controls come from it only (`compliance_profile.controls_from_decision_record`; no second read, no
        STANDARD default). Without it (direct callers: eval harness, unit tests) the stored product-keyed decision is
        read with the plan gate's precedence (compliance_profile.py): no Firestore client = STANDARD, as the gate's
        DEFAULT_STANDARD. Owner option Q1 (on): an unreadable document refuses the stage with
        COMPLIANCE_DECISION_UNAVAILABLE.

        `region` (FD-4AL): the workload region the profile's allowed regions are checked against (generate_code_files
        passes the resolved one; None = the settings schema default, for direct callers)."""
        try:
            from . import compliance_profile as cprof
        except ImportError:  # top-level import layout (developer_agent dir on sys.path)
            import compliance_profile as cprof
        region = region or WORKLOAD_REGION_DEFAULT
        if compliance_decision is not None:
            try:
                regulated = cprof.controls_from_decision_record(compliance_decision, region)
            except cprof.ComplianceRenderRefused as refused:
                raise DeveloperStageError(refused.error_class, str(refused)) from refused
            if regulated is not None:
                logger.info(f"Regulated profile {regulated.profile} ({regulated.source}, trace "
                            f"{compliance_decision.get('source_trace_id')}) for '{product_id}': rendering "
                            f"CMEK={regulated.cmek}, data-access audit logging={regulated.audit_logging} "
                            f"(lane 14 PR-0b)")
            return regulated
        doc_data: Any = None
        if self.db:
            try:
                doc = self.db.collection("workloads").document(product_id).get()
                doc_data = doc.to_dict() if getattr(doc, "exists", False) else None
            except Exception as e:  # noqa: BLE001 - the plan gate is the enforcing point (docstring)
                if cprof.FAIL_CLOSED_ON_UNREADABLE_DECISION:   # owner option Q1 (off by default)
                    raise DeveloperStageError(
                        cprof.COMPLIANCE_DECISION_UNAVAILABLE,
                        f"workloads/{product_id} unreadable while resolving the compliance profile: {type(e).__name__}",
                    ) from e
                logger.error(f"COMPLIANCE_DECISION_UNREADABLE: workloads/{product_id} could not be read "
                             f"({type(e).__name__}); rendering the STANDARD profile, the plan gate decides at apply")
        try:
            profile, source = cprof.profile_from_workload_doc(doc_data if isinstance(doc_data, dict) else None)
            regulated = cprof.resolve_regulated_controls(profile, source, region)
        except cprof.ComplianceRenderRefused as refused:
            raise DeveloperStageError(refused.error_class, str(refused)) from refused
        if regulated is not None:
            logger.info(f"Regulated profile {regulated.profile} ({regulated.source}) for '{product_id}': rendering "
                        f"CMEK={regulated.cmek}, data-access audit logging={regulated.audit_logging} (lane 14 PR-0b)")
        return regulated

    # ------------------------------------------------------------------- SLOW-CALL-FALLBACK: who wrote what
    def _record_model_provenance(self, trace_id: Optional[str], outputs: List[Dict[str, Any]]) -> None:
        """The run record of which model wrote each output (llm_transport.model_provenance_record): kept on this
        trace's run record (`stack_run(trace)["model_provenance"]`, read by the gateway's response) and written to
        `pipeline_executions/{trace}.stages.developer.details.model_provenance` (the Control Center's run view).
        Firestore errors are logged; the record stays in memory."""
        record = model_provenance_record(outputs)
        self._record_stack(trace_id, model_provenance=record)
        if not trace_id or not self.db or not record["outputs"]:
            return
        try:
            self.db.collection("pipeline_executions").document(trace_id).set(
                {"stages": {"developer": {"details": {"model_provenance": record}}}}, merge=True)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Could not write the model provenance of {trace_id}: {type(e).__name__}: {e}")

    def _record_repair_model_provenance(self, trace_id: Optional[str], events: List[Any], repair_model: str) -> None:
        """Adds each repair answer (RepairEvent kind "repair": model, model_fallback) to this trace's record."""
        prior = (self.stack_run(trace_id).get("model_provenance") or {}).get("outputs") or []
        repairs = [{"output": f"repair:{getattr(ev, 'persona', '')}#{getattr(ev, 'iteration', '')}",
                    "model": getattr(ev, "model", None), "primary_model": repair_model,
                    "fallback": bool(getattr(ev, "model_fallback", None)),
                    "fallback_reason": getattr(ev, "model_fallback", None)}
                   for ev in events or [] if getattr(ev, "kind", "repair") == "repair" and getattr(ev, "model", None)]
        if repairs:
            self._record_model_provenance(trace_id, [dict(x) for x in prior] + repairs)

    def generate_code_files(
        self,
        product_id: str,
        spec_text: str,
        task_dag: List[Dict[str, Any]],
        trace_id: Optional[str] = None,
        plan_markdown: Optional[str] = None,
        plan_file_path: Optional[str] = None,
        domain_restricted_sharing: Optional[bool] = None,
        allowed_domains: Optional[List[str]] = None,
        allow_unauthenticated: Optional[bool] = None,
        enable_direct_iap: Optional[bool] = None,
        target_compute_services: Optional[List[str]] = None,
        architect_compute_intent: Optional[Dict[str, Any]] = None,
        compliance_decision: Optional[Dict[str, Any]] = None,
        access: Any = None,
        deadline: Optional[float] = None,
        stage_stop: Any = None,
        **kwargs: Any,
    ) -> Dict[str, str]:
        # SLOW-CALL-FALLBACK (owner 11-13): `deadline` = the developer stage's deadline as an absolute time.monotonic()
        # (None = no stage bound); every model call of this dispatch (lead, juniors, single turn, repair) is capped by
        # it (llm_transport.CallWalk). The stage-deadline object itself is built by the caller. RT F5: `stage_stop`
        # (the active stage deadline's `exceeded`) makes "no stage time left" raise the stage's own class
        # (STAGE_DEADLINE_EXCEEDED) instead of LLM_STAGE_BUDGET_EXHAUSTED.
        # RT F3: with no explicit bound, the active STAGE-DEADLINE bounds every model call of this dispatch and its
        # typed stop (STAGE_DEADLINE_EXCEEDED) answers "no stage time left" (RT F5). The walk's clock is time.monotonic.
        deadline, stage_stop = active_stage_bound(deadline, stage_stop, time.monotonic)
        # Lane 19 (owner register row 27a): no LLM -> fail loudly; never a template app or swarm stub files.
        if not self.genai_client:
            raise DeveloperStageError(LLM_UNAVAILABLE, "no LLM client configured for the developer agent")
        # FD-4R R-6 (lane 17 plan R-3/R-6): ingress intent has ONE source, the compliance decision the gateway
        # resolved from the persisted record and passes here. The developer's own fallbacks (task_dag string scan,
        # Firestore-by-trace read, spec keywords, "public unless restricted" default) are deleted; a missing flag
        # stops the stage before any LLM call instead of being guessed.
        missing = [name for name, value in (("allow_unauthenticated", allow_unauthenticated),
                                            ("enable_direct_iap", enable_direct_iap),
                                            ("domain_restricted_sharing", domain_restricted_sharing))
                   if not isinstance(value, bool)]
        if missing:
            raise GateUnavailableError(
                f"developer called without a compliance decision ({', '.join(missing)} not set); ingress is never "
                f"guessed", reason="COMPLIANCE_DECISION_MISSING", stage="developer",
                details={"product_id": product_id, "missing": missing})
        # FD-4AL: the workload region, resolved ONCE for this dispatch, before any LLM call (typed when unset).
        # FD-7M-a: the workload's recorded region (workloads/{pid}.region) through the approved-regions helper; a
        # record without a region follows the platform region exactly as before; not approved -> typed, no LLM call.
        try:
            workload_region = resolve_workload_region(getattr(self, "db", None), product_id=product_id)
        except RegionUnavailable as region_err:
            raise DeveloperStageError(REGION_UNAVAILABLE, str(region_err)) from region_err
        except RegionNotApproved as not_approved:
            raise DeveloperStageError(REGION_NOT_APPROVED, str(not_approved)) from not_approved
        # Lane 14 PR-0b: before any LLM call (a refusal here costs nothing). On the pipeline, from the same compliance
        # record as the ingress flags above (FD-4R R-6 integration).
        regulated = self._resolve_regulated_controls(product_id, compliance_decision, region=workload_region)
        if not task_dag:
            try:
                if self.db and trace_id:
                    pe_doc = self.db.collection("pipeline_executions").document(trace_id).get()
                    if pe_doc.exists:
                        task_dag = (pe_doc.to_dict() or {}).get("task_dag") or []
                if not task_dag and self.db and product_id:
                    fr_docs = self.db.collection("feature_requests").where("product_id", "==", product_id).limit(1).get()
                    for fr in fr_docs:
                        task_dag = (fr.to_dict() or {}).get("task_dag") or []
            except Exception as e:
                logger.debug(f"Could not retrieve task_dag from Firestore: {e}")

        if not target_compute_services:
            if isinstance(task_dag, dict):
                target_compute_services = task_dag.get("target_compute_services") or []
            elif isinstance(task_dag, list):
                for item in task_dag:
                    if isinstance(item, dict) and "target_compute_services" in item:
                        target_compute_services = item["target_compute_services"]
                        break


        # Lane 19 L19-2 (FD-4I): who may reach the workload is resolved from typed data BEFORE any LLM call. A private
        # workload with no principals stops here (ACCESS_POLICY_INCOMPLETE, operator), never widened or guessed.
        run_access, domain_restricted_sharing, allowed_domains = self._resolve_run_access(
            product_id, trace_id, task_dag, access, allow_unauthenticated, enable_direct_iap,
            domain_restricted_sharing, allowed_domains)
        allow_unauthenticated = run_access.allow_unauthenticated
        enable_direct_iap = run_access.enable_direct_iap

        # QA-FEEDBACK: a QA retry whose evidence the gateway matched (qa_feedback); decided before any LLM call. A
        # finding the repair loop cannot own -> today's regeneration (logged); else the tested tree is the repository
        # this dispatch starts from and QA's findings are repaired in place (no regeneration).
        qa_plan = self._plan_qa_repair(product_id, trace_id, kwargs)
        if qa_plan is not None:
            existing_files = dict(qa_plan.tree)
            self.last_tree_status = {"complete": True, "truncated": False, "error": None}   # fetched at the commit
            # RT14-13: the repair's base check compares with the base its tested commit was cut from
            self._record_qa_repair_base(product_id, trace_id, kwargs.get("qa_feedback"))
        else:
            existing_files = self.fetch_existing_repo_files(product_id)
            # RT14-28 / RT14-13 (RT F2): the branch and base this dispatch read, from the read itself, under its trace
            self._record_base_read(trace_id, existing_files)
        # SAT-49 F4 (RT F4): whether THIS fetch read the repository completely, captured now (the agent's
        # last_tree_status is instance state shared by concurrent dispatches); an orphan is removed only after one
        tree_status = getattr(self, "last_tree_status", None)
        repo_tree_complete = isinstance(tree_status, dict) and tree_status.get("complete") is True
        # HD-01/HD-02 replacement (FD-4X, FD-4AC): archetype and service set from typed facts only -- the architect's
        # recorded plan fields and the repository's pinned compute -- never from spec prose. Resolved before any LLM call.
        compute_intent = self._resolve_compute_intent(product_id, trace_id, architect_compute_intent,
                                                      existing_files, target_compute_services)
        # Lane 10: the developer / lead prompt contract (services, code dirs, exact env keys); "" = unchanged prompts
        # MANIFEST-PATH-DEFERS-TO-DAG: a gke service's manifests at the paths the DAG names ({}: k8s/<svc>.yaml)
        manifest_paths = dag_manifest_paths(task_dag, compute_intent.topology)
        wiring_contract = topology_contract_rule(compute_intent.topology, manifest_paths=manifest_paths or None)
        # AC-2: the platform's Cloud Run startup probe path for the lead prompt; "" (no Cloud Run service) = unchanged
        probe_rule = health_probe_rule(cloudrun_probe_services(compute_intent))
        # DIRECT-IAP-SKILL-VERIFY: the one rule value of this dispatch (every prompt and repair); after the compute intent
        # because an existing repository can re-pin the archetype, and only Cloud Run services have Direct IAP
        app_auth_rule = direct_iap_auth_rule(enable_direct_iap, allow_unauthenticated,
                                             cloudrun_probe_services(compute_intent),
                                             non_cloudrun_services(compute_intent))
        # APP-ADMIN-IAP-CONTRACT: the admin list the IaC renders, under exactly the rule's gate (the rule tells the code
        # writers about the env); None = no variable, no env (byte-identical renders)
        app_admin_emails = tuple(run_access.effective_app_admin_emails) if app_auth_rule else None
        self._app_admin_outcome(product_id, trace_id, run_access, app_admin_emails)
        # Step 1 (I-20): the repository IaC files an earlier run's LLM wrote, verified by sha256 (before any LLM call)
        prior_llm = self._load_prior_llm(product_id, existing_files or {})
        # Step 1 S1-B (HS-03/HS-05/HS-06): readiness and budget are checked BEFORE any LLM spend.
        stack_gate = self._hallucination_stack_gate(product_id, trace_id)
        # SAT-49 F4: the earlier builds' app provenance (exact path + sha256), before any LLM call
        self._load_app_provenance(product_id, trace_id, stack_gate is not None, repo_tree_complete)
        # RT R3: only a dispatch that starts from the default branch (not a QA repair's tested tree) records its
        # versions as the paths' `base`, which the history bound never evicts
        self._record_stack(trace_id, app_start_is_default_branch=qa_plan is None)
        # QA-REPAIR-KEEPS-ORPHAN-DELETIONS: a QA repair carries forward the orphan deletions of the commit it repairs
        # (its own commit branches from the default branch again, so without them the deleted files come back)
        self._record_stack(trace_id, app_carried_deletions=list(qa_repair.recorded_paths(
            kwargs.get("qa_feedback"), qa_repair.ORPHAN_DELETIONS_FIELD)) if qa_plan is not None else [])
        # TI-3: the typed IaC intent contract (sticky per workload), resolved before any LLM call; None = mode "off"
        intent_run = self._resolve_intent_run(compute_intent, existing_files, stack_gate)
        if intent_run is not None:   # SECRET-INITIAL-VERSION: the slot lines name this dispatch's generated secrets
            wiring_contract = topology_contract_rule(compute_intent.topology, iac_intent=True,
                                                     generated_secrets=intent_run.generated_secrets,
                                                     manifest_paths=manifest_paths or None)
        # TI-5-R3: the deploy's typed report (terraform remediation dispatch), decided before any LLM call. A legacy
        # workload, no report or an unusable one -> today's path; a platform / user-owned file -> typed stop; a
        # CODE_DEFECT on intent entries -> the repair loop on the committed intent (no regeneration).
        # SAT-49: the released build's own files (main._deploy_repair_draft_paths, exact sha match; absent = none)
        deploy_plan = deploy_repair.plan_deploy_repair(kwargs.get("tf_validation_report"), intent_run=intent_run,
                                                       existing_files=existing_files,
                                                       draft_paths=kwargs.get(deploy_repair.DRAFT_PATHS_KWARG))
        if deploy_plan.reason != "NO_REPORT":
            self._record_stack(trace_id, deploy_repair=deploy_plan.summary())
            logger.warning(f"Deploy validation report for '{product_id}': {deploy_plan.mode} ({deploy_plan.reason})")
        if deploy_plan.mode == deploy_repair.STOP:
            raise deploy_repair.stop_error(deploy_plan, product_id)
        deploy_plan = deploy_plan if deploy_plan.mode == deploy_repair.INTENT_REPAIR else None
        existing_context = ""
        if existing_files:
            existing_context = (
                f"\n\nExisting Repository Files (Current State on main branch):\n"
                f"{json.dumps(existing_files, indent=2)}\n\n"
                f"CRITICAL INSTRUCTION: You must preserve and build upon all existing code, endpoints, models, "
                f"and logic already present in the repository above. Do not revert or overwrite existing features added "
                f"by other developers unless explicitly requested in the specification."
            )

        tf_remediation_context = kwargs.get("tf_remediation_context")
        tf_retry_count = kwargs.get("tf_retry_count", 0)
        remediation_prompt = ""
        if tf_remediation_context:
            detected_arch = compute_intent.archetype
            if detected_arch == "gke-autopilot":
                arch_hint = "Primary GKE Autopilot cluster is in `module.compute` (`module.compute.cluster_name`). Any secondary Cloud Run edge service in custom.tf must declare its own `google_cloud_run_v2_service` resource."
            elif detected_arch == "gce-bastion":
                arch_hint = "Primary Compute Engine bastion is in `module.compute` (`module.compute.bastion_name`)."
            elif detected_arch == "cloudrun":
                arch_hint = "Primary Cloud Run service is in `module.compute` - never reference `google_cloud_run_v2_service.*` as a root resource."
            else:
                arch_hint = "Primary compute archetype is in `module.compute`."

            remediation_prompt = (
                f"\n\nCRITICAL IAC REMEDIATION NOTICE (Attempt {tf_retry_count}):\n"
                f"A previous Terraform validation or deployment attempt failed with the following diagnostics:\n"
                f"{tf_remediation_context}\n\n"
                f"You MUST resolve this error in the generated .tf files. {arch_hint}"
            )

        prompt = (
            f"Product ID: {product_id}\n"
            f"Requirements Specification:\n{spec_text}\n\n"
            f"Architecture Task DAG:\n{json.dumps(task_dag, indent=2)}\n"
            f"{existing_context}\n"
            f"{remediation_prompt}\n\n"
            + (intent_contract.SINGLE_TURN_IAC_LINE if intent_run is not None else   # TI-3
               f"Generate all necessary application files, Procfile, requirements.txt, .python-version, "
               f"cloudbuild.yaml, Terraform infrastructure in infra/workload/, and pytest unit tests.")
        )

        files = None
        any_model_answered = False  # lane 19 (27a): LLM_OUTPUT_INVALID vs LLM_UNAVAILABLE, across swarm + solo
        not_text: List[str] = []    # TI-5-G2: the last single-turn answer's non-text file paths (typed message)
        swarm_dispatcher_ref = None
        swarm_attribution: Dict[str, str] = {}
        repair_plan = deploy_plan if deploy_plan is not None else qa_plan
        # INCREMENTAL-CHANGE-NO-ORPHAN-DELETE (owner 11-14): only a dispatch that generates the whole application derives
        # orphan deletions; a repair of given files does not (typed: the repair plan), nor a SOLO_FAST_PATH change (below)
        self._record_stack(trace_id, app_full_build=repair_plan is None, app_build_kind=(
            "FULL" if repair_plan is None else "QA_REPAIR" if repair_plan is qa_plan else "DEPLOY_REPAIR"))
        if repair_plan is not None:   # TI-5-R3 / QA-FEEDBACK: the committed files are the draft; no generation call
            files = dict(repair_plan.draft)
            swarm_attribution = {p: (intent_contract.IAC_PERSONA if p == intent_contract.INTENT_PATH else "developer")
                                 for p in files}

        # DEFAULT-MODEL-GEMINI-4-CARBON RT F3: the developer model is read ONCE per build (after the checks that stop
        # a build before any model call) and passed down (lead, swarm, single-call path, repair), so a Settings change
        # during a build cannot switch models mid-build.
        model = self.model_name

        # 1. Attempt Hierarchical Developer Swarm (Fan-Out / Fan-In)
        swarm_enabled = repair_plan is None and os.getenv("ENABLE_DEVELOPER_SWARM", "true").lower() in ["true", "1",
                                                                                                         "yes"]
        self._last_junior_reasks = []
        model_outputs: List[Dict[str, Any]] = []   # SLOW-CALL-FALLBACK: who wrote what (run record)
        if swarm_enabled:
            dispatcher = None
            try:
                resolved_iac_engine = getattr(self, "iac_engine", "OPENTOFU") or "OPENTOFU"
                resolved_vcs_provider = getattr(self, "vcs_provider", "GITHUB") or "GITHUB"
                lead_orch = LeadDeveloperOrchestrator(
                    genai_client=self.genai_client,
                    model_name=model,
                    db=self.db,
                    project_id=self.project_id,
                )
                wbs_plan = lead_orch.decompose_specification(
                    product_id=product_id,
                    spec_text=spec_text,
                    task_dag=task_dag,
                    plan_markdown=plan_markdown,
                    iac_engine=resolved_iac_engine,
                    vcs_provider=resolved_vcs_provider,
                    existing_files=existing_files,
                    trace_id=trace_id,
                    service_names=compute_intent.service_names,  # row L3-PRB-t: per-service tests when > 1
                    **({"wiring_contract": wiring_contract} if wiring_contract else {}),  # lane 10
                    **({"probe_rule": probe_rule} if probe_rule else {}),  # AC-2
                    **({"iac_intent_rule": intent_contract.lead_intent_rule()} if intent_run is not None else {}),
                    **({"app_auth_rule": app_auth_rule} if app_auth_rule else {}),  # DIRECT-IAP-SKILL-VERIFY
                    **({"deadline": deadline} if deadline is not None else {}),  # SLOW-CALL-FALLBACK
                    **({"stage_stop": stage_stop} if stage_stop is not None else {}),  # RT F5
                )

                if wbs_plan.execution_mode == SwarmExecutionMode.SOLO_FAST_PATH:   # INCREMENTAL-CHANGE-NO-ORPHAN-DELETE
                    self._record_stack(trace_id, app_full_build=False, app_build_kind="SOLO_FAST_PATH")
                if wbs_plan.execution_mode != SwarmExecutionMode.SOLO_FAST_PATH and len(wbs_plan.tasks) > 0:
                    logger.info(f"Engaging Developer Swarm ({wbs_plan.execution_mode.value}) for '{product_id}' with {len(wbs_plan.tasks)} tasks across waves.")
                    dispatcher = SwarmDispatcher(genai_client=self.genai_client, model_name=model, db=self.db)
                    if intent_run is not None:   # TI-3: the IaC persona writes the typed intent
                        dispatcher.iac_intent = intent_run
                    dispatcher.app_auth_rule = app_auth_rule   # DIRECT-IAP-SKILL-VERIFY
                    dispatcher.read_view = self._committed_read_view(product_id)   # COMMITTED-READ-VIEW
                    dispatcher.deadline = deadline   # SLOW-CALL-FALLBACK: None = no stage bound
                    dispatcher.stage_stop = stage_stop   # RT F5
                    swarm_dispatcher_ref = dispatcher
                    import asyncio
                    try:
                        loop = asyncio.get_running_loop()
                    except RuntimeError:
                        loop = None

                    if loop and loop.is_running():
                        import concurrent.futures
                        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                            # STAGE-DEADLINE: the pool thread runs in the caller's context (the stage deadline)
                            swarm_files = pool.submit(stage_deadline.bind_context(asyncio.run), dispatcher.execute_phased_junior_swarm(wbs_plan, trace_id or "swarm-trace", product_id, model)).result()
                    else:
                        swarm_files = asyncio.run(dispatcher.execute_phased_junior_swarm(wbs_plan, trace_id or "swarm-trace", product_id, model))

                    if swarm_files and isinstance(swarm_files, dict) and len(swarm_files) > 0:
                        files = swarm_files
                        files.pop("cloudbuild.yaml", None)
                        swarm_attribution = dict(getattr(dispatcher, "last_file_attribution", None) or {})
                        self._last_envelope_checks = list(getattr(dispatcher, "envelope_checks", []) or [])
                        self._last_junior_reasks = list(getattr(dispatcher, "junior_reasks", []) or [])
                        lead_prov = getattr(lead_orch, "last_model_provenance", None)
                        model_outputs = ([dict(lead_prov)] if isinstance(lead_prov, dict) and lead_prov.get("model")
                                         else []) + [dict(x) for x in (getattr(dispatcher, "task_provenance", None)
                                                                       or [])]
                        for step_id in ["STEP-01-APIS", "STEP-02-DB-REGISTRY", "STEP-03-IAM", "STEP-04-APP-CODE", "STEP-05-CICD", "STEP-06-COMPUTE", "STEP-07-TESTS"]:
                            self.update_build_step_status(product_id, trace_id, step_id, "COMPLETED", f"Generated by Developer Swarm ({wbs_plan.execution_mode.value})")
            except StageError as typed_err:
                # S2-A A1 (register HS-61): a junior that returned invalid JSON on every typed re-ask is a typed
                # CODE_DEFECT (JSON.OUTPUT_INVALID); it is reported, never silently dropped into the single-turn path.
                self._last_junior_reasks = list(getattr(dispatcher, "junior_reasks", []) or [])
                reask_events = self._junior_reask_events(trace_id, product_id)
                self._record_stack(trace_id, validation_report=typed_err.report, repair_events=reask_events,
                                   envelope_checks=list(getattr(dispatcher, "envelope_checks", []) or []))
                raise
            except DeveloperStageError:
                raise  # lane 19 (27a): a swarm-level LLM outage is not masked by a second (solo) attempt
            except stage_deadline.STOP_ERRORS:
                raise  # STAGE-DEADLINE: a stopped stage never falls back to the single-turn path
            except Exception as swarm_err:
                self._last_junior_reasks = list(getattr(dispatcher, "junior_reasks", []) or [])
                logger.warning(f"Developer Swarm execution notice ({swarm_err}); falling back to standard pipeline path.")
            any_model_answered = bool(getattr(swarm_dispatcher_ref, "any_model_answered", False))

        candidate_models = get_model_cascade_for_agent("developer", project_id=self.project_id)
        if model and model not in candidate_models:
            candidate_models.insert(0, model)

        cooldown_attempt = 1
        max_cooldown_attempts = 3
        base_prompt = prompt   # code RT F3: a JSON re-ask note replaces the previous one, never stacks
        # SLOW-CALL-FALLBACK (owner 11-13): each single-turn call is bounded (purpose SINGLE_TURN, capped by the stage
        # deadline); a timed-out call or a late answer (never used) prunes that model and the next one is asked.
        single_walk = (CallWalk(candidate_models, purpose=CallPurpose.SINGLE_TURN, stage="developer", deadline=deadline,
                                abandoned=ledger_abandoned_sink(self.db, trace_id, "developer_single_turn"),
                                retry_last_on_transient=False, stage_stop=stage_stop)
                       if candidate_models and not files else None)

        while not files and cooldown_attempt <= max_cooldown_attempts:
            all_rate_limited = True
            last_rate_model = candidate_models[0] if candidate_models else "gemini"

            for m in list(candidate_models):
                if not self.genai_client:
                    all_rate_limited = False
                    break
                try:
                    from google.genai import types
                    try:
                        from shared.settings import get_platform_settings
                        settings = get_platform_settings(project_id=self.project_id)
                        token_limit = settings.models.get_developer_token_limit()
                        thinking_budget = thinking_budget_of(settings)   # FD-4CI-b: Settings > Thinking Budget
                    except Exception:
                        token_limit = 65536
                        thinking_budget = 0

                    token_limit = max_output_tokens_for(
                        m, token_limit, Purpose.DEVELOPER,
                        reserved_thinking_tokens=_reserved_thinking_tokens(m, thinking_budget))   # RT F6
                    logger.info(f"Invoking Gemini model '{m}' for code generation (token_limit={token_limit}, thinking_budget={thinking_budget}, temperature=0.2)...")
                    gen_config_kwargs = {
                        "system_instruction": build_developer_system_prompt(
                            service_names=compute_intent.service_names,  # row L3-PRB-t
                            **({"wiring_contract": wiring_contract} if wiring_contract else {}),  # lane 10
                            **({"iac_intent_rule": intent_contract.developer_intent_rule(intent_run)}
                               if intent_run is not None else {}),  # TI-3
                            **({"app_auth_rule": app_auth_rule} if app_auth_rule else {})),  # DIRECT-IAP-SKILL-VERIFY
                        "response_mime_type": "application/json",
                        "temperature": 0.2,
                        "max_output_tokens": token_limit,
                    }
                    tc = thinking_config_for(m, thinking_budget, Purpose.DEVELOPER, types=types)
                    if tc is not None:
                        gen_config_kwargs["thinking_config"] = tc
                    if hasattr(types, "AutomaticFunctionCallingConfig"):
                        gen_config_kwargs["automatic_function_calling"] = types.AutomaticFunctionCallingConfig(disable=True)
                    # STAGE-DEADLINE checkpoint; the walk alone sets the call's http_options (RT F3)
                    stage_deadline.checkpoint("developer.single_turn")
                    call = single_walk.plan(m)   # SLOW-CALL-FALLBACK: bounded; no room left -> typed stop
                    outcome, call_err = None, None
                    for _try in (0, 1):   # RT F10: one same-model retry after 4 s on a 429 / 503
                        try:
                            response = self.genai_client.models.generate_content(
                                model=m,
                                contents=prompt,
                                config=single_walk.config(call, types.GenerateContentConfig(
                                    **adapt_generate_config_kwargs(m, Purpose.DEVELOPER, gen_config_kwargs,
                                                                   types=types))),
                            )
                            outcome = None
                            break
                        except stage_deadline.STOP_ERRORS:
                            raise
                        except Exception as e_call:
                            outcome, call_err = single_walk.failed(call, e_call), e_call
                            if outcome is None:
                                raise   # not a typed timeout / transient: today's handling below
                            retry_s = single_walk.same_model_retry_s(call, outcome)
                            if retry_s is None:
                                break
                            logger.warning(f"Model '{m}' {outcome}; retrying it once in {retry_s:.0f}s.")
                            getattr(self, "_llm_sleep", time.sleep)(retry_s)
                            stage_deadline.checkpoint("developer.single_turn")
                            call = single_walk.plan(m, backoff_s=retry_s)
                    if outcome is not None:
                        if outcome == TIMEOUT:
                            logger.warning(f"Model '{m}' timed out after {single_walk.attempts[-1].elapsed_s:.1f}s; "
                                           f"trying next candidate...")
                            candidate_models = [cm for cm in candidate_models if cm != m]
                            all_rate_limited = False
                            continue
                        if outcome == "TRANSIENT_429":   # today's 429 path (cooldown when every model is limited)
                            logger.warning(f"Model '{m}' rate limited (429 / ResourceExhausted). Trying next candidate...")
                            last_rate_model = m
                            continue
                        logger.warning(f"Model '{m}' generation failed: {outcome}: {call_err}")
                        all_rate_limited = False
                        continue
                    if not single_walk.answered(call, response):
                        logger.warning(f"Model '{m}' answered after its timeout; the answer is not used. Trying next "
                                       f"candidate...")
                        candidate_models = [cm for cm in candidate_models if cm != m]
                        all_rate_limited = False
                        continue
                    if response is not None:
                        any_model_answered = True

                    if trace_id and self.db:
                        try:
                            from shared.token_accounting import extract_token_usage, record_agent_tokens
                            usage_rec = extract_token_usage(response, m)
                            record_agent_tokens(self.db, trace_id, "developer_single_turn", usage_rec)
                        except Exception as t_err:
                            logger.debug(f"Failed to record developer single-turn tokens: {t_err}")

                    # Check for token limit truncation via finish_reason
                    if response and hasattr(response, "candidates") and response.candidates:
                        candidate = response.candidates[0]
                        finish_reason = getattr(candidate, "finish_reason", None)
                        finish_reason_str = str(finish_reason).upper()
                        if "MAX_TOKENS" in finish_reason_str:
                            logger.critical(
                                f"TOKEN_LIMIT_EXCEEDED: Developer model '{m}' reached output token limit ({token_limit}). "
                                f"Code synthesis was truncated mid-generation. Pruning from current run and cascading to next candidate."
                            )
                            candidate_models = [cm for cm in candidate_models if cm != m]
                            all_rate_limited = False
                            continue

                    if response and response.text:
                        raw_text = response.text.strip()
                        parsed = {}
                        try:
                            parsed = json.loads(raw_text, strict=False)
                        except json.JSONDecodeError as parse_err:
                            # HB-50 (regex backslash doubling of the model's JSON) DELETED in Step 2 S2-A (register
                            # HS-12): the next attempt (the next model of the cascade) carries the parser's exact
                            # message as a typed re-ask (V6, JSON.OUTPUT_INVALID); the note names the previous
                            # attempt and replaces any earlier note (code RT F3).
                            logger.warning(f"Model '{m}' output is not valid JSON ({parse_err}); re-asking with the "
                                           f"parser error. Cascading...")
                            prompt = base_prompt + JSON_REASK_PREVIOUS_ATTEMPT.format(
                                error=f"JSONDecodeError: {parse_err}"[:500])
                            candidate_models = [cm for cm in candidate_models if cm != m]
                            all_rate_limited = False
                            continue

                        parsed_files = None
                        if "files" in parsed and isinstance(parsed["files"], dict) and len(parsed["files"]) > 0:
                            parsed_files = parsed["files"]
                        elif isinstance(parsed, dict) and any(
                            k.startswith(("apps/", "infra/", "tests/", ".", "cloudbuild", "Procfile")) or "/" in k
                            for k in parsed.keys()
                        ):
                            parsed_files = parsed

                        if parsed_files and isinstance(parsed_files, dict) and len(parsed_files) > 0:
                            files = parsed_files
                            if intent_run is not None:   # TI-3/TI-5 gate: an intent given as a JSON object
                                files = intent_contract.normalize_intent_files(files)   # -> its canonical text
                            clean_pid = product_id.lower().replace("_", "-")

                            # Remove legacy cloudbuild.yaml if present in files
                            files.pop("cloudbuild.yaml", None)
                            not_text = sorted(p for p, c in files.items() if not isinstance(c, str))
                            if not_text:   # TI-5-G2: typed re-ask (next model of the cascade), never a crash
                                logger.warning(f"Model '{m}' files content is not text for {not_text[:5]}; "
                                               f"re-asking. Cascading...")
                                prompt = base_prompt + FILES_REASK_PREVIOUS_ATTEMPT.format(
                                    paths=", ".join(json.dumps(p) for p in not_text)[:500])
                                files = None
                                candidate_models = [cm for cm in candidate_models if cm != m]
                                all_rate_limited = False
                                continue
                            # Mark DAG steps as completed
                            for step_id in ["STEP-01-APIS", "STEP-02-DB-REGISTRY", "STEP-03-IAM", "STEP-04-APP-CODE", "STEP-05-CICD", "STEP-06-COMPUTE", "STEP-07-TESTS"]:
                                self.update_build_step_status(product_id, trace_id, step_id, "COMPLETED", f"Generated by model {m}")
                            model_outputs = [{"output": "single_turn", "model": m, "primary_model": single_walk.primary,
                                              "fallback": m != single_walk.primary,
                                              "fallback_reason": (single_walk.left_primary_reason()
                                                                  if m != single_walk.primary else None),
                                              "attempts": [a.to_dict() for a in single_walk.attempts]}]
                            all_rate_limited = False
                            break
                        else:
                            logger.warning(
                                f"Model '{m}' output parsed but did not contain valid 'files' dictionary. "
                                f"Parsed keys: {list(parsed.keys()) if isinstance(parsed, dict) else 'none'}. Cascading..."
                            )
                            candidate_models = [cm for cm in candidate_models if cm != m]
                            all_rate_limited = False
                            continue
                except stage_deadline.STOP_ERRORS:
                    raise  # STAGE-DEADLINE: never cascade past a stopped stage
                except DeveloperStageError:
                    raise   # SLOW-CALL-FALLBACK: the stage budget is gone (typed), never a model to skip
                except Exception as e:
                    if is_model_deprecated_error(e):
                        logger.warning(f"Model '{m}' is deprecated or not found (404). Pruning from candidate cascade.")
                        candidate_models = [cm for cm in candidate_models if cm != m]
                        all_rate_limited = False
                        continue
                    elif is_rate_limit_error(e):
                        logger.warning(f"Model '{m}' rate limited (429 / ResourceExhausted). Trying next candidate...")
                        last_rate_model = m
                        continue
                    else:
                        logger.warning(f"Model '{m}' generation failed: {e}")
                        all_rate_limited = False

            if files or not all_rate_limited:
                break

            if all_rate_limited and not files:
                logger.warning(
                    f"All candidate models ({candidate_models}) hit 429 rate limits. "
                    f"Entering interruptible 60s cooldown (cycle {cooldown_attempt}/{max_cooldown_attempts})."
                )
                should_retry = wait_for_rate_limit_cooldown(
                    trace_id=trace_id,
                    product_id=product_id,
                    stage="developer_code_synthesis",
                    model_name=last_rate_model,
                    attempt=cooldown_attempt,
                    max_attempts=max_cooldown_attempts,
                    project_id=self.project_id,
                )
                if not should_retry:
                    break
                cooldown_attempt += 1

        # SLOW-CALL-FALLBACK: no model answered in time -> typed stop with every attempt (invariant 8)
        if not files and single_walk is not None and single_walk.timed_out and not single_walk.any_answer \
                and not any_model_answered:
            raise single_walk.exhausted()
        # Lane 19 (owner register row 27a): the template fallback app is deleted; no files -> typed failure.
        if not files:
            raise DeveloperStageError(
                LLM_OUTPUT_INVALID if any_model_answered else LLM_UNAVAILABLE,
                "no model produced a usable files dict"
                + (f" (file content not text: {', '.join(not_text)[:300]})" if not_text else ""),
            )
        self._record_model_provenance(trace_id, model_outputs)   # SLOW-CALL-FALLBACK: who wrote what
        # Step 1 S1-A: who wrote each file (files is non-empty here)
        if files and not swarm_attribution:
            swarm_attribution = {p: "developer" for p in files}  # single-turn path: one persona

        # Step 1 S1-A: every file here is an LLM draft (lane 19 row 27a deleted the template scaffold, so the
        # former `frozenset() if draft_from_template` branch is unreachable and was dropped in the step1 merge).
        llm_draft_paths = frozenset(files)

        # Resolve target_project_id and project_number from Firestore
        target_project_id = ""
        project_number = ""
        workload_vcs = None
        stored_repo = None
        recorded_branch = None
        promoted_from = None
        recorded_gha = None
        records_db = None
        w_record: Any = {}   # COMMITTED-READ-VIEW (M1): the record read here ({} = no record / not read)
        if self.project_id:
            try:
                from google.cloud import firestore
                db = firestore.Client(project=self.project_id)
                records_db = db
                w_doc = db.collection("workloads").document(product_id).get()
                if w_doc.exists:
                    w_dict = w_doc.to_dict() or {}
                    w_record = w_dict
                    project_number = w_dict.get("project_number", "")
                    workload_vcs = w_dict.get("vcs_provider", "")
                    stored_repo = w_dict.get("github_repo", "")
                    recorded_branch = w_dict.get("default_branch")   # FD-4CI-b-R1
                    promoted_from = w_dict.get("promoted_from_product_id")   # FD-4CI-b-R1-WIF-SHARED
                    recorded_gha = (w_dict.get(GITHUB_ACTIONS_DEPLOY_FIELD)   # GHA-DEPLOY-SWITCH (a dict record only)
                                    if isinstance(w_dict, dict) else None)
            except Exception:
                pass
        # COMMITTED-READ-VIEW (M1): the one project-ID resolver, also used by the swarm's read view (same record field)
        target_project_id = self._workload_project_id(product_id, record=w_record)
        gha_deploy_on = self._recorded_gha_deploy(product_id, recorded_gha)   # GHA-DEPLOY-SWITCH
        # FD-4CI-b-R1. RT14-28: when this read gave no branch (no record here, or the read failed and was passed over
        # above), the branch this dispatch's tree was read from (the same rule, recorded at the tree read) is used,
        # never "main" by default; without either, "main" as before.
        deploy_branch = deploy_workflow_branch(recorded_branch,
                                               self.stack_run(trace_id).get("base_branch") if trace_id else None)
        deploy_secrets_branch_named = self._deploy_secrets_branch_named(   # FD-4CI-b-R1-WIF-SHARED
            product_id, deploy_branch, stored_repo, promoted_from, records_db)

        # Lane 19 L19-2: exact members from the resolved access record only (never prefixed, guessed or widened).
        auth_invokers = list(run_access.invoker_members)

        # S1-B 1/n: the post-draft tail is a function of (draft, inputs) so the repair loop can re-assemble a
        # repaired draft exactly as the first one (no LLM call inside; integration plan §S.6 step 7).
        assembly_inputs = AssemblyInputs(product_id=product_id, spec_text=spec_text, trace_id=trace_id, task_dag=task_dag,
                                         plan_markdown=plan_markdown, plan_file_path=plan_file_path, domain_restricted_sharing=domain_restricted_sharing, allowed_domains=allowed_domains,
                                         allow_unauthenticated=allow_unauthenticated, enable_direct_iap=enable_direct_iap, target_compute_services=target_compute_services, compute_intent=compute_intent, existing_files=existing_files,
                                         prior_llm=prior_llm, llm_draft_paths=llm_draft_paths, swarm_attribution=swarm_attribution,
                                         target_project_id=target_project_id, project_number=project_number, workload_vcs=workload_vcs, stored_repo=stored_repo,
                                         auth_invokers=auth_invokers,
                                         app_auth_rule=app_auth_rule,   # DIRECT-IAP-SKILL-VERIFY
                                         app_admin_emails=app_admin_emails,   # APP-ADMIN-IAP-CONTRACT
                                         run_access=run_access,   # FD-4AQ W4: V2l reads the mode / sign-in mode
                                         regulated=regulated,
                                         region=workload_region,
                                         compute_defaults=resolve_platform_compute_defaults(self.project_id),
                                         deploy_branch=deploy_branch,   # FD-4CI-b-R1
                                         deploy_secrets_branch_named=deploy_secrets_branch_named,   # R1-WIF-SHARED
                                         github_actions_deploy=gha_deploy_on,   # GHA-DEPLOY-SWITCH
                                         llm_deadline=deadline,   # SLOW-CALL-FALLBACK: None = no stage bound
                                         llm_stage_stop=stage_stop,   # RT F5
                                         **({"iac_intent": intent_run} if intent_run is not None else {}),  # TI-3
                                         )
        if stack_gate is None:
            files, _assembly_meta = self._assemble_tree_typed(files, assembly_inputs)
            return files
        return self._run_hallucination_stack(files, assembly_inputs, stack_gate, deploy_plan=deploy_plan,
                                             developer_model=model,
                                             **({"qa_plan": qa_plan} if qa_plan is not None else {}))

    @staticmethod
    def _recorded_gha_deploy(product_id: str, recorded: Any) -> bool:
        """GHA-DEPLOY-SWITCH: the recorded switch (missing = on). A value that is not true / false stops the stage
        typed (GHA_DEPLOY_SWITCH_INVALID), never coerced."""
        if recorded is None:
            return True
        if github_actions_deploy_enabled is None:
            raise PlatformDefectError(
                f"workloads/{product_id}.{GITHUB_ACTIONS_DEPLOY_FIELD} is set but shared.github_identity is not "
                "importable; the switch cannot be read", reason="GHA_DEPLOY_SWITCH_UNAVAILABLE", stage="developer")
        try:
            return github_actions_deploy_enabled(recorded)
        except ValueError as e:
            raise PlatformDefectError(
                f"workloads/{product_id}.{GITHUB_ACTIONS_DEPLOY_FIELD}: {e}. Nothing was generated or committed; "
                "an administrator sets it on the workload page.", reason="GHA_DEPLOY_SWITCH_INVALID",
                stage="developer") from e

    def _deploy_secrets_branch_named(self, product_id: str, deploy_branch: str, stored_repo: Any,
                                     promoted_from: Any, db: Any) -> bool:
        """FD-4CI-b-R1-WIF-SHARED: True when the workload's deploy workflows read the branch-named deploy secrets
        first. The decision vending's redeploy makes when it writes them (vending.redeploy_workload): a branch other
        than main AND (a promoted workload, or another workload record names the same repository, or the records
        cannot be read). main: False without any read (byte-identical workflows). A workload on its own repository:
        False (its workflows read the plain names, as before)."""
        if deploy_branch == "main":
            return False
        if promoted_from:
            return True
        if repository_shared_with_other_workload is None:
            logger.warning(f"R1_WIF_SHARED_UNKNOWN: '{product_id}': shared.github_identity unavailable; the "
                           "repository counts as shared")
            return True
        try:
            _, _, full_repo = resolve_repo_identity(stored_repo or None, default_owner=self.github_owner,
                                                    product_id=product_id)
        except Exception as e:  # noqa: BLE001 - no repository identity: unknown = shared (as vending)
            logger.warning(f"R1_WIF_SHARED_UNKNOWN: '{product_id}': repository not resolved ({type(e).__name__}); "
                           "it counts as shared")
            return True
        shared = repository_shared_with_other_workload(db, product_id, full_repo, default_owner=self.github_owner)
        if shared is None:
            logger.warning(f"R1_WIF_SHARED_UNKNOWN: '{product_id}': workload records not readable; '{full_repo}' "
                           "counts as shared (the workflows read the branch-named deploy secrets first)")
        return shared is not False

    # ------------------------------------------------------------------------- Step 1 S1-B hallucination stack
    def _platform_region(self, product_id: Optional[str] = None) -> str:
        """FD-4AF: the platform region setting `orchestration.default_gcp_region`, read through `get_platform_settings`.
        FD-4AK (RT F2/F6): the read is strict -- an unreadable or invalid settings document raises a typed
        PlatformSettingsUnavailable, so this returns "" (never the compile-time default region); a manifest that then
        uses ${REGION} / ${ARTIFACT_REGISTRY} stops with K8S.PLACEHOLDER_VALUE_UNAVAILABLE. A missing settings
        document (fresh install) is the schema default region, as for every settings reader.

        FD-7M-a: with a `product_id`, the workload's recorded region (workloads/{pid}.region, read with this agent's
        client) through `shared.settings.workload_region`; a record without a region gives the setting exactly as
        before. A record read that fails, or a region that is not approved, gives "" (the same "unusable" answer)."""
        try:
            from shared.settings import get_platform_settings
            orchestration = get_platform_settings(project_id=self.project_id, strict=True).orchestration
            region = str(getattr(orchestration, "default_gcp_region", "") or "")
        except Exception as e:  # noqa: BLE001 - an unusable settings object = no region (no literal fallback here)
            logger.warning(f"orchestration.default_gcp_region not read ({e})")
            return ""
        db = getattr(self, "db", None)
        if not product_id:
            return region
        if db is None:
            # SAT-23 RT F1: a configured install without a client cannot read the recorded region ("" = unusable);
            # only a process with no project at all (the eval harness child) keeps the setting.
            if os.getenv("PROJECT_ID") or os.getenv("GOOGLE_CLOUD_PROJECT"):
                logger.warning(f"workload region of '{product_id}' not readable for manifest hydration (no Firestore "
                               "client although a project is configured)")
                return ""
            return region
        try:
            record_region = _workload_record_region(db, product_id)
            if record_region is None:
                return region
            from shared.settings import workload_region
            return workload_region(record_region, orchestration, default_region=region, stage="k8s_hydration")
        except Exception as e:  # noqa: BLE001 - unknown / unapproved workload region = no region (typed downstream)
            logger.warning(f"workload region of '{product_id}' not usable for manifest hydration ({e})")
            return ""

    def _workload_project_id(self, product_id: str, record: Any = None) -> str:
        """COMMITTED-READ-VIEW (M1): the workload's vended child project, `workloads/{product_id}.project_id`, the ONE
        resolver of that value for the assembly (AssemblyInputs.target_project_id) and the swarm's read view, so both
        always hydrate with the same project (the eval harness patches only this method). `record`: the workload
        record the caller already read ({} = none / not readable); None = read it here, the way the assembly does
        (a client of this agent's host project; no host project = no record). "" when there is no usable value."""
        if record is None:
            record = {}
            if self.project_id:
                try:
                    from google.cloud import firestore
                    doc = firestore.Client(project=self.project_id).collection("workloads").document(product_id).get()
                    record = (doc.to_dict() or {}) if doc.exists else {}
                except Exception as read_err:  # noqa: BLE001 - unreadable = no value (the assembly's own rule)
                    logger.warning(f"workload record of '{product_id}' not read for its project id "
                                   f"({type(read_err).__name__})")
                    record = {}
        value = record.get("project_id", "") if isinstance(record, dict) else ""
        return value if isinstance(value, str) else ""

    @staticmethod
    def _hydrate_k8s(files: Dict[str, str], product_id: str, project_id: str, region: Any, *,
                     defer_unresolved: bool) -> Tuple[Dict[str, str], List[str]]:
        """FD-4AF: the one manifest hydration call, shared by the assembly (step 8) and COMMITTED-READ-VIEW (RT F3), so
        the bytes a later wave reads and the bytes the commit holds come from the same call. `project_id` is the
        workload record's `project_id`, `region` the `_platform_region` resolver for this product."""
        return hydrate_kubernetes_manifests(files, product_id, project_id=project_id, region=region,
                                            defer_unresolved=defer_unresolved)

    def _committed_read_view(self, product_id: str) -> Callable[[Dict[str, str]], Dict[str, str]]:
        """COMMITTED-READ-VIEW (ex04-1114, 11-15; register row COMMITTED-READ-VIEW): the swarm's read-dependency view.
        A junior of a later wave reads earlier waves' files through it (SwarmDispatcher.read_view), so it reads them as
        the platform will commit them: before, the FD-4AF manifest hydration rewrote `${PROJECT_ID}` /
        `${PRODUCT_ID}` / `${ARTIFACT_REGISTRY}` ... in k8s/*.yaml only at assembly, after the tests had been written
        against the placeholder text, so the tests failed in QA on the committed (hydrated) manifests.

        The one rule is the assembly's own: `hydrate_kubernetes_manifests` with the same values (the project through
        `_workload_project_id`, the assembly's own resolver; the region through `_platform_region`, only when a
        manifest uses `${REGION}` / `${ARTIFACT_REGISTRY}`) and `defer_unresolved=True`, through the same `_hydrate_k8s`
        call. A file that is not a manifest, or a manifest without a placeholder, is returned byte-identical (Do No
        Harm). A value the platform does not have (K8S.PLACEHOLDER_VALUE_UNAVAILABLE) leaves every dependency text of
        that read as staged (hydration is all-or-nothing per call): the view decides nothing, and the assembly
        resolves the values again before the commit (and stops typed when they are still missing). The staged tree, the draft and the committed tree are
        unchanged by this view. RT F4: only a value that was read is kept for the view's later calls; an empty or
        unreadable one is read again by the next wave. The swarm calls the view off its event loop (RT F5)."""
        cache: Dict[str, str] = {}
        lock = threading.Lock()

        def project_id() -> str:
            with lock:
                if cache.get("project_id"):
                    return cache["project_id"]
            value = self._workload_project_id(product_id)   # M1: the assembly's own resolver
            if value:
                with lock:
                    cache["project_id"] = value
            return value

        def region() -> str:
            with lock:
                if cache.get("region"):
                    return cache["region"]
            value = self._platform_region(product_id)
            if value:
                with lock:
                    cache["region"] = value
            return value

        def view(deps: Dict[str, str]) -> Dict[str, str]:
            if not any(isinstance(p, str) and is_kubernetes_manifest_path(p) for p in deps):
                return deps
            try:
                viewed, actions = self._hydrate_k8s(dict(deps), product_id, project_id(), region,
                                                    defer_unresolved=True)
            except ManifestHydrationError as e:
                logger.warning(f"COMMITTED_READ_VIEW_UNAVAILABLE '{product_id}': {e.code} for {e.path}; every "
                               f"dependency text of this read stays as staged (the assembly resolves the same values "
                               f"again before the commit and stops typed if they are still missing)")
                return deps
            for act in actions:
                logger.info(f"COMMITTED_READ_VIEW '{product_id}': a later wave reads the committed form: {act}")
            return viewed

        return view

    def _manifest_hydration_stage_error(self, trace_id: Optional[str], e: "ManifestHydrationError") -> StageError:
        """FD-4AF RT F1: a k8s manifest that cannot be hydrated without guessing stops the stage typed, like
        FactsUnavailable. A missing platform value (workload project / region) is UNAVAILABLE (GATE_UNAVAILABLE);
        an unresolved `$` in an image / WI annotation is a CODE_DEFECT FAIL. The report is recorded here (legacy
        path); on the stack path _run_hallucination_stack records it again with the repair events and persists it."""
        unavailable = e.code == "K8S.PLACEHOLDER_VALUE_UNAVAILABLE"
        diag = Diagnostic(tool="yaml", code=e.code, severity="error",
                          error_class=ErrorClass.PLATFORM_DEFECT if unavailable else ErrorClass.CODE_DEFECT,
                          file=e.path or "<k8s>", source="precommit", message=str(e))
        report = ValidationReport(
            status="UNAVAILABLE" if unavailable else "FAIL", source="precommit", artifact_hash="",
            tools_unavailable=([("workload_record" if e.unavailable == "project_id" else "platform_settings")]
                               if unavailable else []),
            diagnostics=[diag])
        self._record_stack(trace_id, validation_report=report)
        return StageError(report, str(e))

    def _platform_repair_model(self) -> str:
        """models.repair_model from the platform settings ("" when unset or the settings are unavailable)."""
        try:
            from shared.settings import get_platform_settings
            return str(getattr(get_platform_settings(project_id=self.project_id).models, "repair_model", "") or "")
        except Exception as e:  # noqa: BLE001 - unavailable settings = unset (the developer model repairs)
            logger.debug(f"models.repair_model not read ({e}); the developer model repairs")
            return ""

    def _hallucination_stack_gate(self, product_id: str, trace_id: Optional[str]) -> Optional[Dict[str, Any]]:
        """None = the stack is not configured for this agent (unit tests, scripts): legacy path, logged. On Cloud Run
        an unconfigured stack is a deployment defect and stops the stage (never a silent pass). Otherwise the per-trace
        ledger must have budget left and the validate service must be ready -- both before any LLM call."""
        rt = self.stack_runtime()
        if rt.source == "unconfigured":
            if runtime_env.on_cloud_run():
                raise StageError(ValidationReport(status="UNAVAILABLE", source="precommit", artifact_hash="",
                                                  tools_unavailable=["hallucination_stack_runtime"]),
                                 "hallucination stack runtime not configured on Cloud Run")
            logger.warning("Hallucination stack not configured for this DeveloperAgent: validators and repair loop "
                           "are off (legacy path).")
            return None
        trace = trace_id or f"dev-{product_id}"
        if rt.ledger_store is None:
            raise StageError(ValidationReport(status="UNAVAILABLE", source="precommit", artifact_hash="",
                                              tools_unavailable=["repair_ledger_store"]), "no repair ledger store")
        try:
            ledger = rt.ledger_store.load(trace)
        except StoreUnavailable as e:
            raise StageError(ValidationReport(status="UNAVAILABLE", source="precommit", artifact_hash="",
                                              tools_unavailable=["repair_ledger_store"]), str(e)) from e
        if ledger is not None and (ledger.exhausted_reason or ledger.iteration >= rt.settings.repair_max_iterations_total):
            report = ValidationReport(status="FAIL", source="precommit", artifact_hash="", diagnostics=[Diagnostic(
                tool="platform", code="GATE.REPAIR_BUDGET_EXHAUSTED", severity="error", file="<trace>",
                message=f"trace {trace}: repair budget already exhausted ({ledger.exhausted_reason or 'ITERATIONS'})",
                source="precommit")])
            raise RepairBudgetExhausted(report, ledger.exhausted_reason or "ITERATIONS",
                                        "dispatch refused: the trace's repair budget is exhausted")
        # Owner 10-13 (Step 1 follow-up): bounded readiness wait -- a cold terraform server is still fetching the
        # engine/mirror in its warm-up. Poll with backoff up to validate_ready_wait_s (default 180 s); still not
        # ready (or every probe errored) -> GATE_UNAVAILABLE, $0, before any LLM call. Never proceeds unready.
        ready, probes, waited = wait_for_validate_ready(
            rt.validate_client, getattr(self, "iac_engine", "OPENTOFU") or "OPENTOFU",
            rt.settings.validate_ready_wait_s)
        if ready.get("ready") is not True:
            raise StageError(ValidationReport(status="UNAVAILABLE", source="precommit", artifact_hash="",
                                              tools_unavailable=["V1b"]),
                             f"terraform validate service not ready after {probes} probe(s) in {waited:.0f}s "
                             f"(limit {rt.settings.validate_ready_wait_s}s): {ready.get('reason')}")
        return {"runtime": rt, "trace_id": trace, "providers": list(ready.get("providers") or []),
                "engine_label": f"{str(ready.get('engine') or 'OPENTOFU').lower()} {ready.get('engine_version') or ''}".strip(),
                "provider_versions": ready.get("provider_versions"),   # TI-3: schema-slice parity (intent mode)
                "ready_waited_s": waited}   # validate-ready-wait: the parity wait gets what is left of the budget

    def _run_stack_settings(self, rt: Any, stack_gate: Optional[Dict[str, Any]]) -> Any:
        """TI-3h (owner 10-21): the HallucinationStackSettings of this developer run. On the gateway the install's
        platform setting governance.iac_intent_generate decides iac_intent_mode for a new workload: "generate" only
        when the runtime's reader answers exactly True. Without the hallucination stack (stack_gate None) the setting
        does not apply and is not read; a runtime without a reader (eval harness, unit tests) keeps its own settings
        (the harness passes the mode explicitly). An unreadable setting -- or any error of the reader -- is "off" and
        never fails the run. Stickiness is not decided here (iac_intent_mode_decision: an intent workload stays on
        the intent path and a legacy workload stays legacy, whatever this returns)."""
        settings = getattr(rt, "settings", None)
        reader = getattr(rt, "intent_generate_setting", None)
        if reader is None or stack_gate is None or settings is None:
            return settings
        try:
            on = reader(project_id=self.project_id or None) is True
        except Exception as e:  # noqa: BLE001 - the toggle never fails a run: unreadable = off
            logger.warning(f"governance.iac_intent_generate could not be read ({type(e).__name__}: {e}); "
                           f"typed infrastructure stays off for this run")
            on = False
        mode = intent_contract.MODE_GENERATE if on else intent_contract.MODE_OFF
        if getattr(settings, "iac_intent_mode", None) == mode:
            return settings
        return settings.model_copy(update={"iac_intent_mode": mode})

    def _await_schema_parity(self, rt: Any, art: Any, stack_gate: Dict[str, Any], check_ready_parity: Any,
                             gate_unavailable: Any, unavailable: Any) -> None:
        """validate-ready-wait (live incident 10-27): the terraform server answers /validate/ready `ready: true` as
        soon as `hashicorp/google` is in its provider mirror, while its warm-up is still fetching google-beta,
        kubernetes and random (a few seconds on a cold instance). The schema-slice parity check needs every slice
        provider version, so a parity miss on the gate's answer re-polls /validate/ready until the typed
        `provider_versions` hold every slice version -- with what is left of `validate_ready_wait_s` (one readiness
        budget for the whole developer dispatch, before any LLM call). Still missing -> the same GATE_UNAVAILABLE
        (IAC_SCHEMA_PARITY), naming the wait. Parity already holds -> no further probe (no extra call)."""
        try:
            check_ready_parity(art, stack_gate.get("provider_versions"))
            return
        except gate_unavailable as first:
            miss: Any = first
        budget = float(getattr(rt.settings, "validate_ready_wait_s", 0) or 0)
        left = max(0.0, budget - float(stack_gate.get("ready_waited_s") or 0.0))

        def parity_holds(answer: Dict[str, Any]) -> bool:
            try:
                check_ready_parity(art, answer.get("provider_versions"))
            except gate_unavailable:
                return False
            return True
        logger.info(f"Schema-slice parity not met yet ({miss}); waiting up to {left:.0f}s for the validate "
                    f"service's provider mirror")
        ready, probes, waited = wait_for_validate_ready(
            rt.validate_client, getattr(self, "iac_engine", "OPENTOFU") or "OPENTOFU", left, accept=parity_holds)
        if ready.get("ready") is True and parity_holds(ready):
            stack_gate.update(providers=list(ready.get("providers") or []),
                              provider_versions=ready.get("provider_versions"))
            return
        if ready.get("ready") is True:
            try:
                check_ready_parity(art, ready.get("provider_versions"))
            except gate_unavailable as last:
                miss = last
        else:
            miss = f"{miss}; validate service then not ready: {ready.get('reason')}"
        raise unavailable("iac_intent_artifacts",
                          f"{miss} (waited {waited:.0f}s more over {probes} probe(s); readiness limit "
                          f"{budget:.0f}s)")

    def _resolve_intent_run(self, compute_intent: Any, existing_files: Optional[Dict[str, str]],
                            stack_gate: Optional[Dict[str, Any]]) -> Any:
        """TI-3 (register TI-3a/TI-3e): the dispatch's typed-intent run, or None (mode "off": nothing changes).
        Mode = HallucinationStackSettings.iac_intent_mode for a new typed-topology workload; a repository that already
        holds iac_intent.json stays on the intent path. Fail-closed before any LLM call (GATE_UNAVAILABLE): no
        hallucination stack (the intent gate is one of its validators), no typed topology for a sticky workload, an
        unusable intent artifact, or a validate service whose provider versions differ from the schema slice."""
        rt = self.stack_runtime()
        settings = self._run_stack_settings(rt, stack_gate)
        topology = compute_intent.topology
        mode, why = intent_contract.iac_intent_mode_decision(
            getattr(settings, "iac_intent_mode", intent_contract.MODE_OFF), existing_files, topology)
        if mode != intent_contract.MODE_GENERATE:
            if why:   # RT F2 / F7: logged only; the dispatch runs the legacy contract unchanged
                logger.warning(f"Typed IaC intent not used for this dispatch: {why}")
            return None

        def unavailable(tool: str, reason: str) -> StageError:
            return StageError(ValidationReport(status="UNAVAILABLE", source="precommit", artifact_hash="",
                                               tools_unavailable=[tool]), reason)
        if stack_gate is None:
            raise unavailable("iac_intent_gate", "the typed IaC intent needs the hallucination stack (validators and "
                                                 "repair loop); it is not configured for this agent")
        if topology is None:
            raise unavailable("iac_intent_gate", "IAC.INTENT_WITHOUT_TOPOLOGY: the repository holds a typed IaC intent "
                                                 "but this run has no typed service topology to bind it to")
        try:
            from shared.iac_intent import IntentGateUnavailable, check_ready_parity, load_artifacts
        except ImportError:  # pragma: no cover
            from ..shared.iac_intent import IntentGateUnavailable, check_ready_parity, load_artifacts  # type: ignore
        try:
            art = load_artifacts()
        except IntentGateUnavailable as e:
            raise unavailable("iac_intent_artifacts", str(e)) from e
        self._await_schema_parity(rt, art, stack_gate, check_ready_parity, IntentGateUnavailable, unavailable)
        # RT F3(3), TI-5c: a topology resource whose realizing module needs a fact the platform cannot supply on the
        # intent path stays on the legacy path (logged). Since TI-5 the network / zone facts are supplied, so this
        # holds only for a future fact without an expression (intent_path_facts).
        # A topology resource only a not-yet-wired module could realize (shared/iac_intent.NOT_YET_WIRED_MODULES; empty
        # since TI-5-R2) stays on the legacy path, with its own code. A sticky workload cannot go legacy and its gate
        # would refuse the module on every repair: Fable 10-22 note, a typed stop before any LLM call ($0).
        unwired = intent_contract.not_wired_slots(topology, art)
        if unwired and why == intent_contract.STICKY:
            raise unavailable("iac_intent_gate", f"{intent_contract.NOT_WIRED_YET}: topology resources {unwired} need "
                                                 f"a module the typed-intent path does not wire yet")
        if unwired:
            logger.warning(f"Typed IaC intent not used for this dispatch: {intent_contract.NOT_WIRED_YET} "
                           f"(topology resources {unwired} need a module the intent path does not wire yet)")
            return None
        bound = intent_contract.network_bound_slots(topology, art, facts=intent_contract.intent_path_facts())
        if bound and why != intent_contract.STICKY:
            logger.warning(f"Typed IaC intent not used for this dispatch: {intent_contract.NETWORK_FACT_UNAVAILABLE} "
                           f"(topology resources {bound} need a network / zone the platform cannot express yet)")
            return None
        return intent_contract.build_intent_run(
            topology, existing_files, artifacts=art,
            structured_output=bool(getattr(settings, "iac_intent_structured_output", False)),
            thinking_budget=int(getattr(settings, "iac_intent_thinking_budget", 4096)),
            max_output_tokens=int(getattr(settings, "iac_intent_max_output_tokens", 16_384)))

    def _plan_qa_repair(self, product_id: str, trace_id: Optional[str], kwargs: Mapping[str, Any]) -> Any:
        """QA-FEEDBACK (developer_agent/qa_repair.py): the QA_REPAIR plan of this dispatch, or None (today's path).
        None without a `qa_feedback` (every first build, every unmatched QA retry: nothing is recorded or logged here)
        and on a terraform remediation dispatch (the deploy's typed report has its own path, TI-5-R3). A stale
        tf_remediation_context of an earlier deploy round is not a report: the tested tree already holds that round's
        fix, and no generation prompt is built on a QA repair."""
        feedback = kwargs.get("qa_feedback")
        if feedback is None:
            return None
        if kwargs.get("tf_validation_report") is not None:
            logger.warning(f"QA feedback for '{product_id}' ignored on a terraform remediation dispatch; regenerating")
            return None
        rt = self.stack_runtime()
        plan = qa_repair.plan_qa_repair(feedback, stack_configured=rt.source != "unconfigured")
        if plan.mode == qa_repair.QA_REPAIR:
            # Fable RT F2: a QA repair needs one repair iteration; a ledger that cannot fund it takes today's path
            # (which may still pass at zero iterations; its own gate refuses an exhausted ledger as before)
            try:
                from .repair_loop import effective_repair_token_budget
                ledger = rt.ledger_store.load(trace_id or f"dev-{product_id}") if rt.ledger_store else None
                spent = qa_repair.budget_spent(ledger, rt.settings, effective_repair_token_budget(rt.settings))
            except Exception as e:  # noqa: BLE001 - an unreadable ledger: today's path (its gate decides)
                spent = f"LEDGER_UNAVAILABLE ({type(e).__name__})"
            if spent:
                plan = qa_repair.QARepairPlan(qa_repair.REGENERATE, "REPAIR_BUDGET_EXHAUSTED", plan.attempt,
                                              plan.commit_sha)
                self._record_stack(trace_id, qa_repair=dict(plan.summary(), budget=spent))
                self._persist_qa_repair(trace_id, dict(plan.summary(), budget=spent))
                logger.warning(f"QA feedback not used for '{product_id}' (trace {trace_id}, QA attempt "
                               f"{plan.attempt}): REPAIR_BUDGET_EXHAUSTED ({spent}); regenerating without it")
                return None
        # PLATFORM-RENDERED-FINDING: a finding on a file the platform renders every run -> typed PLATFORM_DEFECT, no
        # LLM call. QA-FINDING-ON-UNOWNED-FILE: before a regeneration for a finding outside the draft, the same
        # ownership predicate on the default branch; a file no regeneration can change or remove -> typed stop.
        unowned = None
        if plan.mode == qa_repair.REGENERATE and plan.reason == qa_repair.NOT_ON_A_DRAFT_FILE and plan.off_draft_files:
            unowned = self._unowned_finding_check(product_id, trace_id, plan, feedback)
        summary = dict(plan.summary(), unowned_check=unowned)
        if unowned is not None and unowned.get("verdict") == qa_repair.STOP:
            # the decision of this dispatch is the typed stop (never recorded as a regeneration that did not happen)
            summary.update(mode=qa_repair.STOP, reason=unowned.get("reason"))
        self._record_stack(trace_id, qa_repair=summary)
        self._persist_qa_repair(trace_id, summary)
        if plan.mode == qa_repair.STOP or (unowned is not None and unowned.get("verdict") == qa_repair.STOP):
            logger.error(f"QA feedback for '{product_id}' (trace {trace_id}, QA attempt {plan.attempt}): "
                         f"{plan.reason if plan.mode == qa_repair.STOP else unowned['reason']}; the run stops")
            raise qa_repair.stop_error(plan, product_id, feedback,
                                       None if plan.mode == qa_repair.STOP else unowned)
        logger.warning(f"QA feedback for '{product_id}' (QA attempt {plan.attempt}, commit {plan.commit_sha}): "
                       f"{plan.mode} ({plan.reason})")
        for fact in plan.missing_modules:   # QA-REPAIR-MISSING-MODULE: the typed outcome of each reported module
            log = logger.error if fact.get("status") == qa_repair.MODULE_NOT_IN_CATALOG else logger.warning
            log(f"QA missing module for '{product_id}' (trace {trace_id}): {fact.get('file')}: module "
                f"{fact.get('module')!r} -> {fact.get('status')}"
                + (f" ({fact.get('requirement')})" if fact.get("requirement") else "")
                + ("; no distribution is guessed, nothing may be added for it" if
                   fact.get("status") == qa_repair.MODULE_NOT_IN_CATALOG else ""))
        return plan if plan.mode == qa_repair.QA_REPAIR else None

    def _unowned_finding_check(self, product_id: str, trace_id: Optional[str], plan: Any,
                               feedback: Mapping[str, Any]) -> Dict[str, Any]:
        """QA-FINDING-ON-UNOWNED-FILE: qa_repair.unowned_finding_outcome over the default branch (the tree every
        regeneration starts from, read now with its completeness) and the workload's app provenance. Without the
        evidence (no store, an unreadable record, a failed read) -> REGENERATE with the reason, logged: no stop on
        incomplete evidence, never a fake pass."""
        store = getattr(self.stack_runtime(), "app_provenance_store", None)
        if store is None:
            return {"verdict": qa_repair.REGENERATE, "reason": "NO_PROVENANCE_STORE", "files": []}
        try:
            record = store.load(product_id)
            base = self.fetch_existing_repo_files(product_id)
            status = getattr(self, "last_tree_status", None)
        except Exception as e:  # noqa: BLE001 - AppProvenanceUnavailable or a repository read failure: no evidence
            logger.warning(f"QA-FINDING-ON-UNOWNED-FILE check not made for '{product_id}' (trace {trace_id}): "
                           f"{type(e).__name__}; regenerating as before")
            return {"verdict": qa_repair.REGENERATE, "reason": f"EVIDENCE_UNAVAILABLE ({type(e).__name__})",
                    "files": []}
        seen = self._unowned_seen(trace_id)   # RT R1: the first failures of earlier QA attempts of this trace
        outcome = qa_repair.unowned_finding_outcome(
            plan.off_draft_files, feedback.get("files") or {}, base or {}, record or {},
            base_complete=isinstance(status, dict) and status.get("complete") is True,
            codes=plan.off_draft_codes, seen=seen, attempt=plan.attempt,
            replaced=qa_repair.recorded_paths(feedback, qa_repair.COMMITTED_PATHS_FIELD))
        self._record_unowned_seen(trace_id, qa_repair.seen_entries(outcome, plan.attempt))
        return outcome

    def _unowned_seen(self, trace_id: Optional[str]) -> Dict[str, Any]:
        """RT R1: pipeline_executions/{trace}.stages.developer.unowned_seen (merged per dispatch), else this
        instance's run record. A read failure is no evidence (a first failure: one more regeneration, never a stop)."""
        local = dict(self.stack_run(trace_id).get("unowned_seen") or {}) if trace_id else {}
        db = getattr(self, "db", None)
        if db is None or not trace_id:
            return local
        try:
            snap = db.collection("pipeline_executions").document(trace_id).get()
            data = (snap.to_dict() or {}) if getattr(snap, "exists", False) is True else {}
            stored = ((data.get("stages") or {}).get("developer") or {}).get("unowned_seen")
        except Exception as e:  # noqa: BLE001 - no evidence: never a stop
            logger.warning(f"unowned_seen unreadable for {trace_id}: {type(e).__name__}")
            return local
        return dict(local, **stored) if isinstance(stored, dict) else local

    def _record_unowned_seen(self, trace_id: Optional[str], entries: Mapping[str, Any]) -> None:
        """RT R1: merge this dispatch's first failures into the run record and pipeline_executions (best-effort)."""
        if not entries or not trace_id:
            return
        self._record_stack(trace_id, unowned_seen=dict(self.stack_run(trace_id).get("unowned_seen") or {},
                                                       **entries))
        db = getattr(self, "db", None)
        if db is None:
            return
        try:
            db.collection("pipeline_executions").document(trace_id).set(
                {"stages": {"developer": {"unowned_seen": dict(entries)}}}, merge=True)
        except Exception as e:  # noqa: BLE001 - telemetry: a lost record costs one more regeneration, never a stop
            logger.warning(f"unowned_seen not recorded for {trace_id}: {type(e).__name__}")

    def _persist_qa_repair(self, trace_id: Optional[str], summary: Dict[str, Any]) -> None:
        """SAT-49 (Fable RT F6): the dispatch's QA-FEEDBACK decision (mode, typed reason, attempt, commit, seeds) on
        pipeline_executions/{trace}.stages.developer.qa_repair (merge), where the operator looks, beside the run
        record and the WARNING log. A few hundred bytes. Best-effort: a failed write is logged, never the outcome.
        Every key is always written (`budget` None unless the budget path set it): Firestore's merge replaces leaf
        fields one by one, so a key left out would keep an earlier dispatch's value."""
        db = getattr(self, "db", None)
        if db is None or not trace_id:
            return
        record = dict({"mode": None, "reason": None, "attempt": None, "commit_sha": None, "findings": 0, "seeds": [],
                       "budget": None, "missing_modules": [], "unowned_check": None, "stop_files": []},
                      **summary)   # QA-REPAIR-MISSING-MODULE; QA-FINDING-ON-UNOWNED-FILE; PLATFORM-RENDERED-FINDING
        try:
            db.collection("pipeline_executions").document(trace_id).set(
                {"stages": {"developer": {"qa_repair": record}}}, merge=True)
        except Exception as pe:  # noqa: BLE001 - telemetry only: never changes the stage outcome
            logger.warning(f"Could not persist the QA repair decision for {trace_id}: {type(pe).__name__}: {pe}")

    @staticmethod
    def _repair_call_room(window: Mapping[str, Optional[float]], settings: Any, dispatcher: Any) -> Callable[[], bool]:
        """REPAIR-WALL-CLOCK-ROOM (RT F2): the repair loop's pre-dispatch check (LoopContext.repair_call_room). True
        while the dispatch's repair deadline (`window["start"]` + settings.repair_wall_clock_s, the same deadline
        invoke_repair gets) leaves room for a call by the walk's own rule (`call_timeout_s`, the dispatcher's caps and
        clock), so the loop never dispatches an iteration the walk would refuse. No window start yet or no wall clock
        setting: True (the loop's own check only)."""
        def room() -> bool:
            wall_s = getattr(settings, "repair_wall_clock_s", None)
            if window.get("start") is None or not wall_s:
                return True
            # a dispatcher without its own clock / caps (test doubles) uses the walk's defaults
            clock = getattr(dispatcher, "_clock", None) or time.monotonic
            return call_timeout_s(CallPurpose.REPAIR, deadline=float(window["start"]) + float(wall_s), now=clock(),
                                  timeouts=getattr(dispatcher, "call_timeouts", None) or DEFAULT_CALL_TIMEOUTS
                                  ) is not None
        return room

    def _run_hallucination_stack(self, draft: Dict[str, str], inputs: "AssemblyInputs",
                                 gate: Dict[str, Any], deploy_plan: Any = None, qa_plan: Any = None,
                                 developer_model: Optional[str] = None) -> Dict[str, str]:
        from .repair_loop import Assembled, LoopContext, RepairLoop
        from .validators.step1 import build_step1_stack
        try:
            from gatekeeper_agent.verifier import SynthesisVerifierAgent as _Verifier
        except ImportError:  # pragma: no cover
            _Verifier = SynthesisVerifierAgent
        rt = gate["runtime"]
        trace = gate["trace_id"]
        product_id = inputs.product_id
        # lane 11 near-term: IP ranges are platform facts. The purposes come from the exact allocation types of the
        # draft being assembled (code RT F4: resolved per iteration, so a repair that adds a connector gets its fact;
        # facts only grow). An existing workload's network is pinned by live state (lane 11 RT F3): nothing is ever
        # allocated for it; its own committed facts are reused (reuse-only, code RT F3) so a regeneration renders
        # the same declarations and values, and V2h only measures.
        existing_network = has_existing_network(inputs.existing_files)
        existing_purposes = (required_network_purposes(inputs.existing_files) if existing_network else frozenset())
        topo_purposes = topology_network_purposes(inputs.compute_intent.topology)   # lane 10 L10-u: gce-worker subnet
        topo_purposes |= primary_network_purposes(inputs.compute_intent.archetype)   # gce-bastion-network: its subnet
        llm_paths = set(inputs.llm_draft_paths)   # shared with the loop context: renamed repair files join it
        holder = FactsHolder()
        attempted: set = set()

        def resolve_facts(d: Mapping[str, str]) -> None:
            needed = set(required_network_purposes(d, paths=llm_paths)) | set(existing_purposes) | set(topo_purposes)
            if inputs.iac_intent is not None:   # TI-5c: the intent's network modules (+ connector) need IPAM facts
                needed |= intent_contract.intent_network_purposes(d, inputs.iac_intent.artifacts,
                                                                  inputs.compute_intent.topology,
                                                                  inputs.existing_files)
            if not needed - attempted:
                return
            attempted.update(needed)
            holder.facts = self._resolve_network_facts(rt, inputs, frozenset(attempted),
                                                       allocate=not existing_network)
            self._record_stack(inputs.trace_id, network_facts=(
                holder.facts.model_dump(mode="json") if holder.facts is not None else None),
                facts_source=("reuse-only" if existing_network else
                              (holder.facts.source if holder.facts is not None else None)))

        self._record_stack(inputs.trace_id, network_facts=None, existing_network=existing_network, facts_source=None)

        # FD-55 W5 (FD55-W5): V3c-planned's planned set = the typed plan (planned_cloud_run_services) plus, RT F2, the
        # Cloud Run services this iteration's assembly actually rendered (HB-04's planned_out); refreshed in place
        typed_planned = planned_cloud_run_services(inputs.compute_intent.archetype, product_id,
                                                   inputs.compute_intent.service_names, inputs.compute_intent.topology)
        planned_holder: List[str] = list(typed_planned)

        def assemble(d: Dict[str, str]) -> Assembled:
            resolve_facts(d)
            # FD-4AF-r: an unknown k8s placeholder is V-K8S-PH's repairable finding here (registered blocking below)
            tree, meta = self._assemble_tree_typed(d, replace(inputs, network_facts=holder.facts,
                                                              defer_k8s_unresolved=True))
            planned_holder[:] = list(dict.fromkeys(list(typed_planned) + list(meta.get("planned_services") or ())))
            return Assembled(tree=tree, record=meta["assembly_record"], platform_files=meta["platform_files"],
                             vendored_before_restore=meta["vendored_before_restore"],
                             assembled_root=meta["assembled_root"],
                             iac_intent=meta.get("iac_intent"))   # TI-3: None on mode "off"

        # repair model: the runtime override (eval harness) -> the admin setting models.repair_model (Argon compat,
        # owner 10-14; "" = unset) -> the developer model (owner decision D1): the one this build was generated with
        repair_model = rt.settings.repair_model or self._platform_repair_model() or developer_model or self.model_name
        dispatcher = SwarmDispatcher(genai_client=self.genai_client, model_name=repair_model, db=self.db)
        if inputs.iac_intent is not None:   # TI-3: repaired intents given as objects are normalized too
            dispatcher.iac_intent = inputs.iac_intent

        def repair(task: Any) -> Dict[str, Any]:
            try:
                from .juniors.prompt_registry import resolve_junior_prompt
                system_instruction = resolve_junior_prompt(task.persona, db=self.db)
            except Exception:  # noqa: BLE001 - single-turn / lead files: the developer system prompt
                system_instruction = build_developer_system_prompt(
                    service_names=inputs.compute_intent.service_names,  # row L3-PRB-t
                    **({"wiring_contract": topology_contract_rule(
                        inputs.compute_intent.topology,
                        manifest_paths=dag_manifest_paths(inputs.task_dag, inputs.compute_intent.topology) or None)}
                       if inputs.compute_intent.topology is not None else {}))  # lane 10
            system_instruction = with_app_auth_rule(system_instruction, inputs.app_auth_rule,
                                                    task.persona)   # DIRECT-IAP-SKILL-VERIFY
            if inputs.iac_intent is not None and intent_contract.repair_task_needs_intent_prompt(task.files_to_fix):
                system_instruction = intent_contract.repair_system_instruction(inputs.iac_intent, task.persona,
                                                                               system_instruction, task.files_to_fix)
            size = getattr(task, "files_to_fix_tokens", None)
            # SLOW-CALL-FALLBACK: a fallback model's bound is sized for its own family from the same task size
            sizing = ((lambda m: (repair_call_max_output_tokens(rt.settings, size, model=m),
                                  repair_call_thinking_budget(rt.settings, model=m))) if size is not None else None)
            # RT F6: the walk inside one repair iteration is bounded by this dispatch's repair wall clock (the loop
            # itself checks it only between iterations)
            wall_s = getattr(rt.settings, "repair_wall_clock_s", None)
            repair_deadline = (repair_window["start"] + float(wall_s)
                               if repair_window["start"] is not None and wall_s else None)
            return dispatcher.invoke_repair(task.persona, system_instruction, task.prompt(), repair_model,
                                            task.max_output_tokens, trace_id=trace,
                                            thinking_budget=task.thinking_budget,
                                            **({"deadline": inputs.llm_deadline}
                                               if getattr(inputs, "llm_deadline", None) is not None else {}),
                                            **({"repair_deadline": repair_deadline}
                                               if repair_deadline is not None else {}),
                                            **({"stage_stop": inputs.llm_stage_stop}
                                               if getattr(inputs, "llm_stage_stop", None) is not None else {}),
                                            **({"sizing": sizing} if sizing is not None else {}))

        repair_window: Dict[str, Optional[float]] = {"start": None}   # RT F6: set when each dispatch starts
        repair_call_room = self._repair_call_room(repair_window, rt.settings, dispatcher)   # RT F2
        required_targets = dispatch_plan_targets(inputs, qa_plan, deploy_plan)   # PLAN-TARGET-FILES
        manifest_paths = dag_manifest_paths(inputs.task_dag, inputs.compute_intent.topology)   # MANIFEST-PATH-...

        stack = build_step1_stack(validate_client=rt.validate_client,
                                  verifier_factory=lambda: _Verifier(product_id=product_id),
                                  iac_engine=getattr(self, "iac_engine", "OPENTOFU") or "OPENTOFU",
                                  network_facts=holder, existing_network=existing_network,
                                  topology=inputs.compute_intent.topology,   # lane 10: V-T3 on the topology path
                                  platform_values=deploy_platform_values(product_id, inputs.region,
                                                                         inputs.target_project_id),   # FD-55 W4: V2k
                                  access=inputs.run_access,   # FD-4AQ W4: V2l (AQ-4)
                                  # FD-55 W5 (FD55-W5): V3c-planned, a planned Cloud Run service without code
                                  planned_services=planned_holder,
                                  # V1B-WARMUP-RETRY: V1b's wait before asking a warming server again
                                  validate_ready_wait_s=float(getattr(rt.settings, "validate_ready_wait_s", 0) or 0),
                                  plan_targets=required_targets,   # PLAN-TARGET-FILES: V-PLAN-TARGETS
                                  manifest_paths=manifest_paths or None,   # MANIFEST-PATH-DEFERS-TO-DAG: V3c-k8s
                                  **({"iac_intent": inputs.iac_intent} if inputs.iac_intent is not None else {}))
        ctx = LoopContext(trace_id=trace, product_id=product_id, assemble=assemble, stack=stack,
                          ledger_store=rt.ledger_store, settings=rt.settings,
                          attribution=dict(inputs.swarm_attribution), llm_draft_paths=llm_paths,
                          preexisting=set(inputs.existing_files or {}), prior_llm=dict(inputs.prior_llm or {}),
                          preexisting_files=dict(inputs.existing_files or {}),
                          repair_fn=repair if self.genai_client is not None else None, model=repair_model,
                          available_providers=gate["providers"], engine_label=gate["engine_label"],
                          topology=inputs.compute_intent.topology,   # FD55-W5c-PLAN-FACTS
                          repair_call_room=repair_call_room,   # REPAIR-WALL-CLOCK-ROOM (RT F2)
                          plan_targets={t.path: t.siblings for t in required_targets},   # PLAN-TARGET-FILES
                          manifest_services={p: svc for svc, paths in manifest_paths.items() for p in paths},
                          **({"seed_diagnostics": tuple(deploy_plan.seeds),   # TI-5-R3: repair only the intent
                              "seed_entries": dict(deploy_plan.seed_entries),
                              "repairable_paths": deploy_repair.REPAIRABLE_PATHS} if deploy_plan is not None else {}),
                          # QA-FEEDBACK: QA's findings are the seeds; repairs may edit only the files QA named
                          **({"seed_diagnostics": tuple(qa_plan.seeds), "seed_files": dict(qa_plan.seed_files),
                              "repairable_paths": qa_plan.repairable_paths,
                              "requirements_guard": dict(qa_plan.requirements_guard),
                              "requirements_crash_guard": dict(qa_plan.requirements_crash_guard),
                              "untrusted_output": qa_plan.untrusted_output} if qa_plan is not None else {}))
        loop = RepairLoop(ctx)
        repair_window["start"] = time.monotonic()   # RT F6: this dispatch's repair wall clock starts now
        try:
            tree, report = loop.run(draft)
        except StageError as e:
            events = self._junior_reask_events(inputs.trace_id, product_id) + list(ctx.events)
            self._record_stack(inputs.trace_id, validation_report=e.report, repair_events=events,
                               envelope_checks=list(getattr(self, "_last_envelope_checks", []) or []))
            self._persist_stack_outcome(inputs.trace_id, e.report, events, error=e)
            logger.warning(f"Developer stage stopped for '{product_id}': {type(e).__name__} "
                           f"{e.error_class.value if e.error_class else ''}: "
                           f"{sorted({d.code for d in e.report.diagnostics})[:20]}")
            raise
        if inputs.iac_intent is not None:   # TI-3i-c: one repair turn before a plan-named stop
            repair_window["start"] = time.monotonic()   # RT F6: the turn is its own dispatch
            tree, report = self._intent_repair_turn(inputs, ctx, loop, tree, report, RepairLoop)
        self._record_repair_model_provenance(inputs.trace_id, ctx.events, repair_model)   # SLOW-CALL-FALLBACK
        events = self._junior_reask_events(inputs.trace_id, product_id) + list(ctx.events)
        if inputs.iac_intent is not None:   # TI-3i: dropped entries -> workload warnings; a plan-named one stops
            self._intent_drop_outcome(inputs, ctx.intent_drops, tree, events)
        # SAT-49 (Fable RT F3): the loop's final draft set (renamed repair files joined `llm_paths`): what the gateway
        # records for this dispatch's commit (main._record_committed_draft) as the next repair's draft
        # QA-REPAIR-MISSING-MODULE (RT F4): a gatekeeper-written requirements file the plan lent to this repair stays
        # the platform's unless the committed tree changed it (exact content, the tested one from the plan)
        lent = getattr(qa_plan, "platform_paths", frozenset()) if qa_plan is not None else frozenset()
        unchanged_lent = {p for p in lent if tree.get(p) == qa_plan.seed_files.get(p)}
        self._record_stack(inputs.trace_id, validation_report=report, repair_events=events,
                           validated_hash=report.artifact_hash,
                           envelope_checks=list(getattr(self, "_last_envelope_checks", []) or []),
                           llm_draft_paths=sorted(set(llm_paths) - unchanged_lent))
        self._persist_stack_outcome(inputs.trace_id, report, events)
        self._runtime_env_outcome(inputs, tree, stack)   # RUNTIME-ENV-CONTRACT-CHECK: visibility only
        self._decide_app_orphans(inputs, tree)   # SAT-49 F4: the earlier build's unchanged orphans this commit deletes
        return tree

    def _intent_repair_turn(self, inputs: "AssemblyInputs", ctx: Any, loop: Any, tree: Dict[str, str],
                            report: Any, loop_cls: Any) -> Tuple[Dict[str, str], Any]:
        """TI-3i-c (FOLLOWUPS-1025, owner 10-25): when the passing tree would stop as plan-named
        (intent_contract.intent_outcome), the IaC persona gets ONE repair turn first: the same repair loop on the
        passing draft, one iteration, its findings = intent_contract.repair_turn_seeds (recomputed on every candidate's
        assembled tree, with the drops of the first loop). The loop's own rules decide (accept, preservation, removal
        justification, token / wall-clock / total-iteration budgets). A candidate that passes replaces the tree (its
        drops join ctx.intent_drops); anything else keeps the first tree, so _intent_drop_outcome raises the typed
        stop. A stop with no typed way to provide it (then the build stops whatever the turn does), no repair model, or
        an intent the run may not edit: no turn, no spend."""
        art, topology = inputs.iac_intent.artifacts, inputs.compute_intent.topology
        plan_apis = tuple(self.stack_run(inputs.trace_id).get("plan_required_apis") or ())
        drops0 = [dict(x) for x in ctx.intent_drops]
        warnings, _stops = intent_contract.intent_outcome(drops0, tree, topology, plan_apis, art)
        seeds = intent_contract.repair_turn_seeds(warnings, art, topology)
        if not seeds:
            return tree, report
        stopping = sum(1 for w in warnings if w.get("stops_build"))
        if len(seeds) < stopping:   # a stop without a typed way stops the build whatever the turn does
            reason = "STOP_WITHOUT_TYPED_WAY"
        elif ctx.repair_fn is None:
            reason = "NO_REPAIR_MODEL"
        elif ctx.repairable_paths is not None and intent_contract.INTENT_PATH not in ctx.repairable_paths:
            reason = "INTENT_NOT_REPAIRABLE"
        elif loop.final_draft is None:
            reason = "NO_PASSING_DRAFT"
        else:
            reason = None
        if reason is not None:
            self._record_stack(inputs.trace_id, intent_repair_turn={"ran": False, "reason": reason,
                                                                    "codes": sorted({d.code for d in seeds})})
            return tree, report

        def still_stopping(candidate: Mapping[str, str]) -> List[Any]:
            w, _s = intent_contract.intent_outcome(drops0, candidate, topology, plan_apis, art)
            return intent_contract.repair_turn_seeds(w, art, topology)

        turn_ctx = replace(ctx, settings=ctx.settings.model_copy(update={"repair_max_iterations_precommit": 1}),
                           seed_check=still_stopping, events=[], intent_drops=[])
        outcome: Dict[str, Any] = {"ran": True, "codes": sorted({d.code for d in seeds})}
        try:
            tree2, report2 = loop_cls(turn_ctx).run(dict(loop.final_draft))
        except StageError as e:   # RepairBudgetExhausted included: the typed plan-named stop follows
            outcome.update(result="NOT_FIXED", reason=str(getattr(e, "exhausted_reason", "") or type(e).__name__),
                           error_class=e.error_class.value if e.error_class else None)
            tree2 = report2 = None
        finally:
            ctx.events.extend(turn_ctx.events)
        if tree2 is None:
            logger.warning(f"Typed IaC intent repair turn did not fix the plan-named stop for "
                           f"'{inputs.product_id}': {outcome.get('reason')}")
            self._record_stack(inputs.trace_id, intent_repair_turn=outcome)
            return tree, report
        ctx.intent_drops.extend(turn_ctx.intent_drops)
        outcome.update(result="PASSED")
        self._record_stack(inputs.trace_id, intent_repair_turn=outcome)
        return tree2, report2

    RUNTIME_ENV_LOG_MAX = 50   # WARNING lines per build; one summary line names the rest

    def _app_admin_outcome(self, product_id: str, trace_id: Optional[str], run_access: Any,
                           app_admin_emails: Optional[Tuple[str, ...]]) -> None:
        """APP-ADMIN-DEFAULT (owner 11-16): the typed record of the admin list a Direct IAP Cloud Run build renders,
        `workloads/{product_id}.app_admin_contract` = {admin_count, source (record / submitter / none), warning,
        admin_list_sha256 (shared.access_policy.app_admin_list_digest), trace_id} (never an address), replaced on every
        such build, plus the stack record. The Control Center's Fast-Path check (access_only_fast_path) compares the
        digest with the list the current access record gives, so an access change that changes the admins takes a full
        build.
        An empty list is warn-and-continue (fail-loudly policy section 2): the app is built and deployed, nobody holds
        its privileged role, and the warning APP_ADMIN.NONE_CONFIGURED is logged and stored here; the generated code
        still grants no administrator any other way (developer rule, QA judges). Nothing for any other workload
        (None). A failed write is logged (APP_ADMIN_RECORD_FAILED), never changes the build."""
        if app_admin_emails is None:
            return
        count = len(app_admin_emails)
        source = getattr(run_access, "app_admin_source", "none")
        warning = APP_ADMIN_NONE_CONFIGURED if count == 0 else None
        from shared.access_policy import app_admin_list_digest   # imported by resolve_access for this record

        record = {"admin_count": count, "source": source, "warning": warning,
                  "admin_list_sha256": app_admin_list_digest(app_admin_emails), "trace_id": trace_id or ""}
        if warning:
            logger.warning(f"{warning} '{product_id}' (trace {trace_id or '-'}): no app administrator is configured "
                           f"(access record app_admin_emails empty, and no verified submitter who is an exact user "
                           f"invoker); a privileged role in the app is held by nobody")
        else:
            logger.info(f"App administrators for '{product_id}' (trace {trace_id or '-'}): {count} from {source}")
        self._record_stack(trace_id, app_admin_contract=dict(record))
        db = getattr(self, "db", None)
        if db is not None and product_id:
            try:
                db.collection("workloads").document(product_id).set({APP_ADMIN_CONTRACT_FIELD: record}, merge=True)
            except Exception as we:  # noqa: BLE001 - visibility only; logged, never changes the outcome
                logger.warning(f"APP_ADMIN_RECORD_FAILED '{product_id}': the app administrator record was not stored "
                               f"on the workload record ({type(we).__name__}: {we})")

    def _runtime_env_outcome(self, inputs: "AssemblyInputs", tree: Mapping[str, str], stack: Any) -> None:
        """RUNTIME-ENV-CONTRACT-CHECK (owner 11-10, warning-only for launch): V-ENV's findings on the validated tree
        (the same pure function of the same tree, repository files and topology the stack ran) become
        `workloads/{product_id}.runtime_env_advisories` (the kept findings, at most runtime_env_facts.MAX_FINDINGS)
        with `runtime_env_advisories_total` (all of them), replaced on every passing build ([] clears; shown on the
        Control Center workload page), and at most RUNTIME_ENV_LOG_MAX WARNING lines plus one summary line. Visibility
        only: never changes the tree, the report, a prompt or the stage outcome; a failure is logged with a typed code
        (RUNTIME_ENV_CHECK_FAILED / RUNTIME_ENV_RECORD_FAILED; fail-loudly policy §2, validator roll-out) and the
        stack's report keeps the same findings in `report_only`. Nothing is written when V-ENV is "off" or the build
        has no topology (the check does not apply there: legacy path, no typed env set)."""
        if inputs.compute_intent.topology is None:
            return
        try:
            try:
                from .validators.runtime_env import VALIDATOR_ID
                from .runtime_env_facts import runtime_env_result
            except ImportError:  # pragma: no cover - imported as a top-level module
                from developer_agent.validators.runtime_env import VALIDATOR_ID  # type: ignore[no-redef]
                from developer_agent.runtime_env_facts import runtime_env_result  # type: ignore[no-redef]
            if stack.mode_of(VALIDATOR_ID) == "off":
                return
            result = runtime_env_result(inputs.compute_intent.topology, tree,
                                        deployed_files=deployed_view(tree, inputs.existing_files))
        except Exception as fe:  # noqa: BLE001 - visibility only; the report's report_only keeps the findings
            logger.warning(f"RUNTIME_ENV_CHECK_FAILED for '{inputs.product_id}': {type(fe).__name__}: {fe}")
            return
        records = [f.record() for f in result.findings]
        self._record_stack(inputs.trace_id, runtime_env_advisories=records,
                           runtime_env_advisories_total=result.total)
        logged = result.findings[:self.RUNTIME_ENV_LOG_MAX]
        for f in logged:
            logger.warning(f"RUNTIME_ENV_ADVISORY {f.code} '{inputs.product_id}': {f.message}")
        if result.total > len(logged):
            logger.warning(f"RUNTIME_ENV_ADVISORY_SUMMARY '{inputs.product_id}': {result.total} findings, "
                           f"{len(logged)} logged, {len(records)} stored")
        db = getattr(self, "db", None)
        if db is not None and inputs.product_id:
            try:
                db.collection("workloads").document(inputs.product_id).set(
                    {"runtime_env_advisories": records, "runtime_env_advisories_total": result.total,
                     "runtime_env_advisories_trace_id": inputs.trace_id or ""}, merge=True)
            except Exception as we:  # noqa: BLE001 - visibility only; logged, never changes the outcome
                logger.warning(f"RUNTIME_ENV_RECORD_FAILED '{inputs.product_id}': the runtime env advisories were not "
                               f"stored on the workload record ({type(we).__name__}: {we})")

    def _intent_drop_outcome(self, inputs: "AssemblyInputs", drops: List[Any], tree: Dict[str, str],
                             events: List[Any]) -> None:
        """TI-3i (register, owner 10-21): the entries the repairs removed as IAC.TYPE_NOT_ALLOWED /
        IAC.MODULE_UNKNOWN become `workloads/{product_id}.iac_intent_warnings` (replaced on every intent-path build,
        [] clears; shown on the Control Center workload page). An entry the architect's typed plan names and the build
        no longer provides stops the stage (IAC.REQUESTED_SERVICE_DROPPED) instead of shipping without it.
        TI-3i-e (IAC.PLAN_API_NOT_PROVIDED) is held for 0.9.1, owner decision pending (intent_contract.intent_outcome)."""
        warnings, stops = intent_contract.intent_outcome(
            drops, tree, inputs.compute_intent.topology,
            self.stack_run(inputs.trace_id).get("plan_required_apis") or (), inputs.iac_intent.artifacts)
        # SECRET-INITIAL-VERSION: a secret the plan marks "random" that already exists in the repository gets no
        # platform version; the operator sees it with the other typed-intent warnings (never stops the build). Red-team
        # F9: first in the list, so the list's bound never drops it behind removed entries
        _generated, secret_warnings = intent_contract.secret_generation(inputs.compute_intent.topology,
                                                                        getattr(inputs, "existing_files", None))
        warnings = (list(secret_warnings) + list(warnings))[:intent_contract.WARNINGS_MAX]
        self._record_stack(inputs.trace_id, iac_intent_warnings=warnings)
        db = getattr(self, "db", None)
        if db is not None and inputs.product_id:
            try:
                db.collection("workloads").document(inputs.product_id).set(
                    {"iac_intent_warnings": warnings, "iac_intent_warnings_trace_id": inputs.trace_id or ""},
                    merge=True)
            except Exception as we:  # noqa: BLE001 - visibility only; logged, never changes the outcome
                logger.warning(f"Could not store the typed-intent warnings of '{inputs.product_id}': {we}")
        for w in warnings:
            logger.warning(f"Typed IaC intent warning for '{inputs.product_id}': {w['message']}")
        if stops:
            report = ValidationReport(status="FAIL", source="precommit", artifact_hash="", diagnostics=stops)
            self._record_stack(inputs.trace_id, validation_report=report, repair_events=events)
            err = StageError(report, f"{'/'.join(sorted({d.code for d in stops}))}: "
                                     + "; ".join(d.message for d in stops))
            self._persist_stack_outcome(inputs.trace_id, report, events, error=err)
            raise err

    def _resolve_network_facts(self, rt: Any, inputs: "AssemblyInputs", needed: Any, *, allocate: bool = True) -> Any:
        """The workload's IPAM facts for the purposes the draft needs (lane 11 near-term). Fail-closed: no provider,
        unreadable settings or an IPAM error stop the stage with GATE_UNAVAILABLE (no further LLM spend).

        `allocate=False` (existing network, code RT F3): reuse-only. The provider returns this product's own ledger
        records and never creates one. A reused fact is rendered only when the repository's committed platform tfvars
        already carry that fact variable (the workload was generated with facts): a pre-facts workload's live range is
        in its own code, and binding its `var.subnet_cidr` to a ledger record could move the range. A committed fact
        that the ledger does not hold, or holds with another value, stops the stage (never re-derived, never
        dropped: dropping it is what let the legacy preflight declare an invented default)."""
        def unavailable(reason: str) -> StageError:
            return StageError(ValidationReport(status="UNAVAILABLE", source="precommit", artifact_hash="",
                                               tools_unavailable=["platform_facts"]), reason)
        committed: Dict[str, str] = {}
        if not allocate:
            try:
                committed = committed_fact_values(inputs.existing_files)
            except FactsUnavailable as e:
                raise unavailable(str(e)) from e
            if not committed:
                return None   # a workload generated before facts: nothing to reuse, no IPAM access needed
        provider = getattr(rt, "facts_provider", None)
        if provider is None:
            raise unavailable(f"no IPAM facts provider configured; the draft needs {sorted(needed)}")
        try:
            # FD-4AK (code RT F6.3): load_ipam_pool reads the settings strictly -- an unreadable or invalid settings
            # document raises a typed PlatformSettingsUnavailable (the stage stops), never the compile-time pool.
            pool = load_ipam_pool(self.project_id)   # FD-4BZ RT F2: the same reader as the architect stage
        except Exception as e:  # noqa: BLE001 - an unusable settings object stops the stage
            raise unavailable(f"IPAM pool settings unavailable: {type(e).__name__}: {e}") from e
        # FD-7M-a: the ledger records carry the workload's region (this dispatch's one region); None (direct callers)
        # or the default region leaves the pool unchanged.
        pool = pool.for_region(inputs.region)
        try:
            if allocate and inputs.iac_intent is not None:
                # TI-5c (Fable RT F3): an intent workload's network is platform-rendered from these facts, so a
                # committed value the ledger does not return identically would move a live range (subnet /
                # connector replacement). The committed purposes this draft needs are resolved REUSE-ONLY first
                # (nothing is created) and compared; only then are the new purposes allocated. A mismatch stops the
                # stage before any allocation (never re-derived, never silently changed, no leaked record).
                intent_committed = committed_fact_values(inputs.existing_files)
                held = {FACT_PURPOSE[n] for n in intent_committed} & set(needed)
                reused_facts = None
                if held:
                    reused_facts = provider.resolve(inputs.product_id, frozenset(held), pool=pool,
                                                    project_id=inputs.target_project_id or "", allocate=False)
                    reused = reused_facts.variables() if reused_facts is not None else {}
                    for name, value in intent_committed.items():
                        if FACT_PURPOSE[name] in held and reused.get(name) != value:
                            raise FactsUnavailable(
                                f"IPAM.LEDGER_MISMATCH: the committed {name} = {value} is "
                                f"{'held as ' + reused[name] if name in reused else 'not held'} by the IPAM "
                                f"ledger for {inputs.product_id}")
                new = frozenset(set(needed) - held)
                if not new:
                    return reused_facts
                fresh = provider.resolve(inputs.product_id, new, pool=pool,
                                         project_id=inputs.target_project_id or "", allocate=True)
                if reused_facts is None:
                    return fresh
                # disjoint purposes (held vs new): the reused values join the fresh allocation's facts
                return fresh.model_copy(update=dict(reused_facts.variables()))
            wanted = set(needed) | {FACT_PURPOSE[name] for name in committed}
            facts = provider.resolve(inputs.product_id, frozenset(wanted), pool=pool,
                                     project_id=inputs.target_project_id or "", allocate=allocate)
            if allocate:
                return facts
            reused = facts.variables() if facts is not None else {}
            for name, value in committed.items():
                if reused.get(name) != value:
                    raise FactsUnavailable(f"IPAM.LEDGER_MISMATCH: the committed {name} = {value} is "
                                           f"{'held as ' + reused[name] if name in reused else 'not held'} by the "
                                           f"IPAM ledger for {inputs.product_id}")
            return facts.restricted_to(committed)
        except FactsUnavailable as e:
            raise unavailable(str(e)) from e

    STACK_PERSIST_MAX_DIAGNOSTICS = 50
    STACK_PERSIST_MAX_EVENTS = 50

    def _junior_reask_events(self, trace_id: Optional[str], product_id: str) -> List[Any]:
        """Code RT F4: every typed JSON re-ask of a swarm junior (HS-61) as a RepairEvent(kind="junior_reask"), so
        the run record shows its cost. Bounded by the junior's own 3 retries; not counted against the 5-iteration /
        250k repair budget (the repair loop's ledger never sees them)."""
        out = []
        for r in list(getattr(self, "_last_junior_reasks", []) or []):
            out.append(RepairEvent(trace_id=trace_id or "", product_id=product_id, iteration=0, source="precommit",
                                   persona=str(r.get("persona") or ""), files=list(r.get("files") or []),
                                   # TI5-TRUNC: a truncation re-ask carries its own code (JSON.OUTPUT_TRUNCATED)
                                   codes=[str(r.get("code") or "JSON.OUTPUT_INVALID")], fingerprints_before=[],
                                   fingerprints_after=[],
                                   accepted=False, reject_reason="ENVELOPE_INVALID", model=str(r.get("model") or ""),
                                   kind="junior_reask", task_id=r.get("task_id"), attempt=r.get("attempt"),
                                   detail=r.get("error")))
        return out

    def _persist_stack_outcome(self, trace_id: Optional[str], report: Any, events: List[Any],
                               error: Optional[BaseException] = None) -> None:
        """Lane 8B §6.4 / Step 1 code RT F4: the final ValidationReport and the RepairEvents go to
        pipeline_executions/{trace}.stages.developer (merge; best-effort, logged on failure) on PASS and on every
        typed failure, so the operator/Control Center sees the diagnostics, not only an error string. Bounded so the
        document stays far below Firestore's 1 MiB limit. No db (tests, eval harness) -> nothing written."""
        db = getattr(self, "db", None)
        if db is None or not trace_id:
            return
        try:
            rep = report.model_dump(mode="json")
            for key in ("diagnostics", "report_only"):
                items = rep.get(key) or []
                rep[f"{key}_total"] = len(items)
                rep[key] = items[:self.STACK_PERSIST_MAX_DIAGNOSTICS]
            payload: Dict[str, Any] = {
                "validation_report": rep,
                "repair_events": [ev.model_dump(mode="json") for ev in list(events or [])[-self.STACK_PERSIST_MAX_EVENTS:]],
            }
            if error is not None:
                payload["error_class"] = report.error_class.value if report.error_class else None
                payload["exhausted_reason"] = getattr(error, "exhausted_reason", None)
            db.collection("pipeline_executions").document(trace_id).set({"stages": {"developer": payload}}, merge=True)
        except Exception as pe:  # noqa: BLE001 - telemetry only: never changes the stage outcome
            logger.warning(f"Could not persist the developer validation report for {trace_id}: {type(pe).__name__}: {pe}")

    @staticmethod
    def _service_kind(svc: str, archetype: str, intent: "ComputeIntent") -> str:
        """A CI workflow's compute kind, from the typed compute intent only. Lane 10: on the topology path a topology
        service has its own typed kind and any other directory gets the primary archetype. FD-55 W8 (register
        FD55-W8; plan G19): without a topology the intent's own service-list contract decides the same way: a planned
        secondary (`service_names[1:]`) is a Cloud Run service (the compute-cloudrun module the platform renders for
        it), the primary and any other directory get the primary archetype. The deleted HD-03
        `resolve_service_archetype` read the AI's HCL and name substrings instead (tombstone above).
        The directory name is normalized exactly as the intent's service names are (normalize_service_name: trim,
        lower case, `_` -> `-`), so `apps/Edge_Svc/` is the planned `edge-svc` (W8 review F1; was `_` -> `-` only)."""
        name = normalize_service_name(svc)
        if intent.topology is not None:
            return intent.topology.kind(name) or archetype
        return "cloudrun" if name in intent.secondary_services else archetype

    @staticmethod
    def _topology_primary_overrides(vt: Any, bespoke_hcl: Optional[str], files: Dict[str, str],
                                    allow_unauthenticated: Optional[bool] = None,
                                    deployed_files: Optional[Mapping[str, str]] = None
                                    ) -> Tuple[Optional[Dict[str, str]], Optional[Dict[str, Any]]]:
        """Lane 10: the Cloud Run primary's env (edges + resources + HB-05 non-sibling bindings, same caller
        argument as today: none) and its scaling when the architect stated it. (None, None) on the legacy path.
        `deployed_files` (topology_wiring.deployed_view): read only by the audience decision (RT F1)."""
        if vt is None or vt.primary is None or vt.primary.kind != "cloudrun":
            return None, None
        env = topology_env_vars(vt, vt.primary.name, bespoke_hcl, files, caller_service=None,
                                allow_unauthenticated=allow_unauthenticated,   # SIBLING-AUDIENCE-BINDING
                                deployed_files=deployed_files)   # SIBLING-AUDIENCE-GETENV-DEFAULT RT F1
        sc = topology_scaling(vt, vt.primary.name, 0, 10)
        scaling = ({"min_instances": sc["min_instances"], "max_instances": sc["max_instances"],
                    "cpu_idle": bool(sc["cpu_idle"])} if sc["from_topology"] else None)
        return env, scaling

    def _assemble_tree_typed(self, draft: Dict[str, str],
                             inputs: "AssemblyInputs") -> Tuple[Dict[str, str], Dict[str, Any]]:
        """`_assemble_tree` with the APP-ADMIN-IAP-CONTRACT render refusal typed: an env binding that already uses the
        platform-owned STACKVEND_APP_ADMIN_EMAILS key (terraform_engine.AppAdminEnvCollision) stops the stage as
        PlatformDefectError APP_ADMIN_ENV_COLLISION (nothing generated is committed), never an untyped crash."""
        try:
            return self._assemble_tree(draft, inputs)
        except AppAdminEnvCollision as collision:
            raise PlatformDefectError(
                f"'{inputs.product_id}': {collision}. Nothing was committed; the binding that uses the platform's "
                "app administrator env key must be renamed.", reason=APP_ADMIN_ENV_COLLISION,
                stage="developer") from collision

    def _assemble_tree(self, draft: Dict[str, str], inputs: "AssemblyInputs") -> Tuple[Dict[str, str], Dict[str, Any]]:
        """Platform assembly of one developer draft (Step 1 S1-B `assemble()`): golden renders, the S1-A assembly
        contract, HB-04/HB-01, vendoring, container contract, gatekeeper cures, R-class healers until S1-D.
        Deterministic in (draft, inputs); makes no LLM call (lane 8B §6.1). The draft is never mutated."""
        files = dict(draft)
        product_id = inputs.product_id
        spec_text = inputs.spec_text
        trace_id = inputs.trace_id
        plan_markdown = inputs.plan_markdown
        plan_file_path = inputs.plan_file_path
        domain_restricted_sharing = inputs.domain_restricted_sharing
        allow_unauthenticated = inputs.allow_unauthenticated
        enable_direct_iap = inputs.enable_direct_iap
        target_compute_services = inputs.target_compute_services
        existing_files = inputs.existing_files
        prior_llm = inputs.prior_llm
        llm_draft_paths = inputs.llm_draft_paths
        swarm_attribution = inputs.swarm_attribution
        target_project_id = inputs.target_project_id
        project_number = inputs.project_number
        workload_vcs = inputs.workload_vcs
        stored_repo = inputs.stored_repo
        auth_invokers = inputs.auth_invokers
        # 1. Compute archetype and service set: the typed compute intent resolved before generation (HD-01/HD-02
        #    replacement; compute_intent.py). Never re-derived from the spec or from the draft.
        intent: ComputeIntent = inputs.compute_intent
        archetype = intent.archetype
        # Lane 10 (FD-51): the validated per-service topology (None on the legacy record path). Its review file
        # infra/workload/topology.json is platform-owned: an LLM-authored one is never kept (rendered below).
        vt = intent.topology
        files.pop(TOPOLOGY_JSON_PATH, None)

        # 2. Enforce deterministic golden CI/CD workflow generation:
        # Purge any LLM-authored .github/workflows/ or cloudbuild.yaml entries to eliminate hallucinated syntax bugs
        for k in list(files.keys()):
            if k.startswith(".github/workflows/") or k == "cloudbuild.yaml":
                del files[k]

        # Resolve dynamic container sizing profile from requirements and spec intent
        sizing = apply_platform_container_baseline(resolve_workload_sizing(files, spec_text=spec_text),
                                                   inputs.compute_defaults)   # FD-4CI-b
        default_min = platform_default_min_instances(inputs.compute_defaults)   # FD-4CI-b: 0 = today

        effective_vcs = (
            workload_vcs
            or getattr(self, "vcs_provider", None)
            or ("SERVERLESS_GIT" if (stored_repo and "serverless-git" in str(stored_repo).lower()) else None)
        )
        # GHA-DEPLOY-SWITCH: off only on a GitHub workload whose switch is off (Serverless Git ignores it). Off: no
        # deploy workflow is generated, the foundation renders without the GitHub Actions deploy resources, and the
        # workflow files an earlier run committed are deleted by this commit (recorded below, typed).
        gha_deploy_on = inputs.github_actions_deploy or str(effective_vcs).upper() == "SERVERLESS_GIT"
        self._record_stack(inputs.trace_id, gha_workflow_deletions=(
            [] if gha_deploy_on else gha_workflow_paths(existing_files or {})))

        # Foundation-only workloads have zero compute services and no CI/CD workflows
        if archetype in ("foundation-only", "none", "empty"):
            for k in list(files.keys()):
                if k.startswith("apps/") or k.startswith(".github/workflows/") or k in ("main.py", "app.py", "Procfile", "requirements.txt", "cloudbuild.yaml"):
                    del files[k]
        else:
            # lane 10 (RT F2): on the topology path CI deploys exactly the planned services (an unplanned
            # apps/<x>/ gets no `gcloud run deploy` workflow); the legacy path is unchanged.
            services = workflow_services(vt) if vt is not None else detect_workload_services(files, product_id)
            if str(effective_vcs).upper() == "SERVERLESS_GIT":
                if VCSProviderFactory is not None:
                    vcs = VCSProviderFactory.get_provider(
                        provider_name="SERVERLESS_GIT",
                        default_owner=self.github_owner,
                        project_id=self.project_id,
                        product_id=product_id,
                    )
                    for svc in services:
                        # FD-7M-a: the committed cloudbuild.yaml names the workload's region (`_REGION`)
                        pipeline_cfg = vcs.get_pipeline_contract(svc, product_id, region=inputs.region)
                        files[pipeline_cfg.target_file] = getattr(pipeline_cfg, "template_content", getattr(pipeline_cfg, "content", ""))
            elif gha_deploy_on:   # GHA-DEPLOY-SWITCH: off = no GitHub Actions deploy workflow
                wf_scaling = extract_scaling_from_spec(spec_text, default_min_instances=default_min)
                wf_min = wf_scaling.get("min_instances", 0)
                wf_max = wf_scaling.get("max_instances", 10)
                for svc in services:
                    wf_name = f".github/workflows/deploy-{svc}.yml"
                    svc_archetype = self._service_kind(svc, archetype, intent)
                    files[wf_name] = generate_service_workflow(
                        svc,
                        product_id,
                        target_project_id,
                        project_number,
                        archetype=svc_archetype,
                        allow_unauthenticated=allow_unauthenticated,
                        memory_limit=sizing.memory_limit,
                        cpu_limit=sizing.gcloud_cpu,
                        min_instances=wf_min,
                        max_instances=wf_max,
                        region=inputs.region,
                        branch=inputs.deploy_branch,   # FD-4CI-b-R1
                        branch_secrets=inputs.deploy_secrets_branch_named,   # FD-4CI-b-R1-WIF-SHARED
                    )

        # Incorporate any existing repository custom infrastructure files
        for p, content in (existing_files or {}).items():
            if (p.startswith("infra/workload/") or p.startswith("infra/workloads/") or (p.startswith("infra/") and "/" not in p[6:])) and p.endswith(".tf"):
                if p not in files:
                    files[p] = content

        # 3. Step 1 S1-A assembly contract (integration plan §S.5; register HS-01, HS-08). Replaces the Tier-3
        #    consolidation (HB-03 extraction, plural purge, HB-02 dedupe, custom.tf rewrite) and the HA-10 stem purge:
        #    the AI's files at platform-rendered paths are appended verbatim to custom.tf, its other .tf files stay in
        #    place, and the only removals are exact-key splices of platform root declarations / prior declarations,
        #    each recorded in the AssemblyRecord. No .tf file under infra/workload/ is deleted.
        full_repo_name = self.get_full_repo_name(product_id)
        # TI-1: on the topology path the secondaries are rendered into services.tf (platform file), so their keys are
        # platform root keys: an AI copy is an exact recorded PLATFORM_ROOT_DECLARATION. A secondary a repository
        # file (still in the tree) already declares is neither rendered nor a root key (never duplicated / removed).
        try:
            from .terraform_engine import services_tf_root_keys, services_tf_skip_addresses
        except ImportError:  # pragma: no cover - top-level import of this module (same ladder as the module imports)
            from developer_agent.terraform_engine import services_tf_root_keys, services_tf_skip_addresses
        services_skip = services_tf_skip_addresses(files, existing_files) if vt is not None else frozenset()
        root_keys = services_tf_root_keys(vt, services_skip) | platform_root_keys({
            "infra/workload/main.tf": generate_golden_main_tf(
                product_id, archetype, spec_text, allow_unauthenticated=allow_unauthenticated,
                authorized_invoker_members=auth_invokers, enable_direct_iap=enable_direct_iap,
                regulated=inputs.regulated,   # lane 14 PR-0b: module.cmek is a platform root key when regulated
                default_min_instances=default_min,   # FD-4CI-b
                github_default_branch=inputs.deploy_branch,   # FD-4CI-b-R1-WIF
                github_actions_deploy=gha_deploy_on,   # GHA-DEPLOY-SWITCH: on = byte-identical
                # IAP-GATE-KNOWN-MEMBER: the same data key the final render declares (reconcile has not run yet)
                cloud_run_secondaries=bool(planned_cloud_run_services(archetype, product_id,
                                                                      list(intent.service_names), vt)),
                app_admin_emails=inputs.app_admin_emails),   # APP-ADMIN-IAP-CONTRACT: None = byte-identical
            "infra/workload/variables.tf": generate_golden_variables_tf(
                product_id, full_repo_name, allow_unauthenticated=allow_unauthenticated,
                authorized_invoker_members=auth_invokers, enable_direct_iap=enable_direct_iap, region=inputs.region,
                github_default_branch=inputs.deploy_branch,   # FD-4CI-b-R1-WIF
                github_actions_deploy=gha_deploy_on,   # GHA-DEPLOY-SWITCH: on = byte-identical
                app_admin_emails=inputs.app_admin_emails)   # APP-ADMIN-IAP-CONTRACT: None = byte-identical
            + render_fact_variables(inputs.network_facts),
            "infra/workload/outputs.tf": generate_golden_outputs_tf(product_id, archetype),
            "infra/workload/moved.tf": generate_golden_moved_tf(product_id, archetype),
        })
        assembly = assemble_root_module(
            files,
            llm_paths=llm_draft_paths,
            preexisting=frozenset(existing_files or {}),
            root_keys=root_keys,
            attribution=swarm_attribution,
            default_persona="LEAD_DEVELOPER",
            trace_id=trace_id or "",
        )
        files = assembly.files
        self._record_stack(trace_id, assembly_record=assembly.record, llm_iac_paths=list(assembly.llm_iac_paths),
                           attribution=dict(swarm_attribution), llm_draft_paths=sorted(llm_draft_paths),
                           prior_llm=dict(prior_llm))
        if assembly.record.replaced:
            logger.info(f"S1-A assembly for '{product_id}': recorded {len(assembly.record.replaced)} exact-key "
                        f"replacement(s): {dict(assembly.record.replaced_reason)}")
        # TI-3 (typed IaC intent): gate the intent, render custom.tf.json from a gate-clean one and bind the topology's
        # consumers to its realizing entries (vt below). Mode "off": nothing runs and vt is unchanged.
        intent_asm = None
        if inputs.iac_intent is not None:
            intent_asm, vt = intent_contract.assemble_intent(files, inputs.iac_intent, vt, root_keys,
                                                             existing_files=existing_files, record=assembly.record,
                                                             network_facts=inputs.network_facts)   # TI-5c
        # PUSH-TO-PRIVATE (owner 10-27): the gate-clean intent's push identities per compute-cloudrun module address
        push_ids = dict(intent_asm.push_identities) if intent_asm is not None else {}
        # FD-4DK: a legacy workload (no service topology, mode "off") has no per-service consumer edge; its platform
        # Cloud Run modules get the one connector on the network of a private database / cache its parsed IaC
        # declares (topology_wiring.legacy_vpc_connector). The AI's drafts at platform paths (main.tf, ...) are read
        # once, where the assembly put them (custom.tf): their stale draft keys are left out (FD-4DK RT F1: read
        # twice, every declaration in them would count as a duplicate). None (topology / typed-intent path, or no
        # such facts) = byte-identical renders.
        legacy_connector = (legacy_vpc_connector({p: t for p, t in files.items()
                                                  if p not in assembly.relocated_draft_paths})
                            if vt is None and inputs.iac_intent is None else None)

        # Reconcile multi-service microservice definitions across main.tf and custom.tf
        planned_services: List[str] = []   # FD-55 W5 RT F2: filled by HB-04 with the Cloud Run services it renders
        if archetype not in ("foundation-only", "none", "empty"):
            reconcile_multi_service_declarations(
                files=files,
                product_id=product_id,
                spec_text=spec_text,
                archetype=archetype,
                allow_unauthenticated=allow_unauthenticated,
                enable_direct_iap=enable_direct_iap,
                authorized_invoker_members=auth_invokers,
                target_services=list(intent.service_names),
                assembly_record=assembly.record,
                llm_iac_paths=list(assembly.llm_iac_paths),
                topology=vt,   # lane 10: exact topology secondaries, edge-only env
                services_tf_skip=services_skip,   # TI-1: secondaries render into services.tf
                regulated=inputs.regulated,   # lane 14 PR-0b: secondaries get the workload key
                default_min_instances=default_min,   # FD-4CI-b: Enforce Scale-to-Zero (0 = today)
                typed_iac=inputs.iac_intent is not None,   # FD55-W2 (TI-4a); HB-01 itself is deleted (FD-55 W5)
                planned_out=planned_services,   # FD-55 W5 RT F2: the services it renders, for V3c-planned
                push_identities=push_ids,   # PUSH-TO-PRIVATE: {} (no push subscription / mode off) = unchanged
                legacy_vpc_connector=legacy_connector,   # FD-4DK: legacy secondaries only; None = unchanged
                relocated_draft_paths=assembly.relocated_draft_paths,   # FD4DK-3: topology connector view
                # SIBLING-AUDIENCE-GETENV-DEFAULT RT F1: the audience decision reads the tree the build deploys
                deployed_files=deployed_view(files, existing_files) if vt is not None else None,
                # RT14-12: a Cloud Run service the repository's custom.tf declares is kept, never replaced
                repository_keys=repository_custom_tf_keys(existing_files),
                app_admin_emails=inputs.app_admin_emails,   # APP-ADMIN-IAP-CONTRACT: None = byte-identical
            )
        # S1-B attribution only: the root module as the S1-A contract + HB-04/HB-01 left it (before the R-class
        # healers below). The AI's relocated draft files (still keyed for today's detection inputs until the golden
        # render) are excluded. V2c does NOT use this snapshot (Step 1 code RT F1): it checks the final root module.
        assembled_root_pre_healers = {
            p: files[p] for p in files if p.startswith("infra/workload/") and p.endswith(".tf")
            and "/" not in p[len("infra/workload/"):] and p not in assembly.record.relocated}

        # Ensure CI/CD workflows exist for all detected microservices (including secondary services)
        if (archetype not in ("foundation-only", "none", "empty") and str(effective_vcs).upper() != "SERVERLESS_GIT"
                and gha_deploy_on):   # GHA-DEPLOY-SWITCH: off = no GitHub Actions deploy workflow
            active_svcs = (workflow_services(vt) if vt is not None   # lane 10 (RT F2)
                           else detect_workload_services(files, product_id))
            wf_scaling = extract_scaling_from_spec(spec_text, default_min_instances=default_min)
            wf_min = wf_scaling.get("min_instances", 0)
            wf_max = wf_scaling.get("max_instances", 10)
            for svc in active_svcs:
                wf_name = f".github/workflows/deploy-{svc}.yml"
                svc_archetype = self._service_kind(svc, archetype, intent)
                files[wf_name] = generate_service_workflow(
                    svc,
                    product_id,
                    target_project_id,
                    project_number,
                    archetype=svc_archetype,
                    allow_unauthenticated=allow_unauthenticated,
                    memory_limit=sizing.memory_limit,
                    cpu_limit=sizing.gcloud_cpu,
                    min_instances=wf_min,
                    max_instances=wf_max,
                    region=inputs.region,
                    branch=inputs.deploy_branch,   # FD-4CI-b-R1
                    branch_secrets=inputs.deploy_secrets_branch_named,   # FD-4CI-b-R1-WIF-SHARED
                )
            # Prune obsolete single-service workflow if product_id is not among active services
            if product_id not in active_svcs and f".github/workflows/deploy-{product_id}.yml" in files:
                del files[f".github/workflows/deploy-{product_id}.yml"]

        # 4. Tier 1 & Tier 2: Deterministic Golden Terraform Foundation & Compute Archetypes
        primary_svc = intent.primary
        # S1-A: the env-var wiring and GKE network detection read every bespoke root-module file (Tier 3 used to
        # consolidate exactly these into custom.tf; they now stay in their own files).
        primary_env, primary_scaling = self._topology_primary_overrides(
            vt, bespoke_root_text(files) or None, files, allow_unauthenticated,
            deployed_files=deployed_view(files, existing_files) if vt is not None else None)   # RT F1
        files["infra/workload/main.tf"] = generate_golden_main_tf(
            product_id,
            archetype,
            spec_text,
            allow_unauthenticated=allow_unauthenticated,
            authorized_invoker_members=auth_invokers,
            enable_direct_iap=enable_direct_iap,
            service_name=primary_svc,
            custom_tf_content=bespoke_root_text(files) or None,
            app_files=files,
            env_vars_override=primary_env,      # lane 10: None on the legacy path (today's wiring)
            scaling_override=primary_scaling,
            regulated=inputs.regulated,         # lane 14 PR-0b: None (STANDARD) = byte-identical
            default_min_instances=default_min,  # FD-4CI-b: Enforce Scale-to-Zero (0 = today)
            topology=vt,                        # gce-bastion-network: a bastion primary's settings + grants
            network_facts=inputs.network_facts,   # gce-bastion-network: a bastion primary's own subnet fact
            # platform-db-connector-wiring: the connector to a private resource the primary consumes (typed
            # consumer edge); None (no such resource / no single connector) = byte-identical. FD-4DK: on the legacy
            # path (no topology) the workload's one connector to its private database (legacy_connector above).
            # FD4DK-3: evaluated before main.tf is overwritten, so the AI's relocated drafts (main.tf, ...; their
            # text is already in custom.tf) are left out, as for legacy_connector
            vpc_access_connector=(topology_vpc_connector(vt, vt.primary.name,
                                                         {p: t for p, t in files.items()
                                                          if p not in assembly.relocated_draft_paths})
                                  if vt is not None and vt.primary is not None else legacy_connector),
            # PUSH-TO-PRIVATE: the push identities of module.compute (typed intent); None = byte-identical
            push_service_accounts=push_ids.get("module.compute"),
            # FD-4CI-b-R1-WIF: the WIF condition accepts the deploy workflows' branch; "main" = byte-identical
            github_default_branch=inputs.deploy_branch,
            github_actions_deploy=gha_deploy_on,   # GHA-DEPLOY-SWITCH: on = byte-identical
            # IAP-GATE-KNOWN-MEMBER: Cloud Run secondaries of a non-cloudrun primary need the root's project-number
            # data source too (reconcile_multi_service_declarations above recorded them; Direct IAP off = unchanged)
            cloud_run_secondaries=bool(planned_services),
            app_admin_emails=inputs.app_admin_emails,   # APP-ADMIN-IAP-CONTRACT: None = byte-identical
        )
        if vt is not None:
            files[TOPOLOGY_JSON_PATH] = render_topology_json(vt)   # lane 10 review artifact (data, never HCL)
        files["infra/workload/variables.tf"] = generate_golden_variables_tf(
            product_id,
            full_repo_name,
            allow_unauthenticated=allow_unauthenticated,
            authorized_invoker_members=auth_invokers,
            enable_direct_iap=enable_direct_iap,
            region=inputs.region,
            github_default_branch=inputs.deploy_branch,   # FD-4CI-b-R1-WIF: "main" = byte-identical
            github_actions_deploy=gha_deploy_on,   # GHA-DEPLOY-SWITCH: on = byte-identical
            app_admin_emails=inputs.app_admin_emails,   # APP-ADMIN-IAP-CONTRACT: None = byte-identical
        ) + render_fact_variables(inputs.network_facts)   # lane 11: IPAM fact variables ("" without facts)
        files["infra/workload/outputs.tf"] = generate_golden_outputs_tf(product_id, archetype)
        files["infra/workload/moved.tf"] = generate_golden_moved_tf(product_id, archetype)

        # Preserve or initialize human architect extension files (human.tf & human_override.tf). FD-4AW-a F2: their
        # content comes only from the repository's existing files, never from an LLM draft at the same key.
        if "infra/workload/human.tf" in existing_files:
            files["infra/workload/human.tf"] = existing_files["infra/workload/human.tf"]
        else:
            files["infra/workload/human.tf"] = generate_human_tf_template()

        if "infra/workload/human_override.tf" in existing_files:
            files["infra/workload/human_override.tf"] = existing_files["infra/workload/human_override.tf"]
        else:
            files["infra/workload/human_override.tf"] = generate_human_override_tf_template()

        files["infra/workload/README.md"] = generate_infra_readme(product_id, archetype)

        # Lane 11 RT2 G1: infra/workload/terraform.tfvars is platform-rendered only. deploy_workload seeds the root
        # tfvars from it, so an LLM-authored file at this path would set root variables (sizing, network, env_vars,
        # ...) that no rule sees. Remove it (exact path; recorded), then render the platform's lines below.
        if files.pop(_PLATFORM_TFVARS, None) is not None:
            assembly.record.drop(_PLATFORM_TFVARS, "PLATFORM_PATH_RESERVED")
            logger.info(f"Assembly for '{product_id}' (trace {trace_id or '-'}): removed the LLM-authored "
                        f"{_PLATFORM_TFVARS} (platform-rendered path; PLATFORM_PATH_RESERVED)")

        # Emit terraform.tfvars combining Direct IAP, domain restrictions, dynamic container sizing, and inferred custom APIs
        tfvars_lines = []
        if enable_direct_iap:
            tfvars_lines.append("enable_direct_iap          = true")
        if not allow_unauthenticated:
            members_hcl = json.dumps(auth_invokers)
            tfvars_lines.append("allow_unauthenticated      = false")
            tfvars_lines.append(f"authorized_invoker_members = {members_hcl}")

        # FD-4CI-b: also when the platform baseline changed a standard service's 512Mi / 1000m
        if sizing.tier > 1 or (sizing.memory_limit, sizing.cpu_limit) != ("512Mi", "1000m"):
            tfvars_lines.append(f'memory_limit               = "{sizing.memory_limit}"')
            tfvars_lines.append(f'cpu_limit                  = "{sizing.cpu_limit}"')

        # S1-A 4/5: APIs are inferred from every root-module file (custom.tf + the AI's auxiliary files, which no longer
        # move into custom.tf). S2-C (HS-63): by the exact type/module-source table, over the platform renders too, so
        # main.tf's golden module calls (e.g. compute-gke-autopilot -> container) count by their exact source.
        inferred_apis = infer_additional_apis_from_custom_tf(
            {p: t for p, t in files.items() if p.startswith("infra/workload/") and "/" not in p[len("infra/workload/"):]
             and p.endswith((".tf", ".tf.json")) and isinstance(t, str)})
        if inferred_apis:
            apis_hcl = json.dumps(inferred_apis)
            tfvars_lines.append(f"additional_apis            = {apis_hcl}")
        # lane 11 near-term: the IPAM fact values (the terraform server keeps these keys: deploy_workload's merge)
        tfvars_lines.extend(render_fact_tfvars(inputs.network_facts))

        if tfvars_lines:
            files[_PLATFORM_TFVARS] = "\n".join(tfvars_lines) + "\n"

        # 5. Option A (Vendoring): Vendor canonical modules directly into child repo under infra/modules/
        # FD-4AB: record exactly what the platform vendored; those files are restored before returning.
        files, platform_files = vendor_platform_files(
            files, archetype, intent_modules=(intent_asm.modules if intent_asm is not None else ()))   # TI-3
        # FD-4CX: a private workload never deploys a registered module that grants public access by itself
        if allow_unauthenticated is not True:
            refuse_public_registered_modules(platform_files, files, existing_files)

        # 6. Enforce Complete GCP-Native Buildpack Container Contract across all microservices
        enforce_container_contract(files, product_id, archetype,
                                   topology=inputs.compute_intent.topology)   # FD-55 W5 RT F1

        # 7. Firestore Query Guardrails & Automated Composite Index Generation
        index_reqs = scan_firestore_queries(files)
        if index_reqs:
            try:
                indexes_tf = generate_golden_indexes_tf(index_reqs)
            except FirestoreIndexIdInvalid as id_err:   # RT14-08: never rendered, never skipped silently
                raise DeveloperStageError(FIRESTORE_INDEX_ID_INVALID, f"{id_err} (stage {id_err.stage})") from id_err
            if indexes_tf:
                files["infra/workload/indexes.tf"] = indexes_tf
            indexes_json = generate_firestore_indexes_json(index_reqs)
            if indexes_json:
                target_svcs = services or [product_id]
                for svc in target_svcs:
                    files[f"apps/{svc}/firestore.indexes.json"] = indexes_json

        # 8. Anti-Hallucination Gatekeeper: In-memory AST import transformation, dependency reconciliation & syntax verification
        # FD-4F A9 (PC-3): a non-blocking healing pass by design; the blocking verdicts are the hallucination stack's
        # validators and the pre-commit gate in commit_and_open_pr. Its failure is now logged at ERROR, never hidden.
        try:
            gatekeeper = SynthesisVerifierAgent(product_id=product_id)
            files, passed, verifier_errors = gatekeeper.verify_and_cure(
                files, product_id=product_id,
                typed_iac=inputs.iac_intent is not None)   # FD55-W2 (TI-4a)
            if not passed:
                logger.warning(f"Gatekeeper detected {len(verifier_errors)} issues; code cured to best possible state: {verifier_errors}")
        except Exception as gk_err:
            logger.error(f"Generation-time gatekeeper healing pass failed ({type(gk_err).__name__}: {gk_err}); the "
                         f"pre-commit gate still verifies the tree before any commit.")

        # Lane 8 (red-team A4 option 1, generation-time copy only): the per-file sanitize_hcl_triggers rewrite was
        # deleted. It mutated valid HCL (brace walker without heredoc/comment support, dangling-reference regexes,
        # list reformatting). LLM-declared Cloud Build connections/triggers now reach apply unchanged (FD-53: policy
        # diagnostic). The apply-time copy in mcp-servers/terraform/service.py is lane 6's.
        # FD-4F A9: the former `.py and not SynthesisVerifierAgent` branch is gone (the verifier is a hard import).
        # G22 DELETED (FD-55 W5, register FD55-W5): the overwrite of every `*.python-version` file in the tree with
        # 3.13 (a second copy of the runtime pin); enforce_container_contract (step 6) pins every deployed service and
        # the root.

        # 7. Validate all generated GitHub Actions CI/CD workflows
        validate_all_staged_workflows(files, base_dir=product_id)

        # Inject Architecture Implementation Plan into docs/planning/ of child repository
        target_plan_path = plan_file_path or "docs/planning/0001-initial-workload-architecture.md"
        if not target_plan_path.startswith("docs/planning/"):
            target_plan_path = f"docs/planning/{os.path.basename(target_plan_path)}"

        if plan_markdown:
            files[target_plan_path] = plan_markdown
        elif not any(k.startswith("docs/planning/") for k in files.keys()):
            date_today = time.strftime("%Y-%m-%d")
            files[target_plan_path] = f"""---
title: "Workload Architecture Plan for {product_id}"
product_id: "{product_id}"
trace_id: "{trace_id or 'trace-auto'}"
date: "{date_today}"
tier: 1
status: "PLANNED"
author: "StackVend Autonomous Engineering Pipeline"
reviewers: ["Architect Agent", "Compliance Agent", "QA Agent"]
approved_by: "Autonomous Tier 1/2 Policy"
---

# Implementation Plan: {product_id}

## 1. Executive Summary & Requirements
- **Problem Statement**: Automated workload implementation for `{product_id}`.
- **Acceptance Criteria**:
- [ ] Core FastAPI microservice operational
- [ ] Terraform infrastructure configured for Cloud Run v2

## 2. Architecture & Topology Design
Microservice architecture deployed to Cloud Run v2 with native Firestore database storage.

## 3. Security, IAM & Governance Assessment
- Runtime Service Account: `sa-{product_id}@{target_project_id or 'project-id'}.iam.gserviceaccount.com`
- Scoped roles: `roles/datastore.user`, `roles/logging.logWriter`

## 4. Component Manifest & Proposed Changes
{chr(10).join(f"- `{k}`" for k in files.keys())}

## 5. Sequenced Build Plan (Task DAG)
Topologically generated build stages executed.

## 6. Verification & Automated Test Strategy
Pytest test execution in ephemeral container sandbox.

## 7. Rollback & Blast Radius Assessment
Isolated to `{product_id}` namespace.
"""

        # 8. FD-4AF: k8s manifests get their explicit placeholders only (the vended child project; the platform region
        # setting, read only when a manifest uses ${REGION} / ${ARTIFACT_REGISTRY}); a concrete image is never
        # rewritten. An unavailable value or an unresolved placeholder raises ManifestHydrationError (no guess).
        try:
            files, k8s_actions = self._hydrate_k8s(files, product_id, target_project_id or "",
                                                   functools.partial(self._platform_region, product_id),
                                                   defer_unresolved=bool(inputs.defer_k8s_unresolved))
        except ManifestHydrationError as e:
            raise self._manifest_hydration_stage_error(trace_id, e) from e
        if k8s_actions:
            for act in k8s_actions:
                logger.info(f"Pre-flight gate auto-hydrated Kubernetes manifest: {act}")

        # FD-55 W4 (register FD55-W4): the generation-time HCL rewriters that ran here are deleted: HA-06 duplicate
        # GKE cluster strip, HB-06 multi-service coverage, HB-19 Cloud Run timeouts, HB-17 naming (+ HB-18 / HA-17 /
        # HD-14 guesses), HD-15 regex pre-flight + self_correct_hcl (HC-03 image, HA-18 WI grant, HB-24 call). (W2
        # had already kept them off platform renders, user files and typed-intent runs.) A literal name GCP rejects is
        # V1b; a templated one resolved from platform values is V2k IAC.NAME_INVALID; the AI repairs both.

        # 9/10 DELETED (FD-55 W5, register FD55-W5): the second add-only requirements contract call (G28,
        # preflight_validator.validate_and_heal_python_requirements), the second add-only `__init__.py` pass (G26,
        # validate_and_heal_python_packages) and the third Dockerfile purge (G24, validate_zero_dockerfiles + delete):
        # the gatekeeper pass above already ran the same add-only contracts on this tree (reconcile_service_requirements,
        # purge_shadowed_package_files) and enforce_container_contract is the one Dockerfile rule (step 6); nothing
        # between them adds a .py, requirements.txt or Dockerfile.

        vendored_before_restore = {p: files.get(p) for p in platform_files}
        final = restore_platform_files(files, platform_files)
        # S1-B V2c postcondition input (Step 1 code RT F1): the root module exactly as it will be validated and
        # committed, i.e. AFTER every healer above (gatekeeper cures, platform renders). A draft
        # declaration any of them removed without an AssemblyRecord entry is then PLATFORM.ASSEMBLY_DROPPED_DECLARATION.
        # The relocated draft paths (main/variables/outputs/moved) hold the golden renders by now, so they are part of
        # the root module; the draft's services.tf was popped by the assembly.
        assembled_root = {p: final[p] for p in final if p.startswith("infra/workload/") and p.endswith(".tf")
                          and "/" not in p[len("infra/workload/"):]}
        # Eval harness only (in-memory): the last assembled tree, so a run that stops at the gate still shows what
        # the platform assembled (faithfulness of archetype / service set at iteration 0).
        self._record_stack(trace_id, assembled_tree=dict(final))
        return final, {
            "planned_services": tuple(planned_services),   # FD-55 W5 RT F2 (V3c-planned)
            "platform_files": dict(platform_files), "archetype": archetype, "assembly_record": assembly.record,
            "assembled_root": assembled_root, "assembled_root_pre_healers": assembled_root_pre_healers,
            "vendored_before_restore": vendored_before_restore,
            **({"iac_intent": intent_asm} if intent_asm is not None else {})}   # TI-3

    def get_full_repo_name(self, product_id: str, github_repo: Optional[str] = None) -> str:
        """Resolves full repository name (owner/repo) from parameter, Firestore, parent workload, or default owner."""
        stored_repo = github_repo
        if not stored_repo:
            try:
                from google.cloud import firestore
                db = firestore.Client(project=self.project_id) if self.project_id else None
                if db:
                    doc = db.collection("workloads").document(product_id).get()
                    if doc.exists:
                        wdict = doc.to_dict()
                        if isinstance(wdict, dict):
                            stored_repo = wdict.get("github_repo")
                            if not stored_repo and wdict.get("promoted_from_product_id"):
                                parent_doc = db.collection("workloads").document(wdict["promoted_from_product_id"]).get()
                                if parent_doc.exists:
                                    pdict = parent_doc.to_dict() or {}
                                    stored_repo = pdict.get("github_repo")
            except Exception:
                pass

        if stored_repo is not None and not isinstance(stored_repo, (str, dict)):
            stored_repo = None

        _, _, full_name = resolve_repo_identity(
            stored_repo,
            default_owner=self.github_owner,
            product_id=product_id,
        )
        return full_name

    @staticmethod
    def _precommit_verify(run: Any, full_repo_name: str) -> Any:
        """FD-4F A9 (PC-1): run the pre-commit verifier; a verifier that cannot run is GATE_UNAVAILABLE (chained to its
        cause), whatever the exception type. Never a skipped gate."""
        if SynthesisVerifierAgent is None:  # defensive: the import is hard (FS-3)
            raise GateUnavailableError("pre-commit verifier unavailable", reason="PRECOMMIT_VERIFIER_UNAVAILABLE",
                                       stage="developer")
        try:
            return run()
        except GateError:
            raise
        except Exception as e:
            logger.error(f"🛡️ Pre-commit Gatekeeper could not run for {full_repo_name}: {type(e).__name__}: {e}")
            raise GateUnavailableError(f"pre-commit verifier failed to run: {type(e).__name__}: {e}",
                                       reason="PRECOMMIT_VERIFIER_UNAVAILABLE", stage="developer") from e

    @staticmethod
    def _precommit_diag(message: Any, source: Any = None) -> Dict[str, Any]:
        """One bounded diagnostic for a GateFailedError body (the verifier's own Diagnostic when it has one)."""
        if source is not None and hasattr(source, "model_dump"):
            try:
                return source.model_dump(mode="json")
            except Exception:  # noqa: BLE001 - fall back to the plain message
                pass
        return {"tool": "gatekeeper", "code": "GATE.PRECOMMIT_VERIFY", "severity": "error", "source": "precommit",
                "message": str(message)[:2048]}

    @staticmethod
    def _check_commit_split(files: Dict[str, str], commit_paths: Optional[List[str]],
                            files_to_delete: Optional[List[str]]) -> Tuple[List[str], List[str]]:
        """FD-4DC-d/e: validate a split commit before anything runs. Every written path is in the gated tree (a
        string), no deleted path is (the gated tree is the branch after the commit). Duplicates are dropped, order is
        kept. A violation is the caller's defect: PLATFORM_DEFECT, nothing is checked or committed."""
        paths = list(dict.fromkeys(files if commit_paths is None else commit_paths))
        dels = list(dict.fromkeys(files_to_delete or []))
        missing = [p for p in paths if not isinstance(files.get(p), str)]
        kept = [p for p in dels if p in files]
        if missing or kept:
            raise PlatformDefectError(
                f"invalid split commit: {len(missing)} path(s) to write are not in the checked tree {missing[:20]}, "
                f"{len(kept)} path(s) to delete are still in it {kept[:20]}",
                reason="COMMIT_SET_INVALID", stage="developer",
                details={"not_in_tree": missing[:50], "deleted_but_in_tree": kept[:50]})
        return paths, dels

    @staticmethod
    def _commit_set_after_gate(gate_input: Dict[str, str], gated: Dict[str, str],
                               commit_paths: List[str]) -> Dict[str, str]:
        """FD-4DC-d: the bytes to write for a split commit = the gate's output for `commit_paths`. The gate must have
        left every other path exactly as it was (not changed, added or removed): otherwise the tree it approved is not
        the tree that lands, so the commit is refused, never written without that cure.

        FD-4DC RT F2: this is the gate's verdict about the repository (a human edit, an imported tree, or a newer gate
        rule the committed files do not meet yet), not a platform defect: GateFailedError, naming the paths."""
        wanted = set(commit_paths)
        outside = sorted(p for p in set(gate_input) | set(gated)
                         if p not in wanted and gate_input.get(p) != gated.get(p))
        dropped = [p for p in commit_paths if not isinstance(gated.get(p), str)]
        if outside or dropped:
            raise GateFailedError(
                f"the pre-commit gate would change {len(outside)} file(s) outside this commit {outside[:20]} and drop "
                f"{len(dropped)} of its own file(s) {dropped[:20]}. Nothing was committed. Those files must be fixed "
                f"and committed first (or the workload needs a developer run); this commit writes only {len(wanted)} "
                f"file(s) and cannot carry the gate's changes to other files",
                reason="PRECOMMIT_CURE_OUTSIDE_COMMIT_SET", stage="developer",
                details={"changed_outside": outside[:50], "dropped": dropped[:50]})
        return {p: gated[p] for p in commit_paths}

    @github_retry_with_backoff(max_retries=3, initial_wait=2.0)
    def commit_and_open_pr(
        self,
        product_id: str,
        files: Dict[str, str],
        branch_name: Optional[str] = None,
        commit_message: Optional[str] = None,
        github_repo: Optional[str] = None,
        trace_id: Optional[str] = None,
        commit_paths: Optional[List[str]] = None,
        files_to_delete: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Commits code files to GitHub and opens a Pull Request.

        `files` is the tree every pre-commit check sees. By default all of it is written (every caller before
        FD-4DC-d). FD-4DC-d/e: with `commit_paths` only those paths are written, with the bytes the gate returned for
        them, and `files_to_delete` are removed in the same commit; `files` must then be the branch's whole tree
        after the commit (so it never contains a deleted path). A gate cure of any path outside `commit_paths` is a
        GateFailedError PRECOMMIT_CURE_OUTSIDE_COMMIT_SET (the gate would have approved a tree that is not the one
        that lands); an inconsistent split is PLATFORM_DEFECT COMMIT_SET_INVALID. Nothing is committed either way."""
        split = commit_paths is not None or bool(files_to_delete)
        if split:
            commit_paths, files_to_delete = self._check_commit_split(files, commit_paths, files_to_delete)
            gate_input = dict(files)
        full_repo_name = self.get_full_repo_name(product_id, github_repo=github_repo)
        branch = branch_name or f"feature/{product_id}-initial"
        msg = commit_message or f"feat({product_id}): automated implementation by StackVend Developer Agent"

        # RT14-28: one resolver for the base branch and VCS provider (typed when the record is unreadable; was a
        # second Firestore client with `except Exception: pass`, so a transient error committed against "main")
        target_base_branch, vcs_name = self._commit_base(product_id, trace_id)

        if not vcs_name and full_repo_name and "serverless-git" in full_repo_name.lower():
            vcs_name = "SERVERLESS_GIT"

        # Pre-commit workflow validation: reject duplicate mapping keys, invalid expressions, or syntax errors
        try:
            validated = validate_all_staged_workflows(files, base_dir=full_repo_name)
            if validated:
                logger.info(f"Pre-commit workflow validation succeeded for {full_repo_name}: {validated}")
        except WorkflowValidationError as e:
            logger.error(f"Pre-commit workflow validation failed for {full_repo_name}: {e}")
            raise RuntimeError(f"Workflow pre-commit validation failed: {e}") from e

        # Step 1 S1-B (register HS-04): when the hallucination stack validated this trace's tree, commit exactly that
        # tree -- hash equality with the passing report and the check-only gatekeeper; no cure runs between
        # validation and commit.
        stack_record = self.stack_run(trace_id)
        if stack_record.get("validated_hash"):
            committed_hash = artifact_hash({k: v for k, v in files.items() if isinstance(v, str)})
            if committed_hash != stack_record["validated_hash"]:
                raise StageError(ValidationReport(status="FAIL", source="precommit", artifact_hash=committed_hash,
                                                  diagnostics=[Diagnostic(
                    tool="platform", code="PLATFORM.COMMIT_TREE_MISMATCH", severity="error",
                    error_class="PLATFORM_DEFECT", file="<tree>", source="precommit",
                    message=f"tree to commit {committed_hash[:12]} != validated tree "
                            f"{stack_record['validated_hash'][:12]}")]), "committed tree differs from the validated tree")
            gate_diags = self._precommit_verify(lambda: SynthesisVerifierAgent(product_id=product_id).verify(files),
                                                full_repo_name)
            if gate_diags:
                raise GateFailedError(
                    f"Gatekeeper pre-commit verification failed: {[d.message for d in gate_diags]}",
                    reason="PRECOMMIT_VERIFY_FAILED", stage="developer",
                    diagnostics=[self._precommit_diag(getattr(d, "message", d), source=d) for d in gate_diags][:200])
        # Pre-commit platform invariant: in-memory package directory disambiguation and hermetic curing (Pure Additive Git Policy)
        else:
            # FD-4F A9 (PC-1): the gate fails CLOSED. Any verifier exception (not only RuntimeError) is
            # GATE_UNAVAILABLE and nothing is committed; a failed verdict is CODE_DEFECT with the verifier's errors.
            def _verify_and_cure():
                # RT F5: the result shape is unpacked INSIDE the guarded call, so a verifier answering an unexpected
                # shape is PRECOMMIT_VERIFIER_UNAVAILABLE (typed), never a bare ValueError.
                # FD-55 W8 (register FD55-W8; FD-4AD residual, HB-27 copy): the separate purge_shadowed_package_files
                # pass that ran before this call is DELETED. verify_and_cure's step 0 is that same add-only
                # `__init__.py` pass and adds nothing on its second run, so the cured tree is unchanged.
                gatekeeper = SynthesisVerifierAgent(product_id=product_id)
                cured, ok, errs = gatekeeper.verify_and_cure(
                    files, product_id=product_id,
                    typed_iac=intent_contract.is_intent_tree(files))   # FD-55 W5 (F4): same skip as generation
                return cured, ok, errs

            cured_files, passed, c_errors = self._precommit_verify(_verify_and_cure, full_repo_name)
            if cured_files:
                files = cured_files
            logger.info(f"🛡️ Pre-commit Gatekeeper verification: passed={passed}, cured_files={len(cured_files or {})}, errors={len(c_errors or [])}")
            if passed is not True:
                logger.error(f"🛡️ Pre-commit Gatekeeper verification FAILED for {full_repo_name}: {c_errors}")
                raise GateFailedError(
                    f"Gatekeeper pre-commit verification failed: {c_errors}",
                    reason="PRECOMMIT_VERIFY_FAILED", stage="developer",
                    diagnostics=[self._precommit_diag(e) for e in (c_errors or [])][:200])

        # FD-4DC-d: the written set (all of `files` unless the caller split it); deletions only when asked for.
        to_write = self._commit_set_after_gate(gate_input, files, commit_paths) if split else files
        to_delete = list(files_to_delete or [])
        delete_kw = {"files_to_delete": to_delete} if to_delete else {}
        # RT14-13: a person's change on the base branch during the build is never overwritten (typed stop, read-only)
        base_head_sha = self._check_base_unmoved(product_id, trace_id, to_write, to_delete)
        base_head = {"base_head_sha": base_head_sha} if base_head_sha else {}

        # STAGE-DEADLINE orphan guard: nothing reaches the repository once the stage has answered (deadline, run
        # ended, superseded, emergency stop) or when the write could not finish inside the budget. The bookkeeping
        # after a write that did start (provenance, PR ledger) is kept, so a started commit is never left unrecorded.
        stage_deadline.guard_side_effect("developer.commit")
        stage_deadline.mark("developer.commit", files=len(to_write))
        token = self.fetch_github_token()
        if not token and vcs_name != "SERVERLESS_GIT":
            # FD-4F A9 (Q-E): no VCS credential is a stage failure, never a fabricated "MOCK_COMMITTED" success with
            # a made-up pull/1 URL (no TEST_MODE branch, plan D1). Nothing was committed, so no provenance is written.
            logger.error(f"No VCS credential available for {full_repo_name}; nothing committed.")
            raise GateUnavailableError(
                f"no VCS credential for {full_repo_name}; the developer stage cannot commit",
                reason="VCS_CREDENTIAL_UNAVAILABLE", stage="developer",
                details={"product_id": product_id, "repo_name": full_repo_name, "branch_name": branch})

        vcs = None
        if VCSProviderFactory is not None:
            try:
                vcs = VCSProviderFactory.get_provider(
                    provider_name=vcs_name,
                    default_owner=self.github_owner,
                    project_id=self.project_id,
                    github_token=token,
                    product_id=product_id,
                    full_repo_name=full_repo_name,
                )
            except Exception as vcs_init_err:
                logger.debug(f"Could not initialize VCS provider: {vcs_init_err}")

        if vcs is not None:
            try:
                vcs.create_or_verify_branch(full_repo_name, branch, source_branch=target_base_branch)
                time.sleep(3.0)  # Grace window: allow GitHub Spokes router to replicate new branch ref
                commit_sha = vcs.commit_files(full_repo_name, branch, to_write, msg, **delete_kw)
                pr_url = f"https://github.com/{full_repo_name}/tree/{branch}"
                created_pr_number = None  # code RT F1: integer from the provider's PR-creation result only
                pr_identity = None  # FD-4P: the PR-creation response's identity fields (ledger input)
                if branch != target_base_branch:
                    try:
                        # RT S3: a commit that outlived the answer is recorded below, but no PR is opened for it (the
                        # refusal logs ORPHAN_ABANDONED and lands in the warning below; the bookkeeping still runs).
                        stage_deadline.guard_side_effect("developer.pr", reserve_s=0)
                        pr_res = vcs.create_pull_request(
                            full_repo_name,
                            title=f"feat({product_id}): automated implementation by StackVend Developer Agent",
                            body=f"## StackVend: Automated Developer Agent Delivery\n\n- **Product ID**: `{product_id}`\n- **Branch**: `{branch}`\n- **Files Committed**: {len(to_write)}\n\nThis PR was generated automatically by the StackVend Developer Agent.",
                            head_branch=branch,
                            base_branch=target_base_branch,
                            trace_id=trace_id,
                            product_id=product_id,
                        )
                        pr_url = pr_res.get("pull_request_url", pr_url)
                        created_pr_number = _created_pr_number(pr_res.get("pr_number"))
                        if isinstance(pr_res, dict):
                            pr_identity = {k: pr_res.get(k) for k in PR_IDENTITY_KEYS}
                    except Exception as pr_err:
                        logger.warning(f"Could not open PR ({pr_err}); commit was successful.")

                self._write_iac_provenance(product_id, trace_id, files)
                self._write_app_provenance(product_id, trace_id, files)   # SAT-49 F4
                return {
                    "status": "COMMITTED",
                    "repo_name": full_repo_name,
                    "branch_name": branch,
                    "commit_sha": commit_sha,
                    "pull_request_url": pr_url,
                    "pr_number": created_pr_number,
                    "pull_request": pr_identity,
                    "base_branch": target_base_branch,
                    "files_committed": list(to_write.keys()),
                    **base_head,   # RT14-13: the base head the commit's base check saw
                    **({"files_deleted": to_delete} if to_delete else {}),
                }
            except Exception as vcs_err:
                logger.error(f"VCSProvider commit_files failed: {vcs_err}")
                raise RuntimeError(f"Developer Agent GitHub commit failed: {vcs_err}") from vcs_err

        if shutil.which("git") and token:
            try:
                # RT14-10: the auth header goes through git's environment configuration, for clone / pull / push only
                clean_url = f"https://github.com/{full_repo_name}.git"
                env = os.environ.copy()
                env["GIT_TERMINAL_PROMPT"] = "0"
                auth_env = git_auth_env(token, env)
                git_secrets = git_secret_values(token)
                with tempfile.TemporaryDirectory() as tmp_dir:
                    cloned = False
                    try:
                        res = run_git(["clone", "--depth", "1", "--no-tags", "--single-branch", "-b", branch, clean_url,
                                       tmp_dir], env=auth_env, timeout=45, secrets=git_secrets)
                        if res.returncode == 0:
                            cloned = True
                    except Exception:
                        pass
                    if not cloned:
                        res_m = run_git(["clone", "--depth", "1", "--no-tags", "--single-branch", "-b", target_base_branch,
                                         clean_url, tmp_dir], env=auth_env, timeout=45, secrets=git_secrets)   # FD-4CI-b-R1
                        if res_m.returncode != 0:
                            raise RuntimeError(f"Git CLI clone failed for {full_repo_name}: "
                                               f"{without_git_secrets(res_m.stderr, git_secrets)}")
                        run_git(["checkout", "-B", branch], cwd=tmp_dir, env=env, timeout=15, check=True,
                                secrets=git_secrets)

                    run_git(["config", "user.name", "StackVend Developer Agent"], cwd=tmp_dir, env=env, timeout=15,
                            check=True)
                    run_git(["config", "user.email", os.getenv("STACKVEND_GIT_AUTHOR_EMAIL") or "stackvend-agent@noreply.invalid"],
                            cwd=tmp_dir, env=env, timeout=15, check=True)  # FD-12

                    # FD-4G: safe_join rejects escapes, the clone root itself and any .git component (H1).
                    for path, content in to_write.items():
                        clean_path = path.lstrip("/").replace("\\", "/")
                        target_file = safe_join(tmp_dir, clean_path, reserved=GIT_RESERVED)
                        if os.path.isdir(target_file):
                            shutil.rmtree(target_file)
                        parent_dir = os.path.dirname(target_file)
                        if os.path.isfile(parent_dir):
                            os.remove(parent_dir)
                        os.makedirs(parent_dir, exist_ok=True)
                        with open(target_file, "w", encoding="utf-8") as f:
                            f.write(content)
                    # FD-4DC-e: exact file paths only (a path the branch does not have is already absent)
                    for path in to_delete:
                        target_file = safe_join(tmp_dir, path.lstrip("/").replace("\\", "/"), reserved=GIT_RESERVED)
                        if os.path.isfile(target_file):
                            os.remove(target_file)

                    run_git(["add", "-A"], cwd=tmp_dir, env=env, timeout=30, check=True)
                    status_res = run_git(["status", "--porcelain"], cwd=tmp_dir, env=env, timeout=15, check=True)
                    if not status_res.stdout.strip():
                        commit_sha = run_git(["rev-parse", "HEAD"], cwd=tmp_dir, env=env, timeout=15,
                                             check=True).stdout.strip()
                    else:
                        run_git(["commit", "-m", msg], cwd=tmp_dir, env=env, timeout=30, check=True)
                        push_args = ["push", "-u", "origin", branch]
                        push_res = run_git(push_args, cwd=tmp_dir, env=auth_env, timeout=60, secrets=git_secrets)
                        if push_res.returncode != 0:
                            run_git(["pull", "--rebase", "origin", branch], cwd=tmp_dir, env=auth_env, timeout=30,
                                    secrets=git_secrets)
                            push_res = run_git(push_args, cwd=tmp_dir, env=auth_env, timeout=60, secrets=git_secrets)
                            if push_res.returncode != 0:
                                raise RuntimeError(f"Git CLI push failed for {full_repo_name} ({branch}): "
                                                   f"{without_git_secrets(push_res.stderr, git_secrets)}")
                        commit_sha = run_git(["rev-parse", "HEAD"], cwd=tmp_dir, env=env, timeout=15,
                                             check=True).stdout.strip()

                    pr_url = f"https://github.com/{full_repo_name}/tree/{branch}"
                    created_pr_number = None  # code RT F1: integer from the PR-creation result only
                    pr_identity = None  # RT F3: ledger input from the PR-creation response
                    try:
                        gh = Github(token)
                        repo = gh.get_repo(full_repo_name)
                        pr_body = (
                            f"## StackVend: Automated Developer Agent Delivery\n\n"
                            f"- **Product ID**: `{product_id}`\n"
                            f"- **Branch**: `{branch}`\n"
                            f"- **Files Committed**: {len(to_write)}\n\n"
                            f"This PR was generated automatically by the StackVend Developer Agent.\n\n"
                            f"<!-- castor-metadata: {{\"managed_by\": \"project-castor\", \"product_id\": \"{product_id}\", \"trace_id\": \"{trace_id or ''}\"}} -->\n"
                            f"<!-- managed-by: project-castor -->"
                        )
                        pr_res = repo.create_pull(
                            title=f"feat({product_id}): automated implementation by StackVend Developer Agent",
                            body=pr_body,
                            head=branch,
                            base=target_base_branch,
                        )
                        pr_url = pr_res.html_url
                        created_pr_number = _created_pr_number(getattr(pr_res, "number", None))
                        pr_identity = _pr_identity_from_pull(pr_res)
                        try:
                            pr_res.add_to_labels("managed-by:project-castor")
                        except Exception:
                            pass
                    except Exception as pr_err:
                        logger.warning(f"Could not open PR ({pr_err}); commit was successful.")

                    self._write_iac_provenance(product_id, trace_id, files)
                    self._write_app_provenance(product_id, trace_id, files)   # SAT-49 F4
                    return {
                        "status": "COMMITTED",
                        "repo_name": full_repo_name,
                        "branch_name": branch,
                        "commit_sha": commit_sha,
                        "pull_request_url": pr_url,
                        "pr_number": created_pr_number,
                        "pull_request": pr_identity,
                        "base_branch": target_base_branch,
                        "files_committed": list(to_write.keys()),
                        **base_head,   # RT14-13: the base head the commit's base check saw
                        **({"files_deleted": to_delete} if to_delete else {}),
                    }
            except UnsafePathError:
                raise  # FD-4G: an unsafe key fails closed; never retried through the REST fallback.
            except Exception as cli_fallback_err:
                logger.warning(f"Native Git CLI fallback in handler noticed ({cli_fallback_err}); trying PyGithub REST.")

        try:
            gh = Github(token)
            repo = gh.get_repo(full_repo_name)

            # 1. Get or create branch from the workload's base branch safely (FD-4CI-b-R1: its recorded branch)
            base_sha = None
            main_branch = repo.get_branch(target_base_branch)
            base_sha = main_branch.commit.sha

            try:
                target_branch = repo.get_branch(branch)
                base_sha = target_branch.commit.sha
                logger.info(f"Branch '{branch}' already exists in '{full_repo_name}' (SHA: {base_sha[:7]})")
            except Exception:
                try:
                    repo.create_git_ref(ref=f"refs/heads/{branch}", sha=main_branch.commit.sha)
                    base_sha = main_branch.commit.sha
                    logger.info(f"Created branch '{branch}' from '{target_base_branch}' (SHA: {base_sha[:7]})")
                except GithubException as ge:
                    if ge.status == 422:
                        target_branch = repo.get_branch(branch)
                        base_sha = target_branch.commit.sha
                        logger.info(f"Branch '{branch}' confirmed existing after concurrent creation (SHA: {base_sha[:7]})")
                    else:
                        raise

            if not base_sha:
                for attempt in range(3):
                    try:
                        target_branch = repo.get_branch(branch)
                        base_sha = target_branch.commit.sha
                        break
                    except Exception:
                        if attempt < 2:
                            time.sleep(1.0)
                        else:
                            raise

            # 2. Commit files
            tree_sha = None
            target_c = getattr(target_branch, "commit", None)
            if target_c and hasattr(target_c, "commit") and hasattr(target_c.commit, "tree"):
                tree_sha = target_c.commit.tree.sha

            try:
                base_commit_obj = repo.get_git_commit(base_sha)
                base_tree = repo.get_git_tree(tree_sha or base_commit_obj.tree.sha)
            except Exception:
                try:
                    main_b = repo.get_branch(target_base_branch)
                    main_commit = repo.get_git_commit(main_b.commit.sha)
                    base_tree = repo.get_git_tree(main_commit.tree.sha)
                except Exception as fb_err:
                    logger.error(f"Fallback direct commit base_tree resolution failed: {fb_err}")
                    raise

            tree_elements = []
            # FD-4AD: the validated bytes are committed exactly (the HB-31/HB-42 import / path rewrites that ran here,
            # after validation, are deleted).
            for path, content in to_write.items():
                tree_elements.append(
                    InputGitTreeElement(
                        path=path,
                        mode="100644",
                        type="blob",
                        content=content,
                    )
                )
            for path in to_delete:   # FD-4DC-e: a tree entry with sha null removes the path (GitHub git trees API)
                tree_elements.append(InputGitTreeElement(path=path, mode="100644", type="blob", sha=None))

            # Direct commit fallback tree creation with calibrated backoff for GitRPC replica sync
            gitrpc_backoffs = [4.0, 8.0, 16.0]
            max_tree_attempts = len(gitrpc_backoffs) + 1
            new_tree = None
            for tree_attempt in range(max_tree_attempts):
                try:
                    new_tree = repo.create_git_tree(tree_elements, base_tree)
                    break
                except GithubException as g_err:
                    body_lower = str(getattr(g_err, "data", "") or g_err).lower()
                    if g_err.status == 422 and ("badobjectstate" in body_lower or "gitrpc" in body_lower) and tree_attempt < len(gitrpc_backoffs):
                        wait_sec = gitrpc_backoffs[tree_attempt]
                        logger.warning(
                            f"GitRPC replica sync latency (BadObjectState) in direct commit on {full_repo_name} ({branch}). "
                            f"Waiting {wait_sec}s for replica convergence (Attempt {tree_attempt + 1}/{len(gitrpc_backoffs)})..."
                        )
                        time.sleep(wait_sec)
                        continue
                    raise
            parent_commit = repo.get_git_commit(base_sha)
            new_commit = repo.create_git_commit(
                message=msg,
                tree=new_tree,
                parents=[parent_commit],
            )

            # Update ref with auto-rebase loop for non-fast-forward collisions
            max_ref_attempts = 3
            for ref_attempt in range(max_ref_attempts):
                try:
                    ref = repo.get_git_ref(f"heads/{branch}")
                    ref.edit(new_commit.sha, force=False)
                    break
                except GithubException as ge:
                    if ge.status == 422 and ref_attempt < max_ref_attempts - 1:
                        logger.warning(
                            f"Non-fast-forward collision on branch '{branch}' (Attempt {ref_attempt + 1}/{max_ref_attempts}). "
                            "Fetching latest branch HEAD and rebasing commit..."
                        )
                        time.sleep(1.0 + random.uniform(0.2, 0.8))
                        latest_branch = repo.get_branch(branch)
                        latest_sha = latest_branch.commit.sha
                        rebased_tree_sha = None
                        latest_c = getattr(latest_branch, "commit", None)
                        if latest_c and hasattr(latest_c, "commit") and hasattr(latest_c.commit, "tree"):
                            rebased_tree_sha = latest_c.commit.tree.sha
                        latest_parent = repo.get_git_commit(latest_sha)
                        latest_tree = repo.get_git_tree(rebased_tree_sha or latest_parent.tree.sha)
                        new_tree = repo.create_git_tree(tree_elements, latest_tree)
                        new_commit = repo.create_git_commit(
                            message=msg,
                            tree=new_tree,
                            parents=[latest_parent],
                        )
                    else:
                        raise
                except Exception as ref_err:
                    if ref_attempt < max_ref_attempts - 1:
                        time.sleep(1.0)
                    else:
                        raise ref_err

            logger.info(f"Committed {len(to_write)} files to '{branch}' on '{full_repo_name}' (SHA: {new_commit.sha[:7]})")

            # 3. Create Pull Request if not on the base branch
            pr_url = f"https://github.com/{full_repo_name}/tree/{branch}"
            created_pr_number = None  # code RT F1: integer from the PR-creation result only
            pr_identity = None  # RT F3: ledger input from the PR-creation response
            if branch != target_base_branch:
                try:
                    # Extract executive summary & criteria from implementation plan if available
                    plan_file = next((k for k in files.keys() if k.startswith("docs/planning/")), None)
                    plan_content = files.get(plan_file, "") if plan_file else ""
                    plan_summary_section = ""
                    if plan_file and "## 1. Executive Summary" in plan_content:
                        try:
                            sec1 = plan_content.split("## 1. Executive Summary")[1].split("## 2.")[0].strip()
                            plan_summary_section = f"\n\n### 📋 Implementation Plan (`{plan_file}`)\n{sec1}\n"
                        except Exception:
                            plan_summary_section = f"\n\n### 📋 Implementation Plan\nSee [`{plan_file}`]({plan_file}) for full technical specifications.\n"

                    pr_body = (
                        f"## 🚀 StackVend Autonomous Implementation\n\n"
                        f"Automated delivery for **{product_id}**.\n"
                        f"{plan_summary_section}\n"
                        f"### 📦 Generated Components\n" + "\n".join([f"- `{p}`" for p in to_write.keys()]) + "\n\n"
                        f"<!-- castor-metadata: {{\"managed_by\": \"project-castor\", \"product_id\": \"{product_id}\", \"trace_id\": \"{trace_id or ''}\"}} -->\n"
                        f"<!-- managed-by: project-castor -->"
                    )
                    for pr_attempt in range(3):
                        try:
                            pr = repo.create_pull(
                                title=f"Feat({product_id}): Autonomous Implementation & Architecture Plan",
                                body=pr_body,
                                head=branch,
                                base=target_base_branch,   # FD-4CI-b-R1
                            )
                            pr_url = pr.html_url
                            created_pr_number = _created_pr_number(getattr(pr, "number", None))
                            pr_identity = _pr_identity_from_pull(pr)
                            try:
                                pr.add_to_labels("managed-by:project-castor")
                            except Exception:
                                pass
                            logger.info(f"Successfully opened Pull Request: {pr_url}")
                            break
                        except Exception as pr_err:
                            if pr_attempt < 2:
                                time.sleep(2.0)
                            else:
                                logger.info(f"Pull Request creation notice: {pr_err}")
                except Exception as pr_err:
                    logger.info(f"Pull Request creation notice: {pr_err}")

            self._write_iac_provenance(product_id, trace_id, files)
            self._write_app_provenance(product_id, trace_id, files)   # SAT-49 F4
            return {
                "status": "SUCCESS",
                "repo_name": full_repo_name,
                "branch_name": branch,
                "commit_sha": new_commit.sha,
                "pull_request_url": pr_url,
                "pr_number": created_pr_number,
                "pull_request": pr_identity,
                "base_branch": target_base_branch,  # this path cuts the branch from and opens the PR against it
                "files_committed": list(to_write.keys()),
                **base_head,   # RT14-13: the base head the commit's base check saw
                **({"files_deleted": to_delete} if to_delete else {}),
            }
        except Exception as e:
            logger.error(f"GitHub commit failed for '{full_repo_name}': {e}")
            return {
                "status": "FAILED",
                "error": str(e),
                "repo_name": full_repo_name,
                "pull_request_url": f"https://github.com/{full_repo_name}",
            }

    # FD-4P / FD-4BB: DeveloperAgent.merge_pull_request (substring / single-open-PR / PR #1 merges) is deleted.
    # The release step merges only through the PR ledger (apps/orchestrator-gateway/main.py:_release_merge).

