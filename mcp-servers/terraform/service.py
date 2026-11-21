"""
Project Castor: Terraform MCP Tool Server - Service Engine
Manages ephemeral workspace directories, GCS state locking, and deterministic Terraform execution.
"""

import ast
import base64
import json
import logging
import os
import posixpath
import re
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Set, Tuple, Union

try:
    from google.cloud import firestore
except ImportError:
    firestore = None

# FD-4G: no ImportError fallback -- a missing path guard must crash at boot, never fail open.
# S2-C C1b (register HS-63): API enablement uses the exact type / golden-module-source table shared with the gateway
# (shared/api_requirements.{json,py}; python-hcl2 + PyYAML pinned in requirements.txt). No fallback: a missing table
# must crash at boot, never enable APIs on a guess.
from shared.api_requirements import required_apis
# Lane 14 PR-0 (FD-4S): compliance plan gate client (sibling module; loaded by path when this file is).
try:
    import compliance_gate
except ImportError:  # pragma: no cover - service.py loaded by path without its directory on sys.path
    import importlib.util as _cg_util
    import sys as _cg_sys

    _cg_spec = _cg_util.spec_from_file_location(
        "compliance_gate", os.path.join(os.path.dirname(os.path.abspath(__file__)), "compliance_gate.py")
    )
    compliance_gate = _cg_util.module_from_spec(_cg_spec)
    _cg_sys.modules["compliance_gate"] = compliance_gate
    _cg_spec.loader.exec_module(compliance_gate)
# FD-4AQ W1b (AQ-X1a): the single provider allow-list source (sibling module; loaded by path when this file is).
try:
    import provider_allowlist
except ImportError:  # pragma: no cover - service.py loaded by path without its directory on sys.path
    import importlib.util as _pa_util
    import sys as _pa_sys

    _pa_spec = _pa_util.spec_from_file_location(
        "provider_allowlist", os.path.join(os.path.dirname(os.path.abspath(__file__)), "provider_allowlist.py")
    )
    provider_allowlist = _pa_util.module_from_spec(_pa_spec)
    _pa_sys.modules["provider_allowlist"] = provider_allowlist
    _pa_spec.loader.exec_module(provider_allowlist)
# FD-4CY W7: adoption of existing resources from the plan (sibling module; loaded by path when this file is).
try:
    import brownfield_adoption
except ImportError:  # pragma: no cover - service.py loaded by path without its directory on sys.path
    import importlib.util as _ba_util
    import sys as _ba_sys

    _ba_spec = _ba_util.spec_from_file_location(
        "brownfield_adoption", os.path.join(os.path.dirname(os.path.abspath(__file__)), "brownfield_adoption.py")
    )
    brownfield_adoption = _ba_util.module_from_spec(_ba_spec)
    _ba_sys.modules["brownfield_adoption"] = brownfield_adoption
    _ba_spec.loader.exec_module(brownfield_adoption)
# CLOUDSQL-CREATE-OWN-OPERATION: the deploy's own Cloud SQL create read back after a failed apply (sibling module).
try:
    import cloudsql_create_recovery
except ImportError:  # pragma: no cover - service.py loaded by path without its directory on sys.path
    import importlib.util as _csql_util
    import sys as _csql_sys

    _csql_spec = _csql_util.spec_from_file_location(
        "cloudsql_create_recovery",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "cloudsql_create_recovery.py")
    )
    cloudsql_create_recovery = _csql_util.module_from_spec(_csql_spec)
    _csql_sys.modules["cloudsql_create_recovery"] = cloudsql_create_recovery
    _csql_spec.loader.exec_module(cloudsql_create_recovery)
# FD-7L Phase 2a: the runner's brokered credentials, metadata endpoint and tofu env allow-list (sibling module).
try:
    import runner_credentials as runner_creds
except ImportError:  # pragma: no cover - service.py loaded by path without its directory on sys.path
    import importlib.util as _rc_util
    import sys as _rc_sys

    _rc_spec = _rc_util.spec_from_file_location(
        "runner_credentials", os.path.join(os.path.dirname(os.path.abspath(__file__)), "runner_credentials.py")
    )
    runner_creds = _rc_util.module_from_spec(_rc_spec)
    _rc_sys.modules["runner_credentials"] = runner_creds
    _rc_spec.loader.exec_module(runner_creds)
# SECRET-INITIAL-VERSION (red-team F1): plan JSON masking by the engine's sensitive marks (sibling module).
try:
    import plan_redaction
except ImportError:  # pragma: no cover - service.py loaded by path without its directory on sys.path
    import importlib.util as _pr_util
    import sys as _pr_sys

    _pr_spec = _pr_util.spec_from_file_location(
        "plan_redaction", os.path.join(os.path.dirname(os.path.abspath(__file__)), "plan_redaction.py")
    )
    plan_redaction = _pr_util.module_from_spec(_pr_spec)
    _pr_sys.modules["plan_redaction"] = plan_redaction
    _pr_spec.loader.exec_module(plan_redaction)
# SECRET-INITIAL-VERSION (red-team F2): the generated version never shadows an existing value (sibling module).
try:
    import secret_generation_guard
except ImportError:  # pragma: no cover - service.py loaded by path without its directory on sys.path
    import importlib.util as _sg_util
    import sys as _sg_sys

    _sg_spec = _sg_util.spec_from_file_location(
        "secret_generation_guard",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "secret_generation_guard.py")
    )
    secret_generation_guard = _sg_util.module_from_spec(_sg_spec)
    _sg_sys.modules["secret_generation_guard"] = secret_generation_guard
    _sg_spec.loader.exec_module(secret_generation_guard)
# DEPLOY-FAILURE-OWNER-ROUTER: who can change what made a deploy fail (sibling module, pure functions).
try:
    import deploy_failure_router as dfr
except ImportError:  # pragma: no cover - service.py loaded by path without its directory on sys.path
    import importlib.util as _dfr_util
    import sys as _dfr_sys

    _dfr_spec = _dfr_util.spec_from_file_location(
        "deploy_failure_router",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "deploy_failure_router.py")
    )
    dfr = _dfr_util.module_from_spec(_dfr_spec)
    _dfr_sys.modules["deploy_failure_router"] = dfr
    _dfr_spec.loader.exec_module(dfr)
# RT14-04: the deploy's own REST-only Kubernetes manifest applier (sibling module; invariant 7, no kubectl).
try:
    import k8s_manifest_apply
except ImportError:  # pragma: no cover - service.py loaded by path without its directory on sys.path
    import importlib.util as _k8s_util
    import sys as _k8s_sys

    _k8s_spec = _k8s_util.spec_from_file_location(
        "k8s_manifest_apply", os.path.join(os.path.dirname(os.path.abspath(__file__)), "k8s_manifest_apply.py"))
    k8s_manifest_apply = _k8s_util.module_from_spec(_k8s_spec)
    _k8s_sys.modules["k8s_manifest_apply"] = k8s_manifest_apply
    _k8s_spec.loader.exec_module(k8s_manifest_apply)
from shared import runner_identity as ri   # FD-7L: install mode + typed refusals (replica of the root shared/)
from shared.path_safety import (
    TF_WORKSPACE_RESERVED,
    UnsafePathError,
    safe_join,
    validate_manifest_keys,
    validate_path_component,
    validate_product_id,
    validate_trace_id,
)
from shared.static_mounts import static_placeholder_files  # FD55-A8-CONVERT: the gateway's W5 AST rule, one copy
# FD-4DT: byte-identical replica of the root shared/access_policy.py (tests/test_lane19_access_policy.py)
from shared.access_policy import ACCESS_WIDENING_APPROVAL_FIELD, AccessPolicy, deploy_access_tfvars

try:
    from shared.vcs_provider import IncompleteRepoTreeError, VCSProviderFactory
except ImportError:
    try:
        from vcs_provider import IncompleteRepoTreeError, VCSProviderFactory
    except ImportError:
        VCSProviderFactory = None

        class IncompleteRepoTreeError(RuntimeError):   # FD-4D: same contract as shared.vcs_provider's
            def __init__(self, repo, branch, tree_status):
                self.repo, self.branch, self.tree_status = repo, branch, dict(tree_status or {})
                super().__init__(f"repository tree of '{repo}' ({branch}) could not be read completely")

# FD-4D: deploy_workload error_class when the repository tree could not be read completely (truncated, errored).
REPO_TREE_INCOMPLETE = "REPO_TREE_INCOMPLETE"
# SAT-50 RT F1: the most files a Per-workload GitHub read accepts (the FD-7L Phase 4 bound: GitHubProvider's
# fetch_file_tree max_files default, pinned equal by tests/test_fd7l_4_repo_read.py). A larger tree is refused before
# any blob call.
REPO_READ_MAX_FILES = 2500
# SAT-50 follow-up (bounded rate-limit retry): a Per-workload GitHub read retries a 403/429 answer only when GitHub's
# own headers ask for a wait (`Retry-After: <seconds>`, or `X-RateLimit-Remaining: 0` with `X-RateLimit-Reset:
# <epoch>`; never the body), at most REPO_READ_RATE_LIMIT_RETRIES times per call, never for a wait longer than
# REPO_READ_RATE_LIMIT_MAX_WAIT_S and never past REPO_READ_RATE_LIMIT_TOTAL_WAIT_S of waiting for the whole read.
# Anything else stays the typed REPO_TREE_INCOMPLETE after one call.
REPO_READ_RATE_LIMIT_RETRIES = 3
REPO_READ_RATE_LIMIT_MAX_WAIT_S = 60
REPO_READ_RATE_LIMIT_TOTAL_WAIT_S = 180
_repo_read_sleep = time.sleep   # test seams (module level, read at call time)
_repo_read_clock = time.time

# FD-4G R-1: serialises terraform.rc rewrites across the FastAPI thread pool (concurrent cold-start tofu runs).
_RC_WRITE_LOCK = threading.Lock()
# FD-4BQ F1: serialises provider-mirror population (startup warm-up thread vs. concurrent tofu runs).
_MIRROR_LOCK = threading.Lock()

# FD-4H: fixed prefix of every held-state-lock error so callers (workflow, Control Center) can route it.
STATE_LOCKED_SENTINEL = "STATE_LOCKED:"

# FD-4AQ W3 (register AQ-5): time limits for every OpenTofu command `_run_subprocess` runs. At the limit the
# command's process group gets SIGINT (OpenTofu stops cleanly and releases the state lock), then SIGKILL after the
# grace period; the result carries error_class TOFU_TIMEOUT and deploy_workload fails with that class.
TOFU_TIMEOUT = "TOFU_TIMEOUT"


@dataclass(frozen=True)
class TofuTimeLimits:
    apply_destroy_s: float   # `apply` / `destroy`
    other_s: float           # every other subcommand (init, validate, plan, show, import, state, output, ...)
    grace_s: float = 60.0    # SIGINT -> SIGKILL

    def limit_for(self, cmd: List[str]) -> float:
        return self.apply_destroy_s if len(cmd) > 1 and cmd[1] in ("apply", "destroy") else self.other_s


# tf-applier job (fresh container per run, 24 h task timeout): apply/destroy 3 h, others 30 min; 15 min after SIGINT
# so in-flight Google Cloud creates can finish and land in state before the kill.
TOFU_TIME_LIMITS_JOB = TofuTimeLimits(apply_destroy_s=3 * 3600.0, other_s=30 * 60.0, grace_s=15 * 60.0)
# mcp-terraform-server (Cloud Run request limit 1800 s): one 20 min cap per command and 4 min after SIGINT, so limit +
# grace + the 30 s pipe drain of one command stay inside the request limit (per command, not per deploy).
TOFU_TIME_LIMITS_SERVICE = TofuTimeLimits(apply_destroy_s=20 * 60.0, other_s=20 * 60.0, grace_s=4 * 60.0)
# How long `_run_bounded` still reads a killed command's output pipes after SIGKILL.
TOFU_PIPE_DRAIN_S = 30.0
# DEPLOY-SYNC-BUDGET (owner 10-25; Fable RT F1): one overall time budget for a whole synchronous `/deploy` (main.py),
# not only per command. Cloud Run cuts that request at SYNC_REQUEST_LIMIT_S however many commands ran (the
# mcp-terraform-server template `timeout = "1800s"` in infra/platform/main.tf; both sync callers, the Control Center's
# EXPRESS_DEPLOY_TIMEOUT_SECONDS and vending's REDEPLOY_REQUEST_BUDGET_S, wait the same 1800 s; parity test
# tests/test_deploy_sync_budget.py). The budget leaves room, after the deadline, for the SIGINT grace, the pipe drain
# and a response margin (post-processing + the response; vending keeps 60 s too): SIGINT <= 1470 s, SIGKILL <= 1710 s,
# drain <= 1740 s, 60 s left. Each OpenTofu command of the deploy runs for at most min(its own limit, deadline - now),
# a command due to start after the deadline does not start, and the usual SIGINT -> grace -> SIGKILL and TOFU_TIMEOUT
# apply. The tf-applier job and the in-process /deploy-async path pass no budget (per-command limits only).
SYNC_REQUEST_LIMIT_S = 1800.0
SYNC_DEPLOY_RESPONSE_MARGIN_S = 60.0
SYNC_DEPLOY_TIME_BUDGET_S = (SYNC_REQUEST_LIMIT_S - TOFU_TIME_LIMITS_SERVICE.grace_s - TOFU_PIPE_DRAIN_S
                             - SYNC_DEPLOY_RESPONSE_MARGIN_S)   # 1470 s

# ------------------------------------------------------------------------------
# FD-4BA follow-up: Cloud Build source tarball ALLOW-list.
# The tarball used to contain the whole workspace, including the root terraform.tfvars that carries the host
# OAuth client secret and Firebase API key. What the build consumes is decided by the pack steps:
#   * services under apps/: each step runs `pack build --path=apps/<svc>`, so only apps/<svc>/** is read;
#   * no services: one `pack build` on the workspace root, so only app sources/manifests at the root are read.
# Never-list entries are excluded in both modes (IaC, state, plans, env files, keys/certs, VCS/tooling dirs).
# ------------------------------------------------------------------------------
_BUILD_SOURCE_NEVER_DIRS = frozenset({
    "infra", "k8s", ".terraform", ".git", ".github", "__pycache__", ".venv", "venv", "node_modules",
})
_BUILD_SOURCE_NEVER_NAMES = frozenset({
    "tfplan", "plan.bin", "terraform.rc", "Dockerfile", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
})
_BUILD_SOURCE_NEVER_SUFFIXES = (
    ".tfvars", ".tfvars.json", ".tfstate", ".tfstate.backup", ".tflock", ".tfplan", ".tf", ".tf.json",
    ".env", ".pem", ".key", ".p12", ".pfx", ".crt", ".cer", ".der", ".jks", ".keystore",
)
_BUILD_SOURCE_DOTFILE_ALLOW = frozenset({".python-version"})
# Root-mode allow-list (buildpack inputs and application sources/assets).
_ROOT_BUILD_SOURCE_NAMES = frozenset({
    "Procfile", "project.toml", "requirements.txt", "runtime.txt", "Pipfile", "Pipfile.lock", "pyproject.toml",
    "setup.py", "setup.cfg", "poetry.lock", "uv.lock", "package.json", "package-lock.json", "yarn.lock",
    "pnpm-lock.yaml", "go.mod", "go.sum", "alembic.ini", ".python-version",
})
_ROOT_BUILD_SOURCE_EXTENSIONS = frozenset({
    ".py", ".pyi", ".mako", ".sql", ".txt", ".toml", ".cfg", ".ini", ".lock", ".json", ".yaml", ".yml",
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go",
    ".html", ".htm", ".jinja", ".jinja2", ".j2", ".css", ".scss", ".map",
    ".svg", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".webp", ".woff", ".woff2", ".ttf", ".eot",
})


TOPOLOGY_RECORD_SCHEMA = "service_topology/v1"   # lane 10 (FD-51): shared/service_topology.TOPOLOGY_RECORD_SCHEMA


def _read_service_topology_intent(workspace_dir: str) -> Optional[Dict[str, Any]]:
    """The `intent` object of the platform-rendered `topology.json` (workspace root or infra/workload/) with schema
    service_topology/v1, or None (missing / unreadable / other schema). json.load only."""
    for rel in ("topology.json", os.path.join("infra", "workload", "topology.json")):
        path = os.path.join(workspace_dir, rel)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            continue
        if isinstance(doc, dict) and doc.get("schema") == TOPOLOGY_RECORD_SCHEMA and isinstance(doc.get("intent"), dict):
            return doc["intent"]
    return None


# ------------------------------------------------------------------------------
# TI-5 (typed IaC plan §4 TI-5; register TI-5a / TI-5b): the apply side of the typed IaC intent.
# A workspace whose repository holds the typed intent (`infra/workload/iac_intent.json`, schema iac_intent/v1; the
# platform renders all of its workload IaC from it) gets NO text healing of its IaC here: every apply-time HCL
# rewriter is skipped and a validate failure returns as a typed `validation_report` (shared/diagnostics
# ValidationReport shape, source "apply") instead of being patched. Human files (`human*.tf`), Terraform override
# files and, beside an intent, a legacy `custom.tf` are USER_OWNED on every workspace: never edited here.
# Exact path / basename rules and json.loads only (AGENTS.md invariant 2); nothing is guessed.
# ------------------------------------------------------------------------------
IAC_INTENT_SCHEMA = "iac_intent/v1"            # shared/iac_intent.SCHEMA_ID
IAC_INTENT_REPO_PATH = "infra/workload/iac_intent.json"   # shared/iac_intent.INTENT_PATH
IAC_INTENT_RENDER_BASENAME = "custom.tf.json"  # shared/iac_intent.RENDER_PATH (basename)
WORKLOAD_DIR = "infra/workload"


def workload_relpath(path: Any, workload_dir: str = WORKLOAD_DIR) -> Optional[str]:
    """FD-4D-b: the workspace path of a repository file under `workload_dir`: its path below that directory with
    every subdirectory kept (infra/workload/main.tf -> main.tf, infra/workload/modules/db/main.tf ->
    modules/db/main.tf). None for any other path. Exact path components only."""
    prefix = workload_dir.rstrip("/") + "/"
    if not isinstance(path, str) or not path.startswith(prefix) or len(path) == len(prefix):
        return None
    return path[len(prefix):]


# The deploy's workspace-root copy of the intent (FD-4D-b: the intent's path below infra/workload/).
IAC_INTENT_ROOT_PATH = workload_relpath(IAC_INTENT_REPO_PATH)
APPLY_INTENT_WITHOUT_TOPOLOGY = "APPLY.INTENT_WITHOUT_TOPOLOGY"
APPLY_INTENT_UNREADABLE = "APPLY.INTENT_UNREADABLE"
# FD55-TFVARS (register FD55-TFVARS): a workload terraform.tfvars / module source python-hcl2 cannot parse stops the
# deploy with this code (nothing built, planned or applied) instead of a line-pattern / regex guess. The deploy
# result's error_class is IAC_DEFECT (the workflow's bounded developer remediation), the code leads the error text.
APPLY_TFVARS_UNPARSEABLE = "APPLY.TFVARS_UNPARSEABLE"
APPLY_SOURCE_UNPARSEABLE = "APPLY.SOURCE_UNPARSEABLE"
# FD55-W6e (register FD55-W6e): infra/workloads/ (plural) .tf files beside a root config from infra/workload/ (or the
# repository root) would not be applied: a typed stop (IAC_DEFECT, nothing built, planned or applied), never a merge.
APPLY_PLURAL_WORKLOADS_NOT_APPLIED = "APPLY.PLURAL_WORKLOADS_NOT_APPLIED"
IAC_DEFECT_ERROR_CLASS = "IAC_DEFECT"
# FD55-W6c (register FD55-W6c; W6a review F3): a committed workflow file that fails validate_github_workflow_yaml stops
# deploy_workload / generate_plan with this code (status FAILED, the file and line the validator names; nothing is
# rewritten, built, planned or applied) instead of an unhandled WorkflowValidationError. The error_class routes it to
# the operator (workflows/main_orchestrator.yaml check_deploy_status, gate_errors.NON_REMEDIABLE_DEPLOY_CLASSES): the
# workflow files are platform renders, never AI IaC, so a developer regeneration is not the fix.
APPLY_WORKFLOW_INVALID = "APPLY.WORKFLOW_INVALID"
ERROR_WORKFLOW_INVALID = "WORKFLOW_INVALID"
# FD55-W3 / W6d (A30, HS-42): report-only finding for a vendored golden-module file that differs from the platform
# payload, on every workspace (logged; the workspace and the repository are left exactly as committed; the workload is
# marked "IaC outdated" in Control Center and the fix is the Upgrade IaC pull request).
PLATFORM_VENDORED_MODULE_STALE = "PLATFORM.VENDORED_MODULE_STALE"


# AQ-2 (register AQ-2, rows 42/46): the exact AccessMode values of shared/access_policy.py (parity test in
# tests/test_fd4aq_w1_no_host_secret.py). Only TENANT_SIGNIN_ACCESS_MODE gets a web sign-in key and Identity Platform
# setup at deploy; every other mode, and a missing or unreadable record, gets neither.
ACCESS_MODES = ("PUBLIC_APP", "PRIVATE_IAM", "PRIVATE_IAP")
TENANT_SIGNIN_ACCESS_MODE = "PUBLIC_APP"
TENANT_SIGNIN_ARTIFACTS_SKIPPED = "TENANT_SIGNIN_ARTIFACTS_SKIPPED"
# FD-55 W3 / AQ-3 review follow-up F3: a PUBLIC_APP workload whose web sign-in key could not be created or read is
# deployed without it (firebase_api_key ""); the deploy result then carries this typed warning (never a failure).
SIGNIN_KEY_MISSING = "SIGNIN_KEY_MISSING"

# FD-4DE (fail-loudly policy rule 1.4): a deploy never builds a run.app address from ids. Its service URL is the apply's
# own output, else the Cloud Run v2 API `uri` of the child project's service (REST through AuthorizedSession,
# invariant 7). When neither gives one, the URL is reported unknown: `service_url` is "" and
# `service_url_unknown_reason` is one of the typed reasons below; the result's warnings carry SERVICE_URL_UNKNOWN.
SERVICE_URL_UNKNOWN = "SERVICE_URL_UNKNOWN"
SERVICE_URL_API_UNAVAILABLE = "CLOUD_RUN_API_UNAVAILABLE"      # no credential, a non-200 answer, or an unreadable body
SERVICE_URL_NOT_FOUND = "CLOUD_RUN_SERVICE_NOT_FOUND"          # the region lists no service with a `uri`
SERVICE_URL_AMBIGUOUS = "CLOUD_RUN_SERVICE_AMBIGUOUS"          # several services and none has the workload's name
# FD-102 (register SEC-HOTFIX-SERVICE-URL-CONFIRMED): the apply's own output names a URL, but it is not a printable
# string equal to the `uri` or one of the `urls` of a service in the complete Cloud Run listing of the child region
SERVICE_URL_NOT_CONFIRMED = "CLOUD_RUN_URL_NOT_CONFIRMED"
SERVICE_URL_UNKNOWN_REASONS = (SERVICE_URL_API_UNAVAILABLE, SERVICE_URL_NOT_FOUND, SERVICE_URL_AMBIGUOUS,
                               SERVICE_URL_NOT_CONFIRMED)
CLOUD_RUN_API = "https://run.googleapis.com/v2"
_CLOUD_RUN_LIST_MAX_PAGES = 10


def _without_one_trailing_slash(url: str) -> str:
    return url[:-1] if url.endswith("/") else url


def confirm_cloud_run_service_url(value: Any,
                                  listed: Optional[List[Mapping[str, Any]]]) -> Tuple[str, Optional[str]]:
    """FD-102: (the listed URL, None) when `value` is Run-API-confirmed, else ("", typed reason).

    `value` is a URL the deploy did not read from the Cloud Run API (an apply output, which can be any JSON type).
    It must be a `str` whose every character is printable (`urlsplit` silently drops tab, CR and LF, so nothing is
    parsed before this check) and, after removing at most one trailing '/', equal the `uri` or one of the `urls` of a
    service in `listed`, the complete Cloud Run v2 listing of the child project's region (None = the listing failed:
    SERVICE_URL_API_UNAVAILABLE). The API's own string is returned (never the value), so from here on the URL is the
    API's. Anything else is SERVICE_URL_NOT_CONFIRMED; no listing URL is ever substituted for an unconfirmed value."""
    if not isinstance(value, str) or not value or not value.isprintable():
        return "", SERVICE_URL_NOT_CONFIRMED
    if listed is None:
        return "", SERVICE_URL_API_UNAVAILABLE
    wanted = _without_one_trailing_slash(value)
    for service in listed:
        if not isinstance(service, Mapping):
            continue
        urls = service.get("urls")
        for candidate in [service.get("uri")] + (list(urls) if isinstance(urls, list) else []):
            if (isinstance(candidate, str) and candidate and candidate.isprintable()
                    and _without_one_trailing_slash(candidate) == wanted):
                return candidate, None
    return "", SERVICE_URL_NOT_CONFIRMED


def cloud_run_service_short_name(service: Mapping[str, Any]) -> str:
    """The last segment of a Cloud Run v2 resource name (`projects/*/locations/*/services/<name>`), else ""."""
    name = service.get("name") if isinstance(service, Mapping) else None
    return name.rsplit("/", 1)[-1] if isinstance(name, str) else ""


def pick_cloud_run_service_url(services: List[Mapping[str, Any]],
                               candidate_names: Tuple[str, ...]) -> Tuple[str, Optional[str]]:
    """FD-4DE: (url, None) for the workload's service in a complete Cloud Run v2 listing of its child project's region,
    else ("", typed reason). The child project is the workload's alone, so one service with a `uri` is its service;
    with several, the first of `candidate_names` that is exactly a service's name decides. The url is the API's `uri`
    as given (never rebuilt)."""
    with_uri = [s for s in services if isinstance(s, Mapping) and isinstance(s.get("uri"), str) and s.get("uri")]
    if not with_uri:
        return "", SERVICE_URL_NOT_FOUND
    if len(with_uri) == 1:
        return with_uri[0]["uri"], None
    by_name = {cloud_run_service_short_name(s): s["uri"] for s in with_uri}
    for cand in candidate_names:
        if cand and cand in by_name:
            return by_name[cand], None
    return "", SERVICE_URL_AMBIGUOUS


def deploy_url_summary(res: Any) -> str:
    """FD-4DE: the URL part of a deploy summary line: the reported URL, "unknown (<reason>)" when the deploy says
    it could not be read, else "N/A" (no URL expected)."""
    if not isinstance(res, Mapping):
        return "N/A"
    url = res.get("service_url")
    if isinstance(url, str) and url:
        return url
    reason = res.get("service_url_unknown_reason")
    return f"unknown ({reason})" if isinstance(reason, str) and reason else "N/A"


def callback_outputs(res: Any) -> Dict[str, str]:
    """FD-102: the `outputs` a deploy outcome carries (callback body; `shared/callbacks.py` writes its `service_url`
    into `pipeline_executions.outputs`): only the deploy's own `service_url`, a confirmed string or "". Never the
    Terraform output map (which the result's `outputs` is), so a workload's output cannot become the run's URL."""
    url = res.get("service_url") if isinstance(res, Mapping) else None
    return {"service_url": url if isinstance(url, str) else ""}


SIGNIN_DOMAINS_INCOMPLETE = "SIGNIN_DOMAINS_INCOMPLETE"


def signin_domains_incomplete_warning(target_project_id: str, reason: str) -> Dict[str, str]:
    """FD-4DE RT N1: the typed warning of a PUBLIC_APP deploy whose Cloud Run listing failed in the sign-in domain
    step, so hosts only the API names (e.g. the deterministic <name>-<number> form) were not authorized."""
    return {
        "code": SIGNIN_DOMAINS_INCOMPLETE,
        "reason": reason,
        "message": (f"{SIGNIN_DOMAINS_INCOMPLETE} ({reason}): the Cloud Run services of project "
                    f"'{target_project_id}' could not be listed, so only the known service URL, localhost and the "
                    f"firebaseapp domain were authorized for sign-in; a later deploy whose listing works adds the rest."),
    }


def service_url_unknown_warning(product_id: str, reason: str) -> Dict[str, str]:
    """FD-4DE: the typed warning of a successful deploy whose service URL could not be read (never guessed)."""
    return {
        "code": SERVICE_URL_UNKNOWN,
        "reason": reason,
        "message": (f"{SERVICE_URL_UNKNOWN} ({reason}): the deploy of '{product_id}' succeeded, but its service URL "
                    f"could not be read from the apply outputs or the Cloud Run API, so it is reported as unknown."),
    }


# FD55-3D (register FOLLOWUPS-1025, owner 10-25): after a deploy with a fresh container build, each Cloud Run service
# is rolled to a new revision of exactly the image the apply set for it, read from the applied state (`tofu show
# -json`): `values.template[0].containers[0].image` of every managed `google_cloud_run_v2_service`, in the root module
# and every child module. No image is derived from folder or service names and there is no `:latest` fallback. A state
# that cannot be read, or a Cloud Run service in it whose name, location or image cannot be read, stops the deploy
# typed (OQ-10, the recommended answer): ROLLOUT_IMAGE_UNREADABLE, operator_required, and nothing is rolled.
# RT F4: a Cloud Run service the state places in another project than the deploy's target stops it the same way, as
# ROLLOUT_SERVICE_OUTSIDE_TARGET. RT F1: only a service whose applied image is inside the Artifact Registry repository
# this deploy's build pushed to (rollout_repository_prefix, exact prefix equality) is rolled; the other services keep
# their revision and are listed in the result's `rollout_skipped`. RT F3: the state is read with its own fixed time
# budget (ROLLOUT_STATE_READ_BUDGET_S), not what is left of the deploy's, so a successful apply is not reported FAILED
# only because the deploy's budget ran out after it.
ROLLOUT_IMAGE_UNREADABLE = "ROLLOUT_IMAGE_UNREADABLE"
ROLLOUT_SERVICE_OUTSIDE_TARGET = "ROLLOUT_SERVICE_OUTSIDE_TARGET"
CLOUD_RUN_V2_SERVICE_TYPE = "google_cloud_run_v2_service"
# Within SYNC_DEPLOY_RESPONSE_MARGIN_S (60 s) of a sync /deploy: a state read past the deadline still ends, with the
# SIGINT grace and pipe drain, inside the request limit.
ROLLOUT_STATE_READ_BUDGET_S = 30.0
# DEPLOY-FAILURE-OWNER-ROUTER: the read-only `plan -json` re-run that classifies a failed plan gets at most this long,
# and never more than what is left of a deploy with a budget (sync /deploy); under CLASSIFY_PLAN_MIN_S it is not run.
CLASSIFY_PLAN_BUDGET_S = 600.0
CLASSIFY_PLAN_MIN_S = 30.0


def rollout_repository_prefix(region: str, project_id: str, repository: str) -> str:
    """FD55-3D RT F1: `<region>-docker.pkg.dev/<project>/<repository>/`, the Artifact Registry repository the deploy's
    build pushes to (the same values as the deploy's image_tag)."""
    return f"{region}-docker.pkg.dev/{project_id}/{repository}/"


class AppliedStateUnreadable(ValueError):
    """FD55-3D: the applied state JSON is not the documented `tofu show -json` shape (not an object, or a `values` /
    `root_module` / `resources` / `child_modules` member of the wrong JSON type)."""


def _first_block(value: Any) -> Optional[Mapping[str, Any]]:
    """A nested block in state JSON is a list of objects (`template = [{...}]`); the first one, else None."""
    if isinstance(value, list) and value and isinstance(value[0], Mapping):
        return value[0]
    return None


def applied_cloud_run_services(state: Any) -> Tuple[List[Dict[str, str]], List[str]]:
    """FD55-3D: (services, unreadable) from the parsed `tofu show -json` of the applied state.

    `services` is one {"address", "name", "location", "project", "image"} per managed google_cloud_run_v2_service
    (root module and every child module, in state order); `image` is its `template[0].containers[0].image`, the
    container the post-apply rollout sets (`_rollout_cloud_run_revision` writes containers[0] only). `project` is ""
    when the state does not name one. `unreadable` lists the addresses of Cloud Run services whose name, location or
    image is not a non-empty string. A state with no `values` (nothing applied yet) has no services.
    Raises AppliedStateUnreadable when the JSON does not have the documented shape."""
    if not isinstance(state, Mapping):
        raise AppliedStateUnreadable("the state JSON is not an object")
    values = state.get("values")
    if values is None:
        return [], []
    if not isinstance(values, Mapping):
        raise AppliedStateUnreadable("`values` is not an object")
    services: List[Dict[str, str]] = []
    unreadable: List[str] = []

    def _walk(module: Any, where: str) -> None:
        if module is None:
            return
        if not isinstance(module, Mapping):
            raise AppliedStateUnreadable(f"{where} is not an object")
        resources = module.get("resources")
        if resources is not None and not isinstance(resources, list):
            raise AppliedStateUnreadable(f"{where}.resources is not a list")
        for res in resources or []:
            if not isinstance(res, Mapping):
                raise AppliedStateUnreadable(f"{where}.resources has an entry that is not an object")
            if res.get("mode") != "managed" or res.get("type") != CLOUD_RUN_V2_SERVICE_TYPE:
                continue
            address = res.get("address") if isinstance(res.get("address"), str) else f"{where}.<no address>"
            attrs = res.get("values")
            attrs = attrs if isinstance(attrs, Mapping) else {}
            name, location, project = attrs.get("name"), attrs.get("location"), attrs.get("project")
            template = _first_block(attrs.get("template"))
            container = _first_block(template.get("containers")) if template is not None else None
            image = container.get("image") if container is not None else None
            if not all(isinstance(v, str) and v for v in (name, location, image)):
                unreadable.append(address)
                continue
            services.append({"address": address, "name": name, "location": location,
                             "project": project if isinstance(project, str) else "", "image": image})
        children = module.get("child_modules")
        if children is not None and not isinstance(children, list):
            raise AppliedStateUnreadable(f"{where}.child_modules is not a list")
        for child in children or []:
            child_where = child.get("address") if isinstance(child, Mapping) else None
            _walk(child, child_where if isinstance(child_where, str) else f"{where}.child_modules[]")

    _walk(values.get("root_module"), "root_module")
    return services, unreadable


def rollout_image_unreadable_result(product_id: str, target_project_id: str, detail: str,
                                    error_class: str = ROLLOUT_IMAGE_UNREADABLE) -> Dict[str, Any]:
    """FD55-3D: the typed failure of a deploy whose applied Cloud Run images could not be read (OQ-10), or (RT F4,
    `error_class` ROLLOUT_SERVICE_OUTSIDE_TARGET) whose state holds a Cloud Run service in another project."""
    what = ("the state holds a Cloud Run service in another project than the target"
            if error_class == ROLLOUT_SERVICE_OUTSIDE_TARGET else
            "the image it set for each Cloud Run service could not be read from the applied state")
    error = (f"{error_class}: the apply of '{product_id}' in '{target_project_id}' succeeded and the infrastructure is "
             f"in place, but {what} ({detail}), so no service was rolled to a new revision: the services keep their "
             f"previous revision until the deploy is re-run. Nothing is guessed; re-run the deploy, or read the state "
             f"with `tofu show -json`.")
    return {"error_class": error_class, "error": error, "operator_required": True}


def workload_access_mode(record: Any) -> Optional[str]:
    """AQ-2: the exact access mode of a workload's `access` record (a mapping whose `mode` is exactly one of
    ACCESS_MODES), else None (no record, or not a readable one). Exact string equality only."""
    if not isinstance(record, Mapping):
        return None
    mode = record.get("mode")
    return mode if isinstance(mode, str) and mode in ACCESS_MODES else None


# ------------------------------------------------------------------------------
# FD-4DT (access applies on Fast-Path): every deploy applies the workload's CURRENT access record
# (`workloads/{pid}.access`), not the copy the developer stage baked into the committed terraform.tfvars, so a
# DEPLOY_ONLY re-apply after an administrator's change applies that change without regenerating code. The record is
# platform data: it is rendered into one platform-owned variable file of the deploy workspace (JSON, exact values from
# shared.access_policy.deploy_access_tfvars), never into a committed file. The file is passed to the deploy as the
# manifest key below, so it replaces a repository file at that path, and the flattening copies it to the workspace
# root; OpenTofu loads it automatically (*.auto.tfvars.json, over terraform.tfvars) and the gated plan also names it
# with -var-file, so no other variable file of the workspace can override it. When nothing is rendered (no record,
# a PUBLIC_APP record, an Express workload, no Firestore client) the file is "{}" and the committed values apply as
# before. Refusals are typed and stop the deploy before anything is fetched, built or planned.
# ------------------------------------------------------------------------------
PLATFORM_ACCESS_VARS_FILE = "stackvend-access.auto.tfvars.json"
PLATFORM_ACCESS_VARS_MANIFEST_KEY = "infra/workload/" + PLATFORM_ACCESS_VARS_FILE
# The developer stage's exact access error classes (apps/orchestrator-gateway/developer_agent/errors.py; parity test)
ACCESS_POLICY_INVALID = "ACCESS_POLICY_INVALID"
ACCESS_POLICY_INCOMPLETE = "ACCESS_POLICY_INCOMPLETE"
ACCESS_POLICY_UNAVAILABLE = "ACCESS_POLICY_UNAVAILABLE"
ACCESS_WIDENING_UNAPPROVED = "ACCESS_WIDENING_UNAPPROVED"
ACCESS_VARS_NOT_RENDERED = "ACCESS_VARS_NOT_RENDERED"   # log code: the committed access values apply
ACCESS_APPLIED_AUDIT_ACTION = "WORKLOAD_ACCESS_APPLIED"
# FD-4DT RT F3: deploy_workload accepts only a canonical workload id (RFC 1123 label, shared.path_safety), so the
# access record is read under the same id the deploy uses for the repository, the state prefix and import IDs.
PRODUCT_ID_INVALID = "PRODUCT_ID_INVALID"
EXPRESS_CREATION_MODE = "EXPRESS"


class DeployAccessRefused(Exception):
    """FD-4DT: the current access record cannot be applied; the deploy stops before anything runs."""

    def __init__(self, error_class: str, message: str, operator_required: bool):
        super().__init__(message)
        self.error_class, self.message, self.operator_required = error_class, message, operator_required

    def result(self, product_id: str, trace_id: str) -> Dict[str, Any]:
        out: Dict[str, Any] = {"status": "FAILED", "error_class": self.error_class,
                               "error": f"{self.error_class}: {self.message}. Nothing was built, planned or applied.",
                               "product_id": product_id, "trace_id": trace_id}
        if self.operator_required:
            out["operator_required"] = True   # WF-OPERATOR-FLAG: the workflow stops for an operator, no retry
        return out


def render_deploy_access_vars(product_id: str, workload: Any) -> Tuple[str, Dict[str, Any]]:
    """FD-4DT: (the platform access var file text, a summary for logs / audit) from the stored workload document.

    Pure: typed checks only, the same validation as the developer stage (shared AccessPolicy model). ``workload`` is
    the `workloads/{pid}` document as a dict, or None when there is none.

    * not a dict / no `access` field / `creation_mode` EXPRESS (Express renders its access as module arguments at each
      Express submit) -> "{}" (nothing rendered: the committed values apply, as before);
    * `access_widening_approval` present and non-null (L19-F4) -> ACCESS_WIDENING_UNAPPROVED (operator): a widening is
      applied only by a full build that passed its plan approval;
    * an `access` value that is not a valid AccessPolicy -> ACCESS_POLICY_INVALID (operator);
    * a private record without principals -> ACCESS_POLICY_INCOMPLETE (operator);
    * PUBLIC_APP -> "{}" (deploy_access_tfvars: never opened by a variable);
    * PRIVATE_IAM / PRIVATE_IAP -> the three variables, exact."""
    if not isinstance(workload, dict) or workload.get("access") is None:
        return "{}", {"rendered": False, "reason": "NO_ACCESS_RECORD"}
    if workload.get("creation_mode") == EXPRESS_CREATION_MODE:
        return "{}", {"rendered": False, "reason": "EXPRESS_WORKLOAD"}
    if workload.get(ACCESS_WIDENING_APPROVAL_FIELD) is not None:
        raise DeployAccessRefused(
            ACCESS_WIDENING_UNAPPROVED,
            f"workloads/{product_id}.access was widened and the widening is not approved yet; relaunch with a full "
            "build (Full Swarm Rebuild) so the plan approval (ACCESS_WIDENED) can clear it", operator_required=True)
    record = workload.get("access")
    try:
        if not isinstance(record, Mapping):
            raise ValueError("not an object")
        policy = AccessPolicy.model_validate(dict(record))
    except (ValueError, TypeError) as err:   # pydantic ValidationError is a ValueError
        detail = "; ".join(str(e.get("msg", ""))[:160] for e in err.errors()[:3]) if hasattr(err, "errors") else str(err)
        raise DeployAccessRefused(
            ACCESS_POLICY_INVALID, f"workloads/{product_id}.access is not a valid access record ({detail}); an "
            f"administrator sets it (PATCH /api/workloads/{product_id}/access)", operator_required=True) from None
    try:
        values = deploy_access_tfvars(policy)
    except ValueError as err:   # AccessPolicyIncompleteError
        raise DeployAccessRefused(ACCESS_POLICY_INCOMPLETE, f"workloads/{product_id}.access: {err}",
                                  operator_required=True) from None
    summary: Dict[str, Any] = {"mode": policy.mode.value, "invoker_principals": policy.invoker_members(),
                               "access_updated_at": workload.get("access_updated_at"),
                               "access_updated_by": workload.get("access_updated_by")}
    if values is None:
        return "{}", dict(summary, rendered=False, reason="PUBLIC_APP_RECORD")
    return json.dumps(values, indent=2, sort_keys=True) + "\n", dict(summary, rendered=True)


# AQ-3 (register AQ-3): each PUBLIC_APP workload's one web sign-in key, by a fixed key ID, limited to the two Google
# sign-in APIs (apikeys v2, REST through AuthorizedSession).
APIKEYS_API = "https://apikeys.googleapis.com/v2"
WEB_KEY_ID = "stackvend-web"
WEB_KEY_DISPLAY_NAME = "StackVend web sign-in key"
WEB_KEY_API_TARGETS = ({"service": "identitytoolkit.googleapis.com"}, {"service": "securetoken.googleapis.com"})
LEGACY_WEB_KEY_RESTRICTED = "LEGACY_WEB_KEY_RESTRICTED"
_APIKEYS_OP_POLL_ATTEMPTS = 30
_APIKEYS_OP_POLL_SECONDS = 2.0
_APIKEYS_LIST_MAX_PAGES = 10


class SourceUnparseableError(ValueError):
    """FD55-TFVARS: a flattened root .tf file python-hcl2 cannot parse, so its module sources cannot be re-anchored
    by the parser (no regex fallback)."""
# The report rides in the workflow callback body (Cloud Workflows keeps every variable within 512 KB), so it keeps
# at most 20 error diagnostics (then `truncated`), each field capped like shared/diagnostics (MESSAGE_CAP).
APPLY_REPORT_MAX_DIAGNOSTICS = 20
_APPLY_MESSAGE_CAP = 2048            # shared/diagnostics.MESSAGE_CAP (bytes)


def _iac_intent_doc(text: Any) -> Optional[Dict[str, Any]]:
    """The parsed typed intent (a JSON object with schema iac_intent/v1), else None. json.loads only."""
    if not isinstance(text, str):
        return None
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    return doc if isinstance(doc, dict) and doc.get("schema") == IAC_INTENT_SCHEMA else None


def iac_intent_state(files: Mapping[str, Any]) -> str:
    """The gateway's sticky rule (iac_intent_contract.iac_intent_mode_decision, TI-3 RT F7): a repository is on the
    intent path when it holds the intent AND the platform's render of it (custom.tf.json). Then "intent" when the
    intent (exact repository path, and the deploy's workspace copy at its path below infra/workload/ when present,
    FD-4D-b) is a valid typed intent, else
    "unreadable". A lone intent or a lone render is "" (today's path, exactly as the gateway generated it)."""
    files = files or {}
    intent_keys = [k for k in (IAC_INTENT_REPO_PATH, IAC_INTENT_ROOT_PATH) if k in files]
    render_keys = [k for k in (WORKLOAD_DIR + "/" + IAC_INTENT_RENDER_BASENAME, IAC_INTENT_RENDER_BASENAME)
                   if k in files]
    if not intent_keys or not render_keys:
        return ""
    return "intent" if all(_iac_intent_doc(files[k]) is not None for k in intent_keys) else "unreadable"


def files_have_iac_intent(files: Mapping[str, Any]) -> bool:
    """TI-5: the manifest holds a valid typed intent (see iac_intent_state)."""
    return iac_intent_state(files) == "intent"


def workspace_has_iac_intent(workspace_dir: str) -> bool:
    """TI-5a: True when the prepared workspace is on the intent path (iac_intent_state over its intent and render
    files, root copy or infra/workload/), json.loads only like _read_service_topology_intent. Missing / unreadable
    -> False."""
    files: Dict[str, str] = {}
    for rel in (IAC_INTENT_REPO_PATH, IAC_INTENT_ROOT_PATH,
                "infra/workload/" + IAC_INTENT_RENDER_BASENAME, IAC_INTENT_RENDER_BASENAME):
        try:
            with open(os.path.join(workspace_dir, rel), "r", encoding="utf-8") as fh:
                files[rel] = fh.read()
        except OSError:
            continue
    return iac_intent_state(files) == "intent"


def manifest_has_service_topology(files: Mapping[str, Any]) -> bool:
    """The manifest holds the platform-rendered topology.json (service_topology/v1 with an object intent)."""
    for rel in ("topology.json", "infra/workload/topology.json"):
        text = (files or {}).get(rel)
        if not isinstance(text, str):
            continue
        try:
            doc = json.loads(text)
        except ValueError:
            continue
        if isinstance(doc, dict) and doc.get("schema") == TOPOLOGY_RECORD_SCHEMA and isinstance(doc.get("intent"), dict):
            return True
    return False


def apply_user_owned(relpath: str, intent_workspace: bool = False) -> bool:
    """TI-5b (S2-F F3 / HS-67, server-side classifier of plan RT F9): a USER_OWNED Terraform file is never edited by an
    apply-time fixer. Exact basename rules of shared/artifact_ownership: `human*.tf` (the human architect's files),
    Terraform override files (`override.tf`, `*_override.tf`, and their `.tf.json` forms), and on an intent
    workspace a legacy `custom.tf` (the intent path never writes one). Everything else is not decided here."""
    base = os.path.basename(relpath or "")
    if base.startswith("human") and base.endswith((".tf", ".tf.json")):
        return True
    if base in ("override.tf", "override.tf.json") or base.endswith(("_override.tf", "_override.tf.json")):
        return True
    return bool(intent_workspace) and base == "custom.tf"


def _apply_code_slug(summary: str) -> str:
    """Naming only (byte-identical rule to developer_agent/validators/tofu_diagnostics.slug; parity test in
    tests/test_ti5_apply_side.py): the title before the first ": ", double-quoted spans dropped, upper-cased, runs of
    non-alphanumerics -> "_", at most 80 characters. Never decides routing or a rewrite."""
    title = (summary or "").split(": ", 1)[0]
    out: List[str] = []
    in_quote = False
    for ch in title:
        if ch == '"':
            in_quote = not in_quote
            continue
        if in_quote:
            continue
        out.append(ch.upper() if ch.isalnum() else "_")
    text = "".join(out)
    while "__" in text:
        text = text.replace("__", "_")
    return text.strip("_")[:80].strip("_") or "UNKNOWN"


def _cap_text(text: Any, limit: int = _APPLY_MESSAGE_CAP) -> Optional[str]:
    if not isinstance(text, str):
        return None
    raw = text.encode("utf-8")
    return text if len(raw) <= limit else raw[:limit].decode("utf-8", errors="ignore")


def _snippet_of(snippet: Any) -> Optional[str]:
    """The engine's source snippet, capped like shared/diagnostics (SNIPPET_MAX_LINES lines, then MESSAGE_CAP)."""
    code = snippet.get("code") if isinstance(snippet, dict) else None
    return _cap_text("\n".join(code.split("\n")[:11])) if isinstance(code, str) else None


class _JsonSpans:
    """Byte spans of the top-level `module.<name>` / `resource.<type>.<name>` / `output.<name>` objects of a
    Terraform JSON file: a closed recursive-descent JSON scanner over the exact bytes (no pattern matching). Used to
    put an engine diagnostic's byte offset on the intent entry the platform rendered there."""

    def __init__(self, raw: bytes):
        self.raw, self.i = raw, 0

    def _ws(self) -> None:
        while self.i < len(self.raw) and self.raw[self.i] in b" \t\r\n":
            self.i += 1

    def _string(self) -> str:
        start = self.i
        self.i += 1
        while self.raw[self.i] != 0x22:
            self.i += 2 if self.raw[self.i] == 0x5C else 1
        self.i += 1
        return json.loads(self.raw[start:self.i].decode("utf-8"))

    def _value(self, path: Tuple[str, ...], out: Dict[str, Tuple[int, int]]) -> None:
        self._ws()
        start = self.i
        c = self.raw[self.i]
        if c == 0x7B:   # {
            self.i += 1
            self._ws()
            if self.raw[self.i] == 0x7D:
                self.i += 1
            else:
                while True:
                    self._ws()
                    key = self._string()
                    self._ws()
                    self.i += 1   # :
                    self._value(path + (key,), out)
                    self._ws()
                    if self.raw[self.i] == 0x2C:
                        self.i += 1
                        continue
                    self.i += 1   # }
                    break
        elif c == 0x5B:   # [
            self.i += 1
            self._ws()
            if self.raw[self.i] == 0x5D:
                self.i += 1
            else:
                while True:
                    self._value(path + ("[]",), out)
                    self._ws()
                    if self.raw[self.i] == 0x2C:
                        self.i += 1
                        continue
                    self.i += 1
                    break
        elif c == 0x22:
            self._string()
        else:
            while self.i < len(self.raw) and self.raw[self.i] not in b",]} \t\r\n":
                self.i += 1
        if (len(path) == 2 and path[0] in ("module", "output")) or (len(path) == 3 and path[0] == "resource"):
            addr = ".".join(path[1:]) if path[0] == "resource" else ".".join(path)
            out[addr] = (start, self.i)

    def spans(self) -> Dict[str, Tuple[int, int]]:
        out: Dict[str, Tuple[int, int]] = {}
        try:
            self._value((), out)
        except (IndexError, ValueError):
            return {}
        return out


def _intent_entry_pointers(intent_doc: Optional[Mapping[str, Any]]) -> Dict[str, str]:
    """{"module.<name>": "/modules/<i>", "<type>.<name>": "/resources/<i>", "output.<name>": "/outputs/<i>"} of the
    typed intent (exact list positions; the same pointers the gateway's provenance map uses)."""
    out: Dict[str, str] = {}
    if not isinstance(intent_doc, Mapping):
        return out
    for key, fmt in (("modules", "module.{name}"), ("resources", "{type}.{name}"), ("outputs", "output.{name}")):
        for n, e in enumerate(intent_doc.get(key) or []):
            if isinstance(e, dict) and isinstance(e.get("name"), str) and (key != "resources"
                                                                            or isinstance(e.get("type"), str)):
                out.setdefault(fmt.format(name=e["name"], type=e.get("type")), f"/{key}/{n}")
    return out


def apply_validation_report(validate_json: str, workspace_dir: str, *, source: str = "apply",
                            fallback_error: str = "", manifest_paths: Optional[Any] = None,
                            engine_result: bool = True) -> Dict[str, Any]:
    """TI-5a (S2-F F1 subset, intent workspaces): `tofu validate -json` output -> a typed report with the exact field
    set of shared.diagnostics.ValidationReport (validated against the real model in tests/test_ti5_apply_side.py).
    Per engine diagnostic: code "TF." + slug(summary) (naming only), its own range, and its owner by exact path:
    the render of the intent (custom.tf.json) -> CODE_DEFECT on the intent entry whose rendered object holds the
    diagnostic's byte offset (block_address + `attribute_path` = the intent pointer, file = the intent); a
    USER_OWNED file -> BROWNFIELD_CONFLICT; every other file (platform renders, vendored modules, unlocated) ->
    PLATFORM_DEFECT. Unparseable output -> one TF.UNPARSED_APPLY_ERROR diagnostic with the engine's text verbatim
    (PLATFORM_DEFECT: nothing is parsed out of error text).

    Fable RT F1: `engine_result=False` means no engine result exists (the failure happened before or outside
    tofu: init retries, container build, Secret Manager, ...): the report is then status UNAVAILABLE
    (GATE_UNAVAILABLE), `tools_ran` [] / `tools_unavailable` ["tofu"], with the deploy's text verbatim as one
    report-only APPLY.UNTYPED_FAILURE diagnostic, and nothing is read from disk. The intent is read only from an
    absolute `workspace_dir` (never relative to the process CWD).
    Fable RT F5: a root file maps to `infra/workload/<name>` only when the deploy manifest (`manifest_paths`) holds
    that exact repository path; a server-written root file (backend.tf, terraform.tfvars) or an unknown one keeps no
    repository path (`<workspace>/<name>`, which no ownership set holds: PLATFORM_DEFECT)."""
    if not engine_result:
        note = {"tool": "platform", "code": "APPLY.UNTYPED_FAILURE", "severity": "warning",
                "error_class": "PLATFORM_DEFECT", "file": "<unlocated>", "line": None, "column": None,
                "end_line": None, "block_address": None, "attribute_path": None, "symbol": None,
                "message": _cap_text(fallback_error or "deploy failed") or "", "detail": None, "snippet": None,
                "hint": None, "source": source, "iteration": 0}
        return {"status": "UNAVAILABLE", "error_class": "GATE_UNAVAILABLE", "source": source, "artifact_hash": "",
                "tools_ran": [], "tools_unavailable": ["tofu"], "diagnostics": [], "report_only": [note],
                "truncated": False, "repair_iteration": 0, "duration_ms": 0}
    manifest = frozenset(manifest_paths or ())
    readable = bool(workspace_dir) and os.path.isabs(workspace_dir)
    intent_doc = None
    for rel in ((IAC_INTENT_ROOT_PATH, IAC_INTENT_REPO_PATH) if readable else ()):
        try:
            with open(os.path.join(workspace_dir, rel), "r", encoding="utf-8") as fh:
                intent_doc = _iac_intent_doc(fh.read())
        except OSError:
            continue
        if intent_doc is not None:
            break
    pointers = _intent_entry_pointers(intent_doc)
    spans: Dict[str, Dict[str, Tuple[int, int]]] = {}
    diags: List[Dict[str, Any]] = []

    def diag(**kw: Any) -> Dict[str, Any]:
        base = {"tool": "tofu", "severity": "error", "error_class": "PLATFORM_DEFECT", "file": "<unlocated>",
                "line": None, "column": None, "end_line": None, "block_address": None, "attribute_path": None,
                "symbol": None, "message": "", "detail": None, "snippet": None, "hint": None, "source": source,
                "iteration": 0}
        base.update(kw)
        return base

    try:
        vj = json.loads(validate_json or "")
        raw_diags = vj.get("diagnostics") if isinstance(vj, dict) else None
        if not isinstance(raw_diags, list):
            raise ValueError("no diagnostics list")
    except ValueError:
        raw_diags = None
    if raw_diags is None:
        diags.append(diag(code="TF.UNPARSED_APPLY_ERROR", message=_cap_text(fallback_error or validate_json or
                                                                            "validate failed") or ""))
    for raw in raw_diags or []:
        if not isinstance(raw, dict) or raw.get("severity") != "error":
            continue
        rng = raw.get("range") if isinstance(raw.get("range"), dict) else {}
        fname = rng.get("filename") if isinstance(rng.get("filename"), str) else ""
        start = rng.get("start") if isinstance(rng.get("start"), dict) else {}
        end = rng.get("end") if isinstance(rng.get("end"), dict) else {}
        repo_path = fname
        if fname and "/" not in fname:
            # a root file is a repository file only when the deploy flatten copied it from infra/workload/ (exact
            # manifest path, RT F5); anything else at the root was written by the server (backend.tf, tfvars)
            repo_path = ("infra/workload/" + fname) if ("infra/workload/" + fname) in manifest else (
                "<workspace>/" + fname)
        elif fname and not os.path.isabs(fname) and ("infra/workload/" + fname) in manifest:
            # FD-4D-b: a nested infra/workload/ file is copied to its path below infra/workload/ (subdirs kept)
            repo_path = "infra/workload/" + fname
        kw: Dict[str, Any] = dict(code="TF." + _apply_code_slug(raw.get("summary") or ""),
                                  file=repo_path or "<unlocated>", line=start.get("line"),
                                  column=start.get("column"), end_line=end.get("line"),
                                  message=_cap_text(raw.get("summary") or "") or "",
                                  detail=_cap_text(raw.get("detail")) or None,
                                  snippet=_snippet_of(raw.get("snippet")))
        if (fname and os.path.basename(fname) == IAC_INTENT_RENDER_BASENAME and intent_doc is not None
                and not os.path.isabs(fname) and ".." not in fname.split("/")):
            if fname not in spans:
                try:
                    with open(os.path.join(workspace_dir, fname), "rb") as fh:
                        spans[fname] = _JsonSpans(fh.read()).spans()
                except OSError:
                    spans[fname] = {}
            off = start.get("byte")
            hit = [a for a, (s, e) in spans[fname].items() if isinstance(off, int) and s <= off < e]
            addr = min(hit, key=lambda a: spans[fname][a][1] - spans[fname][a][0]) if hit else None
            if addr is not None and addr in pointers:
                kw.update(error_class="CODE_DEFECT", file=IAC_INTENT_REPO_PATH, block_address=addr,
                          attribute_path=pointers[addr],
                          hint=_cap_text(json.dumps({"rendered_from": pointers[addr], "rendered_file":
                                                     "infra/workload/" + IAC_INTENT_RENDER_BASENAME,
                                                     "action": "OpenTofu rejected the platform's render of this "
                                                               "intent entry at apply: fix the entry in "
                                                               + IAC_INTENT_REPO_PATH})))
        elif repo_path and apply_user_owned(repo_path, intent_doc is not None):
            kw.update(error_class="BROWNFIELD_CONFLICT")
        diags.append(diag(**kw))
    if not diags:
        diags.append(diag(code="TF.UNPARSED_APPLY_ERROR", message=_cap_text(fallback_error or "validate failed") or ""))
    truncated = len(diags) > APPLY_REPORT_MAX_DIAGNOSTICS
    diags = diags[:APPLY_REPORT_MAX_DIAGNOSTICS]
    present = {d["error_class"] for d in diags}
    error_class = next(c for c in ("PLATFORM_DEFECT", "BROWNFIELD_CONFLICT", "CODE_DEFECT") if c in present)
    return {"status": "FAIL", "error_class": error_class, "source": source, "artifact_hash": "",
            "tools_ran": ["tofu"], "tools_unavailable": [], "diagnostics": diags, "report_only": [],
            "truncated": truncated, "repair_iteration": 0, "duration_ms": 0}


# Service kinds that run on a VM, never in a Buildpacks container (FD-4AE re-check F1b, matching S3B-1). Local data:
# the MCP container has no gateway `validators` package; tests/test_fd4ae_post_qa_injectors.py pins parity with
# apps/orchestrator-gateway/developer_agent/validators/container.NON_CONTAINER_KINDS.
NON_CONTAINER_KINDS = frozenset({"gce-bastion", "gce-worker"})
# FD-4DE RT F1: the one typed kind (shared/service_topology.ComputeKind) that creates a Cloud Run *service*, so a URL.
# gke-autopilot and event-worker (a Cloud Run job) are container kinds without one.
CLOUD_RUN_SERVICE_KIND = "cloudrun"


def topology_expects_service_url(kinds: Optional[Mapping[str, str]]) -> bool:
    """FD-4DE RT F1: False only when the typed topology is known and names no `cloudrun` service (no URL is expected
    then); True when it names one, or when there is no typed topology (the legacy behavior)."""
    if kinds is None:
        return True
    return any(k == CLOUD_RUN_SERVICE_KIND for k in kinds.values())


def workspace_service_kinds(workspace_dir: str) -> Optional[Dict[str, str]]:
    """{service name: typed kind} from the architect's topology (`intent.services`), or None when the workspace has
    no service_topology/v1 record or it names no service (then callers keep the legacy, topology-free behavior)."""
    intent = _read_service_topology_intent(workspace_dir)
    if intent is None:
        return None
    kinds: Dict[str, str] = {}
    for svc in intent.get("services") or []:
        if isinstance(svc, dict) and isinstance(svc.get("name"), str) and isinstance(svc.get("kind"), str):
            kinds[svc["name"]] = svc["kind"]
    return kinds or None


def vm_service_dir(item: str, kinds: Optional[Dict[str, str]]) -> Optional[str]:
    """The VM kind of `apps/<item>` per the topology (same name normalization as S3B-1: `_` -> `-`), else None."""
    if not kinds:
        return None
    kind = kinds.get(item.replace("_", "-"))
    return kind if kind in NON_CONTAINER_KINDS else None


def procfile_processes(text: str) -> Dict[str, str]:
    """{process: command} of a Procfile, with exactly the line rules of the pre-commit V3c contract
    (developer_agent/validators/container.parse_procfile; parity pinned by tests/test_procfile_worker_build.py):
    `<name>: <command>` lines, blank and `#` lines skipped, a line without a one-word name or a command ignored."""
    procs: Dict[str, str] = {}
    for raw in text.split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        name, sep, cmd = line.partition(":")
        if not sep or not name.strip() or not cmd.strip() or " " in name.strip():
            continue
        procs.setdefault(name.strip(), cmd.strip())
    return procs


def entryless_service_is_buildable(item: str, sub_path: str, kinds: Optional[Dict[str, str]]) -> bool:
    """Procfile-worker build (RT F3 of FD-4AE-c): whether `apps/<item>`, which has no entry module (main.py, app.py,
    ...), is still a real service to build while a sibling has one. Typed facts only, never the dir name:
    * with the architect's topology: the topology names it (S3B-1 normalization `_` -> `-`) with a container kind
      (every kind except NON_CONTAINER_KINDS; VM kinds are skipped earlier, F1b);
    * without a topology: its Procfile declares at least one process (`worker: python consumer.py`).
    A dir with neither (an empty skeleton) stays skipped, as before."""
    if kinds is not None:
        kind = kinds.get(item.replace("_", "-"))
        return kind is not None and kind not in NON_CONTAINER_KINDS
    procfile = os.path.join(sub_path, "Procfile")
    if not os.path.isfile(procfile):
        return False
    try:
        with open(procfile, "r", encoding="utf-8") as f:
            return bool(procfile_processes(f.read()))
    except (OSError, UnicodeDecodeError):
        return False


COMPUTE_RESOURCE_TYPE_PREFIXES = ("google_cloud_run", "kubernetes_deployment")


def _unquote(value: Any) -> str:
    text = value if isinstance(value, str) else str(value)
    return text[1:-1] if len(text) >= 2 and text[0] == text[-1] == '"' else text


def _tf_text_declares_compute(text: str) -> bool:
    """FD-4AE RT F1: compute declared in one root .tf, read from python-hcl2's parsed blocks (comments never count):
    a `module` whose label starts with `compute` or whose `source` names a `/compute-*` golden module, or a
    `google_cloud_run*` / `kubernetes_deployment*` resource. Raises when the text cannot be parsed."""
    import hcl2  # python-hcl2==7.3.1 (requirements.txt)

    doc = hcl2.loads(text)
    for block in doc.get("module", []) or []:
        for label, body in (block or {}).items():
            source = _unquote((body or {}).get("source", "")) if isinstance(body, dict) else ""
            if _unquote(label).startswith("compute") or "/compute-" in source:
                return True
    for block in doc.get("resource", []) or []:
        for rtype in (block or {}):
            if _unquote(rtype).startswith(COMPUTE_RESOURCE_TYPE_PREFIXES):
                return True
    return False


def workspace_declares_compute(workspace_dir: str) -> bool:
    """True when a root `*.tf` of the deploy workspace declares a compute module or resource (parsed HCL). The old
    substring scan matched the commented examples in the platform-rendered human_override.tf (`# module "compute" {`)
    and started a container build for foundation-only workloads (Gate A plan 07). The substring scan survives ONLY
    as the per-file fallback when python-hcl2 is missing or cannot parse that file (logged)."""
    for name in sorted(os.listdir(workspace_dir)):
        if not name.endswith(".tf"):
            continue
        try:
            with open(os.path.join(workspace_dir, name), "r", encoding="utf-8", errors="ignore") as fh:
                text = fh.read()
        except OSError:
            continue
        try:
            if _tf_text_declares_compute(text):
                return True
            continue
        except Exception as parse_err:  # noqa: BLE001 - unparseable (or python-hcl2 missing): legacy scan, logged
            logger.warning(f"IAC.COMPUTE_SCAN_UNPARSEABLE {name}: {parse_err}; using the legacy substring scan")
        if ('module "compute' in text or 'compute-cloudrun' in text or 'google_cloud_run' in text
                or 'kubernetes_deployment' in text):
            return True
    return False


# FD-55-IMG RT F2 (contract of developer_agent/terraform_engine.generate_golden_main_tf, image_expr): the golden
# primary module takes `var.container_image` directly (no replace()) for the PRODUCT's own service: a service named
# <clean product id>, "castor-<clean product id>" or one of GOLDEN_DIRECT_IMAGE_NAMES, or a module with no literal
# service_name (`var.product_id`; the event-worker `module "compute"` has none -> DIRECT_IMAGE_PRODUCT_SERVICE).
# Parity: tests/test_fd55_img_deploy_image.py renders the engine with each name.
GOLDEN_DIRECT_IMAGE_NAMES = ("compute", "app")
DIRECT_IMAGE_PRODUCT_SERVICE = "${var.product_id}"


def _build_service_key(name: str) -> str:
    """apps/<svc> and service names compare with `_` and `-` as one (vm_service_dir, the dual build tags and the
    engine's clean_s_name do the same)."""
    return name.replace("_", "-")


def direct_container_image_services(workspace_dir: str) -> Optional[Set[str]]:
    """FD-55-IMG: the plain-literal `service_name` of every root `module` block whose `container_image` is exactly
    `var.container_image` (the platform's `.../app:latest` tfvars value, used as is by the golden render for the
    product's own service); DIRECT_IMAGE_PRODUCT_SERVICE for such a module with no service_name or exactly
    `var.product_id`. Parsed with python-hcl2 from the workspace-root `*.tf`; None when one cannot be parsed
    (or python-hcl2 is missing), so the caller keeps its previous choice. Nothing is matched as text."""
    names: Set[str] = set()
    try:
        import hcl2  # python-hcl2==7.3.1 (requirements.txt)

        for fname in sorted(os.listdir(workspace_dir)):
            if not fname.endswith(".tf") or not os.path.isfile(os.path.join(workspace_dir, fname)):
                continue
            with open(os.path.join(workspace_dir, fname), "r", encoding="utf-8") as fh:
                doc = hcl2.loads(fh.read())
            for block in doc.get("module", []) or []:
                for body in (block or {}).values():
                    if not isinstance(body, dict) or _unquote(body.get("container_image", "")) != "${var.container_image}":
                        continue
                    svc_name = body.get("service_name")
                    if svc_name is None or _unquote(svc_name) == DIRECT_IMAGE_PRODUCT_SERVICE:
                        names.add(DIRECT_IMAGE_PRODUCT_SERVICE)
                    elif isinstance(svc_name, str) and "${" not in svc_name:
                        names.add(_unquote(svc_name))
    except Exception as parse_err:  # noqa: BLE001 - unreadable / unparseable root .tf: no decision from the HCL
        logger.warning(f"FD-55-IMG: root .tf not parseable ({parse_err}); the app:latest tag keeps the previous choice")
        return None
    return names


def primary_build_service(active_pool: List[str], clean_pid: str, direct_services: Optional[Set[str]]) -> str:
    """The `apps/<svc>` the build also tags `.../app:latest` (the tfvars `container_image`). FD-55-IMG: exactly one
    pool service that a root module takes `var.container_image` for directly (direct_container_image_services) wins,
    so that module runs its own image without any deploy-time HCL rewrite. Names compare with `_` == `-`; a product
    alias of the golden contract (GOLDEN_DIRECT_IMAGE_NAMES, castor-<pid>, DIRECT_IMAGE_PRODUCT_SERVICE) is the
    product's own service, apps/<clean_pid>, when that is in the pool. Otherwise the previous rules, unchanged."""
    product = _build_service_key(clean_pid)
    product_aliases = {product, f"castor-{product}", *GOLDEN_DIRECT_IMAGE_NAMES}
    product_in_pool = any(_build_service_key(s) == product for s in active_pool)
    wanted: Set[str] = set()
    for name in direct_services or set():
        key = _build_service_key(name)
        if name == DIRECT_IMAGE_PRODUCT_SERVICE or key in product_aliases:
            if product_in_pool:
                wanted.add(product)
                continue
            if name == DIRECT_IMAGE_PRODUCT_SERVICE:
                continue
        wanted.add(key)
    direct = [s for s in active_pool if _build_service_key(s) in wanted]
    if len(direct) == 1:
        return direct[0]
    # Rule 3: Scaffold Stub Quarantine
    # If multiple services exist, prioritize UI/web services over generic scaffold stubs matching clean_pid
    ui_candidates = [
        s for s in active_pool
        if any(k in s.lower() for k in ("storefront", "frontend", "ui", "web", "gateway", "portal"))
    ]
    if ui_candidates:
        return ui_candidates[0]
    if clean_pid in active_pool and len(active_pool) > 1:
        other_candidates = [s for s in active_pool if s != clean_pid]
        return other_candidates[0] if other_candidates else clean_pid
    if clean_pid in active_pool:
        return clean_pid
    return active_pool[0]


def _build_source_never(rel_path: str) -> bool:
    parts = rel_path.replace(os.sep, "/").split("/")
    name = parts[-1]
    if any(p in _BUILD_SOURCE_NEVER_DIRS or p.startswith(".") for p in parts[:-1]):
        return True
    if name.startswith(".") and name not in _BUILD_SOURCE_DOTFILE_ALLOW:
        return True  # .env, .env.*, .npmrc, .netrc, .terraformrc, ...
    if name in _BUILD_SOURCE_NEVER_NAMES:
        return True
    return name.lower().endswith(_BUILD_SOURCE_NEVER_SUFFIXES)


def select_build_source_files(workspace_dir: str, services: List[str]) -> List[str]:
    """
    FD-4BA follow-up: workspace-relative paths that go into the Cloud Build source tarball (allow-list).

    With ``services`` the build reads only ``apps/<svc>/**`` for each built service; without services it reads
    the workspace root, restricted to buildpack manifests and application source/asset types. Never-list files
    are excluded in both modes and symlinks are never followed. Raises when a service directory (or the root)
    yields no files, so a build never runs on an empty or secret-only payload.
    """
    selected: List[str] = []

    def _walk(base_rel: str, accept) -> List[str]:
        found: List[str] = []
        base = os.path.join(workspace_dir, base_rel) if base_rel else workspace_dir
        for root, dirs, filenames in os.walk(base, followlinks=False):
            dirs[:] = sorted(d for d in dirs if not os.path.islink(os.path.join(root, d)))
            for fn in sorted(filenames):
                full = os.path.join(root, fn)
                if os.path.islink(full) or not os.path.isfile(full):
                    continue
                rel = os.path.relpath(full, workspace_dir)
                if _build_source_never(rel) or not accept(rel, fn):
                    continue
                found.append(rel)
        return found

    if services:
        # Root-level buildpack manifests (Procfile, .python-version, requirements.txt, ...) are not read by
        # `pack --path=apps/<svc>` but carry no secrets; they stay in the tarball as before (no behavior change).
        for fn in sorted(os.listdir(workspace_dir)):
            full = os.path.join(workspace_dir, fn)
            if fn in _ROOT_BUILD_SOURCE_NAMES and os.path.isfile(full) and not os.path.islink(full) and not _build_source_never(fn):
                selected.append(fn)
        for svc in services:
            svc_rel = os.path.join("apps", svc)
            if not os.path.isdir(os.path.join(workspace_dir, svc_rel)):
                raise RuntimeError(f"build source for service '{svc}' is missing (apps/{svc} does not exist)")
            svc_files = _walk(svc_rel, lambda rel, fn: True)
            if not svc_files:
                raise RuntimeError(f"build source allow-list selected no files for service '{svc}'")
            selected.extend(svc_files)
    else:
        def _root_accept(rel: str, fn: str) -> bool:
            return fn in _ROOT_BUILD_SOURCE_NAMES or os.path.splitext(fn)[1].lower() in _ROOT_BUILD_SOURCE_EXTENSIONS

        selected = _walk("", _root_accept)
        if not selected:
            raise RuntimeError("build source allow-list selected no application files at the workspace root")
    return selected


# ------------------------------------------------------------------------------
# FD-4BD: platform secrets reach OpenTofu only as TF_VAR_<name> environment variables of the deploy workspace's
# tofu processes. They are never written to terraform.tfvars (or any other workspace file), so no tarball, upload
# or Git writeback can carry them. A same-named key in a tfvars file would override the environment (OpenTofu
# precedence: env < terraform.tfvars < *.auto.tfvars), so these keys are always dropped from the root tfvars.
# ------------------------------------------------------------------------------
PLATFORM_SECRET_TFVARS = ("oauth_client_secret", "firebase_api_key")


def _hcl2_kids(node) -> list:
    return [c for c in getattr(node, "children", []) if getattr(c, "data", None) is not None]


def _hcl2_identifier(node) -> Optional[str]:
    """identifier -> its single NAME token."""
    if getattr(node, "data", None) == "identifier" and len(node.children) == 1:
        return str(node.children[0])
    return None


def _hcl2_plain_string_token(node):
    """expr_term/string -> its single STRING_CHARS token (a plain quoted literal without escapes or templates)."""
    if getattr(node, "data", None) == "expr_term" and len(node.children) == 1:
        node = node.children[0]
    if getattr(node, "data", None) == "string" and len(node.children) == 1:
        part = node.children[0]
        if getattr(part, "data", None) == "string_part" and len(part.children) == 1:
            tok = part.children[0]
            if getattr(tok, "start_pos", None) is not None:
                return tok
    return None


def _hcl2_lexable_view(text: str) -> Tuple[str, List[int]]:
    """FD55-TFVARS F1: the view of `text` python-hcl2 7.3.1 can lex, and for every view offset (plus the end) the
    offset in `text` where that character's source starts. OpenTofu accepts three forms python-hcl2's lexer rejects:
    one leading UTF-8 BOM (dropped: +1 offset), CRLF line endings (each `\r\n` read as `\n`, mapped to its `\r`, so
    an exclusive end before a line break never includes the `\r`), and a last line without a newline (e.g. a final
    `#` / `//` comment: one `\n` appended, mapped to the end). Exact characters only; `text` itself is never
    rewritten: callers slice the ORIGINAL text through the map."""
    view: List[str] = []
    orig: List[int] = []
    i = 1 if text.startswith("\ufeff") else 0
    n = len(text)
    while i < n:
        if text[i] == "\r" and i + 1 < n and text[i + 1] == "\n":
            view.append("\n")
            orig.append(i)
            i += 2
            continue
        view.append(text[i])
        orig.append(i)
        i += 1
    if not view or view[-1] != "\n":
        view.append("\n")
        orig.append(n)
    orig.append(n)   # the view's end
    return "".join(view), orig


def _hcl2_top_level_body(text: str):
    """(the top-level `body` node of `text` parsed by python-hcl2, the view -> `text` offset map), or (None, None)
    when unparseable / python-hcl2 is missing. Parsed through _hcl2_lexable_view (FD55-TFVARS F1): node offsets
    index the VIEW; translate them with the map (`orig[pos]`) before slicing `text`."""
    try:
        import hcl2  # python-hcl2==7.3.1 (requirements.txt)
    except ImportError:
        return None, None
    view, orig = _hcl2_lexable_view(text or "")
    try:
        tree = hcl2.parses(view)
    except Exception:  # noqa: BLE001 - unparseable: structure unknown
        return None, None
    return next((c for c in _hcl2_kids(tree) if c.data == "body"), None), orig


def _hcl2_parse_error(text: str) -> str:
    """FD55-TFVARS: where python-hcl2 stops on a text it cannot parse (the error type and the parser's line/column
    only: never the text itself, which may hold values), for the typed APPLY.*_UNPARSEABLE error. Never decides."""
    try:
        import hcl2  # python-hcl2==7.3.1 (requirements.txt)
    except ImportError:
        return "python-hcl2 is not installed"
    try:
        hcl2.parses(_hcl2_lexable_view(text or "")[0])
    except Exception as err:  # noqa: BLE001 - the position only (in the view: CRLF / BOM / final newline aside)
        line, column = getattr(err, "line", None), getattr(err, "column", None)
        where = f" at line {line}, column {column}" if isinstance(line, int) and isinstance(column, int) else ""
        return f"{type(err).__name__}{where}"
    return "parsed, but not a plain variable-values file"


def parse_tfvars_attributes(text: str) -> Optional[List[Tuple[str, str, str]]]:
    """FD-4BV: [(name, exact attribute text, exact value text)] for each top-level attribute of a tfvars file, in
    file order, located with python-hcl2's parse tree (exact offsets, no text matching). An empty/blank text is [].
    None when python-hcl2 cannot parse the text (or is missing)."""
    if not text or not text.strip():
        return []
    body, orig = _hcl2_top_level_body(text)
    if body is None:
        return None
    out: List[Tuple[str, str, str]] = []
    for node in _hcl2_kids(body):
        if node.data == "new_line_or_comment":
            continue
        if node.data != "attribute":
            return None   # a block in a tfvars file: not a variable-values file; let the caller keep its fallback
        kids = _hcl2_kids(node)
        name = _hcl2_identifier(kids[0]) if len(kids) == 2 else None
        meta, vmeta = getattr(node, "meta", None), getattr(kids[1], "meta", None) if len(kids) == 2 else None
        if not name or meta is None or vmeta is None or getattr(meta, "empty", False) or getattr(vmeta, "empty", False):
            return None
        out.append((name, text[orig[meta.start_pos]:orig[meta.end_pos]],
                    text[orig[vmeta.start_pos]:orig[vmeta.end_pos]]))
    return out


def recorded_wif_branch(recorded: Any) -> Optional[str]:
    """FD-4CI-b-R1-WIF: the workload's recorded default_branch for the workload-foundation WIF condition
    (`github_default_branch` root tfvar), or None (no key: the root's default). None for no record, "main" (the
    module default; tfvars stay byte-identical) and anything that is not a plain branch name
    (shared.settings.is_branch_name, the rule the generated deploy workflows use; the module validates it again).
    Never rewritten; None when the settings module is unavailable (the condition stays at main)."""
    if not isinstance(recorded, str) or recorded == "main":
        return None
    try:
        from shared.settings import is_branch_name
    except ImportError:
        return None
    if not is_branch_name(recorded):
        logger.error(f"DEFAULT_BRANCH_INVALID: recorded branch {recorded!r} is not a plain branch name; the WIF "
                     "condition keeps the root's default branch.")
        return None
    return recorded


# GHA-DEPLOY-SWITCH (register row GHA-DEPLOY-SWITCH, owner 10-30; OQ-37 = deploy time): the workload record's
# GitHub Actions deploy switch reaches the workload-foundation module as the root variable below, written into the
# root tfvars at every deploy -- but only for a root that declares it (the developer renders the declaration while the
# switch is off; a root rendered while it was on has none and stays byte-identical). The record off and a root
# without the declaration: typed stop APPLY.GHA_DEPLOY_SWITCH_NOT_IN_IAC (operator_required: the operator runs the
# workload's pipeline, which re-renders the root), never a deploy that keeps the identity federation the administrator turned off. A value that is not true /
# false: GHA_DEPLOY_SWITCH_INVALID (operator_required). Serverless Git records ignore the switch.
GHA_DEPLOY_SWITCH_TFVAR = "enable_github_actions_deploy"
APPLY_GHA_DEPLOY_SWITCH_NOT_IN_IAC = "APPLY.GHA_DEPLOY_SWITCH_NOT_IN_IAC"
GHA_DEPLOY_SWITCH_INVALID = "GHA_DEPLOY_SWITCH_INVALID"


def root_declares_variable(files: Mapping[str, str], name: str) -> Optional[bool]:
    """True when a workspace-root `*.tf` of `files` (a key without "/") declares `variable "<name>"`, False when
    none does, None when one of them cannot be parsed by python-hcl2 (or it is missing). Parsed blocks only."""
    try:
        import hcl2  # python-hcl2==7.3.1 (requirements.txt)
    except ImportError:
        return None
    found = False
    for path in sorted(files):
        if "/" in path or not path.endswith(".tf") or not isinstance(files[path], str):
            continue
        try:
            doc = hcl2.loads(files[path])
        except Exception:  # noqa: BLE001 - unparseable root file: unknown
            return None
        for block in doc.get("variable", []) or []:
            if isinstance(block, dict) and any(_unquote(label) == name for label in block):
                found = True
    return found


def gha_deploy_tfvar(recorded: Any, vcs_provider: Any, files: Mapping[str, str]
                     ) -> Tuple[Optional[str], Optional[Tuple[str, str]]]:
    """GHA-DEPLOY-SWITCH: (tfvars value or None for no key, None or (code, detail) for a typed stop).
    On (record missing or true) with a root that declares the variable: "true"; on without it: no key (tfvars
    byte-identical). Off with the declaration: "false"; off without it (or an unparseable root): stop
    APPLY.GHA_DEPLOY_SWITCH_NOT_IN_IAC. Not true / false: stop GHA_DEPLOY_SWITCH_INVALID. Serverless Git: no key."""
    if str(vcs_provider or "").strip().upper() == "SERVERLESS_GIT":
        return None, None
    if recorded is None:
        on = True
    else:
        try:
            if github_actions_deploy_enabled is None:
                raise ValueError("shared.github_identity is not importable")
            on = github_actions_deploy_enabled(recorded)
        except ValueError as e:
            return None, (GHA_DEPLOY_SWITCH_INVALID,
                          f"workloads/<id>.{GITHUB_ACTIONS_DEPLOY_FIELD}: {e}; an administrator sets it on the "
                          "workload page")
    declares = root_declares_variable(files, GHA_DEPLOY_SWITCH_TFVAR)
    if on:
        return ("true" if declares else None), None
    if declares:
        return "false", None
    return None, (APPLY_GHA_DEPLOY_SWITCH_NOT_IN_IAC,
                  "the workload's GitHub Actions deploy switch is off, but its committed infrastructure code was "
                  f"generated while it was on (no `variable \"{GHA_DEPLOY_SWITCH_TFVAR}\"` in the root module), so "
                  "this deploy would keep its GitHub Actions identity federation and deployer account. A pipeline "
                  "run regenerates the code with the switch")


# GHA-DEPLOY-SWITCH: the workspace paths of the vendored workload-foundation module (repository path; legacy flatten).
FOUNDATION_MODULE_DIRS = ("infra/modules/workload-foundation/base", "modules/workload-foundation/base")


def foundation_module_address(workspace_dir: str, rtype: str, rname: str) -> str:
    """GHA-DEPLOY-SWITCH: the `tofu import` address of a workload-foundation resource: module.foundation.<type>.<name>,
    plus `[0]` when the workspace's vendored module declares that resource with `count` (the module since the switch:
    pool, provider, deployer SA and grants). A module vendored before the switch (no count), or one that cannot be read
    or parsed, keeps the address without an index, as before. Parsed blocks only."""
    address = f"module.foundation.{rtype}.{rname}"
    try:
        import hcl2  # python-hcl2==7.3.1 (requirements.txt)
    except ImportError:
        return address
    for rel in FOUNDATION_MODULE_DIRS:
        mod_dir = os.path.join(workspace_dir, rel)
        if not os.path.isdir(mod_dir):
            continue
        for name in sorted(os.listdir(mod_dir)):
            if not name.endswith(".tf"):
                continue
            try:
                with open(os.path.join(mod_dir, name), "r", encoding="utf-8") as fh:
                    doc = hcl2.loads(fh.read())
            except Exception:  # noqa: BLE001 - unreadable / unparseable: the address as before
                return address
            for block in doc.get("resource", []) or []:
                body = ((block or {}).get(rtype) or {}).get(rname) if isinstance(block, dict) else None
                if isinstance(body, dict) and "count" in body:
                    return address + "[0]"
        return address
    return address


def merge_tfvars_texts(
    sources: List[str], overrides: Dict[str, str], drop: Tuple[str, ...] = PLATFORM_SECRET_TFVARS
) -> Optional[str]:
    """FD-4BV: one root terraform.tfvars from layered tfvars texts, merged by parsed key.

    Every key of every source is kept with its exact source text (a later source wins per key, as before);
    `overrides` ({name: HCL value text}) win for the keys they name (platform-owned facts); `drop` keys are removed
    from every layer (FD-4BD: secrets go by environment). Source keys come first in first-seen order, then the
    override keys. None when any source is not parseable (the caller keeps its previous behavior)."""
    merged: Dict[str, str] = {}
    for text in sources:
        attrs = parse_tfvars_attributes(text or "")
        if attrs is None:
            return None
        for name, attr_text, _value in attrs:
            merged[name] = attr_text
    for name, value in overrides.items():
        merged.pop(name, None)
        merged[name] = f"{name} = {value}"
    for name in drop:
        merged.pop(name, None)
    return "".join(f"{attr_text}\n" for attr_text in merged.values())


# ------------------------------------------------------------------------------
# SAT-01 (FD4BD-Q1 deploy half; owner OQ-1 / OQ-2 / OQ-3 10-31): OpenTofu loads, from the directory it runs in,
# terraform.tfvars, then terraform.tfvars.json, then every *.auto.tfvars / *.auto.tfvars.json in name order; a later
# file wins and every file beats TF_VAR_*. The deploy merges the platform's values into the root terraform.tfvars
# (platform keys win, FD-4BV) and passes the secrets as TF_VAR_* (FD-4BD), so any OTHER auto-loaded file in the
# workspace root could override them. Before anything is built, planned or applied, every such file in the workspace
# root (exact OpenTofu name rule; the platform's own access file excluded) must be a regular file whose variable names
# the platform can list (python-hcl2; json for .json; OpenTofu's own parser decides when python-hcl2 cannot) and must
# set no platform-owned variable. Otherwise a typed stop that names the file (and the variable). Nothing is rewritten
# or removed: a file that passes reaches OpenTofu byte-identical.
# ------------------------------------------------------------------------------
APPLY_TFVARS_OVERRIDES_PLATFORM = "APPLY.TFVARS_OVERRIDES_PLATFORM"
APPLY_TFVARS_SYMLINK = "APPLY.TFVARS_SYMLINK"
ERROR_TFVARS_OVERRIDES_PLATFORM = "TFVARS_OVERRIDES_PLATFORM"   # error_class; operator_required (WF-OPERATOR-FLAG)
ERROR_TFVARS_SYMLINK = "TFVARS_SYMLINK"                         # error_class; operator_required (WF-OPERATOR-FLAG)
AUTO_TFVARS_JSON_FILE = "terraform.tfvars.json"
AUTO_TFVARS_SUFFIXES = (".auto.tfvars", ".auto.tfvars.json")
# Every variable the deploy sets for the workload: the TF_VAR_* secrets and every key `_deploy_workload_impl` can put
# in the root terraform.tfvars (`platform_tfvars`; the call site also adds that dict's keys, so a new key there is
# covered even before it is listed here; tests pin the two lists equal).
PLATFORM_OWNED_TFVARS = frozenset(PLATFORM_SECRET_TFVARS) | frozenset((
    "project_id", "region", "product_id", "github_repo_full_name", "container_image", "oauth_client_id",
    "firebase_auth_domain", "github_repository_id", "github_default_branch",
))


def is_auto_loaded_tfvars_name(name: str) -> bool:
    """OpenTofu's own rule for the variables files it loads by itself from its working directory, apart from
    terraform.tfvars (which the deploy writes from the merged platform values): exactly `terraform.tfvars.json`, or a
    name ending in `.auto.tfvars` / `.auto.tfvars.json`. Exact name and suffix only."""
    return name == AUTO_TFVARS_JSON_FILE or name.endswith(AUTO_TFVARS_SUFFIXES)


class _JsonPairs(list):
    """json object_pairs_hook result: every (key, value) of one JSON object, duplicate keys included."""


def _opentofu_tfvars_verdict(text: str, filename: str, parser_bin: Optional[str]) -> Optional[List[str]]:
    """OpenTofu's own parser (`<bin> fmt -` on stdin, hcl_utils.hcl_parse_errors; syntax only, read-only): [] = it
    parses, [message] = it rejects the text, None = no binary or it could not decide (never a verdict)."""
    if not parser_bin:
        return None
    try:
        from shared.hcl_utils import hcl_parse_errors
    except ImportError:
        try:
            from hcl_utils import hcl_parse_errors
        except ImportError:
            return None
    return hcl_parse_errors(text, filename=filename, parser_bin=parser_bin)


def tfvars_file_variable_names(text: str, filename: str, parser_bin: Any = None) -> Tuple[Optional[List[str]], str]:
    """SAT-01: (the top-level variable names a variables file sets, "") or (None, why the platform cannot list them).

    `.json` files: json (one leading UTF-8 BOM ignored); the document must be a JSON object; duplicate keys are all
    listed. Other files: python-hcl2 (parse_tfvars_attributes: CRLF / BOM / no final newline read as OpenTofu reads
    them). When python-hcl2 cannot list them, OpenTofu's own parser (`parser_bin`: its path, or a no-argument callable
    that returns it, called only then) decides whether the file is broken; either way the names stay unknown, so the
    reason says which case it is. A reason never quotes the file's text (it may hold values): positions only."""
    if filename.endswith(".json"):
        body = text[1:] if text.startswith("\ufeff") else text
        try:
            doc = json.loads(body, object_pairs_hook=_JsonPairs)
        except json.JSONDecodeError as err:
            return None, f"is not valid JSON (line {err.lineno}, column {err.colno})"
        except (ValueError, RecursionError) as err:
            return None, f"is not valid JSON ({type(err).__name__})"
        if not isinstance(doc, _JsonPairs):
            return None, "is not a JSON object"
        return [key for key, _value in doc], ""
    attrs = parse_tfvars_attributes(text)
    if attrs is not None:
        return [name for name, _attr_text, _value in attrs], ""
    hcl2_where = _hcl2_parse_error(text)
    verdict = _opentofu_tfvars_verdict(text, filename, parser_bin() if callable(parser_bin) else parser_bin)
    if verdict == []:
        return None, (f"cannot be read by python-hcl2 ({hcl2_where}) although OpenTofu's parser accepts it, so the "
                      f"platform cannot list the variables it sets (the file is not proven broken)")
    if verdict:
        return None, f"is rejected by OpenTofu's parser (python-hcl2: {hcl2_where})"
    return None, (f"cannot be read by python-hcl2 ({hcl2_where}) and no OpenTofu parser was available to decide "
                  f"(the file is not proven broken)")


def _read_regular_file_no_follow(path: str) -> str:
    """The exact text of a regular file, opened without following a symbolic link (O_NOFOLLOW where the OS has it;
    the caller has already refused links). CRLF kept."""
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "r", encoding="utf-8", newline="") as fh:
        return fh.read()


def workspace_auto_tfvars_findings(workspace_dir: str, owned: FrozenSet[str], skip: Tuple[str, ...] = (),
                                   parser_bin: Any = None) -> List[Tuple[str, str, str, List[str]]]:
    """SAT-01: [(code, workspace file name, reason, platform-owned names it sets)] for every variables file OpenTofu
    would load by itself from `workspace_dir` (is_auto_loaded_tfvars_name; names in `skip` excluded) that the deploy
    must refuse, in name order. [] when there is none. Read-only: nothing is changed.

    - a symbolic link (or anything but a regular file): APPLY_TFVARS_SYMLINK / APPLY_TFVARS_UNPARSEABLE;
    - names the platform cannot list (tfvars_file_variable_names): APPLY_TFVARS_UNPARSEABLE;
    - sets a name in `owned`: APPLY_TFVARS_OVERRIDES_PLATFORM.
    `parser_bin`: OpenTofu's binary path, or a no-argument callable that returns it (asked only when python-hcl2
    cannot read a file)."""
    with os.scandir(workspace_dir) as it:
        entries = sorted((e for e in it if is_auto_loaded_tfvars_name(e.name) and e.name not in skip),
                         key=lambda e: e.name)
    findings: List[Tuple[str, str, str, List[str]]] = []
    resolved_bin: List[Optional[str]] = []

    def _parser_bin() -> Optional[str]:   # resolved once, and only when python-hcl2 cannot read a file
        if not resolved_bin:
            try:
                resolved_bin.append(parser_bin() if callable(parser_bin) else parser_bin)
            except Exception as bin_err:  # noqa: BLE001 - no parser: the reason says so (still a typed stop)
                logger.warning(f"SAT-01: OpenTofu's parser is unavailable for the variables-file check "
                               f"({type(bin_err).__name__})")
                resolved_bin.append(None)
        return resolved_bin[0]

    for entry in entries:
        if entry.is_symlink():
            findings.append((APPLY_TFVARS_SYMLINK, entry.name, "is a symbolic link", []))
            continue
        if not entry.is_file(follow_symlinks=False):
            findings.append((APPLY_TFVARS_UNPARSEABLE, entry.name, "is not a regular file", []))
            continue
        try:
            text = _read_regular_file_no_follow(entry.path)
        except (OSError, UnicodeDecodeError) as err:
            findings.append((APPLY_TFVARS_UNPARSEABLE, entry.name, f"cannot be read as UTF-8 text "
                                                                   f"({type(err).__name__})", []))
            continue
        names, reason = tfvars_file_variable_names(text, entry.name, _parser_bin)
        if names is None:
            findings.append((APPLY_TFVARS_UNPARSEABLE, entry.name, reason, []))
            continue
        hits = sorted(set(names) & owned)
        if hits:
            findings.append((APPLY_TFVARS_OVERRIDES_PLATFORM, entry.name,
                             "sets the platform-owned variable" + ("s " if len(hits) > 1 else " ") + ", ".join(hits),
                             hits))
    return findings


_FLATTEN_SOURCE_ANCHORS = (
    (("..", "modules"), "./infra/modules"),
    (("..", "..", "modules"), "./infra/modules"),
    (("..", "bundles"), "./infra/bundles"),
    (("..", "..", "bundles"), "./infra/bundles"),
)


def _flattened_module_source(value: str) -> Optional[str]:
    """FD-4BW: the workspace-root path for a module source written relative to infra/workload/ (or to a bundle
    dir), by path segments: ../modules/<x> and ../../modules/<x> -> ./infra/modules/<x>; same for bundles. The
    same four mappings the deploy flatten always applied. None for any other source (left as written)."""
    parts = value.split("/")
    for anchor, root in _FLATTEN_SOURCE_ANCHORS:
        n = len(anchor)
        if tuple(parts[:n]) == anchor and len(parts) > n and parts[n]:
            return root + "/" + "/".join(parts[n:])
    return None


def _nested_module_source(value: str, repo_path: str, workload_dir: str = WORKLOAD_DIR) -> Optional[str]:
    """FD-4D-b: a nested workload file (repo `workload_dir`/<d>/<file>) is kept at <d>/<file> in the workspace, so
    every local module source that stays inside `workload_dir` still names the same directory (left as written).
    A local source that leaves `workload_dir` (for example a golden module under infra/modules/, which the workspace
    holds at its repository path) is re-anchored to that same repository directory from the new location: exact
    path arithmetic (posixpath.normpath / relpath) on path segments. None (left as written) for any non-local
    source, a source that stays inside `workload_dir`, or one that leaves the repository."""
    rel = workload_relpath(repo_path, workload_dir)
    if rel is None or not value.startswith(("./", "../")):
        return None
    target = posixpath.normpath(posixpath.join(posixpath.dirname(repo_path), value))
    if (target == ".." or target.startswith("../") or target == workload_dir.rstrip("/")
            or workload_relpath(target, workload_dir) is not None):
        return None
    new_value = posixpath.relpath(target, posixpath.dirname(rel) or ".")
    return new_value if new_value.startswith("../") else "./" + new_value


def rewrite_flattened_module_sources(content: str, filename: str = "", nested_repo_path: str = "",
                                     workload_dir: str = WORKLOAD_DIR) -> str:
    """FD-4BW: rewrite the `source` argument of every top-level `module` block for a root flattened from
    infra/workload/ to the workspace root, found with python-hcl2's parse tree (any whitespace or alignment; exact
    token offsets). Only those string values change; every other byte is kept. FD55-TFVARS: text python-hcl2 cannot
    parse raises SourceUnparseableError (APPLY.SOURCE_UNPARSEABLE; the previous regex rewrite is no longer used).
    FD-4D-b: with `nested_repo_path` (a file in a subdirectory of `workload_dir`, kept at its relative path) the
    mapping is _nested_module_source instead; text python-hcl2 cannot parse is then kept exactly as written."""
    if not content:
        return content
    body, orig = _hcl2_top_level_body(content)
    if body is None:
        if nested_repo_path:
            logger.warning(f"FD-4D-b: {filename or 'file'} not parseable by python-hcl2; module sources kept as written")
            return content
        raise SourceUnparseableError(
            f"{filename or 'file'} is not parseable by python-hcl2 ({_hcl2_parse_error(content)}), so its module "
            f"sources cannot be re-anchored to the workspace root")
    spans = []
    for blk in _hcl2_kids(body):
        kids = _hcl2_kids(blk)
        if blk.data != "block" or len(kids) < 3 or _hcl2_identifier(kids[0]) != "module" or kids[-1].data != "body":
            continue
        for attr in _hcl2_kids(kids[-1]):
            akids = _hcl2_kids(attr)
            if attr.data != "attribute" or len(akids) != 2 or _hcl2_identifier(akids[0]) != "source":
                continue
            tok = _hcl2_plain_string_token(akids[1])
            if tok is None:
                continue
            start, end = orig[tok.start_pos], orig[tok.end_pos]   # view offsets -> the original text (F1)
            if content[start:end] != str(tok):   # the mapped offsets index exactly this token in the original
                continue
            new_value = (_nested_module_source(str(tok), nested_repo_path, workload_dir) if nested_repo_path
                         else _flattened_module_source(str(tok)))
            if new_value is not None:
                spans.append((start, end, new_value))
    for start, end, new_value in reversed(spans):
        content = content[:start] + new_value + content[end:]
    return content

try:
    from shared.workflow_validator import validate_github_workflow_yaml, WorkflowValidationError
except ImportError:
    try:
        from workflow_validator import validate_github_workflow_yaml, WorkflowValidationError
    except ImportError:
        validate_github_workflow_yaml = None

        class WorkflowValidationError(Exception):   # FD55-W6c: never `Exception` (callers catch this class)
            """Placeholder when the validator is unavailable (nothing raises it then)."""

try:
    from shared.github_identity import (GITHUB_ACTIONS_DEPLOY_FIELD, GITHUB_REPOSITORY_IDENTITY_FIELD,
                                        get_default_github_owner, github_actions_deploy_enabled,
                                        pinned_github_repository_id, resolve_repo_identity)
except ImportError:
    try:
        from .github_identity import (GITHUB_ACTIONS_DEPLOY_FIELD, GITHUB_REPOSITORY_IDENTITY_FIELD,
                                      get_default_github_owner, github_actions_deploy_enabled,
                                      pinned_github_repository_id, resolve_repo_identity)
    except ImportError:
        try:
            from github_identity import (GITHUB_ACTIONS_DEPLOY_FIELD, GITHUB_REPOSITORY_IDENTITY_FIELD,
                                         get_default_github_owner, github_actions_deploy_enabled,
                                         pinned_github_repository_id, resolve_repo_identity)
        except ImportError:
            # GHA-DEPLOY-SWITCH: a record that carries the switch is refused (gha_deploy_tfvar); none = on (today).
            GITHUB_ACTIONS_DEPLOY_FIELD = "github_actions_deploy"
            github_actions_deploy_enabled = None
            def get_default_github_owner():  # FD-4AY: no built-in owner (shared.github_identity unavailable)
                owner = os.getenv("GITHUB_ORG") or os.getenv("GITHUB_DEPLOYMENTS_ORG") or os.getenv("GITHUB_OWNER")
                if not owner:
                    raise RuntimeError("No GitHub owner configured: set GITHUB_ORG")
                return owner
            def resolve_repo_identity(repo, default_owner=None, product_id=None):
                owner = default_owner or get_default_github_owner()
                if isinstance(repo, dict):
                    repo = repo.get("full_name") or repo.get("repo_name")
                if repo and "/" in repo:
                    parts = repo.split("/", 1)
                    return parts[0], parts[1], repo
                clean_pid = (product_id or "workload").lower().replace("_", "-")
                repo_name = repo or clean_pid   # GITHUB-REPO-NAME-NO-PREFIX: shared default_repository_name
                return owner, repo_name, f"{owner}/{repo_name}"
            # FD-4AT-c: no vend-time repository-id pin without shared.github_identity (name + main branch only).
            GITHUB_REPOSITORY_IDENTITY_FIELD = "github_repository_identity"

            def pinned_github_repository_id(record, full_repo_name):
                return None

try:
    from shared.github_resilience import get_github_token, github_retry_with_backoff
except ImportError:
    try:
        from .github_resilience import get_github_token, github_retry_with_backoff
    except ImportError:
        def get_github_token(*args, **kwargs):
            return os.getenv("GITHUB_TOKEN") or ""
        def github_retry_with_backoff(*args, **kwargs):
            return lambda f: f

try:
    from shared.resource_sizing import resolve_workload_sizing
except ImportError:
    try:
        from .shared.resource_sizing import resolve_workload_sizing
    except ImportError:
        try:
            from resource_sizing import resolve_workload_sizing
        except ImportError:
            def resolve_workload_sizing(*args, **kwargs):
                from dataclasses import dataclass
                @dataclass
                class _FallbackProfile:
                    memory_limit: str = "512Mi"
                    cpu_limit: str = "1000m"
                return _FallbackProfile()

logger = logging.getLogger("mcp-terraform-server")
logging.basicConfig(level=logging.INFO)


class IaCEngineDowngradeBlockedError(Exception):
    """Raised when an attempt is made to downgrade an OpenTofu state to Terraform 1.5.7."""
    pass


# FD-4AL: the region a workload is vended and applied in. ONE resolver for this server (the runtime tfvars `region`,
# image tags, Artifact Registry / Cloud Run / VPC Access / subnetwork REST paths, import IDs, the GKE manifest apply and
# the generated-CI sanitizer all read it). There is no per-workload region field on the workload record today, so the
# workload region is the platform setting. Order: Platform Settings `orchestration.default_gcp_region`, read with the
# server's OWN Firestore client (`db`), then $REGION / $DEFAULT_REGION. The settings schema default (shared.settings,
# the documented value) applies only when there is no settings document, or no settings store at all (no client, as
# get_platform_settings without Firestore). An unreadable document or an empty stored value with no env is
# RegionUnavailable (REGION_UNAVAILABLE): never a guessed region.
REGION_UNAVAILABLE = "REGION_UNAVAILABLE"
# RT14-01: typed names of the read-only stub detection and of the subnet CIDR conflict (no REST delete runs).
STUB_DETECTION_REFUSED = "STUB_DETECTION_REFUSED"
STUB_DETECTION_UNREADABLE = "STUB_DETECTION_UNREADABLE"
ERRORED_CHILD_STUBS = "ERRORED_CHILD_STUBS"
SUBNET_CIDR_CONFLICT = "SUBNET_CIDR_CONFLICT"
SUBNET_CIDR_CONFLICT_STAGE = "apply"


class RegionUnavailable(RuntimeError):
    """No platform region is configured (settings `orchestration.default_gcp_region`, $REGION, $DEFAULT_REGION)."""


def _schema_default_region() -> str:
    try:
        from shared.settings import OrchestrationSettings

        region = OrchestrationSettings().default_gcp_region
    except Exception:  # noqa: BLE001 - no settings schema importable = no documented default
        return ""
    return region if isinstance(region, str) else ""


def _project_configured() -> bool:
    """An install (a project is configured): a missing settings client there is a FAILED store, never "no store"."""
    return bool(os.getenv("PROJECT_ID") or os.getenv("GOOGLE_CLOUD_PROJECT"))


def _settings_region(db: Any) -> Tuple[str, bool, str]:
    """(`orchestration.default_gcp_region` of system_config/platform_settings read through `db`, consulted, cause).
    consulted=False only for a process with no project configured at all and no client (the eval harness child) or
    a non-snapshot object: no settings store exists, as when get_platform_settings has no Firestore. FD-4AL RT F1: a
    configured install whose client could not be built is a failed store (consulted=True). A missing document is
    the schema default; a read error, an invalid document or an empty stored value is ("", True, <cause>): the caller
    falls to $REGION / $DEFAULT_REGION and then fails typed with the cause, never to a default."""
    if db is None:
        if _project_configured():
            return "", True, "no settings Firestore client although a project is configured"
        return "", False, ""
    try:
        from shared.settings import OrchestrationSettings

        snap = db.collection("system_config").document("platform_settings").get()
        exists = getattr(snap, "exists", None)
        if exists is False:
            return _schema_default_region(), True, ""
        data = snap.to_dict() if exists is True else None
        if not isinstance(data, dict):
            return "", False, ""
        orch = data.get("orchestration")
        region = OrchestrationSettings(**(orch if isinstance(orch, dict) else {})).default_gcp_region
    except Exception as settings_err:  # noqa: BLE001 - unreadable = no setting ($REGION / $DEFAULT_REGION next)
        cause = f"settings document unreadable/invalid: {type(settings_err).__name__}: {settings_err}"
        logger.warning(f"Could not read the platform region setting: {cause}")
        return "", True, cause
    if not isinstance(region, str) or not region:
        return "", True, "settings default_gcp_region is blank"
    return region, True, ""


def resolve_platform_region(db: Any = None) -> str:
    region, consulted, cause = _settings_region(db)
    region = region or os.getenv("REGION", "") or os.getenv("DEFAULT_REGION", "")
    if not region and not consulted:
        region = _schema_default_region()   # no settings store at all: the documented default (as get_platform_settings)
    if not region:
        raise RegionUnavailable(f"{REGION_UNAVAILABLE}: {cause or 'no platform region configured'} "
                                "(settings default_gcp_region; REGION and DEFAULT_REGION unset)")
    return region


# FD-7M-a (SAT-22): a workload deploys into the region recorded on workloads/{product_id}.region, through the settings
# helper `workload_region()` (shared/settings.py, the SAT-21 contract) against the install's approved deployable
# regions. A record WITHOUT a region (legacy) keeps FD-4AL exactly: `resolve_platform_region` (byte-identical). A
# recorded region that is not approved is RegionNotApprovedError (REGION_NOT_APPROVED), never another region.
REGION_NOT_APPROVED = "REGION_NOT_APPROVED"   # parity: shared.settings.REGION_NOT_APPROVED (tests/test_sat22_*)


class RegionNotApprovedError(RuntimeError):
    """A workload's recorded region is not in the approved deployable regions (shared.settings.RegionNotApproved,
    re-raised as this server's typed error). `region` is the refused value, `approved` the effective list."""

    error_class = REGION_NOT_APPROVED

    def __init__(self, message: str, region: Any, approved: List[str]):
        super().__init__(message)
        self.region = region
        self.approved = list(approved)


def _settings_orchestration(db: Any) -> Dict[str, Any]:
    """The stored `orchestration` mapping of system_config/platform_settings, read through `db` with the same store
    contract as `_settings_region`: a missing document (or no `orchestration` key) is {} (schema defaults); no
    settings store at all (no client and no project, or a non-snapshot object) is the FD-4AL region as the only
    default ({"default_gcp_region": resolve_platform_region(db)}). A configured install without a client and an
    unreadable document raise RegionUnavailable with the cause: the approved list is never guessed."""
    if db is None:
        if _project_configured():
            raise RegionUnavailable(f"{REGION_UNAVAILABLE}: no settings Firestore client although a project is "
                                    "configured (the approved deployable regions cannot be read)")
        return {"default_gcp_region": resolve_platform_region(db)}
    try:
        snap = db.collection("system_config").document("platform_settings").get()
        exists = getattr(snap, "exists", None)
        if exists is False:
            return {}
        data = snap.to_dict() if exists is True else None
    except Exception as settings_err:  # noqa: BLE001 - classified: typed, never a default list
        raise RegionUnavailable(f"{REGION_UNAVAILABLE}: settings document unreadable/invalid: "
                                f"{type(settings_err).__name__}: {settings_err}") from settings_err
    if not isinstance(data, dict):
        return {"default_gcp_region": resolve_platform_region(db)}
    orch = data.get("orchestration")
    return dict(orch) if isinstance(orch, dict) else {}


def resolve_workload_region(db: Any, record_region: Any, *, stage: str = "terraform_deploy") -> str:
    """FD-7M-a: the region of one workload. `record_region` is workloads/{product_id}.region as read (None = the
    record has none: FD-4AL `resolve_platform_region(db)`, unchanged). Otherwise `workload_region(record_region,
    orchestration)`: the recorded region when approved, else RegionNotApprovedError; an unreadable or invalid
    settings document is RegionUnavailable."""
    if record_region is None:
        return resolve_platform_region(db)
    orchestration = _settings_orchestration(db)
    if not orchestration.get("default_gcp_region"):
        # FD-7M-a RT F2: a blank / missing stored default is FD-4AL's "no setting" ($REGION / $DEFAULT_REGION, else
        # typed RegionUnavailable), so the record path approves the same default the legacy path deploys into.
        orchestration["default_gcp_region"] = resolve_platform_region(db)
    try:
        from shared import settings as settings_contract
    except Exception as import_err:  # noqa: BLE001 - no contract = the region cannot be checked: typed
        raise RegionUnavailable(f"{REGION_UNAVAILABLE}: the settings contract is not importable "
                                f"({type(import_err).__name__}: {import_err})") from import_err
    try:
        region = settings_contract.workload_region(record_region, orchestration, stage=stage)
    except settings_contract.RegionNotApproved as refused:
        raise RegionNotApprovedError(str(refused), refused.region, refused.approved) from refused
    except Exception as invalid:  # noqa: BLE001 - an invalid orchestration document (pydantic): typed with the cause
        raise RegionUnavailable(f"{REGION_UNAVAILABLE}: settings document unreadable/invalid: "
                                f"{type(invalid).__name__}: {invalid}") from invalid
    if not isinstance(region, str) or not region:
        raise RegionUnavailable(f"{REGION_UNAVAILABLE}: settings default_gcp_region is blank")
    return region


# FD-4AZ RT F2 (with lane 14 PR-0 RT F4): a delete or replace of a resource whose PRIOR STATE (`change.before`, the
# value the provider enforces) has deletion protection on is refused before the apply with DESTROY_BLOCKED (routed to
# the operator by the workflow; never to developer IaC remediation, whose fix would be to switch the protection off).
# Exact (type -> attribute path -> protected value) table over the plan JSON; no text matching. `lifecycle
# { prevent_destroy }` is enforced by OpenTofu itself at plan time (the plan fails; nothing is applied).
ERROR_DESTROY_BLOCKED = "DESTROY_BLOCKED"
DELETION_PROTECTION_ATTRIBUTES: Dict[str, Tuple[Tuple[Tuple[Any, ...], Any], ...]] = {
    "google_sql_database_instance": ((("deletion_protection",), True),
                                     (("settings", 0, "deletion_protection_enabled"), True)),
    "google_spanner_database": ((("deletion_protection",), True),),
    "google_bigtable_instance": ((("deletion_protection",), True),),
    "google_bigtable_table": ((("deletion_protection",), "PROTECTED"),),
    "google_firestore_database": ((("delete_protection_state",), "DELETE_PROTECTION_ENABLED"),),
    "google_container_cluster": ((("deletion_protection",), True),),
    "google_compute_instance": ((("deletion_protection",), True),),
    "google_cloud_run_v2_service": ((("deletion_protection",), True),),
    "google_cloud_run_v2_job": ((("deletion_protection",), True),),
    # golden storage-bucket: prevent_destroy (FD-4AZ default) == force_destroy false
    "google_storage_bucket": ((("force_destroy",), False),),
}


class DestroyBlocked(Exception):
    """Raised from `_compliance_gated_apply`; `deploy_workload` returns `.result` (typed, status FAILED)."""

    def __init__(self, result: Dict[str, Any]):
        super().__init__(result.get("error", "destroy of a protected resource blocked"))
        self.result = result


# ------------------------------------------------------------------------------
# DEPLOY-ROOT-VARS (follow-up of AI-TFVARS-REFUSED; owner 11-07 backlog approval): the plan-level backstop of SAT-01's
# file check. After every gated `plan -out` / `show -json`, each variable the platform supplies for the workload (every
# key of the root terraform.tfvars it merges, the TF_VAR_* secrets, and the access variables when it rendered the
# access file) that the root module declares must have exactly the platform's value in the plan's own `variables`
# (the input values OpenTofu evaluated, from every source: files, -var-file, environment). A different value, or no
# value, refuses the apply typed (APPLY.ROOT_VARIABLE_OVERRIDDEN, error class TFVARS_OVERRIDES_PLATFORM,
# operator_required) naming the variable, never its value. A variable the root does not declare is not in the plan
# and is not checked. Exact JSON equality only (no text matching); nothing is rewritten.
# ------------------------------------------------------------------------------
APPLY_ROOT_VARIABLE_OVERRIDDEN = "APPLY.ROOT_VARIABLE_OVERRIDDEN"


class _UndecodablePlatformValue:
    """A platform variable text that is not a JSON literal: it can never be shown equal (fail closed)."""

    def __repr__(self) -> str:
        return "<undecodable platform value>"


def platform_root_variable_values(tfvars_values: Mapping[str, str], env_values: Mapping[str, Any],
                                  access_text: Optional[str]) -> Dict[str, Any]:
    """DEPLOY-ROOT-VARS: {variable: the exact input value the platform supplies}.

    `tfvars_values` is the deploy's {name: HCL value text} it merges into the root terraform.tfvars (always a quoted
    string without escapes or `true` / `false`, so the text is also a JSON literal and is decoded with json);
    `env_values` the TF_VAR_* values (strings, as OpenTofu receives them); `access_text` the platform access var file
    it renders ("{}" or None = none rendered). A text that does not decode is kept as an undecodable marker, which
    never matches."""
    out: Dict[str, Any] = {}
    for name, text in tfvars_values.items():
        try:
            out[name] = json.loads(text)
        except (TypeError, ValueError):
            out[name] = _UndecodablePlatformValue()
    for name, value in env_values.items():
        out[name] = "" if value is None else str(value)
    if access_text:
        try:
            access = json.loads(access_text)
        except ValueError:
            access = {"<platform access file>": _UndecodablePlatformValue()}
        if isinstance(access, dict):
            out.update(access)
    return out


def _same_json_value(a: Any, b: Any) -> bool:
    """Exact JSON equality (True is not 1, "1" is not 1, list order counts)."""
    if isinstance(a, _UndecodablePlatformValue) or isinstance(b, _UndecodablePlatformValue):
        return False
    try:
        return json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)
    except (TypeError, ValueError):
        return False


def root_variable_overrides(plan_json: Mapping[str, Any], expected: Mapping[str, Any]) -> List[Dict[str, str]]:
    """DEPLOY-ROOT-VARS: [{"variable", "reason"}] for every platform variable whose input value in the saved plan's
    JSON is not exactly the platform's ([] = none). Only variables the plan lists (the root declares them) are
    checked; a plan whose `variables` member is not an object is one finding."""
    variables = plan_json.get("variables")
    if variables is None:
        return []
    if not isinstance(variables, Mapping):
        return [{"variable": "*", "reason": "the plan's variables cannot be read"}]
    out: List[Dict[str, str]] = []
    for name in sorted(expected):
        if name not in variables:
            continue
        entry = variables[name]
        if not isinstance(entry, Mapping) or "value" not in entry:
            out.append({"variable": name, "reason": "has no value in the plan"})
        elif not _same_json_value(entry["value"], expected[name]):
            out.append({"variable": name, "reason": "has a value other than the one the platform sets"})
    return out


class RootVariableOverridden(DestroyBlocked):
    """DEPLOY-ROOT-VARS: a typed apply refusal with DestroyBlocked's contract (every handler returns `.result`)."""


def root_variable_overridden_result(product_id: str, trace_id: str,
                                    findings: List[Dict[str, str]]) -> Dict[str, Any]:
    names = [f["variable"] for f in findings]
    error = (f"{APPLY_ROOT_VARIABLE_OVERRIDDEN}: in the plan of '{product_id}', the platform-set variable"
             f"{'s' if len(names) > 1 else ''} " + "; ".join(f"{f['variable']} {f['reason']}" for f in findings)
             + ". A variables file, variable flag or environment value overrides what the platform sets; remove it "
               "from the repository or the runner environment. Nothing was applied.")
    return {"status": "FAILED", "error_class": ERROR_TFVARS_OVERRIDES_PLATFORM, "code": APPLY_ROOT_VARIABLE_OVERRIDDEN,
            "error": error, "variables": names, "operator_required": True, "product_id": product_id,
            "trace_id": trace_id}


# ------------------------------------------------------------------------------
# FD55-W6e (A34 replacement, register FD55-W6e): Cloud Run sets PORT itself and rejects a service that sets it. The
# deleted apply-time regex removed literal `env { name = "PORT" }` blocks from the .tf text (and missed dynamic blocks
# and module inputs). Now the saved plan is read: a create or update of a Cloud Run service whose planned container
# env names PORT stops the gated apply typed (APPLY.RESERVED_ENV_PORT, IAC_DEFECT) before anything is imported or
# applied. Exact type / attribute paths of the plan JSON and exact string equality; an env name still unknown at
# plan time is not decided here (Cloud Run's own error). Nothing is rewritten.
# ------------------------------------------------------------------------------
APPLY_RESERVED_ENV_PORT = "APPLY.RESERVED_ENV_PORT"
CLOUD_RUN_RESERVED_ENV_NAME = "PORT"
# Resource type -> the nested-block path (in the planned `after` value) to the list of containers.
_CLOUD_RUN_CONTAINER_PATHS: Mapping[str, Tuple[str, ...]] = {
    "google_cloud_run_v2_service": ("template", "containers"),
    "google_cloud_run_service": ("template", "spec", "containers"),
}


def _nested_blocks(value: Any, path: Tuple[str, ...]) -> List[Any]:
    """Every object at the nested-block `path` (each step: an object attribute holding an object or a list of
    objects, as `show -json` renders blocks)."""
    current = [value]
    for key in path:
        nxt: List[Any] = []
        for item in current:
            child = item.get(key) if isinstance(item, dict) else None
            nxt.extend(child if isinstance(child, list) else [child] if isinstance(child, dict) else [])
        current = nxt
    return current


def reserved_env_port_findings(plan_json: Any) -> List[Dict[str, Any]]:
    """[{"address", "container"}] for each planned Cloud Run service container (create / update) whose env sets
    PORT ([] = none)."""
    out: List[Dict[str, Any]] = []
    changes = plan_json.get("resource_changes") if isinstance(plan_json, dict) else None
    for rc in changes if isinstance(changes, list) else []:
        if not isinstance(rc, dict) or rc.get("mode", "managed") != "managed":
            continue
        path = _CLOUD_RUN_CONTAINER_PATHS.get(rc.get("type"))
        change = rc.get("change") if isinstance(rc.get("change"), dict) else {}
        actions = change.get("actions") if isinstance(change.get("actions"), list) else []
        if path is None or not ({"create", "update"} & set(actions)):
            continue
        for index, container in enumerate(_nested_blocks(change.get("after"), path)):
            envs = container.get("env") if isinstance(container, dict) else None
            for env in envs if isinstance(envs, list) else []:
                if isinstance(env, dict) and env.get("name") == CLOUD_RUN_RESERVED_ENV_NAME:
                    out.append({"address": str(rc.get("address") or ""),
                                "container": str(container.get("name") or index)})
    return out


class ReservedEnvRefused(DestroyBlocked):
    """FD55-W6e: a typed apply refusal with DestroyBlocked's contract (every handler returns `.result`)."""


def reserved_env_port_result(product_id: str, trace_id: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    where = "; ".join(f"{f['address']} (container {f['container']})" for f in findings[:20])
    error = (f"{APPLY_RESERVED_ENV_PORT}: the plan of '{product_id}' sets the environment variable PORT on "
             f"{where}. Cloud Run sets PORT itself and rejects a service that sets it; remove that env entry from the "
             "workload's Terraform. Nothing was applied.")
    return {"status": "FAILED", "error_class": IAC_DEFECT_ERROR_CLASS, "code": APPLY_RESERVED_ENV_PORT,
            "error": error, "reserved_env": findings[:50], "product_id": product_id, "trace_id": trace_id}


def _value_at(value: Any, path: Tuple[Any, ...]) -> Any:
    for step in path:
        if isinstance(step, int):
            if not isinstance(value, list) or len(value) <= step:
                return None
            value = value[step]
        else:
            if not isinstance(value, dict):
                return None
            value = value.get(step)
    return value


# FD-4CG (PR-0b Fable RT F3): workload data/registry stores whose destroy or replace is ALWAYS an operator decision,
# whatever their prior-state protection flags say (a Firestore database's delete_protection_state can be disabled by
# a regenerated config in the same plan; an Artifact Registry repository has no protection attribute at all).
REPLACE_BLOCKED_TYPES = frozenset({"google_firestore_database", "google_artifact_registry_repository"})
PROTECTION_REPLACE_BLOCKED_TYPE = "REPLACE_BLOCKED_TYPE"


def protected_destroys(plan_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every `resource_changes` entry whose actions include `delete` (a destroy or either replace order) and that is
    either of a REPLACE_BLOCKED_TYPES type or has, in its prior state, a deletion-protection attribute at its
    protected value (DELETION_PROTECTION_ATTRIBUTES)."""
    blocked = []
    for change in plan_json.get("resource_changes") or []:
        if not isinstance(change, dict):
            continue
        body = change.get("change") if isinstance(change.get("change"), dict) else {}
        actions = body.get("actions") if isinstance(body.get("actions"), list) else []
        if "delete" not in actions:
            continue
        if change.get("type") in REPLACE_BLOCKED_TYPES:
            blocked.append({"address": change.get("address"), "type": change.get("type"), "actions": actions,
                            "protection": PROTECTION_REPLACE_BLOCKED_TYPE})
            continue
        before = body.get("before")
        for path, protected in DELETION_PROTECTION_ATTRIBUTES.get(change.get("type") or "", ()):
            value = _value_at(before, path)
            if type(value) is type(protected) and value == protected:
                blocked.append({"address": change.get("address"), "type": change.get("type"), "actions": actions,
                                "protection": ".".join(str(p) for p in path)})
                break
    return blocked


def destroy_blocked_result(product_id: str, trace_id: str, blocked: List[Dict[str, Any]]) -> Dict[str, Any]:
    addresses = [b["address"] for b in blocked]
    return {
        "status": "FAILED",
        "error_class": ERROR_DESTROY_BLOCKED,
        "error": (f"{ERROR_DESTROY_BLOCKED}: the plan deletes or replaces deletion-protected resources {addresses}; "
                  "nothing was applied. An operator must decide (a protected data store is never destroyed by an "
                  "automatic deploy)."),
        "destroy_blocked": blocked,
        "product_id": product_id,
        "trace_id": trace_id,
    }


# ------------------------------------------------------------------------------
# FD-4AW-b (register row, owner 10-20): apply-time content policy on the saved plan's JSON (`tofu show -json`, the
# engine's own parse of every file it loaded: AI-written, platform-written AND human-written `human*.tf` / override
# files, every module). Before an apply, the plan is refused (typed APPLY_CONTENT_POLICY, nothing applied) when:
#  * POLICY.PROVISIONER_FORBIDDEN: any resource in any module declares a provisioner (local-exec / remote-exec / file:
#    they run commands on the apply runner or on the hosts it creates);
#  * POLICY.MODULE_SOURCE_NOT_LOCAL: a module call is not a local path inside the workspace (FD-4AW-a's rule at
#    apply: Terraform's local-path source `./` / `../`, no `version`, resolved against the calling module's directory
#    with posixpath.normpath; a registry, Git, HTTP or bucket source, or a path leaving the workspace, is refused).
#    The one path outside the workspace that is allowed is a module directory under `../modules/`: prepare_workspace
#    links <trace>/modules to this workspace's infra/modules (the typed-intent render's `../modules/<id>` sources
#    resolve through it);
#  * POLICY.PROVIDER_SOURCE_MISMATCH: a provider the plan uses or configures is not the platform's pinned set
#    (FD-4AW-a's PLATFORM_PROVIDER_SOURCES on either registry host, plus OpenTofu's built-in `terraform` provider);
#  * POLICY.REMOTE_STATE_FORBIDDEN: a `data "terraform_remote_state"` that does not provably read this workload's own
#    state (constant backend "gcs", constant config of exactly {bucket: the platform state bucket, prefix:
#    workloads/<product_id>});
#  * POLICY.PLAN_NOT_CHECKABLE: the plan JSON has no `configuration` object (fail closed).
# Exact JSON keys only, no text matching (AGENTS.md invariant 2). Note: `tofu plan` itself has already run by then
# (data sources were read, providers were started); this check stops the apply, not the plan.
# ------------------------------------------------------------------------------
ERROR_APPLY_CONTENT_POLICY = "APPLY_CONTENT_POLICY"
# FD-4AQ W1b: the server's single allow-list source (provider_allowlist.py), which equals the gateway's FD-4AW-a tables
# (developer_agent/validators/policy_tables.PLATFORM_PROVIDER_SOURCES and PLATFORM_PROVIDER_SOURCE_FORMS; parity pinned
# by tests/test_fd4aw_b_apply_content_policy.py).
APPLY_PLATFORM_PROVIDER_SOURCES = provider_allowlist.PLATFORM_PROVIDER_SOURCES
APPLY_PROVIDER_REGISTRIES = provider_allowlist.PROVIDER_REGISTRIES
APPLY_BUILTIN_PROVIDER = provider_allowlist.BUILTIN_PROVIDER   # terraform_data / terraform_remote_state
APPLY_ALLOWED_PROVIDERS = frozenset(
    {f"{reg}/{src}" for reg in APPLY_PROVIDER_REGISTRIES for src in APPLY_PLATFORM_PROVIDER_SOURCES.values()}
    | {APPLY_BUILTIN_PROVIDER})
_LOCAL_MODULE_SOURCE_PREFIXES = ("./", "../")   # Terraform's local-path module source rule (exact prefixes)
_PARENT_MODULES_LINK = ("..", "modules")   # prepare_workspace step 3: <trace>/modules -> <workspace>/infra/modules


def _module_target_allowed(target: str) -> bool:
    """A normalized workspace-relative module directory is inside the workspace (not the root itself), or a module
    directory under the platform's parent link `../modules/` (exact path segments)."""
    parts = tuple(target.split("/"))
    if parts[0] != "..":
        return target != "."
    return parts[:2] == _PARENT_MODULES_LINK and len(parts) > 2


def _plan_modules(module: Any, module_dir: str = "", address: str = ""):
    """(address, workspace-relative directory, module JSON) of `configuration.root_module` and every module it calls,
    depth first. A module call whose source is not a local path has no directory ("<remote>") and is still walked."""
    if not isinstance(module, dict):
        return
    yield address, module_dir, module
    calls = module.get("module_calls") if isinstance(module.get("module_calls"), dict) else {}
    for name, call in calls.items():
        if not isinstance(call, dict):
            continue
        source = call.get("source")
        child_dir = "<remote>"
        if module_dir != "<remote>" and isinstance(source, str) and source.startswith(_LOCAL_MODULE_SOURCE_PREFIXES):
            child_dir = posixpath.normpath(posixpath.join(module_dir or ".", source))
        yield from _plan_modules(call.get("module"), child_dir, f"{address}module.{name}.")


def _plan_provider_names(plan_json: Dict[str, Any]) -> Set[str]:
    """Every provider full name the plan configures or uses (configuration.provider_config, resource_changes,
    prior_state and planned_values resources, every module)."""
    names: Set[str] = set()
    config = plan_json.get("configuration") if isinstance(plan_json.get("configuration"), dict) else {}
    for entry in (config.get("provider_config") or {}).values() if isinstance(config.get("provider_config"), dict) \
            else ():
        if isinstance(entry, dict) and isinstance(entry.get("full_name"), str):
            names.add(entry["full_name"])
    for change in plan_json.get("resource_changes") or []:
        if isinstance(change, dict) and isinstance(change.get("provider_name"), str):
            names.add(change["provider_name"])

    def _walk_values(mod: Any) -> None:
        if not isinstance(mod, dict):
            return
        for res in mod.get("resources") or []:
            if isinstance(res, dict) and isinstance(res.get("provider_name"), str):
                names.add(res["provider_name"])
        for child in mod.get("child_modules") or []:
            _walk_values(child)

    prior = plan_json.get("prior_state") if isinstance(plan_json.get("prior_state"), dict) else {}
    _walk_values((prior.get("values") or {}).get("root_module") if isinstance(prior.get("values"), dict) else None)
    planned = plan_json.get("planned_values") if isinstance(plan_json.get("planned_values"), dict) else {}
    _walk_values(planned.get("root_module"))
    return names


def _remote_state_is_own(resource: Dict[str, Any], state_bucket: str, product_id: str) -> bool:
    """True only when the remote-state data source reads exactly this workload's own state (constant values)."""
    expr = resource.get("expressions") if isinstance(resource.get("expressions"), dict) else {}
    backend = (expr.get("backend") or {}).get("constant_value") if isinstance(expr.get("backend"), dict) else None
    config = (expr.get("config") or {}).get("constant_value") if isinstance(expr.get("config"), dict) else None
    return (bool(state_bucket) and backend == "gcs" and isinstance(config, dict)
            and config == {"bucket": state_bucket, "prefix": f"workloads/{product_id}"})


def plan_content_policy_violations(plan_json: Dict[str, Any], state_bucket: str = "",
                                   product_id: str = "") -> List[Dict[str, Any]]:
    """FD-4AW-b: every content-policy violation of a saved plan's JSON (see the section comment); [] = allowed."""
    out: List[Dict[str, Any]] = []
    config = plan_json.get("configuration") if isinstance(plan_json, dict) else None
    if not isinstance(config, dict):
        return [{"code": "POLICY.PLAN_NOT_CHECKABLE", "address": None,
                 "message": "the plan JSON has no configuration object; its content cannot be checked"}]
    for mod_address, mod_dir, module in _plan_modules(config.get("root_module")):
        for res in module.get("resources") or []:
            if not isinstance(res, dict):
                continue
            address = f"{mod_address}{res.get('address') or ''}"
            for prov in res.get("provisioners") or []:
                p_type = prov.get("type") if isinstance(prov, dict) else None
                out.append({"code": "POLICY.PROVISIONER_FORBIDDEN", "address": address, "provisioner": p_type,
                            "message": f'{address} declares provisioner "{p_type}"'})
            if res.get("mode") == "data" and res.get("type") == "terraform_remote_state" \
                    and not _remote_state_is_own(res, state_bucket, product_id):
                out.append({"code": "POLICY.REMOTE_STATE_FORBIDDEN", "address": address,
                            "message": f"{address} reads a Terraform state other than this workload's own"})
        calls = module.get("module_calls") if isinstance(module.get("module_calls"), dict) else {}
        for name, call in calls.items():
            call = call if isinstance(call, dict) else {}
            source = call.get("source")
            address = f"{mod_address}module.{name}"
            target = None
            if mod_dir != "<remote>" and isinstance(source, str) and source.startswith(_LOCAL_MODULE_SOURCE_PREFIXES):
                target = posixpath.normpath(posixpath.join(mod_dir or ".", source))
            if "version_constraint" in call or target is None or not _module_target_allowed(target):
                out.append({"code": "POLICY.MODULE_SOURCE_NOT_LOCAL", "address": address, "source": source,
                            "message": f"{address} source {source!r} is not a local module inside the workspace"
                                       + (" (it sets version)" if "version_constraint" in call else "")})
    for name in sorted(_plan_provider_names(plan_json) - APPLY_ALLOWED_PROVIDERS):
        out.append({"code": "POLICY.PROVIDER_SOURCE_MISMATCH", "address": None, "provider": name,
                    "message": f"provider {name!r} is not one of the platform's providers "
                               f"({', '.join(sorted(APPLY_ALLOWED_PROVIDERS))})"})
    return out


class ContentPolicyRefused(DestroyBlocked):
    """FD-4AW-b: a typed apply refusal with DestroyBlocked's contract (raised from the gated apply before anything is
    applied; every handler of DestroyBlocked returns `.result`, status FAILED)."""


class SecretGenerationRefused(DestroyBlocked):
    """SECRET-INITIAL-VERSION F2: the gated apply refuses to add the platform's random first version to an existing
    secret that has (or may have) a value (secret_generation_guard; DestroyBlocked's contract, operator required)."""


def content_policy_refusal(product_id: str, trace_id: str,
                           violations: List[Dict[str, Any]]) -> Dict[str, Any]:
    codes = sorted({v["code"] for v in violations})
    return {
        "status": "FAILED",
        "error_class": ERROR_APPLY_CONTENT_POLICY,
        "error": (f"{ERROR_APPLY_CONTENT_POLICY}: the plan breaks the platform's content policy ({', '.join(codes)}): "
                  + "; ".join(v["message"] for v in violations[:20])
                  + ". Nothing was applied. Workload Terraform (including human-written files) may not run "
                    "provisioners, use non-local modules or providers outside the platform's set, or read another "
                    "Terraform state"
                  # FD-7L Phase 2b: the sentence grows only when the new rule fired (every other refusal unchanged)
                  + (", or manage the platform's deployer account, its keys and grants, deny policies or the state "
                     "bucket" if POLICY_PLATFORM_IDENTITY_TOUCHED in codes else "")
                  + "."),
        "content_policy_violations": violations[:50],
        "product_id": product_id,
        "trace_id": trace_id,
    }


# ------------------------------------------------------------------------------
# FD-7L Phase 2b (plan docs/planning/fd-7l-per-workload-runner-identity-plan.md rev 3, sections 2.5-2.7 and 2.11;
# register rows FD-7L plan / FD-7L-c / -d / -e, owner OQ-32): the per-workload runner identity on the terraform server.
#  * Mode: `_runner_identity_mode()` is the ONE place the server reads it (shared.runner_identity.runner_identity_mode,
#    the install env STACKVEND_TF_RUNNER_IDENTITY; an unknown value is a typed refusal of every run).
#  * State location (`RunnerStateContext`): PLATFORM = the platform bucket, exactly as before (nothing is read).
#    PER_WORKLOAD = the bucket of vending's signed provenance record (guard database), only when that record verifies
#    and is READY: MIGRATING -> STATE_MIGRATION_IN_PROGRESS, any other status or no record ->
#    RUNNER_IDENTITY_NOT_READY, a record that does not verify -> its RUNNER_RECORD_* class. Never a fallback.
#  * Backend writer: PER_WORKLOAD writes `backend.tf` AFTER the committed files, so a committed root `backend.tf` is
#    replaced in the workspace (BACKEND_REPLACED_BY_PLATFORM, the repository is unchanged); PLATFORM keeps today's order.
#  * Pre-init policy (provider_allowlist.preinit_policy_findings) before the first `init` of every deploy / plan /
#    drift / force-unlock run: PER_WORKLOAD refuses (APPLY_CONTENT_POLICY, operator_required, nothing initialized);
#    PLATFORM refuses nothing and logs one POLICY_WOULD_REFUSE line per finding (OQ-32: a measurement before the
#    switch; no deploy result changes).
#  * Content policy addition POLICY.PLATFORM_IDENTITY_TOUCHED (`platform_identity_violations`, plan JSON, exact type /
#    attribute / value): refused in PER_WORKLOAD, POLICY_WOULD_REFUSE log lines in PLATFORM. The self-healing imports
#    never import the deployer account, the state bucket or `<project>-cloudbuild-source` in PER_WORKLOAD
#    (`reserved_import_reason`; PLATFORM logs POLICY_WOULD_REFUSE and imports as before).
#  * P1 (plan section 6, SAT-29 RT F2-1): `force_unlock` reads the lock object first and refuses the migration
#    tombstone and the migration lock (STATE_MOVED_DO_NOT_UNLOCK); a lock it cannot read is refused too
#    (STATE_LOCK_UNREADABLE). The STATE_LOCKED message names no force-unlock for those two locks. Every mode.
# ------------------------------------------------------------------------------
POLICY_PLATFORM_IDENTITY_TOUCHED = "POLICY.PLATFORM_IDENTITY_TOUCHED"
POLICY_WOULD_REFUSE = "POLICY_WOULD_REFUSE"                    # log code (PLATFORM mode measurement, OQ-32)
BACKEND_REPLACED_BY_PLATFORM = "BACKEND_REPLACED_BY_PLATFORM"  # warning code (PER_WORKLOAD backend writer)
RUNNER_IDENTITY_NOT_READY = "RUNNER_IDENTITY_NOT_READY"
STATE_MIGRATION_IN_PROGRESS = "STATE_MIGRATION_IN_PROGRESS"
RUNNER_STORE_UNAVAILABLE = "RUNNER_STORE_UNAVAILABLE"
STATE_BACKEND_MISMATCH = "STATE_BACKEND_MISMATCH"
STATE_MOVED_DO_NOT_UNLOCK = "STATE_MOVED_DO_NOT_UNLOCK"
STATE_LOCK_UNREADABLE = "STATE_LOCK_UNREADABLE"
STATE_IN_CHILD_BUCKET = "STATE_IN_CHILD_BUCKET"            # SAT-41 HIGH-3 (Shared path)
STATE_LOCATION_UNREADABLE = "STATE_LOCATION_UNREADABLE"    # SAT-41 HIGH-3 (Shared path)
STATE_LOCATION_UNCHECKED = "STATE_LOCATION_UNCHECKED"      # SAT-41 HIGH-3 (log code)
GUARD_DB_ENV = "STACKVEND_GUARD_FIRESTORE_DATABASE"
CLOUDBUILD_SOURCE_BUCKET_SUFFIX = "-cloudbuild-source"   # _build_and_push_container's staging bucket
_OWNER_ROLE = "roles/owner"


class RunnerIdentityRefused(Exception):
    """FD-7L Phase 2b: a run that may not start (typed; nothing is initialized, planned or applied)."""

    def __init__(self, error_class: str, message: str):
        super().__init__(f"{error_class}: {message}")
        self.error_class, self.message = error_class, message

    def result(self, product_id: str, trace_id: Optional[str]) -> Dict[str, Any]:
        return {"status": "FAILED", "error_class": self.error_class,
                "error": f"{self.error_class}: {self.message}. Nothing was initialized, planned or applied.",
                "product_id": product_id, "trace_id": trace_id,
                "operator_required": True}   # WF-OPERATOR-FLAG: a developer retry cannot change any of these


class RunnerContextRefusedAtApply(DestroyBlocked):
    """FD-7L Phase 2b: the gated apply could not establish the run's state context (DestroyBlocked's contract: the
    deploy returns `.result`, status FAILED, nothing applied)."""


@dataclass(frozen=True)
class RunnerStateContext:
    """Where one run's OpenTofu state lives and which identity facts the policies use (FD-7L Phase 2b)."""

    mode: str                            # ri.MODE_PLATFORM | MODE_PER_WORKLOAD
    bucket: str                          # the backend bucket of this run ("" = none configured, as before)
    source: str                          # "platform" | "provenance"
    project_id: Optional[str] = None     # PER_WORKLOAD: the provenance project
    deployer_email: Optional[str] = None  # PER_WORKLOAD: re-derived from the provenance project

    @property
    def per_workload(self) -> bool:
        return self.mode == ri.MODE_PER_WORKLOAD


def platform_identity(project_id: Optional[str], buckets: Iterable[str]) -> Optional[Dict[str, Any]]:
    """The identity facts PLATFORM_IDENTITY_TOUCHED protects: the project's deployer account (re-derived, never read)
    and the state bucket names. None when `project_id` is not a project id."""
    if not ri.is_project_id(project_id):
        return None
    return {"project_id": project_id, "deployer_email": ri.deployer_email(project_id).lower(),
            "state_buckets": frozenset(b for b in buckets if isinstance(b, str) and b)}


def parse_service_account_name(value: Any) -> Optional[Tuple[Optional[str], str]]:
    """Review F2: the IAM resource-name grammar of a service account reference, as the google provider accepts it in
    `service_account_id` and in an import id: `projects/<project>/serviceAccounts/<account>`, `<project>/<account>`
    or `<account>`, where <project> is a project id, a project number or `-`, and <account> an email or a numeric
    unique id. Returns (project or None, account lower-cased), or None when the value is not of that grammar."""
    if not isinstance(value, str) or not value:
        return None
    parts = value.split("/")
    if len(parts) == 4 and parts[0] == "projects" and parts[2] == "serviceAccounts" and parts[1] and parts[3]:
        return parts[1], parts[3].lower()
    if len(parts) == 2 and parts[0] and parts[1]:
        return parts[0], parts[1].lower()
    if len(parts) == 1:
        return None, parts[0].lower()
    return None


def _names_deployer_or_unresolvable(value: Any, identity: Mapping[str, Any]) -> bool:
    """True when a service account reference names the deployer, or cannot be shown not to: not of the grammar, or
    an account without `@` (the numeric unique id, which the platform cannot resolve before apply)."""
    parsed = parse_service_account_name(value)
    if parsed is None:
        return value is not None
    account = parsed[1]
    return not _is_account_email(account) or account == identity["deployer_email"]


_ACCOUNT_LOCAL_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
_ACCOUNT_DOMAIN_CHARS = _ACCOUNT_LOCAL_CHARS | {"."}


def _is_account_email(account: str) -> bool:
    """Re-check N2: a lower-cased service account email of the closed shape `<[a-z0-9-]+>@<[a-z0-9.-]+>` (no
    whitespace, no `?` / `#` / `%`, domain neither starting nor ending with `.`). Anything else -- the numeric unique
    id, a value with stray characters -- cannot be resolved by the platform before apply and is refused."""
    local, at, domain = account.partition("@")
    return (bool(at) and bool(local) and bool(domain) and set(local) <= _ACCOUNT_LOCAL_CHARS
            and set(domain) <= _ACCOUNT_DOMAIN_CHARS and not domain.startswith(".") and not domain.endswith(".")
            and ".." not in domain)


def _bucket_forms(identity: Mapping[str, Any]) -> FrozenSet[str]:
    """The exact values that name a state bucket in a storage resource's bucket attribute (`b/<name>` is the IAM form)."""
    return frozenset(v for b in identity["state_buckets"] for v in (b, f"b/{b}"))


def _bucket_import_names(import_id: Any) -> Set[str]:
    """The bucket a google_storage_bucket import id names: `<bucket>` or `<project>/<bucket>`."""
    if not isinstance(import_id, str) or not import_id:
        return set()
    return {import_id, import_id.split("/", 1)[1]} if "/" in import_id else {import_id}


# Exact (resource type -> attribute holding the bucket name) of the google provider's storage resources.
STORAGE_BUCKET_ATTRIBUTE = {
    "google_storage_bucket": "name",
    "google_storage_bucket_iam_member": "bucket",
    "google_storage_bucket_iam_binding": "bucket",
    "google_storage_bucket_iam_policy": "bucket",
    "google_storage_bucket_acl": "bucket",
    "google_storage_bucket_access_control": "bucket",
    "google_storage_bucket_object": "bucket",
    "google_storage_default_object_acl": "bucket",
    "google_storage_default_object_access_control": "bucket",
    "google_storage_object_acl": "bucket",
    "google_storage_object_access_control": "bucket",
    "google_storage_notification": "bucket",
    "google_storage_managed_folder": "bucket",
    "google_storage_managed_folder_iam_member": "bucket",
    "google_storage_managed_folder_iam_binding": "bucket",
    "google_storage_managed_folder_iam_policy": "bucket",
    "google_storage_anywhere_cache": "bucket",
}
DEPLOYER_SA_ID_TYPES = frozenset({"google_service_account_iam_member", "google_service_account_iam_binding",
                                  "google_service_account_iam_policy", "google_service_account_key"})
ALWAYS_IDENTITY_TOUCHING_TYPES = frozenset({"google_project_iam_policy", "google_iam_deny_policy"})
# Review F3 (owner 11-01): project-level grants that hand the deployer's power to another principal (owner and editor
# act on everything in the project; serviceAccountTokenCreator at project level mints the deployer's tokens). Exact
# role strings, a subset of the gateway's PRIVILEGED_ROLES (parity test).
PROJECT_LEVEL_IAM_TYPES = frozenset({"google_project_iam_member", "google_project_iam_binding",
                                     "google_project_iam_policy"})
PRIVILEGED_PROJECT_ROLES = frozenset({"roles/owner", "roles/editor", "roles/iam.serviceAccountTokenCreator"})

# Review F1: the ONLY shapes an identity attribute unknown at plan time may have. The value must be a bare reference
# (no function, template or conditional around it, checked on the workload's own HCL) to an attribute of a resource
# of this exact type in the same module, and that resource's key attribute must be known at plan time and not name a
# platform identity. Every other unknown value (another resource type such as terraform_data or random_*, a module
# input, a local, a data source) is refused: the value is decided at apply, after the gate.
UNKNOWN_REFERENCE_SHAPES = {
    "service_account_id": ("google_service_account", frozenset({"name", "email", "id"}), "account_id"),
    "bucket": ("google_storage_bucket", frozenset({"name", "id", "url", "self_link"}), "name"),
}
_IDENT_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")


def _parse_module_path(module_address: Any) -> Optional[Tuple[str, ...]]:
    """`module.a["k"].module.b[0]` -> ("a", "b") (instance keys dropped; a key is a JSON string or an integer).
    "" / None -> (). None when the text is not a module address."""
    if module_address in (None, ""):
        return ()
    if not isinstance(module_address, str):
        return None
    names: List[str] = []
    pos, text, decoder = 0, module_address, json.JSONDecoder()
    while pos < len(text):
        if not text.startswith("module.", pos):
            return None
        pos += len("module.")
        start = pos
        while pos < len(text) and text[pos] not in ".[":
            pos += 1
        if pos == start:
            return None
        names.append(text[start:pos])
        if pos < len(text) and text[pos] == "[":
            pos += 1
            if pos < len(text) and text[pos] == '"':
                try:
                    _key, pos = decoder.raw_decode(text, pos)
                except ValueError:
                    return None
            else:
                digits = pos
                while pos < len(text) and text[pos].isdigit():
                    pos += 1
                if pos == digits:
                    return None
            if pos >= len(text) or text[pos] != "]":
                return None
            pos += 1
        if pos < len(text):
            if text[pos] != ".":
                return None
            pos += 1
    return tuple(names)


def _config_module(root: Any, path: Tuple[str, ...]) -> Optional[Dict[str, Any]]:
    module = root if isinstance(root, dict) else None
    for name in path:
        calls = module.get("module_calls") if isinstance(module, dict) else None
        call = calls.get(name) if isinstance(calls, dict) else None
        module = call.get("module") if isinstance(call, dict) else None
    return module if isinstance(module, dict) else None


def _expression_refs(expressions: Any, attr: str) -> List[str]:
    expr = expressions.get(attr) if isinstance(expressions, dict) else None
    refs = expr.get("references") if isinstance(expr, dict) else None
    return [r for r in refs if isinstance(r, str)] if isinstance(refs, list) else []


def _instance_name(segment: str) -> Optional[str]:
    """`name`, `name[0]` or `name["k"]` -> name; None for anything else."""
    name, sep, rest = segment.partition("[")
    if not name or not set(name) <= _IDENT_CHARS:
        return None
    if sep and not (rest.endswith("]") and (rest[:-1].isdigit() or (len(rest) > 3 and rest[0] == '"'
                                                                     and rest[-2] == '"'))):
        return None
    return name


def _shape_resource(refs: List[str], rtype: str, attrs: FrozenSet[str]) -> Optional[str]:
    """The one resource name all `refs` point to when every reference is exactly `<rtype>.<name>[idx]` or
    `<rtype>.<name>[idx].<attr in attrs>` (OpenTofu lists the bare resource beside the attribute), else None."""
    names: Set[str] = set()
    for ref in refs:
        parts = ref.split(".")
        if len(parts) not in (2, 3) or parts[0] != rtype or (len(parts) == 3 and parts[2] not in attrs):
            return None
        name = _instance_name(parts[1])
        if name is None:
            return None
        names.add(name)
    return names.pop() if len(names) == 1 else None


def is_bare_reference(rendered: Any, rtype: str, name: str, attrs: FrozenSet[str]) -> bool:
    """True when python-hcl2's rendering of an attribute is exactly `${<rtype>.<name>[idx].<attr>}` (a reference and
    nothing around it: no function call, template text, operator or conditional). Exact grammar, refusal only."""
    if not isinstance(rendered, str) or not (rendered.startswith("${") and rendered.endswith("}")):
        return False
    parts = rendered[2:-1].split(".")
    return (len(parts) == 3 and parts[0] == rtype and _instance_name(parts[1]) == name and parts[2] in attrs)


def platform_identity_violations(plan_json: Dict[str, Any], identity: Optional[Mapping[str, Any]],
                                 source_lookup: Optional[Callable[..., Any]] = None) -> List[Dict[str, Any]]:
    """FD-7L Phase 2b (plan 2.5; review F1-F3): POLICY.PLATFORM_IDENTITY_TOUCHED for every planned change (any action
    but no-op / read) that would manage the platform's deployer account, its keys or grants, grant owner / editor /
    token creation at project level or remove the owner role, attach a deny policy, touch a state bucket, or import
    one of them. Known values are judged by exact grammar (parse_service_account_name, bucket names). An identity
    attribute unknown at plan time passes only in one of the closed UNKNOWN_REFERENCE_SHAPES, verified on the
    workload's HCL with `source_lookup(module_path, type, name, attribute) -> rendered value or None` (None: refused)."""
    if not identity:
        return []
    out: List[Dict[str, Any]] = []
    bucket_forms = _bucket_forms(identity)
    deployer_member = f"serviceaccount:{identity['deployer_email']}"
    config = plan_json.get("configuration") if isinstance(plan_json, dict) else None
    root = config.get("root_module") if isinstance(config, dict) else None
    changes = (plan_json.get("resource_changes") if isinstance(plan_json, dict) else None) or []
    changes = [rc for rc in changes if isinstance(rc, dict)] if isinstance(changes, list) else []

    def _instances(module_address: Any, rtype: str, name: str) -> List[Dict[str, Any]]:
        return [rc for rc in changes if (rc.get("module_address") or "") == (module_address or "")
                and rc.get("type") == rtype and rc.get("name") == name and rc.get("mode", "managed") == "managed"]

    def _unknown_ok(rc: Dict[str, Any], attr: str, cfg_res: Any, path: Optional[Tuple[str, ...]]) -> bool:
        shape = UNKNOWN_REFERENCE_SHAPES.get(attr)
        if shape is None or path is None or cfg_res is None or rc.get("type") == shape[0]:
            return False
        rtype, attrs, key = shape
        name = _shape_resource(_expression_refs(cfg_res.get("expressions"), attr), rtype, attrs)
        if name is None:
            return False
        targets = _instances(rc.get("module_address"), rtype, name)
        if not targets:
            return False
        for target in targets:
            t_change = target.get("change") if isinstance(target.get("change"), dict) else {}
            t_after = t_change.get("after") if isinstance(t_change.get("after"), dict) else {}
            t_unknown = t_change.get("after_unknown") if isinstance(t_change.get("after_unknown"), dict) else {}
            value = t_after.get(key)
            if t_unknown.get(key) is True or not isinstance(value, str) or not value:
                return False
            if (key == "account_id" and value.lower() == ri.DEPLOYER_ACCOUNT_ID) or \
                    (key == "name" and value in identity["state_buckets"]):
                return False
        if source_lookup is None:
            return False
        try:
            rendered = source_lookup(path, rc.get("type"), rc.get("name"), attr)
        except Exception:  # noqa: BLE001 - a source that cannot be read cannot be shown to be a bare reference
            return False
        return is_bare_reference(rendered, rtype, name, attrs)

    for rc in changes:
        if rc.get("mode", "managed") != "managed":
            continue
        rtype, address = rc.get("type"), rc.get("address")
        change = rc.get("change") if isinstance(rc.get("change"), dict) else {}
        actions = change.get("actions") if isinstance(change.get("actions"), list) else []
        importing = rc.get("importing") if isinstance(rc.get("importing"), dict) else {}
        reasons: List[str] = []
        if importing:
            import_id = importing.get("id")
            if rtype == "google_storage_bucket" and _bucket_import_names(import_id) & set(identity["state_buckets"]):
                reasons.append(f"imports the state bucket {import_id}")
            if rtype == "google_service_account" and _names_deployer_or_unresolvable(import_id, identity):
                reasons.append("imports the deployer account (or an account it cannot resolve)")
        if actions not in (["no-op"], ["read"]) and actions:
            values = change.get("after") if isinstance(change.get("after"), dict) else None
            if values is None or actions == ["delete"]:
                values = change.get("before") if isinstance(change.get("before"), dict) else {}
            unknown = change.get("after_unknown") if isinstance(change.get("after_unknown"), dict) else {}
            path = _parse_module_path(rc.get("module_address"))
            cfg_module = _config_module(root, path) if path is not None else None
            cfg_res = next((r for r in (cfg_module or {}).get("resources") or []
                            if isinstance(r, dict) and r.get("mode") == "managed" and r.get("type") == rtype
                            and r.get("name") == rc.get("name")), None)

            def _check(attr: str, bad: Callable[[Any], bool], what: str) -> None:
                if unknown.get(attr) is True and actions != ["delete"]:
                    if not _unknown_ok(rc, attr, cfg_res, path):
                        reasons.append(f"{attr} is not known until apply and is not a plain reference to a "
                                       f"resource of this configuration that is known to be safe (it could name "
                                       f"{what})")
                elif bad(values.get(attr)):
                    reasons.append(f"{attr} names {what}")

            def _own_project(v: Any) -> bool:
                """Re-check N1 (fail closed): only a known, well-formed OTHER project id is another project. The
                provider normalises `projects/<id>` to <id> and the IAM API takes the project number, so None, "",
                the own id in any case or prefix form, a project number, or any value outside the project-id grammar
                count as the workload's own project (the deployer has no rights elsewhere, so treating an
                unparseable value as own costs a legitimate author nothing)."""
                if v in (None, ""):
                    return True
                if not isinstance(v, str):
                    return True
                name = v[len("projects/"):] if v.startswith("projects/") else v
                name = name.lower()
                return not (ri.is_project_id(name) and name != identity["project_id"])

            if rtype == "google_service_account":
                _check("account_id", lambda v: isinstance(v, str) and v.lower() == ri.DEPLOYER_ACCOUNT_ID,
                       "the deployer account")
            elif rtype in DEPLOYER_SA_ID_TYPES:
                _check("service_account_id", lambda v: _names_deployer_or_unresolvable(v, identity),
                       "the deployer account (or an account the platform cannot resolve)")
            elif rtype in ALWAYS_IDENTITY_TOUCHING_TYPES:
                reasons.append(f"{rtype} is never managed by workload Terraform")
            elif rtype in PROJECT_LEVEL_IAM_TYPES:
                project_known = unknown.get("project") is not True
                if not project_known or _own_project(values.get("project")):
                    _check("role", lambda v: v in PRIVILEGED_PROJECT_ROLES,
                           f"a privileged project role ({', '.join(sorted(PRIVILEGED_PROJECT_ROLES))})")
            elif rtype == "google_project_iam_member_remove":
                _check("role", lambda v: v == _OWNER_ROLE, _OWNER_ROLE)
                _check("member", lambda v: isinstance(v, str) and v.lower() == deployer_member,
                       "the deployer account")
            elif rtype in STORAGE_BUCKET_ATTRIBUTE:
                _check(STORAGE_BUCKET_ATTRIBUTE[rtype], lambda v: v in bucket_forms, "a state bucket")
        for why in reasons:
            out.append({"code": POLICY_PLATFORM_IDENTITY_TOUCHED, "address": address,
                        "message": f"{address} {why}"})
    return out


def state_move_lock_kind(lock: Any) -> Optional[str]:
    """"tombstone" / "migration" when a lock (a parsed LockInfo body, or a lock_info dict of this module with
    `operation` / `who`) is FD-7L's migration tombstone or migration lock (exact Operation and Who, through
    shared.runner_identity), else None."""
    if not isinstance(lock, Mapping):
        return None
    body = dict(lock) if "Operation" in lock else {"Operation": lock.get("operation"), "Who": lock.get("who")}
    if ri.is_tombstone(body):
        return "tombstone"
    if ri.is_migration_lock(body):
        return "migration"
    return None


def reserved_import_reason(rtype: Any, import_id: Any, identity: Optional[Mapping[str, Any]]) -> Optional[str]:
    """FD-7L Phase 2b (plan 2.5): why the self-healing import may not adopt this resource (the deployer account, a
    state bucket, the project's `<project>-cloudbuild-source` build bucket), else None. Exact values only."""
    if not identity or not isinstance(import_id, str):
        return None
    if rtype == "google_service_account" and _names_deployer_or_unresolvable(import_id, identity):
        return "the platform's deployer account (or an account the platform cannot resolve)"
    if rtype == "google_storage_bucket":
        reserved = set(identity["state_buckets"]) | {identity["project_id"] + CLOUDBUILD_SOURCE_BUCKET_SUFFIX}
        if _bucket_import_names(import_id) & reserved:
            return "a platform-owned bucket (state or build staging)"
    return None


# EXP-7 (register row, owner 10-19): an Express deploy refuses to delete or replace a resource already in state unless
# the operator approved exactly those addresses. Typed trigger only: the Control Center's Express pipeline sends
# `refuse_destroy: true` (+ `approved_removals`) in the /deploy body, which becomes a DestroyPolicy; without it (every
# Agent-mode deploy, /deploy-async, apply_plan) nothing changes. Decided from `show -json` `resource_changes` only:
# an entry whose actions include `delete` (a destroy, either replace order, or a deposed object's delete) needs
# approval, except a replacement whose typed `action_reason` is `replace_because_tainted` (OpenTofu 1.9.0 emits it:
# a retry after a partially failed apply must still work). No text matching.
ERROR_DESTROY_REQUIRES_APPROVAL = "DESTROY_REQUIRES_APPROVAL"
TAINTED_REPLACE_REASON = "replace_because_tainted"


@dataclass(frozen=True)
class DestroyPolicy:
    """EXP-7: present only on an Express deploy. `approved_removals` = the addresses the operator approved."""

    approved_removals: FrozenSet[str] = frozenset()


def removals_requiring_approval(plan_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Every `resource_changes` entry whose actions include `delete`, except a delete+create whose action_reason is
    exactly TAINTED_REPLACE_REASON."""
    out: List[Dict[str, Any]] = []
    for change in plan_json.get("resource_changes") or []:
        if not isinstance(change, dict):
            continue
        body = change.get("change") if isinstance(change.get("change"), dict) else {}
        actions = body.get("actions") if isinstance(body.get("actions"), list) else []
        if "delete" not in actions:
            continue
        reason = change.get("action_reason")
        if reason == TAINTED_REPLACE_REASON and "create" in actions:
            continue
        entry = {"address": change.get("address"), "type": change.get("type"), "actions": list(actions),
                 "action_reason": reason}
        if change.get("deposed"):
            entry["deposed"] = change.get("deposed")
        out.append(entry)
    return out


def record_destroy_approval(db: Any, product_id: str, trace_id: str, evidence: Dict[str, Any]) -> None:
    """EXP-7 RT B2: `workloads/{pid}/compliance_audits/{trace}.destroy_approval` (evidence only, like the gate's
    `_record_evidence`: a write failure is logged and never changes the outcome)."""
    if db is None or not trace_id:
        return
    try:
        db.collection("workloads").document(product_id).collection("compliance_audits").document(trace_id).set(
            {"destroy_approval": evidence}, merge=True)
    except Exception as e:
        logger.warning(f"Could not record the destroy approval for {product_id}/{trace_id}: {type(e).__name__}")


def destroy_approval_refusal(product_id: str, trace_id: str, plan_json: Dict[str, Any],
                             policy: DestroyPolicy) -> Optional[Dict[str, Any]]:
    """None when the plan removes nothing that needs approval, or when the approved list equals exactly the set of
    addresses it removes; otherwise the typed DESTROY_REQUIRES_APPROVAL result (status FAILED)."""
    removals = removals_requiring_approval(plan_json)
    if not removals:
        return None
    raw = [r["address"] for r in removals]
    if all(isinstance(a, str) and a for a in raw) and set(raw) == set(policy.approved_removals):
        return None
    addresses = sorted({a for a in raw if isinstance(a, str)})
    return {
        "status": "FAILED",
        "error_class": ERROR_DESTROY_REQUIRES_APPROVAL,
        "error": (f"{ERROR_DESTROY_REQUIRES_APPROVAL}: the plan deletes or replaces resources already in state "
                  f"{addresses}; nothing was applied. Re-submit without the change, or approve by re-submitting "
                  "with approved_removals set to exactly these addresses."),
        "destroy_requires_approval": removals,
        "removal_addresses": addresses,
        "approved_removals": sorted(policy.approved_removals),
        "product_id": product_id,
        "trace_id": trace_id,
    }


# settings-toggles ST-2 (path b, owner 10-19; amends EXP-7's "Agent deploys unchanged"): governance.
# require_hitl_for_destructive_tf. Without a DestroyPolicy (every Agent-mode deploy; Express keeps EXP-7's exact-address
# approval), when the setting is on -- or cannot be read (strict read, fail closed) -- a gated apply whose plan
# deletes or replaces a DATA-HOLDING resource stops before the apply with DESTROY_REQUIRES_APPROVAL (an operator
# class: never developer remediation). "Data-holding" is the owner-set exact provider resource type below, read from
# the plan's typed `resource_changes[].type` (module-wrapped addresses included: the type, never the name or address).
# The removal rule is EXP-7's `removals_requiring_approval` (tainted replacements exempt). Deletes/replaces of any
# other type (Cloud Run, IAM, topics, service accounts, NEGs, ...) apply as today, so the self-healing loop keeps
# working. Deletion-protected resources are DESTROY_BLOCKED first. Off -> exactly today. The settings are read only
# when the plan removes a data-holding resource. No text matching.
DATA_HOLDING_RESOURCE_TYPES = frozenset({
    "google_storage_bucket",
    "google_firestore_database",
    "google_bigquery_dataset",
    "google_bigquery_table",
    "google_redis_instance",
    "google_filestore_instance",
    "google_alloydb_cluster",
    "google_alloydb_instance",
    "google_sql_database_instance",
    "google_sql_database",
    "google_secret_manager_secret",
    "google_artifact_registry_repository",
    "google_pubsub_subscription",
    "google_container_cluster",
    "google_compute_disk",
    "google_kms_crypto_key",
    "google_kms_key_ring",
    # ST-2b (owner 10-19)
    "google_spanner_instance",
    "google_spanner_database",
    "google_bigtable_instance",
    "google_bigtable_table",
    "google_composer_environment",
    "google_cloud_tasks_queue",
    "google_compute_instance",
    # Deliberately NOT listed (ST-2b): google_secret_manager_secret_version -- a rotation replaces the version and must
    # keep applying; the parent google_secret_manager_secret is listed.
})


def data_holding_removals(plan_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    """EXP-7's removals_requiring_approval, restricted to DATA_HOLDING_RESOURCE_TYPES (exact `type`)."""
    return [r for r in removals_requiring_approval(plan_json) if r.get("type") in DATA_HOLDING_RESOURCE_TYPES]


def destructive_tf_requires_approval() -> bool:
    """governance.require_hitl_for_destructive_tf (shared.settings, strict read); True when it cannot be read."""
    try:
        from shared.settings import destructive_tf_requires_approval as _requires
    except ImportError:
        return True
    return _requires()


def hitl_destroy_refusal(product_id: str, trace_id: str, removals: List[Dict[str, Any]]) -> Dict[str, Any]:
    addresses = sorted({r["address"] for r in removals if isinstance(r.get("address"), str)})
    return {
        "status": "FAILED",
        "error_class": ERROR_DESTROY_REQUIRES_APPROVAL,
        "error": (f"{ERROR_DESTROY_REQUIRES_APPROVAL}: the plan deletes or replaces data-holding resources {addresses} "
                  "and the platform setting 'Require Human Approval for Destructive Terraform' is on (or could not be "
                  "read); nothing was applied. An operator decides: change the workload so the plan keeps these "
                  "resources, or approve by switching the setting off on the Settings page (recorded in the settings "
                  "audit log), re-running the deploy, and switching it back on."),
        "destroy_requires_approval": removals,
        "removal_addresses": addresses,
        "product_id": product_id,
        "trace_id": trace_id,
    }


# S2-C C1b: the pre-S2-C substring tables, kept ONLY for the legacy remainder below (one unparseable file at a time)
# until the B4 live inventory shows no such file on either install; deleted in S2-F F6 (register HS-63).
GCP_RESOURCE_TO_API_MAP = {
    "google_cloud_run": "run.googleapis.com",
    "google_firestore": "firestore.googleapis.com",
    "google_pubsub": "pubsub.googleapis.com",
    "google_bigquery": "bigquery.googleapis.com",
    "google_storage": "storage.googleapis.com",
    "google_secret_manager": "secretmanager.googleapis.com",
    "google_cloud_tasks": "cloudtasks.googleapis.com",
    "google_cloud_scheduler": "cloudscheduler.googleapis.com",
    "google_eventarc": "eventarc.googleapis.com",
    "google_workflows": "workflows.googleapis.com",
    "google_redis": "redis.googleapis.com",
    "google_spanner": "spanner.googleapis.com",
    "google_compute": "compute.googleapis.com",
    "google_container": "container.googleapis.com",
    "google_cloudbuild": "cloudbuild.googleapis.com",
    "google_artifact_registry": "artifactregistry.googleapis.com",
    "google_logging": "logging.googleapis.com",
    "google_monitoring": "monitoring.googleapis.com",
    "google_vpc_access": "vpcaccess.googleapis.com",
    "google_sql": "sqladmin.googleapis.com",
    "google_iap": "iap.googleapis.com",
    "google_service_networking": "servicenetworking.googleapis.com",
    "google_compute_global_address": "compute.googleapis.com",
}

GCP_MODULE_TO_API_MAP = {
    "compute-gke-autopilot": ["container.googleapis.com", "compute.googleapis.com"],
    "compute-cloudrun": ["run.googleapis.com"],
    "compute-gce-bastion": ["compute.googleapis.com"],
    "compute-gce-worker": ["compute.googleapis.com"],
    "compute-event-worker": ["run.googleapis.com", "pubsub.googleapis.com"],
    "database-cloudsql": ["sqladmin.googleapis.com", "compute.googleapis.com", "servicenetworking.googleapis.com"],
    "database-spanner": ["spanner.googleapis.com"],
    "database-alloydb": ["alloydb.googleapis.com", "compute.googleapis.com", "servicenetworking.googleapis.com"],
    "database-bigtable": ["bigtableadmin.googleapis.com"],
    "cache-redis": ["redis.googleapis.com", "compute.googleapis.com", "servicenetworking.googleapis.com"],
    "messaging-pubsub": ["pubsub.googleapis.com"],
    "analytics-bigquery": ["bigquery.googleapis.com"],
    "ai-vertex-endpoint": ["aiplatform.googleapis.com"],
    "orchestration-composer": ["composer.googleapis.com"],
    "scheduling-cron": ["cloudscheduler.googleapis.com"],
    "tasks-queue": ["cloudtasks.googleapis.com"],
    "security-secret": ["secretmanager.googleapis.com"],
    "security-kms": ["cloudkms.googleapis.com"],
    "networking-vpc": ["compute.googleapis.com", "servicenetworking.googleapis.com"],
    "networking-vpc-connector": ["vpcaccess.googleapis.com"],   # FD-4BH golden Serverless VPC Access connector
    "observability-alerts": ["monitoring.googleapis.com"],
    "workflows-dag": ["workflows.googleapis.com"],
}

# Standard self-signed RFC 5280 dummy x509 test certificate (base64-encoded PEM)
# Used exclusively to satisfy static provider schema validation during out-of-band imports
DUMMY_K8S_PEM_CERT = (
    "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURBVENDQWVtZ0F3SUJBZ0lVZCtUbDZkV00x"
    "UUpRaGlVTkUvKzJCa1ZScFZBd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0VERU9NQXdHQTFVRUF3d0Za"
    "SFZ0Ylhrd0hoY05Nall4TURBME1UZ3lOelU1V2hjTk16WXhNREF4TVRneQpOelU1V2pBUU1RNHdE"
    "QVlEVlFRRERBVmtkVzF0ZVRDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDCkFRb0Nn"
    "Z0VCQU5mMXZ5VkVYR1FXVWNlTFh0NGlmMXp3MnVrVCtJWG4yMEQ5NDBMSnRta2NpQVk3R213Zmda"
    "QmEKTVM2OWUrSENRcnBkNFpzT3lkT05RR0taOXl5by9xa2UvMWRyVmdEVUtkOGFvZThBMHBac2RR"
    "RmQwdjRnMGwvSQpyQmZ4ZVdtc2loQlE4L3BSOTJrY0NGbXZ3bFc3dDN4QUEzallXUnFXNmJISm5n"
    "ZmtWYW52dEdFVytPbnc2ajZ6Ck9aMFl4ZndueUd4czBPcFhjUWEyMTlIZWU0L2s2cnc1UGVpL2dm"
    "TUMxUHBUWU9FOHViNFIxUDJOajFBNkFCRHcKUDZNUkR3dUx3Y2FoYng1RXJCK3E0S283TjdxUFBP"
    "ZjNGenpEQ01WRlhmVENoY24zWVNBTnFOb09nR2kxTUdZdwp0VVZMNWxCWGlrdlVxb2RsNlZERUJw"
    "KzROZ1UwQ0pFQ0F3RUFBYU5UTUZFd0hRWURWUjBPQkJZRUZCRWNveVpGCldnQ2tIYnNOdWovUTJn"
    "WUk2NnRKTUI4R0ExVWRJd1FZTUJhQUZCRWNveVpGV2dDa0hic051ai9RMmdZSTY2dEoKTUE4R0Ex"
    "VWRFd0VCL3dRRk1BTUJBZjh3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUxJa25QS0F4RlVhaElt"
    "agovL3BwOVBnaGlnL29vSHdBNk5wU1ZtdmJqWUlLTVF1dzVtTDdtaGN3UWcrdW5QMG4rZjlGb1dU"
    "L1BrYnFET0p5CmlxVk5CMm1reXB5Q2wyY0VueVRMK21YS2F3YUEvWUhvTUppc1U2ZDExYTNYRDRZ"
    "VFhvWEVjdS9rQ3lwdUx3eisKdDg3ZFRWbC91SDBObWlTTUcvVWJyN0sraGRvTThNRkVCWXdLcjVT"
    "Vm4zQW1iRGozeXlIQ0ZSdXoxM292SjFnQgozUVZqTEI1Z25SV3U3UjdqUFF6Z0luaXN6VEFsZ2Va"
    "MnVEdlhBUVVaNGtObzl5WXVNaHpxYXRyMERpQ3dvdDc3Ck5pOVhhQ1dIcXdHOWFrZHVhYlhGMTB0"
    "U3d6UW42RUJmcDJJZ04zc01mWmdhOUVYSEd3ZXljdG5vT1gvK2NlODkKcHBpWnNjZz0KLS0tLS1F"
    "TkQgQ0VSVElGSUNBVEUtLS0tLQo="
)


_LEGACY_K8S_SIGNATURES = (
    "apiVersion: apps/", "apiVersion: v1", "kind: Deployment", "kind: Service", "kind: HorizontalPodAutoscaler",
    "kind: StatefulSet", "kind: DaemonSet", "kind: Ingress",
)


def _legacy_extract_apis_from_text(text: str, is_yaml: bool = False) -> Set[str]:
    """S2-C C1b legacy remainder (deleted in S2-F F6): the pre-S2-C substring scan, applied ONLY to a single file the
    exact scanner could not parse (IAC.API_SCAN_UNPARSEABLE), so a legacy committed tree keeps its API coverage until
    the B4 inventory shows no such file. A Step-1/Step-2 committed tree always parses (V1a/V1b), so this never runs for
    new workloads. The old "default to run + firestore" rule is not kept (both are in the foundation's base_apis)."""
    apis: Set[str] = set()
    if is_yaml:
        if any(sig in text for sig in _LEGACY_K8S_SIGNATURES):
            apis.update({"container.googleapis.com", "compute.googleapis.com"})
        return apis
    for resource_prefix, api_service in GCP_RESOURCE_TO_API_MAP.items():
        if resource_prefix in text:
            apis.add(api_service)
    for module_name, api_list in GCP_MODULE_TO_API_MAP.items():
        if module_name in text:
            apis.update(api_list)
    return apis


def extract_apis_from_hcl(hcl_dict: Dict[str, str], yaml_dict: Optional[Dict[str, str]] = None) -> List[str]:
    """
    APIs the workspace needs, for the REST services:batchEnable before apply (S2-C C1b, register HS-63).

    The exact table shared with the gateway (shared.api_requirements.required_apis): base trio + exact resource/data
    types (.tf via python-hcl2, .tf.json via json) + golden-module rows by literal local module source + Kubernetes
    YAML by exact apiVersion/kind. The substring scan over the concatenated text and the "default run + firestore"
    rule are deleted. Unknown types are logged (IAC.API_UNKNOWN_FOR_TYPE), never guessed; for a file the parsers
    reject, the legacy per-file scan is unioned in and logged (IAC.API_SCAN_UNPARSEABLE) until S2-F F6.
    """
    req = required_apis(hcl_dict or {}, yaml_dict or {})
    apis = set(req.apis)
    for path in req.unparseable_files:
        is_yaml = path.lower().endswith((".yaml", ".yml"))
        text = ((yaml_dict or {}) if is_yaml else (hcl_dict or {})).get(path) or ""
        legacy = _legacy_extract_apis_from_text(text, is_yaml)
        logger.warning(f"IAC.API_SCAN_UNPARSEABLE {path}: exact API scan not possible; legacy per-file scan adds "
                       f"{sorted(legacy - apis)}")
        apis |= legacy
    for path, key in req.unknown:
        logger.warning(f"IAC.API_UNKNOWN_FOR_TYPE {path}: no API row for {key} (not enabled automatically)")
    return sorted(apis)


def sanitize_wheel_requirements(
    req_content: str,
    python_version: str = "3.13",
    package_versions: Optional[Dict[str, str]] = None,
    *,
    harmonize_legacy_wheels: bool = True,
) -> str:
    """
    Harmonizes dependencies against the centrally configured Platform BOM (package_versions)
    and relaxes legacy pinned binary packages lacking wheels on Python 3.13+.
    Custom or unmanaged dependencies are preserved verbatim.
    FD-4DJ-HARMONIZE: `harmonize_legacy_wheels` is Settings > Auto-Harmonize Legacy C-Extension Wheels. True (the
    default) is the behaviour before the switch was read, byte for byte. Only `False` keeps an old numpy / scipy /
    pandas / asyncpg pin that the BOM does not list exactly as written; the BOM rewrites and the starlette / greenlet
    lines run in both cases.
    """
    if not req_content:
        return req_content

    import re
    lines = req_content.splitlines()
    harmonized_lines = []

    # Rules specifically for Python 3.13+ missing wheels
    numpy_pattern = re.compile(r"^numpy\s*==\s*1\.[0-9\.]+", re.IGNORECASE)
    scipy_pattern = re.compile(r"^scipy\s*==\s*1\.[0-9\.]+", re.IGNORECASE)
    pandas_pattern = re.compile(r"^pandas\s*==\s*[01]\.[0-9\.]+", re.IGNORECASE)
    asyncpg_pattern = re.compile(r"^asyncpg\s*(==|>=|<=|<|>|~=)?\s*0\.(2[0-9]|[0-1][0-9])(\.[0-9]+)?.*", re.IGNORECASE)

    bom_overrides = dict(package_versions or {})
    if "starlette" not in bom_overrides:
        bom_overrides["starlette"] = ">=0.37.2,<1.0.0"
    if "email-validator" not in bom_overrides:
        bom_overrides["email-validator"] = ">=2.0.0,<3.0.0"

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            harmonized_lines.append(line)
            continue

        # Check against central BOM package_versions
        matched_bom = False
        for pkg_name, target_constraint in bom_overrides.items():
            pkg_pattern = re.compile(rf"^{re.escape(pkg_name)}(\[[^\]]*\])?(\s*([=><~]=?|!=).*)?$", re.IGNORECASE)
            m = pkg_pattern.match(stripped)
            if m:
                extras = m.group(1) or ""
                clean_target = target_constraint.strip()
                if not any(clean_target.startswith(op) for op in ["==", ">=", "<=", ">", "<", "~=", "!="]):
                    clean_target = f"=={clean_target}"
                harmonized_lines.append(f"{pkg_name}{extras}{clean_target}  # enforced by Platform BOM")
                matched_bom = True
                break

        if matched_bom:
            continue

        if harmonize_legacy_wheels is False:
            harmonized_lines.append(line)   # FD-4DJ-HARMONIZE: switch off -> the unlisted legacy pin is kept as written
        elif numpy_pattern.match(stripped):
            harmonized_lines.append("numpy>=1.26.0  # auto-harmonized by Castor BOM for Python 3.13 wheel compatibility")
        elif scipy_pattern.match(stripped):
            harmonized_lines.append("scipy>=1.14.0  # auto-harmonized by Castor BOM for Python 3.13 wheel compatibility")
        elif pandas_pattern.match(stripped):
            harmonized_lines.append("pandas>=2.2.0  # auto-harmonized by Castor BOM for Python 3.13 wheel compatibility")
        elif asyncpg_pattern.match(stripped):
            harmonized_lines.append("asyncpg>=0.30.0,<1.0.0  # auto-harmonized by Castor BOM for Python 3.13 wheel compatibility")
        else:
            harmonized_lines.append(line)

    # Ensure starlette constraint is present if FastAPI or Jinja2 is declared without explicit starlette pin
    has_fastapi_or_jinja = any(re.match(r"^(fastapi|jinja2)\b", l.strip(), re.IGNORECASE) for l in lines if not l.strip().startswith("#"))
    has_starlette = any(re.match(r"^starlette\b", l.strip(), re.IGNORECASE) for l in harmonized_lines if not l.strip().startswith("#"))
    if has_fastapi_or_jinja and not has_starlette:
        starlette_constraint = bom_overrides.get("starlette", ">=0.37.2,<1.0.0").strip()
        if not any(starlette_constraint.startswith(op) for op in ["==", ">=", "<=", ">", "<", "~=", "!="]):
            starlette_constraint = f"=={starlette_constraint}"
        harmonized_lines.append(f"starlette{starlette_constraint}  # enforced by Platform BOM for FastAPI/Starlette template compatibility")

    # Ensure greenlet constraint is present if SQLAlchemy or asyncpg is declared without explicit greenlet pin
    has_async_sql = any(re.match(r"^(sqlalchemy|asyncpg)\b", l.strip(), re.IGNORECASE) for l in lines if not l.strip().startswith("#"))
    has_greenlet = any(re.match(r"^greenlet\b", l.strip(), re.IGNORECASE) for l in harmonized_lines if not l.strip().startswith("#"))
    if has_async_sql and not has_greenlet:
        greenlet_constraint = bom_overrides.get("greenlet", ">=3.1.1,<4.0.0").strip()
        if not any(greenlet_constraint.startswith(op) for op in ["==", ">=", "<=", ">", "<", "~=", "!="]):
            greenlet_constraint = f"=={greenlet_constraint}"
        harmonized_lines.append(f"greenlet{greenlet_constraint}  # enforced by Platform BOM for SQLAlchemy asyncio / asyncpg compatibility")

    return "\n".join(harmonized_lines) + ("\n" if req_content.endswith("\n") else "")


# FD-4AE (FD23-05/14): the build-time app-code injectors that lived here were DELETED. They rewrote application
# code after the QA gate had certified it, so QA never saw what shipped: `inject_castor_runtime_compat` (Starlette
# TemplateResponse monkey-patch prepended above `from __future__` -> SyntaxError), `inject_castor_schema_bootstrap`
# (`create_all` try/except in `lifespan` calling an undefined `logger` -> NameError at startup),
# `synthesize_router_aggregator` (overwrote `routers/__init__.py` and rewrote route prefixes at runtime),
# `heal_commented_contract_schemas` + `ensure_pydantic_orm_compatibility` (un-commented code, injected imports,
# shadowed pydantic.BaseModel) and `sanitize_sqlalchemy_model_synonyms` (regex rename of mapped columns).
# Owners now: Starlette signature = Platform BOM pin (`sanitize_wheel_requirements`, starlette <1.0); tables =
# the app's migrations (pre-QA V3c-migration, CONTAINER.MIGRATION_NOT_INVOKED); routers/schemas/models = the
# developer contract, checked before QA. Nothing in the deploy path may change application code after QA.


def default_procfile_text(has_alembic: bool) -> str:
    """The Procfile written ONLY when a service has none (an authored Procfile is never rewritten, FD-4AE).
    With Alembic present the migration runs first and a failed migration fails the container start: no `|| true`."""
    migrate = "alembic upgrade head && " if has_alembic else ""
    return f"web: {migrate}uvicorn main:app --host 0.0.0.0 --port ${{PORT:-8080}}\n"


# Typed build failure: a Python service reached the post-QA build with no Procfile and no main.py, so the default
# `uvicorn main:app` could not start. Replaces the hello-world `main.py` the build used to write (FD-4AE, FD23-14a).
BUILD_ENTRYPOINT_MISSING = "BUILD.ENTRYPOINT_MISSING"
# deploy_workload error_class for app-contract build failures (RT F3): not IAC_DEFECT / "", so the workflow never
# sends it to Terraform remediation (it ends as DEPLOY_FAILED with this error text).
BUILD_CONTRACT_ERROR_CLASS = "BUILD_CONTRACT"


# FD55-W6b + W6c (registers FD55-W6b+W6d / FD55-W6c): the service imports nothing from hcl_utils any more.
# validate_hcl_syntax_tree, self_correct_hcl_syntax (A27) and auto_wire_network_graph_dependencies (A29) were
# deleted with prepare_workspace's calls (W6b); the locals pair extract_declared_locals /
# sanitize_hcl_locals_invariants (HA-17) with the validate-error / apply-error heals A44 / A48 (W6c).


# FD55-W6a (A7, HB-43): sanitize_github_workflow / _deduplicate_env_block DELETED. They rewrote workflow YAML in the
# deploy workspace only (never committed, never read by OpenTofu); prepare_workspace now validates the committed
# workflow text as-is.

# HB-42 `sanitize_python_paths` DELETED (FD-4AD): prepare_workspace ran it on every `.py` AFTER QA. It regex-rewrote
# `apps/<svc>/static|templates` literals and `os.path.join("apps", ...)` calls, renamed `exceptions.is_transient_error`
# (the HC-16 twin) and PREPENDED `from google.api_core.retry import if_transient_error` (a SyntaxError above
# `from __future__`). The deployed `.py` files are now the bytes QA tested.


# FD55-W6c (A42 / A46, register FD55-W6c): strip_hcl_output, parse_variables_tf_schema, the lane 19
# `_ACCESS_KEY_DEFAULTS` table and HD-14 generate_rfc1123_variable_default DELETED with their only callers (the
# pre-apply tfvars reconciler and the validate-error output purge). No variable value is guessed from its name.


# FD55-W6a (A10 / A41, HB-17 + HB-22 copy): sanitize_gcp_naming_invariants / sanitize_secret_manager_references
# DELETED (names and secret refs are applied as committed).
# FD55-W6a (A22, HB-19 copy): inject_cloud_run_timeouts DELETED.


# FD55-W6e (A35, HB-20 / HB-21 / HA-18 copies): inject_subnet_lifecycle_ignore_changes,
# inject_kubernetes_deployment_timeouts and inject_gke_workload_identity_bindings DELETED with their only caller (the
# deploy's GKE "Guardrail 4").


# FD55-W6c (A47, HB-18 copy): sanitize_self_referential_hcl_blocks DELETED with its only caller (the apply-error
# loop). A self-referential block is an apply error that reaches the developer.


_GOLDEN_MODULE_NAMES: Optional[Tuple[Tuple[str, ...], ...]] = None


def golden_module_names() -> Tuple[Tuple[str, ...], ...]:
    """Path segments of every platform golden module (exact keys of the builtin module payload, e.g.
    ("workload-foundation", "base")). Loaded once; an unavailable payload yields no names (nothing is exempted)."""
    global _GOLDEN_MODULE_NAMES
    if _GOLDEN_MODULE_NAMES is None:
        try:
            from shared.builtin_modules_payload import BUILTIN_MODULE_FILES
        except ImportError:
            try:
                from builtin_modules_payload import BUILTIN_MODULE_FILES
            except ImportError:
                BUILTIN_MODULE_FILES = {}
        _GOLDEN_MODULE_NAMES = tuple(sorted(tuple(name.split("/")) for name in BUILTIN_MODULE_FILES))
    return _GOLDEN_MODULE_NAMES


def is_golden_module_file(rel_path: str) -> bool:
    """True iff rel_path (workspace-relative, posix) is a file inside a vendored golden module directory:
    infra/modules/<name>/... or modules/<name>/... for an exact golden module name (path-segment comparison)."""
    parts = tuple(p for p in rel_path.replace(os.sep, "/").split("/") if p not in ("", "."))
    for root in (("infra", "modules"), ("modules",)):
        if parts[:len(root)] != root:
            continue
        rest = parts[len(root):]
        for name in golden_module_names():
            if rest[:len(name)] == name and len(rest) > len(name):
                return True
    return False


def _builtin_module_files() -> Dict[str, Dict[str, str]]:
    """The platform's golden-module payload {"<module>": {"<file>": text}} ({} when the payload is unavailable)."""
    try:
        from shared.builtin_modules_payload import BUILTIN_MODULE_FILES
    except ImportError:
        try:
            from builtin_modules_payload import BUILTIN_MODULE_FILES
        except ImportError:
            BUILTIN_MODULE_FILES = {}
    return BUILTIN_MODULE_FILES


def _module_content_hash_fn():
    """The Control Center's module comparison rule, ``iac_upgrade_engine.calculate_module_content_hash`` (the IaC drift
    inspection that clears ``iac_drift_detected``), or None when that shared module is unavailable."""
    try:
        from shared.iac_upgrade_engine import calculate_module_content_hash
    except ImportError:
        try:
            from iac_upgrade_engine import calculate_module_content_hash
        except ImportError:
            return None
    return calculate_module_content_hash


def stale_vendored_module_files(workspace_dir: str) -> Dict[str, List[str]]:
    """FD55-W6d (HS-42, register FD55-W6b+W6d): report only, never writes. For every vendored golden-module directory
    in the workspace (``infra/modules/<name>`` or ``modules/<name>``, the same directory once when one is a symlink of
    the other), the workspace-relative paths of the payload files whose committed text differs from the platform's
    payload (a missing file counts as empty text, as the deleted refresh compared it). {module name: [paths]};
    empty when every vendored module matches or no payload (or no comparison rule) is available.

    "Differs" is the Control Center's rule (W6bd review F2): each file is compared through
    ``calculate_module_content_hash`` (``.tf`` only, CRLF -> LF, trailing whitespace per line and leading / trailing
    blank lines ignored), so a whitespace-only difference the CC inspection would clear is never raised here.

    Before W6d the deploy overwrote such files with the payload and committed them to the deploy branch (A30 HA-31 +
    A31). Now the committed module is applied as committed; the workload shows "IaC outdated" in Control Center and
    the fix is the Upgrade IaC pull request (review + QA like any other change)."""
    stale: Dict[str, List[str]] = {}
    seen_dirs: Set[str] = set()
    content_hash = _module_content_hash_fn()
    if content_hash is None:
        logger.warning("stale vendored module check skipped: iac_upgrade_engine (the Control Center comparison rule) "
                       "is unavailable")
        return stale
    for mod_name, mod_files in sorted(_builtin_module_files().items()):
        for mod_root in ("infra/modules", "modules"):
            target_mod_dir = os.path.join(workspace_dir, mod_root, mod_name)
            if not os.path.isdir(target_mod_dir):
                continue
            real_dir = os.path.realpath(target_mod_dir)
            if real_dir in seen_dirs:
                continue   # `modules` is the workspace's symlink of `infra/modules`: one directory, one report
            seen_dirs.add(real_dir)
            for fname, canonical_content in sorted(mod_files.items()):
                target_file = os.path.join(target_mod_dir, fname)
                current_content = ""
                if os.path.exists(target_file):
                    try:
                        with open(target_file, "r", encoding="utf-8") as f_curr:
                            current_content = f_curr.read()
                    except Exception:
                        pass
                if content_hash({fname: current_content}) != content_hash({fname: canonical_content}):
                    stale.setdefault(mod_name, []).append(os.path.relpath(target_file, workspace_dir))
    return stale


# FD55-W6c (A46, HC-08 / HB-10): strip_invalid_hcl_blocks DELETED with its last caller (the validate-error output
# purge; the prepare_workspace call went with FD55-W6a A14).


def is_cloud_capacity_stockout(err_text: str) -> bool:
    """
    Returns True if an error message indicates an external cloud provider
    capacity deficit, regional stockout, or resource pool exhaustion.
    """
    if not err_text:
        return False
    patterns = [
        r"GCE_STOCKOUT",
        r"ZONE_RESOURCE_POOL_EXHAUSTED",
        r"does not have enough resources available",
        r"Try a different location, or try again later",
        r"RESOURCE_EXHAUSTED",
        r"is currently overloaded",
        r"temporarily unavailable in this zone",
    ]
    return any(re.search(p, str(err_text), re.IGNORECASE) for p in patterns)


def is_subnet_cidr_conflict(apply_err: Optional[str]) -> bool:
    """RT14-01: the exact condition the deleted subnet REST delete ran under (the provider's `Invalid IPCidrRange ...
    conflicts with existing subnetwork` error), now only naming the failure SUBNET_CIDR_CONFLICT. No name is parsed."""
    text = apply_err or ""
    return "Invalid IPCidrRange" in text and "conflicts with existing subnetwork" in text


def mask_sensitive_outputs(raw_outputs: Mapping[str, Any]) -> Dict[str, Any]:
    """RT14-09: `tofu output -json` with the value of every output the engine marks `"sensitive": true` replaced by
    plan_redaction.SENSITIVE_PLACEHOLDER (the engine's typed flag only; never a name or value pattern, invariant 2).
    Every other output is returned unchanged (Do No Harm). Pure: the input is not changed."""
    masked: Dict[str, Any] = {}
    for name, entry in (raw_outputs or {}).items():
        if isinstance(entry, dict) and entry.get("sensitive") is True and "value" in entry:
            entry = dict(entry, value=plan_redaction.mask_marked(entry["value"], True))
        masked[name] = entry
    return masked


def decode_repo_blob(raw: bytes) -> Union[str, bytes]:
    """RT14-21: a repository blob as the deploy carries it. Valid UTF-8 is the same `str` the old
    `decode("utf-8", errors="ignore")` gave (Do No Harm); anything else stays the exact `bytes` (fonts, images, pdf,
    sqlite...), never silently altered. The workspace writes bytes with "wb" (prepare_workspace `binary_files`)."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return bytes(raw)


def add_serverless_git_binaries(reader: Any, repo_identifier: str, branch: str,
                                tree: Dict[str, Any]) -> Dict[str, Any]:
    """RT14-21: the Serverless Git tree endpoint returns text only (it drops binary extensions and replaces invalid
    UTF-8), so the deploy read adds the exact bytes of every other blob from the same branch's archive
    (`export_archive_with_sha`, one commit). A tree text that differs from the archive, a tree path the archive does not
    have (the branch moved between the two reads) or an archive that cannot be read is IncompleteRepoTreeError (the
    deploy's typed REPO_TREE_INCOMPLETE), never a silent partial build. Returns a new dict: the tree's entries
    unchanged plus the binary members as bytes."""
    import io
    import tarfile

    def _incomplete(why: str) -> "IncompleteRepoTreeError":
        return IncompleteRepoTreeError(repo_identifier, branch, {"complete": False, "truncated": False,
                                                                 "error": f"RT14-21 archive check: {why}"[:300]})
    try:
        _sha, archive = reader.export_archive_with_sha(repo_identifier, branch=branch)
        members: Dict[str, bytes] = {}
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            for m in tar.getmembers():
                if m.isfile():
                    fh = tar.extractfile(m)
                    members[m.name] = fh.read() if fh is not None else b""
    except IncompleteRepoTreeError:
        raise
    except Exception as e:  # noqa: BLE001 - typed: the binary files could not be read
        raise _incomplete(f"the branch archive could not be read ({type(e).__name__})") from None
    out: Dict[str, Any] = dict(tree)
    for path, text in tree.items():
        raw = members.get(path)
        if raw is None:
            raise _incomplete(f"{path!r} is in the tree but not in the archive")
        blob = decode_repo_blob(raw)
        if isinstance(blob, bytes):
            out[path] = blob             # the tree's text was a lossy decode: the exact bytes replace it
        elif blob != text:
            raise _incomplete(f"{path!r} differs between the tree and the archive")
    for path, raw in members.items():
        if path not in out:
            out[path] = bytes(raw)       # dropped by the tree (binary extension): exact bytes
    return out


# FEATURE-REQUEST-CLOSE-OWN-ONLY: the statuses of a feature request a run is building (the gateway's end-of-run uses the
# same two for a run with no recorded id). A filed request stays PENDING_TRIAGE until a relaunch starts it.
FEATURE_REQUEST_IN_BUILD_STATUSES = ("IN_PROGRESS", "IN_DEVELOPMENT")


def _run_built_feature_request(fr_id: str, fr_data: Mapping[str, Any], recorded_request_id: Optional[str],
                               trace_id: str) -> bool:
    """Whether the run `trace_id` built this feature request of its workload. With a recorded id it built exactly that
    one. A run with none (Express, initial builds until they record theirs, other channels, runs from before the
    record): a request in a build status not started by another run. An initial request is IN_PROGRESS from its creation
    with no trace yet; Express has no other close, and the sandbox sweep treats an IN_PROGRESS request as a build in
    flight. A relaunched request carries its own run's `trace_id`, and a filed one is not in a build status."""
    if recorded_request_id:
        return fr_id == recorded_request_id
    return (fr_data.get("status") in FEATURE_REQUEST_IN_BUILD_STATUSES
            and fr_data.get("trace_id") in (None, "", trace_id))


# RT14-22: the deploy engine is run only after its release zip matched an owner-verified checksum.
ENGINE_UNVERIFIABLE = "ENGINE_UNVERIFIABLE"   # = validate_service.ENGINE_UNVERIFIABLE
ENGINE_STAGE = "engine"
ENGINE_FETCH_TIMEOUT_S = 60.0          # RT14 RT F2: per socket operation of the engine release zip download
ENGINE_ZIP_MAX_BYTES = 200 << 20       # RT14 RT F2: release zips are ~20-30 MB; a larger body is refused


class EngineUnverifiable(RuntimeError):
    """RT14-22: typed refusal to run an unverified IaC engine (class ENGINE_UNVERIFIABLE, stage `engine`)."""
    error_class = ENGINE_UNVERIFIABLE
    stage = ENGINE_STAGE

    def __init__(self, detail: str):
        super().__init__(f"{ENGINE_UNVERIFIABLE} ({ENGINE_STAGE}): {detail}")
        self.detail = detail

    def result(self) -> Dict[str, Any]:
        return {"success": False, "exit_code": 1, "stdout": "", "stderr": str(self),
                "error_class": ENGINE_UNVERIFIABLE, "stage": ENGINE_STAGE}


def engine_os_arch() -> str:
    """`<os>_<arch>` of this host as the release zips name it (= validate_service.host_os_arch)."""
    import platform
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine, machine)
    return f"{platform.system().lower()}_{arch}"


def _binary_checksums_module():
    try:
        import binary_checksums as bc  # sibling module (validate_service imports it the same way)
    except ImportError:  # service.py loaded by file path (tests, tooling): same file, no sys.path change
        import importlib.util
        import sys as _bc_sys
        _spec = importlib.util.spec_from_file_location(
            "binary_checksums", os.path.join(os.path.dirname(os.path.abspath(__file__)), "binary_checksums.py"))
        bc = importlib.util.module_from_spec(_spec)
        _spec.loader.exec_module(bc)
        _bc_sys.modules["binary_checksums"] = bc
    return bc


def _is_serverless_git_reader(vcs: Any) -> bool:
    """RT14-21: the Shared read's provider is the Serverless Git reader (exact class, not a name check)."""
    try:
        from shared.providers.serverless_git_provider import ServerlessGitProvider
    except ImportError:  # pragma: no cover - the provider package is part of this image
        return False
    return isinstance(vcs, ServerlessGitProvider)


class TerraformService:
    def __init__(
        self,
        project_id: Optional[str] = None,
        state_bucket: Optional[str] = None,
        workspace_base_dir: str = "/tmp/castor_tf_workspaces",
        firestore_client: Optional[Any] = None,
        db: Optional[Any] = None,
    ):
        self.project_id = project_id or os.getenv("PROJECT_ID", "")
        self.state_bucket = state_bucket or os.getenv("TFSTATE_BUCKET", "")
        self.workspace_base_dir = workspace_base_dir
        # FD-4CI-b: None = resolved per use (see the lock_timeout / stale_lock_max_age_min properties)
        self._lock_timeout_override = None
        self._stale_lock_max_age_override = None
        self._orchestration_setting_cache = {}
        # FD-4AQ W3 (AQ-5): the server's cap; applier.py switches its instance to TOFU_TIME_LIMITS_JOB.
        self.tofu_time_limits = TOFU_TIME_LIMITS_SERVICE

        client = db if db is not None else firestore_client
        if client:
            self.db = client
        else:
            try:
                self.db = firestore.Client(project=self.project_id) if self.project_id else None
            except Exception as e:
                logger.warning(f"Could not initialize Firestore client: {e}")
                self.db = None

        os.makedirs(self.workspace_base_dir, exist_ok=True)
        # FD-4G: per-trace workspaces live directly under workspace_root. Tool-owned state (tofu/terraform
        # binaries, provider mirror, plugin cache, terraform.rc) lives under a dot-prefixed dir that no valid
        # trace_id can name (validate_trace_id requires an alphanumeric first character).
        self.workspace_root = self.workspace_base_dir
        self.tooling_dir = os.path.join(self.workspace_base_dir, ".castor-tooling")
        os.makedirs(self.tooling_dir, exist_ok=True)

    def _workspace_dir(self, trace_id: str, product_id: str) -> str:
        """Validated <workspace_root>/<trace_id>/<product_id>. Raises UnsafePathError.

        no_symlinks=True: a workspace dir is never legitimately a symlink. This rejects product IDs that
        collide with platform-made links such as <trace>/modules -> <other product>/infra/modules (FD-4G H3).
        """
        validate_trace_id(trace_id)
        validate_path_component(product_id)
        return safe_join(self.workspace_root, trace_id, product_id, no_symlinks=True)

    def workspace_trace_dir(self, trace_id: str) -> str:
        """Validated <workspace_root>/<trace_id> (used for per-trace cleanup). Raises UnsafePathError."""
        validate_trace_id(trace_id)
        return safe_join(self.workspace_root, trace_id, no_symlinks=True)

    @staticmethod
    def _normalize_engine(engine: Optional[str]) -> str:
        """Normalizes user/agent engine string to 'tofu' or 'terraform'."""
        clean = (engine or "tofu").strip().lower()
        if clean in ("tofu", "opentofu"):
            return "tofu"
        if clean in ("terraform", "tf"):
            return "terraform"
        return "tofu"

    # SAT-01 (FD4BD-Q2): the exact-text "Guardrail 2" rewriter `_rewrite_bundle_and_module_paths` is DELETED (it had
    # no production caller). Module sources are re-anchored only by rewrite_flattened_module_sources (parse tree,
    # infra/workload/** and legacy infra/workloads/**); infra/bundles/** and vendored infra/modules/** reach the
    # workspace exactly as committed. tests/test_sat01_deploy_tfvars.py pins both.

    def _read_tofu_outputs(self, workspace_dir: str, active_engine: Optional[str]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
        """RT14-09: the ONLY `output -json` reader (AST guard). Returns (masked, raw): `masked` (mask_sensitive_outputs)
        is what may be stored in Firestore, returned or sent in a callback; `raw` stays in the caller's memory for
        reads such as the service URL or the GKE cluster name. Unreadable output is ({}, {}) as before."""
        out_res = self._run_subprocess(["terraform", "output", "-json"], cwd=workspace_dir, iac_engine=active_engine)
        stdout = (out_res or {}).get("stdout") or ""
        if not stdout.strip().startswith("{"):
            return {}, {}
        try:
            raw = json.loads(stdout)
        except ValueError:
            return {}, {}
        if not isinstance(raw, dict):
            return {}, {}
        return mask_sensitive_outputs(raw), raw

    def detect_errored_child_stubs(self, child_project: str, region: Optional[str] = None) -> Dict[str, Any]:
        """RT14-01 (FD-4Q / lane 18 S3): READ-ONLY listing of the child project's dead stubs, for an operator.

        Replaces `purge_errored_child_stubs`, which REST-deleted every ERROR GKE cluster in every region (a
        cross-region secondary too: invariant 5), ran a hardcoded `state rm module.compute.google_container_cluster.
        autopilot` / `google_vpc_access_connector.connector` (orphaning whatever really sat at those addresses) and
        ran on every deploy and on any stockout-looking error, outside every plan / destroy / approval gate. This
        method only GETs: never a DELETE, never a state command. Clean-up is the manual runbook
        `docs/runbooks/stub-cleanup.md` (the HITL path; vending has no CHILD_RESOURCE_DELETE executor yet).

        Returns {"connectors": [...], "clusters": [...], "errors": [...]}: Serverless VPC Access connectors in ERROR /
        FAILED in the workload region, and GKE clusters in ERROR in the project, each with `in_workload_region` (a
        cluster in another region is listed for visibility only). A listing that could not be read is named in
        `errors` (typed: class + cause), never reported as "no stubs"."""
        found: Dict[str, Any] = {"connectors": [], "clusters": [], "errors": []}
        if not child_project or child_project == self.project_id:
            found["errors"].append(f"{STUB_DETECTION_REFUSED}: no child project, or the host project")
            return found
        try:
            workload_region: Optional[str] = region or self._resolve_region()
        except RegionUnavailable as region_err:
            workload_region = None
            found["errors"].append(f"{REGION_UNAVAILABLE}: {region_err}")
        try:
            from google.auth.transport.requests import AuthorizedSession

            auth_res = self._child_credentials(child_project)   # FD4BD-Q3: quota project = the child, per call
            creds = auth_res[0] if isinstance(auth_res, (list, tuple)) and len(auth_res) >= 1 else auth_res
            session = AuthorizedSession(creds)
        except Exception as e:  # noqa: BLE001 - typed in the listing, never "no stubs"
            found["errors"].append(f"{STUB_DETECTION_UNREADABLE}: no Google session ({type(e).__name__})")
            return found

        def _listed(url: str, key: str, what: str) -> List[Dict[str, Any]]:
            try:
                resp = session.get(url, timeout=15)
            except Exception as e:  # noqa: BLE001 - typed in the listing
                found["errors"].append(f"{STUB_DETECTION_UNREADABLE}: {what}: {type(e).__name__}")
                return []
            if resp.status_code != 200:
                found["errors"].append(f"{STUB_DETECTION_UNREADABLE}: {what}: HTTP {resp.status_code}")
                return []
            items = (resp.json() or {}).get(key) or []
            return [i for i in items if isinstance(i, dict)]

        if workload_region:
            for conn in _listed(f"https://vpcaccess.googleapis.com/v1/projects/{child_project}/locations/"
                                f"{workload_region}/connectors", "connectors", "VPC Access connectors"):
                if conn.get("state") in ("ERROR", "FAILED"):
                    found["connectors"].append({"name": conn.get("name"), "state": conn.get("state"),
                                                "in_workload_region": True})
        for cl in _listed(f"https://container.googleapis.com/v1/projects/{child_project}/locations/-/clusters",
                          "clusters", "GKE clusters"):
            if cl.get("status") == "ERROR":
                found["clusters"].append({"name": cl.get("name"), "location": cl.get("location"), "status": "ERROR",
                                          "in_workload_region": bool(workload_region)
                                          and cl.get("location") == workload_region})
        return found

    def _ensure_binary(self, engine: str = "TERRAFORM", version: Optional[str] = None) -> str:
        """
        RT14-22: the requested IaC engine (terraform or tofu), downloaded and verified against binary_checksums.py
        before it is unpacked (cached for this process by path + stat signature). Raises EngineUnverifiable
        (ENGINE_UNVERIFIABLE) when no pinned checksum exists or the download / verification fails; never a PATH binary.
        """
        clean_engine = (engine or "TERRAFORM").strip().upper()
        is_tofu = clean_engine in ("OPENTOFU", "TOFU")
        bin_cmd = "tofu" if is_tofu else "terraform"

        # Resolve version from argument, environment, or settings
        target_version = version or os.getenv("TERRAFORM_VERSION" if not is_tofu else "OPENTOFU_VERSION")
        if not target_version:
            try:
                from shared.settings import get_platform_settings
                ps = get_platform_settings()
                target_version = getattr(ps.orchestration, "tofu_version", "1.9.0") if is_tofu else getattr(ps.orchestration, "terraform_version", "1.5.7")
            except Exception:
                target_version = "1.9.0" if is_tofu else "1.5.7"

        # Enforce strict Terraform 1.5.7 open-source ceiling (MPL-2.0 only, no BSL). FD-4CI-b RT F4: one version
        # parse, shared with the Settings save check (shared.settings.terraform_version_accepted).
        if not is_tofu:
            from shared.settings import terraform_version_accepted
            if not terraform_version_accepted(target_version):
                raise ValueError(
                    f"Terraform >= 1.6.0 is strictly forbidden to eliminate BSL contamination. "
                    f"Only Terraform v1.5.7 or OpenTofu v1.9.0 is supported (requested: {target_version!r})."
                )

        # RT14-22 (D12 / HS-52 "apply path in Step 2"): the engine that runs plan, apply, import and every state command
        # with the deployer's credentials is ONLY a release zip verified against an owner-fetched checksum
        # (binary_checksums.py, the same table `/validate` uses), verified BEFORE it is unpacked. A binary found on
        # PATH is never used (it cannot be verified), and a download or checksum failure is never answered with the
        # bare command name. No pinned row (e.g. Terraform 1.5.7 today, or another Settings version) is the typed
        # ENGINE_UNVERIFIABLE (stage `engine`).
        engine_key = "opentofu" if is_tofu else "terraform"
        # one verification per engine at a time (concurrent deploys in this process share the cache)
        with self.__dict__.setdefault("_engine_lock", threading.Lock()):
            verified = self.__dict__.setdefault("_verified_engines", {})
            record = verified.get((engine_key, target_version))
            if record is not None:
                path, sig = record
                try:
                    st = os.stat(path)
                    if (st.st_ino, st.st_size, st.st_mtime_ns) == sig:
                        return path
                except OSError:
                    pass
                verified.pop((engine_key, target_version), None)

            bc = _binary_checksums_module()
            os_arch = engine_os_arch()
            want = bc.expected_sha256(engine_key, target_version, os_arch)
            if not want:
                raise EngineUnverifiable(
                    f"no owner-verified checksum for {engine_key} {target_version} {os_arch} (binary_checksums.py, D12); "
                    f"the deploy engine is never run unverified")

            import hashlib
            import zipfile

            bin_dir = os.path.join(self.tooling_dir, "bin")
            os.makedirs(bin_dir, exist_ok=True)
            cached_bin = os.path.join(bin_dir, f"{bin_cmd}_{target_version}")
            zip_path = os.path.join(bin_dir, f"{bin_cmd}_{target_version}_{os_arch}.zip")
            if is_tofu:
                url = (f"https://github.com/opentofu/opentofu/releases/download/v{target_version}/"
                       f"tofu_{target_version}_{os_arch}.zip")
            else:
                url = (f"https://releases.hashicorp.com/terraform/{target_version}/"
                       f"terraform_{target_version}_{os_arch}.zip")
            logger.info(f"Downloading {bin_cmd} v{target_version} ({os_arch}) and verifying its release checksum...")
            try:
                # RT14 RT F2: this runs under _engine_lock, so a stalled download must not hold it forever: the
                # FD-4BQ fetch primitive (timeout per socket operation, size cap while streaming, https-only
                # redirects). A timeout or an oversize body is typed below (ENGINE_UNVERIFIABLE) and frees the lock.
                with open(zip_path, "wb") as zip_out:
                    bc.fetch_to(url, zip_out, ENGINE_ZIP_MAX_BYTES, timeout=ENGINE_FETCH_TIMEOUT_S)
                digest = hashlib.sha256()
                with open(zip_path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        digest.update(chunk)
                if digest.hexdigest() != want:
                    raise EngineUnverifiable(f"{engine_key} {target_version} release zip sha256 {digest.hexdigest()} "
                                             f"!= owner-verified {want}")
                with zipfile.ZipFile(zip_path) as zf:
                    if bin_cmd not in zf.namelist():
                        raise EngineUnverifiable(f"{engine_key} {target_version} release zip has no {bin_cmd!r} member")
                    data = zf.read(bin_cmd)
                # dot-prefixed: hcl_utils.find_hcl_parser_binary never picks up a half-written `tofu_*` file
                tmp_bin = os.path.join(bin_dir, f".{bin_cmd}_{target_version}.partial")
                with open(tmp_bin, "wb") as fh:
                    fh.write(data)
                os.chmod(tmp_bin, 0o755)
                os.replace(tmp_bin, cached_bin)
                st = os.stat(cached_bin)
                verified[(engine_key, target_version)] = (cached_bin, (st.st_ino, st.st_size, st.st_mtime_ns))
                logger.info(f"Installed verified {bin_cmd} v{target_version} at {cached_bin}")
                return cached_bin
            except EngineUnverifiable:
                raise
            except Exception as e:  # noqa: BLE001 - typed: never the bare name, never a PATH binary
                raise EngineUnverifiable(f"{engine_key} {target_version} download/verify failed: "
                                         f"{type(e).__name__}: {e}"[:400]) from None
            finally:
                if os.path.exists(zip_path):
                    os.remove(zip_path)

    def _ensure_terraform_binary(self) -> str:
        """Legacy helper for backward compatibility."""
        return self._ensure_binary("TERRAFORM")

    def _validate_no_engine_downgrade(self, product_id: str, requested_engine: str) -> None:
        """
        Guardrail 1: Enforces one-way state migration from Terraform 1.5.7 -> OpenTofu 1.9.0.
        Once an OpenTofu state is generated, downgrading to Terraform 1.5.7 is strictly blocked.
        """
        clean_req = (requested_engine or "").strip().upper()
        if clean_req not in ("TERRAFORM", "TF"):
            return  # Target is OpenTofu, allowed

        if not self.db or not product_id:
            return

        try:
            doc = self.db.collection("workloads").document(product_id).get()
            if doc.exists:
                wdata = doc.to_dict() or {}
                last_applied = (wdata.get("applied_iac_engine") or wdata.get("last_applied_engine") or "").strip().upper()
                if last_applied in ("OPENTOFU", "TOFU"):
                    raise IaCEngineDowngradeBlockedError(
                        f"Guardrail 1 Violation: Workload '{product_id}' was previously deployed using OpenTofu v1.9.0 "
                        f"and cannot be downgraded to Terraform v1.5.7 to prevent state schema corruption."
                    )
        except IaCEngineDowngradeBlockedError:
            raise
        except Exception as e:
            logger.debug(f"Could not verify engine downgrade status: {e}")

    def _ensure_provider_mirror(self) -> str:
        """
        Writes the platform CLI config and pre-caches the verified provider mirror (both registry hosts).
        FD-4AQ W1b (AQ-X1a): the CLI config (provider_allowlist.cli_config) lets OpenTofu install exactly the
        platform's providers (google, google-beta, kubernetes, random on either registry host) from this mirror or
        the official registry; any other provider fails `init`.
        """
        mirror_dir = os.path.join(self.tooling_dir, "plugin_mirror")
        rc_path = os.path.join(self.tooling_dir, "terraform.rc")

        # FD-4G: the CLI config is compared for EXACT content on every call (any tampering is reverted before
        # the next tofu run) and replaced atomically as a read-only file. Write failures raise: running tofu
        # without this config would fall back to implied local mirrors (e.g. terraform.d/plugins in the cwd).
        rc_content = provider_allowlist.cli_config(mirror_dir)
        with _RC_WRITE_LOCK:
            current = None
            if os.path.exists(rc_path):
                with open(rc_path, "r") as f:
                    current = f.read()
            if current != rc_content:
                fd, tmp_rc = tempfile.mkstemp(prefix="terraform.rc.", suffix=".tmp", dir=self.tooling_dir)
                try:
                    with os.fdopen(fd, "w") as f:
                        f.write(rc_content)
                    os.chmod(tmp_rc, 0o444)
                    os.replace(tmp_rc, rc_path)
                except BaseException:
                    if os.path.lexists(tmp_rc):
                        os.remove(tmp_rc)
                    raise

        import platform
        import sys

        try:
            import binary_checksums as bc  # sibling module (validate_service imports it the same way)
        except ImportError:  # service.py loaded by file path (tests, tooling): same file, no sys.path change
            import importlib.util
            _spec = importlib.util.spec_from_file_location(
                "binary_checksums", os.path.join(os.path.dirname(os.path.abspath(__file__)), "binary_checksums.py"))
            bc = importlib.util.module_from_spec(_spec)
            _spec.loader.exec_module(bc)
            sys.modules["binary_checksums"] = bc

        # PROVIDER-CHECKSUMS (owner 10-28): a zip that failed verification, or has no pinned row, is not re-downloaded
        # on every tofu call (sticky for this process); a failed download is retried after 5 minutes. Each such
        # provider is left out of the mirror (plan/apply then use OpenTofu's own verified `direct {}` install) and is
        # listed by provider_mirror_gaps() for /validate/ready. `verified` binds every mirror file this process
        # installed to its verified sha256 (binary_checksums.record_provider_files); files without a record are
        # never used.
        rejected = self.__dict__.setdefault("_provider_zip_rejected", set())
        unavailable = self.__dict__.setdefault("_provider_zip_unavailable_until", {})
        verified = self.__dict__.setdefault("_provider_bins_verified", {})
        gaps = self.__dict__.setdefault("_provider_mirror_gaps", {})

        arch = "amd64"
        machine = platform.machine().lower()
        if "arm" in machine or "aarch64" in machine:
            arch = "arm64"

        # Pre-cache key provider versions for BOTH Terraform and OpenTofu registries
        target_registries = ["registry.terraform.io", "registry.opentofu.org"]
        target_providers_map = provider_allowlist.MIRROR_PROVIDER_VERSIONS

        with _MIRROR_LOCK:
            for reg in target_registries:
                for provider_name, versions in target_providers_map.items():
                    # The mirror path and each included provider's type dir always exist (they hold no package by
                    # themselves; only <version>/<os_arch> dirs do, and those exist only for verified installs).
                    try:
                        os.makedirs(os.path.join(mirror_dir, reg, "hashicorp", provider_name), exist_ok=True)
                    except OSError as mk_err:
                        logger.warning(f"Could not create the mirror dir for {provider_name} ({mk_err})")
                    for version in versions:
                        key = (provider_name, version, arch)
                        provider_dest_dir = os.path.join(
                            mirror_dir, reg, "hashicorp", provider_name, version, f"linux_{arch}"
                        )
                        try:
                            if bc.cached_provider_ok(provider_dest_dir, provider_name, verified.get(provider_dest_dir)):
                                continue
                            # Not (or no longer) the verified bytes this process installed: never left in place.
                            verified.pop(provider_dest_dir, None)
                            stale = bc.remove_provider_dir(provider_dest_dir, provider_name)
                            if stale:
                                logger.warning(f"Removed unverified provider files {stale} from {provider_dest_dir}")

                            # Check if already cached under another registry to avoid duplicate download
                            cached_source = os.path.join(
                                mirror_dir, "registry.terraform.io", "hashicorp", provider_name, version, f"linux_{arch}"
                            )
                            if cached_source != provider_dest_dir and bc.cached_provider_ok(
                                    cached_source, provider_name, verified.get(cached_source)):
                                try:
                                    os.makedirs(provider_dest_dir, exist_ok=True)
                                    copied = bc.copy_verified_provider(cached_source, provider_dest_dir,
                                                                       verified[cached_source])
                                    verified[provider_dest_dir] = bc.record_provider_files(provider_dest_dir, copied)
                                    continue
                                except bc.ProviderChecksumError as copy_bad:
                                    verified.pop(provider_dest_dir, None)
                                    logger.error(f"Provider copy from {cached_source} REJECTED: {copy_bad}")
                                except (OSError, ValueError) as copy_err:
                                    verified.pop(provider_dest_dir, None)
                                    logger.warning(f"Could not copy provider from {cached_source} ({copy_err})")

                            if key in rejected or time.monotonic() < unavailable.get(key, 0.0):
                                continue
                            logger.info(f"Pre-caching provider {reg}/hashicorp/{provider_name} v{version}...")
                            # PROVIDER-CHECKSUMS: only bytes matching the pinned row are installed, atomically.
                            digests: Dict[str, str] = {}
                            try:
                                os.makedirs(provider_dest_dir, exist_ok=True)
                                bc.install_verified_provider(provider_name, version, f"linux_{arch}", provider_dest_dir,
                                                             self.tooling_dir, digests=digests)
                            except bc.ProviderChecksumError as bad:   # mismatch, or no pinned row
                                rejected.add(key)
                                gaps[key] = f"{type(bad).__name__}: {bad}"
                                logger.error(f"Provider zip REJECTED, not mirrored (plan/apply use the registry): {bad}")
                            except (OSError, ValueError) as na:   # download failed / malformed registry answer
                                unavailable[key] = time.monotonic() + 300.0
                                gaps[key] = f"download failed (retry in 5 min): {type(na).__name__}: {na}"
                                logger.warning(f"Provider not mirrored (retry in 5 min): {provider_name} v{version}: {na}")
                            else:
                                try:
                                    verified[provider_dest_dir] = bc.record_provider_files(provider_dest_dir, digests)
                                    gaps.pop(key, None)
                                except (bc.ProviderChecksumError, OSError, ValueError) as rec_err:
                                    # the verified zip was fine; the file changed right after install: retry later
                                    unavailable[key] = time.monotonic() + 300.0
                                    gaps[key] = f"installed file changed (retry in 5 min): {rec_err}"
                                    logger.error(f"Provider file changed after a verified install, not mirrored: {rec_err}")
                        except Exception as dl_err:
                            gaps[key] = f"unexpected: {type(dl_err).__name__}: {dl_err}"
                            logger.warning(f"Could not pre-cache provider {provider_name} v{version} ({dl_err}); init uses the official registry for it.")
                        finally:
                            # RT F1: a provider left out of the mirror leaves no <version>/<os_arch> dir behind; OpenTofu's
                            # filesystem mirror counts even an empty one as an available package, which would block the
                            # `direct {}` registry install of that version.
                            if provider_dest_dir not in verified:
                                try:
                                    bc.remove_provider_dir(provider_dest_dir, provider_name)
                                except Exception as rm_err:  # noqa: BLE001 - the mirror build never fails a tofu run
                                    logger.error(f"Could not remove {provider_dest_dir} ({rm_err})")

        return rc_path

    def provider_mirror_gaps(self) -> List[Dict[str, str]]:
        """PROVIDER-CHECKSUMS: pinned providers the mirror build left out in this process (checksum mismatch, no
        pinned row, failed download), for /validate/ready. [] when nothing was left out (or before the first build)."""
        gaps = dict(self.__dict__.get("_provider_mirror_gaps", {}))
        return [{"provider": p, "version": v, "os_arch": f"linux_{a}", "reason": reason}
                for (p, v, a), reason in sorted(gaps.items())]

    # FD-4BD: {realpath(workspace_dir): {variable name: value}} for running deploys; guarded by the lock below.
    _WORKSPACE_TF_VARS_LOCK = threading.Lock()

    def _register_workspace_tf_vars(self, workspace_dir: str, tf_vars: Dict[str, str]) -> Tuple[str, Dict[str, str]]:
        """FD-4BD: every tofu process this service runs in `workspace_dir` (or below it) gets `tf_vars` as
        TF_VAR_<name> environment variables. Values stay in memory only; deploy_workload forgets them when it ends.
        Returns the registration (key, stored dict) the caller hands back to `_forget_workspace_tf_vars`."""
        key = os.path.realpath(workspace_dir)
        stored = {str(k): "" if v is None else str(v) for k, v in tf_vars.items()}
        with self._WORKSPACE_TF_VARS_LOCK:
            self.__dict__.setdefault("_workspace_tf_vars", {})[key] = stored
        return key, stored

    def _forget_workspace_tf_vars(self, key: str, stored: Dict[str, str]) -> None:
        """RT F2: removes the entry only when it is still THIS registration (identity), so a later deploy of the same
        workspace in this process keeps its own values when an earlier one finishes first."""
        with self._WORKSPACE_TF_VARS_LOCK:
            registry = self.__dict__.get("_workspace_tf_vars", {})
            if registry.get(key) is stored:
                registry.pop(key)

    def _workspace_tf_var_env(self, cwd: Optional[str]) -> Dict[str, str]:
        """FD-4BD: TF_VAR_* for `cwd` when it is (inside) a registered deploy workspace, else {} (path comparison)."""
        if not cwd:
            return {}
        here = os.path.realpath(cwd)
        with self._WORKSPACE_TF_VARS_LOCK:
            registry = dict(self.__dict__.get("_workspace_tf_vars", {}))
        for root, tf_vars in registry.items():
            try:
                inside = os.path.commonpath([root, here]) == root
            except ValueError:
                inside = False
            if inside:
                return {f"TF_VAR_{name}": value for name, value in tf_vars.items()}
        return {}

    # FD4BD-Q3 (owner OQ-5a: first commit of FD-7L Phase 2a): {realpath(workspace_dir): {"project_id": quota project}}
    # for running deploys. It replaces the process-wide GOOGLE_BILLING_PROJECT / GOOGLE_CLOUD_QUOTA_PROJECT /
    # GOOGLE_USER_PROJECT_OVERRIDE environment and the `_active_target_project_id` attribute, with which concurrent
    # deploys in one server process billed whichever child project was set last.
    _WORKSPACE_BILLING_LOCK = threading.Lock()

    def _register_workspace_billing(self, workspace_dir: str, project_id: str) -> Tuple[str, Dict[str, str]]:
        """FD4BD-Q3: every tofu process this service runs in `workspace_dir` (or below it) bills `project_id`
        (GOOGLE_BILLING_PROJECT / GOOGLE_CLOUD_QUOTA_PROJECT / GOOGLE_USER_PROJECT_OVERRIDE in its own env only).
        Returns the registration the caller hands back to `_forget_workspace_billing`."""
        key = os.path.realpath(workspace_dir)
        stored = {"project_id": str(project_id)}
        with self._WORKSPACE_BILLING_LOCK:
            self.__dict__.setdefault("_workspace_billing", {})[key] = stored
        return key, stored

    def _forget_workspace_billing(self, key: str, stored: Dict[str, str]) -> None:
        """Removes the entry only when it is still THIS registration (identity), like `_forget_workspace_tf_vars`."""
        with self._WORKSPACE_BILLING_LOCK:
            registry = self.__dict__.get("_workspace_billing", {})
            if registry.get(key) is stored:
                registry.pop(key)

    @staticmethod
    def _innermost_registration(registry: Dict[str, Any], cwd: Optional[str]) -> Any:
        """The value registered for the innermost root that contains `cwd` (path comparison), else None."""
        if not cwd:
            return None
        here = os.path.realpath(cwd)
        best_root, best = None, None
        for root, value in registry.items():
            try:
                inside = os.path.commonpath([root, here]) == root
            except ValueError:
                inside = False
            if inside and (best_root is None or len(root) > len(best_root)):
                best_root, best = root, value
        return best

    def _workspace_billing_project(self, cwd: Optional[str]) -> Optional[str]:
        """FD4BD-Q3: the quota project registered for `cwd`'s deploy workspace, else None (no override)."""
        with self._WORKSPACE_BILLING_LOCK:
            registry = dict(self.__dict__.get("_workspace_billing", {}))
        stored = self._innermost_registration(registry, cwd)
        return stored.get("project_id") if isinstance(stored, dict) else None

    # FD-7L Phase 2a: {realpath(workspace_dir): runner_credentials.WorkspaceRunner} -- the brokered deployer credentials and
    # the local metadata endpoint of a Per-workload run (registered by tf-applier for its trace folder; memory only).
    _WORKSPACE_RUNNER_LOCK = threading.Lock()
    _process_runner: Any = None   # SAT-27 RT L3: the one brokered runner of this process (class-wide)
    # SAT-37 (SAT-27 RT L4): every live registration of the process runner, by ANY instance: {(id(instance), key)}.
    # The runner is released only when none is left, so one instance forgetting it never frees the process for a
    # different runner while another instance still holds it.
    _process_runner_holders: FrozenSet[Tuple[int, str]] = frozenset()

    def _register_workspace_runner(self, workspace_dir: str, runner: Any) -> Tuple[str, Any]:
        """FD-7L 2a: every tofu process in `workspace_dir` (or below it) runs with `runner`'s deployer credentials
        (GCE_METADATA_HOST = its local endpoint) and every child REST call for its project uses them. Returns the
        registration for `_forget_workspace_runner`."""
        key = os.path.realpath(workspace_dir)
        with self._WORKSPACE_RUNNER_LOCK:
            # SAT-27 RT L3: ONE brokered runner per process. The isolation unit of the local metadata endpoint is the
            # container (any process in it can reach 127.0.0.1), so a second workload's deployer never runs here.
            held = TerraformService._process_runner
            if held is not None and held is not runner:
                raise ri.RunnerIdentityError(runner_creds.RUNNER_NOT_SINGLE_TENANT, "this process already holds another "
                                             "workload's brokered credentials (one tf-applier execution per run)",
                                             stage="runner-target", http_status=409)
            holders = TerraformService._process_runner_holders if held is runner else frozenset()
            TerraformService._process_runner = runner
            TerraformService._process_runner_holders = holders | {(id(self), key)}
            self.__dict__.setdefault("_workspace_runners", {})[key] = runner
        return key, runner

    def _forget_workspace_runner(self, key: str, runner: Any) -> None:
        with self._WORKSPACE_RUNNER_LOCK:
            registry = self.__dict__.get("_workspace_runners", {})
            if registry.get(key) is runner:
                registry.pop(key)
                if TerraformService._process_runner is runner:
                    TerraformService._process_runner_holders = (TerraformService._process_runner_holders
                                                                - {(id(self), key)})
            if TerraformService._process_runner is runner and not TerraformService._process_runner_holders:
                TerraformService._process_runner = None

    def _workspace_runner(self, cwd: Optional[str]) -> Any:
        """FD-7L 2a: the brokered runner registered for `cwd`'s workspace, else None (Shared installs: always None)."""
        with self._WORKSPACE_RUNNER_LOCK:
            registry = dict(self.__dict__.get("_workspace_runners", {}))
        return self._innermost_registration(registry, cwd)

    def _runner_for_project(self, project_id: Optional[str]) -> Any:
        """FD-7L 2a: the brokered runner whose deployer belongs to `project_id`, else None."""
        with self._WORKSPACE_RUNNER_LOCK:
            runners = list(self.__dict__.get("_workspace_runners", {}).values())
        for runner in runners:
            if project_id and runner.project_id == project_id:
                return runner
        return None

    @staticmethod
    def _runner_refusal_result(code: str, message: str, stdout: str = "") -> Dict[str, Any]:
        """A typed tofu-command refusal (FD-7L 2a; operator_required: no developer run changes it)."""
        return {"exit_code": 1, "stdout": stdout, "stderr": f"{code}: {message}", "success": False,
                "error_class": code, "operator_required": True}

    def _runner_subprocess_refusal(self, runner: Any) -> Optional[Dict[str, Any]]:
        """FD-7L 2a: None when this tofu command may run. A Per-workload install never runs tofu without brokered
        credentials registered for its workspace (RUNNER_IDENTITY_NOT_REGISTERED: no fallback to the platform
        identity); an unknown mode value and a broker that already failed for this workspace refuse too."""
        try:
            mode = self._runner_identity_mode()
        except ri.RunnerIdentityError as e:
            return self._runner_refusal_result(e.code, e.detail)
        if runner is None:
            if mode == ri.MODE_PER_WORKLOAD:
                return self._runner_refusal_result(
                    runner_creds.RUNNER_IDENTITY_NOT_REGISTERED,
                    "this install runs workload OpenTofu only with the workload deployer's brokered credentials, and "
                    "none are registered for this workspace (a Per-workload run happens only in a tf-applier "
                    "execution that vending dispatched)")
            return None
        failure = runner.endpoint.failure
        if failure is not None:
            return self._runner_refusal_result(failure.code, failure.detail)
        return None

    def _runner_admission(self, product_id: str, trace_id: str, target_project_id: str) -> Optional[Dict[str, Any]]:
        """FD-7L 2a, once per deploy (before any child call): the mode log line (re-RT R10), then None, or a typed
        refusal: an unknown mode value; a Per-workload install without brokered credentials for this deploy's
        workspace (RUNNER_IDENTITY_NOT_REGISTERED); credentials for another project than the deploy's target
        (RUNNER_TARGET_MISMATCH). Shared installs without a registration: the log line only."""
        try:
            workspace = self._workspace_dir(trace_id, product_id)
        except UnsafePathError:
            workspace = None
        runner = self._workspace_runner(workspace)
        try:
            mode, mode_error = self._runner_identity_mode(), None
        except ri.RunnerIdentityError as e:
            mode, mode_error = None, e
        runner_creds.log_mode(run="deploy", product_id=product_id, trace_id=trace_id, mode=mode,
                              mode_error=mode_error.code if mode_error else None,
                              key_id=getattr(runner, "key_id", None), brokered=runner is not None)
        if mode_error is not None:
            code, message = mode_error.code, mode_error.detail
        else:
            if runner is None and mode != ri.MODE_PER_WORKLOAD:
                return None
            if runner is None:
                code = runner_creds.RUNNER_IDENTITY_NOT_REGISTERED
                message = (f"deploy of '{product_id}' refused: this install deploys only with the workload "
                           "deployer's brokered credentials, in a tf-applier execution that vending dispatched")
            elif runner.project_id != target_project_id:
                code = runner_creds.RUNNER_TARGET_MISMATCH
                message = (f"deploy of '{product_id}' refused: the deploy targets '{target_project_id}', the "
                           f"brokered deployer belongs to '{runner.project_id}' (provenance)")
            else:
                return None
        logger.error(f"{code}: {message}")
        return {"status": "FAILED", "error_class": code, "error": f"{code}: {message}", "product_id": product_id,
                "trace_id": trace_id, "operator_required": True}

    def _child_credentials(self, project_id: str, scoped: bool = True):
        """FD4BD-Q3: Google credentials for a REST call INTO the child project `project_id`, with that project as the
        quota project (google-auth sends `x-goog-user-project: <project_id>` on every request), passed per call. Until
        this change the quota project came from the process env that deploy_workload / tf-applier set, so the calls
        below were already billed to the child; the value is now explicit and per deploy. `scoped=False` keeps the
        unscoped `google.auth.default()` of the call sites that had no scopes.
        FD-7L 2a: when brokered deployer credentials are registered for that project, those (same quota project);
        on a Per-workload install without them, RUNNER_IDENTITY_NOT_REGISTERED (never the platform identity)."""
        runner = self._runner_for_project(project_id)
        if runner is not None:
            return runner.credentials
        if self._runner_identity_mode() == ri.MODE_PER_WORKLOAD:
            raise ri.RunnerIdentityError(runner_creds.RUNNER_IDENTITY_NOT_REGISTERED,
                                         f"no brokered credentials for '{project_id}'", stage="runner-child-call")
        import google.auth
        if scoped:
            creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"],
                                           quota_project_id=project_id)
        else:
            creds, _ = google.auth.default(quota_project_id=project_id)
        return creds

    def _child_storage_client(self, project_id: str):
        """FD4BD-Q3: a Cloud Storage client for the child project's buckets, quota project = the child (the explicit
        form of what the process env did; the client's default project stays the platform's, as before).
        FD-7L 2a: the brokered deployer's credentials when registered for that project (see `_child_credentials`)."""
        from google.cloud import storage
        runner = self._runner_for_project(project_id)
        if runner is not None:
            return storage.Client(project=project_id, credentials=runner.credentials)
        if self._runner_identity_mode() == ri.MODE_PER_WORKLOAD:
            raise ri.RunnerIdentityError(runner_creds.RUNNER_IDENTITY_NOT_REGISTERED,
                                         f"no brokered credentials for '{project_id}'", stage="runner-child-call")
        return storage.Client(project=self.project_id, client_options={"quota_project_id": project_id})

    def _tofu_timeout_slot(self) -> threading.local:
        """FD-4AQ W3: per-thread deploy scope (`in_deploy`) and the first timed-out command of that deploy."""
        slot = self.__dict__.get("_tofu_timeout_tls")
        if slot is None:
            slot = self.__dict__.setdefault("_tofu_timeout_tls", threading.local())
        return slot

    @staticmethod
    def _tofu_timeout_result(message: str, stdout: str = "") -> Dict[str, Any]:
        # stderr holds only the fixed TOFU_TIMEOUT line (no engine text), so no apply-time healer reads an
        # interrupted run's output as a defect to repair.
        return {"exit_code": 124, "stdout": stdout, "stderr": message, "success": False,
                "timed_out": True, "error_class": TOFU_TIMEOUT}

    @staticmethod
    def _signal_process_group(proc: "subprocess.Popen", sig: int) -> None:
        pid = getattr(proc, "pid", None)
        if not isinstance(pid, int) or pid <= 1:
            return                            # never killpg(0 / 1 / -1): only a real child's own group
        try:
            os.killpg(pid, sig)               # start_new_session=True: the group is tofu and its provider plugins
        except (ProcessLookupError, PermissionError):
            pass
        except OSError:
            try:
                proc.send_signal(sig)
            except OSError:
                pass

    def _deploy_time_left(self) -> Optional[float]:
        """DEPLOY-SYNC-BUDGET: seconds left of the running deploy's overall budget; None outside a deploy or for a
        deploy without a budget."""
        slot = self._tofu_timeout_slot()
        deadline = getattr(slot, "deadline", None)
        if not getattr(slot, "in_deploy", False) or deadline is None:
            return None
        return deadline - time.monotonic()

    def _deploy_budget_message(self, sub: str, how: Optional[str]) -> str:
        """DEPLOY-SYNC-BUDGET: the TOFU_TIMEOUT text when the deploy's overall budget (not the command's own limit)
        stopped it; `how` None = the command was never started."""
        budget = float(getattr(self._tofu_timeout_slot(), "budget_s", None) or 0.0)
        what = "was not started" if how is None else f"was {how}"
        return (f"{TOFU_TIMEOUT}: this deploy's overall time limit of {budget:.0f} seconds ran out; the OpenTofu "
                f"command `{sub}` {what}. Nothing more is run for this deploy.")

    def _run_bounded(self, cmd: List[str], cwd: str, exec_env: Dict[str, str]) -> Dict[str, Any]:
        """FD-4AQ W3 (AQ-5): runs `cmd` with the instance's time limit. At the limit: SIGINT to the process group
        (OpenTofu releases the state lock), `grace_s` to stop, then SIGKILL. Returns the usual result dict; a timeout
        adds timed_out / error_class=TOFU_TIMEOUT and is recorded for the running deploy (if any)."""
        import signal as _signal
        limits = getattr(self, "tofu_time_limits", None) or TOFU_TIME_LIMITS_SERVICE
        limit = limits.limit_for(cmd)
        # DEPLOY-SYNC-BUDGET: inside a deploy with a time budget the command gets min(its limit, deadline - now).
        budget_left = self._deploy_time_left()
        if budget_left is not None and budget_left <= 0:
            # Fable RT F2: the deadline passed during the setup in `_run_subprocess` (engine / mirror / override file):
            # the command is not started (same typed result as the check at the top of `_run_subprocess`).
            slot = self._tofu_timeout_slot()
            if not getattr(slot, "message", None):
                slot.message = self._deploy_budget_message(cmd[1] if len(cmd) > 1 else cmd[0], None)
            logger.error(f"TOFU_TIMEOUT: not starting `{' '.join(cmd[:2])}`; this deploy's time budget ran out")
            return self._tofu_timeout_result(slot.message)
        by_budget = budget_left is not None and budget_left < limit
        if by_budget:
            limit = budget_left
        proc = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                env=exec_env, start_new_session=True)
        runner = self._workspace_runner(cwd)
        if runner is not None:
            runner.endpoint.attach(proc)   # FD-7L 2a: a broker failure interrupts it (SIGINT, state lock release)
        try:
            stdout, stderr = proc.communicate(timeout=limit)
            return {
                "exit_code": proc.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "success": proc.returncode == 0,
            }
        except subprocess.TimeoutExpired:
            pass
        sub = cmd[1] if len(cmd) > 1 else cmd[0]
        logger.error(f"TOFU_TIMEOUT: `{sub}` in '{cwd}' ran past {limit:.0f} s; sending SIGINT (state lock release)")
        self._signal_process_group(proc, _signal.SIGINT)
        how = "interrupted"
        try:
            stdout, stderr = proc.communicate(timeout=limits.grace_s)
        except subprocess.TimeoutExpired:
            how = "interrupted, then killed"
            logger.error(f"TOFU_TIMEOUT: `{sub}` still running {limits.grace_s:.0f} s after SIGINT; sending SIGKILL")
            self._signal_process_group(proc, _signal.SIGKILL)
            try:
                stdout, stderr = proc.communicate(timeout=TOFU_PIPE_DRAIN_S)
            except subprocess.TimeoutExpired:
                stdout, stderr = "", ""
                logger.error(f"TOFU_TIMEOUT: output pipes of `{sub}` still open {TOFU_PIPE_DRAIN_S:.0f} s after SIGKILL; "
                             f"abandoning them")
        if by_budget:
            message = self._deploy_budget_message(sub, how)
        else:
            message = (f"{TOFU_TIMEOUT}: the OpenTofu command `{sub}` did not finish within {limit:.0f} seconds and "
                       f"was {how}. Nothing more is run for this deploy.")
        if how != "interrupted":
            message += (" Because it had to be killed, the state lock may still be held and the last resource being "
                        "created may be missing from state.")
        if stderr:
            logger.error(f"TOFU_TIMEOUT: engine output of the stopped `{sub}` (last 4000 chars):\n{stderr[-4000:]}")
        slot = self._tofu_timeout_slot()
        if getattr(slot, "in_deploy", False) and not getattr(slot, "message", None):
            slot.message = message
        return self._tofu_timeout_result(message, stdout or "")

    def _run_with_own_budget(self, cmd: List[str], cwd: str, iac_engine: Optional[str],
                             budget_s: float) -> Dict[str, Any]:
        """FD55-3D RT F3: runs a read-only command inside a deploy with its own fixed time budget instead of what is
        left of the deploy's (`_deploy_time_left` sees `budget_s`); the deploy's deadline is restored afterwards. A
        command of a deploy that already timed out is still refused (`_run_subprocess`)."""
        slot = self._tofu_timeout_slot()
        if not getattr(slot, "in_deploy", False):
            return self._run_subprocess(cmd, cwd=cwd, iac_engine=iac_engine)
        saved = (getattr(slot, "deadline", None), getattr(slot, "budget_s", None))
        slot.deadline, slot.budget_s = time.monotonic() + float(budget_s), float(budget_s)
        try:
            return self._run_subprocess(cmd, cwd=cwd, iac_engine=iac_engine)
        finally:
            slot.deadline, slot.budget_s = saved

    def _run_subprocess(self, cmd: List[str], cwd: str, env: Optional[Dict[str, str]] = None, iac_engine: Optional[str] = None) -> Dict[str, Any]:
        """Executes a subprocess command safely within the target workspace directory using the requested IaC engine.
        FD-4AQ W3: every command has a time limit (`tofu_time_limits`); inside a deploy whose earlier command timed
        out, nothing more is started and the TOFU_TIMEOUT result is returned at once."""
        timeout_slot = self._tofu_timeout_slot()
        if getattr(timeout_slot, "in_deploy", False) and getattr(timeout_slot, "message", None):
            logger.warning(f"TOFU_TIMEOUT: not running `{' '.join(cmd[:2])}`; this deploy already timed out")
            return self._tofu_timeout_result(timeout_slot.message)
        budget_left = self._deploy_time_left()
        if budget_left is not None and budget_left <= 0:
            # DEPLOY-SYNC-BUDGET: the deploy's overall deadline passed before this command: it is not started.
            timeout_slot.message = self._deploy_budget_message(cmd[1] if len(cmd) > 1 else cmd[0], None)
            logger.error(f"TOFU_TIMEOUT: not starting `{' '.join(cmd[:2])}`; this deploy's time budget ran out")
            return self._tofu_timeout_result(timeout_slot.message)
        # FD-7L Phase 2a: the brokered deployer of this workspace (Per-workload installs only), or a typed refusal.
        runner = self._workspace_runner(cwd)
        refusal = self._runner_subprocess_refusal(runner)
        if refusal is not None:
            logger.error(f"{refusal['error_class']}: not running `{' '.join(cmd[:2])}` in '{cwd}'")
            return refusal
        # FD-7L Phase 2a (both modes): an allow-list of the runner's environment, not a copy of it (plan 2.4; no
        # credential, token, nonce, kubeconfig, log setting or platform secret of this process reaches tofu).
        exec_env = runner_creds.tofu_base_env(os.environ)
        # SAT-27 RT L1: no version-check call per command (each command gets a fresh, empty HOME, so the engine's
        # checkpoint cache never persists); an explicit env= still wins.
        exec_env["CHECKPOINT_DISABLE"] = "1"
        # FD-4BD: the deploy workspace's platform secrets, as TF_VAR_<name> (never in a file); an explicit env wins.
        exec_env.update(self._workspace_tf_var_env(cwd))
        if env:
            exec_env.update(env)

        # Multi-tenant quota override enforcement: attribute child project quota/billing to target project.
        # FD4BD-Q3: the deploy workspace's registered quota project (never a process-wide value); an explicit env wins.
        target_billing_pid = (exec_env.get("GOOGLE_BILLING_PROJECT")
                              or (runner.project_id if runner is not None else None)
                              or self._workspace_billing_project(cwd))
        if target_billing_pid and isinstance(target_billing_pid, str):
            exec_env["GOOGLE_USER_PROJECT_OVERRIDE"] = "true"
            exec_env["GOOGLE_BILLING_PROJECT"] = target_billing_pid
            exec_env["GOOGLE_CLOUD_QUOTA_PROJECT"] = target_billing_pid
        if runner is not None:
            # FD-7L 2a: ADC inside tofu resolves to this workspace's local endpoint, which serves only the deployer.
            exec_env["GCE_METADATA_HOST"] = exec_env["GCE_METADATA_IP"] = runner.endpoint.host

        engine = iac_engine or "TERRAFORM"
        try:
            engine_bin = self._ensure_binary(engine)
        except EngineUnverifiable as unverified:   # RT14-22: a typed failed command, nothing is run
            logger.error(f"{unverified}; not running `{' '.join(cmd[:2])}`")
            return unverified.result()

        # Replace 'terraform' or 'tofu' in cmd[0] with resolved binary path
        if cmd and cmd[0] in ("terraform", "tofu"):
            cmd = [engine_bin] + cmd[1:]

        # Centralized lock-timeout injection for state-locking commands (Plan 10)
        LOCK_SENSITIVE_SUBCOMMANDS = {"plan", "apply", "destroy", "import"}
        if cmd and len(cmd) > 1:
            subcmd = cmd[1]
            if subcmd in LOCK_SENSITIVE_SUBCOMMANDS:
                if not any(arg.startswith("-lock-timeout") for arg in cmd):
                    cmd = [cmd[0], subcmd, f"-lock-timeout={self.lock_timeout}"] + cmd[2:]

        bin_dir = os.path.dirname(engine_bin) if os.path.isabs(engine_bin) else ""
        if bin_dir and bin_dir not in exec_env.get("PATH", ""):
            exec_env["PATH"] = f"{bin_dir}:{exec_env.get('PATH', '')}"

        # Configure persistent plugin cache to avoid registry rate limits
        plugin_cache = os.path.join(self.tooling_dir, "plugin_cache")
        os.makedirs(plugin_cache, exist_ok=True)
        exec_env["TF_PLUGIN_CACHE_DIR"] = plugin_cache

        # Configure provider filesystem mirror via CLI config file (OpenTofu inherits TF_CLI_CONFIG_FILE natively).
        # FD-4G: fail closed -- never run tofu without the platform CLI config.
        rc_path = self._ensure_provider_mirror()
        if not os.path.isfile(rc_path):
            raise RuntimeError("provider mirror CLI config missing; refusing to run tofu without it")
        exec_env["TF_CLI_CONFIG_FILE"] = rc_path
        # FD-4AQ W1b (Fable F3): no inherited extra CLI arguments (e.g. `-plugin-dir`, which would bypass the
        # provider_installation allow-list at init).
        for name in ("TF_CLI_ARGS", "TF_CLI_ARGS_init"):
            exec_env.pop(name, None)

        # Transient Kubernetes provider stubbing during non-Kubernetes state imports
        override_created = False
        override_path = os.path.join(cwd, "_castor_k8s_override.tf")
        if cmd and len(cmd) > 1 and cmd[1] == "import" and os.path.isdir(cwd):
            # Check if this import is for a non-Kubernetes resource while kubernetes provider is configured
            target_res = ""
            for arg in cmd[2:]:
                if not arg.startswith("-"):
                    target_res = arg
                    break
            if not (target_res.startswith("kubernetes_") or ".kubernetes_" in target_res):
                try:
                    has_k8s_provider = False
                    for f_name in os.listdir(cwd):
                        if f_name.endswith(".tf") and not f_name.startswith("_"):
                            f_full = os.path.join(cwd, f_name)
                            if os.path.isfile(f_full):
                                try:
                                    with open(f_full, "r", encoding="utf-8") as f_chk:
                                        cont = f_chk.read()
                                        if 'provider "kubernetes"' in cont and ("module." in cont or "${module." in cont):
                                            has_k8s_provider = True
                                            break
                                except Exception:
                                    pass
                    if has_k8s_provider:
                        # Provide a temporary static override so OpenTofu doesn't crash evaluating uncomputed cluster outputs
                        k8s_stub = (
                            '# Transient override injected by Castor during foundational resource import\n'
                            'provider "kubernetes" {\n'
                            '  host                   = "https://127.0.0.1"\n'
                            '  token                  = "dummy-import-token"\n'
                            f'  cluster_ca_certificate = base64decode("{DUMMY_K8S_PEM_CERT}")\n'
                            '  insecure               = true\n'
                            '}\n'
                        )
                        with open(override_path, "w", encoding="utf-8") as f_ov:
                            f_ov.write(k8s_stub)
                        override_created = True
                        logger.info(f"Temporarily staged Kubernetes provider stub '{override_path}' for '{target_res}' import")
                except Exception as k8s_ov_err:
                    logger.debug(f"Kubernetes provider stub staging notice: {k8s_ov_err}")

        logger.info(f"Executing command in '{cwd}': {' '.join(cmd)}")
        tofu_home = None
        try:
            # FD-7L Phase 2a (both modes): a fresh, empty HOME for every tofu process (Go's ADC reads
            # $HOME/.config/gcloud/application_default_credentials.json before the metadata server); removed after.
            tofu_home = tempfile.mkdtemp(prefix="stackvend-tofu-home-")
            exec_env["HOME"] = tofu_home
            out = self._run_bounded(cmd, cwd, exec_env)
            if runner is not None and runner.endpoint.failure is not None:
                # FD-7L 2a: the broker could not renew the deployer token; tofu was interrupted (SIGINT). Typed.
                failure = runner.endpoint.failure
                return self._runner_refusal_result(failure.code, failure.detail, stdout=out.get("stdout") or "")
            # FD-4AQ W1b on the bounded runner (AQ-5): a failed, not timed-out `init` is classified for providers
            # outside the allow-list (config or state); a timeout keeps its TOFU_TIMEOUT class.
            if (not out.get("success")) and not out.get("timed_out") and len(cmd) > 1 and cmd[1] == "init":
                self._classify_provider_not_allowed(out, cwd, engine)
            return out
        except Exception as e:
            logger.error(f"Command execution error: {e}")
            return {
                "exit_code": 1,
                "stdout": "",
                "stderr": str(e),
                "success": False,
            }
        finally:
            if tofu_home:
                shutil.rmtree(tofu_home, ignore_errors=True)
            if override_created and os.path.exists(override_path):
                try:
                    os.remove(override_path)
                    logger.info(f"Cleaned up temporary Kubernetes provider stub '{override_path}'")
                except Exception as rm_err:
                    logger.warning(f"Could not remove temporary Kubernetes provider stub: {rm_err}")

    def _classify_provider_not_allowed(self, out: Dict[str, Any], cwd: str, engine: str) -> None:
        """FD-4AQ W1b (AQ-6): after a failed `init`, names every provider outside the allow-list that the configuration
        requires (provider_allowlist.disallowed_providers: python-hcl2 parse + Terraform's provider rules + OpenTofu's
        module manifest) or that the state records (Fable F2: when init got as far as the backend,
        `.terraform/terraform.tfstate`, `state pull` JSON `resources[].provider`). No error text is read. A hit sets
        error_class PROVIDER_NOT_ALLOWED and the exact addresses, and prefixes stderr with the typed sentence.
        Classification never fails the call: any error leaves the untyped result unchanged."""
        registry = (provider_allowlist.PROVIDER_REGISTRIES[0]
                    if (engine or "").strip().upper() in ("OPENTOFU", "TOFU") else provider_allowlist.PROVIDER_REGISTRIES[1])
        try:
            bad = provider_allowlist.disallowed_providers(cwd, registry)
            state_bad: List[str] = []
            if os.path.isfile(os.path.join(cwd, ".terraform", "terraform.tfstate")):
                pulled = self._run_subprocess(["terraform", "state", "pull"], cwd=cwd, iac_engine=engine)
                if pulled.get("success"):
                    state_bad = [a for a in provider_allowlist.state_disallowed_providers(pulled.get("stdout") or "")
                                 if a not in bad]
        except Exception as e:  # noqa: BLE001 - the untyped init failure stands
            logger.warning(f"Provider allow-list classification unavailable ({type(e).__name__}: {e})")
            return
        if bad or state_bad:
            message = provider_allowlist.not_allowed_message(bad, state_bad)
            logger.error(message)
            out["error_class"] = provider_allowlist.ERROR_PROVIDER_NOT_ALLOWED
            out["providers_not_allowed"] = bad + state_bad
            if state_bad:
                out["providers_not_allowed_in_state"] = state_bad
            out["stderr"] = f"{message}\n\n{out.get('stderr') or ''}"

    # FD55-W6a (A5, HA-03 / FD-4AZ-b2): the Cloud Run deletion_protection add / flip and
    # _cloud_run_deletion_protection_off are DELETED; the committed value is applied.

    @staticmethod
    def _add_static_mount_placeholders(workspace_dir: str) -> List[str]:
        """FD55-A8-CONVERT (owner 10-27): adds an empty `<dir>/.gitkeep` to the deploy workspace for each directory a
        service's Python code mounts with a literal `StaticFiles(directory="<dir>")`, found with Python's parser by
        the gateway's own rule (shared/static_mounts.static_placeholder_files, FD-55 W5 G21), add-only (only when that
        directory holds no file yet). It replaced a substring test (the words `StaticFiles` and `static` anywhere in
        each `main.py`), which also fired on an import, a comment or a string and only ever made `static/`.

        Service roots (the same set as before): the workspace root and every directory `apps/<d>/`. Every `.py` file
        of a service root is parsed (for the workspace root: every one outside `apps/`) and `<dir>` is relative to that
        root (the service's working directory at run time). A3 + A8 (FD55-W6a review F4): a committed root `main.py`
        beside `apps/<svc>/` (kept since FD55-W6a A3; the build does not pack the root when services exist) now gets
        a root placeholder only when it really mounts a literal directory, not when it mentions `StaticFiles`.
        Every file of the root (apps/ included) still counts for the add-only check. Directories named in
        TF_WORKSPACE_RESERVED are never walked. The committed files are never changed; a
        placeholder that cannot be written (unsafe path, a file in the way) is logged and skipped. Returns the
        workspace-relative paths written.
        """
        apps_root = os.path.join(workspace_dir, "apps")
        service_roots = [""] + sorted(
            f"apps/{d}" for d in (os.listdir(apps_root) if os.path.isdir(apps_root) else ())
            if os.path.isdir(os.path.join(apps_root, d)) and d not in TF_WORKSPACE_RESERVED)
        written: List[str] = []
        for svc_rel in service_roots:
            svc_dir = os.path.join(workspace_dir, svc_rel) if svc_rel else workspace_dir
            service_files: Dict[str, Optional[str]] = {}
            for root, dirs, fnames in os.walk(svc_dir):
                dirs[:] = sorted(d for d in dirs if d not in TF_WORKSPACE_RESERVED)
                for fname in fnames:
                    rel = os.path.relpath(os.path.join(root, fname), svc_dir).replace(os.sep, "/")
                    text: Optional[str] = None   # None = "a file is here" (add-only check), not parsed
                    # the workspace root's own code is every .py outside apps/ (apps/<d>/ are service roots)
                    if fname.endswith(".py") and (svc_rel or rel.split("/")[0] != "apps"):
                        try:
                            with open(os.path.join(root, fname), "r", encoding="utf-8") as f_py:
                                text = f_py.read()
                        except (OSError, UnicodeDecodeError) as e:
                            logger.warning(f"Static mount check could not read {svc_rel or '.'}/{rel}: {e}")
                    service_files[rel] = text
            for rel in static_placeholder_files(service_files):
                ws_rel = f"{svc_rel}/{rel}" if svc_rel else rel
                try:
                    target = safe_join(workspace_dir, ws_rel, reserved=TF_WORKSPACE_RESERVED)
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    if not os.path.exists(target):
                        with open(target, "w", encoding="utf-8") as f_gk:
                            f_gk.write("")
                        written.append(ws_rel)
                        logger.info(f"Static mount placeholder {ws_rel} added to the deploy workspace")
                except (UnsafePathError, OSError) as e:
                    logger.warning(f"Could not add static mount placeholder {ws_rel}: {e}")
        return written

    # ------------------------------------------------------------------------------ FD-7L Phase 2b (section comment
    # above platform_identity_violations): the run's mode, state location, pre-init policy and content-policy identity.
    RUNNER_CTX_REGISTRY_MAX = 256

    def _runner_identity_mode(self) -> str:
        """The ONE place the terraform runner (service, tf-applier, the mode log line) reads the runner identity mode
        (FD-7L-n; pinned by an AST test over service.py, runner_credentials.py and applier.py). Today the install env
        STACKVEND_TF_RUNNER_IDENTITY through shared.runner_identity.runner_identity_mode; where the operative mode lives
        changes only that call (owner F4: the vending-signed install record, read with this instance's guard database
        and certificate fetcher). Raises shared.runner_identity.RunnerIdentityError (RUNNER_IDENTITY_MODE_INVALID)
        for an unknown value: a misconfigured install never guesses a mode. Works on an instance built without
        __init__ (install_runner_identity_mode)."""
        return ri.runner_identity_mode()

    def _recorded_project_id(self, product_id: str) -> Optional[str]:
        """Review F9 (PLATFORM measurement only): workloads/{pid}.project_id, so a plan / saved-plan apply / drift run
        on a Shared install also logs its POLICY_WOULD_REFUSE identity findings. Any read problem -> None (nothing
        decides from it; a log line only)."""
        db = getattr(self, "db", None)
        if db is None or not product_id:
            return None
        try:
            snap = db.collection("workloads").document(product_id).get()
            data = snap.to_dict() if getattr(snap, "exists", False) is True else None
        except Exception:  # noqa: BLE001 - measurement only
            return None
        value = data.get("project_id") if isinstance(data, dict) else None
        return value if isinstance(value, str) else None

    def _guard_db_client(self) -> Any:
        """The guard database (vending's signed provenance records), read-only. `self.guard_db` is the test seam."""
        injected = getattr(self, "guard_db", None)
        if injected is not None:
            return injected
        name = (os.getenv(GUARD_DB_ENV) or "").strip()
        if not name:
            raise RunnerIdentityRefused(RUNNER_STORE_UNAVAILABLE, f"{GUARD_DB_ENV} is not set, so the workload's "
                                                                  "signed runner identity record cannot be read")
        try:
            self.guard_db = firestore.Client(project=self.project_id, database=name)
        except Exception as e:  # noqa: BLE001
            raise RunnerIdentityRefused(RUNNER_STORE_UNAVAILABLE,
                                        f"the guard database client failed ({type(e).__name__})") from None
        return self.guard_db

    def _runner_certs(self) -> Callable[..., Mapping[str, str]]:
        certs = getattr(self, "runner_certs", None)   # test seam
        if certs is None:
            certs = self.runner_certs = ri.X509CertFetcher()
        return certs

    def _runner_state_context(self, product_id: str, target_project_id: Optional[str] = None,
                              measure: bool = False) -> RunnerStateContext:
        """FD-7L Phase 2b (plan 2.6 / 2.11): where this run's state lives. PLATFORM: the platform bucket, nothing read
        (`project_id` is the run's target, used only for POLICY_WOULD_REFUSE log lines). PER_WORKLOAD: the READY,
        vending-signed record of workload_provenance/{product_id}; anything else raises RunnerIdentityRefused."""
        try:
            mode = self._runner_identity_mode()
        except ri.RunnerIdentityError as e:
            raise RunnerIdentityRefused(e.code, e.detail) from None
        if mode != ri.MODE_PER_WORKLOAD:
            self._refuse_state_left_in_child_bucket(product_id)   # SAT-41 HIGH-3 (reads nothing before step A)
            measured = (target_project_id if target_project_id is not None
                        else self._recorded_project_id(product_id) if measure else None)
            return RunnerStateContext(mode=mode, bucket=self.state_bucket or "", source="platform",
                                      project_id=measured if ri.is_project_id(measured) else None)
        gdb = self._guard_db_client()
        doc_path = ri.provenance_doc_path(product_id)
        try:
            snap = gdb.collection(ri.PROVENANCE_COLLECTION).document(product_id).get()
            prov = snap.to_dict() if getattr(snap, "exists", False) is True else None
        except Exception as e:  # noqa: BLE001
            raise RunnerIdentityRefused(RUNNER_STORE_UNAVAILABLE,
                                        f"{doc_path} could not be read ({type(e).__name__})") from None
        raw = prov.get(ri.RUNNER_IDENTITY_FIELD) if isinstance(prov, dict) else None
        if raw is None:
            raise RunnerIdentityRefused(RUNNER_IDENTITY_NOT_READY,
                                        f"'{product_id}' has no runner identity record ({doc_path}); the runner "
                                        "identity backfill sets it up (Settings > Terraform runner identity)")
        signer = ri.expected_broker_email()
        if not signer:
            raise RunnerIdentityRefused("RUNNER_RECORD_UNVERIFIABLE",
                                        f"{doc_path}: the broker identity is not configured on this server")
        try:
            rec = ri.verify_record(doc_path, raw, expected_signer=signer, certs=self._runner_certs())
            if rec.get("status") == ri.STATUS_MIGRATING:
                raise RunnerIdentityRefused(STATE_MIGRATION_IN_PROGRESS,
                                            f"the state of '{product_id}' is being moved into its own bucket; run "
                                            "again when the backfill has finished")
            rec = ri.check_runner_identity(rec, product_id=product_id, project_id=prov.get("project_id"))
        except ri.RunnerIdentityError as e:
            raise RunnerIdentityRefused(e.code, e.detail) from None
        project = rec["project_id"]
        if target_project_id is not None and target_project_id != project:
            raise RunnerIdentityRefused("RUNNER_TARGET_MISMATCH",
                                        f"'{product_id}': the run targets project {target_project_id!r}, its signed "
                                        f"record names {project!r}")
        return RunnerStateContext(mode=mode, bucket=rec["state_bucket"], source="provenance", project_id=project,
                                  deployer_email=ri.deployer_email(project))

    def _refuse_state_left_in_child_bucket(self, product_id: str) -> None:
        """SAT-41 (FD-7L pre-switch RT HIGH-3), Shared path only. A workload whose runner identity record is READY
        may hold its state only in its own bucket (vended under Per workload, or its platform copy purged); a Shared
        run would plan from an empty platform state. Raises RunnerIdentityRefused(STATE_IN_CHILD_BUCKET) when the
        record (READY, the provenance project's bucket shape) names a child bucket whose `default.tfstate` is live
        while the platform bucket holds none for the workload: one existence read each, platform first.
        Nothing is read without STACKVEND_GUARD_FIRESTORE_DATABASE and STACKVEND_BROKER_SA on this process (before
        step A: unchanged); nothing more when the workload has no READY record. The check only ever refuses (it never moves where state is read or
        written), so a record whose signature no longer verifies (after a switch back to Shared vending's re-sign
        sweep is off and the key may retire) still counts, with its signature state named in the refusal."""
        if not (os.getenv(GUARD_DB_ENV) or "").strip() or not (os.getenv(ri.BROKER_SA_ENV) or "").strip() \
                or not self.state_bucket:
            return   # before step A (both are Terraform-owned step-A settings): nothing read, as before
        signer = ri.expected_broker_email()
        doc_path = ri.provenance_doc_path(product_id)
        try:
            snap = self._guard_db_client().collection(ri.PROVENANCE_COLLECTION).document(product_id).get()
            prov = snap.to_dict() if getattr(snap, "exists", False) is True else None
        except RunnerIdentityRefused:
            raise
        except Exception as e:  # noqa: BLE001 - where the state lives cannot be checked: never assumed
            raise RunnerIdentityRefused(RUNNER_STORE_UNAVAILABLE, f"{doc_path} could not be read "
                                        f"({type(e).__name__}), so where the state of '{product_id}' lives cannot "
                                        "be checked") from None
        raw = prov.get(ri.RUNNER_IDENTITY_FIELD) if isinstance(prov, dict) else None
        if not isinstance(raw, dict) or raw.get("status") != ri.STATUS_READY:
            return   # no record, or the state has not left the platform bucket
        try:
            rec = ri.check_runner_identity(raw, product_id=product_id, project_id=prov.get("project_id"))
        except ri.RunnerIdentityError as e:
            logger.error(f"{STATE_LOCATION_UNCHECKED}: '{product_id}': its READY runner identity record names no "
                         f"bucket of its project ({e.code}); the Shared run uses the platform bucket as before")
            return
        try:
            ri.verify_record(doc_path, raw, expected_signer=signer, certs=self._runner_certs())
            signature = "signed by vending"
        except ri.RunnerIdentityError as e:
            signature = f"signature not verified: {e.code}"
        child = rec["state_bucket"]
        try:
            if self._live_state_exists(self.state_bucket, product_id):
                return
            in_child = self._live_state_exists(child, product_id, client_project=rec["project_id"])
        except Exception as e:  # noqa: BLE001
            raise RunnerIdentityRefused(STATE_LOCATION_UNREADABLE, f"the state objects of '{product_id}' "
                                        f"(gs://{self.state_bucket}, gs://{child}) could not be read "
                                        f"({type(e).__name__})") from None
        if in_child:
            obj = ri.state_object_name(product_id)
            raise RunnerIdentityRefused(STATE_IN_CHILD_BUCKET, (
                f"the OpenTofu state of '{product_id}' is in its own bucket gs://{child}/{obj} (runner identity "
                f"record READY, {signature}) and the platform bucket gs://{self.state_bucket} holds none for it, so a "
                "Shared run would start from an empty state. Copy that state to the platform bucket (same object "
                "name) before deploying on a Shared install, or switch the install back to Per workload"))

    def _live_state_exists(self, bucket: str, product_id: str, *, client_project: Optional[str] = None) -> bool:
        """SAT-41: whether gs://<bucket>/workloads/<product_id>/default.tfstate has a live object (one metadata read;
        a child bucket through `_child_storage_client`). Raises when the bucket cannot be read."""
        from google.cloud import storage
        client = (self._child_storage_client(client_project) if client_project
                  else storage.Client(project=self.project_id))
        return client.bucket(bucket).get_blob(ri.state_object_name(product_id)) is not None

    _RUNNER_CTX_LOCK = threading.Lock()   # review F8: the two registries below are shared by FastAPI worker threads

    def _register_runner_ctx(self, workspace_dir: str, ctx: RunnerStateContext) -> None:
        if not isinstance(workspace_dir, str):
            return
        key = os.path.realpath(workspace_dir)
        with self._RUNNER_CTX_LOCK:
            registry = self.__dict__.setdefault("_runner_ctx_by_workspace", {})
            registry[key] = ctx
            while len(registry) > self.RUNNER_CTX_REGISTRY_MAX:
                registry.pop(next(iter(registry)))

    def _stage_runner_ctx(self, trace_id: str, product_id: str, ctx: RunnerStateContext) -> None:
        """Hands a run's context to the next prepare_workspace of the same (trace_id, product_id) (deploy_workload /
        generate_plan; keeps prepare_workspace's call signature for its callers)."""
        with self._RUNNER_CTX_LOCK:
            staged = self.__dict__.setdefault("_staged_runner_ctx", {})
            staged[(trace_id, product_id)] = ctx
            while len(staged) > self.RUNNER_CTX_REGISTRY_MAX:
                staged.pop(next(iter(staged)))

    def _take_staged_runner_ctx(self, trace_id: str, product_id: str) -> Optional[RunnerStateContext]:
        with self._RUNNER_CTX_LOCK:
            return self.__dict__.get("_staged_runner_ctx", {}).pop((trace_id, product_id), None)

    def _workspace_runner_ctx(self, workspace_dir: str, product_id: str, measure: bool = False) -> RunnerStateContext:
        """The context the workspace was prepared with, else a fresh one (direct callers and tests)."""
        hit = None
        if isinstance(workspace_dir, str):
            key = os.path.realpath(workspace_dir)
            with self._RUNNER_CTX_LOCK:
                hit = self.__dict__.get("_runner_ctx_by_workspace", {}).get(key)
        return hit if hit is not None else self._runner_state_context(product_id, measure=measure)

    def _policy_identity(self, ctx: RunnerStateContext) -> Optional[Dict[str, Any]]:
        """PLATFORM_IDENTITY_TOUCHED facts: the run project's deployer and both state buckets (the run's and the
        platform's)."""
        return platform_identity(ctx.project_id, {ctx.bucket, self.state_bucket or ""})

    @staticmethod
    def _log_would_refuse(product_id: str, trace_id: Optional[str], stage: str,
                          findings: List[Dict[str, Any]]) -> None:
        """OQ-32: one structured POLICY_WOULD_REFUSE line per finding a PLATFORM run does not enforce."""
        for f in findings:
            logger.warning(json.dumps({"event": POLICY_WOULD_REFUSE, "product_id": product_id, "trace_id": trace_id,
                                       "stage": stage, "code": f.get("code"),
                                       "file": f.get("file"), "address": f.get("address"),
                                       "detail": f.get("detail") or f.get("message")}, sort_keys=True))

    @staticmethod
    def _identity_source_lookup(workspace_dir: Optional[str], plan_json: Any) -> Optional[Callable[..., Any]]:
        """Review F1: (module path, type, name, attribute) -> python-hcl2's rendering of that attribute in the
        workload's HCL (the module directory follows the plan configuration's local module sources from
        `workspace_dir`), else None. None when there is no workspace."""
        if not isinstance(workspace_dir, str):
            return None
        config = plan_json.get("configuration") if isinstance(plan_json, dict) else None
        root = config.get("root_module") if isinstance(config, dict) else None
        cache: Dict[str, Any] = {}

        def lookup(path: Tuple[str, ...], rtype: str, name: str, attr: str) -> Any:
            directory, module = workspace_dir, root
            for call_name in path:
                calls = module.get("module_calls") if isinstance(module, dict) else None
                call = calls.get(call_name) if isinstance(calls, dict) else None
                source = call.get("source") if isinstance(call, dict) else None
                if not isinstance(source, str) or not source.startswith(_LOCAL_MODULE_SOURCE_PREFIXES):
                    return None
                directory = os.path.normpath(os.path.join(directory, *source.split("/")))
                module = call.get("module")
            if directory not in cache:
                cache[directory] = provider_allowlist.module_resource_bodies(directory)
            bodies = cache[directory]
            body = bodies.get((rtype, name)) if isinstance(bodies, dict) else None
            return body.get(attr) if isinstance(body, dict) else None

        return lookup

    def _content_policy_findings(self, plan_json: Dict[str, Any], ctx: RunnerStateContext, product_id: str,
                                 trace_id: Optional[str], log: bool = True,
                                 workspace_dir: Optional[str] = None) -> List[Dict[str, Any]]:
        """FD-4AW-b violations with this run's own state bucket, plus PLATFORM_IDENTITY_TOUCHED in PER_WORKLOAD
        (PLATFORM: logged as POLICY_WOULD_REFUSE when `log`, never returned). `workspace_dir`: the workspace whose
        HCL the closed unknown-value shapes are checked on (None: every unknown identity value is refused)."""
        violations = plan_content_policy_violations(plan_json, ctx.bucket, product_id)
        try:
            touched = platform_identity_violations(plan_json, self._policy_identity(ctx),
                                                   self._identity_source_lookup(workspace_dir, plan_json))
        except Exception as e:  # noqa: BLE001 - PER_WORKLOAD: a check that cannot run never passes; PLATFORM: logged
            touched = [{"code": POLICY_PLATFORM_IDENTITY_TOUCHED, "address": None,
                        "message": f"the platform identity check could not run ({type(e).__name__})"}]
        if ctx.per_workload:
            return violations + touched
        if log:
            self._log_would_refuse(product_id, trace_id, "content_policy", touched)
        return violations

    def _preinit_policy_stop(self, workspace_dir: str, ctx: RunnerStateContext, product_id: str,
                             trace_id: Optional[str]) -> Optional[Dict[str, Any]]:
        """FD-7L Phase 2b (plan 2.5, OQ-32): run before the first `init`. PER_WORKLOAD: a typed refusal (status
        FAILED, APPLY_CONTENT_POLICY, operator_required, `preinit_policy_violations`) when anything is found; PLATFORM:
        POLICY_WOULD_REFUSE log lines only, None."""
        try:
            findings = provider_allowlist.preinit_policy_findings(
                workspace_dir, product_id=product_id, state_bucket=ctx.bucket,
                module_target_allowed=_module_target_allowed)
        except Exception as e:  # noqa: BLE001 - a check that cannot run never passes in PER_WORKLOAD
            findings = [{"code": provider_allowlist.POLICY_SOURCE_UNPARSEABLE, "file": ".",
                         "detail": f"the pre-init policy could not run ({type(e).__name__})"}]
        if not findings:
            return None
        if not ctx.per_workload:
            self._log_would_refuse(product_id, trace_id, provider_allowlist.PREINIT_POLICY_STAGE, findings)
            return None
        codes = sorted({f["code"] for f in findings})
        error = (f"{ERROR_APPLY_CONTENT_POLICY}: the workload Terraform breaks the platform's pre-init policy "
                 f"({', '.join(codes)}): " + "; ".join(f"{f['file']}: {f['detail']}" for f in findings[:20])
                 + ". Nothing was initialized, planned or applied. Workload Terraform (including human-written and "
                   "override files) may set only the listed provider settings, no backend, cloud or state "
                   "encryption block, only local modules, and may read only its own state.")
        logger.error(error)
        return {"status": "FAILED", "error_class": ERROR_APPLY_CONTENT_POLICY, "code": codes[0], "error": error,
                "stage": provider_allowlist.PREINIT_POLICY_STAGE, "preinit_policy_violations": findings[:50],
                "product_id": product_id, "trace_id": trace_id, "operator_required": True}

    def _check_workspace_backend(self, workspace_dir: str, ctx: "RunnerStateContext", product_id: str,
                                 what: str) -> None:
        """FD-7L 2b (drift; review F7: saved-plan apply): in PER_WORKLOAD an existing workspace must have been prepared
        for the record's bucket (its backend.tf equals the platform's render for it, exact text), else
        STATE_BACKEND_MISMATCH (a backfill or re-vend moved the bucket since). PLATFORM: nothing checked."""
        if not ctx.per_workload:
            return
        try:
            with open(os.path.join(workspace_dir, provider_allowlist.PLATFORM_BACKEND_FILE), "r",
                      encoding="utf-8") as fh:
                written = fh.read()
        except OSError:
            written = None
        if written != self._platform_backend_hcl(ctx.bucket, product_id):
            raise RunnerIdentityRefused(STATE_BACKEND_MISMATCH,
                                        f"the {what} workspace of '{product_id}' was not prepared for its state bucket "
                                        f"gs://{ctx.bucket} (its backend.tf is not the platform's for that bucket); "
                                        "run a plan or deploy first")

    @staticmethod
    def _platform_backend_hcl(bucket: str, product_id: str) -> str:
        """The backend.tf prepare_workspace writes (unchanged text; only the bucket comes from the run's context)."""
        return f"""terraform {{
  required_version = ">= 1.5.0"
  backend "gcs" {{
    bucket = "{bucket}"
    prefix = "workloads/{product_id}"
  }}
}}
"""

    def prepare_workspace(
        self, product_id: str, trace_id: str, hcl_files: Dict[str, str], iac_engine: Optional[str] = None,
        region: Optional[str] = None, state_ctx: Optional[RunnerStateContext] = None,
        binary_files: Optional[Mapping[str, bytes]] = None,
    ) -> str:
        """Sets up an isolated workspace directory and injects GCS backend configuration.

        FD-4G: every manifest key is validated before anything is written (atomic rejection); a bad key,
        trace_id or product_id raises UnsafePathError.

        ``iac_engine`` (the workload's resolved engine, passed by deploy_workload / generate_plan): when given,
        the engine binary is made available here. It is the same ``_ensure_binary`` call the first
        ``_run_subprocess`` makes right after this method: on PATH or already cached it returns without
        downloading; on a cold tf-applier job the one download moves here from ``init``; a failed download returns
        the bare name exactly as before (``init`` then fails as it did); a forbidden version raises the same error,
        earlier. (It used to serve the parser-gated orphaned-syntax healer, register row 7, which FD55-W6b deleted;
        the call is kept so a forbidden engine version still fails before any file is written.) When omitted
        (direct callers, tests) nothing changes.

        FD55-W6b / W6d: every committed file is written as committed (Dockerfiles dropped, invariant 4); no .tf file
        is rewritten and nothing is recorded for a commit back to the repository. A vendored golden module that
        differs from the platform payload is reported (``stale_vendored_module_files``), never overwritten.

        FD-7L Phase 2b (plan 2.6): ``state_ctx`` (the run's RunnerStateContext; None = resolved here) decides the
        backend. PLATFORM: ``backend.tf`` names the platform bucket and is written first, exactly as before. PER_WORKLOAD:
        it names the bucket of the workload's signed record and is written after the committed files, so a committed
        root ``backend.tf`` is replaced in the workspace (BACKEND_REPLACED_BY_PLATFORM; the repository is unchanged).
        """
        validate_manifest_keys(hcl_files, reserved=TF_WORKSPACE_RESERVED)
        if binary_files:   # RT14-21: the same key rules for the files carried as exact bytes
            validate_manifest_keys(dict(binary_files), reserved=TF_WORKSPACE_RESERVED)
        ctx = state_ctx if state_ctx is not None else (self._take_staged_runner_ctx(trace_id, product_id)
                                                       or self._runner_state_context(product_id))
        # FD55-W6b / W6d (register FD55-W6b+W6d): no committed .tf file is rewritten in this method, on any workspace
        # (typed intent or legacy), and nothing is recorded for a commit back to the repository: the deploy never
        # writes to the workload repository (the A31 write-back dict `_last_healed_files` is deleted).
        if iac_engine:
            self._ensure_binary(iac_engine)
        workspace_dir = self._workspace_dir(trace_id, product_id)
        os.makedirs(workspace_dir, exist_ok=True)
        self._register_runner_ctx(workspace_dir, ctx)
        backend_path = os.path.join(workspace_dir, provider_allowlist.PLATFORM_BACKEND_FILE)

        # 1. Write backend.tf with GCS state locking (PLATFORM: first, as before; PER_WORKLOAD: after the files, below)
        if ctx.bucket and not ctx.per_workload:
            with open(backend_path, "w") as f:
                f.write(self._platform_backend_hcl(ctx.bucket, product_id))

        # 2. Write provided source files exactly as committed (FD55-W6a, register FD55-W6a: no file is rewritten here).
        # FD55-W6a DELETED (A3) the drop of root main.py / Procfile / requirements.txt when apps/ exists, (A4) the
        # `default = "...${var.x}..."` -> `""` wipe, (A5) the Cloud Run deletion_protection add / flip, (A6) the
        # provider `version = "...5.x"` -> `>= 6.0.0, < 7.0.0` rewrite, and (A7) the workflow YAML sanitizer (with the
        # Firestore read it needed). A file that would not apply fails `tofu validate` / apply and is reported back
        # (intent workspaces: the typed validation report; legacy: the validate / apply error reaches the developer).
        # Lane 11 RT F2 (HB-08 / FD-4Z): the `_ensure_default` healer that injected a guessed default into every
        # variable block without one is deleted (values come from terraform.tfvars). ``region`` is accepted for the
        # callers' signature and no longer used here (its only user was the workflow sanitizer).
        for filename, content in hcl_files.items():
            base_fname = os.path.basename(filename).lower()
            if base_fname == "dockerfile" or base_fname.startswith("dockerfile."):
                continue  # Strictly suppress any Dockerfile (GCP Buildpacks exclusivity)
            file_path = safe_join(workspace_dir, filename, reserved=TF_WORKSPACE_RESERVED)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            if filename.endswith((".yml", ".yaml")) and "workflows" in filename and validate_github_workflow_yaml:
                validate_github_workflow_yaml(content, filename=filename)   # the committed text, judged as-is
            # FD-4AD: `.py` files are written as committed (the HB-42 post-QA rewrite is deleted).
            if isinstance(content, (bytes, bytearray)):   # RT14-21: exact bytes, never decoded
                with open(file_path, "wb") as f:
                    f.write(content)
                continue
            with open(file_path, "w") as f:
                f.write(content)

        # RT14-21: binary repository files (fonts, images, pdf, sqlite...) written byte for byte under the same path
        # rules; a text file of the same path (the deploy request's own files) wins, as in the text manifest.
        for filename, content in (binary_files or {}).items():
            base_fname = os.path.basename(filename).lower()
            if filename in hcl_files or base_fname == "dockerfile" or base_fname.startswith("dockerfile."):
                continue
            file_path = safe_join(workspace_dir, filename, reserved=TF_WORKSPACE_RESERVED)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "wb") as f:
                f.write(bytes(content))

        # 2b. FD-7L Phase 2b (plan 2.6): in PER_WORKLOAD the platform's backend is written last, from the signed record,
        # so it replaces a committed root backend.tf in this workspace (exact manifest key; the repository is unchanged).
        if ctx.per_workload:
            if provider_allowlist.PLATFORM_BACKEND_FILE in hcl_files:
                logger.warning(f"{BACKEND_REPLACED_BY_PLATFORM}: the committed root "
                               f"{provider_allowlist.PLATFORM_BACKEND_FILE} of '{product_id}' is replaced in the "
                               f"deploy workspace by the platform's (gs://{ctx.bucket}/workloads/{product_id}); the "
                               "repository is not changed")
            if os.path.islink(backend_path):
                os.remove(backend_path)
            with open(backend_path, "w") as f:
                f.write(self._platform_backend_hcl(ctx.bucket, product_id))
        elif provider_allowlist.PLATFORM_BACKEND_FILE in hcl_files and ctx.bucket:
            # Shared install: the committed root backend.tf stays in effect (today's behaviour); measurement line only
            logger.info(f"{BACKEND_REPLACED_BY_PLATFORM} (not applied, Shared install): '{product_id}' commits a root "
                        f"{provider_allowlist.PLATFORM_BACKEND_FILE}; a Per-workload run would replace it")

        # Static directory placeholder (FD55-A8-CONVERT, owner 10-27; deploy workspace copy only, never committed back).
        self._add_static_mount_placeholders(workspace_dir)

        # FD-4AE-c (#16, deploy-workspace copy): DELETED the mirror of every non-reserved root dir (scripts/, contracts/,
        # modules/, ...) into each apps/<svc>/, hierarchical and flat. It added files QA never ran (a flat copy can shadow
        # an installed module); the pre-QA package gate vendors what a service needs before QA.

        # Proactively purge any lingering Dockerfile from workspace to guarantee Buildpacks exclusivity
        for root, dirs, fnames in os.walk(workspace_dir):
            for f in fnames:
                if f.lower() == "dockerfile" or f.lower().startswith("dockerfile."):
                    try:
                        os.remove(os.path.join(root, f))
                        logger.info(f"Purged Dockerfile at {os.path.join(root, f)} to preserve Buildpacks exclusivity.")
                    except Exception:
                        pass

        # FD55-W6a DELETED the root-module rewriters (they ran on legacy workspaces only; TI-5a already skipped them on
        # intent workspaces): (A9, HB-12) appending a guessed `variable` block for every undeclared `var.x`, (A10, HB-17)
        # the GCP naming-invariant rewrite of every root .tf, (A11, HC-08) deleting an output re-declared in another
        # file, and (A12) re-pointing `module "compute"` on a service-name collision. Each was a text guess over files
        # that already passed `tofu validate` before commit; an undeclared variable, a duplicate output or a rejected
        # name is a validate / apply error that is reported back.

        # 3. Ensure modules are resolvable from both workspace root and subdirectories
        infra_modules = os.path.join(workspace_dir, "infra", "modules")
        if os.path.exists(infra_modules):
            root_modules = os.path.join(workspace_dir, "modules")
            if not os.path.exists(root_modules):
                try:
                    os.symlink("infra/modules", root_modules)
                except Exception as sym_err:
                    logger.debug(f"Could not symlink root modules: {sym_err}")

            parent_modules = os.path.join(os.path.dirname(workspace_dir), "modules")
            if not os.path.exists(parent_modules):
                try:
                    os.symlink(infra_modules, parent_modules)
                except Exception as sym_err:
                    logger.debug(f"Could not symlink parent modules: {sym_err}")

            # FD55-W6a DELETED (A13, HB-16): the text edits of the vendored compute-cloudrun `variables.tf` / `main.tf`
            # (enable_direct_iap / env_vars declarations, google-beta provider, iap_sa strip, dynamic env block) and of
            # the root `infra/workload/variables.tf` (env_vars). No module file is text-edited here (the golden-module
            # payload alignment below, A30, is W6b / W6d).

        # 4. FD55-W6a: the workspace-wide per-file .tf sanitize chain is DELETED (register FD55-W6a). Nothing above writes
        # a committed .tf any more (final newline included); the only .tf writers left in this method are the W6b / W6d
        # steps below (A27-A29 curing / wiring, A30 module alignment). Removed, in chain order: (A14, HB-10)
        # strip_invalid_hcl_blocks, which deleted every AI-declared output in custom.tf (C4 Gate A: 25/25 trees), the
        # IAP / project-number / budget blocks and duplicate client_config / kubernetes provider blocks; (A15) its
        # newline re-join that dropped the final newline of every file it saw; (A16) `module.X.service_url` ->
        # `service_uri`; (A17, HB-51) placeholder `locals` synthesis; (A18) `google_firestore_database.*` reference
        # rewrites; (A19, HC-17) a prepended `data "google_project" "project"`; (A20) `../modules/` / `../../bundles/`
        # source rewrites by substring (FD-4BW re-anchors flattened sources with the parser before this method);
        # (A21, HB-14) google-beta provider injection (per resource and in the root main.tf), the
        # `enforce_bucket_policy_only` -> uniform_bucket_level_access swap and the `repository_id` default reset;
        # (A22-A24, HB-19 / HB-20 / HB-21) Cloud Run timeouts, subnet `ignore_changes` and kubernetes_deployment
        # timeouts; (A25, HA-18) Workload Identity bindings with a guessed role; (A26, HE-15) `= =` and
        # `app-(default)` text fixes. A file that would not apply is a validate / apply error reported back.
        # Step 1 (register HS-08): auxiliary .tf files are never deleted or consolidated into custom.tf.
        # S2-F HB-13 (deleted): no reference is remapped to module.foundation.* (an undeclared reference fails
        # `tofu validate` as TF.REFERENCE_TO_UNDECLARED_RESOURCE).

        # FD55-W6b (register FD55-W6b+W6d) DELETED the apply-time "Autonomous IaC Curing" of committed .tf files, which
        # also queued every rewritten file for a commit to the deploy branch (A31, deleted too): (A27, HC-14)
        # self_correct_hcl_syntax, a delimiter "balancer" that deleted or appended `}` / `]` / `)` by an in-process
        # bracket count; (A28, HA-17) sanitize_hcl_locals_invariants, which rewrote `locals.` -> `local.` and
        # synthesized every undeclared `local.x` (IAM role lists, placeholder names); (A29, HB-24 / HA-13 Phase 0)
        # auto_wire_network_graph_dependencies, the parser-gated orphaned `depends_on` rebuild (register row 7, kept
        # until the FD-53 repair loop, which is live). Committed trees pass `tofu validate` before commit; a file that
        # would not parse or apply is a validate / apply error reported back (typed report on intent workspaces).
        # (FD-4AA, HA-14 apply caller: the semantic deduplication sweep is deleted; it ran between A27 and A28 and
        # deleted distinct resources sharing a (type, name) identifier.)

        # 4. FD55-W6d (HS-42): vendored golden modules are applied exactly as committed. A copy that differs from the
        # platform's payload is reported (PLATFORM.VENDORED_MODULE_STALE; deploy_workload also marks the workload
        # "IaC outdated" in Control Center); the fix is the Upgrade IaC pull request. The deleted A30 (HA-31 "Canonical
        # Golden Module Alignment") overwrote such files here and the deleted A31 committed them to the deploy branch.
        for mod_name, stale_paths in sorted(stale_vendored_module_files(workspace_dir).items()):
            for rel_path in stale_paths:
                logger.warning(
                    f"{PLATFORM_VENDORED_MODULE_STALE}: '{rel_path}' differs from the platform's golden module "
                    f"'{mod_name}'; applied as committed (IaC outdated: update it through an Upgrade IaC pull request)")

        # (FD-4AE: steps 6 'contract schema healing' and 3e 'SQLAlchemy synonym curing' were DELETED. They rewrote
        #  application code in the deploy workspace AND committed it back to the repo after QA; app code is never
        #  changed here.)

        logger.info(
            f"Prepared isolated workspace at {workspace_dir} with {len(hcl_files)} files."
        )
        return workspace_dir

    def _report_iac_outdated(self, product_id: str, trace_id: str, stale: Dict[str, List[str]]) -> None:
        """FD55-W6d (HS-42, register FD55-W6b+W6d): mark a workload whose vendored golden modules differ from the
        platform payload as "IaC outdated" in Control Center. It sets the same workload summary fields the
        Control Center drift inspection and the Upgrade IaC pull request maintain (``iac_drift_detected``,
        ``iac_drift_count`` = number of stale modules), which drive the catalog's "IaC Update" badge and "Outdated
        IaC" filter. Report only: no file is written and nothing reaches the repository; the fix is the Upgrade IaC
        pull request (refused while the workload is under Code Freeze, so a frozen workload stays reported).

        The flag is only raised, never cleared or lowered here: the drift inspection (which also compares bundles
        and version manifests) and a completed upgrade own clearing it. No workload record -> nothing is created.
        Best-effort: a Firestore error is logged and never fails the deploy."""
        if not stale or not self.db or not product_id:
            return
        try:
            ref = self.db.collection("workloads").document(product_id)
            snap = ref.get()
            if not getattr(snap, "exists", False):
                return
            data = snap.to_dict() or {}
            try:
                current_count = int(data.get("iac_drift_count") or 0)
            except (TypeError, ValueError):
                current_count = 0
            if data.get("iac_drift_detected") is True and current_count >= len(stale):
                return
            ref.set({"iac_drift_detected": True, "iac_drift_count": max(current_count, len(stale))}, merge=True)
            logger.info(f"{PLATFORM_VENDORED_MODULE_STALE}: marked '{product_id}' IaC outdated "
                        f"({sorted(stale)}; trace {trace_id})")
        except Exception as e:  # noqa: BLE001 - a report never fails the deploy
            logger.warning(f"Could not record IaC outdated for '{product_id}': {e}")

    def _resolve_iac_engine(self, product_id: str, iac_engine: Optional[str] = None) -> str:
        """Engine for a workload: explicit argument, then Firestore workloads.iac_engine, then platform settings,
        then OPENTOFU. Same order deploy_workload uses (FD-4AO: the drift check used to skip this entirely)."""
        active_engine = iac_engine
        if not active_engine and self.db and product_id:
            try:
                doc = self.db.collection("workloads").document(product_id).get()
                if doc.exists:
                    active_engine = (doc.to_dict() or {}).get("iac_engine")
            except Exception:
                pass
        if not active_engine:
            try:
                from shared.settings import get_platform_settings
                active_engine = getattr(get_platform_settings().orchestration, "default_iac_engine", "OPENTOFU")
            except Exception:
                active_engine = "OPENTOFU"
        return active_engine

    @staticmethod
    def _summarize_plan_changes(plan_json: Dict[str, Any]) -> Dict[str, Any]:
        """
        FD-4AO: summarize ``tofu show -json`` resource_changes. Any action list containing ``delete`` is a
        destroy, including replacements (``["delete","create"]`` and ``["create","delete"]``), which used to be
        counted as adds and reported as safe.
        """
        summary: Dict[str, Any] = {"add": 0, "change": 0, "destroy": 0, "resources": [], "destroy_addresses": []}
        for change in plan_json.get("resource_changes", []) or []:
            actions = list((change.get("change") or {}).get("actions") or [])
            address = change.get("address") or f"{change.get('type', '')}.{change.get('name', '')}"
            if "delete" in actions:
                summary["destroy"] += 1
                summary["destroy_addresses"].append(address)
                summary["resources"].append(f"{'-/+' if 'create' in actions else '-'} {address}")
            elif "create" in actions:
                summary["add"] += 1
                summary["resources"].append(f"+ {address}")
            elif "update" in actions:
                summary["change"] += 1
                summary["resources"].append(f"~ {address}")
        return summary

    def _read_saved_plan(
        self, workspace_dir: str, active_engine: str, plan_file: str = "tfplan"
    ) -> Tuple[Optional[Dict[str, Any]], str]:
        """Returns (parsed plan JSON, "") or (None, reason) for the saved plan file (default ``tfplan``)."""
        show_res = self._run_subprocess(["terraform", "show", "-json", plan_file], cwd=workspace_dir, iac_engine=active_engine)
        if not show_res.get("success"):
            return None, f"`show -json {plan_file}` failed: {show_res.get('stderr') or show_res.get('stdout') or 'no output'}"
        try:
            parsed = json.loads(show_res.get("stdout") or "")
        except Exception as json_err:
            return None, f"plan JSON could not be parsed: {json_err}"
        if not isinstance(parsed, dict):
            return None, "plan JSON is not an object"
        return parsed, ""

    def generate_plan(
        self, product_id: str, trace_id: str, hcl_files: Dict[str, str], iac_engine: Optional[str] = None
    ) -> Dict[str, Any]:
        """Runs init, validate and plan (-out=tfplan) and summarizes the saved plan. Never applies.
        ``is_safe_autonomous`` is True only for a readable plan with no destroys or replacements (FD-4AO)."""
        active_engine = self._resolve_iac_engine(product_id, iac_engine)

        # Guardrail 1: One-way state gate preventing tofu -> terraform downgrade
        self._validate_no_engine_downgrade(product_id, active_engine)

        try:   # FD-7L Phase 2b: the run's state location (PLATFORM: the platform bucket; F9 measurement project)
            state_ctx = self._runner_state_context(product_id, measure=True)
        except RunnerIdentityRefused as refused:
            return dict(refused.result(product_id, trace_id), is_safe_autonomous=False)
        try:
            self._stage_runner_ctx(trace_id, product_id, state_ctx)
            workspace_dir = self.prepare_workspace(product_id, trace_id, hcl_files, iac_engine=active_engine)
        except WorkflowValidationError as wf_err:   # FD55-W6c: typed APPLY.WORKFLOW_INVALID, never unhandled
            return dict(self._workflow_invalid_result(wf_err, product_id, trace_id), is_safe_autonomous=False)
        except EngineUnverifiable as unverified:   # RT14-22: typed, nothing is planned with an unverified engine
            logger.error(str(unverified))
            return {"status": "FAILED", "error_class": ENGINE_UNVERIFIABLE, "stage": ENGINE_STAGE,
                    "error": str(unverified), "product_id": product_id, "trace_id": trace_id,
                    "is_safe_autonomous": False}
        finally:
            self._take_staged_runner_ctx(trace_id, product_id)
        self._register_runner_ctx(workspace_dir, state_ctx)
        preinit_stop = self._preinit_policy_stop(workspace_dir, state_ctx, product_id, trace_id)
        if preinit_stop is not None:
            return dict(preinit_stop, is_safe_autonomous=False)

        # 1. IaC Init
        init_res = self._run_subprocess(["terraform", "init", "-input=false", "-no-color"], cwd=workspace_dir, iac_engine=active_engine)
        if not init_res["success"]:
            logger.error(f"IaC init failed: {init_res['stderr']}")
            failed = {
                "status": "INIT_FAILED",
                "error": init_res["stderr"],
                "stdout": init_res["stdout"],
            }
            if init_res.get("error_class"):   # FD-4AQ W1b: PROVIDER_NOT_ALLOWED
                failed.update(error_class=init_res["error_class"],
                              providers_not_allowed=init_res.get("providers_not_allowed") or [])
            return failed

        # 2. IaC Validate (FD-4AO: a failed validate stops here instead of being ignored)
        val_res = self._run_subprocess(["terraform", "validate", "-json"], cwd=workspace_dir, iac_engine=active_engine)
        if not val_res["success"]:
            logger.error(f"IaC validate failed: {val_res.get('stderr') or val_res.get('stdout')}")
            return {
                "status": "VALIDATE_FAILED",
                "error": val_res.get("stderr") or val_res.get("stdout") or "validate failed",
                "stdout": val_res.get("stdout", ""),
                "is_safe_autonomous": False,
            }

        # 3. IaC Plan
        plan_res = self._run_subprocess(
            ["terraform", "plan", "-out=tfplan", "-input=false", "-no-color"],
            cwd=workspace_dir,
            iac_engine=active_engine,
        )
        if not plan_res["success"]:
            logger.error(f"IaC plan failed: {plan_res['stderr']}")
            return {
                "status": "PLAN_FAILED",
                "error": plan_res["stderr"],
                "stdout": plan_res["stdout"],
            }

        # 4. Summarize the saved plan (fail closed: an unreadable plan is never "safe")
        plan_json, plan_err = self._read_saved_plan(workspace_dir, active_engine)
        if plan_json is None:
            logger.warning(f"Could not read the saved plan for '{product_id}': {plan_err}")
            resource_changes = self._summarize_plan_changes({})
        else:
            resource_changes = self._summarize_plan_changes(plan_json)

        result = {
            "status": "PLAN_READY",
            "product_id": product_id,
            "trace_id": trace_id,
            "workspace_dir": workspace_dir,
            "resource_changes": resource_changes,
            "is_safe_autonomous": plan_json is not None and resource_changes["destroy"] == 0,
            "plan_output": plan_res["stdout"],
            # SECRET-INITIAL-VERSION F1: every value the engine marks sensitive is masked before the JSON leaves
            # (tf-applier plan mode stores it in Firestore runner_results)
            "raw_plan_json": plan_redaction.redact_plan_json(plan_json) if plan_json else {},
        }
        if plan_err:
            result["plan_json_error"] = plan_err
        return result

    def apply_plan(self, product_id: str, trace_id: str, iac_engine: Optional[str] = None) -> Dict[str, Any]:
        """Applies ONLY a previously saved plan, and only when that plan contains no destroy or replacement
        (FD-4AO). Never runs a plan-less apply and never breaks a state lock. Writes audit logs to Firestore."""
        active_engine = self._resolve_iac_engine(product_id, iac_engine)

        # Guardrail 1: One-way state gate preventing tofu -> terraform downgrade
        self._validate_no_engine_downgrade(product_id, active_engine)

        workspace_dir = self._workspace_dir(trace_id, product_id)
        plan_path = os.path.join(workspace_dir, "tfplan")

        if not os.path.exists(workspace_dir):
            return {
                "status": "ERROR",
                "message": f"Workspace directory '{workspace_dir}' does not exist. Run plan first.",
            }

        def _refused(reason: str, message: str, **extra: Any) -> Dict[str, Any]:
            logger.warning(f"Refusing apply_plan for '{product_id}' ({reason}): {message}")
            return {
                "status": "REFUSED",
                "reason": reason,
                "message": message,
                "product_id": product_id,
                "trace_id": trace_id,
                **extra,
            }

        # FD-4AO: never run a plan-less `apply -auto-approve`.
        if not os.path.exists(plan_path):
            return _refused("NO_SAVED_PLAN", "No saved plan (tfplan) in the workspace. Run terraform_plan first.")

        # Re-derive safety from the saved plan itself; never trust an earlier summary.
        plan_json, plan_err = self._read_saved_plan(workspace_dir, active_engine)
        if plan_json is None:
            return _refused("PLAN_UNREADABLE", f"The saved plan could not be inspected: {plan_err}")
        # FD-4AW-b: the content policy on the exact saved plan, before anything else decides to apply it.
        # FD-7L Phase 2b: with this run's own state bucket, and PLATFORM_IDENTITY_TOUCHED in PER_WORKLOAD.
        try:
            state_ctx = self._workspace_runner_ctx(workspace_dir, product_id, measure=True)
            self._check_workspace_backend(workspace_dir, state_ctx, product_id, "saved-plan")
        except RunnerIdentityRefused as refused:
            return _refused(refused.error_class, refused.message, error_class=refused.error_class,
                            operator_required=True)
        violations = self._content_policy_findings(plan_json, state_ctx, product_id, trace_id,
                                                        workspace_dir=workspace_dir)
        if violations:
            refusal = content_policy_refusal(product_id, trace_id, violations)
            return _refused(ERROR_APPLY_CONTENT_POLICY, refusal["error"], error_class=ERROR_APPLY_CONTENT_POLICY,
                            content_policy_violations=refusal["content_policy_violations"])
        changes = self._summarize_plan_changes(plan_json)
        if changes["destroy"]:
            return _refused(
                "PLAN_HAS_DESTROY",
                "The saved plan destroys or replaces resources; destroys require a plan-based human approval "
                "and are never applied through this endpoint.",
                destroy_addresses=changes["destroy_addresses"],
                resource_changes=changes,
            )

        # Lane 14 PR-0 (FD-4S): the compliance plan gate on the exact saved plan, before the apply.
        gate = self._compliance_gate_check(product_id, trace_id, workspace_dir, active_engine, plan_json=plan_json)
        if not gate.get("passed"):
            gate_result = gate.get("result") or {}
            return _refused(
                gate_result.get("error_class") or compliance_gate.ERROR_UNAVAILABLE,
                gate_result.get("error") or "compliance gate refused the apply",
                error_class=gate_result.get("error_class") or compliance_gate.ERROR_UNAVAILABLE,
                compliance_gate=gate_result.get("compliance_gate") or {},
            )

        cmd = ["terraform", "apply", "-input=false", "-auto-approve", "tfplan"]

        apply_res = self._run_subprocess(cmd, cwd=workspace_dir, iac_engine=active_engine)

        # FD-4H: never break a state lock automatically; report it with the STATE_LOCKED contract.
        if not apply_res["success"]:
            lock_info = self.parse_state_lock_info(apply_res.get("stderr", ""), max_age_minutes=self.stale_lock_max_age_min)
            if lock_info:
                locked = self._state_locked_result(
                    product_id,
                    lock_info,
                    phase="apply_plan",
                    stdout=apply_res.get("stdout", ""),
                    stderr=apply_res.get("stderr", ""),
                )
                locked["trace_id"] = trace_id
                return locked

        # Retrieve outputs
        outputs, _raw = self._read_tofu_outputs(workspace_dir, active_engine)   # RT14-09: masked

        # Log deployment to Firestore audit trail
        deployment_record = {
            "product_id": product_id,
            "trace_id": trace_id,
            "applied_at": datetime.now(timezone.utc).isoformat(),
            "applied_iac_engine": (active_engine or "OPENTOFU").strip().lower(),
            "status": "SUCCESS" if apply_res["success"] else "FAILED",
            "stdout": apply_res["stdout"],
            "stderr": apply_res["stderr"],
            "outputs": outputs,
        }
        if self.db:
            try:
                self.db.collection("terraform_deployments").document(trace_id).set(deployment_record)
                self.db.collection("workloads").document(product_id).set({
                    "applied_iac_engine": (active_engine or "OPENTOFU").strip().lower(),
                    "last_applied_engine": (active_engine or "OPENTOFU").strip().lower(),
                }, merge=True)
                logger.info(f"Recorded Terraform/OpenTofu deployment audit in Firestore for {trace_id}")
            except Exception as db_err:
                logger.warning(f"Failed to record Firestore deployment audit: {db_err}")

        return {
            "status": "APPLIED" if apply_res["success"] else "FAILED",
            "product_id": product_id,
            "trace_id": trace_id,
            "outputs": outputs,
            "stdout": apply_res["stdout"],
            "stderr": apply_res["stderr"],
            "applied_iac_engine": (active_engine or "OPENTOFU").strip().lower(),
        }

    def _sync_feature_requests(
        self,
        product_id: str,
        trace_id: str,
        is_successful_deploy: bool,
        error_msg: Optional[str] = None,
        service_url: Optional[str] = None,
    ) -> None:
        """
        Synchronizes the feature request this run built in Firestore.
        For orchestrated runs (intake-*, retry-*, fastpath-*), orchestrator-gateway owns terminal FAILED status.
        mcp-terraform-server only updates feature_requests to COMPLETED on success, or stores
        intermediate error provenance without prematurely declaring terminal FAILED while
        self-healing loops (terraform_remediation) are active.

        FEATURE-REQUEST-CLOSE-OWN-ONLY: only the run's own request changes (`_run_built_feature_request`), never a
        request filed while it ran. The run record unreadable changes nothing: it is not read as "no recorded id".
        """
        if not self.db or not product_id:
            return

        is_orchestrated = bool(trace_id and any(trace_id.startswith(p) for p in ["intake-", "retry-", "fastpath-"]))
        now_iso = datetime.now(timezone.utc).isoformat()

        try:
            recorded_request_id = self._run_recorded_request_id(trace_id)
            active_frs = self.db.collection("feature_requests").where("product_id", "==", product_id).stream()
            for fr in active_frs:
                fr_data = fr.to_dict() or {}
                if (fr_data.get("status") != "COMPLETED"
                        and _run_built_feature_request(fr.id, fr_data, recorded_request_id, trace_id)):
                    if is_successful_deploy:
                        # On successful deployment, mark COMPLETED
                        self.db.collection("feature_requests").document(fr.id).set({
                            "status": "COMPLETED",
                            "completed_at": now_iso,
                            "failed_at": None,
                            "service_url": service_url,
                            "trace_id": trace_id,
                            "error": None,
                        }, merge=True)
                        logger.info(f"Marked feature request '{fr.id}' as COMPLETED in Firestore")
                    elif not is_orchestrated:
                        # Standalone un-orchestrated runs declare FAILED directly
                        self.db.collection("feature_requests").document(fr.id).set({
                            "status": "FAILED",
                            "failed_at": now_iso,
                            "trace_id": trace_id,
                            "error": error_msg or "",
                        }, merge=True)
                        logger.info(f"Marked standalone feature request '{fr.id}' as FAILED in Firestore")
                    else:
                        # Orchestrated runs with potential remediation: record error provenance but keep IN_PROGRESS
                        self.db.collection("feature_requests").document(fr.id).set({
                            "last_iac_error": error_msg or "",
                            "trace_id": trace_id,
                        }, merge=True)
                        logger.info(f"Recorded intermediate IaC error for feature request '{fr.id}'; deferred terminal status to orchestrator.")
        except Exception as fr_err:
            logger.warning(f"Could not update feature requests status: {type(fr_err).__name__}: {fr_err}")

    def _run_recorded_request_id(self, trace_id: str) -> Optional[str]:
        """The feature request recorded on `pipeline_executions/{trace_id}`; None when the run recorded none (or has no
        record). A store error is raised to the caller."""
        if not trace_id:
            return None
        snap = self.db.collection("pipeline_executions").document(trace_id).get()
        recorded = (snap.to_dict() or {}).get("request_id") if snap.exists else None
        return recorded if isinstance(recorded, str) and recorded else None

    def apply_infrastructure(
        self,
        product_id: str,
        trace_id: str,
        target_project_id: Optional[str] = None,
        branch: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Convenience method for applying infrastructure and syncing feature requests."""
        res = self.apply_plan(product_id=product_id, trace_id=trace_id)
        is_success = res.get("status") in ("APPLIED", "SUCCESS")
        err = res.get("stderr") or res.get("error") or ""
        service_url = self._confirmed_output_url(res, product_id, target_project_id) if is_success else None
        self._sync_feature_requests(
            product_id=product_id,
            trace_id=trace_id,
            is_successful_deploy=is_success,
            error_msg=err,
            service_url=service_url,
        )
        return res

    def _confirmed_output_url(self, res: Mapping[str, Any], product_id: str,
                              target_project_id: Optional[str]) -> Optional[str]:
        """FD-102: apply_infrastructure's URL (its `url` output) under the deploy's rule: only a Run-API-confirmed URL
        (confirm_cloud_run_service_url, the child project's listing in the platform region), else None with the typed
        SERVICE_URL_UNKNOWN reason logged. No output URL: None, and nothing is listed."""
        outputs = res.get("outputs") if isinstance(res, Mapping) else None
        entry = outputs.get("url") if isinstance(outputs, Mapping) else None
        value = entry.get("value") if isinstance(entry, Mapping) else None
        if value is None or value == "":
            return None
        if not isinstance(target_project_id, str) or not target_project_id:
            # R2: no project id is built from the product id; without the run's child project nothing is listed
            logger.warning(f"{SERVICE_URL_UNKNOWN} ({SERVICE_URL_API_UNAVAILABLE}) for '{product_id}': no target "
                           "project, so the applied output URL cannot be confirmed and is not recorded.")
            return None
        project = target_project_id
        try:
            region = self._resolve_region()
        except RegionUnavailable as region_err:
            logger.warning(f"{SERVICE_URL_UNKNOWN} ({SERVICE_URL_API_UNAVAILABLE}) for '{product_id}': {region_err}")
            return None
        listed, list_reason = self._list_cloud_run_services(project, region)
        confirmed, reason = confirm_cloud_run_service_url(value, listed)
        if not confirmed:
            logger.warning(f"{SERVICE_URL_UNKNOWN} ({list_reason or reason}) for '{product_id}' in '{project}': the "
                           "applied output URL is not confirmed by the Cloud Run API, so it is not recorded.")
            return None
        return confirmed

    def check_drift(self, product_id: str, trace_id: str, iac_engine: Optional[str] = None) -> Dict[str, Any]:
        """Drift detection via `plan -detailed-exitcode` with the workload's resolved engine.
        Exit 0 = IN_SYNC, 2 = DRIFT_DETECTED, anything else = ERROR (FD-4AO: errors were reported IN_SYNC)."""
        workspace_dir = self._workspace_dir(trace_id, product_id)
        if not os.path.exists(workspace_dir):
            return {"status": "ERROR", "message": "Workspace not found"}

        active_engine = self._resolve_iac_engine(product_id, iac_engine)
        # Guardrail 1 (red-team F-5): same one-way tofu -> terraform downgrade gate as plan/apply.
        self._validate_no_engine_downgrade(product_id, active_engine)
        # FD-7L Phase 2b: the run's state location, and the pre-init policy on the workspace before the plan. In
        # PER_WORKLOAD the workspace must have been prepared for the same bucket (its backend.tf names it).
        try:
            state_ctx = self._runner_state_context(product_id, measure=True)
            self._check_workspace_backend(workspace_dir, state_ctx, product_id, "drift")
        except RunnerIdentityRefused as refused:
            return dict(refused.result(product_id, trace_id), status="ERROR",
                        message=f"{refused.error_class}: {refused.message}")
        preinit_stop = self._preinit_policy_stop(workspace_dir, state_ctx, product_id, trace_id)
        if preinit_stop is not None:
            return dict(preinit_stop, status="ERROR", message=preinit_stop["error"])
        res = self._run_subprocess(
            ["terraform", "plan", "-detailed-exitcode", "-no-color"], cwd=workspace_dir, iac_engine=active_engine
        )
        exit_code = res.get("exit_code")
        if exit_code == 0:
            status = "IN_SYNC"
        elif exit_code == 2:
            status = "DRIFT_DETECTED"
        else:
            status = "ERROR"
        result = {
            "status": status,
            "has_drift": status == "DRIFT_DETECTED",
            "exit_code": exit_code,
            "stdout": res.get("stdout", ""),
        }
        if status == "ERROR":
            result["error"] = res.get("stderr") or res.get("stdout") or f"plan exited with code {exit_code}"
        return result

    @staticmethod
    def parse_state_lock_info(stderr: str, max_age_minutes: int = 20) -> Optional[Dict[str, Any]]:
        """
        Extracts lock ID, holder, path, and creation time from Terraform lock error message.
        Determines whether the lock is stale (> max_age_minutes old).
        """
        if not stderr or "Error acquiring the state lock" not in stderr:
            return None

        lock_id_m = re.search(r'ID:\s+([^\n]+)', stderr)
        who_m = re.search(r'Who:\s+([^\n]+)', stderr)
        created_m = re.search(r'Created:\s+([^\n]+)', stderr)
        path_m = re.search(r'Path:\s+([^\n]+)', stderr)
        op_m = re.search(r'Operation:\s+([^\n]+)', stderr)

        lock_id = lock_id_m.group(1).strip() if lock_id_m else "unknown"
        who = who_m.group(1).strip() if who_m else "unknown"
        created = created_m.group(1).strip() if created_m else "unknown"
        path = path_m.group(1).strip() if path_m else "unknown"
        operation = op_m.group(1).strip() if op_m else "unknown"

        age_seconds = 0.0
        if created != "unknown":
            try:
                clean_dt = created.strip()
                if " UTC" in clean_dt:
                    clean_dt = clean_dt.replace(" UTC", "")
                    parts = clean_dt.split(".")
                    dt_base = parts[0]
                    parsed_dt = datetime.strptime(dt_base, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                    age_seconds = (datetime.now(timezone.utc) - parsed_dt).total_seconds()
                else:
                    dt = datetime.fromisoformat(clean_dt)
                    if not dt.tzinfo:
                        dt = dt.replace(tzinfo=timezone.utc)
                    age_seconds = (datetime.now(timezone.utc) - dt).total_seconds()
            except Exception as parse_err:
                logger.debug(f"Could not parse lock created timestamp '{created}': {parse_err}")

        is_stale = age_seconds > (max_age_minutes * 60) if age_seconds > 0 else False

        return {
            "lock_id": lock_id,
            "who": who,
            "created": created,
            "path": path,
            "operation": operation,
            "age_seconds": round(age_seconds, 1),
            "is_stale": is_stale,
        }

    def _read_state_lock(self, product_id: str, bucket: Optional[str] = None,
                         client_project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        FD-4H: READ-ONLY inspection of the workload's GCS state lock object.

        Returns None when no lock object exists. Lock identity comes from GCS object metadata (the OpenTofu GCS
        backend uses the object generation as the lock ID and the object creation time as the lock time) plus the
        JSON LockInfo body (Who / Operation). Raises when the bucket cannot be read; callers must then proceed
        without acting on the lock. This method never writes or deletes anything.
        ``bucket`` (FD-7L Phase 2b): the run's state bucket; None = the platform bucket, as before.
        ``client_project``: a Per-workload run's project (the read goes through its brokered deployer).
        """
        found = self._read_state_lock_object(product_id, self.state_bucket if bucket is None else bucket,
                                             client_project=client_project)
        return found[0] if found is not None else None

    def _read_state_lock_object(self, product_id: str, bucket: str, *, client_project: Optional[str] = None,
                                require_body: bool = False) -> Optional[Tuple[Dict[str, Any], Optional[Dict[str, Any]]]]:
        """(lock_info as _read_state_lock returns it, the parsed LockInfo JSON body or None when the body could not be
        read), or None when no lock object exists. Read-only; raises when the bucket cannot be read.
        `bucket` is required (review F7: no silent default to the platform bucket). `client_project` (FD-7L 2b, a
        Per-workload run): the read uses `_child_storage_client(client_project)`, i.e. the workload's brokered
        deployer (the platform identity has no rights on the workload's bucket after the final apply); without it,
        the platform client as before. `require_body`: a body that cannot be read raises instead of being None."""
        from google.cloud import storage

        bucket_name = bucket
        lock_name = f"workloads/{product_id}/default.tflock"
        if client_project:
            client = self._child_storage_client(client_project)
        else:
            client = storage.Client(project=self.project_id)
        blob = client.bucket(bucket_name).get_blob(lock_name)
        if blob is None:
            return None
        generation = getattr(blob, "generation", None)
        if not isinstance(generation, int):
            raise ValueError(f"lock object gs://{bucket_name}/{lock_name} has no readable generation")

        body: Dict[str, Any] = {}
        body_read: Optional[Dict[str, Any]] = None
        try:
            raw = blob.download_as_bytes(if_generation_match=generation)
            parsed = json.loads(raw) if raw else {}
            body = parsed if isinstance(parsed, dict) else {}
            body_read = body
        except Exception as body_err:
            if require_body:
                raise
            logger.warning(f"Could not read the lock body for '{product_id}' (generation {generation}): {body_err}")

        created_dt = getattr(blob, "time_created", None)
        created = "unknown"
        age_seconds: Optional[float] = None
        if isinstance(created_dt, datetime):
            if not created_dt.tzinfo:
                created_dt = created_dt.replace(tzinfo=timezone.utc)
            created = created_dt.isoformat()
            age_seconds = round((datetime.now(timezone.utc) - created_dt).total_seconds(), 1)

        return {
            "lock_id": str(generation),
            "who": str(body.get("Who") or "unknown"),
            "created": created,
            "path": f"gs://{bucket_name}/{lock_name}",
            "operation": str(body.get("Operation") or "unknown"),
            "age_seconds": age_seconds,
            "source": "gcs",
        }, body_read

    ORCHESTRATION_SETTING_TTL_SECONDS = 60.0   # FD-4CI-b RT F5: like the shared settings cache

    def _orchestration_setting(self, name: str, fallback: int) -> int:
        """FD-4CI-b: Platform Settings `orchestration.<name>` (a positive int) through this server's own client
        (FD-4AL pattern); `fallback` (the value before the setting was wired) when it cannot be read. RT F5: the
        result (a fallback too) is kept per instance for ORCHESTRATION_SETTING_TTL_SECONDS, so plan/apply/destroy do
        not each read Firestore and an unreadable store is logged at most once per TTL."""
        cache = getattr(self, "_orchestration_setting_cache", None)
        if cache is None:
            cache = self._orchestration_setting_cache = {}
        hit = cache.get(name)
        now = time.monotonic()
        if hit is not None and now - hit[1] < self.ORCHESTRATION_SETTING_TTL_SECONDS:
            return hit[0]
        try:
            from shared.settings import is_setting_int, stored_setting_value
        except ImportError:
            return fallback
        value = stored_setting_value(getattr(self, "db", None), "orchestration", name, fallback,
                                     accept=lambda v: is_setting_int(v) and v > 0)
        cache[name] = (value, now)
        return value

    @property
    def lock_timeout(self) -> str:
        """FD-4CI-b: the -lock-timeout (e.g. "180s"): an explicit assignment, else $TF_LOCK_TIMEOUT, else Settings
        orchestration.terraform_lock_timeout_seconds, else 180s. Waiting longer or shorter never breaks a lock."""
        explicit = getattr(self, "_lock_timeout_override", None)
        if explicit is not None:
            return explicit
        return os.getenv("TF_LOCK_TIMEOUT") or f"{self._orchestration_setting('terraform_lock_timeout_seconds', 180)}s"

    @lock_timeout.setter
    def lock_timeout(self, value: str) -> None:
        self._lock_timeout_override = value

    @property
    def stale_lock_max_age_min(self) -> int:
        """FD-4CI-b: the age (minutes) above which a held lock is REPORTED stale (lock_info.is_stale; no lock is ever
        cleared automatically): an explicit assignment, else $TF_STALE_LOCK_MAX_AGE_MINUTES, else Settings
        orchestration.stale_lock_threshold_minutes, else 20."""
        explicit = getattr(self, "_stale_lock_max_age_override", None)
        if explicit is not None:
            return explicit
        env = os.getenv("TF_STALE_LOCK_MAX_AGE_MINUTES")
        if env:
            try:
                return int(env)
            except ValueError:
                logger.warning(f"Unparseable TF_STALE_LOCK_MAX_AGE_MINUTES '{env}'; using the platform setting.")
        return self._orchestration_setting("stale_lock_threshold_minutes", 20)

    @stale_lock_max_age_min.setter
    def stale_lock_max_age_min(self, value: int) -> None:
        self._stale_lock_max_age_override = value

    def _lock_timeout_seconds(self) -> float:
        """``self.lock_timeout`` (the ``-lock-timeout`` passed to tofu, e.g. "180s", "3m", "1h") in seconds."""
        raw = str(self.lock_timeout or "").strip().lower()
        units = {"s": 1.0, "m": 60.0, "h": 3600.0}
        try:
            if raw and raw[-1] in units:
                return max(0.0, float(raw[:-1]) * units[raw[-1]])
            return max(0.0, float(raw))
        except ValueError:
            logger.warning(f"Unparseable TF_LOCK_TIMEOUT '{self.lock_timeout}'; using 180s for the pre-flight wait.")
            return 180.0

    def _wait_for_state_lock_release(self, product_id: str, poll_seconds: float = 5.0,
                                     bucket: Optional[str] = None,
                                     client_project: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        FD-4H pre-flight (red-team F-4): read-only wait for a held lock to be released, bounded by the same
        ``-lock-timeout`` OpenTofu itself would wait, so a transient plan/drift lock does not fail a deploy.
        Returns None once no lock object exists, or the lock that is still held when the timeout elapses.
        Raises when the lock cannot be read (callers then proceed; tofu's own locking still applies).
        Never writes or deletes anything.
        """
        deadline = time.monotonic() + self._lock_timeout_seconds()
        while True:
            lock = (self._read_state_lock(product_id) if bucket is None
                    else self._read_state_lock(product_id, bucket, client_project=client_project))
            if lock is None:
                return None
            remaining = deadline - time.monotonic()
            if remaining <= 0 or state_move_lock_kind(lock) is not None:
                # FD-7L Phase 2b: a migration tombstone / migration lock is never released by waiting
                return lock
            logger.info(
                f"State for '{product_id}' is locked (lock ID {lock.get('lock_id')}, held by {lock.get('who')}); "
                f"waiting up to {int(remaining)}s for release before deploying."
            )
            time.sleep(min(poll_seconds, remaining))

    @staticmethod
    def _tofu_lock_who() -> str:
        """
        The ``Who`` string OpenTofu records in a lock taken by this process: ``statemgr.NewLockInfo()`` uses
        ``fmt.Sprintf("%s@%s", user.Current().Username, os.Hostname())``. Pure-Go ``user.Current()`` (release
        binaries are CGO-disabled) reads /etc/passwd for the uid, then falls back to ``$USER``; on error the
        username is empty. Mirrors that order exactly (H-3); used for attribution only, never as proof of liveness.
        """
        import socket

        user_name = ""
        try:
            import pwd

            user_name = pwd.getpwuid(os.getuid()).pw_name or ""
        except Exception:
            user_name = ""
        if not user_name:
            user_name = os.environ.get("USER", "")
        try:
            host = socket.gethostname()
        except Exception:
            host = ""
        return f"{user_name}@{host}"

    def _state_locked_result(
        self,
        product_id: str,
        lock_info: Dict[str, Any],
        phase: str,
        stdout: str = "",
        stderr: str = "",
    ) -> Dict[str, Any]:
        """
        FD-4H error contract for a held state lock (machine-routable): ``status=FAILED``,
        ``error_class=STATE_LOCKED``, ``error`` starting with the fixed ``STATE_LOCKED:`` sentinel and naming the
        exact operator action, plus ``lock_info`` and ``lock_holder``. No lock is ever broken automatically.
        """
        lock_id = lock_info.get("lock_id") or "unknown"
        who = lock_info.get("who") or "unknown"
        created = lock_info.get("created") or "unknown"
        operation = lock_info.get("operation") or "unknown"
        move_kind = state_move_lock_kind(lock_info)   # FD-7L Phase 2b (P1): never advise a force-unlock of these
        if move_kind == "tombstone":
            action = ("This lock is StackVend's state-migration tombstone: the workload's state moved to its own "
                      "bucket, and this copy must stay locked. Do not force-unlock it. A Per-workload install deploys "
                      "from the moved state; on a Shared install an operator restores the platform copy first "
                      "(runner identity backfill step restore_platform_state).")
        elif move_kind == "migration":
            action = ("This lock is held by StackVend's state migration (runner identity backfill). Do not "
                      "force-unlock it: run again when the migration has finished.")
        else:
            action = (f"If no apply is running for this workload, an "
                      f"operator can clear the lock with POST /api/workloads/{product_id}/force-unlock "
                      f'{{"product_id": "{product_id}", "lock_id": "{lock_id}"}}.')
        error = (
            f"{STATE_LOCKED_SENTINEL} OpenTofu state for '{product_id}' is locked "
            f"(lock ID {lock_id}, held by {who} since {created}, operation {operation}; detected at {phase}). "
            f"StackVend never breaks state locks automatically. " + action
        )
        logger.error(error)
        this_runner_who = self._tofu_lock_who()
        if move_kind is not None:
            return {
                "status": "FAILED", "error_class": "STATE_LOCKED", "error": error, "product_id": product_id,
                "lock_info": lock_info, "state_move_lock": move_kind, "operator_required": True,
                "lock_holder": {"verdict": "STACKVEND_STATE_MOVE", "reason": f"FD-7L {move_kind} lock",
                                "this_runner_who": this_runner_who, "same_identity_as_this_runner": False},
                "stdout": stdout, "stderr": stderr,
            }
        return {
            "status": "FAILED",
            "error_class": "STATE_LOCKED",
            "error": error,
            "product_id": product_id,
            "lock_info": lock_info,
            "lock_holder": {
                "verdict": "NOT_ASSESSED",
                "reason": "automatic stale-lock recovery is disabled; an operator must confirm the holder is gone",
                "this_runner_who": this_runner_who,
                # Same identity does NOT mean same process: every StackVend runner shares one image and uid.
                "same_identity_as_this_runner": who == this_runner_who,
            },
            "stdout": stdout,
            "stderr": stderr,
        }

    LOCK_READ_ATTEMPTS = 3
    LOCK_READ_RETRY_SECONDS = (0.5, 1.5)

    @staticmethod
    def _lock_read_is_transient(err: BaseException) -> bool:
        """Review F6: a lock read worth repeating, by exception class only: google-api-core's own transient
        classifier (429 / 500 / 502 / 503 / 504, connection errors), and a 412 / 404 on the body read (the lock was
        released or replaced between the metadata and the body reads, so a fresh read sees the new state)."""
        try:
            from google.api_core import exceptions as gexc
            from google.api_core.retry import if_transient_error
        except ImportError:  # pragma: no cover - google-api-core ships with google-cloud-storage
            return isinstance(err, (TimeoutError, ConnectionError))
        return bool(if_transient_error(err)) or isinstance(err, (gexc.PreconditionFailed, gexc.NotFound,
                                                                  TimeoutError, ConnectionError))

    def _read_lock_for_unlock(self, product_id: str,
                              ctx: "RunnerStateContext") -> Optional[Tuple[Dict[str, Any], Dict[str, Any]]]:
        """P1 + review F6: the lock object and its body for force_unlock, read up to LOCK_READ_ATTEMPTS times while
        the failure is transient; the last failure is raised (the caller refuses with STATE_LOCK_UNREADABLE).
        Per-workload: through the workload's brokered deployer (`client_project`)."""
        attempt = 0
        while True:
            try:
                return self._read_state_lock_object(product_id, ctx.bucket, require_body=True,
                                                    client_project=ctx.project_id if ctx.per_workload else None)
            except ri.RunnerIdentityError:
                raise
            except Exception as err:  # noqa: BLE001 - classified below; anything else is raised at once
                if attempt + 1 >= self.LOCK_READ_ATTEMPTS or not self._lock_read_is_transient(err):
                    raise
                logger.warning(f"STATE_LOCK_READ_RETRY: reading the state lock of '{product_id}' raised "
                               f"{type(err).__name__}; reading it again")
                time.sleep(self.LOCK_READ_RETRY_SECONDS[min(attempt, len(self.LOCK_READ_RETRY_SECONDS) - 1)])
                attempt += 1

    def force_unlock(
        self,
        product_id: str,
        lock_id: str,
        trace_id: Optional[str] = None,
        workspace_dir: Optional[str] = None,
        iac_engine: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Force-unlocks a stuck Terraform GCS state lock for a given workload.

        ``workspace_dir`` is INTERNAL ONLY (passed by apply/self-heal callers with a directory this service
        built via ``_workspace_dir``); it must never be populated from request input (FD-4G).

        FD-7L Phase 2b (plan 2.6 / 2.7 step 6, precondition P1; every mode): the run's state bucket comes from
        `_runner_state_context` (PLATFORM: the platform bucket, as before), and the lock object is read FIRST. The
        migration tombstone and the migration lock are refused (STATE_MOVED_DO_NOT_UNLOCK); a lock object that cannot
        be read, or whose body cannot be read, is refused too (STATE_LOCK_UNREADABLE): nothing is unlocked on doubt.
        No lock object: OpenTofu decides, as before.
        """
        target_dir = workspace_dir
        new_workspace = not target_dir or not os.path.exists(target_dir)
        if new_workspace:   # FD-4G: the ids are validated (UnsafePathError) before anything is read or written
            tid = trace_id or f"force-unlock-{product_id}-{int(datetime.now(timezone.utc).timestamp())}"
            target_dir = self._workspace_dir(tid, product_id)
        try:
            state_ctx = self._runner_state_context(product_id)
        except RunnerIdentityRefused as refused:
            return dict(refused.result(product_id, trace_id), lock_id=lock_id)

        def _refuse(error_class: str, message: str, **extra: Any) -> Dict[str, Any]:
            error = f"{error_class}: {message}. Nothing was unlocked."
            logger.error(error)
            return {"status": "FAILED", "error_class": error_class, "error": error, "product_id": product_id,
                    "lock_id": lock_id, "operator_required": True, **extra}

        try:
            found = (self._read_lock_for_unlock(product_id, state_ctx) if state_ctx.bucket else False)
        except ri.RunnerIdentityError as read_err:   # Per-workload: no brokered deployer in this process
            return _refuse(read_err.code, read_err.detail)
        except Exception as read_err:  # noqa: BLE001 - an unreadable lock is never unlocked blind
            found = False
            read_why = f"{type(read_err).__name__}: {read_err}"
        else:
            read_why = "no state bucket is configured" if found is False else ""
        if found is False:
            return _refuse(STATE_LOCK_UNREADABLE, f"the state lock of '{product_id}' could not be read ({read_why}), "
                                                  "so it cannot be shown not to be a StackVend state-migration lock")
        if found is not None:
            lock_info, body = found
            if body is None:
                return _refuse(STATE_LOCK_UNREADABLE, f"the state lock body of '{product_id}' (lock ID "
                                                      f"{lock_info.get('lock_id')}) could not be read")
            move_kind = state_move_lock_kind(body)
            if move_kind is not None:
                what = ("its state moved to the workload's own bucket (migration tombstone)" if move_kind == "tombstone"
                        else "a state migration holds it (migration lock)")
                return _refuse(STATE_MOVED_DO_NOT_UNLOCK,
                               f"the state lock of '{product_id}' ({lock_info.get('path')}) is StackVend's: {what}; "
                               "it is never force-unlocked", state_move_lock=move_kind, lock_info=lock_info)

        if new_workspace:
            os.makedirs(target_dir, exist_ok=True)
            self._register_runner_ctx(target_dir, state_ctx)
            backend_hcl = f"""terraform {{
  backend "gcs" {{
    bucket = "{state_ctx.bucket}"
    prefix = "workloads/{product_id}"
  }}
}}
"""
            with open(os.path.join(target_dir, "backend.tf"), "w") as f:
                f.write(backend_hcl)
            preinit_stop = self._preinit_policy_stop(target_dir, state_ctx, product_id, trace_id)
            if preinit_stop is not None:
                return dict(preinit_stop, lock_id=lock_id)

            init_res = self._run_subprocess(["terraform", "init", "-input=false", "-no-color"], cwd=target_dir, iac_engine=iac_engine)
            if not init_res["success"]:
                logger.error(f"IaC init failed during force-unlock for {product_id}: {init_res['stderr']}")
                return {
                    "status": "FAILED",
                    "error": f"IaC init failed during force-unlock: {init_res['stderr']}",
                    "product_id": product_id,
                    "lock_id": lock_id,
                }

        unlock_res = self._run_subprocess(
            ["terraform", "force-unlock", "-force", lock_id],
            cwd=target_dir,
            iac_engine=iac_engine,
        )

        if unlock_res["success"]:
            logger.info(f"Successfully force-unlocked Terraform state for {product_id} (Lock ID: {lock_id})")
            return {
                "status": "UNLOCKED",
                "product_id": product_id,
                "lock_id": lock_id,
                "stdout": unlock_res.get("stdout", ""),
            }
        else:
            logger.error(f"Failed to force-unlock Terraform state for {product_id}: {unlock_res.get('stderr')}")
            return {
                "status": "FAILED",
                "product_id": product_id,
                "lock_id": lock_id,
                "error": unlock_res.get("stderr") or unlock_res.get("stdout"),
            }

    # ------------------------------------------------------------------------------ FD-7L Phase 4 (plan 2.10, §8 row 4)
    # On a Per-workload install the run reads exactly the repository vending's SIGNED provenance record pins: GitHub
    # with the read-only, single-repository token vending mints for this execution's session (`/runner/repo-token`),
    # Serverless Git with the job's own Google ID token (the git server's read-only invoker class). It never reads
    # GITHUB_TOKEN, the GitHub App key in Secret Manager, the cached platform token or the legacy GitHub REST fallback.
    # A Shared install takes the read below exactly as before (nothing here is consulted).
    REPO_READ_PROVIDERS = ("GITHUB", "SERVERLESS_GIT")

    def _brokered_repo_runner(self, product_id: str, owner: str, repo_name: str) -> Optional[Tuple[Any, Dict[str, Any]]]:
        """None on a Shared install. Per-workload: (the brokered runner registered for `product_id`, the repository
        its signed provenance record pins), after checking that the requested repository is that one. Anything else
        raises RunnerIdentityRefused before any repository call."""
        try:
            mode = self._runner_identity_mode()
        except ri.RunnerIdentityError as e:   # an unreadable / invalid mode is a typed stop, never a guess
            raise RunnerIdentityRefused(e.code, e.detail) from None
        if mode != ri.MODE_PER_WORKLOAD:
            return None
        ignored = [name for name in runner_creds.REPO_READ_IGNORED_ENV if name in os.environ]   # names only
        if ignored:
            logger.warning(f"{runner_creds.RUNNER_ENV_IGNORED}: {', '.join(ignored)} (a Per-workload run reads its "
                           "repository only with vending's read-only token or the job's own ID token)")
        with self._WORKSPACE_RUNNER_LOCK:
            registered = list(self.__dict__.get("_workspace_runners", {}).values())
        runners = list({id(r): r for r in registered if getattr(r, "product_id", None) == product_id}.values())
        if not runners:
            raise RunnerIdentityRefused(
                runner_creds.RUNNER_IDENTITY_NOT_REGISTERED,
                f"the repository of '{product_id}' is read only with the read-only credentials of a tf-applier "
                "execution that vending dispatched, and none are registered for it")
        if len(runners) > 1:
            raise RunnerIdentityRefused(runner_creds.RUNNER_TARGET_MISMATCH,
                                        f"more than one brokered run of '{product_id}' is registered in this process")
        runner = runners[0]
        pinned = runner.repository
        full_name = pinned.get("full_name") if isinstance(pinned, dict) else None
        provider = pinned.get("provider") if isinstance(pinned, dict) else None
        if not isinstance(full_name, str) or not full_name or provider not in self.REPO_READ_PROVIDERS:
            raise RunnerIdentityRefused(
                runner_creds.RUNNER_REPOSITORY_NOT_PINNED,
                f"the signed runner identity record of '{product_id}' pins no readable repository "
                f"(provider {provider!r})")
        requested = f"{owner}/{repo_name}"
        same = requested.lower() == full_name.lower() if provider == "GITHUB" else requested == full_name
        if not same:
            raise RunnerIdentityRefused(runner_creds.RUNNER_TARGET_MISMATCH,
                                        f"'{product_id}': the deploy names repository {requested!r}, its signed "
                                        f"record pins {full_name!r}")
        return runner, dict(pinned)

    def _fetch_repo_files_brokered(self, product_id: str, branch: str, runner: Any,
                                   pinned: Dict[str, Any]) -> Dict[str, str]:
        """FD-7L Phase 4: the complete tree of the pinned repository at `branch`. A broker refusal is typed
        (RunnerIdentityRefused); a tree that cannot be read completely is IncompleteRepoTreeError (the deploy's typed
        REPO_TREE_INCOMPLETE), never a fallback to another credential or reader. No token is logged."""
        full_name = pinned["full_name"]

        def _unread(why: str) -> IncompleteRepoTreeError:
            return IncompleteRepoTreeError(full_name, branch, {"complete": False, "truncated": False,
                                                               "error": why[:300]})

        server_url = None
        try:
            runner_creds.check_branch_name(branch)   # SAT-50 RT F2: before any token or URL
            if pinned["provider"] == "GITHUB":
                token, answer = runner.credentials.repository_token()
                runner_creds.check_repo_token_answer(answer, full_name)
            else:
                # The git server's address only from the job's Terraform-owned GIT_SERVER_URL (never the agent-writable
                # platform setting, never Cloud Run discovery); the ID token is the job's own, for that origin.
                server_url = runner_creds.git_server_url(os.environ)
                token = runner_creds.job_id_token(runner_creds.url_origin(server_url))
        except ri.RunnerIdentityError as e:
            raise RunnerIdentityRefused(e.code, e.detail) from None
        except Exception as e:  # noqa: BLE001 - the repository credential could not be obtained (SAT-30 RT L2: per branch)
            what = "repository token" if pinned["provider"] == "GITHUB" else "job ID token"
            raise _unread(f"{what} unavailable ({type(e).__name__})") from None
        try:
            # Built here with explicit credentials (no VCSProviderFactory: its one call stays the Shared read's, W6bd
            # F1), so no platform setting, Firestore record, env token or Secret Manager key is consulted. The
            # provider is used only to read the tree. SAT-50: GitHub is read over REST (httpx), never through the
            # shared GitHubProvider: PyGithub is not in this image (mcp-servers/terraform/requirements.txt).
            if pinned["provider"] == "GITHUB":
                tree = self._read_github_tree_rest(full_name, branch, token)
            else:
                from shared.providers.serverless_git_provider import ServerlessGitProvider as _Reader
                reader = _Reader(server_url=server_url, project_id=self.project_id, auth_token=token)
                tree = reader.fetch_file_tree(full_name, branch=branch, require_complete=True)
                tree = add_serverless_git_binaries(reader, full_name, branch, tree)   # RT14-21
        except IncompleteRepoTreeError:
            raise
        except Exception as e:  # noqa: BLE001 - typed below; the message names the class and the server's answer only
            raise _unread(f"{type(e).__name__}: {e}") from None
        logger.info(f"Per-workload read of {len(tree)} files from '{full_name}' ({branch}) "
                    f"({'read-only repository token' if pinned['provider'] == 'GITHUB' else 'job ID token'}).")
        return tree

    @staticmethod
    def _read_github_tree_rest(full_name: str, branch: str, token: str) -> Dict[str, Union[str, bytes]]:
        """SAT-50: the Per-workload GitHub tree, read with the brokered read-only token over the GitHub REST API (httpx,
        in this image's requirements). The Shared legacy read's calls (the recursive git tree of `branch`, then each
        blob), but complete or typed: a tree answer other than 200, a truncated tree, more than REPO_READ_MAX_FILES
        files (refused before any blob call, RT F1) or a blob that cannot be read raises IncompleteRepoTreeError. The
        only retry is the bounded rate-limit wait (`_rate_limit_wait`, REPO_READ_RATE_LIMIT_*): a 403/429 whose
        headers ask for a short wait; a rate limit past those bounds is typed. `branch` was checked as a git branch name
        by the caller (RT F2). Blob URLs are built from the tree's SHAs on api.github.com (the token goes to no URL
        taken from a response body); no raw-content fallback. Files are decoded exactly as the Shared read decodes
        them (RT14-21 decode_repo_blob: valid UTF-8 as str, anything else as its exact bytes). The token is never
        logged or put in an error."""
        import httpx
        import urllib.parse

        def _incomplete(truncated: bool, why: Optional[str]) -> IncompleteRepoTreeError:
            return IncompleteRepoTreeError(full_name, branch, {"complete": False, "truncated": truncated,
                                                               "error": why})

        api = f"https://api.github.com/repos/{full_name}"
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github.v3+json"}
        files: Dict[str, str] = {}
        def _answered(res) -> str:
            """`HTTP <status>`; on a 403/429 also the rate-limit headers GitHub sent (RT M1: headers only, never the
            body), so a rate limit can be told from a permission refusal."""
            out = f"HTTP {res.status_code}"
            if res.status_code in (403, 429):
                got = {str(k).lower(): str(v) for k, v in (getattr(res, "headers", None) or {}).items()}
                limits = [f"retry-after: {got['retry-after'][:20]}"] if "retry-after" in got else []
                if got.get("x-ratelimit-remaining") == "0":
                    limits.append("x-ratelimit-remaining: 0")
                out += f" ({', '.join(limits)})" if limits else " (no rate-limit headers)"
            return out

        waited = [0]   # seconds of rate-limit waiting so far, whole read

        with httpx.Client(timeout=25.0) as client:
            def _get(url, what):
                """(answer, note): the final answer of one call, after at most the bounded rate-limit retries; the
                note says why a rate-limited answer was not retried further ('' when it was not a rate limit)."""
                retries = 0
                while True:
                    res = client.get(url, headers=headers)
                    wait = TerraformService._rate_limit_wait(res, int(_repo_read_clock()))
                    if wait is None:
                        return res, ""
                    if retries >= REPO_READ_RATE_LIMIT_RETRIES:
                        return res, f" after {retries} rate-limit retries"
                    if wait > REPO_READ_RATE_LIMIT_MAX_WAIT_S:
                        return res, (f" (not retried: GitHub asks for a {wait} s wait, more than "
                                     f"{REPO_READ_RATE_LIMIT_MAX_WAIT_S} s)")
                    if waited[0] + wait > REPO_READ_RATE_LIMIT_TOTAL_WAIT_S:
                        return res, (f" (not retried: this read already waited {waited[0]} s of its "
                                     f"{REPO_READ_RATE_LIMIT_TOTAL_WAIT_S} s)")
                    retries += 1
                    logger.warning(f"GitHub rate limit on the Per-workload read of '{full_name}' ({what}): "
                                   f"{_answered(res)}; retry {retries} of {REPO_READ_RATE_LIMIT_RETRIES} in {wait} s")
                    _repo_read_sleep(wait)
                    waited[0] += wait

            r, note = _get(f"{api}/git/trees/{urllib.parse.quote(branch, safe='/')}?recursive=1", "tree")
            if r.status_code != 200:
                raise _incomplete(False, f"GitHub tree read answered {_answered(r)}{note}")
            tree_json = r.json()
            if tree_json.get("truncated") is True:
                raise _incomplete(True, None)
            blobs = [item for item in tree_json.get("tree", []) if item.get("type") == "blob"]
            if len(blobs) > REPO_READ_MAX_FILES:
                raise _incomplete(True, f"the tree has {len(blobs)} files, more than {REPO_READ_MAX_FILES}")
            for item in blobs:
                path, sha = item.get("path"), item.get("sha")
                if not (isinstance(path, str) and path and isinstance(sha, str) and sha):
                    raise _incomplete(False, "GitHub tree entry without a path or SHA")
                blob, note = _get(f"{api}/git/blobs/{urllib.parse.quote(sha, safe='')}", "blob")
                if blob.status_code != 200:
                    raise _incomplete(False, f"blob of {path!r} answered {_answered(blob)}{note}")
                files[path] = decode_repo_blob(base64.b64decode(blob.json().get("content", "")))   # RT14-21
        return files

    @staticmethod
    def _rate_limit_wait(res: Any, now: int) -> Optional[int]:
        """Seconds GitHub's headers ask a 403/429 answer to wait before the next call, else None (not a rate limit,
        e.g. a permission refusal, or headers that are not plain decimal numbers). Headers only, never the body:
        `Retry-After: <seconds>` (secondary limit) first, else `X-RateLimit-Remaining: 0` with
        `X-RateLimit-Reset: <epoch seconds>` (primary limit; a reset already passed waits 1 s)."""
        if getattr(res, "status_code", None) not in (403, 429):
            return None
        got = {str(k).lower(): str(v).strip() for k, v in (getattr(res, "headers", None) or {}).items()}
        retry_after = got.get("retry-after")
        if retry_after is not None:
            return int(retry_after) if retry_after.isascii() and retry_after.isdigit() else None
        reset = got.get("x-ratelimit-reset")
        if got.get("x-ratelimit-remaining") == "0" and reset is not None and reset.isascii() and reset.isdigit():
            return max(int(reset) - now, 0) + 1
        return None

    def _fetch_repo_files(self, product_id: str, github_repo: Optional[str] = None,
                          branch: Optional[str] = None) -> Dict[str, Union[str, bytes]]:
        """Fetches latest committed files from the GitHub repository for the specified branch (defaulting to Firestore default_branch or main).
        FD-7L Phase 4: on a Per-workload install only the pinned repository, through `_fetch_repo_files_brokered`."""
        owner, repo_name, _ = resolve_repo_identity(github_repo, product_id=product_id)
        brokered = self._brokered_repo_runner(product_id, owner, repo_name)   # None on a Shared install
        files: Dict[str, str] = {}

        target_branch = branch
        if not target_branch and self.db:
            try:
                doc = self.db.collection("workloads").document(product_id).get()
                if doc.exists:
                    wdata = doc.to_dict() or {}
                    target_branch = wdata.get("default_branch")
            except Exception as e:
                logger.debug(f"Could not read default_branch from Firestore for '{product_id}': {e}")
        if not target_branch:
            target_branch = "main"
        if brokered is not None:
            return self._fetch_repo_files_brokered(product_id, target_branch, *brokered)
        token = os.getenv("GITHUB_TOKEN", "")

        if VCSProviderFactory is not None:
            vcs = None
            try:
                vcs = VCSProviderFactory.get_provider(
                    default_owner=owner,
                    project_id=self.project_id,
                    product_id=product_id,
                    full_repo_name=f"{owner}/{repo_name}",
                )
                tree = vcs.fetch_file_tree(f"{owner}/{repo_name}", branch=target_branch, require_complete=True)
                if tree and _is_serverless_git_reader(vcs):   # RT14-21: binaries from the same branch's archive
                    tree = add_serverless_git_binaries(vcs, f"{owner}/{repo_name}", target_branch, tree)
                if tree:
                    logger.info(f"VCSProvider fetched {len(tree)} files from '{owner}/{repo_name}' ({target_branch}).")
                    return tree
            except IncompleteRepoTreeError:
                raise   # FD-4D: an incomplete tree is a typed deploy failure, never a fall-through to the legacy fetch
            except Exception as vcs_err:
                logger.debug(f"VCSProvider fetch_file_tree notice ({vcs_err}); trying legacy fetch.")
            # FD-4D RT F2: the legacy fetch is a GitHub REST read. A non-GitHub provider (Serverless Git) that could
            # not read the repo, or read it empty, is refused ({} -> the manifest guard) and never read from GitHub.
            try:
                from shared.providers.github_provider import GitHubProvider as _GitHubProvider
            except ImportError:
                _GitHubProvider = None
            if vcs is not None and not (_GitHubProvider is not None and isinstance(vcs, _GitHubProvider)):
                logger.error(f"{type(vcs).__name__} could not read '{owner}/{repo_name}' ({target_branch}); "
                             f"no GitHub fallback for a non-GitHub repository.")
                return {}

        # 0. Check cached GitHubTokenManager first
        if not token:
            try:
                token = get_github_token(self.project_id)
            except Exception as e:
                logger.debug(f"github_resilience token fetch skipped: {e}")

        # 1. Try Secret Manager JIT Token Minting directly
        if not token:
            for sec_id in ["castor-github-app-private-key", "castor-github-app-credentials"]:
                try:
                    import time
                    import re
                    import jwt
                    import httpx
                    from google.cloud import secretmanager
                    sm_client = secretmanager.SecretManagerServiceClient()
                    secret_name = f"projects/{self.project_id}/secrets/{sec_id}/versions/latest"
                    sec_res = sm_client.access_secret_version(name=secret_name)
                    payload_str = sec_res.payload.data.decode("utf-8").strip()

                    clean_str = payload_str.replace("“", '"').replace("”", '"').replace("‘", "'").replace("’", "'")
                    clean_str = clean_str.replace("—", "-").replace("–", "-")

                    pat_match = re.search(r'["\']?(?:pat|personal_access_token|github_token)["\']?\s*:\s*["\']?([a-zA-Z0-9_]+)["\']?', clean_str)
                    if pat_match:
                        token = pat_match.group(1)
                        break
                    pat_direct = re.search(r'github_pat_[a-zA-Z0-9_]+|ghp_[a-zA-Z0-9]+', clean_str)
                    if pat_direct:
                        token = pat_direct.group(0)
                        break

                    app_id_match = re.search(r'["\']?app_id["\']?\s*:\s*["\']?(\d+)["\']?', clean_str)
                    inst_id_match = re.search(r'["\']?installation_id["\']?\s*:\s*["\']?(\d+)["\']?', clean_str)
                    pem_match = re.search(r'(-----BEGIN [A-Z\s]+PRIVATE KEY-----[\s\S]+?-----END [A-Z\s]+PRIVATE KEY-----)', clean_str)
                    if app_id_match and inst_id_match and pem_match:
                        now = int(time.time())
                        jwt_payload = {"iat": now - 60, "exp": now + 600, "iss": str(app_id_match.group(1))}
                        encoded_jwt = jwt.encode(jwt_payload, pem_match.group(1).strip(), algorithm="RS256")
                        headers = {"Authorization": f"Bearer {encoded_jwt}", "Accept": "application/vnd.github+json"}
                        url = f"https://api.github.com/app/installations/{inst_id_match.group(1)}/access_tokens"
                        with httpx.Client(timeout=15.0) as http_client:
                            r = http_client.post(url, headers=headers)
                            if r.status_code in (200, 201):
                                token = r.json().get("token", "")
                                if token:
                                    break
                except Exception as e:
                    logger.debug(f"Direct Secret Manager token minting for {sec_id} skipped: {e}")

        # 2. (GH-TOKEN-CALLERS) No vending /github-token fallback: that route answers only its allow-listed caller.

        # 3. Retrieve files from GitHub
        if token:
            tree_json = None   # FD-4D: set once the tree is read; a later failure means a partial read
            unread: List[str] = []
            try:
                import httpx
                import base64
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github.v3+json",
                }
                with httpx.Client(timeout=25.0) as client:
                    @github_retry_with_backoff(max_retries=3, initial_wait=2.0)
                    def _fetch_tree_req():
                        res = client.get(f"https://api.github.com/repos/{owner}/{repo_name}/git/trees/{target_branch}?recursive=1", headers=headers)
                        if res.status_code in (403, 429):
                            res.raise_for_status()
                        return res

                    @github_retry_with_backoff(max_retries=3, initial_wait=2.0)
                    def _fetch_blob_req(url):
                        res = client.get(url, headers=headers)
                        if res.status_code in (403, 429):
                            res.raise_for_status()
                        return res

                    r = _fetch_tree_req()
                    if r.status_code == 200:
                        tree_json = r.json()
                        tree_items = tree_json.get("tree", [])
                        for item in tree_items:
                            if item.get("type") == "blob":
                                path = item.get("path", "")
                                # Fetch from Git blob API url first to avoid raw.githubusercontent branch CDN caching TTL
                                fetched = False
                                if "url" in item:
                                    try:
                                        blob_res = _fetch_blob_req(item["url"])
                                        if blob_res.status_code == 200:
                                            content_b64 = blob_res.json().get("content", "")
                                            files[path] = decode_repo_blob(base64.b64decode(content_b64))   # RT14-21
                                            fetched = True
                                    except Exception:
                                        pass
                                if not fetched:
                                    raw_res = _fetch_blob_req(f"https://raw.githubusercontent.com/{owner}/{repo_name}/{target_branch}/{path}")
                                    if raw_res.status_code == 200:
                                        files[path] = decode_repo_blob(raw_res.content)   # RT14-21: exact bytes
                                    else:
                                        unread.append(path)
                        if tree_json.get("truncated") is True or unread:
                            raise IncompleteRepoTreeError(f"{owner}/{repo_name}", target_branch, {
                                "complete": False, "truncated": tree_json.get("truncated") is True,
                                "error": f"{len(unread)} file(s) unreadable" if unread else None})
                        logger.info(f"Successfully fetched {len(files)} files from GitHub repo '{owner}/{repo_name}' (branch: '{target_branch}') for deployment.")
            except IncompleteRepoTreeError:
                raise
            except Exception as e:
                if tree_json is not None:   # FD-4D: the tree was read but not every file: never a partial deploy
                    raise IncompleteRepoTreeError(f"{owner}/{repo_name}", target_branch, {
                        "complete": False, "truncated": False, "error": f"{type(e).__name__}: {e}"[:300]}) from e
                logger.warning(f"Could not fetch files from GitHub repo: {e}")
        else:
            logger.warning("No GitHub token available to fetch workload repository files.")

        return files

    def _build_and_push_container(
        self,
        product_id: str,
        target_project_id: str,
        workspace_dir: str,
        image_tag: str,
        ar_repo_name: Optional[str] = None,
        region: Optional[str] = None,
    ) -> bool:
        """Builds the workload container image in the target child project using Google Cloud Buildpacks.
        `region` (FD-4AL): the workload region of the Artifact Registry repository; None = resolve_platform_region."""
        self._last_build_error = None
        self._last_build_error_class = None
        try:
            region = region or self._resolve_region()
        except RegionUnavailable as region_err:
            self._last_build_error = str(region_err)
            logger.error(self._last_build_error)
            return False
        import io
        import tarfile
        from google.auth.transport.requests import AuthorizedSession

        has_app = (
            os.path.exists(os.path.join(workspace_dir, "Procfile"))
            or os.path.exists(os.path.join(workspace_dir, "main.py"))
            or os.path.exists(os.path.join(workspace_dir, "requirements.txt"))
            or os.path.exists(os.path.join(workspace_dir, "Dockerfile"))
        )
        clean_pid = product_id.lower().replace("_", "-")

        # 1. Enforce root Procfile and .python-version exist for clean Buildpack compilation
        procfile_path = os.path.join(workspace_dir, "Procfile")
        root_has_alembic = os.path.exists(os.path.join(workspace_dir, "alembic.ini")) or os.path.isdir(os.path.join(workspace_dir, "alembic"))
        # FD-4AE: an authored Procfile is never rewritten (the old `(alembic upgrade head || true) &&` rewrite
        # swallowed migration failures). Only a MISSING one gets the default, and a failing migration fails it.
        if not os.path.exists(procfile_path):
            with open(procfile_path, "w") as f:
                f.write(default_procfile_text(root_has_alembic))

        # Resolve Platform BOM configuration dynamically
        bom_packages = {}
        target_python = "3.13"
        cb_machine_type = "E2_HIGHCPU_8"
        cb_timeout_seconds = 1200
        harmonize_wheels = True   # FD-4DJ-HARMONIZE: on unless the setting is exactly False
        try:
            from shared.settings import get_platform_settings
            platform_settings = get_platform_settings(project_id=self.project_id)
            if platform_settings and platform_settings.runtimes:
                target_python = platform_settings.runtimes.default_python_version or "3.13"
                cb_machine_type = platform_settings.runtimes.cloud_build_machine_type or "E2_HIGHCPU_8"
                cb_timeout_seconds = platform_settings.runtimes.cloud_build_timeout_seconds or 1200
                bom_packages = platform_settings.runtimes.package_versions or {}
                harmonize_wheels = getattr(platform_settings.runtimes, "auto_harmonize_wheels", True) is not False
        except Exception as bom_load_err:
            logger.debug(f"Could not load Platform BOM settings: {bom_load_err}")
        if not harmonize_wheels:
            logger.info("FD-4DJ-HARMONIZE: Auto-Harmonize Legacy C-Extension Wheels is off; old numpy / scipy / pandas "
                        "/ asyncpg pins the BOM does not list are kept as written")

        # Sanitize all .python-version files across workspace
        # Valid enterprise runtimes (3.10, 3.11, 3.12, 3.13) are preserved; invalid or corrupt versions are defaulted
        valid_runtimes = {"3.10", "3.11", "3.12", "3.13"}
        for root, _, filenames in os.walk(workspace_dir):
            if ".python-version" in filenames:
                p_file = os.path.join(root, ".python-version")
                try:
                    with open(p_file, "r") as f:
                        v = f.read().strip()
                    if not any(v.startswith(vr) for vr in valid_runtimes):
                        with open(p_file, "w") as f:
                            f.write(f"{target_python}\n")
                except Exception:
                    pass

        pyver_path = os.path.join(workspace_dir, ".python-version")
        if not os.path.exists(pyver_path):
            with open(pyver_path, "w") as f:
                f.write(f"{target_python}\n")

        # 2. Discover services under apps/ and enforce container contract BEFORE tarball packaging
        apps_dir = os.path.join(workspace_dir, "apps")
        services = []
        service_kinds = workspace_service_kinds(workspace_dir)
        vm_items = set()
        if os.path.exists(apps_dir):
            vm_items = {d for d in os.listdir(apps_dir) if vm_service_dir(d, service_kinds)}
            entrypoint_files = ("main.py", "app.py", "server.js", "main.go", "index.js", "main.ts", "app.ts")
            populated_service_dirs = [
                d for d in os.listdir(apps_dir)
                if os.path.isdir(os.path.join(apps_dir, d))
                and any(os.path.exists(os.path.join(apps_dir, d, ep)) for ep in entrypoint_files)
            ]
            for item in sorted(os.listdir(apps_dir)):
                if item.endswith(".py"):
                    continue
                sub_path = os.path.join(apps_dir, item)
                if os.path.isdir(sub_path) and item in vm_items:
                    # FD-4AE re-check F1b: a VM-kind service (topology) is never built, checked or given a Procfile.
                    logger.info(f"BUILD.SKIP_VM_SERVICE apps/{item} ({vm_service_dir(item, service_kinds)})")
                    continue
                if os.path.isdir(sub_path):
                    # Exclude non-service library directories unless an entrypoint exists
                    if item in ("common", "contracts", "schemas", "shared") and not any(os.path.exists(os.path.join(sub_path, f)) for f in ("main.py", "app.py")):
                        continue

                    # If authentic populated services exist elsewhere in apps/, skip empty skeleton directories.
                    # A dir without an entry module is still built when typed facts say it is a service (topology
                    # container kind, or no topology + a Procfile process): e.g. a GKE `worker: python consumer.py`.
                    has_entrypoint = any(os.path.exists(os.path.join(sub_path, ep)) for ep in entrypoint_files)
                    if populated_service_dirs and not has_entrypoint \
                            and not entryless_service_is_buildable(item, sub_path, service_kinds):
                        logger.info(f"Skipping empty skeleton directory 'apps/{item}' without entrypoint because populated services exist: {populated_service_dirs}")
                        continue

                    # procfile-worker RT F1: a topology container service with no Procfile and no main.py cannot start,
                    # whatever else it ships (with or without requirements.txt): fail typed, never drop it silently.
                    # A Node service (package.json) is left to the Node buildpack's own `npm start`, as before.
                    if service_kinds is not None and not has_entrypoint \
                            and entryless_service_is_buildable(item, sub_path, service_kinds) \
                            and not os.path.exists(os.path.join(sub_path, "Procfile")) \
                            and not os.path.exists(os.path.join(sub_path, "package.json")):
                        self._last_build_error = (
                            f"{BUILD_ENTRYPOINT_MISSING}: apps/{item} is a container service in the topology but has no "
                            f"Procfile and no main.py, so no process can start; the service must ship its own entrypoint "
                            f"(nothing is generated after QA)."
                        )
                        self._last_build_error_class = BUILD_CONTRACT_ERROR_CLASS
                        logger.error(self._last_build_error)
                        return False

                    # Only include valid service directories with runnable application files
                    if any(os.path.exists(os.path.join(sub_path, f)) for f in ("main.py", "app.py", "Procfile", "requirements.txt", "package.json")):
                        services.append(item)
                        # Check if this service is a Python service before enforcing Python container contract
                        is_python_service = any(os.path.exists(os.path.join(sub_path, f)) for f in ("main.py", "app.py", "requirements.txt", "pyproject.toml"))
                        if is_python_service:
                            # Ensure apps/{svc} has Procfile and .python-version
                            svc_procfile = os.path.join(sub_path, "Procfile")
                            svc_has_alembic = os.path.exists(os.path.join(sub_path, "alembic.ini")) or os.path.isdir(os.path.join(sub_path, "alembic"))
                            # FD-4AE: no hello-world main.py. Without an authored Procfile the default below runs
                            # `uvicorn main:app`; when main.py is missing that cannot start, so fail the build with a
                            # typed reason (pre-QA V3c reports the same gap as CONTAINER.ENTRYPOINT_MISSING).
                            if not os.path.exists(svc_procfile) and not os.path.exists(os.path.join(sub_path, "main.py")):
                                self._last_build_error = (
                                    f"{BUILD_ENTRYPOINT_MISSING}: apps/{item} has no Procfile and no main.py, so no web "
                                    f"process can start; the service must ship its own entrypoint (nothing is generated after QA)."
                                )
                                self._last_build_error_class = BUILD_CONTRACT_ERROR_CLASS
                                logger.error(self._last_build_error)
                                return False
                            # FD-4AE: an authored Procfile is never rewritten (the old `(alembic upgrade head || true)`
                            # rewrite swallowed migration failures). Only a missing one gets the default.
                            if not os.path.exists(svc_procfile):
                                try:
                                    with open(svc_procfile, "w") as pf:
                                        pf.write(default_procfile_text(svc_has_alembic))
                                except Exception:
                                    pass
                            svc_pyver = os.path.join(sub_path, ".python-version")
                            if not os.path.exists(svc_pyver):
                                try:
                                    with open(svc_pyver, "w") as pv:
                                        pv.write(f"{target_python}\n")
                                except Exception:
                                    pass
                        # (FD-4AE: hello-world main.py, Starlette compat header and schema bootstrap DELETED.)
                        # Harmonize requirements for Python 3.13 binary wheel compatibility
                        svc_reqs = os.path.join(sub_path, "requirements.txt")
                        if os.path.exists(svc_reqs):
                            try:
                                with open(svc_reqs, "r", encoding="utf-8") as rf:
                                    r_raw = rf.read()
                                svc_pyver_file = os.path.join(sub_path, ".python-version")
                                svc_py = target_python
                                if os.path.exists(svc_pyver_file):
                                    try:
                                        with open(svc_pyver_file, "r") as pvf:
                                            rv = pvf.read().strip()
                                            if any(rv.startswith(vr) for vr in valid_runtimes):
                                                svc_py = rv
                                    except Exception:
                                        pass
                                r_sanitized = sanitize_wheel_requirements(r_raw, python_version=svc_py, package_versions=bom_packages,
                                                                          harmonize_legacy_wheels=harmonize_wheels)
                                if r_sanitized != r_raw:
                                    with open(svc_reqs, "w", encoding="utf-8") as rf:
                                        rf.write(r_sanitized)
                                    logger.info(f"Harmonized requirements in 'apps/{item}' with Platform BOM (Python {svc_py})")
                            except Exception as req_err:
                                logger.warning(f"Requirements harmonization notice for 'apps/{item}': {req_err}")

                        # (FD-4AE: routers/__init__.py aggregator synthesis DELETED; routers is the app's code.)

                        # Ensure static directory exists in microservice package
                        svc_static = os.path.join(sub_path, "static")
                        os.makedirs(svc_static, exist_ok=True)
                        keep_file = os.path.join(svc_static, ".gitkeep")
                        if not os.path.exists(keep_file):
                            try:
                                with open(keep_file, "w") as kf:
                                    kf.write("")
                            except Exception:
                                pass

            # Disambiguate duplicate hyphen vs underscore directories (e.g. apps/testplan04-b vs apps/testplan04_b)
            manifest_content = ""
            for m_dir in [os.path.join(workspace_dir, "infra"), os.path.join(workspace_dir, "k8s")]:
                if os.path.isdir(m_dir):
                    for r, _, fs in os.walk(m_dir):
                        for f in fs:
                            if f.endswith((".tf", ".yaml", ".yml")):
                                try:
                                    with open(os.path.join(r, f), "r", encoding="utf-8", errors="ignore") as mf:
                                        manifest_content += "\n" + mf.read()
                                except Exception:
                                    pass

            pruned_services = []
            for svc in services:
                under_svc = svc.replace("-", "_")
                hyphen_svc = svc.replace("_", "-")
                if under_svc != hyphen_svc and under_svc in services and hyphen_svc in services:
                    # If both exist, keep the one referenced in manifests, or default to underscore module
                    if hyphen_svc in manifest_content and under_svc not in manifest_content:
                        if svc == hyphen_svc:
                            pruned_services.append(svc)
                        else:
                            logger.info(f"🛡️ Service Disambiguation: Skipping redundant alias 'apps/{svc}' in favor of referenced 'apps/{hyphen_svc}'")
                    else:
                        if svc == under_svc:
                            pruned_services.append(svc)
                        else:
                            logger.info(f"🛡️ Service Disambiguation: Skipping redundant alias 'apps/{svc}' in favor of canonical 'apps/{under_svc}'")
                else:
                    pruned_services.append(svc)
            services = pruned_services

        # Harmonize root requirements.txt if present
        root_reqs = os.path.join(workspace_dir, "requirements.txt")
        if os.path.exists(root_reqs):
            try:
                with open(root_reqs, "r", encoding="utf-8") as rf:
                    r_raw = rf.read()
                r_sanitized = sanitize_wheel_requirements(r_raw, python_version=target_python, package_versions=bom_packages,
                                                          harmonize_legacy_wheels=harmonize_wheels)
                if r_sanitized != r_raw:
                    with open(root_reqs, "w", encoding="utf-8") as rf:
                        rf.write(r_sanitized)
                    logger.info(f"Harmonized root requirements with Platform BOM (Python {target_python})")
            except Exception as req_err:
                logger.warning(f"Root requirements harmonization notice: {req_err}")

        # (FD-4AE: root main.py/app.py Starlette compat header and schema bootstrap DELETED.)

        # 3. Assemble Cloud Build steps with parallel execution (waitFor: ['-'])
        build_steps = []
        repo_name = ar_repo_name or clean_pid
        if services:
            # Prefer a primary service that actually has a runnable entrypoint
            valid_services = [s for s in services if any(os.path.exists(os.path.join(apps_dir, s, ep)) for ep in ("main.py", "app.py", "server.js", "main.go"))]
            active_pool = valid_services if valid_services else services
            # FD-55-IMG: the service a root module takes var.container_image for directly gets app:latest
            primary_svc = primary_build_service(active_pool, clean_pid, direct_container_image_services(workspace_dir))
            for svc in services:
                svc_image_tag = f"{region}-docker.pkg.dev/{target_project_id}/{repo_name}/{svc}:latest"
                pack_args = [
                    "build",
                    svc_image_tag,
                    "--builder=us-central1-docker.pkg.dev/serverless-runtimes/google-24-full/builder/universal:latest",
                    f"--path=apps/{svc}",
                    "--publish"
                ]
                if svc == primary_svc:
                    pack_args.extend(["--tag", image_tag])
                    clean_primary = clean_pid.replace("_", "-")
                    if clean_primary != svc:
                        pack_args.extend(["--tag", f"{region}-docker.pkg.dev/{target_project_id}/{repo_name}/{clean_primary}:latest"])
                # Dual-tag hyphen and underscore equivalents (e.g. service-b and service_b)
                clean_hyphen = svc.replace("_", "-")
                clean_under = svc.replace("-", "_")
                if clean_hyphen != svc:
                    pack_args.extend(["--tag", f"{region}-docker.pkg.dev/{target_project_id}/{repo_name}/{clean_hyphen}:latest"])
                if clean_under != svc:
                    pack_args.extend(["--tag", f"{region}-docker.pkg.dev/{target_project_id}/{repo_name}/{clean_under}:latest"])
                build_steps.append({
                    "name": "gcr.io/k8s-skaffold/pack",
                    "args": pack_args,
                    "waitFor": ["-"],  # Parallel execution across all services!
                })
        else:
            build_steps.append({
                "name": "gcr.io/k8s-skaffold/pack",
                "args": [
                    "build",
                    image_tag,
                    "--builder=us-central1-docker.pkg.dev/serverless-runtimes/google-24-full/builder/universal:latest",
                    "--publish"
                ],
                "waitFor": ["-"],
            })

        try:
            logger.info(f"Initiating Google Cloud Build for '{product_id}' in project '{target_project_id}'...")
            credentials = self._child_credentials(target_project_id)   # FD4BD-Q3: quota project = the child
            session = AuthorizedSession(credentials)

            # FD-4AE-c: nothing rewrites or adds application code after QA. QA runs every service with apps/<svc>/ as cwd and
            # PYTHONPATH, the same import root as `pack --path=apps/<svc>`, so the build ships apps/<svc>/ exactly as QA ran it.
            # DELETED here: the AST/regex rewrite of `apps.<svc>.` and `from ..x` imports (#11; pre-QA V3c-imports reports an
            # import that leaves the service root, QA's `import main` fails on it) and the copy of apps/shared|common|contracts
            # and of every root auxiliary dir into each service (#16; the pre-QA package gate vendors before QA).

            # FD-4AE-c: DELETED every package-layout pass over the workspace, so the image carries exactly the files QA ran:
            #   #12 the Alembic `alembic/` -> `migrations/` rename with its alembic.ini / `.py` string rewrites;
            #   #13 the purge of `__init__.py` in "shielded" dirs (reserved names or any requirement stem);
            #   #14 the purge of a flat `x.py` next to an `x/` dir (the 10-18 corpus: 103 `schemas.py` files in 67 of 75 builds);
            #   #17 the generation of a missing `__init__.py` (Fable RT F1: an init turns a namespace dir such as `yaml/` into a
            #       regular package found before site-packages, so `import yaml` would load the empty local dir, not PyYAML).
            # The pre-QA package gate (gatekeeper_agent/verifier.py purge_shadowed_package_files, add-only `__init__.py`)
            # owns package layout before QA.

            # (FD-4AE: 3d contract-schema un-commenting / BaseModel shadowing and 3e SQLAlchemy synonym curing DELETED.)

            # FD-4AE-c: DELETED the "Dual Guard" requirements.txt pruning (#15). It dropped requirements QA had installed (any
            # name in a fixed scaffold list such as `docker` or `config`, even with a version, and any bare name equal to a local
            # file or dir stem). Requirements are owned before QA: QA's PEP 508 check + pip install and the REQ.* validators.

            # 4. Package ONLY what the pack steps consume (FD-4BA follow-up allow-list; no tfvars/state/IaC/keys).
            try:
                build_files = select_build_source_files(workspace_dir, services)
            except Exception as sel_err:
                self._last_build_error = f"Could not assemble the build source: {sel_err}"
                logger.error(self._last_build_error)
                return False
            tar_stream = io.BytesIO()
            with tarfile.open(fileobj=tar_stream, mode="w:gz") as tar:
                for rel_path in build_files:
                    tar.add(os.path.join(workspace_dir, rel_path), arcname=rel_path, recursive=False)
            tar_stream.seek(0)
            tar_bytes = tar_stream.read()
            logger.info(f"Packaged {len(build_files)} allow-listed build source file(s) for '{product_id}'")

            storage_client = self._child_storage_client(target_project_id)   # FD4BD-Q3
            target_bucket_name = f"{target_project_id}-cloudbuild-source"
            bucket_name = target_bucket_name
            exec_id = os.environ.get("CLOUD_RUN_EXECUTION") or f"run-{int(time.time() * 1000)}"
            source_blob_name = f"sources/{product_id}/{exec_id}/source.tar.gz"

            # FD-4BA: the source bucket lives in the child project and is readable only by that project's
            # resolved Cloud Build service account. There is no public grant and no fallback to the platform
            # state bucket: if staging fails, the build fails with the reason.
            try:
                self._stage_build_source(
                    storage_client=storage_client,
                    session=session,
                    target_project_id=target_project_id,
                    bucket_name=target_bucket_name,
                    object_name=source_blob_name,
                    payload=tar_bytes,
                    region=region,   # FD-7M-a: the bucket lives in the build's (the workload's) region
                )
            except Exception as stage_err:
                self._last_build_error = f"Could not stage build source in gs://{target_bucket_name}: {stage_err}"
                logger.error(self._last_build_error)
                return False

            # 6. Ensure Artifact Registry repository exists with IAM permissions in target project
            repo_name = ar_repo_name or clean_pid
            try:
                # Enable Artifact Registry API
                enable_url = f"https://serviceusage.googleapis.com/v1/projects/{target_project_id}/services/artifactregistry.googleapis.com:enable"
                session.post(enable_url)

                # Check if repo exists, create if not
                ar_repo_url = f"https://artifactregistry.googleapis.com/v1/projects/{target_project_id}/locations/{region}/repositories/{repo_name}"
                check_res = session.get(ar_repo_url)
                if check_res.status_code == 404:
                    create_url = f"https://artifactregistry.googleapis.com/v1/projects/{target_project_id}/locations/{region}/repositories?repositoryId={repo_name}"
                    session.post(create_url, json={
                        "format": "DOCKER",
                        "description": f"Docker container repository for {clean_pid}"
                    })
                    logger.info(f"Created Artifact Registry repository '{repo_name}' in '{target_project_id}'")

                # Resolve target project number for explicit, domain-policy compliant service account bindings
                proj_url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{target_project_id}"
                proj_res = session.get(proj_url)
                p_num = proj_res.json().get("projectNumber", "") if proj_res.status_code == 200 else ""

                ar_members = [
                    f"serviceAccount:sa-castor-gcp-devops@{self.project_id}.iam.gserviceaccount.com",
                    f"serviceAccount:sa-castor-developer@{self.project_id}.iam.gserviceaccount.com",
                ]
                if p_num:
                    ar_members.extend([
                        f"serviceAccount:{p_num}-compute@developer.gserviceaccount.com",
                        f"serviceAccount:{p_num}@cloudbuild.gserviceaccount.com",
                    ])

                # Grant repository read/write to explicit GCP service accounts (strictly domain-policy compliant)
                iam_url = f"https://artifactregistry.googleapis.com/v1/projects/{target_project_id}/locations/{region}/repositories/{repo_name}:setIamPolicy"
                session.post(iam_url, json={
                    "policy": {
                        "bindings": [
                            {
                                "role": "roles/artifactregistry.writer",
                                "members": ar_members
                            },
                            {
                                "role": "roles/artifactregistry.reader",
                                "members": ar_members
                            }
                        ]
                    }
                })
                logger.info(f"Configured Artifact Registry IAM on '{repo_name}' for service accounts")
            except Exception as ar_err:
                logger.debug(f"Artifact Registry preparation notice: {ar_err}")

            # Ensure IAP API and service identity exist in target project for Direct IAP
            try:
                session.post(f"https://serviceusage.googleapis.com/v1/projects/{target_project_id}/services/iap.googleapis.com:enable")
                session.post(f"https://serviceusage.googleapis.com/v1beta1/projects/{target_project_id}/services/iap.googleapis.com:generateServiceIdentity")
                logger.info(f"Ensured IAP API and service identity initialized for '{target_project_id}'")
            except Exception as iap_init_err:
                logger.debug(f"IAP identity initialization notice: {iap_init_err}")

            # Grant logging.logWriter and artifactregistry.writer on target project so Cloud Build can push images and write logs
            try:
                proj_url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{target_project_id}"
                proj_res = session.get(proj_url)
                p_num = proj_res.json().get("projectNumber", "") if proj_res.status_code == 200 else ""
                m_list = []
                if p_num:
                    m_list.extend([
                        f"serviceAccount:{p_num}-compute@developer.gserviceaccount.com",
                        f"serviceAccount:{p_num}@cloudbuild.gserviceaccount.com",
                    ])
                m_list.append(f"serviceAccount:sa-castor-gcp-devops@{self.project_id}.iam.gserviceaccount.com")

                crm_iam_url = f"https://cloudresourcemanager.googleapis.com/v1/projects/{target_project_id}:getIamPolicy"
                for _attempt in range(3):
                    iam_res = session.post(crm_iam_url)
                    if iam_res.status_code == 200:
                        pol = iam_res.json()
                        b_list = pol.get("bindings", [])
                        b_list.append({
                            "role": "roles/logging.logWriter",
                            "members": m_list
                        })
                        b_list.append({
                            "role": "roles/artifactregistry.writer",
                            "members": m_list
                        })
                        b_list.append({
                            "role": "roles/storage.admin",
                            "members": m_list
                        })
                        b_list.append({
                            "role": "roles/cloudbuild.builds.builder",
                            "members": m_list
                        })
                        pol["bindings"] = b_list
                        set_res = session.post(f"https://cloudresourcemanager.googleapis.com/v1/projects/{target_project_id}:setIamPolicy", json={"policy": pol})
                        if set_res.status_code in (200, 201):
                            logger.info(f"Granted roles/logging.logWriter, roles/artifactregistry.writer, roles/storage.admin, and roles/cloudbuild.builds.builder on '{target_project_id}'")
                            break
                        elif set_res.status_code == 409:
                            time.sleep(1.5)
            except Exception as log_iam_err:
                logger.debug(f"Logging and Artifact Registry IAM grant notice: {log_iam_err}")

            # 7. Submit build payload with parallel steps to Cloud Build API
            build_payload = {
                "source": {
                    "storageSource": {
                        "bucket": bucket_name,
                        "object": source_blob_name,
                    }
                },
                "steps": build_steps,
                "timeout": f"{cb_timeout_seconds}s",
                "options": {
                    "logging": "CLOUD_LOGGING_ONLY",
                    "machineType": cb_machine_type,
                }
            }

            max_build_attempts = 3
            for build_attempt in range(1, max_build_attempts + 1):
                build_url = f"https://cloudbuild.googleapis.com/v1/projects/{target_project_id}/builds"
                build_res = None
                max_submit_attempts = 20
                for _b_attempt in range(1, max_submit_attempts + 1):
                    build_res = session.post(build_url, json=build_payload, timeout=120.0)
                    if build_res.status_code in (200, 201):
                        break
                    elif build_res.status_code in (403, 404, 503) and _b_attempt < max_submit_attempts:
                        logger.warning(
                            f"Cloud Build submission returned HTTP {build_res.status_code} (attempt {_b_attempt}/{max_submit_attempts}). "
                            f"Waiting 5s for GCP IAM eventual consistency propagation..."
                        )
                        time.sleep(5.0)
                    else:
                        break

                if not (build_res and build_res.status_code in (200, 201)):
                    logger.warning(f"Cloud Build submission returned {build_res.status_code if build_res else 'None'}: {build_res.text if build_res else ''}")
                    if build_attempt < max_build_attempts:
                        time.sleep(5.0)
                        continue
                    return False

                build_data = build_res.json()
                build_id = build_data.get("metadata", {}).get("build", {}).get("id") or build_data.get("id", "")
                logger.info(f"Google Cloud Buildpack build submitted successfully (Build ID: {build_id}, attempt {build_attempt}/{max_build_attempts}). Polling until completion...")

                if not build_id:
                    logger.warning("Could not extract build ID from Cloud Build response, proceeding without polling.")
                    return True

                poll_url = f"https://cloudbuild.googleapis.com/v1/projects/{target_project_id}/builds/{build_id}"
                max_wait_seconds = cb_timeout_seconds  # Dynamic timeout from Platform Settings
                poll_interval = 10
                start_time = time.time()
                retrying_transient = False

                while time.time() - start_time < max_wait_seconds:
                    time.sleep(poll_interval)
                    try:
                        poll_res = session.get(poll_url, timeout=30.0)
                        if poll_res.status_code == 200:
                            b_info = poll_res.json()
                            b_status = b_info.get("status")
                            elapsed = int(time.time() - start_time)

                            if b_status == "SUCCESS":
                                logger.info(f"Google Cloud Buildpack build [{build_id}] completed successfully in {elapsed}s. Image ready: {image_tag}")
                                return True
                            elif b_status in ("FAILURE", "INTERNAL_ERROR", "TIMEOUT", "CANCELLED"):
                                failure_info = b_info.get("failureInfo", {})
                                fail_detail = failure_info.get("detail", "") or b_info.get("statusDetail", "")

                                log_tail = self._fetch_cloud_build_logs_tail(session, target_project_id, build_id)
                                is_transient = self._is_transient_buildpack_failure(b_status, log_tail, fail_detail)

                                if is_transient and build_attempt < max_build_attempts:
                                    backoff = 10.0 * build_attempt
                                    logger.warning(
                                        f"🛡️ Transient upstream Buildpack/Registry error detected in build [{build_id}] "
                                        f"(attempt {build_attempt}/{max_build_attempts}). Retrying in {backoff:.0f}s...\n"
                                        f"Detail: {fail_detail}\n"
                                        f"Logs: {log_tail[-300:] if log_tail else 'None'}"
                                    )
                                    time.sleep(backoff)
                                    retrying_transient = True
                                    break
                                else:
                                    logger.error(
                                        f"Google Cloud Buildpack build [{build_id}] failed permanently with status '{b_status}': {fail_detail}\n"
                                        f"Logs: {log_tail[-500:] if log_tail else 'None'}"
                                    )
                                    return False
                            else:
                                if elapsed % 30 == 0 or elapsed <= 20:
                                    logger.info(f"Waiting for Cloud Build [{build_id}]... Status: {b_status} ({elapsed}s elapsed)")
                        else:
                            logger.debug(f"Cloud Build poll returned status {poll_res.status_code}")
                    except Exception as poll_err:
                        logger.warning(f"Error polling Cloud Build status: {poll_err}")

                if retrying_transient:
                    continue

                logger.error(f"Google Cloud Buildpack build [{build_id}] timed out after {max_wait_seconds}s.")
                return False
        except Exception as e:
            logger.warning(f"Container build via Cloud Build skipped or failed: {e}")

        return False

    _PUBLIC_IAM_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})

    # Red-team F-6: the build failure reason is per call, not shared instance state. The service object is shared
    # by concurrent in-process deploys (FastAPI thread pool); each deploy sets and reads the reason within one call
    # on one worker thread, so a thread-local slot cannot leak one deploy's reason into another's error.
    def _build_error_slot(self) -> threading.local:
        slot = self.__dict__.get("_build_error_tls")
        if slot is None:
            slot = self.__dict__.setdefault("_build_error_tls", threading.local())
        return slot

    @property
    def _last_build_error(self) -> Optional[str]:
        return getattr(self._build_error_slot(), "reason", None)

    @_last_build_error.setter
    def _last_build_error(self, value: Optional[str]) -> None:
        self._build_error_slot().reason = value

    @property
    def _last_build_error_class(self) -> Optional[str]:
        return getattr(self._build_error_slot(), "error_class", None)

    @_last_build_error_class.setter
    def _last_build_error_class(self, value: Optional[str]) -> None:
        self._build_error_slot().error_class = value

    def _resolve_region(self) -> str:
        """Platform region (FD-4AL `resolve_platform_region` over this server's Firestore client); raises
        RegionUnavailable (a RuntimeError)."""
        return resolve_platform_region(getattr(self, "db", None))

    def _resolve_workload_region(self, record_region: Any, *, stage: str = "terraform_deploy") -> str:
        """FD-7M-a: the workload's region. No recorded region (None) = `_resolve_region()`, exactly as before;
        otherwise `resolve_workload_region` over this server's Firestore client (RegionNotApprovedError /
        RegionUnavailable)."""
        if record_region is None:
            return self._resolve_region()
        return resolve_workload_region(getattr(self, "db", None), record_region, stage=stage)

    @staticmethod
    def _resolve_cloud_build_service_account(session, target_project_id: str) -> str:
        """
        FD-4BA: the exact service account Cloud Build uses for builds submitted to ``projects/<p>/builds``
        without an explicit ``serviceAccount``, read from the Cloud Build API
        (``projects.locations.getDefaultServiceAccount`` for the ``global`` location, which is where those
        builds run). Never guessed from the project number. Raises if it cannot be resolved.
        """
        url = f"https://cloudbuild.googleapis.com/v1/projects/{target_project_id}/locations/global/defaultServiceAccount"
        res = session.get(url, timeout=30.0)
        if res.status_code != 200:
            raise RuntimeError(
                f"could not resolve the Cloud Build default service account for '{target_project_id}' "
                f"(HTTP {res.status_code}: {str(getattr(res, 'text', ''))[:300]})"
            )
        resource = (res.json() or {}).get("serviceAccountEmail", "")
        email = resource.rsplit("/serviceAccounts/", 1)[-1] if "/serviceAccounts/" in resource else resource
        if not email or "@" not in email or "/" in email:
            raise RuntimeError(
                f"Cloud Build default service account for '{target_project_id}' is missing or malformed: {resource!r}"
            )
        return email

    def _stage_build_source(
        self,
        storage_client,
        session,
        target_project_id: str,
        bucket_name: str,
        object_name: str,
        payload: bytes,
        region: Optional[str] = None,
    ) -> None:
        """
        FD-4BA: upload the build source to the child project's staging bucket.

        - A new bucket is created in the build's region (FD-7M-a: `region`, the workload region the caller built
          for; None = the platform region, as before) with uniform bucket-level access and public access
          prevention enforced.
        - ``roles/storage.objectViewer`` is granted to the resolved Cloud Build service account only.
        - Public members (``allUsers`` / ``allAuthenticatedUsers``) left on this platform-owned staging bucket by
          earlier releases are removed.
        Every failure raises; nothing is uploaded anywhere else.
        """
        from google.cloud import storage

        bucket = storage_client.bucket(bucket_name)
        if not bucket.exists():
            new_bucket = storage.Bucket(storage_client, name=bucket_name)
            new_bucket.iam_configuration.uniform_bucket_level_access_enabled = True
            new_bucket.iam_configuration.public_access_prevention = "enforced"
            bucket = storage_client.create_bucket(new_bucket, project=target_project_id,
                                                  location=region or self._resolve_region())
            logger.info(f"Created isolated staging bucket 'gs://{bucket_name}' in project '{target_project_id}'")

        build_member = f"serviceAccount:{self._resolve_cloud_build_service_account(session, target_project_id)}"
        policy = bucket.get_iam_policy(requested_policy_version=3)
        changed = False
        kept_bindings = []
        for binding in list(policy.bindings):
            members = set(binding.get("members") or ())
            public = members & self._PUBLIC_IAM_MEMBERS
            if public:
                logger.warning(
                    f"Removing public member(s) {sorted(public)} from {binding.get('role')} on gs://{bucket_name}"
                )
                members -= public
                changed = True
            if members:
                kept_bindings.append({**binding, "members": members})
        has_grant = any(
            b.get("role") == "roles/storage.objectViewer" and not b.get("condition") and build_member in b["members"]
            for b in kept_bindings
        )
        if not has_grant:
            kept_bindings.append({"role": "roles/storage.objectViewer", "members": {build_member}})
            changed = True
        if changed:
            policy.bindings = kept_bindings
            bucket.set_iam_policy(policy)
            logger.info(f"Set gs://{bucket_name} objectViewer to {build_member} (no public members)")

        blob = bucket.blob(object_name)
        blob.upload_from_string(payload, content_type="application/gzip")
        logger.info(f"Uploaded source tarball to gs://{bucket_name}/{object_name}")

    def _fetch_cloud_build_logs_tail(self, session, target_project_id: str, build_id: str, max_lines: int = 25) -> str:
        """Fetches the tail of Cloud Logging entries for a specific Cloud Build ID using native REST API."""
        try:
            log_url = "https://logging.googleapis.com/v2/entries:list"
            payload = {
                "resourceNames": [f"projects/{target_project_id}"],
                "filter": f'resource.type="build" AND resource.labels.build_id="{build_id}"',
                "orderBy": "timestamp desc",
                "pageSize": max_lines,
            }
            res = session.post(log_url, json=payload, timeout=15.0)
            if res.status_code == 200:
                entries = res.json().get("entries", [])
                lines = [e.get("textPayload", "") for e in entries if e.get("textPayload")]
                return "\n".join(reversed(lines))
        except Exception as e:
            logger.debug(f"Could not retrieve Cloud Logging entries for build {build_id}: {e}")
        return ""

    def _is_transient_buildpack_failure(self, status: str, log_text: str, fail_detail: str) -> bool:
        """Determines if a buildpack build failure is due to transient upstream network/registry flakiness."""
        if status == "INTERNAL_ERROR":
            return True
        transient_indicators = (
            "503 service unavailable",
            "502 bad gateway",
            "504 gateway timeout",
            "unexpected status code 50",
            "artifacts-uploads",
            "connection reset by peer",
            "rate limit exceeded",
            "resource_exhausted",
            "transport endpoint is not connected",
            "failed to export",
        )
        combined = f"{fail_detail}\n{log_text}".lower()
        return any(ind in combined for ind in transient_indicators)

    # FD55-W6a (A12): _reconcile_modular_compute_collisions DELETED (it re-pointed module.compute's service_name /
    # image on a name collision).

    # FD-4DE: _reconcile_cloud_run_service DELETED with the startup-probe override it served (a failed apply whose
    # text named a startup-probe failure was reported SUCCESS when some revision of the service was Ready, although
    # the apply had stopped part-way). A failed apply now stays FAILED with the engine's text.

    def _list_cloud_run_services(self, target_project_id: str,
                                 region: str) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
        """FD-4DE: (services, None) for the complete Cloud Run v2 service listing of one child-project region (REST
        through AuthorizedSession, invariant 7), else (None, SERVICE_URL_API_UNAVAILABLE). A listing longer than
        _CLOUD_RUN_LIST_MAX_PAGES pages is not complete, so it is unavailable too."""
        try:
            from google.auth.transport.requests import AuthorizedSession

            credentials = self._child_credentials(target_project_id)   # FD4BD-Q3
            session = AuthorizedSession(credentials)
        except Exception as auth_err:
            logger.warning(f"Cloud Run service listing of '{target_project_id}': no credential "
                           f"({type(auth_err).__name__}).")
            return None, SERVICE_URL_API_UNAVAILABLE
        base = f"{CLOUD_RUN_API}/projects/{target_project_id}/locations/{region}/services"
        services: List[Dict[str, Any]] = []
        page_token = ""
        for _ in range(_CLOUD_RUN_LIST_MAX_PAGES):
            params: Dict[str, Any] = {"pageSize": 100}
            if page_token:
                params["pageToken"] = page_token
            try:
                resp = session.get(base, params=params, timeout=15.0)
                if resp.status_code != 200:
                    logger.warning(f"Cloud Run service listing of '{target_project_id}' ({region}): "
                                   f"HTTP {resp.status_code}.")
                    return None, SERVICE_URL_API_UNAVAILABLE
                body = resp.json()
            except Exception as list_err:
                logger.warning(f"Cloud Run service listing of '{target_project_id}' ({region}) failed: "
                               f"{type(list_err).__name__}.")
                return None, SERVICE_URL_API_UNAVAILABLE
            if not isinstance(body, dict):
                return None, SERVICE_URL_API_UNAVAILABLE
            services.extend(s for s in (body.get("services") or []) if isinstance(s, dict))
            page_token = body.get("nextPageToken") or ""
            if not isinstance(page_token, str) or not page_token:
                return services, None
        logger.warning(f"Cloud Run service listing of '{target_project_id}' ({region}) has more than "
                       f"{_CLOUD_RUN_LIST_MAX_PAGES} pages; treated as unavailable.")
        return None, SERVICE_URL_API_UNAVAILABLE

    def _rollout_cloud_run_revision(
        self,
        target_project_id: str,
        service_name: str,
        region: Optional[str] = None,
        image_tag: Optional[str] = None,
        max_wait_seconds: int = 90,
        poll_interval: int = 4,
    ) -> Tuple[bool, str, str]:
        """
        Forces Cloud Run to deploy a fresh revision from the newly compiled container image
        (Cloud Separation of Concerns Pattern).
        1. Fetches current Cloud Run v2 service description via REST API using AuthorizedSession.
        2. Sets template annotation/label nonce to guarantee revision regeneration even if image tag string is unchanged.
        3. Updates template container image if provided, clears specific template.revision name.
        4. Issues PATCH to Cloud Run v2 API with updateMask=template.
        5. Polls until latestReadyRevision advances and conditions report Ready.
        Returns (success, revision_name, uri).
        """
        import time
        region = region or self._resolve_region()   # FD-4AL: the caller's workload region, else the platform region
        logger.info(
            f"🚀 Initiating Post-Apply Cloud Run revision rollout for '{service_name}' in '{target_project_id}'..."
        )
        start_time = time.time()

        try:
            from google.auth.transport.requests import AuthorizedSession

            credentials = self._child_credentials(target_project_id)   # FD4BD-Q3
            session = AuthorizedSession(credentials)
        except Exception as auth_err:
            logger.warning(f"Could not initialize AuthorizedSession for Cloud Run revision rollout: {auth_err}")
            return False, "", ""

        run_url = f"https://run.googleapis.com/v2/projects/{target_project_id}/locations/{region}/services/{service_name}"

        try:
            resp = session.get(run_url, timeout=10.0)
            if resp.status_code != 200:
                logger.warning(f"Cloud Run revision rollout: service '{service_name}' not found in '{target_project_id}' (HTTP {resp.status_code}).")
                return False, "", ""

            svc_data = resp.json()
            initial_ready_rev = svc_data.get("latestReadyRevision", "")
            tmpl = svc_data.get("template", {})

            if "labels" not in tmpl or not isinstance(tmpl["labels"], dict):
                tmpl["labels"] = {}
            tmpl["labels"]["client.knative.dev/nonce"] = f"deploy-{int(time.time())}"

            # FD55-3D RT F2: the "Declarative Image Preservation" substring rule (kept the current image when it held the
            # service name and the given one did not) is deleted. The caller passes the image the apply set for this
            # service (applied_cloud_run_services), so that exact image is set; nothing is judged by name.
            if image_tag and "containers" in tmpl and tmpl["containers"]:
                tmpl["containers"][0]["image"] = image_tag

            # Container-Spec Level Cache Busting (Cloud Run v2 Revision Trigger)
            # In Cloud Run v2, changing template.labels is metadata-only and will NOT re-pull :latest digests.
            # Upserting an environment variable inside template.containers[0] guarantees that Cloud Run v2
            # detects a container specification change, mints a new revision, and pulls the newest image digest.
            if "containers" in tmpl and tmpl["containers"]:
                c0 = tmpl["containers"][0]
                if "env" not in c0 or not isinstance(c0["env"], list):
                    c0["env"] = []
                nonce_str = str(int(time.time()))
                found_nonce = False
                for env_item in c0["env"]:
                    if isinstance(env_item, dict) and env_item.get("name") == "CASTOR_DEPLOY_NONCE":
                        env_item["value"] = nonce_str
                        found_nonce = True
                        break
                if not found_nonce:
                    c0["env"].append({"name": "CASTOR_DEPLOY_NONCE", "value": nonce_str})

            if "revision" in tmpl:
                del tmpl["revision"]

            patch_url = f"{run_url}?updateMask=template"
            patch_resp = session.patch(patch_url, json={"template": tmpl}, timeout=15.0)
            if patch_resp.status_code not in (200, 201):
                logger.warning(
                    f"Cloud Run revision rollout PATCH failed for '{service_name}': {patch_resp.status_code} {patch_resp.text[:300]}"
                )
                return False, "", ""

            logger.info(f"Cloud Run v2 API accepted revision update for '{service_name}'. Awaiting readiness...")

            while time.time() - start_time < max_wait_seconds:
                time.sleep(poll_interval)
                try:
                    chk_resp = session.get(run_url, timeout=10.0)
                    if chk_resp.status_code == 200:
                        chk_data = chk_resp.json()
                        uri = chk_data.get("uri", "")
                        latest_ready = chk_data.get("latestReadyRevision", "")
                        latest_created = chk_data.get("latestCreatedRevision", "")
                        conditions = {c.get("type"): (c.get("state") or c.get("status")) for c in chk_data.get("conditions", [])}
                        term_cond = chk_data.get("terminalCondition") or {}
                        if term_cond.get("type") == "Ready":
                            conditions["Ready"] = term_cond.get("state") or term_cond.get("status")

                        is_ready_cond = conditions.get("Ready") in ("CONDITION_SUCCEEDED", "True")
                        if latest_ready and latest_ready != initial_ready_rev and (latest_ready == latest_created or is_ready_cond):
                            rev_name = latest_ready.split("/")[-1]
                            elapsed = round(time.time() - start_time, 1)
                            logger.info(
                                f"✅ Cloud Run revision rollout successful after {elapsed}s! Revision '{rev_name}' is Ready. URL: {uri}"
                            )
                            return True, rev_name, uri
                except Exception as poll_err:
                    logger.debug(f"Cloud Run rollout poll notice: {poll_err}")

        except Exception as rollout_err:
            logger.warning(f"Cloud Run revision rollout encountered non-fatal error: {rollout_err}")

        return False, "", ""

    def deploy_workload(
        self,
        product_id: str,
        trace_id: str,
        hcl_files: Optional[Dict[str, str]] = None,
        target_project_id: Optional[str] = None,
        branch: Optional[str] = None,
        iac_engine: Optional[str] = None,
        destroy_policy: Optional[DestroyPolicy] = None,
        time_budget_s: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Lane 14 PR-0 (FD-4S): every apply inside the deployment runs behind the compliance plan gate
        (`_compliance_gated_apply`). A refusal stops the deployment and returns the gate's typed result
        (`status=FAILED`, `error_class` COMPLIANCE_VIOLATION / COMPLIANCE_UNAVAILABLE / UNKNOWN_PROFILE).
        EXP-7: `destroy_policy` (Express deploys only) adds the DESTROY_REQUIRES_APPROVAL check to every gated apply;
        None (every other caller) changes nothing.
        DEPLOY-SYNC-BUDGET: `time_budget_s` (the sync `/deploy` only: SYNC_DEPLOY_TIME_BUDGET_S) is one deadline,
        counted from here, that every OpenTofu command of this deploy respects; None (every other caller) changes
        nothing.
        WF-OPERATOR-FLAG (result contract): a failed result may carry `operator_required: True` (a JSON boolean,
        set together with its typed `error_class`). The terraform server and tf-applier pass it through to the
        workflow callback unchanged (`outcome.update(res)`); the workflow's check_deploy_status then stops the run
        for an operator whatever the class, like the operator classes in gate_errors.NON_REMEDIABLE_DEPLOY_CLASSES.
        FD-4DT sets it on its access refusals (ACCESS_WIDENING_UNAPPROVED / ACCESS_POLICY_INVALID /
        ACCESS_POLICY_INCOMPLETE).
        FD-4DT: before anything runs, the workload's current access record is rendered into the platform access var
        file (`render_deploy_access_vars`, passed as `PLATFORM_ACCESS_VARS_MANIFEST_KEY`); a refusal returns its typed
        result. A successful deploy that rendered the record writes one `WORKLOAD_ACCESS_APPLIED` audit entry.
        FD-4DT RT F3: a product id that is not canonical (`validate_product_id`, e.g. `Shop`, `shop_api`) is refused
        first (PRODUCT_ID_INVALID, operator_required), before any Firestore read."""
        try:
            validate_product_id(product_id)
        except UnsafePathError:
            message = (f"{PRODUCT_ID_INVALID}: product_id {product_id!r} is not a canonical workload id (lower-case "
                       "letters, digits and hyphens). Nothing was built, planned or applied.")
            logger.error(message)
            return {"status": "FAILED", "error_class": PRODUCT_ID_INVALID, "error": message,
                    "product_id": product_id, "trace_id": trace_id, "operator_required": True}
        try:
            access_text, access_summary = self._deploy_access_vars(product_id)
        except DeployAccessRefused as refused:
            logger.error(f"{refused.error_class}: deploy of '{product_id}' (trace {trace_id}) refused: {refused.message}")
            result = refused.result(product_id, trace_id)
            try:
                self._sync_feature_requests(
                    product_id=product_id, trace_id=trace_id, is_successful_deploy=False, error_msg=result["error"])
            except Exception as sync_err:
                logger.warning(f"Feature-request sync after an access refusal failed: {type(sync_err).__name__}")
            return result
        # The platform file always replaces a caller's or the repository's file at that path ("{}" = nothing rendered).
        hcl_files = dict(hcl_files or {})
        hcl_files[PLATFORM_ACCESS_VARS_MANIFEST_KEY] = access_text
        tf_var_registrations: List[Tuple[str, Dict[str, str]]] = []   # FD-4BD: what this deploy registered
        billing_registrations: List[Tuple[str, Dict[str, str]]] = []   # FD4BD-Q3: same lifetime
        apply_ctx: Dict[str, Any] = {}   # TI-5a: set by the impl (intent workspace)
        # FD-4AQ W3 (AQ-5): deploy scope for the OpenTofu time limits (a timed-out command stops the deploy).
        timeout_slot = self._tofu_timeout_slot()
        outer_scope = (getattr(timeout_slot, "in_deploy", False), getattr(timeout_slot, "message", None),
                       getattr(timeout_slot, "deadline", None), getattr(timeout_slot, "budget_s", None))
        timeout_slot.in_deploy, timeout_slot.message = True, None
        if time_budget_s is not None:   # DEPLOY-SYNC-BUDGET (else a nested deploy keeps the outer one's deadline)
            timeout_slot.deadline = time.monotonic() + float(time_budget_s)
            timeout_slot.budget_s = float(time_budget_s)
        try:
            result = self._with_tofu_timeout_class(self._deploy_workload_impl(
                product_id=product_id,
                trace_id=trace_id,
                hcl_files=hcl_files,
                target_project_id=target_project_id,
                branch=branch,
                iac_engine=iac_engine,
                tf_var_registrations=tf_var_registrations,
                destroy_policy=destroy_policy,
                apply_ctx=apply_ctx,
                billing_registrations=billing_registrations,
            ))
            # TI-5a (S2-F F1 subset): on an intent workspace every untyped failure also carries a typed report: the
            # engine's text verbatim as one TF.UNPARSED_APPLY_ERROR (nothing is parsed out of error text). A
            # failure that already has an error_class (operator classes, typed refusals) or a report is unchanged.
            if (apply_ctx.get("intent_ws") and isinstance(result, dict)
                    and result.get("status") != "SUCCESS" and not result.get("error_class")
                    and "validation_report" not in result):
                # Fable RT F1: no engine result here, so no tofu claim and nothing read from disk (see the report)
                result = dict(result, validation_report=apply_validation_report(
                    "", apply_ctx.get("workspace_dir") or "", engine_result=False,
                    fallback_error=str(result.get("error") or result.get("stderr") or "apply failed")))
            # DEPLOY-FAILURE-OWNER-ROUTER: every failed result gets its owner route (after the TI-5a report, which keeps
            # the engine text verbatim); a non-developer one is typed and flagged operator_required (the workflow
            # stops for the operator), and the route is recorded for the gateway's remediation allow-list. A
            # developer-owned or already typed result is unchanged.
            result = self._route_failed_deploy(result, trace_id)
            if isinstance(result, dict) and result.get("status") == "SUCCESS" and access_summary.get("rendered"):
                self._audit_access_applied(product_id, trace_id, access_summary)
            return self._with_deploy_region(self._with_deploy_warnings(result, apply_ctx), apply_ctx)
        except (compliance_gate.ComplianceGateRefused, DestroyBlocked) as refused:
            result = self._with_deploy_region(self._with_deploy_warnings(dict(refused.result), apply_ctx), apply_ctx)
            try:
                self._sync_feature_requests(
                    product_id=product_id, trace_id=trace_id, is_successful_deploy=False, error_msg=result["error"]
                )
            except Exception as sync_err:
                logger.warning(f"Feature-request sync after a compliance refusal failed: {type(sync_err).__name__}")
            # DEPLOY-FAILURE-OWNER-ROUTER RT F1: a typed refusal raised from the gated apply gets its route too (e.g.
            # ReservedEnvRefused, IAC_DEFECT = DEVELOPER); without it the gateway's allow-list would refuse the repair
            return self._route_failed_deploy(result, trace_id)
        finally:
            (timeout_slot.in_deploy, timeout_slot.message, timeout_slot.deadline,
             timeout_slot.budget_s) = outer_scope
            # FD-4BD: the platform secrets this deploy registered leave memory with the deploy (RT F2: only its own).
            for reg_key, reg_vars in tf_var_registrations:
                self._forget_workspace_tf_vars(reg_key, reg_vars)
            for reg_key, reg_billing in billing_registrations:   # FD4BD-Q3
                self._forget_workspace_billing(reg_key, reg_billing)

    def _deploy_access_vars(self, product_id: str) -> Tuple[str, Dict[str, Any]]:
        """FD-4DT: read `workloads/{pid}` and render the platform access var file (`render_deploy_access_vars`).
        No Firestore client (eval harness, direct tests) -> "{}" (the committed values apply, as before). A read that
        fails -> ACCESS_POLICY_UNAVAILABLE (whether a newer or a widened record exists is unknown: never guessed)."""
        if not self.db:
            logger.info(f"{ACCESS_VARS_NOT_RENDERED}: '{product_id}': no Firestore client; the committed access "
                        "values apply")
            return "{}", {"rendered": False, "reason": "NO_FIRESTORE_CLIENT"}
        try:
            snap = self.db.collection("workloads").document(product_id).get()
            workload = snap.to_dict() if getattr(snap, "exists", False) is True else None
        except Exception as err:  # noqa: BLE001 - typed refusal below, never a silent fallback
            raise DeployAccessRefused(ACCESS_POLICY_UNAVAILABLE, f"workloads/{product_id} unreadable "
                                      f"({type(err).__name__})", operator_required=False) from None
        text, summary = render_deploy_access_vars(product_id, workload)
        if summary.get("rendered"):
            logger.info(f"FD-4DT: deploy of '{product_id}' applies the current access record: mode {summary['mode']}, "
                        f"{len(summary['invoker_principals'])} invoker(s) (updated {summary.get('access_updated_at')})")
        else:
            logger.info(f"{ACCESS_VARS_NOT_RENDERED}: '{product_id}': {summary['reason']}; the committed access values "
                        "apply")
        return text, summary

    def _audit_access_applied(self, product_id: str, trace_id: str, summary: Dict[str, Any]) -> None:
        """FD-4DT: one `workloads/{pid}/audit_logs` entry for a successful deploy that applied the current record
        (best effort: the apply already happened, so a failed write is logged, never a failed deploy)."""
        if not self.db:
            return
        try:
            self.db.collection("workloads").document(product_id).collection("audit_logs").document().set({
                "action": ACCESS_APPLIED_AUDIT_ACTION,
                "operator_email": "tf-applier",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "trace_id": trace_id,
                "mode": summary.get("mode"),
                "invoker_principals": list(summary.get("invoker_principals") or []),
                "access_updated_at": summary.get("access_updated_at"),
                "access_updated_by": summary.get("access_updated_by"),
                "var_file": PLATFORM_ACCESS_VARS_FILE,
            })
        except Exception as err:  # noqa: BLE001
            logger.warning(f"FD-4DT: the {ACCESS_APPLIED_AUDIT_ACTION} audit entry of '{product_id}' (trace "
                           f"{trace_id}) was not written: {type(err).__name__}")

    @staticmethod
    def _signin_key_missing_warning(target_project_id: str) -> Dict[str, str]:
        """F3: the typed warning of a PUBLIC_APP deploy without its web sign-in key (the resolver logged the step)."""
        message = (f"{SIGNIN_KEY_MISSING}: the web sign-in key '{WEB_KEY_ID}' of project '{target_project_id}' could "
                   f"not be created or read (the deploy log names the step). The public app was deployed without it, "
                   f"so its Google sign-in does not work until a later deploy gets the key.")
        logger.warning(message)
        return {"code": SIGNIN_KEY_MISSING, "message": message}

    @staticmethod
    def _with_deploy_warnings(result: Any, apply_ctx: Mapping[str, Any]) -> Any:
        """F3: a deploy that recorded warnings returns them as `warnings` (a list of {code, message}); a deploy
        without warnings returns its result object unchanged."""
        warnings = apply_ctx.get("warnings")
        if not warnings or not isinstance(result, dict):
            return result
        return dict(result, warnings=list(result.get("warnings") or []) + list(warnings))

    @staticmethod
    def _with_deploy_region(result: Any, apply_ctx: Mapping[str, Any]) -> Any:
        """FD-7M-a (SAT-22): a deploy that resolved its region returns it as `region` (the tf-applier's stockout purge
        uses it); a result that already names one, a deploy stopped before the region and a non-dict are unchanged."""
        region = apply_ctx.get("region")
        if not region or not isinstance(result, dict) or "region" in result:
            return result
        return dict(result, region=region)

    def _with_tofu_timeout_class(self, result: Any) -> Any:
        """FD-4AQ W3 (AQ-5): when an OpenTofu command of this deploy hit its time limit, the deploy fails with
        error_class TOFU_TIMEOUT (whatever the later steps returned; nothing ran after the timeout). Otherwise the
        result is returned unchanged."""
        message = getattr(self._tofu_timeout_slot(), "message", None)
        if not message:
            return result
        out = dict(result) if isinstance(result, dict) else {}
        out.update(status="FAILED", error_class=TOFU_TIMEOUT, error=message)
        return out

    def _sqladmin_session(self, project_id: Optional[str]):
        """CLOUDSQL-CREATE-OWN-OPERATION: an AuthorizedSession as the workload's deployer (FD4BD-Q3), or None."""
        try:
            from google.auth.transport.requests import AuthorizedSession
            return AuthorizedSession(self._child_credentials(project_id))
        except Exception as cred_err:  # noqa: BLE001 - the callers fail typed or leave the failure unchanged
            logger.warning(f"CLOUDSQL_CREATE_NOT_CHECKED: no SQL Admin session for '{project_id}' "
                           f"({type(cred_err).__name__})")
            return None

    @staticmethod
    def _sqladmin_get_json(sess: Any, url: str, timeout: float) -> Optional[Dict[str, Any]]:
        """GET `url` -> the JSON object of a 200 answer, else None (logged; typed by the caller)."""
        try:
            resp = sess.get(url, timeout=timeout)
            body = resp.json() if resp.status_code == 200 else None
        except Exception as get_err:  # noqa: BLE001 - an unreadable answer is None
            logger.warning(f"SQL Admin read of {url} failed: {type(get_err).__name__}")
            return None
        return body if isinstance(body, dict) else None

    def _sqladmin_timeout(self) -> float:
        """A SQL Admin GET's timeout: GET_TIMEOUT_S, capped to what is left of a deploy's overall budget."""
        left = self._deploy_time_left()
        cap = cloudsql_create_recovery.GET_TIMEOUT_S
        return cap if left is None else max(0.0, min(cap, left))

    def _cloudsql_adoption_refusal(self, project_id: Optional[str], cand: Any,
                                   plan_json: Optional[Mapping[str, Any]]) -> Optional[str]:
        """CLOUDSQL-CREATE-OWN-OPERATION RT F1/F2: the W7 409 adoption of an existing Cloud SQL instance (like the
        bucket owner check): None when it may be imported, else why not (instance not RUNNABLE, a `root`@`%` user,
        a planned backup restore, unreadable). Typed REST fields only."""
        csql = cloudsql_create_recovery
        after = csql.planned_after(plan_json, cand.address)
        name = after.get("name")
        if not (isinstance(name, str) and name and project_id):
            return "the planned instance name is not known"
        timeout = self._sqladmin_timeout()
        sess = self._sqladmin_session(project_id) if timeout > 0 else None
        if sess is None:
            return "the instance could not be read (no SQL Admin session or no deploy time left)"
        instance = self._sqladmin_get_json(sess, csql.instance_url(project_id, name), timeout)
        users = self._sqladmin_get_json(sess, csql.users_url(project_id, name), self._sqladmin_timeout()) \
            if isinstance(instance, Mapping) and instance.get("state") == "RUNNABLE" else None
        return csql.adoption_refusal(after, instance, users)

    def _recover_own_cloudsql_creates(self, product_id: str, workspace_dir: str, active_engine: Optional[str],
                                      project_id: Optional[str], region: Optional[str],
                                      plan_json: Optional[Mapping[str, Any]],
                                      not_before: float) -> Tuple[List[Dict[str, Any]], bool]:
        """CLOUDSQL-CREATE-OWN-OPERATION (cloudsql_create_recovery): after a failed apply, the Cloud SQL instances the
        applied plan creates that are not in state. When none has a CREATE operation inserted by this deploy
        (`not_before`), nothing is done: ([], False), the failure is unchanged. Otherwise every missing instance is
        decided (one without its own create is recorded, never skipped) after a wait bounded by wall clock and by the
        deploy's budget; only when EVERY one is adoptable (DONE without an error, RUNNABLE, `adoption_refusal` None)
        is each imported at the plan's address (all-or-nothing; IMPORTED). Returns (records, retry): `retry` True when
        every instance was imported (the caller applies once more). Typed fields only; nothing deleted or rewritten."""
        csql = cloudsql_create_recovery
        creates = csql.instance_creates(plan_json, project_id or "", region or "")
        if not creates or getattr(self._tofu_timeout_slot(), "message", None):
            return [], False
        listed = self._run_subprocess(["terraform", "state", "list"], cwd=workspace_dir, iac_engine=active_engine)
        if not listed.get("success"):
            logger.warning(f"CLOUDSQL_CREATE_NOT_CHECKED: `state list` failed for '{product_id}'; the apply failure is "
                           "reported as it is")
            return [], False
        in_state = csql.state_addresses(listed.get("stdout"))
        missing = [c for c in creates if c[0].address not in in_state]
        timeout = self._sqladmin_timeout()
        if not missing or timeout <= 0:
            return [], False
        sess = self._sqladmin_session(project_id)
        if sess is None:
            return [], False

        # 1. this deploy's own create of each missing instance
        found = []
        for resolved, name, after in missing:
            ops = self._sqladmin_get_json(sess, csql.operations_url(project_id, name), self._sqladmin_timeout())
            op = csql.own_create_operation(ops, project_id, name, not_before) if ops is not None else None
            found.append((resolved, name, after, ops is not None, op))
        if all(f[4] is None for f in found):
            logger.info(f"CLOUDSQL_CREATE_NOT_OWN: no CREATE operation of {[f[1] for f in found]} inserted by this "
                        "deploy (refused, older, or operations unreadable); the apply failure is reported as it is")
            return [], False

        # 2. wait for each (wall clock: WAIT_S or the deploy's budget minus the retry's reserve), then decide all
        wait_s = csql.wait_seconds(self._deploy_time_left())
        deadline = time.monotonic() + wait_s
        polls_left = int(wait_s // csql.POLL_S)   # also bounds the loop when the clock does not advance (tests)
        records: List[Dict[str, Any]] = []
        adoptable = []
        for resolved, name, after, readable, op in found:
            if op is None:
                records.append(csql.record(
                    resolved.address, name, None, None, csql.NO_OWN_OPERATION if readable else csql.UNREADABLE,
                    "no CREATE operation of this instance inserted by this deploy" if readable
                    else "the instance's operations could not be read"))
                continue
            op_name = op.get("name")
            logger.warning(f"CLOUDSQL_CREATE_WAIT: the apply failed while this deploy's create of Cloud SQL instance "
                           f"'{name}' (operation {op_name}, {op.get('status')}, error codes {csql.error_codes(op)}) "
                           "was outside state" + ("" if op.get("status") == "DONE" else
                                                  f"; waiting up to {max(0.0, deadline - time.monotonic()):.0f} s"))
            while (op.get("status") != "DONE" and isinstance(op_name, str) and op_name and polls_left > 0
                   and deadline - time.monotonic() > csql.POLL_S):
                time.sleep(csql.POLL_S)
                polls_left -= 1
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                fresh = self._sqladmin_get_json(sess, csql.operation_url(project_id, op_name),
                                                min(csql.GET_TIMEOUT_S, remaining))
                if fresh is not None:
                    op = fresh
            instance = users = None
            if op.get("status") == "DONE":
                instance = self._sqladmin_get_json(sess, csql.instance_url(project_id, name), self._sqladmin_timeout())
            outcome, reason = csql.decide(op, instance)
            if outcome == csql.ADOPT:
                users = self._sqladmin_get_json(sess, csql.users_url(project_id, name), self._sqladmin_timeout())
                refusal = csql.adoption_refusal(after, instance, users)
                if refusal:
                    outcome, reason = csql.REFUSED, refusal
            records.append(csql.record(resolved.address, name, op, instance, outcome, reason))
            if outcome == csql.ADOPT:
                adoptable.append((resolved, records[-1]))

        # 3. all-or-nothing: import only when every missing instance is adoptable. RT N1: an instance whose operations
        # were read and hold no create of this deploy (NO_OWN_OPERATION, e.g. a replica whose create never started) is
        # left out: the retry apply creates it or fails with the engine's error. UNREADABLE still blocks.
        if any(r["outcome"] not in (csql.ADOPT, csql.NO_OWN_OPERATION) for r in records):
            return records, False
        for resolved, rec in adoptable:
            imp = self._run_subprocess(["terraform", "import", "-input=false", resolved.address, resolved.import_id],
                                       cwd=workspace_dir, iac_engine=active_engine)
            if imp.get("success"):
                rec["outcome"] = csql.IMPORTED
            else:
                rec["outcome"] = csql.IMPORT_FAILED
                rec["reason"] = (f"`import` of '{resolved.import_id}' failed: "
                                 f"{(imp.get('stderr') or imp.get('stdout') or 'no output').strip()[:300]}")
        return records, all(r["outcome"] == csql.IMPORTED for _res, r in adoptable)

    # ------------------------------------------------------------------------------------------------------------------
    # DEPLOY-FAILURE-OWNER-ROUTER (register row, owner 11-13; plan docs/planning/deploy-failure-owner-router-plan.md)
    # ------------------------------------------------------------------------------------------------------------------
    def _route_failed_deploy(self, result: Any, trace_id: Optional[str]) -> Any:
        """Every failed deploy result gets a `failure_route` (deploy_failure_router). A result with a typed class is
        returned unchanged, its route only recorded (IAC_DEFECT = DEVELOPER); an untyped one uses the route its failure
        point set (validate / plan /
        apply / init / build), else UNKNOWN (CLASSIFY_NOT_RUN). Non-developer routes make the result typed and
        operator_required. The route is recorded on the run for the gateway's remediation allow-list."""
        if not isinstance(result, dict) or result.get("status") == "SUCCESS":
            return result
        given = result.get(dfr.FAILURE_ROUTE_FIELD)
        phase = given.get("phase") if isinstance(given, dict) else dfr.PHASE_UNKNOWN
        if result.get("error_class"):
            # a typed result is returned exactly as it is (same object); only its route is recorded for the gateway.
            # RT F4: one typed after its failure point set a route (TOFU_TIMEOUT over a plan failure) gets the typed
            # route in place of the stale one, in a copy, so the callback body and the record agree.
            typed = dfr.route_of_typed_result(result, phase or dfr.PHASE_UNKNOWN)
            if dfr.FAILURE_ROUTE_FIELD in result:
                result = dict(result, **{dfr.FAILURE_ROUTE_FIELD: typed})
            self._record_failure_route(trace_id, typed, dfr.remediation_text(result))
            return result
        if isinstance(given, dict) and given.get("owner") in dfr.OWNERS:
            r = given
        else:
            r = dfr.route(dfr.UNKNOWN, dfr.PHASE_UNKNOWN, dfr.BASIS_CLASSIFY_NOT_RUN)
        out = dfr.apply_route(result, r)
        if r.get("owner") != dfr.DEVELOPER:
            logger.error(f"{out.get('error_class')}: deploy failure routed to {r.get('owner')} (phase {r.get('phase')}, "
                         f"{r.get('basis')}); not sent to the developer")
        self._record_failure_route(trace_id, out[dfr.FAILURE_ROUTE_FIELD], dfr.remediation_text(out))
        return out

    def _record_failure_route(self, trace_id: Optional[str], route_rec: Dict[str, Any], error_text: str) -> None:
        """`pipeline_executions/{trace}.stages.terraform.failure_route` = the route plus the sha256 of the error text the
        callback delivers (the gateway pairs it with the workflow's tf_remediation_context by exact equality). An
        update, never a create: a trace with no run record gets none. A failed write is logged; the gateway then
        refuses the developer (fail closed)."""
        if not (self.db and trace_id):
            return
        record = dict(route_rec, error_sha256=dfr.error_digest(error_text), recorded_at=time.time())
        try:
            self.db.collection("pipeline_executions").document(trace_id).update({dfr.STAGE_ROUTE_FIELD_PATH: record})
        except Exception as rec_err:  # noqa: BLE001 - logged; the gateway's allow-list then refuses (fail closed)
            logger.warning(f"DEPLOY_FAILURE_ROUTE_NOT_RECORDED: run '{trace_id}' ({type(rec_err).__name__}); a "
                           "developer remediation of this failure will be refused")

    def _route_validate_failure(self, validate_json_stdout: Any, workspace_dir: str, files: Mapping[str, Any],
                                intent_ws: bool, report: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """The route of a failed `validate`: an intent workspace's typed report (unchanged), else the legacy owner rule
        over `validate -json`'s error diagnostics."""
        diags = dfr.error_diagnostics_from_validate(validate_json_stdout)
        if intent_ws:
            return dfr.route_from_report(report, phase=dfr.PHASE_VALIDATE, raw_diags=diags)
        return dfr.route_from_legacy_diagnostics(diags, phase=dfr.PHASE_VALIDATE, workspace_dir=workspace_dir,
                                                 manifest=(files or {}).keys(), is_golden=is_golden_module_file,
                                                 user_owned=apply_user_owned)

    def _classify_plan_failure(self, workspace_dir: str, active_engine: Optional[str], files: Mapping[str, Any],
                               intent_ws: bool) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
        """(route, typed report or None) of a failed gated plan, from ONE read-only re-plan: `plan -json -lock=false`,
        no plan file, the same platform access var file, its own bounded budget. Exit 0 = the failure did not
        reproduce (PROVIDER_TRANSIENT). Its own timeout never turns the deploy into TOFU_TIMEOUT (the deploy's commands
        all ran); the route is then UNKNOWN (CLASSIFY_TIMED_OUT). Intent workspaces: the diagnostics also become the
        result's typed report (apply_validation_report, source "apply")."""
        slot = self._tofu_timeout_slot()
        budget = CLASSIFY_PLAN_BUDGET_S
        left = self._deploy_time_left()
        if left is not None:
            budget = min(budget, left)
        if getattr(slot, "message", None) or budget < CLASSIFY_PLAN_MIN_S:
            return dfr.route(dfr.UNKNOWN, dfr.PHASE_PLAN, dfr.BASIS_CLASSIFY_NOT_RUN), None
        cmd = ["terraform", "plan", "-json", "-input=false", "-no-color", "-lock=false"]
        if os.path.isfile(os.path.join(workspace_dir, PLATFORM_ACCESS_VARS_FILE)):
            cmd.append(f"-var-file={PLATFORM_ACCESS_VARS_FILE}")   # exactly as the gated plan (FD-4DT)
        res = self._run_with_own_budget(cmd, workspace_dir, active_engine, budget)
        if res.get("timed_out"):
            slot.message = None   # this advisory run's timeout is not the deploy's (it ran after every deploy step)
            return dfr.route(dfr.UNKNOWN, dfr.PHASE_PLAN, dfr.BASIS_CLASSIFY_TIMED_OUT), None
        if res.get("success"):
            return dfr.route(dfr.PROVIDER_TRANSIENT, dfr.PHASE_PLAN, dfr.BASIS_PLAN_NOT_REPRODUCED), None
        diags = dfr.error_diagnostics_from_stream(res.get("stdout"))
        if intent_ws and diags:
            report = apply_validation_report(json.dumps({"diagnostics": diags}), workspace_dir,
                                             manifest_paths=(files or {}).keys())
            return dfr.route_from_report(report, phase=dfr.PHASE_PLAN, raw_diags=diags), report
        return dfr.route_from_legacy_diagnostics(diags, phase=dfr.PHASE_PLAN, workspace_dir=workspace_dir,
                                                 manifest=(files or {}).keys(), is_golden=is_golden_module_file,
                                                 user_owned=apply_user_owned), None

    def _compliance_gate_check(
        self,
        product_id: str,
        trace_id: str,
        workspace_dir: str,
        active_engine: Optional[str],
        plan_json: Optional[Dict[str, Any]] = None,
        plan_error: str = "",
    ) -> Dict[str, Any]:
        """Lane 14 PR-0: ask the compliance server's `/evaluate-plan` about an already-produced plan JSON (the saved
        plan of `apply_plan`, or the gated plan file of `_compliance_gated_apply`). Returns {"passed": True, ...} or
        {"passed": False, "result": <typed FAILED>}; `plan_json=None` is COMPLIANCE_UNAVAILABLE (PLAN_UNREADABLE)."""
        return compliance_gate.gate_plan(
            db=self.db, product_id=product_id, trace_id=trace_id, plan_json=plan_json, plan_error=plan_error
        )

    @staticmethod
    def _remove_gate_plan_file(workspace_dir: str, plan_file: str) -> None:
        """RT F8: the gated plan file holds the full plan (secrets); a failed removal is logged, never silent."""
        path = os.path.join(workspace_dir, plan_file)
        try:
            os.remove(path)
        except FileNotFoundError:
            pass
        except OSError as rm_err:
            logger.warning(f"GATE_PLAN_FILE_NOT_REMOVED: could not remove the gated plan file {path}: "
                           f"{type(rm_err).__name__}")

    def _compliance_gated_apply(
        self, product_id: str, trace_id: str, workspace_dir: str, active_engine: Optional[str],
        destroy_policy: Optional[DestroyPolicy] = None,
        plan_sink: Optional[Dict[str, Any]] = None,
        pre_apply_adopt: Optional[Callable[[Dict[str, Any]], int]] = None,
        expected_root_vars: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Lane 14 PR-0 (RT F4): every deploy_workload apply applies the plan the gate evaluated.
        DEPLOY-ROOT-VARS: `expected_root_vars` ({variable: the platform's input value}, platform_root_variable_values)
        is checked on every saved plan before anything else (root_variable_overrides); a finding raises
        RootVariableOverridden (APPLY.ROOT_VARIABLE_OVERRIDDEN) and nothing is imported or applied. None / {} (callers
        other than the deploy) checks nothing.
        FD-4CY W7: `plan_sink["plan_json"]` receives the parsed plan this call applies (None when there is none), so the
        caller adopts a 409 at that plan's exact address. `pre_apply_adopt(plan_json)` (Pass 0) imports planned creates
        that already exist and returns how many it imported; when it imported any, the saved plan is stale, so the
        plan runs once more and every check below runs on that new plan.
        `plan -out=<gate file>` -> `show -json` -> destroy check (FD-4AZ RT F2) -> compliance gate ->
        `apply <gate file>` -> the file is removed. No PASS cache and no plan-less apply: a state change between plan
        and apply makes OpenTofu refuse the stale saved plan (fail closed). A plan-time error is returned as the
        apply's result (an apply would print the same error) and nothing is applied. A gate refusal raises
        ComplianceGateRefused; a delete/replace of a deletion-protected resource raises DestroyBlocked. EXP-7: with a
        `destroy_policy` (Express), any other delete/replace of a resource in state that the operator did not approve
        exactly raises DestroyBlocked with DESTROY_REQUIRES_APPROVAL (after the DESTROY_BLOCKED check, which no
        approval overrides; before the compliance gate). An unreadable plan stays the gate's PLAN_UNREADABLE.
        settings-toggles ST-2: without a `destroy_policy` (Agent), with require_hitl_for_destructive_tf on (or
        unreadable), a non-tainted delete/replace of a DATA_HOLDING_RESOURCE_TYPES resource raises DestroyBlocked with
        DESTROY_REQUIRES_APPROVAL."""
        plan_file = compliance_gate.GATE_PLAN_FILE
        plan_cmd = ["terraform", "plan", f"-out={plan_file}", "-input=false", "-no-color"]
        if os.path.isfile(os.path.join(workspace_dir, PLATFORM_ACCESS_VARS_FILE)):
            # FD-4DT: the platform access var file (deploy_workload) wins over every other variable file of the
            # workspace (OpenTofu: -var-file after terraform.tfvars and every *.auto.tfvars*). Exact path, no glob.
            plan_cmd.append(f"-var-file={PLATFORM_ACCESS_VARS_FILE}")
        if plan_sink is not None:
            plan_sink["plan_json"] = None   # FD-4CY W7: never a previous call's plan
        try:   # FD-7L Phase 2b: the context the workspace was prepared with (its state bucket, its mode)
            state_ctx = self._workspace_runner_ctx(workspace_dir, product_id)
        except RunnerIdentityRefused as refused:
            raise RunnerContextRefusedAtApply(refused.result(product_id, trace_id)) from None
        try:
            plan_res = self._run_subprocess(plan_cmd, cwd=workspace_dir, iac_engine=active_engine)
            if not plan_res.get("success"):
                failed = dict(plan_res)
                failed["compliance_gate_phase"] = "plan"
                return failed
            plan_json, plan_err = self._read_saved_plan(workspace_dir, active_engine, plan_file=plan_file)
            self._refuse_root_variable_overrides(plan_json, expected_root_vars, product_id, trace_id)
            self._refuse_reserved_env_port(plan_json, product_id, trace_id)
            if (plan_json is not None and pre_apply_adopt is not None
                    and not self._content_policy_findings(plan_json, state_ctx, product_id, trace_id, log=False,
                                                   workspace_dir=workspace_dir)
                    and pre_apply_adopt(plan_json)):
                # FD-4CY W7: never an import for a plan the content policy refuses (it is refused just below). The
                # imports changed the state; OpenTofu refuses a saved plan made before them (stale plan): plan again,
                # and every check below runs on the new plan.
                self._remove_gate_plan_file(workspace_dir, plan_file)
                plan_res = self._run_subprocess(plan_cmd, cwd=workspace_dir, iac_engine=active_engine)
                if not plan_res.get("success"):
                    failed = dict(plan_res)
                    failed["compliance_gate_phase"] = "plan"
                    return failed
                plan_json, plan_err = self._read_saved_plan(workspace_dir, active_engine, plan_file=plan_file)
                self._refuse_root_variable_overrides(plan_json, expected_root_vars, product_id, trace_id)
                self._refuse_reserved_env_port(plan_json, product_id, trace_id)
            if plan_sink is not None:
                plan_sink["plan_json"] = plan_json
            if plan_json is not None:
                # FD-4AW-b: the content policy on the exact plan about to be applied (every file, human ones too)
                # FD-7L Phase 2b: this run's own state bucket; PLATFORM_IDENTITY_TOUCHED refused in PER_WORKLOAD
                violations = self._content_policy_findings(plan_json, state_ctx, product_id, trace_id,
                                                        workspace_dir=workspace_dir)
                if violations:
                    compliance_gate._record_evidence(self.db, product_id, trace_id, {
                        "gate": "content_policy", "verified": False, "error_class": ERROR_APPLY_CONTENT_POLICY,
                        "checked_at": time.time(), "plan_digest": compliance_gate.plan_digest(plan_json),
                        "content_policy_violations": violations[:50]})
                    raise ContentPolicyRefused(content_policy_refusal(product_id, trace_id, violations))
                # SECRET-INITIAL-VERSION F2: the generated version never becomes `latest` over an existing value
                # (Pass 0 / 409 adoption imports the secret; this is the plan after the imports)
                self._refuse_secret_generation_over_existing(plan_json, product_id, trace_id)
                blocked = protected_destroys(plan_json)
                if blocked:
                    # PR-0 tip RT N5: audit evidence for the blocked destroy (evidence only; never changes the outcome,
                    # _record_evidence swallows its own write errors).
                    compliance_gate._record_evidence(self.db, product_id, trace_id, {
                        "gate": "destroy", "verified": False, "error_class": ERROR_DESTROY_BLOCKED,
                        "checked_at": time.time(), "plan_digest": compliance_gate.plan_digest(plan_json),
                        "destroy_blocked": blocked[:50]})
                    raise DestroyBlocked(destroy_blocked_result(product_id, trace_id, blocked))
                if destroy_policy is not None:
                    refusal = destroy_approval_refusal(product_id, trace_id, plan_json, destroy_policy)
                    if refusal is not None:
                        compliance_gate._record_evidence(self.db, product_id, trace_id, {
                            "gate": "destroy_approval", "verified": False,
                            "error_class": ERROR_DESTROY_REQUIRES_APPROVAL, "checked_at": time.time(),
                            "plan_digest": compliance_gate.plan_digest(plan_json),
                            "destroy_requires_approval": refusal["destroy_requires_approval"][:50]})
                        raise DestroyBlocked(refusal)
                    approved = removals_requiring_approval(plan_json)
                    if approved:
                        # EXP-7 RT B2: an approved deletion is audited (which addresses, which plan) before it runs.
                        # Its own key next to `enforcement` in the same audit doc: the compliance gate's PASS evidence
                        # below writes `enforcement` and must not overwrite (or merge into) this record.
                        record_destroy_approval(self.db, product_id, trace_id, {
                            "gate": "destroy_approval", "verified": True, "checked_at": time.time(),
                            "plan_digest": compliance_gate.plan_digest(plan_json),
                            "approved_removals": sorted(destroy_policy.approved_removals),
                            "destroy_approved": approved[:50]})
                else:
                    # settings-toggles ST-2 (path b): Agent deploys -- data-holding removals need an operator
                    removals = data_holding_removals(plan_json)
                    if removals and destructive_tf_requires_approval():
                        compliance_gate._record_evidence(self.db, product_id, trace_id, {
                            "gate": "destroy_hitl", "verified": False,
                            "error_class": ERROR_DESTROY_REQUIRES_APPROVAL, "checked_at": time.time(),
                            "plan_digest": compliance_gate.plan_digest(plan_json),
                            "destroy_requires_approval": removals[:50]})
                        raise DestroyBlocked(hitl_destroy_refusal(product_id, trace_id, removals))
            gate = self._compliance_gate_check(
                product_id, trace_id, workspace_dir, active_engine, plan_json=plan_json, plan_error=plan_err
            )
            if not gate.get("passed"):
                raise compliance_gate.ComplianceGateRefused(gate["result"])
            return self._run_subprocess(
                ["terraform", "apply", "-input=false", "-auto-approve", "-no-color", plan_file],
                cwd=workspace_dir, iac_engine=active_engine,
            )
        finally:
            self._remove_gate_plan_file(workspace_dir, plan_file)

    def _refuse_root_variable_overrides(self, plan_json: Optional[Dict[str, Any]],
                                        expected_root_vars: Optional[Mapping[str, Any]], product_id: str,
                                        trace_id: str) -> None:
        """DEPLOY-ROOT-VARS: raises RootVariableOverridden when the saved plan gives a platform-set variable another
        value. No plan JSON (the compliance gate refuses it as PLAN_UNREADABLE) or no expected values: no check."""
        if plan_json is None or not expected_root_vars:
            return
        findings = root_variable_overrides(plan_json, expected_root_vars)
        if findings:
            result = root_variable_overridden_result(product_id, trace_id, findings)
            logger.error(result["error"])
            compliance_gate._record_evidence(self.db, product_id, trace_id, {
                "gate": "root_variables", "verified": False, "error_class": ERROR_TFVARS_OVERRIDES_PLATFORM,
                "code": APPLY_ROOT_VARIABLE_OVERRIDDEN, "checked_at": time.time(),
                "plan_digest": compliance_gate.plan_digest(plan_json), "variables": result["variables"]})
            raise RootVariableOverridden(result)

    def _refuse_secret_generation_over_existing(self, plan_json: Optional[Dict[str, Any]], product_id: str,
                                                trace_id: str) -> None:
        """SECRET-INITIAL-VERSION F2: raises SecretGenerationRefused when the plan creates the golden security-secret
        module's generated version for a secret that already exists (secret_generation_guard rule) and the secret has
        an ENABLED version, or its versions cannot be listed (REST via AuthorizedSession, invariant 7). A plan without
        such a pair makes no call."""
        pairs = secret_generation_guard.generated_versions_over_existing_secrets(plan_json)
        if not pairs:
            return
        findings: List[Dict[str, Any]] = []
        for pair in pairs:
            finding = dict(pair)
            project, secret_id = pair.get("project"), pair.get("secret_id")
            count: Optional[int] = None
            reason = "the plan does not name the secret's project and id"
            if project and secret_id:
                try:
                    from google.auth.transport.requests import AuthorizedSession
                    session = AuthorizedSession(self._child_credentials(project))
                    resp = session.get(secret_generation_guard.versions_url(project, secret_id), timeout=15.0)
                    try:
                        body = resp.json()
                    except ValueError:
                        body = None
                    count = secret_generation_guard.enabled_versions(resp.status_code, body)
                    reason = f"Secret Manager answered HTTP {resp.status_code}"
                except Exception as list_err:  # noqa: BLE001 - typed below: never read as "no version"
                    reason = f"Secret Manager could not be read ({type(list_err).__name__})"
            if count == 0:
                continue
            if count is None:
                finding.update(code=secret_generation_guard.APPLY_SECRET_VERSIONS_UNREADABLE, reason=reason)
            else:
                finding.update(code=secret_generation_guard.APPLY_SECRET_GENERATION_WOULD_SHADOW_EXISTING,
                               reason=f"{count}+ enabled version(s)")
            findings.append(finding)
        if not findings:
            return
        result = secret_generation_guard.refusal_result(product_id, trace_id, findings)
        logger.error(result["error"])
        compliance_gate._record_evidence(self.db, product_id, trace_id, {
            "gate": "secret_generation", "verified": False, "error_class": result["error_class"],
            "code": result["code"], "checked_at": time.time(), "plan_digest": compliance_gate.plan_digest(plan_json),
            "secret_generation_findings": result["secret_generation_findings"]})
        raise SecretGenerationRefused(result)

    def _refuse_reserved_env_port(self, plan_json: Optional[Dict[str, Any]], product_id: str, trace_id: str) -> None:
        """FD55-W6e: raises ReservedEnvRefused when the saved plan sets PORT on a Cloud Run service (before any
        import or apply). No plan JSON: no check (the compliance gate refuses it as PLAN_UNREADABLE)."""
        if plan_json is None:
            return
        findings = reserved_env_port_findings(plan_json)
        if findings:
            result = reserved_env_port_result(product_id, trace_id, findings)
            logger.error(result["error"])
            compliance_gate._record_evidence(self.db, product_id, trace_id, {
                "gate": "reserved_env", "verified": False, "error_class": IAC_DEFECT_ERROR_CLASS,
                "code": APPLY_RESERVED_ENV_PORT, "checked_at": time.time(),
                "plan_digest": compliance_gate.plan_digest(plan_json), "reserved_env": result["reserved_env"]})
            raise ReservedEnvRefused(result)

    def _resolve_workload_web_key(self, target_project_id: str, clean_pid: str) -> Tuple[str, str]:
        """AQ-3 (register AQ-3): the child project's ONE web sign-in key, for a PUBLIC_APP workload only. Returns
        (key string, project number); ("", ...) when it cannot be resolved (warnings name the step, never a value).

        All REST through AuthorizedSession (invariant 7), exact resource names only:
        - GET projects/<number>/locations/global/keys/stackvend-web. Present: its apiTargets are compared with
          WEB_KEY_API_TARGETS and PATCHed (?updateMask=restrictions, other restriction kinds kept) only when they
          differ; the operation is polled.
        - Absent: one-time migration of the key StackVend used to create (displayName exactly
          "Castor <pid> Web Key"): restricted the same way and logged LEGACY_WEB_KEY_RESTRICTED, never used; then
          POST ?keyId=stackvend-web with the restrictions, the operation polled to done, the key name taken from
          the operation's response.name only (never the operation name).
        No other key in the project is ever used or read, and no key without restrictions is ever created."""
        firebase_api_key = ""
        target_p_num = ""
        try:
            from google.auth.transport.requests import AuthorizedSession
            creds = self._child_credentials(target_project_id)   # FD4BD-Q3 (see the headers note)
            sess = AuthorizedSession(creds)
            # FD4BD-Q3 headers note: AuthorizedSession adds the credentials' `x-goog-user-project` (the child) after
            # this header, and requests keeps the last of two case-variant keys, so these calls bill the child -- as
            # they did when the child came from the process env. The line is unchanged (OQ-5b decides its fate).
            headers = {"X-Goog-User-Project": self.project_id or target_project_id}
            crm_res = sess.get(f"https://cloudresourcemanager.googleapis.com/v1/projects/{target_project_id}",
                               headers=headers, timeout=10.0)
            if crm_res.status_code == 200:
                target_p_num = str(crm_res.json().get("projectNumber", "") or "")
            if not target_p_num:
                logger.warning(f"Web sign-in key for '{target_project_id}': project number lookup returned "
                               f"{crm_res.status_code}; no key")
                return "", ""
            parent = f"projects/{target_p_num}/locations/global"
            key_name = f"{parent}/keys/{WEB_KEY_ID}"
            get_res = sess.get(f"{APIKEYS_API}/{key_name}", headers=headers, timeout=10.0)
            if get_res.status_code == 200:
                if not self._restrict_web_key(sess, headers, get_res.json() or {}):
                    return "", target_p_num
            elif get_res.status_code == 404:
                self._restrict_legacy_web_key(sess, headers, parent, clean_pid)
                create_res = sess.post(f"{APIKEYS_API}/{parent}/keys?keyId={WEB_KEY_ID}", headers=headers,
                                       json={"displayName": WEB_KEY_DISPLAY_NAME,
                                             "restrictions": {"apiTargets": list(WEB_KEY_API_TARGETS)}},
                                       timeout=10.0)
                if create_res.status_code not in (200, 201):
                    logger.warning(f"Web sign-in key creation on '{parent}' returned {create_res.status_code}; no key")
                    return "", target_p_num
                done = self._poll_apikeys_operation(sess, headers, create_res.json() or {})
                created = (done or {}).get("response") if isinstance(done, dict) else None
                if not isinstance(created, dict) or created.get("name") != key_name:
                    logger.warning(f"Web sign-in key creation on '{parent}' did not finish with the key "
                                   f"'{WEB_KEY_ID}'; no key")
                    return "", target_p_num
            else:
                logger.warning(f"Web sign-in key lookup '{key_name}' returned {get_res.status_code}; no key")
                return "", target_p_num
            ks_res = sess.get(f"{APIKEYS_API}/{key_name}/keyString", headers=headers, timeout=10.0)
            if ks_res.status_code == 200:
                firebase_api_key = str((ks_res.json() or {}).get("keyString", "") or "")
                logger.info(f"Resolved the web sign-in key '{WEB_KEY_ID}' for '{target_project_id}'")
            else:
                logger.warning(f"Could not read the key string of '{key_name}': {ks_res.status_code}")
        except Exception as key_err:
            logger.warning(f"Could not resolve the web sign-in key for '{target_project_id}': "
                           f"{type(key_err).__name__}")
        return firebase_api_key, target_p_num

    @staticmethod
    def _web_key_targets_match(restrictions: Any) -> bool:
        """AQ-3: the key's apiTargets are exactly WEB_KEY_API_TARGETS (services, no per-method limits)."""
        targets = (restrictions or {}).get("apiTargets") if isinstance(restrictions, dict) else None
        if not isinstance(targets, list):
            return False
        services = [t.get("service") if isinstance(t, dict) and set(t) == {"service"} else None for t in targets]
        return sorted(services, key=str) == sorted(t["service"] for t in WEB_KEY_API_TARGETS)

    def _restrict_web_key(self, sess: Any, headers: Dict[str, str], key: Dict[str, Any]) -> bool:
        """Compare-then-write: PATCH the key's restrictions to WEB_KEY_API_TARGETS (keeping any other restriction
        kind, e.g. a browser referrer list) only when its apiTargets differ. True when the key is restricted."""
        restrictions = key.get("restrictions") if isinstance(key.get("restrictions"), dict) else {}
        if self._web_key_targets_match(restrictions):
            return True
        name = key.get("name", "")
        res = sess.patch(f"{APIKEYS_API}/{name}?updateMask=restrictions", headers=headers,
                         json={"restrictions": dict(restrictions, apiTargets=list(WEB_KEY_API_TARGETS))},
                         timeout=10.0)
        if res.status_code != 200:
            logger.warning(f"Restricting the API key '{name}' returned {res.status_code}")
            return False
        done = self._poll_apikeys_operation(sess, headers, res.json() or {})
        if not (isinstance(done, dict) and not done.get("error")):
            logger.warning(f"Restricting the API key '{name}' did not finish")
            return False
        logger.info(f"Restricted the API key '{name}' to the Google sign-in APIs")
        return True

    def _restrict_legacy_web_key(self, sess: Any, headers: Dict[str, str], parent: str, clean_pid: str) -> None:
        """AQ-3 one-time migration: the key StackVend used to create without limits (displayName exactly
        "Castor <pid> Web Key") is restricted like the web key and never used. Runs only while stackvend-web is
        absent (bounded listing; exact display-name equality)."""
        legacy_name = f"Castor {clean_pid} Web Key"
        page_token = ""
        for _ in range(_APIKEYS_LIST_MAX_PAGES):
            url = f"{APIKEYS_API}/{parent}/keys" + (f"?pageToken={page_token}" if page_token else "")
            res = sess.get(url, headers=headers, timeout=10.0)
            if res.status_code != 200:
                logger.warning(f"Listing API keys on '{parent}' for the legacy key returned {res.status_code}")
                return
            body = res.json() or {}
            for key in body.get("keys", []) or []:
                if isinstance(key, dict) and key.get("displayName") == legacy_name:
                    if self._restrict_web_key(sess, headers, key):
                        logger.warning(f"{LEGACY_WEB_KEY_RESTRICTED}: '{key.get('name', '')}' ({legacy_name}) is "
                                       f"limited to the Google sign-in APIs and no longer used")
            page_token = body.get("nextPageToken") or ""
            if not page_token:
                return

    @staticmethod
    def _poll_apikeys_operation(sess: Any, headers: Dict[str, str], op: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """The finished long-running operation (``done`` true), polled by its exact name with a bound; else None."""
        for _ in range(_APIKEYS_OP_POLL_ATTEMPTS):
            if not isinstance(op, dict):
                return None
            if op.get("done"):
                return op
            name = op.get("name")
            if not isinstance(name, str) or not name.startswith("operations/"):
                return None
            time.sleep(_APIKEYS_OP_POLL_SECONDS)
            res = sess.get(f"{APIKEYS_API}/{name}", headers=headers, timeout=10.0)
            if res.status_code != 200:
                return None
            op = res.json() or {}
        return None

    @staticmethod
    def _unparseable_iac_result(code: str, detail: str, product_id: str, trace_id: str,
                                built: bool = False) -> Dict[str, Any]:
        """FD55-TFVARS: the typed stop for a workload tfvars / module source python-hcl2 cannot parse. IAC_DEFECT
        keeps the workflow's bounded developer remediation; the code leads the error (tf-applier keeps 120 chars)."""
        done = "Nothing was planned or applied." if built else "Nothing was built, planned or applied."
        error = f"{code}: {detail}. {done}"
        logger.error(error)
        return {"status": "FAILED", "error_class": IAC_DEFECT_ERROR_CLASS, "code": code, "error": error,
                "product_id": product_id, "trace_id": trace_id}

    @staticmethod
    def _workflow_invalid_result(err: Exception, product_id: str, trace_id: str) -> Dict[str, Any]:
        """FD55-W6c (W6a review F3): the typed stop for a committed workflow file that fails
        validate_github_workflow_yaml in prepare_workspace. File and line are the validator's own attributes (no
        parsing of its message); nothing is rewritten. The code leads the error (tf-applier keeps 120 chars)."""
        file_name = getattr(err, "filename", None) or None
        line = getattr(err, "line_number", None)
        message = getattr(err, "message", None) or str(err)
        where = f"{file_name}:{line}" if file_name and line else (file_name or "a workflow file")
        error = (f"{APPLY_WORKFLOW_INVALID}: the committed workflow {where} is not valid ({message}). The file was "
                 f"not changed; nothing was built, planned or applied.")
        logger.error(error)
        return {"status": "FAILED", "error_class": ERROR_WORKFLOW_INVALID, "code": APPLY_WORKFLOW_INVALID,
                "error": error, "file": file_name, "line": line, "product_id": product_id, "trace_id": trace_id}

    def _auto_tfvars_stop(self, workspace_dir: str, files: Mapping[str, str], hcl_files: Optional[Mapping[str, str]],
                          platform_tfvars: Mapping[str, str], active_engine: Optional[str], product_id: str,
                          trace_id: str) -> Optional[Dict[str, Any]]:
        """SAT-01 (FD4BD-Q1 deploy half; owner OQ-1 / OQ-2 / OQ-3 10-31): the typed stop for the variables files
        OpenTofu would load by itself from the prepared workspace root (workspace_auto_tfvars_findings), else None.
        The platform's access file is not judged when the platform wrote it (the deploy_workload manifest key). Each
        file is named by its repository path. Every stop is for an operator (operator_required: a developer
        regeneration cannot change a file a person committed): a symbolic link, a platform-owned variable, and a file
        whose variables cannot be listed (APPLY.TFVARS_UNPARSEABLE / IAC_DEFECT, the code and class of the root
        terraform.tfvars, Fable RT F1-1). The code leads the error (tf-applier keeps 120 chars); no file text is
        quoted."""
        skip = (PLATFORM_ACCESS_VARS_FILE,) if PLATFORM_ACCESS_VARS_MANIFEST_KEY in (hcl_files or {}) else ()
        owned = PLATFORM_OWNED_TFVARS | frozenset(platform_tfvars)
        findings = workspace_auto_tfvars_findings(workspace_dir, owned, skip=skip,
                                                  parser_bin=lambda: self._ensure_binary(active_engine or "OPENTOFU"))
        if not findings:
            return None

        def _source(name: str) -> str:
            if f"{WORKLOAD_DIR}/{name}" in files:
                return f"{WORKLOAD_DIR}/{name}"
            return name if name in files else f"{name} (in the deploy workspace, not from the repository)"

        codes = {code for code, _n, _r, _h in findings}
        code = next(c for c in (APPLY_TFVARS_SYMLINK, APPLY_TFVARS_OVERRIDES_PLATFORM, APPLY_TFVARS_UNPARSEABLE)
                    if c in codes)
        detail = "; ".join(f"{_source(name)} {reason}" for _c, name, reason, _h in findings)
        if code == APPLY_TFVARS_UNPARSEABLE:
            # Fable RT F1-1: the AI may not write these files (V2n), so this one is a person's: operator stop (the
            # code and IAC_DEFECT class stay those of the root terraform.tfvars; that path is unchanged).
            detail += (" (a person-committed variables file: fix or remove it in the repository; a developer "
                       "regeneration does not change it)")
            result = self._unparseable_iac_result(code, detail, product_id, trace_id)
            result["files"] = [_source(name) for _c, name, _r, _h in findings]
            result["operator_required"] = True   # WF-OPERATOR-FLAG: the workflow stops for an operator, no retry
            return result
        why = ("OpenTofu loads these variables files by itself after terraform.tfvars, so they would override the "
               "values the platform sets; the platform sets these variables itself, so remove them from the file"
               if code == APPLY_TFVARS_OVERRIDES_PLATFORM else
               "OpenTofu would read the file a link points to, which the platform does not check; commit the file "
               "itself, not a link")
        error = f"{code}: {detail}. {why}. Nothing was built, planned or applied."
        logger.error(error)
        error_class = ERROR_TFVARS_SYMLINK if code == APPLY_TFVARS_SYMLINK else ERROR_TFVARS_OVERRIDES_PLATFORM
        return {"status": "FAILED", "error_class": error_class, "code": code, "error": error,
                "files": [_source(name) for _c, name, _r, _h in findings],
                "variables": {_source(name): hits for _c, name, _r, hits in findings if hits},
                "operator_required": True, "product_id": product_id, "trace_id": trace_id}

    def _deploy_workload_impl(
        self,
        product_id: str,
        trace_id: str,
        hcl_files: Optional[Dict[str, str]] = None,
        target_project_id: Optional[str] = None,
        branch: Optional[str] = None,
        iac_engine: Optional[str] = None,
        tf_var_registrations: Optional[List[Tuple[str, Dict[str, str]]]] = None,
        destroy_policy: Optional[DestroyPolicy] = None,
        apply_ctx: Optional[Dict[str, Any]] = None,
        billing_registrations: Optional[List[Tuple[str, Dict[str, str]]]] = None,
    ) -> Dict[str, Any]:
        """
        `tf_var_registrations` (FD-4BD): deploy_workload's list; the workspace's TF_VAR registration is appended so
        deploy_workload's `finally` forgets exactly it. `billing_registrations` (FD4BD-Q3): the same for the
        workspace's quota project. `destroy_policy` (EXP-7): passed to every gated apply.
        `apply_ctx` (TI-5a): deploy_workload's dict; "intent_ws" is set when the repository holds the typed intent.

        Executes complete Terraform deployment for a workload:
        1. Resolves target child project from Firestore if not provided
        2. Fetches latest code files from GitHub repository
        3. Builds application container image via Google Cloud Buildpacks
        4. Executes terraform init and terraform apply -auto-approve
        5. Extracts outputs, writes default.tfstate to GCS, and updates Firestore
        """
        clean_pid = product_id.lower().replace("_", "-")
        stored_repo = None
        repo_identity_record = None
        recorded_default_branch = None   # FD-4CI-b-R1-WIF: the record's own value (not the deploy's branch argument)
        recorded_gha_deploy = None   # GHA-DEPLOY-SWITCH: workloads/{pid}.github_actions_deploy (missing = on)
        recorded_vcs = None
        record_region = None   # FD-7M-a: workloads/{pid}.region (None = no record region: the platform region)
        record_read_error: Optional[BaseException] = None   # FD-7M-a RT F1: the impl's own read failed (typed below)
        target_branch = branch
        active_engine = iac_engine
        # AQ-2: the workload's access record (workloads/{pid}.access) decides the tenant sign-in artifacts below.
        access_mode: Optional[str] = None
        access_state = "MISSING (no workload record)" if self.db else "UNREADABLE (no Firestore client)"
        if self.db:
            try:
                doc = self.db.collection("workloads").document(product_id).get()
                if doc.exists:
                    wdata = doc.to_dict() or {}
                    access_mode = workload_access_mode(wdata.get("access"))
                    if access_mode is None:
                        access_state = ("MISSING (no access record)" if wdata.get("access") is None
                                        else "UNREADABLE (not an access record with an exact mode)")
                    vended_pid = wdata.get("project_id")
                    if not target_project_id or (target_project_id == product_id and vended_pid and vended_pid != product_id):
                        target_project_id = vended_pid
                    stored_repo = wdata.get("github_repo")
                    repo_identity_record = wdata.get(GITHUB_REPOSITORY_IDENTITY_FIELD)
                    recorded_default_branch = wdata.get("default_branch")
                    if isinstance(wdata, dict):   # GHA-DEPLOY-SWITCH: read from a dict record only
                        recorded_gha_deploy = wdata.get(GITHUB_ACTIONS_DEPLOY_FIELD)
                        recorded_vcs = wdata.get("vcs_provider")
                        record_region = wdata.get("region")   # FD-7M-a (SAT-22): read from a dict record only
                    if not target_branch:
                        target_branch = wdata.get("default_branch")
                    if not active_engine:
                        active_engine = wdata.get("iac_engine")
            except Exception as e:
                logger.warning(f"Could not read workload metadata from Firestore: {e}")
                access_mode, access_state = None, f"UNREADABLE (Firestore workloads/{product_id}: {type(e).__name__})"
                record_read_error = e

        if not active_engine:
            try:
                from shared.settings import get_platform_settings
                active_engine = getattr(get_platform_settings().orchestration, "default_iac_engine", "OPENTOFU")
            except Exception:
                active_engine = "OPENTOFU"

        # Guardrail 1: One-way state gate preventing tofu -> terraform downgrade
        self._validate_no_engine_downgrade(product_id, active_engine)

        # FD-4AL: the one region of this deploy (runtime tfvars, image tags, REST paths, import IDs, GKE apply).
        # FD-7M-a (SAT-22): the workload's recorded region when it has one (approved), else the platform region.
        # The region classes are operator conditions (record / Settings): operator_required (WF-OPERATOR-FLAG) routes
        # them to the operator stop with their class kept; without it the workflow's generic deploy failure would
        # replace the class with DEPLOY_FAILED. Nothing is fetched, built, planned or applied.
        if record_read_error is not None:
            # FD-7M-a RT F1: the recorded region is unknown, so the region cannot be established; never the default.
            message = (f"{REGION_UNAVAILABLE}: workloads/{product_id} unreadable "
                       f"({type(record_read_error).__name__}); the workload's recorded region cannot be established. "
                       "Nothing was fetched, built, planned or applied.")
            logger.error(message)
            return {"status": "FAILED", "error_class": REGION_UNAVAILABLE, "error": message,
                    "product_id": product_id, "trace_id": trace_id, "operator_required": True}
        try:
            workload_region = self._resolve_workload_region(record_region)
        except RegionUnavailable as region_err:
            logger.error(str(region_err))
            return {"status": "FAILED", "error_class": REGION_UNAVAILABLE, "error": str(region_err),
                    "product_id": product_id, "trace_id": trace_id, "operator_required": True}
        except RegionNotApprovedError as region_err:
            logger.error(str(region_err))
            return {"status": "FAILED", "error_class": REGION_NOT_APPROVED, "error": str(region_err),
                    "product_id": product_id, "trace_id": trace_id, "approved_regions": list(region_err.approved),
                    "operator_required": True}
        if apply_ctx is not None:
            apply_ctx["region"] = workload_region   # FD-7M-a: deploy_workload puts it on the result (tf-applier purge)

        if not target_project_id or not isinstance(target_project_id, str):
            target_project_id = str(clean_pid)
        if not target_branch or not isinstance(target_branch, str):
            target_branch = "main"

        # FD4BD-Q3: no process-wide quota env and no `_active_target_project_id` any more: the child's quota project
        # is registered for this deploy's workspace below (tofu) and passed per call (`_child_credentials`).
        # FD-7L Phase 2a: the mode log line, and on a Per-workload install the brokered deployer must be registered
        # for this workspace and belong to the target project (typed refusal before any child call).
        runner_refusal = self._runner_admission(product_id, trace_id, target_project_id)
        if runner_refusal is not None:
            return runner_refusal

        _, _, full_repo_name = resolve_repo_identity(stored_repo, product_id=product_id)

        # FD-7L Phase 2b (plan 2.6 / 2.11): this run's state location. PLATFORM: the platform bucket (nothing read).
        # PER_WORKLOAD: the workload's READY signed record, whose project must be this deploy's target; anything else is
        # a typed stop before anything is fetched, built or applied (never a fallback to the platform bucket).
        try:
            state_ctx = self._runner_state_context(product_id, target_project_id=target_project_id)
        except RunnerIdentityRefused as refused:
            logger.error(str(refused))
            return refused.result(product_id, trace_id)
        if apply_ctx is not None:
            apply_ctx["state_ctx"] = state_ctx

        # 0. FD-4H: read-only pre-flight state-lock check. StackVend never deletes the lock object, never
        # force-unlocks automatically and never edits state bytes. A held lock fails fast (before the repo
        # fetch and container build) with the STATE_LOCKED contract; an operator clears it explicitly.
        if state_ctx.bucket:
            try:
                existing_lock = (self._wait_for_state_lock_release(product_id) if not state_ctx.per_workload
                                 else self._wait_for_state_lock_release(product_id, bucket=state_ctx.bucket,
                                                                        client_project=state_ctx.project_id))
            except Exception as lk_err:
                if state_ctx.per_workload:
                    # FD-7L 2b: a Per-workload run reads its own bucket with its brokered deployer; a lock it cannot
                    # read stops the deploy (typed) instead of proceeding on the platform's assumption.
                    code = getattr(lk_err, "code", None) if isinstance(lk_err, ri.RunnerIdentityError) else None
                    refused = RunnerIdentityRefused(code or STATE_LOCK_UNREADABLE,
                                                    f"the state lock of '{product_id}' in gs://{state_ctx.bucket} "
                                                    f"could not be read ({type(lk_err).__name__})")
                    logger.error(str(refused))
                    return refused.result(product_id, trace_id)
                existing_lock = None
                logger.warning(
                    f"Could not read the state lock for '{product_id}' ({lk_err}); proceeding. "
                    f"OpenTofu's own state locking still applies."
                )
            if existing_lock:
                locked = self._state_locked_result(product_id, existing_lock, phase="pre-flight")
                self._sync_feature_requests(
                    product_id=product_id,
                    trace_id=trace_id,
                    is_successful_deploy=False,
                    error_msg=locked["error"],
                )
                return locked

        # Fetch latest files from GitHub repository
        try:
            repo_files = self._fetch_repo_files(product_id, github_repo=stored_repo, branch=target_branch)
        except IncompleteRepoTreeError as tree_err:
            # FD-4D: a partial tree can plan the destruction of everything it is missing; nothing is built or run.
            error = f"{REPO_TREE_INCOMPLETE}: {tree_err}. Nothing was built, planned or applied."
            logger.error(error)
            return {"status": "FAILED", "error_class": REPO_TREE_INCOMPLETE, "error": error,
                    "product_id": product_id, "trace_id": trace_id, "tree_status": tree_err.tree_status}
        except RunnerIdentityRefused as refused:   # FD-7L Phase 4: the Per-workload repository read (typed)
            logger.error(str(refused))
            return refused.result(product_id, trace_id)
        # RT14-21: files that are not UTF-8 travel apart as exact bytes, so every text step below sees only `str`; they
        # are written byte for byte by prepare_workspace (the build tarball copies workspace bytes).
        binary_files = {k: v for k, v in repo_files.items() if isinstance(v, (bytes, bytearray))}
        files = {k: v for k, v in repo_files.items() if not isinstance(v, (bytes, bytearray))}
        if hcl_files:
            files.update(hcl_files)
            for k in hcl_files:
                binary_files.pop(k, None)
        # TI-5a (register TI-5a; plan RT F9): a repository with the typed IaC intent gets no text healing of its IaC
        # at apply. An intent needs the platform's topology record (the intent path is a typed-topology path) and
        # must parse: otherwise a typed refusal before anything is built, planned or applied (never a heal).
        intent_state = iac_intent_state(files)
        intent_ws = intent_state == "intent"
        if apply_ctx is not None:
            apply_ctx["intent_ws"] = intent_ws
        if intent_state == "unreadable" or (intent_ws and not manifest_has_service_topology(files)):
            code = APPLY_INTENT_UNREADABLE if intent_state == "unreadable" else APPLY_INTENT_WITHOUT_TOPOLOGY
            error = (f"{code}: {IAC_INTENT_REPO_PATH} "
                     + ("is not a typed IaC intent (schema iac_intent/v1)" if intent_state == "unreadable" else
                        "has no platform-rendered topology.json (service_topology/v1) beside it")
                     + ". Nothing was built, planned or applied.")
            logger.error(error)
            return {"status": "FAILED", "error_class": code, "error": error, "product_id": product_id,
                    "trace_id": trace_id}
        # FD-4D RT F1: the root config is one of these exact keys BEFORE the copy to the workspace root below.
        root_main_present = any(k in files for k in ("main.tf", "infra/workload/main.tf", "infra/workloads/main.tf"))

        # Pull HCL from infra/workload/ directory if present. FD-4D-b: each file is copied to its path below
        # infra/workload/ (subdirectories kept, never its basename), so a nested module's main.tf can never replace
        # the root main.tf. A direct child replaces a same-named root file exactly as before; a nested copy never
        # replaces a file the manifest already holds at that path.
        sources_unparseable: List[str] = []
        for path, content in list(files.items()):
            rel = workload_relpath(path)
            if rel is None:
                continue
            nested = "/" in rel
            # FD-4BW (Guardrail 2): module `source` values re-anchored to the workspace root from the parsed
            # module blocks (any formatting); only .tf files carry module blocks.
            if path.endswith(".tf"):
                try:
                    content = rewrite_flattened_module_sources(content, filename=path,
                                                               nested_repo_path=path if nested else "")
                except SourceUnparseableError as src_err:   # FD55-TFVARS: typed stop below, never a regex guess
                    sources_unparseable.append(str(src_err))
                    continue
            if nested and rel in files:
                logger.warning(f"FD-4D-b: '{path}' not copied to '{rel}': the repository already has that path")
                continue
            files[rel] = content

        # Inspect plural infra/workloads/ directory or legacy infra/ paths
        # FD55-W6e (A33, HB-15 DELETED, register FD55-W6e): no `resource` / `variable` block is copied out of
        # infra/workloads/ (plural) into custom.tf / variables.tf by text pattern any more, and no plural file is
        # dropped without a word. The plural directory is the root config only when nothing else gives the workspace
        # a main.tf (decided once, before the copy; before W6e a plural-only repository lost its outputs.tf /
        # variables.tf once its main.tf had been copied): then every plural .tf is copied to its path (FD-4D-b rules).
        # Beside another root config, any plural .tf stops the deploy typed (APPLY.PLURAL_WORKLOADS_NOT_APPLIED).
        # W6e review F6: a typed-intent workspace (which exists only when the typed-intent switch was on for it)
        # never uses infra/workloads/ as its root; any plural .tf there stops the same way instead of being left in
        # the workspace where OpenTofu ignores it (TI-5a: still never read, copied or edited).
        plural_tf = [p for p in files if p.startswith("infra/workloads/") and p.endswith(".tf")]
        if plural_tf and (intent_ws or "main.tf" in files):
            return self._unparseable_iac_result(
                APPLY_PLURAL_WORKLOADS_NOT_APPLIED,
                ("the typed IaC intent is this workload's root configuration" if intent_ws else
                 "another root configuration (infra/workload/, the repository root or the deploy request) already "
                 "provides main.tf")
                + ", so these files under infra/workloads/ would not be applied: " + ", ".join(sorted(plural_tf))
                + "; move their blocks into infra/workload/", product_id, trace_id)
        for path in plural_tf:
            content = files[path]
            tf_filename = workload_relpath(path, "infra/workloads")   # FD-4D-b: path kept, not the basename
            nested = "/" in tf_filename
            try:
                content = rewrite_flattened_module_sources(   # FD-4BW
                    content, filename=path, nested_repo_path=path if nested else "", workload_dir="infra/workloads")
            except SourceUnparseableError as src_err:   # FD55-TFVARS
                sources_unparseable.append(str(src_err))
                continue
            if nested and tf_filename in files:
                logger.warning(f"FD-4D-b: '{path}' not copied to '{tf_filename}': the repository already has "
                               f"that path")
                continue
            files[tf_filename] = content

        if sources_unparseable:
            return self._unparseable_iac_result(APPLY_SOURCE_UNPARSEABLE, "; ".join(sources_unparseable),
                                                product_id, trace_id)

        # FD55-W6e (A34 DELETED, register FD55-W6e): no `env { name = "PORT" }` block is regex-deleted from the .tf
        # files any more. A planned Cloud Run service that sets PORT (any form: literal, dynamic block, module input)
        # stops the gated apply before anything is imported or applied (reserved_env_port_findings on the saved
        # plan; APPLY.RESERVED_ENV_PORT); the developer's file is never edited. (The Cloud Build trigger / WIF
        # rewriter that used to run here was deleted with lane 8's FD-4U/FD-44 healer removal.)
        # FD55-W6e (A35 DELETED, "Guardrail 4"): no GKE text edits at deploy. Deleted: the `cluster_ca_certificate`
        # output appended to a vendored GKE module, the `kubernetes` required_providers entry, the appended
        # `google_client_config` / `provider "kubernetes"` (the golden render emits all three), the subnetwork
        # `ignore_changes = [secondary_ip_range]` injection (networking-vpc declares it), the 3-minute
        # kubernetes_deployment timeouts (FD-4AN; the provider's own default applies), the `repository_id` default
        # reset, and the Workload Identity bindings with a guessed datastore role. A GKE workload applies as committed.

        # Resolve canonical Artifact Registry repository ID
        ar_repo_name = clean_pid
        for k, v in files.items():
            if k.endswith(".tf") and 'resource "google_artifact_registry_repository"' in v:
                m = re.search(r'repository_id\s*=\s*(?:"([^"]+)"|replace\(var\.product_id,\s*"[^"]*",\s*"[^"]*"\))', v)
                if m:
                    if m.group(1):
                        ar_repo_name = m.group(1)
                    else:
                        ar_repo_name = clean_pid
                    break

        image_tag = f"{workload_region}-docker.pkg.dev/{target_project_id}/{ar_repo_name}/app:latest"
        standalone_sizing = resolve_workload_sizing(files)
        if not root_main_present:   # FD-4D (R04-1, RT F1): the root config itself, not just any infra/workload/ file
            logger.error(f"FATAL: Workload '{product_id}' contains no valid Terraform manifests. Refusing to deploy.")
            return {
                "status": "FAILED",
                "error": f"Workload '{product_id}' has no infrastructure definition (neither 'main.tf' nor 'infra/workload/main.tf' found in repository).",
                "product_id": product_id,
                # DEPLOY-FAILURE-OWNER-ROUTER: no engine ran
                dfr.FAILURE_ROUTE_FIELD: dfr.route(dfr.UNKNOWN, dfr.PHASE_PREPARE, dfr.BASIS_NO_ENGINE_RESULT),
            }

        # AQ-1 (register AQ-1): the install's Google sign-in client id and secret (castor-oauth-client-id / -secret)
        # are never read during a deploy, and no workload's OpenTofu gets a sign-in secret. TF_VAR_oauth_client_secret
        # stays registered with an EXPLICIT empty value, so a legacy root that declares the variable without a default
        # still plans; oauth_client_id is "" until the platform configures shared sign-in itself (row 27b, W6).
        oauth_client_id = ""
        oauth_client_secret = ""

        # AQ-2 (register AQ-2, rows 42/46): only a PUBLIC_APP workload gets a web sign-in key, Identity Platform
        # initialization and authorized domains. Private modes and a missing / unreadable access record get none of
        # them; the values reach Terraform as "".
        tenant_signin = access_mode == TENANT_SIGNIN_ACCESS_MODE
        firebase_api_key = ""
        firebase_auth_domain = f"{target_project_id}.firebaseapp.com" if tenant_signin else ""
        target_p_num = ""
        if tenant_signin:
            firebase_api_key, target_p_num = self._resolve_workload_web_key(target_project_id, clean_pid)
            if not firebase_api_key and apply_ctx is not None:   # F3: typed warning in the deploy result
                apply_ctx.setdefault("warnings", []).append(self._signin_key_missing_warning(target_project_id))
        else:
            logger.info(f"{TENANT_SIGNIN_ARTIFACTS_SKIPPED}: workload '{product_id}' access mode "
                        f"{access_mode or access_state}; no web sign-in key, no Identity Platform setup")

        # FD-4BD: the secrets go to tofu as TF_VAR_* environment variables of this workspace only (never a file).
        secret_tf_vars = {"oauth_client_secret": oauth_client_secret, "firebase_api_key": firebase_api_key}
        # FD-4BV: platform values merged INTO the workload's own tfvars by parsed key (the flattened
        # infra/workload/terraform.tfvars keeps e.g. the IPAM subnet_cidr fact); platform keys win only for these
        # platform-owned facts. Values are written exactly as before (a plain quoted string).
        platform_tfvars = {
            "project_id": f'"{target_project_id}"',
            "region": f'"{workload_region}"',
            "product_id": f'"{clean_pid}"',
            "github_repo_full_name": f'"{full_repo_name}"',
            "container_image": f'"{image_tag}"',
            "oauth_client_id": f'"{oauth_client_id}"',
            "firebase_auth_domain": f'"{firebase_auth_domain}"',
        }
        # FD-4AT-c: the vend-time GitHub repository id, only when its record names this exact repository (digits
        # only, validated by the shared reader and again by the module). No record -> the key is omitted and the
        # root's empty default keeps the WIF condition at repository name + main branch.
        pinned_repo_id = pinned_github_repository_id(repo_identity_record, full_repo_name)
        if pinned_repo_id:
            platform_tfvars["github_repository_id"] = f'"{pinned_repo_id}"'
        # FD-4CI-b-R1-WIF: the recorded default branch (a plain branch name other than main) for the WIF condition;
        # otherwise no key (the root's default; tfvars byte-identical for main).
        wif_branch = recorded_wif_branch(recorded_default_branch)
        if wif_branch:
            platform_tfvars["github_default_branch"] = f'"{wif_branch}"'
        # GHA-DEPLOY-SWITCH (OQ-37: deploy time): the record's switch for a root that declares it; on + no
        # declaration = no key (byte-identical); off + no declaration / invalid = typed stop, nothing built.
        gha_value, gha_stop = gha_deploy_tfvar(recorded_gha_deploy, recorded_vcs, files)
        if gha_stop is not None:
            gha_code, gha_detail = gha_stop
            if gha_code == GHA_DEPLOY_SWITCH_INVALID:
                gha_error = f"{gha_code}: {gha_detail}. Nothing was built, planned or applied."
                logger.error(gha_error)
                return {"status": "FAILED", "error_class": GHA_DEPLOY_SWITCH_INVALID, "code": gha_code,
                        "error": gha_error, "operator_required": True, "product_id": product_id,
                        "trace_id": trace_id}
            # RT SAT-16/34 F1 (owner): an administrator's toggle never buys an automatic developer (LLM) run: the
            # stop waits for an operator, who runs the workload's pipeline to regenerate the IaC.
            return dict(self._unparseable_iac_result(gha_code, gha_detail, product_id, trace_id),
                        operator_required=True)
        if gha_value is not None:
            platform_tfvars[GHA_DEPLOY_SWITCH_TFVAR] = gha_value
        tfvars_keys =[k for k in ("infra/workload/terraform.tfvars", "terraform.tfvars") if k in files]
        merged_root_tfvars = merge_tfvars_texts([files[k] for k in tfvars_keys], platform_tfvars)
        if merged_root_tfvars is None:
            # FD55-TFVARS: no platform-values-only fallback (it silently dropped the workload's own values).
            bad = [k for k in tfvars_keys if parse_tfvars_attributes(files[k]) is None]
            return self._unparseable_iac_result(
                APPLY_TFVARS_UNPARSEABLE, "; ".join(
                    f"{k} is not parseable by python-hcl2 as a variable-values file ({_hcl2_parse_error(files[k])})"
                    for k in bad), product_id, trace_id)
        files["terraform.tfvars"] = merged_root_tfvars

        try:
            self._stage_runner_ctx(trace_id, product_id, state_ctx)   # FD-7L Phase 2b: this run's backend
            workspace_dir = self.prepare_workspace(product_id, trace_id, files, iac_engine=active_engine,
                                                   region=workload_region,
                                                   **({"binary_files": binary_files} if binary_files else {}))
        except WorkflowValidationError as wf_err:   # FD55-W6c: typed APPLY.WORKFLOW_INVALID, never unhandled
            return self._workflow_invalid_result(wf_err, product_id, trace_id)
        except EngineUnverifiable as unverified:   # RT14-22: nothing is planned or applied with an unverified engine
            logger.error(str(unverified))
            return {"status": "FAILED", "error_class": ENGINE_UNVERIFIABLE, "stage": ENGINE_STAGE,
                    "error": f"{unverified}. Nothing was built, planned or applied.", "product_id": product_id,
                    "trace_id": trace_id}
        finally:
            self._take_staged_runner_ctx(trace_id, product_id)
        self._register_runner_ctx(workspace_dir, state_ctx)
        if apply_ctx is not None:
            apply_ctx["workspace_dir"] = workspace_dir
        # SAT-01 (FD4BD-Q1 deploy half): every other variables file OpenTofu would load by itself from the workspace
        # root is checked before anything is built, planned or applied (typed stop; nothing rewritten or removed).
        auto_tfvars_stop = self._auto_tfvars_stop(workspace_dir, files, hcl_files, platform_tfvars, active_engine,
                                                  product_id, trace_id)
        if auto_tfvars_stop is not None:
            return auto_tfvars_stop
        registration = self._register_workspace_tf_vars(workspace_dir, secret_tf_vars)
        # DEPLOY-ROOT-VARS: the exact input values the platform supplies, checked on every gated plan. container_image
        # is the runtime value (set below, after the build); the access file only when this deploy rendered one.
        root_vars_access_text = (hcl_files or {}).get(PLATFORM_ACCESS_VARS_MANIFEST_KEY)
        if tf_var_registrations is not None:
            tf_var_registrations.append(registration)
        # FD4BD-Q3: this workspace's tofu processes bill the child (their own env only); forgotten with the deploy.
        billing_registration = self._register_workspace_billing(workspace_dir, target_project_id)
        if billing_registrations is not None:
            billing_registrations.append(billing_registration)

        # FD55-W6b (register FD55-W6b+W6d, A31 DELETED): the deploy never commits to the workload repository. The
        # "Autonomous GitOps Writeback (Option B)" that committed prepare_workspace's healed files to the deploy
        # branch ("chore(castor): autonomous AST syntax curing ...", bypassing review and QA) is gone with the heals
        # that fed it; the repository always equals what was reviewed. FD55-W6d (HS-42): a vendored golden module
        # that differs from the platform payload is applied as committed and the workload is marked "IaC outdated";
        # the fix is the Upgrade IaC pull request (blocked while the workload is under Code Freeze).
        self._report_iac_outdated(product_id, trace_id, stale_vendored_module_files(workspace_dir))

        # Check if this workload contains compute services that require container compilation
        has_apps = False
        apps_dir = os.path.join(workspace_dir, "apps")
        if os.path.exists(apps_dir):
            for item in os.listdir(apps_dir):
                sub_path = os.path.join(apps_dir, item)
                if os.path.isdir(sub_path):
                    if any(os.path.exists(os.path.join(sub_path, f)) for f in ("main.py", "app.py", "Procfile", "requirements.txt", "package.json")):
                        has_apps = True
                        break

        has_root_app = any(os.path.exists(os.path.join(workspace_dir, f)) for f in ("main.py", "app.py", "Procfile", "requirements.txt"))

        # FD-4AE RT F1 / F1b: with the typed topology, a container build is needed only when some service is a
        # container kind (VM kinds gce-bastion / gce-worker are never built); without one, parsed HCL (not comments).
        service_kinds = workspace_service_kinds(workspace_dir)
        if service_kinds is not None:
            has_compute_module = any(k not in NON_CONTAINER_KINDS for k in service_kinds.values())
        else:
            has_compute_module = workspace_declares_compute(workspace_dir)

        needs_container_build = (has_apps or has_root_app) and has_compute_module

        # 1. Build and Push Container Image via Google Cloud Buildpacks (if compute services are declared)
        if needs_container_build:
            image_built = self._build_and_push_container(product_id, target_project_id, workspace_dir, image_tag, ar_repo_name=ar_repo_name,
                                                         region=workload_region)
            if not image_built:
                logger.error(f"Container image compilation failed for '{product_id}' in '{target_project_id}'. Halting deployment.")
                if self._last_build_error_class == BUILD_CONTRACT_ERROR_CLASS:
                    # FD-4AE RT F3: an app-contract failure is not an IaC defect. A non-empty error_class keeps the
                    # workflow out of increment_tf_retry (Terraform remediation); the code leads the error so the
                    # 120-char tf-applier summary keeps it.
                    return {
                        "status": "FAILED",
                        "error_class": BUILD_CONTRACT_ERROR_CLASS,
                        "error": f"{self._last_build_error} (workload '{product_id}')",
                        "product_id": product_id,
                    }
                return {
                    "status": "FAILED",
                    "error": (
                        f"Cloud Buildpack compilation failed for workload '{product_id}': "
                        f"{getattr(self, '_last_build_error', None) or f'see Cloud Build logs in target project {target_project_id!r}.'}"
                    ),
                    "product_id": product_id,
                    # DEPLOY-FAILURE-OWNER-ROUTER: a container build gives no typed owner
                    dfr.FAILURE_ROUTE_FIELD: dfr.route(dfr.UNKNOWN, dfr.PHASE_BUILD, dfr.BASIS_NO_ENGINE_RESULT),
                }
            deployed_image = image_tag
        else:
            logger.info(f"Workload '{product_id}' has no compute services declared. Skipping Google Cloud Buildpack container build.")
            image_built = False
            deployed_image = ""

        # Non-destructive terraform.tfvars merge preserving Developer Agent security configs (Direct IAP, allowed invokers, etc.)
        tfvars_path = os.path.join(workspace_dir, "terraform.tfvars")
        # FD-4BD: no secret keys here (they reach tofu as TF_VAR_* of this workspace).
        runtime_tfvars = dict(platform_tfvars, container_image=f'"{deployed_image}"')
        expected_root_vars = platform_root_variable_values(runtime_tfvars, secret_tf_vars, root_vars_access_text)

        # Lane 11 RT F1: the developer's values live in infra/workload/terraform.tfvars (the root file was replaced by
        # the runtime template above), so seed the merge from it first, then the root file, then the runtime keys
        # (runtime wins). Without this, a variable with no default (the IPAM facts subnet_cidr / connector_cidr) has
        # no value at plan time, and defaulted ones (additional_apis, sizing, invoker settings) silently use defaults.
        # FD-4BV: merged by parsed key (python-hcl2; maps and lists keep their exact text). FD-4BD: secret keys dropped.
        tfvars_texts = []
        for src_p in (os.path.join(workspace_dir, "infra", "workload", "terraform.tfvars"), tfvars_path):
            if os.path.exists(src_p):
                with open(src_p, "r", encoding="utf-8", newline="") as f:   # F1: exact bytes (CRLF kept)
                    tfvars_texts.append(f.read())
        merged_text = merge_tfvars_texts(tfvars_texts, runtime_tfvars)
        if merged_text is None:
            # FD55-TFVARS (A37): not parseable by python-hcl2 -> typed stop before plan (no line-pattern merge).
            return self._unparseable_iac_result(
                APPLY_TFVARS_UNPARSEABLE, "the workspace terraform.tfvars is not parseable by python-hcl2 as a "
                "variable-values file", product_id, trace_id, built=bool(deployed_image))
        with open(tfvars_path, "w", encoding="utf-8") as f:
            f.write(merged_text)

        # FD-55-IMG (A38/A39 DELETED): no container_image / image literal is rewritten here. The substring regex
        # over os.listdir(apps) gave `api-worker` the `api` image (order-dependent) and edited platform renders
        # (services.tf, typed-intent workspaces). Each service's image is bound by the render through
        # var.container_image (terraform.tfvars, .../app:latest) and the build tags app:latest onto the service a
        # module takes var.container_image for directly (primary_build_service).
        # FD55-W3 (A54 DELETED): main.tf is never read or written here. The OAuth client id, the Firebase browser key
        # and the auth domain (non-secret) reach Terraform only as variables (terraform.tfvars oauth_client_id /
        # firebase_auth_domain, TF_VAR_firebase_api_key); they are never pasted into main.tf as literals.

        # Ensure variables.tf declares firebase_api_key and firebase_auth_domain (legacy roots only: the variables
        # above need a declaration to reach a hand-written main.tf; platform renders declare both).
        vars_tf_path = os.path.join(workspace_dir, "variables.tf")
        if os.path.exists(vars_tf_path) and not intent_ws:   # TI-5a: the platform's variables.tf is applied as rendered
            with open(vars_tf_path, "r") as f:
                vars_hcl = f.read()
            vars_to_append = []
            if "firebase_api_key" not in vars_hcl:
                vars_to_append.append('variable "firebase_api_key" {\n  description = "Firebase Browser API Key"\n  type        = string\n  default     = ""\n}')
            if "firebase_auth_domain" not in vars_hcl:
                vars_to_append.append('variable "firebase_auth_domain" {\n  description = "Firebase Auth Domain"\n  type        = string\n  default     = ""\n}')
            if vars_to_append:
                with open(vars_tf_path, "a") as f:
                    f.write("\n" + "\n".join(vars_to_append) + "\n")

        # Ensure Identity Platform is initialized for target child project (AQ-2: PUBLIC_APP workloads only)
        if tenant_signin:
            try:
                from google.auth.transport.requests import AuthorizedSession
                creds = self._child_credentials(target_project_id, scoped=False)   # FD4BD-Q3
                sess = AuthorizedSession(creds)
                sess.post(
                    f"https://identitytoolkit.googleapis.com/v2/projects/{target_project_id}/identityPlatform:initializeAuth",
                    headers={"X-Goog-User-Project": target_project_id}
                )
                logger.info(f"Ensured Identity Platform is initialized for '{target_project_id}'")
            except Exception as idp_init_err:
                logger.debug(f"Identity Platform proactive init notice: {idp_init_err}")

        # Dynamic Google Cloud API Auto-Enablement Gate (Red Team Hardened)
        # Recursively inspects workspace files (pruning non-source dirs), extracts required GCP APIs
        # from resources, golden modules, and manifests, and enables them in target_project_id.
        try:
            IGNORED_SCAN_DIRS = {".git", ".terraform", ".venv", "__pycache__", "node_modules", "dist", "build"}
            tf_file_map = {}
            yaml_file_map = {}

            if os.path.exists(workspace_dir):
                # FD23-12a: `walk_files`, not `files` (rebinding `files` shadowed the repo-file dict used later in deploy_workload).
                for root, dirs, walk_files in os.walk(workspace_dir):
                    dirs[:] = [d for d in dirs if d not in IGNORED_SCAN_DIRS]
                    for f in walk_files:
                        f_lower = f.lower()
                        rel_path = os.path.relpath(os.path.join(root, f), workspace_dir)
                        if f_lower.endswith((".tf", ".tf.json")):
                            try:
                                with open(os.path.join(root, f), "r", encoding="utf-8", errors="ignore") as tf_in:
                                    tf_file_map[rel_path] = tf_in.read()
                            except Exception:
                                pass
                        elif f_lower.endswith((".yaml", ".yml")):
                            try:
                                with open(os.path.join(root, f), "r", encoding="utf-8", errors="ignore") as yml_in:
                                    yaml_file_map[rel_path] = yml_in.read()
                            except Exception:
                                pass

            needed_apis = extract_apis_from_hcl(tf_file_map, yaml_file_map)
            if needed_apis and target_project_id:
                from google.auth.transport.requests import AuthorizedSession
                creds = self._child_credentials(target_project_id)   # FD4BD-Q3
                su_sess = AuthorizedSession(creds)
                logger.info(f"Dynamically ensuring {len(needed_apis)} required Google Cloud APIs on '{target_project_id}': {needed_apis}")
                
                # Red Team Hardening: Chunk in batches of <= 15
                chunk_size = 15
                newly_enabled = False
                for i in range(0, len(needed_apis), chunk_size):
                    batch = needed_apis[i:i + chunk_size]
                    resp = su_sess.post(
                        f"https://serviceusage.googleapis.com/v1/projects/{target_project_id}/services:batchEnable",
                        headers={"X-Goog-User-Project": target_project_id},
                        json={"serviceIds": batch}
                    )
                    if resp.status_code in (200, 201):
                        op_data = resp.json()
                        op_name = op_data.get("name")
                        if op_name:
                            import time
                            poll_start = time.time()
                            while time.time() - poll_start < 45.0:
                                op_check = su_sess.get(f"https://serviceusage.googleapis.com/v1/{op_name}")
                                if op_check.status_code == 200 and op_check.json().get("done"):
                                    logger.info(f"Dynamic API enablement completed on '{target_project_id}' for batch: {batch}")
                                    newly_enabled = True
                                    break
                                time.sleep(2.0)
                    else:
                        logger.warning(f"Batch API enablement on '{target_project_id}' returned {resp.status_code}: {resp.text[:200]}")
                
                # Red Team Hardening: 5s stabilization buffer if APIs were enabled
                if newly_enabled:
                    logger.info(f"Allowing 5s IAM & Service Usage stabilization buffer on '{target_project_id}'...")
                    import time
                    time.sleep(5.0)
        except Exception as api_enable_err:
            logger.warning(f"Dynamic API auto-enablement notice: {api_enable_err}")

        # FD55-W6a (A41 DELETED): the second naming-invariant pass over every root .tf is gone; names are applied
        # exactly as committed (a name GCP rejects is a validate / apply error that reaches the developer).
        # FD55-W6c (A42 DELETED, register FD55-W6c): the Layer 3 pre-apply variable reconciler is gone. It wrote a
        # value guessed from the variable's name (HD-14) into terraform.tfvars for every referenced variable with no
        # default and no value. terraform.tfvars now holds only the workload's committed values plus the platform
        # and runtime keys; a variable left without a value is OpenTofu's own error, which reaches the developer.

        # FD55-W6e (A43, Layer 3b DELETED, register FD55-W6e): a GKE / GCE primary workspace without topology.json no
        # longer gets a synthetic `module "compute_<dir>"` (compute-cloudrun, copied in when missing) appended to
        # custom.tf and a `service_url` output for each apps/<dir> its .tf text did not name. The service set is the
        # committed IaC (typed-topology workspaces already skipped it, lane 10 RT F3).

        # FD-7L Phase 2b (plan 2.5, OQ-32): the pre-init policy on everything OpenTofu will load (committed and
        # platform-written files alike), before the first `init`. PER_WORKLOAD refuses; PLATFORM only logs.
        preinit_stop = self._preinit_policy_stop(workspace_dir, state_ctx, product_id, trace_id)
        if preinit_stop is not None:
            self._sync_feature_requests(product_id=product_id, trace_id=trace_id, is_successful_deploy=False,
                                        error_msg=preinit_stop["error"])
            return preinit_stop

        # 2. Terraform Init with exponential backoff retry for registry rate limits
        import time
        init_res = None
        for attempt in range(1, 7):
            init_res = self._run_subprocess(["terraform", "init", "-upgrade", "-input=false", "-no-color"], cwd=workspace_dir, iac_engine=active_engine)
            # FD-4AQ W1b: a typed refusal is not retried; FD-4AQ W3 F4: a timed-out init is not retried
            if init_res["success"] or init_res.get("error_class") or init_res.get("timed_out"):
                break
            if attempt < 6:
                wait_sec = attempt * 5
                logger.warning(f"IaC init attempt {attempt}/6 failed ({init_res['stderr'][:200] if init_res else 'unknown'}). Retrying in {wait_sec}s...")
                time.sleep(wait_sec)

        if not init_res or not init_res["success"]:
            init_err = init_res["stderr"] if init_res else "unknown error"
            logger.error(f"IaC init failed in {workspace_dir}: {init_err}")
            failed = {
                "status": "FAILED",
                "error": f"IaC init failed: {init_err}",
                "stdout": init_res["stdout"] if init_res else "",
            }
            if init_res and init_res.get("error_class"):   # FD-4AQ W1b: PROVIDER_NOT_ALLOWED (no AI remediation)
                failed.update(error_class=init_res["error_class"],
                              providers_not_allowed=init_res.get("providers_not_allowed") or [])
            else:   # DEPLOY-FAILURE-OWNER-ROUTER: `init` gives no typed diagnostics
                failed[dfr.FAILURE_ROUTE_FIELD] = dfr.route(dfr.UNKNOWN, dfr.PHASE_INIT, dfr.BASIS_NO_ENGINE_RESULT)
            return failed

        # 2a. Shift-Left IaC Validation Pre-Check
        logger.info(f"Running Shift-Left IaC validation pre-check in {workspace_dir}...")
        validate_res = self._run_subprocess(["terraform", "validate", "-no-color"], cwd=workspace_dir, iac_engine=active_engine)
        if not validate_res["success"] and intent_ws:
            # TI-5a (register TI-5a): an intent workspace's validate failure is never patched here (FD55-W6c deleted the
            # legacy HC-10 / HC-18 / output-purge patches too). The engine's own diagnostics return typed
            # (`validate -json`; exact ranges, owners by exact path) for the repair loop, plus the text as before.
            val_err = validate_res.get("stderr") or validate_res.get("stdout") or "IaC validation failed"
            vjson = self._run_subprocess(["terraform", "validate", "-json", "-no-color"], cwd=workspace_dir,
                                         iac_engine=active_engine)
            report = apply_validation_report((vjson or {}).get("stdout") or "", workspace_dir, fallback_error=val_err,
                                             manifest_paths=files.keys())
            logger.error(f"Shift-Left IaC validation pre-check failed for intent workload '{product_id}' "
                         f"(no apply-time healing on the typed-intent path):\n{val_err}")
            return {
                "status": "VALIDATION_FAILED",
                "error": f"Shift-Left IaC validation failed:\n{val_err}",
                "stdout": validate_res.get("stdout", ""),
                "stderr": validate_res.get("stderr", ""),
                "validation_report": report,
                # DEPLOY-FAILURE-OWNER-ROUTER: the same typed report decides the owner
                dfr.FAILURE_ROUTE_FIELD: self._route_validate_failure((vjson or {}).get("stdout"), workspace_dir,
                                                                      files, True, report),
            }
        if not validate_res["success"]:
            # FD55-W6c (A44 / A45 / A46 DELETED, register FD55-W6c): a legacy workspace's validate failure is no
            # longer patched here either. The HC-18 locals curing, the HC-10 rewrite of undeclared
            # `google_cloud_run_v2_service.<x>` references to `module.compute*` (custom.tf or main.tf) and the HC-08
            # purge of every custom.tf output on an output error are gone: no file is written and validate runs once.
            # The engine's text returns as VALIDATION_FAILED, the workflow's existing bounded regeneration
            # (tf_retry_count); typed repair of legacy validate errors would be its own row.
            # S2-F (proposed with the HB-13 deletion): HC-11 (foundation remap + secret/topic/bucket synthesis on
            # "Reference to undeclared resource") and HA-11 (prune the failing custom.tf block) are deleted. Since HS-68
            # (FD23-12b) both were report-only regex analyses of the error text: they wrote nothing, never re-validated,
            # and their `heal_findings` had no consumer. The deploy returns the engine's original error, exactly as before;
            # S2-F F1 types it from `validate -json` (no error-string parsing).
            val_err = validate_res.get("stderr") or validate_res.get("stdout") or "IaC validation failed"
            logger.error(f"Shift-Left IaC validation pre-check failed for '{product_id}':\n{val_err}")
            # DEPLOY-FAILURE-OWNER-ROUTER: the owner comes from `validate -json` (read-only, no API call); the
            # returned text is unchanged
            slot = self._tofu_timeout_slot()
            prior_timeout = getattr(slot, "message", None)
            vjson = self._run_subprocess(["terraform", "validate", "-json", "-no-color"], cwd=workspace_dir,
                                         iac_engine=active_engine)
            if (vjson or {}).get("timed_out") and prior_timeout is None:
                slot.message = None   # the advisory run's own timeout is not the deploy's: the route is UNKNOWN
            return {
                "status": "VALIDATION_FAILED",
                "error": f"Shift-Left IaC validation failed:\n{val_err}",
                "stdout": validate_res.get("stdout", ""),
                "stderr": validate_res.get("stderr", ""),
                dfr.FAILURE_ROUTE_FIELD: self._route_validate_failure((vjson or {}).get("stdout"), workspace_dir,
                                                                      files, False),
            }
        logger.info(f"Shift-Left IaC validation pre-check passed for '{product_id}'.")

        # 2a-1.5. RT14-01 (FD-4Q / lane 18 S3): the Pass 0.5 stub purge is DELETED. It ran on every deploy (Express
        # too), REST-deleted every ERROR GKE cluster of the project in any region and ran a hardcoded `state rm`; no
        # plan, destroy or approval gate saw it. Dead stubs are detected read-only (detect_errored_child_stubs) by
        # the tf-applier when an apply fails on capacity, and cleaned up by an operator (docs/runbooks/stub-cleanup.md).

        # 2a-2. Proactive Brownfield Discovery (Pass 0)
        # FD-4CY W7 (proposed row FD55-W7): the pre-imports of Cloud Run services, Secret Manager secrets, service
        # accounts and same-name subnetworks (case A) no longer come from a regex scan of the .tf text with guessed
        # names (the product id for a variable-built Cloud Run name, `order-signing-secret` for a secret, root
        # addresses for blocks inside modules). They run inside the gated apply on its own plan (`_pass0_adopt`,
        # brownfield_adoption.pre_apply_candidates): a planned create whose exact planned name already exists in the
        # workload project (REST GET 200) is imported at the plan's address, then the gate plans again.
        # The VPC Access connector text scan (3b) is DELETED (owner OQ-9a, 10-31): it walked vendored modules, turned a
        # `var.*` name into `castor-vpc-conn` and imported at a root address even for a block inside a module. An
        # existing connector is adopted from its typed 409 at its plan address (2b). `terraform state list` no longer
        # runs here: nothing reads it any more.
        # RT14-01 (FD-4Q / OQ-9b): the subnet CIDR orphan purge (case B) and its trigger are DELETED (see below).
        reserved_identity = self._policy_identity(state_ctx)

        def _import_reserved(cand: Any) -> Optional[str]:
            """FD-7L Phase 2b (plan 2.5): the self-healing imports never adopt the platform's deployer account, a
            state bucket or the build staging bucket (exact import ids). PER_WORKLOAD: the reason (the import is
            skipped); PLATFORM: a POLICY_WOULD_REFUSE line and None (imports as before)."""
            why = reserved_import_reason(cand.type, cand.import_id, reserved_identity)
            if why is None:
                return None
            if not state_ctx.per_workload:
                self._log_would_refuse(product_id, trace_id, "self_heal_import", [{
                    "code": POLICY_PLATFORM_IDENTITY_TOUCHED, "address": cand.address,
                    "detail": f"import of {cand.import_id} ({why})"}])
                return None
            logger.error(f"{POLICY_PLATFORM_IDENTITY_TOUCHED}: '{cand.import_id}' at {cand.address} is {why}; it is "
                         "never imported by the platform")
            return why

        def _pass0_adopt(plan_json: Dict[str, Any]) -> int:
            candidates = brownfield_adoption.pre_apply_candidates(plan_json, target_project_id, workload_region)
            if not candidates:
                return 0
            try:
                from google.auth.transport.requests import AuthorizedSession
                credentials = self._child_credentials(target_project_id)   # FD4BD-Q3
                adopt_session = AuthorizedSession(credentials)
            except Exception as sess_err:
                logger.warning(f"Pass 0 adoption skipped for '{product_id}' (no Google session): {sess_err}")
                return 0
            imported = 0
            for cand in candidates:
                if _import_reserved(cand):   # FD-7L Phase 2b: never the deployer / state / build bucket
                    continue
                try:
                    if adopt_session.get(cand.exists_url, timeout=10.0).status_code != 200:
                        continue
                except Exception as chk_err:
                    logger.debug(f"Pass 0 existence check notice for {cand.address}: {chk_err}")
                    continue
                logger.info(f"🔍 Proactive brownfield discovery: '{cand.import_id}' already exists in GCP. "
                            f"Pre-importing into state at {cand.address} (planned create)...")
                imp_res = self._run_subprocess(["terraform", "import", "-input=false", cand.address, cand.import_id],
                                               cwd=workspace_dir, iac_engine=active_engine)
                if imp_res.get("success"):
                    imported += 1
                else:
                    logger.warning(f"Pass 0 import of '{cand.import_id}' at {cand.address} failed; the apply decides: "
                                   f"{(imp_res.get('stderr') or imp_res.get('stdout') or '')[:300]}")
            return imported

        # RT14-01 (FD-4Q / OQ-9b, lane 18 S3): the subnet "case B" orphan purge is DELETED. It REST-deleted any
        # subnetwork of the region whose CIDR equalled a declared one when its name or network contained `castor` or
        # the product id (substring guessing, outside every plan / destroy gate). A CIDR conflict now fails the apply
        # with the provider's error and the typed SUBNET_CIDR_CONFLICT (below); an operator decides.

        # 2b. Terraform Apply
        applied_plan: Dict[str, Any] = {}   # FD-4CY W7: the plan each gated apply applied (409 adoption reads it)
        # CLOUDSQL-CREATE-OWN-OPERATION: a Cloud SQL create operation inserted from here on is this deploy's own
        apply_started_epoch = time.time()
        apply_res = self._compliance_gated_apply(product_id, trace_id, workspace_dir, active_engine,
                                                 destroy_policy=destroy_policy, plan_sink=applied_plan,
                                                 pre_apply_adopt=_pass0_adopt,
                                                 expected_root_vars=expected_root_vars)

        # FD-4H: a held state lock is never broken automatically (the old always-true "stale" condition
        # force-unlocked fresh locks held by live applies). Fail closed before any healer runs without the lock.
        if not apply_res["success"]:
            lock_info = self.parse_state_lock_info(apply_res.get("stderr", ""), max_age_minutes=self.stale_lock_max_age_min)
            if lock_info:
                locked = self._state_locked_result(
                    product_id,
                    lock_info,
                    # PR-0 tip RT N2: a lock hit during the gated helper's plan is labelled "plan", not "apply".
                    phase="plan" if apply_res.get("compliance_gate_phase") == "plan" else "apply",
                    stdout=apply_res.get("stdout", ""),
                    stderr=apply_res.get("stderr", ""),
                )
                self._sync_feature_requests(
                    product_id=product_id,
                    trace_id=trace_id,
                    is_successful_deploy=False,
                    error_msg=locked["error"],
                )
                return locked

        is_successful_deploy = apply_res["success"]
        service_url = ""

        if not is_successful_deploy:
            apply_err = apply_res.get("stderr") or apply_res.get("stdout") or "Terraform apply failed"
            clean_pid = product_id.lower().replace("_", "-")

            # Auto-import self-healing: If resources already exist in GCP, import them into state and retry
            # Allow up to 8 passes to reconcile complex multi-resource brownfield topologies
            # FD-4B: ledger of state addresses successfully imported during this reconcile loop.
            # The Universal 409 engine must never re-import an address a typed handler already
            # adopted (a second import fails with "Resource already managed", which is success).
            imported_addrs: set = set()

            def _tf_import(addr: str, res_id: str) -> dict:
                res = self._run_subprocess(["terraform", "import", "-input=false", addr, res_id], cwd=workspace_dir, iac_engine=active_engine)
                if res.get("success"):
                    imported_addrs.add(addr)
                return res

            def _bucket_in_workload_project(bucket_name: str) -> bool:
                """FD-4CY W7: the existing bucket's typed `projectNumber` equals the workload project's (REST GETs)."""
                try:
                    from google.auth.transport.requests import AuthorizedSession
                    creds = self._child_credentials(target_project_id)   # FD4BD-Q3
                    sess = AuthorizedSession(creds)
                    b_res = sess.get(f"https://storage.googleapis.com/storage/v1/b/{bucket_name}",
                                     params={"fields": "projectNumber"}, timeout=10.0)
                    p_res = sess.get(f"https://cloudresourcemanager.googleapis.com/v1/projects/{target_project_id}",
                                     timeout=10.0)
                    return (b_res.status_code == 200 and p_res.status_code == 200
                            and brownfield_adoption.bucket_owner_matches(b_res.json(), p_res.json()))
                except Exception as own_err:
                    logger.warning(f"Bucket owner check for '{bucket_name}' failed: {own_err}")
                    return False

            # FD-4CY W7: the conflicts of the latest analysed apply error that could not be adopted (typed below)
            adoption_unresolved: List[Dict[str, str]] = []
            adoption_unresolved_for = None

            for _ in range(8):
                if not (
                    "already exists" in apply_err
                    or "Error 409" in apply_err
                    or "timeout while waiting for state to become 'done: true'" in apply_err
                    or "timeout while waiting for Creating Service" in apply_err
                    or "Invalid IPCidrRange" in apply_err
                ):
                    break

                retried = False
                if "timeout while waiting for state to become 'done: true'" in apply_err or "timeout while waiting for Creating Service" in apply_err:
                    logger.info("Cloud Run creation timeout detected; retrying apply to reconcile completed service readiness...")
                    retried = True
                # FD55-W6c (A47 / A48 DELETED, register FD55-W6c): the self-referential block rewrite (HB-18 copy,
                # every .tf in the walk) and the HC-18 locals curing on an apply error are gone, with their two
                # loop triggers. Such an error ends the loop and returns as FAILED with the engine's text (the
                # workflow's existing bounded regeneration). The 409 adoption / import / retry branches are unchanged.
                # FD-4H: no healer for "cannot destroy ... deletion_protection". It used to `state rm` a live
                # service (orphaning it) or regex-inject `deletion_protection = false`. A destroy of a protected
                # resource now fails with the provider's own error; destroys go through a plan-based HITL gate.

                # FD-4CY W7 (proposed row FD55-W7; A50 / A51 CONVERT): ONE typed adoption replaces the per-type handlers
                # (Artifact Registry, Firestore, service accounts, Workload Identity pool / provider, Identity Platform,
                # Pub/Sub, buckets, secrets, Scheduler, Cloud Run, serverless NEG, forwarding rule) and the "Universal
                # 409" engine. They read names and addresses out of the error text and the .tf text with regexes and fell
                # back to guesses (`order-signing-secret`, `daily-reconciliation-job`, `castor-gh-pool`,
                # `castor-vpc-conn`, the product id, `module.foundation.*` / `module.compute.*` by substring). Now the
                # address is the diagnostic's own `with <address>,` line and must be a create of the plan this apply
                # applied; the import id comes from that create's planned attributes (brownfield_adoption). A conflict
                # that cannot be adopted that way is recorded and the deploy fails typed (APPLY_ADOPTION_UNRESOLVED);
                # nothing is guessed. The log line below is the marker the after-action report harvests.
                adoptable, adoption_unresolved = brownfield_adoption.plan_conflicts(
                    apply_err, applied_plan.get("plan_json"), target_project_id, workload_region)
                adoption_unresolved_for = apply_err
                if adoptable or adoption_unresolved:
                    logger.info("Universal 409 Resource Adoption Engine intercepted existing GCP entity in OpenTofu diagnostics...")
                for cand in adoptable:
                    if cand.address in imported_addrs:
                        # FD-4B: adopted earlier in this loop; a second import would only be "Resource already managed"
                        logger.info(f"Universal 409 Engine: '{cand.address}' already imported this reconcile loop; skipping.")
                        continue
                    reserved_why = _import_reserved(cand)   # FD-7L Phase 2b (PER_WORKLOAD): never imported
                    if reserved_why:
                        adoption_unresolved.append({"address": cand.address, "reason": (
                            f"'{cand.import_id}' is {reserved_why} ({POLICY_PLATFORM_IDENTITY_TOUCHED}); the platform "
                            "never imports it")})
                        continue
                    if cand.type in brownfield_adoption.WIF_UNDELETE_TYPES:
                        # A52 (kept): a soft-deleted pool / provider keeps its id for 30 days and answers 409; undelete
                        # the exact planned id before the import (was: a fixed `castor-gh-pool` id).
                        try:
                            from google.auth.transport.requests import AuthorizedSession
                            creds = self._child_credentials(target_project_id, scoped=False)   # FD4BD-Q3
                            sess = AuthorizedSession(creds)
                            undel_res = sess.post(
                                f"https://iam.googleapis.com/v1/{cand.import_id}:undelete",
                                headers={"X-Goog-User-Project": target_project_id}
                            )
                            if undel_res.status_code == 200:
                                logger.info(f"🛡️ Self-healed soft-deleted Workload Identity resource '{cand.import_id}' via undelete API!")
                        except Exception as undel_err:
                            logger.debug(f"WIF undelete attempt notice: {undel_err}")
                    if cand.type in brownfield_adoption.OWNER_CHECK_TYPES and not _bucket_in_workload_project(cand.import_id):
                        adoption_unresolved.append({"address": cand.address, "reason": (
                            f"bucket '{cand.import_id}' is not a bucket of the workload project (or its owner could "
                            "not be read); a bucket name is global, so it is never adopted on the name alone")})
                        continue
                    if cand.type == cloudsql_create_recovery.INSTANCE_TYPE:
                        # CLOUDSQL-CREATE-OWN-OPERATION RT F1/F2: only a RUNNABLE instance without a `root`@`%` user,
                        # for a planned create that restores no backup (typed REST fields)
                        csql_why = self._cloudsql_adoption_refusal(target_project_id, cand,
                                                                   applied_plan.get("plan_json"))
                        if csql_why:
                            adoption_unresolved.append({"address": cand.address, "reason": (
                                f"Cloud SQL instance '{cand.import_id}': {csql_why}")})
                            continue
                    logger.info(f"Universal 409 Engine: adopted existing GCP resource '{cand.import_id}' at "
                                f"'{cand.address}' (planned create; importing into state)...")
                    imp_res = _tf_import(cand.address, cand.import_id)
                    if imp_res.get("success"):
                        retried = True
                    else:
                        # FD-4B: never prune HCL on an import failure; the failure is typed below.
                        adoption_unresolved.append({"address": cand.address, "reason": (
                            f"`import` of '{cand.import_id}' failed: "
                            f"{(imp_res.get('stderr') or imp_res.get('stdout') or 'no output').strip()[:300]}")})

                # RT14-01 (lane 18 S3): the subnet DELETE by a regex over the apply error text is DELETED (it ran on
                # every non-Express deploy). A CIDR conflict ends this loop and the deploy fails typed
                # (SUBNET_CIDR_CONFLICT, below); nothing outside the plan is deleted.

                # The invalid-CIDR rewriter (FD-44/H5, deleted by lane 8) is gone: an invalid CIDR now
                # fails the apply with the provider's error and goes to remediation instead of being rewritten.

                if not retried:
                    break

                logger.info("Retrying terraform apply after auto-importing pre-existing GCP resources...")
                apply_res = self._compliance_gated_apply(product_id, trace_id, workspace_dir, active_engine,
                                                         destroy_policy=destroy_policy, plan_sink=applied_plan,
                                                         expected_root_vars=expected_root_vars)
                is_successful_deploy = apply_res["success"]
                apply_err = apply_res.get("stderr") or apply_res.get("stdout") or ""
                if is_successful_deploy:
                    break

            # Identity Platform not initialized (CONFIGURATION_NOT_FOUND): call initializeAuth (REST, no file written)
            # and retry the apply once. FD55-W6c: no bypass of the sign-in block after that (see below).
            if not is_successful_deploy and ("DefaultSupportedIdpConfig" in apply_err or "CONFIGURATION_NOT_FOUND" in apply_err):
                try:
                    from google.auth.transport.requests import AuthorizedSession
                    creds = self._child_credentials(target_project_id, scoped=False)   # FD4BD-Q3
                    sess = AuthorizedSession(creds)
                    init_res = sess.post(
                        f"https://identitytoolkit.googleapis.com/v2/projects/{target_project_id}/identityPlatform:initializeAuth",
                        headers={"X-Goog-User-Project": target_project_id}
                    )
                    logger.info(f"Called initializeAuth for '{target_project_id}' (HTTP {init_res.status_code}), retrying terraform apply...")
                    apply_res = self._compliance_gated_apply(product_id, trace_id, workspace_dir, active_engine,
                                                             destroy_policy=destroy_policy, plan_sink=applied_plan,
                                                             expected_root_vars=expected_root_vars)
                    is_successful_deploy = apply_res["success"]
                    apply_err = apply_res.get("stderr") or apply_res.get("stdout") or ""
                except (compliance_gate.ComplianceGateRefused, DestroyBlocked):
                    # Lane 14 PR-0 RT F2: a gate refusal / blocked destroy stops the deployment with its typed
                    # result (it is never swallowed as an initializeAuth notice).
                    raise
                except Exception as idp_init_err:
                    logger.warning(f"IdP initializeAuth retry failed: {idp_init_err}")

                # FD55-W6c (A49 DELETED, register FD55-W6c): when the retry after initializeAuth still fails, the
                # `google_identity_platform_default_supported_idp_config` block is no longer regex-deleted from
                # main.tf and re-applied (any workspace): the error returns as FAILED with the engine's text.

            # FD-4DE: the startup-probe "Reconciliation Guard" is DELETED. It matched the apply's error text for a
            # startup-probe failure and then reported SUCCESS when the Cloud Run service had a Ready revision, although
            # the apply had stopped part-way (later resources not applied, the failed one tainted). A failed apply is
            # reported FAILED with the engine's text, like any other apply failure.

            # CLOUDSQL-CREATE-OWN-OPERATION (register row, awaiting owner): the provider stops waiting for a Cloud SQL
            # create on the first poll that carries an operation error, even a passing INTERNAL_ERROR on an operation
            # Cloud SQL then finishes, and drops the instance from state (ex08-g13). Read this deploy's own create
            # back from the SQL Admin API (typed fields, never the error text): adopt it and apply once more when it
            # finished cleanly, else fail typed. A failure with no such create is unchanged.
            cloudsql_unresolved: List[Dict[str, Any]] = []
            if not is_successful_deploy and apply_res.get("compliance_gate_phase") != "plan":
                csql_records, csql_retry = self._recover_own_cloudsql_creates(
                    product_id, workspace_dir, active_engine, target_project_id, workload_region,
                    applied_plan.get("plan_json"), apply_started_epoch)
                if csql_retry:
                    logger.warning("CLOUDSQL_CREATE_ADOPTED: retrying terraform apply after importing this deploy's "
                                   f"own Cloud SQL instance(s): {cloudsql_create_recovery.summary(csql_records)}")
                    if apply_ctx is not None:   # RT F5: before the retry, so a typed refusal of it carries it too
                        apply_ctx.setdefault("warnings", []).append({
                            "code": "CLOUDSQL_CREATE_ADOPTED",
                            "message": ("The provider stopped waiting for a Cloud SQL instance create that Cloud SQL "
                                        "then finished; the deploy imported the instance and applied again: "
                                        + cloudsql_create_recovery.summary(csql_records))})
                    apply_res = self._compliance_gated_apply(product_id, trace_id, workspace_dir, active_engine,
                                                             destroy_policy=destroy_policy, plan_sink=applied_plan,
                                                             expected_root_vars=expected_root_vars)
                    is_successful_deploy = apply_res["success"]
                    apply_err = apply_res.get("stderr") or apply_res.get("stdout") or ""
                else:
                    cloudsql_unresolved = csql_records

            if not is_successful_deploy:
                self._sync_feature_requests(
                    product_id=product_id,
                    trace_id=trace_id,
                    is_successful_deploy=False,
                    error_msg=apply_err,
                )
                lock_info = self.parse_state_lock_info(apply_err, max_age_minutes=self.stale_lock_max_age_min)
                diagnostic = f" (State lock held by: {lock_info['who']} since {lock_info['created']}, Lock ID: {lock_info['lock_id']})" if lock_info else ""
                logger.error(f"Terraform apply failed in {workspace_dir}: {apply_err[:1000]}{diagnostic}")
                failed_res = {
                    "status": "FAILED",
                    "error": f"Terraform apply failed: {apply_err}{diagnostic}",
                    "lock_info": lock_info,
                    "stdout": apply_res.get("stdout", ""),
                    "stderr": apply_res.get("stderr", ""),
                }
                if adoption_unresolved and adoption_unresolved_for == apply_err:
                    # FD-4CY W7 (fail loudly): a conflict of the final apply error that the plan could not name exactly
                    failed_res.update(error_class=brownfield_adoption.ERROR_APPLY_ADOPTION_UNRESOLVED,
                                      stage=brownfield_adoption.ADOPTION_STAGE,
                                      adoption_unresolved=adoption_unresolved)
                    if cloudsql_unresolved:   # CLOUDSQL-CREATE-OWN-OPERATION RT N3: the same failed apply's records
                        failed_res["cloudsql_create"] = cloudsql_unresolved
                    logger.error(f"{brownfield_adoption.ERROR_APPLY_ADOPTION_UNRESOLVED} ({brownfield_adoption.ADOPTION_STAGE}) "
                                 f"for '{product_id}': {brownfield_adoption.unresolved_summary(adoption_unresolved)}")
                elif cloudsql_unresolved:
                    # CLOUDSQL-CREATE-OWN-OPERATION (fail loudly): this deploy's own Cloud SQL create did not finish
                    # cleanly (or could not be read back); the instance is left as it is for an operator
                    failed_res.update(error_class=cloudsql_create_recovery.ERROR_CLOUDSQL_CREATE_UNRESOLVED,
                                      stage=cloudsql_create_recovery.STAGE, operator_required=True,
                                      cloudsql_create=cloudsql_unresolved,
                                      error=(f"{cloudsql_create_recovery.ERROR_CLOUDSQL_CREATE_UNRESOLVED} "
                                             f"({cloudsql_create_recovery.STAGE}): "
                                             f"{cloudsql_create_recovery.summary(cloudsql_unresolved)}. Nothing was "
                                             f"deleted; an operator decides. {failed_res['error']}"))
                    # the typed operator route goes with the callback body too (as SUBNET_CIDR_CONFLICT)
                    failed_res[dfr.FAILURE_ROUTE_FIELD] = dfr.route(dfr.APPLY_PHASE_OWNER, dfr.PHASE_APPLY,
                                                                    dfr.BASIS_APPLY_UNATTRIBUTED)
                    logger.error(f"{cloudsql_create_recovery.ERROR_CLOUDSQL_CREATE_UNRESOLVED} "
                                 f"({cloudsql_create_recovery.STAGE}) for '{product_id}': "
                                 f"{cloudsql_create_recovery.summary(cloudsql_unresolved)}")
                elif is_subnet_cidr_conflict(apply_err):
                    # RT14-01: the conflict that used to trigger a REST subnet delete is a typed stop for an operator
                    failed_res.update(error_class=SUBNET_CIDR_CONFLICT, stage=SUBNET_CIDR_CONFLICT_STAGE,
                                      operator_required=True)
                    failed_res[dfr.FAILURE_ROUTE_FIELD] = dfr.route(dfr.APPLY_PHASE_OWNER, dfr.PHASE_APPLY,
                                                                    dfr.BASIS_APPLY_UNATTRIBUTED)
                    logger.error(f"{SUBNET_CIDR_CONFLICT} ({SUBNET_CIDR_CONFLICT_STAGE}) for '{product_id}': a declared "
                                 "subnetwork range overlaps an existing subnetwork; nothing was deleted")
                elif apply_res.get("compliance_gate_phase") == "plan":
                    # DEPLOY-FAILURE-OWNER-ROUTER: the gated plan failed (nothing applied): one read-only `plan -json`
                    # re-run names the files that failed; on an intent workspace it is also the typed report
                    plan_route, plan_report = self._classify_plan_failure(workspace_dir, active_engine, files,
                                                                          bool(intent_ws))
                    failed_res[dfr.FAILURE_ROUTE_FIELD] = plan_route
                    if plan_report is not None:
                        failed_res["validation_report"] = plan_report
                else:
                    # DEPLOY-FAILURE-OWNER-ROUTER: an apply-time failure has no typed diagnostics (plan §3)
                    failed_res[dfr.FAILURE_ROUTE_FIELD] = dfr.route(dfr.APPLY_PHASE_OWNER, dfr.PHASE_APPLY,
                                                                    dfr.BASIS_APPLY_UNATTRIBUTED)
                return failed_res
        else:
            if apply_res.get("stdout"):
                for line in apply_res["stdout"].splitlines():
                    if "has moved to" in line or "Resource has moved" in line:
                        logger.info(f"🛡️ State migration: {line.strip()}")
                    elif "Apply complete!" in line or "Plan:" in line:
                        logger.info(f"🏁 Terraform Summary: {line.strip()}")

        # 3. Retrieve Outputs
        # RT14-09: `outputs` (records, result, callback) is masked by the engine's own `sensitive` flag; the unmasked
        # map stays in memory for the URL / cluster / sign-in domain reads below and is never stored or returned.
        outputs, raw_outputs = self._read_tofu_outputs(workspace_dir, active_engine)

        # FD-4DE (fail-loudly rule 1.4): no URL is built from ids. A successful container deploy whose outputs name
        # no URL reads the real one from the Cloud Run v2 API; when that gives none, the URL is unknown with a typed
        # reason (`service_url_unknown_reason`) and the result's warnings say so.
        cloud_run_listing: Dict[str, Any] = {}

        def _cloud_run_services() -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
            # one listing per deploy, shared by the URL confirmation, the URL lookup and the sign-in domain step
            if "result" not in cloud_run_listing:
                cloud_run_listing["result"] = self._list_cloud_run_services(target_project_id, workload_region)
            return cloud_run_listing["result"]

        service_url_unknown_reason: Optional[str] = None
        # FD-102: the URL an output names is the workload's own (its Terraform writes it), so it is recorded only when
        # Run-API-confirmed (confirm_cloud_run_service_url), right here, before every write; then the API's string is
        # used. An unconfirmed output records "" with its typed reason (and the SERVICE_URL_UNKNOWN warning below) and
        # is never replaced by a URL picked from the listing. No listing is made for a failed deploy. Not covered: the
        # sign-in domain step (3b) still authorizes the host of any output whose value contains "run.app" without this
        # confirmation (FD-146).
        if raw_outputs and not service_url and is_successful_deploy:
            output_entry = (raw_outputs.get("service_url") or raw_outputs.get("service_uri")
                            or raw_outputs.get("url"))
            output_value = output_entry.get("value") if isinstance(output_entry, Mapping) else None
            if output_value is not None and output_value != "":
                listed, list_reason = _cloud_run_services()
                service_url, service_url_unknown_reason = confirm_cloud_run_service_url(output_value, listed)
                if service_url_unknown_reason == SERVICE_URL_API_UNAVAILABLE and list_reason:
                    service_url_unknown_reason = list_reason   # the listing's own typed reason

        # RT F1: a typed topology without a `cloudrun` service (GKE, event worker only) expects no URL: no lookup, no
        # unknown reason (as a deploy with nothing to build)
        if (not service_url and service_url_unknown_reason is None and is_successful_deploy and needs_container_build
                and topology_expects_service_url(service_kinds)):
            clean_pid = product_id.lower().replace("_", "-")
            listed, list_reason = _cloud_run_services()
            if listed is None:
                service_url_unknown_reason = list_reason or SERVICE_URL_API_UNAVAILABLE
            else:
                # the golden compute-cloudrun module's default service name is the product id
                service_url, service_url_unknown_reason = pick_cloud_run_service_url(
                    listed, (clean_pid, f"castor-{clean_pid}"))

        # 3b. Automatically authorize Cloud Run domains in Identity Platform (Zero-Touch; AQ-2: PUBLIC_APP only)
        if is_successful_deploy and tenant_signin:
            try:
                from urllib.parse import urlparse
                domains_to_authorize = {"localhost", f"{target_project_id}.firebaseapp.com"}
                if service_url:
                    parsed = urlparse(service_url)
                    if parsed.hostname:
                        domains_to_authorize.add(parsed.hostname)
                for out_val in raw_outputs.values():   # RT14-09: the in-memory unmasked map
                    val_str = out_val.get("value", "") if isinstance(out_val, dict) else str(out_val)
                    if isinstance(val_str, str) and "run.app" in val_str:
                        p = urlparse(val_str if "://" in val_str else f"https://{val_str}")
                        if p.hostname:
                            domains_to_authorize.add(p.hostname)
                # FD-4DE: the hosts every Cloud Run service of the child region really serves (its `uri` and `urls`,
                # which include the deterministic <name>-<number> form), read from the API; no host is built from ids.
                listed_services, listing_reason = _cloud_run_services()
                if listed_services is None and apply_ctx is not None:
                    # RT N1: typed warning in the deploy result: only the hosts known without the API are authorized
                    apply_ctx.setdefault("warnings", []).append(
                        signin_domains_incomplete_warning(target_project_id,
                                                          listing_reason or SERVICE_URL_API_UNAVAILABLE))
                for cr_service in listed_services or []:
                    cr_urls = cr_service.get("urls")
                    for cr_url in [cr_service.get("uri")] + (cr_urls if isinstance(cr_urls, list) else []):
                        if isinstance(cr_url, str) and cr_url:
                            cr_host = urlparse(cr_url).hostname
                            if cr_host:
                                domains_to_authorize.add(cr_host)

                from google.auth.transport.requests import Request
                import httpx
                auth_creds = self._child_credentials(target_project_id)   # FD4BD-Q3
                if not auth_creds.valid:
                    auth_creds.refresh(Request())
                # FD-7L 2a: the brokered deployer has no rights in the host project, so a Per-workload run bills the
                # child here; a Shared install keeps the host quota project (OQ-5b open).
                idp_quota_project = (target_project_id if self._runner_for_project(target_project_id) is not None
                                     else self.project_id or target_project_id)
                idp_headers = {
                    "Authorization": f"Bearer {auth_creds.token}",
                    "X-Goog-User-Project": idp_quota_project,
                    "Content-Type": "application/json",
                }
                with httpx.Client(timeout=10.0) as http_client:
                    cfg_url = f"https://identitytoolkit.googleapis.com/admin/v2/projects/{target_project_id}/config"
                    cfg_res = http_client.get(cfg_url, headers=idp_headers)
                    if cfg_res.status_code == 200:
                        existing_domains = cfg_res.json().get("authorizedDomains", [])
                        merged_domains = list(dict.fromkeys(existing_domains + sorted(list(domains_to_authorize))))
                        if set(merged_domains) != set(existing_domains):
                            patch_url = f"{cfg_url}?updateMask=authorizedDomains"
                            patch_res = http_client.patch(patch_url, headers=idp_headers, json={"authorizedDomains": merged_domains})
                            if patch_res.status_code == 200:
                                logger.info(f"Successfully whitelisted domains in Identity Platform for '{target_project_id}': {domains_to_authorize}")
                            else:
                                logger.warning(f"Failed to patch authorizedDomains for '{target_project_id}': {patch_res.status_code} {patch_res.text[:200]}")
                        else:
                            logger.info(f"All required domains already authorized in Identity Platform for '{target_project_id}'")
                    else:
                        logger.warning(f"Could not fetch Identity Platform config for '{target_project_id}': {cfg_res.status_code} {cfg_res.text[:200]}")
            except Exception as idp_err:
                logger.warning(f"Could not automatically authorize domains in Identity Platform: {idp_err}")

        # 3c. RT14-04: the GKE workload's repository-root k8s/*.yaml are applied to the cluster this apply created, by
        # the deploy's own REST applier (k8s_manifest_apply; invariant 7). The old step imported the Kubernetes MCP's
        # package, which this image does not ship, and swallowed the ImportError as "non-fatal": every GKE deploy
        # reported SUCCESS with nothing running. Any refusal or failure is now K8S_MANIFEST_APPLY_FAILED (FAILED).
        k8s_failure: Optional[Dict[str, Any]] = None
        k8s_report: Optional[Dict[str, Any]] = None
        if is_successful_deploy:
            cluster_name_val = ""
            for k_out in ("cluster_name", "gke_cluster_name"):   # RT14-09: read from the unmasked in-memory map
                if k_out in raw_outputs:
                    cluster_name_val = raw_outputs[k_out].get("value", "") if isinstance(raw_outputs[k_out], dict) else str(raw_outputs[k_out])
                    if cluster_name_val:
                        break
            if cluster_name_val and k8s_manifest_apply.manifest_files(workspace_dir):
                logger.info(f"Applying k8s/ manifests of '{product_id}' to GKE cluster '{cluster_name_val}' (REST)...")
                try:
                    from google.auth.transport.requests import AuthorizedSession, Request as _GRequest
                    k8s_creds = self._child_credentials(target_project_id)   # FD4BD-Q3 / FD-7L: the deployer
                    if not getattr(k8s_creds, "valid", False) or not getattr(k8s_creds, "token", None):
                        k8s_creds.refresh(_GRequest())
                    k8s_report = k8s_manifest_apply.apply_workspace_manifests(
                        workspace_dir, google_session=AuthorizedSession(k8s_creds), token=k8s_creds.token,
                        project_id=target_project_id, location=workload_region, cluster_name=cluster_name_val)
                except k8s_manifest_apply.ManifestApplyFailed as k8s_err:
                    k8s_failure = k8s_err.result(cluster_name_val)
                except Exception as k8s_err:  # noqa: BLE001 - typed: never a "non-fatal" notice
                    k8s_failure = k8s_manifest_apply.ManifestApplyFailed(
                        "APPLY_ERROR", f"{type(k8s_err).__name__}").result(cluster_name_val)
                if k8s_failure is not None:
                    logger.error(k8s_failure["error"])
                    is_successful_deploy = False

        # 3d. Post-Apply Cloud Run Revision Rollout Engine (Cloud Separation of Concerns Pattern)
        # When container images were compiled during buildpack phase, Cloud Run must roll out a fresh revision
        # of the newly compiled container image rather than remaining on an old revision due to :latest tag caching.
        # FD55-3D: exactly the Cloud Run services in the applied state, each to exactly the image the apply set
        # (applied_cloud_run_services); an unreadable state or image stops the deploy typed (OQ-10).
        rollout_failure: Optional[Dict[str, Any]] = None
        rollout_skipped: List[str] = []   # RT F1: addresses whose applied image is outside the build's repository
        if is_successful_deploy and needs_container_build and image_built:
            clean_pid = product_id.lower().replace("_", "-")
            rollout_plan: List[Dict[str, str]] = []
            state_res = self._run_with_own_budget(["terraform", "show", "-json"], workspace_dir, active_engine,
                                                  ROLLOUT_STATE_READ_BUDGET_S)   # RT F3
            if not state_res.get("success"):
                rollout_failure = rollout_image_unreadable_result(
                    product_id, target_project_id,
                    f"`show -json` failed: {str(state_res.get('stderr') or 'no error output')[:300]}")
            else:
                try:
                    rollout_plan, unreadable_services = applied_cloud_run_services(
                        json.loads(state_res.get("stdout") or ""))
                except (ValueError, AppliedStateUnreadable) as state_err:   # json.JSONDecodeError is a ValueError
                    rollout_plan, unreadable_services = [], []
                    rollout_failure = rollout_image_unreadable_result(
                        product_id, target_project_id, f"state JSON unreadable: {type(state_err).__name__}: {state_err}")
                if rollout_failure is None:
                    foreign = [s["address"] for s in rollout_plan
                               if s["project"] and s["project"] != target_project_id]
                    if unreadable_services:
                        rollout_failure = rollout_image_unreadable_result(
                            product_id, target_project_id,
                            f"no readable name, location or image: {', '.join(unreadable_services)}")
                    elif foreign:   # RT F4: its own class (the image was read)
                        rollout_failure = rollout_image_unreadable_result(
                            product_id, target_project_id, f"in another project: {', '.join(foreign)}",
                            error_class=ROLLOUT_SERVICE_OUTSIDE_TARGET)
            if rollout_failure is not None:
                logger.error(rollout_failure["error"])
                rollout_plan = []
            # RT F1: only images inside this deploy's own Artifact Registry repository (exact prefix) are rolled
            repo_prefix = rollout_repository_prefix(workload_region, target_project_id, ar_repo_name)
            rollout_skipped = sorted(s["address"] for s in rollout_plan if not s["image"].startswith(repo_prefix))
            rollout_plan = [s for s in rollout_plan if s["image"].startswith(repo_prefix)]
            if rollout_skipped:
                logger.info(f"Post-apply rollout of '{product_id}': not rolled (image outside {repo_prefix}): "
                            f"{', '.join(rollout_skipped)}")

            # FD-4DE: the primary service (its rolled `uri` may replace an unknown URL); unchanged by FD55-3D
            primary_svc_name = clean_pid
            main_tf_path = os.path.join(workspace_dir, "main.tf")   # (was defined by the deleted Layer 3b)
            if os.path.exists(main_tf_path):
                try:
                    with open(main_tf_path, "r", encoding="utf-8") as f_m:
                        m_txt = f_m.read()
                    m_sname = re.search(r'service_name\s*=\s*"([^"]+)"', m_txt)
                    if m_sname:
                        primary_svc_name = m_sname.group(1)
                except Exception:
                    pass

            for applied in sorted(rollout_plan, key=lambda s: (s["name"], s["location"], s["address"])):
                cr_svc = applied["name"]
                try:
                    rollout_ok, rolled_rev, rolled_url = self._rollout_cloud_run_revision(
                        target_project_id=target_project_id,
                        service_name=cr_svc,
                        region=applied["location"],
                        image_tag=applied["image"],
                    )
                    if rollout_ok and rolled_url:
                        # FD-4DE: the primary service's API `uri` replaces an unknown URL; another service's never
                        # does (before FD-4DE a built-from-ids URL always filled the gap, so none ever did).
                        if cr_svc == primary_svc_name or (not service_url and service_url_unknown_reason is None):
                            service_url = rolled_url
                            service_url_unknown_reason = None
                except Exception as cr_rollout_err:
                    logger.warning(f"Post-apply rollout notice for '{cr_svc}': {cr_rollout_err}")
        if rollout_failure is not None:
            is_successful_deploy = False   # FD55-3D (OQ-10): the record and the result say FAILED, typed below

        if service_url:
            service_url_unknown_reason = None
        elif service_url_unknown_reason:
            logger.warning(f"{SERVICE_URL_UNKNOWN} ({service_url_unknown_reason}) for '{product_id}' in "
                           f"'{target_project_id}': the service URL is reported as unknown.")
            if apply_ctx is not None:   # typed warning in the deploy result (deploy_workload adds `warnings`)
                apply_ctx.setdefault("warnings", []).append(
                    service_url_unknown_warning(product_id, service_url_unknown_reason))

        # 4. Update Firestore
        now_iso = datetime.now(timezone.utc).isoformat()
        deployment_record = {
            "product_id": product_id,
            "project_id": target_project_id,
            "trace_id": trace_id,
            "applied_at": now_iso,
            "applied_iac_engine": (active_engine or "OPENTOFU").strip().lower(),
            "status": "SUCCESS" if is_successful_deploy else "FAILED",
            "state_bucket": state_ctx.bucket,   # FD-7L Phase 2b: the run's bucket (PLATFORM: as before)
            "state_path": f"gs://{state_ctx.bucket}/workloads/{product_id}/default.tfstate",
            "service_url": service_url,
            "service_url_unknown_reason": service_url_unknown_reason,
            "outputs": outputs,
            "stdout": apply_res["stdout"][:2000] if apply_res["stdout"] else "",
            "stderr": apply_res["stderr"][:2000] if apply_res["stderr"] else "",
        }
        if rollout_failure is not None:   # FD55-3D: the typed reason is on the audit record too
            deployment_record.update(error_class=rollout_failure["error_class"], error=rollout_failure["error"])
        if k8s_failure is not None:   # RT14-04: the typed reason is on the audit record too
            deployment_record.update(error_class=k8s_failure["error_class"], error=k8s_failure["error"])

        if self.db:
            try:
                self.db.collection("terraform_deployments").document(f"deploy-{trace_id}").set(deployment_record)
                workload_update = {
                    "status": "DEPLOYED" if is_successful_deploy else "FAILED",
                    "deployed_at": now_iso,
                    "applied_iac_engine": (active_engine or "OPENTOFU").strip().lower(),
                    "last_applied_engine": (active_engine or "OPENTOFU").strip().lower(),
                }
                if service_url:
                    workload_update["service_url"] = service_url
                    workload_update["service_url_unknown_reason"] = None
                elif service_url_unknown_reason:
                    # FD-4DE: a URL was expected but could not be read: the record says unknown (and why) instead of
                    # keeping an earlier URL as if this deploy had confirmed it
                    workload_update["service_url"] = ""
                    workload_update["service_url_unknown_reason"] = service_url_unknown_reason
                self.db.collection("workloads").document(product_id).set(workload_update, merge=True)

                # Update all active feature requests for this workload
                self._sync_feature_requests(
                    product_id=product_id,
                    trace_id=trace_id,
                    is_successful_deploy=is_successful_deploy,
                    error_msg=(rollout_failure["error"] if rollout_failure is not None
                               else k8s_failure["error"] if k8s_failure is not None
                               else apply_res.get("stderr", "") or apply_res.get("error", "")),
                    service_url=service_url,
                )

                logger.info(f"Recorded deployment audit and updated status for '{product_id}' in Firestore")
            except Exception as db_err:
                logger.warning(f"Could not persist deployment record to Firestore: {db_err}")

        feature_tag = trace_id or product_id
        final_status = "SUCCESS" if is_successful_deploy else "FAILED"
        logger.info("=" * 64)
        logger.info(f"🏁 FEATURE [{feature_tag}] END PROCESS: {product_id} - STATUS: {final_status} (URL: {service_url})")
        logger.info("=" * 64)
        result = {
            # FD-4D-c / FD-4AI-c F1: deploy success is reported as exactly SUCCESS (the DEPLOYED alias is removed).
            # The workloads/{id} lifecycle field above keeps its own word (DEPLOYED); it is not a deploy result.
            "status": "SUCCESS" if is_successful_deploy else "FAILED",
            "product_id": product_id,
            "project_id": target_project_id,
            "trace_id": trace_id,
            "service_url": service_url,
            # FD-4DE: None when the URL is known or none is expected; else the typed reason it is unknown
            "service_url_unknown_reason": service_url_unknown_reason,
            "state_file": f"gs://{state_ctx.bucket}/workloads/{product_id}/default.tfstate",
            "outputs": outputs,
            "stdout": apply_res["stdout"],
            "stderr": apply_res["stderr"],
        }
        if k8s_failure is not None:   # RT14-04: error_class, stage, error, per-document report
            result.update(k8s_failure)
        elif k8s_report is not None:
            result["k8s_manifests"] = k8s_report
        if rollout_failure is not None:   # FD55-3D (OQ-10): error_class, error, operator_required
            result.update(rollout_failure)
        if rollout_skipped:   # RT F1
            result["rollout_skipped"] = rollout_skipped
        return result


def install_runner_identity_mode() -> str:
    """FD-7L-n: the install's runner identity mode for code that has no TerraformService yet (tf-applier's entry
    branch). Reads it through TerraformService._runner_identity_mode, the one reader, on an instance built without
    __init__ (no Firestore client is constructed). Raises shared.runner_identity.RunnerIdentityError like it."""
    return TerraformService.__new__(TerraformService)._runner_identity_mode()
