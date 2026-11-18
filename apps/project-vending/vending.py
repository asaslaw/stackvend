"""
Project Castor: Account & Repository Vending Machine Engine
Automates Google Cloud project creation under organization folders, billing linking, and GitHub App JIT token minting via Secret Manager.
"""

import json
import logging
import os
import re
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any, Dict, List, Optional, Tuple

import google.auth
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.cloud import firestore, secretmanager
import jwt
from github import Github, GithubException

try:
    from shared.vcs_provider import VCSProviderFactory
except ImportError:
    try:
        from .vcs_provider import VCSProviderFactory
    except ImportError:
        try:
            from vcs_provider import VCSProviderFactory
        except ImportError:
            VCSProviderFactory = None

# GITHUB-ORG-ONLY: no ImportError fallback -- without the organization check repository vending must not run.
from shared.providers.github_provider import (GitHubOwnerNotOrganizationError, GitHubRepositoryCreateError,
                                              require_github_organization)

try:
    from shared.github_identity import (GITHUB_ACTIONS_DEPLOY_FIELD, GITHUB_REPOSITORY_IDENTITY_FIELD,
                                        branch_secret_suffix, get_default_github_owner,
                                        github_actions_deploy_enabled, github_repository_identity_record,
                                        next_github_repository_identity, pinned_github_repository_id,
                                        repository_is_workloads_own, repository_names,
                                        repository_shared_with_other_workload, resolve_repo_identity)
except ImportError:
    try:
        from .github_identity import (GITHUB_ACTIONS_DEPLOY_FIELD, GITHUB_REPOSITORY_IDENTITY_FIELD,
                                      branch_secret_suffix, get_default_github_owner,
                                      github_actions_deploy_enabled, github_repository_identity_record,
                                      next_github_repository_identity, pinned_github_repository_id,
                                      repository_is_workloads_own, repository_names,
                                      repository_shared_with_other_workload, resolve_repo_identity)
    except ImportError:
        try:
            from github_identity import (GITHUB_ACTIONS_DEPLOY_FIELD, GITHUB_REPOSITORY_IDENTITY_FIELD,
                                         branch_secret_suffix, get_default_github_owner,
                                         github_actions_deploy_enabled, github_repository_identity_record,
                                         next_github_repository_identity, pinned_github_repository_id,
                                         repository_is_workloads_own, repository_names,
                                         repository_shared_with_other_workload, resolve_repo_identity)
        except ImportError:
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
            # FD-4AT-c: no repository-id record without shared.github_identity (the WIF condition keeps name + main).
            GITHUB_REPOSITORY_IDENTITY_FIELD = None
            next_github_repository_identity = pinned_github_repository_id = None
            # GITHUB-REPO-NAME-NO-PREFIX: no ownership record to read: an existing repository is never used (refused),
            # and no claim is written before a create.
            repository_is_workloads_own = repository_names = github_repository_identity_record = None
            # FD-4CI-b-R1-WIF-SHARED: no shared-repository secret names without shared.github_identity (a redeploy's
            # secret write then fails and is logged, as any other secret-write failure).
            branch_secret_suffix = repository_shared_with_other_workload = None
            # GHA-DEPLOY-SWITCH: a record that carries the switch writes no deploy secrets (logged below).
            GITHUB_ACTIONS_DEPLOY_FIELD = "github_actions_deploy"
            github_actions_deploy_enabled = None


class GitHubRepositoryNameTakenError(GitHubRepositoryCreateError):
    """GITHUB-REPO-NAME-NO-PREFIX (owner 11-12): the repository vending would create for the workload already exists
    on GitHub and is not the workload's own (shared.github_identity.repository_is_workloads_own: the workload's
    github_repository_identity record does not name it, or pins an id GitHub contradicts). With the default name now
    the bare workload id, an unrelated repository of the organization (for example a staff repository called
    `payments`) can hold the name. Vending never uses, changes or records such a repository: the vend fails with this
    class and stage, the workload record's `github_repo` is cleared (RT F5: no later step that skips vending can
    target it), and nothing is pushed. Not retried (no HTTP status)."""

    error_class = "GITHUB_REPOSITORY_NAME_TAKEN"
    stage = "vcs_repository_vending"

    def __init__(self, owner: str, full_name: str, product_id: str):
        self.owner, self.full_name, self.status = owner, full_name, None
        self.reason = "a repository of that name exists and is not this workload's"
        self.headers, self.data = {}, None
        RuntimeError.__init__(
            self,
            f"{self.error_class}: the GitHub repository '{full_name}' already exists and is not the repository of "
            f"workload '{product_id}'. StackVend does not use or change an existing repository it has not recorded for "
            f"this workload, and nothing was created. Rename or remove that repository on GitHub and run the workload "
            f"again, or create the workload with another workload id (its repository is named after it), or enter "
            f"another existing repository of your organization in New Workload > Target GitHub Repository.")


class GitHubRepositoryIdChangedError(GitHubRepositoryCreateError):
    """GITHUB-REPO-NAME-NO-PREFIX (RT D2): the repository the workload has recorded (its github_repository_identity
    names it and pins GitHub's id) exists under that name with ANOTHER id: it was deleted and a repository of the same
    name was created since (by anyone). Fail closed (FD-4AT-c): it is not used, changed or pinned. Unlike
    GITHUB_REPOSITORY_NAME_TAKEN the workload keeps its `github_repo` and identity record (it stays an established
    workload: retrigger and deploy keep their target; CI deploys from the new repository stay refused by the pin).
    There is no automatic re-pin. Not retried (no HTTP status)."""

    error_class = "GITHUB_REPOSITORY_ID_CHANGED"
    stage = "vcs_repository_vending"

    def __init__(self, owner: str, full_name: str, product_id: str, recorded_id: Any, found_id: Any):
        self.owner, self.full_name, self.status = owner, full_name, None
        self.reason = f"recorded id {recorded_id}, GitHub reports {found_id}"
        self.headers, self.data = {}, None
        RuntimeError.__init__(
            self,
            f"{self.error_class}: the GitHub repository '{full_name}' of workload '{product_id}' now has id "
            f"{found_id}, not the recorded id {recorded_id}: it was deleted and a repository of the same name was "
            f"created. StackVend does not use it. To recover: remove or rename that new repository on GitHub, then "
            f"restore the original from the organization's Deleted repositories (it keeps its id) and run the workload "
            f"again. Only on a Shared runner install can the workload move to the new repository instead (rename it "
            f"on GitHub and re-submit this workload id in New Workload with the new name in Target GitHub "
            f"Repository); on a Per-workload install the runner identity pins the original repository and refuses "
            f"another one (VENDING.RUNNER_REPOSITORY_MISMATCH), so restoring is the way there.")


class GitHubRepositoryUnreadableError(GitHubRepositoryCreateError):
    """GITHUB-REPO-NAME-NO-PREFIX (RT F4): vending could not tell whether the repository it would create exists, or
    whether an existing one is the workload's own (GitHub's answer or the repository id could not be read: a 5xx, a
    timeout, no usable GitHub credentials). Nothing was created, changed or recorded; running the workload again
    reads GitHub again. Never reported as GITHUB_REPOSITORY_NAME_TAKEN. Not retried here (no HTTP status)."""

    error_class = "GITHUB_REPOSITORY_UNREADABLE"
    stage = "vcs_repository_vending"

    def __init__(self, owner: str, full_name: str, why: str):
        self.owner, self.full_name, self.status, self.reason = owner, full_name, None, why
        self.headers, self.data = {}, None
        RuntimeError.__init__(
            self,
            f"{self.error_class}: GitHub could not be read for the repository '{full_name}' ({why}). Nothing was "
            f"created or changed. Run the workload again; if it keeps failing, check the StackVend GitHub App "
            f"credentials and that the App can read repositories in '{owner}'.")


class RepositoryClaimNotRecordedError(GitHubRepositoryCreateError):
    """GITHUB-REPO-NAME-NO-PREFIX (RT F1/F2): the claim on the repository name (workloads/{pid}.
    github_repository_identity = {full_name, repository_id: None}, written BEFORE the create so a retried or
    interrupted create finds its own repository) could not be written. Nothing was created. Not retried here."""

    error_class = "REPOSITORY_CLAIM_NOT_RECORDED"
    stage = "vcs_repository_vending"

    def __init__(self, owner: str, full_name: str, product_id: str, why: str):
        self.owner, self.full_name, self.status, self.reason = owner, full_name, None, why
        self.headers, self.data = {}, None
        RuntimeError.__init__(
            self,
            f"{self.error_class}: workloads/{product_id} could not be updated with the claim on the repository "
            f"'{full_name}' ({why}); the repository was not created. Run the workload again.")


# GITHUB-REPO-NAME-NO-PREFIX RT F2: the repository and the project were vended but workloads/{pid} could not be updated
# with the repository and its identity record. Not reported vended (fail loudly); the next run finds the repository
# through its claim. (RT F6 reuses VENDING.WORKLOAD_RECORD_UNREADABLE, defined below, for vend_all's own record read.)
WORKLOAD_RECORD_NOT_WRITTEN = "VENDING.WORKLOAD_RECORD_NOT_WRITTEN"

# OQ-15 (owner 10-31): the project whose deploy secrets vend_all wrote for a promoted workload (written once per project).
PROMOTION_DEPLOY_SECRETS_FIELD = "promotion_deploy_secrets_project_id"
# RT14-18: the typed reason the GitHub Actions deploy secrets were not written (GitHubSecretsNotWritten.body()),
# on the workload record and the redeploy answer.
DEPLOY_SECRETS_ERROR_FIELD = "wif_secrets_error"

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
            def get_github_token(*args, **kwargs):
                return os.getenv("GITHUB_TOKEN") or os.getenv("GITHUB_PAT") or ""
            def github_retry_with_backoff(*args, **kwargs):
                return lambda f: f
            class GitHubRateLimitExceededError(Exception):
                pass

import cc_log_reader as ccl
import destructive_guard as dg
import runner_broker as rb
import runner_identity_backfill as rib
import runner_identity_mode as rim

ri = rb.ri   # shared/runner_identity.py (FD-7L)

logger = logging.getLogger("project-repo-vending-service")
logging.basicConfig(level=logging.INFO)

# Sandbox designation vocabulary accepted from an explicit vend request (lane 14 Q1 / lane 18 9b). KEYWORD is stored
# as given but is never TTL-eligible (destructive_guard.EXPLICIT_DESIGNATION_SOURCES).
VEND_DESIGNATION_SOURCES = frozenset({"OPERATOR_CHECKBOX", "API_FIELD", "OPERATOR_CONFIRMED", "KEYWORD"})

# VENDING-POLL-TRANSIENT (owner 10-30). Polling a long-running operation (operations.get) is an idempotent read, so a
# poll that fails with a TRANSIENT transport or server error is simply polled again, within the caller's existing
# deadline and backoff. Transient is decided by exception class and HTTP status only, never by message text:
# * TimeoutError (socket.timeout is TimeoutError; an ssl "read operation timed out" inside httplib2 raises it),
# * ConnectionError and its subclasses (reset, aborted, refused, broken pipe; http.client.RemoteDisconnected),
# * googleapiclient HttpError with status 429 / 500 / 502 / 503 / 504.
# Everything else is not transient and is raised at once: other 4xx, httplib2.ServerNotFoundError (DNS: a name that
# does not resolve is a configuration fault, not a blip), auth errors. Create / mutate calls are never retried here.
TRANSIENT_POLL_HTTP_STATUSES = frozenset({429, 500, 502, 503, 504})


# SAT-51 (owner 11-03 live: two workloads vended at once both died with "OSError: [Errno 9] Bad file descriptor"). The
# engine is one module-level object and each vend runs on its own worker thread, so the cached discovery clients are
# shared across threads; httplib2.Http is not thread-safe, and two token refreshes on one connection closed the socket
# under each other. Per the google-api-python-client thread-safety guidance the client object stays shared but every
# request gets its own authorized httplib2 connection (build_http keeps the library's default timeout).
def _build_thread_safe(service: str, version: str):
    import google_auth_httplib2
    from googleapiclient.http import HttpRequest, build_http
    credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])

    def request_builder(_http, *args, **kwargs):
        return HttpRequest(google_auth_httplib2.AuthorizedHttp(credentials, http=build_http()), *args, **kwargs)

    return build(service, version, http=google_auth_httplib2.AuthorizedHttp(credentials, http=build_http()),
                 requestBuilder=request_builder, cache_discovery=False)


def _is_transient_poll_error(err: BaseException) -> bool:
    """True for a transport / server error that a repeated operations.get may outlive (see TRANSIENT_POLL_*)."""
    if isinstance(err, (TimeoutError, ConnectionError)):
        return True
    # HttpError is a class in production; the isinstance(type) guard keeps the check safe where a test stubbed the
    # googleapiclient module out.
    if isinstance(HttpError, type) and isinstance(err, HttpError):
        try:
            status = int(getattr(getattr(err, "resp", None), "status", None))
        except (TypeError, ValueError):
            return False
        return status in TRANSIENT_POLL_HTTP_STATUSES
    return False


def _poll_operation_once(fetch, what: str) -> Tuple[bool, Any]:
    """One operations.get poll. Returns (True, operation) on an answer, or (False, error) after a transient error,
    logged at WARNING with its class (and HTTP status) only. A non-transient error is raised unchanged."""
    try:
        return True, fetch()
    except Exception as e:  # noqa: BLE001 - re-raised below unless typed transient
        if not _is_transient_poll_error(e):
            raise
        status = getattr(getattr(e, "resp", None), "status", None) if not isinstance(e, OSError) else None
        logger.warning(f"VENDING_POLL_TRANSIENT: polling {what} raised {type(e).__name__}"
                       f"{f' {status}' if status is not None else ''}; polling again before the deadline")
        return False, e


# VENDING-READ-TRANSIENT (SAT-25). Vending's single Resource Manager projects.get reads (the existence check of a
# recorded project, the ownership check after a 409 on create, the project number) are idempotent too: a TRANSIENT error
# (_is_transient_poll_error: class and HTTP status only) is read again with the poll backoff (1 s x1.5, cap 5 s) within
# PROJECT_READ_MAX_WAIT_S. Only the typed "not ours / not found" answer (HTTP 403 or 404, OQ-29) means "no such
# project"; another error is raised unchanged; still transient at the bound -> VENDING.PROJECT_READ_UNAVAILABLE. A
# project created in this call whose number is still unknown fails the vend with VENDING.PROJECT_NUMBER_UNRESOLVED
# (OQ-28) instead of going on without provenance.
PROJECT_READ_MAX_WAIT_S = 60.0
PROJECT_NOT_FOUND_HTTP_STATUSES = frozenset({403, 404})
PROJECT_READ_UNAVAILABLE = "VENDING.PROJECT_READ_UNAVAILABLE"
PROJECT_NUMBER_UNRESOLVED = "VENDING.PROJECT_NUMBER_UNRESOLVED"


def _http_status_of(err: BaseException) -> Optional[int]:
    """The HTTP status of a googleapiclient HttpError (resp.status), else None. Typed field only, never message text."""
    if not (isinstance(HttpError, type) and isinstance(err, HttpError)):
        return None
    try:
        return int(getattr(getattr(err, "resp", None), "status", None))
    except (TypeError, ValueError):
        return None


def _unprovenanced_note(project_id: str) -> str:
    """The operator action for a project created in this call that got no provenance (as CHILD_OWNER_GRANT_FAILED)."""
    return (f"Project '{project_id}' was created in this vend (billing may already be linked) but has no provenance "
            "record, so StackVend cannot delete it automatically. If another vend of this workload may still be "
            f"running, wait for it to finish before acting. Recovery: first delete projects/{project_id} by "
            "hand, then re-run the vend (re-running first would adopt the project without provenance).")


class CrmOperationError(RuntimeError):
    """A Resource Manager long-running operation finished with an `error` (a google.rpc.Status dict). Same message as
    the RuntimeError it replaces; `error` keeps the structured status for typed classification."""

    def __init__(self, operation_name: str, error: Any):
        super().__init__(f"GCP Project creation operation failed: {error}")
        self.operation_name = operation_name
        self.error = error


def _status_detail_types(status: Any) -> List[str]:
    """The `@type` strings of a google.rpc.Status dict's `details` entries (in order), else []."""
    details = status.get("details") if isinstance(status, dict) else None
    if not isinstance(details, list):
        return []
    return [d["@type"] for d in details if isinstance(d, dict) and isinstance(d.get("@type"), str)]


def _is_quota_exhausted_status(status: Any) -> bool:
    """VENDING-PROJECT-QUOTA-TYPED: True when a google.rpc.Status dict has `code` exactly 8 (RESOURCE_EXHAUSTED) or a
    `details` entry whose `@type` is exactly QUOTA_FAILURE_TYPE. Structured fields only (never `message`)."""
    if not isinstance(status, dict):
        return False
    code = status.get("code")
    if type(code) is int and code == GRPC_RESOURCE_EXHAUSTED:
        return True
    return QUOTA_FAILURE_TYPE in _status_detail_types(status)


def _project_quota_detail(project_id: str, status: Dict[str, Any]) -> str:
    """The operator message of VENDING.PROJECT_QUOTA_EXCEEDED: the code and detail types Google returned (no free text
    from Google, no other ids), who owns the quota, the 30-day pending-deletion rule and where to raise it."""
    code = status.get("code")
    signal = [f"code {code}" + (" RESOURCE_EXHAUSTED" if code == GRPC_RESOURCE_EXHAUSTED else "")
              if type(code) is int else "no code"]
    if QUOTA_FAILURE_TYPE in _status_detail_types(status):
        signal.append(QUOTA_FAILURE_TYPE)
    return (f"Resource Manager did not create project '{project_id}': the project quota is exhausted (create operation "
            f"error: {', '.join(signal)}). Nothing was created. Google limits how many projects can be created: it "
            "checks the creating account's project quota (StackVend's project-vending service account) and, inside an "
            "organization, the organization's. Projects pending deletion keep counting toward that quota for about 30 "
            "days after they were shut down, so decommissioning a workload does not free a slot at once. Raise the "
            f"project quota (metric cloudresourcemanager.googleapis.com/projects_count) as {PROJECT_QUOTA_DOC} "
            "describes, or wait for pending deletions to finish, then run the workload again.")


def _number_from_create_operation(operation: Any) -> str:
    """F-C: the project number from a finished projects.create operation's response (a v3 Project, whose name is
    exactly 'projects/<number>'), else ''."""
    response = operation.get("response") if isinstance(operation, dict) else None
    return dg._number_of(response) if isinstance(response, dict) else ""


# SAT-38 (RT SAT-25 M1 / M2 / L4 / I2; register row drafted, NOT approved). Vending never makes a second project for, and
# never silently adopts, a project StackVend may already own. Decided only by where the target id came from (a
# PROVISIONED / ACTIVE workload record = "recorded as created") and typed Resource Manager fields (HTTP status, `state`,
# `labels`, `name`) plus the provenance ledger; never by message text (invariant 2).
# * VENDING.RECORDED_PROJECT_UNREADABLE (M1): the workload record says the project was created, but projects.get
#   answers 403 / 404. Project ids are never reusable, so creating it again could only 409 into a fallback id (a
#   second project) while the original may still exist outside what vending can read.
# * VENDING.PROJECT_PENDING_DELETION (L4): the project (recorded, or found after a 409) is DELETE_REQUESTED; vending
#   neither recreates nor vends into it.
# * VENDING.PROJECT_UNPROVENANCED (M2): after a 409 the existing project carries this product's StackVend labels
#   (`stackvend-managed` = "true", `stackvend-product-id` = the product) but no provenance record names it (typically
#   an earlier vend created it and stopped before recording it). It is not adopted (StackVend could never delete it).
#   VENDING.PROJECT_PROVENANCE_UNREADABLE when the provenance record could not be read to decide (fail closed).
# * VENDING.PROJECT_TARGET_UNRECORDED (M2): the target project id is written on workloads/{product_id} before each
#   projects.create, so a vend that stops after Google created the project is re-run against that id (and then meets
#   the M2 stop) instead of generating another; a failed write stops the vend before anything is created.
# * VENDING.PROJECT_READ_FAILED (I2): the existence check and the ownership check after a 409 wrap a non-transient,
#   non-403/404 error (which they already stopped on) in this typed class.
# * VENDING.PROJECT_LABELLED_FOR_OTHER_PRODUCT: after a 409 the existing project's typed `labels` name ANOTHER product
#   (`stackvend-product-id` is a non-empty string other than this product id): another workload's project is never
#   adopted. Like every VendingFailure it stops the run for an operator (the workflow dead-letters vending failures).
# A project found after a 409 without any `stackvend-product-id` label is adopted exactly as before (brownfield / forced
# ids), and a freshly generated or pre-assigned id keeps the fallback id on 403 / 404 exactly as before.
RECORDED_PROJECT_UNREADABLE = "VENDING.RECORDED_PROJECT_UNREADABLE"
PROJECT_PENDING_DELETION = "VENDING.PROJECT_PENDING_DELETION"
PROJECT_UNPROVENANCED = "VENDING.PROJECT_UNPROVENANCED"
PROJECT_PROVENANCE_UNREADABLE = "VENDING.PROJECT_PROVENANCE_UNREADABLE"
PROJECT_TARGET_UNRECORDED = "VENDING.PROJECT_TARGET_UNRECORDED"
PROJECT_READ_FAILED = "VENDING.PROJECT_READ_FAILED"
# VENDING-RECORD-UNREADABLE (RT SAT-38 L4; row drafted, NOT approved): workloads/{product_id} could not be read at the
# start of a vend; it stops before anything is created (the record may already name this workload's project).
WORKLOAD_RECORD_UNREADABLE = "VENDING.WORKLOAD_RECORD_UNREADABLE"
PROJECT_LABELLED_FOR_OTHER_PRODUCT = "VENDING.PROJECT_LABELLED_FOR_OTHER_PRODUCT"
# VENDING-TARGET-MARKER (RT SAT-38 L3; row drafted, NOT approved). The pre-create write also merges a typed marker
# `vend_target` = {project_id, trace_id, recorded_at} ("a vend attempted to create this id"). A LATER vend (the marker is
# read from the start-of-vend record snapshot, so a run's own write never counts) whose create of that same id answers
# 409 and whose read answers 403/404 stops with VENDING.VEND_TARGET_UNREADABLE instead of creating a fallback (second)
# project: the earlier create may not be visible yet. A DECOMMISSIONED record's marker is ignored (it names a project
# of the decommissioned workload, which may be purged; a fallback id is then right, as before). A first run with a
# Control Center pre-assigned id has no marker and keeps the fallback.
VEND_TARGET_MARKER = "vend_target"
VEND_TARGET_UNREADABLE = "VENDING.VEND_TARGET_UNREADABLE"
# VENDING-CLIENT-FAIL-LOUD (SAT-51 review; row pending owner approval): no Resource Manager client could be built (the
# build raised, for example no credentials). A vend or a folder creation stops with this class before anything is
# created; it used to skip the project create (and the existence check, IAM grants and project-number read) and still
# answer PROJECT_VENDED, or answer a made-up folder id. Classified by where it happens (the client is missing), never
# by message text.
RESOURCE_MANAGER_CLIENT_UNAVAILABLE = "VENDING.RESOURCE_MANAGER_CLIENT_UNAVAILABLE"
# VENDING-CLIENT-FAIL-LOUD (gap 1): no Firestore client (no platform project, or the build raised). The workload record
# decides which project a workload owns and carries the pre-create target marker; a vend without it used to skip the
# record read, the marker and the record write and still answer PROJECT_VENDED (a re-vend could create a second
# project). It now stops before anything is created.
FIRESTORE_CLIENT_UNAVAILABLE = "VENDING.FIRESTORE_CLIENT_UNAVAILABLE"
# VENDING-CLIENT-FAIL-LOUD (gap 1): the final workload record write of a vend failed. The project exists (and its
# target marker and provenance are recorded, so a re-run reuses it); the vend fails instead of answering PROJECT_VENDED
# for a workload whose record does not say so.
WORKLOAD_RECORD_UNWRITTEN = "VENDING.WORKLOAD_RECORD_UNWRITTEN"
# VENDING-CLIENT-FAIL-LOUD (gap 2): a project must be created but no parent folder is known (request, record, env).
PARENT_FOLDER_UNCONFIGURED = "VENDING.PARENT_FOLDER_UNCONFIGURED"
# VENDING-CLIENT-FAIL-LOUD (gap 3): a folder create whose answer gives no folder id (never a made-up id).
FOLDER_CREATE_UNCONFIRMED = "VENDING.FOLDER_CREATE_UNCONFIRMED"
# RT14-02 (invariant 5): a vend whose target is the platform itself (a pseudo-workload id, an is_castor record, or a
# recorded / forced project id equal to the host project) stops before any Resource Manager call.
TARGET_IS_PLATFORM = "VENDING.TARGET_IS_PLATFORM"
# VENDING-PROJECT-QUOTA-TYPED (owner 11-16; live 11-16 on stackvend12): Resource Manager reports an exhausted project
# quota in the finished projects.create long-running operation, whose `error` is a google.rpc.Status: `code` 8
# (gRPC RESOURCE_EXHAUSTED) with a `details` entry of `@type` type.googleapis.com/google.rpc.QuotaFailure. Such a
# create stops with this class instead of an untyped RuntimeError (which the workflow recorded as DEPENDENCY_FAILED).
# Classified by those two structured fields only (exact int / exact string equality), never by message text; any
# other operation error is raised exactly as before. Only the project-create waits classify (a folder create keeps its
# untyped error).
PROJECT_QUOTA_EXCEEDED = "VENDING.PROJECT_QUOTA_EXCEEDED"
GRPC_RESOURCE_EXHAUSTED = 8
QUOTA_FAILURE_TYPE = "type.googleapis.com/google.rpc.QuotaFailure"
PROJECT_QUOTA_DOC = ("documentation/known-limitations.md, section 'Every workload uses one Google Cloud project: the "
                     "project quota'")
# HTTP status the sync routes answer a VendingFailure of these classes with (configuration / a dependency that is
# unavailable: 503); any other class answers VendingFailure.http_status (502).
VENDING_FAILURE_HTTP_STATUS = {
    RESOURCE_MANAGER_CLIENT_UNAVAILABLE: 503,
    FIRESTORE_CLIENT_UNAVAILABLE: 503,
    PARENT_FOLDER_UNCONFIGURED: 503,
}
# Resource Manager v3 Project.state / v1 lifecycleState values of a project that is being deleted (exact enum values).
PENDING_DELETION_STATES = frozenset({"DELETE_REQUESTED", "DELETE_IN_PROGRESS"})


def _project_state(project: Any) -> Any:
    """The typed lifecycle field of a projects.get answer (v3 `state`, v1 `lifecycleState`), else None."""
    return (project.get("state") or project.get("lifecycleState")) if isinstance(project, dict) else None


def _labelled_for_product(project: Any, product_id: str) -> bool:
    """True when the project's typed `labels` say StackVend vended it for exactly this product (exact values)."""
    labels = project.get("labels") if isinstance(project, dict) else None
    return (isinstance(labels, dict) and labels.get(dg.LABEL_MANAGED) == "true"
            and isinstance(product_id, str) and bool(product_id) and labels.get(dg.LABEL_PRODUCT) == product_id)


def _labelled_product_of(project: Any) -> str:
    """The exact `stackvend-product-id` label value of a projects.get answer (a non-empty string), else ''."""
    labels = project.get("labels") if isinstance(project, dict) else None
    value = labels.get(dg.LABEL_PRODUCT) if isinstance(labels, dict) else None
    return value if isinstance(value, str) and value else ""


def _project_number_of(project: Any) -> str:
    """The number of a projects.get answer: exact v3 `name` (projects/<digits>), else a numeric v1 `projectNumber`."""
    if not isinstance(project, dict):
        return ""
    return dg._number_of(project) or dg._num(project.get("projectNumber"))


def _vend_target_id(doc_data: Any) -> Optional[str]:
    """The project id of the VENDING-TARGET-MARKER on a workload record snapshot (typed field), else None."""
    marker = doc_data.get(VEND_TARGET_MARKER) if isinstance(doc_data, dict) else None
    value = marker.get("project_id") if isinstance(marker, dict) else None
    return value if isinstance(value, str) and value else None


def _pending_deletion_detail(project_id: str, state: Any, record_status: Any) -> str:
    """RT SAT-38 L5: Redeploy runs only on a DECOMMISSIONED workload, so any other record is told to decommission
    first (by the record's typed `status`)."""
    new_project = ("Redeploy the workload (it creates a project under a new id)" if record_status == "DECOMMISSIONED"
                   else "decommission the workload, then Redeploy it (Redeploy runs only on a decommissioned workload "
                        "and creates a project under a new id)")
    return (f"Resource Manager reports project '{project_id}' as {state} (pending deletion). The vend stopped: StackVend "
            "neither recreates a project id (ids are never reusable) nor vends into a project that is being deleted. "
            f"If the deletion was a mistake, restore projects/{project_id} (undelete) within Google's 30-day window "
            f"and re-run the vend; otherwise the workload needs a new project: {new_project}.")

# VEND-API-TABLE (owner 10-27). Vending enables two exact API sets on a new child project, in one Service Usage call:
# * REQUIRED = base_apis + foundation_base_apis of the platform's API table (shared/api_requirements.json, replicated
#   byte-identical into this service's shared/): exactly the APIs the workload foundation enables in EVERY workload's
#   first apply (iap, pubsub, storage, run, firestore, ...). Enabling them here, before any deploy, removes the race
#   where the same apply creates the IAP agent / topics / buckets minutes after first enabling the API.
# * BEST_EFFORT = vending's own baseline list (unchanged; some rows serve only some workloads).
# Neither fails vending: the first apply still enables both sets itself (the terraform server's pre-apply batchEnable
# and the foundation's google_project_service), so a failure here is recorded on the workload as a typed result
# (`api_enablement`; VENDING.API_ENABLE_FAILED when a REQUIRED API failed, VENDING.API_TABLE_UNAVAILABLE when the
# table could not be read and only the baseline was requested) and logged, never raised.
VENDING_BASELINE_APIS = (
    "serviceusage.googleapis.com",
    "run.googleapis.com",
    "firestore.googleapis.com",
    "iam.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "cloudbuild.googleapis.com",
    "compute.googleapis.com",
    "secretmanager.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
    "identitytoolkit.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudquotas.googleapis.com",
    "cloudscheduler.googleapis.com",
    "eventarc.googleapis.com",
)
API_TABLE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shared", "api_requirements.json")
SERVICE_USAGE_BATCH_MAX = 20   # services:batchEnable accepts at most 20 service ids per call


def workload_deploy_apis(path: str = API_TABLE_PATH) -> Tuple[str, ...]:
    """The REQUIRED set: base_apis + foundation_base_apis of the platform API table, sorted (same rows the gateway's
    shared.api_requirements reads). Raises on a missing / malformed table; the caller records the typed result."""
    with open(path, encoding="utf-8") as fh:
        table = json.load(fh)
    rows = [table["base_apis"], table["foundation_base_apis"]]
    if not all(isinstance(r, list) and all(isinstance(a, str) and a.endswith(".googleapis.com") for a in r)
               for r in rows):
        raise ValueError(f"{path}: base_apis / foundation_base_apis must be lists of API service ids")
    return tuple(sorted(set(rows[0]) | set(rows[1])))
MAX_SANDBOX_TTL_DAYS = 90
MAX_SANDBOX_EXTENSIONS = 3
MAX_EXTENSION_DAYS = 30
# B1 (lane 18 S0 report): IAM member types accepted in STACKVEND_CHILD_PROJECT_OWNER_MEMBERS (exact prefixes).
CHILD_OWNER_MEMBER_TYPES = frozenset({"user", "serviceAccount", "group"})
CHILD_OWNER_GRANT_ATTEMPTS = 3
# Statuses retried by the B1 owner grant. 404 is included because getIamPolicy on a project created a moment
# ago can briefly answer 404 (CRM eventual consistency; lane 18 window RT H5).
CHILD_OWNER_GRANT_RETRY_STATUSES = frozenset({404, 409, 429, 500, 503})
LABEL_VALUE_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_-")

# ORG-POLICY-FOLDER (owner 10-28) supersedes the L10-t2 per-project set: the platform Terraform sets "no external VM
# IPs" (compute.vmExternalIpAccess = deny all) ONCE on the managed workloads folder
# (google_org_policy_policy.managed_folder_vm_external_ip, infra/platform/main.tf) and every child inherits it. No
# service account gets org-policy rights (roles/orgpolicy.policyAdmin is grantable only on the organization). Vending
# now only READS the child's effective policy (Org Policy API v2 getEffectivePolicy; needs orgpolicy.policy.get, which
# the vending identity holds through roles/resourcemanager.folderAdmin on the managed folder) and records the typed
# result on the workload (`org_policies`). It never fails the vend:
#   ENFORCED                                       deny all is in effect on the child;
#   NOT_ENFORCED  VENDING.ORG_POLICY_NOT_ENFORCED  it is not (no folder policy because the installer lacked
#                                                  Organization Policy Administrator; a child outside the managed
#                                                  folder; a project-level override): one WARNING per process + fix;
#   UNVERIFIED    VENDING.ORG_POLICY_API_DISABLED  the read got a 403 whose google.rpc.ErrorInfo says the Org Policy
#                                                  API is disabled for the caller's quota project (the host; FD-4DT
#                                                  row ORG-POLICY-API-DISABLED): one WARNING per process + the fix;
#   UNVERIFIED    VENDING.ORG_POLICY_CHECK_FAILED  any other failure (HTTP error, transport, unreadable body): ERROR.
# Errors are recognised from Google's structured error body only (exact field equality; no message text is read).
ORG_POLICY_SERVICE = "orgpolicy.googleapis.com"
ORG_POLICY_API_DISABLED = "VENDING.ORG_POLICY_API_DISABLED"
ORG_POLICY_NOT_ENFORCED = "VENDING.ORG_POLICY_NOT_ENFORCED"
ORG_POLICY_CHECK_FAILED = "VENDING.ORG_POLICY_CHECK_FAILED"
SERVICE_DISABLED_REASON = "SERVICE_DISABLED"
_ERROR_INFO_TYPE = "type.googleapis.com/google.rpc.ErrorInfo"
ORG_POLICY_API_DISABLED_FIX = (
    "Enable orgpolicy.googleapis.com on the StackVend host project {host}: the platform Terraform enables it, so an "
    "owner runs `PROJECT_ID={host} bash scripts/apply.sh apply`. The vending identity needs no org-policy role (it "
    "only reads the policy). Re-vend the workload to re-check.")
ORG_POLICY_NOT_ENFORCED_FIX = (
    "'No external VM IPs' (compute.vmExternalIpAccess = deny all) is not in effect on this project. StackVend sets it "
    "once on the managed workloads folder: an Organization Policy Administrator (roles/orgpolicy.policyAdmin on the "
    "organization) runs `PROJECT_ID={host} bash scripts/apply.sh apply` (without that role the installer skips the "
    "policy with a warning). A project outside the managed workloads folder, or with its own policy overriding the "
    "folder's, is not covered. Re-vend the workload to re-check.")
_org_policy_warn_lock = threading.Lock()
_org_policy_warned_codes: set = set()  # codes already logged at WARNING in this process (under the lock above)


def _google_error_info(resp: Any) -> Dict[str, Any]:
    """The google.rpc.ErrorInfo of a Google REST error body as {reason, service, consumer}, else {} (not JSON, no
    ErrorInfo detail). Reads only the structured fields of the documented error contract."""
    try:
        body = resp.json()
    except Exception:  # noqa: BLE001 - no JSON body: no structured error
        return {}
    err = body.get("error") if isinstance(body, dict) else None
    details = err.get("details") if isinstance(err, dict) else None
    for d in details if isinstance(details, list) else []:
        if isinstance(d, dict) and d.get("@type") == _ERROR_INFO_TYPE:
            meta = d.get("metadata") if isinstance(d.get("metadata"), dict) else {}
            return {"reason": d.get("reason"), "service": meta.get("service"), "consumer": meta.get("consumer")}
    return {}


def _deny_all_in_effect(policy: Any) -> bool:
    """True only for an effective Policy whose spec.rules is a non-empty list of rules that are each exactly
    `denyAll: true` with no condition (Org Policy API v2 Policy shape). Anything else (no spec, allowAll, values,
    a conditional rule, a non-object) is False: the guardrail is not proven to be in effect."""
    spec = policy.get("spec") if isinstance(policy, dict) else None
    rules = spec.get("rules") if isinstance(spec, dict) else None
    return (isinstance(rules, list) and bool(rules)
            and all(isinstance(r, dict) and r.get("denyAll") is True and "condition" not in r for r in rules))


def _warn_org_policy_once(code: str, msg: str) -> None:
    """One WARNING per process and code (the cause is the same on every vend until an owner acts); later vends log at
    DEBUG. Every vend still records the typed result on its workload."""
    with _org_policy_warn_lock:
        first = code not in _org_policy_warned_codes
        _org_policy_warned_codes.add(code)
    if first:
        logger.warning(msg + " (logged once per process; each vend records it in workloads/<id>.org_policies)")
    else:
        logger.debug(msg)


def _freeze_new_workloads_default(project_id: Optional[str]) -> bool:
    """FD-4CU: governance.freeze_new_workloads for a new workload record (strict read, <= 60 s settings cache). True
    unless the setting is exactly False; True (frozen) when the settings or the reader cannot be loaded. Never raises:
    vending never fails because of this read."""
    try:
        from shared.settings import freeze_new_workloads_enabled
    except Exception as e:  # noqa: BLE001
        logger.warning(f"governance.freeze_new_workloads reader unavailable ({type(e).__name__}: {e}); "
                       "the new workload starts frozen.")
        return True
    try:
        return freeze_new_workloads_enabled(project_id=project_id)
    except Exception as e:  # noqa: BLE001 - the reader never raises; belt and braces
        logger.warning(f"governance.freeze_new_workloads could not be read ({type(e).__name__}: {e}); "
                       "the new workload starts frozen.")
        return True


def _platform_default_budget_usd(project_id: Optional[str]) -> float:
    """FD-4CI-b: finops.default_monthly_budget_usd for a new workload record (strict read, <= 60 s settings cache);
    40.0 -- the budget vending gave every workload before -- when the settings or the reader cannot be loaded. Never
    raises: vending never fails because of this read."""
    try:
        from shared.settings import is_setting_number, strict_setting_value
    except Exception as e:  # noqa: BLE001
        logger.warning(f"finops.default_monthly_budget_usd reader unavailable ({type(e).__name__}: {e}); using 40.")
        return 40.0
    return float(strict_setting_value("finops", "default_monthly_budget_usd", 40.0, project_id=project_id,
                                      accept=lambda v: is_setting_number(v) and v > 0))


def _platform_default_branch(project_id: Optional[str]) -> str:
    """FD-4CI-b-R1: orchestration.default_branch for a workload whose repository vending creates now and whose record
    names no branch (strict read, <= 60 s settings cache); "main" -- the branch vending used before -- when the settings
    or the reader cannot be loaded or the value is not a plain branch name. Never raises."""
    try:
        from shared.settings import default_branch_setting
    except Exception as e:  # noqa: BLE001
        logger.warning(f"orchestration.default_branch reader unavailable ({type(e).__name__}: {e}); using main.")
        return "main"
    try:
        return default_branch_setting(project_id=project_id)
    except Exception as e:  # noqa: BLE001 - the reader never raises; belt and braces
        logger.warning(f"orchestration.default_branch could not be read ({type(e).__name__}: {e}); using main.")
        return "main"


def _apply_initial_branch(repo: Any, initial_branch: str) -> None:
    """FD-4CI-b-R1, direct-creation fallback: the GitHub provider's apply_initial_branch for a repository this module
    just created. Unavailable provider module: logged, the repository keeps GitHub's default branch."""
    try:
        from shared.providers.github_provider import apply_initial_branch
    except Exception as e:  # noqa: BLE001
        logger.error(f"DEFAULT_BRANCH_NOT_APPLIED: GitHub provider unavailable ({type(e).__name__}: {e}); "
                     f"'{getattr(repo, 'full_name', '')}' keeps GitHub's default branch.")
        return
    apply_initial_branch(repo, initial_branch)


def _is_label_value(value: str) -> bool:
    """GCP label value grammar: <= 63 chars of lowercase letters, digits, '_' and '-'."""
    return isinstance(value, str) and 0 < len(value) <= 63 and all(c in LABEL_VALUE_CHARS for c in value)


# Vending stage summary: the repository's provider is named from the vended result's typed `vcs_provider` (the
# VCSRepositoryMeta.provider the provider returned), exact match only. Only the GitHub-only paths (reusing an
# existing GitHub repository, direct GitHub creation) return no `vcs_provider`.
_REPOSITORY_LABELS = {"GITHUB": "GitHub repository", "SERVERLESS_GIT": "Serverless Git repository"}


def _vended_repository_label(repo_res: Dict[str, Any]) -> str:
    provider = repo_res.get("vcs_provider") if isinstance(repo_res, dict) else None
    if provider is None:
        return _REPOSITORY_LABELS["GITHUB"]
    return _REPOSITORY_LABELS.get(str(provider).strip().upper(), "repository")


# FD vending-redeploy: typed outcomes of the terraform /deploy call in redeploy_workload (classified by HTTP status
# and exception type only, never by message text). Only an HTTP 200 makes the workload ACTIVE.
REDEPLOY_TERRAFORM_UNCONFIGURED = "REDEPLOY_TERRAFORM_UNCONFIGURED"  # no terraform service URL: nothing deployed
REDEPLOY_DEPLOY_FAILED = "REDEPLOY_DEPLOY_FAILED"                    # /deploy answered with a non-200 status
REDEPLOY_DEPLOY_CALL_FAILED = "REDEPLOY_DEPLOY_CALL_FAILED"          # the call itself failed (no answer)
REDEPLOY_OUTCOME_UNKNOWN = "REDEPLOY_OUTCOME_UNKNOWN"                # timed out (ours or HTTP 504): apply may go on
# VENDING-CLIENT-FAIL-LOUD gap 4: the vend step raised an exception that is not a VendingFailure (a VendingFailure is
# recorded with its own error_class). Recorded on the workload (FAILED, never left REDEPLOYING); the error is re-raised.
REDEPLOY_VEND_FAILED = "REDEPLOY_VEND_FAILED"
# FD-4AI (owner 10-26, D9): a billing account is configured but could not be linked to the child project (the Cloud
# Billing updateBillingInfo call failed after its retries, or no Cloud Billing client could be built). Vending fails
# with this class instead of reporting the project vended: an unbilled project can enable no API and run nothing.
# Classified by where the failure happens, never by message text.
BILLING_NOT_LINKED = "BILLING_NOT_LINKED"
# GITHUB-REPO-CREATE-FAIL-LOUD: fallback class for a typed repository failure without its own error_class.
REPOSITORY_VEND_FAILED = "REPOSITORY_VEND_FAILED"


class VendingFailure(RuntimeError):
    """A typed vending failure. The async route puts `error_class` on the callback outcome (the workflow's
    handle_vending_failure lifts it into the dead-letter record); the sync routes answer `http_status` with
    {"error_class", "stage", "detail"}."""

    http_status = 502

    def __init__(self, error_class: str, detail: str, stage: str = "vending"):
        super().__init__(f"{error_class}: {detail}")
        self.error_class = error_class
        self.detail = detail
        self.stage = stage   # GITHUB-REPO-CREATE-FAIL-LOUD: the failing step ("vending" unless a typed step names it)
        # RT 11-07 F4: configuration / dependency-unavailable classes answer 503 (as REDEPLOY_TERRAFORM_UNCONFIGURED
        # does); every other class keeps 502.
        self.http_status = VENDING_FAILURE_HTTP_STATUS.get(error_class, VendingFailure.http_status)


GHA_SECRETS_NOT_WRITTEN = "VENDING.GHA_SECRETS_NOT_WRITTEN"


class GitHubSecretsNotWritten(VendingFailure):
    """RT14-18 (owner 11-14): the GitHub Actions deploy secrets were not all written to the repository with any token
    (typically HTTP 403: the GitHub App lacks the Secrets permission). Carries each token attempt's failed secrets and
    GitHub statuses, never a secret value or a token."""

    def __init__(self, repo: str, secret_names: List[str], attempts: List[Dict[str, Any]]):
        detail = (f"the GitHub Actions deploy secrets {secret_names} were not all written to '{repo}' "
                  f"({'no GitHub token available' if not attempts else attempts}); give the GitHub App the "
                  f"repository permission 'Secrets: Read and write', then redeploy")
        super().__init__(GHA_SECRETS_NOT_WRITTEN, detail, stage="github_actions_secrets")
        self.repo = repo
        self.attempts = attempts

    def body(self) -> Dict[str, Any]:
        return {"error_class": self.error_class, "stage": self.stage, "repo": self.repo, "attempts": self.attempts,
                "detail": self.detail}


# HTTP status the vending /redeploy route answers with for each failure class.
REDEPLOY_FAILURE_HTTP_STATUS = {
    REDEPLOY_TERRAFORM_UNCONFIGURED: 503,
    REDEPLOY_DEPLOY_FAILED: 502,
    REDEPLOY_DEPLOY_CALL_FAILED: 502,
    REDEPLOY_OUTCOME_UNKNOWN: 504,
}
# The vending and terraform Cloud Run services both cut a request at 1800 s (infra/platform/main.tf). The /deploy
# wait gets what is left of that budget after vending the project, minus a margin to record the outcome, so the
# final status is always written before this request is cut (it used to wait 180 s, far less than an apply takes).
REDEPLOY_REQUEST_BUDGET_S = 1800.0
REDEPLOY_RECORD_MARGIN_S = 60.0
REDEPLOY_MIN_DEPLOY_WAIT_S = 30.0
REDEPLOY_CONNECT_TIMEOUT_S = 10.0


_CACHED_TERRAFORM_SERVICE_URL: Optional[str] = None


def _discover_cloud_run_service_url(service: str, project_id: str) -> Optional[str]:
    """Cloud Run Admin API lookup of a peer service in THIS project and THIS instance's region (metadata server),
    the same pattern as the Control Center's routes/settings.py. No region default (Invariant 3); any failure ->
    None. Only on Cloud Run (K_SERVICE set)."""
    proj_id = (project_id or os.getenv("PROJECT_ID") or "").strip()
    if not proj_id or not os.getenv("K_SERVICE"):
        return None
    try:
        import requests as _requests
        from google.auth.transport.requests import AuthorizedSession

        region_path = _requests.get(
            "http://metadata.google.internal/computeMetadata/v1/instance/region",
            headers={"Metadata-Flavor": "Google"}, timeout=2,
        ).text.strip()
        region = region_path.rsplit("/", 1)[-1]
        if not region:
            return None
        credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        resp = AuthorizedSession(credentials).get(
            f"https://run.googleapis.com/v2/projects/{proj_id}/locations/{region}/services/{service}", timeout=5.0)
        if resp.status_code == 200:
            uri = (resp.json() or {}).get("uri")
            if isinstance(uri, str) and uri.startswith("https://"):
                return uri.rstrip("/")
    except Exception as api_err:  # noqa: BLE001
        logger.warning(f"Cloud Run Admin API discovery of '{service}' failed ({type(api_err).__name__})")
    return None


def resolve_terraform_service_url(project_id: str) -> Optional[str]:
    """The terraform service vending deploys through, resolved by vending itself (never taken from a caller):
    TERRAFORM_SERVICE_URL / TERRAFORM_MCP_URL, else the Cloud Run lookup of mcp-terraform-server (cached)."""
    global _CACHED_TERRAFORM_SERVICE_URL
    env_url = os.getenv("TERRAFORM_SERVICE_URL") or os.getenv("TERRAFORM_MCP_URL")
    if env_url and env_url.strip():
        return env_url.strip().rstrip("/")
    if _CACHED_TERRAFORM_SERVICE_URL:
        return _CACHED_TERRAFORM_SERVICE_URL
    found = _discover_cloud_run_service_url("mcp-terraform-server", project_id)
    if found:
        _CACHED_TERRAFORM_SERVICE_URL = found
    return found


def _fetch_id_token(audience: str) -> Optional[str]:
    """RT R4: a Google ID token for `audience` (the terraform service URL; mcp-terraform-server is not public).
    None when no token can be minted (e.g. local runs): the call then goes out unauthenticated."""
    try:
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token

        return id_token.fetch_id_token(google_requests.Request(), audience)
    except Exception as e:
        logger.warning(f"Could not mint an ID token for the terraform service ({type(e).__name__})")
        return None


def _deploy_error_text(res: Any) -> str:
    """The terraform /deploy failure text for the record (its string `detail` stays a string; never classified)."""
    try:
        body = res.json()
    except Exception:
        body = None
    detail = body.get("detail") if isinstance(body, dict) else None
    if detail is None:
        detail = getattr(res, "text", "") or ""
    text = detail if isinstance(detail, str) else json.dumps(detail, default=str)
    return f"HTTP {res.status_code}: {text[:2000]}"


class ProjectRepoVendingEngine:
    def __init__(
        self,
        platform_project_id: Optional[str] = None,
        firestore_client: Optional[Any] = None,
        secret_client: Optional[Any] = None,
        crm_service: Optional[Any] = None,
        billing_service: Optional[Any] = None,
        storage_client: Optional[Any] = None,
        github_owner: Optional[str] = None,
        guard_context: Optional[Any] = None,
        guard_db: Optional[Any] = None,
        iam_client: Optional[Any] = None,
        runner_deps: Optional[Any] = None,
    ):
        self.platform_project_id = platform_project_id or os.getenv("PROJECT_ID", "")
        self.folder_id = (
            os.getenv("MANAGED_WORKLOADS_FOLDER_ID")
            or os.getenv("CASTOR_MANAGED_WORKLOADS_FOLDER_ID")
            or os.getenv("FOLDER_ID")
            or ""
        )
        self.billing_account_id = (
            os.getenv("BILLING_ACCOUNT_ID")
            or os.getenv("BILLING_ACCOUNT")
            or ""
        )
        self.github_owner = (
            github_owner
            or os.getenv("GITHUB_OWNER")
            or os.getenv("GITHUB_ORG")
            or get_default_github_owner()
        )
        self.devops_sa_email = os.getenv(
            "DEVOPS_SA_EMAIL",
            f"sa-castor-gcp-devops@{self.platform_project_id}.iam.gserviceaccount.com" if self.platform_project_id else "",
        )
        self.tfstate_bucket = os.getenv("TFSTATE_BUCKET") or f"castor-tfstate-{self.platform_project_id}"
        self._db = firestore_client
        self._secret_client = secret_client
        self._crm = crm_service
        self._billing = billing_service
        self._storage = storage_client
        self._guard_context = guard_context
        self._guard_db = guard_db
        self._iam_client = iam_client
        self._runner_deps = runner_deps
        # VENDING-CLIENT-FAIL-LOUD: the class name of the last failed client build (read by _require_crm/_require_db)
        self._crm_build_error: Optional[str] = None
        self._db_build_error: Optional[str] = None
        self.owner_grant_retry_delay = 2.0

    @property
    def iam_client(self):
        """REST (AuthorizedSession) Resource Manager client for the child-owner grant (B1). Injectable in tests."""
        if self._iam_client is None:
            self._iam_client = dg.RestCRM()
        return self._iam_client

    @property
    def guard_db(self):
        """Named Firestore DB for provenance/approvals once S0b sets STACKVEND_GUARD_FIRESTORE_DATABASE; else the
        default DB (plan 2.5 trust statement: anti-accident until S0b)."""
        if self._guard_db is None:
            name = (os.getenv("STACKVEND_GUARD_FIRESTORE_DATABASE") or "").strip()
            if name and self.platform_project_id:
                try:
                    self._guard_db = firestore.Client(project=self.platform_project_id, database=name)
                except Exception as e:
                    logger.error(f"Could not initialize guard Firestore database '{name}': {e}")
                    return None
            else:
                return self.db
        return self._guard_db

    def guard_context(self) -> "dg.GuardContext":
        if self._guard_context is not None:
            return self._guard_context
        guard_db = self.guard_db
        if guard_db is None and (os.getenv("STACKVEND_GUARD_FIRESTORE_DATABASE") or "").strip():
            guard_db = dg.UnavailableDB("guard Firestore database configured but unavailable")
        store = dg.FirestoreGuardStore(self.db, guard_db)
        return dg.GuardContext.from_env(store=store, crm=dg.RestCRM())

    @property
    def runner_deps(self) -> "rb.RunnerDeps":
        """FD-7L: what the runner-identity provisioner and broker use (built on first use; never on a PLATFORM-mode
        vend). Injectable in tests."""
        if self._runner_deps is None:
            guard_db = self.guard_db
            if guard_db is None and (os.getenv("STACKVEND_GUARD_FIRESTORE_DATABASE") or "").strip():
                guard_db = dg.UnavailableDB("guard Firestore database configured but unavailable")
            rest = rb.GoogleRest()
            self._runner_deps = rb.RunnerDeps(
                config=rb.BrokerConfig.from_env(), rest=rest, project_iam=self.iam_client,
                store=rb.RunnerStore(self.db, guard_db), certs=ri.X509CertFetcher(),
                runtime_email=rb.metadata_runtime_email, region=rb.metadata_region,
                guard_context=self.guard_context, signer_factory=lambda email: rb.IamSigner(rest, email),
                github_repo_token=self.mint_repository_read_token,
                mode=self.operative_runner_identity_mode)   # FD-7L-F4: read live, never cached in the deps
        return self._runner_deps

    def mode_guard_db(self):
        """FD-7L-F4: the guard database client the operative-mode read uses (None = ri's own default client). A
        configured guard database that cannot be opened is never replaced by the default one (fail closed)."""
        if not (os.getenv(ri.GUARD_DB_ENV) or "").strip():
            return None
        return self.guard_db or dg.UnavailableDB("guard Firestore database configured but unavailable")

    MODE_RESIGN_CHECK_SECONDS = 3600.0

    def operative_runner_identity_mode(self) -> str:
        """FD-7L-n / FD-7L-F4: the operative mode through the one shared reader (declaration, then the signed
        Settings record). Raises RunnerIdentityError (typed, 503 for a record that cannot be read or verified)."""
        mode = ri.runner_identity_mode(guard_db=self.mode_guard_db())
        if ri.declared_mode() != ri.MODE_PER_WORKLOAD and (os.getenv(ri.GUARD_DB_ENV) or "").strip():
            self._resign_mode_record_hourly()   # any record (RT H1: Shared is a signed record too once switched)
        return mode

    def _resign_mode_record_hourly(self) -> None:
        """At most once an hour per instance, re-sign the mode record (either mode) older than 72 h (SAT-19 RT F1: keys
        rotate). Maintenance only (fail-loudly policy 2): the read above already succeeded or failed on its own; a
        failure here is logged and retried at the next check, by the Settings view and by /runner-identity/resign."""
        now = time.monotonic()
        last = getattr(self, "_mode_resign_checked_at", None)
        if last is not None and now - last < self.MODE_RESIGN_CHECK_SECONDS:
            return
        self._mode_resign_checked_at = now
        try:
            outcome = self.runner_identity_mode_setting().resign_if_stale()
            if outcome == "RESIGNED":
                logger.info("runner identity mode record re-signed")
        except Exception as e:  # noqa: BLE001
            logger.warning(f"RUNNER_MODE_RESIGN_FAILED: the mode record was not re-signed ({type(e).__name__}: "
                           f"{getattr(e, 'code', '')}); the Settings card and /runner-identity/resign retry it")

    def runner_identity_mode(self) -> str:
        """The operative mode for a vend: an unknown declaration fails it (VENDING.RUNNER_IDENTITY_MODE_INVALID), a
        Settings record that cannot be read or verified fails it (VENDING.RUNNER_IDENTITY_MODE_UNREADABLE, the
        reader's class in the detail), before anything is created."""
        try:
            return self.operative_runner_identity_mode()
        except ri.RunnerIdentityError as e:
            if e.code == "RUNNER_IDENTITY_MODE_INVALID":
                raise VendingFailure("VENDING.RUNNER_IDENTITY_MODE_INVALID", e.detail) from None
            raise VendingFailure("VENDING.RUNNER_IDENTITY_MODE_UNREADABLE", f"{e.code}: {e.detail}") from None

    def _runner_identity_region(self, workload: Dict[str, Any]) -> Optional[str]:
        """The region of the workload's state bucket: the workload record's `region` when set (FD-7M-a), else the
        platform's orchestration.default_gcp_region (strict read). None when neither is known (typed failure)."""
        region = workload.get("region") if isinstance(workload, dict) else None
        if isinstance(region, str) and region.strip():
            return region.strip()
        try:
            from shared.settings import strict_setting_value
            value = strict_setting_value("orchestration", "default_gcp_region", None,
                                         accept=lambda v: isinstance(v, str) and bool(v.strip()),
                                         project_id=self.platform_project_id)
        except Exception as e:  # noqa: BLE001
            logger.error(f"Workload region unavailable for the state bucket ({type(e).__name__})")
            return None
        return value.strip() if isinstance(value, str) and value.strip() else None

    def _record_runner_identity_failure(self, product_id: str, err: "ri.RunnerIdentityError") -> None:
        if not self.db:
            return
        try:
            self.db.collection("workloads").document(product_id).set({
                "runner_identity_status": ri.STATUS_FAILED,
                "vending_error_class": err.code,
                "failure_reason": str(err),
            }, merge=True)
        except Exception as rec_err:  # noqa: BLE001
            logger.error(f"Could not record {err.code} on workloads/{product_id}: {rec_err}")

    def _ensure_runner_identity(self, product_id: str, project_id: str, project_number: str,
                                workload: Dict[str, Any]) -> Dict[str, Any]:
        """FD-7L Phase 1, PER_WORKLOAD only: the vend-order ensure_* steps (runner_broker.RunnerIdentityProvisioner)
        after billing, API enablement and the 3c grants. A failure leaves a billed project without a deployer, records
        the class on the workload and fails the vend (the backfill or a re-vend resumes it)."""
        provisioner = rb.RunnerIdentityProvisioner(self.runner_deps)
        try:
            record = provisioner.ensure(product_id=product_id, project_id=project_id, project_number=project_number,
                                        region=self._runner_identity_region(workload))
        except ri.RunnerIdentityError as e:
            self._record_runner_identity_failure(product_id, e)
            raise VendingFailure(e.code, e.detail) from None
        if self.db:
            try:
                self.db.collection("workloads").document(product_id).set(
                    {"runner_identity_status": record["status"]}, merge=True)   # display copy only (plan 2.1)
            except Exception as rec_err:  # noqa: BLE001
                logger.warning(f"Could not write the runner identity display status of {product_id}: {rec_err}")
        return {"status": record["status"], "deployer_email": record["deployer_email"],
                "state_bucket": record["state_bucket"]}

    def _pin_runner_repository(self, product_id: str, provider: str, full_name: str,
                               repository_id: Optional[str]) -> None:
        """FD-7L Phase 1, PER_WORKLOAD only: pin the workload's repository in its signed runner identity record (the
        runner's read-only repository token is minted for exactly this repository)."""
        repository = {"provider": provider, "full_name": full_name,
                      "id": str(repository_id) if repository_id is not None else None}
        try:
            rb.RunnerIdentityProvisioner(self.runner_deps).pin_repository(product_id, repository)
        except ri.RunnerIdentityError as e:
            self._record_runner_identity_failure(product_id, e)
            raise VendingFailure(e.code, e.detail) from None

    def runner_identity_mode_setting(self) -> "rim.RunnerIdentityModeSetting":
        """FD-7L-F4: the operative-mode record (Settings view and the signed write), on the NAMED guard database
        only."""
        return rim.RunnerIdentityModeSetting(self.runner_deps, guard_db=self.mode_guard_db())

    def runner_identity_backfill(self) -> "rib.RunnerIdentityBackfill":
        """FD-7L Phase 3: status / backfill / migration of the per-workload runner identity
        (runner_identity_backfill.py). The state bucket's region is the workload record's (FD-7M-a), else the platform
        default (strict read); unknown -> the provisioner's typed bucket failure."""
        def _region_for(pid: str) -> Optional[str]:
            workload: Dict[str, Any] = {}
            if self.db:
                try:
                    snap = self.db.collection("workloads").document(pid).get()
                    workload = (snap.to_dict() or {}) if getattr(snap, "exists", False) else {}
                except Exception as e:  # noqa: BLE001 - region unknown -> typed BACKFILL.BUCKET_FAILED
                    logger.error(f"Workload record of {pid} unreadable for the state bucket region "
                                 f"({type(e).__name__})")
                    return None
            return self._runner_identity_region(workload)

        return rib.RunnerIdentityBackfill(self.runner_deps, platform_bucket=self.tfstate_bucket,
                                          region_for=_region_for)

    def _decommission_state_plan(self, pid: str, verdict: Any, ctx: Any,
                                 delete_without_archive: bool) -> Optional[Dict[str, Any]]:
        """FD-7L Phase 3 (plan 2.8), Per-workload installs only: where the workload's state lives and whether the
        approval allows a delete without archive. None = the legacy path (state in the platform bucket: today's
        copy-then-delete after the project delete). Read-only; raises DeletionRefused before anything is changed."""
        skip_ok = False
        if delete_without_archive:
            approval = dg.read_approval(ctx, verdict.approval_id)
            if not approval or approval.get("delete_without_archive") is not True:
                raise dg.DeletionRefused("DELETE_WITHOUT_ARCHIVE_NOT_APPROVED",
                                         "delete without archive needs an approval minted with that option", 409)
            skip_ok = True
        try:
            prov = ctx.store.get_provenance(pid)
        except Exception as e:  # noqa: BLE001
            raise dg.DeletionRefused("LEDGER_UNAVAILABLE", f"provenance unreadable ({type(e).__name__})", 503)
        try:
            loc = rib.runner_state_location(self.runner_deps, pid, prov, self.tfstate_bucket)
        except ri.RunnerIdentityError as e:
            if skip_ok:
                return {"source": "unverified", "skip_ok": True, "error": f"{e.code}: {e.detail}",
                        "migration": None}
            raise dg.DeletionRefused("DECOMMISSION_STATE_ARCHIVE_FAILED",
                                     f"the state location cannot be trusted ({e.code}: {e.detail})", 409)
        if loc["source"] != "provenance":
            return None
        return dict(loc, skip_ok=skip_ok)

    def _archive_runner_state(self, pid: str, plan: Dict[str, Any]) -> Dict[str, Any]:
        """Copies the child's live state into the platform archive path BEFORE the project delete. A failed copy stops
        the decommission (rib.StateArchiveFailed) unless the approval said "delete without archive" (Q4)."""
        archive_name = f"workloads/{pid}/state_history/decommission_{int(time.time())}.tfstate"
        if plan.get("source") != "provenance":
            return {"archived": False, "archive_path": None,
                    "warning": f"STATE_ARCHIVE_SKIPPED_BY_APPROVAL: {plan.get('error')}"}
        try:
            res = rib.archive_child_state(self.runner_deps, pid, plan["bucket"], self.tfstate_bucket, archive_name)
        except rib.StateArchiveFailed as e:
            if plan.get("skip_ok"):
                return {"archived": False, "archive_path": None,
                        "warning": f"STATE_ARCHIVE_SKIPPED_BY_APPROVAL: {e.detail}"}
            raise
        if res is None:
            return {"archived": False, "archive_path": None, "warning": None}
        logger.info(f"Archived the state of '{pid}' from gs://{plan['bucket']} to '{archive_name}' before the delete")
        return {"archived": True, "archive_path": archive_name, "warning": None}

    @property
    def storage(self):
        if self._storage is None and self.platform_project_id:
            try:
                from google.cloud import storage
                self._storage = storage.Client(project=self.platform_project_id)
            except Exception as e:
                logger.warning(f"Could not initialize Storage client: {e}")
        return self._storage

    @property
    def db(self):
        if self._db is None and self.platform_project_id:
            try:
                self._db = firestore.Client(project=self.platform_project_id)
            except Exception as e:
                self._db_build_error = type(e).__name__
                logger.warning(f"Could not initialize Firestore client: {e}")
        return self._db

    def _require_db(self, step: str):
        """VENDING-CLIENT-FAIL-LOUD (gap 1): the Firestore client for a step that cannot be skipped (`step` names it).
        No client (no platform project configured, or the build raised) -> VendingFailure(FIRESTORE_CLIENT_UNAVAILABLE)
        naming the step and the build error's class (never its message), before the step does anything."""
        db = self.db
        if db:
            return db
        cause = getattr(self, "_db_build_error", None) or ("" if self.platform_project_id
                                                          else "no platform project configured")
        raise VendingFailure(
            FIRESTORE_CLIENT_UNAVAILABLE,
            f"No Firestore client could be created{f' ({cause})' if cause else ''}, so {step} could not run. Nothing "
            "was created. Fix the vending service's PROJECT_ID / credentials, then re-run.",
        )

    @property
    def secret_client(self):
        if self._secret_client is None:
            try:
                self._secret_client = secretmanager.SecretManagerServiceClient()
            except Exception as e:
                logger.warning(f"Could not initialize Secret Manager client: {e}")
        return self._secret_client

    @property
    def crm(self):
        if self._crm is None:
            try:
                self._crm = _build_thread_safe("cloudresourcemanager", "v3")   # SAT-51
            except Exception as e:
                self._crm_build_error = type(e).__name__
                logger.warning(f"Could not initialize Cloud Resource Manager client: {e}")
        return self._crm

    def _require_crm(self, step: str):
        """VENDING-CLIENT-FAIL-LOUD: the Resource Manager client for a step that cannot be skipped (`step` names it
        in the detail). No client -> VendingFailure(RESOURCE_MANAGER_CLIENT_UNAVAILABLE) naming the step and the build
        error's class (never its message), before the step does anything."""
        crm = self.crm
        if crm:
            return crm
        cause = getattr(self, "_crm_build_error", None)
        raise VendingFailure(
            RESOURCE_MANAGER_CLIENT_UNAVAILABLE,
            f"No Cloud Resource Manager API client could be created{f' ({cause})' if cause else ''}, so {step} could "
            "not run. Nothing was created. Fix the vending service identity's credentials, then re-run.",
        )

    @property
    def billing(self):
        if self._billing is None:
            try:
                self._billing = _build_thread_safe("cloudbilling", "v1")   # SAT-51
            except Exception as e:
                logger.warning(f"Could not initialize Cloud Billing client: {e}")
        return self._billing

    # Child-project org policies vending CHECKS (lane 10 L10-t2; since ORG-POLICY-FOLDER they are set once on the
    # managed workloads folder by the platform Terraform and inherited). Exact constraint names.
    CHILD_ORG_POLICY_DENY_ALL = ("compute.vmExternalIpAccess",)
    ORG_POLICY_API = "https://orgpolicy.googleapis.com/v2"

    def _org_policy_session(self):
        if getattr(self, "_org_session", None) is None:
            from google.auth.transport.requests import AuthorizedSession
            credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            self._org_session = AuthorizedSession(credentials)
        return self._org_session

    def check_child_org_policies(self, target_project_id: str, session: Optional[Any] = None) -> List[Dict[str, Any]]:
        """Read each CHILD_ORG_POLICY_DENY_ALL constraint's EFFECTIVE policy on the child project (Org Policy API v2
        `GET projects/<child>/policies/<constraint>:getEffectivePolicy`; read-only) and return one typed result per
        constraint: {constraint, status ENFORCED | NOT_ENFORCED | UNVERIFIED, code, http_status, error, check} plus
        `fix` (and `consumer` for a disabled API) when it is not ENFORCED. Never sets a policy, never addresses the host
        project, never raises: the caller records the result on the workload and the vend carries on."""
        results: List[Dict[str, Any]] = []
        host = self.platform_project_id or "<host project>"
        if not target_project_id or target_project_id == self.platform_project_id:
            return [{"constraint": c, "status": "UNVERIFIED", "code": ORG_POLICY_CHECK_FAILED, "http_status": None,
                     "error": "no child project id (or the platform project) given", "check": "effective_policy"}
                    for c in self.CHILD_ORG_POLICY_DENY_ALL]
        for constraint in self.CHILD_ORG_POLICY_DENY_ALL:
            base = {"constraint": constraint, "check": "effective_policy"}
            try:
                sess = session or self._org_policy_session()
                resp = sess.get(f"{self.ORG_POLICY_API}/projects/{target_project_id}/policies/{constraint}"
                                ":getEffectivePolicy", timeout=30)
                if 200 <= resp.status_code < 300:
                    try:
                        policy = resp.json()
                    except Exception as e:  # noqa: BLE001 - typed: the effective policy could not be read
                        results.append({**base, "status": "UNVERIFIED", "code": ORG_POLICY_CHECK_FAILED,
                                        "http_status": resp.status_code,
                                        "error": f"unreadable effective policy: {type(e).__name__}"})
                        continue
                    if _deny_all_in_effect(policy):
                        results.append({**base, "status": "ENFORCED", "code": None, "http_status": resp.status_code,
                                        "error": None})
                    else:
                        results.append({**base, "status": "NOT_ENFORCED", "code": ORG_POLICY_NOT_ENFORCED,
                                        "http_status": resp.status_code, "error": None,
                                        "fix": ORG_POLICY_NOT_ENFORCED_FIX.format(host=host)})
                    continue
                failed = {**base, "status": "UNVERIFIED", "code": ORG_POLICY_CHECK_FAILED,
                          "http_status": resp.status_code, "error": (resp.text or "")[:500]}
                info = _google_error_info(resp)
                if info.get("reason") == SERVICE_DISABLED_REASON and info.get("service") == ORG_POLICY_SERVICE:
                    failed.update(code=ORG_POLICY_API_DISABLED, consumer=info.get("consumer"),
                                  fix=ORG_POLICY_API_DISABLED_FIX.format(host=host))
                results.append(failed)
            except Exception as e:  # noqa: BLE001 - recorded as a typed failure, never swallowed silently
                results.append({**base, "status": "UNVERIFIED", "code": ORG_POLICY_CHECK_FAILED, "http_status": None,
                                "error": f"{type(e).__name__}: {e}"[:500]})
        for r in results:
            if r["status"] == "ENFORCED":
                continue
            if r["code"] == ORG_POLICY_NOT_ENFORCED:
                _warn_org_policy_once(r["code"], f"{r['code']}: {r['constraint']} deny-all is not in effect on "
                                                 f"'{target_project_id}'. {r['fix']}")
            elif r["code"] == ORG_POLICY_API_DISABLED:
                consumer = r.get("consumer")
                _warn_org_policy_once(r["code"], f"{r['code']}: could not check {r['constraint']} on "
                                                 f"'{target_project_id}': {ORG_POLICY_SERVICE} is not enabled"
                                                 f"{f' on {consumer}' if consumer else ''}. {r['fix']}")
            else:
                logger.error(f"{r['code']}: could not check {r['constraint']} on '{target_project_id}' "
                             f"(HTTP {r['http_status']}): {r['error']}")
        return results

    def enable_child_apis(self, target_project_id: str, serviceusage: Optional[Any] = None) -> Dict[str, Any]:
        """VEND-API-TABLE: enable REQUIRED (workload_deploy_apis) + BEST_EFFORT (VENDING_BASELINE_APIS) on the child
        project with Service Usage batchEnable (one call per SERVICE_USAGE_BATCH_MAX ids; today one call), polled up
        to 60 s, falling back to per-API enable when a batch call raises (the pre-VEND-API-TABLE algorithm) or its
        operation finishes with an error (batchEnable is atomic: one refused id fails the batch, so each id is then
        enabled on its own and only the refused ones are recorded). Returns the typed record
        {required, best_effort, requested, status ENABLED | PENDING | FAILED, failed, code, error}; never raises."""
        best_effort = list(VENDING_BASELINE_APIS)
        result: Dict[str, Any] = {"required": [], "best_effort": best_effort, "requested": [], "status": "FAILED",
                                  "failed": [], "code": None, "error": None}
        try:
            required = list(workload_deploy_apis())
        except Exception as e:  # noqa: BLE001 - typed: only the baseline is requested
            required = []
            result["code"] = "VENDING.API_TABLE_UNAVAILABLE"
            result["error"] = f"{type(e).__name__}: {e}"[:500]
        apis = best_effort + [a for a in required if a not in best_effort]
        result["required"], result["requested"] = required, list(apis)
        failed: List[str] = []
        pending = False
        try:
            if serviceusage is None:
                from googleapiclient.discovery import build
                credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
                serviceusage = build("serviceusage", "v1", credentials=credentials, cache_discovery=False)
            try:
                for k in range(0, len(apis), SERVICE_USAGE_BATCH_MAX):
                    batch = apis[k:k + SERVICE_USAGE_BATCH_MAX]
                    op = serviceusage.services().batchEnable(
                        parent=f"projects/{target_project_id}",
                        body={"serviceIds": batch}
                    ).execute()
                    op_name = op.get("name") if isinstance(op, dict) else None
                    done, op_error = not op_name, None
                    if op_name:
                        logger.info(f"Initiated batch API enablement for {len(batch)} child APIs: {op_name}")
                        poll_start = time.time()
                        while time.time() - poll_start < 60.0:
                            # VENDING-POLL-TRANSIENT: a transient poll error is polled again (it used to be swallowed
                            # with every other error); a non-transient one raises into the per-API fallback below.
                            answered, op_status = _poll_operation_once(
                                lambda: serviceusage.operations().get(name=op_name).execute(),
                                f"Service Usage operation '{op_name}'",
                            )
                            if answered and isinstance(op_status, dict) and op_status.get("done"):
                                done = True
                                if op_status.get("error"):
                                    op_error = json.dumps(op_status.get("error"))[:500]
                                    result["error"] = op_error
                                else:
                                    logger.info(f"Batch API enablement completed successfully on '{target_project_id}'.")
                                break
                            time.sleep(2.0)
                        if op_error:
                            # atomic batch failed (e.g. one id refused): enable each id on its own, so one refused
                            # REQUIRED id never takes the baseline down with it
                            raise RuntimeError(f"batchEnable operation failed: {op_error}")
                    pending = pending or not done
                logger.info(f"Enabled essential GCP APIs on '{target_project_id}'")
            except Exception as batch_err:
                logger.warning(f"Batch API enablement notice ({batch_err}); falling back to sequential enablement...")
                failed, pending = [], False
                for api_name in apis:
                    def _enable_api(name=api_name):
                        return serviceusage.services().enable(
                            name=f"projects/{target_project_id}/services/{name}"
                        ).execute()

                    try:
                        self._retry_api_call(
                            _enable_api,
                            max_attempts=2,
                            delay=1.5,
                            description=f"enable API {api_name} on {target_project_id}",
                        )
                    except Exception:
                        failed.append(api_name)
                logger.info(f"Enabled essential GCP APIs on '{target_project_id}' (sequential fallback)")
        except Exception as api_err:
            logger.warning(f"Could not enable APIs via Service Usage: {api_err}")
            failed = list(apis)
            result["error"] = f"{type(api_err).__name__}: {api_err}"[:500]
        result["failed"] = sorted(set(failed))
        result["status"] = "FAILED" if failed else ("PENDING" if pending else "ENABLED")
        failed_required = sorted(set(failed) & set(required))
        if failed_required and result["code"] is None:
            result["code"] = "VENDING.API_ENABLE_FAILED"
        if result["code"]:
            logger.error(f"{result['code']}: on '{target_project_id}' required APIs not enabled at vending: "
                         f"{failed_required or 'API table unavailable'} (the first apply enables them again): "
                         f"{result['error']}")
        return result

    def generate_project_id(self, product_id: str) -> str:
        """Generates a valid, unique GCP project ID (strictly <= 30 chars, lowercase, letters, digits, hyphens)."""
        clean = re.sub(r'[^a-z0-9]', '-', product_id.lower()).strip('-')
        if 6 <= len(clean) <= 30 and clean[0].isalpha():
            return clean
        clean_base = clean[:23].rstrip('-') if len(clean) > 23 else clean
        if not clean_base or not clean_base[0].isalpha():
            clean_base = f"p-{clean_base}".rstrip('-')[:23]
        suffix = uuid.uuid4().hex[:6]
        candidate = f"{clean_base}-{suffix}".strip('-')
        return candidate[:30].rstrip('-')

    def _get_project(self, project_id: str, purpose: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """VENDING-READ-TRANSIENT: one Resource Manager projects.get, read again after a transient error.

        Returns (True, project) on an answer and (False, None) only for the typed "not ours / not found" answer (HTTP
        403 or 404). Another non-transient error is raised unchanged. A transient error (_is_transient_poll_error) is
        logged at WARNING with its class (and HTTP status) only and read again with the poll backoff (1 s x1.5, cap
        5 s) while that stays within PROJECT_READ_MAX_WAIT_S; after that, VendingFailure(PROJECT_READ_UNAVAILABLE)
        naming the project and the read, chained to the last error. Never retries anything but this read."""
        deadline = time.time() + PROJECT_READ_MAX_WAIT_S
        interval = 1.0
        while True:
            try:
                return True, self.crm.projects().get(name=f"projects/{project_id}").execute()
            except Exception as e:  # noqa: BLE001 - classified by class / HTTP status below; others re-raised
                status = _http_status_of(e)
                if status in PROJECT_NOT_FOUND_HTTP_STATUSES:
                    return False, None
                if not _is_transient_poll_error(e):
                    raise
                shown = f"{type(e).__name__}{f' {status}' if status is not None else ''}"
                if time.time() + interval > deadline:
                    raise VendingFailure(
                        PROJECT_READ_UNAVAILABLE,
                        f"Resource Manager projects.get of '{project_id}' ({purpose}) still failed with a transient "
                        f"error after {PROJECT_READ_MAX_WAIT_S:.0f}s (last: {shown}). The vend stopped at this "
                        "read; re-run the vend.",
                    ) from e
                logger.warning(f"VENDING_READ_TRANSIENT: projects.get of '{project_id}' ({purpose}) raised {shown}; "
                               "reading again before the deadline")
            time.sleep(interval)
            interval = min(interval * 1.5, 5.0)

    def _get_project_or_stop(self, project_id: str, purpose: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """SAT-38 (I2): _get_project for the reads that decide whether to create (the existence check and the
        ownership check after a 409). A non-transient error other than 403 / 404, which already stopped the vend
        before anything was created, is wrapped in VendingFailure(PROJECT_READ_FAILED) with its class and HTTP status
        (never its message text), chained to it. VendingFailure (PROJECT_READ_UNAVAILABLE) passes through."""
        try:
            return self._get_project(project_id, purpose)
        except VendingFailure:
            raise
        except Exception as e:  # noqa: BLE001 - typed by class / HTTP status; the original is chained
            status = _http_status_of(e)
            shown = f"{type(e).__name__}{f' {status}' if status is not None else ''}"
            raise VendingFailure(
                PROJECT_READ_FAILED,
                f"Resource Manager projects.get of '{project_id}' ({purpose}) failed ({shown}). The vend stopped "
                "before creating any project; fix the cause (for example the vending identity's access to Resource "
                "Manager), then re-run the vend.",
            ) from e

    def _record_vend_target(self, product_id: str, project_id: str, doc_data: Dict[str, Any],
                            trace_id: Optional[str] = None) -> None:
        """SAT-38 (M2): before projects.create, write the target project id on workloads/{product_id} (merge: only
        `project_id` and the VENDING-TARGET-MARKER `vend_target`), so a vend that stops after Google created the project
        is re-run against the same id and knows it attempted it. Skipped when the record already names it with a marker
        for it, for a DECOMMISSIONED record (its project_id names the old project and a re-run does not read it) and
        without a Firestore client (a record that cannot be read stops the vend earlier: VENDING-RECORD-UNREADABLE).
        A failed write stops the vend (nothing created yet)."""
        if not (self.db and product_id) or doc_data.get("status") == "DECOMMISSIONED":
            return
        if doc_data.get("project_id") == project_id and _vend_target_id(doc_data) == project_id:
            return
        marker = {"project_id": project_id, "trace_id": trace_id,
                  "recorded_at": datetime.now(timezone.utc).isoformat()}
        try:
            self.db.collection("workloads").document(product_id).set(
                {"project_id": project_id, VEND_TARGET_MARKER: marker}, merge=True)
        except Exception as e:  # noqa: BLE001 - any write failure stops the vend before the create
            raise VendingFailure(
                PROJECT_TARGET_UNRECORDED,
                f"Could not record the target project id '{project_id}' on workloads/{product_id} before creating it "
                f"({type(e).__name__}). Nothing was created; re-run the vend.",
            ) from e

    def _check_adoptable(self, product_id: str, project_id: str, project: Any, record_status: Any = None) -> None:
        """SAT-38 (L4, M2): a project that already exists after a 409 on create is adopted only when it is not pending
        deletion, its `stackvend-product-id` label (if any) does not name another product, and, if it carries this
        product's StackVend labels, a provenance record names exactly it (StackVend created and recorded it). A project
        without a `stackvend-product-id` label (or this product's with `stackvend-managed` unset) is adopted as
        before. Another product's project is refused first, whatever its state (RT SAT-38 L1: the pending-deletion
        advice to undelete it would point the operator at another workload's project)."""
        labelled_product = _labelled_product_of(project)
        if labelled_product and labelled_product != product_id:
            raise VendingFailure(
                PROJECT_LABELLED_FOR_OTHER_PRODUCT,
                f"Project '{project_id}' already exists and its StackVend label {dg.LABEL_PRODUCT} names another "
                f"workload ('{labelled_product}'), not '{product_id}'. The vend stopped without adopting it (one "
                "workload never takes over another's project). An operator must resolve the id clash, for example by "
                "giving this workload a different project id, then re-run the vend.",
            )
        state = _project_state(project)
        if state in PENDING_DELETION_STATES:
            raise VendingFailure(PROJECT_PENDING_DELETION, _pending_deletion_detail(project_id, state, record_status))
        if not _labelled_for_product(project, product_id):
            return
        try:
            prov = self.guard_context().store.get_provenance(product_id)
        except Exception as e:  # noqa: BLE001 - could not check is never "adoptable" (fail closed)
            raise VendingFailure(
                PROJECT_PROVENANCE_UNREADABLE,
                f"Project '{project_id}' already exists and carries the StackVend labels of '{product_id}', but its "
                f"provenance record could not be read ({type(e).__name__}). The vend stopped without adopting it; "
                "re-run the vend.",
            ) from e
        number = _project_number_of(project)
        if (isinstance(prov, dict) and prov.get("created_by") in dg.PROVENANCE_CREATORS
                and prov.get("project_id") == project_id and number and dg._num(prov.get("project_number")) == number):
            return
        raise VendingFailure(
            PROJECT_UNPROVENANCED,
            f"Project '{project_id}' already exists and carries the StackVend labels of '{product_id}', but no "
            f"provenance record names it (workload_provenance/{product_id}), so StackVend cannot delete it "
            "automatically. It was most likely created by an earlier vend that stopped before recording it. The vend "
            "stopped without adopting it. If another vend of this workload may still be running (it may be about to "
            "record this project's provenance), wait for it to finish and re-run the vend first. Only if it still "
            f"stops: delete projects/{project_id} by hand, then re-run the vend; or have the owner record its "
            "provenance (backfill_provenance.py), then re-run the vend.",
        )

    def _wait_for_crm_operation(self, operation_name: str, max_wait_seconds: int = 60) -> Dict[str, Any]:
        """
        Polls Cloud Resource Manager v3 operation until completion or timeout.
        Uses exponential backoff (1s -> 1.5s -> 2.25s up to 5.0s max interval).
        VENDING-POLL-TRANSIENT: a poll that fails with a transient error (_is_transient_poll_error) is polled again
        within the same deadline; a non-transient error is raised unchanged, an operation finished with an error raises
        CrmOperationError (a RuntimeError, same message, carrying the operation's structured `error`), and the deadline
        raises TimeoutError (chained to the last transient poll error, if any).
        """
        start_time = time.time()
        poll_interval = 1.0
        last_transient: Optional[BaseException] = None
        while time.time() - start_time < max_wait_seconds:
            answered, op = _poll_operation_once(
                lambda: self.crm.operations().get(name=operation_name).execute(),
                f"Resource Manager operation '{operation_name}'",
            )
            if not answered:
                last_transient = op
            elif isinstance(op, dict) and op.get("done"):
                if "error" in op:
                    raise CrmOperationError(operation_name, op["error"])
                return op
            elif not isinstance(op, dict):
                # Fallback for mock environments
                return {"name": operation_name, "done": True}
            time.sleep(poll_interval)
            poll_interval = min(poll_interval * 1.5, 5.0)
        last = f" (last poll error: {type(last_transient).__name__})" if last_transient is not None else ""
        raise TimeoutError(f"GCP project creation operation '{operation_name}' timed out after "
                           f"{max_wait_seconds}s{last}") from last_transient

    def _wait_for_project_create(self, operation_name: str, project_id: str) -> Dict[str, Any]:
        """VENDING-PROJECT-QUOTA-TYPED: _wait_for_crm_operation for a projects.create operation. An operation error
        that _is_quota_exhausted_status classifies stops the vend with VENDING.PROJECT_QUOTA_EXCEEDED (the original
        error chained); every other outcome is returned or raised unchanged."""
        try:
            return self._wait_for_crm_operation(operation_name)
        except CrmOperationError as op_err:
            if _is_quota_exhausted_status(op_err.error):
                # Service log only (review fix 1): Google's structured status (incl. QuotaFailure violations) and the
                # operation name show which quota tripped; the operator message carries no Google text.
                logger.error(f"{PROJECT_QUOTA_EXCEEDED}: the create operation '{operation_name}' of project "
                             f"'{project_id}' failed with an exhausted project quota; status: {op_err.error}")
                raise VendingFailure(PROJECT_QUOTA_EXCEEDED,
                                     _project_quota_detail(project_id, op_err.error)) from op_err
            raise

    def _billing_already_linked(self, target_project_id: str, billing_formatted: str) -> bool:
        """True only when Cloud Billing itself reports the project linked to exactly this account with billing enabled.

        Any other answer is False, so the caller takes the normal updateBillingInfo path. That includes a read that
        fails: "could not check" is never "linked" (the update then links the project or fails BILLING_NOT_LINKED).
        """
        try:
            info = self.billing.projects().getBillingInfo(name=f"projects/{target_project_id}").execute()
        except Exception as e:  # noqa: BLE001 - never a success: the caller goes on to the update, which reports failure
            logger.warning(f"Could not read the billing info of '{target_project_id}' ({type(e).__name__}: {e}); "
                           "attempting updateBillingInfo")
            return False
        return (isinstance(info, dict)
                and info.get("billingEnabled") is True
                and info.get("billingAccountName") == billing_formatted)

    def _retry_api_call(self, func, max_attempts: int = 3, delay: float = 2.0, description: str = "operation"):
        """
        Retries an API call up to max_attempts on transient 400/404/409/503 errors
        caused by Google Cloud eventual consistency or concurrent policy updates during new project provisioning.
        """
        for attempt in range(1, max_attempts + 1):
            try:
                return func()
            except HttpError as e:
                status_code = getattr(e, "resp", None) and getattr(e.resp, "status", None)
                if status_code in (400, 404, 409, 503) and attempt < max_attempts:
                    logger.warning(
                        f"Transient HTTP {status_code} during {description} (attempt {attempt}/{max_attempts}). "
                        f"Waiting {delay}s for GCP directory replication..."
                    )
                    time.sleep(delay)
                else:
                    raise
            except Exception as e:
                # Handle generic 404/400/409 exceptions from mocks or wrapped clients
                err_str = str(e).lower()
                if any(x in err_str for x in ["not found", "404", "initializing", "409", "concurrent policy", "etag"]) and attempt < max_attempts:
                    logger.warning(
                        f"Transient delay during {description} (attempt {attempt}/{max_attempts}): {e}. "
                        f"Waiting {delay}s for GCP directory replication..."
                    )
                    time.sleep(delay)
                else:
                    raise

    def create_folder(
        self,
        display_name: str,
        parent_folder_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Creates a new folder under an existing folder or organization in Google Cloud Resource Manager v3.
        Defaults to parent = self.folder_id (MANAGED_WORKLOADS_FOLDER_ID).
        """
        clean_name = display_name.strip()
        if not clean_name:
            raise ValueError("display_name cannot be empty")

        parent_folder = parent_folder_id or self.folder_id
        if not parent_folder:
            raise ValueError("No parent folder specified and MANAGED_WORKLOADS_FOLDER_ID is not configured.")

        parent_formatted = (
            parent_folder
            if parent_folder.startswith("folders/") or parent_folder.startswith("organizations/")
            else f"folders/{parent_folder}"
        )

        # VENDING-CLIENT-FAIL-LOUD: without a client this used to skip the create and answer a made-up folder id.
        crm = self._require_crm(f"the creation of folder '{clean_name}'")
        logger.info(f"Creating GCP folder '{clean_name}' under parent '{parent_formatted}'")

        folder_res_name = None
        try:
            folder_body = {
                "displayName": clean_name,
                "parent": parent_formatted,
            }
            operation = crm.folders().create(body=folder_body).execute()
            op_name = operation.get("name") if isinstance(operation, dict) else None
            if op_name:
                logger.info(f"Waiting for folder creation operation '{op_name}'...")
                completed_op = self._wait_for_crm_operation(op_name)
                response_data = completed_op.get("response") if isinstance(completed_op, dict) else None
                folder_res_name = response_data.get("name") if isinstance(response_data, dict) else None
        except Exception as e:
            logger.error(f"Failed to create folder '{clean_name}' via Resource Manager: {e}")
            raise

        # Gap 3 (VENDING-CLIENT-FAIL-LOUD): the folder id comes only from Resource Manager's answer. An operation without
        # a name, or a finished one whose response names no folder, used to be answered with a made-up random id.
        if not (isinstance(folder_res_name, str) and folder_res_name.startswith("folders/")
                and folder_res_name[len("folders/"):]):
            shown = "no operation name" if not op_name else "the finished operation names no folder"
            raise VendingFailure(
                FOLDER_CREATE_UNCONFIRMED,
                f"Resource Manager accepted the creation of folder '{clean_name}' under '{parent_formatted}' but its "
                f"answer gives no folder id ({shown}). The folder may exist: check the parent folder in the Cloud "
                "console before creating it again.",
            )

        folder_num = folder_res_name.replace("folders/", "")
        return {
            "status": "SUCCESS",
            "folder_id": folder_res_name,
            "folder_number": folder_num,
            "display_name": clean_name,
            "parent_folder_id": parent_formatted,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def is_platform_admin_role(raw: Any) -> bool:
        """Exact Control Center role (lane 19 L19-12, FD-4I I10): ``str(raw).strip().upper() == "ADMIN"``.

        Same table as ``shared.access_policy.parse_platform_role(raw) is PlatformRole.ADMIN`` (the vending image has
        no copy of that module yet; tests/test_lane19_tenant_authz.py pins the two to the same answers). Replaces the
        former ``"ADMIN" in role`` substring match, which also admitted NON_ADMIN, ADMIN_PENDING and SUBADMIN."""
        if raw is None:
            return False
        return str(raw).strip().upper() == "ADMIN"

    def get_platform_admin_members(self) -> List[str]:
        """
        Platform ADMINs (Firestore ``authorized_users`` with the exact role ``ADMIN``, not deactivated) to bind as
        ``roles/viewer`` on vended child projects, so admins can see the projects StackVend creates.

        Lane 19 L19-12 (FD-4I I10/I11): nothing else grants access. Environment variables (``ADMIN_USER_EMAIL`` /
        ``ADMIN_EMAIL``) and workload-document fields (``operator_email``, ``initialized_by``, ``created_by``,
        ``owner_email``, ``user_email``) are no longer read: they were guesses, not the platform's role record.
        """
        members: List[str] = []

        def _format_member(email_str: str) -> Optional[str]:
            if not email_str or not isinstance(email_str, str):
                return None
            clean = email_str.strip()
            if not clean or "@" not in clean:
                return None
            if clean.startswith("user:") or clean.startswith("serviceAccount:") or clean.startswith("group:"):
                return clean
            if clean.endswith(".gserviceaccount.com"):
                return f"serviceAccount:{clean}"
            return f"user:{clean}"

        if self.db:
            try:
                docs = self.db.collection("authorized_users").stream()
                for doc in docs:
                    d = doc.to_dict() or {}
                    if d.get("is_active", True) is not False and self.is_platform_admin_role(d.get("role")):
                        email = d.get("email") or doc.id
                        mem = _format_member(email)
                        if mem and mem not in members:
                            members.append(mem)
            except Exception as e:
                logger.warning(f"Could not stream authorized_users for admin binding: {e}")

        return members

    def _refuse_platform_target(self, product_id: str, doc_data: Dict[str, Any],
                                force_new_project_id: Optional[str]) -> None:
        """RT14-02: VendingFailure(TARGET_IS_PLATFORM) for a platform pseudo-workload id, a record with is_castor, or a
        recorded / forced project id equal to the host project. Exact comparisons; nothing is read or created."""
        host = (self.platform_project_id or "").strip()
        recorded = doc_data.get("project_id") if isinstance(doc_data, dict) else None
        reason = None
        if product_id in dg.PLATFORM_PSEUDO_WORKLOADS:
            reason = f"'{product_id}' is a platform pseudo-workload id"
        elif isinstance(doc_data, dict) and doc_data.get("is_castor") is True:
            reason = f"workloads/{product_id} is the platform workload (is_castor)"
        elif host and (recorded == host or force_new_project_id == host):
            reason = f"the target project of '{product_id}' is the host project"
        if reason:
            logger.error(f"{TARGET_IS_PLATFORM}: vend of '{product_id}' refused: {reason}")
            raise VendingFailure(TARGET_IS_PLATFORM,
                                 f"{reason}. StackVend never vends, re-uses or grants on the host project; nothing was "
                                 "created or changed.")

    def vend_gcp_project(
        self,
        product_id: str,
        trace_id: str,
        folder_id: Optional[str] = None,
        billing_account_id: Optional[str] = None,
        initial_budget: Optional[float] = None,
        force_new_project_id: Optional[str] = None,
        is_sandbox: bool = False,
        sandbox_auto_decommission: bool = False,
        sandbox_designation_source: Optional[str] = None,
        sandbox_ttl_days: Optional[int] = None,
        runner_mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Creates a new isolated GCP child project under the Managed Workloads folder,
        attaches billing, enables base APIs, and grants scoped DevOps IAM permissions.

        Provenance at birth (lane 18 S1, plan 2.4): only when projects.create completes in THIS call, the project is
        created with the StackVend labels, gets the IAM-gated stackvend-managed tag binding (when
        STACKVEND_MANAGED_TAG_VALUE is configured) and a workload_provenance/{product_id} record. The sandbox fields
        come only from the explicit request (absent -> not a sandbox). A reused or adopted project gets none of these.
        """
        # FD-7L-n: an unknown value fails before anything is created. FD-7L-F4 RT M2: one snapshot per operation
        # (vend_all passes its own, so a Settings switch during a vend never splits it across two modes).
        if runner_mode is None:
            runner_mode = self.runner_identity_mode()
        # VENDING-CLIENT-FAIL-LOUD: every step below needs Resource Manager (existence check, create, IAM grants,
        # project number). Without a client the vend used to skip them all and still answer PROJECT_VENDED; it now
        # stops here, before anything is read or created. The steps below therefore no longer test for the client.
        self._require_crm(f"the vend of '{product_id}' (project existence check, creation and IAM grants)")
        # Gap 1: the workload record (which project this workload owns, the pre-create target marker, the final
        # PROVISIONED record) is never skipped either.
        self._require_db(f"the vend of '{product_id}' (workload record read, target marker and record write)")
        billing_acct = billing_account_id or self.billing_account_id
        billing_formatted = billing_acct if (billing_acct and billing_acct.startswith("billingAccounts/")) else (f"billingAccounts/{billing_acct}" if billing_acct else None)

        # Check if project was already vended in Firestore
        target_project_id = None
        already_created = False
        doc_data = {}
        if self.db and product_id:
            # VENDING-RECORD-UNREADABLE (RT SAT-38 L4): the record decides which project this workload owns; a vend
            # that cannot read it stops before anything is created (it used to go on as if there were no record and
            # could create a second project).
            try:
                doc = self.db.collection("workloads").document(product_id).get()
                if doc.exists:
                    doc_data = doc.to_dict() or {}
            except Exception as rec_err:  # noqa: BLE001 - typed by class; nothing created yet
                raise VendingFailure(
                    WORKLOAD_RECORD_UNREADABLE,
                    f"The workload record workloads/{product_id} could not be read ({type(rec_err).__name__}). It "
                    "decides which project this workload already owns, so the vend stopped before creating anything; "
                    "re-run the vend once Firestore is reachable.",
                ) from rec_err

        # RT14-02 (invariant 5): the platform workload is never vended. Its record names the HOST project, so a reuse
        # below would run project IAM, API and runner-identity calls against the host and overwrite is_castor.
        self._refuse_platform_target(product_id, doc_data, force_new_project_id)

        if force_new_project_id:
            target_project_id = force_new_project_id
            already_created = False
        elif doc_data:
            # Do NOT reuse project ID if workload was DECOMMISSIONED
            if doc_data.get("status") != "DECOMMISSIONED" and doc_data.get("project_id"):
                existing_id = doc_data.get("project_id")
                if existing_id and not existing_id.startswith("mock-"):
                    target_project_id = existing_id
                    # Only mark already_created if status is already PROVISIONED or ACTIVE,
                    # NOT when it's PROVISIONING (which is an initial/in-flight registration state).
                    if doc_data.get("status") in ("PROVISIONED", "ACTIVE"):
                        already_created = True
                        logger.info(f"Workload '{product_id}' has existing vended project '{target_project_id}' in Firestore (status: {doc_data.get('status')})")
                    else:
                        already_created = False
                        logger.info(f"Workload '{product_id}' has pre-assigned project ID '{target_project_id}' in Firestore (status: {doc_data.get('status')}). Will ensure project is created in GCP.")

        parent_folder = folder_id or doc_data.get("parent_folder_id") or doc_data.get("folder_id") or self.folder_id
        parent_formatted = parent_folder if (parent_folder and (parent_folder.startswith("folders/") or parent_folder.startswith("organizations/"))) else (f"folders/{parent_folder}" if parent_folder else None)

        if not target_project_id or len(target_project_id) > 30:
            if target_project_id and len(target_project_id) > 30:
                logger.warning(f"GCP project ID '{target_project_id}' exceeds maximum 30 chars ({len(target_project_id)} chars). Generating valid ID.")
            target_project_id = self.generate_project_id(product_id)
            already_created = False
        # SAT-38 (M1): the target id is the one a PROVISIONED / ACTIVE workload record names (it was created before).
        recorded_as_created = already_created
        # VENDING-TARGET-MARKER (RT SAT-38 L3): a marker an EARLIER vend left for this exact id (start-of-vend snapshot;
        # ignored on a DECOMMISSIONED record).
        earlier_target = (doc_data.get(VEND_TARGET_MARKER)
                          if (doc_data.get("status") != "DECOMMISSIONED"
                              and _vend_target_id(doc_data) == target_project_id) else None)

        # Verify whether the project genuinely exists and is ACTIVE in GCP Resource Manager
        # VENDING-READ-TRANSIENT: a transient read error is read again (bounded) and never taken for "not created";
        # only HTTP 403 / 404 is; any other error stops the vend (SAT-38 I2: typed PROJECT_READ_FAILED; a create after
        # an unknown answer could 409 into a fallback id, i.e. a second project).
        if already_created:
            found, proj_check = self._get_project_or_stop(target_project_id, "existence check of the recorded project")
            if not found:
                # SAT-38 (M1): never "create it again" for a recorded project: its id cannot be reused, so that could
                # only 409 into a fallback id (a second project) while the original may still exist unseen.
                raise VendingFailure(
                    RECORDED_PROJECT_UNREADABLE,
                    f"The workload record names project '{target_project_id}' (status {doc_data.get('status')}), but "
                    "Resource Manager projects.get answers 403/404 to the vending identity. The vend stopped without "
                    "creating a project. Check that the project still exists and stays under the managed workloads "
                    "folder (vending reads children through its folder grants); StackVend does not create a "
                    "replacement for a recorded project.",
                )
            elif isinstance(proj_check, dict):
                state = proj_check.get("state") or proj_check.get("lifecycleState")
                if state in PENDING_DELETION_STATES:   # SAT-38 (L4): exact enum values
                    raise VendingFailure(PROJECT_PENDING_DELETION,
                                         _pending_deletion_detail(target_project_id, state, doc_data.get("status")))
                if state not in ("ACTIVE", "STATE_UNSPECIFIED") and not (isinstance(state, str) and "ACTIVE" in state.upper()):
                    logger.info(f"Project '{target_project_id}' exists in Resource Manager but state is '{state}'. Will recreate.")
                    already_created = False
                else:
                    logger.info(f"Verified project '{target_project_id}' is ACTIVE in GCP Resource Manager.")

        logger.info(f"Vending GCP project '{target_project_id}' for product '{product_id}' (Parent: {parent_formatted}, already_created: {already_created})")

        # 1. Create Project via Resource Manager v3
        created_in_this_call = False
        crm_create_operation = None
        created_project_number = ""   # F-C: from the finished create operation's response, when it carries it
        workload_type = "sandbox" if is_sandbox is True else "standard"
        # Gap 2 (VENDING-CLIENT-FAIL-LOUD): a project to create needs a parent folder (child projects always live under
        # the managed workloads folder, documentation/configuration.md). With none it used to skip the create silently
        # and go on as if the project existed. A recorded, existing project (already_created) needs none.
        if not already_created and not parent_formatted:
            raise VendingFailure(
                PARENT_FOLDER_UNCONFIGURED,
                f"No parent folder for project '{target_project_id}' of '{product_id}': the request names none, the "
                "workload record names none and MANAGED_WORKLOADS_FOLDER_ID is not set. Nothing was created; "
                "configure the managed workloads folder (or pass folder_id), then re-run.",
            )
        if not already_created:
            try:
                clean_display = re.sub(r'[^a-zA-Z0-9\s-]', '', product_id).strip()[:30]
                display_name = clean_display or product_id
                project_body = {
                    "projectId": target_project_id,
                    "displayName": display_name,
                    "parent": parent_formatted,
                }
                if _is_label_value(product_id):
                    project_body["labels"] = {
                        dg.LABEL_MANAGED: "true",
                        dg.LABEL_PRODUCT: product_id,
                        dg.LABEL_TYPE: workload_type,
                    }
                else:
                    logger.warning(f"PROVENANCE_LABELS_SKIPPED: product id '{product_id}' is not a valid GCP label "
                                   "value; the project will never be deletable by StackVend (fail closed).")
                self._record_vend_target(product_id, target_project_id, doc_data, trace_id=trace_id)   # SAT-38 M2
                operation = self.crm.projects().create(body=project_body).execute()
                op_name = operation.get("name") if isinstance(operation, dict) else None
                logger.info(f"Initiated project creation: {op_name or operation}")
                if op_name:
                    logger.info(f"Waiting for project creation operation '{op_name}' to complete...")
                    created_project_number = _number_from_create_operation(
                        self._wait_for_project_create(op_name, target_project_id))
                    logger.info(f"GCP project '{target_project_id}' is now ACTIVE.")
                created_in_this_call = True
                crm_create_operation = op_name
            except HttpError as e:
                status_code = getattr(e, "resp", None) and getattr(e.resp, "status", None)
                # VENDING-PROJECT-QUOTA-TYPED: the old "HTTP 403 whose text contains 'quota'" branch is gone (a
                # substring guess, invariant 2). Google reports an exhausted project quota in the create operation
                # (code 8 + QuotaFailure, _wait_for_project_create); a 403 is PERMISSION_DENIED and its text can name
                # an unrelated "quota project". A 403 is now raised as Google's own error, like every other status.
                if status_code == 409:
                    # VENDING-READ-TRANSIENT (OQ-29): the fallback id is created only after the typed "not ours"
                    # answer (HTTP 403 / 404); a transient read is read again (bounded, then a typed failure) and any
                    # other error is raised, so an unknown answer never creates a second project.
                    found, existing = self._get_project_or_stop(target_project_id,
                                                                "ownership check after 409 on create")
                    if found:
                        # SAT-38 (L4, M2): not a project pending deletion, and never a silent adoption of a project
                        # labelled for this product that no provenance record names.
                        self._check_adoptable(product_id, target_project_id, existing, doc_data.get("status"))
                        logger.info(f"GCP project '{target_project_id}' already exists in Resource Manager. Proceeding.")
                    elif recorded_as_created:
                        # SAT-38 (M1): a recorded project's id never falls back to another (second) project.
                        raise VendingFailure(
                            RECORDED_PROJECT_UNREADABLE,
                            f"The workload record names project '{target_project_id}', which answered 409 on create "
                            "and then 403/404 to the vending identity. The vend stopped without creating a fallback "
                            "(second) project. Check that the project still exists and stays under the managed "
                            "workloads folder.",
                        ) from e
                    elif earlier_target is not None:
                        # VENDING-TARGET-MARKER (RT SAT-38 L3): an earlier vend attempted this very id; its create may
                        # not be visible yet, so never fall back to a second project.
                        raise VendingFailure(
                            VEND_TARGET_UNREADABLE,
                            f"An earlier vend of this workload (trace {earlier_target.get('trace_id')}, recorded "
                            f"{earlier_target.get('recorded_at')}) started creating project '{target_project_id}'. That "
                            "id now answers 409 on create and 403/404 to the vending identity: either the earlier "
                            "create is not visible yet, or the id is taken outside StackVend. The vend stopped without "
                            "creating a fallback (second) project. Wait a few minutes and re-run the vend; if it "
                            f"keeps stopping, an operator removes the `{VEND_TARGET_MARKER}` field from "
                            f"workloads/{product_id} (the next vend then creates a fallback id) or assigns another "
                            "project id.",
                        ) from e
                    else:
                        fallback_suffix = uuid.uuid4().hex[:6]
                        fallback_id = f"{target_project_id[:23].rstrip('-')}-{fallback_suffix}"
                        logger.warning(f"GCP project ID '{target_project_id}' is globally taken by an external entity (409). Retrying creation with unique ID '{fallback_id}'...")
                        target_project_id = fallback_id
                        project_body["projectId"] = target_project_id
                        self._record_vend_target(product_id, target_project_id, doc_data, trace_id=trace_id)
                        op = self.crm.projects().create(body=project_body).execute()
                        op_name = op.get("name") if isinstance(op, dict) else None
                        if op_name:
                            created_project_number = _number_from_create_operation(
                                self._wait_for_project_create(op_name, target_project_id))
                        created_in_this_call = True
                        crm_create_operation = op_name
                else:
                    logger.error(f"Project creation failed: {e}")
                    raise

        # 1b. Child-project owners (lane 18 S0 blocking item B1, register row L18-i). Once vending runs as its own
        # identity, the SA that deploys workloads is no longer the implicit creator-owner of new children. Only for a
        # project created in THIS call, grant roles/owner to exactly the members in STACKVEND_CHILD_PROJECT_OWNER_MEMBERS
        # (unset -> no-op, today's behaviour). Done before billing is linked, so a failed grant leaves an unbilled,
        # empty project, and it fails the vend loudly (a child nobody can deploy to is useless).
        if created_in_this_call:
            self._grant_child_project_owners(target_project_id)

        # 2. Attach Billing with Eventual Consistency Retry. FD-4AI (owner 10-26): with a billing account configured,
        # a project that could not be linked fails the vend (BILLING_NOT_LINKED), never a PROJECT_VENDED / SUCCESS.
        billing_failure: Optional[VendingFailure] = None
        if billing_formatted and not self.billing:
            billing_failure = VendingFailure(
                BILLING_NOT_LINKED,
                f"Billing account '{billing_formatted}' was not linked to project '{target_project_id}': no Cloud "
                "Billing API client could be created (credentials). Fix the vending service identity, then re-run.",
            )
        elif self.billing and billing_formatted and self._billing_already_linked(target_project_id, billing_formatted):
            # VENDING-BILLING-LINK-IDEMPOTENT: Cloud Billing answers updateBillingInfo with a 400 quota error when the
            # account is at its project limit, even for a project already linked to it, so a relaunch must not re-link.
            logger.info(f"Project '{target_project_id}' is already linked to billing account '{billing_formatted}' "
                        "with billing enabled; skipping updateBillingInfo")
        elif self.billing and billing_formatted:
            def _attach_billing():
                billing_info = {
                    "billingAccountName": billing_formatted,
                    "billingEnabled": True,
                }
                return self.billing.projects().updateBillingInfo(
                    name=f"projects/{target_project_id}",
                    body=billing_info,
                ).execute()

            try:
                self._retry_api_call(
                    _attach_billing,
                    max_attempts=3,
                    delay=2.0,
                    description=f"attach billing to {target_project_id}",
                )
                logger.info(f"Attached billing account '{billing_formatted}' to project '{target_project_id}'")
            except Exception as e:
                err_str = str(e).lower()
                if "quota" in err_str or "quotafailure" in err_str:
                    logger.error(f"GCP Cloud Billing Project Quota exceeded for account '{billing_formatted}': {e}")
                    billing_failure = VendingFailure(
                        BILLING_NOT_LINKED,
                        f"GCP Cloud Billing Project Quota exceeded for billing account '{billing_formatted}'. "
                        "Action required: (1) Unlink obsolete test projects via 'gcloud billing projects unlink <project>', or "
                        "(2) Request a billing quota increase at https://support.google.com/code/contact/billing_quota_increase."
                    )
                else:
                    logger.error(f"Failed to link billing account '{billing_formatted}' to '{target_project_id}': {e}")
                    billing_failure = VendingFailure(
                        BILLING_NOT_LINKED,
                        f"Billing account '{billing_formatted}' could not be linked to project '{target_project_id}' "
                        f"({type(e).__name__}: {e}). The vending identity needs roles/billing.user on the billing "
                        "account (and roles/billing.projectManager on the project); fix it, then re-run.",
                    )
                billing_failure.__cause__ = e
        if billing_failure is not None:
            self._keep_unbilled_project_recoverable(
                product_id=product_id, trace_id=trace_id, project_id=target_project_id,
                created_in_this_call=created_in_this_call, crm_create_operation=crm_create_operation,
                is_sandbox=is_sandbox, sandbox_auto_decommission=sandbox_auto_decommission,
                sandbox_designation_source=sandbox_designation_source, sandbox_ttl_days=sandbox_ttl_days,
                failure=billing_failure, project_number=created_project_number,
            )
            raise billing_failure

        # 3a. Auto-bind Platform Admins to roles/viewer (Dedicated Isolated Call). Lane 19 L19-12: exact ADMIN role
        # only; no env-var admins and no creator / operator fields from the workload document.
        admin_and_creator_members = self.get_platform_admin_members()
        if admin_and_creator_members:
            def _bind_admin_viewers():
                policy = self.crm.projects().getIamPolicy(resource=f"projects/{target_project_id}").execute()
                bindings = policy.get("bindings", [])
                viewer_binding = next((b for b in bindings if b.get("role") == "roles/viewer"), None)
                if viewer_binding:
                    existing = set(viewer_binding.get("members", []))
                    for m in admin_and_creator_members:
                        if m not in existing:
                            viewer_binding.setdefault("members", []).append(m)
                else:
                    bindings.append({
                        "role": "roles/viewer",
                        "members": list(dict.fromkeys(admin_and_creator_members)),
                    })
                policy["bindings"] = bindings
                return self.crm.projects().setIamPolicy(
                    resource=f"projects/{target_project_id}",
                    body={"policy": policy},
                ).execute()

            try:
                self._retry_api_call(
                    _bind_admin_viewers,
                    max_attempts=3,
                    delay=1.5,
                    description=f"bind admin viewer IAM on {target_project_id}",
                )
                logger.info(f"Auto-bound {len(admin_and_creator_members)} platform admins as roles/viewer on '{target_project_id}': {admin_and_creator_members}")
            except Exception as admin_iam_err:
                logger.warning(f"Could not bind admin viewer IAM: {admin_iam_err}")

        # 3b. Enable the child's APIs: the platform API table's workload-deploy set (VEND-API-TABLE) + vending's
        #     baseline. Typed result recorded on the workload; never raises.
        api_enablement = self.enable_child_apis(target_project_id)

        # 3b-2. Enable Google Cloud Native Quota Adjuster (Auto-Scaling Headroom)
        try:
            from google.cloud import cloudquotas_v1
            quota_client = cloudquotas_v1.CloudQuotasClient()
            settings_name = f"projects/{target_project_id}/locations/global/quotaAdjusterSettings"
            settings = cloudquotas_v1.QuotaAdjusterSettings(
                name=settings_name,
                enablement=cloudquotas_v1.QuotaAdjusterSettings.Enablement.ENABLED,
            )
            quota_client.update_quota_adjuster_settings(quota_adjuster_settings=settings)
            logger.info(f"Enabled native Google Cloud Quota Adjuster on '{target_project_id}'")
        except Exception as q_err:
            logger.debug(f"Quota Adjuster auto-enablement skipped on '{target_project_id}': {q_err}")

        # 3b-3. Child-project org policies (lane 10 L10-t2 / ORG-POLICY-FOLDER): "no external VM IPs"
        # (compute.vmExternalIpAccess deny all) is inherited from the managed workloads folder; vending only checks the
        # child's effective policy. Typed result recorded on the workload; never fails the vend.
        org_policy_results = self.check_child_org_policies(target_project_id)

        # 3c. Grant Scoped IAM Permissions to DevOps Service Account and Build Service Accounts
        if self.devops_sa_email:
            def _apply_sa_iam_policy():
                policy = self.crm.projects().getIamPolicy(resource=f"projects/{target_project_id}").execute()
                bindings = policy.get("bindings", [])

                p_num = created_project_number
                try:
                    if not p_num:
                        proj_info = self._get_project(target_project_id, "project number for the build grants")[1]
                        p_num = (proj_info.get("projectNumber") or proj_info.get("name", "").split("/")[-1]) if isinstance(proj_info, dict) else ""
                except Exception:
                    pass

                def _add_or_merge_binding(role: str, members: List[str]):
                    for b in bindings:
                        if b.get("role") == role:
                            existing = set(b.get("members", []))
                            for m in members:
                                if m not in existing:
                                    b.setdefault("members", []).append(m)
                            return
                    bindings.append({
                        "role": role,
                        "members": list(dict.fromkeys(members)),
                    })

                _add_or_merge_binding("roles/editor", [f"serviceAccount:{self.devops_sa_email}"])
                _add_or_merge_binding("roles/cloudbuild.builds.editor", [f"serviceAccount:{self.devops_sa_email}"])
                _add_or_merge_binding("roles/secretmanager.admin", [f"serviceAccount:{self.devops_sa_email}"])
                _add_or_merge_binding("roles/artifactregistry.admin", [f"serviceAccount:{self.devops_sa_email}"])

                log_members = [f"serviceAccount:{self.devops_sa_email}"]
                if p_num:
                    log_members.append(f"serviceAccount:{p_num}@cloudbuild.gserviceaccount.com")
                    log_members.append(f"serviceAccount:{p_num}-compute@developer.gserviceaccount.com")

                _add_or_merge_binding("roles/logging.logWriter", log_members)
                _add_or_merge_binding("roles/artifactregistry.writer", log_members)
                _add_or_merge_binding("roles/storage.admin", log_members)
                _add_or_merge_binding("roles/cloudbuild.builds.builder", log_members)

                policy["bindings"] = bindings
                return self.crm.projects().setIamPolicy(
                    resource=f"projects/{target_project_id}",
                    body={"policy": policy},
                ).execute()

            try:
                self._retry_api_call(
                    _apply_sa_iam_policy,
                    max_attempts=5,
                    delay=2.0,
                    description=f"bind scoped SA IAM policy on {target_project_id}",
                )
                logger.info(f"Granted roles/editor, roles/logging.logWriter, roles/artifactregistry.writer, roles/storage.admin, roles/cloudbuild.builds.editor, and roles/secretmanager.admin on '{target_project_id}'")
            except Exception as e:
                logger.warning(f"Could not bind scoped SA IAM policy: {e}")

        # 4. Resolve project_number: the create operation's answer when this call created the project (F-C), else
        #    Resource Manager, read again after a transient error (VENDING-READ-TRANSIENT). A project created in this
        #    call whose number is still unknown fails the vend typed (OQ-28) instead of going on without provenance.
        project_number = created_project_number
        if not project_number:
            try:
                p_desc = self._get_project(target_project_id, "project number")[1]
                project_number = (p_desc.get("projectNumber") or p_desc.get("name", "").split("/")[-1]) if isinstance(p_desc, dict) else ""
            except VendingFailure as read_err:
                if not created_in_this_call:
                    raise
                failure = VendingFailure(
                    read_err.error_class,
                    f"Resource Manager projects.get of '{target_project_id}' (project number) still failed with a "
                    f"transient error after {PROJECT_READ_MAX_WAIT_S:.0f}s. {_unprovenanced_note(target_project_id)}")
                raise self._record_unprovenanced_project(product_id, target_project_id, failure) from read_err.__cause__
            except Exception as pn_err:
                if created_in_this_call:
                    raise self._record_unprovenanced_project(product_id, target_project_id, VendingFailure(
                        PROJECT_NUMBER_UNRESOLVED,
                        f"Resource Manager projects.get of '{target_project_id}' (project number) failed "
                        f"({type(pn_err).__name__}). {_unprovenanced_note(target_project_id)}")) from pn_err
                logger.debug(f"Could not resolve project_number: {pn_err}")
        if created_in_this_call and not dg._num(project_number):
            raise self._record_unprovenanced_project(product_id, target_project_id, VendingFailure(
                PROJECT_NUMBER_UNRESOLVED,
                f"Neither the create operation's answer nor Resource Manager gave the project number of "
                f"'{target_project_id}'. {_unprovenanced_note(target_project_id)}"))

        # 4b. Provenance at birth (lane 18 S1): only for a project created in this call.
        provenance_status = "NOT_CREATED_IN_THIS_CALL"
        if created_in_this_call:
            provenance_status = self._record_provenance_at_birth(
                product_id=product_id,
                trace_id=trace_id,
                project_id=target_project_id,
                project_number=project_number,
                crm_create_operation=crm_create_operation,
                labelled=_is_label_value(product_id),
                is_sandbox=is_sandbox,
                sandbox_auto_decommission=sandbox_auto_decommission,
                sandbox_designation_source=sandbox_designation_source,
                sandbox_ttl_days=sandbox_ttl_days,
            )

        # Check existing workload record to preserve user preference from modal
        existing_require_review = None
        existing_auto_merge = None
        has_code_freeze = False   # FD-4CU: a record that already has a code_freeze value keeps it
        existing_budget = None    # FD-4CI-b: a record that already has a budget keeps it
        kept_switches: List[str] = []   # FD-4CU-b: SRE / scanner switches the existing record already has
        record_unread = False
        if self.db:
            try:
                cur_doc = self.db.collection("workloads").document(product_id).get()
                if cur_doc.exists:
                    cur_data = cur_doc.to_dict() or {}
                    if "require_human_code_review" in cur_data:
                        existing_require_review = cur_data.get("require_human_code_review")
                    if "auto_merge" in cur_data:
                        existing_auto_merge = cur_data.get("auto_merge")
                    has_code_freeze = "code_freeze" in cur_data
                    existing_budget = cur_data.get("budget_ceiling_monthly_usd")
                    kept_switches = [k for k in ("sre_auto_healing_enabled", "refactor_scanner_enabled")
                                     if k in cur_data]
            except Exception as e:
                logger.debug(f"Could not read existing workload record for review settings: {e}")
                record_unread = True

        # Check platform settings for default HITL review requirement if not explicitly set
        if existing_require_review is not None:
            final_hitl = bool(existing_require_review)
        elif existing_auto_merge is not None:
            final_hitl = not bool(existing_auto_merge)
        else:
            default_hitl = True
            try:
                from shared.settings import get_platform_settings
                # FD-4AK: strict read; unreadable / invalid settings keep human code review on (fail closed).
                plat_settings = get_platform_settings(project_id=self.platform_project_id, strict=True)
                gov = getattr(plat_settings, "governance", None)
                default_hitl = getattr(gov, "default_require_human_code_review", True) if gov else True
            except Exception as e:  # noqa: BLE001
                logger.error(f"{getattr(e, 'code', 'PLATFORM_SETTINGS_UNAVAILABLE')}: default code-review setting "
                             f"unavailable ({type(e).__name__}: {e}); human code review stays required.")
                default_hitl = True
            final_hitl = default_hitl

        # FD-4CI-b: the budget is set when the workload is created. An existing record keeps its
        # budget_ceiling_monthly_usd (the orchestrator's vend call used to overwrite the operator's choice with 40); a
        # new record (Drive intake) gets the request's budget, else the platform's Default Monthly Budget Ceiling.
        # An unreadable record gets no budget written (it may be an existing workload with its own).
        keep_budget = record_unread or existing_budget is not None
        initial_budget = (existing_budget if existing_budget is not None
                          else initial_budget if initial_budget is not None
                          else _platform_default_budget_usd(self.platform_project_id))

        # Register in Firestore workloads collection
        workload_record = {
            "product_id": product_id,
            "project_id": target_project_id,
            "project_number": project_number,
            "trace_id": trace_id,
            "parent_folder_id": parent_folder,
            "billing_account_id": billing_acct,
            "budget_ceiling_monthly_usd": initial_budget,
            "current_spend_usd": 0.0,
            "projected_monthly_spend_usd": 0.0,
            "spend_last_updated_at": datetime.now(timezone.utc).isoformat(),
            "is_overrun_projected": False,
            "status": "PROVISIONED",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "is_castor": False,
            "auth_provider": "identity_platform",
            "idp_provider": "google.com",
            "identity_platform_enabled": True,
            "sre_auto_healing_enabled": True,
            "refactor_scanner_enabled": True,
            "require_human_code_review": final_hitl,
            "auto_merge": not final_hitl,
            "org_policies": org_policy_results,
            "api_enablement": api_enablement,   # VEND-API-TABLE: typed result of the child's API enablement
        }
        # FD-4CU (owner 10-21): a NEW workload record (no code_freeze value yet: a Drive intake, or a record seeded
        # before vending) starts frozen when governance.freeze_new_workloads is on (default; unreadable -> frozen).
        # A record that already has a value (Control Center create / promote, any re-vend or redeploy) keeps it, so
        # vending never changes an existing workload's freeze. If the record could not be read, only a freeze is
        # written (never an unfreeze of a record that may exist).
        # FD-4CU-b (owner 10-21): likewise an existing record keeps its SRE auto-healing / scanner switches (a re-vend
        # no longer turns them back on); a new record gets both on; an unreadable record gets neither written.
        for switch in ("sre_auto_healing_enabled", "refactor_scanner_enabled"):
            if record_unread or switch in kept_switches:
                workload_record.pop(switch, None)
        # FD-4CU-c re-check R2-1: an unreadable record may be an existing workload with human review on; the platform
        # default (possibly off) must never loosen it. Neither review field is written (the gateway and the release
        # gatekeeper treat an absent require_human_code_review as review required).
        if record_unread:
            workload_record.pop("require_human_code_review", None)
            workload_record.pop("auto_merge", None)
        if keep_budget:
            workload_record.pop("budget_ceiling_monthly_usd", None)
        if not has_code_freeze:
            initial_freeze = _freeze_new_workloads_default(self.platform_project_id)
            if initial_freeze or not record_unread:
                workload_record["code_freeze"] = initial_freeze
        try:
            self.db.collection("workloads").document(product_id).set(workload_record, merge=True)
            logger.info(f"Registered workload record in Firestore: workloads/{product_id}")
        except Exception as e:  # noqa: BLE001 - typed by where it happens; the original is chained
            raise VendingFailure(
                WORKLOAD_RECORD_UNWRITTEN,
                f"Project '{target_project_id}' is vended but its workload record workloads/{product_id} could not be "
                f"written ({type(e).__name__}). Re-run the vend once Firestore is reachable; it reuses this project.",
            ) from e

        # 4c. RT14-31 / owner decision D4 (11-14): the Control Center's runtime SA may read this child's logs
        #     (roles/logging.viewer on the child only; cc_log_reader.py). Every vended project (new, re-vend, adopted,
        #     redeploy; idempotent). After provenance and the record, so a failed grant leaves a recorded, provenanced
        #     project that a re-run reuses; the vend fails typed (VENDING.CC_LOG_READER_GRANT_FAILED).
        cc_log_reader = self._grant_cc_log_reader(target_project_id)

        # 5. FD-7L Phase 1 (PER_WORKLOAD installs only; PLATFORM / "Shared" runs none of this): the workload's own
        #    deployer service account and state bucket, recorded in its signed provenance. After billing (2), API
        #    enablement (3b) and the 3c grants, for every provenanced project (new, re-vend, retry: idempotent).
        runner_identity = None
        if runner_mode == ri.MODE_PER_WORKLOAD:
            runner_identity = self._ensure_runner_identity(product_id, target_project_id, project_number, doc_data)

        result = {
            "status": "PROJECT_VENDED",
            "product_id": product_id,
            "project_id": target_project_id,
            "project_number": project_number,
            "trace_id": trace_id,
            "budget_ceiling_monthly_usd": initial_budget,
            "devops_sa_email": self.devops_sa_email,
            "provenance_status": provenance_status,
            "org_policies": org_policy_results,
            "api_enablement": api_enablement,
            "cc_log_reader": cc_log_reader,
            "auth_config": {
                "auth_provider": "identity_platform",
                "idp_provider": "google.com",
                "identity_platform_enabled": True,
            },
        }
        if runner_identity is not None:
            result["runner_identity"] = runner_identity
        return result

    def _grant_child_project_owners(self, project_id: str) -> List[str]:
        """B1: roles/owner for each member of STACKVEND_CHILD_PROJECT_OWNER_MEMBERS (comma-separated IAM members, e.g.
        `serviceAccount:sa@p.iam.gserviceaccount.com`) on a project vending created in this call. REST getIamPolicy /
        setIamPolicy over an AuthorizedSession (dg.RestCRM). Unset or empty -> no-op. A malformed member, an API error
        that survives 3 attempts (404 / etag conflict / 429 / 5xx right after creation), or a returned policy without the
        members raises RuntimeError("CHILD_OWNER_GRANT_FAILED ...") so the vend fails. Never touches other bindings."""
        raw = os.getenv("STACKVEND_CHILD_PROJECT_OWNER_MEMBERS") or ""
        members = list(dict.fromkeys(m.strip() for m in raw.split(",") if m.strip()))
        if not members:
            return []
        for m in members:
            kind, sep, ident = m.partition(":")
            if not sep or kind not in CHILD_OWNER_MEMBER_TYPES or not ident or ident != ident.strip():
                logger.error(f"CHILD_OWNER_GRANT_FAILED: invalid member {m!r} in STACKVEND_CHILD_PROJECT_OWNER_MEMBERS")
                raise RuntimeError(f"CHILD_OWNER_GRANT_FAILED: invalid member {m!r} in "
                                   "STACKVEND_CHILD_PROJECT_OWNER_MEMBERS (expected <user|serviceAccount|group>:<email>)")
        last_err: Optional[Exception] = None
        for attempt in range(1, CHILD_OWNER_GRANT_ATTEMPTS + 1):
            try:
                policy = self.iam_client.get_iam_policy(project_id)
                policy = dict(policy) if isinstance(policy, dict) else {}
                bindings = [dict(b) for b in (policy.get("bindings") or []) if isinstance(b, dict)]
                owner = next((b for b in bindings if b.get("role") == "roles/owner" and not b.get("condition")), None)
                if owner is None:
                    owner = {"role": "roles/owner", "members": []}
                    bindings.append(owner)
                owner["members"] = list(owner.get("members") or [])
                missing = [m for m in members if m not in owner["members"]]
                if not missing:
                    logger.info(f"Child-project owners already present on '{project_id}': {members}")
                    return members
                owner["members"].extend(missing)
                policy["bindings"] = bindings
                result = self.iam_client.set_iam_policy(project_id, policy)
                granted = next((b for b in ((result or {}).get("bindings") or [])
                                if isinstance(b, dict) and b.get("role") == "roles/owner" and not b.get("condition")),
                               {})
                if not all(m in (granted.get("members") or []) for m in members):
                    raise RuntimeError("setIamPolicy returned a policy without the requested owners")
                logger.info(f"Granted roles/owner on '{project_id}' to {members} (STACKVEND_CHILD_PROJECT_OWNER_MEMBERS)")
                return members
            except dg.CRMUnavailable as e:
                last_err = e
                if e.status not in CHILD_OWNER_GRANT_RETRY_STATUSES or attempt == CHILD_OWNER_GRANT_ATTEMPTS:
                    break
                logger.warning(f"Child-owner grant on '{project_id}' attempt {attempt} failed ({e}); retrying")
                time.sleep(self.owner_grant_retry_delay)
            except Exception as e:  # noqa: BLE001
                last_err = e
                break
        logger.error(f"CHILD_OWNER_GRANT_FAILED on '{project_id}': {last_err}")
        raise RuntimeError(f"CHILD_OWNER_GRANT_FAILED on '{project_id}': {last_err}. The project exists without "
                           f"billing, provenance or tag: delete projects/{project_id} by hand, then retry the vend "
                           "(a retried vend would adopt the existing project without owners, provenance or tag).")

    def _grant_cc_log_reader(self, project_id: str) -> str:
        """RT14-31 / D4: roles/logging.viewer on `project_id` for the Control Center's runtime SA. Returns the typed
        state (GRANTED / ALREADY_GRANTED); raises VendingFailure(VENDING.CC_LOG_READER_GRANT_FAILED, stage
        vending.cc_log_reader) when it cannot be made or confirmed."""
        hosts = frozenset(v for v in (self.platform_project_id, (os.getenv("PROJECT_ID") or "").strip(),
                                      (os.getenv("PLATFORM_PROJECT_ID") or "").strip()) if v)
        try:
            member = ccl.control_center_member(self.platform_project_id)
            return ccl.ensure_grant(self.iam_client, project_id, host_project_ids=hosts, member=member,
                                    retry_delay=self.owner_grant_retry_delay)
        except ccl.CCLogReaderGrantError as e:
            logger.error(f"{ccl.CC_LOG_READER_GRANT_FAILED} on '{project_id}': {e.detail}")
            raise VendingFailure(ccl.CC_LOG_READER_GRANT_FAILED,
                                 f"{e.detail} The project is vended and recorded; re-run the vend once the grant can "
                                 "be made (it reuses this project).",
                                 stage=ccl.CC_LOG_READER_STAGE) from e

    def _keep_unbilled_project_recoverable(
        self,
        *,
        product_id: str,
        trace_id: str,
        project_id: str,
        created_in_this_call: bool,
        crm_create_operation: Optional[str],
        is_sandbox: bool,
        sandbox_auto_decommission: bool,
        sandbox_designation_source: Optional[str],
        sandbox_ttl_days: Optional[int],
        failure: VendingFailure,
        project_number: str = "",
    ) -> None:
        """FD-4AI: before a BILLING_NOT_LINKED vend fails, keep the child project it may just have created
        recoverable. A project created in this call gets its provenance at birth (so StackVend can still delete it),
        and the workload record names the project with the failure, so a re-run after the billing permission is fixed
        reuses this project instead of creating another. Best effort: never replaces the typed failure.
        VENDING-READ-TRANSIENT: the number is the create operation's answer (`project_number`) when it gave one, else
        a Resource Manager read (read again after a transient error); the provenance outcome is recorded on the
        workload record as `provenance_status`, next to the failure."""
        provenance_status: Optional[str] = None
        if created_in_this_call and self.crm:
            if not project_number:
                try:
                    p_desc = self._get_project(project_id, "project number of the unbilled project")[1]
                    if isinstance(p_desc, dict):
                        project_number = p_desc.get("projectNumber") or p_desc.get("name", "").split("/")[-1]
                except Exception as pn_err:
                    logger.warning(f"Could not resolve the project number of unbilled '{project_id}': {pn_err}")
            try:
                provenance_status = self._record_provenance_at_birth(
                    product_id=product_id, trace_id=trace_id, project_id=project_id, project_number=project_number,
                    crm_create_operation=crm_create_operation, labelled=_is_label_value(product_id),
                    is_sandbox=is_sandbox, sandbox_auto_decommission=sandbox_auto_decommission,
                    sandbox_designation_source=sandbox_designation_source, sandbox_ttl_days=sandbox_ttl_days,
                )
            except Exception as prov_err:
                logger.error(f"Provenance of unbilled project '{project_id}' was not recorded: {prov_err}")
                provenance_status = "PROVENANCE_WRITE_FAILED"
        if self.db and product_id:
            record = {
                "project_id": project_id,
                "failure_reason": str(failure),
                "vending_error_class": failure.error_class,
            }
            if provenance_status is not None:
                record["provenance_status"] = provenance_status
            try:
                self.db.collection("workloads").document(product_id).set(record, merge=True)
            except Exception as rec_err:
                logger.error(f"Could not record the BILLING_NOT_LINKED failure on workloads/{product_id}: {rec_err}")

    def _record_repository_failure(self, product_id: str, gcp_res: Any, err: Exception) -> "VendingFailure":
        """GITHUB-ORG-ONLY / GITHUB-REPO-CREATE-FAIL-LOUD: the repository step failed with a typed GitHub error.
        Record its class and stage on workloads/{pid} (merge, best effort: a write error is logged and never replaces
        the failure) and hand back the VendingFailure to raise. The project vended before this step is named.
        GITHUB-REPO-NAME-NO-PREFIX: GITHUB_REPOSITORY_NAME_TAKEN also clears `github_repo` (RT F5: the refused
        repository is never left as the workload's; the name is the default, so nothing an operator typed is
        lost)."""
        error_class = getattr(err, "error_class", REPOSITORY_VEND_FAILED)
        stage = getattr(err, "stage", "vcs_repository_vending")
        text = str(err)
        prefix = f"{error_class}: "   # RT F7: the typed messages start with their class; VendingFailure adds it once
        failure = VendingFailure(error_class, text[len(prefix):] if text.startswith(prefix) else text, stage=stage)
        if self.db and product_id:
            record = {"failure_reason": text, "vending_error_class": error_class, "vending_error_stage": stage}
            if isinstance(err, GitHubRepositoryNameTakenError):
                record["github_repo"] = None
            project_id = gcp_res.get("project_id") if isinstance(gcp_res, dict) else None
            if project_id:
                record["project_id"] = project_id
            try:
                self.db.collection("workloads").document(product_id).set(record, merge=True)
            except Exception as rec_err:
                logger.error(f"Could not record the {error_class} failure on workloads/{product_id}: {rec_err}")
        logger.error(f"{error_class} ({stage}): {err}")
        return failure

    def _record_unprovenanced_project(self, product_id: str, project_id: str,
                                      failure: VendingFailure) -> VendingFailure:
        """VENDING-READ-TRANSIENT (OQ-28): a project created in this call is failing the vend before its provenance
        (its number is unknown). Name the project with the failure on the workload record (merge, as the
        BILLING_NOT_LINKED path does) so it is not lost, then hand the failure back to be raised. Best effort: a
        record write error is logged and never replaces the typed failure."""
        if self.db and product_id:
            try:
                self.db.collection("workloads").document(product_id).set({
                    "project_id": project_id,
                    "failure_reason": str(failure),
                    "vending_error_class": failure.error_class,
                    "provenance_status": "PROVENANCE_SKIPPED_NO_NUMBER",
                }, merge=True)
            except Exception as rec_err:
                logger.error(f"Could not record the {failure.error_class} failure on workloads/{product_id}: {rec_err}")
        logger.error(f"{failure.error_class}: {failure.detail}")
        return failure

    def _record_provenance_at_birth(
        self,
        *,
        product_id: str,
        trace_id: str,
        project_id: str,
        project_number: str,
        crm_create_operation: Optional[str],
        labelled: bool,
        is_sandbox: bool,
        sandbox_auto_decommission: bool,
        sandbox_designation_source: Optional[str],
        sandbox_ttl_days: Optional[int],
    ) -> str:
        """Tag binding + workload_provenance record. Never fails the vend: a project without them is simply never
        deletable by StackVend (fail closed). Returns a status string for the vend result and logs."""
        number = dg._num(project_number)
        if not number:
            logger.error(f"PROVENANCE_SKIPPED: project number of '{project_id}' unresolved; never deletable by StackVend.")
            return "PROVENANCE_SKIPPED_NO_NUMBER"

        tag_value = dg._env_tag_value(os.getenv("STACKVEND_MANAGED_TAG_VALUE"))
        tag_bound = False
        if not tag_value:
            logger.warning(f"TAG_UNCONFIGURED: STACKVEND_MANAGED_TAG_VALUE unset/invalid; '{project_id}' is not tagged "
                           "and will never be deletable by StackVend (fail closed).")
        else:
            try:
                self.crm.tagBindings().create(
                    body={"parent": f"//cloudresourcemanager.googleapis.com/projects/{number}", "tagValue": tag_value}
                ).execute()
                tag_bound = True
            except Exception as tag_err:
                logger.error(f"TAG_BINDING_FAILED on projects/{number}: {tag_err}")

        now = datetime.now(timezone.utc)
        sandbox = is_sandbox is True
        ttl_days = sandbox_ttl_days if (sandbox and isinstance(sandbox_ttl_days, int)
                                        and not isinstance(sandbox_ttl_days, bool)
                                        and 0 < sandbox_ttl_days <= MAX_SANDBOX_TTL_DAYS) else None
        source = sandbox_designation_source if (sandbox and sandbox_designation_source in VEND_DESIGNATION_SOURCES) else None
        record = {
            "created_by": dg.CREATED_BY_VENDING,
            "crm_create_operation": crm_create_operation,
            "product_id": product_id,
            "project_id": project_id,
            "project_number": number,
            "created_at": now.isoformat(),
            "trace_id": trace_id,
            "labels_written": labelled,
            "tag_bound": tag_bound,
            "is_sandbox": sandbox,
            "sandbox_auto_decommission": sandbox and sandbox_auto_decommission is True,
            "sandbox_designation_source": source,
            "sandbox_ttl_days": ttl_days,
            "sandbox_expires_at": (now + timedelta(days=ttl_days)).isoformat() if ttl_days else None,
            "extensions": 0,
            "liens": [],
            "dns_records": [],
        }
        store = self.guard_context().store
        try:
            store.create_provenance(product_id, record)
        except Exception as prov_err:
            logger.error(f"PROVENANCE_WRITE_FAILED for '{product_id}': {prov_err}")
            return "PROVENANCE_WRITE_FAILED"
        logger.info(f"Recorded provenance at birth for '{product_id}' -> projects/{number} (tag_bound={tag_bound})")
        return "RECORDED" if tag_bound else "RECORDED_UNTAGGED"

    def fetch_oauth_credentials(self) -> Dict[str, str]:
        """
        Retrieves the platform Google OAuth 2.0 client id and secret from host Secret Manager.

        Lane 19 L19-12 (plan §2.5 / RT F16(8), required-components rule: kept and fixed, not removed): fail closed.
        There is no environment-variable fallback (``OAUTH_CLIENT_ID`` / ``OAUTH_CLIENT_SECRET`` are ignored) and no
        empty-string result: a missing Secret Manager client or project, a read error, or an empty secret raises
        ``RuntimeError`` naming the secret (never its value). The tenant secret names
        (``stackvend-tenant-google-client-{id,secret}``) replace these once L19-10 creates them.
        """
        if not self.secret_client or not self.platform_project_id:
            raise RuntimeError("OAuth credentials unavailable: no Secret Manager client or platform project configured")

        values: Dict[str, str] = {}
        for key, secret in (("client_id", "castor-oauth-client-id"), ("client_secret", "castor-oauth-client-secret")):
            name = f"projects/{self.platform_project_id}/secrets/{secret}/versions/latest"
            try:
                res = self.secret_client.access_secret_version(request={"name": name})
                value = res.payload.data.decode("utf-8").strip()
            except Exception as e:
                raise RuntimeError(f"Could not read {secret} from Secret Manager: {type(e).__name__}") from None
            if not value:
                raise RuntimeError(f"Secret {secret} is empty")
            values[key] = value
        return values

    def fetch_github_app_credentials(self) -> Dict[str, str]:
        """
        Retrieves GitHub App credentials from Secret Manager.
        Supports:
        1. Consolidated JSON payload: {"client_id": "...", "app_id": "...", "installation_id": "...", "private_key": "..."}
        2. Raw PEM private key string (falling back to environment variables for IDs)
        """
        if not self.secret_client or not self.platform_project_id:
            return {
                "client_id": os.getenv("GITHUB_CLIENT_ID") or os.getenv("GITHUB_APP_ID", ""),
                "app_id": os.getenv("GITHUB_APP_ID", ""),
                "installation_id": os.getenv("GITHUB_INSTALLATION_ID", ""),
                "private_key": os.getenv("GITHUB_APP_PRIVATE_KEY", ""),
            }

        try:
            name = f"projects/{self.platform_project_id}/secrets/castor-github-app-private-key/versions/latest"
            response = self.secret_client.access_secret_version(request={"name": name})
            payload_str = response.payload.data.decode("utf-8").strip()

            # Sanitize Mac smart quotes, curly quotes, and smart dashes (em/en dashes)
            clean_str = payload_str.replace("“", '"').replace("”", '"').replace("‘", "'").replace("’", "'")
            clean_str = clean_str.replace("—", "-").replace("–", "-")
            clean_str = re.sub(r'[-—–]{2,}\s*BEGIN\s+([A-Z\s]+)?PRIVATE\s+KEY\s*[-—–]{2,}', '-----BEGIN RSA PRIVATE KEY-----', clean_str)
            clean_str = re.sub(r'[-—–]{2,}\s*END\s+([A-Z\s]+)?PRIVATE\s+KEY\s*[-—–]{2,}', '-----END RSA PRIVATE KEY-----', clean_str)

            # 1. Attempt parsing with strict=False to allow multiline unescaped PEM strings
            if clean_str.startswith("{") and clean_str.endswith("}"):
                try:
                    data = json.loads(clean_str, strict=False)
                    return {
                        "app_id": str(data.get("app_id") or data.get("client_id", "")),
                        "client_id": str(data.get("client_id") or data.get("app_id", "")),
                        "installation_id": str(data.get("installation_id", "")),
                        "private_key": data.get("private_key", "").strip(),
                        "pat": str(data.get("pat") or data.get("personal_access_token") or data.get("github_token", "")).strip(),
                    }
                except Exception as json_err:
                    logger.warning(f"Could not parse GitHub App JSON with strict=False: {json_err}")

            # 2. Regex fallback to extract IDs, PAT, and PEM block from non-standard JSON / multiline text
            app_id_match = re.search(r'["\']?app_id["\']?\s*:\s*["\']?(\d+)["\']?', clean_str)
            inst_id_match = re.search(r'["\']?installation_id["\']?\s*:\s*["\']?(\d+)["\']?', clean_str)
            client_id_match = re.search(r'["\']?client_id["\']?\s*:\s*["\']?([a-zA-Z0-9_-]+)["\']?', clean_str)
            pat_match = re.search(r'["\']?(?:pat|personal_access_token|github_token)["\']?\s*:\s*["\']?([a-zA-Z0-9_]+)["\']?', clean_str)
            pem_match = re.search(r'(-----BEGIN [A-Z\s]+PRIVATE KEY-----[\s\S]+?-----END [A-Z\s]+PRIVATE KEY-----)', clean_str)

            if pem_match:
                return {
                    "app_id": app_id_match.group(1) if app_id_match else (os.getenv("GITHUB_APP_ID") or ""),
                    "client_id": client_id_match.group(1) if client_id_match else (os.getenv("GITHUB_CLIENT_ID") or ""),
                    "installation_id": inst_id_match.group(1) if inst_id_match else (os.getenv("GITHUB_INSTALLATION_ID") or ""),
                    "private_key": pem_match.group(1).strip(),
                    "pat": pat_match.group(1) if pat_match else (os.getenv("GITHUB_PAT") or os.getenv("GITHUB_TOKEN") or ""),
                }

            # 3. Treat as raw PEM string, reading IDs from environment variables if set
            return {
                "app_id": os.getenv("GITHUB_APP_ID") or os.getenv("GITHUB_CLIENT_ID", ""),
                "client_id": os.getenv("GITHUB_CLIENT_ID") or os.getenv("GITHUB_APP_ID", ""),
                "installation_id": os.getenv("GITHUB_INSTALLATION_ID", ""),
                "private_key": payload_str,
                "pat": os.getenv("GITHUB_PAT") or os.getenv("GITHUB_TOKEN") or "",
            }
        except Exception as e:
            logger.warning(f"Could not fetch GitHub App credentials from Secret Manager: {e}")
            return {
                "app_id": os.getenv("GITHUB_APP_ID") or os.getenv("GITHUB_CLIENT_ID", ""),
                "client_id": os.getenv("GITHUB_CLIENT_ID") or os.getenv("GITHUB_APP_ID", ""),
                "installation_id": os.getenv("GITHUB_INSTALLATION_ID", ""),
                "private_key": os.getenv("GITHUB_APP_PRIVATE_KEY", ""),
                "pat": os.getenv("GITHUB_PAT") or os.getenv("GITHUB_TOKEN") or "",
            }

    def generate_github_jit_token(
        self,
        app_id: Optional[str] = None,
        installation_id: Optional[str] = None,
    ) -> str:
        """
        Retrieves a cached 1-hour Installation Access Token from GitHubTokenManager,
        falling back to local token synthesis if needed.
        """
        cached_token = get_github_token(self.platform_project_id)
        if cached_token:
            return cached_token

        creds = self.fetch_github_app_credentials()
        # GitHub App JWTs MUST use the numeric App ID as 'iss'
        iss_id = app_id or creds.get("app_id") or os.getenv("GITHUB_APP_ID") or creds.get("client_id") or os.getenv("GITHUB_CLIENT_ID", "")
        inst_id = installation_id or creds.get("installation_id") or os.getenv("GITHUB_INSTALLATION_ID", "")
        private_key = creds.get("private_key", "")

        if not private_key or not iss_id or not inst_id:
            logger.info("GitHub App credentials not fully configured. Using GITHUB_TOKEN fallback.")
            return creds.get("pat") or os.getenv("GITHUB_TOKEN", "")

        try:
            now = int(time.time())
            payload = {
                "iat": now - 60,
                "exp": now + 600,
                "iss": str(iss_id),
            }
            encoded_jwt = jwt.encode(payload, private_key, algorithm="RS256")

            import httpx
            headers = {
                "Authorization": f"Bearer {encoded_jwt}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            url = f"https://api.github.com/app/installations/{inst_id}/access_tokens"
            with httpx.Client(timeout=15.0) as client:
                res = client.post(url, headers=headers)
                if res.status_code >= 400:
                    logger.warning(f"GitHub JIT Token API returned {res.status_code}: {res.text}")
                res.raise_for_status()
                token_data = res.json()
                logger.info(f"Minted 1-hour GitHub JIT token for installation {inst_id}")
                return token_data.get("token", "")
        except Exception as e:
            logger.warning(f"Failed to generate GitHub JIT token: {e}")
            return creds.get("pat") or os.getenv("GITHUB_TOKEN", "")

    # FD-7L (plan 2.10): the runner's repository token -- one repository, contents:read. GitHub always adds
    # metadata:read; any other permission in the answer refuses the token.
    RUNNER_REPO_TOKEN_PERMISSIONS = {"contents": "read"}
    RUNNER_REPO_TOKEN_ALLOWED_ANSWER = {"contents": "read", "metadata": "read"}

    def mint_repository_read_token(self, full_name: str, repository_id: Optional[str] = None,
                                   http_post: Optional[Any] = None) -> Dict[str, Any]:
        """A GitHub App installation token restricted to `full_name` (by its pinned numeric id when known) with
        contents:read only. Unlike generate_github_jit_token there is no cache, no PAT and no GITHUB_TOKEN
        fallback: missing App credentials or any GitHub failure raise RUNNER_REPO_TOKEN_UNAVAILABLE (fail closed)."""
        def _fail(why: str):
            raise ri.RunnerIdentityError("RUNNER_REPO_TOKEN_UNAVAILABLE", f"{full_name}: {why}", http_status=503)

        owner, sep, name = (full_name or "").partition("/")
        if not sep or not owner or not name or "/" in name:
            _fail("not an owner/name repository")
        creds = self.fetch_github_app_credentials()
        iss_id = creds.get("app_id") or creds.get("client_id")
        inst_id = creds.get("installation_id")
        private_key = creds.get("private_key")
        if not private_key or not iss_id or not inst_id:
            _fail("GitHub App credentials are not configured")
        body: Dict[str, Any] = {"permissions": dict(self.RUNNER_REPO_TOKEN_PERMISSIONS)}
        if repository_id is not None and str(repository_id).isdigit():
            body["repository_ids"] = [int(repository_id)]
        else:
            body["repositories"] = [name]
        now = int(time.time())
        try:
            encoded_jwt = jwt.encode({"iat": now - 60, "exp": now + 600, "iss": str(iss_id)}, private_key,
                                     algorithm="RS256")
        except Exception as e:  # noqa: BLE001
            _fail(f"App JWT not signed ({type(e).__name__})")
        headers = {"Authorization": f"Bearer {encoded_jwt}", "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28"}
        url = f"https://api.github.com/app/installations/{inst_id}/access_tokens"
        try:
            if http_post is None:
                import httpx
                with httpx.Client(timeout=15.0) as client:
                    res = client.post(url, headers=headers, json=body)
            else:
                res = http_post(url, headers=headers, json=body)
            data = res.json() if res.status_code == 201 else None
        except Exception as e:  # noqa: BLE001
            _fail(f"GitHub call failed ({type(e).__name__})")
        if not isinstance(data, dict) or not isinstance(data.get("token"), str) or not data["token"]:
            _fail(f"GitHub answered HTTP {getattr(res, 'status_code', None)}")
        perms = data.get("permissions")
        if not isinstance(perms, dict) or perms.get("contents") != "read" \
                or any(self.RUNNER_REPO_TOKEN_ALLOWED_ANSWER.get(k) != v for k, v in perms.items()):
            _fail("GitHub granted permissions beyond contents:read")
        repos = data.get("repositories")
        if not isinstance(repos, list) or len(repos) != 1 or not isinstance(repos[0], dict) \
                or str(repos[0].get("full_name", "")).lower() != full_name.lower():
            _fail("GitHub did not scope the token to exactly this repository")
        return {"token": data["token"], "expires_at": data.get("expires_at")}

    @staticmethod
    def _github_repository_id(vcs: Any, meta: Any) -> Optional[int]:
        """FD-4AT-c: GitHub's immutable numeric id of the repository `vend_repository` returned, read with the same
        provider's GitHub client. None (never an exception) for a non-GitHub provider, an unreadable repository or a
        repository whose current name differs (GitHub follows renames; the id would then belong to another name)."""
        if str(getattr(meta, "provider", "")).upper() != "GITHUB" or not callable(getattr(vcs, "get_client", None)):
            return None
        full_name = getattr(meta, "full_name", "") or ""
        try:
            client = vcs.get_client()
            repo = client.get_repo(full_name) if client is not None else None
        except Exception as e:
            logger.warning(f"FD-4AT-c: could not read the GitHub repository id of '{full_name}' ({e}); the workload's "
                           f"WIF condition keeps the repository name + main-branch check.")
            return None
        if repo is None or str(getattr(repo, "full_name", "")).lower() != full_name.lower():
            return None
        return getattr(repo, "id", None)

    def _lookup_github_repository_id(self, full_name: str, github_owner: Optional[str] = None,
                                     product_id: Optional[str] = None) -> Optional[int]:
        """FD-4AT-c, reused repositories (vend_all does not call vend_github_repo for them): one GitHub read through
        the GitHub provider's client. None when the gateway is unavailable or the read fails."""
        if VCSProviderFactory is None:
            return None
        try:
            vcs = VCSProviderFactory.get_provider(provider_name="GITHUB", default_owner=github_owner or self.github_owner,
                                                  project_id=self.platform_project_id, product_id=product_id)
        except Exception as e:
            logger.warning(f"FD-4AT-c: no GitHub provider to read the repository id of '{full_name}' ({e}).")
            return None
        return self._github_repository_id(vcs, SimpleNamespace(provider="GITHUB", full_name=full_name))

    def _next_repo_identity(self, existing: Any, repo_full_name: str, github_res: Dict[str, Any], reused: bool,
                            github_owner: Optional[str] = None, product_id: Optional[str] = None) -> Optional[dict]:
        """FD-4AT-c: the repository-id record to write on workloads/{pid}, or None to keep the stored one
        (shared.github_identity.next_github_repository_identity: a valid recorded id is never silently replaced).
        A reused repository is read from GitHub only when no valid id is recorded for it yet."""
        if reused:
            if pinned_github_repository_id(existing, repo_full_name):
                return None
            resolved, created = self._lookup_github_repository_id(repo_full_name, github_owner, product_id), False
        else:
            resolved, created = github_res.get("repository_id"), github_res.get("reused_existing") is False
        record = next_github_repository_identity(existing, repo_full_name, resolved, repository_created=created)
        stored = pinned_github_repository_id(existing, repo_full_name)
        if record is None and stored and resolved is not None and str(resolved) != stored:
            logger.warning(f"FD-4AT-c: GitHub reports id {resolved} for '{repo_full_name}' but id {stored} is recorded "
                           f"(repository re-created?). Keeping the recorded id: CI deploys from the new repository are "
                           f"refused until an operator clears workloads/{{pid}}.{GITHUB_REPOSITORY_IDENTITY_FIELD}.")
        return record

    @staticmethod
    def _refuse_unowned_repository(recorded_identity: Any, full_name: str, repository_id: Any, owner: Any,
                                   product_id: str) -> None:
        """GITHUB-REPO-NAME-NO-PREFIX: raise GitHubRepositoryNameTakenError unless the existing GitHub repository
        `full_name` is the workload's own (repository_is_workloads_own of its recorded identity), and
        GitHubRepositoryUnreadableError when that cannot be told (a pinned id against an id GitHub did not give: RT
        F4). Without shared.github_identity nothing proves ownership: refused."""
        own = repository_is_workloads_own(recorded_identity, full_name, repository_id) \
            if repository_is_workloads_own is not None else False
        if own is True:
            logger.info(f"GitHub repository '{full_name}' is workload '{product_id}''s own (recorded); reused.")
            return
        err: GitHubRepositoryCreateError
        if own is None:
            err = GitHubRepositoryUnreadableError(str(owner or ""), full_name, "the repository id could not be read")
        elif repository_names is not None and repository_names(recorded_identity, full_name):
            # RT D2: the workload's own recorded repository now has another GitHub id (deleted and re-created)
            err = GitHubRepositoryIdChangedError(str(owner or ""), full_name, product_id,
                                                 recorded_identity.get("repository_id"), repository_id)
        else:
            err = GitHubRepositoryNameTakenError(str(owner or ""), full_name, product_id)
        logger.error(str(err))
        raise err

    def _github_repository_presence(self, full_name: str, github_owner: Optional[str] = None,
                                    product_id: Optional[str] = None) -> Optional[bool]:
        """GITHUB-REPO-NAME-NO-PREFIX (RT F1): whether the GitHub repository `full_name` exists: True (GitHub returned
        it), False (GitHub answered 404), None (unknown: no authenticated client, or any other error). Read only, one
        GET through the GitHub provider's client (the token vending creates repositories with), else an installation
        token. Decided from GitHub's typed status only."""
        client = None
        try:
            if VCSProviderFactory is not None:
                vcs = VCSProviderFactory.get_provider(provider_name="GITHUB",
                                                      default_owner=github_owner or self.github_owner,
                                                      project_id=self.platform_project_id, product_id=product_id)
                has_token = not callable(getattr(vcs, "get_token", None)) or bool(vcs.get_token())
                if has_token and callable(getattr(vcs, "get_client", None)):
                    client = vcs.get_client()
            if client is None:
                token = self.generate_github_jit_token()
                client = Github(token) if token else None
        except Exception as e:  # noqa: BLE001 - no client: unknown, never "absent"
            logger.warning(f"GitHub client unavailable to check '{full_name}' ({type(e).__name__}: {e})")
            return None
        if client is None:
            return None
        try:
            repo = client.get_repo(full_name)
        except Exception as e:  # noqa: BLE001 - classified by GitHub's status only
            status = getattr(e, "status", None)
            if isinstance(status, int) and not isinstance(status, bool) and status == 404:
                return False
            logger.warning(f"GitHub could not be read for '{full_name}' ({type(e).__name__}: {e})")
            return None
        return True if repo is not None else None

    def _claim_repository(self, product_id: str, repo_identifier: Optional[str], github_owner: Optional[str],
                          recorded_identity: Any) -> Tuple[Any, bool]:
        """GITHUB-REPO-NAME-NO-PREFIX (RT F1/F2): before vending creates the workload's GitHub repository, record that
        the name is this workload's, so a create GitHub completed but answered with an error (5xx, timeout: the
        provider's retry or vending's direct path then finds the repository) and a vend interrupted before its record
        write still reuse the repository on the next attempt instead of refusing it.

        Returns (identity record to check ownership against, whether this call wrote the claim). Nothing is done when
        the record already names the repository. Otherwise: the repository must not exist (GitHub 404): an existing
        one raises GitHubRepositoryNameTakenError, an unknown answer GitHubRepositoryUnreadableError; then
        workloads/{pid}.github_repository_identity = {full_name, repository_id: None} is merge-written (a failed write
        raises RepositoryClaimNotRecordedError). Nothing is created by any of these failures."""
        if not (self.db and GITHUB_REPOSITORY_IDENTITY_FIELD and repository_names is not None
                and github_repository_identity_record is not None):
            return recorded_identity, False
        owner, _, full_name = resolve_repo_identity(repo_identifier or None,
                                                    default_owner=github_owner or self.github_owner,
                                                    product_id=product_id)
        if repository_names(recorded_identity, full_name):
            return recorded_identity, False
        presence = self._github_repository_presence(full_name, github_owner, product_id)
        if presence is True:
            raise GitHubRepositoryNameTakenError(str(owner or ""), full_name, product_id)
        if presence is None:
            raise GitHubRepositoryUnreadableError(str(owner or ""), full_name,
                                                  "whether the repository already exists could not be read")
        claim = github_repository_identity_record(full_name, None)
        try:
            self.db.collection("workloads").document(product_id).set(
                {GITHUB_REPOSITORY_IDENTITY_FIELD: claim}, merge=True)
        except Exception as e:  # noqa: BLE001 - no claim, no create
            raise RepositoryClaimNotRecordedError(str(owner or ""), full_name, product_id,
                                                  f"{type(e).__name__}: {e}") from e
        logger.info(f"Workload '{product_id}' claims the repository name '{full_name}' before creating it.")
        return claim, True

    @staticmethod
    def _repository_not_created(err: BaseException) -> bool:
        """GITHUB-REPO-NAME-NO-PREFIX: whether a failed repository step certainly created nothing, so the vend's own
        claim is withdrawn (it must never later make a repository someone else creates under the name "own"): an owner
        that is not an organization, or a GitHub 4xx that is not a rate limit (401, 403 permission, 404, 422 name
        exists). A 5xx, a rate limit, a timeout or an unknown status may follow a completed create: the claim stays,
        so the next run reuses the repository. Decided from GitHub's typed status / headers only."""
        if isinstance(err, GitHubOwnerNotOrganizationError):
            return True
        status = getattr(err, "status", None)
        if not isinstance(status, int) or isinstance(status, bool) or not 400 <= status < 500 or status == 429:
            return False
        try:   # the retry decorator's own status/header classifier (a rate-limit 403 may follow a completed create)
            from shared.github_resilience import extract_error_metadata, is_rate_limit_or_transient
        except ImportError:
            return status != 403
        return not is_rate_limit_or_transient(*extract_error_metadata(err))

    def vend_github_repo(
        self,
        product_id: str,
        github_owner: Optional[str] = None,
        auto_protect_branch: bool = True,
        vcs_provider: Optional[str] = None,
        repo_identifier: Optional[str] = None,
        initial_branch: str = "main",
        recorded_identity: Any = None,
        claim: bool = False,
    ) -> Dict[str, Any]:
        """Creates a new repository via the Universal VCS Gateway. FD-4CI-b-R1: a repository created here gets
        `initial_branch` as its default branch (GitHub and Serverless Git); an existing repository is not changed.

        GITHUB-REPO-NAME-NO-PREFIX (owner 11-12): a GitHub repository that already exists under the name is used only
        when it is the workload's own (`recorded_identity`, the workload's github_repository_identity record:
        shared.github_identity.repository_is_workloads_own); any other existing repository raises
        GitHubRepositoryNameTakenError before anything changes or records it. `claim` (vend_all): the name is claimed
        on workloads/{pid} before any create attempt (_claim_repository, RT F1/F2), so every retry below and the next
        run recognise a repository this vend created; a claim written here is withdrawn when the step fails and GitHub
        certainly created nothing (_repository_not_created), or (RT D1) when the failure leaves that open and GitHub
        then answers 404 for the name. The claim is made only when the workload's VCS provider resolves to GitHub
        (_resolved_vcs_provider, RT D3)."""
        claimed = False
        if claim and self._resolved_vcs_provider(vcs_provider) == "GITHUB":
            recorded_identity, claimed = self._claim_repository(product_id.strip().lower(), repo_identifier,
                                                                github_owner, recorded_identity)
        try:
            return self._vend_github_repo_attempts(product_id, github_owner=github_owner,
                                                   auto_protect_branch=auto_protect_branch, vcs_provider=vcs_provider,
                                                   repo_identifier=repo_identifier, initial_branch=initial_branch,
                                                   recorded_identity=recorded_identity)
        except Exception as repo_err:
            if claimed:
                withdraw = self._repository_not_created(repo_err)
                if not withdraw:
                    # RT D1: a 5xx / timeout / rate limit may follow a completed create. One more read: only a clean
                    # 404 proves nothing was created; any other answer keeps the claim for the next run.
                    withdraw = self._github_repository_presence(recorded_identity["full_name"], github_owner,
                                                                product_id.strip().lower()) is False
                if withdraw:
                    try:
                        self.db.collection("workloads").document(product_id.strip().lower()).set(
                            {GITHUB_REPOSITORY_IDENTITY_FIELD: None}, merge=True)
                        logger.info(f"Claim on '{recorded_identity['full_name']}' withdrawn: nothing was created.")
                    except Exception as e:  # noqa: BLE001 - the typed failure below is what the caller gets
                        logger.error(f"REPOSITORY_CLAIM_NOT_WITHDRAWN: workloads/{product_id}: "
                                     f"{type(e).__name__}: {e}")
            raise

    @staticmethod
    def _resolved_vcs_provider(vcs_provider: Optional[str]) -> str:
        """RT D3: the workload's VCS provider as the provider factory resolves it (shared.vcs_provider
        VCSProviderFactory.get_provider): the workload's own value (vend_all passes the record's), else the platform
        setting (governance.vcs_provider, whose reader falls back to $VCS_PROVIDER), else $VCS_PROVIDER, else GITHUB.
        Never "missing = GitHub" while the install says otherwise."""
        if isinstance(vcs_provider, str) and vcs_provider.strip():
            return vcs_provider.strip().upper()
        configured = None
        try:
            from shared.settings import get_platform_settings
            configured = get_platform_settings().vcs_provider
        except Exception as e:  # noqa: BLE001 - unreadable settings: the environment decides, as in the factory
            logger.warning(f"VCS provider setting unreadable ({type(e).__name__}); using $VCS_PROVIDER")
        return str(configured or os.getenv("VCS_PROVIDER") or "GITHUB").strip().upper()

    @github_retry_with_backoff(max_retries=3, initial_wait=2.0)
    def _vend_github_repo_attempts(
        self,
        product_id: str,
        github_owner: Optional[str] = None,
        auto_protect_branch: bool = True,
        vcs_provider: Optional[str] = None,
        repo_identifier: Optional[str] = None,
        initial_branch: str = "main",
        recorded_identity: Any = None,
    ) -> Dict[str, Any]:
        """vend_github_repo's create-or-reuse attempts (retried on GitHub rate limits and 5xx; the claim, if any, is
        already in `recorded_identity`)."""
        if not vcs_provider and self.db:
            try:
                doc = self.db.collection("workloads").document(product_id).get()
                if doc.exists:
                    vcs_provider = doc.to_dict().get("vcs_provider")
            except Exception:
                pass

        if VCSProviderFactory is not None:
            try:
                vcs = VCSProviderFactory.get_provider(
                    provider_name=vcs_provider,
                    default_owner=github_owner or self.github_owner,
                    project_id=self.platform_project_id,
                    product_id=product_id,
                )
                meta = vcs.vend_repository(
                    product_id,
                    github_owner=github_owner or self.github_owner,
                    auto_protect_branch=auto_protect_branch,
                    repo_identifier=repo_identifier,
                    initial_branch=initial_branch,
                )
                status_code = "REPO_VENDED" if not meta.is_reused else "REPO_REUSED"
                repository_id = self._github_repository_id(vcs, meta)
                if meta.is_reused and str(getattr(meta, "provider", "")).upper() == "GITHUB":
                    if repository_id is None:   # RT F4: one more read before "unknown"
                        repository_id = self._github_repository_id(vcs, meta)
                    self._refuse_unowned_repository(recorded_identity, meta.full_name, repository_id,
                                                    github_owner or self.github_owner, product_id)
                return {
                    "status": status_code,
                    "repo_name": meta.repo_name,
                    "full_name": meta.full_name,
                    "html_url": meta.html_url,
                    "clone_url": meta.clone_url_http,
                    "reused_existing": meta.is_reused,
                    "vcs_provider": getattr(meta, "provider", vcs_provider or "GITHUB"),
                    "repository_id": repository_id,
                }
            except (GitHubOwnerNotOrganizationError, GitHubRepositoryNameTakenError, GitHubRepositoryUnreadableError,
                    GitHubRepositoryIdChangedError):
                raise   # GITHUB-ORG-ONLY / GITHUB-REPO-NAME-NO-PREFIX: refused, never retried by the direct path below
            except Exception as e:
                logger.warning(f"VCSProvider vend_repository notice ({e}); falling back to direct creation.")
                if str(vcs_provider).strip().upper() == "SERVERLESS_GIT":
                    raise RuntimeError(f"Serverless Git repository vending failed for '{product_id}': {e}")

        owner, repo_name, full_name = resolve_repo_identity(
            repo_identifier,
            default_owner=github_owner or self.github_owner,
            product_id=product_id,
        )
        creds = self.fetch_github_app_credentials()
        jit_token = self.generate_github_jit_token()
        pat_token = creds.get("pat") or os.getenv("GITHUB_PAT") or os.getenv("GITHUB_TOKEN", "")

        # Try accessing / creating repository using JIT token or fallback PAT
        last_error: Optional[BaseException] = None   # GITHUB-REPO-CREATE-FAIL-LOUD: what the last attempt answered
        for token_candidate in [jit_token, pat_token]:
            if not token_candidate:
                continue
            try:
                gh = Github(token_candidate)
                repo = None
                created_here = False
                # Check if repo already exists
                try:
                    repo = gh.get_repo(full_name)
                    logger.info(f"GitHub repository already exists: {repo.html_url}")
                except Exception:
                    pass
                if repo is not None:   # GITHUB-REPO-NAME-NO-PREFIX: checked before the edit below touches it
                    self._refuse_unowned_repository(recorded_identity, getattr(repo, "full_name", full_name),
                                                    getattr(repo, "id", None), owner, product_id)

                if repo is None:
                    created_here = True
                    # GITHUB-ORG-ONLY: organization repository creation only. An owner that is not an organization
                    # raises GitHubOwnerNotOrganizationError (no personal-account fallback).
                    org = require_github_organization(gh, owner)
                    try:
                        repo = org.create_repo(
                            name=repo_name,
                            description=f"Managed service repository for {product_id} (StackVend)",
                            auto_init=True,
                            private=True,
                        )
                    except Exception as create_err:
                        last_error = create_err
                        logger.warning(f"Token could not create repository ({create_err}). Trying fallback...")
                        continue

                if repo:
                    try:
                        repo.edit(delete_branch_on_merge=True)
                    except Exception:
                        pass
                    if created_here:
                        _apply_initial_branch(repo, initial_branch)   # FD-4CI-b-R1 (a new repository only)
                    logger.info(f"Successfully vended GitHub repository: {repo.html_url}")
                    return {
                        "status": "REPO_VENDED",
                        "repo_name": repo_name,
                        "full_name": repo.full_name,
                        "html_url": repo.html_url,
                        "clone_url": repo.clone_url,
                        "reused_existing": not created_here,
                        "repository_id": getattr(repo, "id", None),  # FD-4AT-c (validated when recorded)
                    }
            except (GitHubOwnerNotOrganizationError, GitHubRepositoryNameTakenError, GitHubRepositoryUnreadableError,
                    GitHubRepositoryIdChangedError):
                raise
            except Exception as e:
                last_error = e
                logger.warning(f"GitHub repository creation attempt failed: {e}")

        # GITHUB-REPO-CREATE-FAIL-LOUD (owner 11-12): no token created or found the repository. A typed failure with
        # GitHub's own status; this used to return a made-up "mock" repository result, which vend_all took as success.
        if last_error is not None:
            raise GitHubRepositoryCreateError.from_exception(owner, full_name, last_error) from last_error
        raise GitHubRepositoryCreateError(owner, full_name, None,
                                          "no GitHub token: the GitHub App credentials are missing or unusable")

    def vend_all(
        self,
        product_id: str,
        trace_id: str,
        initial_budget: Optional[float] = None,
        folder_id: Optional[str] = None,
        billing_account_id: Optional[str] = None,
        github_owner: Optional[str] = None,
        force_new_project_id: Optional[str] = None,
        vcs_provider: Optional[str] = None,
        is_sandbox: bool = False,
        sandbox_auto_decommission: bool = False,
        sandbox_designation_source: Optional[str] = None,
        sandbox_ttl_days: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Atomic vending pipeline: creates GCP Project, links Billing, creates GitHub repo, registers in Firestore."""
        clean_pid = product_id.strip().lower()
        runner_mode = self.runner_identity_mode()   # FD-7L-F4 RT M2: the one mode snapshot of this vend
        existing_repo = None
        existing_repo_identity = None  # FD-4AT-c
        is_promoted = False
        is_brownfield = False
        recorded_branch = None  # FD-4CI-b-R1: the workload's recorded branch (kept as it is)
        stored_record: Dict[str, Any] = {}   # OQ-15: the record as read (a promoted workload's first-vend secrets)
        if self.db:
            try:
                doc = self.db.collection("workloads").document(clean_pid).get()
                if doc.exists:
                    wdata = doc.to_dict() or {}
                    stored_record = wdata if isinstance(wdata, dict) else {}
                    existing_repo = wdata.get("github_repo")
                    if GITHUB_REPOSITORY_IDENTITY_FIELD:
                        existing_repo_identity = wdata.get(GITHUB_REPOSITORY_IDENTITY_FIELD)
                    is_promoted = bool(wdata.get("promoted_from_product_id"))
                    is_brownfield = bool(wdata.get("is_brownfield") or wdata.get("track") == "BYO_IAC")
                    recorded_branch = wdata.get("default_branch") or None
                    if not vcs_provider:
                        vcs_provider = wdata.get("vcs_provider")
            except Exception as e:
                # RT F6 (GITHUB-REPO-NAME-NO-PREFIX): never continue without the record (the default repository is
                # not a recorded castor-<id> one). Nothing is created; the next run reads it again.
                logger.error(f"{WORKLOAD_RECORD_UNREADABLE}: workloads/{clean_pid} could not be read: {e}")
                raise VendingFailure(WORKLOAD_RECORD_UNREADABLE,
                                     f"workloads/{clean_pid} could not be read ({type(e).__name__}); nothing was "
                                     f"vended. Run the workload again.") from e

        # Lane 18 window RT H7: the project, its labels, the provenance record and the ledger doc are keyed by the
        # same normalized id this method reads the ledger with (callers send lowercase today; identical for them).
        gcp_res = self.vend_gcp_project(
            clean_pid,
            trace_id,
            folder_id=folder_id,
            billing_account_id=billing_account_id,
            initial_budget=initial_budget,
            force_new_project_id=force_new_project_id,
            is_sandbox=is_sandbox,
            sandbox_auto_decommission=sandbox_auto_decommission,
            sandbox_designation_source=sandbox_designation_source,
            sandbox_ttl_days=sandbox_ttl_days,
            runner_mode=runner_mode,
        )

        is_serverless_git = (
            str(vcs_provider).strip().upper() == "SERVERLESS_GIT"
            or (existing_repo and "serverless-git" in str(existing_repo).lower())
        )
        # FD-4CI-b-R1: the recorded branch wins (existing workloads keep theirs); a workload with no recorded branch
        # and no repository yet (its first vend) gets Settings > Default GitHub Branch; a recorded repository with no
        # recorded branch is a workload from before branches were recorded: main, as before.
        if recorded_branch:
            default_branch = recorded_branch
        elif not existing_repo:
            default_branch = _platform_default_branch(self.platform_project_id)
        else:
            default_branch = "main"

        owner, repo_name, repo_full_name = resolve_repo_identity(
            existing_repo,
            default_owner=github_owner or self.github_owner,
            product_id=product_id,
        ) if existing_repo else (None, None, None)

        # Only reuse without creation if this workload is explicitly promoting from an existing workload,
        # is an adopted brownfield project, or maps to a different repo name. For greenfield workloads,
        # vend_github_repo ensures the repo is created on GitHub (an existing one is reused there, unchanged, only when
        # it is this workload's own: GITHUB-REPO-NAME-NO-PREFIX, else GITHUB_REPOSITORY_NAME_TAKEN). A recorded name
        # other than the workload id (an operator-named repository, or a workload vended before 11-12 with its
        # `castor-<id>` repository) is used as recorded, as before.
        # FD-4CI-b-R1: a branch other than main no longer means "reuse an existing repository".
        should_reuse_existing = (
            bool(existing_repo)
            and not is_serverless_git
            and (
                is_promoted
                or is_brownfield
                or (repo_name and repo_name.lower() != clean_pid)
            )
        )

        if should_reuse_existing:
            github_res = {
                "owner": owner,
                "repo_name": repo_name,
                "full_name": repo_full_name,
                "html_url": f"https://github.com/{owner}/{repo_name}",
                "reused_existing": True,
            }
            logger.info(f"Workload '{product_id}' reuses existing repository '{repo_full_name}'. Skipping repo creation.")
        else:
            effective_vcs = "SERVERLESS_GIT" if is_serverless_git else vcs_provider
            try:
                github_res = self.vend_github_repo(
                    product_id,
                    github_owner=github_owner,
                    vcs_provider=effective_vcs,
                    repo_identifier=existing_repo if (existing_repo and not is_serverless_git) else None,
                    initial_branch=default_branch,
                    recorded_identity=existing_repo_identity,   # GITHUB-REPO-NAME-NO-PREFIX: own repository only
                    claim=True,                                 # RT F1/F2: the name is claimed before the create
                )
            except (GitHubOwnerNotOrganizationError, GitHubRepositoryCreateError) as repo_err:
                # GITHUB-ORG-ONLY / GITHUB-REPO-CREATE-FAIL-LOUD: the typed class and stage reach the vend's answer
                # (VendingFailure) and the workload record; nothing is reported vended.
                raise self._record_repository_failure(clean_pid, gcp_res, repo_err) from repo_err
            _, _, repo_full_name = resolve_repo_identity(
                github_res.get("full_name") or github_res.get("repo_name"),
                default_owner="serverless-git" if is_serverless_git else (github_owner or self.github_owner),
                product_id=product_id,
            )

        workload_update: Dict[str, Any] = {"github_repo": repo_full_name}
        if not recorded_branch and not existing_repo:
            workload_update["default_branch"] = default_branch   # FD-4CI-b-R1: recorded at the first vend
        if repo_full_name and not is_serverless_git and GITHUB_REPOSITORY_IDENTITY_FIELD \
                and next_github_repository_identity is not None:
            record = self._next_repo_identity(existing_repo_identity, repo_full_name, github_res, should_reuse_existing,
                                              github_owner=github_owner, product_id=product_id)
            if record is not None:
                workload_update[GITHUB_REPOSITORY_IDENTITY_FIELD] = record
        # OQ-15 (owner 10-31): a promoted workload (its branch lives in the source workload's repository) gets its
        # branch-named deploy secrets at its first vend, through redeploy_workload's code path, so its deploy workflows
        # work before any redeploy. Written once per project (recorded); every other vend writes nothing (unchanged).
        vended_project = gcp_res.get("project_id")
        if (is_promoted and not is_serverless_git and repo_full_name and isinstance(vended_project, str)
                and vended_project and stored_record.get(PROMOTION_DEPLOY_SECRETS_FIELD) != vended_project):
            secrets_failures: List[Dict[str, Any]] = []   # RT14-18: the typed reason, kept on the workload record
            if self._write_deploy_secrets(clean_pid, dict(stored_record, github_repo=repo_full_name), vended_project,
                                          failures=secrets_failures):
                workload_update[PROMOTION_DEPLOY_SECRETS_FIELD] = vended_project
                workload_update[DEPLOY_SECRETS_ERROR_FIELD] = firestore.DELETE_FIELD   # RT item 2: no stale error
            else:
                logger.warning(f"PROMOTION_DEPLOY_SECRETS_NOT_WRITTEN: '{clean_pid}': the branch-named deploy secrets "
                               "were not written; the next vend or a redeploy writes them")
                if secrets_failures:
                    workload_update[DEPLOY_SECRETS_ERROR_FIELD] = secrets_failures[0]
        if self.db and repo_full_name:
            try:
                self.db.collection("workloads").document(clean_pid).set(workload_update, merge=True)
            except Exception as e:
                # RT F2 (GITHUB-REPO-NAME-NO-PREFIX): a vend whose repository record did not land is not vended
                logger.error(f"{WORKLOAD_RECORD_NOT_WRITTEN}: workloads/{clean_pid}: {e}")
                raise VendingFailure(WORKLOAD_RECORD_NOT_WRITTEN,
                                     f"the repository '{repo_full_name}' was vended but workloads/{clean_pid} could "
                                     f"not be updated ({type(e).__name__}); run the workload again (the repository "
                                     f"is reused).", stage="vcs_repository_vending") from e

        # FD-7L Phase 1 (PER_WORKLOAD only): pin the repository in the signed runner identity record.
        if repo_full_name and runner_mode == ri.MODE_PER_WORKLOAD:   # the snapshot taken at the start (RT M2)
            provider = "SERVERLESS_GIT" if is_serverless_git else str(vcs_provider or "GITHUB").strip().upper()
            repo_id = None
            if provider == "GITHUB" and pinned_github_repository_id is not None and GITHUB_REPOSITORY_IDENTITY_FIELD:
                repo_id = pinned_github_repository_id(
                    workload_update.get(GITHUB_REPOSITORY_IDENTITY_FIELD, existing_repo_identity), repo_full_name)
            self._pin_runner_repository(clean_pid, provider, repo_full_name, repo_id)

        return {
            "status": "WORKLOAD_VENDED",
            "product_id": product_id,
            "project_id": gcp_res.get("project_id", product_id.lower().replace('_', '-')),
            "project_number": gcp_res.get("project_number", ""),
            "trace_id": trace_id,
            "gcp_project": gcp_res,
            "github_repo": github_res,
            "budget_ceiling_monthly_usd": gcp_res.get("budget_ceiling_monthly_usd", initial_budget),
            "summary": (f"Vended GCP Project '{gcp_res.get('project_id')}' and "
                        f"{_vended_repository_label(github_res)} '{github_res.get('repo_name')}' for {product_id}"),
        }

    def _repository_shared_with_other_workload(self, product_id: str, repo_full_name: str) -> Optional[bool]:
        """FD-4CI-b-R1-WIF: True when a workload record other than `product_id`'s names the repository
        `repo_full_name`, False when none does, None when the records cannot be read (callers treat None as shared).
        Read only. FD-4CI-b-R1-WIF-SHARED: the rule lives in shared.github_identity (the developer's workflow render
        makes the same decision)."""
        if not self.db:
            return None
        return repository_shared_with_other_workload(self.db, product_id, repo_full_name,
                                                     default_owner=self.github_owner)

    def _write_deploy_secrets(self, clean_pid: str, workload_data: Dict[str, Any], project_id: str, *,
                              failures: Optional[List[Dict[str, Any]]] = None) -> bool:
        """The GitHub Actions deploy secrets of `project_id` (GCP_PROJECT_ID / WIF_PROVIDER / WIF_SERVICE_ACCOUNT)
        written to the workload's repository: redeploy_workload (a fresh project) and, OQ-15 (owner 10-31), vend_all at
        a promoted workload's first vend. True when written; False (logged) otherwise, as before. RT14-18: a typed
        GitHubSecretsNotWritten is logged at ERROR and its body appended to `failures` (when given)."""
        github_repo = workload_data.get("github_repo")
        default_branch = workload_data.get("default_branch", "main")
        is_promoted = bool(workload_data.get("promoted_from_product_id"))
        wif_secrets_updated = False
        new_project_id = project_id
        # GHA-DEPLOY-SWITCH: a workload whose GitHub Actions deploy switch is off has no WIF pool, provider or
        # sa-gh-deployer, so no deploy secrets are written for it (logged). Missing = on (today).
        gha_skip = self._gha_deploy_secrets_skip(clean_pid, workload_data.get(GITHUB_ACTIONS_DEPLOY_FIELD))
        if github_repo and not gha_skip:
            try:
                _, _, full_repo = resolve_repo_identity(github_repo, default_owner=self.github_owner, product_id=clean_pid)
                wif_pool = f"projects/{new_project_id}/locations/global/workloadIdentityPools/castor-gh-pool"
                wif_provider = f"{wif_pool}/providers/github-provider"
                sa_deployer = f"sa-gh-deployer@{new_project_id}.iam.gserviceaccount.com"
                
                # FD-4CI-b-R1-WIF: a workload with its own repository gets the plain names its generated deploy
                # workflows read (secrets.GCP_PROJECT_ID / WIF_PROVIDER / WIF_SERVICE_ACCOUNT), on any default branch
                # (a branch suffix was never read). A repository shared with another workload (promoted, or another
                # workload record names it; unreadable records count as shared) keeps the branch-suffixed names
                # (unchanged): its plain secrets are the other workload's, so a redeploy never points that
                # workload's deploys at this project. main: plain names, no extra read (unchanged).
                # FD-4CI-b-R1-WIF-SHARED: the developer makes the same decision when it renders the workflow, and a
                # shared repository's workflow on a non-main branch reads these branch-named secrets first.
                if is_promoted or (default_branch and default_branch != "main"
                                   and self._repository_shared_with_other_workload(clean_pid, full_repo) is not False):
                    clean_br = branch_secret_suffix(default_branch)   # FD-4CI-b-R1-WIF-SHARED: one rule, shared
                    secrets_dict = {
                        f"GCP_PROJECT_ID_{clean_br}": new_project_id,
                        f"WIF_PROVIDER_{clean_br}": wif_provider,
                        f"WIF_SERVICE_ACCOUNT_{clean_br}": sa_deployer,
                    }
                else:
                    secrets_dict = {
                        "GCP_PROJECT_ID": new_project_id,
                        "WIF_PROVIDER": wif_provider,
                        "WIF_SERVICE_ACCOUNT": sa_deployer,
                    }
                wif_secrets_updated = self._update_github_secrets(full_repo, secrets_dict)
            except GitHubSecretsNotWritten as not_written:
                logger.error(f"{not_written.error_class}: '{clean_pid}': {not_written.detail}")
                if failures is not None:
                    failures.append(not_written.body())
            except Exception as gh_err:
                logger.warning(f"GitHub secrets update notice for '{github_repo}': {gh_err}")
        return wif_secrets_updated

    @staticmethod
    def _gha_deploy_secrets_skip(product_id: str, recorded: Any) -> bool:
        """GHA-DEPLOY-SWITCH: True when the redeploy writes no GitHub Actions deploy secrets: the recorded switch is
        off, or it is set to something other than true / false (the deploy refuses that record too). Missing = on."""
        if recorded is None:
            return False
        try:
            if github_actions_deploy_enabled is None:
                raise ValueError("shared.github_identity unavailable")
            on = github_actions_deploy_enabled(recorded)
        except ValueError as e:
            logger.error(f"GHA_DEPLOY_SWITCH_INVALID: workloads/{product_id}.{GITHUB_ACTIONS_DEPLOY_FIELD} ({e}); no "
                         "GitHub Actions deploy secrets written")
            return True
        if not on:
            logger.info(f"GHA_DEPLOY_SWITCH_OFF: '{product_id}' has GitHub Actions deploy off; no deploy secrets "
                        "written")
        return not on

    def _update_github_secrets(self, repo_full_name: str, secrets: Dict[str, str]) -> bool:
        """Updates repository secrets for GitHub Actions CI/CD.

        RT14-18 (owner 11-14): True only when EVERY secret was written with one token. A token with which any write
        failed (for example HTTP 403: the GitHub App has no Secrets permission) is followed by the next token; when
        none wrote them all (or there is no token) GitHubSecretsNotWritten (VENDING.GHA_SECRETS_NOT_WRITTEN) is raised
        with each attempt's GitHub status. Before, the first token that could read the repository returned True even
        when every write failed (logged at DEBUG only)."""
        _, _, target_repo = resolve_repo_identity(repo_full_name, default_owner=self.github_owner)
        creds = self.fetch_github_app_credentials()
        jit_token = self.generate_github_jit_token()
        pat_token = creds.get("pat") or os.getenv("GITHUB_PAT") or os.getenv("GITHUB_TOKEN", "")
        attempts: List[Dict[str, Any]] = []
        for token_kind, token in (("installation", jit_token), ("pat", pat_token)):
            if not token:
                continue
            failed: List[Dict[str, Any]] = []
            try:
                gh = Github(token)
                repo = gh.get_repo(target_repo)
                for secret_name, secret_value in secrets.items():
                    try:
                        repo.create_secret(secret_name, secret_value)
                    except Exception as s_err:  # noqa: BLE001 - typed below (class + GitHub status, never the value)
                        failed.append({"secret": secret_name, "http_status": getattr(s_err, "status", None),
                                       "error": type(s_err).__name__})
            except Exception as e:  # noqa: BLE001 - the repository read failed with this token
                failed.append({"secret": None, "http_status": getattr(e, "status", None), "error": type(e).__name__})
            if not failed:
                return True
            logger.warning(f"{GHA_SECRETS_NOT_WRITTEN}: {len(failed)} deploy secret write(s) on '{target_repo}' "
                           f"failed with the {token_kind} token: {failed}")
            attempts.append({"token": token_kind, "failures": failed})
        raise GitHubSecretsNotWritten(target_repo, sorted(secrets), attempts)

    def decommission_workload(
        self,
        product_id: str,
        operator_email: Optional[str] = None,
        approval_id: Optional[str] = None,
        *,
        action_class: str = "PROJECT_DECOMMISSION",
        caller_email: str = "",
        guard_ctx: Optional[Any] = None,
        delete_without_archive: bool = False,
    ) -> Dict[str, Any]:
        """
        Guarded decommission of a child workload to zero cloud spend (lane 18 S1, plan 3.1). Vending is the only
        executor of a project delete.

        1. destructive_guard.assert_deletable (target ONLY from the ledger + provenance; HITL approval or SANDBOX_TTL
           eligibility; CRM identity, tag, labels, ancestry, liens; audit). Any failure raises DeletionRefused and
           nothing is mutated.
        2. ledger status DECOMMISSION_REQUESTED.
        3. consume the approval (HITL classes), atomically.
        4. fresh re-GET of projects/<number> + tag + ancestry + liens (any lien refuses: StackVend never releases a
           lien, register row L18-g); delete projects/<number>. Any failure: ledger DECOMMISSION_FAILED, approval
           EXECUTION_FAILED, DecommissionFailed (no archive, no spend reset).
        5. after success: delete only DNS records StackVend recorded, archive state (copy then delete), DECOMMISSIONED
           + spend 0, provenance/approval updates, IPAM, audit with the CRM operation name.
        GitHub code and the Firestore spec are kept.

        FD-7L Phase 3 (plan 2.8), Per-workload installs only: for a workload whose signed runner identity record is
        READY (state in its own bucket), the state is archived into the platform bucket between the re-check and the
        delete; a failed archive stops the decommission (DECOMMISSION_STATE_ARCHIVE_FAILED) unless the approval was
        minted with "delete without archive". After the delete, a migrated workload's stale platform copy (every
        generation and the tombstone) is deleted. Shared installs and workloads without a READY record: unchanged.
        """
        ctx = guard_ctx or self.guard_context()
        verdict = dg.assert_deletable(
            dg.DeletionTarget(product_id=product_id),
            action_class=action_class,
            approval_id=approval_id,
            caller_email=caller_email,
            ctx=ctx,
        )
        if verdict.action_class not in (dg.ActionClass.PROJECT_DECOMMISSION, dg.ActionClass.SANDBOX_TTL):
            raise dg.DeletionRefused("INVALID_REQUEST", f"{verdict.action_class.value} does not decommission a project")
        store = ctx.store
        pid = verdict.product_id
        decommissioned_by = verdict.approved_by or caller_email
        runner_state = None   # Shared install (PLATFORM): never computed; the legacy path below is unchanged
        try:
            install_mode = self.operative_runner_identity_mode()
        except ri.RunnerIdentityError as e:
            raise dg.DeletionRefused(e.code, e.detail, 503) from None
        if install_mode == ri.MODE_PER_WORKLOAD:
            runner_state = self._decommission_state_plan(pid, verdict, ctx, delete_without_archive)
        runner_archive: Optional[Dict[str, Any]] = None

        # 2. intent
        try:
            store.update_workload(pid, {"status": "DECOMMISSION_REQUESTED",
                                        "decommission_requested_at": ctx.clock().isoformat(),
                                        "decommission_action_class": verdict.action_class.value})
        except Exception as e:
            raise dg.DeletionRefused("LEDGER_UNAVAILABLE", f"could not record DECOMMISSION_REQUESTED ({type(e).__name__})")

        # 3. approval
        try:
            dg.consume_approval(verdict, ctx=ctx)
        except dg.DeletionRefused:
            try:
                store.update_workload(pid, {"status": verdict.ledger_status})
            except Exception as e:
                logger.error(f"Could not restore status of '{pid}' after an approval refusal: {e}")
            raise

        # 4. re-check (id, state, tag, ancestry, liens), delete by number. StackVend never releases a lien (row L18-g).
        deletion_operation = None
        try:
            dg.recheck_before_delete(verdict, ctx)
            if runner_state is not None:
                runner_archive = self._archive_runner_state(pid, runner_state)   # FD-7L: before the delete
            deletion_operation = ctx.crm.delete_project(verdict.project_number)
        except Exception as exec_err:
            code = exec_err.code if isinstance(exec_err, (dg.DeletionRefused, rib.StateArchiveFailed)) \
                else "DECOMMISSION_FAILED"
            detail = str(exec_err)
            logger.error(f"Decommission of '{pid}' (projects/{verdict.project_number}) failed: {detail}")
            try:
                store.update_workload(pid, {"status": "DECOMMISSION_FAILED", "decommission_error": detail,
                                            "decommission_failed_at": ctx.clock().isoformat()})
            except Exception as e:
                logger.error(f"Could not record DECOMMISSION_FAILED for '{pid}': {e}")
            dg.mark_execution_failed(verdict, error=detail, ctx=ctx)
            try:
                store.write_audit(pid, {"action": "WORKLOAD_DECOMMISSION_FAILED", "code": code, "error": detail,
                                        "project_id": verdict.project_id, "project_number": verdict.project_number,
                                        "action_class": verdict.action_class.value, "approval_id": verdict.approval_id,
                                        "caller": caller_email, "timestamp": ctx.clock().isoformat()})
            except Exception as e:
                logger.error(f"Could not audit the failed decommission of '{pid}': {e}")
            raise dg.DecommissionFailed(code, detail) from None
        operation_name = deletion_operation.get("name") if isinstance(deletion_operation, dict) else None
        logger.info(f"Deleted projects/{verdict.project_number} ({verdict.project_id}) for '{pid}': {operation_name}")

        # 5. post-delete steps (the project is gone: these never undo or hide the delete)
        now_iso = ctx.clock().isoformat()
        warnings: List[str] = []
        host_project = sorted(ctx.host_project_ids)[0] if ctx.host_project_ids else ""
        if verdict.dns_records and not (ctx.dns_zone and ctx.dns is not None and host_project):
            warnings.append("DNS_RECORDS_NOT_DELETED: DNS_MANAGED_ZONE is not configured")
        elif verdict.dns_records:
            for rr_name, rr_type in verdict.dns_records:
                try:
                    ctx.dns.delete_dns_rrset(host_project, ctx.dns_zone, rr_name, rr_type)
                except Exception as dns_err:
                    warnings.append(f"DNS_DELETE_FAILED {rr_name} {rr_type}: {dns_err}")

        state_archived = False
        archive_path = None
        if runner_archive is not None:
            state_archived, archive_path = runner_archive["archived"], runner_archive["archive_path"]
            if runner_archive["warning"]:
                warnings.append(runner_archive["warning"])
            mig = runner_state.get("migration") if isinstance(runner_state, dict) else None
            if isinstance(mig, dict) and mig.get("migrated_at") and not mig.get("restored_at"):
                warnings.extend(rib.delete_stale_platform_copy(self.runner_deps, pid, self.tfstate_bucket))
        elif self.storage and self.tfstate_bucket:
            try:
                bucket = self.storage.bucket(self.tfstate_bucket)
                state_blob = bucket.blob(f"workloads/{pid}/default.tfstate")
                if state_blob.exists():
                    archive_path = f"workloads/{pid}/state_history/decommission_{int(time.time())}.tfstate"
                    bucket.copy_blob(state_blob, bucket, archive_path)
                    state_blob.delete()
                    state_archived = True
                    logger.info(f"Archived GCS state for '{pid}' to '{archive_path}'")
            except Exception as st_err:
                warnings.append(f"STATE_ARCHIVE_FAILED: {st_err}")

        update_fields = {
            "status": "DECOMMISSIONED",
            "service_url": "",
            "last_active_project_id": verdict.project_id,
            "last_active_project_number": verdict.project_number,
            "decommissioned_at": now_iso,
            "decommissioned_by": decommissioned_by,
            "decommission_action_class": verdict.action_class.value,
            "decommission_crm_operation": operation_name,
            "current_spend_usd": 0.0,
            "projected_monthly_spend_usd": 0.0,
            "spend_last_updated_at": now_iso,
            "is_overrun_projected": False,
        }
        if verdict.approval_id:
            update_fields["hitl_approval_id"] = verdict.approval_id
        try:
            store.update_workload(pid, update_fields)
        except Exception as fs_err:
            warnings.append(f"LEDGER_UPDATE_FAILED: {fs_err}")
        try:
            store.update_provenance(pid, {"decommissioned_at": now_iso, "crm_delete_operation": operation_name})
        except Exception as prov_err:
            warnings.append(f"PROVENANCE_UPDATE_FAILED: {prov_err}")
        if verdict.approval_id:
            try:
                store.update_approval(verdict.approval_id, {"status": "EXECUTED", "executed_at": now_iso,
                                                            "crm_operation": operation_name})
            except Exception as ap_err:
                warnings.append(f"APPROVAL_UPDATE_FAILED: {ap_err}")
        try:
            store.write_audit(pid, {
                "action": "WORKLOAD_DECOMMISSIONED",
                "operator_email": decommissioned_by,
                "caller": caller_email,
                "requested_operator_label": operator_email,
                "action_class": verdict.action_class.value,
                "deleted_project_id": verdict.project_id,
                "deleted_project_number": verdict.project_number,
                "crm_operation": operation_name,
                "timestamp": now_iso,
                "state_archived": state_archived,
                "archive_path": archive_path,
                "approval_id": verdict.approval_id,
                "warnings": warnings,
            })
        except Exception as audit_err:
            warnings.append(f"AUDIT_WRITE_FAILED: {audit_err}")

        try:
            try:
                from shared.ipam import CastorIPAMEngine
            except ImportError:
                from .shared.ipam import CastorIPAMEngine
            ipam_engine = CastorIPAMEngine(db=self.db)
            ipam_engine.mark_workload_decommissioned(pid, operator_email=decommissioned_by)
        except Exception as ipam_err:
            warnings.append(f"IPAM_SYNC_FAILED: {ipam_err}")

        for w in warnings:
            logger.warning(f"Post-delete step for '{pid}': {w}")
        return {
            "status": "DECOMMISSIONED",
            "product_id": pid,
            "deleted_project_id": verdict.project_id,
            "deleted_project_number": verdict.project_number,
            "action_class": verdict.action_class.value,
            "decommissioned_at": now_iso,
            "decommissioned_by": decommissioned_by,
            "state_archived": state_archived,
            "archive_path": archive_path,
            "crm_operation": operation_name,
            "warnings": warnings,
            "message": f"Workload '{pid}' decommissioned: projects/{verdict.project_number} ({verdict.project_id}) "
                       "deleted; GitHub code and Firestore spec preserved.",
        }

    def sandbox_lifecycle(
        self,
        product_id: str,
        action: str,
        *,
        ttl_days: Optional[int] = None,
        approval_id: Optional[str] = None,
        caller_email: str = "",
        guard_ctx: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """
        Sandbox lifecycle (lane 18 S1, plan 2.4). The vend-time provenance is the only TTL authority, so the Control
        Center extends / promotes / confirms a sandbox through here (S2). Guard checks 1-7 run before any change.
          EXTEND           +ttl_days (1-30), at most 3 extensions and 90 days from creation; vending-born sandboxes only
          PROMOTE          sandbox -> standard: provenance first (ineligible at once), then the project label
          CONFIRM_SANDBOX  make a vending-born project an auto-decommission sandbox: needs a human ADMIN approval
                           (action CONFIRM_SANDBOX); label first, provenance last (eligible only when both are written)
        """
        ctx = guard_ctx or self.guard_context()
        if action not in ("EXTEND", "PROMOTE", "CONFIRM_SANDBOX"):
            raise dg.DeletionRefused("INVALID_REQUEST", f"unknown lifecycle action {action!r}")
        ident = dg.verify_identity(product_id, ctx=ctx)
        store = ctx.store
        prov = dg._read(store.get_provenance, product_id) or {}
        now = ctx.clock()
        audit = {"action": f"SANDBOX_LIFECYCLE_{action}", "caller": caller_email, "product_id": product_id,
                 "project_id": ident.project_id, "project_number": ident.project_number, "timestamp": now.isoformat()}
        warnings: List[str] = []

        def _valid_days(v) -> bool:
            return isinstance(v, int) and not isinstance(v, bool) and 0 < v <= MAX_EXTENSION_DAYS

        def _relabel(workload_type: str) -> None:
            project = ctx.crm.get_project(ident.project_number)
            labels = dict(project.get("labels") or {}) if isinstance(project, dict) else {}
            labels[dg.LABEL_TYPE] = workload_type
            ctx.crm.patch_labels(ident.project_number, labels)

        if action == "EXTEND":
            if prov.get("created_by") != dg.CREATED_BY_VENDING or prov.get("is_sandbox") is not True:
                raise dg.DeletionRefused("SANDBOX_NOT_ELIGIBLE", "only a vending-born sandbox can be extended")
            if not _valid_days(ttl_days):
                raise dg.DeletionRefused("INVALID_REQUEST", f"ttl_days must be an integer 1-{MAX_EXTENSION_DAYS}")
            extensions = prov.get("extensions") if isinstance(prov.get("extensions"), int) else 0
            created = dg._parse_ts(prov.get("created_at"))
            current = dg._parse_ts(prov.get("sandbox_expires_at"))
            if created is None or current is None:
                raise dg.DeletionRefused("SANDBOX_NOT_ELIGIBLE", "provenance has no creation time or expiry")
            if extensions >= MAX_SANDBOX_EXTENSIONS:
                raise dg.DeletionRefused("EXTENSION_LIMIT", f"already extended {extensions} times")
            new_expiry = max(current, now) + timedelta(days=ttl_days)
            if new_expiry - created > timedelta(days=MAX_SANDBOX_TTL_DAYS):
                raise dg.DeletionRefused("EXTENSION_LIMIT", f"a sandbox lives at most {MAX_SANDBOX_TTL_DAYS} days")
            fields = {"sandbox_expires_at": new_expiry.isoformat(), "extensions": extensions + 1,
                      "last_extended_at": now.isoformat(), "last_extended_by": caller_email}
            try:
                store.update_provenance(product_id, fields)
            except Exception as e:
                raise dg.DecommissionFailed("LIFECYCLE_FAILED", f"provenance update failed: {e}") from None
            try:
                store.update_workload(product_id, {"sandbox_expires_at": new_expiry.isoformat()})
            except Exception as e:
                warnings.append(f"LEDGER_MIRROR_FAILED: {e}")
            audit.update(fields)

        elif action == "PROMOTE":
            if prov.get("is_sandbox") is not True:
                raise dg.DeletionRefused("SANDBOX_NOT_ELIGIBLE", "workload is not a sandbox")
            fields = {"is_sandbox": False, "sandbox_auto_decommission": False, "sandbox_expires_at": None,
                      "promoted_at": now.isoformat(), "promoted_by": caller_email}
            try:
                store.update_provenance(product_id, fields)
            except Exception as e:
                raise dg.DecommissionFailed("LIFECYCLE_FAILED", f"provenance update failed: {e}") from None
            try:
                _relabel("standard")
            except Exception as e:
                warnings.append(f"LABEL_UPDATE_FAILED (provenance already ineligible): {e}")
            try:
                store.update_workload(product_id, {"is_sandbox": False, "sandbox_auto_decommission": False})
            except Exception as e:
                warnings.append(f"LEDGER_MIRROR_FAILED: {e}")
            audit.update(fields)

        else:  # CONFIRM_SANDBOX
            if prov.get("created_by") != dg.CREATED_BY_VENDING:
                raise dg.DeletionRefused("SANDBOX_NOT_ELIGIBLE", "a backfilled project is never TTL-eligible")
            if not _valid_days(ttl_days):
                raise dg.DeletionRefused("INVALID_REQUEST", f"ttl_days must be an integer 1-{MAX_EXTENSION_DAYS}")
            approval = dg.read_approval(ctx, approval_id)
            approved_by = dg.check_approval(approval, approval_id=approval_id, action="CONFIRM_SANDBOX",
                                            product_id=product_id, project_id=ident.project_id,
                                            project_number=ident.project_number, resource_name=None, now=now)
            try:
                store.consume_approval(approval_id, consumed_by=caller_email, now=now)
            except dg.ApprovalConflict as e:
                raise dg.DeletionRefused("APPROVAL_CONSUMED", str(e)) from None
            except dg.StoreUnavailable as e:
                raise dg.DeletionRefused("APPROVAL_UNAVAILABLE", str(e)) from None
            expiry = now + timedelta(days=ttl_days)
            fields = {"is_sandbox": True, "sandbox_auto_decommission": True,
                      "sandbox_designation_source": "OPERATOR_CONFIRMED", "sandbox_ttl_days": ttl_days,
                      "sandbox_expires_at": expiry.isoformat(), "extensions": 0,
                      "confirmed_at": now.isoformat(), "confirmed_by": approved_by}
            try:
                _relabel("sandbox")
                store.update_provenance(product_id, fields)
            except Exception as e:
                try:
                    store.update_approval(approval_id, {"status": "EXECUTION_FAILED", "execution_error": str(e)})
                except Exception as ap_err:
                    logger.error(f"Could not mark approval {approval_id} EXECUTION_FAILED: {ap_err}")
                raise dg.DecommissionFailed("LIFECYCLE_FAILED", f"confirm failed: {e}") from None
            try:
                store.update_approval(approval_id, {"status": "EXECUTED", "executed_at": now.isoformat()})
            except Exception as e:
                warnings.append(f"APPROVAL_UPDATE_FAILED: {e}")
            try:
                store.update_workload(product_id, {"is_sandbox": True, "sandbox_auto_decommission": True,
                                                   "sandbox_designation_source": "OPERATOR_CONFIRMED",
                                                   "sandbox_expires_at": expiry.isoformat()})
            except Exception as e:
                warnings.append(f"LEDGER_MIRROR_FAILED: {e}")
            audit.update(fields, approval_id=approval_id)

        try:
            store.write_audit(product_id, audit)
        except Exception as e:
            warnings.append(f"AUDIT_WRITE_FAILED: {e}")
        return {"status": "OK", "action": action, "product_id": product_id, "project_id": ident.project_id,
                "sandbox_expires_at": audit.get("sandbox_expires_at"), "warnings": warnings}

    def redeploy_workload(
        self,
        product_id: str,
        operator_email: str,
        terraform_service_url: Optional[str] = None,
        target_folder_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Redeploys a decommissioned workload into a fresh Google Cloud child project:
        1. Validates that the workload exists and is DECOMMISSIONED
        2. Generates a fresh unique project_id (castor-{clean_pid}-{uuid})
        3. Provisions the project via vend_gcp_project() in target_folder_id (or original folder)
        4. Rebinds GitHub WIF secrets (GCP_PROJECT_ID, WIF_PROVIDER, WIF_SERVICE_ACCOUNT)
        5. Updates Firestore status to "REDEPLOYING"
        6. Triggers Terraform deploy via mcp-terraform-server
        7. Updates Firestore status to "ACTIVE" with new service_url, only when /deploy answered HTTP 200; any
           other outcome is FAILED with a typed REDEPLOY_* class (FD vending-redeploy)
        """
        clean_pid = product_id.strip().lower()
        now_iso = datetime.now(timezone.utc).isoformat()
        started_monotonic = time.monotonic()

        # VENDING-CLIENT-FAIL-LOUD gap 4 (RT 11-07 F1): the vend's client requirements are checked before anything is
        # read or written, so a redeploy whose vend could not start leaves the workload DECOMMISSIONED (retryable),
        # never FAILED or REDEPLOYING without a project. Firestore first: without it step 1 used to read nothing and the
        # "only DECOMMISSIONED" check below passed for any workload.
        self._require_db(f"the redeploy of '{clean_pid}'")
        self._require_crm(f"the redeploy of '{clean_pid}'")

        # 1. Fetch workload data from Firestore. RT 11-07 F3: an unreadable record stops the redeploy (it used to be
        #    taken for "no record", so an ACTIVE workload could be overwritten); an unknown workload is refused (400).
        try:
            doc = self.db.collection("workloads").document(clean_pid).get()
        except Exception as e:  # noqa: BLE001 - typed by class; nothing written yet
            raise VendingFailure(
                WORKLOAD_RECORD_UNREADABLE,
                f"The workload record workloads/{clean_pid} could not be read ({type(e).__name__}), so the redeploy "
                "stopped before writing or creating anything; re-run it once Firestore is reachable.",
            ) from e
        if not doc.exists:
            raise ValueError(f"Workload '{clean_pid}' does not exist; only a DECOMMISSIONED workload can be redeployed.")
        workload_data = doc.to_dict() or {}

        current_status = workload_data.get("status")
        if current_status and current_status != "DECOMMISSIONED":
            raise ValueError(f"Workload '{clean_pid}' is currently '{current_status}'. Only DECOMMISSIONED workloads can be redeployed.")

        # RT R3: the terraform service is resolved BEFORE anything is written or vended. Without it the redeploy
        # cannot finish, so nothing is billed and the workload stays DECOMMISSIONED.
        # Security (orchestrator decision): vending resolves the URL itself (env, else Cloud Run lookup of
        # mcp-terraform-server); a caller-supplied `terraform_service_url` is never called and never gets the ID token.
        tf_url = resolve_terraform_service_url(self.platform_project_id)
        if terraform_service_url and terraform_service_url != tf_url:
            logger.warning(f"Redeploy of '{clean_pid}': ignoring the caller-supplied terraform_service_url "
                           f"(it is not the self-resolved terraform service)")
        if not tf_url:
            logger.error(f"Redeploy of '{clean_pid}' refused: no terraform service URL ({REDEPLOY_TERRAFORM_UNCONFIGURED})")
            return {
                "status": "FAILED",
                "error_class": REDEPLOY_TERRAFORM_UNCONFIGURED,
                "http_status": None,
                "error": "No terraform service URL is configured; nothing was vended or deployed.",
                "product_id": clean_pid,
                "project_id": None,
                "trace_id": None,
                "message": f"Workload '{clean_pid}' was not redeployed ({REDEPLOY_TERRAFORM_UNCONFIGURED}); "
                           f"it is still DECOMMISSIONED.",
            }

        # Gap 4 (RT 11-07 F1): the redeploy always creates a project, so it needs a parent folder; checked with the
        # same sources vend_gcp_project uses, before step 3 writes anything.
        folder_to_use = target_folder_id or workload_data.get("folder_id")
        if not (folder_to_use or workload_data.get("parent_folder_id") or self.folder_id):
            raise VendingFailure(
                PARENT_FOLDER_UNCONFIGURED,
                f"No parent folder for the redeploy of '{clean_pid}': the request names none, the workload record names "
                "none and MANAGED_WORKLOADS_FOLDER_ID is not set. Nothing was written or created; the workload is still "
                "DECOMMISSIONED.",
            )

        # 2. Generate unique collision-proof project ID
        uid_suffix = uuid.uuid4().hex[:6]
        base_prefix = clean_pid[:23].rstrip("-")
        new_project_id = f"{base_prefix}-{uid_suffix}"

        # 3. Update status to REDEPLOYING
        if self.db:
            try:
                self.db.collection("workloads").document(clean_pid).set({
                    "status": "REDEPLOYING",
                    "project_id": new_project_id,
                    "redeployed_at": now_iso,
                    "redeployed_by": operator_email,
                }, merge=True)
            except Exception as e:
                logger.warning(f"Could not update status to REDEPLOYING: {e}")

        # 4. Vend fresh GCP project
        trace_id = f"redeploy-{clean_pid}-{uid_suffix}"
        try:
            vended_gcp = self.vend_gcp_project(
                product_id=clean_pid,
                trace_id=trace_id,
                folder_id=folder_to_use,
                billing_account_id=workload_data.get("billing_account_id"),
                initial_budget=workload_data.get("budget_ceiling_monthly_usd", 40.0),
                force_new_project_id=new_project_id,
            )
        except Exception as vend_err:  # noqa: BLE001 - recorded typed, then raised unchanged
            # Gap 4 (VENDING-CLIENT-FAIL-LOUD): a vend that raises used to leave the workload REDEPLOYING forever.
            self._record_redeploy_vend_failed(clean_pid, trace_id, new_project_id, operator_email, now_iso, vend_err)
            raise
        # SAT-38: everything after the vend (secrets, the deploy target, the ACTIVE / FAILED record, IPAM, the result)
        # uses the project vending actually created: after a 409 + 403/404 that is a fallback id, not new_project_id.
        vended_project_id = vended_gcp.get("project_id") if isinstance(vended_gcp, dict) else None
        if isinstance(vended_project_id, str) and vended_project_id and vended_project_id != new_project_id:
            logger.warning(f"Redeploy of '{clean_pid}': vending created '{vended_project_id}' instead of the requested "
                           f"'{new_project_id}' (id taken); recording and deploying the vended project.")
            new_project_id = vended_project_id

        # 5. Rebind GitHub Actions secrets (mock-friendly)
        # OQ-15 (owner 10-31): the same code path writes a promoted workload's deploy secrets at its first vend.
        default_branch = workload_data.get("default_branch", "main")   # the deploy call below sends it
        secrets_failures: List[Dict[str, Any]] = []   # RT14-18: typed GitHubSecretsNotWritten bodies
        wif_secrets_updated = self._write_deploy_secrets(clean_pid, workload_data, new_project_id,
                                                         failures=secrets_failures)
        wif_secrets_error = secrets_failures[0] if secrets_failures else None

        # 6. Trigger Terraform deployment. FD vending-redeploy: only an HTTP 200 is a deployed workload; every other
        # outcome is a typed failure (by HTTP status / exception type; the response text is kept only as the message).
        # RT R2: the URL is the terraform service's own top-level `service_url` string, never invented.
        # RT R4: the call carries an ID token for the terraform service (it is not public).
        tf_result = {}
        new_service_url: Optional[str] = None
        failure: Optional[Dict[str, Any]] = None

        # RT S5: one deadline for the whole request; the wait never runs past it.
        deploy_wait_s = REDEPLOY_REQUEST_BUDGET_S - REDEPLOY_RECORD_MARGIN_S - (time.monotonic() - started_monotonic)
        if deploy_wait_s < REDEPLOY_MIN_DEPLOY_WAIT_S:
            failure = {"error_class": REDEPLOY_DEPLOY_CALL_FAILED, "http_status": None,
                       "error": f"Not called: only {max(0, int(deploy_wait_s))} s of the request budget were left "
                                f"after vending the project; nothing was sent to the terraform service."}
        else:
            import httpx
            deploy_payload = {
                "product_id": clean_pid,
                "trace_id": trace_id,
                "target_project_id": new_project_id,
                "branch": default_branch,
                "iac_engine": workload_data.get("iac_engine", "TERRAFORM"),
            }
            headers = {"Content-Type": "application/json"}
            token = _fetch_id_token(tf_url)
            if token:
                headers["Authorization"] = f"Bearer {token}"
            timeout = httpx.Timeout(deploy_wait_s, connect=min(REDEPLOY_CONNECT_TIMEOUT_S, deploy_wait_s))
            try:
                with httpx.Client(timeout=timeout) as client:
                    res = client.post(f"{tf_url.rstrip('/')}/deploy", json=deploy_payload, headers=headers)
            except (httpx.ConnectTimeout, httpx.PoolTimeout) as tf_err:
                # RT S3: nothing was sent.
                failure = {"error_class": REDEPLOY_DEPLOY_CALL_FAILED, "http_status": None,
                           "error": f"Terraform deploy call not sent ({type(tf_err).__name__})"}
            except httpx.TimeoutException as tf_err:
                failure = {"error_class": REDEPLOY_OUTCOME_UNKNOWN, "http_status": None,
                           "error": f"No answer from the terraform service within {int(deploy_wait_s)} s "
                                    f"({type(tf_err).__name__}); the apply may still be running."}
            except Exception as tf_err:
                failure = {"error_class": REDEPLOY_DEPLOY_CALL_FAILED, "http_status": None,
                           "error": f"Terraform deploy call failed ({type(tf_err).__name__}: {tf_err})"}
            else:
                if res.status_code == 200:
                    try:
                        tf_result = res.json() or {}
                    except Exception as parse_err:
                        logger.warning(f"Terraform deploy for '{clean_pid}' returned 200 with an unreadable body "
                                       f"({type(parse_err).__name__})")
                        tf_result = {}
                    reported = tf_result.get("service_url") if isinstance(tf_result, dict) else None
                    new_service_url = reported if isinstance(reported, str) and reported else None
                else:
                    failure = {"error_class": REDEPLOY_OUTCOME_UNKNOWN if res.status_code == 504
                               else REDEPLOY_DEPLOY_FAILED,
                               "http_status": res.status_code, "error": _deploy_error_text(res)}

        if failure is not None:
            failed_result = self._record_redeploy_failed(
                clean_pid, trace_id, new_project_id, folder_to_use, operator_email, now_iso, failure,
                wif_secrets_updated=wif_secrets_updated, vended_gcp=vended_gcp)
            if wif_secrets_error:   # RT14-18
                failed_result[DEPLOY_SECRETS_ERROR_FIELD] = wif_secrets_error
            return failed_result

        # 7. Finalize status to ACTIVE in Firestore
        if self.db:
            try:
                doc_ref = self.db.collection("workloads").document(clean_pid)
                active_update = {
                    "status": "ACTIVE",
                    "project_id": new_project_id,
                    "service_url": new_service_url,
                    "spend_last_updated_at": now_iso,
                }
                if folder_to_use:
                    active_update["folder_id"] = folder_to_use
                if wif_secrets_error:   # RT14-18: GitHub Actions deploys of this project will fail until fixed
                    active_update[DEPLOY_SECRETS_ERROR_FIELD] = wif_secrets_error
                elif wif_secrets_updated:   # RT item 2: secrets written, an earlier error no longer applies
                    active_update[DEPLOY_SECRETS_ERROR_FIELD] = firestore.DELETE_FIELD
                doc_ref.set(active_update, merge=True)

                # Append audit record
                audit_entry = {
                    "action": "WORKLOAD_REDEPLOYED",
                    "operator_email": operator_email,
                    "new_project_id": new_project_id,
                    "service_url": new_service_url,
                    "timestamp": now_iso,
                    "wif_secrets_updated": wif_secrets_updated,
                }
                if wif_secrets_error:
                    audit_entry[DEPLOY_SECRETS_ERROR_FIELD] = wif_secrets_error
                audit_ref = doc_ref.collection("audit_logs").document()
                audit_ref.set(audit_entry)
                logger.info(f"Finalized status for '{clean_pid}' to ACTIVE in Firestore")
            except Exception as fs_err:
                logger.warning(f"Could not finalize Firestore status: {fs_err}")

        self._sync_redeploy_ipam(clean_pid, new_project_id)

        return {
            "status": "ACTIVE",
            "product_id": clean_pid,
            "project_id": new_project_id,
            "service_url": new_service_url,
            "redeployed_at": now_iso,
            "redeployed_by": operator_email,
            "wif_secrets_updated": wif_secrets_updated,
            "gcp_project": vended_gcp,
            "terraform_result": tf_result,
            "message": f"Workload '{clean_pid}' successfully redeployed into project '{new_project_id}'. Live URL: {new_service_url or 'not reported'}",
            **({DEPLOY_SECRETS_ERROR_FIELD: wif_secrets_error} if wif_secrets_error else {}),   # RT14-18
        }

    def _sync_redeploy_ipam(self, clean_pid: str, new_project_id: str) -> None:
        """Synchronize the IPAM reservation back to ALLOCATED with new_project_id (the project exists either way)."""
        try:
            try:
                from shared.ipam import CastorIPAMEngine
            except ImportError:
                from .shared.ipam import CastorIPAMEngine
            ipam_engine = CastorIPAMEngine(db=self.db)
            ipam_engine.reclaim_workload_cidrs(clean_pid, new_project_id=new_project_id)
        except Exception as ipam_err:
            logger.warning(f"IPAM redeploy sync notice for '{clean_pid}': {ipam_err}")

    def _record_redeploy_vend_failed(self, clean_pid: str, trace_id: str, new_project_id: str, operator_email: str,
                                     now_iso: str, err: BaseException) -> None:
        """Gap 4 (VENDING-CLIENT-FAIL-LOUD): the vend step of a redeploy raised. The workload (REDEPLOYING since step 3)
        is recorded FAILED with the vend's typed class (a VendingFailure's error_class; any other exception is
        REDEPLOY_VEND_FAILED with its class name, never its message) and an audit entry. Best effort: a record write
        error is logged and never replaces the vend's own failure, which the caller raises unchanged."""
        if isinstance(err, VendingFailure):
            error_class, reason = err.error_class, str(err)
        else:
            error_class, reason = REDEPLOY_VEND_FAILED, f"{REDEPLOY_VEND_FAILED}: {type(err).__name__}"
        logger.error(f"Redeploy of '{clean_pid}' stopped at the vend of '{new_project_id}' ({error_class})")
        if not self.db:
            return
        try:
            doc_ref = self.db.collection("workloads").document(clean_pid)
            doc_ref.set({
                "status": "FAILED",
                "failure_reason": reason,
                "redeploy_error_class": error_class,
                "vending_error_class": error_class,
                "redeploy_stage": "vending",
                "redeploy_trace_id": trace_id,
                "redeploy_failed_at": datetime.now(timezone.utc).isoformat(),
            }, merge=True)
            doc_ref.collection("audit_logs").document().set({
                "action": "WORKLOAD_REDEPLOY_FAILED",
                "operator_email": operator_email,
                "new_project_id": new_project_id,
                "error_class": error_class,
                "stage": "vending",
                "timestamp": now_iso,
            })
        except Exception as fs_err:  # noqa: BLE001
            logger.error(f"Could not record the failed redeploy vend of '{clean_pid}': {type(fs_err).__name__}")

    def _record_redeploy_failed(self, clean_pid: str, trace_id: str, new_project_id: str,
                                folder_to_use: Optional[str], operator_email: str, now_iso: str,
                                failure: Dict[str, Any], *, wif_secrets_updated: bool,
                                vended_gcp: Any) -> Dict[str, Any]:
        """FD vending-redeploy: the terraform deploy did not answer HTTP 200, so the workload is FAILED with the
        typed class (never ACTIVE). The vended project is recorded (it exists), no service URL is invented, and the
        result carries status FAILED for the route to answer with REDEPLOY_FAILURE_HTTP_STATUS[error_class]."""
        error_class = failure["error_class"]
        detail = failure["error"]
        logger.error(f"Redeploy of '{clean_pid}' into '{new_project_id}' failed ({error_class}, "
                     f"HTTP {failure.get('http_status')})")
        if self.db:
            try:
                doc_ref = self.db.collection("workloads").document(clean_pid)
                failed_update = {
                    "status": "FAILED",
                    "project_id": new_project_id,
                    "failure_reason": f"{error_class}: {detail}",
                    "redeploy_error_class": error_class,
                    "redeploy_http_status": failure.get("http_status"),
                    "redeploy_trace_id": trace_id,
                    "redeploy_failed_at": datetime.now(timezone.utc).isoformat(),
                }
                if folder_to_use:
                    failed_update["folder_id"] = folder_to_use
                doc_ref.set(failed_update, merge=True)
                doc_ref.collection("audit_logs").document().set({
                    "action": "WORKLOAD_REDEPLOY_FAILED",
                    "operator_email": operator_email,
                    "new_project_id": new_project_id,
                    "error_class": error_class,
                    "http_status": failure.get("http_status"),
                    "timestamp": now_iso,
                    "wif_secrets_updated": wif_secrets_updated,
                })
            except Exception as fs_err:
                logger.error(f"Could not record the failed redeploy of '{clean_pid}': {type(fs_err).__name__}")

        self._sync_redeploy_ipam(clean_pid, new_project_id)

        return {
            "status": "FAILED",
            "error_class": error_class,
            "http_status": failure.get("http_status"),
            "error": detail,
            "product_id": clean_pid,
            "project_id": new_project_id,
            "trace_id": trace_id,
            "redeployed_at": now_iso,
            "redeployed_by": operator_email,
            "wif_secrets_updated": wif_secrets_updated,
            "gcp_project": vended_gcp,
            "message": f"Workload '{clean_pid}' was not redeployed into project '{new_project_id}' ({error_class}).",
        }
