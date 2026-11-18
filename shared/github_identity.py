"""
Project Castor: Centralized GitHub Repository Identity Resolver
Provides deterministic parsing and normalization of GitHub repository identifiers,
HTTPS clone URLs, SSH URLs, and shorthand owner/repo strings across all platform services.
"""

import logging
import os
import re
from typing import Optional, Tuple

# FD-4AY / FD-12: there is no built-in GitHub owner. An install names it in its tfvars (`workloads_github_owner` /
# `github_owner` -> GITHUB_ORG / GITHUB_OWNER on every Cloud Run service; the terraform server forwards both to the
# tf-applier job). With VCS_PROVIDER=GITHUB (the default) an unset owner is an error: any built-in value would be
# another installer's organization.
#
# SERVERLESS_GIT_NAMESPACE (FD-4AY, owner 10-26): only for VCS_PROVIDER other than GITHUB with no GITHUB_ORG, where
# the owner segment never reaches a VCS (the Serverless Git provider keys repositories by product id alone) and is
# just the first half of stored/generated `owner/<id>` identities. It is deliberately NOT a valid GitHub
# account name (the underscore is outside GitHub's [A-Za-z0-9-] alphabet): the workload-foundation WIF provider
# trusts GitHub OIDC tokens for `assertion.repository == '<owner>/<id>'`, so a registrable name would let
# whoever registers that GitHub account mint deployer tokens for every such workload. Lowercase, so it is also a
# valid GCP label value. A record stored with an explicit owner keeps that owner (resolve_repo_identity never
# consults this fallback when the identifier names one).
SERVERLESS_GIT_NAMESPACE = "stackvend_serverless-git"


class GitHubOwnerNotConfiguredError(RuntimeError):
    """VCS_PROVIDER is GITHUB and none of GITHUB_ORG / GITHUB_DEPLOYMENTS_ORG / GITHUB_OWNER is set."""


def get_default_github_owner() -> str:
    """
    Resolves the platform default GitHub owner/organization following the standardized precedence:
      1. GITHUB_ORG
      2. GITHUB_DEPLOYMENTS_ORG
      3. GITHUB_OWNER
      4. none set: VCS_PROVIDER=GITHUB (default) -> GitHubOwnerNotConfiguredError;
         any other VCS provider -> SERVERLESS_GIT_NAMESPACE
    """
    configured = os.getenv("GITHUB_ORG") or os.getenv("GITHUB_DEPLOYMENTS_ORG") or os.getenv("GITHUB_OWNER")
    if configured:
        return configured
    if (os.getenv("VCS_PROVIDER") or "GITHUB").strip().upper() == "GITHUB":
        raise GitHubOwnerNotConfiguredError(
            "No GitHub owner configured: set GITHUB_ORG (tfvars workloads_github_owner or github_owner)."
        )
    return SERVERLESS_GIT_NAMESPACE


def default_repository_name(product_id: str) -> str:
    """GITHUB-REPO-NAME-NO-PREFIX (owner 11-12): the name of the repository a workload gets when its record names
    none: the workload id, lower case, every `_` replaced by `-` (no prefix: an organization's repositories are visible
    to its staff). The one definition of the default; resolve_repo_identity uses it for an empty identifier. A record
    that stores `github_repo` keeps that name (a workload vended before 11-12 keeps its `castor-<id>` repository)."""
    return product_id.lower().replace("_", "-")


def resolve_repo_identity(
    github_repo_url_or_name: Optional[str],
    default_owner: Optional[str] = None,
    product_id: Optional[str] = None,
) -> Tuple[str, str, str]:
    """
    Extracts and normalizes (owner, repo, full_name) from any GitHub identifier.

    Handles:
      - Full HTTPS URLs: "https://github.com/AcmeCorp/payment-svc.git" -> ("AcmeCorp", "payment-svc", "AcmeCorp/payment-svc")
      - SSH URLs: "git@github.com:AcmeCorp/payment-svc.git" -> ("AcmeCorp", "payment-svc", "AcmeCorp/payment-svc")
      - Shorthand: "AcmeCorp/payment-svc" -> ("AcmeCorp", "payment-svc", "AcmeCorp/payment-svc")
      - Bare repo names: "payment-svc" -> (resolved_owner, "payment-svc", f"{resolved_owner}/payment-svc")
      - Empty/None with product_id: (resolved_owner, default_repository_name(product_id),
        f"{resolved_owner}/{default_repository_name(product_id)}"), e.g. "Payment_Svc" -> "payment-svc"

    Returns:
      Tuple of (owner, repo, full_name) where full_name is "owner/repo".
    """
    def _owner_fallback() -> str:
        # Resolved only when the identifier names no owner (FD-4AY: an unconfigured GitHub owner raises).
        # Guard default_owner against Mock objects
        if default_owner is not None and not isinstance(default_owner, str):
            if hasattr(default_owner, "__class__") and "Mock" in default_owner.__class__.__name__:
                return get_default_github_owner()
            return str(default_owner)
        return default_owner or get_default_github_owner()

    if isinstance(github_repo_url_or_name, dict):
        raw = str(
            github_repo_url_or_name.get("full_name")
            or github_repo_url_or_name.get("html_url")
            or github_repo_url_or_name.get("repo_name")
            or ""
        ).strip()
    elif isinstance(github_repo_url_or_name, str):
        raw = github_repo_url_or_name.strip()
    else:
        raw = ""

    # If empty, the workload's default repository (GITHUB-REPO-NAME-NO-PREFIX: the workload id, no prefix)
    if not raw:
        owner_fallback = _owner_fallback()
        if product_id and isinstance(product_id, str):
            repo_name = default_repository_name(product_id)
            return owner_fallback, repo_name, f"{owner_fallback}/{repo_name}"
        return owner_fallback, "", f"{owner_fallback}/"

    # Strip .git suffix and surrounding slashes
    clean = raw.strip().rstrip("/")
    clean = re.sub(r"\.git$", "", clean).strip("/")

    # Pattern 1: HTTPS URL (e.g. https://github.com/owner/repo)
    https_match = re.search(r"github\.com/([^/]+)/([^/]+)$", clean)
    if https_match:
        owner = https_match.group(1).strip()
        repo = https_match.group(2).strip()
        return owner, repo, f"{owner}/{repo}"

    # Pattern 2: SSH URL (e.g. git@github.com:owner/repo)
    ssh_match = re.search(r"github\.com:([^/]+)/([^/]+)$", clean)
    if ssh_match:
        owner = ssh_match.group(1).strip()
        repo = ssh_match.group(2).strip()
        return owner, repo, f"{owner}/{repo}"

    # Pattern 3: Shorthand owner/repo
    if "/" in clean:
        parts = clean.split("/", 1)
        owner = parts[0].strip()
        repo = parts[1].strip()
        return owner, repo, f"{owner}/{repo}"

    # Pattern 4: Bare repository name
    owner_fallback = _owner_fallback()
    return owner_fallback, clean, f"{owner_fallback}/{clean}"


# FD-4AT-c (register row FD-4AT-c, owner 10-20): the tenant WIF condition also binds GitHub's immutable numeric
# repository id, so a repository deleted and re-created under the same name (by anyone who can then own that name)
# cannot mint deploy tokens. Vending resolves the id from the GitHub API and stores this record on
# workloads/{product_id}; tf-applier passes the id to the workload-foundation module only when the record names the
# exact repository being applied. The record always carries the name it was resolved for, so a later change of
# `github_repo` can never pair the new name with an old id.
GITHUB_REPOSITORY_IDENTITY_FIELD = "github_repository_identity"


def _repository_id_str(repository_id: object) -> Optional[str]:
    """GitHub's numeric repository id as decimal digits, or None. Accepts a positive int (PyGithub `Repository.id`)
    or a string of ASCII decimal digits without a leading zero; never a bool, float or anything else."""
    if isinstance(repository_id, bool):
        return None
    if isinstance(repository_id, int):
        return str(repository_id) if repository_id > 0 else None
    if isinstance(repository_id, str) and repository_id.isascii() and repository_id.isdigit() \
            and not repository_id.startswith("0"):
        return repository_id
    return None


def github_repository_identity_record(full_name: str, repository_id: object) -> dict:
    """The Firestore value vending writes under GITHUB_REPOSITORY_IDENTITY_FIELD. An unresolved or invalid id is
    stored as None (explicitly), so it also replaces an id recorded for an earlier repository of the same name."""
    return {"full_name": str(full_name or ""), "repository_id": _repository_id_str(repository_id)}


def pinned_github_repository_id(record: object, full_repo_name: str) -> Optional[str]:
    """The repository id to pin for `full_repo_name`, or None (not pinned: the WIF condition keeps the repository
    name + main-branch check). Pinned only when the record names the same repository (GitHub owner and repository
    names are case-insensitive) and carries a valid id."""
    if not isinstance(record, dict) or not isinstance(full_repo_name, str) or not full_repo_name:
        return None
    recorded_name = record.get("full_name")
    if not isinstance(recorded_name, str) or recorded_name.lower() != full_repo_name.lower():
        return None
    return _repository_id_str(record.get("repository_id"))


def repository_names(record: object, full_name: str) -> bool:
    """GITHUB-REPO-NAME-NO-PREFIX: whether the workload's GITHUB_REPOSITORY_IDENTITY_FIELD `record` names the
    repository `full_name` (GitHub owner and repository names are case-insensitive). Vending writes it as a claim
    ({full_name, repository_id: None}) before it creates the repository, and with the id after the vend."""
    if not isinstance(record, dict) or not isinstance(full_name, str) or not full_name:
        return False
    recorded_name = record.get("full_name")
    return isinstance(recorded_name, str) and recorded_name.lower() == full_name.lower()


def repository_is_workloads_own(record: object, full_name: str, repository_id: object) -> Optional[bool]:
    """GITHUB-REPO-NAME-NO-PREFIX (owner 11-12): whether an EXISTING GitHub repository `full_name` (GitHub id
    `repository_id`, None when it could not be read) that vending found where it would create the workload's
    repository is that workload's own, from the workload's GITHUB_REPOSITORY_IDENTITY_FIELD `record`.

    True: the record names it (repository_names) and pins no id (the claim written before the create, or an id that
    could not be read at that vend), or pins the id GitHub reports. False: no record, another name, or a pinned id
    GitHub contradicts: vending refuses it (GITHUB_REPOSITORY_NAME_TAKEN) and never uses or changes it. None: the
    record pins an id and GitHub's id could not be read: unknown (vending stops with GITHUB_REPOSITORY_UNREADABLE and
    the next run reads again), never "taken"."""
    if not repository_names(record, full_name):
        return False
    pinned = _repository_id_str(record.get("repository_id"))
    if pinned is None:
        return True
    found = _repository_id_str(repository_id)
    if found is None:
        return None
    return pinned == found


def next_github_repository_identity(existing: object, full_name: str, resolved_id: object,
                                    repository_created: bool = False) -> Optional[dict]:
    """The record vending writes now, or None to keep the stored one.

    Fail closed: a valid id already recorded for this repository name is never replaced by a missing or different id,
    because a repository deleted and re-created (or re-registered) under the same name is exactly what the pin
    rejects. The one exception is a repository the platform itself created in this vend (`repository_created`): the
    old repository was gone and the new one is the platform's own. An owner who re-created a repository with an
    operator-chosen (or pre-11-12 `castor-<id>`) name on purpose clears the record (Firestore field
    `github_repository_identity` on the workload) and re-vends; a repository named after the workload id is never
    re-pinned that way (vending refuses an unrecorded one: GITHUB_REPOSITORY_ID_CHANGED says what to do)."""
    new = github_repository_identity_record(full_name, resolved_id)
    stored = pinned_github_repository_id(existing, full_name)
    if stored is None:
        return new
    if new["repository_id"] == stored:
        return None
    if repository_created and new["repository_id"] is not None:
        return new
    return None


# FD-4CI-b-R1-WIF-SHARED (register row SAT-1031 approvals, owner 10-29): workloads that share one GitHub repository
# (a promoted workload's branch lives in the source workload's repository) cannot all use the repository's plain
# GitHub Actions deploy secrets GCP_PROJECT_ID / WIF_PROVIDER / WIF_SERVICE_ACCOUNT: those belong to one workload.
# Such a workload's secrets carry its branch as a suffix (`WIF_PROVIDER_<suffix>`). One rule for the writer (vending
# redeploy) and the reader (the generated deploy workflow).
DEPLOY_SECRET_BASE_NAMES = ("GCP_PROJECT_ID", "WIF_PROVIDER", "WIF_SERVICE_ACCOUNT")


def branch_secret_suffix(branch: str) -> str:
    """The suffix of a workload's branch-named deploy secrets: the branch upper-cased, every character outside
    [A-Z0-9_] replaced by "_" (e.g. "release/v1.2-rc" -> "RELEASE_V1_2_RC"). The result is a valid GitHub secret-name
    tail. Raises ValueError for anything that is not a non-empty string."""
    if not isinstance(branch, str) or not branch:
        raise ValueError(f"not a branch name: {branch!r}")
    return re.sub(r"[^A-Z0-9_]", "_", branch.upper())


def repository_shared_with_other_workload(db, product_id: str, repo_full_name: str,
                                          default_owner: Optional[str] = None) -> Optional[bool]:
    """True when a workload record other than `product_id`'s names the repository `repo_full_name`
    (resolve_repo_identity of its github_repo; no field = its default repository <owner>/<pid>; GitHub owner and
    repository names compare case-insensitively), False when none does, None when the records cannot be read
    (callers treat None as shared; logged). Read only: streams the `workloads` collection of `db`."""
    if db is None or not isinstance(repo_full_name, str) or not repo_full_name:
        return None
    wanted = repo_full_name.lower()
    try:
        for doc in db.collection("workloads").stream():
            if doc.id == product_id:
                continue
            # A record without github_repo is its default repository (<owner>/<pid>), never skipped.
            other_repo = (doc.to_dict() or {}).get("github_repo")
            _, _, other = resolve_repo_identity(other_repo, default_owner=default_owner, product_id=doc.id)
            if isinstance(other, str) and other.lower() == wanted:
                return True
    except Exception as e:  # noqa: BLE001 - unreadable records (or no owner to resolve them): unknown = shared
        logging.getLogger(__name__).warning(
            f"Could not read workload records to check whether '{repo_full_name}' is shared: {type(e).__name__}")
        return None
    return False


# GHA-DEPLOY-SWITCH (register row GHA-DEPLOY-SWITCH, owner 10-30): the per-workload switch for the GitHub Actions
# deploy path (the generated .github/workflows/deploy-<service>.yml + sa-gh-deployer through Workload Identity
# Federation). Stored as workloads/{product_id}.github_actions_deploy; Serverless Git workloads ignore it.
GITHUB_ACTIONS_DEPLOY_FIELD = "github_actions_deploy"


class GitHubActionsDeploySwitchInvalid(ValueError):
    """workloads/{pid}.github_actions_deploy holds something other than true, false or nothing."""


def github_actions_deploy_enabled(record_value: object) -> bool:
    """The recorded switch: True (on) or False (off). Missing (None) is on, as for every workload created before the
    switch existed. Any other value raises GitHubActionsDeploySwitchInvalid; it is never coerced."""
    if record_value is None:
        return True
    if isinstance(record_value, bool):
        return record_value
    raise GitHubActionsDeploySwitchInvalid(
        f"{GITHUB_ACTIONS_DEPLOY_FIELD} must be true or false, not {type(record_value).__name__}")
