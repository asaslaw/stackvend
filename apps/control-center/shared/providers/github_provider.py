"""
Project Castor: GitHub Provider Adapter (`GitHubProvider`)
Consolidates all GitHub-specific operations (PyGithub, JIT token minting,
tree creation, branch rebasing, pipeline validation, and archive streaming)
behind the abstract VCSProvider interface.
"""

import base64
import hashlib
import io
import logging
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import time
from typing import Any, BinaryIO, Dict, List, Optional, Sequence, Tuple

# FD-4G: no ImportError fallback -- a missing path guard must crash at import, never fail open.
from ..path_safety import GIT_RESERVED, UnsafePathError, safe_join

try:
    from github import Github, GithubException, InputGitTreeElement
except ImportError:
    Github = None
    GithubException = Exception
    class InputGitTreeElement:
        def __init__(self, path: str, mode: str, type: str, content: str):
            self.path = path
            self.mode = mode
            self.type = type
            self.content = content

try:
    import httpx
except ImportError:
    httpx = None
else:
    # FD-4DC RT F1: httpx logs every request URL at INFO ("HTTP Request: GET <url>"), and an archive download URL
    # (codeload, after the redirect) carries a short-lived token in its query. Every service logs at INFO, so the
    # httpx / httpcore loggers are kept at WARNING: no request URL reaches the logs (archive read and
    # export_archive_stream alike).
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

try:
    import dulwich
    from dulwich import porcelain
    from dulwich.repo import Repo
    DULWICH_AVAILABLE = True
except ImportError:
    dulwich = None
    porcelain = None
    Repo = None
    DULWICH_AVAILABLE = False

from ..vcs_provider import (
    DEFAULT_AGENT_AUTHOR_EMAIL,
    IncompleteRepoTreeError,
    PipelineConfig,
    PRIdentity,
    PRIdentityMismatch,
    PRMergeNotCompleted,
    RepositoryMetadata,
    VCSProvider,
)
from ..github_identity import get_default_github_owner, resolve_repo_identity
from ..github_resilience import (
    GitHubTokenManager,
    get_github_token,
    get_github_client,
    github_retry_with_backoff,
    create_or_verify_branch as resilience_create_branch,
    GitHubRateLimitExceededError,
)
try:
    from ..workflow_validator import validate_github_workflow_yaml, WorkflowValidationError
except Exception:
    try:
        from shared.workflow_validator import validate_github_workflow_yaml, WorkflowValidationError
    except Exception:
        validate_github_workflow_yaml = None
        WorkflowValidationError = Exception

logger = logging.getLogger("vcs-github-provider")


# ----------------------------------------------------------------------------------------------------------------
# RT14-10 (owner 11-14): the GitHub credential never goes on a git command line. It used to be passed as
# `git -c http.extraHeader=Authorization: Basic <token>`, which is visible in the process table and is in the text of
# subprocess.TimeoutExpired / CalledProcessError (their str() is the full argv): a slow push logged a one-hour,
# organisation-wide installation token. Now the header goes through git's own environment configuration
# (GIT_CONFIG_COUNT / GIT_CONFIG_KEY_n / GIT_CONFIG_VALUE_n, git 2.31 or later) and only for the commands that reach
# GitHub; every git call goes through run_git, whose typed error names the sub-command and the timeout only.
# ----------------------------------------------------------------------------------------------------------------
class GitCommandFailed(RuntimeError):
    """RT14-10: a git CLI call failed, timed out or could not start. The message carries the sub-command, the reason
    and the exit code, never the argv or the environment, and the token values are removed from git's own stderr."""

    error_class = "GIT_COMMAND_FAILED"
    stage = "vcs_commit"

    def __init__(self, subcommand: str, reason: str, returncode: Optional[int] = None):
        self.subcommand = subcommand
        self.returncode = returncode
        super().__init__(f"git {subcommand} failed: {reason}")


def git_auth_env(token: str, base_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """RT14-10: a copy of `base_env` (default: the process environment) that gives git the GitHub Basic auth header
    through git's environment configuration, appended after any GIT_CONFIG_* entries already there. Never argv."""
    env = dict(os.environ if base_env is None else base_env)
    env["GIT_TERMINAL_PROMPT"] = "0"
    try:
        index = int(env.get("GIT_CONFIG_COUNT") or 0)
    except ValueError:
        index = 0
    auth_str = base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("utf-8")
    env[f"GIT_CONFIG_KEY_{index}"] = "http.extraHeader"
    env[f"GIT_CONFIG_VALUE_{index}"] = f"Authorization: Basic {auth_str}"
    env["GIT_CONFIG_COUNT"] = str(index + 1)
    return env


def git_secret_values(token: str) -> Tuple[str, ...]:
    """The exact strings that must never appear in a git error: the token and its Basic header form."""
    if not token:
        return ()
    return (token, base64.b64encode(f"x-access-token:{token}".encode("utf-8")).decode("utf-8"))


def without_git_secrets(text: Optional[str], secrets: Sequence[str]) -> str:
    out = (text or "").strip()
    for value in secrets:
        if value:
            out = out.replace(value, "[REDACTED]")   # exact values only (invariant 2: no pattern guessing)
    return out[:2000]


def run_git(args: Sequence[str], *, env: Dict[str, str], timeout: float, cwd: Optional[str] = None,
            check: bool = False, secrets: Sequence[str] = ()) -> "subprocess.CompletedProcess":
    """RT14-10: runs `git <args>` (text, stdout and stderr captured). A timeout, a git that cannot start, or (with
    `check`) a non-zero exit raises GitCommandFailed naming the sub-command only; the subprocess exception (whose text
    is the argv) is never chained or logged. Returns the CompletedProcess otherwise (the caller reads returncode)."""
    subcommand = next((a for a in args if not str(a).startswith("-")), "?")
    try:
        res = subprocess.run(["git", *args], cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise GitCommandFailed(subcommand, f"timed out after {timeout} s") from None
    except OSError as start_err:
        raise GitCommandFailed(subcommand, f"git could not start ({type(start_err).__name__})") from None
    if check and res.returncode != 0:
        raise GitCommandFailed(subcommand, f"exit code {res.returncode}: {without_git_secrets(res.stderr, secrets)}",
                               res.returncode)
    return res


class VCSDeletionNotStaged(RuntimeError):
    """DULWICH-DELETE-LOUD: the dulwich commit path could not stage every requested deletion (or a path was both
    written and deleted). Raised before the commit and the push, so nothing was committed. ``paths`` lists the
    offending tracked paths."""

    error_class = "VCS_DELETION_NOT_STAGED"
    stage = "vcs_commit"

    def __init__(self, repo: str, branch: str, paths: List[str], reason: str):
        self.repo, self.branch, self.paths = repo, branch, list(paths)
        super().__init__(f"Dulwich commit to '{repo}' ({branch}) refused: {reason}: {self.paths[:20]}. "
                         f"Nothing was committed.")


class GitHubOwnerNotOrganizationError(RuntimeError):
    """GITHUB-ORG-ONLY: the configured GitHub owner is not an organization (a personal account, or no account of
    that name). StackVend acts through short-lived GitHub App installation tokens, which can create repositories
    only in an organization where the App is installed; a personal account is not supported. ``owner_type`` is the
    account type GitHub reports ("User", ...) or "NOT_FOUND"."""

    error_class = "GITHUB_OWNER_NOT_ORGANIZATION"
    stage = "vcs_repository_vending"

    def __init__(self, owner: str, owner_type: str):
        self.owner, self.owner_type = owner, owner_type
        found = ("is a personal GitHub account" if owner_type == "User"
                 else "does not exist on GitHub" if owner_type == "NOT_FOUND"
                 else f"is a GitHub account of type '{owner_type}'")
        super().__init__(f"{self.error_class}: the GitHub owner '{owner}' {found}, not an organization. The GitHub "
                         f"VCS provider needs an organization with the StackVend GitHub App installed; personal "
                         f"accounts are not supported. Nothing was created.")


class GitHubRepositoryCreateError(RuntimeError):
    """GITHUB-REPO-CREATE-FAIL-LOUD: GitHub did not create the workload repository (or there was no GitHub client to
    ask). Never answered with invented repository metadata. ``status`` is GitHub's HTTP status (None when GitHub gave
    none); ``headers`` / ``data`` are GitHub's, so github_retry_with_backoff classifies a rate limit or a transient
    error exactly as it does for the original exception. The hint is chosen by ``status`` only."""

    error_class = "GITHUB_REPOSITORY_CREATE_FAILED"
    stage = "vcs_repository_vending"

    def __init__(self, owner: str, full_name: str, status: Optional[int], reason: str,
                 headers: Optional[Dict[str, Any]] = None, data: Any = None):
        self.owner, self.full_name, self.status, self.reason = owner, full_name, status, reason
        self.headers, self.data = dict(headers or {}), data
        if status == 403:
            hint = (f" Check the StackVend GitHub App is installed on {owner} with repository permission "
                    f"Administration: Read & Write.")
        elif status == 422:
            hint = (f" A repository of that name may already exist but not be visible to the App: give the App access "
                    f"to it (installation repository access \"All repositories\", or include '{full_name}'), or use "
                    f"another name.")
        else:
            hint = ""
        http = f"HTTP {status}" if status is not None else "no HTTP answer"
        super().__init__(f"{self.error_class}: the GitHub repository '{full_name}' was not created ({http}: "
                         f"{reason}).{hint}")

    @classmethod
    def from_exception(cls, owner: str, full_name: str, err: BaseException) -> "GitHubRepositoryCreateError":
        """The typed error for a failed create call; GitHub's status / headers / body are taken from the exception's
        own attributes (PyGithub GithubException: status, headers, data), never from its text."""
        status = getattr(err, "status", None)
        status = status if isinstance(status, int) and not isinstance(status, bool) else None
        headers = getattr(err, "headers", None)
        data = getattr(err, "data", None)
        message = data.get("message") if isinstance(data, dict) else None
        return cls(owner, full_name, status, str(message or type(err).__name__),
                   headers=headers if isinstance(headers, dict) else None, data=data)


def require_github_organization(client: Any, owner: str) -> Any:
    """GITHUB-ORG-ONLY: the PyGithub Organization for `owner`, or GitHubOwnerNotOrganizationError. Decided from
    GitHub's typed answers only: GET /orgs/{owner} answers 404 for anything that is not an organization, then
    GET /users/{owner} gives the account `type` (404 = no such account). Any other GitHub error is re-raised as it
    is (it says nothing about the owner's kind)."""
    try:
        org = client.get_organization(owner)
        getattr(org, "id", None)   # completes the object on a lazy client (an eager one already fetched it)
        return org
    except GithubException as org_err:
        if getattr(org_err, "status", None) != 404:
            raise
        try:
            owner_type = str(getattr(client.get_user(owner), "type", "") or "UNKNOWN")
        except GithubException as user_err:
            if getattr(user_err, "status", None) != 404:
                raise
            owner_type = "NOT_FOUND"
        if owner_type == "Organization":
            raise   # an organization the token cannot see: the original 404 says so
        raise GitHubOwnerNotOrganizationError(owner, owner_type) from org_err


def _tree_priority_key(file_name: str) -> tuple:
    """FD-4D: which blobs a capped `fetch_file_tree` keeps. The same rule as the git server's
    `apps/git-server/main.py::_tree_priority_key` (parity pinned by tests/test_fd4d_tree_completeness.py), so both
    VCS backends cap a large tree the same way: tier 0 = `infra/`, any `.tf`, the named entrypoints and root
    files; tier 1 = everything else; each tier in path order."""
    if (
        file_name.startswith("infra/")
        or file_name.endswith(".tf")
        or file_name in ("Procfile", "Dockerfile", "requirements.txt", "main.py", "app.py")
        or "/" not in file_name
    ):
        return (0, file_name)
    return (1, file_name)


# FD-4DC: one tarball read instead of one blob call per file. An archive member is used only when its git blob SHA
# equals the SHA the tree listing gave for that path, so the content is exactly what the blob call returns; any path
# the archive does not prove is read with its blob call as before. Bounds: the compressed bytes downloaded and the
# total member bytes walked (a gzip bomb stops the archive read, never the fetch).
ARCHIVE_MIN_BLOBS = 3                       # below this an archive (link + download) saves no API calls
ARCHIVE_MAX_COMPRESSED_BYTES = 64 * 1024 * 1024
ARCHIVE_MAX_MEMBER_BYTES = 512 * 1024 * 1024   # unpacked tar stream: headers + padded data blocks (RT F3)
ARCHIVE_MAX_MEMBERS = 100_000                    # GitHub's own recursive-tree entry limit (RT F3)
ARCHIVE_TIMEOUT_SECONDS = 60.0                   # per operation AND a whole-download deadline (RT F4)
TAR_BLOCK = 512


def git_blob_sha(data: bytes) -> str:
    """The git object id of a blob with this content (what `git hash-object` prints)."""
    return hashlib.sha1(b"blob %d\x00" % len(data) + data).hexdigest()


def verified_blobs_from_tarball(archive: Any, wanted: Dict[str, str]) -> Dict[str, bytes]:
    """{path: bytes} for each path of `wanted` ({path: blob sha}) whose archive member has exactly that blob SHA.

    `archive` is the .tar.gz as bytes or a binary file object positioned at its start. The archive is GitHub's
    `git archive` tarball: every member sits under one top directory (`<owner>-<repo>-<sha>/`), which is dropped. A
    symlink is compared by its target, as git stores it. Members that are not wanted, or whose SHA differs, are
    ignored (the caller reads those paths with blob calls). Raises ValueError when the unpacked tar stream (each
    member's 512-byte header plus its data padded to 512-byte blocks, RT F3) passes ARCHIVE_MAX_MEMBER_BYTES or the
    archive has more than ARCHIVE_MAX_MEMBERS members; tarfile errors propagate."""
    found: Dict[str, bytes] = {}
    walked = 0
    members = 0
    fileobj = io.BytesIO(archive) if isinstance(archive, (bytes, bytearray)) else archive
    with tarfile.open(fileobj=fileobj, mode="r|gz") as tar:
        for member in tar:
            size = max(int(member.size or 0), 0)
            walked += TAR_BLOCK + ((size + TAR_BLOCK - 1) // TAR_BLOCK) * TAR_BLOCK
            members += 1
            if walked > ARCHIVE_MAX_MEMBER_BYTES:
                raise ValueError(f"archive members exceed {ARCHIVE_MAX_MEMBER_BYTES} bytes")
            if members > ARCHIVE_MAX_MEMBERS:
                raise ValueError(f"archive has more than {ARCHIVE_MAX_MEMBERS} members")
            _top, sep, rel = member.name.partition("/")
            if not sep or rel not in wanted or rel in found:
                continue
            if member.issym():
                data = member.linkname.encode("utf-8", errors="surrogateescape")
            elif member.isfile():
                handle = tar.extractfile(member)
                data = handle.read() if handle is not None else b""
            else:
                continue
            if git_blob_sha(data) == wanted[rel]:
                found[rel] = data
    return found


# FD-4BB RT M1: the GitHub identity the platform token acts as, resolved once per process (successes only).
_ACTOR_CACHE: Dict[Any, Tuple[int, str]] = {}


def apply_initial_branch(repo: Any, initial_branch: Optional[str]) -> str:
    """FD-4CI-b-R1: make `initial_branch` the default branch of a repository that was JUST created with
    ``auto_init`` (GitHub gave it the account's default branch, usually main): the branch is created at the initial
    commit and set as the repository default. Returns the repository's default branch afterwards. Nothing is done when
    the repository already has that branch as its default; the auto-init branch is left in place (nothing is deleted).
    A failure is logged and the repository keeps the branch GitHub gave it (never raises). Never called for a
    repository that already existed."""
    current = getattr(repo, "default_branch", None) or "main"
    if not initial_branch or initial_branch == current:
        return current
    try:
        head_sha = repo.get_branch(current).commit.sha
        repo.create_git_ref(ref=f"refs/heads/{initial_branch}", sha=head_sha)
        repo.edit(default_branch=initial_branch)
    except Exception as e:  # noqa: BLE001 - the repository exists; it keeps GitHub's default branch
        logger.error(f"DEFAULT_BRANCH_NOT_APPLIED: repository '{getattr(repo, 'full_name', '')}' keeps its default "
                     f"branch '{current}'; '{initial_branch}' could not be set ({type(e).__name__}: {e})")
        return current
    logger.info(f"Repository '{getattr(repo, 'full_name', '')}' default branch set to '{initial_branch}'")
    return initial_branch


class GitHubProvider(VCSProvider):
    """Encapsulates all GitHub operations for Project Castor."""

    def __init__(
        self,
        project_id: Optional[str] = None,
        github_token: Optional[str] = None,
        default_owner: Optional[str] = None,
        settings: Optional[Any] = None,
        **kwargs: Any,
    ):
        self.project_id = (
            project_id
            or getattr(settings, "project_id", None)
            or os.getenv("PROJECT_ID")
            or os.getenv("GOOGLE_CLOUD_PROJECT")
            or ""
        )
        self._explicit_token = github_token
        self.default_owner = (
            default_owner
            or getattr(settings, "github_owner", None)
            or os.getenv("GITHUB_OWNER")
            or os.getenv("GITHUB_ORG")
            or get_default_github_owner()
        )
        self._token_manager = GitHubTokenManager(project_id=self.project_id) if self.project_id else None

    def get_token(self) -> str:
        """Resolves active GitHub token via explicit token, TokenManager, or environment."""
        if self._explicit_token:
            return self._explicit_token
        if self._token_manager:
            try:
                t = self._token_manager.get_token()
                if t:
                    return t
            except Exception as e:
                logger.debug(f"TokenManager token fetch notice: {e}")
        return get_github_token(self.project_id)

    def get_client(self) -> Any:
        """Returns an authenticated PyGithub client instance."""
        token = self.get_token()
        if not token:
            logger.warning("No GitHub token resolved. Operating without authenticated PyGithub client.")
            if Github is not None:
                return Github()
            return None
        if Github is None:
            raise RuntimeError("PyGithub is not installed in this Python environment.")
        return Github(token)

    def _get_repo(self, repo_identifier: str) -> Any:
        """Resolves PyGithub repository object."""
        _, _, full_name = resolve_repo_identity(repo_identifier, default_owner=self.default_owner)
        client = self.get_client()
        if not client:
            raise RuntimeError("Cannot resolve GitHub repository without PyGithub client.")
        return client.get_repo(full_name)

    # --------------------------------------------------------------------------
    # 1. Repository Lifecycle & Metadata
    # --------------------------------------------------------------------------
    @github_retry_with_backoff(max_retries=3, initial_wait=2.0)
    def vend_repository(
        self,
        product_id: str,
        description: str = "",
        initial_branch: str = "main",
        auto_protect_branch: bool = True,
        github_owner: Optional[str] = None,
        **kwargs: Any,
    ) -> RepositoryMetadata:
        """Creates a new repository on GitHub with README and branch protection."""
        owner, repo_name, full_name = resolve_repo_identity(
            None,
            default_owner=github_owner or self.default_owner,
            product_id=product_id,
        )
        desc = description or f"Managed service repository for {product_id} (StackVend)"

        client = self.get_client()
        repo = None

        # 1. Check if repo already exists
        if client:
            try:
                repo = client.get_repo(full_name)
                logger.info(f"GitHub repository already exists: {repo.html_url}")
                return RepositoryMetadata(
                    provider="GITHUB",
                    repo_name=repo_name,
                    full_name=repo.full_name,
                    html_url=repo.html_url,
                    clone_url_http=repo.clone_url,
                    clone_url_ssh=getattr(repo, "ssh_url", None),
                    default_branch=repo.default_branch or initial_branch,
                    is_reused=True,
                    ui_icon="🐙",
                )
            except Exception:
                pass

        # 2. Organization repository creation. GITHUB-ORG-ONLY: an owner that is not an organization raises
        # GitHubOwnerNotOrganizationError (no personal-account fallback: an App installation token cannot create
        # repositories there).
        if client and repo is None:
            org = require_github_organization(client, owner)
            try:
                repo = org.create_repo(
                    name=repo_name,
                    description=desc,
                    auto_init=True,
                    private=True,
                )
            except Exception as create_err:
                # GITHUB-REPO-CREATE-FAIL-LOUD: a refused create (403 App not installed / no Administration
                # permission, 422 name taken, any other error) is a typed failure, never invented metadata.
                raise GitHubRepositoryCreateError.from_exception(owner, full_name, create_err) from create_err

        if repo:
            try:
                repo.edit(delete_branch_on_merge=True)
            except Exception:
                pass
            logger.info(f"Successfully vended GitHub repository: {repo.html_url}")
            return RepositoryMetadata(
                provider="GITHUB",
                repo_name=repo_name,
                full_name=repo.full_name,
                html_url=repo.html_url,
                clone_url_http=repo.clone_url,
                clone_url_ssh=getattr(repo, "ssh_url", None),
                default_branch=apply_initial_branch(repo, initial_branch),   # FD-4CI-b-R1
                is_reused=False,
                ui_icon="🐙",
            )

        # GITHUB-REPO-CREATE-FAIL-LOUD: no GitHub client (credentials missing or unusable) or no repository object:
        # a typed failure, never invented metadata (this used to return made-up URLs as a vended repository).
        raise GitHubRepositoryCreateError(
            owner, full_name, None,
            "no GitHub client: the GitHub credentials are missing or unusable" if not client
            else "GitHub returned no repository")

    def get_repository_metadata(self, repo_identifier: str) -> RepositoryMetadata:
        """Resolves metadata for a GitHub repository."""
        owner, repo_name, full_name = resolve_repo_identity(repo_identifier, default_owner=self.default_owner)
        return RepositoryMetadata(
            provider="GITHUB",
            repo_name=repo_name,
            full_name=full_name,
            html_url=f"https://github.com/{full_name}",
            clone_url_http=f"https://github.com/{full_name}.git",
            clone_url_ssh=f"git@github.com:{full_name}.git",
            default_branch="main",
            ui_icon="🐙",
        )

    # --------------------------------------------------------------------------
    # 2. Branch & Reference Management
    # --------------------------------------------------------------------------
    @github_retry_with_backoff(max_retries=3, initial_wait=2.0)
    def create_or_verify_branch(
        self,
        repo_identifier: str,
        branch_name: str,
        source_branch: str = "main",
    ) -> str:
        """Verifies or creates a branch from source_branch using resilience manager."""
        owner, repo_name, full_name = resolve_repo_identity(repo_identifier, default_owner=self.default_owner)
        token = self.get_token()
        return resilience_create_branch(
            repo_full_name=full_name,
            branch_name=branch_name,
            source_branch=source_branch,
            token=token,
            project_id=self.project_id,
        )

    def get_authenticated_clone_url(
        self,
        repo_identifier: str,
        branch: str = "main",
    ) -> str:
        """Generates an authenticated HTTPS clone URL for runners (e.g. apps/qa-runner)."""
        _, _, full_name = resolve_repo_identity(repo_identifier, default_owner=self.default_owner)
        token = self.get_token()
        if token:
            return f"https://x-access-token:{token}@github.com/{full_name}.git"
        return f"https://github.com/{full_name}.git"

    # --------------------------------------------------------------------------
    # 3. Code Ingestion & Streaming
    # --------------------------------------------------------------------------
    @github_retry_with_backoff(max_retries=3, initial_wait=2.0)
    def fetch_file_content(
        self,
        repo_identifier: str,
        file_path: str,
        branch: str = "main",
    ) -> str:
        """Fetches a single file's UTF-8 text content from GitHub."""
        repo = self._get_repo(repo_identifier)
        contents = repo.get_contents(file_path, ref=branch)
        if isinstance(contents, list):
            raise ValueError(f"Target path '{file_path}' is a directory, not a file.")
        return contents.decoded_content.decode("utf-8")

    @github_retry_with_backoff(max_retries=3, initial_wait=2.0)
    def fetch_file_tree(
        self,
        repo_identifier: str,
        branch: str = "main",
        max_files: int = 2500,
        require_complete: bool = False,
    ) -> Dict[str, str]:
        """
        Fetches existing source files from the branch to provide incremental context
        for the Developer Agent (replaces handler.py fetch_existing_repo_files).

        Lane 10 RT F1: `self.last_tree_status` records whether the returned dict is the whole tree
        ({"complete", "truncated", "error"}): truncated at `max_files` or by the API, or failed. The return value
        is unchanged for every caller; only callers that need completeness read the status.

        FD-4D: when the tree has more than `max_files` blobs, the kept ones are chosen by `_tree_priority_key`
        (`infra/` and root files first); the returned dict keeps the API's path order, so a complete tree is the
        same dict in the same order as before. `require_complete=True` raises IncompleteRepoTreeError (carrying
        `last_tree_status`) instead of returning a truncated or errored tree, and makes no blob calls once the
        tree is known to be truncated.

        FD-4DC: the tree listing still decides which files exist, the cap, the order and the status. The contents
        come from one tarball read (`_archive_blobs`) where a file's git blob SHA matches the listing; every other
        kept file is read with its blob call, exactly as before. The archive can only save calls: it never adds,
        drops or changes a file.
        """
        repo = self._get_repo(repo_identifier)
        files: Dict[str, str] = {}
        self.last_tree_status = {"complete": False, "truncated": False, "error": None}
        try:
            tree = repo.get_git_tree(branch, recursive=True)
            wanted = [item for item in tree.tree
                      if item.type == "blob" and not item.path.startswith(".git")
                      # Exclude non-text binary files
                      and not item.path.endswith((".png", ".jpg", ".jpeg", ".ico", ".tar.gz", ".zip", ".pyc"))]
            truncated = len(wanted) > max_files or getattr(tree, "truncated", False) is True
            if truncated and require_complete:
                wanted = []
            keep = {item.path for item in sorted(wanted, key=lambda i: _tree_priority_key(i.path))[:max_files]}
            from_archive = self._archive_blobs(repo, branch, {i.path: i.sha for i in wanted if i.path in keep})
            blob_calls = 0
            for item in wanted:
                if item.path not in keep:
                    continue
                raw = from_archive.get(item.path)
                if raw is None:
                    blob = repo.get_git_blob(item.sha)
                    blob_calls += 1
                    raw = base64.b64decode(blob.content)
                files[item.path] = raw.decode("utf-8", errors="ignore")
            self.last_tree_status = {"complete": not truncated, "truncated": truncated, "error": None}
            logger.info(f"Fetched {len(files)} existing files from GitHub repo '{repo.full_name}' ({branch}): "
                        f"{len(files) - blob_calls} from the archive, {blob_calls} blob call(s).")
        except Exception as e:
            self.last_tree_status = {"complete": False, "truncated": False, "error": f"{type(e).__name__}: {e}"[:300]}
            logger.debug(f"Could not fetch existing files for '{repo.full_name}' ({branch}): {e}")
        if require_complete and self.last_tree_status["complete"] is not True:
            raise IncompleteRepoTreeError(repo.full_name, branch, self.last_tree_status)
        return files

    def _archive_blobs(self, repo: Any, branch: str, wanted: Dict[str, str]) -> Dict[str, bytes]:
        """FD-4DC: {path: bytes} for the `wanted` paths ({path: blob sha}) proven by the branch tarball; {} when the
        archive cannot be used (too few files, no httpx, no archive link, a download error, a size limit, a bad
        archive).

        The link comes from the same authenticated PyGithub repository object as the tree (`get_archive_link`,
        the App / token path); the codeload URL it returns is short-lived and is never logged. Never raises: the
        caller reads every path missing here with its blob call."""
        if len(wanted) < ARCHIVE_MIN_BLOBS or httpx is None:
            return {}
        get_link = getattr(repo, "get_archive_link", None)
        if not callable(get_link):
            return {}
        name = getattr(repo, "full_name", "")
        try:
            url = get_link("tarball", branch)
            if not isinstance(url, str) or not url.startswith("https://"):
                return {}
            buf = io.BytesIO()   # RT F5: one in-memory copy of the compressed archive
            size = 0
            deadline = time.monotonic() + ARCHIVE_TIMEOUT_SECONDS   # RT F4: the whole download, not per read
            with httpx.Client(timeout=ARCHIVE_TIMEOUT_SECONDS, follow_redirects=True) as client:
                with client.stream("GET", url) as res:
                    res.raise_for_status()
                    for chunk in res.iter_bytes():
                        size += len(chunk)
                        if size > ARCHIVE_MAX_COMPRESSED_BYTES:
                            logger.info(f"Archive of '{name}' ({branch}) is larger than "
                                        f"{ARCHIVE_MAX_COMPRESSED_BYTES} bytes; reading blobs one by one.")
                            return {}
                        if time.monotonic() > deadline:
                            logger.info(f"Archive of '{name}' ({branch}) is slower than "
                                        f"{ARCHIVE_TIMEOUT_SECONDS:.0f} s; reading blobs one by one.")
                            return {}
                        buf.write(chunk)
            buf.seek(0)
            return verified_blobs_from_tarball(buf, wanted)
        except Exception as e:  # noqa: BLE001 - the blob calls stay the authority; the archive only saves calls
            logger.info(f"Archive read of '{name}' ({branch}) not used ({type(e).__name__}); "
                        f"reading blobs one by one.")
            return {}

    @github_retry_with_backoff(max_retries=3, initial_wait=2.0)
    def export_archive_stream(
        self,
        repo_identifier: str,
        branch: str = "main",
    ) -> BinaryIO:
        """
        Streams a .tar.gz archive directly from GitHub API.
        Prevents container OOM when staging source code for Cloud Build / Cloud Run.
        """
        owner, repo_name, full_name = resolve_repo_identity(repo_identifier, default_owner=self.default_owner)
        token = self.get_token()
        headers = {
            "Accept": "application/vnd.github.v3+json",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"

        archive_url = f"https://api.github.com/repos/{owner}/{repo_name}/tarball/{branch}"

        if httpx is not None:
            with httpx.Client(timeout=30.0, follow_redirects=True) as client:
                res = client.get(archive_url, headers=headers)
                res.raise_for_status()
                return io.BytesIO(res.content)
        else:
            import urllib.request
            req = urllib.request.Request(archive_url, headers=headers)
            with urllib.request.urlopen(req) as resp:
                return io.BytesIO(resp.read())

    # --------------------------------------------------------------------------
    # 4. Atomic Commits & Pull Requests
    # --------------------------------------------------------------------------
    def _commit_files_via_git_cli(
        self,
        repo_identifier: str,
        branch: str,
        files: Dict[str, str],
        commit_message: str,
        author_name: str = "StackVend Developer Agent",
        author_email: str = DEFAULT_AGENT_AUTHOR_EMAIL,
        files_to_delete: Optional[List[str]] = None,
    ) -> str:
        """
        Commits files using native Git CLI in an ephemeral RAM sandbox.
        RT14-10: the Basic auth header reaches git through its environment configuration (git_auth_env), only for the
        commands that talk to GitHub; it is never on a command line, stored in .git/config or in an error message.
        """
        _, _, full_name = resolve_repo_identity(repo_identifier, default_owner=self.default_owner)
        clean_url = f"https://github.com/{full_name}.git"
        token = self.get_token()
        if not token:
            raise RuntimeError(f"Cannot commit via Git CLI: No GitHub authentication token available for {repo_identifier}")

        env = os.environ.copy()
        env["GIT_TERMINAL_PROMPT"] = "0"
        auth_env = git_auth_env(token, env)        # clone / pull / push only
        secrets = git_secret_values(token)

        with tempfile.TemporaryDirectory() as tmp_dir:
            # 1. Attempt shallow clone of target branch if it exists, else main
            cloned = False
            try:
                res = run_git(["clone", "--depth", "1", "--no-tags", "--single-branch", "-b", branch, clean_url,
                               tmp_dir], env=auth_env, timeout=45, secrets=secrets)
                if res.returncode == 0:
                    cloned = True
                    logger.info(f"Git CLI: cloned existing branch '{branch}' for {full_name}")
            except Exception as e:
                logger.debug(f"Direct branch clone notice ({e}); will clone main.")

            if not cloned:
                res_main = run_git(["clone", "--depth", "1", "--no-tags", "--single-branch", "-b", "main", clean_url,
                                    tmp_dir], env=auth_env, timeout=45, secrets=secrets)
                if res_main.returncode != 0:
                    raise RuntimeError(f"Git CLI clone failed for {full_name}: "
                                       f"{without_git_secrets(res_main.stderr, secrets)}")

                run_git(["checkout", "-B", branch], cwd=tmp_dir, env=env, timeout=15, check=True, secrets=secrets)

            # 2. Configure ephemeral commit identity
            run_git(["config", "user.name", author_name], cwd=tmp_dir, env=env, timeout=15, check=True)
            run_git(["config", "user.email", author_email], cwd=tmp_dir, env=env, timeout=15, check=True)

            # 3. Path traversal security validation and file writing.
            # FD-4G: safe_join rejects escapes, the clone root itself and any .git component (H1).
            for path, content in (files or {}).items():
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

            # Handle files_to_delete
            for del_path in (files_to_delete or []):
                clean_del = del_path.lstrip("/").replace("\\", "/")
                target_del = safe_join(tmp_dir, clean_del, reserved=GIT_RESERVED)
                if os.path.isfile(target_del):
                    os.remove(target_del)
                elif os.path.isdir(target_del):
                    shutil.rmtree(target_del)

            # 4. Stage changes
            run_git(["add", "-A"], cwd=tmp_dir, env=env, timeout=30, check=True)

            # 5. Check if working tree is clean
            status_res = run_git(["status", "--porcelain"], cwd=tmp_dir, env=env, timeout=15, check=True)
            if not status_res.stdout.strip():
                head_sha = run_git(["rev-parse", "HEAD"], cwd=tmp_dir, env=env, timeout=15, check=True).stdout.strip()
                logger.info(f"Git CLI: working tree clean (no new changes), returning existing HEAD {head_sha[:7]}")
                return head_sha

            # 6. Commit
            run_git(["commit", "-m", commit_message], cwd=tmp_dir, env=env, timeout=30, check=True)

            # 7. Push with push/rebase retry
            push_args = ["push", "-u", "origin", branch]
            push_res = run_git(push_args, cwd=tmp_dir, env=auth_env, timeout=60, secrets=secrets)
            if push_res.returncode != 0:
                logger.warning(f"Git CLI push conflict on '{branch}', attempting rebase on remote...")
                run_git(["pull", "--rebase", "origin", branch], cwd=tmp_dir, env=auth_env, timeout=30,
                        secrets=secrets)
                push_res = run_git(push_args, cwd=tmp_dir, env=auth_env, timeout=60, secrets=secrets)
                if push_res.returncode != 0:
                    raise RuntimeError(f"Git CLI push failed for {full_name} ({branch}): "
                                       f"{without_git_secrets(push_res.stderr, secrets)}")

            commit_sha = run_git(["rev-parse", "HEAD"], cwd=tmp_dir, env=env, timeout=15, check=True).stdout.strip()
            logger.info(f"Git CLI: Successfully committed and pushed {len(files or {})} files to '{branch}' on '{full_name}' (SHA: {commit_sha[:7]})")
            return commit_sha

    def _commit_files_via_dulwich(
        self,
        repo_identifier: str,
        branch: str,
        files: Dict[str, str],
        commit_message: str,
        author_name: str = "StackVend Developer Agent",
        author_email: str = DEFAULT_AGENT_AUTHOR_EMAIL,
        files_to_delete: Optional[List[str]] = None,
    ) -> str:
        """
        Commits files using in-process pure-Python Dulwich engine.
        Operates directly in an ephemeral RAM sandbox with zero OS binary dependency.
        Guarantees 100% immunity to GitRPC::BadObjectState and strict token redaction.
        """
        if not DULWICH_AVAILABLE:
            raise RuntimeError("Dulwich is not installed in the Python runtime environment.")

        _, _, full_name = resolve_repo_identity(repo_identifier, default_owner=self.default_owner)
        token = self.get_token()
        if not token:
            raise RuntimeError(f"Cannot commit via Dulwich: No GitHub authentication token available for {repo_identifier}")

        # Construct Smart HTTP authenticated clone/push URL
        remote_url = f"https://x-access-token:{token}@github.com/{full_name}.git"

        def _sanitize(err_str: str) -> str:
            clean = re.sub(r":gh[a-zA-Z0-9_]+@", ":[REDACTED]@", str(err_str))
            clean = re.sub(r"x-access-token:[^@]+@", "x-access-token:[REDACTED]@", clean)
            return clean

        with tempfile.TemporaryDirectory() as tmp_dir:
            # 1. Attempt shallow clone of target branch if it exists, else default branch
            cloned = False
            local_repo = None
            clone_err_stream = io.BytesIO()
            clone_out_stream = io.BytesIO()

            try:
                local_repo = porcelain.clone(
                    source=remote_url,
                    target=tmp_dir,
                    branch=branch.encode("utf-8"),
                    depth=1,
                    errstream=clone_err_stream,
                )
                cloned = True
                logger.info(f"Dulwich: cloned existing branch '{branch}' for {full_name}")
            except Exception as clone_err:
                logger.debug(f"Dulwich direct branch clone notice ({_sanitize(str(clone_err))}); attempting clone from default branch.")

            if not cloned:
                # Clean up any partial clone directory artifacts from attempt 1
                for item in os.listdir(tmp_dir):
                    item_path = os.path.join(tmp_dir, item)
                    if os.path.isdir(item_path):
                        shutil.rmtree(item_path, ignore_errors=True)
                    else:
                        try:
                            os.remove(item_path)
                        except OSError:
                            pass
                try:
                    local_repo = porcelain.clone(
                        source=remote_url,
                        target=tmp_dir,
                        depth=1,
                        errstream=clone_err_stream,
                    )
                    try:
                        porcelain.branch_create(local_repo, branch.encode("utf-8"))
                    except Exception:
                        pass
                    try:
                        local_repo.refs.set_symbolic_ref(b"HEAD", f"refs/heads/{branch}".encode("utf-8"))
                    except Exception:
                        pass
                except Exception as main_clone_err:
                    raise RuntimeError(f"Dulwich clone failed for {full_name}: {_sanitize(str(main_clone_err))}")

            # 2. Path traversal security validation and safe file writing.
            # FD-4G: safe_join rejects escapes, the clone root itself and any .git component (H1).
            staged_paths = []
            for path, content in (files or {}).items():
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
                staged_paths.append(clean_path)

            # Handle files_to_delete (DULWICH-DELETE-LOUD). The clone's index is the source of truth for what is
            # tracked: a requested path is a tracked file (deleted as is) or a directory (expanded to the tracked
            # files under it). A path with nothing tracked at or under it is already absent: not an error, the
            # same contract as the git CLI path above and the git server's /commits-with-deletions.
            tracked = sorted(p.decode("utf-8") for p in local_repo.open_index()) if files_to_delete else []
            written = set(staged_paths)
            del_paths: List[str] = []
            for del_path in (files_to_delete or []):
                clean_del = del_path.lstrip("/").replace("\\", "/")
                safe_join(tmp_dir, clean_del, reserved=GIT_RESERVED)   # canonical relpath (no trailing "/")
                under = clean_del + "/"
                entries = [clean_del] if clean_del in tracked else [p for p in tracked if p.startswith(under)]
                for entry in entries:
                    if entry not in del_paths:
                        del_paths.append(entry)
            both = sorted(written.intersection(del_paths))
            if both:
                raise VCSDeletionNotStaged(full_name, branch, both,
                                           "paths are both written and deleted in the same commit")
            for entry in del_paths:
                target_del = safe_join(tmp_dir, entry, reserved=GIT_RESERVED)
                if os.path.isfile(target_del) or os.path.islink(target_del):
                    os.remove(target_del)

            # 3. Stage changes. Deletions leave the index exactly (cached=True: the checked-out files are already
            # removed above); a failure is never swallowed.
            try:
                if staged_paths:
                    porcelain.add(local_repo, paths=staged_paths)
                if del_paths:
                    porcelain.remove(local_repo, paths=del_paths, cached=True)
            except Exception as add_err:
                raise RuntimeError(f"Dulwich staging failed: {_sanitize(str(add_err))}") from add_err

            # 4. Check if working tree has changes
            status = porcelain.status(local_repo)
            # DULWICH-DELETE-LOUD: every requested deletion must be a staged delete before anything is committed.
            staged_deletes = {p.decode("utf-8") if isinstance(p, bytes) else str(p) for p in status.staged["delete"]}
            not_staged = [p for p in del_paths if p not in staged_deletes]
            if not_staged:
                raise VCSDeletionNotStaged(full_name, branch, not_staged, "the deletions are not staged")
            has_changes = bool(status.staged["add"] or status.staged["modify"] or status.staged["delete"])
            if not has_changes:
                head_sha = local_repo.head().decode("ascii")
                logger.info(f"Dulwich: working tree clean (no new changes), returning existing HEAD {head_sha[:7]}")
                return head_sha

            # 5. Commit with explicit identity as UTF-8 encoded bytes
            author_bytes = f"{author_name} <{author_email}>".encode("utf-8")
            commit_sha_bytes = porcelain.commit(
                local_repo,
                message=commit_message.encode("utf-8"),
                author=author_bytes,
                committer=author_bytes,
            )
            commit_sha = commit_sha_bytes.decode("ascii") if isinstance(commit_sha_bytes, bytes) else str(commit_sha_bytes)

            # 6. Push to remote with refspec
            refspec = f"refs/heads/{branch}:refs/heads/{branch}".encode("utf-8")
            push_out_stream = io.BytesIO()
            push_err_stream = io.BytesIO()
            try:
                porcelain.push(
                    local_repo,
                    remote_location=remote_url,
                    refspecs=[refspec],
                    errstream=push_err_stream,
                )
            except Exception as push_err:
                raise RuntimeError(f"Dulwich push failed for {full_name} ({branch}): {_sanitize(str(push_err))}")

            logger.info(f"Dulwich: Successfully committed and pushed {len(files or {})} files to '{branch}' on '{full_name}' (SHA: {commit_sha[:7]})")
            return commit_sha

    @github_retry_with_backoff(max_retries=3, initial_wait=2.0)
    def commit_files(
        self,
        repo_identifier: str,
        branch: str,
        files: Dict[str, str],
        commit_message: str,
        author_name: str = "StackVend Developer Agent",
        author_email: str = DEFAULT_AGENT_AUTHOR_EMAIL,
        files_to_delete: Optional[List[str]] = None,
    ) -> str:
        """Creates an atomic Git commit with the provided files and returns commit SHA."""
        if not files and not files_to_delete:
            return ""

        # Priority 1: Native Git CLI (fastest when binary exists in environment)
        if shutil.which("git"):
            try:
                return self._commit_files_via_git_cli(
                    repo_identifier=repo_identifier,
                    branch=branch,
                    files=files,
                    commit_message=commit_message,
                    author_name=author_name,
                    author_email=author_email,
                    files_to_delete=files_to_delete,
                )
            except UnsafePathError:
                raise  # FD-4G: an unsafe key fails closed; never retried through another engine.
            except Exception as git_err:
                logger.warning(f"Native Git CLI commit attempt noticed ({git_err}); falling back to in-process Dulwich engine.")

        # Priority 2: Pure-Python Dulwich Engine (in-process, 100% binary-free, serverless safe)
        if DULWICH_AVAILABLE:
            try:
                return self._commit_files_via_dulwich(
                    repo_identifier=repo_identifier,
                    branch=branch,
                    files=files,
                    commit_message=commit_message,
                    author_name=author_name,
                    author_email=author_email,
                    files_to_delete=files_to_delete,
                )
            except (UnsafePathError, VCSDeletionNotStaged):
                raise  # typed refusals keep their class (nothing was committed)
            except Exception as dul_err:
                logger.error(f"Dulwich Git commit failed: {dul_err}")
                raise RuntimeError(f"Serverless Git commit failed: {dul_err}") from dul_err

        # Fail-fast: Never fall back to broken REST create_git_tree API
        raise RuntimeError("No Git engine available: neither git binary nor dulwich package is installed in runtime.")


    @github_retry_with_backoff(max_retries=3, initial_wait=2.0)
    def get_diff(
        self,
        repo_identifier: str,
        base_branch: str,
        target_branch: str,
    ) -> Dict[str, Any]:
        """Generates a comparison diff between base and target branches."""
        repo = self._get_repo(repo_identifier)
        comparison = repo.compare(base_branch, target_branch)
        files_changed = []
        for f in comparison.files:
            files_changed.append({
                "filename": f.filename,
                "status": f.status,
                "additions": f.additions,
                "deletions": f.deletions,
                "patch": f.patch or "",
            })
        return {
            "status": "SUCCESS",
            "base": base_branch,
            "head": target_branch,
            "total_commits": comparison.total_commits,
            "files_changed_count": len(files_changed),
            "files": files_changed,
        }

    @github_retry_with_backoff(max_retries=3, initial_wait=2.0)
    def create_pull_request(
        self,
        repo_identifier: str,
        title: str,
        body: str,
        head_branch: str,
        base_branch: str = "main",
        trace_id: Optional[str] = None,
        product_id: Optional[str] = None,
        labels: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Opens a Pull Request with Castor metadata and governance labels."""
        repo = self._get_repo(repo_identifier)

        meta_comment = (
            f"<!-- castor-metadata: {{\"managed_by\": \"project-castor\", "
            f"\"product_id\": \"{product_id or ''}\", \"trace_id\": \"{trace_id or ''}\"}} -->\n"
            f"<!-- managed-by: project-castor -->"
        )
        if "managed-by: project-castor" not in (body or "") and "castor-metadata" not in (body or ""):
            body = f"{(body or '').rstrip()}\n\n{meta_comment}\n"

        pr = repo.create_pull(
            title=title,
            body=body,
            head=head_branch,
            base=base_branch,
        )
        logger.info(f"Opened PR #{pr.number} in '{repo.full_name}': {pr.html_url}")

        # Attach governance labels
        pr_labels = list(labels or [])
        if "managed-by:project-castor" not in pr_labels:
            pr_labels.append("managed-by:project-castor")
        try:
            pr.add_to_labels(*pr_labels)
        except Exception as l_err:
            logger.debug(f"Could not attach labels {pr_labels} to PR #{pr.number}: {l_err}")

        # FD-4P: the identity GitHub reports for the PR it just created (read from the API response, never parsed),
        # so the caller can write the PR ledger entry and refuse a PR whose head is not this repository.
        head, base = getattr(pr, "head", None), getattr(pr, "base", None)
        head_repo, base_repo = getattr(head, "repo", None), getattr(base, "repo", None)
        return {
            "status": "PR_CREATED",
            "pr_number": pr.number,
            "title": pr.title,
            "pull_request_url": pr.html_url,
            "diff_url": pr.diff_url,
            "head": head_branch,
            "base": base_branch,
            "head_ref": getattr(head, "ref", None),
            "head_sha": getattr(head, "sha", None),
            "head_repo_full_name": getattr(head_repo, "full_name", None),
            "head_repo_id": getattr(head_repo, "id", None),
            "base_ref": getattr(base, "ref", None),
            "base_repo_full_name": getattr(base_repo, "full_name", None),
            "base_repo_id": getattr(base_repo, "id", None),
        }

    # --------------------------------------------------------------------------
    # FD-4P / FD-4BB: ledger-bound PR identity (exact equality only)
    # --------------------------------------------------------------------------
    @staticmethod
    def _int_id(value: Any) -> Optional[int]:
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    def actor_identity(self) -> Optional[Tuple[int, str]]:
        """FD-4BB RT M1: (numeric user id, "Bot" | "User") of the identity StackVend's token acts as, i.e. the
        creator of every PR StackVend opens. Mode mirrors GitHubTokenManager._mint_token: App credentials
        (app_id + installation_id + private key) => the App's "<slug>[bot]" user; otherwise the PAT's own user.
        No new env. Returns None when it cannot be resolved (callers then refuse auto-merge: HITL only)."""
        creds: Dict[str, Any] = {}
        if self._token_manager is not None:
            try:
                creds = self._token_manager._get_credentials() or {}
            except Exception as c_err:  # noqa: BLE001
                logger.warning(f"Provenance: GitHub credentials unreadable: {c_err}")
                return None
        app_id, inst_id, private_key = creds.get("app_id"), creds.get("installation_id"), creds.get("private_key")
        mode = "APP" if (app_id and inst_id and private_key) else "PAT"
        key = (self.project_id, mode, str(app_id or ""))
        if key in _ACTOR_CACHE:
            return _ACTOR_CACHE[key]
        try:
            if mode == "APP":
                from github import Auth
                slug = Github(auth=Auth.AppAuth(app_id, private_key)).get_app().slug
                user, kind = self.get_client().get_user(f"{slug}[bot]"), "Bot"
            else:
                user, kind = self.get_client().get_user(), "User"
            uid = self._int_id(getattr(user, "id", None))
        except Exception as a_err:  # noqa: BLE001 - unresolvable => HITL only
            logger.warning(f"Provenance: could not resolve the platform GitHub identity ({mode}): {a_err}")
            return None
        if uid is None:
            return None
        _ACTOR_CACHE[key] = (uid, kind)
        return _ACTOR_CACHE[key]

    @staticmethod
    def _check_expected(expected: Any) -> PRIdentity:
        """The ledger identity itself must be complete before any GitHub call (fail closed, nothing guessed)."""
        if not isinstance(expected, PRIdentity):
            raise TypeError("expected must be a PRIdentity from the PR ledger")
        if expected.provider != "GITHUB":
            raise PRIdentityMismatch("provider", "GITHUB", expected.provider)
        if GitHubProvider._int_id(expected.pr_number) is None or expected.pr_number <= 0:
            raise PRIdentityMismatch("pr_number", "positive integer", expected.pr_number)
        if GitHubProvider._int_id(expected.repo_id) is None:
            raise PRIdentityMismatch("repo_id", "integer repository id", expected.repo_id)
        for field in ("repo_full_name", "branch", "base_branch", "head_sha"):
            value = getattr(expected, field)
            if not isinstance(value, str) or not value or value != value.strip():
                raise PRIdentityMismatch(field, "non-empty string", value)
        return expected

    def _verify_identity(self, repo: Any, pr: Any, expected: PRIdentity, *, require_open: bool,
                         actor: Optional[Tuple[int, str]] = None) -> None:
        """Raises PRIdentityMismatch on the first field where the live PR differs from the ledger identity.
        Checks: repository (numeric id + name), PR number, PR base repo == repo, PR head repo == repo (no forks, no
        deleted forks), head ref, base ref, head SHA, (when require_open) open and not merged, and (RT M1, when the
        platform identity is known) the PR was opened by that identity (App mode: a Bot user)."""
        repo_id = self._int_id(getattr(repo, "id", None))
        if repo_id is None or repo_id != expected.repo_id:
            raise PRIdentityMismatch("repo_id", expected.repo_id, getattr(repo, "id", None))
        repo_name = getattr(repo, "full_name", None)
        if not isinstance(repo_name, str) or repo_name.casefold() != expected.repo_full_name.casefold():
            raise PRIdentityMismatch("repo_full_name", expected.repo_full_name, repo_name)
        if self._int_id(getattr(pr, "number", None)) != expected.pr_number:
            raise PRIdentityMismatch("pr_number", expected.pr_number, getattr(pr, "number", None))
        base, head = getattr(pr, "base", None), getattr(pr, "head", None)
        base_repo_id = self._int_id(getattr(getattr(base, "repo", None), "id", None))
        if base_repo_id != repo_id:
            raise PRIdentityMismatch("base_repo_id", repo_id, base_repo_id)
        head_repo = getattr(head, "repo", None)
        head_repo_id = self._int_id(getattr(head_repo, "id", None)) if head_repo is not None else None
        if head_repo_id != repo_id:  # fork PR, or a fork that was deleted (head.repo is None)
            raise PRIdentityMismatch("head_repo_id", repo_id, head_repo_id)
        if getattr(head, "ref", None) != expected.branch:
            raise PRIdentityMismatch("head_ref", expected.branch, getattr(head, "ref", None))
        if getattr(base, "ref", None) != expected.base_branch:
            raise PRIdentityMismatch("base_ref", expected.base_branch, getattr(base, "ref", None))
        if getattr(head, "sha", None) != expected.head_sha:
            raise PRIdentityMismatch("head_sha", expected.head_sha, getattr(head, "sha", None))
        if actor is not None:
            pr_user = getattr(pr, "user", None)
            if self._int_id(getattr(pr_user, "id", None)) != actor[0]:
                raise PRIdentityMismatch("pr_user_id", actor[0], getattr(pr_user, "id", None))
            if actor[1] == "Bot" and getattr(pr_user, "type", None) != "Bot":
                raise PRIdentityMismatch("pr_user_type", "Bot", getattr(pr_user, "type", None))
        if require_open:
            if getattr(pr, "merged", None) is not False:
                raise PRIdentityMismatch("merged", False, getattr(pr, "merged", None))
            if getattr(pr, "state", None) != "open":
                raise PRIdentityMismatch("state", "open", getattr(pr, "state", None))

    def _delete_branch_if_unchanged(self, repo: Any, branch: str, head_sha: str) -> bool:
        """Deletes heads/<branch> (the LEDGER name, never pr.head.ref) only while it still points at head_sha."""
        try:
            ref = repo.get_git_ref(f"heads/{branch}")
            ref_sha = getattr(getattr(ref, "object", None), "sha", None)
            if ref_sha != head_sha:
                logger.warning(f"Branch '{branch}' moved ({ref_sha} != {head_sha}); not deleted")
                return False
            ref.delete()
            logger.info(f"Deleted branch '{branch}' at {head_sha[:7]}")
            return True
        except Exception as del_err:  # noqa: BLE001 - a missing ref (delete_branch_on_merge) is fine
            logger.info(f"Branch '{branch}' not deleted: {del_err}")
            return False

    def reconcile_automated_pull_requests(
        self,
        repo_identifier: str,
        *,
        superseded: Sequence[PRIdentity],
        comment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        FD-4P (owner row 23: reconcile REWRITTEN on the ledger). Closes exactly the superseded StackVend PRs named
        by the PR ledger. Each PR is closed only if it still matches its ledger identity (same repository, no fork,
        same head ref, base ref and head SHA, still open); a PR someone pushed to is DIVERGED and left untouched.
        Nothing is listed and nothing is matched by branch-name prefix, label or body text.
        """
        results: List[Dict[str, Any]] = []
        repo = None
        actor = self.actor_identity() if superseded else None  # RT M1: known => only PRs our identity opened
        for ident in superseded or []:
            row: Dict[str, Any] = {"branch": getattr(ident, "branch", None), "pr_number": getattr(ident, "pr_number", None)}
            try:
                self._check_expected(ident)
                if repo is None:
                    repo = self._get_repo(repo_identifier)
                pr = repo.get_pull(ident.pr_number)
                self._verify_identity(repo, pr, ident, require_open=True, actor=actor)
            except PRIdentityMismatch as mm:
                results.append({**row, "outcome": "DIVERGED", "field": mm.field, "reason": str(mm)})
                continue
            except Exception as err:  # noqa: BLE001 - one PR's failure never stops the others
                results.append({**row, "outcome": "ERROR", "reason": f"{type(err).__name__}: {err}"})
                continue
            try:
                text = comment or (
                    "## StackVend: automated PR superseded\n\n"
                    f"This automated delivery PR on branch `{ident.branch}` was superseded by a newer StackVend run "
                    "and is closed automatically.")
                pr.create_issue_comment(text)
                pr.edit(state="closed")
                deleted = self._delete_branch_if_unchanged(repo, ident.branch, ident.head_sha)
                results.append({**row, "outcome": "SUPERSEDED", "branch_deleted": deleted})
                logger.info(f"Closed superseded StackVend PR #{ident.pr_number} on {ident.branch}")
            except Exception as close_err:  # noqa: BLE001
                results.append({**row, "outcome": "ERROR", "reason": f"{type(close_err).__name__}: {close_err}"})
        return {"status": "RECONCILED", "results": results}

    @github_retry_with_backoff(max_retries=3, initial_wait=2.0)
    def merge_pull_request(
        self,
        repo_identifier: str,
        *,
        expected: PRIdentity,
        commit_message: Optional[str] = None,
        merge_method: str = "squash",
        require_provenance: bool = True,
    ) -> Dict[str, Any]:
        """
        FD-4BB: merges exactly the ledger PR. The live PR must match `expected` on every field (repository id and
        name, PR number, base repo, head repo == base repo, head ref, base ref, head SHA). GitHub merges at
        `sha=expected.head_sha`, so a push between this check and the merge is refused by GitHub (409). There is no
        PR-number guess, no branch-name lookup and no direct branch merge: a lookup error propagates.
        An already-merged PR with the same identity returns MERGED without a second merge (idempotent retry).
        RT M1: the PR must have been opened by the platform's own GitHub identity (actor_identity). If that identity
        cannot be resolved, `require_provenance=True` (default; release auto-merge) refuses before any GitHub call;
        the Control Center's human approval passes False and is then bound by the other checks only.
        """
        self._check_expected(expected)
        actor = self.actor_identity()
        if actor is None and require_provenance:
            raise PRIdentityMismatch("pr_user_id", "resolvable platform GitHub identity", None)
        repo = self._get_repo(repo_identifier)
        pr = repo.get_pull(expected.pr_number)
        if getattr(pr, "merged", None) is True:
            self._verify_identity(repo, pr, expected, require_open=False, actor=actor)
            return {"status": "MERGED", "pr_number": expected.pr_number, "merged": True, "already_merged": True,
                    "sha": getattr(pr, "merge_commit_sha", None), "message": "PR was already merged"}
        self._verify_identity(repo, pr, expected, require_open=True, actor=actor)
        msg = commit_message or f"Merge PR #{expected.pr_number}: {getattr(pr, 'title', '')}"
        try:
            merge_status = pr.merge(commit_message=msg, merge_method=merge_method, sha=expected.head_sha)
        except GithubException as ge:
            if getattr(ge, "status", None) == 409:  # GitHub: "Head branch was modified"
                raise PRIdentityMismatch("head_sha", expected.head_sha, "moved before merge") from ge
            raise
        if getattr(merge_status, "merged", None) is not True:
            raise PRMergeNotCompleted(f"GitHub did not merge PR #{expected.pr_number}: {getattr(merge_status, 'message', '')}")
        self._delete_branch_if_unchanged(repo, expected.branch, expected.head_sha)
        return {
            "status": "MERGED",
            "pr_number": expected.pr_number,
            "merged": True,
            "sha": getattr(merge_status, "sha", None),
            "message": getattr(merge_status, "message", None),
        }

    # --------------------------------------------------------------------------
    # 5. CI/CD Pipeline Contracts & Pre-Commit Validation
    # --------------------------------------------------------------------------
    def get_pipeline_contract(self, service_name: str, product_id: str) -> PipelineConfig:
        """Returns the GitHub Actions workflow template for Developer Agent prompt injection."""
        return PipelineConfig(
            pipeline_type="GITHUB_ACTIONS",
            target_file=f".github/workflows/deploy-{service_name}.yml",
            template_content=(
                f"Dedicated GitHub Actions CI/CD workflow authenticating via Google Cloud Workload Identity "
                f"Federation (WIF) with `id-token: write`, path filtering (`on.push.paths: ['apps/{service_name}/**']`), "
                f"and compiling/deploying to Cloud Run with Google Cloud Buildpacks. Always include `--allow-unauthenticated` "
                f"on `gcloud run deploy`, attach `--service-account \"${{GCP_WORKLOAD_SA}}\"`, and define "
                f"`GCP_WORKLOAD_SA: ${{{{ secrets.GCP_WORKLOAD_SA || secrets.GCP_WORKLOAD_SA_EMAIL || 'sa-{product_id}@<project-id>.iam.gserviceaccount.com' }}}}`. "
                f"CRITICAL: In GitHub Actions, NEVER interpolate `${{{{ env.VARIABLE }}}}` inside the top-level `env:` block."
            ),
        )

    def validate_pipeline_content(self, file_path: str, content: str) -> None:
        """Validates GitHub Actions workflow YAML syntax before commit."""
        if file_path.startswith(".github/workflows/") and file_path.endswith((".yml", ".yaml")):
            validate_github_workflow_yaml(content, filename=file_path)
