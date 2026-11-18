"""
StackVend GitHub MCP Tool Server - Service Engine.

Branches, file reads, multi-file commits, diffs and the pull request lifecycle in ONE repository: the workload's own.

FD-4L / FD27-17 (lane 14 plan §3.4, register row 23 "github MCP kept"): every call takes `product_id`. The repository
is exactly `workloads/{product_id}.github_repo` from the workload ledger (`managed_target_seam.verify_ledger_target`:
never the host project, never a platform workload), its owner must equal `GITHUB_ORG` exactly, and an optional
request `repo_name` must equal it exactly; the repository GitHub returns must carry that same full name. Anything else
is a typed refusal before any GitHub call. Non-idempotent writes are not retried (check before write instead):
`create_branch` refuses an existing branch and records the branch it creates; `create_pull_request` returns the
open PR for the same head instead of opening a duplicate. This server never merges (FD-4P / FD-4BB, owner row 23):
StackVend merges only PRs recorded in its PR ledger (gateway release step, Control Center approval).
"""

import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional

from github import Github, GithubException, InputGitTreeElement

import managed_target_seam as seam

try:
    from shared.github_resilience import (
        get_github_token,
        github_retry_with_backoff,
        GitHubRateLimitExceededError,
    )
except ImportError:
    try:
        from .shared.github_resilience import (
            get_github_token,
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

logger = logging.getLogger("mcp-github-toolserver")
logging.basicConfig(level=logging.INFO)

BRANCH_RECORD_COLLECTION = "github_mcp_branches"
MAX_BRANCH_LENGTH = 200
MAX_PATH_LENGTH = 400
MAX_FILES_PER_COMMIT = 200


class GithubRefused(Exception):
    def __init__(self, code: str, detail: str = "", http_status: int = 422):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail, self.http_status = code, detail, http_status


# --------------------------------------------------------------------------------------------------- typed checks
_BRANCH_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/-")


def is_branch_name(value: Any) -> bool:
    """A conservative git ref name: [A-Za-z0-9._/-], no empty / dot-leading component, no '..', no '.lock' end."""
    if not isinstance(value, str) or not value or len(value) > MAX_BRANCH_LENGTH:
        return False
    if any(ch not in _BRANCH_CHARS for ch in value) or value.startswith("-") or ".." in value:
        return False
    parts = value.split("/")
    return all(p and not p.startswith(".") and not p.endswith(".lock") for p in parts) and not value.endswith(".")


def is_repo_path(value: Any) -> bool:
    """A repository-relative file path: no leading '/', no empty, '.' or '..' segment, no backslash or NUL."""
    if not isinstance(value, str) or not value or len(value) > MAX_PATH_LENGTH:
        return False
    if "\\" in value or "\0" in value or value.startswith("/"):
        return False
    return all(seg not in ("", ".", "..") for seg in value.split("/"))


def split_full_name(value: Any) -> Optional[List[str]]:
    if not isinstance(value, str):
        return None
    parts = value.split("/")
    if len(parts) != 2 or not all(parts) or any(ch.isspace() for ch in value):
        return None
    return parts


def _default_db_factory() -> Any:
    from google.cloud import firestore

    project = os.getenv("PROJECT_ID") or None
    return firestore.Client(project=project) if project else None


def _status_of(e: GithubException) -> int:
    status = getattr(e, "status", None)
    return status if isinstance(status, int) else 502


class GithubService:
    def __init__(self, github_client: Optional[Github] = None, *, db_factory: Optional[Callable[[], Any]] = None,
                 env: Optional[Mapping[str, str]] = None, clock: Optional[Callable[[], datetime]] = None):
        self._gh = github_client
        self.project_id = os.getenv("PROJECT_ID") or os.getenv("GOOGLE_CLOUD_PROJECT") or ""
        self._db_factory = db_factory or _default_db_factory
        self._db: Any = None
        self._db_ready = False
        self._env = os.environ if env is None else env
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    @property
    def gh(self) -> Optional[Github]:
        if self._gh:
            return self._gh
        token = os.getenv("GITHUB_TOKEN") or os.getenv("GITHUB_PAT")
        if not token:
            try:
                token = get_github_token(self.project_id)
            except Exception as e:
                logger.warning(f"Could not read GitHub token from resilience manager: {e}")

        if token:
            self._gh = Github(token)
            logger.info("Initialized PyGithub client dynamically.")
        return self._gh

    # ------------------------------------------------------------------ target
    def _ledger_db(self) -> Any:
        if not self._db_ready:
            try:
                self._db = self._db_factory()
            except Exception as e:
                logger.warning(f"Firestore client unavailable: {type(e).__name__}")
                self._db = None
            self._db_ready = True
        return self._db

    def workload_repo(self, product_id: Any, repo_name: Optional[str] = None) -> str:
        """The workload's own repository full name from the ledger (module docstring). Raises GithubRefused."""
        try:
            target = seam.verify_ledger_target(self._ledger_db(), product_id, seam.host_project_ids(self._env))
        except seam.TargetRefused as e:
            raise GithubRefused(f"REFUSED:{e.code}", e.detail, 403) from e
        recorded = target.workload.get("github_repo")
        parts = split_full_name(recorded)
        if parts is None:
            raise GithubRefused("REFUSED:REPO_NOT_RECORDED", "the workload ledger has no owner/name github_repo", 403)
        org = str(self._env.get("GITHUB_ORG") or "").strip()
        if not org:
            raise GithubRefused("REFUSED:GITHUB_ORG_UNCONFIGURED", "GITHUB_ORG is not set", 503)
        if parts[0] != org:
            raise GithubRefused("REFUSED:REPO_OUTSIDE_ORG", f"{recorded!r} is not in {org!r}", 403)
        if repo_name is not None and repo_name != recorded:
            raise GithubRefused("REFUSED:REPO_MISMATCH", "repo_name is not the workload's repository", 403)
        return recorded

    def _repo(self, product_id: Any, repo_name: Optional[str]):
        full_name = self.workload_repo(product_id, repo_name)
        client = self.gh
        if not client:
            raise GithubRefused("GITHUB_UNAVAILABLE", "no GitHub credentials", 503)
        try:
            repo = client.get_repo(full_name)
        except GithubException as e:
            raise GithubRefused("GITHUB_ERROR", f"get_repo: HTTP {_status_of(e)}", 404 if _status_of(e) == 404 else 502) from e
        if getattr(repo, "full_name", None) != full_name:  # a renamed / transferred repository redirects
            raise GithubRefused("REFUSED:REPO_MISMATCH", f"GitHub answered {getattr(repo, 'full_name', None)!r}", 403)
        return repo, full_name

    @staticmethod
    def _branch(value: Any, what: str) -> str:
        if not is_branch_name(value):
            raise GithubRefused(f"{what.upper()}_INVALID", f"{what} must be a plain git branch name")
        return value

    def _branch_record_id(self, full_name: str, branch: str) -> str:
        return hashlib.sha256(f"{full_name}\0{branch}".encode("utf-8")).hexdigest()[:40]

    # ------------------------------------------------------------------ writes (no retry: check before write)
    def create_branch(self, product_id: str, new_branch: str, source_branch: str = "main",
                      repo_name: Optional[str] = None) -> Dict[str, Any]:
        self._branch(new_branch, "new_branch")
        self._branch(source_branch, "source_branch")
        repo, full_name = self._repo(product_id, repo_name)
        try:
            repo.get_branch(new_branch)
        except GithubException as e:
            if _status_of(e) != 404:
                raise
        else:
            raise GithubRefused("BRANCH_EXISTS", new_branch, 409)
        sb = repo.get_branch(source_branch)
        repo.create_git_ref(ref=f"refs/heads/{new_branch}", sha=sb.commit.sha)
        recorded = True
        try:
            self._ledger_db().collection(BRANCH_RECORD_COLLECTION).document(
                self._branch_record_id(full_name, new_branch)).set({
                    "repo": full_name, "branch": new_branch, "product_id": product_id,
                    "source_branch": source_branch, "created_at": self._clock().isoformat()})
        except Exception as e:
            recorded = False  # audit trail only (this server never merges or deletes branches)
            logger.warning(f"Could not record created branch: {type(e).__name__}")
        logger.info(f"Created branch '{new_branch}' in '{full_name}' from '{source_branch}' (SHA: {sb.commit.sha[:7]})")
        return {"status": "BRANCH_CREATED", "repo": full_name, "branch": new_branch, "source_branch": source_branch,
                "commit_sha": sb.commit.sha, "branch_recorded": recorded}

    def commit_files(self, product_id: str, branch: str, commit_message: str, files: Dict[str, str],
                     repo_name: Optional[str] = None) -> Dict[str, Any]:
        """Commits files atomically (one tree, one commit, fast-forward ref update; never forced, never retried)."""
        self._branch(branch, "branch")
        if not isinstance(commit_message, str) or not commit_message.strip():
            raise GithubRefused("COMMIT_MESSAGE_INVALID", "commit_message is required")
        if not isinstance(files, dict) or not files or len(files) > MAX_FILES_PER_COMMIT:
            raise GithubRefused("FILES_INVALID", f"files must map 1..{MAX_FILES_PER_COMMIT} paths to text")
        for path, content in files.items():
            if not is_repo_path(path) or not isinstance(content, str):
                raise GithubRefused("FILES_INVALID", f"invalid path or content for {path!r}")
        repo, full_name = self._repo(product_id, repo_name)
        target_branch = repo.get_branch(branch)
        base_tree = repo.get_git_tree(target_branch.commit.sha)
        tree_elements = [InputGitTreeElement(path=path, mode="100644", type="blob", content=content)
                         for path, content in files.items()]
        new_tree = repo.create_git_tree(tree_elements, base_tree)
        parent_commit = repo.get_git_commit(target_branch.commit.sha)
        new_commit = repo.create_git_commit(message=commit_message, tree=new_tree, parents=[parent_commit])
        repo.get_git_ref(f"heads/{branch}").edit(new_commit.sha, force=False)
        logger.info(f"Committed {len(files)} files to '{branch}' in '{full_name}' (Commit: {new_commit.sha[:7]})")
        return {"status": "COMMITTED", "repo": full_name, "branch": branch, "commit_sha": new_commit.sha,
                "files_updated": list(files.keys())}

    def create_pull_request(self, product_id: str, title: str, body: str, head_branch: str,
                            base_branch: str = "main", repo_name: Optional[str] = None) -> Dict[str, Any]:
        """Opens a PR from a branch of the same repository; an open PR for the same head/base is returned as is."""
        self._branch(head_branch, "head_branch")
        self._branch(base_branch, "base_branch")
        if not isinstance(title, str) or not title.strip() or not isinstance(body, str):
            raise GithubRefused("PR_INVALID", "title (non-empty) and body are required")
        repo, full_name = self._repo(product_id, repo_name)
        owner = full_name.split("/")[0]
        for existing in repo.get_pulls(state="open", head=f"{owner}:{head_branch}", base=base_branch):
            return self._pr_view(existing, "PR_EXISTS", head_branch, base_branch)
        pr = repo.create_pull(title=title, body=body, head=head_branch, base=base_branch)
        logger.info(f"Opened PR #{pr.number} in '{full_name}': {pr.html_url}")
        return self._pr_view(pr, "PR_CREATED", head_branch, base_branch)

    @staticmethod
    def _pr_view(pr: Any, status: str, head: str, base: str) -> Dict[str, Any]:
        return {"status": status, "pr_number": pr.number, "title": pr.title, "pull_request_url": pr.html_url,
                "diff_url": pr.diff_url, "head": head, "base": base}

    # ------------------------------------------------------------------ reads (idempotent: retried on transient errors)
    @github_retry_with_backoff(max_retries=3, initial_wait=2.0)
    def read_file_content(self, product_id: str, file_path: str, branch: str = "main",
                          repo_name: Optional[str] = None) -> Dict[str, Any]:
        """Reads a file (or lists a directory) on a branch of the workload repository."""
        if not is_repo_path(file_path):
            raise GithubRefused("FILE_PATH_INVALID", "file_path must be a repository-relative path")
        self._branch(branch, "branch")
        repo, _ = self._repo(product_id, repo_name)
        contents = repo.get_contents(file_path, ref=branch)
        if isinstance(contents, list):
            return {"path": file_path, "type": "directory", "files": [f.name for f in contents]}
        return {"status": "SUCCESS", "path": file_path, "branch": branch,
                "content": contents.decoded_content.decode("utf-8"), "sha": contents.sha,
                "size_bytes": contents.size}

    @github_retry_with_backoff(max_retries=3, initial_wait=2.0)
    def get_diff(self, product_id: str, base: str = "main", head: str = "main",
                 repo_name: Optional[str] = None) -> Dict[str, Any]:
        """Comparison diff between two branches of the workload repository."""
        self._branch(base, "base")
        self._branch(head, "head")
        repo, _ = self._repo(product_id, repo_name)
        comparison = repo.compare(base, head)
        files_changed = [{"filename": f.filename, "status": f.status, "additions": f.additions,
                          "deletions": f.deletions, "patch": f.patch or ""} for f in comparison.files]
        return {"status": "SUCCESS", "base": base, "head": head, "total_commits": comparison.total_commits,
                "files_changed_count": len(files_changed), "files": files_changed}
