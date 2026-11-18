"""
Project Castor: Serverless Git Provider Adapter (`ServerlessGitProvider`)
Implements the abstract VCSProvider interface for internal, 100% Google Cloud native
source control backed by the `apps/git-server` microservice and Cloud Storage FUSE.
Scales to zero ($0/mo idle cost), requires zero relational databases, and supports
pure headless operation for autonomous AI agents and local developer workflows.

FD-4K: every call carries a Google ID token (audience = the git server origin) in BOTH
`Authorization` (verified by the git server) and `X-Serverless-Authorization` (consumed by Cloud Run IAM,
which strips the signature of the header it validates). Only ID tokens are ever sent: never an OAuth access
token. Failures are raised, never reported as success (no fake commit SHA / fake MERGED).
REPLICATED FILE: byte-identical copies in apps/{control-center,orchestrator-gateway,project-vending,qa-runner}/
shared/providers/ and mcp-servers/{github,terraform}/shared/providers/ (tests/test_fd4k_serverless_git_client.py).

SERVERLESS-AUTOMERGE-SHA: `merge_pull_request(..., expected_source_sha=<sha>)` asks the git server to merge only
that source commit. A git server older than this check ignores the field, so the answer alone is never trusted:
`merge_source_check_supported()` asks the server first (GET /api/v1/capabilities; an older server has no such
route -> False), and the merge result reports `source_sha_checked` True only when the server echoed
`source_sha_checked: true` with `source_sha` equal to the expected commit. A 409 with reason_code SOURCE_MOVED
raises ServerlessGitSourceMoved (a PRIdentityMismatch on head_sha, like GitHub's moved-head refusal).

GIT-404-TYPED: a 404 means "not found" only when the git server sent it (header X-StackVend-Git-Server: 1); any other
404 raises GitServerUnreachable (stage vcs). Deploy order: the git server first, then the clients.
"""

import io
import logging
import os
import urllib.parse
from typing import Any, BinaryIO, Dict, List, Optional, Sequence, Tuple

try:
    import requests
except ImportError:
    requests = None

from ..path_safety import validate_product_id
from ..vcs_provider import (
    DEFAULT_AGENT_AUTHOR_EMAIL, IncompleteRepoTreeError, PRIdentityMismatch, VCSProvider, RepositoryMetadata,
    PipelineConfig,
)

logger = logging.getLogger("vcs-serverless-git-provider")

LOCAL_COMPOSE_URL = "http://castor-git-server:8080"


class ServerlessGitError(RuntimeError):
    """A Serverless Git call failed. Never swallowed into a fake success."""


class ServerlessGitConfigError(ServerlessGitError):
    """No git server URL is configured or discoverable."""


class ServerlessGitAuthError(ServerlessGitError):
    """No ID token available, or the git server rejected the caller (HTTP 401/403)."""


class ServerlessGitMergeConflict(ServerlessGitError):
    """HTTP 409: the target branch advanced since the branch point (FD-4V); nothing was merged.

    `body` is the server's JSON answer (a dict, empty when it was not JSON). A 409 whose reason_code is SOURCE_MOVED
    never reaches a caller as this class: merge_pull_request raises ServerlessGitSourceMoved instead."""

    def __init__(self, message: str, body: Any = None):
        super().__init__(message)
        self.body: Dict[str, Any] = body if isinstance(body, dict) else {}


class ServerlessGitSourceMoved(PRIdentityMismatch):
    """SERVERLESS-AUTOMERGE-SHA: HTTP 409 reason_code SOURCE_MOVED. The source branch head is not the commit the
    caller asked to merge (expected_source_sha); nothing was merged and both branches are unchanged. It is a
    PRIdentityMismatch on head_sha, the same refusal GitHub gives when a PR head moved before the merge."""

    error_class = "SOURCE_MOVED"

    def __init__(self, expected_sha: str, actual_sha: Any):
        super().__init__("head_sha", expected_sha, actual_sha)


class ServerlessGitNotFound(ServerlessGitError):
    """HTTP 404 on a commit-bound read: the repository or refs/heads/{branch} does not exist (never another branch)."""


class GitServerUnreachable(ServerlessGitError):
    """GIT-404-TYPED: an HTTP 404 that the git server itself did not send (no GIT_SERVER_HEADER), e.g. Cloud Run's
    front end refusing a caller that the internal-only ingress does not admit. Never read as "not found"."""

    error_class = "GIT_SERVER_UNREACHABLE"
    stage = "vcs"


# GIT-404-TYPED (internal-ingress plan §6.3): apps/git-server sets this exact header on every answer, its own 404s
# included (= apps/git-server/main.py GIT_SERVER_HEADER; tests pin both). A 404 counts as "repository / branch / route
# not found" only when it is present with this value. HTTP header names are case-insensitive (RFC 9110).
GIT_SERVER_HEADER = "X-StackVend-Git-Server"
GIT_SERVER_HEADER_VALUE = "1"


def answered_by_git_server(res: Any) -> bool:
    """True when the response carries GIT_SERVER_HEADER == GIT_SERVER_HEADER_VALUE (header name case-insensitive)."""
    headers = getattr(res, "headers", None)
    items = headers.items() if hasattr(headers, "items") else ()
    want = GIT_SERVER_HEADER.lower()
    return any(isinstance(k, str) and k.lower() == want and v == GIT_SERVER_HEADER_VALUE for k, v in items)


class ServerlessGitDeletionUnsupported(ServerlessGitError):
    """FD-4DC-e: HTTP 404 on the commit-with-deletions route (repository missing, or a git server older than file
    deletion). Nothing was committed."""

    error_class = "VCS_DELETION_UNSUPPORTED"


def _is_commit_sha(value: Any) -> bool:
    """True for a full SHA-1 commit id: exactly 40 lowercase hex characters (the git server's X-Commit-Sha)."""
    return isinstance(value, str) and len(value) == 40 and all(c in "0123456789abcdef" for c in value)


# FD-7M-a: the `_REGION` substitution the committed cloudbuild.yaml carries when the caller passes no region (direct
# callers, tests). The developer always passes the workload's region (DeveloperAgent._assemble_tree). Category (c): a
# default callers override, like shared/express_synthesizer.py `region`.
DEFAULT_CLOUDBUILD_REGION = "us-central1"

DEFAULT_CLOUDBUILD_TEMPLATE = """# ==============================================================================
# STACKVEND: GOOGLE CLOUD BUILD PIPELINE (SERVERLESS GIT NATIVE)
# Workload: {product_id}
# Service:  {service_name}
# ==============================================================================

steps:
  # 1. Run automated unit tests in isolated runner
  - name: "python:3.11-slim"
    id: "unit-tests"
    entrypoint: "bash"
    args:
      - "-c"
      - |
        if [ -f requirements.txt ]; then
          pip install --no-cache-dir -r requirements.txt pytest
          if [ -d tests ]; then
            python -m pytest tests/ -v
          fi
        fi

  # 2. Build application container image via Google Cloud Buildpacks
  - name: "gcr.io/k8s-skaffold/pack"
    id: "buildpack-compile"
    args:
      - "build"
      - "${{_REGION}}-docker.pkg.dev/${{PROJECT_ID}}/castor-docker-repo/{product_id}:${{COMMIT_SHA}}"
      - "--builder"
      - "gcr.io/buildpacks/builder:v1"
      - "--path"
      - "."

  # 3. Push container image to Google Artifact Registry
  - name: "gcr.io/cloud-builders/docker"
    id: "push-image"
    args:
      - "push"
      - "${{_REGION}}-docker.pkg.dev/${{PROJECT_ID}}/castor-docker-repo/{product_id}:${{COMMIT_SHA}}"

substitutions:
  _REGION: "{region}"

images:
  - "${{_REGION}}-docker.pkg.dev/${{PROJECT_ID}}/castor-docker-repo/{product_id}:${{COMMIT_SHA}}"

options:
  logging: CLOUD_LOGGING_ONLY
"""


class ServerlessGitProvider(VCSProvider):
    """Encapsulates all Serverless Git operations for Project Castor."""

    def __init__(
        self,
        server_url: Optional[str] = None,
        project_id: Optional[str] = None,
        auth_token: Optional[str] = None,
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
        raw_url = (
            server_url
            or getattr(settings, "git_server_url", None)
            or getattr(getattr(settings, "governance", None), "git_server_url", None)
            or os.getenv("CASTOR_GIT_SERVER_URL")
            or os.getenv("GIT_SERVER_URL")
            or ""
        )
        if not raw_url:
            try:
                from shared.settings import get_platform_settings
                p_settings = get_platform_settings()
                raw_url = (
                    getattr(p_settings, "git_server_url", "")
                    or getattr(getattr(p_settings, "governance", None), "git_server_url", "")
                )
            except Exception:
                pass
        raw_url = str(raw_url).strip().rstrip("/") if raw_url else ""
        if not raw_url and not self.project_id:
            raw_url = LOCAL_COMPOSE_URL  # local docker-compose development only

        # FD-4K/Q11: no guessed hostname. Unknown URL -> lazy discovery on first use, else ServerlessGitConfigError.
        self.server_url: Optional[str] = raw_url or None
        self.auth_token = auth_token or os.getenv("CASTOR_GIT_AUTH_TOKEN")

    # --------------------------------------------------------------------------
    # Endpoint, identity and transport
    # --------------------------------------------------------------------------
    def _discover_server_url(self) -> str:
        """Cloud Run v2 REST discovery of castor-git-server in the platform project (region from env only)."""
        region = os.getenv("REGION") or os.getenv("DEFAULT_REGION") or ""
        if not (self.project_id and region):
            return ""
        try:
            import google.auth
            from google.auth.transport.requests import AuthorizedSession

            creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            resp = AuthorizedSession(creds).get(
                f"https://run.googleapis.com/v2/projects/{self.project_id}/locations/{region}/services/castor-git-server",
                timeout=5,
            )
            if resp.status_code == 200:
                return str(resp.json().get("uri", "")).rstrip("/")
        except Exception as disc_err:
            logger.warning(f"Discovery of castor-git-server failed: {type(disc_err).__name__}")
        return ""

    def _base_url(self) -> str:
        if not self.server_url:
            self.server_url = self._discover_server_url() or None
        if not self.server_url:
            raise ServerlessGitConfigError(
                "Serverless Git server URL is not configured (set GIT_SERVER_URL / CASTOR_GIT_SERVER_URL or "
                "governance.git_server_url)."
            )
        return self.server_url

    def _audience(self) -> str:
        parsed = urllib.parse.urlsplit(self._base_url())
        return f"{parsed.scheme}://{parsed.netloc}"

    def _resolve_iam_token(self) -> Optional[str]:
        """Google OIDC ID token for the git server. Never an OAuth access token (FD-4K)."""
        if self.auth_token:
            return self.auth_token
        token = os.getenv("GOOGLE_OIDC_ID_TOKEN")
        if token:
            return token
        try:
            from google.auth.transport import requests as google_requests
            from google.oauth2 import id_token

            token = id_token.fetch_id_token(google_requests.Request(), self._audience())
            if token:
                return token
        except ServerlessGitConfigError:
            raise
        except Exception as e:
            logger.warning(f"OIDC ID token fetch failed: {type(e).__name__}: {e}")
        return None

    def _auth_header_pairs(self) -> List[Tuple[str, str]]:
        token = self._resolve_iam_token()
        if not token:
            raise ServerlessGitAuthError("No Google ID token available for the Serverless Git server.")
        value = f"Bearer {token}"
        return [("Authorization", value), ("X-Serverless-Authorization", value)]

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        headers.update(dict(self._auth_header_pairs()))
        return headers

    def _call(self, method: str, path: str, *, ok: Tuple[int, ...] = (200, 201), allow_404: bool = False,
              timeout: int = 30, **kwargs: Any):
        """One REST call. Returns the response for an `ok` status (or 404 when allow_404); raises otherwise."""
        if requests is None:
            raise ServerlessGitError("The 'requests' package is required for Serverless Git calls.")
        url = f"{self._base_url()}{path}"
        try:
            res = getattr(requests, method)(url, headers=self._get_headers(), timeout=timeout,
                                            allow_redirects=False, **kwargs)
        except ServerlessGitError:
            raise
        except Exception as e:
            raise ServerlessGitError(f"Serverless Git {method.upper()} {path} failed: {type(e).__name__}: {e}") from e
        code = res.status_code
        if code == 404 and not answered_by_git_server(res):
            raise GitServerUnreachable(
                f"Serverless Git {method.upper()} {path} returned HTTP 404 without the {GIT_SERVER_HEADER} header: "
                "the git server did not answer (an ingress refusal or a wrong URL), so this is not 'not found'")
        if code in (401, 403):
            raise ServerlessGitAuthError(f"Serverless Git rejected the caller on {path} (HTTP {code}): {res.text[:300]}")
        if code == 409:
            try:
                body = res.json()
            except Exception:  # noqa: BLE001 - a non-JSON 409 keeps an empty body (never a reason code)
                body = None
            raise ServerlessGitMergeConflict(f"Serverless Git conflict on {path}: {res.text[:500]}", body=body)
        if code in ok or (allow_404 and code == 404):
            return res
        raise ServerlessGitError(f"Serverless Git {method.upper()} {path} returned HTTP {code}: {res.text[:300]}")

    def _clean_product_id(self, repo_identifier: str) -> str:
        """Extracts the bare product_id from repo_identifier ('castor/my-app' or 'castor/my-app.git' -> 'my-app').

        FD-4K: suffix removal only (no substring replace) and an anchored RFC 1123 id, else UnsafePathError.
        """
        clean = str(repo_identifier).strip().split("/")[-1].removesuffix(".git")
        return validate_product_id(clean)

    # --------------------------------------------------------------------------
    # 1. Repository Lifecycle & Metadata
    # --------------------------------------------------------------------------
    def vend_repository(
        self,
        product_id: str,
        description: str = "",
        initial_branch: str = "main",
        auto_protect_branch: bool = True,
        **kwargs: Any,
    ) -> RepositoryMetadata:
        """Initializes a new bare Git repository on Cloud Storage FUSE via apps/git-server."""
        clean_id = self._clean_product_id(product_id)
        payload = {
            "product_id": clean_id,
            "description": description or f"StackVend workload repository for '{clean_id}'",
            "initial_branch": initial_branch,
        }
        res = self._call("post", "/api/v1/repos", json=payload, timeout=30)
        data = res.json()
        clone_http = f"{self._base_url()}{data.get('clone_url', f'/git/{clean_id}.git')}"
        logger.info(f"Vended Serverless Git repo for '{clean_id}' ({data.get('status', 'CREATED')})")
        return RepositoryMetadata(
            provider="SERVERLESS_GIT",
            repo_name=clean_id,
            full_name=f"castor/{clean_id}",
            html_url=clone_http,
            clone_url_http=clone_http,
            clone_url_ssh=None,
            default_branch=initial_branch,
            is_reused=data.get("status") == "EXISTS",
            ui_icon="☁️",
        )

    def get_repository_metadata(self, repo_identifier: str) -> RepositoryMetadata:
        clean_id = self._clean_product_id(repo_identifier)
        clone_http = f"{self._base_url()}/git/{clean_id}.git"
        default_branch = "main"
        res = self._call("get", f"/api/v1/repos/{clean_id}/metadata", ok=(200,), allow_404=True, timeout=10)
        if res.status_code == 200:
            default_branch = res.json().get("default_branch", "main")

        return RepositoryMetadata(
            provider="SERVERLESS_GIT",
            repo_name=clean_id,
            full_name=f"castor/{clean_id}",
            html_url=clone_http,
            clone_url_http=clone_http,
            clone_url_ssh=None,
            default_branch=default_branch,
            is_reused=False,
            ui_icon="☁️",
        )

    # --------------------------------------------------------------------------
    # 2. Branch & Reference Management
    # --------------------------------------------------------------------------
    def create_or_verify_branch(
        self,
        repo_identifier: str,
        branch_name: str,
        source_branch: str = "main",
    ) -> str:
        clean_id = self._clean_product_id(repo_identifier)
        payload = {"branch_name": branch_name, "source_branch": source_branch}
        self._call("post", f"/api/v1/repos/{clean_id}/branches", json=payload, timeout=15)
        return branch_name

    def get_authenticated_clone_url(
        self,
        repo_identifier: str,
        branch: str = "main",
    ) -> str:
        """DEPRECATED (kept for the VCSProvider interface): a URL with an embedded token cannot pass Cloud Run IAM
        (it only accepts Bearer headers) and persists the token in .git/config. Use get_clone_auth()."""
        clean_id = self._clean_product_id(repo_identifier)
        token = self._resolve_iam_token()
        parsed = urllib.parse.urlsplit(self._base_url())

        if token and parsed.netloc:
            return f"{parsed.scheme}://oauth2:{token}@{parsed.netloc}/git/{clean_id}.git"
        return f"{self._base_url()}/git/{clean_id}.git"

    def get_clone_auth(self, repo_identifier: str) -> Tuple[str, List[Tuple[str, str]]]:
        """(plain clone URL, HTTP headers) for `git -c http.extraHeader=...` style clones; no token in the URL."""
        clean_id = self._clean_product_id(repo_identifier)
        return f"{self._base_url()}/git/{clean_id}.git", self._auth_header_pairs()

    # --------------------------------------------------------------------------
    # 3. Code Ingestion & Streaming
    # --------------------------------------------------------------------------
    def fetch_file_content(
        self,
        repo_identifier: str,
        file_path: str,
        branch: str = "main",
    ) -> str:
        """Text of `file_path` on exactly refs/heads/{branch}.

        Register row 40: the server never substitutes HEAD. A missing repository or branch raises
        ServerlessGitNotFound (fail closed); only a missing file on an existing branch (404 with
        `X-Git-Not-Found: file`) returns '' as before. Slashed branch names are sent like the archive client's.
        """
        clean_id = self._clean_product_id(repo_identifier)
        clean_path = urllib.parse.quote(file_path.lstrip("/"), safe="/")
        path = f"/api/v1/repos/{clean_id}/blob/{self._branch_path(branch)}/{clean_path}"
        res = self._call("get", path, ok=(200,), allow_404=True, timeout=15)
        if res.status_code == 404:
            if (getattr(res, "headers", None) or {}).get("X-Git-Not-Found") == "file":
                return ""
            raise ServerlessGitNotFound(f"Serverless Git branch '{branch}' of '{clean_id}' not found")
        return res.json().get("content", "")

    def fetch_file_tree(
        self,
        repo_identifier: str,
        branch: str = "main",
        max_files: int = 2500,
        require_complete: bool = False,
    ) -> Dict[str, str]:
        """Text files of exactly refs/heads/{branch}. Register row 40: a missing repository or branch raises
        ServerlessGitNotFound (the server never substitutes HEAD); an existing empty branch returns {}.
        FD-4D: require_complete=True raises IncompleteRepoTreeError when the tree reached `max_files`.
        FD-4DC: the whole tree is already one server call (the git server reads every blob locally). A server that
        sends the boolean `truncated` flag is believed (a tree of exactly `max_files` files is then complete); a
        server without the flag keeps the old rule (reaching the cap counts as truncated)."""
        clean_id = self._clean_product_id(repo_identifier)
        path = f"/api/v1/repos/{clean_id}/tree/{self._branch_path(branch)}?max_files={max_files}"
        self.last_tree_status = {"complete": False, "truncated": False, "error": None}
        res = self._call("get", path, ok=(200,), allow_404=True, timeout=30)
        if res.status_code == 404:
            raise ServerlessGitNotFound(f"Serverless Git branch '{branch}' of '{clean_id}' not found")
        body = res.json()
        files = body.get("files", {})
        server_flag = body.get("truncated")
        if isinstance(server_flag, bool):
            truncated = server_flag or len(files) > max_files
        else:
            # Lane 10 RT F1: an older server cuts at max_files without a flag, so reaching the cap is "maybe truncated".
            truncated = len(files) >= max_files
        self.last_tree_status = {"complete": not truncated, "truncated": truncated, "error": None}
        if require_complete and truncated:
            raise IncompleteRepoTreeError(clean_id, branch, self.last_tree_status)
        return files

    def export_archive_stream(
        self,
        repo_identifier: str,
        branch: str = "main",
    ) -> BinaryIO:
        clean_id = self._clean_product_id(repo_identifier)
        res = self._call("get", f"/api/v1/repos/{clean_id}/archive/{branch}", ok=(200,), allow_404=True, timeout=60)
        if res.status_code == 200:
            return io.BytesIO(res.content)
        return io.BytesIO(b"")

    def _branch_path(self, branch: str) -> str:
        if not isinstance(branch, str) or not branch:
            raise ServerlessGitError("branch must be a non-empty string")
        return urllib.parse.quote(branch, safe="/")

    def export_archive_with_sha(
        self,
        repo_identifier: str,
        branch: str = "main",
    ) -> Tuple[str, bytes]:
        """(commit SHA, .tar.gz bytes) of exactly one commit: the head of refs/heads/{branch} when the server built it.

        19c: the SHA comes from the git server's `X-Commit-Sha` header for the same response as the body. A missing
        branch raises ServerlessGitNotFound (the server never substitutes HEAD); a missing or malformed header, or an
        empty body, raises ServerlessGitError. Nothing is ever returned without a verified 40-hex commit id.
        """
        clean_id = self._clean_product_id(repo_identifier)
        path = f"/api/v1/repos/{clean_id}/archive/{self._branch_path(branch)}"
        res = self._call("get", path, ok=(200,), allow_404=True, timeout=60)
        if res.status_code == 404:
            raise ServerlessGitNotFound(f"Serverless Git branch '{branch}' of '{clean_id}' not found")
        sha = (getattr(res, "headers", None) or {}).get("X-Commit-Sha", "")
        if not _is_commit_sha(sha):
            raise ServerlessGitError(f"Serverless Git archive of '{clean_id}@{branch}' lacks a valid X-Commit-Sha header")
        if not res.content:
            raise ServerlessGitError(f"Serverless Git archive of '{clean_id}@{branch}' is empty")
        return sha, res.content

    def get_branch_head_sha(
        self,
        repo_identifier: str,
        branch: str = "main",
    ) -> str:
        """Head commit SHA of refs/heads/{branch} (read-only refs endpoint). Raises ServerlessGitNotFound when the
        branch is missing and ServerlessGitError on any other failure or a malformed answer."""
        clean_id = self._clean_product_id(repo_identifier)
        path = f"/api/v1/repos/{clean_id}/refs/heads/{self._branch_path(branch)}"
        res = self._call("get", path, ok=(200,), allow_404=True, timeout=15)
        if res.status_code == 404:
            raise ServerlessGitNotFound(f"Serverless Git branch '{branch}' of '{clean_id}' not found")
        try:
            sha = res.json().get("commit_sha", "")
        except Exception as e:
            raise ServerlessGitError(f"Serverless Git refs answer for '{clean_id}@{branch}' is not JSON: {type(e).__name__}") from e
        if not _is_commit_sha(sha):
            raise ServerlessGitError(f"Serverless Git refs answer for '{clean_id}@{branch}' lacks a valid commit_sha")
        return sha

    # --------------------------------------------------------------------------
    # 4. Atomic Commits & Pull Requests
    # --------------------------------------------------------------------------
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
        clean_id = self._clean_product_id(repo_identifier)
        payload = {
            "branch": branch,
            "files": files,
            "commit_message": commit_message,
            "author_name": author_name,
            "author_email": author_email,
        }
        if not files_to_delete:   # no deletions: exactly the request every caller sent before FD-4DC-e
            res = self._call("post", f"/api/v1/repos/{clean_id}/commits", json=payload, timeout=30)
            commit_sha = res.json().get("commit_sha")
            if not commit_sha:
                raise ServerlessGitError(f"Serverless Git commit to '{clean_id}@{branch}' returned no commit_sha")
            return commit_sha
        # FD-4DC-e: deletions go to their own route. A git server older than FD-4DC-e has no such route and answers
        # 404 before writing anything, so an old server + new client refuses loudly (nothing committed) instead of
        # committing the files and silently keeping the paths it was asked to delete.
        res = self._call("post", f"/api/v1/repos/{clean_id}/commits-with-deletions",
                         json=dict(payload, files_to_delete=list(files_to_delete)), timeout=30, allow_404=True)
        if res.status_code == 404:
            raise ServerlessGitDeletionUnsupported(
                f"Serverless Git refused the commit with {len(files_to_delete)} deletion(s) on '{clean_id}@{branch}' "
                f"(HTTP 404): the repository does not exist or the git server predates file deletion (FD-4DC-e; "
                f"deploy the git server first). Nothing was committed.")
        body = res.json()
        commit_sha = body.get("commit_sha")
        if not commit_sha or not isinstance(body.get("files_deleted"), list):
            raise ServerlessGitError(f"Serverless Git commit with deletions to '{clean_id}@{branch}' returned no "
                                     f"commit_sha / files_deleted")
        return commit_sha

    def get_diff(
        self,
        repo_identifier: str,
        base_branch: str,
        target_branch: str,
    ) -> Dict[str, Any]:
        return {
            "base_branch": base_branch,
            "target_branch": target_branch,
            "files_changed": [],
            "diff_text": "",
        }

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
        """
        Synthesizes a PR reference URL for bare Git on Cloud Storage FUSE.
        Tracks the candidate branch without requiring a relational database.
        """
        clean_id = self._clean_product_id(repo_identifier)
        synthetic_pr_url = f"{self._base_url()}/git/{clean_id}.git/refs/heads/{head_branch}"

        self._last_head_branch = head_branch
        logger.info(f"Synthetic PR opened for '{clean_id}' ({head_branch} -> {base_branch}) at {synthetic_pr_url}")
        return {
            "status": "OPEN",
            "pull_request_url": synthetic_pr_url,
            "pr_number": 1,
            "head_branch": head_branch,
            "base_branch": base_branch,
            "title": title,
            "body": body,
        }

    def reconcile_automated_pull_requests(
        self,
        repo_identifier: str,
        *,
        superseded: Sequence[Any] = (),
        comment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """FD-4P (RT F5): same keyword-only ledger contract as the ABC. The git server has no PR objects and no
        SHA-guarded branch delete yet (lane 3 follow-up), so every superseded identity is SKIPPED (untouched)."""
        return {
            "status": "RECONCILED",
            "results": [{"branch": getattr(i, "branch", None), "pr_number": None, "outcome": "SKIPPED",
                         "reason": "Serverless Git has no SHA-guarded branch delete yet"} for i in superseded or ()],
        }

    def merge_source_check_supported(self) -> bool:
        """SERVERLESS-AUTOMERGE-SHA: True only when the git server says its merge refuses a source branch whose head
        is not `expected_source_sha`. An older server has no capabilities route (404) -> False. Any other failure
        raises (ServerlessGitError / ServerlessGitAuthError): the caller decides, it is never read as True."""
        res = self._call("get", "/api/v1/capabilities", ok=(200,), allow_404=True, timeout=10)
        if res.status_code == 404:
            return False
        try:
            data = res.json()
        except Exception as e:  # noqa: BLE001
            raise ServerlessGitError(f"Serverless Git capabilities answer is not JSON: {type(e).__name__}") from e
        caps = data.get("capabilities") if isinstance(data, dict) else None
        return isinstance(caps, dict) and caps.get("merge_expected_source_sha") is True

    def merge_pull_request(
        self,
        repo_identifier: str,
        pr_number: int,
        commit_message: Optional[str] = None,
        merge_method: str = "squash",
        source_branch: Optional[str] = None,
        target_branch: Optional[str] = None,
        expected_source_sha: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Server-side fast-forward-only merge via apps/git-server (FD-4V).

        Returns merged=True only for HTTP 200 with status MERGED or ALREADY_UP_TO_DATE. A 409 (the target advanced
        since the branch point) raises ServerlessGitMergeConflict; every other failure raises ServerlessGitError.
        SERVERLESS-AUTOMERGE-SHA: with `expected_source_sha` (a full commit SHA) the server merges only that source
        commit; a 409 SOURCE_MOVED raises ServerlessGitSourceMoved. `source_sha_checked` in the result is True only
        when the server confirmed the check for exactly that commit (an older server ignores the field: False).
        """
        clean_id = self._clean_product_id(repo_identifier)
        if expected_source_sha is not None and not _is_commit_sha(expected_source_sha):
            raise ServerlessGitError(f"expected_source_sha must be a full commit SHA, got {expected_source_sha!r}")

        # Determine source branch from parameter, last head branch, or default to stage
        source_branch = source_branch or getattr(self, "_last_head_branch", None) or "stage"
        target_branch = target_branch or "main"

        payload = {
            "source_branch": source_branch,
            "target_branch": target_branch,
            "commit_message": commit_message or f"feat({clean_id}): automated release merge into {target_branch} by StackVend",
            "merge_method": merge_method,
        }
        if expected_source_sha is not None:
            payload["expected_source_sha"] = expected_source_sha
        try:
            res = self._call("post", f"/api/v1/repos/{clean_id}/merge", ok=(200,), json=payload, timeout=20)
        except ServerlessGitMergeConflict as conflict:
            if expected_source_sha is not None and conflict.body.get("reason_code") == ServerlessGitSourceMoved.error_class:
                raise ServerlessGitSourceMoved(expected_source_sha, conflict.body.get("source_sha")) from conflict
            raise
        data = res.json()
        status_str = data.get("status")
        if status_str not in ("MERGED", "ALREADY_UP_TO_DATE"):
            raise ServerlessGitError(f"Serverless Git merge on '{clean_id}' returned unexpected status {status_str!r}")
        checked = (expected_source_sha is not None and data.get("source_sha_checked") is True
                   and data.get("source_sha") == expected_source_sha)
        return {
            "status": status_str,
            "merged": True,
            "commit_sha": data.get("commit_sha", ""),
            "target_branch": target_branch,
            "source_sha_checked": checked,
        }

    # --------------------------------------------------------------------------
    # 5. CI/CD Pipeline Contracts & Validation
    # --------------------------------------------------------------------------
    def get_pipeline_contract(self, service_name: str, product_id: str,
                              region: Optional[str] = None) -> PipelineConfig:
        """Returns Google Cloud Build pipeline contract for pure GCP native workloads.

        FD-7M-a: `region` is the workload's region, rendered into the `_REGION` substitution (Artifact Registry host
        of the image). None / "" -> DEFAULT_CLOUDBUILD_REGION (the text is byte-identical to before for it)."""
        content = DEFAULT_CLOUDBUILD_TEMPLATE.format(
            service_name=service_name,
            product_id=product_id,
            region=region or DEFAULT_CLOUDBUILD_REGION,
        )
        return PipelineConfig(
            pipeline_type="CLOUD_BUILD",
            target_file="cloudbuild.yaml",
            template_content=content,
        )

    def validate_pipeline_content(self, file_path: str, content: str) -> None:
        """Validates Cloud Build YAML syntax."""
        if not content.strip():
            raise ValueError(f"Pipeline file '{file_path}' is empty.")
        if "steps:" not in content:
            raise ValueError(f"Cloud Build pipeline in '{file_path}' must declare 'steps:' mapping.")
