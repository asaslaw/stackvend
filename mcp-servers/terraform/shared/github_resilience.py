"""
Project Castor: Centralized GitHub Resilience, Token Caching & Rate Limit Gateway
Provides proactive JIT token caching, secondary & primary rate limit backoff,
and git concurrency resilience across all platform microservices.
"""

import functools
import json
import logging
import os
import random
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional, Tuple

logger = logging.getLogger("castor.github.resilience")


class GitHubRateLimitExceededError(Exception):
    """Raised when GitHub rate limit reset duration exceeds safety threshold."""
    pass


def extract_error_metadata(ex: Exception) -> Tuple[Optional[int], Dict[str, str], str]:
    """
    Extracts HTTP status code, headers (lowercased), and response body
    from various exception types (PyGithub GithubException, httpx.HTTPStatusError, requests.HTTPError).
    """
    status: Optional[int] = None
    headers: Dict[str, str] = {}
    body: str = ""

    # 1. PyGithub GithubException
    if hasattr(ex, "status") and isinstance(getattr(ex, "status"), int):
        status = getattr(ex, "status")
        raw_headers = getattr(ex, "headers", {}) or {}
        headers = {str(k).lower(): str(v) for k, v in raw_headers.items()}
        data = getattr(ex, "data", "") or ""
        body = str(data) if data else str(ex)
        return status, headers, body

    # 2. HTTPX HTTPStatusError
    if hasattr(ex, "response") and ex.response is not None:
        resp = ex.response
        status = getattr(resp, "status_code", None)
        raw_headers = getattr(resp, "headers", {}) or {}
        headers = {str(k).lower(): str(v) for k, v in raw_headers.items()}
        try:
            body = getattr(resp, "text", "") or str(ex)
        except Exception:
            body = str(ex)
        return status, headers, body

    # 3. Generic Exception fallback
    body = str(ex)
    return status, headers, body


def is_rate_limit_or_transient(status: Optional[int], headers: Dict[str, str], body: str) -> bool:
    """
    Determines if an HTTP error is due to primary/secondary rate limits
    or transient upstream gateway errors (500, 502, 503, 504).
    """
    if status is None:
        return False

    # Standard rate limit status
    if status == 429:
        return True

    # Upstream transient gateway errors
    if status in (500, 502, 503, 504):
        return True

    # 422 Unprocessable Entity: check for GitHub GitRPC replica sync latency (BadObjectState)
    if status == 422:
        body_lower = body.lower()
        if "badobjectstate" in body_lower or "gitrpc" in body_lower:
            return True

    # 403 Forbidden: check for rate limits
    if status == 403:
        if "retry-after" in headers:
            return True
        if headers.get("x-ratelimit-remaining") == "0":
            return True
        body_lower = body.lower()
        if "secondary rate limit" in body_lower or "abuse detection" in body_lower or "rate limit" in body_lower:
            return True

    return False


def calculate_backoff(
    status: Optional[int],
    headers: Dict[str, str],
    current_wait: float,
    max_sleep_seconds: float = 60.0,
) -> float:
    """
    Calculates sleep duration respecting 'Retry-After', 'x-ratelimit-reset',
    or applying exponential backoff with random jitter.
    """
    # 1. Retry-After header
    if "retry-after" in headers:
        try:
            retry_after = float(headers["retry-after"])
            if retry_after > 0:
                return retry_after
        except (ValueError, TypeError):
            pass

    # 2. x-ratelimit-reset epoch header
    if headers.get("x-ratelimit-remaining") == "0" and "x-ratelimit-reset" in headers:
        try:
            reset_ts = float(headers["x-ratelimit-reset"])
            now = time.time()
            sleep_needed = reset_ts - now + 1.0 # 1s buffer
            if sleep_needed > 0:
                return sleep_needed
        except (ValueError, TypeError):
            pass

    # 3. Exponential backoff with jitter
    jitter = random.uniform(0.5, 1.5)
    return current_wait + jitter


def github_retry_with_backoff(
    max_retries: int = 4,
    initial_wait: float = 2.0,
    max_sleep_seconds: float = 60.0,
    max_attempts: Optional[int] = None,
) -> Callable:
    """
    Decorator that catches GitHub secondary rate limits, primary rate limits,
    and transient HTTP errors. Respects 'Retry-After' and 'x-ratelimit-reset',
    with a hard sleep ceiling (max_sleep_seconds) to prevent Cloud Run request timeouts.
    """
    if max_attempts is not None:
        max_retries = max_attempts
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            retries = 0
            wait = initial_wait
            while True:
                try:
                    return func(*args, **kwargs)
                except Exception as ex:
                    status, headers, body = extract_error_metadata(ex)
                    if not is_rate_limit_or_transient(status, headers, body):
                        raise

                    retries += 1
                    if retries > max_retries:
                        logger.error(f"GitHub retry limit exceeded ({retries}/{max_retries}). Last error: {ex}")
                        raise

                    sleep_time = calculate_backoff(status, headers, wait, max_sleep_seconds)

                    # Guardrail: Fail fast if sleep exceeds Cloud Run request timeout ceiling
                    if sleep_time > max_sleep_seconds:
                        logger.error(
                            f"GitHub rate limit reset ({sleep_time:.1f}s) exceeds safety ceiling ({max_sleep_seconds}s). "
                            "Aborting retry to prevent Cloud Run container timeout."
                        )
                        raise GitHubRateLimitExceededError(
                            f"GitHub rate limit sleep required ({sleep_time:.1f}s) exceeds max threshold ({max_sleep_seconds}s)."
                        )

                    logger.warning(
                        f"GitHub rate limit or transient error ({status}). "
                        f"Retrying in {sleep_time:.1f}s (Attempt {retries}/{max_retries})..."
                    )
                    time.sleep(sleep_time)
                    wait *= 2.0
        return wrapper
    return decorator


class GitHubTokenManager:
    """
    Thread-safe in-memory cache and proactive JIT token generator for GitHub App installations.
    Eliminates redundant Secret Manager and GitHub API trips by caching credentials and valid tokens.
    """

    def __init__(self, project_id: Optional[str] = None):
        self.project_id = project_id or os.getenv("PROJECT_ID") or os.getenv("GOOGLE_CLOUD_PROJECT") or ""
        if not self.project_id:
            try:
                import google.auth
                _, _discovered_proj = google.auth.default()
                if _discovered_proj:
                    self.project_id = _discovered_proj
            except Exception:
                pass
        self._cached_token: Optional[str] = None
        self._token_expires_at: float = 0.0
        self._cached_credentials: Optional[Dict[str, str]] = None
        self._lock = threading.Lock()

    def get_token(self, force_refresh: bool = False) -> str:
        """Returns a valid GitHub token, proactively refreshing if within 10 minutes of expiry."""
        with self._lock:
            now = time.time()
            if not force_refresh and self._cached_token and (self._token_expires_at - now > 600):
                return self._cached_token

            token, expires_at = self._mint_token()
            self._cached_token = token
            self._token_expires_at = expires_at
            return self._cached_token

    def _get_credentials(self, force_refresh: bool = False) -> Dict[str, str]:
        """Fetches and parses Secret Manager credentials (cached once found)."""
        if not force_refresh and self._cached_credentials is not None:
            if any(self._cached_credentials.values()):
                return self._cached_credentials

        # 1. Check environment variables first
        static_token = os.getenv("GITHUB_TOKEN") or os.getenv("GITHUB_PAT")
        if static_token:
            self._cached_credentials = {
                "app_id": os.getenv("GITHUB_APP_ID", ""),
                "installation_id": os.getenv("GITHUB_INSTALLATION_ID", ""),
                "private_key": os.getenv("GITHUB_APP_PRIVATE_KEY", ""),
                "pat": static_token,
            }
            return self._cached_credentials

        # 2. Secret Manager resolution
        try:
            from google.cloud import secretmanager
            client = secretmanager.SecretManagerServiceClient()
            name = f"projects/{self.project_id}/secrets/castor-github-app-private-key/versions/latest"
            resp = client.access_secret_version(request={"name": name})
            payload_str = resp.payload.data.decode("utf-8").strip()

            clean_str = payload_str.replace("“", '"').replace("”", '"').replace("‘", "'").replace("’", "'")
            clean_str = clean_str.replace("—", "-").replace("–", "-")
            clean_str = re.sub(r'[-—–]{2,}\s*BEGIN\s+([A-Z\s]+)?PRIVATE\s+KEY\s*[-—–]{2,}', '-----BEGIN RSA PRIVATE KEY-----', clean_str)
            clean_str = re.sub(r'[-—–]{2,}\s*END\s+([A-Z\s]+)?PRIVATE\s+KEY\s*[-—–]{2,}', '-----END RSA PRIVATE KEY-----', clean_str)

            # Check for JSON format
            if clean_str.startswith("{") and clean_str.endswith("}"):
                try:
                    data = json.loads(clean_str, strict=False)
                    self._cached_credentials = {
                        "app_id": str(data.get("app_id") or data.get("client_id", "")),
                        "installation_id": str(data.get("installation_id", "")),
                        "private_key": data.get("private_key", "").strip(),
                        "pat": str(data.get("pat") or data.get("personal_access_token") or data.get("github_token", "")).strip(),
                    }
                    return self._cached_credentials
                except Exception:
                    pass

            # Regex parsing fallback
            app_id_match = re.search(r'["\']?app_id["\']?\s*:\s*["\']?(\d+)["\']?', clean_str)
            inst_id_match = re.search(r'["\']?installation_id["\']?\s*:\s*["\']?(\d+)["\']?', clean_str)
            pat_match = re.search(r'["\']?(?:pat|personal_access_token|github_token)["\']?\s*:\s*["\']?([a-zA-Z0-9_]+)["\']?', clean_str)
            pem_match = re.search(r'(-----BEGIN [A-Z\s]+PRIVATE KEY-----[\s\S]+?-----END [A-Z\s]+PRIVATE KEY-----)', clean_str)

            self._cached_credentials = {
                "app_id": app_id_match.group(1) if app_id_match else (os.getenv("GITHUB_APP_ID") or ""),
                "installation_id": inst_id_match.group(1) if inst_id_match else (os.getenv("GITHUB_INSTALLATION_ID") or ""),
                "private_key": pem_match.group(1).strip() if pem_match else clean_str,
                "pat": pat_match.group(1) if pat_match else "",
            }
            return self._cached_credentials
        except Exception as e:
            logger.warning(f"Could not load GitHub credentials from Secret Manager: {e}")
            creds = {
                "app_id": os.getenv("GITHUB_APP_ID", ""),
                "installation_id": os.getenv("GITHUB_INSTALLATION_ID", ""),
                "private_key": os.getenv("GITHUB_APP_PRIVATE_KEY", ""),
                "pat": os.getenv("GITHUB_PAT") or os.getenv("GITHUB_TOKEN", ""),
            }
            if any(creds.values()):
                self._cached_credentials = creds
            return creds

    def _mint_token(self) -> Tuple[str, float]:
        """Mints a 1-hour Installation Access Token via GitHub App RS256 JWT, falling back to static PAT."""
        creds = self._get_credentials()
        app_id = creds.get("app_id") or os.getenv("GITHUB_APP_ID")
        inst_id = creds.get("installation_id") or os.getenv("GITHUB_INSTALLATION_ID")
        private_key = creds.get("private_key")
        pat = creds.get("pat") or os.getenv("GITHUB_PAT") or os.getenv("GITHUB_TOKEN")

        if not private_key or not app_id or not inst_id:
            if pat:
                logger.info("Using static GitHub PAT/token.")
                return pat, time.time() + 86400
            logger.warning("No GitHub App credentials or PAT available.")
            return "", 0.0

        try:
            import jwt
            now = int(time.time())
            payload = {
                "iat": now - 60,
                "exp": now + 600,
                "iss": str(app_id),
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
                token = token_data.get("token", "")

                # Parse expires_at ISO8601 string
                expires_at_str = token_data.get("expires_at", "")
                expires_at_epoch = time.time() + 3600 # default 1 hr
                if expires_at_str:
                    try:
                        clean_iso = expires_at_str.replace("Z", "+00:00")
                        dt = datetime.fromisoformat(clean_iso)
                        expires_at_epoch = dt.timestamp()
                    except Exception:
                        pass

                logger.info(f"Minted 1-hour GitHub JIT token for installation {inst_id} (valid until {expires_at_epoch})")
                return token, expires_at_epoch
        except Exception as e:
            logger.warning(f"Failed to generate GitHub JIT token: {e}")
            if pat:
                return pat, time.time() + 86400
            return "", 0.0


# Module-level singleton
TokenManager = GitHubTokenManager
_default_manager: Optional[GitHubTokenManager] = None
_manager_lock = threading.Lock()


def get_token_manager(project_id: Optional[str] = None) -> GitHubTokenManager:
    """Returns the singleton GitHubTokenManager instance."""
    global _default_manager
    with _manager_lock:
        if _default_manager is None:
            _default_manager = GitHubTokenManager(project_id=project_id)
        elif project_id and not _default_manager.project_id:
            _default_manager.project_id = project_id
        return _default_manager


def get_github_token(project_id: Optional[str] = None, force_refresh: bool = False) -> str:
    """Convenience helper to retrieve a cached, valid GitHub token."""
    mgr = get_token_manager(project_id=project_id)
    return mgr.get_token(force_refresh=force_refresh)


def get_github_client(project_id: Optional[str] = None, token: Optional[str] = None) -> Any:
    """Initializes and returns an authenticated PyGithub client using a cached valid token."""
    from github import Github
    active_token = token or get_github_token(project_id=project_id)
    if not active_token:
        raise RuntimeError("No valid GitHub token could be obtained for PyGithub client.")
    return Github(active_token)


def create_or_verify_branch(
    repo_full_name: str,
    branch_name: str,
    source_branch: str = "main",
    project_id: Optional[str] = None,
    client: Optional[Any] = None,
    token: Optional[str] = None,
    **kwargs: Any,
) -> str:
    """
    Creates a new branch in the given GitHub repository from the HEAD of source_branch.
    If the branch already exists, verifies and returns its commit SHA.
    Uses github_retry_with_backoff to handle rate limits and transient errors.
    """
    clean_branch = branch_name.strip()
    if not clean_branch:
        raise ValueError("branch_name cannot be empty")

    if client:
        gh = client
    elif token:
        from github import Github
        gh = Github(token)
    else:
        gh = get_github_client(project_id=project_id)
    repo = gh.get_repo(repo_full_name)

    @github_retry_with_backoff(max_retries=3, initial_wait=1.0)
    def _ensure_branch():
        # Check if target branch already exists
        try:
            target_ref = repo.get_git_ref(f"heads/{clean_branch}")
            logger.info(f"Branch '{clean_branch}' already exists in '{repo_full_name}' (SHA: {target_ref.object.sha})")
            return target_ref.object.sha
        except Exception:
            # Branch does not exist; fetch source branch HEAD
            source_ref = repo.get_git_ref(f"heads/{source_branch}")
            source_sha = source_ref.object.sha
            logger.info(f"Creating branch '{clean_branch}' from '{source_branch}' (SHA: {source_sha}) in '{repo_full_name}'")
            new_ref = repo.create_git_ref(ref=f"refs/heads/{clean_branch}", sha=source_sha)
            # Settle buffer to allow GitHub's distributed GitRPC fileserver mesh to synchronize the ref
            time.sleep(2.0)
            return new_ref.object.sha

    return _ensure_branch()

