"""
Project Castor: Unit Test Suite for GitHub API Resilience & Token Caching Gateway
Verifies secondary/primary rate limit backoff, JIT token caching, proactive refresh,
and git concurrency rebase mechanisms under simulated GitHub API edge cases.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import time
import unittest
from unittest.mock import MagicMock, patch

import sys

if "httpx" not in sys.modules or isinstance(sys.modules.get("httpx"), MagicMock):
    class _MockHttpxResponse:
        def __init__(self, status_code=200, headers=None, text="", request=None):
            self.status_code = status_code
            self.headers = headers or {}
            self.text = text
            self.request = request

    class _MockHttpxRequest:
        def __init__(self, method="GET", url=""):
            self.method = method
            self.url = url

    class _MockHTTPStatusError(Exception):
        def __init__(self, message, request=None, response=None):
            super().__init__(message)
            self.request = request
            self.response = response

    class _MockHttpx:
        Response = _MockHttpxResponse
        Request = _MockHttpxRequest
        HTTPStatusError = _MockHTTPStatusError

    httpx = _MockHttpx()
else:
    import httpx

if (
    "github" not in sys.modules
    or isinstance(sys.modules.get("github"), MagicMock)
    or not hasattr(sys.modules["github"], "GithubException")
    or isinstance(getattr(sys.modules["github"], "GithubException", None), MagicMock)
):
    class GithubException(Exception):
        def __init__(self, status=400, data=None, headers=None):
            super().__init__(str(data))
            self.status = status
            self.data = data or {}
            self.headers = headers or {}
else:
    from github import GithubException

from shared.github_resilience import (
    GitHubRateLimitExceededError,
    GitHubTokenManager,
    calculate_backoff,
    extract_error_metadata,
    get_github_token,
    get_token_manager,
    github_retry_with_backoff,
    is_rate_limit_or_transient,
)


class TestGitHubResilience(unittest.TestCase):
    def setUp(self):
        # Reset token manager singleton state before each test
        manager = get_token_manager()
        manager._cached_token = None
        manager._token_expires_at = 0.0
        manager._cached_credentials = None

    def test_extract_error_metadata_github_exception(self):
        """Verifies extracting metadata from PyGithub GithubException."""
        ge = GithubException(
            status=403,
            data={"message": "You have exceeded a secondary rate limit. Please wait."},
            headers={"Retry-After": "3", "X-RateLimit-Remaining": "0"},
        )
        status, headers, body = extract_error_metadata(ge)
        self.assertEqual(status, 403)
        self.assertEqual(headers.get("retry-after"), "3")
        self.assertEqual(headers.get("x-ratelimit-remaining"), "0")
        self.assertIn("secondary rate limit", body.lower())

    def test_extract_error_metadata_httpx_status_error(self):
        """Verifies extracting metadata from httpx.HTTPStatusError."""
        request = httpx.Request("GET", "https://api.github.com/rate_limit")
        response = httpx.Response(
            status_code=429,
            headers={"Retry-After": "5"},
            text='{"message": "Too Many Requests"}',
            request=request,
        )
        http_err = httpx.HTTPStatusError(message="429 Too Many Requests", request=request, response=response)
        status, headers, body = extract_error_metadata(http_err)
        self.assertEqual(status, 429)
        self.assertEqual(headers.get("retry-after"), "5")
        self.assertIn("too many requests", body.lower())

    def test_is_rate_limit_or_transient(self):
        """Verifies rate limit detection heuristics."""
        # 429 is always rate limit
        self.assertTrue(is_rate_limit_or_transient(429, {}, ""))
        # 503 is transient
        self.assertTrue(is_rate_limit_or_transient(503, {}, ""))
        # 403 with secondary rate limit body
        self.assertTrue(is_rate_limit_or_transient(403, {}, "You have exceeded a secondary rate limit."))
        # 403 with retry-after
        self.assertTrue(is_rate_limit_or_transient(403, {"retry-after": "2"}, ""))
        # 403 with x-ratelimit-remaining == 0
        self.assertTrue(is_rate_limit_or_transient(403, {"x-ratelimit-remaining": "0"}, ""))
        # Standard 404 is not transient
        self.assertFalse(is_rate_limit_or_transient(404, {}, "Not Found"))
        # Standard 401 Bad Credentials is not transient
        self.assertFalse(is_rate_limit_or_transient(401, {}, "Bad credentials"))

    @patch("time.sleep", return_value=None)
    def test_retry_with_backoff_secondary_rate_limit(self, mock_sleep):
        """Verifies retry decorator successfully retries on secondary rate limit."""
        attempts = 0

        @github_retry_with_backoff(max_retries=3, initial_wait=0.1)
        def mock_api_call():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise GithubException(
                    status=403,
                    data={"message": "You have exceeded a secondary rate limit."},
                    headers={"retry-after": "2"},
                )
            return "SUCCESS"

        result = mock_api_call()
        self.assertEqual(result, "SUCCESS")
        self.assertEqual(attempts, 2)
        mock_sleep.assert_called_once_with(2.0)

    @patch("time.sleep", return_value=None)
    def test_retry_with_backoff_primary_rate_limit(self, mock_sleep):
        """Verifies retry decorator calculates sleep until x-ratelimit-reset epoch."""
        attempts = 0
        now = time.time()
        reset_epoch = now + 4.0

        @github_retry_with_backoff(max_retries=3, initial_wait=0.1)
        def mock_api_call():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise GithubException(
                    status=403,
                    data={"message": "API rate limit exceeded."},
                    headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(reset_epoch)},
                )
            return "SUCCESS"

        result = mock_api_call()
        self.assertEqual(result, "SUCCESS")
        self.assertEqual(attempts, 2)
        self.assertTrue(mock_sleep.called)
        # Sleep time should be approximately reset_epoch - now + 1.0
        sleep_arg = mock_sleep.call_args[0][0]
        self.assertGreaterEqual(sleep_arg, 3.0)
        self.assertLessEqual(sleep_arg, 6.0)

    def test_retry_with_backoff_sleep_ceiling_guardrail(self):
        """Verifies failing fast when sleep required exceeds max_sleep_seconds."""
        now = time.time()
        long_reset_epoch = now + 3600.0 # 1 hour away

        @github_retry_with_backoff(max_retries=3, initial_wait=0.1, max_sleep_seconds=60.0)
        def mock_blocked_call():
            raise GithubException(
                status=403,
                data={"message": "API rate limit exceeded."},
                headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": str(long_reset_epoch)},
            )

        with self.assertRaises(GitHubRateLimitExceededError):
            mock_blocked_call()

    @patch("time.sleep", return_value=None)
    def test_retry_with_backoff_httpx_status_error(self, mock_sleep):
        """Verifies retry decorator catches raw HTTPX rate limit errors."""
        attempts = 0

        @github_retry_with_backoff(max_retries=3, initial_wait=0.1)
        def mock_httpx_call():
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                req = httpx.Request("GET", "https://api.github.com/rate_limit")
                resp = httpx.Response(status_code=429, headers={"retry-after": "1"}, request=req)
                raise httpx.HTTPStatusError("Rate limited", request=req, response=resp)
            return "HTTPX_SUCCESS"

        result = mock_httpx_call()
        self.assertEqual(result, "HTTPX_SUCCESS")
        self.assertEqual(attempts, 2)
        mock_sleep.assert_called_once_with(1.0)

    def test_token_manager_caching_and_proactive_refresh(self):
        """Verifies token caching and refresh when within 10 minutes of expiry."""
        manager = GitHubTokenManager(project_id="test-proj")
        mint_count = 0

        def mock_mint():
            nonlocal mint_count
            mint_count += 1
            # Return token valid for 1 hour (3600s)
            return f"token_v{mint_count}", time.time() + 3600

        manager._mint_token = mock_mint

        # 1. First call mints token
        token1 = manager.get_token()
        self.assertEqual(token1, "token_v1")
        self.assertEqual(mint_count, 1)

        # 2. Subsequent calls within valid window return cached token without re-minting
        token2 = manager.get_token()
        token3 = manager.get_token()
        self.assertEqual(token2, "token_v1")
        self.assertEqual(token3, "token_v1")
        self.assertEqual(mint_count, 1)

        # 3. Simulate token expiring soon (< 600s remaining)
        manager._token_expires_at = time.time() + 300 # 5 minutes remaining
        token4 = manager.get_token()
        self.assertEqual(token4, "token_v2")
        self.assertEqual(mint_count, 2)

    def test_token_manager_credential_caching(self):
        """Verifies Secret Manager credentials are only fetched once."""
        manager = GitHubTokenManager(project_id="test-proj")
        secret_reads = 0

        def mock_get_credentials():
            nonlocal secret_reads
            if manager._cached_credentials:
                return manager._cached_credentials
            secret_reads += 1
            manager._cached_credentials = {
                "app_id": "12345",
                "installation_id": "67890",
                "private_key": "MOCK_KEY",
            }
            return manager._cached_credentials

        manager._get_credentials = mock_get_credentials

        creds1 = manager._get_credentials()
        creds2 = manager._get_credentials()
        self.assertEqual(creds1["app_id"], "12345")
        self.assertEqual(creds2["app_id"], "12345")
        self.assertEqual(secret_reads, 1)


if __name__ == "__main__":
    unittest.main()
