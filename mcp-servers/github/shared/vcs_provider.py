"""
Project Castor: Universal VCS Gateway (`VCSProvider`)
Abstract Strategy & Factory interface for Version Control System providers.
Decouples Castor from hardcoded GitHub dependencies, enabling seamless support
for GitHub, Serverless Git (Cloud Run + GCS), and future enterprise SCMs.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
import io
import os
from typing import Any, BinaryIO, Dict, List, Optional, Sequence

# FD-12: author e-mail of platform-made commits. Set STACKVEND_GIT_AUTHOR_EMAIL per install; the default is a
# non-routable RFC 2606 `.invalid` address, so no third party can own it.
DEFAULT_AGENT_AUTHOR_EMAIL = os.getenv("STACKVEND_GIT_AUTHOR_EMAIL") or "stackvend-agent@noreply.invalid"

try:
    from pydantic import BaseModel, Field
except ImportError:
    class BaseModel:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
        def dict(self) -> Dict[str, Any]:
            return {k: v for k, v in self.__dict__.items() if not k.startswith('_')}
        def model_dump(self) -> Dict[str, Any]:
            return self.dict()


class RepositoryMetadata(BaseModel):
    provider: str                     # "GITHUB", "SERVERLESS_GIT", etc.
    repo_name: str                    # "castor-example-workload"
    full_name: str                    # "example-org/castor-example-workload"
    html_url: str                     # Web browser URL for human operators
    clone_url_http: str               # HTTPS clone URL
    clone_url_ssh: Optional[str] = None
    default_branch: str = "main"
    is_reused: bool = False
    ui_icon: str = "📦"               # "🐙" (GitHub), "☁️" (Serverless Git)


class PipelineConfig(BaseModel):
    pipeline_type: str                # "GITHUB_ACTIONS", "CLOUD_BUILD", "GITLAB_CI"
    target_file: str                  # ".github/workflows/deploy-<service>.yml", "cloudbuild.yaml"
    template_content: str             # Base template string with variables
    content: Optional[str] = None

    def __init__(self, **data: Any):
        if "content" not in data and "template_content" in data:
            data["content"] = data["template_content"]
        elif "template_content" not in data and "content" in data:
            data["template_content"] = data["content"]
        super().__init__(**data)


@dataclass(frozen=True)
class PRIdentity:
    """FD-4P / FD-4BB: the exact identity of a branch / pull request StackVend created, as written to the PR ledger
    (shared/vcs_ledger.py) at creation time. A provider may merge, close or delete ONLY what matches every field
    (exact equality; GitHub names compared case-insensitively, numeric repository ids exactly)."""
    provider: str                      # "GITHUB" | "SERVERLESS_GIT"
    repo_full_name: str                # "owner/repo" (GitHub) or the git-server repo identifier
    branch: str                        # exact head ref StackVend pushed
    base_branch: str                   # exact base ref the PR targets
    head_sha: str                      # the commit StackVend pushed (what QA certified and what a merge pins)
    pr_number: Optional[int] = None    # GitHub PR number from the PR-creation API response (never parsed)
    repo_id: Optional[int] = None      # GitHub numeric repository id (stable across renames)


class PRIdentityMismatch(RuntimeError):
    """The live PR/branch does not match the ledger identity. Nothing was merged, closed or deleted."""

    def __init__(self, field: str, expected: Any, actual: Any):
        super().__init__(f"PR identity mismatch on {field}: expected {expected!r}, found {actual!r}")
        self.field, self.expected, self.actual = field, expected, actual


class IncompleteRepoTreeError(RuntimeError):
    """FD-4D: `fetch_file_tree(..., require_complete=True)` could not read the whole branch.

    ``tree_status`` is the provider's ``last_tree_status`` dict ({"complete", "truncated", "error"}): truncated
    (more files than ``max_files``, or the API's own truncated flag) or errored (rate limit, timeout, any
    exception). It is not named ``status``: github_resilience reads an int ``status`` as an HTTP code to retry on.
    FD-4DC: ``error_class`` is the typed class every reader reports (the deploy's operator-routed class).
    """

    error_class = "REPO_TREE_INCOMPLETE"

    def __init__(self, repo: str, branch: str, tree_status: Dict[str, Any]):
        self.repo, self.branch, self.tree_status = repo, branch, dict(tree_status or {})
        reason = "truncated" if self.tree_status.get("truncated") else (self.tree_status.get("error") or "not complete")
        super().__init__(f"repository tree of '{repo}' ({branch}) could not be read completely: {reason}")


class PRMergeNotCompleted(RuntimeError):
    """The provider was asked to merge a verified PR and reported that it did not merge it."""


class VCSProvider(ABC):
    """Abstract Strategy interface for all Version Control System providers."""

    # --------------------------------------------------------------------------
    # 1. Repository Lifecycle & Metadata
    # --------------------------------------------------------------------------
    @abstractmethod
    def vend_repository(
        self,
        product_id: str,
        description: str = "",
        initial_branch: str = "main",
        auto_protect_branch: bool = True,
        **kwargs: Any,
    ) -> RepositoryMetadata:
        """Initializes a new code repository with initial README, .gitignore, and branch protection."""
        pass

    @abstractmethod
    def get_repository_metadata(self, repo_identifier: str) -> RepositoryMetadata:
        """Resolves browser URLs, clone URLs, and default branch for a given repository."""
        pass

    # --------------------------------------------------------------------------
    # 2. Branch & Reference Management
    # --------------------------------------------------------------------------
    @abstractmethod
    def create_or_verify_branch(
        self,
        repo_identifier: str,
        branch_name: str,
        source_branch: str = "main",
    ) -> str:
        """Verifies or initializes an environment branch (stage, prod) from a source branch."""
        pass

    @abstractmethod
    def get_authenticated_clone_url(
        self,
        repo_identifier: str,
        branch: str = "main",
    ) -> str:
        """
        Generates an authenticated HTTPS clone URL (with embedded JIT token or IAM credentials)
        for sandbox runners (e.g. apps/qa-runner) to execute `git clone`.
        """
        pass

    # --------------------------------------------------------------------------
    # 3. Code Ingestion & Streaming (Memory Safe)
    # --------------------------------------------------------------------------
    @abstractmethod
    def fetch_file_content(
        self,
        repo_identifier: str,
        file_path: str,
        branch: str = "main",
    ) -> str:
        """Fetches a single file's UTF-8 text content."""
        pass

    @abstractmethod
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
        Excludes non-code binaries (.png, .jpg, .ico, .tar.gz).
        FD-4D: require_complete=True raises IncompleteRepoTreeError instead of returning a truncated or
        errored tree; the default (False) returns whatever was read and records it in `last_tree_status`.
        """
        pass

    @abstractmethod
    def export_archive_stream(
        self,
        repo_identifier: str,
        branch: str = "main",
    ) -> BinaryIO:
        """
        Streams a .tar.gz archive directly from the provider.
        Prevents container OOM when staging source code for Cloud Build / Cloud Run.
        """
        pass

    # --------------------------------------------------------------------------
    # 4. Atomic Commits & Pull Requests
    # --------------------------------------------------------------------------
    @abstractmethod
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
        """Creates an atomic Git commit with the provided files and returns the new commit SHA.

        FD-4DC-e: `files_to_delete` (exact file paths) are removed in the same commit. A provider that cannot delete
        raises; it never commits the files and silently keeps the paths it was asked to delete."""
        pass

    @abstractmethod
    def get_diff(
        self,
        repo_identifier: str,
        base_branch: str,
        target_branch: str,
    ) -> Dict[str, Any]:
        """Generates unified diff text comparing two branches."""
        pass

    @abstractmethod
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
        """Opens a Pull Request."""
        pass

    @abstractmethod
    def reconcile_automated_pull_requests(
        self,
        repo_identifier: str,
        *,
        superseded: Sequence[PRIdentity],
        comment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        FD-4P: closes exactly the superseded StackVend PRs named by the PR ledger (`superseded`), each only if the live
        PR still matches its ledger identity (same repo, no fork, same head ref/base ref/head SHA). It never lists PRs
        or branches and never matches by name, prefix, label or body text, so human PRs, forks and other products'
        PRs are unreachable. Returns one result per identity (SUPERSEDED / DIVERGED / SKIPPED / ERROR).
        """
        pass

    @abstractmethod
    def merge_pull_request(self, repo_identifier: str, **kwargs: Any) -> Dict[str, Any]:
        """
        FD-4BB: merges exactly one StackVend-created change. GitHub: keyword-only `expected: PRIdentity` (from the PR
        ledger); the live PR must match it exactly (no PR-number guess, no branch-name lookup, no direct branch merge).
        Serverless Git: `source_branch` / `target_branch` taken from the ledger entry by the caller.
        """
        pass

    # --------------------------------------------------------------------------
    # 5. CI/CD Pipeline Contracts & Pre-Commit Validation
    # --------------------------------------------------------------------------
    @abstractmethod
    def get_pipeline_contract(self, service_name: str, product_id: str) -> PipelineConfig:
        """Returns the specific CI/CD file path and template expected for this provider."""
        pass

    @abstractmethod
    def validate_pipeline_content(self, file_path: str, content: str) -> None:
        """Validates pipeline syntax (e.g. GitHub Actions ${{ }}, Cloud Build)."""
        pass


class VCSProviderFactory:
    """Lean, statically typed factory resolving active VCS provider without runtime bloat."""

    @staticmethod
    def get_provider(
        provider_name: Optional[str] = None,
        settings: Optional[Any] = None,
        **kwargs: Any,
    ) -> VCSProvider:
        """
        Resolves active provider following strict precedence:
        1. Explicit workload-level parameter (from Firestore workload document)
        2. Global platform settings (from Firestore system_config/platform_settings)
        3. Environment variable (VCS_PROVIDER)
        4. Default fallback: 'GITHUB'
        """
        if settings is None:
            try:
                from shared.settings import get_platform_settings
                settings = get_platform_settings()
            except Exception:
                try:
                    from .settings import get_platform_settings
                    settings = get_platform_settings()
                except Exception:
                    pass

        # Auto-detect provider if not explicitly specified
        if not provider_name:
            owner = kwargs.get("default_owner") or kwargs.get("owner")
            repo = kwargs.get("repo_name") or kwargs.get("full_repo_name") or kwargs.get("repo_identifier")
            if (owner and "serverless-git" in str(owner).lower()) or (repo and "serverless-git" in str(repo).lower()):
                provider_name = "SERVERLESS_GIT"
            else:
                product_id = kwargs.get("product_id")
                if product_id:
                    try:
                        from google.cloud import firestore
                        _proj = kwargs.get("project_id") or (settings.project_id if settings else None) or os.getenv("PROJECT_ID")
                        db = firestore.Client(project=_proj) if _proj else firestore.Client()
                        doc = db.collection("workloads").document(str(product_id).strip()).get()
                        if doc.exists:
                            wdata = doc.to_dict() or {}
                            if wdata.get("vcs_provider"):
                                provider_name = wdata.get("vcs_provider")
                            elif wdata.get("github_repo") and "serverless-git" in str(wdata.get("github_repo")).lower():
                                provider_name = "SERVERLESS_GIT"
                    except Exception:
                        pass

        raw_name = (
            provider_name
            or getattr(settings, "vcs_provider", None)
            or getattr(getattr(settings, "governance", None), "vcs_provider", None)
            or os.getenv("VCS_PROVIDER")
            or "GITHUB"
        ).strip().upper()

        if raw_name == "GITHUB":
            from .providers.github_provider import GitHubProvider
            return GitHubProvider(settings=settings, **kwargs)

        elif raw_name == "SERVERLESS_GIT":
            from .providers.serverless_git_provider import ServerlessGitProvider
            return ServerlessGitProvider(settings=settings, **kwargs)
        else:
            raise ValueError(
                f"Unsupported VCS provider '{raw_name}'. Supported: GITHUB, SERVERLESS_GIT."
            )
