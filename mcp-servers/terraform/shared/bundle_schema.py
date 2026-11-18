"""
Project Castor: Composite Bundles Schema & Contract Engine
Data models for composite multi-module solutions, Git-native ingestion, monorepo scanning, and version drift.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CompositeBundleSourceType(str, Enum):
    BUILTIN = "BUILTIN"
    REMOTE_GIT = "REMOTE_GIT"


class CompositeBundleRecord(BaseModel):
    """Canonical representation of a Composite Solution Bundle."""
    bundle_id: str = Field(description="Unique kebab-case bundle ID (e.g. 'secure-three-tier-web')")
    name: str = Field(description="Human-readable architectural solution name")
    category: str = Field(default="COMPUTE_DATA", description="Solution category (e.g. COMPUTE_DATA, EVENT_DRIVEN, AI_ML, KUBERNETES, ANALYTICS)")
    description: str = Field(default="", description="Architectural summary and components")
    source_type: CompositeBundleSourceType = Field(default=CompositeBundleSourceType.BUILTIN)
    source_url: Optional[str] = Field(default=None, description="GitHub or StackVend Git repository URL or slug")
    repo_path: Optional[str] = Field(default="", description="Subdirectory path in monorepo where bundle lives")
    version_tag: Optional[str] = Field(default="1.0.0", description="Release tag, branch, or semver version")
    commit_sha: Optional[str] = Field(default=None, description="Immutable Git commit SHA at registration time")
    supported_engines: List[str] = Field(default_factory=lambda: ["tofu", "terraform"], description="Supported IaC execution engines")
    default_engine: str = Field(default="tofu", description="Preferred engine (tofu or terraform)")
    modules_included: List[str] = Field(default_factory=list, description="IDs of underlying Golden Modules invoked by this bundle")
    resource_footprint: Dict[str, Any] = Field(default_factory=dict, description="Estimated compute, RAM, subnet, and IP requirements for Quota Preflight")
    default_parameters: Dict[str, Any] = Field(default_factory=dict, description="Default parameters exposed to workload HCL")
    variables: List[Dict[str, Any]] = Field(default_factory=list, description="Extracted inputs and parameter contracts")
    outputs: List[Dict[str, Any]] = Field(default_factory=list, description="Extracted output values exposed to application code")
    hcl_files: Dict[str, str] = Field(default_factory=dict, description="In-tree HCL files (main.tf, variables.tf, outputs.tf)")
    is_active: bool = Field(default=True, description="Whether the bundle is enabled for Architect Agent selection")
    is_builtin: bool = Field(default=False, description="Whether this is a canonical built-in bundle shipped with StackVend")
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class RegisterBundleRequest(BaseModel):
    """Git-native request to link a custom bundle from GitHub or Castor Git."""
    source_url: str = Field(description="Git repository URL or slug (e.g. 'acme-corp/cloud-foundations' or full HTTPS URL)")
    repo_path: Optional[str] = Field(default="", description="Subdirectory in repository (e.g. 'bundles/secure-three-tier-web')")
    version_tag: Optional[str] = Field(default="main", description="Git tag, branch, or commit SHA")
    bundle_id: Optional[str] = Field(default=None, description="Optional override for bundle ID (defaults to folder basename)")
    name: Optional[str] = Field(default=None, description="Optional override for human-readable name")
    auth_token_secret: Optional[str] = Field(default=None, description="Optional Secret Manager key for private repo auth")
    supported_engines: Optional[List[str]] = Field(default=None, description="Optional engine override (['tofu', 'terraform'])")
    override_builtin: Optional[str] = Field(default=None, description="Optional built-in bundle ID to override")


class ScanRepositoryBundlesRequest(BaseModel):
    """Request to scan a monorepo subdirectory for all bundle packages."""
    source_url: str = Field(description="Git repository URL or slug")
    parent_path: Optional[str] = Field(default="bundles", description="Parent directory containing bundles (e.g. 'bundles' or 'solutions')")
    version_tag: Optional[str] = Field(default="main", description="Git ref (tag, branch, or commit SHA)")
    auth_token_secret: Optional[str] = Field(default=None, description="Optional Secret Manager key for private repo auth")


class DiscoveredBundleSummary(BaseModel):
    """Summary of a bundle discovered in a monorepo scan."""
    bundle_id: str
    name: str
    repo_path: str
    has_manifest: bool
    modules_detected: List[str] = Field(default_factory=list)
    supported_engines: List[str] = Field(default_factory=lambda: ["tofu", "terraform"])
    description: str = ""


class BundleDriftStatusResponse(BaseModel):
    """Result of drift inspection comparing vendored bundle against upstream Git."""
    bundle_id: str
    installed_version: str
    latest_version: str
    has_drift: bool
    drift_reason: Optional[str] = None
    commit_sha: Optional[str] = None


class UpdateBundleRequest(BaseModel):
    """Request to update mutable fields of a registered custom bundle."""
    name: Optional[str] = None
    description: Optional[str] = None
    category: Optional[str] = None
    is_active: Optional[bool] = None
    default_parameters: Optional[Dict[str, Any]] = None
    version_tag: Optional[str] = None

