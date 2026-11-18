"""
Project Castor: Workload IaC Module & Bundle Upgrade Engine Schemas
Data models for tracking IaC drift, module/bundle vendoring versions,
deterministic upgrade requests, pre-flight validation status, and audit subcollections.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IaCAssetType(str, Enum):
    BUILTIN_MODULE = "BUILTIN_MODULE"
    CUSTOM_MODULE = "CUSTOM_MODULE"
    BUILTIN_BUNDLE = "BUILTIN_BUNDLE"
    CUSTOM_BUNDLE = "CUSTOM_BUNDLE"



class IaCModuleStatus(BaseModel):
    name: str = Field(description="Module directory name or identifier (e.g. compute-cloudrun, networking-vpc, acme-custom)")
    type: str = Field(default=IaCAssetType.BUILTIN_MODULE.value, description="BUILTIN_MODULE, CUSTOM_MODULE, or CUSTOM_BUNDLE")
    current_version: Optional[str] = Field(default=None, description="Current recorded version tag or commit SHA")
    latest_version: Optional[str] = Field(default=None, description="Upstream latest version tag or commit SHA")
    current_sha256: Optional[str] = Field(default=None, description="SHA-256 content hash of vendored module files in child repo")
    latest_sha256: Optional[str] = Field(default=None, description="SHA-256 content hash of latest upstream canonical module files")
    drift_detected: bool = Field(default=False, description="True if content hashes or version tags differ")
    source: str = Field(default="infra/modules", description="Canonical source location or git repository URL")
    changed_files: List[str] = Field(default_factory=list, description="List of file paths that differ between vendored and upstream")


class IaCDriftStatusResponse(BaseModel):
    workload_id: str
    drift_detected: bool = Field(default=False, description="True if any vendored module or bundle has drifted")
    modules: List[IaCModuleStatus] = Field(default_factory=list, description="Status of all vendored modules")
    total_modules: int = 0
    outdated_modules: int = 0
    last_upgrade_at: Optional[str] = None
    last_upgrade_by: Optional[str] = None
    last_upgrade_status: Optional[str] = None


class IaCUpgradeRecord(BaseModel):
    upgrade_id: str
    workload_id: str
    triggered_at: str
    triggered_by: str = "Operator"
    status: str = Field(default="IN_PROGRESS", description="IN_PROGRESS, SUCCESS, FAILED, ROLLED_BACK")
    updated_modules: List[str] = Field(default_factory=list)
    pr_number: Optional[int] = None
    pr_url: Optional[str] = None
    commit_sha: Optional[str] = None
    validation_error: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


class IaCUpgradeHistoryResponse(BaseModel):
    workload_id: str
    upgrades: List[IaCUpgradeRecord] = Field(default_factory=list)


class TriggerIaCUpgradeRequest(BaseModel):
    author: Optional[str] = Field(default="Operator", description="User or service triggering the upgrade")
    modules_to_upgrade: Optional[List[str]] = Field(default=None, description="Specific module names to upgrade, or None/empty for all drifted")
