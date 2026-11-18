"""
Project Castor: Dual-Architect Consensus & Red-Team Critique Schemas
Pydantic contracts for adversarial architecture audits, topological cycle checks,
bounded remediation briefs, and Control Center UI telemetry.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CritiqueCategory(str, Enum):
    TOPOLOGY_AND_ORDERING = "TOPOLOGY_AND_ORDERING"
    SPEC_COVERAGE = "SPEC_COVERAGE"
    GOLDEN_MODULES_GROUNDING = "GOLDEN_MODULES_GROUNDING"
    IAM_SECURITY_SEQUENCE = "IAM_SECURITY_SEQUENCE"
    FINOPS_SIZING = "FINOPS_SIZING"


class CritiqueSeverity(str, Enum):
    CRITICAL = "CRITICAL"   # Blocks DAG; triggers targeted remediation
    WARNING = "WARNING"     # Advisory; logged to audit record
    INFO = "INFO"


class CritiqueFinding(BaseModel):
    category: CritiqueCategory = Field(description="Gauntlet evaluation category")
    severity: CritiqueSeverity = Field(description="CRITICAL, WARNING, or INFO")
    step_or_task_id: Optional[str] = Field(default=None, description="Affected step or task ID (e.g. STEP-06-COMPUTE)")
    description: str = Field(description="Adversarial finding details")
    recommended_remediation: str = Field(description="Actionable fix instructions for Architect 1")


class GauntletCheckResult(BaseModel):
    invariant_name: str = Field(description="Invariant title (e.g. 'DAG Topology & Cycles')")
    status: str = Field(default="PASSED", description="'PASSED' | 'WARNING' | 'CRITICAL'")
    details: str = Field(default="", description="Detailed outcome summary")


class ArchitecturalCritique(BaseModel):
    soundness_score: float = Field(default=1.0, ge=0.0, le=1.0, description="Overall DAG soundness score (0.0 to 1.0)")
    has_critical_findings: bool = Field(default=False, description="True if any findings have CRITICAL severity")
    findings: List[CritiqueFinding] = Field(default_factory=list, description="List of discrete audit findings")
    gauntlet_checks: List[GauntletCheckResult] = Field(default_factory=list, description="Results for each of the 5 invariants")
    verdict_summary: str = Field(default="Architectural plan verified without critical defects.", description="Executive critique verdict")


# Telemetry Models for Glass Pane & Flight Deck UI
class ArchitectSubagentTelemetry(BaseModel):
    persona: str = Field(description="'LEAD_ARCHITECT' | 'RED_TEAM_CRITIC' | 'REMEDIATION_TURN'")
    status: str = Field(default="SUCCEEDED", description="'PENDING' | 'RUNNING' | 'SUCCEEDED' | 'FAILED'")
    elapsed_seconds: float = Field(default=0.0, description="Execution duration in seconds")
    output_tokens: int = Field(default=0, description="Approximate or actual output tokens consumed")


class DualArchitectConsensusTelemetry(BaseModel):
    consensus_status: str = Field(
        default="CONSENSUS_VERIFIED",
        description="'CONSENSUS_VERIFIED' | 'AUTO_REMEDIATED' | 'CRITIQUE_FAILED' | 'BYPASSED'",
    )
    soundness_score: float = Field(default=1.0, description="Overall soundness score")
    has_critical_findings: bool = Field(default=False, description="Whether critical faults were detected")
    remediation_performed: bool = Field(default=False, description="True if Architect 1 executed an N=1 patch turn")
    remediation_diff_summary: Optional[str] = Field(default=None, description="Human-readable delta of remediated items")
    subagents: List[ArchitectSubagentTelemetry] = Field(default_factory=list, description="Subagent execution metrics")
    gauntlet_checks: List[GauntletCheckResult] = Field(default_factory=list, description="5-Point Gauntlet checklist results")
    findings: List[CritiqueFinding] = Field(default_factory=list, description="Attributed findings")
