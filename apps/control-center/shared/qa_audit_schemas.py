"""
Project Castor: Autonomous QA Gatekeeper & Dual-Lens Audit Schemas
Pydantic contracts for deterministic CI gates, security & contextual ingress analysis,
Task DAG adherence scoring, and certified release gatekeeper decisions.
"""

from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

# FD-4F A12: every pass/fail field defaults to False ("not verified"). A report that omits a check can never
# read as a pass; producers set each verdict explicitly. The 5 copies are byte-identical
# (tests/test_fd4f_fail_closed_remainders.py::test_qa_audit_schema_copies_are_byte_identical).
# QA-RECORD-HCL-FIELD (owner 11-14): `hcl_syntax_passed` is None ("not checked by this report") unless a producer
# checked HCL. QA does not parse HCL (the pre-commit gate validates it), so a stored `false` beside `hcl_errors: []`
# read as a failed check that never ran. None is never a pass (only True is), so nothing reads it as one.


class DeterministicGateReport(BaseModel):
    """Stage 1: Deterministic Machine Barrier evaluation report."""
    passed: bool = Field(description="True if all deterministic checks succeeded with zero blocking issues")
    pytest_success: bool = Field(default=False, description="True if pytest exited with return code 0")
    pytest_passed_count: int = Field(default=0, description="Count of passed unit tests")
    pytest_failed_count: int = Field(default=0, description="Count of failed unit tests")
    coverage_percentage: float = Field(default=100.0, description="Calculated test coverage percentage")
    bandit_passed: bool = Field(default=False, description="True if zero HIGH/MEDIUM Bandit vulnerabilities found")
    bandit_issues: List[str] = Field(default_factory=list, description="Bandit security scan issue summaries")
    hcl_syntax_passed: Optional[bool] = Field(default=None, description="True if all .tf files parse validly; "
                                              "None if this report's producer did not check HCL")
    hcl_errors: List[str] = Field(default_factory=list, description="HCL syntax or block parsing errors")
    zero_dockerfile_passed: bool = Field(default=False, description="True if zero Dockerfiles exist (Google Cloud Buildpacks mandate)")
    zero_dockerfile_violations: List[str] = Field(default_factory=list, description="Violations of Zero-Dockerfile policy")
    ast_syntax_passed: bool = Field(default=False, description="True if all Python files pass AST syntax parsing")
    ast_syntax_errors: List[str] = Field(default_factory=list, description="Python AST syntax errors")
    git_diff_pruned: str = Field(default="", description="Sanitized, token-bounded unified Git diff")
    files_inspected: List[str] = Field(default_factory=list, description="Relative paths of inspected files")
    execution_time_seconds: float = Field(default=0.0, description="Stage 1 execution duration in seconds")
    summary: str = Field(default="", description="Deterministic barrier outcome summary")


class SecurityLensResult(BaseModel):
    """Stage 2, Lens A: Security & Contextual Ingress Auditor report."""
    lens_name: str = Field(default="SECURITY_AND_INGRESS", description="Identifier for Lens A")
    passed: bool = Field(default=False, description="True if 0 critical vulnerabilities and policy compliant")
    critical_vulnerabilities: List[str] = Field(default_factory=list, description="Blocking security defects")
    moderate_vulnerabilities: List[str] = Field(default_factory=list, description="Advisory security defects")
    compliance_flags: List[str] = Field(default_factory=list, description="Regulatory and policy compliance flags")
    summary: str = Field(default="Security audit passed with no critical defects.", description="Security lens summary")
    eval_judge_model: str = Field(default="gemini-3.7-flash", description="Model or heuristic used for evaluation")


class AdherenceLensResult(BaseModel):
    """Stage 2, Lens B: Task DAG & Spec Adherence Auditor report."""
    lens_name: str = Field(default="TASK_DAG_ADHERENCE", description="Identifier for Lens B")
    instruction_adherence_score: float = Field(default=1.0, ge=0.0, le=1.0, description="Task DAG acceptance criteria adherence (0.0 - 1.0)")
    grounding_score: float = Field(default=1.0, ge=0.0, le=1.0, description="Technical grounding and lack of hallucinated packages (0.0 - 1.0)")
    passed: bool = Field(default=False, description="True if adherence >= 0.95, grounding >= 0.95, and 0 missed directives")
    missed_directives: List[str] = Field(default_factory=list, description="Omitted task criteria or required components")
    hallucinated_features: List[str] = Field(default_factory=list, description="Unmandated libraries or endpoints added")
    summary: str = Field(default="Implementation strictly adheres to Task DAG specification.", description="Adherence lens summary")
    eval_judge_model: str = Field(default="gemini-3.7-flash", description="Model or heuristic used for evaluation")


class CompositeAuditReport(BaseModel):
    """Composite Stage 1 + Stage 2 unified verification outcome for Step 5 QA."""
    passed: bool = Field(description="True if Stage 1 AND Stage 2 passed completely")
    deterministic_gate: DeterministicGateReport
    security_lens: SecurityLensResult
    adherence_lens: AdherenceLensResult
    overall_soundness_score: float = Field(default=1.0, ge=0.0, le=1.0)
    blocking_reasons: List[str] = Field(default_factory=list, description="Aggregated blocking defects")
    summary: str = Field(default="Composite QA & Dual-Lens verification succeeded.")
    executed_at: str = Field(default="", description="ISO-8601 timestamp")


class ReleaseGateDecision(BaseModel):
    """Stage 3: Lead Release Gatekeeper decision report."""
    is_approved: bool = Field(description="True if release is certified and approved for merge")
    requires_human_intervention: bool = Field(description="True if human operator review is required")
    deterministic_passed: bool = Field(default=True)
    security_clean: bool = Field(default=True)
    adherence_score: float = Field(default=1.0)
    grounding_score: float = Field(default=1.0)
    blocking_reasons: List[str] = Field(default_factory=list)
    release_certificate_markdown: str = Field(default="")
    recommended_action: Literal["AUTO_MERGE", "BLOCK_FOR_HITL_REVIEW", "AUTO_REJECT"] = Field(
        default="BLOCK_FOR_HITL_REVIEW"
    )
    certified_at: str = Field(default="", description="ISO-8601 timestamp")
