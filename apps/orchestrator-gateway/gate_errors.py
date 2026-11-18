"""
FD-4F: typed gate outcomes shared by every pipeline gate in the gateway.

error_class contract (shared with lane 8 / FD-53, see docs/implemented/wave2-lane13-fd4f-hardened-plan.md §3):
- CODE_DEFECT       the gate ran and the generated code failed it. The only class that may loop back to the
                    developer, and it carries structured diagnostics.
- GATE_UNAVAILABLE  the gate could not run (tool/API/LLM/config missing, timeout). Never a pass, never retried
                    by regeneration: the run stops (DLQ).
- PLATFORM_DEFECT   the gate ran and found a platform-side integrity problem (non-idempotent cure, branch moved
                    under the pipeline, defect on a platform-owned path). Stops the run; an LLM retry cannot fix it.

Lane 17 (FD-4AJ / FD-4R / FD-4AG, plan docs/planning/wave2-lane17-workflow-integrity-plan.md section 3) adds the
workflow-level vocabulary. The workflow's single failure handler lifts `error_class` / `stage` / `reason` from a
typed gateway body unchanged (RT F4), so the DLQ record and pipeline_executions/{trace} carry the real class:
- POLICY_REJECTED          a human rejected (plan, PR, quota gate) or a DEPLOY_ONLY branch is not allowed (403)
- GATE_TIMEOUT             an await_callback timed out (workflow)
- KILL_SWITCH_ACTIVE       the platform emergency stop is on (409)
- CONTRACT_VIOLATION       missing field / unknown status / record mismatch (409/422)
- OPERATOR_ACTION_REQUIRED the gateway refused a developer re-dispatch for a non-remediable terraform class (409)
- STATE_LOCKED / DEPLOY_TIMEOUT / IAC_DEFECT / DEPLOY_FAILED   deploy outcomes (tf-applier / workflow)
- RELEASE_FAILED / MAIN_MOVED   release refusals (lane 16 contract)
- DEPENDENCY_FAILED        an HTTP error with no typed body (workflow handler)
- UNHANDLED                anything else (workflow handler)

PRIVATE-INGRESS-EARLY-STOP (owner 11-08): COMPLIANCE.PRIVATE_INGRESS_UNSUPPORTED (409, stage `compliance`): the
compliance decision requires internal-only ingress and the plan has a Cloud Run service, which this release cannot make
internal-only. Stops the run before vending; only the operator can resolve it (change the requirement or use IAM only).
"""

from enum import Enum
from typing import Any, Dict, List, Optional


class ErrorClass(str, Enum):
    CODE_DEFECT = "CODE_DEFECT"
    GATE_UNAVAILABLE = "GATE_UNAVAILABLE"
    PLATFORM_DEFECT = "PLATFORM_DEFECT"
    # lane 10 (FD-51): the architect's typed output (service_topology) is still invalid after its one bounded
    # repair (shared.diagnostics.ErrorClass.ARCHITECT_DEFECT, HTTP 422). Stops the run (DLQ); never a developer retry.
    ARCHITECT_DEFECT = "ARCHITECT_DEFECT"
    # lane 17 (workflow integrity)
    POLICY_REJECTED = "POLICY_REJECTED"
    GATE_TIMEOUT = "GATE_TIMEOUT"
    KILL_SWITCH_ACTIVE = "KILL_SWITCH_ACTIVE"
    CONTRACT_VIOLATION = "CONTRACT_VIOLATION"
    RELEASE_FAILED = "RELEASE_FAILED"
    MAIN_MOVED = "MAIN_MOVED"
    OPERATOR_ACTION_REQUIRED = "OPERATOR_ACTION_REQUIRED"
    STATE_LOCKED = "STATE_LOCKED"
    DEPLOY_TIMEOUT = "DEPLOY_TIMEOUT"
    IAC_DEFECT = "IAC_DEFECT"
    DEPLOY_FAILED = "DEPLOY_FAILED"
    DEPENDENCY_FAILED = "DEPENDENCY_FAILED"
    UNHANDLED = "UNHANDLED"
    COMPLIANCE_PRIVATE_INGRESS_UNSUPPORTED = "COMPLIANCE.PRIVATE_INGRESS_UNSUPPORTED"
    # STAGE-DEADLINE (owner 11-13, stage_deadline.py): the stage's budget ran out before it finished (HTTP 504); the
    # body carries the stage and a progress summary. Stops the run (DLQ); never CODE_DEFECT, never a developer retry.
    STAGE_DEADLINE_EXCEEDED = "STAGE_DEADLINE_EXCEEDED"
    # STAGE-DEADLINE: the stage stopped because its run ended, was superseded by a newer job for the same stage, or
    # the emergency stop is on (409). Nothing is committed after it.
    STAGE_ABANDONED = "STAGE_ABANDONED"
    # LONG-STAGE-CALLBACK (owner 11-13, stage_jobs.py): the gateway instance running a stage job is shutting down
    # (SIGTERM: scale-in, new revision); the job stops and its callback reports this class (503).
    STAGE_INTERRUPTED = "STAGE_INTERRUPTED"
    # LONG-STAGE-CALLBACK: the workflow's await_callback for a stage job timed out (workflow-side, no gateway answer).
    STAGE_TIMEOUT = "STAGE_TIMEOUT"


# Terraform deploy classes that only an operator can resolve: never routed to developer remediation (AJ-14, F6).
# IAC_DEFECT (and, during the lane 6 transition, an empty class) is the only remediable deploy class.
NON_REMEDIABLE_DEPLOY_CLASSES = frozenset({
    "STATE_LOCKED", "DEPLOY_TIMEOUT", "QUOTA_EXHAUSTED", "GCE_STOCKOUT", "PERMISSION_DENIED", "DESTROY_BLOCKED",
    "DESTROY_REQUIRES_APPROVAL",  # settings-toggles: require_hitl_for_destructive_tf (an operator decision)
    "REPO_TREE_INCOMPLETE",  # FD-4D-c: the repository could not be read completely (rate limit, timeout, > 2500 files)
    "APPLY_CONTENT_POLICY",  # FD-4AW-b-r: the plan breaks the platform content policy (nothing was applied)
    "PROVIDER_NOT_ALLOWED",  # FD-4AQ W1b (AQ-6): init refused a provider outside the allow-list (config or state)
    "TOFU_TIMEOUT",  # TOFU-TIMEOUT-OP: an OpenTofu command ran past its time limit (AQ-5) and was interrupted
    "WORKFLOW_INVALID",  # FD55-W6c: a committed workflow file fails the workflow validator (APPLY.WORKFLOW_INVALID)
})
# Parity: equals the operator list in workflows/main_orchestrator.yaml check_deploy_status
# (tests/test_fd4dc_deploy_success_word.py::test_gateway_non_remediable_set_equals_the_workflow_operator_list).
# WF-OPERATOR-FLAG: a deploy result with `operator_required: true` (exactly the boolean) is non-remediable too,
# whatever its class, in the workflow and in the gateway's remediation guard (tests/test_wf_operator_flag.py).

# DEPLOY-FAILURE-OWNER-ROUTER (owner 11-13; docs/planning/deploy-failure-owner-router-plan.md): the terraform server
# records who can change what made a deploy fail at pipeline_executions/{trace}.stages.terraform.failure_route
# (mcp-servers/terraform/deploy_failure_router.py; parity test tests/test_deploy_failure_owner_router.py). The
# automatic remediation loop (tf_retry_count >= 1) is an ALLOW-list: the developer is dispatched only when that route's
# owner is DEPLOY_OWNER_DEVELOPER and its error_sha256 equals sha256 of the dispatch's tf_remediation_context.
DEPLOY_FAILURE_ROUTE_FIELD = "failure_route"
DEPLOY_OWNER_DEVELOPER = "DEVELOPER"
DEPLOY_OWNER_PLATFORM_DEFECT = "PLATFORM_DEFECT"
DEPLOY_OWNERS = frozenset({DEPLOY_OWNER_DEVELOPER, DEPLOY_OWNER_PLATFORM_DEFECT, "OPERATOR_REQUIRED",
                           "PROVIDER_TRANSIENT", "UNKNOWN"})
NO_DEPLOY_FAILURE_ROUTE = "NO_DEPLOY_FAILURE_ROUTE"          # no route recorded (older terraform server, lost write)
DEPLOY_FAILURE_ROUTE_STALE = "DEPLOY_FAILURE_ROUTE_STALE"    # the route describes another failure than this dispatch's


class GateError(RuntimeError):
    """Base class for typed gate outcomes. Never caught-and-passed: callers map it to a FAILED response."""

    error_class: ErrorClass = ErrorClass.GATE_UNAVAILABLE
    http_status: int = 503

    def __init__(
        self,
        message: str,
        *,
        diagnostics: Optional[List[Dict[str, Any]]] = None,
        reason: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        stage: Optional[str] = None,
    ):
        super().__init__(message)
        self.stage = stage
        self.message = message
        self.diagnostics = list(diagnostics or [])
        self.reason = reason
        self.details = dict(details or {})

    def to_body(self, **extra: Any) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "status": "FAILED",
            "passed": False,
            "error_class": self.error_class.value,
            "summary": self.message,
            "errors": [self.message],
            "diagnostics": self.diagnostics,
        }
        if self.reason:
            body["reason"] = self.reason
        if self.details:
            body["details"] = self.details
        if self.stage:
            body["stage"] = self.stage
        body.update(extra)
        return body


class GateUnavailableError(GateError):
    error_class = ErrorClass.GATE_UNAVAILABLE
    http_status = 503


class GateFailedError(GateError):
    error_class = ErrorClass.CODE_DEFECT
    http_status = 422


class PlatformDefectError(GateError):
    error_class = ErrorClass.PLATFORM_DEFECT
    http_status = 503


class PolicyRejectedError(GateError):
    error_class = ErrorClass.POLICY_REJECTED
    http_status = 403


class KillSwitchActiveError(GateError):
    error_class = ErrorClass.KILL_SWITCH_ACTIVE
    http_status = 409


class ContractViolationError(GateError):
    error_class = ErrorClass.CONTRACT_VIOLATION
    http_status = 409


class OperatorActionRequiredError(GateError):
    error_class = ErrorClass.OPERATOR_ACTION_REQUIRED
    http_status = 409


class PrivateIngressUnsupportedError(GateError):
    """PRIVATE-INGRESS-EARLY-STOP: see the module docstring and compliance_agent/private_ingress.py."""
    error_class = ErrorClass.COMPLIANCE_PRIVATE_INGRESS_UNSUPPORTED
    http_status = 409


class ReleaseRefusedError(GateError):
    """FD-4P / FD-4BB (lane 16 contract): the release has nothing StackVend may merge (no PR ledger entry, ledger /
    workload repository mismatch, unknown VCS provider). 409 -> the workflow's release `except` -> DLQ now."""
    error_class = ErrorClass.RELEASE_FAILED
    http_status = 409


class MainMovedError(GateError):
    """FD-4BE (register row 11 follow-up): the fast-forward-only release merge was refused because the base branch
    advanced since the release branch was cut (the Serverless Git server's HTTP 409 on /merge, typed by the provider
    as ServerlessGitMergeConflict). Nothing was merged and the source branch is kept. 409 -> the workflow's release
    `except` ends the run MAIN_MOVED at once (no approval card, no 24 h wait, no auto-rebase): re-run the workload."""
    error_class = ErrorClass.MAIN_MOVED
    http_status = 409


class SourceCheckUnconfirmedError(PlatformDefectError):
    """SERVERLESS-AUTOMERGE-SHA: the git server advertised the tested-commit check (expected_source_sha) but its merge
    answer did not confirm it for the expected commit (for example an older revision answered the merge). The
    server reported the merge as done, so the PR ledger records it as merged with `source_check_confirmed: False`;
    the release stops typed (503 PLATFORM_DEFECT) and a re-invoke of the release is refused MERGE_UNCONFIRMED, so
    nothing deploys from an unconfirmed merge. Check the git server version."""


class StageDeadlineExceededError(GateError):
    """STAGE-DEADLINE: see ErrorClass.STAGE_DEADLINE_EXCEEDED and stage_deadline.py."""
    error_class = ErrorClass.STAGE_DEADLINE_EXCEEDED
    http_status = 504


class StageAbandonedError(GateError):
    """STAGE-DEADLINE: see ErrorClass.STAGE_ABANDONED and stage_deadline.py."""
    error_class = ErrorClass.STAGE_ABANDONED
    http_status = 409


class StageInterruptedError(GateError):
    """LONG-STAGE-CALLBACK: see ErrorClass.STAGE_INTERRUPTED and stage_jobs.py."""
    error_class = ErrorClass.STAGE_INTERRUPTED
    http_status = 503
