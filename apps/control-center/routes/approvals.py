"""
StackVend Control Center: Human-in-the-Loop (HITL) Approvals
Manages pending architectural reviews, pull request merges, rework cycles, and Cloud Workflows callbacks.

FD-4N hardening (docs/planning/wave1-lane4-plan-red-team.md B4/B6/B7, H4-H7):
- Decisions run through a compare-and-set state machine: {PENDING, MERGE_FAILED, CALLBACK_FAILED} -> DECIDING
  -> final status, written only AFTER the merge / callback outcome. A second concurrent decision gets 409.
- The repository to merge comes ONLY from workloads/{product_id}; the record's own github_repo must name the same
  repository (same normalizer the gateway used) or be absent. Platform pseudo-workloads are never merged from here.
- FD-4P / FD-4BB: every merge goes through the PR ledger (shared/vcs_ledger.py). The approval's `ledger_id` must be
  the entry StackVend wrote when it created exactly this (provider, workload repository, branch) for this product;
  no ledger entry => MERGE_FAILED ("merge on GitHub"), nothing merged.
- GitHub: the provider merges with `expected=` the ledger identity and re-checks the live PR first (repository id,
  PR number, head repo == base repo (no forks), head ref, base ref, head SHA); GitHub merges at that SHA.
- Serverless Git (single-tenant server, no forks, no PR objects): merges source_branch = the ledger branch into
  target_branch = the ledger base branch (the base the developer agent cut it from); pr_number unused.
- merge_status=MERGED is persisted the moment the merge succeeds (code RT F5), so no later failure can re-merge.
- Merge failure => MERGE_FAILED (502): no callback, no rollout. Callback failure => CALLBACK_FAILED (502).
  FD-4BE: except the git server's fast-forward-only 409 (main moved since the branch was cut, typed
  ServerlessGitMergeConflict): a re-decision can never merge it, so the workflow gets a MERGE_FAILED / MAIN_MOVED
  callback and ends the run at once (no 24 h wait); nothing is merged, the card ends in the terminal MAIN_MOVED.
  GH-MERGE-CALLBACK (owner 10-27): the same for a GitHub merge that the provider attempted and that failed (the
  provider raised, or GitHub did not merge, typed ReleaseMergeFailed): the workflow gets a MERGE_FAILED /
  RELEASE_FAILED callback and ends the run at once; the card ends in the terminal RELEASE_FAILED. Refusals BEFORE
  the provider's merge (no ledger entry, repository mismatch, no pr_number, provider init) stay the re-decidable
  MERGE_FAILED (the operator fixes the cause and decides again).
- The Pub/Sub "re-inject a fresh pipeline" fallback is deleted: an approval without callback_url gets 409.
- Callback delivery goes only through lane 3's validator + sender (shared/callbacks.py, FD-4J): no token is ever
  minted for a URL that is not this project's Workflows callback endpoint (see _deliver_workflow_callback).
- APPROVAL-CONSUME-VIA-VENDING (owner 11-07): an MCP_ACTION card (written by the kubernetes / agent-builder MCP
  servers) is decided by a human ADMIN only. APPROVED re-reads the workload ledger, refuses a card whose project or
  binding no longer matches (409, re-decidable) and mints a single-use `destructive_approvals` record bound to the
  card's exact action, target and binding (destructive_actions.mint_approval); the card then shows its id and expiry.
  The MCP server consumes it through project-vending; the CC never executes the action.
"""

from datetime import datetime, timezone
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, HTTPException, Request
from authz import APPROVAL, PLATFORM_PSEUDO_WORKLOADS, SCOPED, require, workload_scope

from auth import verify_workload_access
from config import PROJECT_ID
from db import db
import destructive_actions
import build_queue  # BUILD-ADMISSION-QUEUE F2 option A: an approved run takes a build slot again
from shared import build_admission as _build_admission
from routes.settings import make_vending_request
from schemas import (
    ApprovalDecisionRequest,
    ApprovalRequestRecord,
    ApprovalStatus,
    ApprovalType,
    ComplianceProfile,
    UserRole,
)

from shared import vcs_ledger  # FD-4P / FD-4BB: no ImportError fallback (a missing ledger must never fail open)

try:
    from shared.vcs_provider import VCSProviderFactory
except ImportError:
    try:
        from .vcs_provider import VCSProviderFactory
    except ImportError:
        try:
            from vcs_provider import VCSProviderFactory
        except ImportError:
            VCSProviderFactory = None
# FD-4BE: the Serverless Git server's fast-forward-only 409 (base advanced since the branch was cut), typed by status.
from shared.providers.serverless_git_provider import ServerlessGitMergeConflict, ServerlessGitSourceMoved

logger = logging.getLogger("control-center-approvals")


class MainMoved(Exception):
    """FD-4BE (register row 11 follow-up): the approved merge was refused because the base branch moved since the
    branch was cut. A re-decision can never fast-forward it, so the waiting run is ended typed MAIN_MOVED."""


class ReleaseMergeFailed(Exception):
    """GH-MERGE-CALLBACK (owner 10-27): the GitHub provider attempted the approved merge and it failed (the provider
    raised, e.g. PRIdentityMismatch / a GitHub error, or GitHub did not merge). The waiting run is ended typed
    RELEASE_FAILED at once instead of waiting for the 24 h approval timeout."""

router = APIRouter(tags=["Approvals"])

DECIDABLE_STATUSES = frozenset({"PENDING", "MERGE_FAILED", "CALLBACK_FAILED", "EXECUTION_FAILED"})
# Final statuses that mean "nothing happened, operator action needed": answered 502 and re-decidable.
FAILED_STATUSES = ("MERGE_FAILED", "CALLBACK_FAILED", "EXECUTION_FAILED")
# FD-4BE: terminal (NOT decidable): the merge was refused because main moved and the run was ended by the
# MERGE_FAILED / MAIN_MOVED callback. Answered 502 like a failure; listed in history, never in pending.
MAIN_MOVED_STATUS = "MAIN_MOVED"
# GH-MERGE-CALLBACK: terminal (NOT decidable): the GitHub merge failed and the run was ended by the MERGE_FAILED /
# RELEASE_FAILED callback. Answered 502 like a failure; listed in history, never in pending.
RELEASE_FAILED_STATUS = "RELEASE_FAILED"
RUN_ENDED_STATUSES = (MAIN_MOVED_STATUS, RELEASE_FAILED_STATUS)
VCS_GITHUB, VCS_SERVERLESS_GIT = "GITHUB", "SERVERLESS_GIT"
OPERATOR_DECISIONS = frozenset({ApprovalStatus.APPROVED, ApprovalStatus.REJECTED, ApprovalStatus.REWORK})


class DecisionConflict(Exception):
    def __init__(self, status: str):
        super().__init__(status)
        self.status = status


# C10 (RT residual R3, FD26-07): the enforcer engine is not packaged in this image, so the Control Center never imports
# it (the old in-process import worked only in a source checkout, never in the deployed container: restores silently
# did nothing). It runs finops-budget-enforcer-job with env overrides and waits for the execution's run record
# (shared/enforcer_job.py, the same client billing-alert-drain-job uses). The CC SA holds the custom role
# {run.jobs.run, run.jobs.runWithOverrides, run.executions.get} on that job only (Terraform cc_enforcer_runner).
CC_ENFORCER_WAIT_S = 600   # within the Control Center's 1800 s request timeout


def get_finops_enforcer():
    """The enforcer-job client, or None when this instance cannot run it (no project, no region, no credentials);
    callers then report a typed ENFORCER_UNAVAILABLE, never a success."""
    from shared.enforcer_job import EnforcerJob
    project = (PROJECT_ID or os.getenv("PROJECT_ID", "")).strip()
    try:
        from routes import platform_release
        region = (platform_release._region() or "").strip()
    except Exception as e:  # noqa: BLE001 - typed by the caller
        logger.warning(f"Could not resolve this instance's region for the enforcer job: {e}")
        region = ""
    if not project or not region:
        logger.error("ENFORCER_UNAVAILABLE: PROJECT_ID or the region is unknown; the enforcer job cannot be run")
        return None
    try:
        import google.auth
        from google.auth.transport.requests import AuthorizedSession
        creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        session = AuthorizedSession(creds)
    except Exception as e:  # noqa: BLE001
        logger.error(f"ENFORCER_UNAVAILABLE: no Google credentials ({type(e).__name__}: {e})")
        return None
    return EnforcerJob(session, db, project, region, wait_s=CC_ENFORCER_WAIT_S)


def _restore_via_enforcer(target_pid: Optional[str], target_project: Optional[str],
                          base: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Runs the restore; None when it was done (RESTORE_STATUSES), else the EXECUTION_FAILED decision (typed
    failure_reason; the card stays decidable, pending_decision APPROVED). Never a fabricated restore."""
    from shared.enforcer_job import RESTORE_STATUSES, EnforcerRunError
    if not target_pid or not target_project:
        return {**base, "status": "EXECUTION_FAILED", "pending_decision": "APPROVED",
                "failure_reason": "RESTORE_TARGET_UNKNOWN: the workload record has no project_id; nothing restored"}
    client = get_finops_enforcer()
    if client is None:
        return {**base, "status": "EXECUTION_FAILED", "pending_decision": "APPROVED",
                "failure_reason": "ENFORCER_UNAVAILABLE: the enforcer job cannot be run from this instance; "
                                  "nothing restored"}
    try:
        res = client.restore_workload(target_pid, target_project)
    except EnforcerRunError as e:
        logger.error(f"Budget-breach restore of '{target_pid}' failed: {e.code}: {e.detail}")
        return {**base, "status": "EXECUTION_FAILED", "pending_decision": "APPROVED",
                "failure_reason": f"{e.code}: {e.detail}", "enforcer_execution": e.execution or None}
    except Exception as e:  # noqa: BLE001 - typed, never a success
        logger.error(f"Budget-breach restore of '{target_pid}' failed: {type(e).__name__}: {e}")
        return {**base, "status": "EXECUTION_FAILED", "pending_decision": "APPROVED",
                "failure_reason": f"RESTORE_FAILED: {type(e).__name__}: {e}"}
    outcome = (res or {}).get("status")
    if outcome not in RESTORE_STATUSES:
        return {**base, "status": "EXECUTION_FAILED", "pending_decision": "APPROVED",
                "failure_reason": f"{outcome}: {(res or {}).get('reason') or 'the enforcer did not restore'}",
                "enforcer_execution": (res or {}).get("execution")}
    logger.info(f"Budget-breach restore of '{target_pid}': {outcome} ({(res or {}).get('execution')})")
    return None


@router.get("/api/approvals", response_model=List[ApprovalRequestRecord], dependencies=[require(SCOPED)])
def list_pending_approvals(request: Request):
    """Lists pending and historical HITL approval requests, scoped to the caller (FD-4N: filtered unconditionally;
    an empty assignment list sees nothing; records without a product_id are visible to administrators only)."""
    scope = workload_scope(request)
    if db:
        try:
            try:
                raw_docs = list(db.collection("approval_requests").stream())
            except Exception as stream_err:
                logger.warning(f"Failed to stream approval_requests from Firestore: {stream_err}")
                raw_docs = []

            # Sort in memory chronologically
            def _sort_key(d):
                data = d.to_dict() or {}
                return str(data.get("requested_at") or data.get("created_at_iso") or data.get("decided_at") or data.get("created_at") or "")

            docs = sorted(raw_docs, key=_sort_key, reverse=True)

            workload_cache: Dict[str, Dict[str, Any]] = {}
            results = []
            for d in docs:
                data = d.to_dict() or {}
                pid = data.get("product_id")
                if not scope.all and not scope.allows(pid):
                    continue

                # Resilient enum resolution for legacy and missing approval_type values
                raw_type = data.get("approval_type")
                if not raw_type or raw_type == "PR_MERGE":
                    appr_type = ApprovalType.PULL_REQUEST
                else:
                    try:
                        appr_type = ApprovalType(raw_type)
                    except ValueError:
                        appr_type = ApprovalType.PULL_REQUEST

                # Resilient status resolution
                raw_status = data.get("status")
                try:
                    appr_status = ApprovalStatus(raw_status) if raw_status else ApprovalStatus.PENDING
                except ValueError:
                    appr_status = ApprovalStatus.PENDING

                # Resilient timestamp resolution across legacy formats
                req_at = (
                    data.get("requested_at")
                    or data.get("created_at_iso")
                    or data.get("decided_at")
                    or ""
                )
                if not req_at and isinstance(data.get("created_at"), (int, float)):
                    req_at = datetime.fromtimestamp(data["created_at"], timezone.utc).isoformat()
                if not req_at:
                    req_at = datetime.now(timezone.utc).isoformat()

                results.append(
                    ApprovalRequestRecord(
                        approval_id=d.id,
                        approval_type=appr_type,
                        product_id=pid if isinstance(pid, str) else "",
                        trace_id=data.get("trace_id", ""),
                        cost_delta_monthly=str(data.get("cost_delta_monthly", "$0.00/mo")),
                        risk_assessment=data.get("risk_assessment", ""),
                        status=appr_status,
                        plan_markdown=data.get("plan_markdown"),
                        task_dag=data.get("task_dag", []),
                        compliance_summary=data.get("compliance_summary"),
                        rework_cycle=data.get("rework_cycle", 0),
                        feedback=data.get("feedback"),
                        requested_at=req_at,
                        decided_at=data.get("decided_at"),
                        decided_by=data.get("decided_by"),
                        decision_reason=data.get("decision_reason"),
                        target_project_id=data.get("target_project_id"),
                        current_spend_usd=data.get("current_spend_usd"),
                        budget_ceiling_usd=data.get("budget_ceiling_usd"),
                        buffer_ceiling_usd=data.get("buffer_ceiling_usd"),
                        projected_monthly_spend_usd=data.get("projected_monthly_spend_usd"),
                        quarantined_resources=data.get("quarantined_resources", []),
                        snapshot_id=data.get("snapshot_id"),
                        failure_reason=data.get("failure_reason"),
                        error_class=data.get("error_class"),
                        from_profile=data.get("from_profile"),
                        to_profile=data.get("to_profile"),
                        **_merge_identity(data, appr_type, workload_cache),
                        **_access_review(data),
                        **_access_advisories(data, appr_type),
                        **_secret_advisories(data, appr_type),
                        **_finops_recommendation(data, appr_type),
                        # one dict: the guard-DB view overrides the card's expiry (no duplicate keyword)
                        **{**_mcp_action_view(data, appr_type), **_mcp_minted_view(d.id, data, appr_type, request)},
                    )
                )
            return results
        except Exception as e:
            logger.warning(f"Failed to query approval_requests from Firestore: {e}")
    return []


_FINOPS_RECOMMENDATION_TEXT_FIELDS = ("finops_recommendation", "finops_recommendation_status",
                                      "finops_recommendation_note", "finops_recommendation_model")


def _finops_recommendation(data: Dict[str, Any], appr_type) -> Dict[str, Any]:
    """FD-4CI-b-R2: the FinOps Agent Model's recommendation fields of a budget-breach card, copied only when they have
    the type the advisor writes (str, usage dict), so a malformed field never breaks the approvals list. Other card
    types: none."""
    if appr_type not in (ApprovalType.BUDGET_BREACH, ApprovalType.BUDGET_BREACH_REMEDIATION):
        return {}
    view = {k: data[k] for k in _FINOPS_RECOMMENDATION_TEXT_FIELDS if isinstance(data.get(k), str)}
    usage = data.get("finops_recommendation_usage")
    if isinstance(usage, dict):
        view["finops_recommendation_usage"] = usage
    return view


def _mcp_action_view(data: Dict[str, Any], appr_type) -> Dict[str, Any]:
    """APPROVAL-CONSUME-VIA-VENDING: what an MCP_ACTION card asks for (typed fields only; a malformed field is
    dropped, never shown as something else). Other card types: none."""
    if appr_type != ApprovalType.MCP_ACTION:
        return {}
    view: Dict[str, Any] = {k: data[k] for k in ("mcp_action", "mcp_project_id", "mcp_requested_by",
                                                 "mcp_approval_expires_at") if isinstance(data.get(k), str)}
    # RT N1: the fingerprint the decision must echo is computed HERE from the arguments shown, never copied from the
    # card's stored digest field (a default-database field any agent account can set).
    clean = destructive_actions.clean_mcp_binding(data.get("mcp_action"), data.get("mcp_binding"))
    if clean is not None:
        view["mcp_binding"] = clean
        view["mcp_binding_digest"] = destructive_actions.binding_digest(clean)
    else:
        binding = data.get("mcp_binding")
        if isinstance(binding, dict):
            view["mcp_binding"] = {k: v for k, v in binding.items() if isinstance(k, str) and isinstance(v, str)}
        view["mcp_card_malformed"] = True
    # RT F3: display-only details, typed: requirements is a list of short strings, source_uri / model_name strings;
    # anything else (or a malformed value) is dropped.
    details = data.get("mcp_details") if isinstance(data.get("mcp_details"), dict) else {}
    typed: Dict[str, Any] = {}
    reqs = details.get("requirements")
    if isinstance(reqs, list) and all(isinstance(r, str) and len(r) <= MCP_DETAIL_MAX_LENGTH for r in reqs):
        typed["requirements"] = list(reqs)
    for k in ("source_uri", "model_name"):
        if isinstance(details.get(k), str) and len(details[k]) <= MCP_DETAIL_MAX_URI_LENGTH:
            typed[k] = details[k]
    view["mcp_details"] = typed
    return view


def _mcp_minted_view(card_id: str, data: Dict[str, Any], appr_type, request) -> Dict[str, Any]:
    """RT F2: the minted approval id is never stored on the card (default database); administrators see it, read
    from the guard database by the card id. Display only: a read failure shows nothing."""
    if appr_type != ApprovalType.MCP_ACTION or data.get("status") != "APPROVED" \
            or getattr(getattr(request, "state", None), "user_role", None) != UserRole.ADMIN:
        return {}
    try:
        gdb = destructive_actions.get_guard_db()
        snaps = list(gdb.collection(destructive_actions.APPROVALS).where("request_id", "==", card_id).limit(2).stream()) \
            if gdb else []
    except Exception as e:  # noqa: BLE001 - display only
        logger.warning(f"Could not read the approval minted for card {card_id}: {type(e).__name__}")
        return {}
    if len(snaps) != 1:
        return {}
    rec = snaps[0].to_dict() or {}
    view = {"mcp_approval_id": snaps[0].id}
    if isinstance(rec.get("status"), str):
        view["mcp_approval_status"] = rec["status"]
    if isinstance(rec.get("expires_at"), str):
        view["mcp_approval_expires_at"] = rec["expires_at"]
    return view


def _access_review(data: Dict[str, Any]) -> Dict[str, Any]:
    """L19-F4 RT R2: what a plan approval forced by ACCESS_WIDENED widens, for the card. Read only from the typed
    fields the gateway copied (``gate_reasons``, ``access_under_review = {flag, current_access}``): the last approved
    mode, the mode the build will use, and the exact members added since that record (set difference of canonical
    ``kind:value`` strings). A malformed copy shows "unknown" values, never nothing."""
    reasons = data.get("gate_reasons") if isinstance(data.get("gate_reasons"), list) else []
    reasons = [r for r in reasons if isinstance(r, str)]
    view: Dict[str, Any] = {"gate_reasons": reasons, "access_widened": "ACCESS_WIDENED" in reasons}
    if not view["access_widened"]:
        return view
    review = data.get("access_under_review") if isinstance(data.get("access_under_review"), dict) else {}
    flag = review.get("flag") if isinstance(review.get("flag"), dict) else {}
    current = review.get("current_access") if isinstance(review.get("current_access"), dict) else {}

    def _members(v: Any) -> Optional[List[str]]:
        return [m for m in v if isinstance(m, str)] if isinstance(v, list) else None

    now = _members(current.get("invoker_principals"))
    before = _members(flag.get("previous_members"))
    # Re-check N2: unknown members are shown as unknown (None), never as "no members added".
    added = sorted(set(now) - set(before)) if now is not None and before is not None else None
    mode_before = flag.get("previous_mode") if isinstance(flag.get("previous_mode"), str) else None
    mode_after = current.get("mode") if isinstance(current.get("mode"), str) else (
        flag.get("new_mode") if isinstance(flag.get("new_mode"), str) else "unknown")
    view.update({"access_mode_before": mode_before or ("none recorded" if flag else "unknown"),
                 "access_mode_after": mode_after, "access_added_members": added,
                 "access_members_now": sorted(now or [])})
    return view


# ACCESS-INTERNAL-SERVICE-ADVISORY: the codes the gateway copies onto a plan approval card (the gateway's
# workflow_gates.ACCESS_ADVISORY_CODES; a test pins the equality).
ACCESS_ADVISORY_CODES = ("ACCESS.INTERNAL_SERVICE_PUBLIC",)
ACCESS_ADVISORY_MAX_TEXT = 1000


def _access_advisories(data: Dict[str, Any], appr_type) -> Dict[str, Any]:
    """ACCESS-INTERNAL-SERVICE-ADVISORY: the plan's typed access warnings for the ARCHITECTURAL_PLAN card, from the
    gateway's copy (``approval_requests/{id}.access_advisories``). Absent or [] -> nothing (the card is unchanged). A
    malformed copy is never shown as "no warnings": the card says the warnings could not be read. Other card types:
    none."""
    if appr_type != ApprovalType.ARCHITECTURAL_PLAN or data.get("access_advisories") is None:
        return {}
    raw = data.get("access_advisories")
    if not isinstance(raw, list):
        return {"access_advisories_unreadable": True}
    out: List[Dict[str, Any]] = []
    for item in raw:
        ok = (isinstance(item, dict) and item.get("code") in ACCESS_ADVISORY_CODES
              and all(isinstance(item.get(k), str) and 0 < len(item[k]) <= ACCESS_ADVISORY_MAX_TEXT
                      for k in ("service", "message")))
        if not ok:
            return {"access_advisories_unreadable": True}
        out.append({"code": item["code"], "service": item["service"], "message": item["message"]})
    omitted = data.get("access_advisories_omitted", 0)
    if isinstance(omitted, bool) or not isinstance(omitted, int) or omitted < 0:
        return {"access_advisories_unreadable": True}
    return {"access_advisories": out, "access_advisories_omitted": omitted}


# SECRET-INITIAL-VERSION: the codes the gateway copies onto a plan approval card (the gateway's
# workflow_gates.SECRET_ADVISORY_CODES; a test pins the equality).
SECRET_ADVISORY_CODES = ("SECRET.OPERATOR_VALUE_REQUIRED", "SECRET.VALUE_SOURCE_UNSTATED")


def _secret_advisories(data: Dict[str, Any], appr_type) -> Dict[str, Any]:
    """SECRET-INITIAL-VERSION: the plan's Secret Manager secrets that the platform creates without a value, for the
    ARCHITECTURAL_PLAN card, from the gateway's copy (``approval_requests/{id}.secret_advisories``). Absent or [] ->
    nothing (the card is unchanged). A malformed copy is never shown as "no warnings": the card says the warnings could
    not be read. Other card types: none."""
    if appr_type != ApprovalType.ARCHITECTURAL_PLAN or data.get("secret_advisories") is None:
        return {}
    raw = data.get("secret_advisories")
    if not isinstance(raw, list):
        return {"secret_advisories_unreadable": True}
    out: List[Dict[str, Any]] = []
    for item in raw:
        ok = (isinstance(item, dict) and item.get("code") in SECRET_ADVISORY_CODES
              and all(isinstance(item.get(k), str) and 0 < len(item[k]) <= ACCESS_ADVISORY_MAX_TEXT
                      for k in ("secret", "message")))
        if not ok:
            return {"secret_advisories_unreadable": True}
        out.append({"code": item["code"], "secret": item["secret"], "message": item["message"]})
    omitted = data.get("secret_advisories_omitted", 0)
    if isinstance(omitted, bool) or not isinstance(omitted, int) or omitted < 0:
        return {"secret_advisories_unreadable": True}
    return {"secret_advisories": out, "secret_advisories_omitted": omitted}


def _merge_identity(data: Dict[str, Any], appr_type, cache: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Code RT F6: what an APPROVED decision would merge, for the approval card. The repository shown is the one the
    merge uses (workloads/{product_id}.github_repo), not the agent-writable record field."""
    if appr_type != ApprovalType.PULL_REQUEST:
        return {}
    pid = data.get("product_id")
    if isinstance(pid, str) and pid and pid not in cache:
        try:
            cache[pid] = _workload_doc(pid)
        except Exception as e:  # noqa: BLE001 - display only
            logger.warning(f"Could not load workload {pid} for approval card: {e}")
            cache[pid] = {}
    w = cache.get(pid, {}) if isinstance(pid, str) else {}
    w = w if isinstance(w, dict) else {}
    pr, repo, branch, vcs = data.get("pr_number"), w.get("github_repo"), data.get("branch_name"), w.get("vcs_provider")
    return {
        "github_repo": repo if isinstance(repo, str) and repo else None,
        "branch_name": branch if isinstance(branch, str) and branch else None,
        "pr_number": pr if isinstance(pr, int) and not isinstance(pr, bool) and pr > 0 else None,
        "vcs_provider": vcs.strip().upper() if isinstance(vcs, str) and vcs.strip() else VCS_GITHUB,
    }


# ---------------------------------------------------------------- state machine helpers
def _cas_claim(doc_ref, decider: str, now_iso: str) -> Dict[str, Any]:
    """Atomically move the record from a decidable status to DECIDING. Returns the pre-claim record.
    Raises LookupError (missing) or DecisionConflict (not decidable).

    Real Firestore (an instance of google.cloud.firestore_v1 DocumentReference): a read-check-write TRANSACTION, so
    two concurrent decisions can never both pass (tests/test_approvals.py::TestConcurrentDecisions drives this exact
    path with a contention-modelling transaction). Plain in-memory fakes (unit tests only) use the same check
    without a transaction; production always runs on the real client."""
    def _check(data):
        status = data.get("status") or "PENDING"
        if status not in DECIDABLE_STATUSES:
            raise DecisionConflict(status)
        return {"status": "DECIDING", "deciding_by": decider, "deciding_at": now_iso, "status_before_decision": status}

    try:
        from google.cloud.firestore_v1.document import DocumentReference as _FirestoreDocRef
    except ImportError:  # pragma: no cover - the CC image always ships google-cloud-firestore
        _FirestoreDocRef = None
    if _FirestoreDocRef is not None and isinstance(doc_ref, _FirestoreDocRef):
        from google.cloud.firestore_v1 import transactional

        @transactional
        def _txn(txn):
            snap = doc_ref.get(transaction=txn)
            if not snap.exists:
                raise LookupError("missing")
            data = snap.to_dict() or {}
            txn.update(doc_ref, _check(data))
            return data

        return _txn(doc_ref._client.transaction())

    snap = doc_ref.get()
    if not getattr(snap, "exists", False):
        raise LookupError("missing")
    data = snap.to_dict() or {}
    doc_ref.set(_check(data), merge=True)
    return data


def _release(doc_ref, prior_status: str) -> None:
    try:
        doc_ref.set({"status": prior_status}, merge=True)
    except Exception as e:  # noqa: BLE001
        logger.error(f"Could not release approval claim: {e}")


def _deliver_workflow_callback(callback_url: str, payload: Dict[str, Any]) -> Tuple[bool, str]:
    """Deliver the HITL decision to the waiting Cloud Workflows callback through lane 3's FD-4J helper
    (`shared/callbacks.py`, the Control Center's byte-identical replica): `classify_callback_url` refuses anything
    that is not this platform project's Workflows callback endpoint (or a loopback harness) BEFORE a credential is
    minted, and `CallbackDeliveryClient.send_callback` never follows redirects (red-team H5: one validator, owned by
    lane 3; no local URL check here). Never raises: every failure is (False, reason) => CALLBACK_FAILED."""
    try:
        from shared.callbacks import CallbackDeliveryClient, CallbackURLRejected, classify_callback_url
    except ImportError as imp_err:
        logger.error(f"HITL callback not delivered: shared/callbacks.py validator unavailable ({imp_err}); failing closed.")
        return False, "callback validator (shared/callbacks.py) unavailable; nothing sent (fails closed)"
    try:
        classify_callback_url(callback_url)
    except CallbackURLRejected as rej:
        logger.error(f"HITL callback refused before any credential was minted: {rej}")
        return False, f"callback URL refused: {rej}"
    try:
        CallbackDeliveryClient.send_callback(callback_url=callback_url, payload=payload, timeout=10, max_attempts=3)
    except Exception as e:  # noqa: BLE001 - delivery failure is a recorded state, never a 500
        logger.error(f"HITL callback delivery failed: {type(e).__name__}: {e}")
        return False, f"callback delivery failed: {type(e).__name__}: {e}"
    return True, ""


def _record_response(approval_id: str, record: Dict[str, Any], now_iso: str, admin_email: str) -> ApprovalRequestRecord:
    raw_type = record.get("approval_type")
    if not raw_type or raw_type == "PR_MERGE":
        appr_type_val = ApprovalType.PULL_REQUEST
    else:
        try:
            appr_type_val = ApprovalType(raw_type)
        except ValueError:
            appr_type_val = ApprovalType.PULL_REQUEST
    try:
        appr_status_val = ApprovalStatus(record.get("status") or "PENDING")
    except ValueError:
        appr_status_val = ApprovalStatus.PENDING
    return ApprovalRequestRecord(
        approval_id=approval_id,
        approval_type=appr_type_val,
        product_id=record.get("product_id", "") or "",
        trace_id=record.get("trace_id", ""),
        cost_delta_monthly=str(record.get("cost_delta_monthly", "$0.00/mo")),
        risk_assessment=record.get("risk_assessment", ""),
        status=appr_status_val,
        plan_markdown=record.get("plan_markdown"),
        task_dag=record.get("task_dag", []),
        compliance_summary=record.get("compliance_summary"),
        rework_cycle=record.get("rework_cycle", 0),
        feedback=record.get("feedback"),
        requested_at=record.get("requested_at", now_iso),
        decided_at=record.get("decided_at", now_iso),
        decided_by=record.get("decided_by", admin_email),
        decision_reason=record.get("decision_reason"),
        target_project_id=record.get("target_project_id"),
        current_spend_usd=record.get("current_spend_usd"),
        budget_ceiling_usd=record.get("budget_ceiling_usd"),
        buffer_ceiling_usd=record.get("buffer_ceiling_usd"),
        projected_monthly_spend_usd=record.get("projected_monthly_spend_usd"),
        quarantined_resources=record.get("quarantined_resources", []),
        snapshot_id=record.get("snapshot_id"),
        failure_reason=record.get("failure_reason"),
        error_class=record.get("error_class"),
        **_merge_identity(record, appr_type_val, {}),
        **_access_review(record),
        **_access_advisories(record, appr_type_val),
        **_secret_advisories(record, appr_type_val),
        **_mcp_action_view(record, appr_type_val),
        # RT F2: the minted id only in the decision answer (in-memory record), never from the stored card.
        **({"mcp_approval_id": record["mcp_approval_id"]}
           if appr_type_val == ApprovalType.MCP_ACTION and isinstance(record.get("mcp_approval_id"), str) else {}),
    )


# ---------------------------------------------------------------- decision
@router.post("/api/approvals/{approval_id}/decision", response_model=ApprovalRequestRecord, dependencies=[require(APPROVAL())])
def decide_approval_request(approval_id: str, req: ApprovalDecisionRequest, request: Request):
    """
    Operator approves, rejects, or requests rework on a Tier 3 / Tier 3.5 HITL policy gate.
    APPROVED on a PR approval merges the workload's PR (verified same-repo) and then resumes the waiting workflow
    through its callback. Final status is written only after those side effects (state machine, see module doc).
    """
    admin_email = getattr(request.state, "user_email", "admin-console")
    now_iso = datetime.now(timezone.utc).isoformat()
    if req.decision not in OPERATOR_DECISIONS:
        raise HTTPException(status_code=400, detail="decision must be APPROVED, REJECTED or REWORK.")
    if not db:
        raise HTTPException(status_code=503, detail="Database unavailable")

    doc_ref = db.collection("approval_requests").document(approval_id)
    try:
        record = _cas_claim(doc_ref, admin_email, now_iso)
    except LookupError:
        raise HTTPException(status_code=404, detail=f"Approval request '{approval_id}' not found.")
    except DecisionConflict as c:
        raise HTTPException(status_code=409, detail=f"Approval request '{approval_id}' is not decidable (status {c.status}).")
    except Exception as e:  # noqa: BLE001
        logger.error(f"Approval claim failed for {approval_id}: {e}")
        raise HTTPException(status_code=503, detail="Could not claim the approval for decision; retry.")

    prior_status = record.get("status") or "PENDING"
    target_pid = record.get("product_id")
    try:
        # Defense in depth (the route policy APPROVAL already checked this): no product_id => ADMIN only.
        if isinstance(target_pid, str) and target_pid:
            verify_workload_access(target_pid, request, require_manager=True)
        elif getattr(request.state, "user_role", None) != UserRole.ADMIN:
            raise HTTPException(status_code=403, detail="Access denied.")
        final = _decide(approval_id, record, req, request, admin_email, now_iso, doc_ref)
    except HTTPException as he:
        if getattr(he, "status_code", 500) < 500:
            _release(doc_ref, prior_status)  # refusal: nothing happened, stay decidable
        else:
            _release(doc_ref, prior_status if prior_status in DECIDABLE_STATUSES else "PENDING")
        raise
    except Exception as e:  # noqa: BLE001
        logger.error(f"Failed to process approval decision {approval_id}: {e}")
        _release(doc_ref, prior_status)
        raise HTTPException(status_code=500, detail=str(e))

    try:
        doc_ref.set(final, merge=True)
    except Exception as e:  # noqa: BLE001 - re-raised; RT F5: a minted MCP approval must not be orphaned silently
        if record.get("mcp_approval_id"):
            logger.error(f"MCP approval {record['mcp_approval_id']} minted for card {approval_id} but the card could "
                         f"not be updated ({type(e).__name__}); it expires unused unless the id is passed to the tool")
        raise
    record.update(final)
    _record_release_stage(approval_id, record, admin_email, now_iso)
    if final.get("status") in FAILED_STATUSES or final.get("status") in RUN_ENDED_STATUSES:
        raise HTTPException(status_code=502, detail=f"{final['status']}: {final.get('failure_reason', '')}")
    return _record_response(approval_id, record, now_iso, admin_email)


# RELEASE-STAGE-OUTCOME (FD-4DT): the workflow marks pipeline_executions/{trace}.stages.release PAUSED_FOR_APPROVAL
# while it waits for a release card, and nothing wrote the decision back, so an approved run kept showing "paused"
# after it SUCCEEDED. The decision now writes the release stage's real outcome. A release card is the one
# /agent/release/promote writes: a PR-type approval carrying the PR ledger entry (`ledger_id`) it merges. Keyed on
# the card's typed final status only (no text is read). Re-decidable failures (MERGE_FAILED, CALLBACK_FAILED) leave
# the stage paused: the card is still waiting for a decision.
RELEASE_APPROVAL_TYPES = frozenset({ApprovalType.PR_MERGE.value, ApprovalType.PULL_REQUEST.value})
RELEASE_STAGE_STATUS_BY_DECISION = {"APPROVED": "SUCCESS", "REJECTED": "REJECTED"}


def _release_stage_update(approval_id: str, record: Dict[str, Any], admin_email: str,
                          now_iso: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """(trace_id, stage) for a decided release card, else None. `record` is the card after its final write."""
    stage_status = RELEASE_STAGE_STATUS_BY_DECISION.get(record.get("status"))
    if stage_status is None:
        return None
    if (record.get("approval_type") or ApprovalType.PR_MERGE.value) not in RELEASE_APPROVAL_TYPES:
        return None
    trace_id, ledger_id = record.get("trace_id"), record.get("ledger_id")
    if not (isinstance(trace_id, str) and trace_id and isinstance(ledger_id, str) and ledger_id):
        return None
    if stage_status == "SUCCESS":
        if record.get("merge_status") != "MERGED":
            return None  # an approved release card always merges first; never claim a merge that is not recorded
        into = record.get("merged_into")
        summary = f"Approved by {admin_email}; merged into {into}" if into else f"Approved by {admin_email}; merged"
    else:
        summary = f"Rejected by {admin_email}: {record.get('decision_reason') or 'no reason given'}"
    return trace_id, {"status": stage_status, "summary": summary, "decision": record.get("status"),
                      "approval_id": approval_id, "decided_by": admin_email, "decided_at": now_iso}


def _record_release_stage(approval_id: str, record: Dict[str, Any], admin_email: str, now_iso: str) -> None:
    """Write the decided release card's outcome to its run's release stage. The decision itself is already final on
    the card (the source of truth), so a failed write is logged, never raised."""
    upd = _release_stage_update(approval_id, record, admin_email, now_iso)
    if upd is None:
        return
    trace_id, stage = upd
    try:
        db.collection("pipeline_executions").document(trace_id).set({"stages": {"release": stage}}, merge=True)
    except Exception as e:  # noqa: BLE001 - display record only; the approval card holds the decision
        logger.error(f"Release stage of {trace_id} not updated after {approval_id} {record.get('status')}: "
                     f"{type(e).__name__}: {e}")


def _workload_doc(product_id: Optional[str]) -> Dict[str, Any]:
    if not isinstance(product_id, str) or not product_id:
        return {}
    snap = db.collection("workloads").document(product_id).get()
    return (snap.to_dict() or {}) if snap.exists else {}


def _decide(approval_id: str, record: Dict[str, Any], req: ApprovalDecisionRequest, request: Request,
            admin_email: str, now_iso: str, doc_ref=None) -> Dict[str, Any]:
    """Runs the side effects of a claimed decision and returns the FINAL fields to write."""
    target_pid = record.get("product_id")
    appr_type = record.get("approval_type", "PR_MERGE")
    base = {"decided_at": now_iso, "decided_by": admin_email, "decision_reason": req.reason or req.feedback,
            "failure_reason": None, "error_class": None}
    if req.feedback:
        base["feedback"] = req.feedback

    # ---------------- budget-breach remediation (no merge, no callback)
    if appr_type in ("BUDGET_BREACH", "BUDGET_BREACH_REMEDIATION"):
        return _decide_budget(record, req, admin_email, now_iso, base, request)

    # ---------------- compliance profile downgrade (owner decision 10-18, row CP-11; no merge, no callback)
    if appr_type == ApprovalType.COMPLIANCE_PROFILE_DOWNGRADE.value:
        return _decide_compliance_downgrade(record, req, request, admin_email, now_iso, base)

    # ---------------- MCP action approval (APPROVAL-CONSUME-VIA-VENDING; no merge, no callback)
    if appr_type == ApprovalType.MCP_ACTION.value:
        return _decide_mcp_action(approval_id, record, req, request, now_iso, base)

    callback_url = record.get("callback_url")

    # ---------------- APPROVED
    if req.decision == ApprovalStatus.APPROVED:
        if not callback_url:
            # Red-team B7/H7: no blind re-injection of a fresh pipeline from agent-writable fields.
            raise HTTPException(status_code=409, detail="Legacy approval without a workflow callback: use Retrigger on the workload instead.")
        branch = record.get("branch_name")
        needs_merge = appr_type != "ARCHITECTURAL_PLAN" and bool(branch)
        if needs_merge and record.get("merge_status") != "MERGED":
            try:
                err = _merge_workload_pr(record, target_pid, branch, admin_email)
            except MainMoved as moved:
                return _end_run_main_moved(base, callback_url, str(moved), admin_email, approval_id)
            except ReleaseMergeFailed as failed:
                return _end_run_merge_failed(base, callback_url, str(failed), admin_email, approval_id,
                                             error_class="RELEASE_FAILED", terminal_status=RELEASE_FAILED_STATUS)
            if err:
                logger.error(f"HITL merge refused/failed for {approval_id}: {err}")
                return {**base, "status": "MERGE_FAILED", "failure_reason": err}
            base["merge_status"] = "MERGED"
            base["merged_at"] = now_iso
            record["merge_status"] = "MERGED"
            merged_into = {"merged_into": record["merged_into"]} if record.get("merged_into") else {}
            base.update(merged_into)
            # Code RT F5: persist NOW, before the callback. Whatever fails after this point (callback, final write,
            # an exception that releases the claim to its prior status), a re-decision never merges again.
            if doc_ref is not None:
                try:
                    doc_ref.set({"merge_status": "MERGED", "merged_at": now_iso, "merged_by": admin_email,
                                 **merged_into}, merge=True)
                except Exception as w_err:  # noqa: BLE001 - the final write below carries merge_status too
                    logger.critical(f"Merged {approval_id} but could not persist merge_status immediately: {w_err}")
        cb_payload = {"status": "APPROVED", "decision": "APPROVED", "decided_by": admin_email, "product_id": target_pid}
        if branch:
            cb_payload["branch_name"] = branch
        # BUILD-ADMISSION-QUEUE F2 option A (owner 11-14): the run gave its build slot up while it waited; it takes one
        # again first. None free: it waits at the head of the queue and the callback is delivered when one frees.
        resumed = build_queue.resume_after_approval(db, record, approval_id, callback_url, cb_payload, "APPROVED")
        if resumed is not None and resumed.state == _build_admission.QUEUED:
            return {**base, "status": "APPROVED", "build_queue": resumed.view(),
                    "decision_reason": (req.reason or req.feedback or "Approved by operator via Control Center.")
                                       + f" The run waits for a build slot (#{resumed.position} in line)."}
        ok, why = _deliver_workflow_callback(callback_url, cb_payload)
        if not ok:
            return {**base, "status": "CALLBACK_FAILED", "failure_reason": why, "pending_decision": "APPROVED"}
        return {**base, "status": "APPROVED", "decision_reason": req.reason or req.feedback or "Approved by operator via Control Center."}

    # ---------------- REJECTED
    if req.decision == ApprovalStatus.REJECTED:
        reason = req.reason or "Operator rejected approval request"
        if callback_url:
            ok, why = _deliver_workflow_callback(callback_url, {
                "status": "REJECTED", "decision": "REJECTED", "decided_by": admin_email, "decision_reason": reason})
            if not ok:
                return {**base, "status": "CALLBACK_FAILED", "failure_reason": why, "pending_decision": "REJECTED"}
        return {**base, "status": "REJECTED", "decision_reason": reason}

    # ---------------- REWORK (architect loopback)
    feedback = req.feedback or req.reason or "Operator requested architectural rework"
    if callback_url:
        rework_payload = {"status": "REWORK", "decision": "REWORK", "decided_by": admin_email, "feedback": feedback,
                          "rework_cycle": record.get("rework_cycle", 0)}
        # F2 option A: a rework sends the run back to the architect (model calls): it takes a build slot again first.
        resumed = build_queue.resume_after_approval(db, record, approval_id, callback_url, rework_payload, "REWORK")
        if resumed is not None and resumed.state == _build_admission.QUEUED:
            return {**base, "status": "REWORK", "build_queue": resumed.view(),
                    "decision_reason": f"{req.feedback or feedback} The run waits for a build slot "
                                       f"(#{resumed.position} in line)."}
        ok, why = _deliver_workflow_callback(callback_url, rework_payload)
        if not ok:
            return {**base, "status": "CALLBACK_FAILED", "failure_reason": why, "pending_decision": "REWORK"}
    trace_id = record.get("trace_id")
    if trace_id:
        try:
            db.collection("pipeline_executions").document(trace_id).set({
                "state": "REWORK_REQUESTED",
                "current_step": "REWORK_REQUESTED",
                "updated_at": now_iso,
            }, merge=True)
        except Exception as e:  # noqa: BLE001
            logger.warning(f"Could not mark trace {trace_id} REWORK_REQUESTED: {e}")
    return {**base, "status": "REWORK", "decision_reason": req.feedback or feedback}


def _end_run_main_moved(base: Dict[str, Any], callback_url: str, reason: str, admin_email: str,
                        approval_id: str) -> Dict[str, Any]:
    """FD-4BE: nothing was merged and a fast-forward can never succeed on a re-decision, so the waiting workflow is
    told now (decision MERGE_FAILED, error_class MAIN_MOVED: the workflow's handle_merge_failed ends the run typed)
    instead of waiting 24 h. The card ends in the terminal MAIN_MOVED status (502, not re-decidable, shown in history);
    a failed delivery is CALLBACK_FAILED (re-decidable, so the callback can be retried)."""
    return _end_run_merge_failed(base, callback_url, reason, admin_email, approval_id,
                                 error_class="MAIN_MOVED", terminal_status=MAIN_MOVED_STATUS)


def _end_run_merge_failed(base: Dict[str, Any], callback_url: str, reason: str, admin_email: str, approval_id: str,
                          *, error_class: str, terminal_status: str) -> Dict[str, Any]:
    """FD-4BE / GH-MERGE-CALLBACK: an attempted merge failed, so the waiting workflow is told now (decision
    MERGE_FAILED with the typed error_class; the workflow's handle_merge_failed ends the run with that class) instead
    of waiting 24 h. The card ends in `terminal_status` (502, not re-decidable, shown in history). A failed delivery
    is logged and recorded as CALLBACK_FAILED (502, re-decidable, so the merge and this callback can be retried)."""
    logger.warning(f"HITL merge for {approval_id} failed: {reason} ({error_class}; ending the run)")
    ok, why = _deliver_workflow_callback(callback_url, {
        "status": "MERGE_FAILED", "decision": "MERGE_FAILED", "error_class": error_class, "reason": reason,
        "decided_by": admin_email})
    if not ok:  # stays decidable: a re-decision retries the merge and this callback
        logger.error(f"HITL merge for {approval_id} failed ({error_class}) and the run could not be ended: {why}")
        return {**base, "status": "CALLBACK_FAILED", "error_class": error_class,
                "failure_reason": f"{reason}; the run could not be ended: {why}"}
    # Terminal: a re-decision would re-merge and call back a run that has already ended.
    return {**base, "status": terminal_status, "error_class": error_class,
            "failure_reason": f"{reason} (run ended {error_class})", "decision_reason": reason}


def _repo_key(value) -> Optional[str]:
    """The `owner/repo` identity the gateway stores on approval records (shared.github_identity.resolve_repo_identity,
    the same parser the developer/release steps use), so the record and the workload doc compare exactly."""
    if not isinstance(value, str) or not value.strip():
        return None
    from shared.github_identity import resolve_repo_identity
    return resolve_repo_identity(value)[2]


def _merge_succeeded(res) -> bool:
    if not isinstance(res, dict):
        return res is not None and res is not False
    return res.get("merged") is not False and res.get("status") in (None, "MERGED", "ALREADY_UP_TO_DATE")


def _ledger_entry_for(record: Dict[str, Any], target_pid: str, vcs_kind: str, repo_target: str,
                      branch: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """FD-4P / FD-4BB: the PR ledger entry this approval may merge, or an error string. The entry must be the one
    StackVend wrote for exactly (vcs_kind, the WORKLOAD's repository, the approved branch) for this product (and
    trace), still mergeable; a GitHub record's pr_number, when present, must equal the ledger's."""
    lid = record.get("ledger_id")
    if not isinstance(lid, str) or not lid:
        return None, ("approval record has no PR ledger entry (created before the PR ledger, or not a change StackVend "
                      "created); nothing merged: merge on GitHub")
    repo_full = _repo_key(repo_target)
    try:
        if lid != vcs_ledger.ledger_id(vcs_kind, repo_full, branch):
            return None, "approval's ledger entry is not for this workload repository and branch; nothing merged"
        entry = vcs_ledger.get_entry(db, lid)
        trace = record.get("trace_id") if isinstance(record.get("trace_id"), str) and record.get("trace_id") else None
        vcs_ledger.check_entry(entry, provider=vcs_kind, repo_full_name=repo_full, branch=branch, product_id=target_pid,
                               trace_id=trace, mergeable=True)
    except vcs_ledger.LedgerError as e:
        return None, f"PR ledger refused the merge ({e.reason}): {e}"
    rec_pr = record.get("pr_number")
    if rec_pr is not None and rec_pr != entry.get("pr_number"):
        return None, f"approval names PR #{rec_pr}, the PR ledger names #{entry.get('pr_number')}; nothing merged"
    return entry, None


def _mark_ledger(entry: Dict[str, Any], state: str, **fields: Any) -> None:
    try:
        vcs_ledger.mark(db, entry["ledger_id"], state, **fields)
    except vcs_ledger.LedgerError as e:  # the approval record carries merge_status either way
        logger.critical(f"PR ledger state {state} not recorded for {entry.get('branch')}: {e}")


def _merge_workload_pr(record: Dict[str, Any], target_pid, branch: str, admin_email: str) -> Optional[str]:
    """Merge the approved change. Returns an error string (=> MERGE_FAILED, recorded; re-decidable after a fix), or
    None on success; raises MainMoved (Serverless Git FF-only 409) / ReleaseMergeFailed (an attempted GitHub merge
    failed), which end the waiting run typed. Never defaults or parses a PR number (the old `pr_num = 1` fallback
    merged PR #1 of the repo for every `/tree/<branch>` URL). Every refusal happens BEFORE the provider's merge.

    The provider kind is the workload doc's exact `vcs_provider` (absent => GITHUB, the default the gateway writes on
    the approval record and the CC uses everywhere); it is passed explicitly to the factory so the provider class
    and the checks below always agree. What may be merged comes only from the PR ledger (FD-4P / FD-4BB)."""
    if not isinstance(target_pid, str) or not target_pid or target_pid in PLATFORM_PSEUDO_WORKLOADS:
        return "platform pseudo-workload PRs are never merged from the Control Center"
    if VCSProviderFactory is None:
        return "VCS provider unavailable"
    if not isinstance(branch, str) or not branch or branch != branch.strip():
        return "approval record has no valid branch_name; nothing merged"
    w_data = _workload_doc(target_pid)
    repo_target = w_data.get("github_repo")
    if not isinstance(repo_target, str) or not repo_target:
        return f"workload '{target_pid}' has no registered github_repo; nothing merged"
    rec_repo = record.get("github_repo")
    if rec_repo and _repo_key(rec_repo) != _repo_key(repo_target):
        return f"approval names repository '{rec_repo}', but workload '{target_pid}' is '{repo_target}'; nothing merged"
    vcs_kind = str(w_data.get("vcs_provider") or VCS_GITHUB).strip().upper()
    if vcs_kind not in (VCS_GITHUB, VCS_SERVERLESS_GIT):
        return f"unsupported vcs_provider {w_data.get('vcs_provider')!r} on workload '{target_pid}'; nothing merged"
    if vcs_kind == VCS_GITHUB:
        pr_num = record.get("pr_number")
        if isinstance(pr_num, bool) or not isinstance(pr_num, int) or pr_num <= 0:
            return "approval record has no integer pr_number (PR identity is never parsed from a URL); nothing merged"
    entry, why = _ledger_entry_for(record, target_pid, vcs_kind, repo_target, branch)
    if why:
        return why
    target_branch = entry.get("base_branch")
    if not isinstance(target_branch, str) or not target_branch or branch == target_branch:
        return f"approved branch '{branch}' has no distinct ledger base branch ({target_branch!r}); nothing merged"
    commit_message = f"feat({target_pid}): HITL approved merge of '{branch}' into {target_branch} by {admin_email}"

    if vcs_kind == VCS_SERVERLESS_GIT:
        # Code RT F1(b): the git server has no PR objects and no forks; the provider ignores pr_number and, without an
        # explicit source_branch, would merge `_last_head_branch or "stage"`. Merge exactly the ledger branch into
        # the ledger base (handler.commit_and_open_pr cut it from default_branch or "main").
        # SERVERLESS-AUTOMERGE-SHA: pinned to the ledger head (the commit StackVend pushed and QA tested), like the
        # GitHub merge at the ledger SHA; a git server with the check refuses a branch that moved (SOURCE_MOVED).
        # A human approved this card, so an older git server without the check still merges (no capability gate).
        try:
            vcs = VCSProviderFactory.get_provider(provider_name=VCS_SERVERLESS_GIT, project_id=PROJECT_ID, product_id=target_pid)
            res = vcs.merge_pull_request(
                repo_target,
                pr_number=0,
                commit_message=commit_message,
                source_branch=entry["branch"],
                target_branch=target_branch,
                expected_source_sha=entry.get("head_sha") or None,
            )
        except ServerlessGitSourceMoved as moved:  # the branch moved after QA: GitHub's moved-head path
            _mark_ledger(entry, vcs_ledger.STATE_MERGE_FAILED, reason=f"SOURCE_MOVED: {moved}")
            raise ReleaseMergeFailed(f"merge refused: '{branch}' changed after QA tested it ({moved}); nothing merged, "
                                     "re-run the workload") from moved
        except ServerlessGitMergeConflict as conflict:  # FD-4BE: the git server's FF-only 409
            _mark_ledger(entry, vcs_ledger.STATE_MERGE_FAILED, reason=f"MAIN_MOVED: {conflict}")
            raise MainMoved(f"{target_branch} moved since '{branch}' was cut; nothing merged, re-run the workload") from conflict
        except Exception as m_err:  # noqa: BLE001
            _mark_ledger(entry, vcs_ledger.STATE_MERGE_FAILED, reason=f"{type(m_err).__name__}: {m_err}")
            return f"merge failed: {m_err}"
        if not _merge_succeeded(res):
            _mark_ledger(entry, vcs_ledger.STATE_MERGE_FAILED, reason="merge not completed")
            return f"merge not completed: {res.get('status') if isinstance(res, dict) else res}"
        _mark_ledger(entry, vcs_ledger.STATE_MERGED, merged_by=admin_email)
        record["merged_into"] = target_branch  # the ledger base just merged into (release stage summary)
        logger.info(f"HITL Approval merged '{branch}' into '{target_branch}' in {repo_target} (Serverless Git) for '{target_pid}'")
        return None

    try:
        vcs = VCSProviderFactory.get_provider(provider_name=VCS_GITHUB, project_id=PROJECT_ID, product_id=target_pid)
    except Exception as e:  # noqa: BLE001
        return f"VCS provider init failed: {e}"
    try:
        # The provider re-checks the live PR against the ledger identity (same repo, no forks, head ref, base ref,
        # head SHA) and merges at the ledger SHA; there is no PR-number or branch-name fallback.
        # require_provenance=False: a human approved this card. When the platform's GitHub identity is known the
        # provider still requires that it opened the PR (RT M1); when it cannot be resolved the human decides.
        # GHA-PLATFORM-MERGE-SKIP-ACTIONS: the approved run builds and applies this merge itself, so the merge commit
        # carries GitHub's skip directive (no Actions Day-2 deploy racing the apply). Serverless Git: unchanged.
        res = vcs.merge_pull_request(repo_target, expected=vcs_ledger.identity(entry),
                                     commit_message=vcs_ledger.github_platform_merge_message(commit_message),
                                     require_provenance=False)
    except Exception as m_err:  # noqa: BLE001 - PRIdentityMismatch, PRMergeNotCompleted, GitHub errors
        _mark_ledger(entry, vcs_ledger.STATE_MERGE_FAILED, reason=f"{type(m_err).__name__}: {m_err}")
        # GH-MERGE-CALLBACK: the merge was attempted and failed -> the waiting run is ended RELEASE_FAILED now.
        raise ReleaseMergeFailed(f"merge refused/failed: {m_err}") from m_err
    if not _merge_succeeded(res):
        _mark_ledger(entry, vcs_ledger.STATE_MERGE_FAILED, reason="merge not completed")
        if isinstance(res, dict) and res.get("merged") is False:
            raise ReleaseMergeFailed(f"merge not completed: {res.get('message')}")
        raise ReleaseMergeFailed(f"merge not completed: {res.get('status') if isinstance(res, dict) else res}")
    _mark_ledger(entry, vcs_ledger.STATE_MERGED, merged_by=admin_email)
    record["merged_into"] = target_branch  # the ledger base just merged into (release stage summary)
    logger.info(f"HITL Approval merged PR #{entry.get('pr_number')} ('{branch}') in {repo_target} for '{target_pid}'")
    return None


def _decommission_via_vending(target_pid, workload: Dict[str, Any], req: ApprovalDecisionRequest, admin_email: str,
                              base: Dict[str, Any], request: Optional[Request]) -> Dict[str, Any]:
    """Lane 18 S2 (plan §3.2, probe P11): the budget-breach DECOMMISSION runs the same path as the UI decommission --
    a human ADMIN approval minted for exactly this workload's project, then vending executes behind its destructive
    guard. It used to flip the ledger to DECOMMISSIONED without deleting anything. Failure -> EXECUTION_FAILED (HTTP
    502, re-decidable), the workload status is NOT changed. A non-ADMIN decider gets 403 (nothing happened)."""
    if not isinstance(target_pid, str) or not target_pid or target_pid in PLATFORM_PSEUDO_WORKLOADS:
        return {**base, "status": "EXECUTION_FAILED", "failure_reason": "approval names no tenant workload; nothing deleted"}
    if workload.get("is_castor") is True:
        return {**base, "status": "EXECUTION_FAILED", "failure_reason": "platform workload; nothing deleted"}
    target = destructive_actions.resolve_target(target_pid, workload)
    approval_id = None
    if target["project_id"] and target["project_number"]:
        try:
            approval_id = destructive_actions.mint_approval(
                request, action=destructive_actions.PROJECT_DECOMMISSION, product_id=target_pid,
                project_id=target["project_id"], project_number=target["project_number"],
                reason=req.reason or "Budget breach remediation: decommission")
        except destructive_actions.MintRefused as refused:
            raise HTTPException(status_code=refused.http_status, detail=f"{refused.code}: {refused.detail}")
    outcome = destructive_actions.call_vending(
        make_vending_request, f"/projects/{target_pid}/decommission",
        {"action_class": destructive_actions.PROJECT_DECOMMISSION, "approval_id": approval_id,
         "operator_email": admin_email},
        request=request, timeout=destructive_actions.DECOMMISSION_TIMEOUT_SECONDS)
    if not outcome.ok:
        destructive_actions.void_approval(approval_id, outcome)
        logger.warning(f"Budget-breach decommission of '{target_pid}' not executed: {outcome.code}: {outcome.detail}")
        return {**base, "status": "EXECUTION_FAILED", "failure_reason": f"{outcome.code}: {outcome.detail}",
                "pending_decision": "APPROVED", "destructive_approval_id": approval_id}
    vended = outcome.body
    logger.info(f"Budget breach remediation: vending decommissioned workload '{target_pid}' ({vended.get('crm_operation')})")
    return {**base, "status": "APPROVED", "destructive_approval_id": approval_id,
            "decommission_crm_operation": vended.get("crm_operation"),
            "decision_reason": req.reason or "Operator decommissioned workload following budget breach."}


# Same values as the MCP seam's INACTIVE_STATUSES (mcp-servers/*/managed_target_seam.py, a separate deploy, not
# importable here); tests/test_mcp_action_approvals.py checks they stay equal.
MCP_INACTIVE_STATUSES = frozenset({"DECOMMISSIONED", "QUARANTINED", "DELETED"})
MCP_DETAIL_MAX_LENGTH = 256
MCP_DETAIL_MAX_URI_LENGTH = 2048


def _decide_mcp_action(approval_id: str, record: Dict[str, Any], req: ApprovalDecisionRequest, request: Request,
                       now_iso: str, base: Dict[str, Any]) -> Dict[str, Any]:
    """APPROVAL-CONSUME-VIA-VENDING: a human ADMIN approves or rejects one exact MCP action. APPROVED mints a bound
    single-use approval for the ledger's project (never the card's own project field alone); REWORK is not valid."""
    if getattr(request.state, "user_role", None) != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Only an administrator can approve a platform action.")
    record.pop("mcp_approval_id", None)   # RT F2: never echo an id from the stored card
    action = record.get("mcp_action")
    # RT F1 / N1 / N2: the decision names what the administrator saw: the action and the fingerprint the CC computed
    # from the displayed arguments (_mcp_action_view), or no fingerprint for a malformed card. Both are recomputed
    # from the claimed record; a card changed since the display is refused (409, still decidable, nothing minted).
    # The card's stored digest field proves nothing here (it is attacker-writable); it is checked below only so
    # that vending's re-hash of the minted record agrees.
    binding = destructive_actions.clean_mcp_binding(action, record.get("mcp_binding"))
    shown_digest = destructive_actions.binding_digest(binding) if binding is not None else None
    seen = req.mcp_binding_digest if isinstance(req.mcp_binding_digest, str) and req.mcp_binding_digest else None
    if req.mcp_action != action or seen != shown_digest:
        raise HTTPException(status_code=409, detail=(
            "APPROVAL_CARD_CHANGED: the card changed since it was displayed; reload and decide again."))
    if req.decision == ApprovalStatus.REJECTED:
        return {**base, "status": "REJECTED", "decision_reason": req.reason or f"{action} rejected; nothing minted."}
    if req.decision != ApprovalStatus.APPROVED:
        raise HTTPException(status_code=400, detail="A platform action approval is APPROVED or REJECTED.")
    pid = record.get("product_id")
    if not (isinstance(pid, str) and pid) or pid in PLATFORM_PSEUDO_WORKLOADS or binding is None \
            or record.get("mcp_binding_digest") != shown_digest:
        raise HTTPException(status_code=409, detail="APPROVAL_CARD_MALFORMED: the card's action, workload or binding is invalid.")
    workload = _workload_doc(pid)
    if not workload or workload.get("is_castor") is True or workload.get("status") in MCP_INACTIVE_STATUSES:
        raise HTTPException(status_code=409, detail=f"APPROVAL_TARGET_UNKNOWN: workload '{pid}' is not an active tenant workload.")
    target = destructive_actions.resolve_target(pid, workload)
    if target["project_id"] != record.get("mcp_project_id"):
        raise HTTPException(status_code=409, detail=(
            f"APPROVAL_TARGET_MISMATCH: the card names project {record.get('mcp_project_id')!r}, the workload's "
            f"project is {target['project_id']!r}; nothing minted."))
    problem = destructive_actions.ledger_target_refusal(db, pid, target["project_id"])   # RT F4
    if problem:
        raise HTTPException(status_code=409, detail=f"APPROVAL_TARGET_UNKNOWN: {problem}; nothing minted.")
    minted_at = datetime.fromisoformat(now_iso)
    try:
        minted = destructive_actions.mint_approval(
            request, action=action, product_id=pid, project_id=target["project_id"],
            project_number=target["project_number"], reason=req.reason or f"MCP action card {approval_id}",
            now=minted_at, binding=binding, request_id=approval_id)
    except destructive_actions.MintRefused as refused:
        raise HTTPException(status_code=refused.http_status, detail=f"{refused.code}: {refused.detail}")
    expires = (minted_at + destructive_actions.APPROVAL_LIFETIME).isoformat()
    # RT F2: the id goes to the administrator in this answer only (record is the in-memory copy the response is built
    # from); the persisted card gets the expiry, never the id.
    record["mcp_approval_id"] = minted
    return {**base, "status": "APPROVED", "mcp_approval_expires_at": expires,
            "decision_reason": req.reason or f"{action} approved: single-use approval valid until {expires}."}


def _decide_compliance_downgrade(record: Dict[str, Any], req: ApprovalDecisionRequest, request: Request,
                                 admin_email: str, now_iso: str, base: Dict[str, Any]) -> Dict[str, Any]:
    """CP-11: only an ADMIN decides. APPROVED stores `to_profile` as the workload's selection, but only while the stored
    selection is still `from_profile` (otherwise 409: the card is stale). REJECTED keeps the stored profile. REWORK is
    not a valid decision here."""
    if getattr(request.state, "user_role", None) != UserRole.ADMIN:
        raise HTTPException(status_code=403, detail="Only an administrator can approve a compliance profile downgrade.")
    pid, from_p, to_p = record.get("product_id"), record.get("from_profile"), record.get("to_profile")
    if req.decision == ApprovalStatus.REJECTED:
        return {**base, "status": "REJECTED",
                "decision_reason": req.reason or f"Downgrade rejected; {from_p} stays the compliance profile."}
    if req.decision != ApprovalStatus.APPROVED:
        raise HTTPException(status_code=400, detail="A compliance profile downgrade is APPROVED or REJECTED.")
    if not (isinstance(pid, str) and pid and isinstance(from_p, str) and isinstance(to_p, str)
            and to_p in {p.value for p in ComplianceProfile}):
        raise HTTPException(status_code=409, detail="Malformed compliance downgrade approval record.")
    current = _workload_doc(pid).get("requested_compliance_profile")
    if current != from_p:
        raise HTTPException(status_code=409, detail=(
            f"The workload's compliance profile is now {current!r}, not {from_p!r}: this approval is stale."))
    db.collection("workloads").document(pid).set({
        "requested_compliance_profile": to_p,
        "compliance_profile_downgrade": {"from": from_p, "to": to_p, "approved_by": admin_email,
                                         "approved_at": now_iso, "approval_id": record.get("approval_id")},
    }, merge=True)
    return {**base, "status": "APPROVED",
            "decision_reason": req.reason or f"Compliance profile downgrade {from_p} -> {to_p} approved."}


def _decide_budget(record: Dict[str, Any], req: ApprovalDecisionRequest, admin_email: str, now_iso: str,
                   base: Dict[str, Any], request: Optional[Request] = None) -> Dict[str, Any]:
    target_pid = record.get("product_id")
    action = (req.action or "").upper()
    # The enforcer guard (apps/finops-enforcer, FD-4O) refuses the host and non-descendant projects; the project
    # comes from the workload doc only, never from the approval record.
    workload = _workload_doc(target_pid)
    target_project = workload.get("project_id")

    if action == "DECOMMISSION":
        return _decommission_via_vending(target_pid, workload, req, admin_email, base, request)

    if action == "MAINTAIN_QUARANTINE" or req.decision == ApprovalStatus.REJECTED:
        logger.info(f"Operator maintained quarantine for '{target_pid}'")
        return {**base, "status": "REJECTED", "decision_reason": req.reason or "Operator maintained compute quarantine."}

    # C10: the restore runs FIRST (the enforcer job, verified by its run record); the ceiling change and ACTIVE are
    # written only when it restored. A failure is EXECUTION_FAILED with the typed reason (the card stays decidable).
    if action == "RESTORE_BUFFER":
        spend = float(record.get("current_spend_usd", 40.0) or 40.0)
        budget = float(record.get("budget_ceiling_usd", 40.0) or 40.0)
        buffer_cap = round(max(spend, budget) * 1.15, 2)
        failed = _restore_via_enforcer(target_pid, target_project, base)
        if failed is not None:
            return failed
        db.collection("workloads").document(target_pid).set({"buffer_ceiling_usd": buffer_cap, "status": "ACTIVE"}, merge=True)
        return {**base, "status": "APPROVED", "decision_reason": f"Restored with temporary buffer ceiling ${buffer_cap:.2f} (+15%)."}

    new_budget = req.new_budget_usd
    if not new_budget:
        proj_spend = float(record.get("projected_monthly_spend_usd", 0.0) or 0.0)
        curr_spend = float(record.get("current_spend_usd", 40.0) or 40.0)
        new_budget = round(max(proj_spend, curr_spend * 1.5, 50.0), 2)
    failed = _restore_via_enforcer(target_pid, target_project, base)
    if failed is not None:
        return failed
    db.collection("workloads").document(target_pid).set({
        "budget_ceiling_monthly_usd": new_budget,
        "buffer_ceiling_usd": None,
        "status": "ACTIVE",
    }, merge=True)
    return {**base, "status": "APPROVED", "decision_reason": f"Budget increased to ${new_budget:.2f} and services restored."}
