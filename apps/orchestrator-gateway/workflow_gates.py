"""
Lane 17 (FD-4AJ / FD-4R / FD-4AG): deterministic workflow-gate decisions used by the gateway routes that
`workflows/main_orchestrator.yaml` calls. Plan: docs/planning/wave2-lane17-workflow-integrity-plan.md (rev 2) §4.

Every decision here is a pure function of typed inputs (no I/O), so the YAML only routes and the decision is tested
in Python. No string matching on free text: inputs are booleans, enums and exact ids.
"""

import json
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------------------------- pre-build gate (§4.1)
GATE_PASS = "PASS"
GATE_AWAIT_APPROVAL = "AWAIT_APPROVAL"

REASON_COMPLIANCE_REQUIRES_APPROVAL = "COMPLIANCE_REQUIRES_APPROVAL"
REASON_COMPLIANCE_POLICY_CONFLICT = "COMPLIANCE_POLICY_CONFLICT"
REASON_OPERATOR_REQUESTED = "OPERATOR_REQUESTED"
REASON_FINOPS_UNAVAILABLE = "FINOPS_UNAVAILABLE"
REASON_FINOPS_INCOMPLETE = "FINOPS_INCOMPLETE"
REASON_FINOPS_THRESHOLD = "FINOPS_THRESHOLD"
REASON_POLICY_HARVEST_FAILED = "POLICY_HARVEST_FAILED"
REASON_ACCESS_WIDENED = "ACCESS_WIDENED"  # L19-F4: an admin widened the workload's access record since last approval
# settings-toggles: a compliance profile advisory while governance.strict_compliance_gates is on.
REASON_COMPLIANCE_PROFILE_ADVISORY = "COMPLIANCE_PROFILE_ADVISORY"
# ACCESS-INTERNAL-SERVICE-ADVISORY (owner 11-10, option a): the plan leaves a push-only Cloud Run service of a Public
# workload reachable from the internet (compliance `access_advisories`, ACCESS.INTERNAL_SERVICE_PUBLIC). Like
# FINOPS_THRESHOLD it always waits for a human; no setting turns it off.
REASON_ACCESS_INTERNAL_SERVICE_PUBLIC = "ACCESS_INTERNAL_SERVICE_PUBLIC"
# SECRET-INITIAL-VERSION (owner 11-10): the plan's service topology has a Secret Manager secret the platform creates
# without a value (initial_value "operator", or not stated), so the app cannot read it until an operator adds one.
REASON_SECRET_CREATED_EMPTY = "SECRET_CREATED_EMPTY"
# The one policy point for that reason. Owner 11-10: "warning-only" (the pause was considered and declined for launch):
# False = no reason is added, so such a plan does not wait; the advisories are still computed, logged and kept on the
# persisted gate decision (`prebuild_gate.secret_advisories`) and on the approval record, and the card shows them
# whenever another reason pauses the run. True would make such a plan wait for approval (SECRET_CREATED_EMPTY).
SECRET_ADVISORY_PAUSES_PLAN = False

# L19-F4: the one-shot flag a widening PATCH /api/workloads/{pid}/access sets on workloads/{pid}
# (shared.access_policy.ACCESS_WIDENING_APPROVAL_FIELD; a test pins the equality). Present (non-null) = pending.
ACCESS_WIDENING_APPROVAL_FIELD = "access_widening_approval"

PRE_BUILD_REASONS = (
    REASON_COMPLIANCE_REQUIRES_APPROVAL,
    REASON_COMPLIANCE_POLICY_CONFLICT,
    REASON_OPERATOR_REQUESTED,
    REASON_FINOPS_UNAVAILABLE,
    REASON_FINOPS_INCOMPLETE,
    REASON_FINOPS_THRESHOLD,
    REASON_POLICY_HARVEST_FAILED,
    REASON_ACCESS_WIDENED,
    REASON_COMPLIANCE_PROFILE_ADVISORY,
    REASON_ACCESS_INTERNAL_SERVICE_PUBLIC,
    REASON_SECRET_CREATED_EMPTY,
)

# Plan-approval outcomes the Control Center delivers on the callback (apps/control-center/routes/approvals.py).
PLAN_DECISIONS = ("APPROVED", "REJECTED", "REWORK")
# A persisted pre-build gate that lets a RESUME_DEVELOPER run skip the architect / FinOps / plan gate (RT F1).
RESUMABLE_GATE_STATUSES = ("PASS", "APPROVED")


def evaluate_pre_build_gate(
    *,
    compliance: Optional[Dict[str, Any]],
    finops: Optional[Dict[str, Any]],
    finops_error: Optional[str] = None,
    policy_harvest_status: Optional[str] = None,
    operator_requested: bool = False,
    access_widening_pending: bool = False,
    advisories_block: bool = False,
    secret_advisories: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[str, List[str]]:
    """Returns (decision, reasons). Any reason -> AWAIT_APPROVAL (a human decides); none -> PASS.

    - compliance missing                        -> ValueError (the route answers 422; never a silent pass)
    - compliance.requires_human_approval True   -> COMPLIANCE_REQUIRES_APPROVAL
    - compliance.has_policy_conflicts True      -> COMPLIANCE_POLICY_CONFLICT
    - operator_requested True                   -> OPERATOR_REQUESTED (spec / CC `require_plan_approval`)
    - FinOps errored or returned no body        -> FINOPS_UNAVAILABLE   (AG-3: was "LOW, no approval")
    - FinOps body without a bool `requires_human_approval` -> FINOPS_INCOMPLETE (AG-4: was a KeyError)
    - FinOps requires_human_approval True       -> FINOPS_THRESHOLD     (AG-1/AG-2: every channel, a real wait)
    - policy_harvest_status == "FAILED"         -> POLICY_HARVEST_FAILED (AJ-16: org policy was not evaluated)
    - access_widening_pending True              -> ACCESS_WIDENED (L19-F4: widening PATCH not yet approved)
    - advisories_block True and compliance.profile_advisories a non-empty list
                                                -> COMPLIANCE_PROFILE_ADVISORY (settings-toggles:
                                                   governance.strict_compliance_gates; the profile is unchanged)
    - compliance.access_advisories a non-empty list
                                                -> ACCESS_INTERNAL_SERVICE_PUBLIC (ACCESS-INTERNAL-SERVICE-ADVISORY:
                                                   the operator sees the warning on the plan card; the list itself
                                                   is checked by `access_advisories_of` in the route)
    - secret_advisories a non-empty list        -> SECRET_CREATED_EMPTY (SECRET-INITIAL-VERSION: the route builds
                                                   it from the architect's topology, `secret_advisories`), while
                                                   SECRET_ADVISORY_PAUSES_PLAN is True
    """
    if not isinstance(compliance, dict):
        raise ValueError("compliance decision is required for the pre-build gate")
    reasons: List[str] = []
    if compliance.get("requires_human_approval") is True:
        reasons.append(REASON_COMPLIANCE_REQUIRES_APPROVAL)
    if compliance.get("has_policy_conflicts") is True:
        reasons.append(REASON_COMPLIANCE_POLICY_CONFLICT)
    if operator_requested is True:
        reasons.append(REASON_OPERATOR_REQUESTED)
    if finops_error or not isinstance(finops, dict) or not finops:
        reasons.append(REASON_FINOPS_UNAVAILABLE)
    else:
        flag = finops.get("requires_human_approval")
        if not isinstance(flag, bool):
            reasons.append(REASON_FINOPS_INCOMPLETE)
        elif flag:
            reasons.append(REASON_FINOPS_THRESHOLD)
    if policy_harvest_status == "FAILED":
        reasons.append(REASON_POLICY_HARVEST_FAILED)
    if access_widening_pending is True:
        reasons.append(REASON_ACCESS_WIDENED)
    advisories = compliance.get("profile_advisories")
    if advisories_block is True and isinstance(advisories, list) and advisories:
        reasons.append(REASON_COMPLIANCE_PROFILE_ADVISORY)
    access_advisories = compliance.get("access_advisories")
    if isinstance(access_advisories, list) and access_advisories:
        reasons.append(REASON_ACCESS_INTERNAL_SERVICE_PUBLIC)
    if SECRET_ADVISORY_PAUSES_PLAN and isinstance(secret_advisories, list) and secret_advisories:
        reasons.append(REASON_SECRET_CREATED_EMPTY)
    return (GATE_AWAIT_APPROVAL if reasons else GATE_PASS), reasons


# SECRET-INITIAL-VERSION (owner 11-10): one plan-time warning per Secret Manager secret of the architect's validated
# service topology that the platform creates without a value. Typed facts only: the resource type and its exact
# `initial_value` (shared.service_topology); never the secret's name or the specification text.
SECRET_ADVISORY_OPERATOR = "SECRET.OPERATOR_VALUE_REQUIRED"     # initial_value "operator"
SECRET_ADVISORY_UNSTATED = "SECRET.VALUE_SOURCE_UNSTATED"       # no initial_value (a plan written before the field)
SECRET_ADVISORY_CODES = (SECRET_ADVISORY_OPERATOR, SECRET_ADVISORY_UNSTATED)
MAX_SECRET_ADVISORIES = 50
REASON_SECRET_ADVISORY_FACTS_UNAVAILABLE = "SECRET_ADVISORY_FACTS_UNAVAILABLE"
REASON_SECRET_ADVISORY_FACTS_INVALID = "SECRET_ADVISORY_FACTS_INVALID"


def secret_advisories(topology: Any) -> List[Dict[str, Any]]:
    """The warnings for a `shared.service_topology.ValidatedTopology` (None -> []), in resource order: every secret
    whose initial_value is not "random" (the platform generates only those). Each names the topology resource, the
    services that read it and one plain sentence. Raises ValueError when the topology is not a validated one."""
    if topology is None:
        return []
    try:
        values = topology.secret_initial_values()
        resources = list(topology.intent.resources)
    except AttributeError as e:
        raise ValueError(f"the service topology is not a validated topology: {e}") from None
    out: List[Dict[str, Any]] = []
    for r in resources:
        logical = getattr(r, "logical_name", None)
        if logical not in values or values[logical] == "random":
            continue
        services = sorted({c.service for c in (getattr(r, "consumers", None) or [])})
        readers = ", ".join(services) if services else "the app"
        # red-team F9: what the platform does, not a claim about the workload's own infrastructure (agent-written
        # Terraform may add a version itself)
        if values[logical] == "operator":
            code = SECRET_ADVISORY_OPERATOR
            message = (f"The platform creates {logical} without a value: it holds a credential an outside system "
                       f"issues, so unless the workload's own infrastructure adds one, an operator must add its value "
                       f"in Secret Manager (a new version of the secret) before {readers} can read it.")
        else:
            code = SECRET_ADVISORY_UNSTATED
            message = (f"The platform creates {logical} without a value (the plan does not say who supplies it): "
                       f"unless the workload's own infrastructure adds one, add its value in Secret Manager (a new "
                       f"version of the secret) before {readers} can read it, or ask for rework so the plan states "
                       f"it.")
        out.append({"code": code, "secret": logical, "services": services, "message": message})
    return out


def capped_secret_advisories(advisories: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], int]:
    """(the first MAX_SECRET_ADVISORIES, how many more): a large plan still pauses with a count, never fails."""
    return list(advisories[:MAX_SECRET_ADVISORIES]), max(0, len(advisories) - MAX_SECRET_ADVISORIES)


# ACCESS-INTERNAL-SERVICE-ADVISORY: the compliance stage's typed access warnings (compliance_agent/access_advisory.py
# CODE; a test pins the equality), copied onto the plan approval card; a non-empty list is the gate reason
# ACCESS_INTERNAL_SERVICE_PUBLIC.
ACCESS_ADVISORY_CODES = ("ACCESS.INTERNAL_SERVICE_PUBLIC",)
_ACCESS_ADVISORY_TEXT_FIELDS = ("code", "service", "message")
_ACCESS_ADVISORY_LIST_FIELDS = ("delivered_by", "push_topics", "push_paths")
MAX_ACCESS_ADVISORIES = 50


def access_advisories_of(compliance: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The compliance decision's `access_advisories`, checked and copied for the approval card. Absent (a decision
    from before this field) -> []. Present but malformed (not a list, an item that is not an object with an exact code,
    a service and a message, list fields that are not lists of strings, too many items) -> ValueError: the gateway's
    own compliance route wrote it, so a bad value is a contract break, never dropped silently."""
    if not isinstance(compliance, dict) or compliance.get("access_advisories") is None:
        return []
    raw = compliance["access_advisories"]
    if not isinstance(raw, list) or len(raw) > MAX_ACCESS_ADVISORIES:
        raise ValueError("compliance.access_advisories is not a list of at most "
                         f"{MAX_ACCESS_ADVISORIES} advisories")
    out: List[Dict[str, Any]] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict) or item.get("code") not in ACCESS_ADVISORY_CODES:
            raise ValueError(f"compliance.access_advisories[{i}] has no known code")
        if not all(isinstance(item.get(k), str) and item[k] for k in _ACCESS_ADVISORY_TEXT_FIELDS):
            raise ValueError(f"compliance.access_advisories[{i}] needs a service and a message")
        copy: Dict[str, Any] = {k: item[k] for k in _ACCESS_ADVISORY_TEXT_FIELDS}
        for k in _ACCESS_ADVISORY_LIST_FIELDS:
            v = item.get(k, [])
            if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
                raise ValueError(f"compliance.access_advisories[{i}].{k} is not a list of strings")
            copy[k] = list(v)
        out.append(copy)
    return out


def access_advisories_omitted_of(compliance: Optional[Dict[str, Any]]) -> int:
    """How many advisories the compliance stage counted beyond the MAX_ACCESS_ADVISORIES it sent (it caps at the
    source). Absent -> 0. Not a non-negative int, or a count without a full list -> ValueError (contract break)."""
    if not isinstance(compliance, dict) or compliance.get("access_advisories_omitted") is None:
        return 0
    n = compliance["access_advisories_omitted"]
    if isinstance(n, bool) or not isinstance(n, int) or n < 0:
        raise ValueError("compliance.access_advisories_omitted is not a non-negative integer")
    listed = compliance.get("access_advisories")
    if n and (not isinstance(listed, list) or len(listed) != MAX_ACCESS_ADVISORIES):
        raise ValueError("compliance.access_advisories_omitted counts advisories beyond a list that is not full")
    return n


def numeric_cost(finops: Optional[Dict[str, Any]]) -> float:
    """The FinOps monthly delta as a number for the approval card (0.0 when absent / not numeric)."""
    if not isinstance(finops, dict):
        return 0.0
    v = finops.get("monthly_cost_delta_usd")
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return 0.0
    return float(v)


COST_NOT_EVALUATED = "not evaluated"


def cost_display(finops: Optional[Dict[str, Any]]) -> str:
    """Bundle RT F5: the FinOps display string for the approval card (`monthly_cost_estimate`, e.g. "+$5.00/mo"),
    or "not evaluated" when FinOps gave none. Same wording as the workflow's Doc callout."""
    if not isinstance(finops, dict):
        return COST_NOT_EVALUATED
    v = finops.get("monthly_cost_estimate")
    return v if isinstance(v, str) and v.strip() else COST_NOT_EVALUATED


def plan_approval_id(trace_id: str, rework_cycle: int) -> str:
    """Deterministic id (RT F7): a retried POST finds the same record instead of writing a second one."""
    return f"appr-plan-{trace_id}-{int(rework_cycle)}"


def quota_approval_id(trace_id: str, recheck_n: int) -> str:
    return f"appr-quota-{trace_id}-{int(recheck_n)}"


# ---------------------------------------------------------------------------------------------- DEPLOY_ONLY gate (§4.4)
def deploy_only_allowed(
    *,
    branch: str,
    workload: Optional[Dict[str, Any]],
    ledger_entries: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[bool, str]:
    """RT F2: a DEPLOY_ONLY re-apply may only target reviewed code.

    Allowed when `branch` equals the workload's default branch (`workloads/{pid}.default_branch`, "main" when the
    field is absent), or when the release ledger (lane 16, once it lands) holds exactly one entry for this branch with
    state MERGED. Exact equality only. Returns (allowed, reason).
    """
    if not isinstance(branch, str) or not branch:
        return False, "BRANCH_MISSING"
    default_branch = "main"
    if isinstance(workload, dict) and isinstance(workload.get("default_branch"), str) and workload["default_branch"]:
        default_branch = workload["default_branch"]
    if branch == default_branch:
        return True, "DEFAULT_BRANCH"
    entries = [e for e in (ledger_entries or []) if isinstance(e, dict) and e.get("branch") == branch]
    if len(entries) == 1 and entries[0].get("state") == "MERGED":
        return True, "LEDGER_MERGED"
    if len(entries) > 1:
        return False, "LEDGER_AMBIGUOUS"
    return False, "BRANCH_NOT_REVIEWED"


# ---------------------------------------------------------------------------------------------- resume (§4.3, RT F1)
def resume_outcome_problems(
    *,
    product_id: str,
    compliance_record: Optional[Dict[str, Any]],
    prebuild_gate: Optional[Dict[str, Any]],
) -> List[str]:
    """Reasons a RESUME_DEVELOPER run may NOT reuse the prior full build's gate decisions. Empty list = reusable.

    The persisted pre-build gate must be PASS or APPROVED, and the compliance decision must come from the SAME
    prior trace (exact trace_id equality) and the same product.
    """
    problems: List[str] = []
    if not isinstance(prebuild_gate, dict) or not prebuild_gate:
        return ["NO_PREBUILD_GATE"]
    if not isinstance(compliance_record, dict) or not compliance_record:
        return ["NO_COMPLIANCE_RECORD"]
    if prebuild_gate.get("status") not in RESUMABLE_GATE_STATUSES:
        problems.append("PREBUILD_GATE_NOT_PASSED")
    gate_trace = prebuild_gate.get("trace_id")
    if not isinstance(gate_trace, str) or not gate_trace or compliance_record.get("trace_id") != gate_trace:
        problems.append("TRACE_MISMATCH")
    if compliance_record.get("product_id") != product_id or prebuild_gate.get("product_id") != product_id:
        problems.append("PRODUCT_MISMATCH")
    return problems


# RESUME-DEVELOPER-TASK-DAG (register row): the compliance-enriched Task DAG of a full build is kept for the trace in
# workloads/{pid}/prebuild_task_dags/{trace} (its own document: the DAG is not decision data and can be large), so a
# RESUME_DEVELOPER run, which has no architect or compliance stage, gives the QA adherence judge the real plan.
# The Control Center's resume check reads the same document: keep its mirror in routes/workloads.py equal
# (tests/test_resume_developer_task_dag.py).
TASK_DAG_COLLECTION = "prebuild_task_dags"
TASK_DAG_STORED = "STORED"
TASK_DAG_EMPTY = "EMPTY"
TASK_DAG_TOO_LARGE = "TOO_LARGE"
# Firestore's document limit is 1 MiB (1,048,576 bytes); the margin covers the other fields and the document name.
MAX_PERSISTED_TASK_DAG_BYTES = 900_000
# pipeline_executions/{resume trace}.resume_prebuild_gate: the gate decision /agent/resume/outcome validated for this
# resume, the only gate QA takes the DAG from (workloads/{pid}.last_prebuild_gate can move on during the run).
RESUME_GATE_FIELD = "resume_prebuild_gate"
NO_PERSISTED_TASK_DAG = "NO_PERSISTED_TASK_DAG"
PERSISTED_TASK_DAG_TOO_LARGE = "TASK_DAG_TOO_LARGE"


def task_dag_record(*, product_id: str, trace_id: str, rework_cycle: int, task_dag: List[Dict[str, Any]],
                    recorded_at: str) -> Dict[str, Any]:
    """The document that keeps one gate decision's Task DAG. A DAG too large for one document keeps no DAG, only the
    typed status: a full build carries its DAG in the workflow and does not need this copy, and a later resume stops
    on the status (`persisted_task_dag`). An empty DAG is recorded as such, so it replaces an earlier cycle's DAG."""
    encoded = json.dumps(task_dag, separators=(",", ":"))  # ASCII only: the length is the size in bytes
    if not task_dag:
        status = TASK_DAG_EMPTY
    elif len(encoded) > MAX_PERSISTED_TASK_DAG_BYTES:
        status = TASK_DAG_TOO_LARGE
    else:
        status = TASK_DAG_STORED
    return {"product_id": product_id, "trace_id": trace_id, "rework_cycle": rework_cycle, "status": status,
            "task_count": len(task_dag), "size_bytes": len(encoded),
            "task_dag_json": encoded if status == TASK_DAG_STORED else "", "recorded_at": recorded_at}


def persisted_task_dag(record: Any, *, product_id: str, prebuild_gate: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """(the DAG, None), or ([], the problem) when the record is not the usable DAG of exactly this gate decision
    (same product, trace and rework cycle). Nothing is ever defaulted: an adherence verdict needs the real plan."""
    gate = prebuild_gate if isinstance(prebuild_gate, dict) else {}
    if (not isinstance(record, dict) or not record or record.get("product_id") != product_id
            or record.get("trace_id") != gate.get("trace_id") or record.get("rework_cycle") != gate.get("rework_cycle")):
        return [], NO_PERSISTED_TASK_DAG
    if record.get("status") == TASK_DAG_TOO_LARGE:
        return [], PERSISTED_TASK_DAG_TOO_LARGE
    if record.get("status") != TASK_DAG_STORED:
        return [], NO_PERSISTED_TASK_DAG
    try:
        task_dag = json.loads(record.get("task_dag_json"))
    except (TypeError, ValueError):
        return [], NO_PERSISTED_TASK_DAG
    if not isinstance(task_dag, list) or not task_dag or not all(isinstance(t, dict) for t in task_dag):
        return [], NO_PERSISTED_TASK_DAG
    return task_dag, None


DEVELOPER_INGRESS_BOOL_FIELDS = ("allow_unauthenticated", "enable_direct_iap", "domain_restricted_sharing")


def developer_decision_problems(record: Any, *, product_id: str, trace_id: str) -> List[str]:
    """FD-4R R-6: reasons a persisted compliance decision may NOT feed the developer's ingress flags. Empty = usable.

    The record must be the decision of this product and of the trace it was looked up by, and every ingress field
    must be present with its exact type (a missing or mistyped flag is never defaulted: the run stops instead).
    """
    if not isinstance(record, dict) or not record:
        return ["NO_COMPLIANCE_RECORD"]
    problems: List[str] = []
    if record.get("product_id") != product_id:
        problems.append("PRODUCT_MISMATCH")
    if record.get("trace_id") != trace_id:
        problems.append("TRACE_MISMATCH")
    for field in DEVELOPER_INGRESS_BOOL_FIELDS:
        if not isinstance(record.get(field), bool):
            problems.append(f"FIELD_INVALID:{field}")
    domains = record.get("allowed_domains")
    if not isinstance(domains, list) or not all(isinstance(d, str) for d in domains):
        problems.append("FIELD_INVALID:allowed_domains")
    return problems


def compliance_ingress_view(record: Dict[str, Any]) -> Dict[str, Any]:
    """The ingress fields a resumed developer run needs, read from the persisted compliance record.

    Missing fields take the restrictive value (private, IAP off, no domain restriction list) -- never public.
    """
    allow = record.get("allow_unauthenticated")
    return {
        "allow_unauthenticated": allow if isinstance(allow, bool) else False,
        "enable_direct_iap": record.get("enable_direct_iap") is True,
        "domain_restricted_sharing": record.get("domain_restricted_sharing") is True,
        "allowed_domains": [d for d in (record.get("allowed_domains") or []) if isinstance(d, str)],
        "compliance_profile": record.get("compliance_profile"),
        "trace_id": record.get("trace_id"),
    }
