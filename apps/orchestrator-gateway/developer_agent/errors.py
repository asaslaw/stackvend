"""
Typed developer-stage failures (Wave 2 lane 19, L19-3a; owner register row 27a: delete the template fallback,
fail loudly).

``DeveloperStageError(error_class)`` is raised instead of rendering a template app or swarm stub files when no LLM
produced code. Lane 13 (FD-4F) maps it to a stage ``FAILED`` event; today the gateway's ``guaranteed_callback_scope``
already reports any exception from the developer stage as FAILED. When Step 1's ``shared.diagnostics.StageError``
lands, this class can become a subclass of it with the same ``error_class`` strings.

Definitions (plan §2.2, Fable RT F6):
* ``LLM_UNAVAILABLE``    there is no client, or every candidate model call ended in a 429 / 404 / transport error
                         with NO model returning a response.
* ``LLM_OUTPUT_INVALID`` at least one model returned a response and none yielded a usable ``files`` dict
                         (mixed outcomes count here: a model did answer).
* ``LLM_STAGE_BUDGET_EXHAUSTED`` (SLOW-CALL-FALLBACK) the stage deadline leaves no room for another model call
                         (llm_transport.LlmStageBudgetExhausted). A fallback chain whose every call timed out or
                         answered a transient status is ``LLM_UNAVAILABLE`` (llm_transport.LlmFallbackExhausted).
* ``SWARM_TOKEN_ENVELOPE_EXCEEDED`` (RT14-23) the swarm's FinOps circuit breaker tripped
                         (swarm_schemas.FinOpsCircuitBreakerError); never a fallback to the single-turn path.
* ``WORKLOAD_RECORD_UNREADABLE`` (RT14-28) ``workloads/{pid}`` could not be read, so the base branch / VCS provider of
                         the commit is unknown; never "main" by guess.

Access-policy classes (FD-4I, lane 19 L19-2; plan §2.1). All are raised BEFORE any LLM call and are operator (HITL)
outcomes, never LLM repair: the LLM cannot invent who may use a workload.
* ``ACCESS_POLICY_INCOMPLETE``   a private workload (PRIVATE_IAM / PRIVATE_IAP) has no invoker principals.
* ``ACCESS_POLICY_INVALID``      the access record (request ``access`` or ``workloads/{pid}.access``) fails validation.
* ``ACCESS_POLICY_REQUIRED``     no access record and no typed ingress decision (compliance flags) to derive a mode from.
* ``ACCESS_POLICY_UNAVAILABLE``  ``workloads/{pid}`` could not be read, so whether a record exists is unknown.
* ``ACCESS_ORG_POLICY_CONFLICT`` the record says PUBLIC_APP but the folder's org policy (domain-restricted sharing)
                                 forbids ``allUsers``.
* ``ACCESS_COMPLIANCE_CONFLICT`` the record says PUBLIC_APP but the run's compliance decision requires private ingress
                                 (``enable_direct_iap is True`` or ``allow_unauthenticated is False``); the most
                                 restrictive answer wins, so a contradiction stops for an operator (L19-11 RT F5).
* ``ACCESS_WIDENING_UNAPPROVED`` ``workloads/{pid}.access_widening_approval`` is still pending: an administrator widened
                                 the access record and no plan approval has cleared it yet (a run that passed the
                                 pre-build gate before the PATCH, or a resume). Owner decision L19-F4.
"""

from __future__ import annotations

LLM_UNAVAILABLE = "LLM_UNAVAILABLE"
LLM_OUTPUT_INVALID = "LLM_OUTPUT_INVALID"
# Lane 14 PR-0b (developer_agent/compliance_profile.py): the compliance profile cannot be rendered into IaC the plan
# gate accepts (unknown profile / platform region outside the profile). Raised before any LLM call.
# COMPLIANCE_DECISION_UNAVAILABLE: the stored decision is unreadable (owner Q1 = fail closed, 10-18) or the
# gateway-resolved compliance record contradicts its own profile (integration with FD-4R R-6).
# COMPLIANCE_DECISION_STALE: the stored decision was made for another profile selection (the plan gate's
# DECISION_STALE; compliance-profile-explicit RT F1), direct-caller path only.
COMPLIANCE_PROFILE_UNKNOWN = "COMPLIANCE_PROFILE_UNKNOWN"
COMPLIANCE_REGION_NOT_ALLOWED = "COMPLIANCE_REGION_NOT_ALLOWED"
COMPLIANCE_DECISION_UNAVAILABLE = "COMPLIANCE_DECISION_UNAVAILABLE"
COMPLIANCE_DECISION_STALE = "COMPLIANCE_DECISION_STALE"
COMPLIANCE_ERROR_CLASSES = frozenset({COMPLIANCE_PROFILE_UNKNOWN, COMPLIANCE_REGION_NOT_ALLOWED,
                                      COMPLIANCE_DECISION_UNAVAILABLE, COMPLIANCE_DECISION_STALE})
ACCESS_POLICY_INCOMPLETE = "ACCESS_POLICY_INCOMPLETE"
ACCESS_POLICY_INVALID = "ACCESS_POLICY_INVALID"
ACCESS_POLICY_REQUIRED = "ACCESS_POLICY_REQUIRED"
ACCESS_POLICY_UNAVAILABLE = "ACCESS_POLICY_UNAVAILABLE"
ACCESS_ORG_POLICY_CONFLICT = "ACCESS_ORG_POLICY_CONFLICT"
ACCESS_COMPLIANCE_CONFLICT = "ACCESS_COMPLIANCE_CONFLICT"
ACCESS_WIDENING_UNAPPROVED = "ACCESS_WIDENING_UNAPPROVED"
ACCESS_ERROR_CLASSES = frozenset({ACCESS_POLICY_INCOMPLETE, ACCESS_POLICY_INVALID, ACCESS_POLICY_REQUIRED,
                                  ACCESS_POLICY_UNAVAILABLE, ACCESS_ORG_POLICY_CONFLICT, ACCESS_COMPLIANCE_CONFLICT,
                                  ACCESS_WIDENING_UNAPPROVED})
# FD-4AL: no platform region is configured (settings `orchestration.default_gcp_region`, $REGION, $DEFAULT_REGION);
# raised before any LLM call (terraform_engine.resolve_workload_region). Never a literal region.
REGION_UNAVAILABLE = "REGION_UNAVAILABLE"
# FD-7M-a: the workload's recorded region (workloads/{pid}.region) is not in the install's approved deployable regions
# (shared.settings.workload_region); raised before any LLM call (terraform_engine.resolve_workload_region). Same string
# as shared.settings.REGION_NOT_APPROVED and the terraform server's deploy refusal. Never another region.
REGION_NOT_APPROVED = "REGION_NOT_APPROVED"
# FD-4CX: a private workload (PRIVATE_IAM / PRIVATE_IAP) would vendor a registered (non-golden) module whose own files
# grant public access (shared/module_exposure.py). Raised at assembly, after the draft, before any commit; operator
# outcome (fix the module in Settings > Modules, or choose Public), never LLM repair. Same string as the Express stop
# and the Control Center registration refusal (shared.module_exposure.REGISTERED_MODULE_PUBLIC_EXPOSURE).
REGISTERED_MODULE_PUBLIC_EXPOSURE = "REGISTERED_MODULE_PUBLIC_EXPOSURE"
# SLOW-CALL-FALLBACK (owner 11-13): the stage's remaining budget (the caller's `deadline`) leaves no room for another
# model call (llm_transport.LlmStageBudgetExhausted). A chain of timed-out / transient calls with no answer stays
# LLM_UNAVAILABLE (llm_transport.LlmFallbackExhausted, reason LLM_FALLBACK_EXHAUSTED, every attempt listed).
LLM_STAGE_BUDGET_EXHAUSTED = "LLM_STAGE_BUDGET_EXHAUSTED"
# RT14-08: a Firestore collection id, field path or query scope the app code queries is outside the grammar the platform
# renders into infra/workload/indexes.tf (terraform_engine.FirestoreIndexIdInvalid). Raised at assembly (composite
# indexes), after the draft, before any commit; the index is never rendered and never skipped silently.
FIRESTORE_INDEX_ID_INVALID = "FIRESTORE_INDEX_ID_INVALID"
# RT14-23 (owner 11-14): the swarm's cumulative tokens passed 110% of the build's token envelope (Settings > Developer
# Swarm Token Ceiling). The build stops here; it never continues on the unmetered single-turn path.
SWARM_TOKEN_ENVELOPE_EXCEEDED = "SWARM_TOKEN_ENVELOPE_EXCEEDED"
# RT14-28 (owner 11-14): workloads/{product_id} could not be read, so the workload's base branch and VCS provider are
# unknown. Never "main" / the default provider by guess: the stage stops.
WORKLOAD_RECORD_UNREADABLE = "WORKLOAD_RECORD_UNREADABLE"
ERROR_CLASSES = (frozenset({LLM_UNAVAILABLE, LLM_OUTPUT_INVALID, REGION_UNAVAILABLE, REGION_NOT_APPROVED,
                             REGISTERED_MODULE_PUBLIC_EXPOSURE, LLM_STAGE_BUDGET_EXHAUSTED,
                             FIRESTORE_INDEX_ID_INVALID, SWARM_TOKEN_ENVELOPE_EXCEEDED,
                             WORKLOAD_RECORD_UNREADABLE})
                 | COMPLIANCE_ERROR_CLASSES | ACCESS_ERROR_CLASSES)


class DeveloperStageError(RuntimeError):
    """The developer stage cannot produce code. Never caught to fall back to generated stand-in files."""

    def __init__(self, error_class: str, message: str = ""):
        if error_class not in ERROR_CLASSES:
            raise ValueError(f"unknown developer error_class {error_class!r}")
        self.error_class = error_class
        super().__init__(f"{error_class}: {message}" if message else error_class)
