"""
Developer-site access resolution (Wave 2 lane 19, L19-2; FD-4I I7, I9, I11, I12; plan §2.1).

Who may reach a generated workload is explicit, typed data. It is never read from spec keywords, never widened to
``allAuthenticatedUsers``, never auto-prefixed (``domain:`` + an org customer id), and never filled with guessed people
(every platform ADMIN, env ``ADMIN_EMAIL``, or whichever creator field a workload document happens to carry).

Sources, in order (the first that exists wins; the others are not merged in):
1. ``access``          the request's ``AccessPolicy`` (``DeveloperExecuteRequest.access``), or
2. ``workload_access`` the authoritative ``workloads/{pid}.access`` record (an ``AccessPolicy`` dict), or
3. legacy typed ingress flags: the compliance decision's booleans (``enable_direct_iap``, ``allow_unauthenticated``).
   They give the MODE only. They never give principals: ``allowed_domains`` carries org-policy values (customer ids,
   domains of ``iam.allowedPolicyMemberDomains``), which are not IAM members. So a private workload that reaches the
   developer with no access record stops here with ``ACCESS_POLICY_INCOMPLETE`` (operator / HITL), before any LLM
   call, instead of being opened to every Google account.

A PUBLIC_APP mode (from any source) under domain-restricted sharing is ``ACCESS_ORG_POLICY_CONFLICT``: the org policy
forbids ``allUsers``, so the apply would fail; the operator must pick a private mode with principals.

Most restrictive wins (L19-11 RT F5): the record's mode is used unless it is LESS restrictive than the run's typed
compliance decision. A PUBLIC_APP record while the decision is private (``enable_direct_iap is True`` or
``allow_unauthenticated is False``, exact booleans) is ``ACCESS_COMPLIANCE_CONFLICT`` (operator / HITL, before any
LLM call). A private record under a public decision is stricter and is used as is.

Every failure is a ``DeveloperStageError`` with an exact access class (``errors.ACCESS_ERROR_CLASSES``).

Deploy note: the gateway image carries ``shared/access_policy.py`` as a committed, byte-identical lane 12 Phase 0
replica (``apps/orchestrator-gateway/shared/access_policy.py``, policed by ``test_replica_identical_to_root``; FD-4I RT
R2). It is still imported only where an access RECORD must be validated, and its absence would be a typed failure
(``ACCESS_POLICY_UNAVAILABLE``), never a fallback: a record is never ignored. The record-less path (compliance flags)
needs no model. The mode strings below are ``shared.access_policy.AccessMode`` values (pinned by a test).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional, Tuple

from .errors import (
    ACCESS_COMPLIANCE_CONFLICT,
    ACCESS_ORG_POLICY_CONFLICT,
    ACCESS_POLICY_INCOMPLETE,
    ACCESS_POLICY_INVALID,
    ACCESS_POLICY_REQUIRED,
    ACCESS_POLICY_UNAVAILABLE,
    DeveloperStageError,
)

__all__ = ["ResolvedAccess", "resolve_access", "MODES", "PUBLIC_APP", "PRIVATE_IAM", "PRIVATE_IAP",
           "SOURCE_REQUEST", "SOURCE_WORKLOAD_RECORD", "SOURCE_COMPLIANCE_FLAGS"]

# shared.access_policy.AccessMode values (exact strings; tests/test_lane19_tenant_authz.py pins the equality).
PUBLIC_APP = "PUBLIC_APP"
PRIVATE_IAM = "PRIVATE_IAM"
PRIVATE_IAP = "PRIVATE_IAP"
MODES = frozenset({PUBLIC_APP, PRIVATE_IAM, PRIVATE_IAP})

SOURCE_REQUEST = "request"
SOURCE_WORKLOAD_RECORD = "workload_record"
SOURCE_COMPLIANCE_FLAGS = "compliance_flags"


@dataclass(frozen=True)
class ResolvedAccess:
    """The developer's access facts for one run. ``invoker_members`` are exact ``<kind>:<value>`` IAM members."""

    mode: str  # one of MODES
    invoker_members: Tuple[str, ...]
    app_admin_emails: Tuple[str, ...]
    source: str
    policy: Any = None  # the validated shared.access_policy.AccessPolicy when the source is a record
    # APP-ADMIN-DEFAULT (owner 11-16): shared.access_policy.effective_app_admin_emails of the record and the workload's
    # verified submitter: the record's list, else that submitter when an exact `user:` invoker, else () ("none").
    # Read only for a Direct IAP Cloud Run workload (STACKVEND_APP_ADMIN_EMAILS); () / "none" without a record.
    effective_app_admin_emails: Tuple[str, ...] = ()
    app_admin_source: str = "none"

    @property
    def allow_unauthenticated(self) -> bool:
        return self.mode == PUBLIC_APP

    @property
    def enable_direct_iap(self) -> bool:
        return self.mode == PRIVATE_IAP


def _parse_policy(raw: Any, where: str) -> Any:
    try:
        from shared.access_policy import AccessPolicy
    except ImportError:  # not vendored into this image yet (lane 12 Phase 1): refuse, never ignore the record
        raise DeveloperStageError(ACCESS_POLICY_UNAVAILABLE,
                                  f"{where} present but shared.access_policy is not in this image") from None
    if isinstance(raw, AccessPolicy):
        return raw
    if not isinstance(raw, Mapping):
        raise DeveloperStageError(ACCESS_POLICY_INVALID, f"{where} is not an AccessPolicy object")
    try:
        return AccessPolicy.model_validate(dict(raw))
    except Exception as e:  # pydantic ValidationError / ValueError: report the first problems, never guess a fix
        errors = getattr(e, "errors", None)
        detail = "; ".join(str(err.get("msg", ""))[:160] for err in errors()[:3]) if callable(errors) else str(e)[:300]
        raise DeveloperStageError(ACCESS_POLICY_INVALID, f"{where}: {detail}") from None


def _legacy_mode(allow_unauthenticated: Optional[bool], enable_direct_iap: Optional[bool]) -> str:
    """Mode from the compliance decision's typed booleans (exact ``is True`` / ``is False``; nothing else counts)."""
    if enable_direct_iap is True:
        return PRIVATE_IAP
    if allow_unauthenticated is True:
        return PUBLIC_APP
    if allow_unauthenticated is False:
        return PRIVATE_IAM
    raise DeveloperStageError(
        ACCESS_POLICY_REQUIRED,
        "no access record and no typed ingress decision (allow_unauthenticated / enable_direct_iap); "
        "an operator must record workloads/{pid}.access",
    )


def resolve_access(
    *,
    access: Any = None,
    workload_access: Any = None,
    allow_unauthenticated: Optional[bool] = None,
    enable_direct_iap: Optional[bool] = None,
    domain_restricted_sharing: Optional[bool] = None,
    workload_doc: Optional[Mapping[str, Any]] = None,
) -> ResolvedAccess:
    """Resolve the run's access facts or raise a typed ``DeveloperStageError`` (no I/O; deterministic).

    ``workload_doc`` (APP-ADMIN-DEFAULT): the ``workloads/{pid}`` document the caller already read (None = not read).
    Only its platform-verified submitter (``shared.access_policy.workload_verified_submitter``: two typed provenance
    fields, never a creator field) is used, and only for ``effective_app_admin_emails``."""
    policy: Any = None
    if access is not None:
        policy, source = _parse_policy(access, "request access"), SOURCE_REQUEST
    elif workload_access is not None:
        policy, source = _parse_policy(workload_access, "workloads/{pid}.access"), SOURCE_WORKLOAD_RECORD
    else:
        source = SOURCE_COMPLIANCE_FLAGS

    if policy is not None:
        from shared.access_policy import effective_app_admin_emails, workload_verified_submitter   # see _parse_policy

        admins, admin_source = effective_app_admin_emails(
            policy, workload_verified_submitter(dict(workload_doc) if isinstance(workload_doc, Mapping) else None))
        resolved = ResolvedAccess(mode=policy.mode.value, invoker_members=tuple(policy.invoker_members()),
                                  app_admin_emails=tuple(policy.app_admin_emails), source=source, policy=policy,
                                  effective_app_admin_emails=tuple(admins), app_admin_source=admin_source)
    else:
        resolved = ResolvedAccess(mode=_legacy_mode(allow_unauthenticated, enable_direct_iap), invoker_members=(),
                                  app_admin_emails=(), source=source)

    if policy is not None and resolved.mode == PUBLIC_APP and (enable_direct_iap is True
                                                                or allow_unauthenticated is False):
        # L19-11 RT F5: the most restrictive of the record and the compliance decision wins. A private record under a
        # public decision is used as is (stricter); a PUBLIC_APP record under a private decision (IAP, or no
        # unauthenticated access, e.g. PCI-DSS private ingress) is a contradiction only an operator can resolve.
        raise DeveloperStageError(
            ACCESS_COMPLIANCE_CONFLICT,
            f"access record says PUBLIC_APP (source: {source}) but the compliance decision requires private ingress "
            f"(enable_direct_iap={enable_direct_iap}, allow_unauthenticated={allow_unauthenticated}); an operator "
            "must choose PRIVATE_IAP / PRIVATE_IAM with explicit principals, or change the compliance answer",
        )
    if resolved.mode == PUBLIC_APP and domain_restricted_sharing is True:
        raise DeveloperStageError(
            ACCESS_ORG_POLICY_CONFLICT,
            f"access mode PUBLIC_APP (source: {source}) but the folder's org policy (domain-restricted sharing) "
            "forbids allUsers; an operator must choose PRIVATE_IAP / PRIVATE_IAM with explicit principals",
        )
    if resolved.mode != PUBLIC_APP and not resolved.invoker_members:
        raise DeveloperStageError(
            ACCESS_POLICY_INCOMPLETE,
            f"{resolved.mode} workload has no invoker principals (source: {source}); an operator must list "
            "them in workloads/{pid}.access.invoker_principals (they are never guessed or widened)",
        )
    return resolved
