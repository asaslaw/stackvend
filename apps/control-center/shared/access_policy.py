"""
StackVend workload access policy (Wave 2 lane 19, L19-1; FD-4I I7-I12; register rows 27, 42, 45, 46).

Access to a generated tenant workload is explicit, validated data, never inferred from spec keywords and never
filled with guessed or widened principals:

* ``AccessMode``          exact enum: PUBLIC_APP | PRIVATE_IAM | PRIVATE_IAP.
* ``Principal``           ``<kind>:<value>`` with kind in {user, group, serviceAccount, domain}. ``allUsers``,
                          ``allAuthenticatedUsers``, ``domain:allAuthenticatedUsers``, org customer ids (``C0...``),
                          unprefixed strings and any other kind are REJECTED (ValueError); nothing is ever prefixed.
* ``SignInPolicy``        Google sign-in mode (owner 27b: shared platform client, BYO, disabled), email/password flag,
                          extra authorized domains. Only meaningful for PUBLIC_APP.
* ``AccessPolicy``        the whole record (``workloads/{pid}.access``).
* ``PlatformRole``        exact Control Center role enum; ``parse_platform_role`` replaces ``"ADMIN" in role``.
* ``ACCESS_MODE_BREADTH`` explicit order of the modes, narrowest first (owner decision L19-F4).
* ``widening_changes``    exactly how a new record is wider than the previous one (``is_widening``: any at all).
* ``AccessWideningApproval`` the one-shot ``workloads/{pid}.access_widening_approval`` flag a widening PATCH sets;
                          it forces plan approval on the workload's next run (L19-F4).
* ``deploy_access_tfvars``  the three access variable values a deploy applies from the CURRENT record (FD-4DT
                          Fast-Path access; private records only, ``None`` for PUBLIC_APP).
* ``platform_default_access_record`` the record a NEW workload gets when nobody chose its access (OSS-D23, owner
                          10-19/10-20): ``PRIVATE_IAP`` (private, Google sign-in through IAP), ``source=
                          "platform_default"``, listing only the platform-verified submitter (``user:<email>``) when
                          known; with nobody known its build stops with ``ACCESS_POLICY_INCOMPLETE`` until an
                          administrator lists who may use it. Never public by omission; public stays an explicit
                          choice (``mode=PUBLIC_APP`` in the create form or the admin PATCH).
* ``effective_app_admin_emails`` the app administrators a PRIVATE_IAP Cloud Run workload's env carries
                          (APP-ADMIN-DEFAULT): the record's list, else the verified submitter when an exact ``user:``
                          invoker (``workload_verified_submitter``), else nobody.

Every check is an exact enum / exact format check. There is no substring or regex matching in this module.

Replica rule (WAVE2.md): edit ONLY this root copy. The gateway and Control Center images carry byte-identical lane 12
Phase 0 replicas (``apps/orchestrator-gateway/shared/`` FD-4I RT R2, ``apps/control-center/shared/`` L19-11), synced
with ``python deploy/vendor_shared.py sync --write shared/access_policy.py`` and policed by
``tests/test_shared_packaging.py::test_replica_identical_to_root`` and
``tests/test_lane19_access_policy.py::test_root_copy_plus_only_the_phase0_replicas``. Never hand-edit a replica.
"""

from __future__ import annotations

import hashlib
import json
import string
from enum import Enum
from typing import List, Literal, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

__all__ = [
    "ACCESS_MODE_BREADTH",
    "ACCESS_WIDENING_APPROVAL_FIELD",
    "APP_ADMIN_CONTRACT_FIELD",
    "APP_ADMIN_SOURCE_NONE",
    "APP_ADMIN_SOURCE_RECORD",
    "APP_ADMIN_SOURCE_SUBMITTER",
    "AccessMode",
    "AccessPolicy",
    "AccessPolicyIncompleteError",
    "AccessWideningApproval",
    "DEPLOY_ACCESS_TFVARS_KEYS",
    "GoogleIdpMode",
    "HTTP_METHODS",
    "PlatformRole",
    "Principal",
    "PrincipalKind",
    "SignInPolicy",
    "app_admin_list_digest",
    "PLATFORM_DEFAULT_ACCESS_MODE",
    "PLATFORM_DEFAULT_ACCESS_SOURCE",
    "SUBMITTER_PROVENANCE_FIELD",
    "SUBMITTER_VERIFIED_BY",
    "VERIFIED_SUBMITTER_FIELD",
    "WideningChange",
    "deploy_access_tfvars",
    "effective_app_admin_emails",
    "is_widening",
    "parse_platform_role",
    "platform_default_access_policy",
    "platform_default_access_record",
    "submitter_provenance",
    "validate_email",
    "validate_hostname",
    "verified_submitter_member",
    "widening_approval",
    "widening_changes",
    "workload_verified_submitter",
]


class AccessMode(str, Enum):
    PUBLIC_APP = "PUBLIC_APP"    # run.invoker allUsers via the golden compute module only; app enforces login on /api/*
    PRIVATE_IAM = "PRIVATE_IAM"  # run.invoker = invoker_principals only
    PRIVATE_IAP = "PRIVATE_IAP"  # Direct IAP; iap.httpsResourceAccessor = invoker_principals


# Owner decision L19-F4: the access modes in an explicit order, narrowest first. A mode change to a higher number is a
# widening. PRIVATE_IAM (callers must present an identity token that run.invoker accepts) is narrower than PRIVATE_IAP
# (the same members, plus an interactive browser path through Google sign-in); PUBLIC_APP (allUsers) is the widest.
ACCESS_MODE_BREADTH = {
    AccessMode.PRIVATE_IAM: 0,
    AccessMode.PRIVATE_IAP: 1,
    AccessMode.PUBLIC_APP: 2,
}


class PrincipalKind(str, Enum):
    USER = "user"
    GROUP = "group"
    SERVICE_ACCOUNT = "serviceAccount"
    DOMAIN = "domain"


class GoogleIdpMode(str, Enum):  # owner decision 27b
    SHARED_PLATFORM_CLIENT = "SHARED_PLATFORM_CLIENT"  # install-wide tenant client (host SM), REST-configured
    BYO = "BYO"                                        # tenant's own client in its child project (child SM)
    DISABLED = "DISABLED"


class PlatformRole(str, Enum):
    ADMIN = "ADMIN"
    WORKLOAD_MANAGER = "WORKLOAD_MANAGER"
    VIEWER = "VIEWER"


HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"})

_LABEL_CHARS = frozenset(string.ascii_lowercase + string.digits + "-")
# RFC 5322 atext plus '.', i.e. the unquoted local-part alphabet. Quoted local parts are not accepted.
_LOCAL_CHARS = frozenset(string.ascii_letters + string.digits + "!#$%&'*+-/=?^_`{|}~.")


class AccessPolicyIncompleteError(ValueError):
    """A private workload has no invoker principals: HITL (``ACCESS_POLICY_INCOMPLETE``), never LLM repair."""

    error_class = "ACCESS_POLICY_INCOMPLETE"


def validate_hostname(value: str) -> str:
    """Exact RFC 1123 hostname check (lower-case, >= 2 labels, no wildcard). Returns the value or raises ValueError."""
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ValueError(f"not an RFC 1123 hostname: {value!r}")
    labels = value.split(".")
    if len(labels) < 2:
        raise ValueError(f"hostname needs at least two labels: {value!r}")
    for label in labels:
        if not (1 <= len(label) <= 63) or not set(label) <= _LABEL_CHARS or label[0] == "-" or label[-1] == "-":
            raise ValueError(f"not an RFC 1123 hostname (label {label!r}): {value!r}")
    if labels[-1].isdigit():
        raise ValueError(f"top-level label must not be numeric: {value!r}")
    return value


def validate_email(value: str) -> str:
    """Exact address check: one '@', unquoted dot-atom local part, RFC 1123 domain. Returns the lower-cased address.

    Google account and group addresses are case-insensitive; the lower-cased form is the one IAM stores."""
    if not isinstance(value, str) or value != value.strip() or not value:
        raise ValueError(f"not an email address: {value!r}")
    lowered = value.lower()
    local, sep, domain = lowered.partition("@")
    if not sep or "@" in domain or not local or len(local) > 64:
        raise ValueError(f"not an email address: {value!r}")
    if not set(local) <= _LOCAL_CHARS or local[0] == "." or local[-1] == "." or ".." in local:
        raise ValueError(f"not an email address (local part): {value!r}")
    validate_hostname(domain)
    return lowered


class Principal(BaseModel):
    """One IAM member. Parsed by splitting on the FIRST ':' into (kind, value); kind must be a ``PrincipalKind``."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: PrincipalKind
    value: str

    @model_validator(mode="after")
    def _check_value(self) -> "Principal":
        if self.kind is PrincipalKind.DOMAIN:
            validate_hostname(self.value)
        else:
            object.__setattr__(self, "value", validate_email(self.value))
        return self

    @classmethod
    def parse(cls, raw: str) -> "Principal":
        if not isinstance(raw, str):
            raise ValueError(f"principal must be a string '<kind>:<value>': {raw!r}")
        kind, sep, value = raw.partition(":")
        if not sep:
            raise ValueError(f"principal has no '<kind>:' prefix (never auto-prefixed): {raw!r}")
        try:
            pkind = PrincipalKind(kind)
        except ValueError:
            raise ValueError(f"principal kind {kind!r} is not one of {[k.value for k in PrincipalKind]}: {raw!r}") from None
        return cls(kind=pkind, value=value)

    def __str__(self) -> str:
        return f"{self.kind.value}:{self.value}"


class SignInPolicy(BaseModel):
    """Tenant app sign-in (owner 27b). Only meaningful for PUBLIC_APP; PRIVATE_* must be DISABLED / False / []."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    google: GoogleIdpMode
    email_password: bool = False  # Q21: off by default; email/password users still need email_verified
    additional_authorized_domains: List[str] = Field(default_factory=list)  # exact hostnames, no wildcards

    @field_validator("additional_authorized_domains")
    @classmethod
    def _domains(cls, v: List[str]) -> List[str]:
        for d in v:
            validate_hostname(d)
        if len(set(v)) != len(v):
            raise ValueError("additional_authorized_domains contains duplicates")
        return v


class AccessPolicy(BaseModel):
    """The authoritative access record of one workload (``workloads/{pid}.access``)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    mode: AccessMode
    invoker_principals: List[Principal] = Field(default_factory=list)  # PRIVATE_*: required (see require_complete)
    app_admin_emails: List[str] = Field(default_factory=list)         # lower-cased; may be empty
    public_api_routes: List[str] = Field(default_factory=lambda: ["GET /api/config"])  # exact "METHOD /path"
    sign_in: SignInPolicy
    tenant_isolation_required: Optional[bool] = None  # A8 (row 45): PUBLIC_APP needs an explicit answer
    source: Literal["intake", "operator_hitl", "migration", "platform_default"]

    @field_validator("invoker_principals", mode="before")
    @classmethod
    def _parse_principals(cls, v):
        if v is None:
            return []
        if not isinstance(v, list):
            raise ValueError("invoker_principals must be a list")
        return [Principal.parse(p) if isinstance(p, str) else p for p in v]

    @field_validator("app_admin_emails")
    @classmethod
    def _admins(cls, v: List[str]) -> List[str]:
        out = [validate_email(e) for e in v]
        if len(set(out)) != len(out):
            raise ValueError("app_admin_emails contains duplicates")
        return out

    @field_validator("public_api_routes")
    @classmethod
    def _routes(cls, v: List[str]) -> List[str]:
        for r in v:
            method, sep, path = r.partition(" ") if isinstance(r, str) else ("", "", "")
            if not sep or method not in HTTP_METHODS or not path.startswith("/") or any(c.isspace() for c in path):
                raise ValueError(f"public_api_routes entries must be exact 'METHOD /path' pairs: {r!r}")
        if len(set(v)) != len(v):
            raise ValueError("public_api_routes contains duplicates")
        return v

    @model_validator(mode="after")
    def _cross_field(self) -> "AccessPolicy":
        if len({str(p) for p in self.invoker_principals}) != len(self.invoker_principals):
            raise ValueError("invoker_principals contains duplicates")
        if self.mode is AccessMode.PUBLIC_APP:
            if self.invoker_principals:
                raise ValueError("PUBLIC_APP takes no invoker_principals (the golden compute module grants allUsers)")
            if self.sign_in.google is GoogleIdpMode.DISABLED and not self.sign_in.email_password:
                raise ValueError("PUBLIC_APP needs a sign-in method: sign_in.google != DISABLED or email_password")
            if self.tenant_isolation_required is None:
                raise ValueError("PUBLIC_APP requires an explicit tenant_isolation_required answer (A8, row 45)")
            if self.tenant_isolation_required and self.sign_in.google is GoogleIdpMode.SHARED_PLATFORM_CLIENT:
                raise ValueError("tenant_isolation_required apps may not use the shared platform Google client: "
                                 "choose BYO, email/password, or PRIVATE_IAP (A8, row 45)")
        else:
            # Rows 42/46: private workloads get no OAuth / IdP artifacts, so a sign-in setting would be silently
            # ineffective; refuse it loudly instead (Fable R3 check F-R3-5).
            if self.sign_in.google is not GoogleIdpMode.DISABLED:
                raise ValueError(f"{self.mode.value} requires sign_in.google == DISABLED (rows 42/46)")
            if self.sign_in.email_password:
                raise ValueError(f"{self.mode.value} does not support email_password sign-in (rows 42/46)")
            if self.sign_in.additional_authorized_domains:
                raise ValueError(f"{self.mode.value} takes no additional_authorized_domains (rows 42/46)")
        return self

    # -------------------------------------------------------------------------------------------- derived facts
    @property
    def is_complete(self) -> bool:
        return self.mode is AccessMode.PUBLIC_APP or bool(self.invoker_principals)

    def require_complete(self) -> "AccessPolicy":
        """Raise ``AccessPolicyIncompleteError`` for a private workload with no principals (HITL before LLM spend)."""
        if not self.is_complete:
            raise AccessPolicyIncompleteError(
                f"{self.mode.value} workload has no invoker_principals; an operator must list them (never guessed)")
        return self

    def invoker_members(self) -> List[str]:
        return [str(p) for p in self.invoker_principals]

    @property
    def allow_unauthenticated(self) -> bool:
        return self.mode is AccessMode.PUBLIC_APP

    @property
    def enable_direct_iap(self) -> bool:
        return self.mode is AccessMode.PRIVATE_IAP


def parse_platform_role(raw) -> Optional[PlatformRole]:
    """Exact Control Center role: ``PlatformRole(str(raw).strip().upper())``; anything else is None (not admin)."""
    if raw is None:
        return None
    try:
        return PlatformRole(str(raw).strip().upper())
    except ValueError:
        return None


# ------------------------------------------------------------------------------------------------ widening (L19-F4)
ACCESS_WIDENING_APPROVAL_FIELD = "access_widening_approval"


class WideningChange(str, Enum):
    """Why a new access record is wider than the previous one (exact, typed; no text is compared)."""

    NO_PREVIOUS_RECORD = "NO_PREVIOUS_RECORD"  # nothing (or nothing valid) was recorded: every grant is new
    MODE_WIDENED = "MODE_WIDENED"              # ACCESS_MODE_BREADTH[new.mode] > ACCESS_MODE_BREADTH[old.mode]
    MEMBERS_ADDED = "MEMBERS_ADDED"            # both private and new members are not a subset of the old ones


def widening_changes(previous: Optional[AccessPolicy], new: AccessPolicy) -> List[WideningChange]:
    """Owner decision L19-F4: how ``new`` is wider than ``previous`` ([] = narrowing or no change).

    * ``previous`` None (no record, or one that does not validate): the platform grants nothing without a record
      (the build stops), so any record is a widening.
    * mode: ``ACCESS_MODE_BREADTH`` order, so PUBLIC_APP -> private is narrowing, private -> PUBLIC_APP widening.
    * members: compared only when both modes are private (a PUBLIC_APP record already admits everyone, so a private
      record after it is narrowing whatever its members). The test is exact set inclusion of the canonical
      ``kind:value`` strings; membership is never resolved, so replacing ``domain:example.com`` with one user of that
      domain still counts as adding a member (conservative).
    Not compared: the PUBLIC_APP sign-in settings and A8 answer, ``app_admin_emails`` and ``public_api_routes``."""
    if previous is None:
        return [WideningChange.NO_PREVIOUS_RECORD]
    changes: List[WideningChange] = []
    if ACCESS_MODE_BREADTH[new.mode] > ACCESS_MODE_BREADTH[previous.mode]:
        changes.append(WideningChange.MODE_WIDENED)
    if (new.mode is not AccessMode.PUBLIC_APP and previous.mode is not AccessMode.PUBLIC_APP
            and not set(new.invoker_members()) <= set(previous.invoker_members())):
        changes.append(WideningChange.MEMBERS_ADDED)
    return changes


def is_widening(previous: Optional[AccessPolicy], new: AccessPolicy) -> bool:
    return bool(widening_changes(previous, new))


class AccessWideningApproval(BaseModel):
    """``workloads/{pid}.access_widening_approval`` (L19-F4): set by a widening ``PATCH /api/workloads/{pid}/access``
    in the same atomic write as the record and its audit entry. While it is present (any non-null value, valid or
    not), the gateway's pre-build gate requires plan approval (``ACCESS_WIDENED``) and the developer refuses to build
    from the record (``ACCESS_WIDENING_UNAPPROVED``). An APPROVED plan decision clears it (set to null) only if it is
    still the value that approval reviewed.

    RT R2: the flag describes "last approved record -> now". ``previous_mode`` / ``previous_members`` are the baseline
    (the record before the FIRST still-pending widening; None / [] when there was no valid record), ``added_members``
    the exact set difference of the new canonical members minus that baseline (sorted), and ``changes`` every
    widening reason accumulated since the baseline."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    required: Literal[True] = True
    audit_log_id: str = Field(min_length=1)
    set_at: str = Field(min_length=1)
    set_by: str = Field(min_length=1)
    previous_mode: Optional[AccessMode] = None
    previous_members: List[str] = Field(default_factory=list)
    new_mode: AccessMode
    added_members: List[str] = Field(default_factory=list)
    changes: List[WideningChange] = Field(min_length=1)


def widening_approval(*, previous: Optional[AccessPolicy], new: AccessPolicy, changes: List[WideningChange],
                      pending: object, audit_log_id: str, set_at: str, set_by: str) -> AccessWideningApproval:
    """The flag a confirmed widening writes (RT R2). ``pending`` is the stored flag value (None: nothing pending).

    A still-pending valid flag keeps ITS baseline (the earliest unapproved one) and its changes; a pending value that
    does not validate gives an unknown baseline (``NO_PREVIOUS_RECORD``, conservative). Nothing pending: the baseline
    is ``previous`` (None when there was no valid record)."""
    if pending is None:
        base_mode = previous.mode if previous is not None else None
        base_members = previous.invoker_members() if previous is not None else []
        prior_changes: List[WideningChange] = []
    else:
        try:
            prior = AccessWideningApproval.model_validate(pending)
            base_mode, base_members, prior_changes = prior.previous_mode, list(prior.previous_members), list(prior.changes)
        except (ValueError, TypeError):
            base_mode, base_members, prior_changes = None, [], [WideningChange.NO_PREVIOUS_RECORD]
    merged = list(prior_changes)
    for c in changes:
        if c not in merged:
            merged.append(c)
    return AccessWideningApproval(
        audit_log_id=audit_log_id, set_at=set_at, set_by=set_by, previous_mode=base_mode,
        previous_members=sorted(base_members), new_mode=new.mode,
        added_members=sorted(set(new.invoker_members()) - set(base_members)), changes=merged)


# ------------------------------------------------------------------------------- deploy-time access (FD-4DT)
# The root variables the platform renders from the access record (developer: infra/workload/terraform.tfvars and the
# variables.tf defaults; deploy: the platform access var file). Same names as the developer's access-policy validator
# (PLATFORM_TFVARS_KEYS) and the golden compute module's inputs.
DEPLOY_ACCESS_TFVARS_KEYS = ("allow_unauthenticated", "enable_direct_iap", "authorized_invoker_members")


def deploy_access_tfvars(policy: AccessPolicy) -> Optional[dict]:
    """FD-4DT: the access variable values a deploy applies from the workload's CURRENT record, so a Fast-Path Deploy
    (no code generation) applies the record an administrator saved after the code was committed.

    Private records only (PRIVATE_IAM / PRIVATE_IAP): ``{"allow_unauthenticated": False, "enable_direct_iap": <mode is
    PRIVATE_IAP>, "authorized_invoker_members": <the exact canonical members, in record order>}``, the values the
    developer stage renders for the same record. The two private modes differ only in these variables (the golden
    compute module switches IAP and the invoker grants on them). ``None`` for PUBLIC_APP: a public app's own sign-in
    is generated application code, so private code is never opened by a variable; a change to Public needs a full
    rebuild (and, as a widening, its plan approval, L19-F4). An incomplete private record raises
    ``AccessPolicyIncompleteError`` (never an empty invoker list)."""
    policy.require_complete()
    if policy.mode is AccessMode.PUBLIC_APP:
        return None
    return {
        "allow_unauthenticated": False,
        "enable_direct_iap": policy.mode is AccessMode.PRIVATE_IAP,
        "authorized_invoker_members": policy.invoker_members(),
    }


# ------------------------------------------------------------------------------------- platform default (OSS-D23)
# Owner decisions 10-19 / 10-20 (register row OSS-D23): a NEW workload whose access nobody chose is private with Google
# sign-in (IAP), never public, and lists its SUBMITTER when the platform itself verified who that is (the Control
# Center's authenticated caller, or the Drive file owner from Drive API metadata). Only the code paths that create a
# workload apply it, and only when the workload document does not exist yet: an existing workload keeps whatever it
# has (no silent migration).
PLATFORM_DEFAULT_ACCESS_MODE = AccessMode.PRIVATE_IAP
PLATFORM_DEFAULT_ACCESS_SOURCE = "platform_default"
SUBMITTER_PROVENANCE_FIELD = "access_default_submitter"  # workloads/{pid}: who was listed by default, and how verified
SUBMITTER_VERIFIED_BY = frozenset({"control_center_auth", "drive_file_owner"})


def verified_submitter_member(email: object) -> Optional[str]:
    """``user:<email>`` for a platform-verified submitter address, or None (unknown: nobody is listed).

    Exact checks only: a valid address (``validate_email``) whose domain is not a Google service-account domain
    (last two labels exactly ``gserviceaccount.com``: service accounts are never listed automatically). Groups,
    domains and anything else are never produced here."""
    if not isinstance(email, str):
        return None
    try:
        address = validate_email(email)
    except ValueError:
        return None
    if address.partition("@")[2].split(".")[-2:] == ["gserviceaccount", "com"]:
        return None
    return str(Principal(kind=PrincipalKind.USER, value=address))


def platform_default_access_policy(submitter_member: Optional[str] = None) -> AccessPolicy:
    """The platform default record: ``PRIVATE_IAP``, Google sign-in disabled (rows 42/46), ``source="platform_default"``.
    Its only principal is ``submitter_member`` (from ``verified_submitter_member``) when one is known; with none the
    record is incomplete on purpose and the build stops with ``ACCESS_POLICY_INCOMPLETE`` until an administrator lists
    the principals (``PATCH /api/workloads/{pid}/access``)."""
    members = [submitter_member] if submitter_member is not None else []
    return AccessPolicy(mode=PLATFORM_DEFAULT_ACCESS_MODE, invoker_principals=members,
                        sign_in=SignInPolicy(google=GoogleIdpMode.DISABLED), source=PLATFORM_DEFAULT_ACCESS_SOURCE)


def platform_default_access_record(submitter_member: Optional[str] = None) -> dict:
    """``platform_default_access_policy`` in the stored ``workloads/{pid}.access`` shape (principals as exact strings)."""
    policy = platform_default_access_policy(submitter_member)
    record = policy.model_dump(mode="json")
    record["invoker_principals"] = policy.invoker_members()
    return record


def submitter_provenance(submitter_member: str, verified_by: str) -> dict:
    """``workloads/{pid}.access_default_submitter``: the member the default listed and how the platform verified it."""
    if verified_by not in SUBMITTER_VERIFIED_BY:
        raise ValueError(f"unknown submitter verification: {verified_by!r}")
    return {"member": submitter_member, "source": "submitter", "verified_by": verified_by}


# ------------------------------------------------------------------------- app administrators (APP-ADMIN-DEFAULT)
# Owner 11-16 (register rows APP-ADMIN-IAP-CONTRACT, APP-ADMIN-DEFAULT): a PRIVATE_IAP workload's Cloud Run services
# get the platform-set env STACKVEND_APP_ADMIN_EMAILS (a JSON list) from the EFFECTIVE admin list below. The record's
# own ``app_admin_emails`` wins when it is not empty. When it is empty, the effective list is the platform-verified
# submitter of the workload, but only when that submitter is an exact ``user:`` member of ``invoker_principals``
# (they already reach the app); otherwise it is empty and no app administrator is configured (never "every invoker",
# never a guess, never a creator field the platform did not verify).
# workloads/{pid}: the platform-verified human who created the workload (the submitter_provenance shape)
VERIFIED_SUBMITTER_FIELD = "verified_submitter"
APP_ADMIN_SOURCE_RECORD = "record"        # the access record's app_admin_emails
APP_ADMIN_SOURCE_SUBMITTER = "submitter"  # the default: the verified submitter, an exact user: invoker
APP_ADMIN_SOURCE_NONE = "none"            # nobody: no app administrator is configured
# workloads/{pid}: the developer's record of the admin list its last Direct IAP Cloud Run build rendered (counts, source,
# warning and app_admin_list_digest only, never an address). The Control Center's Fast-Path check compares the digest.
APP_ADMIN_CONTRACT_FIELD = "app_admin_contract"


def app_admin_list_digest(emails: object) -> str:
    """sha256 (hex) of the JSON of the sorted admin addresses: equal for the same set, whatever the order. It identifies
    the rendered list on the workload record without storing an address."""
    return hashlib.sha256(json.dumps(sorted(str(e) for e in emails or ()), separators=(",", ":"))
                          .encode("utf-8")).hexdigest()


def workload_verified_submitter(workload: object) -> Optional[str]:
    """The ``user:<email>`` member a workload document records as its platform-verified submitter, or None.

    Read from exactly two typed fields, both in the ``submitter_provenance`` shape and written only by platform code
    from an identity the platform itself verified: ``verified_submitter`` (the Control Center create route, from the
    IAP assertion or session its auth layer verified) and ``access_default_submitter`` (the platform default record of
    a Control Center or Drive create, SUBMITTER_PROVENANCE_FIELD). Exact checks: ``source == "submitter"``,
    ``verified_by`` in SUBMITTER_VERIFIED_BY, and a member that ``verified_submitter_member`` gives back unchanged
    (a ``user:`` address, never a service account). Anything else (a missing, malformed or other field such as
    ``creator_email``) is None."""
    if not isinstance(workload, dict):
        return None
    for field_name in (VERIFIED_SUBMITTER_FIELD, SUBMITTER_PROVENANCE_FIELD):
        record = workload.get(field_name)
        if not isinstance(record, dict) or record.get("source") != "submitter":
            continue
        if record.get("verified_by") not in SUBMITTER_VERIFIED_BY:
            continue
        member = record.get("member")
        if not isinstance(member, str):
            continue
        kind, sep, address = member.partition(":")
        if sep and kind == PrincipalKind.USER.value and verified_submitter_member(address) == member:
            return member
    return None


def effective_app_admin_emails(policy: AccessPolicy, submitter_member: Optional[str]) -> Tuple[List[str], str]:
    """(the effective app administrator emails, their source) for ``policy`` (APP-ADMIN-DEFAULT).

    * The record lists admins: exactly those, in record order (APP_ADMIN_SOURCE_RECORD).
    * Else ``submitter_member`` (``workload_verified_submitter``) when it is an exact member of the record's
      ``invoker_principals`` and of kind ``user``: ``[<its email>]`` (APP_ADMIN_SOURCE_SUBMITTER).
    * Else ``[]`` (APP_ADMIN_SOURCE_NONE): no app administrator is configured."""
    if policy.app_admin_emails:
        return list(policy.app_admin_emails), APP_ADMIN_SOURCE_RECORD
    if isinstance(submitter_member, str) and submitter_member in policy.invoker_members():
        kind, _, address = submitter_member.partition(":")
        if kind == PrincipalKind.USER.value:
            return [address], APP_ADMIN_SOURCE_SUBMITTER
    return [], APP_ADMIN_SOURCE_NONE
