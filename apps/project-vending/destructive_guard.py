"""
StackVend project vending: destructive-action guard (Wave 2 lane 18, FD-4Q, step S1).

Plan: docs/planning/wave2-lane18-destructive-guards-plan.md rev 2a, section 2. Register row 26 (owner 10-12).
Vending is the ONLY executor of a GCP project delete. Every delete path calls `assert_deletable` first; it fails
closed, makes only read calls, compares structured fields exactly (no substring/regex) and raises
`DeletionRefused(code, detail)` on the first failed check. Refusal codes are the plan's section 2.3 codes and the same
codes as the Control Center's interim sweep guard (lane 4, apps/control-center/sandbox_guard.py) and lane 14's
`shared/managed_target.py` (`verify_managed_target`).

Check order (lane 4's interim order, so both guards report the same code for the same input):

  1  GUARD_UNCONFIGURED      managed root folder id (numeric), managed tag value (tagValues/<n>), >= 1 host id;
                             PLATFORM_PROJECT_ID, if set, equals PROJECT_ID (lane 14 contract)
  2  LEDGER_MISSING / LEDGER_UNAVAILABLE / PLATFORM_WORKLOAD / LEDGER_MISMATCH
                             fresh read of workloads/{product_id}; is_castor is not True; no URL fallback
  3  LEDGER_UNPROVENANCED / LEDGER_MISMATCH
                             workload_provenance/{product_id} (guard DB): created_by in {stackvend-vending,
                             owner-backfill}; project_id == ledger project_id; numeric project_number (== ledger
                             number when the ledger has one); reverse uniqueness of the project id in the ledger
  4  HOST_PROJECT            project id is not a host id
  9  (Firestore-only part, evaluated before any CRM call, as lane 4 does)
     9a APPROVAL_*           HITL classes: destructive_approvals/{id} minted by a human ADMIN session for exactly
                             this action and target, unexpired (<= 15 min), not consumed
     9b SANDBOX_NOT_ELIGIBLE SANDBOX_TTL: caller in SANDBOX_TTL_CALLERS; vend-time provenance (created_by ==
                             stackvend-vending, is_sandbox is True, sandbox_auto_decommission is True, explicit
                             designation source, sandbox_expires_at < now); ledger is_sandbox is True and not in-flight
  5  CRM_MISMATCH / NOT_ACTIVE / HOST_PROJECT / CRM_UNAVAILABLE
                             CRM v3 GET projects/{project_number}: projectId exact, number != host number, ACTIVE
  6  NOT_STACKVEND_OWNED / SANDBOX_NOT_ELIGIBLE
                             labels stackvend-managed == "true", stackvend-product-id == product_id,
                             stackvend-workload-type in {sandbox, standard} (== sandbox for SANDBOX_TTL); a DIRECT tag
                             binding (tagBindings.list on the project, never inherited tags) whose tagValue equals
                             STACKVEND_MANAGED_TAG_VALUE
  7  NOT_IN_MANAGED_FOLDER / ANCESTRY_UNAVAILABLE
                             CRM v1 getAncestry: starts at the project; the managed root folder is an ancestor (i >= 1)
  8  LIEN_PRESENT / CRM_UNAVAILABLE
                             ANY lien on the project refuses (S1 code RT Fix 2(a), register row L18-g): StackVend never
                             releases a lien; no StackVend component places one, so provenance.liens[] is not trusted.
                             The owner removes a lien by hand and retries.
  10 RESOURCE_NOT_IN_STATE / CROSS_REGION_SECONDARY
                             child resources only (CHILD_RESOURCE_DELETE): positional REST-name parse, project segment,
                             primary region (injected resolver; none -> refuse), present in state (injected)
  11 AUDIT_UNAVAILABLE       audit record written before ALLOW; failure refuses

Checks 1-7 without the class-specific part are the identity half (`verify_identity`), the same contract as lane 14's
`verify_managed_target`; tests/test_destructive_guard_contract.py keeps them equal until lane 18 S5 imports it.

CRM errors of any kind, including 429 and 5xx, refuse (CRM_UNAVAILABLE / ANCESTRY_UNAVAILABLE). There is no retry loop.
The executor deletes `projects/<project_number>` only, after `recheck_before_delete` (plan F8), which re-reads the
project by number, the direct tag, the ancestry and the liens immediately before the delete (S1 code RT Fix 3).

Trust (plan 2.5): until S0 + S0b (vending on its own SA with the only tagUser grant; provenance and approvals in the
named guard database) every agent SA can write the default Firestore DB and labels, so this guard is anti-accident
(host project, foreign folders, guessed targets, keyword sandboxes), not anti-attacker. The tag cannot be bound by
anyone before S0, so until then every delete refuses NOT_STACKVEND_OWNED (fail closed).

Approval record (destructive_approvals/{approval_id}, guard DB; minted by the Control Center for a human session, S2):
  status "APPROVED" | "CONSUMED" | "EXECUTED" | "EXECUTION_FAILED"; action (ActionClass value or a lifecycle action);
  product_id; project_id; project_number; resource_name (null for project-level actions); principal_type "USER";
  approved_by (Google-verified email); approved_by_role "ADMIN"; approved_at (not in the future beyond the clock
  skew); expires_at (<= approved_at + 15 min);
  consumed_at / consumed_by (set once, in a transaction, by vending); executed_at / crm_operation / execution_error.

google-auth / google-cloud modules are imported inside the functions that use them: several root-suite test files
replace `google.*` with MagicMocks in sys.modules before vending is imported.
"""
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import json
import logging
import os
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Tuple

logger = logging.getLogger("project-vending-destructive-guard")


class ActionClass(str, Enum):
    PROJECT_DECOMMISSION = "PROJECT_DECOMMISSION"    # HITL: approval required
    SANDBOX_TTL = "SANDBOX_TTL"                      # automatic (row 26): provenance + tag gated
    CHILD_RESOURCE_DELETE = "CHILD_RESOURCE_DELETE"  # HITL: approval required (no executor yet; runbook)
    BILLING_UNLINK = "BILLING_UNLINK"                # HITL: approval required (owner 10-12, OQ-3)
    # EPHEMERAL_TTL (plan 2a, step S1e) is NOT part of S1: it waits for the owner's approval of register row L14-s.


HITL_CLASSES = frozenset({ActionClass.PROJECT_DECOMMISSION, ActionClass.CHILD_RESOURCE_DELETE, ActionClass.BILLING_UNLINK})
PROJECT_LEVEL_CLASSES = frozenset({ActionClass.PROJECT_DECOMMISSION, ActionClass.SANDBOX_TTL, ActionClass.BILLING_UNLINK})

# Vocabulary shared with lane 4 (CC) and lane 14.
LABEL_MANAGED = "stackvend-managed"
LABEL_PRODUCT = "stackvend-product-id"
LABEL_TYPE = "stackvend-workload-type"
WORKLOAD_TYPES = frozenset({"sandbox", "standard"})
CREATED_BY_VENDING = "stackvend-vending"
CREATED_BY_BACKFILL = "owner-backfill"
PROVENANCE_CREATORS = frozenset({CREATED_BY_VENDING, CREATED_BY_BACKFILL})
EXPLICIT_DESIGNATION_SOURCES = frozenset({"OPERATOR_CHECKBOX", "API_FIELD", "OPERATOR_CONFIRMED"})
NOT_ELIGIBLE_STATUSES = frozenset({"DECOMMISSIONED", "DELETED", "PROVISIONING", "REDEPLOYING", "DEPLOYING",
                                   "DECOMMISSION_REQUESTED"})
PLATFORM_PSEUDO_WORKLOADS = frozenset({"project-castor", "castor", "platform"})
APPROVAL_MAX_LIFETIME = timedelta(minutes=15)

WORKLOADS = "workloads"
PROVENANCE = "workload_provenance"
APPROVALS = "destructive_approvals"
AUDIT = "audit_logs"

_CRM_V3 = "https://cloudresourcemanager.googleapis.com/v3/"
_CRM_V1 = "https://cloudresourcemanager.googleapis.com/v1/"
_CRM_FULL_PROJECT = "//cloudresourcemanager.googleapis.com/projects/"
_DNS_V1 = "https://dns.googleapis.com/dns/v1/"
_MAX_PAGES = 10

# HTTP status per refusal code (route mapping). Anything not listed is 403.
_STATUS = {
    "GUARD_UNCONFIGURED": 503, "LEDGER_UNAVAILABLE": 503, "CRM_UNAVAILABLE": 503, "ANCESTRY_UNAVAILABLE": 503,
    "AUDIT_UNAVAILABLE": 503, "APPROVAL_UNAVAILABLE": 503,
    "LEDGER_MISSING": 404,
    "LIEN_PRESENT": 409, "NOT_ACTIVE": 409, "SANDBOX_NOT_ELIGIBLE": 409, "EXTENSION_LIMIT": 409,
    "INVALID_REQUEST": 422,
}


class DeletionRefused(Exception):
    def __init__(self, code: str, detail: str, http_status: Optional[int] = None):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail
        self.http_status = http_status or _STATUS.get(code, 403)


class DecommissionFailed(Exception):
    """The guard allowed the action but executing it failed (route: 502). Ledger + approval record the failure."""

    def __init__(self, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


class CRMUnavailable(Exception):
    """Any non-success Google API answer (incl. 429/5xx) or transport error. Never retried."""

    def __init__(self, what: str, status: Optional[int] = None):
        super().__init__(f"{what} -> {'HTTP ' + str(status) if status is not None else 'transport error'}")
        self.status = status


class StoreUnavailable(Exception):
    pass


class ApprovalConflict(Exception):
    pass


class CallerRefused(Exception):
    def __init__(self, http_status: int, code: str, detail: str):
        super().__init__(f"{code}: {detail}")
        self.http_status, self.code, self.detail = http_status, code, detail


# ------------------------------------------------------------------------------------------------ data types
@dataclass(frozen=True)
class DeletionTarget:
    product_id: str
    resource_name: Optional[str] = None  # child resources only; the project id comes ONLY from the ledger


@dataclass(frozen=True)
class ManagedIdentity:
    """Same shape as lane 14's ManagedTarget."""
    product_id: str
    project_id: str
    project_number: str
    workload_type: str
    provenance_created_by: str


@dataclass(frozen=True)
class GuardVerdict:
    product_id: str
    project_id: str
    project_number: str
    resource_name: Optional[str]
    action_class: ActionClass
    approval_id: Optional[str]
    caller_email: str
    checks: Tuple[str, ...]
    approved_by: Optional[str] = None
    ledger_status: Optional[str] = None
    dns_records: Tuple[Tuple[str, str], ...] = ()


# ------------------------------------------------------------------------------------------------ adapters
class RestCRM:
    """Resource Manager (and Cloud DNS) over REST with an AuthorizedSession. No retries; raises CRMUnavailable."""

    def __init__(self, session=None):
        self._session = session

    def _s(self):
        if self._session is None:
            import google.auth
            from google.auth.transport.requests import AuthorizedSession
            creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            self._session = AuthorizedSession(creds)
        return self._session

    def _call(self, method: str, url: str, what: str, **kw) -> Dict[str, Any]:
        try:
            resp = getattr(self._s(), method)(url, timeout=10, **kw)
        except Exception as e:  # noqa: BLE001 - transport error => refuse
            raise CRMUnavailable(f"{what} ({type(e).__name__})") from None
        if resp.status_code != 200:
            raise CRMUnavailable(what, resp.status_code)
        try:
            return resp.json() or {}
        except Exception:  # noqa: BLE001
            raise CRMUnavailable(f"{what} (unparseable body)") from None

    def _paged(self, url: str, what: str, params: Dict[str, str], key: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        params = dict(params)
        for _ in range(_MAX_PAGES):
            body = self._call("get", url, what, params=params)
            out.extend(body.get(key) or [])
            token = body.get("nextPageToken")
            if not token:
                return out
            params["pageToken"] = token
        raise CRMUnavailable(f"{what} (more than {_MAX_PAGES} pages)")

    def get_project(self, number_or_id: str) -> Dict[str, Any]:
        return self._call("get", f"{_CRM_V3}projects/{number_or_id}", f"projects.get {number_or_id}")

    def get_ancestry(self, project_id: str) -> List[Dict[str, Any]]:
        body = self._call("post", f"{_CRM_V1}projects/{project_id}:getAncestry", f"getAncestry {project_id}", json={})
        return body.get("ancestor") or []

    def list_liens(self, project_number: str) -> List[Dict[str, Any]]:
        return self._paged(f"{_CRM_V3}liens", f"liens.list {project_number}",
                           {"parent": f"projects/{project_number}"}, "liens")

    def list_tag_bindings(self, project_number: str) -> List[Dict[str, Any]]:
        return self._paged(f"{_CRM_V3}tagBindings", f"tagBindings.list {project_number}",
                           {"parent": f"{_CRM_FULL_PROJECT}{project_number}"}, "tagBindings")

    def create_tag_binding(self, project_number: str, tag_value: str) -> Dict[str, Any]:
        return self._call("post", f"{_CRM_V3}tagBindings", f"tagBindings.create {project_number}",
                          json={"parent": f"{_CRM_FULL_PROJECT}{project_number}", "tagValue": tag_value})

    def patch_labels(self, project_number: str, labels: Dict[str, str]) -> Dict[str, Any]:
        return self._call("patch", f"{_CRM_V3}projects/{project_number}", f"projects.patch {project_number}",
                          params={"updateMask": "labels"}, json={"labels": labels})

    # No delete_lien: StackVend never releases a lien (S1 code RT Fix 2(a), register row L18-g).

    def get_iam_policy(self, project_id: str) -> Dict[str, Any]:
        return self._call("post", f"{_CRM_V3}projects/{project_id}:getIamPolicy", f"getIamPolicy {project_id}",
                          json={"options": {"requestedPolicyVersion": 3}})

    def set_iam_policy(self, project_id: str, policy: Dict[str, Any]) -> Dict[str, Any]:
        return self._call("post", f"{_CRM_V3}projects/{project_id}:setIamPolicy", f"setIamPolicy {project_id}",
                          json={"policy": policy})

    def delete_project(self, project_number: str) -> Dict[str, Any]:
        return self._call("delete", f"{_CRM_V3}projects/{project_number}", f"projects.delete {project_number}")

    def delete_dns_rrset(self, project: str, zone: str, name: str, rtype: str) -> Dict[str, Any]:
        return self._call("delete", f"{_DNS_V1}projects/{project}/managedZones/{zone}/rrsets/{name}/{rtype}",
                          f"rrsets.delete {name} {rtype}")


class UnavailableDB:
    """Stands in for a configured-but-unreachable guard database: every access fails (fail closed, never the
    default DB)."""

    def __init__(self, reason: str):
        self.reason = reason

    def collection(self, *_a, **_k):
        raise StoreUnavailable(self.reason)

    def transaction(self, *_a, **_k):
        raise StoreUnavailable(self.reason)


class FirestoreGuardStore:
    """Ledger (default DB) + guard records (named guard DB after S0b; default DB until then)."""

    def __init__(self, db, guard_db=None):
        self.db = db
        self.guard_db = guard_db if guard_db is not None else db

    @staticmethod
    def _get(db, collection: str, doc_id: str) -> Optional[Dict[str, Any]]:
        if db is None:
            raise StoreUnavailable("Firestore client unavailable")
        try:
            snap = db.collection(collection).document(doc_id).get()
        except Exception as e:  # noqa: BLE001
            raise StoreUnavailable(f"{collection}/{doc_id} unreadable: {type(e).__name__}") from None
        if getattr(snap, "exists", False) is not True:
            return None
        data = snap.to_dict()
        return data if isinstance(data, dict) else {}

    def get_workload(self, product_id: str):
        return self._get(self.db, WORKLOADS, product_id)

    def workloads_claiming(self, project_id: str) -> List[str]:
        if self.db is None:
            raise StoreUnavailable("Firestore client unavailable")
        try:
            return [d.id for d in self.db.collection(WORKLOADS).where("project_id", "==", project_id).stream()]
        except Exception as e:  # noqa: BLE001
            raise StoreUnavailable(f"reverse lookup failed: {type(e).__name__}") from None

    def get_provenance(self, product_id: str):
        return self._get(self.guard_db, PROVENANCE, product_id)

    def get_approval(self, approval_id: str):
        return self._get(self.guard_db, APPROVALS, approval_id)

    def update_workload(self, product_id: str, fields: Dict[str, Any]) -> None:
        self.db.collection(WORKLOADS).document(product_id).set(fields, merge=True)

    def update_provenance(self, product_id: str, fields: Dict[str, Any]) -> None:
        self.guard_db.collection(PROVENANCE).document(product_id).set(fields, merge=True)

    def create_provenance(self, product_id: str, record: Dict[str, Any]) -> None:
        """Vending is the single writer. A record left by an earlier project of the same product (decommission +
        redeploy) is moved to workload_provenance/{pid}/history/{old_number} before the new one is written."""
        ref = self.guard_db.collection(PROVENANCE).document(product_id)
        old = self._get(self.guard_db, PROVENANCE, product_id)
        if old is None:
            ref.create(record)
            return
        old_number = _num(old.get("project_number")) or "unknown"
        ref.collection("history").document(old_number).set(old)
        ref.set(record)

    def update_approval(self, approval_id: str, fields: Dict[str, Any]) -> None:
        self.guard_db.collection(APPROVALS).document(approval_id).set(fields, merge=True)

    def write_audit(self, product_id: str, record: Dict[str, Any]) -> None:
        self.db.collection(WORKLOADS).document(product_id).collection(AUDIT).document().set(record)

    def _run_in_transaction(self, body: Callable[[Any], None]) -> None:
        from google.cloud import firestore as gcf
        txn = self.guard_db.transaction()
        gcf.transactional(body)(txn)

    def consume_approval(self, approval_id: str, *, consumed_by: str, now: datetime) -> None:
        """Atomically APPROVED -> CONSUMED. Raises ApprovalConflict if it is not consumable, StoreUnavailable on error."""
        ref = self.guard_db.collection(APPROVALS).document(approval_id)
        stamp = now.isoformat()

        def _body(txn):
            snap = ref.get(transaction=txn)
            data = snap.to_dict() if getattr(snap, "exists", False) is True else None
            if not isinstance(data, dict) or data.get("status") != "APPROVED" or data.get("consumed_at"):
                raise ApprovalConflict(f"approval {approval_id} is not consumable")
            txn.update(ref, {"status": "CONSUMED", "consumed_at": stamp, "consumed_by": consumed_by})

        try:
            self._run_in_transaction(_body)
        except ApprovalConflict:
            raise
        except Exception as e:  # noqa: BLE001
            raise StoreUnavailable(f"approval consume failed: {type(e).__name__}") from None
        after = self._get(self.guard_db, APPROVALS, approval_id) or {}
        if after.get("consumed_at") != stamp or after.get("consumed_by") != consumed_by:
            raise ApprovalConflict(f"approval {approval_id} was consumed by someone else")

    def consume_approval_checked(self, approval_id: str, check: Callable[[Optional[Dict[str, Any]]], Dict[str, Any]]
                                 ) -> None:
        """MCP action approvals (mcp_approvals.py): ONE transaction reads the record, `check(record or None)` either
        raises (its typed refusal propagates unchanged; nothing is written) or returns the fields to write. Any
        Firestore error -> StoreUnavailable. The caller re-reads the record to confirm its own stamp."""
        ref = self.guard_db.collection(APPROVALS).document(approval_id)
        refusal: List[BaseException] = []

        def _body(txn):
            snap = ref.get(transaction=txn)
            data = snap.to_dict() if getattr(snap, "exists", False) is True else None
            try:
                fields = check(data if isinstance(data, dict) or data is None else {})
            except Exception as e:  # noqa: BLE001 - the check's own typed refusal, re-raised below
                refusal.append(e)
                raise
            txn.update(ref, fields)

        try:
            self._run_in_transaction(_body)
        except Exception as e:  # noqa: BLE001
            if refusal and e is refusal[-1]:
                raise
            if refusal:
                raise refusal[-1] from None
            raise StoreUnavailable(f"approval consume failed: {type(e).__name__}") from None


# ------------------------------------------------------------------------------------------------ context
def _num(value) -> str:
    """Project numbers as digit strings; anything else -> ''."""
    if isinstance(value, bool):
        return ""
    if isinstance(value, int):
        return str(value) if value > 0 else ""
    if isinstance(value, str) and value.isdigit():
        return value
    return ""


def _csv_emails(raw: Optional[str]) -> FrozenSet[str]:
    return frozenset(p.strip().lower() for p in (raw or "").split(",") if p.strip())


def _env_root_folder(raw: Optional[str]) -> Optional[str]:
    v = (raw or "").strip()
    parts = v.split("/")
    if len(parts) == 2 and parts[0] == "folders":
        v = parts[1]
    return v if v.isdigit() else None


def _env_tag_value(raw: Optional[str]) -> Optional[str]:
    v = (raw or "").strip()
    parts = v.split("/")
    return v if len(parts) == 2 and parts[0] == "tagValues" and parts[1].isdigit() else None


def _parse_ts(value) -> Optional[datetime]:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _number_of(project: Dict[str, Any]) -> str:
    """v3 Project.name is exactly 'projects/<number>' (positional split, exact segment count)."""
    parts = str(project.get("name") or "").split("/")
    return parts[1] if len(parts) == 2 and parts[0] == "projects" and parts[1].isdigit() else ""


@dataclass
class GuardContext:
    host_project_ids: FrozenSet[str]
    managed_root_folder_id: Optional[str]
    managed_tag_value: Optional[str]
    ttl_callers: FrozenSet[str]
    crm: Any
    store: Any
    clock: Callable[[], datetime] = field(default=lambda: datetime.now(timezone.utc))
    platform_project_conflict: bool = False
    dns: Any = None
    dns_zone: Optional[str] = None
    child_resources: Any = None  # check 10 resolver: primary_region(product_id), in_state(product_id, rest_name)
    _host_numbers: Optional[FrozenSet[str]] = None

    @classmethod
    def from_env(cls, *, store, crm, clock=None, dns=None, child_resources=None) -> "GuardContext":
        project_id = (os.getenv("PROJECT_ID") or "").strip()
        platform = (os.getenv("PLATFORM_PROJECT_ID") or "").strip()
        hosts = frozenset(v for v in (project_id, (os.getenv("GOOGLE_CLOUD_PROJECT") or "").strip(), platform) if v)
        return cls(
            host_project_ids=hosts,
            managed_root_folder_id=_env_root_folder(os.getenv("MANAGED_WORKLOADS_FOLDER_ID")),
            managed_tag_value=_env_tag_value(os.getenv("STACKVEND_MANAGED_TAG_VALUE")),
            ttl_callers=_csv_emails(os.getenv("SANDBOX_TTL_CALLERS")),
            crm=crm,
            store=store,
            clock=clock or (lambda: datetime.now(timezone.utc)),
            platform_project_conflict=bool(platform) and platform != project_id,
            dns=dns if dns is not None else crm,
            dns_zone=(os.getenv("DNS_MANAGED_ZONE") or "").strip() or None,
            child_resources=child_resources,
        )

    def host_numbers(self) -> FrozenSet[str]:
        """Resolved once per context. Raises CRMUnavailable."""
        if self._host_numbers is None:
            nums = frozenset(_number_of(self.crm.get_project(h)) for h in sorted(self.host_project_ids))
            if "" in nums or not nums:
                raise CRMUnavailable("could not resolve the host project number")
            self._host_numbers = nums
        return self._host_numbers


# ------------------------------------------------------------------------------------------------ caller authn
GOOGLE_ISSUERS = ("accounts.google.com", "https://accounts.google.com")
CLOCK_SKEW_SECONDS = 10


def verify_google_id_token(token: str, audiences: List[str]) -> Dict[str, Any]:
    """Google-signed OIDC ID token (Cloud Run service-to-service). Same verifier the Control Center uses."""
    from google.oauth2 import id_token
    from google.auth.transport import requests as google_requests
    return id_token.verify_oauth2_token(token, google_requests.Request(), audience=audiences,
                                        clock_skew_in_seconds=CLOCK_SKEW_SECONDS)


def authenticate_caller(authorization: Optional[str], *, allowed: FrozenSet[str], audiences: List[str],
                        verifier: Callable[[str, List[str]], Dict[str, Any]],
                        callers_env: str = "DESTRUCTIVE_CALLERS", caller_kind: str = "destructive caller") -> str:
    """Returns the verified, allow-listed caller email or raises CallerRefused (401/403/503). No test-mode bypass.
    `callers_env` / `caller_kind` only name the allow-list in refusal texts (GH-TOKEN-CALLERS reuses this verifier)."""
    if not allowed:
        raise CallerRefused(503, "CALLERS_UNCONFIGURED", f"{callers_env} is not configured")
    if not audiences:
        raise CallerRefused(503, "AUDIENCE_UNCONFIGURED", "VENDING_SERVICE_URL is not configured")
    parts = (authorization or "").split(" ")
    if len(parts) != 2 or parts[0] != "Bearer" or not parts[1]:
        raise CallerRefused(401, "UNAUTHENTICATED", "a Google-signed Bearer ID token is required")
    try:
        info = verifier(parts[1], audiences)
    except Exception as e:  # noqa: BLE001 - any verification failure is unauthenticated
        raise CallerRefused(401, "UNAUTHENTICATED", f"ID token rejected ({type(e).__name__})") from None
    if not isinstance(info, dict) or info.get("iss") not in GOOGLE_ISSUERS:
        raise CallerRefused(401, "UNAUTHENTICATED", "ID token issuer is not Google")
    if info.get("aud") not in audiences:
        raise CallerRefused(401, "UNAUTHENTICATED", "ID token audience is not this service")
    email = info.get("email")
    if info.get("email_verified") is not True or not isinstance(email, str) or not email:
        raise CallerRefused(403, "CALLER_NOT_ALLOWED", "ID token has no verified email")
    email = email.strip().lower()
    if email not in allowed:
        raise CallerRefused(403, "CALLER_NOT_ALLOWED", f"{email} is not an allow-listed {caller_kind}")
    return email


def sandbox_ttl_callers_from_env() -> FrozenSet[str]:
    """SANDBOX_TTL_CALLERS (exact emails, CSV): who may request a SANDBOX_TTL decommission (C10: the CC and the
    sandbox-workload-sweeper-job persona). The guard's 9b check reads the same variable (GuardContext.ttl_callers)."""
    return _csv_emails(os.getenv("SANDBOX_TTL_CALLERS"))


def caller_config_from_env() -> Tuple[FrozenSet[str], List[str]]:
    callers = _csv_emails(os.getenv("DESTRUCTIVE_CALLERS"))
    audiences = [u.strip().rstrip("/") for u in (os.getenv("VENDING_SERVICE_URL") or "").split(",") if u.strip()]
    return callers, audiences


# GH-TOKEN-CALLERS (owner 10-29): who may obtain a GitHub App installation token from GET /github-token.
# The only caller is the refactor scanner job, which runs as sa-castor-developer (infra/platform main.tf
# google_cloud_run_v2_job.jobs: job_runtime_sa has no entry for it). Without the env var the allow-list is that
# account in this host project (PROJECT_ID, set by Terraform on every service), so the narrow default needs no
# core Terraform; a later platform release may set the env var explicitly. A blank value counts as unset; a value
# that parses to no email leaves the list empty (503 CALLERS_UNCONFIGURED, fail closed).
GITHUB_TOKEN_CALLERS_ENV = "GITHUB_TOKEN_ALLOWED_CALLERS"
GITHUB_TOKEN_DEFAULT_CALLER_ACCOUNT = "sa-castor-developer"


def github_token_caller_config_from_env() -> Tuple[FrozenSet[str], List[str]]:
    raw = os.getenv(GITHUB_TOKEN_CALLERS_ENV)
    if raw is not None and raw.strip():
        callers = _csv_emails(raw)
    else:
        host = (os.getenv("PROJECT_ID") or "").strip()
        callers = frozenset({f"{GITHUB_TOKEN_DEFAULT_CALLER_ACCOUNT}@{host}.iam.gserviceaccount.com".lower()}) \
            if host else frozenset()
    _, audiences = caller_config_from_env()
    return callers, audiences


# ------------------------------------------------------------------------------------------------ checks
def _refuse(code: str, detail: str):
    raise DeletionRefused(code, detail)


def _read(fn, *args):
    try:
        return fn(*args)
    except StoreUnavailable as e:
        raise DeletionRefused("LEDGER_UNAVAILABLE", str(e)) from None


def _check_config(ctx: GuardContext) -> None:
    if not ctx.managed_root_folder_id or not ctx.managed_tag_value or not ctx.host_project_ids \
            or ctx.platform_project_conflict:
        _refuse("GUARD_UNCONFIGURED", "MANAGED_WORKLOADS_FOLDER_ID (numeric), STACKVEND_MANAGED_TAG_VALUE "
                "(tagValues/<id>) and a host project id are required; PLATFORM_PROJECT_ID must equal PROJECT_ID")


def _ledger_checks(product_id: str, ctx: GuardContext, checks: List[str]):
    """Checks 1-4. Returns (workload, provenance, project_id, project_number)."""
    _check_config(ctx)
    checks.append("config")

    if not isinstance(product_id, str) or not product_id or product_id in PLATFORM_PSEUDO_WORKLOADS:
        _refuse("PLATFORM_WORKLOAD", f"{product_id!r} is not a tenant workload")
    w = _read(ctx.store.get_workload, product_id)
    if w is None:
        _refuse("LEDGER_MISSING", f"workloads/{product_id} does not exist")
    if w.get("is_castor") is True:
        _refuse("PLATFORM_WORKLOAD", f"workloads/{product_id} is the platform workload")
    if "product_id" in w and w.get("product_id") != product_id:
        _refuse("LEDGER_MISMATCH", "workload record product_id differs from its document id")
    checks.append("ledger")

    project_id = w.get("project_id")
    if not isinstance(project_id, str) or not project_id:
        _refuse("LEDGER_UNPROVENANCED", "workload record has no project_id (no fallback to the product id)")
    prov = _read(ctx.store.get_provenance, product_id)
    if prov is None:
        _refuse("LEDGER_UNPROVENANCED", f"{PROVENANCE}/{product_id} does not exist")
    if prov.get("created_by") not in PROVENANCE_CREATORS:
        _refuse("LEDGER_UNPROVENANCED", f"provenance created_by {prov.get('created_by')!r} is not StackVend's")
    if prov.get("project_id") != project_id:
        _refuse("LEDGER_MISMATCH", "provenance project_id differs from the workload record")
    project_number = _num(prov.get("project_number"))
    if not project_number:
        _refuse("LEDGER_UNPROVENANCED", "provenance has no numeric project_number")
    ledger_number = w.get("project_number")
    if ledger_number not in (None, "") and _num(ledger_number) != project_number:
        _refuse("LEDGER_MISMATCH", "workload record project_number differs from provenance")
    owners = _read(ctx.store.workloads_claiming, project_id)
    if owners != [product_id]:
        _refuse("LEDGER_MISMATCH", f"project {project_id} is claimed by {sorted(owners)}")
    checks.append("provenance")

    if project_id in ctx.host_project_ids:
        _refuse("HOST_PROJECT", f"{project_id} is the host project")
    checks.append("not_host")
    return w, prov, project_id, project_number


def _crm_identity(product_id: str, project_id: str, project_number: str, ctx: GuardContext, checks: List[str],
                  *, require_sandbox_label: bool = False) -> Tuple[Dict[str, Any], str]:
    """Checks 5-7. Returns (project, workload_type)."""
    try:
        host_numbers = ctx.host_numbers()
        project = ctx.crm.get_project(project_number)
    except CRMUnavailable as e:
        raise DeletionRefused("CRM_UNAVAILABLE", str(e)) from None
    if not isinstance(project, dict) or _number_of(project) != project_number or project.get("projectId") != project_id:
        _refuse("CRM_MISMATCH", f"projects/{project_number} is not {project_id}")
    if project_number in host_numbers:
        _refuse("HOST_PROJECT", f"projects/{project_number} is the host project")
    if project.get("state") != "ACTIVE":
        _refuse("NOT_ACTIVE", f"project state is {project.get('state')!r}")
    checks.append("crm_identity")

    workload_type = _check_labels(project, product_id, require_sandbox_label=require_sandbox_label)
    _check_tag(project_number, ctx)
    checks.append("ownership")

    _check_ancestry(project_id, project_number, ctx)
    checks.append("ancestry")
    return project, workload_type


def _check_labels(project: Dict[str, Any], product_id: str, *, require_sandbox_label: bool = False) -> str:
    """Check 6, label half: stackvend-managed == "true", stackvend-product-id == product_id, stackvend-workload-type in
    {sandbox, standard} (== sandbox when required). Returns the workload type. Also used by the lane 18 v3 tag
    backfill (managed_tag_backfill.py), so a tag is never bound to a project the guard would not recognise."""
    labels = project.get("labels")
    labels = labels if isinstance(labels, dict) else {}
    if labels.get(LABEL_MANAGED) != "true" or labels.get(LABEL_PRODUCT) != product_id \
            or labels.get(LABEL_TYPE) not in WORKLOAD_TYPES:
        _refuse("NOT_STACKVEND_OWNED", "StackVend labels do not name this product")
    workload_type = labels[LABEL_TYPE]
    if require_sandbox_label and workload_type != "sandbox":
        _refuse("SANDBOX_NOT_ELIGIBLE", "project is labelled as a non-sandbox workload")
    return workload_type


def _check_ancestry(project_id: str, project_number: str, ctx: GuardContext) -> None:
    """Check 7: v1 getAncestry by the project id (pinned to the number by check 5) starts at the project and has the
    managed root folder as a folder ancestor (i >= 1)."""
    try:
        ancestors = ctx.crm.get_ancestry(project_id)
    except CRMUnavailable as e:
        raise DeletionRefused("ANCESTRY_UNAVAILABLE", str(e)) from None
    ancestors = ancestors if isinstance(ancestors, list) else []
    first = ancestors[0].get("resourceId") if ancestors and isinstance(ancestors[0], dict) else None
    if not isinstance(first, dict) or first.get("type") != "project" \
            or str(first.get("id")) not in (project_id, project_number):
        _refuse("ANCESTRY_UNAVAILABLE", "ancestry does not start at the target project")
    if not any(isinstance(a, dict) and isinstance(a.get("resourceId"), dict)
               and a["resourceId"].get("type") == "folder"
               and str(a["resourceId"].get("id")) == ctx.managed_root_folder_id
               for a in ancestors[1:]):
        _refuse("NOT_IN_MANAGED_FOLDER", f"projects/{project_number} is not under the managed root folder")


def _check_tag(project_number: str, ctx: GuardContext) -> None:
    try:
        bindings = ctx.crm.list_tag_bindings(project_number)
    except CRMUnavailable as e:
        raise DeletionRefused("CRM_UNAVAILABLE", str(e)) from None
    parent = f"{_CRM_FULL_PROJECT}{project_number}"
    if not any(isinstance(b, dict) and b.get("parent") == parent and b.get("tagValue") == ctx.managed_tag_value
               for b in (bindings or [])):
        _refuse("NOT_STACKVEND_OWNED", "no direct stackvend-managed tag binding on the project")


def verify_identity(product_id: str, *, ctx: GuardContext) -> ManagedIdentity:
    """Checks 1-7 (the identity half; lane 14 `verify_managed_target` contract). Read-only."""
    checks: List[str] = []
    _w, prov, project_id, project_number = _ledger_checks(product_id, ctx, checks)
    _project, workload_type = _crm_identity(product_id, project_id, project_number, ctx, checks)
    return ManagedIdentity(product_id=product_id, project_id=project_id, project_number=project_number,
                           workload_type=workload_type, provenance_created_by=prov["created_by"])


def read_approval(ctx: GuardContext, approval_id: Optional[str]) -> Optional[Dict[str, Any]]:
    if not approval_id:
        return None
    try:
        return ctx.store.get_approval(approval_id)
    except StoreUnavailable as e:
        raise DeletionRefused("APPROVAL_UNAVAILABLE", str(e)) from None


def check_approval(approval: Optional[Dict[str, Any]], *, approval_id: Optional[str], action: str, product_id: str,
                   project_id: str, project_number: str, resource_name: Optional[str], now: datetime) -> str:
    """Check 9a. Returns approved_by. Raises DeletionRefused(APPROVAL_*)."""
    if not approval_id or approval is None:
        _refuse("APPROVAL_MISSING", "an approval minted by a human ADMIN session is required")
    if approval.get("consumed_at") or approval.get("status") in ("CONSUMED", "EXECUTED", "EXECUTION_FAILED"):
        _refuse("APPROVAL_CONSUMED", f"approval {approval_id} was already used")
    if approval.get("status") != "APPROVED":
        _refuse("APPROVAL_NOT_APPROVED", f"approval status is {approval.get('status')!r}")
    if approval.get("action") != action or approval.get("product_id") != product_id \
            or approval.get("project_id") != project_id or _num(approval.get("project_number")) != project_number \
            or approval.get("resource_name") != resource_name:
        _refuse("APPROVAL_MISMATCH", "approval does not name this action and target")
    approved_by = approval.get("approved_by")
    if approval.get("principal_type") != "USER" or approval.get("approved_by_role") != "ADMIN" \
            or not isinstance(approved_by, str) or not approved_by:
        _refuse("APPROVAL_NOT_HUMAN", "approval was not minted by a human ADMIN session")
    approved_at, expires_at = _parse_ts(approval.get("approved_at")), _parse_ts(approval.get("expires_at"))
    # S1 code RT Fix 1: the window is anchored to NOW, not only to approved_at. An approved_at in the future (beyond
    # the clock skew) would otherwise make a 15-minute record valid for as long as its author likes.
    if approved_at is None or expires_at is None or not approved_at < expires_at \
            or expires_at - approved_at > APPROVAL_MAX_LIFETIME \
            or approved_at > now + timedelta(seconds=CLOCK_SKEW_SECONDS) \
            or not now < expires_at:
        _refuse("APPROVAL_EXPIRED", "approval is expired, dated in the future, or has no valid 15-minute window")
    return approved_by


def _sandbox_ttl_precheck(caller_email: str, w: Dict[str, Any], prov: Dict[str, Any], ctx: GuardContext,
                          now: datetime) -> None:
    """Check 9b, Firestore part."""
    if not caller_email or caller_email not in ctx.ttl_callers:
        raise DeletionRefused("SANDBOX_NOT_ELIGIBLE", "caller is not an allow-listed SANDBOX_TTL caller", 403)
    if prov.get("created_by") != CREATED_BY_VENDING:
        _refuse("SANDBOX_NOT_ELIGIBLE", "provenance was not written by vending at birth")
    if prov.get("is_sandbox") is not True or prov.get("sandbox_auto_decommission") is not True:
        _refuse("SANDBOX_NOT_ELIGIBLE", "not an auto-decommission sandbox")
    if prov.get("sandbox_designation_source") not in EXPLICIT_DESIGNATION_SOURCES:
        _refuse("SANDBOX_NOT_ELIGIBLE",
                f"sandbox designation {prov.get('sandbox_designation_source')!r} is not explicit")
    expires = _parse_ts(prov.get("sandbox_expires_at"))
    if expires is None or not expires < now:
        _refuse("SANDBOX_NOT_ELIGIBLE", "vend-time sandbox_expires_at is missing or in the future")
    if w.get("is_sandbox") is not True or w.get("status") in NOT_ELIGIBLE_STATUSES:
        _refuse("SANDBOX_NOT_ELIGIBLE", f"workload status {w.get('status')!r} is not eligible")


def _check_liens(project_number: str, ctx: GuardContext) -> None:
    """Check 8. S1 code RT Fix 2(a) / register row L18-g: StackVend never releases a lien. No StackVend component
    places liens, so a name in provenance.liens[] proves nothing (that list has no producer and, before S0b, sits in a
    database every agent SA can write). ANY lien refuses; the owner removes it by hand."""
    try:
        liens = ctx.crm.list_liens(project_number)
    except CRMUnavailable as e:
        raise DeletionRefused("CRM_UNAVAILABLE", str(e)) from None
    for lien in liens or []:
        name = lien.get("name") if isinstance(lien, dict) else None
        _refuse("LIEN_PRESENT", f"lien {name!r} is on projects/{project_number}; StackVend never removes a lien "
                "(remove it by hand, then retry)")


def _check_child_resource(resource_name: Optional[str], product_id: str, project_id: str, ctx: GuardContext) -> None:
    """Check 10 (CHILD_RESOURCE_DELETE): projects/<p>/(locations|regions)/<loc>/<collection>/<name>."""
    parts = resource_name.split("/") if isinstance(resource_name, str) else []
    if len(parts) != 6 or parts[0] != "projects" or parts[2] not in ("locations", "regions") \
            or not all(parts):
        _refuse("RESOURCE_NOT_IN_STATE", f"unsupported resource name {resource_name!r}")
    if parts[1] != project_id:
        _refuse("RESOURCE_NOT_IN_STATE", "resource is not in the workload's project")
    resolver = ctx.child_resources
    if resolver is None:
        _refuse("RESOURCE_NOT_IN_STATE", "no workload state/region resolver configured (fail closed)")
    try:
        primary = resolver.primary_region(product_id)
        in_state = resolver.in_state(product_id, resource_name)
    except Exception as e:  # noqa: BLE001
        _refuse("RESOURCE_NOT_IN_STATE", f"state/region facts unavailable ({type(e).__name__})")
    if not isinstance(primary, str) or not primary:
        _refuse("RESOURCE_NOT_IN_STATE", "the workload's primary region is not resolvable")
    if parts[3] != primary:
        _refuse("CROSS_REGION_SECONDARY", f"{parts[4]} in {parts[3]} is outside the primary region (Invariant 5)")
    if in_state is not True:
        _refuse("RESOURCE_NOT_IN_STATE", "resource is not present in the workload state")


def _audit(ctx: GuardContext, product_id: str, record: Dict[str, Any]) -> None:
    logger.info("destructive-guard %s", json.dumps(record, sort_keys=True, default=str))
    ctx.store.write_audit(product_id, record)


def assert_deletable(target: DeletionTarget, *, action_class, approval_id: Optional[str], caller_email: str,
                     ctx: GuardContext) -> GuardVerdict:
    """Raises DeletionRefused unless every check passes. Read-only except the audit record (check 11)."""
    action_class = ActionClass(action_class)
    product_id = target.product_id
    now = ctx.clock()
    checks: List[str] = []
    try:
        if action_class in PROJECT_LEVEL_CLASSES and target.resource_name is not None:
            _refuse("INVALID_REQUEST", f"{action_class.value} takes no resource name")
        w, prov, project_id, project_number = _ledger_checks(product_id, ctx, checks)

        approved_by = None
        if action_class in HITL_CLASSES:
            approval = read_approval(ctx, approval_id)
            approved_by = check_approval(approval, approval_id=approval_id, action=action_class.value,
                                         product_id=product_id, project_id=project_id,
                                         project_number=project_number, resource_name=target.resource_name, now=now)
            checks.append("approval")
        elif action_class is ActionClass.SANDBOX_TTL:
            _sandbox_ttl_precheck(caller_email, w, prov, ctx, now)
            checks.append("sandbox_ttl")

        _crm_identity(product_id, project_id, project_number, ctx, checks,
                      require_sandbox_label=action_class is ActionClass.SANDBOX_TTL)
        _check_liens(project_number, ctx)
        checks.append("liens")

        if action_class is ActionClass.CHILD_RESOURCE_DELETE:
            _check_child_resource(target.resource_name, product_id, project_id, ctx)
            checks.append("child_resource")

        dns = tuple((r["name"], r["type"]) for r in (prov.get("dns_records") or [])
                    if isinstance(r, dict) and isinstance(r.get("name"), str) and isinstance(r.get("type"), str))
        verdict = GuardVerdict(product_id=product_id, project_id=project_id, project_number=project_number,
                               resource_name=target.resource_name, action_class=action_class,
                               approval_id=approval_id if action_class in HITL_CLASSES else None,
                               caller_email=caller_email, checks=tuple(checks), approved_by=approved_by,
                               ledger_status=w.get("status"), dns_records=dns)
        try:
            _audit(ctx, product_id, {"action": "DESTRUCTIVE_GUARD_ALLOW", "action_class": action_class.value,
                                     "product_id": product_id, "project_id": project_id,
                                     "project_number": project_number, "resource_name": target.resource_name,
                                     "approval_id": verdict.approval_id, "caller": caller_email,
                                     "approved_by": approved_by, "checks": list(checks), "timestamp": now.isoformat()})
        except Exception as e:  # noqa: BLE001
            _refuse("AUDIT_UNAVAILABLE", f"audit write failed ({type(e).__name__})")
        return verdict
    except DeletionRefused as refusal:
        logger.warning("destructive-guard %s", json.dumps({
            "action": "DESTRUCTIVE_GUARD_REFUSED", "code": refusal.code, "detail": refusal.detail,
            "action_class": action_class.value, "product_id": product_id, "caller": caller_email,
            "approval_id": approval_id, "checks_passed": checks}, sort_keys=True, default=str))
        raise


def recheck_before_delete(verdict: GuardVerdict, ctx: GuardContext) -> None:
    """Plan F8 + S1 code RT Fix 3: immediately before the delete, re-read projects/<number> (id, state), the direct
    tag, the ancestry (a project moved out of the managed folder in between is refused) and the liens (any lien
    refuses). Read-only."""
    try:
        project = ctx.crm.get_project(verdict.project_number)
    except CRMUnavailable as e:
        raise DeletionRefused("CRM_UNAVAILABLE", str(e)) from None
    if not isinstance(project, dict) or _number_of(project) != verdict.project_number \
            or project.get("projectId") != verdict.project_id:
        _refuse("CRM_MISMATCH", f"projects/{verdict.project_number} is no longer {verdict.project_id}")
    if project.get("state") != "ACTIVE":
        _refuse("NOT_ACTIVE", f"project state is {project.get('state')!r}")
    _check_tag(verdict.project_number, ctx)
    _check_ancestry(verdict.project_id, verdict.project_number, ctx)
    _check_liens(verdict.project_number, ctx)


def consume_approval(verdict: GuardVerdict, *, ctx: GuardContext) -> None:
    if verdict.action_class not in HITL_CLASSES:
        return
    try:
        ctx.store.consume_approval(verdict.approval_id, consumed_by=verdict.caller_email, now=ctx.clock())
    except ApprovalConflict as e:
        raise DeletionRefused("APPROVAL_CONSUMED", str(e)) from None
    except StoreUnavailable as e:
        raise DeletionRefused("APPROVAL_UNAVAILABLE", str(e)) from None


def mark_execution_failed(verdict: GuardVerdict, *, error: str, ctx: GuardContext) -> None:
    """Plan F10b. Best effort: the failure is also in the ledger and the audit log."""
    if verdict.action_class not in HITL_CLASSES or not verdict.approval_id:
        return
    try:
        ctx.store.update_approval(verdict.approval_id, {"status": "EXECUTION_FAILED", "execution_error": error,
                                                        "execution_failed_at": ctx.clock().isoformat()})
    except Exception as e:  # noqa: BLE001
        logger.error("could not mark approval %s EXECUTION_FAILED: %s", verdict.approval_id, e)
