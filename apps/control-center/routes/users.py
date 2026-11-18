"""
Project Castor: User Directory & Access Control Routes
Manages approved emails, roles, and workload-scoped RBAC permissions.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Request
from authz import ADMIN, require

from auth import MOCK_AUTHORIZED_USERS, bootstrap_registry_record, verify_admin_access
from config import DEFAULT_ADMIN_EMAIL
from db import db
from schemas import (
    AddUserRequest,
    UpdateUserWorkloadsRequest,
    UserAccessRecord,
    UserRole,
)

logger = logging.getLogger("control-center-users")

router = APIRouter(tags=["Users"])

# FD-4CI-b (9-10): every grant, role / workload change and revoke is recorded here (who, when, before and after), in
# the same Firestore batch as the change itself, so a change without its audit entry is never stored.
USER_ACCESS_AUDIT_COLLECTION = "user_access_audit"


def _stored_role(role: Any) -> str:
    """The role value stored for a user. The legacy APPROVER is stored as WORKLOAD_MANAGER, which is what
    authorization has always given it (``UserAccessRecord``); every other role as is. No new powers."""
    value = role.value if hasattr(role, "value") else str(role)
    return UserRole.WORKLOAD_MANAGER.value if value == UserRole.APPROVER.value else value


def _access_view(data: Any) -> Optional[Dict[str, Any]]:
    """The access fields of a stored user record for the audit entry (None = no record)."""
    if not isinstance(data, dict):
        return None
    workloads = data.get("assigned_workloads")
    return {"role": data.get("role"), "is_active": data.get("is_active", True),
            "assigned_workloads": list(workloads) if isinstance(workloads, (list, tuple)) else []}


_UNREADABLE = object()


def _audit_entry(action: str, email: str, operator: str, before: Any, after: Any) -> Dict[str, Any]:
    entry = {"action": action, "email": email, "operator_email": operator,
             "timestamp": datetime.now(timezone.utc).isoformat(),
             "before": None if before is _UNREADABLE else _access_view(before), "after": _access_view(after)}
    if before is _UNREADABLE:
        entry["before_unreadable"] = True
    return entry


# FD-4CI-b-3b: a user access change Firestore did not store is answered 503 with this typed detail, never 200.
USER_ACCESS_NOT_STORED = "USER_ACCESS_NOT_STORED"
# FD-4CI-b-3c: the Access Control tab shows at most this many audit entries, newest first.
USER_ACCESS_AUDIT_VIEW_LIMIT = 50


def _not_stored(message: str, err: Exception) -> HTTPException:
    """FD-4CI-b-3b: the typed 503 for a user access write that Firestore did not store (exception type only)."""
    return HTTPException(status_code=503, detail={"code": USER_ACCESS_NOT_STORED,
                                                  "message": f"{message} (Firestore: {type(err).__name__}). Retry."})


def _firestore_unreachable(err: BaseException) -> bool:
    """FD-4CI-b-3d: True only when the write never reached Firestore (the service was unavailable or the call timed out,
    typed google.api_core errors). Firestore refusing the write (permission, invalid data, quota, ...) or any other
    error is False: no emergency copy is kept for it."""
    try:
        from google.api_core import exceptions as gexc
    except ImportError:  # pragma: no cover
        return False
    # DeadlineExceeded is a GatewayTimeout. A RetryError counts only by its last cause (a lasting quota refusal
    # surfaces as RetryError(cause=ResourceExhausted)); with no cause recorded the retries simply ran out.
    if isinstance(err, gexc.RetryError):
        cause = err.cause
        return cause is None or isinstance(cause, (gexc.ServiceUnavailable, gexc.GatewayTimeout))
    return isinstance(err, (gexc.ServiceUnavailable, gexc.GatewayTimeout))


def _clear_emergency_copy(email: str) -> None:
    """FD-4CI-b-3d: drop this instance's emergency (break-glass) copy of a grant Firestore did not save, once the user's
    access has been saved / changed / revoked (or a newer grant was refused). The install-time entry of the platform
    owner is not a copy: it is put back as it was at startup."""
    if email not in MOCK_AUTHORIZED_USERS:
        return
    if DEFAULT_ADMIN_EMAIL and email == DEFAULT_ADMIN_EMAIL:
        MOCK_AUTHORIZED_USERS[email] = bootstrap_registry_record(email)
    else:
        MOCK_AUTHORIZED_USERS.pop(email, None)


def _stored_user(doc_ref: Any) -> Any:
    """The stored record before a grant / revoke (None = none). Best effort: an unreadable record never stops the
    change itself; the audit entry then says so (``before_unreadable``)."""
    try:
        snap = doc_ref.get()
        return (snap.to_dict() or {}) if getattr(snap, "exists", False) else None
    except Exception as e:  # noqa: BLE001
        logger.warning(f"User record {getattr(doc_ref, 'id', '?')} unreadable before the change ({type(e).__name__})")
        return _UNREADABLE


@router.get("/api/users", response_model=List[UserAccessRecord], dependencies=[require(ADMIN)])
def list_approved_users(request: Request):
    """Lists all approved email addresses and assigned authorization roles."""
    verify_admin_access(request)
    if db:
        try:
            docs = db.collection("authorized_users").stream()
            results = []
            for d in docs:
                data = d.to_dict() or {}
                role_val = data.get("role", "WORKLOAD_MANAGER")
                try:
                    role_enum = UserRole(role_val)
                except ValueError:
                    role_enum = UserRole.WORKLOAD_MANAGER
                results.append(
                    UserAccessRecord(
                        email=data.get("email", d.id),
                        role=role_enum,
                        assigned_workloads=data.get("assigned_workloads") or [],
                        added_at=data.get("added_at", ""),
                        added_by=data.get("added_by", "admin"),
                        is_active=data.get("is_active", True),
                    )
                )
            if results:
                return results
        except Exception as e:
            logger.warning(f"Failed to list authorized users from Firestore ({e}). Returning fallback registry.")

    return list(MOCK_AUTHORIZED_USERS.values())


@router.post("/api/users", response_model=UserAccessRecord, dependencies=[require(ADMIN)])
def add_approved_user(req: AddUserRequest, request: Request):
    """Adds a new authorized email address with role permissions in Firestore and local registry."""
    verify_admin_access(request)
    admin_email = getattr(request.state, "user_email", "admin-console")

    clean_email = req.email.strip().lower()
    if not clean_email or "@" not in clean_email:
        raise HTTPException(status_code=400, detail="Invalid email address format.")

    assigned = req.assigned_workloads if (req.role != UserRole.ADMIN) else []
    record = UserAccessRecord(
        email=clean_email,
        role=req.role or UserRole.VIEWER,
        assigned_workloads=assigned,
        added_at=datetime.now(timezone.utc).isoformat(),
        added_by=admin_email,
        is_active=True,
    )

    # N2: the per-instance registry is break-glass only. Write it only when Firestore is absent or the
    # write could not reach Firestore, so a grant revoked on another instance cannot resurface during an outage.
    if db:
        try:
            doc_ref = db.collection("authorized_users").document(clean_email)
            stored = record.model_dump(mode="json")
            batch = db.batch()  # FD-4CI-b: the grant and its audit entry land together or not at all
            batch.set(doc_ref, stored)
            batch.set(db.collection(USER_ACCESS_AUDIT_COLLECTION).document(),
                      _audit_entry("USER_ACCESS_GRANTED", clean_email, admin_email, _stored_user(doc_ref), stored))
            batch.commit()
            logger.info(f"Added approved user email to Firestore: {clean_email} (Role: {record.role.value}) by {admin_email}")
        except Exception as e:
            # FD-4CI-b-3b: the answer says it was not stored, never 200. FD-4CI-b-3d: the emergency copy (read only
            # while this instance cannot read Firestore) is kept only when Firestore could not be reached at all.
            if _firestore_unreachable(e):
                logger.error(f"Failed to persist user {clean_email} (Role: {record.role.value}) by {admin_email}: "
                             f"Firestore unreachable ({type(e).__name__}). Stored in this instance's break-glass "
                             f"registry only.")
                MOCK_AUTHORIZED_USERS[clean_email] = record
                raise _not_stored(f"Access for {clean_email} was not saved. It works only on this Control Center "
                                  f"instance, and only while that instance cannot reach Firestore", e)
            logger.error(f"Failed to persist user {clean_email} (Role: {record.role.value}) by {admin_email}: "
                         f"Firestore refused the write ({type(e).__name__}). No break-glass copy kept.")
            _clear_emergency_copy(clean_email)
            raise _not_stored(f"Access for {clean_email} was not saved", e)
        _clear_emergency_copy(clean_email)  # FD-4CI-b-3d: saved, so an older emergency copy is stale
    else:
        MOCK_AUTHORIZED_USERS[clean_email] = record

    return record


@router.put("/api/users/{email}/workloads", response_model=UserAccessRecord, dependencies=[require(ADMIN)])
def update_user_workloads(email: str, req: UpdateUserWorkloadsRequest, request: Request):
    """Updates assigned workloads and optional role for an authorized user."""
    verify_admin_access(request)
    admin_email = getattr(request.state, "user_email", "admin-console")
    clean_email = email.strip().lower()

    if db:
        try:
            doc_ref = db.collection("authorized_users").document(clean_email)
            doc = doc_ref.get()
        except Exception as e:  # noqa: BLE001  FD-4CI-b-3b: typed 503, nothing changed
            logger.error(f"User record {clean_email} unreadable; access not changed ({type(e).__name__})")
            raise _not_stored(f"Access for {clean_email} was not changed: the user record could not be read", e)
        if not doc.exists:
            raise HTTPException(status_code=404, detail=f"User '{clean_email}' not found.")
        before = doc.to_dict() or {}
        data = dict(before)
        data["assigned_workloads"] = req.assigned_workloads
        if req.role is not None:
            data["role"] = _stored_role(req.role)
        try:
            batch = db.batch()  # FD-4CI-b: the change and its audit entry land together or not at all
            batch.set(doc_ref, data, merge=True)
            batch.set(db.collection(USER_ACCESS_AUDIT_COLLECTION).document(),
                      _audit_entry("USER_ACCESS_UPDATED", clean_email, admin_email, before, data))
            batch.commit()
        except Exception as e:  # noqa: BLE001  FD-4CI-b-3b: typed 503, nothing claimed
            logger.error(f"Failed to update user {clean_email} in Firestore; access not changed ({type(e).__name__})")
            raise _not_stored(f"Access for {clean_email} was not changed", e)
        logger.info(f"Updated user access in Firestore: {clean_email} (Role: {data.get('role')}) by {admin_email}")
        _clear_emergency_copy(clean_email)  # FD-4CI-b-3d: changed, so an older emergency copy is stale
        rec = UserAccessRecord(**data)
        return rec

    if clean_email in MOCK_AUTHORIZED_USERS:
        rec = MOCK_AUTHORIZED_USERS[clean_email]
        rec.assigned_workloads = req.assigned_workloads
        if req.role is not None:
            rec.role = UserRole(_stored_role(req.role))  # legacy APPROVER -> WORKLOAD_MANAGER on every path
        return rec

    raise HTTPException(status_code=404, detail=f"User '{clean_email}' not found.")


@router.delete("/api/users/{email}", dependencies=[require(ADMIN)])
def remove_approved_user(email: str, request: Request):
    """Removes / revokes an authorized user email address from Firestore and local registry."""
    verify_admin_access(request)
    admin_email = getattr(request.state, "user_email", "admin-console")
    clean_email = email.strip().lower()

    if DEFAULT_ADMIN_EMAIL and clean_email == DEFAULT_ADMIN_EMAIL:
        raise HTTPException(status_code=400, detail="Cannot revoke permissions for the primary platform owner.")

    MOCK_AUTHORIZED_USERS.pop(clean_email, None)

    if db:
        try:
            doc_ref = db.collection("authorized_users").document(clean_email)
            batch = db.batch()  # FD-4CI-b: the revoke and its audit entry land together or not at all
            batch.set(db.collection(USER_ACCESS_AUDIT_COLLECTION).document(),
                      _audit_entry("USER_ACCESS_REVOKED", clean_email, admin_email, _stored_user(doc_ref), None))
            batch.delete(doc_ref)
            batch.commit()
            logger.info(f"Removed approved user email from Firestore: {clean_email} by {admin_email}")
        except Exception as e:  # noqa: BLE001
            # FD-4CI-b-3b: before, 200 "REMOVED" while the Firestore record (and so the user's access) stayed.
            logger.error(f"Failed to delete user {clean_email} from Firestore ({type(e).__name__}); NOT revoked.")
            raise _not_stored(f"Access for {clean_email} was NOT revoked; the user can still sign in", e)

    return {"status": "REMOVED", "email": clean_email}


def _audit_view(entry: Any) -> Optional[Dict[str, Any]]:
    """One ``user_access_audit`` entry as shown on the Access Control tab: only the known fields (who, when, what,
    access before and after); anything else stored on the document is never returned."""
    if not isinstance(entry, dict):
        return None
    view = {k: (str(entry.get(k)) if entry.get(k) is not None else None)
            for k in ("action", "email", "operator_email", "timestamp")}
    view["before"], view["after"] = _access_view(entry.get("before")), _access_view(entry.get("after"))
    view["before_unreadable"] = entry.get("before_unreadable") is True
    return view


@router.get("/api/users/access-audit", dependencies=[require(ADMIN)])
def list_user_access_audit(request: Request):
    """FD-4CI-b-3c: the most recent user access audit entries (grant / change / revoke), newest first, at most
    ``USER_ACCESS_AUDIT_VIEW_LIMIT``. ADMIN only. 503 (typed) when Firestore is absent or unreadable: no audit is
    kept without Firestore, and an empty list would wrongly say nothing changed."""
    verify_admin_access(request)
    if not db:
        raise HTTPException(status_code=503, detail={"code": "USER_ACCESS_AUDIT_UNAVAILABLE",
                                                     "message": "Firestore is not configured; no access audit is kept."})
    try:
        docs = (db.collection(USER_ACCESS_AUDIT_COLLECTION).order_by("timestamp", direction="DESCENDING")
                .limit(USER_ACCESS_AUDIT_VIEW_LIMIT).stream())
        entries = [v for v in (_audit_view(d.to_dict()) for d in docs) if v is not None]
    except Exception as e:  # noqa: BLE001
        logger.error(f"user_access_audit unreadable ({type(e).__name__})")
        raise HTTPException(status_code=503, detail={"code": "USER_ACCESS_AUDIT_UNAVAILABLE",
                                                     "message": f"The access audit could not be read "
                                                                f"(Firestore: {type(e).__name__}). Retry."})
    # Firestore already orders and limits; sorting again keeps the contract when an entry's timestamp is missing.
    entries.sort(key=lambda v: v.get("timestamp") or "", reverse=True)
    return {"entries": entries[:USER_ACCESS_AUDIT_VIEW_LIMIT], "limit": USER_ACCESS_AUDIT_VIEW_LIMIT}
