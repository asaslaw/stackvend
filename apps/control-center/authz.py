"""
StackVend Control Center: route-level authorization (FD-4N). Single source of truth for "who may call what".

Rules (see docs/planning/wave1-lane4-control-center-plan.md and wave1-lane4-plan-red-team.md):
- Every FastAPI route declares exactly ONE policy, on its decorator: `@router.get(path, dependencies=[require(P)])`.
  A policy set through `APIRouter(dependencies=...)` is NOT found (fails closed: 403).
- `enforce_declared_policy` is an app-level dependency: a route without a policy is denied (403), and
  `main.py` refuses to boot if any effective route lacks one (`assert_all_routes_have_policy`).
- Authorization never reads TEST_MODE / MOCK_MODE. Tests call handlers directly or authenticate for real.
- Service principals (platform callers) are trusted only through a verified OIDC bearer, and only on routes whose
  policy accepts them (ADMIN_OR_JOB, PUBSUB_PUSH). Everywhere else a bearer identity is refused.
- Child objects (feature requests, traces, approvals) are bound to their workload by an exact `product_id` match.
- Raises the real fastapi.HTTPException (never the test-scaffolding DynamicHTTPException).
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import FrozenSet, Iterable, Iterator, List, Optional, Tuple

from fastapi import Depends, HTTPException, Request

import identity
from schemas import UserRole

logger = logging.getLogger("control-center-authz")

# Platform pseudo-workloads: ids that address the HOST platform itself (host-wide logs, platform repo).
# Exact ids only; WORKLOAD-type policies treat them as ADMIN-only (red-team H8).
PLATFORM_PSEUDO_WORKLOADS: FrozenSet[str] = frozenset({"project-castor", "castor", "platform"})

HUMAN_METHODS = frozenset({"iap", "session"})

# Exact paths that skip authentication in AuthorizationMiddleware. Must equal the set of routes declared PUBLIC.
PUBLIC_PATHS: FrozenSet[str] = frozenset({"/health", "/auth/google-login", "/auth/config-client-id", "/auth/logout"})

# FD-4AR: the ONE public static mount. Vendored, SRI-pinned browser scripts that the sign-in page needs before login.
# Exempt by this exact prefix only (trailing slash included); nothing else under /static is mounted or public.
PUBLIC_STATIC_MOUNT = "/static/vendor"
PUBLIC_STATIC_PREFIX = PUBLIC_STATIC_MOUNT + "/"


def is_public_path(path: str) -> bool:
    """True only for the exact PUBLIC route paths and files under the vendored-scripts mount."""
    return path in PUBLIC_PATHS or path.startswith(PUBLIC_STATIC_PREFIX)


# ---------------------------------------------------------------- policies
@dataclass(frozen=True)
class Policy:
    kind: str
    param: str = ""
    child_param: str = ""
    collection: str = ""
    manager: bool = False
    path: str = ""
    child_field: str = ""

    def describe(self) -> str:
        parts = [self.kind]
        if self.param:
            parts.append(f"param={self.param}")
        if self.child_param:
            parts.append(f"child={self.collection}/{{{self.child_param}}}")
        elif self.kind == "TRACE" and self.collection != "pipeline_executions":
            parts.append(f"collection={self.collection}")
        if self.manager:
            parts.append("manager")
        if self.path:
            parts.append(f"path={self.path}")
        return " ".join(parts)


PUBLIC = Policy("PUBLIC")
AUTHENTICATED = Policy("AUTHENTICATED")
SCOPED = Policy("SCOPED")
ADMIN = Policy("ADMIN")
ADMIN_OR_JOB = Policy("ADMIN_OR_JOB")


def WORKLOAD(param: str = "product_id", manager: bool = False) -> Policy:
    return Policy("WORKLOAD", param=param, manager=manager)


def WORKLOAD_CHILD(child_param: str, collection: str, param: str = "product_id", manager: bool = False,
                   child_field: str = "") -> Policy:
    """`collection/{child_param}` must exist and carry product_id == the path product_id (exact). When the child is
    not stored under its id, `child_field` names the field to look it up by (both fields re-checked in Python)."""
    return Policy("WORKLOAD_CHILD", param=param, child_param=child_param, collection=collection, manager=manager,
                  child_field=child_field)


def WORKLOAD_BY_PROJECT(param: str = "project_id") -> Policy:
    return Policy("WORKLOAD_BY_PROJECT", param=param)


def TRACE(param: str = "trace_id", manager: bool = False, collection: str = "pipeline_executions") -> Policy:
    """Object keyed by a trace id: `collection/{param}.product_id` -> WORKLOAD check. No doc / no product_id => ADMIN."""
    return Policy("TRACE", param=param, collection=collection, manager=manager)


def APPROVAL(param: str = "approval_id") -> Policy:
    return Policy("APPROVAL", param=param, collection="approval_requests", manager=True)


def PUBSUB_PUSH(path: str) -> Policy:
    return Policy("PUBSUB_PUSH", path=path)


# ---------------------------------------------------------------- scope type (red-team H11: no `None == all`)
@dataclass(frozen=True)
class WorkloadScope:
    all: bool
    ids: FrozenSet[str]

    def allows(self, product_id) -> bool:
        if self.all:
            return True
        return isinstance(product_id, str) and product_id in self.ids and product_id not in PLATFORM_PSEUDO_WORKLOADS


NO_WORKLOADS = WorkloadScope(all=False, ids=frozenset())


def _assigned_ids(request) -> FrozenSet[str]:
    raw = getattr(getattr(request, "state", None), "assigned_workloads", None)
    if not isinstance(raw, (list, tuple, set, frozenset)):
        return frozenset()
    return frozenset(a.strip().lower() for a in raw if isinstance(a, str) and a.strip())


def _role(request) -> Optional[UserRole]:
    role = getattr(getattr(request, "state", None), "user_role", None)
    if isinstance(role, UserRole):
        return role
    if isinstance(role, str):
        try:
            return UserRole(role)
        except ValueError:
            return None
    return None


def _method(request) -> str:
    m = getattr(getattr(request, "state", None), "auth_method", "")
    return m if isinstance(m, str) else ""


def is_platform_bearer(request) -> bool:
    email = getattr(getattr(request, "state", None), "user_email", "")
    return _method(request) == "bearer" and isinstance(email, str) and email in identity.platform_callers()


def is_human_admin(request) -> bool:
    return _method(request) in HUMAN_METHODS and _role(request) == UserRole.ADMIN


# Typed principal of the verified identity (lane 18 S2: destructive approvals record it; vending requires "USER").
PRINCIPAL_USER = "USER"
PRINCIPAL_SERVICE_ACCOUNT = "SERVICE_ACCOUNT"


def principal_type(request) -> str:
    """HOW the auth layer verified this request's identity, as a type -- never derived from the email text:
    "USER" for a human verified by an IAP assertion or a session cookie (HUMAN_METHODS), "SERVICE_ACCOUNT" for an
    allow-listed platform caller verified by an OIDC bearer, "" for anything else (fails closed)."""
    if _method(request) in HUMAN_METHODS:
        return PRINCIPAL_USER
    if is_platform_bearer(request):
        return PRINCIPAL_SERVICE_ACCOUNT
    return ""


def workload_scope(request) -> WorkloadScope:
    """Caller's visible workloads, for in-handler filtering of SCOPED routes. Role-based (the route policy has
    already required a human principal). Fails closed: missing/unknown role => nothing; pseudo-workloads only
    for ADMIN. There is no privileged default (red-team H11)."""
    role = _role(request)
    if role == UserRole.ADMIN:
        return WorkloadScope(all=True, ids=frozenset())
    if role is None:
        return NO_WORKLOADS
    return WorkloadScope(all=False, ids=_assigned_ids(request) - PLATFORM_PSEUDO_WORKLOADS)


# ---------------------------------------------------------------- checks
def _deny(status: int, detail: str):
    raise HTTPException(status_code=status, detail=detail)


def _require_human(request: Request) -> UserRole:
    if not hasattr(request, "state") or not getattr(request.state, "user_email", None):
        _deny(401, "Authentication required.")
    if _method(request) not in HUMAN_METHODS:
        _deny(403, "Forbidden: this route does not accept service credentials.")
    role = _role(request)
    if role is None:
        _deny(401, "Authentication required.")
    return role


def _check_workload(request: Request, product_id, manager: bool) -> None:
    """Workload ids are compared EXACTLY against the path (code RT F8): every writer of workloads/{id} lower-cases the
    id (CC create/express/bootstrap `strip().lower()`, project-vending, spec-ingestion `extract_product_id`), so a
    path id that is not already lower-case never names a StackVend workload and is refused. Assignments, which an
    administrator types, are matched after strip().lower() (as on main), so no existing assignee is locked out.
    Mixed-case workload document ids written outside StackVend are unsupported (administrators still reach them)."""
    role = _require_human(request)
    if role == UserRole.ADMIN:
        return
    pid = product_id if isinstance(product_id, str) else ""
    if not pid or pid in PLATFORM_PSEUDO_WORKLOADS or pid != pid.strip().lower() or pid not in _assigned_ids(request):
        _deny(403, f"Access denied: you are not assigned to workload '{pid}'.")
    if manager and role == UserRole.VIEWER:
        _deny(403, f"Permission denied: Viewer role cannot modify workload '{pid}'.")


def _db():
    from db import db  # LazyDbProxy: resolves main.db (tests swap in a fake)
    return db


def _load(collection: str, doc_id: str):
    db = _db()
    if not db:
        _deny(503, "Firestore unavailable: cannot authorize this request.")
    try:
        snap = db.collection(collection).document(doc_id).get()
    except Exception as e:  # noqa: BLE001 - fail closed
        logger.error(f"authz lookup {collection}/{doc_id} failed: {e}")
        _deny(503, "Authorization lookup failed.")
    return (snap.to_dict() or {}) if getattr(snap, "exists", False) else None


def _find_child(collection: str, field: str, value: str, product_id) -> Optional[dict]:
    db = _db()
    if not db or not value:
        return None
    try:
        for snap in db.collection(collection).where(field, "==", value).stream():
            data = snap.to_dict() or {}
            if data.get(field) == value and data.get("product_id") == product_id:
                return data
    except Exception as e:  # noqa: BLE001 - fail closed
        logger.error(f"authz lookup {collection}[{field}=={value}] failed: {e}")
        _deny(503, "Authorization lookup failed.")
    return None


def _check(policy: Policy, request: Request) -> None:
    k = policy.kind
    params = request.path_params
    if k == "PUBLIC":
        return
    if k in ("AUTHENTICATED", "SCOPED"):
        _require_human(request)
        return
    if k == "ADMIN":
        if _require_human(request) != UserRole.ADMIN:
            _deny(403, "Forbidden: Platform Administrator privileges required.")
        return
    if k == "ADMIN_OR_JOB":
        if is_platform_bearer(request):
            return
        if _require_human(request) != UserRole.ADMIN:
            _deny(403, "Forbidden: Platform Administrator privileges required.")
        return
    if k == "PUBSUB_PUSH":
        if not is_platform_bearer(request):
            _deny(403, "Forbidden: Pub/Sub push endpoint accepts only the platform push identity.")
        aud = getattr(request.state, "token_audience", "")
        expected = {u + policy.path for u in identity.get_runtime_identity().service_urls}
        if not isinstance(aud, str) or aud not in expected:
            _deny(403, "Forbidden: push token audience must be exactly this endpoint.")
        return
    if k == "WORKLOAD":
        _check_workload(request, params.get(policy.param), policy.manager)
        return
    if k == "WORKLOAD_CHILD":
        pid = params.get(policy.param)
        _check_workload(request, pid, policy.manager)
        child = params.get(policy.child_param) or ""
        doc = _load(policy.collection, child)
        if doc is None and policy.child_field:
            doc = _find_child(policy.collection, policy.child_field, child, pid)
        if doc is None:
            if is_human_admin(request):
                return  # handler reports 404
            _deny(403, "Access denied.")
        if doc.get("product_id") != pid:
            _deny(404 if is_human_admin(request) else 403,
                  f"'{child}' does not belong to workload '{pid}'.")
        return
    if k in ("TRACE", "APPROVAL"):
        role = _require_human(request)
        if role == UserRole.ADMIN:
            return
        doc = _load(policy.collection, params.get(policy.param) or "")
        if doc is None or not isinstance(doc.get("product_id"), str) or not doc.get("product_id"):
            _deny(403, "Access denied.")
        _check_workload(request, doc["product_id"], policy.manager)
        return
    if k == "WORKLOAD_BY_PROJECT":
        role = _require_human(request)
        if role == UserRole.ADMIN:
            return
        proj = params.get(policy.param) or ""
        host = (os.getenv("PROJECT_ID") or "").strip()
        if not proj or proj == host:
            _deny(403, "Access denied: host project is administrator-only.")
        db = _db()
        if not db:
            _deny(503, "Firestore unavailable: cannot authorize this request.")
        assigned = _assigned_ids(request) - PLATFORM_PSEUDO_WORKLOADS
        try:
            owners = [s.id for s in db.collection("workloads").where("project_id", "==", proj).stream()
                      if (s.to_dict() or {}).get("project_id") == proj]
        except Exception as e:  # noqa: BLE001
            logger.error(f"authz project lookup failed: {e}")
            _deny(503, "Authorization lookup failed.")
        if not any(o in assigned for o in owners):
            _deny(403, "Access denied: project is not part of an assigned workload.")
        return
    _deny(403, f"Unknown authorization policy {k!r}.")


def require(policy: Policy):
    """Route-decorator dependency: `dependencies=[require(ADMIN)]`."""
    def _authz_dependency(request: Request) -> None:
        _check(policy, request)

    _authz_dependency.__authz_policy__ = policy
    _authz_dependency.__name__ = f"authz_{policy.kind.lower()}"
    return Depends(_authz_dependency)


# ---------------------------------------------------------------- inventory + deny-by-default
def policies_of(route) -> List[Policy]:
    out = []
    for dep in getattr(route, "dependencies", None) or []:
        pol = getattr(getattr(dep, "dependency", None), "__authz_policy__", None)
        if isinstance(pol, Policy):
            out.append(pol)
    return out


def policy_of(route) -> Optional[Policy]:
    pols = policies_of(route)
    return pols[0] if len(pols) == 1 else None


def iter_effective_routes(routes: Iterable) -> Iterator[Tuple[object, str, frozenset]]:
    """(original_route, effective path, methods) for every route, including routes inside included routers.
    FastAPI >= 0.13x wraps include_router in _IncludedRouter objects, so `app.routes` alone is NOT enough."""
    try:
        from fastapi.routing import iter_route_contexts
    except ImportError:  # older FastAPI flattens include_router into app.routes
        iter_route_contexts = None
    if iter_route_contexts is not None:
        for ctx in iter_route_contexts(list(routes)):
            yield ctx.original_route, ctx.path or getattr(ctx.original_route, "path", ""), frozenset(ctx.methods or ())
        return
    for r in routes:
        yield r, getattr(r, "path", ""), frozenset(getattr(r, "methods", None) or ())


def routes_missing_policy(app) -> List[str]:
    from fastapi.routing import APIRoute
    missing = []
    for route, path, methods in iter_effective_routes(app.routes):
        if isinstance(route, APIRoute) and policy_of(route) is None:
            missing.append(f"{sorted(methods)} {path}")
    return missing


def assert_all_routes_have_policy(app) -> None:
    from fastapi.routing import APIRoute
    registered = list(app.routes)
    if registered and not any(isinstance(r, APIRoute) for r, _, _ in iter_effective_routes(registered)):
        # Code RT F10: requirements.txt sets a floor, not an exact pin. A FastAPI release that changes route
        # enumeration would otherwise make this self-check vacuous (routes registered, 0 enumerated => 0 missing).
        raise RuntimeError("FD-4N: refusing to start, route enumeration found no API routes (FastAPI internals changed?)")
    missing = routes_missing_policy(app)
    if missing:
        raise RuntimeError(f"FD-4N: refusing to start, routes without an authorization policy: {missing}")


def enforce_declared_policy(request: Request) -> None:
    """App-level dependency: deny any route that does not declare exactly one policy (deny by default)."""
    route = request.scope.get("route")
    if route is None or policy_of(route) is None:
        _deny(403, "Forbidden: route has no authorization policy.")


def public_paths(app) -> FrozenSet[str]:
    return frozenset(p for r, p, _ in iter_effective_routes(app.routes) if policy_of(r) == PUBLIC)
