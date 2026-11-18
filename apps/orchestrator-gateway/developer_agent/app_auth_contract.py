"""
Platform-owned auth contract for generated FastAPI services (Wave 2 lane 19, L19-3c; FD-4I I1-I6; owner rows 27, 27b,
42, 46; plan §2.2).

Two files per Python FastAPI service, rendered deterministically (never written by the LLM; lane 8's provenance set
marks them platform-owned: validated, never repaired; ``APP.AUTH_MODULE_MODIFIED`` is a byte comparison with this
renderer's output):

* ``apps/<svc>/stackvend_auth.py``  deny-by-default auth: ``require_user`` / ``require_admin`` / ``add_member``.
  Mode-specific verifier (exact ``AccessMode``):
    - PUBLIC_APP:  Firebase ID token of THIS child project only (google-auth signature/exp/aud, plus exact ``iss``,
                   ``aud``, no ``firebase.tenant``, ``sign_in_provider`` in the Terraform-set allow-list, verified
                   email, per-role max auth age -> 401 ``REAUTH_REQUIRED``). No raw Google token / host client path.
    - PRIVATE_IAP: the ``X-Goog-IAP-JWT-Assertion`` header against IAP's keys and the exact service audience.
    - PRIVATE_IAM: a Google ID token for the exact service audience (Cloud Run IAM in front).
  Admins come only from Terraform-set env (``access.app_admin_emails``); members only from ``authorized_users/{email}``
  with ``status == "ACTIVE"``; roles are never read from a request. Any verification failure is a generic 401.
* ``tests/test_stackvend_auth_contract_<svc>.py``  black-box contract test (runs in the QA sandbox job, never in the
  gateway: importing LLM code there would be code execution): every non-public ``/api/*`` route must depend on
  ``stackvend_auth.require_user`` (identity, via FastAPI's dependant graph) and return 401 without valid credentials.
  Multi-service workloads (row L3-PRB-t, ``workload_test_layout.py``): ``apps/<svc>/tests/`` instead of root
  ``tests/`` (the QA job rejects a root ``tests/`` next to more than one service as PY.TEST_LAYOUT).

STATUS: standalone. Not yet wired into ``generate_code_files`` / prompts: that needs ``AccessPolicy`` on the developer
request (L19-2) and lane 8's provenance set; the prompt contract ("import require_user from stackvend_auth") must ship
in the same change as the wiring, or generated apps would import a module that is not rendered.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable

try:
    from .workload_test_layout import ROOT_TESTS_DIR, is_multi_service, service_tests_dir, services
except ImportError:
    try:
        from workload_test_layout import ROOT_TESTS_DIR, is_multi_service, service_tests_dir, services
    except ImportError:
        from developer_agent.workload_test_layout import ROOT_TESTS_DIR, is_multi_service, service_tests_dir, services

# ``access`` is a ``shared.access_policy.AccessPolicy``; not imported (replica rule: the gateway's committed shared/
# copy gains access_policy only through lane 12's vendoring). Only .mode and .public_api_routes are read.
AccessPolicy = Any

__all__ = ["AUTH_MODULE_NAME", "contract_test_path", "render_auth_module", "render_contract_test",
           "render_service_files"]

AUTH_MODULE_NAME = "stackvend_auth"
_MODES = ("PUBLIC_APP", "PRIVATE_IAP", "PRIVATE_IAM")

_HEADER = '''"""
StackVend platform-owned auth module (rendered by the platform; DO NOT EDIT: an edited copy fails the build as
APP.AUTH_MODULE_MODIFIED and is re-rendered). Access mode: {mode}.

Use it from routes:  `user: AppUser = Depends(require_user)` / `Depends(require_admin)`.
Never verify tokens yourself, never accept a role from a request, never add generic collection endpoints.
"""
import json
import os
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from fastapi import Depends, Header, HTTPException
from google.auth.transport import requests as _google_requests
from google.oauth2 import id_token as _id_token

RENDERED_MODE = "{mode}"
ACCESS_MODE = os.environ["STACKVEND_ACCESS_MODE"]
if ACCESS_MODE != RENDERED_MODE:
    raise RuntimeError("STACKVEND_ACCESS_MODE does not match the rendered auth module (" + RENDERED_MODE + ")")
PROJECT_ID = os.environ["PROJECT_ID"]
if not PROJECT_ID:
    raise RuntimeError("PROJECT_ID is empty")


def _json_str_list(name):
    value = json.loads(os.environ[name])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise RuntimeError(name + " must be a JSON list of strings")
    return value


ADMIN_EMAILS = frozenset(e.lower() for e in _json_str_list("STACKVEND_APP_ADMIN_EMAILS"))


class AppRole(str, Enum):
    ADMIN = "admin"
    MEMBER = "member"


@dataclass(frozen=True)
class AppUser:
    email: str
    role: AppRole


def _unauthorized(detail="Unauthorized"):
    return HTTPException(status_code=401, detail=detail, headers={{"WWW-Authenticate": "Bearer"}})


def _forbidden():
    return HTTPException(status_code=403, detail="Forbidden")
'''

_PUBLIC = '''

def _positive_int(name, default):
    raw = os.environ.get(name, str(default))
    value = int(raw)
    if value <= 0:
        raise RuntimeError(name + " must be a positive integer")
    return value


_ALLOWED_PROVIDERS = frozenset({"google.com", "password"})
SIGN_IN_PROVIDERS = frozenset(_json_str_list("STACKVEND_SIGN_IN_PROVIDERS"))
if not SIGN_IN_PROVIDERS or not SIGN_IN_PROVIDERS <= _ALLOWED_PROVIDERS:
    raise RuntimeError("STACKVEND_SIGN_IN_PROVIDERS must be a non-empty subset of google.com / password")
MAX_AUTH_AGE_ADMIN_S = _positive_int("STACKVEND_MAX_AUTH_AGE_ADMIN_S", 3600)
MAX_AUTH_AGE_MEMBER_S = _positive_int("STACKVEND_MAX_AUTH_AGE_MEMBER_S", 43200)
CLOCK_SKEW_S = 60
ISSUER = "https://securetoken.google.com/" + PROJECT_ID


def _verify(authorization, iap_assertion):
    """Firebase ID token minted by THIS project's Identity Platform; anything else raises."""
    scheme, _, token = (authorization or "").partition(" ")
    if scheme != "Bearer" or not token:
        raise ValueError("no bearer token")
    claims = _id_token.verify_firebase_token(token, _google_requests.Request(), audience=PROJECT_ID)
    if not isinstance(claims, dict) or claims.get("iss") != ISSUER or claims.get("aud") != PROJECT_ID:
        raise ValueError("issuer / audience")
    firebase = claims.get("firebase")
    if not isinstance(firebase, dict) or "tenant" in firebase:
        raise ValueError("tenant")
    if firebase.get("sign_in_provider") not in SIGN_IN_PROVIDERS:
        raise ValueError("provider")
    auth_time = claims.get("auth_time")
    if not isinstance(auth_time, int) or isinstance(auth_time, bool):
        raise ValueError("auth_time")
    return claims


def _check_auth_age(claims, role):
    max_age = MAX_AUTH_AGE_ADMIN_S if role is AppRole.ADMIN else MAX_AUTH_AGE_MEMBER_S
    age = int(time.time()) - claims["auth_time"]
    if age < -CLOCK_SKEW_S or age > max_age:
        raise _unauthorized("REAUTH_REQUIRED")
'''

_IAP = '''

IAP_AUDIENCE = os.environ["STACKVEND_IAP_AUDIENCE"]
if not IAP_AUDIENCE:
    raise RuntimeError("STACKVEND_IAP_AUDIENCE is empty")
IAP_ISSUER = "https://cloud.google.com/iap"
IAP_CERTS_URL = "https://www.gstatic.com/iap/verify/public_key"


def _verify(authorization, iap_assertion):
    """Signed IAP header for this exact service; IAP admits only Google-authenticated principals."""
    if not iap_assertion:
        raise ValueError("no IAP assertion")
    claims = _id_token.verify_token(iap_assertion, _google_requests.Request(), audience=IAP_AUDIENCE,
                                    certs_url=IAP_CERTS_URL)
    if not isinstance(claims, dict) or claims.get("iss") != IAP_ISSUER or claims.get("aud") != IAP_AUDIENCE:
        raise ValueError("issuer / audience")
    claims = dict(claims)
    claims["email_verified"] = True  # the IAP assertion has no such claim; IAP authenticated the Google identity
    return claims


def _check_auth_age(claims, role):
    return None  # bounded by the IAP assertion's own expiry
'''

_IAM = '''

SERVICE_AUDIENCE = os.environ["STACKVEND_SERVICE_AUDIENCE"]
if not SERVICE_AUDIENCE:
    raise RuntimeError("STACKVEND_SERVICE_AUDIENCE is empty")
GOOGLE_ISSUERS = frozenset({"https://accounts.google.com", "accounts.google.com"})


def _verify(authorization, iap_assertion):
    """Google ID token for this exact service URL (Cloud Run IAM in front)."""
    scheme, _, token = (authorization or "").partition(" ")
    if scheme != "Bearer" or not token:
        raise ValueError("no bearer token")
    claims = _id_token.verify_oauth2_token(token, _google_requests.Request(), audience=SERVICE_AUDIENCE)
    if not isinstance(claims, dict) or claims.get("iss") not in GOOGLE_ISSUERS or claims.get("aud") != SERVICE_AUDIENCE:
        raise ValueError("issuer / audience")
    return claims


def _check_auth_age(claims, role):
    return None  # bounded by the Google ID token's own expiry (1 h)
'''

_FOOTER = '''

_DB = None


def _db():
    global _DB
    if _DB is None:
        from google.cloud import firestore
        _DB = firestore.Client(project=PROJECT_ID)
    return _DB


def _member_is_active(email):
    doc = _db().collection("authorized_users").document(email).get()
    return bool(doc.exists) and (doc.to_dict() or {}).get("status") == "ACTIVE"


def _write_member(email, record):
    _db().collection("authorized_users").document(email).set(record)


def require_user(authorization: Optional[str] = Header(None),
                 x_goog_iap_jwt_assertion: Optional[str] = Header(None)) -> AppUser:
    try:
        claims = _verify(authorization, x_goog_iap_jwt_assertion)
    except HTTPException:
        raise
    except Exception:
        raise _unauthorized() from None
    if claims.get("email_verified") is not True or not isinstance(claims.get("email"), str):
        raise _unauthorized()
    email = claims["email"].lower()
    if email in ADMIN_EMAILS:
        role = AppRole.ADMIN
    else:
        try:
            active = _member_is_active(email)
        except Exception:
            raise HTTPException(status_code=503, detail="Membership store unavailable") from None
        if not active:
            raise _forbidden()
        role = AppRole.MEMBER
    _check_auth_age(claims, role)
    return AppUser(email=email, role=role)


def require_admin(user: AppUser = Depends(require_user)) -> AppUser:
    if user.role is not AppRole.ADMIN:
        raise _forbidden()
    return user


def add_member(email: str, actor: AppUser) -> None:
    """Admin-only. Always stores role "member"; promoting an admin is a GitOps change to access.app_admin_emails."""
    if not isinstance(actor, AppUser) or actor.role is not AppRole.ADMIN:
        raise _forbidden()
    if not isinstance(email, str):
        raise HTTPException(status_code=422, detail="email must be a string")
    address = email.strip().lower()
    local, sep, domain = address.partition("@")
    if not sep or not local or "@" in domain or "." not in domain:
        raise HTTPException(status_code=422, detail="invalid email")
    _write_member(address, {"role": AppRole.MEMBER.value, "status": "ACTIVE", "added_by": actor.email})
'''


def _mode(access: "AccessPolicy") -> str:
    mode = getattr(getattr(access, "mode", None), "value", getattr(access, "mode", None))
    if mode not in _MODES:
        raise ValueError(f"unsupported access mode {mode!r}")
    return mode


def render_auth_module(access: "AccessPolicy") -> str:
    """Deterministic source of ``apps/<svc>/stackvend_auth.py`` for the policy's mode (same input -> same bytes)."""
    mode = _mode(access)
    body = {"PUBLIC_APP": _PUBLIC, "PRIVATE_IAP": _IAP, "PRIVATE_IAM": _IAM}[mode]
    return _HEADER.format(mode=mode) + body + _FOOTER


def _multi_service(service: str, service_names: Iterable[str]) -> bool:
    """``service_names`` is the workload's typed service list (``ComputeIntent.service_names``); exact membership."""
    names = services(service_names)
    if service not in names:
        raise ValueError(f"service {service!r} is not one of the workload's services {list(names)}")
    return is_multi_service(names)


def contract_test_path(service: str, *, service_names: Iterable[str]) -> str:
    """Root ``tests/`` for a single-service workload (unchanged); ``apps/<svc>/tests/`` with more than one service."""
    tests_dir = service_tests_dir(service) if _multi_service(service, service_names) else ROOT_TESTS_DIR
    return f"{tests_dir}/test_stackvend_auth_contract_{service.replace('-', '_')}.py"


def render_contract_test(service: str, access: "AccessPolicy", *, service_names: Iterable[str]) -> str:
    """Deterministic black-box contract test for one service (runs in the QA sandbox job only)."""
    mode = _mode(access)
    # The service directory relative to the test file: `tests/` -> `../apps/<svc>`, `apps/<svc>/tests/` -> `..`.
    if _multi_service(service, service_names):
        service_dir = 'os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))'
    else:
        service_dir = f'os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "apps", {json.dumps(service)}))'
    public_routes = sorted(getattr(access, "public_api_routes", []) or [])
    return f'''"""
StackVend platform-owned auth contract test for service `{service}` (rendered; DO NOT EDIT). Access mode: {mode}.
Every /api/* route that is not an exact public "METHOD /path" pair must depend on stackvend_auth.require_user and must
answer 401 without valid credentials (APP.ROUTE_UNAUTHENTICATED otherwise).
"""
import importlib
import os
import sys

import pytest

SERVICE_DIR = {service_dir}
PUBLIC_API_ROUTES = frozenset({json.dumps(public_routes)})
BAD_CREDENTIALS = (None, "Bearer MOCK", "Basic x", "Bearer", "Bearer garbage.token.value")
TEST_ENV = {{
    "STACKVEND_ACCESS_MODE": {json.dumps(mode)},
    "PROJECT_ID": "contract-test-project",
    "STACKVEND_APP_ADMIN_EMAILS": "[]",
    "STACKVEND_SIGN_IN_PROVIDERS": '["google.com"]',
    "STACKVEND_IAP_AUDIENCE": "/projects/0/locations/x/services/contract-test",
    "STACKVEND_SERVICE_AUDIENCE": "https://contract-test.invalid",
}}


@pytest.fixture(scope="module")
def loaded():
    for key, value in TEST_ENV.items():
        os.environ.setdefault(key, value)
    sys.path.insert(0, SERVICE_DIR)
    auth = importlib.import_module("stackvend_auth")

    def _refuse(*args, **kwargs):
        raise ValueError("contract test: every credential is invalid")

    auth._verify = _refuse
    main = importlib.import_module("main")
    return auth, main.app


def _protected_routes(app):
    from fastapi.routing import APIRoute
    for route in app.routes:
        if isinstance(route, APIRoute) and route.path.startswith("/api/"):
            for method in sorted(route.methods):
                if method + " " + route.path not in PUBLIC_API_ROUTES:
                    yield method, route


def _depends_on(dependant, target):
    stack = [dependant]
    while stack:
        node = stack.pop()
        if node.call is target:
            return True
        stack.extend(node.dependencies)
    return False


def test_every_api_route_depends_on_require_user(loaded):
    auth, app = loaded
    missing = sorted(m + " " + r.path for m, r in _protected_routes(app) if not _depends_on(r.dependant, auth.require_user))
    assert not missing, "APP.ROUTE_UNAUTHENTICATED: " + ", ".join(missing)


def test_every_api_route_rejects_bad_credentials(loaded):
    from fastapi.testclient import TestClient
    auth, app = loaded
    client = TestClient(app)
    failures = []
    for method, route in _protected_routes(app):
        path = route.path_format.format(**{{name: "1" for name in route.param_convertors}})
        for credential in BAD_CREDENTIALS:
            headers = {{}} if credential is None else {{"Authorization": credential}}
            response = client.request(method, path, headers=headers)
            if response.status_code != 401:
                failures.append(method + " " + route.path + " [" + str(credential) + "] -> " + str(response.status_code))
    assert not failures, "APP.ROUTE_UNAUTHENTICATED: " + "; ".join(failures)
'''


def render_service_files(service: str, access: "AccessPolicy", *, service_names: Iterable[str]) -> Dict[str, str]:
    """The two platform-owned files for one FastAPI service (paths are repo-relative). ``service_names``: the
    workload's typed service list (``ComputeIntent.service_names``); it decides the test layout."""
    return {
        f"apps/{service}/{AUTH_MODULE_NAME}.py": render_auth_module(access),
        contract_test_path(service, service_names=service_names): render_contract_test(
            service, access, service_names=service_names),
    }
