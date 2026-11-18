"""Lane 19 L19-1: shared/access_policy.py (FD-4I I7-I12; register rows 27, 42, 45, 46).

Exact enums and exact formats only: allUsers / allAuthenticatedUsers / org customer ids / unprefixed strings are
rejected, never prefixed or widened. Plan: docs/planning/wave2-lane19-generated-app-security-plan.md §2.1, §3, §10.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import ast
import os

import pytest
from pydantic import ValidationError

from shared.access_policy import (
    AccessMode,
    AccessPolicy,
    AccessPolicyIncompleteError,
    GoogleIdpMode,
    PlatformRole,
    Principal,
    SignInPolicy,
    parse_platform_role,
)

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DISABLED = {"google": "DISABLED"}
SHARED = {"google": "SHARED_PLATFORM_CLIENT"}


def _private(mode="PRIVATE_IAP", principals=("user:alice@example.com",), **kw):
    return AccessPolicy(mode=mode, invoker_principals=list(principals), sign_in=DISABLED, source="intake", **kw)


def _public(sign_in=None, tenant_isolation_required=False, **kw):
    return AccessPolicy(mode="PUBLIC_APP", sign_in=sign_in or SHARED,
                        tenant_isolation_required=tenant_isolation_required, source="intake", **kw)


# ------------------------------------------------------------------------------------------------ Principal
@pytest.mark.parametrize("raw,kind,value", [
    ("user:alice@example.com", "user", "alice@example.com"),
    ("group:eng@example.com", "group", "eng@example.com"),
    ("serviceAccount:sa-1@proj-1.iam.gserviceaccount.com", "serviceAccount", "sa-1@proj-1.iam.gserviceaccount.com"),
    ("domain:example.com", "domain", "example.com"),
])
def test_principal_accepts_the_four_kinds(raw, kind, value):
    p = Principal.parse(raw)
    assert p.kind.value == kind and p.value == value and str(p) == raw


@pytest.mark.parametrize("raw", [
    "allUsers", "allAuthenticatedUsers", "domain:allAuthenticatedUsers", "user:allUsers", "C0xyz789",
    "alice@example.com", "projectOwner:p", "projectEditor:proj", "principalSet://x", "User:alice@example.com",
    "user:", "domain:", "domain:*.example.com", "domain:localhost", "user: alice@example.com",
    "user:alice@@example.com", "user:alice", "serviceAccount:sa@", "", "domain:-bad.example.com",
])
def test_principal_rejects_public_unprefixed_and_unknown(raw):
    with pytest.raises((ValueError, ValidationError)):
        Principal.parse(raw)


def test_principal_lowercases_email_values_only():
    assert str(Principal.parse("user:Alice@Example.COM")) == "user:alice@example.com"
    with pytest.raises((ValueError, ValidationError)):
        Principal.parse("domain:Example.com")  # hostnames must already be exact lower-case


# ------------------------------------------------------------------------------------------------ AccessPolicy
def test_private_policy_round_trip_and_derived_flags():
    p = _private(principals=["user:alice@example.com", "group:ops@example.com"])
    assert p.invoker_members() == ["user:alice@example.com", "group:ops@example.com"]
    assert p.enable_direct_iap and not p.allow_unauthenticated and p.is_complete
    again = AccessPolicy.model_validate(p.model_dump(mode="json"))
    assert again == p
    iam = _private(mode="PRIVATE_IAM")
    assert not iam.enable_direct_iap and not iam.allow_unauthenticated


def test_private_without_principals_is_incomplete_not_widened():
    p = _private(principals=())
    assert not p.is_complete and p.invoker_members() == []
    with pytest.raises(AccessPolicyIncompleteError) as e:
        p.require_complete()
    assert e.value.error_class == "ACCESS_POLICY_INCOMPLETE"


@pytest.mark.parametrize("bad", ["allUsers", "allAuthenticatedUsers", "domain:allAuthenticatedUsers", "C0abc123"])
def test_policy_rejects_public_principals(bad):
    with pytest.raises(ValidationError):
        _private(principals=[bad])


def test_public_app_takes_no_principals():
    with pytest.raises(ValidationError):
        _public(invoker_principals=["user:alice@example.com"])


def test_public_app_needs_a_sign_in_method():
    with pytest.raises(ValidationError):
        _public(sign_in={"google": "DISABLED", "email_password": False})
    ok = _public(sign_in={"google": "DISABLED", "email_password": True})
    assert ok.allow_unauthenticated and not ok.enable_direct_iap


@pytest.mark.parametrize("mode", ["PRIVATE_IAM", "PRIVATE_IAP"])
@pytest.mark.parametrize("sign_in", [
    {"google": "SHARED_PLATFORM_CLIENT"}, {"google": "BYO"},
    {"google": "DISABLED", "email_password": True},                       # F-R3-5
    {"google": "DISABLED", "additional_authorized_domains": ["app.example.com"]},
])
def test_private_modes_refuse_any_sign_in_surface(mode, sign_in):
    with pytest.raises(ValidationError):
        AccessPolicy(mode=mode, invoker_principals=["user:a@example.com"], sign_in=sign_in, source="intake")


def test_a8_tenant_isolation_answer_required_for_public_app():
    with pytest.raises(ValidationError):
        AccessPolicy(mode="PUBLIC_APP", sign_in=SHARED, source="intake")  # None: no default (row 45)
    with pytest.raises(ValidationError):
        _public(sign_in=SHARED, tenant_isolation_required=True)
    assert _public(sign_in={"google": "BYO"}, tenant_isolation_required=True).sign_in.google is GoogleIdpMode.BYO
    assert _public(sign_in=SHARED, tenant_isolation_required=False).sign_in.google is GoogleIdpMode.SHARED_PLATFORM_CLIENT


def test_admin_emails_lowercased_and_validated():
    p = _private(app_admin_emails=["Boss@Example.com"])
    assert p.app_admin_emails == ["boss@example.com"]
    for bad in (["not-an-email"], ["a@b"], ["user:a@example.com"], ["a@example.com", "A@example.com"]):
        with pytest.raises(ValidationError):
            _private(app_admin_emails=bad)


def test_public_routes_exact_pairs():
    assert _private().public_api_routes == ["GET /api/config"]
    assert _private(public_api_routes=["GET /api/health", "POST /api/webhook"]).public_api_routes[1] == "POST /api/webhook"
    for bad in (["/api/config"], ["get /api/config"], ["GET api/config"], ["GET /api/a b"], ["FETCH /x"]):
        with pytest.raises(ValidationError):
            _private(public_api_routes=bad)


def test_unknown_fields_and_sources_rejected():
    with pytest.raises(ValidationError):
        AccessPolicy(mode="PRIVATE_IAP", invoker_principals=["user:a@example.com"], sign_in=DISABLED,
                     source="intake", allow_unauthenticated=True)
    with pytest.raises(ValidationError):
        AccessPolicy(mode="PRIVATE_IAP", invoker_principals=["user:a@example.com"], sign_in=DISABLED, source="llm")
    with pytest.raises(ValidationError):
        AccessPolicy(mode="private_iap", invoker_principals=["user:a@example.com"], sign_in=DISABLED, source="intake")
    with pytest.raises(ValidationError):
        _private(principals=["user:a@example.com", "user:a@example.com"])


def test_sign_in_domains_exact_hostnames():
    assert SignInPolicy(google="SHARED_PLATFORM_CLIENT", additional_authorized_domains=["app.example.com"])
    for bad in (["*.example.com"], ["localhost"], ["https://app.example.com"], ["App.example.com"]):
        with pytest.raises(ValidationError):
            SignInPolicy(google="SHARED_PLATFORM_CLIENT", additional_authorized_domains=bad)


# ------------------------------------------------------------------------------------------------ PlatformRole
@pytest.mark.parametrize("raw", ["NON_ADMIN", "ADMIN_PENDING", "SUBADMIN", "", None, "administrator", "ADMIN!", 1])
def test_parse_platform_role_not_admin(raw):
    assert parse_platform_role(raw) is not PlatformRole.ADMIN


@pytest.mark.parametrize("raw", ["ADMIN", " admin ", "Admin"])
def test_parse_platform_role_admin(raw):
    assert parse_platform_role(raw) is PlatformRole.ADMIN


def test_parse_platform_role_other_roles():
    assert parse_platform_role("viewer") is PlatformRole.VIEWER
    assert parse_platform_role("WORKLOAD_MANAGER") is PlatformRole.WORKLOAD_MANAGER


# ------------------------------------------------------------------------------------------------ hygiene
def test_module_uses_no_regex_or_substring_role_checks():
    src = open(os.path.join(REPO, "shared", "access_policy.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    imported = {a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
                for a in n.names} | {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert "re" not in imported and "regex" not in imported


def test_root_copy_plus_only_the_phase0_replicas():
    """Replica rule (WAVE2.md) as ruled by the FD-4I code RT (R2) and the L19-11 code RT (F10): the root module plus
    exactly the committed lane 12 Phase 0 replicas in the gateway and Control Center images
    (``vendor_shared.replica_pairs()`` discovers them, ``test_replica_identical_to_root`` polices them); each stays
    byte-identical to root. No other copy."""
    found = []
    for top in ("shared", "apps", "mcp-servers"):
        for root, dirs, names in os.walk(os.path.join(REPO, top)):
            dirs[:] = [d for d in dirs if d not in {"node_modules", "__pycache__", ".venv"}]
            found += [os.path.relpath(os.path.join(root, n), REPO) for n in names if n == "access_policy.py"]
    # FD-4DT: the terraform MCP image renders the deploy-time access variables (deploy_access_tfvars) too.
    replicas = [os.path.join("apps", "orchestrator-gateway", "shared", "access_policy.py"),
                os.path.join("apps", "control-center", "shared", "access_policy.py"),
                os.path.join("mcp-servers", "terraform", "shared", "access_policy.py")]
    assert sorted(found) == sorted([os.path.join("shared", "access_policy.py")] + replicas), found
    root_bytes = open(os.path.join(REPO, "shared", "access_policy.py"), "rb").read()
    for rel in replicas:
        assert open(os.path.join(REPO, rel), "rb").read() == root_bytes, f"replica differs from root: {rel}"




def test_enum_values_are_exact():
    assert {m.value for m in AccessMode} == {"PUBLIC_APP", "PRIVATE_IAM", "PRIVATE_IAP"}
    assert {m.value for m in GoogleIdpMode} == {"SHARED_PLATFORM_CLIENT", "BYO", "DISABLED"}
