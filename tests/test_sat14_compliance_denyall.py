"""SAT-14: the compliance harvest recognises `denyAll` for compute.vmExternalIpAccess.

The canonical Org Policy API v2 form of "deny every value" on a list constraint is `spec.rules: [{denyAll: true}]`, and
StackVend's own managed-folder policy is exactly that. Before SAT-14 the harvest read only `enforce` / `values`, so the
platform's own guardrail harvested as `disallow_vm_external_ip = False`. Now:
- v2: a policy whose rules are each exactly `denyAll: true` with no condition sets the flag (same semantics as vending's
  `_deny_all_in_effect`, which the compliance service copies; the copy is pinned identical below);
- CRM fallback: `listPolicy.allValues == "DENY"` sets the flag.
Do No Harm: every pre-existing input form (enforce, deniedValues, allowedValues, empty list, other constraints) gives
the same matrix as before. Hermetic: the HTTP session is a fake.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import importlib.util
import os
import sys
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

for m in [
    'httpx', 'fastapi', 'fastapi.responses', 'google', 'google.genai',
    'google.genai.types', 'google.cloud', 'google.cloud.firestore',
    'google.cloud.storage', 'google.cloud.logging', 'google.cloud.pubsub_v1',
    'github', 'jwt'
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

COMPLIANCE_PY = os.path.join(REPO_ROOT, "mcp-servers", "compliance", "service.py")
VENDING_PY = os.path.join(REPO_ROOT, "apps", "project-vending", "vending.py")

_spec = importlib.util.spec_from_file_location("sat14_compliance_service", COMPLIANCE_PY)
compliance_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(compliance_mod)
ComplianceService = compliance_mod.ComplianceService

VM = "folders/12345/policies/compute.vmExternalIpAccess"
CRM_VM = "constraints/compute.vmExternalIpAccess"

DEFAULT_MATRIX = {
    "disallow_vm_external_ip": False,
    "disallow_default_network": False,
    "require_os_login": False,
    "require_shielded_vm": False,
    "enforce_private_ingress": False,
    "enforce_uniform_bucket_level_access": False,
    "enforce_public_access_prevention": False,
    "domain_restricted_sharing": False,
    "allowed_domains": [],
    "allow_unauthenticated": True,
    "disable_sa_key_creation": False,
    "restrict_public_sql": False,
    "allowed_locations": [],
    "has_constraints": False,
}


class _Resp:
    def __init__(self, code, body=None):
        self.status_code = code
        self._body = body or {}

    def json(self):
        return self._body


class _Session:
    """v2 `GET .../policies` answers `policies`; CRM `POST ...:getEffectiveOrgPolicy` answers per constraint."""

    def __init__(self, policies=None, v2_code=200, crm=None):
        self.policies = policies
        self.v2_code = v2_code
        self.crm = crm or {}
        self.posts = []

    def get(self, url, timeout=None):
        return _Resp(self.v2_code, {"policies": self.policies} if self.policies is not None else {})

    def post(self, url, json=None, timeout=None):
        constraint = (json or {}).get("constraint")
        self.posts.append(constraint)
        if constraint in self.crm:
            return _Resp(200, self.crm[constraint])
        return _Resp(404, {})


def _harvest(session):
    svc = ComplianceService(project_id="mock-stackvend-project")
    svc._get_session = lambda: session
    return svc.harvest_folder_policies("folders/12345")


# ---- v2 denyAll ---------------------------------------------------------------------------------------------------

def test_v2_deny_all_sets_flag():
    """The platform's own folder policy shape (`deny_all = "TRUE"` in infra/platform/main.tf)."""
    session = _Session(policies=[{"name": VM, "spec": {"rules": [{"denyAll": True}]}}])
    m = _harvest(session)
    assert m["disallow_vm_external_ip"] is True
    assert m["has_constraints"] is True
    # v2 produced a record, so the CRM fallback is not consulted.
    assert session.posts == []
    # Nothing else changes.
    assert {k: v for k, v in m.items() if k not in ("disallow_vm_external_ip", "has_constraints")} == \
        {k: v for k, v in DEFAULT_MATRIX.items() if k not in ("disallow_vm_external_ip", "has_constraints")}


def test_v2_deny_all_with_other_policies():
    session = _Session(policies=[
        {"name": "folders/12345/policies/storage.uniformBucketLevelAccess", "spec": {"rules": [{"enforce": True}]}},
        {"name": VM, "spec": {"rules": [{"denyAll": True}]}},
    ])
    m = _harvest(session)
    assert m["disallow_vm_external_ip"] is True
    assert m["enforce_uniform_bucket_level_access"] is True


@pytest.mark.parametrize("rules", [
    [{"denyAll": True, "condition": {"expression": "resource.matchTag('env', 'prod')"}}],   # conditional (as vending)
    [{"denyAll": True}, {"allowAll": True, "condition": {"expression": "x"}}],              # not every rule denyAll
    [{"allowAll": True}],
    [{"denyAll": False}],
    [{"denyAll": "true"}],                                                                   # not the JSON boolean
    [],
])
def test_v2_deny_all_not_in_effect(rules):
    """Same semantics as vending's `_deny_all_in_effect`: only every-rule, unconditional `denyAll: true` counts. With
    no v2 record the CRM fallback runs (here: 404 everywhere), so the flag stays False."""
    m = _harvest(_Session(policies=[{"name": VM, "spec": {"rules": rules}}]))
    assert m["disallow_vm_external_ip"] is False
    assert m == DEFAULT_MATRIX


def test_v2_deny_all_on_other_constraint_unchanged():
    """Scope: only compute.vmExternalIpAccess reads denyAll. Other constraints keep their former behavior."""
    m = _harvest(_Session(policies=[
        {"name": "folders/12345/policies/run.allowedIngress", "spec": {"rules": [{"denyAll": True}]}},
        {"name": "folders/12345/policies/gcp.resourceLocations", "spec": {"rules": [{"denyAll": True}]}},
    ]))
    assert m == DEFAULT_MATRIX


# ---- CRM fallback allValues DENY -----------------------------------------------------------------------------------

def test_fallback_all_values_deny_sets_flag():
    session = _Session(policies=[], crm={CRM_VM: {"constraint": CRM_VM, "listPolicy": {"allValues": "DENY"}}})
    m = _harvest(session)
    assert CRM_VM in session.posts
    assert m["disallow_vm_external_ip"] is True
    assert m["has_constraints"] is True


@pytest.mark.parametrize("list_policy", [
    {"allValues": "ALLOW"},
    {"allValues": "ALL_VALUES_UNSPECIFIED"},
    {"allValues": "deny"},          # exact enum value only, no case folding
    {},
])
def test_fallback_all_values_not_deny(list_policy):
    m = _harvest(_Session(policies=[], crm={CRM_VM: {"constraint": CRM_VM, "listPolicy": list_policy}}))
    assert m == DEFAULT_MATRIX


def test_fallback_all_values_deny_on_other_constraint_unchanged():
    """Scope: `allValues: DENY` is read for vmExternalIpAccess only."""
    c = "constraints/run.allowedIngress"
    m = _harvest(_Session(policies=[], crm={c: {"constraint": c, "listPolicy": {"allValues": "DENY"}}}))
    assert m == DEFAULT_MATRIX


# ---- Do No Harm: the pre-existing forms -----------------------------------------------------------------------------

@pytest.mark.parametrize("rule", [
    {"enforce": True},
    {"values": {"deniedValues": ["all"]}},
    {"values": {"deniedValues": ["is:all"]}},
])
def test_v2_existing_enforced_forms_unchanged(rule):
    m = _harvest(_Session(policies=[{"name": VM, "spec": {"rules": [rule]}}]))
    assert m["disallow_vm_external_ip"] is True


@pytest.mark.parametrize("rule", [
    {"enforce": False},
    {"values": {"allowedValues": ["projects/p/zones/us-central1-a/instances/vm"]}},
    {"values": {"deniedValues": ["projects/p/zones/us-central1-a/instances/vm"]}},
])
def test_v2_existing_not_enforced_forms_unchanged(rule):
    m = _harvest(_Session(policies=[{"name": VM, "spec": {"rules": [rule]}}]))
    assert m["disallow_vm_external_ip"] is False


@pytest.mark.parametrize("list_policy,expected", [
    ({"deniedValues": ["all"]}, True),
    ({"deniedValues": ["is:all"]}, True),
    ({"allowedValues": ["projects/p/zones/z/instances/vm"]}, True),
    ({"allowedValues": ["all"]}, False),
])
def test_fallback_existing_forms_unchanged(list_policy, expected):
    m = _harvest(_Session(policies=[], crm={CRM_VM: {"constraint": CRM_VM, "listPolicy": list_policy}}))
    assert m["disallow_vm_external_ip"] is expected


def test_empty_policy_list_unchanged():
    assert _harvest(_Session(policies=[])) == DEFAULT_MATRIX


def test_v2_error_unchanged():
    assert _harvest(_Session(policies=None, v2_code=403)) == DEFAULT_MATRIX


def test_no_resource_unchanged():
    svc = ComplianceService(project_id="mock-stackvend-project")
    svc._get_session = MagicMock(side_effect=AssertionError("no API call for an empty resource"))
    assert svc.harvest_folder_policies("") == DEFAULT_MATRIX
    assert svc.harvest_folder_policies("0") == DEFAULT_MATRIX


# ---- the copy stays identical to vending's reader -------------------------------------------------------------------

def _function_body_dump(path, name):
    tree = ast.parse(open(path, encoding="utf-8").read())
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(getattr(body[0], "value", None), ast.Constant) \
                    and isinstance(body[0].value.value, str):
                body = body[1:]  # docstrings may differ
            return [ast.dump(stmt) for stmt in body], ast.dump(node.args)
    raise AssertionError(f"{name} not found in {path}")


def test_deny_all_reader_copy_matches_vending():
    """SAT-14 copies vending's `_deny_all_in_effect` (the services share no package). Both must keep the same logic."""
    assert _function_body_dump(COMPLIANCE_PY, "_deny_all_in_effect") == \
        _function_body_dump(VENDING_PY, "_deny_all_in_effect")


@pytest.mark.parametrize("policy,expected", [
    ({"spec": {"rules": [{"denyAll": True}]}}, True),
    ({"spec": {"rules": [{"denyAll": True}, {"denyAll": True}]}}, True),
    ({"spec": {"rules": [{"denyAll": True, "condition": {}}]}}, False),
    ({"spec": {"rules": []}}, False),
    ({"spec": {}}, False),
    ({}, False),
    (None, False),
    ({"spec": {"rules": ["denyAll"]}}, False),
    ({"spec": {"rules": {"denyAll": True}}}, False),
])
def test_deny_all_reader(policy, expected):
    assert compliance_mod._deny_all_in_effect(policy) is expected
