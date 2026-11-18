"""Lane 10 L10-t2 / ORG-POLICY-FOLDER (owner 10-28): vending CHECKS the child's "no external VM IPs" guardrail.

The platform Terraform sets compute.vmExternalIpAccess = deny all once on the managed workloads folder; every child
inherits it. Vending never sets an org policy any more: it reads the child's EFFECTIVE policy (Org Policy API v2
getEffectivePolicy, read-only, needs only orgpolicy.policy.get) and records one typed result per constraint:
ENFORCED / NOT_ENFORCED (VENDING.ORG_POLICY_NOT_ENFORCED + fix) / UNVERIFIED (VENDING.ORG_POLICY_API_DISABLED + fix,
or VENDING.ORG_POLICY_CHECK_FAILED). Never an exception, never the host project. Hermetic: the HTTP session is a fake."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import json
import logging
import os
import sys
from unittest.mock import MagicMock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VENDING_DIR = os.path.join(REPO_ROOT, "apps", "project-vending")
if VENDING_DIR not in sys.path:
    sys.path.insert(0, VENDING_DIR)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

for m in [
    'httpx', 'fastapi', 'google', 'google.auth', 'googleapiclient',
    'googleapiclient.discovery', 'googleapiclient.errors', 'google.cloud',
    'google.cloud.firestore', 'google.cloud.storage', 'google.cloud.secretmanager',
    'github', 'jwt'
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

from vending import ProjectRepoVendingEngine  # noqa: E402

vending = sys.modules[ProjectRepoVendingEngine.__module__]  # the module whose globals the engine reads

API = "https://orgpolicy.googleapis.com/v2"
URL = f"{API}/projects/child-1/policies/compute.vmExternalIpAccess:getEffectivePolicy"
DENY_ALL = {"name": "projects/123/policies/compute.vmExternalIpAccess", "spec": {"rules": [{"denyAll": True}]}}

SERVICE_DISABLED_BODY = {"error": {
    "code": 403, "status": "PERMISSION_DENIED",
    "message": "Organization Policy API has not been used in project 123 before or it is disabled.",
    "details": [
        {"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "SERVICE_DISABLED", "domain": "googleapis.com",
         "metadata": {"service": "orgpolicy.googleapis.com", "consumer": "projects/123"}},
        {"@type": "type.googleapis.com/google.rpc.Help", "links": [{"description": "enable", "url": "https://x"}]},
    ]}}


class _Resp:
    def __init__(self, code, body=None, raw=None):
        self.status_code = code
        self._body = body
        self.text = raw if raw is not None else json.dumps(body)

    def json(self):
        if self._body is None:
            raise ValueError("not json")
        return self._body


class _Session:
    """Only GET exists: a write method (post/patch/put/delete) would raise AttributeError."""

    def __init__(self, *resps, boom=None):
        self.resps, self.calls, self.boom = list(resps), [], boom

    def get(self, url, timeout=None):
        self.calls.append(("GET", url))
        if self.boom:
            raise self.boom
        return self.resps.pop(0)


def _engine():
    return ProjectRepoVendingEngine(platform_project_id="host-platform", firestore_client=MagicMock(),
                                    secret_client=MagicMock(), crm_service=MagicMock(), billing_service=MagicMock(),
                                    storage_client=MagicMock())


def _reset_once(monkeypatch):
    monkeypatch.setattr(vending, "_org_policy_warned_codes", set())


def test_inherited_deny_all_is_enforced_with_one_read_only_get(monkeypatch):
    _reset_once(monkeypatch)
    s = _Session(_Resp(200, DENY_ALL))
    (r,) = _engine().check_child_org_policies("child-1", session=s)
    assert r == {"constraint": "compute.vmExternalIpAccess", "check": "effective_policy", "status": "ENFORCED",
                 "code": None, "http_status": 200, "error": None}
    assert s.calls == [("GET", URL)]


def test_no_policy_in_effect_is_a_typed_warning_with_the_fix(monkeypatch, caplog):
    _reset_once(monkeypatch)
    caplog.set_level(logging.DEBUG, logger=vending.logger.name)
    for body in ({"name": "projects/123/policies/compute.vmExternalIpAccess"},  # no spec: list default = allow
                 {"spec": {"rules": [{"allowAll": True}]}},
                 {"spec": {"rules": [{"values": {"allowedValues": ["projects/p/zones/z/instances/vm"]}}]}},
                 {"spec": {"rules": []}}):
        (r,) = _engine().check_child_org_policies("child-1", session=_Session(_Resp(200, body)))
        assert (r["status"], r["code"]) == ("NOT_ENFORCED", "VENDING.ORG_POLICY_NOT_ENFORCED"), body
        assert "PROJECT_ID=host-platform bash scripts/apply.sh apply" in r["fix"]
        assert "roles/orgpolicy.policyAdmin on the organization" in r["fix"]
        assert "outside the managed workloads folder" in r["fix"]
    mine = [rec for rec in caplog.records if "ORG_POLICY_NOT_ENFORCED" in rec.getMessage()]
    assert [rec.levelno for rec in mine] == [logging.WARNING, logging.DEBUG, logging.DEBUG, logging.DEBUG]
    assert not [rec for rec in caplog.records if rec.levelno >= logging.ERROR]


def test_negative_partial_or_conditional_deny_is_not_enforced(monkeypatch):
    """Only rules that are each exactly denyAll: true (no condition) prove the guardrail."""
    _reset_once(monkeypatch)
    for body in ({"spec": {"rules": [{"denyAll": True}, {"allowAll": True}]}},
                 {"spec": {"rules": [{"denyAll": True, "condition": {"expression": "resource.matchTag('a', 'b')"}}]}},
                 {"spec": {"rules": [{"denyAll": "true"}]}},
                 {"spec": {"rules": {"denyAll": True}}},
                 ["not", "a", "dict"]):
        (r,) = _engine().check_child_org_policies("child-1", session=_Session(_Resp(200, body)))
        assert r["status"] == "NOT_ENFORCED", body


def test_api_disabled_is_typed_with_the_corrected_fix(monkeypatch):
    _reset_once(monkeypatch)
    (r,) = _engine().check_child_org_policies("child-1", session=_Session(_Resp(403, SERVICE_DISABLED_BODY)))
    assert (r["status"], r["code"], r["http_status"]) == ("UNVERIFIED", "VENDING.ORG_POLICY_API_DISABLED", 403)
    assert r["consumer"] == "projects/123"
    assert "orgpolicy.googleapis.com" in r["fix"]
    assert "PROJECT_ID=host-platform bash scripts/apply.sh apply" in r["fix"]
    # The old fix named a folder grant of roles/orgpolicy.policyAdmin, which Google does not allow (org only).
    assert "policyAdmin" not in r["fix"]
    assert "needs no org-policy role" in r["fix"]


def test_api_disabled_warns_once_per_process_and_records_every_vend(monkeypatch, caplog):
    _reset_once(monkeypatch)
    caplog.set_level(logging.DEBUG, logger=vending.logger.name)
    results = [_engine().check_child_org_policies(f"child-{i}", session=_Session(_Resp(403, SERVICE_DISABLED_BODY)))
               for i in range(3)]
    assert [rs[0]["code"] for rs in results] == ["VENDING.ORG_POLICY_API_DISABLED"] * 3  # every vend records it
    mine = [rec for rec in caplog.records if "ORG_POLICY_API_DISABLED" in rec.getMessage()]
    assert [rec.levelno for rec in mine] == [logging.WARNING, logging.DEBUG, logging.DEBUG]
    assert not [rec for rec in caplog.records if rec.levelno >= logging.ERROR]


def test_each_code_warns_once_independently(monkeypatch, caplog):
    _reset_once(monkeypatch)
    caplog.set_level(logging.DEBUG, logger=vending.logger.name)
    _engine().check_child_org_policies("child-1", session=_Session(_Resp(403, SERVICE_DISABLED_BODY)))
    _engine().check_child_org_policies("child-2", session=_Session(_Resp(200, {})))
    warns = [rec.getMessage() for rec in caplog.records if rec.levelno == logging.WARNING]
    assert len(warns) == 2
    assert "ORG_POLICY_API_DISABLED" in warns[0] and "ORG_POLICY_NOT_ENFORCED" in warns[1]


def test_negative_other_errors_are_check_failed_at_error(monkeypatch, caplog):
    """A different ErrorInfo reason (e.g. IAM_PERMISSION_DENIED), another service's SERVICE_DISABLED, an error body
    without ErrorInfo, or a non-JSON body: VENDING.ORG_POLICY_CHECK_FAILED at ERROR, no fix, once-flags untouched."""
    _reset_once(monkeypatch)
    caplog.set_level(logging.DEBUG, logger=vending.logger.name)
    other_reason = json.loads(json.dumps(SERVICE_DISABLED_BODY))
    other_reason["error"]["details"][0]["reason"] = "IAM_PERMISSION_DENIED"
    other_service = json.loads(json.dumps(SERVICE_DISABLED_BODY))
    other_service["error"]["details"][0]["metadata"]["service"] = "compute.googleapis.com"
    resps = [_Resp(403, other_reason), _Resp(403, other_service), _Resp(403, {"error": {"code": 403}}),
             _Resp(500, None, raw="boom")]
    for resp in resps:
        (r,) = _engine().check_child_org_policies("child-1", session=_Session(resp))
        assert (r["status"], r["code"], "fix" in r) == ("UNVERIFIED", "VENDING.ORG_POLICY_CHECK_FAILED", False)
    assert sum(rec.levelno == logging.ERROR for rec in caplog.records) == 4
    assert vending._org_policy_warned_codes == set()


def test_unreadable_200_body_is_check_failed(monkeypatch):
    _reset_once(monkeypatch)
    (r,) = _engine().check_child_org_policies("child-1", session=_Session(_Resp(200, None, raw="<html>")))
    assert (r["status"], r["code"], r["http_status"]) == ("UNVERIFIED", "VENDING.ORG_POLICY_CHECK_FAILED", 200)


def test_transport_error_is_a_typed_failure_never_raised(monkeypatch):
    _reset_once(monkeypatch)
    (r,) = _engine().check_child_org_policies("child-1", session=_Session(boom=RuntimeError("no route")))
    assert (r["status"], r["code"], r["http_status"]) == ("UNVERIFIED", "VENDING.ORG_POLICY_CHECK_FAILED", None)
    assert "no route" in r["error"]


def test_the_platform_project_is_never_addressed(monkeypatch):
    _reset_once(monkeypatch)
    s = _Session(_Resp(200, DENY_ALL))
    for target in ("host-platform", ""):
        (r,) = _engine().check_child_org_policies(target, session=s)
        assert (r["status"], r["code"]) == ("UNVERIFIED", "VENDING.ORG_POLICY_CHECK_FAILED")
    assert s.calls == []


def test_folder_policy_applied_later_is_enforced_on_the_next_vend(monkeypatch):
    """The check runs on every vend, so applying the folder policy fixes the next vend without a restart."""
    _reset_once(monkeypatch)
    s = _Session(_Resp(200, {}), _Resp(200, DENY_ALL))
    assert _engine().check_child_org_policies("child-1", session=s)[0]["status"] == "NOT_ENFORCED"
    assert _engine().check_child_org_policies("child-1", session=s)[0]["status"] == "ENFORCED"


# ---- static: vending never writes an org policy any more (ORG-POLICY-FOLDER) ----
def _method_src(name):
    path = os.path.join(VENDING_DIR, "vending.py")
    src = open(path).read()
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(src, node)
    raise AssertionError(name)


def test_vending_only_reads_org_policy():
    body = _method_src("check_child_org_policies")
    tree = ast.parse("class _X:\n" + "\n".join("    " + line for line in body.splitlines()))
    called = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert "get" in called
    assert not called & {"post", "patch", "put", "delete"}
    src = open(os.path.join(VENDING_DIR, "vending.py")).read()
    assert "apply_child_org_policies" not in src
    # VENDING-CLIENT-FAIL-LOUD: the vend requires the Resource Manager client up front, so the call is unguarded
    assert "org_policy_results = self.check_child_org_policies(target_project_id)\n" in src
