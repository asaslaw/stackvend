"""settings-toggles ST-3: governance.strict_compliance_gates in the gateway pre-build gate.

Compliance gates always run. On (or unreadable: strict read, fail closed) -> a compliance profile advisory makes the
pre-build gate AWAIT_APPROVAL (COMPLIANCE_PROFILE_ADVISORY). Off, or no advisory (the setting is then not even read)
-> exactly today's decision and approval card. Hermetic: FakeDB, gateway loaded by path.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
GW_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
SPEC_DIR = os.path.join(REPO_ROOT, "apps", "spec-ingestion")
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.dirname(__file__))

from shared import settings as S  # noqa: E402


def _settings(**gov):
    return S.PlatformSettings(governance=gov)


def _raises(err):
    def read(*a, **k):
        raise err
    return read


def _never_read(*a, **k):
    raise AssertionError("the settings must not be read when there is nothing to decide")


@pytest.fixture(autouse=True)
def _fresh_settings_caches():
    def clear():
        for name in ("shared.settings", "shared_settings"):
            mod = sys.modules.get(name)
            if mod is not None and hasattr(mod, "invalidate_settings_cache"):
                mod.invalidate_settings_cache()
        S.invalidate_settings_cache()
    clear()
    yield
    clear()


ERRORS = [S.PlatformSettingsReadError("down"), S.PlatformSettingsInvalid("bad"), RuntimeError("anything else")]
ERROR_CODES = ["PLATFORM_SETTINGS_READ_FAILED", "PLATFORM_SETTINGS_INVALID", "PLATFORM_SETTINGS_UNAVAILABLE"]


# ------------------------------------------------------------------------------------------------ gateway helpers
from fd4f_support import FakeDB, gw  # noqa: E402,F401  (gw is a fixture)

TRACE, PID = "tr-toggles-1", "app"


def _gw_settings(monkeypatch, read):
    import shared.settings as gw_settings   # the module the gateway's lazy import resolves to
    gw_settings.invalidate_settings_cache()
    monkeypatch.setattr(gw_settings, "get_platform_settings", read)

# ================================================================================================ strict compliance
CB = "https://workflowexecutions.googleapis.com/v1/projects/p/locations/r/workflows/w/executions/e/callbacks/c1"
ADVISORY = {"profile": "HIPAA", "matched_terms": ["patient"],
            "advisory": "The spec mentions 'patient'. If this workload must meet HIPAA, set compliance_profile=HIPAA "
                        "explicitly. This note does not change the profile."}


def _compliance(**kw):
    base = {"requires_human_approval": False, "has_policy_conflicts": False, "allow_unauthenticated": True}
    base.update(kw)
    return base


def _finops():
    return {"requires_human_approval": False, "monthly_cost_delta_usd": 12.5, "risk_assessment": "LOW"}


def _gate(gw, db, compliance):
    from fastapi.testclient import TestClient
    gw.app.dependency_overrides[gw.get_governance_db] = lambda: db
    body = {"trace_id": TRACE, "product_id": PID, "callback_url": CB, "rework_cycle": 0, "compliance": compliance,
            "finops": _finops(), "finops_error": "", "policy_harvest_status": "SUCCESS", "operator_requested": False,
            "spec_doc_id": "", "task_dag": []}
    return TestClient(gw.app).post("/events/pre-build-gate", json=body)


@pytest.mark.parametrize("read", [lambda **k: _settings(strict_compliance_gates=True), _raises(ERRORS[0]),
                                  _raises(ERRORS[1])])
def test_strict_gates_advisory_waits_for_approval(gw, monkeypatch, read):
    _gw_settings(monkeypatch, read)
    db = FakeDB()
    r = _gate(gw, db, _compliance(profile_advisories=[ADVISORY]))
    assert r.status_code == 200 and r.json()["decision"] == "AWAIT_APPROVAL"
    assert r.json()["gate_reasons"] == ["COMPLIANCE_PROFILE_ADVISORY"]
    rec = db.docs[f"approval_requests/appr-plan-{TRACE}-0"]
    assert rec["gate_reasons"] == ["COMPLIANCE_PROFILE_ADVISORY"] and ADVISORY["advisory"] in rec["risk_assessment"]


def test_strict_gates_off_advisory_stays_advisory(gw, monkeypatch):
    _gw_settings(monkeypatch, lambda **k: _settings(strict_compliance_gates=False))
    r = _gate(gw, FakeDB(), _compliance(profile_advisories=[ADVISORY]))
    assert r.json()["decision"] == "PASS" and r.json()["gate_reasons"] == []


def test_strict_gates_autonomous_policy_advisory_does_not_hold_the_run(gw, monkeypatch):
    """RT F8: plan_approval_policy AUTONOMOUS_UNLESS_FAILED wins over the advisory wait; card unchanged."""
    _gw_settings(monkeypatch, lambda **k: _settings(strict_compliance_gates=True,
                                                    plan_approval_policy="AUTONOMOUS_UNLESS_FAILED"))
    db = FakeDB()
    r = _gate(gw, db, _compliance(profile_advisories=[ADVISORY]))
    assert r.json()["decision"] == "PASS" and r.json()["gate_reasons"] == []
    assert not [p for p in db.docs if p.startswith("approval_requests/")]


def test_strict_gates_conflict_policy_advisory_waits(gw, monkeypatch):
    _gw_settings(monkeypatch, lambda **k: _settings(strict_compliance_gates=True,
                                                    plan_approval_policy="ON_COMPLIANCE_CONFLICT"))
    r = _gate(gw, FakeDB(), _compliance(profile_advisories=[ADVISORY]))
    assert r.json()["decision"] == "AWAIT_APPROVAL" and r.json()["gate_reasons"] == ["COMPLIANCE_PROFILE_ADVISORY"]


@pytest.mark.parametrize("advisories", [None, [], "not-a-list"])
def test_strict_gates_negative_no_advisory_never_reads_settings(gw, monkeypatch, advisories):
    _gw_settings(monkeypatch, _never_read)
    comp = _compliance() if advisories is None else _compliance(profile_advisories=advisories)
    r = _gate(gw, FakeDB(), comp)
    assert r.status_code == 200 and r.json()["decision"] == "PASS"


def test_strict_gates_other_reasons_unchanged_and_card_text_unchanged(gw, monkeypatch):
    """An existing reason with strict gates on but no advisory: same reasons, same risk_assessment as before."""
    _gw_settings(monkeypatch, _never_read)
    db = FakeDB()
    r = _gate(gw, db, _compliance(has_policy_conflicts=True))
    assert r.json()["gate_reasons"] == ["COMPLIANCE_POLICY_CONFLICT"]
    assert db.docs[f"approval_requests/appr-plan-{TRACE}-0"]["risk_assessment"] == \
        "Pre-build gate: COMPLIANCE_POLICY_CONFLICT"


def test_pure_gate_default_is_todays_behavior():
    if GW_DIR not in sys.path:
        sys.path.insert(0, GW_DIR)
    import workflow_gates as g
    comp = _compliance(profile_advisories=[ADVISORY])
    snapshot = json.dumps(comp, sort_keys=True)
    assert g.evaluate_pre_build_gate(compliance=comp, finops=_finops()) == ("PASS", [])
    assert g.evaluate_pre_build_gate(compliance=comp, finops=_finops(), advisories_block=True) == \
        ("AWAIT_APPROVAL", ["COMPLIANCE_PROFILE_ADVISORY"])
    assert json.dumps(comp, sort_keys=True) == snapshot   # input unchanged



def test_settings_page_describes_the_strict_compliance_switch():
    html = open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8").read()
    assert "Compliance gates always run (this switch never turns them off)" in html
    assert "not when the plan-approval policy is Autonomous unless failed" in html
