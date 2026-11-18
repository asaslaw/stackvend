"""FD-4AK: platform settings fail closed.

1. Read side (`shared.settings.get_platform_settings`): a missing document is a fresh install (defaults); a failed read
   or an invalid document is a typed PlatformSettingsUnavailable -- raised to strict callers, degraded (last good,
   else defaults that are not cached) for lenient ones. Matrix per caller class.
2. Write side (Control Center): the whole document is validated before it is stored (422), the current document is
   read strictly (503 on a failed read, repair on an invalid one), and the store is exact (merge=False).
3. Gate callers: compliance plan approval -> approval required; CC intake -> 503; IPAM pool / region (other files).
4. Do No Harm: valid documents give exactly the settings they gave before, strict and lenient alike.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import copy
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
GW_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for _p in (REPO_ROOT,):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from shared import settings as S  # noqa: E402
from settings_write_fake import wire_settings_writes  # noqa: E402


# ------------------------------------------------------------------------------------------------ fake Firestore
class _Doc:
    def __init__(self, data, exists=True):
        self._data, self.exists = data, exists

    def to_dict(self):
        return copy.deepcopy(self._data)


class _Client:
    """system_config/platform_settings only; counts reads; `error` makes every read raise."""

    def __init__(self, data=None, exists=True, error=None):
        self.doc, self.error, self.reads = _Doc(data, exists), error, 0

    def collection(self, name):
        assert name == "system_config"
        return self

    def document(self, name):
        assert name == "platform_settings"
        return self

    def get(self):
        self.reads += 1
        if self.error is not None:
            raise self.error
        return self.doc


@pytest.fixture(autouse=True)
def _fresh_cache():
    S.invalidate_settings_cache()
    yield
    S.invalidate_settings_cache()


def _store(monkeypatch, data=None, exists=True, error=None) -> _Client:
    client = _Client(data, exists, error)
    monkeypatch.setattr("google.cloud.firestore.Client", lambda *a, **k: client)
    return client


# FD27-09 probe: governance set, one bad FinOps value.
GOV_ON = {"maintenance_mode": True, "require_plan_approval": True, "plan_approval_policy": "ALWAYS"}
BAD_DOC = {"governance": dict(GOV_ON), "finops": {"default_monthly_budget_usd": "forty"}}

# Valid documents (Do No Harm corpus): bootstrap's partial doc, a full dump, admin values, legacy values the read-side
# migrations still rewrite exactly as before, an unknown model id (owner-approved lenient read, Argon RT F1).
VALID_DOCS = [
    {},
    {"governance": {"vcs_provider": "SERVERLESS_GIT"}},
    S.PlatformSettings().model_dump(mode="json"),
    {"governance": dict(GOV_ON), "finops": {"default_monthly_budget_usd": 75.0, "default_breach_policy": "ALERT_ONLY"},
     "orchestration": {"default_gcp_region": "europe-west4", "ipam_supernet_cidr": "10.50.0.0/16"}, "version": 7},
    {"models": {"max_output_tokens": 4096, "fallback_models": ["gemini-2.5-flash", "gemini-3.7-flash"]}},
    {"models": {"finops_model": "gemini-9.9-ultra"}, "governance": {"require_plan_approval": True}},
    {"governance": {"plan_approval_policy": "AUTONOMOUS_UNLESS_FAILED"}, "audit_log": [
        {"timestamp": "2026-10-01T00:00:00+00:00", "admin_email": "a@example.com", "changed_fields": {}}]},
]


def _expected(doc):
    """What the loader produces for a VALID document: the fallback purge, then the lenient parse. FD-4CI-b (owner
    10-21, "no silent raise"): a stored max_output_tokens is no longer raised to 65536."""
    data = copy.deepcopy(doc)
    if isinstance(data.get("models"), dict):
        m = data["models"]
        if isinstance(m.get("fallback_models"), list):
            m["fallback_models"] = [x for x in m["fallback_models"] if "2.5" not in x and "3.8-pro" not in x] \
                or ["gemini-3.7-flash"]
    return S.platform_settings_from_stored(data).model_dump()


# ================================================================================================ 1. read side
@pytest.mark.parametrize("idx", range(len(VALID_DOCS)))
def test_do_no_harm_valid_documents_read_identically_strict_and_lenient(monkeypatch, idx):
    doc = VALID_DOCS[idx]
    client = _store(monkeypatch, doc)
    strict = S.get_platform_settings(project_id="p", strict=True)
    lenient = S.get_platform_settings(project_id="p")
    assert strict is lenient                          # one read, cached as before
    assert client.reads == 1
    assert strict.model_dump() == _expected(doc)


def test_valid_document_values_are_applied_not_reset(monkeypatch):
    _store(monkeypatch, VALID_DOCS[3])
    s = S.get_platform_settings(project_id="p", strict=True)
    assert (s.governance.maintenance_mode, s.governance.require_plan_approval, s.governance.plan_approval_policy) == \
        (True, True, "ALWAYS")
    assert s.orchestration.default_gcp_region == "europe-west4" and s.version == 7


def test_missing_document_is_a_fresh_install_defaults_for_every_caller(monkeypatch):
    client = _store(monkeypatch, None, exists=False)
    assert S.get_platform_settings(project_id="p", strict=True).model_dump() == S.PlatformSettings().model_dump()
    assert S.get_platform_settings(project_id="p").model_dump() == S.PlatformSettings().model_dump()
    assert client.reads == 1 and S._SETTINGS_CACHE is not None   # cached: the defaults ARE the settings


def test_read_failure_strict_raises_typed_lenient_degrades_without_caching_defaults(monkeypatch):
    client = _store(monkeypatch, error=RuntimeError("firestore down"))
    with pytest.raises(S.PlatformSettingsReadError) as ei:
        S.get_platform_settings(project_id="p", strict=True)
    assert ei.value.code == "PLATFORM_SETTINGS_READ_FAILED" and isinstance(ei.value, S.PlatformSettingsUnavailable)
    lenient = S.get_platform_settings(project_id="p")
    assert lenient.model_dump() == S.PlatformSettings().model_dump()
    assert S._SETTINGS_CACHE is None                  # defaults are never cached as if they had been read
    assert client.reads == 1                          # negative cache: one retry per TTL, not one per call
    with pytest.raises(S.PlatformSettingsReadError):
        S.get_platform_settings(project_id="p", strict=True)
    assert client.reads == 1


def test_rt_r2_failure_is_remembered_only_for_the_short_negative_ttl(monkeypatch):
    """RT R2: a blip is a few seconds of fail-closed, not the 60 s positive TTL."""
    assert S._NEGATIVE_CACHE_TTL_SECONDS == 5.0 < S._CACHE_TTL_SECONDS
    client = _store(monkeypatch, error=RuntimeError("blip"))
    with pytest.raises(S.PlatformSettingsReadError):
        S.get_platform_settings(project_id="p", strict=True)
    with pytest.raises(S.PlatformSettingsReadError):
        S.get_platform_settings(project_id="p", strict=True)
    assert client.reads == 1                          # within the negative TTL: no re-read
    client.error, client.doc = None, _Doc(VALID_DOCS[3])
    S._LAST_FAILURE_TIME -= 6.0                       # t + 6 s
    assert S.get_platform_settings(project_id="p", strict=True).version == 7
    assert client.reads == 2 and S._LAST_FAILURE is None


def test_rt_r2_force_refresh_bypasses_the_negative_cache(monkeypatch):
    client = _store(monkeypatch, error=RuntimeError("blip"))
    S.get_platform_settings(project_id="p")
    client.error, client.doc = None, _Doc(VALID_DOCS[3])
    assert S.get_platform_settings(force_refresh=True, project_id="p", strict=True).version == 7
    assert client.reads == 2


R3_BODIES = [
    ({"models": {"max_output_tokens": "forty"}}, ("max_output_tokens",)),
    ({"models": {"fallback_models": [3]}}, ("fallback_models", 0)),
    ({"audit_log": ["x"]}, ("audit_log", 0)),
]


@pytest.mark.parametrize("body, loc", R3_BODIES)
def test_rt_r3_pre_validation_bodies_are_validation_errors_with_a_field_path(body, loc):
    """RT R3: these bodies were a TypeError (FastAPI 500) raised by the pre-validation code; now pydantic refuses them
    (FastAPI 422) with the field path. TypeAdapter.validate_python is what FastAPI runs for the PUT body."""
    from pydantic import TypeAdapter, ValidationError
    with pytest.raises(ValidationError) as ei:
        TypeAdapter(S.PlatformSettings).validate_python(copy.deepcopy(body))
    assert any(tuple(e["loc"])[-len(loc):] == loc for e in ei.value.errors()), ei.value.errors()
    with pytest.raises(S.PlatformSettingsInvalid) as ei2:
        S.validate_settings_document(copy.deepcopy(body))
    assert all(e["loc"] for e in ei2.value.errors) and ei2.value.errors


@pytest.mark.parametrize("body, loc", R3_BODIES)
def test_rt_r3_stored_document_with_those_values_is_invalid_with_a_field_path(monkeypatch, body, loc):
    _store(monkeypatch, body)
    with pytest.raises(S.PlatformSettingsInvalid) as ei:
        S.get_platform_settings(project_id="p", strict=True)
    assert all(e["loc"] for e in ei.value.errors)


def test_rt_r3_negative_numeric_migration_unchanged():
    """FD-4CI-b (owner 10-21, "no silent raise"): a stored max_output_tokens is used as it is (int and a Firestore
    double); str fallback ids are still purged."""
    for tokens in (4096, 4096.0):
        assert S.PlatformSettings(models={"max_output_tokens": tokens}).models.max_output_tokens == 4096
    assert S.PlatformSettings(models={"fallback_models": ["gemini-2.5-flash"]}).models.fallback_models == \
        ["gemini-4-argon", "gemini-3.8-flash", "gemini-3.7-flash"]   # nothing left: the default fallback (DEFAULT-FALLBACK-CHAIN)


def test_client_construction_failure_is_a_read_failure(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("no credentials")
    monkeypatch.setattr("google.cloud.firestore.Client", boom)
    with pytest.raises(S.PlatformSettingsReadError):
        S.get_platform_settings(project_id="p", strict=True)


def test_read_failure_after_a_good_read_lenient_keeps_last_good_strict_raises(monkeypatch):
    client = _store(monkeypatch, VALID_DOCS[3])
    good = S.get_platform_settings(project_id="p")
    client.error = RuntimeError("firestore down")
    S._LAST_FETCH_TIME = 0.0                          # the TTL expired
    assert S.get_platform_settings(project_id="p") is good
    with pytest.raises(S.PlatformSettingsReadError):
        S.get_platform_settings(project_id="p", strict=True)
    client.error = None                               # recovered: force_refresh re-reads and clears the failure
    assert S.get_platform_settings(force_refresh=True, project_id="p", strict=True).version == 7
    assert S._LAST_FAILURE is None


def test_fd27_09_one_bad_field_no_longer_resets_governance(monkeypatch):
    _store(monkeypatch, BAD_DOC)
    with pytest.raises(S.PlatformSettingsInvalid) as ei:
        S.get_platform_settings(project_id="p", strict=True)
    err = ei.value
    assert err.code == "PLATFORM_SETTINGS_INVALID"
    assert any(e["loc"][-1:] == ["default_monthly_budget_usd"] for e in err.errors)
    assert "forty" not in repr(err.errors)            # errors never carry stored values
    assert err.document["governance"] == GOV_ON       # kept for the admin repair path
    # lenient (display) callers degrade to defaults, as before
    assert S.get_platform_settings(project_id="p").governance.require_plan_approval is False


@pytest.mark.parametrize("doc", [
    {"governance": "x"}, {"governance": None}, {"finops": ["a"]}, {"orchestration": 3}, {"models": "flash"},
    {"runtimes": "x"}, {"audit_log": "x"}, {"audit_log": [{"timestamp": "t"}]},
    {"governance": {"plan_approval_policy": "NEVER"}}, {"governance": {"require_plan_approval": "maybe"}},
    {"models": {"max_output_tokens": "forty"}}, {"orchestration": {"ipam_connector_prefix": 16}},
])
def test_invalid_documents_are_typed_errors_never_silent_defaults(monkeypatch, doc):
    _store(monkeypatch, doc)
    with pytest.raises(S.PlatformSettingsInvalid):
        S.get_platform_settings(project_id="p", strict=True)


def test_non_mapping_document_is_invalid(monkeypatch):
    _store(monkeypatch, ["not", "a", "mapping"])
    with pytest.raises(S.PlatformSettingsInvalid):
        S.get_platform_settings(project_id="p", strict=True)


def test_plan_approval_policy_spelling_normalized_like_the_gate_did(monkeypatch):
    _store(monkeypatch, {"governance": {"plan_approval_policy": " always "}})
    assert S.get_platform_settings(project_id="p", strict=True).governance.plan_approval_policy == "ALWAYS"
    for policy in S.PLAN_APPROVAL_POLICIES:           # negative: every valid spelling is unchanged
        assert S.GovernanceSettings(plan_approval_policy=policy).plan_approval_policy == policy


def test_invalidate_clears_a_remembered_failure(monkeypatch):
    client = _store(monkeypatch, error=RuntimeError("down"))
    S.get_platform_settings(project_id="p")
    S.invalidate_settings_cache()
    client.error = None
    client.doc = _Doc(VALID_DOCS[3])
    assert S.get_platform_settings(project_id="p", strict=True).version == 7


def test_eval_harness_pinned_cache_serves_strict_callers(monkeypatch):
    """eval/stackvend_eval/stages.py pins `_SETTINGS_CACHE` with `_LAST_FETCH_TIME = inf`: no read, strict included."""
    client = _store(monkeypatch, error=RuntimeError("must not be read"))
    pinned = S.PlatformSettings()
    S._SETTINGS_CACHE, S._LAST_FETCH_TIME = pinned, float("inf")
    assert S.get_platform_settings(strict=True) is pinned and client.reads == 0


def test_display_caller_model_cascade_degrades_on_failure(monkeypatch):
    _store(monkeypatch, error=RuntimeError("down"))
    assert S.get_model_cascade_for_agent("architect")[0] == S.AgentModelSettings().architect_model


# ================================================================================================ 2. write side
def test_validate_settings_document_matrix():
    S.validate_settings_document(S.PlatformSettings().model_dump())          # negative: a valid doc passes
    S.validate_settings_document({})
    for bad in (BAD_DOC, {"governance": "x"}, {"governance": {"plan_approval_policy": "NEVER"}},
                {"models": {"architect_model": "gemini-9.9-ultra"}}, "not-a-mapping"):
        with pytest.raises(S.PlatformSettingsInvalid):
            S.validate_settings_document(bad)        # strict at save: no unknown-model leniency either


@pytest.fixture
def cc(monkeypatch):
    """The Control Center routes with a recording settings store (CC's own `db`)."""
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    monkeypatch.setattr(cc_db, "_db_client", False)
    from routes import settings as rs
    from routes import agent_evals as ae
    cc_store = MagicMock()
    doc_ref = MagicMock()
    cc_store.collection.return_value.document.return_value = doc_ref
    monkeypatch.setattr(rs, "db", cc_store)
    monkeypatch.setattr(ae, "db", cc_store)
    writes = wire_settings_writes(cc_store, doc_ref)   # FD-4CI-b-R3 (tests/settings_write_fake.py)
    request = MagicMock()
    request.state.user_role = rs.UserRole.ADMIN
    request.state.user_email = "admin@example.com"
    return SimpleNamespace(rs=rs, ae=ae, doc_ref=doc_ref, request=request, writes=writes)


def _http_status(exc):
    return getattr(exc, "status_code", None)


def test_put_valid_payload_stores_exactly_the_validated_document(cc, monkeypatch):
    _store(monkeypatch, VALID_DOCS[3])
    payload = S.PlatformSettings(**copy.deepcopy(VALID_DOCS[3]))
    payload.finops.default_monthly_budget_usd = 90.0
    out = cc.rs.update_settings_api(payload, cc.request)
    (stored,), kwargs = cc.doc_ref.set.call_args
    assert kwargs == {"merge": False}
    assert S.validate_settings_document(stored).finops.default_monthly_budget_usd == 90.0
    assert out.version == 8 and out.audit_log[0].changed_fields["finops.default_monthly_budget_usd"]["to"] == 90.0
    assert stored["governance"]["require_plan_approval"] is True


def test_put_invalid_field_is_refused_422_and_nothing_is_stored(cc, monkeypatch):
    _store(monkeypatch, VALID_DOCS[3])
    payload = S.PlatformSettings()
    payload.governance.plan_approval_policy = "NEVER"   # assignment is not validated: what a bypassed body would be
    with pytest.raises(Exception) as ei:
        cc.rs.update_settings_api(payload, cc.request)
    assert _http_status(ei.value) == 422 and ei.value.detail["code"] == "PLATFORM_SETTINGS_INVALID"
    cc.doc_ref.set.assert_not_called()


def test_put_body_model_refuses_invalid_fields():
    """FastAPI validates the PUT body with PlatformSettings.model_validate: the 422 before the route runs."""
    from pydantic import ValidationError
    for body in (BAD_DOC, {"governance": {"plan_approval_policy": "NEVER"}}, {"governance": "x"}):
        with pytest.raises(ValidationError):
            S.PlatformSettings.model_validate(body)
    assert S.PlatformSettings.model_validate(VALID_DOCS[3]).version == 7   # negative


def test_put_when_current_read_fails_is_503_and_nothing_is_stored(cc, monkeypatch):
    _store(monkeypatch, error=RuntimeError("firestore down"))
    with pytest.raises(Exception) as ei:
        cc.rs.update_settings_api(S.PlatformSettings(), cc.request)
    assert _http_status(ei.value) == 503 and ei.value.detail["code"] == "PLATFORM_SETTINGS_READ_FAILED"
    cc.doc_ref.set.assert_not_called()


def test_put_over_an_invalid_document_repairs_it_and_keeps_its_history(cc, monkeypatch):
    bad = copy.deepcopy(BAD_DOC)
    bad["version"] = 4
    bad["audit_log"] = [{"timestamp": "2026-10-01T00:00:00+00:00", "admin_email": "old@example.com"}, {"junk": 1}]
    _store(monkeypatch, bad)
    out = cc.rs.update_settings_api(S.PlatformSettings(governance=dict(GOV_ON)), cc.request)
    (stored,), kwargs = cc.doc_ref.set.call_args
    assert kwargs == {"merge": False} and S.validate_settings_document(stored)
    assert out.version == 5 and [e.admin_email for e in out.audit_log] == ["admin@example.com", "old@example.com"]
    assert "repaired_invalid_document" in out.audit_log[0].changed_fields


def test_reset_defaults_read_failure_503_invalid_repaired(cc, monkeypatch):
    client = _store(monkeypatch, error=RuntimeError("down"))
    with pytest.raises(Exception) as ei:
        cc.rs.reset_settings_defaults_api(cc.request)
    assert _http_status(ei.value) == 503
    cc.doc_ref.set.assert_not_called()
    client.error, client.doc = None, _Doc(dict(BAD_DOC, version=2))
    out = cc.rs.reset_settings_defaults_api(cc.request)
    assert out.version == 3 and out.finops.default_monthly_budget_usd == 40.0
    assert cc.doc_ref.set.call_args.kwargs == {"merge": False}


def test_get_settings_typed_503_never_defaults_for_the_editor(cc, monkeypatch):
    _store(monkeypatch, BAD_DOC)
    with pytest.raises(Exception) as ei:
        cc.rs.get_settings_api(force=True, request=cc.request)
    assert _http_status(ei.value) == 503 and ei.value.detail["code"] == "PLATFORM_SETTINGS_INVALID"
    assert "forty" not in repr(ei.value.detail)
    S.invalidate_settings_cache()
    _store(monkeypatch, error=RuntimeError("down"))
    with pytest.raises(Exception) as ei:
        cc.rs.get_settings_api(force=True, request=cc.request)
    assert ei.value.detail["code"] == "PLATFORM_SETTINGS_READ_FAILED"
    S.invalidate_settings_cache()
    _store(monkeypatch, VALID_DOCS[3])                # negative: a valid doc is returned as stored
    assert cc.rs.get_settings_api(force=True, request=cc.request).version == 7


def test_directive_write_validates_the_whole_document(cc):
    good = MagicMock(exists=True)
    good.to_dict.return_value = {"models": {"custom_directives": {}}}
    cc.doc_ref.get.side_effect = None   # the directive endpoints read the raw document themselves
    cc.doc_ref.get.return_value = good
    req = cc.ae.ApplyDirectiveRequest(directive="Prefer Cloud Run")
    cc.ae.apply_prompt_directive("ARCHITECT_AGENT", req, None)
    cc.doc_ref.set.assert_called_once()               # negative: a valid document is written as before
    cc.doc_ref.set.reset_mock()
    bad = MagicMock(exists=True)
    bad.to_dict.return_value = copy.deepcopy(BAD_DOC)
    cc.doc_ref.get.return_value = bad
    for call in (lambda: cc.ae.apply_prompt_directive("ARCHITECT_AGENT", req, None),):
        with pytest.raises(Exception) as ei:
            call()
        assert _http_status(ei.value) == 422 and ei.value.detail["code"] == "PLATFORM_SETTINGS_INVALID"
    bad.to_dict.return_value = dict(copy.deepcopy(BAD_DOC), models={"custom_directives": {"ARCHITECT_AGENT": ["x"]}})
    with pytest.raises(Exception) as ei:
        cc.ae.remove_prompt_directive("ARCHITECT_AGENT", "x", None)
    assert _http_status(ei.value) == 422
    cc.doc_ref.set.assert_not_called()


# ================================================================================================ 3. gate callers
@pytest.fixture
def compliance_gate(monkeypatch):
    if GW_DIR not in sys.path:
        monkeypatch.syspath_prepend(GW_DIR)
    from compliance_agent.handler import ComplianceAgentHandler
    agent = SimpleNamespace(project_id="p")
    return lambda conflicts: ComplianceAgentHandler._determine_approval_requirement(agent, conflicts)


@pytest.mark.parametrize("err", [S.PlatformSettingsReadError("down"), S.PlatformSettingsInvalid("bad"),
                                 RuntimeError("anything else")])
@pytest.mark.parametrize("conflicts", [False, True])
def test_compliance_gate_requires_approval_when_settings_unavailable(compliance_gate, err, conflicts):
    with patch("shared.settings.get_platform_settings", side_effect=err):
        assert compliance_gate(conflicts) is True


def test_compliance_gate_unreadable_store_requires_approval_end_to_end(compliance_gate, monkeypatch):
    _store(monkeypatch, BAD_DOC)
    assert compliance_gate(False) is True             # formerly: defaults -> ON_COMPLIANCE_CONFLICT -> False


@pytest.mark.parametrize("gov, conflicts, expected", [
    ({}, False, False), ({}, True, True),
    ({"plan_approval_policy": "ALWAYS"}, False, True),
    ({"plan_approval_policy": "AUTONOMOUS_UNLESS_FAILED"}, False, False),
    ({"plan_approval_policy": "AUTONOMOUS_UNLESS_FAILED"}, True, True),
    ({"require_plan_approval": True}, False, True),
])
def test_compliance_gate_do_no_harm_with_valid_settings(compliance_gate, monkeypatch, gov, conflicts, expected):
    _store(monkeypatch, {"governance": gov})
    assert compliance_gate(conflicts) is expected


@pytest.mark.parametrize("err", [S.PlatformSettingsReadError("down"), S.PlatformSettingsInvalid("bad")])
def test_cc_intake_refuses_503_when_settings_unavailable(monkeypatch, err):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from fastapi import HTTPException
    from routes import workloads as wl_routes
    from schemas import CreateWorkloadRequest
    monkeypatch.setattr(cc_db, "_db_client", False)
    mock_db = MagicMock()
    doc = MagicMock()
    mock_db.collection().document.return_value = doc
    monkeypatch.setattr(wl_routes, "db", mock_db)
    publisher = MagicMock()
    request = MagicMock()
    request.state.user_email, request.state.user_role = "admin@example.com", "ADMIN"
    with patch.dict(os.environ, {"GITHUB_OWNER": "example-org", "MANAGED_WORKLOADS_FOLDER_ID": "111111111111"}), \
         patch("routes.workloads.get_pubsub_publisher", return_value=publisher), \
         patch("routes.workloads.get_platform_settings", side_effect=err):
        with pytest.raises(HTTPException) as ei:
            wl_routes.create_workload(CreateWorkloadRequest(product_id="shop-app", spec_content="a shop"), request)
    assert ei.value.status_code == 503 and ei.value.detail["code"] == err.code
    doc.set.assert_not_called()
    publisher.publish.assert_not_called()


# ================================================================================================ RT R1: UI recovery
def test_rt_r1_settings_page_has_a_recovery_card_outside_the_settings_form():
    """After a typed 503 `platformSettings` stays null and the form (with its own Refresh / Reset) is not rendered;
    the recovery card must offer Retry and Reset to defaults without needing the settings object."""
    html = open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8").read()
    start = html.index('<template x-if="!isSettingsLoading && !platformSettings && settingsLoadError">')
    end = html.index('<template x-if="platformSettings">', start)
    card = html[start:end]
    assert '@click="fetchPlatformSettings(true)"' in card and '@click="resetPlatformSettings()"' in card
    assert "settingsLoadError.code" in card and "settingsLoadError.message" in card
    assert "settingsLoadError: null" in html
    reset_fn = html[html.index("async resetPlatformSettings()"):]
    reset_fn = reset_fn[:reset_fn.index("async ", 10)]
    assert "d.message" in reset_fn and "this.settingsLoadError = null" in reset_fn
