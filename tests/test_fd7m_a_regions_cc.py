"""FD-7M-a (SAT-21, owner 10-31, OQ-21..OQ-25): approved deployable regions, Control Center side.

* Settings PUT: grammar / default-in-list (422), an added region checked against Cloud Run's locations (OQ-22:
  REGION_UNKNOWN 422, lookup failure 503 REGION_LOOKUP_UNAVAILABLE), a removed region still recorded on a live workload
  refused (OQ-23: REGION_IN_USE 422). Nothing stored on any refusal. No change to the regions: no lookup, no query.
* Create (Agent and Express): a region outside the list -> 422 REGION_NOT_APPROVED before any write / vend / publish;
  a regulated baseline that does not allow the region -> 422 REGION_PROFILE_CONFLICT (OQ-25); the region is recorded on
  the first record write; an existing workload keeps its region (409 REGION_CHANGE_REFUSED), a legacy record is not
  stamped (OQ-24).
* Express deploys into the record's region (F-D: never the host $REGION or a literal).
* Do No Harm: the default list changes nothing but the new `region` field; the Express HCL for the default region is
  byte-identical through the real synthesizer.
Hermetic: in-memory fakes only (no Firestore, no network, no ADC).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import copy
import importlib.util
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

TESTS = os.path.dirname(__file__)
REPO_ROOT = os.path.abspath(os.path.join(TESTS, ".."))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
for p in (TESTS, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from shared import settings as S  # noqa: E402
from test_fd4ak_settings_fail_closed import _store, cc as settings_cc  # noqa: F401,E402  (fixture)
from test_l19_11_access_intake import ADMIN_H, FakeDB, _client, cc  # noqa: F401,E402  (fixture)
from test_exp7_express_destroy_approval import _route  # noqa: E402

EAST = "us-east4"
TWO = {"orchestration": {"approved_deployable_regions": ["us-central1", EAST]}}


@pytest.fixture(autouse=True)
def _fresh_cache():
    S.invalidate_settings_cache()
    yield
    S.invalidate_settings_cache()


# ============================================================================================ Settings PUT
def _put(settings_cc, monkeypatch, stored, payload, *, locations=None, lookup_error=None, in_use=None,
         query_error=None):
    """PUT `payload` over `stored`; returns (result or exception, lookups made, regions queried)."""
    _store(monkeypatch, stored)
    lookups, queried = [], []

    def _locations():
        lookups.append(1)
        if lookup_error is not None:
            raise settings_cc.rs.RegionLookupUnavailable(lookup_error)
        return set(locations or ())

    def _in_use(regions):
        queried.append(list(regions))
        if query_error is not None:
            raise query_error
        return {r: v for r, v in (in_use or {}).items() if r in regions}

    monkeypatch.setattr(settings_cc.rs, "cloud_run_locations", _locations)
    monkeypatch.setattr(settings_cc.rs, "_workloads_in_regions", _in_use)
    try:
        out = settings_cc.rs.update_settings_api(S.PlatformSettings(**copy.deepcopy(payload)), settings_cc.request)
    except Exception as e:  # noqa: BLE001 - the HTTP refusal is the result under test
        out = e
    return out, lookups, queried


def _stored(settings_cc):
    return settings_cc.doc_ref.set.call_args[0][0] if settings_cc.doc_ref.set.call_args else None


def test_put_adding_a_cloud_run_region_is_stored_and_audited(settings_cc, monkeypatch):
    out, lookups, queried = _put(settings_cc, monkeypatch, {"version": 3}, {**TWO, "version": 3},
                                 locations={"us-central1", EAST, "europe-west1"})
    assert not isinstance(out, Exception), out
    assert lookups == [1] and queried == []
    assert _stored(settings_cc)["orchestration"]["approved_deployable_regions"] == ["us-central1", EAST]
    changed = out.audit_log[0].changed_fields["orchestration.approved_deployable_regions"]
    assert changed == {"from": [], "to": ["us-central1", EAST]}


def test_put_unknown_region_is_422_and_nothing_stored(settings_cc, monkeypatch):
    out, _, _ = _put(settings_cc, monkeypatch, {"version": 3}, {**TWO, "version": 3}, locations={"us-central1"})
    assert out.status_code == 422 and out.detail["code"] == "REGION_UNKNOWN" and out.detail["regions"] == [EAST]
    assert _stored(settings_cc) is None


def test_put_lookup_failure_is_503_and_nothing_stored(settings_cc, monkeypatch):
    out, _, _ = _put(settings_cc, monkeypatch, {"version": 3}, {**TWO, "version": 3}, lookup_error="HTTP 403")
    assert out.status_code == 503 and out.detail["code"] == "REGION_LOOKUP_UNAVAILABLE"
    assert _stored(settings_cc) is None


def test_put_removing_a_region_in_use_is_422_region_in_use(settings_cc, monkeypatch):
    stored = {**copy.deepcopy(TWO), "version": 3}
    out, lookups, queried = _put(settings_cc, monkeypatch, stored, {"version": 3}, in_use={EAST: ["shop-app"]})
    assert out.status_code == 422 and out.detail["code"] == "REGION_IN_USE"
    assert out.detail["workloads"] == {EAST: ["shop-app"]} and queried == [[EAST]] and lookups == []
    assert _stored(settings_cc) is None


def test_put_removing_an_unused_region_is_stored(settings_cc, monkeypatch):
    stored = {**copy.deepcopy(TWO), "version": 3}
    out, lookups, queried = _put(settings_cc, monkeypatch, stored, {"version": 3}, in_use={})
    assert not isinstance(out, Exception), out
    assert queried == [[EAST]] and lookups == []
    assert _stored(settings_cc)["orchestration"]["approved_deployable_regions"] == []


def test_put_in_use_query_failure_is_503_and_nothing_stored(settings_cc, monkeypatch):
    stored = {**copy.deepcopy(TWO), "version": 3}
    out, _, _ = _put(settings_cc, monkeypatch, stored, {"version": 3}, query_error=RuntimeError("down"))
    assert out.status_code == 503 and out.detail["code"] == "REGION_LOOKUP_UNAVAILABLE"
    assert _stored(settings_cc) is None


def test_put_changing_the_default_with_an_empty_list_checks_both_ways(settings_cc, monkeypatch):
    """The effective list is [default]: moving the default removes the old one (in-use check) and adds the new one
    (Cloud Run check)."""
    out, lookups, queried = _put(settings_cc, monkeypatch, {"version": 3},
                                 {"orchestration": {"default_gcp_region": "europe-west1"}, "version": 3},
                                 locations={"europe-west1"}, in_use={})
    assert not isinstance(out, Exception), out
    assert queried == [["us-central1"]] and lookups == [1]


@pytest.mark.parametrize("orch", [{"approved_deployable_regions": [EAST]},                       # default not in list
                                  {"approved_deployable_regions": ["us-central1", "US-EAST4"]},  # grammar
                                  {"approved_deployable_regions": ["us-central1", "us-central1"]}])
def test_bad_lists_are_refused_by_the_model(orch):
    with pytest.raises(Exception):
        S.PlatformSettings(orchestration=orch)


def test_negative_save_without_region_change_makes_no_lookup_and_no_query(settings_cc, monkeypatch):
    """Do No Harm: the default list (or an unchanged list) -> no Cloud Run call, no workload query, stored as before."""
    for stored, payload in (({"version": 3}, {"finops": {"default_monthly_budget_usd": 90.0}, "version": 3}),
                            ({**copy.deepcopy(TWO), "version": 3}, {**copy.deepcopy(TWO), "version": 3})):
        settings_cc.doc_ref.set.reset_mock()
        out, lookups, queried = _put(settings_cc, monkeypatch, stored, payload)
        assert not isinstance(out, Exception), out
        assert lookups == [] and queried == []
        S.invalidate_settings_cache()


def test_reset_defaults_refuses_to_drop_a_region_in_use_and_never_looks_up(settings_cc, monkeypatch):
    stored = {"orchestration": {"default_gcp_region": EAST, "approved_deployable_regions": [EAST]}, "version": 3}
    _store(monkeypatch, stored)
    monkeypatch.setattr(settings_cc.rs, "cloud_run_locations", MagicMock(side_effect=AssertionError("no lookup")))
    monkeypatch.setattr(settings_cc.rs, "_workloads_in_regions", lambda regions: {EAST: ["shop-app"]})
    with pytest.raises(Exception) as ei:
        settings_cc.rs.reset_settings_defaults_api(settings_cc.request)
    assert ei.value.status_code == 422 and ei.value.detail["code"] == "REGION_IN_USE"
    settings_cc.doc_ref.set.assert_not_called()
    S.invalidate_settings_cache()
    _store(monkeypatch, stored)
    monkeypatch.setattr(settings_cc.rs, "_workloads_in_regions", lambda regions: {})
    out = settings_cc.rs.reset_settings_defaults_api(settings_cc.request)
    assert out.orchestration.approved_deployable_regions == [] and out.orchestration.default_gcp_region == "us-central1"


def test_workloads_in_regions_skips_decommissioned(settings_cc, monkeypatch):
    docs = [MagicMock(id="a", to_dict=lambda: {"product_id": "a", "region": EAST, "status": "ACTIVE"}),
            MagicMock(id="b", to_dict=lambda: {"product_id": "b", "region": EAST, "status": "DECOMMISSIONED"})]
    fake = MagicMock()
    fake.collection.return_value.where.return_value.stream.return_value = docs
    monkeypatch.setattr(settings_cc.rs, "db", fake)
    assert settings_cc.rs._workloads_in_regions([EAST]) == {EAST: ["a"]}
    fake.collection.return_value.where.assert_called_with("region", "==", EAST)


def test_cloud_run_locations_reads_typed_location_ids_and_pages(settings_cc, monkeypatch):
    pages = [MagicMock(status_code=200, json=lambda: {"locations": [{"locationId": "us-central1"}],
                                                       "nextPageToken": "t"}),
             MagicMock(status_code=200, json=lambda: {"locations": [{"locationId": EAST, "name": "x"}]})]
    session = MagicMock()
    session.get.side_effect = pages
    with patch("google.auth.default", return_value=(MagicMock(), "p")), \
         patch("google.auth.transport.requests.AuthorizedSession", return_value=session):
        assert settings_cc.rs.cloud_run_locations() == {"us-central1", EAST}
    assert session.get.call_args_list[1].kwargs["params"]["pageToken"] == "t"
    session.get.side_effect = [MagicMock(status_code=403, json=lambda: {})]
    with patch("google.auth.default", return_value=(MagicMock(), "p")), \
         patch("google.auth.transport.requests.AuthorizedSession", return_value=session), \
         pytest.raises(settings_cc.rs.RegionLookupUnavailable):
        settings_cc.rs.cloud_run_locations()


# ============================================================================================ create
def _create(wl, monkeypatch, body, *, settings=None, initial=None):
    fake_db = FakeDB(initial)
    client = _client(wl, monkeypatch, fake_db)
    publisher = MagicMock()
    publisher.publish.return_value.result.return_value = "msg-1"
    express = []
    monkeypatch.setattr(wl, "execute_express_provisioning", lambda **k: express.append(k))
    vend = MagicMock()
    monkeypatch.setattr(wl, "make_vending_request", vend)
    plat = S.PlatformSettings(**(settings or {}))
    with patch.dict(os.environ, {"GITHUB_OWNER": "example-org", "MANAGED_WORKLOADS_FOLDER_ID": "111111111111"}), \
         patch.object(wl, "get_pubsub_publisher", return_value=publisher), \
         patch.object(wl, "get_platform_settings", return_value=plat):
        r = client.post("/api/workloads", json={"product_id": "shop-app", "spec_content": "a shop", **body},
                        headers=ADMIN_H)
    return r, fake_db, publisher, express, vend


EXPRESS = {"creation_mode": "EXPRESS",
           "module_instances": [{"module_id": "compute-cloudrun", "instance_name": "api", "parameters": {}}]}


@pytest.mark.parametrize("extra", [{}, EXPRESS])
def test_create_refuses_an_unapproved_region_before_any_side_effect(cc, monkeypatch, extra):
    _, wl = cc
    r, fake_db, publisher, express, vend = _create(wl, monkeypatch, {"region": EAST, **extra})
    assert r.status_code == 422, r.text
    d = r.json()["detail"]
    assert d["error_class"] == "REGION_NOT_APPROVED" and d["region"] == EAST and d["approved_regions"] == ["us-central1"]
    assert fake_db.writes == [] and fake_db.get("workloads/shop-app") is None
    assert not publisher.publish.called and express == [] and not vend.called


@pytest.mark.parametrize("extra", [{}, EXPRESS])
def test_create_records_an_approved_region(cc, monkeypatch, extra):
    _, wl = cc
    r, fake_db, publisher, express, _ = _create(wl, monkeypatch, {"region": EAST, **extra}, settings=TWO)
    assert r.status_code == 200, r.text
    assert fake_db.get("workloads/shop-app")["region"] == EAST
    if extra:
        assert express[0]["region"] == EAST
    else:
        assert publisher.publish.called


@pytest.mark.parametrize("body", [{}, {"region": None}, {"region": ""}])
def test_create_without_a_region_records_the_default(cc, monkeypatch, body):
    _, wl = cc
    r, fake_db, _, _, _ = _create(wl, monkeypatch, body,
                                  settings={"orchestration": {"default_gcp_region": "europe-west1"}})
    assert r.status_code == 200, r.text
    assert fake_db.get("workloads/shop-app")["region"] == "europe-west1"


def test_negative_default_install_record_is_todays_record_plus_region(cc, monkeypatch):
    """Do No Harm: with the default list, a create without `region` writes the same record as before plus
    region = default_gcp_region, and the intake event is unchanged (no region field)."""
    _, wl = cc
    r, fake_db, publisher, _, _ = _create(wl, monkeypatch, {})
    assert r.status_code == 200, r.text
    record = dict(fake_db.get("workloads/shop-app"))
    assert record.pop("region") == "us-central1"
    import json
    event = json.loads(publisher.publish.call_args[0][1].decode("utf-8"))
    assert "region" not in event
    # same field set as a create on the code before FD-7M-a (region was the only addition)
    with patch.object(wl, "_create_region", lambda *a, **k: ("us-central1", False)):
        r2, fake_db2, _, _, _ = _create(wl, monkeypatch, {})
    assert r2.status_code == 200
    before = dict(fake_db2.get("workloads/shop-app"))
    for volatile in ("created_at", "spend_last_updated_at"):
        record.pop(volatile, None)
        before.pop(volatile, None)
    assert record == before


@pytest.mark.parametrize("profile,region,ok", [("HIPAA", EAST, True), ("EU_REGIONS_AND_SUPPORT", EAST, False),
                                                ("STANDARD", EAST, True), (None, EAST, True)])
def test_create_region_must_fit_the_regulated_baseline(cc, monkeypatch, profile, region, ok):
    _, wl = cc
    body = {"region": region, **({"compliance_profile": profile} if profile else {})}
    r, fake_db, _, _, _ = _create(wl, monkeypatch, body, settings=TWO)
    if ok:
        assert r.status_code == 200, r.text
    else:
        assert r.status_code == 422, r.text
        d = r.json()["detail"]
        assert d["error_class"] == "REGION_PROFILE_CONFLICT" and d["profile"] == profile
        assert fake_db.writes == []


def test_create_default_region_outside_the_baseline_is_refused(cc, monkeypatch):
    """No requested region: the default region is checked against the baseline before the record is written."""
    _, wl = cc
    r, fake_db, publisher, _, _ = _create(wl, monkeypatch, {"compliance_profile": "EU_REGIONS_AND_SUPPORT"})
    assert r.status_code == 422 and r.json()["detail"]["error_class"] == "REGION_PROFILE_CONFLICT"
    assert fake_db.get("workloads/shop-app") is None and not publisher.publish.called


EXISTING = {"product_id": "shop-app", "status": "ACTIVE", "default_branch": "main",
            "access": {"mode": "PRIVATE_IAP", "invoker_principals": ["user:admin@example.com"],
                       "sign_in": {"google": "DISABLED"}, "source": "platform_default"}}


def test_recreate_keeps_the_recorded_region_and_refuses_another(cc, monkeypatch):
    _, wl = cc
    initial = {"workloads/shop-app": {**EXISTING, "region": EAST}}
    r, fake_db, _, _, _ = _create(wl, monkeypatch, {}, settings=TWO, initial=initial)
    assert r.status_code == 200, r.text
    assert fake_db.get("workloads/shop-app")["region"] == EAST
    r, fake_db, _, _, _ = _create(wl, monkeypatch, {"region": "us-central1"}, settings=TWO, initial=initial)
    assert r.status_code == 409 and r.json()["detail"]["error_class"] == "REGION_CHANGE_REFUSED"
    assert r.json()["detail"]["current_region"] == EAST and fake_db.writes == []


def test_recreate_with_a_record_region_no_longer_approved_is_422(cc, monkeypatch):
    _, wl = cc
    initial = {"workloads/shop-app": {**EXISTING, "region": EAST}}
    r, fake_db, _, _, _ = _create(wl, monkeypatch, {}, initial=initial)
    assert r.status_code == 422 and r.json()["detail"]["error_class"] == "REGION_NOT_APPROVED"
    assert fake_db.writes == []


def test_negative_legacy_record_is_not_stamped(cc, monkeypatch):
    """OQ-24: an existing workload without a recorded region keeps following the default; no region is written."""
    _, wl = cc
    initial = {"workloads/shop-app": dict(EXISTING)}
    r, fake_db, _, _, _ = _create(wl, monkeypatch, {}, initial=initial)
    assert r.status_code == 200, r.text
    assert "region" not in fake_db.get("workloads/shop-app")
    r, fake_db, _, _, _ = _create(wl, monkeypatch, {"region": "us-central1"}, initial=initial)
    assert r.status_code == 200 and "region" not in fake_db.get("workloads/shop-app")
    r, _, _, _, _ = _create(wl, monkeypatch, {"region": EAST}, settings=TWO, initial=initial)
    assert r.status_code == 409 and r.json()["detail"]["error_class"] == "REGION_CHANGE_REFUSED"


def test_create_region_helper_unreadable_record():
    sys.path.insert(0, CC_DIR)
    try:
        from routes import workloads as wl
    finally:
        sys.path.remove(CC_DIR)
    orch = S.OrchestrationSettings()
    assert wl._create_region("p", None, None, "us-central1", orch) == ("us-central1", False)
    with pytest.raises(Exception) as ei:
        wl._create_region("p", None, "us-central1", "us-central1", orch)
    assert ei.value.status_code == 503 and ei.value.detail["error_class"] == "REGION_UNAVAILABLE"


def test_schema_region_field(cc):
    schemas, _ = cc
    assert schemas.CreateWorkloadRequest(product_id="x").region is None
    assert schemas.CreateWorkloadRequest(product_id="x", region="").region is None
    assert schemas.CreateWorkloadRequest(product_id="x", region=EAST).region == EAST


def test_profile_region_table_equals_the_compliance_table(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "_fd7m_cp", os.path.join(REPO_ROOT, "apps", "orchestrator-gateway", "developer_agent", "compliance_profile.py"))
    cp = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "_fd7m_cp", cp)   # dataclasses look their module up by name
    spec.loader.exec_module(cp)
    sys.path.insert(0, CC_DIR)
    try:
        import schemas
    finally:
        sys.path.remove(CC_DIR)
    assert schemas.PROFILE_ALLOWED_REGIONS == {p: v["allowed_regions"] for p, v in cp.PROFILE_REQUIREMENTS.items()}


# ============================================================================================ Express
def _run_express(wl, **kw):
    wl.execute_express_provisioning(
        product_id="exp-app", target_project_id="castor-exp-1", clean_vcs_provider="GITHUB",
        full_github_repo="org/exp-repo", target_branch="main", target_folder=None, budget=50.0,
        clean_engine="OPENTOFU", is_sandbox=False, admin_email="admin@example.com",
        module_instances=[{"module_id": "compute-cloudrun", "instance_name": "api", "parameters": {}}],
        include_vpc=False, trace_id="tr-exp7", **kw)


class _FakeSynth:
    seen = []

    def __init__(self, *a, **k):
        pass

    def requires_private_network(self, _instances):
        return False

    def synthesize_workload(self, **kw):
        _FakeSynth.seen.append(kw["region"])
        return {"main.tf": "# x\n"}


def test_express_synthesizes_in_the_given_region_never_the_host_env(monkeypatch):
    wl, store, _tfm = _route(monkeypatch)
    _FakeSynth.seen = []
    monkeypatch.setattr(wl, "ExpressHCLSynthesizer", _FakeSynth)
    monkeypatch.setenv("REGION", "asia-east1")   # the host region must not leak into the workload
    _run_express(wl, region=EAST)
    assert _FakeSynth.seen == [EAST]


def test_express_without_a_region_reads_the_record_through_the_helper(monkeypatch):
    wl, store, _tfm = _route(monkeypatch)
    store.docs["workloads/exp-app"] = {"product_id": "exp-app", "region": EAST}
    _FakeSynth.seen = []
    monkeypatch.setattr(wl, "ExpressHCLSynthesizer", _FakeSynth)
    monkeypatch.setattr(wl, "get_platform_settings", lambda **k: S.PlatformSettings(**TWO))
    _run_express(wl)
    assert _FakeSynth.seen == [EAST]


def test_express_record_region_not_approved_stops_before_vending(monkeypatch):
    wl, store, tfm = _route(monkeypatch)
    store.docs["workloads/exp-app"] = {"product_id": "exp-app", "region": EAST}
    monkeypatch.setattr(wl, "get_platform_settings", lambda **k: S.PlatformSettings())
    _run_express(wl)
    assert not wl.make_vending_request.called and not tfm.called
    pe = store.docs["pipeline_executions/tr-exp7"]
    assert pe["status"] == "FAILED" and pe["error_class"] == "REGION_NOT_APPROVED"
    assert store.docs["workloads/exp-app"]["status"] == "FAILED"


def test_express_settings_unreadable_stops_typed_before_vending(monkeypatch):
    wl, store, tfm = _route(monkeypatch)
    store.docs["workloads/exp-app"] = {"product_id": "exp-app"}

    def _boom(**_k):
        raise S.PlatformSettingsReadError("down")

    monkeypatch.setattr(wl, "get_platform_settings", _boom)
    _run_express(wl)
    assert not wl.make_vending_request.called
    assert store.docs["pipeline_executions/tr-exp7"]["error_class"] == "REGION_UNAVAILABLE"


def test_negative_express_hcl_for_the_default_region_is_byte_identical():
    """Do No Harm: the real synthesizer given the default region renders exactly what the old call (host REGION
    us-central1) rendered."""
    from shared.express_synthesizer import ExpressHCLSynthesizer

    args = dict(product_id="exp-app", project_id="castor-exp-1", github_repo_full_name="org/exp-repo",
                module_instances=[{"module_id": "compute-cloudrun", "instance_name": "api", "parameters": {}}],
                state_bucket="castor-tfstate-castor-exp-1", include_vpc=False, vcs_provider="GITHUB",
                iac_engine="OPENTOFU", subnet_cidr=None, access=None)
    old = ExpressHCLSynthesizer().synthesize_workload(region="us-central1", **args)   # the old call (host REGION)
    new = ExpressHCLSynthesizer().synthesize_workload(
        region=S.workload_region(None, S.OrchestrationSettings()), **args)
    assert old == new and old


# ============================================================================================ display
def test_diagram_shows_the_recorded_region_or_the_default_label():
    sys.path.insert(0, CC_DIR)
    try:
        from diagram import ArchitectureDiagramEngine
    finally:
        sys.path.remove(CC_DIR)
    eng = ArchitectureDiagramEngine()
    with_region = eng.generate_mermaid_diagram("shop", {"project_id": "p-1", "region": EAST}, {}).mermaid_code
    legacy = eng.generate_mermaid_diagram("shop", {"project_id": "p-1"}, {}).mermaid_code
    assert f"{EAST}-docker.pkg.dev/p-1/castor-shop" in with_region
    assert "us-central1-docker" not in legacy and "(Settings default region)/p-1/castor-shop" in legacy


def test_dashboard_has_no_literal_region_fallback_and_offers_the_list():
    html = open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8").read()
    assert "item.region || 'us-central1'" not in html and "item.region || '-'" in html
    assert 'x-model="newWorkloadForm.region"' in html and "approvedRegionOptions()" in html
    assert "Approved Deployable Regions" in html and "platformSettings.orchestration.approved_deployable_regions" in html
    assert 'data-testid="workload-region"' in html


def test_workload_details_response_carries_the_region(cc):
    schemas, _ = cc
    assert "region" in schemas.WorkloadDetailsResponse.model_fields
    assert schemas.WorkloadDetailsResponse.model_fields["region"].default is None


def test_quota_view_defaults_to_the_approved_regions(cc, monkeypatch):
    from routes import telemetry
    monkeypatch.setattr(S, "get_platform_settings", lambda *a, **k: S.PlatformSettings(**TWO))
    assert telemetry._approved_quota_regions() == ["us-central1", EAST]
    monkeypatch.setattr(S, "get_platform_settings", lambda *a, **k: S.PlatformSettings())
    assert telemetry._approved_quota_regions() == ["us-central1"]


# ============================================================================================ RT fixes (Fable 10-31)
def test_rt_f1_region_in_use_message_states_the_two_step_default_change(settings_cc, monkeypatch):
    out, _, _ = _put(settings_cc, monkeypatch, {"version": 3},
                     {"orchestration": {"default_gcp_region": EAST}, "version": 3},
                     locations={EAST}, in_use={"us-central1": ["shop-app"]})
    assert out.status_code == 422 and out.detail["code"] == "REGION_IN_USE"
    msg = out.detail["message"]
    assert "both the current and the new default region" in msg and "follow a changed default" in msg
    assert _stored(settings_cc) is None


def test_rt_f1_the_two_step_default_change_is_accepted(settings_cc, monkeypatch):
    stored = {"orchestration": {"approved_deployable_regions": ["us-central1", EAST]}, "version": 3}
    payload = {"orchestration": {"approved_deployable_regions": ["us-central1", EAST], "default_gcp_region": EAST},
               "version": 3}
    out, lookups, queried = _put(settings_cc, monkeypatch, stored, payload)
    assert not isinstance(out, Exception), out
    assert lookups == [] and queried == []
    assert _stored(settings_cc)["orchestration"]["default_gcp_region"] == EAST


def test_rt_f1_settings_reference_states_the_workaround():
    ref = open(os.path.join(REPO_ROOT, "documentation", "settings-reference.md"), encoding="utf-8").read()
    assert "change the default in two saves" in ref and "moves them at their next deploy" in ref


def test_rt_f2_baseline_conflict_writes_no_downgrade_approval_card(cc, monkeypatch):
    """The effective region (the recorded one) is checked against the baseline before the compliance downgrade guard,
    so a refused create leaves no approval card behind."""
    _, wl = cc
    initial = {"workloads/shop-app": {**EXISTING, "region": EAST, "requested_compliance_profile": "HIPAA"}}
    r, fake_db, publisher, _, _ = _create(wl, monkeypatch, {"compliance_profile": "EU_REGIONS_AND_SUPPORT"},
                                          settings=TWO, initial=initial)
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["error_class"] == "REGION_PROFILE_CONFLICT" and r.json()["detail"]["region"] == EAST
    assert fake_db.writes == [] and not any(k.startswith("approval_requests/") for k in fake_db)
    assert not publisher.publish.called


def test_rt_f2_negative_a_downgrade_in_an_allowed_region_still_gets_its_card(cc, monkeypatch):
    """Do No Harm: when the region fits the requested baseline the downgrade guard runs as before (409 + card)."""
    _, wl = cc
    initial = {"workloads/shop-app": {**EXISTING, "region": EAST, "requested_compliance_profile": "FEDRAMP_HIGH"}}
    r, fake_db, _, _, _ = _create(wl, monkeypatch, {"compliance_profile": "HIPAA"}, settings=TWO, initial=initial)
    assert r.status_code == 409 and r.json()["detail"]["error_class"] == "COMPLIANCE_DOWNGRADE_REQUIRES_APPROVAL"
    assert any(k.startswith("approval_requests/") for k in fake_db)
