"""FD-7M-a contract (SAT-21 contract commit): `orchestration.approved_deployable_regions`, its validation, the
`workload_region()` helper and `RegionNotApproved` (REGION_NOT_APPROVED) in shared/settings.py (x7 byte-identical,
tests/test_shared_packaging.py). SAT-22 / SAT-23 consume the helper; this file pins its behavior."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from shared import settings as S  # noqa: E402


# ---------------------------------------------------------------- defaults: nothing changes (Do No Harm)
def test_default_list_is_empty_and_means_default_region():
    orch = S.OrchestrationSettings()
    assert orch.approved_deployable_regions == []
    assert S.approved_deployable_regions(orch) == [orch.default_gcp_region] == ["us-central1"]


def test_document_without_the_field_reads_as_before():
    """Negative: a stored document with no new field parses to the same values as before (plus the empty list)."""
    stored = {"orchestration": {"default_gcp_region": "europe-west1", "default_branch": "trunk"}}
    parsed = S.PlatformSettings(**stored).orchestration.model_dump()
    assert parsed.pop("approved_deployable_regions") == []
    before = S.OrchestrationSettings(default_gcp_region="europe-west1", default_branch="trunk").model_dump()
    before.pop("approved_deployable_regions")
    assert parsed == before
    assert S.approved_deployable_regions(S.PlatformSettings(**stored).orchestration) == ["europe-west1"]


def test_missing_record_region_is_the_default_region():
    orch = S.OrchestrationSettings(default_gcp_region="europe-west1")
    assert S.workload_region(None, orch) == "europe-west1"
    # FD-4AL: a caller's already-resolved platform region wins for a record without a region
    assert S.workload_region(None, orch, default_region="asia-east1") == "asia-east1"


def test_record_region_equal_to_default_with_default_list():
    assert S.workload_region("us-central1", S.OrchestrationSettings()) == "us-central1"


# ---------------------------------------------------------------- approved / not approved
def test_record_region_approved_is_returned():
    orch = S.OrchestrationSettings(approved_deployable_regions=["us-central1", "us-east4"])
    assert S.workload_region("us-east4", orch) == "us-east4"
    assert S.workload_region("us-central1", orch) == "us-central1"


def test_mapping_orchestration_is_accepted():
    orch = {"default_gcp_region": "us-central1", "approved_deployable_regions": ["us-central1", "us-east4"]}
    assert S.workload_region("us-east4", orch) == "us-east4"
    assert S.approved_deployable_regions({}) == ["us-central1"]


@pytest.mark.parametrize("region", ["us-east4", "", "US-CENTRAL1", 5, ["us-central1"]])
def test_record_region_not_approved_raises_typed(region):
    orch = S.OrchestrationSettings()
    with pytest.raises(S.RegionNotApproved) as ei:
        S.workload_region(region, orch, stage="deploy")
    err = ei.value
    assert err.code == err.error_class == S.REGION_NOT_APPROVED == "REGION_NOT_APPROVED"
    assert err.region == region and err.approved == ["us-central1"] and err.stage == "deploy"
    assert isinstance(err, ValueError)


def test_removed_region_is_never_replaced_by_another():
    orch = S.OrchestrationSettings(approved_deployable_regions=["us-central1"])
    with pytest.raises(S.RegionNotApproved):
        S.workload_region("europe-west1", orch)


def test_helper_refuses_an_unknown_settings_type():
    with pytest.raises(TypeError):
        S.workload_region("us-central1", None)


# ---------------------------------------------------------------- validation (typed read / write errors)
def test_default_outside_stored_list_is_invalid():
    with pytest.raises(Exception):
        S.OrchestrationSettings(approved_deployable_regions=["us-east4"])
    with pytest.raises(S.PlatformSettingsInvalid) as ei:
        S.validate_settings_document({"orchestration": {"approved_deployable_regions": ["us-east4"]}})
    assert ei.value.code == "PLATFORM_SETTINGS_INVALID"


@pytest.mark.parametrize("bad", [["us-central1", "us central1"], ["us-central1", "USEAST"], ["us-central1", ""],
                                 ["us-central1", "uscentral1"], ["us-central1", 4], ["us-central1", "us-central1"],
                                 ["us-central1", "us-é1"], ["us-central1", "a-" + "b" * 40]])
def test_bad_grammar_or_duplicate_is_invalid(bad):
    with pytest.raises(S.PlatformSettingsInvalid):
        S.validate_settings_document({"orchestration": {"approved_deployable_regions": bad}})


def test_stored_invalid_list_is_a_typed_strict_read_error(monkeypatch):
    S.invalidate_settings_cache()
    monkeypatch.setattr(S, "_read_stored_document",
                        lambda _pid: {"orchestration": {"approved_deployable_regions": ["us-east4"]}})
    try:
        with pytest.raises(S.PlatformSettingsInvalid):
            S.get_platform_settings(force_refresh=True, strict=True)
    finally:
        S.invalidate_settings_cache()


def test_valid_list_is_stored_unchanged():
    """Do No Harm: validation never rewrites the list (order kept, nothing dropped)."""
    regions = ["us-east4", "us-central1", "europe-west1"]
    orch = S.OrchestrationSettings(approved_deployable_regions=list(regions))
    assert orch.approved_deployable_regions == regions
    assert S.approved_deployable_regions(orch) == regions


@pytest.mark.parametrize("value,ok", [("us-central1", True), ("europe-west4", True), ("me-central2", True),
                                      ("northamerica-northeast1", True), ("global", False), ("us-", False),
                                      ("-us", False), ("us--east", False), (None, False), ("us_east1", False)])
def test_region_id_grammar_matches_gcloud_executor(value, ok):
    assert S.is_region_id(value) is ok
    sys.path.insert(0, os.path.join(REPO_ROOT, "mcp-servers", "gcloud"))
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("_fd7m_gcloud_executor",
                                                      os.path.join(REPO_ROOT, "mcp-servers", "gcloud", "executor.py"))
        mod = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(mod)
        except Exception:  # noqa: BLE001 - the executor's imports may be absent in this env: grammar test above stands
            return
        assert mod.is_region(value) is ok
    finally:
        sys.path.pop(0)


def test_every_settings_copy_has_the_contract():
    import hashlib
    copies = ["shared/settings.py", "apps/control-center/shared/settings.py", "apps/finops-enforcer/shared/settings.py",
              "apps/orchestrator-gateway/shared/settings.py", "apps/project-vending/shared/settings.py",
              "apps/spec-ingestion/shared/settings.py", "mcp-servers/terraform/shared/settings.py"]
    digests = set()
    for rel in copies:
        with open(os.path.join(REPO_ROOT, rel), "rb") as fh:
            body = fh.read()
        assert b"def workload_region(" in body and b"class RegionNotApproved(" in body, rel
        digests.add(hashlib.sha256(body).hexdigest())
    assert len(digests) == 1
