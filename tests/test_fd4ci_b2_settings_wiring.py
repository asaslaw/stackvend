"""FD-4CI-b items 2-5 and 7 (register row FD-4CI-b, owner 10-21, "fix, never remove"): Settings that did nothing or
were mislabelled now do what the page says.

2. FinOps: Default Monthly Budget Ceiling (CC create, project vending for a record without a budget, no hardcoded 40 in
   the orchestrator's vend call), Warning Threshold + Circuit Breaker (CC billing webhook), Enforce Scale-to-Zero
   (Agent-mode Cloud Run min_instances when the spec states none).
3. Orchestration: Terraform Lock Timeout and Verified Stale Lock Age (Terraform server, env var still wins), Default
   Container Memory / vCPU (Agent-mode Cloud Run sizing). Default GitHub Branch stays unwired (labelled "Not used yet").
4. Terraform Version list = versions the Terraform server accepts at run time (< 1.6); a refused version is not saved.
5. Models: help-text defaults, no silent raise of max_output_tokens, Thinking Budget read, cleared architect override
   inherits the global limit. FinOps Agent Model has no reader (no FinOps model call exists): labelled "Not used".
7. Config Version: a stale save is refused with 409 SETTINGS_VERSION_CONFLICT and nothing is written.

Every wired setting: set -> the reader uses it; unset / unreadable -> the behaviour before (negative tests).
Hermetic: in-memory fakes only.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import base64
import copy
import json
import os
import re
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

TESTS = os.path.dirname(__file__)
REPO_ROOT = os.path.abspath(os.path.join(TESTS, ".."))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
GW_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TF_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
for p in (TESTS, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

from shared import settings as S  # noqa: E402
from test_fd4ak_settings_fail_closed import _Client, _store, cc as cc_settings_routes  # noqa: F401,E402
from test_fd4cu_freeze_new_workloads import _create, vend  # noqa: F401,E402  (vend: fixture)
from test_l19_11_access_intake import cc  # noqa: F401,E402  (fixture)

DASHBOARD = open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8").read()
SETTINGS_REF = open(os.path.join(REPO_ROOT, "documentation", "settings-reference.md"), encoding="utf-8").read()


@pytest.fixture(autouse=True)
def _fresh_cache():
    S.invalidate_settings_cache()
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        yield
    S.invalidate_settings_cache()


def _raises(err):
    def read(*a, **k):
        raise err
    return read


def _ps(**sections):
    return S.PlatformSettings(**sections)


# ================================================================================================ shared readers
def test_strict_setting_value_set_unset_unreadable_and_unusable():
    s = _ps(finops={"circuit_breaker_threshold_pct": 150.0})
    seen = {}

    def read(**k):
        seen.update(k)
        return s
    assert S.strict_setting_value("finops", "circuit_breaker_threshold_pct", 100.0, read=read, project_id="h") == 150.0
    assert seen == {"project_id": "h", "strict": True}
    assert S.strict_setting_value("finops", "circuit_breaker_threshold_pct", 100.0, read=lambda **k: _ps()) == 100.0
    for err in (S.PlatformSettingsReadError("down"), S.PlatformSettingsInvalid("bad"), RuntimeError("x")):
        assert S.strict_setting_value("finops", "circuit_breaker_threshold_pct", 7, read=_raises(err)) == 7
    odd = SimpleNamespace(finops=SimpleNamespace(circuit_breaker_threshold_pct="lots"))
    assert S.strict_setting_value("finops", "circuit_breaker_threshold_pct", 7, read=lambda **k: odd,
                                  accept=S.is_setting_number) == 7
    assert S.strict_setting_value("finops", "x", 7, read=lambda **k: SimpleNamespace()) == 7   # no section
    assert S.strict_setting_value("finops", "circuit_breaker_threshold_pct", 7) == 7   # store unreadable (autouse)


def test_stored_setting_value_reads_the_callers_own_client():
    doc = {"orchestration": {"terraform_lock_timeout_seconds": 240}}
    assert S.stored_setting_value(_Client(doc), "orchestration", "terraform_lock_timeout_seconds", 180) == 240
    # no document (fresh install) -> the schema default; a document without the section -> the schema default
    assert S.stored_setting_value(_Client(None, exists=False), "orchestration", "terraform_lock_timeout_seconds",
                                  9) == 180
    assert S.stored_setting_value(_Client({}), "orchestration", "stale_lock_threshold_minutes", 9) == 20
    # negative: unreadable, invalid, no client, a mock (not a snapshot), a section that is not a mapping -> fallback
    for db in (_Client(error=RuntimeError("down")), _Client({"orchestration": {"terraform_lock_timeout_seconds": 5}}),
               None, MagicMock(), _Client({"orchestration": "x"})):
        assert S.stored_setting_value(db, "orchestration", "terraform_lock_timeout_seconds", 180) == 180
    assert S.stored_setting_value(_Client(doc), "nope", "x", "fb") == "fb"
    assert S.stored_setting_value(_Client(doc), "orchestration", "terraform_lock_timeout_seconds", 180,
                                  accept=lambda v: v > 1000) == 180


def test_settings_copies_are_byte_identical():
    root = open(os.path.join(REPO_ROOT, "shared", "settings.py"), "rb").read()
    for d in ("apps/control-center/shared", "apps/orchestrator-gateway/shared", "apps/project-vending/shared",
              "apps/spec-ingestion/shared", "mcp-servers/terraform/shared"):
        assert open(os.path.join(REPO_ROOT, d, "settings.py"), "rb").read() == root, d


# ================================================================================================ 2. FinOps
def test_create_without_a_budget_gets_the_platform_default(cc, monkeypatch):
    _, wl = cc
    r, fake_db, payload = _create(wl, monkeypatch, _ps(finops={"default_monthly_budget_usd": 75.0}))
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"]["budget_ceiling_monthly_usd"] == 75.0 == r.json()["budget_ceiling_monthly_usd"]
    assert payload["budget_ceiling_monthly_usd"] == 75.0
    # unset setting -> the schema default (40, the budget agent workloads ended up with after vending before)
    r, fake_db, _ = _create(wl, monkeypatch, _ps())
    assert fake_db["workloads/shop-app"]["budget_ceiling_monthly_usd"] == 40.0


def test_create_with_a_budget_keeps_it(cc, monkeypatch):
    _, wl = cc
    r, fake_db, _ = _create(wl, monkeypatch, _ps(finops={"default_monthly_budget_usd": 75.0}),
                            body={"budget_ceiling_monthly_usd": 120.0})
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"]["budget_ceiling_monthly_usd"] == 120.0


def test_create_with_unreadable_settings_is_still_refused(cc, monkeypatch):
    _, wl = cc
    r, fake_db, _ = _create(wl, monkeypatch, _raises(S.PlatformSettingsReadError("down")))
    assert r.status_code == 503 and "workloads/shop-app" not in fake_db


def test_create_request_budget_defaults_to_none_and_helper_falls_back(cc):
    schemas, wl = cc
    assert schemas.CreateWorkloadRequest(product_id="x").budget_ceiling_monthly_usd is None
    assert wl._platform_default_budget_usd(SimpleNamespace()) == 40.0
    assert wl._platform_default_budget_usd(SimpleNamespace(finops=SimpleNamespace(default_monthly_budget_usd=True))) \
        == 40.0


def test_vending_keeps_an_existing_records_budget(vend):
    initial = {"workloads/fresh-svc": {"product_id": "fresh-svc", "budget_ceiling_monthly_usd": 120.0}}
    res, db, record = vend(_ps(finops={"default_monthly_budget_usd": 75.0}), initial=initial)
    assert "budget_ceiling_monthly_usd" not in record   # the merge write leaves the operator's budget alone
    assert db.doc("workloads/fresh-svc")["budget_ceiling_monthly_usd"] == 120.0
    assert res["budget_ceiling_monthly_usd"] == 120.0


@pytest.mark.parametrize("settings, budget", [(_ps(finops={"default_monthly_budget_usd": 75.0}), 75.0),
                                              (_ps(), 40.0),
                                              (_raises(S.PlatformSettingsReadError("down")), 40.0)])
def test_vending_a_new_record_gets_the_platform_default(vend, settings, budget):
    res, db, record = vend(settings)
    assert record["budget_ceiling_monthly_usd"] == budget == res["budget_ceiling_monthly_usd"]


def test_vending_an_unreadable_record_writes_no_budget(vend):
    _, _, record = vend(_ps(), fail_read=True)
    assert "budget_ceiling_monthly_usd" not in record


def test_workflow_and_vending_api_no_longer_force_40():
    wf = open(os.path.join(REPO_ROOT, "workflows", "main_orchestrator.yaml"), encoding="utf-8").read()
    assert "initial_budget: 40.0" not in wf
    tree = ast.parse(open(os.path.join(REPO_ROOT, "apps", "project-vending", "main.py"), encoding="utf-8").read())
    for cls in (n for n in tree.body if isinstance(n, ast.ClassDef)):
        for f in cls.body:
            if isinstance(f, ast.AnnAssign) and getattr(f.target, "id", "") == "initial_budget":
                assert isinstance(f.value, ast.Constant) and f.value.value is None, cls.name


class _AlertDB:
    """The Control Center db for the billing webhook: one workload, the settings document, billing_alerts."""

    def __init__(self, workload, settings_doc=None, settings_error=None):
        self.workload, self.alerts = dict(workload), {}
        self.settings = _Client(settings_doc, exists=settings_doc is not None, error=settings_error)

    def collection(self, name):
        if name == "system_config":
            return self.settings
        if name == "billing_alerts":   # RT F1: one deterministic document per workload and period (no add())
            alerts = self.alerts

            def _set(doc_id):
                def set_(data, merge=False):
                    alerts[doc_id] = {**alerts.get(doc_id, {}), **data} if merge else dict(data)
                return SimpleNamespace(set=set_)
            return SimpleNamespace(document=lambda doc_id: _set(doc_id))
        assert name == "workloads"
        outer = self

        class _Ref:
            def __init__(self, pid):
                self.pid = pid

            def get(self):
                return SimpleNamespace(exists=True, id=self.pid, to_dict=lambda: dict(outer.workload))

            def set(self, data, merge=False):
                outer.workload.update(data)
        return SimpleNamespace(document=lambda pid: _Ref(pid), where=MagicMock())


def _alert(monkeypatch, cost, workload, settings_doc=None, settings_error=None, db=None, extra=None):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    from routes import finops as fr
    from routes import approvals as ar
    db = db or _AlertDB(workload, settings_doc, settings_error)
    monkeypatch.setattr(fr, "db", db)
    enforcer = MagicMock()
    enforcer.quarantine_workload.return_value = {"status": "QUARANTINED"}
    monkeypatch.setattr(ar, "get_finops_enforcer", lambda: enforcer)
    body = {"budgetDisplayName": "budget-shop-app", "costAmount": cost, **(extra or {})}
    data = base64.b64encode(json.dumps(body).encode()).decode()
    # C10: the notification must come from this install's billing account (shared/billing_alerts.py)
    monkeypatch.setenv("BILLING_ACCOUNT_ID", "billingAccounts/01ABCD-234567-89EF01")
    env = fr.PubSubAlertEnvelope(message=fr.PubSubAlertMessage(
        data=data, attributes={"billingAccountId": "01ABCD-234567-89EF01"}))
    return fr.billing_alert_webhook(env, MagicMock()), enforcer, db


WL = {"product_id": "shop-app", "project_id": "shop-app-1", "budget_ceiling_monthly_usd": 100.0,
      "budget_breach_policy": "ALERT_ONLY"}


@pytest.mark.parametrize("cost, settings_doc, tripped, threshold", [
    (100.0, None, True, 100.0),                                             # no document: 100 % (as before)
    (99.0, None, False, 100.0),
    (100.0, {"finops": {"circuit_breaker_threshold_pct": 150.0}}, False, 150.0),
    (150.0, {"finops": {"circuit_breaker_threshold_pct": 150.0}}, True, 150.0),
    (60.0, {"finops": {"circuit_breaker_threshold_pct": 50.0}}, True, 50.0),
])
def test_circuit_breaker_percent_of_the_ceiling(monkeypatch, cost, settings_doc, tripped, threshold):
    res, enforcer, _ = _alert(monkeypatch, cost, WL, settings_doc)
    assert enforcer.quarantine_workload.called is tripped
    if tripped:
        assert enforcer.quarantine_workload.call_args.kwargs["budget_amount"] == threshold
    else:
        assert res["threshold"] == threshold


def test_circuit_breaker_unreadable_settings_is_100_percent(monkeypatch):
    res, enforcer, db = _alert(monkeypatch, 100.0, WL, settings_error=RuntimeError("down"))
    assert enforcer.quarantine_workload.call_args.kwargs["budget_amount"] == 100.0
    res, enforcer, db = _alert(monkeypatch, 90.0, WL, settings_error=RuntimeError("down"))
    assert res["status"] == "UNDER_THRESHOLD" and db.alerts == {}   # and no warning either (as before)


def test_an_approved_buffer_ceiling_is_used_as_it_is(monkeypatch):
    wl = dict(WL, buffer_ceiling_usd=115.0)
    doc = {"finops": {"circuit_breaker_threshold_pct": 50.0}}
    res, enforcer, _ = _alert(monkeypatch, 110.0, wl, doc)
    assert not enforcer.quarantine_workload.called and res["threshold"] == 115.0


def test_warning_threshold_records_a_warning_alert_and_stops_nothing(monkeypatch):
    res, enforcer, db = _alert(monkeypatch, 85.0, WL, {})   # document without FinOps: default 80 %
    assert res["status"] == "WARNING_THRESHOLD" and res["warning_at"] == 80.0
    assert not enforcer.quarantine_workload.called
    (alert,) = db.alerts.values()
    assert alert["code"] == "BUDGET_WARNING_THRESHOLD" and alert["severity"] == "WARNING"
    assert (alert["product_id"], alert["spend_amount"], alert["budget_amount"]) == ("shop-app", 85.0, 100.0)
    # below the warning share -> as before
    res, _, db = _alert(monkeypatch, 79.0, WL, {})
    assert res["status"] == "UNDER_THRESHOLD" and db.alerts == {}
    # a raised warning share
    res, _, db = _alert(monkeypatch, 85.0, WL, {"finops": {"warning_threshold_pct": 90.0}})
    assert res["status"] == "UNDER_THRESHOLD" and db.alerts == {}
    assert db.workload["current_spend_usd"] == 85.0 and db.workload["budget_ceiling_monthly_usd"] == 100.0


# ------------------------------------------------------------------ Enforce Scale-to-Zero + container sizing (gateway)
@pytest.fixture
def gw(monkeypatch):
    if GW_DIR not in sys.path:
        monkeypatch.syspath_prepend(GW_DIR)
    from developer_agent import platform_compute as pc
    from developer_agent import terraform_engine as te
    return SimpleNamespace(pc=pc, te=te)


def test_scale_to_zero_on_is_todays_detection(gw):
    for spec in ("", "a shop", "scale to zero please", "min instances: 2", "keep 2 warm instances", "always-on api"):
        assert gw.te.detect_cloudrun_scaling_parameters(spec) == \
            gw.te.detect_cloudrun_scaling_parameters(spec, default_min_instances=0)


@pytest.mark.parametrize("spec, expected", [("", 1), ("a shop", 1), ("scale to zero please", 0),
                                            ("minimum instances: 0", 0), ("min instances: 3", 3),
                                            ("keep 2 warm instances", 2), ("always-on api", 1)])
def test_scale_to_zero_off_only_changes_an_unstated_minimum(gw, spec, expected):
    assert gw.te.detect_cloudrun_scaling_parameters(spec, default_min_instances=1)["min_instances"] == expected


def test_main_tf_byte_identical_when_on_and_warm_when_off(gw):
    base = gw.te.generate_golden_main_tf("shop-app", "cloudrun", "a shop")
    assert gw.te.generate_golden_main_tf("shop-app", "cloudrun", "a shop", default_min_instances=0) == base
    off = gw.te.generate_golden_main_tf("shop-app", "cloudrun", "a shop", default_min_instances=1)
    assert re.search(r"min_instances\s*=\s*0\b", base) and re.search(r"min_instances\s*=\s*1\b", off)
    assert off.replace("min_instances         = 1", "min_instances         = 0") == base
    # the architect's stated scaling always wins
    stated = {"min_instances": 0, "max_instances": 5, "cpu_idle": True}
    assert gw.te.generate_golden_main_tf("shop-app", "cloudrun", "a shop", scaling_override=stated,
                                         default_min_instances=1) == \
        gw.te.generate_golden_main_tf("shop-app", "cloudrun", "a shop", scaling_override=stated)


def test_resolve_compute_defaults_set_unset_unreadable(gw):
    pc = gw.pc
    assert pc.resolve_platform_compute_defaults(read=lambda **k: _ps()) == pc.PlatformComputeDefaults()
    got = pc.resolve_platform_compute_defaults(read=lambda **k: _ps(
        finops={"enforce_scale_to_zero_default": False},
        orchestration={"default_container_memory_mb": 2048, "default_container_cpu": 2}))
    assert got == pc.PlatformComputeDefaults(default_min_instances=1, memory_mb=2048, cpu=2)
    assert pc.resolve_platform_compute_defaults(read=_raises(S.PlatformSettingsReadError("x"))) == \
        pc.PlatformComputeDefaults()
    assert pc.resolve_platform_compute_defaults() == pc.PlatformComputeDefaults()   # store unreadable (autouse)
    assert pc.default_min_instances(None) == 0


def _profile(tier=1, mem="512Mi", cpu="1000m", gcpu="1"):
    from shared.resource_sizing import ContainerSizingProfile
    return ContainerSizingProfile(tier=tier, memory_limit=mem, cpu_limit=cpu, gcloud_cpu=gcpu, initial_delay_secs=2,
                                  failure_threshold=20, matched_packages=[], matched_intents=[])


def test_container_baseline(gw):
    pc = gw.pc
    p1, p2, p3 = _profile(), _profile(2, "1Gi"), _profile(3, "2Gi", "2000m", "2")
    # today's defaults / no defaults: the profile itself (negative: nothing changes)
    for p in (p1, p2, p3):
        assert pc.apply_platform_container_baseline(p, None) is p
        assert pc.apply_platform_container_baseline(p, pc.PlatformComputeDefaults()) is p
    big = pc.PlatformComputeDefaults(memory_mb=2048, cpu=2)
    out = pc.apply_platform_container_baseline(p1, big)
    assert (out.memory_limit, out.cpu_limit, out.gcloud_cpu, out.tier) == ("2048Mi", "2000m", "2", 1)
    # a heavier tier keeps its larger value; a smaller baseline never shrinks it
    assert pc.apply_platform_container_baseline(p3, pc.PlatformComputeDefaults(memory_mb=1024, cpu=1)) is p3
    out = pc.apply_platform_container_baseline(p2, pc.PlatformComputeDefaults(memory_mb=768, cpu=1))
    assert (out.memory_limit, out.cpu_limit) == ("1024Mi", "1000m") or out is p2
    # combinations Cloud Run cannot run keep the profile
    for bad in (pc.PlatformComputeDefaults(memory_mb=8192, cpu=1), pc.PlatformComputeDefaults(memory_mb=512, cpu=3),
                pc.PlatformComputeDefaults(memory_mb=256, cpu=1), pc.PlatformComputeDefaults(memory_mb=1024, cpu=4)):
        assert pc.apply_platform_container_baseline(p1, bad) is p1


def test_handler_threads_the_defaults_to_every_scaling_site():
    src = open(os.path.join(GW_DIR, "developer_agent", "handler.py"), encoding="utf-8").read()
    tree = ast.parse(src)
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and getattr(n.func, "id", None) in (
        "generate_golden_main_tf", "reconcile_multi_service_declarations", "extract_scaling_from_spec")]
    assert len(calls) == 5
    for c in calls:
        assert any(k.arg == "default_min_instances" for k in c.keywords), ast.unparse(c)[:80]
    assert "compute_defaults=resolve_platform_compute_defaults(self.project_id)" in src
    assert 'if sizing.tier > 1 or (sizing.memory_limit, sizing.cpu_limit) != ("512Mi", "1000m"):' in src


# ================================================================================================ 3. Terraform server
@pytest.fixture
def tf(monkeypatch):
    monkeypatch.syspath_prepend(TF_DIR)
    import service as tf_service
    monkeypatch.delenv("TF_LOCK_TIMEOUT", raising=False)
    monkeypatch.delenv("TF_STALE_LOCK_MAX_AGE_MINUTES", raising=False)

    def make(db):
        svc = tf_service.TerraformService.__new__(tf_service.TerraformService)
        svc.db = db
        svc._lock_timeout_override = None
        svc._stale_lock_max_age_override = None
        return svc
    return SimpleNamespace(mod=tf_service, make=make)


def test_lock_timeout_and_stale_age_from_settings(tf, monkeypatch):
    svc = tf.make(_Client({"orchestration": {"terraform_lock_timeout_seconds": 300,
                                             "stale_lock_threshold_minutes": 45}}))
    assert svc.lock_timeout == "300s" and svc._lock_timeout_seconds() == 300.0
    assert svc.stale_lock_max_age_min == 45
    # the environment variable still wins (an install-time override)
    monkeypatch.setenv("TF_LOCK_TIMEOUT", "90s")
    monkeypatch.setenv("TF_STALE_LOCK_MAX_AGE_MINUTES", "30")
    assert svc.lock_timeout == "90s" and svc.stale_lock_max_age_min == 30
    # an explicit assignment wins over both
    svc.lock_timeout, svc.stale_lock_max_age_min = "12s", 7
    assert svc.lock_timeout == "12s" and svc.stale_lock_max_age_min == 7


@pytest.mark.parametrize("db", [None, MagicMock(), _Client(error=RuntimeError("down")),
                                _Client({"orchestration": {"terraform_lock_timeout_seconds": "x"}})])
def test_lock_settings_unreadable_are_todays_values(tf, db):
    svc = tf.make(db)
    assert svc.lock_timeout == "180s" and svc.stale_lock_max_age_min == 20


def test_stale_age_is_report_only(tf):
    """Wiring the age never breaks a lock: it only sets lock_info.is_stale in the STATE_LOCKED report."""
    src = open(os.path.join(TF_DIR, "service.py"), encoding="utf-8").read()
    uses = [m.start() for m in re.finditer(r"self\.stale_lock_max_age_min\b", src)]
    for at in uses:
        line = src[src.rfind("\n", 0, at) + 1: src.find("\n", at)]
        assert "parse_state_lock_info(" in line or "return" in line or "def " in line or "explicit" in line, line
    stderr = ("Error acquiring the state lock\nLock Info:\n  ID: 1\n  Who: a@b\n  Operation: OperationTypeApply\n"
              "  Created: 2000-01-01 00:00:00.0 UTC\n")
    assert tf.mod.TerraformService.parse_state_lock_info(stderr, max_age_minutes=45)["is_stale"] is True


# ================================================================================================ 4. Terraform versions
@pytest.mark.parametrize("version", ["1.5.7", "1.5.0", "1.4.6", "v1.5.7", "1.6.0", "1.7.5", "1.8.5", "1.9.0",
                                     "2.0.0", "v1.6.2"])
def test_terraform_version_accepted_matches_the_runtime_check(tf, version, monkeypatch, tmp_path):
    svc = tf.make(None)
    svc.tooling_dir = str(tmp_path)
    monkeypatch.setattr(tf.mod.shutil, "which", lambda cmd: "/bin/terraform")
    # RT14 RT D1: Terraform 1.5.7 has a pinned row now; never download in tests (offline -> EngineUnverifiable)
    monkeypatch.setattr(tf.mod._binary_checksums_module(), "fetch_to",
                        lambda *a, **k: (_ for _ in ()).throw(OSError("offline test")))
    try:
        svc._ensure_binary("TERRAFORM", version)
        runtime_ok = True
    except ValueError:
        runtime_ok = False
    except tf.mod.EngineUnverifiable:   # RT14-22: past the version check; refused later (no pinned checksum row)
        runtime_ok = True
    assert S.terraform_version_accepted(version) is runtime_ok


def test_supported_terraform_versions_are_runtime_accepted_only():
    assert S.OrchestrationSettings().supported_terraform_versions == ["1.5.7"]
    old = S.PlatformSettings(orchestration={"supported_terraform_versions": ["1.5.7", "1.7.5", "1.8.5", "1.9.0"]})
    assert old.orchestration.supported_terraform_versions == ["1.5.7"]
    assert S.OrchestrationSettings(supported_terraform_versions=["1.9.0"]).supported_terraform_versions == ["1.5.7"]
    # negative: an all-accepted list is unchanged, and the OpenTofu list is not filtered
    assert S.OrchestrationSettings(supported_terraform_versions=["1.4.6", "1.5.7"]).supported_terraform_versions == \
        ["1.4.6", "1.5.7"]
    assert S.OrchestrationSettings(supported_tofu_versions=["1.10.0"]).supported_tofu_versions == ["1.10.0"]
    assert "['1.5.7', '1.7.5', '1.8.5', '1.9.0']" not in DASHBOARD


def test_put_refuses_a_terraform_version_refused_at_run_time(cc_settings_routes, monkeypatch):
    _store(monkeypatch, {"version": 3})
    payload = S.PlatformSettings(orchestration={"terraform_version": "1.9.0"}, version=3)
    with pytest.raises(Exception) as ei:
        cc_settings_routes.rs.update_settings_api(payload, cc_settings_routes.request)
    assert ei.value.status_code == 422 and ei.value.detail["code"] == "TERRAFORM_VERSION_REFUSED"
    cc_settings_routes.doc_ref.set.assert_not_called()


# ================================================================================================ 5. Models
def test_no_silent_raise_of_max_output_tokens(monkeypatch):
    _store(monkeypatch, {"models": {"max_output_tokens": 8192, "developer_max_output_tokens": None}})
    s = S.get_platform_settings(project_id="p", strict=True)
    assert s.models.max_output_tokens == 8192 and s.models.get_developer_token_limit() == 8192


def test_cleared_architect_override_inherits_the_global_limit():
    m = S.AgentModelSettings(architect_max_output_tokens=None, max_output_tokens=32768)
    assert m.get_architect_token_limit() == 32768
    assert S.AgentModelSettings().get_architect_token_limit() == 16384                   # default unchanged
    assert S.AgentModelSettings(architect_max_output_tokens=4096).get_architect_token_limit() == 4096


def test_thinking_budget_of():
    assert S.thinking_budget_of(_ps(models={"default_thinking_budget": 512})) == 512
    for odd in (_ps(), MagicMock(), None, SimpleNamespace(models=SimpleNamespace(default_thinking_budget=True))):
        assert S.thinking_budget_of(odd) == 0


def test_thinking_budget_is_read_at_every_documented_call_site():
    for rel, needle in (("architect_agent/handler.py", "thinking_budget = thinking_budget_of(settings)"),
                        ("developer_agent/handler.py", "thinking_budget = thinking_budget_of(settings)"),
                        ("developer_agent/swarm_dispatcher.py", "thinking_budget = thinking_budget_of(settings)"),
                        ("developer_agent/lead_orchestrator.py", "thinking_budget = thinking_budget_of(p_settings)")):
        src = open(os.path.join(GW_DIR, rel), encoding="utf-8").read()
        assert needle in src, rel
        assert 'getattr(self, "thinking_budget", 0)' not in src, rel


def test_lead_and_junior_configs_unchanged_when_the_budget_is_zero(monkeypatch):
    """Do No Harm: with the default 0 the lead's config dict is exactly the one sent before (no thinking_config)."""
    if GW_DIR not in sys.path:
        monkeypatch.syspath_prepend(GW_DIR)
    from shared.gemini_model_config import thinking_config_for, Purpose
    types = SimpleNamespace(ThinkingConfig=lambda **k: ("TC", k))
    assert thinking_config_for("gemini-3.8-flash", 0, Purpose.DEVELOPER, types=types) is None
    assert thinking_config_for("gemini-3.8-flash", 512, Purpose.DEVELOPER, types=types) == \
        ("TC", {"thinking_budget": 512})


# ------------------------------------------------------------------ help texts state the model defaults
def _help_after(field):
    at = DASHBOARD.index(f'x-model.number="platformSettings.{field}"')
    return DASHBOARD[at: DASHBOARD.index("</p>", at)]


def test_help_texts_state_the_model_defaults():
    fin, orch, models = S.FinOpsSettings(), S.OrchestrationSettings(), S.AgentModelSettings()
    expected = {
        "finops.default_monthly_budget_usd": f"Default ${fin.default_monthly_budget_usd:g}",
        "finops.warning_threshold_pct": f"Default {fin.warning_threshold_pct:g}.",
        "finops.circuit_breaker_threshold_pct": f"Default {fin.circuit_breaker_threshold_pct:g}.",
        "orchestration.terraform_lock_timeout_seconds": f"Default {orch.terraform_lock_timeout_seconds}.",
        "orchestration.stale_lock_threshold_minutes": f"Default {orch.stale_lock_threshold_minutes}.",
        "orchestration.default_container_memory_mb": f"Default {orch.default_container_memory_mb}.",
        "orchestration.default_container_cpu": f"Default {orch.default_container_cpu} ",
        "models.max_output_tokens": f"Default {models.max_output_tokens:,}",
        "models.default_thinking_budget": f"Default {models.default_thinking_budget}:",
        "models.architect_max_output_tokens": f"Default {models.architect_max_output_tokens:,}",
        "models.developer_max_output_tokens": f"Default {models.developer_max_output_tokens:,}",
    }
    for field, text in expected.items():
        assert text in _help_after(field), (field, text)
    assert "Default token ceiling (16,384" not in DASHBOARD
    assert f"Default {orch.terraform_version}." in DASHBOARD


def test_settings_reference_states_the_model_defaults_and_drops_the_fixed_gaps():
    models = S.AgentModelSettings()
    assert f"`models.max_output_tokens`, {models.max_output_tokens}" in SETTINGS_REF
    gaps = SETTINGS_REF[SETTINGS_REF.index("## Known gaps between the page and the platform"):]
    for gone in ("*Warning Threshold*", "*Circuit Breaker*", "*Terraform Lock Timeout*", "1.7.5, 1.8.5 and 1.9.0",
                 "*Thinking Budget*", "raised to 65,536", "**Config Version** is a counter"):
        assert gone not in gaps, gone
    assert "**Config Version** is a counter, not a lock" not in SETTINGS_REF


# ================================================================================================ 7. Config Version
def test_stale_config_version_is_409_and_nothing_is_written(cc_settings_routes, monkeypatch):
    _store(monkeypatch, {"version": 5, "finops": {"default_monthly_budget_usd": 60.0}})
    payload = S.PlatformSettings(finops={"default_monthly_budget_usd": 90.0}, version=4)
    with pytest.raises(Exception) as ei:
        cc_settings_routes.rs.update_settings_api(payload, cc_settings_routes.request)
    assert ei.value.status_code == 409
    assert ei.value.detail["code"] == "SETTINGS_VERSION_CONFLICT" and ei.value.detail["stored_version"] == 5
    assert "changed by someone else" in ei.value.detail["message"]
    cc_settings_routes.doc_ref.set.assert_not_called()


def test_current_config_version_saves_and_increments(cc_settings_routes, monkeypatch):
    _store(monkeypatch, {"version": 5})
    payload = S.PlatformSettings(finops={"default_monthly_budget_usd": 90.0}, version=5)
    out = cc_settings_routes.rs.update_settings_api(payload, cc_settings_routes.request)
    assert out.version == 6
    cc_settings_routes.doc_ref.set.assert_called_once()


def test_a_body_without_a_version_is_not_checked(cc_settings_routes, monkeypatch):
    """API callers that PUT the whole document without `version` keep working (the page always sends it)."""
    _store(monkeypatch, {"version": 9})
    out = cc_settings_routes.rs.update_settings_api(S.PlatformSettings(), cc_settings_routes.request)
    assert out.version == 10


def test_a_directive_change_moves_config_version(cc_settings_routes):
    """The Multi-Agent Pipeline directive endpoints store the settings document too: Config Version moves, so a page
    loaded before the directive change gets 409 instead of silently dropping it."""
    ae, ref = cc_settings_routes.ae, cc_settings_routes.doc_ref
    ref.get.side_effect = None   # the directive endpoints read the raw document themselves
    ref.get.return_value = SimpleNamespace(exists=True, to_dict=lambda: {"version": 4,
                                                                        "models": {"custom_directives": {}}})
    ae.apply_prompt_directive("ARCHITECT_AGENT", ae.ApplyDirectiveRequest(directive="Prefer Cloud Run"), None)
    (stored,), _ = ref.set.call_args
    assert stored["version"] == 5
    assert stored["models"]["custom_directives"] == {"ARCHITECT_AGENT": ["Prefer Cloud Run"]}


def test_ui_shows_the_conflict_and_offers_reload():
    assert "settingsVersionConflict" in DASHBOARD and "res.status === 409" in DASHBOARD
    assert "Settings were changed by someone else" in DASHBOARD
    banner = DASHBOARD[DASHBOARD.index('<template x-if="settingsVersionConflict">'):]
    assert "fetchPlatformSettings(true)" in banner[:800]


def test_repeated_warning_notifications_upsert_one_alert_per_period(monkeypatch):
    """RT F1: Cloud Billing re-sends notifications several times a day; billing_alerts must not grow per notification."""
    db = _AlertDB(WL, {})
    october = {"costIntervalStart": "2026-10-01T07:00:00Z"}
    _alert(monkeypatch, 85.0, WL, db=db, extra=october)
    _alert(monkeypatch, 88.0, WL, db=db, extra=october)
    assert list(db.alerts) == ["budget-warning-shop-app-2026-10"]
    assert db.alerts["budget-warning-shop-app-2026-10"]["spend_amount"] == 88.0   # the latest spend
    _alert(monkeypatch, 82.0, WL, db=db, extra={"costIntervalStart": "2026-11-01T07:00:00Z"})
    assert sorted(db.alerts) == ["budget-warning-shop-app-2026-10", "budget-warning-shop-app-2026-11"]


def test_billing_period_parse(monkeypatch):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    from routes import finops as fr
    assert fr._billing_period({"costIntervalStart": "2026-10-01T07:00:00Z"}) == "2026-10"
    assert fr._billing_period({"costIntervalStart": "2026-09-01T00:00:00-07:00"}) == "2026-09"
    for odd in ({}, {"costIntervalStart": "garbage"}, {"costIntervalStart": 5}):
        assert re.fullmatch(r"\d{4}-\d{2}", fr._billing_period(odd))


def test_directive_write_invalidates_the_settings_cache_and_the_page_reloads_with_force(cc_settings_routes):
    """RT F3: after a directive change the same admin's next GET sees the new version (no false 409)."""
    ae, ref = cc_settings_routes.ae, cc_settings_routes.doc_ref
    S._SETTINGS_CACHE, S._LAST_FETCH_TIME = S.PlatformSettings(version=4), float("inf")
    ref.get.side_effect = None
    ref.get.return_value = SimpleNamespace(exists=True, to_dict=lambda: {"version": 4})
    ae.apply_prompt_directive("ARCHITECT_AGENT", ae.ApplyDirectiveRequest(directive="Prefer Cloud Run"), None)
    assert S._SETTINGS_CACHE is None
    handlers = [m.start() for m in re.finditer(r"/api/platform/agents/\$\{encodeURIComponent\(\w+\)\}/directives",
                                               DASHBOARD)]
    assert len(handlers) == 3
    for at in handlers:
        tail = DASHBOARD[at: at + 1500]
        assert "await this.fetchPlatformSettings(true);" in tail.split("catch (e)")[0], tail[:200]


def test_ensure_binary_has_one_version_parse(tf, monkeypatch):
    """RT F4: _ensure_binary uses shared.settings.terraform_version_accepted (no IndexError on "1")."""
    src = open(os.path.join(TF_DIR, "service.py"), encoding="utf-8").read()
    assert "terraform_version_accepted(target_version)" in src and "parts[1] >= 6" not in src
    svc = tf.make(None)
    svc.tooling_dir = "/nonexistent"
    monkeypatch.setattr(tf.mod.shutil, "which", lambda cmd: "/bin/terraform")
    # RT14-22: "1" passes the version check; the PATH binary is never used and no checksum row exists -> typed refusal
    with pytest.raises(tf.mod.EngineUnverifiable):
        svc._ensure_binary("TERRAFORM", "1")
    with pytest.raises(ValueError):
        svc._ensure_binary("TERRAFORM", "1.6")


def test_put_empty_terraform_version_message(cc_settings_routes, monkeypatch):
    _store(monkeypatch, {"version": 3})
    payload = S.PlatformSettings(orchestration={"terraform_version": ""}, version=3)
    with pytest.raises(Exception) as ei:
        cc_settings_routes.rs.update_settings_api(payload, cc_settings_routes.request)
    assert ei.value.status_code == 422 and ei.value.detail["message"] == "No Terraform version is selected. Choose 1.5.7."


def test_lock_settings_are_memoized_per_ttl(tf, monkeypatch, caplog):
    """RT F5: one Firestore read per setting per TTL; an unreadable store is logged at most once per TTL."""
    client = _Client({"orchestration": {"terraform_lock_timeout_seconds": 300}})
    svc = tf.make(client)
    for _ in range(5):
        assert svc.lock_timeout == "300s"
    assert client.reads == 1
    svc._orchestration_setting_cache["terraform_lock_timeout_seconds"] = ("300s-old", -1e9)   # expired
    assert svc.lock_timeout == "300s" and client.reads == 2
    down = tf.make(_Client(error=RuntimeError("down")))
    with caplog.at_level("ERROR"):
        for _ in range(5):
            assert down.lock_timeout == "180s"
    assert sum("could not be read" in r.getMessage() for r in caplog.records) == 1


def test_reserved_thinking_tokens_only_for_budget_family(monkeypatch):
    """RT F6: a thinking-level model (Argon) never receives the budget, so none of its output room is reserved."""
    if GW_DIR not in sys.path:
        monkeypatch.syspath_prepend(GW_DIR)
    from architect_agent import handler as ah
    from developer_agent import handler as dh
    for mod in (ah, dh):
        assert mod._reserved_thinking_tokens("gemini-4-argon", 512) == 0
        assert mod._reserved_thinking_tokens("gemini-3.8-flash", 512) == 512
        assert mod._reserved_thinking_tokens("gemini-3.8-flash", 0) == 0
