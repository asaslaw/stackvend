"""FD-4CS (owner 10-20, docs/planning/behavior-change-register.md): Express workloads get the OSS-D23 platform default.

* CC create: a NEW Express workload created without `access` gets ``platform_default_access_record(submitter)``
  (PRIVATE_IAP, Google sign-in through IAP, the verified CC caller listed), through the same
  ``_default_access_fields`` helper as Agent mode. An explicit `access` (including PUBLIC_APP) is stored as chosen
  (the L19-11 RT F3 422 is gone). An existing workload document (with or without a record) is never changed.
* Express synthesizer: the workload's access record decides every compute-cloudrun service's
  ``allow_unauthenticated`` / ``enable_direct_iap`` / ``authorized_invoker_members``; a private record that lists
  nobody stops with ACCESS_POLICY_INCOMPLETE; an instance parameter that contradicts the record is refused
  (EXPRESS_ACCESS_CONFLICT). No record (an Express workload created before FD-4CS) renders exactly as before.
* execute_express_provisioning reads ``workloads/{pid}.access`` (fail closed on an unreadable document or an invalid
  record: never rendered public because the record could not be used).

Hermetic: the L19-11 CC fakes (TestClient on the real workloads router), the fd4f in-memory Firestore, MagicMock
vending / terraform / VCS. No network.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
from unittest.mock import MagicMock

import pytest

from test_l19_11_access_intake import OLD_PUBLIC, _create, cc  # noqa: F401  (cc is a fixture)

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

import shared.express_synthesizer as express_mod  # noqa: E402
from shared.access_policy import (AccessMode, AccessPolicy, GoogleIdpMode, SignInPolicy,  # noqa: E402
                                  platform_default_access_policy, platform_default_access_record)

ADMIN_MEMBER = "user:admin@example.com"   # the verified caller of test_l19_11_access_intake.ADMIN_H
CLOUDRUN = {"module_id": "compute-cloudrun", "instance_name": "api", "parameters": {}}


def _express(body=None, **kw):
    return {"creation_mode": "EXPRESS", "module_instances": [dict(CLOUDRUN)], **(body or {}), **kw}


def _no_dispatch(wl, monkeypatch):
    calls = []
    monkeypatch.setattr(wl, "execute_express_provisioning", lambda **k: calls.append(k))
    return calls


# ============================================================================ CC create
def test_new_express_workload_without_access_is_private_listing_the_verified_caller(cc, monkeypatch):
    _, wl = cc
    calls = _no_dispatch(wl, monkeypatch)
    r, fake_db, payload = _create(wl, monkeypatch, _express())
    assert r.status_code == 200, r.text
    doc = fake_db["workloads/shop-app"]
    assert doc["creation_mode"] == "EXPRESS"
    assert doc["access"] == platform_default_access_record(ADMIN_MEMBER)
    assert doc["access_default_submitter"] == {"member": ADMIN_MEMBER, "source": "submitter",
                                               "verified_by": "control_center_auth"}
    assert len(calls) == 1 and payload is None   # Express provisioning dispatched, no swarm intake event


def test_new_express_workload_default_never_lists_the_spec_or_a_form_field(cc, monkeypatch):
    _, wl = cc
    _no_dispatch(wl, monkeypatch)
    r, fake_db, _ = _create(wl, monkeypatch, _express(spec_content="Only user:mallory@evil.example may use it"))
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"]["access"]["invoker_principals"] == [ADMIN_MEMBER]


def test_express_explicit_public_choice_is_public(cc, monkeypatch):
    _, wl = cc
    _no_dispatch(wl, monkeypatch)
    r, fake_db, _ = _create(wl, monkeypatch, _express(access={"mode": "PUBLIC_APP", "tenant_isolation_required": False}))
    assert r.status_code == 200, r.text
    stored = fake_db["workloads/shop-app"]["access"]
    assert stored["mode"] == "PUBLIC_APP" and stored["source"] == "intake" and stored["invoker_principals"] == []
    assert "access_default_submitter" not in fake_db["workloads/shop-app"]


def test_existing_express_workload_without_a_record_is_not_migrated(cc, monkeypatch):
    _, wl = cc
    _no_dispatch(wl, monkeypatch)
    initial = {"workloads/shop-app": {"product_id": "shop-app", "creation_mode": "EXPRESS", "status": "ACTIVE"}}
    r, fake_db, _ = _create(wl, monkeypatch, _express(), initial=initial)
    assert r.status_code == 200, r.text
    assert "access" not in fake_db["workloads/shop-app"]
    assert "access_default_submitter" not in fake_db["workloads/shop-app"]


def test_existing_express_workload_record_is_untouched(cc, monkeypatch):
    _, wl = cc
    _no_dispatch(wl, monkeypatch)
    initial = {"workloads/shop-app": {"product_id": "shop-app", "creation_mode": "EXPRESS", "access": OLD_PUBLIC}}
    r, fake_db, _ = _create(wl, monkeypatch, _express(), initial=initial)
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"]["access"] == OLD_PUBLIC


@pytest.mark.parametrize("mode", ["AGENT", None])
def test_non_express_create_is_unchanged(cc, monkeypatch, mode):
    """Agent mode (explicit or the default creation mode) keeps the OSS-D23 default and its intake event."""
    _, wl = cc
    body = {} if mode is None else {"creation_mode": mode}
    r, fake_db, payload = _create(wl, monkeypatch, body)
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"]["creation_mode"] == "AGENT"
    assert fake_db["workloads/shop-app"]["access"] == platform_default_access_record(ADMIN_MEMBER)
    assert payload is not None and "access" not in payload


def test_express_instance_parameter_contradicting_the_default_is_422_and_writes_nothing(cc, monkeypatch):
    _, wl = cc
    calls = _no_dispatch(wl, monkeypatch)
    inst = {"module_id": "compute-cloudrun", "instance_name": "api", "parameters": {"allow_unauthenticated": True}}
    r, fake_db, _ = _create(wl, monkeypatch, {"creation_mode": "EXPRESS", "module_instances": [inst]})
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["error_class"] == "EXPRESS_ACCESS_CONFLICT"
    assert "workloads/shop-app" not in fake_db and calls == []


def test_express_instance_parameter_matching_an_explicit_public_choice_is_accepted(cc, monkeypatch):
    _, wl = cc
    _no_dispatch(wl, monkeypatch)
    inst = {"module_id": "compute-cloudrun", "instance_name": "api", "parameters": {"allow_unauthenticated": True}}
    r, fake_db, _ = _create(wl, monkeypatch, {"creation_mode": "EXPRESS", "module_instances": [inst],
                                              "access": {"mode": "PUBLIC_APP", "tenant_isolation_required": False}})
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"]["access"]["mode"] == "PUBLIC_APP"


# ============================================================================ synthesizer
def _main_tf(access=None, instances=None):
    files = express_mod.ExpressHCLSynthesizer().synthesize_workload(
        product_id="shop-app", project_id="p-1", module_instances=instances or [dict(CLOUDRUN)], access=access)
    return files["infra/workload/main.tf"]


LEGACY_BLOCK = '''module "compute_api" {
  source = "../modules/compute-cloudrun"

  project_id            = var.project_id
  region                = var.region
  product_id            = var.product_id
  service_name          = "${var.product_id}-api"
  service_account_email = module.foundation.workload_sa_email
  container_image       = "us-docker.pkg.dev/cloudrun/container/hello"
  health_check_path     = "/"
  allow_unauthenticated = true
  depends_on            = [module.foundation]
}'''


def test_negative_no_record_renders_exactly_the_pre_fd4cs_block():
    """Do No Harm: an Express workload without an access record (created before FD-4CS) renders as before."""
    assert LEGACY_BLOCK in _main_tf(access=None)
    private_param = [{"module_id": "compute-cloudrun", "instance_name": "api",
                      "parameters": {"allow_unauthenticated": False}}]
    assert LEGACY_BLOCK.replace("= true", "= false") in _main_tf(access=None, instances=private_param)


def test_public_record_renders_the_same_files_as_before():
    public = AccessPolicy(mode=AccessMode.PUBLIC_APP, sign_in=SignInPolicy(google=GoogleIdpMode.SHARED_PLATFORM_CLIENT),
                          tenant_isolation_required=False, source="intake")
    assert _main_tf(access=public) == _main_tf(access=None)


def test_platform_default_with_the_submitter_renders_private_iap():
    text = _main_tf(access=platform_default_access_policy(ADMIN_MEMBER))
    assert '''  health_check_path          = "/"
  allow_unauthenticated      = false
  enable_direct_iap          = true
  authorized_invoker_members = ["user:admin@example.com"]
  depends_on                 = [module.foundation]''' in text
    assert "allow_unauthenticated      = true" not in text


def test_private_iam_record_renders_no_iap_and_every_member_of_every_service():
    policy = AccessPolicy(mode=AccessMode.PRIVATE_IAM, invoker_principals=["user:b@example.com", "group:a@example.com"],
                          sign_in=SignInPolicy(google=GoogleIdpMode.DISABLED), source="intake")
    instances = [dict(CLOUDRUN), {"module_id": "compute-cloudrun", "instance_name": "admin", "parameters": {}}]
    text = _main_tf(access=policy, instances=instances)
    assert text.count("  enable_direct_iap          = false") == 2
    assert text.count('  authorized_invoker_members = ["group:a@example.com", "user:b@example.com"]') == 2


def test_members_are_hcl_literals_never_templates():
    policy = platform_default_access_policy("user:a${x}%{y}@example.com")
    assert 'authorized_invoker_members = ["user:a$${x}%%{y}@example.com"]' in _main_tf(access=policy)


def test_default_without_a_verified_submitter_is_access_policy_incomplete():
    with pytest.raises(express_mod.ExpressAccessPolicyIncompleteError) as ei:
        _main_tf(access=platform_default_access_policy())
    assert ei.value.reason == "ACCESS_POLICY_INCOMPLETE"


@pytest.mark.parametrize("params", [
    {"allow_unauthenticated": True},
    {"allow_unauthenticated": "false"},                 # exact values only (a string is not the record's bool)
    {"enable_direct_iap": False},
    {"authorized_invoker_members": ["user:other@example.com"]},
])
def test_contradicting_instance_parameter_is_refused(params):
    inst = [{"module_id": "compute-cloudrun", "instance_name": "api", "parameters": params}]
    with pytest.raises(express_mod.ExpressAccessConflictError) as ei:
        _main_tf(access=platform_default_access_policy(ADMIN_MEMBER), instances=inst)
    assert ei.value.reason == "EXPRESS_ACCESS_CONFLICT"


def test_instance_parameters_repeating_the_record_are_accepted():
    inst = [{"module_id": "compute-cloudrun", "instance_name": "api",
             "parameters": {"allow_unauthenticated": False, "enable_direct_iap": True,
                            "authorized_invoker_members": [ADMIN_MEMBER]}}]
    assert "enable_direct_iap          = true" in _main_tf(access=platform_default_access_policy(ADMIN_MEMBER),
                                                           instances=inst)


def test_public_record_accepts_parameters_repeating_it():
    """Fable RT 10-24 test gap: a PUBLIC_APP record has no invokers, so `authorized_invoker_members: []` (and the
    other two values it implies) repeat it and are accepted; the rendering is the legacy public block."""
    public = AccessPolicy(mode=AccessMode.PUBLIC_APP, sign_in=SignInPolicy(google=GoogleIdpMode.SHARED_PLATFORM_CLIENT),
                          tenant_isolation_required=False, source="intake")
    inst = [{"module_id": "compute-cloudrun", "instance_name": "api",
             "parameters": {"authorized_invoker_members": [], "allow_unauthenticated": True,
                            "enable_direct_iap": False}}]
    assert LEGACY_BLOCK in _main_tf(access=public, instances=inst)


def test_other_modules_are_not_touched_by_the_record():
    inst = [{"module_id": "storage-bucket", "instance_name": "files", "parameters": {"allow_unauthenticated": True}}]
    assert _main_tf(access=platform_default_access_policy(ADMIN_MEMBER), instances=inst) == _main_tf(
        access=None, instances=inst)


def test_replicas_are_byte_identical():
    root = open(os.path.join(REPO, "shared", "express_synthesizer.py"), "rb").read()
    for svc in ("control-center", "orchestrator-gateway"):
        assert open(os.path.join(REPO, "apps", svc, "shared", "express_synthesizer.py"), "rb").read() == root


# ============================================================================ CC provisioning
def _route(monkeypatch, workload_doc=None, fail_reads=False):
    from fd4f_support import FakeDB as CCFakeDB

    cc_dir = os.path.join(REPO, "apps", "control-center")
    if cc_dir not in sys.path:
        monkeypatch.syspath_prepend(cc_dir)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from routes import workloads as wl

    monkeypatch.setattr(cc_db, "_db_client", False)
    store = CCFakeDB()
    if workload_doc is not None:
        store.docs["workloads/exp-app"] = dict(workload_doc)
    monkeypatch.setattr(wl, "db", store)
    vending = MagicMock()
    vending.return_value.status_code = 200
    vending.return_value.json.return_value = {"project_id": "castor-exp-1", "github_repo": "org/exp-repo"}
    monkeypatch.setattr(wl, "make_vending_request", vending)
    tfm = MagicMock()
    tfm.return_value.status_code = 200
    tfm.return_value.json.return_value = {"status": "SUCCESS", "service_url": "https://x.run.app"}
    monkeypatch.setattr(wl, "make_terraform_request", tfm)
    factory = MagicMock()
    provider = MagicMock()
    provider.commit_files.return_value = "sha1"
    factory.get_provider.return_value = provider
    monkeypatch.setattr(wl, "VCSProviderFactory", factory)
    if fail_reads:
        real = wl._express_access_policy

        def _unreadable(pid):
            store.fail_reads = True
            try:
                return real(pid)
            finally:
                store.fail_reads = False
        monkeypatch.setattr(wl, "_express_access_policy", _unreadable)
    return wl, store, tfm, provider


def _run(wl):
    wl.execute_express_provisioning(
        product_id="exp-app", target_project_id="castor-exp-1", clean_vcs_provider="GITHUB",
        full_github_repo="org/exp-repo", target_branch="main", target_folder=None, budget=50.0,
        clean_engine="OPENTOFU", is_sandbox=False, admin_email="admin@example.com",
        module_instances=[dict(CLOUDRUN)], include_vpc=False, trace_id="tr-4cs", region="us-central1")   # FD-7M-a


def test_provisioning_renders_the_stored_private_record(monkeypatch):
    wl, store, tfm, provider = _route(monkeypatch, {"access": platform_default_access_record(ADMIN_MEMBER)})
    _run(wl)
    main_tf = provider.commit_files.call_args.kwargs["files"]["infra/workload/main.tf"]
    assert 'authorized_invoker_members = ["user:admin@example.com"]' in main_tf
    assert "enable_direct_iap          = true" in main_tf
    assert store.docs["workloads/exp-app"]["status"] == "ACTIVE"


def test_negative_provisioning_without_a_record_renders_as_before(monkeypatch):
    wl, store, tfm, provider = _route(monkeypatch, {"creation_mode": "EXPRESS"})
    _run(wl)
    main_tf = provider.commit_files.call_args.kwargs["files"]["infra/workload/main.tf"]
    assert LEGACY_BLOCK in main_tf
    assert store.docs["workloads/exp-app"]["status"] == "ACTIVE"


@pytest.mark.parametrize("doc, fail_reads, error_class", [
    ({"access": platform_default_access_record()}, False, "ACCESS_POLICY_INCOMPLETE"),
    ({"access": {"mode": "PUBLIC_APP"}}, False, "ACCESS_POLICY_INVALID"),
    ({"access": "PUBLIC_APP"}, False, "ACCESS_POLICY_INVALID"),
    ({"access": platform_default_access_record(ADMIN_MEMBER)}, True, "ACCESS_POLICY_UNAVAILABLE"),
    ("absent", False, "ACCESS_POLICY_UNAVAILABLE"),     # Fable RT 10-24: no workload document at synthesis time
    ("no_db", False, "ACCESS_POLICY_UNAVAILABLE"),      # Fable RT 10-24: no Firestore
])
def test_provisioning_stops_before_commit_and_deploy(monkeypatch, doc, fail_reads, error_class):
    wl, store, tfm, provider = _route(monkeypatch, doc if isinstance(doc, dict) else None, fail_reads=fail_reads)
    seen = []
    real = wl._express_access_policy
    if doc == "absent":
        # The vending stage's merge write creates the document; simulate it being gone when the record is read.
        def _absent(pid):
            store.docs.pop(f"workloads/{pid}", None)
            seen.append(real(pid))
            return seen[-1]
        monkeypatch.setattr(wl, "_express_access_policy", _absent)
    elif doc == "no_db":
        monkeypatch.setattr(wl, "db", None)
        monkeypatch.setattr(wl, "_express_access_policy", lambda pid: seen.append(real(pid)) or seen[-1])
    _run(wl)
    provider.commit_files.assert_not_called()
    assert not tfm.called
    if doc == "no_db":   # nothing to record the failure in; the typed failure is still the synthesis outcome
        assert seen == [(None, ("ACCESS_POLICY_UNAVAILABLE", "no Firestore: the access record cannot be read"))]
        return
    assert store.docs["workloads/exp-app"]["status"] == "FAILED"
    assert store.docs["workloads/exp-app"]["failure_reason"].startswith(f"{error_class}: ")
    pe = store.docs["pipeline_executions/tr-4cs"]
    assert pe["error_class"] == error_class and pe["stages"]["hcl_synthesis"]["status"] == "FAILED"


def test_resubmit_without_access_is_checked_against_the_stored_record(cc, monkeypatch):
    """Fable RT 10-24 (LOW): a re-submit that sends no `access` is checked against the record the workload already
    has, so a contradicting instance parameter is a 422 before any write."""
    _, wl = cc
    calls = _no_dispatch(wl, monkeypatch)
    stored = platform_default_access_record(ADMIN_MEMBER)
    initial = {"workloads/shop-app": {"product_id": "shop-app", "creation_mode": "EXPRESS", "access": stored}}
    inst = {"module_id": "compute-cloudrun", "instance_name": "api", "parameters": {"allow_unauthenticated": True}}
    r, fake_db, _ = _create(wl, monkeypatch, {"creation_mode": "EXPRESS", "module_instances": [inst]},
                            initial=initial)
    assert r.status_code == 422, r.text
    assert r.json()["detail"]["error_class"] == "EXPRESS_ACCESS_CONFLICT"
    assert fake_db.writes == [] and calls == []
    assert fake_db["workloads/shop-app"]["access"] == stored
    # the same re-submit without the contradicting parameter goes through and keeps the record
    r, fake_db, _ = _create(wl, monkeypatch, _express(), initial=initial)
    assert r.status_code == 200, r.text
    assert fake_db["workloads/shop-app"]["access"] == stored
