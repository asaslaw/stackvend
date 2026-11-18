"""
FD-7L Phase 1, vending side (apps/project-vending/runner_broker.py + vending.py + main.py). Hermetic fakes only.

* PLATFORM ("Shared", mode unset): a vend's steps and outputs are unchanged and the broker routes are inert.
* PER_WORKLOAD: the vend-order ensure_* steps after billing and API enablement, idempotent on re-vend and retry, typed
  failures, add-only IAM, a signed provenance record; the broker: caller allow-lists, signed records, a single-use
  nonce bound to one execution and one product, the redeem window, session keys, no token for another product.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import copy
import logging
import os
import re
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient

import destructive_guard_fakes as f
import fd7l_fakes as k
from test_destructive_guard_vending import (  # noqa: F401  (fixtures)
    VENDING_MAIN, _vend_crm, _vend_engine, vmain, _freeze_setting_without_firestore,
)

_G = VENDING_MAIN.ProjectRepoVendingEngine.vend_gcp_project.__globals__
rb = _G["rb"]
ri = _G["ri"]
VDG = _G["dg"]
VendingFailure = _G["VendingFailure"]

AUD = "https://project-repo-vending-service-999000999000.us-central1.run.app"
PID, PROJECT, NUMBER = f.PID, f.PROJECT, f.NUMBER
DEPLOYER = f"stackvend-deployer@{PROJECT}.iam.gserviceaccount.com"
BUCKET = f"{PROJECT}-tfstate"
CALLBACK = "https://workflowexecutions.googleapis.com/v1/projects/p/locations/r/workflows/w/executions/e/callbacks/c"


# ---------------------------------------------------------------------------------------------- world
def _env(mode="PER_WORKLOAD", **env):
    base = {"PROJECT_ID": k.HOST, ri.MODE_ENV: mode,
            ri.RUNNER_MEMBERS_ENV: f"{k.DEVELOPER},{k.RUNNER_SA}", ri.SERVER_MEMBERS_ENV: f"{k.DEVELOPER},{k.SERVER_SA}"}
    base.update(env)
    return base


def _config(mode="PER_WORKLOAD", **env):
    return rb.BrokerConfig.from_env({key: v for key, v in _env(mode, **env).items() if v is not None})


class World:
    def __init__(self, mode="PER_WORKLOAD", runtime=k.BROKER, signer_key=k.BROKER_KEY, **env):
        self.db, self.crm = f.make_world()
        self.crm.projects[NUMBER]["labels"]["stackvend-workload-type"] = "standard"
        self.ctx = f.make_ctx(self.db, self.crm)
        self.google = k.FakeGoogle()
        self.iam = k.FakeProjectIAM()
        self.clock_now = [f.NOW]
        self.slept = []
        self.env = _env(mode, **env)
        self.store = TestRunnerStore(self.db, self.db)
        self.deps = rb.RunnerDeps(
            config=_config(mode, **env), rest=self.google, project_iam=self.iam, store=self.store,
            certs=k.certs_for(), runtime_email=lambda: runtime, region=lambda: k.REGION,
            guard_context=lambda: self.ctx, signer_factory=lambda email: signer_key.sign,
            clock=lambda: self.clock_now[0], sleep=self.slept.append,
            github_repo_token=self._gh)
        self.gh_calls = []

    def _gh(self, full_name, repo_id):
        self.gh_calls.append((full_name, repo_id))
        return {"token": "ghs_repo_read_token", "expires_at": "2026-10-31T13:00:00Z"}

    def prov(self, pid=PID):
        return self.db.doc(f"workload_provenance/{pid}")

    def runner_record(self, pid=PID):
        return (self.prov(pid) or {}).get("runner_identity")

    def provisioner(self):
        return rb.RunnerIdentityProvisioner(self.deps)

    def broker(self):
        return rb.RunnerBroker(self.deps)

    def ensure(self, **kw):
        args = dict(product_id=PID, project_id=PROJECT, project_number=NUMBER, region=k.REGION)
        args.update(kw)
        return self.provisioner().ensure(**args)


class TestRunnerStore(rb.RunnerStore):
    __test__ = False

    def _run_in_transaction(self, body):
        body(f.FakeTxn(self.guard_db))


@pytest.fixture
def w():
    return World()


def _code(excinfo):
    return excinfo.value.code if hasattr(excinfo.value, "code") else excinfo.value.error_class


# ---------------------------------------------------------------------------------------------- persona ids
def test_persona_account_ids_exist_in_platform_terraform():
    tf = "".join(open(os.path.join(f.REPO_ROOT, "infra", "platform", n)).read()
                 for n in os.listdir(os.path.join(f.REPO_ROOT, "infra", "platform")) if n.endswith(".tf"))
    for account in (rb.DEVELOPER_ACCOUNT_ID, rb.PROVISIONER_ACCOUNT_ID, rb.CONTROL_CENTER_ACCOUNT_ID):
        assert f'"{account}"' in tf, account


def test_no_region_literal_in_the_new_vending_code():
    src = open(os.path.join(f.REPO_ROOT, "apps", "project-vending", "runner_broker.py")).read()
    assert not re.search(r"\b(us|europe|asia|northamerica|southamerica|australia|me|africa)-[a-z]+\d\b", src)


# ---------------------------------------------------------------------------------------------- provisioner
def test_ensure_creates_everything_in_order_and_signs_a_ready_record(w):
    rec = w.ensure()
    assert rec["status"] == "READY" and rec["deployer_email"] == DEPLOYER and rec["state_bucket"] == BUCKET
    kinds = [line.split(" ")[1].split("/")[2] for line in w.google.log]
    first = {kind: kinds.index(kind) for kind in reversed(kinds)}
    assert first["serviceusage.googleapis.com"] < first["iam.googleapis.com"] < first["storage.googleapis.com"]
    # owner grant (project IAM) happened between the SA create and the bucket
    assert [c[0] for c in w.iam.calls] == ["get", "set"]
    stored = w.runner_record()
    verified = ri.verify_record(ri.provenance_doc_path(PID), stored, expected_signer=k.BROKER, certs=k.certs_for())
    ri.check_runner_identity(verified, product_id=PID, project_id=PROJECT, project_number=NUMBER)
    bucket = w.google.buckets[BUCKET]
    assert bucket["location"] == k.REGION and bucket["projectNumber"] == NUMBER
    assert bucket["iamConfiguration"] == {"uniformBucketLevelAccess": {"enabled": True},
                                          "publicAccessPrevention": "enforced"}
    assert bucket["versioning"] == {"enabled": True}
    policy = w.google.bucket_iam[BUCKET]
    roles = {(b["role"], m) for b in policy["bindings"] for m in b["members"]}
    assert ("roles/storage.objectAdmin", f"serviceAccount:{DEPLOYER}") in roles
    assert ("roles/storage.objectViewer", f"serviceAccount:{k.BROKER}") in roles
    assert ("roles/storage.objectViewer", f"serviceAccount:{k.CC}") in roles
    assert ("roles/storage.legacyBucketOwner", f"projectOwner:{NUMBER}") in roles   # kept (add-only)
    assert w.google.sa_policies[DEPLOYER]["bindings"] == [
        {"role": "roles/iam.serviceAccountTokenCreator", "members": [f"serviceAccount:{k.BROKER}"]}]


def test_owner_grant_is_add_only(w):
    before = copy.deepcopy(w.iam._policy(PROJECT))
    w.ensure()
    [(_, _, after)] = w.iam.sets()
    assert after["etag"] == before["etag"] and after["version"] == 3
    for b in before["bindings"]:
        if b.get("condition") or b["role"] != "roles/owner":
            assert b in after["bindings"]
    owner = [b for b in after["bindings"] if b["role"] == "roles/owner" and not b.get("condition")]
    assert owner == [{"role": "roles/owner", "members": [f"serviceAccount:{k.DEVELOPER}",
                                                         f"serviceAccount:{DEPLOYER}"]}]
    assert len(after["bindings"]) == len(before["bindings"])


def test_ensure_is_idempotent_on_re_vend(w):
    first = w.ensure()
    w.google.calls.clear()
    w.iam.calls.clear()
    second = w.ensure()
    assert second["state_bucket"] == first["state_bucket"]
    assert w.iam.sets() == []
    mutating = w.google.mutating()
    # the only POST is the SA create that answers 409 (adopted); no IAM write, no bucket create
    assert mutating == [("POST", f"https://iam.googleapis.com/v1/projects/{PROJECT}/serviceAccounts")]


def test_recorded_suffixed_bucket_is_reused(w):
    w.google.foreign.add(BUCKET)
    first = w.ensure()
    assert first["state_bucket"].startswith(BUCKET + "-") and ri.is_state_bucket_name_for(PROJECT,
                                                                                         first["state_bucket"])
    w.google.calls.clear()
    assert w.ensure()["state_bucket"] == first["state_bucket"]
    assert not any(m == "POST" and u.endswith("/storage/v1/b") for m, u in w.google.mutating())


def test_both_bucket_names_taken_is_typed(w, monkeypatch):
    w.google.foreign.add(BUCKET)
    monkeypatch.setattr(ri, "random_bucket_suffix", lambda: "abcdef")
    w.google.foreign.add(f"{BUCKET}-abcdef")
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.ensure()
    assert _code(e) == "VENDING.STATE_BUCKET_NAME_TAKEN"


def test_existing_own_bucket_without_versioning_is_refused_not_changed(w):
    w.google.buckets[BUCKET] = {"name": BUCKET, "projectNumber": NUMBER, "versioning": {"enabled": False},
                                "iamConfiguration": k.GOOD_BUCKET["iamConfiguration"]}
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.ensure()
    assert _code(e) == "VENDING.STATE_BUCKET_FAILED"
    assert w.google.buckets[BUCKET]["versioning"] == {"enabled": False}
    assert not any(u.endswith("/iam") for m, u in w.google.mutating())


@pytest.mark.parametrize("fail_key,statuses,code", [
    ("sa_create", [403], "VENDING.DEPLOYER_SA_FAILED"),
    ("sa_set", [403], "VENDING.BROKER_GRANT_FAILED"),
    ("bucket_create", [403], "VENDING.STATE_BUCKET_FAILED"),
    ("bucket_iam_set", [403], "VENDING.STATE_BUCKET_FAILED"),
    ("apis", [500] * 6, "VENDING.RUNNER_IDENTITY_APIS_MISSING")])
def test_step_failures_are_typed_and_recorded_as_failed(w, fail_key, statuses, code):
    w.google.fail[fail_key] = list(statuses)
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.ensure()
    assert _code(e) == code
    rec = ri.verify_record(ri.provenance_doc_path(PID), w.runner_record(), expected_signer=k.BROKER,
                           certs=k.certs_for())
    assert rec["status"] == "FAILED" and rec["error_class"] == code


def test_failed_re_check_never_downgrades_a_ready_record(w):
    w.ensure()
    before = copy.deepcopy(w.runner_record())
    w.google.fail["sa_get"] = [403]
    w.google.fail["sa_create"] = [403]
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.ensure()
    assert _code(e) == "VENDING.DEPLOYER_SA_FAILED"
    assert w.runner_record() == before


def test_owner_grant_failure_is_typed(w):
    w.iam.fail_set = [403]
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.ensure()
    assert _code(e) == "VENDING.DEPLOYER_OWNER_GRANT_FAILED"
    assert not w.google.buckets


def test_transient_errors_are_retried_with_a_bound(w):
    w.google.fail["sa_create"] = [503, 429]
    w.iam.fail_set = [409]
    w.google.fail["bucket_iam_set"] = [400]    # a new SA not yet visible to IAM
    assert w.ensure()["status"] == "READY"
    assert len(w.slept) == 4


def test_missing_api_is_typed_after_bounded_polls(w):
    w.google.enabled[NUMBER] = {"iam.googleapis.com", "iamcredentials.googleapis.com"}
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.ensure()
    assert _code(e) == "VENDING.RUNNER_IDENTITY_APIS_MISSING" and "storage.googleapis.com" in e.value.detail
    assert len(w.slept) == rb.API_CHECK_ATTEMPTS - 1
    assert w.google.mutating() == []


def test_unknown_region_is_typed(w):
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.ensure(region=None)
    assert _code(e) == "VENDING.STATE_BUCKET_FAILED"


def test_unexpected_token_creator_on_the_deployer_refuses(w):
    w.google.sas[DEPLOYER] = {"email": DEPLOYER, "projectId": PROJECT}
    w.google.sa_policies[DEPLOYER] = {"etag": "x", "bindings": [
        {"role": "roles/iam.serviceAccountTokenCreator", "members": [f"serviceAccount:{k.DEVELOPER}"]}]}
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.ensure()
    assert _code(e) == "VENDING.DEPLOYER_UNEXPECTED_TOKEN_CREATOR"
    assert not any(u.endswith(":setIamPolicy") for _, u in w.google.mutating())


def test_disabled_or_foreign_deployer_is_refused(w):
    w.google.sas[DEPLOYER] = {"email": DEPLOYER, "projectId": PROJECT, "disabled": True}
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.ensure()
    assert _code(e) == "VENDING.DEPLOYER_SA_FAILED"


@pytest.mark.parametrize("runtime,env,why", [
    (k.DEVELOPER, {}, "runs as the developer SA"),
    (k.BROKER, {ri.BROKER_SA_ENV: f"other@{k.HOST}.iam.gserviceaccount.com"}, "env names another SA"),
    (k.BROKER, {ri.RUNNER_MEMBERS_ENV: k.BROKER}, "broker is a runner member"),
    (k.BROKER, {ri.SERVER_MEMBERS_ENV: k.BROKER}, "broker is a server member"),
    (None, {}, "unknown runtime")])
def test_broker_must_not_be_a_shared_identity(runtime, env, why):
    world = World(runtime=runtime, **env)
    with pytest.raises(ri.RunnerIdentityError) as e:
        world.ensure()
    assert _code(e) == "VENDING.RUNNER_BROKER_SHARED_IDENTITY", why
    assert world.google.calls == [] and world.iam.calls == []


def test_explicit_broker_env_equal_to_runtime_is_accepted():
    world = World(runtime=f"sa-vending@{k.HOST}.iam.gserviceaccount.com",
                  **{ri.BROKER_SA_ENV: f"SA-VENDING@{k.HOST}.iam.gserviceaccount.com"})
    world.deps.certs = k.certs_for({f"sa-vending@{k.HOST}.iam.gserviceaccount.com":
                                    {k.BROKER_KEY.key_id: k.BROKER_KEY.cert_pem}})
    assert world.ensure()["signed_by"] == f"sa-vending@{k.HOST}.iam.gserviceaccount.com"


def test_unsigned_existing_record_is_refused_never_replaced(w):
    w.db.docs[f"workload_provenance/{PID}"]["runner_identity"] = {"schema": ri.SCHEMA, "state_bucket": "evil",
                                                                  "status": "READY"}
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.ensure()
    assert _code(e) == "RUNNER_RECORD_UNSIGNED"
    assert w.google.calls == [] and w.runner_record()["state_bucket"] == "evil"


def test_record_signed_by_the_control_center_is_refused(w):
    rec = ri.new_runner_identity_record(product_id=PID, project_id=PROJECT, project_number=NUMBER,
                                        state_bucket=BUCKET, status="READY", updated_at="t")
    w.db.docs[f"workload_provenance/{PID}"]["runner_identity"] = ri.sign_record(
        ri.provenance_doc_path(PID), rec, signer_email=k.CC, signed_at="t", sign_blob=k.OTHER_KEY.sign)
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.ensure()
    assert _code(e) == "RUNNER_RECORD_UNSIGNED"


@pytest.mark.parametrize("mutate", [lambda p: p.clear(), lambda p: p.update(created_by="someone"),
                                    lambda p: p.update(project_id="other-proj-123"),
                                    lambda p: p.update(project_number="1")])
def test_unprovenanced_project_is_refused(w, mutate):
    mutate(w.db.docs[f"workload_provenance/{PID}"])
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.ensure()
    assert _code(e) == "VENDING.RUNNER_IDENTITY_NO_PROVENANCE"
    assert w.google.calls == []


def test_signing_failure_is_typed(w):
    w.deps.signer_factory = lambda email: (lambda payload: ("", ""))
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.ensure()
    assert _code(e) == "RUNNER_RECORD_SIGN_FAILED"


def test_pin_repository(w):
    w.ensure()
    prov = w.provisioner()
    repo = {"provider": "GITHUB", "full_name": "acme/castor-shop-api", "id": "42"}
    prov.pin_repository(PID, repo)
    rec = ri.verify_record(ri.provenance_doc_path(PID), w.runner_record(), expected_signer=k.BROKER,
                           certs=k.certs_for())
    assert rec["repository"] == repo and rec["status"] == "READY"
    prov.pin_repository(PID, repo)   # same repository: no-op
    with pytest.raises(ri.RunnerIdentityError) as e:
        prov.pin_repository(PID, dict(repo, full_name="evil/repo"))
    assert _code(e) == "VENDING.RUNNER_REPOSITORY_MISMATCH"


# ---------------------------------------------------------------------------------------------- vend integration
def _engine(vmain, world, crm=None, db=None):
    eng = _vend_engine(vmain, db or world.db, crm or _vend_crm())
    eng._runner_deps = world.deps
    return eng


class Exploding:
    def __getattr__(self, name):
        raise AssertionError(f"runner deps touched in PLATFORM mode: {name}")


@pytest.fixture
def vend_env(monkeypatch):
    monkeypatch.delenv("STACKVEND_MANAGED_TAG_VALUE", raising=False)
    monkeypatch.delenv("STACKVEND_GUARD_FIRESTORE_DATABASE", raising=False)
    monkeypatch.delenv("STACKVEND_CHILD_PROJECT_OWNER_MEMBERS", raising=False)
    monkeypatch.delenv(ri.MODE_ENV, raising=False)
    return monkeypatch


EXPECTED_VEND_KEYS = {"status", "product_id", "project_id", "project_number", "trace_id", "budget_ceiling_monthly_usd",
                      "devops_sa_email", "provenance_status", "org_policies", "api_enablement", "auth_config",
                      "cc_log_reader"}   # RT14-31 / D4: every mode grants the Control Center log reads


@pytest.mark.parametrize("mode", [None, "", "PLATFORM"])
def test_platform_mode_vend_is_unchanged(vmain, vend_env, mode):
    """Negative (Do No Harm): Shared installs run none of the new steps and return the same keys as before."""
    if mode is not None:
        vend_env.setenv(ri.MODE_ENV, mode)
    db = f.FakeDB()
    eng = _vend_engine(vmain, db, _vend_crm())
    eng._runner_deps = Exploding()
    res = eng.vend_gcp_project("fresh-svc", "tr-1", folder_id=f.ROOT, force_new_project_id="fresh-svc-123abc")
    assert set(res) == EXPECTED_VEND_KEYS and res["status"] == "PROJECT_VENDED"
    assert "runner_identity_status" not in db.doc("workloads/fresh-svc")
    assert "runner_identity" not in db.doc("workload_provenance/fresh-svc")


def test_platform_and_unset_produce_identical_records(vmain, vend_env):
    outs = []
    for mode in (None, "PLATFORM"):
        if mode:
            vend_env.setenv(ri.MODE_ENV, mode)
        db = f.FakeDB()
        eng = _vend_engine(vmain, db, _vend_crm())
        res = eng.vend_gcp_project("fresh-svc", "tr-1", folder_id=f.ROOT, force_new_project_id="fresh-svc-123abc")
        # timestamps differ between the two vends; nested ones too (SAT-38 VENDING-TARGET-MARKER vend_target.recorded_at)
        strip = lambda d: {k_: (strip(v) if isinstance(v, dict) else v)  # noqa: E731
                           for k_, v in d.items() if not k_.endswith("_at")}
        outs.append((strip(res), [(op, p, strip(d)) for op, p, d in db.writes]))
    assert outs[0] == outs[1]


def test_invalid_mode_fails_before_anything_is_created(vmain, vend_env):
    vend_env.setenv(ri.MODE_ENV, "per_workload")
    crm = _vend_crm()
    eng = _vend_engine(vmain, f.FakeDB(), crm)
    with pytest.raises(VendingFailure) as e:
        eng.vend_gcp_project("fresh-svc", "tr-1", folder_id=f.ROOT, force_new_project_id="fresh-svc-123abc")
    assert e.value.error_class == "VENDING.RUNNER_IDENTITY_MODE_INVALID"
    crm.projects.return_value.create.assert_not_called()


def _per_workload_vend(vmain, vend_env, world, *, events=None, **kw):
    vend_env.setenv(ri.MODE_ENV, "PER_WORKLOAD")
    crm = _vend_crm(project_id=PROJECT)
    eng = _engine(vmain, world, crm=crm)
    world.db.docs.pop(f"workload_provenance/{PID}")
    world.db.docs.pop(f"workloads/{PID}")
    events = events if events is not None else []
    eng.billing_account_id = "billingAccounts/000000-000000-000000"
    eng.billing.projects.return_value.updateBillingInfo.return_value.execute.side_effect = \
        lambda: events.append("billing") or {}
    real_enable = eng.enable_child_apis
    eng.enable_child_apis = lambda pid, **a: events.append("apis") or real_enable(pid, **a)
    world.google.log = events
    eng._iam_client = world.iam
    res = eng.vend_gcp_project(PID, "tr-1", folder_id=f.ROOT, force_new_project_id=PROJECT, **kw)
    return eng, res, events


def test_per_workload_vend_runs_after_billing_and_apis(vmain, vend_env, w):
    eng, res, events = _per_workload_vend(vmain, vend_env, w)
    assert res["runner_identity"] == {"status": "READY", "deployer_email": DEPLOYER, "state_bucket": BUCKET}
    assert events.index("billing") < events.index("apis") < min(
        i for i, e in enumerate(events) if e not in ("billing", "apis"))
    assert w.db.doc(f"workloads/{PID}")["runner_identity_status"] == "READY"
    assert set(res) - EXPECTED_VEND_KEYS == {"runner_identity"}


def test_per_workload_re_vend_of_existing_project_still_ensures(vmain, vend_env, w):
    """Not only created_in_this_call (the B1 pattern): a retried / re-vended provenanced project is completed."""
    vend_env.setenv(ri.MODE_ENV, "PER_WORKLOAD")
    w.db.docs[f"workloads/{PID}"]["status"] = "ACTIVE"
    crm = _vend_crm(project_id=PROJECT)
    eng = _engine(vmain, w, crm=crm)
    eng._iam_client = w.iam
    res = eng.vend_gcp_project(PID, "tr-2", folder_id=f.ROOT)
    crm.projects.return_value.create.assert_not_called()
    assert res["provenance_status"] == "NOT_CREATED_IN_THIS_CALL"
    assert res["runner_identity"]["status"] == "READY"


def test_per_workload_failure_fails_the_vend_typed_and_records_it(vmain, vend_env, w):
    w.google.fail["sa_create"] = [403]
    with pytest.raises(VendingFailure) as e:
        _per_workload_vend(vmain, vend_env, w)
    assert e.value.error_class == "VENDING.DEPLOYER_SA_FAILED"
    rec = w.db.doc(f"workloads/{PID}")
    assert rec["runner_identity_status"] == "FAILED" and rec["vending_error_class"] == "VENDING.DEPLOYER_SA_FAILED"
    assert rec["project_id"] == PROJECT and rec["status"] == "PROVISIONED"   # a retry reuses this project


def test_vend_all_pins_the_repository(vmain, vend_env, w):
    vend_env.setenv(ri.MODE_ENV, "PER_WORKLOAD")
    w.ensure()
    eng = _engine(vmain, w)
    eng.vend_gcp_project = lambda product_id, trace_id, **kw: {"project_id": PROJECT, "project_number": NUMBER}
    eng.vend_github_repo = lambda product_id, **kw: {"full_name": "acme/castor-shop-api", "repo_name": "castor-shop-api",
                                                     "repository_id": 4242, "reused_existing": False}
    eng.vend_all(PID, "tr-3", vcs_provider="GITHUB")
    rec = ri.verify_record(ri.provenance_doc_path(PID), w.runner_record(), expected_signer=k.BROKER,
                           certs=k.certs_for())
    assert rec["repository"] == {"provider": "GITHUB", "full_name": "acme/castor-shop-api", "id": "4242"}


def test_vend_all_platform_mode_pins_nothing(vmain, vend_env, w):
    eng = _engine(vmain, w)
    eng._runner_deps = Exploding()
    eng.vend_gcp_project = lambda product_id, trace_id, **kw: {"project_id": PROJECT, "project_number": NUMBER}
    eng.vend_github_repo = lambda product_id, **kw: {"full_name": "acme/castor-shop-api", "repo_name": "castor-shop-api"}
    assert eng.vend_all(PID, "tr-3", vcs_provider="GITHUB")["status"] == "WORKLOAD_VENDED"
    assert "runner_identity" not in w.prov()


# ---------------------------------------------------------------------------------------------- broker (direct)
def _ready(world):
    world.ensure()
    world.provisioner().pin_repository(PID, {"provider": "GITHUB", "full_name": "acme/castor-shop-api", "id": "42"})
    world.google.calls.clear()
    world.google.tokens_minted.clear()


def _dispatch(world, **over):
    req = {"product_id": PID, "trace_id": "tr-9", "branch": "main", "mode": "deploy", "callback_url": CALLBACK}
    req.update(over)
    return world.broker().dispatch(k.SERVER_SA, req)


def _nonce_of(world, execution):
    [env] = [e["value"] for e in world.google.executions[execution]["env"] if e["name"] == "RUNNER_NONCE"]
    return env


def test_dispatch_binds_one_execution_and_never_returns_the_nonce(w, caplog):
    _ready(w)
    caplog.set_level(logging.DEBUG)
    out = _dispatch(w)
    assert out["status"] == "DISPATCHED" and out["execution"].startswith(k.EXEC_PREFIX)
    nonce = _nonce_of(w, out["execution"])
    assert nonce not in str(out) and nonce not in caplog.text
    [run] = [c for c in w.google.calls if c[1].endswith(":run")]
    assert run[2] == {"overrides": {"containerOverrides": [{"env": [{"name": "RUNNER_NONCE", "value": nonce}]}]}}
    doc = w.db.doc(f"runner_nonces/{ri.nonce_doc_id(nonce)}")
    rec = ri.verify_record(ri.nonce_doc_path(ri.nonce_doc_id(nonce)), doc, expected_signer=k.BROKER,
                           certs=k.certs_for())
    assert rec["execution"] == out["execution"] and rec["redeemed"] is False and rec["product_id"] == PID
    assert rec["deployer_email"] == DEPLOYER and rec["callback_url"] == CALLBACK
    assert not any(nonce in str(v) for v in doc.values())


@pytest.mark.parametrize("over,code", [
    ({"mode": ri.BACKFILL_MODE}, "RUNNER_DISPATCH_INVALID"), ({"mode": "destroy"}, "RUNNER_DISPATCH_INVALID"),
    ({"branch": "../main"}, "RUNNER_DISPATCH_INVALID"), ({"trace_id": "a b"}, "RUNNER_DISPATCH_INVALID"),
    ({"callback_url": "https://evil.example/cb"}, "RUNNER_DISPATCH_INVALID"),
    ({"callback_url": "https://workflowexecutions.googleapis.com.evil.example/x"}, "RUNNER_DISPATCH_INVALID"),
    ({"callback_url": "https://u@workflowexecutions.googleapis.com/x"}, "RUNNER_DISPATCH_INVALID"),
    ({"callback_url": "http://workflowexecutions.googleapis.com/x"}, "RUNNER_DISPATCH_INVALID"),
    ({"payload_ref": "gs://b/o", "payload_sha256": "0" * 64}, "RUNNER_PAYLOAD_UNCONFIGURED"),
    ({"saved_plan_sha256": "0" * 64}, "RUNNER_DISPATCH_INVALID")])
def test_dispatch_input_refusals(w, over, code):
    _ready(w)
    with pytest.raises(ri.RunnerIdentityError) as e:
        _dispatch(w, **over)
    assert e.value.code == code
    assert not any(u.endswith(":run") for _, u in w.google.mutating())


def test_dispatch_payload_ref_must_name_the_staging_bucket():
    world = World(**{rb.STAGING_BUCKET_ENV: "stackvend-staging"})
    _ready(world)
    with pytest.raises(ri.RunnerIdentityError):
        _dispatch(world, payload_ref="gs://other/o", payload_sha256="0" * 64)
    out = _dispatch(world, payload_ref="gs://stackvend-staging/p/1.json", payload_sha256="a" * 64)
    assert out["status"] == "DISPATCHED"


def test_dispatch_refuses_unready_unsigned_or_mismatched_targets(w):
    with pytest.raises(ri.RunnerIdentityError) as e:
        _dispatch(w)
    assert e.value.code == "RUNNER_IDENTITY_NOT_READY"
    _ready(w)
    w.db.docs[f"workloads/{PID}"]["project_id"] = "other-proj-123"        # writable ledger retargeted
    with pytest.raises(ri.RunnerIdentityError) as e:
        _dispatch(w)
    assert e.value.code == "RUNNER_TARGET_UNVERIFIED" and "LEDGER_MISMATCH" in e.value.detail
    w.db.docs[f"workloads/{PID}"]["project_id"] = PROJECT
    w.db.docs[f"workload_provenance/{PID}"]["runner_identity"]["state_bucket"] = "attacker-bucket"
    with pytest.raises(ri.RunnerIdentityError) as e:
        _dispatch(w)
    assert e.value.code == "RUNNER_RECORD_UNSIGNED"
    assert w.google.mutating() == []


def test_dispatch_refuses_when_the_managed_tag_is_gone(w):
    _ready(w)
    w.crm.tag_bindings[NUMBER] = []
    with pytest.raises(ri.RunnerIdentityError) as e:
        _dispatch(w)
    assert e.value.code == "RUNNER_TARGET_UNVERIFIED" and "NOT_STACKVEND_OWNED" in e.value.detail


def test_dispatch_refuses_a_job_running_as_an_unlisted_identity(w):
    _ready(w)
    w.google.job_sa = f"sa-castor-qa@{k.HOST}.iam.gserviceaccount.com"
    with pytest.raises(ri.RunnerIdentityError) as e:
        _dispatch(w)
    assert (e.value.code, e.value.http_status) == ("RUNNER_IDENTITY_UNRESOLVED", 503)


def test_dispatch_without_an_execution_name_is_typed(w):
    _ready(w)
    w.google.run_without_execution = True
    with pytest.raises(ri.RunnerIdentityError) as e:
        _dispatch(w)
    assert e.value.code == "RUNNER_DISPATCH_FAILED"


def test_redeem_once_then_spent(w, caplog):
    _ready(w)
    caplog.set_level(logging.DEBUG)
    exe = _dispatch(w)["execution"]
    nonce = _nonce_of(w, exe)
    out = w.broker().redeem(k.RUNNER_SA, nonce, exe)
    key = out["session_key"]
    assert out["record"]["product_id"] == PID and out["record"]["deployer_email"] == DEPLOYER
    assert key not in caplog.text and nonce not in caplog.text
    doc = w.db.doc(f"runner_nonces/{ri.nonce_doc_id(nonce)}")
    assert key not in str(doc) and doc["session_key_sha256"] == ri.secret_hash(key)
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().redeem(k.RUNNER_SA, nonce, exe)
    assert e.value.code == "RUNNER_NONCE_SPENT"


def test_redeem_window_expires(w):
    _ready(w)
    exe = _dispatch(w)["execution"]
    w.clock_now[0] = f.NOW + timedelta(seconds=ri.REDEEM_WINDOW_SECONDS + 1)
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().redeem(k.RUNNER_SA, _nonce_of(w, exe), exe)
    assert (e.value.code, e.value.http_status) == ("RUNNER_NONCE_EXPIRED", 410)


def test_redeem_refuses_another_execution_unknown_nonce_and_unbrokered_execution(w):
    _ready(w)
    a = _dispatch(w)["execution"]
    b = _dispatch(w, trace_id="tr-10")["execution"]
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().redeem(k.RUNNER_SA, _nonce_of(w, a), b)
    assert e.value.code == "RUNNER_EXECUTION_MISMATCH"
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().redeem(k.RUNNER_SA, "x" * 43, a)
    assert (e.value.code, e.value.http_status) == ("RUNNER_NONCE_UNKNOWN", 404)
    w.google.executions[a]["creator"] = k.DEVELOPER   # someone with run.developer re-ran the job with the nonce
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().redeem(k.RUNNER_SA, _nonce_of(w, a), a)
    assert e.value.code == "RUNNER_EXECUTION_NOT_BROKERED"


def test_redeem_refuses_a_finished_execution(w):
    _ready(w)
    exe = _dispatch(w)["execution"]
    w.google.end_execution(exe)
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().redeem(k.RUNNER_SA, _nonce_of(w, exe), exe)
    assert e.value.code == "RUNNER_EXECUTION_NOT_RUNNING"


# ---- SAT-52: a just-started execution the Admin API still reads as not running (runningCount lags the container)
def _pending(world, exe, **fields):
    """The bound execution as the v2 API answers right after RunJob: proto3 JSON omits the zero runningCount."""
    base = {k_: v for k_, v in world.google.executions[exe].items() if k_ != "runningCount"}
    world.google.executions[exe] = dict(base, **fields)


@pytest.mark.parametrize("fields", [
    {},
    {"runningCount": 0},
    {"startTime": "2026-10-31T12:00:01Z", "taskCount": 1, "reconciling": True},
    {"conditions": [{"type": "Completed", "state": "CONDITION_PENDING"},
                    {"type": "ResourcesAvailable", "state": "CONDITION_SUCCEEDED"},
                    {"type": "Started", "state": "CONDITION_RECONCILING"}]},
    {"completionTime": None, "deleteTime": None},                            # RT LOW: proto3 JSON null = unset
    {"conditions": [{"type": "Completed", "state": "CONDITION_RECONCILING",
                     "executionReason": "JOB_STATUS_SERVICE_POLLING_ERROR"}]},  # Cloud Run retries its own read
])
def test_redeem_of_a_pending_execution_is_retryable_and_consumes_nothing(w, fields):
    _ready(w)
    exe = _dispatch(w)["execution"]
    nonce = _nonce_of(w, exe)
    path = f"runner_nonces/{ri.nonce_doc_id(nonce)}"
    before = copy.deepcopy(w.db.doc(path))
    _pending(w, exe, **fields)
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().redeem(k.RUNNER_SA, nonce, exe)
    assert (e.value.code, e.value.http_status) == ("RUNNER_EXECUTION_NOT_YET_RUNNING", 409)
    assert (rb.RUNNER_EXECUTION_NOT_YET_RUNNING, rb.NOT_YET_RUNNING_STATUS) == ("RUNNER_EXECUTION_NOT_YET_RUNNING", 409)
    assert w.db.doc(path) == before and w.google.tokens_minted == []   # nothing issued, the nonce is not spent
    w.google.executions[exe]["runningCount"] = 1                        # the container is now reported running
    out = w.broker().redeem(k.RUNNER_SA, nonce, exe)
    assert out["session_key"] and w.db.doc(path)["redeemed"] is True


@pytest.mark.parametrize("fields", [
    {"completionTime": "2026-10-31T12:30:00Z"},
    {"runningCount": 1, "completionTime": "2026-10-31T12:30:00Z"},          # unchanged: completion wins
    {"deleteTime": "2026-10-31T12:30:00Z"},
    {"conditions": [{"type": "Completed", "state": "CONDITION_FAILED", "executionReason": "NON_ZERO_EXIT_CODE"}]},
    {"conditions": [{"type": "Completed", "state": "CONDITION_SUCCEEDED"}]},
    {"conditions": [{"type": "Completed", "state": "CONDITION_RECONCILING", "executionReason": "CANCELLING"}]},
    {"conditions": [{"type": "Completed", "state": "CONDITION_PENDING", "executionReason": "CANCELLED"}]},
    {"conditions": [{"type": "Ready", "state": "CONDITION_PENDING", "executionReason": "DELETED"}]},
    {"failedCount": 1},
    {"cancelledCount": 1},
    {"succeededCount": 1},
    {"succeededCount": 1, "taskCount": 1},
    {"runningCount": "1"},                                                   # malformed: the permanent refusal
    {"runningCount": True},
    {"runningCount": -1},
    {"runningCount": None},
    {"conditions": "Completed"},
    {"conditions": ["Completed"]},
    {"failedCount": "0"},
    {"taskCount": None},
    # RT LOW (falsy completionTime): a timestamp is judged by presence, never truthiness
    {"completionTime": ""},
    {"runningCount": 1, "completionTime": ""},
    {"runningCount": 0, "completionTime": ""},
    {"deleteTime": ""},
    {"completionTime": 0},
    {"completionTime": {}},
    {"conditions": [{"type": "Completed", "state": "CONDITION_FAILED", "executionReason": "NON_ZERO_EXIT_CODE"}],
     "runningCount": 1},                                                     # RT LOW: ended wins over a lagging 1
    {"conditions": [{"type": "Completed", "state": "CONDITION_RECONCILING", "executionReason": "NON_ZERO_EXIT_CODE"}]},
])
def test_redeem_of_an_ended_or_unreadable_execution_is_still_the_permanent_refusal(w, fields):
    _ready(w)
    exe = _dispatch(w)["execution"]
    nonce = _nonce_of(w, exe)
    path = f"runner_nonces/{ri.nonce_doc_id(nonce)}"
    before = copy.deepcopy(w.db.doc(path))
    _pending(w, exe, **fields)
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().redeem(k.RUNNER_SA, nonce, exe)
    assert (e.value.code, e.value.http_status) == ("RUNNER_EXECUTION_NOT_RUNNING", 403)
    assert w.db.doc(path) == before and w.google.tokens_minted == []


def test_execution_ended_reads_structured_fields_only():
    """Negative tests: a message that mentions completion or cancellation decides nothing."""
    assert rb._execution_ended({}) is False
    assert rb._execution_ended({"conditions": [{"type": "Completed", "state": "CONDITION_PENDING",
                                                "message": "Completed CANCELLED failed"}]}) is False
    assert rb._execution_ended({"taskCount": 2, "succeededCount": 1}) is False
    assert rb._execution_ended({"taskCount": 2, "succeededCount": 2}) is True
    assert rb._execution_ended({"conditions": [{"type": "Retry", "state": "CONDITION_FAILED"}]}) is False


def test_execution_state_ended_needs_no_completion_time():
    """SAT-52 RT LOW (falsy completionTime): the end condition reads every structured v2 Execution field, so an empty or
    lagging completionTime decides nothing on its own; ended always wins over runningCount."""
    assert rb._execution_state({}) == rb.EXECUTION_NOT_YET_RUNNING
    assert rb._execution_state({"runningCount": 0, "completionTime": None}) == rb.EXECUTION_NOT_YET_RUNNING
    assert rb._execution_state({"runningCount": 1}) == rb.EXECUTION_RUNNING
    for ended in ({"completionTime": ""}, {"deleteTime": ""}, {"runningCount": 1, "completionTime": ""},
                  {"runningCount": 1, "succeededCount": 1}, {"runningCount": 1, "failedCount": 1},
                  {"runningCount": 1, "conditions": [{"type": "Completed", "state": "CONDITION_SUCCEEDED"}]},
                  {"runningCount": 1, "conditions": [{"type": "Completed", "executionReason": "CANCELLING"}]},
                  {"runningCount": 2.0}):
        assert rb._execution_state(ended) == rb.EXECUTION_ENDED, ended


def test_redeem_of_an_execution_that_ended_between_polls_is_the_ended_refusal(w):
    """SAT-52 RT LOW (retry gap): the first poll reads the execution as not running yet (retryable); it ends before the
    retry. The retry is RUNNER_EXECUTION_NOT_RUNNING (403) while Cloud Run has not yet written completionTime --
    runningCount dropped to 0 with a terminal task count, or a stale runningCount 1 with a terminal condition -- and
    nothing is issued or consumed."""
    _ready(w)
    for ended in ({"failedCount": 1},
                  {"succeededCount": 1, "taskCount": 1},
                  {"runningCount": 1, "conditions": [{"type": "Completed", "state": "CONDITION_FAILED",
                                                      "executionReason": "NON_ZERO_EXIT_CODE"}]},
                  {"runningCount": 1, "completionTime": ""}):
        exe = _dispatch(w, trace_id=f"tr-gap-{len(w.google.executions)}")["execution"]
        nonce = _nonce_of(w, exe)
        path = f"runner_nonces/{ri.nonce_doc_id(nonce)}"
        before = copy.deepcopy(w.db.doc(path))
        _pending(w, exe)
        with pytest.raises(ri.RunnerIdentityError) as e:
            w.broker().redeem(k.RUNNER_SA, nonce, exe)
        assert (e.value.code, e.value.http_status) == ("RUNNER_EXECUTION_NOT_YET_RUNNING", 409)
        _pending(w, exe, **ended)                          # ended between the two polls
        with pytest.raises(ri.RunnerIdentityError) as e:
            w.broker().redeem(k.RUNNER_SA, nonce, exe)
        assert (e.value.code, e.value.http_status) == ("RUNNER_EXECUTION_NOT_RUNNING", 403), ended
        assert w.db.doc(path) == before and w.google.tokens_minted == []


@pytest.mark.parametrize("fields", [
    {},                                                                      # the fake's RunJob answer: runningCount 1
    {"startTime": "2026-10-31T12:00:01Z", "taskCount": 1, "reconciling": True, "completionTime": None,
     "conditions": [{"type": "Completed", "state": "CONDITION_RECONCILING"},
                    {"type": "ResourcesAvailable", "state": "CONDITION_SUCCEEDED"},
                    {"type": "Started", "state": "CONDITION_SUCCEEDED"}]},
])
def test_a_running_execution_redeems_on_the_first_try_unchanged(w, fields):
    """SAT-52 RT LOW negative test: a normal running execution redeems on the first call, and its session's deployer
    token is minted, exactly as before."""
    _ready(w)
    exe = _dispatch(w)["execution"]
    w.google.executions[exe].update(fields)
    assert rb._execution_state(w.google.executions[exe]) == rb.EXECUTION_RUNNING
    nonce = _nonce_of(w, exe)
    out = w.broker().redeem(k.RUNNER_SA, nonce, exe)
    assert out["session_key"] and w.db.doc(f"runner_nonces/{ri.nonce_doc_id(nonce)}")["redeemed"] is True
    assert w.broker().deployer_token(k.RUNNER_SA, out["session_key"])["deployer_email"] == DEPLOYER


def test_redeem_checks_before_the_running_state_are_unchanged_for_a_pending_execution(w):
    """Every earlier check still answers first, in the same order, when the execution is pending."""
    _ready(w)
    a = _dispatch(w)["execution"]
    b = _dispatch(w, trace_id="tr-10")["execution"]
    _pending(w, a)
    _pending(w, b)
    with pytest.raises(ri.RunnerIdentityError) as e:      # nonce of another execution
        w.broker().redeem(k.RUNNER_SA, _nonce_of(w, a), b)
    assert (e.value.code, e.value.http_status) == ("RUNNER_EXECUTION_MISMATCH", 403)
    with pytest.raises(ri.RunnerIdentityError) as e:      # unknown nonce
        w.broker().redeem(k.RUNNER_SA, "x" * 43, a)
    assert (e.value.code, e.value.http_status) == ("RUNNER_NONCE_UNKNOWN", 404)
    w.google.executions[a]["creator"] = k.DEVELOPER       # not started by the broker
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().redeem(k.RUNNER_SA, _nonce_of(w, a), a)
    assert (e.value.code, e.value.http_status) == ("RUNNER_EXECUTION_NOT_BROKERED", 403)
    w.google.executions[b]["name"] = b + "-other"          # the API answers another execution
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().redeem(k.RUNNER_SA, _nonce_of(w, b), b)
    assert (e.value.code, e.value.http_status) == ("RUNNER_EXECUTION_MISMATCH", 403)
    w.clock_now[0] = f.NOW + timedelta(seconds=ri.REDEEM_WINDOW_SECONDS + 1)
    with pytest.raises(ri.RunnerIdentityError) as e:      # the redeem window still bounds every retry
        w.broker().redeem(k.RUNNER_SA, _nonce_of(w, a), a)
    assert (e.value.code, e.value.http_status) == ("RUNNER_NONCE_EXPIRED", 410)


def test_a_session_whose_execution_reads_not_running_is_ended_never_retryable(w):
    """Session routes keep the permanent refusal: a session exists only after the redeem saw the execution run."""
    _ready(w)
    exe, key = _session(w)
    _pending(w, exe)
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().deployer_token(k.RUNNER_SA, key)
    assert (e.value.code, e.value.http_status) == ("RUNNER_SESSION_ENDED", 403)
    assert w.google.tokens_minted == []


def test_redeem_of_an_unbound_record_is_retryable(w):
    _ready(w)
    exe = _dispatch(w)["execution"]
    nonce = _nonce_of(w, exe)
    doc_id = ri.nonce_doc_id(nonce)
    doc = w.db.doc(f"runner_nonces/{doc_id}")
    body = {k_: v for k_, v in doc.items() if k_ not in ("signature", "signed_by", "signed_at")}
    w.db.docs[f"runner_nonces/{doc_id}"] = ri.sign_record(ri.nonce_doc_path(doc_id), dict(body, execution=None),
                                                           signer_email=k.BROKER, signed_at="t",
                                                           sign_blob=k.BROKER_KEY.sign)
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().redeem(k.RUNNER_SA, nonce, exe)
    assert e.value.code == "RUNNER_DISPATCH_NOT_BOUND"


def test_a_reset_redeemed_flag_breaks_the_signature(w):
    """A guard-DB writer other than vending (the CC SA) cannot re-arm a spent nonce."""
    _ready(w)
    exe = _dispatch(w)["execution"]
    nonce = _nonce_of(w, exe)
    w.broker().redeem(k.RUNNER_SA, nonce, exe)
    w.db.docs[f"runner_nonces/{ri.nonce_doc_id(nonce)}"]["redeemed"] = False
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().redeem(k.RUNNER_SA, nonce, exe)
    assert e.value.code == "RUNNER_RECORD_UNSIGNED"


def _session(world, **over):
    exe = _dispatch(world, **over)["execution"]
    return exe, world.broker().redeem(k.RUNNER_SA, _nonce_of(world, exe), exe)["session_key"]


def test_deployer_token_is_only_the_sessions_product(w, caplog):
    _ready(w)
    caplog.set_level(logging.DEBUG)
    _exe, key = _session(w)
    out = w.broker().deployer_token(k.RUNNER_SA, key)
    assert out["deployer_email"] == DEPLOYER and out["quota_project_id"] == PROJECT
    assert w.google.tokens_minted == [DEPLOYER]
    assert out["access_token"] not in caplog.text and key not in caplog.text


def test_session_of_one_product_never_mints_another(w):
    """Two READY workloads; a session for A mints only A's deployer, whatever the job asks."""
    _ready(w)
    other_pid, other_project, other_number = "blog-api", "blog-api-x9y8z7", "210987654321"
    f.add_project(w.crm, other_project, other_number, labels={"stackvend-managed": "true",
                                                              "stackvend-product-id": other_pid,
                                                              "stackvend-workload-type": "standard"})
    w.db.docs[f"workloads/{other_pid}"] = {"product_id": other_pid, "project_id": other_project,
                                           "project_number": other_number, "status": "ACTIVE", "is_castor": False}
    w.db.docs[f"workload_provenance/{other_pid}"] = {"created_by": "stackvend-vending", "product_id": other_pid,
                                                     "project_id": other_project, "project_number": other_number}
    w.ensure(product_id=other_pid, project_id=other_project, project_number=other_number)
    w.google.tokens_minted.clear()
    _exe, key = _session(w)
    w.broker().deployer_token(k.RUNNER_SA, key)
    _exe_b, key_b = _session(w, product_id=other_pid, trace_id="tr-b")
    w.broker().deployer_token(k.RUNNER_SA, key_b)
    assert w.google.tokens_minted == [DEPLOYER, f"stackvend-deployer@{other_project}.iam.gserviceaccount.com"]


@pytest.mark.parametrize("tamper", ["wrong-key", "ended", "retargeted"])
def test_deployer_token_refusals(w, tamper):
    _ready(w)
    exe, key = _session(w)
    if tamper == "wrong-key":
        key = key.split(".")[0] + "." + "x" * 43
        code = "RUNNER_SESSION_INVALID"
    elif tamper == "ended":
        w.google.end_execution(exe)
        code = "RUNNER_SESSION_ENDED"
    else:   # vending re-signs another bucket for the product after the dispatch: the session no longer matches
        rec = ri.verify_record(ri.provenance_doc_path(PID), w.runner_record(), expected_signer=k.BROKER,
                               certs=k.certs_for())
        body = {k_: v for k_, v in rec.items() if k_ not in ("signed_by", "signed_at")}
        body["state_bucket"] = f"{BUCKET}-abcdef"
        w.provisioner()._sign_and_write(PID, body, k.BROKER)
        code = "RUNNER_TARGET_MISMATCH"
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().deployer_token(k.RUNNER_SA, key)
    assert e.value.code == code
    assert w.google.tokens_minted == []


def test_deployer_token_waits_for_grant_propagation_then_gives_up(w):
    _ready(w)
    _exe, key = _session(w)
    w.google.mint_status = [403, 404]
    assert w.broker().deployer_token(k.RUNNER_SA, key)["deployer_email"] == DEPLOYER
    w.google.mint_status = [403] * 100
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().deployer_token(k.RUNNER_SA, key)
    assert (e.value.code, e.value.http_status) == ("RUNNER_IMPERSONATION_FAILED", 503)
    assert len(w.slept) == 2 + int(rb.IMPERSONATION_PROPAGATION_S // rb.RETRY_DELAY_S) - 1   # capped at 60 s


def test_repo_token_is_for_the_pinned_repository(w):
    _ready(w)
    _exe, key = _session(w)
    out = w.broker().repo_token(k.RUNNER_SA, key)
    assert out["repository"] == "acme/castor-shop-api" and w.gh_calls == [("acme/castor-shop-api", "42")]


def test_repo_token_refuses_unpinned_and_non_github(w):
    w.ensure()
    _exe, key = _session(w)
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().repo_token(k.RUNNER_SA, key)
    assert e.value.code == "RUNNER_REPOSITORY_NOT_PINNED"
    w.provisioner().pin_repository(PID, {"provider": "SERVERLESS_GIT", "full_name": "serverless-git/shop-api",
                                         "id": None})
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().repo_token(k.RUNNER_SA, key)
    assert e.value.code == "RUNNER_REPO_TOKEN_UNSUPPORTED"
    assert w.gh_calls == []


def _backfill_session(world, product_ids):
    nonce = ri.new_nonce()
    doc_id = ri.nonce_doc_id(nonce)
    exe = f"{k.EXEC_PREFIX}tf-applier-bf1"
    world.google.executions[exe] = {"name": exe, "creator": k.BROKER, "runningCount": 1}
    rec = {"schema": ri.NONCE_SCHEMA, "product_id": None, "mode": ri.BACKFILL_MODE,
           "backfill_product_ids": product_ids, "created_at": f.NOW.isoformat(), "execution": exe,
           "redeemed": False, "redeemed_at": None, "redeemed_by": None, "session_key_sha256": None}
    world.db.docs[f"runner_nonces/{doc_id}"] = ri.sign_record(ri.nonce_doc_path(doc_id), rec, signer_email=k.BROKER,
                                                               signed_at="t", sign_blob=k.BROKER_KEY.sign)
    return world.broker().redeem(k.RUNNER_SA, nonce, exe)["session_key"]


def test_backfill_result_is_verified_against_the_child_before_signing(w):
    key = _backfill_session(w, [PID])
    # the backfill execution created the child resources (as the platform identity); vending only verifies
    w.google.sas[DEPLOYER] = {"email": DEPLOYER, "projectId": PROJECT}
    w.google.sa_policies[DEPLOYER] = {"bindings": [{"role": "roles/iam.serviceAccountTokenCreator",
                                                    "members": [f"serviceAccount:{k.BROKER}"]}]}
    w.iam.policies[PROJECT] = {"bindings": [{"role": "roles/owner", "members": [f"serviceAccount:{DEPLOYER}"]}]}
    w.google.buckets[BUCKET] = dict(k.GOOD_BUCKET, name=BUCKET, projectNumber=NUMBER)
    w.google.bucket_iam[BUCKET] = {"bindings": [
        {"role": "roles/storage.objectAdmin", "members": [f"serviceAccount:{DEPLOYER}"]},
        {"role": "roles/storage.objectViewer", "members": [f"serviceAccount:{k.BROKER}", f"serviceAccount:{k.CC}"]}]}
    w.google.calls.clear()
    out = w.broker().backfill_result(k.RUNNER_SA, key, [{"product_id": PID, "state_bucket": BUCKET},
                                                         {"product_id": "not-listed"}])
    assert out["results"] == [{"product_id": PID, "status": "READY", "error_class": None},
                              {"product_id": "not-listed", "status": "REFUSED",
                               "error_class": "BACKFILL.NOT_IN_DISPATCH"}]
    assert w.google.mutating() == [] and w.iam.sets() == []     # verify only: nothing created in the child
    assert w.runner_record()["status"] == "READY"


def test_backfill_result_with_a_missing_deployer_is_failed_without_creating_it(w):
    key = _backfill_session(w, [PID])
    out = w.broker().backfill_result(k.RUNNER_SA, key, [{"product_id": PID, "state_bucket": BUCKET}])
    assert out["results"][0]["status"] == "FAILED"
    assert out["results"][0]["error_class"] == "VENDING.DEPLOYER_SA_FAILED"
    assert w.google.sas == {} and w.google.mutating() == []


def test_backfill_session_gets_no_tokens_and_deploy_session_no_backfill(w):
    key = _backfill_session(w, [PID])
    for call in (w.broker().deployer_token, w.broker().repo_token):
        with pytest.raises(ri.RunnerIdentityError) as e:
            call(k.RUNNER_SA, key)
        assert e.value.code == "RUNNER_SESSION_MODE_MISMATCH"
    _ready(w)
    _exe, deploy_key = _session(w)
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().backfill_result(k.RUNNER_SA, deploy_key, [])
    assert e.value.code == "RUNNER_SESSION_MODE_MISMATCH"


# ---------------------------------------------------------------------------------------------- SAT-37 result / status
FP = "ab" * 32


def _sync_session(world):
    return _session(world, callback_url=None)          # a synchronous run (FD-7L 5b): no callback URL


def _nonce_doc(world, execution):
    return world.db.doc(f"runner_nonces/{ri.nonce_doc_id(_nonce_of(world, execution))}")


def test_sign_result_signs_the_fingerprint_into_the_dispatch_record_once(w, caplog):
    _ready(w)
    caplog.set_level(logging.DEBUG)
    exe, key = _sync_session(w)
    out = w.broker().sign_result(k.RUNNER_SA, key, FP)
    doc_id = ri.nonce_doc_id(_nonce_of(w, exe))
    assert out == {"status": "SIGNED", "dispatch_id": doc_id, "result_sha256": FP}
    rec = ri.verify_record(ri.nonce_doc_path(doc_id), _nonce_doc(w, exe), expected_signer=k.BROKER,
                           certs=k.certs_for())
    assert rec["result_sha256"] == FP and rec["result_signed_at"] and rec["redeemed"] is True
    assert rec["execution"] == exe and rec["session_key_sha256"] == ri.secret_hash(key)
    assert key not in caplog.text and w.google.tokens_minted == []
    # the job's bounded retry: the same fingerprint is answered unchanged, nothing re-signed
    before = dict(_nonce_doc(w, exe))
    assert w.broker().sign_result(k.RUNNER_SA, key, FP) == out and _nonce_doc(w, exe) == before
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().sign_result(k.RUNNER_SA, key, "cd" * 32)
    assert (e.value.code, e.value.http_status) == ("RUNNER_RESULT_ALREADY_SIGNED", 409)
    assert _nonce_doc(w, exe) == before


@pytest.mark.parametrize("case,code,status", [
    ("workflow_run", "RUNNER_SESSION_MODE_MISMATCH", 403),
    ("not_sha", "RUNNER_RESULT_INVALID", 422),
    ("upper_sha", "RUNNER_RESULT_INVALID", 422),
    ("wrong_key", "RUNNER_SESSION_INVALID", 401),
    ("ended", "RUNNER_SESSION_ENDED", 403),
])
def test_sign_result_refusals(w, case, code, status):
    _ready(w)
    exe, key = _session(w) if case == "workflow_run" else _sync_session(w)
    fp = {"not_sha": "x" * 64, "upper_sha": "AB" * 32}.get(case, FP)
    if case == "wrong_key":
        key = key.split(".")[0] + "." + "y" * 43
    if case == "ended":
        w.google.end_execution(exe)
    before = dict(_nonce_doc(w, exe))
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().sign_result(k.RUNNER_SA, key, fp)
    assert (e.value.code, e.value.http_status) == (code, status)
    assert _nonce_doc(w, exe) == before


_ENDED_WHILE_RUNNING_COUNT_LAGS = [
    {"runningCount": 1, "failedCount": 1},
    {"runningCount": 1, "conditions": [{"type": "Completed", "state": "CONDITION_FAILED",
                                        "executionReason": "NON_ZERO_EXIT_CODE"}]},
    {"runningCount": 1, "conditions": [{"type": "Completed", "executionReason": "CANCELLING"}]},
]


@pytest.mark.parametrize("ended", _ENDED_WHILE_RUNNING_COUNT_LAGS)
def test_a_session_whose_execution_ended_while_running_count_lags_is_ended(w, ended):
    """SAT-52 RT LOW (rt-sat-52-lows F1): on the session routes too, an ended signal outranks a lagging runningCount 1:
    RUNNER_SESSION_ENDED (403), nothing minted (deployer token) and nothing signed (result)."""
    _ready(w)
    exe, key = _session(w)
    w.google.executions[exe].update(ended)
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().deployer_token(k.RUNNER_SA, key)
    assert (e.value.code, e.value.http_status) == ("RUNNER_SESSION_ENDED", 403)
    assert w.google.tokens_minted == []
    exe, key = _sync_session(w)
    w.google.executions[exe].update(ended)
    before = dict(_nonce_doc(w, exe))
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().sign_result(k.RUNNER_SA, key, FP)
    assert (e.value.code, e.value.http_status) == ("RUNNER_SESSION_ENDED", 403)
    assert _nonce_doc(w, exe) == before and w.google.tokens_minted == []


@pytest.mark.parametrize("concurrent,expect", [(FP, "SIGNED"), ("cd" * 32, "RUNNER_RESULT_ALREADY_SIGNED")])
def test_sign_result_lost_swap_is_idempotent_only_for_the_same_fingerprint(w, monkeypatch, concurrent, expect):
    """RT M1 (rt-sat-37): the job's retry overlaps its first call; the other call commits first. The same fingerprint
    is SIGNED (the record the other call committed stays as it is); a different one is still a 409."""
    _ready(w)
    exe, key = _sync_session(w)
    real, seen = w.store.swap_nonce, {}

    def racing(doc_id, expected, new):
        if not seen:
            seen["first"] = True
            w.broker().sign_result(k.RUNNER_SA, key, concurrent)       # the concurrent call commits first
            seen["committed"] = dict(_nonce_doc(w, exe))
            return False
        return real(doc_id, expected, new)
    monkeypatch.setattr(w.store, "swap_nonce", racing)
    if expect == "SIGNED":
        out = w.broker().sign_result(k.RUNNER_SA, key, FP)
        assert out == {"status": "SIGNED", "dispatch_id": ri.nonce_doc_id(_nonce_of(w, exe)), "result_sha256": FP}
    else:
        with pytest.raises(ri.RunnerIdentityError) as e:
            w.broker().sign_result(k.RUNNER_SA, key, FP)
        assert (e.value.code, e.value.http_status) == ("RUNNER_RESULT_ALREADY_SIGNED", 409)
    assert _nonce_doc(w, exe) == seen["committed"] and seen["committed"]["result_sha256"] == concurrent


def test_sign_result_refuses_a_backfill_session(w):
    key = _backfill_session(w, [PID])
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().sign_result(k.RUNNER_SA, key, FP)
    assert e.value.code == "RUNNER_SESSION_MODE_MISMATCH"


def test_a_fingerprint_written_without_vending_breaks_the_signature(w):
    """A guard-DB writer other than vending cannot set or change the signed fingerprint."""
    _ready(w)
    exe, key = _sync_session(w)
    w.broker().sign_result(k.RUNNER_SA, key, FP)
    doc_id = ri.nonce_doc_id(_nonce_of(w, exe))
    w.db.docs[f"runner_nonces/{doc_id}"]["result_sha256"] = "cd" * 32
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.verify_record(ri.nonce_doc_path(doc_id), _nonce_doc(w, exe), expected_signer=k.BROKER,
                         certs=k.certs_for())
    assert e.value.code == "RUNNER_RECORD_UNSIGNED"


def test_dispatch_status_reports_the_bound_execution_for_its_dispatcher_only(w):
    _ready(w)
    exe, key = _sync_session(w)
    doc_id = ri.nonce_doc_id(_nonce_of(w, exe))
    out = w.broker().dispatch_status(k.SERVER_SA, doc_id)
    assert out["execution"] == exe and out["ended"] is False and out["redeemed"] is True
    assert out["result_signed"] is False
    w.broker().sign_result(k.RUNNER_SA, key, FP)
    w.google.executions[exe].update(failedCount=1)
    w.google.end_execution(exe)
    out = w.broker().dispatch_status(k.SERVER_SA, doc_id)
    assert (out["ended"], out["result_signed"], out["failed_count"]) == (True, True, 1)
    assert key not in str(out) and _nonce_of(w, exe) not in str(out)
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().dispatch_status(k.DEVELOPER, doc_id)                 # not the dispatcher
    assert (e.value.code, e.value.http_status) == ("RUNNER_DISPATCH_UNKNOWN", 404)
    assert not any(u.endswith("dispatch-status") for _, u in w.google.mutating())


@pytest.mark.parametrize("fields,ended", [
    ({"runningCount": 0, "failedCount": 1}, True),             # failed before Cloud Run writes completionTime
    ({"failedCount": 1}, True),
    ({"runningCount": 1, "conditions": [{"type": "Completed", "executionReason": "CANCELLING"}]}, True),
    ({"completionTime": ""}, True),
    ({"runningCount": 1}, False),                               # running
    ({"runningCount": 0}, False),                               # not yet running: not ended
    ({"completionTime": None}, False),
])
def test_dispatch_status_ended_is_the_same_reading_as_the_credential_routes(w, fields, ended):
    """SAT-52 RT LOW (rt-sat-52-lows F2): `ended` is `_execution_ended`, not completionTime alone; completion_time
    stays the raw field."""
    _ready(w)
    exe, _key = _sync_session(w)
    doc_id = ri.nonce_doc_id(_nonce_of(w, exe))
    w.google.executions[exe] = dict({k_: v for k_, v in w.google.executions[exe].items() if k_ != "runningCount"},
                                    **fields)
    out = w.broker().dispatch_status(k.SERVER_SA, doc_id)
    assert out["ended"] is ended and out["ended"] is rb._execution_ended(w.google.executions[exe])
    assert out["completion_time"] == fields.get("completionTime") and out["failed_count"] == fields.get("failedCount")


@pytest.mark.parametrize("case,code", [("bad_id", "RUNNER_DISPATCH_INVALID"), ("unknown", "RUNNER_DISPATCH_UNKNOWN"),
                                       ("forged", "RUNNER_RECORD_UNSIGNED"), ("unreadable", "RUNNER_EXECUTION_UNVERIFIED")])
def test_dispatch_status_refusals(w, case, code):
    _ready(w)
    exe, _key = _sync_session(w)
    doc_id = ri.nonce_doc_id(_nonce_of(w, exe))
    if case == "bad_id":
        doc_id = "Z" * 64
    elif case == "unknown":
        doc_id = "e" * 64
    elif case == "forged":
        w.db.docs[f"runner_nonces/{doc_id}"]["redeemed"] = False
    else:
        del w.google.executions[exe]
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().dispatch_status(k.SERVER_SA, doc_id)
    assert e.value.code == code


def test_dispatch_status_of_an_unbound_record_reports_no_execution(w):
    _ready(w)
    exe = _dispatch(w, callback_url=None)["execution"]
    nonce = _nonce_of(w, exe)
    doc_id = ri.nonce_doc_id(nonce)
    doc = w.db.doc(f"runner_nonces/{doc_id}")
    body = {k_: v for k_, v in doc.items() if k_ not in ("signature", "signed_by", "signed_at")}
    w.db.docs[f"runner_nonces/{doc_id}"] = ri.sign_record(ri.nonce_doc_path(doc_id), dict(body, execution=None),
                                                           signer_email=k.BROKER, signed_at="t",
                                                           sign_blob=k.BROKER_KEY.sign)
    out = w.broker().dispatch_status(k.SERVER_SA, doc_id)
    assert out["execution"] is None and out["ended"] is None and out["redeemed"] is False


def test_probe_returns_results_and_no_token(w):
    _ready(w)
    out = w.broker().probe(f.CC_SA, None, 25)
    assert out == {"results": [{"product_id": PID, "status": "OK", "error_class": None, "own_project_ok": True,
                                "host_project_denied": True}], "ok": True}
    assert "ya29" not in str(out)


@pytest.mark.parametrize("call", ["dispatch", "redeem", "deployer_token", "repo_token", "backfill_result", "probe",
                                  "sign_result", "dispatch_status"])
def test_every_broker_call_is_inert_in_platform_mode(call):
    world = World(mode="PLATFORM")
    args = {"dispatch": ({"product_id": PID},), "redeem": ("x" * 43, "e"), "deployer_token": ("k",),
            "repo_token": ("k",), "backfill_result": ("k", []), "probe": (None, 25),
            "sign_result": ("k", FP), "dispatch_status": ("e" * 64,)}[call]
    with pytest.raises(ri.RunnerIdentityError) as e:
        getattr(world.broker(), call)(k.RUNNER_SA, *args)
    assert (e.value.code, e.value.http_status) == ("RUNNER_IDENTITY_MODE_PLATFORM", 409)
    assert world.google.calls == [] and world.db.writes == [] and world.crm.calls == []


# ---------------------------------------------------------------------------------------------- routes
def _claims(email, aud=AUD):
    return {"iss": "https://accounts.google.com", "aud": aud, "email": email, "email_verified": True}


ID_TOKENS = {"server": _claims(k.SERVER_SA), "runner": _claims(k.RUNNER_SA), "cc": _claims(f.CC_SA),
             "developer": _claims(k.DEVELOPER), "qa": _claims(f"sa-castor-qa@{k.HOST}.iam.gserviceaccount.com"),
             "wrong-aud": _claims(k.RUNNER_SA, aud="https://other.run.app")}


def _verifier(token, audiences):
    claims = ID_TOKENS.get(token)
    if claims is None or claims["aud"] not in audiences:
        raise ValueError("bad token")
    return dict(claims)


@pytest.fixture
def routes(vmain, monkeypatch):
    def make(world):
        eng = _vend_engine(vmain, world.db, _vend_crm())
        eng._runner_deps = world.deps
        monkeypatch.setattr(vmain, "vending_engine", eng)
        monkeypatch.setattr(vmain, "CALLER_TOKEN_VERIFIER", _verifier)
        monkeypatch.setenv("VENDING_SERVICE_URL", AUD)
        monkeypatch.setenv("DESTRUCTIVE_CALLERS", f.CC_SA)
        monkeypatch.delenv("STACKVEND_CHILD_PROJECT_OWNER_MEMBERS", raising=False)
        for name in (ri.RUNNER_MEMBERS_ENV, ri.SERVER_MEMBERS_ENV):   # the caller checks read the env (RT F6)
            if world.env.get(name) is None:
                monkeypatch.delenv(name, raising=False)
            else:
                monkeypatch.setenv(name, world.env[name])
        return TestClient(vmain.app)
    return make


def _h(token):
    return {"Authorization": f"Bearer {token}"} if token else {}


ROUTES = [("/runner/dispatch", "server", {"product_id": PID, "trace_id": "t", "branch": "main", "mode": "deploy"}),
          ("/runner/redeem", "runner", {"nonce": "x" * 43, "execution": "e"}),
          ("/runner/deployer-token", "runner", {"session_key": "0" * 64 + "." + "x" * 43}),
          ("/runner/repo-token", "runner", {"session_key": "0" * 64 + "." + "x" * 43}),
          ("/runner/backfill-result", "runner", {"session_key": "0" * 64 + "." + "x" * 43, "results": []}),
          ("/runner/result", "runner", {"session_key": "0" * 64 + "." + "x" * 43, "result_sha256": "ab" * 32}),
          ("/runner/dispatch-status", "server", {"dispatch_id": "e" * 64}),
          ("/runner-identity/probe", "cc", {})]


@pytest.mark.parametrize("path,who,body", ROUTES)
def test_routes_are_inert_in_platform_mode(routes, path, who, body):
    world = World(mode="PLATFORM")
    r = routes(world).post(path, headers=_h(who), json=body)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "RUNNER_IDENTITY_MODE_PLATFORM"
    assert world.google.calls == [] and world.db.writes == []


@pytest.mark.parametrize("path,who,body", ROUTES)
@pytest.mark.parametrize("token,status", [(None, 401), ("wrong-aud", 401), ("forged", 401), ("qa", 403)])
def test_route_caller_checks(routes, path, who, body, token, status):
    world = World()
    r = routes(world).post(path, headers=_h(token), json=body)
    assert r.status_code == status
    assert world.google.calls == [] and world.db.writes == []


@pytest.mark.parametrize("path,who,body", ROUTES[:7])
def test_runner_routes_refuse_the_other_runner_role(routes, path, who, body):
    other = "runner" if who == "server" else "server"
    r = routes(World()).post(path, headers=_h(other), json=body)
    assert r.status_code == 403


def test_runner_routes_unconfigured_members_are_503(routes):
    world = World(**{ri.RUNNER_MEMBERS_ENV: None, ri.SERVER_MEMBERS_ENV: None})
    r = routes(world).post("/runner/redeem", headers=_h("runner"), json={"nonce": "x" * 43, "execution": "e"})
    assert r.status_code == 503 and r.json()["detail"]["code"] == "CALLERS_UNCONFIGURED"


def test_members_default_to_the_child_owner_list_before_step_a():
    cfg = rb.BrokerConfig.from_env({"PROJECT_ID": k.HOST,
                                    "STACKVEND_CHILD_PROJECT_OWNER_MEMBERS": f"serviceAccount:{k.DEVELOPER}"})
    assert cfg.runner_members == cfg.server_members == {k.DEVELOPER} and cfg.mode == "PLATFORM"


def test_full_route_flow(routes, caplog):
    caplog.set_level(logging.DEBUG)
    world = World()
    _ready(world)
    client = routes(world)
    d = client.post("/runner/dispatch", headers=_h("server"), json={
        "product_id": PID, "trace_id": "tr-1", "branch": "main", "mode": "plan"})
    assert d.status_code == 200, d.text
    exe = d.json()["execution"]
    nonce = _nonce_of(world, exe)
    r = client.post("/runner/redeem", headers=_h("runner"), json={"nonce": nonce, "execution": exe})
    assert r.status_code == 200
    key = r.json()["session_key"]
    t = client.post("/runner/deployer-token", headers=_h("runner"), json={"session_key": key})
    assert t.status_code == 200 and t.json()["deployer_email"] == DEPLOYER
    g = client.post("/runner/repo-token", headers=_h("runner"), json={"session_key": key})
    assert g.status_code == 200 and g.json()["repository"] == "acme/castor-shop-api"
    again = client.post("/runner/redeem", headers=_h("runner"), json={"nonce": nonce, "execution": exe})
    assert again.status_code == 409 and again.json()["detail"]["code"] == "RUNNER_NONCE_SPENT"
    p = client.post("/runner-identity/probe", headers=_h("cc"), json={"max": 5})
    assert p.status_code == 200 and p.json()["ok"] is True
    for secret in (nonce, key, t.json()["access_token"], g.json()["token"]):
        assert secret not in caplog.text


def test_result_and_dispatch_status_route_flow(routes, caplog):
    """SAT-37: a synchronous run's execution signs its result fingerprint; the dispatching server reads the state."""
    caplog.set_level(logging.DEBUG)
    world = World()
    _ready(world)
    client = routes(world)
    d = client.post("/runner/dispatch", headers=_h("server"), json={
        "product_id": PID, "trace_id": "tr-1", "branch": "main", "mode": "deploy"})
    assert d.status_code == 200, d.text
    exe, dispatch_id = d.json()["execution"], d.json()["dispatch_id"]
    key = client.post("/runner/redeem", headers=_h("runner"), json={"nonce": _nonce_of(world, exe),
                                                                    "execution": exe}).json()["session_key"]
    s = client.post("/runner/result", headers=_h("runner"), json={"session_key": key, "result_sha256": FP})
    assert s.status_code == 200 and s.json() == {"status": "SIGNED", "dispatch_id": dispatch_id, "result_sha256": FP}
    bad = client.post("/runner/result", headers=_h("runner"), json={"session_key": key, "result_sha256": "x" * 64})
    assert bad.status_code == 422 and bad.json()["detail"]["code"] == "RUNNER_RESULT_INVALID"
    st = client.post("/runner/dispatch-status", headers=_h("server"), json={"dispatch_id": dispatch_id})
    assert st.status_code == 200 and st.json()["result_signed"] is True and st.json()["ended"] is False
    short = client.post("/runner/result", headers=_h("runner"), json={"session_key": key, "result_sha256": "ab"})
    assert short.status_code == 422 and key not in short.text          # RT F9: the body is never echoed
    assert key not in caplog.text


def test_probe_route_refuses_runner_identities(routes):
    r = routes(World()).post("/runner-identity/probe", headers=_h("runner"), json={})
    assert r.status_code == 403


def test_invalid_mode_answers_503_on_broker_routes(routes, vmain, monkeypatch):
    world = World()
    client = routes(world)
    vmain.vending_engine._runner_deps = None
    monkeypatch.setenv(ri.MODE_ENV, "bogus")
    r = client.post("/runner/redeem", headers=_h("runner"), json={"nonce": "x" * 43, "execution": "e"})
    assert r.status_code == 503 and r.json()["detail"]["code"] == "RUNNER_IDENTITY_MODE_INVALID"


# ---------------------------------------------------------------------------------------------- GitHub repo token
class _GH:
    def __init__(self, status=201, body=None):
        self.status_code = status
        self._body = body if body is not None else {
            "token": "ghs_x", "expires_at": "2026-10-31T13:00:00Z", "permissions": {"contents": "read",
                                                                                   "metadata": "read"},
            "repositories": [{"full_name": "acme/castor-shop-api"}]}

    def json(self):
        return self._body


def _gh_engine(vmain, creds):
    eng = _vend_engine(vmain, f.FakeDB(), _vend_crm())
    eng.fetch_github_app_credentials = lambda: creds
    return eng


PEM = k.BROKER_KEY._key.private_bytes(encoding=__import__("cryptography.hazmat.primitives.serialization",
                                                          fromlist=["x"]).Encoding.PEM,
                                      format=__import__("cryptography.hazmat.primitives.serialization",
                                                        fromlist=["x"]).PrivateFormat.TraditionalOpenSSL,
                                      encryption_algorithm=__import__("cryptography.hazmat.primitives.serialization",
                                                                      fromlist=["x"]).NoEncryption()).decode()
APP = {"app_id": "123", "installation_id": "456", "private_key": PEM}


def test_repo_read_token_is_restricted_to_one_repository_contents_read(vmain):
    sent = []
    eng = _gh_engine(vmain, APP)
    out = eng.mint_repository_read_token("acme/castor-shop-api", "42",
                                         http_post=lambda url, headers, json: sent.append((url, json)) or _GH())
    assert out["token"] == "ghs_x"
    assert sent == [("https://api.github.com/app/installations/456/access_tokens",
                     {"permissions": {"contents": "read"}, "repository_ids": [42]})]
    sent.clear()
    eng.mint_repository_read_token("acme/castor-shop-api", None,
                                   http_post=lambda url, headers, json: sent.append(json) or _GH())
    assert sent == [{"permissions": {"contents": "read"}, "repositories": ["castor-shop-api"]}]


@pytest.mark.parametrize("creds,resp", [
    ({"app_id": "", "installation_id": "456", "private_key": PEM, "pat": "ghp_pat"}, _GH()),
    (APP, _GH(status=422, body={"message": "nope"})),
    (APP, _GH(body={"token": "t", "permissions": {"contents": "write"}, "repositories": [
        {"full_name": "acme/castor-shop-api"}]})),
    (APP, _GH(body={"token": "t", "permissions": {"contents": "read", "administration": "read"}, "repositories": [
        {"full_name": "acme/castor-shop-api"}]})),
    (APP, _GH(body={"token": "t", "permissions": {"contents": "read"}})),
    (APP, _GH(body={"token": "t", "permissions": {"contents": "read"}, "repositories": [
        {"full_name": "acme/other"}]}))])
def test_repo_read_token_fails_closed(vmain, monkeypatch, creds, resp):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_env_token_must_not_be_used")
    eng = _gh_engine(vmain, creds)
    with pytest.raises(ri.RunnerIdentityError) as e:
        eng.mint_repository_read_token("acme/castor-shop-api", "42", http_post=lambda url, headers, json: resp)
    assert (e.value.code, e.value.http_status) == ("RUNNER_REPO_TOKEN_UNAVAILABLE", 503)
