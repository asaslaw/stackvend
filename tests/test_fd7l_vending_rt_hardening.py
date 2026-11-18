"""
FD-7L Phase 1 red-team hardening (docs/handoff/sat-19-rt.md F1-F6, F9) on apps/project-vending/runner_broker.py and
main.py. Hermetic fakes only (tests/fd7l_fakes.py, the World of test_fd7l_vending_runner_identity.py).

F1  READY records older than 72 h are re-signed with the current key after a verified read, and by the CC-callable
    /runner-identity/resign sweep; a younger record is never rewritten; a retired key is RUNNER_RECORD_KEY_RETIRED.
F2  the execution creator comes from the v1 annotation when the v2 Execution has no `creator`.
F3  the deployer-token mint waits for propagation only for a young record (capped at 60 s); the probe makes one call.
F4  a state bucket new to the record must hold only the expected IAM members.
F5  a MIGRATING record is never overwritten; `migration` is carried forward.
F6  the route caller checks build no engine dependencies before authentication.
F9  a malformed /runner/* body is answered without echoing its input.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import copy
from datetime import timedelta

import pytest

import destructive_guard_fakes as f
import fd7l_fakes as k
from test_fd7l_vending_runner_identity import (  # noqa: F401  (helpers + fixtures, no tests)
    BUCKET, DEPLOYER, NUMBER, PID, PROJECT, World, _dispatch, _h, _nonce_of, _ready, _session, rb, ri, routes, vmain,
    _freeze_setting_without_firestore,
)

NEW_KEY = k.SigningKey("broker-key-2")


def _verified(world, certs=None):
    return ri.verify_record(ri.provenance_doc_path(PID), world.runner_record(), expected_signer=k.BROKER,
                            certs=certs or world.deps.certs)


def _rotate(world, *, keep_old=True):
    """Google publishes a new broker key (and, until it retires it, the old one); vending now signs with the new key."""
    published = {NEW_KEY.key_id: NEW_KEY.cert_pem}
    if keep_old:
        published[k.BROKER_KEY.key_id] = k.BROKER_KEY.cert_pem
    world.deps.certs = k.certs_for({k.BROKER: published, k.CC: {k.OTHER_KEY.key_id: k.OTHER_KEY.cert_pem}})
    world.deps.signer_factory = lambda email: NEW_KEY.sign


# ---------------------------------------------------------------------------------------------- F1
def test_young_record_is_not_rewritten_on_a_verified_read(w):
    _ready(w)
    before = copy.deepcopy(w.runner_record())
    writes = len(w.db.writes)
    w.clock_now[0] = f.NOW + timedelta(seconds=rb.RESIGN_AFTER_SECONDS - 60)
    w.broker().verified_identity(PID, k.BROKER)
    assert w.runner_record() == before and len(w.db.writes) == writes


def test_stale_record_is_re_signed_with_the_current_key_content_unchanged(w):
    _ready(w)
    before = _verified(w)
    _rotate(w)
    w.clock_now[0] = f.NOW + timedelta(seconds=rb.RESIGN_AFTER_SECONDS + 1)
    w.broker().verified_identity(PID, k.BROKER)
    doc = w.runner_record()
    assert doc["signature"]["key_id"] == NEW_KEY.key_id
    after = _verified(w)
    strip = lambda r: {x: y for x, y in r.items() if x not in ("signed_at", "signed_by")}  # noqa: E731
    assert strip(after) == strip(before)
    # once the old key is retired, the re-signed record still verifies
    w.deps.certs = k.certs_for({k.BROKER: {NEW_KEY.key_id: NEW_KEY.cert_pem}})
    assert _verified(w)["status"] == "READY"


def test_a_retired_key_is_reported_and_never_re_signed(w):
    _ready(w)
    _rotate(w, keep_old=False)
    with pytest.raises(ri.RunnerIdentityError) as e:
        _dispatch(w)
    assert e.value.code == "RUNNER_RECORD_KEY_RETIRED"
    assert w.runner_record()["signature"]["key_id"] == k.BROKER_KEY.key_id


def test_resign_sweep(w):
    _ready(w)
    _rotate(w)
    out = w.broker().resign_sweep(f.CC_SA, None, 25)
    assert out == {"results": [{"product_id": PID, "status": "FRESH", "error_class": None}], "ok": True}
    w.clock_now[0] = f.NOW + timedelta(seconds=rb.RESIGN_AFTER_SECONDS + 1)
    out = w.broker().resign_sweep(f.CC_SA, None, 25)
    assert out["results"][0]["status"] == "RESIGNED"
    assert w.runner_record()["signature"]["key_id"] == NEW_KEY.key_id


def test_resign_sweep_reports_unverifiable_records(w):
    _ready(w)
    w.db.docs[f"workload_provenance/{PID}"]["runner_identity"]["state_bucket"] = "attacker"
    out = w.broker().resign_sweep(f.CC_SA, [PID], 25)
    assert out == {"results": [{"product_id": PID, "status": "FAILED", "error_class": "RUNNER_RECORD_UNSIGNED"}],
                   "ok": False}
    assert w.runner_record()["state_bucket"] == "attacker"


def test_resign_route_is_cc_only_and_inert_in_platform_mode(routes):
    assert routes(World()).post("/runner-identity/resign", headers=_h("runner"), json={}).status_code == 403
    world = World(mode="PLATFORM")
    r = routes(world).post("/runner-identity/resign", headers=_h("cc"), json={})
    assert r.status_code == 409 and r.json()["detail"]["code"] == "RUNNER_IDENTITY_MODE_PLATFORM"
    world = World()
    _ready(world)
    r = routes(world).post("/runner-identity/resign", headers=_h("cc"), json={"max": 5})
    assert r.status_code == 200 and r.json()["results"][0]["status"] == "FRESH"


# ---------------------------------------------------------------------------------------------- F2
@pytest.mark.parametrize("annotation,ok", [(k.BROKER, True), (k.DEVELOPER, False), (None, False)])
def test_creator_from_the_v1_annotation_when_v2_has_none(w, annotation, ok):
    _ready(w)
    exe = _dispatch(w)["execution"]
    w.google.executions[exe].pop("creator")
    if annotation:
        w.google.executions[exe]["v1_annotations"] = {"run.googleapis.com/creator": annotation}
    if ok:
        assert w.broker().redeem(k.RUNNER_SA, _nonce_of(w, exe), exe)["session_key"]
    else:
        with pytest.raises(ri.RunnerIdentityError) as e:
            w.broker().redeem(k.RUNNER_SA, _nonce_of(w, exe), exe)
        assert e.value.code == "RUNNER_EXECUTION_NOT_BROKERED"
    assert any("/apis/run.googleapis.com/v1/namespaces/" in c[1] for c in w.google.calls)


def test_v2_creator_present_never_reads_v1(w):
    _ready(w)
    exe = _dispatch(w)["execution"]
    w.broker().redeem(k.RUNNER_SA, _nonce_of(w, exe), exe)
    assert not any("/apis/run.googleapis.com/v1/" in c[1] for c in w.google.calls)


# ---------------------------------------------------------------------------------------------- F3
def test_old_record_403_answers_after_one_attempt(w):
    _ready(w)
    _exe, key = _session(w)
    w.clock_now[0] = f.NOW + timedelta(seconds=rb.PROPAGATION_YOUNG_S + 1)
    w.google.mint_status = [403] * 100
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.broker().deployer_token(k.RUNNER_SA, key)
    assert e.value.code == "RUNNER_IMPERSONATION_FAILED"
    mints = [c for c in w.google.calls if c[1].endswith(":generateAccessToken")]
    assert len(mints) == 1 and w.slept == []


def test_old_record_transient_errors_get_bounded_retries(w):
    _ready(w)
    _exe, key = _session(w)
    w.clock_now[0] = f.NOW + timedelta(seconds=rb.PROPAGATION_YOUNG_S + 1)
    w.google.mint_status = [503, 503]
    assert w.broker().deployer_token(k.RUNNER_SA, key)["deployer_email"] == DEPLOYER
    assert len(w.slept) == 2


def test_probe_makes_one_mint_call_per_record(w):
    _ready(w)
    w.google.mint_status = [403] * 100
    out = w.broker().probe(f.CC_SA, None, 25)
    assert out["results"][0]["error_class"] == "RUNNER_IMPERSONATION_FAILED"
    assert len([c for c in w.google.calls if c[1].endswith(":generateAccessToken")]) == 1 and w.slept == []


# ---------------------------------------------------------------------------------------------- F4
def test_adopted_bucket_with_a_foreign_member_is_refused_untouched(w):
    w.google.buckets[BUCKET] = dict(k.GOOD_BUCKET, name=BUCKET, projectNumber=NUMBER)
    policy = {"etag": "x", "bindings": [{"role": "roles/storage.objectViewer", "members": ["user:intruder@example.com"]},
                                        {"role": "roles/storage.legacyBucketOwner",
                                         "members": [f"projectOwner:{PROJECT}"]}]}
    w.google.bucket_iam[BUCKET] = copy.deepcopy(policy)
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.ensure()
    assert e.value.code == "VENDING.STATE_BUCKET_UNEXPECTED_MEMBERS" and "intruder" in e.value.detail
    assert w.google.bucket_iam[BUCKET] == policy


def test_adopted_bucket_with_only_expected_members_is_adopted_unchanged(w):
    w.google.buckets[BUCKET] = dict(k.GOOD_BUCKET, name=BUCKET, projectNumber=NUMBER)
    policy = {"etag": "x", "bindings": [
        {"role": "roles/storage.objectAdmin", "members": [f"serviceAccount:{DEPLOYER}"]},
        {"role": "roles/storage.objectViewer", "members": [f"serviceAccount:{k.BROKER}", f"serviceAccount:{k.CC}"]},
        {"role": "roles/storage.legacyBucketOwner", "members": [f"projectOwner:{PROJECT}", f"projectEditor:{NUMBER}"]},
        {"role": "roles/storage.legacyBucketReader", "members": [f"projectViewer:{PROJECT}"]}]}
    w.google.bucket_iam[BUCKET] = copy.deepcopy(policy)
    assert w.ensure()["state_bucket"] == BUCKET
    assert w.google.bucket_iam[BUCKET] == policy
    assert not any(m == "PUT" for m, _ in w.google.mutating())


def test_recorded_bucket_is_not_re_checked_on_re_vend(w):
    w.ensure()
    w.google.bucket_iam[BUCKET]["bindings"].append({"role": "roles/storage.objectViewer",
                                                    "members": ["user:later@example.com"]})
    assert w.ensure()["status"] == "READY"


def test_backfill_result_refuses_a_bucket_with_foreign_members(w):
    from test_fd7l_vending_runner_identity import _backfill_session
    key = _backfill_session(w, [PID])
    w.google.sas[DEPLOYER] = {"email": DEPLOYER, "projectId": PROJECT}
    w.google.sa_policies[DEPLOYER] = {"bindings": [{"role": "roles/iam.serviceAccountTokenCreator",
                                                    "members": [f"serviceAccount:{k.BROKER}"]}]}
    w.iam.policies[PROJECT] = {"bindings": [{"role": "roles/owner", "members": [f"serviceAccount:{DEPLOYER}"]}]}
    w.google.buckets[BUCKET] = dict(k.GOOD_BUCKET, name=BUCKET, projectNumber=NUMBER)
    w.google.bucket_iam[BUCKET] = {"bindings": [
        {"role": "roles/storage.objectAdmin", "members": [f"serviceAccount:{DEPLOYER}", "user:x@example.com"]},
        {"role": "roles/storage.objectViewer", "members": [f"serviceAccount:{k.BROKER}", f"serviceAccount:{k.CC}"]}]}
    out = w.broker().backfill_result(k.RUNNER_SA, key, [{"product_id": PID, "state_bucket": BUCKET}])
    assert out["results"][0]["error_class"] == "VENDING.STATE_BUCKET_UNEXPECTED_MEMBERS"


# ---------------------------------------------------------------------------------------------- F5
def _set_record(world, **over):
    rec = _verified(world)
    body = {x: y for x, y in rec.items() if x not in ("signed_by", "signed_at")}
    body.update(over)
    world.provisioner()._sign_and_write(PID, body, k.BROKER)


def test_migrating_record_is_never_overwritten(w):
    w.ensure()
    _set_record(w, status=ri.STATUS_MIGRATING, migration={"last_source_generation_copied": "17"})
    before = copy.deepcopy(w.runner_record())
    w.google.calls.clear()
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.ensure()
    assert e.value.code == "RUNNER_IDENTITY_MIGRATING"
    assert w.runner_record() == before and w.google.calls == []


def test_migration_is_carried_forward(w):
    w.ensure()
    _set_record(w, migration={"migrated_from": {"bucket": "b", "generation": "1"}})
    assert w.ensure()["migration"] == {"migrated_from": {"bucket": "b", "generation": "1"}}
    w.google.fail["sa_create"] = [403]
    w.google.fail["sa_get"] = [403]
    _set_record(w, status=ri.STATUS_FAILED)
    with pytest.raises(ri.RunnerIdentityError):
        w.ensure()
    assert _verified(w)["migration"] == {"migrated_from": {"bucket": "b", "generation": "1"}}


# ---------------------------------------------------------------------------------------------- F6 / F9
def test_unauthenticated_request_builds_no_runner_dependencies(routes, vmain):
    client = routes(World())
    vmain.vending_engine._runner_deps = None
    r = client.post("/runner/redeem", json={"nonce": "x" * 43, "execution": "e"})
    assert r.status_code == 401 and vmain.vending_engine._runner_deps is None


def test_invalid_mode_without_a_token_is_401(routes, vmain, monkeypatch):
    client = routes(World())
    vmain.vending_engine._runner_deps = None
    monkeypatch.setenv(ri.MODE_ENV, "bogus")
    r = client.post("/runner/redeem", json={"nonce": "x" * 43, "execution": "e"})
    assert r.status_code == 401


def test_malformed_runner_body_is_not_echoed(routes):
    secret = "n" * 40 + "SECRET-NONCE"
    r = routes(World()).post("/runner/redeem", headers=_h("runner"), json={"nonce": secret, "execution": "e" * 600})
    assert r.status_code == 422 and secret not in r.text and "e" * 600 not in r.text


def test_other_routes_keep_the_default_422(routes):
    r = routes(World()).post("/vend-project", json={"trace_id": "t"})
    assert r.status_code == 422 and "input" in r.json()["detail"][0]


@pytest.fixture
def w():
    return World()
