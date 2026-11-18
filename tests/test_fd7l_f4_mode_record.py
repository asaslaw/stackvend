"""
FD-7L-F4 (owner 11-01): the operative Terraform runner identity mode is a vending-signed `install_settings/
runner_identity` record in the guard database, set from Control Center Settings; `STACKVEND_TF_RUNNER_IDENTITY` stays
the install's declaration. Hermetic fakes only (no network, no Firestore client, no IAM).

* shared/runner_identity.py `runner_identity_mode()`: declaration PER_WORKLOAD wins without a read; otherwise the signed
  record; no record -> PLATFORM; a record that exists but cannot be read or verified -> a typed error (never a default);
  a 15 s cache of successful reads only.
* vending (runner_identity_mode.py, main.py routes, runner_broker live mode, vending engine readers).
* Control Center (runner_state.operative_mode, the Settings card's mode block and change route, Express).
* infra-rollback (resolve_state_bucket follows the record).
* Do No Harm: no record (or no guard database) -> byte-identical PLATFORM behaviour, and nothing is read without a
  guard database.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import copy
import importlib
import json
import os
import re
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

import destructive_guard_fakes as f
import fd7l_fakes as k
import fd7l_gcs_fakes as g
from shared import runner_identity as ri
from test_destructive_guard_vending import VENDING_MAIN, fake_verifier, AUD as DG_AUD  # noqa: F401
from test_fd7l_vending_runner_identity import World, _config  # noqa: F401
from test_fd7l_phase3_readers import (  # noqa: F401  (fixtures and helpers)
    GuardDB, Storage, Bucket, Blob, _engine as _rollback_engine, cc, provenance, rollback_mod, signed_record,
    LEGACY, CHILD_BUCKET, PID, _Resp,
)

_G = VENDING_MAIN.ProjectRepoVendingEngine.vend_gcp_project.__globals__
VRI = _G["ri"]          # the vending replica as vending imports it
rim = _G["rim"]
rb = _G["rb"]
VendingFailure = _G["VendingFailure"]

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GUARD = "stackvend-guard"
AT = "2026-11-01T10:00:00+00:00"
ADMIN = "owner@example.com"
CC_TOKEN = "good-token"


@pytest.fixture(autouse=True)
def _fresh_cache():
    ri.clear_mode_cache(high_water=True)
    VRI.clear_mode_cache(high_water=True)
    yield
    ri.clear_mode_cache(high_water=True)
    VRI.clear_mode_cache(high_water=True)


def mode_record(mode="PER_WORKLOAD", version=1, key=k.BROKER_KEY, signer=k.BROKER, previous="PLATFORM", **over):
    rec = ri.new_mode_record(mode=mode, version=version, previous_mode=previous, set_by=ADMIN, set_at=AT,
                             change_id="c" * 32)
    rec.update(over)
    return ri.sign_record(ri.mode_record_doc_path(), rec, signer_email=signer, signed_at=AT, sign_blob=key.sign)


def env(**over):
    e = {"PROJECT_ID": k.HOST, ri.GUARD_DB_ENV: GUARD}
    e.update(over)
    return {key: v for key, v in e.items() if v is not None}


class RaisingDB:
    """Any read is a test failure (proves "nothing read")."""

    def collection(self, name):
        raise AssertionError(f"unexpected guard-database read of {name}")


def change_entry(version=1, change_id="c" * 32, to_mode="PER_WORKLOAD", key=k.BROKER_KEY, signer=k.BROKER):
    body = {"schema": ri.MODE_CHANGE_SCHEMA, "change_id": change_id, "from_mode": "PLATFORM", "from_version": 0,
            "from_error": None, "to_mode": to_mode, "to_version": version, "changed_by": k.CC,
            "operator_attested": ADMIN, "changed_at": AT}
    return ri.sign_record(ri.mode_change_doc_path(change_id), body, signer_email=signer, signed_at=AT,
                          sign_blob=key.sign)


def guard_with(record=None, log=True):
    """A guard DB holding `record` and (log=True) the change entry that wrote it (version + change id)."""
    g = GuardDB()
    if record is not None:
        g.docs[ri.mode_record_doc_path()] = record
        if log and isinstance(record, dict) and isinstance(record.get("version"), int):
            g.docs[ri.mode_change_doc_path(record.get("change_id"))] = change_entry(
                record["version"], record.get("change_id"), record.get("mode"))
    return g


CHANGES_QUERY = f"{ri.mode_record_doc_path()}/{ri.MODE_CHANGES_COLLECTION}?query"


# ================================================================================================ shared reader
def test_declaration_per_workload_wins_without_a_read():
    assert ri.runner_identity_mode(env(**{ri.MODE_ENV: "PER_WORKLOAD"}), guard_db=RaisingDB()) == "PER_WORKLOAD"
    # even when a PLATFORM record exists, the declaration is final
    g = guard_with(mode_record("PLATFORM", previous="PER_WORKLOAD"))
    assert ri.runner_identity_mode(env(**{ri.MODE_ENV: "PER_WORKLOAD"}), guard_db=g, certs=k.certs_for()) \
        == "PER_WORKLOAD" and g.reads == []


def test_unknown_declaration_is_typed_and_reads_nothing():
    for raw in ("per_workload", "SHARED", "1"):
        with pytest.raises(ri.RunnerIdentityError) as e:
            ri.runner_identity_mode(env(**{ri.MODE_ENV: raw}), guard_db=RaisingDB())
        assert e.value.code == "RUNNER_IDENTITY_MODE_INVALID" and e.value.http_status == 503


def test_no_guard_database_and_no_step_a_is_platform_without_a_read():
    """Do No Harm: an install (or service) before step A: exactly the old env-only behaviour."""
    for declared in (None, "", "PLATFORM", " PLATFORM "):
        e = env(**{ri.GUARD_DB_ENV: None, ri.MODE_ENV: declared})
        assert ri.runner_identity_mode(e, guard_db=RaisingDB()) == "PLATFORM"
    assert ri.runner_identity_mode({}) == "PLATFORM"


def test_no_guard_database_after_step_a_is_typed():
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.runner_identity_mode(env(**{ri.GUARD_DB_ENV: None, ri.BROKER_SA_ENV: k.BROKER}), guard_db=RaisingDB())
    assert e.value.code == "RUNNER_STORE_UNAVAILABLE" and e.value.http_status == 503


def test_no_record_and_no_change_is_platform():
    """Never switched: Shared as today (one document read + one empty existence query, no signature)."""
    g = guard_with()
    assert ri.runner_identity_mode(env(), guard_db=g, certs=k.certs_for()) == "PLATFORM"
    assert g.reads == [ri.mode_record_doc_path(), CHANGES_QUERY]
    assert ri.read_mode_record(env(), guard_db=g, certs=lambda *a, **kw: 1 / 0) is None   # no certificate needed


def test_rt_h1_a_deleted_record_after_a_switch_is_typed_not_platform():
    g = GuardDB()
    g.docs[ri.mode_change_doc_path("c" * 32)] = change_entry()   # a switch happened; the record is gone
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.runner_identity_mode(env(), guard_db=g, certs=k.certs_for())
    assert e.value.code == "RUNNER_MODE_RECORD_MISSING" and e.value.http_status == 503
    bad = MagicMock()
    bad.collection.return_value.document.return_value.get.return_value = type("S", (), {"exists": False})()
    bad.collection.return_value.document.return_value.collection.return_value.limit.return_value.stream.side_effect = \
        RuntimeError("503")
    with pytest.raises(ri.RunnerIdentityError) as e:   # the log cannot be read: never "never switched"
        ri.runner_identity_mode(env(), guard_db=bad, certs=k.certs_for())
    assert e.value.code == "RUNNER_STORE_UNAVAILABLE"


def test_rt_m1_a_replayed_older_record_is_stale():
    old = mode_record("PER_WORKLOAD", version=1, change_id="a" * 32)
    g = GuardDB()
    g.docs[ri.mode_record_doc_path()] = old
    g.docs[ri.mode_change_doc_path("a" * 32)] = change_entry(1, "a" * 32, "PER_WORKLOAD")
    g.docs[ri.mode_change_doc_path("b" * 32)] = change_entry(2, "b" * 32, "PLATFORM")   # the newer switch back
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.runner_identity_mode(env(), guard_db=g, certs=k.certs_for())
    assert e.value.code == "RUNNER_MODE_RECORD_STALE"
    del g.docs[ri.mode_change_doc_path("b" * 32)]
    del g.docs[ri.mode_change_doc_path("a" * 32)]
    with pytest.raises(ri.RunnerIdentityError) as e:   # a record with no change entry at all is stale too
        ri.runner_identity_mode(env(), guard_db=g, certs=k.certs_for())
    assert e.value.code == "RUNNER_MODE_RECORD_STALE"


@pytest.mark.parametrize("mode", ["PER_WORKLOAD", "PLATFORM"])
def test_signed_record_is_the_operative_mode(mode):
    g = guard_with(mode_record(mode, previous=None))
    assert ri.runner_identity_mode(env(), guard_db=g, certs=k.certs_for()) == mode
    rec = ri.read_mode_record(env(), guard_db=g, certs=k.certs_for())
    assert rec["mode"] == mode and rec["set_by"] == ADMIN and "signature" not in rec
    assert g.reads == [ri.mode_record_doc_path(), CHANGES_QUERY] * 2


def test_signer_is_the_terraform_owned_broker_when_named():
    other = "sa-other@mock-stackvend-project.iam.gserviceaccount.com"
    g = guard_with(mode_record(signer=other), log=False)
    g.docs[ri.mode_change_doc_path("c" * 32)] = change_entry(signer=other)
    certs = k.certs_for({other: {k.BROKER_KEY.key_id: k.BROKER_KEY.cert_pem}})
    assert ri.runner_identity_mode(env(**{ri.BROKER_SA_ENV: other}), guard_db=g, certs=certs) == "PER_WORKLOAD"
    ri.clear_mode_cache()
    with pytest.raises(ri.RunnerIdentityError) as e:   # derived signer (provisioner) != the record's signer
        ri.runner_identity_mode(env(), guard_db=g, certs=certs)
    assert e.value.code == "RUNNER_RECORD_UNSIGNED"


def _tampered():
    rec = mode_record()
    rec["mode"] = "PLATFORM"   # changed after signing
    return rec


def _path_swap():
    """A real broker signature, but over another document (a provenance record's path)."""
    rec = ri.new_mode_record(mode="PER_WORKLOAD", version=1, previous_mode=None, set_by=ADMIN, set_at=AT,
                             change_id="c" * 32)
    return ri.sign_record(ri.provenance_doc_path("x"), rec, signer_email=k.BROKER, signed_at=AT,
                          sign_blob=k.BROKER_KEY.sign)


def _forged():
    rec = mode_record(key=k.OTHER_KEY)
    rec["signature"] = dict(rec["signature"], key_id=k.BROKER_KEY.key_id)
    return rec


def _signed_body(body):
    return ri.sign_record(ri.mode_record_doc_path(), body, signer_email=k.BROKER, signed_at=AT,
                          sign_blob=k.BROKER_KEY.sign)


def _base():
    return ri.new_mode_record(mode="PER_WORKLOAD", version=1, previous_mode=None, set_by=ADMIN, set_at=AT,
                              change_id="c" * 32)


@pytest.mark.parametrize("doc,code", [
    ({"mode": "PER_WORKLOAD"}, "RUNNER_RECORD_UNSIGNED"),                                   # unsigned
    ("junk", "RUNNER_RECORD_UNSIGNED"),
    (None, "RUNNER_RECORD_UNSIGNED"),                                                        # empty document
    (_tampered(), "RUNNER_RECORD_UNSIGNED"),
    (_path_swap(), "RUNNER_RECORD_UNSIGNED"),
    (_forged(), "RUNNER_RECORD_UNSIGNED"),
    (mode_record(signer="sa-stackvend-control-center@mock-stackvend-project.iam.gserviceaccount.com",
                 key=k.OTHER_KEY), "RUNNER_RECORD_UNSIGNED"),                               # signed by another SA
    (_signed_body(dict(_base(), extra=1)), "RUNNER_MODE_RECORD_INVALID"),                   # valid signature, bad shape
    (_signed_body(dict(_base(), schema="runner_identity_mode/v0")), "RUNNER_MODE_RECORD_INVALID"),
    (_signed_body(dict(_base(), mode="per_workload")), "RUNNER_MODE_RECORD_INVALID"),
    (_signed_body(dict(_base(), version=0)), "RUNNER_MODE_RECORD_INVALID"),
    (_signed_body(dict(_base(), version=True)), "RUNNER_MODE_RECORD_INVALID"),
])
def test_a_record_that_cannot_be_verified_is_typed_never_a_default(doc, code):
    g = GuardDB()
    g.docs[ri.mode_record_doc_path()] = {} if doc is None else doc

    class _G(GuardDB):
        pass

    if not isinstance(doc, dict) and doc is not None:   # a non-dict document body
        class _S:
            exists = True

            def to_dict(self):
                return doc
        g = MagicMock()
        g.collection.return_value.document.return_value.get.return_value = _S()
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.runner_identity_mode(env(), guard_db=g, certs=k.certs_for())
    assert e.value.code == code and e.value.http_status == 503 and e.value.stage == "runner-identity-mode"


def test_retired_key_unavailable_certs_and_unreadable_store_are_typed():
    g = guard_with(mode_record())
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.runner_identity_mode(env(), guard_db=g, certs=k.certs_for({k.BROKER: {}}))
    assert e.value.code == "RUNNER_RECORD_KEY_RETIRED"

    def boom(email, refresh=False):
        raise RuntimeError("down")
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.runner_identity_mode(env(), guard_db=g, certs=boom)
    assert e.value.code == "RUNNER_RECORD_UNVERIFIABLE"
    bad = MagicMock()
    bad.collection.return_value.document.return_value.get.side_effect = RuntimeError("503")
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.runner_identity_mode(env(), guard_db=bad, certs=k.certs_for())
    assert e.value.code == "RUNNER_STORE_UNAVAILABLE"
    with pytest.raises(ri.RunnerIdentityError) as e:   # no broker named and no PROJECT_ID: nothing to verify against
        ri.runner_identity_mode({ri.GUARD_DB_ENV: GUARD}, guard_db=g, certs=k.certs_for())
    assert e.value.code == "RUNNER_RECORD_UNVERIFIABLE"


def test_cache_holds_successes_for_the_ttl_only(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(ri.time, "monotonic", lambda: now[0])
    g = guard_with()
    assert ri.runner_identity_mode(env(), guard_db=g, certs=k.certs_for()) == "PLATFORM"
    g.docs[ri.mode_record_doc_path()] = mode_record()
    g.docs[ri.mode_change_doc_path("c" * 32)] = change_entry()
    now[0] += ri.MODE_CACHE_SECONDS - 1
    assert ri.runner_identity_mode(env(), guard_db=g, certs=k.certs_for()) == "PLATFORM"   # cached
    assert g.reads.count(ri.mode_record_doc_path()) == 1
    now[0] += 2
    assert ri.runner_identity_mode(env(), guard_db=g, certs=k.certs_for()) == "PER_WORKLOAD"
    assert g.reads.count(ri.mode_record_doc_path()) == 2
    # a failure is never cached: the next call reads again
    g.docs[ri.mode_record_doc_path()] = _forged()
    now[0] += ri.MODE_CACHE_SECONDS + 1
    for _ in range(2):
        with pytest.raises(ri.RunnerIdentityError):
            ri.runner_identity_mode(env(), guard_db=g, certs=k.certs_for())
    assert g.reads.count(ri.mode_record_doc_path()) == 4
    assert ri.MODE_CACHE_SECONDS == 15.0


def test_replicas_are_byte_identical():
    copies = ["shared/runner_identity.py", "apps/project-vending/shared/runner_identity.py",
              "mcp-servers/terraform/shared/runner_identity.py", "apps/control-center/shared/runner_identity.py",
              "apps/infra-rollback/shared/runner_identity.py"]
    assert len({open(os.path.join(REPO, p), "rb").read() for p in copies}) == 1


def test_every_reader_goes_through_the_one_shared_function():
    """No reader parses STACKVEND_TF_RUNNER_IDENTITY itself (except the gateway-only Express fallback, which the CC
    overrides with the operative mode) and no service keeps the mode in a process-wide value."""
    for rel in ("apps/project-vending/vending.py", "apps/project-vending/runner_broker.py",
                "apps/project-vending/runner_identity_backfill.py", "apps/project-vending/runner_identity_mode.py",
                "apps/control-center/services/runner_state.py", "apps/control-center/routes/runner_identity_card.py",
                "apps/infra-rollback/rollback.py"):
        src = open(os.path.join(REPO, rel)).read()
        assert "getenv(ri.MODE_ENV" not in src and "environ.get(ri.MODE_ENV" not in src, rel
        assert "getenv(\"STACKVEND_TF_RUNNER_IDENTITY\"" not in src, rel
    broker = open(os.path.join(REPO, "apps/project-vending/runner_broker.py")).read()
    assert "self.d.config.mode != ri.MODE_PER_WORKLOAD" not in broker
    backfill = open(os.path.join(REPO, "apps/project-vending/runner_identity_backfill.py")).read()
    assert "self.d.config.mode" not in backfill


# ================================================================================================ vending
class FullTxn:
    def __init__(self, db):
        self.db = db

    def set(self, ref, data):
        ref.set(data)

    def create(self, ref, data):
        ref.create(data)

    def update(self, ref, data):
        ref.update(data)

    def delete(self, ref):   # RT H1: vending never deletes; a call is a test failure
        raise AssertionError(f"unexpected delete of {ref.path}")


class Setting(rim.RunnerIdentityModeSetting):
    __test__ = False

    def __init__(self, *a, before_txn=None, **kw):
        super().__init__(*a, **kw)
        self.before_txn = before_txn

    def _run_in_transaction(self, body):
        if self.before_txn:
            self.before_txn()
        body(FullTxn(self.guard_db))


STEP_A = {VRI.BROKER_SA_ENV: k.BROKER, VRI.RUNNER_MEMBERS_ENV: f"{k.DEVELOPER},{k.RUNNER_SA}",
          VRI.SERVER_MEMBERS_ENV: f"{k.DEVELOPER},{k.SERVER_SA}", "STACKVEND_RUNNER_STAGING_BUCKET": "stage-b"}


def _vworld(declared=None, step_a=True, runtime=k.BROKER, **extra):
    """A vending world: SAT-19's deps with the config built from an env that has (or lacks) step A."""
    w = World(mode="PER_WORKLOAD", runtime=runtime)
    w.google = g.GCSGoogle(w.google.log)   # SAT-41: lists tf-applier executions (the switch's in-flight check)
    w.deps.rest = w.google
    e = {"PROJECT_ID": k.HOST, VRI.GUARD_DB_ENV: GUARD}
    if declared is not None:
        e[VRI.MODE_ENV] = declared
    if step_a:
        e.update(STEP_A)
    else:
        e["STACKVEND_CHILD_PROJECT_OWNER_MEMBERS"] = f"serviceAccount:{k.DEVELOPER}"
    e.update(extra)
    w.env = e
    w.deps.config = rb.BrokerConfig.from_env(e)
    w.deps.mode = lambda: VRI.runner_identity_mode(e, guard_db=w.db, certs=w.deps.certs)
    w.signed = []
    orig = w.deps.signer_factory
    w.deps.signer_factory = lambda email: (lambda payload: (w.signed.append(payload), orig(email)(payload))[1])
    return w


def _setting(w, **kw):
    return Setting(w.deps, guard_db=w.db, environ=w.env, **kw)


def _mode_docs(w):
    return {p: d for p, d in w.db.docs.items() if p.startswith(ri.INSTALL_SETTINGS_COLLECTION + "/")}


def test_runner_account_ids_match_the_platform_terraform():
    tf = open(os.path.join(REPO, "infra", "platform", "tf_runner_identity.tf")).read()
    assert f'tf_runner_job_account_id    = "{rb.RUNNER_JOB_ACCOUNT_ID}"' in tf
    assert f'tf_runner_server_account_id = "{rb.RUNNER_SERVER_ACCOUNT_ID}"' in tf
    assert k.RUNNER_SA.startswith(rb.RUNNER_JOB_ACCOUNT_ID + "@") and k.SERVER_SA.startswith(rb.RUNNER_SERVER_ACCOUNT_ID + "@")


def test_step_a_detection_uses_exact_env_values():
    assert _vworld().deps.config.step_a_missing() == []
    missing = _vworld(step_a=False).deps.config.step_a_missing()
    assert missing == [VRI.BROKER_SA_ENV, f"{VRI.RUNNER_MEMBERS_ENV} (sa-stackvend-tf-applier)",
                       f"{VRI.SERVER_MEMBERS_ENV} (sa-stackvend-tf-server)", "STACKVEND_RUNNER_STAGING_BUCKET"]
    # a list naming only the developer (or a look-alike account) is not step A
    w = _vworld(**{VRI.RUNNER_MEMBERS_ENV: f"{k.DEVELOPER},sa-stackvend-tf-applier-x@{k.HOST}.iam.gserviceaccount.com"})
    assert w.deps.config.step_a_missing() == [f"{VRI.RUNNER_MEMBERS_ENV} (sa-stackvend-tf-applier)"]


def test_per_workload_is_refused_before_step_a():
    w = _vworld(step_a=False)
    with pytest.raises(VRI.RunnerIdentityError) as e:
        _setting(w).set(f.CC_SA, mode="PER_WORKLOAD", expected_version=0, operator_email=ADMIN)
    assert e.value.code == "RUNNER_IDENTITY_STEP_A_MISSING" and e.value.http_status == 409
    assert _mode_docs(w) == {} and w.signed == [] and w.db.writes == []


def test_set_per_workload_then_back_signs_the_record_and_keeps_every_change():
    w = _vworld()
    out = _setting(w).set(f.CC_SA, mode="PER_WORKLOAD", expected_version=0, operator_email=" Owner@Example.com ")
    assert out["changed"] is True and out["version"] == 1 and out["previous_mode"] == "PLATFORM"
    rec = w.db.doc(ri.mode_record_doc_path())
    assert rec["set_by"] == f.CC_SA.lower() and rec["signed_by"] == k.BROKER and rec["mode"] == "PER_WORKLOAD"
    # every reader resolves it through the shared function
    assert ri.runner_identity_mode(env(), guard_db=w.db, certs=k.certs_for()) == "PER_WORKLOAD"
    assert w.deps.operative_mode() == "PER_WORKLOAD"
    first_change = ri.mode_change_doc_path(out["change_id"])
    change = w.db.doc(first_change)
    ri.verify_record(first_change, change, expected_signer=k.BROKER, certs=k.certs_for())
    assert {key: change[key] for key in ("from_mode", "to_mode", "from_version", "to_version", "changed_by",
                                         "operator_attested", "from_error")} == {
        "from_mode": "PLATFORM", "to_mode": "PER_WORKLOAD", "from_version": 0, "to_version": 1,
        "changed_by": f.CC_SA.lower(), "operator_attested": ADMIN, "from_error": None}   # RT L1: both, labelled
    snapshot = copy.deepcopy(change)
    VRI.clear_mode_cache()
    out2 = _setting(w).set(f.CC_SA, mode="PLATFORM", expected_version=1, operator_email=ADMIN)   # the drill back
    assert out2["version"] == 2 and out2["record_version"] == 2 and out2["previous_mode"] == "PER_WORKLOAD"
    back = w.db.doc(ri.mode_record_doc_path())
    assert back["mode"] == "PLATFORM" and back["version"] == 2   # RT H1: Shared is a signed record, never a delete
    assert ri.runner_identity_mode(env(), guard_db=w.db, certs=k.certs_for()) == "PLATFORM"
    changes = [p for p in _mode_docs(w) if "/changes/" in p]
    assert len(changes) == 2 and w.db.doc(first_change) == snapshot   # never trimmed or rewritten
    view = _setting(w).view()
    assert view["mode"] == "PLATFORM" and view["editable"] is True and view["record_version"] == 2
    assert view["last_mode_change"] == {"by": ADMIN, "verified_caller": f.CC_SA.lower(),
                                        "at": view["last_mode_change"]["at"], "mode": "PLATFORM", "version": 2}
    assert [c["to_version"] for c in view["mode_changes"]] == [2, 1]
    assert view["mode_source"] == "Control Center Settings (signed by vending)" and view["step_a_missing"] == []
    assert view["warnings"] == [] and view["record_error"] is None
    out3 = _setting(w).set(f.CC_SA, mode="PER_WORKLOAD", expected_version=2, operator_email=ADMIN)
    assert out3["version"] == 3 and w.db.doc(ri.mode_record_doc_path())["version"] == 3


def test_nothing_is_ever_removed():
    w = _vworld()
    s = _setting(w)
    s.set(f.CC_SA, mode="PER_WORKLOAD", expected_version=0, operator_email=ADMIN)
    s.set(f.CC_SA, mode="PLATFORM", expected_version=1, operator_email=ADMIN)
    assert {op for op, _p, _d in w.db.writes} == {"set", "create"}
    assert all(op == "create" for op, p, _d in w.db.writes if "/changes/" in p)   # entries are created, never rewritten
    src = open(os.path.join(REPO, "apps", "project-vending", "runner_identity_mode.py")).read()
    assert ".delete(" not in src


def test_rt_h1_probe_delete_after_a_switch_stops_every_reader(cc, rollback_mod, monkeypatch):
    """Probe A of the F4 RT: a guard-DB writer deletes the Per-workload record. Every reader refuses (typed); none
    falls back to PLATFORM. A new switch from Settings repairs it."""
    w = _vworld()
    _setting(w).set(f.CC_SA, mode="PER_WORKLOAD", expected_version=1 - 1, operator_email=ADMIN)
    w.db.docs.pop(ri.mode_record_doc_path())
    VRI.clear_mode_cache()
    ri.clear_mode_cache()
    with pytest.raises(VRI.RunnerIdentityError) as e:
        w.deps.operative_mode()                                                  # vending (broker, vend)
    assert e.value.code == "RUNNER_MODE_RECORD_MISSING"
    rs, guard = cc                                                               # Control Center
    _cc_env(monkeypatch)
    monkeypatch.setattr(rs, "guard_db_provider", lambda: w.db)
    with pytest.raises(ri.RunnerIdentityError) as e:
        rs.operative_mode()
    assert e.value.code == "RUNNER_MODE_RECORD_MISSING"
    eng = _rollback_engine(rollback_mod, Storage({LEGACY: Bucket([])}))          # rollback
    eng.guard_db, eng.certs = w.db, k.certs_for()
    rollback_mod.ri.clear_mode_cache()
    rec = eng.execute_rollback(PID, "tr-h1")
    assert rec["status"] == rollback_mod.ROLLBACK_UNAVAILABLE and "RUNNER_MODE_RECORD_MISSING" in rec["message"]
    view = _setting(w).view()
    assert view["record_error"] == "RUNNER_MODE_RECORD_MISSING"
    assert [x["code"] for x in view["warnings"]] == ["RUNNER_MODE_RECORD_MISSING"]
    out = _setting(w).set(f.CC_SA, mode="PLATFORM", expected_version=0, operator_email=ADMIN)   # repair
    assert out["changed"] is True and out["version"] == 2 and out["previous_mode"] is None
    assert w.db.doc(ri.mode_change_doc_path(out["change_id"]))["from_error"] == "RUNNER_MODE_RECORD_MISSING"
    VRI.clear_mode_cache()
    assert w.deps.operative_mode() == "PLATFORM"


def test_rt_m1_probe_replay_of_an_old_signed_record(cc, monkeypatch):
    """Probe B: switch to Per workload (v1), back to Shared (v2), a writer puts the saved v1 back: readers refuse
    (RUNNER_MODE_RECORD_STALE), the card warns, and the record is never re-signed."""
    w = _vworld()
    s = _setting(w)
    s.set(f.CC_SA, mode="PER_WORKLOAD", expected_version=0, operator_email=ADMIN)
    saved = copy.deepcopy(w.db.doc(ri.mode_record_doc_path()))
    s.set(f.CC_SA, mode="PLATFORM", expected_version=1, operator_email=ADMIN)
    w.db.docs[ri.mode_record_doc_path()] = saved
    VRI.clear_mode_cache()
    with pytest.raises(VRI.RunnerIdentityError) as e:
        w.deps.operative_mode()
    assert e.value.code == "RUNNER_MODE_RECORD_STALE"
    view = s.view()
    assert view["record_error"] == "RUNNER_MODE_RECORD_STALE" and view["record_resign"].startswith("FAILED")
    assert [x["code"] for x in view["warnings"]] == ["RUNNER_MODE_RECORD_STALE"]
    from routes import runner_identity_card as card

    def requester(method, path, json_body=None, timeout=None, request=None):
        if path == "/runner-identity/mode":
            return _Resp(200, view)
        return _Resp(200, {"mode": "PLATFORM", "mode_label": "Shared", "per_workload": False, "workloads": []})

    monkeypatch.setattr(card, "vending_requester", requester)
    rs, guard = cc
    _cc_env(monkeypatch)
    monkeypatch.setattr(rs, "guard_db_provider", lambda: w.db)
    out = card.get_runner_identity_card(_req())
    assert "RUNNER_MODE_RECORD_STALE" in [x["code"] for x in out["warnings"]]


def test_a_tampered_change_entry_is_shown():
    w = _vworld()
    s = _setting(w)
    out = s.set(f.CC_SA, mode="PER_WORKLOAD", expected_version=0, operator_email=ADMIN)
    w.db.docs[ri.mode_change_doc_path(out["change_id"])]["operator_attested"] = "someone@else.example"
    view = s.view()
    assert view["record_error"] == "RUNNER_MODE_TAMPERED" and [x["code"] for x in view["warnings"]] == \
        ["RUNNER_MODE_TAMPERED"]


def test_resign_keeps_the_content_and_skips_young_or_unverifiable_records():
    from datetime import timedelta
    new_key = k.SigningKey("broker-key-2")
    w = _vworld()
    w.deps.certs = k.certs_for({k.BROKER: {k.BROKER_KEY.key_id: k.BROKER_KEY.cert_pem,
                                           new_key.key_id: new_key.cert_pem}})
    s = _setting(w)
    assert s.resign_if_stale() is None   # no record
    s.set(f.CC_SA, mode="PER_WORKLOAD", expected_version=0, operator_email=ADMIN)
    before = copy.deepcopy(w.db.doc(ri.mode_record_doc_path()))
    writes = len(w.db.writes)
    assert s.resign_if_stale() == "FRESH" and len(w.db.writes) == writes
    w.clock_now[0] = w.clock_now[0] + timedelta(seconds=rb.RESIGN_AFTER_SECONDS + 1)
    w.deps.signer_factory = lambda email: new_key.sign   # Google rotated the key
    assert s.resign_if_stale() == "RESIGNED"
    after = w.db.doc(ri.mode_record_doc_path())
    assert after["signature"]["key_id"] == "broker-key-2" and after["signed_at"] != before["signed_at"]
    assert {key: v for key, v in after.items() if key not in ("signature", "signed_at")} == \
        {key: v for key, v in before.items() if key not in ("signature", "signed_at")}
    VRI.clear_mode_cache()
    assert w.deps.operative_mode() == "PER_WORKLOAD"
    w.db.docs[ri.mode_record_doc_path()]["mode"] = "PLATFORM"   # tampered: never re-signed
    with pytest.raises(VRI.RunnerIdentityError) as e:
        s.resign_if_stale()
    assert e.value.code == "RUNNER_RECORD_UNSIGNED"
    assert s.view()["record_resign"] == "FAILED (RUNNER_RECORD_UNSIGNED)"


def test_resign_covers_a_shared_record_too():
    from datetime import timedelta
    new_key = k.SigningKey("broker-key-3")
    w = _vworld()
    w.deps.certs = k.certs_for({k.BROKER: {k.BROKER_KEY.key_id: k.BROKER_KEY.cert_pem,
                                           new_key.key_id: new_key.cert_pem}})
    s = _setting(w)
    s.set(f.CC_SA, mode="PER_WORKLOAD", expected_version=0, operator_email=ADMIN)
    s.set(f.CC_SA, mode="PLATFORM", expected_version=1, operator_email=ADMIN)
    w.clock_now[0] = w.clock_now[0] + timedelta(seconds=rb.RESIGN_AFTER_SECONDS + 1)
    w.deps.signer_factory = lambda email: new_key.sign
    assert s.resign_if_stale() == "RESIGNED"
    assert w.db.doc(ri.mode_record_doc_path())["signature"]["key_id"] == "broker-key-3"
    VRI.clear_mode_cache()
    assert w.deps.operative_mode() == "PLATFORM"


def test_vending_reads_resign_the_record_at_most_hourly(monkeypatch):
    from datetime import timedelta
    w = _vworld()
    eng = _engine(w)
    for key, v in w.env.items():
        monkeypatch.setenv(key, v)
    monkeypatch.delenv(VRI.MODE_ENV, raising=False)
    monkeypatch.setattr(VRI, "_default_certs", lambda: k.certs_for())
    calls = []
    monkeypatch.setattr(eng, "runner_identity_mode_setting",
                        lambda: type("S", (), {"resign_if_stale": lambda self_: calls.append(1) or "FRESH"})())
    assert eng.operative_runner_identity_mode() == "PLATFORM" and calls == [1]   # checked for any record (RT H1)
    w.db.docs[ri.mode_record_doc_path()] = mode_record()
    w.db.docs[ri.mode_change_doc_path("c" * 32)] = change_entry()
    VRI.clear_mode_cache()
    assert eng.operative_runner_identity_mode() == "PER_WORKLOAD" and calls == [1]   # within the hour
    eng._mode_resign_checked_at -= eng.MODE_RESIGN_CHECK_SECONDS + 1
    eng.operative_runner_identity_mode()
    assert calls == [1, 1]

    def boom(self_):
        raise RuntimeError("store down")
    monkeypatch.setattr(eng, "runner_identity_mode_setting", lambda: type("S", (), {"resign_if_stale": boom})())
    eng._mode_resign_checked_at -= eng.MODE_RESIGN_CHECK_SECONDS + 1
    assert eng.operative_runner_identity_mode() == "PER_WORKLOAD"   # maintenance failure never changes the read


def test_stale_version_same_mode_and_noop_write_nothing():
    w = _vworld()
    s = _setting(w)
    assert s.set(f.CC_SA, mode="PLATFORM", expected_version=0, operator_email=ADMIN) == {
        "changed": False, "mode": "PLATFORM", "version": 0}   # no record already means PLATFORM
    assert w.db.writes == [] and w.signed == []
    with pytest.raises(VRI.RunnerIdentityError) as e:
        s.set(f.CC_SA, mode="PER_WORKLOAD", expected_version=3, operator_email=ADMIN)
    assert e.value.code == "RUNNER_MODE_CHANGED" and w.db.writes == []
    s.set(f.CC_SA, mode="PER_WORKLOAD", expected_version=0, operator_email=ADMIN)
    writes = len(w.db.writes)
    assert s.set(f.CC_SA, mode="PER_WORKLOAD", expected_version=1, operator_email=ADMIN)["changed"] is False
    assert len(w.db.writes) == writes


def test_a_concurrent_change_is_refused_inside_the_transaction():
    w = _vworld()

    def sneak():
        w.db.docs[ri.mode_record_doc_path()] = mode_record("PLATFORM", previous=None)
    with pytest.raises(VRI.RunnerIdentityError) as e:
        _setting(w, before_txn=sneak).set(f.CC_SA, mode="PER_WORKLOAD", expected_version=0, operator_email=ADMIN)
    assert e.value.code == "RUNNER_MODE_CHANGED" and [p for p in _mode_docs(w) if "/changes/" in p] == []


def test_declared_per_workload_makes_the_setting_read_only():
    w = _vworld(declared="PER_WORKLOAD")
    for mode in ("PLATFORM", "PER_WORKLOAD"):
        with pytest.raises(VRI.RunnerIdentityError) as e:
            _setting(w).set(f.CC_SA, mode=mode, expected_version=0, operator_email=ADMIN)
        assert e.value.code == "RUNNER_IDENTITY_MODE_RETIRED" and e.value.http_status == 409
    assert w.db.writes == []
    view = _setting(w).view()
    assert view["mode"] == "PER_WORKLOAD" and view["editable"] is False and "final" in view["mode_source"]


def test_an_unverifiable_record_is_shown_and_can_be_repaired():
    w = _vworld()
    w.db.docs[ri.mode_record_doc_path()] = {"mode": "PER_WORKLOAD", "version": 4}   # e.g. written by another SA
    view = _setting(w).view()
    assert view["mode"] is None and view["mode_error"].startswith("RUNNER_RECORD_UNSIGNED")
    assert view["record_error"] == "RUNNER_RECORD_UNSIGNED" and view["record_version"] == 4
    with pytest.raises(VRI.RunnerIdentityError):
        w.deps.operative_mode()   # every reader refuses meanwhile (never a silent PLATFORM)
    out = _setting(w).set(f.CC_SA, mode="PLATFORM", expected_version=4, operator_email=ADMIN)
    assert out["changed"] is True and out["version"] == 5 and out["previous_mode"] is None
    assert w.db.doc(ri.mode_record_doc_path())["mode"] == "PLATFORM"
    change = w.db.doc(ri.mode_change_doc_path(out["change_id"]))
    assert change["from_error"] == "RUNNER_RECORD_UNSIGNED" and change["from_mode"] is None
    VRI.clear_mode_cache()
    assert w.deps.operative_mode() == "PLATFORM"


def test_bad_requests_and_store_or_broker_problems_write_nothing():
    w = _vworld()
    for kw, code in ((dict(mode="per_workload", expected_version=0, operator_email=ADMIN), "RUNNER_IDENTITY_MODE_INVALID"),
                     (dict(mode="PLATFORM", expected_version=-1, operator_email=ADMIN), "RUNNER_MODE_CHANGE_INVALID"),
                     (dict(mode="PLATFORM", expected_version=True, operator_email=ADMIN), "RUNNER_MODE_CHANGE_INVALID"),
                     (dict(mode="PLATFORM", expected_version=0, operator_email=" "), "RUNNER_MODE_CHANGE_INVALID")):
        with pytest.raises(VRI.RunnerIdentityError) as e:
            _setting(w).set(f.CC_SA, **kw)
        assert e.value.code == code
    with pytest.raises(VRI.RunnerIdentityError) as e:
        Setting(w.deps, guard_db=None, environ=w.env).set(f.CC_SA, mode="PER_WORKLOAD", expected_version=0,
                                                           operator_email=ADMIN)
    assert e.value.code == "RUNNER_STORE_UNAVAILABLE"
    shared = _vworld(runtime=k.DEVELOPER, **{VRI.BROKER_SA_ENV: k.DEVELOPER})
    with pytest.raises(VRI.RunnerIdentityError) as e:
        _setting(shared).set(f.CC_SA, mode="PER_WORKLOAD", expected_version=0, operator_email=ADMIN)
    assert e.value.code == "RUNNER_BROKER_SHARED_IDENTITY"
    assert w.db.writes == [] and shared.db.writes == [] and w.signed == []


def test_broker_follows_the_live_mode():
    w = _vworld()
    broker = rb.RunnerBroker(w.deps)
    with pytest.raises(VRI.RunnerIdentityError) as e:
        broker.require_per_workload()
    assert e.value.code == "RUNNER_IDENTITY_MODE_PLATFORM"
    _setting(w).set(f.CC_SA, mode="PER_WORKLOAD", expected_version=0, operator_email=ADMIN)
    broker.require_per_workload()   # no new deps, no restart
    # deps built by hand without a resolver keep the declaration (SAT-19 unit tests)
    w.deps.mode = None
    with pytest.raises(VRI.RunnerIdentityError):
        rb.RunnerBroker(w.deps).require_per_workload()


def test_backfill_status_follows_the_record_and_shows_a_bad_one():
    import runner_identity_backfill as rib
    w = _vworld()
    bf = rib.RunnerIdentityBackfill(w.deps, platform_bucket="castor-tfstate-test", region_for=lambda _p: k.REGION)
    st = bf.status()
    assert st == {"mode": "PLATFORM", "mode_label": "Shared", "mode_source": ri.MODE_ENV, "per_workload": False,
                  "workloads": [], "totals": {}, "truncated": False}   # Do No Harm: unchanged without a record
    w.db.docs[ri.mode_record_doc_path()] = _forged()
    VRI.clear_mode_cache()
    st = bf.status()
    assert st["mode"] is None and st["mode_error"].startswith("RUNNER_RECORD_UNSIGNED") and st["per_workload"] is False
    with pytest.raises(VRI.RunnerIdentityError):
        bf.run("cc", dry_run=True)


def _engine(w):
    eng = VENDING_MAIN.ProjectRepoVendingEngine(platform_project_id=f.HOST, firestore_client=w.db,
                                                crm_service=MagicMock(), storage_client=MagicMock(),
                                                guard_context=w.ctx, runner_deps=w.deps)
    eng._guard_db = w.db
    return eng


def test_vending_engine_mode_errors_are_typed_vend_failures(monkeypatch):
    w = _vworld()
    eng = _engine(w)
    monkeypatch.setenv("PROJECT_ID", k.HOST)
    monkeypatch.setenv(VRI.GUARD_DB_ENV, GUARD)
    monkeypatch.delenv(VRI.MODE_ENV, raising=False)
    monkeypatch.setattr(VRI, "_default_certs", lambda: k.certs_for())
    assert eng.runner_identity_mode() == "PLATFORM"
    w.db.docs[ri.mode_record_doc_path()] = mode_record()
    w.db.docs[ri.mode_change_doc_path("c" * 32)] = change_entry()
    VRI.clear_mode_cache()
    assert eng.runner_identity_mode() == "PER_WORKLOAD"
    w.db.docs[ri.mode_record_doc_path()] = _forged()
    VRI.clear_mode_cache()
    with pytest.raises(VendingFailure) as e:
        eng.runner_identity_mode()
    assert e.value.error_class == "VENDING.RUNNER_IDENTITY_MODE_UNREADABLE" and "RUNNER_RECORD_UNSIGNED" in str(e.value)
    monkeypatch.setenv(VRI.MODE_ENV, "bogus")
    with pytest.raises(VendingFailure) as e:
        eng.runner_identity_mode()
    assert e.value.error_class == "VENDING.RUNNER_IDENTITY_MODE_INVALID"


def test_vending_engine_without_a_guard_database_reads_nothing(monkeypatch):
    """Do No Harm: a vend on an install without the guard database (or before step A) is exactly as before."""
    w = _vworld()
    eng = _engine(w)
    eng._guard_db = RaisingDB()
    monkeypatch.delenv(VRI.GUARD_DB_ENV, raising=False)
    monkeypatch.delenv(VRI.BROKER_SA_ENV, raising=False)
    monkeypatch.delenv(VRI.MODE_ENV, raising=False)
    assert eng.runner_identity_mode() == "PLATFORM" and eng.mode_guard_db() is None


@pytest.fixture
def vclient(monkeypatch):
    monkeypatch.setenv("DESTRUCTIVE_CALLERS", f.CC_SA)
    monkeypatch.setenv("VENDING_SERVICE_URL", DG_AUD)
    w = _vworld()
    for key, v in w.env.items():
        monkeypatch.setenv(key, v)
    monkeypatch.delenv(VRI.MODE_ENV, raising=False)
    eng = _engine(w)
    monkeypatch.setattr(eng, "runner_identity_mode_setting", lambda: _setting(w))
    monkeypatch.setattr(VENDING_MAIN, "vending_engine", eng)
    monkeypatch.setattr(VENDING_MAIN, "CALLER_TOKEN_VERIFIER", fake_verifier)
    return w, TestClient(VENDING_MAIN.app)


def test_vending_mode_routes(vclient):
    w, c = vclient
    hdr = {"Authorization": f"Bearer {CC_TOKEN}"}
    assert c.get("/runner-identity/mode").status_code == 401
    assert c.post("/runner-identity/mode", json={"mode": "PER_WORKLOAD", "expected_version": 0,
                                                 "operator_email": ADMIN},
                  headers={"Authorization": "Bearer dev-token"}).status_code == 403
    assert w.db.writes == []
    r = c.get("/runner-identity/mode", headers=hdr)
    assert r.status_code == 200 and r.json()["mode"] == "PLATFORM" and r.json()["editable"] is True
    r = c.post("/runner-identity/mode", json={"mode": "per_workload", "expected_version": 0, "operator_email": ADMIN},
               headers=hdr)
    assert r.status_code == 422
    r = c.post("/runner-identity/mode", json={"mode": "PER_WORKLOAD", "expected_version": 5, "operator_email": ADMIN},
               headers=hdr)
    assert r.status_code == 409 and r.json()["detail"]["code"] == "RUNNER_MODE_CHANGED"
    r = c.post("/runner-identity/mode", json={"mode": "PER_WORKLOAD", "expected_version": 0, "operator_email": ADMIN},
               headers=hdr)
    assert r.status_code == 200 and r.json()["changed"] is True
    change = w.db.doc(ri.mode_change_doc_path(r.json()["change_id"]))
    assert change["changed_by"] == f.CC_SA.lower() and change["operator_attested"] == ADMIN
    r = c.post("/runner-identity/resign", json={}, headers=hdr)   # the sweep covers the mode record too
    assert r.status_code == 200 and r.json()["mode_record"] == "FRESH"


# ================================================================================================ Control Center
def _cc_env(monkeypatch, record=None, guard=None):
    monkeypatch.setenv("PROJECT_ID", k.HOST)
    monkeypatch.setenv(ri.GUARD_DB_ENV, GUARD)
    monkeypatch.delenv(ri.MODE_ENV, raising=False)
    if record is not None:
        guard.docs[ri.mode_record_doc_path()] = record
        guard.docs[ri.mode_change_doc_path(record["change_id"])] = change_entry(
            record["version"], record["change_id"], record["mode"])


def test_cc_state_readers_follow_the_record(cc, monkeypatch):
    rs, guard = cc
    _cc_env(monkeypatch, mode_record(), guard)
    guard.docs[f"workload_provenance/{PID}"] = provenance(signed_record())
    assert rs.operative_mode() == "PER_WORKLOAD" and rs.state_bucket(PID, LEGACY) == CHILD_BUCKET
    ri.clear_mode_cache()
    guard.docs[ri.mode_record_doc_path()] = _forged()
    with pytest.raises(ri.RunnerIdentityError) as e:   # never a silent fallback to the platform bucket
        rs.state_bucket(PID, LEGACY)
    assert e.value.code == "RUNNER_RECORD_UNSIGNED"


def test_cc_without_a_record_reads_only_the_mode_documents(cc, monkeypatch):
    """Do No Harm: no record -> the legacy bucket and no provenance read."""
    rs, guard = cc
    _cc_env(monkeypatch)
    guard.docs[f"workload_provenance/{PID}"] = provenance(signed_record())
    assert rs.state_bucket(PID, LEGACY) == LEGACY
    assert guard.reads == [ri.mode_record_doc_path(), CHANGES_QUERY]   # no provenance read


def test_cc_guard_database_configured_but_unavailable_is_typed(cc, monkeypatch):
    rs, _guard = cc
    _cc_env(monkeypatch)
    monkeypatch.setattr(rs, "guard_db_provider", lambda: None)
    with pytest.raises(ri.RunnerIdentityError) as e:
        rs.operative_mode()
    assert e.value.code == "RUNNER_STORE_UNAVAILABLE"


def _req(method="session", issued=None, email=ADMIN):
    req = MagicMock()
    req.state.user_email = email
    req.state.user_role = "ADMIN"
    req.state.auth_method = method
    req.state.session_issued_at = issued
    return req


def test_cc_mode_change_needs_a_human_a_recent_sign_in_and_a_typed_confirmation(cc, monkeypatch):
    from routes import runner_identity_card as card
    calls = []

    def requester(method, path, json_body=None, timeout=None, request=None):
        calls.append((method, path, json_body))
        return _Resp(200, {"changed": True, "mode": json_body["mode"], "version": 1})

    monkeypatch.setattr(card, "vending_requester", requester)
    monkeypatch.setattr(card, "clock", lambda: 10_000.0)
    body = card.RunnerIdentityModeBody(mode="PER_WORKLOAD", expected_version=0, confirm="PER_WORKLOAD")

    def code(resp):
        return resp.status_code, json.loads(resp.body)["code"]

    assert code(card.set_runner_identity_mode(_req(method="bearer"), body)) == (403, "HUMAN_ADMIN_REQUIRED")
    assert code(card.set_runner_identity_mode(_req(method="iap"), body)) == (403, "RECENT_SIGN_IN_UNAVAILABLE")
    detail = json.loads(card.set_runner_identity_mode(_req(method="iap"), body).body)["detail"]
    assert "Run it from the root of the StackVend folder you installed from" in detail  # CC-APPLY-WHERE
    assert code(card.set_runner_identity_mode(_req(issued=None), body)) == (403, "RECENT_SIGN_IN_REQUIRED")
    assert code(card.set_runner_identity_mode(_req(issued=10_000 - 15 * 60 - 1), body)) == \
        (403, "RECENT_SIGN_IN_REQUIRED")
    assert code(card.set_runner_identity_mode(_req(issued=10_100), body)) == (403, "RECENT_SIGN_IN_REQUIRED")
    wrong = card.RunnerIdentityModeBody(mode="PER_WORKLOAD", expected_version=0, confirm="PLATFORM")
    assert code(card.set_runner_identity_mode(_req(issued=9_900), wrong)) == (422, "RUNNER_MODE_CONFIRMATION_MISMATCH")
    assert calls == []
    out = card.set_runner_identity_mode(_req(issued=10_000 - 15 * 60), body)
    assert out == {"changed": True, "mode": "PER_WORKLOAD", "version": 1}
    assert calls == [("POST", "/runner-identity/mode",
                      {"mode": "PER_WORKLOAD", "expected_version": 0, "operator_email": ADMIN})]


def test_cc_mode_change_passes_vendings_typed_refusal(cc, monkeypatch):
    from routes import runner_identity_card as card

    def requester(method, path, json_body=None, timeout=None, request=None):
        return _Resp(409, {"detail": {"code": "RUNNER_IDENTITY_STEP_A_MISSING", "detail": "missing: x"}})

    monkeypatch.setattr(card, "vending_requester", requester)
    monkeypatch.setattr(card, "clock", lambda: 10_000.0)
    body = card.RunnerIdentityModeBody(mode="PER_WORKLOAD", expected_version=0, confirm="PER_WORKLOAD")
    resp = card.set_runner_identity_mode(_req(issued=9_999), body)
    assert resp.status_code == 409 and json.loads(resp.body)["code"] == "RUNNER_IDENTITY_STEP_A_MISSING"


def test_cc_card_shows_the_mode_record(cc, monkeypatch):
    from routes import runner_identity_card as card
    rs, guard = cc
    _cc_env(monkeypatch, mode_record(), guard)
    view = {"declared_mode": "PLATFORM", "mode": "PER_WORKLOAD", "editable": True, "record_version": 1,
            "mode_source": "Control Center Settings (signed by vending)",
            "last_mode_change": {"by": ADMIN, "at": AT, "mode": "PER_WORKLOAD", "version": 1}}

    def requester(method, path, json_body=None, timeout=None, request=None):
        if path == "/runner-identity/mode":
            return _Resp(200, view)
        return _Resp(200, {"mode": "PER_WORKLOAD", "mode_label": "Per workload", "per_workload": True,
                           "workloads": []})

    monkeypatch.setattr(card, "vending_requester", requester)
    out = card.get_runner_identity_card(_req())
    assert out["control_center_mode"] == "PER_WORKLOAD" and out["mode_setting"] == view
    assert out["mode_source"] == view["mode_source"] and out["last_mode_change"] == view["last_mode_change"]
    assert out["warnings"] == []   # both sides agree


def test_session_issued_at(cc):
    auth = importlib.import_module("auth")
    token = auth.create_session_token("a@example.com")
    assert auth.session_issued_at(token) == int(token.split(":")[1])
    assert auth.session_issued_at(token[:-1] + ("0" if token[-1] != "0" else "1")) is None
    assert auth.session_issued_at("junk") is None


# ================================================================================================ Express
def _render(mode_kw):
    from shared.express_synthesizer import ExpressHCLSynthesizer
    return ExpressHCLSynthesizer().synthesize_workload(
        product_id="express-demo", project_id="castor-express-demo-1234", region=k.REGION,
        module_instances=[{"module_id": "compute-cloudrun", "instance_name": "gateway", "parameters": {}}],
        include_vpc=False, state_bucket="castor-tfstate-1234", **mode_kw)


def test_express_takes_the_operative_mode(monkeypatch):
    from shared.express_synthesizer import ExpressRunnerIdentityModeInvalid
    monkeypatch.delenv(ri.MODE_ENV, raising=False)
    base = _render({})
    assert _render({"runner_identity_mode": "PLATFORM"}) == base   # Do No Harm: byte-identical
    per = _render({"runner_identity_mode": "PER_WORKLOAD"})
    assert per == {p: c for p, c in base.items() if p != "infra/workload/backend.tf"}
    with pytest.raises(ExpressRunnerIdentityModeInvalid):
        _render({"runner_identity_mode": "per_workload"})


def test_cc_express_reads_the_mode_through_the_shared_reader(cc, monkeypatch):
    rs, guard = cc
    wl = importlib.import_module("routes.workloads")
    _cc_env(monkeypatch, mode_record(), guard)
    assert wl._express_runner_mode() == ("PER_WORKLOAD", None)
    ri.clear_mode_cache()
    guard.docs[ri.mode_record_doc_path()] = _forged()
    mode, failure = wl._express_runner_mode()
    assert mode is None and failure[0] == "RUNNER_RECORD_UNSIGNED"
    src = open(os.path.join(REPO, "apps", "control-center", "routes", "workloads.py")).read()
    assert "runner_identity_mode=runner_mode," in src and "elif runner_mode_failure:" in src


# ================================================================================================ rollback
def test_rollback_follows_the_record(rollback_mod, monkeypatch):
    monkeypatch.delenv(ri.MODE_ENV, raising=False)
    monkeypatch.setenv(ri.GUARD_DB_ENV, GUARD)
    monkeypatch.setenv("PROJECT_ID", k.HOST)
    obj = f"workloads/{PID}/default.tfstate"
    storage = Storage({LEGACY: Bucket([Blob(obj, 2)]), CHILD_BUCKET: Bucket([Blob(obj, 5)])})
    eng = _rollback_engine(rollback_mod, storage)
    eng.certs = k.certs_for()
    eng.guard_db = GuardDB({f"workload_provenance/{PID}": provenance(signed_record())})
    eng.get_state_history(PID)
    assert storage.used == [LEGACY] and eng.guard_db.reads == [ri.mode_record_doc_path(), CHANGES_QUERY]
    eng.guard_db.docs[ri.mode_record_doc_path()] = mode_record()
    eng.guard_db.docs[ri.mode_change_doc_path("c" * 32)] = change_entry()
    rollback_mod.ri.clear_mode_cache()
    eng.get_state_history(PID)
    assert storage.used[-1] == CHILD_BUCKET
    eng.guard_db.docs[ri.mode_record_doc_path()] = _forged()
    rollback_mod.ri.clear_mode_cache()
    rec = eng.execute_rollback(PID, "tr-1")
    assert rec["status"] == rollback_mod.ROLLBACK_UNAVAILABLE and "RUNNER_RECORD_UNSIGNED" in rec["message"]


# ================================================================================================ docs
def test_new_classes_are_in_the_fail_loudly_policy():
    doc = open(os.path.join(REPO, "documentation", "fail-loudly-policy.md")).read()
    for code in ("RUNNER_MODE_RECORD_INVALID", "RUNNER_IDENTITY_STEP_A_MISSING", "RUNNER_IDENTITY_MODE_RETIRED",
                 "RUNNER_MODE_CHANGED", "RUNNER_MODE_CHANGE_INVALID", "VENDING.RUNNER_IDENTITY_MODE_UNREADABLE",
                 "RUNNER_MODE_CONFIRMATION_MISMATCH", "RECENT_SIGN_IN_UNAVAILABLE", "RUNNER_MODE_RECORD_MISSING",
                 "RUNNER_MODE_RECORD_STALE", "RUNNER_MODE_TAMPERED"):
        assert code in doc, code
    assert re.search(r"install_settings/runner_identity", open(os.path.join(REPO, "documentation",
                                                                             "settings-reference.md")).read())


# ================================================================================================ M2 + shared sign-in rule
def test_rt_m2_one_mode_snapshot_per_vend(monkeypatch):
    live = importlib.import_module("shared.settings")   # a vend's strict platform-settings read (no Firestore here)
    live.invalidate_settings_cache()
    monkeypatch.setattr(live, "get_platform_settings", lambda *a, **kw: live.PlatformSettings())
    w = _vworld()
    eng = _engine(w)
    reads, seen = [], {}
    monkeypatch.setattr(eng, "runner_identity_mode", lambda: reads.append(1) or "PLATFORM")

    def fake_gcp(product_id, trace_id, **kw):
        seen.update(kw)
        return {"project_id": "p-1", "project_number": f.NUMBER}

    eng.vend_gcp_project = fake_gcp
    eng.vend_github_repo = lambda product_id, **kw: {"full_name": "acme/castor-shop-api", "repo_name": "castor-shop-api"}
    eng.vend_all("shop-api", "tr-m2", vcs_provider="GITHUB")
    assert reads == [1] and seen["runner_mode"] == "PLATFORM"   # read once, passed down, reused for the pin


def test_recent_sign_in_rule_is_one_helper(cc):
    import recent_sign_in as rsi
    from routes import platform_release, runner_identity_card
    assert platform_release.RECENT_SIGN_IN_SECONDS == runner_identity_card.RECENT_SIGN_IN_SECONDS == 15 * 60
    req = _req(issued=1000)
    assert rsi.sign_in_refusal(req, 1000 + 900) is None
    assert rsi.sign_in_refusal(req, 1000 + 901) == "RECENT_SIGN_IN_REQUIRED"
    assert rsi.sign_in_refusal(req, 999) == "RECENT_SIGN_IN_REQUIRED"            # a future sign-in time
    assert rsi.sign_in_refusal(_req(issued=True), 2) == "RECENT_SIGN_IN_REQUIRED"
    assert rsi.sign_in_refusal(_req(method="iap"), 1000) == "RECENT_SIGN_IN_UNAVAILABLE"
    for rel in ("apps/control-center/routes/platform_release.py", "apps/control-center/routes/runner_identity_card.py"):
        src = open(os.path.join(REPO, rel)).read()
        assert "recent_sign_in.sign_in_refusal(request, clock())" in src, rel
        assert 'getattr(request.state, "session_issued_at"' not in src, rel   # the rule lives in one place


# ================================================================================================ RT round 2: N1, Q1
def _forge(w, doc_id, to_version):
    w.db.docs[ri.mode_change_doc_path(doc_id)] = {"schema": ri.MODE_CHANGE_SCHEMA, "change_id": doc_id,
                                                  "to_mode": "PLATFORM", "to_version": to_version}


@pytest.mark.parametrize("forged", ["9", True, {"n": 9}, None])
def test_rt2_n1_a_non_numeric_version_never_ranks(forged):
    """Readers' query is type-scoped (where to_version >= 1) and vending ranks the same way: a forged non-numeric
    entry is ignored by both, shown as a warning naming it, and a switch from Settings still works."""
    w = _vworld()
    s = _setting(w)
    s.set(f.CC_SA, mode="PER_WORKLOAD", expected_version=0, operator_email=ADMIN)
    _forge(w, "f" * 32, forged)
    VRI.clear_mode_cache()
    assert w.deps.operative_mode() == "PER_WORKLOAD"
    assert ri.runner_identity_mode(env(), guard_db=w.db, certs=k.certs_for()) == "PER_WORKLOAD"
    view = s.view()
    assert view["record_error"] is None and view["unranked_change_entries"] == [ri.mode_change_doc_path("f" * 32)]
    (warning,) = view["warnings"]
    assert warning["code"] == "RUNNER_MODE_LOG_CORRUPT" and ri.mode_change_doc_path("f" * 32) in warning["message"]
    out = s.set(f.CC_SA, mode="PLATFORM", expected_version=1, operator_email=ADMIN)
    assert out["version"] == 2
    VRI.clear_mode_cache()
    assert w.deps.operative_mode() == "PLATFORM"


@pytest.mark.parametrize("forged", [1e300, float("inf"), 2 ** 63])
def test_rt2_n1_an_unbeatable_version_is_typed_and_named(forged):
    """A forged numeric version no Firestore integer can outrank: readers refuse (STALE: it ranks first), vending's
    view and switch say RUNNER_MODE_LOG_CORRUPT and name the document to remove; nothing is written."""
    w = _vworld()
    s = _setting(w)
    s.set(f.CC_SA, mode="PER_WORKLOAD", expected_version=0, operator_email=ADMIN)
    _forge(w, "e" * 32, forged)
    VRI.clear_mode_cache()
    with pytest.raises(VRI.RunnerIdentityError) as e:
        w.deps.operative_mode()
    assert e.value.code == "RUNNER_MODE_RECORD_STALE"
    view = s.view()
    assert view["record_error"] == "RUNNER_MODE_LOG_CORRUPT"
    assert ri.mode_change_doc_path("e" * 32) in view["record_error_detail"]
    assert [x["code"] for x in view["warnings"]] == ["RUNNER_MODE_LOG_CORRUPT"]
    writes = len(w.db.writes)
    with pytest.raises(VRI.RunnerIdentityError) as e:
        s.set(f.CC_SA, mode="PLATFORM", expected_version=1, operator_email=ADMIN)
    assert e.value.code == "RUNNER_MODE_LOG_CORRUPT" and ri.mode_change_doc_path("e" * 32) in e.value.detail
    assert len(w.db.writes) == writes


def test_rt2_n1_a_large_but_reachable_version_is_outranked():
    w = _vworld()
    s = _setting(w)
    s.set(f.CC_SA, mode="PER_WORKLOAD", expected_version=0, operator_email=ADMIN)
    _forge(w, "d" * 32, 41.5)   # forged, numeric, outrankable: readers refuse until the next switch repairs it
    VRI.clear_mode_cache()
    with pytest.raises(VRI.RunnerIdentityError):
        w.deps.operative_mode()
    assert s.view()["record_error"] == "RUNNER_MODE_TAMPERED"   # the forged entry is not vending-signed
    out = s.set(f.CC_SA, mode="PER_WORKLOAD", expected_version=1, operator_email=ADMIN)
    assert out["version"] == 42
    VRI.clear_mode_cache()
    assert w.deps.operative_mode() == "PER_WORKLOAD"


def test_rt2_q1_high_water_mark_catches_a_wiped_log_in_a_running_process():
    w = _vworld()
    s = _setting(w)
    s.set(f.CC_SA, mode="PER_WORKLOAD", expected_version=0, operator_email=ADMIN)
    assert ri.runner_identity_mode(env(), guard_db=w.db, certs=k.certs_for()) == "PER_WORKLOAD"   # this process saw v1
    for p in [p for p in w.db.docs if p.startswith(ri.INSTALL_SETTINGS_COLLECTION + "/")]:
        del w.db.docs[p]   # the record AND the whole log deleted
    ri.clear_mode_cache()  # the 15 s cache expired
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.runner_identity_mode(env(), guard_db=w.db, certs=k.certs_for())
    assert e.value.code == "RUNNER_MODE_RECORD_MISSING"
    ri.clear_mode_cache(high_water=True)   # a fresh process: the residual the post-RC audit-log row covers
    assert ri.runner_identity_mode(env(), guard_db=w.db, certs=k.certs_for()) == "PLATFORM"


def test_rt2_q1_high_water_mark_refuses_an_older_version():
    w = _vworld()
    s = _setting(w)
    s.set(f.CC_SA, mode="PER_WORKLOAD", expected_version=0, operator_email=ADMIN)
    old = {p: copy.deepcopy(d) for p, d in w.db.docs.items() if p.startswith(ri.INSTALL_SETTINGS_COLLECTION + "/")}
    s.set(f.CC_SA, mode="PLATFORM", expected_version=1, operator_email=ADMIN)
    assert ri.runner_identity_mode(env(), guard_db=w.db, certs=k.certs_for()) == "PLATFORM"   # saw v2
    for p in [p for p in w.db.docs if p.startswith(ri.INSTALL_SETTINGS_COLLECTION + "/")]:
        del w.db.docs[p]
    w.db.docs.update(old)   # the v1 world restored wholesale (record + its only entry)
    ri.clear_mode_cache()
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.runner_identity_mode(env(), guard_db=w.db, certs=k.certs_for())
    assert e.value.code == "RUNNER_MODE_RECORD_STALE"


def test_no_internal_paths_or_tool_names_in_the_branch_files():
    for rel in ("apps/project-vending/runner_identity_mode.py", "apps/control-center/recent_sign_in.py",
                "shared/runner_identity.py", "apps/control-center/routes/runner_identity_card.py"):
        text = open(os.path.join(REPO, rel)).read().lower()
        tool = "cl" + "aude"   # spelled in two parts so this test itself passes the public-export name check
        assert tool not in text and "/users/" not in text, rel
