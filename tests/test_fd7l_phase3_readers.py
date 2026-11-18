"""
FD-7L Phase 3 off the vending service: shared state-location helpers (shared/runner_identity.py), the Control Center
state readers (services/runner_state.py, routes/workloads.py resources view, services/finops_sync.py), the rollback
engine (apps/infra-rollback/rollback.py), the Express backend (shared/express_synthesizer.py x3) and the Settings card
(routes/runner_identity_card.py). Hermetic fakes only.

Do No Harm: on a Shared install (STACKVEND_TF_RUNNER_IDENTITY unset / PLATFORM) every reader uses exactly today's
bucket and object without any guard-database read, and Express output is byte-identical.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import json
import os
import sys
import types
from datetime import datetime, timezone

import pytest

import fd7l_fakes as k
from shared import runner_identity as ri

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO, "apps", "control-center")
PID, PROJECT, NUMBER = "shop-api", "shop-api-a1b2c3", "123456789012"
CHILD_BUCKET = f"{PROJECT}-tfstate"
LEGACY = "castor-tfstate-mock-stackvend-project"
SIGNED_AT = "2026-10-31T12:00:00+00:00"


def _load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def signed_record(status="READY", key=k.BROKER_KEY, signer=k.BROKER, bucket=CHILD_BUCKET, **over):
    rec = ri.new_runner_identity_record(product_id=PID, project_id=PROJECT, project_number=NUMBER,
                                        state_bucket=bucket, status=status, updated_at=SIGNED_AT)
    rec.update(over)
    return ri.sign_record(ri.provenance_doc_path(PID), rec, signer_email=signer, signed_at=SIGNED_AT,
                          sign_blob=key.sign)


def forged():
    """Signed with another key but claiming the broker's published key id: a forgery (RUNNER_RECORD_UNSIGNED)."""
    rec = signed_record(key=k.OTHER_KEY)
    rec["signature"] = dict(rec["signature"], key_id=k.BROKER_KEY.key_id)
    return rec


def provenance(record=None):
    doc = {"created_by": "stackvend-vending", "project_id": PROJECT, "project_number": NUMBER}
    if record is not None:
        doc[ri.RUNNER_IDENTITY_FIELD] = record
    return doc


class _Snap:
    def __init__(self, data):
        self.exists = data is not None
        self._d = data

    def to_dict(self):
        return dict(self._d) if self._d is not None else None


class GuardDB:
    def __init__(self, docs=None):
        self.docs = docs or {}
        self.reads = []

    def collection(self, name):
        db = self

        class _C:
            def document(self, doc_id):
                class _D:
                    def get(self_inner):
                        db.reads.append(f"{name}/{doc_id}")
                        return _Snap(db.docs.get(f"{name}/{doc_id}"))

                    def collection(self_inner, sub):   # FD-7L-F4: the mode change log (limit / order_by queries)
                        return _Q(f"{name}/{doc_id}/{sub}", db=db)
                return _D()
        return _C()


class _Q:
    """GuardDB sub-collection query: limit(n) / order_by(field, direction) / stream, reads logged as '<path>?query'."""

    def __init__(self, path, field=None, desc=False, n=None, db=None, at_least=None):
        self.path, self.field, self.desc, self.n, self.db, self.at_least = path, field, desc, n, db, at_least

    def where(self, field, op, value):   # a type-scoped numeric range filter (op ">=" only), as Firestore applies it
        assert op == ">="
        return _Q(self.path, self.field, self.desc, self.n, self.db, (field, value))

    def order_by(self, field, direction="ASCENDING"):
        return _Q(self.path, field, direction == "DESCENDING", self.n, self.db, self.at_least)

    def limit(self, n):
        return _Q(self.path, self.field, self.desc, n, self.db, self.at_least)

    def stream(self):
        db = self.db
        db.reads.append(f"{self.path}?query")
        rows = [(p, d) for p, d in sorted(db.docs.items())
                if p.startswith(self.path + "/") and "/" not in p[len(self.path) + 1:]]
        if self.at_least is not None:
            f, low = self.at_least
            rows = [r for r in rows if not isinstance(r[1].get(f), bool) and isinstance(r[1].get(f), (int, float))
                    and r[1].get(f) >= low]
        if self.field is not None:
            rows.sort(key=lambda r: r[1].get(self.field) or 0, reverse=self.desc)
        rows = rows if self.n is None else rows[:self.n]
        return iter([_Snap(d) for _p, d in rows])


# ---------------------------------------------------------------------------------------------- shared helpers
def test_lock_and_tombstone_helpers_use_exact_fields():
    tomb = ri.lock_info(operation=ri.TOMBSTONE_OPERATION, lock_id="x", info=ri.tombstone_info(CHILD_BUCKET, PID),
                        path=ri.lock_object_name(PID), created=SIGNED_AT)
    assert set(tomb) == {"ID", "Operation", "Info", "Who", "Version", "Created", "Path"}
    assert ri.is_tombstone(tomb) and not ri.is_migration_lock(tomb)
    assert tomb["Info"].startswith(ri.TOMBSTONE_MARKER) and f"gs://{CHILD_BUCKET}/workloads/{PID}" in tomb["Info"]
    # an ordinary OpenTofu lock (or a lock that only mentions the marker in Info) is not a tombstone
    assert not ri.is_tombstone({"ID": "1", "Operation": "OperationTypeApply", "Info": ri.TOMBSTONE_MARKER,
                                "Who": "x"})
    assert not ri.is_tombstone(None) and not ri.is_tombstone("STACKVEND_STATE_MOVED")
    lock = ri.lock_info(operation=ri.MIGRATION_LOCK_OPERATION, lock_id="m-1", info="i", path="p", created="c")
    assert ri.is_migration_lock(lock, "m-1") and not ri.is_migration_lock(lock, "m-2")
    assert ri.state_object_name(PID) == f"workloads/{PID}/default.tfstate"
    assert ri.lock_object_name(PID) == f"workloads/{PID}/default.tflock"


def test_expected_broker_email():
    assert ri.expected_broker_email({"PROJECT_ID": "h-proj"}) == "sa-project-provisioner@h-proj.iam.gserviceaccount.com"
    assert ri.expected_broker_email({"PROJECT_ID": "h", ri.BROKER_SA_ENV: " B@X.iam.gserviceaccount.com"}) \
        == "b@x.iam.gserviceaccount.com"
    assert ri.expected_broker_email({}) is None


def test_state_location_rules():
    certs = k.certs_for()
    kw = dict(legacy_bucket=LEGACY, expected_signer=k.BROKER, certs=certs)
    assert ri.state_location(PID, None, **kw)["bucket"] == LEGACY
    assert ri.state_location(PID, provenance(), **kw) == {"bucket": LEGACY, "prefix": f"workloads/{PID}",
                                                          "source": "platform", "status": "NONE"}
    assert ri.state_location(PID, provenance(signed_record()), **kw)["bucket"] == CHILD_BUCKET
    for status in ("BUCKET_READY", "MIGRATING", "FAILED"):
        loc = ri.state_location(PID, provenance(signed_record(status)), **kw)
        assert loc["bucket"] == LEGACY and loc["status"] == status
    for bad in (forged(), dict(signed_record(), state_bucket="someone-else-tfstate"),
                {"schema": ri.SCHEMA, "status": "READY"}, signed_record(signer=k.CC, key=k.OTHER_KEY)):
        with pytest.raises(ri.RunnerIdentityError) as e:
            ri.state_location(PID, provenance(bad), **kw)
        assert e.value.code == "RUNNER_RECORD_UNSIGNED"
    with pytest.raises(ri.RunnerIdentityError) as e:   # a retired broker key: refused too (SAT-19 RT F1)
        ri.state_location(PID, provenance(signed_record(key=k.OTHER_KEY)), **kw)
    assert e.value.code == "RUNNER_RECORD_KEY_RETIRED"
    with pytest.raises(ri.RunnerIdentityError) as e:   # validly signed, but names another project's bucket
        ri.state_location(PID, provenance(signed_record(bucket="other-proj-1-tfstate")), **kw)
    assert e.value.code == "RUNNER_TARGET_MISMATCH"
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.state_location(PID, provenance(signed_record()), legacy_bucket=LEGACY, expected_signer=None, certs=certs)
    assert e.value.code == "RUNNER_RECORD_UNVERIFIABLE"


# ---------------------------------------------------------------------------------------------- Control Center
@pytest.fixture
def cc(monkeypatch):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    monkeypatch.setattr(cc_db, "_db_client", False)
    rs = importlib.import_module("services.runner_state")
    guard = GuardDB()
    monkeypatch.setattr(rs, "guard_db_provider", lambda: guard)
    monkeypatch.setattr(rs, "certs_provider", k.certs_for())
    return rs, guard


def test_cc_state_location_shared_install_reads_nothing(cc, monkeypatch):
    rs, guard = cc
    for value in (None, "", "PLATFORM"):
        if value is None:
            monkeypatch.delenv(ri.MODE_ENV, raising=False)
        else:
            monkeypatch.setenv(ri.MODE_ENV, value)
        guard.docs[f"workload_provenance/{PID}"] = provenance(signed_record())
        assert rs.state_bucket(PID, LEGACY) == LEGACY
    assert guard.reads == []


def test_cc_state_location_per_workload(cc, monkeypatch):
    rs, guard = cc
    monkeypatch.setenv(ri.MODE_ENV, "PER_WORKLOAD")
    assert rs.state_bucket(PID, LEGACY) == LEGACY                       # no provenance at all
    guard.docs[f"workload_provenance/{PID}"] = provenance(signed_record("MIGRATING"))
    assert rs.state_bucket(PID, LEGACY) == LEGACY
    guard.docs[f"workload_provenance/{PID}"] = provenance(signed_record())
    assert rs.state_bucket(PID, LEGACY) == CHILD_BUCKET
    guard.docs[f"workload_provenance/{PID}"] = provenance(forged())
    with pytest.raises(ri.RunnerIdentityError):
        rs.state_bucket(PID, LEGACY)
    monkeypatch.setenv(ri.MODE_ENV, "per_workload")
    with pytest.raises(ri.RunnerIdentityError) as e:
        rs.state_bucket(PID, LEGACY)
    assert e.value.code == "RUNNER_IDENTITY_MODE_INVALID"


class FakeStorageModule:
    def __init__(self, objects):
        self.objects = objects        # {(bucket, name): text}
        self.buckets = []
        mod = self

        class Client:
            def __init__(self, project=None):
                pass

            def bucket(self, name):
                mod.buckets.append(name)

                class _B:
                    def blob(self, path):
                        class _Blob:
                            def exists(self):
                                return (name, path) in mod.objects

                            def download_as_text(self):
                                return mod.objects[(name, path)]
                        return _Blob()

                    def list_blobs(self, prefix=None, max_results=None):
                        return []
                return _B()

        self.Client = Client


STATE = {"version": 4, "serial": 3, "lineage": "l", "resources": [
    {"mode": "managed", "type": "google_cloud_run_v2_service", "name": "api", "provider": "p",
     "instances": [{"attributes": {"name": "api", "location": "europe-west1"}}]}]}


def test_cc_resources_view_reads_the_provenance_bucket_only_per_workload(cc, monkeypatch):
    rs, guard = cc
    from routes import workloads as wl
    store = FakeStorageModule({(LEGACY, f"workloads/{PID}/default.tfstate"): json.dumps(STATE),
                               (CHILD_BUCKET, f"workloads/{PID}/default.tfstate"): json.dumps(STATE)})
    monkeypatch.setattr(wl, "storage", store)
    monkeypatch.setenv("TFSTATE_BUCKET", LEGACY)
    guard.docs[f"workload_provenance/{PID}"] = provenance(signed_record())
    monkeypatch.delenv(ri.MODE_ENV, raising=False)
    shared_out = wl.fetch_workload_state_from_gcs(PID, "mock-stackvend-project")
    assert store.buckets == [LEGACY] and guard.reads == []
    assert shared_out["state_source"] == f"gs://{LEGACY}/workloads/{PID}/default.tfstate"
    monkeypatch.setenv(ri.MODE_ENV, "PER_WORKLOAD")
    out = wl.fetch_workload_state_from_gcs(PID, "mock-stackvend-project")
    assert store.buckets[-1] == CHILD_BUCKET and out["state_source"].startswith(f"gs://{CHILD_BUCKET}/")
    guard.docs[f"workload_provenance/{PID}"] = provenance(forged())
    n = len(store.buckets)
    assert wl.fetch_workload_state_from_gcs(PID, "mock-stackvend-project") is None and len(store.buckets) == n


def test_cc_finops_reader(cc, monkeypatch):
    rs, guard = cc
    fs = importlib.import_module("services.finops_sync")
    monkeypatch.delenv("TEST_MODE", raising=False)
    store = FakeStorageModule({(LEGACY, f"workloads/{PID}/default.tfstate"): json.dumps(STATE),
                               (CHILD_BUCKET, f"workloads/{PID}/default.tfstate"): json.dumps({"serial": 9})})
    client = store.Client()
    monkeypatch.delenv(ri.MODE_ENV, raising=False)
    guard.docs[f"workload_provenance/{PID}"] = provenance(signed_record())
    assert fs.fetch_workload_state_from_gcs(PID, "mock-stackvend-project", client) == STATE
    assert store.buckets == [LEGACY] and guard.reads == []
    monkeypatch.setenv(ri.MODE_ENV, "PER_WORKLOAD")
    assert fs.fetch_workload_state_from_gcs(PID, "mock-stackvend-project", client) == {"serial": 9}
    guard.docs[f"workload_provenance/{PID}"] = provenance(forged())
    assert fs.fetch_workload_state_from_gcs(PID, "mock-stackvend-project", client) is None
    assert store.buckets[-1] == CHILD_BUCKET   # never a fallback to the platform bucket


# ---------------------------------------------------------------------------------------------- Settings card
class _Resp:
    def __init__(self, status, body):
        self.status_code, self._b, self.text = status, body, json.dumps(body)

    def json(self):
        return self._b


def test_settings_card_shared_and_per_workload(cc, monkeypatch):
    from routes import runner_identity_card as card
    from unittest.mock import MagicMock
    seen = []

    def requester(method, path, json_body=None, timeout=None, request=None):
        seen.append((method, path, json_body))
        if path == "/runner-identity/status":
            return _Resp(200, answers["status"])
        return _Resp(200, {"dry_run": json_body["dry_run"], "counts": {"DRY_RUN": 1}, "results": []})

    monkeypatch.setattr(card, "vending_requester", requester)
    req = MagicMock()
    req.state.user_email = "admin@example.com"
    monkeypatch.delenv(ri.MODE_ENV, raising=False)
    answers = {"status": {"mode": "PLATFORM", "mode_label": "Shared", "per_workload": False, "workloads": []}}
    out = card.get_runner_identity_card(req)
    assert out["mode_label"] == "Shared" and [w["code"] for w in out["warnings"]] == ["RUNNER_IDENTITY_SHARED"]
    answers["status"] = {"mode": "PER_WORKLOAD", "mode_label": "Per workload", "per_workload": True,
                         "workloads": []}
    out = card.get_runner_identity_card(req)
    assert [w["code"] for w in out["warnings"]] == ["RUNNER_IDENTITY_MODE_DIFFERS"]
    res = card.run_runner_identity_backfill(req, card.RunnerIdentityBackfillBody())
    assert res["dry_run"] is True
    assert seen[-1] == ("POST", "/runner-identity/backfill",
                        {"dry_run": True, "max": 25, "operator_email": "admin@example.com"})


def test_settings_card_real_run_names_its_workloads_and_is_audited(cc, monkeypatch):
    from routes import runner_identity_card as card
    from unittest.mock import MagicMock
    from destructive_guard_fakes import FakeDB
    seen, store = [], FakeDB()

    def requester(method, path, json_body=None, timeout=None, request=None):
        seen.append(json_body)
        return _Resp(200, {"dry_run": False, "counts": {"MIGRATED": 1},
                           "results": [{"product_id": PID, "outcome": "MIGRATED", "error_class": None}]})

    monkeypatch.setattr(card, "vending_requester", requester)
    monkeypatch.setattr(card, "audit_db_provider", lambda: store)
    req = MagicMock()
    req.state.user_email = "admin@example.com"
    for body in (card.RunnerIdentityBackfillBody(dry_run=False),
                 card.RunnerIdentityBackfillBody(dry_run=False, product_ids=["a", "b", "c", "d"], max=3),
                 card.RunnerIdentityBackfillBody(dry_run=False, product_ids=[PID])):   # max defaults to 25
        r = card.run_runner_identity_backfill(req, body)
        assert r.status_code == 422 and json.loads(r.body)["code"] == "BACKFILL.REAL_RUN_TOO_LARGE"
    assert seen == []
    out = card.run_runner_identity_backfill(req, card.RunnerIdentityBackfillBody(dry_run=False, product_ids=[PID],
                                                                                 max=1))
    assert out["counts"] == {"MIGRATED": 1} and seen[-1]["product_ids"] == [PID]
    audits = [d for p, d in store.docs.items() if p.startswith(f"workloads/{PID}/audit_logs/")]
    assert len(audits) == 1 and audits[0]["action"] == "RUNNER_IDENTITY_BACKFILL_REQUESTED" \
        and audits[0]["operator"] == "admin@example.com" and audits[0]["outcome"] == "MIGRATED"
    card.run_runner_identity_backfill(req, card.RunnerIdentityBackfillBody())   # a dry run writes no audit
    assert len([p for p in store.docs if "/audit_logs/" in p]) == 1


def test_decommission_approval_carries_delete_without_archive_only_when_chosen(cc, monkeypatch):
    import destructive_actions as da
    from unittest.mock import MagicMock
    created = []

    class _G:
        def collection(self, name):
            class _C:
                def document(self, doc_id):
                    class _D:
                        def create(self, rec):
                            created.append(rec)
                    return _D()
            return _C()

    monkeypatch.setattr(da, "get_guard_db", lambda: _G())
    monkeypatch.setattr(da, "principal_type", lambda r: da.PRINCIPAL_USER)
    req = MagicMock()
    req.state.user_role = da.UserRole.ADMIN
    req.state.user_email = "admin@example.com"
    now = datetime(2026, 10, 31, tzinfo=timezone.utc)
    da.mint_approval(req, action=da.PROJECT_DECOMMISSION, product_id=PID, project_id=PROJECT, project_number=NUMBER,
                     now=now)
    da.mint_approval(req, action=da.PROJECT_DECOMMISSION, product_id=PID, project_id=PROJECT, project_number=NUMBER,
                     now=now, delete_without_archive=True)
    assert "delete_without_archive" not in created[0]
    assert created[1]["delete_without_archive"] is True
    assert {k_: v for k_, v in created[1].items() if k_ != "delete_without_archive"} == created[0]


# ---------------------------------------------------------------------------------------------- rollback
class Blob:
    def __init__(self, name, generation, metadata=None, live=True):
        self.name, self.generation, self.metadata = name, generation, metadata
        self.updated = datetime(2026, 10, 1, tzinfo=timezone.utc)
        self.size, self.etag = 10, "e"
        self.time_deleted = None if live else datetime(2026, 10, 2, tzinfo=timezone.utc)


class Bucket:
    def __init__(self, blobs):
        self.blobs = blobs

    def list_blobs(self, prefix=None, versions=False):
        return [b for b in self.blobs if b.name.startswith(prefix)]

    def get_blob(self, name, generation=None):
        return None


class Storage:
    def __init__(self, buckets):
        self.buckets, self.used = buckets, []

    def bucket(self, name):
        self.used.append(name)
        return self.buckets[name]


@pytest.fixture
def rollback_mod():
    return _load("fd7l_p3_rollback", os.path.join(REPO, "apps", "infra-rollback", "rollback.py"))


def _engine(mod, storage):
    eng = mod.InfraRollbackEngine(project_id="mock-stackvend-project", state_bucket_name=LEGACY,
                                  firestore_client=object(), storage_client=storage)
    eng.db = None
    return eng


def test_rollback_shared_install_reads_todays_bucket_without_the_guard_db(rollback_mod, monkeypatch):
    monkeypatch.delenv(ri.MODE_ENV, raising=False)
    obj = f"workloads/{PID}/default.tfstate"
    storage = Storage({LEGACY: Bucket([Blob(obj, 2), Blob(obj, 1, live=False)])})
    eng = _engine(rollback_mod, storage)
    eng.guard_db = GuardDB()
    hist = eng.get_state_history(PID)
    assert storage.used == [LEGACY] and eng.guard_db.reads == []
    assert all(set(v) == {"generation", "updated", "size_bytes", "etag", "live"} for v in hist)


def test_rollback_per_workload_reads_the_provenance_bucket(rollback_mod, monkeypatch):
    monkeypatch.setenv(ri.MODE_ENV, "PER_WORKLOAD")
    monkeypatch.setenv("STACKVEND_GUARD_FIRESTORE_DATABASE", "stackvend-guard")
    obj = f"workloads/{PID}/default.tfstate"
    meta = {"stackvend-source-updated": "2026-09-01T00:00:00Z", "stackvend-source-generation": "77"}
    storage = Storage({LEGACY: Bucket([]), CHILD_BUCKET: Bucket([Blob(obj, 5, meta)])})
    eng = _engine(rollback_mod, storage)
    eng.guard_db = GuardDB({f"workload_provenance/{PID}": provenance(signed_record())})
    eng.certs = k.certs_for()
    (v,) = eng.get_state_history(PID)
    assert storage.used == [CHILD_BUCKET] and v["source_updated"] == "2026-09-01T00:00:00Z" \
        and v["source_generation"] == "77"
    rec = eng.execute_rollback(PID, "tr-1")
    assert rec["state_bucket"] == CHILD_BUCKET and rec["status"] == rollback_mod.NO_PREVIOUS_VERSION
    eng.guard_db = GuardDB({f"workload_provenance/{PID}": provenance(forged())})
    rec = eng.execute_rollback(PID, "tr-2")
    assert rec["status"] == rollback_mod.ROLLBACK_UNAVAILABLE and "RUNNER_RECORD_UNSIGNED" in rec["message"]
    monkeypatch.delenv("STACKVEND_GUARD_FIRESTORE_DATABASE")
    rec = eng.execute_rollback(PID, "tr-3")
    assert rec["status"] == rollback_mod.ROLLBACK_UNAVAILABLE and "RUNNER_STORE_UNAVAILABLE" in rec["message"]


# ---------------------------------------------------------------------------------------------- Express
def _synth(monkeypatch, value):
    if value is None:
        monkeypatch.delenv(ri.MODE_ENV, raising=False)
    else:
        monkeypatch.setenv(ri.MODE_ENV, value)
    from shared.express_synthesizer import ExpressHCLSynthesizer
    return ExpressHCLSynthesizer().synthesize_workload(
        product_id="express-demo", project_id="castor-express-demo-1234", region=k.REGION,
        module_instances=[{"module_id": "compute-cloudrun", "instance_name": "gateway", "parameters": {}}],
        include_vpc=False, state_bucket="castor-tfstate-1234")


def test_express_shared_install_output_is_byte_identical(monkeypatch):
    base = _synth(monkeypatch, None)
    assert "infra/workload/backend.tf" in base
    assert _synth(monkeypatch, "") == base and _synth(monkeypatch, "PLATFORM") == base


def test_express_per_workload_commits_no_backend(monkeypatch):
    base = _synth(monkeypatch, None)
    per = _synth(monkeypatch, "PER_WORKLOAD")
    assert "infra/workload/backend.tf" not in per
    assert per == {p: c for p, c in base.items() if p != "infra/workload/backend.tf"}


def test_express_unknown_mode_fails_loudly(monkeypatch):
    from shared.express_synthesizer import ExpressRunnerIdentityModeInvalid
    with pytest.raises(ExpressRunnerIdentityModeInvalid):
        _synth(monkeypatch, "per-workload")


def test_express_copies_are_identical():
    blobs = {p: open(os.path.join(REPO, p), "rb").read() for p in (
        "shared/express_synthesizer.py", "apps/control-center/shared/express_synthesizer.py",
        "apps/orchestrator-gateway/shared/express_synthesizer.py")}
    assert len(set(blobs.values())) == 1
