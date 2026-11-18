"""Lane 14 PR-4 (plan §2.7, rows L14-j / L14-n): refactor scanner on workload repos + exact intake allow-set.

Hermetic: dict-backed Firestore fakes, injected archive/bandit/publisher transports, the gateway loaded by path with
the Workflows client faked (same harness as tests/test_lane17_gateway_gates.py).
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import base64
import copy
import importlib.util
import io
import json
import os
import sys
import tarfile
import types
from types import SimpleNamespace

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RS_DIR = os.path.join(REPO, "apps", "refactor-scanner")
sys.path.insert(0, os.path.dirname(__file__))

from fd4f_support import FakeDB as GwFakeDB, gw  # noqa: E402,F401  (gw is a fixture)


# ============================================================================================ scanner fakes
@pytest.fixture()
def rs(monkeypatch):
    from fd4g_support import real_modules

    real_modules(monkeypatch)
    spec = importlib.util.spec_from_file_location("lane14_rs_scanner", os.path.join(RS_DIR, "scanner.py"))
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "lane14_rs_scanner", mod)
    spec.loader.exec_module(mod)
    return mod


class _Snap:
    def __init__(self, doc_id, data):
        self.id, self._d = doc_id, data
        self.exists = data is not None

    def to_dict(self):
        return copy.deepcopy(self._d)


class AlreadyExists(Exception):
    pass


class _Q:
    def __init__(self, store, coll, flt=None):
        self.store, self.coll, self.flt = store, coll, flt

    def where(self, filter=None):  # noqa: A002
        return _Q(self.store, self.coll, filter)

    def limit(self, n):
        return self

    def stream(self):
        if self.store.get("__fail__"):
            raise RuntimeError("down")
        out = []
        for k, v in sorted(self.store.items()):
            if k.startswith(self.coll + "/") and k.count("/") == 1:
                if self.flt is None or v.get(self.flt.field_path) == self.flt.value:
                    out.append(_Snap(k.split("/", 1)[1], v))
        return out

    def document(self, doc_id):
        return _D(self.store, f"{self.coll}/{doc_id}")


class _D:
    def __init__(self, store, path):
        self.store, self.path = store, path

    def get(self):
        return _Snap(self.path.split("/")[-1], self.store.get(self.path))

    def set(self, data, merge=False):
        self.store[self.path] = copy.deepcopy(data)

    def create(self, data):
        if self.path in self.store:
            raise AlreadyExists(self.path)
        self.store[self.path] = copy.deepcopy(data)


class FakeDB:
    def __init__(self, store):
        self.store = store

    def collection(self, name):
        return _Q(self.store, name)


class FakePublisher:
    def __init__(self, fail=False):
        self.messages, self.fail = [], fail

    def topic_path(self, project, topic):
        return f"projects/{project}/topics/{topic}"

    def publish(self, topic, data):
        if self.fail:
            raise RuntimeError("pubsub down")
        self.messages.append((topic, json.loads(data)))
        return SimpleNamespace(result=lambda timeout=None: f"m{len(self.messages)}")


def make_tar(files, *, prefix="repo-abc/", members=None):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(prefix + name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        for ti, data in members or []:
            tf.addfile(ti, io.BytesIO(data) if data is not None else None)
    return raw.getvalue()


BAD_CODE = b"def f():\n    try:\n        return 1\n    except:\n        return 0\n"
CLEAN_CODE = b"def f():\n    return 1\n"


class FakeArchives:
    def __init__(self, archive=None, fail=None):
        self.archive, self.fail, self.calls = archive, fail, []

    def fetch(self, target):
        self.calls.append(target)
        if self.fail:
            raise self.fail
        return self.archive


def _workloads(**extra):
    store = {
        "workloads/app": {"status": "ACTIVE", "project_id": "child-app", "github_repo": "acme/app",
                          "vcs_provider": "GITHUB", "default_branch": "main"},
    }
    store.update(extra)
    return store


def _scanner(rs, store, *, archive=None, fail=None, bandit_out='{"results": []}', env=None, publisher=None):
    env = {"PROJECT_ID": "host-platform", "CLOUD_RUN_EXECUTION": "exec-1", "VENDING_SERVICE_URL": "https://v.run.app",
           "GIT_SERVER_URL": "https://g.run.app", **(env or {})}

    def bandit(argv):
        if bandit_out is FileNotFoundError:
            raise FileNotFoundError("bandit")
        return SimpleNamespace(stdout=bandit_out, returncode=0)

    archives = FakeArchives(archive if archive is not None else make_tar({"apps/svc/main.py": BAD_CODE}), fail)
    pub = publisher or FakePublisher()
    s = rs.RefactorScanner(firestore_client=FakeDB(store), publisher_client=pub, env=env, archive_client=archives,
                           bandit_runner=bandit)
    return s, archives, pub


# ============================================================================================ scanner tests
def test_event_is_one_per_product_with_exact_fields(rs):
    files = {"apps/svc/main.py": BAD_CODE, "apps/svc/other.py": BAD_CODE}
    s, archives, pub = _scanner(rs, _workloads(), archive=make_tar(files))
    code, summary = s.run()
    assert code == 0 and len(pub.messages) == 1
    topic, msg = pub.messages[0]
    assert topic == "projects/host-platform/topics/autonomous-refactor-events"
    assert msg["product_id"] == "app" and msg["source_channel"] == "github_refactor_scanner"
    assert msg["execution_mode"] == "FULL_BUILD" and msg["scan_id"].startswith("scan-")
    assert len(msg["findings_digest"]) == 64 and msg["trace_id"] == f"refactor-app-{msg['scan_id']}"
    assert archives.calls[0].repo == "acme/app" and archives.calls[0].branch == "main"


def test_disabled_frozen_and_unproven_targets_are_not_scanned(rs):
    store = _workloads(**{
        "workloads/off": {"status": "ACTIVE", "project_id": "c-off", "github_repo": "a/off", "vcs_provider": "GITHUB",
                          "refactor_scanner_enabled": False},
        "workloads/frozen": {"status": "ACTIVE", "project_id": "c-fr", "github_repo": "a/fr", "vcs_provider": "GITHUB",
                             "code_freeze": True},
        "workloads/hosty": {"status": "ACTIVE", "project_id": "host-platform", "github_repo": "a/h",
                            "vcs_provider": "GITHUB"},
        "workloads/dup1": {"status": "ACTIVE", "project_id": "c-dup", "github_repo": "a/d1", "vcs_provider": "GITHUB"},
        "workloads/dup2": {"status": "ACTIVE", "project_id": "c-dup", "github_repo": "a/d2", "vcs_provider": "GITHUB"},
        "workloads/castor": {"status": "ACTIVE", "is_castor": True, "project_id": "host-platform"},
        "workloads/old": {"status": "DECOMMISSIONED", "project_id": "c-old", "github_repo": "a/o", "vcs_provider": "GITHUB"},
    })
    s, archives, _ = _scanner(rs, store)
    code, summary = s.run()
    assert [t.product_id for t in archives.calls] == ["app"]  # absent toggle = enabled (CC default)
    statuses = {x["product_id"]: x["status"] for x in summary["skipped"]}
    assert statuses == {"off": "SKIPPED:SCANNER_DISABLED", "frozen": "SKIPPED:CODE_FREEZE",
                        "hosty": "REFUSED:HOST_PROJECT", "dup1": "REFUSED:LEDGER_MISMATCH",
                        "dup2": "REFUSED:LEDGER_MISMATCH"}


def test_archive_failure_is_scan_failed_and_exit_1(rs):
    s, _, pub = _scanner(rs, _workloads(), fail=rs.ScanFailed("ARCHIVE", "HTTP 404"))
    code, summary = s.run()
    assert code == 1 and summary["scans"][0]["status"] == "SCAN_FAILED:ARCHIVE" and pub.messages == []


def test_path_traversal_member_is_refused_and_nothing_escapes(rs, tmp_path):
    evil = tarfile.TarInfo("../escaped.txt")
    evil.size = 3
    archive = make_tar({}, prefix="", members=[(evil, b"pwn")])
    s, _, pub = _scanner(rs, _workloads(), archive=archive)
    code, summary = s.run()
    assert summary["scans"][0]["status"] == "SCAN_FAILED:ARCHIVE" and code == 1
    with pytest.raises(rs.ScanFailed):
        rs.safe_extract(archive, str(tmp_path / "x"))
    assert not (tmp_path / "escaped.txt").exists()


def test_safe_extract_negative_valid_archive_is_extracted_unchanged(rs, tmp_path):
    archive = make_tar({"a.py": CLEAN_CODE, "pkg/b.txt": b"hello"})
    dest = tmp_path / "d"
    dest.mkdir()
    root = rs.safe_extract(archive, str(dest))
    assert open(os.path.join(root, "a.py"), "rb").read() == CLEAN_CODE
    assert open(os.path.join(root, "pkg", "b.txt"), "rb").read() == b"hello"


def test_missing_bandit_is_scan_failed_never_skipped(rs):
    s, _, pub = _scanner(rs, _workloads(), bandit_out=FileNotFoundError)
    code, summary = s.run()
    assert summary["scans"][0]["status"] == "SCAN_FAILED:BANDIT_UNAVAILABLE" and pub.messages == [] and code == 1


def test_clean_repo_publishes_nothing(rs):
    s, _, pub = _scanner(rs, _workloads(), archive=make_tar({"apps/svc/main.py": CLEAN_CODE,
                                                             "apps/svc/test_main.py": CLEAN_CODE}))
    code, summary = s.run()
    assert code == 0 and pub.messages == [] and summary["scans"][0]["dispatch"] == "NO_ACTIONABLE_FINDINGS"


def test_same_execution_twice_scans_and_dispatches_once(rs):
    store = _workloads()
    s, archives, pub = _scanner(rs, store)
    s.run()
    s.run()
    assert len(archives.calls) == 1 and len(pub.messages) == 1


def test_rt_f9_stale_running_record_is_exit_1_interrupted_never_ok(rs):
    store = _workloads(**{"refactor_scanner_runs/exec-1": {"job": "x", "run_id": "exec-1", "outcome": "RUNNING"}})
    s, archives, pub = _scanner(rs, store)
    code, summary = s.run()
    assert code == 1 and summary["outcome"] == "INTERRUPTED" and archives.calls == [] and pub.messages == []
    # Negative: a recorded OK stays exit 0; a recorded ERROR stays exit 1.
    store["refactor_scanner_runs/exec-1"]["outcome"] = "OK"
    assert s.run()[0] == 0
    store["refactor_scanner_runs/exec-1"]["outcome"] = "ERROR"
    assert s.run()[0] == 1


def test_rt_f8_missing_data_filter_is_typed_scan_failed_never_unfiltered(rs, monkeypatch, tmp_path):
    monkeypatch.delattr(rs.tarfile, "data_filter")
    with pytest.raises(rs.ScanFailed) as ei:
        rs.safe_extract(make_tar({"a.py": CLEAN_CODE}), str(tmp_path))
    assert ei.value.stage == "ARCHIVE_FILTER_UNAVAILABLE" and os.listdir(tmp_path) == []
    s, _, pub = _scanner(rs, _workloads())
    code, summary = s.run()
    assert code == 1 and summary["scans"][0]["status"] == "SCAN_FAILED:ARCHIVE_FILTER_UNAVAILABLE"
    assert pub.messages == []


def test_rt_f8_typeerror_from_extractall_is_scan_failed(rs, monkeypatch, tmp_path):
    def old_extractall(self, path=".", members=None, *, numeric_owner=False):  # Python < 3.11.4 signature
        raise AssertionError("never reached")

    monkeypatch.setattr(rs.tarfile.TarFile, "extractall", old_extractall)
    with pytest.raises(rs.ScanFailed) as ei:
        rs.safe_extract(make_tar({"a.py": CLEAN_CODE}), str(tmp_path))
    assert ei.value.stage == "ARCHIVE" and "TypeError" in ei.value.detail


def test_rt_f10_uncompressed_size_and_member_caps(rs, monkeypatch, tmp_path):
    monkeypatch.setattr(rs, "MAX_EXTRACTED_BYTES", 10)
    with pytest.raises(rs.ScanFailed) as ei:
        rs.safe_extract(make_tar({"a.py": b"x" * 11}), str(tmp_path))
    assert ei.value.stage == "ARCHIVE" and "expands" in ei.value.detail and os.listdir(tmp_path) == []
    monkeypatch.setattr(rs, "MAX_EXTRACTED_BYTES", 1024)
    monkeypatch.setattr(rs, "MAX_ARCHIVE_MEMBERS", 2)
    with pytest.raises(rs.ScanFailed):
        rs.safe_extract(make_tar({"a.py": b"1", "b.py": b"2", "c.py": b"3"}), str(tmp_path))
    # Negative: at the caps, the archive extracts unchanged.
    monkeypatch.setattr(rs, "MAX_ARCHIVE_MEMBERS", 3)
    root = rs.safe_extract(make_tar({"a.py": b"1", "b.py": b"2", "c.py": b"3"}), str(tmp_path))
    assert open(os.path.join(root, "c.py"), "rb").read() == b"3"


def test_rt_f11_digest_ignores_line_numbers_and_order_but_counts_findings(rs):
    a = [{"rule": "BARE_EXCEPT", "file": "x.py", "line": 4}, {"rule": "B105", "file": "y.py", "line": 9}]
    shifted = [{"rule": "B105", "file": "y.py", "line": 30}, {"rule": "BARE_EXCEPT", "file": "x.py", "line": 7}]
    assert rs.findings_digest(a) == rs.findings_digest(shifted)
    assert rs.findings_digest(a) != rs.findings_digest(a + [{"rule": "BARE_EXCEPT", "file": "x.py", "line": 12}])
    assert rs.findings_digest(a) != rs.findings_digest([a[0]])


def test_not_configured_exits_3_without_any_fetch(rs):
    store = _workloads()
    s, archives, _ = _scanner(rs, store, env={"VENDING_SERVICE_URL": ""})
    code, summary = s.run()
    assert code == 3 and summary["missing"] == ["VENDING_SERVICE_URL"] and archives.calls == []
    s2, _, _ = _scanner(rs, store, env={"PROJECT_ID": "", "CLOUD_RUN_EXECUTION": "exec-2"})
    assert s2.run()[0] == 3


def test_platform_repo_is_never_scanned(rs):
    """A leftover PLATFORM_GITHUB_REPO changes nothing: the platform repository is never a target."""
    s, archives, pub = _scanner(rs, {}, env={"PLATFORM_GITHUB_REPO": "acme/x", "CLOUD_RUN_EXECUTION": "exec-9"})
    code, summary = s.run()
    assert code == 0 and archives.calls == [] and pub.messages == [] and summary["scans"] == []


def test_publish_failure_is_an_error(rs):
    s, _, _ = _scanner(rs, _workloads(), publisher=FakePublisher(fail=True))
    code, summary = s.run()
    assert code == 1 and summary["scans"][0]["dispatch"] == "PUBLISH_FAILED"


def test_github_archive_uses_a_vending_token_and_exact_repo(rs):
    calls = []

    def get(url, headers):
        calls.append((url, headers))
        if url.endswith("/github-token"):
            return 200, json.dumps({"token": "ghs_x"}).encode(), {}
        return 200, b"tar", {}

    env = {"VENDING_SERVICE_URL": "https://vend.run.app"}
    client = rs.ArchiveClient(env, http_get=get, id_token=lambda aud: f"id-{aud}")
    target = rs.ScanTarget("app", "acme/app", "main", "GITHUB")
    assert client.fetch(target) == b"tar"
    assert calls[0] == ("https://vend.run.app/github-token", {"Authorization": "Bearer id-https://vend.run.app"})
    assert calls[1][0] == "https://api.github.com/repos/acme/app/tarball/main"
    assert calls[1][1]["Authorization"] == "Bearer ghs_x"
    with pytest.raises(rs.ScanFailed):
        client.fetch(rs.ScanTarget("app", "acme/app/../x", "main", "GITHUB"))
    sg = rs.ArchiveClient({"GIT_SERVER_URL": "https://git.run.app"}, http_get=get, id_token=lambda aud: "t")
    sg.fetch(rs.ScanTarget("app", "castor/app", "main", "SERVERLESS_GIT"))
    assert calls[-1][0] == "https://git.run.app/api/v1/repos/app/archive/main"


def test_no_literal_platform_ids_remain(rs):
    src = open(os.path.join(RS_DIR, "scanner.py")).read()
    assert '"project-castor"' not in src and 'execute_full_scan(".")' not in src


# ============================================================================================ workload archive errors
def _scan1(rs, store, statuses, *, env=None):
    """Scanner with the REAL ArchiveClient; `statuses` maps a GitHub repo slug to its tarball HTTP status."""
    env = {"PROJECT_ID": "host-platform", "CLOUD_RUN_EXECUTION": "exec-s1", "VENDING_SERVICE_URL": "https://v.run.app",
           "GIT_SERVER_URL": "https://g.run.app", **(env or {})}
    calls = []
    archive = make_tar({"apps/svc/main.py": BAD_CODE})

    def get(url, headers):
        calls.append(url)
        if url.endswith("/github-token"):
            return 200, json.dumps({"token": "ghs_secret"}).encode(), {}
        slug = url.split("/repos/", 1)[1].split("/tarball/", 1)[0]
        status = statuses.get(slug, 200)
        return status, (archive if status == 200 else b'{"message": "Not Found"}'), {}

    client = rs.ArchiveClient(env, http_get=get, id_token=lambda aud: "id")
    pub = FakePublisher()
    s = rs.RefactorScanner(firestore_client=FakeDB(store), publisher_client=pub, env=env, archive_client=client,
                           bandit_runner=lambda argv: SimpleNamespace(stdout='{"results": []}', returncode=0))
    return s, calls, pub


def _statuses(summary):
    return {x["product_id"]: x["status"] for x in summary["scans"]}


def test_scan1_workload_404_still_scan_failed_exit_1(rs):
    s, _, pub = _scan1(rs, _workloads(), {"acme/app": 404})
    code, summary = s.run()
    assert code == 1 and summary["outcome"] == "ERROR" and _statuses(summary) == {"app": "SCAN_FAILED:ARCHIVE"}
    assert "not_configured" not in summary and pub.messages == []


def test_scan1_a_ledger_workload_named_platform_is_not_the_platform_target(rs):
    store = {"workloads/platform": {"status": "ACTIVE", "project_id": "child-p", "github_repo": "acme/p",
                                    "vcs_provider": "GITHUB"}}
    s, _, _ = _scan1(rs, store, {"acme/p": 404})
    code, summary = s.run()
    assert code == 1 and _statuses(summary) == {"platform": "SCAN_FAILED:ARCHIVE"}


# ============================================================================================ gateway intake
def _envelope(payload):
    return {"message": {"data": base64.b64encode(json.dumps(payload).encode()).decode(), "messageId": "m1"}}


def _post(gw, monkeypatch, db, payload):
    import google.cloud.firestore as fs_mod
    from fastapi.testclient import TestClient

    monkeypatch.setattr(fs_mod, "Client", lambda *a, **k: db)
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project")
    monkeypatch.setenv("REGION", "us-central1")   # FALLBACK-URLS: dispatch needs REGION (no default)
    created = []

    class _Exec:
        def __init__(self, argument=None):
            self.argument = argument

    class _Client:
        def workflow_path(self, *a):
            return "projects/p/locations/r/workflows/w"

        def create_execution(self, parent=None, execution=None):
            created.append(json.loads(execution.argument))
            return types.SimpleNamespace(name=parent + "/executions/e-1")

    fake = types.SimpleNamespace(ExecutionsClient=_Client, Execution=_Exec)
    monkeypatch.setitem(sys.modules, "google.cloud.workflows", types.SimpleNamespace(executions_v1=fake))
    monkeypatch.setitem(sys.modules, "google.cloud.workflows.executions_v1", fake)
    monkeypatch.setitem(sys.modules, "google.cloud.workflows_v1", types.SimpleNamespace())
    monkeypatch.setattr(gw, "resolve_service_url", lambda name, *a, **k: f"https://{name}.example.run.app")
    r = TestClient(gw.app).post("/events/pubsub-intake", json=_envelope(payload))
    return r, created


REFACTOR = {"product_id": "app", "trace_id": "refactor-app-scan-1", "scan_id": "scan-1", "findings_digest": "d" * 64,
            "source_channel": "github_refactor_scanner", "execution_mode": "FULL_BUILD"}


def _gwdb(**docs):
    db = GwFakeDB()
    db.docs["workloads/app"] = {"status": "ACTIVE", "project_id": "child-app"}
    db.docs.update(docs)
    return db


def test_unknown_channel_is_422_and_never_dispatched(gw, monkeypatch):
    r, created = _post(gw, monkeypatch, _gwdb(), {"product_id": "app", "trace_id": "t", "source_channel": "slack"})
    assert r.status_code == 422 and r.json()["detail"]["status"] == "SUPPRESSED:UNKNOWN_SOURCE_CHANNEL"
    assert created == []


@pytest.mark.parametrize("channel", ["google_docs", "control_center_form", "control_center_retrigger",
                                     "control_center_deploy_infra", "deploy_to_folder", "control_center_hitl_approval"])
def test_existing_producers_dispatch_unchanged(gw, monkeypatch, channel):
    payload = {"product_id": "app", "trace_id": f"t-{channel}", "source_channel": channel, "spec_text": "x"}
    r, created = _post(gw, monkeypatch, _gwdb(), payload)
    assert r.status_code == 200 and r.json()["status"] == "DISPATCHED"
    assert "require_plan_approval" not in created[0] and created[0]["source_channel"] == channel


def test_absent_channel_is_the_google_docs_path_unchanged(gw, monkeypatch):
    r, created = _post(gw, monkeypatch, _gwdb(), {"product_id": "app", "trace_id": "t-docs"})
    assert r.status_code == 200 and "source_channel" not in created[0] and "require_plan_approval" not in created[0]


def test_refactor_event_forces_plan_approval(gw, monkeypatch):
    r, created = _post(gw, monkeypatch, _gwdb(), dict(REFACTOR, require_plan_approval=False))
    assert r.status_code == 200 and created[0]["require_plan_approval"] is True
    assert created[0]["execution_mode"] == "FULL_BUILD"


@pytest.mark.parametrize("drop,status", [("scan_id", "SUPPRESSED:INVALID_REFACTOR_EVENT"),
                                         ("product_id", "SUPPRESSED:INVALID_REFACTOR_EVENT"),
                                         ("execution_mode", "SUPPRESSED:INVALID_REFACTOR_EVENT")])
def test_incomplete_refactor_event_is_422(gw, monkeypatch, drop, status):
    payload = {k: v for k, v in REFACTOR.items() if k != drop}
    r, created = _post(gw, monkeypatch, _gwdb(), payload)
    assert r.status_code == 422 and r.json()["detail"]["status"] == status and created == []


def test_sre_platform_remediation_is_422_until_lane_17(gw, monkeypatch):
    payload = {"product_id": "app", "trace_id": "t-sre", "incident_id": "inc-1", "source_channel": "sre_sentinel",
               "execution_mode": "PLATFORM_REMEDIATION"}
    r, created = _post(gw, monkeypatch, _gwdb(), payload)
    assert r.status_code == 422 and r.json()["detail"]["status"] == "SUPPRESSED:INVALID_SRE_EVENT" and created == []


@pytest.mark.parametrize("workload,status", [
    ({"status": "ACTIVE", "code_freeze": True}, "SUPPRESSED:CODE_FREEZE"),
    ({"status": "ACTIVE", "refactor_scanner_enabled": False}, "SUPPRESSED:REFACTOR_SCANNER_ENABLED_OFF"),
    ({"status": "DECOMMISSIONED"}, "SUPPRESSED:NOT_ACTIVE"),
    (None, "SUPPRESSED:LEDGER_MISSING"),
])
def test_refactor_event_rechecks_the_ledger(gw, monkeypatch, workload, status):
    db = _gwdb()
    if workload is None:
        del db.docs["workloads/app"]
    else:
        db.docs["workloads/app"] = workload
    r, created = _post(gw, monkeypatch, db, REFACTOR)
    assert r.status_code == 200 and r.json()["status"] == status and created == []


CLAIM = "refactor_intake_requests/app--" + "d" * 64  # RT F11: one claim document per (product, findings digest)


def test_one_open_refactor_request_per_product_and_digest(gw, monkeypatch):
    import time

    db = _gwdb(**{CLAIM: {"findings_digest": "d" * 64, "trace_id": "refactor-app-scan-0",
                          "opened_at": time.time() - 60}})
    r, created = _post(gw, monkeypatch, db, REFACTOR)
    assert r.json()["status"] == "SUPPRESSED:DUPLICATE_OPEN_REQUEST" and created == []
    # A redelivery of the message that opened the request is not a duplicate.
    db.docs[CLAIM]["trace_id"] = REFACTOR["trace_id"]
    r, created = _post(gw, monkeypatch, db, REFACTOR)
    assert r.json()["status"] == "DISPATCHED"
    # New findings (another digest has its own claim) -> a new request.
    db2 = _gwdb(**{"refactor_intake_requests/app--" + "e" * 64: {"findings_digest": "e" * 64, "trace_id": "x",
                                                                 "opened_at": time.time() - 60}})
    r, created = _post(gw, monkeypatch, db2, REFACTOR)
    assert r.json()["status"] == "DISPATCHED" and db2.docs[CLAIM]["trace_id"] == REFACTOR["trace_id"]


def test_rt_f11_refactor_event_without_a_digest_is_422(gw, monkeypatch):
    payload = {k: v for k, v in REFACTOR.items() if k != "findings_digest"}
    r, created = _post(gw, monkeypatch, _gwdb(), payload)
    assert r.status_code == 422 and r.json()["detail"]["status"] == "SUPPRESSED:INVALID_REFACTOR_EVENT"
    assert created == []


@pytest.mark.parametrize("digest", ["D" * 64, "d" * 63, "d" * 65, "g" * 64, "../" + "d" * 61, 42, ""])
def test_rt_r1_findings_digest_must_be_64_lowercase_hex(gw, monkeypatch, digest):
    r, created = _post(gw, monkeypatch, _gwdb(), dict(REFACTOR, findings_digest=digest))
    assert r.status_code == 422 and r.json()["detail"]["status"] == "SUPPRESSED:INVALID_REFACTOR_EVENT"
    assert created == []


def test_rt_r1_negative_a_real_scanner_digest_is_accepted(gw, monkeypatch, rs):
    digest = rs.findings_digest([{"rule": "BARE_EXCEPT", "file": "x.py", "line": 3}])
    r, created = _post(gw, monkeypatch, _gwdb(), dict(REFACTOR, findings_digest=digest))
    assert r.status_code == 200 and r.json()["status"] == "DISPATCHED" and created


def test_rt_f11_second_trace_for_the_same_digest_is_suppressed_by_the_atomic_claim(gw, monkeypatch):
    db = _gwdb()
    r, created = _post(gw, monkeypatch, db, REFACTOR)
    assert r.json()["status"] == "DISPATCHED" and CLAIM in db.docs
    r, created = _post(gw, monkeypatch, db, dict(REFACTOR, trace_id="refactor-app-scan-2", scan_id="scan-2"))
    assert r.json()["status"] == "SUPPRESSED:DUPLICATE_OPEN_REQUEST" and created == []


def test_rt_f11_expired_claim_reopens_only_with_the_read_version(gw, monkeypatch):
    import time

    old = {"findings_digest": "d" * 64, "trace_id": "refactor-app-scan-0", "opened_at": time.time() - 8 * 24 * 3600}
    db = _gwdb(**{CLAIM: dict(old)})
    r, created = _post(gw, monkeypatch, db, REFACTOR)
    assert r.json()["status"] == "DISPATCHED" and db.docs[CLAIM]["trace_id"] == REFACTOR["trace_id"]
    # A concurrent re-open between the read and the write fails the precondition -> 503 (Pub/Sub retries).
    db = _gwdb(**{CLAIM: dict(old)})
    real_get = type(db.collection("x").document("y")).get

    def racing_get(self):
        snap = real_get(self)
        if self._path == CLAIM:
            db.__dict__.setdefault("versions", {})[CLAIM] = 99  # someone else wrote after our read
        return snap

    monkeypatch.setattr(type(db.collection("x").document("y")), "get", racing_get)
    r, created = _post(gw, monkeypatch, db, REFACTOR)
    assert r.status_code == 503 and created == []


def test_ledger_unreadable_is_503(gw, monkeypatch):
    db = _gwdb()
    real_get = db.collection("workloads").document("app").__class__.get

    def flaky_get(self):
        if self._path == "workloads/app":
            raise RuntimeError("down")
        return real_get(self)

    monkeypatch.setattr(db.collection("workloads").document("app").__class__, "get", flaky_get)
    r, created = _post(gw, monkeypatch, db, REFACTOR)
    assert r.status_code == 503 and created == []
