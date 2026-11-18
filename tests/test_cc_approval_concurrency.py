"""
Code red-team F7 (wave1-lane4-code-red-team-fable.md): exactly-once merge under two CONCURRENT HITL decisions.

Runs in a clean subprocess (hermetic_guard.child_env) on the FD-4E hermetic harness prefix (sockets/DNS refused, no ADC), because
tests/test_approvals.py replaces fastapi/google.* in sys.modules and the real google.cloud.firestore_v1 cannot be
imported there. The approval document is a real `google.cloud.firestore_v1.DocumentReference` subclass, so
`routes.approvals._cas_claim` takes its PRODUCTION path (isinstance check + `firestore_v1.transactional`), and the
REAL library retry loop runs against a transaction fake with Firestore's optimistic-concurrency semantics:
a commit whose read set changed since it was read raises `Aborted`, and the library re-runs the function.
"""

import hermetic_guard  # noqa: F401,E402  (lane 2: must stay the first import; tests/hermetic_guard.py)

import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
OWN_CALLBACK = ("https://workflowexecutions.googleapis.com/v1/projects/mock-stackvend-project/locations/us-central1/"
                "workflows/castor-main/executions/e1/callbacks/c1")


def _harness():  # noqa: C901 - one linear scenario script
    import copy
    import inspect
    import threading
    from unittest.mock import MagicMock, patch

    marker = "# ================================================================ public mode"
    src_path = os.path.join(HERE, "cc_identity_harness.py")
    with open(src_path, encoding="utf-8") as f:
        src = f.read()
    assert marker in src, "FD-4E harness prefix changed"
    ns = {"__file__": src_path, "__name__": "cc_approval_concurrency_harness"}
    exec(compile(src.split(marker, 1)[0], src_path, "exec"), ns)

    from google.api_core import exceptions as gexc
    from google.cloud.firestore_v1.document import DocumentReference
    import routes.approvals as appr
    from schemas import ApprovalDecisionRequest, ApprovalStatus

    out = {}

    class Store:
        def __init__(self):
            self.docs, self.versions, self.lock = {}, {}, threading.Lock()

        def write(self, key, data, merge):
            with self.lock:
                cur = self.docs.get(key) if merge else None
                self.docs[key] = {**(cur or {}), **data}
                self.versions[key] = self.versions.get(key, 0) + 1

    class ContendedTransaction:
        """The slice of firestore_v1.Transaction that firestore_v1.transactional drives. The first commit of every
        transaction waits until both decisions have read the record (maximal contention)."""
        _read_only = False
        _max_attempts = 5

        def __init__(self, store, barrier, log):
            self.store, self.barrier, self.log, self._id, self.attempts = store, barrier, log, None, 0
            self.reads, self.writes = {}, []

        def _clean_up(self):
            self.reads, self.writes, self._id = {}, [], None

        def _begin(self, retry_id=None):
            self.attempts += 1
            self._id = f"txn-{id(self)}-{self.attempts}".encode()

        def _rollback(self):
            self._clean_up()

        def update(self, ref, fields):
            self.writes.append((ref._path, dict(fields)))

        def _commit(self):
            if self.attempts == 1 and self.barrier is not None:
                self.barrier.wait(timeout=10)
            with self.store.lock:
                stale = any(self.store.versions.get(k, 0) != v for k, v in self.reads.items())
                if not stale:
                    for key, fields in self.writes:
                        cur = self.store.docs.get(key) or {}
                        self.store.docs[key] = {**cur, **fields}
                        self.store.versions[key] = self.store.versions.get(key, 0) + 1
            self.log.append("aborted" if stale else "committed")
            self._clean_up()
            if stale:
                raise gexc.Aborted("concurrent modification")
            return []

    def build(barrier):
        store, log = Store(), []

        class Client:
            def transaction(self):
                return ContendedTransaction(store, barrier, log)

        client = Client()

        class Snap:
            def __init__(self, doc_id, data):
                self.id, self._d, self.exists = doc_id, data, data is not None

            def to_dict(self):
                return copy.deepcopy(self._d) if self._d is not None else None

        class Ref(DocumentReference):
            def get(self, field_paths=None, transaction=None, **kw):
                with store.lock:
                    data, ver = copy.deepcopy(store.docs.get(self._path)), store.versions.get(self._path, 0)
                if transaction is not None:
                    transaction.reads[self._path] = ver
                return Snap(self.id, data)

            def set(self, data, merge=False):
                store.write(self._path, data, merge)

        class Coll:
            def __init__(self, name):
                self.name = name

            def document(self, doc_id):
                return Ref(self.name, doc_id, client=client)

        class DB:
            def collection(self, name):
                return Coll(name)

        store.write(("workloads", "tenant-a"), {"github_repo": "example-org/tenant-a", "vcs_provider": "GITHUB"}, False)
        # FD-4P: the PR ledger entry the gateway wrote when it created PR #7 (the CC merges only ledger entries).
        from shared import vcs_ledger
        lid = vcs_ledger.ledger_id("GITHUB", "example-org/tenant-a", "feature-x")
        store.write(("vcs_ledger", lid), {
            "schema_version": 1, "ledger_id": lid, "provider": "GITHUB", "repo_full_name": "example-org/tenant-a",
            "repo_key": "example-org/tenant-a", "repo_id": 100, "product_id": "tenant-a", "trace_id": None,
            "origin": "DEVELOPER", "branch": "feature-x", "base_branch": "main", "head_sha": "e" * 40, "pr_number": 7,
            "pr_url": "https://github.com/example-org/tenant-a/pull/7", "state": "OPEN"}, False)
        store.write(("approval_requests", "appr-1"), {
            "approval_type": "PULL_REQUEST", "product_id": "tenant-a", "branch_name": "feature-x", "pr_number": 7,
            "status": "PENDING", "callback_url": OWN_CALLBACK, "ledger_id": lid}, False)
        return store, log, DB()

    def vcs_factory():
        vcs = MagicMock()
        repo = MagicMock()
        repo.full_name = "example-org/tenant-a"
        pr = MagicMock()
        pr.head.repo.full_name = pr.base.repo.full_name = "example-org/tenant-a"
        pr.head.ref = "feature-x"
        repo.get_pull.return_value = pr
        vcs._get_repo.return_value = repo
        vcs.merge_pull_request.return_value = {"status": "MERGED", "merged": True}
        factory = MagicMock()
        factory.get_provider.return_value = vcs
        return vcs, factory

    def run(n_threads, barrier):
        store, log, db = build(barrier)
        vcs, factory = vcs_factory()
        outcomes = []

        def decide(who):
            req = MagicMock()
            req.state.user_email, req.state.user_role = who, appr.UserRole.ADMIN
            try:
                appr.decide_approval_request("appr-1", ApprovalDecisionRequest(decision=ApprovalStatus.APPROVED), req)
                outcomes.append(200)
            except Exception as e:  # noqa: BLE001
                outcomes.append(getattr(e, "status_code", repr(e)))

        with patch.object(appr, "db", db), patch.object(appr, "VCSProviderFactory", factory), \
                patch.object(appr, "_deliver_workflow_callback", MagicMock(return_value=(True, ""))):
            threads = [threading.Thread(target=decide, args=(f"admin{i}@example.com",)) for i in range(n_threads)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)
        rec = store.docs[("approval_requests", "appr-1")]
        return {"outcomes": sorted(outcomes, key=str), "merge_calls": vcs.merge_pull_request.call_count,
                "status": rec.get("status"), "merge_status": rec.get("merge_status"), "commit_log": log}

    out["concurrent"] = run(2, threading.Barrier(2))
    out["sequential_control"] = run(1, None)
    out["dispatch_src_ok"] = ("isinstance(doc_ref, _FirestoreDocRef)" in inspect.getsource(appr._cas_claim)
                              and "__module__" not in inspect.getsource(appr._cas_claim))
    out["network_attempts"] = ns["NETWORK_ATTEMPTS"]
    print(json.dumps(out))


@pytest.fixture(scope="module")
def result():
    # hermetic_guard.child_env: Layer-0 env (ADC -> non-existent file, NO_GCE_CHECK, loopback proxy, guard shim)
    env = hermetic_guard.child_env(drop=("TEST_MODE", "K_SERVICE", "SESSION_SECRET", "ADMIN_EMAIL"),
                                   extra={"PROJECT_ID": "mock-stackvend-project", "GOOGLE_CLOUD_PROJECT": "mock-stackvend-project"})
    out = subprocess.run([sys.executable, os.path.abspath(__file__), "--harness"],
                         capture_output=True, text=True, timeout=300, env=env)
    assert out.returncode == 0, out.stderr[-4000:]
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_hermetic(result):
    assert result["network_attempts"] == []


def test_two_concurrent_approvals_merge_exactly_once(result):
    r = result["concurrent"]
    assert r["outcomes"] == [200, 409], r
    assert r["merge_calls"] == 1, r
    assert (r["status"], r["merge_status"]) == ("APPROVED", "MERGED"), r
    # Contention really happened: one claim committed, the other was aborted by the transaction and retried.
    assert r["commit_log"].count("aborted") == 1 and r["commit_log"].count("committed") == 1, r


def test_single_decision_control(result):
    r = result["sequential_control"]
    assert (r["outcomes"], r["merge_calls"], r["status"]) == ([200], 1, "APPROVED"), r


def test_production_dispatch_is_a_type_check(result):
    assert result["dispatch_src_ok"] is True


if __name__ == "__main__" and "--harness" in sys.argv:
    _harness()
