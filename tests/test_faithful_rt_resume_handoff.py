"""faithful-hd01-hd02 code RT fix 1 (register row FH-7): a Control Center RESUME_DEVELOPER relaunch skips the
architect, so it copies the architect's typed compute record (`architect_compute_intent`) from the previous execution
onto the new trace -- in the intake payload and in `pipeline_executions/{new trace}` -- with `copied_from_trace`.
Without a prior record nothing is written (the developer then fails closed, COMPUTE_INTENT_MISSING); a FULL relaunch
never copies (the architect runs again and writes a fresh record).

The real `retrigger_feature_request_build` runs in a clean subprocess (hermetic_guard.child_env) on the FD-4E hermetic
harness prefix (sockets/DNS refused and recorded, no ADC), with a filtering in-memory Firestore and a fake publisher."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
HOST = "mock-stackvend-project"
PID = "demo"
RECORD = {"schema": "architect_compute_intent/v1", "target_compute_services": ["stream-processor"],
          "bundle_id": "private-gke-microservices", "compute_archetype": "gke-autopilot"}


# ------------------------------------------------------------------------------------------------ fakes (child)
class Snap:
    def __init__(self, id_, data):
        self.id, self._d, self.exists = id_, data, data is not None

    def to_dict(self):
        return dict(self._d) if self._d is not None else None


class Doc:
    def __init__(self, db, path):
        self.db, self.path, self.id = db, path, path[-1]

    def get(self):
        return Snap(self.id, self.db.store.get(self.path))

    def set(self, data, merge=False):
        cur = self.db.store.get(self.path) if merge else None
        self.db.store[self.path] = {**(cur or {}), **data}

    def collection(self, name):
        return Coll(self.db, self.path + (name,))


class Coll:
    def __init__(self, db, path, filters=()):
        self.db, self.path, self.filters = db, path, filters

    def document(self, id_):
        return Doc(self.db, self.path + (id_,))

    def where(self, field, op, value):
        return Coll(self.db, self.path, self.filters + ((field, op, value),))

    def limit(self, *_):
        return self

    def stream(self):
        return [Snap(p[-1], d) for p, d in list(self.db.store.items())
                if len(p) == len(self.path) + 1 and p[:-1] == self.path
                and all(op == "==" and d.get(f) == v for f, op, v in self.filters)]


class FakeDB:
    def __init__(self):
        self.store = {}

    def collection(self, name):
        return Coll(self, (name,))


class FakePublisher:
    def __init__(self):
        self.messages = []

    def publish(self, topic, data):
        self.messages.append((topic, json.loads(data.decode("utf-8"))))

        class _F:
            @staticmethod
            def result(timeout=None):
                return "msg-1"
        return _F()


def _seed(db, prior):
    db.store[("feature_requests", "fr-1")] = {"product_id": PID, "title": "Stream processor", "description": "spec"}
    # A resumable workload (RESUME-DEVELOPER-TASK-DAG): the full build's passed gate and its kept Task DAG
    db.store[("workloads", PID)] = {"project_id": "sv-demo-1a2b", "github_repo": "example-org/demo",
                                    "last_prebuild_gate": {"status": "PASS", "trace_id": "t-full", "product_id": PID,
                                                           "rework_cycle": 0}}
    db.store[("workloads", PID, "prebuild_task_dags", "t-full")] = {
        "product_id": PID, "trace_id": "t-full", "rework_cycle": 0, "status": "STORED", "task_count": 1}
    if prior is not None:
        db.store[("pipeline_executions", prior["trace_id"])] = prior


def _harness():
    marker = "# ================================================================ public mode"
    src_path = os.path.join(HERE, "cc_identity_harness.py")
    with open(src_path, encoding="utf-8") as f:
        src = f.read()
    assert marker in src, "FD-4E harness prefix changed"
    ns = {"__file__": src_path, "__name__": "cc_resume_handoff_harness"}
    exec(compile(src.split(marker, 1)[0], src_path, "exec"), ns)
    from types import SimpleNamespace
    from unittest.mock import MagicMock, patch
    import routes.workloads as wl

    def run(prior, body):
        db, pub = FakeDB(), FakePublisher()
        _seed(db, prior)
        main_mod = SimpleNamespace(project_id=HOST, get_pubsub_publisher=lambda: pub)
        req = MagicMock()
        req.state.user_email = "operator@example.com"
        from build_admission_support import every_build_admitted   # BUILD-ADMISSION-QUEUE: this store holds no slots
        with patch.object(wl, "db", db), patch.object(wl, "verify_workload_access", lambda *a, **k: None), \
                patch.object(wl, "get_caller_main_module", lambda: main_mod), every_build_admitted(wl):
            res = wl.retrigger_feature_request_build(PID, "fr-1", req, body=body)
        trace = res["trace_id"]
        return {"mode": res["execution_mode"], "trace": trace,
                "doc": db.store.get(("pipeline_executions", trace), {}).get("architect_compute_intent", "<absent>"),
                "payload": pub.messages[0][1].get("architect_compute_intent", "<absent>")}

    failed_dev = {"trace_id": "trace-prev-1", "product_id": PID, "status": "FAILED", "current_stage": "DEVELOPER",
                  "started_at": "2026-10-13T10:00:00Z", "stages": {"developer": {"status": "FAILED"}},
                  "architect_compute_intent": dict(RECORD)}
    no_record = {k: v for k, v in failed_dev.items() if k != "architect_compute_intent"}
    out = {
        "explicit_resume": run(failed_dev, {"execution_mode": "RESUME_DEVELOPER"}),
        "auto_resume": run(failed_dev, None),
        "resume_without_record": run(no_record, {"execution_mode": "RESUME_DEVELOPER"}),
        "resume_without_prior": run(None, {"execution_mode": "RESUME_DEVELOPER"}),
        "full": run(failed_dev, {"execution_mode": "FULL"}),
        "network_attempts": ns["NETWORK_ATTEMPTS"],
    }
    print(json.dumps(out, default=str))


@pytest.fixture(scope="module")
def resume():
    # hermetic_guard.child_env: Layer-0 env (ADC -> non-existent file, NO_GCE_CHECK, loopback proxy, guard shim)
    env = hermetic_guard.child_env(drop=("TEST_MODE", "K_SERVICE", "SESSION_SECRET", "ADMIN_EMAIL"),
                                   extra={"PROJECT_ID": HOST, "GOOGLE_CLOUD_PROJECT": HOST,
                                          "MANAGED_WORKLOADS_FOLDER_ID": "111111111111", "GITHUB_OWNER": "example-org"})
    out = subprocess.run([sys.executable, os.path.abspath(__file__), "--harness"],
                         capture_output=True, text=True, timeout=300, env=env)
    assert out.returncode == 0, out.stderr[-4000:]
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_resume_harness_is_hermetic(resume):
    assert resume["network_attempts"] == []


@pytest.mark.parametrize("case", ["explicit_resume", "auto_resume"])
def test_resume_copies_the_prior_record_to_the_new_trace_with_copied_from_trace(resume, case):
    r = resume[case]
    assert r["mode"] == "RESUME_DEVELOPER" and r["trace"].startswith(f"resume-{PID}-")
    expected = dict(RECORD, copied_from_trace="trace-prev-1")
    assert r["doc"] == expected   # what the developer reads by trace id
    assert r["payload"] == expected


@pytest.mark.parametrize("case", ["resume_without_record", "resume_without_prior"])
def test_resume_without_a_prior_record_fabricates_nothing(resume, case):
    r = resume[case]
    assert r["mode"] == "RESUME_DEVELOPER"
    assert r["doc"] == "<absent>" and r["payload"] == "<absent>"


def test_full_relaunch_never_copies_a_stale_record(resume):
    r = resume["full"]
    assert r["mode"] == "FULL" and r["doc"] == "<absent>" and r["payload"] == "<absent>"


if __name__ == "__main__" and "--harness" in sys.argv:
    _harness()
