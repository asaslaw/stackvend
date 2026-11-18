"""FD-4F test support: hermetic gateway loader + fakes (Firestore, source backend, QA job, Run API, GCS).

Nothing here touches the network or real Google clients: every gate dependency is injected through the
gateway's FastAPI dependencies (get_qa_job_client / get_source_backend_factory / get_evidence_db) or the
qa_job_client constructor. Nothing reads TEST_MODE (FD-4F D1).
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import io
import json
import os
import sys
import tarfile
from typing import Any, Dict, List, Optional

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GW_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
if GW_DIR not in sys.path:
    sys.path.insert(0, GW_DIR)

SHA_A = "a" * 40
SHA_B = "b" * 40


def load_gateway(monkeypatch, name: str = "fd4f_gw_main"):
    """Imports apps/orchestrator-gateway/main.py by path with real web-stack modules and no project (no clients)."""
    from fd4g_support import real_modules
    import importlib.util

    real_modules(monkeypatch)
    for k in ("PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "GCP_PROJECT", "GEMINI_API_KEY", "GOOGLE_API_KEY", "K_SERVICE",
              "QA_JOB_NAME", "QA_STAGING_BUCKET", "QA_SANDBOX_SA", "REGION"):
        monkeypatch.delenv(k, raising=False)
    if GW_DIR not in sys.path:
        sys.path.insert(0, GW_DIR)
    spec = importlib.util.spec_from_file_location(name, os.path.join(GW_DIR, "main.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def gw(monkeypatch):
    mod = load_gateway(monkeypatch)
    yield mod
    mod.app.dependency_overrides.clear()


def make_tar(files: Dict[str, bytes], *, prefix: str = "", extra: Optional[List[tarfile.TarInfo]] = None,
             gz: bool = True) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz" if gz else "w") as tf:
        if prefix:
            ti = tarfile.TarInfo(prefix.rstrip("/"))
            ti.type = tarfile.DIRTYPE
            tf.addfile(ti)
        for name, data in files.items():
            ti = tarfile.TarInfo(prefix + name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
        for ti in extra or []:
            tf.addfile(ti)
    return raw.getvalue()


# ------------------------------------------------------------------ Firestore fake
class _Snap:
    def __init__(self, db, path):
        self._db, self._path = db, path
        self.id = path.rsplit("/", 1)[-1]
        self.reference = _DocRef(db, path)
        self._read_version = getattr(db, "versions", {}).get(path)

    @property
    def exists(self):
        return self._path in self._db.docs

    @property
    def update_time(self):
        """Version token of the document at read time (lane 14 RT F11 precondition writes)."""
        return self._read_version

    def to_dict(self):
        return json.loads(json.dumps(self._db.docs.get(self._path))) if self.exists else None



def firestore_nested_array_paths(value: Any, path: str = "", in_array: bool = False) -> List[str]:
    """JUDGE-NAMED-INTENT-REMOVAL RT F1: Firestore refuses an array directly inside an array (the real client sends it
    and the server answers 400). The paths of every such array in `value` ([] = storable); the fake stores enforce it."""
    out: List[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            out += firestore_nested_array_paths(v, f"{path}.{k}", False)
    elif isinstance(value, (list, tuple)):
        if in_array:
            return [path]
        for i, v in enumerate(value):
            out += firestore_nested_array_paths(v, f"{path}[{i}]", True)
    return out


class _DocRef:
    def __init__(self, db, path):
        self._db, self._path = db, path

    def get(self, timeout=None):   # DocumentReference.get(timeout=...) (STAGE-JOB-RUNNER N8)
        if self._db.fail_reads:
            raise RuntimeError("firestore read failed")
        return _Snap(self._db, self._path)

    def set(self, data, merge=False):
        if self._db.fail_writes:
            raise RuntimeError("firestore write failed")
        bad = firestore_nested_array_paths(json.loads(json.dumps(data, default=str)))
        if bad:   # JUDGE-NAMED-INTENT-REMOVAL RT F1: what Firestore would refuse (400) is refused here too
            raise ValueError(f"Firestore cannot store an array inside an array: {bad[:5]}")
        self._db.writes.append((self._path, dict(data), merge))
        if merge and self._path in self._db.docs:
            self._db.docs[self._path].update(json.loads(json.dumps(data, default=str)))
        else:
            self._db.docs[self._path] = json.loads(json.dumps(data, default=str))

    def create(self, data):
        """Firestore DocumentReference.create(): AlreadyExists when the document exists (lane 17 RT F7 idempotency)."""
        if self._db.fail_writes:
            raise RuntimeError("firestore write failed")
        if self._path in self._db.docs:
            from google.api_core import exceptions as gexc

            raise gexc.AlreadyExists(f"{self._path} already exists")
        self.set(data)

    def update(self, data, option=None):
        """DocumentReference.update(): NotFound when absent; FailedPrecondition when `option` (from
        FakeDB.write_option(last_update_time=...)) no longer matches the stored version (lane 14 RT F11)."""
        from google.api_core import exceptions as gexc

        if self._db.fail_writes:
            raise RuntimeError("firestore write failed")
        if self._path not in self._db.docs:
            raise gexc.NotFound(f"{self._path} not found")
        versions = self._db.__dict__.setdefault("versions", {})
        if option is not None and option.get("last_update_time") != versions.get(self._path):
            raise gexc.FailedPrecondition(f"{self._path} changed since it was read")
        self._db.writes.append((self._path, dict(data), "update"))
        self._db.docs[self._path].update(json.loads(json.dumps(data, default=str)))
        versions[self._path] = versions.get(self._path, 0) + 1

    def collection(self, name):
        return _ColRef(self._db, f"{self._path}/{name}")


class _ColRef:
    def __init__(self, db, path):
        self._db, self._path = db, path

    def document(self, doc_id=None):
        if doc_id is None:   # CollectionReference.document(): a new auto id (RT14 D3 audit entries)
            self._db.__dict__["auto_ids"] = self._db.__dict__.get("auto_ids", 0) + 1
            doc_id = f"auto-{self._db.auto_ids}"
        return _DocRef(self._db, f"{self._path}/{doc_id}")

    def order_by(self, *a, **k):
        return self

    def where(self, *a, **k):
        return self

    def limit(self, n):
        return self

    def stream(self):
        prefix = self._path + "/"
        return [_Snap(self._db, p) for p in list(self._db.docs) if p.startswith(prefix) and "/" not in p[len(prefix):]]


class FakeDB:
    def __init__(self):
        self.docs: Dict[str, Dict[str, Any]] = {}
        self.writes: List[Any] = []
        self.fail_reads = False
        self.fail_writes = False

    def collection(self, name):
        return _ColRef(self, name)

    def write_option(self, **kw):
        return dict(kw)

    def batch(self):
        return _Batch(self)


class _Batch:
    """WriteBatch: buffered `set` / `create` / `update` applied on `commit()`, all or nothing (a failing store, an
    existing `create` target or a missing / changed `update` target applies none: RT14 D3)."""

    def __init__(self, db):
        self._db, self._ops = db, []

    def set(self, ref, data, merge=False):
        self._ops.append(("set", ref, data, merge))

    def create(self, ref, data):
        self._ops.append(("create", ref, data, None))

    def update(self, ref, data, option=None):
        self._ops.append(("update", ref, data, option))

    def commit(self):
        from google.api_core import exceptions as gexc

        if self._db.fail_writes:
            raise RuntimeError("firestore write failed")
        versions = self._db.__dict__.setdefault("versions", {})
        for kind, ref, _data, option in self._ops:   # preconditions first: nothing applies when one fails
            if kind == "create" and ref._path in self._db.docs:
                raise gexc.AlreadyExists(f"{ref._path} already exists")
            if kind == "update" and ref._path not in self._db.docs:
                raise gexc.NotFound(f"{ref._path} not found")
            if kind == "update" and option is not None and option.get("last_update_time") != versions.get(ref._path):
                raise gexc.FailedPrecondition(f"{ref._path} changed since it was read")
        for kind, ref, data, extra in self._ops:
            if kind == "set":
                ref.set(data, merge=extra)
            elif kind == "create":
                ref.create(data)
            else:
                ref.update(data)


# QA-STAGE2-POLICY: the security judge's policy comes from workloads/{pid}.access + the persisted compliance decision.
QA_IAP_ACCESS = {"mode": "PRIVATE_IAP", "invoker_principals": ["group:staff@example.com"],
                 "sign_in": {"google": "DISABLED"}, "source": "intake"}


def seed_compliance_decision(db: FakeDB, product_id="app", trace_id="tr-1", *, allow_unauthenticated=False,
                             enable_direct_iap=True):
    db.docs[f"workloads/{product_id}/compliance_audits/{trace_id}"] = {
        "product_id": product_id, "trace_id": trace_id, "allow_unauthenticated": allow_unauthenticated,
        "enable_direct_iap": enable_direct_iap, "domain_restricted_sharing": False, "allowed_domains": []}


def seed_context(db: FakeDB, product_id="app", trace_id="tr-1"):
    db.docs[f"workloads/{product_id}"] = {"vcs_provider": "GITHUB", "access": dict(QA_IAP_ACCESS)}
    seed_compliance_decision(db, product_id, trace_id)
    db.docs[f"pipeline_executions/{trace_id}"] = {
        "stages": {"architect": {"details": {"task_dag": [{"task_id": "t1", "title": "svc"}]}},
                   "compliance": {"summary": "ok", "details": {"active_frameworks": ["SOC2-BASELINE"]}}}
    }


# ------------------------------------------------------------------ source backend fake
class FakeBackend:
    strip_top_dir = False

    def __init__(self, trees: Dict[str, Dict[str, bytes]], shas: Dict[str, str], *, fail: bool = False):
        self.trees, self.shas, self.fail = trees, shas, fail
        self.calls: List[Any] = []

    def head_sha(self, branch):
        from qa_source import BranchFetchError, BranchNotFoundError

        self.calls.append(("head", branch))
        if self.fail:
            raise BranchFetchError(f"source unavailable ({branch})")
        if branch not in self.shas:   # RT14-28: the providers' typed "no such branch"
            raise BranchNotFoundError(f"no branch {branch}")
        return self.shas[branch]

    def archive(self, branch, sha):
        self.calls.append(("archive", branch, sha))
        return sha, make_tar(self.trees[branch])


def backend_factory(backend):
    return lambda product_id: backend


# ------------------------------------------------------------------ QA job client fake
class FakeQAClient:
    def __init__(self, outcome):
        self.outcome = outcome
        self.calls: List[Dict[str, Any]] = []
        self.readiness_checks = 0
        self.readiness_error: Optional[BaseException] = None  # row L3-PRB-r: what verify_job_readiness raises

    def run(self, **kw):
        self.calls.append(kw)
        return self.outcome

    def verify_job_readiness(self):
        self.readiness_checks += 1
        if self.readiness_error is not None:
            raise self.readiness_error


def passing_outcome():
    from qa_job_client import QAOutcome

    return QAOutcome(passed=True, error_class=None, summary="QA passed: 3/3 tests",
                     static={"passed": True}, report={"passed": True, "tests_total": 3, "tests_failed": 0, "logs_tail": "3 passed"},
                     exit_code=0, execution_name="projects/p/locations/r/jobs/j/executions/e1", nonce="n" * 32)


def code_defect_outcome(code="PY.TEST_FAILED", message="tests/test_a.py::test_x failed", file="tests/test_a.py"):
    from gate_errors import ErrorClass
    from qa_job_client import QAOutcome

    return QAOutcome(passed=False, error_class=ErrorClass.CODE_DEFECT, summary="QA failed",
                     diagnostics=[{"tool": "pytest", "code": code, "severity": "error", "file": file, "line": 3,
                                   "message": message, "detail": None}],
                     static={"passed": True}, report={"passed": False}, exit_code=10, nonce="n" * 32)


def judge_reply(sec_passed=True, crit=None, adh=1.0, gnd=1.0, missed=None):
    def _call(prompt, model, **kw):
        if "Security Engineer" in prompt:
            return json.dumps({"passed": sec_passed, "critical_vulnerabilities": crit or [],
                               "moderate_vulnerabilities": [], "compliance_flags": [], "summary": "s"})
        return json.dumps({"instruction_adherence_score": adh, "grounding_score": gnd,
                           "missed_directives": missed or [], "hallucinated_features": [], "summary": "a"})
    return _call


def sdk_response(text: Optional[str] = None, finish: Optional[str] = "STOP", thought: Optional[str] = None,
                 usage: Optional[Dict[str, int]] = None, candidates: bool = True) -> Any:
    """A real google.genai GenerateContentResponse (JUDGE-LEVEL-FAMILY-CONFIG: the judge reads typed parts and the
    finish reason). `thought` adds a thought part BEFORE the answer part; `text=None` sends no answer part."""
    from google.genai import types

    parts = []
    if thought is not None:
        parts.append(types.Part(text=thought, thought=True))
    if text is not None:
        parts.append(types.Part(text=text))
    data: Dict[str, Any] = {"usage_metadata": usage or {"prompt_token_count": 10, "candidates_token_count": 5}}
    if candidates:
        data["candidates"] = [{"content": {"role": "model", "parts": [p.model_dump(exclude_none=True) for p in parts]},
                               **({"finish_reason": finish} if finish is not None else {})}]
    return types.GenerateContentResponse.model_validate(data)
