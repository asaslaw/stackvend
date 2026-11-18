"""FD-4F GK-1/GK-2/GK-5/D7: /agent/gatekeeper/verify fails closed and judges the committed bytes."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

from fastapi.testclient import TestClient

from fd4f_support import SHA_A, FakeBackend, backend_factory, gw  # noqa: F401  (gw is a fixture)

# A tree that is already in the verifier's cured form is produced by running verify_and_cure once (the same thing
# the pre-commit gate does before committing).
RAW = {
    "apps/svc/main.py": "from fastapi import FastAPI\napp = FastAPI()\n\n@app.get('/')\ndef root():\n    return {'ok': True}\n",
    "apps/svc/requirements.txt": "fastapi==0.115.0\n",
}


def _cured_tree():
    from gatekeeper_agent.verifier import SynthesisVerifierAgent

    cured, passed, errors = SynthesisVerifierAgent(product_id="svc").verify_and_cure(dict(RAW), product_id="svc")
    assert passed, errors
    return cured


def _client(gw, backend):
    gw.app.dependency_overrides[gw.get_source_backend_factory] = lambda: backend_factory(backend)
    return TestClient(gw.app)


def _post(c, **body):
    payload = {"trace_id": "tr-1", "product_id": "svc", "branch_name": "castor/svc-1"}
    payload.update(body)
    return c.post("/agent/gatekeeper/verify", json={k: v for k, v in payload.items() if v is not None})


def test_negative_cured_tree_passes_and_verifier_sees_exact_bytes(gw, monkeypatch):
    cured = _cured_tree()
    backend = FakeBackend({"castor/svc-1": {k: v.encode() for k, v in cured.items()}}, {"castor/svc-1": SHA_A})
    seen = {}
    from gatekeeper_agent.verifier import SynthesisVerifierAgent

    real = SynthesisVerifierAgent.verify_and_cure

    def spy(self, files, **kw):
        seen["files"] = dict(files)
        return real(self, files, **kw)

    monkeypatch.setattr(SynthesisVerifierAgent, "verify_and_cure", spy)
    r = _post(_client(gw, backend))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["passed"] is True and body["error_class"] is None
    assert body["commit_sha"] == SHA_A
    assert seen["files"] == cured  # Do No Harm: the gate received the committed tree byte-for-byte


def test_fetch_failure_is_gate_unavailable_not_pass(gw):
    r = _post(_client(gw, FakeBackend({}, {}, fail=True)))
    assert r.status_code == 503
    assert r.json()["error_class"] == "GATE_UNAVAILABLE" and r.json()["passed"] is False
    assert r.json()["reason"] == "SOURCE_FETCH"


def test_files_and_branch_together_or_neither_is_422(gw):
    c = _client(gw, FakeBackend({}, {}))
    assert _post(c, files={"a.py": "x = 1\n"}).status_code == 422
    assert c.post("/agent/gatekeeper/verify", json={"trace_id": "tr-1", "product_id": "svc"}).status_code == 422


def test_empty_files_manifest_is_gate_unavailable(gw):
    c = _client(gw, FakeBackend({}, {}))
    r = c.post("/agent/gatekeeper/verify", json={"trace_id": "tr-1", "product_id": "svc", "files": {}})
    assert r.status_code == 503 and r.json()["reason"] == "EMPTY_TREE"


def test_gk5_cure_would_change_committed_tree_is_platform_defect(gw):
    backend = FakeBackend({"castor/svc-1": {k: v.encode() for k, v in RAW.items()}}, {"castor/svc-1": SHA_A})
    r = _post(_client(gw, backend))
    assert r.status_code == 503, r.text
    body = r.json()
    assert body["error_class"] == "PLATFORM_DEFECT" and body["reason"] == "CURE_WOULD_CHANGE_TREE"
    assert "apps/svc/__init__.py" in body["details"]["changed_paths"]  # FD-4AD: requirements are add-only; FD-55 W5: the verifier no longer pins .python-version, so the remaining change is the package init
    assert "apps/svc/requirements.txt" not in body["details"]["changed_paths"]
    assert body["details"]["commit_sha"] == SHA_A


def test_verifier_crash_is_gate_unavailable(gw, monkeypatch):
    from gatekeeper_agent.verifier import SynthesisVerifierAgent

    monkeypatch.setattr(SynthesisVerifierAgent, "verify_and_cure", lambda self, files, **kw: (_ for _ in ()).throw(ValueError("boom")))
    backend = FakeBackend({"castor/svc-1": {"a.py": b"x = 1\n"}}, {"castor/svc-1": SHA_A})
    r = _post(_client(gw, backend))
    assert r.status_code == 503 and r.json()["reason"] == "VERIFIER_ERROR"


def test_trace_id_required_and_validated(gw):
    c = _client(gw, FakeBackend({}, {}))
    assert c.post("/agent/gatekeeper/verify", json={"product_id": "svc", "branch_name": "b"}).status_code == 422
    assert _post(c, trace_id="../x").status_code == 422
    assert _post(c, branch_name="../../etc").status_code == 422
