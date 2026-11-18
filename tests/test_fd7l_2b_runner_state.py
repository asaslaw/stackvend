"""FD-7L Phase 2b on the terraform server (plan docs/planning/fd-7l-per-workload-runner-identity-plan.md rev 3,
sections 2.6, 2.7 step 6, 2.11, precondition P1 of section 6): the run's mode and state location
(`_runner_state_context`), the platform backend writer (`prepare_workspace`), the pre-init gate wiring, the drift
backend check, `force_unlock`'s refusal of the migration tombstone / migration lock, and the STATE_LOCKED message.

Do No Harm: on a Shared install (STACKVEND_TF_RUNNER_IDENTITY unset / PLATFORM) nothing is read from the guard
database, backend.tf is byte-identical and written first (a committed root backend.tf still wins, as today), and every
result is unchanged; only POLICY_WOULD_REFUSE log lines are added. Hermetic fakes only.
"""
import hermetic_guard  # noqa: F401  (first import)

import json
import logging
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import fd7l_fakes as k  # noqa: E402
from fd4g_support import load_tf_service  # noqa: E402
from shared import runner_identity as ri  # noqa: E402

pytest.importorskip("hcl2", reason="python-hcl2 (terraform MCP requirement) not installed")

PID, PROJECT, NUMBER = "shop-api", "shop-api-a1b2c3", "123456789012"
CHILD_BUCKET = f"{PROJECT}-tfstate"
PLATFORM_BUCKET = "castor-tfstate-host"
SIGNED_AT = "2026-10-31T12:00:00+00:00"
OLD_BACKEND = f"""terraform {{
  required_version = ">= 1.5.0"
  backend "gcs" {{
    bucket = "{PLATFORM_BUCKET}"
    prefix = "workloads/{PID}"
  }}
}}
"""


def signed_record(status="READY", key=k.BROKER_KEY, **over):
    rec = ri.new_runner_identity_record(product_id=PID, project_id=PROJECT, project_number=NUMBER,
                                        state_bucket=CHILD_BUCKET, status=status, updated_at=SIGNED_AT)
    rec.update(over)
    return ri.sign_record(ri.provenance_doc_path(PID), rec, signer_email=k.BROKER, signed_at=SIGNED_AT,
                          sign_blob=key.sign)


def forged():
    """Signed with another key but claiming the broker's published key id (RUNNER_RECORD_UNSIGNED)."""
    rec = signed_record(key=k.OTHER_KEY)
    rec["signature"] = dict(rec["signature"], key_id=k.BROKER_KEY.key_id)
    return rec


class _Snap:
    def __init__(self, data):
        self.exists = data is not None
        self._d = data

    def to_dict(self):
        return dict(self._d) if self._d is not None else None


class GuardDB:
    def __init__(self, docs=None, boom=False):
        self.docs, self.boom, self.reads = docs or {}, boom, []

    def collection(self, name):
        db = self

        class _C:
            def document(self, doc_id):
                class _D:
                    def get(self_inner):
                        db.reads.append(f"{name}/{doc_id}")
                        if db.boom:
                            raise RuntimeError("guard db down")
                        return _Snap(db.docs.get(f"{name}/{doc_id}"))
                return _D()
        return _C()


def provenance(record):
    doc = {"created_by": "stackvend-vending", "project_id": PROJECT, "project_number": NUMBER}
    if record is not None:
        doc[ri.RUNNER_IDENTITY_FIELD] = record
    return doc


@pytest.fixture
def tf(monkeypatch):
    monkeypatch.delenv(ri.MODE_ENV, raising=False)
    return load_tf_service(monkeypatch)


def _svc(tf, tmp_path, guard=None):
    svc = tf.TerraformService(project_id=k.HOST, state_bucket=PLATFORM_BUCKET, workspace_base_dir=str(tmp_path),
                              firestore_client=object())
    svc.guard_db = guard if guard is not None else GuardDB(boom=True)   # PLATFORM must never read it
    svc.runner_certs = k.certs_for()
    return svc


def _per_workload(monkeypatch):
    monkeypatch.setenv(ri.MODE_ENV, ri.MODE_PER_WORKLOAD)
    monkeypatch.setenv(ri.BROKER_SA_ENV, k.BROKER)


def _guard(record):
    return GuardDB({f"{ri.PROVENANCE_COLLECTION}/{PID}": provenance(record)})


# ------------------------------------------------------------------------------------------------ mode / context
def test_platform_context_reads_nothing(tf, tmp_path):
    svc = _svc(tf, tmp_path)
    ctx = svc._runner_state_context(PID, target_project_id=PROJECT)
    assert (ctx.mode, ctx.bucket, ctx.source, ctx.per_workload) == (ri.MODE_PLATFORM, PLATFORM_BUCKET, "platform",
                                                                    False)
    assert svc.guard_db.reads == []


def test_the_mode_is_read_in_one_place():
    """F4-ready (review F5): the terraform runner (service, tf-applier, the mode log line) calls the shared
    runner_identity_mode exactly once, inside TerraformService._runner_identity_mode, under any alias (AST: every call
    whose function is named runner_identity_mode, as a name or an attribute); nothing reads the mode env directly."""
    import ast
    calls = []
    for name in ("service.py", "runner_credentials.py", "applier.py", "main.py"):
        tree = ast.parse(open(os.path.join(REPO_ROOT, "mcp-servers", "terraform", name), encoding="utf-8").read())
        stack = []

        class _V(ast.NodeVisitor):
            def visit_FunctionDef(self, node):
                stack.append(node.name)
                self.generic_visit(node)
                stack.pop()

            def visit_Call(self, node):
                fn = node.func
                fname = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", None)
                if fname == "runner_identity_mode":
                    calls.append((name, stack[-1] if stack else "<module>"))
                self.generic_visit(node)

            def visit_Attribute(self, node):
                assert node.attr != "MODE_ENV" or name == "runner_credentials.py", (name, node.lineno)
                self.generic_visit(node)

        _V().visit(tree)
    assert calls == [("service.py", "_runner_identity_mode")]


def test_unknown_mode_refuses_every_run(tf, tmp_path, monkeypatch):
    monkeypatch.setenv(ri.MODE_ENV, "SOMETIMES")
    svc = _svc(tf, tmp_path)
    monkeypatch.setattr(svc, "_run_subprocess", lambda *a, **kw: pytest.fail("tofu must not run"))
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **kw: None)
    monkeypatch.setattr(svc, "_ensure_binary", lambda *a, **kw: "tofu")
    res = svc.generate_plan(PID, "t1", {"main.tf": ""}, iac_engine="OPENTOFU")
    assert (res["status"], res["error_class"], res["operator_required"]) == ("FAILED", "RUNNER_IDENTITY_MODE_INVALID",
                                                                             True)
    res = svc.force_unlock(product_id=PID, lock_id="1", trace_id="t2")
    assert res["error_class"] == "RUNNER_IDENTITY_MODE_INVALID"


def test_per_workload_ready_record(tf, tmp_path, monkeypatch):
    _per_workload(monkeypatch)
    svc = _svc(tf, tmp_path, _guard(signed_record()))
    ctx = svc._runner_state_context(PID, target_project_id=PROJECT)
    assert (ctx.bucket, ctx.source, ctx.project_id, ctx.deployer_email) == (
        CHILD_BUCKET, "provenance", PROJECT, ri.deployer_email(PROJECT))


@pytest.mark.parametrize("record,code", [
    (signed_record(status="MIGRATING"), "STATE_MIGRATION_IN_PROGRESS"),
    (signed_record(status="BUCKET_READY"), "RUNNER_IDENTITY_NOT_READY"),
    (signed_record(status="FAILED"), "RUNNER_IDENTITY_NOT_READY"),
    (None, "RUNNER_IDENTITY_NOT_READY"),
    (forged(), "RUNNER_RECORD_UNSIGNED"),
    (signed_record(key=k.OTHER_KEY), "RUNNER_RECORD_KEY_RETIRED"),
    (dict(signed_record(), status="READY", state_bucket="someone-elses-bucket"), "RUNNER_RECORD_UNSIGNED"),
])
def test_per_workload_never_falls_back(tf, tmp_path, monkeypatch, record, code):
    _per_workload(monkeypatch)
    svc = _svc(tf, tmp_path, _guard(record))
    with pytest.raises(tf.RunnerIdentityRefused) as e:
        svc._runner_state_context(PID)
    assert e.value.error_class == code


def test_per_workload_target_mismatch_and_store_errors(tf, tmp_path, monkeypatch):
    _per_workload(monkeypatch)
    svc = _svc(tf, tmp_path, _guard(signed_record()))
    with pytest.raises(tf.RunnerIdentityRefused) as e:
        svc._runner_state_context(PID, target_project_id="another-project-1")
    assert e.value.error_class == "RUNNER_TARGET_MISMATCH"
    with pytest.raises(tf.RunnerIdentityRefused) as e:
        _svc(tf, tmp_path, GuardDB(boom=True))._runner_state_context(PID)
    assert e.value.error_class == "RUNNER_STORE_UNAVAILABLE"
    bare = _svc(tf, tmp_path)
    bare.guard_db = None
    monkeypatch.delenv(tf.GUARD_DB_ENV, raising=False)
    with pytest.raises(tf.RunnerIdentityRefused) as e:
        bare._runner_state_context(PID)
    assert e.value.error_class == "RUNNER_STORE_UNAVAILABLE"


# ------------------------------------------------------------------------------------------------ backend writer
def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def test_platform_backend_is_byte_identical_and_written_first(tf, tmp_path, caplog):
    svc = _svc(tf, tmp_path)
    ws = svc.prepare_workspace(PID, "t1", {"main.tf": "# x\n"})
    assert _read(os.path.join(ws, "backend.tf")) == OLD_BACKEND
    committed = 'terraform {\n  backend "gcs" {\n    bucket = "committed"\n    prefix = "x"\n  }\n}\n'
    hcl = {"main.tf": "# x\n", "backend.tf": committed}
    with caplog.at_level(logging.INFO):
        ws2 = svc.prepare_workspace(PID, "t2", hcl)
    assert _read(os.path.join(ws2, "backend.tf")) == committed            # today: the committed file wins
    assert any("BACKEND_REPLACED_BY_PLATFORM (not applied, Shared install)" in r.getMessage() for r in caplog.records)
    assert svc.guard_db.reads == []


def test_per_workload_backend_replaces_a_committed_backend(tf, tmp_path, monkeypatch, caplog):
    _per_workload(monkeypatch)
    svc = _svc(tf, tmp_path, _guard(signed_record()))
    committed = 'terraform {\n  backend "gcs" {\n    bucket = "committed"\n    prefix = "x"\n  }\n}\n'
    hcl = {"main.tf": "# x\n", "backend.tf": committed}
    before = dict(hcl)
    with caplog.at_level(logging.WARNING):
        ws = svc.prepare_workspace(PID, "t1", hcl)
    assert _read(os.path.join(ws, "backend.tf")) == OLD_BACKEND.replace(PLATFORM_BUCKET, CHILD_BUCKET)
    assert hcl == before                                                   # the repository's files are unchanged
    assert any(r.getMessage().startswith("BACKEND_REPLACED_BY_PLATFORM:") for r in caplog.records)
    assert svc._workspace_runner_ctx(ws, PID).bucket == CHILD_BUCKET


# ------------------------------------------------------------------------------------------------ pre-init gate
FORBIDDEN = {"main.tf": 'provider "google" {\n  credentials = "x"\n}\n'}


def test_generate_plan_per_workload_refuses_before_init(tf, tmp_path, monkeypatch):
    _per_workload(monkeypatch)
    svc = _svc(tf, tmp_path, _guard(signed_record()))
    monkeypatch.setattr(svc, "_run_subprocess", lambda *a, **kw: pytest.fail("tofu must not run"))
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **kw: None)
    monkeypatch.setattr(svc, "_ensure_binary", lambda *a, **kw: "tofu")
    res = svc.generate_plan(PID, "t1", FORBIDDEN, iac_engine="OPENTOFU")
    assert (res["status"], res["error_class"], res["code"], res["operator_required"]) == (
        "FAILED", "APPLY_CONTENT_POLICY", "POLICY.PROVIDER_ATTRIBUTE_FORBIDDEN", True)
    assert res["preinit_policy_violations"][0]["file"] == "main.tf" and res["is_safe_autonomous"] is False


def test_generate_plan_platform_only_logs(tf, tmp_path, monkeypatch, caplog):
    svc = _svc(tf, tmp_path)
    calls = []

    def run(cmd, cwd, env=None, iac_engine=None):
        calls.append(cmd[1])
        return {"success": False, "exit_code": 1, "stdout": "", "stderr": "init failed"}

    monkeypatch.setattr(svc, "_run_subprocess", run)
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **kw: None)
    monkeypatch.setattr(svc, "_ensure_binary", lambda *a, **kw: "tofu")
    with caplog.at_level(logging.WARNING):
        res = svc.generate_plan(PID, "t1", FORBIDDEN, iac_engine="OPENTOFU")
    assert res == {"status": "INIT_FAILED", "error": "init failed", "stdout": ""}   # exactly today's result
    assert calls == ["init"]
    lines = [json.loads(r.getMessage()) for r in caplog.records if r.getMessage().startswith("{")]
    assert [(x["event"], x["code"], x["file"]) for x in lines] == [
        ("POLICY_WOULD_REFUSE", "POLICY.PROVIDER_ATTRIBUTE_FORBIDDEN", "main.tf")]


def test_deploy_calls_the_gate_right_before_the_first_init():
    import ast
    src = open(os.path.join(REPO_ROOT, "mcp-servers", "terraform", "service.py"), encoding="utf-8").read()
    impl = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef)
                and n.name == "_deploy_workload_impl")
    body = ast.get_source_segment(src, impl)
    gate = body.index("preinit_stop = self._preinit_policy_stop(workspace_dir, state_ctx, product_id, trace_id)")
    first_init = body.index('"terraform", "init"')
    assert gate < first_init and body.count('"terraform", "init"') == 1


def test_check_drift_per_workload_needs_the_platform_backend(tf, tmp_path, monkeypatch):
    _per_workload(monkeypatch)
    svc = _svc(tf, tmp_path, _guard(signed_record()))
    ws = svc._workspace_dir("t1", PID)
    os.makedirs(ws)
    with open(os.path.join(ws, "backend.tf"), "w", encoding="utf-8") as fh:
        fh.write(OLD_BACKEND)   # prepared for the platform bucket
    monkeypatch.setattr(svc, "_run_subprocess", lambda *a, **kw: pytest.fail("tofu must not run"))
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **kw: None)
    res = svc.check_drift(PID, "t1", iac_engine="OPENTOFU")
    assert (res["status"], res["error_class"]) == ("ERROR", "STATE_BACKEND_MISMATCH")
    with open(os.path.join(ws, "backend.tf"), "w", encoding="utf-8") as fh:
        fh.write(OLD_BACKEND.replace(PLATFORM_BUCKET, CHILD_BUCKET))
    monkeypatch.setattr(svc, "_run_subprocess", lambda *a, **kw: {"exit_code": 0, "stdout": "", "stderr": "",
                                                                    "success": True})
    assert svc.check_drift(PID, "t1", iac_engine="OPENTOFU")["status"] == "IN_SYNC"


# ------------------------------------------------------------------------------------------------ P1: force_unlock
def _tombstone():
    return ri.lock_info(operation=ri.TOMBSTONE_OPERATION, lock_id="mig-1",
                        info=ri.tombstone_info(CHILD_BUCKET, PID), path="p", created=SIGNED_AT)


def _migration_lock():
    return ri.lock_info(operation=ri.MIGRATION_LOCK_OPERATION, lock_id="mig-1", info="moving", path="p",
                        created=SIGNED_AT)


def _info(body):
    return {"lock_id": "77", "who": body.get("Who"), "operation": body.get("Operation"), "path": "gs://b/x"}


@pytest.mark.parametrize("per_workload", [False, True])
@pytest.mark.parametrize("body,kind", [(_tombstone(), "tombstone"), (_migration_lock(), "migration")])
def test_force_unlock_refuses_the_state_move_locks(tf, tmp_path, monkeypatch, per_workload, body, kind):
    if per_workload:
        _per_workload(monkeypatch)
    svc = _svc(tf, tmp_path, _guard(signed_record()) if per_workload else None)
    seen = []
    monkeypatch.setattr(svc, "_read_state_lock_object", lambda pid, bucket, **kw: seen.append(
        (bucket, kw.get("client_project"))) or (_info(body), body))
    monkeypatch.setattr(svc, "_run_subprocess", lambda *a, **kw: pytest.fail("tofu must not run"))
    res = svc.force_unlock(product_id=PID, lock_id="77", trace_id="t1")
    assert (res["status"], res["error_class"], res["state_move_lock"], res["operator_required"]) == (
        "FAILED", "STATE_MOVED_DO_NOT_UNLOCK", kind, True)
    # Per-workload: the workload's bucket, read through its brokered deployer (client_project); Shared: as before
    assert seen == [(CHILD_BUCKET, PROJECT) if per_workload else (PLATFORM_BUCKET, None)]


@pytest.mark.parametrize("reader", ["raises", "no_body"])
def test_force_unlock_refuses_an_unreadable_lock(tf, tmp_path, monkeypatch, reader):
    svc = _svc(tf, tmp_path)
    if reader == "raises":
        monkeypatch.setattr(svc, "_read_state_lock_object",
                            lambda pid, bucket, **kw: (_ for _ in ()).throw(RuntimeError("403")))
    else:
        monkeypatch.setattr(svc, "_read_state_lock_object", lambda pid, bucket, **kw: ({"lock_id": "77"}, None))
    monkeypatch.setattr(svc, "_run_subprocess", lambda *a, **kw: pytest.fail("tofu must not run"))
    res = svc.force_unlock(product_id=PID, lock_id="77", trace_id="t1")
    assert (res["status"], res["error_class"]) == ("FAILED", "STATE_LOCK_UNREADABLE")


def test_force_unlock_rereads_a_transient_failure_before_refusing(tf, tmp_path, monkeypatch):
    """Review F6: a transient read failure (google-api-core's own classifier, or a 412 when the lock changed between
    the metadata and body reads) is read again; only a lasting or non-transient failure refuses."""
    from google.api_core import exceptions as gexc
    svc = _svc(tf, tmp_path)
    monkeypatch.setattr(tf.time, "sleep", lambda s: None)
    body = {"ID": "x", "Operation": "OperationTypeApply", "Who": "cnb@localhost"}
    answers = [gexc.ServiceUnavailable("503"), gexc.PreconditionFailed("412"), (_info(body), body)]

    def read(pid, bucket, **kw):
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a

    monkeypatch.setattr(svc, "_read_state_lock_object", read)
    monkeypatch.setattr(svc, "_run_subprocess", lambda cmd, cwd, env=None, iac_engine=None: {
        "success": True, "exit_code": 0, "stdout": "ok", "stderr": ""})
    assert svc.force_unlock(product_id=PID, lock_id="77", trace_id="t1")["status"] == "UNLOCKED" and not answers
    for err, tries in ((gexc.ServiceUnavailable("503"), 3), (gexc.Forbidden("403"), 1)):
        n = []
        monkeypatch.setattr(svc, "_read_state_lock_object",
                            lambda pid, bucket, _e=err, **kw: n.append(1) or (_ for _ in ()).throw(_e))
        res = svc.force_unlock(product_id=PID, lock_id="77", trace_id="t2")
        assert (res["error_class"], len(n)) == ("STATE_LOCK_UNREADABLE", tries), err


def test_force_unlock_per_workload_without_a_brokered_deployer_is_typed(tf, tmp_path, monkeypatch):
    """Per-workload: the lock read goes through the brokered deployer; outside a dispatched execution there is none,
    so the unlock is refused with the 2a class, never read with the platform identity."""
    _per_workload(monkeypatch)
    svc = _svc(tf, tmp_path, _guard(signed_record()))
    monkeypatch.setattr(svc, "_run_subprocess", lambda *a, **kw: pytest.fail("tofu must not run"))
    res = svc.force_unlock(product_id=PID, lock_id="77", trace_id="t1")
    assert (res["status"], res["error_class"]) == ("FAILED", "RUNNER_IDENTITY_NOT_REGISTERED")


@pytest.mark.parametrize("found", [None, "ordinary"])
def test_force_unlock_proceeds_for_an_ordinary_or_absent_lock(tf, tmp_path, monkeypatch, found):
    """Negative (Do No Harm): an ordinary OpenTofu lock, or no lock object, unlocks exactly as before."""
    svc = _svc(tf, tmp_path)
    body = {"ID": "x", "Operation": "OperationTypeApply", "Who": "cnb@localhost"}
    monkeypatch.setattr(svc, "_read_state_lock_object",
                        lambda pid, bucket, **kw: None if found is None else (_info(body), body))
    calls = []

    def run(cmd, cwd, env=None, iac_engine=None):
        calls.append((cmd, cwd))
        return {"success": True, "exit_code": 0, "stdout": "ok", "stderr": ""}

    monkeypatch.setattr(svc, "_run_subprocess", run)
    res = svc.force_unlock(product_id=PID, lock_id="77", trace_id="t1")
    assert res == {"status": "UNLOCKED", "product_id": PID, "lock_id": "77", "stdout": "ok"}
    assert [c[0][1] for c in calls] == ["init", "force-unlock"]
    backend = _read(os.path.join(calls[0][1], "backend.tf"))
    assert backend == ('terraform {\n  backend "gcs" {\n    bucket = "' + PLATFORM_BUCKET + '"\n    prefix = '
                       f'"workloads/{PID}"\n  }}\n}}\n')


# ------------------------------------------------------------------------------------------------ STATE_LOCKED text
def test_state_locked_message_never_advises_unlocking_a_state_move_lock(tf, tmp_path):
    svc = _svc(tf, tmp_path)
    for body, kind in ((_tombstone(), "tombstone"), (_migration_lock(), "migration")):
        res = svc._state_locked_result(PID, _info(body), phase="pre-flight")
        assert res["error_class"] == "STATE_LOCKED" and res["state_move_lock"] == kind
        assert "force-unlock " not in res["error"].replace("Do not force-unlock it", "")
        assert "/force-unlock" not in res["error"] and res["operator_required"] is True


def test_state_locked_message_unchanged_for_an_ordinary_lock(tf, tmp_path):
    svc = _svc(tf, tmp_path)
    info = {"lock_id": "77", "who": "cnb@localhost", "created": "c", "operation": "OperationTypeApply"}
    res = svc._state_locked_result(PID, info, phase="apply")
    assert res["error"] == (
        f"STATE_LOCKED: OpenTofu state for '{PID}' is locked (lock ID 77, held by cnb@localhost since c, operation "
        "OperationTypeApply; detected at apply). StackVend never breaks state locks automatically. If no apply is "
        f"running for this workload, an operator can clear the lock with POST /api/workloads/{PID}/force-unlock "
        f'{{"product_id": "{PID}", "lock_id": "77"}}.')
    assert set(res) == {"status", "error_class", "error", "product_id", "lock_info", "lock_holder", "stdout",
                        "stderr"}


def test_preflight_wait_does_not_wait_for_a_tombstone(tf, tmp_path, monkeypatch):
    svc = _svc(tf, tmp_path)
    svc.lock_timeout = "600s"
    monkeypatch.setattr(svc, "_read_state_lock", lambda pid, bucket=None, **kw: _info(_tombstone()))
    monkeypatch.setattr(tf.time, "sleep", lambda s: pytest.fail("must not wait for a tombstone"))
    assert tf.state_move_lock_kind(svc._wait_for_state_lock_release(PID)) == "tombstone"


# ------------------------------------------------------------------------------------------------ deploy wiring
def _deploy(tf, svc, tmp_path, main_tf, plan_json=None, lock_reader=None):
    """deploy_workload with the FD-4H hermetic harness shape: a fixed workspace, tofu recorded, no Google calls; the
    real gated apply (content policy included) on `plan_json`, with the compliance gate answering PASS."""
    from unittest.mock import MagicMock, patch
    plan_json = plan_json or {"configuration": {"root_module": {}}, "resource_changes": []}
    ws = str(tmp_path / "ws")
    os.makedirs(ws, exist_ok=True)
    with open(os.path.join(ws, "main.tf"), "w", encoding="utf-8") as fh:
        fh.write(main_tf)
    calls, lock_buckets, lock_clients = [], [], []

    def fake_run(self, cmd, *a, **kw):
        calls.append(cmd[1])
        if cmd[1] == "output":
            return {"success": True, "exit_code": 0, "stdout": '{"service_url": {"value": "https://t.run.app"}}',
                    "stderr": ""}
        if cmd[1] == "show":
            return {"success": True, "exit_code": 0, "stderr": "", "stdout": json.dumps(plan_json)}
        return {"success": True, "exit_code": 0, "stdout": "", "stderr": ""}

    def read_lock(self, product_id, bucket=None, client_project=None):
        lock_buckets.append(bucket)
        lock_clients.append(client_project)
        return None

    svc.db = MagicMock()
    svc.lock_timeout = "0s"
    if svc._runner_identity_mode() == ri.MODE_PER_WORKLOAD:
        # FD-7L 2a: a Per-workload deploy runs only with the workload's brokered deployer registered for its trace
        # folder (tf-applier does it after the redeem); tofu is recorded here, so the endpoint is never used.
        import types
        svc._register_workspace_runner(os.path.join(svc.workspace_root, "t1"), types.SimpleNamespace(
            project_id=PROJECT, credentials=MagicMock(), key_id="k1",
            endpoint=types.SimpleNamespace(failure=None, host="127.0.0.1:9")))
    with patch("shutil.which", return_value="/usr/local/bin/tofu"), \
            patch.object(tf.TerraformService, "prepare_workspace", return_value=ws), \
            patch.object(tf.TerraformService, "_build_and_push_container", return_value=True), \
            patch.object(tf.TerraformService, "_ensure_provider_mirror"), \
            patch.object(tf.TerraformService, "_run_subprocess", fake_run), \
            patch.object(tf.TerraformService, "_read_state_lock", lock_reader or read_lock), \
            patch.object(tf.TerraformService, "_fetch_repo_files", return_value={}) as fetch, \
            patch.object(tf.TerraformService, "_validate_no_engine_downgrade"), \
            patch.object(tf.TerraformService, "_compliance_gate_check",
                         return_value={"passed": True, "evidence": {"verified": True}}), \
            patch("google.auth.default", return_value=(MagicMock(), "p")), \
            patch("google.auth.transport.requests.AuthorizedSession"), \
            patch("httpx.Client"):
        res = svc.deploy_workload(product_id=PID, trace_id="t1", hcl_files={"main.tf": main_tf},
                                  target_project_id=PROJECT, iac_engine="OPENTOFU")
    return res, calls, lock_buckets, fetch


CLEAN = 'module "foundation" {\n  source = "./infra/modules/foundation"\n}\n'


def test_deploy_platform_unchanged_and_only_logs(tf, tmp_path, caplog):
    svc = _svc(tf, tmp_path)
    with caplog.at_level(logging.WARNING):
        res, calls, buckets, _fetch = _deploy(tf, svc, tmp_path, FORBIDDEN["main.tf"])
    assert res["status"] == "SUCCESS", res
    assert res["state_file"] == f"gs://{PLATFORM_BUCKET}/workloads/{PID}/default.tfstate"
    assert "init" in calls and buckets == [None]           # the platform bucket, read exactly as before
    assert any('"POLICY_WOULD_REFUSE"' in r.getMessage() for r in caplog.records)
    assert svc.guard_db.reads == []


def test_deploy_per_workload_not_ready_stops_before_anything(tf, tmp_path, monkeypatch):
    _per_workload(monkeypatch)
    svc = _svc(tf, tmp_path, _guard(signed_record(status="BUCKET_READY")))
    res, calls, buckets, fetch = _deploy(tf, svc, tmp_path, CLEAN)
    assert (res["status"], res["error_class"], res["operator_required"]) == ("FAILED", "RUNNER_IDENTITY_NOT_READY",
                                                                             True)
    assert calls == [] and buckets == [] and not fetch.called


def test_deploy_per_workload_preinit_refusal_before_init(tf, tmp_path, monkeypatch):
    _per_workload(monkeypatch)
    svc = _svc(tf, tmp_path, _guard(signed_record()))
    res, calls, buckets, _fetch = _deploy(tf, svc, tmp_path, FORBIDDEN["main.tf"])
    assert (res["status"], res["error_class"], res["code"]) == ("FAILED", "APPLY_CONTENT_POLICY",
                                                                "POLICY.PROVIDER_ATTRIBUTE_FORBIDDEN")
    assert "init" not in calls and buckets == [CHILD_BUCKET]


DENY_PLAN = {"configuration": {"root_module": {}}, "resource_changes": [
    {"address": "google_iam_deny_policy.d", "mode": "managed", "type": "google_iam_deny_policy", "name": "d",
     "change": {"actions": ["create"], "after": {"name": "d"}, "after_unknown": {}}}]}


def test_deploy_identity_touched_refused_per_workload_logged_on_platform(tf, tmp_path, monkeypatch, caplog):
    with caplog.at_level(logging.WARNING):
        res, calls, _b, _f = _deploy(tf, _svc(tf, tmp_path / "a"), tmp_path / "a", CLEAN, plan_json=DENY_PLAN)
    assert res["status"] == "SUCCESS" and "apply" in calls
    assert any('"POLICY.PLATFORM_IDENTITY_TOUCHED"' in r.getMessage() for r in caplog.records)
    _per_workload(monkeypatch)
    res, calls, _b, _f = _deploy(tf, _svc(tf, tmp_path / "b", _guard(signed_record())), tmp_path / "b", CLEAN,
                                 plan_json=DENY_PLAN)
    assert (res["status"], res["error_class"]) == ("FAILED", "APPLY_CONTENT_POLICY")
    assert [v["code"] for v in res["content_policy_violations"]] == ["POLICY.PLATFORM_IDENTITY_TOUCHED"]
    assert "apply" not in calls


def test_deploy_per_workload_uses_the_workload_bucket(tf, tmp_path, monkeypatch):
    _per_workload(monkeypatch)
    svc = _svc(tf, tmp_path, _guard(signed_record()))
    res, calls, buckets, _fetch = _deploy(tf, svc, tmp_path, CLEAN)
    assert res["status"] == "SUCCESS", res
    assert res["state_file"] == f"gs://{CHILD_BUCKET}/workloads/{PID}/default.tfstate"
    assert buckets == [CHILD_BUCKET] and "init" in calls


def test_deploy_per_workload_preflight_lock_read_fails_closed(tf, tmp_path, monkeypatch):
    """FD-7L 2b: a Per-workload deploy reads its lock with the brokered deployer; a read that fails stops the deploy
    (typed) instead of proceeding as a Shared install does."""
    _per_workload(monkeypatch)
    svc = _svc(tf, tmp_path, _guard(signed_record()))

    def broken(self, product_id, bucket=None, client_project=None):
        assert (bucket, client_project) == (CHILD_BUCKET, PROJECT)
        raise RuntimeError("403 from the workload bucket")

    res, calls, _b, fetch = _deploy(tf, svc, tmp_path, CLEAN, lock_reader=broken)
    assert (res["status"], res["error_class"], res["operator_required"]) == ("FAILED", "STATE_LOCK_UNREADABLE", True)
    assert calls == [] and not fetch.called


def test_apply_plan_per_workload_needs_the_platform_backend(tf, tmp_path, monkeypatch):
    """Review F7: a saved plan whose workspace was prepared for another bucket (a restart, then a backfill or re-vend
    moved the bucket) is refused before anything is read or applied."""
    _per_workload(monkeypatch)
    svc = _svc(tf, tmp_path, _guard(signed_record()))
    ws = svc._workspace_dir("t1", PID)
    os.makedirs(ws)
    with open(os.path.join(ws, "tfplan"), "w") as fh:
        fh.write("x")
    with open(os.path.join(ws, "backend.tf"), "w", encoding="utf-8") as fh:
        fh.write(OLD_BACKEND)
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **kw: None)
    monkeypatch.setattr(svc, "_read_saved_plan", lambda *a, **kw: ({"configuration": {}, "resource_changes": []}, ""))
    monkeypatch.setattr(svc, "_run_subprocess", lambda *a, **kw: pytest.fail("tofu must not run"))
    res = svc.apply_plan(PID, "t1", iac_engine="OPENTOFU")
    assert (res["status"], res["reason"], res["operator_required"]) == ("REFUSED", "STATE_BACKEND_MISMATCH", True)


def test_platform_plan_paths_measure_with_the_recorded_project(tf, tmp_path):
    """Review F9: on a Shared install a plan / saved-plan apply / drift run takes the workload's recorded project for
    its POLICY_WOULD_REFUSE identity lines (a read for a log line only; any read problem -> no project)."""
    from unittest.mock import MagicMock
    svc = _svc(tf, tmp_path)
    db = MagicMock()
    db.collection.return_value.document.return_value.get.return_value = _Snap({"project_id": PROJECT})
    svc.db = db
    assert svc._runner_state_context(PID, measure=True).project_id == PROJECT
    assert svc._runner_state_context(PID).project_id is None          # no read unless a plan path measures
    db.collection.return_value.document.return_value.get.side_effect = RuntimeError("down")
    assert svc._runner_state_context(PID, measure=True).project_id is None
    assert svc._runner_state_context(PID, target_project_id=PROJECT).project_id == PROJECT


def test_identity_source_lookup_reads_the_workloads_own_hcl(tf, tmp_path):
    """Review F1: the unknown-value shapes are checked on the workload's HCL: the root and a local module, by the
    plan configuration's module sources; a resource an override file also declares is never shown as bare."""
    ws = tmp_path / "ws"
    (ws / "infra" / "modules" / "m").mkdir(parents=True)
    (ws / "main.tf").write_text('resource "google_service_account_iam_member" "r" {\n'
                                '  service_account_id = google_service_account.app.name\n}\n')
    (ws / "infra" / "modules" / "m" / "main.tf").write_text(
        'resource "google_storage_bucket_iam_member" "b" {\n  bucket = google_storage_bucket.x.id\n}\n')
    plan = {"configuration": {"root_module": {"module_calls": {"m": {"source": "./infra/modules/m", "module": {}}}}}}
    lookup = tf.TerraformService._identity_source_lookup(str(ws), plan)
    assert lookup((), "google_service_account_iam_member", "r", "service_account_id") == \
        "${google_service_account.app.name}"
    assert lookup(("m",), "google_storage_bucket_iam_member", "b", "bucket") == "${google_storage_bucket.x.id}"
    assert lookup(("nope",), "google_storage_bucket_iam_member", "b", "bucket") is None
    (ws / "main_override.tf").write_text('resource "google_service_account_iam_member" "r" {\n'
                                         '  service_account_id = "x"\n}\n')
    lookup = tf.TerraformService._identity_source_lookup(str(ws), plan)
    assert lookup((), "google_service_account_iam_member", "r", "service_account_id") is None
    assert tf.TerraformService._identity_source_lookup(None, plan) is None

