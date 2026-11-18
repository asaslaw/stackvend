"""TI-5-R3-d (owner 10-25, register FOLLOWUPS-1025): a Control Center RESUME_DEVELOPER relaunch forwards the failed
deploy's typed validation report, so the resumed developer plans exactly as on an in-run terraform remediation
(developer_agent/deploy_repair.py). No workflow YAML change (post-RC policy):

1. shared/callbacks.py (x6, byte-identical) keeps a failed stage outcome's `validation_report` on the stage record,
   paired with the error it belongs to (`validation_report_error`), in its own merge write after the status write;
2. the Control Center copies it from the source execution's FAILED terraform stage (only when the pair matches) onto
   the new execution's record (`resume_tf_validation_report`, with the source trace), never into the workflow args;
3. the gateway reads it on the resumed run's FIRST developer dispatch (no report in the request, retry counters 0) and
   matches the SAT-49 draft record on the source trace, whose release the failed deploy applied.
Every other dispatch is byte-identical to today's. Hermetic."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import copy
import importlib.util
import json
import logging
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, ".."))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

CALLBACK_REPLICAS = ("shared/callbacks.py", "apps/control-center/shared/callbacks.py",
                     "apps/orchestrator-gateway/shared/callbacks.py", "apps/project-vending/shared/callbacks.py",
                     "apps/qa-runner/shared/callbacks.py", "mcp-servers/terraform/shared/callbacks.py")
CB_URL = "http://127.0.0.1:9/callback"
REPORT = {"status": "FAIL", "source": "apply", "artifact_hash": "", "error_class": "PLATFORM_DEFECT",
          "diagnostics": [{"tool": "tofu", "code": "TF.UNSUPPORTED_ARGUMENT", "severity": "error",
                           "file": "infra/workload/main.tf", "message": "Unsupported argument", "source": "apply",
                           "error_class": "PLATFORM_DEFECT", "block_address": "module.compute"}]}


# ================================================================================================ 1. callbacks
def _load(rel):
    name = "r3d_cb_" + rel.replace("/", "_").replace("-", "_").replace(".py", "")
    spec = importlib.util.spec_from_file_location(name, os.path.join(REPO_ROOT, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(params=CALLBACK_REPLICAS)
def cb(request):
    return _load(request.param)


class _WriteDb:
    def __init__(self, fail_on=()):
        self.writes, self.fail_on = [], set(fail_on)

    def collection(self, name):
        db = self

        class _Doc:
            def __init__(self, doc_id):
                self.doc_id = doc_id

            def set(self, data, merge=False):
                n = len(db.writes)
                db.writes.append((name, self.doc_id, copy.deepcopy(data), merge))
                if n in db.fail_on:
                    raise RuntimeError("firestore write failed")

        class _Coll:
            def document(self, doc_id):
                return _Doc(doc_id)

        return _Coll()


def _scope(cb, monkeypatch, body, db=None):
    sent = []
    monkeypatch.setattr(cb.CallbackDeliveryClient, "send_callback",
                        staticmethod(lambda callback_url, payload, timeout=15, max_attempts=5: sent.append(
                            copy.deepcopy(payload)) or {}))
    monkeypatch.setattr(cb.time, "time", lambda: 1000.0)
    db = db or _WriteDb()
    with cb.guaranteed_callback_scope(CB_URL, "trace-1", "terraform", "prod-1", db) as outcome:
        body(outcome)
    return sent[0], db.writes


def _failed(report, error="Error: Unsupported argument"):
    def body(o):
        o["status"] = "FAILED"
        o["error"] = error
        if report is not _ABSENT:
            o["validation_report"] = report
    return body


_ABSENT = object()


def test_callbacks_copies_stay_byte_identical():
    texts = {rel: open(os.path.join(REPO_ROOT, rel), encoding="utf-8").read() for rel in CALLBACK_REPLICAS}
    assert len(set(texts.values())) == 1


def test_a_failed_outcome_keeps_its_report_beside_its_error_in_a_second_merge_write(cb, monkeypatch):
    payload, writes = _scope(cb, monkeypatch, _failed(REPORT))
    assert payload["validation_report"] == REPORT                          # the workflow callback, as before
    (_c1, _d1, status_doc, m1), (coll, doc_id, report_doc, m2) = writes
    assert "validation_report" not in status_doc["stages"]["terraform"]    # the status write is today's
    assert status_doc["stages"]["terraform"]["error"] == "Error: Unsupported argument"
    assert (coll, doc_id, m1, m2) == ("pipeline_executions", "trace-1", True, True)
    attempt = status_doc["stages"]["terraform"]["attempt_id"]
    assert isinstance(attempt, str) and len(attempt) == 32
    assert report_doc == {"stages": {"terraform": {"validation_report": REPORT,
                                                   "validation_report_error": "Error: Unsupported argument",
                                                   "validation_report_attempt": attempt}}}


def test_rt_f1_every_status_write_has_its_own_attempt_id_and_a_reportless_repeat_unpairs_the_old_report(
        cb, monkeypatch):
    """RT 11-07 F1: a later FAILED outcome without a report and with the SAME error text writes a new attempt id and
    no report, so the stored report (merged state) no longer pairs with the stage record."""
    _p, first = _scope(cb, monkeypatch, _failed(REPORT))
    _p, second = _scope(cb, monkeypatch, _failed(_ABSENT))
    merged = {}
    for _c, _d, doc, _m in first + second:     # Firestore merge semantics on stages.terraform
        merged.update(doc["stages"]["terraform"])
    assert len(second) == 1 and merged["error"] == merged["validation_report_error"]
    assert merged["validation_report"] == REPORT and merged["validation_report_attempt"] != merged["attempt_id"]
    assert first[0][2]["stages"]["terraform"]["attempt_id"] != second[0][2]["stages"]["terraform"]["attempt_id"]


def test_dnh_no_report_key_or_a_success_is_one_write_as_before(cb, monkeypatch):
    _p, writes = _scope(cb, monkeypatch, _failed(_ABSENT))
    assert len(writes) == 1

    def ok(o):
        o["status"] = "SUCCESS"
        o["validation_report"] = REPORT
    _p, writes = _scope(cb, monkeypatch, ok)
    assert len(writes) == 1 and "validation_report" not in writes[0][2]["stages"]["terraform"]


@pytest.mark.parametrize("value", [None, "text", ["x"], 3])
def test_a_report_that_is_not_a_dict_is_stored_as_null(cb, monkeypatch, value):
    _p, writes = _scope(cb, monkeypatch, _failed(value))
    assert writes[1][2]["stages"]["terraform"]["validation_report"] is None
    assert writes[1][2]["stages"]["terraform"]["validation_report_error"] == "Error: Unsupported argument"


def test_an_oversized_or_unserializable_report_is_not_kept(cb, monkeypatch, caplog):
    big = dict(REPORT, padding="x" * (cb.STAGE_VALIDATION_REPORT_MAX_BYTES + 1))
    with caplog.at_level(logging.WARNING):
        _p, writes = _scope(cb, monkeypatch, _failed(big))
    assert writes[1][2]["stages"]["terraform"]["validation_report"] is None
    assert "not kept on the stage record" in caplog.text
    _p, writes = _scope(cb, monkeypatch, _failed(dict(REPORT, bad={1, 2})))
    assert writes[1][2]["stages"]["terraform"]["validation_report"] is None


def test_a_failed_report_write_is_logged_and_the_status_write_stands(cb, monkeypatch, caplog):
    db = _WriteDb(fail_on={1})
    with caplog.at_level(logging.WARNING):
        _p, writes = _scope(cb, monkeypatch, _failed(REPORT), db=db)
    assert len(writes) == 2 and writes[0][2]["stages"]["terraform"]["status"] == "FAILED"
    assert "Could not persist the validation report" in caplog.text


# ================================================================================================ 2. Control Center
def _source(**tf):
    stage = {"status": "FAILED", "error": "Error: Unsupported argument", "validation_report": REPORT,
             "validation_report_error": "Error: Unsupported argument", "attempt_id": "a" * 32,
             "validation_report_attempt": "a" * 32}
    stage.update(tf)
    return {"trace_id": "trace-prev-1", "product_id": "demo", "status": "FAILED", "stages": {"terraform": stage}}


def _pick_cases():
    unpaired = _source()
    del unpaired["stages"]["terraform"]["validation_report_error"]
    return {"paired": _source(), "succeeded_later": _source(status="SUCCESS"),
            "later_failure_without_report": _source(error="Error: another failure"), "unpaired": unpaired,
            "null_report": _source(validation_report=None), "no_trace": dict(_source(), trace_id=""),
            # RT 11-07 F1: a later reportless failure with the same error text (a new attempt id)
            "same_error_later_attempt": _source(attempt_id="b" * 32),
            "no_attempt_ids": _source(attempt_id=None, validation_report_attempt=None),
            "empty": {}, "developer_failure": {"stages": {"developer": {"status": "FAILED"}}}}


def test_cc_forwards_only_the_failed_deploys_own_report(relaunch):
    picks = relaunch["picks"]
    assert picks.pop("paired") == {"validation_report": REPORT, "source_trace_id": "trace-prev-1"}
    assert picks and all(v is None for v in picks.values()), picks


# The real retrigger route in a clean subprocess on the FD-4E hermetic harness prefix (as the FH-7 resume test).
HOST, PID = "mock-stackvend-project", "demo"


def _harness():
    from test_faithful_rt_resume_handoff import FakeDB, FakePublisher, _seed
    marker = "# ================================================================ public mode"
    src_path = os.path.join(HERE, "cc_identity_harness.py")
    with open(src_path, encoding="utf-8") as f:
        src = f.read()
    assert marker in src, "FD-4E harness prefix changed"
    ns = {"__file__": src_path, "__name__": "cc_r3d_harness"}
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
        doc = db.store.get(("pipeline_executions", res["trace_id"]), {})
        return {"mode": res["execution_mode"], "trace": res["trace_id"],
                "doc": doc.get("resume_tf_validation_report", "<absent>"),
                "doc_mode": doc.get("execution_mode"), "doc_status": doc.get("status"),
                "payload_keys": sorted(pub.messages[0][1])}

    code_defect = "Error: Reference to undeclared resource"
    failed_tf = dict(_source(error=code_defect, validation_report_error=code_defect),
                     current_stage="FAILED", started_at="2026-11-01T10:00:00Z")
    out = {
        "explicit_resume": run(failed_tf, {"execution_mode": "RESUME_DEVELOPER"}),
        "auto_resume": run(failed_tf, None),
        "stale_report": run(dict(failed_tf, stages={"terraform": dict(failed_tf["stages"]["terraform"],
                                                                      validation_report_error="older")}),
                            {"execution_mode": "RESUME_DEVELOPER"}),
        "full": run(failed_tf, {"execution_mode": "FULL"}),
        "picks": {name: wl._resume_validation_report(doc) for name, doc in _pick_cases().items()},
        "network_attempts": ns["NETWORK_ATTEMPTS"],
    }
    print(json.dumps(out, default=str))


@pytest.fixture(scope="module")
def relaunch():
    env = hermetic_guard.child_env(drop=("TEST_MODE", "K_SERVICE", "SESSION_SECRET", "ADMIN_EMAIL"),
                                   extra={"PROJECT_ID": HOST, "GOOGLE_CLOUD_PROJECT": HOST,
                                          "MANAGED_WORKLOADS_FOLDER_ID": "111111111111", "GITHUB_OWNER": "example-org"})
    out = subprocess.run([sys.executable, os.path.abspath(__file__), "--harness"],
                         capture_output=True, text=True, timeout=300, env=env)
    assert out.returncode == 0, out.stderr[-4000:]
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_cc_harness_is_hermetic(relaunch):
    assert relaunch["network_attempts"] == []


@pytest.mark.parametrize("case", ["explicit_resume", "auto_resume"])
def test_cc_resume_writes_the_report_on_the_new_execution_never_into_the_workflow_args(relaunch, case):
    r = relaunch[case]
    assert r["mode"] == "RESUME_DEVELOPER" and r["doc_mode"] == "RESUME_DEVELOPER" and r["doc_status"] == "ACTIVE"
    assert r["doc"] == {"validation_report": REPORT, "source_trace_id": "trace-prev-1"}
    assert "resume_tf_validation_report" not in r["payload_keys"] and "tf_validation_report" not in r["payload_keys"]


def test_cc_never_forwards_a_stale_report_or_on_a_full_build(relaunch):
    assert relaunch["stale_report"]["mode"] == "RESUME_DEVELOPER" and relaunch["stale_report"]["doc"] == "<absent>"
    assert relaunch["full"]["mode"] == "FULL" and relaunch["full"]["doc"] == "<absent>"


# ================================================================================================ 3. gateway
from fd4f_support import FakeDB as GwDB, gw  # noqa: E402,F401  (gw: the gateway app fixture)

SHA_A = "a" * 40


def _dispatch(gw, monkeypatch, *, exec_doc, ledger=(), drafts=None, **req):
    """The generate_code_files kwargs of one developer dispatch of trace `t-resume` (product svc)."""
    db = GwDB()
    db.docs["workloads/svc/compliance_audits/t-resume"] = {
        "product_id": "svc", "trace_id": "t-resume", "allow_unauthenticated": True, "enable_direct_iap": False,
        "domain_restricted_sharing": False, "allowed_domains": []}
    if exec_doc is not None:
        db.docs["pipeline_executions/t-resume"] = exec_doc
    for trace, rec in (drafts or {}).items():
        db.docs[f"pipeline_executions/{trace}"] = {"stages": {"developer": {"committed_draft": rec}}}
    for i, e in enumerate(ledger):
        db.docs[f"vcs_ledger/l{i}"] = dict({"ledger_id": f"l{i}", "product_id": "svc", "origin": "DEVELOPER",
                                            "state": "MERGED"}, **e)
    monkeypatch.setattr(gw, "db", db)
    monkeypatch.setattr(gw.developer_agent, "fetch_github_token", lambda *a, **k: None)
    got = {}
    monkeypatch.setattr(gw.developer_agent, "generate_code_files", lambda **kw: got.update(kw) or {"a.py": "x=1\n"})
    monkeypatch.setattr(gw.developer_agent, "commit_and_open_pr", lambda **kw: {
        "status": "COMMITTED", "branch_name": kw["branch_name"], "commit_sha": "c" * 40,
        "files_committed": ["a.py"], "pull_request_url": "https://example.invalid/pr/2"})
    monkeypatch.setattr(gw, "_assert_tf_remediation_allowed", lambda *a, **k: None)
    gw._execute_developer_logic(gw.DeveloperExecuteRequest(product_id="svc", trace_id="t-resume", **req))
    return got


def _resume_doc(**rec):
    field = {"validation_report": REPORT, "source_trace_id": "t-prev"}
    field.update(rec)
    return {"trace_id": "t-resume", "product_id": "svc", "execution_mode": "RESUME_DEVELOPER",
            "resume_tf_validation_report": field}


DRAFT = {"commit_sha": SHA_A, "llm_draft_paths": ["apps/svc/main.py", "infra/workload/iac_intent.json"]}
RELEASE = [{"trace_id": "t-prev", "head_sha": SHA_A, "created_at": "2026-11-01T10:00:00+00:00"}]


def test_gw_first_dispatch_of_a_resume_plans_with_the_forwarded_report(gw, monkeypatch, caplog):
    with caplog.at_level(logging.INFO):
        got = _dispatch(gw, monkeypatch, exec_doc=_resume_doc(), tf_remediation_context="Error: x")
    assert got["tf_validation_report"] == REPORT
    assert "forwards the failed deploy's validation report of trace t-prev" in caplog.text
    # without the source trace's release record an INTENT_REPAIR regenerates (SAT-49, logged)
    assert "deploy_draft_paths" not in got


def test_gw_resume_matches_the_draft_record_on_the_source_traces_release(gw, monkeypatch):
    got = _dispatch(gw, monkeypatch, exec_doc=_resume_doc(), ledger=RELEASE, drafts={"t-prev": DRAFT})
    assert got["tf_validation_report"] == REPORT
    assert got["deploy_draft_paths"] == sorted(DRAFT["llm_draft_paths"])
    # the release of another trace never counts
    other = [dict(RELEASE[0], trace_id="t-other")]
    got = _dispatch(gw, monkeypatch, exec_doc=_resume_doc(), ledger=other, drafts={"t-other": DRAFT})
    assert "deploy_draft_paths" not in got and got["tf_validation_report"] == REPORT


@pytest.mark.parametrize("exec_doc,req,reason", [
    (None, {}, None),                                                                        # no record
    ({"trace_id": "t-resume", "product_id": "svc", "execution_mode": "RESUME_DEVELOPER"}, {}, None),   # no field
    (dict(_resume_doc(), execution_mode="FULL"), {}, "NOT_A_RESUME_EXECUTION"),
    (dict(_resume_doc(), product_id="other"), {}, "PRODUCT_MISMATCH"),
    (_resume_doc(validation_report="text"), {}, "RECORD_INVALID"),
    (dict(_resume_doc(), resume_tf_validation_report="x"), {}, "RECORD_INVALID"),
    (_resume_doc(source_trace_id=""), {}, "SOURCE_TRACE_INVALID"),
    (_resume_doc(source_trace_id="t-resume"), {}, "SOURCE_TRACE_INVALID"),
    (_resume_doc(), {"tf_retry_count": 1, "tf_remediation_context": "Error: later deploy"}, None),   # in-run retry
    (_resume_doc(), {"retry_count": 1}, None),                                                # a QA retry
])
def test_gw_dnh_every_other_dispatch_is_todays(gw, monkeypatch, caplog, exec_doc, req, reason):
    baseline = _dispatch(gw, monkeypatch, exec_doc=None, **req)
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        got = _dispatch(gw, monkeypatch, exec_doc=exec_doc, **req)
    assert json.dumps(got, sort_keys=True, default=repr) == json.dumps(baseline, sort_keys=True, default=repr)
    assert got.get("tf_validation_report") is None
    if reason:
        assert f"Resume validation report not used for 'svc' (trace t-resume): {reason}" in caplog.text


def test_gw_a_report_in_the_request_always_wins(gw, monkeypatch):
    own = dict(REPORT, error_class="CODE_DEFECT")
    got = _dispatch(gw, monkeypatch, exec_doc=_resume_doc(), tf_validation_report=own)
    assert got["tf_validation_report"] == own


def test_gw_an_unreadable_record_is_todays_path(gw, monkeypatch, caplog):
    got_ok = _dispatch(gw, monkeypatch, exec_doc=None)
    db = GwDB()
    db.fail_reads = True
    monkeypatch.setattr(gw, "db", db)
    with caplog.at_level(logging.WARNING):
        assert gw._resume_validation_report(gw.DeveloperExecuteRequest(product_id="svc", trace_id="t-resume")) is None
    assert "READ_FAILED" in caplog.text
    monkeypatch.setattr(gw, "db", None)
    assert gw._resume_validation_report(gw.DeveloperExecuteRequest(product_id="svc", trace_id="t-resume")) is None
    assert gw._resume_validation_report(gw.DeveloperExecuteRequest(product_id="svc")) is None
    assert got_ok.get("tf_validation_report") is None


def test_gw_and_cc_name_the_same_field():
    import ast
    names = {}
    for rel in ("apps/orchestrator-gateway/main.py", "apps/control-center/routes/workloads.py"):
        tree = ast.parse(open(os.path.join(REPO_ROOT, rel), encoding="utf-8").read())
        for node in tree.body:
            if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "RESUME_TF_VALIDATION_REPORT_FIELD"
                                                    for t in node.targets):
                names[rel] = ast.literal_eval(node.value)
    assert set(names.values()) == {"resume_tf_validation_report"} and len(names) == 2


def test_the_workflow_first_dispatch_counters_the_gateway_relies_on_are_zero():
    """The workflow YAML is unchanged (post-RC: no core change): a run starts with retry_count 0, tf_retry_count 0
    and no report, and only increment_qa_retry / increment_tf_retry raise the counters."""
    import yaml
    with open(os.path.join(REPO_ROOT, "workflows", "main_orchestrator.yaml"), encoding="utf-8") as fh:
        text = fh.read()
    assert "resume_tf_validation_report" not in text
    doc = yaml.safe_load(text)
    steps = doc["run_pipeline"]["steps"]
    init = next(s["init_context"] for s in steps if "init_context" in s)
    assigned = {k: v for a in init["assign"] for k, v in a.items()}
    assert (assigned["retry_count"], assigned["tf_retry_count"], assigned["tf_validation_report"]) == (0, 0, None)


if __name__ == "__main__" and "--harness" in sys.argv:
    _harness()
