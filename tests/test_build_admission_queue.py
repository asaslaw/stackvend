"""BUILD-ADMISSION-QUEUE (G4, owner 11-13): one admission function for every LLM-heavy pipeline run.

Plan: docs/planning/build-admission-queue-plan.md (dispatch sites, slot model, race/crash matrix §4). Pins:
- shared/build_admission.py: the compare-and-set slot accounting (two submits at once, threads, idempotency, FIFO,
  release of ended / lost runs, limit lowered, cancel vs promote, pump failures, gate, restart), the limit read and the
  three byte-identical copies;
- the setting (`orchestration.max_concurrent_builds`, 1..20, default 1) on the settings model (8 copies) and the page;
- the gateway intake (admission before create_execution, QUEUED answer, terminal event releases + dispatches the next
  run in process, a refused admitted event frees its slot) and the Control Center (create 202, relaunch 202 / 409,
  Fast-Path bypass, Flight Deck poll reconcile + publish, cancel of a queued run);
- Do No Harm: with max_concurrent_builds >= the submissions, every run is dispatched exactly as before.
Hermetic: in-memory Firestore fakes (compare-and-set semantics), fake publisher / Workflows client. No network.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import base64
import copy
import hashlib
import json
import logging
import os
import sys
import threading
import types
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO, "apps", "control-center")
GW_DIR = os.path.join(REPO, "apps", "orchestrator-gateway")

from fd4f_support import FakeDB as GwFakeDB, gw  # noqa: E402,F401  (gw is a fixture)

import importlib.util  # noqa: E402

_spec = importlib.util.spec_from_file_location("build_admission_under_test", os.path.join(REPO, "shared",
                                                                                             "build_admission.py"))
ba = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ba)

COPIES = ("shared/build_admission.py", "apps/control-center/shared/build_admission.py",
          "apps/orchestrator-gateway/shared/build_admission.py")


# ================================================================================================ fake Firestore
class _Snap:
    def __init__(self, path, data, version):
        self.id = path.rsplit("/", 1)[-1]
        self._data = copy.deepcopy(data)
        self.exists = data is not None
        self.update_time = version if data is not None else None

    def to_dict(self):
        return copy.deepcopy(self._data)


class _Ref:
    def __init__(self, store, path):
        self.store, self.path = store, path
        self.id = path.rsplit("/", 1)[-1]

    def get(self):
        with self.store.lock:
            if self.store.fail_reads:
                raise RuntimeError("firestore down")
            snap = _Snap(self.path, self.store.docs.get(self.path), self.store.versions.get(self.path, 0))
            snap.reference = self
        hook = self.store.on_get.pop(self.path, None)
        if hook:
            hook()
        return snap

    def _bump(self):
        self.store.versions[self.path] = self.store.versions.get(self.path, 0) + 1

    def set(self, data, merge=False):
        with self.store.lock:
            if self.store.fail_writes:
                raise RuntimeError("firestore write failed")
            base = dict(self.store.docs.get(self.path) or {}) if merge else {}
            base.update(copy.deepcopy(data))
            self.store.docs[self.path] = base
            self._bump()

    def create(self, data):
        from google.api_core import exceptions as gexc
        with self.store.lock:
            if self.path in self.store.docs:
                raise gexc.AlreadyExists(self.path)
            self.store.docs[self.path] = copy.deepcopy(data)
            self._bump()

    def update(self, data, option=None):
        from google.api_core import exceptions as gexc
        with self.store.lock:
            if self.path not in self.store.docs:
                raise gexc.NotFound(self.path)
            if option is not None and option.get("last_update_time") != self.store.versions.get(self.path, 0):
                raise gexc.FailedPrecondition(self.path)
            self.store.docs[self.path].update(copy.deepcopy(data))
            self._bump()
            if self.store.commit_then_conflict > 0:   # RT F4: the commit landed, the client's retry reports a conflict
                self.store.commit_then_conflict -= 1
                raise gexc.FailedPrecondition(self.path)

    def delete(self):
        with self.store.lock:
            self.store.docs.pop(self.path, None)
            self._bump()

    def collection(self, name):
        return _Col(self.store, f"{self.path}/{name}")


class _Col:
    def __init__(self, store, path):
        self.store, self.path = store, path

    def document(self, doc_id=None):
        if doc_id is None:
            self.store.auto += 1
            doc_id = f"auto{self.store.auto}"
        return _Ref(self.store, f"{self.path}/{doc_id}")


class Store:
    """Firestore stand-in: per-document versions as update_time; update(option) and create() enforce them."""

    def __init__(self, docs=None):
        self.docs = copy.deepcopy(docs or {})
        self.versions = {}
        self.lock = threading.RLock()
        self.on_get = {}
        self.fail_reads = False
        self.fail_writes = False
        self.auto = 0
        self.commit_then_conflict = 0

    def __bool__(self):
        return True

    def collection(self, name):
        return _Col(self, name)

    @staticmethod
    def write_option(**kw):
        return dict(kw)


STATE = "system_config/build_admission"
SETTINGS = "system_config/platform_settings"


def _store(limit=None, **docs):
    s = Store()
    if limit is not None:
        s.docs[SETTINGS] = {"orchestration": {"max_concurrent_builds": limit}}
    for path, data in docs.items():
        s.docs[path.replace("__", "/")] = data
    return s


def _admit(s, trace, product="app", **kw):
    payload = kw.pop("payload", None) or {"trace_id": trace, "product_id": product, "execution_mode": "FULL"}
    return ba.admit(s, trace, product_id=product, payload=payload, source="test", **kw)


def _state(s):
    return s.docs.get(STATE) or {"holders": {}, "queue": []}


def _queue(s):
    return [q["trace_id"] for q in _state(s).get("queue", [])]


# ================================================================================================ copies / setting
def test_copies_are_byte_identical():
    digests = {p: hashlib.sha256(open(os.path.join(REPO, p), "rb").read()).hexdigest() for p in COPIES}
    assert len(set(digests.values())) == 1, digests


def test_setting_is_on_the_model_with_its_bounds():
    sys.path.insert(0, REPO)
    try:
        from shared.settings import OrchestrationSettings, PlatformSettings
    finally:
        sys.path.remove(REPO)
    assert OrchestrationSettings().max_concurrent_builds == 1
    assert PlatformSettings(orchestration={"max_concurrent_builds": 4}).orchestration.max_concurrent_builds == 4
    for bad in (0, 21, -1):
        with pytest.raises(Exception):
            OrchestrationSettings(max_concurrent_builds=bad)


def test_setting_is_on_the_settings_page_with_its_default_and_bounds():
    page = open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8").read()
    at = page.index('x-model.number="platformSettings.orchestration.max_concurrent_builds"')
    tag = page[page.rindex("<input", 0, at): page.index("/>", at)]
    assert 'min="1"' in tag and 'max="20"' in tag
    assert "Default 1." in page[at: page.index("</p>", at)]


def test_relaunch_toasts_read_the_build_queue_answer_rt_f8():
    """RT F8: the no-publisher retrigger answer is {"status": "QUEUED"} with no build_queue; the toasts key on
    build_queue.state, so it never shows "#undefined in line"."""
    page = open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8").read()
    assert "data.status === 'QUEUED'" not in page
    assert page.count("data.build_queue?.state === 'QUEUED'") == 2


@pytest.mark.parametrize("stored, expected, warns", [
    (None, 1, False),                                       # no document: the default
    ({"finops": {}}, 1, False),                             # no orchestration section
    ({"orchestration": {}}, 1, False),                      # no value
    ({"orchestration": {"max_concurrent_builds": 3}}, 3, False),
    ({"orchestration": {"max_concurrent_builds": 20}}, 20, False),
    ({"orchestration": {"max_concurrent_builds": 0}}, 1, True),
    ({"orchestration": {"max_concurrent_builds": 21}}, 1, True),
    ({"orchestration": {"max_concurrent_builds": "4"}}, 1, True),
    ({"orchestration": {"max_concurrent_builds": True}}, 1, True),
    ({"orchestration": "x"}, 1, True),
])
def test_limit_read(stored, expected, warns, caplog):
    s = Store({SETTINGS: stored} if stored is not None else {})
    with caplog.at_level(logging.WARNING):
        assert ba.read_limit(s) == expected
    assert any("max_concurrent_builds" in r.message for r in caplog.records if r.levelno == logging.WARNING) == warns


def test_limit_unreadable_is_one_with_a_warning_never_unlimited(caplog):
    s = Store()
    s.fail_reads = True
    with caplog.at_level(logging.WARNING):
        assert ba.read_limit(s) == 1
    assert any("could not be read" in r.message for r in caplog.records)
    assert ba.read_limit(MagicMock()) == 1   # not a Firestore snapshot: the safe default


def test_requires_admission_only_bypasses_fast_path():
    assert ba.requires_admission({"execution_mode": "DEPLOY_ONLY"}) is False
    assert ba.requires_admission({"execution_mode": "deploy_only"}) is False
    for mode in (None, "", "FULL", "RESUME_DEVELOPER", "FULL_BUILD", "AUTO"):
        assert ba.requires_admission({"execution_mode": mode}) is True


# ================================================================================================ admission
def test_do_no_harm_limit_covers_every_submission():
    s = _store(limit=3)
    results = [_admit(s, f"t{i}") for i in range(3)]
    assert [r.state for r in results] == [ba.ADMITTED] * 3
    assert _queue(s) == [] and set(_state(s)["holders"]) == {"t0", "t1", "t2"}
    assert not any(p.startswith("build_queue/") or p.startswith("pipeline_executions/") for p in s.docs)


def test_over_the_limit_is_queued_in_fifo_order_with_positions():
    s = _store(limit=1)
    assert _admit(s, "a").state == ba.ADMITTED
    b, c = _admit(s, "b"), _admit(s, "c")
    assert (b.state, b.position, b.view()["ahead"]) == (ba.QUEUED, 1, 0)
    assert (c.state, c.position, c.view()["ahead"]) == (ba.QUEUED, 2, 1)
    assert _queue(s) == ["b", "c"]
    assert s.docs["build_queue/b"]["payload"]["trace_id"] == "b" and s.docs["build_queue/b"]["status"] == "QUEUED"


def test_admit_is_idempotent():
    s = _store(limit=1)
    assert _admit(s, "a").state == ba.ADMITTED
    again = _admit(s, "a")
    assert again.state == ba.ADMITTED and again.already
    _admit(s, "b")
    b2 = _admit(s, "b")
    assert b2.state == ba.QUEUED and b2.position == 1 and b2.already and _queue(s) == ["b"]


def test_two_concurrent_admits_one_slot():
    """B commits between A's read and A's write: A's compare-and-set fails, A re-reads and queues."""
    s = _store(limit=1)
    out = {}
    s.on_get[STATE] = lambda: out.setdefault("b", _admit(s, "b"))
    a = _admit(s, "a")
    assert out["b"].state == ba.ADMITTED
    assert a.state == ba.QUEUED and a.position == 1
    assert list(_state(s)["holders"]) == ["b"] and _queue(s) == ["a"]


def test_threaded_admits_never_exceed_the_limit():
    s = _store(limit=2)
    results, errors = [], []

    def run(i):
        try:
            results.append(_admit(s, f"t{i}"))
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=run, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # A burst can exhaust the compare-and-set attempts: that is a typed refusal (503), never a double grant.
    assert all(isinstance(e, ba.BuildAdmissionError) for e in errors)
    admitted = [r for r in results if r.state == ba.ADMITTED]
    queued = sorted(r.position for r in results if r.state == ba.QUEUED)
    assert len(admitted) == 2 and len(_state(s)["holders"]) == 2
    assert queued == list(range(1, len(queued) + 1)) and len(_queue(s)) == len(queued)


def test_newcomer_never_jumps_the_queue():
    s = _store(limit=2)
    _admit(s, "a")
    _admit(s, "b")
    _admit(s, "c")                                   # queued
    s.docs["pipeline_executions/a"] = {"status": "SUCCEEDED"}
    d = _admit(s, "d")                               # a slot is free, but c is waiting
    assert d.state == ba.QUEUED and d.position == 2 and d.pump_needed
    assert _queue(s) == ["c", "d"]


def test_one_per_product_refuses_a_second_queued_run():
    s = _store(limit=1)
    _admit(s, "a", product="shop")
    _admit(s, "b", product="shop")
    again = _admit(s, "c", product="shop", one_per_product=True)
    assert again.state == ba.ALREADY_QUEUED and again.queued_trace_id == "b"
    assert _queue(s) == ["b"] and "build_queue/c" not in s.docs


def test_relaunch_race_refused_after_writing_cleans_up():
    """Another run of the workload joins the queue between this relaunch's two rounds: this one is refused (409) and
    its queue entry and QUEUED record are removed, so nothing is left behind."""
    s = _store(limit=1)
    _admit(s, "x", product="other")

    def write_record_then_race():
        s.docs["pipeline_executions/b"] = {"status": "QUEUED"}
        _admit(s, "a", product="shop")

    r = _admit(s, "b", product="shop", one_per_product=True, before_queue=write_record_then_race)
    assert r.state == ba.ALREADY_QUEUED and r.queued_trace_id == "a"
    assert "build_queue/b" not in s.docs and "pipeline_executions/b" not in s.docs and _queue(s) == ["a"]


def test_admission_failing_in_round_two_leaves_no_orphans_rt_f5(monkeypatch):
    """RT F5 / probe P1: the queue write keeps conflicting after the payload and the QUEUED record were written ->
    typed 503-class error, and neither document is left behind."""
    from google.api_core import exceptions as gexc

    s = _store(limit=1)
    _admit(s, "a")
    monkeypatch.setattr(ba, "_sleep", lambda _s: None)

    def write_record():
        s.docs["pipeline_executions/b"] = {"status": "QUEUED"}
        monkeypatch.setattr(_Ref, "update", lambda self, data, option=None: (_ for _ in ()).throw(
            gexc.FailedPrecondition(self.path)))

    with pytest.raises(ba.BuildAdmissionError) as ei:
        _admit(s, "b", before_queue=write_record)
    assert ei.value.error_class == ba.BUILD_ADMISSION_UNAVAILABLE
    assert "build_queue/b" not in s.docs and "pipeline_executions/b" not in s.docs and _queue(s) == []


def test_before_queue_runs_before_the_run_joins_the_queue():
    s = _store(limit=1)
    _admit(s, "a")
    seen = {}
    _admit(s, "b", before_queue=lambda: seen.setdefault("queue", list(_queue(s))))
    assert seen["queue"] == [] and _queue(s) == ["b"]


def test_admission_store_down_is_typed():
    s = _store(limit=1)
    s.fail_reads = True
    with pytest.raises(ba.BuildAdmissionError) as ei:
        _admit(s, "a")
    assert ei.value.error_class == ba.BUILD_ADMISSION_UNAVAILABLE
    with pytest.raises(ba.BuildAdmissionError):
        ba.admit(MagicMock(), "a", product_id="p", payload={}, source="t", limit=1)


def test_state_survives_new_client():
    """A Control Center instance restart: nothing is in memory, a new client over the same store sees it all."""
    s = _store(limit=1)
    _admit(s, "a")
    _admit(s, "b")
    restarted = Store()
    restarted.docs, restarted.versions = s.docs, s.versions
    view = ba.queue_view(restarted)
    assert view["running"] == 1 and [q["trace_id"] for q in view["queue"]] == ["b"]
    assert _admit(restarted, "b").state == ba.QUEUED


# ================================================================================================ release
NOW = datetime(2026, 11, 13, 12, 0, tzinfo=timezone.utc)


def test_admit_releases_terminal_holder():
    s = _store(limit=1)
    _admit(s, "a")
    for status in ("SUCCEEDED", "FAILED", "ABORTED", "CANCELLED"):
        s.docs["pipeline_executions/a"] = {"status": status, "workflow_execution_id": "e"}
        s.docs[STATE]["holders"] = {"a": {"product_id": "app", "acquired_at": NOW.isoformat()}}
        s.docs[STATE]["queue"] = []
        r = ba.admit(s, f"n-{status}", product_id="app", payload={}, source="t", now=NOW)
        assert r.state == ba.ADMITTED and ("a", f"RUN_ENDED:{status}") in r.released
        s.docs[STATE]["holders"] = {}


@pytest.mark.parametrize("record, age_min, released", [
    (None, 21, True),                                                         # no record: lost
    (None, 5, False),                                                         # within the grace
    ({"status": "ACTIVE"}, 21, True),                                         # never bound: lost
    ({"status": "QUEUED"}, 21, True),                                         # promoted, never started
    ({"status": "ACTIVE", "workflow_execution_id": "e-1"}, 300, False),       # bound and running: kept
    ({"status": "AWAITING_PLAN_APPROVAL", "workflow_execution_id": "e"}, 1, True),  # not a holding status
])
def test_lost_dispatch_released_after_grace(record, age_min, released):
    s = _store(limit=1)
    s.docs[STATE] = {"holders": {"a": {"product_id": "app", "acquired_at": (NOW - timedelta(minutes=age_min)).isoformat()}},
                     "queue": []}
    if record is not None:
        s.docs["pipeline_executions/a"] = dict(record)
    r = ba.admit(s, "b", product_id="app", payload={}, source="t", now=NOW)
    assert (r.state == ba.ADMITTED) == released
    if released and record is not None and record["status"] in ("ACTIVE", "QUEUED") \
            and not record.get("workflow_execution_id"):
        assert s.docs["pipeline_executions/a"]["status"] == "FAILED"
        assert s.docs["pipeline_executions/a"]["error_class"] == ba.BUILD_DISPATCH_LOST


def test_release_is_only_for_holders():
    s = _store(limit=1)
    _admit(s, "a")
    assert ba.release(s, "a", reason="RUN_ENDED:SUCCEEDED") is True
    assert ba.release(s, "a", reason="again") is False
    assert _state(s)["holders"] == {}


def test_limit_lowered_while_runs_are_active():
    s = _store(limit=3)
    for t in ("a", "b", "c"):
        _admit(s, t)
    s.docs[SETTINGS]["orchestration"]["max_concurrent_builds"] = 1
    for t in ("a", "b", "c"):
        s.docs[f"pipeline_executions/{t}"] = {"status": "ACTIVE", "workflow_execution_id": "e"}
    assert _admit(s, "d").state == ba.QUEUED                     # running builds untouched, nothing new admitted
    assert set(_state(s)["holders"]) == {"a", "b", "c"}
    s.docs["pipeline_executions/a"]["status"] = "SUCCEEDED"
    assert ba.promote(s) == []                                   # 2 still running >= 1
    s.docs["pipeline_executions/b"]["status"] = "SUCCEEDED"
    s.docs["pipeline_executions/c"]["status"] = "FAILED"
    promoted = ba.promote(s)
    assert [e["trace_id"] for e in promoted] == ["d"] and list(_state(s)["holders"]) == ["d"]


# ================================================================================================ pump / cancel
def _queued_two(limit=1):
    s = _store(limit=limit, **{"workloads__app": {"status": "ACTIVE"}})
    _admit(s, "a")
    _admit(s, "b")
    _admit(s, "c")
    s.docs["pipeline_executions/a"] = {"status": "SUCCEEDED"}
    return s


def test_pump_dispatches_head_once_and_marks_it():
    s = _queued_two()
    s.docs["feature_requests/fr-b"] = {"status": "QUEUED"}
    s.docs["build_queue/b"]["request_id"] = "fr-b"
    s.docs["build_queue/b"]["request_status_on_dispatch"] = "IN_DEVELOPMENT"
    sent = []
    out = ba.pump(s, lambda e: sent.append(e["trace_id"]) or ba.DISPATCHED)
    assert sent == ["b"] and out == [{"trace_id": "b", "outcome": "DISPATCHED"}]
    assert list(_state(s)["holders"]) == ["b"] and _queue(s) == ["c"]
    assert s.docs["build_queue/b"]["status"] == "DISPATCHED"
    assert s.docs["feature_requests/fr-b"]["status"] == "IN_DEVELOPMENT"
    assert ba.pump(s, lambda e: sent.append(e["trace_id"]) or ba.DISPATCHED) == []   # nothing free: no double
    assert sent == ["b"]


def test_pump_dispatch_failure_fails_loudly_and_moves_on():
    s = _queued_two()
    s.docs["pipeline_executions/b"] = {"status": "QUEUED", "trace_id": "b"}
    calls = []

    def dispatch(entry):
        calls.append(entry["trace_id"])
        if entry["trace_id"] == "b":
            raise RuntimeError("pubsub down")
        return ba.DISPATCHED

    out = ba.pump(s, dispatch)
    assert calls == ["b", "c"]
    assert out[0] == {"trace_id": "b", "outcome": "FAILED", "error_class": ba.BUILD_DISPATCH_FAILED}
    assert s.docs["pipeline_executions/b"]["status"] == "FAILED"
    assert s.docs["pipeline_executions/b"]["error_class"] == ba.BUILD_DISPATCH_FAILED
    assert "pubsub down" in s.docs["pipeline_executions/b"]["error"]
    assert s.docs["build_queue/b"]["status"] == "FAILED"
    assert list(_state(s)["holders"]) == ["c"]


def test_transient_start_failure_requeues_at_the_head_then_succeeds_rt_f1():
    s = _queued_two()
    answers = [ba.BuildDispatchRetryable("HTTP 503: workflows quota"), ba.DISPATCHED]
    calls = []

    def dispatch(entry):
        calls.append(entry["trace_id"])
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a

    out = ba.pump(s, dispatch)
    assert out == [{"trace_id": "b", "outcome": "QUEUED", "error": "HTTP 503: workflows quota"}]
    assert _queue(s) == ["b", "c"] and _state(s)["holders"] == {}            # back at the head, slot free
    assert s.docs["build_queue/b"]["dispatch_attempts"] == 1
    assert ba.pump(s, dispatch) == [{"trace_id": "b", "outcome": "DISPATCHED"}]   # the next trigger starts it once
    assert calls == ["b", "b"] and list(_state(s)["holders"]) == ["b"] and _queue(s) == ["c"]


def test_third_transient_start_failure_fails_the_run_typed_rt_f1():
    s = _queued_two()
    s.docs["pipeline_executions/b"] = {"status": "QUEUED"}

    def dispatch(entry):
        raise ba.BuildDispatchRetryable("HTTP 503: no url")

    assert ba.pump(s, dispatch)[0]["outcome"] == "QUEUED"
    assert ba.pump(s, dispatch)[0]["outcome"] == "QUEUED"
    third = ba.pump(s, dispatch)
    assert third[0] == {"trace_id": "b", "outcome": "FAILED", "error_class": ba.BUILD_DISPATCH_FAILED}
    run = s.docs["pipeline_executions/b"]
    assert run["status"] == "FAILED" and run["error_class"] == ba.BUILD_DISPATCH_FAILED
    assert "HTTP 503: no url" in run["error"] and "attempt 3 of 3" in run["error"]
    assert _queue(s) == [] or _queue(s) == ["c"]       # c is dispatched in the same pump once b's slot is free
    assert "b" not in _state(s)["holders"]


def test_untried_runs_keep_their_order_after_a_transient_failure_rt_f1():
    s = _queued_two(limit=2)                       # a, b running; c queued
    _admit(s, "d")
    s.docs["pipeline_executions/a"] = {"status": "SUCCEEDED"}
    s.docs["pipeline_executions/b"] = {"status": "SUCCEEDED"}
    tried = []

    def dispatch(entry):
        tried.append(entry["trace_id"])
        raise ba.BuildDispatchRetryable("HTTP 503")

    ba.pump(s, dispatch)                             # c and d promoted; c fails; d is put back untried behind c
    assert tried == ["c"] and _queue(s) == ["c", "d"] and _state(s)["holders"] == {}
    assert "dispatch_attempts" not in s.docs["build_queue/d"]


def test_pump_refusal_keeps_its_class():
    s = _queued_two()

    def dispatch(entry):
        raise ba.BuildDispatchRefused(ba.BUILD_DISPATCH_REFUSED, "intake answered SUPPRESSED:X")

    out = ba.pump(s, dispatch)
    assert out[0]["error_class"] == ba.BUILD_DISPATCH_REFUSED


def test_pump_outcome_unknown_keeps_the_slot():
    s = _queued_two()
    ba.pump(s, lambda e: ba.OUTCOME_UNKNOWN)
    assert list(_state(s)["holders"]) == ["b"] and s.docs["build_queue/b"]["status"] == "DISPATCH_OUTCOME_UNKNOWN"


def test_pump_skipped_when_gate_says_no():
    s = _queued_two()
    sent = []
    assert ba.pump(s, lambda e: sent.append(1) or ba.DISPATCHED, gate=lambda: "platform emergency stop") == []
    assert sent == [] and _queue(s) == ["b", "c"]


def test_pump_refuses_a_workload_that_is_gone():
    s = _queued_two()
    s.docs["workloads/app"]["status"] = "DECOMMISSIONED"
    s.docs["pipeline_executions/b"] = {"status": "QUEUED"}
    sent = []
    out = ba.pump(s, lambda e: sent.append(1) or ba.DISPATCHED)
    assert sent == [] and out[0]["error_class"] == ba.BUILD_QUEUE_WORKLOAD_GONE
    assert s.docs["pipeline_executions/b"]["error_class"] == ba.BUILD_QUEUE_WORKLOAD_GONE


def test_cancel_vs_promote():
    s = _queued_two()
    s.docs["pipeline_executions/b"] = {"status": "QUEUED"}
    ba.promote(s)                                                   # b promoted first
    with pytest.raises(ba.BuildAdmissionError) as ei:
        ba.cancel(s, "b", by="ops@example.com")
    assert ei.value.error_class == ba.BUILD_QUEUE_ALREADY_DISPATCHING
    s.docs["pipeline_executions/c"] = {"status": "QUEUED", "request_id": "fr-c"}
    s.docs["feature_requests/fr-c"] = {"status": "QUEUED"}
    assert ba.cancel(s, "c", by="ops@example.com")["state"] == "CANCELLED"    # cancel first: never dispatched
    assert _queue(s) == [] and s.docs["pipeline_executions/c"]["status"] == "ABORTED"
    assert s.docs["pipeline_executions/c"]["error_class"] == ba.BUILD_QUEUE_CANCELLED
    assert s.docs["feature_requests/fr-c"]["status"] == "CANCELLED"
    with pytest.raises(ba.BuildAdmissionError) as ei:
        ba.cancel(s, "zz", by="ops")
    assert ei.value.error_class == ba.BUILD_QUEUE_NOT_QUEUED


def test_cancel_product_removes_only_that_workload():
    s = _store(limit=1)
    _admit(s, "a", product="x")
    _admit(s, "b", product="shop")
    _admit(s, "c", product="other")
    _admit(s, "d", product="shop")
    assert ba.cancel_product(s, "shop", by="decommission") == ["b", "d"]
    assert _queue(s) == ["c"]


def test_own_write_reported_as_conflict_is_recognised_rt_f4():
    """RT F4 / probe P2: a promote whose write commits but is reported as a conflict still dispatches the run, and a
    cancel in the same situation still answers CANCELLED."""
    s = _queued_two()
    s.commit_then_conflict = 1
    promoted = ba.promote(s)
    assert [e["trace_id"] for e in promoted] == ["b"] and list(_state(s)["holders"]) == ["b"]
    s.commit_then_conflict = 1
    assert ba.cancel(s, "c", by="ops")["state"] == "CANCELLED" and _queue(s) == []
    s.commit_then_conflict = 1
    assert _admit(s, "d").state == ba.QUEUED and _queue(s) == ["d"]


def test_cas_backs_off_with_jitter_between_conflicts_rt_f6(monkeypatch):
    """RT F6: every conflicting attempt waits a jittered, growing, capped delay; all attempts lost -> typed error."""
    from google.api_core import exceptions as gexc

    s = _store(limit=1)
    _admit(s, "a")
    waits = []
    monkeypatch.setattr(ba, "_sleep", waits.append)
    monkeypatch.setattr(_Ref, "update", lambda self, data, option=None: (_ for _ in ()).throw(
        gexc.FailedPrecondition(self.path)))
    with pytest.raises(ba.BuildAdmissionError) as ei:
        ba.release(s, "a", reason="x")
    assert ei.value.error_class == ba.BUILD_ADMISSION_UNAVAILABLE
    assert len(waits) == ba.CAS_ATTEMPTS
    for attempt, wait in enumerate(waits):
        assert 0 <= wait <= min(ba.CAS_BACKOFF_CAP_SECONDS, ba.CAS_BACKOFF_BASE_SECONDS * 2 ** attempt)


def test_fail_dispatch_is_a_noop_for_an_unknown_run():
    s = _store(limit=1)
    assert ba.fail_dispatch(s, "nobody", ba.BUILD_DISPATCH_REFUSED, "x") is False
    assert STATE not in s.docs


# ================================================================================================ F2 option A (owner 11-14)
CB = "https://workflowexecutions.googleapis.com/v1/projects/p/locations/r/workflows/w/executions/e/callbacks/c1"


def _resume(s, trace, stage="AWAITING_PLAN_APPROVAL", decision="APPROVED", **kw):
    return ba.resume(s, trace, stage=stage, callback_url=CB, callback_payload={"decision": decision},
                     approval_id=f"appr-{trace}", decision=decision, **kw)


def _running(s, *traces):
    for t in traces:
        s.docs[f"pipeline_executions/{t}"] = {"status": "ACTIVE", "workflow_execution_id": f"e-{t}"}


def test_a_run_waiting_for_a_person_gives_its_slot_to_the_next_build():
    s = _store(limit=1, **{"workloads__app": {"status": "ACTIVE"}})
    _admit(s, "a")
    _admit(s, "b")
    _running(s, "a")
    assert ba.park(s, "a", stage="AWAITING_PLAN_APPROVAL") == ba.PARKED
    assert ba.park(s, "a", stage="AWAITING_PLAN_APPROVAL") == "ALREADY"            # heartbeats are idempotent
    assert _state(s)["holders"] == {} and list(_state(s)["waiting"]) == ["a"]
    sent = []
    ba.pump(s, lambda e: sent.append(e["trace_id"]) or ba.DISPATCHED)
    assert sent == ["b"] and list(_state(s)["holders"]) == ["b"]
    assert ba.park(s, "zz", stage="QUOTA_PAUSED") == "NOT_HELD"
    assert ba.park(s, "b", stage="SOMETHING_ELSE") == ba.RESUME_NOT_HELD and "b" in _state(s)["holders"]


def test_approval_with_a_free_slot_resumes_now():
    s = _store(limit=1)
    _admit(s, "a")
    _running(s, "a")
    ba.park(s, "a", stage="AWAITING_PR_APPROVAL")
    r = _resume(s, "a", stage="AWAITING_PR_APPROVAL")
    assert r.state == ba.RESUME_NOW and list(_state(s)["holders"]) == ["a"] and _state(s)["waiting"] == {}


def test_approval_granted_while_the_queue_is_full_waits_at_the_head_and_never_exceeds_the_limit():
    s = _store(limit=1, **{"workloads__app": {"status": "ACTIVE"}})
    _admit(s, "a")
    _running(s, "a")
    ba.park(s, "a", stage="AWAITING_PLAN_APPROVAL")
    _admit(s, "b")                                  # takes the free slot
    _admit(s, "c")                                  # a new submission waits
    _running(s, "b")
    r = _resume(s, "a")
    assert r.state == ba.QUEUED and r.position == 1 and _queue(s) == ["a", "c"]     # ahead of the new submission
    assert len(_state(s)["holders"]) == 1
    assert s.docs["build_queue/a"]["kind"] == "resume" and s.docs["build_queue/a"]["callback_url"] == CB
    resumed, started = [], []
    pump = lambda: ba.pump(s, lambda e: started.append(e["trace_id"]) or ba.DISPATCHED,  # noqa: E731
                           resume_dispatch=lambda e: resumed.append(e["trace_id"]) or ba.DISPATCHED)
    pump()
    assert resumed == [] and started == []          # b still runs: nothing exceeds the limit
    s.docs["pipeline_executions/b"]["status"] = "SUCCEEDED"
    pump()
    assert resumed == ["a"] and started == [] and list(_state(s)["holders"]) == ["a"] and _queue(s) == ["c"]


def test_approval_granted_twice_takes_one_place():
    s = _store(limit=1)
    _admit(s, "a")
    _running(s, "a")
    ba.park(s, "a", stage="AWAITING_PLAN_APPROVAL")
    _admit(s, "b")
    _running(s, "b")
    first, second = _resume(s, "a"), _resume(s, "a")
    assert first.state == second.state == ba.QUEUED and second.already and _queue(s) == ["a"]
    s2 = _store(limit=1)
    _admit(s2, "x")
    _running(s2, "x")
    ba.park(s2, "x", stage="AWAITING_PLAN_APPROVAL")
    assert _resume(s2, "x").state == ba.RESUME_NOW
    again = _resume(s2, "x")
    assert again.state == ba.RESUME_NOW and again.already and list(_state(s2)["holders"]) == ["x"]


def test_a_late_wait_notice_after_the_approval_keeps_the_slot():
    """The operator approved before the workflow's wait notice arrived: the run kept its slot; the late notice must
    not give it up (the run is already going on), but the next wait does."""
    s = _store(limit=1)
    _admit(s, "a")
    _running(s, "a")
    assert _resume(s, "a").state == ba.RESUME_NOW
    assert ba.park(s, "a", stage="AWAITING_PLAN_APPROVAL") == "KEPT" and "a" in _state(s)["holders"]
    assert ba.park(s, "a", stage="AWAITING_PR_APPROVAL") == ba.PARKED


def test_run_cancelled_while_waiting_never_takes_a_slot_again():
    s = _store(limit=1, **{"workloads__app": {"status": "ACTIVE"}})
    _admit(s, "a")
    _running(s, "a")
    ba.park(s, "a", stage="AWAITING_PLAN_APPROVAL")
    s.docs["pipeline_executions/a"]["status"] = "ABORTED"          # aborted (or rejected / timed out) while waiting
    assert ba.release(s, "a", reason="ABORTED") is False and _state(s)["waiting"] == {}
    assert _resume(s, "a").state == ba.RESUME_NOT_HELD and _state(s)["holders"] == {}
    # cancelled after it was approved and queued: the pump frees the slot and sends nothing
    _admit(s, "b")
    _running(s, "b")
    ba.park(s, "b", stage="AWAITING_PLAN_APPROVAL")
    _admit(s, "c")
    _running(s, "c")
    assert _resume(s, "b").state == ba.QUEUED
    s.docs["pipeline_executions/b"]["status"] = "ABORTED"
    s.docs["pipeline_executions/c"]["status"] = "SUCCEEDED"
    resumed = []
    ba.pump(s, lambda e: ba.DISPATCHED, resume_dispatch=lambda e: resumed.append(1) or ba.DISPATCHED)
    assert resumed == [] and _queue(s) == [] and _state(s)["holders"] == {}


def test_waiting_run_that_ends_leaves_the_waiting_list_on_any_admission():
    s = _store(limit=1)
    _admit(s, "a")
    _running(s, "a")
    ba.park(s, "a", stage="QUOTA_PAUSED")
    s.docs["pipeline_executions/a"]["status"] = "FAILED"            # rejected, or its 24 h wait expired
    assert _admit(s, "b").state == ba.ADMITTED and _state(s)["waiting"] == {}


def test_limit_lowered_during_a_wait_resumes_at_the_head_without_exceeding_it():
    s = _store(limit=2)
    _admit(s, "a")
    _admit(s, "b")
    _running(s, "a", "b")
    ba.park(s, "a", stage="AWAITING_PLAN_APPROVAL")
    s.docs[SETTINGS]["orchestration"]["max_concurrent_builds"] = 1
    r = _resume(s, "a")
    assert r.state == ba.QUEUED and r.position == 1 and list(_state(s)["holders"]) == ["b"]


def test_resume_callback_that_cannot_be_delivered_goes_back_to_the_operator():
    s = _store(limit=1, **{"workloads__app": {"status": "ACTIVE"}})
    s.docs["approval_requests/appr-a"] = {"status": "APPROVED"}
    _admit(s, "a")
    _running(s, "a")
    ba.park(s, "a", stage="AWAITING_PLAN_APPROVAL")
    _admit(s, "b")
    _running(s, "b")
    _resume(s, "a")
    s.docs["pipeline_executions/b"]["status"] = "SUCCEEDED"

    def fails(entry):
        raise ba.BuildDispatchRetryable("callback delivery failed (503)")

    for _ in range(ba.MAX_DISPATCH_ATTEMPTS):
        ba.pump(s, lambda e: ba.DISPATCHED, resume_dispatch=fails)
    assert _state(s)["holders"] == {} and list(_state(s)["waiting"]) == ["a"] and _queue(s) == []
    appr = s.docs["approval_requests/appr-a"]
    assert appr["status"] == "CALLBACK_FAILED" and appr["pending_decision"] == "APPROVED"
    assert ba.BUILD_DISPATCH_FAILED in appr["failure_reason"]
    assert _resume(s, "a").state == ba.RESUME_NOW                   # the operator re-decides: it resumes


def test_slot_view_for_the_flight_deck():
    s = _store(limit=1)
    _admit(s, "a")
    _running(s, "a")
    ba.park(s, "a", stage="AWAITING_PLAN_APPROVAL")
    st = ba.read_state(s)
    assert ba.slot_view(st, "a", 1)["state"] == "WAITING_FOR_APPROVAL"
    _admit(s, "b")
    _running(s, "b")
    _resume(s, "a")
    v = ba.slot_view(ba.read_state(s), "a", 1)
    assert (v["state"], v["kind"], v["position"]) == ("QUEUED", "resume", 1)
    assert ba.slot_view(ba.read_state(s), "b", 1) is None
    page = open(os.path.join(CC_DIR, "templates", "dashboard.html"), encoding="utf-8").read()
    assert "waiting for approval — not holding a build slot" in page
    assert "approved — waiting for a build slot" in page


# ================================================================================================ gateway
TRACE = "intake-shop-abc123"


def _gw_env(gw, monkeypatch, db):
    import google.cloud.firestore as fs_mod

    monkeypatch.setattr(fs_mod, "Client", lambda *a, **k: db)
    monkeypatch.setenv("REGION", "us-central1")
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project")
    created = []

    class _Exec:
        def __init__(self, argument=None):
            self.argument = argument

    class _Client:
        def workflow_path(self, *a):
            return "projects/p/locations/r/workflows/w"

        def create_execution(self, parent=None, execution=None):
            created.append(json.loads(execution.argument))
            return types.SimpleNamespace(name=parent + f"/executions/e-{len(created)}")

    fake_exec_mod = types.SimpleNamespace(ExecutionsClient=_Client, Execution=_Exec)
    monkeypatch.setitem(sys.modules, "google.cloud.workflows", types.SimpleNamespace(executions_v1=fake_exec_mod))
    monkeypatch.setitem(sys.modules, "google.cloud.workflows.executions_v1", fake_exec_mod)
    monkeypatch.setitem(sys.modules, "google.cloud.workflows_v1", types.SimpleNamespace())
    monkeypatch.setattr(gw, "resolve_service_url", lambda name, *a, **k: f"https://{name}.example.run.app")
    monkeypatch.setattr(gw, "_maintenance_refusal", lambda action: None)
    monkeypatch.setattr(gw._wfx, "session_provider", lambda: MagicMock())   # never ADC; reads are patched per test
    monkeypatch.setattr(gw._wfx, "get_execution_state", MagicMock(return_value="ACTIVE"))
    return created


def _post(gw, payload):
    env = {"message": {"data": base64.b64encode(json.dumps(payload).encode()).decode(), "messageId": "m1"}}
    return TestClient(gw.app).post("/events/pubsub-intake", json=env)


def _event(trace, pid="shop", **kw):
    return {"product_id": pid, "trace_id": trace, "source_channel": "google_docs", "title": f"Build {pid}", **kw}


def _gw_db(limit):
    db = GwFakeDB()
    db.docs[SETTINGS] = {"orchestration": {"max_concurrent_builds": limit}}
    for pid in ("shop", "blog", "news"):
        db.docs[f"workloads/{pid}"] = {"status": "ACTIVE", "default_branch": "main"}
    return db


def test_gateway_do_no_harm_dispatches_every_run_when_slots_suffice(gw, monkeypatch):
    db = _gw_db(3)
    created = _gw_env(gw, monkeypatch, db)
    answers = [_post(gw, _event(f"t-{p}", p)).json()["status"] for p in ("shop", "blog", "news")]
    assert answers == ["DISPATCHED"] * 3 and len(created) == 3
    assert not any(p.startswith("build_queue/") for p in db.docs)
    for p in ("shop", "blog", "news"):
        assert db.docs[f"pipeline_executions/t-{p}"]["status"] == "ACTIVE"


def test_gateway_over_the_limit_queues_and_terminal_event_dispatches_the_next(gw, monkeypatch):
    db = _gw_db(1)
    created = _gw_env(gw, monkeypatch, db)
    assert _post(gw, _event("t-shop", "shop")).json()["status"] == "DISPATCHED"
    r = _post(gw, _event("t-blog", "blog"))
    assert r.status_code == 200 and r.json()["status"] == "QUEUED"
    assert r.json()["build_queue"]["position"] == 1 and len(created) == 1
    queued = db.docs["pipeline_executions/t-blog"]
    assert queued["status"] == "QUEUED" and "workflow_execution_id" not in queued
    # The first run ends: its slot is released and the queued run is dispatched in process, once.
    r = TestClient(gw.app).post("/events/workflow-status", json={"trace_id": "t-shop", "product_id": "shop",
                                                                  "status": "SUCCEEDED"})
    assert r.json()["status"] == "UPDATED"
    assert [c["trace_id"] for c in created] == ["t-shop", "t-blog"]
    started = db.docs["pipeline_executions/t-blog"]
    assert started["status"] == "ACTIVE" and started["workflow_execution_id"] == "e-2"
    assert started["queued_at"] == queued["queued_at"] and started["stages"]
    assert list(db.docs[STATE]["holders"]) == ["t-blog"] and db.docs[STATE]["queue"] == []
    assert db.docs["build_queue/t-blog"]["status"] == "DISPATCHED"
    # a redelivery of the dispatched event is still deduplicated
    assert _post(gw, _event("t-blog", "blog")).json()["status"] == "DUPLICATE" and len(created) == 2


def test_gateway_next_run_starts_after_the_ending_runs_records_are_final_rt_f7(gw, monkeypatch):
    db = _gw_db(1)
    _gw_env(gw, monkeypatch, db)
    _post(gw, _event("t-shop", "shop"))
    _post(gw, _event("t-blog", "blog"))
    db.docs["pipeline_executions/t-shop"]["request_id"] = "fr-shop"
    db.docs["feature_requests/fr-shop"] = {"product_id": "shop", "status": "IN_DEVELOPMENT"}
    seen = {}
    real = gw._dispatch_queued_build

    def spy(entry):
        seen["fr_status_at_next_dispatch"] = db.docs["feature_requests/fr-shop"]["status"]
        return real(entry)

    monkeypatch.setattr(gw, "_dispatch_queued_build", spy)
    TestClient(gw.app).post("/events/workflow-status", json={"trace_id": "t-shop", "product_id": "shop",
                                                              "status": "SUCCEEDED"})
    assert seen == {"fr_status_at_next_dispatch": "COMPLETED"}


@pytest.mark.parametrize("wf_answer, run_status, error_class, admitted", [
    ("FAILED", "FAILED", "WORKFLOW_EXECUTION_FAILED", True),
    ("CANCELLED", "ABORTED", "WORKFLOW_EXECUTION_CANCELLED", True),
    ("SUCCEEDED", "SUCCEEDED", None, True),
    ("ACTIVE", "ACTIVE", None, False),
    (404, "FAILED", "WORKFLOW_EXECUTION_NOT_FOUND", True),
    (503, "ACTIVE", None, False),                       # a read error never ends the run
])
def test_gateway_admission_frees_the_slot_of_a_dead_holder_rt_f3a(gw, monkeypatch, wf_answer, run_status,
                                                                  error_class, admitted):
    """RT F3a: the holder's terminal notify was lost and no Control Center is open: the next intake reads the holder's
    workflow state and, when it has ended, closes the run and takes the slot."""
    db = _gw_db(1)
    created = _gw_env(gw, monkeypatch, db)
    _post(gw, _event("t-shop", "shop"))
    if isinstance(wf_answer, int):
        monkeypatch.setattr(gw._wfx, "get_execution_state", MagicMock(side_effect=gw._wfx.WorkflowExecutionsError(
            gw._wfx.STATE_READ_FAILED, "get", http_status=wf_answer)))
    else:
        monkeypatch.setattr(gw._wfx, "get_execution_state", MagicMock(return_value=wf_answer))
    r = _post(gw, _event("t-blog", "blog"))
    shop = db.docs["pipeline_executions/t-shop"]
    assert shop["status"] == run_status and shop.get("error_class") == error_class
    assert (r.json()["status"] == "DISPATCHED") == admitted and (len(created) == 2) == admitted
    assert list(db.docs[STATE]["holders"]) == (["t-blog"] if admitted else ["t-shop"])


def test_gateway_wait_notice_gives_the_slot_to_the_next_build_f2(gw, monkeypatch):
    db = _gw_db(1)
    created = _gw_env(gw, monkeypatch, db)
    _post(gw, _event("t-shop", "shop"))
    _post(gw, _event("t-blog", "blog"))
    r = TestClient(gw.app).post("/events/workflow-status", json={
        "trace_id": "t-shop", "product_id": "shop", "current_stage": "AWAITING_PLAN_APPROVAL",
        "stage_name": "plan_approval", "stage_status": "PAUSED_FOR_APPROVAL"})
    assert r.json()["status"] == "UPDATED"
    assert [c["trace_id"] for c in created] == ["t-shop", "t-blog"]
    assert list(db.docs[STATE]["holders"]) == ["t-blog"] and list(db.docs[STATE]["waiting"]) == ["t-shop"]


def test_gateway_fast_path_never_waits(gw, monkeypatch):
    db = _gw_db(1)
    created = _gw_env(gw, monkeypatch, db)
    _post(gw, _event("t-shop", "shop"))
    r = _post(gw, _event("fastpath-blog-1", "blog", execution_mode="DEPLOY_ONLY",
                         source_channel="control_center_deploy_infra"))
    assert r.json()["status"] == "DISPATCHED" and len(created) == 2
    assert "fastpath-blog-1" not in db.docs[STATE]["holders"]


def test_gateway_admission_store_down_is_503_and_nothing_starts(gw, monkeypatch):
    db = _gw_db(1)
    created = _gw_env(gw, monkeypatch, db)
    db.docs[STATE] = {"holders": "garbage", "queue": []}
    r = _post(gw, _event("t-shop", "shop"))
    assert r.status_code == 503 and r.json()["detail"]["code"] == ba.BUILD_ADMISSION_UNAVAILABLE
    assert created == []


def test_gateway_refusal_of_an_admitted_run_frees_its_slot(gw, monkeypatch):
    """The CC admitted the run (holder), then the gateway refused the event for good (emergency stop)."""
    db = _gw_db(1)
    created = _gw_env(gw, monkeypatch, db)
    db.docs[STATE] = {"holders": {"t-shop": {"product_id": "shop", "acquired_at": NOW.isoformat()}}, "queue": []}
    db.docs["governance/platform_kill_switch"] = {"emergency_stop_active": True}
    r = _post(gw, _event("t-shop", "shop"))
    assert r.json()["status"] == "SUPPRESSED_BY_EMERGENCY_STOP" and created == []
    assert db.docs[STATE]["holders"] == {}


def test_gateway_pump_waits_while_the_emergency_stop_is_on(gw, monkeypatch):
    db = _gw_db(1)
    created = _gw_env(gw, monkeypatch, db)
    _post(gw, _event("t-shop", "shop"))
    _post(gw, _event("t-blog", "blog"))
    db.docs["governance/platform_kill_switch"] = {"emergency_stop_active": True}
    TestClient(gw.app).post("/events/workflow-status", json={"trace_id": "t-shop", "status": "FAILED"})
    assert len(created) == 1 and [q["trace_id"] for q in db.docs[STATE]["queue"]] == ["t-blog"]


def test_gateway_pump_refusal_fails_the_queued_run_loudly(gw, monkeypatch):
    db = _gw_db(1)
    created = _gw_env(gw, monkeypatch, db)
    _post(gw, _event("t-shop", "shop"))
    _post(gw, _event("t-blog", "blog"))
    monkeypatch.setattr(gw, "resolve_service_url", MagicMock(side_effect=gw.ServiceUrlUnavailable("no url")))
    # RT F1: a 5xx while starting the queued run requeues it at the head (as Pub/Sub retries an admitted run) ...
    TestClient(gw.app).post("/events/workflow-status", json={"trace_id": "t-shop", "status": "SUCCEEDED"})
    assert [q["trace_id"] for q in db.docs[STATE]["queue"]] == ["t-blog"] and db.docs[STATE]["holders"] == {}
    assert db.docs["pipeline_executions/t-blog"]["status"] == "QUEUED"
    TestClient(gw.app).post("/events/workflow-status", json={"trace_id": "t-shop", "status": "SUCCEEDED"})
    assert db.docs["build_queue/t-blog"]["dispatch_attempts"] == 2
    # ... and the 3rd failure fails it, typed, with the error
    TestClient(gw.app).post("/events/workflow-status", json={"trace_id": "t-shop", "status": "SUCCEEDED"})
    run = db.docs["pipeline_executions/t-blog"]
    assert run["status"] == "FAILED" and run["error_class"] == ba.BUILD_DISPATCH_FAILED and "503" in run["error"]
    assert db.docs[STATE]["holders"] == {} and db.docs[STATE]["queue"] == [] and len(created) == 1


def test_gateway_queued_run_survives_one_transient_5xx(gw, monkeypatch):
    db = _gw_db(1)
    created = _gw_env(gw, monkeypatch, db)
    _post(gw, _event("t-shop", "shop"))
    _post(gw, _event("t-blog", "blog"))
    good = gw.resolve_service_url
    monkeypatch.setattr(gw, "resolve_service_url", MagicMock(side_effect=gw.ServiceUrlUnavailable("no url")))
    TestClient(gw.app).post("/events/workflow-status", json={"trace_id": "t-shop", "status": "SUCCEEDED"})
    monkeypatch.setattr(gw, "resolve_service_url", good)
    TestClient(gw.app).post("/events/workflow-status", json={"trace_id": "t-shop", "status": "SUCCEEDED"})
    assert [c["trace_id"] for c in created] == ["t-shop", "t-blog"]
    assert db.docs["pipeline_executions/t-blog"]["status"] == "ACTIVE"
    assert list(db.docs[STATE]["holders"]) == ["t-blog"]


# ================================================================================================ Control Center
@pytest.fixture
def cc(monkeypatch):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from routes import telemetry as tel
    from routes import workloads as wl_routes

    monkeypatch.setattr(cc_db, "_db_client", False)
    monkeypatch.setattr(wl_routes, "project_id", "mock-stackvend-project", raising=False)
    return wl_routes, tel


def _wfx():
    from routes import telemetry
    return telemetry.wfx


def _cc_create(wl, monkeypatch, store, pid="shop-app"):
    from test_l19_11_access_intake import ADMIN_H, _client

    client = _client(wl, monkeypatch, store)
    publisher = MagicMock()
    publisher.publish.return_value.result.return_value = "msg-1"
    with patch.dict(os.environ, {"GITHUB_OWNER": "example-org", "MANAGED_WORKLOADS_FOLDER_ID": "111111111111"}), \
            patch.object(wl, "get_pubsub_publisher", return_value=publisher), \
            patch.object(wl, "get_platform_settings",
                         return_value=__import__("routes.settings", fromlist=["x"]).PlatformSettings()):
        r = client.post("/api/workloads", json={"product_id": pid, "spec_content": "a shop",
                                                "access": {"mode": "PRIVATE_IAP",
                                                           "invoker_principals": ["user:ana@example.com"]}},
                        headers=ADMIN_H)
    return r, publisher


def test_cc_create_do_no_harm_publishes_as_before(cc, monkeypatch):
    wl, _ = cc
    store = _store(limit=2)
    r, publisher = _cc_create(wl, monkeypatch, store)
    assert r.status_code == 200, r.text
    assert r.json()["build_queue"] is None and publisher.publish.call_count == 1
    payload = json.loads(publisher.publish.call_args[0][1])
    assert payload["source_channel"] == "control_center_form"
    assert list(store.docs[STATE]["holders"]) == [payload["trace_id"]]
    assert not any(p.startswith("pipeline_executions/") or p.startswith("build_queue/") for p in store.docs)


def test_cc_create_over_the_limit_is_202_queued_and_not_published(cc, monkeypatch):
    wl, _ = cc
    store = _store(limit=1)
    store.docs[STATE] = {"holders": {"other": {"product_id": "x", "acquired_at": datetime.now(timezone.utc).isoformat()}},
                         "queue": []}
    store.docs["pipeline_executions/other"] = {"status": "ACTIVE", "workflow_execution_id": "e-9",
                                               "workflow_execution_name": "projects/p/locations/r/workflows/w/executions/e-9"}
    with patch.object(_wfx(), "get_execution_state", return_value="ACTIVE"), \
            patch.object(_wfx(), "_session", return_value=MagicMock()):
        r, publisher = _cc_create(wl, monkeypatch, store)
    assert r.status_code == 202, r.text
    bq = r.json()["build_queue"]
    assert bq["state"] == "QUEUED" and bq["position"] == 1 and bq["ahead"] == 0
    assert publisher.publish.call_count == 0
    trace = bq["trace_id"]
    assert store.docs[f"pipeline_executions/{trace}"]["status"] == "QUEUED"
    assert store.docs[f"build_queue/{trace}"]["payload"]["source_channel"] == "control_center_form"
    fr = [v for k, v in store.docs.items() if k.startswith("feature_requests/")][0]
    assert fr["status"] == "QUEUED"


def test_cc_create_frees_a_slot_whose_workflow_ended_before_queueing(cc, monkeypatch):
    """The holder's terminal notify was lost; the Workflows API says SUCCEEDED -> the new build is admitted."""
    wl, tel = cc
    store = _store(limit=1)
    old = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    store.docs[STATE] = {"holders": {"other": {"product_id": "x", "acquired_at": old}}, "queue": []}
    store.docs["pipeline_executions/other"] = {
        "status": "ACTIVE", "started_at": old, "workflow_execution_id": "e-9",
        "workflow_execution_name": "projects/p/locations/r/workflows/w/executions/e-9"}
    monkeypatch.setattr(tel, "db", store)
    with patch.object(_wfx(), "get_execution_state", return_value="SUCCEEDED"), \
            patch.object(_wfx(), "_session", return_value=MagicMock()):
        r, publisher = _cc_create(wl, monkeypatch, store)
    assert r.status_code == 200 and publisher.publish.call_count == 1
    assert store.docs["pipeline_executions/other"]["status"] == "SUCCEEDED"


def test_cc_admission_store_down_is_503_nothing_published(cc, monkeypatch):
    wl, _ = cc
    store = _store(limit=1)
    store.docs[STATE] = {"holders": [], "queue": "x"}
    r, publisher = _cc_create(wl, monkeypatch, store)
    assert r.status_code == 503 and r.json()["detail"]["code"] == ba.BUILD_ADMISSION_UNAVAILABLE
    assert publisher.publish.call_count == 0
    assert store.docs["workloads/shop-app"]["status"] == "FAILED"


def _retrigger(wl, store, body=None, *, publisher=None):
    from types import SimpleNamespace

    pub = publisher or MagicMock()
    if publisher is None:
        pub.publish.return_value.result.return_value = "msg-1"
    main_mod = SimpleNamespace(project_id="mock-stackvend-project", get_pubsub_publisher=lambda: pub)
    req = MagicMock()
    req.state.user_email = "operator@example.com"
    from routes.settings import PlatformSettings
    with patch.object(wl, "db", store), patch.object(wl, "verify_workload_access", lambda *a, **k: None), \
            patch.object(wl, "get_caller_main_module", lambda: main_mod), \
            patch.object(wl, "get_platform_settings", return_value=PlatformSettings()), \
            patch.object(wl, "new_run_refusal", return_value=None):
        return wl.retrigger_feature_request_build("shop", "fr-1", req, body=body), pub


def _retrigger_store(limit):
    s = _store(limit=limit)
    s.docs["workloads/shop"] = {"project_id": "shop-proj", "github_repo": "org/shop", "default_branch": "main",
                                "status": "ACTIVE"}
    s.docs["feature_requests/fr-1"] = {"product_id": "shop", "title": "Add search", "description": "spec",
                                       "status": "PENDING_TRIAGE"}
    return s


def _no_route_query(wl):
    """The Auto route reads earlier runs with a query this fake does not serve: Auto then picks FULL."""
    return patch.object(wl, "_resume_developer_block", lambda *a, **k: None)


def test_cc_retrigger_do_no_harm(cc, monkeypatch):
    wl, _ = cc
    store = _retrigger_store(limit=2)
    res, pub = _retrigger(wl, store, {"execution_mode": "FULL"})
    assert res["status"] == "DISPATCHED" and pub.publish.call_count == 1
    trace = res["trace_id"]
    assert store.docs[f"pipeline_executions/{trace}"]["status"] == "ACTIVE"
    assert store.docs["feature_requests/fr-1"]["status"] == "IN_DEVELOPMENT"
    assert list(store.docs[STATE]["holders"]) == [trace]


def test_cc_retrigger_over_the_limit_is_202_and_relaunch_while_queued_is_409(cc, monkeypatch):
    from fastapi import HTTPException
    from fastapi.responses import JSONResponse

    wl, _ = cc
    store = _retrigger_store(limit=1)
    store.docs[STATE] = {"holders": {"other": {"product_id": "x", "acquired_at": datetime.now(timezone.utc).isoformat()}},
                         "queue": []}
    store.docs["pipeline_executions/other"] = {"status": "ACTIVE"}
    res, pub = _retrigger(wl, store, {"execution_mode": "FULL"})
    assert isinstance(res, JSONResponse) and res.status_code == 202
    body = json.loads(res.body)
    trace = body["trace_id"]
    assert body["status"] == "QUEUED" and body["build_queue"]["position"] == 1 and pub.publish.call_count == 0
    rec = store.docs[f"pipeline_executions/{trace}"]
    assert rec["status"] == "QUEUED" and rec["stages"]["architect"]["status"] == "QUEUED"   # the full pre-seed
    assert store.docs["feature_requests/fr-1"]["status"] == "QUEUED"
    with pytest.raises(HTTPException) as ei:
        _retrigger(wl, store, {"execution_mode": "FULL"})
    assert ei.value.status_code == 409 and ei.value.detail["code"] == ba.BUILD_ALREADY_QUEUED
    assert ei.value.detail["queued_trace_id"] == trace and _queue(store) == [trace]


def test_cc_fast_path_relaunch_never_waits(cc, monkeypatch):
    wl, _ = cc
    store = _retrigger_store(limit=1)
    store.docs[STATE] = {"holders": {"other": {"product_id": "x", "acquired_at": datetime.now(timezone.utc).isoformat()}},
                         "queue": []}
    store.docs["pipeline_executions/other"] = {"status": "ACTIVE"}
    res, pub = _retrigger(wl, store, {"execution_mode": "DEPLOY_ONLY"})
    assert res["status"] == "DISPATCHED" and pub.publish.call_count == 1
    assert list(store.docs[STATE]["holders"]) == ["other"]


def test_cc_retrigger_publish_failure_releases_the_slot(cc, monkeypatch):
    wl, _ = cc
    store = _retrigger_store(limit=1)
    pub = MagicMock()
    pub.publish.side_effect = RuntimeError("pubsub down")
    with pytest.raises(Exception):
        _retrigger(wl, store, {"execution_mode": "FULL"}, publisher=pub)
    assert store.docs[STATE]["holders"] == {}


def test_cc_poll_reconciles_and_pumps(cc, monkeypatch):
    """Terminal event lost: the Flight Deck poll closes the run from the Workflows API, frees its slot and publishes
    the queued build; the queued list shows the rest in order."""
    wl, tel = cc
    store = _store(limit=1, **{"workloads__shop": {"status": "ACTIVE"}, "workloads__blog": {"status": "ACTIVE"},
                               "workloads__news": {"status": "ACTIVE"}})
    old = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    store.docs[STATE] = {"holders": {"t-shop": {"product_id": "shop", "acquired_at": old}}, "queue": []}
    store.docs["pipeline_executions/t-shop"] = {
        "trace_id": "t-shop", "product_id": "shop", "status": "ACTIVE", "started_at": old,
        "workflow_execution_name": "projects/p/locations/r/workflows/w/executions/e-1"}
    for trace, pid in (("t-blog", "blog"), ("t-news", "news")):
        assert ba.admit(store, trace, product_id=pid, payload={"trace_id": trace, "product_id": pid},
                        source="t").state == ba.QUEUED
        store.docs[f"pipeline_executions/{trace}"] = {"trace_id": trace, "product_id": pid, "status": "QUEUED",
                                                      "started_at": old}

    class _Query:
        def __init__(self, docs):
            self.docs = docs

        def where(self, field, op, value):
            vals = value if op == "in" else [value]
            return _Query([d for d in self.docs if (d.to_dict() or {}).get(field) in vals])

        def order_by(self, *a, **k):
            return self

        def limit(self, n):
            return _Query(self.docs[:n])

        def stream(self):
            return list(self.docs)

    def snaps():
        out = []
        for path in sorted(store.docs):
            if path.startswith("pipeline_executions/") and path.count("/") == 1:
                ref = store.collection("pipeline_executions").document(path.split("/")[1])
                snap = ref.get()
                snap.reference = ref
                out.append(snap)
        return out

    orig_collection = store.collection

    def collection(name):
        col = orig_collection(name)
        if name == "pipeline_executions":
            col.where = lambda *a: _Query(snaps()).where(*a)
            col.order_by = lambda *a, **k: _Query(snaps())
            col.limit = lambda n: _Query(snaps()[:n])
        return col

    store.collection = collection
    publisher = MagicMock()
    publisher.publish.return_value.result.return_value = "msg"
    monkeypatch.setattr(tel, "db", store)
    monkeypatch.setattr(tel, "_wf_check_cache", {})
    import db as cc_db
    monkeypatch.setattr(cc_db, "get_pubsub_publisher", lambda: publisher)
    from routes.settings import PlatformSettings
    with patch.object(_wfx(), "get_execution_state", return_value="SUCCEEDED"), \
            patch.object(_wfx(), "_session", return_value=MagicMock()), \
            patch("routes.settings.get_platform_settings", return_value=PlatformSettings()):
        resp = tel.get_active_pipeline_executions()
    assert store.docs["pipeline_executions/t-shop"]["status"] == "SUCCEEDED"
    assert publisher.publish.call_count == 1
    assert json.loads(publisher.publish.call_args[0][1])["trace_id"] == "t-blog"
    assert list(store.docs[STATE]["holders"]) == ["t-blog"]
    assert [e.trace_id for e in resp.queued_executions] == ["t-news"]
    assert resp.queued_executions[0].build_queue["position"] == 1
    assert resp.build_queue == {"limit": 1, "running": 1, "queued": 1}


def test_cc_abort_of_a_queued_run_cancels_it(cc, monkeypatch):
    wl, tel = cc
    store = _store(limit=1)
    _admit(store, "a")
    _admit(store, "b", product="shop")
    store.docs["pipeline_executions/b"] = {"trace_id": "b", "product_id": "shop", "status": "QUEUED"}
    monkeypatch.setattr(tel, "db", store)
    monkeypatch.setattr(tel, "verify_workload_access", lambda *a, **k: None)
    req = MagicMock()
    req.state.user_email = "ops@example.com"
    out = tel.abort_pipeline_execution("b", req)
    assert out["status"] == "ABORTED" and out["build_queue"]["state"] == "CANCELLED"
    assert _queue(store) == [] and store.docs["pipeline_executions/b"]["error_class"] == ba.BUILD_QUEUE_CANCELLED
    # promoted between the read and the cancel: 409, never a silent abort of a starting run
    _admit(store, "c", product="shop")
    store.docs["pipeline_executions/c"] = {"trace_id": "c", "product_id": "shop", "status": "QUEUED"}
    store.docs["pipeline_executions/a"] = {"status": "SUCCEEDED"}
    ba.promote(store)
    with pytest.raises(Exception) as ei:
        tel.abort_pipeline_execution("c", req)
    assert getattr(ei.value, "status_code", None) == 409


def test_cc_approval_resumes_through_a_slot_f2(cc, monkeypatch):
    """F2 option A through the Control Center's real decision code: a slot free -> the callback is delivered now; all
    slots taken -> the approval is recorded, the run waits at the head of the queue and nothing is delivered yet."""
    from routes import approvals
    from schemas import ApprovalDecisionRequest

    store = _store(limit=1)
    _admit(store, "a")
    _running(store, "a")
    ba.park(store, "a", stage="AWAITING_PLAN_APPROVAL")
    delivered = []
    monkeypatch.setattr(approvals, "db", store)
    monkeypatch.setattr(approvals, "_deliver_workflow_callback", lambda url, payload: delivered.append(payload)
                        or (True, ""))
    record = {"approval_type": "ARCHITECTURAL_PLAN", "trace_id": "a", "product_id": "app", "callback_url": CB}
    req = ApprovalDecisionRequest(decision="APPROVED")
    out = approvals._decide("appr-a", dict(record), req, MagicMock(), "ops@example.com", "2026-11-14T00:00:00Z")
    assert out["status"] == "APPROVED" and len(delivered) == 1 and list(_state(store)["holders"]) == ["a"]
    # the same run waits for a person again (PR approval) while another build takes the slot
    ba.park(store, "a", stage="AWAITING_PR_APPROVAL")
    _admit(store, "b")
    _running(store, "b")
    out = approvals._decide("appr-a2", dict(record, approval_type="ARCHITECTURAL_PLAN"), req, MagicMock(),
                            "ops@example.com", "2026-11-14T00:00:00Z")
    assert out["status"] == "APPROVED" and out["build_queue"]["state"] == "QUEUED" and len(delivered) == 1
    assert _queue(store) == ["a"] and store.docs["build_queue/a"]["approval_id"] == "appr-a2"


def test_cc_decommission_cascade_cancels_queued_runs(cc, monkeypatch):
    wl, _ = cc
    store = _store(limit=1)
    _admit(store, "a", product="x")
    _admit(store, "b", product="shop")
    monkeypatch.setattr(wl, "db", store)
    with patch.object(wl.sandbox_sweep, "cancel_active_executions", return_value=0):
        wl.cancel_workload_active_executions("shop", "ops@example.com", "decommission")
    assert _queue(store) == []
