"""
Wave 2 lane 14 PR-3: sre-telemetry-digest-job reports real telemetry only (C33; plan
docs/planning/wave2-lane14-core-services-plan.md section 2.4, section 2.0; register row L14-m).

Hermetic: an in-memory Firestore fake and injected Logging / Monitoring readers, Cloud Run URL resolver, ID-token
fetcher and HTTP poster. The default REST readers are exercised against a fake AuthorizedSession. Nothing here builds a
cloud client or reaches the network.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import copy
import importlib.util
import json
import logging
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from google.api_core.exceptions import AlreadyExists, ServiceUnavailable

REPO = Path(__file__).resolve().parent.parent
APP_DIR = REPO / "apps" / "sre-digest"
SENTINEL_DIR = REPO / "apps" / "log-sre-sentinel"


def _load_modules():
    sys.path.insert(0, str(APP_DIR))
    try:
        import digest as digest_mod

        spec = importlib.util.spec_from_file_location("lane14_digest_main", APP_DIR / "main.py")
        main_mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(main_mod)
    finally:
        sys.path.remove(str(APP_DIR))
    sys.path.insert(0, str(SENTINEL_DIR))
    try:
        import sre_classifier as clf_mod
    finally:
        sys.path.remove(str(SENTINEL_DIR))
    return digest_mod, main_mod, clf_mod


digest, digest_main, clf = _load_modules()

HOST = "mock-stackvend-project"
REGION = "us-central1"
NOW = datetime(2026, 10, 18, 7, 0, 0, tzinfo=timezone.utc)
SENTINEL_URL = "https://log-sre-sentinel-service-h4sh-uc.a.run.app"


# ---------------------------------------------------------------------------------------------------------------
# Fakes
# ---------------------------------------------------------------------------------------------------------------
class FakeSnap:
    def __init__(self, doc_id, data):
        self.id = doc_id
        self._data = copy.deepcopy(data)

    @property
    def exists(self):
        return self._data is not None

    def to_dict(self):
        return copy.deepcopy(self._data)


class FakeDocRef:
    def __init__(self, db, coll, doc_id):
        self.db, self.coll, self.id = db, coll, doc_id

    def _store(self):
        return self.db.data.setdefault(self.coll, {})

    def get(self):
        self.db._check("get", self.coll)
        return FakeSnap(self.id, self._store().get(self.id))

    def create(self, data):
        self.db._check("create", self.coll)
        if self.id in self._store():
            raise AlreadyExists(f"{self.coll}/{self.id}")
        self.db.writes.append(("create", self.coll, self.id))
        self._store()[self.id] = copy.deepcopy(data)

    def set(self, data, merge=False):
        self.db._check("set", self.coll)
        self.db.writes.append(("set", self.coll, self.id))
        self._store()[self.id] = copy.deepcopy(data)


class FakeQuery:
    def __init__(self, db, coll, filters=(), limit_n=None):
        self.db, self.coll, self.filters, self.limit_n = db, coll, tuple(filters), limit_n

    def where(self, *args, filter=None):
        assert filter is not None and not args and filter.op_string == "=="
        return FakeQuery(self.db, self.coll, self.filters + ((filter.field_path, filter.value),), self.limit_n)

    def limit(self, n):
        return FakeQuery(self.db, self.coll, self.filters, n)

    def stream(self):
        self.db._check("stream", self.coll)
        out = [FakeSnap(k, v) for k, v in self.db.data.get(self.coll, {}).items()
               if all(v.get(f) == val for f, val in self.filters)]
        return iter(out[: self.limit_n] if self.limit_n is not None else out)


class FakeCollection(FakeQuery):
    def document(self, doc_id):
        return FakeDocRef(self.db, self.coll, doc_id)


class FakeDB:
    def __init__(self):
        self.data, self.writes, self.fail = {}, [], {}

    def _check(self, op, coll):
        if (op, coll) in self.fail:
            raise self.fail[(op, coll)]

    def collection(self, name):
        return FakeCollection(self, name)


def ledger(db, extra=None):
    db.data["workloads"] = {
        "shop-app": {"project_id": "child-shop-1", "status": "ACTIVE"},
        "project-castor": {"project_id": HOST, "status": "ACTIVE", "is_castor": True},
        "old-app": {"project_id": "child-old-3", "status": "DECOMMISSIONED"},
    }
    db.data["workloads"].update(extra or {})
    return db


def warn_entry(service, message, ts="2026-10-17T10:00:00Z", severity="WARNING"):
    return {"logName": "projects/child-shop-1/logs/run.googleapis.com%2Fstderr", "severity": severity,
            "timestamp": ts, "textPayload": message,
            "resource": {"type": "cloud_run_revision", "labels": {"service_name": service, "project_id": "child-shop-1"}}}


class Telemetry:
    """Injected readers: per project, log entries and per-window latency maps (keyed by window start)."""

    def __init__(self, logs=None, current=None, baseline=None, log_error=None, latency_error=None):
        self.logs, self.current, self.baseline = logs or {}, current or {}, baseline or {}
        self.log_error, self.latency_error = log_error, latency_error
        self.log_calls, self.latency_calls = [], []

    def log_reader(self, project_id, start, end, max_entries):
        self.log_calls.append((project_id, start, end, max_entries))
        if self.log_error:
            raise self.log_error
        return list(self.logs.get(project_id, [])), False

    def latency_reader(self, project_id, start, end):
        self.latency_calls.append((project_id, start, end))
        if self.latency_error:
            raise self.latency_error
        window = self.current if end == NOW else self.baseline
        return copy.deepcopy(window.get(project_id, {}))


class Sentinel:
    def __init__(self, status=200, body=None):
        self.calls = []
        self.status = status
        self.body = body if body is not None else {"status": "INCIDENT_RECORDED", "incident_id": "inc-1",
                                                   "auto_remediation_status": "SUPPRESSED:INTAKE_CONTRACT_PENDING"}

    def __call__(self, url, *, headers, json_body, timeout):
        self.calls.append({"url": url, "headers": headers, "json": json_body})
        return self.status, self.body


def make(env=None, *, db=None, telemetry=None, sentinel=None, verifier=None, url=SENTINEL_URL):
    db = db if db is not None else ledger(FakeDB())
    telemetry = telemetry if telemetry is not None else Telemetry()
    sentinel = sentinel if sentinel is not None else Sentinel()
    base_env = {"PROJECT_ID": HOST, "REGION": REGION, "CLOUD_RUN_EXECUTION": "sre-telemetry-digest-job-xyz"}
    if env is not None:
        base_env = env
    resolver_calls = []

    def resolver(project, region, service):
        resolver_calls.append((project, region, service))
        return url

    eng = digest.SRETelemetryDigest(
        project_id=base_env.get("PROJECT_ID", ""), firestore_client=db, env=base_env,
        log_reader=telemetry.log_reader, latency_reader=telemetry.latency_reader, target_verifier=verifier,
        service_url_resolver=resolver, id_token_fetcher=lambda aud: f"tok-for-{aud}", http_post=sentinel,
        clock=lambda: NOW)
    return eng, db, telemetry, sentinel, resolver_calls


def workload(report, pid):
    return [w for w in report["workloads"] if w["product_id"] == pid][0]


# ---------------------------------------------------------------------------------------------------------------
# Honest outcomes (no fabricated data)
# ---------------------------------------------------------------------------------------------------------------
def test_no_entries_and_no_samples_is_no_data_without_a_score():
    eng, db, tel, sentinel, _ = make()
    report = eng.generate_digest_report()
    w = workload(report, "shop-app")
    assert w["status"] == "NO_DATA" and w["health_score"] is None
    assert report["overall_health_score"] is None and report["system_status"] == "NO_DATA"
    assert report["top_warning_clusters"] == [] and report["latency_regressions"] == []
    assert report["proactive_maintenance_recommendations"] == []
    assert report["exit_code"] == 0 and report["run_outcome"] == "COMPLETED"
    saved = db.data[digest.DIGEST_COLLECTION][report["digest_id"]]
    assert saved["system_status"] == "NO_DATA" and saved["overall_health_score"] is None
    assert sentinel.calls == []


def test_entries_produce_the_expected_clusters_and_a_real_score():
    logs = {"child-shop-1": [warn_entry("cart", "Retry 1 of 5 for order 12345"),
                             warn_entry("cart", "Retry 2 of 5 for order 67890"),
                             warn_entry("auth", "Token near expiry")]}
    eng, db, tel, _, _ = make(telemetry=Telemetry(logs=logs))
    report = eng.generate_digest_report()
    w = workload(report, "shop-app")
    assert w["status"] == "OK" and w["warning_entries"] == 3
    assert [(c["service_name"], c["count"]) for c in w["warning_clusters"]] == [("cart", 2), ("auth", 1)]
    assert w["warning_clusters"][0]["pattern"] == "Retry <NUM> of <NUM> for order <NUM>"
    assert w["health_score"] == 100 - 2 * 2 and w["score_basis"] == ["warning_logs"]
    assert report["overall_health_score"] == 96 and report["system_status"] == "EXCELLENT"


def test_three_samples_with_minimum_ten_is_no_baseline():
    cur = {"child-shop-1": {"api": {"p95_ms": 900.0, "samples": 3}}}
    base = {"child-shop-1": {"api": {"p95_ms": 100.0, "samples": 3}}}
    eng, _, _, sentinel, _ = make(env={"PROJECT_ID": HOST, "REGION": REGION, "DIGEST_MIN_SAMPLES": "10",
                                       "CLOUD_RUN_EXECUTION": "e1"}, telemetry=Telemetry(current=cur, baseline=base))
    report = eng.generate_digest_report()
    w = workload(report, "shop-app")
    assert w["latency"]["api"]["status"] == "NO_BASELINE" and w["status"] == "NO_BASELINE"
    assert w["health_score"] is None and w["latency_regressions"] == [] and sentinel.calls == []


@pytest.mark.parametrize("cur_n,base_n", [(500, 3), (3, 500)])
def test_regression_needs_minimum_samples_in_both_windows(cur_n, base_n):
    """RT F3-2a: a 9x p95 jump is NO_BASELINE (no registration, no score) when EITHER week is below the minimum."""
    cur = {"child-shop-1": {"api": {"p95_ms": 900.0, "samples": cur_n}}}
    base = {"child-shop-1": {"api": {"p95_ms": 100.0, "samples": base_n}}}
    eng, _, _, sentinel, _ = make(telemetry=Telemetry(current=cur, baseline=base))
    report = eng.generate_digest_report()
    w = workload(report, "shop-app")
    assert w["latency"]["api"]["status"] == "NO_BASELINE" and w["status"] == "NO_BASELINE"
    assert w["health_score"] is None and w["latency_regressions"] == [] and sentinel.calls == []


def test_p95_200_to_300_with_enough_samples_is_ratio_exactly_1_5_and_not_registered():
    cur = {"child-shop-1": {"api": {"p95_ms": 300.0, "samples": 500}}}
    base = {"child-shop-1": {"api": {"p95_ms": 200.0, "samples": 500}}}
    eng, _, _, sentinel, _ = make(telemetry=Telemetry(current=cur, baseline=base))
    report = eng.generate_digest_report()
    reg = workload(report, "shop-app")["latency_regressions"]
    assert len(reg) == 1 and reg[0]["ratio"] == 1.5 and reg[0]["severity"] == "MEDIUM"
    assert reg[0]["drift_percentage"] == "+50.0%"
    assert sentinel.calls == []  # 1.5 is not above the incident threshold (1.5)
    assert workload(report, "shop-app")["health_score"] == 95


def test_high_regression_is_registered_with_the_sentinel_exactly_once():
    cur = {"child-shop-1": {"api": {"p95_ms": 400.0, "samples": 500}}}
    base = {"child-shop-1": {"api": {"p95_ms": 200.0, "samples": 500}}}
    eng, db, _, sentinel, resolver_calls = make(telemetry=Telemetry(current=cur, baseline=base))
    report = eng.generate_digest_report()
    assert len(sentinel.calls) == 1
    call = sentinel.calls[0]
    assert call["url"] == f"{SENTINEL_URL}/incidents/register"
    assert call["headers"] == {"Authorization": f"Bearer tok-for-{SENTINEL_URL}"}
    assert call["json"]["product_id"] == "shop-app" and call["json"]["source"] == "sre-telemetry-digest-job"
    assert call["json"]["fingerprint"] == "latency_regression/api"
    assert call["json"]["evidence"]["ratio"] == 2.0
    assert resolver_calls == [(HOST, REGION, "log-sre-sentinel-service")]
    assert report["incident_registrations"][0]["status"] == "REGISTERED" and report["exit_code"] == 0


def test_healthy_workload_registers_nothing_negative():
    """Do-No-Harm negative test: steady latency and no warnings -> no registration, score 100."""
    cur = {"child-shop-1": {"api": {"p95_ms": 100.0, "samples": 500}}}
    base = {"child-shop-1": {"api": {"p95_ms": 100.0, "samples": 500}}}
    eng, _, _, sentinel, resolver_calls = make(telemetry=Telemetry(current=cur, baseline=base))
    report = eng.generate_digest_report()
    assert sentinel.calls == [] and resolver_calls == []
    assert workload(report, "shop-app")["health_score"] == 100


def test_untagged_project_is_skipped_with_not_stackvend_owned():
    def verifier(product_id, data):
        raise digest.TargetRefused("NOT_STACKVEND_OWNED", "no direct stackvend-managed tag binding")

    eng, _, tel, sentinel, _ = make(verifier=verifier)
    report = eng.generate_digest_report()
    assert workload(report, "shop-app")["status"] == "REFUSED:NOT_STACKVEND_OWNED"
    assert tel.log_calls == [] and tel.latency_calls == [] and sentinel.calls == []
    assert report["exit_code"] == 0


def test_host_project_is_never_queried():
    eng, _, tel, _, _ = make()
    report = eng.generate_digest_report()
    assert HOST not in {c[0] for c in tel.log_calls}
    assert all(w["scope"] == "workload" for w in report["workloads"])


def test_decommissioned_and_platform_ledger_docs_are_not_tenant_targets():
    eng, _, tel, _, _ = make()
    eng.generate_digest_report()
    assert {c[0] for c in tel.log_calls} == {"child-shop-1"}


def test_host_project_id_on_a_tenant_ledger_doc_is_refused():
    db = ledger(FakeDB(), {"evil-app": {"project_id": HOST, "status": "ACTIVE"}})
    eng, _, tel, _, _ = make(db=db)
    report = eng.generate_digest_report()
    assert workload(report, "evil-app")["status"] == "REFUSED:HOST_PROJECT"
    assert HOST not in {c[0] for c in tel.log_calls}


def test_project_owned_by_two_ledger_docs_is_refused_ledger_mismatch():
    db = ledger(FakeDB(), {"twin-app": {"project_id": "child-shop-1", "status": "ACTIVE"}})
    eng, _, tel, _, _ = make(db=db)
    report = eng.generate_digest_report()
    assert workload(report, "shop-app")["status"] == "REFUSED:LEDGER_MISMATCH"
    assert workload(report, "twin-app")["status"] == "REFUSED:LEDGER_MISMATCH"
    assert tel.log_calls == []


# ---------------------------------------------------------------------------------------------------------------
# Errors, configuration, idempotency (plan 2.0)
# ---------------------------------------------------------------------------------------------------------------
def test_logging_read_error_is_error_and_partial_exit_one_with_an_honest_record():
    eng, db, _, _, _ = make(telemetry=Telemetry(log_error=RuntimeError("403 logging.viewer missing")))
    report = eng.generate_digest_report()
    w = workload(report, "shop-app")
    assert w["status"] == "ERROR" and w["health_score"] is None and "LOGGING_READ_FAILED" in w["errors"][0]
    assert report["run_outcome"] == "PARTIAL" and report["exit_code"] == 1
    assert report["overall_health_score"] is None
    assert db.data[digest.RUN_RECORD_COLLECTION]["sre-telemetry-digest-job-xyz"]["outcome"] == "PARTIAL"


def test_ledger_read_failure_writes_no_digest_and_exits_one():
    db = ledger(FakeDB())
    db.fail[("stream", "workloads")] = ServiceUnavailable("down")
    eng, db, tel, _, _ = make(db=db)
    report = eng.generate_digest_report()
    assert report["status"] == "FAILED" and report["exit_code"] == 1
    assert digest.DIGEST_COLLECTION not in db.data and tel.log_calls == []


def test_missing_project_id_is_not_configured_exit_three(caplog):
    eng, db, _, _, _ = make(env={"REGION": REGION})
    with caplog.at_level(logging.WARNING, logger="sre-telemetry-digest-job"):
        report = eng.generate_digest_report()
    assert report["exit_code"] == 3 and report["missing"] == ["PROJECT_ID"] and db.writes == []
    assert [json.loads(r.getMessage()) for r in caplog.records if r.levelno == logging.WARNING] == [
        {"error_class": "NOT_CONFIGURED", "job": digest.JOB_NAME, "missing": ["PROJECT_ID"]}]


@pytest.mark.parametrize("key,value", [("DIGEST_MIN_SAMPLES", "ten"), ("DIGEST_MIN_SAMPLES", "0"),
                                       ("DIGEST_REGRESSION_RATIO", "-1"), ("DIGEST_INCIDENT_RATIO", "1.1"),
                                       # RT F3-3: non-finite floats pass `<= 0` and would silently disable regressions
                                       ("DIGEST_REGRESSION_RATIO", "nan"), ("DIGEST_INCIDENT_RATIO", "inf"),
                                       ("DIGEST_REGRESSION_RATIO", "-inf"), ("DIGEST_INCIDENT_RATIO", "NaN")])
def test_invalid_settings_are_not_configured_exit_three(key, value):
    eng, db, tel, _, _ = make(env={"PROJECT_ID": HOST, "REGION": REGION, "CLOUD_RUN_EXECUTION": "e-cfg", key: value})
    report = eng.generate_digest_report()
    assert report["exit_code"] == 3 and tel.log_calls == []
    assert db.data[digest.RUN_RECORD_COLLECTION]["e-cfg"]["outcome"] == "NOT_CONFIGURED"
    assert clf.run_record_collection(digest.JOB_NAME) == digest.RUN_RECORD_COLLECTION
    assert digest.JOB_NAME in clf.DEFAULT_PLATFORM_JOBS


def test_missing_region_with_a_registration_due_is_not_configured_but_the_digest_is_written():
    cur = {"child-shop-1": {"api": {"p95_ms": 400.0, "samples": 500}}}
    base = {"child-shop-1": {"api": {"p95_ms": 200.0, "samples": 500}}}
    eng, db, _, sentinel, _ = make(env={"PROJECT_ID": HOST, "CLOUD_RUN_EXECUTION": "e-reg"},
                                   telemetry=Telemetry(current=cur, baseline=base))
    report = eng.generate_digest_report()
    assert sentinel.calls == [] and report["exit_code"] == 3
    assert report["incident_registrations"][0]["status"] == "NOT_CONFIGURED"
    assert report["digest_id"] in db.data[digest.DIGEST_COLLECTION]
    assert db.data[digest.RUN_RECORD_COLLECTION]["e-reg"]["outcome"] == "NOT_CONFIGURED"


def test_sentinel_refusal_is_recorded_and_not_an_error():
    cur = {"child-shop-1": {"api": {"p95_ms": 400.0, "samples": 500}}}
    base = {"child-shop-1": {"api": {"p95_ms": 200.0, "samples": 500}}}
    eng, _, _, sentinel, _ = make(telemetry=Telemetry(current=cur, baseline=base),
                                  sentinel=Sentinel(422, {"status": "NOT_RECORDED", "error_class": "PRODUCT_AMBIGUOUS"}))
    report = eng.generate_digest_report()
    assert report["incident_registrations"][0] == {"product_id": "shop-app", "fingerprint": "latency_regression/api",
                                                   "status": "REFUSED", "code": "PRODUCT_AMBIGUOUS"}
    assert report["exit_code"] == 0


@pytest.mark.parametrize("status", [500, 503, 403])
def test_sentinel_failure_is_partial_exit_one(status):
    cur = {"child-shop-1": {"api": {"p95_ms": 400.0, "samples": 500}}}
    base = {"child-shop-1": {"api": {"p95_ms": 200.0, "samples": 500}}}
    eng, _, _, _, _ = make(telemetry=Telemetry(current=cur, baseline=base), sentinel=Sentinel(status, {}))
    report = eng.generate_digest_report()
    assert report["incident_registrations"][0]["code"] == f"HTTP_{status}"
    assert report["run_outcome"] == "PARTIAL" and report["exit_code"] == 1


@pytest.mark.parametrize("status,error_class", [(401, "UNAUTHENTICATED"), (403, "CALLER_NOT_ALLOWED"),
                                                (503, "CALLERS_UNCONFIGURED"), (503, "AUDIENCE_UNCONFIGURED")])
def test_sentinel_caller_refusals_are_failures_not_refusals(status, error_class):
    """RT F3-1: the sentinel's typed caller-identity answers are visible failures (PARTIAL, exit 1), never REFUSED."""
    cur = {"child-shop-1": {"api": {"p95_ms": 400.0, "samples": 500}}}
    base = {"child-shop-1": {"api": {"p95_ms": 200.0, "samples": 500}}}
    body = {"status": "NOT_RECORDED", "error_class": error_class, "detail": "x"}
    eng, _, _, _, _ = make(telemetry=Telemetry(current=cur, baseline=base), sentinel=Sentinel(status, body))
    report = eng.generate_digest_report()
    reg = report["incident_registrations"][0]
    assert (reg["status"], reg["code"]) == ("FAILED", f"HTTP_{status}")
    assert report["run_outcome"] == "PARTIAL" and report["exit_code"] == 1


def test_same_execution_twice_writes_one_digest_and_registers_once():
    cur = {"child-shop-1": {"api": {"p95_ms": 400.0, "samples": 500}}}
    base = {"child-shop-1": {"api": {"p95_ms": 200.0, "samples": 500}}}
    eng, db, tel, sentinel, _ = make(telemetry=Telemetry(current=cur, baseline=base))
    first = eng.generate_digest_report()
    second = eng.generate_digest_report()
    assert len(sentinel.calls) == 1 and len(db.data[digest.DIGEST_COLLECTION]) == 1
    assert second["status"] == "ALREADY_RECORDED" and second["recorded_outcome"] == first["run_outcome"]
    assert second["exit_code"] == 0


def test_run_record_failure_fails_closed():
    db = ledger(FakeDB())
    db.fail[("create", digest.RUN_RECORD_COLLECTION)] = ServiceUnavailable("down")
    eng, db, tel, _, _ = make(db=db)
    report = eng.generate_digest_report()
    assert report["exit_code"] == 1 and tel.log_calls == [] and digest.DIGEST_COLLECTION not in db.data


def test_windows_are_this_week_and_the_previous_week():
    eng, _, tel, _, _ = make()
    eng.generate_digest_report()
    week = timedelta(days=7)
    assert tel.log_calls == [("child-shop-1", NOW - week, NOW, 5000)]
    assert tel.latency_calls == [("child-shop-1", NOW - week, NOW), ("child-shop-1", NOW - 2 * week, NOW - week)]


# ---------------------------------------------------------------------------------------------------------------
# Default REST readers (fake AuthorizedSession; no network)
# ---------------------------------------------------------------------------------------------------------------
class FakeResp:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        return None

    def json(self):
        return self._data


class FakeSession:
    def __init__(self, posts=None, gets=None):
        self.posts, self.gets = list(posts or []), list(gets or [])
        self.post_calls, self.get_calls = [], []

    def post(self, url, json=None, timeout=None):
        self.post_calls.append((url, copy.deepcopy(json)))
        return FakeResp(self.posts.pop(0))

    def get(self, url, params=None, timeout=None):
        self.get_calls.append((url, copy.deepcopy(params)))
        return FakeResp(self.gets.pop(0))


def test_default_log_reader_pages_and_caps(monkeypatch):
    session = FakeSession(posts=[{"entries": [{"n": 1}, {"n": 2}], "nextPageToken": "t2"},
                                 {"entries": [{"n": 3}, {"n": 4}], "nextPageToken": "t3"}])
    monkeypatch.setattr(digest, "_authorized_session", lambda: session)
    entries, truncated = digest.default_log_reader("child-shop-1", NOW - timedelta(days=7), NOW, 3)
    assert [e["n"] for e in entries] == [1, 2, 3] and truncated is True
    url, body = session.post_calls[0]
    assert url == "https://logging.googleapis.com/v2/entries:list"
    assert body["resourceNames"] == ["projects/child-shop-1"]
    assert body["filter"] == 'severity>=WARNING AND timestamp>="2026-10-11T07:00:00Z" AND timestamp<"2026-10-18T07:00:00Z"'
    assert session.post_calls[1][1]["pageToken"] == "t2"


def test_default_latency_reader_queries_p95_and_counts(monkeypatch):
    def series(svc, value):
        return {"resource": {"labels": {"service_name": svc}}, "points": [{"value": value}]}

    session = FakeSession(gets=[
        {"timeSeries": [series("api", {"doubleValue": 312.5}), series("web", {"doubleValue": 80.0})]},
        {"timeSeries": [series("api", {"distributionValue": {"count": "1200"}}),
                        series("web", {"distributionValue": {"count": "7"}})]},
    ])
    monkeypatch.setattr(digest, "_authorized_session", lambda: session)
    out = digest.default_latency_reader("child-shop-1", NOW - timedelta(days=7), NOW)
    assert out == {"api": {"p95_ms": 312.5, "samples": 1200}, "web": {"p95_ms": 80.0, "samples": 7}}
    (u1, p1), (u2, p2) = session.get_calls
    assert u1 == u2 == "https://monitoring.googleapis.com/v3/projects/child-shop-1/timeSeries"
    assert p1["filter"] == 'metric.type="run.googleapis.com/request_latencies" AND resource.type="cloud_run_revision"'
    assert p1["aggregation.alignmentPeriod"] == "604800s" and p1["aggregation.perSeriesAligner"] == "ALIGN_DELTA"
    assert p1["aggregation.crossSeriesReducer"] == "REDUCE_PERCENTILE_95"
    assert p2["aggregation.crossSeriesReducer"] == "REDUCE_SUM"
    assert p1["aggregation.groupByFields"] == "resource.label.service_name"


def test_default_latency_reader_takes_the_largest_p95_point_and_sums_counts(monkeypatch):
    """RT F3-2b: more than one point per series -> the conservative (largest) p95 and the summed request count."""
    session = FakeSession(gets=[
        {"timeSeries": [{"resource": {"labels": {"service_name": "api"}},
                         "points": [{"value": {"doubleValue": 120.0}}, {"value": {"doubleValue": 312.5}}]}]},
        {"timeSeries": [{"resource": {"labels": {"service_name": "api"}},
                         "points": [{"value": {"distributionValue": {"count": "700"}}},
                                    {"value": {"distributionValue": {"count": "500"}}}]}]},
    ])
    monkeypatch.setattr(digest, "_authorized_session", lambda: session)
    out = digest.default_latency_reader("child-shop-1", NOW - timedelta(days=7), NOW)
    assert out == {"api": {"p95_ms": 312.5, "samples": 1200}}


# ---------------------------------------------------------------------------------------------------------------
# No sample data, no floor, no substring heuristics (source checks)
# ---------------------------------------------------------------------------------------------------------------
def _digest_tree():
    return ast.parse((APP_DIR / "digest.py").read_text())


def test_digest_source_has_no_sample_telemetry_and_no_score_floor():
    tree = _digest_tree()
    literals = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    for fake in ("Rate limit retry", "Token expiration warning", "Optimize Google Drive", "remote state read cache"):
        assert not any(fake in lit for lit in literals), fake
    fn = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "generate_digest_report"][0]
    assert [a.arg for a in fn.args.args] == ["self", "run_id"]  # no sample_warnings / sample_metrics
    floors = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
              and n.func.id == "max" and any(isinstance(a, ast.Constant) and a.value == 70 for a in n.args)]
    assert floors == []


def test_digest_regex_use_is_limited_to_the_kept_he07_normalization():
    tree = _digest_tree()
    re_calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                and isinstance(n.func.value, ast.Name) and n.func.value.id == "re"]
    owners = set()
    for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
        if any(c in ast.walk(fn) for c in re_calls):
            owners.add(fn.name)
    assert owners == {"cluster_warning_logs"} and len(re_calls) == 2
    calls = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert not ({"endswith", "find", "rfind"} & calls)


def test_health_score_has_no_floor():
    assert digest.health_score(30, 0) == 0
    assert digest.health_score(1, 9) == 100 - 5 - 10
    assert digest.system_status(None) == "NO_DATA"


# ---------------------------------------------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------------------------------------------
def test_main_import_builds_no_client_and_run_batch_propagates_exit_codes(capsys):
    assert digest_main._engine is None
    eng, _, _, _, _ = make()
    assert digest_main.run_batch(["--batch"], engine=eng) == 0
    assert json.loads(capsys.readouterr().out)["run_outcome"] == "COMPLETED"
    eng2, _, _, _, _ = make(env={"REGION": REGION})
    assert digest_main.run_batch([], engine=eng2) == 3
    assert digest_main.run_batch(["--lookback_days", "3"], engine=eng) == 2


def test_digest_api_accepts_no_sample_data():
    from fastapi.testclient import TestClient

    eng, _, _, _, _ = make()
    digest_main._engine = eng
    try:
        client = TestClient(digest_main.app)
        health = client.get("/health").json()
        resp = client.post("/digest", json={"sample_warnings": [{"service_name": "x", "message": "fake"}]})
    finally:
        digest_main._engine = None
    assert health["status"] == "healthy" and health["settings"]["DIGEST_MIN_SAMPLES"] == 50
    assert resp.status_code == 200 and resp.json()["top_warning_clusters"] == []
