"""
Interim lane-18 guard on the live sandbox TTL sweep (owner decision 2026-10-12, lane 18 OQ-1), carried by lane 4.

Unit part: apps/control-center/sandbox_guard.py loaded by path (stdlib only), every refusal code of lane 18's
SANDBOX_TTL check list as far as it exists today, plus the legit expired sandbox that must still pass.
Endpoint part: the real `sweep_expired_sandboxes_endpoint` in a clean subprocess (hermetic_guard.child_env) on the FD-4E hermetic
harness prefix (sockets/DNS refused, no ADC) with a filtering Firestore fake. Since the lane 18 single window the sweep
calls project-vending (SANDBOX_TTL) instead of this module + an in-process delete; the vending answer is faked and the
CC must make zero Resource Manager calls. This module stays as lane 4's interim implementation (no longer called).
"""

import hermetic_guard  # noqa: F401,E402  (lane 2: must stay the first import; tests/hermetic_guard.py)

from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
import subprocess
import sys
import unittest
from unittest.mock import patch

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
CC = os.path.join(os.path.dirname(HERE), "apps", "control-center")
ROOT_FOLDER = "111111111111"
HOST = "mock-stackvend-project"
HOST_NUMBER = "999000999"
NOW = datetime(2026, 10, 12, 12, 0, tzinfo=timezone.utc)
PAST = (NOW - timedelta(days=1)).isoformat()
FUTURE = (NOW + timedelta(days=3)).isoformat()


def _load_guard():
    spec = importlib.util.spec_from_file_location("cc_sandbox_guard_under_test", os.path.join(CC, "sandbox_guard.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ------------------------------------------------------------------------------------------------ fakes (shared)
class Snap:
    def __init__(self, id_, data):
        self.id, self._d, self.exists = id_, data, data is not None

    def to_dict(self):
        return dict(self._d) if self._d is not None else None


class Doc:
    def __init__(self, db, path):
        self.db, self.path, self.id = db, path, path[-1]

    def get(self):
        if self.db.fail_reads:
            raise RuntimeError("503 Firestore unavailable")
        return Snap(self.id, self.db.store.get(self.path))

    def set(self, data, merge=False):
        cur = self.db.store.get(self.path) if merge else None
        self.db.store[self.path] = {**(cur or {}), **data}
        self.db.writes.append(self.path)

    def collection(self, name):
        return Coll(self.db, self.path + (name,))


class Coll:
    def __init__(self, db, path, filters=()):
        self.db, self.path, self.filters = db, path, filters

    def document(self, id_=None):
        self.db.auto += 1
        return Doc(self.db, self.path + (id_ or f"auto-{self.db.auto}",))

    def where(self, field, op, value):
        return Coll(self.db, self.path, self.filters + ((field, op, value),))

    def limit(self, *_):
        return self

    def stream(self):
        out = []
        for p, d in list(self.db.store.items()):
            if len(p) == len(self.path) + 1 and p[:-1] == self.path:
                ok = all((op == "==" and d.get(f) == v) or (op == "in" and d.get(f) in v) for f, op, v in self.filters)
                if ok:
                    out.append(Snap(p[-1], d))
        return out


class FakeDB:
    def __init__(self):
        self.store, self.writes, self.auto, self.fail_reads = {}, [], 0, False

    def collection(self, name):
        return Coll(self, (name,))


class FakeCRM:
    """Records every call. `fail` maps a method name to an HTTP status the adapter reports as CRMUnavailable."""

    def __init__(self, guard_mod, projects, ancestry, liens=None, fail=None):
        self.g, self.projects, self.ancestry, self.liens, self.fail = guard_mod, projects, ancestry, liens or {}, fail or {}
        self.calls = []

    def _maybe_fail(self, what):
        if what in self.fail:
            raise self.g.CRMUnavailable(what, self.fail[what])

    def get_project(self, key):
        self.calls.append(("get_project", key))
        self._maybe_fail("get_project")
        if key not in self.projects:
            raise self.g.CRMUnavailable(f"projects.get {key}", 403)
        return self.projects[key]

    def get_ancestry(self, project_id):
        self.calls.append(("get_ancestry", project_id))
        self._maybe_fail("get_ancestry")
        return self.ancestry.get(project_id, [])

    def list_liens(self, number):
        self.calls.append(("list_liens", number))
        self._maybe_fail("list_liens")
        return self.liens.get(number, [])

    def delete_project(self, number):
        self.calls.append(("delete_project", number))
        self._maybe_fail("delete_project")
        return {"name": f"operations/delete-{number}"}


def seed_world(db, guard_mod, pid="sb-ok", project_id="sv-sb-ok-1a2b", number="123456789", **ledger):
    rec = {"product_id": pid, "project_id": project_id, "project_number": number, "is_castor": False,
           "is_sandbox": True, "sandbox_auto_decommission": True, "sandbox_designation_source": "API_FIELD",
           "sandbox_expires_at": PAST, "status": "ACTIVE"}
    rec.update(ledger)
    db.store[("workloads", pid)] = rec
    projects = {
        HOST: {"name": f"projects/{HOST_NUMBER}", "projectId": HOST, "state": "ACTIVE"},
        number: {"name": f"projects/{number}", "projectId": project_id, "state": "ACTIVE", "labels": {}},
    }
    ancestry = {project_id: [{"resourceId": {"type": "project", "id": project_id}},
                             {"resourceId": {"type": "folder", "id": "222"}},
                             {"resourceId": {"type": "folder", "id": ROOT_FOLDER}},
                             {"resourceId": {"type": "organization", "id": "1"}}]}
    return FakeCRM(guard_mod, projects, ancestry)


ENV = {"MANAGED_WORKLOADS_FOLDER_ID": ROOT_FOLDER, "PROJECT_ID": HOST, "GOOGLE_CLOUD_PROJECT": HOST,
       "PLATFORM_PROJECT_ID": ""}


class TestSandboxGuardChecks(unittest.TestCase):
    def setUp(self):
        self.g = _load_guard()
        pt = patch.dict(os.environ, ENV)
        pt.start()
        self.addCleanup(pt.stop)
        self.db = FakeDB()
        self.crm = seed_world(self.db, self.g)

    def check(self, pid="sb-ok"):
        return self.g.assert_sandbox_deletable(pid, db=self.db, crm=self.crm, now=NOW)

    def refused(self, code, pid="sb-ok"):
        with self.assertRaises(self.g.SandboxDeletionRefused) as ctx:
            self.check(pid)
        self.assertEqual(ctx.exception.code, code, ctx.exception.detail)
        self.assertNotIn("delete_project", [c[0] for c in self.crm.calls])
        return ctx.exception

    def ledger(self, **fields):
        self.db.store[("workloads", "sb-ok")].update(fields)

    # ---------------------------------------------------------------- the legit case still passes
    def test_legit_expired_explicit_sandbox_passes_read_only(self):
        before = repr(sorted(self.db.store.items()))
        v = self.check()
        self.assertEqual((v.project_id, v.project_number, v.action_class), ("sv-sb-ok-1a2b", "123456789", "SANDBOX_TTL"))
        self.assertIn("labels:pre-vocabulary", v.checks)
        self.assertIn("eligibility:ledger_explicit_designation", v.checks)
        self.assertEqual(repr(sorted(self.db.store.items())), before)  # read-only
        self.assertEqual(self.db.writes, [])
        self.assertNotIn("delete_project", [c[0] for c in self.crm.calls])
        self.assertIn(("get_project", "123456789"), self.crm.calls)  # fresh read BY NUMBER

    def test_full_stackvend_label_set_passes(self):
        self.crm.projects["123456789"]["labels"] = {"stackvend-managed": "true", "stackvend-product-id": "sb-ok",
                                                    "stackvend-workload-type": "sandbox", "team": "x"}
        self.assertIn("labels:stackvend", self.check().checks)

    def test_vend_time_provenance_is_preferred_when_present(self):
        self.ledger(sandbox_designation_source=None)  # ledger alone would refuse
        self.db.store[("workload_provenance", "sb-ok")] = {
            "created_by": "stackvend-vending", "project_id": "sv-sb-ok-1a2b", "project_number": "123456789",
            "is_sandbox": True, "sandbox_auto_decommission": True, "sandbox_designation_source": "OPERATOR_CHECKBOX",
            "sandbox_expires_at": PAST}
        self.assertIn("eligibility:provenance", self.check().checks)

    # ---------------------------------------------------------------- 1 config
    def test_unconfigured_root_refuses(self):
        with patch.dict(os.environ, {"MANAGED_WORKLOADS_FOLDER_ID": ""}):
            self.refused("GUARD_UNCONFIGURED")
        with patch.dict(os.environ, {"MANAGED_WORKLOADS_FOLDER_ID": "organizations/1"}):
            self.refused("GUARD_UNCONFIGURED")

    # ---------------------------------------------------------------- 2/3 ledger
    def test_missing_or_unreadable_ledger_refuses(self):
        self.refused("LEDGER_MISSING", pid="sb-nope")
        self.db.fail_reads = True
        self.refused("LEDGER_UNAVAILABLE")

    def test_platform_workloads_refuse(self):
        self.ledger(is_castor=True)
        self.refused("PLATFORM_WORKLOAD")
        self.refused("PLATFORM_WORKLOAD", pid="project-castor")

    def test_no_project_id_fallback_and_number_required(self):
        self.ledger(project_id="")
        self.refused("LEDGER_UNPROVENANCED")
        self.ledger(project_id="sv-sb-ok-1a2b", project_number="")
        self.refused("LEDGER_UNPROVENANCED")

    def test_project_claimed_by_two_workloads_refuses(self):
        self.db.store[("workloads", "prod-app")] = {"product_id": "prod-app", "project_id": "sv-sb-ok-1a2b"}
        self.refused("LEDGER_MISMATCH")

    def test_provenance_disagreeing_with_ledger_refuses(self):
        self.db.store[("workload_provenance", "sb-ok")] = {"created_by": "stackvend-vending", "project_id": "other",
                                                           "project_number": "123456789"}
        self.refused("LEDGER_MISMATCH")

    def test_provenance_not_written_by_vending_refuses(self):
        self.db.store[("workload_provenance", "sb-ok")] = {
            "created_by": "owner-backfill", "project_id": "sv-sb-ok-1a2b", "project_number": "123456789",
            "is_sandbox": True, "sandbox_auto_decommission": True, "sandbox_designation_source": "API_FIELD",
            "sandbox_expires_at": PAST}
        self.refused("SANDBOX_NOT_ELIGIBLE")

    # ---------------------------------------------------------------- 4/5 host + CRM identity
    def test_host_project_refuses_by_id_and_by_number(self):
        self.ledger(project_id=HOST)
        self.refused("HOST_PROJECT")
        self.ledger(project_id="sv-sb-ok-1a2b", project_number=HOST_NUMBER)
        self.crm.projects[HOST_NUMBER] = {"name": f"projects/{HOST_NUMBER}", "projectId": "sv-sb-ok-1a2b", "state": "ACTIVE"}
        self.refused("HOST_PROJECT")

    def test_number_resolving_to_another_project_refuses(self):
        self.crm.projects["123456789"]["projectId"] = "prod-payments"
        self.refused("CRM_MISMATCH")

    def test_inactive_project_refuses(self):
        self.crm.projects["123456789"]["state"] = "DELETE_REQUESTED"
        self.refused("NOT_ACTIVE")

    def test_crm_429_and_5xx_refuse_without_retry(self):
        for status in (429, 500, 503):
            self.crm.calls.clear()
            self.crm.fail = {"get_project": status}
            self.refused("CRM_UNAVAILABLE")
            self.assertEqual(len(self.crm.calls), 1)  # first CRM read failed; nothing retried
        self.crm.fail = {"get_ancestry": 429}
        self.refused("ANCESTRY_UNAVAILABLE")
        self.crm.fail = {"list_liens": 503}
        self.refused("CRM_UNAVAILABLE")

    # ---------------------------------------------------------------- 6 labels
    def test_label_set_must_match_exactly(self):
        for labels in ({"stackvend-managed": "true", "stackvend-product-id": "prod-app"},
                       {"stackvend-managed": "false", "stackvend-product-id": "sb-ok"},
                       {"stackvend-product-id": "sb-ok"},
                       {"stackvend-managed": "TRUE", "stackvend-product-id": "sb-ok"}):
            self.crm.projects["123456789"]["labels"] = labels
            self.refused("NOT_STACKVEND_OWNED")
        self.crm.projects["123456789"]["labels"] = {"stackvend-managed": "true", "stackvend-product-id": "sb-ok",
                                                    "stackvend-workload-type": "standard"}
        self.refused("SANDBOX_NOT_ELIGIBLE")

    # ---------------------------------------------------------------- 7 ancestry
    def test_project_outside_managed_root_refuses(self):
        self.crm.ancestry["sv-sb-ok-1a2b"] = [{"resourceId": {"type": "project", "id": "sv-sb-ok-1a2b"}},
                                              {"resourceId": {"type": "folder", "id": "333"}},
                                              {"resourceId": {"type": "organization", "id": "1"}}]
        self.refused("NOT_IN_MANAGED_FOLDER")

    def test_root_matching_only_as_the_project_itself_refuses(self):
        self.crm.ancestry["sv-sb-ok-1a2b"] = [{"resourceId": {"type": "folder", "id": ROOT_FOLDER}}]
        self.refused("ANCESTRY_UNAVAILABLE")

    # ---------------------------------------------------------------- 8 liens
    def test_any_lien_refuses_and_is_never_removed(self):
        self.crm.liens = {"123456789": [{"name": "liens/abc"}]}
        self.refused("LIEN_PRESENT")

    # ---------------------------------------------------------------- 9b eligibility
    def test_keyword_derived_or_missing_designation_refuses(self):
        for src in ("KEYWORD_DETECTED", None, "api_field", ""):
            self.ledger(sandbox_designation_source=src)
            self.refused("SANDBOX_NOT_ELIGIBLE")
        self.assertEqual(self.crm.calls, [])  # refused before any CRM call

    def test_not_expired_not_auto_or_in_flight_refuses(self):
        for fields in ({"sandbox_expires_at": FUTURE}, {"sandbox_expires_at": None}, {"sandbox_expires_at": "soon"},
                       {"sandbox_auto_decommission": False}, {"sandbox_auto_decommission": "true"},
                       {"is_sandbox": "yes"}, {"status": "PROVISIONING"}, {"status": "DECOMMISSIONED"}):
            self.db.store[("workloads", "sb-ok")] = {**self.db.store[("workloads", "sb-ok")], "sandbox_expires_at": PAST,
                                                     "sandbox_auto_decommission": True, "is_sandbox": True,
                                                     "status": "ACTIVE", **fields}
            self.refused("SANDBOX_NOT_ELIGIBLE")


class TestRestCRMNeverRetries(unittest.TestCase):
    def test_429_is_one_call_and_unavailable(self):
        g = _load_guard()

        class Resp:
            status_code = 429

            def json(self):
                return {}

        class Session:
            def __init__(self):
                self.n = 0

            def get(self, *a, **k):
                self.n += 1
                return Resp()

        s = Session()
        with self.assertRaises(g.CRMUnavailable) as ctx:
            g.RestCRM(session=s).get_project("123")
        self.assertEqual((s.n, ctx.exception.status), (1, 429))


# ================================================================================================ endpoint harness
# Lane 18 S2 (single window): the sweep no longer runs this module's interim guard or deletes anything itself. It
# calls project-vending POST /projects/{id}/decommission {action_class: SANDBOX_TTL} once per expired workload and
# reports vending's refusals. Vending's guard is tested in tests/test_destructive_guard_*.py; here the vending answer is
# a fake and the CC must make ZERO Resource Manager calls (any construction of the interim CRM adapter fails the run).
class FakeVendingResponse:
    def __init__(self, status_code, body):
        self.status_code, self._body = status_code, body
        self.text = json.dumps(body)

    def json(self):
        return self._body


class FakeVending:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self.body = body if body is not None else {
            "status": "DECOMMISSIONED", "deleted_project_id": "sv-sb-ok-1a2b", "deleted_project_number": "123456789",
            "crm_operation": "operations/delete-123456789", "action_class": "SANDBOX_TTL", "warnings": []}
        self.calls = []

    def __call__(self, method, path, json_body=None, timeout=60.0, request=None):
        self.calls.append([method, path, json_body])
        return FakeVendingResponse(self.status_code, self.body)


class UnconfiguredVending(FakeVending):
    """make_vending_request answers None when VENDING_SERVICE_URL is unset (fail closed)."""

    def __call__(self, method, path, json_body=None, timeout=60.0, request=None):
        self.calls.append([method, path, json_body])
        return None


def _harness():  # noqa: C901
    marker = "# ================================================================ public mode"
    src_path = os.path.join(HERE, "cc_identity_harness.py")
    with open(src_path, encoding="utf-8") as f:
        src = f.read()
    assert marker in src, "FD-4E harness prefix changed"
    ns = {"__file__": src_path, "__name__": "cc_sandbox_guard_harness"}
    exec(compile(src.split(marker, 1)[0], src_path, "exec"), ns)
    from unittest.mock import MagicMock
    for k, v in ENV.items():
        if v:
            os.environ[k] = v
        else:
            os.environ.pop(k, None)
    import routes.workloads as wl
    import sandbox_guard as g

    crm_constructed = []

    class ForbiddenCRM:
        def __init__(self, *a, **k):
            crm_constructed.append("RestCRM")
            raise AssertionError("the Control Center must not call Resource Manager (lane 18 S2)")

    out = {}

    def run(vending, **ledger):
        db = FakeDB()
        seed_world(db, g, **ledger)
        cancel = MagicMock(return_value=0)
        with patch.object(wl, "db", db), patch.object(wl, "make_vending_request", vending), \
                patch.object(g, "RestCRM", ForbiddenCRM), patch.object(wl, "storage", None), \
                patch.object(wl, "cancel_workload_active_executions", cancel):
            res = wl.sweep_expired_sandboxes_endpoint(MagicMock())
        rec = db.store[("workloads", "sb-ok")]
        audits = [d.get("action") for p, d in db.store.items() if len(p) == 4 and p[2] == "audit_logs"]
        return {"decommissioned": res.decommissioned_workloads, "errors": res.errors, "vending_calls": vending.calls,
                "not_eligible": res.not_eligible_workloads, "refused_list": res.refused_workloads,
                "status": rec.get("status"), "decom_status": rec.get("sandbox_decommission_status"),
                "refusal": rec.get("sandbox_guard_refusal"), "audits": audits, "cancel_calls": cancel.call_count}

    out["legit"] = run(FakeVending())
    out["refused"] = run(FakeVending(409, {"detail": {"code": "SANDBOX_NOT_ELIGIBLE", "detail": "not explicit"}}),
                         sandbox_designation_source="KEYWORD_DETECTED")
    out["refused_explicit"] = run(FakeVending(409, {"detail": {"code": "SANDBOX_NOT_ELIGIBLE", "detail": "no provenance"}}))
    out["crm_429"] = run(FakeVending(503, {"detail": {"code": "CRM_UNAVAILABLE", "detail": "projects.get -> HTTP 429"}}))
    out["delete_fails"] = run(FakeVending(502, {"detail": {"code": "DECOMMISSION_FAILED", "detail": "HTTP 403"}}))
    out["unconfigured"] = run(UnconfiguredVending())
    out["not_expired"] = run(FakeVending(), sandbox_expires_at=(datetime.now(timezone.utc) + timedelta(days=3)).isoformat())
    out["crm_constructed"] = crm_constructed
    out["network_attempts"] = ns["NETWORK_ATTEMPTS"]
    print(json.dumps(out, default=str))


@pytest.fixture(scope="module")
def sweep():
    # hermetic_guard.child_env: Layer-0 env (ADC -> non-existent file, NO_GCE_CHECK, loopback proxy, guard shim)
    env = hermetic_guard.child_env(drop=("TEST_MODE", "K_SERVICE", "SESSION_SECRET", "ADMIN_EMAIL", "PLATFORM_PROJECT_ID"),
                                   extra={"PROJECT_ID": HOST, "GOOGLE_CLOUD_PROJECT": HOST})
    out = subprocess.run([sys.executable, os.path.abspath(__file__), "--harness"],
                         capture_output=True, text=True, timeout=300, env=env)
    assert out.returncode == 0, out.stderr[-4000:]
    return json.loads(out.stdout.strip().splitlines()[-1])


def test_sweep_hermetic_and_never_calls_resource_manager(sweep):
    assert sweep["network_attempts"] == []
    assert sweep["crm_constructed"] == []


def test_sweep_decommissions_a_legit_expired_sandbox_through_vending(sweep):
    r = sweep["legit"]
    assert r["decommissioned"] == ["sb-ok"], r
    assert r["vending_calls"] == [["POST", "/projects/sb-ok/decommission", {"action_class": "SANDBOX_TTL"}]], r
    assert r["decom_status"] == "DECOMMISSIONED" and "AUTO_SANDBOX_DECOMMISSION_EXPIRED" in r["audits"]
    assert r["cancel_calls"] == 1
    # the ledger status/spend/state archive are vending's writes; the CC does not fabricate them
    assert r["status"] == "ACTIVE"


def test_sweep_skips_a_sandbox_vending_never_ttl_deletes(sweep):
    """C10 (RT finding 4): a keyword-detected sandbox awaits confirmation; it is not sent to vending and nothing on
    the workload changes (it is listed as not eligible)."""
    r = sweep["refused"]
    assert r["decommissioned"] == [] and r["vending_calls"] == [] and r["errors"] == [], r
    assert (r["status"], r["decom_status"], r["refusal"]) == ("ACTIVE", None, None), r
    assert r["not_eligible"] == ["sb-ok"] and r["cancel_calls"] == 0


def test_sweep_reports_vending_refusal_without_any_change(sweep):
    """A typed vending refusal (409) is recorded for the dashboard and listed as refused, not as an error."""
    r = sweep["refused_explicit"]
    assert r["decommissioned"] == [] and len(r["vending_calls"]) == 1, r
    assert (r["status"], r["decom_status"], r["refusal"]) == ("ACTIVE", "GUARD_REFUSED", "SANDBOX_NOT_ELIGIBLE"), r
    assert r["errors"] == [] and r["refused_list"] == ["sb-ok (SANDBOX_NOT_ELIGIBLE)"]
    assert "SANDBOX_TTL_DELETE_REFUSED" in r["audits"] and r["cancel_calls"] == 0


def test_sweep_reports_crm_unavailable(sweep):
    r = sweep["crm_429"]
    assert r["decommissioned"] == [] and r["status"] == "ACTIVE", r
    assert r["refusal"] == "CRM_UNAVAILABLE" and any("CRM_UNAVAILABLE" in e for e in r["errors"])
    assert len(r["vending_calls"]) == 1  # no retry loop


def test_failed_delete_does_not_mark_decommissioned(sweep):
    r = sweep["delete_fails"]
    assert (r["decommissioned"], r["status"], r["decom_status"]) == ([], "ACTIVE", "DECOMMISSION_FAILED"), r


def test_sweep_with_vending_unconfigured_refuses(sweep):
    r = sweep["unconfigured"]
    assert r["decommissioned"] == [] and r["refusal"] == "VENDING_UNCONFIGURED", r


def test_sweep_does_not_call_vending_before_expiry(sweep):
    r = sweep["not_expired"]
    assert r["vending_calls"] == [] and r["decommissioned"] == [], r


if __name__ == "__main__" and "--harness" in sys.argv:
    _harness()
