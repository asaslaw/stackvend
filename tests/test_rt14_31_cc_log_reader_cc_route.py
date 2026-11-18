"""
RT14-31 / owner decision D4 (11-14): the Control Center's ADMIN route that asks vending to grant the CC
roles/logging.viewer on existing child projects (POST /api/settings/cc-log-reader/backfill). The CC never changes IAM;
vending executes it (tests/test_rt14_31_cc_log_reader.py). Hermetic: vending is a test double.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import pytest

from test_deletion_tag_banner import _Resp, ist, make_client  # noqa: F401  (fixture)

PATH = "/api/settings/cc-log-reader/backfill"
RESULT = {"role": "roles/logging.viewer", "member": "serviceAccount:cc@p.iam.gserviceaccount.com", "dry_run": False,
          "results": [{"product_id": "shop-api", "project_id": "shop-api-a1b2", "decision": "GRANTED"}],
          "counts": {"GRANTED": 1}, "truncated": False}


class Vending:
    def __init__(self, status=200, body=None):
        self.status, self.body, self.calls = status, body if body is not None else RESULT, []

    def __call__(self, method, path, json_body=None, timeout=60.0, request=None):
        self.calls.append((method, path, json_body))
        return _Resp(self.status, self.body)


def test_admin_runs_vendings_backfill_with_the_caller_recorded(make_client):
    v = Vending()
    r = make_client(v).post(PATH)
    assert r.status_code == 200 and r.json() == RESULT
    assert v.calls == [("POST", "/guard/cc-log-reader/backfill", {"operator_email": "u@example.com",
                                                                   "dry_run": False})]


def test_dry_run_is_passed_through(make_client):
    v = Vending()
    assert make_client(v).post(PATH, json={"dry_run": True}).status_code == 200
    assert v.calls[0][2]["dry_run"] is True


@pytest.mark.parametrize("role", ["VIEWER", "WORKLOAD_MANAGER", "APPROVER"])
def test_only_admins(make_client, role):
    v = Vending()
    assert make_client(v, role=role).post(PATH).status_code == 403
    assert v.calls == []


def test_a_vending_failure_is_typed_never_a_success(make_client):
    v = Vending(status=503, body={"detail": {"code": "VENDING.CC_LOG_READER_GRANT_FAILED", "detail": "no host"}})
    r = make_client(v).post(PATH)
    assert r.status_code == 502 and r.json()["vending_status"] == 503
