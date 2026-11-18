"""CLOUDSQL-CREATE-OWN-OPERATION (register row, awaiting owner; ex08-g13 2026-11-17): unit tests of
mcp-servers/terraform/cloudsql_create_recovery.py (pure functions over the plan, `state list` lines and the SQL Admin
API's typed fields) and the brownfield import rule for `google_sql_database_instance`. The deploy-level cases (wait,
adopt, retry, typed failure, Do No Harm) live in mcp-servers/terraform/test_service.py (`test_csql_*`).
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import copy
import importlib.util
import os
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO, "mcp-servers", "terraform")


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(TF_DIR, filename))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod   # dataclasses resolve annotations through sys.modules
    spec.loader.exec_module(mod)
    return mod


# the module under test does `import brownfield_adoption`; an already loaded copy (same file) is reused, never replaced
ba = sys.modules.get("brownfield_adoption") or _load("brownfield_adoption", "brownfield_adoption.py")
csql = _load("cloudsql_create_recovery_test", "cloudsql_create_recovery.py")

P, R = "child-p", "us-central1"
ADDR = "module.postgres.google_sql_database_instance.instance"
NAME = "child-p-postgres"
T0 = 1_800_000_000.0   # the deploy's first apply (epoch seconds)


def change(address=ADDR, rtype="google_sql_database_instance", actions=("create",), unknown=None, **after):
    a = {"name": NAME, "project": P, "region": R}
    a.update(after)
    return {"address": address, "mode": "managed", "type": rtype,
            "change": {"actions": list(actions), "after": a, "after_unknown": dict(unknown or {})}}


def plan(*changes):
    return {"format_version": "1.2", "configuration": {"root_module": {}, "provider_config": {}},
            "variables": {"project_id": {"value": P}, "region": {"value": R}}, "resource_changes": list(changes)}


def op(insert, status="DONE", op_type="CREATE", target=NAME, name="op-1", codes=None, project=P):
    o = {"name": name, "operationType": op_type, "status": status, "targetId": target, "targetProject": project,
         "insertTime": insert}
    if codes is not None:
        o["error"] = {"errors": [{"code": c} for c in codes]}
    return o


def iso(epoch):
    import datetime as dt
    return dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# --- the import rule ---
def test_import_rule_for_cloudsql_instance_is_project_scoped_and_exact():
    resolved, why = ba.resolve_import(change(), P, R, plan(change()))
    assert why == "" and resolved.import_id == f"projects/{P}/instances/{NAME}" and resolved.address == ADDR
    assert resolved.exists_url is None   # never pre-imported (not a Pass 0 type)
    assert "google_sql_database_instance" not in ba.PRE_APPLY_TYPES
    assert ba.resolve_import(change(project="host-p"), P, R)[0] is None
    assert ba.resolve_import(change(unknown={"name": True}), P, R)[0] is None


# --- instance_creates ---
def test_instance_creates_takes_only_exact_creates_of_the_type_in_the_workload_project():
    p = plan(change(),
             change(address="module.other.google_sql_database_instance.instance", project="host-p"),
             change(address="module.u.google_sql_database_instance.instance", actions=("update",)),
             change(address="module.r.google_sql_database_instance.instance", actions=("delete", "create")),
             change(address="module.k.google_sql_database_instance.instance", unknown={"name": True}),
             change(address="google_pubsub_topic.t", rtype="google_pubsub_topic", name="t"))
    snap = copy.deepcopy(p)
    got = csql.instance_creates(p, P, R)
    assert [(r.address, r.import_id, n, a["name"]) for r, n, a in got] == [
        (ADDR, f"projects/{P}/instances/{NAME}", NAME, NAME)]
    assert p == snap   # pure
    assert csql.instance_creates(None, P, R) == [] and csql.instance_creates(p, "", R) == []


# --- state_addresses ---
def test_state_addresses_compares_whole_lines_only():
    s = csql.state_addresses(f"module.foundation.google_service_account.sa\n{ADDR}_2\n  \n")
    assert ADDR not in s and f"{ADDR}_2" in s
    assert ADDR in csql.state_addresses(f"{ADDR}\n")
    assert csql.state_addresses(None) == frozenset()


# --- parse_time / own_create_operation ---
@pytest.mark.parametrize("value,expected", [
    ("2026-11-17T00:04:16.884Z", 1794873856.884), ("2026-11-17T00:04:16Z", 1794873856.0),
    ("2026-11-17T00:04:16+00:00", 1794873856.0), ("2026-11-17T00:04:16", None), ("", None), (None, None),
    ("yesterday", None), (17, None)])
def test_parse_time(value, expected):
    got = csql.parse_time(value)
    assert (got is None and expected is None) or abs(got - expected) < 1e-3


def test_own_create_operation_is_the_newest_create_of_the_instance_inserted_by_this_deploy():
    ops = {"items": [
        op(iso(T0 - 3600), name="older"),                       # an earlier deploy's create
        op(iso(T0 + 60), name="mine-1"),
        op(iso(T0 + 120), name="mine-2"),
        op(iso(T0 + 300), op_type="UPDATE", name="update"),     # not a create
        op(iso(T0 + 400), target=NAME + "-2", name="other"),     # another instance
        op(iso(T0 + 500), project="host-p", name="other-project"),   # RT F9: another project
        op("not-a-time", name="bad-time"),
        "junk",
    ]}
    assert csql.own_create_operation(ops, P, NAME, T0)["name"] == "mine-2"
    assert csql.own_create_operation({"items": [op(iso(T0 - 1))]}, P, NAME, T0) is None
    assert csql.own_create_operation({"items": [op(iso(T0))]}, P, NAME, T0)["name"] == "op-1"   # inclusive
    for empty in ({}, {"items": None}, None, [], {"items": "x"}):
        assert csql.own_create_operation(empty, P, NAME, T0) is None


# --- error_codes / decide ---
def test_error_codes():
    assert csql.error_codes(op("x", codes=["INTERNAL_ERROR", "QUOTA"])) == ["INTERNAL_ERROR", "QUOTA"]
    assert csql.error_codes({"error": {"errors": [{"message": ""}]}}) == [""]   # an entry without a code still counts
    assert csql.error_codes(op("x")) == [] and csql.error_codes(None) == [] and csql.error_codes({"error": {}}) == []


@pytest.mark.parametrize("o,inst,outcome", [
    (op("x"), {"state": "RUNNABLE"}, csql.ADOPT),
    (op("x", status="RUNNING"), {"state": "RUNNABLE"}, csql.OP_NOT_DONE),
    (op("x", status="PENDING"), None, csql.OP_NOT_DONE),
    (op("x", codes=["INTERNAL_ERROR"]), {"state": "RUNNABLE"}, csql.OP_FAILED),   # DONE with an error: never adopted
    (op("x", codes=[]), {"state": "RUNNABLE"}, csql.ADOPT),                     # an empty error list is no error
    (op("x"), {"state": "PENDING_CREATE"}, csql.NOT_RUNNABLE),
    (op("x"), {"state": "FAILED"}, csql.NOT_RUNNABLE),
    (op("x"), None, csql.NOT_RUNNABLE),
    (None, {"state": "RUNNABLE"}, csql.UNREADABLE),
])
def test_decide(o, inst, outcome):
    assert csql.decide(o, inst)[0] == outcome


@pytest.mark.parametrize("after,instance,users,refused", [
    ({}, {"state": "RUNNABLE"}, {"items": [{"name": "postgres", "host": ""}]}, None),
    ({}, {"state": "RUNNABLE"}, {}, None),                                              # no users at all
    ({"restore_backup_context": []}, {"state": "RUNNABLE"}, {"items": []}, None),       # empty block = no restore
    ({"restore_backup_context": [{"instance_id": "x"}]}, {"state": "RUNNABLE"}, {}, "restore_backup_context"),
    ({}, {"state": "PENDING_CREATE"}, {}, "PENDING_CREATE, not RUNNABLE"),
    ({}, {"state": "FAILED"}, {}, "FAILED, not RUNNABLE"),
    ({}, None, {}, "could not be read"),
    ({}, {"state": "RUNNABLE"}, None, "users could not be read"),
    ({}, {"state": "RUNNABLE"}, {"items": "x"}, "users could not be read"),
    ({}, {"state": "RUNNABLE"}, {"items": [{"name": "root", "host": "%"}]}, "removal of that default user"),
    ({}, {"state": "RUNNABLE"}, {"items": [{"name": "root", "host": "10.0.0.1"}]}, None),   # not any host
    ({}, {"state": "RUNNABLE"}, {"items": [{"name": "rooty", "host": "%"}]}, None),
])
def test_adoption_refusal(after, instance, users, refused):
    got = csql.adoption_refusal(after, instance, users)
    assert (got is None) if refused is None else (refused in got)


def test_planned_after():
    p = plan(change(), change(address="module.u.google_sql_database_instance.instance", actions=("update",)))
    assert csql.planned_after(p, ADDR)["name"] == NAME
    assert csql.planned_after(p, "module.u.google_sql_database_instance.instance") == {}
    assert csql.planned_after(None, ADDR) == {}


def test_wait_polls_is_bounded_and_keeps_a_reserve_of_a_deploy_budget():
    assert csql.wait_polls(None) == int(csql.WAIT_S // csql.POLL_S)
    assert csql.wait_polls(csql.RETRY_RESERVE_S + 100) == int(100 // csql.POLL_S)
    assert csql.wait_polls(csql.RETRY_RESERVE_S) == 0 and csql.wait_polls(-5) == 0
    assert csql.wait_polls(10 ** 9) == int(csql.WAIT_S // csql.POLL_S)
    assert csql.wait_seconds(None) == csql.WAIT_S and csql.wait_seconds(csql.RETRY_RESERVE_S + 7) == 7
    assert csql.wait_seconds(-1) == 0.0


def test_record_and_summary_carry_typed_fields_only():
    rec = csql.record(ADDR, NAME, op("x", codes=["INTERNAL_ERROR"], name="op-9"), {"state": "FAILED"},
                      csql.OP_FAILED, "why")
    assert rec == {"address": ADDR, "instance": NAME, "operation": "op-9", "operation_status": "DONE",
                   "error_codes": ["INTERNAL_ERROR"], "instance_state": "FAILED", "outcome": csql.OP_FAILED,
                   "reason": "why"}
    assert csql.summary([rec]) == f"{ADDR} ({NAME}): {csql.OP_FAILED}: why"
    assert csql.summary([dict(rec, outcome=csql.IMPORTED, reason="")]) == f"{ADDR} ({NAME}): {csql.IMPORTED}"


def test_urls_quote_their_parts():
    assert csql.operations_url(P, NAME) == f"https://sqladmin.googleapis.com/v1/projects/{P}/operations?instance={NAME}"
    assert csql.operation_url(P, "a/b") == f"https://sqladmin.googleapis.com/v1/projects/{P}/operations/a%2Fb"
    assert csql.instance_url(P, "x?y") == f"https://sqladmin.googleapis.com/v1/projects/{P}/instances/x%3Fy"
    assert csql.users_url(P, NAME) == f"https://sqladmin.googleapis.com/v1/projects/{P}/instances/{NAME}/users"


# --- invariant 2: no engine / error text is read for a decision ---
def test_the_recovery_reads_no_engine_text():
    """The module never sees the apply's output: no function takes it, and no `message` field of an API answer is
    read (the operation's error message is empty in the ex08-g13 case anyway)."""
    tree = ast.parse(open(os.path.join(TF_DIR, "cloudsql_create_recovery.py"), encoding="utf-8").read())
    params = {a.arg for f in ast.walk(tree) if isinstance(f, ast.FunctionDef) for a in f.args.args}
    assert not params & {"apply_err", "apply_output", "stderr", "stdout", "text", "error_text"}
    consts = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    assert "message" not in consts
    svc = open(os.path.join(TF_DIR, "service.py"), encoding="utf-8").read()
    body = svc[svc.index("def _sqladmin_session"):svc.index("def _route_failed_deploy")]
    assert "apply_err" not in body and "apply_res" not in body
