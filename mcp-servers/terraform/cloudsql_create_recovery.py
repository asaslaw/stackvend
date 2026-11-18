"""CLOUDSQL-CREATE-OWN-OPERATION (register row, awaiting owner; diagnosis docs/handoff/ex08-g13-cloudsql-internal-error-diagnosis.md):
the deploy's own Cloud SQL instance create, read back from the SQL Admin API after the provider stopped waiting for it.

Why: the google provider's Cloud SQL operation waiter (`SqlAdminOperationWaiter`, `IsRetryable` = false) fails the
resource as soon as ONE poll of the create operation carries an `error`, even while the operation is still RUNNING, and
then drops the instance from state (`d.SetId("")`). Cloud SQL can report a passing INTERNAL_ERROR on a create it then
finishes (ex08-g13, 2026-11-17: `Error waiting for Create Instance:` with an empty message, the instance left
PENDING_CREATE outside state). The apply fails, the instance keeps being created, and a re-run meets a 409.

What: after a failed apply, for each `google_sql_database_instance` the applied plan CREATES that is NOT in state, the
deploy reads the instance's operations (`operations.list?instance=`) and takes the CREATE operation of the workload
project (`targetProject`) whose `targetId` is that instance and whose `insertTime` is not before this deploy's first
apply (the create of THIS deploy, never an older instance). When at least one such create exists, every missing
instance is decided (a sibling without one is recorded, never skipped); the deploy waits (bounded by wall clock and by
the deploy's own budget) for each operation to be DONE, then:

- every instance with its own create ADOPT (DONE without `error`, instance RUNNABLE, `adoption_refusal` None) -> each
  is imported at the plan's address with the plan's exact import id (brownfield_adoption.resolve_import) and the apply
  runs once more (an instance whose readable operations hold no create of this deploy, NO_OWN_OPERATION, is left to
  that retry: it creates the instance or fails with the engine's error);
- anything else (DONE with an error, still running at the end of the wait, instance not RUNNABLE, a refused adoption,
  unreadable operations of a sibling) -> NOTHING is imported and the deploy fails typed
  CLOUDSQL_CREATE_UNRESOLVED (operator; nothing is deleted).

`adoption_refusal` (also the gate of the W7 409 adoption of an existing instance): never adopt an instance that is not
RUNNABLE, whose users cannot be read, that has a `root`@`%` user (MySQL: the provider deletes that default user right
after a successful create wait; when the wait failed it did not run, so a MySQL create transient always ends typed for
an operator, while a Postgres instance is adoptable), or whose planned create restores a backup
(`restore_backup_context`).

Typed fields only (AGENTS.md invariant 2): the plan's `resource_changes`, `state list` lines compared by equality, and
the SQL Admin API's `operationType`, `targetProject`, `targetId`, `insertTime`, `status`, `error.errors[].code`, the
instance's `state` and the users' `name` / `host`. No engine text is read. Pure functions; service.py does the I/O.
"""
from __future__ import annotations

import datetime as _dt
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple
from urllib.parse import quote

try:
    import brownfield_adoption as ba
except ImportError:  # pragma: no cover - loaded by path without its directory on sys.path
    import importlib.util as _ba_util
    import os as _ba_os
    import sys as _ba_sys

    _ba_spec = _ba_util.spec_from_file_location(
        "brownfield_adoption", _ba_os.path.join(_ba_os.path.dirname(_ba_os.path.abspath(__file__)),
                                                "brownfield_adoption.py"))
    ba = _ba_util.module_from_spec(_ba_spec)
    _ba_sys.modules["brownfield_adoption"] = ba
    _ba_spec.loader.exec_module(ba)

INSTANCE_TYPE = "google_sql_database_instance"
ERROR_CLOUDSQL_CREATE_UNRESOLVED = "CLOUDSQL_CREATE_UNRESOLVED"
STAGE = "apply_cloudsql_create"
SQLADMIN = "https://sqladmin.googleapis.com/v1"

# The wait for the deploy's own create operation: a db-f1-micro / small Postgres create takes ~5-12 min; 25 min covers
# a slow one. A deploy with an overall time budget (the sync /deploy) keeps RETRY_RESERVE_S of it for the retry apply.
WAIT_S = 1500.0
POLL_S = 20.0
RETRY_RESERVE_S = 300.0
GET_TIMEOUT_S = 15.0

ADOPT = "ADOPT"                    # decided adoptable (nothing imported yet)
IMPORTED = "IMPORTED"              # imported into state
OP_FAILED = "OPERATION_FAILED"
OP_NOT_DONE = "OPERATION_NOT_DONE"
NOT_RUNNABLE = "INSTANCE_NOT_RUNNABLE"
REFUSED = "ADOPTION_REFUSED"
UNREADABLE = "UNREADABLE"
NO_OWN_OPERATION = "NO_OWN_OPERATION"
IMPORT_FAILED = "IMPORT_FAILED"


def wait_seconds(deploy_time_left: Optional[float]) -> float:
    """The wall-clock wait the deploy may spend (shared by all its instances): WAIT_S, or what is left of a deploy's
    overall budget minus RETRY_RESERVE_S (0 when that is not positive)."""
    wait_s = WAIT_S
    if deploy_time_left is not None:
        wait_s = min(wait_s, deploy_time_left - RETRY_RESERVE_S)
    return max(0.0, wait_s)


def wait_polls(deploy_time_left: Optional[float]) -> int:
    """The most POLL_S polls that fit in `wait_seconds` (the loop also stops at the wall-clock deadline)."""
    return int(wait_seconds(deploy_time_left) // POLL_S)


def instance_creates(plan_json: Optional[Mapping[str, Any]], project_id: str,
                     region: str) -> List[Tuple[Any, str, Mapping[str, Any]]]:
    """[(brownfield_adoption.Resolved, instance name, planned `after`)] for each `google_sql_database_instance` the plan
    creates with an exact import id in the workload project (resolve_import's rules: a known name, the workload
    project). A create whose id the plan cannot name exactly is left out (its failure stays as it was)."""
    out: List[Tuple[Any, str, Mapping[str, Any]]] = []
    for _address, rc in ba.planned_creates(plan_json).items():
        if rc.get("type") != INSTANCE_TYPE:
            continue
        resolved, _why = ba.resolve_import(rc, project_id, region, plan_json)
        if resolved is None:
            continue
        after = rc["change"]["after"]   # resolve_import checked: `name` is a known, non-empty string
        out.append((resolved, after["name"], after))
    return out


def planned_after(plan_json: Optional[Mapping[str, Any]], address: str) -> Mapping[str, Any]:
    """The planned `after` of the plan's create at `address` ({} when there is none)."""
    rc = ba.planned_creates(plan_json).get(address)
    change = rc.get("change") if isinstance(rc, Mapping) and isinstance(rc.get("change"), Mapping) else {}
    after = change.get("after")
    return after if isinstance(after, Mapping) else {}


def state_addresses(state_list_stdout: Any) -> frozenset:
    """The addresses `state list` printed (one per line, compared by equality)."""
    if not isinstance(state_list_stdout, str):
        return frozenset()
    return frozenset(line.strip() for line in state_list_stdout.splitlines() if line.strip())


def operations_url(project: str, instance: str) -> str:
    """`operations.list` of one instance (newest first; the deploy takes the newest of its own CREATEs anyway)."""
    return f"{SQLADMIN}/projects/{quote(project, safe='')}/operations?instance={quote(instance, safe='')}"


def operation_url(project: str, operation: str) -> str:
    return f"{SQLADMIN}/projects/{quote(project, safe='')}/operations/{quote(operation, safe='')}"


def instance_url(project: str, name: str) -> str:
    return f"{SQLADMIN}/projects/{quote(project, safe='')}/instances/{quote(name, safe='')}"


def users_url(project: str, name: str) -> str:
    return f"{instance_url(project, name)}/users"


def parse_time(value: Any) -> Optional[float]:
    """Epoch seconds of an RFC 3339 timestamp (`2026-11-17T00:04:16.884Z`); None when it is not one."""
    if not isinstance(value, str) or not value:
        return None
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = _dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.timestamp()


def own_create_operation(operations_json: Any, project: str, instance: str,
                         not_before: float) -> Optional[Dict[str, Any]]:
    """The newest CREATE operation of `instance` in `project` (`targetProject`) inserted at or after `not_before`
    (epoch seconds); None when there is none (the create was refused, or the instance is older than this deploy)."""
    items = operations_json.get("items") if isinstance(operations_json, Mapping) else None
    best: Optional[Dict[str, Any]] = None
    best_t = None
    for op in items if isinstance(items, list) else []:
        if not isinstance(op, dict):
            continue
        if (op.get("operationType") != "CREATE" or op.get("targetId") != instance
                or op.get("targetProject") != project):
            continue
        t = parse_time(op.get("insertTime"))
        if t is None or t < not_before:
            continue
        if best_t is None or t > best_t:
            best, best_t = op, t
    return best


def error_codes(op: Any) -> List[str]:
    """The operation's `error.errors[].code` values (an error entry without a code counts as "")."""
    err = op.get("error") if isinstance(op, Mapping) else None
    errors = err.get("errors") if isinstance(err, Mapping) else None
    if not isinstance(errors, list):
        return []
    return [e.get("code") if isinstance(e.get("code"), str) else "" for e in errors if isinstance(e, Mapping)]


def decide(op: Any, instance: Any) -> Tuple[str, str]:
    """(outcome, reason) for the deploy's own create operation after the wait, from typed fields only."""
    if not isinstance(op, Mapping):
        return UNREADABLE, "the create operation could not be read"
    status = op.get("status")
    if status != "DONE":
        return OP_NOT_DONE, f"the create operation is still {status} after the wait"
    codes = error_codes(op)
    if codes:
        return OP_FAILED, f"the create operation ended with error code(s) {codes}"
    state = instance.get("state") if isinstance(instance, Mapping) else None
    if state != "RUNNABLE":
        return NOT_RUNNABLE, f"the create operation is DONE but the instance is {state or 'unreadable'}"
    return ADOPT, ""


def adoption_refusal(after: Any, instance: Any, users: Any) -> Optional[str]:
    """Why an existing instance must NOT be imported at the plan's address (None = it may be). Typed fields only: the
    planned `restore_backup_context`, the instance's `state`, the users' `name` / `host`."""
    restore = after.get("restore_backup_context") if isinstance(after, Mapping) else None
    if restore:
        return "the planned create restores a backup (`restore_backup_context`); such an instance is never adopted"
    if not isinstance(instance, Mapping):
        return "the instance could not be read"
    state = instance.get("state")
    if state != "RUNNABLE":
        return f"the instance is {state or 'in an unknown state'}, not RUNNABLE"
    if not isinstance(users, Mapping):
        return "the instance's users could not be read"
    items = users.get("items", [])
    if not isinstance(items, list):
        return "the instance's users could not be read"
    for user in items:
        if isinstance(user, Mapping) and user.get("name") == "root" and user.get("host") == "%":
            return ("the instance has a `root`@`%` user: the provider's removal of that default user after the create "
                    "did not run (MySQL); an operator removes the user (or the instance) before it can be adopted")
    return None


def record(address: str, name: str, op: Any, instance: Any, outcome: str, reason: str) -> Dict[str, Any]:
    """One `cloudsql_create` entry of the deploy result (typed fields of the API answers, no free text from them)."""
    return {
        "address": address,
        "instance": name,
        "operation": op.get("name") if isinstance(op, Mapping) else None,
        "operation_status": op.get("status") if isinstance(op, Mapping) else None,
        "error_codes": error_codes(op),
        "instance_state": instance.get("state") if isinstance(instance, Mapping) else None,
        "outcome": outcome,
        "reason": reason,
    }


def summary(records: Iterable[Mapping[str, Any]]) -> str:
    return "; ".join(f"{r.get('address')} ({r.get('instance')}): {r.get('outcome')}"
                     + (f": {r.get('reason')}" if r.get("reason") else "") for r in records)
