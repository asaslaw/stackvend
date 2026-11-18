"""SAT-43: Cloud Workflows executions through the Workflows Executions REST API (v1), with typed outcomes.

`google-cloud-workflows` is not in the Control Center image (requirements.txt), so the client library is never used:
before SAT-43 the Emergency Stop, the run Abort button, the decommission cascade and the stale-run reconcile imported
it lazily, the import failed in the deployed image, a warning was logged and no workflow execution was cancelled.
Here every call goes to https://workflowexecutions.googleapis.com/v1 with the Control Center's own credentials
(google-auth `AuthorizedSession`, already in the image) and every failure is reported with a typed reason
(AGENTS.md invariant 8): nothing here returns "cancelled" for an execution that was not cancelled.

Permissions: the Control Center runtime SA (sa-stackvend-control-center) holds roles/workflows.invoker on the host
project (infra/platform/destructive_guard.tf cc_project_roles), which includes workflows.executions.list / .get /
.cancel. A 403 is still reported as WORKFLOW_CANCEL_NOT_PERMITTED (e.g. an install whose platform apply predates
that grant, or the Workflows API disabled).
"""

from __future__ import annotations

import logging
import urllib.parse
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

WORKFLOW_EXECUTIONS_API = "https://workflowexecutions.googleapis.com/v1"
# infra/modules/workflows/main.tf (deployed in the host project, region = var.region, the Control Center's region).
PLATFORM_WORKFLOWS = ("castor-main-orchestrator", "castor-sre-remediation")
MAIN_WORKFLOW = PLATFORM_WORKFLOWS[0]  # the only workflow that creates pipeline_executions records (gateway dispatch)
# The API refuses an unquoted value ("invalid value ACTIVE, value must be a string in quotation marks", HTTP 400;
# checked read-only against the dev install on 2026-11-02).
ACTIVE_FILTER = 'state="ACTIVE"'
PAGE_SIZE = 100
MAX_PAGES = 20  # 2,000 active executions; more is reported as a list failure, never silently truncated
TIMEOUT_SECONDS = 15.0
TERMINAL_STATES = ("SUCCEEDED", "FAILED", "CANCELLED")

# Overall / per-item typed reasons.
OK = "OK"
NOT_PERMITTED = "WORKFLOW_CANCEL_NOT_PERMITTED"
UNCONFIGURED = "WORKFLOW_CANCEL_UNCONFIGURED"
LIST_FAILED = "WORKFLOW_LIST_FAILED"
CANCEL_FAILED = "WORKFLOW_CANCEL_FAILED"
BAD_EXECUTION_NAME = "WORKFLOW_EXECUTION_NAME_INVALID"
STATE_READ_FAILED = "WORKFLOW_STATE_READ_FAILED"

# Per-execution outcomes.
CANCELLED = "CANCELLED"
ALREADY_FINISHED = "ALREADY_FINISHED"  # the execution had already ended (listed, cancel answer or a fresh read)
FAILED = "FAILED"

# Test seams (production leaves them None): a requests-like session (get/post returning .status_code / .json()) and
# the region.
session_provider: Optional[Callable[[], Any]] = None
region_provider: Optional[Callable[[], str]] = None


class WorkflowExecutionsError(Exception):
    """A Workflows Executions call that did not succeed; `code` is one of the typed reasons above."""

    def __init__(self, code: str, detail: str, http_status: Optional[int] = None,
                 partial: Optional[List[Dict[str, Any]]] = None):
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.http_status = http_status
        self.partial = partial or []  # a list call that stopped part-way: what it had listed so far


def _session():
    if session_provider is not None:
        return session_provider()
    try:
        import google.auth
        from google.auth.transport.requests import AuthorizedSession
        credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        return AuthorizedSession(credentials)
    except Exception as e:  # noqa: BLE001 - typed below
        raise WorkflowExecutionsError(UNCONFIGURED, f"no Google credentials ({type(e).__name__}: {e})") from e


def _region() -> str:
    if region_provider is not None:
        return (region_provider() or "").strip()
    # REGION env, else this instance's region from the metadata server (the Control Center has no REGION env today).
    from routes import platform_release as pr
    return (pr._region() or "").strip()


def _json(resp) -> Dict[str, Any]:
    try:
        body = resp.json()
    except ValueError:
        return {}
    return body if isinstance(body, dict) else {}


def _http_error(other_code: str, what: str, resp) -> WorkflowExecutionsError:
    status = resp.status_code
    err = _json(resp).get("error")
    err = err if isinstance(err, dict) else {}
    api_status = str(err.get("status") or "")
    message = str(err.get("message") or "")[:300]
    code = NOT_PERMITTED if status == 403 else other_code
    return WorkflowExecutionsError(code, f"{what}: HTTP {status} {api_status} {message}".strip(), status)


def _q(segment: str) -> str:
    return urllib.parse.quote(segment, safe="")


def _segments(name: Any) -> List[str]:
    return name.split("/") if isinstance(name, str) else []


def _is_execution_name(name: Any) -> bool:
    parts = _segments(name)
    return (len(parts) == 8 and parts[0] == "projects" and parts[2] == "locations" and parts[4] == "workflows"
            and parts[6] == "executions" and all(parts))


def _execution_path(name: str) -> str:
    """projects/P/locations/L/workflows/W/executions/E, each segment URL-quoted; anything else is refused."""
    if not _is_execution_name(name):
        raise WorkflowExecutionsError(BAD_EXECUTION_NAME, f"not a workflow execution name: {name!r}")
    return "/".join(_q(p) for p in _segments(name))


def workflow_of(name: str) -> str:
    parts = _segments(name)
    return parts[5] if len(parts) == 8 else ""


def execution_name_of(record: Dict[str, Any], project: str, region: Optional[str] = None) -> Optional[str]:
    """The full execution name of a pipeline_executions record; None when no execution is bound to it.

    The gateway stores the execution id (`workflow_execution_id`, the last segment of the name, also what the
    workflow's own callbacks write) and, since SAT-43, the full name (`workflow_execution_name`). Records written
    before SAT-43 hold only the id: their name is built for castor-main-orchestrator (the only workflow that creates
    pipeline_executions records) in this project and region. A stored name whose last segment is not the stored id is
    not used (the id is the one the running workflow reported). Raises WorkflowExecutionsError
    (WORKFLOW_EXECUTION_NAME_INVALID, or WORKFLOW_CANCEL_UNCONFIGURED when the name must be built and the project or
    region is unknown)."""
    name = record.get("workflow_execution_name")
    eid = record.get("workflow_execution_id")
    if not name and not eid:
        return None
    if _is_execution_name(name) and (not eid or _segments(name)[-1] == eid):
        return name
    if _is_execution_name(eid):
        return eid
    if isinstance(eid, str) and eid and "/" not in eid:
        project = (project or "").strip()
        region = (region if region is not None else _region()).strip()
        if not project or not region:
            raise WorkflowExecutionsError(UNCONFIGURED, f"cannot build the execution name of {eid!r}: the Control "
                                                        "Center's project id or region is unknown")
        return f"projects/{project}/locations/{region}/workflows/{MAIN_WORKFLOW}/executions/{eid}"
    raise WorkflowExecutionsError(BAD_EXECUTION_NAME, f"no usable workflow execution on the record (name {name!r}, "
                                                      f"id {eid!r})")


def list_active_executions(session, project: str, region: str, workflow: str) -> List[Dict[str, Any]]:
    """Every execution the API lists for the ACTIVE filter (all pages): [{name, workflow, state}]. The caller treats an
    entry whose served state is not ACTIVE as already finished. Raises WorkflowExecutionsError (LIST_FAILED /
    NOT_PERMITTED); past MAX_PAGES the error carries what was listed (`partial`) so the caller can still cancel it."""
    base = (f"{WORKFLOW_EXECUTIONS_API}/projects/{_q(project)}/locations/{_q(region)}/workflows/{_q(workflow)}"
            f"/executions?pageSize={PAGE_SIZE}&filter={_q(ACTIVE_FILTER)}")
    found: List[Dict[str, Any]] = []
    token = ""
    for _ in range(MAX_PAGES):
        url = base + (f"&pageToken={_q(token)}" if token else "")
        try:
            resp = session.get(url, timeout=TIMEOUT_SECONDS)
        except Exception as e:  # noqa: BLE001 - transport failure, typed
            raise WorkflowExecutionsError(LIST_FAILED, f"list {workflow}: {type(e).__name__}: {e}", partial=found) from e
        if resp.status_code != 200:
            err = _http_error(LIST_FAILED, f"list {workflow}", resp)
            err.partial = found
            raise err
        body = _json(resp)
        executions = body.get("executions", [])
        if not isinstance(executions, list):
            raise WorkflowExecutionsError(LIST_FAILED, f"list {workflow}: unexpected answer (executions is not a list)",
                                          partial=found)
        for ex in executions:
            name = ex.get("name") if isinstance(ex, dict) else None
            if not isinstance(name, str) or not name:
                raise WorkflowExecutionsError(LIST_FAILED, f"list {workflow}: an execution has no name", partial=found)
            found.append({"name": name, "workflow": workflow, "state": str(ex.get("state") or "ACTIVE").upper()})
        token = body.get("nextPageToken") or ""
        if not token:
            return found
    raise WorkflowExecutionsError(LIST_FAILED, f"list {workflow}: more than {PAGE_SIZE * MAX_PAGES} active executions "
                                               f"(only the first {len(found)} were listed)", partial=found)


def get_execution_state(name: str, session=None) -> str:
    """The execution's state (ACTIVE, SUCCEEDED, FAILED, CANCELLED, ...). Raises WorkflowExecutionsError."""
    path = _execution_path(name)
    session = session if session is not None else _session()
    try:
        resp = session.get(f"{WORKFLOW_EXECUTIONS_API}/{path}", timeout=TIMEOUT_SECONDS)
    except Exception as e:  # noqa: BLE001
        raise WorkflowExecutionsError(STATE_READ_FAILED, f"get {name}: {type(e).__name__}: {e}") from e
    if resp.status_code != 200:
        raise _http_error(STATE_READ_FAILED, f"get {name}", resp)
    state = _json(resp).get("state")
    if not isinstance(state, str) or not state:
        raise WorkflowExecutionsError(STATE_READ_FAILED, f"get {name}: the answer has no state")
    return state.upper()


def _result(name: Any) -> Dict[str, Any]:
    return {"name": name, "workflow": workflow_of(name), "outcome": FAILED, "reason": None, "detail": None,
            "state": None}


def cancel_execution(name: str, session=None) -> Dict[str, Any]:
    """Cancels one execution. Never raises; returns {name, workflow, outcome, reason, detail, state}:
    outcome CANCELLED (the API answered the execution CANCELLED); ALREADY_FINISHED (it had already SUCCEEDED or
    FAILED, per the cancel answer or a fresh read after a refused cancel: nothing left to stop); FAILED with reason
    WORKFLOW_CANCEL_NOT_PERMITTED / WORKFLOW_CANCEL_FAILED / WORKFLOW_CANCEL_UNCONFIGURED /
    WORKFLOW_EXECUTION_NAME_INVALID."""
    result = _result(name)
    try:
        return _cancel_execution(name, session, result)
    except Exception as e:  # noqa: BLE001 - never crash the caller (an engage already written); typed instead
        logger.error(f"Unexpected error cancelling workflow execution {name!r}: {type(e).__name__}: {e}")
        result.update(outcome=FAILED, reason=CANCEL_FAILED, detail=f"unexpected: {type(e).__name__}: {e}"[:500])
        return result


def _cancel_execution(name: str, session, result: Dict[str, Any]) -> Dict[str, Any]:
    try:
        path = _execution_path(name)
        session = session if session is not None else _session()
    except WorkflowExecutionsError as e:
        result.update(reason=e.code, detail=e.detail)
        return result
    try:
        resp = session.post(f"{WORKFLOW_EXECUTIONS_API}/{path}:cancel", json={}, timeout=TIMEOUT_SECONDS)
    except Exception as e:  # noqa: BLE001
        result.update(reason=CANCEL_FAILED, detail=f"cancel {name}: {type(e).__name__}: {e}")
        return result
    if resp.status_code == 200:
        state = _json(resp).get("state")
        state = state.upper() if isinstance(state, str) and state else None
        result["state"] = state
        if state == "CANCELLED":
            result["outcome"] = CANCELLED
        elif state in TERMINAL_STATES:
            result.update(outcome=ALREADY_FINISHED, detail=f"cancel {name}: the execution had already {state}")
        else:
            result.update(reason=CANCEL_FAILED,
                          detail=f"cancel {name}: HTTP 200 but the execution is {state or 'in an unknown state'}")
        return result
    err = _http_error(CANCEL_FAILED, f"cancel {name}", resp)
    if err.code == NOT_PERMITTED:
        result.update(reason=err.code, detail=err.detail)
        return result
    # Refused for another reason: an execution that ended between the list and the cancel is not a failure.
    try:
        state = get_execution_state(name, session=session)
    except WorkflowExecutionsError as read_err:
        result.update(reason=CANCEL_FAILED, detail=f"{err.detail}; state unknown ({read_err.detail})")
        return result
    if state in TERMINAL_STATES:
        result.update(outcome=ALREADY_FINISHED, state=state, detail=err.detail)
    else:
        result.update(reason=CANCEL_FAILED, state=state, detail=err.detail)
    return result


def cancel_bound_execution(record: Dict[str, Any], project: str) -> Optional[Dict[str, Any]]:
    """Cancels the execution bound to a pipeline_executions record (execution_name_of). None when none is bound;
    otherwise a cancel_execution result. Never raises."""
    try:
        name = execution_name_of(record, project)
    except WorkflowExecutionsError as e:
        result = _result(record.get("workflow_execution_name") or record.get("workflow_execution_id"))
        result.update(reason=e.code, detail=e.detail)
        return result
    except Exception as e:  # noqa: BLE001
        result = _result(record.get("workflow_execution_name") or record.get("workflow_execution_id"))
        result.update(reason=CANCEL_FAILED, detail=f"unexpected: {type(e).__name__}: {e}"[:500])
        return result
    if name is None:
        return None
    return cancel_execution(name)


def cancel_active_platform_workflows(project: str) -> Dict[str, Any]:
    """Lists the ACTIVE executions of every platform workflow and cancels each one, then lists once more and cancels
    any execution that started meanwhile (a dispatch that passed the kill-switch check just before engage). Never
    raises; returns {status, detail, cancelled, already_finished, failed, executions: [cancel results + "pass"],
    list_failures: [{workflow, reason, detail, pass}]}.
    status is OK only when every workflow was listed and every listed execution was cancelled (or had already
    finished); otherwise the first of WORKFLOW_CANCEL_NOT_PERMITTED, WORKFLOW_CANCEL_UNCONFIGURED,
    WORKFLOW_LIST_FAILED, WORKFLOW_CANCEL_FAILED that applies (an unexpected error: WORKFLOW_CANCEL_FAILED)."""
    report: Dict[str, Any] = {"status": OK, "detail": None, "cancelled": 0, "already_finished": 0, "failed": 0,
                              "executions": [], "list_failures": []}
    try:
        _cancel_active_platform_workflows((project or "").strip(), report)
    except Exception as e:  # noqa: BLE001 - the engage is already written: report it typed, never crash the route
        logger.error(f"Emergency stop: unexpected error while cancelling workflow executions: "
                     f"{type(e).__name__}: {e}")
        report.update(status=CANCEL_FAILED, detail=f"unexpected: {type(e).__name__}: {e}"[:500])
    return report


def _cancel_active_platform_workflows(project: str, report: Dict[str, Any]) -> None:
    try:
        if not project:
            raise WorkflowExecutionsError(UNCONFIGURED, "the Control Center's project id is unknown (PROJECT_ID)")
        region = _region()
        if not region:
            raise WorkflowExecutionsError(UNCONFIGURED, "the Control Center's region is unknown (REGION / metadata)")
        session = _session()
    except WorkflowExecutionsError as e:
        report["list_failures"] = [{"workflow": w, "reason": e.code, "detail": e.detail, "pass": 1}
                                   for w in PLATFORM_WORKFLOWS]
        report.update(status=e.code, detail=e.detail)
        logger.error(f"Emergency stop: no workflow execution was cancelled ({e.code}): {e.detail}")
        return

    seen = set()
    listed_ok = list(PLATFORM_WORKFLOWS)
    for pass_no in (1, 2):
        workflows, listed_ok = listed_ok, []
        for workflow in workflows:
            try:
                listed = list_active_executions(session, project, region, workflow)
                listed_ok.append(workflow)
            except WorkflowExecutionsError as e:
                listed = e.partial  # past the page cap: still cancel what was listed
                report["list_failures"].append({"workflow": workflow, "reason": e.code, "detail": e.detail,
                                                "pass": pass_no})
                logger.error(f"Emergency stop: could not list active {workflow} executions ({e.code}): {e.detail}")
            for ex in listed:
                if ex["name"] in seen:
                    continue
                seen.add(ex["name"])
                if ex["state"] != "ACTIVE":
                    r = _result(ex["name"])
                    r.update(outcome=ALREADY_FINISHED, state=ex["state"], detail=f"listed as {ex['state']}")
                else:
                    r = cancel_execution(ex["name"], session=session)
                r["workflow"], r["pass"] = workflow, pass_no
                report["executions"].append(r)
                if r["outcome"] == CANCELLED:
                    report["cancelled"] += 1
                    logger.info(f"Emergency stop: cancelled workflow execution {r['name']}")
                elif r["outcome"] == ALREADY_FINISHED:
                    report["already_finished"] += 1
                    logger.info(f"Emergency stop: workflow execution {r['name']} had already ended ({r['state']})")
                else:
                    report["failed"] += 1
                    logger.error(f"Emergency stop: could not cancel workflow execution {r['name']} "
                                 f"({r['reason']}): {r['detail']}")

    reasons = [f["reason"] for f in report["list_failures"]] + [
        r["reason"] for r in report["executions"] if r["outcome"] == FAILED]
    for code in (NOT_PERMITTED, UNCONFIGURED, LIST_FAILED, CANCEL_FAILED):
        if code in reasons:
            report["status"] = code
            break
    else:
        if reasons:  # e.g. WORKFLOW_EXECUTION_NAME_INVALID from a malformed listed name
            report["status"] = CANCEL_FAILED
    if report["status"] != OK:
        parts = []
        if report["list_failures"]:
            parts.append("could not list " + ", ".join(f"{f['workflow']} ({f['reason']})"
                                                       for f in report["list_failures"]))
        if report["failed"]:
            parts.append(f"{report['failed']} execution(s) could not be cancelled")
        report["detail"] = "; ".join(parts)
