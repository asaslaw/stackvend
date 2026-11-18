from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import logging
import os
import time
import traceback
import urllib.parse
import uuid
from typing import Any, Callable, Dict, List, Optional

import urllib3.util

logger = logging.getLogger("castor.callbacks")

# FD-4AI-c (FD27-07): the exact status words a worker body sets on genuine success, from the caller audit in
# docs/handoff/fd-4ai-c-report.md. Exact equality only. FD-4D-c / FD-4AI-c F1: only "SUCCESS"; the DEPLOYED alias is
# removed (TerraformService.deploy_workload reports SUCCESS, and mcp-servers/terraform/{main,applier}.py set the
# status after copying the result into the outcome, so a result word can never override it).
SUCCESS_STATUSES = frozenset({"SUCCESS"})
# A body that returns without setting a status is FAILED with this class (never SUCCESS).
WORKER_NO_OUTCOME = "WORKER_NO_OUTCOME"
_NO_STATUS_SENTINEL = "Worker terminated unexpectedly without reporting status"
# TI-5-R3-d (owner 10-25, FOLLOWUPS-1025): a failed stage outcome's typed `validation_report` (the tf-applier's apply
# report, shared/diagnostics ValidationReport; already bounded to 20 diagnostics) is kept on the stage record beside
# the error it belongs to, so the Control Center's resume can forward it. Larger serialized reports are not kept.
# Every status write carries a fresh `attempt_id`; the report write stores the same id (`validation_report_attempt`),
# so a reader takes a report only from the attempt the stage record describes (RT 11-07 F1).
STAGE_ATTEMPT_ID_FIELD = "attempt_id"
STAGE_VALIDATION_REPORT_FIELD = "validation_report"
STAGE_VALIDATION_REPORT_ERROR_FIELD = "validation_report_error"
STAGE_VALIDATION_REPORT_ATTEMPT_FIELD = "validation_report_attempt"
STAGE_VALIDATION_REPORT_MAX_BYTES = 256 * 1024


@contextmanager
def guaranteed_callback_scope(
    callback_url: Optional[str],
    trace_id: Optional[str],
    stage_name: str,
    product_id: Optional[str] = None,
    firestore_db: Optional[Any] = None,
):
    """
    Context manager guaranteeing that an execution outcome (SUCCESS or FAILED)
    is ALWAYS delivered back to Cloud Workflows and Firestore, even on unhandled crashes.

    FD-4AI-c: SUCCESS only when the body sets a status in SUCCESS_STATUSES. A body that leaves the status
    untouched is FAILED (error_class WORKER_NO_OUTCOME); any other status is FAILED with the caller's error kept
    and its original word in ``reported_status``.
    """
    start_time = time.time()
    outcome: Dict[str, Any] = {
        "status": "IN_PROGRESS",
        "stage": stage_name,
        "trace_id": trace_id or "",
        "product_id": product_id or "",
        "error": _NO_STATUS_SENTINEL,
        "traceback": None,
        "execution_duration_seconds": 0.0,
        "outputs": {},
    }

    try:
        yield outcome
        # If task finished without unhandled exception:
        current_status = outcome.get("status")
        caller_error = outcome.get("error")
        caller_error_unset = not caller_error or caller_error == _NO_STATUS_SENTINEL
        if isinstance(current_status, str) and current_status in SUCCESS_STATUSES:
            outcome["status"] = "SUCCESS"
            outcome["error"] = None
        elif current_status == "IN_PROGRESS":
            outcome["status"] = "FAILED"
            outcome["reported_status"] = "IN_PROGRESS"
            if not outcome.get("error_class"):
                outcome["error_class"] = WORKER_NO_OUTCOME
            if caller_error_unset:
                outcome["error"] = f"{WORKER_NO_OUTCOME}: worker finished without reporting an outcome"
            logger.error(f"Stage '{stage_name}' for product '{product_id}' finished without reporting an outcome")
        else:
            outcome["status"] = "FAILED"
            if current_status != "FAILED":
                # Always a JSON string, so a non-JSON status can never break delivery (FD-4AI-c RT F2).
                outcome["reported_status"] = current_status if isinstance(current_status, str) else repr(current_status)
                if caller_error_unset:
                    outcome["error"] = f"worker reported status {current_status!r}, which is not a success status"
    except Exception as exc:
        logger.error(
            f"Unhandled worker exception during stage '{stage_name}' for product '{product_id}': {exc}\n{traceback.format_exc()}"
        )
        outcome["status"] = "FAILED"
        outcome["error"] = f"{type(exc).__name__}: {str(exc)}"
        outcome["traceback"] = traceback.format_exc()
        raise
    finally:
        if outcome.get("status") != "SUCCESS":
            outcome["status"] = "FAILED"
        elapsed = round(time.time() - start_time, 2)
        outcome["execution_duration_seconds"] = elapsed

        # 1. Primary Delivery: Signed Google Cloud Workflows Callback Endpoint
        callback_delivered = False
        callback_error: Optional[BaseException] = None
        if callback_url:
            try:
                CallbackDeliveryClient.send_callback(
                    callback_url=callback_url,
                    payload=outcome,
                    timeout=15,
                    max_attempts=4,
                )
                callback_delivered = True
            except Exception as cb_err:
                callback_error = cb_err
                logger.critical(
                    f"CRITICAL: Failed to deliver callback to Cloud Workflows for {product_id} ({trace_id}): {cb_err}"
                )
        # RT14-25: an outcome no workflow received is kept, with its callback URL, for redelivery (any status).
        if callback_url and not callback_delivered and firestore_db and trace_id:
            persist_undelivered_callback(firestore_db, trace_id, stage_name.lower(), callback_url, outcome,
                                         callback_error)

        # 2. Secondary / Telemetry Delivery: Fallback or Parallel write to Firestore
        if firestore_db and trace_id:
            try:
                stage_status = "SUCCESS" if outcome.get("status") == "SUCCESS" else "FAILED"
                summary_text = (
                    outcome.get("summary")
                    or outcome.get("outputs", {}).get("summary")
                    or (
                        f"{stage_name.capitalize()} stage completed successfully"
                        if stage_status == "SUCCESS"
                        else f"{stage_name.capitalize()} stage failed: {outcome.get('error', 'Unknown error')}"
                    )
                )

                attempt_id = uuid.uuid4().hex   # TI-5-R3-d (RT F1): pairs this write with its report write
                stage_payload: Dict[str, Any] = {
                    "status": stage_status,
                    "duration_seconds": elapsed,
                    "error": outcome.get("error"),
                    "summary": summary_text,
                    "state": "CALLBACK_DELIVERED" if callback_delivered else "CALLBACK_FAILED",
                    STAGE_ATTEMPT_ID_FIELD: attempt_id,
                }
                if stage_status == "FAILED" and outcome.get("traceback"):
                    stage_payload["traceback"] = outcome["traceback"]

                doc_update: Dict[str, Any] = {
                    "stages": {
                        stage_name.lower(): stage_payload
                    }
                }

                # If outputs contains service_url, record in top-level outputs
                outputs_dict = outcome.get("outputs", {})
                if isinstance(outputs_dict, dict) and outputs_dict.get("service_url"):
                    doc_update["outputs"] = {"service_url": outputs_dict["service_url"]}
                elif outcome.get("service_url"):
                    doc_update["outputs"] = {"service_url": outcome["service_url"]}

                # STAGE-FAIL-NOT-RUN-FAIL: a failed stage whose outcome reached the workflow is the workflow's to
                # decide (it may remediate, e.g. the bounded terraform remediation loop); the run's own status is set
                # by its terminal notify (gateway /events/workflow-status) or the Control Center's Workflows-state
                # reconcile. Only an outcome no workflow received (no callback URL, or delivery failed) also fails
                # the run here, as before.
                if stage_status == "FAILED" and not callback_delivered:
                    doc_update["status"] = "FAILED"
                    doc_update["current_stage"] = "FAILED"
                    doc_update["error"] = outcome.get("error")

                firestore_db.collection("pipeline_executions").document(trace_id).set(doc_update, merge=True)
                logger.info(
                    f"Updated Firestore pipeline_executions telemetry for {trace_id} (stage: {stage_name}, status: {stage_status})"
                )
                if stage_status == "FAILED" and STAGE_VALIDATION_REPORT_FIELD in outcome:
                    _persist_stage_validation_report(firestore_db, trace_id, stage_name.lower(), outcome, attempt_id)
            except Exception as fs_err:
                logger.warning(f"Could not persist telemetry to Firestore for {trace_id}: {fs_err}")


def _persist_stage_validation_report(firestore_db: Any, trace_id: str, stage: str, outcome: Dict[str, Any],
                                     attempt_id: str) -> None:
    """TI-5-R3-d: `pipeline_executions/{trace}.stages.<stage>.validation_report` = the failed outcome's report (a
    dict, JSON at most STAGE_VALIDATION_REPORT_MAX_BYTES; anything else -> null), `.validation_report_error` = the
    outcome's error and `.validation_report_attempt` = the `attempt_id` the status write above stored (a reader pairs
    report and stage record by exact equality of the ids, so a later failure without a report, even with the same
    error text, never inherits an older one). Its own merge write after the status write: a report the document cannot
    hold never loses the stage status. A failed write is logged."""
    report = outcome.get(STAGE_VALIDATION_REPORT_FIELD)
    if isinstance(report, dict):
        try:
            size = len(json.dumps(report).encode("utf-8"))
        except (TypeError, ValueError):
            size = None
        if size is None or size > STAGE_VALIDATION_REPORT_MAX_BYTES:
            logger.warning(f"Validation report of stage '{stage}' for {trace_id} not kept on the stage record "
                           f"({'not JSON' if size is None else f'{size} bytes'}); a resume regenerates without it")
            report = None
    else:
        report = None
    try:
        firestore_db.collection("pipeline_executions").document(trace_id).set(
            {"stages": {stage: {STAGE_VALIDATION_REPORT_FIELD: report,
                                STAGE_VALIDATION_REPORT_ERROR_FIELD: outcome.get("error"),
                                STAGE_VALIDATION_REPORT_ATTEMPT_FIELD: attempt_id}}}, merge=True)
    except Exception as fs_err:
        logger.warning(f"Could not persist the validation report of stage '{stage}' for {trace_id}: {fs_err}")


# ----------------------------------------------------------------------------------------------------------------
# FD-4J: callback URL classification. Real parsers and exact comparisons only (no substring/regex host tests).
# A platform OAuth token is attached ONLY to a Cloud Workflows callback endpoint of THIS platform project:
#   https://workflowexecutions.googleapis.com/v1/projects/<own id|number>/locations/L/workflows/W/executions/E/callbacks/C
# Loopback IP literals (local harnesses) receive the payload without any credential. Everything else is refused.
# REPLICATED FILE: byte-identical copies in apps/{control-center,orchestrator-gateway,project-vending,qa-runner}/shared/
# and mcp-servers/terraform/shared/ (tests/test_fd4j_callbacks.py::test_callbacks_replica_parity,
# tests/test_fd4ai_callback_outcome.py::test_callbacks_six_copies_byte_identical).
# ----------------------------------------------------------------------------------------------------------------
WORKFLOWS_CALLBACK_HOST = "workflowexecutions.googleapis.com"
# Exact path shape; None marks a non-empty identifier segment. Index 3 is the project.
_WORKFLOWS_PATH_SHAPE = ("", "v1", "projects", None, "locations", None, "workflows", None, "executions", None,
                         "callbacks", None)
_METADATA_PROJECT_URL = "http://metadata.google.internal/computeMetadata/v1/project/"
_own_project_cache: Optional[frozenset] = None

KIND_WORKFLOWS = "google_workflows"
KIND_LOOPBACK = "loopback"


class CallbackURLRejected(ValueError):
    """The callback URL is not an allowed delivery target. It is never contacted and never retried."""


def _metadata_project_value(leaf: str) -> str:
    try:
        import requests

        resp = requests.get(_METADATA_PROJECT_URL + leaf, headers={"Metadata-Flavor": "Google"}, timeout=2,
                            allow_redirects=False)
        if resp.status_code == 200:
            return resp.text.strip()
    except Exception as md_err:
        logger.warning(f"Could not read project {leaf} from the metadata server: {type(md_err).__name__}")
    return ""


def _own_project_identities() -> frozenset:
    """Platform project id and number: from env, plus the metadata server when running on Cloud Run."""
    global _own_project_cache
    if _own_project_cache is not None:
        return _own_project_cache
    values = {os.getenv(k, "").strip() for k in ("PROJECT_ID", "GOOGLE_CLOUD_PROJECT", "PROJECT_NUMBER")}
    on_cloud_run = bool(os.getenv("K_SERVICE") or os.getenv("CLOUD_RUN_JOB"))
    md_id, md_num = "", ""
    if on_cloud_run:
        md_id = _metadata_project_value("project-id")
        md_num = _metadata_project_value("numeric-project-id")
        values.update({md_id, md_num})
    resolved = frozenset(v for v in values if v)
    if on_cloud_run and md_id and md_num:
        # Cache only a complete answer: Workflows callback URLs carry the project NUMBER, so a failed metadata
        # read must be retried on the next callback, never frozen for the process lifetime.
        _own_project_cache = resolved
    return resolved


def _parsed_ip(host: str):
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def classify_callback_url(url: Any) -> str:
    """Return KIND_WORKFLOWS or KIND_LOOPBACK, or raise CallbackURLRejected."""
    if not isinstance(url, str) or not url:
        raise CallbackURLRejected("callback_url must be a non-empty string")
    if not url.isascii() or not url.isprintable() or any(c.isspace() or c == "\\" for c in url):
        raise CallbackURLRejected("callback_url contains non-ASCII, control, whitespace or backslash characters")
    try:
        split = urllib.parse.urlsplit(url)
        host = split.hostname or ""
        port = split.port
        u3 = urllib3.util.parse_url(url)
    except ValueError as parse_err:
        raise CallbackURLRejected(f"callback_url does not parse: {type(parse_err).__name__}") from None
    scheme = split.scheme.lower()
    if scheme not in ("https", "http"):
        raise CallbackURLRejected(f"callback_url scheme {scheme!r} is not allowed")
    if split.username is not None or split.password is not None or u3.auth is not None:
        raise CallbackURLRejected("callback_url must not carry userinfo")
    # requests connects with urllib3's parse: both parsers must agree on scheme and host (IP literals compared as
    # addresses, because urllib3 keeps IPv6 brackets and urlsplit drops them).
    u3_host = (u3.host or "").lower()
    ip = _parsed_ip(host)
    same_host = (ip is not None and ip == _parsed_ip(u3_host)) or (ip is None and bool(host) and u3_host == host)
    if (u3.scheme or "").lower() != scheme or not same_host:
        raise CallbackURLRejected("callback_url host is ambiguous between URL parsers")

    if ip is not None:
        if ip.is_loopback:
            return KIND_LOOPBACK
        raise CallbackURLRejected("callback_url IP literal is not loopback")

    if scheme != "https" or port is not None or split.netloc.lower() != WORKFLOWS_CALLBACK_HOST:
        raise CallbackURLRejected(f"callback_url host {host!r} is not the Cloud Workflows callback endpoint")
    if split.query or split.fragment or "?" in url or "#" in url:
        raise CallbackURLRejected("Workflows callback_url must not carry a query or fragment")
    segments = split.path.split("/")
    if len(segments) != len(_WORKFLOWS_PATH_SHAPE) or any(
        (expected is not None and seg != expected) or (expected is None and not seg)
        for seg, expected in zip(segments, _WORKFLOWS_PATH_SHAPE)
    ):
        raise CallbackURLRejected("callback_url path is not a Workflows execution callback path")
    own = _own_project_identities()
    if not own or segments[3] not in own:
        raise CallbackURLRejected("Workflows callback_url targets a project other than this platform project")
    return KIND_WORKFLOWS


def validate_callback_url(url: Any) -> str:
    """API-boundary validator (usable from a Pydantic field_validator): returns url unchanged or raises ValueError."""
    classify_callback_url(url)
    return url


def _describe(url: str) -> str:
    try:
        split = urllib.parse.urlsplit(url)
        return f"{split.scheme}://{split.hostname}"
    except ValueError:
        return "<unparseable>"


class CallbackDeliveryClient:
    """Delivers callback payloads back to Google Cloud Workflows with exponential backoff."""

    @staticmethod
    def _get_headers(callback_url: str) -> Dict[str, str]:
        """Request headers. A Google OAuth token is attached only for this project's Workflows callback endpoint.

        Raises CallbackURLRejected for any URL that is not an allowed delivery target.
        """
        kind = classify_callback_url(callback_url)
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "ProjectCastor-AsyncWorker/1.0",
        }
        if kind == KIND_WORKFLOWS:
            try:
                import google.auth
                import google.auth.transport.requests

                credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
                auth_req = google.auth.transport.requests.Request()
                credentials.refresh(auth_req)
                if credentials.token:
                    headers["Authorization"] = f"Bearer {credentials.token}"
            except Exception as auth_err:
                logger.warning(f"Could not attach Google auth Bearer token for workflow callback: {auth_err}")
        return headers

    @staticmethod
    def send_callback(
        callback_url: str,
        payload: Dict[str, Any],
        timeout: int = 15,
        max_attempts: int = 5,
    ) -> Dict[str, Any]:
        """
        Sends HTTP POST to the signed Cloud Workflows callback endpoint.
        Retries up to max_attempts with exponential backoff if transient network errors occur.
        A rejected URL (CallbackURLRejected) is never contacted and never retried. Redirects are never followed.
        """
        import requests

        headers = CallbackDeliveryClient._get_headers(callback_url)
        logger.info(f"Sending callback to {_describe(callback_url)} (payload keys: {list(payload.keys())})")
        start_time = time.time()
        last_exception = None

        for attempt in range(1, max_attempts + 1):
            try:
                response = requests.post(
                    callback_url,
                    json=payload,
                    headers=headers,
                    timeout=timeout,
                    allow_redirects=False,
                )
                elapsed = time.time() - start_time
                if response.status_code in [200, 202, 204]:
                    logger.info(f"Callback delivered successfully in {elapsed:.2f}s (HTTP {response.status_code})")
                    try:
                        return response.json()
                    except Exception:
                        return {"status_code": response.status_code, "text": response.text}
                logger.warning(
                    f"Callback delivery returned HTTP {response.status_code} (attempt {attempt}/{max_attempts}): {response.text[:500]}"
                )
                if 300 <= response.status_code < 400:
                    raise RuntimeError(f"Callback endpoint redirected (HTTP {response.status_code}); redirects are not followed")
                response.raise_for_status()
            except Exception as exc:
                last_exception = exc
                elapsed = time.time() - start_time
                if attempt < max_attempts:
                    sleep_time = min(2 ** (attempt - 1) * 1.5, 30)
                    logger.warning(
                        f"Callback delivery attempt {attempt} failed ({exc}). Retrying in {sleep_time:.1f}s..."
                    )
                    time.sleep(sleep_time)
                else:
                    logger.error(f"Callback delivery permanently failed after {attempt} attempts ({elapsed:.2f}s): {exc}")

        if last_exception:
            raise last_exception
        raise RuntimeError("Callback delivery failed with unknown error.")


# ----------------------------------------------------------------------------------------------------------------
# RT14-25 (owner 11-14; non-core alternative of docs/planning/full-scope-red-team-1114.md): an outcome whose callback
# could not be delivered (endpoint 5xx / 429 past the retries, a URL rejected because the platform project number was
# not readable yet) is kept with its callback URL in pipeline_executions/{trace}/undelivered_callbacks/{id}, whatever
# its status. Before, only a FAILED one marked the run FAILED; a SUCCESS stayed in the logs, the run stayed ACTIVE with
# its build slot for the workflow's whole await (about 24 h for the deploy) and then failed DEPLOY_TIMEOUT although the
# deploy had succeeded. `redeliver_undelivered_callbacks` re-sends a kept outcome to its own URL. It is called where the
# platform already reads a running run's Workflows execution state and finds it still ACTIVE: the gateway's admission
# reconcile of build-slot holders and the Control Center's bound-run reconcile. No new scheduler, IAM or workflow step.
# ----------------------------------------------------------------------------------------------------------------
UNDELIVERED_CALLBACKS = "undelivered_callbacks"
UNDELIVERED_PAYLOAD_MAX_BYTES = 512 * 1024
REDELIVERY_MAX_ATTEMPTS = 5
REDELIVERY_CLAIM_STALE_S = 300           # a SENDING claim older than this was lost (the instance stopped mid-send)
STAGE_STATE_CALLBACK_FAILED = "CALLBACK_FAILED"
STAGE_STATE_CALLBACK_REDELIVERED = "CALLBACK_REDELIVERED"
# undelivered_callbacks/{id}.state
REDELIVERY_PENDING = "PENDING"
REDELIVERY_SENDING = "SENDING"
REDELIVERY_DELIVERED = "DELIVERED"
REDELIVERY_REJECTED = "REJECTED"        # typed end: CALLBACK_URL_REJECTED (the URL is not this platform's endpoint)
REDELIVERY_EXHAUSTED = "EXHAUSTED"      # typed end: CALLBACK_REDELIVERY_EXHAUSTED
REDELIVERY_UNSTORABLE = "UNSTORABLE"    # typed end: CALLBACK_OUTCOME_TOO_LARGE (logged CRITICAL, never sent)
CALLBACK_URL_REJECTED = "CALLBACK_URL_REJECTED"
CALLBACK_REDELIVERY_EXHAUSTED = "CALLBACK_REDELIVERY_EXHAUSTED"
CALLBACK_OUTCOME_TOO_LARGE = "CALLBACK_OUTCOME_TOO_LARGE"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def undelivered_callback_id(stage: str, callback_url: str) -> str:
    return f"{stage}-{hashlib.sha256(callback_url.encode('utf-8')).hexdigest()[:16]}"


def has_undelivered_stage(run_record: Optional[Dict[str, Any]]) -> bool:
    """True when a stage record of the run says its outcome never reached the workflow (cheap check before listing)."""
    stages = (run_record or {}).get("stages")
    return isinstance(stages, dict) and any(
        isinstance(s, dict) and s.get("state") == STAGE_STATE_CALLBACK_FAILED for s in stages.values())


# RT14-09 / RT14-25: the placeholder of mcp-servers/terraform/plan_redaction.py (SENSITIVE_PLACEHOLDER), so a kept
# outcome reads the same as the source-masked callback and state viewer.
SENSITIVE_OUTPUT_PLACEHOLDER = "(sensitive value)"


def mask_sensitive_output_entries(value: Any) -> Any:
    """RT14-09 / RT14-25: a copy of `value` in which every OpenTofu output entry the engine marks sensitive (a dict
    with `"sensitive": true` and a `value`, the `tofu output -json` shape) has its value replaced by
    SENSITIVE_OUTPUT_PLACEHOLDER, at any depth. The engine's typed flag only, never a name or value pattern
    (invariant 2); everything else is returned unchanged (Do No Harm). Pure: the input is not changed."""
    if isinstance(value, dict):
        if value.get("sensitive") is True and "value" in value:
            return {k: (SENSITIVE_OUTPUT_PLACEHOLDER if k == "value" and v is not None else v)
                    for k, v in value.items()}
        return {k: mask_sensitive_output_entries(v) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_sensitive_output_entries(v) for v in value]
    return value


def persist_undelivered_callback(firestore_db: Any, trace_id: str, stage: str, callback_url: str,
                                 outcome: Dict[str, Any], error: Optional[BaseException] = None) -> Optional[str]:
    """RT14-25: keeps an outcome the workflow did not receive, with its callback URL. Returns the record id, or None
    when it could not be written (logged CRITICAL: the workflow then waits for its await bound, as before).
    RT14-09: the kept (and later re-sent) copy has every sensitive-marked OpenTofu output masked."""
    outcome = mask_sensitive_output_entries(outcome)
    doc_id = undelivered_callback_id(stage, callback_url)
    now_iso = _utc_now().isoformat()
    record: Dict[str, Any] = {"stage": stage, "trace_id": trace_id, "callback_url": callback_url,
                              "outcome_status": outcome.get("status"), "state": REDELIVERY_PENDING, "attempts": 0,
                              "first_error": type(error).__name__ if error is not None else None,
                              "created_at": now_iso, "updated_at": now_iso}
    try:
        payload_json = json.dumps(outcome, default=str)
    except (TypeError, ValueError) as dump_err:
        payload_json, record["state"] = None, REDELIVERY_UNSTORABLE
        record["error_class"], record["detail"] = CALLBACK_OUTCOME_TOO_LARGE, f"not JSON ({type(dump_err).__name__})"
    if payload_json is not None and len(payload_json.encode("utf-8")) > UNDELIVERED_PAYLOAD_MAX_BYTES:
        record["state"], record["error_class"] = REDELIVERY_UNSTORABLE, CALLBACK_OUTCOME_TOO_LARGE
        record["detail"] = f"{len(payload_json.encode('utf-8'))} bytes (limit {UNDELIVERED_PAYLOAD_MAX_BYTES})"
        payload_json = None
    record["payload_json"] = payload_json
    try:
        firestore_db.collection("pipeline_executions").document(trace_id).collection(
            UNDELIVERED_CALLBACKS).document(doc_id).set(record)
    except Exception as fs_err:  # noqa: BLE001
        logger.critical(f"CRITICAL: undelivered {stage} outcome of {trace_id} not kept for redelivery "
                        f"({type(fs_err).__name__}); the workflow waits for its await bound")
        return None
    if record["state"] == REDELIVERY_UNSTORABLE:
        logger.critical(f"CRITICAL: {CALLBACK_OUTCOME_TOO_LARGE}: undelivered {stage} outcome of {trace_id} cannot be "
                        f"redelivered ({record['detail']})")
    else:
        logger.error(f"Undelivered {stage} outcome ({outcome.get('status')}) of {trace_id} kept for redelivery "
                     f"(pipeline_executions/{trace_id}/{UNDELIVERED_CALLBACKS}/{doc_id})")
    return doc_id


def _default_send(url: str, payload: Dict[str, Any]) -> None:
    CallbackDeliveryClient.send_callback(callback_url=url, payload=payload, timeout=10, max_attempts=2)


def _claim_age_s(data: Dict[str, Any], now: datetime) -> Optional[float]:
    try:
        claimed = datetime.fromisoformat(str(data.get("last_attempt_at")))
    except (TypeError, ValueError):
        return None
    if claimed.tzinfo is None:
        claimed = claimed.replace(tzinfo=timezone.utc)
    return (now - claimed).total_seconds()


def redeliver_undelivered_callbacks(db: Any, trace_id: str, *,
                                    send: Optional[Callable[[str, Dict[str, Any]], Any]] = None,
                                    now: Optional[datetime] = None,
                                    max_attempts: int = REDELIVERY_MAX_ATTEMPTS) -> List[Dict[str, Any]]:
    """RT14-25: re-sends every kept outcome of `trace_id` that is still PENDING (or whose SENDING claim went stale) to
    its own callback URL. Call it only while the run's workflow execution is ACTIVE (the caller has just read it).
    Each record is claimed by compare-and-set first (update-time precondition), so concurrent reconcilers send it once.
    Outcomes: DELIVERED (the stage record then says CALLBACK_REDELIVERED), PENDING (retried by the next reconcile),
    REJECTED (CALLBACK_URL_REJECTED: never sent, final), EXHAUSTED (CALLBACK_REDELIVERY_EXHAUSTED after `max_attempts`,
    final, written on the run record as `callback_redelivery_error`). Returns [{id, stage, outcome}]. Never raises."""
    send = send or _default_send
    now = now or _utc_now()
    now_iso = now.isoformat()
    results: List[Dict[str, Any]] = []
    run_ref = db.collection("pipeline_executions").document(trace_id)
    try:
        snaps = list(run_ref.collection(UNDELIVERED_CALLBACKS).stream())
    except Exception as list_err:  # noqa: BLE001
        logger.warning(f"Undelivered callbacks of {trace_id} not read ({type(list_err).__name__}); retried later")
        return [{"id": None, "stage": None, "outcome": "UNREADABLE"}]
    for snap in snaps:
        data = snap.to_dict() or {}
        state = data.get("state")
        if state == REDELIVERY_SENDING:
            age = _claim_age_s(data, now)
            if age is not None and age < REDELIVERY_CLAIM_STALE_S:
                continue
        elif state != REDELIVERY_PENDING:
            continue
        stage = str(data.get("stage") or "")
        attempts = int(data.get("attempts") or 0) + 1
        try:
            snap.reference.update({"state": REDELIVERY_SENDING, "attempts": attempts, "last_attempt_at": now_iso,
                                   "updated_at": now_iso},
                                  option=db.write_option(last_update_time=snap.update_time))
        except Exception as claim_err:  # noqa: BLE001 - another reconciler claimed it (or the store is down)
            logger.info(f"Undelivered {stage} outcome of {trace_id} not claimed ({type(claim_err).__name__})")
            continue
        final: Dict[str, Any]
        try:
            send(str(data.get("callback_url") or ""), json.loads(data.get("payload_json") or "null") or {})
        except CallbackURLRejected as rejected:
            final = {"state": REDELIVERY_REJECTED, "error_class": CALLBACK_URL_REJECTED, "detail": str(rejected)}
        except Exception as send_err:  # noqa: BLE001
            reason = f"{type(send_err).__name__}: {str(send_err)[:300]}"
            if attempts >= max_attempts:
                final = {"state": REDELIVERY_EXHAUSTED, "error_class": CALLBACK_REDELIVERY_EXHAUSTED, "detail": reason}
            else:
                final = {"state": REDELIVERY_PENDING, "last_error": reason}
        else:
            final = {"state": REDELIVERY_DELIVERED, "delivered_at": now_iso}
        final["updated_at"] = now_iso
        try:
            snap.reference.set(final, merge=True)
        except Exception as fs_err:  # noqa: BLE001 - the SENDING claim goes stale and the next reconcile decides
            logger.warning(f"Redelivery state of the {stage} outcome of {trace_id} not recorded "
                           f"({type(fs_err).__name__})")
        try:
            if final["state"] == REDELIVERY_DELIVERED:
                run_ref.set({"stages": {stage: {"state": STAGE_STATE_CALLBACK_REDELIVERED,
                                                "redelivered_at": now_iso}}}, merge=True)
            elif final["state"] in (REDELIVERY_REJECTED, REDELIVERY_EXHAUSTED):
                run_ref.set({"callback_redelivery_error": {"stage": stage, "error_class": final["error_class"],
                                                           "detail": final["detail"], "at": now_iso}}, merge=True)
        except Exception as fs_err:  # noqa: BLE001
            logger.warning(f"Run record {trace_id} not updated after a redelivery ({type(fs_err).__name__})")
        if final["state"] == REDELIVERY_DELIVERED:
            logger.warning(f"Undelivered {stage} outcome of {trace_id} redelivered to its workflow (attempt {attempts})")
        elif final["state"] == REDELIVERY_PENDING:
            logger.error(f"Redelivery of the {stage} outcome of {trace_id} failed (attempt {attempts} of "
                         f"{max_attempts}): {final['last_error']}")
        else:
            logger.critical(f"CRITICAL: {final['error_class']}: the {stage} outcome of {trace_id} cannot be "
                            f"redelivered: {final['detail']}")
        results.append({"id": snap.id, "stage": stage, "outcome": final["state"]})
    return results
