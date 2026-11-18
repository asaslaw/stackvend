"""
Project Castor: FinOps Budget Enforcer Engine
Cloud Run Job and Service executing the 100% budget breach circuit breaker,
multi-resource quarantine (Cloud Run, GCE, Cloud SQL, GKE, Billing Unlink),
pre-quarantine state snapshotting, and 1-click state restoration.
"""

import argparse
from datetime import datetime, timezone
from enum import Enum
import json
import logging
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple
import uuid

import google.auth
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from google.cloud import firestore

logger = logging.getLogger("finops-budget-enforcer-job")
logging.basicConfig(level=logging.INFO)


# FD-4CI-b-R2: how long the Cloud Run job waits, in total, for the card recommendations it started (after its run
# record is final): finops_advisor.ADVISOR_TIMEOUT_S (20 s) + 5 s (pinned by tests/test_fd4dj_wiring.py).
ADVISOR_WAIT_S = 25.0

# C10 (RT finding 6): a restore re-arms budget enforcement. The billing-alert-drain-job (shared/billing_alerts.py)
# latches an enforced breach per workload, billing month and threshold (budget_breach_latch) and re-asks a refused one
# once a day (budget_breach_refusal); after a restore a new breach in the same month must act again. A null field is
# not a latch (latch_matches / refusal_recent need a mapping).
RESTORE_CLEARS_BREACH_LATCH = {"budget_breach_latch": None, "budget_breach_refusal": None}

# RT14-05 / RT14-20: the scale-to-zero and the billing unlink are idempotent and never act without a durable record.
# A workload whose quarantine record exists, or whose status is one of these, is already enforced: a second breach
# (a re-sent alert, a changed ceiling or Circuit Breaker %, a failed latch write) changes nothing and answers the
# existing outcome, so the pre-quarantine snapshot is never replaced by the already-zeroed state.
ALREADY_ENFORCED_STATUSES = frozenset({"QUARANTINED", "BILLING_UNLINKED"})
SNAPSHOT_VERSION = 2   # snapshots written with create() before any scale-down (RT14-20)
# The restore re-reads the live state and reports RESTORED only once it matches the snapshot (RT14-05). A VM counts as
# started once Compute Engine is bringing it up; Cloud SQL and Cloud Run must show the recorded values. The wait is
# bounded inside the job's 600 s task timeout; a resource not confirmed in time is RESTORE_PARTIAL (deciding the card
# again re-applies the snapshot, which is idempotent, and checks again).
RESTORE_VERIFY_WAIT_S = 180.0
RESTORE_VERIFY_POLL_S = 10.0
VM_STARTED_STATUSES = frozenset({"PROVISIONING", "STAGING", "RUNNING"})


class QuarantineStateError(Exception):
    """RT14-05 / RT14-20: a typed stop of a scale-to-zero or billing unlink (class + stage). `error_class`:
    QUARANTINE_STATE_UNREADABLE (the quarantine markers cannot be read; nothing changed), SNAPSHOT_READ_FAILED (the live
    state cannot be read completely; nothing changed), SNAPSHOT_PERSIST_FAILED (the snapshot or the billing account
    could not be made durable; nothing changed), QUARANTINE_RECORD_FAILED (compute was stopped or billing detached, but
    the quarantine record was not written; a re-sent alert finishes it from the kept snapshot). None of these is an
    enforced outcome, so the billing alert is not acked and is delivered again."""

    def __init__(self, error_class: str, message: str, stage: str = "finops_quarantine"):
        self.error_class, self.stage = error_class, stage
        super().__init__(f"{error_class}: {message}")


class LiveStateReadError(Exception):
    """A strict live-state read (snapshot or restore check) could not list one resource type completely."""

    def __init__(self, resource_type: str, detail: str):
        self.resource_type = resource_type
        super().__init__(f"{resource_type}: {detail}")


def _is_already_exists(exc: BaseException) -> bool:
    return type(exc).__name__ == "AlreadyExists" or getattr(exc, "code", None) == 409


def _api_disabled(exc: BaseException) -> bool:
    """True when a Google API answered that it is not enabled in the project (the structured ErrorInfo reason
    SERVICE_DISABLED, or the legacy errors[].reason accessNotConfigured): the project then holds none of that API's
    resources. Exact field comparisons on the error body; anything else is a read failure."""
    content = getattr(exc, "content", None) if isinstance(exc, HttpError) else None
    if not content:
        return False
    try:
        body = json.loads(content.decode("utf-8") if isinstance(content, (bytes, bytearray)) else content)
    except (TypeError, ValueError, UnicodeDecodeError):
        return False
    err = body.get("error") if isinstance(body, dict) else None
    if not isinstance(err, dict):
        return False
    for detail in err.get("details") or []:
        if (isinstance(detail, dict) and detail.get("@type") == "type.googleapis.com/google.rpc.ErrorInfo"
                and detail.get("reason") == "SERVICE_DISABLED"):
            return True
    return any(isinstance(e, dict) and e.get("reason") == "accessNotConfigured" for e in err.get("errors") or [])


# Identity of one snapshot entry per resource type (the resume path adds only entries the kept snapshot lacks).
_SNAPSHOT_KEYS = {
    "cloud_run_services": lambda e: e.get("name"),
    "compute_vms": lambda e: (e.get("zone"), e.get("name")),
    "cloud_sql": lambda e: e.get("name"),
    "gke_pools": lambda e: (e.get("location"), e.get("cluster_name"), e.get("pool_name")),
}


def _running_now(field: str, entry: Dict[str, Any]) -> bool:
    """RT14 F1: True when a live snapshot entry shows the resource serving (a valid pre-stop state, so on the resume
    path it replaces the kept entry): a VM RUNNING, a Cloud SQL instance whose activation policy is not NEVER, a Cloud
    Run service with a max recorded or a min above zero. A stopped entry (what an interrupted attempt left) is False.
    GKE pools are never replaced: the live read reports the pool's initial node count, not its current size."""
    if field == "compute_vms":
        return entry.get("status") == "RUNNING"
    if field == "cloud_sql":
        return entry.get("activation_policy", "ALWAYS") != "NEVER"
    if field == "cloud_run_services":
        max_inst, min_inst = entry.get("max_instances"), entry.get("min_instances") or 0
        return (max_inst is not None and max_inst != 0) or min_inst > 0
    return False


def _default_advisor(project_id: str, creds: Any) -> Optional[Any]:
    """FD-4CI-b-R2: the budget-breach card advisor (finops_advisor.FinopsAdvisor, next to this module). It is imported
    here, not at module level, because some callers load this file by path without its directory on sys.path: only
    when the finops_advisor module itself is not found there is no advisor (logged) and cards are written exactly as
    before. Any other import failure (for example a job image without its vendored shared/) raises."""
    try:
        from finops_advisor import FinopsAdvisor
    except ModuleNotFoundError as e:
        if e.name != "finops_advisor":
            raise
        logger.warning(f"FINOPS_ADVISOR_UNAVAILABLE: {e}; budget-breach cards get no recommendation")
        return None
    return FinopsAdvisor(project_id, credentials=creds)


class BudgetBreachPolicy(str, Enum):
    AUTONOMOUS_SCALE_TO_ZERO = "AUTONOMOUS_SCALE_TO_ZERO"
    ALERT_ONLY = "ALERT_ONLY"
    HITL_CONFIRMATION_REQUIRED = "HITL_CONFIRMATION_REQUIRED"
    NUCLEAR_UNLINK_BILLING = "NUCLEAR_UNLINK_BILLING"


class QuarantineTargetRefused(Exception):
    """FD-4O: the enforcer refuses to touch this project (host project, not under the managed folder, unknown)."""


class WorkloadRegionRefused(Exception):
    """FD-7M-a: the workload's Cloud Run region cannot be established, so its Cloud Run services are never listed or
    scaled (never in another region). `error_class` REGION_NOT_APPROVED (the recorded region is not in Settings >
    Approved Deployable Regions) or REGION_UNAVAILABLE (the workload record or the settings cannot be read)."""

    def __init__(self, error_class: str, message: str):
        self.error_class = error_class
        super().__init__(f"{error_class}: {message}")


def _normalize_folder_id(value: str) -> str:
    v = (value or "").strip()
    if v.startswith("folders/"):
        v = v[len("folders/"):]
    return v if v.isdigit() else ""


# SAT-51 (owner 11-03 live, project-vending: two concurrent requests both died with "OSError: [Errno 9] Bad file
# descriptor"). A discovery client built with credentials= holds ONE httplib2.Http, which is not thread-safe; the
# module-global enforcer (main.py) would share it across request threads whenever it runs as a service. Per the
# google-api-python-client thread-safety guidance every request gets its own authorized httplib2 connection.
def _build_thread_safe(service: str, version: str, credentials):
    import google_auth_httplib2
    from googleapiclient.http import HttpRequest, build_http

    def request_builder(_http, *args, **kwargs):
        return HttpRequest(google_auth_httplib2.AuthorizedHttp(credentials, http=build_http()), *args, **kwargs)

    return build(service, version, http=google_auth_httplib2.AuthorizedHttp(credentials, http=build_http()),
                 requestBuilder=request_builder, cache_discovery=False)


class FinopsBudgetEnforcer:
    def __init__(
        self,
        project_id: Optional[str] = None,
        region: str = "us-central1",
        firestore_client: Optional[Any] = None,
        run_service: Optional[Any] = None,
        compute_service: Optional[Any] = None,
        sql_service: Optional[Any] = None,
        container_service: Optional[Any] = None,
        billing_service: Optional[Any] = None,
        crm_service: Optional[Any] = None,
        advisor: Optional[Any] = None,
    ):
        self.platform_project_id = project_id or os.getenv("PROJECT_ID", "")
        self.region = region or os.getenv("REGION", "us-central1")

        # Firestore Database Client
        if firestore_client is not None:
            self.db = firestore_client
        else:
            try:
                self.db = firestore.Client(project=self.platform_project_id) if self.platform_project_id else None
            except Exception as e:
                logger.warning(f"Could not initialize Firestore client for Budget Enforcer: {e}")
                self.db = None

        # Google Cloud API Clients
        creds = None
        if not (run_service and compute_service and sql_service and container_service and billing_service and crm_service):
            try:
                creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            except Exception:
                creds = None

        # Cloud Run API
        if run_service is not None:
            self.run = run_service
        elif creds:
            try:
                self.run = _build_thread_safe("run", "v2", creds)
            except Exception as e:
                logger.warning(f"Could not initialize Cloud Run API client: {e}")
                self.run = None
        else:
            self.run = None

        # Compute Engine API
        if compute_service is not None:
            self.compute = compute_service
        elif creds:
            try:
                self.compute = _build_thread_safe("compute", "v1", creds)
            except Exception as e:
                logger.warning(f"Could not initialize Compute Engine API client: {e}")
                self.compute = None
        else:
            self.compute = None

        # Cloud SQL Admin API
        if sql_service is not None:
            self.sql = sql_service
        elif creds:
            try:
                self.sql = _build_thread_safe("sqladmin", "v1beta4", creds)
            except Exception as e:
                logger.warning(f"Could not initialize Cloud SQL Admin API client: {e}")
                self.sql = None
        else:
            self.sql = None

        # GKE Container API
        if container_service is not None:
            self.container = container_service
        elif creds:
            try:
                self.container = _build_thread_safe("container", "v1", creds)
            except Exception as e:
                logger.warning(f"Could not initialize GKE Container API client: {e}")
                self.container = None
        else:
            self.container = None

        # Cloud Billing API
        if billing_service is not None:
            self.billing = billing_service
        elif creds:
            try:
                self.billing = _build_thread_safe("cloudbilling", "v1", creds)
            except Exception as e:
                logger.warning(f"Could not initialize Cloud Billing API client: {e}")
                self.billing = None
        else:
            self.billing = None

        # Cloud Resource Manager v1 (FD-4O target guard: projects.getAncestry)
        if crm_service is not None:
            self.crm = crm_service
        elif creds:
            try:
                self.crm = _build_thread_safe("cloudresourcemanager", "v1", creds)
            except Exception as e:
                logger.warning(f"Could not initialize Cloud Resource Manager API client: {e}")
                self.crm = None
        else:
            self.crm = None

        # FD-4CI-b-R2: the budget-breach card recommendation (Settings > FinOps Agent Model), with the same
        # credentials. Without credentials it is unavailable and cards are written exactly as before.
        self.advisor = advisor if advisor is not None else _default_advisor(self.platform_project_id, creds)
        self._advisor_threads: List[threading.Thread] = []
        # RT14-05: the restore's live-state check (bounded poll; replaced in tests)
        self.restore_verify_wait_s = RESTORE_VERIFY_WAIT_S
        self.restore_verify_poll_s = RESTORE_VERIFY_POLL_S
        self._clock = time.monotonic
        self._sleep = time.sleep

    # --------------------------------------------------------------------------
    # FD-4CI-b-R2: budget-breach card recommendation (never blocks or delays enforcement)
    # --------------------------------------------------------------------------
    def _start_recommendation(self, approval_id: str, product_id: str, spend_amount: float,
                              budget_amount: float) -> None:
        """Starts the one advisor call for a card that was just written, in a daemon thread (the enforcement action
        is already done). No advisor / no credentials / no Firestore: nothing is started (the card stays as written)."""
        adv = self.advisor
        if adv is None or not getattr(adv, "available", False) or self.db is None:
            logger.info(f"FinOps recommendation for {approval_id} not requested (advisor unavailable)")
            return
        thread = threading.Thread(target=adv.recommend, args=(self.db, approval_id, product_id, spend_amount,
                                                              budget_amount),
                                  name=f"finops-advisor-{approval_id}", daemon=True)
        thread.start()
        self._advisor_threads.append(thread)

    def wait_for_recommendations(self, timeout_s: float = ADVISOR_WAIT_S) -> bool:
        """Waits at most `timeout_s` seconds in total for the recommendations this engine started (the Cloud Run job
        calls it after its run record is final, so the process does not exit mid-call). True when all finished."""
        deadline = time.monotonic() + max(0.0, timeout_s)
        for thread in list(self._advisor_threads):
            thread.join(max(0.0, deadline - time.monotonic()))
        self._advisor_threads = [t for t in self._advisor_threads if t.is_alive()]
        return not self._advisor_threads

    # --------------------------------------------------------------------------
    # FD-4O target guard (Invariant 5: never touch the host project)
    # --------------------------------------------------------------------------
    def authorize_target(self, target_project_id: Optional[str]) -> str:
        """Returns the project id when the enforcer may act on it; raises QuarantineTargetRefused otherwise.
        Fails closed on every uncertainty. Exact field comparisons on the Resource Manager ancestry, no string
        matching: the managed root folder must appear as a `folder` ancestor (not the project itself)."""
        proj = (target_project_id or "").strip()
        if not proj:
            raise QuarantineTargetRefused("target_project_id is required (no fallback to the platform project)")
        host_ids = {p for p in (self.platform_project_id, os.getenv("PROJECT_ID", ""), os.getenv("GOOGLE_CLOUD_PROJECT", "")) if p}
        if proj in host_ids:
            raise QuarantineTargetRefused(f"refusing to act on the host platform project '{proj}'")
        root = _normalize_folder_id(os.getenv("MANAGED_WORKLOADS_FOLDER_ID", ""))
        if not root:
            raise QuarantineTargetRefused("MANAGED_WORKLOADS_FOLDER_ID is not configured")
        if self.crm is None:
            raise QuarantineTargetRefused("Resource Manager client unavailable; cannot verify project ancestry")
        try:
            resp = self.crm.projects().getAncestry(projectId=proj, body={}).execute() or {}
            ancestors = resp.get("ancestor") or []
            host_numbers = set()
            for hid in host_ids:
                try:
                    host_numbers.add(str(self.crm.projects().get(projectId=hid).execute().get("projectNumber") or ""))
                except Exception as e:  # noqa: BLE001 - host lookup failure => cannot rule out aliasing
                    raise QuarantineTargetRefused(f"cannot resolve host project number: {e}")
            target_number = str(self.crm.projects().get(projectId=proj).execute().get("projectNumber") or "")
        except QuarantineTargetRefused:
            raise
        except Exception as e:  # noqa: BLE001
            raise QuarantineTargetRefused(f"ancestry lookup failed for '{proj}': {e}")
        if not target_number or target_number in host_numbers:
            raise QuarantineTargetRefused(f"'{proj}' resolves to the host project (or has no project number)")
        under_root = any(
            isinstance(a, dict)
            and (a.get("resourceId") or {}).get("type") == "folder"
            and str((a.get("resourceId") or {}).get("id")) == root
            for a in ancestors[1:]
        )
        if not under_root:
            raise QuarantineTargetRefused(f"'{proj}' is not a descendant of folders/{root}")
        return proj

    def _refused(self, product_id: str, target_project_id: Optional[str], action: str, reason: str) -> Dict[str, Any]:
        logger.error(f"FinOps {action} REFUSED for '{product_id}' (target {target_project_id!r}): {reason}")
        return {"status": "REFUSED", "product_id": product_id, "project_id": target_project_id, "action": action,
                "reason": reason}

    def _region_refused(self, product_id: str, target_project_id: Optional[str], action: str,
                        err: "WorkloadRegionRefused") -> Dict[str, Any]:
        """FD-7M-a: the typed REFUSED body (409 on /enforce and /restore) with the region `error_class`."""
        out = self._refused(product_id, target_project_id, action, str(err))
        out["error_class"] = err.error_class
        return out

    # --------------------------------------------------------------------------
    # Budget-breach records (billing alert, BUDGET_BREACH approval card); the caller handles a write failure
    # --------------------------------------------------------------------------
    def _write_billing_alert(self, product_id: str, proj_id: str, tr_id: str, spend_amount: float,
                             budget_amount: float, policy: str, now_iso: str, severity: str, message: str) -> None:
        self.db.collection("billing_alerts").add({
            "product_id": product_id,
            "project_id": proj_id,
            "trace_id": tr_id,
            "spend_amount": spend_amount,
            "budget_amount": budget_amount,
            "policy": policy,
            "created_at": now_iso,
            "severity": severity,
            "message": message,
        })

    def _write_budget_breach_card(self, approval_id: str, product_id: str, proj_id: str, tr_id: str,
                                  spend_amount: float, budget_amount: float, now_iso: str, risk_assessment: str,
                                  quarantined_resources: List[str]) -> None:
        self.db.collection("approval_requests").document(approval_id).set({
            "approval_id": approval_id,
            "approval_type": "BUDGET_BREACH",
            "product_id": product_id,
            "target_project_id": proj_id,
            "trace_id": tr_id,
            "cost_delta_monthly": f"${spend_amount:.2f}/mo (Ceiling: ${budget_amount:.2f})",
            "risk_assessment": risk_assessment,
            "status": "PENDING",
            "requested_at": now_iso,
            "current_spend_usd": spend_amount,
            "budget_ceiling_usd": budget_amount,
            "buffer_ceiling_usd": round(budget_amount * 1.15, 2),
            "quarantined_resources": quarantined_resources,
        })

    def _record_unenforced_breach(self, product_id: str, proj_id: str, tr_id: str, spend_amount: float,
                                  budget_amount: float, policy: str, now_iso: str,
                                  err: "WorkloadRegionRefused") -> Dict[str, Any]:
        """SAT-23 RT Q3: a scale-to-zero refused for the workload's region leaves the breach visible to an operator:
        the existing billing alert and BUDGET_BREACH approval card (nothing quarantined). Nothing is recorded as
        enforced, so the next scheduled enforcement retries. Returns {"approval_id": ...} when the card was written."""
        if not self.db:
            return {}
        approval_id = f"appr-budget-{product_id}-{uuid.uuid4().hex[:6]}"
        reason = (f"Budget breach NOT enforced (${spend_amount:.2f} / ${budget_amount:.2f}): the workload's Cloud Run "
                  f"region could not be established ({err.error_class}); nothing was scaled. {err}")
        out: Dict[str, Any] = {}
        try:
            self._write_billing_alert(product_id, proj_id, tr_id, spend_amount, budget_amount, policy, now_iso,
                                      "ERROR", reason)
        except Exception as e:
            logger.warning(f"Could not record billing alert in Firestore: {e}")
        try:
            self._write_budget_breach_card(approval_id, product_id, proj_id, tr_id, spend_amount, budget_amount,
                                           now_iso, reason, [])
            out["approval_id"] = approval_id
        except Exception as e:
            logger.warning(f"Could not record the unenforced budget-breach approval request in Firestore: {e}")
        return out

    # --------------------------------------------------------------------------
    # FD-7M-a: the workload's own region (Cloud Run list / scale)
    # --------------------------------------------------------------------------
    def resolve_workload_region(self, product_id: str) -> str:
        """The region the workload's Cloud Run services run in: workloads/{product_id}.region through the one settings
        helper `shared.settings.workload_region` (approved list from system_config/platform_settings, read with this
        engine's Firestore client). A record without a region (created before FD-7M-a) -> Settings
        `default_gcp_region`, where the platform deployed it. Raises WorkloadRegionRefused (REGION_NOT_APPROVED /
        REGION_UNAVAILABLE); never another region. Without a Firestore store (no client, or a client whose answer is
        not a Firestore snapshot: direct callers and test doubles) -> the engine's `region`, as before; but no client
        while a platform project is configured -> REGION_UNAVAILABLE (SAT-23 RT F1, as the terraform server). A blank
        stored `default_gcp_region` -> REGION_UNAVAILABLE (RT F2: never `locations//services`)."""
        if self.db is None:
            if self.platform_project_id:
                raise WorkloadRegionRefused("REGION_UNAVAILABLE", "no Firestore client although a platform project "
                                                                  "is configured")
            return self.region
        try:
            snap = self.db.collection("workloads").document(product_id).get()
        except Exception as e:  # noqa: BLE001 - unreadable record = unknown region (typed)
            raise WorkloadRegionRefused("REGION_UNAVAILABLE", f"workloads/{product_id} unreadable: "
                                                              f"{type(e).__name__}: {e}") from e
        exists = getattr(snap, "exists", None)
        if exists is True:
            data = snap.to_dict()
            if not isinstance(data, dict):
                raise WorkloadRegionRefused("REGION_UNAVAILABLE", f"workloads/{product_id} is not a document")
            record_region = data.get("region")
        elif exists is False:
            record_region = None
        else:
            return self.region
        orchestration = self._orchestration_settings()
        if "default_gcp_region" in orchestration and not orchestration.get("default_gcp_region"):
            raise WorkloadRegionRefused("REGION_UNAVAILABLE", "settings default_gcp_region is blank")
        try:
            from shared.settings import RegionNotApproved, workload_region
        except ImportError as e:
            raise WorkloadRegionRefused("REGION_UNAVAILABLE", f"settings contract not importable: {e}") from e
        try:
            region = workload_region(record_region, orchestration, stage="finops_enforcer")
        except RegionNotApproved as e:
            raise WorkloadRegionRefused("REGION_NOT_APPROVED", str(e)) from e
        except (TypeError, ValueError) as e:   # an invalid stored orchestration (pydantic: ValueError)
            raise WorkloadRegionRefused("REGION_UNAVAILABLE", f"settings invalid: {type(e).__name__}: {e}") from e
        if not isinstance(region, str) or not region:
            raise WorkloadRegionRefused("REGION_UNAVAILABLE", "settings default_gcp_region is blank")
        return region

    def _orchestration_settings(self) -> Dict[str, Any]:
        """FD-7M-a: the stored `orchestration` mapping of system_config/platform_settings (no document = {} = the
        schema defaults). A failed read, a non-snapshot answer or a non-mapping value -> WorkloadRegionRefused."""
        try:
            snap = self.db.collection("system_config").document("platform_settings").get()
            exists = getattr(snap, "exists", None)
            if exists is False:
                return {}
            data = snap.to_dict() if exists is True else None
        except Exception as e:  # noqa: BLE001 - unreadable settings = approval unknown (typed)
            raise WorkloadRegionRefused("REGION_UNAVAILABLE", f"platform settings unreadable: "
                                                              f"{type(e).__name__}: {e}") from e
        if not isinstance(data, dict):
            raise WorkloadRegionRefused("REGION_UNAVAILABLE", "platform settings gave no answer")
        orchestration = data.get("orchestration")
        if orchestration is None:
            return {}
        if not isinstance(orchestration, dict):
            raise WorkloadRegionRefused("REGION_UNAVAILABLE", "platform settings orchestration is not a mapping")
        return orchestration

    # --------------------------------------------------------------------------
    # Cloud Run Multi-Service Controls
    # --------------------------------------------------------------------------
    def list_workload_services(self, target_project_id: str, region: Optional[str] = None,
                               strict: bool = False) -> List[Dict[str, Any]]:
        """Lists all Cloud Run v2 services and their scaling configurations within the target workload project.
        FD-7M-a: `region` = the workload's region (resolve_workload_region); None = the engine's region (direct
        callers). RT14-05: a service without maxInstanceCount is recorded as max None (never a guessed 5; a service
        scaled to zero reads that way). RT14-20: `strict` (snapshot / restore check) pages through every result and
        raises LiveStateReadError instead of answering [] on a failed or missing read."""
        if not self.run:
            if strict:
                raise LiveStateReadError("cloud_run", "no Cloud Run client")
            return []

        parent = f"projects/{target_project_id}/locations/{region or self.region}"
        try:
            results = []
            token = None
            while True:
                kwargs = {"parent": parent}
                if token:
                    kwargs["pageToken"] = token
                res = self.run.projects().locations().services().list(**kwargs).execute()
                if not isinstance(res, dict):
                    if strict:
                        raise LiveStateReadError("cloud_run", f"no list answer for {parent}")
                    res = {}
                for s in res.get("services", []):
                    name = s.get("name", "").split("/")[-1]
                    scaling = s.get("template", {}).get("scaling", {})
                    results.append({
                        "name": name,
                        "max_instances": scaling.get("maxInstanceCount"),
                        "min_instances": scaling.get("minInstanceCount", 0),
                    })
                token = res.get("nextPageToken")
                if not (strict and isinstance(token, str) and token):
                    return results
        except LiveStateReadError:
            raise
        except HttpError as e:
            if strict:
                raise LiveStateReadError("cloud_run", f"list failed in {parent}: {e}") from e
            logger.warning(f"Could not list Cloud Run services in {target_project_id}: {e}")
            return []
        except Exception as e:  # noqa: BLE001 - strict reads are typed; the lenient read keeps its old answer
            if strict:
                raise LiveStateReadError("cloud_run", f"list failed in {parent}: {type(e).__name__}: {e}") from e
            raise

    def set_service_scaling(
        self, target_project_id: str, service_name: str, max_instances: Optional[int], min_instances: int = 0,
        region: Optional[str] = None,
    ) -> bool:
        """Updates scaling limits on a Cloud Run v2 service. FD-7M-a: `region` = the workload's region; None = the
        engine's region (direct callers). C10 (RT D3): max_instances None leaves the max unchanged (min only)."""
        if not self.run:
            logger.info(f"Mock scaling update for {service_name} (max: {max_instances}, min: {min_instances})")
            return True

        name = f"projects/{target_project_id}/locations/{region or self.region}/services/{service_name}"
        try:
            scaling: Dict[str, Any] = {"minInstanceCount": min_instances}
            mask = "template.scaling.minInstanceCount"
            if max_instances is not None:
                scaling = {"maxInstanceCount": max_instances, "minInstanceCount": min_instances}
                mask = "template.scaling.maxInstanceCount,template.scaling.minInstanceCount"
            patch_body = {"template": {"scaling": scaling}}
            self.run.projects().locations().services().patch(
                name=name,
                updateMask=mask,
                body=patch_body,
            ).execute()
            logger.info(f"Updated scaling on '{service_name}': max={max_instances}, min={min_instances}")
            return True
        except HttpError as e:
            logger.error(f"Failed to update scaling on '{service_name}': {e}")
            return False

    # --------------------------------------------------------------------------
    # Compute Engine VM Controls
    # --------------------------------------------------------------------------
    def list_running_vms(self, target_project_id: str, strict: bool = False) -> List[Dict[str, Any]]:
        """Inspects all GCE instances across aggregated zones in the target project. RT14-20: `strict` raises
        LiveStateReadError on a failed read or an unreachable zone (Compute Engine API not enabled = no VMs)."""
        if not self.compute:
            if strict:
                raise LiveStateReadError("compute_vms", "no Compute Engine client")
            return []

        results = []
        try:
            req = self.compute.instances().aggregatedList(project=target_project_id)
            while req is not None:
                resp = req.execute()
                if strict and not isinstance(resp, dict):
                    raise LiveStateReadError("compute_vms", "no aggregatedList answer")
                if strict and resp.get("unreachables"):
                    raise LiveStateReadError("compute_vms", f"unreachable zones: {resp.get('unreachables')}")
                for zone_scoped in resp.get("items", {}).values():
                    instances = zone_scoped.get("instances", [])
                    for inst in instances:
                        zone = inst.get("zone", "").split("/")[-1]
                        results.append({
                            "name": inst.get("name"),
                            "zone": zone,
                            "status": inst.get("status"),  # RUNNING, TERMINATED, etc.
                        })
                req = self.compute.instances().aggregatedList_next(previous_request=req, previous_response=resp)
        except LiveStateReadError:
            raise
        except Exception as e:
            if strict:
                if _api_disabled(e):
                    return []
                raise LiveStateReadError("compute_vms", f"{type(e).__name__}: {e}") from e
            logger.warning(f"Could not list GCE instances in {target_project_id}: {e}")
        return results

    def stop_vms(self, target_project_id: str, vms: List[Dict[str, Any]]) -> List[str]:
        """Stops active Compute Engine VMs."""
        stopped = []
        for vm in vms:
            name = vm.get("name")
            zone = vm.get("zone")
            if not self.compute:
                stopped.append(f"{zone}/{name}")
                continue
            try:
                self.compute.instances().stop(project=target_project_id, zone=zone, instance=name).execute()
                logger.info(f"Stopped GCE VM {name} in {zone}")
                stopped.append(f"{zone}/{name}")
            except Exception as e:
                logger.error(f"Failed to stop VM {name}: {e}")
        return stopped

    def start_vms(self, target_project_id: str, vms: List[Dict[str, Any]]) -> List[str]:
        """Restores (starts) previously running Compute Engine VMs."""
        started = []
        for vm in vms:
            name = vm.get("name")
            zone = vm.get("zone")
            if not self.compute:
                started.append(f"{zone}/{name}")
                continue
            try:
                self.compute.instances().start(project=target_project_id, zone=zone, instance=name).execute()
                logger.info(f"Started GCE VM {name} in {zone}")
                started.append(f"{zone}/{name}")
            except Exception as e:
                logger.error(f"Failed to start VM {name}: {e}")
        return started

    # --------------------------------------------------------------------------
    # Cloud SQL Controls
    # --------------------------------------------------------------------------
    def list_cloud_sql_instances(self, target_project_id: str, strict: bool = False) -> List[Dict[str, Any]]:
        """Lists all Cloud SQL instances and their activation policies. RT14-20: `strict` pages through every result
        and raises LiveStateReadError on a failed read (Cloud SQL Admin API not enabled = no instances)."""
        if not self.sql:
            if strict:
                raise LiveStateReadError("cloud_sql", "no Cloud SQL Admin client")
            return []
        try:
            items: List[Dict[str, Any]] = []
            token = None
            while True:
                kwargs = {"project": target_project_id}
                if token:
                    kwargs["pageToken"] = token
                resp = self.sql.instances().list(**kwargs).execute()
                if not isinstance(resp, dict):
                    if strict:
                        raise LiveStateReadError("cloud_sql", "no list answer")
                    resp = {}
                items += resp.get("items", [])
                token = resp.get("nextPageToken")
                if not (strict and isinstance(token, str) and token):
                    break
            return [
                {
                    "name": item.get("name"),
                    "activation_policy": item.get("settings", {}).get("activationPolicy", "ALWAYS"),
                }
                for item in items
            ]
        except LiveStateReadError:
            raise
        except Exception as e:
            if strict:
                if _api_disabled(e):
                    return []
                raise LiveStateReadError("cloud_sql", f"{type(e).__name__}: {e}") from e
            logger.warning(f"Could not list Cloud SQL instances in {target_project_id}: {e}")
            return []

    def set_cloud_sql_activation(self, target_project_id: str, instance_name: str, activation_policy: str) -> bool:
        """Sets activation policy on Cloud SQL ('NEVER' to shut off, 'ALWAYS' to resume)."""
        if not self.sql:
            logger.info(f"Mock Cloud SQL activationPolicy={activation_policy} for {instance_name}")
            return True
        try:
            body = {"settings": {"activationPolicy": activation_policy}}
            self.sql.instances().patch(project=target_project_id, instance=instance_name, body=body).execute()
            logger.info(f"Cloud SQL '{instance_name}' activationPolicy updated to {activation_policy}")
            return True
        except Exception as e:
            logger.error(f"Failed to set Cloud SQL activationPolicy for {instance_name}: {e}")
            return False

    # --------------------------------------------------------------------------
    # GKE Node Pool Controls
    # --------------------------------------------------------------------------
    def list_gke_pools(self, target_project_id: str, strict: bool = False) -> List[Dict[str, Any]]:
        """Lists GKE clusters and node pool sizes. RT14-20: `strict` raises LiveStateReadError on a failed read or
        missing zones (Kubernetes Engine API not enabled = no clusters)."""
        if not self.container:
            if strict:
                raise LiveStateReadError("gke_pools", "no GKE client")
            return []
        parent = f"projects/{target_project_id}/locations/-"
        results = []
        try:
            resp = self.container.projects().locations().clusters().list(parent=parent).execute()
            if strict and not isinstance(resp, dict):
                raise LiveStateReadError("gke_pools", "no list answer")
            if strict and resp.get("missingZones"):
                raise LiveStateReadError("gke_pools", f"missing zones: {resp.get('missingZones')}")
            clusters = resp.get("clusters", [])
            for c in clusters:
                cluster_name = c.get("name")
                location = c.get("location")
                for pool in c.get("nodePools", []):
                    results.append({
                        "cluster_name": cluster_name,
                        "location": location,
                        "pool_name": pool.get("name"),
                        "node_count": pool.get("initialNodeCount", 1),
                    })
        except LiveStateReadError:
            raise
        except Exception as e:
            if strict:
                if _api_disabled(e):
                    return []
                raise LiveStateReadError("gke_pools", f"{type(e).__name__}: {e}") from e
            logger.warning(f"Could not list GKE clusters in {target_project_id}: {e}")
        return results

    def scale_gke_pool(self, target_project_id: str, location: str, cluster_name: str, pool_name: str, node_count: int) -> bool:
        """Scales a GKE node pool."""
        if not self.container:
            logger.info(f"Mock GKE scaling for {pool_name} in {cluster_name} to {node_count}")
            return True
        try:
            name = f"projects/{target_project_id}/locations/{location}/clusters/{cluster_name}/nodePools/{pool_name}"
            body = {"nodeCount": node_count}
            self.container.projects().locations().clusters().nodePools().setSize(name=name, body=body).execute()
            logger.info(f"Scaled GKE pool {pool_name} to {node_count} nodes")
            return True
        except Exception as e:
            logger.error(f"Failed to scale GKE pool {pool_name}: {e}")
            return False

    # --------------------------------------------------------------------------
    # Cloud Billing Detach & Re-link
    # --------------------------------------------------------------------------
    def _billing_mock_allowed(self) -> bool:
        """C10 (RT D1): the no-client "mock" success exists for TEST_MODE only; elsewhere a missing billing client is a
        failure (fail loudly), never a pretended unlink / relink."""
        return os.getenv("TEST_MODE") == "true"

    def billing_account_of(self, target_project_id: str) -> Optional[str]:
        """The project's current billing account (`billingAccounts/...`), or None (unreadable, none, or no client)."""
        if not self.billing:
            return None
        try:
            info = self.billing.projects().getBillingInfo(name=f"projects/{target_project_id}").execute() or {}
        except Exception as e:  # noqa: BLE001 - the caller records None and says so
            logger.error(f"Could not read the billing account of {target_project_id}: {e}")
            return None
        name = info.get("billingAccountName") if isinstance(info, dict) else None
        return name if isinstance(name, str) and name.startswith("billingAccounts/") else None

    def unlink_billing_account(self, target_project_id: str) -> bool:
        """Detaches the Google Cloud Billing Account entirely from the child project."""
        if not self.billing:
            if self._billing_mock_allowed():
                logger.info(f"Mock unlinked billing account from project {target_project_id}")
                return True
            logger.error(f"BILLING_CLIENT_UNAVAILABLE: cannot unlink billing from {target_project_id}")
            return False
        try:
            name = f"projects/{target_project_id}"
            body = {"billingAccountName": ""}
            self.billing.projects().updateBillingInfo(name=name, body=body).execute()
            logger.warning(f"Detached billing account from project {target_project_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to unlink billing account from {target_project_id}: {e}")
            return False

    def relink_billing_account(self, target_project_id: str, root_billing_account: str) -> bool:
        """Re-attaches the Google Cloud Billing Account to the child project."""
        clean_account = root_billing_account.strip()
        if not clean_account.startswith("billingAccounts/"):
            clean_account = f"billingAccounts/{clean_account}"

        if not self.billing:
            if self._billing_mock_allowed():
                logger.info(f"Mock re-linked billing account {clean_account} to {target_project_id}")
                return True
            logger.error(f"BILLING_CLIENT_UNAVAILABLE: cannot re-link billing to {target_project_id}")
            return False
        try:
            name = f"projects/{target_project_id}"
            body = {"billingAccountName": clean_account}
            self.billing.projects().updateBillingInfo(name=name, body=body).execute()
            logger.info(f"Successfully re-linked billing account {clean_account} to project {target_project_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to re-link billing account for {target_project_id}: {e}")
            return False

    # --------------------------------------------------------------------------
    # State Snapshotting (Pre-Quarantine State)
    # --------------------------------------------------------------------------
    def take_pre_quarantine_snapshot(self, product_id: str, target_project_id: str,
                                     region: Optional[str] = None) -> Dict[str, Any]:
        """
        Reads the live state of every compute resource and makes it durable in `quarantine_snapshots/{product_id}`
        BEFORE anything is scaled down. FD-7M-a: Cloud Run services are listed in `region` (the workload's region).
        RT14-20: the reads are strict (a failed read is SNAPSHOT_READ_FAILED, never an empty list) and the snapshot is
        written with create(); a write that fails is SNAPSHOT_PERSIST_FAILED. Both raise QuarantineStateError and
        nothing has been changed. RT14-05: an existing snapshot is never overwritten (see _persist_snapshot).
        Returns the live state (what the quarantine stops) with `durable_snapshot`: the snapshot the restore uses.
        """
        try:
            live = {
                "cloud_run_services": self.list_workload_services(target_project_id, region=region, strict=True),
                "compute_vms": self.list_running_vms(target_project_id, strict=True),
                "cloud_sql": self.list_cloud_sql_instances(target_project_id, strict=True),
                "gke_pools": self.list_gke_pools(target_project_id, strict=True),
            }
        except LiveStateReadError as e:
            raise QuarantineStateError("SNAPSHOT_READ_FAILED", f"the live state of '{target_project_id}' could not be "
                                                               f"read ({e}); nothing was changed") from e
        snapshot = {
            "product_id": product_id,
            "project_id": target_project_id,
            "quarantined_at": datetime.now(timezone.utc).isoformat(),
            "snapshot_version": SNAPSHOT_VERSION,
            **live,
        }
        durable = self._persist_snapshot(product_id, snapshot)
        logger.info(f"Captured pre-quarantine snapshot for {product_id} in Firestore.")
        return dict(snapshot, durable_snapshot=durable)

    def _persist_snapshot(self, product_id: str, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """RT14-20 / RT14-05: create() the snapshot. When one already exists (an earlier quarantine was interrupted
        after its snapshot and before its quarantine record), that snapshot holds the state before the first attempt
        and its entries are kept: resources it does not list (created since) are added with their live values, and
        (RT14 F1) a kept entry is replaced by the live one only when the live read shows that resource serving now
        (_running_now: the quarantine stops it, so the restore must start it again); a resource the interrupted
        attempt stopped keeps its kept entry. Written under a last-update-time precondition. Raises
        QuarantineStateError(SNAPSHOT_PERSIST_FAILED); returns the durable snapshot."""
        if self.db is None:
            raise QuarantineStateError("SNAPSHOT_PERSIST_FAILED", "no Firestore client, so the pre-quarantine snapshot "
                                                                  "cannot be kept; nothing was changed")
        ref = self.db.collection("quarantine_snapshots").document(product_id)
        try:
            ref.create(snapshot)
            return snapshot
        except Exception as e:  # noqa: BLE001 - classified below
            if not _is_already_exists(e):
                raise QuarantineStateError("SNAPSHOT_PERSIST_FAILED", f"quarantine_snapshots/{product_id} could not be "
                                                                      f"written ({type(e).__name__}: {e}); nothing "
                                                                      "was changed") from e
        try:
            prior_snap = ref.get()
            prior = prior_snap.to_dict() if getattr(prior_snap, "exists", None) is True else None
        except Exception as e:  # noqa: BLE001 - typed
            raise QuarantineStateError("SNAPSHOT_PERSIST_FAILED", f"the existing quarantine_snapshots/{product_id} "
                                                                  f"could not be read ({type(e).__name__}); nothing "
                                                                  "was changed") from e
        if not isinstance(prior, dict):
            raise QuarantineStateError("SNAPSHOT_PERSIST_FAILED", f"quarantine_snapshots/{product_id} changed while "
                                                                  "it was written; nothing was changed")
        additions: Dict[str, List[Dict[str, Any]]] = {}
        added = replaced = 0
        for field, key in _SNAPSHOT_KEYS.items():
            live = {key(e): e for e in snapshot.get(field) or [] if isinstance(e, dict)}
            kept: List[Any] = []
            field_replaced = 0
            for entry in prior.get(field) or []:
                cur = live.get(key(entry)) if isinstance(entry, dict) else None
                if cur is not None and cur != entry and _running_now(field, cur):
                    kept.append(cur)          # RT14 F1: serving now -> the restore must bring this state back
                    field_replaced += 1
                else:
                    kept.append(entry)
            known = {key(e) for e in kept if isinstance(e, dict)}
            new = [e for e in live.values() if key(e) not in known]
            if new or field_replaced:
                additions[field] = kept + new
                added += len(new)
                replaced += field_replaced
        if not additions:
            logger.warning(f"Quarantine of '{product_id}' resumes an interrupted one; its snapshot is kept unchanged")
            return prior
        try:
            ref.update(additions, option=self.db.write_option(last_update_time=prior_snap.update_time))
        except Exception as e:  # noqa: BLE001 - typed (a concurrent writer fails the precondition)
            raise QuarantineStateError("SNAPSHOT_PERSIST_FAILED", f"the kept snapshot could not be updated with "
                                                                  f"resources created since or serving now ({type(e).__name__}: {e}); nothing "
                                                                  "was changed") from e
        logger.warning(f"Quarantine of '{product_id}' resumes an interrupted one; its snapshot is kept, {added} "
                       f"resource(s) created since were added and {replaced} entry(ies) of resources serving now "
                       "were replaced by their live state")
        return {**prior, **additions}

    def _existing_enforcement(self, product_id: str, proj_id: str) -> Optional[Dict[str, Any]]:
        """RT14-05: the outcome of an enforcement already in place, or None. A quarantine record, or a workload status
        in ALREADY_ENFORCED_STATUSES, means a second breach changes nothing (the snapshot, the recorded billing
        account and the compute stay as they are). A read failure raises QUARANTINE_STATE_UNREADABLE (fail closed).
        Without a Firestore client there is no marker to read (the durable-record step then refuses)."""
        if self.db is None:
            return None
        try:
            rec_snap = self.db.collection("quarantined_workloads").document(product_id).get()
            wl_snap = self.db.collection("workloads").document(product_id).get()
        except Exception as e:  # noqa: BLE001 - typed, nothing changed
            raise QuarantineStateError("QUARANTINE_STATE_UNREADABLE", f"the quarantine markers of '{product_id}' could "
                                                                      f"not be read ({type(e).__name__}: {e}); nothing "
                                                                      "was changed") from e
        record = rec_snap.to_dict() if getattr(rec_snap, "exists", None) is True else None
        workload = wl_snap.to_dict() if getattr(wl_snap, "exists", None) is True else None
        status = workload.get("status") if isinstance(workload, dict) else None
        if not isinstance(record, dict) and status not in ALREADY_ENFORCED_STATUSES:
            return None
        rec = record if isinstance(record, dict) else {}
        outcome = "BILLING_UNLINKED" if status == "BILLING_UNLINKED" else "QUARANTINED"
        logger.warning(json.dumps({"event": "BUDGET_BREACH_ALREADY_ENFORCED", "product_id": product_id,
                                   "outcome": outcome, "quarantined_at": rec.get("quarantined_at")}))
        return {
            "status": outcome,
            "product_id": product_id,
            "project_id": proj_id,
            "already_enforced": True,
            "approval_id": rec.get("approval_id"),
            "policy": rec.get("policy"),
            "quarantined_at": rec.get("quarantined_at"),
            "quarantined_resources": list(rec.get("quarantined_resources") or []),
            "reason": f"'{product_id}' is already {outcome}; nothing was changed (the pre-quarantine snapshot and the "
                      "recorded billing account are kept for the restore)",
        }

    def _state_failure(self, product_id: str, proj_id: str, policy: str,
                       err: QuarantineStateError) -> Dict[str, Any]:
        """The typed body of a QuarantineStateError (status = its class; never an enforced outcome)."""
        logger.error(json.dumps({"error_class": err.error_class, "stage": err.stage, "product_id": product_id,
                                 "project_id": proj_id, "detail": str(err)[:500]}))
        return {"status": err.error_class, "error_class": err.error_class, "stage": err.stage,
                "product_id": product_id, "project_id": proj_id, "policy": policy, "reason": str(err)}

    def _commit(self, writes: List[Tuple[Any, ...]]) -> None:
        """Writes the quarantine / restore markers together (one Firestore batch): ("set", ref, data[, merge]) or
        ("delete", ref). Raises on failure; the caller answers a typed outcome."""
        batch = self.db.batch()
        for op, ref, *rest in writes:
            if op == "set":
                batch.set(ref, rest[0], merge=bool(rest[1]) if len(rest) > 1 else False)
            else:
                batch.delete(ref)
        batch.commit()

    def _restore_markers(self, product_id: str, workload_data: Dict[str, Any]
                         ) -> Tuple[Optional[Dict[str, Any]], bool, Optional[Dict[str, Any]]]:
        """(snapshot or None, quarantined?, quarantine record or None) read strictly: a read failure raises (the
        restore fails closed)."""
        if not self.db:
            raise RuntimeError("no Firestore client")
        snap = self.db.collection("quarantine_snapshots").document(product_id).get()
        snapshot = (snap.to_dict() or {}) if getattr(snap, "exists", False) else None
        rec = self.db.collection("quarantined_workloads").document(product_id).get()
        record = rec.to_dict() if getattr(rec, "exists", False) else None
        quarantined = bool(getattr(rec, "exists", False)) or workload_data.get("status") == "QUARANTINED"
        return snapshot, quarantined, (record if isinstance(record, dict) else None)

    def get_quarantine_snapshot(self, product_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves the pre-quarantine state snapshot for a workload."""
        if not self.db:
            return None
        try:
            doc = self.db.collection("quarantine_snapshots").document(product_id).get()
            if doc.exists:
                return doc.to_dict()
        except Exception as e:
            logger.warning(f"Could not read quarantine snapshot for {product_id}: {e}")
        return None

    # --------------------------------------------------------------------------
    # Core Quarantine Execution
    # --------------------------------------------------------------------------
    def quarantine_workload(
        self,
        product_id: str,
        target_project_id: Optional[str] = None,
        trace_id: Optional[str] = None,
        spend_amount: float = 0.0,
        budget_amount: float = 0.0,
        policy: Optional[str] = "AUTONOMOUS_SCALE_TO_ZERO",
    ) -> Dict[str, Any]:
        """
        Executes budget enforcement based on policy:
        1. ALERT_ONLY: logs/dispatches alert, leaves compute active.
        2. NUCLEAR_UNLINK_BILLING: records the billing account, then detaches it.
        3. HITL_CONFIRMATION_REQUIRED: opens pending approval card, leaves compute untouched until decision.
        4. AUTONOMOUS_SCALE_TO_ZERO: makes the pre-quarantine snapshot durable, stops Cloud Run, GCE, Cloud SQL, GKE,
           and records the quarantine (record, status QUARANTINED, approval card) in one batch.
        RT14-05: the destructive policies (2 and 4) are idempotent: an enforcement already in place answers its outcome
        and changes nothing. RT14-20: they never act without a durable record; every stop is a typed status
        (QuarantineStateError classes), never an enforced outcome.
        """
        try:
            proj_id = self.authorize_target(target_project_id)
        except QuarantineTargetRefused as refused:
            return self._refused(product_id, target_project_id, "QUARANTINE", str(refused))
        tr_id = trace_id or f"kill-{uuid.uuid4().hex[:8]}"
        now_iso = datetime.now(timezone.utc).isoformat()

        # Policy Resolution
        resolved_policy = str(policy or BudgetBreachPolicy.AUTONOMOUS_SCALE_TO_ZERO.value).upper()

        logger.warning(
            f"🚨 FINOPS ENFORCER TRIGGERED for '{product_id}' (Project: {proj_id}). "
            f"Spend: ${spend_amount:.2f} / Budget: ${budget_amount:.2f} [Policy: {resolved_policy}]"
        )

        # 1. ALERT ONLY
        if resolved_policy == BudgetBreachPolicy.ALERT_ONLY.value:
            logger.info(f"Workload '{product_id}' configured for ALERT_ONLY. Skipping compute shutdown.")
            if self.db:
                try:
                    self._write_billing_alert(
                        product_id, proj_id, tr_id, spend_amount, budget_amount, resolved_policy, now_iso, "WARNING",
                        f"Workload {product_id} exceeded budget ceiling (${spend_amount:.2f} / ${budget_amount:.2f})")
                except Exception as e:
                    logger.warning(f"Could not record billing alert in Firestore: {e}")
            return {
                "status": "ALERTED_ONLY",
                "product_id": product_id,
                "project_id": proj_id,
                "policy": resolved_policy,
                "spend_amount": spend_amount,
                "budget_amount": budget_amount,
                "scaled_services": [],
            }

        # 2. NUCLEAR UNLINK BILLING
        if resolved_policy == BudgetBreachPolicy.NUCLEAR_UNLINK_BILLING.value:
            # RT14-05: already unlinked or quarantined -> nothing changes (a second unlink would record no account)
            try:
                existing = self._existing_enforcement(product_id, proj_id)
            except QuarantineStateError as state_err:
                return self._state_failure(product_id, proj_id, resolved_policy, state_err)
            if existing is not None:
                return existing
            logger.warning(f"Executing NUCLEAR_UNLINK_BILLING on project {proj_id}")
            # C10 (RT D1): the account being detached is recorded, so the restore relinks exactly that one.
            # RT14-20: recorded BEFORE the unlink (no durable record -> nothing detached); RT14-05: an unreadable or
            # absent account never overwrites one recorded earlier.
            if self.db is None:
                return self._state_failure(product_id, proj_id, resolved_policy, QuarantineStateError(
                    "SNAPSHOT_PERSIST_FAILED", "no Firestore client, so the billing account cannot be recorded; "
                                               "nothing was detached"))
            root_account = self.billing_account_of(proj_id)
            if root_account:
                try:
                    self.db.collection("workloads").document(product_id).set({"root_billing_account": root_account},
                                                                             merge=True)
                except Exception as e:  # noqa: BLE001 - typed, nothing detached
                    return self._state_failure(product_id, proj_id, resolved_policy, QuarantineStateError(
                        "SNAPSHOT_PERSIST_FAILED", f"the billing account could not be recorded ({type(e).__name__}: "
                                                   f"{e}); nothing was detached"))
            else:
                # RT14 F2: unlink without a readable account only when the restore still has one to relink (recorded
                # earlier on the workload, else this install's BILLING_ACCOUNT_ID); otherwise nothing is detached.
                try:
                    w_snap = self.db.collection("workloads").document(product_id).get()
                    w_rec = w_snap.to_dict() if getattr(w_snap, "exists", None) is True else None
                except Exception as e:  # noqa: BLE001 - typed, nothing detached
                    return self._state_failure(product_id, proj_id, resolved_policy, QuarantineStateError(
                        "SNAPSHOT_READ_FAILED", f"the billing account of '{proj_id}' could not be read and the "
                                                f"workload record could not be read either ({type(e).__name__}: "
                                                f"{e}); nothing was detached"))
                recorded = w_rec.get("root_billing_account") if isinstance(w_rec, dict) else None
                has_recorded = isinstance(recorded, str) and bool(recorded.strip())
                if not has_recorded and not os.getenv("BILLING_ACCOUNT_ID", "").strip():
                    return self._state_failure(product_id, proj_id, resolved_policy, QuarantineStateError(
                        "SNAPSHOT_READ_FAILED", f"the billing account of '{proj_id}' could not be read, none was "
                                                "recorded earlier and BILLING_ACCOUNT_ID is not set, so a restore "
                                                "could not relink it; nothing was detached"))
                logger.error(json.dumps({"error_class": "BILLING_ACCOUNT_UNREAD", "product_id": product_id,
                                         "detail": "the current billing account could not be read; the restore "
                                                   "relinks the account recorded earlier, else BILLING_ACCOUNT_ID"}))
            if not self.unlink_billing_account(proj_id):
                return {"status": "BILLING_UNLINK_FAILED", "product_id": product_id, "project_id": proj_id,
                        "policy": resolved_policy, "reason": "the billing account could not be detached; nothing changed"}
            approval_id = f"appr-budget-{product_id}-{uuid.uuid4().hex[:6]}"
            card = {
                "approval_id": approval_id,
                "approval_type": "BUDGET_BREACH",
                "product_id": product_id,
                "target_project_id": proj_id,
                "trace_id": tr_id,
                "cost_delta_monthly": f"${spend_amount:.2f}/mo (Ceiling: ${budget_amount:.2f})",
                "risk_assessment": f"Billing detached! 100% budget breach triggered nuclear unlink: ${spend_amount:.2f} spent against ${budget_amount:.2f} limit.",
                "status": "PENDING",
                "requested_at": now_iso,
                "current_spend_usd": spend_amount,
                "budget_ceiling_usd": budget_amount,
                "buffer_ceiling_usd": round(budget_amount * 1.15, 2),
                "quarantined_resources": [f"billing/projects/{proj_id}"],
            }
            try:
                self._commit([("set", self.db.collection("workloads").document(product_id),
                               {"status": "BILLING_UNLINKED"}, True),
                              ("set", self.db.collection("approval_requests").document(approval_id), card)])
            except Exception as e:  # noqa: BLE001 - typed: a re-sent alert records it (the account is kept)
                return self._state_failure(product_id, proj_id, resolved_policy, QuarantineStateError(
                    "QUARANTINE_RECORD_FAILED", f"billing was detached but BILLING_UNLINKED could not be recorded "
                                                f"({type(e).__name__}: {e}); a re-sent alert records it"))
            self._start_recommendation(approval_id, product_id, spend_amount, budget_amount)

            return {
                "status": "BILLING_UNLINKED",
                "product_id": product_id,
                "project_id": proj_id,
                "approval_id": approval_id,
                "policy": resolved_policy,
            }

        # 3. HITL CONFIRMATION REQUIRED (Pause without halting compute yet)
        if resolved_policy == BudgetBreachPolicy.HITL_CONFIRMATION_REQUIRED.value:
            logger.info(f"Creating HITL approval card for '{product_id}' prior to quarantine.")
            approval_id = f"appr-budget-{product_id}-{uuid.uuid4().hex[:6]}"
            if self.db:
                try:
                    self._write_budget_breach_card(
                        approval_id, product_id, proj_id, tr_id, spend_amount, budget_amount, now_iso,
                        f"100% Budget breach detected (${spend_amount:.2f} / ${budget_amount:.2f}). Awaiting operator "
                        "remediation choice.", [])
                    self._start_recommendation(approval_id, product_id, spend_amount, budget_amount)
                except Exception as e:
                    logger.warning(f"Could not record HITL approval request in Firestore: {e}")
            return {
                "status": "HITL_CONFIRMATION_PENDING",
                "product_id": product_id,
                "project_id": proj_id,
                "approval_id": approval_id,
                "policy": resolved_policy,
            }

        # 4. AUTONOMOUS SCALE TO ZERO (Default Tiered Quarantine)
        # FD-7M-a: the workload's own region, before anything is snapshotted or stopped (typed refusal, never another
        # region).
        try:
            region = self.resolve_workload_region(product_id)
        except WorkloadRegionRefused as region_err:
            refused = self._region_refused(product_id, proj_id, "QUARANTINE", region_err)
            refused.update(self._record_unenforced_breach(product_id, proj_id, tr_id, spend_amount, budget_amount,
                                                          resolved_policy, now_iso, region_err))
            return refused

        # RT14-05: already quarantined or unlinked -> nothing changes (a second snapshot would record the zeroed
        # state over the pre-quarantine one).
        try:
            existing = self._existing_enforcement(product_id, proj_id)
        except QuarantineStateError as state_err:
            return self._state_failure(product_id, proj_id, resolved_policy, state_err)
        if existing is not None:
            return existing

        # 4a. Take snapshot (RT14-20: durable before anything is stopped; a failure stops here, nothing changed)
        try:
            snapshot = self.take_pre_quarantine_snapshot(product_id, proj_id, region=region)
        except QuarantineStateError as state_err:
            return self._state_failure(product_id, proj_id, resolved_policy, state_err)
        durable_snapshot = snapshot.pop("durable_snapshot", None) if isinstance(snapshot, dict) else None

        # 4b. Cloud Run scale to zero
        scaled_services = []
        for svc in snapshot.get("cloud_run_services", []):
            name = svc.get("name") if isinstance(svc, dict) else svc
            if self.set_service_scaling(proj_id, name, max_instances=0, min_instances=0, region=region):
                scaled_services.append(f"run/{name}")

        # 4c. Stop active VMs
        running_vms = [v for v in snapshot.get("compute_vms", []) if v.get("status") == "RUNNING"]
        stopped_vms = self.stop_vms(proj_id, running_vms)

        # 4d. Stop Cloud SQL
        stopped_sql = []
        for db_inst in snapshot.get("cloud_sql", []):
            db_name = db_inst.get("name")
            if db_inst.get("activation_policy") != "NEVER":
                if self.set_cloud_sql_activation(proj_id, db_name, "NEVER"):
                    stopped_sql.append(f"sql/{db_name}")

        # 4e. Scale GKE node pools to 0
        scaled_gke = []
        for pool in snapshot.get("gke_pools", []):
            cl = pool.get("cluster_name")
            loc = pool.get("location")
            pname = pool.get("pool_name")
            if self.scale_gke_pool(proj_id, loc, cl, pname, 0):
                scaled_gke.append(f"gke/{cl}/{pname}")

        quarantined_resources = scaled_services + [f"gce/{v}" for v in stopped_vms] + stopped_sql + scaled_gke
        approval_id = f"appr-budget-{product_id}-{uuid.uuid4().hex[:6]}"

        record = {
            "product_id": product_id,
            "project_id": proj_id,
            "trace_id": tr_id,
            "approval_id": approval_id,
            "quarantined_at": now_iso,
            "spend_amount": spend_amount,
            "budget_amount": budget_amount,
            "quarantined_resources_count": len(quarantined_resources),
            "quarantined_resources": quarantined_resources,
            "status": "QUARANTINED",
            "action": "AUTO_KILL_SCALE_TO_ZERO",
            "policy": resolved_policy,
            "reason": f"100% budget ceiling reached (${spend_amount:.2f} / ${budget_amount:.2f})",
        }
        if isinstance(durable_snapshot, dict):
            record["snapshot"] = durable_snapshot   # RT14-20: the second copy (the restore falls back to it)

        # Update Firestore: the quarantine record, the status and the card land together or not at all (RT14-20)
        if self.db:
            card = {
                "approval_id": approval_id,
                "approval_type": "BUDGET_BREACH",
                "product_id": product_id,
                "target_project_id": proj_id,
                "trace_id": tr_id,
                "cost_delta_monthly": f"${spend_amount:.2f}/mo (Ceiling: ${budget_amount:.2f})",
                "risk_assessment": f"100% Budget breach! Quarantined {len(quarantined_resources)} compute resources to halt charges.",
                "status": "PENDING",
                "requested_at": now_iso,
                "current_spend_usd": spend_amount,
                "budget_ceiling_usd": budget_amount,
                "buffer_ceiling_usd": round(budget_amount * 1.15, 2),
                "quarantined_resources": quarantined_resources,
                "snapshot_id": product_id,
            }
            try:
                self._commit([("set", self.db.collection("quarantined_workloads").document(product_id), record),
                              ("set", self.db.collection("workloads").document(product_id),
                               {"status": "QUARANTINED"}, True),
                              ("set", self.db.collection("approval_requests").document(approval_id), card)])
            except Exception as e:  # noqa: BLE001 - typed: compute is stopped, the snapshot is kept
                failure = self._state_failure(product_id, proj_id, resolved_policy, QuarantineStateError(
                    "QUARANTINE_RECORD_FAILED", f"compute was stopped but the quarantine record could not be written "
                                                f"({type(e).__name__}: {e}); the snapshot is kept and a re-sent alert "
                                                "finishes the quarantine"))
                return {**record, **failure}
            logger.info(f"Updated Firestore status to QUARANTINED and created approval {approval_id} for {product_id}")
            self._start_recommendation(approval_id, product_id, spend_amount, budget_amount)

        return record

    # --------------------------------------------------------------------------
    # Core Restoration Execution (1-Click Restore)
    # --------------------------------------------------------------------------
    def _unconfirmed_restore(self, proj_id: str, region: str, snapshot: Dict[str, Any],
                             max_override: Optional[int]) -> List[str]:
        """RT14-05: the snapshot resources whose live state does not show the restored values. Cloud Run: the recorded
        max (or the override for an entry without one) and min; VMs recorded RUNNING: started (VM_STARTED_STATUSES);
        Cloud SQL: the recorded activation policy. A read that fails leaves its resources unconfirmed. GKE node pools
        are not checked: the node pool resource has no current size (the restore relies on the setSize answer)."""
        pending: List[str] = []
        services = [s for s in snapshot.get("cloud_run_services") or [] if isinstance(s, dict)]
        if services:
            try:
                live = {s.get("name"): s for s in self.list_workload_services(proj_id, region=region, strict=True)}
            except LiveStateReadError as e:
                logger.warning(f"Restore check: {e}")
                live = {}
            for svc in services:
                cur = live.get(svc.get("name"))
                want_max = svc.get("max_instances") if svc.get("max_instances") is not None else max_override
                if (cur is None or (want_max is not None and cur.get("max_instances") != want_max)
                        or (cur.get("min_instances") or 0) != (svc.get("min_instances") or 0)):
                    pending.append(f"run/{svc.get('name')}")
        vms = [v for v in snapshot.get("compute_vms") or [] if isinstance(v, dict) and v.get("status") == "RUNNING"]
        if vms:
            try:
                live_vms = {(v.get("zone"), v.get("name")): v for v in self.list_running_vms(proj_id, strict=True)}
            except LiveStateReadError as e:
                logger.warning(f"Restore check: {e}")
                live_vms = {}
            for vm in vms:
                cur = live_vms.get((vm.get("zone"), vm.get("name")))
                if cur is None or cur.get("status") not in VM_STARTED_STATUSES:
                    pending.append(f"gce/{vm.get('zone')}/{vm.get('name')}")
        dbs = [d for d in snapshot.get("cloud_sql") or []
               if isinstance(d, dict) and d.get("activation_policy", "ALWAYS") != "NEVER"]
        if dbs:
            try:
                live_sql = {d.get("name"): d for d in self.list_cloud_sql_instances(proj_id, strict=True)}
            except LiveStateReadError as e:
                logger.warning(f"Restore check: {e}")
                live_sql = {}
            for d in dbs:
                cur = live_sql.get(d.get("name"))
                if cur is None or cur.get("activation_policy") != d.get("activation_policy", "ALWAYS"):
                    pending.append(f"sql/{d.get('name')}")
        return pending

    def _confirm_restore(self, proj_id: str, region: str, snapshot: Dict[str, Any],
                         max_override: Optional[int]) -> List[str]:
        """Polls _unconfirmed_restore until nothing is pending or restore_verify_wait_s has passed."""
        deadline = self._clock() + max(0.0, float(self.restore_verify_wait_s))
        while True:
            pending = self._unconfirmed_restore(proj_id, region, snapshot, max_override)
            if not pending or self._clock() >= deadline:
                return pending
            self._sleep(max(0.0, float(self.restore_verify_poll_s)))

    def restore_workload(
        self,
        product_id: str,
        target_project_id: Optional[str] = None,
        max_instances: Optional[int] = None,
        root_billing_account: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Restores normal operational scaling limits for a previously quarantined or unlinked workload.
        Restores only resources that were active prior to quarantine using the pre-quarantine snapshot.
        C10 (RT D1-D3): an unlinked workload is relinked to the account recorded at unlink time (else this install's
        BILLING_ACCOUNT_ID); `root_billing_account`, when given, must be that same account. No account
        (BILLING_ACCOUNT_UNKNOWN), a failed relink (BILLING_RELINK_FAILED) or no billing client
        (BILLING_CLIENT_UNAVAILABLE) changes nothing. Any resource of the snapshot not restored -> RESTORE_PARTIAL (the
        snapshot and the quarantine record are kept for a retry). A snapshot entry without max_instances keeps its max
        unless `max_instances` is given.
        RT14-05: RESTORED / BILLING_RESTORED only after the live state is read back and matches (else RESTORE_PARTIAL
        with `unverified`, or BILLING_RELINK_UNVERIFIED); the markers are cleared in one batch (a failed write is
        RESTORE_RECORD_FAILED, markers kept). The snapshot falls back to the quarantine record's copy; the two
        disagreeing is SNAPSHOT_MISMATCH (nothing restored).
        """
        try:
            proj_id = self.authorize_target(target_project_id)
        except QuarantineTargetRefused as refused:
            return self._refused(product_id, target_project_id, "RESTORE", str(refused))
        now_iso = datetime.now(timezone.utc).isoformat()
        logger.info(f"Restoring workload '{product_id}' (Project: {proj_id})")

        # 1. Check if Workload was in BILLING_UNLINKED state
        is_billing_unlinked = False
        workload_data = {}
        workload_unreadable = False
        if self.db:
            try:
                w_doc = self.db.collection("workloads").document(product_id).get()
                if w_doc.exists:
                    workload_data = w_doc.to_dict() or {}
                    if workload_data.get("status") == "BILLING_UNLINKED":
                        is_billing_unlinked = True
            except Exception as e:
                workload_unreadable = True   # C10: the quarantine marker below cannot be trusted either
                logger.warning(f"Could not inspect workload status in Firestore: {e}")

        if is_billing_unlinked:
            def _norm(acct: Any) -> str:
                a = acct.strip() if isinstance(acct, str) else ""
                return a if not a or a.startswith("billingAccounts/") else f"billingAccounts/{a}"

            billing_acct = _norm(workload_data.get("root_billing_account")) or _norm(os.getenv("BILLING_ACCOUNT_ID", ""))
            base = {"product_id": product_id, "project_id": proj_id}
            if root_billing_account and _norm(root_billing_account) != billing_acct:
                return {**base, "status": "BILLING_ACCOUNT_MISMATCH",
                        "reason": "root_billing_account differs from the recorded / install billing account; nothing "
                                  "relinked"}
            if not billing_acct:
                return {**base, "status": "BILLING_ACCOUNT_UNKNOWN",
                        "reason": "no billing account was recorded at unlink time and BILLING_ACCOUNT_ID is not set; "
                                  "nothing relinked"}
            if not self.billing and not self._billing_mock_allowed():
                return {**base, "status": "BILLING_CLIENT_UNAVAILABLE",
                        "reason": "no Cloud Billing client; nothing relinked"}
            if not self.relink_billing_account(proj_id, billing_acct):
                return {**base, "status": "BILLING_RELINK_FAILED",
                        "reason": f"re-linking {billing_acct} failed (see the job log); nothing else changed"}
            # RT14-05: read back before reporting (the TEST_MODE no-client relink has nothing to read)
            if self.billing and self.billing_account_of(proj_id) != billing_acct:
                logger.error(f"Restore of '{product_id}': the project does not show {billing_acct} after the relink")
                return {**base, "status": "BILLING_RELINK_UNVERIFIED",
                        "reason": f"the project does not show {billing_acct} after the relink; status unchanged "
                                  "(approve again to retry)"}
            if self.db:
                try:
                    self._commit([("set", self.db.collection("workloads").document(product_id),
                                   {"status": "ACTIVE", **RESTORE_CLEARS_BREACH_LATCH}, True),
                                  ("delete", self.db.collection("quarantined_workloads").document(product_id))])
                except Exception as e:  # noqa: BLE001 - typed: billing is relinked; a retry records it
                    logger.error(f"Restore of '{product_id}': billing relinked but not recorded: {e}")
                    return {**base, "status": "RESTORE_RECORD_FAILED", "billing_account": billing_acct,
                            "reason": f"billing was relinked but ACTIVE could not be recorded ({type(e).__name__}); "
                                      "approve again to record it"}
            return {
                "status": "BILLING_RESTORED",
                "product_id": product_id,
                "project_id": proj_id,
                "billing_account": billing_acct,
                "restored_at": now_iso,
            }

        # C10 (owner-directed, 11-07): only a workload the quarantine path scaled down is restored, and only to its
        # pre-quarantine snapshot. The quarantine writes three markers: quarantine_snapshots/{id} (the snapshot),
        # quarantined_workloads/{id} and workloads/{id}.status QUARANTINED. No snapshot and no marker: the workload was
        # never scaled down (a HITL card, ALERT_ONLY, a refused region): NOTHING is changed (never "every service to
        # max_instances", which would cut a healthy workload's capacity), the breach latch is cleared, and the typed
        # answer is NOTHING_TO_RESTORE. A marker without a snapshot: SNAPSHOT_MISSING, nothing changed (never a
        # guess). Markers that cannot be read: SNAPSHOT_UNREADABLE, nothing changed.
        try:
            if workload_unreadable:
                raise RuntimeError(f"workloads/{product_id} unreadable")
            snapshot, quarantined, record = self._restore_markers(product_id, workload_data)
        except Exception as e:  # noqa: BLE001 - typed, fail closed
            logger.error(f"Restore of '{product_id}': quarantine markers unreadable: {type(e).__name__}: {e}")
            return {"status": "SNAPSHOT_UNREADABLE", "product_id": product_id, "project_id": proj_id,
                    "reason": f"quarantine markers unreadable ({type(e).__name__}); nothing restored"}
        # RT14-20: the quarantine record keeps a second copy of the snapshot
        record_copy = (record or {}).get("snapshot")
        record_copy = record_copy if isinstance(record_copy, dict) else None
        if snapshot and record_copy is not None and snapshot != record_copy:
            logger.error(f"Restore of '{product_id}': the snapshot differs from the quarantine record's copy")
            return {"status": "SNAPSHOT_MISMATCH", "product_id": product_id, "project_id": proj_id,
                    "reason": "quarantine_snapshots and the quarantine record's copy of the snapshot differ (one was "
                              "rewritten after the quarantine); nothing restored"}
        if not snapshot and record_copy is not None:
            logger.warning(f"Restore of '{product_id}': quarantine_snapshots is missing; using the record's copy")
            snapshot = record_copy
        if not snapshot and not quarantined:
            if self.db:
                try:
                    self.db.collection("workloads").document(product_id).set(dict(RESTORE_CLEARS_BREACH_LATCH),
                                                                             merge=True)
                except Exception as e:  # noqa: BLE001 - nothing was changed; the latch stays (re-armed next month)
                    logger.warning(f"Could not clear the breach latch of '{product_id}': {e}")
            logger.info(f"Restore of '{product_id}': it was never scaled down; no service changed")
            return {"status": "NOTHING_TO_RESTORE", "product_id": product_id, "project_id": proj_id,
                    "restored_services": [], "restored_at": now_iso,
                    "reason": "the workload was not quarantined (no snapshot, no quarantine record); nothing changed"}
        if not snapshot:
            logger.error(f"Restore of '{product_id}': quarantined but its pre-quarantine snapshot is missing")
            return {"status": "SNAPSHOT_MISSING", "product_id": product_id, "project_id": proj_id,
                    "reason": "the workload is quarantined but quarantine_snapshots has no snapshot for it; nothing "
                              "restored (restore its services by hand, then approve again)"}

        # FD-7M-a: the workload's own region for its Cloud Run services (typed refusal, nothing restored elsewhere)
        try:
            region = self.resolve_workload_region(product_id)
        except WorkloadRegionRefused as region_err:
            return self._region_refused(product_id, proj_id, "RESTORE", region_err)

        # 2. Restore from Pre-Quarantine Snapshot
        restored_services = []
        started_vms = []
        restored_sql = []
        restored_gke = []
        failed: List[str] = []

        if snapshot:
            # Restore Cloud Run
            for svc in snapshot.get("cloud_run_services", []):
                name = svc.get("name")
                # RT D3 / RT14-05: absent or recorded as None -> the override, else the max is left unchanged
                max_inst = svc.get("max_instances") if svc.get("max_instances") is not None else max_instances
                min_inst = svc.get("min_instances", 0)
                if self.set_service_scaling(proj_id, name, max_instances=max_inst, min_instances=min_inst,
                                            region=region):
                    restored_services.append(name)
                else:
                    failed.append(f"run/{name}")

            # Restore VMs (only those running in snapshot)
            running_vms = [v for v in snapshot.get("compute_vms", []) if v.get("status") == "RUNNING"]
            started_vms = self.start_vms(proj_id, running_vms)
            failed += [f"gce/{v.get('zone')}/{v.get('name')}" for v in running_vms
                       if f"{v.get('zone')}/{v.get('name')}" not in started_vms]

            # Restore Cloud SQL
            for db_inst in snapshot.get("cloud_sql", []):
                db_name = db_inst.get("name")
                orig_policy = db_inst.get("activation_policy", "ALWAYS")
                if orig_policy != "NEVER":
                    if self.set_cloud_sql_activation(proj_id, db_name, orig_policy):
                        restored_sql.append(db_name)
                    else:
                        failed.append(f"sql/{db_name}")

            # Restore GKE pools
            for pool in snapshot.get("gke_pools", []):
                cl = pool.get("cluster_name")
                loc = pool.get("location")
                pname = pool.get("pool_name")
                orig_count = pool.get("node_count", 1)
                if self.scale_gke_pool(proj_id, loc, cl, pname, orig_count):
                    restored_gke.append(f"{cl}/{pname}")
                else:
                    failed.append(f"gke/{cl}/{pname}")

        progress = {"restored_services": restored_services, "started_vms": started_vms, "restored_sql": restored_sql,
                    "restored_gke": restored_gke}
        if failed:
            # RT D2: never RESTORED with a resource still stopped; snapshot and quarantine record stay for a retry
            logger.error(f"Restore of '{product_id}' is partial; not restored: {failed}")
            return {"status": "RESTORE_PARTIAL", "product_id": product_id, "project_id": proj_id, **progress,
                    "failed": failed, "unverified": [],
                    "reason": f"not restored: {', '.join(failed)} (the snapshot is kept; approve again to retry)"}

        # RT14-05: read the live state back before reporting RESTORED (never RESTORED with a resource still stopped)
        unverified = self._confirm_restore(proj_id, region, snapshot, max_instances)
        if unverified:
            logger.error(f"Restore of '{product_id}' is not confirmed for: {unverified}")
            return {"status": "RESTORE_PARTIAL", "product_id": product_id, "project_id": proj_id, **progress,
                    "failed": [], "unverified": unverified,
                    "reason": f"not confirmed after the restore: {', '.join(unverified)} (the live state does not "
                              "show the snapshot's values yet; the snapshot is kept; approve again to re-apply and "
                              "check again)"}

        # Update Firestore: the markers are cleared together (RT14-05); a failure keeps them for a retry
        if self.db:
            try:
                self._commit([("set", self.db.collection("workloads").document(product_id),
                               {"status": "ACTIVE", **RESTORE_CLEARS_BREACH_LATCH}, True),
                              ("delete", self.db.collection("quarantined_workloads").document(product_id)),
                              ("delete", self.db.collection("quarantine_snapshots").document(product_id))])
                logger.info(f"Restored Firestore status to ACTIVE for {product_id}")
            except Exception as e:  # noqa: BLE001 - typed: compute is restored, the markers are kept
                logger.error(f"Restore of '{product_id}': restored but not recorded: {type(e).__name__}: {e}")
                return {"status": "RESTORE_RECORD_FAILED", "product_id": product_id, "project_id": proj_id,
                        **progress,
                        "reason": f"the resources were restored but ACTIVE could not be recorded ({type(e).__name__}); "
                                  "the snapshot is kept; approve again to record it"}

        return {
            "status": "RESTORED",
            "product_id": product_id,
            "project_id": proj_id,
            "restored_services": restored_services,
            "started_vms": started_vms,
            "restored_sql": restored_sql,
            "restored_gke": restored_gke,
            "restored_at": now_iso,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="StackVend FinOps Budget Enforcer CLI")
    parser.add_argument("--product_id", required=True, help="Target product identifier")
    parser.add_argument("--project_id", default=None, help="Target GCP project ID")
    parser.add_argument("--action", choices=["quarantine", "restore"], default="quarantine", help="Enforcement action")
    parser.add_argument("--policy", default="AUTONOMOUS_SCALE_TO_ZERO", help="Breach policy")
    parser.add_argument("--spend_amount", type=float, default=0.0, help="Current incurred spend in USD")
    parser.add_argument("--budget_amount", type=float, default=0.0, help="Monthly budget ceiling in USD")

    args = parser.parse_args()
    enforcer = FinopsBudgetEnforcer()

    if args.action == "quarantine":
        res = enforcer.quarantine_workload(
            product_id=args.product_id,
            target_project_id=args.project_id,
            spend_amount=args.spend_amount,
            budget_amount=args.budget_amount,
            policy=args.policy,
        )
    else:
        res = enforcer.restore_workload(
            product_id=args.product_id,
            target_project_id=args.project_id,
        )
    print(json.dumps(res, indent=2))
