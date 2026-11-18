"""
StackVend: sandbox-workload-sweeper-job (C10, owner 11-07; register row C10-MACHINE-CALLERS-OFF-CC).

Cloud Scheduler castor-sandbox-workload-sweeper runs this job daily at 4:00 AM (America/New_York); until C10 the
scheduler called the Control Center's /api/workloads/sweep-expired-sandboxes, which Direct IAP refused. It runs the
SAME sweep as that (now human-only) route: shared/sandbox_sweep.py run_sweep, a byte copy of the Control Center's:
T-7 / T-2 notices, in-flight and pending-review deferrals, platform self-preservation, BATCH_LIMIT = 10, audit records
by "system-sandbox-sweeper", and for each expired sandbox ONE POST /projects/{id}/decommission {action_class:
SANDBOX_TTL} to project-vending with this job's own ID token for VENDING_SERVICE_URL. Lane 18 S2: vending's destructive
guard decides and executes every delete; this job deletes nothing and never mints an approval. After a vending delete,
the workload's running Workflows executions are cancelled (workflow_executions.py, a byte copy; SAT-43 fail closed).

Identity: sa-stackvend-sandbox-sweeper, listed in vending's DESTRUCTIVE_CALLERS and SANDBOX_TTL_CALLERS (Terraform);
default-database datastore.user, invoker on vending only, workflows.invoker, logWriter. Nothing else.
Outcome: COMPLETED (exit 0) when the sweep reported no error (vending's typed refusals, 403 / 409, and expired
sandboxes vending never TTL-deletes are listed, not errors: RT finding 4); COMPLETED_WITH_ERRORS (exit 1) when a
delete failed (5xx, unreachable) or platform protection fired (listed); FAILED (exit 1) when the sandbox query failed; NOT_CONFIGURED (exit 3) without PROJECT_ID /
VENDING_SERVICE_URL / REGION. Job contract: shared/day2_job.py.

    python3 main.py            (Procfile; a Cloud Run job, max_retries = 0)
"""

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
import json
import logging
import os
import sys
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from shared import day2_job as contract
from shared import sandbox_sweep

JOB_NAME = "sandbox-workload-sweeper-job"
REQUIRED_ENV = ("PROJECT_ID", "VENDING_SERVICE_URL", "REGION")
LEASE_SECONDS = 7200          # > the task timeout (Terraform local.job_timeouts: 3600 s)
MAX_RECORDED_ERRORS = 50

logger = logging.getLogger(JOB_NAME)


def _db(project: str):
    from google.cloud import firestore
    try:
        return firestore.Client(project=project)
    except Exception as e:  # noqa: BLE001 - run_job reports RUN_RECORD_UNAVAILABLE
        logger.error(f"Could not open the Firestore database: {type(e).__name__}: {e}")
        return None


def default_id_token(audience: str) -> str:
    import google.auth.transport.requests
    from google.oauth2 import id_token
    return id_token.fetch_id_token(google.auth.transport.requests.Request(), audience)


def default_http_post(url: str, json: Dict[str, Any], headers: Dict[str, str], timeout: float):
    import requests
    return requests.post(url, json=json, headers=headers, timeout=timeout)


def summarize(res: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    errors = list(res.get("errors") or [])
    detail = {
        "scanned_count": res.get("scanned_count", 0),
        "expired_count": res.get("expired_count", 0),
        "decommissioned_workloads": list(res.get("decommissioned_workloads") or []),
        "deferred_workloads": list(res.get("deferred_workloads") or []),
        "notifications_count": len(res.get("notifications_sent") or []),
        "not_eligible_workloads": list(res.get("not_eligible_workloads") or [])[:MAX_RECORDED_ERRORS],
        "refused_workloads": list(res.get("refused_workloads") or [])[:MAX_RECORDED_ERRORS],
        "error_count": len(errors),
        "errors": errors[:MAX_RECORDED_ERRORS],
    }
    if not errors:
        return contract.COMPLETED, detail
    # run_sweep reports a failed sandbox query as an error with nothing scanned.
    return (contract.FAILED if not res.get("scanned_count") else contract.COMPLETED_WITH_ERRORS), detail


def run(env: Optional[Mapping[str, str]] = None, database: Any = None,
        id_token: Optional[Callable[[str], str]] = None, http_post: Optional[Callable[..., Any]] = None,
        workflows: Any = None) -> Tuple[int, Dict[str, Any]]:
    env = os.environ if env is None else env
    project = (env.get("PROJECT_ID") or "").strip()
    if database is None and project:
        database = _db(project)
    if workflows is None:
        import workflow_executions as workflows
    # The Control Center's region lookup lives in its routes; this job has REGION in its env (Terraform).
    workflows.region_provider = lambda: (env.get("REGION") or "").strip()

    def work(run_id: str) -> Tuple[str, Dict[str, Any]]:
        client = sandbox_sweep.SandboxVendingClient((env.get("VENDING_SERVICE_URL") or "").strip(),
                                                    id_token or default_id_token, http_post or default_http_post)
        def cancel(target_product_id, operator_email, reason, failures):
            return sandbox_sweep.cancel_active_executions(database, target_product_id, operator_email, reason, failures,
                                                          workflows.cancel_bound_execution, workflows.FAILED, project)

        res = sandbox_sweep.run_sweep(database, decommission=client.decommission, cancel_executions=cancel)
        return summarize(res)

    return contract.run_job(JOB_NAME, work, database, env, required_env=REQUIRED_ENV, lease_seconds=LEASE_SECONDS)


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    release_info.log_release("sandbox-workload-sweeper-job")  # FD-7C P3a: one stackvend.release line per run
    code, summary = run()
    print(json.dumps(summary, indent=2, default=str))
    return code


if __name__ == "__main__":
    sys.exit(main())
