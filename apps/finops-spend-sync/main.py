"""
StackVend: finops-spend-sync-job (C10, owner 11-07; register row C10-MACHINE-CALLERS-OFF-CC).

Cloud Scheduler castor-finops-nightly-spend-sync runs this job daily at 3:00 AM (America/New_York); until C10 the
scheduler called the Control Center's /api/finops/sync-spend, which Direct IAP refused. It runs the SAME sync as that
(now human-only) route: shared/spend_sync.py with services/finops_sync.reconcile_workload_spend (byte copies of the
Control Center's), writing each workload's month-to-date spend and run-rate projection to Firestore workloads/{id}. The
Control Center reads those fields.

Differences from the route, on purpose (pre-review F16-F18): every workload is tried (a failure is listed and the run
ends COMPLETED_WITH_ERRORS, exit 1), the day-2 job contract (shared/day2_job.py: run record, lease, exit codes), and
NOT_CONFIGURED (exit 3) without PROJECT_ID. Identity: sa-stackvend-finops-sync (default-database datastore.user,
guard-database datastore.viewer, workload-state objectViewer, logWriter; nothing else).

    python3 main.py            (Procfile; a Cloud Run job, max_retries = 0)
"""

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
import json
import logging
import os
import sys
from typing import Any, Callable, Dict, Mapping, Optional, Tuple

from shared import day2_job as contract
from shared import spend_sync

JOB_NAME = "finops-spend-sync-job"
LEASE_SECONDS = 3600          # > the task timeout (Terraform local.job_timeouts: 1800 s)
MAX_RECORDED_FAILURES = 50

logger = logging.getLogger(JOB_NAME)


def run(env: Optional[Mapping[str, str]] = None, database: Any = None,
        reconcile: Optional[Callable[..., Dict[str, Any]]] = None) -> Tuple[int, Dict[str, Any]]:
    env = os.environ if env is None else env
    if database is None:
        import db as job_db
        database = job_db.get_db()
    if reconcile is None:
        from services.finops_sync import reconcile_workload_spend as reconcile

    def work(run_id: str) -> Tuple[str, Dict[str, Any]]:
        res = spend_sync.sync_all_workloads(database, reconcile, (env.get("PROJECT_ID") or "").strip(),
                                            continue_on_error=True)
        failed = res.get("failed") or []
        detail = {
            "synced_count": res.get("count", 0),
            "synced_at": res.get("synced_at"),
            "overrun_projected": sorted(w["product_id"] for w in res.get("workloads") or []
                                        if w.get("is_overrun_projected")),
            "failed_count": len(failed),
            "failed": failed[:MAX_RECORDED_FAILURES],
        }
        return (contract.COMPLETED_WITH_ERRORS if failed else contract.COMPLETED), detail

    return contract.run_job(JOB_NAME, work, database, env, required_env=("PROJECT_ID",), lease_seconds=LEASE_SECONDS)


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    release_info.log_release("finops-spend-sync-job")  # FD-7C P3a: one stackvend.release line per run
    code, summary = run()
    print(json.dumps(summary, indent=2, default=str))
    return code


if __name__ == "__main__":
    sys.exit(main())
