"""
StackVend: run the FinOps enforcer as its Cloud Run job, the one deployable form of the enforcer (C10).

The enforcer engine (apps/finops-enforcer/enforcer.py) is not packaged in the Control Center image (FD26-07), so every
caller outside that job runs `finops-budget-enforcer-job` ONCE with the env overrides of its job contract
(apps/finops-enforcer/main.py run_batch) and waits for that execution's run record
`finops-budget-enforcer-job_runs/{execution}` (default Firestore database): the verified outcome.

- quarantine_workload(...): FINOPS_ACTION unset (= QUARANTINE, the job's original contract) + FINOPS_ENFORCE_*;
  billing-alert-drain-job on a budget breach.
- restore_workload(...): FINOPS_ACTION=RESTORE + FINOPS_ENFORCE_PRODUCT_ID / _TARGET_PROJECT_ID (+ optional
  FINOPS_RESTORE_MAX_INSTANCES, 1..100); the Control Center's budget-breach approval
  (RESTORE_BUFFER / budget increase). The engine's restore also clears the breach latch.

Returns {"status": <the run record outcome>, "execution": <name>, "reason": ...} for an accepted outcome (quarantine:
ENFORCED_STATUSES or REFUSED; restore: RESTORE_STATUSES or REFUSED); raises EnforcerRunError (typed) for anything else:
the run refused, no execution name, the execution ended without an outcome, a timeout, or a failed outcome. Never a
fabricated success. Permissions: the custom role {run.jobs.run, run.jobs.runWithOverrides, run.executions.get} bound on
finops-budget-enforcer-job only (Terraform billing_drain_enforcer_runner / cc_enforcer_runner), and Firestore read of
the run record.

Replicated (byte-identical, tests/test_c10_platform_tf.py::test_c10_copies_are_byte_identical): shared/,
apps/control-center/shared/, apps/billing-alert-drain/shared/. Standard library only.
"""

import json
import logging
import time
from typing import Any, Callable, Dict, FrozenSet, Optional

logger = logging.getLogger("stackvend-enforcer-job")

RUN_API = "https://run.googleapis.com/v2"
DEFAULT_JOB_NAME = "finops-budget-enforcer-job"
HTTP_TIMEOUT_S = 60
DEFAULT_WAIT_S = 900          # the enforcer job's task timeout is the Cloud Run default (600 s) + start-up
POLL_INTERVAL_S = 10
RUNNING = "RUNNING"
REFUSED = "REFUSED"
# Parity: apps/finops-enforcer/main.py ENFORCED_STATUSES / RESTORE_STATUSES (tests/test_c10_billing_drain.py).
ENFORCED_STATUSES: FrozenSet[str] = frozenset({"QUARANTINED", "ALERTED_ONLY", "BILLING_UNLINKED",
                                               "HITL_CONFIRMATION_PENDING"})
RESTORE_STATUSES: FrozenSet[str] = frozenset({"RESTORED", "BILLING_RESTORED", "NOTHING_TO_RESTORE"})


class EnforcerRunError(RuntimeError):
    """The enforcer job did not report an accepted outcome. `code` is the typed class (ENFORCER_RUN_REFUSED,
    ENFORCER_ENDED_WITHOUT_OUTCOME, ENFORCER_TIMEOUT, ENFORCER_<outcome>); `execution` when one was started."""

    def __init__(self, code: str, detail: str, execution: str = ""):
        super().__init__(f"{code}: {detail}".strip())
        self.code, self.detail, self.execution = code, detail, execution


class EnforcerJob:
    def __init__(self, session: Any, database: Any, project: str, region: str, job_name: str = DEFAULT_JOB_NAME,
                 keepalive: Callable[[], None] = lambda: None, trace_id: str = "",
                 clock: Callable[[], float] = time.monotonic, sleep: Callable[[float], None] = time.sleep,
                 wait_s: float = DEFAULT_WAIT_S, poll_s: float = POLL_INTERVAL_S):
        self.session, self.db, self.keepalive, self.trace_id = session, database, keepalive, trace_id
        self.job_path = f"projects/{project}/locations/{region}/jobs/{job_name}"
        self.job_name, self.clock, self.sleep, self.wait_s, self.poll_s = job_name, clock, sleep, wait_s, poll_s

    def _record(self, execution_id: str) -> Dict[str, Any]:
        snap = self.db.collection(f"{self.job_name}_runs").document(execution_id).get()
        return (snap.to_dict() or {}) if getattr(snap, "exists", False) else {}

    def quarantine_workload(self, product_id: str, target_project_id: str, spend_amount: float,
                            budget_amount: float, policy: str) -> Dict[str, Any]:
        env = {"FINOPS_ENFORCE_PRODUCT_ID": product_id, "FINOPS_ENFORCE_TARGET_PROJECT_ID": target_project_id,
               "FINOPS_ENFORCE_SPEND_AMOUNT": str(spend_amount), "FINOPS_ENFORCE_BUDGET_AMOUNT": str(budget_amount),
               "FINOPS_ENFORCE_POLICY": str(policy or ""), "FINOPS_ENFORCE_TRACE_ID": self.trace_id}
        return self._run(env, ENFORCED_STATUSES, product_id)

    def restore_workload(self, product_id: str, target_project_id: Optional[str] = None,
                         max_instances: Optional[int] = None) -> Dict[str, Any]:
        """The billing account is never sent (RT D5): the job relinks the one recorded at unlink time."""
        env = {"FINOPS_ACTION": "RESTORE", "FINOPS_ENFORCE_PRODUCT_ID": product_id,
               "FINOPS_ENFORCE_TARGET_PROJECT_ID": str(target_project_id or ""),
               "FINOPS_RESTORE_MAX_INSTANCES": "" if max_instances is None else str(int(max_instances))}
        return self._run(env, RESTORE_STATUSES, product_id)

    def _run(self, env: Dict[str, str], accepted: FrozenSet[str], product_id: str) -> Dict[str, Any]:
        body = {"overrides": {"containerOverrides": [{"env": [{"name": k, "value": v}
                                                              for k, v in sorted(env.items()) if v]}]}}
        self.keepalive()
        try:
            res = self.session.post(f"{RUN_API}/{self.job_path}:run", json=body, timeout=HTTP_TIMEOUT_S)
        except Exception as e:  # noqa: BLE001 - typed
            raise EnforcerRunError("ENFORCER_RUN_REFUSED", f"{self.job_name}:run failed ({type(e).__name__}: {e})")
        if res.status_code not in (200, 201):
            raise EnforcerRunError("ENFORCER_RUN_REFUSED", f"{self.job_name}:run answered HTTP {res.status_code}")
        try:
            execution = res.json()["metadata"]["name"]
        except Exception:  # noqa: BLE001
            raise EnforcerRunError("ENFORCER_RUN_REFUSED", "the run response has no execution name")
        if not isinstance(execution, str) or not execution.startswith(f"{self.job_path}/executions/"):
            raise EnforcerRunError("ENFORCER_RUN_REFUSED", f"unexpected execution name {execution!r}")
        execution_id = execution.rsplit("/", 1)[-1]
        logger.warning(json.dumps({"event": "FINOPS_ENFORCER_STARTED", "product_id": product_id,
                                   "action": env.get("FINOPS_ACTION", "QUARANTINE"), "execution": execution}))

        deadline = self.clock() + self.wait_s
        while True:
            self.keepalive()
            record = self._record(execution_id)
            if record.get("outcome") and record.get("outcome") != RUNNING:
                break
            try:
                ex = self.session.get(f"{RUN_API}/{execution}", timeout=HTTP_TIMEOUT_S)
                finished = ex.status_code == 200 and bool((ex.json() or {}).get("completionTime"))
            except Exception as e:  # noqa: BLE001 - the run record is the authority; keep waiting
                logger.warning(f"Enforcer execution read failed ({type(e).__name__}); waiting for its run record")
                finished = False
            if finished:
                record = self._record(execution_id)
                if not record.get("outcome") or record.get("outcome") == RUNNING:
                    raise EnforcerRunError("ENFORCER_ENDED_WITHOUT_OUTCOME", execution, execution)
                break
            if self.clock() >= deadline:
                raise EnforcerRunError("ENFORCER_TIMEOUT",
                                       f"no outcome from {execution} after {self.wait_s:.0f}s (it may still finish; "
                                       "its run record is the authority)", execution)
            self.sleep(self.poll_s)

        outcome = record["outcome"]
        logger.warning(json.dumps({"event": "FINOPS_ENFORCER_OUTCOME", "product_id": product_id,
                                   "execution": execution, "outcome": outcome}))
        if outcome in accepted or outcome == REFUSED:
            return {"status": outcome, "execution": execution, "reason": record.get("reason", "")}
        raise EnforcerRunError(f"ENFORCER_{outcome}",
                               f"{execution} {record.get('error') or record.get('reason') or ''}".strip(), execution)
