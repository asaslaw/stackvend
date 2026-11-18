"""Where this gateway code runs (STAGE-JOB-RUNNER red team G1, 11-14). Standard library only.

The gateway image runs in two places: the `orchestrator-gateway-service` Cloud Run service (Cloud Run sets
`K_SERVICE`) and the `stage-runner` Cloud Run Job (Cloud Run sets `CLOUD_RUN_JOB`, not `K_SERVICE`). Every fail-closed
gate that is strict "on Cloud Run" and relaxed in local runs and tests asks `on_cloud_run()`, never `K_SERVICE`
directly, so the gates stay closed inside the job too (pinned by tests/test_stage_runner_gates.py: no other file under
apps/orchestrator-gateway/ reads `K_SERVICE`).
"""

import os


def on_cloud_run() -> bool:
    """True on a Cloud Run service revision or a Cloud Run Job execution."""
    return bool(os.getenv("K_SERVICE") or os.getenv("CLOUD_RUN_JOB"))
