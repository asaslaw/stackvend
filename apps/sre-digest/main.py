"""
StackVend: sre-telemetry-digest-job entrypoint (C33).

As a Cloud Run job (``CLOUD_RUN_JOB`` / ``CLOUD_RUN_EXECUTION`` set, or ``--batch``, or no ``PORT``) it runs ONE weekly
digest (``digest.SRETelemetryDigest.generate_digest_report``) from real Cloud Logging / Cloud Monitoring data and exits
with the run's exit code (0 ok, 1 error, 2 usage, 3 NOT_CONFIGURED).

The FastAPI app (``/health``, ``/digest``) is kept for local operation; the job is not deployed as a service. The API
no longer accepts caller-supplied sample logs or metrics (lane 14 PR-3: the digest reports only real telemetry).
"""

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
import argparse
import json
import logging
import os
import sys
from typing import List, Optional

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from digest import EXIT_USAGE, JOB_NAME, NotConfigured, SRETelemetryDigest

logger = logging.getLogger("sre-digest-runner")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="StackVend SRE Telemetry Digest",
    description="Weekly warning-log clusters and p95 latency regressions from Cloud Logging and Cloud Monitoring.",
    version="2.0.0",
)

_engine: Optional[SRETelemetryDigest] = None


def get_engine() -> SRETelemetryDigest:
    """Built on first use (not at import), so importing this module never constructs a cloud client."""
    global _engine
    if _engine is None:
        _engine = SRETelemetryDigest()
    return _engine


@app.get("/health")
def health_check():
    engine = get_engine()
    missing = [] if engine.project_id else ["PROJECT_ID"]
    try:
        settings = engine.settings()
    except NotConfigured as e:
        settings, missing = None, missing + e.missing
    return {"status": "degraded" if missing else "healthy", "service": JOB_NAME,
            "missing_configuration": missing, "settings": settings,
            "release": release_info.current_release()}  # FD-7C P3a


@app.post("/digest")
def run_digest():
    """One digest run, same as the weekly schedule. Non-zero exit outcomes answer 500 (error) or 503 (NOT_CONFIGURED)."""
    report = get_engine().generate_digest_report()
    return JSONResponse(status_code={0: 200, 3: 503}.get(report["exit_code"], 500), content=report)


def run_batch(argv: List[str], engine: Optional[SRETelemetryDigest] = None) -> int:
    parser = argparse.ArgumentParser(prog=JOB_NAME, description="StackVend weekly SRE telemetry digest")
    parser.add_argument("--batch", action="store_true", help="run one digest and exit (Cloud Run job mode)")
    try:
        parser.parse_args(argv)
    except SystemExit:
        return EXIT_USAGE
    report = (engine or get_engine()).generate_digest_report()
    print(json.dumps(report, indent=2, default=str))
    return int(report["exit_code"])


if __name__ == "__main__":
    if os.getenv("CLOUD_RUN_JOB") or os.getenv("CLOUD_RUN_EXECUTION") or "--batch" in sys.argv or not os.getenv("PORT"):
        release_info.log_release("sre-telemetry-digest-job")  # FD-7C P3a: one stackvend.release line per run
        logger.info("Executing the SRE telemetry digest as a Cloud Run batch job...")
        sys.exit(run_batch(sys.argv[1:]))
    else:
        import uvicorn

        uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
