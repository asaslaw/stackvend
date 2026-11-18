"""
StackVend: sandbox-garbage-collector-job entrypoint (C32).

As a Cloud Run job (``CLOUD_RUN_JOB`` / ``CLOUD_RUN_EXECUTION`` set, or ``--batch``, or no ``PORT``) it runs ONE ledger
pass (``cleaner.SandboxGarbageCollector.execute_cleanup``) and exits with the run's exit code (0 ok, 1 error,
2 usage, 3 NOT_CONFIGURED). ``--dry-run`` is an operator flag: it reads the ledger and reports ``WOULD_REQUEST`` per due
record, with no vending call and no Firestore write. Scheduled runs never pass it.

The FastAPI app (``/health``, ``/clean``) is kept for local operation; the job is not deployed as a service.
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
from pydantic import BaseModel

from cleaner import EXIT_USAGE, JOB_NAME, SandboxGarbageCollector

logger = logging.getLogger("sandbox-cleaner-runner")
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="StackVend Sandbox Garbage Collector",
    description="Expires registered ephemeral resources past their TTL through project-repo-vending (EPHEMERAL_TTL).",
    version="2.0.0",
)

_collector: Optional[SandboxGarbageCollector] = None


def get_collector() -> SandboxGarbageCollector:
    """Built on first use (not at import), so importing this module never constructs a cloud client."""
    global _collector
    if _collector is None:
        _collector = SandboxGarbageCollector()
    return _collector


class CleanRequest(BaseModel):
    dry_run: bool = False


@app.get("/health")
def health_check():
    return {**get_collector().health(), "release": release_info.current_release()}  # FD-7C P3a


@app.post("/clean")
def trigger_cleanup(req: Optional[CleanRequest] = None):
    """One ledger pass, same as a scheduled run. Non-zero exit outcomes answer 500 (error) or 503 (NOT_CONFIGURED)."""
    report = get_collector().execute_cleanup(dry_run=bool(req and req.dry_run))
    status = {0: 200, 3: 503}.get(report["exit_code"], 500)
    return JSONResponse(status_code=status, content=report)


def _parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog=JOB_NAME, description="StackVend ephemeral-resource TTL cleaner")
    parser.add_argument("--batch", action="store_true", help="run one ledger pass and exit (Cloud Run job mode)")
    parser.add_argument("--dry-run", action="store_true", help="report what would be requested; no call, no write")
    return parser.parse_args(argv)


def run_batch(argv: List[str], collector: Optional[SandboxGarbageCollector] = None) -> int:
    try:
        args = _parse_args(argv)
    except SystemExit:
        return EXIT_USAGE
    report = (collector or get_collector()).execute_cleanup(dry_run=args.dry_run)
    print(json.dumps(report, indent=2, default=str))
    return int(report["exit_code"])


if __name__ == "__main__":
    if os.getenv("CLOUD_RUN_JOB") or os.getenv("CLOUD_RUN_EXECUTION") or "--batch" in sys.argv or not os.getenv("PORT"):
        release_info.log_release("sandbox-garbage-collector-job")  # FD-7C P3a: one stackvend.release line per run
        logger.info("Executing the sandbox garbage collector as a Cloud Run batch job...")
        sys.exit(run_batch(sys.argv[1:]))
    else:
        import uvicorn

        uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
