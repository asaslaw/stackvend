"""
StackVend: GitHub Refactor Scanner Service API (github-refactor-scanner-job)
FastAPI interface for an on-demand scan of ONE ledger workload's repository, and the nightly batch entrypoint.

Lane 14 PR-4: /scan takes `product_id` only (the repository, branch and provider come from the workload ledger; no
caller-supplied path or repo). The batch job scans every eligible workload (scanner.py).
"""

import release_info  # FD-7C P3a (SELFUP-VERSION-RECORD): this build's release.json, read-only
import os
from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from scanner import EXIT_NOT_CONFIGURED, RefactorScanner

app = FastAPI(
    title="StackVend GitHub Refactor Scanner Service",
    description="AST static analysis, test gap detection and Bandit for workload repositories; one refactor event per product.",
    version="2.0.0",
)

scanner = RefactorScanner()


class ScanRequest(BaseModel):
    # FD-4G (T13): no caller-supplied workspace_dir. Lane 14 PR-4: the target is a ledger workload.
    product_id: str = Field(min_length=1)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "github-refactor-scanner-job",
        "environment": os.getenv("ENVIRONMENT", "prod"),
        "vending_url_configured": bool(os.getenv("VENDING_SERVICE_URL")),
        "git_server_url_configured": bool(os.getenv("GIT_SERVER_URL")),
        "release": release_info.current_release(),  # FD-7C P3a: read-only, from this build's release.json
    }


@app.post("/scan")
def trigger_scan(req: ScanRequest):
    """Scans one ledger workload's repository and dispatches at most one refactor event for it."""
    code, report = scanner.run(product_id=req.product_id)
    if code == EXIT_NOT_CONFIGURED:
        raise HTTPException(status_code=503, detail=report)
    if not report.get("scans") and report.get("outcome") == "OK":
        raise HTTPException(status_code=404, detail={"status": "NOT_A_SCAN_TARGET", "skipped": report.get("skipped", [])})
    return report


if __name__ == "__main__":
    import logging
    import sys

    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("refactor-scanner-runner")

    if os.getenv("CLOUD_RUN_JOB") or os.getenv("CLOUD_RUN_EXECUTION") or "--batch" in sys.argv or not os.getenv("PORT"):
        release_info.log_release("github-refactor-scanner-job")  # FD-7C P3a: one stackvend.release line per run
        logger.info("Executing Refactor Scanner as Cloud Run Batch Job...")
        exit_code, summary = scanner.run()
        logger.info(f"Refactor Scanner finished (exit {exit_code}): {summary.get('outcome')}")
        sys.exit(exit_code)
    else:
        import uvicorn

        port = int(os.getenv("PORT", "8080"))
        uvicorn.run(app, host="0.0.0.0", port=port)
