"""FD-30 LIVE calibration (SPENDS MONEY on Vertex). Skipped unless STACKVEND_EVAL_LIVE=1 and the owner has approved
the spend. Never part of the default suite or CI.

    STACKVEND_EVAL_LIVE=1 STACKVEND_EVAL_VERTEX_PROJECT=<dev project> STACKVEND_EVAL_MODEL=<model> \
        pytest tests/test_eval_live.py

Optional (RT finding 1c): STACKVEND_EVAL_IMPERSONATE_SA=<sa email> adds --impersonate-service-account.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

pytestmark = pytest.mark.skipif(os.environ.get("STACKVEND_EVAL_LIVE") != "1",
                                reason="live Vertex calibration: set STACKVEND_EVAL_LIVE=1 (owner-approved spend only)")


def test_live_calibration_example_01_under_two_dollars(tmp_path):
    model = os.environ["STACKVEND_EVAL_MODEL"]
    cmd = [sys.executable, str(ROOT / "eval" / "run_examples.py"), "--examples", "01", "--runs", "1",
           "--llm", "record", "--model", model, "--budget-usd", "2", "--run-cap", "2",
           "--accept-unverified-prices", "--out", str(tmp_path), "--out-id", "calibration"]
    if os.environ.get("STACKVEND_EVAL_IMPERSONATE_SA"):
        cmd += ["--impersonate-service-account", os.environ["STACKVEND_EVAL_IMPERSONATE_SA"]]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=3600, env=hermetic_guard.child_env())
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-3000:]
    res = json.loads((tmp_path / "calibration" / "runs" / "01-r1" / "result.json").read_text())
    assert res["canary"]["ok"] is True
    assert res["budget"]["settled_usd"] <= 2.0
    for c in res["llm"]["per_call"]:  # B6: thinking tokens inside the reserved max_output_tokens
        u = c.get("usage") or {}
        if c.get("max_output_tokens") and u:
            assert u["candidates"] + u["thoughts"] <= c["max_output_tokens"]
