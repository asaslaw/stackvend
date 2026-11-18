#!/usr/bin/env python3
"""Scoring child: credential-less, network-less scoring of finished runs (plan §3.3; red-team H1, H6).

    python -I eval/score_child.py --config <scoring_config.json>

Installs the socket + gRPC guards with an EMPTY allowlist (nothing in this process may reach the network) and
runs tofu only through TofuRunner (offline mirror, sandbox-exec on macOS, allowlisted subcommands).
"""
from __future__ import annotations

import json
import sys
import traceback
from pathlib import Path

EVAL_DIR = Path(__file__).resolve().parent


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", required=True)
    a = ap.parse_args()
    cfg = json.loads(Path(a.config).read_text())
    sys.path.insert(0, str(EVAL_DIR))
    from stackvend_eval.guard import Guard
    from stackvend_eval.state import get_state
    state = get_state()
    g = Guard(state, allow_hosts=[])
    g.install_grpc_guard()
    g.install_socket_guard()
    g.install_client_guards()
    g.install_auth_guard()
    from stackvend_eval.paths import add_dep_dirs
    add_dep_dirs(cfg.get("dep_dirs") or [])  # the parent's python-hcl2/pyflakes dirs (-I dropped its PYTHONPATH)

    from stackvend_eval import invariants
    from stackvend_eval.scoring import score_run
    from stackvend_eval.tofu_runner import TofuRunner
    runner = TofuRunner(Path(cfg["work_root"]), Path(cfg["mirror_dir"]) if cfg.get("mirror_dir") else None,
                        tofu_bin=cfg.get("tofu_bin"))
    oracle = None  # S1-0 (F5): second column (e.g. tofu 1.13.1 + the lane 7 mirror), disagreements listed
    if cfg.get("oracle_mirror_dir") or cfg.get("oracle_tofu_bin"):
        oracle = TofuRunner(Path(cfg["work_root"]) / "oracle",
                            Path(cfg["oracle_mirror_dir"]) if cfg.get("oracle_mirror_dir") else None,
                            tofu_bin=cfg.get("oracle_tofu_bin"))
    regions = invariants.load_regions()
    forbidden = set(cfg.get("forbidden_projects") or [])
    status = 0
    for run_dir in cfg["run_dirs"]:
        rd = Path(run_dir)
        before = len(state.events)
        try:
            s = score_run(rd, runner, regions=regions, forbidden_projects=forbidden, plan=cfg.get("plan", True),
                          oracle=oracle, column_label=cfg.get("column_label") or "default",
                          oracle_label=cfg.get("oracle_label") or "oracle",
                          product_root=Path(cfg["product_root"]) if cfg.get("product_root") else None)
        except Exception:  # noqa: BLE001
            s = {"error": traceback.format_exc()[-3000:]}
            status = 1
        s["scoring_guard_events"] = state.to_json()["events"][before:]
        (rd / "score.json").write_text(json.dumps(s, indent=1, sort_keys=True, default=str))
    return status


if __name__ == "__main__":
    sys.exit(main())
