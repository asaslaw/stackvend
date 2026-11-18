#!/usr/bin/env python3
"""
FD-7L Phase 0 (read-only): scan copies of live workload state for resources outside the workload's own project (plan
section 1.5 / RT F13: a deployer that owns only its own project could not manage them) and for the GKE deployer-token
pattern (RT F14).

Usage:  python3 scripts/fd7l-phase0/state_scan.py [--json] <state dir>

<state dir> holds `<product_id>.tfstate` (a copy of gs://<TFSTATE_BUCKET>/workloads/<product_id>/default.tfstate)
and `<product_id>.project` (the workload's project id), as written by phase0_reads.sh --state-dir. Prints resource
ADDRESSES, TYPES and PROJECT IDS only, never attribute values (state holds secrets). Delete the directory afterwards.

Lines:
  CROSS_PROJECT <pid> <address> <type> project=<other>   a managed resource whose `project` is not the workload's
  CLIENT_CONFIG_TOKEN <pid> <address>                   data.google_client_config with an access_token in state
  UNREADABLE <pid> <why>
  SUMMARY workloads=<n> resources=<n> cross_project=<n> client_config_tokens=<n> unreadable=<n>
Exit: 0 when no CROSS_PROJECT resource, 1 otherwise, 2 usage error.
"""
import json
import os
import sys


def _address(res):
    mod = res.get("module")
    base = f"{'data.' if res.get('mode') == 'data' else ''}{res.get('type')}.{res.get('name')}"
    return f"{mod}.{base}" if mod else base


def scan_state(pid, state, own_project):
    cross, tokens, count = [], [], 0
    for res in state.get("resources") or []:
        if not isinstance(res, dict):
            continue
        for inst in res.get("instances") or []:
            count += 1
            attrs = inst.get("attributes") if isinstance(inst, dict) else None
            attrs = attrs if isinstance(attrs, dict) else {}
            addr = _address(res) + (f"[{json.dumps(inst['index_key'])}]" if "index_key" in inst else "")
            if res.get("mode") == "data" and res.get("type") == "google_client_config" and attrs.get("access_token"):
                tokens.append(addr)
            project = attrs.get("project")
            if res.get("mode") == "managed" and isinstance(project, str) and project and project != own_project:
                cross.append((addr, res.get("type"), project))
    return cross, tokens, count


def main(argv):
    as_json = "--json" in argv
    dirs = [a for a in argv if not a.startswith("--")]
    if len(dirs) != 1 or not os.path.isdir(dirs[0]):
        print(__doc__, file=sys.stderr)
        return 2
    d = dirs[0]
    out = {"cross_project": [], "client_config_tokens": [], "unreadable": [], "workloads": 0, "resources": 0}
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".tfstate"):
            continue
        pid = fn[:-len(".tfstate")]
        out["workloads"] += 1
        try:
            with open(os.path.join(d, pid + ".project"), encoding="utf-8") as fh:
                own = fh.read().strip()
            with open(os.path.join(d, fn), encoding="utf-8") as fh:
                state = json.load(fh)
        except Exception as e:  # noqa: BLE001
            out["unreadable"].append({"product_id": pid, "why": type(e).__name__})
            continue
        cross, tokens, count = scan_state(pid, state if isinstance(state, dict) else {}, own)
        out["resources"] += count
        out["cross_project"] += [{"product_id": pid, "address": a, "type": t, "project": p} for a, t, p in cross]
        out["client_config_tokens"] += [{"product_id": pid, "address": a} for a in tokens]
    if as_json:
        print(json.dumps(out, indent=1))
    else:
        for r in out["cross_project"]:
            print("CROSS_PROJECT", r["product_id"], r["address"], r["type"], f"project={r['project']}")
        for r in out["client_config_tokens"]:
            print("CLIENT_CONFIG_TOKEN", r["product_id"], r["address"])
        for r in out["unreadable"]:
            print("UNREADABLE", r["product_id"], r["why"])
        print(f"SUMMARY workloads={out['workloads']} resources={out['resources']} "
              f"cross_project={len(out['cross_project'])} client_config_tokens={len(out['client_config_tokens'])} "
              f"unreadable={len(out['unreadable'])}")
    return 1 if out["cross_project"] else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
