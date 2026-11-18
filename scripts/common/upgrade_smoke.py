#!/usr/bin/env python3
"""FD-4DA item 9: the read-only smoke check at the end of scripts/upgrade.sh.

Input: the JSON of `gcloud run services list --format=json` (Cloud Run Admin API v1 Service objects). Only typed fields
are read, never text:

- platform services = services whose label `managed_by` is exactly `castor-terraform` (the label infra/platform/main.tf
  puts on every platform Cloud Run service);
- each must have condition `Ready` with status `True` and `status.latestReadyRevisionName` equal to
  `status.latestCreatedRevisionName` (its newest revision serves);
- platform stamp (FD-4DA item 10): when the release declares it (`--stamp-required yes`), the Control Center service's
  annotation `stackvend/platform-commit` must equal `--expect-commit`. When present on an older release it must match too.

Exit 0 = pass, 1 = a finding (each printed as `CLASS: detail`), 2 = unreadable input or usage. Prints no secrets
(names, revisions and commits only).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any, Dict, List

PLATFORM_LABEL = ("managed_by", "castor-terraform")
CONTROL_CENTER = "product-control-center-ui"
STAMP_COMMIT = "stackvend/platform-commit"
COMMIT_RE = re.compile(r"[0-9a-f]{40}")


def _str(d: Any, *keys: str) -> str:
    for k in keys:
        if not isinstance(d, dict):
            return ""
        d = d.get(k)
    return d if isinstance(d, str) else ""


def platform_services(services: List[Any]) -> List[Dict[str, Any]]:
    return [s for s in services
            if isinstance(s, dict) and isinstance(s.get("metadata"), dict)
            and isinstance(s["metadata"].get("labels"), dict)
            and s["metadata"]["labels"].get(PLATFORM_LABEL[0]) == PLATFORM_LABEL[1]]


def check(services: List[Any], expect_commit: str, stamp_required: bool) -> List[str]:
    findings: List[str] = []
    platform = platform_services(services)
    if not platform:
        return [f"SMOKE_NO_PLATFORM_SERVICES: no Cloud Run service with label {PLATFORM_LABEL[0]}={PLATFORM_LABEL[1]}"]
    by_name = {}
    for s in platform:
        name = _str(s, "metadata", "name") or "<unnamed>"
        by_name[name] = s
        conditions = (s.get("status") or {}).get("conditions") if isinstance(s.get("status"), dict) else None
        ready = [c for c in (conditions or []) if isinstance(c, dict) and c.get("type") == "Ready"]
        if len(ready) != 1 or ready[0].get("status") != "True":
            state = ready[0].get("status") if len(ready) == 1 else "missing"
            findings.append(f"SMOKE_SERVICE_NOT_READY: {name} (Ready={state})")
            continue
        newest = _str(s, "status", "latestCreatedRevisionName")
        serving = _str(s, "status", "latestReadyRevisionName")
        if not newest or newest != serving:
            findings.append(f"SMOKE_NEWEST_REVISION_NOT_READY: {name} (newest {newest or '?'}, ready {serving or '?'})")
    cc = by_name.get(CONTROL_CENTER)
    stamp = _str(cc, "metadata", "annotations", STAMP_COMMIT) if cc is not None else ""
    if stamp_required and cc is None:
        findings.append(f"SMOKE_STAMP_MISSING: {CONTROL_CENTER} is not among the platform services")
    elif stamp:
        if stamp != expect_commit:
            findings.append(f"SMOKE_STAMP_MISMATCH: {CONTROL_CENTER} {STAMP_COMMIT}={stamp}, expected {expect_commit}")
    elif stamp_required:
        findings.append(f"SMOKE_STAMP_MISSING: {CONTROL_CENTER} has no {STAMP_COMMIT} annotation")
    return findings


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--services-json", required=True)
    ap.add_argument("--expect-commit", required=True)
    ap.add_argument("--stamp-required", required=True, choices=("yes", "no"))
    args = ap.parse_args(argv)
    if not COMMIT_RE.fullmatch(args.expect_commit):
        print("SMOKE_USAGE: --expect-commit must be a 40-character commit id", file=sys.stderr)
        return 2
    try:
        with open(args.services_json, encoding="utf-8") as f:
            services = json.load(f)
    except (OSError, ValueError) as e:
        print(f"SMOKE_UNREADABLE: {type(e).__name__}", file=sys.stderr)
        return 2
    if not isinstance(services, list):
        print("SMOKE_UNREADABLE: the services list is not a JSON array", file=sys.stderr)
        return 2
    findings = check(services, args.expect_commit, args.stamp_required == "yes")
    for line in findings:
        print(line, file=sys.stderr)
    if findings:
        return 1
    n = len(platform_services(services))
    print(f"Smoke check passed: {n} platform services Ready on their newest revision"
          + ("; platform stamp matches." if args.stamp_required == "yes" else "."), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
