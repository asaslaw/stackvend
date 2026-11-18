#!/usr/bin/env python3
"""
STAGE-JOB-RUNNER rollback switch (red team N1). Called by scripts/stage-jobs-switch.sh.

  set    --project ID --state on|off [--set-by EMAIL] --token-stdin
         Writes `governance/stage_jobs` in the default Firestore database: {enabled, set_by, set_at}. The gateway
         reads it (cached 15 s) and reports `stage_jobs_enabled` on /health; the workflow reads /health before every
         architect / developer / QA stage. off = the stages run through the synchronous routes as before
         LONG-STAGE-CALLBACK (a stage already running in a stage-runner job finishes there); on = stage-runner jobs.
  status --project ID --token-stdin
         Prints the stored value (or "unset: the release default applies").

No deploy, no apply, no code edit. An env STAGE_JOBS_ENABLED on the gateway, when set, wins over this setting.
Exit 1 on any failure. Standard library only.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Callable, Optional, Tuple

HTTP_TIMEOUT = 30
COLLECTION, DOCUMENT = "governance", "stage_jobs"
Http = Callable[[str, str, Optional[bytes]], Tuple[int, Any]]


def doc_url(project: str) -> str:
    return (f"https://firestore.googleapis.com/v1/projects/{project}/databases/(default)/documents/"
            f"{COLLECTION}/{DOCUMENT}")


def make_http(token: str, quota_project: str) -> Http:
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json",
               "X-Goog-User-Project": quota_project}

    def call(method: str, url: str, body: Optional[bytes] = None) -> Tuple[int, Any]:
        req = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                raw, status = resp.read(), resp.status
        except urllib.error.HTTPError as e:
            raw, status = e.read(), e.code
        try:
            return status, json.loads(raw.decode("utf-8")) if raw else None
        except ValueError:
            return status, None
    return call


def set_switch(http: Http, project: str, enabled: bool, set_by: str, now: Optional[str] = None) -> None:
    fields = {"enabled": {"booleanValue": bool(enabled)}, "set_by": {"stringValue": set_by or "unknown"},
              "set_at": {"timestampValue": now or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}}
    mask = "&".join(f"updateMask.fieldPaths={k}" for k in fields)
    status, body = http("PATCH", f"{doc_url(project)}?{mask}", json.dumps({"fields": fields}).encode("utf-8"))
    if status != 200:
        raise RuntimeError(f"Firestore answered HTTP {status}: {json.dumps(body)[:300]}")
    stored = ((body or {}).get("fields") or {}).get("enabled", {}).get("booleanValue")
    if stored is not bool(enabled):
        raise RuntimeError("Firestore did not store the requested value")


def read_switch(http: Http, project: str) -> Optional[bool]:
    status, body = http("GET", doc_url(project), None)
    if status == 404:
        return None
    if status != 200:
        raise RuntimeError(f"Firestore answered HTTP {status}: {json.dumps(body)[:300]}")
    value = ((body or {}).get("fields") or {}).get("enabled", {}).get("booleanValue")
    return value if isinstance(value, bool) else None


def main(argv: Optional[list] = None, http_factory: Callable[[str, str], Http] = make_http,
         stdin: Any = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("set")
    s.add_argument("--project", required=True)
    s.add_argument("--state", required=True, choices=["on", "off"])
    s.add_argument("--set-by", default="")
    s.add_argument("--token-stdin", action="store_true", required=True)
    st = sub.add_parser("status")
    st.add_argument("--project", required=True)
    st.add_argument("--token-stdin", action="store_true", required=True)
    a = p.parse_args(argv)
    token = (stdin or sys.stdin).readline().strip()
    if not token:
        print("stage-jobs-switch: no access token on stdin", file=sys.stderr)
        return 1
    http = http_factory(token, a.project)
    try:
        if a.cmd == "set":
            set_switch(http, a.project, a.state == "on", a.set_by)
            print(f"stage jobs {a.state.upper()} on {a.project}: the gateway reports it within 15 s; the next stage "
                  f"of every run uses {'stage-runner jobs' if a.state == 'on' else 'the synchronous routes'}")
        else:
            v = read_switch(http, a.project)
            print("unset: the release default applies" if v is None else ("on" if v else "off"))
    except Exception as e:  # noqa: BLE001
        print(f"stage-jobs-switch: FAILED: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
