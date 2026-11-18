#!/usr/bin/env python3
"""
StackVend deployed version record (FD-7C P3a, SELFUP-VERSION-RECORD). Called by scripts/deploy-services.sh.

  stamp  --repo-root DIR [--builder deploy-services]
         Print the `release.json` document for this checkout on stdout (plan §3.11.1):
         release from VERSION, commit from `git rev-parse HEAD`, dirty = a TRACKED file differs from that commit
         (`git status --porcelain --untracked-files=no` is not empty; untracked files such as local tool notes never
         make a build dirty, SAT-48: the rule the platform stamp in scripts/common/platform_target.sh already uses),
         source_repo from STACKVEND_SOURCE_REPO, else the `origin` remote only when it is one of the two exact
         github.com URL forms, else "local checkout". Exit 1 (nothing printed) when VERSION is missing or is not a
         SemVer version, or STACKVEND_SOURCE_REPO is set but is not an owner/repo name.

  record --project ID --region REGION --release-file FILE [--deployed-by EMAIL] [--full-run]
         (--token-stdin | --token-from-metadata) NAME...
         The quota-project header (X-Goog-User-Project) is sent only with the operator's --token-stdin token, never
         with the build identity's metadata token (SAT-48 H-1: that would need serviceusage.services.use).
         After a deploy: read back each deployed component's image from Cloud Run (typed fields, never assumed) and
         write `system_config/platform_release` in the default Firestore database once (Firestore REST, an
         updateTime precondition, 3 attempts). The token: the operator's own, read from stdin (deploy-services.sh), or
         the build identity's from the metadata server (the upgrader, `stamp --builder upgrader`; SELFUP P3b M-8).
         Exit 1 on any failure.

A record failure never fails a deploy: deploy-services.sh prints a warning and carries on (plan §3.11.3). The record
is information, never a security input (the Control Center checks it against the images actually running).
Standard library only.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import importlib.util

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _load_release_manifest():
    """Root shared/release_manifest.py by exact path (shared/ is never put on sys.path: its module names could shadow
    the standard library)."""
    path = os.path.join(REPO_ROOT, "shared", "release_manifest.py")
    spec = importlib.util.spec_from_file_location("stackvend_release_manifest", path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclasses resolve their module through sys.modules
    spec.loader.exec_module(mod)
    return mod


rm = _load_release_manifest()

BUILDERS = ("deploy-services", "upgrader", "bootstrap")
RELEASE_FIELDS = ("schema_version", "release", "commit", "dirty", "built_at", "source_repo", "builder")
RECORD_SCHEMA = 1
HTTP_TIMEOUT = 15
ATTEMPTS = 3
FIRESTORE = "https://firestore.googleapis.com/v1"


class RecordError(Exception):
    pass


# ------------------------------------------------------------------------------------------------ stamp
def _git(repo_root: str, *args: str) -> Optional[str]:
    try:
        res = subprocess.run(["git", "-C", repo_root, *args], capture_output=True, timeout=30, check=True)
    except (OSError, subprocess.SubprocessError):
        return None
    return res.stdout.decode("utf-8", "replace")


def _is_commit(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 40 and set(value) <= set("0123456789abcdef")


def tracked_changes(repo_root: str) -> Optional[bool]:
    """True when a TRACKED file differs from HEAD (modified, staged, deleted, renamed); None when git cannot tell.
    Untracked files are not a change to the commit (SAT-48: an operator's untracked tool notes made every
    component `dirty`); the platform stamp (platform_target.sh sv_export_platform_stamp) uses the same rule."""
    status = _git(repo_root, "status", "--porcelain", "--untracked-files=no")
    return None if status is None else bool(status.strip())


def make_release_document(repo_root: str, builder: str = "deploy-services",
                          env: Optional[Dict[str, str]] = None, now: Optional[datetime] = None,
                          ) -> Dict[str, Any]:
    env = os.environ if env is None else env
    if builder not in BUILDERS:
        raise RecordError(f"builder must be one of {BUILDERS}")
    try:
        with open(os.path.join(repo_root, "VERSION"), encoding="utf-8") as fh:
            version = fh.read().strip()
    except OSError:
        raise RecordError("no VERSION file in the checkout") from None
    if rm.parse_semver(version) is None:
        raise RecordError(f"VERSION {version!r} is not a SemVer version")
    head = (_git(repo_root, "rev-parse", "HEAD") or "").strip()
    commit = head if _is_commit(head) else "unknown"
    if commit == "unknown":
        dirty = True  # not a readable git checkout: never claim a clean tree
    else:
        changed = tracked_changes(repo_root)
        dirty = True if changed is None else changed
    override = env.get("STACKVEND_SOURCE_REPO", "")
    if override:
        if not rm.is_valid_repository(override):
            raise RecordError(f"STACKVEND_SOURCE_REPO {override!r} is not an owner/repo name")
        source = override
    else:
        source = rm.repository_from_remote_url((_git(repo_root, "remote", "get-url", "origin") or "").strip()) \
            or "local checkout"
    built_at = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"schema_version": 1, "release": version, "commit": commit, "dirty": dirty, "built_at": built_at,
            "source_repo": source, "builder": builder}


# ------------------------------------------------------------------------------------------------ record (pure)
def _valid_release(doc: Any) -> bool:
    return isinstance(doc, dict) and set(doc) == set(RELEASE_FIELDS) and doc.get("schema_version") == 1 \
        and isinstance(doc.get("release"), str) and isinstance(doc.get("commit"), str) \
        and type(doc.get("dirty")) is bool and doc.get("builder") in BUILDERS


def merge_record(existing: Any, release: Dict[str, Any], components: Dict[str, Dict[str, str]], deployed_by: str,
                 run_id: str, now_iso: str, full_run: bool) -> Tuple[Dict[str, Any], List[str]]:
    """The new record and warnings. Only the components that deployed in this run change; one history entry per run
    (newest first, capped at HISTORY_LIMIT). The top-level release is that of the last full run."""
    warnings: List[str] = []
    base: Dict[str, Any] = {}
    if isinstance(existing, dict):
        base = dict(existing)
        if base.get("schema_version") not in (None, RECORD_SCHEMA) or not isinstance(base.get("components", {}), dict) \
                or not isinstance(base.get("history", []), list):
            warnings.append("the stored record had an unexpected shape; it was replaced")
            base = {}
    merged_components = {k: v for k, v in (base.get("components") or {}).items()
                         if isinstance(k, str) and isinstance(v, dict)}
    for name, live in components.items():
        merged_components[name] = {
            "kind": rm.COMPONENT_KINDS[name],
            "image_digest": live["image_digest"],
            "revision": live.get("revision", ""),
            "release": release["release"], "commit": release["commit"], "dirty": release["dirty"],
            "source_repo": release["source_repo"], "built_at": release["built_at"], "deployed_at": now_iso,
        }
    entry = {"deployed_at": now_iso, "deployed_by": deployed_by, "deployer": release["builder"], "run_id": run_id,
             "release": release["release"], "commit": release["commit"], "dirty": release["dirty"],
             "source_repo": release["source_repo"], "components": sorted(components), "full_run": full_run}
    history = [h for h in (base.get("history") or []) if isinstance(h, dict)]
    record = {
        "schema_version": RECORD_SCHEMA,
        "release": base.get("release"), "commit": base.get("commit"), "dirty": base.get("dirty"),
        "source_repo": base.get("source_repo"),
        "components": merged_components,
        "deployed_at": now_iso, "deployed_by": deployed_by, "deployer": release["builder"], "run_id": run_id,
        "history": ([entry] + history)[:rm.HISTORY_LIMIT],
    }
    if full_run:
        record.update({"release": release["release"], "commit": release["commit"], "dirty": release["dirty"],
                       "source_repo": release["source_repo"]})
    return record, warnings


# ------------------------------------------------------------------------------------------------ Firestore values
def to_value(v: Any) -> Dict[str, Any]:
    if v is None:
        return {"nullValue": None}
    if isinstance(v, bool):
        return {"booleanValue": v}
    if isinstance(v, int):
        return {"integerValue": str(v)}
    if isinstance(v, float):
        return {"doubleValue": v}
    if isinstance(v, str):
        return {"stringValue": v}
    if isinstance(v, dict):
        return {"mapValue": {"fields": {str(k): to_value(x) for k, x in v.items()}}}
    if isinstance(v, (list, tuple)):
        return {"arrayValue": {"values": [to_value(x) for x in v]}}
    raise RecordError(f"cannot store a {type(v).__name__}")


def from_value(v: Dict[str, Any]) -> Any:
    if "nullValue" in v:
        return None
    if "booleanValue" in v:
        return bool(v["booleanValue"])
    if "integerValue" in v:
        return int(v["integerValue"])
    if "doubleValue" in v:
        return float(v["doubleValue"])
    if "stringValue" in v:
        return v["stringValue"]
    if "timestampValue" in v:
        return v["timestampValue"]
    if "mapValue" in v:
        return {k: from_value(x) for k, x in (v["mapValue"].get("fields") or {}).items()}
    if "arrayValue" in v:
        return [from_value(x) for x in (v["arrayValue"].get("values") or [])]
    raise RecordError(f"unsupported Firestore value {sorted(v)}")


# ------------------------------------------------------------------------------------------------ HTTP
Http = Callable[[str, str, Optional[bytes]], Tuple[int, Any]]


def make_http(token: str, quota_project: str) -> Http:
    """`quota_project` non-empty: send `X-Goog-User-Project` (the operator's own token from stdin: a user credential
    needs a quota project). Empty: no header (SAT-48 review H-1: a service account's token from the metadata server
    bills its own project; the header would need serviceusage.services.use, which the build identities lack)."""
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    if quota_project:
        headers["X-Goog-User-Project"] = quota_project

    def call(method: str, url: str, body: Optional[bytes] = None) -> Tuple[int, Any]:
        req = urllib.request.Request(url, data=body, method=method, headers=dict(headers))
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as e:
            raw, status = e.read(), e.code
        try:
            return status, json.loads(raw.decode("utf-8")) if raw else None
        except ValueError:
            return status, None
    return call


def write_record(http: Http, project: str, region: str, release: Dict[str, Any], names: List[str], deployed_by: str,
                 full_run: bool, now_iso: Optional[str] = None, run_id: Optional[str] = None) -> List[str]:
    """Read the components back from Cloud Run and write the record. Returns warnings; raises RecordError."""
    unknown = sorted(set(names) - set(rm.COMPONENT_KINDS))
    if unknown:
        raise RecordError(f"unknown components {unknown}")
    if not _valid_release(release):
        raise RecordError("the release file is not a release.json document")
    warnings: List[str] = []
    components: Dict[str, Dict[str, str]] = {}
    for name in sorted(set(names)):
        try:
            live = rm.read_component(lambda url: http("GET", url, None), project, region, name, rm.COMPONENT_KINDS[name])
        except rm.ComponentReadError as e:
            warnings.append(f"{name}: not recorded ({e.code}: {e.detail})")
            continue
        if live.get("image_tag"):  # a mutable tag cannot identify what was deployed (review M4)
            warnings.append(f"{name}: not recorded (IMAGE_BY_TAG: {live['image_tag']})")
            continue
        components[name] = {"image_digest": live["image_digest"], "revision": live["revision"]}
    if not components:
        raise RecordError("no deployed component could be read back from Cloud Run")
    now_iso = now_iso or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    run_id = run_id or uuid.uuid4().hex
    # DISPLAY ONLY. This record lives in the (default) database, which every agent service account with project-wide
    # datastore.user can write (including the identity tf-applier runs as). Settings cross-checks it against the running
    # digests, so a rewrite can only make the page show a wrong release. It must never be used as the installed
    # version for an upgrade decision (P3b reads that from something the upgrader controls: the guard database or the
    # image's own release.json).
    doc_url = (f"{FIRESTORE}/projects/{project}/databases/(default)/documents/"
               f"{rm.RECORD_COLLECTION}/{rm.RECORD_DOCUMENT}")
    last = ""
    for _ in range(ATTEMPTS):
        status, body = http("GET", doc_url, None)
        if status == 200 and isinstance(body, dict):
            existing = from_value({"mapValue": {"fields": body.get("fields") or {}}})
            precondition = "currentDocument.updateTime=" + urllib.parse.quote(str(body.get("updateTime", "")), safe="")
        elif status == 404:
            existing, precondition = None, "currentDocument.exists=false"
        else:
            raise RecordError(f"could not read the record (HTTP {status})")
        record, merge_warnings = merge_record(existing, release, components, deployed_by, run_id, now_iso, full_run)
        payload = json.dumps({"fields": to_value(record)["mapValue"]["fields"]}).encode("utf-8")
        status, body = http("PATCH", f"{doc_url}?{precondition}", payload)
        if status == 200:
            return warnings + merge_warnings
        last = f"HTTP {status}"
        if status not in (400, 409, 412):  # 400 FAILED_PRECONDITION / 409 ABORTED: someone wrote in between, retry
            break
    raise RecordError(f"could not write the record ({last})")


METADATA_TOKEN = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"


def metadata_token(opener: Callable[..., Any] = urllib.request.urlopen) -> str:
    """The build identity's access token from the metadata server (the upgrader's Cloud Build, SELFUP P3b M-8).
    Never printed."""
    req = urllib.request.Request(METADATA_TOKEN, headers={"Metadata-Flavor": "Google"})
    try:
        with opener(req, timeout=HTTP_TIMEOUT) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise RecordError(f"no access token from the metadata server ({type(e).__name__})") from None
    token = body.get("access_token") if isinstance(body, dict) else None
    if not isinstance(token, str) or not token:
        raise RecordError("the metadata server returned no access token")
    return token


# ------------------------------------------------------------------------------------------------ CLI
def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="release_record.py")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("stamp")
    s.add_argument("--repo-root", required=True)
    s.add_argument("--builder", default="deploy-services", choices=BUILDERS)
    r = sub.add_parser("record")
    r.add_argument("--project", required=True)
    r.add_argument("--region", required=True)
    r.add_argument("--release-file", required=True)
    r.add_argument("--deployed-by", default="")
    r.add_argument("--full-run", action="store_true")
    token_from = r.add_mutually_exclusive_group(required=True)
    token_from.add_argument("--token-stdin", action="store_true")
    # SELFUP P3b (plan RT M-8): the upgrader's Cloud Build has no gcloud login; it uses the build identity's token
    token_from.add_argument("--token-from-metadata", action="store_true")
    r.add_argument("components", nargs="+")
    a = p.parse_args(argv)
    try:
        if a.cmd == "stamp":
            print(json.dumps(make_release_document(a.repo_root, a.builder), sort_keys=True))
            return 0
        token = metadata_token() if a.token_from_metadata else sys.stdin.readline().strip()
        if not token:
            raise RecordError("no access token (metadata server)" if a.token_from_metadata
                              else "no access token on stdin")
        with open(a.release_file, encoding="utf-8") as fh:
            release = json.load(fh)
        # H-1: the quota-project header only for the operator's token, never for the build identity's
        http = make_http(token, "" if a.token_from_metadata else a.project)
        for w in write_record(http, a.project, a.region, release, a.components, a.deployed_by, a.full_run):
            print(f"release record: {w}", file=sys.stderr)
        print(f"release record: system_config/platform_release updated ({len(a.components)} component(s))")
        return 0
    except (RecordError, OSError, ValueError) as e:
        print(f"release record: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
