#!/usr/bin/env python3
"""
StackVend release source from a terminal (FD-7C P3a; owner decision 11-01 for installs behind Identity-Aware Proxy).

Behind IAP the Control Center cannot see when an administrator signed in, so Settings refuses to change the release
source there (RECENT_SIGN_IN_UNAVAILABLE, fail closed). This script is the other way: the operator's own Google
credentials (Application Default Credentials, a person, never a service account) write the same setting.

  show  [--project ID] [--guard-database NAME]
        Print where upgrades come from (or why the stored setting is invalid).

  set   --repository OWNER/REPO [--official-key] [--ssh-key-file PATH ...] [--ssh-key-label LABEL ...]
        [--keep-current-keys] [--previews on|off] [--project ID] [--guard-database NAME]
        Validate exactly as the Control Center does (apps/control-center/release_source.py, loaded by path; the same
        `plan_change`), ask for the same typed confirmation (the repository name, and the last 6 characters of each
        newly trusted key's fingerprint), then write `platform_release_source/current` and a never-trimmed
        `platform_release_source/current/changes/{id}` record (`via: "cli"`) in ONE Firestore commit with an
        update-time precondition, and read the result back.

  update-check on|off [--project ID] [--guard-database NAME]
        The "Check for updates" switch (P3a-OFF, plan §3.12): every other field of the stored release source is kept;
        asks you to type ON / OFF to confirm; the same `plan_change`, document shape, change record and commit as `set`.
        Off: the Control Center makes no GitHub call for releases or the upstream-sync variables (updates are manual).

The project comes only from --project or PROJECT_ID (never from gcloud configuration). Who made the change comes from
the credentials (Google's token information endpoint), never from an argument. Only signed release tags can be
followed; the Control Center shows a stored branch or unsigned source as invalid and switches the update check off.
Nothing here prints a token. Every failure is a typed error with one next
command; exit 1.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import types
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FIRESTORE = "https://firestore.googleapis.com/v1"
TOKENINFO = "https://oauth2.googleapis.com/tokeninfo"
GUARD_DATABASE = "stackvend-guard"  # infra/platform/destructive_guard.tf local.guard_db_id (pinned by a test)
HTTP_TIMEOUT = 15
SCOPES = ["https://www.googleapis.com/auth/cloud-platform", "https://www.googleapis.com/auth/userinfo.email"]
LOGIN = "gcloud auth application-default login"
SHOW = "PROJECT_ID=<project> python3 scripts/release-source.py show"
SET = "PROJECT_ID=<project> python3 scripts/release-source.py set --repository <owner>/<repo> --official-key"
UPDATE_CHECK = "PROJECT_ID=<project> python3 scripts/release-source.py update-check on|off"


def _load(name: str, path: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod  # dataclasses resolve their module through sys.modules
    spec.loader.exec_module(mod)
    return mod


def _load_release_source():
    """apps/control-center/release_source.py by exact path. Its `from shared import release_manifest` is served from
    the root shared/release_manifest.py (byte copy of the Control Center's), loaded by path too; shared/ is never put
    on sys.path (its module names could shadow the standard library)."""
    rm = _load("stackvend_release_manifest", os.path.join(REPO_ROOT, "shared", "release_manifest.py"))
    previous = sys.modules.get("shared")
    package = types.ModuleType("shared")
    package.__path__ = []  # a package with exactly one submodule
    package.release_manifest = rm
    sys.modules["shared"], sys.modules["shared.release_manifest"] = package, rm
    try:
        return _load("stackvend_release_source", os.path.join(REPO_ROOT, "apps", "control-center", "release_source.py"))
    finally:
        sys.modules.pop("shared.release_manifest", None)
        if previous is None:
            sys.modules.pop("shared", None)
        else:
            sys.modules["shared"] = previous


rsrc = _load_release_source()
rr = _load("stackvend_release_record", os.path.join(REPO_ROOT, "scripts", "common", "release_record.py"))


class CliError(Exception):
    def __init__(self, code: str, message: str, next_command: str):
        super().__init__(f"{code}: {message}")
        self.code, self.message, self.next_command = code, message, next_command


# ------------------------------------------------------------------------------------------------ seams (tests)
# None = the real implementation.
credentials_provider: Optional[Callable[[], Tuple[str, bool]]] = None  # -> (access token, is a person)
http_request: Optional[Callable[..., Tuple[int, Any]]] = None          # (method, url, body, headers) -> (status, json)
prompt: Callable[[str], str] = input
interactive: Callable[[], bool] = lambda: sys.stdin.isatty()
clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc)


def target_project(arg: Optional[str]) -> str:
    """--project, else PROJECT_ID. Never gcloud configuration, never the ADC file's project."""
    project = (arg or os.environ.get("PROJECT_ID") or "").strip()
    if not project:
        raise CliError("PROJECT_REQUIRED", "name the install's project with --project or PROJECT_ID", SHOW)
    ok = 6 <= len(project) <= 30 and project[0].isascii() and project[0].islower() and project[-1] != "-" \
        and all(c.isascii() and (c.islower() or c.isdigit() or c == "-") for c in project)
    if not ok:
        raise CliError("INVALID_PROJECT", f"{project!r} is not a Google Cloud project ID", SHOW)
    return project


def _credentials() -> Tuple[str, bool]:
    if credentials_provider is not None:
        return credentials_provider()
    try:
        import google.auth
        import google.oauth2.credentials
        from google.auth.transport.requests import Request
    except ImportError:
        raise CliError("AUTH_LIBRARY_MISSING", "google-auth (with requests) is not installed",
                       "python3 -m pip install google-auth requests") from None
    try:
        credentials, _ignored_project = google.auth.default(scopes=SCOPES)  # the project is never taken from here
        credentials.refresh(Request())
    except Exception as e:  # noqa: BLE001 - typed below
        raise CliError("NO_CREDENTIALS", f"Application Default Credentials are not usable ({type(e).__name__})",
                       LOGIN) from None
    return credentials.token, isinstance(credentials, google.oauth2.credentials.Credentials)


def _http(method: str, url: str, body: Optional[bytes], headers: Dict[str, str]) -> Tuple[int, Any]:
    if http_request is not None:
        return http_request(method, url, body, headers)
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            raw, status = resp.read(), resp.status
    except urllib.error.HTTPError as e:
        raw, status = e.read(), e.code
    except (urllib.error.URLError, OSError) as e:
        raise CliError("NETWORK_ERROR", f"{url.split('?')[0]} could not be reached ({type(e).__name__})",
                       "retry when the network is back") from None
    try:
        return status, json.loads(raw.decode("utf-8")) if raw else None
    except ValueError:
        return status, None


def operator_identity(token: str, is_person: bool) -> str:
    """The person the credentials belong to (Google's token information; the token goes in the POST body, never in
    a URL). A service account is refused, as the Control Center refuses a non-human principal."""
    if not is_person:
        raise CliError("HUMAN_CREDENTIALS_REQUIRED", "the Application Default Credentials are not a person's", LOGIN)
    status, body = _http("POST", TOKENINFO, urllib.parse.urlencode({"access_token": token}).encode("ascii"),
                         {"Content-Type": "application/x-www-form-urlencoded"})
    email = body.get("email") if status == 200 and isinstance(body, dict) else None
    verified = isinstance(body, dict) and str(body.get("email_verified")).lower() == "true"
    if not isinstance(email, str) or not email or not verified:
        raise CliError("IDENTITY_UNKNOWN", "the credentials do not carry a verified e-mail address", LOGIN)
    return email


# ------------------------------------------------------------------------------------------------ Firestore REST
def _doc_path(project: str, database: str, *parts: str) -> str:
    return f"projects/{project}/databases/{database}/documents/" + "/".join(parts)


def _auth(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}


def read_current(project: str, database: str, token: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """(stored document or None, its updateTime or None)."""
    status, body = _http("GET", f"{FIRESTORE}/{_doc_path(project, database, rsrc.COLLECTION, rsrc.DOCUMENT)}", None,
                         _auth(token))
    if status == 404:
        return None, None
    if status in (401, 403):
        raise CliError("PERMISSION_DENIED", f"these credentials may not read the guard database {database!r} "
                       f"(HTTP {status})", LOGIN)
    if status != 200 or not isinstance(body, dict) or not isinstance(body.get("updateTime"), str):
        raise CliError("READ_FAILED", f"the release source could not be read (HTTP {status})", SHOW)
    return rr.from_value({"mapValue": {"fields": body.get("fields") or {}}}), body["updateTime"]


def commit_writes(project: str, database: str, plan, update_time: Optional[str], change_id: str) -> Dict[str, Any]:
    """The Control Center's batch, as one Firestore commit: the never-trimmed change record (must not exist) and the
    whole `current` document (no update mask = the stored document becomes exactly the model; precondition: the
    update time that was read, or that it does not exist yet)."""
    current = _doc_path(project, database, rsrc.COLLECTION, rsrc.DOCUMENT)
    return {"writes": [
        {"update": {"name": f"{current}/{rsrc.CHANGES}/{change_id}",
                    "fields": rr.to_value(plan.change)["mapValue"]["fields"]},
         "currentDocument": {"exists": False}},
        {"update": {"name": current, "fields": rr.to_value(plan.stored)["mapValue"]["fields"]},
         "currentDocument": {"updateTime": update_time} if update_time else {"exists": False}},
    ]}


# ------------------------------------------------------------------------------------------------ commands
def _load_state(project: str, database: str, token: str):
    doc, update_time = read_current(project, database, token)
    if doc is None:
        return None, None, None, 0, None
    try:
        current, error = rsrc.read_stored(doc), None
    except rsrc.SourceError as e:
        current, error = None, e
    version = doc.get("version") if type(doc.get("version")) is int else 0
    return current, error, doc, version, update_time


def build_request(args, current) -> Dict[str, Any]:
    signers: List[Dict[str, Any]] = []
    if args.keep_current_keys and current is not None:
        for s in current.signers:
            signers.append({"kind": rsrc.SIGNER_OFFICIAL} if s["kind"] == rsrc.SIGNER_OFFICIAL else
                           {"kind": rsrc.SIGNER_SSH_KEY, "principal": s.get("principal", ""),
                            "public_key": s["public_key"]})
    if args.official_key and {"kind": rsrc.SIGNER_OFFICIAL} not in signers:
        signers.append({"kind": rsrc.SIGNER_OFFICIAL})
    labels = list(args.ssh_key_label or [])
    files = list(args.ssh_key_file or [])
    if labels and len(labels) != len(files):
        raise CliError("INVALID_ARGUMENTS", "give one --ssh-key-label per --ssh-key-file, in the same order", SET)
    for i, path in enumerate(files):
        try:
            with open(path, "r", encoding="utf-8") as f:
                text = f.read().strip()
        except OSError as e:
            raise CliError("KEY_FILE_UNREADABLE", f"{path}: {type(e).__name__}", SET) from None
        signers.append({"kind": rsrc.SIGNER_SSH_KEY, "principal": labels[i] if labels else "", "public_key": text})
    previews = {"on": True, "off": False}.get(args.previews) if args.previews else \
        (current.include_previews if current is not None else rsrc.DEFAULT_INCLUDE_PREVIEWS)
    return {"repository": args.repository, "follow": rsrc.FOLLOW_TAGS, "branch": "", "allow_unsigned": False,
            "include_previews": previews, "signers": signers}


def cmd_show(args, out=print) -> int:
    project = target_project(args.project)
    token, _person = _credentials()
    current, error, _doc, version, _t = _load_state(project, args.guard_database, token)
    if error is not None:
        out(f"Release source invalid ({error.message}); upgrade checks are off. Save a valid one: {SET}")
    else:
        src = current or rsrc.default_source()
        out(src.describe() + (f" (version {version})" if current else " (default; nothing stored)"))
        out(src.describe_update_check())
    # This script never reads GitHub (review §4): the Control Center does the check.
    out("The Control Center checks this repository (Settings ▸ Upgrades) when the update check is on; this command "
        "prints the stored setting only.")
    return 0


def _commit(project: str, database: str, token: str, plan, update_time: Optional[str]) -> None:
    """One Firestore commit of a planned change (`set` and `update-check`), refusals typed."""
    status, body = _http("POST", f"{FIRESTORE}/projects/{project}/databases/{database}/documents:commit",
                         json.dumps(commit_writes(project, database, plan, update_time,
                                                  uuid.uuid4().hex)).encode("utf-8"), _auth(token))
    if status in (401, 403):
        raise CliError("PERMISSION_DENIED", f"these credentials may not write the guard database (HTTP {status})",
                       LOGIN)
    error_status = (body.get("error") or {}).get("status") if isinstance(body, dict) and \
        isinstance(body.get("error"), dict) else None
    if status == 409 or error_status in ("FAILED_PRECONDITION", "ABORTED", "ALREADY_EXISTS"):
        raise CliError("RELEASE_SOURCE_CHANGED", "someone changed the release source meanwhile; nothing was saved",
                       SHOW)
    if status != 200:
        raise CliError("RELEASE_SOURCE_NOT_SAVED", f"Firestore refused the change (HTTP {status}); nothing was saved",
                       SHOW)


def cmd_update_check(args, out=print) -> int:
    project = target_project(args.project)
    if not interactive():
        raise CliError("NOT_INTERACTIVE", "the change needs a typed confirmation; run it in a terminal", UPDATE_CHECK)
    enabled = args.state == "on"
    token, is_person = _credentials()
    email = operator_identity(token, is_person)
    current, error, _doc, version, update_time = _load_state(project, args.guard_database, token)
    if error is not None:
        raise CliError("RELEASE_SOURCE_INVALID", f"the stored release source is invalid ({error.message}); update "
                       "checks are already off. Save a valid release source first", SET)
    effective = current or rsrc.default_source()
    out(f"Project {project}, guard database {args.guard_database}, as {email}.")
    out("Now:   " + effective.describe_update_check())
    if effective.update_check is enabled:
        out(f"Nothing changed: the update check is already {args.state}.")
        return 0
    word = "ON" if enabled else "OFF"
    if prompt(f"Type {word} to turn the update check {args.state}: ").strip() != word:
        raise CliError("CONFIRMATION_REQUIRED", f"type {word} exactly to confirm; nothing was saved", UPDATE_CHECK)
    try:
        plan = rsrc.plan_change(rsrc.update_check_request(effective, enabled), current, None, version,
                                email, clock().isoformat(), "", [], rsrc.VIA_CLI)
    except rsrc.SourceError as e:
        raise CliError(e.code, e.message, SHOW) from None
    if plan is None:
        out(f"Nothing changed: the update check is already {args.state}.")
        return 0
    _commit(project, args.guard_database, token, plan, update_time)
    after, after_error, _d, after_version, _t = _load_state(project, args.guard_database, token)
    if after_error is not None or after is None or after.update_check is not enabled:
        raise CliError("RELEASE_SOURCE_STILL_INVALID", "saved, but it does not read back as requested", SHOW)
    out(json.dumps({"event": "stackvend.release_source_changed", "by": email, "via": rsrc.VIA_CLI,
                    "from_fingerprint": plan.change["from"].get("fingerprint"), "to_fingerprint": plan.new.fingerprint,
                    "to_repository": plan.new.repository, "to_update_check": plan.new.update_check,
                    "version": after_version}, sort_keys=True))
    out(f"Saved: {after.describe_update_check()} (version {after_version}).")
    return 0


def cmd_set(args, out=print) -> int:
    project = target_project(args.project)
    if not interactive():
        raise CliError("NOT_INTERACTIVE", "the change needs a typed confirmation; run it in a terminal", SET)
    token, is_person = _credentials()
    email = operator_identity(token, is_person)
    current, error, _doc, version, update_time = _load_state(project, args.guard_database, token)
    requested = build_request(args, current)
    try:  # validate first, so the confirmation questions name the right repository and keys
        preview = rsrc.validate_source(requested)
    except rsrc.SourceError as e:
        raise CliError(e.code, e.message, SET) from None
    out(f"Project {project}, guard database {args.guard_database}, as {email}.")
    out("Now:   " + (f"invalid ({error.message})" if error else (current or rsrc.default_source()).describe()))
    out("After: " + preview.describe())
    typed_repository = prompt(f"Type the repository name ({preview.repository}) to confirm: ").strip()
    suffixes = [prompt(f"Type the last {rsrc.CONFIRM_SUFFIX_LEN} characters of {fp[:-rsrc.CONFIRM_SUFFIX_LEN]}......: ")
                .strip() for fp in rsrc.new_key_fingerprints(current, preview)]
    try:
        plan = rsrc.plan_change(requested, current, error, version, email,
                                clock().isoformat(), typed_repository, suffixes, rsrc.VIA_CLI)
    except rsrc.SourceError as e:
        raise CliError(e.code, e.message, SET) from None
    if plan is None:
        out("Nothing changed: the release source is already this.")
        return 0
    _commit(project, args.guard_database, token, plan, update_time)
    _c, after_error, _d, after_version, _t = _load_state(project, args.guard_database, token)
    if after_error is not None:
        raise CliError("RELEASE_SOURCE_STILL_INVALID", f"saved, but it reads back invalid ({after_error.message})",
                       SET)
    out(json.dumps({"event": "stackvend.release_source_changed", "by": email, "via": rsrc.VIA_CLI,
                    "from_fingerprint": plan.change["from"].get("fingerprint"), "to_fingerprint": plan.new.fingerprint,
                    "to_repository": plan.new.repository, "version": after_version}, sort_keys=True))
    out(f"Saved: {plan.new.describe()} (version {after_version}).")
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="StackVend release source (terminal path for IAP installs).")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("show", "set", "update-check"):
        s = sub.add_parser(name)
        s.add_argument("--project")
        s.add_argument("--guard-database", default=GUARD_DATABASE)
        if name == "update-check":
            s.add_argument("state", choices=("on", "off"))
        if name == "set":
            s.add_argument("--repository", required=True)
            s.add_argument("--previews", choices=("on", "off"))
            s.add_argument("--official-key", action="store_true")
            s.add_argument("--ssh-key-file", action="append")
            s.add_argument("--ssh-key-label", action="append")
            s.add_argument("--keep-current-keys", action="store_true")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "update-check":
            return cmd_update_check(args)
        return cmd_set(args) if args.command == "set" else cmd_show(args)
    except CliError as e:
        print(f"ERROR [{e.code}] {e.message}", file=sys.stderr)
        print(f"Next: {e.next_command}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
