#!/usr/bin/env python3
"""StackVend live canary: read-only follower (FD-4DN, release gate RC-LIVE-GATE; FD-102 hardening).

Run through scripts/live_canary.sh (python3 -I, standard library only). Two sub-commands:

  spec <example.md>          print the "Workload Form Submission Prompt" text of an example plan
  follow --project ... --product-id ...
                             follow one workload read-only through the pipeline, probe /health, report per stage

Every Google API read uses the operator's own gcloud login: an access token (`gcloud auth print-access-token`), sent
only to the googleapis.com URLs this script builds. Tokens are handed to curl on stdin (`--config -`, which carries
only header lines), never on a command line, and are never printed. Every curl call starts with `-q` (no ~/.curlrc,
no CURL_HOME), never follows a redirect (`--max-redirs 0`, `--proto =https`, `--proto-redir =https`), never globs
(`-g`) and takes its URL as the argument after `--url`. A token with whitespace, quotes, a backslash or a control
character is refused. Nothing here writes, deletes or submits.

FD-102: every value read from the platform records and used (service URL, child project, region, workflow execution
id, trace id) must be a str of printable characters, and the ids and names must also match their exact formats
(`.` and `..` refused; path segments are percent-encoded), else RECORD_VALUE_REFUSED (exit 5) before any parse or
request. The service URL must be exactly `https://<host>` or `https://<host>/` (no userinfo, port, path, query or
fragment; the host a Cloud Run run.app host of lowercase letter/digit/hyphen labels), else SERVICE_URL_REFUSED
(exit 4). It is then Run-API-confirmed before anything is sent to it: the child
project named by the workload record must have the install's managed-workloads folder (`MANAGED_WORKLOADS_FOLDER_ID`
of the host's vending service) among its ancestors, and the complete Cloud Run listing (every page) of the
workload's region must hold a service whose `uri`, or one of whose `urls`, equals the URL (one trailing '/' aside).
After that the API's string is used. No match, or a child outside the folder, is SERVICE_URL_NOT_CONFIRMED (exit
4); a refused read is "ERROR (permission denied)" (exit 5): the canary needs read access to the child project
(vending grants roles/viewer on a child only to the admins that exist when it is vended); a read that gets no
answer, 429 or a 5xx three times, or any other 4xx once, is CLOUD_RUN_API_UNAVAILABLE or ANCESTRY_UNAVAILABLE (exit
5, with the HTTP code). In none of these cases is anything sent to the URL. A workload's answer is capped at 1 MiB
and a Google API answer at 16 MiB (curl --max-filesize; a larger API answer is API_ANSWER_TOO_LARGE, exit 5), and
both are decoded with errors="replace"; the access token (`Authorization`) is only ever sent to this script's
googleapis.com hosts (https, no userinfo, port 443).

The health verdict follows the workload's access mode (`workloads/{pid}.access.mode`). The canary never sends a token
that is valid outside the probed service: never a user's default identity token, and never `Authorization` to a
workload.
  PUBLIC_APP   GET <service_url>/health with no credentials: must answer 200
  PRIVATE_IAM  one anonymous GET first. 2xx: ACCESS_RECORD_MISMATCH (the service is public although the record says
               private), FAIL (exit 4). 401/403/404: the token probe below. Any other answer: FAIL after three tries.
               The token probe needs the confirmed service's invokerIamDisabled not true and no allUsers /
               allAuthenticatedUsers in its IAM policy (else ACCESS_RECORD_MISMATCH; an unreadable policy is a
               permission error, exit 5), then `gcloud auth print-identity-token --audiences=<confirmed URL>` (gcloud
               grants an audience only to a service-account login, or an impersonated one) whose decoded `aud` claim
               equals the confirmed URL exactly. That token goes only in X-Serverless-Authorization. A user login
               (gcloud refused --audiences) or a token bound to another audience sends nothing:
               HEALTH_NOT_PROBED_PRIVATE_IAM (exit 6), never a pass or a failure.
  PRIVATE_IAP  /health is NOT probed: a gcloud user identity token cannot pass Direct IAP (IAP refuses it with
               "Invalid JWT audience"), and the canary mints no other token. It checks only that IAP is in front (an
               anonymous GET of /health is redirected, 302, to Google sign-in) and reports the typed state
               HEALTH_NOT_PROBED_PRIVATE_IAP with RESULT "DEPLOYED, HEALTH_NOT_PROBED_PRIVATE_IAP" (exit 6), never a
               pass. --iap-browser-check prints the URL to open in a browser signed in as an allowed principal.
               A redirect proves IAP only when the confirmed Cloud Run service's `iapEnabled` is true (the app can
               send the same redirect itself); otherwise ACCESS_RECORD_MISMATCH (exit 4), also with --child-checks.
  no record    anonymous GETs only, never a token: 2xx PASS; a redirect to Google sign-in from a service with
               `iapEnabled` true is treated as PRIVATE_IAP (from any other service: ACCESS_RECORD_MISMATCH, exit 4);
               401/403/404 is HEALTH_NOT_PROBED_NO_ACCESS_RECORD (exit 6); any other answer FAIL after three tries.
--child-checks (opt-in, default off; needs roles/run.viewer + roles/logging.viewer in the child project) restores the
platform-signal check for PRIVATE_IAP: the confirmed Cloud Run service has a Ready latest revision, its startup probe
is an HTTP probe on /health, Cloud Logging holds a "STARTUP HTTP probe succeeded ... path "/health"" line for that
revision, and the anonymous GET is redirected to Google sign-in: PASS (exit 0). A missing permission is "ERROR
(permission denied)" (exit 5), never a pass. With no access record it also reads the service's iapEnabled.
The `access` line also names the workload's region (`workloads/{pid}.region`; a legacy record without one follows
--region).

Printing: everything goes through one writer that drops non-printable characters except newline, and every field
taken from a record or a response is also put on one line, so no answer can forge a line such as `RESULT: PASS`. A
workload's response body is echoed ASCII-only and quoted (ascii()); a record stage named like one of the canary's
own rows (health, qa_job, ...) is shown as `stage:<name>`.

Sources (all read-only):
  Firestore  workloads/{product_id}                  record status, child project, region, service_url, access
             pipeline_executions (product_id == id)  the run: status, current_stage, stages{}, outputs, typed error
             qa_test_runs/{trace_id}                  QA verdict + diagnostics
  Workflows  castor-main-orchestrator execution       state, typed error payload, result
  Cloud Run  jobs qa-sandbox-test-runner, tf-applier  the execution whose env names this run's trace id
  Cloud Run  host service project-repo-vending-service  its MANAGED_WORKLOADS_FOLDER_ID (only that env is read)
  Resource Manager  child project getAncestry         the child project is inside the managed-workloads folder
  Cloud Build child project builds                    container builds started after the run
  Cloud Run  child project services (every page)      the service URL is confirmed; PRIVATE_IAM: the IAM policy
  Cloud Run  child project revision                   (--child-checks, IAP) ready revision, startup probe
  Logging    child project run.googleapis.com/varlog/system   (--child-checks, IAP) the startup probe result
  HTTPS      <confirmed service_url>/health          final check (per access mode, above)

Exit codes: 0 pass; 1 the pipeline failed; 2 usage; 3 timed out; 4 deployed but /health failed, the service URL was
refused or not confirmed, or ACCESS_RECORD_MISMATCH; 5 prerequisite missing (gcloud login, permission to read the
records, the managed folder or the child project), RECORD_VALUE_REFUSED, CLOUD_RUN_API_UNAVAILABLE,
ANCESTRY_UNAVAILABLE or API_ANSWER_TOO_LARGE; 6 deployed, health not probed
(PRIVATE_IAP with IAP shown in front, PRIVATE_IAM with a user login, or no access record and a private answer).
"""
import argparse
import base64
import datetime
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse

EXIT_PASS, EXIT_FAILED, EXIT_USAGE, EXIT_TIMEOUT, EXIT_PROBE, EXIT_PREREQ, EXIT_NOT_PROBED = (
    0, 1, 2, 3, 4, 5, 6)

FIRESTORE = "https://firestore.googleapis.com/v1"
WORKFLOWS = "https://workflowexecutions.googleapis.com/v1"
RUN_API = "https://run.googleapis.com/v2"
CLOUDBUILD = "https://cloudbuild.googleapis.com/v1"
LOGGING = "https://logging.googleapis.com/v2"
CRM_V1 = "https://cloudresourcemanager.googleapis.com/v1"

# workloads/{pid}.access.mode: the exact AccessMode enum of the Control Center (shared/access_policy.py)
PUBLIC_APP, PRIVATE_IAM, PRIVATE_IAP = "PUBLIC_APP", "PRIVATE_IAM", "PRIVATE_IAP"
ACCESS_MODES = (PUBLIC_APP, PRIVATE_IAM, PRIVATE_IAP)
HEALTH_PATH = "/health"
GOOGLE_SIGN_IN_HOST = "accounts.google.com"   # where IAP redirects a request that carries no Google sign-in
# Cloud Run writes one system log line per instance start, for example
#   STARTUP HTTP probe succeeded after 1 attempt for container "app-1" on port 8080 path "/health".
#   STARTUP HTTP probe failed 20 times consecutively for container "app-1" on port 8080 path "/health". ...
STARTUP_PROBE_LOG = "run.googleapis.com%2Fvarlog%2Fsystem"
STARTUP_PROBE_TEXT = "STARTUP HTTP probe"
STARTUP_PROBE_OK = "STARTUP HTTP probe succeeded"
STARTUP_PROBE_FAILED = "STARTUP HTTP probe failed"
STARTUP_PROBE_PATH = f'path "{HEALTH_PATH}"'

# The health states (summary `health` row). Only HEALTH_PASS is a pass; the others never are.
HEALTH_PASS = "PASS"
HEALTH_FAIL = "FAIL"
HEALTH_NOT_PROBED_PRIVATE_IAP = "HEALTH_NOT_PROBED_PRIVATE_IAP"
HEALTH_NOT_PROBED_PRIVATE_IAM = "HEALTH_NOT_PROBED_PRIVATE_IAM"
HEALTH_NOT_PROBED_NO_ACCESS_RECORD = "HEALTH_NOT_PROBED_NO_ACCESS_RECORD"
ACCESS_RECORD_MISMATCH = "ACCESS_RECORD_MISMATCH"
HEALTH_ERROR_PERMISSION = "ERROR (permission denied)"   # a read the check needs was refused
NOT_PROBED_IAP_REASON = ("a gcloud user identity token cannot pass Direct IAP (IAP refuses it: Invalid JWT audience); "
                         "open the URL in a browser signed in as an allowed principal")
NOT_PROBED_IAM_REASON = ("only an identity token bound to the service URL is ever sent, and gcloud mints one only for "
                         "a service-account login; a user login's default token is valid on every service the user "
                         "may invoke, so it is never sent")
NOT_PROBED_NO_RECORD_REASON = ("the workload has no access record and its service refused an anonymous request; "
                               "without an access record no token is sent")

# FD-102 typed refusals: after any of them nothing is sent to the service URL and no identity token is minted
RECORD_VALUE_REFUSED = "RECORD_VALUE_REFUSED"
SERVICE_URL_REFUSED = "SERVICE_URL_REFUSED"
SERVICE_URL_NOT_CONFIRMED = "SERVICE_URL_NOT_CONFIRMED"
MANAGED_FOLDER_UNKNOWN = "MANAGED_FOLDER_UNKNOWN"
API_ANSWER_TOO_LARGE = "API_ANSWER_TOO_LARGE"     # a Google API answer larger than GOOGLE_API_MAX_BYTES
CLOUD_RUN_API_UNAVAILABLE = "CLOUD_RUN_API_UNAVAILABLE"   # the child listing failed (not 401/403) after the retries
ANCESTRY_UNAVAILABLE = "ANCESTRY_UNAVAILABLE"             # the child ancestry read failed (not 401/403) after retries
READ_ATTEMPTS = 3                                          # like probe(): a transient read failure is retried
PERMISSION_DENIED = "PERMISSION_DENIED"
CHILD_READ_DENIED = "permission denied (the canary needs read access to the child project)"

# The exact formats of the values used in a request (re.fullmatch: `$` would also accept a trailing newline).
PROJECT_RE = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]")     # live_canary.sh PROJECT_RE (also a child project id)
REGION_RE = re.compile(r"[a-z]+-[a-z]+[0-9]+")                # live_canary.sh REGION_RE
PRODUCT_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")           # live_canary.sh --watch-only (slug form)
ID_RE = re.compile(r"[A-Za-z0-9._-]{1,128}")                  # trace / execution ids (live_canary.sh --trace-id)
FOLDER_RE = re.compile(r"[0-9]{1,32}")
_RUN_SEGMENT = r"[a-z0-9][a-z0-9-]{0,62}"
SERVICE_NAME_RE = re.compile(rf"projects/{_RUN_SEGMENT}/locations/{_RUN_SEGMENT}/services/{_RUN_SEGMENT}")
# FD-102 R4: the only service URL host form accepted (Cloud Run's own `uri` / `urls`): lowercase LDH labels under
# run.app, e.g. <name>-<hash>-<region code>.a.run.app or <name>-<project number>.<region>.run.app
_LDH_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
RUN_APP_HOST_RE = re.compile(rf"(?:{_LDH_LABEL}\.)+run\.app")
REVISION_NAME_RE = re.compile(rf"projects/{_RUN_SEGMENT}/locations/{_RUN_SEGMENT}/services/{_RUN_SEGMENT}"
                              rf"/revisions/{_RUN_SEGMENT}")
LIST_MAX_PAGES = 20
VENDING_SERVICE = "project-repo-vending-service"   # its MANAGED_WORKLOADS_FOLDER_ID is the install's managed folder
MANAGED_FOLDER_ENV = "MANAGED_WORKLOADS_FOLDER_ID"
PUBLIC_MEMBERS = ("allUsers", "allAuthenticatedUsers")
AUTH_HEADER = "Authorization"                          # Google API reads only (the access token)
# FD-102 R5: the only hosts an `Authorization` header (the operator's access token) is ever sent to
GOOGLE_API_HOSTS = frozenset(urllib.parse.urlsplit(base).hostname
                             for base in (FIRESTORE, WORKFLOWS, RUN_API, CLOUDBUILD, LOGGING, CRM_V1))
MAX_BODY_BYTES = 1024 * 1024   # FD-102 A3: a workload's answer: curl --max-filesize, and the body is cut to it
GOOGLE_API_MAX_BYTES = 16 * 1024 * 1024   # a Google API answer: curl --max-filesize; larger is API_ANSWER_TOO_LARGE
CURL_FILESIZE_EXCEEDED = 63               # curl's exit code when --max-filesize stops a transfer
WORKLOAD_TOKEN_HEADER = "X-Serverless-Authorization"   # the only header a request to a workload carries a token in

WORKFLOW_NAMES = ("castor-main-orchestrator", "main-orchestrator")
QA_JOB = "qa-sandbox-test-runner"
APPLIER_JOB = "tf-applier"
# The only env names read from a job execution. Every other value (signed URLs, callback URLs, HCL) is never read
# into output.
QA_TRACE_ENV = "QA_TRACE_ID"
APPLIER_TRACE_ENV = "TRACE_ID"

STAGE_ORDER = ("discovery", "architect", "compliance", "finops", "plan_approval", "quota_gate", "vending",
               "developer", "gatekeeper", "qa", "release", "terraform", "terraform_remediation", "sre")
OPERATOR_WAITS = {
    "AWAITING_PLAN_APPROVAL": "plan approval: approve it in the Control Center (Approvals)",
    "AWAITING_PR_APPROVAL": "release pull request review: approve it in the Control Center (Approvals)",
    "QUOTA_PAUSED": "quota approval: approve it in the Control Center (Approvals)",
}
DETAIL_LIMIT = 2048
# FD-102 A5a: summary rows and line labels the canary itself writes; a record's stage of the same name is shown as
# `stage:<name>` so a record can never fill (or spoof) one of them
CANARY_ROWS = frozenset({"health", "qa_job", "qa_result", "tf_applier", "cloud_build", "submit", "access", "confirmed",
                         "refused", "service_url", "record", "run", "pipeline", "workflow", "WAITING", "timeout",
                         "iap_browser"})
TOKEN_TTL_S = 30 * 60


class Refused(Exception):
    """FD-102: a typed stop (error class, message, exit code) before anything is sent to the service URL."""

    def __init__(self, error_class, message, exit_code):
        super().__init__(f"{error_class}: {message}")
        self.error_class, self.message, self.exit_code = error_class, message, exit_code


# ---------------------------------------------------------------------------------------------------- printing
def clean(text):
    """The one writer's filter: every character that is not printable is dropped, except newline."""
    return "".join(ch for ch in str(text) if ch == "\n" or ch.isprintable())


def flat(text):
    """A field read from a record or a response: printable characters on one line (newline -> space)."""
    return clean(text).replace("\n", " ")


def say(text="", file=None):
    """The one writer: every line of output (reports, errors, argparse messages) goes through it."""
    out = file if file is not None else sys.stdout
    out.write(clean(text) + "\n")
    out.flush()


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def stamp():
    return now_utc().strftime("%Y-%m-%dT%H:%M:%SZ")


def one_line(text, limit=160):
    s = " ".join(clean(text or "").split())
    return s if len(s) <= limit else s[: limit - 3] + "..."


def body_echo(body, limit=200):
    """FD-102 A4: a workload's response body as printed: its first `limit` characters, ASCII only and quoted
    (Python ascii(): every non-ASCII character, blanks such as U+2800 / U+3164 / U+115F included, is escaped), so
    a body cannot draw anything that looks like a line of the report."""
    return ascii(str(body or "")[:limit])


def stage_row(name):
    """FD-102 A5a: the summary row / line label of a record's stage name (one line, 40 characters at most)."""
    row = one_line(name, 40)
    return f"stage:{row}" if row in CANARY_ROWS else row


def parse_time(value):
    if not value or not isinstance(value, str):
        return None
    v = value.strip().replace("Z", "+00:00")
    # Firestore / RFC 3339 can carry nanoseconds; fromisoformat takes at most microseconds.
    if "." in v:
        head, rest = v.split(".", 1)
        frac, tz = rest, ""
        for sep in ("+", "-"):
            if sep in rest:
                frac, tz = rest.split(sep, 1)
                tz = sep + tz
                break
        v = f"{head}.{frac[:6]}{tz}"
    try:
        t = datetime.datetime.fromisoformat(v)
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=datetime.timezone.utc)


# ---------------------------------------------------------------------------------------------------- record values
def record_value(name, value, pattern=None):
    """FD-102: a record value used in a request or a check: a str of printable characters, matching `pattern` exactly
    when given (re.fullmatch), never `.` or `..`. Else Refused(RECORD_VALUE_REFUSED), exit 5. The value itself is
    never printed."""
    if not isinstance(value, str) or not value or not value.isprintable():
        raise Refused(RECORD_VALUE_REFUSED, f"{name} is not a string of printable characters "
                                            f"({type(value).__name__})", EXIT_PREREQ)
    if value in (".", "..") or (pattern is not None and not pattern.fullmatch(value)):
        raise Refused(RECORD_VALUE_REFUSED, f"{name} does not have the expected format", EXIT_PREREQ)
    return value


def seg(value):
    """One URL path segment (percent-encoded; '/' included)."""
    return urllib.parse.quote(value, safe="")


def without_one_trailing_slash(url):
    return url[:-1] if url.endswith("/") else url


def checked_service_url(value):
    """FD-102: the service URL exactly as given, when it is a printable str that is `https://<host>` or
    `https://<host>/`: no userinfo, no port, no other path, no query, no fragment (the URL must equal the one rebuilt
    from its parsed scheme and host, so anything urlsplit drops or normalizes is refused), and the host is a Cloud
    Run run.app host (RUN_APP_HOST_RE, fullmatch).
    RECORD_VALUE_REFUSED (exit 5) for a value that is not a printable str; SERVICE_URL_REFUSED (exit 4) otherwise."""
    record_value("service_url", value)
    try:
        parts = urllib.parse.urlsplit(value)
        host = parts.hostname
    except ValueError:
        raise Refused(SERVICE_URL_REFUSED, "the service URL cannot be parsed", EXIT_PROBE) from None
    if parts.scheme != "https" or not host:
        raise Refused(SERVICE_URL_REFUSED, "the service URL is not an https URL with a host", EXIT_PROBE)
    if parts.netloc != host and parts.netloc.lower() == host:   # urlsplit lowercases `hostname`
        raise Refused(SERVICE_URL_REFUSED, "the service URL host has uppercase letters (a Cloud Run host is "
                                           "lowercase)", EXIT_PROBE)
    if value not in (f"https://{host}", f"https://{host}/"):
        raise Refused(SERVICE_URL_REFUSED, "the service URL has userinfo, a port, a path, a query or a fragment",
                      EXIT_PROBE)
    if not RUN_APP_HOST_RE.fullmatch(host):
        raise Refused(SERVICE_URL_REFUSED, "the service URL host is not a Cloud Run run.app host (lowercase "
                                           "letters, digits and '-' labels)", EXIT_PROBE)
    return value


def matching_service(url, services):
    """(service, the API's URL string) of the first service whose `uri` or one of whose `urls` equals `url` (one
    trailing '/' aside on both), else (None, None). Only printable str entries count."""
    wanted = without_one_trailing_slash(url)
    for svc in services:
        if not isinstance(svc, dict):
            continue
        urls = svc.get("urls")
        for candidate in [svc.get("uri")] + (list(urls) if isinstance(urls, list) else []):
            if (isinstance(candidate, str) and candidate and candidate.isprintable()
                    and without_one_trailing_slash(candidate) == wanted):
                return svc, candidate
    return None, None


def folder_id(value):
    """`folders/<n>` or `<n>` -> `<n>` (positional split), else None."""
    if not isinstance(value, str):
        return None
    parts = value.strip().split("/")
    if len(parts) == 2 and parts[0] == "folders":
        parts = parts[1:]
    return parts[0] if len(parts) == 1 and FOLDER_RE.fullmatch(parts[0]) else None


def public_members_in(policy):
    """The allUsers / allAuthenticatedUsers members of an IAM policy, in any role (any role that names them on a
    private service is already an access-record mismatch)."""
    found = []
    for b in (policy or {}).get("bindings") or []:
        if not isinstance(b, dict):
            continue
        for m in b.get("members") or []:
            if m in PUBLIC_MEMBERS:
                found.append(f"{m} ({b.get('role')})")
    return found


def submission_prompt(path):
    """The blockquote under the example's "Workload Form Submission Prompt" heading (the text a user pastes)."""
    with open(path, "r", encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.lstrip().startswith("#") and "Submission Prompt" in line:
            start = i + 1
            break
    if start is None:
        return None
    out, seen = [], False
    for line in lines[start:]:
        stripped = line.strip()
        if stripped.startswith(">"):
            seen = True
            out.append(stripped[1:].lstrip())
        elif seen and stripped:
            break
        elif seen:
            out.append("")
    text = "\n".join(out).strip()
    return text or None


# ---------------------------------------------------------------------------------------------------- HTTP / auth
def usable_token(tok):
    """A token that can travel in a curl config header line: printable, no whitespace, quote or backslash."""
    return (isinstance(tok, str) and bool(tok) and tok.isprintable()
            and not any(ch.isspace() or ch in "\"'\\" for ch in tok))


def jwt_audience(token):
    """The `aud` claim (a str) of a JWT's payload, decoded without verification (the token is gcloud's own, minted
    for this run); None when it is not a three-part JWT with a str `aud`."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8"))
    except (ValueError, UnicodeError, AttributeError):
        return None
    aud = claims.get("aud") if isinstance(claims, dict) else None
    return aud if isinstance(aud, str) else None


class Auth:
    def __init__(self):
        self._token, self._at = None, 0.0

    @staticmethod
    def _gcloud(args):
        try:
            r = subprocess.run(["gcloud"] + args, capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            return None
        tok = (r.stdout or "").strip()
        return tok if r.returncode == 0 and usable_token(tok) else None

    def access_token(self, force=False):
        if force or not self._token or time.time() - self._at > TOKEN_TTL_S:
            tok = self._gcloud(["auth", "print-access-token"])
            if tok:
                self._token, self._at = tok, time.time()
        return self._token

    def audience_token(self, audience):
        """(token, None) for an identity token whose `aud` is exactly `audience` (the confirmed service URL), else
        (None, why). `print-identity-token` is never run without `--audiences`: gcloud grants an audience only to a
        service-account login (or an impersonated account), so a user login gets nothing and its default token,
        valid on every service the user may invoke, is never minted or sent."""
        tok = self._gcloud(["auth", "print-identity-token", f"--audiences={audience}"])
        if not tok:
            return None, ("gcloud refused --audiences (a user login: gcloud binds an identity token to an audience "
                          "only for a service account); no token was minted")
        if jwt_audience(tok) != audience:
            return None, "the minted identity token is not bound to the confirmed service URL; it was not sent"
        return tok, None


def _cfg_quote(value):
    return '"' + str(value).replace("\\", "\\\\").replace('"', '\\"') + '"'


def redirect_host(redirect):
    """The host of a redirect Location, or None (no Location, or one urllib.parse cannot split, e.g. "https://[x")."""
    if not redirect:
        return None
    try:
        return urllib.parse.urlsplit(redirect).hostname
    except ValueError:
        return None


def answer_cap(url):
    """The largest answer read from `url`: GOOGLE_API_MAX_BYTES for this script's Google API hosts, else (a
    workload) MAX_BODY_BYTES."""
    return GOOGLE_API_MAX_BYTES if google_api_host(url) else MAX_BODY_BYTES


def curl_argv(url, timeout, body_path=None):
    """The curl command line. `-q` first (no ~/.curlrc / CURL_HOME), https only, no redirect followed, no globbing,
    the answer capped (answer_cap), the URL as the argument after `--url`; headers (tokens) arrive on stdin only."""
    args = ["curl", "-q", "-sS", "--proto", "=https", "--proto-redir", "=https", "--max-redirs", "0", "-g",
            "--max-filesize", str(answer_cap(url)), "--max-time", str(timeout), "-w", "\n%{redirect_url}\n%{http_code}", "--config", "-"]
    if body_path is not None:
        args += ["-H", "Content-Type: application/json", "--data-binary", "@" + body_path]
    return args + ["--url", url]


def http(url, token=None, body=None, timeout=30, token_header=AUTH_HEADER):
    """(status, text). status 0 = no HTTP answer (network / curl error). The token goes to curl on stdin only."""
    status, text, _redirect = http_full(url, token, body, timeout, token_header)
    return status, text


def google_api_host(url):
    """FD-102 R5: True only for an https URL whose host is one of this script's googleapis.com bases, with no
    userinfo and no port other than 443."""
    try:
        parts = urllib.parse.urlsplit(url)
        return (parts.scheme == "https" and parts.hostname in GOOGLE_API_HOSTS and parts.username is None
                and parts.password is None and parts.port in (None, 443))
    except (ValueError, TypeError, AttributeError):
        return False


def decode_answer(raw, cap=MAX_BODY_BYTES):
    """FD-102 A2/A3: curl's stdout bytes -> (status, text, redirect). The body part is cut to `cap` bytes and
    decoded with errors="replace", so an invalid or oversized answer never stops the run."""
    rest, _, code = raw.rpartition(b"\n")
    body, _, redirect = rest.rpartition(b"\n")
    try:
        status = int(code.strip())
    except ValueError:
        return 0, "", ""
    text = body[:cap].decode("utf-8", errors="replace")
    return status, text, redirect.decode("utf-8", errors="replace").strip()


def http_full(url, token=None, body=None, timeout=30, token_header=AUTH_HEADER):
    """(status, text, redirect_url). Redirects are never followed; redirect_url is curl's %{redirect_url}: the
    Location a 3xx answer names, "" otherwise. A token that could not travel safely is never sent (no request), and
    the access token (`Authorization`) goes only to this script's googleapis.com hosts (R5). A Google API answer
    larger than GOOGLE_API_MAX_BYTES (curl exit 63) raises Refused(API_ANSWER_TOO_LARGE), never an empty parse; a
    workload's answer is cut to MAX_BODY_BYTES (its status still counts)."""
    cfg = []
    if token is not None:
        if not usable_token(token) or token_header not in (AUTH_HEADER, WORKLOAD_TOKEN_HEADER):
            return 0, "", ""
        if token_header == AUTH_HEADER and not google_api_host(url):
            return 0, "", ""
        cfg.append(f"header = {_cfg_quote(token_header + ': Bearer ' + token)}")
    tmp = None
    if body is not None:
        fd, tmp = tempfile.mkstemp(prefix="live-canary-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(body, fh)
    try:
        r = subprocess.run(curl_argv(url, timeout, tmp), input="".join(c + "\n" for c in cfg).encode("utf-8"),
                           capture_output=True, timeout=timeout + 15)
    except (OSError, subprocess.TimeoutExpired):
        return 0, "", ""
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    cap = answer_cap(url)
    if r.returncode == CURL_FILESIZE_EXCEEDED and google_api_host(url):
        raise Refused(API_ANSWER_TOO_LARGE, f"{urllib.parse.urlsplit(url).hostname} answered more than {cap} bytes; "
                                            "the answer was not used", EXIT_PREREQ)
    return decode_answer(r.stdout or b"", cap)


def retryable(status):
    """A read failure worth another try: no answer (0), 429, or a 5xx. Any other 4xx is reported at once."""
    return status == 0 or status == 429 or 500 <= status <= 599


def http_json(url, auth, body=None):
    status, text = http(url, auth.access_token(), body)
    if status == 401:
        status, text = http(url, auth.access_token(force=True), body)
    try:
        data = json.loads(text) if text.strip() else None
    except ValueError:
        data = None
    return status, data


# ---------------------------------------------------------------------------------------------------- Firestore
def fs_value(v):
    if not isinstance(v, dict):
        return v
    if "mapValue" in v:
        return {k: fs_value(x) for k, x in (v["mapValue"].get("fields") or {}).items()}
    if "arrayValue" in v:
        return [fs_value(x) for x in (v["arrayValue"].get("values") or [])]
    if "integerValue" in v:
        try:
            return int(v["integerValue"])
        except (TypeError, ValueError):
            return v["integerValue"]
    if "nullValue" in v:
        return None
    for key in ("stringValue", "booleanValue", "doubleValue", "timestampValue", "referenceValue", "bytesValue",
                "geoPointValue"):
        if key in v:
            return v[key]
    return None


def fs_doc(raw):
    return {k: fs_value(v) for k, v in ((raw or {}).get("fields") or {}).items()}


class Reader:
    def __init__(self, project, region, auth, database="(default)"):
        self.project, self.region, self.auth = project, region, auth
        self.docs = f"{FIRESTORE}/projects/{seg(project)}/databases/{seg(database)}/documents"
        self.denied = 0
        self.workflow_name = None

    def _note(self, status):
        if status in (401, 403):
            self.denied += 1
        elif status == 200:
            self.denied = 0

    def get_doc(self, collection, doc_id):
        status, data = http_json(f"{self.docs}/{seg(collection)}/{seg(doc_id)}", self.auth)
        self._note(status)
        if status == 200 and isinstance(data, dict):
            return fs_doc(data)
        return None

    def runs(self, product_id):
        body = {"structuredQuery": {
            "from": [{"collectionId": "pipeline_executions"}],
            "where": {"fieldFilter": {"field": {"fieldPath": "product_id"}, "op": "EQUAL",
                                      "value": {"stringValue": product_id}}},
            "limit": 100}}
        status, data = http_json(f"{self.docs}:runQuery", self.auth, body)
        self._note(status)
        out = []
        if status == 200 and isinstance(data, list):
            for row in data:
                raw = (row or {}).get("document")
                if raw:
                    doc = fs_doc(raw)
                    doc.setdefault("trace_id", raw.get("name", "").rsplit("/", 1)[-1])
                    out.append(doc)
        return out

    def workflow_execution(self, execution_id):
        names = [self.workflow_name] if self.workflow_name else list(WORKFLOW_NAMES)
        for name in names:
            url = (f"{WORKFLOWS}/projects/{seg(self.project)}/locations/{seg(self.region)}/workflows/{seg(name)}"
                   f"/executions/{seg(execution_id)}")
            status, data = http_json(url, self.auth)
            if status == 200 and isinstance(data, dict):
                self.workflow_name = name
                return data
        return None

    def job_execution_for(self, job, env_name, trace_id):
        """The newest execution of `job` whose container env `env_name` equals trace_id (only that env is read)."""
        url = (f"{RUN_API}/projects/{seg(self.project)}/locations/{seg(self.region)}/jobs/{seg(job)}"
               f"/executions?pageSize=25")
        status, data = http_json(url, self.auth)
        if status != 200 or not isinstance(data, dict):
            return None
        best = None
        for ex in data.get("executions") or []:
            match = False
            for c in ((ex.get("template") or {}).get("containers") or []):
                for e in c.get("env") or []:
                    if e.get("name") == env_name and e.get("value") == trace_id:
                        match = True
            if match and (best is None or (ex.get("createTime") or "") > (best.get("createTime") or "")):
                best = ex
        return best

    def builds(self, child_project):
        url = f"{CLOUDBUILD}/projects/{seg(child_project)}/builds?pageSize=10"
        status, data = http_json(url, self.auth)
        if status != 200 or not isinstance(data, dict):
            return []
        return data.get("builds") or []

    def managed_folder(self):
        """FD-102: the install's managed-workloads folder id: the `MANAGED_WORKLOADS_FOLDER_ID` env of the host's
        vending service (only that env is read). Refused (exit 5) when it cannot be read or is not a folder id."""
        url = f"{RUN_API}/projects/{seg(self.project)}/locations/{seg(self.region)}/services/{seg(VENDING_SERVICE)}"
        status, data = http_json(url, self.auth)
        if status in (401, 403):
            raise Refused(PERMISSION_DENIED, f"permission denied reading Cloud Run service {VENDING_SERVICE} in "
                                             f"{self.project} (the canary reads its {MANAGED_FOLDER_ENV})", EXIT_PREREQ)
        if status != 200 or not isinstance(data, dict):
            raise Refused(MANAGED_FOLDER_UNKNOWN, f"Cloud Run service {VENDING_SERVICE} in {self.project} "
                                                  f"({self.region}) could not be read (HTTP {status or 'no answer'})",
                          EXIT_PREREQ)
        values = [e.get("value") for c in ((data.get("template") or {}).get("containers") or [])
                  if isinstance(c, dict) for e in (c.get("env") or [])
                  if isinstance(e, dict) and e.get("name") == MANAGED_FOLDER_ENV]
        folder = folder_id(values[0]) if len(values) == 1 else None
        if folder is None:
            raise Refused(MANAGED_FOLDER_UNKNOWN, f"{VENDING_SERVICE} has no single folder id in "
                                                  f"{MANAGED_FOLDER_ENV}", EXIT_PREREQ)
        return folder

    def child_in_folder(self, child_project, folder, attempts=READ_ATTEMPTS, spacing=10):
        """FD-102 (plan §8 Q16): the child project's ancestry (Resource Manager v1 getAncestry, a read by POST)
        starts at the project and holds the managed folder. Refused otherwise; nothing is listed or probed. A read
        that gets no answer, 429 or a 5xx is retried (`attempts`); any failure left (or another 4xx, at once) is
        ANCESTRY_UNAVAILABLE (exit 5) with its HTTP code."""
        status, ancestors = 0, None
        for i in range(attempts):
            status, data = http_json(f"{CRM_V1}/projects/{seg(child_project)}:getAncestry", self.auth, {})
            if status in (401, 403):
                raise Refused(PERMISSION_DENIED, CHILD_READ_DENIED, EXIT_PREREQ)
            ancestors = (data or {}).get("ancestor") if status == 200 and isinstance(data, dict) else None
            if isinstance(ancestors, list) or not retryable(status):
                break
            if i + 1 < attempts:
                time.sleep(spacing)
        if not isinstance(ancestors, list):
            raise Refused(ANCESTRY_UNAVAILABLE, f"the ancestry of {child_project} could not be read "
                                                f"(HTTP {status or 'no answer'})", EXIT_PREREQ)
        ids = [((a or {}).get("resourceId") or {}) if isinstance(a, dict) else {} for a in ancestors]
        first = ids[0] if ids else {}
        if (first.get("type") != "project" or first.get("id") != child_project
                or not any(r.get("type") == "folder" and str(r.get("id")) == folder for r in ids[1:])):
            raise Refused(SERVICE_URL_NOT_CONFIRMED, f"{child_project} is not inside the install's managed-workloads "
                                                     f"folder", EXIT_PROBE)

    def list_services(self, child_project, region, attempts=READ_ATTEMPTS, spacing=10):
        """(status, services): the complete Cloud Run v2 service listing of one child-project region (every page),
        or (status, None) when it could not be read completely. Only no answer, 429 or a 5xx is retried (`attempts`)."""
        status, services = 0, None
        for i in range(attempts):
            status, services = self._list_services_once(child_project, region)
            if services is not None or not retryable(status):
                break
            if i + 1 < attempts:
                time.sleep(spacing)
        return status, services

    def _list_services_once(self, child_project, region):
        """(status, services), or (status, None) when a page could not be read or the listing is longer than
        LIST_MAX_PAGES pages."""
        base = f"{RUN_API}/projects/{seg(child_project)}/locations/{seg(region)}/services?pageSize=100"
        services, token, status = [], "", 0
        for _ in range(LIST_MAX_PAGES):
            status, data = http_json(base + (f"&pageToken={seg(token)}" if token else ""), self.auth)
            if status != 200 or not isinstance(data, dict):
                return status, None
            services.extend(s for s in (data.get("services") or []) if isinstance(s, dict))
            token = data.get("nextPageToken")
            if not isinstance(token, str) or not token:
                return status, services
        return status, None

    def iam_policy(self, service_name):
        status, data = http_json(f"{RUN_API}/{service_name}:getIamPolicy", self.auth)
        return status, (data if status == 200 and isinstance(data, dict) else None)

    def run_resource(self, name):
        """(status, resource) for a full Cloud Run v2 resource name (projects/.../services/.../revisions/...)."""
        status, data = http_json(f"{RUN_API}/{name}", self.auth)
        return status, (data if status == 200 and isinstance(data, dict) else None)

    def startup_probe_entries(self, child_project, service_name, revision_name, since=None):
        """(status, entries): the revision's HTTP startup probe lines in Cloud Run's system log, newest first.
        Logging's entries:list is a read; it is a POST only because the filter travels in the body."""
        parts = ['resource.type="cloud_run_revision"',
                 f'resource.labels.service_name="{service_name}"',
                 f'resource.labels.revision_name="{revision_name}"',
                 f'logName="projects/{child_project}/logs/{STARTUP_PROBE_LOG}"',
                 f'textPayload:"{STARTUP_PROBE_TEXT}"']
        if since and isinstance(since, str) and since.isprintable() and '"' not in since and "\\" not in since:
            parts.append(f'timestamp>="{since}"')
        body = {"resourceNames": [f"projects/{child_project}"], "filter": " AND ".join(parts),
                "orderBy": "timestamp desc", "pageSize": 50}
        status, data = http_json(f"{LOGGING}/entries:list", self.auth, body)
        if status != 200 or not isinstance(data, dict):
            return status, []
        return status, data.get("entries") or []


def execution_state(ex):
    """RUNNING / SUCCEEDED / FAILED / CANCELLED / PENDING of a Cloud Run job execution (v2 resource)."""
    if not ex:
        return None
    if ex.get("cancelledCount"):
        return "CANCELLED"
    if ex.get("completionTime"):
        return "SUCCEEDED" if (ex.get("succeededCount") or 0) >= 1 and not ex.get("failedCount") else "FAILED"
    if ex.get("runningCount"):
        return "RUNNING"
    return "PENDING"


def short(name):
    return str(name or "").rsplit("/", 1)[-1]


# ---------------------------------------------------------------------------------------------------- follower
class Follower:
    def __init__(self, reader, args, out=sys.stdout):
        self.r, self.a, self.out = reader, args, out
        self.seen = {}
        self.summary = {}          # stage -> status (the end-of-run table)
        self.run = None
        self.workload = None
        self.wf = None
        self.qa = None
        self.service_url = ""      # the record's URL (checked); after confirm(), the Cloud Run API's own string
        self.service = None        # the confirmed Cloud Run service (confirm())
        self.since = parse_time(args.since) if getattr(args, "since", None) else None
        self.waits_reported = set()

    # -- output (the one writer; every line is one line)
    def say(self, text=""):
        say(text, self.out)

    def line(self, label, text):
        self.say(f"{stamp()}  {label:<16} {flat(text)}")

    def emit(self, key, label, value, detail=""):
        if value is None or self.seen.get(key) == value:
            return
        self.seen[key] = value
        self.line(label, f"{value}{('  ' + str(detail)) if detail else ''}")

    # -- record values (FD-102)
    def child_project(self):
        """The workload record's child project (exact project-id format), None when the record names none."""
        child = (self.workload or {}).get("project_id")
        if child is None or child == "":
            return None
        return record_value("workloads.project_id", child, PROJECT_RE)

    # -- reads
    def pick_run(self):
        runs = self.r.runs(self.a.product_id)
        if self.a.trace_id:
            runs = [x for x in runs if x.get("trace_id") == self.a.trace_id]
        if self.since:
            runs = [x for x in runs if (parse_time(x.get("started_at")) or self.since) >= self.since]
        if not runs:
            return None
        return max(runs, key=lambda x: parse_time(x.get("started_at")) or datetime.datetime.min.replace(
            tzinfo=datetime.timezone.utc))

    def poll(self):
        """One read pass. Returns 'success', 'failed' or None (still running). Raises Refused (FD-102)."""
        wl = self.r.get_doc("workloads", self.a.product_id)
        if wl is not None:
            self.workload = wl
            self.emit("record", "record", one_line(wl.get("status") or "?"),
                      f"child project {self.child_project() or '?'}")
        run = self.pick_run()
        if run is None:
            return None
        self.run = run
        trace = record_value("pipeline_executions trace_id", run.get("trace_id"), ID_RE)
        self.emit("run", "run", trace, f"mode {one_line(run.get('execution_mode') or '?')}")
        self.emit("current_stage", "pipeline", one_line(run.get("current_stage") or "?"),
                  f"status {one_line(run.get('status') or '?')}")
        stages = run.get("stages") if isinstance(run.get("stages"), dict) else {}
        for name in sorted(stages, key=lambda n: (STAGE_ORDER.index(n) if n in STAGE_ORDER else 99, str(n))):
            st = stages.get(name) if isinstance(stages.get(name), dict) else {}
            status = st.get("status")
            if status:
                self.summary[stage_row(name)] = one_line(status, 60)
                self.emit(f"stage:{name}", stage_row(name), one_line(status, 60), one_line(st.get("summary"), 120))
        wait = OPERATOR_WAITS.get(str(run.get("current_stage") or ""))
        if wait and run.get("current_stage") not in self.waits_reported:
            self.waits_reported.add(run.get("current_stage"))
            self.line("WAITING", f"for the operator: {wait}")

        exec_id = run.get("workflow_execution_id")
        if exec_id is not None and exec_id != "":
            exec_id = record_value("pipeline_executions workflow_execution_id", exec_id, ID_RE)
            wf = self.r.workflow_execution(exec_id)
            if wf:
                self.wf = wf
                self.emit("workflow", "workflow", one_line(wf.get("state")) if wf.get("state") else None,
                          f"execution {exec_id}")

        self._follow_jobs(trace, stages)
        child = self.child_project()
        if child:
            self._follow_builds(child, run)

        url = ((run.get("outputs") or {}).get("service_url") if isinstance(run.get("outputs"), dict) else "") or ""
        if not url and self.wf and self.wf.get("result"):
            try:
                url = (json.loads(self.wf["result"]) or {}).get("service_url") or ""
            except (ValueError, AttributeError, TypeError):
                url = ""
        if not url and str(run.get("status")) == "SUCCEEDED":
            url = (self.workload or {}).get("service_url") or ""
        if url:
            # FD-102: a non-str value (records written before the fix can hold the raw Terraform output map), a
            # control character or a URL that is not exactly https://<host> stops here, before any request
            self.service_url = checked_service_url(url)
            self.emit("service_url", "service_url", self.service_url)

        wf_state = (self.wf or {}).get("state")
        if str(run.get("status")) == "FAILED" or wf_state in ("FAILED", "CANCELLED"):
            return "failed"
        if str(run.get("status")) == "SUCCEEDED" or wf_state == "SUCCEEDED":
            return "success"
        return None

    def _follow_jobs(self, trace, stages):
        qa_started = (stages.get("qa") or {}).get("status") not in (None, "QUEUED") \
            if isinstance(stages.get("qa"), dict) else False
        cur = str((self.run or {}).get("current_stage") or "")
        if qa_started or cur in ("QA", "RELEASE", "TERRAFORM_CALLBACK", "COMPLETE", "FAILED"):
            ex = self.r.job_execution_for(QA_JOB, QA_TRACE_ENV, trace)
            if ex:
                state = execution_state(ex)
                self.summary["qa_job"] = state
                self.emit("qa_job", "qa_job", state, short(ex.get("name")))
            qa = self.r.get_doc("qa_test_runs", trace)
            if qa:
                self.qa = qa
                verdict = ("PASSED" if qa.get("passed") else
                           f"FAILED {one_line(qa.get('error_class') or '')} {one_line(qa.get('reason') or '')}".strip())
                self.summary["qa"] = "SUCCESS" if qa.get("passed") else "FAILED"
                self.emit("qa_result", "qa_result", verdict,
                          f"attempt {one_line(qa.get('attempt'))} exit {one_line(qa.get('exit_code'))} "
                          f"{one_line(qa.get('summary'), 100)}")
        if cur in ("TERRAFORM_CALLBACK", "COMPLETE", "FAILED") or "terraform" in stages:
            ex = self.r.job_execution_for(APPLIER_JOB, APPLIER_TRACE_ENV, trace)
            if ex:
                state = execution_state(ex)
                self.summary["tf_applier"] = state
                self.emit("tf_applier", "tf_applier", state, short(ex.get("name")))

    def _follow_builds(self, child, run):
        started = parse_time(run.get("started_at"))
        for b in self.r.builds(child):
            created = parse_time(b.get("createTime"))
            if started and created and created < started:
                continue
            bid = one_line(b.get("id") or "?", 80)
            status = one_line(b.get("status"), 40) if b.get("status") else None
            self.summary["cloud_build"] = status
            fail = one_line(((b.get("failureInfo") or {}).get("detail")) or "", 120)
            self.emit(f"build:{bid}", "cloud_build", status, f"build {bid}{('  ' + fail) if fail else ''}")

    # -- terminal reports
    def failure_report(self):
        run = self.run or {}
        self.say("")
        self.say("FAILED")
        payload = None
        err = (self.wf or {}).get("error") or {}
        if isinstance(err, dict) and err.get("payload"):
            try:
                payload = json.loads(err["payload"])
            except (ValueError, TypeError):
                payload = {"message": err["payload"]}
        if not isinstance(payload, dict):
            payload = {}
        error_class = payload.get("error_class") or run.get("error_class") or "UNKNOWN"
        stage = payload.get("stage") or run.get("failed_stage") or run.get("current_stage") or "unknown"
        reason = payload.get("reason") or run.get("failure_reason") or ""
        message = payload.get("message") or run.get("error") or ""
        self.say(f"  error_class : {flat(error_class)}")
        self.say(f"  stage       : {flat(stage)}")
        if reason:
            self.say(f"  reason      : {flat(reason)}")
        self.say(f"  message     : {flat(str(message)[:DETAIL_LIMIT])}")
        qa = self.qa
        if qa is None and run.get("trace_id"):
            qa = self.r.get_doc("qa_test_runs", record_value("pipeline_executions trace_id", run["trace_id"], ID_RE))
        if qa and (stage == "qa" or not qa.get("passed")):
            self.say("  QA:")
            self.say(f"    verdict   : passed={flat(qa.get('passed'))} error_class={flat(qa.get('error_class'))} "
                     f"reason={flat(qa.get('reason'))} exit_code={flat(qa.get('exit_code'))}")
            self.say(f"    execution : {flat(qa.get('execution_name'))}")
            self.say(f"    summary   : {flat(str(qa.get('summary') or '')[:DETAIL_LIMIT])}")
            diags = qa.get("diagnostics") if isinstance(qa.get("diagnostics"), list) else []
            for d in diags[:10]:
                if not isinstance(d, dict):
                    continue
                where = str(d.get("file") or "-")
                if d.get("file") and d.get("line") is not None:
                    where += f":{d.get('line')}"
                self.say(f"    - {flat(d.get('code'))}  {flat(where)}  {one_line(d.get('message'), 300)}")
                if d.get("detail"):
                    self.say("      detail: " + flat(str(d["detail"])[:DETAIL_LIMIT]))
            if len(diags) > 10:
                self.say(f"    ... {len(diags) - 10} more diagnostics (qa_test_runs/{flat(run.get('trace_id'))})")
        self.summary[stage_row(stage)] = "FAILED"
        # stages the run never reached keep the QUEUED the run record was created with
        for name, status in list(self.summary.items()):
            if status == "QUEUED":
                self.summary[name] = "NOT_REACHED"

    # -- the service URL (FD-102)
    def confirm(self, spacing=10):
        """Run-API confirmation of the record's service URL (module docstring). Sets self.service and replaces
        self.service_url with the API's string. Raises Refused; nothing is sent to the URL before it returns."""
        child = self.child_project()
        if child is None:
            raise Refused(SERVICE_URL_NOT_CONFIRMED, "the workload record names no child project, so its Cloud Run "
                                                     "services cannot be listed", EXIT_PROBE)
        region, _source = self.workload_region()
        folder = self.r.managed_folder()
        self.r.child_in_folder(child, folder, spacing=spacing)
        status, services = self.r.list_services(child, region, spacing=spacing)
        if status in (401, 403):
            raise Refused(PERMISSION_DENIED, CHILD_READ_DENIED, EXIT_PREREQ)
        if services is None:
            raise Refused(CLOUD_RUN_API_UNAVAILABLE, f"the Cloud Run services of {child} ({region}) could not be "
                                                     f"listed completely (HTTP {status or 'no answer'})", EXIT_PREREQ)
        svc, api_url = matching_service(self.service_url, services)
        if svc is None:
            raise Refused(SERVICE_URL_NOT_CONFIRMED, f"no Cloud Run service in {child} ({region}) serves the "
                                                     f"recorded service URL", EXIT_PROBE)
        self.service_url, self.service = checked_service_url(api_url), svc
        self.line("confirmed", f"{self.service_url}  (Cloud Run service {short(svc.get('name')) or '?'} in {child}, "
                               f"{region})")

    # -- health verdict, per access mode
    def access_mode(self):
        """The exact `workloads/{pid}.access.mode`, or None (no access record, or a value outside the enum)."""
        access = (self.workload or {}).get("access")
        mode = access.get("mode") if isinstance(access, dict) else None
        return mode if mode in ACCESS_MODES else None

    def workload_region(self):
        """(region, source): `workloads/{pid}.region` (exact region format, else RECORD_VALUE_REFUSED), or --region
        for a legacy record that names none (such a workload follows the install's default region)."""
        region = (self.workload or {}).get("region")
        if region is None or (isinstance(region, str) and not region.strip()):
            return self.a.region, "no region on the workload record; --region"
        return record_value("workloads.region", region, REGION_RE), "workload record"

    def allowed_principals(self):
        """`workloads/{pid}.access.invoker_principals` (the people the Control Center lets in), as listed."""
        access = (self.workload or {}).get("access")
        principals = access.get("invoker_principals") if isinstance(access, dict) else None
        return [flat(p) for p in principals if isinstance(p, str) and p] if isinstance(principals, list) else []

    def health_url(self):
        return without_one_trailing_slash(self.service_url) + HEALTH_PATH

    @staticmethod
    def signs_in_with_google(status, redirect):
        """A 302 whose Location host is exactly Google sign-in (parsed with urllib.parse, not matched as text)."""
        return status == 302 and redirect_host(redirect) == GOOGLE_SIGN_IN_HOST

    def health(self, auth, attempts=3, spacing=10):
        """(health state, exit code). The check the workload's access mode calls for (module docstring); the
        service URL is the confirmed one (confirm())."""
        mode, source = self.access_mode(), "workload record"
        region, region_source = self.workload_region()
        first = None
        if mode is None and self.a.child_checks and (self.service or {}).get("iapEnabled") is True:
            mode, source = PRIVATE_IAP, "no access record; the Cloud Run service has iapEnabled"
        if mode is None:
            first = http_full(self.health_url(), None, timeout=30)
            if self.signs_in_with_google(first[0], first[2]):
                if not self.iap_enabled():   # A1: the app itself can answer with that redirect
                    return self.not_iap_mismatch("no access record; ")
                mode = PRIVATE_IAP
                source = f"no access record; an anonymous GET {HEALTH_PATH} was redirected to {GOOGLE_SIGN_IN_HOST}"
        where = f"region {region} ({region_source})"
        self.line("access", f"{mode}  ({source})  {where}" if mode else
                  f"unknown  (no access record, and no IAP in front): anonymous requests only, no token  {where}")
        if mode == PRIVATE_IAP:
            if self.a.child_checks:
                return self.iap_child_checks(region, attempts, spacing)
            return self.iap_not_probed(attempts, spacing)
        if mode == PUBLIC_APP:
            ok = self.probe(lambda: None, attempts, spacing,
                            "a public (PUBLIC_APP) service refused an anonymous request: its Cloud Run invoker "
                            "binding or ingress does not match the access record")
            return (HEALTH_PASS, EXIT_PASS) if ok else (HEALTH_FAIL, EXIT_PROBE)
        if mode == PRIVATE_IAM:
            return self.private_iam(auth, attempts, spacing)
        return self.no_access_record(first, attempts, spacing)

    def anonymous(self, attempts, spacing, first=None):
        """GET /health with no credentials until it answers 2xx, 401/403/404 or a redirect to Google sign-in, up to
        `attempts` (`first`: an answer already received). (status, redirect) of the last answer."""
        url = self.health_url()
        status, redirect = 0, ""
        for i in range(attempts):
            status, body, redirect = first if (i == 0 and first is not None) else http_full(url, None, timeout=30)
            where = redirect_host(redirect)
            self.line("health", f"HTTP {status or 'no answer'}{' to ' + where if where else ''}  {url}  (anonymous)  "
                                f"{body_echo(body)}")
            if 200 <= status < 300 or status in (401, 403, 404) or self.signs_in_with_google(status, redirect):
                return status, redirect
            if i + 1 < attempts:
                time.sleep(spacing)
        return status, redirect

    def no_access_record(self, first, attempts, spacing):
        status, redirect = self.anonymous(attempts, spacing, first)
        if 200 <= status < 300:
            return HEALTH_PASS, EXIT_PASS
        if status in (401, 403, 404):
            self.line("health", f"{HEALTH_NOT_PROBED_NO_ACCESS_RECORD}  {NOT_PROBED_NO_RECORD_REASON}")
            return HEALTH_NOT_PROBED_NO_ACCESS_RECORD, EXIT_NOT_PROBED
        self.line("health", f"{self.health_url()} did not answer 2xx, 401, 403 or 404 in {attempts} tries")
        return HEALTH_FAIL, EXIT_PROBE

    def iam_gate(self):
        """None when an audience-bound token may be sent to the confirmed PRIVATE_IAM service, else (state, exit
        code). Defence in depth only (the token's audience binding is the control): the service's invoker check is
        on, and its IAM policy names no allUsers / allAuthenticatedUsers."""
        svc = self.service or {}
        name = short(svc.get("name")) or "?"
        if svc.get("invokerIamDisabled") is True:
            self.line("health", f"{ACCESS_RECORD_MISMATCH}  Cloud Run service {name} has its invoker check off "
                                "(invokerIamDisabled) although the access record says PRIVATE_IAM; no token was minted")
            return ACCESS_RECORD_MISMATCH, EXIT_PROBE
        full = svc.get("name")
        if not isinstance(full, str) or not SERVICE_NAME_RE.fullmatch(full):
            self.line("health", "the confirmed Cloud Run service has no readable resource name; no token was minted")
            return HEALTH_FAIL, EXIT_PROBE
        status, policy = self.r.iam_policy(full)
        if policy is None:
            self.line("health", f"permission denied: the IAM policy of Cloud Run service {name} could not be read "
                                f"(HTTP {status or 'no answer'}; the canary needs read access to the child project); "
                                "no token was minted")
            return HEALTH_ERROR_PERMISSION, EXIT_PREREQ
        public = public_members_in(policy)
        if public:
            self.line("health", f"{ACCESS_RECORD_MISMATCH}  Cloud Run service {name} grants {', '.join(public)} "
                                "although the access record says PRIVATE_IAM; no token was minted")
            return ACCESS_RECORD_MISMATCH, EXIT_PROBE
        return None

    def private_iam(self, auth, attempts, spacing):
        status, _redirect = self.anonymous(attempts, spacing)
        if 200 <= status < 300:
            self.line("health", f"{ACCESS_RECORD_MISMATCH}  an anonymous GET {self.health_url()} answered HTTP "
                                f"{status}: the service is public although the access record says PRIVATE_IAM")
            return ACCESS_RECORD_MISMATCH, EXIT_PROBE
        if status not in (401, 403, 404):
            self.line("health", f"{self.health_url()} did not answer 401, 403 or 404 to an anonymous request in "
                                f"{attempts} tries")
            return HEALTH_FAIL, EXIT_PROBE
        gate = self.iam_gate()
        if gate is not None:
            return gate
        token, why = auth.audience_token(self.service_url)
        if token is None:
            self.line("health", f"{HEALTH_NOT_PROBED_PRIVATE_IAM}  {why}; {NOT_PROBED_IAM_REASON}")
            return HEALTH_NOT_PROBED_PRIVATE_IAM, EXIT_NOT_PROBED
        ok = self.probe(lambda: token, attempts, spacing,
                        "the probe identity was refused: a private (IAM invoker) service must list the "
                        "probing service account under who may use it")
        return (HEALTH_PASS, EXIT_PASS) if ok else (HEALTH_FAIL, EXIT_PROBE)

    def probe(self, token_fn, attempts, spacing, refused):
        """GET <service_url>/health with token_fn() (None = anonymous) until it answers 200, up to `attempts`. A token
        to a workload travels only in X-Serverless-Authorization."""
        url = self.health_url()
        status, body = 0, ""
        for i in range(attempts):
            token = token_fn()
            status, body = http(url, token, timeout=30, token_header=WORKLOAD_TOKEN_HEADER)
            self.line("health", f"HTTP {status or 'no answer'}  {url}  {body_echo(body)}")
            if status == 200:
                return True
            if i + 1 < attempts:
                time.sleep(spacing)
        if status in (302, 401, 403):
            self.line("health", refused)
        else:
            self.line("health", f"{url} did not answer 200 in {attempts} tries")
        return False

    def iap_enabled(self):
        """A1 (owner-approved): the confirmed Cloud Run v2 service's `iapEnabled` is exactly true. Cloud Run omits
        the field when it is false, so a missing or unreadable field is "not IAP" (fail closed)."""
        return (self.service or {}).get("iapEnabled") is True

    def not_iap_mismatch(self, prefix=""):
        """A1: a redirect to Google sign-in from a service whose iapEnabled is not true is not IAP (the container can
        send that redirect itself): ACCESS_RECORD_MISMATCH, exit 4, never "IAP enforced" or a pass."""
        name = short((self.service or {}).get("name")) or "?"
        self.line("health", f"{ACCESS_RECORD_MISMATCH}  {prefix}an anonymous GET {self.health_url()} was redirected "
                            f"to {GOOGLE_SIGN_IN_HOST}, but Cloud Run service {name} does not have iapEnabled true: "
                            "the redirect is not IAP's, so IAP is not proven")
        return ACCESS_RECORD_MISMATCH, EXIT_PROBE

    def iap_not_probed(self, attempts, spacing):
        """PRIVATE_IAP: /health is not probed (NOT_PROBED_IAP_REASON). No token is sent and none is minted; the one
        check is that IAP is in front: an anonymous GET of /health must be redirected to Google sign-in. A 2xx answer
        (the app reached without sign-in) or any other answer is a failure, never a pass."""
        url = self.health_url()
        status = 0
        for i in range(attempts):
            status, _body, redirect = http_full(url, None, timeout=30)
            if self.signs_in_with_google(status, redirect):
                if not self.iap_enabled():
                    return self.not_iap_mismatch()
                self.line("health", f"{HEALTH_NOT_PROBED_PRIVATE_IAP}  IAP enforced: an anonymous GET {url} was "
                                    f"redirected (302) to {GOOGLE_SIGN_IN_HOST}; {HEALTH_PATH} itself was not probed: "
                                    f"{NOT_PROBED_IAP_REASON}")
                if self.a.iap_browser_check:
                    principals = self.allowed_principals()
                    self.line("iap_browser", f"open {url} in a browser signed in as an allowed principal"
                                             f"{' (' + ', '.join(principals) + ')' if principals else ''}; "
                                             "a healthy service answers 200")
                return HEALTH_NOT_PROBED_PRIVATE_IAP, EXIT_NOT_PROBED
            where = redirect_host(redirect)
            self.line("health", f"IAP check ({i + 1}/{attempts}): an anonymous GET {url} answered HTTP "
                                f"{status or 'no answer'}{' to ' + where if where else ''}")
            if i + 1 < attempts:
                time.sleep(spacing)
        if 200 <= status < 300:
            self.line("health", f"IAP is not enforced: an anonymous GET {url} answered HTTP {status}; a PRIVATE_IAP "
                                "service must redirect it to Google sign-in")
        else:
            self.line("health", f"IAP not proven: an anonymous GET {url} was not redirected to Google sign-in "
                                f"({GOOGLE_SIGN_IN_HOST}) in {attempts} tries")
        return HEALTH_FAIL, EXIT_PROBE

    def iap_child_checks(self, region, attempts, spacing):
        """PRIVATE_IAP with --child-checks: never tries to pass IAP; reads the platform's own signals in the child
        project (iap_child_once). (state, exit code): PASS, ERROR (permission denied), ACCESS_RECORD_MISMATCH (A1: the
        confirmed service's iapEnabled is not true, so a redirect to Google sign-in proves nothing) or FAIL."""
        if not self.iap_enabled():
            name = short((self.service or {}).get("name")) or "?"
            self.line("health", f"{ACCESS_RECORD_MISMATCH}  Cloud Run service {name} does not have iapEnabled true "
                                "although the workload is PRIVATE_IAP; IAP is not proven")
            return ACCESS_RECORD_MISMATCH, EXIT_PROBE
        code = EXIT_PROBE
        for i in range(attempts):
            ok, code, message = self.iap_child_once(region)
            if ok:
                self.line("health", message)
                return HEALTH_PASS, EXIT_PASS
            self.line("health", f"not verified ({i + 1}/{attempts}): {message}")
            if code == EXIT_PREREQ:
                return HEALTH_ERROR_PERMISSION, EXIT_PREREQ
            if i + 1 < attempts:
                time.sleep(spacing)
        return HEALTH_FAIL, code

    def iap_child_once(self, region):
        """(ok, exit code, message). Every read here is a GET, except Logging's entries:list (a read by a POST). The
        service is the confirmed one (confirm()); revision names are used only in their exact resource format."""
        def denied(what, role):
            return False, EXIT_PREREQ, (f"permission denied reading {what} in {child}: the operator needs {role} in "
                                        "the child project")

        child = self.child_project()
        svc = self.service
        if not child or svc is None:
            return False, EXIT_PROBE, "the service URL was not confirmed, so its Cloud Run service is unknown"
        full = svc.get("name")
        if not isinstance(full, str) or not SERVICE_NAME_RE.fullmatch(full):   # R6: before it reaches the filter
            return False, EXIT_PROBE, "the confirmed Cloud Run service names itself in an unexpected format"
        service = short(full)
        ready_rev, created_rev = svc.get("latestReadyRevision") or "", svc.get("latestCreatedRevision") or ""
        if not ready_rev:
            return False, EXIT_PROBE, f"service {service} has no ready revision"
        if not isinstance(ready_rev, str) or not REVISION_NAME_RE.fullmatch(ready_rev):
            return False, EXIT_PROBE, f"service {service} names its ready revision in an unexpected format"
        if created_rev and created_rev != ready_rev:
            return False, EXIT_PROBE, (f"the newest revision {short(created_rev)} of service {service} is not ready "
                                       f"(the latest ready revision is still {short(ready_rev)})")
        revision = short(ready_rev)
        status, rev = self.r.run_resource(ready_rev)
        if status in (401, 403):
            return denied("Cloud Run revisions", "roles/run.viewer")
        if rev is None:
            return False, EXIT_PROBE, f"could not read revision {revision} (HTTP {status or 'no answer'})"
        ready = [c for c in rev.get("conditions") or [] if isinstance(c, dict) and c.get("type") == "Ready"]
        if not ready or ready[0].get("state") != "CONDITION_SUCCEEDED":
            state = ready[0].get("state") if ready else "missing"
            why = one_line(ready[0].get("message"), 200) if ready else ""
            return False, EXIT_PROBE, f"revision {revision} is not Ready (Ready condition {state}){': ' + why if why else ''}"
        paths = []
        for c in rev.get("containers") or []:
            get = ((c or {}).get("startupProbe") or {}).get("httpGet")
            if isinstance(get, dict):
                paths.append(get.get("path") or "/")     # the API's default path is "/"
        if HEALTH_PATH not in paths:
            if not paths:
                return False, EXIT_PROBE, (f"revision {revision} has no HTTP startup probe, so Cloud Run never "
                                           f"checked {HEALTH_PATH} (the golden compute-cloudrun module sets one)")
            return False, EXIT_PROBE, (f"the startup probe of revision {revision} checks "
                                       f"{', '.join(str(p) for p in paths)}, not {HEALTH_PATH}")
        status, entries = self.r.startup_probe_entries(child, service, revision, rev.get("createTime"))
        if status in (401, 403):
            return denied("Cloud Logging", "roles/logging.viewer")
        if status != 200:
            return False, EXIT_PROBE, f"could not read Cloud Logging in {child} (HTTP {status or 'no answer'})"
        texts = [str((e or {}).get("textPayload") or "") for e in entries]
        succeeded = [t for t in texts if STARTUP_PROBE_OK in t and STARTUP_PROBE_PATH in t]
        failed = [t for t in texts if STARTUP_PROBE_FAILED in t]
        if not succeeded:
            if failed:
                return False, EXIT_PROBE, (f"the {HEALTH_PATH} startup probe of revision {revision} failed: "
                                           f"{one_line(failed[0], 300)}")
            return False, EXIT_PROBE, (f"no \"{STARTUP_PROBE_OK} ... {STARTUP_PROBE_PATH}\" line for revision "
                                       f"{revision} in Cloud Logging (run.googleapis.com/varlog/system) yet")
        url = self.health_url()
        status, _body, redirect = http_full(url, None, timeout=30)
        iap_flag = f"iapEnabled {svc.get('iapEnabled')}"
        if self.signs_in_with_google(status, redirect):
            return True, EXIT_PASS, (f"(startup probe) 200, IAP enforced (302)  revision {revision} of {service}, "
                                     f"anonymous GET {url} redirected to {GOOGLE_SIGN_IN_HOST}")
        if 200 <= status < 300:
            return False, EXIT_PROBE, (f"IAP is not enforced: an anonymous GET {url} answered HTTP {status} "
                                       f"({iap_flag}); a PRIVATE_IAP service must redirect it to Google sign-in")
        where = redirect_host(redirect)
        return False, EXIT_PROBE, (f"IAP not proven: an anonymous GET {url} answered HTTP {status or 'no answer'}"
                                   f"{' to ' + where if where else ''} ({iap_flag}); expected a 302 redirect to "
                                   f"Google sign-in ({GOOGLE_SIGN_IN_HOST})")

    def print_summary(self, verdict):
        self.say("")
        self.say(f"Per-stage summary ({flat(self.a.product_id)}, run "
                 f"{flat((self.run or {}).get('trace_id') or '-')}):")
        order = list(STAGE_ORDER[:10]) + ["qa_job", "release", "cloud_build", "terraform", "terraform_remediation",
                                          "tf_applier", "health"]
        names = [n for n in order if n in self.summary] + sorted(str(n) for n in self.summary if n not in order)
        for n in names:
            self.say(f"  {flat(n):<22} {flat(self.summary[n])}")
        self.say(f"RESULT: {flat(verdict)}")


def _refused_report(f, refused):
    """The typed FD-102 stop: one line, the summary row and RESULT; nothing was sent to the service URL."""
    f.line("refused", f"{refused.error_class}: {refused.message}")
    if refused.error_class == PERMISSION_DENIED:
        f.summary["health"] = HEALTH_ERROR_PERMISSION
        f.print_summary(HEALTH_ERROR_PERMISSION)
    else:
        f.summary["health"] = refused.error_class
        word = "FAIL" if refused.exit_code == EXIT_PROBE else "ERROR"
        f.print_summary(f"{word} ({refused.error_class})")
    return refused.exit_code


def follow(args):
    for name, value, pattern in (("--project", args.project, PROJECT_RE), ("--region", args.region, REGION_RE),
                                 ("--product-id", args.product_id, PRODUCT_RE)):
        if not isinstance(value, str) or not pattern.fullmatch(value):
            say(f"invalid {name}", sys.stderr)
            return EXIT_USAGE
    if args.trace_id and (not ID_RE.fullmatch(args.trace_id) or args.trace_id in (".", "..")):
        say("invalid --trace-id", sys.stderr)
        return EXIT_USAGE
    auth = Auth()
    if not auth.access_token():
        say("No gcloud access token: run `gcloud auth login` first.", sys.stderr)
        return EXIT_PREREQ
    reader = Reader(args.project, args.region, auth)
    f = Follower(reader, args)
    try:
        return _follow(args, auth, reader, f)
    except Refused as refused:
        return _refused_report(f, refused)


def _follow(args, auth, reader, f):
    poll = max(0.0, float(args.poll_sec))

    first = reader.get_doc("workloads", args.product_id)
    if reader.denied:
        say("Permission denied reading Firestore in the host project: the operator needs read access to "
            "the platform records (for example roles/datastore.viewer).", sys.stderr)
        return EXIT_PREREQ
    if args.require_new and first is not None:
        say(f"Workload '{args.product_id}' already exists: choose a new --product-id, or follow it with "
            f"--watch-only {args.product_id}.", sys.stderr)
        return EXIT_USAGE

    if args.await_submit_min:
        f.line("submit", f"waiting up to {args.await_submit_min} min for workload '{args.product_id}' to be submitted")
        deadline = time.time() + float(args.await_submit_min) * 60
        while reader.get_doc("workloads", args.product_id) is None:
            if time.time() >= deadline:
                f.line("submit", "no workload record appeared")
                f.summary["submit"] = "NOT_SUBMITTED"
                f.print_summary("TIMEOUT (not submitted)")
                return EXIT_TIMEOUT
            time.sleep(poll)
        wl = reader.get_doc("workloads", args.product_id) or {}
        f.summary["submit"] = "SUBMITTED"
        f.line("submit", f"record created (mode {one_line(wl.get('creation_mode'))}, code review "
                         f"{'on' if wl.get('require_human_code_review') else 'off'}, plan approval "
                         f"{'on' if wl.get('require_plan_approval') else 'off'})")

    deadline = time.time() + float(args.timeout_min) * 60
    outcome = None
    while True:
        outcome = f.poll()
        if outcome:
            break
        if reader.denied >= 3:
            say("Permission denied reading the platform records (3 reads in a row).", sys.stderr)
            f.print_summary("ERROR (permission denied)")
            return EXIT_PREREQ
        if time.time() >= deadline:
            stage = one_line((f.run or {}).get("current_stage") or "not started", 40)
            f.line("timeout", f"after {args.timeout_min} min at stage {stage}")
            f.summary[stage_row(stage.lower())] = "TIMEOUT"
            f.print_summary("TIMEOUT")
            return EXIT_TIMEOUT
        time.sleep(poll)

    if outcome == "failed":
        f.failure_report()
        f.print_summary("FAIL")
        return EXIT_FAILED
    if not f.service_url:
        # the deploy reports an unreadable URL as unknown with a typed reason (never a guessed address)
        unknown_reason = (f.workload or {}).get("service_url_unknown_reason")
        f.line("health", "the run succeeded but reported no service URL"
               + (f" (unknown: {one_line(unknown_reason, 80)})" if unknown_reason else ""))
        f.summary["health"] = "NO_SERVICE_URL"
        f.print_summary("FAIL (no service URL)")
        return EXIT_PROBE
    f.confirm(spacing=min(10.0, poll))   # FD-102: nothing is sent to the URL before it is Run-API-confirmed
    state, code = f.health(auth, spacing=min(10.0, poll))
    f.summary["health"] = state
    if state == HEALTH_PASS:
        f.print_summary("PASS")
    elif state == HEALTH_NOT_PROBED_PRIVATE_IAP:
        # deployed with IAP in front: neither a pass nor an error; /health cannot be probed from the command line
        f.print_summary(f"DEPLOYED, {HEALTH_NOT_PROBED_PRIVATE_IAP} ({NOT_PROBED_IAP_REASON}: {f.health_url()})")
    elif state == HEALTH_NOT_PROBED_PRIVATE_IAM:
        f.print_summary(f"DEPLOYED, {HEALTH_NOT_PROBED_PRIVATE_IAM} ({NOT_PROBED_IAM_REASON})")
    elif state == HEALTH_NOT_PROBED_NO_ACCESS_RECORD:
        f.print_summary(f"DEPLOYED, {HEALTH_NOT_PROBED_NO_ACCESS_RECORD} ({NOT_PROBED_NO_RECORD_REASON})")
    elif state == HEALTH_ERROR_PERMISSION:
        f.print_summary(HEALTH_ERROR_PERMISSION)
    elif state == ACCESS_RECORD_MISMATCH:
        f.print_summary(f"FAIL ({ACCESS_RECORD_MISMATCH})")
    else:
        f.print_summary("FAIL (health probe)")
    return code


class _Parser(argparse.ArgumentParser):
    """argparse with its messages through the one writer."""

    def _print_message(self, message, file=None):
        if message:
            say(message.rstrip("\n"), file if file is not None else sys.stderr)


def main(argv=None):
    p = _Parser(prog="live_canary_follow.py", description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", parser_class=_Parser)
    s = sub.add_parser("spec")
    s.add_argument("example")
    fo = sub.add_parser("follow")
    fo.add_argument("--project", required=True)
    fo.add_argument("--region", default="us-central1")
    fo.add_argument("--product-id", required=True)
    fo.add_argument("--trace-id", default="")
    fo.add_argument("--since", default="")
    fo.add_argument("--timeout-min", type=float, default=75)
    fo.add_argument("--poll-sec", type=float, default=30)
    fo.add_argument("--await-submit-min", type=float, default=0)
    fo.add_argument("--require-new", action="store_true")
    fo.add_argument("--iap-browser-check", action="store_true")
    fo.add_argument("--child-checks", action="store_true")
    args = p.parse_args(argv)
    if args.cmd == "spec":
        try:
            text = submission_prompt(args.example)
        except OSError as e:
            say(f"cannot read {args.example}: {e.strerror}", sys.stderr)
            return EXIT_USAGE
        if not text:
            say(f"{args.example} has no 'Workload Form Submission Prompt' block", sys.stderr)
            return EXIT_USAGE
        say(text)
        return EXIT_PASS
    if args.cmd == "follow":
        return follow(args)
    p.print_usage(sys.stderr)
    return EXIT_USAGE


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - printed through the one writer (no raw traceback text)
        say(f"live_canary_follow.py: internal error: {type(exc).__name__}: {one_line(exc, 300)}", sys.stderr)
        sys.exit(EXIT_FAILED)
