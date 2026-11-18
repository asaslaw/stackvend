#!/usr/bin/env python3
"""StackVend live canary: read-only follower (FD-4DN, release gate RC-LIVE-GATE).

Run through scripts/live_canary.sh (python3 -I, standard library only). Two sub-commands:

  spec <example.md>          print the "Workload Form Submission Prompt" text of an example plan
  follow --project ... --product-id ...
                             follow one workload read-only through the pipeline, probe /health, report per stage

Every read uses the operator's own gcloud login: an access token (`gcloud auth print-access-token`) for the Google
APIs and, for the /health probe of a private (IAM) service, an identity token (`gcloud auth print-identity-token`).
Tokens are handed to curl on stdin (`--config -`), never on a command line, and are never printed. Nothing here
writes, deletes or submits.

The health verdict follows the workload's access mode (`workloads/{pid}.access.mode`). The service URL comes from
the platform records only (the run's outputs, the workflow result or `workloads/{pid}.service_url`); the canary
never lists Cloud Run in the child project, so it needs no access there.
  PUBLIC_APP   GET <service_url>/health with no credentials: must answer 200
  PRIVATE_IAM  GET <service_url>/health with the operator's identity token (service URL as audience): must answer 200
  PRIVATE_IAP  /health is NOT probed: a gcloud user identity token cannot pass Direct IAP (IAP refuses it with
               "Invalid JWT audience"), and the canary mints no other token. It checks only that IAP is in front (an
               anonymous GET of /health is redirected, 302, to Google sign-in) and reports the typed state
               HEALTH_NOT_PROBED_PRIVATE_IAP with RESULT "DEPLOYED, HEALTH_NOT_PROBED_PRIVATE_IAP" (exit 6), never a
               pass. --iap-browser-check prints the URL to open in a browser signed in as an allowed principal.
  no record    an anonymous GET of /health redirected to Google sign-in is treated as PRIVATE_IAP; otherwise the
               probe with the operator's identity token
--child-checks (opt-in, default off; needs roles/run.viewer + roles/logging.viewer in the child project) restores the
platform-signal check for PRIVATE_IAP: the Cloud Run service (in the workload's region) whose URL is the recorded
service URL has a Ready latest revision, its startup probe is an HTTP probe on /health, Cloud Logging holds a
"STARTUP HTTP probe succeeded ... path "/health"" line for that revision, and the anonymous GET is redirected to
Google sign-in: PASS (exit 0). A missing permission is "ERROR (permission denied)" (exit 5), never a pass. With no
access record it also reads the service's iapEnabled.
The `access` line also names the workload's region (`workloads/{pid}.region`; a legacy record without one follows
--region).

Sources (all read-only):
  Firestore  workloads/{product_id}                  record status, child project, region, service_url, access
             pipeline_executions (product_id == id)  the run: status, current_stage, stages{}, outputs, typed error
             qa_test_runs/{trace_id}                  QA verdict + diagnostics
  Workflows  castor-main-orchestrator execution       state, typed error payload, result
  Cloud Run  jobs qa-sandbox-test-runner, tf-applier  the execution whose env names this run's trace id
  Cloud Build child project builds                    container builds started after the run
  Cloud Run  child project service + revision         (--child-checks, IAP) ready revision, startup probe
  Logging    child project run.googleapis.com/varlog/system   (--child-checks, IAP) the startup probe result
  HTTPS      <service_url>/health                     final check (per access mode, above)

Exit codes: 0 pass; 1 the pipeline failed; 2 usage; 3 timed out; 4 deployed but /health failed;
5 prerequisite missing (gcloud login, permission to read the records; with --child-checks, the child project's
Cloud Run service or Cloud Logging); 6 deployed, health not probeable from the
command line (PRIVATE_IAP, with IAP shown in front).
"""
import argparse
import datetime
import json
import os
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
HEALTH_ERROR_PERMISSION = "ERROR (permission denied)"   # --child-checks without the child-project roles
NOT_PROBED_IAP_REASON = ("a gcloud user identity token cannot pass Direct IAP (IAP refuses it: Invalid JWT audience); "
                         "open the URL in a browser signed in as an allowed principal")

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
TOKEN_TTL_S = 30 * 60


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def stamp():
    return now_utc().strftime("%Y-%m-%dT%H:%M:%SZ")


def one_line(text, limit=160):
    s = " ".join(str(text or "").split())
    return s if len(s) <= limit else s[: limit - 3] + "..."


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


# ---------------------------------------------------------------------------------------------------- spec text
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
        return tok if r.returncode == 0 and tok else None

    def access_token(self, force=False):
        if force or not self._token or time.time() - self._at > TOKEN_TTL_S:
            tok = self._gcloud(["auth", "print-access-token"])
            if tok:
                self._token, self._at = tok, time.time()
        return self._token

    def identity_token(self, audience=None):
        """An identity token. With `audience` (the service URL) gcloud is first asked for that audience; it grants
        one only to a service-account login, so a user login falls back to its default token, which Cloud Run's
        invoker check accepts for a listed user."""
        if audience:
            tok = self._gcloud(["auth", "print-identity-token", f"--audiences={audience}"])
            if tok:
                return tok
        return self._gcloud(["auth", "print-identity-token"])


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


def http(url, token=None, body=None, timeout=30):
    """(status, text). status 0 = no HTTP answer (network / curl error). The token goes to curl on stdin only."""
    status, text, _redirect = http_full(url, token, body, timeout)
    return status, text


def http_full(url, token=None, body=None, timeout=30):
    """(status, text, redirect_url). Redirects are never followed; redirect_url is curl's %{redirect_url}: the
    Location a 3xx answer names, "" otherwise."""
    cfg = [f"url = {_cfg_quote(url)}"]
    if token:
        cfg.append(f"header = {_cfg_quote('Authorization: Bearer ' + token)}")
    args = ["curl", "-sS", "--max-time", str(timeout), "-w", "\n%{redirect_url}\n%{http_code}", "--config", "-"]
    tmp = None
    if body is not None:
        fd, tmp = tempfile.mkstemp(prefix="live-canary-", suffix=".json")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(body, fh)
        args += ["-H", "Content-Type: application/json", "--data-binary", "@" + tmp]
    try:
        r = subprocess.run(args, input="\n".join(cfg) + "\n", capture_output=True, text=True, timeout=timeout + 15)
    except (OSError, subprocess.TimeoutExpired):
        return 0, "", ""
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    out = r.stdout or ""
    rest, _, code = out.rpartition("\n")
    text, _, redirect = rest.rpartition("\n")
    try:
        status = int(code.strip())
    except ValueError:
        return 0, "", ""
    return status, text, redirect.strip()


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
        self.docs = f"{FIRESTORE}/projects/{project}/databases/{database}/documents"
        self.denied = 0
        self.workflow_name = None

    def _note(self, status):
        if status in (401, 403):
            self.denied += 1
        elif status == 200:
            self.denied = 0

    def get_doc(self, path):
        status, data = http_json(f"{self.docs}/{path}", self.auth)
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
            url = (f"{WORKFLOWS}/projects/{self.project}/locations/{self.region}/workflows/{name}"
                   f"/executions/{execution_id}")
            status, data = http_json(url, self.auth)
            if status == 200 and isinstance(data, dict):
                self.workflow_name = name
                return data
        return None

    def job_execution_for(self, job, env_name, trace_id):
        """The newest execution of `job` whose container env `env_name` equals trace_id (only that env is read)."""
        url = f"{RUN_API}/projects/{self.project}/locations/{self.region}/jobs/{job}/executions?pageSize=25"
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
        url = f"{CLOUDBUILD}/projects/{child_project}/builds?pageSize=10"
        status, data = http_json(url, self.auth)
        if status != 200 or not isinstance(data, dict):
            return []
        return data.get("builds") or []

    def service_for_url(self, child_project, region, service_url):
        """(status, service): the Cloud Run v2 service in the child project and the workload's region whose `uri`, or
        one of whose `urls`, equals service_url exactly (a trailing '/' aside). status is the list call's HTTP status.
        Only with --child-checks."""
        want = service_url.rstrip("/")
        url = f"{RUN_API}/projects/{child_project}/locations/{region}/services?pageSize=100"
        status, data = http_json(url, self.auth)
        if status != 200 or not isinstance(data, dict):
            return status, None
        for svc in data.get("services") or []:
            urls = [svc.get("uri")] + list(svc.get("urls") or [])
            if want in [str(u).rstrip("/") for u in urls if u]:
                return status, svc
        return status, None

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
        if since:
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
        self.service_url = ""
        self.since = parse_time(args.since) if getattr(args, "since", None) else None
        self.waits_reported = set()

    # -- output
    def line(self, label, text):
        print(f"{stamp()}  {label:<16} {text}", file=self.out, flush=True)

    def emit(self, key, label, value, detail=""):
        if value is None or self.seen.get(key) == value:
            return
        self.seen[key] = value
        self.line(label, f"{value}{('  ' + detail) if detail else ''}")

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
        """One read pass. Returns 'success', 'failed' or None (still running)."""
        wl = self.r.get_doc(f"workloads/{self.a.product_id}")
        if wl is not None:
            self.workload = wl
            self.emit("record", "record", wl.get("status") or "?",
                      f"child project {wl.get('project_id') or '?'}")
        run = self.pick_run()
        if run is None:
            return None
        self.run = run
        trace = run.get("trace_id")
        self.emit("run", "run", trace, f"mode {run.get('execution_mode') or '?'}")
        self.emit("current_stage", "pipeline", run.get("current_stage") or "?", f"status {run.get('status') or '?'}")
        stages = run.get("stages") if isinstance(run.get("stages"), dict) else {}
        for name in sorted(stages, key=lambda n: (STAGE_ORDER.index(n) if n in STAGE_ORDER else 99, n)):
            st = stages.get(name) if isinstance(stages.get(name), dict) else {}
            status = st.get("status")
            if status:
                self.summary[name] = status
                self.emit(f"stage:{name}", name, status, one_line(st.get("summary"), 120))
        wait = OPERATOR_WAITS.get(str(run.get("current_stage") or ""))
        if wait and run.get("current_stage") not in self.waits_reported:
            self.waits_reported.add(run.get("current_stage"))
            self.line("WAITING", f"for the operator: {wait}")

        exec_id = run.get("workflow_execution_id")
        if exec_id:
            wf = self.r.workflow_execution(exec_id)
            if wf:
                self.wf = wf
                self.emit("workflow", "workflow", wf.get("state"), f"execution {exec_id}")

        if trace:
            self._follow_jobs(trace, stages)
        child = (self.workload or {}).get("project_id")
        if child and trace:
            self._follow_builds(child, run)

        url = ((run.get("outputs") or {}).get("service_url") if isinstance(run.get("outputs"), dict) else "") or ""
        if not url and self.wf and self.wf.get("result"):
            try:
                url = (json.loads(self.wf["result"]) or {}).get("service_url") or ""
            except (ValueError, AttributeError):
                url = ""
        if not url and str(run.get("status")) == "SUCCEEDED":
            url = (self.workload or {}).get("service_url") or ""
        if url:
            self.service_url = url
            self.emit("service_url", "service_url", url)

        wf_state = (self.wf or {}).get("state")
        if str(run.get("status")) == "FAILED" or wf_state in ("FAILED", "CANCELLED"):
            return "failed"
        if str(run.get("status")) == "SUCCEEDED" or wf_state == "SUCCEEDED":
            return "success"
        return None

    def _follow_jobs(self, trace, stages):
        qa_started = (stages.get("qa") or {}).get("status") not in (None, "QUEUED")
        cur = str((self.run or {}).get("current_stage") or "")
        if qa_started or cur in ("QA", "RELEASE", "TERRAFORM_CALLBACK", "COMPLETE", "FAILED"):
            ex = self.r.job_execution_for(QA_JOB, QA_TRACE_ENV, trace)
            if ex:
                state = execution_state(ex)
                self.summary["qa_job"] = state
                self.emit("qa_job", "qa_job", state, ex.get("name", "").rsplit("/", 1)[-1])
            qa = self.r.get_doc(f"qa_test_runs/{trace}")
            if qa:
                self.qa = qa
                verdict = "PASSED" if qa.get("passed") else f"FAILED {qa.get('error_class') or ''} {qa.get('reason') or ''}".strip()
                self.summary["qa"] = "SUCCESS" if qa.get("passed") else "FAILED"
                self.emit("qa_result", "qa_result", verdict,
                          f"attempt {qa.get('attempt')} exit {qa.get('exit_code')} {one_line(qa.get('summary'), 100)}")
        if cur in ("TERRAFORM_CALLBACK", "COMPLETE", "FAILED") or "terraform" in stages:
            ex = self.r.job_execution_for(APPLIER_JOB, APPLIER_TRACE_ENV, trace)
            if ex:
                state = execution_state(ex)
                self.summary["tf_applier"] = state
                self.emit("tf_applier", "tf_applier", state, ex.get("name", "").rsplit("/", 1)[-1])

    def _follow_builds(self, child, run):
        started = parse_time(run.get("started_at"))
        for b in self.r.builds(child):
            created = parse_time(b.get("createTime"))
            if started and created and created < started:
                continue
            bid = b.get("id") or "?"
            status = b.get("status")
            self.summary["cloud_build"] = status
            fail = one_line(((b.get("failureInfo") or {}).get("detail")) or "", 120)
            self.emit(f"build:{bid}", "cloud_build", status, f"build {bid}{('  ' + fail) if fail else ''}")

    # -- terminal reports
    def failure_report(self):
        run = self.run or {}
        print("", file=self.out)
        print("FAILED", file=self.out)
        payload = None
        err = (self.wf or {}).get("error") or {}
        if isinstance(err, dict) and err.get("payload"):
            try:
                payload = json.loads(err["payload"])
            except ValueError:
                payload = {"message": err["payload"]}
        if not isinstance(payload, dict):
            payload = {}
        error_class = payload.get("error_class") or run.get("error_class") or "UNKNOWN"
        stage = payload.get("stage") or run.get("failed_stage") or run.get("current_stage") or "unknown"
        reason = payload.get("reason") or run.get("failure_reason") or ""
        message = payload.get("message") or run.get("error") or ""
        print(f"  error_class : {error_class}", file=self.out)
        print(f"  stage       : {stage}", file=self.out)
        if reason:
            print(f"  reason      : {reason}", file=self.out)
        print(f"  message     : {str(message)[:DETAIL_LIMIT]}", file=self.out)
        qa = self.qa
        if qa is None and run.get("trace_id"):
            qa = self.r.get_doc(f"qa_test_runs/{run['trace_id']}")
        if qa and (stage == "qa" or not qa.get("passed")):
            print("  QA:", file=self.out)
            print(f"    verdict   : passed={qa.get('passed')} error_class={qa.get('error_class')} "
                  f"reason={qa.get('reason')} exit_code={qa.get('exit_code')}", file=self.out)
            print(f"    execution : {qa.get('execution_name')}", file=self.out)
            print(f"    summary   : {str(qa.get('summary') or '')[:DETAIL_LIMIT]}", file=self.out)
            diags = qa.get("diagnostics") if isinstance(qa.get("diagnostics"), list) else []
            for d in diags[:10]:
                if not isinstance(d, dict):
                    continue
                where = str(d.get("file") or "-")
                if d.get("file") and d.get("line") is not None:
                    where += f":{d.get('line')}"
                print(f"    - {d.get('code')}  {where}  {one_line(d.get('message'), 300)}", file=self.out)
                if d.get("detail"):
                    print("      detail: " + str(d["detail"])[:DETAIL_LIMIT].replace("\n", "\n              "),
                          file=self.out)
            if len(diags) > 10:
                print(f"    ... {len(diags) - 10} more diagnostics (qa_test_runs/{run.get('trace_id')})", file=self.out)
        self.summary[str(stage)] = "FAILED"
        # stages the run never reached keep the QUEUED the run record was created with
        for name, status in list(self.summary.items()):
            if status == "QUEUED":
                self.summary[name] = "NOT_REACHED"

    # -- health verdict, per access mode
    def access_mode(self):
        """The exact `workloads/{pid}.access.mode`, or None (no access record, or a value outside the enum)."""
        access = (self.workload or {}).get("access")
        mode = access.get("mode") if isinstance(access, dict) else None
        return mode if mode in ACCESS_MODES else None

    def workload_region(self):
        """(region, source): `workloads/{pid}.region`, or --region for a legacy record that names none (such a
        workload follows the install's default region)."""
        region = (self.workload or {}).get("region")
        if isinstance(region, str) and region.strip():
            return region.strip(), "workload record"
        return self.a.region, "no region on the workload record; --region"

    def allowed_principals(self):
        """`workloads/{pid}.access.invoker_principals` (the people the Control Center lets in), as listed."""
        access = (self.workload or {}).get("access")
        principals = access.get("invoker_principals") if isinstance(access, dict) else None
        return [p for p in principals if isinstance(p, str) and p] if isinstance(principals, list) else []

    def health_url(self):
        return self.service_url.rstrip("/") + HEALTH_PATH

    @staticmethod
    def signs_in_with_google(status, redirect):
        """A 302 whose Location host is exactly Google sign-in (parsed with urllib.parse, not matched as text)."""
        return status == 302 and redirect_host(redirect) == GOOGLE_SIGN_IN_HOST

    def health(self, auth, attempts=3, spacing=10):
        """(health state, exit code). The check the workload's access mode calls for (module docstring)."""
        mode, source = self.access_mode(), "workload record"
        region, region_source = self.workload_region()
        if mode is None and self.a.child_checks:
            child = (self.workload or {}).get("project_id")
            svc = self.r.service_for_url(child, region, self.service_url)[1] if child else None
            if svc is not None and svc.get("iapEnabled") is True:
                mode, source = PRIVATE_IAP, "no access record; the Cloud Run service has iapEnabled"
        if mode is None:
            status, _body, redirect = http_full(self.health_url(), None, timeout=30)
            if self.signs_in_with_google(status, redirect):
                mode = PRIVATE_IAP
                source = f"no access record; an anonymous GET {HEALTH_PATH} was redirected to {GOOGLE_SIGN_IN_HOST}"
        where = f"region {region} ({region_source})"
        self.line("access", f"{mode}  ({source})  {where}" if mode else
                  f"unknown  (no access record, and no IAP in front): probing with your identity token  {where}")
        if mode == PRIVATE_IAP:
            if self.a.child_checks:
                return self.iap_child_checks(region, attempts, spacing)
            return self.iap_not_probed(attempts, spacing)
        if mode == PUBLIC_APP:
            ok = self.probe(lambda: None, attempts, spacing,
                            "a public (PUBLIC_APP) service refused an anonymous request: its Cloud Run invoker "
                            "binding or ingress does not match the access record")
        elif mode == PRIVATE_IAM:
            ok = self.probe(lambda: auth.identity_token(audience=self.service_url.rstrip("/")), attempts, spacing,
                            "the probe identity was refused: a private (IAM invoker) service must list the "
                            "operator's account under who may use it")
        else:
            ok = self.probe(auth.identity_token, attempts, spacing,
                            "the probe identity was refused: a private (IAP / invoker) service must list the "
                            "operator's account under who may use it")
        return (HEALTH_PASS, EXIT_PASS) if ok else (HEALTH_FAIL, EXIT_PROBE)

    def probe(self, token_fn, attempts, spacing, refused):
        """GET <service_url>/health with token_fn() (None = anonymous) until it answers 200, up to `attempts`."""
        url = self.health_url()
        status, body = 0, ""
        for i in range(attempts):
            status, body = http(url, token_fn(), timeout=30)
            self.line("health", f"HTTP {status or 'no answer'}  {url}  {one_line(body, 200)}")
            if status == 200:
                return True
            if i + 1 < attempts:
                time.sleep(spacing)
        if status in (302, 401, 403):
            self.line("health", refused)
        else:
            self.line("health", f"{url} did not answer 200 in {attempts} tries")
        return False

    def iap_not_probed(self, attempts, spacing):
        """PRIVATE_IAP: /health is not probed (NOT_PROBED_IAP_REASON). No token is sent and none is minted; the one
        check is that IAP is in front: an anonymous GET of /health must be redirected to Google sign-in. A 2xx answer
        (the app reached without sign-in) or any other answer is a failure, never a pass."""
        url = self.health_url()
        status = 0
        for i in range(attempts):
            status, _body, redirect = http_full(url, None, timeout=30)
            if self.signs_in_with_google(status, redirect):
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
        project (iap_child_once). (state, exit code): PASS, ERROR (permission denied) or FAIL."""
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
        """(ok, exit code, message). Every read here is a GET, except Logging's entries:list (a read by a POST)."""
        def short(name):
            return str(name or "").rsplit("/", 1)[-1]

        def denied(what, role):
            return False, EXIT_PREREQ, (f"permission denied reading {what} in {child}: the operator needs {role} in "
                                        "the child project")

        child = (self.workload or {}).get("project_id")
        if not child:
            return False, EXIT_PROBE, "the workload record names no child project, so its Cloud Run service is unknown"
        status, svc = self.r.service_for_url(child, region, self.service_url)
        if status in (401, 403):
            return denied("Cloud Run services", "roles/run.viewer")
        if svc is None:
            return False, EXIT_PROBE, (f"no Cloud Run service in {child} ({region}) serves {self.service_url} "
                                       f"(services list: HTTP {status or 'no answer'})")
        service = short(svc.get("name"))
        ready_rev, created_rev = svc.get("latestReadyRevision") or "", svc.get("latestCreatedRevision") or ""
        if not ready_rev:
            return False, EXIT_PROBE, f"service {service} has no ready revision"
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
            return False, EXIT_PROBE, (f"the startup probe of revision {revision} checks {', '.join(paths)}, "
                                       f"not {HEALTH_PATH}")
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
        url = self.service_url.rstrip("/") + HEALTH_PATH
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
        print("", file=self.out)
        print(f"Per-stage summary ({self.a.product_id}, run {(self.run or {}).get('trace_id') or '-'}):", file=self.out)
        order = list(STAGE_ORDER[:10]) + ["qa_job", "release", "cloud_build", "terraform", "terraform_remediation",
                                          "tf_applier", "health"]
        names = [n for n in order if n in self.summary] + sorted(n for n in self.summary if n not in order)
        for n in names:
            print(f"  {n:<22} {self.summary[n]}", file=self.out)
        print(f"RESULT: {verdict}", file=self.out)


def follow(args):
    auth = Auth()
    if not auth.access_token():
        print("No gcloud access token: run `gcloud auth login` first.", file=sys.stderr)
        return EXIT_PREREQ
    reader = Reader(args.project, args.region, auth)
    f = Follower(reader, args)
    poll = max(0.0, float(args.poll_sec))

    first = reader.get_doc(f"workloads/{args.product_id}")
    if reader.denied:
        print("Permission denied reading Firestore in the host project: the operator needs read access to "
              "the platform records (for example roles/datastore.viewer).", file=sys.stderr)
        return EXIT_PREREQ
    if args.require_new and first is not None:
        print(f"Workload '{args.product_id}' already exists: choose a new --product-id, or follow it with "
              f"--watch-only {args.product_id}.", file=sys.stderr)
        return EXIT_USAGE

    if args.await_submit_min:
        f.line("submit", f"waiting up to {args.await_submit_min} min for workload '{args.product_id}' to be submitted")
        deadline = time.time() + float(args.await_submit_min) * 60
        while reader.get_doc(f"workloads/{args.product_id}") is None:
            if time.time() >= deadline:
                f.line("submit", "no workload record appeared")
                f.summary["submit"] = "NOT_SUBMITTED"
                f.print_summary("TIMEOUT (not submitted)")
                return EXIT_TIMEOUT
            time.sleep(poll)
        wl = reader.get_doc(f"workloads/{args.product_id}") or {}
        f.summary["submit"] = "SUBMITTED"
        f.line("submit", f"record created (mode {wl.get('creation_mode')}, code review "
                         f"{'on' if wl.get('require_human_code_review') else 'off'}, plan approval "
                         f"{'on' if wl.get('require_plan_approval') else 'off'})")

    deadline = time.time() + float(args.timeout_min) * 60
    outcome = None
    while True:
        outcome = f.poll()
        if outcome:
            break
        if reader.denied >= 3:
            print("Permission denied reading the platform records (3 reads in a row).", file=sys.stderr)
            f.print_summary("ERROR (permission denied)")
            return EXIT_PREREQ
        if time.time() >= deadline:
            stage = (f.run or {}).get("current_stage") or "not started"
            f.line("timeout", f"after {args.timeout_min} min at stage {stage}")
            f.summary[str(stage).lower()] = "TIMEOUT"
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
               + (f" (unknown: {unknown_reason})" if unknown_reason else ""))
        f.summary["health"] = "NO_SERVICE_URL"
        f.print_summary("FAIL (no service URL)")
        return EXIT_PROBE
    state, code = f.health(auth, spacing=min(10.0, poll))
    f.summary["health"] = state
    if state == HEALTH_PASS:
        f.print_summary("PASS")
    elif state == HEALTH_NOT_PROBED_PRIVATE_IAP:
        # deployed with IAP in front: neither a pass nor an error; /health cannot be probed from the command line
        f.print_summary(f"DEPLOYED, {HEALTH_NOT_PROBED_PRIVATE_IAP} ({NOT_PROBED_IAP_REASON}: {f.health_url()})")
    elif state == HEALTH_ERROR_PERMISSION:
        f.print_summary(HEALTH_ERROR_PERMISSION)
    else:
        f.print_summary("FAIL (health probe)")
    return code


def main(argv=None):
    p = argparse.ArgumentParser(prog="live_canary_follow.py", description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd")
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
            print(f"cannot read {args.example}: {e.strerror}", file=sys.stderr)
            return EXIT_USAGE
        if not text:
            print(f"{args.example} has no 'Workload Form Submission Prompt' block", file=sys.stderr)
            return EXIT_USAGE
        print(text)
        return EXIT_PASS
    if args.cmd == "follow":
        return follow(args)
    p.print_usage(sys.stderr)
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
