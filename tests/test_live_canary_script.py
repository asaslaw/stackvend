"""FD-4DN (release gate RC-LIVE-GATE): scripts/live_canary.sh + scripts/live_canary_follow.py; FD-102 hardening.

Hermetic: stub `gcloud` and `curl` first on PATH (plus `python3` -> this interpreter); nothing can reach GCP. The
stub curl answers from a route table (URL substring -> sequence of (status, body)) and records, per request, the URL
(the argument after `--url`), which token headers came in on stdin (`Authorization`, `X-Serverless-Authorization`),
the raw stdin lines and its own argv, so the tests can prove a token never reaches a command line or the output. With
CURL_HOME/.curlrc saying `location` and argv not starting with `-q`, the stub follows a redirect the way curl would
(it records a request to the second host). The stub gcloud mints an identity token only with `--audiences=` and only
for a service-account login (STUB_ID_MODE=sa; `user` refuses `--audiences` like gcloud does for a user login).

Covers: bash -n; usage errors exit 2 before any gcloud call; no gcloud login exits 5; watch-only of a failed run
(typed workflow error, QA diagnostics with the 2 KB detail cap, signed URLs in the QA job env never printed); a
successful run with tf-applier / Cloud Build lines; submit mode (prints the form values and the example's spec, waits
for the record, refuses an existing id); the follower's timeout (exit 3); the spec extractor; the health verdict per
access mode; --child-checks (PRIVATE_IAP from the revision, the startup probe log and the anonymous 302).
FD-102: record values refused (control characters, non-str, formats, `.`/`..`, a trailing-newline project id) with no
request to the URL and no token minted; the URL parse (https host only); Run-API confirmation (every page, the
managed-folder ancestry, permission denied exit 5, unlisted exit 4); curl flags on every call (`-q` first,
`--max-redirs 0`, `--proto(-redir) =https`, `-g`, the URL after `--url`, stdin = header lines only) and a planted
.curlrc; `print-identity-token` only with `--audiences=`; a user login is HEALTH_NOT_PROBED_PRIVATE_IAM; a token whose
`aud` differs is not sent; the token only in X-Serverless-Authorization, never `Authorization` to a workload; the IAM
gates and ACCESS_RECORD_MISMATCH; HEALTH_NOT_PROBED_NO_ACCESS_RECORD; stripped, one-line printing (a body cannot
forge a RESULT line).
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import base64
import datetime
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
SCRIPT = os.path.join(REPO, "scripts", "live_canary.sh")
FOLLOWER = os.path.join(REPO, "scripts", "live_canary_follow.py")
EXAMPLE_01 = os.path.join(REPO, "documentation", "examples", "01-cloudrun-pubsub-event-router.md")
BASH = "/bin/bash"

PROJ = "host-proj-123"
PID = "canary-wl-01"
TRACE = "intake-canary-wl-01-abc123"
EXEC_ID = "11111111-2222-3333-4444-555555555555"
ACCESS_TOKEN = "stub-access-token-DO-NOT-PRINT"
ID_SIG = "stub-identity-token-DO-NOT-PRINT"              # the signature part of every minted identity token
DEFAULT_ID_TOKEN = "stub-default-identity-token-DO-NOT-PRINT"   # a user's default token (must never be asked for)
SIGNED = "https://signed.example.test/qa-source?X-Goog-Signature=SECRET-SIGNED-VALUE"
SERVICE_URL = "https://canary-svc-424242.us-central1.run.app"
FOLDER = "4242"

GCLOUD_STUB = r'''
import base64, json, os, sys
args = sys.argv[1:]
with open(os.environ["STUB_LOG"], "a") as log:
    log.write("gcloud " + " ".join(args) + "\n")
cmd = " ".join(args)
if cmd.startswith("auth list"):
    if os.environ.get("STUB_ACCOUNT"):
        print(os.environ["STUB_ACCOUNT"])
    sys.exit(0)
if cmd.startswith("auth print-access-token"):
    print("@ACCESS@")
    sys.exit(0)
if cmd.startswith("auth print-identity-token"):
    auds = [a.split("=", 1)[1] for a in args if a.startswith("--audiences=")]
    if not auds:
        print("@DEFAULT@")
        sys.exit(0)
    mode = os.environ.get("STUB_ID_MODE", "user")
    if mode == "user":
        sys.stderr.write("ERROR: (gcloud.auth.print-identity-token) Invalid account type for `--audiences`. "
                         "Requires valid service account.\n")
        sys.exit(1)
    aud = {"sa": auds[0], "wrong-aud": "https://other.example.test", "list-aud": [auds[0]]}[mode]
    claims = base64.urlsafe_b64encode(json.dumps({"aud": aud, "iss": "https://accounts.google.com"}).encode())
    print("eyJhbGciOiJSUzI1NiJ9." + claims.decode().rstrip("=") + ".@SIG@")
    sys.exit(0)
if cmd.startswith("run services describe"):
    print("https://cc.example.test")
    sys.exit(0)
sys.exit(1)
'''.replace("@ACCESS@", ACCESS_TOKEN).replace("@DEFAULT@", DEFAULT_ID_TOKEN).replace("@SIG@", ID_SIG)

CURL_STUB = r'''
import json, os, sys
argv = sys.argv[1:]
cfg = sys.stdin.read()
url = argv[argv.index("--url") + 1] if "--url" in argv else ""
headers = []
for line in cfg.splitlines():
    key, _, val = line.partition("=")
    val = val.strip()
    if val.startswith('"') and val.endswith('"'):
        val = val[1:-1].replace('\\"', '"').replace('\\\\', '\\')
    if key.strip() == "header":
        headers.append(val.split(":", 1)[0])
routes = json.load(open(os.environ["STUB_ROUTES"]))
counts_path = os.environ["STUB_ROUTES"] + ".counts"
counts = json.load(open(counts_path)) if os.path.exists(counts_path) else {}
posted = None
if "--data-binary" in argv:
    posted = json.load(open(argv[argv.index("--data-binary") + 1][1:]))
# curl reads $CURL_HOME/.curlrc unless -q is its first argument; `location` there makes it follow redirects
curlrc = os.path.join(os.environ.get("CURL_HOME", "/nonexistent"), ".curlrc")
follows = argv[:1] != ["-q"] and os.path.exists(curlrc) and "location" in open(curlrc).read().split()


def record(u, followed=False):
    with open(os.environ["STUB_LOG"], "a") as log:
        log.write("curl " + json.dumps({"url": u, "auth": "Authorization" in headers,
                                        "xsa": "X-Serverless-Authorization" in headers, "headers": headers,
                                        "stdin": cfg.splitlines(), "argv": argv, "body": posted,
                                        "followed": followed}) + "\n")


def answer(u):
    status, body, redirect = 404, '{"error": {"code": 404}}', ""
    for i, r in enumerate(routes):
        if r["match"] in u:
            n = counts.get(str(i), 0)
            counts[str(i)] = n + 1
            seq = r["responses"]
            got = seq[min(n, len(seq) - 1)]
            status, body = got[0], got[1]
            redirect = got[2] if len(got) > 2 else ""
            if isinstance(body, dict) and set(body) == {"@file"}:
                body = open(body["@file"], "rb").read()
            elif not isinstance(body, str):
                body = json.dumps(body)
            break
    return status, body, redirect


record(url)
status, body, redirect = answer(url)
if follows and 300 <= status < 400 and redirect:
    record(redirect, followed=True)
    status, body, redirect = answer(redirect)
json.dump(counts, open(counts_path, "w"))
# the follower's -w format: "\n%{redirect_url}\n%{http_code}"
raw = body if isinstance(body, bytes) else body.encode("utf-8")
# curl --max-filesize: the transfer stops at the cap and curl exits 63 (the write-out is still printed)
cap = int(argv[argv.index("--max-filesize") + 1]) if "--max-filesize" in argv else None
too_big = cap is not None and len(raw) > cap
sys.stdout.buffer.write((raw[:cap] if too_big else raw) + ("\n" + redirect + "\n" + str(status)).encode("utf-8"))
sys.exit(63 if too_big else 0)
'''


# ------------------------------------------------------------------------------------------------ fixture helpers
def fs(value):
    """Python value -> Firestore REST typed value."""
    if value is None:
        return {"nullValue": None}
    if isinstance(value, bool):
        return {"booleanValue": value}
    if isinstance(value, int):
        return {"integerValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    if isinstance(value, dict):
        return {"mapValue": {"fields": {k: fs(v) for k, v in value.items()}}}
    if isinstance(value, list):
        return {"arrayValue": {"values": [fs(v) for v in value]}}
    return {"stringValue": str(value)}


def fs_doc(name, fields):
    return {"name": f"projects/{PROJ}/databases/(default)/documents/{name}", "fields": {k: fs(v) for k, v in fields.items()},
            "updateTime": "2026-01-01T00:00:00Z"}


def iso(delta_min=0):
    t = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=delta_min)
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f+00:00")


WORKLOAD = fs_doc(f"workloads/{PID}", {"product_id": PID, "project_id": PID, "status": "PROVISIONING",
                                       "creation_mode": "AGENT", "require_human_code_review": False,
                                       "require_plan_approval": False, "service_url": ""})


def run_doc(status, current_stage, stages, started=None, **extra):
    fields = {"trace_id": TRACE, "product_id": PID, "status": status, "current_stage": current_stage,
              "execution_mode": "FULL", "started_at": started or iso(-30), "workflow_execution_id": EXEC_ID,
              "stages": stages}
    fields.update(extra)
    return [{"document": fs_doc(f"pipeline_executions/{TRACE}", fields)}]


def job_executions(job, env_name, state="SUCCEEDED"):
    ex = {"name": f"projects/{PROJ}/locations/us-central1/jobs/{job}/executions/{job}-zz9",
          "createTime": iso(-10),
          "template": {"containers": [{"env": [
              {"name": "QA_SOURCE_URL", "value": SIGNED},
              {"name": "CALLBACK_URL", "value": SIGNED},
              {"name": env_name, "value": TRACE}]}]}}
    if state == "SUCCEEDED":
        ex.update({"completionTime": iso(-5), "succeededCount": 1})
    elif state == "FAILED":
        ex.update({"completionTime": iso(-5), "failedCount": 1})
    else:
        ex.update({"runningCount": 1})
    other = {"name": f"projects/{PROJ}/locations/us-central1/jobs/{job}/executions/{job}-other",
             "createTime": iso(-1), "runningCount": 1,
             "template": {"containers": [{"env": [{"name": env_name, "value": "some-other-trace"}]}]}}
    return {"executions": [other, ex]}


DONE = {"architect": {"status": "SUCCESS", "summary": "Task DAG decomposed"},
        "developer": {"status": "SUCCESS"}, "gatekeeper": {"status": "SUCCESS"}}


# --- FD-102 confirmation reads: the host's vending service, the child's ancestry, the child's Cloud Run listing
def child_run(region="us-central1"):
    return f"projects/{PID}/locations/{region}/services"


CHILD_RUN = child_run()
SVC = "canary-svc"
SVC_NAME = f"{CHILD_RUN}/{SVC}"
REV = f"{SVC}-00002-abc"
REV_NAME = f"{CHILD_RUN}/{SVC}/revisions/{REV}"
OK_LINE = 'STARTUP HTTP probe succeeded after 1 attempt for container "app-1" on port 8080 path "/health".'
FAIL_LINE = ('STARTUP HTTP probe failed 20 times consecutively for container "app-1" on port 8080 path "/health". '
             'The instance was not started.')
VENDING_READ = f"projects/{PROJ}/locations/us-central1/services/project-repo-vending-service"
ANCESTRY_READ = f"cloudresourcemanager.googleapis.com/v1/projects/{PID}:getAncestry"
IAM_READ = f"{SVC_NAME}:getIamPolicy"
OPERATOR_ONLY = {"bindings": [{"role": "roles/run.invoker", "members": ["user:operator@example.test"]}]}


def cloud_run_service(iap=True, created=None, region="us-central1", **extra):
    run = child_run(region)
    svc = {"name": f"{run}/{SVC}", "uri": "https://canary-svc-hash-uc.a.run.app",
           "urls": [SERVICE_URL + "/"], "iapEnabled": iap, "latestReadyRevision": f"{run}/{SVC}/revisions/{REV}",
           "latestCreatedRevision": created or f"{run}/{SVC}/revisions/{REV}"}
    svc.update(extra)
    return {"services": [
        {"name": f"{run}/other-svc", "uri": "https://other-svc-hash-uc.a.run.app", "iapEnabled": False,
         "latestReadyRevision": f"{run}/other-svc/revisions/other-svc-00001-x"}, svc]}


def ancestry(folder=FOLDER, project=PID):
    return {"ancestor": [{"resourceId": {"type": "project", "id": project}},
                         {"resourceId": {"type": "folder", "id": "777"}},
                         {"resourceId": {"type": "folder", "id": folder}},
                         {"resourceId": {"type": "organization", "id": "1"}}]}


def vending(folder="folders/" + FOLDER):
    env = [{"name": "QA_SOURCE_URL", "value": SIGNED}]
    if folder is not None:
        env.append({"name": "MANAGED_WORKLOADS_FOLDER_ID", "value": folder})
    return {"name": VENDING_READ, "template": {"containers": [{"env": env}]}}


def confirm_routes(region="us-central1", host_region="us-central1", listing=None, anc=None, vend=None, iam=None,
                   listing_seq=None, anc_seq=None):
    """`listing` / `anc`: one answer (repeated); `listing_seq` / `anc_seq`: a sequence of answers (R3 retries)."""
    return [(f"projects/{PROJ}/locations/{host_region}/services/project-repo-vending-service", [vend or [200, vending()]]),
            (ANCESTRY_READ, anc_seq or [anc or [200, ancestry()]]),
            (f"{child_run(region)}?pageSize=100", listing_seq or [listing or [200, cloud_run_service(region=region)]]),
            (":getIamPolicy", [iam or [200, OPERATOR_ONLY]])]


def workload_with_access(mode, region=None, principals=("user:operator@example.test",), **extra):
    fields = {"product_id": PID, "project_id": PID, "status": "ACTIVE", "creation_mode": "AGENT", "service_url": ""}
    if region:
        fields["region"] = region
    if mode:
        fields["access"] = {"mode": mode, "invoker_principals": list(principals), "source": "platform_default"}
    fields.update(extra)
    return fs_doc(f"workloads/{PID}", fields)


def success_routes(health, workload=WORKLOAD, url=SERVICE_URL, region="us-central1", host_region="us-central1",
                   **confirm):
    stages = dict(DONE, qa={"status": "SUCCESS"}, release={"status": "SUCCESS"},
                  terraform={"status": "SUCCESS", "summary": "Apply complete"})
    build = {"builds": [{"id": "old-build", "status": "FAILURE", "createTime": iso(-600)},
                        {"id": "build-new-1", "status": "SUCCESS", "createTime": iso(-8)}]}
    qa = fs_doc(f"qa_test_runs/{TRACE}", {"passed": True, "attempt": 0, "exit_code": 0, "summary": "ok"})
    return ([(f"documents/workloads/{PID}", [[200, workload]]),
             ("documents:runQuery", [[200, run_doc("SUCCEEDED", "COMPLETE", stages, outputs={"service_url": url})]]),
             (f"executions/{EXEC_ID}", [[200, {"state": "SUCCEEDED", "result": json.dumps({"service_url": url})}]]),
             ("jobs/qa-sandbox-test-runner/executions", [[200, job_executions("qa-sandbox-test-runner",
                                                                              "QA_TRACE_ID")]]),
             ("jobs/tf-applier/executions", [[200, job_executions("tf-applier", "TRACE_ID")]]),
             (f"documents/qa_test_runs/{TRACE}", [[200, qa]]),
             (f"projects/{PID}/builds", [[200, build]])]
            + confirm_routes(region=region, host_region=host_region, **confirm)
            + [(SERVICE_URL + "/health", health)])


class _Harness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="live-canary-test-")
        self.stub = os.path.join(self.tmp, "bin")
        os.makedirs(self.stub)
        self.log = os.path.join(self.tmp, "calls.log")
        self.routes_path = os.path.join(self.tmp, "routes.json")
        self.curl_home = os.path.join(self.tmp, "curl-home")
        os.makedirs(self.curl_home)
        self.id_mode = "user"
        open(self.log, "w").close()
        for name, src in (("gcloud", GCLOUD_STUB), ("curl", CURL_STUB)):
            with open(os.path.join(self.stub, name), "w") as fh:
                fh.write(f"#!{sys.executable} -I\n" + src)
            os.chmod(os.path.join(self.stub, name), 0o755)
        os.symlink(sys.executable, os.path.join(self.stub, "python3"))
        self.set_routes([])

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def set_routes(self, routes):
        if os.path.exists(self.routes_path + ".counts"):      # a fresh route table starts every sequence again
            os.unlink(self.routes_path + ".counts")
        with open(self.routes_path, "w") as fh:
            json.dump([{"match": m, "responses": r} for m, r in routes], fh)

    def env(self, account="operator@example.test"):
        extra = {"PATH": f"{self.stub}:/usr/bin:/bin", "STUB_LOG": self.log, "STUB_ROUTES": self.routes_path,
                 "TMPDIR": self.tmp, "LANG": "C", "CURL_HOME": self.curl_home, "STUB_ID_MODE": self.id_mode}
        if account:
            extra["STUB_ACCOUNT"] = account
        return hermetic_guard.child_env(drop=("STUB_ACCOUNT",), extra=extra)

    def run_script(self, *args, account="operator@example.test"):
        return subprocess.run([BASH, SCRIPT] + list(args), cwd=REPO, env=self.env(account),
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)

    def run_follower(self, *args):
        return subprocess.run([sys.executable, "-I", FOLLOWER] + list(args), cwd=REPO, env=self.env(),
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)

    def run_watch(self, *extra):
        return self.run_script("--project", PROJ, "--watch-only", PID, "--poll-sec", "0", *extra)

    def calls(self):
        with open(self.log) as fh:
            return [line.rstrip("\n") for line in fh if line.strip()]

    def curl_calls(self):
        return [json.loads(c[5:]) for c in self.calls() if c.startswith("curl ")]

    def health_calls(self):
        return [c for c in self.curl_calls() if c["url"] == SERVICE_URL + "/health"]

    def workload_calls(self):
        """Every request that did not go to a Google API (i.e. to the workload, or anywhere else)."""
        return [c for c in self.curl_calls() if not c["url"].startswith("https://") or
                not c["url"].split("/")[2].endswith(".googleapis.com")]

    def minted(self):
        return [c for c in self.calls() if c.startswith("gcloud auth print-identity-token")]

    def assert_no_token_leak(self, r):
        for tok in (ACCESS_TOKEN, ID_SIG, DEFAULT_ID_TOKEN):
            self.assertNotIn(tok, r.stdout + r.stderr)
            for c in self.curl_calls():
                self.assertNotIn(tok, " ".join(c["argv"]))
        self.assertNotIn("SECRET-SIGNED", r.stdout + r.stderr)

    def assert_curl_contract(self):
        """FD-102 Do No Harm: the same contract on every curl call."""
        for c in self.curl_calls():
            argv = c["argv"]
            self.assertEqual(argv[0], "-q", argv)
            for pair in (["--max-redirs", "0"], ["--proto", "=https"], ["--proto-redir", "=https"]):
                self.assertIn(pair, [argv[i:i + 2] for i in range(len(argv) - 1)], argv)
            self.assertIn("-g", argv)
            google = c["url"].split("/")[2].endswith(".googleapis.com")
            cap = "16777216" if google else "1048576"   # a Google API answer may be larger than a workload's
            self.assertIn(["--max-filesize", cap], [argv[i:i + 2] for i in range(len(argv) - 1)], argv)
            self.assertEqual(argv[-2:], ["--url", c["url"]])
            self.assertNotIn("-L", argv)
            self.assertNotIn("-X", argv)
            for line in c["stdin"]:
                self.assertTrue(line.startswith("header = "), line)
            if c["auth"]:   # the access token goes to Google APIs only
                self.assertTrue(c["url"].split("/")[2].endswith(".googleapis.com"), c["url"])
        for c in self.workload_calls():
            self.assertFalse(c["auth"], c["url"])   # never `Authorization` to a workload
        for g in self.minted():
            self.assertIn("--audiences=", g)        # never the default identity token

    def assert_read_only(self):
        for c in self.curl_calls():
            if "--data-binary" in c["argv"]:
                self.assertTrue(c["url"].endswith("documents:runQuery") or c["url"].endswith("/v2/entries:list")
                                or c["url"].endswith(":getAncestry"), c["url"])
        self.assertFalse([c for c in self.calls() if c.startswith("gcloud") and "auth " not in c])

    def assert_no_logging_read(self):
        for c in self.curl_calls():
            self.assertNotIn("logging.googleapis.com", c["url"])
            self.assertNotIn("/revisions/", c["url"])

    def result_lines(self, out):
        return [line for line in out.splitlines() if line.startswith("RESULT")]


class TestSyntaxAndUsage(_Harness):
    def test_bash_syntax(self):
        r = subprocess.run([BASH, "-n", SCRIPT], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_follower_compiles_stdlib_only(self):
        src = open(FOLLOWER, encoding="utf-8").read()
        compile(src, FOLLOWER, "exec")
        imports = {line.split()[1].split(".")[0] for line in src.splitlines()
                   if line.startswith("import ") or line.startswith("from ")}
        self.assertLessEqual(imports, {"argparse", "base64", "datetime", "json", "os", "re", "subprocess", "sys",
                                       "tempfile", "time", "urllib"})

    def test_help(self):
        r = self.run_script("--help")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("--watch-only <product_id>", r.stdout)
        self.assertEqual(self.calls(), [])

    def test_usage_errors_exit_2_before_any_cloud_call(self):
        cases = [
            (),                                                   # no --project
            ("--project",),                                       # flag without value
            ("--project", "Bad_Project"),
            ("--project", PROJ, "--region", "central"),
            ("--project", PROJ, "--bogus"),
            ("--project", PROJ, "--timeout-min", "0"),
            ("--project", PROJ, "--timeout-min", "ten"),
            ("--project", PROJ, "--poll-sec", "-1"),
            ("--project", PROJ, "--product-id", "abc"),          # too short for a child project id
            ("--project", PROJ, "--product-id", "9starts-with-digit"),
            ("--project", PROJ, "--trace-id", TRACE),             # trace id only with --watch-only
            ("--project", PROJ, "--watch-only", PID, "--trace-id", "bad trace"),
            ("--project", PROJ, "--watch-only", PID, "--product-id", "another-id"),
            ("--project", PROJ, "--watch-only", "Bad/Id"),
            ("--project", PROJ, "--example", "documentation/examples/no-such-example.md"),
        ]
        for args in cases:
            with self.subTest(args=args):
                r = self.run_script(*args)
                self.assertEqual(r.returncode, 2, (args, r.stdout, r.stderr))
                self.assertIn("Usage:", r.stderr)
        self.assertEqual(self.calls(), [])

    def test_follower_refuses_bad_arguments_itself(self):
        """FD-102: the follower checks its own arguments (fullmatch) when run without the shell."""
        for args in (("--project", PROJ + "\n"), ("--project", PROJ, "--region", "us-central1\n"),
                     ("--project", PROJ, "--trace-id", "..")):
            with self.subTest(args=args):
                pid = ("--product-id", PID)
                r = self.run_follower("follow", *args, *pid, "--timeout-min", "0.001", "--poll-sec", "0")
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertFalse(self.curl_calls())

    def test_no_gcloud_login_exits_5(self):
        r = self.run_script("--project", PROJ, "--watch-only", PID, account="")
        self.assertEqual(r.returncode, 5, r.stderr)
        self.assertIn("gcloud auth login", r.stderr)
        self.assertFalse(self.curl_calls())

    def test_permission_denied_exits_5(self):
        self.set_routes([("documents/workloads/", [[403, {"error": {"code": 403}}]])])
        r = self.run_script("--project", PROJ, "--watch-only", PID, "--poll-sec", "0")
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
        self.assertIn("Permission denied", r.stderr)


class TestWatchOnly(_Harness):
    def failed_routes(self, detail, summary="QA failed: 1 diagnostic(s)"):
        payload = {"tag": "StackVendPipelineError", "error_class": "CODE_DEFECT", "stage": "qa", "reason": "",
                   "message": 'QA failed ("CODE_DEFECT"): "1 diagnostic(s)"', "raw_error": {"body": SIGNED}}
        qa = fs_doc(f"qa_test_runs/{TRACE}", {
            "passed": False, "error_class": "CODE_DEFECT", "reason": None, "attempt": 1, "exit_code": 10,
            "execution_name": "qa-sandbox-test-runner-zz9", "summary": summary,
            "diagnostics": [{"tool": "pytest", "code": "PY.IMPORT_FAILED", "severity": "error",
                             "file": "apps/x/main.py", "line": None, "message": "`import main` failed",
                             "detail": detail}]})
        stages = dict(DONE, qa={"status": "QUEUED"}, terraform={"status": "QUEUED"})
        return [
            (f"documents/workloads/{PID}", [[200, WORKLOAD]]),
            ("documents:runQuery", [[200, run_doc("FAILED", "FAILED", stages, error_class="CODE_DEFECT",
                                                  failed_stage="qa")]]),
            (f"executions/{EXEC_ID}", [[200, {"state": "FAILED", "error": {"payload": json.dumps(payload),
                                                                            "context": SIGNED}}]]),
            ("jobs/qa-sandbox-test-runner/executions", [[200, job_executions("qa-sandbox-test-runner", "QA_TRACE_ID",
                                                                             "FAILED")]]),
            (f"documents/qa_test_runs/{TRACE}", [[200, qa]]),
        ]

    def test_failed_run_reports_typed_error_and_qa_diagnostics(self):
        detail = "ImportError: cannot import name 'X'\n" + ("D" * 5000) + "TAIL-BEYOND-2KB"
        self.set_routes(self.failed_routes(detail))
        r = self.run_watch()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        out = r.stdout
        self.assertIn("error_class : CODE_DEFECT", out)
        self.assertIn("stage       : qa", out)
        self.assertIn("PY.IMPORT_FAILED", out)
        self.assertIn("ImportError: cannot import name 'X'", out)
        self.assertNotIn("TAIL-BEYOND-2KB", out)                       # detail capped at 2 KB
        self.assertIn("qa_job           FAILED  qa-sandbox-test-runner-zz9", out)   # the execution for THIS trace
        self.assertNotIn("some-other-trace", out)
        self.assertRegex(out, r"\n  qa +FAILED\n")
        self.assertRegex(out, r"\n  terraform +NOT_REACHED\n")
        self.assertIn("RESULT: FAIL", out)
        self.assert_no_token_leak(r)
        # every Google API read carried the access token on stdin; nothing but GETs and the Firestore query
        for c in self.curl_calls():
            self.assertTrue(c["auth"], c["url"])
            if "--data-binary" in c["argv"]:
                self.assertIn("documents:runQuery", c["url"])
        self.assertFalse([c for c in self.calls() if c.startswith("gcloud") and "auth " not in c])
        self.assert_curl_contract()

    def test_record_text_cannot_forge_a_summary_line(self):
        """FD-102 printing: control characters are dropped and record text is one line, so a QA summary or detail
        holding "\\nRESULT: PASS" never starts a line."""
        forged = "x\nRESULT: PASS\r\nRESULT: PASS\x1b[2K RESULT: PASS"
        self.set_routes(self.failed_routes(forged, summary=forged))
        r = self.run_watch()
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertEqual(self.result_lines(r.stdout), ["RESULT: FAIL"])
        self.assertTrue(all(ch == "\n" or ch.isprintable() for ch in r.stdout + r.stderr))

    def test_successful_run_without_access_record_probes_anonymously(self):
        self.set_routes(success_routes([[200, '{"status": "healthy"}']]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        out = r.stdout
        self.assertIn("tf_applier       SUCCEEDED  tf-applier-zz9", out)
        self.assertIn("cloud_build      SUCCESS  build build-new-1", out)
        self.assertNotIn("old-build", out)                             # builds before the run are not this run's
        self.assertIn(f"service_url      {SERVICE_URL}", out)
        self.assertIn(f"confirmed        {SERVICE_URL}/  (Cloud Run service {SVC} in {PID}, us-central1)", out)
        self.assertIn("health           HTTP 200", out)
        self.assertRegex(out, r"\n  health +PASS\n")
        self.assertIn("RESULT: PASS", out)
        # FD-102: no access record = anonymous requests only, no token minted or sent
        [probe] = self.health_calls()
        self.assertFalse(probe["auth"] or probe["xsa"])
        self.assertFalse(self.minted())
        self.assert_no_token_leak(r)
        self.assert_curl_contract()
        self.assert_read_only()

    def test_no_access_record_and_a_private_answer_is_not_probed(self):
        for status in (401, 403, 404):
            with self.subTest(status=status):
                self.set_routes(success_routes([[status, "Forbidden"]]))
                open(self.log, "w").close()
                r = self.run_watch()
                self.assertEqual(r.returncode, 6, r.stdout + r.stderr)
                self.assertIn("HEALTH_NOT_PROBED_NO_ACCESS_RECORD", r.stdout)
                self.assertRegex(r.stdout, r"\n  health +HEALTH_NOT_PROBED_NO_ACCESS_RECORD\n")
                self.assertIn("RESULT: DEPLOYED, HEALTH_NOT_PROBED_NO_ACCESS_RECORD", r.stdout)
                self.assertEqual([c["auth"] or c["xsa"] for c in self.health_calls()], [False])
                self.assertFalse(self.minted())
                self.assertFalse([c for c in self.curl_calls() if ":getIamPolicy" in c["url"]])

    def test_no_access_record_any_other_answer_fails_after_three_tries(self):
        self.set_routes(success_routes([[500, "boom"]]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertEqual(len(self.health_calls()), 3)
        self.assertIn("RESULT: FAIL (health probe)", r.stdout)
        self.assertFalse(self.minted())

    def test_operator_wait_is_reported_and_timeout_exits_3(self):
        stages = dict(DONE, release={"status": "PAUSED_FOR_APPROVAL"})
        self.set_routes([
            (f"documents/workloads/{PID}", [[200, WORKLOAD]]),
            ("documents:runQuery", [[200, run_doc("ACTIVE", "AWAITING_PR_APPROVAL", stages)]]),
            (f"executions/{EXEC_ID}", [[200, {"state": "ACTIVE"}]]),
        ])
        r = self.run_follower("follow", "--project", PROJ, "--product-id", PID, "--timeout-min", "0.002",
                              "--poll-sec", "0")
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertEqual(r.stdout.count("WAITING          for the operator:"), 1)   # once, not every poll
        self.assertIn("release pull request review", r.stdout)
        self.assertIn("timeout", r.stdout)
        self.assertIn("RESULT: TIMEOUT", r.stdout)

    def test_trace_id_pins_the_run(self):
        self.set_routes(self.failed_routes("x"))
        r = self.run_follower("follow", "--project", PROJ, "--product-id", PID, "--trace-id", "retry-other-run",
                              "--timeout-min", "0.002", "--poll-sec", "0")
        # the only run on record is another trace: nothing is followed until the timeout (exit 3), never misreported
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertNotIn("CODE_DEFECT", r.stdout)


SIGN_IN = "https://accounts.google.com/o/oauth2/v2/auth?client_id=iap-client.apps.example.test&response_type=code"


def load_follower():
    spec = importlib.util.spec_from_file_location("live_canary_follow_under_test", FOLLOWER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestHealthByAccessMode(_Harness):
    """The /health verdict follows workloads/{pid}.access.mode; the URL is the confirmed one."""

    def routes(self, mode, health, region=None, principals=("user:operator@example.test",), list_region=None,
               **confirm):
        return success_routes(health, workload=workload_with_access(mode, region, principals),
                              region=list_region or region or "us-central1", **confirm)

    # ---------------------------------------------------------------------------------------------- PUBLIC_APP
    def test_public_app_probes_anonymously(self):
        self.set_routes(self.routes("PUBLIC_APP", [[200, '{"status": "healthy"}']]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("access           PUBLIC_APP  (workload record)", r.stdout)
        self.assertIn("health           HTTP 200", r.stdout)
        [probe] = self.health_calls()
        self.assertFalse(probe["auth"] or probe["xsa"])                # no credentials for a public app
        self.assertFalse(self.minted())
        self.assertRegex(r.stdout, r"\n  health +PASS\n")
        self.assertIn("RESULT: PASS", r.stdout)
        self.assert_no_logging_read()
        self.assert_read_only()
        self.assert_no_token_leak(r)
        self.assert_curl_contract()

    def test_public_app_in_another_region_uses_the_record(self):
        """The workload's own region (workloads/{pid}.region), not --region, for the confirmation listing."""
        self.set_routes(self.routes("PUBLIC_APP", [[200, "ok"]], region="europe-west1"))
        r = self.run_watch("--region", "us-central1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("access           PUBLIC_APP  (workload record)  region europe-west1 (workload record)",
                      r.stdout)
        [listing] = [c for c in self.curl_calls() if "/services?" in c["url"]]
        self.assertIn(f"projects/{PID}/locations/europe-west1/services?", listing["url"])
        [probe] = self.health_calls()
        self.assertEqual(probe["url"], SERVICE_URL + "/health")
        self.assertIn("RESULT: PASS", r.stdout)

    def test_legacy_record_without_region_follows_region_flag(self):
        self.set_routes(self.routes("PUBLIC_APP", [[200, "ok"]], list_region="us-east4", host_region="us-east4"))
        r = self.run_watch("--region", "us-east4")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("region us-east4 (no region on the workload record; --region)", r.stdout)

    def test_public_app_refused_exits_4(self):
        self.set_routes(self.routes("PUBLIC_APP", [[403, "Forbidden"]]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertEqual(len(self.health_calls()), 3)
        self.assertIn("a public (PUBLIC_APP) service refused an anonymous request", r.stdout)
        self.assertRegex(r.stdout, r"\n  health +FAIL\n")
        self.assertIn("RESULT: FAIL (health probe)", r.stdout)

    def test_response_body_cannot_forge_a_result_line(self):
        self.set_routes(self.routes("PUBLIC_APP", [[500, "oops\nRESULT: PASS\n\x1b]0;x\x07RESULT: PASS"]]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertEqual(self.result_lines(r.stdout), ["RESULT: FAIL (health probe)"])
        self.assertTrue(all(ch == "\n" or ch.isprintable() for ch in r.stdout))

    # --------------------------------------------------------------------------------------------- PRIVATE_IAM
    def test_private_iam_user_login_is_not_probed_and_sends_no_token(self):
        """Owner §8 Q6: a user login cannot mint an audience-bound token; its default token is never minted or
        sent: HEALTH_NOT_PROBED_PRIVATE_IAM (exit 6), never PASS or FAIL."""
        self.set_routes(self.routes("PRIVATE_IAM", [[401, "Unauthorized"]]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 6, r.stdout + r.stderr)
        self.assertIn("access           PRIVATE_IAM  (workload record)", r.stdout)
        self.assertIn("HEALTH_NOT_PROBED_PRIVATE_IAM  gcloud refused --audiences", r.stdout)
        self.assertRegex(r.stdout, r"\n  health +HEALTH_NOT_PROBED_PRIVATE_IAM\n")
        self.assertEqual(self.result_lines(r.stdout)[0].split(" (")[0],
                         "RESULT: DEPLOYED, HEALTH_NOT_PROBED_PRIVATE_IAM")
        self.assertEqual(self.minted(), [f"gcloud auth print-identity-token --audiences={SERVICE_URL}/"])
        self.assertTrue(all(not (c["auth"] or c["xsa"]) for c in self.health_calls()))
        self.assertEqual(len(self.health_calls()), 1)                  # the one anonymous GET
        self.assert_curl_contract()
        self.assert_no_token_leak(r)

    def test_private_iam_service_account_token_goes_only_in_x_serverless_authorization(self):
        self.id_mode = "sa"
        self.set_routes(self.routes("PRIVATE_IAM", [[401, "Unauthorized"], [200, "ok"]]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        anonymous, probe = self.health_calls()
        self.assertFalse(anonymous["auth"] or anonymous["xsa"])
        self.assertTrue(probe["xsa"])
        self.assertFalse(probe["auth"])                                # never `Authorization` to a workload
        self.assertEqual(probe["headers"], ["X-Serverless-Authorization"])
        self.assertEqual(self.minted(), [f"gcloud auth print-identity-token --audiences={SERVICE_URL}/"])
        [policy] = [c for c in self.curl_calls() if c["url"].endswith(IAM_READ)]
        self.assertTrue(policy["auth"])                                # a Google API read, with the access token
        self.assertIn("RESULT: PASS", r.stdout)
        self.assert_curl_contract()
        self.assert_no_token_leak(r)
        self.assert_read_only()

    def test_private_iam_token_with_another_audience_is_not_sent(self):
        for mode in ("wrong-aud", "list-aud"):
            with self.subTest(mode=mode):
                self.id_mode = mode
                self.set_routes(self.routes("PRIVATE_IAM", [[403, "Forbidden"], [200, "ok"]]))
                open(self.log, "w").close()
                r = self.run_watch()
                self.assertEqual(r.returncode, 6, r.stdout + r.stderr)
                self.assertIn("not bound to the confirmed service URL; it was not sent", r.stdout)
                self.assertEqual(len(self.health_calls()), 1)
                self.assertTrue(all(not (c["auth"] or c["xsa"]) for c in self.health_calls()))

    def test_private_iam_refused_token_probe_exits_4(self):
        self.id_mode = "sa"
        self.set_routes(self.routes("PRIVATE_IAM", [[401, "Unauthorized"]]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertEqual([c["xsa"] for c in self.health_calls()], [False, True, True, True])
        self.assertIn("probe identity was refused: a private (IAM invoker) service", r.stdout)
        self.assertIn("RESULT: FAIL (health probe)", r.stdout)
        self.assert_no_token_leak(r)

    def test_private_iam_answering_anonymously_is_an_access_record_mismatch(self):
        self.id_mode = "sa"
        self.set_routes(self.routes("PRIVATE_IAM", [[200, "ok"]]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn("ACCESS_RECORD_MISMATCH  an anonymous GET", r.stdout)
        self.assertRegex(r.stdout, r"\n  health +ACCESS_RECORD_MISMATCH\n")
        self.assertIn("RESULT: FAIL (ACCESS_RECORD_MISMATCH)", r.stdout)
        self.assertFalse(self.minted())
        self.assertNotIn("RESULT: PASS", r.stdout)

    def test_private_iam_gates_mint_no_token(self):
        """Defence in depth: invoker check off, or a public member in the policy: ACCESS_RECORD_MISMATCH; an
        unreadable policy: a permission error (exit 5). No token is minted in any of them."""
        public = {"bindings": [{"role": "roles/run.invoker", "members": ["user:operator@example.test", "allUsers"]}]}
        authed = {"bindings": [{"role": "roles/run.invoker", "members": ["allAuthenticatedUsers"]}]}
        cases = [
            (dict(listing=[200, cloud_run_service(invokerIamDisabled=True)]), 4, "invoker check off"),
            (dict(iam=[200, public]), 4, "grants allUsers (roles/run.invoker)"),
            (dict(iam=[200, authed]), 4, "grants allAuthenticatedUsers"),
            (dict(iam=[403, {"error": {"code": 403}}]), 5, "the IAM policy of Cloud Run service canary-svc could "
                                                           "not be read (HTTP 403"),
            (dict(iam=[503, "unavailable"]), 5, "could not be read (HTTP 503"),
        ]
        for confirm, code, expect in cases:
            with self.subTest(expect=expect):
                self.id_mode = "sa"
                self.set_routes(self.routes("PRIVATE_IAM", [[401, "Unauthorized"], [200, "ok"]], **confirm))
                open(self.log, "w").close()
                r = self.run_watch()
                self.assertEqual(r.returncode, code, r.stdout + r.stderr)
                self.assertIn(expect, r.stdout)
                self.assertIn("no token was minted", r.stdout)
                self.assertFalse(self.minted())
                self.assertEqual(len(self.health_calls()), 1)
                if code == 4:
                    self.assertIn("RESULT: FAIL (ACCESS_RECORD_MISMATCH)", r.stdout)
                else:
                    self.assertIn("RESULT: ERROR (permission denied)", r.stdout)

    def test_private_iam_other_answers_fail_after_retries(self):
        for answer in ([302, "", "https://login.example.test/sso"], [500, "boom"], [0, ""]):
            with self.subTest(answer=answer[:1]):
                self.id_mode = "sa"
                self.set_routes(self.routes("PRIVATE_IAM", [answer]))
                open(self.log, "w").close()
                r = self.run_watch()
                self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
                self.assertEqual(len(self.health_calls()), 3)
                self.assertFalse(self.minted())
                self.assertIn("RESULT: FAIL (health probe)", r.stdout)

    # --------------------------------------------------------------------------------------------- PRIVATE_IAP
    def test_private_iap_is_reported_not_probed_never_a_pass(self):
        self.set_routes(self.routes("PRIVATE_IAP", [[302, "", SIGN_IN]]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 6, r.stdout + r.stderr)
        out = r.stdout
        self.assertIn("access           PRIVATE_IAP  (workload record)", out)
        self.assertIn("health           HEALTH_NOT_PROBED_PRIVATE_IAP  IAP enforced: an anonymous GET "
                      f"{SERVICE_URL}/health was redirected (302) to accounts.google.com", out)
        self.assertIn("a gcloud user identity token cannot pass Direct IAP", out)
        self.assertIn("open the URL in a browser signed in as an allowed principal", out)
        self.assertRegex(out, r"\n  health +HEALTH_NOT_PROBED_PRIVATE_IAP\n")
        self.assertIn(f"RESULT: DEPLOYED, HEALTH_NOT_PROBED_PRIVATE_IAP (a gcloud user identity token cannot pass "
                      f"Direct IAP", out)
        self.assertIn(f": {SERVICE_URL}/health)\n", out)
        for wrong in ("RESULT: PASS", "RESULT: ERROR", "RESULT: FAIL", "permission denied", "roles/run.viewer"):
            self.assertNotIn(wrong, out)
        self.assertNotIn("iap_browser", out)                           # only with --iap-browser-check
        self.assertNotIn("client_id", out)                             # only the sign-in host is printed
        # the canary never tries to pass IAP: no identity token, the one /health request is anonymous
        self.assertFalse(self.minted())
        [probe] = self.health_calls()
        self.assertFalse(probe["auth"] or probe["xsa"])
        self.assert_no_logging_read()
        self.assert_read_only()
        self.assert_no_token_leak(r)
        self.assert_curl_contract()

    def test_private_iap_browser_check_prints_the_url_to_open(self):
        self.set_routes(self.routes("PRIVATE_IAP", [[302, "", SIGN_IN]],
                                    principals=("user:operator@example.test", "group:team@example.test")))
        r = self.run_watch("--iap-browser-check")
        self.assertEqual(r.returncode, 6, r.stdout + r.stderr)
        self.assertIn(f"iap_browser      open {SERVICE_URL}/health in a browser signed in as an allowed principal "
                      "(user:operator@example.test, group:team@example.test); a healthy service answers 200",
                      r.stdout)
        self.assertRegex(r.stdout, r"\n  health +HEALTH_NOT_PROBED_PRIVATE_IAP\n")   # still not a pass
        self.assertFalse(self.minted())
        self.assertEqual(len(self.health_calls()), 1)

    def test_private_iap_not_enforced_exits_4(self):
        """A PRIVATE_IAP workload whose service answers an anonymous request with 200 is a failure, never a pass."""
        self.set_routes(self.routes("PRIVATE_IAP", [[200, '{"status": "healthy"}']]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertEqual(r.stdout.count("IAP check ("), 3)               # three tries, like the direct probe
        self.assertIn("IAP is not enforced: an anonymous GET", r.stdout)
        self.assertIn("answered HTTP 200; a PRIVATE_IAP service must redirect it", r.stdout)
        self.assertNotIn("HEALTH_NOT_PROBED", r.stdout)
        self.assertRegex(r.stdout, r"\n  health +FAIL\n")
        self.assertIn("RESULT: FAIL (health probe)", r.stdout)

    def test_private_iap_unexpected_answer_exits_4(self):
        cases = [([401, "Invalid IAP credentials"], "answered HTTP 401"),
                 ([302, "", "https://login.example.test/sso"], "answered HTTP 302 to login.example.test"),
                 ([302, "", "https://accounts.google.com.example.test/x"],
                  "answered HTTP 302 to accounts.google.com.example.test"),
                 ([302, "", "https://[x"], "answered HTTP 302\n")]       # malformed Location: typed FAIL, no traceback
        for answer, expect in cases:
            with self.subTest(answer=answer[:1] + answer[2:]):
                self.set_routes(self.routes("PRIVATE_IAP", [answer]))
                open(self.log, "w").close()
                r = self.run_watch()
                self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
                self.assertIn("IAP not proven", r.stdout)
                self.assertIn(expect, r.stdout)
                self.assertNotIn("HEALTH_NOT_PROBED", r.stdout)
                self.assertFalse(self.minted())

    def test_a_redirect_from_a_service_without_iap_is_an_access_record_mismatch(self):
        """A1 (owner-approved): a 302 to accounts.google.com proves IAP only when the confirmed Cloud Run service has
        iapEnabled true; a public service (or one whose field is missing) faking the redirect is
        ACCESS_RECORD_MISMATCH (exit 4), never "IAP enforced" and never a pass, with or without --child-checks."""
        no_field = cloud_run_service()
        del no_field["services"][1]["iapEnabled"]
        for mode in ("PRIVATE_IAP", None):
            for listing in ([200, cloud_run_service(iap=False)], [200, no_field],
                            [200, cloud_run_service(iap="true")]):
                for flags in ((), ("--child-checks",)):
                    with self.subTest(mode=mode, iap=listing[1]["services"][1].get("iapEnabled", "missing"),
                                      flags=flags):
                        self.set_routes([(f"/revisions/{REV}", [[200, revision()]]),
                                         ("logging.googleapis.com", [[200, log_entries(OK_LINE)]])]
                                        + self.routes(mode, [[302, "", SIGN_IN]], listing=listing))
                        open(self.log, "w").close()
                        r = self.run_watch(*flags)
                        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
                        self.assertIn("ACCESS_RECORD_MISMATCH", r.stdout)
                        self.assertIn("does not have iapEnabled true", r.stdout)
                        self.assertNotIn("IAP enforced", r.stdout)
                        self.assertNotIn("HEALTH_NOT_PROBED", r.stdout)
                        self.assertIn("RESULT: FAIL (ACCESS_RECORD_MISMATCH)", r.stdout)
                        self.assertFalse(self.minted())
                        self.assertFalse([c for c in self.curl_calls() if "/revisions/" in c["url"]
                                          or "logging.googleapis.com" in c["url"]])

    def test_iap_found_from_an_anonymous_redirect_without_an_access_record(self):
        self.set_routes(self.routes(None, [[302, "", SIGN_IN]]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 6, r.stdout + r.stderr)
        self.assertIn("access           PRIVATE_IAP  (no access record; an anonymous GET /health was redirected to "
                      "accounts.google.com)", r.stdout)
        self.assertIn("RESULT: DEPLOYED, HEALTH_NOT_PROBED_PRIVATE_IAP", r.stdout)
        self.assertFalse(self.minted())
        self.assertTrue(all(not (c["auth"] or c["xsa"]) for c in self.health_calls()))
        self.assert_no_logging_read()

    # ------------------------------------------------------------------------------- answers the canary prints
    def test_invalid_utf8_body_reaches_the_result_line(self):
        """A2: a /health body that is not UTF-8 is decoded with errors="replace"; the run ends with its RESULT."""
        bad = os.path.join(self.tmp, "bad-utf8.txt")
        with open(bad, "wb") as fh:
            fh.write(b"\xff\xfe\xc3(broken\x80")
        self.set_routes(self.routes("PUBLIC_APP", [[500, {"@file": bad}]]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertNotIn("Traceback", r.stdout + r.stderr)
        self.assertNotIn("internal error", r.stderr)
        self.assertEqual(self.result_lines(r.stdout), ["RESULT: FAIL (health probe)"])
        for answer in ([200, {"@file": bad}],):   # and a passing one with such a body still passes
            self.set_routes(self.routes("PUBLIC_APP", [answer]))
            r = self.run_watch()
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_oversized_body_is_capped(self):
        """A3: curl gets --max-filesize 1 MiB, and the body is cut to 1 MiB before decoding; 200 characters print."""
        big = os.path.join(self.tmp, "big.txt")
        with open(big, "wb") as fh:
            fh.write(b"A" * (3 * 1024 * 1024))
        self.set_routes(self.routes("PUBLIC_APP", [[200, {"@file": big}]]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        [line] = [ln for ln in r.stdout.splitlines() if "health           HTTP 200" in ln]
        self.assertIn("'" + "A" * 200 + "'", line)
        self.assertNotIn("A" * 201, line)
        self.assert_curl_contract()

    def test_body_echo_is_ascii_and_quoted(self):
        """A4: printable blanks (U+2800 / U+3164 / U+115F) and padding cannot draw a fake RESULT line."""
        spoof = ("\u2800" * 150) + "RESULT: PASS" + ("\u3164\u115f" * 40) + "\x1b[1A"
        self.set_routes(self.routes("PUBLIC_APP", [[503, spoof]]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertTrue(all(ord(ch) < 128 for ch in r.stdout), "non-ASCII from the body reached the output")
        self.assertEqual(self.result_lines(r.stdout), ["RESULT: FAIL (health probe)"])
        [first] = [ln for ln in r.stdout.splitlines() if "health           HTTP 503" in ln][:1]
        self.assertIn("'\\u2800", first)                                # escaped, inside quotes

    def test_record_stage_names_cannot_fill_canary_rows(self):
        """A5a: a record stage named like a canary row (health, qa_job, tf_applier, cloud_build, submit, ...) is
        shown as stage:<name>; the canary's own rows stay its own."""
        stages = dict(DONE, terraform={"status": "SUCCESS"},
                      **{name: {"status": "PASS", "summary": "spoof"}
                         for name in ("health", "qa_job", "tf_applier", "cloud_build", "submit", "confirmed")})
        wl = workload_with_access("PUBLIC_APP")
        routes = success_routes([[503, "down"]], workload=wl)
        routes[1] = ("documents:runQuery", [[200, run_doc("SUCCEEDED", "COMPLETE", stages,
                                                          outputs={"service_url": SERVICE_URL})]])
        self.set_routes(routes)
        r = self.run_watch()
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertRegex(r.stdout, r"\n  health +FAIL\n")
        self.assertNotRegex(r.stdout, r"\n  health +PASS\n")
        for name in ("health", "qa_job", "tf_applier", "cloud_build", "submit", "confirmed"):
            self.assertRegex(r.stdout, rf"\n  stage:{name} +PASS\n")
        self.assertNotIn("  confirmed        PASS", r.stdout)
        self.assertIn("stage:health     PASS  spoof", r.stdout)

    # --------------------------------------------------------------------------------------------- curl contract
    def test_planted_curlrc_cannot_make_a_request_reach_a_second_host(self):
        """S2: a ~/.curlrc (CURL_HOME) with `location` would make curl follow a redirect and resend the headers;
        `-q` first means it is never read."""
        with open(os.path.join(self.curl_home, ".curlrc"), "w") as fh:
            fh.write("location\n")
        self.id_mode = "sa"
        self.set_routes(self.routes("PRIVATE_IAM", [[401, "Unauthorized"],
                                                    [302, "", "https://second-host.example.test/steal"]]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertFalse([c for c in self.curl_calls() if c["followed"]])
        self.assertFalse([c for c in self.curl_calls() if "second-host" in c["url"]])
        self.assert_curl_contract()
        # negative control: the stub does follow when -q is missing, so the assertion above can fail
        stub = os.path.join(self.stub, "curl")
        ctl = subprocess.run([sys.executable, "-I", stub, "-sS", "--url", SERVICE_URL + "/health"],
                             input='header = "X-Serverless-Authorization: Bearer t"\n',
                             env=hermetic_guard.child_env(drop=("STUB_ACCOUNT",), extra={
                                 k: v for k, v in self.env().items()
                                 if k in ("PATH", "STUB_LOG", "STUB_ROUTES", "TMPDIR", "LANG", "CURL_HOME",
                                          "STUB_ID_MODE", "STUB_ACCOUNT")}),
                             capture_output=True, text=True, timeout=60)
        self.assertEqual(ctl.returncode, 0, ctl.stderr)
        self.assertTrue([c for c in self.curl_calls() if c["followed"] and "second-host" in c["url"]])


class TestRecordValuesRefused(_Harness):
    """FD-102: a record value that is not a printable str, not in its exact format, or a URL that is not exactly
    https://<host>, stops the canary typed: no request reaches the URL and no identity token is minted."""

    def assert_nothing_sent(self, r, host="canary-svc"):
        self.assertFalse([c for c in self.workload_calls()], r.stdout)
        self.assertFalse([c for c in self.curl_calls() if host in c["url"]])
        self.assertFalse(self.minted())
        self.assertTrue(all(ch == "\n" or ch.isprintable() for ch in r.stdout + r.stderr))
        self.assertNotIn("RESULT: PASS", r.stdout)
        self.assertNotIn("Traceback", r.stdout + r.stderr)

    def run_url(self, url, mode="PRIVATE_IAM"):
        self.id_mode = "sa"
        self.set_routes(success_routes([[200, "ok"]], workload=workload_with_access(mode), url=url))
        open(self.log, "w").close()
        return self.run_watch()

    def test_control_characters_in_the_url_are_refused(self):
        for ch in ("\n", "\r", "\t", "\x1b", "\x00", "\x7f", "\u0085", " "):
            for url in (SERVICE_URL + ch, SERVICE_URL[:8] + ch + SERVICE_URL[8:]):
                with self.subTest(url=repr(url)):
                    r = self.run_url(url)
                    self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
                    self.assertIn("RECORD_VALUE_REFUSED: service_url is not a string of printable characters",
                                  r.stdout)
                    self.assertIn("RESULT: ERROR (RECORD_VALUE_REFUSED)", r.stdout)
                    self.assert_nothing_sent(r)

    def test_non_string_urls_are_refused(self):
        """Records written before FD-102 can hold the raw Terraform output map."""
        for url in ({"value": SERVICE_URL, "type": "string", "sensitive": False}, [SERVICE_URL], 7):
            with self.subTest(url=url):
                r = self.run_url(url)
                self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
                self.assertIn("RECORD_VALUE_REFUSED", r.stdout)
                self.assert_nothing_sent(r)

    def test_urls_that_are_not_exactly_an_https_host_are_refused(self):
        for url in ("http://canary-svc-424242.us-central1.run.app", "https://user@canary-svc-424242.us-central1.run.app",
                    "https://user:pw@canary-svc-424242.us-central1.run.app", "https://canary-svc-424242.us-central1.run.app:8443",
                    "https://canary-svc-424242.us-central1.run.app:", "https://canary-svc-424242.us-central1.run.app/x",
                    "https://canary-svc-424242.us-central1.run.app//", "https://canary-svc-424242.us-central1.run.app?a=1",
                    "https://canary-svc-424242.us-central1.run.app?", "https://canary-svc-424242.us-central1.run.app#f",
                    "https://canary-svc-424242.us-central1.run.app/#", "https://CANARY-SVC-424242.us-central1.run.app", "https://",
                    "https:canary-svc-424242.us-central1.run.app", "//canary-svc-424242.us-central1.run.app", "https://[::1",
                    "file:///etc/passwd", "-K/etc/passwd", "{}", "[]",
                    # R4: the host must be lowercase LDH labels under run.app
                    "https://canary-svc.example.test", "https://a b.run.app", "https://a%2fb.run.app",
                    "https://\uff41.run.app", "https://.", "https://.run.app", "https://a..run.app",
                    "https://-a.run.app", "https://a-.run.app", "https://run.app", "https://a.run.app.",
                    "https://a_b.run.app", "https://a.run.app.evil.test", "https://evil.test/.run.app"):
            with self.subTest(url=url):
                r = self.run_url(url)
                self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
                self.assertIn("SERVICE_URL_REFUSED", r.stdout)
                self.assertIn("RESULT: FAIL (SERVICE_URL_REFUSED)", r.stdout)
                self.assert_nothing_sent(r)
                self.assertFalse([c for c in self.curl_calls() if "/services?" in c["url"]])   # not even listed

    def test_record_ids_and_names_are_refused(self):
        stages = dict(DONE, terraform={"status": "SUCCESS"})
        cases = [
            ("trace_id", dict(trace_id=".."), "pipeline_executions trace_id does not have the expected format"),
            ("trace_id", dict(trace_id="."), "trace_id does not have the expected format"),
            ("trace_id", dict(trace_id="a/b"), "trace_id does not have the expected format"),
            ("workflow_execution_id", dict(workflow_execution_id="../../x"), "workflow_execution_id does not have"),
            ("workflow_execution_id", dict(workflow_execution_id={"x": 1}), "workflow_execution_id is not a string"),
        ]
        for name, extra, expect in cases:
            with self.subTest(field=name, value=list(extra.values())[0]):
                doc = run_doc("SUCCEEDED", "COMPLETE", stages, outputs={"service_url": SERVICE_URL})
                doc[0]["document"]["fields"].update({k: fs(v) for k, v in extra.items()})
                self.set_routes([(f"documents/workloads/{PID}", [[200, workload_with_access("PUBLIC_APP")]]),
                                 ("documents:runQuery", [[200, doc]])] + confirm_routes()
                                + [(SERVICE_URL + "/health", [[200, "ok"]])])
                open(self.log, "w").close()
                r = self.run_watch()
                self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
                self.assertIn("RECORD_VALUE_REFUSED: ", r.stdout)
                self.assertIn(expect, r.stdout)
                self.assert_nothing_sent(r)
                for c in self.curl_calls():
                    self.assertNotIn("..", c["url"])
                    self.assertNotIn("qa_test_runs/.", c["url"])

    def test_child_project_and_region_are_refused(self):
        for extra, expect in ((dict(project_id=PID + "\n"), "workloads.project_id is not a string"),
                              (dict(project_id="Child_Proj"), "workloads.project_id does not have"),
                              (dict(project_id={"id": PID}), "workloads.project_id is not a string"),
                              (dict(region="us-central1\n"), "workloads.region is not a string"),
                              (dict(region="us-central1/../x"), "workloads.region does not have")):
            with self.subTest(extra=extra):
                wl = workload_with_access("PUBLIC_APP", **extra)
                self.set_routes(success_routes([[200, "ok"]], workload=wl))
                open(self.log, "w").close()
                r = self.run_watch()
                self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
                self.assertIn(expect, r.stdout)
                self.assert_nothing_sent(r)


class TestConfirmation(_Harness):
    """FD-102: the URL is confirmed against the complete Cloud Run listing of a child project inside the install's
    managed-workloads folder before anything is sent to it."""

    def run_public(self, **confirm):
        self.set_routes(success_routes([[200, "ok"]], workload=workload_with_access("PUBLIC_APP"), **confirm))
        open(self.log, "w").close()
        return self.run_watch()

    def assert_not_probed(self, r):
        self.assertFalse(self.health_calls())
        self.assertFalse(self.minted())
        self.assertNotIn("RESULT: PASS", r.stdout)

    def test_unlisted_url_is_not_confirmed(self):
        listing = {"services": [{"name": SVC_NAME, "uri": "https://canary-svc-hash-uc.a.run.app",
                                 "urls": ["https://canary-svc-424242.us-central1.run.app.evil.test"]}]}
        r = self.run_public(listing=[200, listing])
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn(f"SERVICE_URL_NOT_CONFIRMED: no Cloud Run service in {PID} (us-central1) serves the recorded "
                      "service URL", r.stdout)
        self.assertIn("RESULT: FAIL (SERVICE_URL_NOT_CONFIRMED)", r.stdout)
        self.assert_not_probed(r)

    def test_every_page_is_read(self):
        page1 = {"services": [{"name": f"{CHILD_RUN}/a", "uri": "https://a.example.test"}], "nextPageToken": "p/2"}
        page2 = cloud_run_service()
        routes = [("pageToken=p%2F2", [[200, page2]])] + success_routes(   # page 2 first (its URL holds page 1's)
            [[200, "ok"]], workload=workload_with_access("PUBLIC_APP"), listing=[200, page1])
        self.set_routes(routes)
        r = self.run_watch()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        pages = [c["url"] for c in self.curl_calls() if "/services?" in c["url"]]
        self.assertEqual(len(pages), 2)
        self.assertTrue(pages[1].endswith("&pageToken=p%2F2"))
        # unlisted on both pages: not confirmed
        routes[0] = ("pageToken=p%2F2", [[200, {"services": [{"name": f"{CHILD_RUN}/b", "uri": "https://b.test"}]}]])
        self.set_routes(routes)
        open(self.log, "w").close()
        r = self.run_watch()
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assert_not_probed(r)

    def test_listing_permission_denied_exits_5(self):
        for status in (401, 403):
            with self.subTest(status=status):
                r = self.run_public(listing=[status, {"error": {"code": status}}])
                self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
                self.assertIn("permission denied (the canary needs read access to the child project)", r.stdout)
                self.assertIn("RESULT: ERROR (permission denied)", r.stdout)
                self.assert_not_probed(r)

    def test_listing_unavailable_is_its_own_class(self):
        """R3: no answer, 429 or a 5xx is read three times; any other 4xx (or an unreadable 200) is reported at once;
        either way CLOUD_RUN_API_UNAVAILABLE with the HTTP code (exit 5, not the exit 4 of "listed completely, no
        match")."""
        for answer, tries, code in (([503, "unavailable"], 3, "503"), ([0, ""], 3, "no answer"),
                                    ([429, "slow down"], 3, "429"), ([404, {"error": {"code": 404}}], 1, "404"),
                                    ([400, "bad"], 1, "400"), ([200, "not json"], 1, "200")):
            with self.subTest(answer=answer[:1]):
                r = self.run_public(listing=answer)
                self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
                self.assertIn("CLOUD_RUN_API_UNAVAILABLE: the Cloud Run services of", r.stdout)
                self.assertIn(f"could not be listed completely (HTTP {code})", r.stdout)
                self.assertIn("RESULT: ERROR (CLOUD_RUN_API_UNAVAILABLE)", r.stdout)
                self.assertEqual(len([c for c in self.curl_calls() if "/services?" in c["url"]]), tries)
                self.assert_not_probed(r)

    def test_google_api_answer_too_large_is_typed(self):
        """(1) A Google API answer over 16 MiB stops curl (exit 63): API_ANSWER_TOO_LARGE (exit 5), never parsed as
        an empty answer."""
        big = os.path.join(self.tmp, "big-listing.json")
        with open(big, "wb") as fh:
            fh.write(b'{"services": [' + b" " * (16 * 1024 * 1024) + b"]}")
        r = self.run_public(listing=[200, {"@file": big}])
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
        self.assertIn("API_ANSWER_TOO_LARGE: run.googleapis.com answered more than 16777216 bytes", r.stdout)
        self.assertIn("RESULT: ERROR (API_ANSWER_TOO_LARGE)", r.stdout)
        self.assertNotIn("SERVICE_URL_NOT_CONFIRMED", r.stdout)
        self.assert_not_probed(r)

    def test_listing_longer_than_the_page_bound_is_unavailable(self):
        endless = {"services": [], "nextPageToken": "again"}
        r = self.run_public(listing=[200, endless])
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
        self.assertIn("CLOUD_RUN_API_UNAVAILABLE", r.stdout)
        self.assertEqual(len([c for c in self.curl_calls() if "/services?" in c["url"]]), 20)   # not retried
        self.assert_not_probed(r)

    def test_transient_listing_and_ancestry_failures_are_retried(self):
        r = self.run_public(listing_seq=[[503, "x"], [0, ""], [200, cloud_run_service()]],
                            anc_seq=[[500, "x"], [200, ancestry()]])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(len([c for c in self.curl_calls() if "/services?" in c["url"]]), 3)
        self.assertEqual(len([c for c in self.curl_calls() if c["url"].endswith(":getAncestry")]), 2)
        self.assertIn("RESULT: PASS", r.stdout)

    def test_ancestry_unavailable_is_its_own_class(self):
        for anc, tries, code in (([500, "x"], 3, "500"), ([0, ""], 3, "no answer"), ([429, "x"], 3, "429"),
                                 ([404, {}], 1, "404"), ([200, {"ancestor": "x"}], 1, "200")):
            with self.subTest(anc=anc[:1]):
                r = self.run_public(anc=anc)
                self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
                self.assertIn(f"ANCESTRY_UNAVAILABLE: the ancestry of {PID} could not be read (HTTP {code})", r.stdout)
                self.assertIn("RESULT: ERROR (ANCESTRY_UNAVAILABLE)", r.stdout)
                self.assertEqual(len([c for c in self.curl_calls() if c["url"].endswith(":getAncestry")]), tries)
                self.assertFalse([c for c in self.curl_calls() if "/services?" in c["url"]])
                self.assert_not_probed(r)

    def test_child_outside_the_managed_folder_is_not_confirmed_and_not_listed(self):
        for anc, expect in (([200, ancestry(folder="9999")], "is not inside the install's managed-workloads folder"),
                            ([200, ancestry(project="attacker-proj")], "is not inside"),
                            ([200, {"ancestor": []}], "is not inside")):
            with self.subTest(expect=expect):
                r = self.run_public(anc=anc)
                self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
                self.assertIn(expect, r.stdout)
                self.assertFalse([c for c in self.curl_calls() if "/services?" in c["url"]])
                self.assert_not_probed(r)

    def test_ancestry_permission_denied_exits_5(self):
        r = self.run_public(anc=[403, {"error": {"code": 403}}])
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
        self.assertIn("permission denied (the canary needs read access to the child project)", r.stdout)
        self.assert_not_probed(r)

    def test_managed_folder_unknown_or_unreadable_exits_5(self):
        for vend, expect in (([200, vending(folder=None)], "MANAGED_FOLDER_UNKNOWN"),
                             ([200, vending(folder="organizations/1")], "MANAGED_FOLDER_UNKNOWN"),
                             ([200, vending(folder="folders/12/../3")], "MANAGED_FOLDER_UNKNOWN"),
                             ([404, {}], "MANAGED_FOLDER_UNKNOWN"),
                             ([403, {}], "permission denied reading Cloud Run service project-repo-vending-service")):
            with self.subTest(expect=expect, vend=vend[1]):
                r = self.run_public(vend=vend)
                self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
                self.assertIn(expect, r.stdout)
                self.assertNotIn("SECRET-SIGNED", r.stdout)                 # no other env value is printed
                self.assertFalse([c for c in self.curl_calls() if c["url"].endswith(":getAncestry")])
                self.assert_not_probed(r)

    def test_ancestry_is_a_read_of_the_childs_own_project(self):
        r = self.run_public()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        [anc] = [c for c in self.curl_calls() if c["url"].endswith(":getAncestry")]
        self.assertEqual(anc["url"], f"https://{ANCESTRY_READ}")
        self.assertEqual(anc["body"], {})
        [vend] = [c for c in self.curl_calls() if "project-repo-vending-service" in c["url"]]
        self.assertEqual(vend["url"], f"https://run.googleapis.com/v2/{VENDING_READ}")

    def test_the_api_string_is_used_after_confirmation(self):
        """The record's URL without the trailing '/' matches the listed `urls` entry with it; the probe uses the
        API's string (one trailing '/' removed before /health)."""
        r = self.run_public()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn(f"confirmed        {SERVICE_URL}/  (Cloud Run service {SVC}", r.stdout)
        self.assertEqual([c["url"] for c in self.health_calls()], [SERVICE_URL + "/health"])


class TestChildChecksOptIn(_Harness):
    """--child-checks (default off): the PRIVATE_IAP check from the confirmed service's revision + startup probe log +
    the anonymous 302, for operators with roles/run.viewer + roles/logging.viewer in the child."""

    def routes(self, anonymous, service=None, rev=None, logs=None, mode="PRIVATE_IAP", region=None,
               list_region="us-central1"):
        return ([(f"/revisions/{REV}", [rev or [200, revision()]]),
                 ("logging.googleapis.com/v2/entries:list", [logs or [200, log_entries(FAIL_LINE, OK_LINE)]])]
                + success_routes(anonymous, workload=workload_with_access(mode, region), region=list_region,
                                 listing=service))

    def run_watch(self, *extra, child_checks=True):
        flags = ("--child-checks",) if child_checks else ()
        return self.run_script("--project", PROJ, "--watch-only", PID, "--poll-sec", "0", *flags, *extra)

    def child_calls(self):
        return [c for c in self.curl_calls() if "/revisions/" in c["url"] or "logging.googleapis.com" in c["url"]]

    # ------------------------------------------------------------------------------------------------- flag off
    def test_flag_off_reads_no_revision_or_log_even_when_it_would_pass(self):
        self.set_routes(self.routes([[302, "", SIGN_IN]]))
        r = self.run_watch(child_checks=False)
        self.assertEqual(r.returncode, 6, r.stdout + r.stderr)
        self.assertIn("RESULT: DEPLOYED, HEALTH_NOT_PROBED_PRIVATE_IAP", r.stdout)
        self.assertFalse(self.child_calls())
        self.assertNotIn("startup probe", r.stdout)

    def test_flag_passes_through_both_modes(self):
        """Submit mode and watch-only both hand --child-checks to the follower."""
        self.set_routes(self.routes([[302, "", SIGN_IN]]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(self.child_calls())
        stages = dict(DONE, qa={"status": "SUCCESS"}, terraform={"status": "SUCCESS"})
        self.set_routes([
            (f"documents/workloads/{PID}", [[404, {}], [200, workload_with_access("PRIVATE_IAP")]]),
            ("documents:runQuery", [[200, run_doc("SUCCEEDED", "COMPLETE", stages, started=iso(+5),
                                                  outputs={"service_url": SERVICE_URL})]]),
            (f"executions/{EXEC_ID}", [[200, {"state": "SUCCEEDED"}]]),
            (f"/revisions/{REV}", [[403, {"error": {"code": 403}}]]),
        ] + confirm_routes() + [(SERVICE_URL + "/health", [[302, "", SIGN_IN]])])
        open(self.log, "w").close()
        r = self.run_script("--project", PROJ, "--product-id", PID, "--poll-sec", "0", "--child-checks")
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)          # the revision read happened, and was refused
        self.assertTrue(self.child_calls())
        self.assertIn("RESULT: ERROR (permission denied)", r.stdout)

    # -------------------------------------------------------------------------------------------------- flag on
    def test_success_uses_startup_probe_and_anonymous_302(self):
        self.set_routes(self.routes([[302, "", SIGN_IN]]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        out = r.stdout
        self.assertIn("access           PRIVATE_IAP  (workload record)", out)
        self.assertIn("health           (startup probe) 200, IAP enforced (302)", out)
        self.assertIn(f"revision {REV} of {SVC}", out)
        self.assertRegex(out, r"\n  health +PASS\n")
        self.assertIn("RESULT: PASS", out)
        self.assertNotIn("HEALTH_NOT_PROBED", out)
        self.assertNotIn("client_id", out)
        self.assertFalse(self.minted())
        [probe] = self.health_calls()
        self.assertFalse(probe["auth"] or probe["xsa"])
        [logs] = [c for c in self.curl_calls() if c["url"].endswith("/v2/entries:list")]
        self.assertTrue(logs["auth"])
        self.assertEqual(logs["body"]["resourceNames"], [f"projects/{PID}"])
        flt = logs["body"]["filter"]
        for part in ('resource.type="cloud_run_revision"', f'resource.labels.service_name="{SVC}"',
                     f'resource.labels.revision_name="{REV}"',
                     f'logName="projects/{PID}/logs/run.googleapis.com%2Fvarlog%2Fsystem"',
                     'textPayload:"STARTUP HTTP probe"', "timestamp>="):
            self.assertIn(part, flt)
        self.assert_read_only()
        self.assert_no_token_leak(r)
        self.assert_curl_contract()

    def test_service_is_listed_in_the_workloads_region(self):
        self.set_routes(self.routes([[302, "", SIGN_IN]], region="europe-west1", list_region="europe-west1"))
        r = self.run_watch("--region", "us-central1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        [listing] = [c for c in self.curl_calls() if "/services?" in c["url"]]
        self.assertIn(f"projects/{PID}/locations/europe-west1/services?", listing["url"])
        self.assertIn("RESULT: PASS", r.stdout)

    def test_listing_permission_denied_is_the_typed_error_not_a_pass(self):
        self.set_routes(self.routes([[302, "", SIGN_IN]], service=[403, {"error": {"code": 403}}]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
        self.assertIn("permission denied (the canary needs read access to the child project)", r.stdout)
        self.assertRegex(r.stdout, r"\n  health +ERROR \(permission denied\)\n")
        self.assertIn("RESULT: ERROR (permission denied)", r.stdout)
        self.assertNotIn("RESULT: PASS", r.stdout)
        self.assertNotIn("HEALTH_NOT_PROBED", r.stdout)
        self.assertFalse(self.health_calls())

    def test_revision_permission_denied_exits_5(self):
        self.set_routes(self.routes([[302, "", SIGN_IN]], rev=[403, {"error": {"code": 403}}]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
        self.assertIn(f"permission denied reading Cloud Run revisions in {PID}: the operator needs roles/run.viewer",
                      r.stdout)
        self.assertEqual(r.stdout.count("not verified ("), 1)          # no retries on a missing permission
        self.assertIn("RESULT: ERROR (permission denied)", r.stdout)

    def test_log_permission_denied_exits_5(self):
        self.set_routes(self.routes([[302, "", SIGN_IN]], logs=[403, {"error": {"code": 403}}]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
        self.assertIn("permission denied reading Cloud Logging", r.stdout)
        self.assertIn("roles/logging.viewer", r.stdout)
        self.assertIn("RESULT: ERROR (permission denied)", r.stdout)

    def test_startup_probe_failure_exits_4(self):
        self.set_routes(self.routes([[302, "", SIGN_IN]], logs=[200, log_entries(FAIL_LINE)]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn(f"the /health startup probe of revision {REV} failed: STARTUP HTTP probe failed 20 times",
                      r.stdout)
        self.assertEqual(r.stdout.count("not verified ("), 3)
        self.assertRegex(r.stdout, r"\n  health +FAIL\n")
        self.assertIn("RESULT: FAIL (health probe)", r.stdout)

    def test_no_startup_probe_line_exits_4(self):
        self.set_routes(self.routes([[302, "", SIGN_IN]], logs=[200, {}]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn(f"line for revision {REV} in Cloud Logging", r.stdout)

    def test_iap_not_enforced_or_not_proven_exits_4(self):
        cases = [([200, '{"status": "healthy"}'], "IAP is not enforced: an anonymous GET"),
                 ([401, "Invalid IAP credentials"], "IAP not proven"),
                 ([302, "", "https://login.example.test/sso"], "answered HTTP 302 to login.example.test")]
        for answer, expect in cases:
            with self.subTest(answer=answer[:1]):
                self.set_routes(self.routes([answer]))
                r = self.run_watch()
                self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
                self.assertIn(expect, r.stdout)

    def test_revision_not_ready_exits_4(self):
        self.set_routes(self.routes([[302, "", SIGN_IN]], rev=[200, revision(ready="CONDITION_FAILED")]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn(f"revision {REV} is not Ready (Ready condition CONDITION_FAILED): Container failed", r.stdout)
        self.assertFalse(self.health_calls())

    def test_newest_revision_not_ready_exits_4(self):
        newer = f"{CHILD_RUN}/{SVC}/revisions/{SVC}-00003-new"
        self.set_routes(self.routes([[302, "", SIGN_IN]], service=[200, cloud_run_service(created=newer)]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn(f"the newest revision {SVC}-00003-new of service {SVC} is not ready", r.stdout)

    def test_revision_name_outside_its_format_is_never_read(self):
        bad = f"{CHILD_RUN}/{SVC}/revisions/../../../../x"
        self.set_routes(self.routes([[302, "", SIGN_IN]],
                                    service=[200, cloud_run_service(latestReadyRevision=bad, latestCreatedRevision=bad)]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn("names its ready revision in an unexpected format", r.stdout)
        self.assertFalse(self.child_calls())

    def test_service_name_outside_its_format_never_reaches_the_log_filter(self):
        """R6: the confirmed service's name must fullmatch its resource format before it goes into the filter."""
        listing = cloud_run_service()
        listing["services"][1]["name"] = f'{CHILD_RUN}/canary-svc" OR logName:"x'
        self.set_routes(self.routes([[302, "", SIGN_IN]], service=[200, listing]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn("names itself in an unexpected format", r.stdout)
        self.assertFalse(self.child_calls())

    def test_startup_probe_on_another_path_exits_4(self):
        for path, expect in (("/healthz", "checks /healthz, not /health"), (None, "has no HTTP startup probe")):
            with self.subTest(path=path):
                self.set_routes(self.routes([[302, "", SIGN_IN]], rev=[200, revision(path=path)]))
                r = self.run_watch()
                self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
                self.assertIn(expect, r.stdout)

    def test_iap_found_from_the_service_without_an_access_record(self):
        self.set_routes(self.routes([[302, "", SIGN_IN]], mode=None))
        r = self.run_watch()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("access           PRIVATE_IAP  (no access record; the Cloud Run service has iapEnabled)",
                      r.stdout)
        self.assertIn("IAP enforced (302)", r.stdout)
        self.assertFalse(self.minted())

    def test_no_access_record_and_no_iap_probes_anonymously(self):
        self.set_routes(self.routes([[200, "ok"]], service=[200, cloud_run_service(iap=False)], mode=None))
        r = self.run_watch()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("access           unknown", r.stdout)
        self.assertTrue(all(not (c["auth"] or c["xsa"]) for c in self.health_calls()))
        self.assertFalse(self.minted())


def revision(ready="CONDITION_SUCCEEDED", path="/health"):
    probe = {"httpGet": {"path": path, "port": 8080}} if path else {"tcpSocket": {"port": 8080}}
    return {"name": REV_NAME, "createTime": iso(-12),
            "conditions": [{"type": "ContainerHealthy", "state": "CONDITION_SUCCEEDED"},
                           {"type": "Ready", "state": ready, "message": "Container failed to become healthy."
                            if ready != "CONDITION_SUCCEEDED" else ""}],
            "containers": [{"image": "example.test/app", "startupProbe": probe}]}


def log_entries(*texts):
    return {"entries": [{"textPayload": t, "timestamp": iso(-11),
                         "resource": {"type": "cloud_run_revision", "labels": {"service_name": SVC,
                                                                               "revision_name": REV}}}
                        for t in texts]}


class TestHealthDecisionLogic(unittest.TestCase):
    """The follower's decision helpers, in process (no subprocess, no network)."""

    @classmethod
    def setUpClass(cls):
        cls.m = load_follower()

    def follower(self, workload, region="us-central1", iap_browser_check=False):
        args = types.SimpleNamespace(region=region, since="", iap_browser_check=iap_browser_check, product_id=PID)
        f = self.m.Follower(reader=None, args=args, out=io.StringIO())
        f.workload = workload
        return f

    def test_sign_in_redirect_is_parsed_by_host(self):
        yes = self.m.Follower.signs_in_with_google
        self.assertTrue(yes(302, SIGN_IN))
        self.assertTrue(yes(302, "https://accounts.google.com"))
        for status, loc in ((301, SIGN_IN), (200, SIGN_IN), (302, ""), (302, "https://accounts.google.com.evil.test/"),
                            (302, "https://evil.test/?next=https://accounts.google.com/"),
                            (302, "https://login.example.test/accounts.google.com"), (302, "https://[x")):
            with self.subTest(status=status, loc=loc):
                self.assertFalse(yes(status, loc))

    def test_redirect_host_tolerates_a_malformed_location(self):
        self.assertEqual(self.m.redirect_host(SIGN_IN), "accounts.google.com")
        for loc in ("", None, "https://[x", "http://[::1"):
            with self.subTest(loc=loc):
                self.assertIsNone(self.m.redirect_host(loc))

    def test_workload_region_prefers_the_record(self):
        self.assertEqual(self.follower({"region": "asia-south1"}).workload_region(), ("asia-south1", "workload record"))
        for wl in ({}, {"region": ""}, {"region": "  "}, {"region": None}, None):
            with self.subTest(workload=wl):
                region, source = self.follower(wl, region="us-east4").workload_region()
                self.assertEqual(region, "us-east4")
                self.assertIn("--region", source)
        for bad in ("asia-south1\n", "asia/south1", 7, {"r": 1}):     # FD-102: refused, never used
            with self.subTest(region=bad):
                with self.assertRaises(self.m.Refused) as ctx:
                    self.follower({"region": bad}).workload_region()
                self.assertEqual((ctx.exception.error_class, ctx.exception.exit_code),
                                 (self.m.RECORD_VALUE_REFUSED, self.m.EXIT_PREREQ))

    def test_access_mode_is_the_exact_enum(self):
        for mode in ("PUBLIC_APP", "PRIVATE_IAM", "PRIVATE_IAP"):
            self.assertEqual(self.follower({"access": {"mode": mode}}).access_mode(), mode)
        for wl in ({}, {"access": None}, {"access": {"mode": "private_iap"}}, {"access": {"mode": "IAP"}},
                   {"access": "PRIVATE_IAP"}):
            with self.subTest(workload=wl):
                self.assertIsNone(self.follower(wl).access_mode())

    def test_allowed_principals(self):
        f = self.follower({"access": {"invoker_principals": ["user:a@example.test", "", 7, "group:b@example.test"]}})
        self.assertEqual(f.allowed_principals(), ["user:a@example.test", "group:b@example.test"])
        self.assertEqual(self.follower({"access": {"invoker_principals": "user:a@example.test"}}).allowed_principals(),
                         [])
        self.assertEqual(self.follower({}).allowed_principals(), [])

    def test_states_and_exit_codes(self):
        m = self.m
        self.assertEqual(m.HEALTH_NOT_PROBED_PRIVATE_IAP, "HEALTH_NOT_PROBED_PRIVATE_IAP")
        self.assertNotIn(m.EXIT_NOT_PROBED, (m.EXIT_PASS, m.EXIT_FAILED, m.EXIT_USAGE, m.EXIT_TIMEOUT, m.EXIT_PROBE,
                                             m.EXIT_PREREQ))
        for state in (m.HEALTH_NOT_PROBED_PRIVATE_IAP, m.HEALTH_NOT_PROBED_PRIVATE_IAM,
                      m.HEALTH_NOT_PROBED_NO_ACCESS_RECORD, m.ACCESS_RECORD_MISMATCH):
            self.assertNotEqual(state, m.HEALTH_PASS)

    def test_iap_health_never_mints_or_sends_a_token(self):
        """iap_not_probed takes no auth at all: the only request is the anonymous GET (http_full with token None)."""
        calls = []

        def fake_http_full(url, token=None, body=None, timeout=30, token_header=None):
            calls.append((url, token, body))
            return 302, "", SIGN_IN

        f = self.follower({"access": {"mode": "PRIVATE_IAP"}})
        f.service_url = SERVICE_URL + "/"
        f.service = {"name": SVC_NAME, "iapEnabled": True}
        orig = self.m.http_full
        self.m.http_full = fake_http_full
        try:
            state, code = f.iap_not_probed(attempts=3, spacing=0)
        finally:
            self.m.http_full = orig
        self.assertEqual((state, code), (self.m.HEALTH_NOT_PROBED_PRIVATE_IAP, self.m.EXIT_NOT_PROBED))
        self.assertEqual(calls, [(SERVICE_URL + "/health", None, None)])

    # ------------------------------------------------------------------------------------- FD-102 pure helpers
    def test_checked_service_url(self):
        m = self.m
        for ok in (SERVICE_URL, SERVICE_URL + "/", "https://x-1.a.run.app"):
            self.assertEqual(m.checked_service_url(ok), ok)
        for bad, cls in ((SERVICE_URL + "\n", m.RECORD_VALUE_REFUSED), ({}, m.RECORD_VALUE_REFUSED),
                         (None, m.RECORD_VALUE_REFUSED), ("", m.RECORD_VALUE_REFUSED),
                         ("http://x.test", m.SERVICE_URL_REFUSED), ("https://u@x.test", m.SERVICE_URL_REFUSED),
                         ("https://x.test:1", m.SERVICE_URL_REFUSED), ("https://x.test?", m.SERVICE_URL_REFUSED),
                         ("https://x.test/#", m.SERVICE_URL_REFUSED), ("https://[x", m.SERVICE_URL_REFUSED)):
            with self.subTest(url=bad):
                with self.assertRaises(m.Refused) as ctx:
                    m.checked_service_url(bad)
                self.assertEqual(ctx.exception.error_class, cls)

    def test_matching_service_returns_the_api_string(self):
        m = self.m
        svcs = [{"name": "a", "uri": "https://a.test"}, {"name": "b", "uri": "https://b.test", "urls": ["https://c.test/"]}]
        self.assertEqual(m.matching_service("https://a.test/", svcs), (svcs[0], "https://a.test"))
        self.assertEqual(m.matching_service("https://c.test", svcs), (svcs[1], "https://c.test/"))
        for url in ("https://a.test//", "https://A.test", "https://d.test", "https://a.tes"):
            self.assertEqual(m.matching_service(url, svcs), (None, None))
        self.assertEqual(m.matching_service("https://e.test", [{"uri": "https://e.test\n"}, "x", {"urls": "y"}]),
                         (None, None))

    def test_record_value_formats(self):
        m = self.m
        self.assertEqual(m.record_value("t", TRACE, m.ID_RE), TRACE)
        for bad in (".", "..", "a/b", "a\n", TRACE + "\n", "", None, 3, ["x"]):
            with self.subTest(value=bad):
                with self.assertRaises(m.Refused):
                    m.record_value("t", bad, m.ID_RE)
        with self.assertRaises(m.Refused):
            m.record_value("p", PID + "\n", m.PROJECT_RE)   # fullmatch: `$` would have accepted the newline

    def test_jwt_audience(self):
        m = self.m

        def jwt(claims):
            return "h." + base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=") + ".s"
        self.assertEqual(m.jwt_audience(jwt({"aud": SERVICE_URL})), SERVICE_URL)
        for tok in (jwt({"aud": [SERVICE_URL]}), jwt({}), jwt([1]), "a.b", "a.!!.c", "a.b.c.d", "", "h.e30.s"):
            with self.subTest(tok=tok):
                self.assertIsNone(m.jwt_audience(tok))

    def test_tokens_that_cannot_travel_safely_are_refused(self):
        m = self.m
        self.assertTrue(m.usable_token("ya29.abc-_DEF"))
        for tok in ("a b", "a\tb", 'a"b', "a'b", "a\\b", "a\nb", "a\x00b", "", None):
            with self.subTest(tok=tok):
                self.assertFalse(m.usable_token(tok))

    def test_folder_id(self):
        m = self.m
        self.assertEqual(m.folder_id("folders/4242"), "4242")
        self.assertEqual(m.folder_id("4242"), "4242")
        for bad in ("folders/x", "organizations/1", "folders/1/2", "", None, "folders/", " 1 2"):
            self.assertIsNone(m.folder_id(bad))

    def test_public_members_in_any_role(self):
        m = self.m
        self.assertEqual(m.public_members_in(OPERATOR_ONLY), [])
        policy = {"bindings": [{"role": "roles/custom.invoke", "members": ["allAuthenticatedUsers"]}, "junk"]}
        self.assertEqual(m.public_members_in(policy), ["allAuthenticatedUsers (roles/custom.invoke)"])

    def test_writer_strips_and_flattens(self):
        m = self.m
        self.assertEqual(m.clean("a\x1b[2Kb\r\nc d\x00"), "a[2Kb\ncd")
        self.assertEqual(m.flat("x\nRESULT: PASS"), "x RESULT: PASS")
        self.assertEqual(m.one_line("a\n\x85b  c"), "a b c")
        out = io.StringIO()
        f = self.follower({})
        f.out = out
        f.line("health", "body\nRESULT: PASS\x07")
        self.assertEqual(out.getvalue().count("\n"), 1)
        self.assertNotIn("\x07", out.getvalue())

    def test_service_url_host_grammar(self):
        """R4: only lowercase LDH labels under run.app."""
        m = self.m
        for ok in ("https://a.run.app", "https://shop-k3j2h1-uc.a.run.app/", "https://shop-424242.us-central1.run.app"):
            self.assertEqual(m.checked_service_url(ok), ok)
        for bad in ("https://x.test", "https://a b.run.app", "https://a%2fb.run.app", "https://\uff41.run.app",
                    "https://.", "https://a..run.app", "https://-a.run.app", "https://run.app", "https://a.run.app.",
                    "https://a_b.run.app", "https://" + "a" * 64 + ".run.app"):
            with self.subTest(url=bad):
                with self.assertRaises(m.Refused) as ctx:
                    m.checked_service_url(bad)
                self.assertEqual(ctx.exception.error_class, m.SERVICE_URL_REFUSED)

    def test_access_token_goes_only_to_google_api_hosts(self):
        """R5: http_full refuses an `Authorization` header to any host but the script's googleapis.com bases (no
        curl is started); the workload header is unaffected."""
        started = []
        orig = self.m.subprocess.run

        def fake_run(argv, **kw):
            started.append((argv[-1], kw.get("input")))
            return types.SimpleNamespace(stdout=b"{}\n\n200", returncode=0)
        self.m.subprocess.run = fake_run
        try:
            for url in ("https://evil.test/x", SERVICE_URL + "/health", "http://run.googleapis.com/v2/x",
                        "https://run.googleapis.com.evil.test/v2", "https://evil.test/run.googleapis.com", "https://[x",
                        "https://u@run.googleapis.com/v2/x", "https://u:p@run.googleapis.com/v2/x",
                        "https://run.googleapis.com:8443/v2/x", "https://run.googleapis.com:x/v2/x"):
                with self.subTest(url=url):
                    self.assertEqual(self.m.http_full(url, "tok", token_header=self.m.AUTH_HEADER), (0, "", ""))
            self.assertEqual(started, [])
            for base in ("https://run.googleapis.com:443/v2/x", "https://firestore.googleapis.com/v1/x",
                         "https://cloudresourcemanager.googleapis.com/v1/projects/p:getAncestry"):
                self.assertEqual(self.m.http_full(base, "tok")[0], 200)
            self.assertEqual(self.m.http_full(SERVICE_URL + "/health", "tok",
                                              token_header=self.m.WORKLOAD_TOKEN_HEADER)[0], 200)
        finally:
            self.m.subprocess.run = orig
        self.assertEqual(len(started), 4)
        self.assertIn(b"X-Serverless-Authorization", started[-1][1])

    def test_answer_caps_per_destination(self):
        """(1) curl exit 63 on a Google API read is the typed API_ANSWER_TOO_LARGE; on a workload the status still
        counts and the body is cut to 1 MiB."""
        m = self.m
        self.assertEqual(m.answer_cap("https://run.googleapis.com/v2/x"), 16 * 1024 * 1024)
        self.assertEqual(m.answer_cap(SERVICE_URL + "/health"), 1024 * 1024)
        self.assertIn(str(16 * 1024 * 1024), m.curl_argv("https://firestore.googleapis.com/v1/x", 30))
        orig = m.subprocess.run
        m.subprocess.run = lambda argv, **kw: types.SimpleNamespace(stdout=b"C" * 10 + b"\n\n200", returncode=63)
        try:
            with self.assertRaises(m.Refused) as ctx:
                m.http_full("https://run.googleapis.com/v2/x", "tok")
            self.assertEqual((ctx.exception.error_class, ctx.exception.exit_code),
                             (m.API_ANSWER_TOO_LARGE, m.EXIT_PREREQ))
            self.assertEqual(m.http_full(SERVICE_URL + "/health"), (200, "C" * 10, ""))
        finally:
            m.subprocess.run = orig

    def test_uppercase_host_has_its_own_reason(self):
        """(4) urlsplit lowercases the host; the refusal names the uppercase letters, not userinfo or a port."""
        for url in ("https://Shop-1.a.run.app", "https://SHOP-1.A.RUN.APP/"):
            with self.subTest(url=url):
                with self.assertRaises(self.m.Refused) as ctx:
                    self.m.checked_service_url(url)
                self.assertIn("uppercase", ctx.exception.message)
        with self.assertRaises(self.m.Refused) as ctx:
            self.m.checked_service_url("https://u@shop-1.a.run.app")
        self.assertIn("userinfo", ctx.exception.message)

    def test_decode_answer_never_raises(self):
        """A2/A3: bytes in, (status, text, redirect) out; invalid UTF-8 is replaced and the body is capped."""
        m = self.m
        self.assertEqual(m.decode_answer(b"\xff\xfeok\n\n503"), (503, "\ufffd\ufffdok", ""))
        status, text, _ = m.decode_answer(b"B" * (m.MAX_BODY_BYTES + 10) + b"\nhttps://r\n200")
        self.assertEqual((status, len(text)), (200, m.MAX_BODY_BYTES))
        self.assertEqual(m.decode_answer(b"garbage"), (0, "", ""))

    def test_stage_rows(self):
        m = self.m
        self.assertEqual(m.stage_row("health"), "stage:health")
        self.assertEqual(m.stage_row("terraform"), "terraform")
        self.assertEqual(m.body_echo("a\u2800\nb"), "'a\\u2800\\nb'")

    def test_curl_argv_contract(self):
        argv = self.m.curl_argv("https://x.test/health", 30)
        self.assertEqual(argv[:2], ["curl", "-q"])
        self.assertEqual(argv[-2:], ["--url", "https://x.test/health"])
        for flag in ("-g", "--max-redirs", "--proto", "--proto-redir", "--config", "--max-filesize"):
            self.assertIn(flag, argv)


class TestSubmitMode(_Harness):
    def test_prints_form_values_waits_for_record_then_follows(self):
        stages = dict(DONE, qa={"status": "SUCCESS"}, terraform={"status": "SUCCESS"})
        self.set_routes([
            # 1st read (pre-check) and 2nd read (first wait poll): not submitted yet; then the record exists
            (f"documents/workloads/{PID}", [[404, {"error": {"code": 404}}], [404, {"error": {"code": 404}}],
                                            [200, WORKLOAD]]),
            ("documents:runQuery", [[200, run_doc("SUCCEEDED", "COMPLETE", stages, started=iso(+5),
                                                  outputs={"service_url": SERVICE_URL})]]),
            (f"executions/{EXEC_ID}", [[200, {"state": "SUCCEEDED"}]]),
        ] + confirm_routes() + [(SERVICE_URL + "/health", [[200, "ok"]])])
        r = self.run_script("--project", PROJ, "--product-id", PID, "--poll-sec", "0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        out = r.stdout
        self.assertIn("https://cc.example.test", out)
        self.assertIn(f"Workload Identifier (Slug): {PID}", out)
        self.assertIn("Require Human Code Review (HITL)", out)
        self.assertIn("POST /api/v1/events", out)                     # the example's spec text
        self.assertNotIn("Workload Form Submission Prompt (Copy", out)
        self.assertIn("record created (mode AGENT, code review off, plan approval off)", out)
        self.assertIn("RESULT: PASS", out)
        gcloud_cmds = [c for c in self.calls() if c.startswith("gcloud")]
        self.assertIn(f"gcloud run services describe product-control-center-ui --project={PROJ} "
                      f"--region=us-central1 --format=value(status.url)", gcloud_cmds)
        # read-only: the only non-GET requests are the Firestore query and the ancestry read
        for c in self.curl_calls():
            if "--data-binary" in c["argv"]:
                self.assertTrue(c["url"].endswith("documents:runQuery") or c["url"].endswith(":getAncestry"))
            self.assertNotIn("pubsub", c["url"])
            self.assertNotIn("/api/workloads", c["url"])
        self.assert_no_token_leak(r)
        self.assert_curl_contract()

    def test_existing_product_id_is_refused(self):
        self.set_routes([(f"documents/workloads/{PID}", [[200, WORKLOAD]])])
        r = self.run_script("--project", PROJ, "--product-id", PID, "--poll-sec", "0")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("already exists", r.stderr)
        self.assertIn(f"--watch-only {PID}", r.stderr)

    def test_runs_before_the_submission_are_ignored(self):
        """A product id reused within the window: a run that started before the canary began is never followed."""
        self.set_routes([
            (f"documents/workloads/{PID}", [[404, {}], [200, WORKLOAD]]),
            ("documents:runQuery", [[200, run_doc("FAILED", "FAILED", DONE, started=iso(-120))]]),
        ])
        r = self.run_follower("follow", "--project", PROJ, "--product-id", PID, "--timeout-min", "0.002",
                              "--poll-sec", "0", "--await-submit-min", "1", "--require-new", "--since", iso(-1))
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertNotIn(TRACE, r.stdout)
        self.assertIn("record created", r.stdout)


class TestSpecExtraction(_Harness):
    def test_example_01_prompt(self):
        r = self.run_follower("spec", EXAMPLE_01)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.startswith("Please deploy a lightweight, serverless webhook"))
        self.assertIn("100% pytest test coverage.", r.stdout)
        self.assertNotIn("> ", r.stdout)
        self.assertNotIn("## 2.", r.stdout)

    def test_file_without_prompt_is_a_usage_error(self):
        path = os.path.join(self.tmp, "plain.md")
        with open(path, "w") as fh:
            fh.write("# Title\n\nNo prompt here.\n")
        r = self.run_follower("spec", path)
        self.assertEqual(r.returncode, 2)
        self.assertIn("no 'Workload Form Submission Prompt' block", r.stderr)


if __name__ == "__main__":
    unittest.main()
