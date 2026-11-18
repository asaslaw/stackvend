"""FD-4DN (release gate RC-LIVE-GATE): scripts/live_canary.sh + scripts/live_canary_follow.py.

Hermetic: stub `gcloud` and `curl` first on PATH (plus `python3` -> this interpreter); nothing can reach GCP. The
stub curl answers from a route table (URL substring -> sequence of (status, body)) and records, per request, the URL
and whether an Authorization header came in on stdin, plus its own argv, so the tests can prove a token never
reaches a command line or the output.

Covers: bash -n; usage errors exit 2 before any gcloud call; no gcloud login exits 5; watch-only of a failed run
(typed workflow error, QA diagnostics with the 2 KB detail cap, signed URLs in the QA job env never printed); a
successful run with tf-applier / Cloud Build lines and a /health pass (exit 0) or refusal (exit 4); submit mode
(prints the form values and the example's spec, waits for the record, refuses an existing id); the follower's
timeout (exit 3); the spec extractor. FD-4DN follow-up: the health verdict per access mode (PUBLIC_APP anonymous,
PRIVATE_IAM identity token for the service URL). Private IAP follow-up: the service URL and region come from the
platform records (no child-project Cloud Run or Logging read, so no run.viewer there); a PRIVATE_IAP workload is
reported HEALTH_NOT_PROBED_PRIVATE_IAP (exit 6, RESULT "DEPLOYED, ...") after an anonymous 302 to Google sign-in,
never a pass; IAP not enforced / not proven exit 4; --iap-browser-check prints the URL to open; IAP found from the
anonymous redirect with no access record; in-process tests of the decision helpers. --child-checks (opt-in,
default off) restores the PRIVATE_IAP check from the revision's Ready condition + startup probe log + the
anonymous 302 (PASS), in the workload's region; a missing child-project permission is ERROR (permission
denied), exit 5.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import datetime
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
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
ID_TOKEN = "stub-identity-token-DO-NOT-PRINT"
SIGNED = "https://signed.example.test/qa-source?X-Goog-Signature=SECRET-SIGNED-VALUE"
SERVICE_URL = "https://canary-svc.example.test"

GCLOUD_STUB = textwrap.dedent("""\
    #!/bin/bash
    echo "gcloud $*" >> "$STUB_LOG"
    case "$*" in
      "auth list"*) [ -n "${STUB_ACCOUNT:-}" ] && echo "$STUB_ACCOUNT"; exit 0 ;;
      "auth print-access-token"*) echo "%s"; exit 0 ;;
      "auth print-identity-token"*) echo "%s"; exit 0 ;;
      "run services describe"*) echo "https://cc.example.test"; exit 0 ;;
    esac
    exit 1
    """) % (ACCESS_TOKEN, ID_TOKEN)

CURL_STUB = textwrap.dedent("""\
    import json, os, sys
    argv = sys.argv[1:]
    cfg = sys.stdin.read()
    url, auth = "", False
    for line in cfg.splitlines():
        key, _, val = line.partition("=")
        val = val.strip()
        if val.startswith('"') and val.endswith('"'):
            val = val[1:-1].replace('\\\\"', '"').replace('\\\\\\\\', '\\\\')
        if key.strip() == "url":
            url = val
        elif key.strip() == "header" and val.startswith("Authorization: Bearer "):
            auth = True
    routes = json.load(open(os.environ["STUB_ROUTES"]))
    counts_path = os.environ["STUB_ROUTES"] + ".counts"
    counts = json.load(open(counts_path)) if os.path.exists(counts_path) else {}
    posted = None
    if "--data-binary" in argv:
        posted = json.load(open(argv[argv.index("--data-binary") + 1][1:]))
    with open(os.environ["STUB_LOG"], "a") as log:
        log.write("curl " + json.dumps({"url": url, "auth": auth, "argv": argv, "body": posted}) + "\\n")
    status, body, redirect = 404, '{"error": {"code": 404}}', ""
    for i, r in enumerate(routes):
        if r["match"] in url:
            n = counts.get(str(i), 0)
            counts[str(i)] = n + 1
            seq = r["responses"]
            answer = seq[min(n, len(seq) - 1)]
            status, body = answer[0], answer[1]
            redirect = answer[2] if len(answer) > 2 else ""
            if not isinstance(body, str):
                body = json.dumps(body)
            break
    json.dump(counts, open(counts_path, "w"))
    # the follower's -w format: "\\n%{redirect_url}\\n%{http_code}"
    sys.stdout.write(body + "\\n" + redirect + "\\n" + str(status))
    """)


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


class _Harness(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="live-canary-test-")
        self.stub = os.path.join(self.tmp, "bin")
        os.makedirs(self.stub)
        self.log = os.path.join(self.tmp, "calls.log")
        self.routes_path = os.path.join(self.tmp, "routes.json")
        open(self.log, "w").close()
        with open(os.path.join(self.stub, "gcloud"), "w") as fh:
            fh.write(GCLOUD_STUB)
        with open(os.path.join(self.stub, "curl"), "w") as fh:
            fh.write(f"#!{sys.executable} -I\n" + CURL_STUB)
        for name in ("gcloud", "curl"):
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
                 "TMPDIR": self.tmp, "LANG": "C"}
        if account:
            extra["STUB_ACCOUNT"] = account
        return hermetic_guard.child_env(drop=("STUB_ACCOUNT",), extra=extra)

    def run_script(self, *args, account="operator@example.test"):
        return subprocess.run([BASH, SCRIPT] + list(args), cwd=REPO, env=self.env(account),
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)

    def run_follower(self, *args):
        return subprocess.run([sys.executable, "-I", FOLLOWER] + list(args), cwd=REPO, env=self.env(),
                              stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)

    def calls(self):
        with open(self.log) as fh:
            return [line.rstrip("\n") for line in fh if line.strip()]

    def curl_calls(self):
        return [json.loads(c[5:]) for c in self.calls() if c.startswith("curl ")]

    def assert_no_token_leak(self, r):
        for tok in (ACCESS_TOKEN, ID_TOKEN):
            self.assertNotIn(tok, r.stdout + r.stderr)
            for c in self.curl_calls():
                self.assertNotIn(tok, " ".join(c["argv"]))
        self.assertNotIn("SECRET-SIGNED", r.stdout + r.stderr)


class TestSyntaxAndUsage(_Harness):
    def test_bash_syntax(self):
        r = subprocess.run([BASH, "-n", SCRIPT], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_follower_compiles_stdlib_only(self):
        src = open(FOLLOWER, encoding="utf-8").read()
        compile(src, FOLLOWER, "exec")
        imports = {line.split()[1].split(".")[0] for line in src.splitlines()
                   if line.startswith("import ") or line.startswith("from ")}
        self.assertLessEqual(imports, {"argparse", "datetime", "json", "os", "subprocess", "sys", "tempfile", "time",
                                       "urllib"})

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
    def failed_routes(self, detail):
        payload = {"tag": "StackVendPipelineError", "error_class": "CODE_DEFECT", "stage": "qa", "reason": "",
                   "message": 'QA failed ("CODE_DEFECT"): "1 diagnostic(s)"', "raw_error": {"body": SIGNED}}
        qa = fs_doc(f"qa_test_runs/{TRACE}", {
            "passed": False, "error_class": "CODE_DEFECT", "reason": None, "attempt": 1, "exit_code": 10,
            "execution_name": "qa-sandbox-test-runner-zz9", "summary": "QA failed: 1 diagnostic(s)",
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
        r = self.run_script("--project", PROJ, "--watch-only", PID, "--poll-sec", "0")
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

    def success_routes(self, health):
        stages = dict(DONE, qa={"status": "SUCCESS"}, release={"status": "SUCCESS"},
                      terraform={"status": "SUCCESS", "summary": "Apply complete"})
        build = {"builds": [{"id": "old-build", "status": "FAILURE", "createTime": iso(-600)},
                            {"id": "build-new-1", "status": "SUCCESS", "createTime": iso(-8)}]}
        qa = fs_doc(f"qa_test_runs/{TRACE}", {"passed": True, "attempt": 0, "exit_code": 0, "summary": "ok"})
        return [
            (f"documents/workloads/{PID}", [[200, WORKLOAD]]),
            ("documents:runQuery", [[200, run_doc("SUCCEEDED", "COMPLETE", stages,
                                                  outputs={"service_url": SERVICE_URL})]]),
            (f"executions/{EXEC_ID}", [[200, {"state": "SUCCEEDED",
                                               "result": json.dumps({"service_url": SERVICE_URL})}]]),
            ("jobs/qa-sandbox-test-runner/executions", [[200, job_executions("qa-sandbox-test-runner", "QA_TRACE_ID")]]),
            ("jobs/tf-applier/executions", [[200, job_executions("tf-applier", "TRACE_ID")]]),
            (f"documents/qa_test_runs/{TRACE}", [[200, qa]]),
            (f"projects/{PID}/builds", [[200, build]]),
            (SERVICE_URL + "/health", health),
        ]

    def test_successful_run_probes_health_and_passes(self):
        self.set_routes(self.success_routes([[200, '{"status": "healthy"}']]))
        r = self.run_script("--project", PROJ, "--watch-only", PID, "--poll-sec", "0")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        out = r.stdout
        self.assertIn("tf_applier       SUCCEEDED  tf-applier-zz9", out)
        self.assertIn("cloud_build      SUCCESS  build build-new-1", out)
        self.assertNotIn("old-build", out)                             # builds before the run are not this run's
        self.assertIn(f"service_url      {SERVICE_URL}", out)
        self.assertIn("health           HTTP 200", out)
        self.assertRegex(out, r"\n  health +PASS\n")
        self.assertIn("RESULT: PASS", out)
        # no access record: one anonymous request (is IAP in front?), then the identity-token probe
        anonymous, probe = [c for c in self.curl_calls() if c["url"] == SERVICE_URL + "/health"]
        self.assertFalse(anonymous["auth"])
        self.assertTrue(probe["auth"])                                 # identity token, on stdin
        self.assert_no_token_leak(r)

    def test_refused_health_probe_exits_4(self):
        self.set_routes(self.success_routes([[403, "Forbidden"]]))
        r = self.run_script("--project", PROJ, "--watch-only", PID, "--poll-sec", "0")
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        # one anonymous IAP check (no access record), then three identity-token tries
        self.assertEqual([c["auth"] for c in self.curl_calls() if c["url"].endswith("/health")],
                         [False, True, True, True])
        self.assertIn("probe identity was refused", r.stdout)
        self.assertIn("RESULT: FAIL (health probe)", r.stdout)
        self.assert_no_token_leak(r)

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
# a child-project Cloud Run read in any region: the health check must never make one (no run.viewer needed there)
CHILD_RUN_READ = f"run.googleapis.com/v2/projects/{PID}/"


def workload_with_access(mode, region=None, principals=("user:operator@example.test",)):
    fields = {"product_id": PID, "project_id": PID, "status": "ACTIVE", "creation_mode": "AGENT", "service_url": ""}
    if region:
        fields["region"] = region
    if mode:
        fields["access"] = {"mode": mode, "invoker_principals": list(principals), "source": "platform_default"}
    return fs_doc(f"workloads/{PID}", fields)


def load_follower():
    spec = importlib.util.spec_from_file_location("live_canary_follow_under_test", FOLLOWER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestHealthByAccessMode(_Harness):
    """The /health verdict follows workloads/{pid}.access.mode; the URL and region come from the platform records."""

    def routes(self, mode, health, region=None, principals=("user:operator@example.test",)):
        routes = [(f"documents/workloads/{PID}", [[200, workload_with_access(mode, region, principals)]]),
                  # were the canary to read the child project's Cloud Run, it would be refused (no run.viewer there)
                  (CHILD_RUN_READ, [[403, {"error": {"code": 403, "status": "PERMISSION_DENIED"}}]])]
        return routes + TestWatchOnly.success_routes(self, health)[1:]

    def run_watch(self, *extra):
        return self.run_script("--project", PROJ, "--watch-only", PID, "--poll-sec", "0", *extra)

    def health_calls(self):
        return [c for c in self.curl_calls() if c["url"] == SERVICE_URL + "/health"]

    def assert_read_only(self):
        for c in self.curl_calls():
            if "--data-binary" in c["argv"]:
                self.assertTrue(c["url"].endswith("documents:runQuery"), c["url"])
            self.assertNotIn("-L", c["argv"])                           # redirects are never followed
            self.assertNotIn("-X", c["argv"])
        self.assertFalse([c for c in self.calls() if c.startswith("gcloud") and "auth " not in c])

    def assert_no_child_run_or_logging_read(self):
        for c in self.curl_calls():
            self.assertNotIn(CHILD_RUN_READ, c["url"])
            self.assertNotIn("logging.googleapis.com", c["url"])

    # ---------------------------------------------------------------------------------------------- PUBLIC_APP
    def test_public_app_probes_anonymously(self):
        self.set_routes(self.routes("PUBLIC_APP", [[200, '{"status": "healthy"}']]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("access           PUBLIC_APP  (workload record)", r.stdout)
        self.assertIn("health           HTTP 200", r.stdout)
        [probe] = self.health_calls()
        self.assertFalse(probe["auth"])                                # no credentials for a public app
        self.assertFalse([c for c in self.calls() if "print-identity-token" in c])
        self.assertRegex(r.stdout, r"\n  health +PASS\n")
        self.assertIn("RESULT: PASS", r.stdout)
        self.assert_no_child_run_or_logging_read()
        self.assert_read_only()
        self.assert_no_token_leak(r)

    def test_public_app_in_another_region_uses_the_record(self):
        """The workload's own region (workloads/{pid}.region), not --region; the URL is the run's, read from the
        records, so no Cloud Run read in either region is needed."""
        self.set_routes(self.routes("PUBLIC_APP", [[200, "ok"]], region="europe-west1"))
        r = self.run_watch("--region", "us-central1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("access           PUBLIC_APP  (workload record)  region europe-west1 (workload record)",
                      r.stdout)
        [probe] = self.health_calls()
        self.assertEqual(probe["url"], SERVICE_URL + "/health")
        self.assert_no_child_run_or_logging_read()
        self.assertIn("RESULT: PASS", r.stdout)

    def test_legacy_record_without_region_follows_region_flag(self):
        self.set_routes(self.routes("PUBLIC_APP", [[200, "ok"]]))
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

    # --------------------------------------------------------------------------------------------- PRIVATE_IAM
    def test_private_iam_uses_identity_token_for_the_service_url(self):
        self.set_routes(self.routes("PRIVATE_IAM", [[200, "ok"]]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("access           PRIVATE_IAM  (workload record)", r.stdout)
        [probe] = self.health_calls()
        self.assertTrue(probe["auth"])                                 # identity token, on stdin
        self.assertIn(f"gcloud auth print-identity-token --audiences={SERVICE_URL}", self.calls())
        self.assert_no_child_run_or_logging_read()
        self.assertIn("RESULT: PASS", r.stdout)
        self.assert_read_only()
        self.assert_no_token_leak(r)

    def test_private_iam_refused_exits_4(self):
        self.set_routes(self.routes("PRIVATE_IAM", [[401, "Unauthorized"]]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 4, r.stdout + r.stderr)
        self.assertIn("probe identity was refused: a private (IAM invoker) service", r.stdout)
        self.assertIn("RESULT: FAIL (health probe)", r.stdout)
        self.assert_no_token_leak(r)

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
        self.assertFalse([c for c in self.calls() if "print-identity-token" in c])
        [probe] = self.health_calls()
        self.assertFalse(probe["auth"])
        self.assert_no_child_run_or_logging_read()
        self.assert_read_only()
        self.assert_no_token_leak(r)

    def test_private_iap_browser_check_prints_the_url_to_open(self):
        self.set_routes(self.routes("PRIVATE_IAP", [[302, "", SIGN_IN]],
                                    principals=("user:operator@example.test", "group:team@example.test")))
        r = self.run_watch("--iap-browser-check")
        self.assertEqual(r.returncode, 6, r.stdout + r.stderr)
        self.assertIn(f"iap_browser      open {SERVICE_URL}/health in a browser signed in as an allowed principal "
                      "(user:operator@example.test, group:team@example.test); a healthy service answers 200",
                      r.stdout)
        self.assertRegex(r.stdout, r"\n  health +HEALTH_NOT_PROBED_PRIVATE_IAP\n")   # still not a pass
        self.assertFalse([c for c in self.calls() if "print-identity-token" in c])
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
                self.assertFalse([c for c in self.calls() if "print-identity-token" in c])

    def test_iap_found_from_an_anonymous_redirect_without_an_access_record(self):
        self.set_routes(self.routes(None, [[302, "", SIGN_IN]]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 6, r.stdout + r.stderr)
        self.assertIn("access           PRIVATE_IAP  (no access record; an anonymous GET /health was redirected to "
                      "accounts.google.com)", r.stdout)
        self.assertIn("RESULT: DEPLOYED, HEALTH_NOT_PROBED_PRIVATE_IAP", r.stdout)
        self.assertFalse([c for c in self.calls() if "print-identity-token" in c])
        self.assertTrue(all(not c["auth"] for c in self.health_calls()))
        self.assert_no_child_run_or_logging_read()

    def test_no_access_record_and_no_iap_keeps_the_identity_probe(self):
        self.set_routes(self.routes(None, [[200, "ok"]]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("access           unknown", r.stdout)
        anonymous, probe = self.health_calls()
        self.assertFalse(anonymous["auth"])                            # the IAP check sends no credentials
        self.assertTrue(probe["auth"])
        self.assertIn("gcloud auth print-identity-token", self.calls())
        self.assert_no_child_run_or_logging_read()


def child_run(region="us-central1"):
    return f"projects/{PID}/locations/{region}/services"


CHILD_RUN = child_run()
SVC = "canary-svc"
REV = f"{SVC}-00002-abc"
REV_NAME = f"{CHILD_RUN}/{SVC}/revisions/{REV}"
OK_LINE = 'STARTUP HTTP probe succeeded after 1 attempt for container "app-1" on port 8080 path "/health".'
FAIL_LINE = ('STARTUP HTTP probe failed 20 times consecutively for container "app-1" on port 8080 path "/health". '
             'The instance was not started.')


def cloud_run_service(iap=True, created=REV_NAME):
    return {"services": [
        {"name": f"{CHILD_RUN}/other-svc", "uri": "https://other-svc.example.test", "iapEnabled": False,
         "latestReadyRevision": f"{CHILD_RUN}/other-svc/revisions/other-svc-00001-x"},
        {"name": f"{CHILD_RUN}/{SVC}", "uri": "https://canary-svc-hash.a.run.example.test",
         "urls": [SERVICE_URL + "/"], "iapEnabled": iap, "latestReadyRevision": REV_NAME,
         "latestCreatedRevision": created}]}


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


class TestChildChecksOptIn(_Harness):
    """--child-checks (default off): the PRIVATE_IAP check from the child project's Cloud Run revision + startup
    probe log + the anonymous 302, for operators with roles/run.viewer + roles/logging.viewer in the child."""

    def routes(self, anonymous, service=None, rev=None, logs=None, mode="PRIVATE_IAP", region=None,
               list_region="us-central1"):
        return ([(f"documents/workloads/{PID}", [[200, workload_with_access(mode, region)]]),
                 (f"{child_run(list_region)}?", [service or [200, cloud_run_service()]]),
                 (f"/revisions/{REV}", [rev or [200, revision()]]),
                 ("logging.googleapis.com/v2/entries:list", [logs or [200, log_entries(FAIL_LINE, OK_LINE)]])]
                + TestWatchOnly.success_routes(self, anonymous)[1:])

    def run_watch(self, *extra, child_checks=True):
        flags = ("--child-checks",) if child_checks else ()
        return self.run_script("--project", PROJ, "--watch-only", PID, "--poll-sec", "0", *flags, *extra)

    def health_calls(self):
        return [c for c in self.curl_calls() if c["url"] == SERVICE_URL + "/health"]

    def child_calls(self):
        return [c for c in self.curl_calls() if CHILD_RUN_READ in c["url"] or "logging.googleapis.com" in c["url"]]

    def assert_read_only(self):
        for c in self.curl_calls():
            if "--data-binary" in c["argv"]:
                self.assertTrue(c["url"].endswith("documents:runQuery") or c["url"].endswith("/v2/entries:list"),
                                c["url"])
            self.assertNotIn("-L", c["argv"])
            self.assertNotIn("-X", c["argv"])
        self.assertFalse([c for c in self.calls() if c.startswith("gcloud") and "auth " not in c])

    # ------------------------------------------------------------------------------------------------- flag off
    def test_flag_off_reads_nothing_in_the_child_even_when_it_would_pass(self):
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
        stages = dict(DONE, qa={"status": "SUCCESS"}, terraform={"status": "SUCCESS"})
        self.set_routes([
            (f"documents/workloads/{PID}", [[404, {}], [200, workload_with_access("PRIVATE_IAP")]]),
            ("documents:runQuery", [[200, run_doc("SUCCEEDED", "COMPLETE", stages, started=iso(+5),
                                                  outputs={"service_url": SERVICE_URL})]]),
            (f"executions/{EXEC_ID}", [[200, {"state": "SUCCEEDED"}]]),
            (f"{CHILD_RUN}?", [[403, {"error": {"code": 403}}]]),
            (SERVICE_URL + "/health", [[302, "", SIGN_IN]]),
        ])
        open(self.log, "w").close()
        r = self.run_script("--project", PROJ, "--product-id", PID, "--poll-sec", "0", "--child-checks")
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)          # the child read happened, and was refused
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
        self.assertFalse([c for c in self.calls() if "print-identity-token" in c])
        [probe] = self.health_calls()
        self.assertFalse(probe["auth"])
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

    def test_service_is_listed_in_the_workloads_region(self):
        self.set_routes(self.routes([[302, "", SIGN_IN]], region="europe-west1", list_region="europe-west1"))
        r = self.run_watch("--region", "us-central1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        [listing] = [c for c in self.curl_calls() if "/services?" in c["url"]]
        self.assertIn(f"projects/{PID}/locations/europe-west1/services?", listing["url"])
        self.assertIn("RESULT: PASS", r.stdout)

    def test_service_permission_denied_is_the_typed_error_not_a_pass(self):
        self.set_routes(self.routes([[302, "", SIGN_IN]], service=[403, {"error": {"code": 403}}]))
        r = self.run_watch()
        self.assertEqual(r.returncode, 5, r.stdout + r.stderr)
        self.assertIn(f"permission denied reading Cloud Run services in {PID}: the operator needs roles/run.viewer "
                      "in the child project", r.stdout)
        self.assertEqual(r.stdout.count("not verified ("), 1)          # no retries on a missing permission
        self.assertRegex(r.stdout, r"\n  health +ERROR \(permission denied\)\n")
        self.assertIn("RESULT: ERROR (permission denied)", r.stdout)
        self.assertNotIn("RESULT: PASS", r.stdout)
        self.assertNotIn("HEALTH_NOT_PROBED", r.stdout)

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
        self.assertFalse([c for c in self.calls() if "print-identity-token" in c])

    def test_no_access_record_and_no_iap_keeps_the_identity_probe(self):
        self.set_routes(self.routes([[200, "ok"]], service=[200, cloud_run_service(iap=False)], mode=None))
        r = self.run_watch()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("access           unknown", r.stdout)
        self.assertTrue(self.health_calls()[-1]["auth"])
        self.assertIn("gcloud auth print-identity-token", self.calls())


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
        self.assertNotEqual(m.HEALTH_NOT_PROBED_PRIVATE_IAP, m.HEALTH_PASS)

    def test_iap_health_never_mints_or_sends_a_token(self):
        """iap_not_probed takes no auth at all: the only request is the anonymous GET (http_full with token None)."""
        calls = []

        def fake_http_full(url, token=None, body=None, timeout=30):
            calls.append((url, token, body))
            return 302, "", SIGN_IN

        f = self.follower({"access": {"mode": "PRIVATE_IAP"}})
        f.service_url = SERVICE_URL + "/"
        orig = self.m.http_full
        self.m.http_full = fake_http_full
        try:
            state, code = f.iap_not_probed(attempts=3, spacing=0)
        finally:
            self.m.http_full = orig
        self.assertEqual((state, code), (self.m.HEALTH_NOT_PROBED_PRIVATE_IAP, self.m.EXIT_NOT_PROBED))
        self.assertEqual(calls, [(SERVICE_URL + "/health", None, None)])


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
            (SERVICE_URL + "/health", [[200, "ok"]]),
        ])
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
        # read-only: the only non-GET request is the Firestore query; nothing is published or created
        for c in self.curl_calls():
            if "--data-binary" in c["argv"]:
                self.assertIn("documents:runQuery", c["url"])
            self.assertNotIn("pubsub", c["url"])
            self.assertNotIn("/api/workloads", c["url"])
        self.assert_no_token_leak(r)

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
