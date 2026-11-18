# Live Canary (end-to-end check of an install)

`scripts/live_canary.sh` sends one example workload through a running install and follows it, read-only, through every stage to a deployed service and a `/health` probe. It reports pass or fail per stage.

The local checks (the test suite, [Test a Spec Locally](test-a-spec-locally.md)) stop at a validated tree. Some faults only show up on a live install: a cold validate service, the QA sandbox job, the container build, the apply and the rollout. The canary covers those.

**When to run it:** after every deploy to a dev install, and before a release candidate is cut. A release candidate waits until example 01 passes the canary on every dev install.

## Prerequisites

* `gcloud`, `curl` and `python3` on your machine (the helper `scripts/live_canary_follow.py` uses the Python standard library only). macOS `/bin/bash` 3.2 works.
* A `gcloud auth login` session for an account that is an **administrator in the Control Center** (to submit) and can read, in the host project, Firestore (`roles/datastore.viewer`), Cloud Workflows executions (`roles/workflows.viewer`) and Cloud Run jobs (`roles/run.viewer`). To see container builds, the account also needs `roles/cloudbuild.builds.viewer` in the child project. The health check needs no access in the child project by default: the service URL comes from the platform records. Only the opt-in `--child-checks` reads the child project's Cloud Run service (`roles/run.viewer`) and Cloud Logging (`roles/logging.viewer`). A project owner of a dev install has all of these.
* The script reads only. It never creates, changes, approves, retries or deletes anything, and it never prints a token. Tokens reach `curl` on standard input, never on a command line.

## Run a canary (submit and follow)

```bash
scripts/live_canary.sh --project <host-project-id>
# options: --region us-central1  --product-id <new id>  --timeout-min 75  --submit-wait-min 30  --poll-sec 30
#          --example documentation/examples/01-cloudrun-pubsub-event-router.md  --iap-browser-check  --child-checks
```

The script chooses a new workload id (`canary01-<MMDDhhmm>` unless you pass `--product-id`). It prints the Control Center URL, the values for the form, and the spec text from the example's *Workload Form Submission Prompt*. You then submit the workload yourself, as any user does:

1. In the Control Center open **Workloads Catalog**, then **New Workload**.
2. **Workload Identifier (Slug)**: the id the script printed.
3. **Technical Specification & Requirements**: paste the printed spec text.
4. Turn off **Require Human Code Review (HITL)** and **Require Plan Approval Before Development**, so the run needs no approval clicks. If you leave them on, approve in **Approvals** while the canary waits; it prints a `WAITING` line when the run stops for you.
5. Turn on **Designate as Autonomous Sandbox** (the canary workload is disposable).
6. Leave access at the default (**Private**, Google sign-in through IAP). The canary does not sign in through IAP, so for this workload it reports `HEALTH_NOT_PROBED_PRIVATE_IAP` (exit 6) and you check `/health` in a browser; see [How the health check works](#how-the-health-check-works).
7. Submit.

The script waits (up to `--submit-wait-min`) for the workload record to appear. It refuses an id that already exists (use `--watch-only` for that). It only follows runs that started after the canary began.

**Why the script does not submit by itself.** The Control Center signs people in only through Google sign-in (or IAP when the Control Center runs behind IAP). It accepts a bearer token only from its allow-listed platform service account. Only the platform services may publish to the spec-intake topic; the Control Center first writes the workload record, its access list and the governance defaults. Submitting from the command line would need a way around one of those checks, so the script leaves the submission to you.

## Follow an existing workload (watch-only)

```bash
scripts/live_canary.sh --project <host-project-id> --watch-only <product_id> [--trace-id <run id>] [--iap-browser-check] [--child-checks]
```

This follows the newest run of the workload, or the run you name with `--trace-id`. If that run has already finished, the report comes at once.

## What it reads and prints

One line per change, with a UTC timestamp:

| Line | Source (read-only) |
| :--- | :--- |
| `record` | Firestore `workloads/<product_id>`: status and child project |
| `run`, `pipeline`, one line per stage (`architect` ... `terraform`) | Firestore `pipeline_executions` (the run: `status`, `current_stage`, `stages`) |
| `workflow` | Cloud Workflows execution of `castor-main-orchestrator` |
| `qa_job`, `qa_result` | Cloud Run job `qa-sandbox-test-runner` (the execution for this run) and Firestore `qa_test_runs/<trace_id>` |
| `cloud_build` | Cloud Build builds in the child project created after the run started |
| `tf_applier` | Cloud Run job `tf-applier` (the execution for this run) |
| `service_url`, `access`, `health` | The run's service URL, the workload's access mode, then the health check for that mode (three tries; see below) |

Job executions are matched on the run's trace id only. No other job setting (signed URLs, callback URLs) is read into the output.

On failure the script prints the typed error from the workflow error payload: `error_class`, `stage`, `reason` and `message` (up to 2 KB). If QA failed, it also prints the QA verdict: exit code, execution and, for each diagnostic (up to 10), its code, file, message and the first 2 KB of its detail. Every run ends with a per-stage summary table and a `RESULT:` line.

Sample (a run that QA stopped):

```text
2026-10-27T14:42:06Z  pipeline         FAILED  status FAILED
2026-10-27T14:42:06Z  gatekeeper       SUCCESS  AST monorepo imports sanitized, PyPI dependencies reconciled, py_compile verified
2026-10-27T14:42:07Z  workflow         FAILED  execution <execution id>
2026-10-27T14:42:07Z  qa_job           FAILED  qa-sandbox-test-runner-mvztf
2026-10-27T14:42:07Z  qa_result        FAILED CODE_DEFECT  attempt 1 exit 10 QA failed: 1 diagnostic(s); first: PY.IMPORT_FAILED ...

FAILED
  error_class : CODE_DEFECT
  stage       : qa
  ...
RESULT: FAIL
```

## How the health check works

The service URL comes from the platform records: the run's outputs, the workflow result, or the workload record's
`service_url`. The canary never lists Cloud Run in the child project, so it needs no role there. The `access` line
also names the workload's region (`region` in `workloads/<product_id>`; an older record without one follows
`--region`). `--region` itself is the install's region, where the host's workflow and jobs run.

The check follows the workload's access mode, read from its record (`access.mode` in `workloads/<product_id>`). If the
record has no access mode, the canary sends one anonymous `GET <service_url>/health`: a redirect to Google sign-in
means IAP is in front (handled as `PRIVATE_IAP`); otherwise it sends your identity token.

| Access mode | What the canary checks | Result |
| :--- | :--- | :--- |
| `PUBLIC_APP` | `GET <service_url>/health` with no credentials | 200: `PASS` (exit 0) |
| `PRIVATE_IAM` | `GET <service_url>/health` with your identity token (the service URL as audience when your login is a service account; a user login sends its default token, which Cloud Run accepts for a listed user) | 200: `PASS` (exit 0) |
| `PRIVATE_IAP` (the default) | `/health` is **not probed**. A `gcloud` user identity token cannot pass Direct IAP (IAP refuses it: `Invalid JWT audience`), and the canary does not create an OAuth client or mint any other token. It checks only that IAP is in front: an anonymous `GET <service_url>/health` must be redirected (302) to Google sign-in (`accounts.google.com`). With `--child-checks`, see [Child-project checks](#child-project-checks---child-checks-opt-in). | `HEALTH_NOT_PROBED_PRIVATE_IAP` (exit 6) |

`HEALTH_NOT_PROBED_PRIVATE_IAP` is never a pass. The run deployed and IAP is in front, but nobody has seen `/health`
answer yet. The result line says so:

```text
health                 HEALTH_NOT_PROBED_PRIVATE_IAP
RESULT: DEPLOYED, HEALTH_NOT_PROBED_PRIVATE_IAP (a gcloud user identity token cannot pass Direct IAP (IAP refuses it: Invalid JWT audience); open the URL in a browser signed in as an allowed principal: https://<service>/health)
```

To finish the check, open that URL in a browser signed in as one of the people allowed to use the workload. A healthy
service answers 200. With `--iap-browser-check`, the canary also prints an `iap_browser` line with the URL and the
workload's allowed principals (from its access record). Access to a new private app can take a few minutes to start
working after the deploy.

Failures each print their own line:

| Line | What it means |
| :--- | :--- |
| `a public (PUBLIC_APP) service refused an anonymous request` | The service's invoker binding or ingress does not match the access record. |
| `the probe identity was refused` | A `PRIVATE_IAM` service (or a workload with no access mode) did not accept your identity. It accepts only the people listed under who may use it; check the workload's access settings in the Control Center. |
| `IAP is not enforced` | An anonymous request reached the app (2xx) although the workload is `PRIVATE_IAP`. This is a failure (exit 4), never a pass. |
| `IAP not proven` | An anonymous request got something other than a redirect to Google sign-in, three times (exit 4). |

### Child-project checks (`--child-checks`, opt-in)

If your account holds `roles/run.viewer` and `roles/logging.viewer` in the child project, `--child-checks` (off by
default) checks a `PRIVATE_IAP` workload from the platform's own signals instead of reporting it not probed:

1. The Cloud Run service in the workload's region whose URL is the recorded service URL: its latest ready revision is
   the newest revision, and that revision's `Ready` condition succeeded.
2. That revision's startup probe is an HTTP probe on `/health`.
3. Cloud Logging (`run.googleapis.com/varlog/system` in the child project) has a
   `STARTUP HTTP probe succeeded ... path "/health"` line for that revision.
4. An anonymous `GET <service_url>/health` is redirected (302) to Google sign-in.

All four hold: `health  (startup probe) 200, IAP enforced (302)`, `PASS` (exit 0). Cloud Run sends traffic to a
revision only after its startup probe passes, so a passing startup probe on `/health` means `/health` answered.
With no access mode on the record, `--child-checks` also reads the service's `iapEnabled`.

| Line | What it means |
| :--- | :--- |
| `revision ... is not Ready` / `the newest revision ... is not ready` | The deployed revision did not start (exit 4). |
| `the /health startup probe of revision ... failed` | Cloud Run's startup probe on `/health` failed; the log line is printed (exit 4). |
| `no "STARTUP HTTP probe succeeded ..." line ... yet` | No startup probe result in Cloud Logging for the revision after three tries (exit 4). |
| `has no HTTP startup probe` / `checks <path>, not /health` | The startup probe does not check `/health` (exit 4). |
| `permission denied reading ... in <child project>` | Your account lacks `roles/run.viewer` or `roles/logging.viewer` in the child project: `ERROR (permission denied)` (exit 5), never a pass. Run without `--child-checks`. |

The canary never changes access and never follows a redirect. Only the sign-in host of a redirect is printed.

## Exit codes

| Code | Meaning |
| :--- | :--- |
| 0 | Deployed, and the health check passed (`PUBLIC_APP`, `PRIVATE_IAM`; `PRIVATE_IAP` only with `--child-checks`) |
| 1 | The pipeline failed (typed error printed) |
| 2 | Usage error, or `--product-id` already exists |
| 3 | Timed out (`--timeout-min`), or nothing was submitted within `--submit-wait-min` |
| 4 | The run succeeded, but the health check failed, a `PRIVATE_IAP` service is not behind IAP, or no service URL was reported |
| 5 | A prerequisite is missing: a tool, a `gcloud` login, or read access to the records (with `--child-checks`, also the child project's Cloud Run service and Cloud Logging) |
| 6 | Deployed, health not probeable from the command line: `HEALTH_NOT_PROBED_PRIVATE_IAP` (IAP is in front; check `/health` in a browser) |

## After the canary

The canary workload is a sandbox: it expires on its own, or you can decommission it in the Control Center. On a failure, the [diagnose-workload runbook](../.agents/skills/stackvend-diagnose-workload/SKILL.md) takes the investigation from the stage and error class the canary printed.
