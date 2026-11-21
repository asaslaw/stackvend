# Live Canary (end-to-end check of an install)

`scripts/live_canary.sh` sends one example workload through a running install and follows it, read-only, through every stage to a deployed service and a `/health` probe of the service URL that Cloud Run confirms. It reports pass or fail per stage.

The local checks (the test suite, [Test a Spec Locally](test-a-spec-locally.md)) stop at a validated tree. Some faults only show up on a live install: a cold validate service, the QA sandbox job, the container build, the apply and the rollout. The canary covers those.

**When to run it:** after every deploy to a dev install, and before a release candidate is cut. A release candidate waits until example 01 passes the canary on every dev install. Run it only on a workload whose code and Terraform you trust, such as the examples: the canary sends requests to the workload's own service, and the workload's Terraform decides that service's URL and who may call it.

## Prerequisites

* `gcloud`, `curl` and `python3` on your machine (the helper `scripts/live_canary_follow.py` uses the Python standard library only). macOS `/bin/bash` 3.2 works.
* A `gcloud auth login` session for an account that is an **administrator in the Control Center** (to submit) and can read, in the host project, Firestore (`roles/datastore.viewer`), Cloud Workflows executions (`roles/workflows.viewer`) and Cloud Run jobs (`roles/run.viewer`). To see container builds, the account also needs `roles/cloudbuild.builds.viewer` in the child project.
* **Read access for the health check** (see [How the health check works](#how-the-health-check-works)). In the host project, the Cloud Run viewer role above also lets the canary read the vending service `project-repo-vending-service`, of which it reads only the `MANAGED_WORKLOADS_FOLDER_ID` setting. In the child project, it reads the project's ancestry (Resource Manager, `resourcemanager.projects.get`, for example `roles/browser`) and lists the Cloud Run services and reads a service's IAM policy (`roles/run.viewer`); `roles/viewer` covers both. Vending grants `roles/viewer` on a new child project to the Control Center administrators that exist when the workload is vended, and only as a best effort (a failed grant is a warning); administrators added later and other operators may need it granted. Without it the canary stops with a permission error (exit 5) and sends nothing to the service. The opt-in `--child-checks` also reads Cloud Logging (`roles/logging.viewer`) there. A project owner of a dev install has all of these.
* The script reads only. It never creates, changes, approves, retries or deletes anything, and it never prints a token. Tokens reach `curl` on standard input, never on a command line.
* **What it sends, and to whom.** To Google's APIs (Firestore, Cloud Workflows, Cloud Run, Cloud Build, Resource Manager and, with `--child-checks`, Cloud Logging): your `gcloud` access token, as any `gcloud` command does. To the workload's service: an anonymous `GET <service_url>/health` (up to three tries), and only at the confirmed URL. A token goes to the service in one case only: a service-account login, a `PRIVATE_IAM` workload, and a token minted for exactly that URL (see below). A user login's identity token is never sent anywhere, and your access token never goes to a workload. Every `curl` call ignores curl configuration files (`-q`), uses `https` only, follows no redirects and reads at most 1 MiB of an answer. Text the canary prints from records and responses has control characters removed and stays on one line, and a workload's answer is printed ASCII-only and quoted, so a response cannot forge a `RESULT` line. A script or CI job that reads the outcome must use the exit code, or the line that starts with `RESULT: ` (anchored at the start of a line), never a match anywhere in the output.

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

This follows the newest run of the workload, or the run you name with `--trace-id`. If that run has already finished, the report comes at once. The same rule applies: watch only a workload whose code and Terraform you trust, because the health check sends requests to its service.

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
| `service_url`, `confirmed`, `access`, `health` | The run's recorded service URL, the URL as Cloud Run returns it (with the service, child project and region), the workload's access mode, then the health check for that mode (three tries; see below) |

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

**The URL is confirmed first.** The service URL comes from the platform records: the run's outputs, the workflow
result, or the workload record's `service_url`. Before anything is sent to it, the canary checks it:

1. Every record value it uses (the URL, the child project, the region, run and execution ids) must be plain printable
   text, and the project, region and ids must match their exact formats; otherwise `RECORD_VALUE_REFUSED` (exit 5).
   A record written by an older release that holds something other than text as the URL is refused the same way.
2. The URL must be exactly `https://<host>` or `https://<host>/` with a Cloud Run `run.app` host (lowercase
   letters, digits and hyphens): no user name, no port, no other path, no query, no fragment; otherwise
   `SERVICE_URL_REFUSED` (exit 4).
3. The install's managed-workloads folder is read from the `MANAGED_WORKLOADS_FOLDER_ID` setting of the host's
   `project-repo-vending-service`; when that service cannot be read or holds no single folder id,
   `MANAGED_FOLDER_UNKNOWN` (exit 5). The child project's ancestry (Resource Manager `getAncestry`) must hold that
   folder anywhere above the project; otherwise `SERVICE_URL_NOT_CONFIRMED` (exit 4). An ancestry that cannot be read
   is `ANCESTRY_UNAVAILABLE` (exit 5): no answer, 429 and 5xx are tried three times, other errors are reported at once.
4. The URL must be the `uri`, or one of the `urls`, of a Cloud Run service in that project and the workload's region
   (every page of the listing is read; one trailing `/` aside). When the listing was read completely and no service
   matches, `SERVICE_URL_NOT_CONFIRMED` (exit 4); when it cannot be read completely (no answer, 429 and 5xx
   tried three times, other errors at once), `CLOUD_RUN_API_UNAVAILABLE` (exit 5). From then on the canary uses Cloud Run's string. A record that names no child
   project is `SERVICE_URL_NOT_CONFIRMED` too. A read you are not allowed to make (401 or 403, not retried) is a
   permission error (exit 5).

In none of these cases is anything sent to the URL. A workload whose Terraform publishes another kind of URL (GKE, a
load balancer, a custom domain) has no confirmed URL and is not probed. The `access` line also names the workload's
region (`region` in `workloads/<product_id>`; an older record without one follows `--region`). `--region` itself is
the install's region, where the host's workflow and jobs run.

**Then the check for the access mode** read from the record (`access.mode` in `workloads/<product_id>`). Every mode
starts with one anonymous `GET <service_url>/health` (no credentials):

| Access mode | What the canary checks | Result |
| :--- | :--- | :--- |
| `PUBLIC_APP` | The anonymous request | 2xx: `PASS` (exit 0) |
| `PRIVATE_IAP` (the default) | `/health` is **not probed**. A `gcloud` user identity token cannot pass Direct IAP (IAP refuses it: `Invalid JWT audience`), and the canary does not create an OAuth client or mint any other token. It checks only that IAP is in front: the anonymous request must be redirected (302) to Google sign-in (`accounts.google.com`), and that redirect counts only when Cloud Run reports IAP on for the confirmed service (`iapEnabled` true): the app itself could send the same redirect. With `--child-checks`, see [Child-project checks](#child-project-checks---child-checks-opt-in). | `HEALTH_NOT_PROBED_PRIVATE_IAP` (exit 6). A redirect from a service without `iapEnabled`: `ACCESS_RECORD_MISMATCH` (exit 4), also with `--child-checks` |
| `PRIVATE_IAM` | In this order: (1) the anonymous request must be refused (401, 403, or 404 from a service that accepts only internal traffic); a 2xx is `ACCESS_RECORD_MISMATCH`. (2) The service's own settings, for every login: its invoker check must be on (`invokerIamDisabled` not true) and its IAM policy must name `allUsers` or `allAuthenticatedUsers` in no role; otherwise `ACCESS_RECORD_MISMATCH`, and no token is minted. A policy you may not read is a permission error. (3) An identity token for exactly the confirmed URL: `gcloud auth print-identity-token --audiences=<confirmed URL>`, which `gcloud` grants only to a service-account login (or an impersonated account). A user login gets none, and its default identity token, valid on every Cloud Run service where you may invoke, is never minted or sent. A token whose decoded audience is not exactly the confirmed URL is not sent either. (4) The probe, with the token only in the `X-Serverless-Authorization` header. | Token probe 200: `PASS` (exit 0). No token (a user login, or a token bound to another audience): `HEALTH_NOT_PROBED_PRIVATE_IAM` (exit 6). `ACCESS_RECORD_MISMATCH`: a failure (exit 4). Policy not readable: `ERROR (permission denied)` (exit 5) |
| No access mode on the record | The anonymous request; no token in any case | 2xx: `PASS`; a redirect to Google sign-in from a service with `iapEnabled` true: handled as `PRIVATE_IAP` (from any other service: `ACCESS_RECORD_MISMATCH`, exit 4); 401, 403 or 404: `HEALTH_NOT_PROBED_NO_ACCESS_RECORD` (exit 6) |

Any other answer in any mode (a redirect on a `PRIVATE_IAM` record, a 5xx, no answer) is a failure after three tries
(exit 4).

The not-probed states are never a pass. The run deployed, but nobody has seen `/health` answer yet. The result line
says so, for example:

```text
health                 HEALTH_NOT_PROBED_PRIVATE_IAP
RESULT: DEPLOYED, HEALTH_NOT_PROBED_PRIVATE_IAP (a gcloud user identity token cannot pass Direct IAP (IAP refuses it: Invalid JWT audience); open the URL in a browser signed in as an allowed principal: https://<service>/health)
```

To finish the check of a `PRIVATE_IAP` workload, open that URL in a browser signed in as one of the people allowed to
use the workload. A healthy service answers 200. With `--iap-browser-check`, the canary also prints an `iap_browser`
line with the URL and the workload's allowed principals (from its access record). Access to a new private app can
take a few minutes to start working after the deploy.

Failures each print their own line:

| Line | What it means |
| :--- | :--- |
| `a public (PUBLIC_APP) service refused an anonymous request` | The service's invoker binding or ingress does not match the access record. |
| `the probe identity was refused` | A `PRIVATE_IAM` service did not accept the service account's token (exit 4). It accepts only the principals listed under who may use it; check the workload's access settings in the Control Center. |
| `IAP is not enforced` | An anonymous request reached the app (2xx) although the workload is `PRIVATE_IAP`. This is a failure (exit 4), never a pass. |
| `IAP not proven` | An anonymous request got something other than a redirect to Google sign-in, three times (exit 4). |

### Child-project checks (`--child-checks`, opt-in)

If your account holds `roles/run.viewer` and `roles/logging.viewer` in the child project, `--child-checks` (off by
default) checks a `PRIVATE_IAP` workload from the platform's own signals instead of reporting it not probed:

1. The Cloud Run service in the workload's region whose URL is the confirmed service URL: its latest ready revision is
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
| `permission denied reading ... in <child project>` | Your account lacks `roles/run.viewer` or `roles/logging.viewer` in the child project: `ERROR (permission denied)` (exit 5), never a pass. Without `--child-checks` the canary still needs read access to the child project's Cloud Run services (see Prerequisites). |

The canary never changes access and never follows a redirect. Only the sign-in host of a redirect is printed.

## Exit codes

| Code | Meaning |
| :--- | :--- |
| 0 | Deployed, and the health check passed (`PUBLIC_APP`, `PRIVATE_IAM`; `PRIVATE_IAP` only with `--child-checks`) |
| 1 | The pipeline failed (typed error printed) |
| 2 | Usage error, or `--product-id` already exists |
| 3 | Timed out (`--timeout-min`), or nothing was submitted within `--submit-wait-min` |
| 4 | The run succeeded, but: the health check failed; a `PRIVATE_IAP` service is not behind IAP; no service URL was reported; the recorded URL is not a plain `https://<host>` on `run.app` (`SERVICE_URL_REFUSED`); the complete Cloud Run listing holds no matching service, the child project is not in the managed-workloads folder, or the record names no child project (`SERVICE_URL_NOT_CONFIRMED`); a `PRIVATE_IAM` service is public by its answer, its invoker setting or its IAM policy, or a Google sign-in redirect comes from a service without `iapEnabled` (`ACCESS_RECORD_MISMATCH`) |
| 5 | A prerequisite is missing: a tool, a `gcloud` login, read access to the records, to the host's vending service, or to the child project (its ancestry, its Cloud Run services, a service's IAM policy; with `--child-checks`, also Cloud Logging): `ERROR (permission denied)`; the managed-workloads folder cannot be read from the vending service (`MANAGED_FOLDER_UNKNOWN`); the child project's ancestry or its Cloud Run listing cannot be read (`ANCESTRY_UNAVAILABLE`, `CLOUD_RUN_API_UNAVAILABLE`: no answer, 429 and 5xx are tried three times, any other error is reported at once with its HTTP code); a Google API answer larger than 16 MiB (`API_ANSWER_TOO_LARGE`); or a record value is not plain text in its exact format (`RECORD_VALUE_REFUSED`) |
| 6 | Deployed, health not probed from the command line: `HEALTH_NOT_PROBED_PRIVATE_IAP` (IAP is in front; check `/health` in a browser), `HEALTH_NOT_PROBED_PRIVATE_IAM` (no audience-bound token: a user login, or a token bound to another audience) or `HEALTH_NOT_PROBED_NO_ACCESS_RECORD` (the record has no access mode and the service refused the anonymous request) |

## After the canary

The canary workload is a sandbox: it expires on its own, or you can decommission it in the Control Center. On a failure, the [diagnose-workload runbook](../.agents/skills/stackvend-diagnose-workload/SKILL.md) takes the investigation from the stage and error class the canary printed.
