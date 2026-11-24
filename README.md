# StackVend

> [!IMPORTANT]
> This project is not provided by Google and does not come with any support or warranties.

> **Full Stack IaC and Software Vending Engine** for Google Cloud, with AI agents across the whole software delivery lifecycle

[![Version](https://img.shields.io/badge/version-v0.9.1--preview.3-orange.svg)](VERSION)
[![Status](https://img.shields.io/badge/status-public_preview-orange.svg)](#project-status)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![IaC OpenTofu](https://img.shields.io/badge/IaC-OpenTofu-FFDA00?logo=opentofu&logoColor=black)](https://opentofu.org/)

## Project status

> [!WARNING]
> **StackVend is a public preview.** It is an independent open-source proof of concept, **not** an official Google product, and comes with no support, warranty or SLA (all code is provided "AS IS").
>
> * **Not for production use.** Interfaces, data models and behavior change without notice.
> * **Security hardening is in progress.** Do not run it against projects, organizations or billing accounts you cannot afford to put at risk. Use a dedicated, disposable Google Cloud environment and the authenticated ingress mode, and see [`SECURITY.md`](SECURITY.md) for how to report problems.
> * **Review generated infrastructure.** StackVend uses LLMs to generate application code and infrastructure-as-code and can create projects, IAM bindings and billable resources. Read what it produces before it is applied, and keep budgets and billing limits in place.
> * Documentation is verified against the code on a best-effort basis; where they differ, the code wins.
> * **Read the [known limitations](documentation/known-limitations.md)** first: regulated compliance profiles and Helm charts are not supported yet, each workload runs in one region from an administrator-approved list (the platform itself is installed in `us-central1`), a new install runs each workload's Terraform as that workload's own deployer (an existing install keeps running it with the platform's own account until an administrator moves it to the per-workload runner identity), some Terraform operations are not available with the per-workload runner identity yet, StackVend creates no billing budgets for workloads, and running workloads are not repaired automatically.
> * **Releases.** From `0.9.1-preview.3` on, releases are planned for Tuesdays, at most once a week, as numbered preview steps (`X.Y.Z-preview.N`) with occasional roll-ups (`X.Y.Z`), each with a signed tag and its own section in [`CHANGELOG.md`](CHANGELOG.md). A week with nothing ready is skipped, and security fixes can ship on any day. See [Updating an installation](#updating-an-installation).

## What it is

StackVend is an **AI-driven developer swarm for Google Cloud**. AI agents take a product specification through the whole delivery pipeline to a tested, deployed workload in its own isolated child project: an AI architect agent designs the plan and an AI red-team critic agent reviews it, an AI lead developer agent splits the work among AI junior developer agents (backend, frontend, database, infrastructure as code, tests, DevOps) or handles a small change alone, and after the generated tests and security scans run, an AI reviewer agent checks the result for security and adherence to the spec. Human approval gates and deterministic checks (preflight sanitizers, a pre-commit verifier, OpenTofu validation, a cost estimate and policy checks) sit around the AI agents' steps; [`documentation/known-limitations.md`](documentation/known-limitations.md) lists what they do not cover yet.

The pipeline:

**Spec intake and pre-discovery** (organization policies, quotas) -> **dual-architect consensus** (architect plus red-team critic) -> **advisory compliance review, cost estimate and approval gates** -> **project vending** (child project and repository) -> **developer swarm** (lead developer plus specialist juniors, or a solo fast path) -> **preflight sanitization and verifier** -> **QA gatekeeper and release pull request** -> **OpenTofu/Terraform apply** -> **Day-2 governance** (FinOps budgets, SRE log sentinel, sandbox expiry).

It is built from Cloud Run services and jobs, MCP tool servers, Google Cloud Workflows and Firestore, and uses Gemini models (via Vertex AI or an AI Studio key). Specifications can be typed or uploaded in the Control Center, or dropped in a Google Drive intake folder.

**Less than $10 a month when idle, with the default network design.** StackVend runs serverless: its Cloud Run services scale to zero by default and its jobs run only on schedule, so with no build running the only compute is a few short scheduled housekeeping jobs. An idle install pays mostly for one always-on private network endpoint (about $7 a month at list prices) that the platform's internal-only services use to reach each other, plus small DNS, scheduling and storage charges (container image storage grows with each platform update). That is the default network design; the Cloud NAT alternative costs about $1 to $35 a month plus traffic instead (see [Configuration](documentation/configuration.md#platform-network-internal-only-host-services)). AI model calls are billed by usage and come almost entirely from builds, including builds the nightly code scanner can start; each deployed workload is billed in its own child project.

> **Naming.** The product is called StackVend; "Project Castor" is its original codename. Many internal identifiers (Cloud Run services, service accounts, buckets, secrets, some environment variables and Terraform variables) still start with `castor`. They are shown exactly as they exist in the code.

For a conceptual overview see [`documentation/overview.md`](documentation/overview.md) and [`documentation/architecture.md`](documentation/architecture.md).

---

## Repository layout

```text
.agents/skills/        Runbooks for AI coding assistants (e.g. Google Antigravity; invoked as /stackvend-*)
.github/               Issue/PR templates and GitHub Actions workflows
apps/
  control-center/      Web UI and REST API (Flight Deck, approvals, settings)
  orchestrator-gateway/ Agent hub: architect, compliance, developer, gatekeeper, QA auditor, release
  project-vending/     Child project creation, billing, IAM, Workload Identity Federation
  spec-ingestion/      Google Drive intake poller and webhook
  git-server/          Serverless Git provider (Cloud Storage backed)
  qa-runner/           Sandboxed test and scan runner (job)
  finops-enforcer/     Budget breach enforcement (job)
  log-sre-sentinel/    Error fingerprinting and remediation trigger
  refactor-scanner/    Scheduled code-scan job (being reworked)
  sandbox-cleaner/     Expired test-sandbox cleanup (job)
  infra-rollback/      Terraform state rollback (job)
  sre-digest/          Weekly error digest (job)
mcp-servers/           MCP tool servers: terraform (also the tf-applier job), kubernetes, gcloud,
                       github, workspace, infracost, compliance, agent-builder
shared/                Shared Python libraries (replicated into several services; see CONTRIBUTING.md)
infra/platform/        Terraform for the StackVend host platform itself
infra/modules/         Golden Terraform modules used by generated workloads
workflows/             Cloud Workflows definitions (main_orchestrator.yaml, sre_remediation.yaml)
scripts/               pre-bootstrap.sh (start here: checks your access, prepares the project and folder, runs bootstrap.sh), bootstrap.sh, apply.sh, deploy-services.sh
tests/                 Root pytest suite
documentation/         Public documentation
```

---

## Quick start

> Use a dedicated Google Cloud project. Installing creates billable resources. See also the more detailed [Quickstart](documentation/quickstart.md).

### What you need

* **Google Cloud project** with billing enabled (the platform host project), and Owner on it.
* **`gcloud`** installed and authenticated (`gcloud auth login`, `gcloud auth application-default login`), plus **OpenTofu 1.10 or later** installed (installs are verified with 1.13.x). Also `python3` and `curl` on `PATH` (the install scripts use them). The installer checks for all of these, including the OpenTofu version, and stops with a clear message. It installs none of them itself except OpenTofu, which `scripts/pre-bootstrap.sh`, the installer and `scripts/apply.sh` offer to install into `~/bin` when it is missing or too old. Google Cloud Shell is a convenient place to run everything once OpenTofu is installed there (Cloud Shell does not ship it).
* **A Google Cloud organization, a managed-workloads folder (`folders/<FOLDER_ID>`) and a billing account.** Every workload is created in its own child project under that folder and linked to that billing account, so StackVend cannot deploy a workload without them. The installer needs *Folder IAM Admin* (or *Folder Admin*) on the folder, and *Tag Administrator* on the organization for the deletion-safety tag. You can skip them at the installer's prompts, but then no workload can be deployed; without the organization or the folder, or without *Tag Administrator*, the installer stops unless you answer yes to `Continue without deletion safety? [y/N]` (with deletion safety off, StackVend refuses every child-project delete).
* *Optional:* a GitHub user or organization (or choose the serverless Git provider to avoid GitHub entirely).
* **Gemini access:** Vertex AI through IAM, no API key needed (the installer does not ask for one; an install whose Secret Manager secret `castor-gemini-api-key` already has an enabled version keeps using that Google AI Studio key for the Control Center assistant).

> **Engine and licensing note.** OpenTofu (MPL-2.0) is the engine for the platform install. HashiCorp Terraform 1.5.x (the last MPL release) cannot install the platform: its configuration uses a `removed` block with `lifecycle`, which needs OpenTofu 1.10 or later (Terraform 1.7 or later). Terraform 1.10 or later passes the installer's version check but is not verified with the platform and is BUSL licensed. For workloads, the Terraform MCP server / `tf-applier` runs OpenTofu and refuses Terraform 1.6 or later.

> **Billing roles (post-install).** Terraform grants *Billing Account User* on the billing account to `sa-project-provisioner` and `sa-castor-developer`, and *Billing Account Viewer* to `sa-stackvend-control-center`, when the person running the install is a *Billing Account Administrator* (a read-only check runs before the plan; leave `bind_billing_iam` unset). Without that role the install still succeeds: the grants are skipped, the installer prints them as a post-install step with the exact commands, child projects are not linked to billing until they exist, and the Control Center Settings page shows which service account is missing its grant. See [Post-install: billing access](documentation/quickstart.md#post-install-billing-access).

### 1. Clone

```bash
git clone https://github.com/<owner>/stackvend.git     # or your fork
cd stackvend
```

### 2. Run the installer

**Start here:**

```bash
bash scripts/pre-bootstrap.sh
```

`scripts/pre-bootstrap.sh` is the front door. It checks, read-only, that your account has the rights the install needs and prints the exact grant command for anything missing (if you can set IAM on the organization, it also offers to grant the two organization roles, Tag Administrator and Organization Policy Administrator, both organization-wide; you type `yes` for each); creates the host project, links it to billing and creates the managed-workloads folder if you ask it to; offers to install OpenTofu when it is missing (Cloud Shell has none); and then asks `Run scripts/bootstrap.sh now with these values? [Y/n]` and hands over to the installer with your answers filled in. You run `bash scripts/bootstrap.sh` on its own only to re-run the installer later.

The interactive installer asks for the project ID, region and zone, organization, billing account and managed-workloads folder (the installer lets you skip all but the project, but no workload can be deployed without the organization, billing account and folder), environment tier, VCS provider, GitHub organization (the GitHub provider is organization-only), and the **ingress posture**:

* *Enterprise Authenticated (recommended)*: restricts the Control Center with Google Direct IAP and authorizes the deploying account.
* *Public Sandbox*: allows unauthenticated invocation, relying on in-app login only. For short-lived evaluation only.

It then enables APIs, writes `infra/platform/<your-project-id>.tfvars` (one file per install; it refuses to run while an `infra/platform/terraform.tfvars` exists, because OpenTofu would load that file into every run), applies the platform Terraform (stage 1) and offers to build and deploy all services and jobs from source with Cloud Native Buildpacks (stage 2, `scripts/deploy-services.sh --all-jobs`).

### 3. Open the Control Center

The installer prints the Control Center URL (also available as the `control_center_url` Terraform output). Sign in with an authorized Google account: behind Direct IAP (the default) an account of your organization, with no OAuth client of your own. Only on an install with neither public ingress nor Direct IAP does `gcloud run services proxy product-control-center-ui --port 8080 --project <your-project-id>` expose it on `http://localhost:8080` (use Chrome or Firefox; Safari will not keep the `Secure` session cookie over plain HTTP); see the [quickstart](documentation/quickstart.md#3-open-the-control-center).

### Updating an installation

To a release tag, in one guided run (fetch the tag and verify its signature, read-only plan, confirm, `apply.sh apply`, `deploy-services.sh --all-jobs`, smoke check; it refuses a working tree with changes):

```bash
PROJECT_ID=<your-project-id> bash scripts/upgrade.sh <tag>      # for example v0.9.1
```

An install on `0.9.0-preview` or `0.9.1-preview.1` must update this way: the Control Center's **Update StackVend** button of those releases cannot resolve a release tag (it stops with `TAG_UNRESOLVED` and changes nothing). The button works on an install that already runs `0.9.1-preview.2` or later, for the releases after it.

In a fork, the release tags are on the official repository, not on your `origin`: add it as a remote (for example `git remote add upstream https://github.com/asaslaw/stackvend.git`) and pass `--remote=upstream`; this applies the upstream release, not your fork's `main`. Before anything of the release runs, `upgrade.sh` verifies the tag's SSH signature against `scripts/release/allowed_signers` of the checkout you installed from, and refuses an unsigned tag or one signed by another key; for your own unsigned tags pass `--trust-unsigned` (it prints a red warning). From `0.9.1-preview.2` on it also refuses an annotated tag whose own name is not the tag you asked for (an older signed release published under a newer name), with or without `--trust-unsigned`. Never pass `--trust-unsigned` for an official release. See [Known Limitations](documentation/known-limitations.md).

**On `0.9.0-preview` or `0.9.1-preview.1`, check the tag yourself first.** The `upgrade.sh` that runs is the one of the release you installed, and those releases do not check the name inside the tag. Before you run it, from the checkout you installed from (in a fork, `<remote>` is the official repository's remote):

```bash
git fetch --no-tags <remote> refs/tags/<tag>:refs/tags/<tag>
git cat-file tag refs/tags/<tag> | sed -n 's/^tag //p'     # must print exactly one line: <tag>
git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=scripts/release/allowed_signers verify-tag refs/tags/<tag>
```

Run `upgrade.sh` only when the name line is exactly the tag and `verify-tag` reports a good signature with the `allowed_signers` of the checkout you are on.

Or step by step, from a clean checkout. Verify the tag before you check it out: the release's scripts run with your credentials.

```bash
git fetch --no-tags origin refs/tags/<tag>:refs/tags/<tag>   # in a fork: the official repository instead of origin
git cat-file -t refs/tags/<tag>                              # must print: tag
git for-each-ref --format='%(tag)' refs/tags/<tag>           # must print <tag> itself
git -c gpg.format=ssh -c gpg.ssh.program=ssh-keygen -c gpg.program=false -c gpg.openpgp.program=false \
    -c gpg.x509.program=false -c gpg.ssh.allowedSignersFile=scripts/release/allowed_signers verify-tag refs/tags/<tag>
git checkout --detach 'refs/tags/<tag>^{commit}'             # only after all three checks passed
bash scripts/apply.sh apply                        # first, only if files under infra/platform/ changed
bash scripts/deploy-services.sh                    # all services (add --all-jobs for batch jobs)
bash scripts/deploy-services.sh control-center     # or one service
```

`verify-tag` must report a good signature from the key in `scripts/release/allowed_signers` of the checkout you are on (the one you installed from), never the release's own copy. It checks the signature only, not that the tag object was made for the name you fetched: that is what the `%(tag)` line checks.

### Your configuration is backed up automatically

The platform's Terraform state is stored in `gs://castor-tfstate-<your-project-id>/platform/state/`. The generated `infra/platform/<your-project-id>.tfvars` is not committed (it holds IDs, e-mail addresses and switches, no secrets). The installer copies it to `gs://castor-tfstate-<your-project-id>/platform/<your-project-id>.tfvars` at the end of the install, and `scripts/apply.sh` refreshes that copy after every successful apply. On a new machine or a fresh clone, `PROJECT_ID=<your-project-id> bash scripts/apply.sh plan` offers to restore the file from that copy (see [Configuration](documentation/configuration.md#backup-and-restore-of-the-vars-file)).

### Manual installation (without the wizard)

```bash
cp infra/platform/terraform.tfvars.example infra/platform/<your-project-id>.tfvars   # edit: project_id, region, ingress posture, admin_email, VCS, ...
PROJECT_ID=<your-project-id> bash scripts/apply.sh init     # creates the state bucket gs://castor-tfstate-<your-project-id> (asks first), binds the backend
PROJECT_ID=<your-project-id> bash scripts/apply.sh apply    # reviewed plan, typed confirmation, API pre-enable, apply
PROJECT_ID=<your-project-id> bash scripts/deploy-services.sh --all-jobs
```

Plain `tofu init && tofu apply` does not work: the backend bucket is passed by the wrapper, and the configuration expects the state bucket to exist. See the [Quickstart](documentation/quickstart.md#doing-it-by-hand) for what only the installer does.

All variables are documented in [`infra/platform/variables.tf`](infra/platform/variables.tf) and summarized in [`documentation/configuration.md`](documentation/configuration.md).

---

## Running your own copy

Every install is a stable workload manager: StackVend builds and manages your applications and never modifies its own code or auto-heals its own services. A fork or private copy of StackVend deploys the same way as any install:

* **Update from your own repository:** publish signed release tags there, and point the release source at it (Settings ▸ Upgrades ▸ **Release source**, or `scripts/release-source.py set`) with your signing keys.
* **Or deploy your own changes directly** with `bash scripts/deploy-services.sh` (add `scripts/apply.sh apply` first when `infra/platform/` changed). There are no push-to-deploy triggers: a change reaches an install only when you run one of these.

**Upstream sync: until your default branch has the verified workflow, keep the sync off and the token deleted.** Scheduled runs use the workflow file on your default branch, and the sync ignores pre-release tags, so no fork receives the verified workflow through the sync itself. The workflow of releases up to `0.9.1-preview.1` merges the newest tag without checking its signature, and its pull request body does not show changed scripts or release keys. Turn it off and delete the token now:

```bash
gh variable set STACKVEND_UPSTREAM_SYNC --body false
gh secret delete STACKVEND_SYNC_TOKEN
```

Then merge `v0.9.1-preview.2` (or a later release) by hand with the verified steps below, and only then turn the sync on again. Do not merge a sync pull request opened by the old workflow without running the same checks on its tag.

**Opt-in upstream sync (`.github/workflows/sync-upstream.yml`):** Weekly upstream sync is **off by default**. To enable it in a fork, set the GitHub repository variables `STACKVEND_UPSTREAM_REPO` (the upstream `owner/repo` slug) and `STACKVEND_UPSTREAM_SYNC=true`:

```bash
gh variable set STACKVEND_UPSTREAM_REPO --body example-org/stackvend
gh variable set STACKVEND_UPSTREAM_SYNC --body true
```

When enabled, the workflow reads the upstream repository without credentials, so the upstream must be public (otherwise the run stops with `SYNC_UPSTREAM_FETCH_FAILED`). It is **tag-based** (it syncs only the newest `vX.Y.Z` semantic version release tag from upstream tags, never `main`, and ignores pre-release tags), **verified** (from `0.9.1-preview.2` on: it merges the tag only if it is an annotated tag whose own name is that tag, signed with SSH by a key in `scripts/release/allowed_signers` of your repository's default branch, never the tag's own list; otherwise the run stops with one error that names the tag and the manual path below, and nothing is pushed, so one unsigned or wrongly signed higher tag upstream stops the sync until it is removed there) and **PR-only** (it creates a `chore/sync-upstream-vX.Y.Z` branch from the repository's default branch and opens a pull request against it, also when a manual run is started from another branch; it pushes only that branch, never `main`, and never auto-merges). The pull request body states `needs apply.sh: yes` or `needs apply.sh: no` (computed after merging the release tag from changed paths under `infra/platform/**`, `infra/modules/workflows/**` and `workflows/**`), lists the matching paths, lists every changed trust-anchor path with the tag object, its commit and its signer ("none changed" when there is none; the paths are chosen by shape: `scripts/`, `.github/`, the release keys, the upgrader and release-source files, any path with a component that starts with `.` at any depth, every Markdown file outside `documentation/`, dependency pins and build or test configuration such as `requirements*.txt`, `conftest.py`, `pyproject.toml`, `setup.py`, `Makefile` or `*.pth` at any depth, and every path with a non-ASCII character), and directs you to the release's `CHANGELOG.md` entry for the upgrade run order. **Sync pull requests must be merged with a merge commit (do not squash or rebase)** so the upstream tag commit remains an ancestor of `main` for future `git merge-base --is-ancestor` checks. If you close a sync pull request without merging it, the workflow skips that release (one log line) until upstream publishes a newer `vX.Y.Z` tag; to take the release later, reopen the pull request. If the merge has conflicts, the run fails with one error line that tells you how to merge the tag by hand.

By default the workflow uses the built-in `GITHUB_TOKEN`. That has two limits, both because GitHub keeps that token from starting more workflow runs or changing workflow files: pull requests it opens do not trigger other workflows such as CI (re-run CI before merging, for example by closing and reopening the pull request or pushing a commit), and it cannot push a release that changes files under `.github/workflows/**`. The optional repository secret `STACKVEND_SYNC_TOKEN` (a fine-grained personal access token for this repository with read and write access to Contents, Pull requests and Workflows, or a classic token with the `repo` and `workflow` scopes) removes both limits, and that is also its risk: with it, the workflow files of the pushed branch, which come from upstream, run in your repository with its secrets. The old workflow kept the token in the checkout for every step; the verified workflow uses it only in the push and pull-request step, and pushes only a verified release. Add it, if at all, only after the verified workflow is on your default branch. Without it, merge a release that changes workflow files by hand, verified, from a clean checkout of your default branch:

```bash
git fetch --no-tags https://github.com/<owner>/<repo>.git refs/tags/vX.Y.Z:refs/tags/vX.Y.Z
git cat-file -t refs/tags/vX.Y.Z                      # must print: tag
git for-each-ref --format='%(tag)' refs/tags/vX.Y.Z   # must print: vX.Y.Z
git -c gpg.format=ssh -c gpg.ssh.program=ssh-keygen -c gpg.program=false -c gpg.openpgp.program=false \
    -c gpg.x509.program=false -c gpg.ssh.allowedSignersFile=scripts/release/allowed_signers verify-tag refs/tags/vX.Y.Z
git merge -m "Merge StackVend vX.Y.Z" 'refs/tags/vX.Y.Z^{commit}'   # only after all three checks passed
```

`verify-tag` reads the trusted keys from `scripts/release/allowed_signers` of your default branch (the file in your working tree before the merge). It checks the signature only; the `%(tag)` line checks that the signed tag object was made for the name you fetched.

---

## Optional integrations

### GitHub repository vending

To let StackVend create repositories and pull requests for workloads, store GitHub credentials in the Secret Manager secret `castor-github-app-private-key` (created empty by the platform Terraform):

* **A GitHub organization with a GitHub App.** Create an app with repository permissions *Administration*, *Contents*, *Pull requests*, *Secrets* and *Workflows* set to Read & Write, no webhook, install it on the organization, and generate a private key.
* **Organizations only.** StackVend acts through short-lived GitHub App installation tokens, and those can create repositories only in an organization where the App is installed. Personal GitHub accounts are not supported; repository vending for an owner that is not an organization stops with `GITHUB_OWNER_NOT_ORGANIZATION`.

```bash
cat << 'EOF' | gcloud secrets versions add castor-github-app-private-key --project=<your-project-id> --data-file=-
{
  "app_id": "<APP_ID>",
  "installation_id": "<INSTALLATION_ID>",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
}
EOF
```

### Google Drive intake

Optional. Create folders for intake and status (the platform's variables name `01_Inbox_Requests`, `02_In_Progress` and `04_Completed`), share them with the architect service account `sa-castor-architect@<your-project-id>.iam.gserviceaccount.com` as Editor, and set `enable_drive_spec_polling = true` plus the folder ID variables in `infra/platform/<your-project-id>.tfvars`. The `spec-ingestion` service is polled on a schedule. Only the configured folders are polled: automatic discovery of every `01_Inbox_Requests` folder shared with the service account is off by default until authorized submitters are supported (Settings → Platform Governance → *Drive Folder Auto-Discovery*). A new workload that arrives this way is private (Google sign-in through IAP); it lists the spec file's owner when Drive's file information provides one, otherwise it waits until an administrator lists who may use it.

### Access control

* The deploying account (or `admin_email`) is seeded as an `ADMIN` in Firestore (`authorized_users`). Admins add other users and roles (`ADMIN`, `WORKLOAD_MANAGER`, `VIEWER`).
* `authorized_invoker_members` accepts `user:`, `group:` and `domain:` principals for the IAP-protected ingress.
* Behind Direct IAP (the default) no OAuth consent screen and no OAuth client are needed. Public ingress needs the Control Center's own Web OAuth client and a consent screen (*Internal* if everyone who signs in belongs to your organization). An organization that enforces domain-restricted sharing (`constraints/iam.allowedPolicyMemberDomains`) refuses the public `allUsers` binding, so use Direct IAP there.

---

## Governance features

* **Human-in-the-loop approvals.** The workflow can pause for an operator to approve the architecture plan (when plan approval is required) and to approve a release pull request (when human review is required). Pending decisions appear in the **HITL Approvals** tab; operators approve, reject or request rework (`POST /api/approvals/{id}/decision`).
* **Per-workload policies** (`PATCH /api/workloads/{product_id}/policies`): `code_freeze`, `sre_auto_healing_enabled`, `refactor_scanner_enabled`, `require_human_code_review`, `auto_merge`, `require_plan_approval`.
* **FinOps.** Budget ceilings, breach policies (alert only, scale to zero, require confirmation, unlink billing) and a nightly spend sync with run-rate projection. The breach policy acts on Cloud Billing budget notifications, and StackVend does not create those budgets yet: see the [known limitations](documentation/known-limitations.md).
* **Sandbox lifecycle.** Temporary workloads expire after 30 days by default unless extended (max 3 times, 90 days) or promoted. See [`documentation/workload-lifecycle.md`](documentation/workload-lifecycle.md).
* **Organization-policy awareness.** Effective organization policies for the target folder are read before planning. If the parent folder is an Assured Workloads folder, vended projects live inside that boundary, but StackVend does not detect the folder's regime yet (it needs an organization-level permission the installer does not grant): select the matching compliance profile yourself (see [known limitations](documentation/known-limitations.md#regulated-compliance-profiles-are-not-available-yet)).

### Scheduled jobs

Cloud Scheduler jobs created by the platform Terraform (time zone `America/New_York`):

| Job | Schedule | Action |
| :--- | :--- | :--- |
| `castor-spec-ingestion-poller` | every 5 minutes | Poll Drive intake folders (when enabled). |
| `castor-nightly-refactor-scan` | 02:00 daily | Run the refactor scanner job. |
| `castor-sandbox-ttl-cleaner` | every 2 hours | Run the sandbox garbage-collector job. |
| `castor-sre-telemetry-digest` | Sunday 03:00 | Run the weekly SRE digest job. |
| `castor-finops-nightly-spend-sync` | 03:00 daily | Run the spend sync job (`finops-spend-sync-job`). |
| `castor-sandbox-workload-sweeper` | 04:00 daily | Run the sandbox sweeper job (`sandbox-workload-sweeper-job`). |
| `stackvend-billing-alert-drain` | every 30 minutes | Run the billing alert drain job (`billing-alert-drain-job`). |

No scheduler or subscription calls the Control Center: its scheduled work runs as Cloud Run jobs that write Firestore,
and the Control Center reads Firestore.

---

## What gets deployed for each workload

Each workload gets its own Google Cloud project and repository, with this standard layout:

```text
<product_id>/                        # default repository name (the workload id)
├── apps/<service>/                  # one directory per service: main.py, requirements.txt, Procfile, ...
├── infra/workload/                  # main.tf, variables.tf, outputs.tf (+ custom.tf for bespoke resources)
├── .github/workflows/deploy-<service>.yml   # path-filtered CI/CD per service
├── docs/planning/                   # architecture and implementation plans
└── tests/
```

* **Keyless CI/CD.** GitHub Actions authenticates to Google Cloud with Workload Identity Federation (a per-workload pool `castor-gh-pool` and deployer service account `sa-gh-deployer`, restricted to that workload's repository), then builds with Cloud Native Buildpacks and deploys to Cloud Run. There are no Dockerfiles and no stored service-account keys.
* **Golden modules and bundles.** Generated infrastructure is steered toward the catalog in `infra/modules/` and the built-in composite bundles; see [`documentation/composite-bundles.md`](documentation/composite-bundles.md).
* **Kubernetes.** The `kubernetes` MCP server applies manifests and reads status, logs and events on child GKE clusters, using short-lived credentials.

---

## AI models

StackVend uses Google's `google-genai` SDK with Gemini models. The model for each role (architect, developer, repair, assistant) is a platform setting, with `ARCHITECT_CRITIC_MODEL` as an environment override for the critic; new installs default every role to `gemini-4-carbon` with `gemini-4-argon`, then `gemini-3.8-flash`, then `gemini-3.7-flash` as the fallbacks (several times the per-run cost of `gemini-3.8-flash`; any Gemini model id can be chosen in Settings). Two backends are supported: an AI Studio API key (Secret Manager secret `castor-gemini-api-key`, or `GEMINI_API_KEY`) and Vertex AI through the services' service accounts. See [`documentation/configuration.md`](documentation/configuration.md#2-ai-model-settings).

---

## Working with AI coding assistants

The repository ships runbooks for AI pair-programmers in [`.agents/skills/`](.agents/skills/) (index in [`.agents/skills/README.md`](.agents/skills/README.md)) and a rule sheet in [`AGENTS.md`](AGENTS.md). Tools that use the `.agents/skills` convention, such as Google Antigravity, load them directly; others load them through a tool-specific link. They are invoked as slash commands:

| Command | Purpose |
| :--- | :--- |
| `/stackvend-red-team-review` | Adversarial review of a plan before implementation (required for changes to the core IaC generation and validation files). |
| `/stackvend-extend` | Guide for adding major capabilities across the platform. |
| `/stackvend-golden-module` | Authoring and registering golden modules and bundles. |
| `/stackvend-troubleshoot` | Diagnosing failed workload builds and deployments. |
| `/stackvend-diagnose-workload` | Read-only fault isolation and remediation planning. |
| `/stackvend-monitor-live-workload` | Non-mutating monitoring of a running build. |
| `/stackvend-deploy` | Choosing between `scripts/apply.sh` (host infrastructure) and `scripts/deploy-services.sh` (services). |

---

## Roadmap

Nothing here is scheduled or promised. Items marked *exploratory* have no design yet. See [`documentation/README.md`](documentation/README.md#roadmap).

* Prompt-injection screening of incoming specifications (Google Cloud Model Armor).
* Running the evaluation harness ([dry runs](documentation/test-a-spec-locally.md) already ship) against prompt and model changes in CI.
* Optional separate application and infrastructure repositories per workload.
* Private module and bundle registries (GitLab, Bitbucket, Secure Source Manager).
* Capacity-aware region selection; brownfield adoption of existing projects.
* *Exploratory:* multi-cloud vending (AWS, Azure) and interactive clarification chat with the architect.

---

## Documentation

* [Documentation index](documentation/README.md)
* [Quickstart](documentation/quickstart.md) and [User & Operator Guide](documentation/user-guide.md)
* [Architecture](documentation/architecture.md), [Platform Internals](documentation/platform-internals.md) and [Configuration](documentation/configuration.md)
* [Composite Bundles](documentation/composite-bundles.md), [Workload Lifecycle](documentation/workload-lifecycle.md) and [Reference Examples](documentation/examples/README.md)
* [Known Limitations](documentation/known-limitations.md) and [Test a Spec Locally](documentation/test-a-spec-locally.md)
* [Developer Guide](documentation/developer-guide.md) and [Extensibility Guide](documentation/extensibility-guide.md)
* [Threat Model](documentation/threat-model.md) and [Audit Trail and Roles](documentation/audit-and-roles.md)
* [Contributing](CONTRIBUTING.md), [Security Policy](SECURITY.md), [Support](SUPPORT.md), [Code of Conduct](CODE_OF_CONDUCT.md), [Changelog](CHANGELOG.md)
* [Apache 2.0 License](LICENSE), [NOTICE](NOTICE) and [Third-party notices](THIRD_PARTY_NOTICES.md)
