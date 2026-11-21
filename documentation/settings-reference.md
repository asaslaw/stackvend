# Control Center Settings Reference

This page describes every control on the Control Center **Settings** page, what each one really does in the running
platform, and how to fix the warning cards the page can show. It is written from the code. Where the screen text
and this page disagree, this page describes what the services actually do; the differences are listed under
[Known gaps between the page and the platform](#known-gaps-between-the-page-and-the-platform).

For the stored schema (`system_config/platform_settings`) and the install-time Terraform variables, see
[Configuration](configuration.md). For everyday use of the Control Center, see the [User Guide](user-guide.md).

---

## Contents

1. [How the Settings page works](#1-how-the-settings-page-works)
2. [Status and warning cards](#2-status-and-warning-cards)
3. [FinOps & Budget Controls](#3-finops--budget-controls)
4. [Orchestration & Infrastructure](#4-orchestration--infrastructure)
5. [Agent AI Models & Limits](#5-agent-ai-models--limits)
6. [Platform Governance & Gates](#6-platform-governance--gates)
7. [Buildpack & Runtime Governance (Platform BOM)](#7-buildpack--runtime-governance-platform-bom)
8. [Settings Audit History](#8-settings-audit-history)
9. [The other Settings tabs](#9-the-other-settings-tabs)
10. [Per-workload governance controls](#10-per-workload-governance-controls)
11. [Stored settings that are not on the page](#11-stored-settings-that-are-not-on-the-page)
12. [Known gaps between the page and the platform](#known-gaps-between-the-page-and-the-platform)

---

## 1. How the Settings page works

### Who can use it

* The **Settings** tab is shown only to users with the `ADMIN` role, and every change made from it (settings,
  folders, modules, skills, prompts, users, emergency stop, tag backfill) is refused by the API for anyone else.
* Any signed-in user can *read* the platform settings through `GET /api/settings`; the settings audit log, which
  contains administrator e-mail addresses, is removed from that answer for non-administrators.

### Saving

The **Parameters** tab is one form. **Save Changes** sends the whole form at once:

* The complete document is validated before anything is written. One invalid value (out of range, an unknown model
  id, an unknown plan-approval policy) refuses the whole save with HTTP 422 and a list of the failing fields; nothing
  is stored.
* A successful save replaces the stored document, increases **Config Version**, records who saved it and when, and
  adds an entry to the [Settings Audit History](#8-settings-audit-history) with every changed field (old and new
  value).
* **Config Version** stops you from overwriting someone else's save. A save sends the version the page loaded; if
  another administrator saved in between, the save is refused (HTTP 409, `SETTINGS_VERSION_CONFLICT`), nothing is
  stored, and the page says the settings were changed by someone else. Press **Reload** (your unsaved edits are lost)
  and make your change again. Adding or removing an agent directive (Multi-Agent Pipeline tab) also moves the
  version. The version check and the write are one Firestore operation (a write precondition), so two saves at
  the same moment cannot both pass: the later one gets the 409. An API request that sends no `version` is not
  checked against the page's version, but it still never overwrites a save that lands while it is being written.
* **Reload** reloads the stored settings and discards unsaved edits.
* **Reset Defaults** replaces *every* setting with its built-in default after a confirmation, and is audited
  (`RESET_DEFAULTS`). It also resets the governance switches (for example it turns maintenance mode off and turns
  generate mode and strict compliance gates back on) and the platform region. Note your current values before you
  use it.

### When a change takes effect

Each service keeps the settings in memory for up to **60 seconds**. The Control Center instance that saved the change
uses it immediately; every other service (orchestrator gateway, spec intake, project vending, the Terraform server)
picks it up within about a minute. A run reads each setting when it reaches the step that uses it, so a run already
in progress can see a change in its later steps (for example the destructive-change check at deploy). The
per-setting entries below say whether a setting applies to new workloads only, or to every run.

### When the settings cannot be read

If Firestore is unreachable or the stored document does not validate, the Parameters tab shows **Platform settings
could not be loaded** with the error code (`PLATFORM_SETTINGS_READ_FAILED` or `PLATFORM_SETTINGS_INVALID`) and the
failing fields. No default values are shown in place of the real ones, so you cannot overwrite good settings by
accident. Use **Retry** once Firestore is reachable, or **Reset to defaults** (audited; the audit history that still
validates is kept) to replace an invalid document.

While the settings are unknown, the platform takes the safe choice everywhere it matters:

| Decision | While settings are unreadable |
| :-- | :-- |
| New workloads, retriggers, deploys, Drive intake, gateway dispatch | Refused with HTTP 503 and the settings error code, nothing is started |
| Plan approval, human code review default | Approval / review required |
| Destructive Terraform changes | Stop for approval |
| Profile advisories | Need a human |
| Drive folder auto-discovery, generate mode | Off (generate mode too, although its default is on) |
| Budget of a new Drive-intake workload (project vending) | $40 |
| Budget notifications | No warning is recorded; the breach policy fires at 100 percent of the ceiling |
| Terraform lock wait and stale-lock report | 180 seconds and 20 minutes |
| Scale to zero, container memory and vCPU (Agent-mode Cloud Run) | Scale to zero; 512 MB and 1 vCPU |
| Model choice, token limits, thinking budget, tool versions | The last settings this service read, else the defaults |

A stored model id the platform does not know resets only that model field to its default (logged as
`UNSUPPORTED_MODEL_CONFIG`); every other stored setting still applies.

---

## 2. Status and warning cards

These cards sit at the top of the Parameters tab. They report on the install; most have no switch.

### UI Theme & Appearance

**Dark** / **Light** switches the Control Center's colors. It is stored in your browser only (it is not a platform
setting and is not audited). Safe.

### Google Cloud Billing card

Shows whether StackVend can link new child projects to billing:

* **Google Cloud Billing Not Configured** (*Standalone Mode*): no billing account id was given at install time.
  Child projects are not linked to billing automatically.
* **Google Cloud Billing Linked & Healthy**: the Control Center can read the billing account and both StackVend
  service accounts that need it (`sa-project-provisioner` and `sa-castor-developer`) hold Billing Account User.
* **Google Cloud Billing Access Not Detected** (*Action Required*): one of those checks failed. Each service account
  is listed as *Granted*, *NOT granted* or *Cannot verify*. Only grants on the billing account itself are visible; a
  grant made at organization level, or one with an IAM condition, shows as not granted or cannot verify.

**Fix for a service account marked NOT granted** (a Billing Account Administrator runs one of these):

1. Re-run the platform apply, which grants the role when the person running it is a Billing Account Administrator:
   `PROJECT_ID=<project-id> bash scripts/apply.sh apply`
2. Or grant it directly (the card shows the exact command with your values):
   `gcloud billing accounts add-iam-policy-binding <billing-account-id> --member=serviceAccount:<service-account-email> --role=roles/billing.user`
3. Or, in the Google Cloud console, open **Billing > Account Management** for the billing account, choose
   **Add principal**, paste the service account, select **Billing Account User**, and save.

**Fix for service accounts marked Cannot verify** (the Control Center cannot read the billing account's IAM
policy, usually because its own service account lacks Billing Account Viewer): the card shows the re-run of the
platform apply, where to run it, and the three grants the platform needs, filled with your values. A Billing
Account Administrator runs them (each adds one member and is safe to re-run):

```bash
gcloud billing accounts add-iam-policy-binding <billing-account-id> --member=serviceAccount:sa-project-provisioner@<project-id>.iam.gserviceaccount.com --role=roles/billing.user
gcloud billing accounts add-iam-policy-binding <billing-account-id> --member=serviceAccount:sa-castor-developer@<project-id>.iam.gserviceaccount.com --role=roles/billing.user
gcloud billing accounts add-iam-policy-binding <billing-account-id> --member=serviceAccount:sa-stackvend-control-center@<project-id>.iam.gserviceaccount.com --role=roles/billing.viewer
```

The console steps on the card still apply as well.

Then press **Recheck Status**. Until it is fixed, new child projects are created without billing (see
[Quickstart: Post-install: billing access](quickstart.md#post-install-billing-access)).

### VCS (Git provider) card

Shows the platform's default Git provider and whether its credentials work: provider, sign-in method, the target
organization, and the GitHub API rate limit. The GitHub owner must be an organization: a personal account (or an owner
GitHub does not know) shows **Owner Not an Organization** (`GITHUB_OWNER_NOT_ORGANIZATION`); new repositories are then
refused, but a workload whose repository already exists under a personal account still reuses it on redeploy.
**Recheck VCS Health** tests again.

**Switch Default to GitHub / Serverless Git** changes `governance.vcs_provider`, the provider used for new workloads
that do not choose one. It saves immediately and changes **only that setting**: unsaved edits in the Parameters form
stay unsaved (save or reload them as usual). The switch is recorded in the
[Settings Audit History](#8-settings-audit-history) and increases **Config Version**. If the stored settings do not
validate, the switch is refused (HTTP 409) until a **Save Changes** or **Reset Defaults** repairs them. If a
Settings save lands while the switch is being written, the switch is refused (HTTP 409, `SETTINGS_VERSION_CONFLICT`)
and nothing changes; reload and switch again. Existing
workloads keep their provider. The create form pre-selects Serverless Git when no GitHub credentials are found.

GitHub credentials are read from the Secret Manager secret `castor-github-app-private-key` (a JSON document with
`app_id`, `installation_id` and `private_key` for a GitHub App) or from the services'
environment; see [Configuration: GitHub](configuration.md#github). When the credentials do not work, the card shows
how to add that JSON document as a new version of the secret (`gcloud secrets versions add`).

### Install warning cards

The install never stops for a missing organization role; instead these cards say what is missing and how to fix it.
They are refreshed each time the Settings page loads. Several are about the **deletion safety tag**: StackVend only
deletes (decommissions, or lets a sandbox expire) a child project that carries this tag, so without it project
deletes are refused.

| Card | Severity | Meaning | Fix |
| :-- | :-- | :-- | :-- |
| **Deletion safety tag not set up** (`MANAGED_TAG_NOT_SET_UP`) | Warning | The tag does not exist, usually because the person who ran the install was not a Tag Administrator on the organization. StackVend cannot decommission any project. Lists the StackVend-vended projects without the tag. | See below. |
| **Projects vended before the deletion safety tag existed are untagged** (`MANAGED_TAG_BACKFILL_PENDING`) | Warning | The tag exists, but projects vended earlier are not tagged, so they cannot be decommissioned. Lists the projects that will be tagged. | Press **Bind deletion safety tag** (see below). |
| **Expired auto-delete sandboxes without the tag** (`MANAGED_TAG_SANDBOXES_EXPIRED`) | Info | These sandboxes passed their expiry while untagged. StackVend never tags them automatically, because the next daily sweep would then delete them. | An owner decision: review each project. StackVend will neither tag nor delete them. |
| **Projects without a vend-time record** (`PROJECTS_WITHOUT_PROVENANCE`) | Info | These workloads have no vend-time provenance record, so StackVend never tags or deletes them automatically. | Review them with the provenance backfill tool (below). |
| **Deletion safety status unavailable** (`GUARD_STATUS_UNAVAILABLE`) | Warning | Project vending did not answer, or answered with something unexpected. Project deletes stay refused until it answers. | Check that the project vending service is running and reachable, then reload Settings. |
| **Control Center cannot read the billing account** (`CC_BILLING_VIEWER_MISSING`) | Warning | The Control Center's service account lacks Billing Account Viewer, so the billing card is incomplete. Installs and builds are not affected. | The command on the card (below). |
| **Billing access not checked** (`BILLING_STATUS_UNAVAILABLE`) | Info | The billing check itself failed. | Reload Settings; if it persists, check the Control Center logs. |

A card that lists projects may say that only the first records were checked; the list can then be incomplete.

While the tag is not set up, a banner at the top of every Control Center page says so, for every signed-in user (an
administrator also gets an **Open Settings** button that jumps to the card), and the new-workload and Deploy to Folder
forms show the same fact above the submit button (you can still submit). A lighter banner points to **Bind deletion
safety tag** while older projects are untagged. If the status cannot be read, the banner says *Couldn't check deletion
safety status* instead. **Hide for this session** shrinks the banner to one line until you close the browser tab.
The banner and these cards report whether the tag itself is set up; a project whose tag could not be read, or one
beyond the first 200 records of a cut-short scan, is not flagged by the banner, so check the card details in Settings.

**Deletion safety tag not set up: fix**

1. If the organization and the managed workloads folder are configured, someone allowed to change the organization's
   IAM grants the Tag Administrator role to the person who will run the install:
   `gcloud organizations add-iam-policy-binding <org-id> --member=user:<tag-admin-email> --role=roles/resourcemanager.tagAdmin`
   If the card says they are not configured, first set `organization_id` and `castor_managed_workloads_folder_id` in
   `infra/platform/<project-id>.tfvars`.
2. That person re-runs the platform apply: `PROJECT_ID=<project-id> bash scripts/apply.sh apply`
3. Reload Settings. If projects vended earlier are now listed under *untagged*, do the backfill below.

**Bind deletion safety tag (backfill)**

The button asks for confirmation, then asks project vending to bind the tag to every project that its own vend-time
record and labels prove StackVend created. Nothing is deleted, and pressing it again is safe (tagged projects are
skipped). A large backfill can take longer than the Control Center's 120-second wait; vending keeps going, so press
the button again later to see the final counts. **Be aware:** a sandbox whose recorded expiry has not passed becomes
deletable by the daily sweep at that expiry once it is tagged. Extend or promote such sandboxes first if you want to
keep them.

**Projects without a vend-time record: fix**

An owner runs the provenance backfill from `apps/project-vending/` for named workloads only:

```bash
python backfill_provenance.py --project <product-id>            # dry run (default): prints what would be written
python backfill_provenance.py --project <product-id> --apply    # writes labels, the tag and the provenance record
```

Brownfield / adopted projects, platform workloads and projects outside the managed workloads folder are skipped. A
backfilled project gets no sandbox expiry: it can only be decommissioned through an approved decommission, never by
the sandbox sweep.

**Control Center cannot read the billing account: fix** (a Billing Account Administrator):

```bash
gcloud billing accounts add-iam-policy-binding <billing-account-id> \
  --member=serviceAccount:sa-stackvend-control-center@<project-id>.iam.gserviceaccount.com \
  --role=roles/billing.viewer
```

### Terraform runner identity card

Administrators only. The card shows the install's **Terraform runner identity**:

* **Shared**: every workload's OpenTofu runs as the platform's service account. This is a known limitation
  ([known-limitations.md](known-limitations.md)), and the card shows it as a warning (`RUNNER_IDENTITY_SHARED`).
* **Per workload**: each workload has its own deployer account and state bucket in its own project.

The install declares its mode in the platform Terraform (`tf_runner_identity`, passed as
`STACKVEND_TF_RUNNER_IDENTITY`). An install that declares **Per workload** is final: the card shows the mode and
cannot change it. A new install made with `scripts/bootstrap.sh` declares Per workload from its first apply, so on a
new install the card only shows the mode; the switch below is for an existing install that still declares Shared.

On an install that declares **Shared**, the card can switch the mode between Shared and Per workload without a
platform apply (FD-7L-F4), for the upgrade and for the rollback drill:

* Only a signed-in administrator can switch it, with a sign-in younger than 15 minutes, and must type the new mode
  (`PLATFORM` or `PER_WORKLOAD`) to confirm. Behind Identity-Aware Proxy the Control Center cannot see the sign-in
  time, so the card refuses (`RECENT_SIGN_IN_UNAVAILABLE`); on such an install, change `tf_runner_identity` and run
  `scripts/apply.sh` instead.
* Per workload is refused until the platform's step A is applied (`RUNNER_IDENTITY_STEP_A_MISSING`, with what is
  missing).
* Project vending keeps the mode in the guard database as a record it signs, `install_settings/runner_identity`
  (Shared or Per workload), and adds one signed entry per switch under `install_settings/runner_identity/changes`:
  the identity vending verified (the Control Center's service account), the administrator the Control Center named
  (`operator_attested`), when, from and to. Nothing is ever removed; the card shows the last ten entries. An install
  that was never switched has neither and is Shared. Vending re-signs the record when it is older than 72 hours
  (when the card is opened, at most hourly while vending runs, and in the `/runner-identity/resign` sweep), because
  Google rotates the keys that verify it.
* If the record is deleted after a switch (`RUNNER_MODE_RECORD_MISSING`), replaced by an older signed one
  (`RUNNER_MODE_RECORD_STALE`), or a change entry does not verify (`RUNNER_MODE_TAMPERED`), the card shows it as a
  warning and the services stop; switching the mode again from the card repairs it. A change entry with a version
  no switch can outrank (`RUNNER_MODE_LOG_CORRUPT`, the card names the document) cannot be repaired from Settings: a
  project owner removes that document in the Firestore console, then switches the mode again. Entries with a
  non-numeric version are ignored by every service and listed in the same warning for removal.
* A switch does not change operations that are already running: a vend uses the mode it read when it started, and a
  repository synthesized by Express keeps the backend choice made at synthesis. Switch when no vend or deploy is in
  progress.
* On a Shared install the services read the guard database for the mode (and, once the mode was switched, Google's
  certificate endpoint for the signature): when either is unreachable they stop with a typed error.
* Every service reads the record through one shared function and caches a successful read for 15 seconds, so a
  switch reaches every service within about 15 seconds. A record that exists but does not verify stops the readers
  with a typed class (see [fail-loudly-policy.md](fail-loudly-policy.md)); switching again from the card replaces it.

Moving an existing install to Per workload for good is still the backfill, then the platform apply (step B), which declares
`tf_runner_identity = "PER_WORKLOAD"`. The whole order (step A, switch, backfill, readiness check, step B) and what a
Per-workload install refuses today are in
[Configuration](configuration.md#terraform-runner-identity-shared-or-per-workload).

On a Per-workload install, the card lists these for each workload: the workload's own status (from its workload
record; `unknown` when that record cannot be read), the runner identity status, step B readiness, repository,
deployer account, state location and the last error. A line above the table counts live workloads, how many are
ready and not ready for step B, and closed workloads. Closed workloads (status `DECOMMISSIONED`, `ARCHIVED` or
`DELETED`) are folded under **Show N closed workloads** and have no **Run** button: there is nothing to backfill. It
has two kinds of button:

* **Dry run** lists every call the backfill would make for each workload. It writes nothing. A workload where the run
  would be refused for missing rights shows `DRY_RUN_STOP` with the class (`BACKFILL.NO_RIGHTS_ON_PROJECT` or
  `BACKFILL.NO_RIGHTS_ON_BUCKET`). For a state bucket that does not exist yet, the bucket rights are checked by the run
  right after it creates the bucket.
* **Run**, on a workload's row, backfills that one workload. A real backfill runs inside one request, so it names its
  workloads: at most 3 per request through the API (`BACKFILL.REAL_RUN_TOO_LARGE` otherwise), one per click on the
  card. Each run is recorded in that workload's audit log (`RUNNER_IDENTITY_BACKFILL_REQUESTED`). After you confirm,
  project vending does the following:
  * creates the deployer account, its owner grant, the broker grant and the state bucket. Each step is idempotent,
    and IAM grants are only ever added.
  * copies the workload's state from the platform bucket into the new bucket, byte for byte. It copies the last 20
    older versions and then the current one. The copy can be resumed if it stops part-way.
  * leaves a lock in the platform bucket that says where the state moved. The old copy is kept for 30 days.

A workload that is deploying when the backfill reaches it is skipped at once with `STATE_MIGRATION_BUSY` (the backfill
does not wait); run it again later. A copy that fails its checksum is deleted again before the run stops, so the next
run starts cleanly. The status table covers at most 50 workload records; when there are more, the card says
"Showing 50 of N records". Every result has a typed class (see [fail-loudly-policy.md](fail-loudly-policy.md)).

If vending runs in a different mode from the Control Center, the card warns (`RUNNER_IDENTITY_MODE_DIFFERS`). Until
the modes match, the Control Center's state views keep reading the platform bucket.

---

## 3. FinOps & Budget Controls

The budget of each workload is set on the create form or the workload's page; these controls are the defaults and
thresholds around it. Budget warnings and the circuit breaker act on Cloud Billing budget notifications for the
workload's project.

#### Default Monthly Budget Ceiling ($ USD)

* **Key / default / range:** `finops.default_monthly_budget_usd`, 40, 5 to 5000.
* **What it does:** the budget of a new workload created without one. The create form is pre-filled with it (you can
  change it there), an API request without `budget_ceiling_monthly_usd` gets it, and a Drive-intake workload gets it
  when project vending creates its record. A workload's own budget is never changed by vending.
* **Who / when:** administrators; workloads created after the save. Existing workloads keep theirs.
* **Safe / risky:** a lower value makes the breach policy act sooner on new workloads.

#### Warning Threshold (%)

* **Key / default / range:** `finops.warning_threshold_pct`, 80, 10 to 100.
* **What it does:** when a budget notification reports spend at or above this share of the workload's ceiling (or
  its approved buffer ceiling) but below the circuit breaker, the Control Center records a warning
  (`BUDGET_WARNING_THRESHOLD`, severity `WARNING`) in the `billing_alerts` collection and its log: one entry per
  workload and billing month, updated with the latest spend. Nothing is stopped and no e-mail is sent.
* **Who / when:** administrators; the next budget notification.

#### Circuit Breaker (%)

* **Key / default / range:** `finops.circuit_breaker_threshold_pct`, 100, 50 to 200.
* **What it does:** the workload's breach policy fires when a budget notification reports spend at or above this
  share of the workload's own monthly ceiling (100 = at the ceiling). An approved buffer ceiling is an amount you
  chose and is used as it is. The budget card then shows the amount the breaker fired at.
* **Who / when:** administrators; the next budget notification, for every workload.
* **Safe / risky:** above 100 lets spend pass the ceiling before anything happens; below 100 acts early.

#### Default Budget Breach Enforcement Policy

* **Key / default:** `finops.default_breach_policy`, `AUTONOMOUS_SCALE_TO_ZERO`.
* **Choices:**
  * **Autonomous Scale-to-Zero**: scale the workload's compute down when the ceiling is reached. The enforcer scales
    only Cloud Run services in the workload's own region. When it cannot establish that region (`REGION_NOT_APPROVED`
    or `REGION_UNAVAILABLE`), it scales nothing, raises the usual budget-breach approval card and a billing alert,
    and tries again at its next scheduled run.
  * **Alert Only**: notify, never stop anything.
  * **HITL Confirmation Required**: create an approval card first.
  * **Nuclear Unlink Billing**: detach the project from billing, which stops every billable resource in it.
* **What it does:** the policy given to a new workload created without one (the create form's *Platform Default*
  choice, or an API request without `budget_breach_policy`). Each workload can change its own policy later (see
  [Per-workload governance](#10-per-workload-governance-controls)).
* **Who / when:** administrators; new workloads created after the save. Existing workloads keep theirs.
* **Safe / risky:** *Alert Only* never protects you from runaway spend. *Nuclear Unlink Billing* is the strongest
  guard but stops everything in the project that needs billing; use it for disposable workloads.

#### Enforce Scale-to-Zero by Default

* **Key / default:** `finops.enforce_scale_to_zero_default`, on.
* **What it does:** on, an Agent-mode Cloud Run service whose spec or architect plan states no minimum instance count
  gets `min_instances = 0` and scales to zero when idle. Off, such a service keeps one warm instance. A minimum the
  spec or the plan states (including an explicit zero) always wins. Express workloads use their module settings.
* **Who / when:** administrators; developer runs that start after the change (the generated Terraform of the next
  build or redeploy).
* **Safe / risky:** off costs money for every idle service; use it only when cold starts matter.

---

## 4. Orchestration & Infrastructure

#### Default Workload Region

* **Key / default:** `orchestration.default_gcp_region`, `us-central1`. It must be one of the approved deployable
  regions (below); a save that changes it to a region not approved before is checked against Cloud Run's regions for
  the host project.
* **What it does:** the region selected first on the New Workload form (and used when an API create request names no
  `region`). A workload created with approved regions keeps the region recorded at its creation
  (`workloads/{product_id}.region`). A workload created **before** approved regions has no recorded region and keeps
  following this setting: the generated Terraform's `region`, image tags, Artifact Registry, Cloud Run, VPC connector
  and subnetwork paths, and network allocation all use it.
* **Who / when:** administrators. The Terraform server reads it on every deploy; the other services within 60 s.
* **Safe / risky:** **risky** for workloads without a recorded region: changing it moves them at their next deploy,
  which plans their resources in the new region. Workloads with a recorded region keep it, so while one deploys in the
  current default, a save that drops that region from the effective list is refused (`REGION_IN_USE`). With an empty
  approved list, change the default in two saves: first set **Approved Deployable Regions** to the current and the new
  region, then change the default. An empty value stops deploys with `REGION_UNAVAILABLE`. *Reset
  Defaults* sets it back to `us-central1` (refused with `REGION_IN_USE` while a workload still deploys in a region the
  reset would remove).

#### Approved Deployable Regions

* **Key / default:** `orchestration.approved_deployable_regions`, empty. Empty means the default workload region only,
  which is the behavior before this setting existed.
* **What it does:** the regions a **new** workload may be created in. The New Workload form (Agent and Express) offers
  exactly these; an API create request naming another region is refused (HTTP 422, `REGION_NOT_APPROVED`) before
  anything is written or vended. A regulated security controls baseline whose allowed regions do not include the
  chosen region is refused at creation too (HTTP 422, `REGION_PROFILE_CONFLICT`). A workload keeps its region: a
  re-submit naming another one is refused (HTTP 409, `REGION_CHANGE_REFUSED`). One region per workload; a workload
  across several regions is not supported.
* **Validation on save:** each entry is a region id (lowercase letters, digits and `-`), no entry twice, and the
  default workload region is in the list (else HTTP 422). A region added by the save must be one Cloud Run offers to
  the host project (HTTP 422, `REGION_UNKNOWN`); when that list cannot be read, nothing is saved (HTTP 503,
  `REGION_LOOKUP_UNAVAILABLE`). A region removed by the save that a workload (not decommissioned) still deploys in is
  refused (HTTP 422, `REGION_IN_USE`, naming the workloads); with an empty list the default region counts as
  listed, so moving the default needs the two-step save described under Default Workload Region.
* **Who / when:** administrators; new workloads created after the save. Existing workloads are not changed.
* **Safe / risky:** adding a region is safe for existing workloads. The StackVend platform itself stays in its install
  region.

#### Default GitHub Branch

* **Key / default:** `orchestration.default_branch`, `main`.
* **What it does:** the branch a **new** workload gets when its create form, API call (`target_branch`) or Drive
  intake names none. Its repository is created with this branch as its default (GitHub and Serverless Git), the
  generated deploy workflows run on pushes to it, release pull requests target it and the platform deploys from it.
  The developer reads the existing code from it and cuts its branch from it, and QA compares the build with it. If
  the workload's record cannot be read at that point, the run stops (`WORKLOAD_RECORD_UNREADABLE`) and never falls
  back to `main`.
  A branch other than `main` no longer makes vending reuse an existing repository.
* **Who / when:** administrators; workloads created after the save (settings are re-read within 60 s). Existing
  workloads keep the branch they have recorded; re-creating an existing workload without a branch keeps its
  recorded one.
* **Safe / risky:** use a plain branch name (letters, digits, `.`, `_`, `-`, `/`). Any other value, or settings
  that cannot be read, gives `main` (logged). The workload's GitHub identity-federation condition accepts its
  recorded branch (exactly that one, push and manual runs only), so GitHub Actions deploys from it work; a workload
  created before this change keeps `main` there until its next pipeline run regenerates its IaC. On GitHub the auto-created `main` branch is left in place next to the new default branch.

#### Terraform Lock Timeout (s)

* **Key / default / range:** `orchestration.terraform_lock_timeout_seconds`, 180, 10 to 600.
* **What it does:** how long a deploy waits for the workload's Terraform state lock (the `-lock-timeout` of plan,
  apply and destroy, and the Terraform server's pre-flight wait) before it stops with `STATE_LOCKED`. The lock is
  never broken, whatever the value. A `TF_LOCK_TIMEOUT` environment variable on the Terraform server wins over this
  field.
* **Who / when:** administrators; the next plan or apply.
* **Safe / risky:** safe. A shorter wait stops a deploy sooner when another run holds the lock; a longer one keeps the
  deploy waiting.

#### Max Concurrent Builds

* **Key / default / range:** `orchestration.max_concurrent_builds`, 1, 1 to 20.
* **What it does:** how many builds that use the AI models run at the same time (new Agent-mode workloads, Full
  Swarm Rebuild and Resume Developer relaunches, promotions, Drive, refactor-scanner and SRE builds). A build over the
  limit waits in a first-in-first-out queue: it shows as **Queued (#n in line)** in the Flight Deck, where **Cancel
  Queued Build** removes it, and it starts when a running build ends. Fast-Path Deploy, Express, redeploy and
  Upgrade IaC never wait. Unreadable settings: 1.
* **Who / when:** administrators; the next submission or relaunch. Lowering it never stops a running build.
* **Safe / risky:** safe at 1. Several builds at once share the install's model quota: raise it only when the quota
  serves them (builds that share too little quota fail with model quota errors and timeouts). A build waiting for a
  person (plan, quota or pull-request approval) gives its slot up and takes one again when approved, ahead of new
  submissions.

#### Verified Stale tf-applier Lock Age (min)

* **Key / default / range:** `orchestration.stale_lock_threshold_minutes`, 20, 5 to 120.
* **What it does:** a held state lock older than this is reported as stale (`lock_info.is_stale`) in the
  `STATE_LOCKED` error. It is a report only: StackVend never clears a state lock automatically. An operator checks
  that no apply is running and clears it with force-unlock. `TF_STALE_LOCK_MAX_AGE_MINUTES` on the Terraform server
  wins over this field.

#### Default Container Memory (MB) and Default Container vCPU

* **Keys / defaults:** `orchestration.default_container_memory_mb` (512, 128 to 32768) and
  `orchestration.default_container_cpu` (1, 1 to 8).
* **What they do:** the memory (MiB) and vCPU of an Agent-mode Cloud Run service without heavy packages. A service
  the platform sizes up for data or compute packages keeps its larger value (1 GB, or 2 GB with 2 vCPU). A
  combination Cloud Run cannot run (vCPU must be 1, 2, 4, 6 or 8; 1 vCPU allows 512 to 4096 MB, 2 vCPU up to
  8192 MB, 4 vCPU 2048 to 16384 MB, 6 and 8 vCPU from 4096 MB) is not applied: the service keeps 512 MB and 1 vCPU and
  the developer log says why.
* **Who / when:** administrators; developer runs that start after the change.
* **Safe / risky:** larger values cost more per instance.

#### Private Services Access Range Size (prefix)

* **Key / default / range:** `orchestration.ipam_psa_prefix`, 20, 16 to 24.
* **What it does:** the size of the Private Services Access range (`PRIVATE_SERVICES_ACCESS`) the platform takes from
  the IP address pool for a workload built with typed infrastructure that needs a private database or endpoint
  (AlloyDB, Cloud SQL, Vertex AI endpoint). Google Cloud needs an allocated range of at least /24; AlloyDB and Cloud
  SQL each use a /24 of it, so the default /20 holds 16 of them. A larger range (a /16 is a common choice) leaves more
  room for services that peer through it.
* **Who / when:** administrators; ranges allocated after the save. A workload that already has a range keeps it.
* **Safe / risky:** a larger range uses more of the pool: with the default pool (`10.100.0.0/16`) a /16 range cannot
  be allocated next to the workload's subnet (the build stops with `IPAM.POOL_EXHAUSTED`), so set a larger
  `orchestration.ipam_supernet_cidr` first; a /20 leaves room for about 15 such workloads in the default pool.

#### Default IaC Engine

* **Key / default:** `orchestration.default_iac_engine`, `OPENTOFU` (or `TERRAFORM`).
* **What it does:** the engine pre-selected on the create form and used for a new workload whose request names none.
  It is also the fallback for a workload whose record has no engine.
* **Who / when:** administrators; new workloads. Existing workloads keep their engine.
* **Safe / risky:** OpenTofu is the tested path. Terraform is limited to the 1.5 series (below).

#### Terraform Version and OpenTofu Version

* **Keys / defaults:** `orchestration.terraform_version` (`1.5.7`) and `orchestration.tofu_version` (`1.9.0`). The
  **+** button adds a version to the drop-down list (`supported_terraform_versions` / `supported_tofu_versions`) and
  selects it; it is stored when you save.
* **What they do:** the version the Terraform server downloads when no `OPENTOFU_VERSION` / `TERRAFORM_VERSION`
  environment variable is set. The downloaded release archive runs only after it matches a pinned SHA-256 checksum;
  a binary already on `PATH` is never used. Pinned checksums exist for the versions the Settings lists offer (OpenTofu
  `1.8.8`, `1.9.0` and `1.10.0`, Terraform `1.5.7`); any other version fails the deploy with `ENGINE_UNVERIFIABLE`.
* **Who / when:** administrators; the next deploy that needs a download.
* **Safe / risky:** **Terraform 1.6 or later is refused at run time** (it is not open-source licensed), so the
  Terraform list offers only versions below 1.6 (`1.5.7` by default). The **+** button refuses a version of 1.6 or
  later, a stored one is dropped from the list when the settings are read, and a save that selects one is refused
  (HTTP 422, `TERRAFORM_VERSION_REFUSED`). Keep `1.5.7`.

---

## 5. Agent AI Models & Limits

Changes apply to model calls made after the services pick up the new settings (within 60 s), for every workload.

**Any Gemini model id can be entered** (letters, digits, dots and hyphens, at most 80 characters). Model ids are
checked when you save, with one small live call:

* **What is called:** each model field you changed (for the fallback list `models.fallback_models`, which is not on
  the Parameters form, each new entry), and each Gemini 4-style model of a role whose thinking level you changed.
  Fields you did not change are not called.
* **How:** through the client the agents use (the AI Studio key when one is configured, else Vertex AI on
  `GEMINI_LOCATION`), with that role's request settings (thinking level or budget, as the agents send it). The call
  asks for a short answer with at most 256 output tokens: a fraction of a cent per changed model (at most about
  $0.005 on Gemini 4 Carbon), billed to the platform project like every other agent call.
* **Refused:** a model the API refuses is not saved (HTTP 422, `MODEL_CHECK_FAILED`, with Google's message). A check
  that gets no answer within 20 s is refused too (`MODEL_CHECK_TIMEOUT`), and so is a save when no model client can be
  built (`MODEL_CHECK_UNAVAILABLE`). Nothing is stored when any check fails, and the page puts the refused field back
  to its saved value.
* **Models without built-in rules:** the built-in ids (the Gemini 1.5 to 3.8 Flash and Pro ids, `gemini-4-argon` and
  `gemini-4-carbon`) have fixed request rules. For any other id the check finds its request style from the API's
  answers, never from the name: first the Gemini 3.x style (a thinking budget of 128 tokens and the sampling
  settings), then the Gemini 4 style (a thinking level, no budget, no sampling or penalty settings). The first style
  the API accepts is stored with the settings (`models.custom_families`, written only by this check) and used by every
  agent call; when neither is accepted the save is refused with both errors. An id with neither built-in rules nor a
  stored style is refused (`UNSUPPORTED_MODEL_CONFIG`). Both probes use the developer's request settings. A model that
  accepts a thinking budget is stored with the Gemini 3.x style even if it would also take a thinking level; thinking
  levels then do not apply to it. The page shows each stored style (read-only, under **Detected request styles**).
* **Checked again:** a model without built-in rules is probed again whenever a save changes any field that names it
  (or adds it to the fallback list), so its stored style is refreshed. A field you did not change keeps its stored
  style without a call.
* **Limits:** at most 4 fallback models per save (`FALLBACK_MODELS_TOO_MANY`) and at most 10 checks per save
  (`MODEL_CHECK_TOO_MANY`), both refused before any call; at most 8 calls run at once.
* **Rollout after an upgrade:** the services that read these settings (orchestrator gateway, FinOps enforcer, project
  vending, spec ingestion, the billing-alert drain job and the Terraform tool server) must run the new release before
  the Control Center does. An older service resets a model it has no rules for to that field's default (logged at
  ERROR) and ignores the thinking levels, so a saved model is not used there until that service is redeployed.
* **Cost figures:** a model without a built-in price has an unknown cost. The token figures show "cost unknown"
  instead of a dollar amount, never $0.

**Defaults.** A new install uses `gemini-4-carbon` (Gemini 4 Carbon) for every model role and `gemini-4-argon`
(Gemini 4 Argon), then `gemini-3.8-flash`, then `gemini-3.7-flash` as the fallback models. An existing install keeps the models its saved settings name; nothing is
migrated. Carbon costs several times more per pipeline run than `gemini-3.8-flash`: about 4.5 times on the simpler
examples and 6 to 9 times on the harder ones in offline evaluations. You can pick any Gemini model id for each role on
this page (for example `gemini-3.8-flash` to cut cost); each changed model gets the live check above when you save.

Gemini 4 Argon, Gemini 4 Carbon and models saved with the Gemini 4 style are thinking-level models: the platform sends
them the role's thinking level (see **Thinking Levels**) instead of a thinking budget, and leaves out the request
settings they refuse. A fallback call uses the fallback model's own request rules. Gemini 4 Carbon costs $4 input /
$20 output per million tokens at list price; Gemini 4 Argon $2 / $10 until 2026-11-30, then $4 / $20.

**Vertex AI location.** The platform services call Vertex AI on `GEMINI_LOCATION`, which the platform Terraform sets
to `global` on every service and job whatever the install region; Carbon and Argon are called on `global` (the
location StackVend has verified for them), so they work in every approved region. A Carbon or Argon call configured
for any other location (`us`, `eu` or a region) is sent to `global` instead: this covers the FinOps advisor (which
uses `GEMINI_LOCATION`) and the agent-quality evaluator's backup client (which uses `DEFAULT_GCP_REGION`; the
platform Terraform does not set it, so it is `us-central1`). Gemini 3.x models keep the configured location.

#### Architect Agent Model

* **Key / default:** `models.architect_model`, `gemini-4-carbon`.
* **What it does:** the model for specification decomposition, the architecture plan and task DAG, and the red-team
  critic (unless `ARCHITECT_CRITIC_MODEL` is set). If it fails, the services try the fallback models (see
  [section 11](#11-stored-settings-that-are-not-on-the-page)).
* **Safe / risky:** a weaker model gives weaker plans; a larger model costs more and is slower.

#### Developer Agent Model

* **Key / default:** `models.developer_model`, `gemini-4-carbon`.
* **What it does:** the model for the lead developer and the junior developers (code, infrastructure and tests).

#### FinOps Agent Model

* **Key / default:** `models.finops_model`, `gemini-4-carbon`.
* **What it does:** writes a short recommendation (at most three sentences) on each budget-breach approval card. One
  model call per card, made after the enforcement action and the card are written, so it never blocks or delays the
  enforcement; 20 s timeout, 256 answer tokens, no retry. The model sees only the workload id and the spend numbers
  (spend, ceiling, percent of the ceiling); its answer is shown on the card as plain text. A failed call leaves the
  card without a recommendation and with a typed note (`FINOPS_MODEL_CALL_FAILED`, `FINOPS_MODEL_HTTP_ERROR`,
  `FINOPS_MODEL_EMPTY_ANSWER`, `FINOPS_MODEL_NOT_CONFIGURED`). The call's tokens and cost are recorded on the card
  (`finops_recommendation_usage`).
* **Who / when:** administrators; the next budget breach. The cost check before a build is still the Infracost
  estimate, and the action taken at a breach is still the workload's breach policy: the recommendation is advice only.
* **Safe / risky:** each breach card is one paid model call.

#### Control Center Assistant Model

* **Key / default:** `models.assistant_model`, `gemini-4-carbon`.
* **What it does:** the model behind the **StackVend Assistant** tab, and the model that writes a run's
  **After-Action Report** (then the fallback models; each with its own request rules and the **Other** thinking
  level). When no model answers, the report is written from the run's recorded stages and error only, its engine
  shows `deterministic-rules`, and the reason is stored with it (`model_failure`: `AAR_MODEL_UNAVAILABLE` or
  `AAR_MODEL_CALL_FAILED`, with each model's error).

The compliance agent has no model field of its own: it uses the **Architect Agent Model**, then the fallback models
(with the **Other** thinking level). Every agent leads with its Settings model; the `GEMINI_MODEL` environment
variable that the platform Terraform sets (variable `gemini_model`, default `gemini-3.7-flash`) does not outrank it.

#### Repair Model

* **Key / default:** `models.repair_model`, empty (= the developer model).
* **What it does:** the model used for the targeted repair calls that fix files a validation step rejected. Lets
  repair run on a different model from development.

#### Global Max Output Tokens

* **Key / default / range:** `models.max_output_tokens`, 65536, 1024 to 65536.
* **What it does:** the output limit of a role whose override below is empty (architect and critic, or developer).
  The stored value is used as it is.

#### Thinking Budget

* **Key / default / range:** `models.default_thinking_budget`, 0, 0 to 2048.
* **What it does:** the thinking budget (tokens) sent with the architect's plan call and the developer's calls (the
  lead's work breakdown, the swarm's junior calls and the single-call path) on Gemini 3.x and earlier models. 0 sends
  no thinking setting, so the model uses its own default, as before. Gemini 4-style models (the defaults) use
  **Thinking Levels** instead and never receive a budget, so this setting has no effect on them. The
  typed-infrastructure junior call and repair calls keep their own budgets; the critic, spec decomposer and
  compliance calls send none.
* **Safe / risky:** a budget makes calls slower and costs tokens.

#### Thinking Levels

* **Key / default:** `models.thinking_levels`: `architect` LOW, `developer` MEDIUM, `repair` LOW, `auxiliary` LOW.
  On the page: **Architect**, **Developer**, **Repair** and **Other** (QA judges, compliance, the assistant and the
  FinOps advisor).
* **What it does:** the thinking level sent to Gemini 4-style models (Gemini 4 Argon, Gemini 4 Carbon and models saved
  with the Gemini 4 request style) for each role: LOW, MEDIUM or HIGH. MINIMAL is refused, because Gemini 4 rejects it.
  A role left out uses its default. Gemini 3.x models ignore it and use **Thinking Budget**. The output limit of such a
  call reserves room for thinking by level (LOW 4,096, MEDIUM 8,192, HIGH 16,384 tokens) and stays within 32,768;
  when that cap leaves less room for the answer than asked (for example HIGH with a 32,768 limit), the services log it
  once with the numbers.
* **Who / when:** administrators; the next model call. A changed level is checked with one live call per affected
  model when you save.
* **Safe / risky:** HIGH means more thinking tokens, so calls are slower and cost more. On Gemini 4 Carbon thinking is
  billed as output at $20 per 1M tokens.

#### Architect Token Limit (Override)

* **Key / default:** `models.architect_max_output_tokens`, 16384 (1024 to 65536).
* **What it does:** the architect's and critic's output limit. When empty, **Global Max Output Tokens** applies.

#### Developer Token Limit (Override)

* **Key / default:** `models.developer_max_output_tokens`, 65536 (1024 to 65536).
* **What it does:** the developer's output limit; when empty, **Global Max Output Tokens** applies.
* **Safe / risky:** limits that are too low truncate generated files and cause failed builds and repair cycles.

#### Developer Swarm Token Ceiling (Circuit Breaker)

* **Key / default / range:** `models.max_swarm_token_envelope`, 350,000, 50,000 to 2,000,000.
* **What it does:** the token budget of one developer swarm build (input plus output, across all waves). When a build
  uses more than 110 percent of it, the swarm stops (circuit breaker) and the run fails with
  `SWARM_TOKEN_ENVELOPE_EXCEEDED`; it never continues on the single-call path. The ceiling meters swarm builds only: a
  small single-file change is built in one model call, bounded by the stage deadline and the developer output token
  limit, not by this ceiling. It also sizes the token budget available to repair calls. The cost shown next to it is
  a rough estimate.
* **Who / when:** administrators; builds that start after the change.
* **Safe / risky:** too low stops large workloads part-way; too high lets a looping build spend more.

---

## 6. Platform Governance & Gates

#### Maintenance Mode

* **Key / default:** `governance.maintenance_mode`, off.
* **What it does:** while on, **no new run starts**, platform-wide. Workload creation (form, API and Express),
  retrigger, redeploy, infrastructure deploy, deploy to a new folder, Drive spec intake and every orchestrator gateway
  dispatch answer HTTP 503 `MAINTENANCE_MODE`. Drive specs stay in the inbox and are picked up after maintenance.
  Runs already in progress continue; they are not stopped. Settings, approvals and decommission still work.
* **Who / when:** administrators; within 60 s.
* **Safe / risky:** safe to turn on and off. To stop runs that are already going, use the
  [Emergency Stop](#emergency-stop) instead.

#### Strict Compliance Gates

* **Key / default:** `governance.strict_compliance_gates`, on.
* **What it does:** compliance checks always run; this switch never turns them off. When on, a *compliance profile
  advisory* (the spec mentions terms associated with a profile the workload does not use, for example "credit card"
  on a Standard workload) pauses the run at the pre-build gate for a human (reason `COMPLIANCE_PROFILE_ADVISORY`).
  With the plan-approval policy *Autonomous unless failed*, advisories never pause the run. The advisory never
  changes the profile.
* **Who / when:** administrators; runs that reach the pre-build gate after the change.
* **Safe / risky:** turning it off removes a human check on possibly regulated data; organization policy conflicts
  still pause the run.

#### Require Human Approval for Destructive Terraform

* **Key / default:** `governance.require_hitl_for_destructive_tf`, on.
* **What it does:** when on, an Agent-mode deploy whose plan deletes or replaces a data-holding resource (bucket,
  database, dataset, cache, secret, registry, subscription, cluster, disk, KMS key, VM, task queue, Composer
  environment) stops before anything is applied (`DESTROY_REQUIRES_APPROVAL`) for an operator decision. Secret
  version rotations and other resources apply as before. Express deploys use their own exact-address approval.
  Deletion-protected resources are always blocked, whatever this switch says.
* **Who / when:** administrators; deploys planned after the change, for every workload.
* **Safe / risky:** **turning it off is risky**: a regenerated plan that replaces a database or bucket then deletes
  its data without asking.

#### Drive Folder Auto-Discovery

* **Key / default:** `governance.drive_folder_auto_discovery`, off.
* **What it does:** off, Drive intake polls only the inbox and in-progress folders configured on the spec intake
  service (`INBOX_FOLDER_ID` / `IN_PROGRESS_FOLDER_ID`). On, the poller also searches Drive for every folder named
  `01_Inbox_Requests` shared with the platform service account and polls each one whose Drive **owner** is an
  authorized submitter (see the next card). The configured inbox and in-progress folders are still polled as well; a
  folder that is both configured and discovered is polled once, with the configured in-progress folder.
* **Who / when:** administrators; the next poll after the change (within 60 s).
* **Safe / risky:** **riskier than the default.** Any authorized submitter can then start builds by sharing a folder of
  that name with the service account, and anyone with edit access to such a folder can change the specs in it. Review
  the Access Control list and the sharing of those folders first.

#### Typed infrastructure (generate mode)

* **Key / default:** `governance.iac_intent_generate`, **on**. The default applies when the saved settings have no
  value for it (a fresh install); a value an administrator saved, on or off, is kept.
* **What it does:** on, the agents describe a new workload's infrastructure as a typed list of approved building
  blocks (`infra/workload/iac_intent.json`) and the platform checks it and writes the Terraform from it, instead of
  the agents writing Terraform directly. The building blocks include a short approved list of Google APIs the code
  only calls (Vertex AI, Document AI, Speech-to-Text, Cloud Translation, Cloud Vision, Natural Language,
  Text-to-Speech): the platform turns the API on and grants the workload's service account exactly one narrow role
  for it, never an admin role (Cloud Vision, Natural Language and Text-to-Speech have no role, so none is granted). A building block a repair had
  to remove is listed as a warning on the workload page; if the architect's plan named that service and nothing else
  in the build provides it, the build stops (`IAC.REQUESTED_SERVICE_DROPPED`) instead of shipping without it.
* **Who / when:** administrators; **new workloads only**, for builds that start after the save (allow up to a
  minute). A workload already built this way stays on it even if the setting is turned off later; a workload built
  with agent-written Terraform keeps that. Workloads that need Cloud SQL, Redis, AlloyDB, Vertex AI endpoints or
  Bigtable are built this way too: the platform supplies the private network (with its Private Services Access
  range from the platform's IP address plan) and the Cloud Run connector where the service needs one. If the
  settings cannot be read when a build starts, that build uses the classic path; the setting never fails a build.
* **Safe / risky:** on is the default and the tested path. Turning it off is safe too: new workloads then get
  agent-written Terraform, with the limits described in
  [Known limitations](known-limitations.md#some-infrastructure-code-is-still-written-by-the-ai).

#### Freeze new workloads by default

* **Key / default:** `governance.freeze_new_workloads`, on.
* **What it does:** on, every **new** workload starts with [Master Code Freeze](#10-per-workload-governance-controls)
  on: one created from the Control Center (form, API or Express), one promoted to a folder (**Deploy to folder**), and
  one that arrives from a Google Doc spec (its first record is written, frozen, when the intake event arrives). While a
  workload is frozen, the automatic runs that change its code are blocked: SRE auto-healing and the code scanner's
  pull requests are suppressed (`SUPPRESSED:CODE_FREEZE`), and the **Upgrade IaC** action answers 423. Budget
  enforcement (the breach policy, for example scale to zero or quarantine) and the sandbox expiry sweep still apply to
  a frozen workload. The first build and deploy of its spec still run, and so do the builds, retriggers and feature
  requests an operator starts. An operator unfreezes the workload with **Unfreeze** on its page (*Workload Governance
  & Autonomy Controls*, administrators); until then that card greys out its other governance controls. Off, new
  workloads start unfrozen, as before.
* **Who / when:** administrators; **new workloads only**, for workloads created after the save (allow up to a minute).
  Existing workloads are never changed by this setting, and a re-create, re-vend or redeploy of an existing workload
  keeps its current freeze. The StackVend platform's own record (*bootstrap*) is not affected. If the settings cannot
  be read, Control Center create and promote are refused (503, as for every governance default) and nothing is
  created; a Google Doc workload whose read fails starts frozen. The freeze read itself never makes a create fail.
* **Safe / risky:** on is the safe side (automatic code changes need an operator first). Turning it off lets the SRE
  sentinel and the code scanner act on a new workload as soon as it is active.

#### Drive Spec Intake: Authorized Submitters Only (information card)

No switch. A Google Doc spec is built only when:

* its Drive owner is an **active** user on the Access Control tab with the `ADMIN`, `WORKLOAD_MANAGER` or legacy
  `APPROVER` role (exact address; viewers, other people and shared-drive files, which have no owner, are refused); and
* its folder tag, if any, names an active managed folder; and
* its title gives a valid workload id that the owner may use: an existing workload needs the `ADMIN` role or an
  assignment to it, and the StackVend platform itself is never a target.

Anything else stays in the inbox and is reported with a reason (`SPEC_SUBMITTER_UNAUTHORIZED`,
`TARGET_FOLDER_NOT_MANAGED`, `SPEC_PRODUCT_ID_INVALID`, `SPEC_WORKLOAD_NOT_ASSIGNED`, `SPEC_TARGET_PLATFORM_WORKLOAD`). If the user list cannot be read, the whole poll is skipped (`SPEC_INTAKE_UNAVAILABLE`)
and retried on the next poll. A role typed directly into Firestore that is not one of these three is refused, even
though the Users list shows it as `WORKLOAD_MANAGER`.

**Related warning:** *no active Administrator or Workload Manager is listed* appears when nobody qualifies; every Drive
spec is then skipped. Add the people who submit specs on the Access Control tab.

Keep edit access to the inbox folder limited to authorized submitters: Drive trusts the document's owner, and inside a
Workspace organization ownership can be transferred immediately. See
[User Guide: Via Google Drive](user-guide.md#via-google-drive-spec-intake).

#### Default Access for New Workloads: Private (information card)

No switch. A new workload (Agent or Express mode) created without an access choice is private behind Identity-Aware
Proxy (IAP) and lists its
submitter when the platform verified who that is (the signed-in Control Center user, or the Drive file's owner). With
no verified submitter nobody is listed and the build stops with `ACCESS_POLICY_INCOMPLETE` until an administrator
lists who may use it in the workload's access settings. Public is always an explicit choice. Existing workloads keep
their access. IAP needs the IAP API in the workload project (enabled by the workload foundation module); if it is
missing, that deploy fails and never falls back to public. IAP admits only accounts of your Google Cloud organization
(a personal Gmail account is refused), so list organization accounts. See
[User Guide: Choosing who may use the app](user-guide.md#choosing-who-may-use-the-app).

#### Force HITL for All New Workloads (Auto-Merge: OFF)

* **Key / default:** `governance.default_require_human_code_review`, on.
* **What it does:** the default for a new workload's **Human code review**: its release pull request waits for a
  person instead of merging automatically. It pre-fills the create form's checkbox and applies to API requests that
  do not set `require_human_code_review` / `auto_merge`, and to workloads that arrive from a Google Doc spec (project
  vending applies it; if the settings cannot be read there, human code review stays on).
* **Who / when:** administrators; new workloads. Existing workloads keep their own setting (change it on the
  workload's page).
* **Safe / risky:** turning it off lets generated code merge and deploy without a human look.

#### Require Plan Approval for Every Run of Every Workload (Architect HITL Gate)

* **Key / default:** `governance.require_plan_approval`, off.
* **What it does:** two things. It pre-fills the create form's **Plan approval** checkbox for new workloads. And, while
  on, the compliance step requires a human approval of the architecture plan on **every run of every workload**, before
  the developers write code, whatever the workload's own setting says.
* **Who / when:** administrators; within 60 s, for Agent-mode builds that reach the compliance step. A resumed run
  keeps the approval decision it already had.
* **Safe / risky:** safe; it only adds approvals. Turning it off returns to the plan-approval policy below plus each
  workload's own setting.

#### Architectural Plan Approval Trigger Policy

* **Key / default:** `governance.plan_approval_policy`, `ON_COMPLIANCE_CONFLICT`.
* **Choices:**
  * **ALWAYS**: every architecture plan of every workload waits for a human.
  * **ON_COMPLIANCE_CONFLICT**: a plan waits when the organization-policy check finds a conflict.
  * **AUTONOMOUS_UNLESS_FAILED**: as above for conflicts, and compliance profile advisories never pause the run even
    with Strict Compliance Gates on.
* **Who / when:** administrators; within 60 s.
* **Safe / risky:** policy conflicts, failed policy harvesting, FinOps cost warnings, a workload's own *Plan approval*,
  an unapproved access widening and a Public app whose push-only Cloud Run service would be reachable from the
  internet (`ACCESS_INTERNAL_SERVICE_PUBLIC`) always pause the run, whatever this policy says.

---

## 7. Buildpack & Runtime Governance (Platform BOM)

These settings are read by the Terraform server when it builds a workload's containers (Cloud Build with buildpacks),
on each build, for **every** workload. A bad value breaks the next build of every workload, so change them one at a
time and watch a build.

#### Default Python Runtime Version

* **Key / default:** `runtimes.default_python_version`, `3.13` (3.11, 3.12 or 3.13).
* **What it does:** written to `.python-version` for a workload or service that has none (or an invalid one). A
  service that already pins 3.10 to 3.13 keeps its version.

#### Cloud Build Worker Machine Type

* **Key / default:** `runtimes.cloud_build_machine_type`, `E2_HIGHCPU_8`.
* **What it does:** the Cloud Build machine used for container builds. Larger machines build faster and cost more.

#### Cloud Build Timeout (Seconds)

* **Key / default:** `runtimes.cloud_build_timeout_seconds`, 1200 (the form allows 300 to 3600).
* **What it does:** the Cloud Build timeout and how long the platform waits for the build.

#### Auto-Harmonize Legacy C-Extension Wheels

* **Key / default:** `runtimes.auto_harmonize_wheels`, on.
* **What it does:** on, a container image build relaxes old `numpy`, `scipy`, `pandas` and `asyncpg` pins in the
  build's copy of `requirements.txt` to ranges with Python 3.13 wheels (for example `numpy==1.26.4` becomes
  `numpy>=1.26.0`), unless **Centrally Governed Package Versions** lists the package: then its bound is used
  (by default all four are listed, so turning the switch off changes nothing until a package is removed from that
  list). Off, those old pins are kept as written; the listed package bounds and the `starlette` / `greenlet` lines
  still apply.
* **Who / when:** administrators; the Terraform server reads it at each container image build. Settings that cannot
  be read: on.

#### Centrally Governed Package Versions (BOM Catalog)

* **Key / default:** `runtimes.package_versions`, a list of version bounds (for example `fastapi >=0.110.0`).
* **What it does:** at build time, each listed package in a workload's `requirements.txt` is rewritten to the bound
  given here (marked `# enforced by Platform BOM`). **+ Add Package** and the remove button change the list; it is
  stored when you save.
* **Safe / risky:** **risky:** a bound that conflicts with a workload's other dependencies breaks that workload's next
  build, and it applies to existing workloads too.

---

## 8. Settings Audit History

The card under the form lists the last **15** saves and resets: action (`UPDATE_SETTINGS`, `RESET_DEFAULTS`), the
administrator, the time and the number of fields changed (the stored entry keeps each field's old and new value).
Older entries are dropped. Only Parameters-tab saves and resets (including the VCS switch) are recorded here; the other
tabs log their changes to the service logs ([Access Control](#access-control) changes are also audited in Firestore).

---

## 9. The other Settings tabs

All of these are administrator-only.

### GCP Folders

The Google Cloud folders StackVend may vend child projects into, all under the managed workloads root folder set at
install time.

* **Create GCP Folder** creates a real folder (through project vending) under the root or one of its sub-folders and
  records it. Folders outside the root are refused.
* **Set Default** marks the folder that new workloads use when the create form or request names none (else the root
  itself). Applies to new workloads immediately.
* **Disable** hides a folder from new workloads (it is not deleted in Google Cloud). It is refused while active
  workloads live in it. There is no re-enable button.

### Network & IPAM

A read-only ledger of the network ranges allocated to workloads from the platform pool (`10.100.0.0/16` by default;
see `ipam_*` in [section 11](#11-stored-settings-that-are-not-on-the-page)). Ranges of decommissioned workloads stay
reserved (`RESERVED_DECOMMISSIONED`) so a redeploy gets them back. A workload built with typed infrastructure that
needs a private database or endpoint also gets its Private Services Access range from this pool
(`PRIVATE_SERVICES_ACCESS`, /20 by default; see [Private Services Access Range Size](#private-services-access-range-size-prefix)),
so the pool holds fewer such workloads than plain subnets. With agent-written Terraform, a `networking-vpc` module call
that sets `psa_address` gets such a range too: the value must be `cidrhost(var.psa_cidr, 0)` with `psa_prefix_length =
tonumber(element(split("/", var.psa_cidr), 1))`, and a hardcoded address is a `POLICY.CIDR_LITERAL` finding the build
repairs. A call without `psa_address` keeps Google's automatic range and takes nothing from the pool.

### Modules & Bundles

The golden module and composite bundle catalog the agents and Express mode build from.

* **Register** adds a custom module from pasted HCL or a Git repository; **Edit** changes its code and bumps its
  version; **Sync** re-reads it from Git; **Delete** removes a custom module. Built-in modules cannot be changed or
  deleted.
* A custom module may not grant public access by itself (`allUsers` / `allAuthenticatedUsers` members, public
  storage ACLs, the Cloud Run invoker check turned off, `allow_unauthenticated = true` passed to a module it
  calls): **Register** and **Edit** refuse it with
  `REGISTERED_MODULE_PUBLIC_EXPOSURE` and name each setting, and **Sync** marks an older module `ERROR`. Who may use a
  workload is set by its access record. See [Known Limitations](known-limitations.md) for what the check does not read.
* Bundles can be registered, scanned from a repository, synced, switched active or inactive, and deleted.
* Changes affect builds that start afterwards. Removing a module that workloads use does not change their deployed
  infrastructure, but their next IaC upgrade or regeneration can no longer use it. See
  [Composite Bundles](composite-bundles.md) and the [Extensibility Guide](extensibility-guide.md).

### Agent Skills

Guidelines that are added to the agents' prompts for matching work. Built-in skills are read-only; custom skills can
be created and deleted. They affect model calls made afterwards.

### Agent Prompts

The system prompt of each agent. **Publish** stores a new version (with a change summary) and makes it active;
**Rollback** re-activates an older version; **Reset to default** returns to the prompt shipped in the code; the diff
view compares the active prompt with that default. Services pick up a published prompt within 60 s.
**Risky:** a prompt change affects every later run of that agent; test it on one workload and keep the summary
meaningful so you can roll back.

### Cloud Quotas

A read-only view of regional headroom (external IPs, vCPUs, Cloud SQL instances, Cloud Run services) used by the
pre-discovery quota check, with a link to the Google Cloud quotas page.

### Upgrades

Which StackVend release this install runs, where upgrades come from, and the **Update StackVend** button, which deploys
a newer signed release's services and jobs (below). Platform Terraform is never changed from this tab: a release that
changes it is installed from a terminal (`scripts/upgrade.sh <tag>`, which runs `scripts/apply.sh apply` and
`scripts/deploy-services.sh --all-jobs`).

**Platform version card.** Every `scripts/deploy-services.sh` run puts a small `release.json` (release from `VERSION`,
commit, whether a tracked file in the checkout had uncommitted changes (`dirty`; untracked files do not count), build
time, source repository) into each service and job it builds, removes it again afterwards, and then writes one record,
`system_config/platform_release`, with what it deployed. Services report their `release.json` on their health check; jobs log a `stackvend.release` line when
they start. The card:

* shows each service and job with its release and commit, but only when the image Cloud Run actually runs is the one
  the record says was deployed. Anything else shows **unknown (not from a recorded deploy)** (a hand `gcloud` deploy) or **unknown (no recorded deploy yet)** (no record yet);
* when there is no record yet, says why in one line: this Control Center image carries no version stamp (deploys from before
  version records), or a stamped deploy did not write the record;
* **Services and jobs** shows the release when every recorded component has the same release and commit, the release
  with **(components from N commits)** when they share a release but come from several commits, **mixed** for several releases, and **not recorded yet**
  without a record; **This Control Center build** shows the Control Center's own `release.json`, or **unknown** with
  the reason;
* says **Mixed versions** when components run different releases or commits (for example after deploying one
  service);
* shows the platform Terraform release from the platform stamp that `scripts/apply.sh apply` (and the installer) writes
  on the Control Center service. Without a stamp it reads **unknown (no platform stamp …)**: every install from the
  first release on has one, so run `scripts/apply.sh apply` to write it. When the stamp differs from the services'
  release, the card says which side is behind: **Platform update pending: run upgrade.sh** when the platform is older, or
  **Services are behind the platform: redeploy the services** when the platform is newer. After a successful
  **Update StackVend** run that needs no `apply.sh` (the release and commit the services run match that run's verified
  release, and its verified minimum platform release is at or below the stamp), the platform is not shown as behind;
  any other state still shows the banner;
* lists the last 20 recorded deploys;
* shows a grey line **Update check off** when the update check (below) is switched off.

If the record cannot be written, the deploy still succeeds; the script (or the trigger build's log) prints a warning and the card shows the
components as "not from a recorded deploy" until the next recorded deploy. The record is information only and is
never used as the platform Terraform version.

**Check for updates.** Lists the newest release in the release source repository on GitHub (preview releases
included unless switched off), whether it is newer than this install, its notes, and its `release-manifest.json`
(`requires apply.sh: yes/no`, oldest platform release it runs on). The terminal command to install it is shown:
`PROJECT_ID=<project> bash scripts/upgrade.sh <tag>`, run from the checkout you installed from (it verifies the tag's
signature, then runs `apply.sh plan`, asks you to confirm, `apply.sh apply` and `deploy-services.sh --all-jobs`; when
the release changes no platform Terraform the plan is empty and only the services are deployed).

The answer is cached for an hour (**Check again** asks GitHub now). Two answers are plain states, not errors, shown in
grey and cached for the hour like a release:

* **The release repository … is not published yet, or it is private.** GitHub answers "not found" for the release
  source repository (before the public StackVend release, every install sees this for the official repository; a
  private fork cannot be read without signing in either). Updates are manual until it is published; the manual
  commands are shown.
* **… has no release yet.** The repository exists but has no usable release tag (drafts and tags that are not
  `vMAJOR.MINOR.PATCH` do not count; nor do previews when the release source hides them).

A failed check (GitHub's rate limit, no internet egress, any other GitHub error) is shown in amber as **Could not
check**, says why and is never cached. Nothing read from GitHub is trusted for anything but this display.

**Check for updates switch** (on by default). **Turn update check off** is for installs that update from their own
fork or that have no internet egress. When it is off:

* the Control Center makes **no GitHub call** for releases, release manifests, branch heads or the weekly upstream-sync
  variables (that card then shows the `gh variable set` commands instead of reading or setting them; the GitHub App
  that workload repositories use is not affected);
* the tab says "Update check: off" (with who last changed the release source and when) and that updates are manual:
  `PROJECT_ID=<project> bash scripts/upgrade.sh <tag>` (verifies the signed tag, then platform Terraform and services,
  from the checkout you installed from); **Turn update check on** switches it back.

Any administrator can change it, also behind Identity-Aware Proxy: no recent sign-in and no typed confirmation are
needed (off only reduces what the Control Center reads; on only re-enables a read of the configured repository's
public data and installs nothing). It is refused if someone else changed the release source since the page loaded,
and while the stored release source is invalid (checks are then off anyway). From a terminal:
`PROJECT_ID=<project> python3 scripts/release-source.py update-check off` (or `on`; asks you to type `OFF` / `ON`).
The switch is stored with the release source in the guard database; every change adds an entry to the release
source's change record (never trimmed) and logs a `stackvend.release_source_changed` line with `to_update_check`. It
does not change where upgrades come from, so the "Upgrades come from" line keeps its colour.

**Update StackVend.** Deploys the newest release's services and jobs from the release source, the same result as
`scripts/deploy-services.sh --all-jobs` from that release. It never runs Terraform. The Control Center itself deploys
nothing: it records the request and a lease in the guard database, turns maintenance mode on, and sends one message to
the upgrader (a Cloud Build trigger that runs as `sa-stackvend-upgrader`, which may only build images and deploy new
revisions of the existing services and jobs).

**On `0.9.0-preview` and `0.9.1-preview.1` the button cannot update.** The Control Center of those releases asks
GitHub for the release tag in a form GitHub does not answer, so every press stops with `TAG_UNRESOLVED` (HTTP 502)
before anything is recorded: no lease, no request, no maintenance mode. Update those installs from a terminal with
`PROJECT_ID=<project_id> bash scripts/upgrade.sh <tag>` from the checkout you installed from. Their `upgrade.sh`
verifies the signature but not the name inside the tag, so check the tag yourself before running it (the commands are
in the README's "Updating an installation"), and never pass `--trust-unsigned` for an official release. The button
works on an install that already runs `0.9.1-preview.2` or later, for the releases after it.

* **When it is shown.** Only on an install whose platform Terraform includes the upgrader (the Control Center then
  has `STACKVEND_PLATFORM_UPGRADE_TOPIC`); otherwise the card says the upgrader is not installed and updates are manual.
  A new install made with `scripts/bootstrap.sh` has the upgrader (`enable_platform_upgrader = true`); an existing
  install has it once that variable is set and `scripts/apply.sh apply` has run ([Configuration](configuration.md)).
  It is also hidden while the update check is off. It is enabled only when the last check found a newer release, its
  `release-manifest.json` was read, and the platform Terraform is at least the oldest platform release the release
  runs on. Otherwise one line says why: not published yet, no release yet, could not check, this install runs the
  newest release, the release needs `apply.sh` first (run the terminal steps, then **Check again**), platform
  release unknown, the release source follows a branch, or an upgrade is in progress.
* **Starting.** Type this install's project id. It is refused while workload runs are in progress unless you tick
  **Upgrade anyway if workload runs are in progress** (they keep running). A second click sends nothing new. New
  workload runs are refused (maintenance mode) until it ends; runs already in progress continue.
* **Approval.** By default an administrator must approve this build in the Google Cloud console (Cloud Build ▸ History)
  within 60 minutes of the request; the card says so while it waits. A build approved later refuses to start (its
  lease no longer covers a whole 2-hour build); clear the lease and request again. Approve only a build whose
  `_REQUEST_ID` substitution matches a request you just made: find the build in Cloud Build ▸ History by that
  substitution (the card links Cloud Build ▸ History; its link to this build appears only once the build starts,
  after approval). An operator can turn the approval off in the install's tfvars.
* **What the build checks again** before it changes anything: the tag's signature against the trusted keys of the
  release source, that the tag still points at the commit you confirmed, no downgrade, the platform guard
  (`NEEDS_APPLY_SH` stops it with the terminal steps), that the update check is on and that the release source did not
  change since you pressed the button. Then it builds every image (nothing is deployed unless all build), deploys them
  with the Control Center last, and checks health.
* **Progress.** The card shows the stage, each component's result (built, deployed, healthy, check failed, rolled
  back), the build log link and any refusal with its code and steps.
* **One at a time.** A second upgrade is refused while one holds the lease, and the release source cannot be changed
  meanwhile.
* **Maintenance mode afterwards.** Restored to its earlier value after success, after a refusal, or after a failure
  before anything was deployed. After a failure that deployed something (**PARTIAL**, a failed health check) or a build
  that never reported an end, it stays on (fail closed) with a banner; **Turn maintenance off** (typed project id)
  puts back the earlier value.
* **Roll back services** (typed project id) is offered after **PARTIAL** or a failed health check: the upgrader
  redeploys the revisions (services) and images (jobs) it recorded before the deploy, through the same approval.
  Platform Terraform is never rolled back. **After the first button update, do not use it:** jobs cannot be rolled
  back yet (`ROLLBACK_UNAVAILABLE`, the result is partial); go back with `scripts/upgrade.sh <previous tag>` instead.
  **Retry** runs a request that did not succeed again, with the same verified release.
* **Stale lease.** The lease lasts the 60-minute approval window, 10 minutes for the build to start and the 2-hour
  build; while a build runs the Control Center extends it to cover that build's 2 hours (never beyond that total). A build that was rejected in the console or never started leaves
  the lease stale once the approval window has passed; one that timed out, once its 2 hours have. **Clear the stale
  lease** (typed project id) then frees it; it is refused while the build may still be waiting or running. Once a
  build has started, its request is marked started, so a repeated delivery of the same message can never run it twice.
* **Record.** Each request stays in the guard database (`platform_upgrades/{id}`: who, when, target, result) and the
  card lists the last 20. Log lines: `stackvend.platform_upgrade_requested`, `stackvend.platform_upgrade_lease_released`,
  `stackvend.platform_upgrade_lease_cleared`, `stackvend.platform_upgrade_maintenance_restored`; each maintenance change
  adds a `PLATFORM_UPGRADE_MAINTENANCE` entry to **Settings Audit History**.

**Release source.** The repository upgrades come from (default: the official StackVend repository), what to follow
(signed release tags only) and which signing keys are trusted (the official release
key by default; SSH `ed25519` / `ecdsa-sha2-nistp256` public keys, at most 8; RSA is refused). It decides what this tab
shows and what **Update StackVend** may install (the upgrader trusts only these keys). The line "Upgrades come from: …" is always shown, amber when it is not the official source. A change:

* needs an administrator signed in through Google Sign-In less than 15 minutes ago. Behind Identity-Aware Proxy the
  Control Center cannot see the sign-in time, so on such installs the release source cannot be changed from the
  browser. Change it from a terminal instead, signed in with your own Google account (`gcloud auth
  application-default login`; a service account is refused):
  `PROJECT_ID=<project> python3 scripts/release-source.py set --repository <owner>/<repo> --official-key`
  (add `--ssh-key-file <key.pub>` for your own signing keys, `--keep-current-keys` to keep the trusted ones;
  `show` prints the current setting and the update check; it never reads GitHub). It applies the same checks and the same typed confirmation, records who changed
  it (taken from the credentials) with `via: "cli"`, and takes the project only from `--project` or `PROJECT_ID`;
* needs the repository name typed again, and for each newly trusted key the last 6 characters of its fingerprint;
* is refused if someone else changed the source since the page loaded, and (in the Control Center) while an upgrade
  is in progress; an upgrade whose release source changed after it was requested is refused by the upgrader;
* is stored in the guard database (which workload Terraform cannot write) with a change record (who, when, from,
  to) that is never trimmed, and logs a `stackvend.release_source_changed` line.

An invalid stored release source is shown as "Release source invalid" and switches the update check off until an
administrator saves a valid one; it is never silently replaced by the default.

**Weekly auto-update from upstream** (off by default). The switch is the GitHub repository variable
`STACKVEND_UPSTREAM_SYNC` of this install's platform repository: when it is `true`, the weekly sync workflow opens a
pull request for the newest signed official release (it never merges). Only the sync workflow of `0.9.1-preview.2` and
later verifies the release tag (its signature against the repository's own `scripts/release/allowed_signers` and the
name inside the tag); scheduled runs use the workflow on the repository's default branch. Leave the switch off, and
delete the repository secret `STACKVEND_SYNC_TOKEN` if it exists, until that branch holds the verified workflow,
merged by hand after verifying the tag (see the README's "Opt-in upstream sync"). The verified workflow reads the
upstream without credentials, so the upstream must be a public repository. The button sets the variable through the GitHub API
when the Control Center's GitHub token is allowed to change repository variables; otherwise it shows the exact
`gh variable set` commands to run. The workflow also needs `STACKVEND_UPSTREAM_REPO` (shown with the commands).
After turning the switch on, the Control Center reads `STACKVEND_UPSTREAM_REPO`: when it is unset, not an
`owner/repo` name, unreadable, or names the platform repository itself, the answer says the switch is on but not
effective (the workflow skips every run) and shows the one remaining command. The Control Center never sets
`STACKVEND_UPSTREAM_REPO` itself: it decides which repository's releases are pulled into the platform repository, so
it stays a terminal step for someone with admin rights on the repository. The command shown always names the official
repository, even when the release source above is set to another one.

### Access Control

The users allowed to sign in, and their roles.

* **Grant Access** adds a Google account (the e-mail is lower-cased) with a role: `ADMIN` (everything),
  `WORKLOAD_MANAGER` (the workloads assigned to the user) or `VIEWER` (read-only, assigned workloads). Non-admin users
  get a list of assigned workloads. Adding an address that already exists replaces its role and workloads. The legacy
  `APPROVER` role is not offered; the API (`POST /api/users`, `PUT /api/users/{email}/workloads`) still accepts it and
  stores it as `WORKLOAD_MANAGER`, which is what it has always allowed.
* **Revoke Access** removes the user's record; it applies from their next request. The platform owner set at install
  time cannot be revoked.
* A grant, change or revoke that Firestore did not save is reported as an error (HTTP 503, code
  `USER_ACCESS_NOT_STORED`), never as done: a failed revoke means the user can still sign in; a failed change leaves
  the user's access as it was. A grant that could not reach Firestore at all (Firestore unavailable or timed out) is
  kept only in that Control Center instance's break-glass list, which is used only while the instance cannot read
  Firestore; grant again once Firestore is back. A grant that Firestore refused keeps no such copy (the answer then
  does not mention the instance). The copy is removed as soon as that user's access is saved, changed or revoked
  through the same instance, or a newer grant for that user is refused.
* Every grant, role or workload change and revoke is audited: an entry in the Firestore collection
  `user_access_audit` (`USER_ACCESS_GRANTED`, `USER_ACCESS_UPDATED`, `USER_ACCESS_REVOKED`, with the user, the
  administrator, the time, and the role and workloads before and after) is written in the same write as the change, so
  a change is never stored without its entry. The tab's **Access Changes** list shows the last 50 entries, newest
  first: when, what, the user, the administrator, and the role and workloads before → after (`GET
  /api/users/access-audit`, administrators only). They are not part of the settings audit history.
* This list is also the list of **authorized Drive submitters** (active `ADMIN` and `WORKLOAD_MANAGER` users, plus
  legacy `APPROVER` records). Revoking someone stops their Drive specs from being built.

### Emergency Stop

A platform-wide kill switch for an incident. **Engage Emergency Stop** (after a reason and a confirmation):

1. records the stop (who, when, why);
2. cancels every running execution of the `castor-main-orchestrator` and `castor-sre-remediation` workflows (through
   the Workflows API, with the Control Center's own service account);
3. sets **code freeze** on and **SRE auto-healing** off on every workload record except decommissioned ones (status
   `DECOMMISSIONED` or `DELETED`, which are not changed). In the same write it saves the workload's previous values in
   `emergency_stop_snapshot` on the record.

Engaging again while the stop is already on freezes the workloads again but keeps each saved snapshot, so the values
from before the first engage are the ones put back. The response and the toast give the counts (frozen, decommissioned
skipped, failed); a workload that could not be frozen is named. If the workload list stops part-way, the workloads
frozen so far stay frozen and the error says how many were reached.

The response also reports each running workflow execution it found: cancelled, already finished, or failed with a
reason. `workflows_cancel_status` is `OK` only when both workflows could be listed and every running execution was
cancelled (or had already finished). Otherwise it names the problem, the toast says the running workflows were **not**
all cancelled, and the Emergency Stop tab shows it while the stop is on:

| `workflows_cancel_status` | Meaning |
| :--- | :--- |
| `WORKFLOW_CANCEL_NOT_PERMITTED` | Google refused the list or the cancel (HTTP 403): the Control Center service account lacks `roles/workflows.invoker`, or the Workflows API is off. |
| `WORKFLOW_CANCEL_UNCONFIGURED` | The Control Center could not tell its project, its region or its credentials, so it listed nothing. |
| `WORKFLOW_LIST_FAILED` | A workflow's running executions could not be listed. |
| `WORKFLOW_CANCEL_FAILED` | At least one running execution could not be cancelled. |

In every one of these cases the stop itself is still on and the workloads are still frozen, but some runs may still be
going: cancel them in the Google Cloud console (Workflows), or engage again.

The workloads are frozen even if recording the stop fails; recording it is then tried once more. If that also fails,
engage ends with an error ("N workloads frozen but the kill switch could not be set") and the switch is **not** on, so
new runs are not blocked: engage again.

While it is engaged, the orchestrator workflow refuses to start a pipeline and checks the switch again before vending,
development and deploy; the SRE sentinel starts nothing.

**Disengage & Resume Operations** clears the switch so new runs can start, then puts back each workload's code freeze
and SRE auto-healing from its snapshot and removes the snapshot. A workload that was frozen before the stop stays
frozen; one that was not is unfrozen. If you changed either setting on a workload while the stop was on (its value is no
longer the one the stop set), your value is kept for that setting. Workloads with no snapshot are not changed, and
neither are decommissioned ones, including a workload decommissioned while the stop was on (its snapshot stays on the
closed record and is never used). A snapshot that cannot be read is removed and that workload keeps its current
(frozen) settings; the response reports it. Each restored workload gets an `EMERGENCY_STOP_RESTORE` entry in its audit
log, and the counts of the last engage and resume are kept on the stop record.

If a workload cannot be restored, it stays frozen with its snapshot and the toast names it. The Emergency Stop tab then
shows the workloads still frozen and a **Retry restore of N frozen workloads** button, which runs the same resume again
(administrators only) and tries only those workloads; you can also unfreeze them on their pages. If the switch itself
cannot be cleared, or the stop is engaged again between reading and clearing it, resume fails with an error and changes
no workload. If the stop is engaged again while workloads are being restored, every workload is frozen again for the new
stop and the page says so. Cancelled runs are not restarted; retrigger them.

Use it for real incidents (runaway spend, a security alert). For planned work use
[Maintenance Mode](#maintenance-mode), which lets running work finish and changes no workload.

---

## 10. Per-workload governance controls

These are on each workload's page (**Workload Governance & Autonomy Controls**), not on the Settings page, but they
override or complement the platform defaults above. Changing them is administrator-only and takes effect for the
workload's next run or automatic event.

| Control | Key | Default for a new workload | Effect |
| :-- | :-- | :-- | :-- |
| **Master Code Freeze** | `code_freeze` | the platform's *Freeze new workloads by default* setting (on) | Stops the automatic runs that change the workload's code: SRE auto-healing and the code scanner are suppressed (`SUPPRESSED:CODE_FREEZE`), and **Upgrade IaC** is refused (423). Budget enforcement and the sandbox expiry sweep still apply. While frozen, the other controls on the card are locked: unfreeze first to change them. Builds, retriggers and feature requests an operator starts are not blocked, including a new workload's first build. A re-create, re-vend or redeploy keeps the current value. |
| **Human Code Review (HITL)** | `require_human_code_review` / `auto_merge` | the platform's *Force HITL* setting | Release pull requests wait for a person instead of merging automatically. |
| **Plan Approval (HITL)** | `require_plan_approval` | the platform's *Require Plan Approval* setting | The run pauses for approval of the architecture plan before development. The platform setting, when on, still applies to every workload. |
| **SRE Auto-Healing** | `sre_auto_healing_enabled` | on (a re-create, re-vend or redeploy keeps the current value) | Lets the SRE sentinel start a hotfix run when runtime error spikes appear in Cloud Logging. |
| **Code & Security Scanner** | `refactor_scanner_enabled` | on (a re-create, re-vend or redeploy keeps the current value) | Lets the scheduled code scanner open refactoring and security pull requests for the workload. |
| **Budget Breach Enforcement Policy** | `budget_breach_policy` | the platform's *Default Budget Breach Enforcement Policy* | What happens when spend reaches the workload's ceiling (choices as in [section 3](#default-budget-breach-enforcement-policy)). |
| **GitHub Actions Deploy** (GitHub workloads) | `github_actions_deploy` (`PATCH /api/workloads/{id}/github-actions-deploy`, audited) | on (the create form's **GitHub Actions deploy** box; a workload without the field is on) | On: each service's `.github/workflows/deploy-<service>.yml` deploys the app's code with `sa-gh-deployer` through Workload Identity Federation, without StackVend's checks. Off: the next pipeline run deletes those workflows and the next deploy removes the identity federation pool, provider and `sa-gh-deployer`; every deploy goes through StackVend's pipeline. Serverless Git workloads refuse it. |

Set when the workload is created (create form or API):

* **Monthly Budget ($ USD)**: the workload's ceiling (default $50, minimum 5 on the form). An approved budget increase
  or a temporary buffer ceiling can raise it later through the approval card.
* **Sandbox** and **Initial Sandbox Lifespan** (14, 30 or 60 days on the form; 1 to 90 through the API, where a longer
  lifespan is not recorded as an expiry and the sandbox is then never deleted automatically): only a workload
  marked as a sandbox on the form or API is deleted automatically when its lifespan ends. A workload that is only
  *detected* as a sandbox from words in its spec shows a countdown but is never deleted automatically. A sandbox can be
  extended (1 to 30 days at a time, at most 3 times, at most 90 days in total), promoted to permanent, or
  decommissioned. Automatic deletion needs the deletion safety tag (see
  [Install warning cards](#install-warning-cards)). See [Workload Lifecycle](workload-lifecycle.md).

---

## 11. Stored settings that are not on the page

These fields are part of the stored settings document but have no field on the Parameters tab. Unless noted, they can
be changed only through `PUT /api/settings` (administrators; same validation and audit as the page), which takes the
whole document. Saving the page keeps their current values.

| Key | Default | What it does |
| :-- | :-- | :-- |
| `governance.vcs_provider` | `GITHUB` (or the `VCS_PROVIDER` environment variable) | Default Git provider for new workloads; changed by the VCS card's switch. |
| `governance.git_server_url` | empty | Address of the serverless Git service. |
| `orchestration.ipam_supernet_cidr` | `10.100.0.0/16` | Pool that workload subnets, VPC connector ranges and Private Services Access ranges are taken from. **Risky:** change it only before workloads exist; it must not overlap your other networks. |
| `orchestration.ipam_connector_prefix` | 28 (26 to 29) | Size of Serverless VPC Access connector ranges (Google Cloud requires /28). |
| `orchestration.ipam_subnet_prefix` | 24 (20 to 28) | Size of standard workload subnets. |
| `orchestration.supported_terraform_versions` / `supported_tofu_versions` | see [Configuration](configuration.md) | The version drop-down lists. |
| `models.fallback_models` | `["gemini-4-argon", "gemini-3.8-flash", "gemini-3.7-flash"]` | Models tried, in order, when an agent's model is rate-limited or unavailable. Ids are checked when saved. |
| `models.custom_directives` | empty | Extra operating instructions per agent role (at most 5 per agent), added to the architect and compliance prompts. Managed from the agent details on the **Multi-Agent Pipeline** tab. |
| `orchestration.default_folder_id` | empty | Not used; the default folder is chosen on the GCP Folders tab. |
| `orchestration.default_terraform_timeout_seconds` | 3600 | Not used at present. |
| `orchestration.max_pipeline_retries` | 3 | Not used at present. |
| `orchestration.max_vending_timeout_seconds` | 1200 | Not used at present. |
| `orchestration.high_memory_container_mb` / `high_cpu_container` | 1024 / 2 | Not used at present. |
| `runtimes.artifact_registry_virtual_repo` | empty | Not used at present. |

---

## Known gaps between the page and the platform

The following controls are shown on the page but do not change what the platform does today, or behave differently
from their description. They are listed so you are not surprised; they are expected to be fixed in a later release.

* None at present.
