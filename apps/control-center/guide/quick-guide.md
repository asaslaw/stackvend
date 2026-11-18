<!--
StackVend quick guide. This file is the source of truth. The Control Center Guide tab serves a byte-identical copy,
apps/control-center/guide/quick-guide.md: after editing this file, copy it there (tests/test_fd4cv_quick_guide.py
fails when the two differ).

Writing rules (checked by that test):
1. Bold text is used only for names shown in the Control Center (tabs, buttons, cards, settings, form fields),
   written exactly as they appear on screen. Every bold name must be visible text in
   apps/control-center/templates/dashboard.html. Use italics for anything else.
2. Every section ends with one line that starts with "Details →" and holds one or more links to headings of the
   other documents in this folder, separated by " · ". Links appear nowhere else. Each link names an existing file
   and, after #, the anchor of an existing heading in it. The Control Center does not show these lines (the Guide
   tab never sends people out of the Control Center), so every section must be complete without them: what to
   click, who can do it, what happens, and the gotcha.
3. Content that only administrators can use sits between two marker lines: an HTML comment whose text is
   admin-only opens the block, and one whose text is /admin-only closes it. Each marker is a line of its own,
   blocks do not nest, and every block is closed. The Control Center hides these blocks from users who are not
   administrators. That is display only: the server still checks every action.
-->

# StackVend Quick Guide

Short answers to everyday tasks in the Control Center. Where this guide and the screen differ, the screen is right.

## Submit a spec

<!-- admin-only -->
- In **Workloads Catalog**, click **New Workload** (administrators only).
- Choose **Autonomous AI Swarm** to build from a written spec. Type it, or use **Upload Document** (PDF, DOCX, Markdown, plain text, JSON or YAML, up to 25 MB). Results are best up to about 25,000 characters (roughly 8-10 pages); the character count under the spec turns amber above that (details may be missed) and red above about 100,000 (the run may fail to start).
- Fill in the slug, **Monthly Budget ($ USD)** (pre-filled with the platform default, $40), **Breach Enforcement**, **Region** (one of the approved regions, the default region selected first; a workload keeps its region), **Security controls baseline** (in an ordinary folder a baseline applies its technical controls but does not make the workload compliant; FedRAMP, HIPAA and CJIS compliance need an Assured Workloads folder of that regime; a baseline that does not allow the chosen region is refused) and **Who may use this app** (private by default; one member per line, for example `user:ana@example.com`; a private app needs at least one member).
- **Public** is always your explicit choice; the form then asks whether the app handles money, personal data or other customers' data. In a Public workload every Cloud Run service is public, including a worker that only Pub/Sub calls: per-service access is not available yet.
- Optional switches: **Require Human Code Review (HITL)**, **Require Plan Approval Before Development (Architect Gate)** and **Designate as Autonomous Sandbox (Auto-Decommission)**.
- **GitHub Actions deploy** (GitHub only, on): each service gets a workflow that redeploys its code from the branch without StackVend's checks. Off: no workflow and no deploy identity, so every deploy goes through StackVend's pipeline. Change it later on the workload's page (**GitHub Actions Deploy**); turning it off removes the workflows on the next pipeline run and the deploy identity on the next deploy.
- Click **Create & Launch Workload**. The run appears in **Flight Deck**.
- **Express Registered Modules** builds from golden modules without a spec.
- Express workloads ask **Who may use this app** too, and are private by default (you are listed); the answer covers every Cloud Run service. Express workloads created before this default keep their current access.
- Keep edit access to the Drive intake folder limited to the people allowed to submit specs: a Drive spec is trusted by its owner, and ownership can be transferred.
<!-- /admin-only -->
- Google Drive: put a Google Doc in the intake folder. Drive intake is *off* unless the installer turned it on.
- A Drive spec is built only when its Drive owner is an active Administrator or Workload Manager (or a legacy Approver). Files in shared drives have no owner and are skipped. The title names the workload: a Workload Manager can send specs only to a new workload (which then assigns them to it) or one assigned to them, nobody can target the StackVend platform itself, and a title that does not give a valid workload id (letters, digits and hyphens, at most 63) is skipped. Anything else stays in the inbox with a reason, and is checked again on the next poll.
- By default a new workload starts frozen (see *New workloads start frozen*) and private: only the people listed under who may use it can open the app. **Public** is only ever an explicit choice.
- Private (Google sign-in) apps admit only accounts of your Google Cloud organization; a personal Gmail account is refused, so list organization accounts.
- Workload Managers and Viewers cannot create workloads in the Control Center.

Details → [Creating a workload](user-guide.md#4-creating-a-workload) · [Via Google Drive](user-guide.md#via-google-drive-spec-intake) · [Choosing who may use the app](user-guide.md#choosing-who-may-use-the-app) · [Known issues](known-limitations.md#other-known-issues)

## Watch a build

- **Flight Deck** shows running builds: the current stage, logs by agent, and rate-limit cooldowns. Its badge counts active runs.
- Only **Max Concurrent Builds** (Settings, default 1) builds that use the AI models run at a time. A new build or relaunch over the limit waits as Queued (#n in line) under **Mission Trace** and starts by itself, oldest first, when a running build ends. The queue moves only when something happens: a build ends, a new build is submitted, or someone has the Flight Deck open. **Cancel Queued Build** removes it before it starts. Fast-Path Deploy and Express builds never wait.
- Stages, in order: pre-discovery, architect plan, compliance and cost, plan approval (when required), project vending, developer swarm, checks and QA, release pull request, deploy.
- **Abort Mission** stops a run (administrators and the workload's Workload Managers). An abort during the deploy stage does not stop an infrastructure apply that has already started: it keeps running and holds the workload's Terraform state lock until it ends. Wait for it to finish before you run the workload again.
  - It cancels the run's Cloud Workflows execution first. If that cancel fails (for example `WORKFLOW_CANCEL_FAILED` or `WORKFLOW_CANCEL_NOT_PERMITTED`), the run is **not** marked aborted, the error says why, and the run may still be going: try again, or cancel it in the Google Cloud console (Workflows).
- Past runs: open the workload from **Workloads Catalog**, pick a run under **Historical Mission Run**, then **Generate Mission Debrief & AAR** for a summary (administrators and the workload's Workload Managers). The **Flight Deck** button there opens its logs.
- After the deploy, the service URL and the Google Cloud project show on the workload's page.
- QA does not judge a requirement the platform meets itself against the generated code: a budget cap in the spec is met by the workload's monthly budget ceiling, a sandbox lifespan by its sandbox record. The QA summary shows it as "Satisfied by the platform". Check that the ceiling is the amount the spec asks for.
- After a build passes its checks, the workload's page may list **Environment variables the platform does not set**: variables the code reads that the service does not get, so the code falls back to its own default. These are warnings and never block; check each one before you approve a release.
- Secrets: a key the app makes and uses itself (a signing or encryption key) gets a random first value. A credential from another system is created empty: add its value in Secret Manager (a new version of the secret) before the app needs it.
- Failed run: the logs stay in **Flight Deck**. Fix the cause, then run it again with **Relaunch with** on the debrief, or **Re-launch Build** on a feature request. Cancelled runs never restart on their own.
- A failed run can leave partly created cloud resources (a child project, for example); review and clean them up.
- A run that stops with `ACCESS_POLICY_INCOMPLETE`, `ACCESS_POLICY_REQUIRED` or `ACCESS_COMPLIANCE_CONFLICT` needs an administrator to set who may use the app: on the workload's page, **Who may use this app**, **Edit access** (API: `PATCH /api/workloads/<id>/access`); then run it again with a full relaunch (**Full Swarm Rebuild**: the run stopped before any code was generated). If the change lets more people in, the next run waits for a plan approval. A later change between private records (people added or removed) applies with **Fast-Path Deploy**; a change to or from Public needs **Full Swarm Rebuild**.
- A run that stops with `COMPLIANCE.PRIVATE_INGRESS_UNSUPPORTED` needs its requirement changed: this release cannot make Cloud Run services internal-only. The message names what asked for it; remove that, then start a full run (with the requirement gone, you can protect the services with IAM only). On a live workload, Fast-Path stays blocked until a full run succeeds without the requirement.

Details → [Following the pipeline](user-guide.md#5-following-the-pipeline) · [If a run fails or stalls](user-guide.md#if-a-run-fails-or-stalls) · [Secrets from other systems](known-limitations.md#secrets-from-other-systems-are-added-by-an-operator)

## Approve a plan or a release

- Decisions waiting for a person are in **HITL Approvals** (the badge counts them). Filter with **Pending**, **Resolved** or **All**.
- Plan card: open **Architecture Plan Blueprint**, then choose **Approve Architecture** (the run continues: project vending, then development), **Request Rework** (you type guidance for the architect) or **Decline Workload**.
- Release card (when human code review is on): it shows the repository and branch it merges. Review the pull request there, then choose **Approve & Resume Pipeline** (it merges and deploys) or **Reject Build**.
- For example, a plan waits for approval when the workload asks for it, when a platform setting requires it, on an organization-policy conflict or a cost warning, and after someone widened who may use the app.
- A plan of a Public workload also waits when a Cloud Run service that only Pub/Sub calls would be public (`ACCESS.INTERNAL_SERVICE_PUBLIC`): the card names it under **Reachable from the internet**. Approve only if that service's own code checks the caller's token. The card also lists **Secrets created without a value**, when there are any: approving adds no value.
- Platform-action card (a Helm uninstall, an Agent Engine deploy or a Discovery Engine datastore create): **Approve Action (single use)** gives a 15-minute approval for exactly that action; pass the approval id shown on the card to the tool.
- A widening of who may use the app keeps every later run waiting at plan approval until a plan is approved; rejecting or asking for rework does not clear it.
- Administrators and the workload's Workload Managers can decide most cards; a compliance profile downgrade, a platform-action card and a budget card's **Decommission** are administrators only. Viewers cannot decide.
- A card that says the merge failed can be decided again once the cause is fixed. If GitHub refused the merge, or main moved on Serverless Git, the run ends at once instead (`RELEASE_FAILED` or `MAIN_MOVED`); re-run the workload.
<!-- admin-only -->
- Require plan approval on every run: Settings, **Parameters**, **Require Plan Approval for Every Run of Every Workload (Architect HITL Gate)**. Human review of release pull requests for new workloads: **Force HITL for All New Workloads (Auto-Merge: OFF)** (on by default; turning it off lets generated code merge and deploy without a human look).
<!-- /admin-only -->

Details → [Approvals](user-guide.md#approvals) · [Cloud Run services cannot be made internal-only yet](known-limitations.md#cloud-run-services-cannot-be-made-internal-only-yet) · [Plan approval settings](settings-reference.md#require-plan-approval-for-every-run-of-every-workload-architect-hitl-gate)

## New workloads start frozen

- While **Freeze new workloads by default** is on (the default), every new workload starts with **Master Code Freeze** on.
- Frozen blocks the automatic runs that change code (SRE auto-healing and the code scanner's pull requests) and the **Upgrade IaC** action.
- Still runs while frozen: the first build and deploy, the builds, retriggers and feature requests you start, budget enforcement, and the sandbox expiry sweep.
- The freeze state shows on the workload's page under **Workload Governance & Autonomy Controls**. Only administrators can change it.
<!-- admin-only -->
- To unfreeze: open the workload, find **Workload Governance & Autonomy Controls**, click **Unfreeze**. The card's other controls stay greyed out until you do. **Freeze Code** freezes it again.
- To start new workloads unfrozen, turn off **Freeze new workloads by default** (Settings, **Parameters**, **Platform Governance & Gates**) and click **Save Changes**. Existing workloads never change; re-creating or redeploying a workload keeps its current freeze.
<!-- /admin-only -->

Details → [New workloads start frozen](user-guide.md#new-workloads-start-frozen) · [Freeze new workloads by default](settings-reference.md#freeze-new-workloads-by-default) · [Per-workload controls](settings-reference.md#10-per-workload-governance-controls)

## Budget breach

- Each workload has a monthly ceiling (set on the create form, pre-filled with the platform default of $40) and a breach policy (**Breach Enforcement** on the create form, or later on the workload's page by an administrator, after unfreezing it).
- Spend is synchronized nightly and shows on the workload's page next to its ceiling.
- The policy acts on Cloud Billing budget notifications, and StackVend does not create budgets yet. In this preview create one yourself on the install's billing account, named `budget-<workload id>`, and connect it to the `billing-budget-alerts` Pub/Sub topic. Without such a budget the policy never fires.
- A notification is acted on within about 30 minutes (a job reads the topic every 30 minutes), once per workload, billing month and threshold.
- What happens when spend reaches the ceiling:
  - **Auto Scale-to-Zero** (the platform default unless an administrator changed it): the workload's compute is stopped and it is marked quarantined.
  - **Alert Only**: an alert is recorded; nothing stops. It never protects you from runaway spend.
  - **HITL Required**: an approval card is created first; nothing stops until someone decides.
  - **Nuclear Unlink**: the project is detached from billing, which stops everything billable in it. Use it for disposable workloads.
- For every policy except **Alert Only**, a budget card appears in **HITL Approvals** with four choices: **Decommission** (administrators only), **Maintain Quarantine**, **Restore (+15% Buffer)** and **Increase Budget & Restore**. A restore can take up to 10 minutes and the page may show a network error meanwhile; deciding the card again is safe.
- Budget enforcement still applies to a frozen workload.
<!-- admin-only -->
- The policy that **Platform Default** stands for: Settings, **Parameters**, **FinOps & Budget Controls**, **Default Budget Breach Enforcement Policy**. It applies to workloads created after the save. The same card sets the budget a new workload starts with (**Default Monthly Budget Ceiling ($ USD)**, $40), when a warning is recorded (**Warning Threshold (%)**, 80) and when the policy fires (**Circuit Breaker (%)**, 100 = at the ceiling).
<!-- /admin-only -->

Details → [Budgets and spend](user-guide.md#budgets-and-spend) · [Default Budget Breach Enforcement Policy](settings-reference.md#default-budget-breach-enforcement-policy) · [No billing budgets are created](known-limitations.md#no-billing-budgets-are-created-for-workloads)

<!-- admin-only -->
## Emergency Stop or Maintenance Mode

- Planned work: use **Maintenance Mode** (Settings, **Parameters**, **Platform Governance & Gates**, then **Save Changes**; takes effect within a minute).
  - No new run starts: create, retrigger, redeploy and Drive intake are refused (`MAINTENANCE_MODE`). Drive specs wait in the inbox.
  - Runs already going finish. No workload is changed. Settings, approvals and decommission still work.
- A real incident (runaway spend, a security alert): use **Emergency Stop** (a Settings tab). Enter a reason, click **ENGAGE EMERGENCY STOP** and confirm.
  - It cancels every running pipeline and SRE remediation run. If the toast says the running workflows were *not* all cancelled, some runs may still be going: cancel them in the Google Cloud console (Workflows), or engage again.
  - It turns code freeze on and SRE auto-healing off on every workload that is not decommissioned, and saves each workload's previous values.
  - New pipelines are refused while it is on, and a red banner shows at the top of the Control Center.
  - If the error says workloads were frozen but the kill switch could not be set, the stop is *not* on: engage again.
- **Disengage & Resume Operations** lets new runs start and puts back each workload's freeze and SRE auto-healing as they were before the stop. A value you changed on a workload during the stop is kept.
- Cancelled runs are not restarted: retrigger them.
- A workload that could not be restored stays frozen. Use **Retry restore** on the **Emergency Stop** tab, or unfreeze it on its page.

Details → [Maintenance Mode](settings-reference.md#maintenance-mode) · [Emergency Stop](settings-reference.md#emergency-stop)
<!-- /admin-only -->

## Decommission and sandbox expiry

- A sandbox is a workload created with **Designate as Autonomous Sandbox (Auto-Decommission)**. It gets an **Initial Sandbox Lifespan** (14, 30 or 60 days; 30 by default) and a countdown on its page.
- Warnings are recorded at 7 and at 2 days left, and a **Sandbox Expiration Imminent** banner names the workloads.
- A daily sweep (04:00, America/New_York) decommissions expired sandboxes. It waits 24 hours while a build is running or a release review is pending.
- A workload only *detected* as a sandbox from words in its spec shows a countdown but is never deleted automatically.
- Decommission deletes the workload's Google Cloud project, with everything in it, and takes its spend to zero. The Git repository and the Terraform state are kept; an administrator can bring it back with **Redeploy Workload** (in a new project).
<!-- admin-only -->
- On a sandbox's page: **Extend (+30 Days)** (at most 3 times and 90 days in total), **Promote to Production** (no expiry) or **Decommission Now**.
- Any workload: **Decommission**, then type the workload's ID to confirm. A decommissioned workload can be archived with **Archive Workload**.
- Decommission, including the automatic sweep, needs the deletion safety tag. While it is not set up, a banner on every Control Center page and a warning on the New Workload form say so, and an install warning card on Settings, **Parameters** gives the fix: do that first (see *Understanding Settings*).
<!-- /admin-only -->

Details → [Sandboxes: extend, promote, decommission](user-guide.md#sandboxes-extend-promote-decommission) · [Daily sweeper](workload-lifecycle.md#4-autonomous-daily-sweeper) · [Install warning cards](settings-reference.md#install-warning-cards)

## Users and roles

- Administrator (`ADMIN`): everything, including creating workloads, Settings, users, the governance controls, decommission and the emergency stop.
- Workload Manager (`WORKLOAD_MANAGER`): the workloads assigned to them. Feature requests, re-running and aborting builds, deciding approvals, and submitting Google Drive specs. Cannot create workloads in the Control Center or change settings.
- Viewer (`VIEWER`): read-only view of the workloads assigned to them. A workload's Terraform state outputs are shown to its Workload Managers and administrators only.
- Sign in to the Control Center with an account of your Google Cloud organization that an administrator added. Behind the installer's default Google sign-in (Direct IAP) a personal Gmail account is refused.
- Your role is shown next to your e-mail address at the top right. To change your role or your assigned workloads, ask an administrator.
- Administrators see extra sections in this guide. Hiding them is display only; the server checks every action.
<!-- admin-only -->
- Add or change a user: Settings, **Access Control**, **Grant Access**. Adding an address that already exists replaces its role and workloads.
- **Revoke Access** removes a user; it applies from their next request. The platform owner set at install time cannot be revoked.
- Every grant, change and revoke is recorded (who did it, when, and the role before and after) in the `user_access_audit` collection in Firestore; **Access Changes** at the bottom of the tab shows the last 50, newest first.
- If the save fails, the page says so (the change was not made; a failed revoke means the user still has access). Try again.
- The same list decides who may submit Google Drive specs: revoking someone stops their Drive specs from being built.
<!-- /admin-only -->

Details → [Signing in and roles](user-guide.md#2-signing-in-and-roles) · [Access Control](settings-reference.md#access-control)

<!-- admin-only -->
## Understanding Settings

- What lives on each Settings tab:
  - **Parameters**: the platform settings form, the billing and Git provider status cards, the install warning cards, the **Platform network** card and **Settings Audit History** (the last 15 saves).
  - **GCP Folders**: the folders child projects are created in. **Set Default** picks the one used when a workload names none.
  - **Network & IPAM**: a read-only list of the network ranges given to workloads.
  - **Modules & Bundles**: the golden modules and bundles the agents build from.
  - **Agent Skills** and **Agent Prompts**: extra guidance and the system prompt of each agent. A published prompt changes every later run of that agent; roll back if a run gets worse.
  - **Cloud Quotas**: read-only regional headroom, used by the quota check before a build. **Upgrades**: which StackVend release each service and job runs, the newest release, where upgrades come from (**Release source**) and the weekly upstream-sync switch. **Update StackVend** deploys a newer signed release's services and jobs (never Terraform; new workload runs pause meanwhile) once the upgrader is installed; by default an administrator must also approve the build in the Google Cloud console (Cloud Build ▸ History). When it cannot run, one line says why (for example the release needs `apply.sh` first: run it from the root of the StackVend folder you installed from, which holds `infra/platform/<project_id>.tfvars`; the card says so with your project id). Before the public release the official repository reads "not published yet": updates are then manual with `scripts/upgrade.sh <tag>`. **Turn update check off** (forked or network-isolated installs) stops every GitHub call from this tab and hides the button.
  - **Access Control**: who may sign in, and their role (see *Users and roles*).
  - **Emergency Stop**: the platform-wide kill switch (see *Emergency Stop or Maintenance Mode*).
- **Save Changes** sends the whole **Parameters** form at once. One invalid value refuses the whole save and nothing is stored. Every service picks up a change within about a minute.
- If another administrator saved after you opened the page, your save is refused and nothing is stored: click **Reload** and make your change again. **Reset Defaults** puts back every built-in default, including maintenance mode, generate mode and the region.

Settings that change what StackVend does (each with its default):

- **Freeze new workloads by default** (on): new workloads start with **Master Code Freeze** on, so SRE auto-healing, the code scanner's pull requests and **Upgrade IaC** wait until you unfreeze. Turn it off only if new workloads should get automatic fixes straight away. Existing workloads never change.
- **Typed infrastructure (generate mode)** (on): new workloads describe their infrastructure as a typed list of approved building blocks, and the platform writes the Terraform from it. Cloud SQL, Redis, AlloyDB, Vertex AI endpoints and Bigtable work this way too (the platform supplies the private network and the Cloud Run connector where needed). New workloads only. Turn it off to have new workloads use agent-written Terraform; a value already saved in the settings is kept.
- **Maintenance Mode** (off): no new run starts; runs already going finish. For an incident, use the **Emergency Stop** tab instead.
- **Default Budget Breach Enforcement Policy** (**Autonomous Scale-to-Zero**): what happens at the spend ceiling of a workload created with **Platform Default** (see *Budget breach*). New workloads only. **Enforce Scale-to-Zero by Default** (on): an Agent-mode Cloud Run service whose spec states no minimum stops when idle; off keeps one warm instance per service, billed while idle.
- **Require Plan Approval for Every Run of Every Workload (Architect HITL Gate)** (off): on, every Agent-mode build of every workload that reaches the compliance step waits in **HITL Approvals** for a plan approval, whatever the workload's own setting (a resumed run keeps its earlier decision). Turn it on for a cautious rollout.
- **Architectural Plan Approval Trigger Policy** (`ON_COMPLIANCE_CONFLICT`): when else a plan waits. `ALWAYS` (every plan), `ON_COMPLIANCE_CONFLICT` (an organization-policy conflict) or `AUTONOMOUS_UNLESS_FAILED` (as before, and compliance advisories never pause). Policy conflicts, cost warnings, a workload's own plan approval and a widened access list always pause.
- **Force HITL for All New Workloads (Auto-Merge: OFF)** (on): release pull requests of new workloads, including those from a Google Doc spec, wait for a person. Off lets generated code merge and deploy without a human look.
- **Strict Compliance Gates** (on): a spec that mentions terms of a compliance profile the workload does not use (for example "credit card") pauses for a person. Off removes that check.
- **Require Human Approval for Destructive Terraform** (on): a deploy that would delete or replace a database, bucket or other data-holding resource stops for an operator. Off lets a regenerated plan delete data without asking.
- **Drive Folder Auto-Discovery** (off): on, Drive intake also polls every `01_Inbox_Requests` folder shared with the platform's service account and owned by an authorized submitter. Riskier: review **Access Control** and the sharing of those folders first.
- **Default Workload Region** (`us-central1`) and **Approved Deployable Regions** (empty: the default region only): the New Workload form offers only the approved regions, and each workload keeps the region it was created in. Saving checks a new region against Cloud Run's regions and refuses to remove a region a workload still uses. A workload created before approved regions follows the default region at its next deploy. Each workload's region (📍) is shown on its Workloads Catalog card and on its details page (in the header and under **Status & Project**); for a workload created before approved regions it reads the default region followed by "(Settings default)", for example us-central1 (Settings default).
- **Developer Swarm Token Ceiling (Circuit Breaker)** (350,000): the token budget of one build; a build that passes 110 percent of it stops and fails. Raise it only when large workloads stop on it. **Max Concurrent Builds** (1): how many AI builds run at once; the others wait in a queue and start when one ends (see *Watch a build*). Raise it only when your model quota can serve several builds at once. A build waiting for an approval gives its slot up and takes one again, ahead of new builds, once approved.
- Roles are set on **Access Control** with **Grant Access**: `ADMIN`, `WORKLOAD_MANAGER` or `VIEWER`. The same list decides whose Google Drive specs are built.

Safe to leave alone:

- Models: **Architect Agent Model**, **Developer Agent Model** and **Control Center Assistant Model** (`gemini-4-carbon`; fallbacks `gemini-4-argon`, `gemini-3.8-flash`, `gemini-3.7-flash`), and **Repair Model** (empty means the developer model). Carbon costs several times more per run than `gemini-3.8-flash` (about 4.5 to 9 times in offline evaluations); an existing install keeps the models it has saved. Any Gemini model id can be entered: each changed model gets one small live call when you save, and a model the API refuses (or that does not answer within 20 s) is not saved. A model StackVend has no price for shows its cost as unknown. Thinking levels (Architect LOW, Developer MEDIUM, Repair LOW, Other LOW) apply to Gemini 4-style models only; HIGH costs more.
- Token limits: **Global Max Output Tokens** (65,536), **Architect Token Limit (Override)** (16,384) and **Developer Token Limit (Override)** (65,536); an empty override uses the global limit. Limits that are too low cut generated files short. **Thinking Budget** (0: the model's own default; Gemini 3.x models only).
- **Terraform Lock Timeout (s)** (180) and **Verified Stale tf-applier Lock Age (min)** (20): how long a deploy waits for a held state lock, and when a held lock is reported as stale; no lock is ever broken automatically. **Default Container Memory (MB)** (512) and **Default Container vCPU** (1): the size of an Agent-mode Cloud Run service without heavy packages.
- **Default IaC Engine** (`OPENTOFU`), **OpenTofu Version** (`1.9.0`) and **Terraform Version** (`1.5.7`). OpenTofu is the tested path; Terraform 1.6 and later is refused when a deploy runs, so the list offers only earlier versions. A deploy runs an engine only after its downloaded release archive matches a pinned checksum: the versions the lists offer have one (OpenTofu `1.8.8`, `1.9.0` and `1.10.0`, Terraform `1.5.7`); any other version fails with `ENGINE_UNVERIFIABLE`. **Private Services Access Range Size (prefix)** (20): the size of the private-services range a typed workload with AlloyDB, Cloud SQL or a Vertex AI endpoint gets from the IP address pool (16 to 24). Google Cloud needs at least a /24 and the default /20 holds 16 of them; a larger range (a /16 is a common choice) needs a larger pool than the default `10.100.0.0/16`. New ranges only.
- **Buildpack & Runtime Governance (Platform BOM)**: **Default Python Runtime Version** (3.13), **Cloud Build Worker Machine Type** (`E2_HIGHCPU_8`), **Cloud Build Timeout (Seconds)** (1200) and the package version list. They apply to the next build of every workload, so one bad value breaks them all.
- **Default GitHub Branch** (`main`): the branch a new workload gets when the create request names none (repository default, deploy workflow trigger, pull request target); existing workloads keep theirs; the workload's identity federation accepts that branch (only that one), so its GitHub Actions deploys work (a workload created before this: after its next pipeline run). **FinOps Agent Model** (`gemini-4-carbon`): a short plain-text recommendation on each budget-breach approval card (one paid call per card, after the enforcement action). **Auto-Harmonize Legacy C-Extension Wheels** (on): off keeps old numpy / scipy / pandas / asyncpg pins that the package version list does not cover.
- **UI Theme & Appearance** changes the colors in your browser only. Not on this page: *keeping the Terraform server warm*, an install variable. The Terraform server scales to zero by default, so a run that starts after a quiet spell can wait a few minutes for it to start. Whoever runs the install can keep one instance running with `cloud_run_min_instances = { "mcp-terraform-server" = 1 }` in the install's variables, then `scripts/apply.sh` (a service deploy does not change it). That costs approximately $100–120 a month per install (list prices; check the Google Cloud pricing calculator).

Status and warning cards (top of **Parameters**):

- They come from the install's own checks, run each time the page loads. Most have no switch: they say what is missing and how to fix it.
- Billing: **Google Cloud Billing Linked & Healthy**; **Google Cloud Billing Not Configured** (no billing account at install, so new child projects get no billing); or **Google Cloud Billing Access Not Detected** (a StackVend service account lacks Billing Account User; the card shows the fix). **Recheck Status** checks again.
- Git provider: the provider, how it signs in and the GitHub rate limit. **Recheck VCS Health** checks again. Its switch button also saves any unsaved edits in the form.
- Install warnings (amber is a warning, grey is information). The **Terraform runner identity** card is one: *Shared* (workload Terraform runs as the platform's own account; an existing install until it is moved) shows as a warning; *Per workload* (every new install) means each workload deploys as its own deployer. The others:
  - *Deletion safety tag not set up* (`MANAGED_TAG_NOT_SET_UP`): StackVend cannot decommission any project, and sandboxes do not expire. Every Control Center page shows a banner and the New Workload form warns before you submit. Fix: grant the person who runs the install Tag Administrator (`roles/resourcemanager.tagAdmin`) on the organization, then that person runs `scripts/apply.sh apply` again. Best: grant it before installing. Without it the installer asks `Continue without deletion safety? [y/N]`; N stops before anything is applied.
  - *Projects vended before the deletion safety tag existed are untagged*: a lighter banner shows on every page until you press the card's button to tag them (the one-click backfill). A sandbox tagged this way is deleted at its expiry, so extend or promote the ones you want to keep first.
  - *Expired auto-delete sandboxes without the tag* and *Projects without a vend-time record*: information only. StackVend never tags or deletes them on its own; review each one. *Deletion safety status unavailable*, *Billing access not checked* and *Control Center cannot read the billing account*: a check could not run or lacks access. Reload Settings; if the card shows a command, a billing or platform owner runs it.
- **Platform network** (read-only): each platform service's and job's ingress and network. Only the Control Center accepts internet traffic (behind Google sign-in by default). Every other platform service is internal-only: a new install from its first apply, an older one once `host_internal_ingress = true` is applied. You then cannot call them from your machine with `curl` or `gcloud run services proxy`. The card flags a service that still accepts internet traffic.
- **Platform settings could not be loaded**: the form is hidden so you cannot overwrite good settings with defaults. Meanwhile the platform takes the safe choice (new runs refused, approvals required). Click **Retry**, or **Reset to defaults** if the stored settings are invalid.

Details → [Control Center Settings Reference](settings-reference.md) · [Status and warning cards](settings-reference.md#2-status-and-warning-cards) · [Keeping the Terraform server warm](configuration.md#keeping-the-terraform-server-warm) · [Terraform runner identity](configuration.md#terraform-runner-identity-shared-or-per-workload) · [Platform network](configuration.md#platform-network-internal-only-host-services)
<!-- /admin-only -->

## Where to get help

- A run failed or stalled: open it in **Flight Deck** and read the logs, or generate its debrief (administrators and the workload's Workload Managers). Common causes are model rate limits (the platform waits out a cooldown and resumes), exhausted quotas, invalid generated infrastructure code, and missing permissions in the platform or the workload's project.
- Questions about the platform or your workloads: ask in the **StackVend Assistant** tab.
- Limits of this preview worth knowing:
  - Install the platform in `us-central1`. Each workload runs in one region from the approved list (by default only `us-central1`); a workload across several regions is not supported.
  - The cost estimate before a build is a rough heuristic; keep budgets in place.
  - Regulated compliance profiles are not supported yet; do not use StackVend for regulated data.
  - StackVend creates no Cloud Billing budgets, so the breach policy never fires until you create one (see *Budget breach*).
  - In a Public workload every Cloud Run service is public; one service cannot be made internal-only yet.
  - Secrets from other systems (API keys, passwords of other services) are created empty; an operator adds the value in Secret Manager.
  - Running workloads are not repaired automatically (SRE auto-healing is off in this preview).
- Anything else, or a permission you do not have: ask an administrator.
- Working in the repository with an AI coding assistant: the `/stackvend-troubleshoot` and `/stackvend-diagnose-workload` skills walk through an investigation.

Details → [If a run fails or stalls](user-guide.md#if-a-run-fails-or-stalls) · [FAQ](user-guide.md#8-faq) · [Known limitations](known-limitations.md)
