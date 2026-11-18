# Threat Model (Public Preview)

> **Status: public preview.** This page describes the security design of the code in this release: what StackVend protects, where the trust boundaries are, which controls exist, and which risks remain. It is not a certification or an external review. Where this page and the code disagree, the code wins: please open an issue (or, for a vulnerability, follow [`SECURITY.md`](../SECURITY.md)).

StackVend is public preview software. Read [Known limitations](known-limitations.md) before you install it, and install it only in a dedicated, disposable Google Cloud environment.

Related pages: [Audit trail and roles](audit-and-roles.md) (what is recorded and who may do what), [System Architecture](architecture.md#5-security-and-isolation-model) (isolation model), [Fail-Loudly Policy](fail-loudly-policy.md) (how a failed check stops a run).

---

## 1. What StackVend protects

| Asset | Where it lives | Why it matters |
| :--- | :--- | :--- |
| The host (platform) project | The Google Cloud project StackVend is installed in | Runs every platform service; a compromise reaches every workload. |
| Platform secrets | Secret Manager in the host project, for example `castor-github-app-private-key`, `castor-gemini-api-key`, `castor-cc-session-secret` | The GitHub App key can push to every workload repository; the session secret signs Control Center sign-in cookies in the public sandbox mode. |
| Terraform state | The platform state bucket: platform state under `platform/`, each workload's state under `workloads/` | State can hold resource attributes, including generated secrets. |
| Platform records | Firestore: the default database (settings, workload records, users and roles, approvals, PR ledger) and the separate guard database `stackvend-guard` (deletion approvals and project provenance) | Decide who may sign in, what is deployed where, and what may be deleted. |
| Child (workload) projects | One Google Cloud project per workload, under the managed folder | Hold each workload's resources and data. |
| Workload repositories | GitHub, or the serverless Git service in the host project | The Terraform in `infra/workload/` is what StackVend applies. |
| Billing | The billing account linked to child projects | Generated infrastructure costs money. |

---

## 2. Actors

| Actor | Trust | Notes |
| :--- | :--- | :--- |
| Control Center **Administrator** (`ADMIN`) | Trusted | Everything, including settings, users, decommission and the emergency stop. See [roles](audit-and-roles.md#3-control-center-roles). |
| **Workload Manager** (`WORKLOAD_MANAGER`) | Trusted for assigned workloads | Feature requests, re-runs and approval decisions for the workloads assigned to them; may submit Google Drive specifications. |
| **Viewer** (`VIEWER`) | Read-only | Sees assigned workloads only. |
| Specification authors | Trusted input source, **not screened** | A specification is passed to the models as written (no prompt-injection screen). |
| The AI models (Gemini, through AI Studio or Vertex AI) | **Untrusted output** | Everything a model writes is treated as untrusted input to deterministic checks (section 4). |
| People with write access to a workload repository | **Must be trusted like platform administrators** | On a Shared install, Terraform they push is applied with the platform runner's credentials (section 6, R1). On a Per-workload install after step B, it runs as the workload's own deployer, which owns the workload's project. |
| Users of a deployed workload | Untrusted | Reach the workload through its access mode (Private: Google sign-in (IAP), Private: IAM callers only, or Public). |
| Platform service accounts | Trusted, broad | Several platform services share one runtime identity in this release (section 6). |

---

## 3. Trust boundaries

| # | Boundary | What crosses it | Control at the boundary |
| :--- | :--- | :--- | :--- |
| B1 | Operator → Control Center | Browser and API requests | Identity-Aware Proxy (the installer's default, Direct IAP) or, in the public sandbox mode, Google sign-in with a signed session cookie. Every request's role is read from Firestore `authorized_users`; an account without a record gets no access. Every route declares a policy, and the app refuses to start when one does not (`assert_all_routes_have_policy`, `enforce_declared_policy`). |
| B2 | Control Center and scheduled jobs → other platform services | Service-to-service calls | Network first: every platform service except the Control Center accepts internal traffic only once `host_internal_ingress` is on (new installs: from the installer's first apply), so a request from the internet, Cloud Shell or a laptop is refused even with a valid token; the platform's own services and jobs reach them through the platform network `stackvend-host` (`host_network.tf`), which the QA sandbox job never joins. Then Cloud Run IAM: each call carries a Google ID token, and only granted identities hold the invoker role. The only `allUsers` invoker binding is on the Control Center, and only in the public sandbox ingress mode (`allow_unauthenticated`). The Control Center accepts no service tokens at all: nothing calls it machine-to-machine (the scheduled jobs and the billing drain run as Cloud Run jobs), so it refuses every service bearer and admits people only. |
| B3 | Platform → AI models | Specifications, plans, code, test output | Model output is untrusted (section 4). Specifications are sent unscreened (residual risk R4). |
| B4 | Generated content → workload repository | Commits and pull requests | Pre-commit checks (section 5.2): nothing is committed while a blocking check fails. |
| B5 | Workload repository → Terraform apply | The Terraform in `infra/workload/`, whoever wrote it | Plan checks before every apply (section 5.4). |
| B6 | Platform → child projects | Project creation, IAM, deployments, deletion | One project per workload; project deletion only through the destructive guard (section 5.5); keyless CI/CD restricted to the workload's own repository. |
| B7 | Workload code → QA sandbox | The generated tests and the code under test | A separate Cloud Run job (`qa-sandbox-test-runner`) whose service account has no roles and can write only its own result files. It has normal internet access (residual risk R5). |
| B8 | Workload repository writers → platform runner | Terraform run with the runner's credentials | **Not a boundary on a Shared install** (an existing install until it is moved). On a Per-workload install after step B (every new install, from its first apply), workload Terraform runs as the workload's own deployer in its own project. See residual risk R1. |

---

## 4. AI output is treated as untrusted input

* **Deterministic checks decide.** The pre-commit validators read the generated files and return findings; none of them writes files or calls a model. Decisions come from real parsers (python-hcl2, CPython's `ast`, pyflakes, OpenTofu's own `validate`) and exact tables, not from text matching.
* **A failed check is repaired by the model and checked again, or the run stops.** Repairable findings go back to the developer agent with the finding; if the repair does not clear a blocking finding, the run stops before anything is committed, with a typed error (see [Fail-Loudly Policy](fail-loudly-policy.md)).
* **Platform-owned files are protected.** Platform (golden) modules vendored into a workload must not be changed by the AI (`PLATFORM.VENDORED_FILE_MUTATED`); the AI may not write infrastructure outside `infra/workload/` (`PATH.IAC_OUTSIDE_WORKLOAD_ROOT`) or files a person owns (`PATH.USER_OWNED_NAME_WRITTEN_BY_LLM`).
* **Test output fed back to a model is marked as data.** When QA fails, each repair round sees QA's findings and a size-limited part of the test output, inside a delimited block marked as untrusted data (`untrusted_block`). This is prompt hygiene, not a prompt-injection screen.
* **Specifications and uploaded documents are not screened.** See residual risk R4.

---

## 5. Controls, in pipeline order

### 5.1 Who may start or steer a run

| Control | What it does |
| :--- | :--- |
| Roles and workload scope | `ADMIN`, `WORKLOAD_MANAGER`, `VIEWER`, stored in `authorized_users` with each user's `assigned_workloads`; see [roles](audit-and-roles.md#3-control-center-roles). |
| Google Drive intake | A Drive document is built only when its owner is an active Control Center user with role `ADMIN` or `WORKLOAD_MANAGER` (legacy `APPROVER` counts as `WORKLOAD_MANAGER`); otherwise it is refused (`SPEC_SUBMITTER_UNAUTHORIZED`). The title names the workload: an existing workload needs the `ADMIN` role or an assignment to it (`SPEC_WORKLOAD_NOT_ASSIGNED`; a Workload Manager who starts a new workload from Drive is assigned to it, audited as `USER_ACCESS_AUTO_ASSIGNED`), the platform itself is never a target (`SPEC_TARGET_PLATFORM_WORKLOAD`; the gateway and project vending refuse it too), and an id that is not a valid workload id is refused (`SPEC_PRODUCT_ID_INVALID`). |
| Maintenance mode | Setting `governance.maintenance_mode`: no new run starts (`MAINTENANCE_MODE`); runs in flight continue. |
| Emergency stop | An administrator action that freezes every workload and cancels running workflow executions; recorded in `governance/platform_kill_switch`. |
| Code freeze | New workloads start frozen by default (`freeze_new_workloads`), so automatic runs wait for an operator. |
| Plan approval | `plan_approval_policy` (`ALWAYS`, `ON_COMPLIANCE_CONFLICT`, `AUTONOMOUS_UNLESS_FAILED`) decides when the architect's plan waits for a human decision; `strict_compliance_gates` makes compliance advisories wait for a human. |

### 5.2 Before commit (AI-written code and infrastructure)

The full list of step-1 validators, with codes and modes, is in the docstring of `apps/orchestrator-gateway/developer_agent/validators/step1.py`. The security-relevant blocking ones:

| Check | Codes | Stops |
| :--- | :--- | :--- |
| Forbidden resources and roles | `POLICY.FORBIDDEN_RESOURCE_TYPE`, `POLICY.PRIVILEGED_ROLE`, `POLICY.PUBLIC_MEMBER`, `POLICY.PLATFORM_OWNED_TYPE`, `POLICY.PLATFORM_OWNED_BINDING`, `POLICY.PROJECT_WIDE_GRANT` (typed IaC intent: `IAC.PROJECT_WIDE_GRANT`) | Privileged IAM roles, public members, resources the platform owns, and Secret Manager or IAM-admin roles granted on the whole project (grant them on the one secret instead). |
| Content policy | `POLICY.PROVISIONER_FORBIDDEN`, `POLICY.CONNECTION_FORBIDDEN`, `POLICY.EXTERNAL_DATA_FORBIDDEN`, `POLICY.REMOTE_STATE_FORBIDDEN`, `POLICY.MODULE_SOURCE_NOT_LOCAL`, `POLICY.PROVIDER_SOURCE_MISMATCH` | Local code execution, outside modules and providers, reading other state. |
| Providers | `POLICY.PROVIDER_NOT_AVAILABLE` | Providers outside the platform's set. |
| Organization policy | `POLICY.ORG_CONSTRAINT` | Resources the organization's policies forbid. |
| Network ranges | `POLICY.CIDR_LITERAL`, `POLICY.CIDR_FACT_MISMATCH`, `POLICY.CIDR_NOT_ALLOCATED` | Address ranges not allocated by IPAM. |
| Secrets in IAM | `IAC.IAM_LITERAL_SECRET_ID` | Literal secret ids in IAM bindings. |
| Sign-in and access | `POLICY.IDP_CONFIG_IN_IAC`, `POLICY.IDP_SECRET_READER_FORBIDDEN`, `POLICY.PUBLIC_PRINCIPAL_IN_MODULE_CALL` | AI-written sign-in configuration, roles that can read a shared sign-in secret, and `allUsers` / `allAuthenticatedUsers` passed to a module in a private workload. |
| Variables and `.tofu` files | `POLICY.TFVARS_NOT_ALLOWED`, `POLICY.TOFU_FILE_NOT_ALLOWED` | AI-written variables files that OpenTofu loads by itself (they could override platform-owned values), and AI-written `.tofu` files (they replace `.tf` files of the same name). |
| Paths | `PATH.UNSAFE_KEY`, `PATH.IAC_OUTSIDE_WORKLOAD_ROOT`, `PATH.USER_OWNED_NAME_WRITTEN_BY_LLM` | Unsafe file paths and writes outside the workload's own area. |
| Vendored modules | `PLATFORM.VENDORED_FILE_MUTATED` | Changes to platform modules copied into the workload. |
| OpenTofu validate | `TF.*` | Configuration OpenTofu itself rejects. |

After the validators, the synthesis verifier (`SynthesisVerifierAgent.verify_and_cure`) is a hard gate before commit, and the QA gatekeeper runs the workload's tests and scans in the QA sandbox before a release pull request is opened.

**Registered modules.** A module an administrator registers in **Settings > Modules & Bundles** is refused when its own files grant public access (`REGISTERED_MODULE_PUBLIC_EXPOSURE`); the check reads literal settings only (see [Known limitations](known-limitations.md#other-security-gaps-in-this-preview)).

### 5.3 Release (pull request to `main`)

* **PR ledger.** Every branch and pull request StackVend creates is recorded in Firestore `vcs_ledger` from the provider's response. A merge is allowed only for a ledger entry, and only while the live pull request still matches it (same repository, no fork, the recorded head commit). A mismatch is logged as a security event (`pr_identity_mismatch`) and nothing is merged.
* **Branch pinning.** If a branch moves after the gatekeeper verified its commit, the run stops (security event `branch_moved`).
* **Human approval.** When the release gate does not merge a change by itself, the change stays open and waits for a human decision in the Control Center (`approval_requests`); approving merges it only through its ledger entry.

### 5.4 Before every apply (any Terraform, AI-written or human-written)

The Terraform server plans to a file, checks that saved plan, and applies exactly that plan. Each check fails closed and nothing is applied:

| Check | Error class | What it refuses |
| :--- | :--- | :--- |
| Content policy (`plan_content_policy_violations`) | `APPLY_CONTENT_POLICY` | Provisioners, modules from outside the workspace or with a registry version, providers outside the platform's set (`APPLY_ALLOWED_PROVIDERS`), and `terraform_remote_state` that reads any state other than the workload's own. |
| Deletion-protected resources | `DESTROY_BLOCKED` | A plan that deletes or replaces a resource with deletion protection on. No approval overrides it. |
| Data-holding resources | `DESTROY_REQUIRES_APPROVAL` | With `require_hitl_for_destructive_tf` on (the default, and assumed on when it cannot be read), an Agent deploy whose plan deletes or replaces a data-holding resource type (`DATA_HOLDING_RESOURCE_TYPES`) stops for an operator decision. An Express deploy applies a removal only when the operator approved exactly that address. While an Express workload's last deploy stands refused this way, every Fast-Path (`DEPLOY_ONLY`) run of it is refused too, whether started by **Deploy Infrastructure** or by a relaunch (explicit or chosen by Auto): the Control Center answers 409 `DESTROY_REQUIRES_APPROVAL` and the gateway's DEPLOY_ONLY gate refuses it (`POLICY_REJECTED`, reason `DESTROY_REQUIRES_APPROVAL`). |
| Compliance gate | `COMPLIANCE_VIOLATION`, `UNKNOWN_PROFILE`, `COMPLIANCE_UNAVAILABLE` | The plan is evaluated against the workload's explicitly chosen compliance profile; anything other than a pass, including an unreachable compliance server, stops the apply. |

Plan checks run on the finished plan. Terraform data sources are read while the plan is made, with the runner's credentials (residual risk R1); on a Per-workload install, with the workload's deployer. A Per-workload install also checks the Terraform before `init` (provider and backend settings, module sources, remote state) and refuses a plan that would manage the deployer account or grant owner, editor or token-creator roles in the workload's project; see [Configuration](configuration.md#terraform-runner-identity-shared-or-per-workload).

### 5.5 Project vending and deletion

* **One project per workload,** under the managed folder, linked to billing by vending.
* **Keyless CI/CD.** Each child project gets a Workload Identity pool (`castor-gh-pool`) and a deployer service account (`sa-gh-deployer`) that only the workload's own repository, on its `main` branch, can impersonate; once the repository's numeric id is recorded, a re-created repository with the same name cannot.
* **Project deletion is guarded.** Vending is the only service that deletes a project, and every delete passes `assert_deletable` first. It refuses (`DeletionRefused`) the host project (`HOST_PROJECT`), a project without StackVend's direct tag and labels (`NOT_STACKVEND_OWNED`), a project outside the managed folder (`NOT_IN_MANAGED_FOLDER`), a project with any lien (`LIEN_PRESENT`), and any delete whose audit record cannot be written first (`AUDIT_UNAVAILABLE`). A human-initiated delete also needs an approval minted for exactly that action and target by an administrator's session, valid for 15 minutes and usable once (`destructive_approvals`, in the guard database, which only the Control Center and vending can write).
* **Tool-server actions need a bound, single-use approval.** `helm_uninstall`, Agent Engine deploy and Discovery Engine datastore create act only with an approval an administrator minted in the Control Center from the tool server's platform-action card, for exactly that action, workload, project and arguments (for a deploy, a digest of the exact scaffold and requirements), valid for 15 minutes. The tool server consumes it through vending (`POST /approvals/{id}/consume`, one transaction in the guard database; caller allow-list `MCP_APPROVAL_CONSUMERS`), never through the Control Center; when vending cannot be reached the action is refused (`APPROVAL_CONSUME_UNAVAILABLE`). Vending never consumes deletion or sandbox approvals on this route.
* **No external VM IPs.** The installer sets the organization policy `compute.vmExternalIpAccess` on the managed folder when the installing person may.

### 5.6 Deployed workloads

* New workloads default to **Private: Google sign-in (IAP)**. A change to or from Public needs a full rebuild, and a widening needs that build's plan approval first (see [Known limitations](known-limitations.md#other-security-gaps-in-this-preview)).
* Generated workloads are built with Buildpacks; the preflight stage rejects Dockerfiles.

---

## 6. Residual risks

Each risk below is accepted for the preview and is listed in [Known limitations](known-limitations.md).

| # | Risk | Impact | Status |
| :--- | :--- | :--- | :--- |
| R1 | **The Terraform runner can read platform secrets and read or change every workload's state.** On a Shared install (an existing install until an operator moves it), `tf-applier` and `mcp-terraform-server` run as one platform service account (`sa-castor-developer`), and Terraform runs with its credentials. | Anyone who can push Terraform to any workload repository can read platform secrets (for example the GitHub App key), read or change other workloads' state, and change platform settings and workload records in the default Firestore database. | **Mitigated on new installs:** the install setting **Terraform runner identity** = **Per workload**, after step B, runs each workload's Terraform as a deployer limited to the workload's own project and state. `scripts/bootstrap.sh` sets it, with step B, for every new install; an existing install moves with the Settings switch, the backfill and step B ([Configuration](configuration.md#terraform-runner-identity-shared-or-per-workload); it is new and has [its own limitations](known-limitations.md#per-workload-terraform-runner-identity-is-new)). On a Shared install, give workload repository write access only to people you trust as platform administrators. [Trust model](known-limitations.md#trust-model-who-may-change-a-workloads-terraform) |
| R2 | **Most platform services share one identity.** Apart from the Control Center (`sa-stackvend-control-center`), vending (`sa-project-provisioner`), the sandbox cleaner and, after step B (every new install), the two Terraform runners, platform services and jobs run as `sa-castor-developer`, which can write the default Firestore database. | Records in the default database (PR ledger, approvals, audit entries) are not tamper-proof against a compromised platform service. The guard database and the provider-side live checks of the PR ledger are the stronger boundaries. | Open (see open question 3). The per-workload runner identity does not change it. |
| R3 | **Human-pushed Terraform is checked only at apply.** | The plan checks in 5.4 apply, but not the pre-commit checks; a person's own variables files and `.tofu` files are applied as committed. | [Variables files and `.tofu` files](known-limitations.md#other-security-gaps-in-this-preview) |
| R4 | **No prompt-injection screening.** Specifications, uploaded documents and Assistant questions reach the models unscreened. | A crafted specification can steer generation. The deterministic checks still apply to what is generated. | Screening is on the [roadmap](README.md#roadmap). [Other security gaps](known-limitations.md#other-security-gaps-in-this-preview) |
| R5 | **The QA sandbox has normal internet access.** | Generated tests can reach the internet; the job's identity has no roles. | [Other security gaps](known-limitations.md#other-security-gaps-in-this-preview) |
| R6 | **Registered-module and access checks read literal settings only.** | Public access built from computed expressions is not detected before apply. | [Other security gaps](known-limitations.md#other-security-gaps-in-this-preview) |
| R7 | **Authorization inside a Public app is not verified.** | AI-written sign-in or permission code may not work. | [Public apps](known-limitations.md#generated-public-apps-have-no-shared-google-sign-in-yet) |
| R8 | **Regulated compliance profiles are advisory before apply.** | Only the apply-time gate blocks. | [Regulated profiles](known-limitations.md#regulated-compliance-profiles-are-not-available-yet) |
| R9 | **Some repair steps rewrite valid code, and package pins can change after QA.** | The deployed image can differ from what QA tested. | [Repair steps](known-limitations.md#some-automatic-repair-steps-can-change-code-that-was-already-valid) |
| R10 | **No separation of duties.** One administrator can both approve and carry out a project deletion; a Workload Manager can decide approvals (including access-widening plan approvals and budget increases) for assigned workloads. | A single trusted account is enough for a destructive or widening change. | Documented in [Audit trail and roles](audit-and-roles.md#36-separation-of-duties). |
| R11 | **Audit records have no retention policy and some events are only in logs.** | See [Audit trail and roles](audit-and-roles.md#2-retention). | Documented. |
| R12 | **One region per workload.** Each workload runs in one region from Settings **Approved Deployable Regions** (by default only the install's region). The platform itself stays in its install region. | A workload cannot span several regions, and the platform's own data stays in its install region. | Documented. [One region per workload](known-limitations.md#one-region-per-workload-from-the-approved-list) |
| R13 | **Public sandbox ingress mode.** With `allow_unauthenticated`, the Control Center is reachable by anyone and relies on in-app Google sign-in and a signed cookie. | A larger attack surface than IAP. | Use it only for short-lived evaluation; the installer default is Direct IAP. |
| R14 | **Data sent to the AI provider.** Specifications, documents and generated code are sent to the configured Gemini backend (AI Studio API key or Vertex AI). | Content leaves the platform project for the model provider. | Choose the backend that fits your data-handling rules ([Configuration](configuration.md#2-ai-model-settings)). |

---

## 7. Out of scope for this model

Vulnerabilities in Google Cloud, GitHub, OpenTofu/Terraform and other third-party software; an already-compromised administrator account; and configurations outside the documented options (for example extra IAM roles granted by hand). See the scope notes in [`SECURITY.md`](../SECURITY.md).

---

## Open questions

These design decisions are still open. When one is decided, this page and [Known limitations](known-limitations.md) will be updated.

1. **Separation of duties (R10).** Whether to add a rule, for example that the person who requests a destructive or access-widening change cannot approve it, or that Workload Managers cannot decide access-widening approvals and budget increases.
2. **Audit retention (R11).** Whether a later platform release sets retention (a Firestore TTL policy, a Cloud Logging bucket retention, or a log sink to long-term storage), or leaves it to each installation.
3. **Shared service identity (R2).** The per-workload runner identity changes only the Terraform runners. Whether to give each other platform service its own identity is still open.
4. **External review.** No external security review has been scheduled yet.
