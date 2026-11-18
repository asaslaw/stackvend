# Audit Trail and Roles Reference

This page lists what StackVend records about who did what, where each record is kept and for how long, and what each Control Center role may do. It describes the code in this release; where this page and the code disagree, the code wins. For the security design as a whole see the [Threat Model](threat-model.md); for the preview's gaps see [Known limitations](known-limitations.md).

**Retention in short:** StackVend sets no retention policy for its audit records. Firestore records are kept until someone deletes them, Cloud Logging entries follow the host project's default log retention, and two lists are capped (noted below). Where this page says **not set**, nothing in StackVend sets it.

---

## 1. What is recorded where

### 1.1 Databases

| Database | Name | Holds | Protection |
| :--- | :--- | :--- | :--- |
| Default Firestore database | `(default)` | Settings, workload records, users and roles, approvals, PR ledger, most audit entries | Point-in-time recovery and delete protection on. Platform services that run as `sa-castor-developer` can write it (see [Threat Model R2](threat-model.md#6-residual-risks)). |
| Guard database | `stackvend-guard` (services find it through `STACKVEND_GUARD_FIRESTORE_DATABASE`) | Deletion approvals and project provenance | Point-in-time recovery and delete protection on. Only the Control Center and vending service accounts can write it. If the environment variable is unset, these collections fall back to the default database. |

### 1.2 Firestore records

| Record | Location | Written when | What it holds | Who can see it in the product | Retention |
| :--- | :--- | :--- | :--- | :--- | :--- |
| User access changes | `user_access_audit` | An administrator grants, changes or revokes a user (`USER_ACCESS_GRANTED`, `USER_ACCESS_UPDATED`, `USER_ACCESS_REVOKED`); written in the same batch as the change, so a change without its audit entry is not stored | `action`, `email`, `operator_email`, `timestamp`, and `before` / `after` (role, active flag, assigned workloads) | Administrators: Settings, **Access Control**, **Access Changes** (the newest 50; `GET /api/users/access-audit`) | Not set. The view shows 50; all entries are kept. |
| Workload audit log | `workloads/{product_id}/audit_logs` | Access changes (`WORKLOAD_ACCESS_SET`, `WORKLOAD_ACCESS_APPLIED`), decommission (`WORKLOAD_DECOMMISSIONED`, `WORKLOAD_DECOMMISSION_FAILED`, `HITL_MANUAL_APPROVED_DECOMMISSION`), each allowed project delete (`DESTRUCTIVE_GUARD_ALLOW`), redeploy, archive and unarchive, sandbox extend / promote / expiry, run aborts (`PIPELINE_EXECUTION_ABORTED`), emergency-stop restore (`EMERGENCY_STOP_RESTORE`), managed-tag backfill | The action, the operator or calling service, a timestamp and action-specific details (for example the access record before and after) | Not shown in the Control Center; read it in the Firestore console | Not set. Workload documents are not deleted, so the log survives decommission. |
| Deletion and platform-action approvals | `destructive_approvals` (guard database) | An administrator confirms a destructive action, or approves a platform-action card (Helm uninstall, Agent Engine deploy, Discovery Engine datastore create); vending consumes it, once | `action`, target project, `approved_by`, `approved_by_role`, `approved_at`, `expires_at` (15 minutes); platform actions also the exact tool arguments (`binding`, `binding_digest`) and the card id (`request_id`); then `CONSUMED` (with `consumed_by`) / `EXECUTED` / `EXECUTION_FAILED` / `VOID` with times | Administrators see a platform-action card's approval id (read from the guard database) and its expiry | Not set. `expires_at` limits use, not storage. |
| Project provenance | `workload_provenance/{product_id}`, with earlier projects under `history` (guard database) | Vending creates a project; redeploy, extend, promote and decommission update it | Who and what created the project, and later lifecycle actors | Used by the Control Center's checks, not shown | Not set |
| PR ledger | `vcs_ledger` | StackVend creates a branch or pull request; merge, supersede or divergence updates it | Provider, repository, branch, head commit, pull request number and URL, `state`, `merged_by` | Not shown | Not set. The state is overwritten in place; earlier states are not kept. |
| Approval decisions | `approval_requests` | The pipeline, or a tool server (a platform-action card, `MCP_ACTION`), asks for a human decision; an operator decides | The request (for a platform action: the action, project and exact arguments), `decided_by`, `decided_at`, `decision_reason`, merge result or minted approval id | **Approvals** (scoped to the user's workloads) | Not set |
| Release certificates | `workloads/{product_id}/release_certificates/{trace_id}` | The release gate decides | The gate's decision | Not shown | Not set |
| Apply-gate evidence | `workloads/{product_id}/compliance_audits/{trace_id}` | Before an apply: compliance gate, content policy, destroy checks and destroy approvals | Gate, verified flag, error class, plan digest, time | Not shown | Not set |
| Settings changes | `audit_log` on `system_config/platform_settings` | An administrator saves or resets Parameters-tab settings (`UPDATE_SETTINGS`, `RESET_DEFAULTS`) | `admin_email`, `timestamp`, `changed_fields` (old and new value of each field) | Administrators: Settings, **Settings Audit History** | **Capped at the newest 15 entries**; older ones are dropped. |
| Emergency stop | `governance/platform_kill_switch` | An administrator engages or resumes the emergency stop | `activated_by`, `activated_at`, `reason`, `resumed_by`, `resumed_at`, result counts | Any signed-in user sees the current state | Only the latest stop is kept (one document, overwritten). |
| Prompt versions | `agent_prompts/{role}/versions/{n}` | An administrator changes an agent prompt | One snapshot per version, with `updated_by` | Administrators: the prompt editor (recent snapshots) | Not set. The parent document's `recent_versions` list keeps 10. |
| Tool-server operations | `gcloud_mcp_ops`, `kubernetes_ops`, `helm_releases`, `github_mcp_branches` (Helm uninstall requests are platform-action cards in `approval_requests`; the older `helm_uninstall_requests` collection is no longer written) | The gcloud, Kubernetes and GitHub tool servers change something | What was changed, on which target, and when (the gcloud and Kubernetes records also hold the state before and after) | Not shown | Not set |
| Sandbox cleanup | `ephemeral_ttl_requests`, `sandbox_cleanups` | The sandbox cleaner asks vending to delete an expired sandbox, and after each sweep | Request, outcome and result code | Not shown | Not set |

Fields on the workload record itself (for example `access_updated_by`, `archived_by`, `decommissioned_by`) keep only the latest actor; the history is in `audit_logs`.

### 1.3 Cloud Logging

| Event | Logger / source | Content |
| :--- | :--- | :--- |
| Destructive guard decisions | Logger `project-vending-destructive-guard` in `project-repo-vending-service`; message prefix `destructive-guard ` | Each allowed delete (`DESTRUCTIVE_GUARD_ALLOW`, also written to `audit_logs`) and each refusal (`DESTRUCTIVE_GUARD_REFUSED`, with the refusal code). **Refusals are recorded only in the logs.** |
| Security events | Platform services | Lines tagged `pr_identity_mismatch` (a pull request did not match the PR ledger), `branch_moved` (a branch moved after verification), `github_token_caller_refused`, `qa_job_drift`, `qa_job_not_ready`, `qa_artifact_precondition`. The services log plain text, so the tag is not a separate field in Cloud Logging: search for the message text. |
| Refused sign-ins | `product-control-center-ui` | "Unauthenticated request" and "Forbidden access attempt" lines. |

**Retention: not set.** StackVend creates no log bucket configuration and no archive sink, so the host project's default Cloud Logging retention applies. The only sink, `castor-sre-error-sink`, forwards error-level entries to the `runtime-incident-events` Pub/Sub topic for the SRE sentinel; it does not keep them.

**Cloud Audit Logs.** Google records Admin Activity audit logs for the host and child projects. StackVend does not turn on Data Access audit logs for the host project. In a child project they are turned on (`google_project_iam_audit_config`, variable `enable_data_access_audit_logs`) only when the workload's compliance profile requires it.

### 1.4 Terraform state

When a workload is decommissioned, its Terraform state is archived in the platform state bucket under `workloads/{product_id}/state_history/`. The bucket has object versioning on and no lifecycle rule: **retention not set**.

---

## 2. Retention

| Record | Retention |
| :--- | :--- |
| All Firestore audit and ledger records in section 1.2 | Not set (no Firestore TTL policy, no cleanup job) |
| Settings audit history | Newest 15 entries |
| Prompt `recent_versions` list | Newest 10 (the version snapshots themselves are not capped) |
| Emergency stop | Latest stop only |
| Cloud Logging | Not set by StackVend: the host project's default retention |
| Archived Terraform state | Not set |
| Point-in-time recovery | On for both Firestore databases; the recovery window is Google's, not set by StackVend |

If you need a longer or shorter retention, set it yourself (for example a Cloud Logging bucket retention, a log sink to Cloud Storage or BigQuery, or a Firestore TTL policy on a field you add).

**Gaps to know about:**

* Destructive-guard refusals are only in Cloud Logging, not in Firestore.
* Engaging the emergency stop writes no entry to each workload's `audit_logs` (resuming does).
* `kubernetes_ops` entries do not record the caller.
* The workload audit log (`audit_logs`) is not shown in the Control Center.
* Records in the default database can be written by platform services that share `sa-castor-developer`, so they are not tamper-proof (see [Threat Model R2](threat-model.md#6-residual-risks)).

---

## 3. Control Center roles

### 3.1 Signing in

* **Behind Identity-Aware Proxy** (the installer's default, Direct IAP), the user is the one in IAP's signed header. The Google Sign-In route is turned off in this mode.
* **In the public sandbox mode** (`allow_unauthenticated`), the user signs in with Google; the Control Center checks the ID token and issues a signed session cookie (`stackvend_session`) valid for 7 days, signed with `SESSION_SECRET`.
* There are **no API keys or personal access tokens**. Scripts use the same sign-in as a person.
* The user's role is read from Firestore on **every request**, so a change or revoke applies from the user's next request.

### 3.2 Where roles are stored

* Collection `authorized_users`, one document per lower-cased e-mail address, with `role`, `assigned_workloads`, `is_active`, `added_by` and `added_at`.
* **An account with no document has no access**: the API answers 403 and the browser shows "Access Denied". Signing in never creates a user.
* **The first administrator** comes from the installer: the Terraform variable `admin_email` (passed to the Control Center as `ADMIN_EMAIL`), and the installer also writes the deploying account as `ADMIN`. A Firestore document for that address takes precedence over `ADMIN_EMAIL`. That address cannot be revoked with **Revoke Access**.
* Administrators manage users in Settings, **Access Control** (`POST /api/users`, `PUT /api/users/{email}/workloads`, `DELETE /api/users/{email}`). Every change is audited in `user_access_audit` (section 1.2).
* `APPROVER` is a legacy value: it is read as `WORKLOAD_MANAGER` everywhere in the Control Center, and is no longer offered.

### 3.3 How checks are enforced

* Every route declares one access policy (`require(...)` in `apps/control-center/authz.py`). A route without a policy is refused, and the app does not start if any route lacks one (`assert_all_routes_have_policy`).
* Workload routes check that the workload is in the user's `assigned_workloads` (administrators pass for every workload). Objects that belong to a workload (feature requests, runs, approvals) must belong to exactly that workload.
* Hiding a section in the page is display only; the server checks every action.
* A request that changes something (any method other than GET, HEAD or OPTIONS) is refused with 403 `CSRF_CROSS_SITE_REFUSED` when a browser sent it from another site: its `Sec-Fetch-Site` header is present and not `same-origin`, or (for a browser that sends no `Sec-Fetch-Site`) its `Origin` header is present and is not the Control Center's own address. When `Sec-Fetch-Site` is `same-origin` the request is allowed without the address comparison, so the CLI proxy path (`gcloud run services proxy`, where the browser is on `localhost` but the Control Center sees its own `run.app` name) keeps working. This runs before sign-in is checked, on every route. The Control Center's own page and clients that send neither header (scripts, Pub/Sub push) are not affected.

### 3.4 What each role can do

| Capability | `ADMIN` | `WORKLOAD_MANAGER` (assigned workloads) | `VIEWER` (assigned workloads) |
| :--- | :---: | :---: | :---: |
| View workloads, runs, logs, plans, diagrams | All | Yes | Yes |
| View a workload's Terraform state outputs | All | Yes | No |
| Create a workload in the Control Center | Yes | No | No |
| Submit a specification through Google Drive | Yes | Yes (see note) | No |
| Feature requests, re-run, deploy infrastructure, unlock a deployment lock | Yes | Yes | No |
| Abort a run | Yes | Yes | No |
| Decide approvals (plan, release merge, budget breach) | Yes | Yes, with the exceptions below | No |
| Upgrade IaC | Yes | Yes | No |
| Sync a workload's spend | Yes | Yes | No |
| Change who may use a workload (access record) | Yes | No | No |
| Budget and workload policies | Yes | No | No |
| Decommission, redeploy, archive, deploy to folder | Yes | No | No |
| Sandbox extend, promote, confirm | Yes | No | No |
| Settings (including maintenance mode), modules, bundles, skills, prompts | Yes | No | No |
| Users and roles, access audit | Yes | No | No |
| Emergency stop | Yes | See the state only | See the state only |
| Platform-wide pipeline views | Yes | No | No |
| Guide and Assistant | Yes | Yes | Yes |

**Exceptions inside approval decisions:**

* A compliance-profile downgrade is decided by an administrator only.
* A platform-action card (Helm uninstall, Agent Engine deploy, Discovery Engine datastore create) is decided by an administrator in a signed-in session only. The decision must match the card as it was displayed, else `APPROVAL_CARD_CHANGED` (reload and decide again). Approving re-reads the workload's project from its record (it must be the workload's own project, not a host project, and not claimed by another workload) and mints a single-use approval for exactly the card's action, project and arguments, valid for 15 minutes; administrators see its id on the card, and the caller passes it to the tool. Nothing runs the tool automatically.
* A budget-breach decision that decommissions the workload needs an administrator (it mints a deletion approval).
* A Workload Manager **can** decide a budget-breach card that restores the buffer or raises the budget, although setting a budget directly is administrator-only.
* A Workload Manager **can** decide the plan approval that follows an access widening.
* An approval that belongs to no workload is decided by an administrator only.

**Note on Drive intake:** Drive intake checks that the document's owner is an active `ADMIN` or `WORKLOAD_MANAGER`; it does not check assigned workloads, so a Workload Manager can start a new workload through Drive although creating one in the Control Center is administrator-only.

**Outside the Control Center:** vending grants every active `ADMIN` the `roles/viewer` role on each child project it creates, so administrators can see the projects StackVend creates.

### 3.5 Service callers

The Control Center accepts no service-account callers. Its scheduled work (nightly spend sync, sandbox sweep, billing alerts) runs as Cloud Run jobs with their own service accounts (`finops-spend-sync-job`, `sandbox-workload-sweeper-job`, `billing-alert-drain-job`); the jobs write Firestore and the Control Center reads it. Every Google ID token presented to the Control Center is refused, and no service account can obtain a browser session. `POST /api/finops/sync-spend` and `POST /api/workloads/sweep-expired-sandboxes` remain as manual triggers for an administrator; `POST /api/alerts/billing` stays registered but refuses every caller.

Tool servers never call the Control Center. The Kubernetes and agent-builder tool servers consume an approved platform action through project vending (`POST /approvals/{id}/consume`), which accepts only their service account (`sa-castor-developer`, `MCP_APPROVAL_CONSUMERS`) and checks the record in one transaction: approved by a human administrator, the same action, workload, project and arguments, inside its 15 minutes, not used before.

### 3.6 Separation of duties

StackVend has **no separation-of-duties rule** in this release:

* The administrator who confirms a destructive action, or approves a platform-action card, is also the one who mints its approval; vending checks that the approval came from a human administrator session, for exactly that action and target (and, for a platform action, those arguments), within 15 minutes and only once.
* An approval decision records `decided_by` but does not compare it with whoever caused the request.
* Concurrent decisions on the same approval are refused (one decision wins).

If you need two-person control, enforce it outside StackVend (for example through review rules on the workload repositories) and limit the number of administrators.
