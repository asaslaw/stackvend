# StackVend Quickstart Guide

This guide takes you from an empty Google Cloud project to a running StackVend Control Center and a first workload.

> **Public preview.** StackVend is not production-ready and security hardening is in progress. Install it in a dedicated, disposable Google Cloud project (ideally under a test organization/folder with a billing account you can cap), choose the authenticated ingress mode, and review all generated infrastructure before it is applied. Deploying creates cloud resources that cost money.

---

## 1. Prerequisites

The whole install, in order (about 1.5 hours, about 20 minutes of it hands-on):

1. Install the tools: `gcloud`, OpenTofu 1.10 or later, `python3`, `curl` ("Tools" below).
2. Sign in to `gcloud` with an **organization account** ("Sign in" below).
3. **Start here:** run `bash scripts/pre-bootstrap.sh` ("Prepare the host project and folder" below). It checks your permissions, creates the host project, links it to billing and creates the managed-workloads folder if you ask it to, offers to install OpenTofu when it is missing, and then runs the installer for you.
4. The installer, `scripts/bootstrap.sh` (section 2), asks its questions with the values from step 3 filled in. With Direct IAP, the default, no OAuth client is needed. Run `scripts/bootstrap.sh` on its own only to re-run the installer later.
5. Open the Control Center (section 3). If you are not a Billing Account Administrator, have one run the "Post-install: billing access" commands.

### Minimum permissions for the installer

"You" is the account that runs `scripts/bootstrap.sh` (and later `scripts/apply.sh`). Organization Administrator alone is not enough for rows 2 and 5.

| # | Permission (for you) | Where | Needed for |
| :-- | :-- | :-- | :-- |
| 1 | An **organization account** (Google Workspace / Cloud Identity), not a personal Gmail account | | Required for Direct IAP, the default ingress: the installer account becomes the first Control Center `ADMIN` and the only person IAP admits, and IAP admits only organization accounts. |
| 2 | *Project Creator* (`roles/resourcemanager.projectCreator`) | Organization or folder | Only to create the host project yourself. Organization Administrator does **not** include it. |
| 3 | *Owner* | Host project | Required. You get it by creating the project. |
| 4 | *Billing Account User* (`roles/billing.user`) | Billing account | To link the host project to billing. *Billing Account Administrator* (`roles/billing.admin`) instead also lets Terraform make StackVend's three billing grants during the install; otherwise they are the post-install step in "Post-install: billing access" (the install never fails on them). |
| 5 | *Folder Creator* (`roles/resourcemanager.folderCreator`) | Organization or parent folder | Only to create the managed-workloads folder yourself. Organization Administrator does **not** include it. |
| 6 | *Folder IAM Admin* (`roles/resourcemanager.folderIamAdmin`) or *Folder Admin* | Managed-workloads folder | Required: the apply grants StackVend's service accounts their roles on that folder (`google_folder_iam_member`). `scripts/bootstrap.sh` (right after the folder prompt) and `scripts/apply.sh apply` (before the plan) check it read-only and stop with `BOOTSTRAP_FOLDER_IAM_MISSING` / `APPLY_FOLDER_IAM_MISSING` and the grant command before changing anything. Organization Administrator covers it (it includes `resourcemanager.folders.setIamPolicy`, inherited from the organization). |
| 7 | *Tag Administrator* (`roles/resourcemanager.tagAdmin`) | Organization | For the deletion-safety tag. Without it the installer asks `Continue without deletion safety? [y/N]` right after the folder question, before it changes anything; if you continue, every project delete is refused (`GUARD_UNCONFIGURED`). |
| 8 | *Organization Policy Administrator* (`roles/orgpolicy.policyAdmin`) | Organization (it cannot be granted lower) | Optional. Lets the install set "no external VM IPs" (`compute.vmExternalIpAccess` = deny all) once on the managed-workloads folder, so every project in it inherits it. Without it the install completes, but VMs in vended projects can get external IPs, and every vend records `VENDING.ORG_POLICY_NOT_ENFORCED` with the fix. Organization Administrator does **not** include it. |

Read-only self-check (lists the permissions you have among those behind rows 2, 5, 6, 7 and 8):

```bash
curl -s -X POST -H "Authorization: Bearer $(gcloud auth print-access-token)" -H "Content-Type: application/json" \
  -d '{"permissions":["resourcemanager.projects.create","resourcemanager.folders.create","resourcemanager.folders.setIamPolicy","resourcemanager.tagKeys.create","orgpolicy.policies.create"]}' \
  https://cloudresourcemanager.googleapis.com/v3/organizations/<ORG_NUM>:testIamPermissions
```

### Sign in

Sign in with the **organization account** you will use the Control Center with (row 1 of the table above). The install scripts use only this `gcloud` sign-in (they hand OpenTofu a token from it); `gcloud auth application-default login` is not needed to install.

```bash
gcloud auth login you@your-org.example
```

If your usual `gcloud` account is a different one (for example a personal Gmail account), keep it and use a separate `gcloud` configuration for StackVend instead. Every command in this guide then runs with the same `CLOUDSDK_ACTIVE_CONFIG_NAME=stackvend` prefix:

```bash
gcloud config configurations create stackvend --no-activate
CLOUDSDK_ACTIVE_CONFIG_NAME=stackvend gcloud auth login you@your-org.example --no-launch-browser
```

`--no-launch-browser` prints a link instead of opening your default browser: open it in a private window, sign in with the organization account, and paste the code it shows back into the terminal. Without it, a browser that is already signed in to another Google account can answer for that account, and `gcloud` stops with "the received credentials were for account ...".

A brand-new account must accept the Google Cloud Terms of Service once before any API can be enabled: open https://console.cloud.google.com in a browser signed in as that account and accept the terms (Google may also ask a new account to verify a phone number once). Otherwise bootstrap stops at its first API enable with `BOOTSTRAP_CLOUD_TERMS_NOT_ACCEPTED`, before it writes anything.

### Prepare the host project and folder

**Recommended: let `scripts/pre-bootstrap.sh` do this section for you** (the steps by hand follow below). At the end it asks `Run scripts/bootstrap.sh now with these values? [Y/n]` and starts the installer with your answers filled in. It first checks, read-only, every right in the table above for the signed-in account (all of them in one run, even when you cannot see the project or folder yet, or have no billing role; a project that is already linked to billing needs none) and prints what you have, what each right is needed for, what happens without it (BLOCKING, DEGRADED or OPTIONAL) and the exact grant commands; it stops before any change only when a BLOCKING right is missing for the path you chose (`PREBOOT_MISSING_RIGHTS`) or could not be checked (`PREBOOT_RIGHTS_UNKNOWN`). Then it uses an existing project and folder or creates new ones, links billing, and prints what to answer at the installer's prompts:

```bash
bash scripts/pre-bootstrap.sh --new-project <your-project-id>              # or --existing-project <id>; --existing-folder <FOLDER_ID>
bash scripts/pre-bootstrap.sh --existing-project <your-project-id> --check-only   # only the rights check
```

In a terminal it asks you to choose `1` (use an existing project) or `2` (create a new one) when you give neither flag, and the same for the folder. A new folder is named `<your-project-id>-workloads` unless you pass `--folder-name` (folder names are at most 30 characters, so that default needs a project id of at most 19). `--dry-run` prints every command it would run, and `--grant-to user:<email>` grants Owner and Folder IAM Admin to the person who will run the installer. When Tag Administrator (row 7) or Organization Policy Administrator (row 8) is missing for the person who will run the installer (you, or the `--grant-to` person, whose organization IAM binding it reads instead; a binding they hold through a group is not seen), and your account can read and set IAM on the organization (it tests `resourcemanager.organizations.getIamPolicy` and `resourcemanager.organizations.setIamPolicy` read-only), a real run in a terminal offers each grant after the project and folder steps, for example `Grant Organization Policy Administrator (roles/orgpolicy.policyAdmin) on organizations/<ORG_NUM> to user:<you> now? This is organization-wide: it lets <you> change every organization policy in organizations/<ORG_NUM>. Type yes to grant, or press Enter to skip`. Both roles are granted on the organization: Organization Policy Administrator cannot be granted lower (row 8 above). Only the full word `yes` grants it, so a key typed ahead cannot: one `gcloud organizations add-iam-policy-binding ... --condition=None`, which adds the binding and changes no other. It then runs the same read-only check again for up to 2 minutes while the change propagates, and prints `[DONE]` only once the check passes. If the check still does not pass, it warns `PREBOOT_ORG_GRANT_NOT_VISIBLE` (the installer checks again). A failed grant warns `PREBOOT_ORG_GRANT_FAILED` with gcloud's message and the grant command. Either way the run continues, because both rows are not blocking. Nothing is offered, and only the grant command is printed as before, on Enter or any other answer, with `--yes`, `--check-only`, `CLOUDSDK_CORE_DISABLE_PROMPTS=1` or without a terminal, for a personal account (row 1), when `gcloud` impersonates a service account, or when the project or folder is not confirmed to be in that organization (`PREBOOT_ORG_OFFER_SKIPPED`); `--dry-run` prints the command it would run. It is safe to re-run: each step checks first and only creates what is missing (on an organization it already prepared it says `[OK] Nothing to change.` and asks nothing, except the organization-role offers above when rows 7 or 8 are still missing), and it never deletes anything or changes an existing billing link. At the end it prints the installer command with the project, organization, billing account and folder it knows as `STACKVEND_*` values, which the installer's prompts then offer as their defaults; after a real run in a terminal it asks "Run scripts/bootstrap.sh now with these values? [Y/n]" (never with `--yes`, `--dry-run`, `--check-only` or `--grant-to` someone else). The manual commands follow.

Look up your organization number and billing account ID:

```bash
gcloud organizations list
gcloud billing accounts list
```

Create the host project (6 to 30 lowercase letters, digits and hyphens; it becomes `<your-project-id>` everywhere below), link it to billing, and create the managed-workloads folder that will hold the projects StackVend creates for your workloads:

```bash
gcloud projects create <your-project-id> --organization=<ORG_NUM>
gcloud billing projects link <your-project-id> --billing-account=<BILLING_ACCOUNT_ID>
gcloud resource-manager folders create --display-name="<folder-name>" --organization=<ORG_NUM>
```

`<folder-name>` is at most 30 characters (letters, digits, spaces, hyphens and underscores), for example `<your-project-id>-workloads` when the project id has at most 19 characters, or a shorter name such as `stackvend-workloads`. The last command prints `name: 'folders/<FOLDER_ID>'`: the installer asks for that value. Use a new, empty folder for each install, so each install's projects, permissions and deletion-safety tag stay separate.

If someone else creates the project or the folder for you, they grant you what you need on them (rows 3 and 6), and an Organization Administrator grants the organization roles (rows 7 and 8; when that administrator runs `scripts/pre-bootstrap.sh`, it offers them, as described above):

```bash
gcloud projects add-iam-policy-binding <your-project-id> --member="user:<you>" --role="roles/owner"
gcloud resource-manager folders add-iam-policy-binding <FOLDER_ID> --member="user:<you>" --role="roles/resourcemanager.folderIamAdmin"
gcloud organizations add-iam-policy-binding <ORG_NUM> --member="user:<you>" --role="roles/resourcemanager.tagAdmin"
gcloud organizations add-iam-policy-binding <ORG_NUM> --member="user:<you>" --role="roles/orgpolicy.policyAdmin"   # optional (row 8)
```

The folder role lets the platform Terraform grant StackVend's service accounts their roles on the folder (project creation, IAM and deletion safety for the child projects). Tag Administrator is used only at apply time, to create StackVend's deletion-safety tag (projects carrying it are the only ones StackVend may ever delete); no StackVend service account receives it. Without it (or when you skip the organization or folder ID, or the installer cannot check the role) the installer shows a **NO DELETION SAFETY** warning with the grant command and asks `Continue without deletion safety? [y/N]`, right after the folder question and before it changes anything (only when it cannot read the platform state does it ask later, just before the plan): **N** or Enter stops (grant the role, then run `bash scripts/bootstrap.sh` again); without a terminal it stops the same way. If you answer **y**, the install completes, but StackVend refuses every project delete (`GUARD_UNCONFIGURED`) and **Settings** shows the fix: grant the role, run `scripts/apply.sh apply` again, then press **Bind deletion safety tag** so projects vended before the tag existed are tagged. Run `scripts/apply.sh` from the root of the StackVend folder you installed from: it holds `infra/platform/<your-project-id>.tfvars` (the installer and every `scripts/apply.sh apply` back it up to `gs://castor-tfstate-<your-project-id>/platform/`, and `scripts/apply.sh` offers to restore it from there when it is missing; see [Configuration](configuration.md#backup-and-restore-of-the-vars-file)). Organization Policy Administrator is also used only at apply time, to set the folder's "no external VM IPs" policy; no StackVend service account receives any org-policy role (vending only reads each new project's effective policy). The policy covers **every** project in the managed-workloads folder, including any you place there yourself. Without the role the installer prints a warning with the grant command and skips only that policy; grant it and run `scripts/apply.sh apply` again.

### Tools

* **Google Cloud SDK (`gcloud`)**, signed in as above.
* **OpenTofu 1.10 or later** (`tofu`; installs are verified with OpenTofu 1.13.x). The installer and `scripts/apply.sh` check the version before doing anything and stop with a clear message on an older engine: OpenTofu 1.9 and HashiCorp Terraform 1.5.x cannot read the platform configuration (its `removed` block with `lifecycle`). The installer prefers OpenTofu (MPL-2.0) when both are present. HashiCorp Terraform 1.10 or later passes the same check but has not been verified with the platform configuration, and Terraform 1.6 and later uses a different (BUSL) license. This requirement is for installing the platform only: workloads are applied by the platform's own Terraform MCP server / `tf-applier` (OpenTofu, default 1.9.0), which refuses Terraform 1.6 or later. **When OpenTofu is missing or too old**, `scripts/pre-bootstrap.sh`, `scripts/bootstrap.sh` and `scripts/apply.sh` offer to install it for you in a terminal: `Install OpenTofu 1.13.1 into ~/bin now? [y/N]`. Yes downloads the official OpenTofu 1.13.1 release zip for your machine (Linux or macOS, amd64 or arm64), checks its SHA-256 against the value pinned in this repository (from the release's `tofu_1.13.1_SHA256SUMS`; any mismatch is refused and nothing is installed), puts only the `tofu` binary in `~/bin` (no sudo, no package manager) and uses it for the rest of the run. In a new shell, run `export PATH="$HOME/bin:$PATH"` first, or add that line to your shell profile. No, or a run without a terminal, stops and prints the manual commands, the same download checked with `sha256sum -c`.
* **`python3` and `curl`** on `PATH`: the install scripts use them (reading the tfvars, the plan gate, the read-only permission checks, the first-admin seed), and the installer stops with a clear message if either is missing. Any Python 3 works for installing; Python 3.12 is needed only for local development. No `gcloud` `beta` component is needed.
* **Gemini access**: Vertex AI via IAM, no key needed (an install whose Secret Manager secret `castor-gemini-api-key` already has an enabled version keeps using that Google AI Studio key for the Control Center assistant).
* **GitHub** (optional): an organization or user for generated workload repositories. Alternatively choose the serverless Git provider and use no GitHub at all.

### Create the Google OAuth clients (public ingress only)

**With Direct IAP, the installer's default ingress, skip this section.** You need no OAuth consent screen and no OAuth client: IAP signs people in with a Google-managed OAuth client, and the Control Center's own Google sign-in is switched off in that mode. Press Enter at both client prompts. Google documents that a Google-managed client admits only accounts of your organization, so sign in with an account of your Google Cloud organization.

**With public ingress** (the installer's option 2, a short-lived sandbox), the Control Center needs its own Web OAuth client, because it then signs people in itself. The installer asks for **two different Web OAuth clients** in the platform project: one for the Control Center and one reserved for Google sign-in to the tenant apps StackVend generates. **In this preview only the Control Center client is used.** Generated apps get no shared Google sign-in (see [Known limitations](known-limitations.md#generated-public-apps-have-no-shared-google-sign-in-yet)), so the tenant client is optional: you can skip it (press Enter at its prompt), and if you enter one it is only stored for a later release. If you enter both, they must be two separate clients; the installer refuses to continue if you enter the same client twice, because a tenant app could then sign platform administrators into the Control Center. Google offers no API that creates Web OAuth clients, so create them by hand **before** running the installer, in the Google Cloud console of `<your-project-id>`:

1. **Configure the OAuth consent screen first** (Google Auth Platform; a new project asks for it before it lets you create a client):
   * **Branding**: an app name (for example `StackVend`) and a support email.
   * **Audience**: *Internal* if everyone who signs in belongs to your Google Workspace / Cloud Identity organization; otherwise *External*, and then either set the publishing status to *In production* or add every person who signs in as a *test user*.
   * **Data access (scopes)**: `openid`, `email` and `profile` only. These are non-sensitive scopes, so no Google verification is needed.
2. **Create the Control Center client**: **Clients > Create client** (or **APIs & Services > Credentials > Create credentials > OAuth client ID**), type **Web application**. Its JavaScript origin is known before the install: `https://product-control-center-ui-<project-number>.<region>.run.app`, where `<project-number>` is printed by `gcloud projects describe <your-project-id> --format='value(projectNumber)'` (the installer prints this exact origin too). After the install, also add the `control_center_url` the installer prints at the end if it is a different form.
3. **Optionally create the tenant sign-in client** the same way, as a second, separate client.

| | Control Center client | Tenant sign-in client |
| :-- | :-- | :-- |
| Name | `StackVend Control Center (<install>)` | `StackVend tenant sign-in (<install>)` |
| Authorized JavaScript origins | The Control Center URL(s) only, as exact `https://host` values. Cloud Run serves two URL forms (`<service>-<project-number>.<region>.run.app`, known before the install, and `<service>-<hash>-<region-code>.a.run.app`, printed as `control_center_url`); list each one you use, plus a custom domain if you have one. Add `http://localhost:8080` only if you use the `gcloud run services proxy` path below. | **None** |
| Authorized redirect URIs | **None** (the Control Center uses the Google sign-in popup, which needs none) | **None** for now. No release uses this client yet; its redirect URI will be documented when shared tenant sign-in ships |
| Client secret | Not used. Do not store it anywhere | Entered once into the installer's hidden prompt; it is kept only in Secret Manager (`stackvend-tenant-google-client-secret`) when that secret exists, and nothing reads it in this release. Never put it in `castor-oauth-client-secret` |
| Scopes / consent screen | The platform project's consent screen (step 1) | `openid`, `email` and `profile` only; publishing status *In production* |

**The Control Center client is pinned.** The installer writes the Control Center client ID to `cc_google_oauth_client_id` in `infra/platform/<your-project-id>.tfvars`, and Terraform passes it to the Control Center. The Control Center then uses exactly that client for Google sign-in, refuses to change it, and never reads the Secret Manager secret `castor-oauth-client-id`. Set the client with the variable: the sign-in screen cannot set one, and its endpoint refuses every attempt (no request can set a first client; on an install without the variable the screen shows only the steps below). The installer never stores either client in `castor-oauth-client-id` / `castor-oauth-client-secret`.

There is no switch, sign-in hub or per-app sign-in client for tenant apps in this release: whichever you choose, generated apps offer no shared "Sign in with Google" button. If the Control Center runs behind Identity-Aware Proxy (authenticated ingress, the installer's default), it needs no client of its own: IAP signs people in, and the Control Center's own Google sign-in is switched off in that mode. Press Enter at its prompt; you only need a client if you later switch the install to public ingress.

To set or change the Control Center client later, put `cc_google_oauth_client_id = "<client-id>"` in `infra/platform/<your-project-id>.tfvars` and run `PROJECT_ID=<your-project-id> bash scripts/apply.sh apply`. An install made without the variable (for example a hand install in public mode) should set it the same way: earlier releases let the first administrator type a client ID on the sign-in screen, and a client stored that way cannot be told apart from one planted by someone with write access to the platform database.

---

## 2. Bootstrap the platform

The installer `scripts/bootstrap.sh` is interactive. Google Cloud Shell is a convenient place to run it. Cloud Shell does not ship OpenTofu (and `apt` has no package for it): answer `y` when `scripts/pre-bootstrap.sh` or the installer offers to install OpenTofu 1.13.1 into `~/bin` ("Tools" above), or install OpenTofu 1.10 or later yourself first with the commands the installer prints when you answer `n`.

```bash
git clone https://github.com/<owner>/stackvend.git    # or your fork
cd stackvend
bash scripts/pre-bootstrap.sh      # start here: it runs scripts/bootstrap.sh for you at the end
```

If you prepared the project and folder by hand, or are re-running the installer, run `bash scripts/bootstrap.sh` directly.

When `STACKVEND_PROJECT_ID`, `STACKVEND_ORG_ID`, `STACKVEND_BILLING_ACCOUNT_ID` or `STACKVEND_FOLDER_ID` is set (the command `scripts/pre-bootstrap.sh` prints sets them), the matching prompt shows that value as its default: Enter accepts it, typing replaces it, and it is checked like typed input. It asks for (press Enter to accept defaults or skip optional values): project ID, region and zone, organization ID, billing account ID, the managed-workloads folder ID (`folders/<FOLDER_ID>`), environment tier, VCS provider, the GitHub organization (GitHub provider only; personal accounts are not supported), the ingress posture (authenticated Direct IAP or public sandbox), and the OAuth client IDs from "Create the Google OAuth clients" above (behind Direct IAP press Enter at both: no client is needed; with public ingress the Control Center client is required, plus the tenant client's secret, in a hidden prompt, if you entered a tenant client). Right after the folder prompt, before anything is changed, it checks read-only that you can set IAM on that folder (row 6 above) and stops with the grant command if not; `scripts/apply.sh apply` runs the same check before its plan. It then enables APIs, writes `infra/platform/<your-project-id>.tfvars` (one file per install; an `infra/platform/terraform.tfvars` is moved aside first, renamed to `<its project_id>.tfvars` or to a timestamped backup, because OpenTofu would load it into every run; a new install is written with the Terraform runner identity **Per workload**, `tf_runner_identity = "PER_WORKLOAD"` and `tf_runner_dedicated_sa = true`, see [Configuration](configuration.md#platform-variables-project_idtfvars)), creates the state bucket `gs://castor-tfstate-<your-project-id>`, runs the platform OpenTofu/Terraform apply (stage 1), and offers to build and deploy the services from source with buildpacks (stage 2, `scripts/deploy-services.sh --all-jobs`). Stage 1 takes about 10-20 minutes; stage 2 builds 3 services at a time and takes about 30-50 minutes. Without stage 2 the services keep their placeholder image.

**Internal-only platform services.** The installer puts every platform service and job except the QA sandbox job on
the platform network `stackvend-host` (`host_vpc_egress = true`) and makes every service except the Control Center
internal-only (`host_internal_ingress = true`), both in the stage 1 apply. Nothing else to run: from the internet,
Cloud Shell or a laptop only the Control Center answers (the other services return 404, even with a valid token). See
[Configuration: Platform network](configuration.md#platform-network-internal-only-host-services).

### Doing it by hand

Use the wrapper, not plain `tofu init && tofu apply`: the platform's `gcs` backend has no bucket in the configuration (the wrapper passes `castor-tfstate-<your-project-id>`), and the configuration reads that bucket as an existing data source, so it must exist first.

```bash
cp infra/platform/terraform.tfvars.example infra/platform/<your-project-id>.tfvars
# edit it: project_id, region, ingress posture, admin_email, VCS provider, cc_google_oauth_client_id, ...
PROJECT_ID=<your-project-id> bash scripts/apply.sh init    # creates the versioned state bucket gs://castor-tfstate-<your-project-id> (asks first) and binds the backend
PROJECT_ID=<your-project-id> bash scripts/apply.sh apply   # plan -> deletes/replaces refused -> type the project id -> API pre-enable -> apply
```

For in-app Google sign-in (public ingress, or the proxy path below), set `cc_google_oauth_client_id` in the vars file before the apply: the sign-in screen cannot set a client.

`apply.sh apply` also runs the read-only Tag Administrator, Organization Policy Administrator and billing checks and pre-enables the base APIs after you confirm. It refuses a project that has no platform state yet, so run `init` first. What only the installer does: it seeds the account that ran it as the first `ADMIN` (by hand, set `admin_email`; the Control Center treats it as the bootstrap administrator), stores the tenant client secret in Secret Manager, wires an existing Gemini API key (`castor-gemini-api-key`) into the Control Center, and offers stage 2.

The apply creates the Cloud Run services with a placeholder image, Firestore, Pub/Sub, Cloud Workflows, secrets, scheduler jobs and service accounts. To put the real code on those services, deploy them from source:

```bash
bash scripts/deploy-services.sh --all-jobs      # everything
bash scripts/deploy-services.sh control-center  # a single service
```

Variable names in `<your-project-id>.tfvars` keep the historical `castor_` prefix where applicable (for example `castor_managed_workloads_folder_id`); see [Configuration](configuration.md#platform-variables-project_idtfvars).

### Ingress posture

* **Authenticated (recommended; the installer's default)**: `allow_unauthenticated = false`, `enable_direct_iap = true`, and `authorized_invoker_members` listing the users, groups or domains IAP lets in (the installer writes your account plus at most one more principal; edit the list and run `scripts/apply.sh apply` to change it). Each person also needs a Control Center user (see "Open the Control Center"). Identity-Aware Proxy signs people in with their Google account before any request reaches the Control Center. The platform's own scheduled work and billing alerts never call the Control Center (they run as Cloud Run jobs), so nothing needs adding for them. IAP uses a Google-managed OAuth client here; Google documents that such a client admits only accounts of your Google Cloud organization, so sign in with an organization account (a personal Gmail account is refused) or use the public sandbox for a personal evaluation.
* **Public sandbox**: `allow_unauthenticated = true`. The Control Center is reachable without Google IAM authentication and relies on in-app login only. Use it only for short-lived evaluation.

### Post-install: billing access

You do not need billing-administrator rights to install StackVend, and the billing grants are never a step the install can fail on. Three grants on the **billing account** need a *Billing Account Administrator*:

| Grant | For | What does not work until it exists |
| :-- | :-- | :-- |
| *Billing Account User* (`roles/billing.user`) to `sa-project-provisioner@<your-project-id>.iam.gserviceaccount.com` | The vending service links each new child project to the billing account | The workload run stops at project vending with `BILLING_NOT_LINKED` (the child project it may have created is kept and reused when you re-run after the grant). Grant it before your first workload. |
| *Billing Account User* to `sa-castor-developer@<your-project-id>.iam.gserviceaccount.com` | The FinOps enforcer re-links billing when a budget-quarantined workload is released | The FinOps enforcer cannot re-link billing when a quarantined workload is released. |
| *Billing Account Viewer* (`roles/billing.viewer`) to `sa-stackvend-control-center@<your-project-id>.iam.gserviceaccount.com` | The **Settings** billing card reads the billing account | The billing card shows a warning that it has no access to the billing account. |

Budget alerts and the nightly spend sync do not depend on these grants.

How they are made: with `bind_billing_iam` unset (the default; the installer never writes it), `scripts/bootstrap.sh` and `scripts/apply.sh` check read-only whether you are a Billing Account Administrator. If you are, Terraform makes all three grants. If you are not, the install completes without them and the installer prints a **Post-install step: billing access** block with the exact commands. If the check cannot run (for example no access to the Cloud Billing API), the installer offers to try the grants with `gcloud` and prints the same block for any it could not make. A Billing Account Administrator then either re-runs `PROJECT_ID=<your-project-id> bash scripts/apply.sh apply`, or runs:

```bash
gcloud billing accounts add-iam-policy-binding <billing-account-id> \
  --member=serviceAccount:sa-project-provisioner@<your-project-id>.iam.gserviceaccount.com --role=roles/billing.user
gcloud billing accounts add-iam-policy-binding <billing-account-id> \
  --member=serviceAccount:sa-castor-developer@<your-project-id>.iam.gserviceaccount.com --role=roles/billing.user
gcloud billing accounts add-iam-policy-binding <billing-account-id> \
  --member=serviceAccount:sa-stackvend-control-center@<your-project-id>.iam.gserviceaccount.com --role=roles/billing.viewer
```

**Running the installer again for the same project.** If `infra/platform/<your-project-id>.tfvars` already exists, `scripts/bootstrap.sh` checks (read-only) whether that project has StackVend platform state. With none (a run that stopped early), it moves the file to a timestamped `.bak-…` copy and continues as a new install. With an installed platform, it asks whether to re-run the installer for it (default Yes): Yes keeps a backup and carries over the file's runner identity, update and network settings, exactly as `--overwrite-tfvars`. If the state cannot be read, it asks with default No. Without a terminal, those two cases stop with the commands to run instead.

Run the `apply.sh` re-run from the root of the StackVend folder you installed from: it holds `infra/platform/<your-project-id>.tfvars`. You do not need to back that file up yourself: the installer copies it to `gs://castor-tfstate-<your-project-id>/platform/<your-project-id>.tfvars` at the end of the install and `scripts/apply.sh` refreshes the copy after every successful apply. From another machine or a fresh clone, `PROJECT_ID=<your-project-id> bash scripts/apply.sh plan` offers to restore it (see [Configuration](configuration.md#backup-and-restore-of-the-vars-file)).

The Control Center shows the state on **Settings** (billing card): for each of the two *Billing Account User* service accounts it shows granted, not granted or cannot verify, with the exact command (all three commands above when it cannot verify), and a warning while the Control Center itself cannot read the billing account. Do not set `bind_billing_iam = true` in the tfvars unless the person who applies is a Billing Account Administrator: an explicit value always wins over the check, and without the rights the apply then fails with a permission error.

### GitHub App (GitHub VCS provider: required before the first workload)

The installer asks for the GitHub organization but not for credentials. With the GitHub VCS provider, do this after stage 1 and **before you create the first workload**; until then vending cannot create the workload's repository. (With the serverless Git provider, skip it.)

1. Create a GitHub App on the organization that will own the workload repositories (GitHub: **Settings > Developer settings > GitHub Apps > New GitHub App**): repository permissions *Administration*, *Contents*, *Pull requests*, *Secrets* and *Workflows* set to **Read & Write**, no webhook. *Secrets* lets vending write each workload's GitHub Actions deploy secrets (`GCP_PROJECT_ID`, `WIF_PROVIDER`, `WIF_SERVICE_ACCOUNT`) on a redeploy or a promotion; without it those writes fail and the redeploy answer carries `wif_secrets_error` (`VENDING.GHA_SECRETS_NOT_WRITTEN`). Install it on the organization and generate a private key. The owner must be an organization: StackVend acts through short-lived GitHub App installation tokens, which can create repositories only in an organization where the App is installed, so personal GitHub accounts are not supported (vending stops with `GITHUB_OWNER_NOT_ORGANIZATION`).
2. Store it in the Secret Manager secret `castor-github-app-private-key` (created empty by the platform Terraform):

   ```bash
   cat << 'EOF' | gcloud secrets versions add castor-github-app-private-key --project=<your-project-id> --data-file=-
   {
     "app_id": "<APP_ID>",
     "installation_id": "<INSTALLATION_ID>",
     "private_key": "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"
   }
   EOF
   ```
3. **Settings** in the Control Center shows the VCS status (GitHub ready or what is missing; an owner that is not an organization shows **Owner Not an Organization**).

---

## 3. Open the Control Center

The Terraform output `control_center_url` (and the bootstrap summary) shows the URL of the `product-control-center-ui` Cloud Run service. With Direct IAP (the installer's default; `access_instructions` starts with "Enterprise IAP Access"), open it in Chrome or Firefox and sign in with an authorized account of your organization: IAP signs you in, with no OAuth client of your own. The Cloud Run proxy below is **not** a fallback for a Direct IAP install: its requests still pass through IAP, and the Control Center's own Google sign-in is off in that mode.

The proxy is for an install with neither public ingress nor Direct IAP (`allow_unauthenticated = false` and `enable_direct_iap = false`, set by hand in the tfvars; `access_instructions` then starts with "CLI Proxy Access"):

```bash
gcloud run services proxy product-control-center-ui --port 8080 --project <your-project-id>
```

then open `http://localhost:8080`. In-app Google sign-in (public mode and this proxy path) uses the Control Center's own Web OAuth client, so both need the client from "Create the Google OAuth clients" (the proxy path also needs `http://localhost:8080` as a JavaScript origin). The client is set by the `cc_google_oauth_client_id` variable (the installer writes it in public mode); set it in the vars file and run `PROJECT_ID=<your-project-id> bash scripts/apply.sh apply`. An install without the variable has no client unless an earlier release stored one; the sign-in screen then shows only those steps (the origin to register with the client, the vars-file line and the apply command) and cannot set a client itself. For local development of the Control Center, set the environment variable `GOOGLE_OAUTH_CLIENT_ID` instead. Use Chrome or Firefox: the session cookie is `Secure`, and Safari does not keep `Secure` cookies over `http://localhost`, which causes sign-in loops.

The account that ran the installer (or `admin_email`) is seeded as an `ADMIN`. Admins manage further users (and their roles) in the Control Center or through the `/api/users` endpoints. **Behind Direct IAP a Control Center user alone does not get anyone in:** IAP refuses the person before the Control Center sees them. Only the principals in `authorized_invoker_members` in `infra/platform/<your-project-id>.tfvars` are granted `roles/iap.httpsResourceAccessor`, after `PROJECT_ID=<your-project-id> bash scripts/apply.sh apply`. A person therefore needs both: an IAP grant (their `user:`, a `group:` or their `domain:` in that list) and a Control Center user. With public ingress only the Control Center user is needed.

---

## 4. Create your first workload

1. In the **Workloads Catalog** tab choose **New Workload**.
2. Pick a creation mode: describe your service in free text or upload a document (the default agent mode), or choose **Express Registered Modules** to assemble a workload from golden modules.
3. Fill in a workload ID (a lowercase slug such as `order-notifier`), a title and the specification, for example:
   ```text
   Build a FastAPI webhook service that receives order events, validates the
   payload (order_id, customer_email, amount_usd), and stores a summary in
   Firestore. Include GET /health and a pytest suite.
   ```
4. Optionally set the monthly budget, VCS provider, IaC engine, whether human code review is required, and whether this is a sandbox (temporary) workload.
5. Submit it. Try the specs in [`examples/`](examples/README.md) for larger scenarios.

You can also create workloads through the REST API (`POST /api/workloads`), which accepts the same fields.

---

## 5. Watch the pipeline

Open the **Flight Deck** tab to follow the run in real time: pre-discovery, architect consensus, advisory compliance and cost evaluation, project vending, the developer swarm, preflight/gatekeeper, QA, release, and infrastructure deployment. If the platform needs a decision from you (plan approval or release approval) the run pauses and a badge appears on the **HITL Approvals** tab.

When the run finishes, the workload details show the pull request, the child project ID and the deployed service URL. Review the generated code and the infrastructure before relying on it.

---

## 6. Day-2 operations

* **Sandbox workloads** expire automatically. Use *Extend* (limited to 3 extensions and 90 days total) or *Promote to Production*; see [Workload Lifecycle](workload-lifecycle.md).
* **Budgets** are configured per workload and as defaults in Settings; see [Configuration](configuration.md#4-finops-and-budget-controls).
* **Updating the platform**: to a release tag, `PROJECT_ID=<your-project-id> bash scripts/upgrade.sh <tag>` runs the whole order with a read-only plan and a confirmation first (see [Known Limitations](known-limitations.md)). By hand: fetch the release tag and verify it before you check it out (that it is an annotated tag carrying its own name, and `git verify-tag` against `scripts/release/allowed_signers` of your checkout: the commands are in the README's "Updating an installation"), or merge the opt-in sync workflow's pull request after the same checks on its tag; then follow the release's `CHANGELOG.md` entry: `PROJECT_ID=<your-project-id> bash scripts/apply.sh apply` first if files under `infra/platform/` changed, then `PROJECT_ID=<your-project-id> REGION=<region> bash scripts/deploy-services.sh --all-jobs`.

### Check for IAM grants made outside Terraform

StackVend's destructive guards (project decommission, sandbox expiry) assume that only the identities the platform Terraform declares can delete projects, change IAM or write the guard database. A grant made by hand later can get around them. To list such grants, run this read-only check:

```bash
PROJECT_ID=<your-project-id> bash scripts/check-install-iam.sh
```

It reads the applied platform Terraform state and the IAM policies (with `getIamPolicy`, never a write) of the host project, the managed workloads folder, the billing account, the deletion-safety tag and every StackVend service account. It then prints a table of the grants that are not in the state and that reach past the guards: for example an extra *Owner* on the host project, *Project Deleter* or *Folder Admin* on the workloads folder, write access to the `stackvend-guard` database, act-as on a platform service account, *Billing Account Administrator*, *Tag User* on the deletion-safety tag, or a StackVend service account holding a role that Terraform did not give it. Each row says why the grant matters and gives the `gcloud ... remove-iam-policy-binding` command that removes it. The check never runs that command: confirm nobody needs the grant first.

The administrators named in your tfvars (`admin_email`, `admin_user_email`, `castor_admin_group`) are not reported, and neither are the host project's Google-managed service agents or the billing grants the installer makes. To accept another administrator, add `--admin=user:<email>` (repeatable). If you cannot read the billing account's IAM, add `--skip=billing`. `--json` prints the result as JSON. Grants inherited from the organization or from parent folders are not checked.

On an install with the Terraform runner service accounts (`sa-stackvend-tf-applier`, `sa-stackvend-tf-server`; see `tf_runner_identity` in [Configuration](configuration.md#platform-variables-project_idtfvars)) the check also reports, even when Terraform declares it: a runner account with Secret Manager, platform state, folder, billing, job-update or token-minting access; anyone able to act as a runner account (except vending's optional act-as on the job account); a workload deployer (`stackvend-deployer@<workload project>`) bound in the host project or folder; vending running as a shared account. It also reads each workload deployer's own IAM policy (the list comes from the guard database) and reports any act-as or token grant other than vending's. Add `--skip=deployers` to leave the deployers out.

Exit status: `0` no unexpected grants, `1` unexpected grants found, `2` the check could not finish (for example, a policy or the state could not be read).

## 7. Cleaning up

The platform host project and every child project it vended incur cost until removed. Decommission workloads from the Control Center, then delete child projects and finally the host project when you are finished evaluating.
