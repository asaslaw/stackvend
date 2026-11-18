# Support

StackVend is **public preview software**, maintained as an open-source project on a best-effort basis. This page says what that means for help, fixes and versions. For security problems, do not use the channels below: follow [`SECURITY.md`](SECURITY.md).

---

## What "preview" means

* **Not for production.** StackVend can create Google Cloud projects, IAM bindings and billable infrastructure. Install it only in a dedicated, disposable Google Cloud environment, review generated infrastructure before it is applied, and do not use it for regulated or sensitive data. The current gaps are listed in [Known limitations](documentation/known-limitations.md).
* **No service level.** There is no support contract, no guaranteed response time and no guaranteed fix time.
* **Behavior can change between previews.** A later preview may change settings, records or generated infrastructure. Each release's [`CHANGELOG.md`](CHANGELOG.md) entry says what changed and the upgrade steps, including whether the platform Terraform (`scripts/apply.sh apply`) must run.
* **Fixes go forward only.** A fix lands on `main` and in the next preview release. Fixes are not backported to older releases.

---

## Supported versions

Only the **latest preview release** is supported: the current tip of `main` and the newest tagged release. The version of a checkout is in [`VERSION`](VERSION) (this release: `0.9.0-preview`).

| Version | Supported |
| :--- | :---: |
| Latest preview (`main` / newest tag) | Yes |
| Older releases | No |
| Forks and modified installations | No |

Before you report a problem, update to the latest release (`git pull`, then `scripts/deploy-services.sh`, and `scripts/apply.sh apply` first when the release changed `infra/platform/`) and check that the problem is still there. `PROJECT_ID=<id> bash scripts/upgrade.sh <tag>` runs that order for a signed release tag; Settings ▸ Upgrades ▸ **Update StackVend** in the Control Center installs a newer signed release only when it needs no `scripts/apply.sh`.

---

## Getting help

| You want to | Go to |
| :--- | :--- |
| Learn how something works | The [documentation index](documentation/README.md), the [Quick Guide](documentation/quick-guide.md) (also in the Control Center's **Guide** tab) and the [User & Operator Guide](documentation/user-guide.md) |
| Check whether a problem is already known | [Known limitations](documentation/known-limitations.md) |
| Try a specification without creating anything | [Test a Spec Locally](documentation/test-a-spec-locally.md) |
| Ask a question | The repository's GitHub Discussions |
| Report a bug | A GitHub issue, using the bug report template |
| Suggest a feature | A GitHub issue, using the feature request template |
| Report a security vulnerability | **Not** an issue: see [`SECURITY.md`](SECURITY.md) |
| Contribute a fix | [`CONTRIBUTING.md`](CONTRIBUTING.md) |

### What to put in a bug report

* The StackVend version (`VERSION`, and the commit if you run `main`).
* What you did, what you expected and what happened.
* For a failed build or deploy: the workload's error class and stage as the Control Center shows them, and the relevant part of the run's log (the **Flight Deck** view). StackVend stops with a typed error when a step fails; that error is the most useful thing to include.
* Your install options that matter (ingress mode, VCS provider, IaC engine).

Remove project ids, account names, secrets and other private values before you post anything publicly.
