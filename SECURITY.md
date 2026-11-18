# Security Policy

StackVend is **public preview software** that can create Google Cloud projects, IAM bindings and infrastructure on your behalf. Security hardening is ongoing, and it is not recommended for production or for any environment holding sensitive data. If you deploy it anyway, use a dedicated, disposable Google Cloud organization/folder and billing account, and review all generated infrastructure before applying it.

We still want to hear about security problems, and we appreciate responsible disclosure. For questions and ordinary bugs, see [`SUPPORT.md`](SUPPORT.md).

---

## Supported versions

Security fixes are made only for the **latest preview release** (the current tip of the `main` branch and the most recent tagged release, see [`VERSION`](VERSION)). Older tags, forks and self-modified deployments are not supported; please reproduce against the latest `main` before reporting. Fixes are not backported; see [`SUPPORT.md`](SUPPORT.md) for what "preview" means for fixes.

| Version | Supported |
| :--- | :---: |
| Latest preview (`main` / newest tag) | Yes |
| Anything older | No |

---

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues, discussions or pull requests.**

Report vulnerabilities only through GitHub's private vulnerability reporting on this repository. There is no security e-mail address.

1. Open the repository's **Security** tab.
2. Click **Report a vulnerability** and fill in the form. This creates a private advisory that only you and the maintainers can see.

Please include, as far as you can:

- a description of the issue and its impact;
- the affected component (for example `apps/control-center`, `apps/orchestrator-gateway`, `apps/project-vending`, `mcp-servers/*`, `infra/`, `scripts/`) and commit or release;
- steps to reproduce, ideally against your own throwaway Google Cloud project;
- any suggested fix.

If you cannot use GitHub Security Advisories, open a public issue that says only that you have a security report and asks for a private contact channel. **Do not include any technical details in the public issue.**

### What to expect

This is a small open-source project maintained on a best-effort basis. We aim to acknowledge reports within a few business days and to keep you informed as we investigate, but we cannot promise specific response or fix times. We will credit reporters in the advisory unless you ask us not to. Please give us a reasonable opportunity to fix an issue before disclosing it publicly.

### Bug bounty

There is **no bug bounty** program. Reports are appreciated but are not eligible for monetary rewards.

---

## Ground rules for security research

- Test only against infrastructure you own or are explicitly authorized to test. Do not probe other people's StackVend installations or any cloud project that is not yours.
- Do not access, modify or destroy data that is not yours. Stop and report as soon as you have demonstrated the issue.
- Do not run denial-of-service, spam or social-engineering attacks.
- Good-faith research that follows these rules will not be pursued by the maintainers.

---

## Scope notes

In scope: the code and infrastructure definitions in this repository. Out of scope: vulnerabilities in Google Cloud, GitHub, OpenTofu/Terraform or other third-party software (report those to the respective vendors), and issues that require an already-compromised administrator account or a configuration that deviates from the documented options (for example manually granted extra IAM permissions). The documented install options, including the public sandbox ingress mode, are in scope.

Known limitations of the preview, including the trust model (who may change a workload's Terraform), are listed in [`documentation/known-limitations.md`](documentation/known-limitations.md). A documented limitation is not a vulnerability by itself, but a way around a control that the documentation says exists is. If you are unsure whether a control exists, ask privately via the advisory form.
