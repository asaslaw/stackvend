# StackVend Documentation Index

Welcome to the technical documentation for **StackVend** (originally codenamed Project Castor).

StackVend turns a product specification into a tested, deployed Google Cloud workload running in its own isolated child project. A specification is analysed by a pair of cooperating AI architects, implemented by a swarm of developer agents, checked by deterministic gates, and then deployed with OpenTofu or Terraform.

> **Public preview.** StackVend is not production-ready, security hardening is in progress, and all generated infrastructure should be reviewed by a human before it is applied. Where this documentation and the code disagree, the code wins. Please open an issue or PR if you find a discrepancy.
>
> **A note on names.** The product name is StackVend. Many *internal* identifiers still carry the older `castor-` prefix (Cloud Run job names, service accounts, buckets, secrets, some environment variables and Terraform variables). Where this documentation shows such an identifier, it is the real name in the code.

---

## Documentation catalog

| Document | Description |
| :--- | :--- |
| **[Overview](overview.md)** | What StackVend does, the stages of the spec-to-cloud pipeline, and the design principles behind it. |
| **[Quickstart](quickstart.md)** | Bootstrapping the platform in a Google Cloud project and submitting a first workload. |
| **[Quick Guide](quick-guide.md)** | Short how-to answers for everyday Control Center tasks (submit a spec, watch a build, approvals, freeze, budget breach, Emergency Stop vs Maintenance Mode, decommission, roles). Also shown, self-contained and without these links, in the Control Center's Guide tab. |
| **[User & Operator Guide](user-guide.md)** | Using the Control Center: creating workloads, watching the pipeline, approvals, and day-2 operations. |
| **[Settings Reference](settings-reference.md)** | Every control on the Control Center Settings page: what it does, its default, who can change it, when it takes effect, and how to fix the install warning cards. |
| **[System Architecture](architecture.md)** | Services, MCP tool servers, the agent pipeline and the isolation model. |
| **[Platform Internals](platform-internals.md)** | Execution lifecycle, the developer swarm, the preflight and gatekeeper stages, Cloud Workflows callbacks and project vending. |
| **[Platform Configuration](configuration.md)** | Platform settings stored in Firestore, IaC engine selection, VCS providers, FinOps settings and organization-policy handling. |
| **[Composite Bundles](composite-bundles.md)** | The built-in catalog of multi-module infrastructure bundles and how custom bundles are registered. |
| **[Workload Lifecycle](workload-lifecycle.md)** | Sandbox workloads, expiry, extension, promotion and decommissioning. |
| **[Test a Spec Locally (dry run)](test-a-spec-locally.md)** | Run a spec through the real generation pipeline on your machine and get a verdict, without creating anything. |
| **[Live Canary](live-canary.md)** | Send example 01 through a running install and follow it read-only through QA, build, apply and a `/health` probe of the service URL Cloud Run confirms (anonymous; no user token is ever sent); pass or fail per stage. Run it after every deploy to a dev install, only on workloads whose code and Terraform you trust. |
| **[Developer & Contributor Guide](developer-guide.md)** | Local setup, running the tests, and quality gates. See also [`CONTRIBUTING.md`](../CONTRIBUTING.md). |
| **[Fail-Loudly Policy](fail-loudly-policy.md)** | When platform code must stop with a typed error and when it may carry on with a recorded warning, with examples from the code. |
| **[Extensibility Guide](extensibility-guide.md)** | Recipes for adding golden modules, validators, MCP servers and swarm roles. |
| **[Implementation Plan Prompt](implementation-plan-prompt.md)** | A system prompt you can give to an LLM so that it drafts implementation plans in the format StackVend's agents expect. |
| **[Reference Examples](examples/README.md)** | Nine example workload specifications you can submit to a running platform. |
| **[Known Limitations](known-limitations.md)** | What does not work yet in the public preview, and how to work around it. |
| **[Threat Model](threat-model.md)** | Assets, trust boundaries, the security controls in pipeline order, and the residual risks of the preview. |
| **[Audit Trail and Roles](audit-and-roles.md)** | What StackVend records about who did what, where and for how long, and what each Control Center role may do. |

---

## Key capabilities

* **Dual-architect consensus.** A lead architect proposes a plan and a red-team critic reviews it. The consensus engine allows a single bounded remediation turn when the critic finds a critical problem. The models used are configurable (see [Configuration](configuration.md#2-ai-model-settings)).
* **Developer swarm.** A lead developer decomposes the plan into waves of work for specialist juniors (backend, frontend, IaC, test, DevOps, database). Small changes to an existing repository take a `SOLO_FAST_PATH` instead.
* **Deterministic gates.** Generated code passes preflight validation and a pre-commit "synthesis verifier", then a QA gatekeeper that runs tests and security scans in a sandbox, before a release pull request is opened.
* **Dual IaC engine.** OpenTofu is the default; HashiCorp Terraform is supported. Versions are configurable.
* **Golden modules and composite bundles.** A catalog of pre-written, parameterized infrastructure modules and multi-module bundles that agents are steered toward instead of writing every resource from scratch.
* **Two VCS backends.** GitHub (a GitHub App on your GitHub organization) or a serverless in-GCP Git service.
* **Project vending.** Each workload gets its own Google Cloud project with network address space reserved by an IPAM component.
* **Day-2 governance.** FinOps spend sync and budget policies, an SRE log sentinel, human-in-the-loop approvals, and automatic lifecycle management for sandbox workloads.

---

## Working on StackVend with an AI coding assistant

The repository includes version-controlled runbooks for AI coding assistants in [`.agents/skills/`](../.agents/skills/) and a short rule sheet in [`AGENTS.md`](../AGENTS.md). If you bring an agentic AI coding assistant (for example Google Antigravity, Cursor or Codex) into the repository, point it at:

1. [`AGENTS.md`](../AGENTS.md): invariants, repository map, and the test commands to use.
2. [`platform-internals.md`](platform-internals.md) and [`architecture.md`](architecture.md): how the pipeline fits together.
3. [`developer-guide.md`](developer-guide.md) and [`extensibility-guide.md`](extensibility-guide.md): test and extension procedures.

Key invariants (full list in `AGENTS.md`):

- Never hardcode project IDs, regions or secrets.
- Sanitizers and healers must never change input that is already valid, and each needs a negative test.
- Do not add new regex or substring heuristics to patch symptoms.
- Edit every copy of replicated shared files.

Available repo skills: `/stackvend-red-team-review`, `/stackvend-extend`, `/stackvend-golden-module`, `/stackvend-troubleshoot`, `/stackvend-diagnose-workload`, `/stackvend-monitor-live-workload` and `/stackvend-deploy`. See the [skills catalog](../.agents/skills/README.md).

---

## Roadmap

The ideas below have some design work behind them in the maintainers' planning notes but **are not scheduled and carry no commitment**. Ideas marked *exploratory* have no design yet.

| Area | Idea | Status |
| :--- | :--- | :--- |
| Prompt-injection defense | Screen incoming specifications and tickets with Google Cloud Model Armor before they reach the architect. | Planned (design exists) |
| Evaluation | Run the evaluation harness against prompt and model changes in CI. (The harness itself ships today: see [Test a Spec Locally](test-a-spec-locally.md).) | Planned |
| Decoupled repositories | Optionally separate application code and infrastructure code into paired repositories. | Planned (design exists) |
| Private module registries | Pull golden modules and bundles from private Git hosts (for example GitLab, Bitbucket or Secure Source Manager). | Planned (design exists) |
| Capacity awareness | Consult quotas and capacity when choosing regions for heavy compute workloads. | Planned (design exists) |
| Brownfield ingestion | Adopt existing GCP projects and repositories instead of only vending new ones. | Planned (design exists) |
| Multi-cloud vending | AWS accounts and Azure subscriptions alongside GCP projects. | *Exploratory* |
| Interactive clarification | Let the architect ask the operator questions in the Control Center before freezing a plan. | *Exploratory* |
