# Contributing to StackVend

Thank you for your interest in contributing to **StackVend**.

> **Pull requests are not accepted during the preview.** Please open an [issue](../../issues) for bugs, questions and ideas instead; issues are read and welcome. Pull requests opened during the preview are closed without review. The sections below describe how the project is built and tested, and how pull requests will work once they are accepted.

> **Public preview.** StackVend is under active development and is not production-ready. Expect breaking changes, and expect some parts of the codebase (especially the IaC "healers" described below) to be in the middle of a redesign. Small, well-tested changes are much easier to review than large ones.

StackVend turns a product spec into a tested, deployed Google Cloud workload in an isolated child project. The code is a monorepo of Cloud Run services, MCP tool servers, shared libraries and OpenTofu/Terraform modules. See [`documentation/architecture.md`](documentation/architecture.md) and [`documentation/platform-internals.md`](documentation/platform-internals.md) for an overview, and [`AGENTS.md`](AGENTS.md) for the short rule sheet that both human and AI contributors are expected to follow.

> **Naming.** The product is called **StackVend**. "Project Castor" was its original codename. Many internal identifiers still use the `castor-` prefix (Cloud Run services, service accounts, buckets, Python docstrings, environment variables). Those are real resource names; do not rename them as part of an unrelated change.

---

## 1. Development setup

You do **not** need a Google Cloud project to run the unit tests.

```bash
git clone https://github.com/<your-github-username>/stackvend.git   # your fork
cd stackvend

python3.12 -m venv .venv          # 3.12 has wheels for every dependency; newer Pythons may not
source .venv/bin/activate

pip install \
  -r apps/control-center/requirements.txt \
  -r apps/orchestrator-gateway/requirements.txt \
  -r mcp-servers/terraform/requirements.txt \
  -r mcp-servers/kubernetes/requirements.txt \
  pytest pytest-asyncio anyio httpx

export TEST_MODE=true
export PROJECT_ID=mock-stackvend-project
export GCP_PROJECT=mock-stackvend-project
export GOOGLE_CLOUD_PROJECT=mock-stackvend-project
export DEFAULT_REGION=us-central1
export COLUMNS=400
# Make Application Default Credentials fail closed on machines that have credentials:
export GOOGLE_APPLICATION_CREDENTIALS=/nonexistent/adc-disabled.json
export CLOUDSDK_CORE_PROJECT=mock-stackvend-project
```

`TEST_MODE=true` is for the test suite only; it relaxes some authorization checks, so never set it on a deployed service or on a locally running instance connected to real cloud resources. `mock-stackvend-project` is a deliberately fake project ID. Always export `PROJECT_ID` as well as the other variables (see "Why tests must stay hermetic" below).

### Running tests

```bash
# Fast core suite (start here)
pytest tests/test_anti_hallucination_preflight.py tests/test_hcl_utils.py tests/test_iac_env_var_bridge.py

# Full suite: run as THREE separate invocations.
# Both MCP test files are named test_service.py, so combining them causes a collection error.
pytest tests/ -rf --tb=no
pytest mcp-servers/terraform/test_service.py
pytest mcp-servers/kubernetes/test_service.py

# Syntax-check anything you changed
python3 -m py_compile <changed .py files>
```

Notes:

- `pytest.ini` already passes `-q`; do not add it again (it hides the summary line).
- All three test invocations must report 0 failed before you open a pull request. **Do not introduce new failures.** If a test fails on your branch, run the same test on `main` first to see whether your change caused it.

### Why tests must stay hermetic

Only run the test commands listed above. In particular, **do not run `apps/*/test_*.py` files against real credentials.** Those files are not all proven hermetic: with `PROJECT_ID` unset, application code can pick up Application Default Credentials and talk to a real Firestore database in whatever project your `gcloud` is logged into. A previous incident did exactly that.

The root `conftest.py` blocks construction of a real Firestore client during any pytest run, but that is a safety net, not a licence. New tests must:

- inject fakes or `mock.patch` the client classes (see `tests/cc_identity_harness.py` for a Firestore fake);
- never construct real Firestore / GCS / Pub/Sub / GitHub clients;
- never require network access or credentials.

---

## 2. Ground rules for code changes

These are the non-negotiable invariants from [`AGENTS.md`](AGENTS.md). Reviewers will check for them.

### 2.1 "Do No Harm" and the negative-test rule

StackVend contains deterministic sanitizers and "healers" that adjust LLM-generated code (Python, HCL, YAML) before it is committed or applied. The rule for all of them:

> A sanitizer or healer must **never mutate input that is already valid**. Only repair what actually fails `ast.parse`, an HCL parse, or `tofu validate`.

Therefore **every new or modified sanitizer/healer must ship with a negative test**: feed it valid input and assert the output is byte-identical to the input. A change that adds a healer without such a test will not be merged. Tests that only show "bad input becomes good output" are not sufficient.

### 2.2 No new string-matching heuristics

Do **not** add new substring or regex guessing to patch a symptom (for example `if "foo" in value.lower()` or a regex rewrite of HCL). The project is moving away from this approach toward:

- **validators** that reject bad output using real parsers and real tool output (`ast`, an HCL parser, `tofu validate`, provider schemas, cloud APIs), and
- **bounded repair loops** that feed validator errors back to the generator instead of rewriting text.

If a fix seems to need a heuristic, prefer (in this order): deleting an over-eager existing heuristic, fixing the generation contract (prompt/schema) so the bad output is not produced, or using a real parser/API. Describe in your PR why none of these work if you still think a heuristic is required.

### 2.3 Other invariants

- **No hardcoded environment values**: no project IDs, folder IDs, regions, CIDR ranges, emails or secrets in code, docs or tests. Use `var.project_id`, `var.region`, the IPAM helper in `shared/ipam.py`, environment variables, or Secret Manager.
- Generated workload IaC lives in `infra/workload/` (singular). Generated workloads use Cloud Native Buildpacks and have **no Dockerfiles**.
- Never prune cross-region secondary GKE clusters, and never touch the host platform project.
- Multi-service IaC must stay acyclic (no A -> B -> A `service_uri` references). Only the `compute-cloudrun` module exports `service_uri`.
- The `tf-applier` job and `mcp-terraform-server` containers have **no `gcloud` or `kubectl`**. Use REST APIs through an authorized session.
- **Fail loudly**: a step that did not work stops with a typed error. It never reports success, a pass, or a placeholder id or URL. Carrying on with a recorded warning is a narrow exception; see [`documentation/fail-loudly-policy.md`](documentation/fail-loudly-policy.md).
- Keep changes scoped. One concern per PR.

### 2.4 Replicated files: edit every copy

Because each service builds in its own container context, some shared code is **copied** into several directories. If you edit one copy, you must edit all of them (or consolidate them) in the same PR.

- `hcl_utils.py` exists in five places and parity is enforced by `tests/test_hcl_utils.py::test_hcl_utils_monorepo_parity`:
  `shared/`, `apps/orchestrator-gateway/shared/`, `apps/orchestrator-gateway/developer_agent/`, `mcp-servers/terraform/`, `mcp-servers/terraform/shared/`.
- Most other files in `shared/` (for example `settings.py`, `builtin_prompts.py`, `builtin_modules_payload.py`, `builtin_bundles_payload.py`, `providers/serverless_git_provider.py`) are also copied into `apps/{control-center,orchestrator-gateway,project-vending,qa-runner}/shared/` and/or `mcp-servers/{github,terraform}/shared/`. Some copies have already drifted; find all copies with `git ls-files | grep <filename>` before editing.
- `generate_rfc1123_variable_default` and `sanitize_gcp_naming_invariants` are deleted everywhere (generation and apply time). Neither generation nor deploy rewrites names or guesses variable values: a templated name is checked by the V2k validator (`developer_agent/validators/names.py`).

### 2.5 Red-team review for high-risk files

Any change to one of these files requires an adversarial design review before merge:

- `apps/orchestrator-gateway/developer_agent/terraform_engine.py`
- `hcl_utils.py` (any of the five copies)
- `apps/orchestrator-gateway/developer_agent/preflight_validator.py`
- `apps/orchestrator-gateway/gatekeeper_agent/verifier.py`
- `mcp-servers/terraform/service.py`

The review protocol lives in [`.agents/skills/stackvend-red-team-review/SKILL.md`](.agents/skills/stackvend-red-team-review/SKILL.md). If you use an AI coding assistant that loads repo skills, run `/stackvend-red-team-review`; otherwise read the file and work through its audit gates by hand. In your PR description, summarize the review: what you attacked, what you ran to verify it (not just reasoned about), and which replicas you updated. The gates cover, among other things: the anti-heuristic veto above, backward compatibility with existing workloads, blast radius (does this need a host-infrastructure apply or only a service redeploy?), slim-container constraints, replica synchronization, and boundary/temporal sanity for any math.

---

## 3. Working with AI coding assistants

The repository ships runbooks for AI pair-programmers in [`.agents/skills/`](.agents/skills/) (index: [`.agents/skills/README.md`](.agents/skills/README.md)). Tools that use the `.agents/skills` convention, such as Google Antigravity, load them directly as `/stackvend-<name>`; others load them through a tool-specific link, or can simply read the `SKILL.md` files. AI-assisted contributions are welcome and are held to exactly the same rules as human ones, including the negative-test and no-heuristics rules above. You are responsible for verifying anything an assistant writes.

---

## 4. Pull requests

_Not accepted during the preview (see the note at the top). This is how they will work later._

1. Fork the repository and branch from `main` (`feat/...`, `fix/...`, `docs/...`, `security/...`).
2. Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`).
3. Fill in the PR template. Before opening the PR, check that:
   - [ ] the relevant tests pass and you added tests for your change (including negative tests for any sanitizer/healer);
   - [ ] all replicas of any shared file you touched are updated;
   - [ ] no project IDs, emails, tokens or other environment-specific values were added;
   - [ ] a red-team review was done if you touched one of the files in section 2.5;
   - [ ] `CHANGELOG.md` has a line under `## [Unreleased]` (directly above the newest release) for user-visible changes.
4. **Do not deploy** as part of a contribution. Deployment of the maintainers' installations is handled by the maintainers.

### Documentation changes

The public docs live in [`documentation/`](documentation/). Where documentation and code disagree, **the code wins**, so please fix the docs. Verify every file path, function name, environment variable and command you mention (for example with `git grep`) and use placeholders such as `<your-project-id>` instead of real identifiers.

---

## 5. Security issues

Please do **not** open public issues for vulnerabilities. See [`SECURITY.md`](SECURITY.md).

## 6. License

By contributing you agree that your contributions are licensed under the [Apache License 2.0](LICENSE).
