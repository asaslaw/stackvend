# StackVend Developer & Contributor Guide

This guide covers setting up a local environment, running the test suites, and the quality gates a change must pass. It complements [`CONTRIBUTING.md`](../CONTRIBUTING.md) (project rules) and [`AGENTS.md`](../AGENTS.md) (the short rule sheet for AI coding assistants). If anything here differs from those files, they win.

> **Public preview.** Parts of the codebase, especially the IaC preflight/healer logic, are being redesigned. Expect churn.

---

## 1. Prerequisites

* **Python 3.12** (recommended: wheels exist for every dependency; newer versions may lack some).
* `pip` and `venv`.
* **OpenTofu** or **Terraform** is only needed if you want to exercise code paths that shell out to the IaC binary. It is not needed for the standard test commands below.
* The **Google Cloud SDK** (`gcloud`) is needed only to deploy to a real environment. Do not use it to "try out" the test suite (see section 3).

---

## 2. Local setup

```bash
git clone https://github.com/<your-github-username>/stackvend.git   # your fork
cd stackvend

python3.12 -m venv .venv
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
```

`TEST_MODE=true` tells the code that it is running under the test suite and relaxes some checks (including some authorization checks in the Control Center) so tests can exercise handlers without real identities. **It is for tests only. Never set it on a deployed service or on a locally running instance connected to real cloud resources.** The project IDs above are deliberately fake; always export `PROJECT_ID` as well.

---

## 3. Running the tests

```bash
# Fast core suite
pytest tests/test_anti_hallucination_preflight.py tests/test_hcl_utils.py tests/test_iac_env_var_bridge.py

# Full suite: run as THREE invocations
# (both MCP test files are named test_service.py, so combining them causes a collection error)
pytest tests/ -rf --tb=no
pytest mcp-servers/terraform/test_service.py
pytest mcp-servers/kubernetes/test_service.py

# Syntax-check anything you changed
python3 -m py_compile <changed .py files>
```

* `pytest.ini` already adds `-q`; do not pass it again.
* `pytest.ini` restricts default discovery to `tests/` and ignores `apps/`, `mcp-servers/` and `infra/`.
* All three invocations are expected to pass with no failures. Do not add new ones.
* The test harness (`tests/conftest.py`, and the top of `mcp-servers/terraform/test_service.py`) sets `GITHUB_ORG=example-org` when it is unset, because the platform has no built-in GitHub owner.

**Do not run `apps/*/test_*.py` against real credentials.** Those files are not all guaranteed hermetic: with `PROJECT_ID` unset, application code can pick up Application Default Credentials and read or write a real Firestore database. The root `conftest.py` blocks creation of a real Firestore client during pytest runs, but you should still keep `PROJECT_ID` set to a fake value and never run those files while logged into a project you care about. New tests must use fakes or mocks (see `tests/cc_identity_harness.py` and `tests/cc_portal_harness.py` for examples) and must never need network access.

### Useful test files

| Area | Test files in `tests/` |
| :--- | :--- |
| Preflight validation | `test_anti_hallucination_preflight.py`, `test_preflight_org_policy_self_correction.py`, `test_hcl_utils.py` |
| Developer swarm and fast path | `test_developer_swarm.py`, `test_fast_path_and_failure_routing.py`, `test_async_developer_and_iac_curing.py` |
| Architect consensus | `test_dual_architect_consensus.py`, `test_spec_decomposer.py`, `test_architect_structured.py` |
| Gatekeeper and QA | `test_synthesis_verifier.py`, `test_gatekeeper_hardening.py`, `test_qa_gatekeeper.py` |
| Golden modules and bundles | `test_golden_modules_catalog_expansion.py`, `test_composite_bundles_catalog.py`, `test_custom_golden_modules_lean.py` |
| FinOps and lifecycle | `test_finops_budget_enforcement.py`, `test_finops_live_sync.py`, `test_sandbox_workload_lifecycle.py` |
| Control Center | `test_cc_portal.py`, `test_cc_identity_fd4e.py`, `test_cc_identity_fd4m.py`, `test_rbac_guardrails.py` |
| MCP servers | `mcp-servers/terraform/test_service.py`, `mcp-servers/kubernetes/test_service.py` |

---

## 4. Running services locally

The services are FastAPI apps started with `uvicorn main:app` from their own directory (each has a `Procfile` with the same command). Starting them without further setup will try to reach real Google Cloud services (Firestore, Secret Manager, and so on) using whatever credentials your environment provides, so only do this against a throwaway project, or point Firestore at the local emulator by setting `FIRESTORE_EMULATOR_HOST` to a `localhost` address.

```bash
cd apps/control-center
uvicorn main:app --reload --port 8080
```

Notes:

* Use Chrome or Firefox for the Control Center locally. The session cookie is `Secure`; Safari does not keep `Secure` cookies over `http://localhost`. For local Safari testing only you can set `CC_INSECURE_LOCAL_COOKIES=true` (ignored when running on Cloud Run).
* Each MCP server exposes `GET /health`, and most also a JSON-RPC endpoint at `POST /mcp` (the compliance server is REST-only); for example `mcp-servers/terraform` listens on whatever port you pass to `uvicorn`.

---

## 5. Quality gates before a pull request

1. **Syntax**: run `python3 -m py_compile` on every Python file you changed.
2. **Tests**: the relevant tests, and the full three-invocation suite for non-trivial changes, with no new failures.
3. **Do No Harm**: a sanitizer or healer must not modify input that is already valid. Every healer needs a negative test (valid input produces byte-identical output).
4. **No new heuristics**: do not add regex or substring guessing to patch symptoms. Prefer removing a heuristic, fixing the generation contract, or using a real parser or API.
5. **No hardcoded environment values**: no project IDs, folder IDs, regions, CIDRs, emails or secrets.
6. **Replicated files**: update every copy (for example the five `hcl_utils.py` copies; parity is enforced by `tests/test_hcl_utils.py::test_hcl_utils_monorepo_parity`).
7. **Multi-cluster invariant**: never prune cross-region secondary GKE clusters.
8. **Red-team review** for changes to `terraform_engine.py`, `hcl_utils.py`, `preflight_validator.py`, `verifier.py` or `mcp-servers/terraform/service.py`, using `.agents/skills/stackvend-red-team-review/SKILL.md`.
9. **Fail loudly**: a step that did not work stops with a typed error; it never reports success, a pass or a made-up value. Carrying on with a recorded warning is the narrow exception described in the [Fail-Loudly Policy](fail-loudly-policy.md).
