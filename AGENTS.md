# AGENTS.md — StackVend

Instructions for AI coding agents (Google Antigravity, Cursor, Codex, etc.). Keep this file short: it is loaded into every session.

StackVend turns a product spec into a tested, deployed GCP workload in an isolated child project: Spec ingestion → Dual-Architect consensus (DAG) → FinOps cost check → Project vending → Developer Swarm (+ Preflight sanitization) → QA Gatekeeper → Release PR → OpenTofu apply → Day-2 governance (order per `workflows/main_orchestrator.yaml`). Background reading: `documentation/overview.md`, `documentation/architecture.md`, `documentation/platform-internals.md`. **Where docs and code disagree, the code wins** (see "Known doc drift").

## Repo map
| Path | What lives there |
| :--- | :--- |
| `workflows/main_orchestrator.yaml` | Cloud Workflows state machine (HTTP callback pattern; state in Firestore `workloads/{product_id}`) |
| `apps/orchestrator-gateway/main.py` | Agent coordination hub (FastAPI) |
| `apps/orchestrator-gateway/developer_agent/` | `handler.py` (entrypoint, Git commit), `lead_orchestrator.py` + `swarm_dispatcher.py` + `juniors/` (swarm), `terraform_engine.py` (IaC synthesis, `generate_golden_*_tf`, `extract_custom_resource_env_vars`), `preflight_validator.py` (deterministic sanitizers), `prompt.py` |
| `apps/orchestrator-gateway/gatekeeper_agent/verifier.py` | `SynthesisVerifierAgent.verify_and_cure` — pre-commit hard gate |
| `apps/orchestrator-gateway/architect_agent/` | Consensus engine, red-team critic, cycle detector |
| `mcp-servers/terraform/service.py` (~9k lines) | OpenTofu/Terraform execution + apply-time self-healing loop; `applier.py` runs as the `tf-applier` Cloud Run Job |
| `mcp-servers/*` | Other MCP tool servers (gcloud, github, compliance, workspace, infracost, kubernetes, agent-builder) |
| `apps/control-center/` | Operator UI + REST API (`routes/`, `templates/dashboard.html`) |
| `apps/project-vending/` | Child project creation, billing, IAM, WIF |
| `infra/modules/` | Golden modules (only `compute-cloudrun` exports `service_uri`) |
| `infra/platform/` | Host-platform Terraform |
| `shared/` | Shared Python libs (**replicated** — see below) |
| `scripts/apply.sh` / `scripts/deploy-services.sh` | Host infra apply vs. Cloud Run service deploys (see `/stackvend-deploy` skill) |
| `eval/` | Offline examples evaluation harness (`documentation/test-a-spec-locally.md`) |
| `tests/` | Root pytest suite (`pytest.ini` ignores `apps/`, `mcp-servers/`, `infra/`) |
| `documentation/` | Public docs |
| `.agents/skills/` | Repo skills: `stackvend-red-team-review`, `-troubleshoot`, `-diagnose-workload`, `-monitor-live-workload`, `-extend`, `-golden-module`, `-deploy` |

## Replicated files (edit ALL copies, or consolidate)
- `hcl_utils.py` ×6: `shared/`, `apps/control-center/shared/`, `apps/orchestrator-gateway/shared/`, `apps/orchestrator-gateway/developer_agent/`, `mcp-servers/terraform/`, `mcp-servers/terraform/shared/` (parity enforced by `tests/test_hcl_utils.py::test_hcl_utils_monorepo_parity`). It holds only the read-only `fmt` parser helpers (`find_hcl_parser_binary`, `hcl_parse_errors`); no HCL rewriter is left.
- `shared/*` is also copied (partially) into `apps/{control-center,finops-enforcer,git-server,infra-rollback,orchestrator-gateway,project-vending,qa-runner,spec-ingestion}/shared/` and `mcp-servers/{github,terraform}/shared/` — copies have already drifted. `settings.py` ×8 (`shared/` + billing-alert-drain, Control Center, finops-enforcer, gateway, project-vending, spec-ingestion, terraform MCP; byte-identical, `tests/test_shared_packaging.py`).
- `quick-guide.md` ×2: `documentation/quick-guide.md` (source) and `apps/control-center/guide/quick-guide.md` (served by the Control Center Guide tab; byte-identical, `tests/test_fd4cv_quick_guide.py`).
- `static_mounts.py` ×3: `shared/`, `apps/orchestrator-gateway/shared/`, `mcp-servers/terraform/shared/` (byte-identical; the `StaticFiles` AST rule shared by the gateway container contract and the deploy workspace).
- `runner_identity.py` ×5: `shared/`, `apps/project-vending/shared/`, `mcp-servers/terraform/shared/`, `apps/control-center/shared/`, `apps/infra-rollback/shared/` (byte-identical, `tests/test_fd7l_runner_identity_shared.py::test_copies_are_byte_identical`).
- `release_info.py` ×23: one per deployed service/job directory (`apps/*/`, `mcp-servers/*/`; `git ls-files | grep release_info.py`), byte-identical, `tests/test_sat11_release_record.py::test_release_info_copies_are_identical`. `release_manifest.py` ×2: `shared/` and `apps/control-center/shared/`.
- Scheduled job bodies (byte-identical; `tests/test_c10_platform_tf.py::test_c10_copies_are_byte_identical` lists every copy): `shared/{spend_sync,sandbox_sweep,billing_alerts,enforcer_job}.py` → `apps/control-center/shared/` + the job dir (`apps/finops-spend-sync`, `apps/sandbox-sweeper`, `apps/billing-alert-drain`); `shared/day2_job.py` → the three job dirs; the Control Center's `services/{finops_sync,runner_state}.py` → `apps/finops-spend-sync/services/`; `workflow_executions.py` → `apps/sandbox-sweeper/` and `apps/orchestrator-gateway/`.
- `agent_evaluator.py` ×4: `shared/`, `apps/{control-center,orchestrator-gateway}/shared/`, `mcp-servers/terraform/shared/` (byte-identical; `tests/test_judge_level_family_config.py`).
- `build_admission.py` ×3: `shared/`, `apps/control-center/shared/`, `apps/orchestrator-gateway/shared/` (byte-identical; `tests/test_build_admission_queue.py::test_copies_are_byte_identical`).
- `vcs_ledger.py` ×3: `shared/`, `apps/control-center/shared/`, `apps/orchestrator-gateway/shared/` (byte-identical; `tests/test_gha_platform_merge_skip_actions.py::test_ledger_copies_are_byte_identical`).
- `managed_target_seam.py` ×4: `mcp-servers/{agent-builder,kubernetes,gcloud,github}/` (byte-identical; `tests/test_lane14_mcp_helm.py::test_seam_copies_are_identical`).

## Required components
Every service, MCP server, job, scheduler, workflow, agent and golden module is **required**, whether or not it is currently called or working. Never delete, undeploy or recommend removing one; fix it instead. A change in user-visible behavior must be described in plain language in the pull request so a maintainer can approve it.

## Host-platform changes
Changes that need `scripts/apply.sh` (`infra/platform/**`, `infra/modules/workflows/**`, `workflows/**`, host IAM / service accounts) make every operator run a host apply when they upgrade. Prefer a design that ships as service/job deploys. If a change does need `apply.sh`, say so in the pull request and in the CHANGELOG entry's `requires apply.sh: yes` line (see "Release entry convention" in `CHANGELOG.md`).

## Invariants (non-negotiable)
1. **Do No Harm**: a sanitizer/healer must never mutate already-valid HCL/Python. Only heal what fails `ast.parse` / HCL parse / `tofu validate`. Every healer needs a negative test (valid input → unchanged).
2. **No new string-matching heuristics** (substring/regex guessing) to patch symptoms. Prefer deleting the greedy heuristic, fixing the generation contract, or using real parsers/APIs.
3. No hardcoded project IDs, folder IDs, regions, CIDRs, or secrets — use `var.project_id`, `var.region`, IPAM (`shared/ipam.py`).
4. Generated workload IaC lives in `infra/workload/` (singular). No Dockerfiles in generated workloads (Buildpacks).
5. Never prune cross-region secondary GKE clusters; never touch the host project.
6. Multi-service IaC must stay acyclic (no A→B→A `service_uri` references).
7. `tf-applier` / `mcp-terraform-server` containers have no `gcloud`/`kubectl` — use REST via `AuthorizedSession`.
8. **Fail loudly**: a failed step raises a typed error (class + stage), never a fake success/pass/id/URL; warn-and-continue only per `documentation/fail-loudly-policy.md` §2.

## Setup & verification
```bash
python3.12 -m venv .venv && source .venv/bin/activate   # 3.12: wheels available for all deps (3.14 may lack some)
pip install -r apps/control-center/requirements.txt -r apps/orchestrator-gateway/requirements.txt -r mcp-servers/terraform/requirements.txt -r mcp-servers/kubernetes/requirements.txt pytest pytest-asyncio anyio httpx
# re-run after pulling: the eval tests need the gateway's python-hcl2/lark/regex/pyflakes pins (tests/test_eval_product_deps.py)
export TEST_MODE=true PROJECT_ID=mock-stackvend-project GCP_PROJECT=mock-stackvend-project GOOGLE_CLOUD_PROJECT=mock-stackvend-project DEFAULT_REGION=us-central1 COLUMNS=400
pytest tests/test_anti_hallucination_preflight.py tests/test_hcl_utils.py tests/test_iac_env_var_bridge.py   # fast core
# Full suite: run as THREE invocations (both MCP test files are named test_service.py → collection error if combined)
pytest tests/ -rf --tb=no
pytest mcp-servers/terraform/test_service.py
pytest mcp-servers/kubernetes/test_service.py
python3 -m py_compile <changed .py files>
```
- **Only run the test commands listed here.** Tests under `apps/*/test_*.py` are not proven hermetic: with `PROJECT_ID` unset they may pick up Application Default Credentials and reach a real project. Always export `PROJECT_ID=mock-stackvend-project` as above. The root `conftest.py` installs a hermetic guard (no credentials, no network, no cloud clients) and fails any pytest run that constructs a real Firestore client.
- `pytest.ini` already adds `-q`; don't pass `-q` again (it hides the summary line).
- The full suite must pass: all three invocations report **0 failed** before you open a pull request. Don't introduce new failures.

## Known doc drift
- Open until per-service access ships: example 06's form prompt asks for the fulfillment worker with "internal ingress", but in a Public workload every Cloud Run service is public. The prompt is left as it is (it is spec input, and the phrase is deliberately not detected); the compliance stage warns (`ACCESS.INTERNAL_SERVICE_PUBLIC`), and the example's QA line does not claim the worker is shielded.
- Otherwise none known. Add new items here when you find them.

## Working conventions
- See `CONTRIBUTING.md` for the pull-request process. Keep each change scoped to one task.
- Run `/stackvend-red-team-review` on any change to `terraform_engine.py`, `hcl_utils.py`, `preflight_validator.py`, `verifier.py`, or `mcp-servers/terraform/service.py`.
- **Skills**: canonical home is `.agents/skills/` (invoke as `/stackvend-<name>`). Tools that use the `.agents/skills` convention, such as Antigravity, load them directly; others load them through a tool-specific link. If your tool doesn't auto-load them, "running a skill" means reading `.agents/skills/<skill-name>/SKILL.md` and following it exactly.
- **Stay inside the repository when searching** (no `find /`, `find ~`, `grep -r ~`): it is slow and can reach private files. Use `git ls-files | grep` or `find . -name`.
