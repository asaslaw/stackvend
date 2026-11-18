# StackVend Extensibility & Contribution Recipes

This guide describes how to extend the platform: golden modules, validation rules, MCP tool servers and swarm roles. Read [`CONTRIBUTING.md`](../CONTRIBUTING.md) first; its rules (negative tests, no new string-matching heuristics, replicated files, red-team review) apply to every recipe here.

> **Public preview.** These recipes reflect the current code layout, which is changing. Verify names with `git grep` before relying on them, and where this guide disagrees with the code, trust the code.

---

## Recipe 1: Adding a golden module

Golden modules are parameterized OpenTofu/Terraform modules in `infra/modules/`.

1. **Create the module** in `infra/modules/<module-id>/` with `main.tf`, `variables.tf` and `outputs.tf`. Follow the existing modules: use `var.project_id` and `var.region` (no hardcoded values), and keep resource names RFC 1123 compatible (lowercase letters, digits and hyphens, not starting or ending with a hyphen). If you declare `google_compute_subnetwork`, ignore changes to `secondary_ip_range` as the existing networking modules do.
2. **Register catalog metadata** in `BUILTIN_MODULE_METADATA` in `shared/builtin_modules_provider.py` (name, category, description, `is_heavy_stateful`, `timeout_minutes`). The provider reads the module's variables and outputs from the files in `infra/modules/`.
3. **Embed the module's files** in `BUILTIN_MODULE_FILES` in `shared/builtin_modules_payload.py`. Containers on Cloud Run do not have access to `infra/modules/` at runtime, so services read this payload instead.
4. **Register required APIs.** Add every new Google Cloud resource type to `GCP_RESOURCE_TO_API_MAP` in `mcp-servers/terraform/service.py` so that the needed APIs are enabled before `apply`.
5. **Update every replica.** `builtin_modules_payload.py` (and any other shared file you touch) is copied into `apps/control-center/shared/`, `apps/orchestrator-gateway/shared/` and `mcp-servers/terraform/shared/`.
6. **Test.** Add or extend tests in `tests/test_golden_modules_catalog_expansion.py` (or a new test file) and run the commands in the [developer guide](developer-guide.md#3-running-the-tests).

To make the module part of a bundle, add its ID to `modules_included` for a bundle in `shared/builtin_bundles_payload.py` (see [Composite Bundles](composite-bundles.md)). Only `compute-cloudrun` exports `service_uri`; keep multi-service wiring acyclic.

If the change touches `terraform_engine.py`, `hcl_utils.py` or `mcp-servers/terraform/service.py`, a red-team review is required.

---

## Recipe 2: Adding a validation rule

Generated files are judged by the **hallucination stack**: `apps/orchestrator-gateway/developer_agent/validators/`. Each validator reads the assembled tree and returns typed `Diagnostic`s (a code such as `IAC.NAME_INVALID`, the file, the block address, a message and a repair hint). The developer stage runs every registered validator on every iteration (`ValidatorStack`), and the **bounded repair loop** (`developer_agent/repair_loop.py`) sends each blocking finding back to the AI persona that wrote the file, re-assembles and validates again, within the per-run iteration, token and time budget. A validator never writes a file.

**Prefer validators over rewriters.** Do not add a function that rewrites generated text with regular expressions or substring matching, and do not invent values (names, defaults, roles, regions). Decide findings with a real parser (python-hcl2, Python `ast`), real tool output (`tofu validate`) or an exact table. If you believe a deterministic repair is unavoidable, it may only run when the input is invalid (`ast.parse` / HCL parse / `tofu validate` fails), and it needs a negative test.

1. **Write the validator** as a class with an `id`, a `tool` and `validate(ctx) -> List[Diagnostic]`. `ctx` (`validators/base.py` `ValidationContext`) gives you the files and each file's ownership; use `step1._llm_blocks(ctx)` to read only the AI's own root-module blocks (platform renders, vendored modules and the user's `human.tf` are not the AI's to fix). `validators/names.py` (`NameTemplateValidator`) and `validators/platform_facts.py` (`CidrFactValidator`) are small examples.
2. **Register it** in `build_step1_stack` (`validators/step1.py`) with a default mode: `"blocking"` (an error goes to the repair loop) or `"report_only"` (measured only). New rules usually start report-only and become blocking after a false-positive review. Add a row to the table at the top of `step1.py`.
3. **Test both directions** in a file under `tests/`:
   * invalid input produces the exact diagnostic (code, file, block address);
   * **valid input produces no diagnostic**, and the files are unchanged.
4. **Replicas.** `hcl_utils.py` has five copies; if you touch them, see the AGENTS.md "Replicated files" list.
5. **Run** the tests and request a red-team review when you touch a gated file (`terraform_engine.py`, `hcl_utils.py`, `preflight_validator.py`, `verifier.py`, `mcp-servers/terraform/service.py`).

---

## Recipe 3: Adding or extending an MCP tool server

MCP servers live in `mcp-servers/<name>/` and are deployed to Cloud Run with buildpacks (there is no Dockerfile).

1. **Create the package**:
   ```text
   mcp-servers/<name>/
   ├── main.py            # FastAPI app: GET /health, POST /mcp, plus any direct REST endpoints
   ├── service.py         # tool logic
   ├── requirements.txt
   ├── Procfile           # web: uvicorn main:app --host 0.0.0.0 --port $PORT
   └── test_service.py    # hermetic tests; mock all cloud calls
   ```
2. **Implement the MCP endpoint.** Look at `mcp-servers/github/main.py` or `mcp-servers/terraform/main.py` for the pattern: `POST /mcp` accepts a JSON-RPC 2.0 request, answers `tools/list` with tool names and `inputSchema`s, and routes `tools/call` to your service functions.
3. **No CLI binaries.** The containers do not include `gcloud` or `kubectl`; call Google Cloud over REST with an authorized session.
4. **Register the service** in the host Terraform (`infra/platform/main.tf`: the `cloud_run_services` map) and in the `SERVICES` list in `scripts/deploy-services.sh`. Changing host Terraform requires an `apply` of the platform; see the `/stackvend-deploy` skill for the decision tree between `scripts/apply.sh` and `scripts/deploy-services.sh`.
5. **Test.** Note that every `test_service.py` shares a file name, so MCP test files must be run in separate pytest invocations.

---

## Recipe 4: Adding or modifying a swarm role

The developer swarm lives in `apps/orchestrator-gateway/developer_agent/`.

1. **Add the persona** to the `JuniorPersona` enum in `swarm_schemas.py`.
2. **Write the worker prompt** in `juniors/<role>_worker.py` and add it to `LOCAL_PROMPTS_MAP` in `juniors/prompt_registry.py`. (Prompts can also be overridden from the Firestore `prompts` collection.)
3. **Teach the lead developer about the role** by updating its decomposition prompt in `lead_orchestrator.py` (persona list, wave guidance and example), so that it can assign tasks to the new persona.
4. **Wave placement.** Tasks carry a `wave` number (1 to 3). Tasks in the same wave run concurrently and must have disjoint `assigned_files`; later waves receive earlier waves' files through `read_dependencies`.
5. **Test.** Extend `tests/test_developer_swarm.py` to cover fan-out and fan-in with the new persona, including the case where two tasks claim the same file (`ConflictingFileAssignmentError`).
6. **Docs.** Update [Platform Internals](platform-internals.md).
