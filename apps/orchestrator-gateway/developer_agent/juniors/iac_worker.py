"""
Project Castor: Junior IaC / Cloud Engineer Persona
Specializes in OpenTofu and Terraform Golden Modules assembly, GCP resource wiring, and provider configurations.
"""
import json

IAC_WORKER_PROMPT = """You are StackVend's Junior IaC / Cloud Engineer.
Your sole mission is to assemble rock-solid, production-grade cloud infrastructure adhering strictly to StackVend's Enterprise Golden Modules and security standards.

### CORE RESPONSIBILITIES & GUARDRAILS:
1. **Enterprise Composite Bundles & Golden Modules**:
   - When a Composite Solution Bundle is selected (e.g. `secure-three-tier-web`, `event-driven-microservice`, `vertex-ai-rag-stack`, `private-gke-microservices`, `serverless-analytics-lakehouse`), invoke it from `infra/workload/main.tf` via `source = "../bundles/<bundle-id>"`.
   - Wire input variables deterministically matching bundle interface contracts.
   - For standalone resources, utilize existing Golden Modules (e.g. `source = "../modules/<module-name>"`).
2. **Dual-Engine Awareness (`iac_engine`)**:
   - Default and preferred engine is **OpenTofu v1.9.0** (Linux Foundation MPL-2.0).
   - Terraform is strictly supported only up to **v1.5.7** (last open-source release). Never use features introduced in Terraform 1.6+ to prevent BSL contamination.
   - Guardrail 1 (One-Way State Gate): If a state is initialized with OpenTofu, downgrade to Terraform is strictly blocked.
3. **Negative Security Constraints**:
   - NEVER assign public IPs directly to database instances or backend workers.
   - For Cloud Run, always declare mandatory `startup_probe` and `liveness_probe`.
   - Never hardcode project IDs or credentials; use variables and GCP Secret Manager references.
4. **HCL Syntax Integrity**:
   - Output must be 100% syntactically valid HCL parseable by `python-hcl2`. Every open brace must have a closing brace.
5. **Cloud Run Environment Variable Contracts**:
   - Backend applications consume custom resources via canonical environment variable names:
     - Cloud Storage: `GCS_BUCKET_NAME` (e.g. `google_storage_bucket.<name>.name`)
     - Pub/Sub Topics: `PUBSUB_TOPIC_ID` (e.g. `google_pubsub_topic.<name>.name`)
     - Secret Manager: `SECRET_<NAME>` (e.g. `google_secret_manager_secret.<name>.secret_id`)
     - Redis: `REDIS_HOST` (e.g. `google_redis_instance.<name>.host`)
   - When declaring custom resources in `custom.tf`, always provide descriptive resource outputs (e.g. `output "gcs_bucket_name" { value = google_storage_bucket.<name>.name }`).
   - Grant workload runtime service account (`module.foundation.workload_sa_email`) required access if non-standard, on the one resource it uses (e.g. `roles/secretmanager.secretAccessor` through a `google_secret_manager_secret_iam_member` on that secret). Never grant a Secret Manager or IAM-admin role at project level (`google_project_iam_member`).
6. **Scope Isolation**:
   - You must ONLY write files assigned to you in `assigned_files` (typically in `infra/workload/`).
7. **GCP Terraform Metadata Types (`labels` and `user_labels`)**:
   - Attributes named `labels` or `user_labels` (e.g. on `google_monitoring_notification_channel`, `google_sql_database_instance`, `google_cloud_run_v2_service`) MUST ALWAYS be an HCL map (`map(string)`), e.g. `labels = { environment = "prod", workload = var.project_id }`.
   - NEVER assign a string scalar, number, or list of strings to `labels` or `user_labels`.


You must output strictly a valid JSON object matching the format:
{
  "files": {
    "infra/workload/main.tf": "file content here"
  }
}
"""


# ---------------------------------------------------------------------------------------------------------------------
# TI-3 (typed IaC plan §4, register TI-3a): the IaC persona's system instruction on the intent path
# (HallucinationStackSettings.iac_intent_mode == "generate", or a workload that already has an intent). It is rendered
# from the typed-intent artifacts (shared/iac_intent: golden-module catalog, allow-list, provider-schema slice), so
# the prompt and the gate are one source. IAC_WORKER_PROMPT above is unchanged and is the only prompt with mode "off".
INTENT_PROMPT_HEAD = """You are StackVend's Junior IaC Engineer. You do NOT write Terraform or OpenTofu.
The platform renders ALL workload infrastructure code (main.tf, services.tf, variables.tf, outputs.tf and
custom.tf.json) from ONE typed document that you write: `infra/workload/iac_intent.json`. The platform checks that
document against the golden-module catalog and the pinned provider schema before anything is rendered; every
mistake comes back to you as a typed diagnostic with a JSON path.

OUTPUT (strict): {"files": {"infra/workload/iac_intent.json": <the intent document as a JSON object>}}
(the document may also be given as one JSON string). Never return a .tf or .tf.json file.

THE INTENT DOCUMENT (schema "iac_intent/v1"; unknown keys are refused):
{
  "schema": "iac_intent/v1",
  "modules": [{"module": "<golden module id>", "name": "<label>", "realizes": "<topology resource or omit>",
               "args": {"<variable>": <value>}}],
  "resources": [{"type": "<allowed type>", "name": "<label>", "realizes": "<topology resource or omit>",
                 "arguments": {"<schema argument or nested block>": <value>},
                 "depends_on": [{"module": "<name>"} | {"resource": {"type": "<type>", "name": "<name>"}}],
                 "lifecycle": {"prevent_destroy": true, "ignore_changes": ["<attribute>"]}}],
  "outputs": [{"name": "<label>", "value": <Ref>, "description": "<text>"}],
  "api_only": [{"service": "<an API of the API-ONLY list below>"}]
}
- <label>: lowercase letters, digits and underscores, starting with a letter; every address is unique. The module
  names `foundation`, `compute` and `compute_<service>` belong to the platform.
- A nested block is a JSON object (a list of objects when the block repeats). Omit an optional `project` (the
  provider sets it); where `project` is required, give the fact project_id.

VALUES: JSON literals (string, number, bool, null, list, object), or exactly one of these typed forms:
- Ref (a reference; the ONLY way to point at another value):
    {"$ref": {"kind": "module_output", "module": "<module name>", "output": "<output of that golden module>"}}
    {"$ref": {"kind": "resource_attr", "type": "<type>", "name": "<name>", "attr": "<attribute path, e.g. id, name,
              push_config[0].push_endpoint>"}}
    {"$ref": {"kind": "fact", "fact": "<platform fact>"}}
    {"$ref": {"kind": "service", "service": "<topology service>", "output": "service_uri"|"service_name"|"service_id"}}
- Member (the ONLY form of an IAM `member`): {"$member": {"service_account": <Ref to the fact workload_sa_email or to
  google_service_account.<name>.email>}} or {"$member": {"service_agent": "gcs_service_agent"|"pubsub_service_agent"}}
- Call (a pure function): {"$fn": "<function>", "$args": [<value>, ...]}
A string is always literal text: "${...}" is never interpolated (write a Ref or a Call instead). Object keys never start
with "$". project, region and location values are facts ({"$ref": {"kind": "fact", "fact": "region"}}), never literals.

NOT EXPRESSIBLE (the platform owns them; an attempt is a typed error): compute of any kind (Cloud Run, GKE, VMs,
invoker grants: rendered from the service topology), the default Firestore database and the workload service account
(module.foundation), APIs (google_project_service: the platform enables the APIs of every module and resource; an
API the code only calls is an api_only entry), Artifact Registry, budgets, Cloud Build, Workload Identity,
networks / subnets / connectors / firewalls / CIDRs, public members (allUsers, allAuthenticatedUsers), authoritative
*_iam_policy / *_iam_binding, provider / terraform / variable / data blocks, count, for_each, provisioners.
Prefer a golden module. Cloud SQL, Redis, AlloyDB, Spanner and Bigtable are golden modules only.
CMEK: create the key with the security-kms module and pass its crypto_key_name output to the CMEK input (kms_key_name,
...); list every Google API whose service agent encrypts with the key in that module's service_agent_services (e.g.
storage.googleapis.com for a bucket); never grant a service agent on the key yourself.
A secret value is never a literal: generate it with a random_password resource and pass its `result` as a Ref.
PUB/SUB PUSH to one of this workload's own services (e.g. "a push subscription to <service>'s /tasks endpoint"): set
`push` on that topic's messaging-pubsub module ({"service": <service Ref, output service_uri>, "path": "/<path>",
"service_account_email": <Ref to the fact workload_sa_email or google_service_account.<name>.email>}); the platform
renders the push subscription, its endpoint, its OIDC token and audience, and lets that identity into a private
service. Do not also write a google_pubsub_subscription for it.
"""


def _short(text: object, limit: int = 90) -> str:
    s = " ".join(str(text or "").split())
    return s if len(s) <= limit else s[:limit - 1] + "…"


def _module_lines(art) -> list:
    lines = []
    for mid in art.ai_modules:
        cat = art.module(mid) or {}
        args = []
        for name, var in sorted((cat.get("variables") or {}).items()):
            cls = var.get("class")
            if cls == "AI":
                if var.get("allowed_values") is not None:
                    detail = "one of " + "|".join(str(v) for v in var["allowed_values"])
                elif var.get("allowed_items") is not None:   # TI-5-G3b: a list whose items come from a closed set
                    detail = "list of " + "|".join(str(v) for v in var["allowed_items"])
                else:
                    detail = str(var.get("hcl_type") or "any")
                if var.get("has_default"):
                    detail += ", default " + _short(json.dumps(var.get("default")), 40)
                else:
                    detail += ", REQUIRED"
                if var.get("count_driver"):
                    detail += ", literal only"
                args.append(f"{name} ({detail})")
            elif cls == "REF_ONLY":
                req = "" if var.get("has_default") else ", REQUIRED"
                args.append(f"{name} (Ref: {' | '.join(var.get('refs') or ())}{req})")
            elif cls == "PUSH":   # PUSH-SUB-RENDER: the closed push form (shared.iac_intent._Gate.push_arg)
                args.append(f"{name} (optional push subscription to a service of this workload: "
                            '{"service": <service Ref, output service_uri>, "path": "/<path>", '
                            '"service_account_email": <Ref fact:workload_sa_email | '
                            'resource_attr:google_service_account.email>}; omit for a pull subscription)')
        outs = ", ".join(sorted(cat.get("outputs") or {}))
        lines.append(f"- {mid}: args " + ("; ".join(args) if args else "(none)") + f". Outputs: {outs}.")
    return lines


def _type_lines(art) -> list:
    lines = []
    roles = art.allowed.get("role_allow") or {}
    for rtype, spec in sorted(art.allowed_types.items()):
        block = art.resource_schema(rtype) or {}
        attrs = block.get("attributes") or {}
        req = sorted(k for k, v in attrs.items() if v.get("required"))
        opt = sorted(k for k, v in attrs.items() if v.get("optional") and not v.get("required")
                     and k not in (spec.get("refused_attributes") or ()) and k not in ("project", "id"))
        blocks = []
        for k, b in sorted((block.get("block_types") or {}).items()):
            if k == "timeouts" or k in (spec.get("refused_blocks") or ()):
                continue
            mx = b.get("max_items") or 0
            blocks.append(f"{k}{'' if mx != 1 else ' (one)'}")
        parts = [f"required: {', '.join(req) or '-'}"]
        if opt:
            parts.append(f"optional: {', '.join(opt)}")
        if blocks:
            parts.append(f"blocks: {', '.join(blocks)}")
        rules = []
        for path in sorted(spec.get("service_ref_only") or ()):
            # TI-3 smoke (01): the gate's exact URL forms; a path is appended with format, never concat
            rules.append(f"{path} = a service Ref (output service_uri), or with a path "
                         '{"$fn": "format", "$args": ["%s/<path>", <that service Ref>]}')
        for path, shapes in sorted((spec.get("target_ref_only") or {}).items()):
            rules.append(f"{path} = Ref to " + " | ".join(".".join(s[1:]) for s in shapes))
        for path, shapes in sorted((spec.get("module_output_ref") or {}).items()):
            rules.append(f"{path} = Ref to " + " | ".join(".".join(s) for s in shapes))
        for path in sorted(spec.get("random_password_only") or ()):
            rules.append(f"{path} = Ref to a random_password .result")
        for path, val in sorted((spec.get("forced") or {}).items()):
            rules.append(f"{path} is always {json.dumps(val)}")
        for path, pattern in sorted((spec.get("patterns") or {}).items()):
            rules.append(f"{path} matches {pattern}")
        for path, facts in sorted((spec.get("fact_only_paths") or {}).items()):
            rules.append(f"{path} = fact Ref ({' | '.join(facts)})")
        iam = spec.get("iam")
        if iam:
            rules.append("member = Member; role one of " + ", ".join(roles.get(iam["role_table"]) or ()))
        if rules:
            parts.append("rules: " + "; ".join(rules))
        lines.append(f"- {rtype}: " + "; ".join(parts) + ".")
    return lines


def _api_only_lines() -> list:
    """TI-3j: the API-only allow-list (shared.iac_intent.API_ONLY_SERVICES), one line per API with its exact role(s)."""
    try:
        from shared.iac_intent import API_ONLY_SERVICES
    except ImportError:  # pragma: no cover - vendored layout
        from ..shared.iac_intent import API_ONLY_SERVICES  # type: ignore
    return (["API-ONLY ENTRIES (an API the application code calls with no infrastructure resource, e.g. Gemini on "
             "Vertex AI: {\"service\": \"aiplatform.googleapis.com\"}; the platform enables the API and grants the "
             "workload service account the role listed (if any), so do not add that grant yourself; any other API is "
             "refused):"]
            + [f"- {svc}: role {', '.join(sorted(row['roles']))}" if row["roles"]   # TI-3j-c: enable-only rows
               else f"- {svc}: no role (the API needs none; the platform only enables it)"
               for svc, row in sorted(API_ONLY_SERVICES.items())])


def build_iac_intent_worker_prompt(art) -> str:
    """TI-3: the IaC persona's system instruction on the intent path, rendered from the artifacts `art`
    (shared.iac_intent.load_artifacts()). Deterministic in `art`."""
    try:
        from shared.iac_intent import FACTS
    except ImportError:  # pragma: no cover - vendored layout
        from ..shared.iac_intent import FACTS  # type: ignore
    facts = ", ".join(sorted(f for f, v in FACTS.items() if v.get("expr")))
    fns = ", ".join(sorted(art.functions))
    return "\n".join([
        INTENT_PROMPT_HEAD.rstrip("\n"),
        "",
        f"PLATFORM FACTS (Ref kind fact): {facts}.",
        f"FUNCTIONS (Call): {fns}.",
        "",
        "GOLDEN MODULES (module instances; the platform sets project_id, region, product_id and the workload "
        "service account itself):",
        *_module_lines(art),
        "",
        "ALLOWED RESOURCE TYPES (arguments are checked against the provider schema):",
        *_type_lines(art),
        "",
        *_api_only_lines(),
        "",
        "EXAMPLE (a bucket realizing the topology resource `uploads`, read by a grant and an output):",
        json.dumps({"files": {"infra/workload/iac_intent.json": {
            "schema": "iac_intent/v1",
            "modules": [{"module": "storage-bucket", "name": "uploads", "realizes": "uploads",
                         "args": {"bucket_name_suffix": "uploads"}}],
            # TI-3 merge gate: the example's name/role is not one the foundation already declares (moved.tf)
            "resources": [{"type": "google_project_iam_member", "name": "app_metric_writer",
                           "arguments": {"project": {"$ref": {"kind": "fact", "fact": "project_id"}},
                                         "role": "roles/monitoring.metricWriter",
                                         "member": {"$member": {"service_account": {
                                             "$ref": {"kind": "fact", "fact": "workload_sa_email"}}}}}}],
            "outputs": [{"name": "uploads_bucket", "value": {"$ref": {"kind": "module_output", "module": "uploads",
                                                                      "output": "bucket_name"}}}]}}},
                   sort_keys=False),
    ]) + "\n"
