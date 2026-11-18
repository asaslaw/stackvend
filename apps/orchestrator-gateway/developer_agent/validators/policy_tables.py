"""Exact policy tables of the interim HCL deny/ownership validator V2a (Step 1; lane 15 takes them over at 15a with the
same codes). Every entry is an exact resource type, role or member string; nothing is matched by substring.

Sources: lane 8B plan §3 V2a (rev 3); integration findings I-22 (foundation classification), Q-S2/Q-S3 (owner 10-12).
"""
from __future__ import annotations

# POLICY.FORBIDDEN_RESOURCE_TYPE: resources the AI may never declare (platform/security owned, or authoritative IAM).
FORBIDDEN_RESOURCE_TYPES = frozenset({
    "google_iam_workload_identity_pool",
    "google_iam_workload_identity_pool_provider",
    "google_identity_platform_config",
    "google_identity_platform_default_supported_idp_config",
    "google_billing_budget",
    "google_cloudbuild_trigger",
    "google_cloudbuildv2_connection",
    "google_cloudbuildv2_repository",
    "google_project_iam_audit_config",
    "google_service_account_key",
})

# FD-7L Phase 2b (plan 2.5 last paragraph): the reserved names of the per-workload runner identity, refused here like
# FORBIDDEN_RESOURCE_TYPES (same code, POLICY.FORBIDDEN_RESOURCE_TYPE) and at apply by the terraform server
# (POLICY.PLATFORM_IDENTITY_TOUCHED; parity pinned by tests/test_fd7l_2b_content_policy.py). Kept apart from
# FORBIDDEN_RESOURCE_TYPES, whose set is pinned equal to the typed-IaC catalog's "forbidden" list (neither type is in
# that catalog's allowed types, so the typed path refuses them already).
PLATFORM_IDENTITY_FORBIDDEN_TYPES = frozenset({"google_iam_deny_policy", "google_project_iam_member_remove"})
RESERVED_SERVICE_ACCOUNT_IDS = frozenset({"stackvend-deployer"})   # = shared/runner_identity.DEPLOYER_ACCOUNT_ID

# Authoritative IAM resources (replace every other grant on the resource) are forbidden by the provider's own type
# naming: google_*_iam_policy / google_*_iam_binding (exact suffix of the resource type name, lane 8B §3 V2a).
AUTHORITATIVE_IAM_SUFFIXES = ("_iam_policy", "_iam_binding")

# POLICY.PRIVILEGED_ROLE on any IAM resource type (exact role strings).
PRIVILEGED_ROLES = frozenset({
    "roles/owner", "roles/editor", "roles/iam.securityAdmin", "roles/iam.serviceAccountAdmin",
    "roles/iam.serviceAccountTokenCreator", "roles/resourcemanager.projectIamAdmin",
    "roles/resourcemanager.folderAdmin", "roles/resourcemanager.organizationAdmin", "roles/run.admin",
    "roles/artifactregistry.admin", "roles/cloudbuild.builds.editor",
})
# Blocking at PROJECT level, report-only when granted on one service account (Q-S3, register HS-59).
IMPERSONATION_ROLES = frozenset({"roles/iam.serviceAccountUser", "roles/iam.workloadIdentityUser"})
PROJECT_LEVEL_IAM_TYPES = frozenset({"google_project_iam_member", "google_project_iam_binding",
                                     "google_project_iam_policy"})
SA_SCOPED_IAM_TYPES = frozenset({"google_service_account_iam_member", "google_service_account_iam_binding",
                                 "google_service_account_iam_policy"})
# POLICY.PROJECT_WIDE_GRANT (OVERBROAD-SECRET-GRANT, owner 11-14): project-level secret and IAM-admin roles the AI may
# never grant (one table, shared with the typed-intent gate's IAC.PROJECT_WIDE_GRANT: shared/iac_intent.py). A role that
# is also in PRIVILEGED_ROLES keeps its POLICY.PRIVILEGED_ROLE finding alone (never two codes for one grant).
try:
    from shared.iac_intent import PROJECT_WIDE_DENIED_ROLES, project_wide_grant_hint  # noqa: F401
except ImportError:  # pragma: no cover
    from ...shared.iac_intent import PROJECT_WIDE_DENIED_ROLES, project_wide_grant_hint  # type: ignore  # noqa: F401
PROJECT_WIDE_GRANT_POLICY_CODE = "POLICY.PROJECT_WIDE_GRANT"

# POLICY.PUBLIC_MEMBER: exact member values on any *_iam_member / *_iam_binding / *_iam_policy resource.
PUBLIC_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})
IAM_TYPE_SUFFIXES = ("_iam_member", "_iam_binding", "_iam_policy")   # Terraform google provider naming convention

# Workload-foundation classification (I-22): every resource type declared in
# infra/modules/workload-foundation/base/*.tf has exactly one class; tests/test_step1_s1b_validators.py parses the
# module and fails on an unclassified or stale entry.
FOUNDATION_CLASSIFICATION = {
    "google_project_service": "PLATFORM_OWNED",              # APIs come from the platform's additional_apis
    "google_artifact_registry_repository": "PLATFORM_OWNED",
    "google_firestore_database": "PLATFORM_OWNED_IF_DEFAULT",  # only name = "(default)"; named databases allowed
    "google_iam_workload_identity_pool": "FORBIDDEN",
    "google_iam_workload_identity_pool_provider": "FORBIDDEN",
    "google_project_iam_audit_config": "FORBIDDEN",            # lane 14 PR-0b: foundation, regulated profiles only
    "google_project_iam_member": "SHARED",
    "google_service_account": "SHARED",
    "google_service_account_iam_member": "SHARED",
}
PLATFORM_OWNED_TYPES = frozenset(t for t, c in FOUNDATION_CLASSIFICATION.items() if c == "PLATFORM_OWNED")
DEFAULT_FIRESTORE_NAME = "(default)"
# Types whose instances the workload foundation declares (PLATFORM_OWNED and PLATFORM_OWNED_IF_DEFAULT). A reference to
# an UNDECLARED address of one of these types gets HINT_PLATFORM_OWNED_REFERENCE in repair (S2-B B4, replaces HC-05's
# Firestore rewrite to "(default)" / module.foundation).
FOUNDATION_DECLARED_TYPES = frozenset(t for t, c in FOUNDATION_CLASSIFICATION.items() if c.startswith("PLATFORM_OWNED"))

# POLICY.PLATFORM_OWNED_BINDING (S2-B B4, HS-19b): exact (resource type, role) grants that Google / the platform own.
# roles/iap.serviceAgent is the IAP service agent's Google-managed role (granted by Google when iap.googleapis.com is
# enabled; the foundation's base_apis enable it); replaces HC-05's regex strip of such grants from custom.tf.
PLATFORM_OWNED_BINDINGS = frozenset({("google_project_iam_member", "roles/iap.serviceAgent")})

# POLICY.ORG_CONSTRAINT (V2e, S2-B B6, HS-62; replaces HD-15's org-policy regexes + the HC-04 strip/inject healer).
# The constraints are platform policy asserted by the compliance contract (compliance_agent/handler.py, shared/
# builtin_prompts.py); no in-repo Terraform sets them, so V2e reports "platform policy (compliance contract)" and does
# not claim the folder enforces them. Exact rules (RT F9):
ORG_CONSTRAINT_VM_EXTERNAL_IP = "constraints/compute.vmExternalIpAccess"
# The resource types whose `network_interface` block gives a VM its external IP through `access_config`.
VM_EXTERNAL_IP_RESOURCE_TYPES = frozenset({"google_compute_instance", "google_compute_instance_template",
                                           "google_compute_region_instance_template"})
ORG_CONSTRAINT_BUCKET_UBLA = "constraints/storage.uniformBucketLevelAccess"
ORG_CONSTRAINT_OS_LOGIN = "constraints/compute.requireOsLogin"
OS_LOGIN_METADATA_KEY = "enable-oslogin"
OS_LOGIN_DISABLED_VALUES = ("FALSE", "false", False)          # exact metadata values that turn OS Login off
UBLA_TRUE_VALUES = (True, "true")                             # literal true (bool, or the string OpenTofu converts)
HINT_ORG_CONSTRAINT = {
    ORG_CONSTRAINT_VM_EXTERNAL_IP: (
        "Platform policy (compliance contract) forbids external IPs on VMs: remove the access_config block from "
        "network_interface. Reach the VM through IAP TCP forwarding (the platform's VPC/bastion modules allow "
        "35.235.240.0/20 on port 22) and give it outbound access through Cloud NAT."),
    ORG_CONSTRAINT_BUCKET_UBLA: (
        "Platform policy (compliance contract) requires uniform bucket-level access: set "
        "uniform_bucket_level_access = true (a literal) on every google_storage_bucket and grant access with "
        "google_storage_bucket_iam_member instead of ACLs."),
    ORG_CONSTRAINT_OS_LOGIN: (
        "Platform policy (compliance contract) requires OS Login: remove enable-oslogin = \"FALSE\" from the "
        "instance metadata (or set it to \"TRUE\")."),
}

# Hints (platform facts, shown to the repairing persona).
HINT_FORBIDDEN = ("This resource type is owned by the platform (or grants authoritative IAM) and may not be declared "
                  "in workload IaC. Remove it; use *_iam_member grants for least-privilege access.")
# POLICY.PRIVILEGED_ROLE hints name the compliant alternative per role class (Step 1 R3c-fix RT fix 3; facts from
# PRIVILEGED_ROLES / IMPERSONATION_ROLES / PROJECT_LEVEL_IAM_TYPES / SA_SCOPED_IAM_TYPES above). "{role}" is the role.
HINT_PRIVILEGED = ("No narrower predefined role exists for {role} in workload IaC: delete this block (and every "
                   "reference to it); privileged roles are never granted by workload IaC.")
HINT_PRIVILEGED_IMPERSONATION_PROJECT = ("Grant {role} on the one service account it must act as "
                                         "(google_service_account_iam_member with service_account_id), not at "
                                         "project level; project-level {role} is never granted by workload IaC.")
HINT_IMPERSONATION_SA_SCOPED = ("{role} on one service account is the compliant scope (report-only); keep it only if "
                                "the workload must act as that account.")
HINT_PUBLIC = ("Public access is configured only by the platform's compute module (allow_unauthenticated). Remove "
               "the allUsers/allAuthenticatedUsers grant or use a specific principal.")
# S2-C C0 (register HS-63): the API sentence is true for the code that runs -- the gateway and the deploy step both
# compute the APIs from shared/api_requirements.json, an exact resource-type / golden-module table; a type the table
# does not know is reported (IAC.API_UNKNOWN_FOR_TYPE), never guessed (tests/test_step2c_api_requirements.py).
HINT_PLATFORM_OWNED = ("The workload foundation already declares this resource. Delete this block and every reference to "
                       "it (depends_on entries, outputs that re-export it): the platform enables the APIs required by "
                       "the resource types and golden modules you declare (from an exact table; a type it does not "
                       "know is reported, not guessed), and the foundation's registry/database are available as "
                       "module.foundation outputs (e.g. module.foundation.docker_repo_id, "
                       "module.foundation.database_name).")
HINT_API_UNKNOWN_FOR_TYPE = ("The platform's API table has no row for this type, so its API is not enabled "
                             "automatically. Report-only: the table is extended by PR (shared/api_requirements.json).")
HINT_PLATFORM_OWNED_REFERENCE = (
    "This address is not declared, and resources of this type belong to the workload foundation (module.foundation): "
    "use its outputs instead (module.foundation.database_name for the (default) Firestore database, "
    "module.foundation.docker_repo_id for the Artifact Registry repository) and, for ordering, depend on "
    "module.foundation instead of a google_project_service block. If you meant a named (non-default) Firestore "
    "database, declare the google_firestore_database resource instead.")   # bcd RT F5 (no recorded prompt has it)
HINT_PLATFORM_OWNED_BINDING = (
    "roles/iap.serviceAgent is a Google-managed service-agent role: Google grants it to the IAP service agent when "
    "iap.googleapis.com is enabled (the workload foundation enables that API), and the compute-cloudrun module grants "
    "that agent roles/run.invoker on the service when Direct IAP is on. Remove this grant: a workload copy of it "
    "revokes Google's own grant when it is destroyed.")
# IAC.IAM_LITERAL_SECRET_ID (V2i, S2-B B4): replaces HC-05's unconditional secret_id literal -> reference rewrite.
HINT_IAM_LITERAL_SECRET_ID = (
    "This grant names a secret that this configuration declares by repeating its literal secret_id, so OpenTofu does "
    "not know the grant depends on the secret and may create it first (404). Reference the secret resource instead: "
    "secret_id = google_secret_manager_secret.{name}.secret_id")
HINT_PROVIDER = "Use only these providers (they are the ones the platform can validate and apply): {providers}."
# HCL.PARSE_ERROR on an LLM-owned root file (V1a-llm, Step 1 code RT F11).
HINT_UNCHECKABLE = ("The platform parses workload Terraform with python-hcl2 to run its policy checks, and it could not "
                    "parse this file. Fix the syntax error named in the detail; if the file is valid OpenTofu, rewrite "
                    "the construct the parser rejects in plain, standard HCL (one attribute or block per line).")
# PATH.UNSAFE_KEY / GATE.UNSAFE_PATH_KEY on a file key the LLM wrote (repair = rename, Step 1 code RT F12).
HINT_UNSAFE_KEY = ("This file key is not a safe relative path. Return the same file under a new key that is relative "
                   "(no leading '/', no drive letter), uses '/' separators (no backslash), has no empty, '.' or '..' "
                   "components and no '.git' component; do not return the old key.")

# HCL content policy (V2j, validators/content_policy.py, FD-4AW): generated Terraform may not execute code.
BUILTIN_PROVIDERS = frozenset({"terraform"})   # OpenTofu's built-in provider: terraform_data, terraform_remote_state
EXTERNAL_DATA_SOURCE_TYPE = "external"          # data "external": runs an arbitrary program on the apply runner
HINT_PROVISIONER_FORBIDDEN = (
    "Remove the provisioner block: workload Terraform may not run commands on the platform's apply runner or on the "
    "hosts it creates. Build and start-up steps belong in the app (its Procfile; the platform builds it with "
    "Buildpacks) or the deploy pipeline, not in Terraform.")
HINT_CONNECTION_FORBIDDEN = (
    "Remove the connection block: workload Terraform may not open SSH/WinRM sessions (connection blocks only serve "
    "provisioners, which are forbidden). Configure a VM through its own resource arguments instead.")
HINT_EXTERNAL_DATA_FORBIDDEN = (
    "Remove the data \"external\" block: it runs an arbitrary program on the platform's apply runner. Compute the value "
    "with Terraform expressions and functions, an input variable, or a data source of an available provider.")
HINT_IMPLICIT_PROVIDER = (
    "This block belongs to provider \"{provider}\" (Terraform takes it from the provider meta-argument, else from the "
    "type name's prefix before the first '_'), which the platform does not offer. Use only resources and data sources "
    "of these providers: {providers}.")
# FD-4AW-a (Fable RT F1/F2/F3/F4/F5, owner 10-20).
REMOTE_STATE_DATA_SOURCE_TYPE = "terraform_remote_state"   # reads any state/URL the apply runner's identity reaches
# Exact provider sources of the validate service's pinned set (mcp-servers/terraform/validate_service.py
# VALIDATE_PROVIDERS; tests/test_fd4aw_hcl_content_policy.py pins the key set to it).
PLATFORM_PROVIDER_SOURCES = {
    "google": "hashicorp/google",
    "google-beta": "hashicorp/google-beta",
    "kubernetes": "hashicorp/kubernetes",
    "random": "hashicorp/random",
}
# FD-4AW-r R2: the exact fully-qualified forms of the same addresses are accepted too, for the two registry hostnames
# the validate service's mirror serves (validate_service.py REGISTRIES; pinned by a test).
PLATFORM_PROVIDER_REGISTRIES = ("registry.opentofu.org", "registry.terraform.io")
PLATFORM_PROVIDER_SOURCE_FORMS = {
    local: frozenset({source, *(f"{host}/{source}" for host in PLATFORM_PROVIDER_REGISTRIES)})
    for local, source in PLATFORM_PROVIDER_SOURCES.items()
}
HINT_REMOTE_STATE_FORBIDDEN = (
    "Remove the data \"terraform_remote_state\" block: workload Terraform may not read other Terraform states. Take "
    "the value from an input variable, a module.foundation output or a data source of an available provider.")
HINT_MODULE_SOURCE_NOT_LOCAL = (
    "Module sources must be the platform's local golden modules: use source = \"../modules/<golden module>\" (a "
    "literal path, no version argument). Remote, registry, git and archive sources are never fetched.")
# FD-4CB-b: POLICY.MODULE_SOURCE_NOT_LOCAL hint when the source is exactly ../modules/<m> for a host-platform module the
# developer stage never vendors (shared/host_platform_modules.py NOT_VENDORED_TO_WORKLOADS; keys pinned equal by
# tests/test_fd4cb_b_host_platform_modules.py).
HINT_HOST_PLATFORM_MODULE = {
    "workflows": (
        "infra/modules/workflows is the StackVend host platform's own orchestrator / SRE workflows module (it reads "
        "files that exist only in the StackVend repository) and is not offered to workloads. For a Cloud Workflows "
        "workflow use the workload golden module `workflows-dag` (source = \"../modules/workflows-dag\"); otherwise "
        "remove this module block."),
}
HINT_PROVIDER_SOURCE_MISMATCH = (
    "Declare each provider with the platform's own source (or omit required_providers): {sources}. A local name "
    "mapped to another source is not available to the platform.")
# The two codes below are repaired by a rename (repair_loop.RENAME_CODES): the file comes back under a new key.
HINT_JSON_IAC_NOT_CHECKABLE = (
    "Write workload Terraform as HCL, not Terraform JSON: the platform's policy checks read HCL. Return the same "
    "declarations as HCL under a new root key ending in .tf (for example infra/workload/custom_<topic>.tf) and do "
    "not return this .tf.json key.")
HINT_USER_OWNED_NAME = (
    "This file name is reserved for the human architect (human.tf, human_override.tf and the Terraform override "
    "files override.tf / *_override.tf are never written by the AI). Return this file's content under a new root key "
    "such as infra/workload/custom_<topic>.tf (a plain file, not an override file) and do not return the old key.")
# FD-4AQ W4 (register AQ-4): validators/access_idp.py (V2l).
HINT_IDP_CONFIG = (
    "Google sign-in (the Identity Platform configuration and its identity providers) is set up by the platform, "
    "never by workload Terraform, and a private workload gets no sign-in module (workload_auth). Delete this block "
    "and every reference to it.")
HINT_IDP_SECRET_READER = (
    "This role can read the shared Google sign-in client secret, which workload principals may not read. Grant a "
    "narrower role that does not include firebaseauth.configs.get, or delete this block.")
# FD-4CX-b: V2l, POLICY.PUBLIC_PRINCIPAL_IN_MODULE_CALL (a private workload; sent only with that finding).
HINT_PUBLIC_PRINCIPAL_IN_MODULE_CALL = (
    "This workload is private: only the principals in its access settings may reach it, and the platform grants "
    "them. Remove allUsers / allAuthenticatedUsers from this module argument (keep only specific principals such as "
    "serviceAccount:, group: or user: members, or leave the argument out). Do not make the module public another "
    "way.")
HINT_UNCHECKABLE_VARIABLES_FILE = (
    "OpenTofu loads this variables file by itself, but it does not parse, so the platform cannot check the values it "
    "sets. The AI may not write such a file at all (POLICY.TFVARS_NOT_ALLOWED): return it with empty content ({} for "
    "a .json file) and give each variable its value as the default of its variable block instead.")
# AI-TFVARS-REFUSED / AI-TOFU-REFUSED (owner 10-29): validators/iac_file_kinds.py (V2n). The .tofu code is repaired by
# a rename (repair_loop.RENAME_ONLY_CODES); a variables file by returning it with no variable in it.
HINT_TFVARS_NOT_ALLOWED = (
    "OpenTofu loads this variables file by itself, and the platform owns the workload's root variable values (it "
    "renders infra/workload/terraform.tfvars and, at deploy, the access settings), so the AI may not write one: a "
    "value here could override the platform's access or secret variables. Give each variable its value as the "
    "default of its variable block in your own .tf file, or pass the value directly in the module call (with the "
    "typed IaC intent: in the intent entry's arguments). Return this file with empty content ({} for a .json file).")
HINT_TOFU_FILE_NOT_ALLOWED = (
    "OpenTofu loads .tofu / .tofu.json files (a .tofu file replaces the .tf file of the same name), but the "
    "platform's checks read only .tf files, so the AI may not write one. Return this file's declarations as HCL under "
    "a new key ending in .tf in the same directory that is not already in the repository (for example custom_<topic>.tf "
    "beside it), and do not return this key.")
HINT_TOFU_FILE_NOT_ALLOWED_INTENT = (
    "OpenTofu loads .tofu / .tofu.json files (a .tofu file replaces the .tf file of the same name), but with the typed "
    "IaC intent the platform renders all Terraform and the AI writes none. Return this file under a new key ending in "
    ".tf in the same directory that is not already in the repository, with empty content, and do not return this key. "
    "The declarations of this file are not kept.")
# SAT-02 / FD4BD-Q4 (owner OQ-6, 10-31): the generated variables.tf declares the platform secrets sensitive
# (terraform_engine.PLATFORM_SECRET_VARIABLES), so OpenTofu's own validate refuses a root output whose value is, or is
# derived from, one of them ("Output refers to sensitive values" = tofu_diagnostics.tf_code of that summary). The
# repair loop gives this hint to the AI file's author and accepts deleting the output (repair_loop.REMOVAL_CODES); the
# same finding in a person's file is BROWNFIELD_CONFLICT (ownership routing). No text scan of output expressions.
SENSITIVE_OUTPUT_CODE = "TF.OUTPUT_REFERS_TO_SENSITIVE_VALUES"
HINT_SENSITIVE_OUTPUT = (
    "OpenTofu refuses this root output because its value is, or is derived from, a sensitive value. The platform's "
    "secrets var.oauth_client_secret (the Google sign-in client secret) and var.firebase_api_key (the Firebase browser "
    "key) are declared sensitive, and workload outputs must never expose them. Delete this output block. Only if the "
    "workload really needs this output and it carries neither of those two values, add sensitive = true to it "
    "instead. Never wrap the value in nonsensitive() to get around this.")
