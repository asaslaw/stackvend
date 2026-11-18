"""
Project Castor: Dynamic Golden Module Contract Inspector
Inspects variables.tf and outputs.tf directly from infra/modules/
to extract ground-truth contracts for LLM prompt context grounding.
Includes resilient embedded fallbacks for containerized Cloud Run environments.
"""

import logging
import os
import re
from typing import Dict, List, Optional

logger = logging.getLogger("castor-contract-inspector")

_CONTRACT_CACHE: Dict[str, str] = {}

# Resilient embedded catalog contracts for containerized production environments.
# The deployed gateway has no infra/modules on disk, so this table IS the production prompt grounding. Each entry
# must equal the variable/output names declared in infra/modules/<module>/{variables,outputs}.tf (CI-5; enforced
# for every entry by tests/test_ci5_embedded_contract_parity.py). Regenerate from those files, never hand-edit.
_EMBEDDED_MODULE_CONTRACTS: Dict[str, Dict[str, List[str]]] = {
    "workload-foundation/base": {
        "inputs": [
            "additional_apis",
            "base_apis",
            "enable_github_actions_deploy",
            "firestore_delete_protection",
            "github_default_branch",
            "github_repo_full_name",
            "github_repository_id",
            "product_id",
            "project_id",
            "region",
        ],
        "outputs": [
            "database_name",
            "deployer_sa_email",
            "docker_repo_id",
            "wif_pool_name",
            "wif_provider_name",
            "workload_sa_email",
            "workload_sa_id",
        ],
    },
    "compute-cloudrun": {
        "inputs": [
            "allow_unauthenticated",
            "authorized_invoker_members",
            "container_image",
            "cpu_idle",
            "cpu_limit",
            "enable_direct_iap",
            "encryption_key",
            "env_vars",
            "firebase_api_key",
            "firebase_auth_domain",
            "health_check_path",
            "ingress",
            "max_instances",
            "memory_limit",
            "min_instances",
            "oauth_client_id",
            "product_id",
            "project_id",
            "project_number",
            "push_service_accounts",
            "region",
            "service_account_email",
            "service_name",
            "vpc_access_connector",
            "vpc_egress",
        ],
        "outputs": [
            "iap_enabled",
            "service_id",
            "service_name",
            "service_uri",
        ],
    },
    "compute-gke-autopilot": {
        "inputs": [
            "cluster_name",
            "database_encryption_key",
            "network",
            "product_id",
            "project_id",
            "region",
            "subnetwork",
        ],
        "outputs": [
            "cluster_ca_certificate",
            "cluster_endpoint",
            "cluster_id",
            "cluster_name",
        ],
    },
    "compute-gce-bastion": {
        "inputs": [
            "bigquery_datasets",      # gce-bastion-network: own-SA grants (platform-rendered from the topology)
            "boot_image",
            "machine_type",
            "network",
            "product_id",
            "project_id",
            "pubsub_subscriptions",   # gce-bastion-network
            "pubsub_topics",          # gce-bastion-network
            "region",
            "secrets",                # gce-bastion-network
            "settings",               # gce-bastion-network: instance metadata settings from the topology bindings
            "startup_script",   # gce-bastion-startup: platform-rendered from apps/<service>/startup.sh
            "storage_buckets",        # gce-bastion-network
            "subnet_cidr",            # gce-bastion-network: own subnet on the IPAM fact var.subnet_cidr
            "subnetwork",
            "subnetwork_id",          # gce-bastion-network: the workload's existing subnetwork
            "use_existing_subnetwork",  # gce-bastion-network
            "zone",                   # RT14-35: empty = the first zone of the region (sorted)
        ],
        "outputs": [
            "bastion_sa_email",
            "instance_id",
            "instance_name",
            "instance_self_link",
        ],
    },
    "compute-event-worker": {
        "inputs": [
            "container_image",
            "cpu_limit",
            "kms_key_name",
            "memory_limit",
            "name_suffix",
            "product_id",
            "project_id",
            "region",
            "service_account_email",
        ],
        "outputs": [
            "job_id",
            "job_name",
            "subscription_name",
            "topic_id",
            "topic_name",
        ],
    },
    "storage-bucket": {
        "inputs": [
            "bucket_name_suffix",
            "kms_key_name",
            "lifecycle_delete_age_days",
            "prevent_destroy",
            "project_id",
            "region",
            "uniform_bucket_level_access",
            "versioning_enabled",
            "workload_sa_email",
        ],
        "outputs": [
            "bucket_name",
            "bucket_url",
        ],
    },
    "messaging-pubsub": {
        "inputs": [
            "ack_deadline_seconds",
            "enable_dead_letter",
            "enable_subscription",
            "kms_key_name",
            "message_retention_duration",
            "project_id",
            "push",
            "topic_name_suffix",
            "workload_sa_email",
        ],
        "outputs": [
            "dead_letter_topic_id",
            "subscription_id",
            "subscription_name",
            "topic_id",
            "topic_name",
        ],
    },
    "security-secret": {
        "inputs": [
            "generate_initial_version",
            "project_id",
            "secret_data",
            "secret_id",
            "workload_sa_email",
        ],
        "outputs": [
            "secret_id",
            "secret_name",
            "secret_version_id",
        ],
    },
    "tasks-queue": {
        "inputs": [
            "max_attempts",
            "max_concurrent_dispatches",
            "max_dispatches_per_second",
            "project_id",
            "queue_name_suffix",
            "region",
            "workload_sa_email",
        ],
        "outputs": [
            "queue_id",
            "queue_name",
        ],
    },
    "scheduling-cron": {
        "inputs": [
            "audience",
            "http_method",
            "job_name_suffix",
            "project_id",
            "region",
            "schedule",
            "service_account_email",
            "target_uri",
            "time_zone",
        ],
        "outputs": [
            "job_id",
            "job_name",
        ],
    },
    "analytics-bigquery": {
        "inputs": [
            "dataset_id",
            "delete_contents_on_destroy",
            "kms_key_name",
            "project_id",
            "region",
            "workload_sa_email",
        ],
        "outputs": [
            "dataset_id",
            "dataset_name",
        ],
    },
    "event-trigger": {
        "inputs": [
            "destination_run_service_name",
            "event_type",
            "project_id",
            "region",
            "service_account_email",
            "trigger_name_suffix",
        ],
        "outputs": [
            "trigger_id",
            "trigger_name",
        ],
    },
    "observability-alerts": {
        "inputs": [
            "alert_name_suffix",
            "duration",
            "filter",
            "notification_channels",
            "project_id",
            "threshold_value",
        ],
        "outputs": [
            "alert_policy_id",
            "alert_policy_name",
        ],
    },
    "workload_auth": {
        "inputs": [
            "additional_authorized_domains",
            "enable_anonymous_auth",
            "enable_email_password_auth",
            "oauth_client_id",
            "oauth_client_secret",
            "project_id",
        ],
        "outputs": [
            "authorized_domains",
            "google_idp_name",
            "identity_platform_config_name",
        ],
    },
    "workflows-dag": {
        "inputs": [
            "project_id",
            "region",
            "service_account_email",
            "source_contents",
            "workflow_name_suffix",
        ],
        "outputs": [
            "workflow_id",
            "workflow_name",
        ],
    },
    "security-kms": {
        "inputs": [
            "enable_apis",
            "key_name",
            "keyring_name",
            "location",
            "project_id",
            "protection_level",
            "rotation_period",
            "service_agent_services",
            "workload_sa_email",
        ],
        "outputs": [
            "crypto_key_id",
            "crypto_key_name",
            "keyring_id",
        ],
    },
    "dns-record": {
        "inputs": [
            "managed_zone",
            "project_id",
            "record_name",
            "record_type",
            "rrdatas",
            "ttl",
        ],
        "outputs": [
            "record_name",
            "record_type",
        ],
    },
    "database-cloudsql": {
        "inputs": [
            "database_name",
            "database_version",
            "db_password",
            "db_user",
            "deletion_protection",
            "enable_public_ip",
            "grant_workload_secret_access",
            "instance_name_suffix",
            "kms_key_name",   # lane 14 PR-0b (integration with FD-CSQL): CMEK input, null = Google-managed
            "private_network_id",
            "project_id",
            "region",
            "ssl_mode",
            "tier",
            "workload_sa_email",
        ],
        "outputs": [
            "database_name",
            "db_user",
            "instance_connection_name",
            "instance_name",
            "private_ip_address",
            "secret_id_password",
        ],
    },
    "cache-redis": {
        "inputs": [
            "auth_enabled",
            "authorized_network",
            "instance_name_suffix",
            "kms_key_name",
            "memory_size_gb",
            "project_id",
            "region",
            "tier",
            "transit_encryption_mode",
        ],
        "outputs": [
            "current_location_id",
            "host",
            "instance_id",
            "port",
        ],
    },
    "database-spanner": {
        "inputs": [
            "config",
            "database_name",
            "ddl_statements",
            "deletion_protection",
            "display_name",
            "instance_id",
            "kms_key_name",
            "labels",
            "processing_units",
            "product_id",
            "project_id",
            "region",                 # RT14-36: the instance configuration is regional-<region>
        ],
        "outputs": [
            "database_id",
            "database_state",
            "instance_id",
            "instance_state",
        ],
    },
    "database-alloydb": {
        "inputs": [
            "cluster_id",
            "cpu_count",
            "grant_workload_secret_access",
            "initial_user_password",
            "instance_id",
            "kms_key_name",
            "labels",
            "network",
            "product_id",
            "project_id",
            "region",
            "workload_sa_email",
        ],
        "outputs": [
            "cluster_id",
            "cluster_name",
            "instance_id",
            "ip_address",
            "secret_id_password",
        ],
    },
    "database-bigtable": {
        "inputs": [
            "cluster_id",
            "column_families",
            "deletion_protection",
            "display_name",
            "instance_id",
            "labels",
            "num_nodes",
            "product_id",
            "project_id",
            "storage_type",
            "table_name",
            "zone",
        ],
        "outputs": [
            "cluster_id",
            "instance_id",
            "table_id",
        ],
    },
    "ai-vertex-endpoint": {
        "inputs": [
            "description",
            "display_name",
            "endpoint_name",
            "kms_key_name",
            "labels",
            "network",
            "product_id",
            "project_id",
            "region",
        ],
        "outputs": [
            "endpoint_id",
            "endpoint_name",
        ],
    },
    "orchestration-composer": {
        "inputs": [
            "environment_name",
            "environment_size",
            "image_version",
            "labels",
            "product_id",
            "project_id",
            "region",
            "service_account",
        ],
        "outputs": [
            "airflow_uri",
            "environment_id",
            "environment_name",
            "gcs_bucket",
        ],
    },
}


# Module inputs that only the platform sets, at apply time (tf-applier's var-file), and that generated code must never
# set. They stay in _EMBEDDED_MODULE_CONTRACTS (CI-5 parity with variables.tf) but are left out of the rendered
# contract, on disk and unmounted alike, so the developer prompt does not advertise them. Exact names only.
# FD-4AT-c: workload-foundation/base github_repository_id (vending resolves it; the generated root only forwards it).
# FD-4CI-b-R1-WIF: workload-foundation/base github_default_branch (the workload record's branch; the platform's own
# render forwards it, tf-applier supplies it).
# GHA-DEPLOY-SWITCH: workload-foundation/base enable_github_actions_deploy (the workload record's switch; the
# platform's own render forwards it while the switch is off, tf-applier supplies it).
# PUSH-TO-PRIVATE: compute-cloudrun push_service_accounts (the platform renders it from the typed intent's push
# subscriptions into its own module calls; generated code never sets it).
# IAP-GATE-KNOWN-MEMBER: compute-cloudrun project_number (the platform's render passes it; generated code never sets it).
# PUSH-SUB-RENDER: messaging-pubsub push (the platform renders it from the typed intent's closed `push` form; the
# classic HCL prompt is unchanged, so it is not advertised there either).
# SECRET-INITIAL-VERSION: security-secret generate_initial_version (the platform renders it from the architect's typed
# topology on typed infrastructure; the classic HCL prompt is unchanged, so it is not advertised there either).
_PLATFORM_ONLY_INPUTS: Dict[str, frozenset] = {
    "workload-foundation/base": frozenset({"github_repository_id", "github_default_branch",
                                           "enable_github_actions_deploy"}),
    "compute-cloudrun": frozenset({"push_service_accounts", "project_number"}),
    "messaging-pubsub": frozenset({"push"}),
    "security-secret": frozenset({"generate_initial_version"}),
}


def get_platform_modules_path() -> Optional[str]:
    """Resolves the canonical infra/modules directory path."""
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../infra/modules"))
    if os.path.isdir(base_dir):
        return base_dir
    # Check current working directory fallback
    cwd_dir = os.path.abspath("infra/modules")
    if os.path.isdir(cwd_dir):
        return cwd_dir
    return None


# RT14-F2 (owner 11-14, option a): one wiring line per module whose classic (AI-written HCL) call must pass an input
# for a platform guarantee. database-spanner: with `region` the module sets config = regional-<region> (residency);
# without it the call's own `config` is used as written (and must be set), so the classic contract asks for
# region = var.region. Typed infrastructure renders `region` itself (FACT). Every other contract is unchanged.
_CONTRACT_WIRING_NOTES: Dict[str, str] = {
    "database-spanner": "- **Required Wiring**: region = var.region (leave config unset; the instance configuration "
                        "is then regional-<region>)\n",
}

def get_golden_module_contract(module_name: str = "compute-cloudrun", force_refresh: bool = False) -> str:
    """
    Reads outputs.tf and variables.tf directly from infra/modules/<module_name>
    or returns embedded ground-truth contract if unmounted.
    """
    if not force_refresh and module_name in _CONTRACT_CACHE:
        return _CONTRACT_CACHE[module_name]

    mod_base = get_platform_modules_path()
    declared_outputs: List[str] = []
    declared_variables: List[str] = []

    target_dir = os.path.join(mod_base, module_name) if mod_base else None
    if target_dir and os.path.isdir(target_dir):
        outputs_path = os.path.join(target_dir, "outputs.tf")
        variables_path = os.path.join(target_dir, "variables.tf")

        if os.path.exists(outputs_path):
            try:
                with open(outputs_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    declared_outputs = re.findall(r'output\s+"([^"]+)"', content)
            except Exception as e:
                logger.warning(f"Could not read {outputs_path}: {e}")

        if os.path.exists(variables_path):
            try:
                with open(variables_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    declared_variables = re.findall(r'variable\s+"([^"]+)"', content)
            except Exception as e:
                logger.warning(f"Could not read {variables_path}: {e}")

    # Resilient fallback if files not on disk or missing
    if not declared_variables and not declared_outputs and module_name in _EMBEDDED_MODULE_CONTRACTS:
        fallback = _EMBEDDED_MODULE_CONTRACTS[module_name]
        declared_variables = fallback.get("inputs", [])
        declared_outputs = fallback.get("outputs", [])

    if not declared_variables and not declared_outputs:
        return f"<!-- Module contract for {module_name} unavailable -->"

    platform_only = _PLATFORM_ONLY_INPUTS.get(module_name, frozenset())
    declared_variables = [v for v in declared_variables if v not in platform_only]

    contract_md = f"""### Golden Module Contract: `{module_name}` (source = "../modules/{module_name}")
- **Allowed Inputs**: {', '.join(sorted(declared_variables)) if declared_variables else 'None'}
- **Allowed Outputs**: {', '.join(sorted(f'module.<name>.{out}' for out in declared_outputs)) if declared_outputs else 'None'}
{_CONTRACT_WIRING_NOTES.get(module_name, "")}*CRITICAL: Never reference an output or input not explicitly listed above.*
"""
    _CONTRACT_CACHE[module_name] = contract_md
    return contract_md


def get_custom_module_contracts() -> List[str]:
    """Fetches and formats contracts for active custom enterprise modules from Firestore."""
    custom_contracts: List[str] = []
    try:
        from google.cloud import firestore
        client = firestore.Client()
        docs = client.collection("custom_modules").where("is_active", "==", True).stream()
        for doc in docs:
            data = doc.to_dict() or {}
            mod_id = data.get("module_id") or doc.id
            source_type = data.get("source_type", "DIRECT_CODE")
            override = data.get("override_builtin")
            override_text = f" (Overrides Built-in: `{override}`)" if override else ""

            if source_type == "DIRECT_CODE":
                src_info = f'source = "../modules/{mod_id}"'
            else:
                src_url = data.get("source_url", "")
                tag = data.get("version_tag", "main")
                path = data.get("repo_path", "")
                sub = f"//{path}" if path else ""
                src_info = f'source = "git::{src_url}{sub}?ref={tag}"'

            inputs = [inp.get("name") if isinstance(inp, dict) else str(inp) for inp in data.get("inputs", [])]
            outputs = [out.get("name") if isinstance(out, dict) else str(out) for out in data.get("outputs", [])]

            md = f"""### Custom Enterprise Module Contract: `{mod_id}`{override_text} ({src_info})
- **Allowed Inputs**: {', '.join(sorted(inputs)) if inputs else 'None'}
- **Allowed Outputs**: {', '.join(sorted(f'module.<name>.{out}' for out in outputs)) if outputs else 'None'}
*CRITICAL: Never reference an output or input not explicitly listed above.*"""
            custom_contracts.append(md)
    except Exception as e:
        logger.debug(f"Could not load custom module contracts from Firestore: {e}")
    return custom_contracts


def get_all_active_module_contracts() -> str:
    """Returns combined markdown contracts for all core, supplemental, and custom catalog modules."""
    contracts = []
    for mod in sorted(_EMBEDDED_MODULE_CONTRACTS.keys()):
        c = get_golden_module_contract(mod)
        if c and not c.startswith("<!--"):
            contracts.append(c.strip())

    for cc in get_custom_module_contracts():
        contracts.append(cc.strip())

    return "\n\n".join(contracts)

