"""
Project Castor: Built-in Golden Modules Catalog Provider
Provides dynamic, code-backed access to Castor's native platform Terraform modules.
Zero-database persistence: canonical definitions live in infra/modules/ with in-memory AST contracts.
"""

import os
import logging
from typing import Dict, List, Any, Optional

from shared.module_inspector import parse_hcl_variables_and_outputs

logger = logging.getLogger("castor-builtin-modules")

# Catalog metadata for native platform modules
BUILTIN_MODULE_METADATA: Dict[str, Dict[str, Any]] = {
    # --- Tier 1: Serverless & Instant Services (< 60s Apply) ---
    "storage-bucket": {
        "name": "Cloud Storage Bucket",
        "category": "STORAGE",
        "description": "Secure Google Cloud Storage bucket with CMEK support, lifecycle rules, uniform bucket-level access, and versioning.",
        "is_heavy_stateful": False,
        "timeout_minutes": 15,
    },
    "messaging-pubsub": {
        "name": "Pub/Sub Topic & Subscription",
        "category": "NETWORKING",
        "description": "Scalable Pub/Sub messaging topic and pull/push subscription with dead-letter queue (DLQ) support and CMEK.",
        "is_heavy_stateful": False,
        "timeout_minutes": 15,
    },
    "security-secret": {
        "name": "Secret Manager Secret",
        "category": "SECURITY",
        "description": "Managed Secret Manager secret with automatic replication, managed payload versions, and least-privilege IAM bindings.",
        "is_heavy_stateful": False,
        "timeout_minutes": 15,
    },
    "tasks-queue": {
        "name": "Cloud Tasks Queue",
        "category": "NETWORKING",
        "description": "Managed Cloud Tasks queue with rate limits (concurrent dispatches, dispatches/sec) and exponential backoff retry policies.",
        "is_heavy_stateful": False,
        "timeout_minutes": 15,
    },
    "scheduling-cron": {
        "name": "Cloud Scheduler Cron Job",
        "category": "COMPUTE",
        "description": "Enterprise Cloud Scheduler cron trigger targeting HTTP endpoints with OIDC service account authentication.",
        "is_heavy_stateful": False,
        "timeout_minutes": 15,
    },
    "analytics-bigquery": {
        "name": "BigQuery Dataset & Tables",
        "category": "ANALYTICS",
        "description": "Managed BigQuery dataset and analytical tables with JSON schema definition, partition expiration, and CMEK encryption.",
        "is_heavy_stateful": False,
        "timeout_minutes": 15,
    },
    "event-trigger": {
        "name": "Eventarc Trigger",
        "category": "NETWORKING",
        "description": "Eventarc event routing trigger forwarding Google Cloud events (Storage, Pub/Sub, Audit) to Cloud Run with dead-letter support.",
        "is_heavy_stateful": False,
        "timeout_minutes": 15,
    },
    "observability-alerts": {
        "name": "Cloud Monitoring Alert Policy",
        "category": "SECURITY",
        "description": "Metric threshold alerting policies with multi-channel notification bindings (email, Pub/Sub, webhooks).",
        "is_heavy_stateful": False,
        "timeout_minutes": 15,
    },
    "workflows-dag": {
        "name": "Cloud Workflows State Machine",
        "category": "COMPUTE",
        "description": "Cloud Workflows multi-step orchestration DAG with execution logging and dedicated least-privilege IAM service accounts.",
        "is_heavy_stateful": False,
        "timeout_minutes": 15,
    },
    "security-kms": {
        "name": "Cloud KMS KeyRing & CryptoKey",
        "category": "SECURITY",
        "description": "Customer-Managed Encryption Keys (CMEK) KeyRing and automated rotating CryptoKey with encrypter/decrypter IAM roles.",
        "is_heavy_stateful": False,
        "timeout_minutes": 15,
    },
    "dns-record": {
        "name": "Cloud DNS Record Set",
        "category": "NETWORKING",
        "description": "Managed DNS record sets (A, CNAME, TXT, etc.) on Google Cloud DNS managed zones with configurable TTL.",
        "is_heavy_stateful": False,
        "timeout_minutes": 15,
    },
    "networking-vpc": {
        "name": "Enterprise VPC Network",
        "category": "NETWORKING",
        "description": "Hardened Google Cloud VPC with configurable multi-region subnets, Private Google Access, Private Services Access (PSA) database peering, Cloud NAT, and IAP firewall rules.",
        "is_heavy_stateful": False,
        "timeout_minutes": 15,
    },
    "workload_auth": {
        "name": "Workload Identity & Auth Config",
        "category": "SECURITY",
        "description": "Identity Platform tenant authentication configuration and Workload Identity Federation (WIF) bindings.",
        "is_heavy_stateful": False,
        "timeout_minutes": 15,
    },
    # --- Tier 2: Heavy Stateful & Long-Running Services (Handled via tf-applier Cloud Run Job) ---
    "database-cloudsql": {
        "name": "Cloud SQL (PostgreSQL/MySQL)",
        "category": "DATABASE",
        "description": "Enterprise relational database instance with Cloud SQL Auth Proxy Unix sockets, automated backups, and 24h batch deployment.",
        "is_heavy_stateful": True,
        "timeout_minutes": 1440,
    },
    "cache-redis": {
        "name": "Memorystore Redis",
        "category": "DATABASE",
        "description": "High-performance in-memory caching cluster with in-transit TLS encryption, Redis AUTH, and maintenance policies.",
        "is_heavy_stateful": True,
        "timeout_minutes": 1440,
    },
    "database-spanner": {
        "name": "Cloud Spanner Instance & DB",
        "category": "DATABASE",
        "description": "Globally scalable, highly consistent relational database with parameterized processing units and CMEK encryption.",
        "is_heavy_stateful": True,
        "timeout_minutes": 1440,
    },
    "database-alloydb": {
        "name": "AlloyDB PostgreSQL Cluster",
        "category": "DATABASE",
        "description": "Enterprise PostgreSQL-compatible database cluster and primary instance with VPC peering and automated backup schedules.",
        "is_heavy_stateful": True,
        "timeout_minutes": 1440,
    },
    "database-bigtable": {
        "name": "Cloud Bigtable NoSQL Cluster",
        "category": "DATABASE",
        "description": "Low-latency NoSQL database instance, SSD cluster, and initial tables with column families for real-time telemetry.",
        "is_heavy_stateful": True,
        "timeout_minutes": 1440,
    },
    "ai-vertex-endpoint": {
        "name": "Vertex AI Model Endpoint",
        "category": "COMPUTE",
        "description": "Managed Vertex AI foundation and custom model inference serving endpoint with CMEK encryption spec.",
        "is_heavy_stateful": True,
        "timeout_minutes": 1440,
    },
    "orchestration-composer": {
        "name": "Cloud Composer 2 (Airflow)",
        "category": "COMPUTE",
        "description": "Managed Apache Airflow workflow orchestration environment with preset sizing and automated DAG bucket.",
        "is_heavy_stateful": True,
        "timeout_minutes": 1440,
    },
    # --- Compute & Workload Archetypes ---
    "compute-cloudrun": {
        "name": "Cloud Run Microservice",
        "category": "COMPUTE",
        "description": "Serverless containerized workload runtime with Direct IAP edge SSO, concurrency controls, and scaling limits.",
        "is_heavy_stateful": False,
        "timeout_minutes": 15,
    },
    "compute-gke-autopilot": {
        "name": "GKE Autopilot Cluster",
        "category": "COMPUTE",
        "description": "Managed Google Kubernetes Engine Autopilot cluster with automated node scaling and hardened enterprise defaults.",
        "is_heavy_stateful": True,
        "timeout_minutes": 45,
    },
    "compute-gce-bastion": {
        "name": "Compute Engine Bastion",
        "category": "COMPUTE",
        "description": "Hardened Compute Engine bastion host with internal IP connectivity and Google OS Login access control.",
        "is_heavy_stateful": False,
        "timeout_minutes": 15,
    },
    "compute-event-worker": {
        "name": "Event Worker Service",
        "category": "COMPUTE",
        "description": "Event-driven background processing service optimized for asynchronous jobs, tasks, and message consumers.",
        "is_heavy_stateful": False,
        "timeout_minutes": 15,
    },
    "compute-gce-worker": {
        "name": "Compute Engine Worker Template",
        "category": "COMPUTE",
        "description": "Instance template for on-demand Spot VM workers that a Cloud Run service launches at runtime: own service account, private subnet, no VM at rest.",
        "is_heavy_stateful": False,
        "timeout_minutes": 15,
    },
}

try:
    from shared.builtin_modules_payload import BUILTIN_MODULE_FILES
except ImportError:
    try:
        from builtin_modules_payload import BUILTIN_MODULE_FILES
    except ImportError:
        BUILTIN_MODULE_FILES = {}

_BUILTIN_CACHE: Optional[List[Dict[str, Any]]] = None


def get_platform_modules_path() -> Optional[str]:
    """Resolves the canonical infra/modules directory path."""
    candidates = [
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../infra/modules")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../../infra/modules")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../infra/modules")),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "infra/modules")),
        os.path.abspath("apps/control-center/infra/modules"),
        os.path.abspath("infra/modules"),
    ]
    for p in candidates:
        if os.path.isdir(p):
            return p
    return None


def get_builtin_modules(force_refresh: bool = False) -> List[Dict[str, Any]]:
    """
    Returns the list of all built-in golden modules with parsed input/output contracts.
    Dynamically parses variables.tf and outputs.tf from infra/modules/ with fallback.
    """
    global _BUILTIN_CACHE
    if _BUILTIN_CACHE is not None and not force_refresh:
        # Return deep copy so callers cannot mutate cache
        import copy
        return copy.deepcopy(_BUILTIN_CACHE)

    modules_dir = get_platform_modules_path()
    catalog: List[Dict[str, Any]] = []

    for module_id, meta in BUILTIN_MODULE_METADATA.items():
        inputs = []
        outputs = []
        hcl_files = {}
        contract_error: Optional[str] = None

        if modules_dir:
            mod_path = os.path.join(modules_dir, module_id)
            var_file = os.path.join(mod_path, "variables.tf")
            out_file = os.path.join(mod_path, "outputs.tf")
            main_file = os.path.join(mod_path, "main.tf")

            var_code = ""
            out_code = ""
            main_code = ""

            if os.path.exists(main_file):
                try:
                    with open(main_file, "r", encoding="utf-8") as f:
                        main_code = f.read()
                        hcl_files["main.tf"] = main_code
                except Exception as e:
                    logger.warning(f"Failed to read {main_file}: {e}")

            if os.path.exists(var_file):
                try:
                    with open(var_file, "r", encoding="utf-8") as f:
                        var_code = f.read()
                        hcl_files["variables.tf"] = var_code
                except Exception as e:
                    logger.warning(f"Failed to read {var_file}: {e}")

            if os.path.exists(out_file):
                try:
                    with open(out_file, "r", encoding="utf-8") as f:
                        out_code = f.read()
                        hcl_files["outputs.tf"] = out_code
                except Exception as e:
                    logger.warning(f"Failed to read {out_file}: {e}")

            # Also capture any other .tf files in module directory
            if os.path.isdir(mod_path):
                try:
                    for fname in sorted(os.listdir(mod_path)):
                        if fname.endswith(".tf") and fname not in hcl_files:
                            fpath = os.path.join(mod_path, fname)
                            if os.path.isfile(fpath):
                                with open(fpath, "r", encoding="utf-8") as f:
                                    hcl_files[fname] = f.read()
                except Exception as e:
                    logger.debug(f"Could not list directory {mod_path}: {e}")

            # Fallback to main.tf if variables.tf is empty
            if not var_code and main_code:
                var_code = main_code

            if var_code or out_code:
                try:
                    inputs, outputs = parse_hcl_variables_and_outputs(var_code, out_code)
                except Exception as e:  # contained per module (row CC-MI-2): the other modules still list
                    contract_error = f"{type(e).__name__}: {e}"

        # Fallback to embedded payloads if unmounted container
        if not hcl_files and module_id in BUILTIN_MODULE_FILES:
            hcl_files = dict(BUILTIN_MODULE_FILES[module_id])
            var_code = hcl_files.get("variables.tf", "")
            out_code = hcl_files.get("outputs.tf", "")
            if not var_code and "main.tf" in hcl_files:
                var_code = hcl_files["main.tf"]
            if (not inputs or not outputs) and (var_code or out_code):
                try:
                    inputs, outputs = parse_hcl_variables_and_outputs(var_code, out_code)
                except Exception as e:  # contained per module (row CC-MI-2)
                    contract_error = f"{type(e).__name__}: {e}"

        if contract_error is not None:
            # The module's own files cannot be read: show it as ERROR with no contract, never the minimal
            # project_id/region placeholder below (that would present a guessed contract as VERIFIED).
            logger.error(f"Built-in module '{module_id}': contract unreadable: {contract_error}")
            catalog.append({
                "module_id": module_id,
                "name": meta["name"],
                "source_type": "BUILT_IN",
                "category": meta["category"],
                "description": meta["description"],
                "is_heavy_stateful": meta["is_heavy_stateful"],
                "timeout_minutes": meta["timeout_minutes"],
                "is_builtin": True,
                "is_active": True,
                "sync_status": "ERROR",
                "error_message": contract_error,
                "created_by": "system",
                "inputs": [],
                "variables": [],
                "outputs": [],
                "hcl_files": hcl_files,
                "overridden_by": None,
            })
            continue

        # Fallback minimal contracts if unmounted container and no payload
        if not inputs:
            inputs = [
                {"name": "project_id", "type": "string", "description": "GCP Project ID", "required": True, "default": None},
                {"name": "region", "type": "string", "description": "GCP Region", "required": False, "default": "us-central1"},
            ]
        if not outputs:
            outputs = [
                {"name": "id", "description": f"Unique identifier of the {module_id} resource"},
            ]

        record = {
            "module_id": module_id,
            "name": meta["name"],
            "source_type": "BUILT_IN",
            "category": meta["category"],
            "description": meta["description"],
            "is_heavy_stateful": meta["is_heavy_stateful"],
            "timeout_minutes": meta["timeout_minutes"],
            "is_builtin": True,
            "is_active": True,
            "sync_status": "VERIFIED",
            "created_by": "system",
            "inputs": inputs,
            "variables": inputs,
            "outputs": outputs,
            "hcl_files": hcl_files,
            "overridden_by": None,
        }
        catalog.append(record)

    _BUILTIN_CACHE = catalog
    import copy
    return copy.deepcopy(_BUILTIN_CACHE)
