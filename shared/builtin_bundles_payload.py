"""
Project Castor: Built-in Composite Bundles Registry
Maintains the canonical, pre-approved multi-module architecture solutions shipped out-of-the-box.
"""

from typing import Any, Dict, List, Optional
from shared.bundle_schema import CompositeBundleRecord, CompositeBundleSourceType


BUILTIN_BUNDLES: Dict[str, CompositeBundleRecord] = {
    "secure-three-tier-web": CompositeBundleRecord(
        bundle_id="secure-three-tier-web",
        name="Enterprise Secure 3-Tier Web & DB Stack",
        category="COMPUTE_DATA",
        description="Hardened Cloud Run web frontend/API with private-IP Cloud SQL PostgreSQL, Serverless VPC Access, Secret Manager, and a Cloud KMS key (Cloud SQL CMEK not wired yet).",
        source_type=CompositeBundleSourceType.BUILTIN,
        version_tag="1.0.0",
        supported_engines=["tofu", "terraform"],
        default_engine="tofu",
        modules_included=[
            "networking-vpc",
            "database-cloudsql",
            "compute-cloudrun",
            "security-secret",
            "security-kms",
        ],
        resource_footprint={
            "cpus": 4,
            "memory_gb": 8,
            "subnets": 2,
            "static_ips": 1,
            "cloud_sql_instances": 1,
            "cloud_run_services": 1,
        },
        default_parameters={
            "database_version": "POSTGRES_15",
            "cloudrun_min_instances": 1,
            "enable_cmek": True,
        },
        variables=[
            {"name": "project_id", "type": "string", "description": "Google Cloud Project ID", "required": True},
            {"name": "region", "type": "string", "description": "GCP region", "required": False, "default": "us-central1"},
            {"name": "environment", "type": "string", "description": "Deployment environment (prod/stage/dev)", "required": False, "default": "prod"},
            {"name": "db_tier", "type": "string", "description": "Cloud SQL compute tier", "required": False, "default": "db-custom-2-7680"},
            {"name": "min_instances", "type": "number", "description": "Minimum Cloud Run container instances", "required": False, "default": 1},
            {"name": "product_id", "type": "string", "description": "Workload product ID", "required": True},
            {"name": "service_account_email", "type": "string", "description": "Workload runtime service account email", "required": True},
            {"name": "container_image", "type": "string", "description": "Container image URL for the web/API service", "required": False, "default": ""},
            {"name": "subnet_cidr", "type": "string", "description": "Workload subnet range from the platform IPAM (never a literal)", "required": True},
            {"name": "connector_cidr", "type": "string", "description": "Serverless VPC Access connector range from the platform IPAM (/28)", "required": True},
        ],
        outputs=[
            {"name": "service_uri", "description": "HTTPS URL of deployed Cloud Run service"},
            {"name": "database_connection_name", "description": "Instance connection string for Cloud SQL"},
            {"name": "database_private_ip_address", "description": "Private IP address of the Cloud SQL instance"},
            {"name": "vpc_network_name", "description": "Name of isolated VPC network"},
            {"name": "kms_key_id", "description": "KMS CryptoKey resource ID (Cloud SQL CMEK not wired yet)"},
        ],
        hcl_files={
            "main.tf": """# ==============================================================================
# StackVend Composite Bundle: Enterprise Secure 3-Tier Web & DB Stack
# ==============================================================================

# FD-CSQL (F5): wired to the golden modules' real inputs and outputs. IP ranges are the platform IPAM facts
# var.subnet_cidr / var.connector_cidr (never literals). The KMS key is created and exported; Cloud SQL CMEK is
# not wired yet (the database module has no CMEK input).

module "kms" {
  source       = "../../modules/security-kms"
  project_id   = var.project_id
  location     = var.region
  keyring_name = "${var.environment}-keyring"
  key_name     = "${var.environment}-db-cmek"
}

# Private Services Access (module default) is the peering the private-IP Cloud SQL instance needs.
module "vpc" {
  source              = "../../modules/networking-vpc"
  project_id          = var.project_id
  region              = var.region
  network_name        = "${var.environment}-private-vpc"
  primary_subnet_cidr = var.subnet_cidr
}

# Serverless VPC Access: Cloud Run reaches the database's private IP through this connector.
resource "google_vpc_access_connector" "connector" {
  project       = var.project_id
  name          = "${var.environment}-web-cx"
  region        = var.region
  network       = module.vpc.network_name
  ip_cidr_range = var.connector_cidr
}

module "secret" {
  source     = "../../modules/security-secret"
  project_id = var.project_id
  secret_id  = "${var.environment}-db-credentials"
}

module "database" {
  source                       = "../../modules/database-cloudsql"
  project_id                   = var.project_id
  region                       = var.region
  database_name                = "${var.environment}_app_db"
  tier                         = var.db_tier
  private_network_id           = module.vpc.network_id
  workload_sa_email            = var.service_account_email
  grant_workload_secret_access = true
  depends_on                   = [module.vpc]
}

module "app" {
  source                = "../../modules/compute-cloudrun"
  project_id            = var.project_id
  region                = var.region
  product_id            = var.product_id
  service_name          = "${var.environment}-web-api"
  service_account_email = var.service_account_email
  container_image       = var.container_image
  vpc_access_connector  = google_vpc_access_connector.connector.id
  min_instances         = var.min_instances
  env_vars = {
    DB_HOST               = module.database.private_ip_address
    DB_NAME               = module.database.database_name
    DB_USER               = module.database.db_user
    DB_PASSWORD_SECRET_ID = module.database.secret_id_password
    SECRET_ID             = module.secret.secret_id
  }
  depends_on = [module.database, module.vpc]
}
""",
            "variables.tf": """variable "project_id" {
  type        = string
  description = "Google Cloud Project ID"
}

variable "region" {
  type        = string
  description = "GCP deployment region"
  default     = "us-central1"
}

variable "environment" {
  type        = string
  description = "Deployment environment (e.g. prod, staging, dev)"
  default     = "prod"
}

variable "db_tier" {
  type        = string
  description = "Cloud SQL machine tier"
  default     = "db-custom-2-7680"
}

variable "min_instances" {
  type        = number
  description = "Minimum Cloud Run container instances"
  default     = 1
}

variable "product_id" {
  type        = string
  description = "Workload product ID"
}

variable "service_account_email" {
  type        = string
  description = "Workload runtime service account email (Cloud Run identity; granted Cloud SQL client and the database password secret)"
}

variable "container_image" {
  type        = string
  description = "Container image URL for the web/API service (empty: the compute-cloudrun module default)"
  default     = ""
}

variable "subnet_cidr" {
  type        = string
  description = "Workload subnet range allocated by the platform IPAM (platform-owned; never a literal)"
  validation {
    condition     = can(cidrnetmask(var.subnet_cidr))
    error_message = "subnet_cidr must be an IPv4 CIDR allocated by the platform IPAM."
  }
}

variable "connector_cidr" {
  type        = string
  description = "Serverless VPC Access connector range allocated by the platform IPAM (platform-owned; /28)"
  validation {
    condition     = can(cidrnetmask(var.connector_cidr))
    error_message = "connector_cidr must be an IPv4 CIDR allocated by the platform IPAM."
  }
}
""",
            "outputs.tf": """output "service_uri" {
  value       = module.app.service_uri
  description = "Cloud Run application URI"
}

output "database_connection_name" {
  value       = module.database.instance_connection_name
  description = "Cloud SQL instance connection string"
}

output "database_private_ip_address" {
  value       = module.database.private_ip_address
  description = "Private IP address of the Cloud SQL instance"
}

output "vpc_network_name" {
  value       = module.vpc.network_name
  description = "VPC network name"
}

output "kms_key_id" {
  value       = module.kms.crypto_key_id
  description = "KMS CryptoKey resource identifier"
}
""",
        },
        is_active=True,
        is_builtin=True,
    ),

    "event-driven-microservice": CompositeBundleRecord(
        bundle_id="event-driven-microservice",
        name="Event-Driven Serverless Microservice",
        category="EVENT_DRIVEN",
        description="Cloud Storage object notifications routed via Eventarc/PubSub and Cloud Tasks to an asynchronous Cloud Run worker backed by Firestore.",
        source_type=CompositeBundleSourceType.BUILTIN,
        version_tag="1.0.0",
        supported_engines=["tofu", "terraform"],
        default_engine="tofu",
        modules_included=[
            "storage-bucket",
            "event-trigger",
            "messaging-pubsub",
            "tasks-queue",
            "compute-event-worker",
        ],
        resource_footprint={
            "cpus": 2,
            "memory_gb": 4,
            "subnets": 0,
            "static_ips": 0,
            "cloud_run_services": 1,
            "storage_buckets": 1,
        },
        default_parameters={
            "queue_rate_limit": 50,
            "bucket_location": "US",
        },
        variables=[
            {"name": "project_id", "type": "string", "description": "Google Cloud Project ID", "required": True},
            {"name": "region", "type": "string", "description": "GCP region", "required": False, "default": "us-central1"},
            {"name": "bucket_name", "type": "string", "description": "Cloud Storage bucket name", "required": True},
            {"name": "queue_name", "type": "string", "description": "Cloud Tasks queue name", "required": False, "default": "workload-tasks"},
        ],
        outputs=[
            {"name": "bucket_url", "description": "GCS bucket URL (gs://...)"},
            {"name": "topic_id", "description": "Pub/Sub ingest topic name"},
            {"name": "worker_uri", "description": "Cloud Run async worker URI"},
            {"name": "tasks_queue_id", "description": "Cloud Tasks queue identifier"},
        ],
        hcl_files={
            "main.tf": """# ==============================================================================
# StackVend Composite Bundle: Event-Driven Serverless Microservice
# ==============================================================================

module "bucket" {
  source     = "../../modules/storage-bucket"
  project_id = var.project_id
  bucket_name = var.bucket_name
}

module "pubsub" {
  source     = "../../modules/messaging-pubsub"
  project_id = var.project_id
  topic_name = "${var.bucket_name}-events"
}

module "tasks" {
  source     = "../../modules/tasks-queue"
  project_id = var.project_id
  region     = var.region
  queue_name = var.queue_name
}

module "worker" {
  source       = "../../modules/compute-event-worker"
  project_id   = var.project_id
  region       = var.region
  service_name = "${var.bucket_name}-worker"
  env_vars = {
    PUBSUB_TOPIC = module.pubsub.topic_name
    QUEUE_ID     = module.tasks.queue_id
  }
}

module "trigger" {
  source           = "../../modules/event-trigger"
  project_id       = var.project_id
  region           = var.region
  trigger_name     = "${var.bucket_name}-on-upload"
  source_bucket    = module.bucket.bucket_name
  target_topic     = module.pubsub.topic_name
  target_service   = module.worker.service_name
  depends_on       = [module.bucket, module.pubsub, module.worker]
}
""",
            "variables.tf": """variable "project_id" {
  type        = string
  description = "Google Cloud Project ID"
}

variable "region" {
  type        = string
  description = "GCP deployment region"
  default     = "us-central1"
}

variable "bucket_name" {
  type        = string
  description = "Cloud Storage landing bucket name"
}

variable "queue_name" {
  type        = string
  description = "Cloud Tasks queue name"
  default     = "workload-tasks"
}
""",
            "outputs.tf": """output "bucket_url" {
  value       = module.bucket.bucket_url
  description = "GCS bucket URL"
}

output "topic_id" {
  value       = module.pubsub.topic_id
  description = "Pub/Sub topic identifier"
}

output "worker_uri" {
  value       = module.worker.service_uri
  description = "Event worker service URI"
}

output "tasks_queue_id" {
  value       = module.tasks.queue_id
  description = "Cloud Tasks queue identifier"
}
""",
        },
        is_active=True,
        is_builtin=True,
    ),

    "vertex-ai-rag-stack": CompositeBundleRecord(
        bundle_id="vertex-ai-rag-stack",
        name="Vertex AI Enterprise RAG Stack",
        category="AI_ML",
        description="Secure document repository on Cloud Storage with Vertex AI Vector Search / Endpoint and Cloud Run conversational agent API.",
        source_type=CompositeBundleSourceType.BUILTIN,
        version_tag="1.0.0",
        supported_engines=["tofu", "terraform"],
        default_engine="tofu",
        modules_included=[
            "storage-bucket",
            "ai-vertex-endpoint",
            "compute-cloudrun",
            "security-secret",
        ],
        resource_footprint={
            "cpus": 8,
            "memory_gb": 16,
            "subnets": 1,
            "static_ips": 1,
            "cloud_run_services": 1,
            "vertex_endpoints": 1,
        },
        default_parameters={
            "embedding_dimension": 768,
            "index_algorithm": "TREE_AH",
        },
        variables=[
            {"name": "project_id", "type": "string", "description": "Google Cloud Project ID", "required": True},
            {"name": "region", "type": "string", "description": "GCP region", "required": False, "default": "us-central1"},
            {"name": "model_id", "type": "string", "description": "Gemini / Vertex model identifier", "required": False, "default": "gemini-3.8-flash"},
        ],
        outputs=[
            {"name": "endpoint_id", "description": "Vertex AI Endpoint Resource ID"},
            {"name": "docs_bucket", "description": "GCS Bucket for document storage"},
            {"name": "agent_api_uri", "description": "Cloud Run Conversational Agent API URI"},
        ],
        hcl_files={
            "main.tf": """# ==============================================================================
# StackVend Composite Bundle: Vertex AI Enterprise RAG Stack
# ==============================================================================

module "docs_bucket" {
  source      = "../../modules/storage-bucket"
  project_id  = var.project_id
  bucket_name = "${var.project_id}-rag-docs"
}

module "secrets" {
  source     = "../../modules/security-secret"
  project_id = var.project_id
  secret_id  = "rag-api-credentials"
}

module "ai_endpoint" {
  source        = "../../modules/ai-vertex-endpoint"
  project_id    = var.project_id
  region        = var.region
  endpoint_name = "enterprise-rag-endpoint"
}

module "agent_api" {
  source       = "../../modules/compute-cloudrun"
  project_id   = var.project_id
  region       = var.region
  service_name = "rag-agent-api"
  env_vars = {
    VERTEX_ENDPOINT_ID = module.ai_endpoint.endpoint_id
    DOCS_BUCKET_NAME   = module.docs_bucket.bucket_name
    SECRET_ID          = module.secrets.secret_id
    MODEL_ID           = var.model_id
  }
  depends_on   = [module.ai_endpoint, module.docs_bucket]
}
""",
            "variables.tf": """variable "project_id" {
  type        = string
  description = "Google Cloud Project ID"
}

variable "region" {
  type        = string
  description = "GCP deployment region"
  default     = "us-central1"
}

variable "model_id" {
  type        = string
  description = "Foundation Model identifier"
  default     = "gemini-3.8-flash"
}
""",
            "outputs.tf": """output "endpoint_id" {
  value       = module.ai_endpoint.endpoint_id
  description = "Vertex AI endpoint resource ID"
}

output "docs_bucket" {
  value       = module.docs_bucket.bucket_name
  description = "RAG document storage bucket name"
}

output "agent_api_uri" {
  value       = module.agent_api.service_uri
  description = "Conversational agent API URI"
}
""",
        },
        is_active=True,
        is_builtin=True,
    ),

    "private-gke-microservices": CompositeBundleRecord(
        bundle_id="private-gke-microservices",
        name="Private Multi-Zone GKE Autopilot Stack",
        category="KUBERNETES",
        description="Enterprise VPC with private subnets, Google Kubernetes Engine (GKE) Autopilot cluster, Workload Identity, Cloud Armor security, and Prometheus alerts.",
        source_type=CompositeBundleSourceType.BUILTIN,
        version_tag="1.0.0",
        supported_engines=["tofu", "terraform"],
        default_engine="tofu",
        modules_included=[
            "networking-vpc",
            "compute-gke-autopilot",
            "security-secret",
            "observability-alerts",
        ],
        resource_footprint={
            "cpus": 12,
            "memory_gb": 32,
            "subnets": 3,
            "static_ips": 2,
            "gke_clusters": 1,
        },
        default_parameters={
            "release_channel": "REGULAR",
            "private_endpoint": True,
        },
        variables=[
            {"name": "project_id", "type": "string", "description": "Google Cloud Project ID", "required": True},
            {"name": "region", "type": "string", "description": "GCP region", "required": False, "default": "us-central1"},
            {"name": "cluster_name", "type": "string", "description": "GKE cluster name", "required": False, "default": "prod-autopilot-cluster"},
        ],
        outputs=[
            {"name": "cluster_id", "description": "GKE Autopilot cluster identifier"},
            {"name": "cluster_endpoint", "description": "Kubernetes API private endpoint"},
            {"name": "network_name", "description": "Underlying VPC network"},
        ],
        hcl_files={
            "main.tf": """# ==============================================================================
# StackVend Composite Bundle: Private Multi-Zone GKE Autopilot Stack
# ==============================================================================

module "vpc" {
  source       = "../../modules/networking-vpc"
  project_id   = var.project_id
  region       = var.region
  network_name = "${var.cluster_name}-vpc"
  subnet_cidr  = "10.10.0.0/16"
}

module "secrets" {
  source     = "../../modules/security-secret"
  project_id = var.project_id
  secret_id  = "${var.cluster_name}-credentials"
}

module "gke" {
  source       = "../../modules/compute-gke-autopilot"
  project_id   = var.project_id
  region       = var.region
  cluster_name = var.cluster_name
  network      = module.vpc.network_name
  subnetwork   = module.vpc.subnet_name
  depends_on   = [module.vpc]
}

module "alerts" {
  source        = "../../modules/observability-alerts"
  project_id    = var.project_id
  resource_type = "k8s_cluster"
  resource_name = module.gke.cluster_name
  depends_on    = [module.gke]
}
""",
            "variables.tf": """variable "project_id" {
  type        = string
  description = "Google Cloud Project ID"
}

variable "region" {
  type        = string
  description = "GCP deployment region"
  default     = "us-central1"
}

variable "cluster_name" {
  type        = string
  description = "GKE Autopilot cluster name"
  default     = "prod-autopilot-cluster"
}
""",
            "outputs.tf": """output "cluster_id" {
  value       = module.gke.cluster_id
  description = "GKE Autopilot cluster resource ID"
}

output "cluster_endpoint" {
  value       = module.gke.cluster_endpoint
  description = "Kubernetes API endpoint"
}

output "network_name" {
  value       = module.vpc.network_name
  description = "VPC network name"
}
""",
        },
        is_active=True,
        is_builtin=True,
    ),

    "serverless-analytics-lakehouse": CompositeBundleRecord(
        bundle_id="serverless-analytics-lakehouse",
        name="Serverless Lakehouse & BigQuery Pipeline",
        category="ANALYTICS",
        description="Landing Cloud Storage bucket, scheduled cron extraction via Cloud Scheduler and Pub/Sub, Cloud Run ETL processor, and partitioned BigQuery analytics dataset.",
        source_type=CompositeBundleSourceType.BUILTIN,
        version_tag="1.0.0",
        supported_engines=["tofu", "terraform"],
        default_engine="tofu",
        modules_included=[
            "storage-bucket",
            "scheduling-cron",
            "messaging-pubsub",
            "compute-event-worker",
            "analytics-bigquery",
        ],
        resource_footprint={
            "cpus": 4,
            "memory_gb": 8,
            "subnets": 0,
            "static_ips": 0,
            "bigquery_datasets": 1,
            "storage_buckets": 1,
        },
        default_parameters={
            "cron_schedule": "0 2 * * *",
            "dataset_retention_days": 365,
        },
        variables=[
            {"name": "project_id", "type": "string", "description": "Google Cloud Project ID", "required": True},
            {"name": "region", "type": "string", "description": "GCP region", "required": False, "default": "us-central1"},
            {"name": "dataset_id", "type": "string", "description": "BigQuery dataset identifier", "required": True},
            {"name": "schedule", "type": "string", "description": "Cron expression for ingestion", "required": False, "default": "0 2 * * *"},
        ],
        outputs=[
            {"name": "dataset_id", "description": "BigQuery dataset ID"},
            {"name": "landing_bucket", "description": "Data lake landing bucket"},
            {"name": "pipeline_topic", "description": "Ingestion trigger Pub/Sub topic"},
        ],
        hcl_files={
            "main.tf": """# ==============================================================================
# StackVend Composite Bundle: Serverless Lakehouse & BigQuery Pipeline
# ==============================================================================

module "lake_bucket" {
  source      = "../../modules/storage-bucket"
  project_id  = var.project_id
  bucket_name = "${var.project_id}-analytics-landing"
}

module "ingest_topic" {
  source     = "../../modules/messaging-pubsub"
  project_id = var.project_id
  topic_name = "${var.dataset_id}-ingest"
}

module "scheduler" {
  source      = "../../modules/scheduling-cron"
  project_id  = var.project_id
  region      = var.region
  job_name    = "${var.dataset_id}-cron"
  schedule    = var.schedule
  target_type = "pubsub"
  target_uri  = module.ingest_topic.topic_id
}

module "bigquery" {
  source     = "../../modules/analytics-bigquery"
  project_id = var.project_id
  dataset_id = var.dataset_id
}

module "etl_worker" {
  source       = "../../modules/compute-event-worker"
  project_id   = var.project_id
  region       = var.region
  service_name = "${var.dataset_id}-etl-processor"
  env_vars = {
    LANDING_BUCKET = module.lake_bucket.bucket_name
    DATASET_ID     = module.bigquery.dataset_id
  }
  depends_on   = [module.lake_bucket, module.bigquery]
}
""",
            "variables.tf": """variable "project_id" {
  type        = string
  description = "Google Cloud Project ID"
}

variable "region" {
  type        = string
  description = "GCP deployment region"
  default     = "us-central1"
}

variable "dataset_id" {
  type        = string
  description = "BigQuery dataset name"
}

variable "schedule" {
  type        = string
  description = "Cron schedule expression"
  default     = "0 2 * * *"
}
""",
            "outputs.tf": """output "dataset_id" {
  value       = module.bigquery.dataset_id
  description = "BigQuery dataset ID"
}

output "landing_bucket" {
  value       = module.lake_bucket.bucket_name
  description = "Landing Cloud Storage bucket"
}

output "pipeline_topic" {
  value       = module.ingest_topic.topic_name
  description = "Ingestion Pub/Sub topic"
}
""",
        },
        is_active=True,
        is_builtin=True,
    ),
}


def get_builtin_bundle(bundle_id: str) -> Optional[CompositeBundleRecord]:
    """Retrieve a built-in bundle by ID."""
    return BUILTIN_BUNDLES.get(bundle_id.strip().lower())


def list_builtin_bundles() -> List[CompositeBundleRecord]:
    """Return all 5 canonical built-in bundles."""
    return list(BUILTIN_BUNDLES.values())
