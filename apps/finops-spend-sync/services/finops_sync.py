"""
Project Castor: FinOps Live Spend Reconciler & Active Accrual Engine
Provides real-time spend estimation from GCS tfstate with authoritative BigQuery export reconciliation.
"""

import calendar
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("control-center-finops-sync")

# Hourly pricing catalog (USD) for Google Cloud us-central1
HOURLY_RESOURCE_RATES = {
    # Cloud SQL
    "sql_db_f1_micro": 0.0105,
    "sql_db_g1_small": 0.0350,
    "sql_custom_vcpu": 0.0413,
    "sql_custom_ram_gb": 0.0070,
    "sql_ssd_storage_gb_hour": 0.170 / 730.0,
    # Serverless VPC Access Connector (2x e2-micro instances minimum)
    "vpc_connector_instance": 0.0180 * 2,
    # Compute Engine / GKE Nodes
    "compute_e2_micro": 0.0084,
    "compute_e2_small": 0.0168,
    "compute_e2_medium": 0.0336,
    # Cloud NAT Gateway
    "cloud_nat_gateway": 0.0014,
    # Cloud Run min instance allocation
    "cloud_run_min_instance": 0.0310,
}


def calculate_hourly_burn_from_tfstate(state_data: Dict[str, Any]) -> Tuple[float, Dict[str, Any]]:
    """
    Parses Terraform / OpenTofu state JSON and computes the aggregate hourly burn rate.
    """
    hourly_burn = 0.0
    billable_summary = {}

    for resource in state_data.get("resources", []):
        rtype = resource.get("type")
        instances = resource.get("instances", [])
        if not instances:
            continue

        for inst in instances:
            attrs = inst.get("attributes", {})

            # 1. Cloud SQL Instances
            if rtype == "google_sql_database_instance":
                settings = attrs.get("settings", [])
                tier = "db-f1-micro"
                disk_size = 10
                if settings and isinstance(settings, list):
                    tier = settings[0].get("tier", "db-f1-micro")
                    disk_size = settings[0].get("disk_size", 10)

                tier_key = f"sql_{tier.replace('-', '_')}"
                tier_rate = HOURLY_RESOURCE_RATES.get(tier_key, HOURLY_RESOURCE_RATES["sql_db_f1_micro"])
                disk_rate = float(disk_size) * HOURLY_RESOURCE_RATES["sql_ssd_storage_gb_hour"]
                rate = tier_rate + disk_rate
                hourly_burn += rate
                billable_summary["cloud_sql"] = {
                    "instance_name": attrs.get("name", "postgres"),
                    "tier": tier,
                    "disk_gb": disk_size,
                    "hourly_rate": round(rate, 4),
                }

            # 2. Serverless VPC Access Connectors
            elif rtype == "google_vpc_access_connector":
                min_instances = attrs.get("min_instances", 2)
                rate = float(min_instances) * 0.0180
                hourly_burn += rate
                billable_summary["vpc_connector"] = {
                    "connector_name": attrs.get("name", "connector"),
                    "min_instances": min_instances,
                    "hourly_rate": round(rate, 4),
                }

            # 3. Cloud NAT Gateways
            elif rtype == "google_compute_router_nat":
                rate = HOURLY_RESOURCE_RATES["cloud_nat_gateway"]
                hourly_burn += rate
                billable_summary["cloud_nat"] = {
                    "nat_name": attrs.get("name", "nat-gateway"),
                    "hourly_rate": round(rate, 4),
                }

            # 4. GCE Compute Instances
            elif rtype == "google_compute_instance":
                mtype = attrs.get("machine_type", "e2-micro")
                rate = HOURLY_RESOURCE_RATES.get(f"compute_{mtype.replace('-', '_')}", 0.02)
                hourly_burn += rate
                billable_summary[f"gce_{attrs.get('name', 'vm')}"] = {
                    "machine_type": mtype,
                    "hourly_rate": round(rate, 4),
                }

            # 5. Cloud Run Min Instances (if configured)
            elif rtype in ("google_cloud_run_v2_service", "google_cloud_run_service"):
                template = attrs.get("template", [])
                min_inst = 0
                if template and isinstance(template, list):
                    scaling = template[0].get("scaling", [])
                    if scaling and isinstance(scaling, list):
                        min_inst = scaling[0].get("min_instance_count", 0)
                if min_inst > 0:
                    rate = float(min_inst) * HOURLY_RESOURCE_RATES["cloud_run_min_instance"]
                    hourly_burn += rate
                    billable_summary[f"cloud_run_{attrs.get('name', 'service')}"] = {
                        "min_instances": min_inst,
                        "hourly_rate": round(rate, 4),
                    }

    return round(hourly_burn, 5), billable_summary


def compute_accrued_spend(deployed_at_iso: Optional[str], hourly_rate: float, now: Optional[datetime] = None) -> float:
    """
    Computes accrued dollar spend based on uptime and hourly burn.
    """
    if hourly_rate <= 0 or not deployed_at_iso:
        return 0.0
    try:
        deployed_dt = datetime.fromisoformat(deployed_at_iso.replace("Z", "+00:00"))
        now_dt = now or datetime.now(timezone.utc)
        uptime_hours = max(0.05, (now_dt - deployed_dt).total_seconds() / 3600.0)
        return round(uptime_hours * hourly_rate, 2)
    except Exception as e:
        logger.warning(f"Error computing accrued spend from {deployed_at_iso}: {e}")
        return 0.0


def fetch_workload_state_from_gcs(
    product_id: str,
    host_project: str,
    storage_client: Optional[Any] = None,
) -> Optional[Dict[str, Any]]:
    """
    Fetches default.tfstate for the child workload from the platform GCS state bucket.
    """
    if os.getenv("TEST_MODE") == "true":
        return None
    try:
        from google.cloud import storage
        client = storage_client or storage.Client(project=host_project)
        bucket_name = f"castor-tfstate-{host_project}"
        # FD-7L Phase 3 (plan 2.9): Shared install -> the same bucket, nothing read; Per workload -> vending's signed
        # provenance record decides (an untrusted record raises and is logged below; no other bucket is tried).
        from services import runner_state
        bucket_name = runner_state.state_bucket(product_id, bucket_name)
        blob_path = f"workloads/{product_id}/default.tfstate"
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(blob_path)
        if not blob.exists():
            return None
        raw_text = blob.download_as_text()
        return json.loads(raw_text)
    except Exception as e:
        logger.warning(f"Could not load tfstate for {product_id} from GCS: {e}")
        return None


def query_bigquery_billing_export(
    project_id: str,
    billing_dataset: str,
    bq_client: Optional[Any] = None,
) -> Optional[float]:
    """
    Queries BigQuery standard billing export for the target project's current month spend.
    Returns float net cost, or None if unconfigured or error.
    """
    if not billing_dataset:
        return None
    if os.getenv("TEST_MODE") == "true" and not bq_client:
        return None
    try:
        try:
            from google.cloud import bigquery
            has_bq = True
        except ImportError:
            has_bq = False

        if bq_client:
            client = bq_client
        elif has_bq:
            client = bigquery.Client()
        else:
            return None

        query = f"""
        SELECT
          SUM(cost) + SUM(IFNULL((SELECT SUM(c.amount) FROM UNNEST(credits) c), 0)) AS net_cost
        FROM `{billing_dataset}.gcp_billing_export_v1_*`
        WHERE project.id = @project_id
          AND _PARTITIONDATE >= DATE_TRUNC(CURRENT_DATE(), MONTH)
        """
        if has_bq:
            job_config = bigquery.QueryJobConfig(
                query_parameters=[bigquery.ScalarQueryParameter("project_id", "STRING", project_id)]
            )
            query_job = client.query(query, job_config=job_config)
        else:
            query_job = client.query(query)
        rows = list(query_job.result())
        if rows and rows[0].net_cost is not None:
            return round(float(rows[0].net_cost), 2)
        return None
    except Exception as e:
        logger.debug(f"BigQuery billing query skipped or failed for {project_id}: {e}")
        return None


def reconcile_workload_spend(
    product_id: str,
    workload_data: Dict[str, Any],
    host_project: str,
    db: Optional[Any] = None,
    storage_client: Optional[Any] = None,
    bq_client: Optional[Any] = None,
) -> Dict[str, Any]:
    """
    Reconciles real-time spend for a workload, utilizing BigQuery, GCS tfstate, or cached hourly burn.
    """
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    # In TEST_MODE, return deterministic mock output unless explicitly testing live calculations
    if os.getenv("TEST_MODE") == "true" and not os.getenv("TEST_LIVE_FINOPS"):
        current_spend = float(workload_data.get("current_spend_usd", 12.50))
        proj_spend = float(workload_data.get("projected_monthly_spend_usd", 25.00))
        return {
            "current_spend_usd": current_spend,
            "projected_monthly_spend_usd": proj_spend,
            "cached_hourly_burn_usd": 0.05,
            "spend_source": "MOCK_TEST_MODE",
            "spend_last_updated_at": now_iso,
            "is_overrun_projected": False,
        }

    target_project = workload_data.get("project_id") or product_id
    budget_ceiling = float(workload_data.get("budget_ceiling_monthly_usd", 40.0))

    # 1. Check Authoritative BigQuery Export (if configured)
    bq_dataset = os.getenv("BILLING_EXPORT_DATASET", "")
    bq_cost = query_bigquery_billing_export(target_project, bq_dataset, bq_client=bq_client)

    if bq_cost is not None and bq_cost > 0.0:
        current_spend = bq_cost
        spend_source = "GCP_BILLING_EXPORT"
        cached_hourly = float(workload_data.get("cached_hourly_burn_usd", 0.0))
    else:
        # 2. Check Cached Hourly Burn in Firestore to avoid GCS read latency
        cached_hourly = workload_data.get("cached_hourly_burn_usd")
        deployed_at = workload_data.get("deployed_at") or workload_data.get("created_at")

        if cached_hourly is None and deployed_at:
            tfstate = fetch_workload_state_from_gcs(product_id, host_project, storage_client)
            if tfstate:
                cached_hourly, summary = calculate_hourly_burn_from_tfstate(tfstate)
                if db:
                    try:
                        db.collection("workloads").document(product_id).set({
                            "cached_hourly_burn_usd": cached_hourly,
                            "billable_resources_summary": summary,
                        }, merge=True)
                    except Exception as err:
                        logger.warning(f"Could not cache hourly burn in Firestore: {err}")
            else:
                cached_hourly = 0.0

        hourly_rate = float(cached_hourly or 0.0)
        current_spend = compute_accrued_spend(deployed_at, hourly_rate, now)
        spend_source = "ESTIMATED_ACTIVE_ACCRUAL" if current_spend > 0 else "GCP_BILLING_DEFAULT"

    # 3. Extrapolate Monthly Run-Rate Projection
    # If active hourly rate is known and > 0, project directly from the resource burn rate (730 billable hrs/mo)
    hourly_rate = float(cached_hourly or 0.0)
    if hourly_rate > 0.0:
        projected_spend = round(hourly_rate * 730.0, 2)
    else:
        # If hourly rate is unknown, check uptime to avoid diluting mid-month deployments
        deployed_at = workload_data.get("deployed_at") or workload_data.get("created_at")
        uptime_days = None
        if deployed_at:
            try:
                deployed_dt = datetime.fromisoformat(deployed_at.replace("Z", "+00:00"))
                uptime_days = max(0.04, (now - deployed_dt).total_seconds() / 86400.0)
            except Exception:
                pass

        _, total_days = calendar.monthrange(now.year, now.month)
        effective_days = min(float(max(1, now.day)), uptime_days) if uptime_days is not None else float(max(1, now.day))
        projected_spend = round((current_spend / max(0.04, effective_days)) * total_days, 2)

    is_overrun = projected_spend > budget_ceiling

    return {
        "current_spend_usd": current_spend,
        "projected_monthly_spend_usd": projected_spend,
        "cached_hourly_burn_usd": float(cached_hourly or 0.0),
        "spend_source": spend_source,
        "spend_last_updated_at": now_iso,
        "is_overrun_projected": is_overrun,
    }
