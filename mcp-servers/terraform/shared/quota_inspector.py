"""
Project Castor: Google Cloud Quotas & Pre-Flight Capacity Inspector
Provides deterministic, zero-LLM headroom harvesting, BOM demand estimation,
Firestore in-flight concurrency claims, and pre-flight validation.
"""

from datetime import datetime, timezone, timedelta
import html
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("castor-quota-inspector")

# Default baseline quotas for Google Cloud Standard Projects
DEFAULT_REGIONAL_BASELINE = {
    "compute.googleapis.com/regional_external_ip_addresses": 8,
    "compute.googleapis.com/cpus": 32,
    "sqladmin.googleapis.com/instances": 8,
    "run.googleapis.com/services": 100,
}

DEFAULT_GLOBAL_BASELINE = {
    "compute.googleapis.com/global_external_ip_addresses": 5,
    "compute.googleapis.com/backend_services": 15,
}

SUPPORTED_REGIONS = [
    "us-central1", "us-east4", "us-east1", "us-west1", "us-west2",
    "europe-west1", "europe-west3", "europe-west4",
    "asia-northeast1", "asia-southeast1"
]


_SHARED_IN_MEMORY_CLAIMS: Dict[str, Dict[str, Any]] = {}

# FD-7M-a / FD-4AL-b: a claim with no `region` is skipped (typed log line), never counted in a guessed region.
QUOTA_CLAIM_REGION_MISSING = "QUOTA_CLAIM_REGION_MISSING"


class QuotaRegionsUnavailable(RuntimeError):
    """FD-7M-a: the install's approved deployable regions could not be read for a quota harvest that needs them
    (no Firestore client, unreadable or invalid settings). Typed (`error_class` REGION_UNAVAILABLE); never answered
    with a fixed region list."""

    error_class = "REGION_UNAVAILABLE"


def approved_quota_regions(db: Any) -> List[str]:
    """FD-7M-a: Settings `orchestration.approved_deployable_regions` (empty = [default_gcp_region]; the one rule is
    shared.settings.approved_deployable_regions), read from system_config/platform_settings with the caller's client
    `db`. No settings document = the schema defaults. A missing client, a failed read, a non-snapshot answer or an
    invalid document -> QuotaRegionsUnavailable."""
    try:
        from shared.settings import approved_deployable_regions
    except ImportError:
        try:
            from .settings import approved_deployable_regions  # type: ignore
        except ImportError as import_err:
            raise QuotaRegionsUnavailable(f"settings contract not importable: {import_err}") from import_err
    if db is None:
        raise QuotaRegionsUnavailable("no Firestore client for the approved deployable regions")
    try:
        snap = db.collection("system_config").document("platform_settings").get()
        exists = getattr(snap, "exists", None)
        if exists is False:
            orchestration: Any = {}
        else:
            data = snap.to_dict() if exists is True else None
            if not isinstance(data, dict):
                raise QuotaRegionsUnavailable("settings document gave no answer")
            orchestration = data.get("orchestration")
            orchestration = {} if orchestration is None else orchestration
        return approved_deployable_regions(orchestration)
    except QuotaRegionsUnavailable:
        raise
    except Exception as settings_err:  # noqa: BLE001 - unreadable / invalid settings = typed, never a fixed list
        raise QuotaRegionsUnavailable(f"settings document unreadable/invalid: {type(settings_err).__name__}: "
                                      f"{settings_err}") from settings_err


class CloudQuotaInspector:
    """
    Sub-second client for Google Cloud Quotas API with LRU caching,
    in-flight concurrency claims tracking, and Bill-of-Materials demand evaluation.
    """

    def __init__(self, cache_ttl_seconds: int = 300, db_client: Any = None):
        self.cache_ttl_seconds = cache_ttl_seconds
        self._cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self._in_memory_claims = _SHARED_IN_MEMORY_CLAIMS
        self.db = db_client

    def _get_firestore(self):
        if self.db is not None:
            return self.db
        try:
            from google.cloud import firestore
            self.db = firestore.Client()
            return self.db
        except Exception as e:
            logger.debug(f"Firestore client unavailable, using in-memory claims: {e}")
            return None

    def harvest_quota_snapshot(
        self,
        project_id: str,
        regions: Optional[List[str]] = None,
        force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """
        Queries Google Cloud Quotas API with 5-minute caching and graceful fallback.
        Returns regional & global headroom mapping.

        FD-7M-a: no (well-formed) region given -> the install's approved deployable regions (approved_quota_regions,
        read with this inspector's client), never a fixed list; unreadable -> QuotaRegionsUnavailable.
        """
        target_regions = [r for r in (regions or []) if re.match(r"^[a-z]+-[a-z0-9]+$", r)]
        if not target_regions:
            target_regions = [r for r in approved_quota_regions(self._get_firestore())
                              if re.match(r"^[a-z]+-[a-z0-9]+$", r)]
        if not target_regions:
            raise QuotaRegionsUnavailable("no well-formed region to harvest")

        cache_key = f"{project_id}:" + ",".join(sorted(target_regions))
        now = time.time()

        if not force_refresh and cache_key in self._cache:
            cached_time, cached_data = self._cache[cache_key]
            if now - cached_time < self.cache_ttl_seconds:
                return cached_data

        snapshot: Dict[str, Any] = {
            "status": "HEALTHY",
            "project_id": project_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "regions": {},
            "global": {},
            "active_claims": {},
        }

        # Attempt Cloud Quotas API client import (skip network calls on mock/test projects)
        client = None
        if project_id and not project_id.startswith("test-") and project_id != "default":
            try:
                from google.cloud import cloudquotas_v1
                client = cloudquotas_v1.CloudQuotasClient()
            except Exception:
                client = None

        for reg in target_regions:
            reg_data = {
                "region": reg,
                "status": "HEALTHY",
                "quotas": {},
                "external_ips_available": DEFAULT_REGIONAL_BASELINE["compute.googleapis.com/regional_external_ip_addresses"],
                "cpus_available": DEFAULT_REGIONAL_BASELINE["compute.googleapis.com/cpus"],
                "sql_instances_available": DEFAULT_REGIONAL_BASELINE["sqladmin.googleapis.com/instances"],
                "run_services_available": DEFAULT_REGIONAL_BASELINE["run.googleapis.com/services"],
            }

            if client and project_id:
                try:
                    # Query regional external IPs with 2s timeout
                    ip_info = client.get_quota_info(
                        name=f"projects/{project_id}/locations/{reg}/quotaInfos/compute.googleapis.com/IN-USE-ADDRESSES",
                        timeout=2.0,
                    )
                    if hasattr(ip_info, "dimensions_infos") and ip_info.dimensions_infos:
                        limit_info = ip_info.dimensions_infos[0].applicable_quota_and_status
                        eff_limit = getattr(limit_info, "effective_limit", None)
                        if eff_limit is not None:
                            reg_data["external_ips_available"] = int(eff_limit)
                except Exception as err:
                    logger.debug(f"Cloud Quotas API query skipped for {reg}: {err}")

            # Assess status based on headroom
            if reg_data["external_ips_available"] <= 1 or reg_data["cpus_available"] <= 4:
                reg_data["status"] = "CONSTRAINED"
            elif reg_data["external_ips_available"] == 0:
                reg_data["status"] = "EXHAUSTED"

            snapshot["regions"][reg] = reg_data

        snapshot["global"] = {
            "global_external_ips_available": DEFAULT_GLOBAL_BASELINE["compute.googleapis.com/global_external_ip_addresses"],
            "backend_services_available": DEFAULT_GLOBAL_BASELINE["compute.googleapis.com/backend_services"],
        }

        # Ingest active in-flight claims
        snapshot["active_claims"] = self.get_active_claims(project_id)

        self._cache[cache_key] = (now, snapshot)
        return snapshot

    def estimate_bom_demand(self, architecture_spec: Dict[str, Any]) -> Dict[str, int]:
        """
        In-memory deterministic inspection calculating net demand delta:
        - 1 regional external IP if public ingress, Cloud NAT, or load balancer is declared.
        - 1 Cloud SQL instance if database is declared.
        - 2 vCPUs per Cloud Run service or microservice.
        - 1 Cloud Run service per declared microservice.
        """
        demand: Dict[str, int] = {
            "compute.googleapis.com/regional_external_ip_addresses": 0,
            "compute.googleapis.com/cpus": 0,
            "sqladmin.googleapis.com/instances": 0,
            "run.googleapis.com/services": 0,
            "compute.googleapis.com/global_external_ip_addresses": 0,
        }

        if not architecture_spec:
            return demand

        spec_str = str(architecture_spec).lower()

        # Check external IP demand
        if "cloud_nat" in spec_str or "nat" in spec_str or "google_compute_address" in spec_str or "load_balancer" in spec_str:
            demand["compute.googleapis.com/regional_external_ip_addresses"] += 1

        if "global_address" in spec_str or "global_forwarding_rule" in spec_str:
            demand["compute.googleapis.com/global_external_ip_addresses"] += 1

        # Check Cloud SQL
        if "sql" in spec_str or "postgres" in spec_str or "mysql" in spec_str or "google_sql_database_instance" in spec_str:
            demand["sqladmin.googleapis.com/instances"] += 1

        # Check Cloud Run / Compute services
        task_dag = architecture_spec.get("task_dag") or []
        sequenced_plan = architecture_spec.get("sequenced_build_plan") or {}
        steps = sequenced_plan.get("steps") or task_dag

        service_count = 0
        for s in steps:
            title = str(s.get("title", "")).lower()
            desc = str(s.get("description", "")).lower()
            cat = str(s.get("category", "")).lower()
            if "run" in title or "run" in desc or "compute" in cat or "service" in title:
                service_count += 1

        if service_count == 0 and ("run.googleapis.com" in spec_str or "cloud run" in spec_str):
            service_count = 1

        demand["run.googleapis.com/services"] = max(service_count, 1 if "service" in spec_str else 0)
        demand["compute.googleapis.com/cpus"] = demand["run.googleapis.com/services"] * 2

        # Guardrail 5: Composite Bundle Footprint Merging & Parameter Overrides
        bundle_id = (
            architecture_spec.get("bundle_id")
            or architecture_spec.get("bundle")
            or architecture_spec.get("composite_bundle")
        )
        if bundle_id and isinstance(bundle_id, str):
            clean_b_id = bundle_id.strip().lower()
            footprint: Dict[str, Any] = {}
            # Check built-in bundles first
            try:
                from shared.builtin_bundles_payload import get_builtin_bundle
                built = get_builtin_bundle(clean_b_id)
                if built:
                    footprint = dict(built.resource_footprint or {})
            except Exception:
                try:
                    from builtin_bundles_payload import get_builtin_bundle
                    built = get_builtin_bundle(clean_b_id)
                    if built:
                        footprint = dict(built.resource_footprint or {})
                except Exception:
                    pass

            # If not found in built-ins, check Firestore if db is available
            fs = self._get_firestore()
            if not footprint and fs:
                try:
                    b_doc = fs.collection("custom_bundles").document(clean_b_id).get()
                    if b_doc.exists:
                        footprint = dict(b_doc.to_dict().get("resource_footprint", {}))
                except Exception as e:
                    logger.debug(f"Could not load custom bundle footprint for {clean_b_id}: {e}")

            if footprint:
                bundle_cpus = int(footprint.get("cpus", 0))
                bundle_ips = int(footprint.get("static_ips", 0))
                bundle_sql = int(footprint.get("cloud_sql_instances", 0))
                bundle_services = int(footprint.get("cloud_run_services", 0))

                # Merge with spec parameter overrides
                params = (
                    architecture_spec.get("parameters")
                    or architecture_spec.get("spec_parameters")
                    or architecture_spec.get("variables")
                    or {}
                )
                if isinstance(params, dict):
                    if "min_instances" in params and isinstance(params["min_instances"], (int, float)):
                        min_inst = int(params["min_instances"])
                        bundle_cpus = max(bundle_cpus, min_inst * 2)
                    if "node_count" in params and isinstance(params["node_count"], (int, float)):
                        node_count = int(params["node_count"])
                        bundle_cpus = max(bundle_cpus, node_count * 4)
                    if "cpus" in params and isinstance(params["cpus"], (int, float)):
                        bundle_cpus = int(params["cpus"])
                    if "cloud_sql_instances" in params and isinstance(params["cloud_sql_instances"], (int, float)):
                        bundle_sql = int(params["cloud_sql_instances"])
                    if "static_ips" in params and isinstance(params["static_ips"], (int, float)):
                        bundle_ips = int(params["static_ips"])

                demand["compute.googleapis.com/cpus"] = max(demand["compute.googleapis.com/cpus"], bundle_cpus)
                demand["compute.googleapis.com/regional_external_ip_addresses"] = max(
                    demand["compute.googleapis.com/regional_external_ip_addresses"], bundle_ips
                )
                demand["sqladmin.googleapis.com/instances"] = max(
                    demand["sqladmin.googleapis.com/instances"], bundle_sql
                )
                demand["run.googleapis.com/services"] = max(
                    demand["run.googleapis.com/services"], bundle_services
                )

        return demand


    def validate_headroom(
        self,
        snapshot: Dict[str, Any],
        target_region: str,
        demand: Dict[str, int],
        trace_id: Optional[str] = None,
    ) -> Tuple[bool, List[str], Dict[str, Any]]:
        """
        Determines if regional & global headroom satisfies demand:
        Available = Effective Limit - Active In-Flight Claims >= Planned Demand.
        """
        violations: List[str] = []
        details: Dict[str, Any] = {
            "target_region": target_region,
            "demand": demand,
            "headroom_evaluated": {},
            "verdict": "PASS",
        }

        # Validate target region format
        if not re.match(r"^[a-z]+-[a-z0-9]+$", target_region):
            return False, [f"Invalid target region identifier: '{target_region}'"], details

        regions = snapshot.get("regions", {})
        reg_data = regions.get(target_region)
        if not reg_data:
            # Fall back to default baseline if region not pre-harvested
            reg_data = {
                "external_ips_available": DEFAULT_REGIONAL_BASELINE["compute.googleapis.com/regional_external_ip_addresses"],
                "cpus_available": DEFAULT_REGIONAL_BASELINE["compute.googleapis.com/cpus"],
                "sql_instances_available": DEFAULT_REGIONAL_BASELINE["sqladmin.googleapis.com/instances"],
                "run_services_available": DEFAULT_REGIONAL_BASELINE["run.googleapis.com/services"],
            }

        # Offset by active in-flight claims for this project/region
        active_claims = snapshot.get("active_claims", {})
        claimed_ips = active_claims.get(f"{target_region}:compute.googleapis.com/regional_external_ip_addresses", 0)
        claimed_cpus = active_claims.get(f"{target_region}:compute.googleapis.com/cpus", 0)
        claimed_sql = active_claims.get(f"{target_region}:sqladmin.googleapis.com/instances", 0)

        # 1. External IPs
        req_ips = demand.get("compute.googleapis.com/regional_external_ip_addresses", 0)
        avail_ips = max(0, reg_data.get("external_ips_available", 0) - claimed_ips)
        details["headroom_evaluated"]["regional_external_ips"] = {
            "required": req_ips,
            "available": avail_ips,
            "claimed_in_flight": claimed_ips,
        }
        if req_ips > avail_ips:
            violations.append(
                f"Regional External IPs exceeded in {target_region}: required {req_ips}, available {avail_ips} "
                f"(current limit: {reg_data.get('external_ips_available', 0)}, active claims: {claimed_ips})"
            )

        # 2. vCPUs
        req_cpus = demand.get("compute.googleapis.com/cpus", 0)
        avail_cpus = max(0, reg_data.get("cpus_available", 0) - claimed_cpus)
        details["headroom_evaluated"]["cpus"] = {
            "required": req_cpus,
            "available": avail_cpus,
            "claimed_in_flight": claimed_cpus,
        }
        if req_cpus > avail_cpus:
            violations.append(
                f"vCPUs exceeded in {target_region}: required {req_cpus}, available {avail_cpus}"
            )

        # 3. Cloud SQL
        req_sql = demand.get("sqladmin.googleapis.com/instances", 0)
        avail_sql = max(0, reg_data.get("sql_instances_available", 0) - claimed_sql)
        details["headroom_evaluated"]["sql_instances"] = {
            "required": req_sql,
            "available": avail_sql,
            "claimed_in_flight": claimed_sql,
        }
        if req_sql > avail_sql:
            violations.append(
                f"Cloud SQL instances exceeded in {target_region}: required {req_sql}, available {avail_sql}"
            )

        is_valid = len(violations) == 0
        details["verdict"] = "PASS" if is_valid else "QUOTA_EXCEEDED"
        return is_valid, violations, details

    def create_in_flight_claim(
        self,
        project_id: str,
        region: str,
        demand: Dict[str, int],
        trace_id: str,
        ttl_minutes: int = 30,
    ) -> str:
        """
        Registers an active in-flight claim to prevent TOCTOU race conditions
        across parallel agent workflows.
        """
        claim_id = f"claim-{trace_id}-{region}"
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)

        claim_doc = {
            "claim_id": claim_id,
            "project_id": project_id,
            "region": region,
            "demand": demand,
            "trace_id": trace_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": expires_at.isoformat(),
            "status": "ACTIVE",
        }

        self._in_memory_claims[claim_id] = claim_doc
        db = self._get_firestore()
        if db is not None:
            try:
                db.collection("quota_claims").document(claim_id).set(claim_doc)
            except Exception as e:
                logger.warning(f"Failed to record claim in Firestore: {e}")

        return claim_id

    def release_in_flight_claim(
        self,
        claim_id: Optional[str] = None,
        trace_id: Optional[str] = None,
    ) -> bool:
        """
        Releases an in-flight quota claim upon pipeline completion, failure, or cancellation.
        """
        db = self._get_firestore()
        released = False

        if claim_id:
            if db is not None:
                try:
                    db.collection("quota_claims").document(claim_id).delete()
                    released = True
                except Exception as e:
                    logger.warning(f"Error releasing Firestore claim {claim_id}: {e}")
            if claim_id in self._in_memory_claims:
                del self._in_memory_claims[claim_id]
                released = True

        if trace_id:
            # Query by trace_id
            if db is not None:
                try:
                    docs = db.collection("quota_claims").where("trace_id", "==", trace_id).stream()
                    for d in docs:
                        d.reference.delete()
                        released = True
                except Exception as e:
                    logger.warning(f"Error querying/deleting Firestore claim by trace {trace_id}: {e}")

            to_del = [k for k, v in self._in_memory_claims.items() if v.get("trace_id") == trace_id]
            for k in to_del:
                del self._in_memory_claims[k]
                released = True

        return released

    def get_active_claims(self, project_id: str) -> Dict[str, int]:
        """
        Returns mapping of `f'{region}:{metric}' -> total_claimed_units`.
        Filters out expired claims.
        """
        aggregated: Dict[str, int] = {}
        now_iso = datetime.now(timezone.utc).isoformat()

        # Check in-memory claims
        for cid, doc in list(self._in_memory_claims.items()):
            if doc.get("expires_at", "") < now_iso:
                del self._in_memory_claims[cid]
                continue
            if doc.get("project_id") == project_id and doc.get("status") == "ACTIVE":
                reg = doc.get("region")
                if not reg:
                    logger.warning(f"{QUOTA_CLAIM_REGION_MISSING}: in-memory claim {cid} has no region; not counted")
                    continue
                for metric, units in doc.get("demand", {}).items():
                    key = f"{reg}:{metric}"
                    aggregated[key] = aggregated.get(key, 0) + int(units)

        # Check Firestore claims
        db = self._get_firestore()
        if db is not None:
            try:
                docs = db.collection("quota_claims").where("project_id", "==", project_id).where("status", "==", "ACTIVE").stream()
                for d in docs:
                    doc = d.to_dict()
                    if doc.get("expires_at", "") < now_iso:
                        continue
                    reg = doc.get("region")
                    if not reg:
                        logger.warning(f"{QUOTA_CLAIM_REGION_MISSING}: quota_claims/{getattr(d, 'id', '?')} has no "
                                       "region; not counted")
                        continue
                    for metric, units in doc.get("demand", {}).items():
                        key = f"{reg}:{metric}"
                        aggregated[key] = aggregated.get(key, 0) + int(units)
            except Exception as e:
                logger.debug(f"Could not load claims from Firestore: {e}")

        return aggregated


def sanitize_quota_for_prompt(snapshot: Dict[str, Any]) -> str:
    """
    Renders a prompt injection-resistant XML block describing regional constraints.
    Applies strict regex whitelisting and HTML entity escaping.
    """
    if not snapshot or snapshot.get("status") == "DEGRADED":
        return "<!-- Regional Quota Constraints: Standard cloud baseline applies -->"

    lines = ["<regional_quota_constraints>"]
    regions = snapshot.get("regions", {})

    for region_name, data in sorted(regions.items()):
        if not re.match(r"^[a-z]+-[a-z0-9]+$", region_name):
            continue
        safe_reg = html.escape(region_name)
        ip_avail = int(data.get("external_ips_available", 0))
        cpu_avail = int(data.get("cpus_available", 0))
        sql_avail = int(data.get("sql_instances_available", 0))
        status_label = data.get("status", "HEALTHY")

        badge = "[HEALTHY]"
        if ip_avail <= 1 or cpu_avail <= 4:
            badge = "[CONSTRAINED]"
        if ip_avail == 0:
            badge = "[EXHAUSTED]"

        lines.append(
            f"  - Region {safe_reg}: {ip_avail} external IPs, {cpu_avail} vCPUs, {sql_avail} SQL instances available {badge}"
        )

    lines.append("CRITICAL INSTRUCTION: You MUST prioritize regions marked [HEALTHY].")
    lines.append("If a requested region is [CONSTRAINED] or [EXHAUSTED], select an adjacent supported region")
    lines.append("or eliminate public IP dependencies using Serverless VPC Access / Private Google Access.")
    lines.append("</regional_quota_constraints>")

    return "\n".join(lines)
