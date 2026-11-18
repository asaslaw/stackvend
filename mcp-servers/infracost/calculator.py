"""
Project Castor: Infracost Calculator & Cost Sentinel Engine
Calculates hourly and monthly delta costs for Terraform plans and enforces dynamic, per-workload Firestore budget boundaries.
"""

import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from google.cloud import firestore

logger = logging.getLogger("mcp-infracost-server")
logging.basicConfig(level=logging.INFO)

# Default estimated monthly pricing for common Google Cloud Platform resources (USD)
GCP_RESOURCE_PRICING = {
    # Serverless (scale-to-zero)
    "google_cloud_run_v2_service": {"base_monthly": 0.0, "min_instance_cost": 22.50},
    "google_cloud_run_service": {"base_monthly": 0.0, "min_instance_cost": 22.50},
    "google_cloud_run_v2_job": {"base_monthly": 0.0},
    "google_workflows_workflow": {"base_monthly": 0.0},
    "google_pubsub_topic": {"base_monthly": 0.0},
    "google_pubsub_subscription": {"base_monthly": 0.0},   # FD-4AG-b: no base fee (usage-billed, like the topic)
    "google_firestore_database": {"base_monthly": 0.0},
    "google_storage_bucket": {"base_monthly": 0.50},
    "google_artifact_registry_repository": {"base_monthly": 0.20},
    "google_secret_manager_secret": {"base_monthly": 0.06},
    "google_cloud_scheduler_job": {"base_monthly": 0.10},
    # Dedicated / Higher Cost Compute & Databases
    "google_sql_database_instance": {"base_monthly": 15.00},
    "google_compute_instance": {"base_monthly": 25.00},
    "google_container_cluster": {"base_monthly": 73.00},
    # FD-4AG-b-r F1: every shared/service_topology.py BOOTSTRAP_CATALOG type has a row (parity-tested), so a typed
    # topology resource is never unpriced. Memorystore Basic M1 (1 GB) is about $35/mo (owner to confirm the figure);
    # a BigQuery dataset has no base fee (storage / query usage-billed).
    "google_redis_instance": {"base_monthly": 35.00},
    "google_bigquery_dataset": {"base_monthly": 0.0},
    # TI-5-R2: the three types the topology catalog gained (owner to confirm the figures; golden-module defaults):
    # AlloyDB primary 2 vCPU / 16 GB (~$0.066 per vCPU-h + ~$0.0112 per GB-h), one-node Bigtable cluster (~$0.65 per
    # node-h, storage usage-billed), a Vertex AI endpoint has no base fee (a deployed model is billed per node-hour).
    "google_alloydb_instance": {"base_monthly": 227.00},
    "google_bigtable_instance": {"base_monthly": 475.00},
    "google_vertex_ai_endpoint": {"base_monthly": 0.0},
}

# FD-4AG-b-r F7: the Terraform types that have Cloud Run min instances (exact set; a v2 job has none).
MIN_INSTANCE_TYPES = frozenset({"google_cloud_run_v2_service", "google_cloud_run_service"})
# FD-4AG-b-r F3: the typed compute kinds whose `scaling.min_instances` is billed per always-on instance.
MIN_INSTANCE_KINDS = frozenset({"cloudrun", "event-worker"})
MIN_INSTANCE_MONTHLY = GCP_RESOURCE_PRICING["google_cloud_run_v2_service"]["min_instance_cost"]

# FD-4AG-b (AG-5): the architect plan is priced from its TYPED compute fields only, never from task description
# text (AGENTS.md invariant 2). One row per exact value of shared/service_topology.py `ComputeKind` plus the
# "foundation-only" archetype (architect_agent/schemas.py `ComputeArchetype`). Figures are monthly USD:
#   cloudrun / event-worker: $0 (scale to zero; today's "Cloud Run (Scale to Zero)" figure),
#   gke-autopilot:            $73 and high risk (today's "GKE Cluster" figure and flag),
#   gce-bastion / gce-worker: $25 (GCP_RESOURCE_PRICING["google_compute_instance"]; the keyword chain had no VM row),
#   foundation-only:          $0 (no compute).
# A value that is not a key here is reported as unpriced, never guessed.
COMPUTE_KIND_PRICING: Dict[str, Dict[str, Any]] = {
    "cloudrun": {"label": "Cloud Run (Scale to Zero)", "monthly_cost": 0.00, "high_risk": False},
    "event-worker": {"label": "Cloud Run event worker (Scale to Zero)", "monthly_cost": 0.00, "high_risk": False},
    "gke-autopilot": {"label": "GKE Autopilot Cluster", "monthly_cost": 73.00, "high_risk": True},
    "gce-bastion": {"label": "Compute Engine bastion VM", "monthly_cost": 25.00, "high_risk": False},
    "gce-worker": {"label": "Compute Engine worker VM", "monthly_cost": 25.00, "high_risk": False},
    "foundation-only": {"label": "Foundation only (no compute)", "monthly_cost": 0.00, "high_risk": False},
}

# Where the typed compute fields come from (response key `pricing_source`).
PRICING_SOURCE_REQUEST = "request_compute_intent"        # no persisted record; the caller's architect_compute_intent
PRICING_SOURCE_FIRESTORE = "pipeline_executions_compute_intent"  # pipeline_executions/{trace}.architect_compute_intent
PRICING_SOURCE_NONE = "no_typed_fields"                  # nothing typed: every task is listed as unpriced

# FD-4AG-b-r F2/F4: fail closed when the compute could not be priced (response key `approval_reasons`).
APPROVAL_NO_TYPED_RECORD = "NO_TYPED_COMPUTE_RECORD"
APPROVAL_UNPRICED_COMPUTE = "UNPRICED_COMPUTE_KIND"
APPROVAL_INCONSISTENT_RECORD = "INCONSISTENT_COMPUTE_RECORD"
APPROVAL_REASON_TEXT = {
    APPROVAL_NO_TYPED_RECORD: "No typed compute record for trace '{trace_id}': the plan's compute was not priced.",
    APPROVAL_UNPRICED_COMPUTE: "A compute service has a kind with no price row (or no kind).",
    APPROVAL_INCONSISTENT_RECORD: "The record's compute_archetype is not among its service_topology kinds.",
}


class ComputeIntentUnavailableError(RuntimeError):
    """The architect's persisted compute intent could not be READ (Firestore error). Raised, never swallowed: the
    /evaluate route answers 500, so the workflow records FINOPS_UNAVAILABLE and the plan needs approval (AG-3)."""


class InfracostCalculator:
    def __init__(
        self,
        default_budget_ceiling: float = 40.0,
        project_id: Optional[str] = None,
        firestore_client: Optional[Any] = None,
    ):
        self.default_budget_ceiling = float(
            os.getenv("BUDGET_CEILING_MONTHLY", str(default_budget_ceiling))
        )
        self.project_id = project_id or os.getenv("PROJECT_ID", "")

        if firestore_client:
            self.db = firestore_client
        else:
            try:
                self.db = firestore.Client(project=self.project_id) if self.project_id else None
            except Exception as e:
                logger.warning(f"Could not initialize Firestore client for Infracost: {e}")
                self.db = None

    def get_workload_budget_ceiling(self, product_id: str, fallback_ceiling: Optional[float] = None) -> float:
        """
        Dynamically fetches the per-workload budget ceiling from the Firestore
        'workloads/{product_id}' collection, falling back to platform default if unset.
        """
        if self.db and product_id:
            try:
                doc = self.db.collection("workloads").document(product_id).get()
                if doc.exists:
                    data = doc.to_dict() or {}
                    if "budget_ceiling_monthly_usd" in data:
                        custom_budget = float(data["budget_ceiling_monthly_usd"])
                        logger.info(f"Loaded dynamic budget ceiling for '{product_id}' from Firestore: ${custom_budget:.2f}/mo")
                        return custom_budget
            except Exception as e:
                logger.warning(f"Could not query Firestore for workload '{product_id}' budget: {e}")

        return fallback_ceiling if fallback_ceiling is not None else self.default_budget_ceiling

    def estimate_resource_cost(self, resource_type: str, resource_config: Dict[str, Any]) -> float:
        """Estimates monthly cost in USD for a single GCP resource."""
        pricing = GCP_RESOURCE_PRICING.get(resource_type)
        if not pricing:
            return 0.0

        base_cost = pricing.get("base_monthly", 0.0)

        # Check for min_instances on Cloud Run (F7: exact type set; a non-dict `scaling` shape is not read)
        if resource_type in MIN_INSTANCE_TYPES:
            scaling = resource_config.get("scaling") if isinstance(resource_config, dict) else None
            min_instances = scaling.get("min_instance_count", 0) if isinstance(scaling, dict) else 0
            if isinstance(min_instances, (int, float)) and not isinstance(min_instances, bool) and min_instances > 0:
                base_cost += min_instances * pricing.get("min_instance_cost", 22.50)

        return base_cost

    def load_compute_intent(self, trace_id: str) -> Optional[Dict[str, Any]]:
        """The architect's typed compute record for this run: `pipeline_executions/{trace_id}.architect_compute_intent`
        (written by the architect's topology gate before the workflow reaches FinOps; the developer reads the same
        record). None when there is no Firestore client, no trace id, no document or no record. A READ ERROR raises
        ComputeIntentUnavailableError (fail closed: the route answers 500 -> FINOPS_UNAVAILABLE -> approval)."""
        if not self.db or not trace_id:
            return None
        try:
            doc = self.db.collection("pipeline_executions").document(trace_id).get()
        except Exception as e:  # noqa: BLE001 - re-raised typed, never swallowed
            raise ComputeIntentUnavailableError(
                f"architect compute intent for trace '{trace_id}' could not be read: {type(e).__name__}: {e}") from e
        if not getattr(doc, "exists", False):
            return None
        record = (doc.to_dict() or {}).get("architect_compute_intent")
        return record if isinstance(record, dict) else None

    @staticmethod
    def _price_kind(name: str, kind: Any, scaling: Any = None) -> List[Dict[str, Any]]:
        """Breakdown lines for one compute service, by exact table lookup on its typed kind (`line: "compute"`), plus
        one line for its typed `scaling.min_instances` when the kind bills always-on instances (F3)."""
        row = COMPUTE_KIND_PRICING.get(kind) if isinstance(kind, str) else None
        if row is None:
            return [{"resource": f"{name} (kind {kind!r})" if name else repr(kind), "line": "compute", "kind": kind,
                     "monthly_cost": None, "priced": False}]
        label = row["label"]
        lines = [{"resource": f"{name} ({label})" if name else label, "line": "compute", "kind": kind,
                  "monthly_cost": row["monthly_cost"], "priced": True, "high_risk": row["high_risk"]}]
        min_instances = scaling.get("min_instances", 0) if isinstance(scaling, dict) else 0
        if (kind in MIN_INSTANCE_KINDS and isinstance(min_instances, int) and not isinstance(min_instances, bool)
                and min_instances > 0):
            lines.append({"resource": f"{name or kind} min instances x{min_instances}", "line": "min_instances",
                          "kind": kind, "monthly_cost": round(min_instances * MIN_INSTANCE_MONTHLY, 2),
                          "priced": True, "high_risk": False})
        return lines

    @staticmethod
    def _price_resource(resource: Any) -> Dict[str, Any]:
        """One breakdown line for one typed topology resource, by exact lookup of its Terraform type."""
        rtype = resource.get("type") if isinstance(resource, dict) else None
        lname = resource.get("logical_name") if isinstance(resource, dict) else None
        label = f"{rtype}.{lname}" if isinstance(rtype, str) and isinstance(lname, str) else repr(rtype)
        pricing = GCP_RESOURCE_PRICING.get(rtype) if isinstance(rtype, str) else None
        if pricing is None:
            return {"resource": label, "line": "resource", "resource_type": rtype, "monthly_cost": None,
                    "priced": False}
        return {"resource": label, "line": "resource", "resource_type": rtype,
                "monthly_cost": float(pricing.get("base_monthly", 0.0)), "priced": True, "high_risk": False}

    def price_compute_intent(self, intent: Dict[str, Any]) -> Tuple[Optional[List[Dict[str, Any]]], bool]:
        """(breakdown lines, inconsistent) from the typed record (architect_agent/schemas.py compute_intent_record);
        lines is None when it has no typed compute fields. v2: every `service_topology.intent.services[]` once by
        `kind` (+ its `scaling.min_instances`), plus every `service_topology.intent.resources[]` by `type`;
        `services == []` is foundation-only. F4: a `compute_archetype` that is not among the services' kinds (or a
        compute archetype with no services) makes the record inconsistent; the archetype is then priced too (max,
        never min). v1 (no topology): `compute_archetype` for `target_compute_services[0]`, and
        `target_compute_services[1:]` as Cloud Run services (the schema's contract for that list)."""
        archetype = intent.get("compute_archetype")
        topo = intent.get("service_topology")
        topo_intent = topo.get("intent") if isinstance(topo, dict) else None
        if isinstance(topo_intent, dict) and isinstance(topo_intent.get("services"), list):
            services = topo_intent["services"]
            lines: List[Dict[str, Any]] = []
            for s in services:
                if isinstance(s, dict):
                    lines.extend(self._price_kind(s.get("name", ""), s.get("kind"), s.get("scaling")))
                else:
                    lines.extend(self._price_kind("", s))
            if not services:
                lines.extend(self._price_kind("", "foundation-only"))
            resources = topo_intent.get("resources")
            for r in resources if isinstance(resources, list) else []:
                lines.append(self._price_resource(r))
            present = {s.get("kind") for s in services if isinstance(s, dict)} if services else {"foundation-only"}
            inconsistent = archetype is not None and (not isinstance(archetype, str) or archetype not in present)
            if inconsistent:
                lines.extend(self._price_kind("compute_archetype", archetype))
            return lines, inconsistent
        if archetype is None:
            return None, False
        tcs = intent.get("target_compute_services")
        names = [str(n) for n in tcs] if isinstance(tcs, list) else []
        lines = self._price_kind(names[0] if names else "", archetype)
        for n in names[1:]:
            lines.extend(self._price_kind(n, "cloudrun"))
        return lines, False

    def evaluate_infra_plan(
        self,
        product_id: str,
        trace_id: str,
        proposed_infra_plan: Optional[Dict[str, Any]] = None,
        budget_ceiling: Optional[float] = None,
        compute_intent: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Evaluates a proposed infrastructure plan against the dynamic per-workload budget ceiling.

        FD-4AG-b: priced ONLY from the architect's typed compute fields with COMPUTE_KIND_PRICING /
        GCP_RESOURCE_PRICING. Source (F5): the gated record persisted at pipeline_executions/{trace_id}
        .architect_compute_intent; the request's `compute_intent` only when there is no DB or no persisted record.
        Task titles and descriptions never change a price.

        Approval: over budget, a high-risk kind (GKE), the plan's own `requires_approval`, and (FD-4AG-b-r F2/F4)
        fail closed when the compute could not be priced: no typed record for a plan with tasks, an unpriced compute
        kind (incl. a service without `kind`), or an inconsistent record. An unpriced RESOURCE type only makes the
        estimate a lower bound (every topology catalog type has a price row).
        """
        # Resolve dynamic budget ceiling from Firestore if not explicitly passed
        ceiling = (
            budget_ceiling
            if budget_ceiling is not None
            else self.get_workload_budget_ceiling(product_id)
        )

        proposed = proposed_infra_plan or {}
        tasks = proposed.get("tasks", [])
        tasks = tasks if isinstance(tasks, list) else []

        intent, pricing_source = self.load_compute_intent(trace_id), PRICING_SOURCE_FIRESTORE
        if intent is None and isinstance(compute_intent, dict):
            intent, pricing_source = compute_intent, PRICING_SOURCE_REQUEST
        resource_breakdown, inconsistent = self.price_compute_intent(intent) if intent is not None else (None, False)
        if resource_breakdown is None:
            pricing_source = PRICING_SOURCE_NONE
            resource_breakdown = [
                {"resource": (t.get("title") if isinstance(t, dict) else None) or "Standard Resource",
                 "line": "task", "monthly_cost": None, "priced": False}
                for t in tasks
            ]

        monthly_delta = sum(line["monthly_cost"] for line in resource_breakdown if line.get("priced"))
        high_risk_detected = any(line.get("high_risk") is True for line in resource_breakdown)
        unpriced_items = sum(1 for line in resource_breakdown if not line.get("priced"))
        lower_bound = unpriced_items > 0

        approval_reasons: List[str] = []
        if pricing_source == PRICING_SOURCE_NONE and tasks:
            approval_reasons.append(APPROVAL_NO_TYPED_RECORD)
        if any(line.get("line") == "compute" and not line.get("priced") for line in resource_breakdown):
            approval_reasons.append(APPROVAL_UNPRICED_COMPUTE)
        if inconsistent:
            approval_reasons.append(APPROVAL_INCONSISTENT_RECORD)

        is_under_budget = monthly_delta <= ceiling
        requires_approval = ((not is_under_budget) or high_risk_detected or proposed.get("requires_approval", False)
                             or bool(approval_reasons))

        if not is_under_budget:
            risk_assessment = (
                f"Projected monthly cost delta of +${monthly_delta:.2f}/mo exceeds the "
                f"workload budget ceiling of ${ceiling:.2f}/mo. Tier 3 Human-in-the-Loop approval required."
            )
        elif high_risk_detected:
            risk_assessment = "High-cost dedicated infrastructure detected (GKE). Tier 3 Human-in-the-Loop approval required."
        elif approval_reasons:
            risk_assessment = (
                f"Projected monthly cost delta is at least +${monthly_delta:.2f}/mo, but the compute could not be "
                f"priced from typed fields. Tier 3 Human-in-the-Loop approval required."
            )
        else:
            risk_assessment = (
                f"Projected monthly cost delta is +${monthly_delta:.2f}/mo, within the "
                f"workload budget ceiling of ${ceiling:.2f}/mo. 100% Policy-Bounded Autonomous rollout approved."
            )
        for reason in approval_reasons:
            risk_assessment += " " + APPROVAL_REASON_TEXT[reason].format(trace_id=trace_id)
        estimate = f"+${monthly_delta:.2f}/mo"
        if lower_bound:
            estimate += f" (lower bound; {unpriced_items} unpriced)"
            risk_assessment += (f" {unpriced_items} item(s) could not be priced from the plan's typed fields; "
                                "the estimate is a lower bound.")

        return {
            "product_id": product_id,
            "trace_id": trace_id,
            "monthly_cost_estimate": estimate,
            "monthly_cost_delta_usd": round(monthly_delta, 2),
            "budget_ceiling_usd": round(ceiling, 2),
            "is_under_budget": is_under_budget,
            "requires_human_approval": requires_approval,
            "breakdown": resource_breakdown,
            "unpriced_items": unpriced_items,
            "estimate_is_lower_bound": lower_bound,
            "pricing_source": pricing_source,
            "approval_reasons": approval_reasons,
            "risk_assessment": risk_assessment,
            "status": "EVALUATED",
        }

    def evaluate_terraform_plan_json(
        self, plan_json: Dict[str, Any], product_id: Optional[str] = None, budget_ceiling: Optional[float] = None
    ) -> Dict[str, Any]:
        """Evaluates raw terraform show -json output against the dynamic workload budget."""
        ceiling = (
            budget_ceiling
            if budget_ceiling is not None
            else (self.get_workload_budget_ceiling(product_id) if product_id else self.default_budget_ceiling)
        )

        resource_changes = plan_json.get("resource_changes", [])
        monthly_delta = 0.0
        breakdown = []
        has_destructive_change = False

        for change in resource_changes:
            res_type = change.get("type", "")
            res_name = change.get("name", "")
            actions = change.get("change", {}).get("actions", [])
            after_config = change.get("change", {}).get("after", {}) or {}

            if "delete" in actions:
                has_destructive_change = True

            if "create" in actions:
                cost = self.estimate_resource_cost(res_type, after_config)
                monthly_delta += cost
                breakdown.append({
                    "resource": f"{res_type}.{res_name}",
                    "action": "create",
                    "monthly_cost": cost,
                })

        is_under_budget = monthly_delta <= ceiling
        requires_approval = (not is_under_budget) or has_destructive_change

        return {
            "monthly_cost_estimate": f"+${monthly_delta:.2f}/mo",
            "monthly_cost_delta_usd": round(monthly_delta, 2),
            "budget_ceiling_usd": round(ceiling, 2),
            "is_under_budget": is_under_budget,
            "has_destructive_change": has_destructive_change,
            "requires_human_approval": requires_approval,
            "breakdown": breakdown,
            "risk_assessment": (
                "Destructive change detected." if has_destructive_change else
                f"Projected cost delta: +${monthly_delta:.2f}/mo (Workload Ceiling: ${ceiling:.2f}/mo)"
            ),
        }
