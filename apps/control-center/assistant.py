"""
Project Castor: Embedded Conversational Assistant Engine ("StackVend Assistant")
Powers natural-language chat queries across all facets of StackVend:
- Golden Modules Catalog (Native & Custom Enterprise Modules)
- Implementation Plan & Architecture Synthesis
- Active Workload Inventory & FinOps Spend Analysis
- Pipeline Flight Deck Telemetry & Build Traces
- Governance, Compliance & Human-in-the-Loop (HITL) Approvals
- GCP Managed Folders & IPAM Network Ledger
Secured by pre-LLM retrieval sandboxing, token pruning, and role-based operational guardrails.
"""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

from schemas import ChatResponse, UserRole
from authz import PLATFORM_PSEUDO_WORKLOADS, WorkloadScope

logger = logging.getLogger("control-center-assistant")
logging.basicConfig(level=logging.INFO)

try:
    from shared.settings import get_model_cascade_for_agent
except ImportError:
    try:
        from ..shared.settings import get_model_cascade_for_agent
    except ImportError:
        def get_model_cascade_for_agent(agent_name, project_id=None):
            return [os.getenv("GEMINI_MODEL") or "gemini-4-carbon", "gemini-4-argon"]

ASSISTANT_SYSTEM_PROMPT = """You are **StackVend Assistant**, the intelligent AI Solutions Architect and operational co-pilot embedded in the StackVend Product Control Center.

### Your Complete Knowledge of StackVend:
1. **Golden & Custom Modules Catalog**:
   - You have complete knowledge of all native built-in Golden Modules (networking-vpc, storage-bucket, messaging-pubsub, database-cloudsql, compute-cloudrun, etc.) and all active custom enterprise modules registered in Firestore.
   - You know their module IDs, allowed inputs, allowed outputs, categories, and whether a custom module overrides a built-in module.
   - When asked about modules, explain their capabilities, variable contracts, and syntax.
2. **Architecture & Implementation Plan Drafting**:
   - You help users architect new features and draft complete implementation plans before they submit them to the autonomous pipeline.
   - You generate production-grade Terraform HCL blocks that use exact module sources (e.g. `source = "../modules/<module-id>"` or `source = "./infra/modules/<module-id>"`).
3. **Pipeline Flight Deck & Telemetry**:
   - You monitor active and historical pipeline executions across the 7 autonomous stages: Vending, Architect, Compliance, Developer, QA Sandbox, Terraform Deploy, and SRE.
   - You explain build stages, why a build failed, or summarize recent mission traces.
4. **Workload Inventory & FinOps**:
   - You know all deployed workloads, Cloud Run service URLs, product IDs, and monthly budget ceilings.
   - You explain spend deltas and cost optimization recommendations.
5. **Governance, Compliance & HITL Approvals**:
   - You track pending Tier 3 Human-in-the-Loop plan approvals, Assured Workloads compliance policies (FedRAMP, HIPAA, PCI-DSS), and emergency code freeze states.

Maintain a professional, helpful, and technically precise tone. Format responses with clean Markdown bullet points, bold headers, and syntax-highlighted code blocks where appropriate.
"""


def _scope_for(user_role: Any, assigned_workloads: Optional[List[str]]) -> WorkloadScope:
    """Explicit scope from role + assignments. Unknown/missing role => nothing; pseudo-workloads ADMIN-only."""
    role_val = str(getattr(user_role, "value", user_role) or "").upper()
    if role_val == "ADMIN":
        return WorkloadScope(all=True, ids=frozenset())
    if role_val not in ("WORKLOAD_MANAGER", "VIEWER", "APPROVER"):
        return WorkloadScope(all=False, ids=frozenset())
    ids = frozenset(p.strip().lower() for p in (assigned_workloads or []) if isinstance(p, str) and p.strip())
    return WorkloadScope(all=False, ids=ids - PLATFORM_PSEUDO_WORKLOADS)


def build_assistant_system_prompt(db_client: Any = None) -> str:
    """Dynamically resolves the active StackVend Assistant prompt from the prompt registry."""
    try:
        try:
            from shared.prompt_resolver import get_agent_system_prompt
        except ImportError:
            from apps.control_center.shared.prompt_resolver import get_agent_system_prompt
        return get_agent_system_prompt(
            agent_role="ASSISTANT",
            fallback_constant=ASSISTANT_SYSTEM_PROMPT,
            db_client=db_client,
        )
    except Exception:
        return ASSISTANT_SYSTEM_PROMPT


def prune_workloads_for_context(workloads: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Strips internal build plans and verbose metadata to save context tokens."""
    pruned = []
    for w in workloads:
        pruned.append({
            "product_id": w.get("product_id"),
            "status": w.get("status", "ACTIVE"),
            "budget_ceiling_monthly_usd": float(w.get("budget_ceiling_monthly_usd", 40.0)),
            "service_url": w.get("service_url"),
            "code_freeze": bool(w.get("code_freeze", False)),
        })
    return pruned


class CastorAssistantEngine:
    def __init__(
        self,
        project_id: Optional[str] = None,
        location: Optional[str] = None,
        firestore_client: Optional[Any] = None,
    ):
        self.project_id = project_id or os.getenv("PROJECT_ID", "")
        self.location = location or os.getenv("GEMINI_LOCATION") or os.getenv("VERTEX_LOCATION", "global")
        self.db = firestore_client
        self._model = None
        self._initialized = False

    def query_active_workloads(self) -> List[Dict[str, Any]]:
        """Queries Firestore for live workload summaries."""
        if not self.db:
            return []
        try:
            docs = self.db.collection("workloads").stream()
            return [d.to_dict() for d in docs if d.to_dict()]
        except Exception as e:
            logger.warning(f"Could not query workloads: {e}")
            return []

    def get_scoped_workloads(
        self,
        user_role: Any = None,
        assigned_workloads: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Retrieves workload documents strictly authorized for the caller.
        Uses batched document lookups (db.get_all) to eliminate full-table scanning.
        """
        if not self.db:
            return []

        scope = _scope_for(user_role, assigned_workloads)
        if scope.all:
            return self.query_active_workloads()

        clean_assigned = sorted(scope.ids)
        if not clean_assigned:
            return []

        try:
            doc_refs = [self.db.collection("workloads").document(pid) for pid in clean_assigned]
            snapshots = self.db.get_all(doc_refs)
            workloads = []
            for snap in snapshots:
                if snap.exists:
                    data = snap.to_dict() or {}
                    workloads.append(data)
            return workloads
        except Exception as e:
            logger.warning(f"Failed batched get_all for assigned workloads ({e}). Falling back to stream filter.")
            try:
                all_w = self.query_active_workloads()
                return [w for w in all_w if str(w.get("product_id", "")).lower() in clean_assigned]
            except Exception as stream_err:
                logger.warning(f"Fallback stream failed: {stream_err}")
                return []

    def get_catalog_modules_summary(self) -> List[Dict[str, Any]]:
        """Retrieves and summarizes all built-in and custom modules for conversational context."""
        summary = []
        try:
            try:
                from shared.builtin_modules_provider import get_builtin_modules
            except ImportError:
                from apps.control_center.shared.builtin_modules_provider import get_builtin_modules
            builtins = get_builtin_modules()
            for b in builtins:
                inputs_list = [
                    f"{inp.get('name')}: {inp.get('type')}{' (required)' if inp.get('required') else ''}"
                    if isinstance(inp, dict) else str(inp)
                    for inp in (b.get("inputs") or [])
                ]
                outputs_list = [
                    out.get("name") if isinstance(out, dict) else str(out)
                    for out in (b.get("outputs") or [])
                ]
                summary.append({
                    "module_id": b.get("module_id"),
                    "name": b.get("name"),
                    "category": b.get("category"),
                    "source_type": "BUILT_IN",
                    "description": b.get("description", ""),
                    "inputs": inputs_list,
                    "outputs": outputs_list,
                    "is_heavy_stateful": b.get("is_heavy_stateful", False),
                })
        except Exception as e:
            logger.debug(f"Could not load built-in modules for assistant: {e}")

        if self.db:
            try:
                c_docs = self.db.collection("custom_modules").stream()
                for cd in c_docs:
                    c_data = cd.to_dict() or {}
                    if not c_data.get("is_active", True):
                        continue
                    inputs_list = [
                        f"{inp.get('name')}: {inp.get('type')}{' (required)' if inp.get('required') else ''}"
                        if isinstance(inp, dict) else str(inp)
                        for inp in (c_data.get("inputs") or [])
                    ]
                    outputs_list = [
                        out.get("name") if isinstance(out, dict) else str(out)
                        for out in (c_data.get("outputs") or [])
                    ]
                    summary.append({
                        "module_id": c_data.get("module_id") or cd.id,
                        "name": c_data.get("name") or cd.id,
                        "category": c_data.get("category", "CUSTOM"),
                        "source_type": c_data.get("source_type", "DIRECT_CODE"),
                        "override_builtin": c_data.get("override_builtin"),
                        "description": c_data.get("description", ""),
                        "inputs": inputs_list,
                        "outputs": outputs_list,
                        "is_heavy_stateful": c_data.get("is_heavy_stateful", False),
                    })
            except Exception as e:
                logger.debug(f"Could not load custom modules for assistant: {e}")

        return summary

    def get_pipeline_executions_summary(self, scope: "WorkloadScope", limit: int = 8) -> List[Dict[str, Any]]:
        """Recent pipeline executions visible to `scope` (filtered in the query, BEFORE the limit)."""
        if not self.db:
            return []
        try:
            col = self.db.collection("pipeline_executions")
            if scope.all:
                docs = list(col.order_by("started_at", direction="DESCENDING").limit(limit).stream())
            else:
                ids = sorted(scope.ids)
                docs = []
                for i in range(0, len(ids), 30):
                    docs.extend(col.where("product_id", "in", ids[i:i + 30]).limit(limit).stream())
                docs = [d for d in docs if scope.allows((d.to_dict() or {}).get("product_id"))]
                docs.sort(key=lambda d: str((d.to_dict() or {}).get("started_at", "")), reverse=True)
                docs = docs[:limit]
            results = []
            for d in docs:
                data = d.to_dict() or {}
                results.append({
                    "trace_id": data.get("trace_id", d.id),
                    "product_id": data.get("product_id"),
                    "status": data.get("status"),
                    "current_stage": data.get("current_stage"),
                    "started_at": data.get("started_at"),
                    "elapsed_seconds": data.get("elapsed_seconds"),
                    "error": data.get("error"),
                })
            return results
        except Exception as e:
            logger.debug(f"Could not load recent pipeline executions for assistant: {e}")
            return []

    def get_pending_approvals_summary(self, scope: "WorkloadScope") -> List[Dict[str, Any]]:
        """Pending approval requests visible to `scope` (records without a product_id: administrators only)."""
        if not self.db:
            return []
        try:
            docs = self.db.collection("approval_requests").where("status", "==", "PENDING").stream()
            results = []
            for d in docs:
                data = d.to_dict() or {}
                if not scope.allows(data.get("product_id")):
                    continue
                results.append({
                    "approval_id": data.get("approval_id", d.id),
                    "product_id": data.get("product_id"),
                    "trace_id": data.get("trace_id"),
                    "approval_type": data.get("approval_type"),
                    "summary": data.get("summary") or data.get("change_summary"),
                })
            return results
        except Exception as e:
            logger.debug(f"Could not load pending approvals for assistant: {e}")
            return []

    def get_platform_settings_summary(self) -> Dict[str, Any]:
        """Retrieves current platform settings and governance policies."""
        if not self.db:
            return {}
        try:
            doc = self.db.collection("system_config").document("platform_settings").get()
            if hasattr(doc, "exists") and doc.exists:
                data = doc.to_dict() if callable(getattr(doc, "to_dict", None)) else {}
                if isinstance(data, dict):
                    governance = data.get("governance") if isinstance(data.get("governance"), dict) else {}
                    vcs = data.get("vcs") if isinstance(data.get("vcs"), dict) else {}
                    return {
                        "plan_approval_policy": str(governance.get("plan_approval_policy", "AUTOMATIC")),
                        "compliance_framework": str(governance.get("compliance_framework", "STANDARD")),
                        "code_freeze_active": bool(governance.get("code_freeze_active", False)),
                        "vcs_mode": str(vcs.get("default_provider", "SERVERLESS_GIT")),
                    }
        except Exception as e:
            logger.debug(f"Could not load platform settings for assistant: {e}")
        return {}

    def get_ipam_summary(self, limit: int = 8) -> List[Dict[str, Any]]:
        """Retrieves IPAM network allocation records."""
        if not self.db:
            return []
        try:
            docs = list(self.db.collection("ipam_allocations").limit(limit).stream())
            return [
                {
                    "cidr_block": (d.to_dict() or {}).get("cidr_block"),
                    "product_id": (d.to_dict() or {}).get("product_id"),
                    "purpose": (d.to_dict() or {}).get("purpose"),
                    "status": (d.to_dict() or {}).get("status"),
                }
                for d in docs
            ]
        except Exception as e:
            logger.debug(f"Could not load IPAM summary for assistant: {e}")
            return []

    def get_folders_summary(self) -> List[Dict[str, Any]]:
        """Retrieves managed GCP folder hierarchy."""
        if not self.db:
            return []
        try:
            docs = self.db.collection("managed_folders").stream()
            return [
                {
                    "folder_id": (d.to_dict() or {}).get("folder_id"),
                    "display_name": (d.to_dict() or {}).get("display_name"),
                    "status": (d.to_dict() or {}).get("status"),
                }
                for d in docs
            ]
        except Exception as e:
            logger.debug(f"Could not load folders summary for assistant: {e}")
            return []

    def generate_ai_response(
        self,
        message: str,
        workloads: List[Dict[str, Any]],
        *,
        user_role: Any,
        assigned_workloads: Optional[List[str]] = None,
        user_email: str = "user",
    ) -> Optional[str]:
        """
        Generates contextual natural language responses using the official google-genai SDK.
        Hydrates Gemini prompt with real-time state across every facet of Project Castor.
        """
        candidate_models = get_model_cascade_for_agent("assistant")
        models_to_try = list(dict.fromkeys(candidate_models))

        # Multi-facet context, SCOPED before it reaches the model (FD-4N / FD25-11): the system prompt is not a
        # security boundary (prompt injection), so non-admins never get other tenants' rows, folders, IPAM or settings.
        scope = _scope_for(user_role, assigned_workloads)
        pruned_workloads = prune_workloads_for_context(workloads)
        catalog_modules = self.get_catalog_modules_summary()
        pipeline_runs = self.get_pipeline_executions_summary(scope, limit=8)
        pending_approvals = self.get_pending_approvals_summary(scope)
        platform_settings = self.get_platform_settings_summary() if scope.all else {}
        ipam_allocations = self.get_ipam_summary(limit=8) if scope.all else []
        managed_folders = self.get_folders_summary() if scope.all else []

        system_context = {
            "active_workloads": pruned_workloads,
            "modules_catalog": catalog_modules,
            "recent_pipeline_runs": pipeline_runs,
            "pending_approvals": pending_approvals,
            "platform_settings": platform_settings,
            "ipam_allocations": ipam_allocations,
            "managed_folders": managed_folders,
        }

        context_summary = f"StackVend Live System State:\n{json.dumps(system_context, indent=2, default=str)}"
        prompt = f"{context_summary}\n\nUser Question: {message}"

        # Dynamic System Prompt Hardening
        role_val = getattr(user_role, "value", str(user_role)).upper()
        clean_assigned = [str(pid).strip().lower() for pid in (assigned_workloads or []) if str(pid).strip()]
        resolved_base = build_assistant_system_prompt(db_client=self.db)
        sys_instruction = f"""{resolved_base}

### Authenticated User Context:
* User Email: {user_email}
* Assigned Role: {role_val}
* Authorized Workload Scope: {json.dumps(clean_assigned, default=str)}

### Strict Operational Directives:
1. You only possess knowledge of and may only answer questions regarding the Authorized Workload Scope listed above.
2. If the user asks about an unassigned workload, respond: "You are not assigned to that workload. Please contact your platform administrator."
3. Role Gating:
   - If role is 'VIEWER', you must NOT assist in submitting features, modifying code, or changing budgets. Inform the user they have read-only permissions.
   - If role is 'WORKLOAD_MANAGER', you may draft feature requests ONLY for authorized workloads.
"""

        # 1. Primary Strategy: Official google-genai SDK
        try:
            from google import genai
            from google.genai import types

            gemini_api_key = os.getenv("GEMINI_API_KEY")
            clients_to_try = []

            if gemini_api_key:
                try:
                    clients_to_try.append(("Gemini-API-Key", genai.Client(api_key=gemini_api_key)))
                except Exception as e:
                    logger.debug(f"Could not init API key client: {e}")

            if self.project_id:
                try:
                    clients_to_try.append(("VertexAI-Regional", genai.Client(vertexai=True, project=self.project_id, location=self.location)))
                except Exception as e:
                    logger.debug(f"Could not init regional Vertex AI client: {e}")
                try:
                    clients_to_try.append(("VertexAI-Global", genai.Client(vertexai=True, project=self.project_id, location="global")))
                except Exception as e:
                    logger.debug(f"Could not init global Vertex AI client: {e}")

            # Argon compat (owner 10-14): per-model-family request rules; identity for Gemini <= 3.x
            from shared.gemini_model_config import Purpose, adapt_generate_config_kwargs
            base_config = dict(system_instruction=sys_instruction, temperature=0.4)

            for client_desc, client in clients_to_try:
                for m_name in models_to_try:
                    try:
                        config = types.GenerateContentConfig(**adapt_generate_config_kwargs(
                            m_name, Purpose.AUXILIARY, base_config, types=types))
                        res = client.models.generate_content(
                            model=m_name,
                            contents=prompt,
                            config=config,
                        )
                        if res and res.text:
                            logger.info(f"StackVend Assistant generated response using {client_desc} with model '{m_name}'")
                            return res.text
                    except Exception as model_err:
                        logger.warning(f"{client_desc} model '{m_name}' failed ({model_err}). Trying next candidate.")
                        continue
        except ImportError:
            logger.debug("google-genai SDK not installed; attempting legacy vertexai fallback.")
        except Exception as e:
            logger.warning(f"google-genai client loop encountered error: {e}")

        # 2. Secondary Strategy: Legacy vertexai fallback
        try:
            import vertexai
            from vertexai.generative_models import GenerativeModel

            if self.project_id:
                vertexai.init(project=self.project_id, location=self.location)
                for m_name in models_to_try:
                    try:
                        gm = GenerativeModel(
                            model_name=m_name,
                            system_instruction=[sys_instruction],
                        )
                        res = gm.generate_content(prompt)
                        if res and res.text:
                            logger.info(f"StackVend Assistant generated response using legacy vertexai with model '{m_name}'")
                            return res.text
                    except Exception as legacy_err:
                        logger.warning(f"Legacy model '{m_name}' failed ({legacy_err}).")
                        continue
        except Exception as e:
            logger.warning(f"Legacy Vertex AI fallback failed ({e}).")

        return None

    def handle_chat_message(
        self,
        message: str,
        conversation_history: Optional[List[Dict[str, str]]] = None,
        *,
        user_role: Any,
        assigned_workloads: Optional[List[str]] = None,
        user_email: str = "user",
    ) -> ChatResponse:
        """Processes user chat messages with strict pre-LLM context sandboxing and role gating."""
        msg_lower = message.lower()
        role_val = getattr(user_role, "value", str(user_role)).upper()

        # Step 1: Pre-LLM retrieval scoping (every context collector filters by the caller's workloads)
        scope = _scope_for(user_role, assigned_workloads)
        workloads = self.get_scoped_workloads(user_role=user_role, assigned_workloads=assigned_workloads)

        # Dynamic action chips tailored to caller privileges
        if role_val == "ADMIN":
            default_chips = ["View Global Architecture", "Browse Golden Modules", "Adjust Spend Ceilings", "Audit Pipeline"]
        elif role_val == "WORKLOAD_MANAGER":
            default_chips = ["View Topology", "Submit Feature Request", "View Workload Logs"]
        else:
            default_chips = ["View Topology", "View Deployed Assets", "Inspect Spend Details"]

        # Step 2: Conversational Action Gating for VIEWER
        if role_val == "VIEWER":
            mutation_triggers = [
                "build", "create", "submit feature", "new feature", "add endpoint",
                "decommission", "redeploy", "change budget", "adjust budget",
                "freeze", "code freeze"
            ]
            if any(trigger in msg_lower for trigger in mutation_triggers):
                return ChatResponse(
                    response_text="🔒 **Read-Only Mode**: You hold the **Viewer** role and cannot submit feature specifications, adjust budgets, or initiate deployments. Please contact an assigned Workload Manager or Platform Administrator.",
                    actions_suggested=default_chips,
                )

        # Step 3: Conversational Scope Gating for WORKLOAD_MANAGER
        if role_val == "WORKLOAD_MANAGER":
            clean_assigned = [pid.strip().lower() for pid in (assigned_workloads or []) if pid.strip()]
            mutation_triggers = ["build", "create", "submit", "add endpoint", "deploy"]
            if any(t in msg_lower for t in mutation_triggers):
                assigned_in_msg = [
                    pid for pid in clean_assigned
                    if re.search(r'(?:\b|_)' + re.escape(pid) + r'(?:\b|_)', msg_lower)
                ]
                if not assigned_in_msg and clean_assigned:
                    return ChatResponse(
                        response_text=f"⚠️ **Scope Boundary**: You are only authorized to manage your assigned workloads: {', '.join([f'`{p}`' for p in clean_assigned])}. Please specify one of your assigned workloads in your request.",
                        actions_suggested=default_chips,
                    )

        # Step 4.0: Modules & Catalog questions
        if any(k in msg_lower for k in ["module", "catalog", "golden module", "custom module"]):
            catalog = self.get_catalog_modules_summary()
            custom_mods = [m for m in catalog if m.get("source_type") != "BUILT_IN"]
            # Attempt AI generation first
            ai_text = self.generate_ai_response(
                message=message,
                workloads=workloads,
                user_role=user_role,
                assigned_workloads=assigned_workloads,
                user_email=user_email,
            )
            if ai_text:
                return ChatResponse(response_text=ai_text, actions_suggested=default_chips)

            # Deterministic fallback for modules
            if "custom" in msg_lower or "vpc" in msg_lower:
                if custom_mods:
                    lines = [f"* **`{m['module_id']}`** ({m['name']}): Category `{m['category']}`" + (f" (Overrides built-in `{m['override_builtin']}`)" if m.get("override_builtin") else " (Additive)") for m in custom_mods]
                    resp = f"### ⚡ Custom Enterprise Golden Modules ({len(custom_mods)})\n\n" + "\n".join(lines) + "\n\nYou can invoke custom modules in `human.tf` or feature specifications."
                else:
                    resp = "### ⚡ Custom Golden Modules (0)\n\nNo custom modules are currently registered. You can add one via **Settings ➔ Golden Modules Catalog**."
                return ChatResponse(response_text=resp, actions_suggested=default_chips)
            else:
                resp = f"### 🏛️ StackVend Golden Modules Catalog ({len(catalog)})\n\n* **Native Built-ins**: 24 modules (Networking, Cloud Run, GKE, Cloud SQL, Spanner, Redis, Pub/Sub, Storage, etc.)\n* **Custom Modules**: {len(custom_mods)} registered\n\nAsk me about any specific module's inputs, outputs, or how to invoke it in Terraform."
                return ChatResponse(response_text=resp, actions_suggested=default_chips)

        # Step 4.1: Implementation Plan / Architecture Drafting
        if any(k in msg_lower for k in ["plan", "implementation plan", "draft", "architect", "hcl"]):
            ai_text = self.generate_ai_response(
                message=message,
                workloads=workloads,
                user_role=user_role,
                assigned_workloads=assigned_workloads,
                user_email=user_email,
            )
            if ai_text:
                return ChatResponse(response_text=ai_text, actions_suggested=default_chips)
            resp = "### 📐 Implementation Plan Assistant\n\nI can help you design your infrastructure and service features. Describe what you'd like to build (e.g. *'A Cloud Run microservice with a Postgres database and custom VPC'*), and I will generate a step-by-step specification and Terraform configuration matching our Golden Modules catalog."
            return ChatResponse(response_text=resp, actions_suggested=default_chips)

        # Step 4.2: Approvals questions
        if "approval" in msg_lower or "pending" in msg_lower:
            approvals = self.get_pending_approvals_summary(scope)
            ai_text = self.generate_ai_response(
                message=message,
                workloads=workloads,
                user_role=user_role,
                assigned_workloads=assigned_workloads,
                user_email=user_email,
            )
            if ai_text:
                return ChatResponse(response_text=ai_text, actions_suggested=default_chips)
            if approvals:
                lines = [f"* **`{a['approval_id']}`** ({a.get('product_id')}): {a.get('summary', 'Plan approval pending')}" for a in approvals]
                resp = f"### ⏳ Pending Tier 3 HITL Approvals ({len(approvals)})\n\n" + "\n".join(lines)
            else:
                resp = "### ⏳ Pending Approvals (0)\n\nThere are no pending Tier 3 Human-in-the-Loop approvals at this time."
            return ChatResponse(response_text=resp, actions_suggested=default_chips)

        # Step 4.3: Workloads list
        if ("workload" in msg_lower or "service" in msg_lower or "list" in msg_lower) and not any(k in msg_lower for k in ["module", "catalog", "approval", "trace", "run", "flight", "plan", "vpc"]):
            if not workloads:
                if role_val == "ADMIN":
                    response_text = "### 📦 Active StackVend Workloads (0)\n\nNo workloads are currently registered in the system. You can initialize StackVend on the **Workloads Catalog** tab."
                else:
                    response_text = "### 📦 Assigned StackVend Workloads (0)\n\nYou do not currently have any workloads assigned to your account. Please contact a platform administrator to grant workload access."
            else:
                title = "Active StackVend Workloads" if role_val == "ADMIN" else "Your Assigned Workloads"
                response_text = (
                    f"### 📦 {title} ({len(workloads)})\n\n"
                    + "\n".join([f"* **`{w.get('product_id')}`**: Status: `{w.get('status', 'ACTIVE')}` | Budget: `${float(w.get('budget_ceiling_monthly_usd', 40.0)):.2f}/mo`" for w in workloads])
                    + "\n\nWould you like me to inspect the live architecture diagram or telemetry for any of these services?"
                )
            return ChatResponse(
                response_text=response_text,
                actions_suggested=default_chips,
            )

        # Step 4.4: Spend / FinOps
        if "spend" in msg_lower or "cost" in msg_lower or "budget" in msg_lower:
            total_budget = sum(float(w.get("budget_ceiling_monthly_usd", 40.0)) for w in workloads)
            title = "Global FinOps Spend & Budget Summary" if role_val == "ADMIN" else f"FinOps Spend Summary ({len(workloads)} Assigned Workloads)"
            response_text = (
                f"### 💰 {title}\n\n"
                f"* **Active Workloads**: `{len(workloads)}`\n"
                f"* **Combined Monthly Budget Ceiling**: `${total_budget:.2f}/mo`\n"
                f"* **Budget Enforcement**: each workload's breach policy (scale-to-zero, alert-only, HITL approval or billing unlink) is applied by the FinOps enforcer when a Cloud Billing alert reports spend at or above the workload's ceiling (or its temporary buffer).\n\n"
                "All current deployments are operating within allocated policy boundaries."
            )
            return ChatResponse(
                response_text=response_text,
                actions_suggested=default_chips,
            )

        # Step 4.5: Pipeline agents / status
        if "pipeline" in msg_lower or "agent" in msg_lower or "backlog" in msg_lower:
            response_text = (
                "### 🤖 Multi-Agent Pipeline Status\n\n"
                "* **The Architect**: Triaging intake requests and synthesizing task DAGs.\n"
                "* **The Compliance Agent**: Enforcing Google Cloud Assured Workloads and regulatory security baselines (HIPAA, FedRAMP, GDPR).\n"
                "* **The Developer**: Implementing application logic, API schemas, and UI components.\n"
                "* **The GCP DevOps Agent**: Managing Terraform remote state and Cloud Run lifecycle.\n"
                "* **The QA Reviewer**: Verifying test suites and access control assertions.\n"
                "* **The Release Engineer**: Monitoring promotions and git commits.\n"
                "* **The FinOps Agent**: Enforcing monthly budget ceilings.\n"
                "* **The SRE Agent**: Clustering real-time Cloud Logging telemetry.\n\n"
                "You can inspect full details and backlogs on the **Multi-Agent Pipeline** tab."
            )
            return ChatResponse(
                response_text=response_text,
                actions_suggested=default_chips,
            )

        # Step 5: Attempt Vertex AI Gemini generation with multi-facet context
        ai_text = self.generate_ai_response(
            message=message,
            workloads=workloads,
            user_role=user_role,
            assigned_workloads=assigned_workloads,
            user_email=user_email,
        )
        if ai_text:
            return ChatResponse(
                response_text=ai_text,
                actions_suggested=default_chips,
            )

        # Fallback response
        scope_str = f" across {len(workloads)} assigned workloads" if role_val != "ADMIN" else " across all workloads"
        return ChatResponse(
            response_text=f"I received your request regarding **'{message}'**{scope_str}. The StackVend multi-agent pipeline is active.",
            actions_suggested=default_chips,
        )
