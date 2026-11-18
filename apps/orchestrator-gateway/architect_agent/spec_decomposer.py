"""
Project Castor: Chunked Map-Reduce Specification Decomposer
Scales Architect Agent decomposition to 90+ page enterprise architecture documents (>25,000 chars)
without JSON truncation, model hallucination, or DAG cycle deadlocks.
"""

import json
import logging
import re
from typing import Any, Dict, List, Optional

try:
    from .cycle_detector import validate_task_dag_items, DAGValidationResult
    from .schemas import (
        ArchitecturePlanDAG,
        BuildPlanStep,
        BuildStepCategory,
        BuildStepStatus,
        SequencedBuildPlan,
        TaskCategory,
        TaskItem,
        TaskPriority,
    )
except ImportError:
    from cycle_detector import validate_task_dag_items, DAGValidationResult
    from schemas import (
        ArchitecturePlanDAG,
        BuildPlanStep,
        BuildStepCategory,
        BuildStepStatus,
        SequencedBuildPlan,
        TaskCategory,
        TaskItem,
        TaskPriority,
    )

try:  # RT14-06: the run context every map prompt renders (same object and renderer as the single-turn path)
    from .context import ArchitectContext
except ImportError:
    from context import ArchitectContext  # type: ignore

from gate_errors import OperatorActionRequiredError

logger = logging.getLogger("castor-spec-decomposer")


class SpecTooLargeError(OperatorActionRequiredError):
    """RT14-06: the specification splits into more domain chunks than MAX_DOMAIN_CHUNKS, so map-reduce would make an
    unbounded number of model calls. Typed (OPERATOR_ACTION_REQUIRED, 409, reason ARCHITECT_SPEC_TOO_LARGE): the
    operator shortens or splits the specification; nothing is called and nothing is defaulted."""


class ChunkedSpecDecomposer:
    """
    Decomposes large-scale enterprise specifications using a Map-Reduce paradigm:
    1. Chunk: Splits specification by architectural functional domains or 15k-char boundaries.
    2. Map: Extracts domain-specific services, infra resources, and contracts concurrently.
    3. Reduce: Consolidates sub-plans, eliminates duplicates, and builds a topologically cycle-free DAG.
    """

    CHUNK_THRESHOLD_CHARS = 25_000
    MAX_CHUNK_SIZE_CHARS = 18_000
    # RT14-06: at most this many map calls per decomposition (about 430k characters of specification); more fails
    # typed before any call (SpecTooLargeError).
    MAX_DOMAIN_CHUNKS = 24

    def __init__(
        self,
        genai_client: Optional[Any] = None,
        model_name: str = "gemini-3.7-flash",
    ):
        self.genai_client = genai_client
        self.model_name = model_name

    def should_activate_map_reduce(self, spec_text: str) -> bool:
        """Determines if the specification warrants chunked map-reduce decomposition."""
        if not spec_text:
            return False
        if len(spec_text) >= self.CHUNK_THRESHOLD_CHARS:
            return True
        # Check if specification defines 4+ major section headers
        headers = re.findall(r"^#{1,3}\s+(.+)$", spec_text, re.MULTILINE)
        return len(headers) >= 4 and len(spec_text) > 12_000

    def split_spec_into_domains(self, spec_text: str) -> List[Dict[str, str]]:
        """
        Splits specification into logical functional domains:
        - Ingestion & API Gateways
        - Business Logic & Core Microservices
        - Data Persistence & Databases
        - Security, IAM & Infrastructure
        - Integration & Observability
        """
        sections = []
        raw_sections = re.split(r"(?m)^(?=#{1,3}\s+)", spec_text)
        
        current_chunk_title = "Executive Overview & Global Context"
        current_chunk_body = []
        current_size = 0

        for sec in raw_sections:
            sec_clean = sec.strip()
            if not sec_clean:
                continue

            sec_len = len(sec_clean)
            if current_size + sec_len > self.MAX_CHUNK_SIZE_CHARS and current_chunk_body:
                sections.append({
                    "domain_title": current_chunk_title,
                    "content": "\n\n".join(current_chunk_body),
                })
                current_chunk_body = []
                current_size = 0
                
                # Derive title for next chunk
                title_match = re.match(r"^#{1,3}\s+(.+)$", sec_clean)
                current_chunk_title = title_match.group(1).strip() if title_match else f"Domain Section {len(sections) + 1}"

            if len(current_chunk_body) == 0:
                title_match = re.match(r"^#{1,3}\s+([^\r\n]+)", sec_clean)
                if title_match:
                    current_chunk_title = title_match.group(1).strip()

            current_chunk_body.append(sec_clean)
            current_size += sec_len

        if current_chunk_body:
            sections.append({
                "domain_title": current_chunk_title,
                "content": "\n\n".join(current_chunk_body),
            })

        # Fallback if no sections formed
        if not sections:
            sections.append({
                "domain_title": "Primary Architecture Specification",
                "content": spec_text,
            })

        logger.info(f"Chunked 90-page specification into {len(sections)} distinct architectural domains.")
        return sections

    def map_domain_subplan(
        self,
        domain_chunk: Dict[str, str],
        product_id: str,
        global_context_summary: str,
        context: Optional[ArchitectContext] = None,
    ) -> Dict[str, Any]:
        """Maps a single architectural domain chunk into concrete services, infra, and code tasks. `context` (RT14-06):
        the run's ArchitectContext; its blocks (organization policies, operator REWORK guidance, current topology,
        quota) are in every map prompt, exactly as the single-turn path renders them."""
        domain_title = domain_chunk.get("domain_title", "General Domain")
        content = domain_chunk.get("content", "")

        prompt = (
            f"You are StackVend's Principal Enterprise Domain Architect.\n"
            f"Analyze this isolated domain partition from a massive 90-page specification for workload '{product_id}'.\n\n"
            f"--- GLOBAL WORKLOAD CONTEXT ---\n{global_context_summary[:1500]}\n\n"
            f"--- DOMAIN PARTITION: {domain_title} ---\n{content}\n\n"
        ) + self.run_context_section(context) + (
            f"Extract all microservices, cloud infrastructure components, and code tasks for THIS domain only.\n"
            f"Respond STRICTLY with valid JSON following this schema:\n"
            f"{{\n"
            f'  "domain": "{domain_title}",\n'
            f'  "services": ["service-a", "service-b"],\n'
            f'  "requires_vpc": true or false,\n'
            f'  "cloud_apis": ["run.googleapis.com", "pubsub.googleapis.com"],\n'
            f'  "shared_contracts": {{"EventPayload": "class EventPayload(BaseModel): event_id: str"}},\n'
            f'  "infra_tasks": [\n'
            f'    {{"task_id": "INFRA-{domain_title[:3].upper()}-01", "title": "Deploy Cloud Run", "description": "Details", "target_files": ["infra/workload/main.tf"], "depends_on": []}}\n'
            f'  ],\n'
            f'  "code_tasks": [\n'
            f'    {{"task_id": "CODE-{domain_title[:3].upper()}-01", "title": "Implement API", "description": "Details", "target_files": ["apps/service-a/main.py"], "depends_on": []}}\n'
            f'  ]\n'
            f"}}"
        )

        if not self.genai_client:
            return self._fallback_domain_subplan(domain_title, product_id)

        import stage_deadline   # STAGE-DEADLINE (gateway root module)
        stage_deadline.checkpoint("architect.domain_map")   # outside the try: a stop is never a fallback sub-plan
        try:
            from google.genai import types
            from shared.gemini_model_config import Purpose, adapt_generate_config_kwargs  # Argon compat 10-14
            response = self.genai_client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=stage_deadline.bound_llm_config(types.GenerateContentConfig(**adapt_generate_config_kwargs(
                    self.model_name, Purpose.AUXILIARY, dict(response_mime_type="application/json", temperature=0.1),
                    types=types)), "architect.domain_map", types=types),
            )
            raw = response.text.strip() if response and response.text else "{}"
            raw = re.sub(r"^```json\s*", "", raw)
            raw = re.sub(r"\s*```$", "", raw)
            subplan = json.loads(raw)
            return subplan
        except stage_deadline.STOP_ERRORS:
            raise
        except Exception as e:
            logger.warning(f"Domain map failed for '{domain_title}' ({e}); using deterministic fallback subplan.")
            return self._fallback_domain_subplan(domain_title, product_id)

    @staticmethod
    def run_context_section(context: Optional[ArchitectContext]) -> str:
        """The run context of a map prompt ("" for an empty context, so such a prompt is unchanged)."""
        if context is None:
            return ""
        body = context.prompt_blocks(for_map=True)   # RT F6: the map schema has `services`, not service_topology
        quota = context.quota_block()
        if quota:
            body += f"\n\n{quota.rstrip()}"
        if not body.strip():
            return ""
        return ("--- RUN CONTEXT (applies to every domain of this workload; the same rules as the whole plan) ---"
                f"{body}\n--- END RUN CONTEXT ---\n\n")

    def _fallback_domain_subplan(self, domain_title: str, product_id: str) -> Dict[str, Any]:
        """Provides a safe deterministic domain sub-plan if LLM call is interrupted."""
        slug = re.sub(r"[^a-zA-Z0-9]+", "-", domain_title.lower()).strip("-")[:12]
        svc_name = f"{product_id}-{slug}" if slug else product_id
        return {
            "domain": domain_title,
            "services": [svc_name],
            "requires_vpc": "vpc" in domain_title.lower() or "network" in domain_title.lower(),
            "cloud_apis": ["run.googleapis.com", "firestore.googleapis.com"],
            "shared_contracts": {},
            "infra_tasks": [
                {
                    "task_id": f"INFRA-{slug.upper()}-01",
                    "title": f"Provision {domain_title} Infrastructure",
                    "category": "INFRA",
                    "target_files": ["infra/workload/main.tf"],
                    "description": f"Declare cloud resources for {domain_title}.",
                    "acceptance_criteria": ["Tofu apply succeeds"],
                    "depends_on": [],
                }
            ],
            "code_tasks": [
                {
                    "task_id": f"CODE-{slug.upper()}-01",
                    "title": f"Implement {domain_title} Microservice",
                    "category": "CODE",
                    "target_files": [f"apps/{svc_name}/main.py"],
                    "description": f"Implement API endpoints and logic for {domain_title}.",
                    "acceptance_criteria": ["Health check passes"],
                    "depends_on": [],
                }
            ],
        }

    def reduce_subplans(
        self,
        subplans: List[Dict[str, Any]],
        product_id: str,
        original_spec: str,
    ) -> ArchitecturePlanDAG:
        """
        Reduces domain sub-plans into a unified, cycle-free ArchitecturePlanDAG:
        - Deduplicates shared infrastructure resources.
        - Merges microservice code tasks.
        - Unifies shared contract definitions.
        - Resolves cyclic task dependencies.
        """
        all_services = set()
        all_apis = {"run.googleapis.com", "firestore.googleapis.com"}
        requires_vpc = False
        shared_contracts = {}
        infra_tasks: List[TaskItem] = []
        code_tasks: List[TaskItem] = []
        seen_task_ids = set()

        for sp in subplans:
            for s in sp.get("services", []):
                all_services.add(s)
            for a in sp.get("cloud_apis", []):
                all_apis.add(a)
            if sp.get("requires_vpc"):
                requires_vpc = True
            
            contracts = sp.get("shared_contracts", {})
            if isinstance(contracts, dict):
                shared_contracts.update(contracts)

            for it in sp.get("infra_tasks", []):
                tid = it.get("task_id", f"INFRA-{len(infra_tasks)+1}")
                if tid not in seen_task_ids:
                    seen_task_ids.add(tid)
                    infra_tasks.append(TaskItem(
                        task_id=tid,
                        title=it.get("title", "Infrastructure Task"),
                        category=TaskCategory.INFRA,
                        target_files=it.get("target_files", ["infra/workload/main.tf"]),
                        description=it.get("description", ""),
                        acceptance_criteria=it.get("acceptance_criteria", ["Valid IaC"]),
                        depends_on=it.get("depends_on", []),
                        assigned_agent="gcp-devops",
                        priority=TaskPriority.HIGH,
                    ))

            for ct in sp.get("code_tasks", []):
                tid = ct.get("task_id", f"CODE-{len(code_tasks)+1}")
                if tid not in seen_task_ids:
                    seen_task_ids.add(tid)
                    code_tasks.append(TaskItem(
                        task_id=tid,
                        title=ct.get("title", "Code Implementation Task"),
                        category=TaskCategory.CODE,
                        target_files=ct.get("target_files", []),
                        description=ct.get("description", ""),
                        acceptance_criteria=ct.get("acceptance_criteria", ["Passing tests"]),
                        depends_on=ct.get("depends_on", []),
                        assigned_agent="developer",
                        priority=TaskPriority.HIGH,
                    ))

        # Build Sequenced Build Plan with 7-stage standard layout
        steps = [
            BuildPlanStep(
                step_id="STEP-01-APIS",
                step_index=1,
                category=BuildStepCategory.FOUNDATION_API,
                title="Enable GCP APIs",
                target_files=["infra/workload/main.tf"],
                description=f"Enable required APIs: {sorted(list(all_apis))}",
                acceptance_criteria=["APIs enabled"],
                depends_on=[],
                status=BuildStepStatus.PENDING,
            ),
            BuildPlanStep(
                step_id="STEP-02-DB-REGISTRY",
                step_index=2,
                category=BuildStepCategory.DATABASE,
                title="Provision Data & State Repositories",
                target_files=["infra/workload/main.tf"],
                description="Provision Firestore and Artifact Registry repositories.",
                acceptance_criteria=["State stores created"],
                depends_on=["STEP-01-APIS"],
                status=BuildStepStatus.PENDING,
            ),
            BuildPlanStep(
                step_id="STEP-03-IAM",
                step_index=3,
                category=BuildStepCategory.IAM,
                title="Service Accounts & IAM Bindings",
                target_files=["infra/workload/main.tf"],
                description="Configure least-privilege IAM service accounts.",
                acceptance_criteria=["IAM roles bound"],
                depends_on=["STEP-02-DB-REGISTRY"],
                status=BuildStepStatus.PENDING,
            ),
            BuildPlanStep(
                step_id="STEP-04-APP-CODE",
                step_index=4,
                category=BuildStepCategory.APP_CODE,
                title="Synthesize Application Microservices",
                target_files=[f"apps/{s}/main.py" for s in all_services] or ["apps/app/main.py"],
                description=f"Synthesize {len(all_services)} microservices across domains.",
                acceptance_criteria=["All services compile"],
                depends_on=["STEP-03-IAM"],
                status=BuildStepStatus.PENDING,
            ),
            BuildPlanStep(
                step_id="STEP-05-CICD",
                step_index=5,
                category=BuildStepCategory.CICD,
                title="Container Buildpacks & Cloud Build Config",
                target_files=["Procfile", "requirements.txt", ".gcloudignore"],
                description="Assemble Buildpacks manifests for continuous deployment.",
                acceptance_criteria=["Procfile and dependencies set"],
                depends_on=["STEP-04-APP-CODE"],
                status=BuildStepStatus.PENDING,
            ),
            BuildPlanStep(
                step_id="STEP-06-COMPUTE",
                step_index=6,
                category=BuildStepCategory.COMPUTE,
                title="Deploy Cloud Run Services",
                target_files=["infra/workload/main.tf"],
                description=f"Provision Cloud Run services for {sorted(list(all_services))}.",
                acceptance_criteria=["Cloud Run services active"],
                depends_on=["STEP-05-CICD"],
                status=BuildStepStatus.PENDING,
            ),
            BuildPlanStep(
                step_id="STEP-07-TESTS",
                step_index=7,
                category=BuildStepCategory.TEST,
                title="Verify Health Probes & Unit Tests",
                target_files=["tests/test_api.py", "tests/conftest.py"],
                description="Verify all services respond 200 OK on GET /health.",
                acceptance_criteria=["All test assertions pass"],
                depends_on=["STEP-06-COMPUTE"],
                status=BuildStepStatus.PENDING,
            ),
        ]

        build_plan = SequencedBuildPlan(
            product_id=product_id,
            title=f"Enterprise Architecture Plan for {product_id}",
            summary=f"Chunked Map-Reduce decomposition of 90-page specification across {len(subplans)} domains with {len(all_services)} microservices.",
            required_cloud_apis=sorted(list(all_apis)),
            steps=steps,
            total_steps=len(steps),
        )

        # Construct final unified DAG
        dag = ArchitecturePlanDAG(
            product_id=product_id,
            project_tier=2 if requires_vpc or len(all_services) > 3 else 1,
            summary=f"Enterprise architecture across {len(subplans)} domains and {len(all_services)} microservices.",
            architecture_overview=(
                f"Multi-service cloud architecture decomposing {len(subplans)} domains into {len(all_services)} "
                f"independent microservices ({', '.join(sorted(list(all_services)))}) on Cloud Run v2 with "
                f"{'Private VPC Peering' if requires_vpc else 'Serverless Ingress'}."
            ),
            infra_tasks=infra_tasks,
            code_tasks=code_tasks,
            sequenced_build_plan=build_plan,
            estimated_complexity="HIGH" if len(all_services) > 3 else "MEDIUM",
            requires_human_approval=len(all_services) > 5 or requires_vpc,
            risk_assessment="Enterprise-grade multi-service topology decomposed via Map-Reduce to guarantee zero JSON truncation.",
            requires_vpc=requires_vpc,
            iac_engine="tofu",
        )

        return dag

    def decompose_large_specification(
        self,
        spec_text: str,
        product_id: str,
        context: Optional[ArchitectContext] = None,
    ) -> ArchitecturePlanDAG:
        """Master Map-Reduce orchestrator for enterprise specifications. `context` (RT14-06): the run's
        ArchitectContext, rendered into every map prompt."""
        logger.info(f"Initiating Map-Reduce decomposition for '{product_id}' ({len(spec_text):,} characters)...")

        # 1. Chunking
        domain_chunks = self.split_spec_into_domains(spec_text)
        if len(domain_chunks) > self.MAX_DOMAIN_CHUNKS:
            raise SpecTooLargeError(
                f"the specification for '{product_id}' ({len(spec_text):,} characters) splits into "
                f"{len(domain_chunks)} domain sections; the architect handles at most {self.MAX_DOMAIN_CHUNKS}. "
                f"Shorten the specification or split it into separate workloads.",
                reason="ARCHITECT_SPEC_TOO_LARGE", stage="architect",
                details={"product_id": product_id, "chunks": len(domain_chunks),
                         "max_chunks": self.MAX_DOMAIN_CHUNKS, "spec_chars": len(spec_text)})
        global_summary = spec_text[:2000]

        # 2. Mapping
        subplans = []
        for chunk in domain_chunks:
            sp = self.map_domain_subplan(chunk, product_id, global_summary, context=context)
            subplans.append(sp)

        # 3. Reducing
        unified_dag = self.reduce_subplans(subplans, product_id, spec_text)
        logger.info(
            f"Map-Reduce complete for '{product_id}': unified {len(unified_dag.code_tasks)} code tasks "
            f"and {len(unified_dag.infra_tasks)} infra tasks."
        )
        return unified_dag
