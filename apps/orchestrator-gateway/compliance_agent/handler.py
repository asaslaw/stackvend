"""
Project Castor: Compliance Agent Handler
Orchestrates compliance evaluation between Architect Decomposition and Developer Implementation.
"""

import importlib.util
import json
import logging
import os
import runtime_env  # G1: on_cloud_run() = service or stage-runner job (never K_SERVICE alone)
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit
try:
    import httpx
except ImportError:
    httpx = None
from . import profiles as _profiles
from .schemas import ComplianceAuditRequest, ComplianceAuditResponse, RemoteInspectResponseV2
from . import private_ingress as _private_ingress
from . import vm_presence as _vm_presence
from . import access_advisory as _access_advisory
from gate_errors import GateUnavailableError, PlatformDefectError, PrivateIngressUnsupportedError
import stage_deadline   # STAGE-DEADLINE (gateway root module)

# FD-4F / owner condition 19f: the remote compliance server is the gate. An outage past this budget is
# GATE_UNAVAILABLE (never PASSED/public), so it must cover a SLOW-but-healthy answer: the server's worst-case Google API
# time for /inspect-folder (Assured Workloads 10 s + Org Policy v2 5 s + CRM v3 fallback 6 x 3 s = 33 s,
# mcp-servers/compliance/service.py INSPECT_FOLDER_WORST_CASE_S) plus a Cloud Run cold start of mcp-compliance-server
# and an access-token refresh. 60 s leaves 27 s for those. It costs nothing elsewhere: the Workflows http.post that
# calls the gateway defaults to 300 s and the gateway's Cloud Run request timeout is 1800 s. The image does not ship
# the server module, so the relation is enforced by a test (tests/test_compliance_bundle.py), not an import.
COMPLIANCE_SERVER_TIMEOUT_S = 60.0

# FD-4R R-6: version of the persisted decision (workloads/{product}/compliance_audits/{trace}). v1 records (before R-6)
# carry no `schema_version` and lack enforce_private_ingress / requires_cmek / injected_tasks.
DECISION_SCHEMA_VERSION = 2

# Lane 17 PR-1a (compliance bundle, owner 10-12). How the compliance decision is obtained (`COMPLIANCE_MODE`):
#   remote    (default) POST {COMPLIANCE_SERVER_URL}/inspect-folder with a Google ID token (audience = the service's
#             https origin, minted by the metadata server) and a contract-v2 answer. Any failure -> COMPLIANCE_UNAVAILABLE.
#   inprocess the SAME server function (mcp-servers/compliance/service.py `ComplianceService.inspect_folder`) called in
#             this process. Explicit opt-in for tests and local dev only: refused on Cloud Run and on the pipeline gate
#             (`require_remote_engine=True`). Never a fallback.
# Any other value is refused (fail closed).
COMPLIANCE_MODE_REMOTE = "remote"
COMPLIANCE_MODE_INPROCESS = "inprocess"
COMPLIANCE_MODES = frozenset({COMPLIANCE_MODE_REMOTE, COMPLIANCE_MODE_INPROCESS})

# An ID token is minted only for an https Cloud Run origin on the default port (exact parsed-URL checks). Anything
# else gets no token; on Cloud Run anything else is refused, because Cloud Run IAM would reject a tokenless call.
CLOUD_RUN_HOST_SUFFIX = ".run.app"


def compliance_server_service_py() -> Path:
    """mcp-servers/compliance/service.py in a monorepo checkout. Resolved lazily: the deployed gateway image does not
    contain the monorepo (and its path is too shallow for parents[3]), so this must never run at import time."""
    return Path(__file__).resolve().parents[3] / "mcp-servers" / "compliance" / "service.py"


logger = logging.getLogger("castor-compliance-agent")
logging.basicConfig(level=logging.INFO)

try:
    from shared.settings import get_model_cascade_for_agent
except ImportError:
    try:
        from ..shared.settings import get_model_cascade_for_agent
    except ImportError:
        def get_model_cascade_for_agent(agent_name, project_id=None):
            return [os.getenv("GEMINI_MODEL") or "gemini-4-carbon", "gemini-4-argon"]

# The settings role whose model and cascade the compliance agent uses (COMPLIANCE-FOLLOWS-ARCHITECT-MODEL, owner 11-11).
COMPLIANCE_MODEL_ROLE = "architect"


class _PerCallLegacyModel:
    """The legacy vertexai path's model: a GenerativeModel built at each call with the agent's model at that moment
    (the architect settings model), so constructing the agent reads no settings (red-team F3)."""

    def __init__(self, agent: Any, model_cls: Any):
        self._agent = agent
        self._model_cls = model_cls

    def generate_content(self, *args: Any, model: Optional[str] = None, **kwargs: Any) -> Any:
        """`model`: the model the caller already read for this call (RT D3), else the agent's model now."""
        return self._model_cls(model or self._agent.model_name).generate_content(*args, **kwargs)


def id_token_audience(url: str) -> Optional[str]:
    """The ID-token audience for `url`, or None when no token may be sent to it.

    Only an https Cloud Run origin qualifies: scheme https, a hostname under run.app, no userinfo, default port. The
    audience is the origin (`https://<host>`), which is what Cloud Run IAM accepts for the service URL.
    """
    try:
        parts = urlsplit(url or "")
        port = parts.port
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host or parts.username is not None or parts.password is not None:
        return None
    if port not in (None, 443):
        return None
    if not host.endswith(CLOUD_RUN_HOST_SUFFIX):
        return None
    return f"https://{host}"


def _compliance_unavailable(message: str, *, product_id: str, failure: str, **details: Any) -> GateUnavailableError:
    return GateUnavailableError(
        f"compliance server unavailable ({message}); the run stops instead of assuming a STANDARD / public workload",
        reason="COMPLIANCE_UNAVAILABLE",
        details={"product_id": product_id, "failure": failure, **details},
    )


class ComplianceAgentHandler:
    # COMPLIANCE-FOLLOWS-ARCHITECT-MODEL (owner 11-11 "yes to all three"; DEFAULT-MODEL-GEMINI-4-CARBON): the
    # compliance agent has no model setting of its own; it uses the architect role's settings model and cascade
    # (models.architect_model + models.fallback_models), read through the cached platform settings at each use. It
    # used the GEMINI_MODEL env (gemini-3.7-flash on a default install). An assigned model still wins.
    @property
    def model_name(self) -> str:
        explicit = getattr(self, "_explicit_model_name", None)
        if explicit:
            return explicit
        project_id = getattr(self, "project_id", None) or None
        return get_model_cascade_for_agent(COMPLIANCE_MODEL_ROLE, project_id=project_id)[0]

    @model_name.setter
    def model_name(self, value: Optional[str]) -> None:
        self._explicit_model_name = value or None

    def __init__(
        self,
        compliance_server_url: Optional[str] = None,
        *,
        require_remote_engine: Optional[bool] = None,
        mode: Optional[str] = None,
        auth_request: Optional[Callable[..., Any]] = None,
        workload_access_reader: Optional[Callable[[str], Optional[str]]] = None,
    ):
        self.compliance_server_url = compliance_server_url or os.getenv("COMPLIANCE_SERVER_URL", "http://localhost:8080")
        # FD-4F / owner condition 19f (register row 19a-19p): when the remote compliance server cannot answer, a
        # pipeline gate must stop (GATE_UNAVAILABLE), never fall back to a local answer. The gateway route passes
        # True; any construction on Cloud Run (service or stage-runner job) defaults to True as well. True also refuses the
        # explicit in-process mode, so the pipeline gate always asks the deployed compliance server.
        if require_remote_engine is None:
            require_remote_engine = runtime_env.on_cloud_run()
        self.require_remote_engine = bool(require_remote_engine)
        # Lane 17 PR-1a: `COMPLIANCE_MODE` (see module constants). Resolved at audit time so a bad value fails closed.
        self.mode = mode
        # google.auth transport used to reach the metadata server for the ID token (injectable for tests).
        self._auth_request = auth_request
        # ACCESS-INTERNAL-SERVICE-ADVISORY: product_id -> the stored access mode (`workloads/{pid}.access.mode`, exact
        # enum, None = no record; the gateway route passes `_read_workload_access_mode`, which raises typed on an
        # unreadable or malformed record). Called only when this run's decision is public. None (direct callers, the
        # eval harness): no advisory.
        self.workload_access_reader = workload_access_reader
        self.project_id = os.getenv("PROJECT_ID", "")
        self.location = os.getenv("GEMINI_LOCATION") or os.getenv("VERTEX_LOCATION", "global")
        self.model_name = None   # None: the architect role's settings model (the model_name property)
        self._db = None
        self.genai_client = None
        self.model = None

        try:
            from google import genai
            gemini_api_key = os.getenv("GEMINI_API_KEY")
            if gemini_api_key:
                self.genai_client = genai.Client(api_key=gemini_api_key)
                # the model is resolved per call (the architect settings model): no settings read here
                logger.info("Initialized google-genai Client with API key for Compliance Agent")
            elif self.project_id:
                self.genai_client = genai.Client(vertexai=True, project=self.project_id, location=self.location)
                logger.info("Initialized google-genai Client Vertex AI for Compliance Agent")
        except Exception as e:
            logger.debug(f"google-genai init skipped in compliance agent ({e}); trying legacy vertexai.")

        if not self.genai_client:
            try:
                import vertexai
                from vertexai.generative_models import GenerativeModel
                vertexai.init(project=self.project_id, location=self.location)
                # RT F3 (construction reads no settings): the legacy model is built per call with the agent's model
                self.model = _PerCallLegacyModel(self, GenerativeModel)
                logger.info("Initialized legacy Vertex AI client for Compliance Agent.")
            except Exception as e:
                logger.debug(f"Vertex AI init skipped in compliance agent: {e}")

    @property
    def db(self):
        if not self._db:
            try:
                from google.cloud import firestore
                self._db = firestore.Client(project=self.project_id)
            except Exception as e:
                logger.debug(f"Firestore not available: {e}")
        return self._db

    def evaluate_policy_invariants(
        self,
        policy_matrix: Dict[str, Any],
        plan_markdown: str,
        task_dag: List[Dict[str, Any]],
        typed_compute_has_no_vm: Optional[Callable[[], bool]] = None,
    ) -> List[str]:
        """
        Evaluates the plan markdown and task DAG against the Tier 1 Org Policy Matrix.
        Returns a list of specific policy violation descriptions if invariants are broken.

        `typed_compute_has_no_vm` (VM-EXTERNAL-IP-FALSE-CONFLICT): the typed answer to "does the platform compute this
        plan declares rule out a VM", asked only when the VM external-IP check below would raise its conflict. It does
        not cover resources the build writes in `custom.tf` (see vm_presence.py). Absent: that check alone decides.
        """
        conflicts: List[str] = []
        if not policy_matrix:
            return conflicts

        plan_lower = (plan_markdown or "").lower()
        dag_text = " ".join([
            f"{t.get('title', '')} {t.get('description', '')}" for t in task_dag
        ]).lower()
        combined = f"{plan_lower} {dag_text}"

        # 1. VM External IP Access
        if policy_matrix.get("disallow_vm_external_ip"):
            has_vm = any(k in combined for k in ["compute instance", "google_compute_instance", "vm instance", "bastion", "gce"])
            has_public_ip = any(k in combined for k in [
                "access_config", "external ip", "public ip", "nat_ip", "ephemeral ip", "publicly accessible vm"
            ])
            has_nat_or_private = any(k in combined for k in ["cloud nat", "private ip", "iap ssh", "no public ip", "private vm"])
            if has_vm and (has_public_ip and not has_nat_or_private) and not (typed_compute_has_no_vm and typed_compute_has_no_vm()):
                conflicts.append(
                    "Folder enforces constraints/compute.vmExternalIpAccess. Public IPs on VMs are prohibited; workload must use Private IPs with Cloud NAT and IAP SSH Bastion."
                )

        # 2. Skip Default Network Creation
        if policy_matrix.get("disallow_default_network"):
            if "default vpc" in combined or "default network" in combined or 'network = "default"' in combined:
                conflicts.append(
                    "Folder enforces constraints/compute.skipDefaultNetworkCreation. Default VPC cannot be used; workload must declare a dedicated custom VPC and subnets."
                )

        # 3. Uniform Bucket-Level Access
        if policy_matrix.get("enforce_uniform_bucket_level_access"):
            if "google_storage_bucket_acl" in combined or "bucket_access_control" in combined:
                conflicts.append(
                    "Folder enforces constraints/storage.uniformBucketLevelAccess. Bucket ACLs are prohibited; Uniform Bucket-Level Access must be enabled."
                )

        # 4. Public Access Prevention
        if policy_matrix.get("enforce_public_access_prevention"):
            has_storage = any(k in combined for k in ["google_storage_bucket", "gcs bucket", "storage bucket"])
            has_public_storage = any(k in combined for k in ["allusers", "allauthenticatedusers"]) and has_storage
            if has_public_storage:
                conflicts.append(
                    "Folder enforces constraints/storage.publicAccessPrevention. Storage buckets cannot allow public allUsers / allAuthenticatedUsers access."
                )

        # 5. Disable Service Account Key Creation
        if policy_matrix.get("disable_sa_key_creation"):
            if any(k in combined for k in [
                "google_service_account_key", "service account key", "download sa key", "generate json key", "private_key"
            ]):
                conflicts.append(
                    "Folder enforces constraints/iam.disableServiceAccountKeyCreation. Static service account keys are prohibited; Workload Identity Federation must be used."
                )

        # 6. Require OS Login
        if policy_matrix.get("require_os_login"):
            if 'enable-oslogin = "false"' in combined or "enable-oslogin = false" in combined or ("ssh-keys" in combined and "oslogin" not in combined):
                conflicts.append(
                    "Folder enforces constraints/compute.requireOsLogin. Instance-level SSH keys are prohibited; OS Login must be enabled."
                )

        # 7. Restrict Public IP on Cloud SQL
        if policy_matrix.get("restrict_public_sql"):
            has_sql = any(k in combined for k in ["cloud sql", "google_sql_database_instance", "postgres", "mysql"])
            if has_sql and any(k in combined for k in ["0.0.0.0/0", "public ip for sql", "authorized_networks"]):
                conflicts.append(
                    "Folder enforces constraints/sql.restrictPublicIp. Cloud SQL must use Private IP (VPC Peering/PSC) rather than public IP."
                )

        # 8. Domain-Restricted Sharing
        if policy_matrix.get("domain_restricted_sharing"):
            if "allusers" in combined and any(k in combined for k in ["roles/run.invoker", "roles/cloudfunctions.invoker"]):
                conflicts.append(
                    "Folder enforces constraints/iam.allowedPolicyMemberDomains. Unauthenticated public invocation is prohibited; domain-restricted or IAP authentication required."
                )

        return conflicts

    def remediate_conflicts(
        self,
        conflicts: List[str],
        plan_markdown: Optional[str],
        task_dag: List[Dict[str, Any]],
        policy_matrix: Dict[str, Any],
        trace_id: Optional[str] = None,
    ) -> tuple:
        """
        Invokes the Gemini Safety Rewriter (the architect model's cascade; or the deterministic fallback)
        to rewrite plan_markdown and adjust Task DAG to satisfy organizational policies.
        """
        remediated_plan = plan_markdown
        remediated_dag = list(task_dag)
        conflict_bullet_points = "\n".join([f"- {c}" for c in conflicts])

        # 1. Attempt the Gemini Safety Rewriter
        if (self.genai_client or self.model) and plan_markdown:
            try:
                try:
                    from .prompt import build_compliance_system_prompt
                    system_prompt = build_compliance_system_prompt(task_context=conflict_bullet_points, db_client=self._db)
                except Exception:
                    system_prompt = (
                        "You are the StackVend Compliance Safety Rewriter. An initial infrastructure architecture "
                        "plan generated by an architect violates organization policies. Rewrite the markdown "
                        "architecture plan so that all policy violations are completely fixed and documented in the plan.\n"
                        "Maintain the exact markdown structure and headers, but replace non-compliant designs with compliant alternatives "
                        "(e.g. Private VMs + Cloud NAT + Cloud Router + IAP SSH Bastion instead of Public IPs; custom VPC instead of default network; "
                        "Workload Identity Federation instead of static SA keys; Uniform Bucket-Level Access on GCS; Private IP for Cloud SQL).\n"
                        "Output ONLY the corrected markdown plan."
                    )
                prompt_content = (
                    f"## Organization Policy Conflicts Detected:\n{conflict_bullet_points}\n\n"
                    f"## Original Architecture Plan:\n{plan_markdown}"
                )

                if self.genai_client:
                    from google.genai import types
                    models_to_try = get_model_cascade_for_agent(COMPLIANCE_MODEL_ROLE, project_id=self.project_id)
                    lead_model = self.model_name   # RT D3: read once per call
                    # DEFAULT-FALLBACK-CHAIN: an explicit lead model leads even when it is also a fallback model
                    if lead_model:
                        models_to_try = [lead_model] + [m for m in models_to_try if m != lead_model]
                    for m_name in models_to_try:
                        try:
                            from shared.gemini_model_config import (Purpose,  # Argon compat 10-14
                                                                    adapt_generate_config_kwargs)
                            cfg = types.GenerateContentConfig(**adapt_generate_config_kwargs(
                                m_name, Purpose.AUXILIARY, dict(system_instruction=system_prompt, temperature=0.1),
                                types=types))
                            response = self.genai_client.models.generate_content(
                                model=m_name,
                                contents=prompt_content,
                                # STAGE-DEADLINE: checkpoint + budget-bound call
                                config=stage_deadline.bound_llm_config(cfg, "compliance.rewriter", types=types),
                            )
                            if trace_id and self._db:
                                try:
                                    from shared.token_accounting import extract_token_usage, record_agent_tokens
                                    usage_rec = extract_token_usage(response, m_name)
                                    record_agent_tokens(self._db, trace_id, "compliance", usage_rec)
                                except Exception as t_err:
                                    logger.debug(f"Failed to record compliance tokens: {t_err}")

                            if response.text and len(response.text.strip()) > 50:
                                remediated_plan = response.text.strip()
                                logger.info(f"Successfully remediated plan markdown with Gemini model '{m_name}'")
                                break
                        except stage_deadline.STOP_ERRORS:
                            raise
                        except Exception as m_err:
                            logger.debug(f"Gemini rewriter model '{m_name}' failed: {m_err}")
                elif self.model:
                    lead_model = self.model_name   # RT D3: one read for the call and its token accounting
                    stage_deadline.checkpoint("compliance.rewriter")   # STAGE-DEADLINE
                    response = self.model.generate_content(
                        f"{system_prompt}\n\n{prompt_content}",
                        **({"model": lead_model} if isinstance(self.model, _PerCallLegacyModel) else {}))
                    if trace_id and self._db:
                        try:
                            from shared.token_accounting import extract_token_usage, record_agent_tokens
                            usage_rec = extract_token_usage(response, lead_model)
                            record_agent_tokens(self._db, trace_id, "compliance", usage_rec)
                        except Exception as t_err:
                            logger.debug(f"Failed to record compliance tokens: {t_err}")
                    if response.text and len(response.text.strip()) > 50:
                        remediated_plan = response.text.strip()
                        logger.info("Successfully remediated plan markdown with Vertex AI GenerativeModel.")
            except stage_deadline.STOP_ERRORS:
                raise  # STAGE-DEADLINE: a stopped stage is not a deterministic remediation
            except Exception as e:
                logger.warning(f"Gemini Safety Rewriter failed ({e}); falling back to deterministic remediation.")

        # 2. Deterministic AST / Regex / DAG corrections
        has_vm_ip_conflict = any("vmExternalIpAccess" in c or "Public IPs on VMs" in c for c in conflicts)
        if has_vm_ip_conflict:
            step_ids = {t.get("step_id") for t in remediated_dag}
            if "STEP-01B-VPC-NAT" not in step_ids:
                remediated_dag.insert(1, {
                    "step_id": "STEP-01B-VPC-NAT",
                    "title": "Provision Custom VPC, Subnets, and Cloud NAT for Private VMs",
                    "category": "INFRA",
                    "description": "Declare google_compute_network, google_compute_subnetwork, google_compute_router, and google_compute_router_nat to provide secure outbound internet egress without public IPs, and configure IAP SSH firewall rules.",
                    "depends_on": ["STEP-01-APIS"],
                    "status": "PENDING",
                })
            for t in remediated_dag:
                if t.get("step_id") in ("STEP-04-APP-CODE", "STEP-06-COMPUTE"):
                    deps = t.get("depends_on", [])
                    if "STEP-01B-VPC-NAT" not in deps:
                        deps.append("STEP-01B-VPC-NAT")
                    t["depends_on"] = deps

            if remediated_plan and "Cloud NAT" not in remediated_plan:
                remediated_plan += (
                    "\n\n> [!IMPORTANT]\n"
                    "> **Tier 3 Compliance Safety Remediation**: Direct VM public IPs are disallowed by organizational policy (`constraints/compute.vmExternalIpAccess`). "
                    "Architecture has been auto-remediated to Private VMs with Cloud NAT, Cloud Router, and IAP SSH Bastion access.\n"
                )

        has_sa_key_conflict = any("disableServiceAccountKeyCreation" in c for c in conflicts)
        if has_sa_key_conflict and remediated_plan and "Workload Identity Federation" not in remediated_plan:
            remediated_plan += (
                "\n\n> [!IMPORTANT]\n"
                "> **Tier 3 Compliance Safety Remediation**: Static Service Account Keys are disallowed (`constraints/iam.disableServiceAccountKeyCreation`). "
                "Workload Identity Federation (WIF) is enforced for identity exchange.\n"
            )

        has_bucket_conflict = any("uniformBucketLevelAccess" in c for c in conflicts)
        if has_bucket_conflict and remediated_plan and "Uniform Bucket-Level Access" not in remediated_plan:
            remediated_plan += (
                "\n\n> [!IMPORTANT]\n"
                "> **Tier 3 Compliance Safety Remediation**: Storage fine-grained ACLs are disallowed (`constraints/storage.uniformBucketLevelAccess`). "
                "Uniform Bucket-Level Access (`uniform_bucket_level_access = true`) is enforced on all buckets.\n"
            )

        return remediated_plan, remediated_dag

    def _determine_approval_requirement(self, has_policy_conflicts: bool) -> bool:
        """Determines whether architectural plan requires human review based on governance settings.

        FD-4AK: fails closed. When the governance settings cannot be established (read failed, stored document
        invalid, or any other error evaluating them) the plan requires human approval -- it is never waved through on
        compile-time defaults."""
        try:
            from shared.settings import get_platform_settings
            gov = get_platform_settings(project_id=self.project_id, strict=True).governance
            if getattr(gov, "require_plan_approval", False):
                return True
            policy = str(getattr(gov, "plan_approval_policy", "ON_COMPLIANCE_CONFLICT")).upper()
            if policy == "ALWAYS":
                return True
            if policy == "ON_COMPLIANCE_CONFLICT" and has_policy_conflicts:
                return True
        except Exception as e:  # noqa: BLE001 - every failure to evaluate the gate requires approval
            logger.error(f"{getattr(e, 'code', 'GOVERNANCE_SETTINGS_UNAVAILABLE')}: plan approval governance could not "
                         f"be evaluated ({type(e).__name__}: {e}); human approval is required (fail closed).")
            return True
        return has_policy_conflicts

    # ------------------------------------------------------------------------------------------------------------
    # Lane 17 PR-1a (compliance bundle): obtaining the compliance decision. Fails closed on every path.
    # ------------------------------------------------------------------------------------------------------------
    def _resolve_mode(self, product_id: str) -> str:
        raw = self.mode if self.mode is not None else os.getenv("COMPLIANCE_MODE", COMPLIANCE_MODE_REMOTE)
        mode = (raw or COMPLIANCE_MODE_REMOTE).strip().lower()
        if mode not in COMPLIANCE_MODES:
            raise _compliance_unavailable(
                f"unknown COMPLIANCE_MODE {raw!r}; expected one of {sorted(COMPLIANCE_MODES)}",
                product_id=product_id, failure="CONFIG",
            )
        return mode

    def _fetch_compliance_decision(
        self, *, folder_id: str, spec_text: str, product_id: str, requested_profile: Optional[str] = None,
    ) -> Dict[str, Any]:
        mode = self._resolve_mode(product_id)
        if mode == COMPLIANCE_MODE_INPROCESS:
            body = self._inprocess_inspect_folder(folder_id=folder_id, spec_text=spec_text, product_id=product_id,
                                                  requested_profile=requested_profile)
        else:
            body = self._remote_inspect_folder(folder_id=folder_id, spec_text=spec_text, product_id=product_id,
                                               requested_profile=requested_profile)
        body = self._validate_contract(body, product_id=product_id, mode=mode)
        # Contract v3: the server must have decided on the selection the gateway sent (an answer for another
        # selection, e.g. a proxy or an old server dropping the field, is refused).
        if body.get("requested_profile") != requested_profile:
            raise _compliance_unavailable(
                f"answer echoes requested_profile {body.get('requested_profile')!r}, sent {requested_profile!r}",
                product_id=product_id, failure="CONTRACT",
            )
        return body

    def _fetch_id_token(self, audience: str) -> str:
        """A Google ID token for `audience` from the runtime identity (the metadata server on Cloud Run), the same
        google-auth call the other platform callers use (shared/callbacks.py)."""
        from google.oauth2 import id_token as google_id_token

        request = self._auth_request
        if request is None:
            from google.auth.transport.requests import Request as GoogleAuthRequest

            request = GoogleAuthRequest()
        token = google_id_token.fetch_id_token(request, audience)
        if not isinstance(token, str) or not token:
            raise RuntimeError("the metadata server returned an empty ID token")
        return token

    def _remote_inspect_folder(
        self, *, folder_id: str, spec_text: str, product_id: str, requested_profile: Optional[str] = None,
    ) -> Any:
        base_url = (self.compliance_server_url or "").rstrip("/")
        audience = id_token_audience(base_url)
        on_cloud_run = runtime_env.on_cloud_run()
        if audience is None and on_cloud_run:
            # mcp-compliance-server is not publicly invokable: a tokenless call is refused by Cloud Run IAM, and an
            # http:// or non-Cloud-Run URL (e.g. a COMPLIANCE_SERVER_URL override such as `http://...:8080`; the
            # gateway's resolve_service_url no longer guesses one, FALLBACK-URLS) must never receive the token.
            raise _compliance_unavailable(
                f"COMPLIANCE_SERVER_URL {base_url!r} is not an https Cloud Run URL",
                product_id=product_id, failure="CONFIG",
            )
        headers: Dict[str, str] = {}
        if audience is not None:
            try:
                headers["Authorization"] = f"Bearer {self._fetch_id_token(audience)}"
            except Exception as e:
                logger.error(f"Could not mint an ID token for the compliance server ({type(e).__name__}).")
                raise _compliance_unavailable(
                    f"could not mint an ID token for audience {audience}: {type(e).__name__}",
                    product_id=product_id, failure="AUTH",
                ) from e

        if httpx is None:
            raise _compliance_unavailable("httpx is not installed", product_id=product_id, failure="CONFIG")
        try:
            # Redirects are never followed: the token is bound to this origin only.
            with httpx.Client(timeout=COMPLIANCE_SERVER_TIMEOUT_S, follow_redirects=False) as client:
                res = client.post(
                    f"{base_url}/inspect-folder",
                    json={"folder_id": folder_id, "spec_text": spec_text, "compliance_profile": requested_profile},
                    headers=headers,
                )
        except Exception as e:
            raise _compliance_unavailable(f"{type(e).__name__}: {e}", product_id=product_id, failure="TRANSPORT") from e

        if res.status_code == 422:
            # Owner decisions 10-18 (CP-8 / CP-10): a typed refusal of the profile decision is passed on as such.
            try:
                detail = (res.json() or {}).get("detail")
            except Exception:
                detail = None
            if isinstance(detail, dict) and detail.get("error_class") in _profiles.SERVER_REFUSAL_CLASSES:
                raise _profiles.ComplianceProfileRefused(detail["error_class"], str(detail.get("detail") or ""))
        if res.status_code != 200:
            failure = "AUTH" if res.status_code in (401, 403) else "HTTP_STATUS"
            raise _compliance_unavailable(
                f"HTTP {res.status_code}", product_id=product_id, failure=failure, http_status=res.status_code
            )
        try:
            return res.json()
        except Exception as e:
            raise _compliance_unavailable(
                f"invalid JSON: {type(e).__name__}: {e}", product_id=product_id, failure="INVALID_JSON"
            ) from e

    def _inprocess_inspect_folder(
        self, *, folder_id: str, spec_text: str, product_id: str, requested_profile: Optional[str] = None,
    ) -> Any:
        if runtime_env.on_cloud_run():
            raise _compliance_unavailable(
                "COMPLIANCE_MODE=inprocess is refused on Cloud Run", product_id=product_id, failure="CONFIG"
            )
        if self.require_remote_engine:
            raise _compliance_unavailable(
                "COMPLIANCE_MODE=inprocess is refused on the pipeline gate (it requires the deployed compliance server)",
                product_id=product_id, failure="CONFIG",
            )
        try:
            # Loaded by path under a unique module name (lane 17 RT F12): other directories also ship a `service`.
            spec = importlib.util.spec_from_file_location(
                "stackvend_compliance_server_service", str(compliance_server_service_py())
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            body = module.ComplianceService(project_id=self.project_id).inspect_folder(
                folder_id, spec_text, requested_profile=requested_profile)
            # Same wire shape as the HTTP path.
            return json.loads(json.dumps(body))
        except Exception as e:
            if getattr(e, "error_class", None) in _profiles.SERVER_REFUSAL_CLASSES:
                raise _profiles.ComplianceProfileRefused(e.error_class, str(getattr(e, "detail", e))) from e
            raise _compliance_unavailable(
                f"in-process compliance engine failed: {type(e).__name__}: {e}", product_id=product_id, failure="INPROCESS"
            ) from e

    def _validate_contract(self, body: Any, *, product_id: str, mode: str) -> Dict[str, Any]:
        if not isinstance(body, dict) or not body:
            raise _compliance_unavailable(
                "response is not a non-empty JSON object", product_id=product_id, failure="CONTRACT"
            )
        if RemoteInspectResponseV2 is None:  # pragma: no cover - pydantic is a hard requirement
            raise _compliance_unavailable("contract validator unavailable", product_id=product_id, failure="CONFIG")
        try:
            RemoteInspectResponseV2.model_validate(body)
        except Exception as e:
            errors = []
            for err in getattr(e, "errors", lambda: [])()[:5]:
                errors.append({"loc": [str(x) for x in err.get("loc", ())], "msg": str(err.get("msg", ""))[:200]})
            raise _compliance_unavailable(
                f"answer violates compliance contract v2: {type(e).__name__}",
                product_id=product_id, failure="CONTRACT", contract_errors=errors,
            ) from e
        logger.info(
            f"Compliance decision for '{product_id}' via {mode} engine: contract_version="
            f"{body.get('contract_version')} profile={body.get('profile')} "
            f"allow_unauthenticated={body.get('allow_unauthenticated')} enable_direct_iap={body.get('enable_direct_iap')}"
        )
        # The server's own JSON object is used unchanged (validation only), so a valid answer is enriched exactly as
        # the pre-bundle remote path enriched it.
        return body

    def audit_and_enrich(self, req: ComplianceAuditRequest) -> ComplianceAuditResponse:
        """
        Audits initial Architect DAG against compliance profile.
        Fast-path completes in <50ms for STANDARD workloads.
        """
        product_id = req.product_id
        spec_text = req.spec_text or ""
        folder_id = req.folder_id or os.getenv("PARENT_FOLDER_ID", "")
        trace_id = req.trace_id or f"trace-{product_id}"

        # 1. The compliance decision (lane 17 PR-1a): the compliance server's contract-v2 answer, remote (ID token) by
        #    default. Any outage / auth failure / invalid answer raises GATE_UNAVAILABLE COMPLIANCE_UNAVAILABLE here,
        #    before any audit record is written (FD-4F 19f). There is no local fallback: the spec ingress-intent
        #    keywords live in the compliance server only (lane 17 R-3).
        # compliance-profile-explicit: the profile is an explicit, typed selection (or the folder regime), never
        # spec words. An invalid value raises InvalidComplianceProfile here (the route answers 422).
        requested_profile = _profiles.parse_profile(req.compliance_profile)
        compliance_data = self._fetch_compliance_decision(
            folder_id=folder_id, spec_text=spec_text, product_id=product_id, requested_profile=requested_profile)

        profile = compliance_data.get("profile", "STANDARD")
        profile_source = compliance_data.get("profile_source")
        if (profile_source == _profiles.SOURCE_EXPLICIT_REQUEST
                and req.compliance_profile_origin == _profiles.SOURCE_WORKLOAD_SELECTION):
            profile_source = _profiles.SOURCE_WORKLOAD_SELECTION
        profile_advisories = [a for a in (compliance_data.get("profile_suggestions") or []) if isinstance(a, dict)]
        if profile_advisories:
            logger.info(f"Compliance profile advisories for '{product_id}' (not applied): "
                        f"{[a.get('profile') for a in profile_advisories]}")
        domain_restricted_sharing = compliance_data.get("domain_restricted_sharing", False)
        allowed_domains = compliance_data.get("allowed_domains", [])
        allow_unauthenticated = compliance_data.get("allow_unauthenticated", not domain_restricted_sharing)
        enable_direct_iap = compliance_data.get("enable_direct_iap", False)
        enforce_private_ingress = compliance_data.get("enforce_private_ingress", False)
        mandated_tasks = list(compliance_data.get("mandated_tasks", []))

        # Resolve Tier 1 Org Policy Matrix (contract v2 always carries the server's `policy_matrix` object, so the old
        # sys.path org-policy harvest fallback is gone with the embedded engine, lane 17 R-3).
        policy_matrix = None
        if req.policy_matrix and isinstance(req.policy_matrix, dict):
            policy_matrix = dict(req.policy_matrix)
        elif compliance_data and isinstance(compliance_data.get("policy_matrix"), dict):
            policy_matrix = dict(compliance_data["policy_matrix"])

        # Synchronize flags with policy_matrix if available
        if policy_matrix:
            if policy_matrix.get("domain_restricted_sharing"):
                domain_restricted_sharing = True
                allow_unauthenticated = False
            if policy_matrix.get("allowed_domains"):
                allowed_domains = list(set(allowed_domains + policy_matrix["allowed_domains"]))
            if policy_matrix.get("allow_unauthenticated") is False:
                allow_unauthenticated = False
            if policy_matrix.get("enforce_private_ingress"):
                enforce_private_ingress = True

        # PRIVATE-INGRESS-EARLY-STOP: before the policy remediation (the only model call of this stage), the plan
        # approval, vending and the developer. Only a run that has the flag reads anything here.
        if enforce_private_ingress:
            stop = self._private_ingress_stop(req, compliance_data, policy_matrix, profile)
            if stop is not None:
                # The decision is persisted before the stop (fail closed, as every decision): the apply gate reads
                # workloads/{pid}.compliance_decision on Fast-Path too, and must keep seeing the flag.
                self._persist_audit_record(self._decision_record(
                    ComplianceAuditResponse(
                        product_id=product_id, compliance_profile=profile or "STANDARD", is_regulated=True,
                        requires_cmek=compliance_data.get("requires_cmek", False),
                        requires_audit_logging=compliance_data.get("requires_audit_logging", False),
                        domain_restricted_sharing=domain_restricted_sharing, allowed_domains=allowed_domains,
                        allow_unauthenticated=allow_unauthenticated, enable_direct_iap=enable_direct_iap,
                        enforce_private_ingress=True, injected_tasks=mandated_tasks,
                        compliance_summary=stop.message, status="FAILED", policy_matrix=policy_matrix,
                        compliance_profile_source=profile_source, profile_advisories=profile_advisories,
                    ),
                    trace_id, profile=profile, summary=stop.message, compliance_data=compliance_data))
                raise stop

        # ACCESS-INTERNAL-SERVICE-ADVISORY: typed facts only, no model call (the pre-build gate waits for plan approval
        # when it is non-empty). Empty unless the workload is Public; malformed facts raise a typed error. Capped at
        # the source (the rest counted), so the gate never refuses a list this stage wrote.
        access_advisories, access_advisories_omitted = _access_advisory.capped(
            self._access_advisories(req, allow_unauthenticated, enable_direct_iap))

        # Tier 3 Gate: Evaluate policy invariants against plan markdown and initial DAG
        working_dag = list(req.task_dag)
        working_plan = req.plan_markdown
        policy_conflicts = self.evaluate_policy_invariants(policy_matrix or {}, working_plan or "", working_dag,
                                                           typed_compute_has_no_vm=lambda: self._typed_compute_has_no_vm(req))
        has_policy_conflicts = len(policy_conflicts) > 0

        if has_policy_conflicts:
            logger.warning(f"Compliance violations detected for '{product_id}': {policy_conflicts}. Invoking safety remediation...")
            working_plan, working_dag = self.remediate_conflicts(
                policy_conflicts, working_plan, working_dag, policy_matrix or {}, trace_id=trace_id
            )

        # SAT14-REGULATED-NARROW (owner 10-31): a guardrail-only org-policy constraint (`has_constraints`, for example
        # "no external VM IPs") is not regulation and no longer leaves the STANDARD fast path by itself. Its plan
        # conflicts are still evaluated above, before the fast path (`has_policy_conflicts` keeps its own term). The
        # material constraints keep their own terms; `not allow_unauthenticated` mirrors the server's rule that a
        # private decision never takes the fast path (which answers public).
        is_regulated = (
            compliance_data.get("is_regulated", False)
            or domain_restricted_sharing
            or enforce_private_ingress
            or enable_direct_iap
            or has_policy_conflicts
            or not allow_unauthenticated
        )

        # Lane 19 L19-8 (FD-4I I8/I10/I11): compliance never adds principals. The former "403 safety guardrail" put every
        # platform ADMIN (`"ADMIN" in role`), env ADMIN_EMAIL and the workload's creator fields -- or, failing those,
        # `allAuthenticatedUsers` -- into allowed_domains for a private workload. allowed_domains now carries only the
        # org-policy values; the developer takes invokers from the access record and stops a private workload that has
        # none (ACCESS_POLICY_INCOMPLETE, operator).

        # Determine if human approval is required by platform governance
        requires_human_approval = self._determine_approval_requirement(has_policy_conflicts)

        # 2. Fast Pass-Through for STANDARD profile without domain restrictions, private ingress, or policy conflicts
        if not is_regulated and not has_policy_conflicts:
            logger.info(f"Compliance check passed for '{product_id}': STANDARD profile (Fast Pass-Through <50ms).")
            enriched_plan = self._enrich_plan_markdown(
                req.plan_markdown, profile, False, False, False,
                domain_restricted_sharing=False, allowed_domains=[], allow_unauthenticated=True
            )
            response = ComplianceAuditResponse(
                product_id=product_id,
                compliance_profile="STANDARD",
                is_regulated=False,
                requires_cmek=False,
                requires_audit_logging=False,
                domain_restricted_sharing=False,
                allowed_domains=[],
                allow_unauthenticated=True,
                enable_direct_iap=False,
                enforce_private_ingress=False,
                enriched_dag=req.task_dag,
                injected_tasks=[],
                compliance_summary="Standard profile passed with zero regulatory restrictions.",
                status="PASSED",
                plan_markdown=enriched_plan or req.plan_markdown,
                plan_file_path=req.plan_file_path,
                policy_matrix=policy_matrix,
                has_policy_conflicts=False,
                policy_conflicts=[],
                requires_human_approval=requires_human_approval,
                compliance_profile_source=profile_source,
                profile_advisories=profile_advisories,
                access_advisories=access_advisories,
                access_advisories_omitted=access_advisories_omitted,
            )
            # FD-4R R-6: the complete decision is persisted before it is returned; a persist failure stops the gate.
            self._persist_audit_record(self._decision_record(
                response, trace_id, profile=profile, summary="Standard workload - fast path passed.",
                compliance_data=compliance_data))
            return response

        # 3. Compliance Enrichment: Inject mandated tasks into DAG
        logger.info(f"Enriching build plan for '{product_id}' with {profile} compliance and org policy requirements...")
        enriched_dag = list(working_dag)
        injected_ids = [t["step_id"] for t in mandated_tasks]

        # Insert mandated tasks right after IAM / Registry steps
        insert_idx = len(enriched_dag)
        for i, step in enumerate(enriched_dag):
            if step.get("step_id") in ("STEP-03-IAM", "STEP-02-DB-REGISTRY"):
                insert_idx = i + 1

        for task in mandated_tasks:
            if not any(t.get("step_id") == task["step_id"] for t in enriched_dag):
                enriched_dag.insert(insert_idx, {
                    "step_id": task["step_id"],
                    "title": task["title"],
                    "category": task.get("category", "INFRA"),
                    "description": task.get("description", ""),
                    "depends_on": ["STEP-01-APIS"],
                    "status": "PENDING",
                })
                insert_idx += 1

        # Update downstream compute and code tasks to depend on KMS CMEK
        for step in enriched_dag:
            if step.get("step_id") in ("STEP-04-APP-CODE", "STEP-06-COMPUTE"):
                deps = step.get("depends_on", [])
                for inj_id in injected_ids:
                    if inj_id not in deps:
                        deps.append(inj_id)
                step["depends_on"] = deps

        summary_parts = []
        if mandated_tasks:
            summary_parts.append(f"Enriched Task DAG with {len(mandated_tasks)} compliance tasks for {profile} regulatory baseline")
        if domain_restricted_sharing:
            summary_parts.append("Enforced domain-restricted authenticated ingress (constraints/iam.allowedPolicyMemberDomains)")
        if enable_direct_iap:
            summary_parts.append("Enforced Direct Identity-Aware Proxy (IAP) browser authentication on Cloud Run")
        if enforce_private_ingress:
            summary_parts.append("Configured private internal ingress with Serverless NEG and HTTPS Load Balancer")
        if has_policy_conflicts:
            summary_parts.append(f"Auto-remediated {len(policy_conflicts)} organization policy conflict(s)")
        summary = ". ".join(summary_parts) if summary_parts else f"Compliance checks evaluated for {profile}."

        enriched_plan = self._enrich_plan_markdown(
            working_plan or req.plan_markdown,
            profile,
            bool(is_regulated),
            compliance_data.get("requires_cmek", True),
            compliance_data.get("requires_audit_logging", True),
            domain_restricted_sharing=domain_restricted_sharing,
            allowed_domains=allowed_domains,
            allow_unauthenticated=allow_unauthenticated,
            enable_direct_iap=enable_direct_iap,
        )

        response = ComplianceAuditResponse(
            product_id=product_id,
            compliance_profile=profile or "STANDARD",
            is_regulated=is_regulated,
            requires_cmek=compliance_data.get("requires_cmek", False),
            requires_audit_logging=compliance_data.get("requires_audit_logging", False),
            domain_restricted_sharing=domain_restricted_sharing,
            allowed_domains=allowed_domains,
            allow_unauthenticated=allow_unauthenticated,
            enable_direct_iap=enable_direct_iap,
            enforce_private_ingress=enforce_private_ingress,
            enriched_dag=enriched_dag,
            injected_tasks=mandated_tasks,
            compliance_summary=summary,
            status="ENRICHED",
            plan_markdown=enriched_plan or working_plan or req.plan_markdown,
            plan_file_path=req.plan_file_path,
            policy_matrix=policy_matrix,
            has_policy_conflicts=has_policy_conflicts,
            policy_conflicts=policy_conflicts,
            requires_human_approval=requires_human_approval,
            compliance_profile_source=profile_source,
            profile_advisories=profile_advisories,
            access_advisories=access_advisories,
            access_advisories_omitted=access_advisories_omitted,
        )
        # FD-4R R-6: the complete decision is persisted before it is returned; a persist failure stops the gate.
        self._persist_audit_record(self._decision_record(
            response, trace_id, profile=profile, summary=summary, compliance_data=compliance_data))
        return response

    @staticmethod
    def _architect_compute_intent(db: Any, product_id: str, trace_id: str) -> Any:
        """The architect's typed compute record of this trace, resolved. Raises when it cannot be read or resolved."""
        from developer_agent.compute_intent import resolve_compute_intent

        doc = db.collection("pipeline_executions").document(trace_id).get()
        record = (doc.to_dict() or {}).get("architect_compute_intent") if doc.exists else None
        if not isinstance(record, dict) or not record:
            raise ValueError(f"pipeline_executions/{trace_id} has no architect_compute_intent")
        # Existing repository compute is the developer's check (brownfield guard, before any model call); the
        # architect's record is the plan, and a plan that dropped existing compute stops there.
        return resolve_compute_intent(product_id, record, {}, None)

    def _typed_compute_has_no_vm(self, req: ComplianceAuditRequest) -> bool:
        """VM-EXTERNAL-IP-FALSE-CONFLICT: True only when the architect's typed compute record shows no VM. Anything
        else (no store, no trace, a record that cannot be read or resolved) is False: the conflict stands and a person
        sees the plan, so "could not check" never clears a conflict."""
        db = self.db if self.project_id else None
        if not db or not req.trace_id:
            logger.warning(f"VM external-IP conflict for '{req.product_id}' kept: no architect compute record to check "
                           f"it against (no store or trace)")
            return False
        try:
            return _vm_presence.typed_compute_has_no_vm(self._architect_compute_intent(db, req.product_id, req.trace_id))
        except Exception as e:  # noqa: BLE001 - never read as "no VM"; the conflict stands
            logger.warning(f"VM external-IP conflict for '{req.product_id}' kept: the architect's compute record could "
                           f"not be read ({type(e).__name__}: {e})")
            return False

    def _planned_cloud_run_services(self, req: ComplianceAuditRequest) -> Optional[List[str]]:
        """The plan's Cloud Run services, from the architect's typed compute record of this trace (the one the
        developer resolves; the workflow does not pass it to this stage). None = an off-pipeline caller that has no
        store on purpose (the eval harness and local runs: not the pipeline gate), which keeps today's behavior. On the
        pipeline gate no store, an empty trace id or a record that cannot be read or resolved stops the run: "could
        not check" is never "no Cloud Run"."""
        product_id = req.product_id
        trace_id = req.trace_id
        db = self.db if self.project_id else None
        if not db and not self.require_remote_engine:
            logger.warning(f"Private-ingress check for '{product_id}' not evaluated: no store (off-pipeline caller); "
                           f"the apply gate still enforces the decision")
            return None
        if not db or not trace_id:
            failure = "NO_STORE" if not db else "NO_TRACE"
            raise GateUnavailableError(
                f"the private-ingress check cannot read the architect's compute record ({failure}); the run stops "
                f"instead of assuming the plan has no Cloud Run service",
                reason=_private_ingress.REASON_COMPUTE_UNKNOWN, stage=_private_ingress.STAGE,
                details={"product_id": product_id, "trace_id": trace_id, "failure": failure},
            )
        try:
            return _private_ingress.cloud_run_services(self._architect_compute_intent(db, product_id, trace_id))
        except Exception as e:  # noqa: BLE001 - typed below; never read as "no Cloud Run"
            raise GateUnavailableError(
                f"the private-ingress check could not read the architect's compute record for trace '{trace_id}': "
                f"{type(e).__name__}: {e}; the run stops instead of assuming the plan has no Cloud Run service",
                reason=_private_ingress.REASON_COMPUTE_UNKNOWN, stage=_private_ingress.STAGE,
                details={"product_id": product_id, "trace_id": trace_id, "failure": type(e).__name__},
            ) from e

    def _access_advisories(self, req: ComplianceAuditRequest, allow_unauthenticated: Any,
                           enable_direct_iap: Any) -> List[Dict[str, Any]]:
        """ACCESS-INTERNAL-SERVICE-ADVISORY (compliance_agent/access_advisory.py): `ACCESS.INTERNAL_SERVICE_PUBLIC` for
        each Cloud Run push target of a Public workload that is neither its HTTP entrypoint nor an `http` callee.

        A private decision -> [] with no read. A public one: the stored access mode (`workload_access_reader`; no reader
        or no record -> []), then, for PUBLIC_APP only, the architect's typed compute record of this trace (the one the
        developer resolves). An off-pipeline caller with no store on purpose (eval harness, local runs) gets [] and a
        WARNING. On the pipeline gate a missing store, trace or record, or a read failure, is GATE_UNAVAILABLE; a record
        or topology that does not resolve is PLATFORM_DEFECT. "Could not check" is never "nothing to report"."""
        product_id, trace_id = req.product_id, req.trace_id
        if allow_unauthenticated is not True or enable_direct_iap is True or self.workload_access_reader is None:
            return []
        mode = self.workload_access_reader(product_id)
        if not _access_advisory.workload_is_public(mode, allow_unauthenticated=allow_unauthenticated,
                                                   enable_direct_iap=enable_direct_iap):
            return []
        db = self.db if self.project_id else None
        if not db and not self.require_remote_engine:
            logger.warning(f"Access advisory for '{product_id}' not evaluated: no store (off-pipeline caller)")
            return []
        details = {"product_id": product_id, "trace_id": trace_id}
        if not db or not trace_id:
            failure = "NO_STORE" if not db else "NO_TRACE"
            raise GateUnavailableError(
                f"the access advisory cannot read the architect's compute record ({failure}); the run stops instead "
                f"of reporting no warning", reason=_access_advisory.REASON_FACTS_UNAVAILABLE,
                stage=_access_advisory.STAGE, details={**details, "failure": failure})
        try:
            doc = db.collection("pipeline_executions").document(trace_id).get()
            record = (doc.to_dict() or {}).get("architect_compute_intent") if doc.exists else None
        except Exception as e:  # noqa: BLE001 - typed below; never read as "nothing to report"
            raise GateUnavailableError(
                f"the access advisory could not read pipeline_executions/{trace_id}: {type(e).__name__}: {e}",
                reason=_access_advisory.REASON_FACTS_UNAVAILABLE, stage=_access_advisory.STAGE,
                details={**details, "failure": type(e).__name__}) from e
        if not isinstance(record, dict) or not record:
            raise GateUnavailableError(
                f"pipeline_executions/{trace_id} has no architect_compute_intent; the access advisory cannot be "
                f"checked", reason=_access_advisory.REASON_FACTS_UNAVAILABLE, stage=_access_advisory.STAGE,
                details={**details, "failure": "NO_RECORD"})
        try:
            from developer_agent.compute_intent import resolve_compute_intent
            intent = resolve_compute_intent(product_id, record, {}, None)
            advisories = _access_advisory.internal_service_advisories(intent.topology)
        except Exception as e:  # noqa: BLE001 - a malformed typed fact is a platform defect, typed
            raise PlatformDefectError(
                f"the access advisory found a malformed compute record for trace '{trace_id}': "
                f"{type(e).__name__}: {e}", reason=_access_advisory.REASON_FACTS_INVALID,
                stage=_access_advisory.STAGE, details={**details, "failure": type(e).__name__}) from e
        for adv in advisories:
            logger.warning(f"{adv['code']} for '{product_id}' ({trace_id}): {adv['message']}")
        return advisories

    def _private_ingress_stop(self, req: ComplianceAuditRequest, compliance_data: Dict[str, Any],
                              policy_matrix: Optional[Dict[str, Any]],
                              profile: str) -> Optional[PrivateIngressUnsupportedError]:
        """PRIVATE-INGRESS-EARLY-STOP: the typed stop when `enforce_private_ingress` is on (the caller's check) and the
        plan has a Cloud Run service, which this release cannot make internal-only; the caller persists the decision
        and raises it. None: plans with no Cloud Run service continue exactly as before (the apply gate checks only
        Cloud Run services)."""
        services = self._planned_cloud_run_services(req)
        if not services:
            return None
        sources = _private_ingress.known_sources(compliance_data.get("private_ingress_sources"))
        if _private_ingress.org_policy_asked(policy_matrix) and _private_ingress.SOURCE_ORG_POLICY not in sources:
            sources.append(_private_ingress.SOURCE_ORG_POLICY)
        spec_terms = _private_ingress.spec_terms_of(compliance_data.get("private_ingress_spec_terms"))
        return PrivateIngressUnsupportedError(
            _private_ingress.unsupported_message(services, sources, spec_terms, profile),
            reason=_private_ingress.REASON_UNSUPPORTED, stage=_private_ingress.STAGE,
            details={"product_id": req.product_id, "trace_id": req.trace_id, "cloud_run_services": list(services),
                     "requested_by": sources, "spec_terms": spec_terms, "compliance_profile": profile},
        )

    def _enrich_plan_markdown(
        self,
        plan_markdown: Optional[str],
        profile: str,
        is_regulated: bool,
        requires_cmek: bool,
        requires_audit_logging: bool,
        domain_restricted_sharing: bool = False,
        allowed_domains: Optional[List[str]] = None,
        allow_unauthenticated: bool = True,
        enable_direct_iap: bool = False,
    ) -> Optional[str]:
        if not plan_markdown:
            return None
        ingress_status = "Direct IAP (Identity-Aware Proxy SSO Ingress)" if enable_direct_iap else ("Domain-Restricted Sharing (Authenticated Ingress Enforced)" if domain_restricted_sharing else "Standard Public Ingress")
        domain_str = ", ".join(allowed_domains) if allowed_domains else ("Direct IAP Accessors" if enable_direct_iap else ("Restricted" if domain_restricted_sharing else "Unrestricted"))
        compliance_block = (
            f"\n- **Compliance Profile**: `{profile}` ({'Regulated Workload' if is_regulated else 'Standard'})\n"
            f"- **Cloud KMS CMEK Encryption**: `{'Enforced' if requires_cmek else 'Standard Google-Managed'}`\n"
            f"- **Dedicated Audit Logging**: `{'Enforced (Cloud Audit Logs Sink)' if requires_audit_logging else 'Standard Cloud Logging'}`\n"
            f"- **Direct Identity-Aware Proxy (IAP)**: `{'Enforced (Cloud Run v2 Direct IAP)' if enable_direct_iap else 'Disabled'}`\n"
            f"- **Ingress Security Policy**: `{ingress_status}`\n"
            f"- **Allowed Member Domains**: `{domain_str}`\n"
        )
        if "## 3. Security, IAM & Governance Assessment" in plan_markdown:
            return plan_markdown.replace(
                "## 3. Security, IAM & Governance Assessment",
                f"## 3. Security, IAM & Governance Assessment{compliance_block}",
            )
        return plan_markdown + f"\n\n## 3. Security, IAM & Governance Assessment{compliance_block}"

    @staticmethod
    def _decision_record(
        response: ComplianceAuditResponse,
        trace_id: str,
        *,
        profile: Optional[str],
        summary: str,
        compliance_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """FD-4R R-6: the complete persisted compliance decision (schema v2), the single source of truth for the
        developer's ingress flags (gateway `_resolve_developer_compliance_decision`) and for RESUME_DEVELOPER.

        It keeps every key the v1 record had with the same value (`compliance_profile` = the engine's profile,
        `summary`, `is_regulated`, the ingress flags, policy fields) and adds the rest of the decision
        (`enforce_private_ingress`, `requires_cmek`, `requires_audit_logging`, `injected_tasks`, `status`, the engine's
        `contract_version` / `intent_source`). The plan text and the enriched DAG are not decision data and are not
        stored (they travel in the workflow; the record stays far below the Firestore document limit)."""
        import time
        source = compliance_data if isinstance(compliance_data, dict) else {}
        now = time.time()
        return {
            "schema_version": DECISION_SCHEMA_VERSION,
            "product_id": response.product_id,
            "trace_id": trace_id,
            "compliance_profile": profile,
            "is_regulated": bool(response.is_regulated),
            "summary": summary,
            "compliance_summary": response.compliance_summary,
            "status": response.status,
            "requires_cmek": bool(response.requires_cmek),
            "requires_audit_logging": bool(response.requires_audit_logging),
            "domain_restricted_sharing": bool(response.domain_restricted_sharing),
            "allowed_domains": list(response.allowed_domains or []),
            "allow_unauthenticated": bool(response.allow_unauthenticated),
            "enable_direct_iap": bool(response.enable_direct_iap),
            "enforce_private_ingress": bool(response.enforce_private_ingress),
            "injected_tasks": list(response.injected_tasks or []),
            "has_policy_conflicts": bool(response.has_policy_conflicts),
            "policy_conflicts": list(response.policy_conflicts or []),
            "policy_matrix": dict(response.policy_matrix or {}),
            "requires_human_approval": bool(response.requires_human_approval),
            "contract_version": source.get("contract_version"),
            "intent_source": source.get("intent_source"),
            # compliance-profile-explicit (additive v2 fields, no version bump: `developer_decision_problems` ignores
            # unknown keys). `requested_profile` is the selection the server decided on (contract v3 echo-checked in
            # `_fetch_compliance_decision`); the apply-time gate's stale check compares it with the stored selection.
            "profile_source": response.compliance_profile_source or _profiles.SOURCE_DEFAULT,
            "requested_profile": source.get("requested_profile"),
            "profile_advisories": list(response.profile_advisories or []),
            # ACCESS-INTERNAL-SERVICE-ADVISORY (additive, no version bump)
            "access_advisories": list(getattr(response, "access_advisories", None) or []),
            "access_advisories_omitted": int(getattr(response, "access_advisories_omitted", 0) or 0),
            "decided_at": now,
            "timestamp": now,
        }

    @staticmethod
    def _gate_projection(record: Dict[str, Any]) -> Dict[str, Any]:
        """Lane 14 PR-0 (FD-4S, plan G15 / R17-5) on the FD-4R R-6 seam: the product-keyed copy of the decision that
        the apply-time compliance plan gate (`mcp-servers/terraform/compliance_gate.py::load_decision`) enforces in
        every execution mode, `workloads/{pid}.compliance_profile` + `.compliance_decision`.

        A pure projection of the v2 record (no second derivation): every value is read from `record`, so the gate,
        the developer resolver and `/agent/resume/outcome` see one decision."""
        matrix = record.get("policy_matrix") if isinstance(record.get("policy_matrix"), dict) else {}
        return {
            "compliance_profile": record.get("compliance_profile"),
            "compliance_decision": {
                "profile": record.get("compliance_profile"),
                "is_regulated": bool(record.get("is_regulated")),
                "enable_direct_iap": bool(record.get("enable_direct_iap")),
                "allow_unauthenticated": bool(record.get("allow_unauthenticated")),
                "enforce_private_ingress": bool(record.get("enforce_private_ingress")),
                # compliance-profile-explicit: where the profile came from (never spec words) and the selection it
                # was decided for. `load_decision` (RT F1) treats a map without `profile_source` as a legacy decision
                # and refuses one whose `requested_profile` differs from the stored selection (DECISION_STALE).
                "profile_source": record.get("profile_source") or _profiles.SOURCE_DEFAULT,
                "requested_profile": record.get("requested_profile"),
                "allowed_locations": [x for x in (matrix.get("allowed_locations") or []) if isinstance(x, str)],
                "trace_id": record.get("trace_id"),
                "recorded_at": record.get("decided_at"),
            },
        }

    def _persist_audit_record(self, record: Dict[str, Any]) -> None:
        """FD-4R R-6: persist the complete compliance decision, fail loud.

        A write error raises GATE_UNAVAILABLE `COMPLIANCE_PERSIST_FAILED` (503; the workflow's existing `except` routes
        it to the DLQ), because a decision the developer cannot read would otherwise be re-derived or defaulted. With
        no Firestore client the pipeline gate (`require_remote_engine`, i.e. the gateway route and any Cloud Run
        construction) also raises; only an explicit off-pipeline caller (tests, the eval harness, local dev) skips the
        write, logged at WARNING. The document is replaced, not merged, so no field of an older decision survives.

        Lane 14 PR-0 (integration): the plan gate's product-keyed projection (`_gate_projection`) is written in the
        SAME Firestore batch as the record, so both land or neither does, and a failure is the same
        `COMPLIANCE_PERSIST_FAILED` (never a log line that lets the apply-time gate default to STANDARD). Only the
        two projected fields of `workloads/{pid}` are replaced (`merge=[field paths]`); the rest of the workload
        document is untouched and no key of an older `compliance_decision` map survives."""
        product_id = record.get("product_id") or ""
        trace_id = record.get("trace_id") or ""
        db = self.db
        if not db:
            if self.require_remote_engine:
                raise GateUnavailableError(
                    "compliance decision not persisted: no Firestore client; the run stops instead of letting the "
                    "developer guess the ingress decision",
                    reason="COMPLIANCE_PERSIST_FAILED", stage=_private_ingress.STAGE,
                    details={"product_id": product_id, "trace_id": trace_id, "failure": "NO_STORE"},
                )
            logger.warning(f"Compliance decision for '{product_id}' ({trace_id}) not persisted: no Firestore client "
                           f"(off-pipeline caller)")
            return
        try:
            workload_ref = db.collection("workloads").document(product_id)
            projection = self._gate_projection(record)
            batch = db.batch()
            batch.set(workload_ref.collection("compliance_audits").document(trace_id), record)
            batch.set(workload_ref, projection, merge=sorted(projection))
            batch.commit()
        except Exception as e:
            raise GateUnavailableError(
                f"compliance decision not persisted: {type(e).__name__}: {e}",
                reason="COMPLIANCE_PERSIST_FAILED", stage=_private_ingress.STAGE,
                details={"product_id": product_id, "trace_id": trace_id, "failure": "WRITE"},
            ) from e
