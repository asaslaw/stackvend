"""Drive the real generation pipeline in-process (plan §2; red-team H3, H4, L1).

Imported only inside the guarded generation child. Stage order mirrors workflows/main_orchestrator.yaml:
architect (+consensus) -> compliance -> developer.generate_code_files -> commit_and_open_pr (pre-commit gate,
captured at the token fetch; MOCK_COMMITTED, nothing pushed) -> gatekeeper step 4.5 on the committed tree.

Checkpoints (H3):  C0_raw (LLM file dict: swarm return or single-turn JSON)  C1_healers_off (generate_code_files
return when --healers-off)  C2_generated (generate_code_files return)  C3_committed (tree at the token fetch inside
commit_and_open_pr, i.e. what production would push).
"""
from __future__ import annotations

import asyncio
import dataclasses
import importlib
import inspect
import json
import re
import sys
import time
import traceback
import types
from typing import Any, Callable, Dict, List, Optional, Tuple

from .cassettes import HARNESS_DEFAULT_FALLBACK_MODELS
from .errors import EvalAbort
from .llm_proxy import SITE_CTX, find_product_frame
from .state import RunState

PRODUCT_MODULES = [
    "shared.settings",
    "shared.github_resilience",
    "architect_agent.handler",
    "architect_agent.red_team_critic",
    "compliance_agent.handler",
    "compliance_agent.schemas",
    "developer_agent.handler",
    "developer_agent.lead_orchestrator",
    "developer_agent.swarm_dispatcher",
    "developer_agent.preflight_validator",
    "developer_agent.terraform_engine",
    "gatekeeper_agent.verifier",
]
SOURCE_CHANNEL = "control_center_form"  # apps/control-center/routes/workloads.py submit path
AGENT_MODEL_FIELDS = ("architect_model", "developer_model", "finops_model", "assistant_model")


def _typed_failure(e: BaseException) -> Optional[Dict[str, Any]]:
    """A Step 1 StageError carries `.report` (ValidationReport) with an ErrorClass; anything else is untyped."""
    report = getattr(e, "report", None)
    if report is None:
        return None
    ec = getattr(report, "error_class", None)
    diags = list(getattr(report, "diagnostics", None) or [])
    return {"exception": type(e).__name__, "error_class": getattr(ec, "value", ec),
            "status": getattr(report, "status", None), "codes": sorted({getattr(d, "code", "") for d in diags}),
            "diagnostics": [d.model_dump(mode="json") if hasattr(d, "model_dump") else str(d) for d in diags][:200],
            "message": str(e)[:1500]}


def import_product() -> Dict[str, types.ModuleType]:
    # L1: production's container has no mcp-servers/compliance on disk, so `from service import
    # ComplianceService` fails there; mimic that instead of importing the MCP module from the checkout.
    sys.modules.setdefault("service", types.ModuleType("service"))
    return {m: importlib.import_module(m) for m in PRODUCT_MODULES}


def rebind(old: Any, new: Any) -> int:
    n = 0
    for mod in list(sys.modules.values()):
        d = getattr(mod, "__dict__", None)
        if not isinstance(d, dict):
            continue
        for k, v in list(d.items()):
            if v is old:
                setattr(mod, k, new)
                n += 1
    return n


def pin_settings(mods: Dict[str, Any], model: str, fallback_models: Optional[List[str]]) -> Dict[str, Any]:
    S = mods["shared.settings"]
    base = S.PlatformSettings()
    upd = {f: model for f in AGENT_MODEL_FIELDS if f in type(base.models).model_fields}
    # DEFAULT-MODEL-GEMINI-4-CARBON: no list given = the harness's pinned fallback, never the product default
    upd["fallback_models"] = list(HARNESS_DEFAULT_FALLBACK_MODELS if fallback_models is None else fallback_models)
    pinned = base.model_copy(update={"models": base.models.model_copy(update=upd)})
    S._SETTINGS_CACHE = pinned
    S._LAST_FETCH_TIME = float("inf")

    # Row SWARM-TOK-1: the stand-in takes exactly the real function's parameters. A call the real function would
    # reject (e.g. the old `get_platform_settings(db=...)`, a swallowed TypeError in production) raises the same
    # TypeError here instead of quietly receiving the pinned settings.
    real_signature = inspect.signature(S.get_platform_settings)

    def get_platform_settings(*args: Any, **kwargs: Any) -> Any:
        real_signature.bind(*args, **kwargs)
        return pinned
    get_platform_settings.__signature__ = real_signature  # type: ignore[attr-defined]
    rebind(S.get_platform_settings, get_platform_settings)
    if hasattr(S, "invalidate_settings_cache"):
        rebind(S.invalidate_settings_cache, lambda *a, **k: None)
    return json.loads(pinned.model_dump_json())


RUNTIME_MODULE = "developer_agent.hallucination_runtime"


def install_hallucination_runtime(mods: Dict[str, Any], *, run_dir: Any, validate_client: str,
                                  repair_iterations: Optional[int], repair_model: Optional[str],
                                  iac_intent_mode: Optional[str] = None) -> Dict[str, Any]:
    """S1-0 (lane 8B §8, Step 1 RT F6): configure the product's hallucination-stack runtime for this child exactly as
    gateway startup would, with harness implementations: MemoryLedgerStore/MemoryProvenanceStore (no Firestore),
    HarnessValidateClient (V1b over file IPC to the parent) and the per-run repair settings. Returns what was set.
    TI-3: `iac_intent_mode` sets the product's HallucinationStackSettings.iac_intent_mode explicitly ("off" too, TI-3h:
    the harness states the mode it measures instead of relying on a product default); None = no override key."""
    from pathlib import Path as _P
    try:
        rt = importlib.import_module(RUNTIME_MODULE)
    except ImportError:
        return {"installed": False, "reason": f"product has no {RUNTIME_MODULE} (pre-Step-1 checkout)"}
    if validate_client != "harness":
        # no V1b in this run: the product's stack stays unconfigured (its legacy path), exactly like a pre-Step-1
        # product; measuring the stack needs --validate-client harness
        return {"installed": False, "reason": "--validate-client none: hallucination stack not configured"}
    from .validate_client import HarnessValidateClient
    client = HarnessValidateClient(_P(run_dir) / "ipc")
    overrides: Dict[str, Any] = {}
    if repair_iterations is not None:
        overrides["repair_max_iterations_precommit"] = int(repair_iterations)
    if repair_model:
        overrides["repair_model"] = repair_model
    if iac_intent_mode:   # TI-3h: an explicit "off" is passed too
        overrides["iac_intent_mode"] = iac_intent_mode
    info = rt.configure_for_harness(validate_client=client, settings_overrides=overrides)
    return {"installed": True, "validate_client": validate_client, "settings_overrides": overrides,
            "configured": info}


REPAIR_LOOP_MODULE = "developer_agent.repair_loop"


def _compact_diag(x: Any) -> Dict[str, Any]:
    return {"code": x.code, "file": x.file, "block": x.block_address, "symbol": x.symbol,
            "attribute_path": x.attribute_path, "message": (x.message or "")[:240]}


def install_accept_observer(sink: List[Dict[str, Any]],
                            shadow: Optional[Dict[int, Tuple[bool, Optional[str]]]] = None) -> Dict[str, Any]:
    """Step 1 R3c offline re-scoring (eval only, $0): wrap the product's repair acceptance `accept()` and record, per
    candidate, the product's own verdict plus the diagnostics it fixed / introduced. With `shadow` (recorded verdicts
    by repair iteration, from an earlier run's RepairEvents) the loop is handed the RECORDED verdict, so every later
    repair prompt equals the recorded one and the replay keeps matching the cassette; the product's verdict is only
    recorded ("shadow acceptance"). Without `shadow` the product's verdict is returned unchanged (observe only)."""
    try:
        rl = importlib.import_module(REPAIR_LOOP_MODULE)
    except ImportError:
        return {"installed": False, "reason": f"product has no {REPAIR_LOOP_MODULE}"}
    real = rl.accept

    def observed(d, d2, asm, asm2, prev, new, removed, engine_label, renamed=None):  # noqa: ANN001
        verdict = real(d, d2, asm, asm2, prev, new, removed, engine_label, renamed)
        P = {rl.fingerprint(x): x for x in prev.diagnostics if x.severity == "error"}
        N = ({rl.fingerprint(x): x for x in new.diagnostics if x.severity == "error"} if new.status == "FAIL" else {})
        it = int(getattr(new, "repair_iteration", 0) or 0)
        rec: Dict[str, Any] = {
            "iteration": it, "product_verdict": [bool(verdict[0]), verdict[1]], "status_after": new.status,
            "n_before": len(P), "n_after": len(N), "removed": sorted(removed),
            "fixed": [_compact_diag(P[f]) for f in sorted(set(P) - set(N))],
            "new": [_compact_diag(N[f]) for f in sorted(set(N) - set(P))]}
        explain = getattr(rl, "removal_justifications", None)
        if callable(explain):
            try:
                rec["removal_justifications"] = explain(d, d2, asm, asm2, prev, removed)
            except Exception as e:  # noqa: BLE001 - observation only
                rec["removal_justifications_error"] = f"{type(e).__name__}: {e}"
        if shadow is not None and it in shadow:
            forced = shadow[it]
            rec["forced_verdict"] = [bool(forced[0]), forced[1]]
            verdict = (bool(forced[0]), forced[1])
        sink.append(rec)
        return verdict

    rl.accept = observed
    return {"installed": True, "shadow": shadow is not None,
            "shadow_iterations": sorted(shadow) if shadow is not None else []}


def install_site_shim() -> None:
    """asyncio.to_thread runs junior calls on a worker thread whose stack has no product frame; record the
    awaiting product frame in a contextvar (to_thread copies the context into the thread)."""
    real = asyncio.to_thread
    if getattr(real, "_stackvend_site_shim", False):
        return

    async def to_thread(func: Callable, /, *args: Any, **kwargs: Any) -> Any:
        gw = getattr(to_thread, "gateway_dir", "")
        site, _ = find_product_frame(gw, start_depth=1) if gw else ("unknown", None)
        token = SITE_CTX.set(site)
        try:
            return await real(func, *args, **kwargs)
        finally:
            SITE_CTX.reset(token)
    to_thread._stackvend_site_shim = True  # type: ignore[attr-defined]
    asyncio.to_thread = to_thread


# Lane 19 L19-2 (FD-4I): the developer no longer guesses invokers for a private workload (it used to take the harness's
# ADMIN_USER_EMAIL). The harness plays the operator who answers the ACCESS_POLICY_INCOMPLETE HITL with that same
# principal, so private examples (09) keep their coverage and their generated IaC. Public runs pass no record.
HARNESS_OPERATOR_PRINCIPAL = "user:eval@example.invalid"


def harness_access(comp: Any) -> Any:
    iap = getattr(comp, "enable_direct_iap", None) is True
    if not iap and getattr(comp, "allow_unauthenticated", None) is not False:
        return None
    return {"mode": "PRIVATE_IAP" if iap else "PRIVATE_IAM", "invoker_principals": [HARNESS_OPERATOR_PRINCIPAL],
            "sign_in": {"google": "DISABLED"}, "source": "operator_hitl"}


# FD-4AF RT F3: production's developer takes the vended child project from the workload record that project vending
# writes (workloads/{product_id}.project_id, read in generate_code_files); DeveloperExecuteRequest has no such field.
# The harness has no vending stage and no Firestore (DeveloperAgent(project_id="") skips that read), so it plays
# project vending: a deterministic, clearly fake project id per example, handed to the product at the one place the
# product puts that record value (AssemblyInputs.target_project_id). The region needs nothing here: the product reads
# it from the pinned settings (orchestration.default_gcp_region). Nothing is created; the id is never contacted.
HARNESS_WORKLOAD_PROJECT_PATTERN = re.compile(r"[a-z][a-z0-9-]{4,28}[a-z0-9]")  # GCP project id format


def harness_workload_project(example: str) -> str:
    pid = f"eval-{str(example).lower() or 'workload'}-project"
    if not HARNESS_WORKLOAD_PROJECT_PATTERN.fullmatch(pid):
        raise ValueError(f"example id {example!r} gives no valid harness project id ({pid!r})")
    return pid


def supply_workload_record(dev: Any, project_id: str) -> List[str]:
    """Give one DeveloperAgent instance the vended project its workload record would hold. Fills
    AssemblyInputs.target_project_id only when the product resolved none (the record read the harness cannot serve);
    a value the product did resolve is never replaced. Products without that seam are left as they are. Returns the
    methods it wrapped (instance attributes only; the class and every other instance are untouched)."""
    wrapped_names: List[str] = []
    for name in ("_run_hallucination_stack", "_assemble_tree"):
        orig = getattr(dev, name, None)
        if orig is None:
            continue

        def wrapped(draft: Any, inputs: Any, *args: Any, _orig: Callable[..., Any] = orig, **kwargs: Any) -> Any:
            if (dataclasses.is_dataclass(inputs) and hasattr(inputs, "target_project_id")
                    and not inputs.target_project_id):
                inputs = dataclasses.replace(inputs, target_project_id=project_id)
            return _orig(draft, inputs, *args, **kwargs)
        setattr(dev, name, wrapped)
        wrapped_names.append(name)
    # COMMITTED-READ-VIEW (M1): the product's one project-ID resolver (assembly and the swarm's read view), so the
    # swarm reads the manifests with the same vended project the commit gets; a value it resolved is kept
    orig_pid = getattr(dev, "_workload_project_id", None)
    if orig_pid is not None:
        def wrapped_pid(product_id: str, record: Any = None, _orig: Callable[..., Any] = orig_pid) -> str:
            return _orig(product_id, record=record) or project_id
        setattr(dev, "_workload_project_id", wrapped_pid)
        wrapped_names.append("_workload_project_id")
    return wrapped_names


class Pipeline:
    def __init__(self, *, state: RunState, mods: Dict[str, Any], proxy: Any, product_id: str, spec_text: str,
                 trace_id: str, stop_after: Optional[str] = None, topology_fixture: Optional[str] = None,
                 example: str = ""):
        self.state = state
        self.stop_after = stop_after  # --stop-after: end the run after this stage (architect-only record)
        # --topology-fixtures (lane 10 checkpoint A, replay only): the recorded architect answers predate the
        # service_topology field; "legacy-equivalent" hands the product the topology that reproduces the recorded
        # run's own service set (so every developer request stays byte-identical) plus the example's typed edges.
        self.topology_fixture = topology_fixture
        self.example = example
        self.mods = mods
        self.proxy = proxy
        self.product_id = product_id
        self.spec_text = spec_text
        self.trace_id = trace_id
        self.checkpoints: Dict[str, Any] = {}
        self.stages: Dict[str, Any] = {}
        self.outcome: Optional[str] = None
        self.capture: Dict[str, Any] = {}
        # S1-0: AssemblyRecord (S1-A), validation report / repair events / typed failure (S1-B), when the product has them
        self.hallucination_stack: Dict[str, Any] = {}

    # ------------------------------------------------------------------------------------- patches (H4)
    def install_patches(self) -> None:
        dev_mod = self.mods["developer_agent.handler"]
        DA = dev_mod.DeveloperAgent
        state, capture = self.state, self.capture

        def fetch_existing_repo_files(self_: Any, *args: Any, **kwargs: Any) -> Dict[str, str]:
            return {}  # greenfield: no VCS read

        def fetch_github_token(self_: Any) -> str:
            caller = sys._getframe(1)
            if caller.f_code.co_name == "commit_and_open_pr":
                files = caller.f_locals.get("files")
                if isinstance(files, dict):
                    capture["C3_committed"] = {k: v for k, v in files.items() if isinstance(v, str)}
                    capture["capture_point"] = "commit_and_open_pr:fetch_github_token"
            else:
                state.record("github_token_requested", {"caller": caller.f_code.co_qualname})
            return ""

        DA.fetch_existing_repo_files = fetch_existing_repo_files
        DA.fetch_github_token = fetch_github_token
        gr = self.mods["shared.github_resilience"]
        if hasattr(gr, "get_github_token"):
            rebind(gr.get_github_token, lambda *a, **k: None)

    # ------------------------------------------------------------------------------------------- stages
    def _stage(self, name: str, fn: Callable[[], Any]) -> Any:
        self.state.check_boundary(name)
        t0 = time.time()
        rec: Dict[str, Any] = {"ok": False}
        self.stages[name] = rec
        try:
            out = fn()
            rec["ok"] = True
            return out
        except EvalAbort:
            raise
        except BaseException as e:  # noqa: BLE001
            rec["error"] = f"{type(e).__name__}: {str(e)[:1500]}"
            rec["traceback"] = traceback.format_exc()[-6000:]
            raise
        finally:
            rec["wall_s"] = round(time.time() - t0, 3)

    def run(self) -> None:
        try:
            ares = self._stage("architect", self._architect)
            if self.stop_after == "architect":
                self.outcome = "stopped_after_architect" if self.state.valid else "invalid"
                return
            comp = self._stage("compliance", lambda: self._compliance(ares))
            files = self._stage("developer", lambda: self._developer(ares, comp))
        except EvalAbort as e:
            self.outcome = "invalid"
            self.stages.setdefault("_abort", {})["reason"] = str(e)
            return
        except BaseException as e:  # noqa: BLE001
            typed = _typed_failure(e)
            if typed is not None and self.state.valid:
                # S1-0: a Step 1 developer stage that stops with a typed StageError (diagnostics + ErrorClass)
                self.hallucination_stack["developer_failed_typed"] = typed
                self.outcome = "developer_failed_typed"
                return
            self.outcome = "invalid" if not self.state.valid else "generation_error"
            return
        try:
            self._stage("precommit", lambda: self._precommit(files))
        except EvalAbort as e:
            self.outcome = "invalid"
            self.stages.setdefault("_abort", {})["reason"] = str(e)
            return
        except RuntimeError as e:
            self.stages["precommit"]["rejected"] = True
            self.outcome = "precommit_rejected"
            self.stages["precommit"]["error"] = f"RuntimeError: {str(e)[:1500]}"
        except BaseException:  # noqa: BLE001
            self.outcome = "generation_error"
            return
        if "C3_committed" in self.checkpoints and self.outcome is None:
            try:
                passed = self._stage("gatekeeper_4_5", self._gatekeeper)
                self.outcome = "committed_passed" if passed else "gatekeeper_rejected"
            except EvalAbort as e:
                self.outcome = "invalid"
                self.stages.setdefault("_abort", {})["reason"] = str(e)
            except BaseException:  # noqa: BLE001
                self.outcome = "gatekeeper_rejected"
        elif self.outcome is None:
            self.outcome = "generation_error"
            self.stages.setdefault("precommit", {})["note"] = "commit_and_open_pr returned without reaching capture"
        if not self.state.valid:
            self.outcome = "invalid"

    def _architect(self) -> Any:
        AA = self.mods["architect_agent.handler"].ArchitectAgent
        agent = AA(project_id="")
        agent.genai_client = self.proxy
        if self.topology_fixture == "legacy-equivalent" and hasattr(self.mods["architect_agent.handler"],
                                                                     "gate_service_topology"):
            self._install_topology_fixture(agent)
        res = agent.decompose(spec_text=self.spec_text, spec_doc_id="", product_id=self.product_id,
                              trace_id=self.trace_id, source_channel=SOURCE_CHANNEL, workspace_mcp_url="",
                              policy_matrix=None, human_feedback=None, quota_snapshot=None)
        ct = res.consensus_telemetry
        ct_d = ct.model_dump() if hasattr(ct, "model_dump") else (ct if isinstance(ct, dict) else {})
        self.stages["architect"].update({
            "tasks": len(res.task_dag), "consensus_status": ct_d.get("consensus_status"),
            "remediation_performed": ct_d.get("remediation_performed"),
            "requires_human_approval": res.architecture_plan.requires_human_approval,
            "target_compute_services": list(res.architecture_plan.target_compute_services or []),
            # typed compute fields (absent on product roots before the field): the record the developer consumes
            "compute_archetype": getattr(res.architecture_plan, "compute_archetype", None),
            "bundle_id": getattr(res.architecture_plan, "bundle_id", None),
            "compute_intent": getattr(res, "compute_intent", None),
            "plan_file_path": res.plan_file_path})
        return res

    # Lane 10 checkpoint A: typed edges per example (data). Only 02 has a planned service-to-service call
    # (public gateway -> internal core); 06's storefront -> worker is a Pub/Sub push (a resource, not an edge) and 05's
    # edge gateway reaches GKE through Kubernetes networking (never an edge).
    FIXTURE_EDGES = {"02": "first-calls-second"}

    def legacy_equivalent_topology(self, plan: Any) -> Dict[str, Any]:
        """The topology whose service set equals what the product resolves today from the recorded plan (typed
        compute intent: target_compute_services + bundle table), primary first, secondaries Cloud Run."""
        ci = importlib.import_module("developer_agent.compute_intent")
        rec = {"target_compute_services": list(getattr(plan, "target_compute_services", None) or []),
               "bundle_id": getattr(plan, "bundle_id", None),
               "compute_archetype": getattr(plan, "compute_archetype", None)}
        intent = ci.resolve_compute_intent(self.product_id, rec, {})
        names = list(intent.service_names)
        if intent.archetype == "foundation-only" or not names:
            return {"services": [], "primary_service": None, "edges": [], "resources": []}
        services = [{"name": names[0], "kind": intent.archetype}] + [{"name": n, "kind": "cloudrun"} for n in names[1:]]
        edges = []
        if self.FIXTURE_EDGES.get(self.example[:2]) == "first-calls-second" and len(names) >= 2:
            edges = [{"caller": names[0], "callee": names[1], "protocol": "http"}]
        return {"services": services, "primary_service": names[0], "edges": edges, "resources": []}

    def _install_topology_fixture(self, agent: Any) -> None:
        original = agent._single_turn_decompose
        schema_mod = self.mods["architect_agent.schemas"] if "architect_agent.schemas" in self.mods else \
            importlib.import_module("architect_agent.schemas")

        def wrapped(**kw: Any) -> Any:
            plan = original(**kw)
            if getattr(plan, "_raw_service_topology", None) is None and not getattr(plan, "_is_fallback", False):
                topo = self.legacy_equivalent_topology(plan)
                plan._raw_service_topology = topo
                try:
                    plan.service_topology = schema_mod.ServiceTopologyIntent.model_validate(topo)
                except Exception:  # noqa: BLE001 - the product's gate reports it
                    pass
                self.stages.setdefault("architect", {})["topology_fixture"] = topo
            return plan
        agent._single_turn_decompose = wrapped

    def _compliance(self, ares: Any) -> Any:
        CH = self.mods["compliance_agent.handler"].ComplianceAgentHandler
        Req = self.mods["compliance_agent.schemas"].ComplianceAuditRequest
        # Compliance bundle (row 43): the gateway no longer falls back to an embedded engine when the server is
        # unreachable; the harness asks explicitly for the deployed server's engine, run in-process (off Cloud Run).
        h = CH(compliance_server_url="http://127.0.0.1:1", mode="inprocess", require_remote_engine=False)
        h.genai_client = self.proxy
        res = h.audit_and_enrich(Req(product_id=self.product_id, spec_text=self.spec_text,
                                     task_dag=[t.model_dump() for t in ares.task_dag], folder_id="",
                                     trace_id=self.trace_id, plan_markdown=ares.plan_markdown or "",
                                     plan_file_path=ares.plan_file_path or "", policy_matrix=None))
        self.stages["compliance"].update({
            "profile": res.compliance_profile, "injected_tasks": len(res.injected_tasks or []),
            "allow_unauthenticated": res.allow_unauthenticated,
            "enable_direct_iap": getattr(res, "enable_direct_iap", False),
            "domain_restricted_sharing": res.domain_restricted_sharing})
        return res

    def _developer(self, ares: Any, comp: Any) -> Dict[str, str]:
        DA = self.mods["developer_agent.handler"].DeveloperAgent
        dev = DA(project_id="")
        dev.genai_client = self.proxy
        self._dev = dev
        workload_project = harness_workload_project(self.example)
        self.stages["developer"]["workload_record"] = {
            "project_id": workload_project, "source": "harness_project_vending",
            "seam": supply_workload_record(dev, workload_project)}

        def pick(v: Any, default: Any) -> Any:  # Cloud Workflows default(): only null falls through
            return default if v is None else v
        task_dag = pick(comp.enriched_dag, [t.model_dump() for t in ares.task_dag])
        try:
            return self._generate(dev, ares, comp, task_dag, pick)
        finally:
            self._collect_stack_records(dev)

    def _collect_stack_records(self, dev: Any) -> None:
        """S1-0: product-side records the developer agent keeps for its last run (absent on older products)."""
        for attr, key in (("last_assembly_record", "assembly_record"), ("last_validation_report", "validation_report"),
                          ("last_repair_events", "repair_events"), ("last_envelope_checks", "envelope_checks"),
                          ("last_compute_intent", "compute_intent")):
            val = getattr(dev, attr, None)
            if val is None:
                continue
            if hasattr(val, "model_dump"):
                val = val.model_dump(mode="json")
            elif isinstance(val, list):
                val = [v.model_dump(mode="json") if hasattr(v, "model_dump") else v for v in val]
            self.hallucination_stack[key] = val
        tree = getattr(dev, "last_assembled_tree", None)
        if isinstance(tree, dict):  # stored as a tree + blobs like every checkpoint (never inline in result.json)
            self.checkpoints["C2a_assembled_last"] = {k: v for k, v in tree.items() if isinstance(v, str)}

    def _generate(self, dev: Any, ares: Any, comp: Any, task_dag: Any, pick: Callable[[Any, Any], Any]) -> Dict[str, str]:
        access = harness_access(comp)
        extra = {"access": access} if access is not None else {}
        files = dev.generate_code_files(
            product_id=self.product_id, spec_text=self.spec_text, task_dag=task_dag, trace_id=self.trace_id,
            plan_markdown=pick(comp.plan_markdown, pick(ares.plan_markdown, "")),
            plan_file_path=pick(comp.plan_file_path, pick(ares.plan_file_path, "")),
            domain_restricted_sharing=pick(comp.domain_restricted_sharing, False),
            allowed_domains=pick(comp.allowed_domains, []),
            allow_unauthenticated=pick(comp.allow_unauthenticated, True),
            enable_direct_iap=pick(getattr(comp, "enable_direct_iap", None), False),
            target_compute_services=[], tf_retry_count=0, tf_remediation_context=None,
            # Production handoff (HD-01/HD-02): the architect persists this record on pipeline_executions/{trace} and
            # the developer reads it by trace id; the harness has no Firestore, so it hands over the same record.
            architect_compute_intent=getattr(ares, "compute_intent", None), **extra)
        files = {k: v for k, v in (files or {}).items() if isinstance(v, str)}
        raw_responses = getattr(self.proxy, "raw_responses", None) or {}
        single_turn = [s for s in raw_responses if s.endswith("DeveloperAgent.generate_code_files")]
        if self.checkpoints.get("C0_raw_swarm"):
            path = "swarm"
        elif single_turn:
            path = "single_turn"
            try:
                parsed = json.loads(raw_responses[single_turn[0]][-1])
                if isinstance(parsed, dict) and isinstance(parsed.get("files"), dict):
                    self.checkpoints["C0_raw_single_turn"] = parsed["files"]
            except Exception:
                self.checkpoints["C0_raw_single_turn_unparsed"] = True
        else:
            path = "none"
        self.stages["developer"].update({"path": path, "files": len(files)})
        self.checkpoints["C2_generated"] = dict(files)
        return files

    def _precommit(self, files: Dict[str, str]) -> None:
        dev = self.mods["developer_agent.handler"].DeveloperAgent(project_id="")
        dev.genai_client = self.proxy
        try:
            res = dev.commit_and_open_pr(product_id=self.product_id, files=dict(files),
                                         branch_name=f"castor/{self.product_id}-eval",
                                         commit_message=f"feat({self.product_id}): eval", github_repo=None,
                                         trace_id=self.trace_id)
        except RuntimeError as e:
            # FD-4F A9 (Q-E): products after the fail-closed change raise a typed GATE_UNAVAILABLE
            # (reason VCS_CREDENTIAL_UNAVAILABLE) at the token fetch instead of returning MOCK_COMMITTED. The tree was
            # captured at that same point (after the pre-commit gate), so the run continues exactly as with an older
            # product's MOCK_COMMITTED return; any other error is the product's pre-commit verdict.
            if getattr(e, "reason", None) != "VCS_CREDENTIAL_UNAVAILABLE" or "C3_committed" not in self.capture:
                raise
            res = {"status": "MOCK_COMMITTED"}
        self.stages["precommit"]["status"] = (res or {}).get("status")
        if "C3_committed" in self.capture:
            self.checkpoints["C3_committed"] = self.capture["C3_committed"]
            self.stages["precommit"]["capture_point"] = self.capture.get("capture_point")
        if (res or {}).get("status") != "MOCK_COMMITTED":
            self.state.record("unexpected_commit_status", {"status": (res or {}).get("status")})

    def _gatekeeper(self) -> bool:
        V = self.mods["gatekeeper_agent.verifier"].SynthesisVerifierAgent
        committed = dict(self.checkpoints["C3_committed"])
        # FD-55 W8: no `archetype` (the product's cure is archetype-free; an older product defaults to "cloudrun",
        # the value this call used to pass, so both read the same)
        cured, passed, errors = V(product_id=self.product_id).verify_and_cure(
            dict(committed), product_id=self.product_id)
        cured = cured or committed
        diff = sorted(k for k in set(cured) | set(committed) if cured.get(k) != committed.get(k))
        self.stages["gatekeeper_4_5"].update({"passed": bool(passed), "errors": [str(e)[:300] for e in (errors or [])][:50],
                                              "idempotent": not diff, "diff_files": diff[:100]})
        return bool(passed)
