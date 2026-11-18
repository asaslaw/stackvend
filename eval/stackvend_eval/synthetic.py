"""Offline synthetic LLM backend (tests and harness end-to-end checks only; never a baseline).

It answers each known call site with a schema-valid response built from the product's OWN deterministic
fallbacks (captured before the tripwires wrap them), so the pipeline takes the normal LLM path offline and the
harness can be exercised end to end at $0. Synthetic runs are labeled llm_mode=synthetic and are refused by
--baseline. Usage metadata is synthesized (bytes/4) so the budget path is exercised too.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, Optional


def _response(text: str, prompt_bytes: int) -> Any:
    from google.genai import types
    return types.GenerateContentResponse.model_validate({
        "candidates": [{"content": {"role": "model", "parts": [{"text": text}]}, "finish_reason": "STOP"}],
        "usage_metadata": {"prompt_token_count": max(1, prompt_bytes // 4),
                           "candidates_token_count": max(1, len(text.encode()) // 4),
                           "thoughts_token_count": 0},
        "model_version": "eval-synthetic",
    })


_ASSIGNED_HEADER = "Mandatory Assigned Files (You must ONLY generate these exact files):\n"
SYNTHETIC_INTENT_PATH = "infra/workload/iac_intent.json"   # shared/iac_intent.INTENT_PATH
SYNTHETIC_INTENT = {"schema": "iac_intent/v1",
                    "modules": [{"module": "storage-bucket", "name": "synthetic_data",
                                 "args": {"bucket_name_suffix": "synthetic"}}],
                    "outputs": [{"name": "synthetic_data_bucket",
                                 "value": {"$ref": {"kind": "module_output", "module": "synthetic_data",
                                                    "output": "bucket_name"}}}]}


def synthetic_junior_files(prompt: str) -> Dict[str, str]:
    """Minimal schema-valid junior output for the files the junior prompt assigns (eval-only stand-in).

    The product's own stub generator (SwarmDispatcher._generate_deterministic_junior_files) was deleted by lane 19
    (owner register row 27a: no stub files without an LLM), so the synthetic backend owns this now. The assigned
    list is read with an exact JSON decode right after the dispatcher's fixed header line."""
    _, sep, tail = prompt.partition(_ASSIGNED_HEADER)
    if not sep:
        return {}
    try:
        assigned, _ = json.JSONDecoder().raw_decode(tail)
    except ValueError:
        return {}
    files: Dict[str, str] = {}
    for f in assigned if isinstance(assigned, list) else []:
        if not isinstance(f, str):
            continue
        if f.endswith(".py"):
            files[f] = "# Auto-generated module by Junior Specialist\nimport logging\nlogger = logging.getLogger(__name__)\n"
        elif f.endswith(".tf"):
            files[f] = '# Auto-generated infrastructure module\nterraform {\n  required_version = ">= 1.5.0"\n}\n'
        elif f == SYNTHETIC_INTENT_PATH:
            # TI-3: a gate-clean typed intent with one golden module, so the intent path (gate, render, vendoring,
            # V1b on custom.tf.json) runs end to end offline
            files[f] = json.dumps(SYNTHETIC_INTENT, indent=2, sort_keys=True) + "\n"
        elif f == "Procfile":
            files[f] = "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n"
        elif f == "requirements.txt":
            files[f] = "fastapi>=0.110.0\nuvicorn>=0.28.0\npytest>=8.0.0\n"
        else:
            files[f] = "# Config\n"
    return files


def synthetic_topology(product_id: Any) -> Dict[str, Any]:
    """One Cloud Run service named after the product (lane 10 single-service default), as a ServiceName."""
    name = str(product_id or "workload").strip().lower().replace("_", "-")[:40].rstrip("-") or "workload"
    return {"services": [{"name": name, "kind": "cloudrun", "purpose": "SYNTHETIC service"}],
            "primary_service": name, "edges": [], "resources": []}


class SyntheticBackend:
    def __init__(self, originals: Dict[str, Callable[..., Any]]):
        # originals: {"architect_fallback": ArchitectAgent._fallback_plan, "lead_fallback": ...}
        self.originals = originals
        self.unknown_sites: list = []

    def __call__(self, *, site: str, frame: Any, model: str, contents: Any, config: Any) -> Any:
        prompt = contents if isinstance(contents, str) else json.dumps(contents, default=str)
        loc = dict(frame.f_locals) if frame is not None else {}
        nbytes = len(prompt.encode())
        if "ArchitectAgent." in site:
            agent = loc.get("self")
            prod = loc.get("prod") or loc.get("product_id") or "workload"
            # lane 10: the architect's answer carries a single-service service_topology (the fallback plan alone no
            # longer passes the topology gate); the gate's one repair call (response_schema ServiceTopologyIntent)
            # gets the topology alone.
            topology = synthetic_topology(prod)
            if getattr(getattr(config, "response_schema", None), "__name__", "") == "ServiceTopologyIntent":
                return _response(json.dumps(topology), nbytes)
            spec = loc.get("final_spec_text") or loc.get("spec_text") or prompt
            plan = self.originals["architect_fallback"](agent, prod, spec)
            body = json.loads(plan.model_dump_json())
            body.update(compute_archetype="cloudrun", target_compute_services=[topology["primary_service"]],
                        service_topology=topology)
            return _response(json.dumps(body), nbytes)
        if "RedTeamCritic." in site:
            return _response(json.dumps({"soundness_score": 0.95, "has_critical_findings": False, "findings": [],
                                         "gauntlet_checks": [], "verdict_summary": "SYNTHETIC critique"}), nbytes)
        if "LeadDeveloperOrchestrator." in site:
            lead = loc.get("self")
            plan = self.originals["lead_fallback"](
                lead, product_id=loc.get("product_id", "workload"), iac_engine=loc.get("iac_engine", "OPENTOFU"),
                vcs_provider=loc.get("vcs_provider", "GITHUB"),
                max_swarm_token_envelope=loc.get("configured_envelope", 350_000),
                **({"iac_intent": True} if loc.get("iac_intent_rule") else {}))   # TI-3: the lead's own intent rule
            return _response(plan.model_dump_json(), nbytes)
        if "SwarmDispatcher." in site:
            files = synthetic_junior_files(prompt)
            return _response(json.dumps({"files": files}), nbytes)
        self.unknown_sites.append(site)
        return _response(json.dumps({"files": {}}), nbytes)
