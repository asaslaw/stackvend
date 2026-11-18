"""
Compliance enforcement gate, terraform side (lane 14 PR-0, FD-4S / FD-4R).

After `tofu plan` and before EVERY apply (deploy_workload's applies, the saved-plan `apply_plan`), the plan JSON is
sent to the compliance server's `POST /evaluate-plan` together with the workload's stored compliance decision. The
apply runs only on `decision == "PASS"`. Everything else fails closed:

  * a violation                                   -> `COMPLIANCE_VIOLATION` (structured violations)
  * an unknown stored profile                     -> `UNKNOWN_PROFILE`
  * compliance server unreachable / 4xx / 5xx /
    bad JSON / wrong contract / no URL / no token,
    Firestore decision unreadable, plan unreadable -> `COMPLIANCE_UNAVAILABLE`

Profile source (plan G15, compliance-profile-explicit + its Opus RT F1). `S` = the explicit selection
`workloads/{pid}.requested_compliance_profile` (written by the Control Center create form, the Pub/Sub intake and the
audit). Never inferred from spec text.
  1. `workloads/{pid}.compliance_decision` (written by the compliance agent's audit):
     * with `profile_source` (current gateway): used as is when its `requested_profile` equals `S`; otherwise it was made
       for another selection and the apply stops (`DECISION_STALE`: run a full build to re-audit);
     * without `profile_source` (recorded before the explicit-profile change; its profile may be a spec-keyword guess):
       its profile is replaced by `S`, else STANDARD; its ingress flags and allowed locations are kept
       (`LEGACY_DECISION_REBASED`);
  2. else `S` (covers runs with no audit, e.g. Express);
  3. else the legacy bare `workloads/{pid}.compliance_profile`;
  4. else STANDARD recorded as `profile_source: "DEFAULT_STANDARD"`.

The compliance server is reached with a Google ID token (audience = its https Cloud Run origin), never anonymously.
Its URL is `COMPLIANCE_SERVER_URL`, else the deterministic Cloud Run URL built from this runtime's own project number
and region read from the metadata server (no literal project, region or URL in code: invariant 3). No gcloud, REST
only (invariant 7).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import urlsplit

logger = logging.getLogger("mcp-terraform-server.compliance-gate")

GATE_CONTRACT_VERSION = 1
GATE_DECISIONS = frozenset({"PASS", "VIOLATION", "REFUSED"})

ERROR_VIOLATION = "COMPLIANCE_VIOLATION"
ERROR_UNAVAILABLE = "COMPLIANCE_UNAVAILABLE"
ERROR_UNKNOWN_PROFILE = "UNKNOWN_PROFILE"

PROFILE_SOURCE_DECISION = "WORKLOAD_DECISION"
PROFILE_SOURCE_PROFILE = "WORKLOAD_PROFILE"
PROFILE_SOURCE_SELECTION = "WORKLOAD_SELECTION"
PROFILE_SOURCE_LEGACY = "LEGACY_DECISION_REBASED"
REQUESTED_PROFILE_FIELD = "requested_compliance_profile"
FAILURE_DECISION_STALE = "DECISION_STALE"
PROFILE_SOURCE_DEFAULT = "DEFAULT_STANDARD"

COMPLIANCE_SERVICE_NAME = "mcp-compliance-server"
COMPLIANCE_URL_ENV = "COMPLIANCE_SERVER_URL"
GATE_TIMEOUT_S = 60.0
GATE_PLAN_FILE = "stackvend-compliance.tfplan"
# FD-4BD RT F1: the platform secrets deploy_workload passes as TF_VAR_* (service.PLATFORM_SECRET_TFVARS; parity
# pinned by tests/test_fd4bd_deploy_workspace.py). `tofu show -json` keeps a root variable's value even when it is
# declared sensitive, so these exact names never go into the plan copy sent to the compliance server.
PLATFORM_SECRET_VARIABLE_NAMES = ("oauth_client_secret", "firebase_api_key")
CLOUD_RUN_HOST_SUFFIX = ".run.app"

METADATA_BASE = "http://metadata.google.internal/computeMetadata/v1/"
METADATA_HEADERS = {"Metadata-Flavor": "Google"}


class ComplianceGateRefused(Exception):
    """Raised from an apply site when the gate refuses; `deploy_workload` returns `.result` (typed, status FAILED)."""

    def __init__(self, result: Dict[str, Any]):
        super().__init__(result.get("error", "compliance gate refused the apply"))
        self.result = result


def on_cloud_run() -> bool:
    return bool(os.getenv("K_SERVICE") or os.getenv("CLOUD_RUN_JOB"))


def id_token_audience(url: str) -> Optional[str]:
    """https Cloud Run origin of `url` (exact parsed-URL checks, same rule as the gateway), else None."""
    try:
        parts = urlsplit(url or "")
        port = parts.port
    except ValueError:
        return None
    host = (parts.hostname or "").lower()
    if parts.scheme != "https" or not host or parts.username is not None or parts.password is not None:
        return None
    if port not in (None, 443) or not host.endswith(CLOUD_RUN_HOST_SUFFIX):
        return None
    return f"https://{host}"


SENSITIVE_PLACEHOLDER = "(sensitive)"


def _redact(value: Any, sensitive: Any) -> Any:
    """`after` with every leaf marked in `after_sensitive` replaced by a placeholder (same structure)."""
    if sensitive is True:
        return SENSITIVE_PLACEHOLDER
    if isinstance(value, dict) and isinstance(sensitive, dict):
        return {k: _redact(v, sensitive.get(k)) for k, v in value.items()}
    if isinstance(value, list) and isinstance(sensitive, list):
        return [_redact(v, sensitive[i] if i < len(sensitive) else None) for i, v in enumerate(value)]
    return value


# The only configuration constants the gate reads: location-like attributes (and the provider's region).
GATE_CONSTANT_ATTRIBUTES = frozenset({"location", "region", "zone"})


def _strip_expressions(expressions: Any) -> Any:
    """Expressions keep their `references`; a `constant_value` survives only for a location-like attribute."""
    if isinstance(expressions, list):
        return [_strip_expressions(e) for e in expressions]
    if not isinstance(expressions, dict):
        return expressions
    out: Dict[str, Any] = {}
    for name, expr in expressions.items():
        if isinstance(expr, dict) and ("references" in expr or "constant_value" in expr):
            out[name] = {k: v for k, v in expr.items() if k != "constant_value" or name in GATE_CONSTANT_ATTRIBUTES}
        else:
            out[name] = _strip_expressions(expr)
    return out


def _strip_module(module: Any) -> Any:
    if not isinstance(module, dict):
        return module
    out = dict(module)
    out["resources"] = [dict(r, expressions=_strip_expressions(r.get("expressions") or {}))
                        for r in module.get("resources") or [] if isinstance(r, dict)]
    calls = {}
    for name, call in (module.get("module_calls") or {}).items():
        if isinstance(call, dict):
            calls[name] = dict(call, expressions=_strip_expressions(call.get("expressions") or {}),
                               module=_strip_module(call.get("module")))
    out["module_calls"] = calls
    outputs = {}
    for name, o in (module.get("outputs") or {}).items():
        if isinstance(o, dict):
            outputs[name] = dict(o, expression=_strip_expressions({"value": o.get("expression") or {}})["value"])
    out["outputs"] = outputs
    # Variable declarations keep only their sensitivity flag (defaults may hold secrets; the gate never reads them).
    out["variables"] = {name: {"sensitive": v.get("sensitive") is True}
                        for name, v in (module.get("variables") or {}).items() if isinstance(v, dict)}
    return out


def _strip_config_constants(config: Dict[str, Any]) -> Dict[str, Any]:
    out = {"root_module": _strip_module(config.get("root_module"))}
    providers = {}
    for key, conf in (config.get("provider_config") or {}).items():
        if isinstance(conf, dict):
            providers[key] = {"name": conf.get("name"),
                              "expressions": {k: v for k, v in (conf.get("expressions") or {}).items()
                                              if k in GATE_CONSTANT_ATTRIBUTES}}
    out["provider_config"] = providers
    return out


# RT F5: allowlist projection. The compliance server (mcp-servers/compliance/plan_gate.py) reads ONLY these planned
# attributes; everything else in `after` (e.g. Cloud Run env values, any non-sensitive attribute a secret could sit
# in) is dropped before the plan leaves the runner. These tables mirror plan_gate's exactly (parity test:
# tests/test_lane14_compliance_gate.py). Paths: str = attribute, int = that block element, "*" = every element.
CMEK_ATTRIBUTE_PATHS: Dict[str, Tuple[Tuple[Any, ...], ...]] = {
    "google_storage_bucket": (("encryption", 0, "default_kms_key_name"),),
    "google_artifact_registry_repository": (("kms_key_name",),),
    "google_firestore_database": (("cmek_config", 0, "kms_key_name"),),
    "google_sql_database_instance": (("encryption_key_name",),),
    "google_bigquery_dataset": (("default_encryption_configuration", 0, "kms_key_name"),),
    "google_bigquery_table": (("encryption_configuration", 0, "kms_key_name"),),
    "google_pubsub_topic": (("kms_key_name",),),
    "google_compute_disk": (("disk_encryption_key", 0, "kms_key_self_link"),),
    "google_redis_instance": (("customer_managed_key",),),
    "google_container_cluster": (("database_encryption", 0, "key_name"),),
    "google_cloud_run_v2_service": (("template", 0, "encryption_key"),),
    "google_spanner_database": (("encryption_config", 0, "kms_key_name"),),
    "google_logging_project_bucket_config": (("cmek_settings", 0, "kms_key_name"),),
    "google_secret_manager_secret": (
        ("replication", 0, "auto", 0, "customer_managed_encryption", 0, "kms_key_name"),
        ("replication", 0, "user_managed", 0, "replicas", "*", "customer_managed_encryption", 0, "kms_key_name"),
    ),
}
PROJECTED_LOCATION_ATTRIBUTES = ("location", "region", "zone")
PROJECTED_TYPE_ATTRIBUTES: Dict[str, Tuple[str, ...]] = {
    "google_project_iam_audit_config": ("service", "audit_log_config"),
    "google_cloud_run_v2_service": ("iap_enabled", "invoker_iam_disabled", "ingress"),
    "google_cloud_run_v2_service_iam_member": ("role", "member"),
    "google_cloud_run_service_iam_member": ("role", "member"),
    "google_cloud_run_v2_service_iam_binding": ("role", "members"),
    "google_cloud_run_service_iam_binding": ("role", "members"),
    "google_cloud_run_v2_service_iam_policy": ("policy_data",),
    "google_cloud_run_service_iam_policy": ("policy_data",),
    # RT14-36: the instance configuration names the Spanner instance's region (compliance plan_gate
    # TYPE_LOCATION_ATTRIBUTES, the same exact table)
    "google_spanner_instance": ("config",),
}


def _mask_for(rtype: Any) -> Dict[Any, Any]:
    """Nested keep-mask for one resource type: {step: True (keep whole) | sub-mask}."""
    mask: Dict[Any, Any] = {attr: True for attr in PROJECTED_LOCATION_ATTRIBUTES}
    for attr in PROJECTED_TYPE_ATTRIBUTES.get(rtype, ()):
        mask[attr] = True
    for path in CMEK_ATTRIBUTE_PATHS.get(rtype, ()):
        node = mask
        for i, step in enumerate(path):
            if i == len(path) - 1:
                node[step] = True
            else:
                if node.get(step) is True:
                    break
                node = node.setdefault(step, {})
    return mask


def _apply_mask(value: Any, mask: Any) -> Any:
    if mask is True:
        return value
    if isinstance(value, dict):
        return {k: _apply_mask(v, mask[k]) for k, v in value.items() if k in mask}
    if isinstance(value, list):
        out = []
        for i, item in enumerate(value):
            sub = mask.get(i, mask.get("*"))
            out.append(_apply_mask(item, sub) if sub is not None else ({} if isinstance(item, dict) else None))
        return out
    return value  # a scalar where a block was expected (e.g. `true` in after_unknown): kept as is


def project_after(rtype: Any, value: Any) -> Any:
    """`after` / `after_unknown` restricted to the attributes the compliance server reads for this type."""
    if not isinstance(value, dict):
        return value
    return _apply_mask(value, _mask_for(rtype))


def minimize_plan(plan_json: Dict[str, Any]) -> Dict[str, Any]:
    """What the gate needs, without secrets: planned `after` values with sensitive leaves redacted and projected to
    the attributes the server reads (RT F5; prior state `before` dropped), the configuration (expressions /
    references), and only non-sensitive root variable values (never PLATFORM_SECRET_VARIABLE_NAMES, FD-4BD RT F1)."""
    out: Dict[str, Any] = {"format_version": plan_json.get("format_version")}
    changes = []
    for rc in plan_json.get("resource_changes") or []:
        if not isinstance(rc, dict):
            changes.append(rc)
            continue
        change = rc.get("change") if isinstance(rc.get("change"), dict) else {}
        slim = {k: rc.get(k) for k in ("address", "module_address", "mode", "type", "name", "index") if k in rc}
        rtype = rc.get("type")
        slim["change"] = {
            "actions": change.get("actions"),
            "after": project_after(rtype, _redact(change.get("after"), change.get("after_sensitive"))),
            "after_unknown": project_after(rtype, change.get("after_unknown") or {}),
        }
        changes.append(slim)
    out["resource_changes"] = changes
    config = plan_json.get("configuration")
    if isinstance(config, dict):
        out["configuration"] = _strip_config_constants(config)
    root_vars = ((config or {}).get("root_module") or {}).get("variables") or {} if isinstance(config, dict) else {}
    variables = plan_json.get("variables") if isinstance(plan_json.get("variables"), dict) else {}
    out["variables"] = {
        name: val for name, val in variables.items()
        if name not in PLATFORM_SECRET_VARIABLE_NAMES
        and not (isinstance(root_vars.get(name), dict) and root_vars[name].get("sensitive") is True)
    }
    return out


def plan_digest(plan_json: Dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(plan_json, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _default_metadata_get(path: str) -> str:
    import requests

    res = requests.get(METADATA_BASE + path, headers=METADATA_HEADERS, timeout=5.0)
    if res.status_code != 200:
        raise RuntimeError(f"metadata {path}: HTTP {res.status_code}")
    return res.text.strip()


def _default_id_token(audience: str) -> str:
    from google.auth.transport.requests import Request
    from google.oauth2 import id_token as google_id_token

    token = google_id_token.fetch_id_token(Request(), audience)
    if not isinstance(token, str) or not token:
        raise RuntimeError("empty ID token")
    return token


def _default_http_post(url: str, body: Dict[str, Any], headers: Dict[str, str], timeout: float) -> Tuple[int, Any]:
    import requests

    res = requests.post(url, json=body, headers=headers, timeout=timeout, allow_redirects=False)
    try:
        payload = res.json()
    except ValueError:
        payload = None
    return res.status_code, payload


class ComplianceGateClient:
    """Calls `/evaluate-plan`. Transports are injectable for hermetic tests."""

    def __init__(
        self,
        *,
        http_post: Optional[Callable[..., Tuple[int, Any]]] = None,
        id_token_fetcher: Optional[Callable[[str], str]] = None,
        metadata_get: Optional[Callable[[str], str]] = None,
    ):
        self.http_post = http_post or _default_http_post
        self.id_token_fetcher = id_token_fetcher or _default_id_token
        self.metadata_get = metadata_get or _default_metadata_get
        self._resolved_url: Optional[str] = None

    def resolve_url(self) -> str:
        """`COMPLIANCE_SERVER_URL`, else `https://mcp-compliance-server-<number>.<region>.run.app` from the metadata
        server of this Cloud Run runtime. Raises RuntimeError when neither is available."""
        env_url = (os.getenv(COMPLIANCE_URL_ENV) or "").strip().rstrip("/")
        if env_url:
            return env_url
        if self._resolved_url:
            return self._resolved_url
        if not on_cloud_run():
            raise RuntimeError(f"{COMPLIANCE_URL_ENV} unset and not running on Cloud Run")
        number = self.metadata_get("project/numeric-project-id")
        region_path = self.metadata_get("instance/region")  # projects/<number>/regions/<region>
        parts = region_path.split("/")
        if not number.isdigit() or len(parts) != 4 or parts[0] != "projects" or parts[2] != "regions" or not parts[3]:
            raise RuntimeError("metadata server returned an unexpected project number / region")
        self._resolved_url = f"https://{COMPLIANCE_SERVICE_NAME}-{number}.{parts[3]}.run.app"
        return self._resolved_url

    def evaluate(self, body: Dict[str, Any]) -> Dict[str, Any]:
        """The validated gate answer. Raises RuntimeError(<failure kind>) on any problem (caller: unavailable)."""
        base = self.resolve_url()
        audience = id_token_audience(base)
        headers: Dict[str, str] = {}
        if audience is None:
            if on_cloud_run():
                raise RuntimeError(f"CONFIG: {base!r} is not an https Cloud Run URL; no token is sent to it")
        else:
            try:
                headers["Authorization"] = f"Bearer {self.id_token_fetcher(audience)}"
            except Exception as e:
                raise RuntimeError(f"AUTH: could not mint an ID token ({type(e).__name__})") from e
        try:
            status, payload = self.http_post(f"{base}/evaluate-plan", body, headers, GATE_TIMEOUT_S)
        except Exception as e:
            raise RuntimeError(f"TRANSPORT: {type(e).__name__}: {e}") from e
        if status != 200:
            raise RuntimeError(f"HTTP_STATUS: {status}")
        if not isinstance(payload, dict):
            raise RuntimeError("INVALID_JSON: answer is not a JSON object")
        if payload.get("gate_contract_version") != GATE_CONTRACT_VERSION:
            raise RuntimeError(f"CONTRACT: gate_contract_version {payload.get('gate_contract_version')!r}")
        decision = payload.get("decision")
        violations = payload.get("violations")
        if decision not in GATE_DECISIONS or not isinstance(violations, list):
            raise RuntimeError(f"CONTRACT: decision {decision!r}")
        if decision == "PASS" and violations:
            raise RuntimeError("CONTRACT: PASS with violations")
        return payload


class DecisionStale(RuntimeError):
    """The stored compliance decision was made for a different profile selection than the workload's current one."""


def load_decision(db: Any, product_id: str) -> Tuple[Dict[str, Any], str]:
    """(decision, profile_source), precedence in the module docstring. Raises RuntimeError when Firestore cannot be
    read (never treated as absent) and DecisionStale when the decision no longer matches the selection."""
    if db is None:
        raise RuntimeError("DECISION_READ: no Firestore client")
    try:
        doc = db.collection("workloads").document(product_id).get()
    except Exception as e:
        raise RuntimeError(f"DECISION_READ: {type(e).__name__}") from e
    data = (doc.to_dict() or {}) if getattr(doc, "exists", False) else {}
    if not isinstance(data, dict):
        data = {}
    # An unknown stored selection is passed through: the server refuses it (UNKNOWN_PROFILE), never STANDARD.
    raw_selection = data.get(REQUESTED_PROFILE_FIELD)
    selection = raw_selection if isinstance(raw_selection, str) and raw_selection else None
    decision = data.get("compliance_decision")
    if isinstance(decision, dict) and isinstance(decision.get("profile"), str) and decision.get("profile"):
        if "profile_source" not in decision:
            # Recorded before the explicit-profile change: the profile is not trusted (it may be a spec-keyword guess);
            # the ingress flags and allowed locations are kept (they only ever restrict). Re-audited on the next build.
            return dict(decision, profile=selection or "STANDARD"), PROFILE_SOURCE_LEGACY
        if decision.get("requested_profile") != selection:
            raise DecisionStale(
                f"{FAILURE_DECISION_STALE}: the stored compliance decision was made for profile selection "
                f"{decision.get('requested_profile')!r}, the workload's selection is now {selection!r}; run a full build "
                "to re-audit")
        return decision, PROFILE_SOURCE_DECISION
    if selection:
        return {"profile": selection}, PROFILE_SOURCE_SELECTION
    profile = data.get("compliance_profile")
    if isinstance(profile, str) and profile:
        return {"profile": profile}, PROFILE_SOURCE_PROFILE
    return {"profile": "STANDARD"}, PROFILE_SOURCE_DEFAULT


def _ingress_of(decision: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key in ("enable_direct_iap", "allow_unauthenticated", "enforce_private_ingress"):
        if isinstance(decision.get(key), bool):
            out[key] = decision[key]
    return out


def _record_evidence(db: Any, product_id: str, trace_id: str, evidence: Dict[str, Any]) -> None:
    """`workloads/{pid}/compliance_audits/{trace}.enforcement` (plan §4 item 3). Evidence only: never changes the
    gate outcome."""
    if db is None or not trace_id:
        return
    try:
        db.collection("workloads").document(product_id).collection("compliance_audits").document(trace_id).set(
            {"enforcement": evidence}, merge=True
        )
    except Exception as e:
        logger.warning(f"Could not record compliance gate evidence for {product_id}/{trace_id}: {type(e).__name__}")


def gate_plan(
    *,
    db: Any,
    product_id: str,
    trace_id: str,
    plan_json: Optional[Dict[str, Any]],
    plan_error: str = "",
    client: Optional[ComplianceGateClient] = None,
) -> Dict[str, Any]:
    """Runs the gate over an already-produced plan JSON. Returns {"passed": True, "evidence": ...} or
    {"passed": False, "result": <typed FAILED result>}. Never raises."""
    client = client or ComplianceGateClient()
    evidence: Dict[str, Any] = {"gate": "plan", "verified": False, "checked_at": time.time()}

    def _fail(error_class: str, message: str, **extra: Any) -> Dict[str, Any]:
        evidence.update({"verified": False, "error_class": error_class, "detail": message[:500], **extra})
        _record_evidence(db, product_id, trace_id, evidence)
        logger.error(f"Compliance gate refused the apply for '{product_id}' ({error_class}): {message}")
        return {
            "passed": False,
            "result": {
                "status": "FAILED",
                "error_class": error_class,
                "error": f"{error_class}: {message}",
                "product_id": product_id,
                "trace_id": trace_id,
                "compliance_gate": dict(evidence),
            },
        }

    if plan_json is None:
        return _fail(ERROR_UNAVAILABLE, f"the plan could not be read for the compliance gate ({plan_error or 'no plan'})",
                     failure="PLAN_UNREADABLE")
    try:
        decision, source = load_decision(db, product_id)
    except DecisionStale as e:
        return _fail(ERROR_UNAVAILABLE, f"{e}", failure=FAILURE_DECISION_STALE)
    except RuntimeError as e:
        return _fail(ERROR_UNAVAILABLE, f"the stored compliance decision could not be read ({e})", failure="DECISION_READ")
    profile = decision.get("profile")
    digest = plan_digest(plan_json)
    evidence.update({"profile": profile, "profile_source": source, "plan_digest": digest})
    org_locations = decision.get("allowed_locations") if isinstance(decision.get("allowed_locations"), list) else []
    body = {
        "gate_contract_version": GATE_CONTRACT_VERSION,
        "product_id": product_id,
        "trace_id": trace_id,
        "profile": profile,
        "ingress": _ingress_of(decision),
        "org_allowed_locations": [x for x in org_locations if isinstance(x, str)],
        "plan": minimize_plan(plan_json),
    }
    try:
        answer = client.evaluate(body)
    except RuntimeError as e:
        return _fail(ERROR_UNAVAILABLE, f"compliance server unavailable ({e}); the apply stops instead of assuming compliance",
                     failure=str(e).split(":", 1)[0])
    evidence.update({
        "decision": answer["decision"],
        "server_error_class": answer.get("error_class"),
        "checks_run": answer.get("checks_run") or [],
        "violations": answer.get("violations")[:50],
        "requirements": answer.get("requirements") or {},
    })
    if answer["decision"] == "PASS":
        evidence["verified"] = True
        _record_evidence(db, product_id, trace_id, evidence)
        logger.info(f"Compliance gate PASS for '{product_id}' profile={profile} ({source}) plan={digest[:12]}")
        return {"passed": True, "evidence": evidence}
    if answer["decision"] == "REFUSED":
        if answer.get("error_class") == ERROR_UNKNOWN_PROFILE:
            return _fail(ERROR_UNKNOWN_PROFILE, f"stored compliance profile {profile!r} is not a known profile")
        # RT F3: any other server refusal (PLAN_INVALID, UNRESOLVED_LOCATION_GROUP, ...) is a platform/table problem
        # an HCL edit cannot fix: COMPLIANCE_UNAVAILABLE with the server's class, never a violation.
        server_class = answer.get("error_class") if isinstance(answer.get("error_class"), str) else "REFUSED"
        return _fail(ERROR_UNAVAILABLE, f"the compliance server refused to evaluate the plan ({server_class}: "
                     f"{answer.get('detail')})", failure=server_class or "REFUSED")
    return _fail(ERROR_VIOLATION, answer.get("detail") or f"plan violates compliance profile {profile}")
