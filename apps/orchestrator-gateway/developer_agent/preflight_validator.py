"""
StackVend developer-stage pre-flight helpers: the exact Kubernetes manifest placeholder hydration (FD-4AF). (The
add-only Python package / requirements copies and the zero-Dockerfile check are deleted, FD-55 W5.) The generation-time HCL rewriters that used
to live here are deleted (FD-55 W4, see the tombstone below; the unused strip / dedupe bodies and
run_compiler_preflight_check were deleted by FD-55 W1); HCL is judged by the hallucination stack's validators.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

# FD-55 W1 (register FD55-W1): the unused bodies are DELETED with their imports: the hcl_utils dedupe / label-coercion
# imports (U10), the HCL strip / semantic-dedupe copies (X1) and the compiler pre-flight run_compiler_preflight_check
# (X7; with it the FD-4G path guard import and PREFLIGHT_UNAVAILABLE, which only it used). The production compiler
# gate is V1b (`tofu validate` on the terraform server). tests/test_fd55_w1_dead_code.py is the tombstone.

logger = logging.getLogger("castor-preflight-validator")


def parse_variables_tf_schema(hcl_content: str) -> Dict[str, Dict[str, Any]]:
    """
    Parses Terraform variable definitions from HCL content using brace-balanced inspection.
    Returns a mapping of variable_name -> {"type": str, "has_default": bool, "default": str}.
    """
    schemas: Dict[str, Dict[str, Any]] = {}
    if not hcl_content:
        return schemas

    pattern = re.compile(r'(?m)^[ \t]*variable\s+"([^"]+)"\s*\{')
    for m in pattern.finditer(hcl_content):
        var_name = m.group(1).strip()
        brace_pos = m.end() - 1
        depth = 1
        i = brace_pos + 1
        in_string = False
        escape = False
        block_body = []
        while i < len(hcl_content) and depth > 0:
            char = hcl_content[i]
            if escape:
                escape = False
            elif char == '\\' and in_string:
                escape = True
            elif char == '"':
                in_string = not in_string
            elif not in_string:
                if char == '{':
                    depth += 1
                elif char == '}':
                    depth -= 1
            if depth > 0:
                block_body.append(char)
            i += 1

        body_text = "".join(block_body)
        
        # Extract declared type
        v_type = "string"
        type_m = re.search(r'(?m)^[ \t]*type\s*=\s*(.+?)$', body_text)
        if type_m:
            v_type = type_m.group(1).strip().strip('"\'')

        # Check if default is provided
        has_default = False
        def_val = ""
        def_m = re.search(r'(?m)^[ \t]*default\s*=\s*(.+?)$', body_text)
        if def_m:
            has_default = True
            def_val = def_m.group(1).strip()

        schemas[var_name] = {
            "type": v_type,
            "has_default": has_default,
            "default": def_val,
        }

    return schemas


# FD-55 W4 (register FD55-W4, owner 10-24): the generation-time HCL rewriters are DELETED, with their only caller
# (handler._assemble_tree) and their gate:
# * HB-17 `sanitize_gcp_naming_invariants` (`= =` / leading-hyphen / `--` / `app-` rewrites, the
#   `${var.x}-...` -> `${coalesce(var.x, <guess>)}-...` rewrite, the connector name and connector-default clamps) with
#   HD-14 `generate_rfc1123_variable_default` (a type and default guessed from the variable name) and its
#   `_ACCESS_KEY_DEFAULTS` table, HB-18 `sanitize_self_referential_hcl_blocks`, the HA-17 locals call
#   (`sanitize_hcl_locals_invariants`: invented locals incl. IAM role lists) and `module_scope_locals`;
# * HB-19 `inject_cloud_run_timeouts`, HA-06 `sanitize_duplicate_gke_clusters` (removed a GKE cluster it took for a
#   duplicate: invariant 5), HB-06 `sanitize_multiservice_compute_coverage`, HA-18
#   `inject_gke_workload_identity_bindings` (a guessed `roles/datastore.user`), HC-03 (a `container_image` with a fixed
#   region), the HB-24 / HA-13 Phase 0 call (`heal_orphaned_root_resource_syntax`);
# * HD-15 `run_ast_preflight_check` / `preflight_validate_terraform` (a regex "pre-flight" whose verdict only gated the
#   sweeps above) with `self_correct_hcl` / `_self_correct_workload_hcl` / `resolve_platform_files` and the private
#   regex helpers and HCL syntax-tree copy only they used.
# Now: a literal name GCP rejects is the provider's ValidateFunc at V1b `tofu validate`; a templated name resolved from
# platform-known values is V2k IAC.NAME_INVALID (validators/names.py); self-references, undeclared locals, duplicate
# addresses and syntax errors are V1a-llm / V1b diagnostics; the AI fixes every one in the repair loop. The terraform
# MCP's own copies (service.py) are separate apply-time rows (FD-55 W6a / W6c).


# FD-55 W5 (register FD55-W5) DELETED, each a second copy of a rule that runs once elsewhere on the same tree:
# * G28 `validate_and_heal_python_requirements`: the add-only requirements contract
#   (gatekeeper_agent/requirements_contract.append_missing_requirements), run by the gatekeeper's
#   reconcile_service_requirements;
# * G26 `validate_and_heal_python_packages`: the add-only `__init__.py` pass, run by the gatekeeper's
#   purge_shadowed_package_files (same shielding rule), plus compile WARNING log lines (PY.SYNTAX / V3a report them);
# * G24 `validate_zero_dockerfiles`: the check before the third Dockerfile purge; the one rule is
#   handler.is_prohibited_container_file, applied by handler.enforce_container_contract.


class ManifestHydrationError(ValueError):
    """FD-4AF: a Kubernetes manifest cannot be hydrated without guessing. Typed by ``code``:

    * ``K8S.PLACEHOLDER_VALUE_UNAVAILABLE`` - a manifest uses an explicit placeholder whose value the platform does
      not have for this run (for example ``${PROJECT_ID}`` with no workload project ID).
    * ``K8S.PLACEHOLDER_UNRESOLVED`` - after substitution, a container ``image`` or a Workload Identity
      ``iam.gke.io/gcp-service-account`` annotation still contains ``$`` (an unknown placeholder such as ``${IMAGE}``
      or the unbraced ``$PROJECT_ID``). A container image reference never contains ``$``, so this is never a value
      that could be pulled.

    ``path`` is the manifest file; ``unavailable`` names the missing value for PLACEHOLDER_VALUE_UNAVAILABLE
    (``"project_id"`` or ``"region"``). The developer handler raises it as a typed ``StageError`` (RT F1).
    """

    def __init__(self, code: str, message: str, path: str = "", unavailable: str = ""):
        self.code = code
        self.path = path
        self.unavailable = unavailable
        super().__init__(f"{code}: {message}")


# FD-4AF: the ONLY placeholders a k8s manifest may carry. Each is an exact `${NAME}` token (braces included), substituted
# by plain string replacement; nothing else in a manifest is rewritten. `${ARTIFACT_REGISTRY}` is the workload's
# Artifact Registry Docker repository (workload-foundation `registry.tf`: location var.region, repository_id the
# product ID), so `image: ${ARTIFACT_REGISTRY}/<service>:latest` names the image the platform builds for apps/<service>.
K8S_MANIFEST_PLACEHOLDERS = ("PROJECT_ID", "PRODUCT_ID", "REGION", "SERVICE_NAME", "ARTIFACT_REGISTRY")
_K8S_CONTAINER_LIST_KEYS = ("containers", "initContainers", "ephemeralContainers")
_K8S_WI_ANNOTATION = "iam.gke.io/gcp-service-account"


def is_kubernetes_manifest_path(path: str) -> bool:
    """A `.yaml`/`.yml` file in a directory segment named exactly `k8s` (e.g. `k8s/deployment.yaml`,
    `infra/workload/k8s/sa.yaml`). An exact path segment, not a substring: `apps/k8sproxy/config.yaml` is not one."""
    parts = path.split("/")
    return path.endswith((".yaml", ".yml")) and "k8s" in parts[:-1]


def _k8s_unresolved_fields(node: Any, out: List[str]) -> None:
    """Collect every container image / Workload Identity annotation value that still contains `$` (parsed YAML)."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _K8S_CONTAINER_LIST_KEYS and isinstance(value, list):
                for c in value:
                    img = c.get("image") if isinstance(c, dict) else None
                    if isinstance(img, str) and "$" in img:
                        out.append(f"image {img!r}")
            elif key == "annotations" and isinstance(value, dict):
                sa = value.get(_K8S_WI_ANNOTATION)
                if isinstance(sa, str) and "$" in sa:
                    out.append(f"{_K8S_WI_ANNOTATION} {sa!r}")
            _k8s_unresolved_fields(value, out)
    elif isinstance(node, list):
        for item in node:
            _k8s_unresolved_fields(item, out)


def k8s_manifest_unresolved_error(path: str, text: str) -> Optional[ManifestHydrationError]:
    """FD-4AF / FD-4AF-r: the typed K8S.PLACEHOLDER_UNRESOLVED finding for one (already hydrated) manifest, or None.
    Judged on a real parse (`yaml.safe_load_all`): a container image / Workload Identity annotation value that still
    contains `$`. A manifest that does not parse (or no YAML parser) is not judged here: apply's finding, no guess."""
    try:
        import yaml
        docs = list(yaml.safe_load_all(text))
    except Exception as parse_err:  # noqa: BLE001 - an unparseable manifest is apply's finding; nothing is guessed
        logger.info(f"Kubernetes manifest {path} is not parseable YAML ({type(parse_err).__name__}); "
                    f"placeholder check skipped")
        return None
    unresolved: List[str] = []
    for doc in docs:
        _k8s_unresolved_fields(doc, unresolved)
    if not unresolved:
        return None
    return ManifestHydrationError(
        "K8S.PLACEHOLDER_UNRESOLVED",
        f"{path}: {', '.join(unresolved)} still contains '$' after substitution; the only manifest "
        f"placeholders are {', '.join('${' + n + '}' for n in K8S_MANIFEST_PLACEHOLDERS)}",
        path=path)


def hydrate_kubernetes_manifests(
    files: Dict[str, str], product_id: str = "workload", service_name: str = "", *,
    project_id: str = "", region: Any = "", defer_unresolved: bool = False,
) -> Tuple[Dict[str, str], List[str]]:
    """
    FD-4AF: substitutes the explicit placeholders of `K8S_MANIFEST_PLACEHOLDERS` in Kubernetes manifests
    (`is_kubernetes_manifest_path`) and nothing else. A manifest without a placeholder is returned byte-identical
    (Do No Harm): concrete images (`redis:7.2`, `ghcr.io/...`, Artifact Registry in any region) and Workload Identity
    annotations are never rewritten.

    * `${PROJECT_ID}` -> `project_id` (the workload's vended child project, never the product ID)
    * `${PRODUCT_ID}` -> the normalized product ID
    * `${REGION}` -> `region` (the platform region setting; a zero-argument callable is called only when a manifest
      uses `${REGION}` or `${ARTIFACT_REGISTRY}`, so a run without them never reads the settings; a callable that
      raises or returns "" is an unavailable value)
    * `${SERVICE_NAME}` -> `service_name` (default: the product ID)
    * `${ARTIFACT_REGISTRY}` -> `<region>-docker.pkg.dev/<project_id>/<product_id>`

    A placeholder whose value is unavailable, or a container image / WI annotation that still contains `$` after
    substitution, raises `ManifestHydrationError` (nothing is guessed).

    FD-4AF-r: `defer_unresolved=True` (the step-1 repair-loop path only) does not raise K8S.PLACEHOLDER_UNRESOLVED:
    the manifest keeps its unknown token (its known placeholders are still substituted) and the blocking step-1
    validator V-K8S-PH reports the same finding (`k8s_manifest_unresolved_error`) as a repairable CODE_DEFECT routed
    to the manifest's author; the stage still stops on it when the repair budget runs out.
    K8S.PLACEHOLDER_VALUE_UNAVAILABLE always raises (a missing platform value is not the author's to fix).
    """
    healed_files = dict(files)
    actions: List[str] = []

    clean_pid = re.sub(r'[^a-z0-9-]', '-', product_id.lower()).strip('-') or "workload"
    clean_svc = re.sub(r'[^a-z0-9-]', '-', (service_name or product_id).lower()).strip('-')
    project_id = (project_id or "").strip()
    resolved_region: List[str] = []

    def _region() -> str:
        if not resolved_region:
            try:
                resolved_region.append(str((region() if callable(region) else region) or "").strip())
            except Exception as region_err:  # noqa: BLE001 - RT F5: a raising resolver is an unavailable value
                logger.warning(f"Kubernetes manifest region resolver raised {type(region_err).__name__}: {region_err}")
                resolved_region.append("")
        return resolved_region[0]

    values = {
        "PROJECT_ID": lambda: project_id,
        "PRODUCT_ID": lambda: clean_pid,
        "REGION": _region,
        "SERVICE_NAME": lambda: clean_svc,
        "ARTIFACT_REGISTRY": lambda: (f"{_region()}-docker.pkg.dev/{project_id}/{clean_pid}"
                                      if project_id and _region() else ""),
    }

    for path, content in list(healed_files.items()):
        if not isinstance(content, str) or not is_kubernetes_manifest_path(path):
            continue

        text = content
        for name in K8S_MANIFEST_PLACEHOLDERS:
            token = "${" + name + "}"
            if token not in text:
                continue
            value = values[name]()
            if not value:
                missing = "project_id" if (name == "PROJECT_ID" or (name == "ARTIFACT_REGISTRY" and not project_id)) \
                    else "region"
                raise ManifestHydrationError(
                    "K8S.PLACEHOLDER_VALUE_UNAVAILABLE",
                    f"{path} uses {token} but the platform has no {missing} for it in this run",
                    path=path, unavailable=missing)
            text = text.replace(token, value)
            actions.append(f"Substituted {token} -> '{value}' in {path}")

        unresolved_err = k8s_manifest_unresolved_error(path, text)
        if unresolved_err is not None:
            if not defer_unresolved:
                raise unresolved_err
            logger.info(f"{unresolved_err} (deferred to the step-1 validator V-K8S-PH)")

        if text != content:
            healed_files[path] = text

    return healed_files, actions
