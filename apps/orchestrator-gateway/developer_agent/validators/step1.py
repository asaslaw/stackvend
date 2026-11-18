"""Step 1 validator set (integration plan §1.7 rev 3, lane 8B plan §3). Each validator reads ctx.files and returns
Diagnostics; none writes, calls an LLM or reads TEST_MODE. Decisions come from real parsers (python-hcl2, CPython
`compile`/`ast`, pyflakes, packaging, OpenTofu via the injected V1b client) and exact tables only.

| id            | code(s)                                   | default mode |
| V1a           | HCL.PARSE_ERROR (platform/vendored/prior files) | report_only |
| V1a-llm       | HCL.PARSE_ERROR (LLM-owned root files, code RT F11) | blocking |
| V1b           | TF.* (tofu validate, remote)              | blocking     |
| V2a           | POLICY.FORBIDDEN_RESOURCE_TYPE / PRIVILEGED_ROLE / PUBLIC_MEMBER / PLATFORM_OWNED_TYPE / PLATFORM_OWNED_BINDING (S2-B) / PROJECT_WIDE_GRANT (OVERBROAD-SECRET-GRANT) | blocking |
| V2e           | POLICY.ORG_CONSTRAINT (S2-B B6, exact org-policy rows; replaces HC-04) | blocking |
| V2g           | IAC.API_UNKNOWN_FOR_TYPE / IAC.API_SCAN_UNPARSEABLE (S2-C, shared/api_requirements) | report_only |
| V2i           | IAC.IAM_LITERAL_SECRET_ID (S2-B B4, replaces HC-05's secret_id rewrite) | blocking |
| V2a-sa-scoped | POLICY.PRIVILEGED_ROLE (impersonation roles on one service account, HS-59) | report_only |
| V2b           | TF.VARIABLE_WITHOUT_VALUE (S2-B B10)      | blocking     |
| V2c           | PLATFORM.ASSEMBLY_DROPPED_DECLARATION     | blocking     |
| V2d           | POLICY.PROVIDER_NOT_AVAILABLE (`provider` blocks, `required_providers` keys; resource/data blocks are V2j's, FD-4CW) | blocking |
| V2j           | POLICY.PROVISIONER_FORBIDDEN / CONNECTION_FORBIDDEN / EXTERNAL_DATA_FORBIDDEN / REMOTE_STATE_FORBIDDEN / IMPLICIT_PROVIDER_NOT_AVAILABLE / MODULE_SOURCE_NOT_LOCAL / PROVIDER_SOURCE_MISMATCH / JSON_IAC_NOT_CHECKABLE (validators/content_policy.py, FD-4AW / FD-4AW-a) | blocking |
| V2l           | POLICY.IDP_CONFIG_IN_IAC / IDP_SECRET_READER_FORBIDDEN (validators/access_idp.py, FD-4AQ W4, register AQ-4); POLICY.PUBLIC_PRINCIPAL_IN_MODULE_CALL (private workloads, FD-4CX-b) | blocking |
| V2n           | POLICY.TFVARS_NOT_ALLOWED (an AI-written variables file OpenTofu loads by itself in the root module) / TOFU_FILE_NOT_ALLOWED (an AI-written .tofu / .tofu.json file) (validators/iac_file_kinds.py, AI-TFVARS-REFUSED / AI-TOFU-REFUSED) | blocking |
| V2f           | IAC.SIBLING_URI_UNBOUND (validators/sibling.py, S2-D, HS-65) | report_only |
| V2f-not-written | IAC.SIBLING_URI_UNBOUND reason=not_written (HS-65b)      | blocking |
| V2f-cycle     | IAC.SIBLING_URI_CYCLE (mutual sibling URL reads, invariant 6; S2-D) | blocking |
| V3a-syntax    | PY.SYNTAX (one per broken top-level unit, AC-1) | blocking |
| V3a-pyflakes  | PY.UNDEFINED_NAME (non-LLM files), PY.<pyflakes message> | report_only |
| V3a-undefined | PY.UNDEFINED_NAME on LLM-owned files (S2-A, HS-15) | blocking |
| V3a-sdk-attr  | PY.ATTRIBUTE on exact SDK modules, alias bound once (S2-A, replaces HC-16, HS-14) | blocking |
| V3c           | CONTAINER.ENTRYPOINT_MISSING / PORT_NOT_BOUND / HEALTH_ROUTE_MISSING (validators/container.py, S2-A, HS-09; not for gce-bastion / gce-worker topology services) | blocking |
| V3c-planned   | CONTAINER.ENTRYPOINT_MISSING (a planned Cloud Run service with no code; FD-55 W5, replaces the HB-04 placeholder app) | blocking |
| V3c-health-unverified | CONTAINER.HEALTH_ROUTE_UNVERIFIED (no FastAPI/Flask/Starlette app, HR-1) | report_only |
| V3c-migration | CONTAINER.MIGRATION_NOT_INVOKED (HS-40, owner 10-19) | blocking |
| V3c-imports   | CONTAINER.IMPORT_OUTSIDE_SERVICE (`apps.<...>` / relative import above apps/<svc>/; FD-4AE-c) | report_only |
| V3e-local-imports | PY.LOCAL_IMPORT_UNRESOLVED (a local import whose target module binds no such name / has no such submodule; validators/local_imports.py, IMPORT-RESOLVE-GATE) | blocking |
| V3c-k8s       | CONTAINER.K8S_WORKLOAD_MISSING / K8S_MANIFEST_UNPARSEABLE (PWB-4; topology runs with a gke-autopilot service only) | blocking |
| V-K8S-PH      | K8S.PLACEHOLDER_UNRESOLVED (FD-4AF-r: unknown `$` left in a k8s manifest image / WI annotation; every run) | blocking |
| V-K8S-WI      | K8S.WORKLOAD_IDENTITY_UNBOUND (an annotated k8s service account with no roles/iam.workloadIdentityUser grant; validators/k8s_identity.py, K8S-WI-UNBOUND) | report_only |
| V4            | REQ.UNPARSEABLE                           | blocking     |
| V5            | YAML.WORKFLOW_INVALID                     | report_only  |
| V7            | PATH.UNSAFE_KEY (LLM key -> rename repair, F12), PATH.IAC_OUTSIDE_WORKLOAD_ROOT, PATH.USER_OWNED_NAME_WRITTEN_BY_LLM (FD-4AW-a F2, rename repair) | blocking |
| V8            | GATE.* (gatekeeper, check-only)           | blocking     |
| VD            | PLATFORM.VENDORED_FILE_MUTATED            | blocking     |
| V-ENV         | ENV.READ_NOT_PROVIDED / ENV.PROVIDED_SET_UNKNOWN (an env name a service's code reads that the platform does not set on it; validators/runtime_env.py, RUNTIME-ENV-CONTRACT-CHECK; topology runs) | report_only |
| V2m           | IAC.PRIVATE_DB_UNREACHABLE (a private-IP Cloud SQL / AlloyDB that no compute service can reach; validators/private_reach.py, FD-4DK) | report_only |
| V2h           | POLICY.CIDR_LITERAL / CIDR_FACT_MISMATCH / CIDR_NOT_ALLOCATED (lane 11, validators/platform_facts.py) | blocking |
| V2h-secondary | POLICY.CIDR_LITERAL_SECONDARY             | report_only  |
| V2k           | IAC.NAME_INVALID (a templated GCP name resolved from platform values only; FD-55 W4, validators/names.py) | blocking |
| V2k-literal   | IAC.NAME_INVALID (a literal name the provider does not check at validate, e.g. a VPC connector; FD55-W4-LIT) | blocking |
| V-T3          | TOPOLOGY.COMPUTE_DECLARED_BY_LLM (lane 10, topology runs only; validators/topology.py) | blocking |
| V-IAC-PUSH    | IAC.PUSH_PLAN_MISSING (a topology push edge the typed intent does not declare; intent path with a push edge only; validators/push_plan.py, PUSH-PLAN-CHECK) | blocking |
"""
from __future__ import annotations

import ast
import posixpath
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

try:
    from shared.artifact_ownership import USER_OWNED_BASENAMES, Ownership, _is_override_file
    from shared.diagnostics import Diagnostic, ErrorClass, artifact_hash
    from shared.path_safety import UnsafePathError, validate_relpath
except ImportError:  # pragma: no cover
    from ...shared.artifact_ownership import USER_OWNED_BASENAMES, Ownership, _is_override_file  # type: ignore
    from ...shared.diagnostics import Diagnostic, ErrorClass, artifact_hash  # type: ignore
    from ...shared.path_safety import UnsafePathError, validate_relpath  # type: ignore

from ..assembly import Block, WORKLOAD, file_keys, index_blocks
from . import policy_tables as T
from .base import MODES, ValidationContext, ValidatorStack, ValidatorUnavailable
from .container import (ContainerContractValidator, HealthRouteUnverifiedValidator, ImportRootValidator,
                        K8sWorkloadValidator, MigrationInvocationValidator, PlannedServiceCodeValidator)
from .local_imports import LocalImportValidator
from .python_layout import PythonLayoutValidator
from .python_units import broken_units
from .sibling import SiblingUriValidator
from .tofu_diagnostics import map_raw_diagnostic

LLM_OWNED = (Ownership.LLM_AUTHORED, Ownership.LLM_DOCUMENT)
# Exact variable names tf-applier's var-file writer always supplies (mcp-servers/terraform/service.py
# deploy_workload runtime_tfvars; tests/test_step1_s1b_validators.py pins this set to that dict's keys).
PLATFORM_SUPPLIED_VARIABLES = frozenset({
    "project_id", "region", "product_id", "github_repo_full_name", "container_image", "oauth_client_id",
    "oauth_client_secret", "firebase_api_key", "firebase_auth_domain",
})
TFVARS = "infra/workload/terraform.tfvars"


def _d(**kw: Any) -> Diagnostic:
    kw.setdefault("source", "precommit")
    kw.setdefault("severity", "error")
    return Diagnostic(**kw)


def _is_root_tf(path: str) -> bool:
    return path.startswith(WORKLOAD) and path.endswith(".tf") and "/" not in path[len(WORKLOAD):]


def _llm_root_files(ctx: ValidationContext) -> List[str]:
    return sorted(p for p in ctx.files if _is_root_tf(p) and ctx.ownership(p) in LLM_OWNED)


def _platform_addresses(ctx: ValidationContext) -> Set[Tuple[str, str]]:
    return set(ctx.extras.get("platform_addresses") or ())


def _llm_blocks(ctx: ValidationContext) -> Iterable[Tuple[str, Block]]:
    """Top-level blocks of LLM-owned root files, excluding blocks the platform synthesized inside them."""
    platform = _platform_addresses(ctx)
    for path in _llm_root_files(ctx):
        for b in index_blocks(ctx.files[path]) or []:
            if (path, b.key) not in platform:
                yield path, b


def _literal(v: Any) -> Optional[str]:
    """A string attribute value that is a literal (python-hcl2 renders expressions as "${...}")."""
    if isinstance(v, str) and "${" not in v:
        return v
    return None


# ------------------------------------------------------------------------------------------------ V1a / V1b
class HclParseValidator:
    """V1a: python-hcl2 parse of every infra/ .tf file. Two registrations (Step 1 code RT F11):

    * `V1a` (report_only): every file that is not an LLM-owned root file (platform-rendered, vendored, prior-run);
    * `V1a-llm` (blocking, `llm_root_only=True`): the LLM-owned root-module files. V2a/V2b/V2c/V2d read these files
      through python-hcl2, so a file it cannot parse would otherwise ship unchecked (e.g. an `allUsers` grant) even when
      `tofu validate` accepts it. Blocking it routes the file to its persona (CODE_DEFECT) with the parser's message.
    """
    id, tool = "V1a", "hcl2"

    def __init__(self, llm_root_only: bool = False):
        self.llm_root_only = llm_root_only
        if llm_root_only:
            self.id = "V1a-llm"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        llm_root = set(_llm_root_files(ctx))
        out = []
        for path in sorted(p for p in ctx.files if p.startswith("infra/") and p.endswith(".tf")):
            if (path in llm_root) is not self.llm_root_only:
                continue
            if file_keys(ctx.files[path]) is not None:
                continue
            line, detail = _hcl2_error(ctx.files[path])
            if self.llm_root_only:
                out.append(_d(tool="hcl2", code="HCL.PARSE_ERROR", file=path, line=line, detail=detail,
                              message="python-hcl2 could not parse this LLM-authored file, so the platform's policy "
                                      "checks cannot run on it",
                              hint=T.HINT_UNCHECKABLE, iteration=ctx.iteration))
            else:
                out.append(_d(tool="hcl2", code="HCL.PARSE_ERROR", file=path, line=line, detail=detail,
                              message="python-hcl2 could not parse this file (structure checks skipped for it)",
                              iteration=ctx.iteration))
        return out


def _hcl2_error(text: str) -> Tuple[Optional[int], Optional[str]]:
    """The parser's own error (line and text) for a file python-hcl2 rejects."""
    try:
        import hcl2
        hcl2.loads(text, with_meta=True)
    except Exception as e:  # noqa: BLE001 - the parser's exception is the finding
        line = getattr(e, "line", None)
        return (line if isinstance(line, int) and line > 0 else None), f"{type(e).__name__}: {e}"[:1500]
    return None, None


# V1B-WARMUP-RETRY (owner 10-30): the terraform server's typed `unavailable_code` values that are transient on its
# instance (mcp-servers/terraform/validate_service.py RETRYABLE_UNAVAILABLE_CODES). Only these get a readiness wait
# and another /validate call; a response without the field (an older server) is not retried.
V1B_RETRYABLE_UNAVAILABLE_CODES = frozenset({"ENGINE_NOT_READY", "CONCURRENCY_LIMIT"})
V1B_MAX_RETRIES = 1


def _v1b_retryable(resp: Any) -> bool:
    return (isinstance(resp, dict) and resp.get("status") == "UNAVAILABLE"
            and resp.get("unavailable_code") in V1B_RETRYABLE_UNAVAILABLE_CODES)


class TofuValidateValidator:
    """V1b: `tofu init -backend=false` + `validate -json` on the whole tree, run by the terraform server (/validate)
    or, in the eval harness, by the parent process. UNAVAILABLE is never a pass.

    V1B-WARMUP-RETRY: an UNAVAILABLE answer whose typed `unavailable_code` is transient (a new server instance whose
    warm-up is still filling the provider mirror, or no free validate slot) waits for /validate/ready -- the same
    bounded wait the dispatch starts with, at most `ready_wait_s` -- and asks again, at most V1B_MAX_RETRIES times.
    Still not ready, or still UNAVAILABLE -> ValidatorUnavailable as before. Decided by the code field only."""

    id, tool = "V1b", "tofu"

    def __init__(self, client: Any, iac_engine: str = "OPENTOFU", ready_wait_s: float = 0.0):
        self.client = client
        self.iac_engine = iac_engine
        self.ready_wait_s = ready_wait_s

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        if self.client is None:
            raise ValidatorUnavailable("no V1b validate client configured")
        tree = {k: v for k, v in ctx.files.items() if k.startswith("infra/")}
        resp = self.client.validate(tree, iac_engine=self.iac_engine, trace_id=ctx.trace_id)
        for _ in range(V1B_MAX_RETRIES):
            if not _v1b_retryable(resp):
                break
            from ..hallucination_runtime import wait_for_validate_ready   # local: the runtime imports no validator
            ready, probes, waited = wait_for_validate_ready(self.client, self.iac_engine, self.ready_wait_s)
            if ready.get("ready") is not True:
                raise ValidatorUnavailable(
                    f"{resp.get('reason') or 'validate unavailable'} ({resp.get('unavailable_code')}); "
                    f"/validate/ready still not ready after {probes} probe(s) in {waited:.0f}s "
                    f"(limit {self.ready_wait_s}s): {ready.get('reason')}")
            resp = self.client.validate(tree, iac_engine=self.iac_engine, trace_id=ctx.trace_id)
        status = (resp or {}).get("status")
        if status not in ("PASS", "FAIL"):
            raise ValidatorUnavailable((resp or {}).get("reason") or f"validate status {status!r}")
        out = [map_raw_diagnostic(raw, ctx.files, iteration=ctx.iteration)[0] for raw in resp.get("diagnostics") or []]
        if status == "FAIL" and not any(d.severity == "error" for d in out):
            raise ValidatorUnavailable("validate reported FAIL without an error diagnostic")
        return out


# ------------------------------------------------------------------------------------------------ V2a
class PolicyValidator:
    id, tool = "V2a", "policy"

    def __init__(self, sa_scoped: bool = False):
        self.sa_scoped = sa_scoped
        if sa_scoped:
            self.id = "V2a-sa-scoped"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        out: List[Diagnostic] = []
        for path, b in _llm_blocks(ctx):
            if b.kind != "resource" or len(b.labels) < 2:
                continue
            rtype = b.labels[0]
            body = b.body or {}
            common = dict(file=path, line=b.start, end_line=b.end, block_address=b.key, iteration=ctx.iteration)
            if self.sa_scoped:
                role = _literal(body.get("role"))
                if rtype in T.SA_SCOPED_IAM_TYPES and role in T.IMPERSONATION_ROLES:
                    out.append(_d(tool="policy", code="POLICY.PRIVILEGED_ROLE", severity="warning",
                                  message=f"{role} granted on one service account ({rtype})",
                                  hint=T.HINT_IMPERSONATION_SA_SCOPED.format(role=role), **common))
                continue
            if (rtype in T.FORBIDDEN_RESOURCE_TYPES or rtype in T.PLATFORM_IDENTITY_FORBIDDEN_TYPES
                    or rtype.endswith(T.AUTHORITATIVE_IAM_SUFFIXES)):
                out.append(_d(tool="policy", code="POLICY.FORBIDDEN_RESOURCE_TYPE",
                              message=f"resource type {rtype} may not be declared in workload IaC",
                              hint=T.HINT_FORBIDDEN, **common))
            if rtype == "google_service_account" and _literal(body.get("account_id")) in T.RESERVED_SERVICE_ACCOUNT_IDS:
                # FD-7L Phase 2b: the platform's per-workload deployer account (exact literal account_id)
                out.append(_d(tool="policy", code="POLICY.FORBIDDEN_RESOURCE_TYPE", attribute_path="account_id",
                              message=f"service account id {_literal(body.get('account_id'))} is reserved for the "
                                      "platform's deployer", hint=T.HINT_FORBIDDEN, **common))
            if rtype in T.PLATFORM_OWNED_TYPES or (
                    rtype == "google_firestore_database" and _literal(body.get("name")) == T.DEFAULT_FIRESTORE_NAME):
                out.append(_d(tool="policy", code="POLICY.PLATFORM_OWNED_TYPE",
                              message=f"{rtype} is declared by the workload foundation",
                              hint=T.HINT_PLATFORM_OWNED, **common))
            if rtype.endswith(T.IAM_TYPE_SUFFIXES):
                role = _literal(body.get("role"))
                if role in T.PRIVILEGED_ROLES or (role in T.IMPERSONATION_ROLES and rtype in T.PROJECT_LEVEL_IAM_TYPES):
                    # the compliant alternative per role class: impersonation roles narrow to one service account;
                    # PRIVILEGED_ROLES have no narrower predefined role, so the grant goes
                    hint = (T.HINT_PRIVILEGED_IMPERSONATION_PROJECT if role in T.IMPERSONATION_ROLES
                            else T.HINT_PRIVILEGED).format(role=role)
                    out.append(_d(tool="policy", code="POLICY.PRIVILEGED_ROLE", attribute_path="role",
                                  message=f"privileged role {role} granted by {rtype}", hint=hint, **common))
                elif rtype in T.PROJECT_LEVEL_IAM_TYPES and role in T.PROJECT_WIDE_DENIED_ROLES:
                    # OVERBROAD-SECRET-GRANT (owner 11-14): a project-wide secret / IAM-admin grant; the hint names the
                    # scoped alternative (the one secret), exact table membership
                    out.append(_d(tool="policy", code=T.PROJECT_WIDE_GRANT_POLICY_CODE, attribute_path="role",
                                  message=f"{role} granted on the whole project by {rtype}",
                                  hint=T.project_wide_grant_hint(role), **common))
                if (rtype, role) in T.PLATFORM_OWNED_BINDINGS:
                    out.append(_d(tool="policy", code="POLICY.PLATFORM_OWNED_BINDING", attribute_path="role",
                                  message=f"{role} is a Google-managed service-agent grant ({rtype})",
                                  hint=T.HINT_PLATFORM_OWNED_BINDING, **common))
                members: List[Any] = []
                if "member" in body:
                    members.append(body.get("member"))
                if isinstance(body.get("members"), list):
                    members.extend(body.get("members"))
                if any(_literal(m) in T.PUBLIC_MEMBERS for m in members):
                    out.append(_d(tool="policy", code="POLICY.PUBLIC_MEMBER", attribute_path="member",
                                  message=f"{rtype} grants access to allUsers/allAuthenticatedUsers",
                                  hint=T.HINT_PUBLIC, **common))
        return out


# ------------------------------------------------------------------------------------------------ V2b
class VariableWithoutValueValidator:
    id, tool = "V2b", "policy"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        tfvars_keys: Set[str] = set()
        if TFVARS in ctx.files:
            try:
                import hcl2
                tfvars_keys = set(hcl2.loads(ctx.files[TFVARS]).keys())
            except Exception:  # noqa: BLE001 - unparseable tfvars: no keys known (more findings, never fewer)
                tfvars_keys = set()
        out = []
        for path, b in _llm_blocks(ctx):
            if b.kind != "variable" or not b.labels:
                continue
            name = b.labels[0]
            if "default" in (b.body or {}) or name in tfvars_keys or name in PLATFORM_SUPPLIED_VARIABLES:
                continue
            out.append(_d(tool="policy", code="TF.VARIABLE_WITHOUT_VALUE", file=path, line=b.start,
                          block_address=b.key, iteration=ctx.iteration,
                          message=f'variable "{name}" has no default and no value is supplied by the platform',
                          hint="Give the variable a default, or use a literal/local value."))
        return out


# ------------------------------------------------------------------------------------------------ V2e
def org_constraint_findings(blocks: Iterable[Block]) -> List[Tuple[Block, str, str]]:
    """(block, constraint, attribute path) for every exact org-constraint violation among resource blocks (RT F9).
    Pure function over python-hcl2 bodies, shared by V2e and the golden-module corpus test."""
    out: List[Tuple[Block, str, str]] = []
    for b in blocks:
        if b.kind != "resource" or len(b.labels) < 2:
            continue
        rtype, body = b.labels[0], (b.body or {})
        if rtype in T.VM_EXTERNAL_IP_RESOURCE_TYPES:
            for nic in body.get("network_interface") or []:
                if isinstance(nic, dict) and isinstance(nic.get("access_config"), list) and nic["access_config"]:
                    out.append((b, T.ORG_CONSTRAINT_VM_EXTERNAL_IP, "network_interface.access_config"))
                    break
        if rtype == "google_compute_instance":
            meta = body.get("metadata")
            if isinstance(meta, dict) and T.OS_LOGIN_METADATA_KEY in meta and any(
                    meta[T.OS_LOGIN_METADATA_KEY] is v or (isinstance(v, str) and meta[T.OS_LOGIN_METADATA_KEY] == v)
                    for v in T.OS_LOGIN_DISABLED_VALUES):
                out.append((b, T.ORG_CONSTRAINT_OS_LOGIN, f"metadata.{T.OS_LOGIN_METADATA_KEY}"))
        elif rtype == "google_storage_bucket":
            v = body.get("uniform_bucket_level_access", None)
            if not any(v is t or (isinstance(t, str) and v == t) for t in T.UBLA_TRUE_VALUES):
                out.append((b, T.ORG_CONSTRAINT_BUCKET_UBLA, "uniform_bucket_level_access"))
    return out


class OrgConstraintValidator:
    """V2e (S2-B B6, register HS-62): exact org-constraint checks on the LLM's root-module resources."""

    id, tool = "V2e", "policy"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        out: List[Diagnostic] = []
        by_path: Dict[str, List[Block]] = {}
        for path, b in _llm_blocks(ctx):
            by_path.setdefault(path, []).append(b)
        for path, blocks in sorted(by_path.items()):
            for b, constraint, attr in org_constraint_findings(blocks):
                out.append(_d(tool="policy", code="POLICY.ORG_CONSTRAINT", file=path, line=b.start, end_line=b.end,
                              block_address=b.key, attribute_path=attr, detail=constraint, iteration=ctx.iteration,
                              message=f"{b.key} violates platform policy (compliance contract) {constraint}",
                              hint=T.HINT_ORG_CONSTRAINT[constraint]))
        return out


# ------------------------------------------------------------------------------------------------ V2g
class ApiCoverageValidator:
    """V2g (S2-C, register HS-63; report-only): the exact API table (shared/api_requirements) has no row for a type
    or module source the root module declares (IAC.API_UNKNOWN_FOR_TYPE), or could not parse a root file to read
    its types (IAC.API_SCAN_UNPARSEABLE). Measured per run; the table grows by PR. Never guesses an API."""

    id, tool = "V2g", "policy"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        try:
            from shared.api_requirements import required_apis
        except ImportError:  # pragma: no cover
            from ...shared.api_requirements import required_apis  # type: ignore
        root = {p: t for p, t in ctx.files.items()
                if p.startswith(WORKLOAD) and "/" not in p[len(WORKLOAD):] and p.endswith((".tf", ".tf.json"))}
        req = required_apis(root)
        out: List[Diagnostic] = []
        for path, key in req.unknown:
            out.append(_d(tool="policy", code="IAC.API_UNKNOWN_FOR_TYPE", severity="warning", file=path,
                          detail=key, iteration=ctx.iteration, hint=T.HINT_API_UNKNOWN_FOR_TYPE,
                          message=f"no API row for {key}: its API is not enabled automatically"))
        for path in req.unparseable_files:
            out.append(_d(tool="policy", code="IAC.API_SCAN_UNPARSEABLE", severity="warning", file=path,
                          iteration=ctx.iteration,
                          message="this root file could not be parsed, so the APIs its types need were not read"))
        return out


# ------------------------------------------------------------------------------------------------ V2i
class IamLiteralSecretIdValidator:
    """V2i (S2-B B4, HS-19b; replaces HC-05's unconditional secret_id rewrite): an LLM-written
    google_secret_manager_secret_iam_member whose `secret_id` is a literal string EXACTLY equal to the literal
    `secret_id` of a google_secret_manager_secret declared in the root module. OpenTofu sees no dependency between the
    two, so the grant can be created before the secret (apply-time 404). Exact literal equality only: a secret named
    by its label, a full resource path or any expression is not judged. A grant whose `depends_on` lists exactly that
    secret (bcd RT F2) is ordered by OpenTofu and is not judged."""

    id, tool = "V2i", "policy"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        declared: Dict[str, str] = {}
        for path in sorted(p for p in ctx.files if _is_root_tf(p)):
            for b in index_blocks(ctx.files[path]) or []:
                if b.kind == "resource" and len(b.labels) == 2 and b.labels[0] == "google_secret_manager_secret":
                    sid = _literal((b.body or {}).get("secret_id"))
                    if sid:
                        declared.setdefault(sid, b.labels[1])
        out: List[Diagnostic] = []
        for path, b in _llm_blocks(ctx):
            if b.kind != "resource" or len(b.labels) < 2 or b.labels[0] != "google_secret_manager_secret_iam_member":
                continue
            sid = _literal((b.body or {}).get("secret_id"))
            if sid is None or sid not in declared:
                continue
            # bcd RT F2: an explicit depends_on on that secret already orders the grant after it (exact list
            # membership of the python-hcl2 rendering of the address or its .id / .secret_id attribute).
            addr = f"google_secret_manager_secret.{declared[sid]}"
            deps = (b.body or {}).get("depends_on")
            if isinstance(deps, list) and any(d in (f"${{{addr}}}", f"${{{addr}.id}}", f"${{{addr}.secret_id}}")
                                              for d in deps if isinstance(d, str)):
                continue
            out.append(_d(tool="policy", code="IAC.IAM_LITERAL_SECRET_ID", file=path, line=b.start, end_line=b.end,
                          block_address=b.key, attribute_path="secret_id", iteration=ctx.iteration,
                          message=f'secret_id "{sid}" repeats the literal id of google_secret_manager_secret.'
                                  f'{declared[sid]} instead of referencing it',
                          hint=T.HINT_IAM_LITERAL_SECRET_ID.format(name=declared[sid])))
        return out


# ------------------------------------------------------------------------------------------------ V2c
class AssemblyPreservationValidator:
    """addresses(draft root IaC) - addresses(assembled root module) - keys(AssemblyRecord.replaced) must be empty.
    Runs on the FINAL root module (ctx.extras['assembled_root']: after every platform healer, Step 1 code RT F1), so
    an unrecorded removal by any healer, not only by the assembly, is reported."""

    id, tool = "V2c", "platform"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        assembled = ctx.extras.get("assembled_root")
        if assembled is None or ctx.assembly is None:
            return []
        draft_keys: Dict[str, str] = {}
        for path, text in ctx.draft.items():
            if _is_root_tf(path):
                for k in file_keys(text) or set():
                    draft_keys.setdefault(k, path)
        tree_keys: Set[str] = set()
        unparsed = False
        for path, text in assembled.items():
            if _is_root_tf(path):
                got = file_keys(text)
                if got is None:
                    unparsed = True
                else:
                    tree_keys |= got
        if unparsed:
            return []  # a file python-hcl2 cannot parse hides its keys; V1b reports the syntax error itself
        replaced = set(ctx.assembly.replaced)
        out = []
        for key in sorted(set(draft_keys) - tree_keys - replaced):
            out.append(_d(tool="platform", code="PLATFORM.ASSEMBLY_DROPPED_DECLARATION",
                          error_class=ErrorClass.PLATFORM_DEFECT, file=draft_keys[key], block_address=key,
                          iteration=ctx.iteration,
                          message=f"{key} was declared by the LLM but the platform assembly dropped it without a "
                                  "recorded replacement"))
        return out


# ------------------------------------------------------------------------------------------------ V2d
# Exact python-hcl2 renderings of HCL keywords inside an expression: `provider = null.x` parses as "${None.x}"
# (FD-4AW). Provider local names are lower case, so no real provider name collides with a rendering.
HCL2_KEYWORD_RENDERING = {"None": "null", "True": "true", "False": "false"}
# Block kinds whose provider V2j (content_policy.py, POLICY.IMPLICIT_PROVIDER_NOT_AVAILABLE) reports once per block;
# V2d leaves them to V2j so a repair gets one diagnostic per block (FD-4CW Q1, owner row FD-4CW-Q2).
PER_BLOCK_PROVIDER_KINDS = frozenset({"resource", "data"})


def block_provider(kind: str, labels: Tuple[str, ...], body: Mapping) -> Optional[str]:
    """Provider local name of a `resource`/`data` block (Terraform's rule: the `provider` meta-argument's local name,
    `x` or `x.alias` -> `x`, else the type label's prefix before the first '_', the whole label when it has none);
    None for any other block kind."""
    if kind not in PER_BLOCK_PROVIDER_KINDS or not labels:
        return None
    meta = body.get("provider") if isinstance(body, Mapping) else None
    if isinstance(meta, str) and meta:
        ref = meta[2:-1] if meta.startswith("${") and meta.endswith("}") else meta
        name = ref.split(".", 1)[0]
        return HCL2_KEYWORD_RENDERING.get(name, name)
    return labels[0].split("_", 1)[0]


def provider_local_names(blocks: Iterable[Block]) -> Dict[str, Tuple[int, str]]:
    """Provider local names a set of blocks requires (Terraform's rule: the resource/data type prefix before the first
    '_', or the `provider` meta-argument, see block_provider; plus provider blocks and required_providers keys)."""
    out: Dict[str, Tuple[int, str]] = {}
    for b in blocks:
        name = block_provider(b.kind, b.labels, b.body or {})
        if name is not None:
            out.setdefault(name, (b.start, b.key))
        elif b.kind == "provider" and b.labels:
            out.setdefault(b.labels[0], (b.start, b.key))
        elif b.kind == "terraform":
            for rp in (b.body or {}).get("required_providers") or []:
                if isinstance(rp, dict):
                    for local in rp:
                        if not local.startswith("__"):
                            out.setdefault(local, (b.start, b.key))
    return out


class ProviderAvailabilityValidator:
    """V2d: `provider` blocks and `required_providers` keys of LLM-owned root files must name a provider the validate
    service offers, or OpenTofu's built-in `terraform` provider (FD-4CW Q2: it is built in, so it is accepted here but
    is not an installable provider of the validate service). `resource`/`data` blocks are V2j's, which reports each
    one (PER_BLOCK_PROVIDER_KINDS, FD-4CW Q1); build_step1_stack keeps V2j at least as strict as V2d."""
    id, tool = "V2d", "policy"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        available = ctx.extras.get("available_providers")
        if available is None:
            raise ValidatorUnavailable("the validate service did not report its provider set")
        allowed = set(available) | T.BUILTIN_PROVIDERS
        out = []
        by_file: Dict[str, List[Block]] = {}
        for path, b in _llm_blocks(ctx):
            if b.kind in PER_BLOCK_PROVIDER_KINDS:
                continue
            by_file.setdefault(path, []).append(b)
        for path, blocks in sorted(by_file.items()):
            for name, (line, key) in sorted(provider_local_names(blocks).items()):
                if name in allowed:
                    continue
                out.append(_d(tool="policy", code="POLICY.PROVIDER_NOT_AVAILABLE", file=path, line=line,
                              block_address=key, iteration=ctx.iteration,
                              message=f'provider "{name}" is not available to the platform',
                              hint=T.HINT_PROVIDER.format(providers=", ".join(sorted(set(available))))))
        return out


# ------------------------------------------------------------------------------------------------ V3a / V4 / V5
def _syntax_diagnostic(path: str, e: SyntaxError, iteration: int, symbol: Optional[str] = None) -> Diagnostic:
    return _d(tool="ast", code="PY.SYNTAX", file=path, line=e.lineno, column=e.offset,
              message=f"{type(e).__name__}: {e.msg}", snippet=(e.text or "").rstrip("\n") or None, symbol=symbol,
              iteration=iteration)


class PythonSyntaxValidator:
    """V3a-syntax. A file that compiles yields nothing (it never reaches the unit split). A file that does not yields
    one PY.SYNTAX per broken top-level def/class/statement (AC-1, validators/python_units.py; `symbol` = the unit),
    else today's single whole-file finding (`symbol` None). Read-only: nothing is rewritten."""

    id, tool = "V3a-syntax", "ast"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        out = []
        for path in sorted(p for p in ctx.files if p.endswith(".py")):
            try:
                compile(ctx.files[path], path, "exec", dont_inherit=True)
            except SyntaxError as e:
                try:
                    units = broken_units(ctx.files[path], path, e)
                except Exception:  # noqa: BLE001 - the split is a refinement: never lose or block the finding
                    units = None
                if not units:
                    out.append(_syntax_diagnostic(path, e, ctx.iteration))
                else:
                    out.extend(_syntax_diagnostic(path, err, ctx.iteration, u.symbol) for u, err in units)
            except ValueError as e:  # null bytes
                out.append(_d(tool="ast", code="PY.SYNTAX", file=path, message=f"ValueError: {e}",
                              iteration=ctx.iteration))
        return out


UNDEFINED_NAME_MESSAGES = frozenset({"UndefinedName", "UndefinedLocal", "UndefinedExport"})


class PyflakesValidator:
    """V3a-pyflakes (report_only). One pyflakes pass per validated tree (code RT F6): the findings are cached by
    (artifact_hash, iteration) and shared with V3a-undefined, which owns the LLM-owned `PY.UNDEFINED_NAME` findings,
    so this report-only view omits them (each finding is emitted once per report)."""

    id, tool = "V3a-pyflakes", "pyflakes"
    _CACHE_MAX = 4

    def __init__(self) -> None:
        self._cache: Dict[Tuple[str, int], List[Diagnostic]] = {}

    def findings(self, ctx: ValidationContext) -> List[Diagnostic]:
        """Every pyflakes finding of every `.py` file of the tree (one pass, cached per tree)."""
        try:
            from pyflakes import checker
        except ImportError as e:
            raise ValidatorUnavailable(f"pyflakes not installed: {e}")
        key = (artifact_hash(ctx.files), ctx.iteration)
        hit = self._cache.get(key)
        if hit is not None:
            return list(hit)
        out = []
        for path in sorted(p for p in ctx.files if p.endswith(".py")):
            try:
                tree = ast.parse(ctx.files[path], filename=path)
            except (SyntaxError, ValueError):
                continue  # PY.SYNTAX reports it
            for m in checker.Checker(tree, filename=path).messages:
                cls = type(m).__name__
                if cls in UNDEFINED_NAME_MESSAGES:
                    code, sev, symbol = "PY.UNDEFINED_NAME", "error", (m.message_args or [None])[0]
                else:
                    code, sev, symbol = "PY." + _camel_to_upper(cls), "warning", None
                out.append(_d(tool="pyflakes", code=code, severity=sev, file=path, line=m.lineno,
                              column=getattr(m, "col", None), symbol=str(symbol) if symbol else None,
                              message=m.message % m.message_args, iteration=ctx.iteration))
        while len(self._cache) >= self._CACHE_MAX:
            self._cache.pop(next(iter(self._cache)))
        self._cache[key] = out
        return list(out)

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        return [d for d in self.findings(ctx) if not _blocking_undefined(d, ctx)]


def _blocking_undefined(d: Diagnostic, ctx: ValidationContext) -> bool:
    return d.code == "PY.UNDEFINED_NAME" and ctx.ownership(d.file) in LLM_OWNED


class UndefinedNameValidator:
    """V3a-undefined (blocking, S2-A A5 / register HS-15): pyflakes `UndefinedName`/`UndefinedLocal`/`UndefinedExport`
    on LLM-owned `.py` files. Flipped after the written FP review of the R2c/G0 corpus (0 false positives: no file uses
    `from __future__ import annotations`, so every flagged annotation is evaluated at import time). The same finding
    on a platform-rendered or vendored copy stays measured in the report-only V3a-pyflakes (its LLM original blocks
    and is repaired; the copy follows on re-assembly). Star-import files: pyflakes reports ImportStarUsage instead, so
    they are excluded by pyflakes semantics. Shares V3a-pyflakes' single pass when given it (build_step1_stack)."""

    id, tool = "V3a-undefined", "pyflakes"

    def __init__(self, pyflakes: Optional[PyflakesValidator] = None) -> None:
        self._pyflakes = pyflakes or PyflakesValidator()

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        return [d for d in self._pyflakes.findings(ctx) if _blocking_undefined(d, ctx)]


# Exact SDK modules whose public attribute set the gateway can read from its own installed copy (google-api-core is a
# gateway dependency). Only these are checked; nothing is imported because the LLM named it.
SDK_ATTRIBUTE_MODULES = ("google.api_core.exceptions", "google.api_core.retry")


def _module_level_imports(body: List[ast.stmt]) -> Iterable[ast.stmt]:
    """Import statements at module level, including the bodies of module-level if/try/with blocks (never inside a
    function or class)."""
    for node in body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            yield node
        elif isinstance(node, (ast.If, ast.Try, ast.With)) or type(node).__name__ == "TryStar":
            for field_name in ("body", "orelse", "finalbody"):
                yield from _module_level_imports(getattr(node, field_name, None) or [])
            for h in getattr(node, "handlers", None) or []:
                yield from _module_level_imports(h.body)


def name_binding_counts(tree: ast.AST) -> Tuple[Dict[str, int], bool]:
    """How many times each name is bound anywhere in the module (any scope), and whether a star import makes the set
    open. Bindings: assignment/for/with/walrus/comprehension targets and `del` (ast.Name Store/Del), function
    parameters, def/class names, import aliases, `global`/`nonlocal` declarations, except-as names, match captures
    and PEP 695 type parameters."""
    counts: Dict[str, int] = {}
    star = False

    def bind(name: Optional[str]) -> None:
        if name:
            counts[name] = counts.get(name, 0) + 1

    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and not isinstance(node.ctx, ast.Load):
            bind(node.id)
        elif isinstance(node, ast.arg):
            bind(node.arg)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bind(node.name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                if a.name == "*":
                    star = True
                else:
                    bind(a.asname or a.name.split(".")[0])
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            for n in node.names:
                bind(n)
        elif isinstance(node, ast.ExceptHandler):
            bind(node.name)
        elif type(node).__name__ in ("MatchAs", "MatchStar"):
            bind(getattr(node, "name", None))
        elif type(node).__name__ == "MatchMapping":
            bind(getattr(node, "rest", None))
        elif type(node).__name__ in ("TypeVar", "ParamSpec", "TypeVarTuple"):   # PEP 695; `type X = ...` is a Name
            bind(getattr(node, "name", None))
    return counts, star


class SdkAttributeValidator:
    """V3a-sdk-attr (blocking, S2-A A4 / register HS-14): `<alias>.<attr>` (read) where <alias> is bound by a
    module-level `import google.api_core.exceptions as X` / `from google.api_core import exceptions [as X]` (exact
    module names in SDK_ATTRIBUTE_MODULES) and <attr> is not an attribute of that module -> PY.ATTRIBUTE (e.g. the
    hallucinated `exceptions.is_transient_error`; the real predicate is `google.api_core.retry.if_transient_error`).
    Replaces HC-16, which renamed it by regex.

    Binding scope (code RT F1): an alias is judged only when that name is bound exactly once in the whole file and
    that one binding is the module-level SDK import. A parameter, local, comprehension variable, later import,
    `global`, fallback import or any other re-binding of the name -> the alias is not judged (never guessed); a star
    import anywhere -> the file is not judged. Only LLM-owned files are judged (a platform-vendored copy follows its
    original). The detail names the gateway's installed google-api-core version, whose `dir()` is the reference."""

    id, tool = "V3a-sdk-attr", "ast"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        import importlib
        attrs: Dict[str, Set[str]] = {}
        for mod in SDK_ATTRIBUTE_MODULES:
            try:
                attrs[mod] = set(dir(importlib.import_module(mod)))
            except Exception as e:  # noqa: BLE001
                raise ValidatorUnavailable(f"{mod} not importable: {e}")
        try:
            import google.api_core as _api_core
            version = str(getattr(_api_core, "__version__", "unknown"))
        except Exception:  # noqa: BLE001 - imported above; the version is informational
            version = "unknown"
        out: List[Diagnostic] = []
        for path in sorted(p for p in ctx.files if p.endswith(".py") and ctx.ownership(p) in LLM_OWNED):
            try:
                tree = ast.parse(ctx.files[path], filename=path)
            except (SyntaxError, ValueError):
                continue
            alias: Dict[str, str] = {}
            for node in _module_level_imports(tree.body):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        if a.name in attrs and a.asname:
                            alias[a.asname] = a.name
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    for a in node.names:
                        full = f"{node.module}.{a.name}"
                        if full in attrs:
                            alias[a.asname or a.name] = full
            if not alias:
                continue
            counts, star = name_binding_counts(tree)
            if star:
                continue
            alias = {k: v for k, v in alias.items() if counts.get(k) == 1}
            seen: Set[Tuple[int, str]] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load) \
                        and isinstance(node.value, ast.Name) and node.value.id in alias:
                    mod = alias[node.value.id]
                    if node.attr not in attrs[mod] and (node.lineno, node.attr) not in seen:
                        seen.add((node.lineno, node.attr))
                        out.append(_d(tool="ast", code="PY.ATTRIBUTE", file=path, line=node.lineno,
                                      column=node.col_offset, symbol=f"{mod}.{node.attr}", iteration=ctx.iteration,
                                      message=f"module {mod!r} has no attribute {node.attr!r}",
                                      detail=f"reference: dir({mod}) of google-api-core {version}"))
        return out


def _camel_to_upper(name: str) -> str:
    out = ""
    for i, ch in enumerate(name):
        if ch.isupper() and i and not name[i - 1].isupper():
            out += "_"
        out += ch.upper()
    return out


class RequirementsValidator:
    """V4: every requirement line parses with packaging (pip option lines `-r`, `--index-url`, `-e` are pip syntax and
    skipped; a `#` at line start or after whitespace starts a comment, as in pip)."""

    id, tool = "V4", "pip"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        try:
            from packaging.requirements import InvalidRequirement, Requirement
        except ImportError as e:
            raise ValidatorUnavailable(f"packaging not installed: {e}")
        out = []
        for path in sorted(p for p in ctx.files if posixpath.basename(p) == "requirements.txt"):
            for n, line in enumerate(ctx.files[path].split("\n"), start=1):
                text = line
                for i, ch in enumerate(line):
                    if ch == "#" and (i == 0 or line[i - 1] in " \t"):
                        text = line[:i]
                        break
                text = text.strip()
                if not text or text.startswith("-"):
                    continue
                try:
                    Requirement(text)
                except InvalidRequirement as e:
                    out.append(_d(tool="pip", code="REQ.UNPARSEABLE", file=path, line=n,
                                  message=f"invalid requirement {text!r}: {str(e)[:300]}", iteration=ctx.iteration))
        return out


class WorkflowYamlValidator:
    id, tool = "V5", "yaml"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        try:
            from shared.workflow_validator import WorkflowValidationError, validate_github_workflow_yaml
        except ImportError as e:
            raise ValidatorUnavailable(f"workflow validator not importable: {e}")
        out = []
        for path in sorted(p for p in ctx.files if p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))):
            try:
                validate_github_workflow_yaml(ctx.files[path])
            except WorkflowValidationError as e:
                out.append(_d(tool="yaml", code="YAML.WORKFLOW_INVALID", file=path, message=str(e)[:1500],
                              iteration=ctx.iteration))
            except Exception as e:  # noqa: BLE001 - any other validator failure is a finding, never a pass
                out.append(_d(tool="yaml", code="YAML.WORKFLOW_INVALID", file=path,
                              message=f"{type(e).__name__}: {str(e)[:1500]}", iteration=ctx.iteration))
        return out


# ------------------------------------------------------------------------------------------------ V7 / V8 / VD
class PathValidator:
    id, tool = "V7", "path"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        out = []
        for path in sorted(ctx.files):
            try:
                validate_relpath(path, reserved=frozenset({".git"}))
            except UnsafePathError as e:
                # Step 1 code RT F12: a key the LLM wrote is named exactly (the router sends it back to its persona
                # for a rename); any other unsafe key stays "<unsafe>" (unattributable -> PLATFORM_DEFECT).
                llm_key = isinstance(path, str) and path in ctx.draft
                out.append(_d(tool="path", code="PATH.UNSAFE_KEY", file=path if llm_key else "<unsafe>",
                              iteration=ctx.iteration, message=f"unsafe file key {path!r}: {e.reason}",
                              hint=T.HINT_UNSAFE_KEY if llm_key else None))
        for path in sorted(ctx.draft):
            if not path.endswith((".tf", ".tf.json")) or path.startswith(WORKLOAD) and "/" not in path[len(WORKLOAD):]:
                continue
            if path not in ctx.files:
                continue
            out.append(_d(tool="path", code="PATH.IAC_OUTSIDE_WORKLOAD_ROOT", file=path, iteration=ctx.iteration,
                          message="workload Terraform must live directly under infra/workload/ (it is not applied "
                                  "from here)",
                          hint=f"Move it to {WORKLOAD}{posixpath.basename(path)}"))
        # FD-4AW-a F2: human.tf / human_override.tf / Terraform override files are USER_OWNED by name, so no LLM-root
        # validator reads them; an LLM draft at such a name is refused (exact existing ownership rules) and renamed.
        for path in sorted(ctx.draft):
            if posixpath.basename(path) in USER_OWNED_BASENAMES or _is_override_file(path):
                out.append(_d(tool="path", code="PATH.USER_OWNED_NAME_WRITTEN_BY_LLM", file=path,
                              iteration=ctx.iteration,
                              message=f"{path} is a file name reserved for the human architect",
                              hint=T.HINT_USER_OWNED_NAME))
        return out


class GatekeeperCheckValidator:
    id, tool = "V8", "gatekeeper"

    def __init__(self, verifier_factory: Any):
        self.verifier_factory = verifier_factory

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        if self.verifier_factory is None:
            raise ValidatorUnavailable("gatekeeper verifier not importable")
        verifier = self.verifier_factory()
        return list(verifier.verify(dict(ctx.files), source="precommit", iteration=ctx.iteration))


class VendoredDriftValidator:
    """A file the platform vendored this run must be byte-identical to what was vendored (I-4): drift can only be a
    platform bug, so it fails loudly (PLATFORM_DEFECT) instead of being silently restored."""

    id, tool = "VD", "platform"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        snapshot: Mapping[str, str] = ctx.extras.get("platform_files") or {}
        # the tree as the assembly left it, before Part A's restore (that restore used to hide the drift, I-4)
        observed: Mapping[str, Any] = ctx.extras.get("vendored_before_restore") or ctx.files
        out = []
        for path in sorted(snapshot):
            current = observed.get(path)
            if current != snapshot[path]:
                out.append(_d(tool="platform", code="PLATFORM.VENDORED_FILE_MUTATED",
                              error_class=ErrorClass.PLATFORM_DEFECT, file=path, iteration=ctx.iteration,
                              message="a vendored platform module file changed after vendoring"
                                      + (" (removed)" if current is None else "")))
        return out


class K8sPlaceholderValidator:
    """V-K8S-PH (FD-4AF-r, blocking, always registered): a Kubernetes manifest (`is_kubernetes_manifest_path`) of the
    assembled tree whose container image / Workload Identity annotation still contains `$` after hydration is
    K8S.PLACEHOLDER_UNRESOLVED (the same typed finding and parser as hydration, `k8s_manifest_unresolved_error`).
    A CODE_DEFECT on the manifest itself: the Router gives it to the manifest's author (a platform / user-owned file
    is PLATFORM_DEFECT / BROWNFIELD_CONFLICT there, a stop), so the repair budget can fix it; when the budget runs out
    the stage stops with it (RepairBudgetExhausted). A valid manifest yields nothing. Never writes."""

    id, tool = "V-K8S-PH", "yaml"

    def validate(self, ctx: ValidationContext) -> List[Diagnostic]:
        try:
            from ..preflight_validator import is_kubernetes_manifest_path, k8s_manifest_unresolved_error
        except ImportError:  # pragma: no cover
            from developer_agent.preflight_validator import (  # type: ignore
                is_kubernetes_manifest_path, k8s_manifest_unresolved_error)
        try:   # RT F2: no YAML parser -> UNAVAILABLE (never a silent PASS of a deferred manifest)
            import yaml  # noqa: F401
        except ImportError as e:
            raise ValidatorUnavailable("yaml") from e
        out: List[Diagnostic] = []
        for path in sorted(ctx.files):
            text = ctx.files[path]
            if not isinstance(text, str) or not is_kubernetes_manifest_path(path):
                continue
            err = k8s_manifest_unresolved_error(path, text)
            if err is not None:
                out.append(_d(tool="yaml", code=err.code, error_class=ErrorClass.CODE_DEFECT, file=path,
                              iteration=ctx.iteration, message=str(err)))
        return out


def build_step1_stack(*, validate_client: Any, verifier_factory: Any, modes: Optional[Mapping[str, str]] = None,
                      classify: Any = None, iac_engine: str = "OPENTOFU", network_facts: Any = None,
                      existing_network: bool = False, topology: Any = None, iac_intent: Any = None,
                      platform_values: Optional[Mapping[str, str]] = None,
                      access: Any = None, planned_services: Iterable[str] = (),
                      validate_ready_wait_s: float = 0.0, plan_targets: Iterable[Any] = (),
                      manifest_paths: Optional[Mapping[str, Any]] = None) -> ValidatorStack:
    """`network_facts` (developer_agent.platform_facts.NetworkFacts or None) feeds V2h, the lane 11 CIDR rule.
    `topology` (lane 10: shared.service_topology.ValidatedTopology or None) enables V-T3 (compute declared by the
    LLM); None registers nothing new. With a topology, S2-D's V2f / V2f-not-written / V2f-cycle are not registered,
    and V3c / V3c-health-unverified / V3c-migration skip services whose typed kind is a VM kind
    (container.NON_CONTAINER_KINDS: gce-bastion, gce-worker; S3-bastion 10-19). `iac_intent` (TI-3: the dispatch's
    iac_intent_contract.IntentRun, intent mode only) adds V-IAC / V-IAC-PATH / V-IAC-RENDER; None adds nothing.
    `platform_values` (FD-55 W4): the exact values the deploy supplies for var.product_id / var.region /
    var.project_id, which V2k resolves name templates with (validators/names.py); None = no value known.
    `access` (FD-4AQ W4: the run's access_resolution.ResolvedAccess) gives V2l the workload's mode and sign-in mode;
    None (direct callers) keeps V2l's mode-independent check only.
    `planned_services` (FD-55 W5: terraform_engine.planned_cloud_run_services, plus RT F2 the services HB-04 renders;
    a list is read at validate time, so the caller can refresh it per assembly) feeds V3c-planned; empty = no finding.
    `validate_ready_wait_s` (V1B-WARMUP-RETRY): the bounded /validate/ready wait V1b may spend before asking again
    after a transient UNAVAILABLE (settings.validate_ready_wait_s in the developer stage); 0 = a single probe.
    `plan_targets` (PLAN-TARGET-FILES: plan_targets.required_plan_targets, given only on a full build) adds the blocking
    V-PLAN-TARGETS; empty = nothing new registered. `manifest_paths` (MANIFEST-PATH-DEFERS-TO-DAG:
    plan_targets.dag_manifest_paths) names V3c-k8s's missing-workload file after the plan; None = `k8s/<svc>.yaml`."""
    from .platform_facts import register as register_platform_facts
    from .topology import register as register_topology
    # FD-4AF-r RT F1: the stack path defers K8S.PLACEHOLDER_UNRESOLVED to V-K8S-PH, so it is the only guard there
    if (modes or {}).get(K8sPlaceholderValidator.id, "blocking") != "blocking":
        raise ValueError("V-K8S-PH guards the deferred k8s hydration (FD-4AF-r) and cannot be downgraded")
    # FD-4CW Q1: V2d leaves resource/data blocks to V2j, so V2j may not run in a weaker mode than V2d
    if MODES.index((modes or {}).get("V2j", "blocking")) < MODES.index((modes or {}).get("V2d", "blocking")):
        raise ValueError("V2j reports the provider of every resource/data block for V2d (FD-4CW) and cannot run in a "
                         "weaker mode than V2d")
    stack = ValidatorStack(modes=modes, classify=classify)
    stack.register(HclParseValidator(), "report_only")
    stack.register(HclParseValidator(llm_root_only=True), "blocking")
    stack.register(TofuValidateValidator(validate_client, iac_engine, ready_wait_s=validate_ready_wait_s), "blocking")
    stack.register(PolicyValidator(), "blocking")
    stack.register(PolicyValidator(sa_scoped=True), "report_only")
    stack.register(VariableWithoutValueValidator(), "blocking")   # S2-B B10 (HS-16): FP review 2/2 true positives
    stack.register(OrgConstraintValidator(), "blocking")      # S2-B B6: 0 findings / 0 FP on the 27 G-B trees
    stack.register(ApiCoverageValidator(), "report_only")      # S2-C: measured, the table grows by PR
    stack.register(IamLiteralSecretIdValidator(), "blocking")
    stack.register(AssemblyPreservationValidator(), "blocking")
    stack.register(ProviderAvailabilityValidator(), "blocking")
    from .content_policy import ContentPolicyValidator   # FD-4AW (local: content_policy imports step1)
    stack.register(ContentPolicyValidator(), "blocking")   # FD-4AW: code-execution constructs in generated Terraform
    from .access_idp import AccessIdpValidator   # FD-4AQ W4 (register AQ-4): sign-in config in AI-written Terraform
    stack.register(AccessIdpValidator(access), "blocking")
    from .iac_file_kinds import register as register_iac_file_kinds   # AI-TFVARS-REFUSED / AI-TOFU-REFUSED (10-29)
    # V2n: AI-written auto-loaded variables files and .tofu files, every mode (the intent path names each dropped
    # .tofu declaration)
    register_iac_file_kinds(stack, intent_mode=iac_intent is not None)
    if topology is None:
        # Lane 10 seam (F4 rule 3): S2-D's sibling-URI validators (V2f, V2f-not-written, V2f-cycle) judge the
        # exact-read sibling wiring, which only runs without a topology. On a topology tree the edge set is the
        # contract (HB-05 makes no sibling binding) and TOPOLOGY.CYCLE owns Invariant 6 for typed edges.
        stack.register(SiblingUriValidator(not_written=False), "report_only")
        stack.register(SiblingUriValidator(not_written=True), "blocking")   # HS-65b (owner, 10-14)
        stack.register(SiblingUriValidator(cycles=True), "blocking")
    stack.register(PythonSyntaxValidator(), "blocking")
    pyflakes = PyflakesValidator()
    stack.register(pyflakes, "report_only")
    stack.register(UndefinedNameValidator(pyflakes), "blocking")
    stack.register(SdkAttributeValidator(), "blocking")
    # S3-bastion (10-19): with a topology, a VM-kind service (gce-bastion / gce-worker) has no container contract
    stack.register(ContainerContractValidator(topology), "blocking")
    # FD-55 W5 (FD55-W5): a planned Cloud Run service without code (the HB-04 placeholder app is deleted)
    stack.register(PlannedServiceCodeValidator(planned_services, topology), "blocking")
    stack.register(HealthRouteUnverifiedValidator(topology), "report_only")   # HR-1
    stack.register(MigrationInvocationValidator(topology), "blocking")   # HS-40 (owner 10-19)
    if topology is not None and any(topology.kind(n) == "gke-autopilot" for n in topology.names):
        # PWB-4: a GKE service needs a k8s workload (MANIFEST-PATH-DEFERS-TO-DAG: at the plan's manifest path)
        stack.register(K8sWorkloadValidator(topology, manifest_paths), "blocking")
    # FD-4AF-r: hydration defers K8S.PLACEHOLDER_UNRESOLVED to this validator on the stack path: it must always run
    stack.register(K8sPlaceholderValidator(), "blocking")
    # FD-4AD: the layout facts the deleted Python healers (HB-26/27/28/31) rewrote; measured first, report-only
    stack.register(PythonLayoutValidator(), "report_only")
    stack.register(ImportRootValidator(topology), "report_only")      # FD-4AE-c: replaces the post-QA import rewrite
    # IMPORT-RESOLVE-GATE (owner 10-28): a local import naming nothing in its target module (live 10-28 testplan01-d)
    stack.register(LocalImportValidator(), "blocking")
    stack.register(RequirementsValidator(), "blocking")
    stack.register(WorkflowYamlValidator(), "report_only")
    stack.register(PathValidator(), "blocking")
    stack.register(GatekeeperCheckValidator(verifier_factory), "blocking")
    stack.register(VendoredDriftValidator(), "blocking")
    from .private_reach import register as register_private_reach   # FD-4DK: V2m, measured only
    register_private_reach(stack)
    from .k8s_identity import register as register_k8s_identity   # W6e review F5: V-K8S-WI, measured only
    register_k8s_identity(stack)
    # RUNTIME-ENV-CONTRACT-CHECK (owner 11-10): V-ENV, env reads the platform does not set; measured only
    from .runtime_env import register as register_runtime_env
    register_runtime_env(stack, topology)
    from .names import register as register_names   # FD-55 W4 (FD55-W4): V2k / V2k-literal
    register_names(stack, platform_values)
    register_platform_facts(stack, network_facts, existing_network=existing_network)
    register_topology(stack, topology)
    from .plan_targets import register as register_plan_targets   # PLAN-TARGET-FILES: V-PLAN-TARGETS
    register_plan_targets(stack, tuple(plan_targets or ()))
    if iac_intent is not None:   # TI-3: intent-path validators (validators/iac_intent.py); None = mode "off"
        from .iac_intent import register as register_iac_intent
        register_iac_intent(stack, iac_intent)
        # PUSH-PLAN-CHECK (owner 10-28): V-IAC-PUSH only when the topology declares a push edge
        from .push_plan import register as register_push_plan
        register_push_plan(stack, topology, iac_intent)
    return stack
