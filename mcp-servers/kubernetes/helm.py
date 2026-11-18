"""
Helm lifecycle for mcp-kubernetes-server (lane 14 PR-8, plan §3.2, row L14-p; owner: "The agents may need access to
HELM"; owner Q6: own Artifact Registry charts always, other repositories only by exact URL allow-list).

Real Helm CLI, never a mock. The binary is pinned (version + SHA-256 in `helm-pin.json`), fetched and verified by
the service's Cloud Build step / `deploy-services.sh` staging into `bin/helm`; a missing binary makes every Helm tool
answer `HELM_UNAVAILABLE`.

Install / upgrade, in order (any refusal stops before anything reaches the cluster):
  1. typed inputs: release RFC 1123 (<= 53), namespace RFC 1123 and not protected, version exact semver or
     `sha256:<64 hex>`, values a JSON object (passed as a file, never `--set`);
  2. target: the workload's project from the ledger (SEAM PR-M), the cluster read from GKE in that project;
  3. chart source: `oci://<AR host>/<the workload's project>/<repo>/<chart>` (positional; host = the verified
     cluster region's `<region>-docker.pkg.dev` or its AR multi-region host, RT F15; pulled with a registry config
     for that one host holding the server SA's token), else a plain chart name from a repository URL in the exact
     allow-list;
  4. cheap pre-check: `helm template --include-crds` -> per-document policy;
  5. authoritative: `helm upgrade --install --skip-crds --dry-run=server -o json` -> policy over `.manifest` and
     every `.hooks[].manifest` (the same rendering, incl. `lookup()`, the install uses); digest recorded;
  6. `helm upgrade --install --skip-crds --atomic --wait --timeout <bounded> -o json`;
  7. the installed release's manifest + hooks digest is compared with the dry-run digest. Equal -> INSTALLED. Different
     (owner F16 = option B) -> the full policy re-runs on what was actually installed: clean -> INSTALLED with
     `render_drift: true` and both digests audited; a violation -> HELM_POST_INSTALL_DRIFT: revision > 1 -> `helm
     rollback` to the previous revision only if the policy passes on it (else, or for a first install, a
     HELM_UNINSTALL approval request is recorded; never an automatic uninstall; also when the rollback target cannot
     be checked or the rollback command fails, RT R4). The installed revision is read with `helm get manifest|hooks
     --revision N` (RT R5). An installed release that cannot be checked (no revision, `helm status` / `helm get`
     failing, discovery, unparsable; RT R6) is never INSTALLED: audited, an approval request is recorded, no
     automatic rollback.
The policy (RT F14): every rendered document's (apiVersion, kind) is resolved through the target cluster's API
discovery; a cluster-scoped kind (CLUSTER_SCOPED_KIND) or one the cluster does not serve (UNKNOWN_KIND) is refused,
as is any protected namespace. `helm_rollback` runs the same policy on the target revision first (RT F18).
`helm_uninstall` needs an approved HELM_UNINSTALL record (lane 18 shape) bound to the exact cluster, location,
namespace and release, minted by a human administrator in the Control Center and consumed through project-vending
(docs/planning/mcp-action-approval-plan.md).

Cluster credentials never touch a kubeconfig file: HELM_KUBEAPISERVER / HELM_KUBETOKEN / HELM_KUBECAFILE env (the CA
in a TemporaryDirectory), from the same GKE lookup the other tools use.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

import yaml

import managed_target_seam as seam

HELM_UNAVAILABLE = "HELM_UNAVAILABLE"
ACTION_HELM_UNINSTALL = "HELM_UNINSTALL"

# Exact protected namespaces (plan §3.2) and cluster-scoped kinds a chart may never create.
PROTECTED_NAMESPACES = frozenset({
    "kube-system", "kube-public", "kube-node-lease", "gke-managed-system", "gke-gmp-system", "gke-managed-cim",
    "gmp-system", "gmp-public", "config-management-system", "config-management-monitoring", "istio-system",
})
CLUSTER_SCOPED_KINDS = frozenset({
    "ClusterRole", "ClusterRoleBinding", "Namespace", "CustomResourceDefinition", "MutatingWebhookConfiguration",
    "ValidatingWebhookConfiguration", "ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding",
    "PriorityClass", "StorageClass", "PersistentVolume", "APIService", "RuntimeClass", "CSIDriver", "Node",
    "PodSecurityPolicy", "IngressClass", "ClusterIssuer",
})
MAX_RELEASE_LENGTH = 53
INSTALL_TIMEOUT = "300s"
HELM_CMD_TIMEOUT_S = 600
# The uninstall approval card is an `approval_requests/{id}` MCP_ACTION card (managed_target_seam); the earlier
# `helm_uninstall_requests` collection had no reader and is no longer written.
REQUESTED_BY = "mcp-kubernetes-server"
RELEASE_AUDIT_COLLECTION = "helm_releases"
ALLOWLIST_ENV = "HELM_CHART_REPOSITORY_ALLOWLIST"
OCI_HOST_SUFFIX = "-docker.pkg.dev"
AR_MULTI_REGIONS = frozenset({"us", "europe", "asia"})  # Artifact Registry multi-region locations (exact)
MIN_HELM_VERSION = (3, 13)  # RT F19: --dry-run=server needs Helm v3.13.0 or later
FIELD_MANAGER = "stackvend"  # FD-4L / FD27-10: server-side apply field manager of k8s_apply_manifest


class HelmRefused(Exception):
    def __init__(self, code: str, detail: str = "", http_status: int = 422, **extra: Any):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail, self.http_status = code, detail, http_status
        self.extra: Dict[str, Any] = dict(extra)  # typed fields for the caller (e.g. approval_request_id)


# --------------------------------------------------------------------------------------------------- typed checks
def is_rfc1123_label(value: Any, max_len: int = 63) -> bool:
    if not isinstance(value, str) or not value or len(value) > max_len or not value.isascii():  # RT F2: ASCII only
        return False
    if not all(ch.islower() or ch.isdigit() or ch == "-" for ch in value):
        return False
    return value[0].isalnum() and value[-1].isalnum()


def is_exact_version(value: Any) -> bool:
    """`MAJOR.MINOR.PATCH` (optional leading v, optional -prerelease / +build of [0-9A-Za-z.-]) or sha256:<64 hex>."""
    if not isinstance(value, str) or not value:
        return False
    if value.startswith("sha256:"):
        digest = value[len("sha256:"):]
        return len(digest) == 64 and all(ch in "0123456789abcdef" for ch in digest)
    core = value[1:] if value.startswith("v") else value
    for sep in ("+", "-"):
        head, found, tail = core.partition(sep)
        if found:
            if not tail or not all(ch.isalnum() or ch in ".-" for ch in tail):
                return False
            core = head
    parts = core.split(".")
    return len(parts) == 3 and all(p.isdigit() and (p == "0" or not p.startswith("0")) for p in parts)


def cluster_region(location: str) -> str:
    """GKE location -> region: a zone `<region>-<letter>` drops its suffix; a region stays as is."""
    head, sep, tail = (location or "").rpartition("-")
    if sep and len(tail) == 1 and tail.isalpha() and "-" in head:
        return head
    return location


def artifact_registry_hosts(regions: Sequence[str]) -> frozenset:
    """RT F15: the exact Artifact Registry hosts a workload chart may come from: `<cluster region>-docker.pkg.dev`
    and, when the region's first label is an AR multi-region (us / europe / asia), that multi-region's host
    (e.g. us-east4 -> us-docker.pkg.dev). The region is split on its dashes (positional), never substring-matched."""
    hosts = set()
    for region in regions:
        if not region:
            continue
        hosts.add(f"{region}{OCI_HOST_SUFFIX}")
        first, sep, _ = region.partition("-")
        if sep and first in AR_MULTI_REGIONS:
            hosts.add(f"{first}{OCI_HOST_SUFFIX}")
    return frozenset(hosts)


def validate_oci_chart(chart_ref: str, *, project_id: str, regions: Sequence[str]) -> str:
    """`oci://<AR host>/<project_id>/<repo>/<chart...>`, positional. Returns the validated host. Raises HelmRefused."""
    scheme, sep, rest = chart_ref.partition("://")
    if scheme != "oci" or not sep:
        raise HelmRefused("CHART_REF_INVALID", "not an oci:// reference")
    segs = rest.split("/")
    if len(segs) < 4 or not all(segs):
        raise HelmRefused("CHART_REF_INVALID", "expected oci://<host>/<project>/<repository>/<chart>")
    host, project = segs[0], segs[1]
    if host not in artifact_registry_hosts(regions):
        raise HelmRefused("CHART_SOURCE_NOT_ALLOWED", f"host {host!r} is not the workload's Artifact Registry")
    if project != project_id:
        raise HelmRefused("CHART_SOURCE_NOT_ALLOWED", f"project segment {project!r} is not the workload's project")
    for seg in segs[2:]:
        if not is_rfc1123_label(seg, 128) and not all(ch.isalnum() or ch in "._-" for ch in seg):
            raise HelmRefused("CHART_REF_INVALID", f"segment {seg!r}")
    return host


# RT F14: `(apiVersion, kind) -> True (namespaced) | False (cluster-scoped) | None (the cluster does not know it)`,
# answered by the target cluster's own API discovery. The exact CLUSTER_SCOPED_KINDS set stays a fast pre-check only.
KindScope = Callable[[str, str], Optional[bool]]


def document_policy(docs: Sequence[Any], default_namespace: str, scope: Optional[KindScope] = None
                    ) -> List[Dict[str, str]]:
    """Per-document policy over rendered manifests: no cluster-scoped kind, no kind the cluster does not know, no
    protected namespace. Without `scope` only the exact pre-check set and the namespaces are checked (used for the
    request-level tests); every install / upgrade / rollback path passes the cluster's discovery."""
    violations = []
    for doc in docs:
        if doc is None:
            continue
        if not isinstance(doc, dict):
            violations.append({"code": "UNPARSABLE_DOCUMENT", "kind": "", "name": "", "namespace": ""})
            continue
        kind = str(doc.get("kind") or "")
        api_version = str(doc.get("apiVersion") or "")
        meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
        name = str(meta.get("name") or "")
        ns = meta.get("namespace") or default_namespace
        if kind == "List" and isinstance(doc.get("items"), list):
            violations.extend(document_policy(doc["items"], default_namespace, scope))
            continue
        entry = {"kind": kind, "name": name, "namespace": str(ns)}
        if kind in CLUSTER_SCOPED_KINDS:
            violations.append(dict(entry, code="CLUSTER_SCOPED_KIND"))
            continue
        if scope is not None:
            namespaced = scope(api_version, kind) if (api_version and kind) else None
            if namespaced is None:
                violations.append(dict(entry, code="UNKNOWN_KIND", api_version=api_version))
                continue
            if namespaced is False:
                violations.append(dict(entry, code="CLUSTER_SCOPED_KIND", api_version=api_version))
                continue
        if ns in PROTECTED_NAMESPACES:
            violations.append(dict(entry, code="PROTECTED_NAMESPACE"))
    return violations


class DiscoveryKindScope:
    """RT F14: a KindScope backed by the target cluster's API discovery (kubernetes.dynamic.DynamicClient, fresh
    discovery cache per use). A kind the server does not serve, or serves ambiguously, is None (refused as
    UNKNOWN_KIND). A discovery failure raises HelmRefused DISCOVERY_FAILED (fail closed: nothing is installed).
    Use as a context manager: the CA file and discovery cache live in a private temp dir until close()."""

    def __init__(self, access: "ClusterAccess", *, dynamic_client_factory: Optional[Callable[..., Any]] = None):
        self._access, self._factory = access, dynamic_client_factory
        self._tmp: Optional[tempfile.TemporaryDirectory] = None
        self._dyn: Any = None
        self._cache: Dict[Tuple[str, str], Optional[bool]] = {}

    def __enter__(self) -> "DiscoveryKindScope":
        from kubernetes import client as k8s_client

        self._tmp = tempfile.TemporaryDirectory(prefix="helm-discovery-")
        ca_path = os.path.join(self._tmp.name, "ca.crt")
        with open(ca_path, "wb") as fh:
            fh.write(base64.b64decode(self._access.ca_cert_b64))
        cfg = k8s_client.Configuration()
        cfg.host = self._access.endpoint
        cfg.api_key = {"authorization": f"Bearer {self._access.token}"}
        cfg.ssl_ca_cert = ca_path
        cache_file = os.path.join(self._tmp.name, "discovery.json")
        try:
            if self._factory is not None:
                self._dyn = self._factory(k8s_client.ApiClient(cfg), cache_file=cache_file)
            else:
                from kubernetes.dynamic import DynamicClient

                self._dyn = DynamicClient(k8s_client.ApiClient(cfg), cache_file=cache_file)
        except Exception as e:
            self.close()
            raise HelmRefused("DISCOVERY_FAILED", type(e).__name__, 502) from e
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        if self._tmp is not None:
            self._tmp.cleanup()
            self._tmp = None

    def __call__(self, api_version: str, kind: str) -> Optional[bool]:
        key = (api_version, kind)
        if key not in self._cache:
            from kubernetes.dynamic.exceptions import ResourceNotFoundError, ResourceNotUniqueError

            try:
                res = self._dyn.resources.get(api_version=api_version, kind=kind)
            except (ResourceNotFoundError, ResourceNotUniqueError):
                self._cache[key] = None
            except Exception as e:
                raise HelmRefused("DISCOVERY_FAILED", type(e).__name__, 502) from e
            else:
                namespaced = getattr(res, "namespaced", None)
                self._cache[key] = namespaced if isinstance(namespaced, bool) else None
        return self._cache[key]

    def server_side_apply(self, doc: Dict[str, Any], namespace: Optional[str], *, dry_run: bool) -> Any:
        """FD-4L / FD27-10: server-side apply of one policy-checked document (k8s_apply_manifest) through this same
        discovery client, so the kind that passed the policy is the resource that is applied. `namespace` is None
        for a cluster-scoped kind (never reached: the policy refuses those). Raises the client's API exception."""
        meta = doc.get("metadata") or {}
        res = self._dyn.resources.get(api_version=str(doc.get("apiVersion")), kind=str(doc.get("kind")))
        return self._dyn.server_side_apply(res, body=doc, name=meta.get("name"), namespace=namespace,
                                           field_manager=FIELD_MANAGER, dry_run="All" if dry_run else None)


def parse_documents(text: str) -> List[Any]:
    try:
        return list(yaml.safe_load_all(text or ""))
    except yaml.YAMLError as e:
        raise HelmRefused("RENDER_UNPARSABLE", f"{type(e).__name__}") from e


def release_manifests(release: Dict[str, Any]) -> Tuple[str, List[str]]:
    manifest = release.get("manifest") if isinstance(release.get("manifest"), str) else ""
    hooks = [h.get("manifest") for h in (release.get("hooks") or []) if isinstance(h, dict) and isinstance(h.get("manifest"), str)]
    return manifest, hooks


def release_digest(release: Dict[str, Any]) -> str:
    manifest, hooks = release_manifests(release)
    h = hashlib.sha256(manifest.encode("utf-8"))
    for hook in hooks:
        h.update(b"\0---hook---\0" + hook.encode("utf-8"))
    return h.hexdigest()


def registry_config(host: str, token: str) -> Dict[str, Any]:
    """Docker-style registry config with exactly one entry (RT F15)."""
    auth = base64.b64encode(f"oauth2accesstoken:{token}".encode("utf-8")).decode("ascii")
    return {"auths": {host: {"auth": auth}}}


# --------------------------------------------------------------------------------------------------- runner
@dataclass
class ClusterAccess:
    endpoint: str
    token: str
    ca_cert_b64: str


class HelmRunner:
    """Runs the Helm CLI with cluster access in env vars and a private temp dir. Injectable `run` for tests."""

    def __init__(self, binary: Optional[str] = None, run: Optional[Callable[..., Any]] = None):
        self._binary = binary
        self._run = run or subprocess.run

    def binary(self) -> Optional[str]:
        if self._binary:
            return self._binary if os.path.isfile(self._binary) and os.access(self._binary, os.X_OK) else None
        explicit = os.getenv("HELM_BIN")
        if explicit:
            return explicit if os.path.isfile(explicit) and os.access(explicit, os.X_OK) else None
        return shutil.which("helm")

    def version(self) -> Optional[str]:
        binary = self.binary()
        if not binary:
            return None
        try:
            res = self._run([binary, "version", "--short"], capture_output=True, text=True, timeout=30, check=False)
        except Exception:
            return None
        return (res.stdout or "").strip() or None if res.returncode == 0 else None

    def __call__(self, args: List[str], access: Optional[ClusterAccess], *, values: Optional[Dict[str, Any]] = None,
                 registry_host: Optional[str] = None) -> Tuple[int, str, str]:
        binary = self.binary()
        if not binary:
            raise HelmRefused(HELM_UNAVAILABLE, "the Helm CLI is not installed in this image", 503)
        with tempfile.TemporaryDirectory(prefix="helm-") as tmp:
            env = {"PATH": os.environ.get("PATH", ""), "HOME": tmp, "HELM_CACHE_HOME": os.path.join(tmp, "cache"),
                   "HELM_CONFIG_HOME": os.path.join(tmp, "config"), "HELM_DATA_HOME": os.path.join(tmp, "data")}
            argv = [binary] + list(args)
            if access is not None:
                ca_path = os.path.join(tmp, "ca.crt")
                with open(ca_path, "wb") as fh:
                    fh.write(base64.b64decode(access.ca_cert_b64))
                env.update(HELM_KUBEAPISERVER=access.endpoint, HELM_KUBETOKEN=access.token, HELM_KUBECAFILE=ca_path)
                if registry_host:
                    # RT F15: Artifact Registry is private. A registry config for the ONE validated host, with the
                    # server SA's access token (oauth2accesstoken), in the private temp dir; never in argv.
                    reg_path = os.path.join(tmp, "registry.json")
                    with open(reg_path, "w", encoding="utf-8") as fh:
                        json.dump(registry_config(registry_host, access.token), fh)
                    env["HELM_REGISTRY_CONFIG"] = reg_path
            if values is not None:
                values_path = os.path.join(tmp, "values.json")
                with open(values_path, "w", encoding="utf-8") as fh:
                    json.dump(values, fh)
                argv += ["--values", values_path]
            res = self._run(argv, capture_output=True, text=True, timeout=HELM_CMD_TIMEOUT_S, check=False, env=env)
            return res.returncode, res.stdout or "", res.stderr or ""


def uninstall_binding(cluster_name: str, location: str, namespace: str, release: str) -> Dict[str, str]:
    """The exact arguments a HELM_UNINSTALL approval is bound to (managed_target_seam.MCP_ACTION_BINDING_KEYS)."""
    return {"cluster": cluster_name, "location": location, "namespace": namespace, "release": release}


# --------------------------------------------------------------------------------------------------- service
class HelmService:
    def __init__(
        self,
        *,
        db_factory: Callable[[], Any],
        guard_db_factory: Callable[[], Any],
        cluster_access: Callable[[str, str, str], Tuple[ClusterAccess, Dict[str, Any]]],
        runner: Optional[HelmRunner] = None,
        approval_consumer: Optional[Callable[..., None]] = None,
        env: Optional[Mapping[str, str]] = None,
        clock: Optional[Callable[[], datetime]] = None,
        kind_scope_factory: Optional[Callable[[ClusterAccess], Any]] = None,
    ):
        self._db_factory, self._guard_db_factory = db_factory, guard_db_factory
        self._cluster_access = cluster_access
        # RT F14: context manager yielding a KindScope for the target cluster (default: its API discovery).
        self._kind_scope_factory = kind_scope_factory or (lambda access: DiscoveryKindScope(access))
        self.runner = runner or HelmRunner()
        self._consume = approval_consumer or seam.consume_approval
        self._env = os.environ if env is None else env
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    # ------------------------------------------------------------------ shared
    def health(self) -> Dict[str, Any]:
        version = self.runner.version()
        return {"helm_version": version, "helm_status": "AVAILABLE" if version else HELM_UNAVAILABLE}

    def resolve_target(self, product_id: str, project_id: Optional[str], cluster_name: str, location: str
                       ) -> Tuple[seam.ManagedTarget, ClusterAccess, Dict[str, Any]]:
        """(ledger target, cluster access, cluster facts). The project comes only from the workload ledger; a
        request `project_id` must equal it exactly. Used by the Helm tools and (FD-4L / FD27-10) every other k8s
        tool in service.py."""
        try:
            target = seam.verify_ledger_target(self._db_factory(), product_id, seam.host_project_ids(self._env))
        except seam.TargetRefused as e:
            raise HelmRefused(f"REFUSED:{e.code}", e.detail, 403) from e
        if project_id and project_id != target.project_id:
            raise HelmRefused("REFUSED:TARGET_MISMATCH", "project_id is not the workload's project", 403)
        if not is_rfc1123_label(cluster_name, 40) or not isinstance(location, str) or not location \
                or not location.isascii() or not all(
                ch.islower() or ch.isdigit() or ch == "-" for ch in location):
            raise HelmRefused("INVALID_CLUSTER", "cluster_name / location")
        try:
            access, cluster = self._cluster_access(target.project_id, cluster_name, location)
        except HelmRefused:
            raise
        except Exception as e:
            raise HelmRefused("CLUSTER_NOT_FOUND", f"{type(e).__name__}", 404) from e
        return target, access, dict(cluster or {})

    def kind_scope(self, access: ClusterAccess) -> Any:
        """FD-4L / FD27-10: the same cluster API-discovery policy scope Helm uses (context manager)."""
        return self._kind_scope_factory(access)

    def _target(self, product_id: str, project_id: Optional[str], cluster_name: str, location: str
                ) -> Tuple[seam.ManagedTarget, ClusterAccess, List[str]]:
        target, access, cluster = self.resolve_target(product_id, project_id, cluster_name, location)
        regions = sorted({cluster_region(str(cluster.get("location") or location))})
        return target, access, regions

    def _allowlist(self) -> frozenset:
        raw = self._env.get(ALLOWLIST_ENV) or "[]"
        try:
            items = json.loads(raw)
        except ValueError:
            return frozenset()
        return frozenset(i for i in items if isinstance(i, str) and i.startswith("https://")) if isinstance(items, list) else frozenset()

    def _chart_args(self, chart_ref: str, repo_url: Optional[str], version: str, project_id: str,
                    regions: Sequence[str]) -> Tuple[List[str], Optional[str]]:
        """(chart args, registry host to authenticate to or None)."""
        if not isinstance(chart_ref, str) or not chart_ref:
            raise HelmRefused("CHART_REF_INVALID", "chart_ref is required")
        if not is_exact_version(version):
            raise HelmRefused("VERSION_NOT_EXACT", "version must be an exact semver or sha256 digest")
        if chart_ref.startswith("oci://"):
            if repo_url:
                raise HelmRefused("CHART_REF_INVALID", "repo_url is not used with an oci:// chart")
            host = validate_oci_chart(chart_ref, project_id=project_id, regions=regions)
            return [chart_ref, "--version", version], host
        if not repo_url or repo_url not in self._allowlist():
            raise HelmRefused("CHART_SOURCE_NOT_ALLOWED", "chart repository is not in the exact allow-list")
        if not is_rfc1123_label(chart_ref, 128):
            raise HelmRefused("CHART_REF_INVALID", "chart name")
        return [chart_ref, "--repo", repo_url, "--version", version], None

    def _revision_violations(self, release: str, revision: int, namespace: str, access: ClusterAccess,
                             scope: KindScope) -> List[Dict[str, str]]:
        """RT F18: the policy over a stored revision's manifest and hooks (`helm get manifest|hooks --revision N`)
        before anything rolls back to it. A revision from before PR-8 may hold content the policy refuses."""
        violations: List[Dict[str, str]] = []
        for what in ("manifest", "hooks"):
            code, out, err = self.runner(["get", what, release, "--revision", str(revision), "--namespace", namespace],
                                         access)
            if code != 0:
                raise HelmRefused(f"HELM_FAILED:GET_{what.upper()}", (err or out)[:500], 502)
            violations += document_policy(parse_documents(out), namespace, scope)
        return violations

    def _audit(self, record: Dict[str, Any]) -> None:
        try:
            self._db_factory().collection(RELEASE_AUDIT_COLLECTION).document(record["audit_id"]).set(record)
        except Exception:
            record["audit_error"] = True

    def _helm_json(self, args: List[str], access: ClusterAccess, stage: str, values=None,
                   registry_host: Optional[str] = None) -> Dict[str, Any]:
        code, out, err = self.runner(args, access, values=values, registry_host=registry_host)
        if code != 0:
            raise HelmRefused(f"HELM_FAILED:{stage}", (err or out)[:500], 502)
        try:
            body = json.loads(out)
        except ValueError as e:
            raise HelmRefused(f"HELM_FAILED:{stage}", "output is not JSON", 502) from e
        if not isinstance(body, (dict, list)):
            raise HelmRefused(f"HELM_FAILED:{stage}", "unexpected output", 502)
        return body

    # ------------------------------------------------------------------ install / upgrade
    def install_or_upgrade(self, *, product_id: str, cluster_name: str, location: str, namespace: str, release: str,
                           chart_ref: str, version: str, values: Optional[Dict[str, Any]] = None,
                           repo_url: Optional[str] = None, project_id: Optional[str] = None) -> Dict[str, Any]:
        if not is_rfc1123_label(release, MAX_RELEASE_LENGTH):
            raise HelmRefused("RELEASE_NAME_INVALID", "release must be an RFC 1123 label of at most 53 characters")
        if not is_rfc1123_label(namespace):
            raise HelmRefused("NAMESPACE_INVALID", "namespace must be an RFC 1123 label")
        if namespace in PROTECTED_NAMESPACES:
            raise HelmRefused("PROTECTED_NAMESPACE", namespace, 403)
        values = {} if values is None else values
        if not isinstance(values, dict):
            raise HelmRefused("VALUES_INVALID", "values must be a JSON object")
        try:
            json.dumps(values)
        except (TypeError, ValueError) as e:
            raise HelmRefused("VALUES_INVALID", "values must be JSON-serializable") from e
        if self.runner.binary() is None:
            raise HelmRefused(HELM_UNAVAILABLE, "the Helm CLI is not installed in this image", 503)
        target, access, regions = self._target(product_id, project_id, cluster_name, location)
        chart, registry_host = self._chart_args(chart_ref, repo_url, version, target.project_id, regions)
        with self._kind_scope_factory(access) as scope:
            return self._install_checked(product_id=product_id, target=target, access=access, scope=scope,
                                         cluster_name=cluster_name, location=location, namespace=namespace,
                                         release=release, chart_ref=chart_ref, chart=chart,
                                         registry_host=registry_host, version=version, values=values)

    def _install_checked(self, *, product_id: str, target: seam.ManagedTarget, access: ClusterAccess,
                         scope: KindScope, cluster_name: str, location: str, namespace: str, release: str,
                         chart_ref: str,
                         chart: List[str], registry_host: Optional[str], version: str, values: Dict[str, Any]
                         ) -> Dict[str, Any]:
        ns_args = ["--namespace", namespace]
        audit = {"audit_id": f"helm-{uuid.uuid4().hex[:12]}", "product_id": product_id, "project_id": target.project_id,
                 "cluster": cluster_name, "namespace": namespace, "release": release, "chart_ref": chart_ref,
                 "version": version, "started_at": self._clock().isoformat()}

        # 4. cheap pre-check (the only check of a chart's static crds/ directory; F17 also skips CRDs below)
        code, out, err = self.runner(["template", release] + chart + ns_args + ["--include-crds"], access,
                                     values=values, registry_host=registry_host)
        if code != 0:
            raise HelmRefused("HELM_FAILED:TEMPLATE", (err or out)[:500], 502)
        pre = document_policy(parse_documents(out), namespace, scope)
        if pre:
            audit.update(status="REFUSED:POLICY", stage="template", violations=pre)
            self._audit(audit)
            return dict(audit, http_status=403)

        # 5. authoritative: the server-side dry run of the real release (hooks included). RT F17: --skip-crds, so a
        # CRD in crds/ can never be installed even if the pre-check regresses.
        dry = self._helm_json(["upgrade", "--install", release] + chart + ns_args +
                              ["--skip-crds", "--dry-run=server", "-o", "json"],
                              access, "DRY_RUN", values=values, registry_host=registry_host)
        manifest, hooks = release_manifests(dry)
        authoritative = document_policy(parse_documents(manifest), namespace, scope)
        for hook in hooks:
            authoritative += document_policy(parse_documents(hook), namespace, scope)
        if authoritative:
            audit.update(status="REFUSED:POLICY", stage="server_dry_run", violations=authoritative)
            self._audit(audit)
            return dict(audit, http_status=403)
        dry_digest = release_digest(dry)

        # 6. the real install
        installed = self._helm_json(["upgrade", "--install", release] + chart + ns_args +
                                    ["--skip-crds", "--atomic", "--wait", "--timeout", INSTALL_TIMEOUT, "-o", "json"],
                                    access, "INSTALL", values=values, registry_host=registry_host)
        revision = installed.get("version")
        if not isinstance(revision, int) or revision < 1:
            # RT residual R6: the install command succeeded, so a release may be live; never a bare 502 without an
            # audit: the operator decides (uninstall card).
            return self._drift_unverified(audit, product_id, target, cluster_name, location, namespace, release,
                                          "HELM_FAILED:INSTALL_REVISION_MISSING", revision=None)

        # 7. post-install digest of what the cluster now holds. Owner decision F16 = option B (register 1202c76): a
        # rendered-vs-installed mismatch alone is not a failure (charts that render random values / generated certs
        # differ on every render); the FULL policy re-runs on the manifest + hooks actually installed, and only a
        # violation is remediated.
        try:
            status = self._helm_json(["status", release] + ns_args + ["--revision", str(revision), "-o", "json"],
                                     access, "STATUS")
        except HelmRefused as e:  # RT residual R6: installed but not checkable -> audit + card, not a bare 502
            return self._drift_unverified(audit, product_id, target, cluster_name, location, namespace, release,
                                          e.code, revision=revision, dry_run_digest=dry_digest)
        audit.update(revision=revision, dry_run_digest=dry_digest, installed_digest=release_digest(status))
        if audit["installed_digest"] == dry_digest:
            audit.update(status="INSTALLED")
            self._audit(audit)
            return dict(audit, http_status=200)
        try:
            # RT residual R5: the installed revision is read with the authoritative `helm get manifest|hooks
            # --revision N` (never depending on `status -o json` carrying `hooks`); any error -> DRIFT_UNVERIFIED.
            drift_violations = self._revision_violations(release, revision, namespace, access, scope)
        except HelmRefused as e:
            # The installed release could not be checked (discovery / unparsable / helm get): never claimed INSTALLED,
            # never an automatic rollback on an unverified result; the operator decides (uninstall card).
            return self._drift_unverified(audit, product_id, target, cluster_name, location, namespace, release,
                                          e.code)
        if not drift_violations:
            audit.update(status="INSTALLED", render_drift=True)
            self._audit(audit)
            return dict(audit, http_status=200)
        audit.update(status="HELM_POST_INSTALL_DRIFT", render_drift=True, drift_violations=drift_violations)
        if revision > 1:
            # RT F18: the revision rolled back to passes the same policy first.
            try:
                previous = self._revision_violations(release, revision - 1, namespace, access, scope)
            except HelmRefused as e:  # RT residual R3 (+R4: card): the rollback target could not be checked
                previous = None
                audit["remediation"] = f"ROLLBACK_FAILED:{e.code}; " + self._request_uninstall(
                    product_id, target, cluster_name, location, namespace, release, "HELM_POST_INSTALL_DRIFT")
            if previous:
                # RT residual R2: nothing safe to roll back to -> the operator decides (uninstall card).
                audit.update(rollback_violations=previous)
                audit["remediation"] = "ROLLBACK_REFUSED:POLICY; " + self._request_uninstall(
                    product_id, target, cluster_name, location, namespace, release, "HELM_POST_INSTALL_DRIFT")
            elif previous is not None:
                code, out, err = self.runner(["rollback", release, str(revision - 1)] + ns_args + ["--wait"], access)
                if code == 0:
                    audit["remediation"] = "ROLLED_BACK"
                else:  # RT residual R4: the violating revision stays installed -> card
                    audit["remediation"] = f"ROLLBACK_FAILED: {(err or out)[:300]}; " + self._request_uninstall(
                        product_id, target, cluster_name, location, namespace, release, "HELM_POST_INSTALL_DRIFT")
        else:
            audit["remediation"] = self._request_uninstall(product_id, target, cluster_name, location, namespace,
                                                           release, "HELM_POST_INSTALL_DRIFT")
        self._audit(audit)
        return dict(audit, http_status=409)

    def _drift_unverified(self, audit: Dict[str, Any], product_id: str, target: seam.ManagedTarget,
                          cluster_name: str, location: str, namespace: str, release: str, code: str,
                          **extra: Any) -> Dict[str, Any]:
        """The install ran but what the cluster holds could not be checked: audited, never INSTALLED, no automatic
        rollback; an uninstall approval card lets the operator decide (RT R5/R6, builder DRIFT_UNVERIFIED)."""
        audit.update(extra)
        audit.update(status="HELM_POST_INSTALL_DRIFT", render_drift=True, drift_check_error=code)
        audit["remediation"] = f"DRIFT_UNVERIFIED:{code}; " + self._request_uninstall(
            product_id, target, cluster_name, location, namespace, release, "HELM_POST_INSTALL_DRIFT_UNVERIFIED")
        self._audit(audit)
        return dict(audit, http_status=409)

    def _request_uninstall(self, product_id: str, target: seam.ManagedTarget, cluster_name: str, location: str,
                           namespace: str, release: str, reason: str) -> str:
        """Records a HELM_UNINSTALL approval request: the MCP_ACTION card in the Control Center's Approvals tab
        (managed_target_seam.record_approval_request); never uninstalls."""
        try:
            request_id = seam.record_approval_request(
                self._db_factory(), action=ACTION_HELM_UNINSTALL, product_id=product_id,
                project_id=target.project_id, binding=uninstall_binding(cluster_name, location, namespace, release),
                requested_by=REQUESTED_BY, reason=reason, now=self._clock())
            return f"UNINSTALL_APPROVAL_REQUESTED:{request_id}"
        except seam.ApprovalRefused as e:
            return f"UNINSTALL_REQUEST_NOT_RECORDED:{e.detail}"

    # ------------------------------------------------------------------ other lifecycle tools
    def rollback(self, *, product_id: str, cluster_name: str, location: str, namespace: str, release: str,
                 revision: int, project_id: Optional[str] = None) -> Dict[str, Any]:
        self._names(release, namespace)
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
            raise HelmRefused("REVISION_INVALID", "revision must be a positive integer")
        if self.runner.binary() is None:
            raise HelmRefused(HELM_UNAVAILABLE, "the Helm CLI is not installed in this image", 503)
        _, access, _ = self._target(product_id, project_id, cluster_name, location)
        with self._kind_scope_factory(access) as scope:
            violations = self._revision_violations(release, revision, namespace, access, scope)
        if violations:  # RT F18
            return {"status": "REFUSED:POLICY", "stage": "rollback_target", "release": release,
                    "namespace": namespace, "revision": revision, "violations": violations, "http_status": 403}
        code, out, err = self.runner(["rollback", release, str(revision), "--namespace", namespace, "--wait"], access)
        if code != 0:
            raise HelmRefused("HELM_FAILED:ROLLBACK", (err or out)[:500], 502)
        return {"status": "ROLLED_BACK", "release": release, "namespace": namespace, "revision": revision,
                "http_status": 200}

    def uninstall(self, *, product_id: str, cluster_name: str, location: str, namespace: str, release: str,
                  approval_id: Optional[str], project_id: Optional[str] = None) -> Dict[str, Any]:
        """Needs an approved HELM_UNINSTALL record bound to exactly this cluster, location, namespace and release.
        Without `approval_id` an approval card is recorded (REFUSED:APPROVAL_REQUIRED + approval_request_id)."""
        self._names(release, namespace)
        if self.runner.binary() is None:
            raise HelmRefused(HELM_UNAVAILABLE, "the Helm CLI is not installed in this image", 503)
        target, access, _ = self._target(product_id, project_id, cluster_name, location)
        binding = uninstall_binding(cluster_name, location, namespace, release)
        try:
            seam.check_approval(self._guard_db_factory(), approval_id, action=ACTION_HELM_UNINSTALL,
                                product_id=product_id, project_id=target.project_id, binding=binding,
                                now=self._clock())
        except seam.ApprovalRefused as e:
            if e.code != "APPROVAL_REQUIRED":
                raise HelmRefused(f"REFUSED:{e.code}", e.detail, 403) from e
            try:
                request_id = seam.record_approval_request(
                    self._db_factory(), action=ACTION_HELM_UNINSTALL, product_id=product_id,
                    project_id=target.project_id, binding=binding, requested_by=REQUESTED_BY,
                    reason="helm_uninstall called without an approval", now=self._clock())
            except seam.ApprovalRefused as r:
                raise HelmRefused(f"REFUSED:{r.code}", r.detail, 503) from r
            raise HelmRefused("REFUSED:APPROVAL_REQUIRED",
                              f"approval requested in the Control Center (approval_request_id {request_id})", 403,
                              approval_request_id=request_id) from e
        try:
            self._consume(approval_id, action=ACTION_HELM_UNINSTALL, product_id=product_id,
                          project_id=target.project_id, binding=binding)
        except seam.ApprovalRefused as e:
            raise HelmRefused(f"REFUSED:{e.code}", e.detail, 503 if e.code == "APPROVAL_CONSUME_UNAVAILABLE" else 403) from e
        code, out, err = self.runner(["uninstall", release, "--namespace", namespace, "--wait"], access)
        if code != 0:
            raise HelmRefused("HELM_FAILED:UNINSTALL", (err or out)[:500], 502)
        return {"status": "UNINSTALLED", "release": release, "namespace": namespace, "approval_id": approval_id,
                "http_status": 200}

    def list_releases(self, *, product_id: str, cluster_name: str, location: str, namespace: str,
                      project_id: Optional[str] = None) -> Dict[str, Any]:
        if not is_rfc1123_label(namespace):
            raise HelmRefused("NAMESPACE_INVALID", "namespace must be an RFC 1123 label")
        _, access, _ = self._target(product_id, project_id, cluster_name, location)
        body = self._helm_json(["list", "--namespace", namespace, "-o", "json"], access, "LIST")
        return {"status": "OK", "namespace": namespace, "releases": body if isinstance(body, list) else [],
                "http_status": 200}

    def release_status(self, *, product_id: str, cluster_name: str, location: str, namespace: str, release: str,
                       project_id: Optional[str] = None) -> Dict[str, Any]:
        self._names(release, namespace)
        _, access, _ = self._target(product_id, project_id, cluster_name, location)
        body = self._helm_json(["status", release, "--namespace", namespace, "-o", "json"], access, "STATUS")
        info = body.get("info") if isinstance(body, dict) else {}
        return {"status": "OK", "release": release, "namespace": namespace, "revision": body.get("version"),
                "info": {k: (info or {}).get(k) for k in ("status", "first_deployed", "last_deployed", "description")},
                "http_status": 200}

    def history(self, *, product_id: str, cluster_name: str, location: str, namespace: str, release: str,
                project_id: Optional[str] = None) -> Dict[str, Any]:
        self._names(release, namespace)
        _, access, _ = self._target(product_id, project_id, cluster_name, location)
        body = self._helm_json(["history", release, "--namespace", namespace, "-o", "json"], access, "HISTORY")
        return {"status": "OK", "release": release, "namespace": namespace,
                "history": body if isinstance(body, list) else [], "http_status": 200}

    @staticmethod
    def _names(release: str, namespace: str) -> None:
        if not is_rfc1123_label(release, MAX_RELEASE_LENGTH):
            raise HelmRefused("RELEASE_NAME_INVALID", "release must be an RFC 1123 label of at most 53 characters")
        if not is_rfc1123_label(namespace):
            raise HelmRefused("NAMESPACE_INVALID", "namespace must be an RFC 1123 label")
        if namespace in PROTECTED_NAMESPACES:
            raise HelmRefused("PROTECTED_NAMESPACE", namespace, 403)
