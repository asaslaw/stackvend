"""RT14-04: apply a GKE workload's repository-root `k8s/*.yaml` after its OpenTofu apply, over REST only.

Before RT14-04 the deploy imported the Kubernetes MCP's `KubernetesService` in-process. That package is not in this
image (the build source is `mcp-servers/terraform` only) and the fallback import resolved to this server's own
`service` module, so the ImportError was swallowed as "non-fatal" and every GKE deploy reported SUCCESS with nothing
running on the cluster.

This module is the deploy's own applier. Invariant 7: no kubectl, no gcloud, no `kubernetes` package; plain HTTPS
with the deploy's child credentials:
  1. cluster endpoint and CA certificate: GKE REST `projects/<p>/locations/<l>/clusters/<n>` (GET);
  2. the k8s MCP's policy (`mcp-servers/kubernetes/helm.py` `document_policy`, kept equal by a parity test): a
     cluster-scoped kind (except a v1 Namespace declaration, K8S-NAMESPACE-PLATFORM below) or a protected namespace
     is refused before any cluster call; then each document's
     (apiVersion, kind) through the cluster's own API discovery: a kind the cluster does not serve (or serves
     ambiguously) is UNKNOWN_KIND, a cluster-scoped one CLUSTER_SCOPED_KIND;
  3. a server-side dry run of every document, then the real server-side apply per document (field manager
     `stackvend`, the k8s MCP's; no force: a field another manager owns is a conflict, reported).
Any refusal or failure raises ManifestApplyFailed (K8S_MANIFEST_APPLY_FAILED, stage `k8s_manifest_apply`) with the
per-document report; the deploy then ends FAILED. Owner (RT D2, 11-14): a manifest the cluster rejects as invalid on the
server dry run (typed answer HTTP 422 `Invalid` / 400 `BadRequest`) is the developer's defect (the generated k8s/*.yaml):
the result is IAC_DEFECT, which the workflow sends to the bounded developer repair. Every other failure (permission,
auth, cluster unreachable, policy, conflict, apply phase) stops for the operator (`operator_required`).
Secret values are never logged or reported (kind / name / namespace / HTTP status / the API's Status `reason` and its
`details.causes` field paths and cause reasons, never a cause message).

K8S-NAMESPACE-PLATFORM (ex04-1115c): the platform creates the namespaces the manifests name. Nothing else does, and the
cluster refuses a namespaced object in a namespace that does not exist (NamespaceLifecycle: 404 on the dry run). Exact
rules (typed checks only, never text matching):
  - which: the `metadata.namespace` of every accepted namespaced document, plus every Namespace declaration (a document
    with exactly `apiVersion: v1` and `kind: Namespace`). `default` implied by a document is never read or written (it
    always exists), so a workload that names no other namespace makes exactly the calls it made before;
  - a declaration may carry only `apiVersion`, `kind`, `metadata.name` (an RFC 1123 label, never a PROTECTED_NAMESPACES
    entry) and `metadata.labels` whose keys are in NAMESPACE_LABEL_ALLOW (exact keys) with valid label values (none on
    `default`, which is never read or written). Any other field, label or annotation, or two different declarations
    of one name, is refused before any cluster call (REFUSED_POLICY, codes NAMESPACE_*). When every violation is such
    a shape code (DEVELOPER_DECLARATION_CODES) the result is IAC_DEFECT (the bounded developer repair, as RT D2);
    a protected namespace stays the operator's. Every other cluster-scoped kind, and a Namespace of any other
    apiVersion, is refused exactly as before (CLUSTER_SCOPED_KINDS is unchanged: k8s MCP parity);
  - how: after the discovery policy, before the server dry run of the documents. Pass 1: GET every namespace;
    200 with `status.phase` Active = it exists and is never modified (EXISTS; a declaration's labels are then not
    applied: `labels_applied: false`); 200 with any other phase = NAMESPACE_UNREADABLE; 404 = a server dry run of a
    create-only POST (field manager `stackvend`) of exactly {name, the declaration's allowed labels, PLATFORM_LABELS},
    never for a name with a reserved `kube-` / `gke-` / `gmp-` prefix (NAMESPACE_RESERVED_PREFIX). Pass 2: the real creates (CREATED;
    a 409 AlreadyExists race is EXISTS; a transport error is re-read once). Any other answer stops typed
    (NAMESPACE_UNREADABLE / NAMESPACE_CREATE_FAILED, for the operator) and no document is applied. The report lists
    each namespace (`source: platform`) before the documents.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import tempfile
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import yaml

logger = logging.getLogger("mcp-terraform-server.k8s-apply")

K8S_MANIFEST_APPLY_FAILED = "K8S_MANIFEST_APPLY_FAILED"
K8S_MANIFEST_APPLY_STAGE = "k8s_manifest_apply"
FIELD_MANAGER = "stackvend"   # = mcp-servers/kubernetes/helm.py FIELD_MANAGER
REQUEST_TIMEOUT_S = 30
IAC_DEFECT = "IAC_DEFECT"   # = service.IAC_DEFECT_ERROR_CLASS = deploy_failure_router.IAC_DEFECT (parity test)
# RT D2 (owner 11-14): the server dry-run answers that mean "this manifest is invalid": (HTTP status, Status.reason).
# Typed fields of the API's Status object only, never its message text.
DEVELOPER_INVALID_ANSWERS = frozenset({(422, "Invalid"), (400, "BadRequest")})
MAX_DNS_SUBDOMAIN = 253
MANIFEST_DIR = "k8s"
MANIFEST_SUFFIXES = (".yaml", ".yml")

# Exact copies of mcp-servers/kubernetes/helm.py (parity: tests/test_rt14_tf_destructive_fake_success.py).
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

# K8S-NAMESPACE-PLATFORM (ex04-1115c): the namespaces the platform creates (module docstring).
NAMESPACE_KIND = "Namespace"
NAMESPACE_API_VERSION = "v1"
DEFAULT_NAMESPACE = "default"
NAMESPACE_DECLARATION_KEYS = frozenset({"apiVersion", "kind", "metadata"})
NAMESPACE_METADATA_KEYS = frozenset({"name", "labels"})
# The Kubernetes recommended labels (kubernetes.io "Recommended Labels"), exact keys. `app.kubernetes.io/managed-by` is
# the platform's own (PLATFORM_LABELS) and is not accepted from a manifest.
NAMESPACE_LABEL_ALLOW = frozenset({
    "app.kubernetes.io/name", "app.kubernetes.io/instance", "app.kubernetes.io/version",
    "app.kubernetes.io/component", "app.kubernetes.io/part-of",
})
PLATFORM_LABELS = (("app.kubernetes.io/managed-by", FIELD_MANAGER),)
MAX_LABEL_VALUE = 63
# Kubernetes reserves `kube-` for its system namespaces (kubernetes.io "Namespaces"); GKE uses `gke-` and Google
# Managed Prometheus `gmp-` for theirs (owner 11-16). The platform never creates a namespace with one of these
# prefixes (an existing one is used as before). RT F1.
RESERVED_NAMESPACE_PREFIXES = ("kube-", "gke-", "gmp-")
# RT F2: a declaration outside the exact shape is the generated manifest's defect, decided before any cluster call:
# when EVERY violation is one of these, the refusal goes to the bounded developer repair (like RT D2). A protected
# namespace, a cluster-scoped kind or an unknown kind stays the operator's.
DEVELOPER_DECLARATION_CODES = frozenset({"NAMESPACE_FIELD_NOT_ALLOWED", "NAMESPACE_LABEL_NOT_ALLOWED",
                                         "NAMESPACE_NAME_INVALID", "NAMESPACE_DECLARED_TWICE"})


class ManifestApplyFailed(Exception):
    """Typed failure of the post-apply manifest step (class K8S_MANIFEST_APPLY_FAILED, stage k8s_manifest_apply)."""

    def __init__(self, code: str, detail: str, resources: Optional[List[Dict[str, Any]]] = None,
                 violations: Optional[List[Dict[str, str]]] = None, *, http_status: Optional[int] = None,
                 api_reason: str = ""):
        super().__init__(f"{K8S_MANIFEST_APPLY_FAILED} ({code}): {detail}")
        self.code, self.detail = code, detail
        self.resources = list(resources or [])
        self.violations = list(violations or [])
        self.http_status, self.api_reason = http_status, api_reason

    @property
    def developer_owned(self) -> bool:
        """RT D2: the cluster rejected a document as invalid on the server dry run (nothing was applied)."""
        return (self.code == "FAILED_SERVER_DRY_RUN"
                and (self.http_status, self.api_reason) in DEVELOPER_INVALID_ANSWERS) or self.declaration_defect

    @property
    def declaration_defect(self) -> bool:
        """RT F2 (K8S-NAMESPACE-PLATFORM): refused before any cluster call, every violation a Namespace declaration
        outside the exact shape (DEVELOPER_DECLARATION_CODES)."""
        return self.code == "REFUSED_POLICY" and bool(self.violations) \
            and all(v.get("code") in DEVELOPER_DECLARATION_CODES for v in self.violations)

    def _created_namespaces_note(self) -> str:
        """K8S-NAMESPACE-PLATFORM: the namespaces the platform created before the failure ("" when none: unchanged)."""
        created = [r["name"] for r in self.resources if r.get("source") == "platform"
                   and r.get("kind") == NAMESPACE_KIND and r.get("status") == "CREATED"]
        return (f" The platform created the empty namespace(s) {', '.join(created)} first; they stay and are reused "
                "by the next deploy." if created else "")

    def result(self, cluster_name: str) -> Dict[str, Any]:
        if self.declaration_defect:
            refused = "; ".join(f"Namespace '{v.get('name', '')}': {v['code']}"
                                + (f" ({v['field']})" if v.get("field") else "") for v in self.violations)
            out: Dict[str, Any] = {
                "error_class": IAC_DEFECT,
                "code": K8S_MANIFEST_APPLY_FAILED,
                "stage": K8S_MANIFEST_APPLY_STAGE,
                "error": (f"{K8S_MANIFEST_APPLY_FAILED}: a Namespace manifest in k8s/*.yaml is outside the shape the "
                          f"platform creates ({refused}). A Namespace manifest may hold only apiVersion: v1, kind, "
                          "metadata.name and the labels " + ", ".join(sorted(NAMESPACE_LABEL_ALLOW)) + " (the platform "
                          "adds app.kubernetes.io/managed-by); remove anything else, or remove the manifest and keep "
                          "metadata.namespace on the objects (the platform creates that namespace). Nothing in k8s/ "
                          "was applied (the OpenTofu apply finished)."),
                "k8s_manifest_code": self.code,
                "operator_required": False,
            }
        elif self.developer_owned:
            out = {
                "error_class": IAC_DEFECT,
                "code": K8S_MANIFEST_APPLY_FAILED,
                "stage": K8S_MANIFEST_APPLY_STAGE,
                "error": (f"{K8S_MANIFEST_APPLY_FAILED}: GKE cluster '{cluster_name}' rejected a Kubernetes manifest "
                          f"(k8s/*.yaml) as invalid on its server-side dry run ({self.code}: {self.detail}). Nothing "
                          "in k8s/ was applied; correct that manifest in k8s/ (the OpenTofu apply finished)."
                          + self._created_namespaces_note()),
                "k8s_manifest_code": self.code,
                "operator_required": False,
            }
        else:
            out = {
                "error_class": K8S_MANIFEST_APPLY_FAILED,
                "stage": K8S_MANIFEST_APPLY_STAGE,
                "error": (f"{K8S_MANIFEST_APPLY_FAILED}: the Kubernetes manifests (k8s/*.yaml) were not applied to "
                          f"GKE cluster '{cluster_name}' ({self.code}: {self.detail}). The OpenTofu apply finished; "
                          "the workload runs nothing on the cluster until the manifests apply."
                          + self._created_namespaces_note()),
                "k8s_manifest_code": self.code,
                "operator_required": True,
            }
        if self.resources:
            out["k8s_resources"] = self.resources
        if self.violations:
            out["k8s_violations"] = self.violations
        return out


# --------------------------------------------------------------------------------------------------- typed checks
def is_rfc1123_label(value: Any, max_len: int = 63) -> bool:
    if not isinstance(value, str) or not value or len(value) > max_len or not value.isascii():
        return False
    if not all(ch.islower() or ch.isdigit() or ch == "-" for ch in value):
        return False
    return value[0].isalnum() and value[-1].isalnum()


def is_dns_subdomain(value: Any) -> bool:
    if not isinstance(value, str) or not value or len(value) > MAX_DNS_SUBDOMAIN:
        return False
    return all(is_rfc1123_label(label) for label in value.split("."))


def is_api_version(value: Any) -> bool:
    """RT14 RT F1: a Kubernetes apiVersion as it may appear in a request path: one RFC 1123 label (the core group,
    `v1`) or exactly `<group>/<version>` with a DNS-subdomain group and an RFC 1123 label version. Typed checks only:
    `..`, `?`, `#`, a third segment or a non-string can never reach the discovery GET or the apply URL."""
    if not isinstance(value, str):
        return False
    parts = value.split("/")
    if len(parts) == 1:
        return is_rfc1123_label(parts[0])
    return len(parts) == 2 and is_dns_subdomain(parts[0]) and is_rfc1123_label(parts[1])


def is_kind(value: Any) -> bool:
    """RT14 RT F1: a Kubernetes kind is a non-empty ASCII alphanumeric string (`Deployment`, `ConfigMap`)."""
    return isinstance(value, str) and bool(value) and len(value) <= MAX_DNS_SUBDOMAIN and value.isascii() \
        and value.isalnum()


def _flatten(docs: Sequence[Any]) -> List[Any]:
    out: List[Any] = []
    for doc in docs:
        if doc is None:
            continue
        if isinstance(doc, dict) and doc.get("kind") == "List" and isinstance(doc.get("items"), list):
            out.extend(_flatten(doc["items"]))
        else:
            out.append(doc)
    return out


def manifest_files(workspace_dir: str) -> List[str]:
    """The repository-root `k8s/*.yaml|yml` files of the workspace, sorted (the PWB-4 contract)."""
    k8s_dir = os.path.join(workspace_dir, MANIFEST_DIR)
    if not os.path.isdir(k8s_dir) or os.path.islink(k8s_dir):
        return []
    return [os.path.join(k8s_dir, f) for f in sorted(os.listdir(k8s_dir))
            if f.endswith(MANIFEST_SUFFIXES) and os.path.isfile(os.path.join(k8s_dir, f))
            and not os.path.islink(os.path.join(k8s_dir, f))]


def load_documents(paths: Sequence[str]) -> List[Dict[str, Any]]:
    """Every document of every file (`kind: List` expanded). Raises ManifestApplyFailed on unparsable YAML or a
    document without a valid apiVersion, kind and metadata.name (nothing is applied then)."""
    docs: List[Any] = []
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                docs.extend(yaml.safe_load_all(fh.read()))
        except (yaml.YAMLError, UnicodeDecodeError, OSError) as e:
            raise ManifestApplyFailed("MANIFEST_UNPARSABLE", f"{os.path.basename(path)}: {type(e).__name__}") from None
    flat = _flatten(docs)
    for doc in flat:
        meta = doc.get("metadata") if isinstance(doc, dict) else None
        if not isinstance(doc, dict) or not isinstance(meta, dict) or not is_api_version(doc.get("apiVersion")) \
                or not is_kind(doc.get("kind")) or not is_dns_subdomain(meta.get("name")):
            raise ManifestApplyFailed("MANIFEST_INVALID",
                                      "every document needs a valid apiVersion (`v1` or `<group>/<version>`), an "
                                      "alphanumeric kind and a valid metadata.name")
        ns = meta.get("namespace")
        if ns is not None and not is_rfc1123_label(ns):
            raise ManifestApplyFailed("MANIFEST_INVALID", "metadata.namespace must be an RFC 1123 label")
    return flat


KindScope = Callable[[str, str], Optional[Tuple[str, bool]]]


def document_policy(docs: Sequence[Dict[str, Any]], default_namespace: str,
                    scope: Optional[KindScope] = None) -> List[Dict[str, str]]:
    """helm.document_policy's rules: no cluster-scoped kind, no kind the cluster does not know, no protected
    namespace. `scope(api_version, kind)` -> (plural, namespaced) or None (unknown)."""
    violations = []
    for doc in docs:
        kind = str(doc.get("kind") or "")
        api_version = str(doc.get("apiVersion") or "")
        meta = doc.get("metadata") or {}
        ns = meta.get("namespace") or default_namespace
        entry = {"kind": kind, "name": str(meta.get("name") or ""), "namespace": str(ns)}
        if kind in CLUSTER_SCOPED_KINDS:
            violations.append(dict(entry, code="CLUSTER_SCOPED_KIND"))
            continue
        if scope is not None:
            found = scope(api_version, kind)
            if found is None:
                violations.append(dict(entry, code="UNKNOWN_KIND", api_version=api_version))
                continue
            if found[1] is False:
                violations.append(dict(entry, code="CLUSTER_SCOPED_KIND", api_version=api_version))
                continue
        if ns in PROTECTED_NAMESPACES:
            violations.append(dict(entry, code="PROTECTED_NAMESPACE"))
    return violations


# --------------------------------------------------------------------------- K8S-NAMESPACE-PLATFORM (ex04-1115c)
def is_namespace_declaration(doc: Any) -> bool:
    """Exactly `apiVersion: v1` + `kind: Namespace` (any other apiVersion keeps the CLUSTER_SCOPED_KIND refusal)."""
    return isinstance(doc, dict) and doc.get("kind") == NAMESPACE_KIND and doc.get("apiVersion") == NAMESPACE_API_VERSION


def is_label_value(value: Any) -> bool:
    """A Kubernetes label value: a string of at most 63 ASCII alphanumerics, `-`, `_`, `.`, starting and ending
    alphanumeric (or empty)."""
    if not isinstance(value, str) or len(value) > MAX_LABEL_VALUE or not value.isascii():
        return False
    if not value:
        return True
    return all(ch.isalnum() or ch in "-_." for ch in value) and value[0].isalnum() and value[-1].isalnum()


def namespace_declaration_violations(decls: Sequence[Dict[str, Any]]) -> List[Dict[str, str]]:
    """The declaration rule (module docstring); [] = every declaration is accepted."""
    violations: List[Dict[str, str]] = []
    seen: Dict[str, Tuple[Tuple[str, str], ...]] = {}
    for doc in decls:
        meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
        name = meta.get("name")
        entry = {"kind": NAMESPACE_KIND, "name": str(name or ""), "namespace": ""}
        found = []
        for key in sorted(set(doc) - NAMESPACE_DECLARATION_KEYS, key=str):   # RT F5: mixed-type keys stay typed
            found.append(dict(entry, code="NAMESPACE_FIELD_NOT_ALLOWED", field=str(key)[:80]))
        for key in sorted(set(meta) - NAMESPACE_METADATA_KEYS, key=str):
            found.append(dict(entry, code="NAMESPACE_FIELD_NOT_ALLOWED", field=f"metadata.{str(key)[:80]}"))
        if not is_rfc1123_label(name):
            found.append(dict(entry, code="NAMESPACE_NAME_INVALID"))
        elif name in PROTECTED_NAMESPACES:
            found.append(dict(entry, code="PROTECTED_NAMESPACE"))
        labels = meta.get("labels", {})
        if not isinstance(labels, dict):
            found.append(dict(entry, code="NAMESPACE_LABEL_NOT_ALLOWED", field="metadata.labels"))
            labels = {}
        elif labels and name == DEFAULT_NAMESPACE:   # RT F6: `default` always exists and is never modified
            found.append(dict(entry, code="NAMESPACE_LABEL_NOT_ALLOWED", field="metadata.labels"))
            labels = {}
        for key in sorted(labels, key=str):
            if key not in NAMESPACE_LABEL_ALLOW or not is_label_value(labels[key]):
                found.append(dict(entry, code="NAMESPACE_LABEL_NOT_ALLOWED", field=f"metadata.labels.{str(key)[:80]}"))
        if not found:
            pairs = tuple(sorted(labels.items()))
            if name in seen and seen[name] != pairs:
                found.append(dict(entry, code="NAMESPACE_DECLARED_TWICE"))
            seen.setdefault(name, pairs)
        violations.extend(found)
    return violations


def namespace_plan(decls: Sequence[Dict[str, Any]], docs: Sequence[Dict[str, Any]],
                   default_namespace: str) -> List[Tuple[str, Dict[str, str]]]:
    """(name, labels) of every namespace the platform ensures, sorted by name: each declaration (its accepted labels)
    and each namespaced document's namespace other than `default` (no labels of its own). Call only after
    namespace_declaration_violations and document_policy found nothing."""
    plan: Dict[str, Dict[str, str]] = {}
    for doc in decls:
        meta = doc["metadata"]
        if meta["name"] != DEFAULT_NAMESPACE:   # RT F6: a label-free `default` declaration is never read or written
            plan[meta["name"]] = dict(meta.get("labels") or {})
    for doc in docs:
        ns = doc["metadata"].get("namespace") or default_namespace
        if ns != DEFAULT_NAMESPACE:
            plan.setdefault(ns, {})
    return sorted(plan.items())


def namespace_body(name: str, labels: Dict[str, str]) -> Dict[str, Any]:
    """Exactly what the platform creates: the name, the declaration's accepted labels and the platform's own label."""
    merged = dict(labels)
    merged.update(PLATFORM_LABELS)
    return {"apiVersion": NAMESPACE_API_VERSION, "kind": NAMESPACE_KIND,
            "metadata": {"name": name, "labels": dict(sorted(merged.items()))}}


# --------------------------------------------------------------------------------------------------- REST transport
def cluster_access(google_session: Any, project_id: str, location: str, cluster_name: str) -> Tuple[str, str]:
    """(https endpoint, base64 CA certificate) of the cluster, from the GKE REST API (GET). Typed on any failure."""
    url = (f"https://container.googleapis.com/v1/projects/{project_id}/locations/{location}/clusters/"
           f"{cluster_name}")
    try:
        res = google_session.get(url, timeout=REQUEST_TIMEOUT_S)
    except Exception as e:  # noqa: BLE001 - typed below
        raise ManifestApplyFailed("CLUSTER_UNREADABLE", f"GKE cluster read failed ({type(e).__name__})") from None
    if res.status_code != 200:
        raise ManifestApplyFailed("CLUSTER_UNREADABLE", f"GKE cluster read answered HTTP {res.status_code}")
    body = res.json() or {}
    endpoint = body.get("endpoint")
    ca = (body.get("masterAuth") or {}).get("clusterCaCertificate")
    if not (isinstance(endpoint, str) and endpoint and isinstance(ca, str) and ca):
        raise ManifestApplyFailed("CLUSTER_UNREADABLE", "the GKE cluster has no endpoint or CA certificate yet")
    return f"https://{endpoint}", ca


MAX_CAUSES = 10
_CAUSE_FIELD_CAP, _CAUSE_REASON_CAP = 160, 60


def _status_of(res: Any) -> Tuple[str, List[Dict[str, str]]]:
    """(Status.reason, Status.details.causes as [{field, reason}]) of an API answer. RT F3: the causes say WHICH field
    failed (field path + typed cause reason, capped); their `message` is never read (it can quote a value)."""
    try:
        body = res.json()
    except Exception:  # noqa: BLE001 - a non-JSON answer has no reason
        return "", []
    if not isinstance(body, dict):
        return "", []
    details = body.get("details") if isinstance(body.get("details"), dict) else {}
    causes = details.get("causes") if isinstance(details.get("causes"), list) else []
    out = [{"field": str(c.get("field") or "")[:_CAUSE_FIELD_CAP],
            "reason": str(c.get("reason") or "")[:_CAUSE_REASON_CAP]}
           for c in causes if isinstance(c, dict) and (c.get("field") or c.get("reason"))]
    return str(body.get("reason") or "")[:80], out[:MAX_CAUSES]



class ClusterApi:
    """Discovery + server-side apply against one cluster (HTTPS, Bearer token, the cluster's CA)."""

    def __init__(self, endpoint: str, token: str, ca_file: str, http: Any):
        self.endpoint, self._http, self._ca = endpoint.rstrip("/"), http, ca_file
        self._headers = {"Authorization": f"Bearer {token}"}
        self._groups: Dict[str, Optional[List[Dict[str, Any]]]] = {}

    @staticmethod
    def _group_path(api_version: str) -> str:
        return f"/api/{api_version}" if "/" not in api_version else f"/apis/{api_version}"

    def _resources(self, api_version: str) -> Optional[List[Dict[str, Any]]]:
        if api_version not in self._groups:
            try:
                res = self._http.get(self.endpoint + self._group_path(api_version), headers=self._headers,
                                     verify=self._ca, timeout=REQUEST_TIMEOUT_S)
            except Exception as e:  # noqa: BLE001 - fail closed: nothing is applied
                raise ManifestApplyFailed("DISCOVERY_FAILED", f"{api_version}: {type(e).__name__}") from None
            if res.status_code == 404:
                self._groups[api_version] = None
            elif res.status_code != 200:
                raise ManifestApplyFailed("DISCOVERY_FAILED", f"{api_version}: HTTP {res.status_code}")
            else:
                items = (res.json() or {}).get("resources") or []
                self._groups[api_version] = [r for r in items if isinstance(r, dict)]
        return self._groups[api_version]

    def scope(self, api_version: str, kind: str) -> Optional[Tuple[str, bool]]:
        """(plural, namespaced) of a served kind (subresources excluded); None when unknown or ambiguous."""
        matches = [r for r in (self._resources(api_version) or [])
                   if r.get("kind") == kind and "/" not in str(r.get("name") or "")]
        if len(matches) != 1 or not isinstance(matches[0].get("namespaced"), bool) or not matches[0].get("name"):
            return None
        return str(matches[0]["name"]), matches[0]["namespaced"]

    def server_side_apply(self, doc: Dict[str, Any], namespace: str, plural: str, *,
                          dry_run: bool) -> Tuple[int, str, List[Dict[str, str]]]:
        name = doc["metadata"]["name"]
        url = f"{self.endpoint}{self._group_path(str(doc['apiVersion']))}/namespaces/{namespace}/{plural}/{name}"
        params = {"fieldManager": FIELD_MANAGER}
        if dry_run:
            params["dryRun"] = "All"
        try:
            res = self._http.patch(url, params=params, data=json.dumps(doc).encode("utf-8"),
                                   headers=dict(self._headers, **{"Content-Type": "application/apply-patch+yaml"}),
                                   verify=self._ca, timeout=REQUEST_TIMEOUT_S)
        except Exception as e:  # noqa: BLE001 - reported per document
            return 0, type(e).__name__, []
        if res.status_code in (200, 201):
            return res.status_code, "", []
        reason, causes = _status_of(res)
        return res.status_code, reason, causes

    def namespace_status(self, name: str) -> Tuple[int, str]:
        """K8S-NAMESPACE-PLATFORM: (HTTP status, `status.phase` of the body; "" when absent) of
        GET /api/v1/namespaces/<name>. Typed on a transport error."""
        try:
            res = self._http.get(f"{self.endpoint}/api/v1/namespaces/{name}", headers=self._headers,
                                 verify=self._ca, timeout=REQUEST_TIMEOUT_S)
        except Exception as e:  # noqa: BLE001 - fail closed: nothing is applied
            raise ManifestApplyFailed("NAMESPACE_UNREADABLE", f"namespace '{name}': {type(e).__name__}") from None
        phase = ""
        if res.status_code == 200:
            try:
                body = res.json()
            except Exception:  # noqa: BLE001 - no typed phase: refused by the caller
                body = None
            status = body.get("status") if isinstance(body, dict) else None
            phase = str(status.get("phase") or "")[:40] if isinstance(status, dict) else ""
        return res.status_code, phase

    def create_namespace(self, body: Dict[str, Any], *, dry_run: bool) -> Tuple[int, str, List[Dict[str, str]]]:
        """K8S-NAMESPACE-PLATFORM: a create-only POST /api/v1/namespaces (never a patch: an existing namespace is never
        modified)."""
        params = {"fieldManager": FIELD_MANAGER}
        if dry_run:
            params["dryRun"] = "All"
        try:
            res = self._http.post(f"{self.endpoint}/api/v1/namespaces", params=params,
                                  data=json.dumps(body).encode("utf-8"),
                                  headers=dict(self._headers, **{"Content-Type": "application/json"}),
                                  verify=self._ca, timeout=REQUEST_TIMEOUT_S)
        except Exception as e:  # noqa: BLE001 - typed by the caller
            return 0, type(e).__name__, []
        if res.status_code in (200, 201):
            return res.status_code, "", []
        reason, causes = _status_of(res)
        return res.status_code, reason, causes


def _namespace_ref(name: str, status: str, **extra: Any) -> Dict[str, Any]:
    return dict({"api_version": NAMESPACE_API_VERSION, "kind": NAMESPACE_KIND, "name": name, "namespace": "",
                 "status": status, "source": "platform"}, **extra)


def _existing_ref(name: str, labels: Dict[str, str]) -> Dict[str, Any]:
    """RT F7: an existing namespace is never modified, so a declaration's labels are not applied to it (said so)."""
    return _namespace_ref(name, "EXISTS", **({"labels_applied": False} if labels else {}))


def _create_error(code: int, reason: str, causes: List[Dict[str, str]]) -> str:
    where = "; ".join(f"{c['field'] or '?'}: {c['reason'] or '?'}" for c in causes)
    return (f"HTTP {code} {reason}".strip() if code else reason) + (f" ({where})" if where else "")


def ensure_namespaces(api: ClusterApi, plan: Sequence[Tuple[str, Dict[str, str]]]) -> List[Dict[str, Any]]:
    """K8S-NAMESPACE-PLATFORM: every planned namespace exists afterwards (EXISTS untouched / CREATED), in plan order.
    Pass 1 reads every namespace and dry-runs the create of each missing one; pass 2 (RT F8) creates them, so nothing
    is created unless every namespace passed pass 1. Raises ManifestApplyFailed (operator) with the namespaces handled
    so far on any other answer."""
    outcome: Dict[str, Dict[str, Any]] = {}
    missing: List[Tuple[str, Dict[str, Any], Dict[str, str]]] = []

    def failed(code: str, name: str, detail: str, error: str, **kw: Any) -> ManifestApplyFailed:
        done = [outcome[n] for n, _ in plan if n in outcome]
        return ManifestApplyFailed(code, f"namespace '{name}': {detail}",
                                   resources=done + [_namespace_ref(name, "FAILED", error=error)], **kw)

    for name, labels in plan:
        status, phase = api.namespace_status(name)
        if status == 200:
            if phase != "Active":   # RT F3: a Terminating (or phase-less) namespace refuses every new object
                raise failed("NAMESPACE_UNREADABLE", name, f"phase {phase or 'unknown'}, not Active",
                             f"phase {phase or 'unknown'}", http_status=status)
            outcome[name] = _existing_ref(name, labels)
            continue
        if status != 404:
            raise failed("NAMESPACE_UNREADABLE", name, f"HTTP {status}", f"HTTP {status}", http_status=status or None)
        prefix = next((p for p in RESERVED_NAMESPACE_PREFIXES if name.startswith(p)), None)
        if prefix is not None:   # RT F1 (+ owner 11-16): reserved for Kubernetes / GKE / Managed Prometheus
            raise failed("NAMESPACE_RESERVED_PREFIX", name, f"the `{prefix}` prefix is reserved for Kubernetes, GKE "
                         "or Google Managed Prometheus system namespaces; the platform does not create one",
                         "reserved prefix")
        body = namespace_body(name, labels)
        code, reason, causes = api.create_namespace(body, dry_run=True)
        if code == 409 and reason == "AlreadyExists":   # created since the GET: never modified
            outcome[name] = _existing_ref(name, labels)
            continue
        if code not in (200, 201):
            error = _create_error(code, reason, causes)
            raise failed("NAMESPACE_CREATE_FAILED", name, f"server dry run: {error}", error,
                         http_status=code or None, api_reason=reason if code else "")
        missing.append((name, body, labels))
    for name, body, labels in missing:
        code, reason, causes = api.create_namespace(body, dry_run=False)
        if code in (200, 201):
            outcome[name] = _namespace_ref(name, "CREATED")
            continue
        if code == 409 and reason == "AlreadyExists":
            outcome[name] = _existing_ref(name, labels)
            continue
        if code == 0:   # RT F9: a transport error on the create: the namespace may exist now; read it once
            status, phase = api.namespace_status(name)
            if status == 200 and phase == "Active":
                outcome[name] = _namespace_ref(name, "CREATED", create_answer_lost=True)
                continue
        error = _create_error(code, reason, causes)
        raise failed("NAMESPACE_CREATE_FAILED", name, f"create: {error}", error,
                     http_status=code or None, api_reason=reason if code else "")
    return [outcome[name] for name, _ in plan]


def _ref(doc: Dict[str, Any], ns: str) -> Dict[str, str]:
    return {"api_version": str(doc.get("apiVersion")), "kind": str(doc.get("kind")),
            "name": str((doc.get("metadata") or {}).get("name")), "namespace": ns}


def apply_documents(api: ClusterApi, docs: List[Dict[str, Any]], namespace: str,
                    declarations: Sequence[Dict[str, Any]] = ()) -> List[Dict[str, Any]]:
    """Discovery policy, the platform's namespaces (K8S-NAMESPACE-PLATFORM; `declarations` = the accepted Namespace
    documents, not in `docs`), server dry run of every document, then the real apply per document. Returns the report
    (the namespaces, then every document APPLIED); raises ManifestApplyFailed otherwise."""
    violations = document_policy(docs, namespace, api.scope)
    if violations:
        raise ManifestApplyFailed("REFUSED_POLICY", f"{len(violations)} document(s) refused by policy",
                                  violations=violations)
    planned = []
    for doc in docs:
        ns = doc["metadata"].get("namespace") or namespace
        body = json.loads(json.dumps(doc))
        body["metadata"]["namespace"] = ns
        planned.append((body, ns, api.scope(str(doc["apiVersion"]), str(doc["kind"]))[0]))
    namespaces = ensure_namespaces(api, namespace_plan(declarations, docs, namespace))
    try:
        return namespaces + _dry_run_then_apply(api, planned)
    except ManifestApplyFailed as err:
        err.resources = namespaces + err.resources
        raise


def _dry_run_then_apply(api: ClusterApi, planned: List[Tuple[Dict[str, Any], str, str]]) -> List[Dict[str, Any]]:
    for phase, dry in (("SERVER_DRY_RUN", True), ("APPLY", False)):
        resources: List[Dict[str, Any]] = []
        for i, (body, ns, plural) in enumerate(planned):
            status, reason, causes = api.server_side_apply(body, ns, plural, dry_run=dry)
            if status not in (200, 201):
                where = "; ".join(f"{c['field'] or '?'}: {c['reason'] or '?'}" for c in causes)
                error = (f"HTTP {status} {reason}".strip() if status else reason) + (f" ({where})" if where else "")
                resources.append(dict(_ref(body, ns), status="FAILED", error=error,
                                      **({"causes": causes} if causes else {})))
                resources += [dict(_ref(b, n), status="NOT_ATTEMPTED") for b, n, _ in planned[i + 1:]]
                code = "PARTIALLY_APPLIED" if (not dry and i) else f"FAILED_{phase}"
                raise ManifestApplyFailed(code, f"{resources[i]['kind']} '{resources[i]['name']}': "
                                                f"{resources[i]['error']}", resources=resources,
                                          http_status=status or None, api_reason=reason if status else "")
            resources.append(dict(_ref(body, ns), status="VALIDATED" if dry else "APPLIED"))
    return resources


def apply_workspace_manifests(workspace_dir: str, *, google_session: Any, token: str, project_id: str,
                              location: str, cluster_name: str, namespace: str = "default",
                              http: Any = None) -> Optional[Dict[str, Any]]:
    """Apply the workspace's `k8s/*.yaml` to the cluster. None when the workspace has no manifest document (nothing to
    do); else {"status": "APPLIED", "cluster_name", "resources"}. Raises ManifestApplyFailed on any refusal or
    failure. The cheap policy pre-check runs before any cluster call."""
    docs = load_documents(manifest_files(workspace_dir))
    if not docs:
        return None
    if not is_rfc1123_label(namespace) or namespace in PROTECTED_NAMESPACES:
        raise ManifestApplyFailed("NAMESPACE_INVALID", f"namespace {namespace!r}")
    if not (is_rfc1123_label(cluster_name, 40) and is_rfc1123_label(location) and is_rfc1123_label(project_id, 30)):
        raise ManifestApplyFailed("INVALID_CLUSTER", "cluster name, location or project id is not a valid label")
    # K8S-NAMESPACE-PLATFORM: a v1 Namespace document is a declaration (its own exact rule), never applied as written
    declarations = [d for d in docs if is_namespace_declaration(d)]
    docs = [d for d in docs if not is_namespace_declaration(d)]
    pre = document_policy(docs, namespace) + namespace_declaration_violations(declarations)
    if pre:
        raise ManifestApplyFailed("REFUSED_POLICY", f"{len(pre)} document(s) refused by policy", violations=pre)
    endpoint, ca_b64 = cluster_access(google_session, project_id, location, cluster_name)
    if http is None:
        import requests
        http = requests.Session()
    with tempfile.TemporaryDirectory(prefix="rt14-k8s-") as tmp:
        ca_path = os.path.join(tmp, "ca.crt")
        try:
            ca_bytes = base64.b64decode(ca_b64, validate=True)
        except Exception:  # noqa: BLE001 - typed
            raise ManifestApplyFailed("CLUSTER_UNREADABLE", "the cluster CA certificate is not base64") from None
        with open(ca_path, "wb") as fh:
            fh.write(ca_bytes)
        resources = apply_documents(ClusterApi(endpoint, token, ca_path, http), docs, namespace, declarations)
    logger.info(f"Kubernetes manifests applied to '{cluster_name}': "
                + ", ".join(f"{r['kind']}/{r['name']}" + ("" if r["status"] == "APPLIED" else f" ({r['status']})")
                            for r in resources))
    return {"status": "APPLIED", "cluster_name": cluster_name, "resources": resources}
