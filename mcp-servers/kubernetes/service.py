"""
StackVend Kubernetes MCP Tool Server - Service Engine.

GKE cluster discovery (Workload Identity), manifest apply, container logs, events and day-2 deployment operations
in a managed workload's own cluster.

FD-4L / FD27-10 (lane 14 plan §3.2): every tool takes `product_id`; the project comes only from the workload ledger
(`HelmService.resolve_target`: the same ledger + GKE lookup the Helm tools use; a request `project_id` must equal
it exactly). `k8s_apply_manifest` parses every document first and runs the SAME per-document policy as Helm
(`helm.document_policy` with the cluster's API discovery, `helm.DiscoveryKindScope`): cluster-scoped kinds
(CLUSTER_SCOPED_KIND), kinds the cluster does not serve (UNKNOWN_KIND) and protected namespaces
(PROTECTED_NAMESPACE, by each document's own `metadata.namespace`) refuse the whole request before anything is
applied. Accepted documents are applied with server-side apply (field manager `stackvend`): a server dry run of
every document first, then the real apply, each reported APPLIED / FAILED. Restart and scale check the namespace
too, and write their `kubernetes_ops` record before the API call (RT F5; audit failure refuses). Secret values are
never logged or audited (kind / name / namespace only). Apply results are recorded after the apply (best effort).
"""

import base64
import contextlib
import copy
import logging
import os
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

import google.auth
import google.auth.transport.requests
from google.cloud import container_v1
from google.cloud import firestore

from helm import (
    PROTECTED_NAMESPACES,
    ClusterAccess,
    HelmRefused,
    HelmService,
    document_policy,
    is_rfc1123_label,
    parse_documents,
)
from managed_target_seam import guard_database_name

logger = logging.getLogger("mcp-kubernetes-server")
logging.basicConfig(level=logging.INFO)

DEPLOYMENT_AUDIT_COLLECTION = "kubernetes_deployments"
OPS_AUDIT_COLLECTION = "kubernetes_ops"  # RT F5: restart / scale, audit-first (the gcloud L14-o standard)
MAX_REPLICAS_ENV = "K8S_MCP_MAX_REPLICAS"
DEFAULT_MAX_REPLICAS = 100
MAX_TAIL_LINES = 5000
MAX_DNS_SUBDOMAIN = 253


def is_dns_subdomain(value: Any) -> bool:
    """Kubernetes object name (RFC 1123 subdomain): dot-separated RFC 1123 labels, at most 253 characters."""
    if not isinstance(value, str) or not value or len(value) > MAX_DNS_SUBDOMAIN:
        return False
    return all(is_rfc1123_label(label) for label in value.split("."))


def _flatten(docs: List[Any]) -> List[Any]:
    """`kind: List` documents expand to their items (the same rule document_policy applies)."""
    out: List[Any] = []
    for doc in docs:
        if doc is None:
            continue
        if isinstance(doc, dict) and doc.get("kind") == "List" and isinstance(doc.get("items"), list):
            out.extend(_flatten(doc["items"]))
        else:
            out.append(doc)
    return out


def _doc_ref(doc: Dict[str, Any], namespace: str) -> Dict[str, str]:
    meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    return {"api_version": str(doc.get("apiVersion") or ""), "kind": str(doc.get("kind") or ""),
            "name": str(meta.get("name") or ""), "namespace": namespace}


class KubernetesService:
    def __init__(
        self,
        default_project_id: Optional[str] = None,
        default_region: Optional[str] = None,
        firestore_client: Optional[Any] = None,
        helm_service: Optional[HelmService] = None,
        env: Optional[Dict[str, str]] = None,
    ):
        # PROJECT_ID is the host project: used only for the Firestore ledger client, never as a target.
        self.default_project_id = default_project_id or os.getenv("PROJECT_ID", "")
        self.default_region = default_region or os.getenv("REGION", "")
        self._env = os.environ if env is None else env

        if firestore_client:
            self.db = firestore_client
        else:
            try:
                self.db = firestore.Client(project=self.default_project_id) if self.default_project_id else None
            except Exception as e:
                logger.warning(f"Could not initialize Firestore client for Kubernetes MCP server: {e}")
                self.db = None

        # Lane 14 PR-8: Helm lifecycle (helm.py). Approvals are read from the guard database (lane 18 S0b) when
        # STACKVEND_GUARD_FIRESTORE_DATABASE is set, else from the default database.
        self._guard_db = None
        self.helm = helm_service or HelmService(
            db_factory=lambda: self.db,
            guard_db_factory=self._guard_db_client,
            cluster_access=self._helm_cluster_access,
        )

    def _guard_db_client(self):
        name = guard_database_name()
        if not name:
            return self.db
        if self._guard_db is None:
            self._guard_db = firestore.Client(project=self.default_project_id or None, database=name)
        return self._guard_db

    def _helm_cluster_access(self, project_id: str, cluster_name: str, location: str):
        """(ClusterAccess, cluster facts) for every tool, from one GKE lookup (it also proves the cluster exists in
        that project)."""
        info = self._get_cluster_credentials(project_id, cluster_name, location)
        facts = {k: info.get(k) for k in ("endpoint", "status", "current_node_count", "current_master_version")}
        facts["location"] = info.get("location") or location
        return ClusterAccess(endpoint=info["endpoint"], token=info["token"], ca_cert_b64=info["ca_cert"]), facts

    def _get_cluster_credentials(self, project_id: str, cluster_name: str, location: str) -> Dict[str, Any]:
        """GKE cluster endpoint, CA certificate and a short-lived access token (Workload Identity)."""
        credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
        auth_req = google.auth.transport.requests.Request()
        credentials.refresh(auth_req)

        cluster_client = container_v1.ClusterManagerClient(credentials=credentials)
        cluster_path = f"projects/{project_id}/locations/{location}/clusters/{cluster_name}"
        logger.info(f"Fetching cluster metadata for '{cluster_path}'")
        cluster = cluster_client.get_cluster(name=cluster_path)

        return {
            "endpoint": f"https://{cluster.endpoint}",
            "ca_cert": cluster.master_auth.cluster_ca_certificate,
            "token": credentials.token,
            "status": cluster.status.name if hasattr(cluster.status, "name") else str(cluster.status),
            "current_node_count": cluster.current_node_count,
            "current_master_version": cluster.current_master_version,
            "location": getattr(cluster, "location", None) or location,
        }

    @contextlib.contextmanager
    def _api_client(self, access: ClusterAccess) -> Iterator[Any]:
        """kubernetes.client.ApiClient for the target cluster; the CA file lives in a private temp dir that is
        removed afterwards (FD27-23b: no leaked CA temp files)."""
        from kubernetes import client

        with tempfile.TemporaryDirectory(prefix="k8s-mcp-") as tmp:
            ca_path = os.path.join(tmp, "ca.crt")
            with open(ca_path, "wb") as fh:
                fh.write(base64.b64decode(access.ca_cert_b64))
            configuration = client.Configuration()
            configuration.host = access.endpoint
            configuration.api_key = {"authorization": f"Bearer {access.token}"}
            configuration.ssl_ca_cert = ca_path
            api_client = client.ApiClient(configuration)
            try:
                yield api_client
            finally:
                close = getattr(api_client, "close", None)
                if callable(close):
                    close()

    # ------------------------------------------------------------------ typed checks
    @staticmethod
    def _namespace(namespace: Any, *, mutating: bool) -> str:
        if not is_rfc1123_label(namespace):
            raise HelmRefused("NAMESPACE_INVALID", "namespace must be an RFC 1123 label")
        if mutating and namespace in PROTECTED_NAMESPACES:
            raise HelmRefused("PROTECTED_NAMESPACE", namespace, 403)
        return namespace

    @staticmethod
    def _object_name(value: Any, what: str) -> str:
        if not is_dns_subdomain(value):
            raise HelmRefused(f"{what.upper()}_INVALID", f"{what} must be a Kubernetes object name")
        return value

    def _max_replicas(self) -> int:
        raw = (self._env.get(MAX_REPLICAS_ENV) or "").strip()
        return int(raw) if raw.isdigit() and int(raw) > 0 else DEFAULT_MAX_REPLICAS  # RT F6: 0 is not a bound

    def _audit(self, record: Dict[str, Any]) -> None:
        try:
            if self.db is None:
                raise RuntimeError("no Firestore client")
            self.db.collection(DEPLOYMENT_AUDIT_COLLECTION).document(record["deployment_id"]).set(record)
        except Exception as e:
            logger.warning(f"Could not record k8s deployment audit: {type(e).__name__}")
            record["audit_error"] = True

    # ------------------------------------------------------------------ apply
    def apply_manifest(
        self,
        product_id: str,
        cluster_name: str,
        location: str,
        namespace: str,
        yaml_content: str,
        dry_run: bool = False,
        project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Policy-checked server-side apply of a multi-document manifest (module docstring)."""
        self._namespace(namespace, mutating=True)
        if not isinstance(yaml_content, str) or not yaml_content.strip():
            raise HelmRefused("MANIFEST_EMPTY", "yaml_content is required")
        try:
            raw_docs = parse_documents(yaml_content)
        except HelmRefused as e:
            raise HelmRefused("MANIFEST_UNPARSABLE", e.detail) from e
        docs = _flatten(raw_docs)
        if not docs:
            raise HelmRefused("MANIFEST_EMPTY", "no documents")
        for doc in docs:
            meta = doc.get("metadata") if isinstance(doc, dict) else None
            if not isinstance(doc, dict) or not isinstance(meta, dict) or not doc.get("apiVersion") \
                    or not doc.get("kind") or not is_dns_subdomain(meta.get("name")):
                raise HelmRefused("MANIFEST_INVALID", "every document needs apiVersion, kind and a valid metadata.name")
            doc_ns = meta.get("namespace")
            if doc_ns is not None and not is_rfc1123_label(doc_ns):
                raise HelmRefused("MANIFEST_INVALID", "metadata.namespace must be an RFC 1123 label")

        # 1. cheap pre-check (exact cluster-scoped kinds + protected namespaces): refused before any cluster call
        pre = document_policy(docs, namespace)
        if pre:
            return {"status": "REFUSED:POLICY", "stage": "precheck", "violations": pre, "http_status": 403}

        target, access, _ = self.helm.resolve_target(product_id, project_id, cluster_name, location)
        audit = {"deployment_id": f"k8s-dep-{uuid.uuid4().hex[:12]}", "product_id": product_id,
                 "project_id": target.project_id, "cluster_name": cluster_name, "request_namespace": namespace,
                 "dry_run": bool(dry_run), "started_at": datetime.now(timezone.utc).isoformat()}
        with self.helm.kind_scope(access) as scope:
            # 2. authoritative: every document's kind through the cluster's API discovery (the Helm policy)
            violations = document_policy(docs, namespace, scope)
            if violations:
                audit.update(status="REFUSED:POLICY", stage="discovery", violations=violations)
                self._audit(audit)
                return dict(audit, http_status=403)

            planned = []
            for doc in docs:
                ns = doc["metadata"].get("namespace") or namespace
                body = copy.deepcopy(doc)
                body["metadata"]["namespace"] = ns
                planned.append((body, ns))

            # 3. server dry run of every document before anything is applied
            resources: List[Dict[str, Any]] = []
            for i, (body, ns) in enumerate(planned):
                ref = _doc_ref(body, ns)
                try:
                    scope.server_side_apply(body, ns, dry_run=True)
                except Exception as e:
                    resources.append(dict(ref, status="FAILED", error=f"{type(e).__name__}: {getattr(e, 'reason', '')}"[:300]))
                    resources += [dict(_doc_ref(b, n), status="NOT_ATTEMPTED") for b, n in planned[i + 1:]]
                    audit.update(status="FAILED:SERVER_DRY_RUN", resources=resources)
                    self._audit(audit)
                    return dict(audit, http_status=422)
                resources.append(dict(ref, status="VALIDATED"))
            if dry_run:
                audit.update(status="DRY_RUN_PASSED", resources=resources, resources_count=len(resources))
                self._audit(audit)
                return dict(audit, http_status=200)

            # 4. the real server-side apply, per document
            resources = []
            for i, (body, ns) in enumerate(planned):
                ref = _doc_ref(body, ns)
                logger.info(f"Server-side applying {ref['kind']} '{ref['name']}' in namespace '{ns}'")
                try:
                    scope.server_side_apply(body, ns, dry_run=False)
                except Exception as e:
                    resources.append(dict(ref, status="FAILED", error=f"{type(e).__name__}: {getattr(e, 'reason', '')}"[:300]))
                    resources += [dict(_doc_ref(b, n), status="NOT_ATTEMPTED") for b, n in planned[i + 1:]]
                    audit.update(status="PARTIALLY_APPLIED" if i else "FAILED:APPLY", resources=resources)
                    self._audit(audit)
                    return dict(audit, http_status=502)
                resources.append(dict(ref, status="APPLIED"))
        audit.update(status="APPLIED", resources=resources, resources_count=len(resources))
        self._audit(audit)
        return dict(audit, http_status=200)

    # ------------------------------------------------------------------ read-only tools
    def get_cluster_status(self, product_id: str, cluster_name: str, location: str,
                           project_id: Optional[str] = None) -> Dict[str, Any]:
        """GKE cluster health, version, nodes and namespaces (one credentials lookup)."""
        from kubernetes import client

        target, access, facts = self.helm.resolve_target(product_id, project_id, cluster_name, location)
        with self._api_client(access) as api_client:
            core_v1 = client.CoreV1Api(api_client)
            nodes = core_v1.list_node()
            namespaces = core_v1.list_namespace()

        node_list = []
        for n in nodes.items:
            node_list.append({
                "name": n.metadata.name,
                "status": "READY" if any(c.type == "Ready" and c.status == "True" for c in n.status.conditions) else "NOT_READY",
                "kubelet_version": n.status.node_info.kubelet_version,
                "os_image": n.status.node_info.os_image,
                "cpu_capacity": n.status.capacity.get("cpu"),
                "memory_capacity": n.status.capacity.get("memory"),
            })

        return {
            "product_id": product_id,
            "project_id": target.project_id,
            "cluster_name": cluster_name,
            "location": facts.get("location") or location,
            "endpoint": facts.get("endpoint"),
            "status": facts.get("status"),
            "master_version": facts.get("current_master_version"),
            "total_nodes": len(node_list),
            "nodes": node_list,
            "namespaces": [ns.metadata.name for ns in namespaces.items],
            "http_status": 200,
        }

    def list_workload_resources(self, product_id: str, cluster_name: str, location: str, namespace: str,
                                project_id: Optional[str] = None) -> Dict[str, Any]:
        """Deployments, Pods, Services and the Ingress count in a namespace."""
        from kubernetes import client

        self._namespace(namespace, mutating=False)
        _, access, _ = self.helm.resolve_target(product_id, project_id, cluster_name, location)
        with self._api_client(access) as api_client:
            core_v1 = client.CoreV1Api(api_client)
            apps_v1 = client.AppsV1Api(api_client)
            networking_v1 = client.NetworkingV1Api(api_client)
            deployments = apps_v1.list_namespaced_deployment(namespace=namespace)
            pods = core_v1.list_namespaced_pod(namespace=namespace)
            services = core_v1.list_namespaced_service(namespace=namespace)
            ingresses = networking_v1.list_namespaced_ingress(namespace=namespace)

        pod_items = []
        for p in pods.items:
            restart_count = sum(cs.restart_count for cs in (p.status.container_statuses or []))
            pod_items.append({
                "name": p.metadata.name,
                "phase": p.status.phase,
                "ip": p.status.pod_ip,
                "node": p.spec.node_name,
                "restarts": restart_count,
                "created_at": p.metadata.creation_timestamp.isoformat() if p.metadata.creation_timestamp else None,
            })
        dep_items = [{
            "name": d.metadata.name,
            "replicas_desired": d.spec.replicas,
            "replicas_ready": d.status.ready_replicas or 0,
            "replicas_updated": d.status.updated_replicas or 0,
        } for d in deployments.items]
        svc_items = [{
            "name": s.metadata.name,
            "type": s.spec.type,
            "cluster_ip": s.spec.cluster_ip,
            "ports": [{"port": port.port, "target_port": port.target_port, "protocol": port.protocol} for port in s.spec.ports or []],
        } for s in services.items]

        return {
            "namespace": namespace,
            "deployments": dep_items,
            "pods": pod_items,
            "services": svc_items,
            "ingresses_count": len(ingresses.items),
            "http_status": 200,
        }

    def fetch_pod_logs(
        self,
        product_id: str,
        cluster_name: str,
        location: str,
        namespace: str,
        pod_name: str,
        container: Optional[str] = None,
        previous: bool = False,
        tail_lines: int = 100,
        project_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Container logs of a Pod (previous=True: the previously crashed instance)."""
        from kubernetes import client

        self._namespace(namespace, mutating=False)
        self._object_name(pod_name, "pod_name")
        if container is not None and not is_rfc1123_label(container):
            raise HelmRefused("CONTAINER_INVALID", "container must be an RFC 1123 label")
        if isinstance(tail_lines, bool) or not isinstance(tail_lines, int) or not 1 <= tail_lines <= MAX_TAIL_LINES:
            raise HelmRefused("TAIL_LINES_INVALID", f"tail_lines must be an integer in 1..{MAX_TAIL_LINES}")
        _, access, _ = self.helm.resolve_target(product_id, project_id, cluster_name, location)
        with self._api_client(access) as api_client:
            core_v1 = client.CoreV1Api(api_client)
            try:
                logs = core_v1.read_namespaced_pod_log(
                    name=pod_name, namespace=namespace, container=container, previous=bool(previous),
                    tail_lines=tail_lines)
            except client.exceptions.ApiException as e:
                raise HelmRefused("K8S_API_ERROR", f"read_namespaced_pod_log: HTTP {getattr(e, 'status', '?')}",
                                  404 if getattr(e, "status", None) == 404 else 502) from e
        return {
            "pod_name": pod_name,
            "namespace": namespace,
            "container": container or "default",
            "previous_instance": bool(previous),
            "logs": logs,
            "http_status": 200,
        }

    def get_cluster_events(self, product_id: str, cluster_name: str, location: str, namespace: str,
                           project_id: Optional[str] = None) -> Dict[str, Any]:
        """Recent events in the namespace."""
        from kubernetes import client

        self._namespace(namespace, mutating=False)
        _, access, _ = self.helm.resolve_target(product_id, project_id, cluster_name, location)
        with self._api_client(access) as api_client:
            events = client.CoreV1Api(api_client).list_namespaced_event(namespace=namespace)
        results = [{
            "type": ev.type,
            "reason": ev.reason,
            "message": ev.message,
            "involved_object": f"{ev.involved_object.kind}/{ev.involved_object.name}",
            "count": ev.count,
            "last_timestamp": ev.last_timestamp.isoformat() if ev.last_timestamp else None,
        } for ev in events.items]
        return {"namespace": namespace, "events": results, "http_status": 200}

    # ------------------------------------------------------------------ day-2 operations
    def _audit_first(self, *, op: str, target: Any, cluster_name: str, namespace: str, deployment: str,
                     after: Dict[str, Any]) -> Dict[str, Any]:
        """RT F5: the op record is written BEFORE the Kubernetes call; if it cannot be written the op is refused."""
        record = {"op_id": f"k8s-op-{uuid.uuid4().hex[:16]}", "op": op, "product_id": target.product_id,
                  "project_id": target.project_id, "cluster_name": cluster_name, "namespace": namespace,
                  "deployment": deployment, "after": after, "status": "PENDING",
                  "requested_at": datetime.now(timezone.utc).isoformat()}
        try:
            if self.db is None:
                raise RuntimeError("no Firestore client")
            self.db.collection(OPS_AUDIT_COLLECTION).document(record["op_id"]).set(record)
        except Exception as e:
            raise HelmRefused("AUDIT_UNAVAILABLE", f"audit entry not written ({type(e).__name__}); op refused",
                              503) from e
        return record

    def _audit_finish(self, record: Dict[str, Any], status: str) -> bool:
        try:
            self.db.collection(OPS_AUDIT_COLLECTION).document(record["op_id"]).set(
                {"status": status, "finished_at": datetime.now(timezone.utc).isoformat()}, merge=True)
            return True
        except Exception:
            return False

    def _patch_deployment(self, access: ClusterAccess, record: Dict[str, Any], name: str, namespace: str,
                          body: Dict[str, Any]) -> bool:
        from kubernetes import client

        try:
            with self._api_client(access) as api_client:
                client.AppsV1Api(api_client).patch_namespaced_deployment(name=name, namespace=namespace, body=body)
        except Exception as e:
            self._audit_finish(record, f"FAILED:{type(e).__name__}")
            raise
        return self._audit_finish(record, "SUBMITTED")

    def restart_deployment(self, product_id: str, cluster_name: str, location: str, namespace: str,
                           deployment_name: str, project_id: Optional[str] = None) -> Dict[str, Any]:
        """Zero-downtime rolling restart by patching the pod template annotation (audit-first, RT F5)."""
        self._namespace(namespace, mutating=True)
        self._object_name(deployment_name, "deployment_name")
        target, access, _ = self.helm.resolve_target(product_id, project_id, cluster_name, location)
        now_iso = datetime.now(timezone.utc).isoformat()
        record = self._audit_first(op="restart_deployment", target=target, cluster_name=cluster_name,
                                   namespace=namespace, deployment=deployment_name, after={"restartedAt": now_iso})
        patch_body = {"spec": {"template": {"metadata": {"annotations": {"kubectl.kubernetes.io/restartedAt": now_iso}}}}}
        finished = self._patch_deployment(access, record, deployment_name, namespace, patch_body)
        logger.info(f"Triggered rolling restart for deployment '{deployment_name}' in '{namespace}'")
        return {
            "status": "RESTART_TRIGGERED",
            "deployment": deployment_name,
            "namespace": namespace,
            "restarted_at": now_iso,
            "op_id": record["op_id"],
            "audit_finalized": finished,
            "http_status": 200,
        }

    def scale_deployment(self, product_id: str, cluster_name: str, location: str, namespace: str,
                         deployment_name: str, replicas: int, project_id: Optional[str] = None) -> Dict[str, Any]:
        """Sets a deployment's replica count (0..K8S_MCP_MAX_REPLICAS; audit-first, RT F5)."""
        self._namespace(namespace, mutating=True)
        self._object_name(deployment_name, "deployment_name")
        bound = self._max_replicas()
        if isinstance(replicas, bool) or not isinstance(replicas, int) or not 0 <= replicas <= bound:
            raise HelmRefused("REPLICAS_INVALID", f"replicas must be an integer in 0..{bound}")
        target, access, _ = self.helm.resolve_target(product_id, project_id, cluster_name, location)
        record = self._audit_first(op="scale_deployment", target=target, cluster_name=cluster_name,
                                   namespace=namespace, deployment=deployment_name, after={"replicas": replicas})
        finished = self._patch_deployment(access, record, deployment_name, namespace, {"spec": {"replicas": replicas}})
        logger.info(f"Scaled deployment '{deployment_name}' in '{namespace}' to {replicas} replicas")
        return {
            "status": "SCALED",
            "deployment": deployment_name,
            "namespace": namespace,
            "replicas": replicas,
            "op_id": record["op_id"],
            "audit_finalized": finished,
            "http_status": 200,
        }
