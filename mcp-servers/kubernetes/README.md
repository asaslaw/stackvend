# StackVend: Kubernetes MCP Tool Server

> **Container Orchestration & GKE Lifecycle Model Context Protocol (MCP) Server**

The `mcp-kubernetes-server` connects StackVend's agents to the Google Kubernetes Engine (GKE) cluster of a managed workload. Every tool takes `product_id`: the target project comes only from the workload ledger (`workloads/{product_id}.project_id`, never the host project); an optional `project_id` must equal it exactly (FD-4L / FD27-10).

---

## 🚀 Capabilities

* **Dynamic Multi-Cluster Authentication**: Uses Google Cloud Workload Identity (`google.auth.default`) and `google.cloud.container_v1.ClusterManagerClient` to dynamically connect to GKE clusters in child projects without static kubeconfig keys.
* **Manifest Apply (server-side apply)**: `k8s_apply_manifest` parses every document first and runs the same per-document policy as Helm: each document's own `metadata.namespace` (else the request namespace) and each kind resolved through the cluster's API discovery. Cluster-scoped kinds (`CLUSTER_SCOPED_KIND`), kinds the cluster does not serve (`UNKNOWN_KIND`) and protected namespaces (`PROTECTED_NAMESPACE`) refuse the whole request (`REFUSED:POLICY`, HTTP 403) before anything is applied. Accepted documents (any namespaced kind the cluster serves, Secrets included) are server-side applied with field manager `stackvend`: a server dry run of every document first (`dry_run=true` stops there: `DRY_RUN_PASSED`), then the real apply, reported per document `APPLIED` / `FAILED` / `NOT_ATTEMPTED`. The audit (`kubernetes_deployments`) records real namespaces and never Secret values.
* **Helm Package Lifecycle** (lane 14 PR-8): real Helm CLI (pinned version + SHA-256 in `helm-pin.json`, baked into `bin/helm` by the Cloud Build step / `deploy-services.sh`; without it every Helm tool answers `HELM_UNAVAILABLE` and `/health` shows `helm_status`). Targets come from the workload ledger (`product_id`). Install/upgrade renders with `helm template` (pre-check), then `helm upgrade --install --skip-crds --dry-run=server -o json`; policy runs on the release manifest **and every hook**: each document's kind is resolved through the cluster's API discovery, and cluster-scoped kinds (`CLUSTER_SCOPED_KIND`), kinds the cluster does not serve (`UNKNOWN_KIND`) and protected namespaces are refused; the real install is `--skip-crds --atomic --wait`; if the installed manifest+hooks digest differs from the dry-run digest (e.g. charts that render random values or generated certificates), the same policy re-runs on what was actually installed: clean -> `INSTALLED` with `render_drift: true` (both digests audited); a violation -> `HELM_POST_INSTALL_DRIFT` (rollback for revision > 1 only to a revision that passes the policy, otherwise an uninstall approval request; an uninstall approval request for a first install; never an automatic uninstall). `helm_rollback` runs the same policy on the target revision first. Charts: `oci://<cluster region>-docker.pkg.dev/<the workload's project>/...` or the region's AR multi-region host (`us-`/`europe-`/`asia-docker.pkg.dev`) always, pulled with the server SA's token for that one host (needs `roles/artifactregistry.reader` on the workload project); other repositories only by exact URL in `HELM_CHART_REPOSITORY_ALLOWLIST` (empty by default). Needs Helm v3.13 or later (TF validation and `deploy-services.sh` both refuse an older pin). In bulk mode `deploy-services.sh` stages Helm first, so a download or SHA-256 failure stops every service deploy (fail closed). Values are passed as a JSON file, never `--set`. `helm_uninstall` needs an approved `HELM_UNINSTALL` operator record bound to the exact cluster, location, namespace and release: called without `approval_id` it records a platform-action card (`approval_requests`, `MCP_ACTION`) and answers `REFUSED:APPROVAL_REQUIRED` with `approval_request_id` (the drift paths above record the same card). An administrator approves the card in the Control Center (**Approvals**), which mints a 15-minute single-use approval; the server checks it in the guard database (`STACKVEND_GUARD_FIRESTORE_DATABASE`) and consumes it through project vending (`POST /approvals/{id}/consume`, URL from `VENDING_SERVICE_URL` or the Cloud Run metadata) before uninstalling; vending unreachable → `REFUSED:APPROVAL_CONSUME_UNAVAILABLE` (503), nothing uninstalled.
* **SRE Incident Forensics**: Retrieves stdout/stderr logs from running and crashed containers (`previous=True`) and warning events (`CrashLoopBackOff`, `OOMKilled`) for automated Root Cause Analysis.
* **Day-2 Runtime Operations**: zero-downtime rolling restarts (`restart_deployment`) and replica scaling (`scale_deployment`, 0..`K8S_MCP_MAX_REPLICAS`, default 100); protected namespaces are refused.

---

## 🛠️ MCP Tool Definitions (JSON-RPC 2.0)

| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| `k8s_apply_manifest` | `product_id`, `cluster_name`, `location`, `namespace`, `yaml_content`, `dry_run` | Policy-checked server-side apply (see above). REST `POST /apply`. |
| `k8s_get_cluster_status` | `product_id`, `cluster_name`, `location` | Master version, endpoint, nodes, namespaces. `POST /status`. |
| `k8s_list_resources` | `product_id`, `cluster_name`, `location`, `namespace` | Deployments, Pods, Services, Ingress count. `POST /resources`. |
| `k8s_fetch_pod_logs` | `product_id`, `cluster_name`, `location`, `namespace`, `pod_name`, `container`, `previous`, `tail_lines` | Container logs (incl. the crashed instance). `POST /logs`. |
| `k8s_get_events` | `product_id`, `cluster_name`, `location`, `namespace` | Events in a namespace. `POST /events`. |
| `k8s_restart_deployment` | `product_id`, `cluster_name`, `location`, `namespace`, `deployment_name` | Rolling restart (protected namespaces refused). `POST /restart`. |
| `k8s_scale_deployment` | `product_id`, `cluster_name`, `location`, `namespace`, `deployment_name`, `replicas` | Replica count (protected namespaces refused). `POST /scale`. |
| `helm_install_or_upgrade` | `product_id`, `cluster_name`, `location`, `namespace`, `release`, `chart_ref`, `version`, `repo_url?`, `values` | Policy-checked install/upgrade (see above). REST `POST /helm/install`. |
| `helm_rollback` | `product_id`, `cluster_name`, `location`, `namespace`, `release`, `revision` | `POST /helm/rollback`. |
| `helm_uninstall` | `product_id`, `cluster_name`, `location`, `namespace`, `release`, `approval_id` (optional: without it an approval card is recorded) | Approval required (bound to these arguments, single use). `POST /helm/uninstall`. |
| `helm_list` / `helm_status` / `helm_history` | `product_id`, `cluster_name`, `location`, `namespace`, (`release`) | Read-only. `POST /helm/list`, `/helm/status`, `/helm/history`. |

---

## 🌐 REST Endpoints

* `GET /health`: Health check and region inspection.
* `POST /mcp`: JSON-RPC 2.0 tool execution endpoint.
* `POST /apply`: Applies Kubernetes YAML manifest.
* `POST /status`: Retrieves live cluster status.
* `POST /resources`: Lists namespaced workloads and services.
* `POST /logs`: Streams pod container logs.
* `POST /events`: Extracts namespaced cluster warning events.
* `POST /restart`: Initiates rolling deployment restart.
* `POST /scale`: Updates deployment replica counts.
