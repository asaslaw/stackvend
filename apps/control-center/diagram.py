"""
Project Castor: Architecture Diagram & Security Boundary Engine
Generates dynamic Mermaid.js visual topology diagrams and security boundary maps for deployed workloads.
"""

import logging
import os
from typing import Any, Dict, List, Optional
from schemas import ArchitectureDiagramResponse

logger = logging.getLogger("control-center-diagram-engine")
logging.basicConfig(level=logging.INFO)


class ArchitectureDiagramEngine:
    def generate_mermaid_diagram(
        self,
        product_id: str,
        workload_data: Optional[Dict[str, Any]] = None,
        build_plan_data: Optional[Dict[str, Any]] = None,
    ) -> ArchitectureDiagramResponse:
        """
        Synthesizes a visual Mermaid.js architecture diagram with color-coded
        security boundaries tailored to the specific workload:
        - For 'project-castor' (or is_castor=True): Renders the Master Platform Architecture
          (Control Center, Orchestrator Gateway, Multi-Agent Swarm, MCP servers, and /DEV /PROD folders).
        - For child workloads (e.g. 'example-workload'): Renders authentic workload architecture
          (Google Identity Services / Identity Platform OAuth, Cloud Run v2, GitHub Actions WIF,
          Cloud Firestore Native, and declared resources like Pub/Sub or Cloud Storage).
        """
        data = workload_data or {}
        is_castor = bool(data.get("is_castor", product_id in ["project-castor", "castor", "platform"]))

        if is_castor:
            return self._generate_platform_diagram(product_id, data)
        return self._generate_child_workload_diagram(product_id, data, build_plan_data or {})

    def _generate_platform_diagram(
        self,
        product_id: str,
        data: Dict[str, Any],
    ) -> ArchitectureDiagramResponse:
        """Generates the Master Platform System Architecture diagram."""
        project_id = data.get("project_id") or os.getenv("PROJECT_ID") or os.getenv("GOOGLE_CLOUD_PROJECT") or "castor-platform"

        mermaid = f"""graph TB
    %% Ingress & Client Access Boundary
    subgraph Ingress ["🔒 Security & Ingress Boundary (Verified Google OAuth)"]
        Operator(["👤 Platform Operator / Product Owner"])
        AuthHub["🛡️ Google OAuth 2.0 Web Client\\n(castor-oauth-client-id)"]
        Operator -->|HTTPS TLS 1.3| AuthHub
    end

    %% Master Control Plane
    subgraph ControlPlane ["🖥️ Master Control Plane ({project_id})"]
        CC["🚀 Control Center (Flight Deck)\\n(FastAPI + Alpine.js | Port 8080)"]
        OG["🚦 Orchestrator Gateway\\n(FastAPI /agent/* Coordinator)"]
        CW["⚡ Google Cloud Workflows\\n(Deterministic main_orchestrator)"]
        AuthHub -->|Verified Session & Bearer JWT| CC
        CC -->|REST APIs| OG
        OG -->|Trigger Workflow Execution| CW
    end

    %% Autonomous Multi-Agent Swarm
    subgraph AgentSwarm ["🤖 Autonomous Multi-Agent Swarm"]
        AA["📐 Architect Agent\\n(Gemini 2.5 Flash | 7-Stage DAG)"]
        CA["🛡️ Compliance Agent\\n(FedRAMP / CIS / CMEK Policy)"]
        DA["💻 Developer Agent\\n(Gemini 2.5 Pro | Code Synthesis)"]
        QA["🧪 QA Reviewer Agent\\n(Sandbox Test Runner)"]
        RA["🚀 Release Agent\\n(GitHub Branch/PR Manager)"]
        
        CW -->|1. Plan| AA
        CW -->|2. Compliance| CA
        CW -->|3. Code| DA
        CW -->|4. Test| QA
        CW -->|5. Release| RA
    end

    %% Deterministic MCP Tool Servers
    subgraph ToolServers ["🧱 Deterministic MCP Tool Servers"]
        TF_MCP["🧱 Terraform MCP Server\\n(GCS State Locking & Cloud Build)"]
        GC_MCP["☁️ gcloud MCP Server\\n(GCP Resource Operations)"]
        GH_MCP["🐙 GitHub MCP Server\\n(Git Trees, Blobs & Commits)"]
        CW -->|6. Deploy| TF_MCP
        DA -.->|Git Operations| GH_MCP
        TF_MCP -.->|CLI Operations| GC_MCP
    end

    %% Platform State & Storage Plane
    subgraph PlatformState ["🟠 Platform State & Persistence Plane"]
        FS[("🔥 Central Cloud Firestore Native\\n(workloads, build_plans, feature_requests)")]
        GCS_STATE[("🪣 Remote Terraform State\\ngs://castor-tfstate-507121")]
        AR["📦 Platform Artifact Registry\\nus-central1-docker.pkg.dev/{project_id}"]
        OG -->|Metadata / Audit Logs| FS
        TF_MCP -->|tfstate Locking| GCS_STATE
        TF_MCP -->|Container Images| AR
    end

    %% Downstream Resource Governance
    subgraph Governance ["📂 Google Cloud Resource Manager Governance"]
        DEV_FOLDER["📁 /primary_folder/DEV (Initial Vending)"]
        PROD_FOLDER["📁 /primary_folder/PROD (Hardened Promotion)"]
        TF_MCP -->|Vend Child Projects| DEV_FOLDER
        DEV_FOLDER -.->|Promote to PROD| PROD_FOLDER
    end

    %% Styling
    classDef security fill:#e8f0fe,stroke:#1a73e8,stroke-width:2px,color:#174ea6;
    classDef control fill:#f1f3f4,stroke:#5f6368,stroke-width:2px,color:#202124;
    classDef compute fill:#e6f4ea,stroke:#137333,stroke-width:2px,color:#0d652d;
    classDef messaging fill:#f3e8fd,stroke:#8430ce,stroke-width:2px,color:#681da8;
    classDef storage fill:#fef7e0,stroke:#b06000,stroke-width:2px,color:#7c3d00;
    classDef governance fill:#e1f5fe,stroke:#0288d1,stroke-width:2px,color:#01579b;

    class Ingress security;
    class ControlPlane control;
    class AgentSwarm compute;
    class ToolServers messaging;
    class PlatformState storage;
    class Governance governance;
"""
        boundaries = [
            "🔒 Verified Google OAuth 2.0 & Session Access Control on Control Center",
            "🟢 Autonomous Multi-Agent Swarm with Cloud Workflows deterministic execution",
            "🧱 Isolated MCP Tool Servers with GCS state locking & audit trails",
            "🔑 Zero-Secret Keyless Platform Service Accounts (sa-castor-developer)",
            "📂 Google Cloud Resource Manager folder governance (/DEV & /PROD)",
        ]

        return ArchitectureDiagramResponse(
            product_id=product_id,
            mermaid_code=mermaid,
            security_boundaries=boundaries,
            services_count=8,
        )

    def _generate_child_workload_diagram(
        self,
        product_id: str,
        data: Dict[str, Any],
        build_plan_data: Dict[str, Any],
    ) -> ArchitectureDiagramResponse:
        """Generates dynamic child workload architecture reflecting authentic cloud resources."""
        clean_pid = product_id.lower().replace("_", "-")
        project_id = data.get("project_id", clean_pid)
        # FD-7M-a: the workload's recorded region; a workload without one follows the Settings default region (shown
        # as such, never a literal region).
        region = data.get("region") if isinstance(data.get("region"), str) and data.get("region") else None
        ar_location = f"{region}-docker.pkg.dev" if region else "(Settings default region)"
        status = data.get("status", "ACTIVE")
        service_url = data.get("service_url", "")
        # FD-4DE: never a made-up run.app address: the recorded URL, else "URL unknown" (with the deploy's typed
        # reason when it gave one)
        unknown_reason = data.get("service_url_unknown_reason")
        if service_url:
            url_display = service_url
        elif (isinstance(unknown_reason, str) and 0 < len(unknown_reason) <= 64
              and all(ch.isupper() or ch == "_" for ch in unknown_reason)):   # a typed token only (diagram text)
            url_display = f"URL unknown: {unknown_reason}"
        else:
            url_display = "URL unknown"
        folder_id = data.get("parent_folder_id", "")
        folder_label = f"folders/{folder_id}" if folder_id else "Google Cloud Folder (/DEV)"

        # Inspect required APIs and build plan steps for optional resources
        req_apis = build_plan_data.get("required_cloud_apis", [])
        has_pubsub = "pubsub.googleapis.com" in req_apis or any(
            "pubsub" in str(s).lower() for s in build_plan_data.get("steps", [])
        )
        has_storage = "storage.googleapis.com" in req_apis or any(
            "bucket" in str(s).lower() or "storage" in str(s).lower() for s in build_plan_data.get("steps", [])
        )
        has_cmek = any("kms" in str(s).lower() or "cmek" in str(s).lower() for s in build_plan_data.get("steps", []))
        network_meta = data.get("network", {})
        has_vpc = bool(
            network_meta.get("connector_cidr")
            or "vpcaccess.googleapis.com" in req_apis
            or any("vpc" in str(s).lower() for s in build_plan_data.get("steps", []))
        )
        conn_cidr = network_meta.get("connector_cidr", "10.100.1.0/28")
        vpc_name = network_meta.get("vpc_name", f"vpc-{clean_pid}")

        # Detect microservices or default to primary
        detected_services = [clean_pid]

        # Build dynamic compute nodes
        compute_nodes = []
        for svc in detected_services:
            compute_nodes.append(
                f'App_{svc}["⚡ Cloud Run v2: {svc}\\n(Status: {status} | Scale: 0 to 5)\\n{url_display}"]'
            )
        compute_str = "\n        ".join(compute_nodes)
        primary_app_ref = f"App_{detected_services[0]}"

        # Build dynamic persistence nodes
        persistence_nodes = [
            f'FS[("🔥 Cloud Firestore Native: (default)\\n├── authorized_users (Whitelist)\\n└── {clean_pid} Collections")]',
            f"{primary_app_ref} -->|Verify Whitelist & CRUD| FS",
        ]
        if has_storage:
            persistence_nodes.extend([
                f'GCS[("🪣 Cloud Storage: gs://{clean_pid}-assets")]',
                f"{primary_app_ref} -->|Blob Assets| GCS",
            ])
        if has_pubsub:
            persistence_nodes.extend([
                f'Topic["📢 Cloud Pub/Sub: {clean_pid}-events"]',
                f"{primary_app_ref} -->|Publish Events| Topic",
            ])
        persistence_str = "\n        ".join(persistence_nodes)

        # Build dynamic security / IAM nodes
        iam_nodes = [
            f'SA["🤖 Runtime Service Account\\nsa-{clean_pid}@{project_id}.iam.gserviceaccount.com"]',
            f'Roles["📋 Scoped Least-Privilege Roles\\n├── roles/datastore.user\\n└── roles/logging.logWriter"]',
            f"SA --- Roles",
            f"SA -->|Runtime Identity| {primary_app_ref}",
        ]
        if has_cmek:
            iam_nodes.extend([
                f'KMS["🔐 Cloud KMS Key Ring: {clean_pid}-keyring\\n(90-Day Key Rotation)"]',
                f"KMS -.->|CMEK Encryption| FS",
            ])
        iam_str = "\n        ".join(iam_nodes)

        network_str = ""
        if has_vpc:
            network_str = f"""
    %% Private VPC & Serverless Network Perimeter
    subgraph Network ["🌐 Private VPC & Serverless Network Perimeter"]
        VPC["☁️ Isolated VPC: {vpc_name}"]
        VPC_CONN["🔌 Serverless VPC Access Connector: conn-{clean_pid}\\n(CIDR: {conn_cidr})"]
        VPC --- VPC_CONN
        {primary_app_ref} -->|Private Egress| VPC_CONN
    end"""

        network_class = "    class Network network;" if has_vpc else ""

        mermaid = f"""graph TB
    %% Ingress & Client Authentication Perimeter (Zero IAP)
    subgraph Ingress ["🔒 Security & Ingress Boundary (Google Identity Platform)"]
        User(["👤 End User / Client Browser"])
        GSI["🔐 Google Identity Services (GSI) / Identity Platform\\n(Provider: google.com | Client-Side Auth)"]
        User -->|1. Sign in with Google| GSI
        GSI -->|2. Returns Verified ID Token JWT| User
    end

    %% Serverless Compute Plane
    subgraph Compute ["🟢 Serverless Compute Plane (Cloud Run v2)"]
        {compute_str}
        User -->|3. HTTPS Request + Bearer JWT| {primary_app_ref}
    end

    %% Keyless CI/CD & Workload Identity Federation
    subgraph CICD ["🐙 CI/CD & Keyless Deployment (WIF)"]
        GHA["⚙️ GitHub Actions CI/CD\\n(.github/workflows/deploy-{clean_pid}.yml)"]
        WIF["🏊 Workload Identity Pool: castor-gh-pool\\n(Provider: github-provider)"]
        DeployerSA["🤖 Deployer Service Account\\nsa-gh-deployer@{project_id}..."]
        AR["📦 Artifact Registry Repository\\n{ar_location}/{project_id}/castor-{clean_pid}"]
        
        GHA -->|OIDC Token Exchange| WIF
        WIF -->|Impersonate| DeployerSA
        DeployerSA -->|Cloud Buildpack Build| AR
        DeployerSA -->|Zero-Downtime Deploy| {primary_app_ref}
    end

    %% Persistence & Data Plane
    subgraph Persistence ["🟠 Persistence & Storage Plane (Encrypted at Rest)"]
        {persistence_str}
    end
{network_str}
    %% IAM & Security Boundary
    subgraph IAM ["🔑 Identity & Access Management (Least Privilege)"]
        {iam_str}
    end

    %% Resource Hierarchy
    subgraph Hierarchy ["📂 Google Cloud Resource Hierarchy"]
        Folder["📁 Parent: {folder_label}"]
        Proj["📦 Workload Project: {project_id}"]
        Folder --- Proj
    end

    %% Styling
    classDef security fill:#e8f0fe,stroke:#1a73e8,stroke-width:2px,color:#174ea6;
    classDef compute fill:#e6f4ea,stroke:#137333,stroke-width:2px,color:#0d652d;
    classDef cicd fill:#f3e8fd,stroke:#8430ce,stroke-width:2px,color:#681da8;
    classDef storage fill:#fef7e0,stroke:#b06000,stroke-width:2px,color:#7c3d00;
    classDef network fill:#e0f2fe,stroke:#0284c7,stroke-width:2px,color:#0369a1;
    classDef iam fill:#fce8e6,stroke:#d93025,stroke-width:2px,color:#c5221f;
    classDef hierarchy fill:#e1f5fe,stroke:#0288d1,stroke-width:2px,color:#01579b;

    class Ingress security;
    class Compute compute;
    class CICD cicd;
    class Persistence storage;
{network_class}
    class IAM iam;
    class Hierarchy hierarchy;
"""
        boundaries = [
            "🔒 Google Identity Services (GSI) & Identity Platform client-side OAuth (Zero IAP)",
            "🟢 Serverless Cloud Run v2 with scale-to-zero enforcement & least-privilege invoker",
            "🐙 Keyless GitHub Actions CI/CD via Workload Identity Federation (WIF: castor-gh-pool)",
            "🔥 Cloud Firestore Native database with authorized_users whitelist enforcement",
            f"🔑 Isolated Runtime Service Account (sa-{clean_pid}) with zero organization-level access",
        ]
        if has_storage:
            boundaries.append(f"🟠 Cloud Storage bucket gs://{clean_pid}-assets with fine-grained IAM")
        if has_pubsub:
            boundaries.append(f"🟣 Dedicated Pub/Sub event streams for {clean_pid}")
        if has_vpc:
            boundaries.append(f"🌐 Isolated Virtual Private Cloud ({vpc_name}) with Serverless VPC Connector ({conn_cidr})")
        if has_cmek:
            boundaries.append("🔐 Customer-Managed Encryption Keys (CMEK) with 90-day rotation")

        svc_count = 4 + (1 if has_storage else 0) + (1 if has_pubsub else 0) + (1 if has_vpc else 0)

        return ArchitectureDiagramResponse(
            product_id=product_id,
            mermaid_code=mermaid,
            security_boundaries=boundaries,
            services_count=svc_count,
        )
