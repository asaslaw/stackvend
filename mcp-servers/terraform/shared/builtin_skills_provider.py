"""
Project Castor: Built-in Agentic Skills Catalog Provider
Provides dynamic, code-backed access to Castor's native platform agentic skills.
Zero-database persistence: canonical definitions live in code as structured SKILL guidelines.
"""

import copy
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger("castor-builtin-skills")

# The app-side rules for a service behind Cloud Run Direct IAP: Pattern A of the `gcp-direct-iap` skill, and the text
# the developer pipeline adds for a Cloud Run workload whose typed access mode is PRIVATE_IAP (developer_agent/prompt.py
# direct_iap_auth_rule; register row DIRECT-IAP-SKILL-VERIFY).
DIRECT_IAP_VERIFICATION_RULES = """- Every protected route verifies the signed header `X-Goog-IAP-JWT-Assertion` (ES256) with IAP's public keys:
  ```python
  from google.auth.transport import requests as google_requests
  from google.oauth2 import id_token
  claims = id_token.verify_token(assertion, cached_certs, audience=audience,
                                 certs_url="https://www.gstatic.com/iap/verify/public_key", clock_skew_in_seconds=30)
  ```
  Without `certs_url`, `verify_token` uses Google's OAuth certificates, which never hold IAP's keys. It does not check the issuer: also require `claims["iss"] == "https://cloud.google.com/iap"`.
- `verify_token` fetches the keys on every call and has no cache. `cached_certs(url, method="GET", **kwargs)` is a small app function that keeps a successful `google_requests.Request()` GET of that URL in memory for 10 minutes, and builds that `Request()` only on a miss so tests can replace it.
- Verification and the metadata reads block: call them from a sync `def` route or dependency (FastAPI runs those in a thread pool) or through `await asyncio.to_thread(...)`, never directly inside `async def`.
- `audience` is exactly `/projects/<project-number>/locations/<region>/services/<service-name>`, never an OAuth client id, a secret name or the service URL. Build it in one named function, `iap_audience()`, on the first request (never at import), and cache it in a module-level variable only once built: the service name from env `K_SERVICE`; from `http://metadata.google.internal/computeMetadata/v1/` with header `Metadata-Flavor: Google` and a 2-second `timeout`, `project/numeric-project-id` and `instance/region` (returns `projects/<n>/regions/<region>`: keep the last segment). Do not add an audience environment variable or Terraform value.
- Identity comes only from the verified claims: `claims["email"]`, required. `X-Goog-Authenticated-User-Email` is unsigned and forgeable: never use it as proof of identity, not even as a fallback.
- A missing header or a failed or impossible verification (metadata lookup failure included) is HTTP 401 for that request. No default user, bypass flag, mock-auth mode or unverified decode in non-test code.
- `requirements.txt` lists `google-auth`, `requests` and `cryptography`.
- Tests run the real verification: sign tokens with a locally generated ES256 key and serve its public key as `{kid: PEM}` JSON through a fake `Request` transport (response with `.status` and `.data`), covering valid, wrong audience, wrong issuer, expired and wrong-key tokens. At the very least assert that `verify_token` received this `certs_url` and audience. A mock that only returns success proves nothing.
- Tests never reach the metadata server or gstatic: the test sandbox has no `K_*` variables, its metadata server answers for another project, and an unstubbed key fetch outlasts the test timeout. An autouse fixture sets `K_SERVICE` with `monkeypatch.setenv`, stubs both metadata reads of `iap_audience()` (project number and `projects/<n>/regions/<region>`) and resets the app's cached audience and cached keys between tests; a test about something else may patch `iap_audience()` itself.
"""

BUILTIN_SKILLS_DATA: List[Dict[str, Any]] = [
    {
        "skill_id": "gcp-direct-iap",
        "name": "Cloud Run Direct IAP & Edge SSO",
        "target_agent": "DEVELOPER_AGENT",
        "description": "Enterprise guidelines for Cloud Run v2 Direct IAP authentication, Identity Platform cookie reflection, and authorized invoker IAM bindings.",
        "trigger_keywords": ["iap", "sso", "auth", "direct-iap", "identity-platform", "google-signin", "firebase"],
        "always_active": False,
        "instructions_markdown": """# Skill: Cloud Run Direct IAP & Edge SSO Authentication

## Overview
Direct Cloud Run URLs (`*.a.run.app`) require specific configuration depending on whether they leverage Google Identity-Aware Proxy (Direct IAP) or Identity Platform browser login.

## Architectural Patterns
### Pattern A: Direct IAP (Enterprise Edge SSO)
- Cloud Run service is configured with `enable_direct_iap = true` in `compute-cloudrun`.
- Never disable authentication or open `--allow-unauthenticated` for internal Direct IAP services.
""" + DIRECT_IAP_VERIFICATION_RULES + """
### Pattern B: Identity Platform / Firebase Auth (Public Edge with Browser Sign-In)
- The Cloud Run service MUST have `allow_unauthenticated = true` in `main.tf` so initial unauthenticated browser clients can reach the web landing page.
- NEVER check for or expect `X-Goog-Authenticated-User-Email` in Pattern B.
- `GET /` and `GET /api/config` must ALWAYS return 200 OK without authentication.
- Expose `GET /api/config` returning:
  ```python
  {"firebase_api_key": os.getenv("FIREBASE_API_KEY", ""), "firebase_auth_domain": os.getenv("FIREBASE_AUTH_DOMAIN", ""), "project_id": os.getenv("PROJECT_ID", "")}
  ```
- Google Sign-In Client SDK: Use official **Firebase / Identity Platform SDK (compat)**:
  `<script src="https://www.gstatic.com/firebasejs/10.8.0/firebase-app-compat.js"></script>`
  `<script src="https://www.gstatic.com/firebasejs/10.8.0/firebase-auth-compat.js"></script>`
- In `templates/index.html`:
  - Auth container with `#user-info`, prominent `#signInButton` (`<button id="signInButton" class="google-btn">Sign in with Google</button>`), and `#signOutButton` (`<button id="signOutButton" style="display: none;">Sign out</button>`).
  - `#signInButton` MUST be visible by default when unauthenticated — NEVER hide it with initial `display: none`.
  - Add CSS for `.google-btn`: background `#4285f4`, color `#fff`, border none, padding `10px 18px`, border-radius `4px`, font-size `15px`, font-weight `bold`, cursor pointer.
- In `static/js/auth.js`:
  - Fetch `/api/config` and initialize `firebase.initializeApp({ apiKey: config.firebase_api_key, authDomain: config.firebase_auth_domain, projectId: config.project_id })`.
  - Wire `firebase.auth().onAuthStateChanged((user) => { ... })`:
    * If `user`: `#user-info` displays `Signed in as: <strong>${user.email}</strong>`, hide `#signInButton`, show `#signOutButton`, show `#authenticated-content`.
    * If not `user`: `#user-info` displays `You are not signed in. Click below to sign in with your Google account.`, show `#signInButton` (`display: inline-block`), hide `#signOutButton`, hide `#authenticated-content`.
  - On `#signInButton` click, invoke `const provider = new firebase.auth.GoogleAuthProvider(); try { await firebase.auth().signInWithPopup(provider); } catch (err) { if (err.code === 'auth/popup-blocked') { await firebase.auth().signInWithRedirect(provider); } else { alert('Sign-in failed: ' + err.message); } }` (routes through `<project-id>.firebaseapp.com/__/auth/handler`).
  - Pass credential ID token via `Authorization: Bearer <token>` on all API requests (`/api/...`).
- Protect all sensitive backend routes `/api/...` by verifying the Bearer ID token with `google.oauth2.id_token.verify_firebase_token`.
""",
    },
    {
        "skill_id": "golden-terraform-patterns",
        "name": "Golden Terraform & Monorepo Infrastructure",
        "target_agent": "DEVELOPER_AGENT",
        "description": "Rules for invoking StackVend Golden Modules, strict variable typing, preserving human.tf overrides, and zero-destroy deployments.",
        "trigger_keywords": ["terraform", "modules", "human.tf", "hcl", "infrastructure", "workload-foundation"],
        "always_active": True,
        "instructions_markdown": """# Skill: Golden Terraform & Monorepo Infrastructure Patterns

## Overview
StackVend enforces strict architectural invariants for all Terraform infrastructure generated under `infra/workload/`.

## Core Conventions
1. **Source Paths**:
   - Always reference platform modules using relative paths: `source = "../modules/<module-id>"`.
   - Never use remote Git URLs for built-in catalog modules.
2. **Human Extensibility Preservation**:
   - Platform architects declare custom or overriding resources in `human.tf` and `human_override.tf`.
   - NEVER overwrite, delete, or alter `human.tf` or `human_override.tf`. Treat them as immutable human-managed artifacts.
3. **Literal Variable Defaults**:
   - In `variables.tf`, all variable `default` values MUST be static literals (`default = ""` or `default = "us-central1"`).
   - NEVER interpolate `${var...}` inside variable default blocks in Terraform HCL.
4. **Zero-Destroy Policy**:
   - Never set `deletion_protection = false` on production databases unless explicitly directed.
   - Foundational WIF pools, base service accounts, and Artifact Registries are provided by `workload-foundation/base`. Do not re-declare them in `custom.tf`.
""",
    },
    {
        "skill_id": "heavy-stateful-applier",
        "name": "Heavy Stateful Database & 24h Batch Applier",
        "target_agent": "ARCHITECT_AGENT",
        "description": "Decision guidelines for setting is_heavy_stateful: true and routing long-running Terraform executions to the 24h Cloud Run Job batch applier.",
        "trigger_keywords": ["cloudsql", "redis", "spanner", "alloydb", "bigtable", "composer", "stateful", "database", "heavy"],
        "always_active": False,
        "instructions_markdown": """# Skill: Heavy Stateful Database & 24h Batch Applier

## Overview
Standard Cloud Run HTTP requests have a 15-minute execution ceiling. Heavy stateful Google Cloud resources (such as Cloud SQL instances, Redis clusters, Spanner, AlloyDB, or Cloud Composer) typically take between 10 to 30 minutes to provision.

## Architect Decision Invariants
1. **Triggering `is_heavy_stateful`**:
   - Whenever the workload specification requests:
     * `database-cloudsql` (PostgreSQL / MySQL)
     * `cache-redis` (Memorystore Redis)
     * `database-spanner` (Cloud Spanner instance & DB)
     * `database-alloydb` (AlloyDB cluster)
     * `database-bigtable` (Bigtable SSD cluster)
     * `orchestration-composer` (Cloud Composer 2 / Airflow)
     * `compute-gke-autopilot` (GKE Autopilot cluster)
   - You MUST set `"is_heavy_stateful": true` in the architecture metadata.
2. **Execution Routing**:
   - Setting `is_heavy_stateful: true` routes deployment through the `tf-applier` Cloud Run Job with 24-hour timeout headroom, decoupling execution from HTTP service limits.
""",
    },
    {
        "skill_id": "zero-trust-org-policies",
        "name": "Zero-Trust Google Cloud Org Policy Governance",
        "target_agent": "ALL_AGENTS",
        "description": "Standard rules for validating enterprise Google Cloud organization policies, preventing public IP leaks, enforcing CMEK, and mandatory audit logging.",
        "trigger_keywords": ["org-policy", "org policy", "zero-trust", "cmek", "audit-logging", "governance", "security-perimeter", "organization policy", "constraints"],
        "always_active": False,
        "instructions_markdown": """# Skill: Zero-Trust Google Cloud Org Policy Governance

## Overview
Compliance Agent evaluates technical designs against Google Cloud Organization Policies harvested during the `DISCOVERY` pipeline stage.

## Standard Invariants
1. **Public IP Restriction (`constraints/compute.vmExternalIpAccess`)**:
   - Compute instances and GKE worker nodes MUST NOT have public external IP addresses. All ingress must route via Cloud Load Balancing, Direct IAP, or Private Google Access.
2. **Domain-Restricted Sharing (`constraints/iam.allowedPolicyMemberDomains`)**:
   - Workload IAM bindings must never bind `allUsers`. Use `allAuthenticatedUsers` only when Direct IAP or Identity Platform edge auth is actively fronting the service.
3. **Storage Uniform Access (`constraints/storage.uniformBucketLevelAccess`)**:
   - All Cloud Storage buckets must have `uniform_bucket_level_access = true`.
4. **CMEK Encryption**:
   - High-compliance workloads (FedRAMP High / HIPAA) require Customer-Managed Encryption Keys (`security-kms`) with 90-day rotation.
""",
    },
    {
        "skill_id": "qa-security-and-coverage-standards",
        "name": "QA Test Coverage & Security Auditing Standards",
        "target_agent": "QA_AGENT",
        "description": "Verification standards for comprehensive pytest test suites, input validation, external dependency mocking, and security vulnerability detection.",
        "trigger_keywords": ["test", "pytest", "coverage", "security", "audit", "validation", "qa"],
        "always_active": True,
        "instructions_markdown": """# Skill: QA Test Coverage & Security Auditing Standards

## Overview
The QA Reviewer Agent verifies application code and test suites before code is merged to the deployment branch.

## Auditing Invariants
1. **Test Coverage Thresholds**:
   - Generated pytest suites in `tests/test_main.py` must achieve at least 80% code coverage across route handlers.
   - Tests must cover:
     * Happy path endpoints (200 OK with valid schemas).
     * Input validation edge cases (400 Bad Request, 422 Unprocessable Entity).
     * Error handling paths (500 internal errors handled cleanly).
2. **Mocking External Cloud Clients**:
   - All tests must use `unittest.mock.MagicMock` or `pytest-mock` fixtures for Google Cloud Firestore, Storage, Secret Manager, and Pub/Sub. Tests must NEVER attempt live network calls to GCP.
3. **Security Anti-Patterns**:
   - Flag any hardcoded API secrets, private keys, or plaintext credentials as immediate QA blockers (`passed = false`).
""",
    },
    {
        "skill_id": "sre-incident-rca-standards",
        "name": "SRE Automated Incident RCA & Remediation Standards",
        "target_agent": "SRE_AGENT",
        "description": "Standard methodology for stack trace root-cause analysis, severity classification (P1-P4), and automated regression test requirement formulation.",
        "trigger_keywords": ["incident", "sre", "rca", "crash", "error", "root-cause", "remediation", "trace"],
        "always_active": True,
        "instructions_markdown": """# Skill: SRE Automated Incident RCA & Remediation Standards

## Overview
The SRE Agent analyzes live runtime exceptions forwarded by log sentinels to isolate root causes and produce deterministic remediation tasks for the Developer Agent.

## Operational Standards
1. **Root Cause Analysis (RCA)**:
   - Isolate the exact repository path, line number, and function where the unhandled exception originated.
   - Categorize the failure mode: schema mismatch, missing environment variable, database timeout, or unhandled null/KeyError.
2. **Severity Classification**:
   - `P1_CRITICAL`: Full service outage or data corruption.
   - `P2_HIGH`: Unhandled 500 in core customer-facing or MCP tool endpoints.
   - `P3_MEDIUM`: Transient retry failure or rate limit throttle.
   - `P4_LOW`: Cosmetic log anomaly or deprecation warning.
3. **Remediation Specification**:
   - Prescribe the exact fix strategy for the Developer Agent.
   - Explicitly define `regression_test_requirements` to guarantee the defect will be caught in QA before redeployment.
""",
    },
]

_BUILTIN_SKILLS_CACHE: Optional[List[Dict[str, Any]]] = None


def get_builtin_skills(force_refresh: bool = False) -> List[Dict[str, Any]]:
    """
    Returns the list of canonical built-in agentic skills.
    Zero-database: read directly from code memory.
    """
    global _BUILTIN_SKILLS_CACHE
    if _BUILTIN_SKILLS_CACHE is not None and not force_refresh:
        return copy.deepcopy(_BUILTIN_SKILLS_CACHE)

    catalog: List[Dict[str, Any]] = []
    for item in BUILTIN_SKILLS_DATA:
        record = {
            "skill_id": item["skill_id"],
            "name": item["name"],
            "source_type": "BUILT_IN",
            "target_agent": item["target_agent"],
            "description": item["description"],
            "trigger_keywords": item.get("trigger_keywords", []),
            "always_active": item.get("always_active", False),
            "instructions_markdown": item["instructions_markdown"],
            "is_builtin": True,
            "is_active": True,
            "created_by": "system",
            "created_at": "2026-09-15T00:00:00Z",
            "updated_at": None,
        }
        catalog.append(record)

    _BUILTIN_SKILLS_CACHE = catalog
    return copy.deepcopy(_BUILTIN_SKILLS_CACHE)


def get_builtin_skill_by_id(skill_id: str) -> Optional[Dict[str, Any]]:
    """
    Look up a single built-in skill by ID.
    Returns None if the skill does not exist.
    """
    for skill in get_builtin_skills():
        if skill.get("skill_id") == skill_id:
            return skill
    return None
