"""
Project Castor: Compliance MCP Tool Server - Service Engine
Inspects GCP parent folders for Assured Workloads, evaluates compliance profiles (HIPAA, FedRAMP, GDPR, CJIS),
and validates Terraform HCL against regulatory policy baselines.
"""

import json
import logging
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple


def _load_plan_gate():
    """The sibling `plan_gate.py`. Loaded by path when this file itself was loaded by path (the gateway's explicit
    `COMPLIANCE_MODE=inprocess` and the eval harness exec this module without its directory on sys.path)."""
    try:
        import plan_gate as module  # the server process: main.py's directory is on sys.path
        return module
    except ImportError:
        import importlib.util
        import sys

        name = "stackvend_compliance_plan_gate"
        if name in sys.modules:
            return sys.modules[name]
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plan_gate.py")
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module  # dataclasses resolve their module through sys.modules
        try:
            spec.loader.exec_module(module)
        except Exception:
            sys.modules.pop(name, None)
            raise
        return module


plan_gate = _load_plan_gate()
try:
    import google.auth
    from google.auth.transport.requests import AuthorizedSession
except ImportError:
    google = None
    AuthorizedSession = None

logger = logging.getLogger("mcp-compliance-server")
logging.basicConfig(level=logging.INFO)


# ADVISORY ONLY (compliance-profile-explicit, 10-18). The compliance profile is never chosen from spec words: it comes
# from an explicit, typed selection (`compliance_profile` on the `/inspect-folder` request, validated against
# `plan_gate.KNOWN_PROFILES`) or the folder's Assured Workloads regime, else STANDARD (`DEFAULT_STANDARD`). These terms
# only produce `profile_suggestions` ("the spec mentions 'credit card': set PCI_DSS explicitly if it applies") for a
# human to act on; `resolve_profile` never reads them (tests/test_compliance_profile_explicit.py).
ADVISORY_PROFILE_TERMS = {
    "HIPAA": ["hipaa", "phi", "patient", "medical", "health record", "healthcare", "ephi"],
    "FEDRAMP_MODERATE": ["fedramp", "fips", "government", "nist 800-53", "cui", "fedramp moderate"],
    "FEDRAMP_HIGH": ["fedramp high", "itar", "classified", "dod", "il4", "il5", "cjis"],
    "EU_REGIONS_AND_SUPPORT": ["gdpr", "eu only", "europe", "data sovereignty", "eu residency"],
    "PCI_DSS": ["pci", "pci-dss", "cardholder", "payment card", "credit card"],
}

# Where the profile came from (`profile_source` in the `/inspect-folder` answer, contract v3).
PROFILE_SOURCE_EXPLICIT = "EXPLICIT_REQUEST"
PROFILE_SOURCE_FOLDER = "ASSURED_WORKLOADS_FOLDER"
PROFILE_SOURCE_DEFAULT = "DEFAULT_STANDARD"
PROFILE_SOURCES = frozenset({PROFILE_SOURCE_EXPLICIT, PROFILE_SOURCE_FOLDER, PROFILE_SOURCE_DEFAULT})
# Assured Workloads regimes that map 1:1 onto a profile (the list `inspect_folder` used before, unchanged).
FOLDER_REGIME_PROFILES = ("HIPAA", "FEDRAMP_MODERATE", "FEDRAMP_HIGH", "EU_REGIONS_AND_SUPPORT", "CJIS")


# Owner decisions 10-18 (rows CP-8..CP-11): strictness of the profiles. Same table as
# apps/orchestrator-gateway/compliance_agent/profiles.py (parity test). rank: higher = stricter; family: the region
# family (EU vs US); profiles of different families are incomparable.
PROFILE_STRICTNESS = {
    "STANDARD":               (0, None),
    "PCI_DSS":                (1, "US"),
    "HIPAA":                  (2, "US"),
    "FEDRAMP_MODERATE":       (3, "US"),
    "CJIS":                   (4, "US"),
    "FEDRAMP_HIGH":           (5, "US"),
    "EU_REGIONS_AND_SUPPORT": (3, "EU"),
}
ERROR_PROFILE_CONFLICT = "COMPLIANCE_PROFILE_CONFLICT"
ERROR_UNMAPPED_REGIME = "UNMAPPED_ASSURED_WORKLOADS_REGIME"


def at_least_as_strict(a: str, b: str) -> bool:
    """True when profile `a` is at least as strict as `b` (exact table lookup)."""
    if a == b:
        return True
    ra, fa = PROFILE_STRICTNESS[a]
    rb, fb = PROFILE_STRICTNESS[b]
    if fb is None:
        return True
    if fa is None or fa != fb:
        return False
    return ra >= rb


class ProfileRefused(Exception):
    """The profile cannot be decided (typed; `/inspect-folder` answers 422 with this error_class)."""

    def __init__(self, error_class: str, detail: str):
        super().__init__(f"{error_class}: {detail}")
        self.error_class = error_class
        self.detail = detail


class InvalidComplianceProfile(ValueError):
    """A requested compliance profile that is not exactly one of `plan_gate.KNOWN_PROFILES` (typed refusal)."""

    error_class = "INVALID_COMPLIANCE_PROFILE"


def parse_requested_profile(value: Any) -> Optional[str]:
    """None / "" -> None (no selection). An exact member of `plan_gate.KNOWN_PROFILES` -> itself. Anything else raises
    InvalidComplianceProfile. Exact comparison only: no case folding or trimming (a typo is refused, never guessed)."""
    if value is None or value == "":
        return None
    if isinstance(value, str) and value in plan_gate.KNOWN_PROFILES:
        return value
    raise InvalidComplianceProfile(f"compliance_profile {value!r} is not one of {sorted(plan_gate.KNOWN_PROFILES)}")


# SAT-14 (compliance harvest recognises denyAll): the canonical Org Policy API v2 form of "deny every value" on a list
# constraint is `rules: [{denyAll: true}]`; StackVend's own folder policy (`managed_folder_vm_external_ip`,
# infra/platform/main.tf) is exactly that. COPY of `_deny_all_in_effect` in apps/project-vending/vending.py (same
# semantics, kept identical on purpose: the two services are deployed separately and share no package). Typed JSON
# fields only, exact equality, no text matching.
def _deny_all_in_effect(policy: Any) -> bool:
    """True only for a Policy whose spec.rules is a non-empty list of rules that are each exactly `denyAll: true` with
    no condition (Org Policy API v2 Policy shape). Anything else (no spec, allowAll, values, a conditional rule, a
    non-object) is False: the guardrail is not proven to be in effect."""
    spec = policy.get("spec") if isinstance(policy, dict) else None
    rules = spec.get("rules") if isinstance(spec, dict) else None
    return (isinstance(rules, list) and bool(rules)
            and all(isinstance(r, dict) and r.get("denyAll") is True and "condition" not in r for r in rules))


# SAT-14: the Cloud Resource Manager v1 ListPolicy enum value for "deny every value" (`listPolicy.allValues`).
LIST_POLICY_ALL_VALUES_DENY = "DENY"

# Read timeouts (seconds) of the Google API calls `/inspect-folder` makes, and the CRM v3 constraints checked one by one
# when Org Policy v2 returns nothing. Named so the gateway's budget can be checked against them: the gateway's
# COMPLIANCE_SERVER_TIMEOUT_S must cover INSPECT_FOLDER_WORST_CASE_S plus a Cloud Run cold start
# (tests/test_compliance_bundle.py). Values unchanged from the former inline literals.
ASSURED_WORKLOADS_TIMEOUT_S = 10.0   # RT14-33: the budget of ALL Assured Workloads calls (ancestry + list pages)
# RT14-33: typed outcomes of the Assured Workloads folder check (`assured_workloads_check` in the answer).
AW_CHECK_CHECKED = "CHECKED"
AW_CHECK_NOT_APPLICABLE = "NOT_APPLICABLE"   # no folder
AW_CHECK_FAILED = "AW_CHECK_FAILED"           # the workloads list could not be read (HTTP status kept)
AW_CHECK_ORG_UNKNOWN = "AW_CHECK_ORG_UNKNOWN" # no ORGANIZATION_ID and the folder ancestry gave none
AW_ANCESTRY_MAX_DEPTH = 10                    # Resource Manager nests folders at most 10 deep
AW_LIST_MAX_PAGES = 10
ORG_POLICY_V2_TIMEOUT_S = 5.0
CRM_V3_TIMEOUT_S = 3.0
CRM_V3_FALLBACK_CONSTRAINTS = [
    ("constraints/iam.allowedPolicyMemberDomains", "domain_restricted_sharing"),
    ("constraints/run.allowedIngress", "enforce_private_ingress"),
    ("constraints/compute.vmExternalIpAccess", "disallow_vm_external_ip"),
    ("constraints/compute.skipDefaultNetworkCreation", "disallow_default_network"),
    ("constraints/storage.uniformBucketLevelAccess", "enforce_uniform_bucket_level_access"),
    ("constraints/compute.requireOsLogin", "require_os_login"),
]
INSPECT_FOLDER_WORST_CASE_S = (
    ASSURED_WORKLOADS_TIMEOUT_S + ORG_POLICY_V2_TIMEOUT_S + CRM_V3_TIMEOUT_S * len(CRM_V3_FALLBACK_CONSTRAINTS)
)

# Lane 17 PR-1a (compliance bundle, owner 10-12): `/inspect-folder` response contract. The gateway refuses any answer
# whose `contract_version` is lower (fail closed: an old server cannot be trusted to have applied the ingress intent).
# v3 (compliance-profile-explicit): the profile comes from the explicit `compliance_profile` request field or the
# folder regime, never spec keywords; the answer adds `profile_source`, `requested_profile`, `profile_suggestions`.
# A v2 server ignores `compliance_profile` and still guesses from keywords, so the gateway refuses it.
COMPLIANCE_CONTRACT_VERSION = 3
# Where the ingress intent below comes from. A structured architect field replaces it later (lane 17 Q12).
INTENT_SOURCE_SPEC_KEYWORDS = "SPEC_KEYWORDS_LEGACY"

# Lane 17 R-3: the spec ingress-intent keywords MOVED here, unchanged, from the gateway's embedded compliance engine
# (apps/orchestrator-gateway/compliance_agent/handler.py, removed there). One implementation; no keyword was added.
DOMAIN_RESTRICTED_KEYWORDS = ["domain-restricted", "domain restricted", "allowedpolicymemberdomains"]
PRIVATE_INGRESS_KEYWORDS = ["no public ip", "internal only", "private ingress", "internal load balancer"]
# PRIVATE-INGRESS-EARLY-STOP: which input asked for private ingress (reported only, never part of the decision; the
# same names are in apps/orchestrator-gateway/compliance_agent/private_ingress.py).
PRIVATE_INGRESS_SOURCE_SPEC = "SPEC_WORDING"
PRIVATE_INGRESS_SOURCE_ORG_POLICY = "ORG_POLICY"
PRIVATE_INGRESS_SOURCE_PROFILE = "COMPLIANCE_PROFILE"
DIRECT_IAP_KEYWORDS = [
    "iap", "identity-aware proxy", "identity aware proxy",
    "corporate sso", "workspace login", "internal web app",
    "internal portal", "google workspace sso",
    "idp", "identity platform", "protected with idp", "idp protected",
    "identity provider", "protected with identity platform",
]
RESTRICT_ACCESS_QUALIFIERS = ["browser", "sso", "unauthenticated", "login", "internal"]
DENY_UNAUTHENTICATED_KEYWORDS = ["do not allow unauthenticated", "no-allow-unauthenticated", "disallow unauthenticated"]

DIRECT_IAP_TASK = {
    "step_id": "STEP-03D-DIRECT-IAP",
    "title": "Configure Direct Identity-Aware Proxy (IAP) on Cloud Run",
    "category": "INFRA",
    "description": "Configure iap_enabled = true on Cloud Run service, provision IAP Service Agent, and assign roles/iap.httpsResourceAccessor to authorized members.",
    "service": "iap.googleapis.com",
}
SERVERLESS_NEG_TASK = {
    "step_id": "STEP-06B-SERVERLESS-NEG",
    "title": "Provision Serverless NEG for Cloud Run",
    "category": "INFRA",
    "description": "Declare google_compute_region_network_endpoint_group pointing to Cloud Run service.",
    "service": "compute.googleapis.com",
}
HTTPS_LOAD_BALANCER_TASK = {
    "step_id": "STEP-06C-HTTPS-LOAD-BALANCER",
    "title": "Provision Global HTTPS Load Balancer with Cloud Armor WAF",
    "category": "INFRA",
    "description": "Declare google_compute_backend_service, google_compute_url_map, and google_compute_global_forwarding_rule with Cloud Armor security policies.",
    "service": "compute.googleapis.com",
}


def derive_ingress_intent(spec_text: str) -> Dict[str, bool]:
    """Spec-text ingress intent (moved verbatim from the gateway's embedded engine, lane 17 R-3).

    Returns raw signals only; `ComplianceService.inspect_folder` combines them with org policy (most restrictive wins).
    """
    text_lower = (spec_text or "").lower()
    enable_direct_iap = any(k in text_lower for k in DIRECT_IAP_KEYWORDS) or (
        "restrict access" in text_lower and any(k in text_lower for k in RESTRICT_ACCESS_QUALIFIERS)
    )
    return {
        "domain_restricted_sharing": any(k in text_lower for k in DOMAIN_RESTRICTED_KEYWORDS),
        "enforce_private_ingress": any(k in text_lower for k in PRIVATE_INGRESS_KEYWORDS),
        "enable_direct_iap": enable_direct_iap,
        "deny_unauthenticated": any(k in text_lower for k in DENY_UNAUTHENTICATED_KEYWORDS),
    }


class ComplianceService:
    def __init__(self, project_id: Optional[str] = None):
        self.project_id = project_id or os.getenv("PROJECT_ID", "")
        self._session: Optional[AuthorizedSession] = None

    def _get_session(self) -> AuthorizedSession:
        if not self._session:
            credentials, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
            self._session = AuthorizedSession(credentials)
        return self._session

    def suggest_profiles_from_spec(self, spec_text: str, decided_profile: str) -> List[Dict[str, Any]]:
        """ADVISORY ONLY: profiles whose `ADVISORY_PROFILE_TERMS` appear in the spec and differ from the decided
        profile. Computed after the decision and never fed back into it (see `inspect_folder`)."""
        text_lower = (spec_text or "").lower()
        suggestions: List[Dict[str, Any]] = []
        for profile, terms in ADVISORY_PROFILE_TERMS.items():
            if profile == decided_profile:
                continue
            hits = [t for t in terms if re.search(r'\b' + re.escape(t) + r'\b', text_lower)]
            if hits:
                suggestions.append({
                    "profile": profile,
                    "matched_terms": hits,
                    "advisory": (
                        f"The spec mentions {', '.join(repr(h) for h in hits)}. If this workload must meet {profile}, "
                        f"set compliance_profile={profile} explicitly. This note does not change the profile."
                    ),
                })
        return suggestions

    def resolve_profile(self, requested_profile: Optional[str], folder_check: Dict[str, Any]) -> Dict[str, Any]:
        """The profile decision, from typed inputs only (owner decisions 10-18, rows CP-8 / CP-10):
          * the folder is an Assured Workloads folder:
              - its regime is not one StackVend maps (`FOLDER_REGIME_PROFILES`) -> ProfileRefused UNMAPPED (never a
                silent STANDARD);
              - no request, or the same profile -> the regime;
              - a different request -> the STRICTER of the two (`PROFILE_STRICTNESS`), with a note naming both;
                an incomparable pair (EU vs US region family) -> ProfileRefused CONFLICT;
          * else the explicit request; else STANDARD."""
        requested = parse_requested_profile(requested_profile)
        base = {"requested_profile": requested, "folder_regime": None, "mismatch_note": None}
        if folder_check.get("is_assured_workload"):
            regime = folder_check.get("compliance_regime")
            if regime not in FOLDER_REGIME_PROFILES:
                raise ProfileRefused(
                    ERROR_UNMAPPED_REGIME,
                    f"the parent folder is an Assured Workloads {regime!r} folder, a regime StackVend does not map to "
                    f"a compliance profile ({list(FOLDER_REGIME_PROFILES)}); nothing is built")
            base["folder_regime"] = regime
            if requested is None or requested == regime:
                return dict(base, profile=regime, profile_source=PROFILE_SOURCE_FOLDER)
            if at_least_as_strict(requested, regime):
                winner, source = requested, PROFILE_SOURCE_EXPLICIT
            elif at_least_as_strict(regime, requested):
                winner, source = regime, PROFILE_SOURCE_FOLDER
            else:
                raise ProfileRefused(
                    ERROR_PROFILE_CONFLICT,
                    f"compliance_profile={requested} and the parent folder's Assured Workloads regime {regime} cannot "
                    "both be met (different region families); choose one")
            base["mismatch_note"] = (
                f"compliance_profile={requested} was requested and the parent folder is an Assured Workloads {regime} "
                f"folder; the stricter profile, {winner}, applies.")
            return dict(base, profile=winner, profile_source=source)
        if requested is not None:
            return dict(base, profile=requested, profile_source=PROFILE_SOURCE_EXPLICIT)
        return dict(base, profile="STANDARD", profile_source=PROFILE_SOURCE_DEFAULT)

    def inspect_parent_folder(self, folder_id: str) -> Dict[str, Any]:
        """Queries Google Cloud Assured Workloads API to check folder compliance profile.

        RT14-33 (owner 11-14): the query used to name the organization `organizations/<ORGANIZATION_ID or
        organizations/0>` and the hardcoded location us-central1, so it never matched; every failure was logged at
        DEBUG and read as "not an Assured Workloads folder". Now:
          * the organization is ORGANIZATION_ID (`123` or `organizations/123`), else the folder's ancestry (Resource
            Manager v3 folders.get, at most AW_ANCESTRY_MAX_DEPTH levels);
          * the list covers every location (`locations/-`) and every page (at most AW_LIST_MAX_PAGES);
          * the answer carries a typed `assured_workloads_check`: {"status": "CHECKED"} when the organization's
            workloads were read, else {"status": "FAILED", "error_class": AW_CHECK_ORG_UNKNOWN | AW_CHECK_FAILED,
            "http_status", "detail"} (logged WARNING). The folder then counts as NOT an Assured Workloads folder, as
            before: refusing would stop every build on every install until the org-level
            `assuredworkloads.workloads.list` grant (a core install step) exists (documentation/known-limitations.md).
        All calls together stay within ASSURED_WORKLOADS_TIMEOUT_S."""
        if not folder_id or folder_id == "0":
            return {"folder_id": folder_id, "is_assured_workload": False, "compliance_regime": "NONE",
                    "assured_workloads_check": {"status": AW_CHECK_NOT_APPLICABLE}}

        clean_folder = folder_id.replace("folders/", "")
        not_found = {"folder_id": folder_id, "is_assured_workload": False, "compliance_regime": "NONE"}
        deadline = time.monotonic() + ASSURED_WORKLOADS_TIMEOUT_S

        def call_timeout(cap: float) -> float:
            return round(min(cap, max(0.0, deadline - time.monotonic())), 1)

        def failed(error_class: str, detail: str, http_status: Optional[int] = None) -> Dict[str, Any]:
            logger.warning(f"{error_class}: Assured Workloads check of folder {clean_folder} not done: {detail}")
            return dict(not_found, assured_workloads_check={"status": "FAILED", "error_class": error_class,
                                                            "http_status": http_status, "detail": detail[:300]})

        try:
            session = self._get_session()
            org_id, org_failure = self._assured_workloads_org(session, clean_folder, call_timeout)
            if org_id is None:
                return failed(AW_CHECK_ORG_UNKNOWN, org_failure[0], org_failure[1])
            url = f"https://assuredworkloads.googleapis.com/v1/organizations/{org_id}/locations/-/workloads"
            page_token = None
            for _page in range(AW_LIST_MAX_PAGES):
                timeout = call_timeout(ASSURED_WORKLOADS_TIMEOUT_S)
                if timeout <= 0:
                    return failed(AW_CHECK_FAILED, f"no time left to read every page of {url}")
                params = {"pageSize": 100, **({"pageToken": page_token} if page_token else {})}
                res = session.get(url, params=params, timeout=timeout)
                if res.status_code != 200:
                    return failed(AW_CHECK_FAILED, f"workloads.list answered HTTP {res.status_code}", res.status_code)
                body = res.json() or {}
                for w in body.get("workloads", []) or []:
                    for r in w.get("resourceSettings", []) or []:
                        # Exact match only (compliance-profile-explicit RT F2): before, `or` matched any AW workload
                        # in the org that has a consumer folder, for every folder.
                        if r.get("resourceType") == "CONSUMER_FOLDER" and r.get("resourceId") == clean_folder:
                            regime = w.get("complianceRegime", "NONE")
                            return {
                                "folder_id": folder_id,
                                "is_assured_workload": True,
                                "compliance_regime": regime,
                                "display_name": w.get("displayName", ""),
                                "kms_settings": w.get("kmsSettings", {}),
                                "assured_workloads_check": {"status": AW_CHECK_CHECKED},
                            }
                page_token = body.get("nextPageToken")
                if not page_token:
                    return dict(not_found, assured_workloads_check={"status": AW_CHECK_CHECKED})
            return failed(AW_CHECK_FAILED, f"more than {AW_LIST_MAX_PAGES} pages of Assured Workloads workloads")
        except Exception as e:  # noqa: BLE001 - typed above; the class only (no message text is parsed)
            return failed(AW_CHECK_FAILED, f"{type(e).__name__}")

    def _assured_workloads_org(self, session: Any, clean_folder: str,
                               call_timeout: Any) -> Tuple[Optional[str], Tuple[str, Optional[int]]]:
        """RT14-33: (organization number, _) from ORGANIZATION_ID, else from the folder's ancestry (Resource Manager v3
        `folders.get` `parent`, a typed `folders/N` / `organizations/N` name); (None, (detail, http_status)) when it
        cannot be established."""
        configured = os.getenv("ORGANIZATION_ID", "").strip()
        if configured:
            org = configured.split("/", 1)[1] if configured.startswith("organizations/") else configured
            if org.isdigit():
                return org, ("", None)
            return None, (f"ORGANIZATION_ID {configured!r} is not an organization number", None)
        name = f"folders/{clean_folder}"
        for _depth in range(AW_ANCESTRY_MAX_DEPTH):
            timeout = call_timeout(CRM_V3_TIMEOUT_S)
            if timeout <= 0:
                return None, ("no time left to read the folder ancestry", None)
            res = session.get(f"https://cloudresourcemanager.googleapis.com/v3/{name}", timeout=timeout)
            if res.status_code != 200:
                return None, (f"folders.get of {name} answered HTTP {res.status_code}", res.status_code)
            parent = str((res.json() or {}).get("parent") or "")
            kind, _, number = parent.partition("/")
            if kind == "organizations" and number.isdigit():
                return number, ("", None)
            if kind == "folders" and number.isdigit():
                name = parent
                continue
            return None, (f"{name} has no organization parent ({parent or 'none'})", None)
        return None, (f"folder ancestry deeper than {AW_ANCESTRY_MAX_DEPTH} levels", None)

    def harvest_folder_policies(self, resource_id: str) -> Dict[str, Any]:
        """
        Dynamically harvests all effective GCP Organization Policies on the target folder
        via Org Policy API v2 and CRM v3, compiling a structured PolicyIntentMatrix.
        """
        matrix: Dict[str, Any] = {
            "disallow_vm_external_ip": False,
            "disallow_default_network": False,
            "require_os_login": False,
            "require_shielded_vm": False,
            "enforce_private_ingress": False,
            "enforce_uniform_bucket_level_access": False,
            "enforce_public_access_prevention": False,
            "domain_restricted_sharing": False,
            "allowed_domains": [],
            "allow_unauthenticated": True,
            "disable_sa_key_creation": False,
            "restrict_public_sql": False,
            "allowed_locations": [],
            "has_constraints": False,
        }

        if not resource_id or resource_id == "0":
            return matrix

        clean_res = resource_id if "/" in resource_id else f"folders/{resource_id}"
        session = self._get_session()
        harvested_any = False

        # 1. Attempt Org Policy API v2 list/effective queries
        try:
            url = f"https://orgpolicy.googleapis.com/v2/{clean_res}/policies"
            res = session.get(url, timeout=ORG_POLICY_V2_TIMEOUT_S)
            if res.status_code == 200:
                policies = res.json().get("policies", [])
                for pol in policies:
                    name = pol.get("name", "")
                    constraint = name.split("/policies/")[-1] if "/policies/" in name else name
                    spec = pol.get("spec", {})
                    rules = spec.get("rules", [])
                    for rule in rules:
                        enforce = rule.get("enforce", False)
                        values = rule.get("values", {})
                        allowed = values.get("allowedValues", [])
                        denied = values.get("deniedValues", [])

                        if "compute.vmExternalIpAccess" in constraint:
                            # SAT-14: also the canonical v2 `denyAll: true` form (every rule, no condition).
                            if enforce or "all" in denied or "is:all" in denied or _deny_all_in_effect(pol):
                                matrix["disallow_vm_external_ip"] = True
                                harvested_any = True
                        elif "compute.skipDefaultNetworkCreation" in constraint:
                            if enforce:
                                matrix["disallow_default_network"] = True
                                harvested_any = True
                        elif "compute.requireOsLogin" in constraint:
                            if enforce:
                                matrix["require_os_login"] = True
                                harvested_any = True
                        elif "compute.requireShieldedVm" in constraint:
                            if enforce:
                                matrix["require_shielded_vm"] = True
                                harvested_any = True
                        elif "storage.uniformBucketLevelAccess" in constraint:
                            if enforce:
                                matrix["enforce_uniform_bucket_level_access"] = True
                                harvested_any = True
                        elif "storage.publicAccessPrevention" in constraint:
                            if enforce:
                                matrix["enforce_public_access_prevention"] = True
                                harvested_any = True
                        elif "iam.disableServiceAccountKeyCreation" in constraint:
                            if enforce:
                                matrix["disable_sa_key_creation"] = True
                                harvested_any = True
                        elif "sql.restrictPublicIp" in constraint:
                            if enforce:
                                matrix["restrict_public_sql"] = True
                                harvested_any = True
                        elif "iam.allowedPolicyMemberDomains" in constraint:
                            if allowed:
                                matrix["domain_restricted_sharing"] = True
                                matrix["allowed_domains"] = [v for v in allowed if not v.startswith("is:")]
                                matrix["allow_unauthenticated"] = False
                                harvested_any = True
                        elif "run.allowedIngress" in constraint:
                            if (allowed and "INGRESS_TRAFFIC_ALL" not in allowed) or ("INGRESS_TRAFFIC_ALL" in denied):
                                matrix["enforce_private_ingress"] = True
                                harvested_any = True
                        elif "gcp.resourceLocations" in constraint:
                            if allowed:
                                matrix["allowed_locations"] = allowed
                                harvested_any = True
        except Exception as e:
            logger.debug(f"Org Policy v2 query skipped ({e}); checking via CRM v3 fallback.")

        # 2. CRM v3 Fallback for core constraints if v2 had no records
        if not harvested_any:
            for constraint_name, key in CRM_V3_FALLBACK_CONSTRAINTS:
                try:
                    url = f"https://cloudresourcemanager.googleapis.com/v3/{clean_res}:getEffectiveOrgPolicy"
                    res = session.post(url, json={"constraint": constraint_name}, timeout=CRM_V3_TIMEOUT_S)
                    if res.status_code == 200:
                        policy = res.json()
                        list_pol = policy.get("listPolicy", {})
                        bool_pol = policy.get("booleanPolicy", {})
                        rule_val = policy.get("rule", {})

                        if bool_pol.get("enforced") or rule_val.get("enforce"):
                            matrix[key] = True
                            harvested_any = True
                        allowed = list_pol.get("allowedValues", []) or rule_val.get("values", {}).get("allowedValues", [])
                        denied = list_pol.get("deniedValues", []) or rule_val.get("values", {}).get("deniedValues", [])
                        if key == "domain_restricted_sharing" and allowed:
                            matrix["domain_restricted_sharing"] = True
                            matrix["allowed_domains"] = [v for v in allowed if not v.startswith("is:")]
                            matrix["allow_unauthenticated"] = False
                            harvested_any = True
                        elif key == "enforce_private_ingress":
                            if (allowed and "INGRESS_TRAFFIC_ALL" not in allowed) or ("INGRESS_TRAFFIC_ALL" in denied):
                                matrix["enforce_private_ingress"] = True
                                harvested_any = True
                        elif key == "disallow_vm_external_ip":
                            # SAT-14: also the v1 ListPolicy `allValues: DENY` (deny every value) form.
                            if (("all" in denied or "is:all" in denied) or (allowed and "all" not in allowed)
                                    or list_pol.get("allValues") == LIST_POLICY_ALL_VALUES_DENY):
                                matrix["disallow_vm_external_ip"] = True
                                harvested_any = True
                except Exception as e:
                    logger.debug(f"CRM v3 check for {constraint_name} skipped: {e}")

        matrix["has_constraints"] = any([
            matrix["disallow_vm_external_ip"],
            matrix["disallow_default_network"],
            matrix["require_os_login"],
            matrix["require_shielded_vm"],
            matrix["enforce_private_ingress"],
            matrix["enforce_uniform_bucket_level_access"],
            matrix["enforce_public_access_prevention"],
            matrix["domain_restricted_sharing"],
            matrix["disable_sa_key_creation"],
            matrix["restrict_public_sql"],
            bool(matrix["allowed_locations"]),
        ])
        return matrix

    def inspect_org_policies(self, resource_id: str) -> Dict[str, Any]:
        """
        Inspects effective organization policies and returns the enriched PolicyIntentMatrix.
        """
        return self.harvest_folder_policies(resource_id)

    def inspect_folder(self, folder_id: str, spec_text: str, requested_profile: Optional[str] = None) -> Dict[str, Any]:
        """The `/inspect-folder` decision (contract v3): folder regime / explicit profile + org policy + spec ingress
        intent. The profile is never read from spec text (`resolve_profile`); an invalid `requested_profile` raises
        InvalidComplianceProfile before any lookup.

        One implementation, used by the HTTP route and by the gateway's explicit `COMPLIANCE_MODE=inprocess` (tests and
        local dev only). Ingress is most-restrictive-wins (lane 17 R-3): a spec asking for IAP, domain restriction or
        "do not allow unauthenticated" can never come out public, whatever the org policy allows.
        """
        folder_id = folder_id or ""
        parse_requested_profile(requested_profile)  # typed refusal before any lookup
        folder_check = self.inspect_parent_folder(folder_id)
        org_policy_check = self.inspect_org_policies(folder_id)
        intent = derive_ingress_intent(spec_text or "")

        decision = self.resolve_profile(requested_profile, folder_check)
        profile = decision["profile"]
        # Advisory only, computed after the decision.
        suggestions = self.suggest_profiles_from_spec(spec_text or "", profile)
        if decision["mismatch_note"]:
            suggestions.append({
                "profile": decision["requested_profile"],
                "folder_regime": decision["folder_regime"],
                "matched_terms": [],
                "advisory": decision["mismatch_note"],
            })

        reqs = self.get_compliance_requirements(profile)
        mandated_tasks = list(reqs.get("mandated_tasks", []))

        # Private ingress: org policy, the profile, or the spec. Ensure the NEG and LB tasks are included.
        enforce_private_ingress = bool(
            org_policy_check.get("enforce_private_ingress", False)
            or reqs.get("enforce_private_ingress", False)
            or intent["enforce_private_ingress"]
        )
        # PRIVATE-INGRESS-EARLY-STOP: the operator's message names what asked for it. Additive report; the decision is
        # the expression above.
        private_ingress_sources = [name for name, asked in (
            (PRIVATE_INGRESS_SOURCE_SPEC, intent["enforce_private_ingress"]),
            (PRIVATE_INGRESS_SOURCE_ORG_POLICY, org_policy_check.get("enforce_private_ingress", False)),
            (PRIVATE_INGRESS_SOURCE_PROFILE, reqs.get("enforce_private_ingress", False)),
        ) if asked]
        spec_lower = (spec_text or "").lower()
        private_ingress_spec_terms = [k for k in PRIVATE_INGRESS_KEYWORDS if k in spec_lower]
        if enforce_private_ingress:
            task_ids = {t["step_id"] for t in mandated_tasks}
            for task in (SERVERLESS_NEG_TASK, HTTPS_LOAD_BALANCER_TASK):
                if task["step_id"] not in task_ids:
                    mandated_tasks.append(dict(task))

        enable_direct_iap = bool(intent["enable_direct_iap"])
        if enable_direct_iap and DIRECT_IAP_TASK["step_id"] not in {t["step_id"] for t in mandated_tasks}:
            mandated_tasks.append(dict(DIRECT_IAP_TASK))

        org_domain_restricted = bool(org_policy_check.get("domain_restricted_sharing", False))
        domain_restricted = org_domain_restricted or intent["domain_restricted_sharing"]
        allowed_domains = list(org_policy_check.get("allowed_domains", []))
        org_allows_unauthenticated = bool(org_policy_check.get("allow_unauthenticated", not org_domain_restricted))
        # Most restrictive wins (lane 17 R-3).
        allow_unauthenticated = (
            org_allows_unauthenticated
            and not enable_direct_iap
            and not domain_restricted
            and not intent["deny_unauthenticated"]
        )

        # SAT14-REGULATED-NARROW (owner 10-31): a guardrail-only folder constraint (for example "no external VM IPs",
        # "uniform bucket access") is not regulation, so `has_constraints` no longer makes a workload regulated. The
        # material org-policy constraints keep their own terms: domain restriction (`domain_restricted` and
        # `not allow_unauthenticated`) and private ingress (`enforce_private_ingress`).
        is_regulated = bool(
            profile != "STANDARD"
            or domain_restricted
            or enforce_private_ingress
            or enable_direct_iap
            # A private (no-public-ingress) decision is never a STANDARD fast-path pass: the gateway's fast path
            # answers allow_unauthenticated=True, so a private answer must take the enrichment path.
            or not allow_unauthenticated
        )

        return {
            "contract_version": COMPLIANCE_CONTRACT_VERSION,
            "intent_source": INTENT_SOURCE_SPEC_KEYWORDS,
            "profile": profile,
            "profile_source": decision["profile_source"],
            "requested_profile": decision["requested_profile"],
            "profile_suggestions": suggestions,
            "is_regulated": is_regulated,
            "is_assured_workload": folder_check.get("is_assured_workload", False),
            "compliance_regime": folder_check.get("compliance_regime", "NONE"),
            "assured_workloads_check": folder_check.get("assured_workloads_check"),   # RT14-33 (typed, additive)
            "requires_cmek": reqs.get("requires_cmek", False),
            "requires_audit_logging": reqs.get("requires_audit_logging", False),
            "allowed_regions": reqs.get("allowed_regions", ["us-central1"]),
            "mandated_tasks": mandated_tasks,
            "description": reqs.get("description", ""),
            "domain_restricted_sharing": domain_restricted,
            "allowed_domains": allowed_domains,
            "allow_unauthenticated": allow_unauthenticated,
            "enable_direct_iap": enable_direct_iap,
            "enforce_private_ingress": enforce_private_ingress,
            "private_ingress_sources": private_ingress_sources,
            "private_ingress_spec_terms": private_ingress_spec_terms,
            "disallow_vm_external_ip": org_policy_check.get("disallow_vm_external_ip", False),
            "disallow_default_network": org_policy_check.get("disallow_default_network", False),
            "require_os_login": org_policy_check.get("require_os_login", False),
            "require_shielded_vm": org_policy_check.get("require_shielded_vm", False),
            "enforce_uniform_bucket_level_access": org_policy_check.get("enforce_uniform_bucket_level_access", False),
            "enforce_public_access_prevention": org_policy_check.get("enforce_public_access_prevention", False),
            "disable_sa_key_creation": org_policy_check.get("disable_sa_key_creation", False),
            "restrict_public_sql": org_policy_check.get("restrict_public_sql", False),
            "policy_matrix": org_policy_check,
        }

    def get_compliance_requirements(self, profile: str) -> Dict[str, Any]:
        """Returns mandatory security controls and tasks for the resolved compliance profile."""
        if profile == "HIPAA":
            return {
                "profile": "HIPAA",
                "requires_cmek": True,
                "requires_audit_logging": True,
                "requires_vpc_sc": True,
                "allowed_regions": ["us-central1", "us-east1", "us-east4", "us-west1"],
                "description": "Health Insurance Portability and Accountability Act (HIPAA) - PHI protection baseline",
                "mandated_tasks": [
                    {
                        "step_id": "STEP-03B-KMS-CMEK",
                        "title": "Provision Cloud KMS Keyring and CMEK Keys",
                        "category": "INFRA",
                        "description": "Declare google_kms_key_ring and google_kms_crypto_key with 90-day automatic rotation for Firestore and Artifact Registry CMEK encryption.",
                        "service": "kms.googleapis.com",
                    },
                    {
                        "step_id": "STEP-03C-AUDIT-LOGGING",
                        "title": "Configure Dedicated Cloud Audit Log Sink",
                        "category": "INFRA",
                        "description": "Configure google_logging_project_sink for DATA_READ and DATA_WRITE audit events to an immutable GCS archive bucket with Object Lock retention.",
                        "service": "logging.googleapis.com",
                    },
                ],
            }
        elif profile in ("FEDRAMP_MODERATE", "FEDRAMP_HIGH", "CJIS"):
            return {
                "profile": profile,
                "requires_cmek": True,
                "requires_audit_logging": True,
                "requires_vpc_sc": True,
                "fips_140_2": True,
                "allowed_regions": ["us-central1", "us-east1", "us-east4"],
                "description": f"Federal Risk and Authorization Management Program ({profile}) - US Federal baseline",
                "mandated_tasks": [
                    {
                        "step_id": "STEP-03B-KMS-CMEK",
                        "title": "Provision FIPS 140-2 Validated Cloud KMS CMEK Keys",
                        "category": "INFRA",
                        "description": "Declare google_kms_crypto_key with HSM protection level and 90-day key rotation.",
                        "service": "kms.googleapis.com",
                    },
                    {
                        "step_id": "STEP-03C-AUDIT-LOGGING",
                        "title": "Configure Tamper-Evident Cloud Audit Log Sink",
                        "category": "INFRA",
                        "description": "Configure centralized logging sink with Access Transparency logs and dual custody retention.",
                        "service": "logging.googleapis.com",
                    },
                ],
            }
        elif profile == "EU_REGIONS_AND_SUPPORT":
            return {
                "profile": "EU_REGIONS_AND_SUPPORT",
                "requires_cmek": True,
                "requires_audit_logging": True,
                "allowed_regions": ["europe-west1", "europe-west3", "europe-west4", "europe-north1"],
                "description": "European Union Data Sovereignty & GDPR Compliance Baseline",
                "mandated_tasks": [
                    {
                        "step_id": "STEP-03B-KMS-CMEK",
                        "title": "Provision EU-Residency Cloud KMS CMEK Keyring",
                        "category": "INFRA",
                        "description": "Declare regional Cloud KMS keys strictly constrained to EU territories.",
                        "service": "kms.googleapis.com",
                    },
                ],
            }
        elif profile == "PCI_DSS":
            return {
                "profile": "PCI_DSS",
                "requires_cmek": True,
                "requires_audit_logging": True,
                "requires_load_balancer": True,
                "enforce_private_ingress": True,
                "allowed_regions": ["us-central1", "us-east1", "us-east4"],
                "description": "Payment Card Industry (PCI-DSS) - Private Ingress + Cloud Armor Load Balancer",
                "mandated_tasks": [
                    {
                        "step_id": "STEP-03B-KMS-CMEK",
                        "title": "Provision Cloud KMS Keyring and CMEK Keys",
                        "category": "INFRA",
                        "description": "Declare google_kms_key_ring and google_kms_crypto_key for CMEK encryption on Firestore and Artifact Registry.",
                        "service": "kms.googleapis.com",
                    },
                    {
                        "step_id": "STEP-06B-SERVERLESS-NEG",
                        "title": "Provision Serverless NEG for Cloud Run",
                        "category": "INFRA",
                        "description": "Declare google_compute_region_network_endpoint_group pointing to Cloud Run service.",
                        "service": "compute.googleapis.com",
                    },
                    {
                        "step_id": "STEP-06C-HTTPS-LOAD-BALANCER",
                        "title": "Provision Global HTTPS Load Balancer with Cloud Armor WAF",
                        "category": "INFRA",
                        "description": "Declare google_compute_backend_service, google_compute_url_map, and google_compute_global_forwarding_rule with Cloud Armor security policies.",
                        "service": "compute.googleapis.com",
                    },
                ],
            }

        return {
            "profile": "STANDARD",
            "requires_cmek": False,
            "requires_audit_logging": False,
            "allowed_regions": ["us-central1"],
            "description": "Standard Enterprise Baseline - Fast-path with default GCP encryption and standard IAM",
            "mandated_tasks": [],
        }

    def evaluate_hcl_compliance(
        self, hcl_files: Dict[str, str], profile: str, ingress: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Advisory pre-commit check of HCL against the profile (lane 14 PR-0, FD-4S): python-hcl2 parse + the same
        typed check table as the plan gate (`plan_gate.py`). Replaces the substring body (a comment containing
        `kms_key_name` used to satisfy CMEK, and `location` was ignored). Unparsable HCL -> `PARSE_ERROR`."""
        return plan_gate.evaluate_hcl(
            hcl_files or {}, profile=profile, requirements=self._gate_requirements(profile), ingress=ingress
        )

    def _gate_requirements(self, profile: str) -> Dict[str, Any]:
        """Requirements for a profile the gate knows; {} for an unknown one (the gate refuses it as UNKNOWN_PROFILE
        instead of `get_compliance_requirements`' STANDARD fallback)."""
        if profile not in plan_gate.KNOWN_PROFILES:
            return {}
        return self.get_compliance_requirements(profile)

    def evaluate_plan_compliance(
        self,
        plan: Any,
        profile: str,
        ingress: Optional[Dict[str, Any]] = None,
        org_allowed_locations: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """The enforcing plan gate (`POST /evaluate-plan`, lane 14 PR-0): `tofu show -json` plan vs profile + the
        stored compliance decision's ingress flags. Decision PASS / VIOLATION / REFUSED (see plan_gate.py)."""
        return plan_gate.evaluate_plan(
            plan,
            profile=profile,
            requirements=self._gate_requirements(profile),
            ingress=ingress,
            org_allowed_locations=org_allowed_locations,
        )
