"""ADHERENCE-PLATFORM-SATISFIED (owner 11-11): a requirement the platform handles itself is never a blocking finding
against the workload's code or IaC.

Two kinds of platform handling, each tied to a facet:
- SATISFIED: the platform meets the requirement itself. Live case ex09-c1 (11-10): the spec asked for "a $10.00
  FinOps budget cap" and the judge demanded a `google_billing_budget` in the workload IaC. StackVend never creates a
  Cloud Billing budget for a workload (known limitation); the cap is the workload record's
  `budget_ceiling_monthly_usd`, held by StackVend FinOps. Facets BUDGET_CAP, SANDBOX_LIFECYCLE.
- LIMITATION: the platform does NOT meet it, and the workload cannot either: a documented platform limitation. Live
  case ex02-c1 (11-10): a Public app; the judge demanded that one Cloud Run service be callable only by the workload's
  service account. In a Public app every Cloud Run service is public; per-service access is not available yet (known
  limitation "Cloud Run services cannot be made internal-only yet"; per-service access is planned). Facet
  PER_SERVICE_ACCESS. It applies only to a public workload whose commit deploys Cloud Run services; in a private mode
  the same finding is a real defect and still blocks.
- IMAGE-BUILD-PLATFORM-FACT (live ex01-g13, 11-16; docs/handoff/ex01-g13-cloudbuild-plan-task-diagnosis.md): the plan
  asked for a `cloudbuild.yaml` that builds the image with Cloud Native Buildpacks; the platform removes every
  AI-written CI or build file and builds every container image itself (`pack build` in its own Cloud Build at deploy
  time), so the developer could not add the file and the judge's "cloudbuild.yaml is missing" blocked the run. Facet
  IMAGE_BUILD (SATISFIED) whenever the commit's root module calls a golden compute module of a container kind.
- IAM_POLICY (IAM-POLICY-PLATFORM-FACT, ex02-g13 11-16) is a LIMITATION of a different source: StackVend's IAM policy
  refuses a fixed set of privileged roles (validators/policy_tables.PRIVILEGED_ROLES) in every workload's IaC, so a
  plan task asking for one (live: roles/iam.serviceAccountTokenCreator for "Scheduler OIDC") can never be met by the
  workload. Besides the facet, the judge names the exact role (`missed_directive_denied_roles`, parallel); the lens
  accepts the facet only when that role is one of PRIVILEGED_ROLES (exact membership), so a mislabelled finding about
  a role the workload CAN grant stays blocking.

The contract is typed on both sides, never text matching on the spec or on the finding (AGENTS.md invariant 2):
- the judge labels each missed directive with a facet from the closed set FACETS (`missed_directive_facets`, parallel
  to `missed_directives`); anything else is OTHER;
- `platform_handlings` decides from typed facts alone (the workload record, the resolved access policy QA already
  uses, the committed tree's compute modules, the compliance decision's typed access advisories) which facets the
  platform handles for THIS workload. Absent or malformed facts: not handled, so the finding still blocks (fail
  closed).
A handled finding is never dropped (invariant 8): the lens keeps it in `platform_satisfied_directives` or
`platform_limitation_advisories`, and the QA summary says so. It is never a repair seed.
"""

import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, FrozenSet, List, Mapping, Optional, Sequence, Tuple

FACET_BUDGET_CAP = "BUDGET_CAP"
FACET_SANDBOX_LIFECYCLE = "SANDBOX_LIFECYCLE"
FACET_PER_SERVICE_ACCESS = "PER_SERVICE_ACCESS"
FACET_GKE_NETWORK = "GKE_NETWORK"   # GKE-NETWORK-PLATFORM-FACT (ex04-1115b)
FACET_IMAGE_BUILD = "IMAGE_BUILD"   # IMAGE-BUILD-PLATFORM-FACT (ex01-g13)
FACET_IAM_POLICY = "IAM_POLICY"     # IAM-POLICY-PLATFORM-FACT (ex02-g13)
FACET_OTHER = "OTHER"
FACETS = (FACET_BUDGET_CAP, FACET_SANDBOX_LIFECYCLE, FACET_PER_SERVICE_ACCESS, FACET_GKE_NETWORK, FACET_IMAGE_BUILD,
          FACET_IAM_POLICY, FACET_OTHER)

KIND_SATISFIED = "SATISFIED"
KIND_LIMITATION = "LIMITATION"


def denied_roles() -> FrozenSet[str]:
    """IAM-POLICY-PLATFORM-FACT: the roles StackVend's IAM policy never lets workload IaC grant: exactly the policy
    validator's PRIVILEGED_ROLES (POLICY.PRIVILEGED_ROLE on the Terraform path; the typed intent's role tables never
    hold one, its gate-gap check pins that). One table, never a copy."""
    try:
        from developer_agent.validators.policy_tables import PRIVILEGED_ROLES
    except ImportError:  # pragma: no cover - package-relative import (gateway imported as a package)
        from ..developer_agent.validators.policy_tables import PRIVILEGED_ROLES  # type: ignore
    return frozenset(PRIVILEGED_ROLES)


def is_denied_role(raw: Any) -> bool:
    """A role the judge named that the platform's IAM policy refuses (exact membership; anything else is False)."""
    return isinstance(raw, str) and raw in denied_roles()


# What each facet means, for the judge's rubric (the gateway never reads the finding text).
FACET_MEANINGS = {
    FACET_BUDGET_CAP: "a monthly spend or budget cap for the workload",
    FACET_SANDBOX_LIFECYCLE: "a sandbox lifespan, time-to-live or automatic teardown of the workload",
    FACET_PER_SERVICE_ACCESS: ("restricting who may call or reach one Cloud Run service separately from the "
                               "workload's access mode (a per-service IAM invoker, or internal-only ingress)"),
    FACET_GKE_NETWORK: ("the VPC network, subnet, secondary IP ranges, router, Cloud NAT or firewall of the workload's "
                        "GKE cluster"),
    # RT 4: an exhaustive list of what the platform does for the image build; everything else is named as OTHER
    FACET_IMAGE_BUILD: ("the build of the workload's container images, limited to: a build or CI configuration file "
                        "that builds them (for example a Cloud Build config such as `cloudbuild.yaml`), building them "
                        "with Cloud Native Buildpacks or `pack`, or building them without a Dockerfile (not a service's "
                        "dependency manifest such as `requirements.txt`, its `Procfile` or other entrypoint, a "
                        "`project.toml`, image signing, vulnerability scanning, SBOM or attestation, builder or "
                        "base-image pinning, or image tags: those are OTHER)"),
    # RT 1 (Opus 11-16): only an entry whose sole ask is ONE refused role; the task's other asks are their own entries
    FACET_IAM_POLICY: ("a missed directive whose only ask is granting ONE IAM role that StackVend's IAM policy refuses "
                       "in workload IaC (exactly one of: " + ", ".join(sorted(denied_roles())) + "); every other "
                       "missing grant, resource or setting of the same task is its own entry, labelled OTHER"),
    FACET_OTHER: "anything else",
}

_FACT_TITLES = {FACET_BUDGET_CAP: "Budget cap", FACET_SANDBOX_LIFECYCLE: "Sandbox lifespan",
                FACET_PER_SERVICE_ACCESS: "Per-service access", FACET_GKE_NETWORK: "GKE cluster network",
                FACET_IMAGE_BUILD: "Container image build", FACET_IAM_POLICY: "IAM policy"}

# documentation/known-limitations.md section heading (a test pins that it exists).
PER_SERVICE_ACCESS_LIMITATION = "Cloud Run services cannot be made internal-only yet"
# GKE-NETWORK-PLATFORM-FACT: documentation/known-limitations.md section heading (a test pins that it exists).
GKE_NETWORK_LIMITATION = "GKE clusters use the project's default network"
# IAM-POLICY-PLATFORM-FACT: documentation/known-limitations.md section heading (a test pins that it exists).
IAM_POLICY_LIMITATION = "Workload infrastructure cannot grant privileged IAM roles"
# compliance_agent.access_advisory.CODE (a test pins the equality).
ACCESS_ADVISORY_CODE = "ACCESS.INTERNAL_SERVICE_PUBLIC"
# Exact access values (developer_agent.access_resolution.PUBLIC_APP; a test pins the equality).
PUBLIC_APP = "PUBLIC_APP"
SERVICE_NAME_MAX_CHARS = 63
# RT F5: the smallest ceiling the fact can state ($X.XX).
MIN_BUDGET_CEILING_USD = 0.01


@dataclass(frozen=True)
class PlatformHandling:
    """One facet the platform handles for this workload. `how` is built only from typed values (an amount, an
    integer, a date, validated service names), because it is printed in the judge's trusted PLATFORM FACTS section."""

    facet: str
    kind: str          # KIND_SATISFIED | KIND_LIMITATION
    how: str           # the full fact (judge prompt, evidence record)
    note: str          # a short form for the QA summary the operator reads
    known_limitation: Optional[str] = None            # LIMITATION: the known-limitations.md section
    advisory_services: Tuple[str, ...] = ()           # LIMITATION: services the plan-time access advisory named


def _budget_cap(record: Mapping[str, Any]) -> Optional[PlatformHandling]:
    ceiling = record.get("budget_ceiling_monthly_usd")
    if isinstance(ceiling, bool) or not isinstance(ceiling, (int, float)):
        return None
    value = float(ceiling)
    if not math.isfinite(value) or value < MIN_BUDGET_CEILING_USD:
        return None
    return PlatformHandling(
        FACET_BUDGET_CAP, KIND_SATISFIED,
        f"StackVend FinOps holds this workload's monthly budget ceiling of ${value:.2f} on the workload record (spend "
        f"sync, budget warnings and the workload's breach policy use it). It is platform configuration, not workload "
        f"code or IaC: StackVend never creates a Cloud Billing budget for a workload.",
        f"StackVend FinOps budget ceiling ${value:.2f}/month on the workload record")


def _sandbox_lifecycle(record: Mapping[str, Any], today: Optional[str] = None) -> Optional[PlatformHandling]:
    """`today`: the current UTC date (ISO), for tests; a sandbox whose lifespan ended before it is not satisfied."""
    if record.get("is_sandbox") is not True:
        return None
    ttl = record.get("sandbox_ttl_days")
    if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl <= 0:
        return None
    expires = record.get("sandbox_expires_at")
    if not isinstance(expires, str):
        return None
    try:
        when = datetime.fromisoformat(expires)
    except ValueError:
        return None
    ends = (when if when.tzinfo is None else when.astimezone(timezone.utc)).date().isoformat()
    if ends < (today or datetime.now(timezone.utc).date().isoformat()):
        return None   # RT F5: the lifespan already ended; QA never cites a lifecycle that has run out
    return PlatformHandling(
        FACET_SANDBOX_LIFECYCLE, KIND_SATISFIED,
        f"StackVend records this workload as a sandbox with a {ttl}-day lifespan ending {ends} on the workload record. "
        f"The platform's sandbox lifecycle acts on it (expiry notices, and decommission by the sandbox sweeper once "
        f"the sandbox designation is explicit or operator-confirmed); it is not workload code or IaC.",
        f"StackVend sandbox lifecycle, {ttl}-day lifespan ending {ends} on the workload record")


def is_printable_service_name(name: Any) -> bool:
    """A service name that may be printed in the trusted PLATFORM FACTS (lowercase letters, digits, hyphens)."""
    return (isinstance(name, str) and 0 < len(name) <= SERVICE_NAME_MAX_CHARS
            and all(c.isascii() and (c.islower() or c.isdigit() or c == "-") for c in name))


def _per_service_access(ingress_policy: Optional[Mapping[str, Any]], deploys_cloud_run: bool,
                        access_advisories: Sequence[Mapping[str, Any]]) -> Optional[PlatformHandling]:
    policy = ingress_policy if isinstance(ingress_policy, Mapping) else {}
    # The resolved policy QA already uses (record + compliance decision, most restrictive wins), exact values only:
    # the same rule as compliance_agent.access_advisory.workload_is_public.
    public = (policy.get("access_mode") == PUBLIC_APP and policy.get("allow_unauthenticated") is True
              and policy.get("enable_direct_iap") is not True)
    if not public or deploys_cloud_run is not True:
        return None
    named = tuple(sorted({a["service"] for a in access_advisories
                          if isinstance(a, Mapping) and a.get("code") == ACCESS_ADVISORY_CODE
                          and is_printable_service_name(a.get("service"))}))
    advisory = (f" The plan-time access advisory {ACCESS_ADVISORY_CODE} already named: {', '.join(named)}."
                if named else "")
    return PlatformHandling(
        FACET_PER_SERVICE_ACCESS, KIND_LIMITATION,
        f"This workload is a Public app (access mode {PUBLIC_APP}): StackVend deploys every Cloud Run service of it "
        f"public, and it cannot yet restrict one service separately (a per-service IAM invoker or internal-only "
        f"ingress). This is a documented platform limitation (\"{PER_SERVICE_ACCESS_LIMITATION}\"), not something the "
        f"workload's code or IaC can change.{advisory}",
        f"Public app, every Cloud Run service is public; known limitation \"{PER_SERVICE_ACCESS_LIMITATION}\""
        + (f"; plan-time advisory {ACCESS_ADVISORY_CODE}: {', '.join(named)}" if named else ""),
        known_limitation=PER_SERVICE_ACCESS_LIMITATION, advisory_services=named)


def _gke_network(gke_default_network: bool) -> Optional[PlatformHandling]:
    """GKE-NETWORK-PLATFORM-FACT (ex04-1115b): `gke_default_network` = the commit is a typed-intent tree whose root
    module calls the golden GKE Autopilot module on `var.network`, which defaults to "default" and no tfvars set
    (main._commit_gke_on_default_network, exact parse). The cluster's network is then the platform's (lane 11): the
    intent cannot declare a network, subnetwork, router, Cloud NAT or firewall (allowed_types.json `lane11_owned`;
    networking-vpc is platform_only in the catalog), and the cluster runs on the project's `default` network."""
    if gke_default_network is not True:
        return None
    return PlatformHandling(
        FACET_GKE_NETWORK, KIND_LIMITATION,
        "This workload's GKE Autopilot cluster is StackVend's golden compute-gke-autopilot module in the root module the "
        "platform renders (infra/workload/main.tf): private nodes without external IP addresses, given the project's "
        "`default` VPC network, with the pod and service IP ranges GKE allocates itself. StackVend does not render a "
        "dedicated subnet, secondary IP ranges or Cloud NAT for a GKE cluster yet, and with the typed IaC intent the "
        "workload cannot declare a network, subnetwork, router, Cloud NAT or firewall (they are platform-owned). This is "
        f"a documented platform limitation (\"{GKE_NETWORK_LIMITATION}\"), not something the workload's code or IaC can "
        "change.",
        f"GKE cluster on the project's default network with private nodes; known limitation \"{GKE_NETWORK_LIMITATION}\"",
        known_limitation=GKE_NETWORK_LIMITATION)


def _image_build(builds_container_images: bool) -> Optional[PlatformHandling]:
    """IMAGE-BUILD-PLATFORM-FACT (ex01-g13): `builds_container_images` = the commit's root module calls a golden
    compute module of a container kind (main._commit_builds_container_images, exact parse; the terraform server's own
    rule for building images: every kind except the VM kinds, validators.container.NON_CONTAINER_KINDS). The platform
    then builds the images itself (mcp-servers/terraform service `_build_and_push_container`: its own Cloud Build of
    `pack build --path=apps/<service>` steps), and the developer handler removes every AI-written file under
    `.github/workflows/` and the root `cloudbuild.yaml` before it writes the platform's own CI file."""
    if builds_container_images is not True:
        return None
    return PlatformHandling(
        FACET_IMAGE_BUILD, KIND_SATISFIED,
        "StackVend builds every container image of this workload itself with Google Cloud Native Buildpacks, without "
        "a Dockerfile: at deploy time the platform submits its own Cloud Build in the workload's project, which runs "
        "`pack build` on each service directory `apps/<service>/`. The platform writes every CI and build file itself "
        "(see the VCS provider fact) and removes AI-written ones (any file under `.github/workflows/` and the root "
        "`cloudbuild.yaml`): the repository's build or CI configuration for the images is platform output, never "
        "workload code or IaC. This covers only those files, the Buildpacks build and the absence of a Dockerfile; "
        "the services' dependency manifests, `Procfile` or other entrypoints, `project.toml`, image signing, "
        "scanning, SBOM or attestation, builder or base-image pinning and image tags are not covered.",
        "StackVend builds the container images itself with Cloud Native Buildpacks (its own Cloud Build, `pack "
        "build`); AI-written CI or build files are removed")


def _iam_policy(has_iac_task: bool) -> Optional[PlatformHandling]:
    """IAM-POLICY-PLATFORM-FACT (ex02-g13): `has_iac_task` = the plan has at least one task whose typed kind is
    infrastructure (judge_input.task_fact_kinds, exact category / exact platform IaC path), the only tasks whose finding
    the facet can apply to (adherence lens RT F3). The policy itself holds for every workload."""
    if has_iac_task is not True:
        return None
    roles = ", ".join(f"`{r}`" for r in sorted(denied_roles()))
    return PlatformHandling(
        FACET_IAM_POLICY, KIND_LIMITATION,
        f"StackVend's IAM policy refuses these roles in a workload's infrastructure, for any member and on any "
        f"resource: {roles}. Neither the typed IaC intent nor Terraform written for the workload can grant one (the "
        f"platform's gate refuses it before any commit), so a plan task or acceptance criterion that asks for one "
        f"cannot be met by the workload. A workload needs none of them for identity tokens: a Cloud Run service gets "
        f"its own identity tokens from the metadata server, and Cloud Scheduler mints a job's OIDC token for the "
        f"job's service account through its own service agent. This is a documented platform limitation "
        f"(\"{IAM_POLICY_LIMITATION}\"), not something the workload's code or IaC can change. Report each such role "
        f"as its own missed directive whose only ask is that one role, and put the exact role (for example "
        f"`roles/iam.serviceAccountTokenCreator`) at the same position in `missed_directive_denied_roles`; every "
        f"other missing grant, resource or setting of the same task is a separate missed directive labelled OTHER "
        f"(it is judged and repaired as usual).",
        f"StackVend's IAM policy refuses the role in workload IaC; known limitation \"{IAM_POLICY_LIMITATION}\"",
        known_limitation=IAM_POLICY_LIMITATION)


def platform_handlings(record: Optional[Mapping[str, Any]], *, ingress_policy: Optional[Mapping[str, Any]] = None,
                       deploys_cloud_run: bool = False, access_advisories: Sequence[Mapping[str, Any]] = (),
                       gke_default_network: bool = False, builds_container_images: bool = False,
                       has_iac_task: bool = False,
                       today: Optional[str] = None) -> Dict[str, PlatformHandling]:
    """The facets the platform handles for this workload, from typed facts only. {} = none (then the adherence prompt,
    schema and verdict are byte-identical to before).
    `record`: the workload record; `ingress_policy`: QA's resolved access policy (main._qa_ingress_policy);
    `deploys_cloud_run`: the commit's root module calls the golden Cloud Run module; `access_advisories`: the
    compliance decision's validated typed advisories (workflow_gates.access_advisories_of);
    `gke_default_network` (GKE-NETWORK-PLATFORM-FACT): the commit is a typed-intent tree whose root module calls the
    golden GKE Autopilot module on the project's `default` network (main._commit_gke_on_default_network);
    `builds_container_images` (IMAGE-BUILD-PLATFORM-FACT): the commit's root module calls a golden compute module of
    a container kind (main._commit_builds_container_images);
    `has_iac_task` (IAM-POLICY-PLATFORM-FACT): the plan has an infrastructure task (`_iam_policy`)."""
    found: List[Optional[PlatformHandling]] = []
    if isinstance(record, Mapping):
        found += [_budget_cap(record), _sandbox_lifecycle(record, today)]
    found.append(_per_service_access(ingress_policy, deploys_cloud_run, access_advisories))
    found.append(_gke_network(gke_default_network))
    found.append(_image_build(builds_container_images))
    found.append(_iam_policy(has_iac_task))
    return {h.facet: h for h in found if h is not None}


def facet_of(raw: Any) -> str:
    """Exact membership in FACETS; anything else (unknown value, wrong type, other case) is OTHER, never handled."""
    return raw if isinstance(raw, str) and raw in FACETS else FACET_OTHER


def parallel_facets(data: Mapping[str, Any], key: str, findings: List[str]) -> List[str]:
    """The judge reply's facet list `key`: a list exactly as long as `findings`, each mapped by `facet_of`. Anything
    else (absent, wrong type, wrong length) makes every finding OTHER (blocking)."""
    raw = data.get(key)
    if not isinstance(raw, list) or len(raw) != len(findings):
        return [FACET_OTHER] * len(findings)
    return [facet_of(x) for x in raw]


def directive_denied_roles(data: Mapping[str, Any], missed: List[str]) -> List[Optional[str]]:
    """IAM-POLICY-PLATFORM-FACT: `missed_directive_denied_roles` of the judge reply: a list of strings exactly as long
    as `missed_directives`; each kept only when it is a role the platform's IAM policy refuses (`is_denied_role`, exact
    membership), else None. Anything else (absent, wrong type, wrong length) names no role, so an IAM_POLICY label
    stays blocking (fail closed)."""
    raw = data.get("missed_directive_denied_roles")
    if not isinstance(raw, list) or len(raw) != len(missed):
        return [None] * len(missed)
    return [x if is_denied_role(x) else None for x in raw]


def directive_facets(data: Mapping[str, Any], missed: List[str]) -> List[str]:
    """`missed_directive_facets` of the judge reply: a list exactly as long as `missed_directives`, each mapped by
    `facet_of`. Anything else (absent, wrong type, wrong length) makes every directive OTHER (blocking)."""
    return parallel_facets(data, "missed_directive_facets", missed)


# SECURITY-LENS-PLATFORM-FACTS (owner 11-13): the facets the security reviewer can label. Only per-service access is a
# security matter (a budget cap or a sandbox lifespan is not); the reply's closed set is these plus OTHER.
SECURITY_FACETS = (FACET_PER_SERVICE_ACCESS,)
SECURITY_REPLY_FACETS = SECURITY_FACETS + (FACET_OTHER,)


def security_handled(handled: Optional[Mapping[str, "PlatformHandling"]]) -> Dict[str, "PlatformHandling"]:
    """The handled facets that apply to the security reviewer ({} = none: no facet rubric, no facet field, and the
    verdict path exactly as before)."""
    return {f: h for f, h in (handled or {}).items() if f in SECURITY_FACETS}


def security_facet_rubric(handled: Mapping[str, PlatformHandling]) -> str:
    """The security reviewer's facet rubric for its handled facets ("" when none). The facts themselves are in the
    shared PLATFORM FACTS section (facts_lines); this only says how to label a critical finding."""
    facets = [f for f in SECURITY_FACETS if f in handled]
    if not facets:
        return ""
    meanings = "; ".join(f"{f} ({FACET_MEANINGS[f]})" for f in facets + [FACET_OTHER])
    lines = [f"- Facets: for each entry of `critical_vulnerabilities`, at the same position in "
             f"`critical_vulnerability_facets`, its facet: {meanings}."]
    if FACET_PER_SERVICE_ACCESS in facets:
        lines.append(
            f"- That a Cloud Run service of this workload accepts every caller at the platform level (an `allUsers` "
            f"invoker binding, `allow_unauthenticated`, `--allow-unauthenticated` in the platform's deploy workflow, or "
            f"ingress that is not internal-only) is the documented platform limitation the PLATFORM FACTS below name "
            f"for facet {FACET_PER_SERVICE_ACCESS}, not a defect of the workload's code or IaC. If you still list such a "
            f"finding, label it {FACET_PER_SERVICE_ACCESS} and name its file. The application's own checks of who a "
            f"caller is (verifying an identity token's signature, issuer, audience or email, or any APPLICATION "
            f"AUTHENTICATION item above) are NOT covered by that fact: judge them exactly as before and label them "
            f"{FACET_OTHER}.")
    return "\n".join(lines) + "\n"


def facts_lines(handled: Mapping[str, PlatformHandling]) -> List[str]:
    """The PLATFORM FACTS lines for the handled facets (fixed facet order)."""
    lines: List[str] = []
    for facet in FACETS:
        h = handled.get(facet)
        if h is None or facet not in _FACT_TITLES:
            continue
        met = ("is met by the platform" if h.kind == KIND_SATISFIED
               else "is a documented platform limitation for this workload, not a defect of its code")
        lines.append(
            f"- {_FACT_TITLES[facet]} (facet {facet}): {h.how} A plan task, acceptance criterion or specification "
            f"requirement for {FACET_MEANINGS[facet]} {met}: do not report it as missing from the code or IaC, and "
            f"it never lowers the adherence score. If you still list it, label it {facet}.")
    return lines


def summary_note(handled: Mapping[str, PlatformHandling], entries: List[Mapping[str, Any]]) -> str:
    """The QA summary sentences for the handled findings (each facet once, fixed order). "" when there are none."""
    out: List[str] = []
    for kind, lead in ((KIND_SATISFIED, "Satisfied by the platform, not judged against the code: "),
                       (KIND_LIMITATION, "Documented platform limitation, not a code defect (advisory): ")):
        parts = []
        for facet in FACETS:
            h = handled.get(facet)
            count = sum(1 for e in entries if e.get("facet") == facet)
            if count and h is not None and h.kind == kind:
                # IAM-POLICY-PLATFORM-FACT RT 3: the refused role(s) are named (a closed set: only exact table roles)
                roles = sorted({e.get("denied_role") for e in entries
                                if e.get("facet") == facet and is_denied_role(e.get("denied_role"))})
                parts.append(f"{facet} ({h.note}; {count} finding(s)"
                             + (f"; role(s): {', '.join(roles)}" if roles else "") + ")")
        if parts:
            out.append(lead + "; ".join(parts) + ".")
    return " ".join(out)
