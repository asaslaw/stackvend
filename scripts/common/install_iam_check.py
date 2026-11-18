#!/usr/bin/env python3
"""StackVend read-only install IAM check: the analysis half of scripts/check-install-iam.sh (FD-4DB, FD-4CT).

Reports IAM grants on the host project, the managed workloads folder, the billing account, the deletion-safety tag
(key and value) and the StackVend service accounts that were made OUTSIDE the platform Terraform and that reach past
the lane 18 destructive guards (infra/platform/destructive_guard.tf): project / folder delete or IAM admin, writes to
the stackvend-guard database, acting as a platform service account, billing admin, tag admin / user on the tag, or a
StackVend service account holding any role beyond its Terraform set.

The expected grants come ONLY from the applied platform Terraform state (the raw state file, or `tofu show -json` of
it): every google_*_iam_member / _binding / _policy instance in it. No project id, folder id, billing account or
service-account email is hard-coded (AGENTS.md invariant 3); role names are the only constants (the catalog below).

This module never calls an API and never writes anything outside the paths it is given. The shell wrapper does the
read-only fetches (getIamPolicy over REST, `gcloud storage cat` of the state) and passes the files in.

FD-7L (SAT-33): once the runner identity step A is in the state, runner_identity_findings() also checks the APPLIED
Terraform itself (a declared grant can still be wrong): no Secret Manager / platform-state / folder / billing /
job-update / token-minting access for the runner SAs, no act-as on them (except vending's optional act-as on the job
SA, and SELFUP-B's upgrader sa-stackvend-upgrader holding exactly roles/iam.serviceAccountUser on either runner SA so
the "Update StackVend" button can deploy new revisions of tf-applier and the terraform server; register row
FD7L-UPGRADER-ACTAS), no stackvend-deployer bound in the host scopes, vending not on a shared identity. inputs "deployers" (listed by
the shell from the guard-database provenance) adds each deployer's own policy: only vending may hold tokenCreator.

Subcommands:
  runner-identity-installed --state S            print "yes" when the FD-7L runner SAs are in the state
  targets --state S --inputs I [--skip K]...     print the getIamPolicy calls to make (TSV: name, method, url, body)
  analyze --state S --inputs I --policies DIR [--admin M]... [--billing-fallback ROLE=ACCOUNT_ID]... [--skip K]...
          [--json]                               print the report; exit 0 clean, 1 findings, 2 could not check

inputs.json: {"project": "<host project id>", "folder": "<folders/N or N or ''>", "billing_account": "<id or ''>",
              "organization": "<organizations/N or ''>", "admins": ["user:a@example.com", ...]}
Policies dir: <name>.json (the getIamPolicy response) and <name>.http (the HTTP status; absent means 200).

Python 3.8+ (macOS system python3), standard library only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
from typing import Dict, Iterable, Iterator, List, NamedTuple, Optional, Set, Tuple

EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_UNCHECKED = 2

SCOPE_KINDS = ("project", "folder", "billing", "tag_key", "tag_value", "service_account", "deployer")
# --skip values (operator flags) -> scope kinds.
SKIP_CHOICES = {
    "project": ("project",),
    "folder": ("folder",),
    "billing": ("billing",),
    "tags": ("tag_key", "tag_value"),
    "service-accounts": ("service_account",),
    "deployers": ("deployer",),
}

# ------------------------------------------------------------------------------
# FD-7L (SAT-33, plan §4 last bullet): Terraform runner identity posture. Exact account ids from
# infra/platform/tf_runner_identity.tf and shared/runner_identity.py; no e-mail is hard-coded.
# ------------------------------------------------------------------------------
RUNNER_JOB_ACCOUNT_ID = "sa-stackvend-tf-applier"
RUNNER_ACCOUNT_IDS = frozenset({RUNNER_JOB_ACCOUNT_ID, "sa-stackvend-tf-server"})
# SELFUP-B (infra/platform/platform_upgrader.tf, H-1 / row FD7L-UPGRADER-ACTAS): the one other act-as allowed on a
# runner SA. Only roles/iam.serviceAccountUser, and only when the upgrader is this install's own SA (in the state).
UPGRADER_ACCOUNT_ID = "sa-stackvend-upgrader"
DEPLOYER_ACCOUNT_ID = "stackvend-deployer"
DEVELOPER_ACCOUNT_ID = "sa-castor-developer"
VENDING_SERVICE_NAME = "project-repo-vending-service"
STATE_BUCKET_PREFIX = "castor-tfstate-"          # data.google_storage_bucket.workload_tfstate_bucket (main.tf)
TOKEN_CREATOR = "roles/iam.serviceAccountTokenCreator"
ACT_AS_USER = "roles/iam.serviceAccountUser"
# Roles that let a member act as / mint tokens for / administer a service account.
ACT_AS_ROLES = frozenset({
    TOKEN_CREATOR, ACT_AS_USER, "roles/iam.workloadIdentityUser", "roles/iam.serviceAccountOpenIdTokenCreator",
    "roles/iam.serviceAccountKeyAdmin", "roles/iam.serviceAccountAdmin", "roles/owner", "roles/editor",
})
# Plan §4 "Not granted" for either runner SA (besides Secret Manager, the state bucket and folder scopes).
RUNNER_FORBIDDEN_ROLES = ACT_AS_ROLES | frozenset({
    "roles/run.developer", "roles/run.admin", "roles/workflows.invoker", "roles/workflows.admin",
    "roles/storage.admin", "roles/storage.objectAdmin", "roles/storage.objectViewer", "roles/storage.objectUser",
    "roles/storage.objectCreator", "roles/billing.user", "roles/billing.admin", "roles/billing.projectManager",
    "roles/datastore.owner", "roles/resourcemanager.projectIamAdmin", "roles/iam.securityAdmin",
})
RUNNER_WHY = ("a Terraform runner service account (FD-7L) must hold no Secret Manager, platform state, folder, "
              "billing, job-update or token-minting access: a token stolen from workload OpenTofu would carry it")

CRM_V3 = "https://cloudresourcemanager.googleapis.com/v3/"
BILLING_V1 = "https://cloudbilling.googleapis.com/v1/"
IAM_V1 = "https://iam.googleapis.com/v1/"
POLICY_V3_BODY = '{"options":{"requestedPolicyVersion":3}}'

_SAFE_NAME = re.compile(r"^[a-z0-9_-]{1,80}$")
_DIGITS = re.compile(r"^[0-9]+$")
_BILLING_ID = re.compile(r"^[0-9A-F]{6}-[0-9A-F]{6}-[0-9A-F]{6}$")
_PROJECT_ID = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")
_EMAIL = re.compile(r"^[^@\s:/]+@[^@\s:/]+$")


class CheckError(Exception):
    """The check cannot produce a trustworthy answer (exit 2)."""


# ------------------------------------------------------------------------------
# Role catalog: what reaches past the lane 18 guards, per scope. A grant that is not in the Terraform state is a
# finding when its role is listed for its scope, or when its member is a StackVend service account (any role).
# ------------------------------------------------------------------------------
_GUARD_DB = ("can write the stackvend-guard database, so it can forge the provenance / approval records the "
             "destructive guards trust")
_ACT_AS = ("can act as the host service accounts, including the only destructive executors (vending, Control "
           "Center, sandbox cleaner)")
_SET_IAM_PROJECT = "can change host project IAM, so it can grant itself any role (including the guard writers')"

PROJECT_ROLES: Dict[str, str] = {
    "roles/owner": "can delete the host project, change any IAM and write the stackvend-guard database",
    "roles/editor": "can write the stackvend-guard database and deploy code as the host service accounts",
    "roles/resourcemanager.projectIamAdmin": _SET_IAM_PROJECT,
    "roles/iam.securityAdmin": _SET_IAM_PROJECT,
    "roles/resourcemanager.projectDeleter": "can delete the host project",
    "roles/resourcemanager.lienModifier": "can remove the liens that protect the host project from deletion",
    "roles/datastore.owner": _GUARD_DB,
    "roles/datastore.user": _GUARD_DB,
    "roles/datastore.importExportAdmin": "can import documents into the stackvend-guard database",
    "roles/firebase.admin": _GUARD_DB,
    "roles/iam.serviceAccountTokenCreator": _ACT_AS,
    "roles/iam.serviceAccountUser": _ACT_AS,
    "roles/iam.workloadIdentityUser": _ACT_AS,
    "roles/iam.serviceAccountKeyAdmin": "can create keys for the host service accounts (act as the guard executors)",
    "roles/iam.serviceAccountAdmin": "can change service-account IAM, so it can give itself act-as on the guard "
                                     "executors",
    "roles/run.admin": "can deploy a new revision of the vending or Control Center service (replace the guard code)",
    "roles/run.developer": "can deploy a new revision of the vending or Control Center service (replace the guard "
                           "code)",
    "roles/cloudbuild.builds.editor": "can run builds as the Cloud Build service account, which deploys the "
                                      "platform services",
}

_FOLDER_ALL_CHILDREN = "on every current and future child project in the managed workloads folder"
FOLDER_ROLES: Dict[str, str] = {
    "roles/owner": "can delete any child project and change folder IAM, outside the vending guards",
    "roles/editor": "edit access " + _FOLDER_ALL_CHILDREN + ", outside the vending guards",
    "roles/resourcemanager.folderAdmin": "can delete child projects and change folder IAM, outside the vending "
                                         "guards",
    "roles/resourcemanager.folderIamAdmin": "can change folder IAM, so it can grant itself project delete",
    "roles/resourcemanager.folderEditor": "can modify the folder and move or change the projects under it",
    "roles/resourcemanager.folderMover": "can move folders out of the managed workloads folder",
    "roles/resourcemanager.projectDeleter": "can delete any child project directly, bypassing the decommission "
                                            "guard",
    "roles/resourcemanager.projectIamAdmin": "can change IAM " + _FOLDER_ALL_CHILDREN,
    "roles/iam.securityAdmin": "can change IAM " + _FOLDER_ALL_CHILDREN,
    "roles/resourcemanager.projectMover": "can move child projects out of the managed workloads folder",
    "roles/resourcemanager.lienModifier": "can remove liens that protect child projects from deletion",
    "roles/resourcemanager.tagUser": "can bind or unbind the deletion-safety tag on child projects",
    "roles/resourcemanager.tagAdmin": "can bind or unbind the deletion-safety tag on child projects",
    "roles/resourcemanager.projectCreator": "can create projects in the managed workloads folder outside vending",
    "roles/resourcemanager.folderCreator": "can create folders in the managed workloads folder outside vending",
    "roles/iam.serviceAccountTokenCreator": "can act as the service accounts " + _FOLDER_ALL_CHILDREN,
    "roles/iam.serviceAccountUser": "can act as the service accounts " + _FOLDER_ALL_CHILDREN,
}

BILLING_ROLES: Dict[str, str] = {
    "roles/billing.admin": "can change billing-account IAM and unlink or relink any project (bypasses the FinOps "
                           "quarantine)",
    "roles/billing.user": "can link projects to this billing account outside vending",
    "roles/billing.projectManager": "can unlink or relink project billing (bypasses the FinOps quarantine)",
}

# Tag key / value: anything but viewing changes who may mark a project as StackVend-managed (lane 18 S0).
TAG_VIEW_ROLES = frozenset({"roles/resourcemanager.tagViewer"})
TAG_REASON = ("can bind the deletion-safety tag to a project or change the tag, so it decides which projects the "
              "decommission guard treats as StackVend-managed")
# StackVend service account policies: any grant lets the member act as or administer that identity.
SA_REASON = "can act as or administer this StackVend service account (and so reach every guard it can pass)"
EXTRA_ROLE_REASON = ("a StackVend service account holds a role outside its Terraform set (lane 18 sized each "
                     "identity's roles; an extra role widens what that service can do)")

# Roles reported even for Google-managed service agents (these never need them).
DESTRUCTIVE_ROLES = frozenset({
    "roles/owner", "roles/resourcemanager.projectDeleter", "roles/resourcemanager.folderAdmin",
    "roles/resourcemanager.folderIamAdmin", "roles/resourcemanager.projectIamAdmin", "roles/iam.securityAdmin",
    "roles/billing.admin", "roles/resourcemanager.tagAdmin",
})


def role_reason(kind: str, role: str) -> Optional[str]:
    """Why a role on this scope reaches past the guards, or None when it does not."""
    if kind == "project":
        return PROJECT_ROLES.get(role)
    if kind == "folder":
        return FOLDER_ROLES.get(role)
    if kind == "billing":
        return BILLING_ROLES.get(role)
    if kind in ("tag_key", "tag_value"):
        return None if role in TAG_VIEW_ROLES else TAG_REASON
    if kind == "service_account":
        return SA_REASON
    return None


# ------------------------------------------------------------------------------
# Normalization (IAM ids appear in several equivalent forms between the state and the API)
# ------------------------------------------------------------------------------
def norm_member(member: str) -> str:
    """Lower-case the e-mail part of user/group/serviceAccount/domain members (IAM e-mails are case-insensitive)."""
    m = (member or "").strip()
    prefix, sep, rest = m.partition(":")
    if sep and prefix in ("user", "group", "serviceAccount", "domain"):
        return prefix + ":" + rest.lower()
    return m


def norm_scope(kind: str, raw: str) -> str:
    v = (raw or "").strip()
    if kind == "project":
        return v[len("projects/"):] if v.startswith("projects/") else v
    if kind == "folder":
        return "folders/" + v if _DIGITS.match(v) else v
    if kind == "billing":
        v = v[len("billingAccounts/"):] if v.startswith("billingAccounts/") else v
        return v.upper()
    if kind == "tag_key":
        return "tagKeys/" + v if _DIGITS.match(v) else v
    if kind == "tag_value":
        return "tagValues/" + v if _DIGITS.match(v) else v
    if kind == "service_account":
        # projects/<p>/serviceAccounts/<email> (the resource's .name / .id) or a bare e-mail
        return v.rsplit("/", 1)[-1].lower()
    return v


class Grant(NamedTuple):
    kind: str
    scope: str
    role: str
    member: str
    condition: str  # the CEL expression, "" when unconditioned


# ------------------------------------------------------------------------------
# State reading (raw state v4 or `tofu show -json`)
# ------------------------------------------------------------------------------
def _iter_show_module(module: dict) -> Iterator[Tuple[str, str, dict]]:
    for r in module.get("resources") or []:
        if isinstance(r, dict):
            yield r.get("mode", "managed"), r.get("type", ""), r.get("values") or {}
    for child in module.get("child_modules") or []:
        if isinstance(child, dict):
            yield from _iter_show_module(child)


def iter_state_resources(state: dict) -> Iterator[Tuple[str, str, dict]]:
    """Yields (mode, type, attributes) for every resource instance in the state."""
    if not isinstance(state, dict):
        raise CheckError("the state is not a JSON object")
    if isinstance(state.get("resources"), list):  # raw state file (format version 4)
        for r in state["resources"]:
            if not isinstance(r, dict):
                continue
            for inst in r.get("instances") or []:
                if isinstance(inst, dict):
                    yield r.get("mode", "managed"), r.get("type", ""), inst.get("attributes") or {}
        return
    values = state.get("values")
    if values is None and isinstance(state.get("prior_state"), dict):  # `tofu show -json <plan>`: applied state
        values = state["prior_state"].get("values")
    if isinstance(values, dict) and isinstance(values.get("root_module"), dict):
        yield from _iter_show_module(values["root_module"])
        return
    raise CheckError("the state is neither a Terraform/OpenTofu state file nor `tofu show -json` output")


_IAM_TYPES = {
    "google_project_iam_": ("project", "project"),
    "google_folder_iam_": ("folder", "folder"),
    "google_billing_account_iam_": ("billing", "billing_account_id"),
    "google_tags_tag_key_iam_": ("tag_key", "tag_key"),
    "google_tags_tag_value_iam_": ("tag_value", "tag_value"),
    "google_service_account_iam_": ("service_account", "service_account_id"),
}


def _iam_kind(rtype: str) -> Optional[Tuple[str, str, str]]:
    for prefix, (kind, attr) in _IAM_TYPES.items():
        if rtype.startswith(prefix):
            flavor = rtype[len(prefix):]
            if flavor in ("member", "binding", "policy"):
                return kind, attr, flavor
    return None


def _condition_expr(cond) -> str:
    if isinstance(cond, list):
        cond = cond[0] if cond else None
    if isinstance(cond, dict):
        return str(cond.get("expression") or "")
    return ""


class AnyGrant(NamedTuple):
    """Every IAM grant in the state, of any resource type (FD-7L posture checks)."""
    rtype: str
    scope: str
    role: str
    member: str


class PlatformState(NamedTuple):
    expected: Set[Grant]
    service_accounts: Dict[str, str]  # email -> account_id (google_service_account resources)
    platform_members: Set[str]        # serviceAccount members that are StackVend identities
    project_id: str
    project_number: str
    tag_keys: List[str]
    tag_values: List[str]
    all_grants: List[AnyGrant] = []
    vending_runtime: str = ""         # template service account of project-repo-vending-service ("" = unknown)


_ANY_IAM_SCOPE_ATTRS = ("bucket", "secret_id", "service_account_id", "project", "folder", "org_id",
                        "billing_account_id", "tag_value", "tag_key", "name")


def _any_iam_flavor(rtype: str) -> str:
    if not rtype.startswith("google_"):
        return ""
    for flavor in ("member", "binding", "policy"):
        if rtype.endswith("_iam_" + flavor):
            return flavor
    return ""


def _any_grants(rtype: str, attrs: dict) -> List[AnyGrant]:
    flavor = _any_iam_flavor(rtype)
    if not flavor:
        return []
    scope = ""
    for a in _ANY_IAM_SCOPE_ATTRS:
        if attrs.get(a):
            scope = str(attrs.get(a))
            break
    if rtype.startswith("google_storage_bucket_iam_") and scope.startswith("b/"):
        scope = scope[2:]
    if flavor == "member":
        return [AnyGrant(rtype, scope, str(attrs.get("role") or ""), norm_member(str(attrs.get("member") or "")))]
    if flavor == "binding":
        return [AnyGrant(rtype, scope, str(attrs.get("role") or ""), norm_member(str(m)))
                for m in attrs.get("members") or []]
    try:
        pol = json.loads(attrs.get("policy_data") or "{}")
    except ValueError:
        raise CheckError(f"{rtype} in the state has unreadable policy_data")
    return [AnyGrant(rtype, scope, str(b.get("role") or ""), norm_member(str(m)))
            for b in pol.get("bindings") or [] for m in b.get("members") or []]


def account_id_of(member_or_email: str) -> str:
    """Account id (local part) of a service-account member or e-mail; '' for anything else."""
    v = (member_or_email or "").strip()
    if v.startswith("serviceAccount:"):
        v = v[len("serviceAccount:"):]
    elif ":" in v:
        return ""
    if v.count("@") != 1:
        return ""
    local, domain = v.split("@")
    return local.lower() if domain.lower().endswith(".iam.gserviceaccount.com") else ""


def _vending_runtime(attrs: dict) -> str:
    tmpl = attrs.get("template")
    if isinstance(tmpl, list) and tmpl and isinstance(tmpl[0], dict):
        return str(tmpl[0].get("service_account") or "").lower()
    return ""


def read_platform_state(state: dict) -> PlatformState:
    expected: Set[Grant] = set()
    sas: Dict[str, str] = {}
    project_id = project_number = ""
    tag_keys: List[str] = []
    tag_values: List[str] = []
    all_grants: List[AnyGrant] = []
    vending_runtime = ""
    for mode, rtype, attrs in iter_state_resources(state):
        if mode == "data" and rtype == "google_project":
            project_id = str(attrs.get("project_id") or project_id)
            project_number = str(attrs.get("number") or project_number)
            continue
        if mode != "managed":
            continue
        all_grants.extend(_any_grants(rtype, attrs))
        if rtype == "google_cloud_run_v2_service" and attrs.get("name") == VENDING_SERVICE_NAME:
            vending_runtime = _vending_runtime(attrs)
            continue
        if rtype == "google_service_account":
            email = str(attrs.get("email") or "").lower()
            if email:
                sas[email] = str(attrs.get("account_id") or "")
            continue
        if rtype == "google_tags_tag_key":
            tid = norm_scope("tag_key", str(attrs.get("id") or attrs.get("name") or ""))
            if tid:
                tag_keys.append(tid)
            continue
        if rtype == "google_tags_tag_value":
            tid = norm_scope("tag_value", str(attrs.get("id") or attrs.get("name") or ""))
            if tid:
                tag_values.append(tid)
            continue
        kind_info = _iam_kind(rtype)
        if not kind_info:
            continue
        kind, attr, flavor = kind_info
        scope = norm_scope(kind, str(attrs.get(attr) or ""))
        if flavor == "member":
            expected.add(Grant(kind, scope, str(attrs.get("role") or ""), norm_member(str(attrs.get("member") or "")),
                               _condition_expr(attrs.get("condition"))))
        elif flavor == "binding":
            for m in attrs.get("members") or []:
                expected.add(Grant(kind, scope, str(attrs.get("role") or ""), norm_member(str(m)),
                                   _condition_expr(attrs.get("condition"))))
        else:  # authoritative _policy: policy_data is the policy JSON
            try:
                pol = json.loads(attrs.get("policy_data") or "{}")
            except ValueError:
                raise CheckError(f"{rtype} in the state has unreadable policy_data")
            for b in pol.get("bindings") or []:
                for m in b.get("members") or []:
                    expected.add(Grant(kind, scope, str(b.get("role") or ""), norm_member(str(m)),
                                       _condition_expr(b.get("condition"))))
    if not sas:
        raise CheckError("the state has no google_service_account resources: it is not an applied StackVend "
                         "platform state (expected infra/platform state)")
    platform_members = {"serviceAccount:" + e for e in sas}
    for g in expected:
        if g.member.startswith("serviceAccount:") and not _is_google_agent(g.member, project_number):
            platform_members.add(g.member)
    return PlatformState(expected, sas, platform_members, project_id, project_number, sorted(set(tag_keys)),
                         sorted(set(tag_values)), all_grants, vending_runtime)


def _is_google_agent(member: str, project_number: str) -> bool:
    """Google-managed service agents OF THE HOST PROJECT (documented e-mail forms; the number must match).

    service-<number>@<agent>.iam.gserviceaccount.com, <number>@cloudservices.gserviceaccount.com and
    <number>@cloudbuild.gserviceaccount.com. The default compute SA (<number>-compute@developer...) is NOT an agent:
    anyone with act-as can run code as it (FD-4CT item 1).
    """
    if not project_number or not member.startswith("serviceAccount:"):
        return False
    local, _, domain = member[len("serviceAccount:"):].partition("@")
    if local == "service-" + project_number and domain.endswith(".iam.gserviceaccount.com"):
        return True
    return local == project_number and domain in ("cloudservices.gserviceaccount.com",
                                                  "cloudbuild.gserviceaccount.com")


# ------------------------------------------------------------------------------
# Targets: which policies to read
# ------------------------------------------------------------------------------
class Target(NamedTuple):
    name: str
    kind: str
    scope: str
    method: str
    url: str
    body: str  # "-" = no body


def _inputs(inputs: dict) -> Tuple[str, str, str]:
    if not isinstance(inputs, dict):
        raise CheckError("inputs.json is not a JSON object")
    project = str(inputs.get("project") or "")
    if not _PROJECT_ID.match(project):
        raise CheckError(f"inputs: project {project!r} is not a valid project id")
    folder = norm_scope("folder", str(inputs.get("folder") or ""))
    if folder and not (folder.startswith("folders/") and _DIGITS.match(folder[len("folders/"):])):
        raise CheckError(f"inputs: folder {folder!r} is not folders/<digits>")
    billing = norm_scope("billing", str(inputs.get("billing_account") or ""))
    if billing and not _BILLING_ID.match(billing):
        raise CheckError(f"inputs: billing account {billing!r} is not XXXXXX-XXXXXX-XXXXXX")
    return project, folder, billing


def build_targets(ps: PlatformState, inputs: dict, skip_kinds: Iterable[str] = ()) -> List[Target]:
    project, folder, billing = _inputs(inputs)
    if ps.project_id and ps.project_id != project:
        raise CheckError(f"the state belongs to project {ps.project_id!r}, not {project!r}: refusing to mix installs")
    skip = set(skip_kinds)
    out: List[Target] = []
    if "project" not in skip:
        out.append(Target("project", "project", project, "POST", f"{CRM_V3}projects/{project}:getIamPolicy",
                          POLICY_V3_BODY))
    if folder and "folder" not in skip:
        out.append(Target("folder", "folder", folder, "POST", f"{CRM_V3}{folder}:getIamPolicy", POLICY_V3_BODY))
    if billing and "billing" not in skip:
        out.append(Target("billing", "billing", billing, "GET",
                          f"{BILLING_V1}billingAccounts/{billing}:getIamPolicy?options.requestedPolicyVersion=3",
                          "-"))
    if "tag_key" not in skip:
        for i, tk in enumerate(ps.tag_keys):
            if _DIGITS.match(tk[len("tagKeys/"):]):
                out.append(Target(f"tag_key_{i}", "tag_key", tk, "POST", f"{CRM_V3}{tk}:getIamPolicy", POLICY_V3_BODY))
    if "tag_value" not in skip:
        for i, tv in enumerate(ps.tag_values):
            if _DIGITS.match(tv[len("tagValues/"):]):
                out.append(Target(f"tag_value_{i}", "tag_value", tv, "POST", f"{CRM_V3}{tv}:getIamPolicy",
                                  POLICY_V3_BODY))
    if "service_account" not in skip:
        for i, email in enumerate(sorted(ps.service_accounts)):
            if not _EMAIL.match(email):
                continue
            out.append(Target(f"sa_{i}", "service_account", email, "POST",
                              f"{IAM_V1}projects/-/serviceAccounts/{email}:getIamPolicy"
                              "?options.requestedPolicyVersion=3", "{}"))
    # FD-7L: each workload's deployer (stackvend-deployer@<child>), listed by scripts/check-install-iam.sh from the
    # guard-database provenance (inputs "deployers"); only exact deployer e-mails are read.
    if "deployer" not in skip:
        raw = inputs.get("deployers") or []
        if not isinstance(raw, list):
            raise CheckError("inputs: deployers is not a list")
        for i, email in enumerate(sorted({str(e).strip().lower() for e in raw})):
            if not _EMAIL.match(email) or account_id_of(email) != DEPLOYER_ACCOUNT_ID:
                raise CheckError(f"inputs: deployer {email!r} is not a stackvend-deployer service account")
            out.append(Target(f"deployer_{i}", "deployer", email, "POST",
                              f"{IAM_V1}projects/-/serviceAccounts/{email}:getIamPolicy"
                              "?options.requestedPolicyVersion=3", "{}"))
    for t in out:  # the shell reads these as TSV and uses the name as a file name
        if not _SAFE_NAME.match(t.name) or any(c in t.url + t.body for c in "\t\n\r"):
            raise CheckError(f"internal: unsafe target {t.name!r}")
    return out


# ------------------------------------------------------------------------------
# Analysis
# ------------------------------------------------------------------------------
class Finding(NamedTuple):
    kind: str
    scope: str
    member: str
    role: str
    condition: str
    condition_title: str
    why: str
    fix: str


def _other_project_note(member: str, host_project: str) -> str:
    if not member.startswith("serviceAccount:"):
        return ""
    domain = member.partition("@")[2]
    suffix = ".iam.gserviceaccount.com"
    if domain.endswith(suffix) and domain[: -len(suffix)] != host_project:
        return f" (a service account of another project: {domain[: -len(suffix)]})"
    return ""


def fix_command(kind: str, scope: str, member: str, role: str, condition: str, condition_title: str,
                host_project: str) -> str:
    q = shlex.quote
    base = {
        "project": f"gcloud projects remove-iam-policy-binding {q(scope)}",
        "folder": f"gcloud resource-manager folders remove-iam-policy-binding {q(scope[len('folders/'):])}",
        "billing": f"gcloud billing accounts remove-iam-policy-binding {q(scope)}",
        "tag_key": f"gcloud resource-manager tags keys remove-iam-policy-binding {q(scope)}",
        "tag_value": f"gcloud resource-manager tags values remove-iam-policy-binding {q(scope)}",
        "service_account": f"gcloud iam service-accounts remove-iam-policy-binding {q(scope)} "
                           f"--project={q(host_project)}",
        "deployer": f"gcloud iam service-accounts remove-iam-policy-binding {q(scope)} "
                    f"--project={q(scope.partition('@')[2][:-len('.iam.gserviceaccount.com')])}",
    }[kind]
    cmd = f"{base} --member={q(member)} --role={q(role)}"
    if condition:
        if "," in condition or "," in condition_title or not condition_title:
            cmd += " --condition-from-file=<a file holding this binding's condition (expression, title)>"
        else:
            cmd += " " + q(f"--condition=expression={condition},title={condition_title}")
    elif kind in ("project", "folder", "service_account", "deployer"):
        cmd += " --condition=None"
    return cmd


def runner_identity_findings(ps: "PlatformState") -> List["Finding"]:
    """FD-7L posture of the APPLIED Terraform (plan §4 last bullet). Grants declared in infra/platform are otherwise
    'expected'; these rules hold even for declared grants, so a future Terraform change cannot quietly widen a
    runner. Out-of-Terraform grants on the host scopes are reported by the generic pass in analyze()."""
    out: List[Finding] = []
    runners = {e for e, acc in ps.service_accounts.items() if acc in RUNNER_ACCOUNT_IDS}
    if not runners:
        return out   # step A not applied on this install: nothing FD-7L to check
    state_bucket = STATE_BUCKET_PREFIX + ps.project_id if ps.project_id else ""
    tf_fix = "remove the grant from infra/platform Terraform and run scripts/apply.sh apply (it is declared there)"

    def add(scope: str, member: str, role: str, why: str, fix: str = tf_fix):
        out.append(Finding("runner_identity", scope, member, role, "", "", why, fix))

    for g in ps.all_grants:
        acc = account_id_of(g.member)
        where = f"{g.rtype} {g.scope}"
        if acc == DEPLOYER_ACCOUNT_ID:
            add(where, g.member, g.role, "a workload deployer (stackvend-deployer) holds a grant in the platform "
                "Terraform: a deployer has rights only in its own project")
            continue
        if acc in RUNNER_ACCOUNT_IDS:
            bad = (g.rtype.startswith("google_secret_manager_") or g.role.startswith("roles/secretmanager.")
                   or g.rtype.startswith(("google_folder_iam_", "google_organization_iam_",
                                          "google_billing_account_iam_"))
                   or (g.rtype.startswith("google_storage_bucket_iam_") and state_bucket and g.scope == state_bucket)
                   or g.role in ACT_AS_ROLES
                   or (g.rtype.startswith("google_project_iam_") and g.role in RUNNER_FORBIDDEN_ROLES))
            if bad:
                add(where, g.member, g.role, RUNNER_WHY)
        # act-as / token grants ON a runner SA: only vending's Phase-0 act-as on the job SA, and the SELFUP-B
        # upgrader's serviceAccountUser on either runner SA (H-1), are allowed.
        if g.rtype.startswith("google_service_account_iam_") and g.role in ACT_AS_ROLES:
            target = norm_scope("service_account", g.scope)
            if account_id_of(target) in RUNNER_ACCOUNT_IDS:
                allowed = (g.role == ACT_AS_USER and account_id_of(target) == RUNNER_JOB_ACCOUNT_ID
                           and ps.vending_runtime and g.member == "serviceAccount:" + ps.vending_runtime)
                upgrader = (g.role == ACT_AS_USER and account_id_of(g.member) == UPGRADER_ACCOUNT_ID
                            and g.member[len("serviceAccount:"):] in ps.service_accounts)
                if not (allowed or upgrader):
                    add(where, g.member, g.role, "an identity can act as or mint tokens for a Terraform runner "
                        "service account (FD-7L allows only vending's act-as on the job SA, var.tf_runner_vending_act_as, "
                        "and the upgrader sa-stackvend-upgrader's serviceAccountUser, row FD7L-UPGRADER-ACTAS)")
    vend_acc = account_id_of(ps.vending_runtime)
    if vend_acc in RUNNER_ACCOUNT_IDS or vend_acc == DEVELOPER_ACCOUNT_ID:
        add(f"google_cloud_run_v2_service {VENDING_SERVICE_NAME}", "serviceAccount:" + ps.vending_runtime,
            "(runtime identity)", "vending (the deployer-token broker) runs as a shared identity, so it refuses every "
            "mint (RUNNER_BROKER_SHARED_IDENTITY, plan R9)",
            "set vending_runs_as_provisioner = true in the tfvars and run scripts/apply.sh apply")
    return out


class Report(NamedTuple):
    project: str
    findings: List[Finding]
    checked: List[Tuple[str, str, str]]    # (kind, scope, "ok" | reason)
    skipped: List[str]                     # scope kinds skipped on request
    unchecked: List[str]                   # human-readable reasons (exit 2)
    counts: Dict[str, int]
    expected_total: int
    service_account_total: int
    organization: str

    @property
    def exit_code(self) -> int:
        if self.unchecked:
            return EXIT_UNCHECKED
        return EXIT_FINDINGS if self.findings else EXIT_CLEAN


def _load_policy(policies_dir: str, name: str) -> Tuple[Optional[dict], str]:
    """(policy, "") or (None, reason)."""
    path = os.path.join(policies_dir, name + ".json")
    code_path = os.path.join(policies_dir, name + ".http")
    code = "200"
    if os.path.exists(code_path):
        with open(code_path) as f:
            code = f.read().strip() or "none"
    if code != "200":
        return None, f"getIamPolicy answered HTTP {code}"
    try:
        with open(path) as f:
            pol = json.load(f)
    except OSError:
        return None, "no getIamPolicy response"
    except ValueError:
        return None, "unreadable getIamPolicy response"
    if not isinstance(pol, dict) or not isinstance(pol.get("bindings", []), list):
        return None, "unexpected getIamPolicy response shape"
    return pol, ""


def analyze(state: dict, inputs: dict, policies_dir: str, admins: Iterable[str] = (),
            billing_fallback: Iterable[Tuple[str, str]] = (), skip_kinds: Iterable[str] = ()) -> Report:
    """billing_fallback: (role, account_id) pairs that scripts/bootstrap.sh may grant with gcloud outside Terraform
    (BG-1 fallback); the member e-mail is taken from the state's google_service_account with that account_id."""
    ps = read_platform_state(state)
    skip = set(skip_kinds)
    targets = build_targets(ps, inputs, skip)
    project = str(inputs.get("project"))
    admin_set = {norm_member(a if ":" in a else "user:" + a) for a in list(admins) + list(inputs.get("admins") or [])
                 if a}
    by_account = {acc: email for email, acc in ps.service_accounts.items() if acc}
    fallback = {(role, norm_member("serviceAccount:" + by_account[acc])) for role, acc in billing_fallback
                if acc in by_account}
    counts = {"terraform": 0, "administrator": 0, "google_agent": 0, "bootstrap_billing": 0, "not_guard_reaching": 0,
              "deleted_principal": 0, "broker": 0}
    findings: List[Finding] = runner_identity_findings(ps)
    checked: List[Tuple[str, str, str]] = []
    unchecked: List[str] = []
    broker_member = "serviceAccount:" + ps.vending_runtime if ps.vending_runtime else ""
    for t in targets:
        pol, reason = _load_policy(policies_dir, t.name)
        if pol is None and t.kind == "deployer" and reason == "getIamPolicy answered HTTP 404":
            checked.append((t.kind, t.scope, "not found (no deployer service account)"))
            continue
        if pol is None:
            checked.append((t.kind, t.scope, reason))
            unchecked.append(f"{t.kind} {t.scope}: {reason}")
            continue
        checked.append((t.kind, t.scope, "ok"))
        for b in pol.get("bindings") or []:
            if not isinstance(b, dict):
                continue
            role = str(b.get("role") or "")
            cond = b.get("condition") if isinstance(b.get("condition"), dict) else {}
            expr = str(cond.get("expression") or "")
            title = str(cond.get("title") or "")
            for raw_member in b.get("members") or []:
                member = norm_member(str(raw_member))
                if t.kind == "deployer":
                    # FD-7L: vending (the broker) is the ONLY identity that may mint a deployer's tokens; nobody else
                    # may act as it. The deployer's own policy is written by vending, never by Terraform.
                    if role not in ACT_AS_ROLES:
                        counts["not_guard_reaching"] += 1
                    elif role == TOKEN_CREATOR and broker_member and member == broker_member and not expr:
                        counts["broker"] += 1
                    else:
                        findings.append(_finding(t, member, role, expr, title,
                                                 "can act as or mint tokens for a workload deployer; only vending "
                                                 "(STACKVEND_BROKER_SA) may mint them (FD-7L plan §2.3)", project))
                    continue
                if Grant(t.kind, t.scope, role, member, expr) in ps.expected:
                    counts["terraform"] += 1
                    continue
                if member.startswith("deleted:"):
                    counts["deleted_principal"] += 1
                    continue
                if account_id_of(member) == DEPLOYER_ACCOUNT_ID:
                    findings.append(_finding(t, member, role, expr, title,
                                             "a workload deployer (stackvend-deployer) is bound outside its own "
                                             "project; a deployer has rights only there (FD-7L)", project))
                    continue
                if member in admin_set:
                    counts["administrator"] += 1
                    continue
                if t.kind == "billing" and not expr and (role, member) in fallback:
                    counts["bootstrap_billing"] += 1
                    continue
                why = role_reason(t.kind, role)
                if _is_google_agent(member, ps.project_number):
                    if role in DESTRUCTIVE_ROLES:
                        findings.append(_finding(t, member, role, expr, title,
                                                 (why or "destructive role") + " (Google service agents never need "
                                                 "this role)", project))
                    else:
                        counts["google_agent"] += 1
                    continue
                if member in ps.platform_members:
                    findings.append(_finding(t, member, role, expr, title, why or EXTRA_ROLE_REASON, project))
                    continue
                if why:
                    findings.append(_finding(t, member, role, expr, title,
                                             why + _other_project_note(member, project), project))
                else:
                    counts["not_guard_reaching"] += 1
    skipped = sorted({k for k in skip if k in SCOPE_KINDS})
    return Report(project, findings, checked, skipped, unchecked, counts, len(ps.expected), len(ps.service_accounts),
                  str(inputs.get("organization") or ""))


def _finding(t: Target, member: str, role: str, expr: str, title: str, why: str, project: str) -> Finding:
    if expr:
        why += f"; conditional binding '{title or 'untitled'}': check that its condition really excludes what " \
               "the guards protect"
    return Finding(t.kind, t.scope, member, role, expr, title, why,
                   fix_command(t.kind, t.scope, member, role, expr, title, project))


# ------------------------------------------------------------------------------
# Output
# ------------------------------------------------------------------------------
_SCOPE_LABEL = {"project": "project", "folder": "folder", "billing": "billing account", "tag_key": "tag key",
                "tag_value": "tag value", "service_account": "service account",
                "deployer": "workload deployer", "runner_identity": "runner identity (Terraform)"}


def _md_cell(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def render_text(r: Report) -> str:
    lines = [f"StackVend install IAM check (read-only) for host project {r.project}",
             f"Expected grants: {r.expected_total} from the applied platform Terraform state "
             f"({r.service_account_total} StackVend service accounts).", ""]
    lines.append("Checked:")
    sa_ok = sum(1 for k, _s, st in r.checked if k == "service_account" and st == "ok")
    dep_ok = sum(1 for k, _s, st in r.checked if k == "deployer" and st == "ok")
    for kind, scope, status in r.checked:
        if kind in ("service_account", "deployer") and status == "ok":
            continue
        shown = "read" if status == "ok" else (status if kind == "deployer" and status.startswith("not found")
                                               else "NOT CHECKED (" + status + ")")
        lines.append(f"  {_SCOPE_LABEL[kind]} {scope}: {shown}")
    if sa_ok:
        lines.append(f"  service accounts: {sa_ok} policies read")
    if dep_ok:
        lines.append(f"  workload deployers: {dep_ok} policies read")
    for kind in r.skipped:
        lines.append(f"  {_SCOPE_LABEL[kind]}: skipped on request (--skip)")
    if not any(k in ("tag_key", "tag_value") for k, _s, _st in r.checked) and "tag_key" not in r.skipped:
        lines.append("  deletion-safety tag: not in the state (no tag to check)")
    lines.append("Not checked: inherited grants on the organization and the folders above the managed workloads "
                 "folder" + (f" (read-only: gcloud organizations get-iam-policy {r.organization.split('/')[-1]})"
                             if r.organization else "") + ".")
    lines.append("")
    if r.findings:
        lines.append(f"Unexpected grants: {len(r.findings)}")
        lines.append("")
        lines.append("| # | Scope | Member | Role | Why it matters | Fix |")
        lines.append("| - | ----- | ------ | ---- | -------------- | --- |")
        for i, f in enumerate(r.findings, 1):
            lines.append(f"| {i} | {_md_cell(_SCOPE_LABEL[f.kind] + ' ' + f.scope)} | {_md_cell(f.member)} | "
                         f"{_md_cell(f.role)} | {_md_cell(f.why)} | `{_md_cell(f.fix)}` |")
        lines.append("")
        lines.append("Run a fix only after you have confirmed nobody needs the grant. To keep a grant, declare it in "
                     "infra/platform Terraform (then it is expected), or pass --admin=<member> for an administrator.")
    else:
        lines.append("Unexpected grants: none")
    c = r.counts
    lines.append("")
    lines.append(f"Not reported: {c['terraform']} matched Terraform, {c['administrator']} administrators, "
                 f"{c['google_agent']} Google service-agent grants, {c['bootstrap_billing']} installer billing "
                 f"grants, {c['not_guard_reaching']} grants that do not reach the guards, "
                 f"{c['deleted_principal']} deleted principals"
                 + (f", {c['broker']} broker token grants on workload deployers" if c.get("broker") else "") + ".")
    if r.unchecked:
        lines.append("")
        lines.append("COULD NOT CHECK (exit 2): " + "; ".join(r.unchecked))
    return "\n".join(lines) + "\n"


def render_json(r: Report) -> str:
    return json.dumps({
        "project": r.project,
        "exit_code": r.exit_code,
        "findings": [f._asdict() for f in r.findings],
        "checked": [{"kind": k, "scope": s, "status": st} for k, s, st in r.checked],
        "skipped": r.skipped,
        "unchecked": r.unchecked,
        "not_reported": r.counts,
        "expected_grants": r.expected_total,
        "service_accounts": r.service_account_total,
    }, indent=2, sort_keys=True) + "\n"


# ------------------------------------------------------------------------------
# CLI
# ------------------------------------------------------------------------------
def _load_json(path: str, what: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except OSError as e:
        raise CheckError(f"cannot read the {what} ({e.strerror})")
    except ValueError:
        raise CheckError(f"the {what} is not valid JSON")


def _skip_kinds(values: Iterable[str]) -> List[str]:
    out: List[str] = []
    for v in values:
        out.extend(SKIP_CHOICES[v])
    return out


def _billing_fallback(values: Iterable[str]) -> List[Tuple[str, str]]:
    out = []
    for v in values:
        role, sep, acc = v.partition("=")
        if not sep or not role.startswith("roles/") or not acc:
            raise CheckError(f"--billing-fallback {v!r} is not ROLE=ACCOUNT_ID")
        out.append((role, acc))
    return out


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    inst = sub.add_parser("runner-identity-installed")   # FD-7L: "yes" when the runner SAs are in the state
    inst.add_argument("--state", required=True)
    for name in ("targets", "analyze"):
        s = sub.add_parser(name)
        s.add_argument("--state", required=True)
        s.add_argument("--inputs", required=True)
        s.add_argument("--skip", action="append", default=[], choices=sorted(SKIP_CHOICES))
        if name == "analyze":
            s.add_argument("--policies", required=True)
            s.add_argument("--admin", action="append", default=[])
            s.add_argument("--billing-fallback", action="append", default=[])
            s.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    try:
        state = _load_json(a.state, "platform state")
        if a.cmd == "runner-identity-installed":
            ps = read_platform_state(state)
            print("yes" if any(acc in RUNNER_ACCOUNT_IDS for acc in ps.service_accounts.values()) else "no")
            return EXIT_CLEAN
        inputs = _load_json(a.inputs, "inputs")
        if a.cmd == "targets":
            for t in build_targets(read_platform_state(state), inputs, _skip_kinds(a.skip)):
                print("\t".join((t.name, t.method, t.url, t.body)))
            return EXIT_CLEAN
        report = analyze(state, inputs, a.policies, a.admin, _billing_fallback(a.billing_fallback),
                         _skip_kinds(a.skip))
    except CheckError as e:
        print(f"[ERROR] could not check: {e}", file=sys.stderr)
        return EXIT_UNCHECKED
    sys.stdout.write(render_json(report) if a.json else render_text(report))
    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
