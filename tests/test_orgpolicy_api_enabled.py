"""ORGPOLICY-API + ORG-POLICY-FOLDER (owner 10-28).

1. The host project enables orgpolicy.googleapis.com. Vending's check_child_org_policies (apps/project-vending/
   vending.py) reads the child's effective compute.vmExternalIpAccess policy through the Org Policy API v2, and Google
   bills that call to the caller's quota project: the vending identity is a host-project service account, so the API
   must be enabled on the HOST (it was not: every vend answered 403 SERVICE_DISABLED). The mcp-compliance-server
   folder harvest bills the host the same way, and so does the folder policy below (host-quota provider alias).
2. The platform Terraform sets compute.vmExternalIpAccess = deny all ONCE on the managed workloads folder
   (google_org_policy_policy.managed_folder_vm_external_ip), gated by var.create_folder_vm_external_ip_policy, which
   the installer's read-only preflight sets (tests/test_org_policy_folder_preflight.py).
3. No service account gets org-policy rights: roles/orgpolicy.policyAdmin can be granted only on an ORGANIZATION
   (Google's role reference: "Lowest-level resources where you can grant this role: Organization"), so a folder or
   project grant of it would fail the apply, and an org grant is outside the owner's rule. No org-level grant at all.

Static (python-hcl2 / block walker) checks only; nothing is applied. The plan-level contract (mock providers) is in
tests/fixtures/lane18_s0/lane18_s0.tftest.hcl."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import glob
import importlib.util
import os

import hcl2

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PLATFORM_DIR = os.path.join(REPO_ROOT, "infra", "platform")
MAIN_TF = os.path.join(PLATFORM_DIR, "main.tf")
VENDING_PY = os.path.join(REPO_ROOT, "apps", "project-vending", "vending.py")
COMPLIANCE_PY = os.path.join(REPO_ROOT, "mcp-servers", "compliance", "service.py")

API = "orgpolicy.googleapis.com"


def _load(path):
    with open(path) as fh:
        return hcl2.load(fh)


def _services():
    [services] = [blk["services"] for blk in _load(MAIN_TF).get("locals", []) if "services" in blk]
    return services


def _resources(doc, rtype):
    out = {}
    for blk in doc.get("resource", []):
        for name, body in (blk.get(rtype) or {}).items():
            out[name] = body
    return out


def test_orgpolicy_api_is_in_the_host_enabled_set_exactly_once():
    services = _services()
    assert services.count(API) == 1, services


def test_the_enabled_set_is_the_host_project_for_each():
    apis = _resources(_load(MAIN_TF), "google_project_service")["apis"]
    assert apis["for_each"] == "${toset(local.services)}"
    assert apis["project"] == "${var.project_id}"
    assert apis["service"] == "${each.key}"
    # Never disabled again by a destroy (same as every other host API).
    assert apis["disable_on_destroy"] is False
    assert apis["disable_dependent_services"] is False


def _class_constant(path, cls, name):
    tree = ast.parse(open(path).read())
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == cls:
            for stmt in node.body:
                if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in stmt.targets):
                    return ast.literal_eval(stmt.value)
    raise AssertionError(f"{cls}.{name} not found in {path}")


def test_vending_calls_the_api_the_host_enables():
    """The service name is the host of vending's Org Policy endpoint (ties the TF entry to the caller)."""
    url = _class_constant(VENDING_PY, "ProjectRepoVendingEngine", "ORG_POLICY_API")
    assert url == f"https://{API}/v2"
    assert API in _services()


def test_compliance_harvest_calls_the_same_api():
    src = open(COMPLIANCE_PY).read()
    assert f"https://{API}/v2/" in src


# python-hcl2 cannot parse every platform file (conditional expressions in some), so the grant scans walk the
# top-level blocks textually with the shared FD-09 walker (comments stripped), as tests/test_lane13_stage_a_tf.py does.
_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("fd09_walker_orgpolicy", os.path.join(_HERE, "test_platform_validate_fd09.py"))
_fd09 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fd09)


def _top_blocks(text):
    """[(header, block_text)] for every top-level block (comments stripped, braces in strings blanked)."""
    out, cur, depth = [], None, 0
    for line in _fd09._strip(text):
        if depth == 0 and line.strip().endswith("{"):
            cur = [line.strip()[:-1].strip(), [line]]
        elif cur is not None:
            cur[1].append(line)
        depth += line.count("{") - line.count("}")
        if depth == 0 and cur is not None:
            out.append((cur[0], "\n".join(cur[1])))
            cur = None
    assert depth == 0
    return out


def _platform_blocks():
    files = sorted(glob.glob(os.path.join(PLATFORM_DIR, "*.tf")))
    assert MAIN_TF in files and os.path.join(PLATFORM_DIR, "destructive_guard.tf") in files
    for path in files:
        with open(path, encoding="utf-8") as fh:
            for head, body in _top_blocks(fh.read()):
                yield os.path.basename(path), head, body


def _resource_type(head):
    parts = head.split('"')
    return parts[1] if head.startswith("resource ") and len(parts) > 1 else ""


def test_no_folder_or_project_grant_of_org_policy_admin():
    """roles/orgpolicy.policyAdmin is grantable only on an organization: a folder/project grant fails the apply."""
    rtypes = {"google_folder_iam_member", "google_folder_iam_binding", "google_folder_iam_policy",
              "google_project_iam_member", "google_project_iam_binding", "google_project_iam_policy"}
    found = [(f, h) for f, h, body in _platform_blocks()
             if _resource_type(h) in rtypes and "roles/orgpolicy.policyAdmin" in body]
    assert found == []


def test_no_organization_level_grant_anywhere():
    """Owner rule 10-28: no organization-level IAM resource of any kind in the platform Terraform."""
    found = [(f, h) for f, h, body in _platform_blocks() if _resource_type(h).startswith("google_organization_iam")]
    assert found == []


def test_no_service_account_gets_org_policy_write_rights():
    """ORG-POLICY-FOLDER: the only org-policy role in any IAM resource is the developer's read-only policyViewer."""
    found = []
    for f, h, body in _platform_blocks():
        rtype = _resource_type(h)
        if "_iam_" in rtype or rtype.endswith("_iam_custom_role"):
            for line in body.splitlines():
                if "roles/orgpolicy." in line and "roles/orgpolicy.policyViewer" not in line:
                    found.append((f, h, line.strip()))
                if "orgpolicy.policy.set" in line or "orgpolicy.policies.create" in line:
                    found.append((f, h, line.strip()))
    assert found == []


# ---- ORG-POLICY-FOLDER: the folder policy resource, its gate and its provider ----
def _folder_policy():
    return _resources(_load(MAIN_TF), "google_org_policy_policy")["managed_folder_vm_external_ip"]


def test_folder_policy_is_deny_all_on_the_managed_folder():
    pol = _folder_policy()
    assert pol["parent"] == "${local.managed_folder}"
    assert pol["name"] == "${local.managed_folder}/policies/compute.vmExternalIpAccess"
    assert pol["spec"] == [{"rules": [{"deny_all": "TRUE"}]}]
    assert pol["depends_on"] == ["${google_project_service.apis}"]


def test_folder_policy_is_gated_by_the_preflight_variable():
    pol = _folder_policy()
    assert pol["count"] == "${local.folder_vm_external_ip_policy_enabled ? 1 : 0}"
    [gate] = [blk["folder_vm_external_ip_policy_enabled"] for blk in _load(MAIN_TF).get("locals", [])
              if "folder_vm_external_ip_policy_enabled" in blk]
    assert gate == '${local.managed_folder != "" && var.create_folder_vm_external_ip_policy != false}'
    [var] = [blk["create_folder_vm_external_ip_policy"]
             for blk in _load(os.path.join(PLATFORM_DIR, "variables.tf")).get("variable", [])
             if "create_folder_vm_external_ip_policy" in blk]
    assert var["type"] in ("bool", "${bool}")  # python-hcl2 versions differ in wrapping bare type keywords
    assert var["default"] is None
    assert var["nullable"] is True
    assert "roles/orgpolicy.policyAdmin on the organization" in var["description"]
    assert "including projects StackVend did not vend" in var["description"]


def test_folder_policy_bills_the_host_as_quota_project():
    pol = _folder_policy()
    assert pol["provider"] == "${google.host_quota}"
    providers = _load(os.path.join(PLATFORM_DIR, "providers.tf"))["provider"]
    aliased = [p["google"] for p in providers if "google" in p and p["google"].get("alias") == "host_quota"]
    assert aliased == [{"alias": "host_quota", "project": "${var.project_id}", "region": "${var.region}",
                        "user_project_override": True, "billing_project": "${var.project_id}"}]
    # The default google provider is unchanged (no override for every other resource).
    default = [p["google"] for p in providers if "google" in p and "alias" not in p["google"]]
    assert default == [{"project": "${var.project_id}", "region": "${var.region}"}]


def test_only_the_folder_policy_uses_the_host_quota_alias():
    users = [(f, h) for f, h, body in _platform_blocks() if "google.host_quota" in body]
    assert users == [("main.tf", 'resource "google_org_policy_policy" "managed_folder_vm_external_ip"')]


def test_no_project_level_org_policy_resource():
    """The guardrail lives on the folder only; the platform never sets an org policy on the host project."""
    found = [(f, h) for f, h, body in _platform_blocks()
             if _resource_type(h) in {"google_org_policy_policy", "google_project_organization_policy",
                                      "google_folder_organization_policy", "google_organization_policy"}]
    assert found == [("main.tf", 'resource "google_org_policy_policy" "managed_folder_vm_external_ip"')]


def test_the_block_walker_sees_the_existing_folder_grants():
    """Positive control for the two scans above: the walker finds destructive_guard.tf's folder reader grants,
    including the developer's roles/orgpolicy.policyViewer (a read role, grantable on a folder)."""
    heads = {(f, h): body for f, h, body in _platform_blocks()}
    body = heads[("destructive_guard.tf", 'resource "google_folder_iam_member" "guard_folder_readers"')]
    assert "roles/orgpolicy.policyViewer" in body


def test_the_block_walker_would_flag_a_folder_policy_admin_grant():
    """Sensitivity: a synthetic folder grant of roles/orgpolicy.policyAdmin is seen with its resource type."""
    text = ('# roles/orgpolicy.policyAdmin in a comment is ignored\n'
            'resource "google_folder_iam_member" "x" {\n  folder = local.managed_folder\n'
            '  role   = "roles/orgpolicy.policyAdmin"\n  member = "serviceAccount:a@b"\n}\n')
    [(head, body)] = _top_blocks(text)
    assert _resource_type(head) == "google_folder_iam_member"
    assert "roles/orgpolicy.policyAdmin" in body
