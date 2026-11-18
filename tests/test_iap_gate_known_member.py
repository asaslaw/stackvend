"""IAP-GATE-KNOWN-MEMBER (live defect 11-08, example 09): the compute-cloudrun IAP agent's roles/run.invoker member is
a known value in the first-deploy plan, and the compliance gate still refuses a member that truly is unknown.

The first deploy's plan shape: module.foundation has changes pending, every compute module call has
`depends_on = [module.foundation]`, so a data source inside the module is deferred to apply. The root's data source
has no depends_on and is read at plan time.

The real-provider tests (skipped without tofu + a provider mirror) render the platform root, plan it with the real
google provider against a local fake Resource Manager endpoint (no credentials, no GCP call: a dead HTTPS proxy), and
feed the real `tofu show -json` to the gate.

Running them: set STACKVEND_WORKLOAD_TOFU to an OpenTofu 1.9.0 binary (the workload engine) and
STACKVEND_WORKLOAD_TOFU_MIRROR to a filesystem mirror of the production provider set (google and google-beta 6.35.0;
mcp-servers/terraform/provider_allowlist.py), or place that mirror at eval/.tofu-mirror-prod. It is untracked and is
NOT the eval oracle mirror eval/.tofu-mirror (google 6.50.0). See "Real-provider plan tests" in eval/README.md.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import http.server
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import threading

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_PATH = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY_PATH, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

import developer_agent.terraform_engine as te  # noqa: E402

_spec = importlib.util.spec_from_file_location("iap_known_plan_gate",
                                               os.path.join(REPO_ROOT, "mcp-servers", "compliance", "plan_gate.py"))
plan_gate = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = plan_gate
_spec.loader.exec_module(plan_gate)

PROJECT = "child-iap-1"
NUMBER = "412345678901"
AGENT = f"serviceAccount:service-{NUMBER}@gcp-sa-iap.iam.gserviceaccount.com"
IAP_INGRESS = {"enable_direct_iap": True, "allow_unauthenticated": False}
NO_REQUIREMENTS = {"requires_cmek": False, "requires_audit_logging": False}
DATA_ADDRESS = "data.google_project.stackvend_iap_project"
DATA_DECLARATION = 'data "google_project" "stackvend_iap_project"'
NUMBER_INPUT = f"  project_number        = {DATA_ADDRESS}.number\n"
IAP_ON = {"allow_unauthenticated": False, "enable_direct_iap": True}


def _root(**kw):
    args = dict(IAP_ON)
    args.update(kw)
    return te.generate_golden_main_tf("shop", "cloudrun", "", **args)


def _module_block(hcl: str, label: str) -> str:
    start = hcl.index(f'module "{label}"')
    return hcl[start:hcl.index("\n}", start)]


# ------------------------------------------------------------------------------------------------ render
def test_direct_iap_primary_passes_the_root_number_to_the_module():
    hcl = _root()
    assert hcl.count(DATA_DECLARATION) == 1
    block = hcl[hcl.index(DATA_DECLARATION):hcl.index("}", hcl.index(DATA_DECLARATION))]
    assert "project_id = var.project_id" in block and "depends_on" not in block   # read at plan time, not deferred
    assert NUMBER_INPUT in _module_block(hcl, "compute")


@pytest.mark.parametrize("kw", [dict(allow_unauthenticated=True, enable_direct_iap=False),
                                dict(allow_unauthenticated=False, enable_direct_iap=False),
                                dict(allow_unauthenticated=True, enable_direct_iap=True)])
def test_not_direct_iap_renders_nothing_new(kw):
    hcl = te.generate_golden_main_tf("shop", "cloudrun", "", **kw)
    assert "stackvend_iap_project" not in hcl and "project_number" not in hcl


def test_non_cloudrun_primary_renders_the_data_source_only_for_cloud_run_secondaries():
    assert "stackvend_iap_project" not in te.generate_golden_main_tf("shop", "gke-autopilot", "", **IAP_ON)
    hcl = te.generate_golden_main_tf("shop", "gke-autopilot", "", cloud_run_secondaries=True, **IAP_ON)
    assert hcl.count(DATA_DECLARATION) == 1
    assert "project_number" not in _module_block(hcl, "compute")


def _secondary_files(**kw):
    files = {"infra/workload/custom.tf": ""}
    args = dict(files=files, product_id="shop", spec_text="", archetype="cloudrun",
                target_services=["shop", "worker-api"])
    args.update(kw)
    te.reconcile_multi_service_declarations(**args)
    return files


@pytest.mark.parametrize("archetype", ["gke-autopilot", "event-worker", "gce-bastion"])
def test_non_cloud_run_primary_reconcile_then_generate_pair(archetype):
    """The wiring the developer stage uses: reconcile records what it rendered, generate reads that record."""
    from developer_agent.assembly import file_keys
    planned = []
    files = _secondary_files(archetype=archetype, target_services=["core", "edge"], planned_out=planned, **IAP_ON)
    assert planned == ["edge"]
    assert NUMBER_INPUT in _module_block(files["infra/workload/custom.tf"], "compute_edge")
    main = te.generate_golden_main_tf("shop", archetype, "", cloud_run_secondaries=bool(planned), **IAP_ON)
    assert main.count(DATA_DECLARATION) == 1
    assert file_keys(main) is not None and file_keys(files["infra/workload/custom.tf"]) is not None


def test_non_cloud_run_primary_without_secondaries_declares_no_data_source():
    planned = []
    _secondary_files(archetype="gke-autopilot", target_services=["core"], planned_out=planned, **IAP_ON)
    assert planned == []
    assert "stackvend_iap_project" not in te.generate_golden_main_tf(
        "shop", "gke-autopilot", "", cloud_run_secondaries=bool(planned), **IAP_ON)


@pytest.mark.parametrize("archetype", ["gke-autopilot", "event-worker", "gce-bastion", "cloudrun"])
def test_root_keys_render_declares_the_same_keys_as_the_final_render(archetype):
    """Red-team F1: an AI copy of the data source is classified against the keys the final root really declares."""
    from developer_agent.assembly import platform_root_keys
    services = ["core", "edge"]
    pre = te.generate_golden_main_tf(
        "shop", archetype, "", cloud_run_secondaries=bool(te.planned_cloud_run_services(archetype, "shop", services)),
        **IAP_ON)
    planned = []
    _secondary_files(archetype=archetype, target_services=services, planned_out=planned, **IAP_ON)
    final = te.generate_golden_main_tf("shop", archetype, "", cloud_run_secondaries=bool(planned), **IAP_ON)
    assert platform_root_keys({"main.tf": pre}) == platform_root_keys({"main.tf": final})
    assert any("stackvend_iap_project" in str(k) for k in platform_root_keys({"main.tf": final}))


def test_both_developer_renders_pass_the_secondaries_flag():
    """The handler's two calls: the root-keys render from the typed plan, the final render from what reconcile rendered."""
    with open(os.path.join(GATEWAY_PATH, "developer_agent", "handler.py"), encoding="utf-8") as f:
        tree = ast.parse(f.read())
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id == "generate_golden_main_tf"]
    assert len(calls) == 2
    flags = sorted(ast.unparse(k.value) for c in calls for k in c.keywords if k.arg == "cloud_run_secondaries")
    assert flags == ["bool(planned_cloud_run_services(archetype, product_id, list(intent.service_names), vt))",
                     "bool(planned_services)"]


def test_strip_helper_refuses_a_doubled_data_block():
    from iap_known_member_render import ROOT_DATA_BLOCK, without_iap_known_member
    with pytest.raises(AssertionError):
        without_iap_known_member(ROOT_DATA_BLOCK + ROOT_DATA_BLOCK)


def test_secondary_cloud_run_services_get_the_same_input():
    files = _secondary_files(**IAP_ON)
    assert NUMBER_INPUT in _module_block(files["infra/workload/custom.tf"], "compute_worker_api")


def test_secondary_without_direct_iap_is_unchanged():
    files = _secondary_files(allow_unauthenticated=False, enable_direct_iap=False)
    assert "project_number" not in files["infra/workload/custom.tf"]


# ------------------------------------------------------------------------------------------------ module
def _module_file(name):
    with open(os.path.join(REPO_ROOT, "infra", "modules", "compute-cloudrun", name), encoding="utf-8") as f:
        return f.read()


def test_module_member_prefers_the_input_and_keeps_the_data_source_fallback():
    assert ('member     = "serviceAccount:service-${var.project_number != "" ? var.project_number : '
            'data.google_project.workload_project.number}@gcp-sa-iap.iam.gserviceaccount.com"') in _module_file("main.tf")
    assert 'data "google_project" "workload_project"' in _module_file("main.tf")
    assert 'variable "project_number"' in _module_file("variables.tf")


def test_input_is_platform_only_in_the_developer_prompt_contract():
    from developer_agent import contract_inspector as CI
    assert "project_number" in CI._PLATFORM_ONLY_INPUTS["compute-cloudrun"]
    assert "project_number" in CI._EMBEDDED_MODULE_CONTRACTS["compute-cloudrun"]["inputs"]


# ------------------------------------------------------------------------------------------------ the gate (fixtures)
def _plan(member=AGENT, member_unknown=False, address="iap_agent_invoker", resources=()):
    after = {"role": "roles/run.invoker", "name": "shop", "location": "us-central1", "project": PROJECT}
    unknown = {"etag": True, "id": True}
    if member_unknown:
        unknown["member"] = True
    else:
        after["member"] = member
    rc = [{"address": f"module.compute.google_cloud_run_v2_service_iam_member.{address}[0]",
           "module_address": "module.compute", "type": "google_cloud_run_v2_service_iam_member", "name": address,
           "mode": "managed", "change": {"actions": ["create"], "before": None, "after": after,
                                         "after_unknown": unknown}},
          {"address": "module.compute.google_cloud_run_v2_service.app", "module_address": "module.compute",
           "type": "google_cloud_run_v2_service", "name": "app", "mode": "managed",
           "change": {"actions": ["create"], "before": None,
                      "after": {"iap_enabled": True, "ingress": "INGRESS_TRAFFIC_ALL", "location": "us-central1"},
                      "after_unknown": {"uri": True}}}]
    return {"format_version": "1.2", "resource_changes": rc + list(resources), "configuration": {"root_module": {}}}


def _gate(plan, ingress=None):
    return plan_gate.evaluate_plan(plan, profile="STANDARD", requirements=NO_REQUIREMENTS,
                                   ingress=dict(IAP_INGRESS) if ingress is None else ingress)


def test_gate_passes_the_known_agent_member_with_direct_iap_and_no_public_invoker():
    out = _gate(_plan())
    assert out["decision"] == plan_gate.DECISION_PASS, out
    assert {"DIRECT_IAP", "NO_PUBLIC_INVOKER"} <= set(out["checks_run"])


def test_gate_still_refuses_an_unknown_member():
    out = _gate(_plan(member_unknown=True))
    assert out["decision"] == plan_gate.DECISION_VIOLATION
    assert [v["code"] for v in out["violations"]] == ["PUBLIC_INVOKER_UNVERIFIABLE"]


def test_gate_still_refuses_all_users():
    out = _gate(_plan(member="allUsers", address="public_access"))
    assert out["decision"] == plan_gate.DECISION_VIOLATION
    assert [v["code"] for v in out["violations"]] == ["PUBLIC_INVOKER"]


def test_gate_does_not_treat_the_iap_web_accessor_type_as_a_run_invoker_grant():
    assert "google_iap_web_cloud_run_service_iam_member" not in plan_gate.RUN_IAM_MEMBER_TYPES
    accessor = {"address": "module.compute.google_iap_web_cloud_run_service_iam_member.iap_accessors[\"x\"]",
                "module_address": "module.compute", "type": "google_iap_web_cloud_run_service_iam_member",
                "name": "iap_accessors", "mode": "managed",
                "change": {"actions": ["create"], "before": None,
                           "after": {"role": "roles/iap.httpsResourceAccessor", "member": "group:ops@example.com"},
                           "after_unknown": {}}}
    assert _gate(_plan(resources=[accessor]))["decision"] == plan_gate.DECISION_PASS


# ------------------------------------------------------------------------------------------------ real provider plan
MIRROR = os.environ.get("STACKVEND_WORKLOAD_TOFU_MIRROR") or os.path.join(REPO_ROOT, "eval", ".tofu-mirror-prod")
TOFU = os.environ.get("STACKVEND_WORKLOAD_TOFU") or shutil.which("tofu") or ""
NEEDS_ENGINE = pytest.mark.skipif(not (os.access(TOFU, os.X_OK) and os.path.isdir(MIRROR)),
                                  reason="tofu + a workload provider mirror (untracked) not present; set "
                                         "STACKVEND_WORKLOAD_TOFU / STACKVEND_WORKLOAD_TOFU_MIRROR")


class _FakeCrm(http.server.BaseHTTPRequestHandler):
    """The two reads `data.google_project` makes, local only: enough for a real plan; never GCP."""

    def do_GET(self):  # noqa: N802 - http.server name
        if self.path.startswith(f"/v1/projects/{PROJECT}/billingInfo") or self.path.startswith(
                f"/projects/{PROJECT}/billingInfo"):
            body = {"name": f"projects/{PROJECT}/billingInfo", "projectId": PROJECT, "billingEnabled": False}
        elif "projects/" in self.path:
            body = {"projectId": PROJECT, "projectNumber": NUMBER, "name": "child", "lifecycleState": "ACTIVE",
                    "parent": {"type": "folder", "id": "1"}}
        else:
            self.send_error(404)
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):  # noqa: D102 - silence
        pass


@pytest.fixture(scope="module")
def fake_crm():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _FakeCrm)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/"
    server.shutdown()
    t.join(5)


def _workspace(tmp_path, port_url, iap=True):
    root = tmp_path / "workspace"
    (root / "infra" / "workload").mkdir(parents=True)
    wd = root / "infra" / "workload"
    wd.joinpath("main.tf").write_text(te.generate_golden_main_tf("shop", "cloudrun", "", allow_unauthenticated=not iap,
                                                                 enable_direct_iap=iap))
    wd.joinpath("variables.tf").write_text(
        te.generate_golden_variables_tf("shop", "acme/shop", allow_unauthenticated=not iap, enable_direct_iap=iap,
                                        authorized_invoker_members=["group:ops@example.com"]))
    (root / "infra" / "modules").mkdir()
    for mod in ("compute-cloudrun", "workload-foundation"):
        shutil.copytree(os.path.join(REPO_ROOT, "infra", "modules", mod), root / "infra" / "modules" / mod,
                        ignore=shutil.ignore_patterns(".terraform*"))
    wd.joinpath("offline_override.tf").write_text(f'''provider "google" {{
  access_token                     = "offline-test-token"
  resource_manager_custom_endpoint = "{port_url}v1/"
  cloud_billing_custom_endpoint    = "{port_url}"
}}
provider "google-beta" {{
  access_token                     = "offline-test-token"
  resource_manager_custom_endpoint = "{port_url}v1/"
  cloud_billing_custom_endpoint    = "{port_url}"
}}
''')
    wd.joinpath("terraform.tfvars").write_text(
        f'project_id = "{PROJECT}"\nproduct_id = "shop"\ncontainer_image = "us-central1-docker.pkg.dev/x/y/app:latest"\n')
    return wd


def _plan_json(wd):
    cli = wd / "cli.tfrc"
    cli.write_text('provider_installation {\n  filesystem_mirror {\n    path = %s\n  }\n}\n' % json.dumps(MIRROR))
    env = {"PATH": "/usr/bin:/bin", "HOME": str(wd), "TF_CLI_CONFIG_FILE": str(cli), "TF_IN_AUTOMATION": "1",
           "CHECKPOINT_DISABLE": "1", "HTTPS_PROXY": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9",
           "NO_PROXY": "127.0.0.1"}

    def run(*args):
        done = subprocess.run([TOFU, *args], cwd=str(wd), env=env, capture_output=True, text=True, timeout=300)
        assert done.returncode == 0, done.stdout + done.stderr
        return done.stdout

    run("init", "-backend=false", "-input=false", "-no-color")
    run("plan", "-refresh=false", "-input=false", "-no-color", "-out=tfplan")
    return json.loads(run("show", "-json", "tfplan"))


@NEEDS_ENGINE
def test_first_deploy_plan_has_a_known_member_and_passes_the_gate(tmp_path, fake_crm):
    plan = _plan_json(_workspace(tmp_path, fake_crm))
    agent = [r for r in plan["resource_changes"] if r["address"].endswith("iap_agent_invoker[0]")]
    assert len(agent) == 1
    assert agent[0]["change"]["after"]["member"] == AGENT       # the same string a deployed workload holds
    assert "member" not in agent[0]["change"]["after_unknown"]
    out = _gate(plan)
    assert out["decision"] == plan_gate.DECISION_PASS, out
    assert {"DIRECT_IAP", "NO_PUBLIC_INVOKER"} <= set(out["checks_run"])


@NEEDS_ENGINE
def test_first_deploy_plan_without_the_input_is_still_refused(tmp_path, fake_crm):
    """The fallback path (a root that does not set project_number) stays unknown on a first deploy: never trusted."""
    wd = _workspace(tmp_path, fake_crm)
    main = wd.joinpath("main.tf").read_text()
    wd.joinpath("main.tf").write_text(main.replace(NUMBER_INPUT, ""))
    out = _gate(_plan_json(wd))
    assert out["decision"] == plan_gate.DECISION_VIOLATION
    assert [v["code"] for v in out["violations"]] == ["PUBLIC_INVOKER_UNVERIFIABLE"]


@NEEDS_ENGINE
def test_push_invoker_of_a_service_account_created_in_the_plan_is_known(tmp_path, fake_crm):
    """Sweep: push_invokers (private IAM-only + a Pub/Sub push identity): the member's email is planned from
    account_id + project by the provider, so it is known on a first deploy and the gate reads a real value."""
    wd = _workspace(tmp_path, fake_crm, iap=False)
    wd.joinpath("main.tf").write_text(wd.joinpath("main.tf").read_text() + '''
resource "google_service_account" "pusher" {
  account_id = "pusher-identity"
}
''')
    main = wd.joinpath("main.tf").read_text()
    wd.joinpath("main.tf").write_text(main.replace(
        "  authorized_invoker_members = var.authorized_invoker_members\n",
        "  authorized_invoker_members = var.authorized_invoker_members\n"
        "  push_service_accounts = { \"google_service_account.pusher\" = google_service_account.pusher.email\n"
        "    \"fact.workload_sa_email\" = module.foundation.workload_sa_email }\n", 1))
    wd.joinpath("terraform.tfvars").write_text(wd.joinpath("terraform.tfvars").read_text()
                                               + "allow_unauthenticated = false\nenable_direct_iap = false\n")
    plan = _plan_json(wd)
    members = {r["address"]: r["change"] for r in plan["resource_changes"]
               if r["type"] == "google_cloud_run_v2_service_iam_member" and r["name"] == "push_invokers"}
    assert len(members) == 2
    for change in members.values():
        assert "member" not in change["after_unknown"]
        assert change["after"]["member"].startswith("serviceAccount:")
    out = _gate(plan, ingress={"allow_unauthenticated": False, "enable_direct_iap": False})
    assert [v["code"] for v in out["violations"]] == []
