"""HOST-INTERNAL-INGRESS + HOST-VPC-EGRESS (owner 11-07: Design B for the RC): static checks on infra/platform.

Every host Cloud Run service except the Control Center takes its ingress from local.host_service_ingress (internal-only
when var.host_internal_ingress), every host Cloud Run service and job except the QA sandbox job has a dynamic
"vpc_access" block over local.host_vpc_access (the stackvend-host network, gated on var.host_vpc_egress), the
network's ranges come from variables whose defaults equal the IPAM platform reservations, and the private run.app zone
answers *.run.app with the Private Service Connect address. Plan: docs/planning/internal-ingress-plan.md §3 and §8.

Hermetic: the comment- and string-aware HCL walker from tests/test_platform_validate_fd09.py; no tofu, no network.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import glob
import importlib.util
import ipaddress
import os
import re
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
PLATFORM = os.path.join(REPO, "infra", "platform")
MAIN_TF = os.path.join(PLATFORM, "main.tf")
NET_TF = os.path.join(PLATFORM, "host_network.tf")
VARS_TF = os.path.join(PLATFORM, "variables.tf")
QA_TF = os.path.join(PLATFORM, "qa_sandbox.tf")
IPAM = os.path.join(REPO, "shared", "ipam.py")
MANIFEST = os.path.join(REPO, "shared", "release_manifest.py")

_spec = importlib.util.spec_from_file_location("fd09_walker_internal_ingress", os.path.join(HERE, "test_platform_validate_fd09.py"))
_fd09 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fd09)
attributes = _fd09.attributes

SERVICES = 'resource "google_cloud_run_v2_service" "services"'
GIT = 'resource "google_cloud_run_v2_service" "git_server"'
JOBS = 'resource "google_cloud_run_v2_job" "jobs"'
APPLIER = 'resource "google_cloud_run_v2_job" "tf_applier"'
STAGE_RUNNER = 'resource "google_cloud_run_v2_job" "stage_runner"'   # STAGE-JOB-RUNNER (stage_runner.tf)
STAGE_RUNNER_TF = os.path.join(PLATFORM, "stage_runner.tf")
QA_JOB = 'resource "google_cloud_run_v2_job" "qa_sandbox"'
NETWORK = 'resource "google_compute_network" "host"'
SUBNET = 'resource "google_compute_subnetwork" "host_run_egress"'
ADDRESS = 'resource "google_compute_global_address" "psc_google_apis"'
RULE = 'resource "google_compute_global_forwarding_rule" "psc_google_apis"'
ZONE = 'resource "google_dns_managed_zone" "host_run_app"'
RECORD = 'resource "google_dns_record_set" "host_run_app_wildcard"'
ROUTER = 'resource "google_compute_router" "host"'
NAT = 'resource "google_compute_router_nat" "host"'
UPGRADER_GRANT = 'resource "google_compute_subnetwork_iam_member" "platform_upgrader_subnet_user"'
CC = "product-control-center-ui"
QA_JOB_NAME = "qa-sandbox-test-runner"

# Where each Cloud Run resource's vpc_access lives (job templates are nested one level deeper).
VPC_PATHS = {
    SERVICES: (SERVICES, "template", 'dynamic "vpc_access"'),
    GIT: (GIT, "template", 'dynamic "vpc_access"'),
    JOBS: (JOBS, "template", "template", 'dynamic "vpc_access"'),
    APPLIER: (APPLIER, "template", "template", 'dynamic "vpc_access"'),
}
# Cloud Run names each resource deploys (the release manifest's components), for the classification check.
RESOURCE_COMPONENTS = {
    SERVICES: "local.cloud_run_services",
    GIT: {"castor-git-server"},
    JOBS: "local.cloud_run_jobs minus local.qa_job_name",
    APPLIER: {"tf-applier"},
    STAGE_RUNNER: {"stage-runner"},
}

# The IPAM platform reservations these defaults equal: shared/ipam.py PLATFORM_RESERVED_CIDRS (review F4: no literal
# fallback; the test fails when the keys are missing).
RESERVATION_KEYS = ("HOST_RUN_EGRESS_SUBNET", "HOST_PSC_GOOGLE_APIS")
QA_SANDBOX_SUBNET = "10.254.0.0/26"  # FD-4BR's reservation (unmerged branch fd-4br-egress): must stay disjoint


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def _attrs(path):
    return attributes(_read(path))


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


def _blocks(path):
    return dict(_top_blocks(_read(path)))


def _var_default(name):
    for p, a, v in _attrs(VARS_TF):
        if p == (f'variable "{name}"',) and a == "default":
            return v
    raise AssertionError(f"variable {name} has no default")


def _locals(path):
    return {a: v for p, a, v in _attrs(path) if p == ("locals",)}


def _reservations():
    """shared/ipam.py PLATFORM_RESERVED_CIDRS (it must define both keys)."""
    tree = ast.parse(_read(IPAM))
    for node in ast.walk(tree):
        target = node.target if isinstance(node, ast.AnnAssign) else (node.targets[0] if isinstance(node, ast.Assign) and len(node.targets) == 1 else None)
        if isinstance(target, ast.Name) and target.id == "PLATFORM_RESERVED_CIDRS" and node.value is not None:
            found = ast.literal_eval(node.value)
            missing = [k for k in RESERVATION_KEYS if k not in found]
            assert not missing, f"shared/ipam.py PLATFORM_RESERVED_CIDRS lacks {missing}"
            return found
    raise AssertionError("shared/ipam.py defines no PLATFORM_RESERVED_CIDRS")


# ------------------------------------------------------------------------------
# 1. Ingress
# ------------------------------------------------------------------------------
def test_services_ingress_comes_from_the_switch_except_the_control_center():
    ing = [v for p, a, v in _attrs(MAIN_TF) if p == (SERVICES,) and a == "ingress"]
    assert ing == [f'each.key == "{CC}" ? var.control_center_ingress_traffic : local.host_service_ingress']


def test_git_server_ingress_comes_from_the_switch():
    assert [v for p, a, v in _attrs(MAIN_TF) if p == (GIT,) and a == "ingress"] == ["local.host_service_ingress"]


def test_host_service_ingress_local_is_internal_only_when_switched_on():
    assert _locals(NET_TF)["host_service_ingress"] == (
        'var.host_internal_ingress ? "INGRESS_TRAFFIC_INTERNAL_ONLY" : "INGRESS_TRAFFIC_ALL"')


def test_no_cloud_run_service_in_the_platform_hardcodes_ingress_all():
    """Every other google_cloud_run_v2_service in infra/platform takes its ingress from a variable or the local."""
    for f in sorted(glob.glob(os.path.join(PLATFORM, "*.tf"))):
        for p, a, v in _attrs(f):
            if len(p) == 1 and p[0].startswith('resource "google_cloud_run_v2_service"') and a == "ingress":
                assert "INGRESS_TRAFFIC_ALL" not in v.split("?")[0] and v != '"INGRESS_TRAFFIC_ALL"', (os.path.basename(f), p, v)


# ------------------------------------------------------------------------------
# 2. Direct VPC egress on every host Cloud Run resource except the QA job
# ------------------------------------------------------------------------------
def _vpc_blocks(path=MAIN_TF):
    attrs = _attrs(path)
    out = {}
    for res, dyn in VPC_PATHS.items():
        got = {}
        for p, a, v in attrs:
            if p == dyn:
                got[a] = v
            elif p == dyn + ("content",):
                got["content." + a] = v
            elif p == dyn + ("content", "network_interfaces"):
                got["ni." + a] = v
        out[res] = got
    return out


def test_every_service_and_job_template_has_the_gated_vpc_access_block():
    expected = {
        "for_each": "local.host_vpc_access",
        "content.egress": "local.host_egress_mode",
        "ni.network": "vpc_access.value.network",
        "ni.subnetwork": "vpc_access.value.subnetwork",
    }
    for res, got in _vpc_blocks().items():
        assert got == expected, res
    text = _read(MAIN_TF)
    assert text.count('dynamic "vpc_access"') == 4
    assert "\n      vpc_access {" not in text and "\n        vpc_access {" not in text  # no static block anywhere


def test_host_vpc_access_local_points_at_the_host_network_and_is_gated():
    raw = _read(NET_TF)
    m = re.search(r"host_vpc_access = var\.host_vpc_egress \? \[\{\s*network\s*= google_compute_network\.host\[0\]\.id\s*"
                  r"subnetwork = google_compute_subnetwork\.host_run_egress\[0\]\.id\s*\}\] : \[\]", raw)
    assert m, "local.host_vpc_access must be [] unless var.host_vpc_egress, and name the host network + subnet"
    loc = _locals(NET_TF)
    assert loc["host_egress_mode"] == 'var.host_egress_mode == "PSC_PRIVATE_RANGES" ? "PRIVATE_RANGES_ONLY" : "ALL_TRAFFIC"'
    assert loc["host_network_psc"] == 'var.host_vpc_egress && var.host_egress_mode == "PSC_PRIVATE_RANGES"'
    assert loc["host_network_nat"] == 'var.host_vpc_egress && var.host_egress_mode == "NAT_ALL_TRAFFIC"'


def test_qa_sandbox_job_never_joins_the_host_network():
    qa = _read(QA_TF)
    for needle in ("google_compute_network.host", "host_run_egress", "host_vpc_access", "local.host_egress_mode",
                   "stackvend-host", "host_network_name"):
        assert needle not in qa, needle
    # and the generic jobs resource (which has the block) still excludes the QA job
    fe = [v for p, a, v in _attrs(MAIN_TF) if p == (JOBS,) and a == "for_each"]
    assert fe == ["{ for k, v in local.cloud_run_jobs : k => v if k != local.qa_job_name }"]
    assert [v for p, a, v in _attrs(QA_TF) if p == ("locals",) and a == "qa_job_name"] == [f'"{QA_JOB_NAME}"']


def test_the_vpc_set_is_every_release_component_except_the_qa_job():
    """A new Cloud Run component fails here until it is classified (on the network, or explicitly off it)."""
    tree = ast.parse(_read(MANIFEST))
    comps = None
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "COMPONENTS":
            comps = ast.literal_eval(node.value)
    assert comps
    names = {n for n, _, _ in comps}
    text = _read(MAIN_TF)

    def _map_keys(local_name):
        body = text[text.index(f"  {local_name} = {{"):]
        body = body[:body.index("\n  }")]
        return set(re.findall(r'^\s*"([a-z0-9-]+)"\s*=', body, re.M))

    services = _map_keys("cloud_run_services")
    jobs = _map_keys("cloud_run_jobs") - {QA_JOB_NAME}
    on_vpc = services | {"castor-git-server", "tf-applier"} | jobs
    # STAGE-JOB-RUNNER: the stage-runner job (its own file) has the same gated block as the gateway it stands in for
    runner = {a: v for p, a, v in _attrs(STAGE_RUNNER_TF)
              if p == (STAGE_RUNNER, "template", "template", 'dynamic "vpc_access"')}
    assert runner == {"for_each": "local.host_vpc_access"}
    runner_content = {a: v for p, a, v in _attrs(STAGE_RUNNER_TF)
                      if p == (STAGE_RUNNER, "template", "template", 'dynamic "vpc_access"', "content")}
    assert runner_content == {"egress": "local.host_egress_mode"}
    on_vpc |= {"stage-runner"}
    assert set(_vpc_blocks()) | {STAGE_RUNNER} == set(RESOURCE_COMPONENTS)
    assert on_vpc == names - {QA_JOB_NAME}, sorted(on_vpc ^ (names - {QA_JOB_NAME}))
    assert QA_JOB_NAME in names and QA_JOB_NAME not in on_vpc


# ------------------------------------------------------------------------------
# 3. Precondition, network, ranges, DNS
# ------------------------------------------------------------------------------
def test_internal_ingress_needs_vpc_egress_precondition():
    conds = [v for p, a, v in _attrs(MAIN_TF) if p == (SERVICES, "lifecycle", "precondition") and a == "condition"]
    assert "!var.host_internal_ingress || var.host_vpc_egress" in conds
    # tests/test_lane19_two_clients_tf.py reads the FIRST precondition: it must stay the A1 one.
    assert conds[0].startswith("var.cc_google_oauth_client_id")


def test_switch_defaults():
    assert _var_default("host_vpc_egress") == "true"
    assert _var_default("host_internal_ingress") == "false"
    for name in ("host_vpc_egress", "host_internal_ingress"):
        assert [v for p, a, v in _attrs(VARS_TF) if p == (f'variable "{name}"',) and a == "type"] == ["bool"]


def test_network_resources_are_gated_and_shaped():
    b = {p[0]: {} for p, _, _ in _attrs(NET_TF) if p}
    for p, a, v in _attrs(NET_TF):
        if len(p) == 1:
            b[p[0]][a] = v
    for res in (NETWORK, SUBNET):
        assert b[res]["count"] == "var.host_vpc_egress ? 1 : 0", res
    for res in (ADDRESS, RULE, ZONE, RECORD):                       # Design B only
        assert b[res]["count"] == "local.host_network_psc ? 1 : 0", res
    for res in (ROUTER, NAT):                                       # Design A only
        assert b[res]["count"] == "local.host_network_nat ? 1 : 0", res
    assert b[NETWORK]["auto_create_subnetworks"] == "false"
    assert b[NETWORK]["name"] == "local.host_network_name"
    assert _locals(NET_TF)["host_network_name"] == '"stackvend-host"'
    assert b[SUBNET]["ip_cidr_range"] == "var.host_egress_subnet_cidr"
    assert b[SUBNET]["private_ip_google_access"] == "true"
    assert b[SUBNET]["region"] == "var.region"
    assert b[ADDRESS]["address"] == "var.host_psc_endpoint_ip"
    assert b[ADDRESS]["purpose"] == '"PRIVATE_SERVICE_CONNECT"'
    assert b[ADDRESS]["address_type"] == '"INTERNAL"'
    assert b[RULE]["target"] == '"all-apis"'
    assert b[RULE]["load_balancing_scheme"] == '""'
    assert b[RULE]["ip_address"] == "google_compute_global_address.psc_google_apis[0].id"
    assert re.fullmatch(r'"[a-z][a-z0-9]{0,19}"', b[RULE]["name"]), b[RULE]["name"]  # PSC endpoint name rule
    # the subnet (which every vpc_access references) waits for the endpoint and the record
    sub = _blocks(NET_TF)[SUBNET]
    for dep in ("google_compute_global_forwarding_rule.psc_google_apis", "google_dns_record_set.host_run_app_wildcard",
                "google_compute_router_nat.host"):
        assert dep in sub, dep
    conds = [v for p, a, v in _attrs(NET_TF) if p == (SUBNET, "lifecycle", "precondition") and a == "condition"]
    assert len(conds) == 1  # the PSC address lies outside the subnet (raw text: the walker blanks ${} braces)
    assert ('condition     = var.host_egress_mode != "PSC_PRIVATE_RANGES" || cidrsubnet("${var.host_psc_endpoint_ip}/'
            '${split("/", var.host_egress_subnet_cidr)[1]}", 0, 0) != var.host_egress_subnet_cidr') in _read(NET_TF)


def test_dns_api_enabled_and_never_disabled():
    blocks = _blocks(NET_TF)
    dns = blocks['resource "google_project_service" "host_network_dns"']
    assert 'service            = "dns.googleapis.com"' in dns and "disable_on_destroy = false" in dns
    sd = blocks['resource "google_project_service" "host_network_service_directory"']
    assert 'service            = "servicedirectory.googleapis.com"' in sd and "disable_on_destroy = false" in sd
    zone = {a: v for p, a, v in _attrs(NET_TF) if p == (ZONE,)}
    assert zone["depends_on"] == "[google_project_service.host_network_dns]"


def test_design_b_private_run_app_zone_bound_to_the_host_network_only():
    zone = {a: v for p, a, v in _attrs(NET_TF) if p == (ZONE,)}
    assert zone["dns_name"] == '"run.app."'
    assert zone["visibility"] == '"private"'
    nets = [v for p, a, v in _attrs(NET_TF) if p == (ZONE, "private_visibility_config", "networks") and a == "network_url"]
    assert nets == ["google_compute_network.host[0].id"]
    rec = {a: v for p, a, v in _attrs(NET_TF) if p == (RECORD,)}
    assert rec["name"] == '"*.run.app."' and rec["type"] == '"A"'
    assert rec["managed_zone"] == "google_dns_managed_zone.host_run_app[0].name"
    assert rec["rrdatas"] == "[google_compute_global_address.psc_google_apis[0].address]"  # = var.host_psc_endpoint_ip
    # no googleapis.com zone: Google APIs keep their default path
    assert 'googleapis.com."' not in _read(NET_TF)


def test_egress_mode_variable_and_its_validation():
    assert _var_default("host_egress_mode") == '"PSC_PRIVATE_RANGES"'
    body = _read(VARS_TF)
    body = body[body.index('variable "host_egress_mode" {'):]
    body = body[:body.index("\n}\n")]
    assert 'contains(["PSC_PRIVATE_RANGES", "NAT_ALL_TRAFFIC"], var.host_egress_mode)' in body


def test_design_a_nat_shape():
    nat = {a: v for p, a, v in _attrs(NET_TF) if p == (NAT,)}
    assert nat["router"] == "google_compute_router.host[0].name"
    assert nat["nat_ip_allocate_option"] == '"AUTO_ONLY"'
    assert nat["source_subnetwork_ip_ranges_to_nat"] == '"ALL_SUBNETWORKS_ALL_IP_RANGES"'
    assert nat["enable_dynamic_port_allocation"] == "true"
    assert nat["enable_endpoint_independent_mapping"] == "false"
    assert nat["min_ports_per_vm"] == "1024"
    assert {a: v for p, a, v in _attrs(NET_TF) if p == (NAT, "log_config")} == {"enable": "true", "filter": '"ERRORS_ONLY"'}
    router = {a: v for p, a, v in _attrs(NET_TF) if p == (ROUTER,)}
    assert router["network"] == "google_compute_network.host[0].id" and router["region"] == "var.region"


def test_deployer_grants_are_off_by_default_and_scoped_to_the_subnet():
    assert _var_default("host_network_deployer_grants") == "false"
    up_tf = os.path.join(PLATFORM, "platform_upgrader.tf")
    up = {a: v for p, a, v in _attrs(up_tf) if p == (UPGRADER_GRANT,)}
    assert up["count"] == "(var.enable_platform_upgrader && var.host_vpc_egress && var.host_network_deployer_grants) ? 1 : 0"
    assert up["role"] == '"roles/compute.networkUser"'
    assert up["subnetwork"] == "google_compute_subnetwork.host_run_egress[0].name"
    assert up["member"] == "google_service_account.stackvend_upgrader[0].member"
    # no project-level compute role anywhere
    for f in glob.glob(os.path.join(PLATFORM, "*.tf")):
        for head, body in _top_blocks(_read(f)):
            if head.startswith('resource "google_project_iam_member"'):
                assert "roles/compute." not in body, (os.path.basename(f), head)


def test_range_defaults_equal_the_ipam_reservations():
    res = _reservations()
    subnet = _var_default("host_egress_subnet_cidr").strip('"')
    psc = _var_default("host_psc_endpoint_ip").strip('"')
    assert subnet == res["HOST_RUN_EGRESS_SUBNET"]
    net = ipaddress.ip_network(res["HOST_PSC_GOOGLE_APIS"])
    assert net.prefixlen == 32 and psc == str(net.network_address)


def test_reserved_ranges_are_private_disjoint_and_outside_the_workload_supernet():
    res = _reservations()
    subnet = ipaddress.ip_network(res["HOST_RUN_EGRESS_SUBNET"])
    psc = ipaddress.ip_network(res["HOST_PSC_GOOGLE_APIS"])
    qa = ipaddress.ip_network(QA_SANDBOX_SUBNET)
    supernet = ipaddress.ip_network(_default_supernet())
    assert subnet.is_private and psc.is_private
    assert 8 <= subnet.prefixlen <= 26
    for a, b in ((subnet, psc), (subnet, qa), (psc, qa), (subnet, supernet), (psc, supernet)):
        assert not a.overlaps(b), (a, b)


def _default_supernet():
    tree = ast.parse(_read(os.path.join(REPO, "shared", "settings.py")))
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "ipam_supernet_cidr":
            for kw in node.value.keywords:
                if kw.arg == "default":
                    return ast.literal_eval(kw.value)
    raise AssertionError("ipam_supernet_cidr default not found")


def test_range_variables_have_validation_blocks():
    raw = _read(VARS_TF)
    for name, needles in (
        ("host_egress_subnet_cidr", ("cidrsubnet(var.host_egress_subnet_cidr, 0, 0) == var.host_egress_subnet_cidr",
                                     "<= 26", ">= 8", '"10.0.0.0/8"', '"172.16.0.0/12"', '"192.168.0.0/16"')),
        ("host_psc_endpoint_ip", ('cidrhost("${var.host_psc_endpoint_ip}/32", 0) == var.host_psc_endpoint_ip',
                                  '"10.0.0.0/8"', '"172.16.0.0/12"', '"192.168.0.0/16"')),
    ):
        body = raw[raw.index(f'variable "{name}" {{'):]
        body = body[:body.index("\n}\n")]
        assert body.count("validation {") == 2, name
        for n in needles:
            assert n in body, (name, n)


def test_no_ipv4_literal_outside_variable_blocks():
    """Resources and locals reference var.*; IPv4 literals live only in variable defaults/validation."""
    ipv4 = re.compile(r"(?<![\w.])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?(?![\w.])")
    for f in sorted(glob.glob(os.path.join(PLATFORM, "*.tf"))):
        for head, body in _top_blocks(_read(f)):
            if head.startswith("variable "):
                continue
            assert not ipv4.search(body), (os.path.basename(f), head, ipv4.search(body).group(0))


def test_walker_sees_the_new_blocks():
    """Negative control: the walker parses host_network.tf and the vpc_access paths exist (else the checks above
    would pass vacuously)."""
    got = _vpc_blocks()
    assert all(got[r] for r in VPC_PATHS)
    assert NETWORK in _blocks(NET_TF)


# ------------------------------------------------------------------------------
# Plan-level contract (tofu test, MOCK providers): tests/fixtures/host_network/host_network.tftest.hcl. Skipped unless
# OpenTofu and a local provider mirror (STACKVEND_TOFU_PROVIDER_MIRROR, filesystem-mirror layout) are present; nothing
# is downloaded. Both designs, the deployer grants and every refusal.
# ------------------------------------------------------------------------------
_TOFU = shutil.which("tofu")
_MIRROR = os.environ.get("STACKVEND_TOFU_PROVIDER_MIRROR", "")
_FIXTURE = os.path.join(HERE, "fixtures", "host_network", "host_network.tftest.hcl")


@unittest.skipUnless(_TOFU and _MIRROR and os.path.isdir(os.path.join(_MIRROR, "registry.opentofu.org", "hashicorp", "google")),
                     "needs OpenTofu and STACKVEND_TOFU_PROVIDER_MIRROR (local provider mirror); nothing is downloaded")
class TestHostNetworkPlanContractMockProviders(unittest.TestCase):
    def test_tofu_test_contract(self):
        tmp = tempfile.mkdtemp(prefix="hostnet-tf-")
        try:
            shutil.copytree(os.path.join(REPO, "infra"), os.path.join(tmp, "infra"),
                            ignore=shutil.ignore_patterns(".terraform*", "*.tfvars", "*.tfstate*"))
            shutil.copytree(os.path.join(REPO, "workflows"), os.path.join(tmp, "workflows"))
            os.makedirs(os.path.join(tmp, "mcp-servers", "kubernetes"))
            shutil.copy(os.path.join(REPO, "mcp-servers", "kubernetes", "helm-pin.json"), os.path.join(tmp, "mcp-servers", "kubernetes"))
            shutil.copy(os.path.join(REPO, "VERSION"), os.path.join(tmp, "VERSION"))
            plat = os.path.join(tmp, "infra", "platform")
            os.makedirs(os.path.join(plat, "tests"))
            shutil.copy(_FIXTURE, os.path.join(plat, "tests"))
            rc_file = os.path.join(tmp, "cli.tfrc")
            with open(rc_file, "w", encoding="utf-8") as f:
                f.write('provider_installation {\n  filesystem_mirror {\n    path    = "%s"\n'
                        '    include = ["registry.opentofu.org/*/*"]\n  }\n}\n' % _MIRROR)
            env = hermetic_guard.child_env(extra={"TF_CLI_CONFIG_FILE": rc_file, "TF_DATA_DIR": os.path.join(tmp, "tfdata"),
                                                  "TF_IN_AUTOMATION": "1"})
            init = subprocess.run([_TOFU, "init", "-backend=false", "-input=false", "-no-color"], cwd=plat, env=env,
                                  capture_output=True, text=True, timeout=300)
            self.assertEqual(init.returncode, 0, init.stdout + init.stderr)
            res = subprocess.run([_TOFU, "test", "-no-color", "-filter=tests/host_network.tftest.hcl"], cwd=plat, env=env,
                                 capture_output=True, text=True, timeout=900)
            self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
            self.assertIn("15 passed, 0 failed", res.stdout)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
