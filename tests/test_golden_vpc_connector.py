"""FD-4BH (owner 10-12): golden module `networking-vpc-connector`, the Serverless VPC Access connector.

The eval baseline of 10-12 showed the AI hand-writing `google_vpc_access_connector` in 8 of 27 runs. On the typed-intent
path (generate mode) the platform already renders the connector itself when a Cloud Run service consumes a
private-network resource (TI-5c): this row makes that render a call of the golden module (`module.stackvend_connector`)
instead of a raw resource, with a `moved` block from the TI-5c address so a connector rendered before is moved, not
re-created. The AI still never declares a connector (the type stays lane11_owned, the module is platform_only).

- golden module: required project_id / region / network / connector_cidr (no region or CIDR literal), /28 and
  network-address validation, RFC 1123 name (at most 25 characters), machine type and instance counts with safe
  defaults; outputs id / name / self_link / region / ip_cidr_range. Registered in infra/modules, the Control Center copy,
  the four payload copies, the typed-IaC catalog (platform_only), the API table and the lane-11 allocation table.
- IPAM: the connector range is the workload's IPAM connector fact (var.connector_cidr), exactly as networking-vpc gets
  var.subnet_cidr; the region is var.region.
- intent: the platform render (module + moved), compute-cloudrun's vpc_access_connector = module.stackvend_connector.id
  (typed, exact), refusals unchanged (no new refusal of a hand-written connector), render byte-identity for every
  context without the connector, generate-mode prompt / response schema / classic contract / critic catalog unchanged.
- real engine (production tofu + mirror, when present): module `tofu test`; a root with the rendered network, connector,
  Cloud SQL and compute-cloudrun validates and plans (no cycle, invariant 6); a state holding the TI-5c connector plans a
  move with 0 to add / change / destroy.

Hermetic: python-hcl2 parsing; real tofu only when the untracked production column is present (network denied by
sandbox-exec for the one `plan` run).
"""
import hermetic_guard  # noqa: F401  (first import)

import functools
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TESTS = os.path.dirname(__file__)
for p in (GATEWAY, REPO_ROOT, TESTS, os.path.join(REPO_ROOT, "eval")):
    if p not in sys.path:
        sys.path.insert(0, p)

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from shared import iac_intent as ii  # noqa: E402
import golden_vpc_connector_cases as cases  # noqa: E402

ART = ii.load_artifacts()
MOD_ID = "networking-vpc-connector"
MODULE = os.path.join(REPO_ROOT, "infra", "modules", MOD_ID)
CC_MODULE = os.path.join(REPO_ROOT, "apps", "control-center", "infra", "modules", MOD_ID)
PAYLOADS = ["shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared", "mcp-servers/terraform/shared"]
FILES = ("main.tf", "outputs.tf", "variables.tf")
# sha256 of networking-vpc's files before FD-4BH (87be7e2e): the network module is not touched
NETWORKING_VPC_SHA256 = {
    "main.tf": "b5cabe527be1b839b4e7f2e0bda9cc741c1aeae37d501b45d57dfa65be9509bb",
    "outputs.tf": "f325dbca3e2352b3440626df85099d6e0b110429b5b4e9256220097113c9df5a",
    "variables.tf": "18f914fb61f2615c95650f56dbd9b03ff64cbad86192e114c4d8e015ec346afa",
}
# generate-mode IaC prompt / Gemini response schema / classic module contracts, computed with the code of 87be7e2e
PRE_GENERATE_PROMPT_SHA256 = "aee6700f756d4098c3e8229b331541681021e548b48188f981d8dca0ebccbc3e"
PRE_RESPONSE_SCHEMA_SHA256 = "9f92d4b6e21b6647abe3adb1f5826ebcf4587d74d0594416f1d8cfe09006f6a8"
PRE_CLASSIC_CONTRACTS_SHA256 = "ca2973f830180af3cd147aae5508690d0152d7c63c0b7a3a2842f34a9732a918"
# SCHEDULING-CRON-AUDIENCE (owner 11-14) later added exactly scheduling-cron's optional `audience` input to both texts
# (intended); without that one insertion each is the pinned text above.
AUDIENCE_PROMPT = ("- scheduling-cron: args audience (string, default null); http_method",
                   "- scheduling-cron: args http_method")
AUDIENCE_CONTRACT = ("- **Allowed Inputs**: audience, http_method, job_name_suffix",
                     "- **Allowed Inputs**: http_method, job_name_suffix")


# RT14-36 / RT14-35 (owner 11-14) later changed exactly: the generate-mode prompt no longer offers database-spanner
# `config` (HELD: the module sets regional-<region>; `region` is a FACT, never listed), and the classic contract lists
# the bastion's new optional `zone` and spanner's new `region` inputs (RT14-F2: and asks for region = var.region).
# Without those edits each text is the pin above.
RT14_PROMPT = ("- database-spanner: args database_name (string",
               '- database-spanner: args config (string, default "regional-us-central1"); database_name (string')
RT14_CONTRACT = (
    ("subnetwork_id, use_existing_subnetwork, zone\n", "subnetwork_id, use_existing_subnetwork\n"),
    ("processing_units, product_id, project_id, region\n", "processing_units, product_id, project_id\n"),
    # RT14-F2 (owner 11-14, option a): the classic spanner contract asks for region = var.region
    ("- **Required Wiring**: region = var.region (leave config unset; the instance configuration is then "
     "regional-<region>)\n", ""),
)
# OVERBROAD-SECRET-GRANT (owner 11-14) later removed exactly roles/secretmanager.secretAccessor from the
# google_project_iam_member role line (a project-wide accessor is IAC.PROJECT_WIDE_GRANT; the secret-scoped line keeps it).
OVERBROAD_PROMPT = ("roles/redis.viewer, roles/spanner.databaseUser",
                    "roles/redis.viewer, roles/secretmanager.secretAccessor, roles/spanner.databaseUser")


def _without_rt14(text, pairs):
    for added, before in pairs:
        assert text.count(added) == 1, added
        text = text.replace(added, before)
    return text


def _without_audience(text, pair):
    added, before = pair
    assert text.count(added) == 1, added
    return text.replace(added, before)


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _hcl(name):
    return hcl2.loads(Path(MODULE, name).read_text(encoding="utf-8"))


def _variables():
    return {n: b for blk in _hcl("variables.tf")["variable"] for n, b in blk.items()}


def _payload(rel):
    ns = {}
    path = os.path.join(REPO_ROOT, rel, "builtin_modules_payload.py")
    with open(path, encoding="utf-8") as f:
        exec(compile(f.read(), path, "exec"), ns)  # noqa: S102 - repo-owned data module
    return ns["BUILTIN_MODULE_FILES"]


def _render(name, d, args, net):
    g = ii.validate_intent(d, ART, cases.ctx_of(ii, args, net))
    assert g.ok, (name, [x.code for x in g.diagnostics])
    return ii.render_intent(g.validated)


def _files_sha(files):
    return hashlib.sha256(json.dumps(dict(files), sort_keys=True).encode()).hexdigest()


# ------------------------------------------------------------------------------------------------ golden module
def test_module_files_and_copies_are_identical():
    texts = {n: Path(MODULE, n).read_text(encoding="utf-8") for n in FILES}
    assert sorted(os.listdir(MODULE)) == sorted(FILES)   # flat: nothing extra is vendored into a workload
    for n in FILES:
        assert Path(CC_MODULE, n).read_text(encoding="utf-8") == texts[n], n
    for rel in PAYLOADS:
        assert _payload(rel)[MOD_ID] == texts, rel


def test_required_inputs_have_no_default_and_the_defaults_are_safe():
    v = _variables()
    assert set(v) == {"project_id", "region", "network", "connector_cidr", "name", "machine_type", "min_instances",
                      "max_instances"}
    for req in ("project_id", "region", "network", "connector_cidr"):
        assert "default" not in v[req], req   # region and CIDR come from the caller (AGENTS.md invariant 3)
    assert v["name"]["default"] == "vpc-connector"
    assert (v["machine_type"]["default"], v["min_instances"]["default"], v["max_instances"]["default"]) == (
        "e2-micro", 2, 3)


def test_the_connector_takes_every_value_from_a_variable_no_literal():
    (res,) = _hcl("main.tf")["resource"]
    body = res["google_vpc_access_connector"]["connector"]
    want = {"project": "project_id", "name": "name", "region": "region", "network": "network",
            "ip_cidr_range": "connector_cidr", "machine_type": "machine_type", "min_instances": "min_instances",
            "max_instances": "max_instances"}
    for attr, var in want.items():
        assert body[attr] == "${var." + var + "}", attr
    assert set(body) - set(want) == {"lifecycle"}
    import re
    text = "".join(Path(MODULE, n).read_text(encoding="utf-8") for n in FILES)
    assert re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", text) == []   # test-side check: no IPv4 / CIDR literal anywhere


def test_outputs_feed_compute_cloudrun_vpc_access_connector():
    outs = {n for blk in _hcl("outputs.tf")["output"] for n in blk}
    assert outs == {"id", "name", "self_link", "region", "ip_cidr_range"}
    cloudrun = {n: b for blk in hcl2.loads(Path(REPO_ROOT, "infra", "modules", "compute-cloudrun",
                                                  "variables.tf").read_text(encoding="utf-8"))["variable"]
                for n, b in blk.items()}
    assert cloudrun["vpc_access_connector"]["type"] == "string" and cloudrun["vpc_access_connector"]["default"] == ""


def test_networking_vpc_is_unchanged():
    for n, want in NETWORKING_VPC_SHA256.items():
        got = _sha(Path(REPO_ROOT, "infra", "modules", "networking-vpc", n).read_text(encoding="utf-8"))
        assert got == want, n


def test_platform_connector_name_satisfies_the_module_name_rule():
    import re
    rule = _variables()["name"]["validation"][0]["condition"]
    assert "^[a-z][-a-z0-9]{0,23}[a-z0-9]$" in rule
    assert re.fullmatch(r"[a-z][-a-z0-9]{0,23}[a-z0-9]", ii._PLATFORM_CONNECTOR_BODY["name"])


# ------------------------------------------------------------------------------------------------ registration
def test_catalog_lists_it_platform_only_never_ai_instantiable_and_check_passes():
    cat = json.loads(Path(REPO_ROOT, "shared", "iac_intent", "module_catalog.json").read_text(encoding="utf-8"))
    assert cat["platform_only"][MOD_ID] == "lane 11 (network)"
    assert MOD_ID not in cat["ai_instantiable"] and MOD_ID not in cat["modules"] and MOD_ID not in ART.ai_modules
    r = subprocess.run([sys.executable, os.path.join(REPO_ROOT, "scripts", "build_iac_catalog.py"), "--check"],
                       capture_output=True, text=True, cwd=REPO_ROOT, timeout=120, env=hermetic_guard.child_env())
    assert r.returncode == 0, (r.stdout + r.stderr)[-2000:]


def test_api_table_and_terraform_server_map_enable_vpcaccess():
    from shared.api_requirements import load_table, required_apis
    assert load_table()["modules"][MOD_ID] == ["vpcaccess.googleapis.com"]
    got = required_apis({"infra/workload/intent_facts.tf.json": json.dumps(
        {"module": {"c": {"source": "../modules/" + MOD_ID}}})})
    assert "vpcaccess.googleapis.com" in got.apis and not got.unknown
    import ast
    tree = ast.parse(Path(REPO_ROOT, "mcp-servers", "terraform", "service.py").read_text(encoding="utf-8"))
    node = next(n for n in tree.body if isinstance(n, ast.Assign)
                and getattr(n.targets[0], "id", None) == "GCP_MODULE_TO_API_MAP")
    assert ast.literal_eval(node.value)[MOD_ID] == ["vpcaccess.googleapis.com"]


def test_lane11_allocation_table_makes_a_module_call_take_the_ipam_connector_fact():
    from developer_agent import platform_facts as PF
    call = 'module "c" {\n  source         = "../modules/networking-vpc-connector"\n  connector_cidr = var.connector_cidr\n}\n'
    assert PF.required_network_purposes({"infra/workload/main.tf": call}) == {PF.PURPOSE_CONNECTOR}
    assert PF.allocation_attributes_for("module", ["c"], {"source": "../modules/" + MOD_ID}) == {
        "connector_cidr": PF.PURPOSE_CONNECTOR}
    # Do No Harm: the raw resource and the network module rows are unchanged
    raw = 'resource "google_vpc_access_connector" "c" {\n  ip_cidr_range = var.connector_cidr\n}\n'
    assert PF.required_network_purposes({"infra/workload/main.tf": raw}) == {PF.PURPOSE_CONNECTOR}
    # TI-5-R2 P5 (owner 10-25): + the optional psa_address (tests/test_ti5_r2_p5_psa_address_ipam.py)
    assert PF.ALLOCATION_ATTRIBUTES[("module", PF.NETWORK_MODULE_DIR)] == {"primary_subnet_cidr": PF.PURPOSE_SUBNET,
                                                                          "psa_address": PF.PURPOSE_PSA}


def test_ipam_connector_fact_is_a_28_like_the_module_requires():
    from developer_agent import platform_facts as PF
    from shared.settings import PlatformSettings
    assert PF.IpamPool.from_settings(PlatformSettings()).prefix_for(PF.PURPOSE_CONNECTOR) == 28
    assert PF.FACT_VARIABLE[PF.PURPOSE_CONNECTOR] == "connector_cidr"


def test_critic_catalog_does_not_offer_it_so_the_critic_prompt_is_unchanged():
    from architect_agent import red_team_critic as rtc
    assert MOD_ID in _payload("apps/orchestrator-gateway/shared")
    assert MOD_ID not in rtc.CANONICAL_GOLDEN_MODULES and MOD_ID in rtc.PLATFORM_RENDERED_MODULES


# ------------------------------------------------------------------------------------------------ IPAM + render
def test_platform_render_is_the_golden_module_on_the_ipam_fact_and_region():
    rr = _render(*cases.CONNECTOR_CASES[0])
    doc = json.loads(rr.files[ii.FACTS_RENDER_PATH])
    body = doc["module"][ii.PLATFORM_CONNECTOR_MODULE]
    assert body["source"] == "../modules/" + MOD_ID
    assert body["connector_cidr"] == "${var.connector_cidr}" and body["region"] == "${var.region}"
    assert body["project_id"] == "${var.project_id}" and body["network"] == "${module.stackvend_network.network_name}"
    assert (body["name"], body["min_instances"], body["max_instances"]) == ("stackvend-conn", 2, 3)
    assert body["depends_on"] == ["module.foundation", "module.stackvend_network"]
    assert set(body) - {"source", "depends_on"} <= set(_variables())   # only real module inputs
    assert "resource" not in doc   # no raw connector any more
    assert doc["moved"] == [{"from": "google_vpc_access_connector.stackvend_connector",
                             "to": "module.stackvend_connector.google_vpc_access_connector.connector"}]
    assert rr.platform_modules == ("networking-vpc", MOD_ID)
    assert ii.PLATFORM_CONNECTOR_REF == "module.stackvend_connector.id"


@pytest.mark.parametrize("case", cases.CONNECTOR_CASES, ids=[c[0] for c in cases.CONNECTOR_CASES])
def test_connector_render_differs_from_before_only_by_the_connector_form(case):
    """The only change: the TI-5c raw connector becomes the module call + its moved block. Undo exactly that and the
    render is the pre-FD-4BH bytes (pinned hash)."""
    rr = _render(*case)
    files = dict(rr.files)
    doc = json.loads(files[ii.FACTS_RENDER_PATH])
    body = doc["module"].pop(ii.PLATFORM_CONNECTOR_MODULE)
    assert doc.pop("moved") and body["source"] == "../modules/" + MOD_ID
    doc["resource"] = {"google_vpc_access_connector": {"stackvend_connector": dict(cases.LEGACY_CONNECTOR_BODY)}}
    files[ii.FACTS_RENDER_PATH] = json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    assert _files_sha(files) == cases.PRE_CHANGE[case[0]]


@pytest.mark.parametrize("case", cases.NO_CONNECTOR_CASES, ids=[c[0] for c in cases.NO_CONNECTOR_CASES])
def test_render_is_byte_identical_without_the_connector(case):
    rr = _render(*case)
    assert _files_sha(rr.files) == cases.PRE_CHANGE[case[0]]
    assert MOD_ID not in rr.platform_modules
    if ii.FACTS_RENDER_PATH in rr.files:   # RT F2: structural, on the parsed platform facts document
        doc = json.loads(rr.files[ii.FACTS_RENDER_PATH])
        assert "moved" not in doc and ii.PLATFORM_CONNECTOR_MODULE not in (doc.get("module") or {})


# ------------------------------------------------------------------------------------------------ intent grammar
def _codes(d, args=None, net=True):
    g = ii.validate_intent(d, ART, cases.ctx_of(ii, args or {}, net))
    return g.ok, sorted({x.code for x in g.diagnostics})


def test_negative_the_ai_cannot_declare_the_connector_module():
    ok, codes = _codes(cases.doc([{"module": MOD_ID, "name": "conn", "args": {}}]))
    assert not ok and "IAC.MODULE_UNKNOWN" in codes


def test_negative_the_platform_connector_module_name_is_reserved():
    ok, codes = _codes(cases.doc([dict(cases.BUCKET, name=ii.PLATFORM_CONNECTOR_MODULE)]))
    assert not ok and codes == ["IAC.DUPLICATE_ADDRESS"]
    assert _codes(cases.doc([dict(cases.BUCKET, name="conn")]))[0]   # any other name passes, as before


def test_raw_connector_in_an_intent_is_refused_exactly_as_before():
    """Unchanged refusal (the type is lane11_owned since TI-2), not a new one."""
    raw = {"type": "google_vpc_access_connector", "name": "c", "arguments": {"name": "c"}}
    ok, codes = _codes(cases.doc(resources=[raw]))
    assert not ok and codes == ["IAC.TYPE_NOT_ALLOWED"]
    assert ART.not_expressible_owner("google_vpc_access_connector") == "lane11_owned"


def test_sql_consumer_intent_with_the_connector_is_acyclic():
    name, d, args, net = cases.CONNECTOR_CASES[1]
    ok, codes = _codes(d, args, net)
    assert ok and "TOPOLOGY.CYCLE" not in codes


# ------------------------------------------------------------------------------------------------ compute wiring
def test_vpc_connector_line_accepts_exactly_the_platform_module_reference():
    from developer_agent.terraform_engine import vpc_connector_line
    assert vpc_connector_line(None) == ""
    assert vpc_connector_line("module.stackvend_connector.id") == "  vpc_access_connector  = module.stackvend_connector.id\n"
    # the hand-written resource form is accepted exactly as before (no new refusal)
    assert vpc_connector_line("google_vpc_access_connector.conn.id") == "  vpc_access_connector  = google_vpc_access_connector.conn.id\n"
    for bad in ("module.stackvend_connector.name", "module.other.id", "module.stackvend_connector.id.x",
                "module.stackvend_connector", "var.connector", "google_vpc_access_connector.c.name"):
        with pytest.raises(ValueError):
            vpc_connector_line(bad)


def test_cloud_run_consumer_gets_the_module_reference_and_others_none():
    from test_typed_iac_ti5c_network_facts import CLOUDSQL, SQL_MODULE, _assemble_net, intent, topo, vt_of
    from developer_agent.topology_wiring import _platform_connector_rendered, topology_vpc_connector
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        raw = topo([CLOUDSQL], services=(("shop", "cloudrun"), ("core", "cloudrun")), edges=(("shop", "core", "http"),))
        asm, bound, files = _assemble_net(vt_of(raw), {ii.INTENT_PATH: intent([SQL_MODULE])})
    assert asm.diagnostics == () and MOD_ID in asm.modules
    assert _platform_connector_rendered(files)
    assert topology_vpc_connector(bound, "shop", files) == "module.stackvend_connector.id"
    assert topology_vpc_connector(bound, "core", files) is None
    # an exact source is required: a module of that name with another source is not the platform connector
    doc = json.loads(files[ii.FACTS_RENDER_PATH])
    doc["module"][ii.PLATFORM_CONNECTOR_MODULE]["source"] = "../modules/other"
    assert not _platform_connector_rendered({ii.FACTS_RENDER_PATH: json.dumps(doc)})


def test_hand_written_connector_on_the_legacy_path_is_still_wired():
    """Classic HCL: a hand-written connector stays accepted and wired (platform-db-connector-wiring rule unchanged)."""
    import test_platform_db_connector_wiring as legacy
    legacy.test_ex08_cloud_sql_private_ip_consumer_gets_the_connector_on_the_instance_network()
    legacy.test_main_tf_with_connector_sets_exactly_the_module_input()


# ------------------------------------------------------------------------------------------------ prompts unchanged
def test_generate_mode_prompt_and_response_schema_are_unchanged():
    from developer_agent.juniors.iac_worker import build_iac_intent_worker_prompt
    text = build_iac_intent_worker_prompt(ART)
    assert _sha(_without_rt14(_without_audience(text, AUDIENCE_PROMPT), (RT14_PROMPT, OVERBROAD_PROMPT))) == PRE_GENERATE_PROMPT_SHA256
    assert MOD_ID not in text and "networks / subnets / connectors / firewalls / CIDRs" in text
    # GKE-WI-INTENT (ex04-1115b) later added exactly the typed gke_service_account member (two $defs and one anyOf
    # entry of Member; intended); without that insertion the schema is the pinned one above
    schema = json.loads(json.dumps(ii.response_json_schema(ART)))   # a copy: never mutate a shared object
    member_forms = schema["$defs"]["Member"]["properties"]["$member"]["anyOf"]
    assert member_forms[-1] == {"$ref": "#/$defs/MemberGkeServiceAccount"}
    del member_forms[-1]
    assert schema["$defs"].pop("MemberGkeServiceAccount")["required"] == ["gke_service_account"]
    assert set(schema["$defs"].pop("GkeServiceAccount")["properties"]) == {"namespace", "name"}
    assert _sha(str(schema)) == PRE_RESPONSE_SCHEMA_SHA256


def test_classic_contract_is_unchanged_and_does_not_list_the_module():
    from developer_agent import contract_inspector as ci
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        ci._CONTRACT_CACHE.clear()
        text = ci.get_all_active_module_contracts()
    assert MOD_ID not in text and MOD_ID not in ci._EMBEDDED_MODULE_CONTRACTS
    assert _sha(_without_rt14(_without_audience(text, AUDIENCE_CONTRACT), RT14_CONTRACT)) == PRE_CLASSIC_CONTRACTS_SHA256


# ------------------------------------------------------------------------------------------------ real engine
PROD_TOFU = os.path.join(REPO_ROOT, "eval", ".tools", "tofu-1.9.0", "tofu")
PROD_MIRROR = os.path.join(REPO_ROOT, "eval", ".tofu-mirror-prod")


@functools.lru_cache(maxsize=1)
def _skip_reason():
    if not (os.access(PROD_TOFU, os.X_OK) and os.path.isdir(PROD_MIRROR)):
        return "production column eval/.tools/tofu-1.9.0/tofu + eval/.tofu-mirror-prod (untracked) not present"
    return None


@pytest.fixture(scope="module")
def runner(tmp_path_factory):
    if _skip_reason():
        pytest.skip(_skip_reason())
    from stackvend_eval.tofu_runner import TofuRunner
    r = TofuRunner(tmp_path_factory.mktemp("vpc-connector-tofu"), Path(PROD_MIRROR), tofu_bin=PROD_TOFU)
    if not r.mirror_ready:
        pytest.skip(f"production mirror not verified: {r.mirror_manifest['status']}")
    return r


def _ok(r):
    assert r.returncode == 0, (r.stdout + r.stderr)[-4000:]
    return r.stdout + r.stderr


def _copy_module(src, dst):
    dst.mkdir(parents=True)
    for name in FILES:
        if Path(src, name).exists():
            (dst / name).write_text(Path(src, name).read_text(encoding="utf-8"), encoding="utf-8")


# 192.0.2.0/24 is RFC 5737 TEST-NET-1 (a test value; the platform passes the IPAM fact)
MODULE_TEST = '''mock_provider "google" {}

variables {
  project_id     = "mock-child-project"
  region         = "test-region1"
  network        = "workload-vpc"
  connector_cidr = "192.0.2.16/28"
}

run "passes_inputs_through_with_safe_defaults" {
  command = plan
  assert {
    condition     = google_vpc_access_connector.connector.ip_cidr_range == var.connector_cidr && google_vpc_access_connector.connector.region == var.region && google_vpc_access_connector.connector.network == var.network
    error_message = "the connector must use the given range, region and network verbatim"
  }
  assert {
    condition     = google_vpc_access_connector.connector.name == "vpc-connector" && google_vpc_access_connector.connector.machine_type == "e2-micro" && google_vpc_access_connector.connector.min_instances == 2 && google_vpc_access_connector.connector.max_instances == 3
    error_message = "default name and sizing"
  }
}

run "rejects_non_28_cidr" {
  command = plan
  variables {
    connector_cidr = "192.0.2.0/24"
  }
  expect_failures = [var.connector_cidr]
}

run "rejects_unaligned_cidr" {
  command = plan
  variables {
    connector_cidr = "192.0.2.17/28"
  }
  expect_failures = [var.connector_cidr]
}

run "rejects_garbage_cidr" {
  command = plan
  variables {
    connector_cidr = "not-a-cidr"
  }
  expect_failures = [var.connector_cidr]
}

run "rejects_ipv6" {
  command = plan
  variables {
    connector_cidr = "2001:db8::/28"
  }
  expect_failures = [var.connector_cidr]
}

run "rejects_long_or_bad_name" {
  command = plan
  variables {
    name = "a-very-long-connector-name-x"
  }
  expect_failures = [var.name]
}

run "rejects_trailing_hyphen_name" {
  command = plan
  variables {
    name = "conn-"
  }
  expect_failures = [var.name]
}

run "rejects_bad_machine_type" {
  command = plan
  variables {
    machine_type = "n2-standard-2"
  }
  expect_failures = [var.machine_type]
}

run "rejects_min_not_below_max" {
  command = plan
  variables {
    min_instances = 3
    max_instances = 3
  }
  expect_failures = [google_vpc_access_connector.connector]
}

run "rejects_too_many_instances" {
  command = plan
  variables {
    max_instances = 11
  }
  expect_failures = [var.max_instances]
}
'''


def test_module_validates_and_its_contract_tests_pass_with_the_production_engine(runner, tmp_path):
    wd = tmp_path / MOD_ID
    _copy_module(MODULE, wd)
    (wd / "tests").mkdir()
    (wd / "tests" / "connector.tftest.hcl").write_text(MODULE_TEST, encoding="utf-8")
    _ok(runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd))
    _ok(runner._run(["validate", "-no-color"], cwd=wd))
    out = _ok(runner._run(["test", "-test-directory=tests", "-filter=tests/connector.tftest.hcl", "-no-color"],
                          cwd=wd))
    assert "10 passed, 0 failed" in out, out[-4000:]


FOUNDATION_STUB = '''output "workload_sa_email" {
  value = "wsa@vpc-conn-test.iam.gserviceaccount.com"
}
'''
ROOT_VARS = '''variable "project_id" {
  default = "vpc-conn-test"
}
variable "region" {
  default = "test-region1"
}
variable "subnet_cidr" {
  default = "192.0.2.0/24"
}
variable "connector_cidr" {
  default = "198.51.100.16/28"
}

module "foundation" {
  source = "./modules/foundation-stub"
}

module "compute" {
  source                     = "./modules/compute-cloudrun"
  project_id                 = var.project_id
  product_id                 = "vpcconn"
  service_account_email      = module.foundation.workload_sa_email
  allow_unauthenticated      = false
  enable_direct_iap          = false
  authorized_invoker_members = ["user:ana@example.com"]
  vpc_access_connector       = module.stackvend_connector.id
  env_vars                   = { DB_HOST = module.db.private_ip_address }
}
'''
ROOT_TEST = '''mock_provider "google" {
  mock_resource "google_compute_network" {
    defaults = {
      id = "projects/vpc-conn-test/global/networks/stackvend-vpc"
    }
  }
}
mock_provider "google-beta" {}
mock_provider "random" {}

run "rendered_network_connector_db_and_service_plan_without_a_cycle" {
  command = plan
  assert {
    condition     = module.stackvend_connector.name == "stackvend-conn"
    error_message = "the root must plan (no dependency cycle) with the platform connector"
  }
}
'''


def _localize(text):
    """The rendered `../modules/<id>` sources (infra/workload/ -> infra/modules/) as this flat test root's
    ./modules/<id> (exact JSON rewrite of the module sources)."""
    doc = json.loads(text)
    for body in (doc.get("module") or {}).values():
        if body["source"].startswith("../modules/"):
            body["source"] = "./modules/" + body["source"][len("../modules/"):]
    return json.dumps(doc, indent=2)


def _rendered_root(rr, wd):
    for mid in ("networking-vpc", MOD_ID, "database-cloudsql", "compute-cloudrun"):
        _copy_module(os.path.join(REPO_ROOT, "infra", "modules", mid), wd / "modules" / mid)
    (wd / "modules" / "foundation-stub").mkdir()
    (wd / "modules" / "foundation-stub" / "main.tf").write_text(FOUNDATION_STUB, encoding="utf-8")
    for path, text in rr.files.items():
        (wd / os.path.basename(path)).write_text(_localize(text), encoding="utf-8")
    (wd / "main.tf").write_text(ROOT_VARS, encoding="utf-8")


def test_negative_the_root_check_sees_a_cycle_when_one_is_added(runner, tmp_path):
    """The acyclic result below is meaningful: the same root with the connector waiting for the service fails."""
    rr = _render(*cases.CONNECTOR_CASES[0])
    files = dict(rr.files)
    doc = json.loads(files[ii.FACTS_RENDER_PATH])
    doc["module"][ii.PLATFORM_CONNECTOR_MODULE]["depends_on"].append("module.compute")
    files[ii.FACTS_RENDER_PATH] = json.dumps(doc)
    wd = tmp_path / "cyclic"
    _rendered_root(ii.RenderResult(files, {}, "", (), ()), wd)
    _ok(runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd))
    r = runner._run(["validate", "-no-color"], cwd=wd)
    assert r.returncode != 0 and "Cycle" in r.stdout + r.stderr, (r.stdout + r.stderr)[-3000:]


def test_rendered_root_with_cloud_sql_consumer_validates_and_plans_acyclic(runner, tmp_path):
    """Invariant 6 in Terraform's own graph: compute -> connector -> network, db -> network, compute -> db."""
    rr = _render(*cases.CONNECTOR_CASES[0])
    wd = tmp_path / "root"
    _rendered_root(rr, wd)
    (wd / "tests").mkdir()
    (wd / "tests" / "root.tftest.hcl").write_text(ROOT_TEST, encoding="utf-8")
    _ok(runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd))
    _ok(runner._run(["validate", "-no-color"], cwd=wd))
    out = _ok(runner._run(["test", "-test-directory=tests", "-filter=tests/root.tftest.hcl", "-no-color"], cwd=wd))
    assert "1 passed, 0 failed" in out, out[-4000:]


NETWORK_STUB = '''output "network_name" {
  value = "stackvend-vpc"
}
'''
MOVE_VARS = '''variable "project_id" {
  default = "vpc-conn-test"
}
variable "region" {
  default = "test-region1"
}
variable "connector_cidr" {
  default = "198.51.100.16/28"
}

module "foundation" {
  source = "./modules/foundation-stub"
}

module "stackvend_network" {
  source = "./modules/network-stub"
}

provider "google" {
  project      = "vpc-conn-test"
  access_token = "offline-test-token"
}
'''
CONNECTOR_ID = "projects/vpc-conn-test/locations/test-region1/connectors/stackvend-conn"
LEGACY_STATE = {
    "version": 4, "terraform_version": "1.9.0", "serial": 1, "lineage": "0f3c1d7e-4b40-4c00-8000-000000000001",
    "outputs": {},
    "resources": [{"mode": "managed", "type": "google_vpc_access_connector", "name": "stackvend_connector",
                   "provider": "provider[\"registry.opentofu.org/hashicorp/google\"]",
                   "instances": [{"schema_version": 0, "sensitive_attributes": [], "attributes": {
                       "id": CONNECTOR_ID, "name": "stackvend-conn", "project": "vpc-conn-test",
                       "region": "test-region1", "network": "stackvend-vpc", "ip_cidr_range": "198.51.100.16/28",
                       "machine_type": "e2-micro", "min_instances": 2, "max_instances": 3,
                       "min_throughput": 200, "max_throughput": 300, "subnet": [], "self_link": CONNECTOR_ID,
                       "state": "READY", "connected_projects": [], "timeouts": None}}]}],
}


@pytest.mark.parametrize("with_moved", [True, False], ids=["moved", "negative-without-moved"])
def test_a_connector_rendered_before_moves_into_the_module_with_no_change(runner, tmp_path, with_moved):
    """The TI-5c raw connector in state + today's render (module + moved): plan is a move, 0 to add / change /
    destroy. Negative: without the moved block the same plan would destroy and re-create the connector, so the block is
    what keeps a connector rendered before FD-4BH. `plan -refresh=false` against a local state file; outbound network
    is denied by sandbox-exec and the provider gets a placeholder token, so nothing leaves the machine."""
    from stackvend_eval.tofu_runner import SANDBOX_EXEC, SANDBOX_PROFILE
    if not os.path.exists(SANDBOX_EXEC):
        pytest.skip("sandbox-exec not available (the plan run needs the network denied)")
    rr = _render(*cases.CONNECTOR_CASES[0])
    doc = json.loads(rr.files[ii.FACTS_RENDER_PATH])
    facts = {"module": {ii.PLATFORM_CONNECTOR_MODULE: doc["module"][ii.PLATFORM_CONNECTOR_MODULE]}}
    if with_moved:
        facts["moved"] = doc["moved"]
    wd = tmp_path / "move"
    _copy_module(MODULE, wd / "modules" / MOD_ID)
    for stub, text in (("foundation-stub", FOUNDATION_STUB), ("network-stub", NETWORK_STUB)):
        (wd / "modules" / stub).mkdir()
        (wd / "modules" / stub / "main.tf").write_text(text, encoding="utf-8")
    (wd / "intent_facts.tf.json").write_text(_localize(json.dumps(facts)), encoding="utf-8")
    (wd / "main.tf").write_text(MOVE_VARS, encoding="utf-8")
    (wd / "terraform.tfstate").write_text(json.dumps(LEGACY_STATE), encoding="utf-8")
    _ok(runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd))
    _ok(runner._run(["validate", "-no-color"], cwd=wd))
    p = subprocess.run([SANDBOX_EXEC, "-p", SANDBOX_PROFILE, runner.tofu, "plan", "-refresh=false", "-lock=false",
                        "-input=false", "-no-color"], cwd=str(wd), env=runner.env(), capture_output=True, text=True,
                       timeout=300)
    out = _ok(p)
    if with_moved:
        assert ("google_vpc_access_connector.stackvend_connector has moved to "
                "module.stackvend_connector.google_vpc_access_connector.connector") in out, out[-3000:]
        assert "0 to add, 0 to change, 0 to destroy" in out, out[-3000:]
    else:
        assert "1 to add, 0 to change, 1 to destroy" in out, out[-3000:]
