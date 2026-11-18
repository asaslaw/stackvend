"""gce-bastion-startup: a gce-bastion primary's code reaches its VM, by the gce-worker mechanism (lane 10).

The golden module compute-gce-bastion gains one optional input, `startup_script` (default null), set as the
instance's `startup-script` metadata key exactly like compute-gce-worker. The platform passes the service's own
`apps/<service>/startup.sh` (exact path, base64 only: no repository text reaches HCL verbatim). No settings map: a
gce-bastion takes no env bindings (service_topology accepts_env_vars=False, cross-checked against the module's
variables by tests/test_service_topology.py). Do No Harm: without a non-blank `apps/<service>/startup.sh` the rendered
main.tf is byte-identical to before (the PR-0b pre-change sha), and the module's metadata with the input unset is
exactly { enable-oslogin = "TRUE" }. Hermetic."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import base64
import hashlib
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import hcl2  # noqa: E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: put eval/.deps on PYTHONPATH; this file must not skip", pytrace=False)

from developer_agent import terraform_engine as te  # noqa: E402
from fd4atc_render import without_fd4atc  # noqa: E402  (FD-4AT-c pin normalization)
from visible_rename_render import pre_visible_rename  # noqa: E402  (VISIBLE-RENAME pin normalization)
from developer_agent.contract_inspector import _EMBEDDED_MODULE_CONTRACTS  # noqa: E402
from developer_agent.topology_wiring import (  # noqa: E402
    render_gce_bastion_code_lines,
    vm_startup_script_expr,
)

MODULE = "compute-gce-bastion"
MODULE_DIR = os.path.join(REPO_ROOT, "infra", "modules", MODULE)
# tests/test_lane14_pr0b_regulated.py PRE_PR0B_STANDARD_RENDER_SHA256["main:gce-bastion"] (also ":full"): the bastion
# main.tf as rendered before this change, for both argument sets below.
PRE_CHANGE_BASTION_MAIN_SHA256 = "66c60e93f287ec4ffe48151c90f3b2624b8d906e4d3b44982d2cd43c466fdced"
FULL_ARGS = dict(allow_unauthenticated=False, enable_direct_iap=True, authorized_invoker_members=["domain:example.com"],
                 custom_tf_content='resource "google_compute_network" "vpc" {\n  name = "v"\n}\n',
                 env_vars_override={"X_URL": '"https://x"'},
                 scaling_override={"min_instances": 1, "max_instances": 3, "cpu_idle": False})
SCRIPT = '#!/bin/bash\necho "}\nresource \\"x\\" \\"y\\" {}" ${var.project_id}\ncat > /opt/x.py <<\'EOF\'\nprint(1)\nEOF\n'


def sha(text):
    # FD-4AT-c: the pin predates the foundation module's github_repository_id line (tests/fd4atc_render.py).
    # VISIBLE-RENAME (owner 10-26): ... and the StackVend header comment (tests/visible_rename_render.py).
    # RT14-F1: ... and the root zone read + `zone` input of a bastion render (tests/rt14_bastion_zone_render.py).
    from rt14_bastion_zone_render import without_rt14_bastion_zone
    text = without_rt14_bastion_zone(text)
    return hashlib.sha256(without_fd4atc(pre_visible_rename(text)).encode("utf-8")).hexdigest()


def main_tf(files=None, service_name="api", product="shop", spec="", **kw):
    return te.generate_golden_main_tf(product, "gce-bastion", spec, service_name=service_name, app_files=files, **kw)


def compute_body(text):
    return [m for m in hcl2.loads(text)["module"] if "compute" in m][0]["compute"]


def decoded(body):
    expr = body["startup_script"]
    assert expr.startswith('${base64decode("') and expr.endswith('")}')
    return base64.b64decode(expr[len('${base64decode("'):-len('")}')]).decode("utf-8")


# ------------------------------------------------------------------------------------------- Do No Harm (renders)
@pytest.mark.parametrize("files", [
    None,
    {},
    {"apps/api/main.py": "x = 1\n", "apps/api/Procfile": "web: uvicorn main:app\n"},   # code, but no startup.sh
    {"apps/api/startup.sh": ""},                                                       # empty
    {"apps/api/startup.sh": " \n\t\n"},                                                # whitespace only
    {"apps/other/startup.sh": "#!/bin/bash\n"},                                        # another service's script
    {"apps/api/scripts/startup.sh": "#!/bin/bash\n"},                                  # not the exact path
    {"startup.sh": "#!/bin/bash\n", "scripts/startup.sh": "#!/bin/bash\n"},            # not under apps/<service>/
    {"apps/api/startup.sh": None},                                                     # not text
])
@pytest.mark.parametrize("full", [False, True])
def test_no_startup_script_renders_byte_identical(files, full):
    kwargs = FULL_ARGS if full else {}
    product = "shop_x" if full else "shop"
    spec = "keep 2 warm instances" if full else ""
    assert sha(main_tf(files, product=product, spec=spec, **kwargs)) == PRE_CHANGE_BASTION_MAIN_SHA256


def test_no_service_name_never_reads_a_script():
    files = {"apps/shop/startup.sh": "#!/bin/bash\n"}
    assert sha(te.generate_golden_main_tf("shop", "gce-bastion", "", app_files=files)) == PRE_CHANGE_BASTION_MAIN_SHA256
    assert render_gce_bastion_code_lines(None, files) == ""
    assert render_gce_bastion_code_lines("", files) == ""


@pytest.mark.parametrize("arch", ["cloudrun", "gke-autopilot", "event-worker", "foundation-only"])
def test_other_archetypes_ignore_a_startup_script(arch):
    files = {"apps/api/startup.sh": SCRIPT, "apps/api/main.py": "x = 1\n"}
    base = te.generate_golden_main_tf("shop", arch, "", service_name="api", app_files={"apps/api/main.py": "x = 1\n"})
    assert te.generate_golden_main_tf("shop", arch, "", service_name="api", app_files=files) == base
    assert "startup_script" not in base


# ------------------------------------------------------------------------------------------- with the bastion's code
def test_startup_script_reaches_the_module_as_base64_only():
    text = main_tf({"apps/api/startup.sh": SCRIPT, "apps/api/export.py": "print(1)\n"})
    body = compute_body(text)
    assert body["source"] == "../modules/compute-gce-bastion"
    assert decoded(body) == SCRIPT                       # byte-exact script
    assert 'resource \\"x\\"' not in text and "print(1)" not in text and "${var.project_id}\n" not in text
    assert body["depends_on"] == ["${module.foundation}"]


@pytest.mark.parametrize("env", [None, {"OPS_REPORTS_BUCKET": "google_storage_bucket.ops_reports.name"}])
def test_no_settings_map_is_rendered(env):
    """A gce-bastion takes no env bindings: neither the topology override nor the legacy extraction reaches it."""
    custom = 'resource "google_storage_bucket" "ops_reports" {\n  name = "r"\n  location = "US"\n}\n'
    text = main_tf({"apps/api/startup.sh": SCRIPT}, custom_tf_content=custom, env_vars_override=env)
    body = compute_body(text)
    assert set(body) == {"source", "project_id", "region", "zone", "product_id", "startup_script", "depends_on"}
    assert "env_vars" not in text.split('module "compute"')[1]


def test_rendered_block_layout_is_exact():
    lines = render_gce_bastion_code_lines("api", {"apps/api/startup.sh": "#!/bin/bash\n"})
    b64 = base64.b64encode(b"#!/bin/bash\n").decode()
    assert lines == f'\n  startup_script = base64decode("{b64}")\n'
    text = main_tf({"apps/api/startup.sh": "#!/bin/bash\n"})
    assert ("  product_id = var.product_id\n" + lines + "\n  depends_on = [module.foundation]\n}") in text


def test_only_the_compute_block_changes():
    """Everything outside the startup_script line is the pre-change render (foundation, wiring, ordering)."""
    plain = main_tf({})
    with_code = main_tf({"apps/api/startup.sh": "#!/bin/bash\n"})
    extra = render_gce_bastion_code_lines("api", {"apps/api/startup.sh": "#!/bin/bash\n"})
    assert extra and with_code.replace(extra, "", 1) == plain


def test_regulated_render_keeps_the_startup_script():
    from developer_agent.compliance_profile import RegulatedControls
    regulated = RegulatedControls(profile="HIPAA", source="test", cmek=True, audit_logging=True, region="us-central1")
    text = main_tf({"apps/api/startup.sh": SCRIPT}, regulated=regulated)
    assert decoded(compute_body(text)) == SCRIPT
    # and without the script the regulated bastion render is the one it was before
    plain = main_tf({}, regulated=regulated)
    assert main_tf({"apps/api/startup.sh": " "}, regulated=regulated) == plain and "startup_script" not in plain


def test_vm_startup_script_expr_is_the_lane10_worker_encoding():
    script = "#!/bin/bash\npoweroff\n"
    assert vm_startup_script_expr({"apps/w/startup.sh": script}, "w") == \
        f'base64decode("{base64.b64encode(script.encode()).decode()}")'
    for files in (None, {}, {"apps/w/startup.sh": "  \n"}, {"apps/w/startup.sh": 3}):
        assert vm_startup_script_expr(files, "w") is None
    assert vm_startup_script_expr({"apps/w/startup.sh": script}, None) is None


# ------------------------------------------------------------------------------------------- the module itself
def _blocks(path, kind):
    with open(path, encoding="utf-8") as f:
        return {k: v for b in hcl2.load(f).get(kind, []) for k, v in b.items()}


def test_module_input_defaults_to_today():
    variables = _blocks(os.path.join(MODULE_DIR, "variables.tf"), "variable")
    assert variables["startup_script"]["default"] is None
    assert variables["startup_script"]["type"].strip("${}") == "string"
    assert "env_vars" not in variables   # service_topology CAPABILITIES["gce-bastion"].accepts_env_vars stays False
    with open(os.path.join(MODULE_DIR, "main.tf"), encoding="utf-8") as f:
        inst = [r for r in hcl2.load(f)["resource"] if "google_compute_instance" in r][0]["google_compute_instance"]
    md = inst["bastion"]["metadata"]
    # merge(script-or-nothing, oslogin): with the input unset the value is exactly { enable-oslogin = "TRUE" }
    # (checked with `tofu console` under the oracle and production tofu, see the report).
    assert md.index("var.startup_script == null ? {} :") < md.index("enable-oslogin")
    assert md.count("startup-script") == 1 and md.count("enable-oslogin") == 1
    # The instance name keeps today's RFC 1123 form (unchanged by this change).
    assert 'bastion-${replace(var.product_id, "_", "-")}' in inst["bastion"]["name"]


def _payload_entry(path):
    with open(os.path.join(REPO_ROOT, path), encoding="utf-8") as f:
        tree = ast.parse(f.read())
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", "") == "BUILTIN_MODULE_FILES":
            return ast.literal_eval(node.value)[MODULE]
    raise AssertionError(f"{path}: no BUILTIN_MODULE_FILES")


@pytest.mark.parametrize("payload", [
    "shared/builtin_modules_payload.py", "mcp-servers/terraform/shared/builtin_modules_payload.py",
    "apps/orchestrator-gateway/shared/builtin_modules_payload.py",
    "apps/control-center/shared/builtin_modules_payload.py"])
def test_payload_copies_equal_the_module(payload):
    entry = _payload_entry(payload)
    assert sorted(entry) == ["main.tf", "outputs.tf", "variables.tf"]
    for fn, text in entry.items():
        with open(os.path.join(MODULE_DIR, fn), encoding="utf-8") as f:
            assert text == f.read(), (payload, fn)
        with open(os.path.join(REPO_ROOT, "apps", "control-center", "infra", "modules", MODULE, fn),
                  encoding="utf-8") as f:
            assert text == f.read(), ("control-center copy", fn)


def test_embedded_contract_equals_the_module_files():
    """Same rule as the CI-5 parity test (branch ci5-embedded-contracts), for this entry."""
    entry = _EMBEDDED_MODULE_CONTRACTS[MODULE]
    assert set(entry["inputs"]) == set(_blocks(os.path.join(MODULE_DIR, "variables.tf"), "variable"))
    assert set(entry["outputs"]) == set(_blocks(os.path.join(MODULE_DIR, "outputs.tf"), "output"))
    for kind in ("inputs", "outputs"):
        assert entry[kind] == sorted(set(entry[kind]))
