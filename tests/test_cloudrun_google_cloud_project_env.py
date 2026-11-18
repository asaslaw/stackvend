import hermetic_guard  # noqa: F401  (must be the first import: WAVE1 standing rule)

"""CLOUDRUN-GOOGLE-CLOUD-PROJECT-ENV (register row, owner 11-10): every golden module that runs workload code on Cloud
Run sets GOOGLE_CLOUD_PROJECT = var.project_id next to PROJECT_ID. Cloud Run sets no project variable, and Google
client libraries (google-auth reads GOOGLE_CLOUD_PROJECT) and most generated code read it; a generated app that fell
back to a literal project published to the wrong topic and returned 500 on every event.

1. Static (python-hcl2, no provider, no network): compute-cloudrun emits the entry from a `dynamic "env"` block whose
   for_each is empty exactly when `var.env_vars` already has the key (a caller's own value stays the single entry;
   Cloud Run env names must be unique); compute-event-worker (no caller env input) sets it literally; the Control
   Center module copy and the four embedded payload copies match the modules on disk.
2. Topology: GOOGLE_CLOUD_PROJECT is a RESERVED_ENV_KEYS name (a topology may not bind it, and the audience default
   logic counts it among the names the platform sets on a callee).
3. Plan-level (tofu test, MOCK providers; skipped without OpenTofu + STACKVEND_TOFU_PROVIDER_MIRROR): no caller key ->
   one entry with the project id; a caller key -> one entry with the caller's value.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for _p in (os.path.join(REPO, "apps", "orchestrator-gateway"), REPO):
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    import hcl2  # noqa: E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: install apps/orchestrator-gateway/requirements.txt", pytrace=False)

from shared import service_topology as st  # noqa: E402

NAME = "GOOGLE_CLOUD_PROJECT"
MODULES = ("compute-cloudrun", "compute-event-worker")
PAYLOADS = [os.path.join(REPO, p, "builtin_modules_payload.py") for p in
            ("shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared", "mcp-servers/terraform/shared")]
TFTEST = os.path.join(REPO, "tests", "fixtures", "cloudrun_gcp_env", "env.tftest.hcl")
TOFU = shutil.which("tofu")
MIRROR = os.environ.get("STACKVEND_TOFU_PROVIDER_MIRROR", "")
MIN_TOFU = (1, 8, 0)   # mock_provider in `tofu test`


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def _module_text(module):
    return _read(os.path.join(REPO, "infra", "modules", module, "main.tf"))


def _containers(module, rtype, name):
    body = hcl2.loads(_module_text(module))
    for res in body["resource"]:
        if rtype in res and name in res[rtype]:
            tmpl = res[rtype][name]["template"][0]
            if rtype == "google_cloud_run_v2_job":
                tmpl = tmpl["template"][0]
            return tmpl["containers"]
    raise AssertionError(f"{module}: {rtype}.{name} not found")


def _literal_env(container):
    return [e for e in container.get("env", []) if e.get("name") == NAME]


def _dynamic_env(container):
    out = []
    for dyn in container.get("dynamic", []):
        env = dyn.get("env")
        if isinstance(env, dict) and any(c.get("name") == NAME for c in env.get("content", [])):
            out.append(env)
    return out


# ------------------------------------------------------------------------------------------------ static
def test_cloudrun_module_sets_it_only_when_the_caller_does_not():
    (container,) = _containers("compute-cloudrun", "google_cloud_run_v2_service", "app")
    assert _literal_env(container) == []            # never an unconditional entry (it could double a caller key)
    (dyn,) = _dynamic_env(container)
    assert dyn["content"] == [{"name": NAME, "value": "${env.value}"}]
    for_each = dyn["for_each"]
    # A typed key check on the caller's map, never a guess: empty when var.env_vars has the key, else [project_id].
    assert for_each.startswith('${contains(keys(var.env_vars), "GOOGLE_CLOUD_PROJECT") ? [] : [')
    assert "var.project_id" in for_each
    # Next to PROJECT_ID in the source, and PROJECT_ID is still a literal entry.
    text = _module_text("compute-cloudrun")
    assert text.index('name  = "PROJECT_ID"') < text.index(f'name  = "{NAME}"') < text.index('name  = "ENVIRONMENT"')
    assert [e["value"] for e in container["env"] if e["name"] == "PROJECT_ID"] == ["${var.project_id}"]


def test_cloudrun_module_caller_env_is_still_merged():
    (container,) = _containers("compute-cloudrun", "google_cloud_run_v2_service", "app")
    caller = [d["env"] for d in container["dynamic"] if d["env"]["for_each"] == "${var.env_vars}"]
    assert caller == [{"for_each": "${var.env_vars}", "content": [{"name": "${env.key}", "value": "${env.value}"}]}]


def test_event_worker_job_sets_it_literally():
    (container,) = _containers("compute-event-worker", "google_cloud_run_v2_job", "worker")
    assert _literal_env(container) == [{"name": NAME, "value": "${var.project_id}"}]
    assert _dynamic_env(container) == []
    # No caller env input, so the literal entry can never be doubled.
    variables = hcl2.loads(_read(os.path.join(REPO, "infra", "modules", "compute-event-worker", "variables.tf")))
    names = {k for v in variables["variable"] for k in v}
    assert "env_vars" not in names and not st.CAPABILITIES["event-worker"].accepts_env_vars


PRE_CHANGE_SHA256 = {   # main c0e82eff, before this row
    "compute-cloudrun": "e80fb17e423ac726bf369a98033b51bc3d3a81cf9fc296fd35da116f99103c36",
    "compute-event-worker": "3de158d59c7d7eff928000a371d557ebbaf308f5892b7af195efff41b6ca42c2",
}


@pytest.mark.parametrize("module", MODULES)
def test_do_no_harm_the_env_entry_is_the_only_change(module):
    import hashlib
    from google_cloud_project_env_delta import pre_google_cloud_project_env
    before = pre_google_cloud_project_env(f"infra/modules/{module}/main.tf", _module_text(module))
    assert hashlib.sha256(before.encode("utf-8")).hexdigest() == PRE_CHANGE_SHA256[module]


@pytest.mark.parametrize("module", MODULES)
def test_control_center_copy_and_payloads_match_disk(module):
    disk = _module_text(module)
    assert _read(os.path.join(REPO, "apps", "control-center", "infra", "modules", module, "main.tf")) == disk
    for path in PAYLOADS:
        ns = {}
        exec(compile(_read(path), path, "exec"), ns)  # noqa: S102 - repo-owned data module
        assert ns["BUILTIN_MODULE_FILES"][module]["main.tf"] == disk, path


# ------------------------------------------------------------------------------------------------ topology
def test_reserved_env_keys_name_it_in_both_copies():
    assert NAME in st.RESERVED_ENV_KEYS
    gateway_copy = os.path.join(REPO, "apps", "orchestrator-gateway", "shared", "service_topology.py")
    assert _read(gateway_copy) == _read(os.path.join(REPO, "shared", "service_topology.py"))


def test_a_topology_may_not_bind_it():
    raw = {"services": [{"name": "api", "kind": "cloudrun"}], "primary_service": "api", "edges": [],
           "resources": [{"type": "google_storage_bucket", "logical_name": "b",
                          "consumers": [{"service": "api", "env_key": NAME}]}]}
    vt, diags = st.validate_service_topology(raw, product_id="p")
    assert vt is None
    assert "TOPOLOGY.ENV_KEY_RESERVED" in [d.code for d in diags if d.severity == "error"]


def test_platform_env_bridge_never_binds_it():
    """Do No Harm: the platform's own renders pass no GOOGLE_CLOUD_PROJECT in env_vars (HB-05 binds PROJECT_ID and
    GCP_PROJECT_ID only), so rendered workload IaC is byte-unchanged and the module's entry is the one the app gets."""
    from developer_agent.terraform_engine import extract_custom_resource_env_vars
    custom = ('resource "google_pubsub_topic" "events" {\n  name = "events"\n}\n'
              'resource "google_storage_bucket" "data" {\n  name = "data"\n  location = "US"\n}\n')
    env = extract_custom_resource_env_vars(custom, {"apps/app/main.py": "import os\n"})
    assert env and "PROJECT_ID" in env and NAME not in env


# ------------------------------------------------------------------------------------------------ tofu (optional)
def _tofu_version():
    if not TOFU:
        return None
    try:
        out = subprocess.run([TOFU, "version", "-json"], capture_output=True, text=True, timeout=30,
                             env=hermetic_guard.child_env())
        parts = json.loads(out.stdout)["terraform_version"].split("-", 1)[0].split(".")
        return tuple(int(p) for p in parts[:3])
    except Exception:
        return None


@pytest.mark.skipif(not (TOFU and MIRROR and os.path.isdir(os.path.join(MIRROR, "registry.opentofu.org", "hashicorp",
                                                                          "google-beta"))),
                    reason="needs OpenTofu and STACKVEND_TOFU_PROVIDER_MIRROR (local provider mirror); nothing is downloaded")
def test_tofu_plan_with_mock_providers():
    version = _tofu_version()
    if version is None or version < MIN_TOFU:
        pytest.skip(f"needs OpenTofu >= {'.'.join(map(str, MIN_TOFU))} (found {version}): mock_provider")
    tmp = tempfile.mkdtemp(prefix="gcpenv-")
    sock_dir = None
    try:
        mod = os.path.join(tmp, "compute-cloudrun")
        shutil.copytree(os.path.join(REPO, "infra", "modules", "compute-cloudrun"), mod,
                        ignore=shutil.ignore_patterns(".terraform*", "*.tfstate*"))
        os.makedirs(os.path.join(mod, "tests"))
        shutil.copy(TFTEST, os.path.join(mod, "tests"))
        rc_file = os.path.join(tmp, "cli.tfrc")
        with open(rc_file, "w", encoding="utf-8") as f:
            f.write('provider_installation {\n  filesystem_mirror {\n    path    = "%s"\n'
                    '    include = ["registry.opentofu.org/*/*"]\n  }\n}\n' % MIRROR)
        extra = {"TF_CLI_CONFIG_FILE": rc_file, "TF_DATA_DIR": os.path.join(tmp, "tfdata"), "TF_IN_AUTOMATION": "1"}
        if len(tempfile.gettempdir()) > 60:  # macOS caps provider unix-socket paths at 104 bytes
            sock_dir = tempfile.mkdtemp(prefix="gcpenv-", dir="/private/tmp" if os.path.isdir("/private/tmp") else "/tmp")
            extra["TMPDIR"] = sock_dir
        env = hermetic_guard.child_env(extra=extra)
        init = subprocess.run([TOFU, "init", "-backend=false", "-input=false", "-no-color"], cwd=mod, env=env,
                              capture_output=True, text=True, timeout=300)
        assert init.returncode == 0, init.stdout + init.stderr
        res = subprocess.run([TOFU, "test", "-no-color"], cwd=mod, env=env, capture_output=True, text=True, timeout=600)
        assert res.returncode == 0, res.stdout + res.stderr
        assert "3 passed, 0 failed" in res.stdout
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        if sock_dir:
            shutil.rmtree(sock_dir, ignore_errors=True)
