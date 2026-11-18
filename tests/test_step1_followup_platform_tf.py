"""Step 1 follow-up (owner decision 10-13), infra/platform: mcp-terraform-server gets 4096Mi and one warm instance;
every other platform Cloud Run service keeps exactly its previous cpu / memory / min_instance_count (the expected
plan diff is that one service's template). Static HCL checks (python-hcl2) plus an opt-in local `tofu console`
check of the new variable's validation (no backend, no providers, no network)."""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
import shutil
import subprocess
import tempfile

import pytest

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PLATFORM = os.path.join(REPO, "infra", "platform")
TOFU = shutil.which("tofu")

# Values before this change (main.tf @ b044672): contains([...terraform, gateway]) ? 2000m/2048Mi : 1000m/1024Mi; min 0.
BEFORE_BIG = {"mcp-terraform-server", "orchestrator-gateway-service"}


def _load(name):
    with open(os.path.join(PLATFORM, name)) as fh:
        return hcl2.load(fh)


def _locals():
    out = {}
    for block in _load("main.tf").get("locals", []):
        out.update(block)
    return out


def _services_resource():
    for res in _load("main.tf")["resource"]:
        if "google_cloud_run_v2_service" in res and "services" in res["google_cloud_run_v2_service"]:
            return res["google_cloud_run_v2_service"]["services"]
    raise AssertionError("google_cloud_run_v2_service.services not found")


def _min_instances_default():
    for v in _load("variables.tf")["variable"]:
        if "cloud_run_min_instances" in v:
            return v["cloud_run_min_instances"]["default"]
    raise AssertionError("variable cloud_run_min_instances not found")


def test_only_the_terraform_server_changes_size_and_scaling():
    loc = _locals()
    services = loc["cloud_run_services"]
    cpu, mem = loc["cloud_run_service_cpu"], loc["cloud_run_service_memory"]
    mins = _min_instances_default()
    assert set(cpu) <= set(services) and set(mem) <= set(services) and set(mins) <= set(services)
    changed = {}
    for svc in services:
        before = ("2000m", "2048Mi", 0) if svc in BEFORE_BIG else ("1000m", "1024Mi", 0)
        after = (cpu.get(svc, "1000m"), mem.get(svc, "1024Mi"), mins.get(svc, 0))
        if after != before:
            changed[svc] = (before, after)
    assert changed == {"mcp-terraform-server": (("2000m", "2048Mi", 0), ("2000m", "4096Mi", 0))}  # owner 10-13: no warm instance by default


def test_services_template_reads_the_maps():
    svc = _services_resource()
    container = svc["template"][0]["containers"][0]
    limits = container["resources"][0]["limits"]
    assert "lookup(local.cloud_run_service_cpu, each.key, \"1000m\")" in limits["cpu"]
    assert "lookup(local.cloud_run_service_memory, each.key, \"1024Mi\")" in limits["memory"]
    scaling = svc["template"][0]["scaling"][0]
    assert "lookup(var.cloud_run_min_instances, each.key, 0)" in str(scaling["min_instance_count"])
    assert scaling["max_instance_count"] == 5
    preconds = [p["condition"] for p in svc["lifecycle"][0]["precondition"]]
    assert any("keys(var.cloud_run_min_instances)" in c and "local.cloud_run_services" in c for c in preconds)
    # template[0].scaling stays managed (not in ignore_changes), so the min instance is applied, not ignored
    assert all("template[0].scaling" not in str(i) for i in svc["lifecycle"][0]["ignore_changes"])


def _block(text, header):
    """The full `header { ... }` block (brace-balanced; test-only extraction of a known block)."""
    start = text.index(header)
    depth, i = 0, text.index("{", start)
    while True:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
        i += 1


@pytest.mark.skipif(not TOFU, reason="needs OpenTofu (local `tofu console`, no backend)")
@pytest.mark.parametrize("value,ok", [('{ "mcp-terraform-server" = 1 }', True), ("{}", True),
                                      ('{ "mcp-terraform-srever" = 1 }', False)])
def test_unknown_service_key_fails_the_precondition(tmp_path, value, ok):
    main = open(os.path.join(PLATFORM, "main.tf")).read()
    svc = _block(main, 'resource "google_cloud_run_v2_service" "services"')
    cond = next(ln.split("=", 1)[1].strip() for ln in svc.splitlines()
                if ln.strip().startswith("condition") and "cloud_run_min_instances" in ln)
    variables = open(os.path.join(PLATFORM, "variables.tf")).read()
    module = "\n".join([_block(variables, 'variable "cloud_run_min_instances"'),
                        "locals {\n  " + _block(main, "cloud_run_services = {") + "\n  probe = " + cond + "\n}"])
    (tmp_path / "main.tf").write_text(module)
    (tmp_path / "t.tfvars").write_text("cloud_run_min_instances = %s\n" % value)
    r = subprocess.run([TOFU, "console", "-var-file=t.tfvars"], input="local.probe\n", cwd=str(tmp_path),
                       capture_output=True, text=True, timeout=60,
                       env=hermetic_guard.child_env(extra={"TF_IN_AUTOMATION": "1"}))
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip() == ("true" if ok else "false")


@pytest.mark.skipif(not TOFU, reason="needs OpenTofu (local `tofu console`, no backend)")
def test_platform_files_are_tofu_fmt_clean():
    r = subprocess.run([TOFU, "fmt", "-check", "-diff", "main.tf", "variables.tf"], cwd=PLATFORM, capture_output=True,
                       text=True, timeout=60, env=hermetic_guard.child_env(extra={"TF_IN_AUTOMATION": "1"}))
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.skipif(not TOFU, reason="needs OpenTofu (local `tofu console`, no backend)")
def test_min_instances_validation_with_tofu_console():
    tmp = tempfile.mkdtemp(prefix="s1fu-var-")
    try:
        shutil.copy(os.path.join(PLATFORM, "variables.tf"), tmp)
        for value, ok in (("{}", True), ('{ "mcp-terraform-server" = 1 }', True), ('{ "a" = 5 }', True),
                          ('{ "a" = -1 }', False), ('{ "a" = 6 }', False), ('{ "a" = 1.5 }', False)):
            tfv = os.path.join(tmp, "t.tfvars")
            with open(tfv, "w") as f:
                f.write('project_id = "proj-aaaa1"\ncloud_run_min_instances = %s\n' % value)
            r = subprocess.run([TOFU, "console", "-var-file=" + tfv], input="jsonencode(var.cloud_run_min_instances)\n",
                               cwd=tmp, capture_output=True, text=True, timeout=60,
                               env={"PATH": "/usr/bin:/bin", "HOME": tmp, "TF_DATA_DIR": os.path.join(tmp, ".d"),
                                    "CHECKPOINT_DISABLE": "1"})
            if ok:
                assert r.returncode == 0 and "Invalid value for variable" not in r.stderr, (value, r.stderr)
            else:
                assert "Invalid value for variable" in r.stderr, value
        r = subprocess.run([TOFU, "console"], input="jsonencode(var.cloud_run_min_instances)\n", cwd=tmp,
                           capture_output=True, text=True, timeout=60,
                           env={"PATH": "/usr/bin:/bin", "HOME": tmp, "TF_DATA_DIR": os.path.join(tmp, ".d"),
                                "CHECKPOINT_DISABLE": "1", "TF_VAR_project_id": "proj-aaaa1"})
        assert json.loads(json.loads(r.stdout.strip())) == {}, r.stderr  # owner 10-13: default {} (no warm instance)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
