"""HOST-AUDIT-LOG-SETTING (register row of the same name): optional Data Access audit logs on the host project.

1. Static: the default is empty, the variable drives only the audit resource (so the default changes nothing), the SRE
   sink filter is untouched, the setting is documented as a Terraform setting and no manual steps are documented.
2. Plan-level (tofu test, MOCK providers; skipped without OpenTofu + STACKVEND_TOFU_PROVIDER_MIRROR): the default plans
   nothing, both entries plan one configuration each, and anything else is refused at plan time.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import glob
import json
import os
import re
import shutil
import subprocess
import tempfile

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
PLATFORM = os.path.join(REPO, "infra", "platform")
CONFIG_DOC = os.path.join(REPO, "documentation", "configuration.md")
TFVARS_EXAMPLE = os.path.join(PLATFORM, "terraform.tfvars.example")
TFTEST = os.path.join(HERE, "fixtures", "host_audit_logs", "host_audit_logs.tftest.hcl")
VAR = "host_data_access_audit_logs"
TOFU = shutil.which("tofu")
MIRROR = os.environ.get("STACKVEND_TOFU_PROVIDER_MIRROR", "")
MIN_TOFU = (1, 10, 0)
SINK_FILTER = ('filter      = "severity >= ERROR OR (resource.type=\\"cloud_run_revision\\" '
               'AND jsonPayload.level=\\"ERROR\\")"')


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _strip_comments(text):
    return "\n".join(line.split("#", 1)[0].rstrip() for line in text.splitlines())


def _variable_block():
    text = _read(os.path.join(PLATFORM, "variables.tf"))
    start = text.index(f'variable "{VAR}" {{')
    return text[start:text.index("\n}\n", start) + 2]


def _doc_section():
    text = _read(CONFIG_DOC)
    start = text.index("### Data Access audit logs on the host project")
    return text[start:text.index("\n### ", start + 4)]


def test_the_default_is_empty():
    block = _variable_block()
    assert "type        = map(string)" in block
    assert "default     = {}" in block


def test_negative_the_default_changes_nothing_because_only_the_audit_resource_reads_the_variable():
    uses = []
    for path in glob.glob(os.path.join(PLATFORM, "*.tf")):
        if os.path.basename(path) == "variables.tf":
            continue
        for line in _strip_comments(_read(path)).splitlines():
            if f"var.{VAR}" in line:
                uses.append((os.path.basename(path), line.strip()))
    assert uses == [("main.tf", f"for_each   = var.{VAR}")]


def test_negative_the_sre_sink_filter_is_unchanged():
    assert SINK_FILTER in _read(os.path.join(PLATFORM, "main.tf"))


def test_the_resource_is_host_project_scoped_with_one_log_type():
    text = _strip_comments(_read(os.path.join(PLATFORM, "main.tf")))
    start = text.index('resource "google_project_iam_audit_config" "host_data_access" {')
    block = text[start:text.index("\n}\n", start) + 2]
    assert "project    = var.project_id" in block
    assert "service    = each.key" in block
    assert "log_type = each.value" in block
    assert "exempted_members" not in block


def test_only_the_two_documented_pairs_are_allowed():
    block = _variable_block()
    allowed = re.search(r"contains\(\[(.*?)\]", block).group(1)
    assert allowed == '"datastore.googleapis.com=DATA_WRITE", "secretmanager.googleapis.com=DATA_READ"'


def test_documented_as_a_terraform_setting_with_its_off_path_and_no_manual_steps():
    section = _doc_section()
    assert "`scripts/apply.sh apply`" in section
    assert "--allow-destroy=<project_id>" in section
    assert '"datastore.googleapis.com"     = "DATA_WRITE"' in section
    assert '"secretmanager.googleapis.com" = "DATA_READ"' in section
    assert "`ERROR`" in section
    assert "gcloud" not in section
    assert "Console" not in section
    assert f"`{VAR}`" in _read(CONFIG_DOC)


def test_the_example_vars_file_shows_it_commented_out():
    lines = [line for line in _read(TFVARS_EXAMPLE).splitlines() if VAR in line]
    assert lines and all(line.lstrip().startswith("#") for line in lines)


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
                                                                          "google"))),
                    reason="needs OpenTofu and STACKVEND_TOFU_PROVIDER_MIRROR (local provider mirror); nothing is downloaded")
def test_tofu_plan_contract_with_mock_providers():
    version = _tofu_version()
    if version is None or version < MIN_TOFU:
        pytest.skip(f"needs OpenTofu >= {'.'.join(map(str, MIN_TOFU))} (found {version})")
    tmp = tempfile.mkdtemp(prefix="hostaudit-")
    sock_dir = None
    try:
        shutil.copytree(os.path.join(REPO, "infra"), os.path.join(tmp, "infra"),
                        ignore=shutil.ignore_patterns(".terraform*", "*.tfvars", "*.tfstate*"))
        shutil.copytree(os.path.join(REPO, "workflows"), os.path.join(tmp, "workflows"))
        os.makedirs(os.path.join(tmp, "mcp-servers", "kubernetes"))
        shutil.copy(os.path.join(REPO, "mcp-servers", "kubernetes", "helm-pin.json"),
                    os.path.join(tmp, "mcp-servers", "kubernetes"))
        plat = os.path.join(tmp, "infra", "platform")
        os.makedirs(os.path.join(plat, "tests"))
        shutil.copy(TFTEST, os.path.join(plat, "tests"))
        rc_file = os.path.join(tmp, "cli.tfrc")
        with open(rc_file, "w", encoding="utf-8") as f:
            f.write('provider_installation {\n  filesystem_mirror {\n    path    = "%s"\n'
                    '    include = ["registry.opentofu.org/*/*"]\n  }\n}\n' % MIRROR)
        extra = {"TF_CLI_CONFIG_FILE": rc_file, "TF_DATA_DIR": os.path.join(tmp, "tfdata"), "TF_IN_AUTOMATION": "1"}
        if len(tempfile.gettempdir()) > 60:  # macOS caps provider unix-socket paths at 104 bytes
            sock_dir = tempfile.mkdtemp(prefix="hostaudit-", dir="/private/tmp" if os.path.isdir("/private/tmp") else "/tmp")
            extra["TMPDIR"] = sock_dir
        env = hermetic_guard.child_env(extra=extra)
        init = subprocess.run([TOFU, "init", "-backend=false", "-input=false", "-no-color"], cwd=plat, env=env,
                              capture_output=True, text=True, timeout=300)
        assert init.returncode == 0, init.stdout + init.stderr
        res = subprocess.run([TOFU, "test", "-no-color"], cwd=plat, env=env, capture_output=True, text=True,
                             timeout=600)
        assert res.returncode == 0, res.stdout + res.stderr
        assert "5 passed, 0 failed" in res.stdout, res.stdout
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        if sock_dir:
            shutil.rmtree(sock_dir, ignore_errors=True)
