"""SAT-01 (FD4BD-Q1 deploy half + FD4BD-Q2; owner OQ-1 / OQ-2 / OQ-3 10-31): mcp-servers/terraform/service.py.

FD4BD-Q1 (deploy half): OpenTofu loads terraform.tfvars, terraform.tfvars.json and every *.auto.tfvars /
*.auto.tfvars.json from the directory it runs in by itself; every one of them beats the TF_VAR_* secrets and the later
ones beat the platform values the deploy merges into terraform.tfvars. Before anything is built, planned or applied,
the deploy checks every such file in the workspace root (the platform's own access file excluded):
  - a symbolic link stops the deploy (APPLY.TFVARS_SYMLINK, operator_required);
  - a file whose variable names the platform cannot list stops it (APPLY.TFVARS_UNPARSEABLE / IAC_DEFECT, operator_required
    since Fable RT F1-1; the root terraform.tfvars path keeps IAC_DEFECT without the flag): python-hcl2
    (json for .json); when python-hcl2 cannot read it, OpenTofu's own parser says whether it is broken (OQ-3), and the
    names stay unknown either way;
  - a file that sets a platform-owned variable stops it (APPLY.TFVARS_OVERRIDES_PLATFORM, operator_required), naming
    the file and the variable.
Do No Harm: a file that passes, a file OpenTofu does not load by itself (prod.tfvars, terraform.tfvars.example), the
platform access file and a workspace without such files all reach OpenTofu byte-identical; the check writes nothing.

FD4BD-Q2: the exact-text rewriter `_rewrite_bundle_and_module_paths` is gone; infra/bundles/** and vendored
infra/modules/** reach the workspace byte-identical (with their ../../modules/ sources).

Hermetic: no repo fetch, no Secret Manager, no ADC, no network, no mutating tofu (the deploy stops at its first tofu
call). The one real-parser test runs `tofu fmt -` on stdin only when a binary is installed (skipped otherwise).
"""
import hermetic_guard  # noqa: F401  (first import)

import ast
import os
import sys
import types
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (terraform MCP requirement) not installed")

from fd4g_support import load_tf_service  # noqa: E402

W = "infra/workload/"
PROJECT = "p-1"
SERVICE_PY = os.path.join(REPO_ROOT, "mcp-servers", "terraform", "service.py")

MAIN = (
    'module "compute" {\n'
    '  source          = "../modules/compute-cloudrun"\n'
    '  project_id      = var.project_id\n'
    '  region          = var.region\n'
    '  service_name    = "shop"\n'
    '  container_image = var.container_image\n'
    '}\n'
)
VARIABLES = (
    'variable "project_id" {\n  type = string\n}\n\n'
    'variable "region" {\n  type    = string\n  default = "us-central1"\n}\n\n'
    'variable "container_image" {\n  type    = string\n  default = ""\n}\n\n'
    'variable "min_instances" {\n  type    = number\n  default = 0\n}\n'
)
APPS = {"apps/shop/main.py": "app = None\n", "apps/shop/requirements.txt": "fastapi\n"}
SECRET_VALUE = "s3cr3t-value-never-in-errors"
BROKEN_HCL = f'min_instances = "{SECRET_VALUE}\n'          # unterminated string
OPERATOR_LEADING = "min_instances = (\n  1\n  + 2\n)\n"     # valid HCL python-hcl2 7.3.1 rejects


def _tree(**extra):
    return {W + "main.tf": MAIN, W + "variables.tf": VARIABLES, **APPS, **extra}


@pytest.fixture
def tf(monkeypatch):
    return load_tf_service(monkeypatch)


class _StopAtTofu(BaseException):
    """Raised by the first tofu call: everything the deploy writes before plan/apply has been written."""


def _no_gcp(monkeypatch):
    import google.auth
    import google.cloud

    class _SM:
        def __init__(self, *a, **k):
            pass

        def access_secret_version(self, name):
            raise RuntimeError("no secrets in tests")

    def _no_adc(*_a, **_k):
        raise RuntimeError("no ADC in tests")

    fake_sm = types.ModuleType("google.cloud.secretmanager")
    fake_sm.SecretManagerServiceClient = _SM
    monkeypatch.setitem(sys.modules, "google.cloud.secretmanager", fake_sm)
    monkeypatch.setattr(sys.modules["google.cloud"], "secretmanager", fake_sm, raising=False)
    monkeypatch.setattr(sys.modules["google.auth"], "default", _no_adc, raising=False)


def _service(tf, monkeypatch, tmp_path, files, verdict=None):
    """The real TerraformService with every outside call faked. `verdict`: what OpenTofu's parser says ([] accepts,
    [msg] rejects, None no parser); the default is "no parser", so nothing depends on the machine's binaries."""
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="",
                              workspace_base_dir=str(tmp_path / "base"), firestore_client=MagicMock())
    svc.db = None
    svc.state_bucket = ""
    monkeypatch.setenv("GITHUB_ORG", "acme-test")
    monkeypatch.setattr(svc, "_fetch_repo_files", lambda *a, **k: dict(files))
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    monkeypatch.setattr(svc, "_ensure_binary", lambda *a, **k: "tofu")
    monkeypatch.setattr(tf, "_opentofu_tfvars_verdict", lambda *a, **k: verdict)
    _no_gcp(monkeypatch)
    vcs = MagicMock(name="vcs")
    factory = MagicMock(name="VCSProviderFactory")
    factory.get_provider.return_value = vcs
    monkeypatch.setattr(tf, "VCSProviderFactory", factory)
    return svc


def _deploy(tf, monkeypatch, tmp_path, files, trace_id="t-sat01", svc=None, verdict=None):
    """The REAL deploy_workload up to the first tofu call (or its typed early return).
    Returns (result or None when it reached tofu, seen dict)."""
    svc = svc or _service(tf, monkeypatch, tmp_path, files, verdict=verdict)
    seen = {"built": False, "registered": False}
    real_register = svc._register_workspace_tf_vars

    def _build(*_a, **_k):
        seen["built"] = True
        return True

    def _register(*a, **k):
        seen["registered"] = True
        return real_register(*a, **k)

    def _tofu(*_a, **kw):
        seen["ws"] = kw.get("cwd")
        raise _StopAtTofu()

    monkeypatch.setattr(svc, "_build_and_push_container", _build)
    monkeypatch.setattr(svc, "_register_workspace_tf_vars", _register)
    monkeypatch.setattr(svc, "_run_subprocess", _tofu)
    try:
        res = svc.deploy_workload(product_id="shop", trace_id=trace_id, target_project_id=PROJECT,
                                  branch="main", iac_engine="OPENTOFU")
    except _StopAtTofu:
        res = None
    return res, seen


def _read(ws, rel):
    with open(os.path.join(ws, rel), encoding="utf-8", newline="") as fh:   # exact bytes: no CRLF translation
        return fh.read()


def _snapshot(root):
    out = {}
    for dirpath, _dirs, names in os.walk(root):
        for name in names:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            if os.path.islink(full):
                out[rel] = ("link", os.readlink(full))
            else:
                with open(full, "rb") as fh:
                    out[rel] = fh.read()
    return out


def _assert_stopped_before_anything(res, seen):
    assert res and res["status"] == "FAILED", res
    assert not seen["built"] and "ws" not in seen and not seen["registered"], seen


# ------------------------------------------------------------------------------------------------ name rule
@pytest.mark.parametrize("name,loaded", [
    ("terraform.tfvars.json", True), ("x.auto.tfvars", True), ("x.auto.tfvars.json", True), (".auto.tfvars", True),
    ("terraform.tfvars", False),           # written by the deploy from the merged platform values
    ("prod.tfvars", False), ("prod.tfvars.json", False), ("terraform.tfvars.example", False),
    ("x.auto.tfvars.bak", False), ("x.auto.tfvar", False), ("X.AUTO.TFVARS", False), ("auto.tfvars", False),
])
def test_auto_loaded_name_rule_is_opentofus_exact_rule(tf, name, loaded):
    assert tf.is_auto_loaded_tfvars_name(name) is loaded


# ------------------------------------------------------------------------------------------------ unparseable
@pytest.mark.parametrize("name,text", [
    ("x.auto.tfvars", BROKEN_HCL),
    ("x.auto.tfvars.json", '{"min_instances": "' + SECRET_VALUE + '",}'),
    ("terraform.tfvars.json", '{"min_instances": "' + SECRET_VALUE + '"'),
    ("y.auto.tfvars.json", '["' + SECRET_VALUE + '"]'),     # valid JSON, not an object
])
@pytest.mark.parametrize("where", ["", W], ids=["repo-root", "infra-workload"])
def test_unparseable_auto_file_is_a_typed_stop_naming_the_file(tf, monkeypatch, tmp_path, name, text, where):
    res, seen = _deploy(tf, monkeypatch, tmp_path, _tree(**{where + name: text}), verdict=["rejected"])
    _assert_stopped_before_anything(res, seen)
    assert res["error_class"] == "IAC_DEFECT" and res["code"] == "APPLY.TFVARS_UNPARSEABLE"
    assert res["error"].startswith(f"APPLY.TFVARS_UNPARSEABLE: {where}{name} ")
    assert res["files"] == [where + name]
    assert SECRET_VALUE not in res["error"]          # positions only, never the file text
    # Fable RT F1-1: a person-committed auto file stops for an operator (developer regeneration cannot change it)
    assert res["operator_required"] is True
    assert "a person-committed variables file: fix or remove it in the repository" in res["error"]


@pytest.mark.parametrize("where", ["", W], ids=["repo-root", "infra-workload"])
def test_unparseable_root_terraform_tfvars_still_goes_to_developer_remediation(tf, monkeypatch, tmp_path, where):
    """Negative (F1-1 scope): the root terraform.tfvars path (FD55-TFVARS) is unchanged: IAC_DEFECT, no operator flag."""
    res, seen = _deploy(tf, monkeypatch, tmp_path, _tree(**{where + "terraform.tfvars": BROKEN_HCL}))
    _assert_stopped_before_anything(res, seen)
    assert res["error_class"] == "IAC_DEFECT" and res["code"] == "APPLY.TFVARS_UNPARSEABLE"
    assert "operator_required" not in res and "person-committed" not in res["error"]


def test_unparseable_hcl_says_opentofu_rejects_it(tf, monkeypatch, tmp_path):
    res, _seen = _deploy(tf, monkeypatch, tmp_path, _tree(**{"x.auto.tfvars": BROKEN_HCL}), verdict=["no"])
    assert "x.auto.tfvars is rejected by OpenTofu's parser (python-hcl2: UnexpectedToken at line 1" in res["error"]


def test_hcl_python_hcl2_cannot_read_and_no_parser_is_a_stop_not_called_broken(tf, monkeypatch, tmp_path):
    res, seen = _deploy(tf, monkeypatch, tmp_path, _tree(**{"x.auto.tfvars": OPERATOR_LEADING}), verdict=None)
    _assert_stopped_before_anything(res, seen)
    assert res["code"] == "APPLY.TFVARS_UNPARSEABLE"
    assert "no OpenTofu parser was available to decide (the file is not proven broken)" in res["error"]


def test_hcl_opentofu_accepts_but_names_unknown_still_stops(tf, monkeypatch, tmp_path):
    """OQ-3 + OQ-1: OpenTofu's parser decides that the file is not broken, but the platform still cannot list the
    variables it sets, so it cannot run the OQ-1 check: a typed stop that says the file is not proven broken."""
    res, seen = _deploy(tf, monkeypatch, tmp_path, _tree(**{"x.auto.tfvars": OPERATOR_LEADING}), verdict=[])
    _assert_stopped_before_anything(res, seen)
    assert res["code"] == "APPLY.TFVARS_UNPARSEABLE" and res["operator_required"] is True
    assert "although OpenTofu's parser accepts it" in res["error"] and "not proven broken" in res["error"]


def test_opentofu_parser_is_asked_only_when_python_hcl2_cannot_read(tf, monkeypatch, tmp_path):
    asked = []
    monkeypatch.setattr(tf, "_opentofu_tfvars_verdict", lambda text, name, b: asked.append((name, b)) or [])
    (tmp_path / "a.auto.tfvars").write_text('min_instances = 1\n')
    (tmp_path / "b.auto.tfvars").write_text(OPERATOR_LEADING)
    (tmp_path / "c.auto.tfvars").write_text(OPERATOR_LEADING)
    calls = []
    findings = tf.workspace_auto_tfvars_findings(str(tmp_path), tf.PLATFORM_OWNED_TFVARS,
                                                 parser_bin=lambda: calls.append(1) or "/bin/tofu-x")
    assert [f[1] for f in findings] == ["b.auto.tfvars", "c.auto.tfvars"]
    assert asked == [("b.auto.tfvars", "/bin/tofu-x"), ("c.auto.tfvars", "/bin/tofu-x")] and calls == [1]


def test_parser_binary_failure_is_no_parser_not_a_crash(tf, tmp_path):
    (tmp_path / "b.auto.tfvars").write_text(OPERATOR_LEADING)

    def _boom():
        raise RuntimeError("download failed")

    findings = tf.workspace_auto_tfvars_findings(str(tmp_path), tf.PLATFORM_OWNED_TFVARS, parser_bin=_boom)
    assert findings[0][0] == "APPLY.TFVARS_UNPARSEABLE" and "no OpenTofu parser" in findings[0][2]


def test_real_opentofu_parser_decides_when_installed(tf):
    """OQ-3 with the real binary (fmt on stdin: syntax only, no files, no network). Skipped without a binary."""
    from shared.hcl_utils import find_hcl_parser_binary
    binary = find_hcl_parser_binary()
    if not binary:
        pytest.skip("no OpenTofu/Terraform binary installed")
    names, reason = tf.tfvars_file_variable_names(OPERATOR_LEADING, "x.auto.tfvars", binary)
    assert names is None and "although OpenTofu's parser accepts it" in reason
    names, reason = tf.tfvars_file_variable_names(BROKEN_HCL, "x.auto.tfvars", binary)
    assert names is None and reason.startswith("is rejected by OpenTofu's parser") and SECRET_VALUE not in reason


# ------------------------------------------------------------------------------------------------ symlinks (OQ-2)
def _prepare_then(svc, monkeypatch, after):
    real = svc.prepare_workspace

    def _prep(*a, **k):
        ws = real(*a, **k)
        after(ws)
        return ws

    monkeypatch.setattr(svc, "prepare_workspace", _prep)


def test_symlinked_auto_file_stops_for_an_operator(tf, monkeypatch, tmp_path):
    outside = tmp_path / "outside.tfvars"
    outside.write_text('min_instances = 1\n')     # a valid file: the link itself is refused, never followed
    files = _tree(**{"x.auto.tfvars": 'min_instances = 1\n'})
    svc = _service(tf, monkeypatch, tmp_path, files)

    def _link(ws):
        os.remove(os.path.join(ws, "x.auto.tfvars"))
        os.symlink(str(outside), os.path.join(ws, "x.auto.tfvars"))
        os.symlink(str(outside), os.path.join(ws, "stray.auto.tfvars"))

    _prepare_then(svc, monkeypatch, _link)
    res, seen = _deploy(tf, monkeypatch, tmp_path, files, svc=svc)
    _assert_stopped_before_anything(res, seen)
    assert res["error_class"] == "TFVARS_SYMLINK" and res["code"] == "APPLY.TFVARS_SYMLINK"
    assert res["operator_required"] is True
    assert res["files"] == ["stray.auto.tfvars (in the deploy workspace, not from the repository)", "x.auto.tfvars"]
    assert res["error"].startswith("APPLY.TFVARS_SYMLINK: stray.auto.tfvars (in the deploy workspace, not from the "
                                   "repository) is a symbolic link; x.auto.tfvars is a symbolic link. ")
    assert outside.read_text() == 'min_instances = 1\n'


def test_symlinked_terraform_tfvars_json_is_refused_even_to_a_platform_free_file(tf, tmp_path):
    target = tmp_path / "t.json"
    target.write_text('{"min_instances": 1}')
    ws = tmp_path / "ws"
    ws.mkdir()
    os.symlink(str(target), str(ws / "terraform.tfvars.json"))
    before = _snapshot(str(ws))
    findings = tf.workspace_auto_tfvars_findings(str(ws), tf.PLATFORM_OWNED_TFVARS)
    assert findings == [("APPLY.TFVARS_SYMLINK", "terraform.tfvars.json", "is a symbolic link", [])]
    assert _snapshot(str(ws)) == before


def test_directory_with_an_auto_name_is_refused(tf, tmp_path):
    (tmp_path / "d.auto.tfvars").mkdir()
    findings = tf.workspace_auto_tfvars_findings(str(tmp_path), tf.PLATFORM_OWNED_TFVARS)
    assert findings == [("APPLY.TFVARS_UNPARSEABLE", "d.auto.tfvars", "is not a regular file", [])]


# ------------------------------------------------------------------------------------------------ OQ-1
@pytest.mark.parametrize("var", sorted([
    "oauth_client_secret", "firebase_api_key", "project_id", "region", "product_id", "github_repo_full_name",
    "container_image", "oauth_client_id", "firebase_auth_domain", "github_repository_id", "github_default_branch"]))
@pytest.mark.parametrize("name,fmt", [("ops.auto.tfvars", 'min_instances = 1\n{v} = "{x}"\n'),
                                      ("terraform.tfvars.json", '{{"min_instances": 1, "{v}": "{x}"}}'),
                                      ("z.auto.tfvars.json", '{{"{v}": "{x}"}}')])
@pytest.mark.parametrize("where", ["", W], ids=["repo-root", "infra-workload"])
def test_platform_owned_variable_in_an_auto_file_stops_for_an_operator(tf, monkeypatch, tmp_path, var, name, fmt,
                                                                       where):
    text = fmt.format(v=var, x=SECRET_VALUE)
    res, seen = _deploy(tf, monkeypatch, tmp_path, _tree(**{where + name: text}))
    _assert_stopped_before_anything(res, seen)
    assert res["error_class"] == "TFVARS_OVERRIDES_PLATFORM" and res["code"] == "APPLY.TFVARS_OVERRIDES_PLATFORM"
    assert res["operator_required"] is True
    assert res["files"] == [where + name] and res["variables"] == {where + name: [var]}
    assert res["error"].startswith(f"APPLY.TFVARS_OVERRIDES_PLATFORM: {where}{name} sets the platform-owned "
                                   f"variable {var}. ")
    assert SECRET_VALUE not in res["error"]


def test_every_platform_key_named_and_duplicate_json_keys_counted(tf, tmp_path):
    (tmp_path / "a.auto.tfvars.json").write_text('{"min_instances": 1, "region": "x", "region": "y"}')
    (tmp_path / "b.auto.tfvars").write_text('project_id = "p"\nregion = "r"\nmin_instances = 2\n')
    findings = tf.workspace_auto_tfvars_findings(str(tmp_path), tf.PLATFORM_OWNED_TFVARS)
    assert [(f[0], f[1], f[3]) for f in findings] == [
        ("APPLY.TFVARS_OVERRIDES_PLATFORM", "a.auto.tfvars.json", ["region"]),
        ("APPLY.TFVARS_OVERRIDES_PLATFORM", "b.auto.tfvars", ["project_id", "region"])]
    assert findings[1][2] == "sets the platform-owned variables project_id, region"


def test_symlink_outranks_override_outranks_unparseable_and_all_are_named(tf, monkeypatch, tmp_path):
    files = _tree(**{"a.auto.tfvars": BROKEN_HCL, "b.auto.tfvars": 'region = "x"\n'})
    res, seen = _deploy(tf, monkeypatch, tmp_path, files, verdict=["rejected"])
    _assert_stopped_before_anything(res, seen)
    assert res["code"] == "APPLY.TFVARS_OVERRIDES_PLATFORM" and res["operator_required"] is True
    assert res["files"] == ["a.auto.tfvars", "b.auto.tfvars"] and res["variables"] == {"b.auto.tfvars": ["region"]}


def test_platform_owned_list_covers_every_platform_tfvars_key(tf):
    """The static list equals the TF_VAR_* secrets plus every key `_deploy_workload_impl` writes into
    `platform_tfvars` (dict literal keys and `platform_tfvars["k"] = ...` assignments, read with ast)."""
    tree = ast.parse(open(SERVICE_PY, encoding="utf-8").read())
    keys = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "platform_tfvars" and isinstance(node.value, ast.Dict):
                    keys |= {k.value for k in node.value.keys if isinstance(k, ast.Constant)}
                if (isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name)
                        and target.value.id == "platform_tfvars" and isinstance(target.slice, ast.Constant)):
                    keys.add(target.slice.value)
    assert keys and "github_repository_id" in keys and "github_default_branch" in keys
    assert tf.PLATFORM_OWNED_TFVARS == keys | set(tf.PLATFORM_SECRET_TFVARS)


def test_call_site_adds_the_live_platform_keys(tf, monkeypatch, tmp_path):
    seen_owned = {}
    real = tf.workspace_auto_tfvars_findings

    def _spy(ws, owned, **kw):
        seen_owned["owned"] = owned
        return real(ws, owned, **kw)

    monkeypatch.setattr(tf, "workspace_auto_tfvars_findings", _spy)
    res, _seen = _deploy(tf, monkeypatch, tmp_path, _tree())
    assert res is None
    assert tf.PLATFORM_OWNED_TFVARS <= seen_owned["owned"]


# ------------------------------------------------------------------------------------------------ Do No Harm
@pytest.mark.parametrize("name,text", [
    ("ops.auto.tfvars", 'min_instances = 2\nlabels = {\n  team = "claims"\n}\n'),
    ("ops.auto.tfvars", 'min_instances = 2\r\nlabels = {\r\n  team = "claims"\r\n}\r\n'),     # CRLF
    ("ops.auto.tfvars", '\ufeffmin_instances = 2\n# trailing comment'),                         # BOM, no final \n
    ("ops.auto.tfvars", ""),                                                                    # empty
    ("ops.auto.tfvars.json", '{"min_instances": 2}\r\n'),
    ("terraform.tfvars.json", '\ufeff{"min_instances": 2, "labels": {"region": "inner keys are not variables"}}'),
])
@pytest.mark.parametrize("where", ["", W], ids=["repo-root", "infra-workload"])
def test_parseable_auto_file_without_platform_names_reaches_tofu_byte_identical(tf, monkeypatch, tmp_path, name,
                                                                               text, where):
    res, seen = _deploy(tf, monkeypatch, tmp_path, _tree(**{where + name: text}))
    assert res is None, res
    assert seen["built"] and seen["registered"]
    assert _read(seen["ws"], name) == text


def test_crlf_and_lf_files_list_the_same_names(tf):
    lf = 'min_instances = 2\nregion = "x"\nlabels = {\n  a = "b"\n}\n'
    assert tf.tfvars_file_variable_names(lf, "a.auto.tfvars") == (["min_instances", "region", "labels"], "")
    assert tf.tfvars_file_variable_names(lf.replace("\n", "\r\n"), "a.auto.tfvars") == (
        ["min_instances", "region", "labels"], "")


@pytest.mark.parametrize("name", ["prod.tfvars", "terraform.tfvars.example", "env/x.auto.tfvars", "x.auto.tfvars.bak"])
def test_files_opentofu_does_not_load_by_itself_are_ignored(tf, monkeypatch, tmp_path, name):
    text = BROKEN_HCL + 'region = "x"\n'
    res, seen = _deploy(tf, monkeypatch, tmp_path, _tree(**{name: text, W + name: text}), verdict=["rejected"])
    assert res is None, res
    assert _read(seen["ws"], name) == text and _read(seen["ws"], W + name) == text


def test_platform_access_file_is_never_judged(tf, monkeypatch, tmp_path):
    """The platform's own file (the deploy_workload manifest key) is never judged, even when its keys would be
    refused in any other auto file; a person's same-named repository file is replaced by it, exactly as before."""
    files = _tree(**{"stackvend-access.auto.tfvars.json": '{"region": "person"}',
                     W + "stackvend-access.auto.tfvars.json": '{"region": "person"}'})
    svc = _service(tf, monkeypatch, tmp_path, files)
    platform_text = '{"region": "platform-rendered-test-value"}'
    monkeypatch.setattr(svc, "_deploy_access_vars", lambda *_a, **_k: (platform_text, {"rendered": False}))
    res, seen = _deploy(tf, monkeypatch, tmp_path, files, svc=svc)
    assert res is None, res
    assert _read(seen["ws"], "stackvend-access.auto.tfvars.json") == platform_text


def test_access_file_name_is_judged_when_the_platform_did_not_write_it(tf, tmp_path):
    (tmp_path / "stackvend-access.auto.tfvars.json").write_text('{"region": "x"}')
    assert tf.workspace_auto_tfvars_findings(str(tmp_path), tf.PLATFORM_OWNED_TFVARS)[0][3] == ["region"]
    assert tf.workspace_auto_tfvars_findings(str(tmp_path), tf.PLATFORM_OWNED_TFVARS,
                                             skip=("stackvend-access.auto.tfvars.json",)) == []


def test_workspace_without_auto_files_is_byte_identical(tf, monkeypatch, tmp_path):
    """The check changes nothing: the same deploy with the check replaced by a no-op writes the same workspace."""
    res, seen = _deploy(tf, monkeypatch, tmp_path / "a", _tree(**{W + "terraform.tfvars": 'min_instances = 1\n'}))
    assert res is None, res
    with_check = _snapshot(seen["ws"])
    monkeypatch.setattr(tf, "workspace_auto_tfvars_findings", lambda *a, **k: [])
    res, seen = _deploy(tf, monkeypatch, tmp_path / "b", _tree(**{W + "terraform.tfvars": 'min_instances = 1\n'}))
    assert res is None, res
    assert _snapshot(seen["ws"]) == with_check


def test_the_check_is_read_only_on_a_workspace_it_refuses(tf, tmp_path):
    (tmp_path / "a.auto.tfvars").write_text(BROKEN_HCL)
    (tmp_path / "b.auto.tfvars").write_text('region = "x"\r\n')
    (tmp_path / "c.auto.tfvars.json").write_text('{"min_instances": 1}')
    before = _snapshot(str(tmp_path))
    assert len(tf.workspace_auto_tfvars_findings(str(tmp_path), tf.PLATFORM_OWNED_TFVARS)) == 2
    assert _snapshot(str(tmp_path)) == before


# ------------------------------------------------------------------------------------------------ FD4BD-Q2
BUNDLE_MAIN = (
    'module "vpc" {\n'
    '  source     = "../../modules/networking-vpc"\n'
    '  project_id = var.project_id\n'
    '}\n'
    'module "db"   {   source = "../modules/cloudsql"   }\n'
)
VENDORED_MODULE = {
    "infra/modules/networking-vpc/main.tf": 'module "inner" {\n  source = "../../modules/cloudsql"\n}\n',
    "infra/modules/networking-vpc/variables.tf": 'variable "project_id" {\r\n  type = string\r\n}\r\n',
}


def test_dead_exact_text_rewriter_is_gone(tf):
    assert not hasattr(tf.TerraformService, "_rewrite_bundle_and_module_paths")
    assert "_rewrite_bundle_and_module_paths(" not in open(SERVICE_PY, encoding="utf-8").read()


def test_bundles_and_vendored_modules_reach_the_workspace_byte_identical(tf, monkeypatch, tmp_path):
    files = _tree(**{"infra/bundles/web/main.tf": BUNDLE_MAIN, **VENDORED_MODULE})
    res, seen = _deploy(tf, monkeypatch, tmp_path, files)
    assert res is None, res
    assert _read(seen["ws"], "infra/bundles/web/main.tf") == BUNDLE_MAIN
    for path, text in VENDORED_MODULE.items():
        assert _read(seen["ws"], path) == text
    # the flattened root keeps its parse-tree re-anchoring (FD-4BW), unchanged by this branch
    assert 'source          = "./infra/modules/compute-cloudrun"' in _read(seen["ws"], "main.tf")
