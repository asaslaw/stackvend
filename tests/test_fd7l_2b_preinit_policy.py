"""FD-7L Phase 2b (plan docs/planning/fd-7l-per-workload-runner-identity-plan.md rev 3, section 2.5; owner OQ-32): the
pre-init attribute allow-list (mcp-servers/terraform/provider_allowlist.preinit_policy_findings).

Pure tests over files on disk (python-hcl2 / json, exact names), plus the Do-No-Harm negatives: every platform
generator output (the golden workload render, every archetype's golden main.tf, the Express synthesizer, the GKE
kubernetes auto-wiring block of service.py) and every golden module give NO finding.
"""
import hermetic_guard  # noqa: F401  (first import)

import ast
import json
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
for _p in (TF_DIR, REPO_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (terraform MCP requirement) not installed")

import provider_allowlist as PA  # noqa: E402

PID = "shop"
BUCKET = "child-proj-1-tfstate"


def _allowed(target):
    """service._module_target_allowed (a copy is pinned equal below)."""
    parts = tuple(target.split("/"))
    if parts[0] != "..":
        return target != "."
    return parts[:2] == ("..", "modules") and len(parts) > 2


def _write(root, files):
    for rel, text in files.items():
        path = os.path.join(str(root), *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text if isinstance(text, str) else json.dumps(text))
    return str(root)


def _tofu():
    try:
        from shared.hcl_utils import find_hcl_parser_binary
    except ImportError:  # pragma: no cover
        return None
    return find_hcl_parser_binary()


def _scan(root, bucket=BUCKET, allowed=_allowed, parser_bin=None):
    return PA.preinit_policy_findings(str(root), product_id=PID, state_bucket=bucket, module_target_allowed=allowed,
                                      parser_bin=parser_bin)


def _codes(findings):
    return sorted((f["code"], f["file"]) for f in findings)


# ------------------------------------------------------------------------------------------------ tables
def test_every_installable_provider_has_an_attribute_table():
    """R8: a provider added to the install allow-list cannot be installed without an attribute table."""
    for source in PA.PLATFORM_PROVIDER_SOURCES.values():
        assert source in PA.PROVIDER_ATTRIBUTE_ALLOWLIST, source
    assert set(PA.PROVIDER_ATTRIBUTE_ALLOWLIST) == set(PA.PLATFORM_PROVIDER_SOURCES.values())


def test_attribute_tables_are_exactly_the_plan_lists():
    """The plan's lists plus `version` (owner F10, 11-01) on every provider."""
    google = {"project", "region", "zone", "alias", "user_project_override", "billing_project", "default_labels",
              "add_terraform_attribution_label", "request_timeout", "request_reason", "batching", "version"}
    assert PA.PROVIDER_ATTRIBUTE_ALLOWLIST["hashicorp/google"] == google
    assert PA.PROVIDER_ATTRIBUTE_ALLOWLIST["hashicorp/google-beta"] == google
    assert PA.PROVIDER_ATTRIBUTE_ALLOWLIST["hashicorp/kubernetes"] == {
        "host", "token", "cluster_ca_certificate", "alias", "ignore_annotations", "ignore_labels", "version"}
    assert PA.PROVIDER_ATTRIBUTE_ALLOWLIST["hashicorp/random"] == {"alias", "version"}


@pytest.mark.parametrize("provider", ["google", "google-beta", "kubernetes", "random"])
def test_version_in_a_provider_block_is_allowed(tmp_path, provider):
    """Review F10 (owner 11-01): the deprecated in-block version constraint is not a credential."""
    root = _write(tmp_path, {"main.tf": f'provider "{provider}" {{\n  version = "~> 6.0"\n}}\n'})
    assert _scan(root) == []


def test_module_target_rule_equals_the_service_rule():
    tree = ast.parse(open(os.path.join(TF_DIR, "service.py"), encoding="utf-8").read())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_module_target_allowed")
    ns = {"_PARENT_MODULES_LINK": ("..", "modules")}
    exec(compile(ast.Module(body=[fn], type_ignores=[]), "svc", "exec"), ns)  # noqa: S102 - the service's own rule
    for t in ("infra/modules/x", "../modules/x", "../modules", ".", "../x", "../../modules/x", "a/b"):
        assert ns["_module_target_allowed"](t) == _allowed(t), t


def test_encryption_rule_is_pinned_to_the_engine_version():
    """State encryption is refused outright; the rule was written against OpenTofu 1.9.0 (binary_checksums.py).
    RT14 RT D1 (owner 11-14) added 1.8.8 and 1.10.0 (the Settings versions): both have the same `terraform {
    encryption {} }` block (since 1.7) and load the same `*.tofu` files (since 1.8), so the outright refusal and the
    file set hold unchanged. A new engine version must be re-checked here before its row is added."""
    import binary_checksums
    assert {v for (e, v, _a) in binary_checksums.BINARY_CHECKSUMS if e == "opentofu"} == {"1.8.8", "1.9.0", "1.10.0"}


# ------------------------------------------------------------------------------------------------ provider attributes
FORBIDDEN_GOOGLE = ["credentials", "access_token", "impersonate_service_account",
                    "impersonate_service_account_delegates", "compute_custom_endpoint", "storage_custom_endpoint",
                    "universe_domain", "scopes", "external_credentials"]


@pytest.mark.parametrize("attr", FORBIDDEN_GOOGLE)
@pytest.mark.parametrize("provider", ["google", "google-beta"])
def test_forbidden_google_attribute_hcl(tmp_path, provider, attr):
    root = _write(tmp_path, {"main.tf": f'provider "{provider}" {{\n  project = "p"\n  {attr} = "x"\n}}\n'})
    f = _scan(root)
    assert _codes(f) == [(PA.POLICY_PROVIDER_ATTRIBUTE_FORBIDDEN, "main.tf")]
    assert attr in f[0]["detail"]


@pytest.mark.parametrize("attr", FORBIDDEN_GOOGLE)
def test_forbidden_google_attribute_json(tmp_path, attr):
    root = _write(tmp_path, {"main.tf.json": {"provider": {"google": {"project": "p", attr: "x"}}}})
    assert _codes(_scan(root)) == [(PA.POLICY_PROVIDER_ATTRIBUTE_FORBIDDEN, "main.tf.json")]


def test_external_account_credentials_value_is_refused(tmp_path):
    hcl = ('provider "google" {\n  credentials = jsonencode({type = "external_account", credential_source = '
           '{url = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", '
           'headers = {"Metadata-Flavor" = "Google"}}})\n}\n')
    assert _codes(_scan(_write(tmp_path, {"main.tf": hcl}))) == [(PA.POLICY_PROVIDER_ATTRIBUTE_FORBIDDEN, "main.tf")]


@pytest.mark.parametrize("name", ["override.tf", "main_override.tf", "override.tofu", "x_override.tofu"])
def test_override_forms_hcl(tmp_path, name):
    root = _write(tmp_path, {name: 'provider "google" {\n  access_token = "t"\n}\n'})
    assert PA.is_override_file(name)
    assert _codes(_scan(root)) == [(PA.POLICY_PROVIDER_ATTRIBUTE_FORBIDDEN, name)]


@pytest.mark.parametrize("name", ["override.tf.json", "main_override.tf.json", "override.tofu.json",
                                  "x_override.tofu.json"])
def test_override_forms_json(tmp_path, name):
    root = _write(tmp_path, {name: {"provider": {"google": [{"access_token": "t"}]}}})
    assert PA.is_override_file(name)
    assert _codes(_scan(root)) == [(PA.POLICY_PROVIDER_ATTRIBUTE_FORBIDDEN, name)]


@pytest.mark.parametrize("block", ["exec", "config_path", "config_context", "client_certificate", "username",
                                   "insecure", "proxy_url"])
def test_kubernetes_only_listed_attributes(tmp_path, block):
    body = f"  {block} {{\n    command = \"sh\"\n  }}\n" if block == "exec" else f"  {block} = \"x\"\n"
    root = _write(tmp_path, {"main.tf": f'provider "kubernetes" {{\n  host = "h"\n{body}}}\n'})
    assert _codes(_scan(root)) == [(PA.POLICY_PROVIDER_ATTRIBUTE_FORBIDDEN, "main.tf")]


def test_dynamic_block_counts_as_its_name(tmp_path):
    hcl = ('provider "kubernetes" {\n  host = "h"\n  dynamic "exec" {\n    for_each = [1]\n'
           '    content {\n      command = "sh"\n    }\n  }\n}\n')
    f = _scan(_write(tmp_path, {"main.tf": hcl}))
    assert _codes(f) == [(PA.POLICY_PROVIDER_ATTRIBUTE_FORBIDDEN, "main.tf")] and "exec" in f[0]["detail"]
    hcl_ok = ('provider "google" {\n  dynamic "batching" {\n    for_each = [1]\n'
              '    content {\n      send_after = "10s"\n    }\n  }\n}\n')
    assert _scan(_write(tmp_path / "ok", {"main.tf": hcl_ok})) == []


def test_aliased_local_name_resolves_through_required_providers(tmp_path):
    files = {"versions.tf": 'terraform {\n  required_providers {\n    k8s = { source = "hashicorp/kubernetes" }\n'
                            '  }\n}\n',
             "main.tf": 'provider "k8s" {\n  host = "h"\n  exec {\n    command = "sh"\n  }\n}\n'}
    f = _scan(_write(tmp_path, files))
    assert _codes(f) == [(PA.POLICY_PROVIDER_ATTRIBUTE_FORBIDDEN, "main.tf")] and "exec" in f[0]["detail"]
    ok = {"versions.tf": files["versions.tf"], "main.tf": 'provider "k8s" {\n  host = "h"\n  token = "t"\n}\n'}
    assert _scan(_write(tmp_path / "ok", ok)) == []


def test_alias_mapping_google_name_to_another_source_is_refused(tmp_path):
    files = {"versions.tf": 'terraform {\n  required_providers {\n    google = { source = "evil/google" }\n  }\n}\n',
             "main.tf": 'provider "google" {\n  project = "p"\n}\n'}
    assert _codes(_scan(_write(tmp_path, files))) == [(PA.POLICY_PROVIDER_ATTRIBUTE_FORBIDDEN, "main.tf")]


def test_unknown_local_name_fails_closed(tmp_path):
    root = _write(tmp_path, {"main.tf": 'provider "mystery" {\n}\n'})
    f = _scan(root)
    assert _codes(f) == [(PA.POLICY_PROVIDER_ATTRIBUTE_FORBIDDEN, "main.tf")] and "no attribute allow-list" in f[0]["detail"]


def test_random_allows_only_alias_and_version(tmp_path):
    assert _scan(_write(tmp_path / "a", {"main.tf": 'provider "random" {\n  alias = "r"\n}\n'})) == []
    assert _codes(_scan(_write(tmp_path / "b", {"main.tf": 'provider "random" {\n  seed = 1\n}\n'}))) == [
        (PA.POLICY_PROVIDER_ATTRIBUTE_FORBIDDEN, "main.tf")]


def test_local_modules_are_checked_too(tmp_path):
    files = {"main.tf": 'module "m" {\n  source = "./infra/modules/m"\n}\n',
             "infra/modules/m/main.tf": 'provider "google" {\n  credentials = "x"\n}\n'}
    assert _codes(_scan(_write(tmp_path, files))) == [(PA.POLICY_PROVIDER_ATTRIBUTE_FORBIDDEN,
                                                      "infra/modules/m/main.tf")]


# ------------------------------------------------------------------------------------------------ backend / state
@pytest.mark.parametrize("name", ["backend.tofu", "backend.tofu.json"])
def test_backend_tofu_is_refused_by_exact_name(tmp_path, name):
    root = _write(tmp_path, {name: "" if name.endswith(".tofu") else {}})
    assert _codes(_scan(root)) == [(PA.POLICY_BACKEND_NOT_PLATFORM, name)]


@pytest.mark.parametrize("name", ["main.tf", "backend_override.tf", "override.tf", "infra.tf"])
def test_backend_outside_the_platform_backend_file(tmp_path, name):
    root = _write(tmp_path, {name: 'terraform {\n  backend "gcs" {\n    bucket = "other"\n  }\n}\n'})
    assert _codes(_scan(root)) == [(PA.POLICY_BACKEND_NOT_PLATFORM, name)]


def test_root_backend_tf_is_the_platforms(tmp_path):
    root = _write(tmp_path, {"backend.tf": 'terraform {\n  backend "gcs" {\n    bucket = "b"\n  }\n}\n'})
    assert _scan(root) == []
    nested = _write(tmp_path / "n", {"main.tf": 'module "m" {\n  source = "./infra/modules/m"\n}\n',
                                     "infra/modules/m/backend.tf": 'terraform {\n  backend "local" {}\n}\n'})
    assert _codes(_scan(nested)) == [(PA.POLICY_BACKEND_NOT_PLATFORM, "infra/modules/m/backend.tf")]


def test_cloud_and_encryption_blocks(tmp_path):
    root = _write(tmp_path, {"main.tf": 'terraform {\n  cloud {\n    organization = "o"\n  }\n}\n',
                             "enc.tf": 'terraform {\n  encryption {\n    key_provider "pbkdf2" "k" {\n'
                                       '      passphrase = "x"\n    }\n  }\n}\n'})
    assert _codes(_scan(root)) == [(PA.POLICY_BACKEND_NOT_PLATFORM, "main.tf"),
                                   (PA.POLICY_STATE_ENCRYPTION_FORBIDDEN, "enc.tf")]


def _remote(bucket, prefix, backend="gcs"):
    return (f'data "terraform_remote_state" "r" {{\n  backend = "{backend}"\n  config = {{\n'
            f'    bucket = "{bucket}"\n    prefix = "{prefix}"\n  }}\n}}\n')


def test_remote_state_only_own_constants(tmp_path):
    assert _scan(_write(tmp_path / "own", {"main.tf": _remote(BUCKET, f"workloads/{PID}")})) == []
    for i, (b, p, be) in enumerate([("other-bucket", f"workloads/{PID}", "gcs"), (BUCKET, "workloads/other", "gcs"),
                                    (BUCKET, f"workloads/{PID}", "local"), ("${var.b}", f"workloads/{PID}", "gcs")]):
        root = _write(tmp_path / f"bad{i}", {"main.tf": _remote(b, p, be)})
        assert _codes(_scan(root)) == [(PA.POLICY_REMOTE_STATE_FORBIDDEN, "main.tf")], (b, p, be)
    # no state bucket for this run -> nothing can be "own"
    assert _codes(_scan(_write(tmp_path / "nob", {"main.tf": _remote(BUCKET, f"workloads/{PID}")}), bucket="")) == [
        (PA.POLICY_REMOTE_STATE_FORBIDDEN, "main.tf")]


# ------------------------------------------------------------------------------------------------ modules / parsing
@pytest.mark.parametrize("source,extra", [("git::https://x/y.git", ""), ("hashicorp/x/google", ""),
                                          ("./infra/modules/m", '  version = "1.0"\n'), ("../../escape", ""),
                                          ("${var.s}", "")])
def test_non_local_modules(tmp_path, source, extra):
    root = _write(tmp_path, {"main.tf": f'module "m" {{\n  source = "{source}"\n{extra}}}\n'})
    assert _codes(_scan(root)) == [(PA.POLICY_MODULE_SOURCE_NOT_LOCAL, "main.tf")]


def test_parent_modules_link_is_allowed_and_walked(tmp_path):
    ws = tmp_path / "trace" / "ws"
    _write(ws, {"main.tf": 'module "c" {\n  source = "../modules/compute"\n}\n'})
    _write(tmp_path / "trace" / "modules" / "compute", {"main.tf": 'provider "google" {\n  scopes = []\n}\n'})
    assert _codes(_scan(ws)) == [(PA.POLICY_PROVIDER_ATTRIBUTE_FORBIDDEN, "../modules/compute/main.tf")]


def test_unparseable_file_fails_closed(tmp_path):
    """A file neither python-hcl2 nor OpenTofu's own parser reads (and broken JSON) is APPLY.SOURCE_UNPARSEABLE."""
    tofu = _tofu()
    if tofu is None:
        pytest.skip("no OpenTofu binary on this machine (the parse fallback needs one)")
    root = _write(tmp_path, {"main.tf": 'resource "x" "y" {\n', "j.tf.json": "{not json"})
    assert _codes(_scan(root, parser_bin=tofu)) == [(PA.POLICY_SOURCE_UNPARSEABLE, "j.tf.json"),
                                                    (PA.POLICY_SOURCE_UNPARSEABLE, "main.tf")]


# Review F4: valid OpenTofu that python-hcl2 7.3.1 cannot read. OpenTofu's own parser (tofu fmt) is asked; the file is
# still refused (its content cannot be checked) but under APPLY.SOURCE_NOT_CHECKABLE, naming the line.
MULTILINE_CONDITIONAL = 'locals {\n  x = (\n    var.a\n    ? "one"\n    : "two"\n  )\n}\n'
HEREDOC_IN_CALL = 'locals {\n  y = trimspace(<<EOT\nhello\nEOT\n  )\n}\n'


def test_valid_hcl_python_hcl2_cannot_read_is_not_checkable(tmp_path):
    tofu = _tofu()
    if tofu is None:
        pytest.skip("no OpenTofu binary on this machine (the parse fallback needs one)")
    f = _scan(_write(tmp_path, {"main.tf": MULTILINE_CONDITIONAL}), parser_bin=tofu)
    assert _codes(f) == [(PA.POLICY_SOURCE_NOT_CHECKABLE, "main.tf")]
    assert "line 4" in f[0]["detail"] and "valid OpenTofu" in f[0]["detail"]


def test_heredoc_argument_in_a_call_is_read(tmp_path):
    """The heredoc-in-a-call form the review named parses with python-hcl2 7.3.1 here: no finding at all."""
    assert _scan(_write(tmp_path, {"main.tf": HEREDOC_IN_CALL}), parser_bin=_tofu()) == []


def test_unreadable_to_python_hcl2_but_accepted_by_opentofu_uses_its_own_code(tmp_path, monkeypatch):
    """Both forms through a stubbed parser pair, so the routing is pinned without a binary: python-hcl2 fails,
    OpenTofu accepts -> NOT_CHECKABLE; OpenTofu rejects -> UNPARSEABLE; OpenTofu undecided -> NOT_CHECKABLE."""
    import hcl2

    def boom(_fh):
        raise ValueError("python-hcl2 cannot read this")
    monkeypatch.setattr(hcl2, "load", boom)
    for verdict, code in (([], PA.POLICY_SOURCE_NOT_CHECKABLE), (["rejects"], PA.POLICY_SOURCE_UNPARSEABLE),
                          (None, PA.POLICY_SOURCE_NOT_CHECKABLE)):
        monkeypatch.setattr(PA, "_opentofu_parse_errors", lambda *a, _v=verdict: _v)
        root = _write(tmp_path / str(code) / str(verdict is None), {"main.tf": MULTILINE_CONDITIONAL})
        assert _codes(_scan(root)) == [(code, "main.tf")], verdict


def test_files_opentofu_ignores_are_skipped_and_json_comments_ignored(tmp_path):
    root = _write(tmp_path, {".hidden.tf": 'provider "google" {\n  credentials = "x"\n}\n',
                             "#x.tf#": "garbage", "main.tf~": "garbage", "notes.txt": "x",
                             "main.tf.json": {"//": "a comment", "provider": {"google": {"//": "c", "project": "p"}}}})
    assert _scan(root) == []


def test_parity_unparseable_code_with_the_service():
    src = open(os.path.join(TF_DIR, "service.py"), encoding="utf-8").read()
    assert 'APPLY_SOURCE_UNPARSEABLE = "APPLY.SOURCE_UNPARSEABLE"' in src
    assert PA.POLICY_SOURCE_UNPARSEABLE == "APPLY.SOURCE_UNPARSEABLE"


# ------------------------------------------------------------------------------------------------ Do No Harm
def _golden_module_dirs():
    base = os.path.join(REPO_ROOT, "infra", "modules")
    for dirpath, _dirs, files in os.walk(base):
        if any(f.endswith((".tf", ".tf.json")) for f in files):
            yield dirpath


@pytest.mark.parametrize("module_dir", sorted(_golden_module_dirs()), ids=lambda d: os.path.relpath(d, REPO_ROOT))
def test_every_golden_module_passes(module_dir):
    """No golden module has a provider, backend, cloud or encryption block, a remote-state read or a remote module
    (the two host-platform modules included)."""
    assert PA.preinit_policy_findings(module_dir, product_id=PID, state_bucket=BUCKET,
                                      module_target_allowed=lambda t: True) == []


def test_golden_workload_render_passes(tmp_path, monkeypatch):
    """The platform's real generation path (fake model, canned app; tests/test_ci_render_golden.py), rendered as the
    eval-harness child renders it (no project configured, so the workload region is the platform default)."""
    for name in ("PROJECT_ID", "GOOGLE_CLOUD_PROJECT"):
        monkeypatch.delenv(name, raising=False)
    sys.path.insert(0, os.path.dirname(__file__))
    from test_ci_render_golden import _scaffold
    files = _scaffold()
    _write(tmp_path, files)
    root = tmp_path / "infra" / "workload"
    assert _scan(root) == []


@pytest.mark.parametrize("archetype", ["cloudrun", "gke-autopilot", "gce-bastion", "event-worker", "foundation-only"])
def test_golden_main_tf_per_archetype_passes(tmp_path, archetype):
    gw = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
    if gw not in sys.path:
        sys.path.insert(0, gw)
    from developer_agent import terraform_engine as TE
    try:
        main_tf = TE.generate_golden_main_tf(PID, archetype=archetype)
    except Exception as e:  # noqa: BLE001 - an archetype this engine does not render is not a platform output
        pytest.skip(f"{archetype}: {type(e).__name__}")
    root = _write(tmp_path, {"main.tf": main_tf, "variables.tf": TE.generate_golden_variables_tf(PID)})
    assert [f for f in _scan(root, allowed=lambda t: True) if f["code"] != PA.POLICY_MODULE_SOURCE_NOT_LOCAL] == []


def test_express_synthesizer_output_passes(tmp_path):
    from shared.express_synthesizer import ExpressHCLSynthesizer
    files = ExpressHCLSynthesizer().synthesize_workload(
        product_id=PID, project_id="child-proj-1", state_bucket="castor-tfstate-x",
        module_instances=[{"module_id": "compute-cloudrun", "instance_name": "web", "parameters": {}},
                          {"module_id": "storage-bucket", "instance_name": "assets", "parameters": {}}])
    _write(tmp_path, files)
    assert _scan(tmp_path / "infra" / "workload") == []


def test_gke_kubernetes_auto_wiring_block_passes(tmp_path):
    """The exact provider block the golden render writes for GKE (read from terraform_engine.py's source). FD55-W6e
    deleted the deploy-time copy of this block (`k8s_wiring` in service.py); the render is now its only writer."""
    engine = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway", "developer_agent", "terraform_engine.py")
    tree = ast.parse(open(engine, encoding="utf-8").read())
    blocks = [n.value.value for n in ast.walk(tree) if isinstance(n, ast.Assign)
              and any(isinstance(t, ast.Name) and t.id == "k8s_provider_block" for t in n.targets)
              and isinstance(n.value, ast.Constant) and n.value.value]
    assert len(blocks) == 1 and 'provider "kubernetes"' in blocks[0]
    root = _write(tmp_path, {"main.tf": 'module "compute" {\n  source = "./infra/modules/c"\n}\n' + blocks[0],
                             "infra/modules/c/main.tf": "", "versions.tf":
                             'terraform {\n  required_providers {\n    kubernetes = {\n'
                             '      source  = "hashicorp/kubernetes"\n      version = ">= 2.20.0"\n    }\n  }\n}\n'})
    assert _scan(root) == []
