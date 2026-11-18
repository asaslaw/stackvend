"""FD-4AQ W1b (finding AQ-X1a; proposed owner row AQ-6): OpenTofu may install only the platform's providers.

mcp-servers/terraform/provider_allowlist.py is the terraform server's single allow-list source: the CLI config of every
tofu run (`_ensure_provider_mirror`), the verified mirror's pre-cache, FD-4AW-b's apply tables and the validate
service's tables derive from it. The CLI config lets OpenTofu install exactly google, google-beta, kubernetes and
random on registry.opentofu.org / registry.terraform.io (verified mirror, then the official registry limited to the
same 8 addresses); any other provider fails `init`, and the failure is typed PROVIDER_NOT_ALLOWED with the exact
provider address (python-hcl2 parse + Terraform's provider rules; no error text is read).

Pure tests, wiring tests with a mocked subprocess, and real-engine tests (pinned OpenTofu 1.9.0 + the production
provider mirror, network denied; skipped when those untracked tools are not on this machine).
"""
import hermetic_guard  # noqa: F401  (first import)

import json
import os
import platform
import shutil
import subprocess
import sys
import zipfile
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
GW = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for _p in (TF_DIR,):
    if _p not in sys.path:
        sys.path.insert(0, _p)

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (terraform MCP requirement) not installed")

import provider_allowlist as PA  # noqa: E402
from fd4g_support import load_tf_service  # noqa: E402
from tests.tofu_popen_fake import popen_from_run  # noqa: E402  FD-4AQ W3: _run_subprocess uses Popen

OTF = "registry.opentofu.org"
TFR = "registry.terraform.io"
EIGHT = [f"{reg}/hashicorp/{p}" for reg in (OTF, TFR) for p in ("google", "google-beta", "kubernetes", "random")]


@pytest.fixture
def tf(monkeypatch):
    return load_tf_service(monkeypatch)


def _write(root, files):
    for rel, text in files.items():
        path = os.path.join(str(root), *rel.split("/"))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
    return str(root)


def _bad(root, files, registry=OTF):
    return PA.disallowed_providers(_write(root, files), registry)


# ------------------------------------------------------------------------------------------------ CLI config
def _parsed_rc(text):
    doc = hcl2.loads(text)
    (pi,) = doc["provider_installation"]
    return pi


def test_cli_config_lists_exactly_the_eight_addresses_in_both_methods():
    pi = _parsed_rc(PA.cli_config("/srv/tooling/plugin_mirror"))
    assert sorted(k for k in pi if not k.startswith("__")) == ["direct", "filesystem_mirror"]
    (fsm,) = pi["filesystem_mirror"]
    (direct,) = pi["direct"]
    assert fsm["path"] == "/srv/tooling/plugin_mirror"
    assert fsm["include"] == EIGHT
    assert direct["include"] == EIGHT                       # no unrestricted `direct {}`
    assert "exclude" not in fsm and "exclude" not in direct
    assert list(PA.INSTALLABLE_PROVIDERS) == EIGHT


def test_validate_form_is_mirror_only_with_the_same_list():
    pi = _parsed_rc(PA.cli_config("/srv/m", registry=False))
    assert sorted(k for k in pi if not k.startswith("__")) == ["filesystem_mirror"]
    assert pi["filesystem_mirror"][0]["include"] == EIGHT


def test_service_rc_is_the_allowlist_config(tf, tmp_path, monkeypatch):
    import binary_checksums as bc
    monkeypatch.setattr(bc, "fetch_to", MagicMock(side_effect=OSError("offline test")))
    svc = tf.TerraformService(project_id="mock-stackvend-project", workspace_base_dir=str(tmp_path),
                              firestore_client=MagicMock())
    rc_path = svc._ensure_provider_mirror()
    with open(rc_path) as fh:
        assert fh.read() == PA.cli_config(os.path.join(svc.tooling_dir, "plugin_mirror"))
    # kubernetes is pre-cached like the others (FD-4BQ path), and now listed. PROVIDER-CHECKSUMS RT F1: offline, every
    # provider's type dir exists but no <version>/<os_arch> dir is left behind (an empty one would block `direct {}`).
    for reg in (OTF, TFR):
        for p, versions in PA.MIRROR_PROVIDER_VERSIONS.items():
            assert os.path.isdir(os.path.join(svc.tooling_dir, "plugin_mirror", reg, "hashicorp", p))
            for v in versions:
                assert not os.path.exists(os.path.join(svc.tooling_dir, "plugin_mirror", reg, "hashicorp", p, v))


# ------------------------------------------------------------------------------------------------ single source
def test_every_table_derives_from_the_one_allowlist(tf, monkeypatch):
    import validate_service as vs
    assert tf.APPLY_PLATFORM_PROVIDER_SOURCES is PA.PLATFORM_PROVIDER_SOURCES
    assert tf.APPLY_PROVIDER_REGISTRIES is PA.PROVIDER_REGISTRIES
    assert tf.APPLY_BUILTIN_PROVIDER == PA.BUILTIN_PROVIDER
    assert tf.APPLY_ALLOWED_PROVIDERS == frozenset(PA.INSTALLABLE_PROVIDERS) | {PA.BUILTIN_PROVIDER}
    assert vs.VALIDATE_PROVIDERS == tuple(PA.PLATFORM_PROVIDER_SOURCES)
    assert vs.REGISTRIES == PA.PROVIDER_REGISTRIES
    assert set(PA.MIRROR_PROVIDER_VERSIONS) == set(PA.PLATFORM_PROVIDER_SOURCES)
    import binary_checksums as bc
    assert {k[0] for k in bc.PROVIDER_CHECKSUMS} <= set(PA.PLATFORM_PROVIDER_SOURCES)
    # the gateway (separate deployable) keeps an exact copy
    for p in (GW, REPO_ROOT):
        if p not in sys.path:
            sys.path.insert(0, p)
    from developer_agent.validators import policy_tables as T
    assert T.PLATFORM_PROVIDER_SOURCES == PA.PLATFORM_PROVIDER_SOURCES
    assert T.PLATFORM_PROVIDER_REGISTRIES == PA.PROVIDER_REGISTRIES


# ------------------------------------------------------------------------------------------------ classification
@pytest.mark.parametrize("files,expected", [
    ({"main.tf": 'data "external" "e" {\n  program = ["sh", "-c", "env"]\n}\n'}, [f"{OTF}/hashicorp/external"]),
    ({"main.tf": 'data "http" "h" {\n  url = "https://example.invalid"\n}\n'}, [f"{OTF}/hashicorp/http"]),
    ({"main.tf": 'resource "null_resource" "n" {}\n'}, [f"{OTF}/hashicorp/null"]),
    ({"main.tf": 'terraform {\n  required_providers {\n    github = {\n      source = "integrations/github"\n    }\n'
                 '  }\n}\n'}, [f"{OTF}/integrations/github"]),
    ({"main.tf": 'terraform {\n  required_providers {\n    google = {\n      source = "evilcorp/google"\n    }\n'
                 '  }\n}\nresource "google_storage_bucket" "b" {\n  name = "x"\n  location = "US"\n}\n'},
     [f"{OTF}/evilcorp/google"]),
    ({"main.tf": 'terraform {\n  required_providers {\n    x = {\n      source = "registry.example.com/acme/x"\n'
                 '    }\n  }\n}\n'}, ["registry.example.com/acme/x"]),
    ({"main.tf": 'resource "google_storage_bucket" "b" {\n  provider = null.x\n  name = "b"\n}\n'},
     [f"{OTF}/hashicorp/null"]),
    ({"main.tf": 'provider "aws" {\n  region = "us-east-1"\n}\n'}, [f"{OTF}/hashicorp/aws"]),
    ({"main.tf": 'terraform {\n  required_providers {\n    local = "~> 2.0"\n  }\n}\n'}, [f"{OTF}/hashicorp/local"]),
    ({"main.tf": 'check "c" {\n  data "http" "h" {\n    url = "https://x.invalid"\n  }\n  assert {\n'
                 '    condition = true\n    error_message = "x"\n  }\n}\n'}, [f"{OTF}/hashicorp/http"]),
    ({"main.tf": 'module "m" {\n  source = "./mod"\n}\n',
      "mod/main.tf": 'resource "time_sleep" "w" {\n  create_duration = "30s"\n}\n'}, [f"{OTF}/hashicorp/time"]),
    ({"main.tf": 'module "m" {\n  source = "./mod"\n  providers = {\n    tls = tls.a\n  }\n}\n',
      "mod/main.tf": ""}, [f"{OTF}/hashicorp/tls"]),
    ({"main.tf.json": json.dumps({"data": {"external": {"e": {"program": ["sh"]}}}})},
     [f"{OTF}/hashicorp/external"]),
    # Fable F4: OpenTofu 1.8+ also loads *.tofu / *.tofu.json
    ({"main.tf": "", "extra.tofu": 'resource "null_resource" "n" {}\n'}, [f"{OTF}/hashicorp/null"]),
    ({"extra.tofu.json": json.dumps({"data": {"http": {"h": {"url": "https://x.invalid"}}}})},
     [f"{OTF}/hashicorp/http"]),
])
def test_disallowed_providers_are_named_exactly(tmp_path, files, expected):
    assert _bad(tmp_path, files) == expected


def test_terraform_engine_names_the_terraform_registry(tmp_path):
    assert _bad(tmp_path, {"main.tf": 'data "external" "e" {\n  program = ["sh"]\n}\n'}, TFR) == \
        [f"{TFR}/hashicorp/external"]


def test_module_manifest_dirs_count_remote_modules_too(tmp_path):
    """OpenTofu's own manifest (written by init before providers) lists a remote module's directory."""
    _write(tmp_path, {"main.tf": 'module "r" {\n  source = "git::https://example.invalid/m.git"\n}\n'})
    data_dir = os.path.join(str(tmp_path), ".terraform", "modules")   # what `init` writes (never a repo key)
    os.makedirs(os.path.join(data_dir, "r"))
    with open(os.path.join(data_dir, "r", "main.tf"), "w") as fh:
        fh.write('resource "null_resource" "x" {}\n')
    with open(os.path.join(data_dir, "modules.json"), "w") as fh:
        json.dump({"Modules": [{"Key": "", "Source": "", "Dir": "."},
                               {"Key": "r", "Source": "git::https://example.invalid/m.git",
                                "Dir": os.path.join(".terraform", "modules", "r")}]}, fh)
    assert PA.disallowed_providers(str(tmp_path), OTF) == [f"{OTF}/hashicorp/null"]


# Do No Harm: the platform's own shapes name nothing
@pytest.mark.parametrize("files", [
    {"main.tf": 'terraform {\n  required_providers {\n    google = {\n      source  = "hashicorp/google"\n'
                '      version = ">= 6.0.0, < 7.0.0"\n    }\n    google-beta = {\n'
                '      source = "registry.terraform.io/hashicorp/google-beta"\n    }\n    kubernetes = {\n'
                '      source = "registry.opentofu.org/hashicorp/kubernetes"\n    }\n    random = {\n'
                '      source = "HashiCorp/Random"\n    }\n  }\n}\n'
                'resource "google_storage_bucket" "b" {\n  provider = google-beta\n  name = "b"\n  location = "US"\n}\n'
                'resource "kubernetes_namespace" "n" {\n  metadata {\n    name = "n"\n  }\n}\n'
                'resource "random_id" "r" {\n  byte_length = 4\n}\n'
                'resource "terraform_data" "t" {}\n'
                'data "terraform_remote_state" "s" {\n  backend = "gcs"\n  config = {\n    bucket = "b"\n  }\n}\n'
                'provider "google" {\n  alias = "west"\n}\n'
                'import {\n  to = google_storage_bucket.b\n  id = "b"\n  provider = google.west\n}\n'
                'module "m" {\n  source = "./mod"\n  providers = {\n    google = google.west\n  }\n}\n',
     "mod/main.tf": 'resource "google_pubsub_topic" "t" {\n  name = "t"\n}\n'},
    {"main.tf": 'terraform {\n  required_providers {\n    gcp = {\n      source = "hashicorp/google"\n    }\n'
                '  }\n}\nresource "gcp_storage_bucket" "b" {}\n'},   # an aliased local name maps through
    {"main.tf": "this is { not hcl"},                                  # unparseable: OpenTofu reports it itself
    {"main.tf": ""},
])
def test_negative_platform_shapes_name_nothing(tmp_path, files):
    assert _bad(tmp_path, files) == []


def test_negative_every_golden_module_and_builtin_payload_names_nothing(tmp_path):
    mods = os.path.join(REPO_ROOT, "infra", "modules")
    for name in sorted(os.listdir(mods)):
        if os.path.isdir(os.path.join(mods, name)):
            assert PA.disallowed_providers(os.path.join(mods, name), OTF) == [], name
    sys.path.insert(0, TF_DIR)
    from shared.builtin_modules_payload import BUILTIN_MODULE_FILES
    for module_id, files in BUILTIN_MODULE_FILES.items():
        assert _bad(tmp_path / module_id, files) == [], module_id


# ------------------------------------------------------------------------------------------------ wiring
def _svc(tf, tmp_path, monkeypatch, rc_text="provider_installation {}\n", tofu="tofu"):
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="",
                              workspace_base_dir=str(tmp_path / "base"), firestore_client=MagicMock())
    svc.db = None
    rc = tmp_path / "terraform.rc"
    rc.write_text(rc_text, encoding="utf-8")
    monkeypatch.setattr(svc, "_ensure_binary", lambda *a, **k: tofu)
    monkeypatch.setattr(svc, "_ensure_provider_mirror", lambda *a, **k: str(rc))
    return svc


def _fake_run(tf, monkeypatch, rc, stderr="Error: Failed to query available provider packages\n", pull=None,
              envs=None):
    """Fake engine (a `subprocess.run`-shaped function served through `subprocess.Popen`, which the bounded runner
    uses): every command exits `rc`; `state pull` returns `pull` = (rc, stdout) when given."""
    calls = []

    def run(cmd, cwd=None, env=None, **kw):
        calls.append(list(cmd))
        if envs is not None:
            envs.append(dict(env or {}))
        if cmd[1:3] == ["state", "pull"] and pull is not None:
            return subprocess.CompletedProcess(cmd, pull[0], pull[1], "" if pull[0] == 0 else "pull failed")
        return subprocess.CompletedProcess(cmd, rc, "", stderr if rc else "")

    monkeypatch.setattr(tf.subprocess, "Popen", popen_from_run(run))
    return calls


def _backend_initialized(ws):
    """What a failed init leaves once it got past the backend step (OpenTofu writes .terraform/terraform.tfstate)."""
    os.makedirs(os.path.join(ws, ".terraform"), exist_ok=True)
    with open(os.path.join(ws, ".terraform", "terraform.tfstate"), "w") as fh:
        fh.write('{"version": 3, "backend": {"type": "gcs"}}\n')


def _state(*providers):
    return json.dumps({"version": 4, "resources": [
        {"mode": "managed", "type": "x_y", "name": f"r{i}", "provider": p, "instances": []}
        for i, p in enumerate(providers)]})


EXTERNAL = {"main.tf": 'data "external" "e" {\n  program = ["sh"]\n}\n'}
GOOGLE = {"main.tf": 'resource "google_storage_bucket" "b" {\n  name = "b"\n  location = "US"\n}\n'}


def test_failed_init_with_a_disallowed_provider_is_typed(tf, tmp_path, monkeypatch):
    svc = _svc(tf, tmp_path, monkeypatch)
    ws = _write(tmp_path / "ws", EXTERNAL)
    _fake_run(tf, monkeypatch, 1)
    out = svc._run_subprocess(["tofu", "init", "-input=false"], cwd=ws, iac_engine="OPENTOFU")
    assert out["success"] is False
    assert out["error_class"] == "PROVIDER_NOT_ALLOWED"
    assert out["providers_not_allowed"] == [f"{OTF}/hashicorp/external"]
    assert out["stderr"].startswith(f"PROVIDER_NOT_ALLOWED: this workload's Terraform requires {OTF}/hashicorp/external")
    assert out["stderr"].endswith("Error: Failed to query available provider packages\n")   # engine text kept


@pytest.mark.parametrize("files,cmd,rc", [
    (GOOGLE, ["tofu", "init", "-input=false"], 1),      # init failed for another reason: untyped, text unchanged
    (EXTERNAL, ["tofu", "init", "-input=false"], 0),    # init succeeded: never classified
    (EXTERNAL, ["tofu", "plan"], 1),                    # not init
])
def test_negative_other_results_are_unchanged(tf, tmp_path, monkeypatch, files, cmd, rc):
    svc = _svc(tf, tmp_path, monkeypatch)
    ws = _write(tmp_path / "ws", files)
    _fake_run(tf, monkeypatch, rc)
    out = svc._run_subprocess(cmd, cwd=ws, iac_engine="OPENTOFU")
    assert "error_class" not in out and "providers_not_allowed" not in out
    assert out["stderr"] == ("Error: Failed to query available provider packages\n" if rc else "")


# ---- Fable F2: a provider recorded only in state is typed too (state pull JSON, no text)
NULL_ADDR = 'provider["registry.opentofu.org/hashicorp/null"]'
GOOGLE_ADDR = 'provider["registry.opentofu.org/hashicorp/google"]'


def test_state_only_disallowed_provider_is_typed(tf, tmp_path, monkeypatch):
    svc = _svc(tf, tmp_path, monkeypatch)
    ws = _write(tmp_path / "ws", GOOGLE)
    _backend_initialized(ws)
    calls = _fake_run(tf, monkeypatch, 1, pull=(0, _state(GOOGLE_ADDR, NULL_ADDR,
                                                            'module.m.provider["registry.terraform.io/hashicorp/time"].a')))
    out = svc._run_subprocess(["tofu", "init", "-input=false"], cwd=ws, iac_engine="OPENTOFU")
    assert [c[1:3] for c in calls] == [["init", "-input=false"], ["state", "pull"]]
    assert out["error_class"] == "PROVIDER_NOT_ALLOWED"
    assert out["providers_not_allowed"] == out["providers_not_allowed_in_state"] == [
        f"{OTF}/hashicorp/null", f"{TFR}/hashicorp/time"]
    assert "recorded in state; an operator removes those resources with `state rm`" in out["stderr"]
    assert out["stderr"].endswith("Error: Failed to query available provider packages\n")


def test_config_and_state_are_named_once_each(tf, tmp_path, monkeypatch):
    svc = _svc(tf, tmp_path, monkeypatch)
    ws = _write(tmp_path / "ws", {"main.tf": 'resource "null_resource" "n" {}\n'})
    _backend_initialized(ws)
    _fake_run(tf, monkeypatch, 1, pull=(0, _state(NULL_ADDR, 'provider["registry.opentofu.org/hashicorp/http"]')))
    out = svc._run_subprocess(["tofu", "init"], cwd=ws, iac_engine="OPENTOFU")
    assert out["providers_not_allowed"] == [f"{OTF}/hashicorp/null", f"{OTF}/hashicorp/http"]
    assert out["providers_not_allowed_in_state"] == [f"{OTF}/hashicorp/http"]


@pytest.mark.parametrize("pull", [
    (0, _state(GOOGLE_ADDR, 'provider["registry.terraform.io/hashicorp/random"]', 'provider["terraform.io/builtin/terraform"]')),
    (1, ""),                          # pull failed
    (0, "not json"),                  # unreadable
    (0, json.dumps({"version": 4})),  # no resources
])
def test_negative_state_with_allowed_providers_or_no_readable_state_is_unchanged(tf, tmp_path, monkeypatch, pull):
    svc = _svc(tf, tmp_path, monkeypatch)
    ws = _write(tmp_path / "ws", GOOGLE)
    _backend_initialized(ws)
    _fake_run(tf, monkeypatch, 1, pull=pull)
    out = svc._run_subprocess(["tofu", "init"], cwd=ws, iac_engine="OPENTOFU")
    assert "error_class" not in out and "providers_not_allowed" not in out
    assert out["stderr"] == "Error: Failed to query available provider packages\n"


def test_no_state_pull_before_the_backend_was_initialized(tf, tmp_path, monkeypatch):
    svc = _svc(tf, tmp_path, monkeypatch)
    ws = _write(tmp_path / "ws", GOOGLE)
    calls = _fake_run(tf, monkeypatch, 1, pull=(0, _state(NULL_ADDR)))
    out = svc._run_subprocess(["tofu", "init"], cwd=ws, iac_engine="OPENTOFU")
    assert [c[1] for c in calls] == ["init"] and "error_class" not in out


# ---- Fable F3: inherited extra CLI arguments never reach tofu
def test_tf_cli_args_are_dropped_from_every_tofu_run(tf, tmp_path, monkeypatch):
    svc = _svc(tf, tmp_path, monkeypatch)
    ws = _write(tmp_path / "ws", GOOGLE)
    monkeypatch.setenv("TF_CLI_ARGS", "-plugin-dir=/tmp/evil")
    monkeypatch.setenv("TF_CLI_ARGS_init", "-plugin-dir=/tmp/evil")
    monkeypatch.setenv("FD4AQ_UNRELATED", "kept")
    envs = []
    _fake_run(tf, monkeypatch, 0, envs=envs)
    svc._run_subprocess(["tofu", "init"], cwd=ws, iac_engine="OPENTOFU")
    svc._run_subprocess(["tofu", "plan"], cwd=ws, env={"TF_CLI_ARGS": "-x", "TF_CLI_ARGS_init": "-y"},
                        iac_engine="OPENTOFU")
    assert len(envs) == 2
    for env in envs:
        assert "TF_CLI_ARGS" not in env and "TF_CLI_ARGS_init" not in env
        # FD-7L Phase 2a (SAT-27): tofu inherits only the allow-list (runner_identity.TOFU_INHERITED_ENV), so an
        # unrelated runner variable no longer reaches it either (was: "the rest of the env is unchanged").
        assert "FD4AQ_UNRELATED" not in env
        assert env["TF_CLI_CONFIG_FILE"] == str(tmp_path / "terraform.rc")


def test_generate_plan_returns_the_typed_init_failure(tf, tmp_path, monkeypatch):
    svc = _svc(tf, tmp_path, monkeypatch)
    ws = _write(tmp_path / "ws", EXTERNAL)
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    monkeypatch.setattr(svc, "prepare_workspace", lambda *a, **k: ws)
    calls = _fake_run(tf, monkeypatch, 1)
    res = svc.generate_plan("shop", "t-1", {}, iac_engine="OPENTOFU")
    assert (res["status"], res["error_class"], res["providers_not_allowed"]) == (
        "INIT_FAILED", "PROVIDER_NOT_ALLOWED", [f"{OTF}/hashicorp/external"])
    assert [c[1] for c in calls] == ["init"]


# ------------------------------------------------------------------------------------------------ real engine
# The production column (untracked): eval/.tools/tofu-1.9.0/tofu + eval/.tofu-mirror-prod, or the same overrides as
# tests/test_lane14_pr0b_regulated.py. The oracle mirror (eval/.tofu-mirror) is only needed for the plugin-cache test.
PROD_TOFU = os.environ.get("STACKVEND_PROD_TOFU") or os.path.join(REPO_ROOT, "eval", ".tools", "tofu-1.9.0", "tofu")
PROD_MIRROR = os.environ.get("STACKVEND_PROD_MIRROR") or os.path.join(REPO_ROOT, "eval", ".tofu-mirror-prod")
_ORACLE_MIRROR = os.environ.get("STACKVEND_ORACLE_MIRROR") or os.path.join(REPO_ROOT, "eval", ".tofu-mirror")


def _prod_tools():
    if os.access(PROD_TOFU, os.X_OK) and os.path.isdir(PROD_MIRROR):
        return PROD_TOFU, PROD_MIRROR
    return None, None


def _os_arch():
    machine = platform.machine().lower()
    return f"{sys.platform}_{'arm64' if machine in ('arm64', 'aarch64') else 'amd64'}"


@pytest.fixture(scope="module")
def engine(tmp_path_factory):
    """Pinned OpenTofu 1.9.0 + a verified-mirror copy in the server's unpacked layout
    (<registry>/hashicorp/<type>/<version>/<os_arch>/terraform-provider-*), both registry hosts, from the production
    provider mirror's zips (no download)."""
    tofu, packed = _prod_tools()
    if not tofu:
        pytest.skip("production column (eval/.tools/tofu-1.9.0/tofu + eval/.tofu-mirror-prod) not on this machine")
    os_arch = _os_arch()
    mirror = tmp_path_factory.mktemp("fd4aq-mirror")
    found = {}
    for p in PA.PLATFORM_PROVIDER_SOURCES:
        pdir = os.path.join(packed, OTF, "hashicorp", p)
        zips = [z for z in sorted(os.listdir(pdir)) if z.endswith(f"_{os_arch}.zip")] if os.path.isdir(pdir) else []
        if not zips:
            pytest.skip(f"production mirror has no {p} zip for {os_arch}")
        version = zips[0][len(f"terraform-provider-{p}_"):-len(f"_{os_arch}.zip")]
        first = None
        for reg in (OTF, TFR):
            dest = os.path.join(str(mirror), reg, "hashicorp", p, version, os_arch)
            os.makedirs(dest)
            if first is None:
                with zipfile.ZipFile(os.path.join(pdir, zips[0])) as zf:
                    zf.extractall(dest)
                for f in os.listdir(dest):
                    os.chmod(os.path.join(dest, f), 0o755)
                first = dest
            else:
                for f in os.listdir(first):
                    os.link(os.path.join(first, f), os.path.join(dest, f))
        found[p] = version
    return tofu, str(mirror), found


def _init(tofu, ws, rc, home, cache=None):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "TF_CLI_CONFIG_FILE": str(rc), "TF_IN_AUTOMATION": "1",
           "CHECKPOINT_DISABLE": "1", "HTTPS_PROXY": "http://127.0.0.1:9", "HTTP_PROXY": "http://127.0.0.1:9"}
    if cache:
        env["TF_PLUGIN_CACHE_DIR"] = str(cache)
    return subprocess.run([tofu, "init", "-backend=false", "-input=false", "-no-color"], cwd=str(ws), env=env,
                          capture_output=True, text=True, timeout=300)


def _root_requiring(addresses_versions):
    lines = "".join(f'    {a.rsplit("/", 1)[1]} = {{\n      source  = "{a}"\n      version = "{v}"\n    }}\n'
                    for a, v in addresses_versions)
    return {"main.tf": "terraform {\n  required_providers {\n" + lines + "  }\n}\n"}


@pytest.mark.parametrize("reg", [OTF, TFR])
def test_real_engine_the_four_providers_init_from_the_verified_mirror_offline(engine, tmp_path, reg):
    """Network denied (proxy to a closed port): the mirror half of the platform config (same include list) installs
    google, google-beta, kubernetes and random for either registry host."""
    tofu, mirror, versions = engine
    rc = tmp_path / "rc"
    rc.write_text(PA.cli_config(mirror, registry=False))
    ws = _write(tmp_path / "ws", _root_requiring([(f"{reg}/hashicorp/{p}", v) for p, v in versions.items()]))
    res = _init(tofu, ws, rc, tmp_path)
    assert res.returncode == 0, res.stderr
    lock = hcl2.load(open(os.path.join(ws, ".terraform.lock.hcl")))
    locked = {label: body["version"] for entry in lock["provider"] for label, body in entry.items()}
    assert locked == {f"{reg}/hashicorp/{p}": v for p, v in versions.items()}


@pytest.mark.parametrize("files,address", [
    (EXTERNAL, f"{OTF}/hashicorp/external"),
    ({"main.tf": 'data "http" "h" {\n  url = "https://example.invalid"\n}\n'}, f"{OTF}/hashicorp/http"),
    ({"main.tf": 'terraform {\n  required_providers {\n    github = {\n      source = "integrations/github"\n'
                 '    }\n  }\n}\n'}, f"{OTF}/integrations/github"),
    ({"main.tf": 'module "m" {\n  source = "./mod"\n}\n',
      "mod/main.tf": 'resource "null_resource" "x" {}\n'}, f"{OTF}/hashicorp/null"),
])
def test_real_engine_a_disallowed_provider_fails_init_typed(engine, tf, tmp_path, monkeypatch, files, address):
    """The production CLI config (mirror + allow-listed registry) and the REAL _run_subprocess: init fails without any
    network attempt for the disallowed provider, and the result names it."""
    tofu, mirror, _versions = engine
    svc = _svc(tf, tmp_path, monkeypatch, rc_text=PA.cli_config(mirror), tofu=tofu)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    ws = _write(tmp_path / "ws", files)
    out = svc._run_subprocess(["tofu", "init", "-input=false", "-no-color"], cwd=ws, iac_engine="OPENTOFU")
    assert out["success"] is False
    assert (out["error_class"], out["providers_not_allowed"]) == ("PROVIDER_NOT_ALLOWED", [address])
    assert not os.path.isdir(os.path.join(ws, ".terraform", "providers", OTF, address.split("/", 1)[1]))


def test_real_engine_negative_allowed_provider_reaches_only_the_registry_and_is_untyped(engine, tf, tmp_path,
                                                                                         monkeypatch):
    """An allowed provider whose version only the registry could serve, with the registry unreachable: init fails on
    the network (the official registry is the only other place OpenTofu looks), and nothing is typed."""
    tofu, mirror, _versions = engine
    svc = _svc(tf, tmp_path, monkeypatch, rc_text=PA.cli_config(mirror), tofu=tofu)
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    ws = _write(tmp_path / "ws", _root_requiring([(f"{OTF}/hashicorp/random", "3.0.0")]))
    out = svc._run_subprocess(["tofu", "init", "-input=false", "-no-color"], cwd=ws, iac_engine="OPENTOFU")
    assert out["success"] is False
    assert "error_class" not in out


def test_real_engine_a_cached_locked_provider_does_not_bypass_the_allowlist(engine, tmp_path):
    """A lock file plus a plugin-cache copy of hashicorp/null (from an earlier unrestricted install) still fails init
    under the platform config: OpenTofu asks the installation methods first."""
    tofu, mirror, _versions = engine
    null_dir = os.path.join(_ORACLE_MIRROR, OTF, "hashicorp", "null")
    if not os.path.isdir(null_dir):
        pytest.skip("oracle mirror with hashicorp/null not on this machine")
    cache = tmp_path / "cache"
    cache.mkdir()
    open_rc = tmp_path / "open.rc"
    open_rc.write_text('provider_installation {\n  filesystem_mirror {\n    path = %s\n  }\n}\n'
                       % json.dumps(_ORACLE_MIRROR))
    files = {"main.tf": 'terraform {\n  required_providers {\n    null = {\n      source = "hashicorp/null"\n'
                        '    }\n  }\n}\n'}
    seed = _write(tmp_path / "seed", files)
    assert _init(tofu, seed, open_rc, tmp_path, cache).returncode == 0
    ws = _write(tmp_path / "ws", files)
    shutil.copy(os.path.join(seed, ".terraform.lock.hcl"), os.path.join(ws, ".terraform.lock.hcl"))
    rc = tmp_path / "rc"
    rc.write_text(PA.cli_config(mirror))
    res = _init(tofu, ws, rc, tmp_path, cache)
    assert res.returncode != 0
    assert PA.disallowed_providers(ws, OTF) == [f"{OTF}/hashicorp/null"]
    assert not os.path.isdir(os.path.join(ws, ".terraform", "providers", OTF, "hashicorp", "null"))


def test_real_engine_a_state_only_provider_fails_init_typed(engine, tf, tmp_path, monkeypatch):
    """Fable F2 on the real engine: the configuration uses only the built-in provider, the (local-backend) state
    records a null_resource. The real init needs hashicorp/null for the state, fails after initializing the backend
    (.terraform/terraform.tfstate), and the classification pulls the state and names it as recorded in state.
    The hermetic guard refuses every `tofu state` child, so `state pull` here returns the local backend's state file
    (what OpenTofu 1.9.0's own `state pull` printed for this workspace in the builder's offline probe)."""
    tofu, mirror, _versions = engine
    svc = _svc(tf, tmp_path, monkeypatch, rc_text=PA.cli_config(mirror), tofu=tofu)
    real_popen = tf.subprocess.Popen
    pulls = []

    def popen(cmd, *a, **k):
        if list(cmd[1:3]) == ["state", "pull"]:
            pulls.append(k.get("cwd"))
            with open(os.path.join(k["cwd"], "state", "w.tfstate")) as fh:
                return popen_from_run(lambda c, **_kw: subprocess.CompletedProcess(c, 0, fh.read(), ""))(cmd, **k)
        return real_popen(cmd, *a, **k)   # the real engine runs through the bounded runner's Popen

    monkeypatch.setattr(tf.subprocess, "Popen", popen)
    ws = _write(tmp_path / "ws", {
        "main.tf": 'terraform {\n  backend "local" {\n    path = "state/w.tfstate"\n  }\n}\n'
                   'resource "terraform_data" "t" {}\n',
        "state/w.tfstate": json.dumps({
            "version": 4, "terraform_version": "1.9.0", "serial": 3,
            "lineage": "11111111-2222-3333-4444-555555555555", "outputs": {}, "check_results": None,
            "resources": [{"mode": "managed", "type": "null_resource", "name": "old", "provider": NULL_ADDR,
                           "instances": [{"schema_version": 0, "attributes": {"id": "1", "triggers": None},
                                          "sensitive_attributes": []}]}]}),
    })
    out = svc._run_subprocess(["tofu", "init", "-input=false", "-no-color"], cwd=ws, iac_engine="OPENTOFU")
    assert out["success"] is False
    assert PA.disallowed_providers(ws, OTF) == []                    # not in the configuration
    assert os.path.isfile(os.path.join(ws, ".terraform", "terraform.tfstate")) and pulls == [ws]
    assert (out["error_class"], out["providers_not_allowed_in_state"]) == ("PROVIDER_NOT_ALLOWED",
                                                                         [f"{OTF}/hashicorp/null"])
