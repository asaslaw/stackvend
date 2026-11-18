"""FD-4BD / FD-4BV / FD-4BW: the deploy workspace (mcp-servers/terraform/service.py deploy_workload).

- FD-4BD: the host OAuth client secret and the child Firebase API key never land in a workspace file (so never in
  the Cloud Build source tarball, an upload or a Git writeback); every tofu process of the deploy workspace gets
  them as TF_VAR_oauth_client_secret / TF_VAR_firebase_api_key instead. (FD-4AQ AQ-1: the host secret is no longer
  read at all, so TF_VAR_oauth_client_secret is the explicit ""; tests/test_fd4aq_w1_no_host_secret.py.)
- FD-4BV: the platform tfvars values are merged INTO the workload's own infra/workload/terraform.tfvars by parsed
  key (python-hcl2); workload keys (the Express IPAM fact subnet_cidr, maps, lists) are kept with their exact text.
- FD-4BW: module `source` values are re-anchored to ./infra/modules/ (bundles: ./infra/bundles/) from the parsed
  module blocks, whatever the whitespace; an already-canonical file is byte-identical (Do No Harm).

Hermetic: no repo fetch, no Secret Manager, no ADC, no network, no real tofu (except the real-engine test, which
skips when the production column eval/.tools/tofu-1.9.0/tofu + eval/.tofu-mirror-prod is not on this machine).
"""
import hermetic_guard  # noqa: F401  (first import)

import io
import json
import os
import subprocess

from tests.tofu_popen_fake import popen_from_run  # FD-4AQ W3: _run_subprocess uses Popen
import sys
import tarfile
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in (REPO_ROOT, os.path.join(REPO_ROOT, "eval")):
    if p not in sys.path:
        sys.path.insert(0, p)

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (terraform MCP requirement) not installed")

from fd4g_support import load_tf_service  # noqa: E402

FACT = "10.100.7.0/24"                                   # a test IPAM allocation (tests only)
FAKE_SECRET = "GOCSPX-fd4bd-test-only-not-a-secret-000"  # test value, never a real credential
FAKE_FB_KEY = "AIzaSy-fd4bd-test-only-browser-key-0000"  # test value, never a real key
FAKE_CLIENT_ID = "1234-fd4bd.apps.googleusercontent.com"
PROD_TOFU = os.path.join(REPO_ROOT, "eval", ".tools", "tofu-1.9.0", "tofu")
PROD_MIRROR = os.path.join(REPO_ROOT, "eval", ".tofu-mirror-prod")


@pytest.fixture
def tf(monkeypatch):
    return load_tf_service(monkeypatch)


# ------------------------------------------------------------------------------------------------ FD-4BV units
def test_parse_tfvars_attributes_keeps_exact_attribute_and_value_text(tf):
    text = ('# IPAM fact\nsubnet_cidr = "10.0.0.0/24"\ntags   = {\n  team = "a" # owner\n}\n'
            'invokers = ["user:a@example.com",\n  "user:b@example.com"]\nempty = ""\n')
    attrs = tf.parse_tfvars_attributes(text)
    assert [a[0] for a in attrs] == ["subnet_cidr", "tags", "invokers", "empty"]
    assert attrs[1][1] == 'tags   = {\n  team = "a" # owner\n}'
    assert attrs[2][2] == '["user:a@example.com",\n  "user:b@example.com"]'
    assert attrs[3][2] == '""'
    assert tf.parse_tfvars_attributes("") == [] and tf.parse_tfvars_attributes("\n# only a comment\n") == []
    assert tf.parse_tfvars_attributes('x = "unterminated\n') is None
    assert tf.parse_tfvars_attributes('block "a" {\n  x = 1\n}\n') is None   # not a variable-values file


def test_merge_keeps_every_workload_key_and_platform_keys_win_only_for_their_facts(tf):
    workload = f'subnet_cidr = "{FACT}"\ntags = {{\n  team = "a"\n}}\nproject_id = "stale"\n'
    root = 'region = "europe-west1"\nextra = 1\n'
    merged = tf.merge_tfvars_texts([workload, root], {"project_id": '"p-1"', "region": '"us-central1"'})
    doc = hcl2.loads(merged)
    assert doc["subnet_cidr"] == FACT and doc["tags"] == {"team": "a"} and doc["extra"] == 1
    assert doc["project_id"] == "p-1" and doc["region"] == "us-central1"
    assert 'tags = {\n  team = "a"\n}\n' in merged                         # exact text kept, not re-serialized
    later = tf.merge_tfvars_texts(['a = 1\n', 'a = 2\n'], {})
    assert hcl2.loads(later) == {"a": 2}                                     # a later layer wins per key


def test_merge_drops_the_platform_secret_keys_from_every_layer(tf):
    workload = f'oauth_client_secret = "{FAKE_SECRET}"\nsubnet_cidr = "{FACT}"\n'
    root = f'firebase_api_key = "{FAKE_FB_KEY}"\n'
    merged = tf.merge_tfvars_texts([workload, root], {"project_id": '"p-1"'})
    assert FAKE_SECRET not in merged and FAKE_FB_KEY not in merged
    assert set(hcl2.loads(merged)) == {"subnet_cidr", "project_id"}


def test_merge_negative_valid_tfvars_without_overrides_keep_every_attribute_byte_identical(tf):
    """Do No Harm: no overrides and no secret keys -> every attribute's text is unchanged."""
    text = 'a = "x"\nb   = {\n  k = [1, 2]\n}\nc = true\n'
    merged = tf.merge_tfvars_texts([text], {})
    assert merged == text
    assert tf.merge_tfvars_texts(['x = "unterminated\n'], {"a": "1"}) is None


# ------------------------------------------------------------------------------------------------ FD-4BW units
ALIGNED = '''module "foundation" {
  source                = "../modules/workload-foundation/base"
  project_id            = var.project_id
}

module "api" {
  source       = "../modules/compute-cloudrun" # the API
  service_name = "api"
}

module "bundle" {
	source="../../bundles/web-stack"
}

module "nested" {
  source = "../bundles/data"
}
'''


def test_fmt_aligned_and_unspaced_module_sources_are_rewritten(tf):
    out = tf.rewrite_flattened_module_sources(ALIGNED, "infra/workload/main.tf")
    sources = {n: b["source"] for blk in hcl2.loads(out)["module"] for n, b in blk.items()}
    assert sources == {"foundation": "./infra/modules/workload-foundation/base",
                       "api": "./infra/modules/compute-cloudrun",
                       "bundle": "./infra/bundles/web-stack", "nested": "./infra/bundles/data"}
    # Every other byte is kept: undoing the four value changes gives back the input exactly.
    undone = (out.replace('"./infra/modules/workload-foundation/base"', '"../modules/workload-foundation/base"')
                 .replace('"./infra/modules/compute-cloudrun"', '"../modules/compute-cloudrun"')
                 .replace('"./infra/bundles/web-stack"', '"../../bundles/web-stack"')
                 .replace('"./infra/bundles/data"', '"../bundles/data"'))
    assert undone == ALIGNED


def test_negative_canonical_and_non_module_sources_are_byte_identical(tf):
    """Do No Harm: already-rewritten roots, remote sources, non-module `source` arguments, a nested object key
    named source, and a bare ../modules (no module path) are all left exactly as written."""
    text = '''module "a" {
  source = "./infra/modules/storage-bucket"
}
module "b" {
  source  = "terraform-google-modules/network/google"
  version = "~> 9.0"
}
module "c" {
  source = "git::https://example.com/m.git//x?ref=v1"
}
module "d" {
  source = "../modules"
}
module "e" {
  source = "../modules/${var.x}"
}
resource "google_storage_bucket_object" "o" {
  source = "../modules/notes.txt"
  meta   = { source = "../modules/q" }
}
'''
    assert tf.rewrite_flattened_module_sources(text, "main.tf") == text
    assert tf.rewrite_flattened_module_sources("", "main.tf") == ""


def test_unparseable_file_is_a_typed_stop_not_a_regex_rewrite(tf):
    """FD55-TFVARS: the previous regex fallback is gone; an unparseable flattened root file raises (the deploy turns
    it into APPLY.SOURCE_UNPARSEABLE)."""
    broken = 'module "a" {\n  source = "../modules/x"\n'          # missing closing brace
    with pytest.raises(tf.SourceUnparseableError):
        tf.rewrite_flattened_module_sources(broken, "main.tf")


# ------------------------------------------------------------------------------------------------ FD-4BD units
def _svc(tf, tmp_path):
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="", workspace_base_dir=str(tmp_path),
                              firestore_client=MagicMock())
    svc.db = None
    svc.state_bucket = ""
    return svc


def _rc(tmp_path):
    rc = tmp_path / "terraform.rc"
    rc.write_text("provider_installation {}\n", encoding="utf-8")
    return str(rc)


def test_registered_workspace_tofu_processes_get_tf_var_env_only_there(tf, monkeypatch, tmp_path):
    svc = _svc(tf, tmp_path / "base")
    monkeypatch.setattr(svc, "_ensure_binary", lambda *a, **k: "tofu")
    monkeypatch.setattr(svc, "_ensure_provider_mirror", lambda *a, **k: _rc(tmp_path))
    seen = []
    monkeypatch.setattr(tf.subprocess, "Popen", popen_from_run(lambda cmd, **kw: seen.append((cmd, kw["cwd"], kw["env"]))
                        or subprocess.CompletedProcess(cmd, 0, "", "")))
    ws = tmp_path / "base" / "t1" / "claims"
    (ws / "infra" / "workload").mkdir(parents=True)
    other = tmp_path / "base" / "t1" / "claims-2"
    other.mkdir()
    reg = svc._register_workspace_tf_vars(str(ws), {"oauth_client_secret": FAKE_SECRET, "firebase_api_key": ""})
    svc._run_subprocess(["tofu", "plan"], cwd=str(ws), iac_engine="OPENTOFU")
    svc._run_subprocess(["tofu", "validate"], cwd=str(ws / "infra" / "workload"), iac_engine="OPENTOFU")
    svc._run_subprocess(["tofu", "plan"], cwd=str(other), iac_engine="OPENTOFU")       # sibling prefix: not inside
    svc._run_subprocess(["tofu", "plan"], cwd=str(ws), env={"TF_VAR_oauth_client_secret": "explicit"},
                        iac_engine="OPENTOFU")
    envs = [e for _c, _d, e in seen]
    assert envs[0]["TF_VAR_oauth_client_secret"] == FAKE_SECRET and envs[0]["TF_VAR_firebase_api_key"] == ""
    assert envs[1]["TF_VAR_oauth_client_secret"] == FAKE_SECRET
    assert "TF_VAR_oauth_client_secret" not in envs[2] and "TF_VAR_firebase_api_key" not in envs[2]
    assert envs[3]["TF_VAR_oauth_client_secret"] == "explicit"
    svc._forget_workspace_tf_vars(*reg)
    svc._run_subprocess(["tofu", "plan"], cwd=str(ws), iac_engine="OPENTOFU")
    assert "TF_VAR_oauth_client_secret" not in seen[-1][2]
    assert all(FAKE_SECRET not in " ".join(c) for c, _d, _e in seen)   # never on a command line


def test_rt_f2_an_earlier_deploy_ending_never_removes_a_later_registration_of_the_same_workspace(tf, tmp_path):
    svc = _svc(tf, tmp_path / "base")
    ws = tmp_path / "base" / "t1" / "claims"
    ws.mkdir(parents=True)
    first = svc._register_workspace_tf_vars(str(ws), {"oauth_client_secret": "first"})
    second = svc._register_workspace_tf_vars(str(ws), {"oauth_client_secret": "second"})   # same (trace, product)
    svc._forget_workspace_tf_vars(*first)                                                   # the first deploy ends
    assert svc._workspace_tf_var_env(str(ws)) == {"TF_VAR_oauth_client_secret": "second"}
    svc._forget_workspace_tf_vars(*second)
    assert svc._workspace_tf_var_env(str(ws)) == {}
    svc._forget_workspace_tf_vars(*second)                                                  # idempotent
    assert svc._workspace_tf_var_env(str(ws)) == {}


# ------------------------------------------------------------------------------------------------ RT F1: compliance POST
def test_rt_f1_secret_names_parity_with_the_compliance_gate(tf):
    assert tuple(tf.compliance_gate.PLATFORM_SECRET_VARIABLE_NAMES) == tuple(tf.PLATFORM_SECRET_TFVARS)


def test_rt_f1_plan_copy_for_the_compliance_server_never_carries_the_platform_secrets(tf, monkeypatch):
    """`tofu show -json` keeps root variable values even for sensitive variables; the generated root declares
    both non-sensitive. The minimized plan (the POST body) must drop both exact names and keep every other variable."""
    cg = tf.compliance_gate
    plan = {
        "format_version": "1.2",
        "variables": {"oauth_client_secret": {"value": FAKE_SECRET}, "firebase_api_key": {"value": FAKE_FB_KEY},
                      "region": {"value": "us-central1"}, "project_id": {"value": "p-1"},
                      "db_password": {"value": "s3"}},
        "configuration": {"root_module": {"variables": {
            "oauth_client_secret": {"default": ""}, "firebase_api_key": {"default": ""},
            "region": {"default": "us-central1"}, "project_id": {}, "db_password": {"sensitive": True}}}},
        "resource_changes": [],
    }
    slim = cg.minimize_plan(plan)
    assert slim["variables"] == {"region": {"value": "us-central1"}, "project_id": {"value": "p-1"}}
    # The real body builder (gate_plan) with an injected transport: the serialized POST body holds neither value.
    sent = []

    def post(url, body, headers, timeout):
        sent.append(json.dumps(body))
        return 200, {"gate_contract_version": cg.GATE_CONTRACT_VERSION, "decision": "PASS", "violations": []}

    monkeypatch.setenv("COMPLIANCE_SERVER_URL", "http://compliance.invalid")
    monkeypatch.delenv("K_SERVICE", raising=False)
    monkeypatch.delenv("CLOUD_RUN_JOB", raising=False)
    db = MagicMock()
    db.collection.return_value.document.return_value.get.return_value = types.SimpleNamespace(
        exists=True, to_dict=lambda: {"compliance_profile": "STANDARD"})
    out = cg.gate_plan(db=db, product_id="claims", trace_id="t1", plan_json=plan,
                       client=cg.ComplianceGateClient(http_post=post, id_token_fetcher=lambda aud: "tok"))
    assert out["passed"] is True, out
    assert len(sent) == 1 and FAKE_SECRET not in sent[0] and FAKE_FB_KEY not in sent[0]
    assert '"region"' in sent[0]                                  # other root variables still reach the server


# ------------------------------------------------------------------------------------------------ deploy harness
class _StopAfterWorkspace(Exception):
    pass


def _no_gcp(monkeypatch):
    """deploy_workload imports Secret Manager / google.auth inline: fakes on the current package objects."""
    import google.auth
    import google.cloud

    def _no_client(*_a, **_k):
        raise RuntimeError("no Secret Manager in tests")

    def _no_adc(*_a, **_k):
        raise RuntimeError("no ADC in tests")

    fake_sm = types.ModuleType("google.cloud.secretmanager")
    fake_sm.SecretManagerServiceClient = _no_client
    monkeypatch.setitem(sys.modules, "google.cloud.secretmanager", fake_sm)
    monkeypatch.setattr(sys.modules["google.cloud"], "secretmanager", fake_sm, raising=False)
    monkeypatch.setattr(sys.modules["google.auth"], "default", _no_adc, raising=False)


def _deploy_workspace(tf, monkeypatch, base, files, product_id="expv"):
    """The REAL deploy_workload flatten + the REAL prepare_workspace on `files` (as the repo contents), then stop:
    no repo fetch, no Firestore, no Secret Manager / API-key calls, no container build, no tofu."""
    svc = _svc(tf, base)
    monkeypatch.setattr(svc, "_fetch_repo_files", lambda *a, **k: dict(files))
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    real_prepare = svc.prepare_workspace
    seen = {}

    def _prepare(pid, trace_id, hcl_files, iac_engine=None, region=None):   # no engine download: iac_engine not passed on
        seen["dir"] = real_prepare(pid, trace_id, hcl_files)
        raise _StopAfterWorkspace()

    monkeypatch.setattr(svc, "prepare_workspace", _prepare)
    _no_gcp(monkeypatch)
    with pytest.raises(_StopAfterWorkspace):
        svc.deploy_workload(product_id=product_id, trace_id="expv-trace", target_project_id="p-1",
                            branch="main", iac_engine="OPENTOFU")
    return Path(seen["dir"])


def _builtin_module_files(module_id):
    sys.path.insert(0, os.path.join(REPO_ROOT, "mcp-servers", "terraform"))
    from shared.builtin_modules_payload import BUILTIN_MODULE_FILES
    return BUILTIN_MODULE_FILES[module_id]


def _express_shaped_cloudsql_tree():
    """The Express output shape (shared/express_synthesizer.py, FD-CSQL): fmt-aligned module sources relative to
    infra/workload/, a required subnet_cidr variable and the IPAM fact in infra/workload/terraform.tfvars."""
    return {
        "infra/workload/main.tf": (
            'module "bucket" {\n'
            '  source             = "../modules/storage-bucket"\n'
            '  project_id         = var.project_id\n'
            '  bucket_name_suffix = "files"\n'
            '  region             = var.region\n'
            '}\n'
        ),
        "infra/workload/variables.tf": (
            'variable "project_id" {\n  type = string\n}\n\n'
            'variable "region" {\n  type    = string\n  default = "us-central1"\n}\n\n'
            'variable "subnet_cidr" {\n  type = string\n}\n'
        ),
        "infra/workload/terraform.tfvars": f'subnet_cidr = "{FACT}"\n',
    }


# ------------------------------------------------------------------------------------------------ FD-4BV / FD-4BW e2e
def test_deploy_workspace_keeps_the_ipam_subnet_fact(tf, monkeypatch, tmp_path):
    """Ported from express-outputs-fix @ 41d566b (tests/test_express_validate_end_to_end.py, strict xfail there)."""
    files = _express_shaped_cloudsql_tree()
    assert files["infra/workload/terraform.tfvars"] == f'subnet_cidr = "{FACT}"\n'
    ws = _deploy_workspace(tf, monkeypatch, tmp_path / "ws", files)
    root = hcl2.loads((ws / "terraform.tfvars").read_text(encoding="utf-8"))
    assert root["subnet_cidr"] == FACT
    assert root["project_id"] == "p-1" and root["product_id"] == "expv"
    assert "oauth_client_secret" not in root and "firebase_api_key" not in root
    # the workload's own file is written as it came
    assert (ws / "infra" / "workload" / "terraform.tfvars").read_text(encoding="utf-8") == f'subnet_cidr = "{FACT}"\n'


def test_deploy_flatten_rewrites_fmt_aligned_module_sources(tf, monkeypatch, tmp_path):
    files = _express_shaped_cloudsql_tree()
    ws = _deploy_workspace(tf, monkeypatch, tmp_path / "ws", files)
    main = (ws / "main.tf").read_text(encoding="utf-8")
    sources = [b["source"] for blk in hcl2.loads(main)["module"] for b in blk.values()]
    assert sources == ["./infra/modules/storage-bucket"]
    # prepare_workspace normalizes the file end; every other byte is the input with only the source value changed
    assert main.rstrip("\n") == files["infra/workload/main.tf"].replace(
        '"../modules/storage-bucket"', '"./infra/modules/storage-bucket"').rstrip("\n")


@pytest.fixture(scope="module")
def runner(tmp_path_factory):
    if not (os.access(PROD_TOFU, os.X_OK) and os.path.isdir(PROD_MIRROR)):
        pytest.skip("production column eval/.tools/tofu-1.9.0/tofu + eval/.tofu-mirror-prod (untracked) not present")
    from stackvend_eval.tofu_runner import TofuRunner
    r = TofuRunner(tmp_path_factory.mktemp("fd4bd-tofu"), Path(PROD_MIRROR), tofu_bin=PROD_TOFU)
    if not r.mirror_ready:
        pytest.skip(f"production mirror not verified: {r.mirror_manifest['status']}")
    return r


def test_fmt_aligned_root_inits_and_validates_in_the_deploy_workspace(runner, tf, monkeypatch, tmp_path):
    files = _express_shaped_cloudsql_tree()
    for fname, text in _builtin_module_files("storage-bucket").items():
        files[f"infra/modules/storage-bucket/{fname}"] = text
    ws = _deploy_workspace(tf, monkeypatch, tmp_path / "ws", files)
    trace_link = ws.parent / "modules"     # the per-trace ../modules link must not be what resolves the root
    if trace_link.is_symlink():
        trace_link.unlink()
    (ws / "backend.tf").unlink(missing_ok=True)
    r = runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=ws)
    assert r.returncode == 0, (r.stdout + r.stderr)[-3000:]
    r = runner._run(["validate", "-json", "-no-color"], cwd=ws)
    out = json.loads(r.stdout)
    assert r.returncode == 0 and out["valid"] is True, json.dumps(out)[-3000:]


# ------------------------------------------------------------------------------------------------ FD-4BD e2e
class _Resp:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body if body is not None else {}
        self.text = json.dumps(self._body)

    def json(self):
        return self._body


class _FakeHttpx:
    """CRM project number, one API key, its keyString (FAKE_FB_KEY); everything else 404."""

    def __init__(self, *a, **k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def get(self, url, headers=None, **_k):
        if url.startswith("https://cloudresourcemanager.googleapis.com/v1/projects/"):
            return _Resp(200, {"projectNumber": "123456"})
        if url.endswith("/locations/global/keys"):
            return _Resp(200, {"keys": [{"name": "projects/123456/locations/global/keys/k1"}]})
        if url.endswith("/keys/k1/keyString"):
            return _Resp(200, {"keyString": FAKE_FB_KEY})
        return _Resp(404, {})

    def post(self, url, headers=None, json=None, **_k):
        return _Resp(404, {})


class _FakeSession:
    """AQ-3: the web key is resolved through AuthorizedSession (project number, stackvend-web, its keyString)."""

    def __init__(self, *a, **k):
        pass

    def get(self, url="", *a, **k):
        if url.startswith("https://cloudresourcemanager.googleapis.com/v1/projects/"):
            return _Resp(200, {"projectNumber": "123456"})
        if url.endswith("/locations/global/keys/stackvend-web"):
            return _Resp(200, {"name": "projects/123456/locations/global/keys/stackvend-web", "restrictions": {
                "apiTargets": [{"service": "identitytoolkit.googleapis.com"},
                               {"service": "securetoken.googleapis.com"}]}})
        if url.endswith("/keys/stackvend-web/keyString"):
            return _Resp(200, {"keyString": FAKE_FB_KEY})
        return _Resp(200, {})

    def post(self, *a, **k):
        return _Resp(200, {})

    def patch(self, *a, **k):
        return _Resp(200, {})


def _fake_gcp_with_secrets(monkeypatch):
    import google.auth
    import google.auth.transport.requests as gatr
    import google.cloud
    import httpx

    class _Payload:
        def __init__(self, data):
            self.payload = types.SimpleNamespace(data=data.encode("utf-8"))

    class _SM:
        def __init__(self, *a, **k):
            pass

        def access_secret_version(self, name):
            if name.endswith("/secrets/castor-oauth-client-secret/versions/latest"):
                return _Payload(FAKE_SECRET)
            if name.endswith("/secrets/castor-oauth-client-id/versions/latest"):
                return _Payload(FAKE_CLIENT_ID)
            raise RuntimeError("unknown secret")

    creds = types.SimpleNamespace(valid=True, token="tok", refresh=lambda *_a: None)
    fake_sm = types.ModuleType("google.cloud.secretmanager")
    fake_sm.SecretManagerServiceClient = _SM
    monkeypatch.setitem(sys.modules, "google.cloud.secretmanager", fake_sm)
    monkeypatch.setattr(sys.modules["google.cloud"], "secretmanager", fake_sm, raising=False)
    monkeypatch.setattr(sys.modules["google.auth"], "default", lambda *a, **k: (creds, "p-1"), raising=False)
    monkeypatch.setattr(gatr, "AuthorizedSession", _FakeSession, raising=False)
    monkeypatch.setattr(httpx, "Client", _FakeHttpx)


DEPLOY_TREE = {
    "infra/workload/main.tf": (
        'module "bucket" {\n'
        '  source             = "../modules/storage-bucket"\n'
        '  project_id         = var.project_id\n'
        '  bucket_name_suffix = "files"\n'
        '  region             = var.region\n'
        '}\n'
        'module "compute_api" {\n'
        '  source          = "../modules/compute-cloudrun"\n'
        '  project_id      = var.project_id\n'
        '  service_name    = "api"\n'
        '  container_image = var.container_image\n'
        '}\n'
        'locals {\n  secret_len = length(var.oauth_client_secret)\n  key_len = length(var.firebase_api_key)\n}\n'
    ),
    "infra/workload/variables.tf": (
        'variable "project_id" {\n  type = string\n}\n\n'
        'variable "region" {\n  type    = string\n  default = "us-central1"\n}\n\n'
        'variable "container_image" {\n  type    = string\n  default = ""\n}\n\n'
        'variable "subnet_cidr" {\n  type = string\n}\n\n'
        'variable "oauth_client_secret" {\n  type = string\n}\n\n'      # no default: the reconciler must not fill it
        'variable "firebase_api_key" {\n  type = string\n}\n'
    ),
    # a workload file that (wrongly) carries placeholders for the platform secrets: they must not override the env
    "infra/workload/terraform.tfvars": (
        f'subnet_cidr = "{FACT}"\noauth_client_secret = ""\nlabels = {{\n  team = "claims"\n}}\n'
    ),
    "apps/api/main.py": "print('hello')\n",
    "apps/api/requirements.txt": "fastapi\n",
}


def _full_deploy(tf, monkeypatch, tmp_path, tree, auth_calls=None):
    """The REAL deploy_workload end to end with fakes for Secret Manager / API keys / REST, the REAL _run_subprocess
    and a fake engine process (records argv + env, snapshots every workspace file at plan/apply time). `auth_calls`
    (FD4BD-Q3): a list that receives the keyword arguments of every google.auth.default() call."""
    svc = _svc(tf, tmp_path / "base")
    # AQ-2: a PUBLIC_APP access record, so the deploy resolves the child's web key (a private one gets none)
    workload_doc = types.SimpleNamespace(exists=True, to_dict=lambda: {
        "project_id": "p-1", "access": {   # FD-4DT: every deploy validates the record, so it is a complete one
            "mode": "PUBLIC_APP", "invoker_principals": [], "app_admin_emails": [],
            "public_api_routes": ["GET /api/config"],
            "sign_in": {"google": "BYO", "email_password": False, "additional_authorized_domains": []},
            "tenant_isolation_required": False, "source": "intake"}})
    svc.db = MagicMock(name="firestore")
    svc.db.collection.return_value.document.return_value.get.return_value = workload_doc
    files = dict(tree)
    for fname, text in _builtin_module_files("storage-bucket").items():
        files[f"infra/modules/storage-bucket/{fname}"] = text
    monkeypatch.setattr(svc, "_fetch_repo_files", lambda *a, **k: dict(files))
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    monkeypatch.setattr(svc, "_ensure_binary", lambda *a, **k: "tofu")
    monkeypatch.setattr(svc, "_ensure_provider_mirror", lambda *a, **k: _rc(tmp_path))
    monkeypatch.setattr(svc, "_compliance_gate_check", lambda *a, **k: {"passed": True, "evidence": {}})
    monkeypatch.setattr(svc, "_sync_feature_requests", lambda **k: None)
    # Cloud Run readiness polling (REST, out of scope here): ready at once
    monkeypatch.setattr(svc, "_rollout_cloud_run_revision", lambda *a, **k: (True, "api-00001", "https://api.example"))
    _fake_gcp_with_secrets(monkeypatch)
    if auth_calls is not None:
        fake_default = sys.modules["google.auth"].default
        monkeypatch.setattr(sys.modules["google.auth"], "default",
                            lambda *a, **k: auth_calls.append(dict(k)) or fake_default(*a, **k), raising=False)

    tarballs = []

    def _build(product_id, target_project_id, workspace_dir, image_tag, ar_repo_name=None, region=None):
        # the exact packaging step of _build_and_push_container (allow-list -> tar.gz members)
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as tar:
            for rel in tf.select_build_source_files(workspace_dir, ["api"]):
                tar.add(os.path.join(workspace_dir, rel), arcname=rel, recursive=False)
        tarballs.append(stream.getvalue())
        return True

    monkeypatch.setattr(svc, "_build_and_push_container", _build)

    calls, snapshots = [], []

    def _run(cmd, cwd=None, env=None, **kw):
        calls.append((list(cmd), cwd, dict(env or {})))
        sub = cmd[1] if len(cmd) > 1 else ""
        if sub in ("plan", "apply"):     # every workspace file at plan/apply time
            snap = {}
            for root, _dirs, fnames in os.walk(cwd):
                for fn in fnames:
                    full = os.path.join(root, fn)
                    if os.path.isfile(full) and not os.path.islink(full):
                        snap[os.path.relpath(full, cwd)] = Path(full).read_bytes()
            snapshots.append(snap)
        if sub == "show":
            return subprocess.CompletedProcess(cmd, 0, json.dumps({"format_version": "1.2", "configuration": {"root_module": {}},
                                                                 "resource_changes": []}), "")
        if sub == "output":
            return subprocess.CompletedProcess(cmd, 0, "{}", "")
        return subprocess.CompletedProcess(cmd, 0, "Apply complete! Resources: 0 added, 0 changed, 0 destroyed.", "")

    monkeypatch.setattr(tf.subprocess, "Popen", popen_from_run(_run))

    res = svc.deploy_workload(product_id="claims", trace_id="t-fd4bd", target_project_id="p-1",
                              branch="main", iac_engine="OPENTOFU")
    return svc, res, calls, snapshots, tarballs


def test_full_deploy_secrets_never_in_a_file_and_every_tofu_run_gets_them(tf, monkeypatch, tmp_path):
    svc, res, calls, snapshots, tarballs = _full_deploy(tf, monkeypatch, tmp_path, DEPLOY_TREE)
    assert res.get("status") == "SUCCESS", res

    tofu_runs = [(c, d, e) for c, d, e in calls if len(c) > 1 and c[1] in ("init", "validate", "plan", "apply")]
    assert {c[1] for c, _d, _e in tofu_runs} >= {"init", "plan", "apply"}
    for cmd, _cwd, env in tofu_runs:
        assert env.get("TF_VAR_oauth_client_secret") == "", cmd    # AQ-1: never read; explicitly empty
        assert env.get("TF_VAR_firebase_api_key") == FAKE_FB_KEY, cmd
        assert FAKE_SECRET not in " ".join(cmd) and FAKE_FB_KEY not in " ".join(cmd)

    # No workspace file ever holds either value; the root tfvars has no secret key that would override the env.
    assert snapshots
    for snap in snapshots:
        for rel, data in snap.items():
            assert FAKE_SECRET.encode() not in data, rel
            assert FAKE_FB_KEY.encode() not in data, rel
        root_tfvars = hcl2.loads(snap["terraform.tfvars"].decode("utf-8"))
        assert "oauth_client_secret" not in root_tfvars and "firebase_api_key" not in root_tfvars
        assert root_tfvars["subnet_cidr"] == FACT and root_tfvars["labels"] == {"team": "claims"}   # FD-4BV
        assert root_tfvars["oauth_client_id"] == "" and root_tfvars["project_id"] == "p-1"   # AQ-1: never read

    # The Cloud Build source tarball: no tfvars member, no secret bytes.
    assert len(tarballs) == 1
    with tarfile.open(fileobj=io.BytesIO(tarballs[0]), mode="r:gz") as tar:
        members = tar.getnames()
        blobs = [tar.extractfile(m).read() for m in tar.getmembers() if m.isfile()]
    assert members and all(m.startswith("apps/api/") for m in members), members
    assert not [m for m in members if m.endswith((".tfvars", ".tfvars.json", ".tf"))]
    assert all(FAKE_SECRET.encode() not in b and FAKE_FB_KEY.encode() not in b for b in blobs)

    # The secrets left memory with the deploy.
    assert svc._workspace_tf_var_env(os.path.join(str(tmp_path / "base"), "t-fd4bd", "claims")) == {}


INLINER_TREE = dict(DEPLOY_TREE)
INLINER_TREE["infra/workload/main.tf"] = DEPLOY_TREE["infra/workload/main.tf"] + (
    'resource "google_cloud_run_v2_service" "web" {\n'
    '  name     = "web"\n'
    '  location = var.region\n'
    '  template {\n'
    '    containers {\n'
    '      image = "us-docker.pkg.dev/cloudrun/container/hello"\n'
    '      env {\n'
    '        name  = "FIREBASE_API_KEY"\n'
    '        value = var.firebase_api_key\n'
    '      }\n'
    '    }\n'
    '  }\n'
    '}\n'
)


def test_rt_f4_firebase_key_never_pasted_into_main_tf(tf, monkeypatch, tmp_path):
    """RT F4 / R2, fixed by FD55-W3 (A54 deleted): the FIREBASE_API_KEY inliner is gone; `value =
    var.firebase_api_key` stays a variable reference and the key reaches tofu only as TF_VAR_firebase_api_key."""
    _svc_, res, _calls, snapshots, _tarballs = _full_deploy(tf, monkeypatch, tmp_path, INLINER_TREE)
    assert snapshots, res
    assert b"FIREBASE_API_KEY" in snapshots[0]["main.tf"]                     # the tree reached the deploy
    for snap in snapshots:
        assert b"value = var.firebase_api_key" in snap["main.tf"]             # still a variable reference
        for rel, data in snap.items():
            assert FAKE_SECRET.encode() not in data, rel                       # the OAuth secret: never
            assert FAKE_FB_KEY.encode() not in data, rel                       # the browser key: never in a file


def test_fd4bd_q3_full_deploy_bills_the_child_per_workspace_and_never_writes_the_process_env(tf, monkeypatch, tmp_path):
    """FD4BD-Q3: every tofu run of the deploy bills the child in its own env, every child REST call passes the child as
    its quota project, and the process environment is the same after the deploy as before (it used to keep the
    child's GOOGLE_BILLING_PROJECT / GOOGLE_CLOUD_QUOTA_PROJECT / GOOGLE_USER_PROJECT_OVERRIDE)."""
    for name in ("GOOGLE_BILLING_PROJECT", "GOOGLE_CLOUD_QUOTA_PROJECT", "GOOGLE_USER_PROJECT_OVERRIDE"):
        monkeypatch.delenv(name, raising=False)
    before = dict(os.environ)
    auth_calls = []
    svc, res, calls, _snapshots, _tarballs = _full_deploy(tf, monkeypatch, tmp_path, DEPLOY_TREE, auth_calls)
    assert res.get("status") == "SUCCESS", res
    assert dict(os.environ) == before
    tofu_runs = [(c, e) for c, _d, e in calls if len(c) > 1 and c[1] in ("init", "validate", "plan", "apply", "output")]
    assert tofu_runs
    for cmd, env in tofu_runs:
        assert (env.get("GOOGLE_BILLING_PROJECT"), env.get("GOOGLE_CLOUD_QUOTA_PROJECT"),
                env.get("GOOGLE_USER_PROJECT_OVERRIDE")) == ("p-1", "p-1", "true"), cmd
    assert auth_calls and all(k.get("quota_project_id") == "p-1" for k in auth_calls), auth_calls
    assert svc._workspace_billing_project(os.path.join(str(tmp_path / "base"), "t-fd4bd", "claims")) is None
