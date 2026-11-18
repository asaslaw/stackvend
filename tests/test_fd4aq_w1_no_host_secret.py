"""FD-4AQ W1 (register AQ-1, AQ-2): no host Google sign-in value reaches OpenTofu; sign-in artifacts only for
PUBLIC_APP workloads (mcp-servers/terraform/service.py deploy_workload).

- AQ-1: a deploy never reads `castor-oauth-client-id` / `castor-oauth-client-secret`; TF_VAR_oauth_client_secret is
  registered with an explicit "" (a legacy root declaring the variable without a default still plans); the pre-apply
  reconciler never writes a value for a platform secret variable (exact name), whatever its value (FD-55 W6c deleted
  the reconciler; the pin stays as a regression guard).
- AQ-2: the workload's access record decides: PUBLIC_APP -> web key + Identity Platform init + authorized domains;
  PRIVATE_IAP / PRIVATE_IAM / no record / unreadable record / Firestore error -> zero apikeys and zero
  identitytoolkit calls, the values "" and one TENANT_SIGNIN_ARTIFACTS_SKIPPED log naming the mode. FD-4DT: an
  invalid record or an unreadable workload document now stops the deploy first (ACCESS_POLICY_INVALID /
  ACCESS_POLICY_UNAVAILABLE), still with zero sign-in calls.
- The DevOps prompt no longer points the AI at the host secret (all builtin_prompts.py copies).
- FD-55 W6c (register FD55-W6c): IaC with an IdP block whose apply fails CONFIGURATION_NOT_FOUND gets initializeAuth
  and one retry (REST, no file written), then the error returns; the regex bypass of the block in main.tf and its
  second retry are deleted (any access mode).

Hermetic: no repo fetch, no Secret Manager, no ADC, no network. The real-engine test runs only when a tofu binary is
on PATH or named by STACKVEND_PINNED_TOFU (built-in provider only, no backend, no network).
"""
import hermetic_guard  # noqa: F401  (first import)

import logging
import os
import shutil
import subprocess
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
PNUM = "123456"
FAKE_SECRET = "GOCSPX-fd4aq-test-only-not-a-secret-00"   # test value, never a real credential
FAKE_CLIENT_ID = "1234-fd4aq.apps.googleusercontent.com"   # test value
FAKE_KEY = "AIzaSy-fd4aq-test-only-browser-key-0000"       # test value, never a real key

MAIN = (
    'module "compute" {\n'
    '  source          = "../modules/compute-cloudrun"\n'
    '  project_id      = var.project_id\n'
    '  service_name    = "shop"\n'
    '  container_image = var.container_image\n'
    '}\n'
    'locals {\n  secret_len = length(var.oauth_client_secret)\n  key_len = length(var.firebase_api_key)\n}\n'
)
VARIABLES = (
    'variable "project_id" {\n  type = string\n}\n\n'
    'variable "container_image" {\n  type    = string\n  default = ""\n}\n\n'
    'variable "oauth_client_secret" {\n  type = string\n}\n\n'      # no default: the legacy root of the plan (W1 2.)
    'variable "firebase_api_key" {\n  type = string\n}\n'
)
TREE = {W + "main.tf": MAIN, W + "variables.tf": VARIABLES,
        "apps/shop/main.py": "app = None\n", "apps/shop/requirements.txt": "fastapi\n"}


@pytest.fixture
def tf(monkeypatch):
    return load_tf_service(monkeypatch)


class _Stop(BaseException):
    pass


class _Resp:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body if body is not None else {}
        self.text = str(self._body)

    def json(self):
        return self._body


class _Cloud:
    """Records every Secret Manager name and every REST call (httpx.Client and AuthorizedSession)."""

    def __init__(self):
        self.secret_names = []
        self.calls = []

    def respond(self, method, url, body=None):
        self.calls.append((method, url, body))
        if url.startswith("https://cloudresourcemanager.googleapis.com/"):
            return _Resp(200, {"projectNumber": PNUM})
        if url.endswith("/keyString"):
            return _Resp(200, {"keyString": FAKE_KEY})
        if url.endswith("/locations/global/keys") and method == "GET":
            return _Resp(200, {"keys": [{"name": f"projects/{PNUM}/locations/global/keys/k1"}]})
        if "/locations/global/keys/" in url and method == "GET":
            return _Resp(200, {"name": url.split("apikeys.googleapis.com/v2/", 1)[-1].split("?")[0],
                               "restrictions": {"apiTargets": [{"service": "identitytoolkit.googleapis.com"},
                                                               {"service": "securetoken.googleapis.com"}]}})
        return _Resp(200, {})

    def hosts(self, host):
        return [c for c in self.calls if c[1].startswith(f"https://{host}/")]


def _fake_cloud(monkeypatch, cloud):
    import google.auth
    import google.auth.transport.requests as gatr
    import google.cloud
    import httpx

    class _SM:
        def __init__(self, *a, **k):
            pass

        def access_secret_version(self, name):
            cloud.secret_names.append(name)
            if name.endswith("/castor-oauth-client-secret/versions/latest"):
                return types.SimpleNamespace(payload=types.SimpleNamespace(data=FAKE_SECRET.encode()))
            if name.endswith("/castor-oauth-client-id/versions/latest"):
                return types.SimpleNamespace(payload=types.SimpleNamespace(data=FAKE_CLIENT_ID.encode()))
            raise RuntimeError("unknown secret")

    class _Http:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def get(self, url, **k):
            return cloud.respond("GET", url)

        def post(self, url, json=None, **k):
            return cloud.respond("POST", url, json)

        def patch(self, url, json=None, **k):
            return cloud.respond("PATCH", url, json)

    class _Session(_Http):
        def request(self, method, url, json=None, **k):
            return cloud.respond(method.upper(), url, json)

    creds = types.SimpleNamespace(valid=True, token="tok", refresh=lambda *_a: None)
    fake_sm = types.ModuleType("google.cloud.secretmanager")
    fake_sm.SecretManagerServiceClient = _SM
    monkeypatch.setitem(sys.modules, "google.cloud.secretmanager", fake_sm)
    monkeypatch.setattr(sys.modules["google.cloud"], "secretmanager", fake_sm, raising=False)
    monkeypatch.setattr(sys.modules["google.auth"], "default", lambda *a, **k: (creds, "p"), raising=False)
    monkeypatch.setattr(gatr, "AuthorizedSession", _Session, raising=False)
    monkeypatch.setattr(httpx, "Client", _Http)


class _Doc:
    def __init__(self, data):
        self.exists = data is not None
        self._data = data

    def to_dict(self):
        return dict(self._data or {})


def _db(record=None, error=None):
    db = MagicMock(name="firestore")
    getter = db.collection.return_value.document.return_value.get
    if error is not None:
        getter.side_effect = error
    else:
        getter.return_value = _Doc(record)
    return db


def _service(tf, monkeypatch, tmp_path, db, tree=TREE):
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="",
                              workspace_base_dir=str(tmp_path / "base"), firestore_client=MagicMock())
    svc.db = db
    svc.state_bucket = ""
    monkeypatch.setenv("GITHUB_ORG", "acme-test")
    monkeypatch.setattr(svc, "_fetch_repo_files", lambda *a, **k: dict(tree))
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    monkeypatch.setattr(svc, "_ensure_binary", lambda *a, **k: "tofu")
    monkeypatch.setattr(svc, "_build_and_push_container", lambda *a, **k: True)
    monkeypatch.setattr(svc, "_sync_feature_requests", lambda **k: None)
    monkeypatch.setattr(tf, "VCSProviderFactory", MagicMock(name="VCSProviderFactory"))
    return svc


def _deploy_to_tofu(tf, monkeypatch, tmp_path, db, tree=TREE):
    """The REAL deploy_workload up to the first tofu call: (workspace dir, TF_VAR env there, cloud recorder)."""
    cloud = _Cloud()
    _fake_cloud(monkeypatch, cloud)
    svc = _service(tf, monkeypatch, tmp_path, db, tree)
    seen = {}

    def _tofu(cmd, cwd=None, **kw):
        seen["ws"] = cwd
        seen["env"] = svc._workspace_tf_var_env(cwd)
        raise _Stop()

    monkeypatch.setattr(svc, "_run_subprocess", _tofu)
    with pytest.raises(_Stop):
        svc.deploy_workload(product_id="shop", trace_id="t-aq", target_project_id=PROJECT, branch="main",
                            iac_engine="OPENTOFU")
    return seen["ws"], seen["env"], cloud


def _tfvars(ws):
    with open(os.path.join(ws, "terraform.tfvars"), encoding="utf-8") as fh:
        return fh.read()


# FD-4DT: every deploy validates the current access record (render_deploy_access_vars), so the records are complete
_SIGN_IN_OFF = {"google": "DISABLED", "email_password": False, "additional_authorized_domains": []}


def _private(mode, members=("user:a@x.io",)):
    return {"mode": mode, "invoker_principals": list(members), "app_admin_emails": [], "public_api_routes": [],
            "sign_in": dict(_SIGN_IN_OFF), "tenant_isolation_required": None, "source": "intake"}


PUBLIC = {"project_id": PROJECT, "access": {
    "mode": "PUBLIC_APP", "invoker_principals": [], "app_admin_emails": [], "public_api_routes": ["GET /api/config"],
    "sign_in": {"google": "BYO", "email_password": False, "additional_authorized_domains": []},
    "tenant_isolation_required": False, "source": "intake"}}


# ------------------------------------------------------------------------------------------------ AQ-1
@pytest.mark.parametrize("record", [PUBLIC, {"project_id": PROJECT, "access": _private("PRIVATE_IAP")}],
                         ids=["public", "private"])
def test_host_oauth_values_are_never_read_and_the_secret_var_is_explicitly_empty(tf, monkeypatch, tmp_path, record):
    ws, env, cloud = _deploy_to_tofu(tf, monkeypatch, tmp_path, _db(record))
    assert not [n for n in cloud.secret_names if "castor-oauth-client" in n]   # neither the id nor the secret
    assert env["TF_VAR_oauth_client_secret"] == ""                              # present, explicitly empty
    tfvars = _tfvars(ws)
    parsed = hcl2.loads(tfvars)
    assert parsed["oauth_client_id"] == ""
    assert "oauth_client_secret" not in parsed and "firebase_api_key" not in parsed   # the reconciler's negative
    assert FAKE_SECRET not in tfvars and FAKE_CLIENT_ID not in tfvars


def test_reconciler_never_writes_a_platform_secret_variable(tf, monkeypatch, tmp_path):
    """A legacy root declaring `oauth_client_secret` / `firebase_api_key` without a default, with no value anywhere:
    before, the empty secret let the reconciler write a generated placeholder into terraform.tfvars, which beats
    TF_VAR and would become the IdP secret."""
    ws, env, _cloud = _deploy_to_tofu(tf, monkeypatch, tmp_path, _db({"project_id": PROJECT}))
    parsed = hcl2.loads(_tfvars(ws))
    assert "oauth_client_secret" not in parsed and "firebase_api_key" not in parsed
    assert env == {"TF_VAR_oauth_client_secret": "", "TF_VAR_firebase_api_key": ""}


# ------------------------------------------------------------------------------------------------ AQ-2
PRIVATE_CASES = {
    "private-iap": _db({"project_id": PROJECT, "access": _private("PRIVATE_IAP")}),
    "private-iam": _db({"project_id": PROJECT, "access": _private("PRIVATE_IAM")}),
    "no-record": _db({"project_id": PROJECT}),
    "no-workload-doc": _db(None),
    "no-firestore": None,
}
# FD-4DT: a record that does not validate, or a workload document that cannot be read, now stops the deploy before
# anything runs (typed), so these never reach the sign-in step (zero apikeys / identitytoolkit calls either way).
REFUSED_CASES = {
    "unreadable-mode": (_db({"project_id": PROJECT, "access": {"mode": "public_app"}}), "ACCESS_POLICY_INVALID"),
    "unreadable-shape": (_db({"project_id": PROJECT, "access": "PUBLIC_APP"}), "ACCESS_POLICY_INVALID"),
    "firestore-error": (_db(error=RuntimeError("firestore down")), "ACCESS_POLICY_UNAVAILABLE"),
}


@pytest.mark.parametrize("case", sorted(PRIVATE_CASES))
def test_non_public_workloads_get_no_sign_in_artifacts(tf, monkeypatch, tmp_path, caplog, case):
    caplog.set_level(logging.INFO, logger="mcp-terraform-server")
    ws, env, cloud = _deploy_to_tofu(tf, monkeypatch, tmp_path, PRIVATE_CASES[case])
    assert cloud.hosts("apikeys.googleapis.com") == []
    assert cloud.hosts("identitytoolkit.googleapis.com") == []
    assert env["TF_VAR_firebase_api_key"] == ""
    parsed = hcl2.loads(_tfvars(ws))
    assert parsed["firebase_auth_domain"] == "" and parsed["oauth_client_id"] == ""
    skipped = [r.getMessage() for r in caplog.records if "TENANT_SIGNIN_ARTIFACTS_SKIPPED" in r.getMessage()]
    assert len(skipped) == 1, skipped
    expected = {"private-iap": "PRIVATE_IAP", "private-iam": "PRIVATE_IAM",
                "no-firestore": "UNREADABLE (no Firestore client)",
                "no-record": "MISSING (no access record)", "no-workload-doc": "MISSING (no workload record)",
                }[case]
    assert expected in skipped[0], skipped[0]


@pytest.mark.parametrize("case", sorted(REFUSED_CASES))
def test_unreadable_access_stops_the_deploy_before_any_sign_in_step(tf, monkeypatch, tmp_path, case):
    db, error_class = REFUSED_CASES[case]
    cloud = _Cloud()
    _fake_cloud(monkeypatch, cloud)
    svc = _service(tf, monkeypatch, tmp_path, db)
    monkeypatch.setattr(svc, "_run_subprocess", lambda *a, **k: (_ for _ in ()).throw(_Stop()))
    res = svc.deploy_workload(product_id="shop", trace_id="t-aq", target_project_id=PROJECT, branch="main",
                              iac_engine="OPENTOFU")
    assert res["status"] == "FAILED" and res["error_class"] == error_class
    assert cloud.hosts("apikeys.googleapis.com") == [] and cloud.hosts("identitytoolkit.googleapis.com") == []


def test_public_workload_gets_its_web_key_and_identity_platform_init(tf, monkeypatch, tmp_path, caplog):
    caplog.set_level(logging.DEBUG, logger="mcp-terraform-server")
    ws, env, cloud = _deploy_to_tofu(tf, monkeypatch, tmp_path, _db(PUBLIC))
    assert env["TF_VAR_firebase_api_key"] == FAKE_KEY
    assert [c for c in cloud.hosts("identitytoolkit.googleapis.com") if c[1].endswith(":initializeAuth")]
    parsed = hcl2.loads(_tfvars(ws))
    assert parsed["firebase_auth_domain"] == f"{PROJECT}.firebaseapp.com"
    assert not any("TENANT_SIGNIN_ARTIFACTS_SKIPPED" in r.getMessage() for r in caplog.records)
    for r in caplog.records:                                    # no value in any log line
        msg = r.getMessage()
        assert FAKE_KEY not in msg and FAKE_SECRET not in msg and FAKE_CLIENT_ID not in msg
    assert FAKE_KEY not in _tfvars(ws)                         # FD-4BD: the key travels as TF_VAR only


def test_access_modes_match_the_shared_enum():
    """The terraform MCP's exact mode list (AQ-2) must equal the enum (FD-4DT: its image now also carries a replica of
    shared/access_policy.py, for the deploy-time access variables)."""
    from shared.access_policy import AccessMode
    tf_dir = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
    src = open(os.path.join(tf_dir, "service.py"), encoding="utf-8").read()
    assert 'ACCESS_MODES = ("PUBLIC_APP", "PRIVATE_IAM", "PRIVATE_IAP")' in src
    assert {"PUBLIC_APP", "PRIVATE_IAM", "PRIVATE_IAP"} == {m.value for m in AccessMode}
    assert 'TENANT_SIGNIN_ACCESS_MODE = "PUBLIC_APP"' in src and AccessMode.PUBLIC_APP.value == "PUBLIC_APP"


def test_workload_access_mode_is_exact(tf):
    assert tf.workload_access_mode({"mode": "PUBLIC_APP"}) == "PUBLIC_APP"
    assert tf.workload_access_mode({"mode": "PRIVATE_IAM"}) == "PRIVATE_IAM"
    for bad in (None, "PUBLIC_APP", {"mode": " PUBLIC_APP"}, {"mode": "public_app"}, {"mode": None}, {}, []):
        assert tf.workload_access_mode(bad) is None, bad


# ------------------------------------------------------------------------------------------------ prompt
PROMPT_COPIES = ("shared/builtin_prompts.py", "apps/control-center/shared/builtin_prompts.py",
                 "apps/orchestrator-gateway/shared/builtin_prompts.py", "mcp-servers/terraform/shared/builtin_prompts.py")


def test_no_prompt_points_the_ai_at_the_host_sign_in_secret():
    for rel in PROMPT_COPIES:
        text = open(os.path.join(REPO_ROOT, rel), encoding="utf-8").read()
        assert "castor-oauth-client" not in text, rel
        assert "* **Workload Authentication**" not in text, rel


# ------------------------------------------------------------------------------------------------ FD-55 W6c (A49)
IDP_MAIN = MAIN + (
    'resource "google_identity_platform_default_supported_idp_config" "google_idp" {\n'
    '  enabled       = true\n'
    '  idp_id        = "google.com"\n'
    '  client_id     = "x"\n'
    '  client_secret = var.oauth_client_secret\n'
    '  lifecycle {\n'
    '    ignore_changes = [client_id]\n'
    '  }\n'
    '}\n'
)


def test_w6c_idp_apply_error_keeps_init_retry_without_bypass(tf, monkeypatch, tmp_path):
    """FD-55 W6c (A49 DELETED; was test_pin_w6c_idp_apply_error_keeps_init_retry_and_bypass): CONFIGURATION_NOT_FOUND
    on the IdP block -> initializeAuth (even for a private workload: this path is the IaC's, not AQ-2's; AQ-4 refuses
    a sign-in resource in a private workload's IaC) and ONE retry. The block is no longer regex-deleted from main.tf
    and re-applied: main.tf is byte-identical and the engine's error returns as FAILED."""
    cloud = _Cloud()
    _fake_cloud(monkeypatch, cloud)
    tree = dict(TREE, **{W + "main.tf": IDP_MAIN})
    svc = _service(tf, monkeypatch, tmp_path, _db({"project_id": PROJECT, "access": _private("PRIVATE_IAP")}), tree)
    monkeypatch.setattr(svc, "_run_subprocess",
                        lambda *a, **k: {"success": True, "exit_code": 0, "stdout": "", "stderr": ""})
    idp_err = {"success": False, "exit_code": 1, "stdout": "",
               "stderr": "Error: CONFIGURATION_NOT_FOUND on google_identity_platform_default_supported_idp_config"}
    seen = {}

    def _gated(product_id, trace_id, workspace_dir, *a, **k):
        seen.setdefault("n", 0)
        seen["n"] += 1
        seen["ws"] = workspace_dir
        with open(os.path.join(workspace_dir, "main.tf"), encoding="utf-8") as fh:
            seen.setdefault("main_at_first_apply", fh.read())
        if seen["n"] <= 2:
            return idp_err
        raise _Stop()   # a third apply (the deleted bypass retry) fails the test

    monkeypatch.setattr(svc, "_compliance_gated_apply", _gated)
    res = svc.deploy_workload(product_id="shop", trace_id="t-aq", target_project_id=PROJECT, branch="main",
                              iac_engine="OPENTOFU")
    assert seen["n"] == 2                                            # first apply + the retry after initializeAuth
    assert [c for c in cloud.hosts("identitytoolkit.googleapis.com") if c[1].endswith(":initializeAuth")]
    with open(os.path.join(seen["ws"], "main.tf"), encoding="utf-8") as fh:
        main_after = fh.read()
    assert main_after == seen["main_at_first_apply"]                 # byte-identical: no bypass
    assert "google_identity_platform_default_supported_idp_config" in main_after
    assert res["status"] == "FAILED" and "CONFIGURATION_NOT_FOUND" in res["error"]


# ------------------------------------------------------------------------------------------------ real engine
def _tofu_bin():
    pinned = os.environ.get("STACKVEND_PINNED_TOFU", "")
    if pinned and os.access(pinned, os.X_OK):
        return pinned
    return shutil.which("tofu")


def test_real_engine_legacy_root_plans_with_the_empty_secret(tf, monkeypatch, tmp_path):
    """OpenTofu itself (built-in provider only, no backend, no network): a root declaring `oauth_client_secret` and
    `firebase_api_key` without defaults plans with the deploy's terraform.tfvars and TF_VAR env (empty values)."""
    tofu = _tofu_bin()
    if not tofu:
        pytest.skip("needs tofu on PATH or STACKVEND_PINNED_TOFU")
    ws, env_vars, _cloud = _deploy_to_tofu(tf, monkeypatch, tmp_path, _db({"project_id": PROJECT}))
    root = tmp_path / "engine"
    root.mkdir()
    (root / "variables.tf").write_text(VARIABLES + "".join(
        f'variable "{k}" {{\n  type    = any\n  default = null\n}}\n'
        for k in hcl2.loads(_tfvars(ws)) if k not in ("project_id", "container_image")))
    (root / "main.tf").write_text('resource "terraform_data" "x" {\n  input = [length(var.oauth_client_secret), '
                                  'length(var.firebase_api_key)]\n}\n')
    (root / "terraform.tfvars").write_text(_tfvars(ws))
    env = dict(os.environ, TF_IN_AUTOMATION="1", CHECKPOINT_DISABLE="1", TF_INPUT="0", **env_vars)
    for args in (["init", "-backend=false", "-no-color"], ["plan", "-no-color", "-input=false"]):
        r = subprocess.run([tofu, *args], cwd=root, capture_output=True, text=True, env=env, timeout=120)
        assert r.returncode == 0, r.stderr
