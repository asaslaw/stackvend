"""FD-7L Phase 2a (SAT-27) in the terraform service and tf-applier: the tofu environment allow-list with a fresh HOME
(both modes), brokered deployer credentials per workspace (Per-workload installs only), the typed refusals, the job
that reads only RUNNER_NONCE, the signed-provenance target check, the mode log line and the `ast` guard.

Do No Harm (Shared installs: STACKVEND_TF_RUNNER_IDENTITY unset or PLATFORM): tofu gets the same effective Google
identity as before (no credential variable, no ADC file in HOME, the container's own metadata server, i.e. no
GCE_METADATA_HOST) and the same TF_VAR_* / quota variables; an explicit `env=` still wins; the deploy and the job take
exactly the old path; `validate` keeps every variable it had and adds only the unroutable metadata host.

Hermetic: fake Popen, fake broker / guard database / workload record, signatures with tests/fd7l_fakes.py's real RSA
key, a real loopback metadata endpoint; no network, no cloud clients.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import logging
import os
import subprocess
import types
from unittest.mock import MagicMock

import pytest

import fd7l_fakes as fk
from tests.tofu_popen_fake import popen_from_run
from test_fd4g_terraform_workspace import (  # noqa: F401  (pytest fixtures reused by name)
    _isolated_tf_service, _import_service, _load_tf_module, base, sent_callbacks)

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO, "mcp-servers", "terraform")
MODE = "STACKVEND_TF_RUNNER_IDENTITY"
CHILD = "claims-prod-1a2b"
PRODUCT = "claims"
DEPLOYER = f"stackvend-deployer@{CHILD}.iam.gserviceaccount.com"
BUCKET = f"{CHILD}-tfstate"
NONCE = "n" * 43                         # test value only
SESSION_KEY = "a" * 64 + "." + "s" * 43  # test value only
TOKEN = "ya29.test-only-deployer-token"  # test value only
CALLBACK = "https://workflowexecutions.googleapis.com/v1/projects/h/locations/r/workflows/w/executions/e/callbacks/c"

PINNED_NEVER = ["GITHUB_TOKEN", "RUNNER_NONCE", "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_OAUTH_ACCESS_TOKEN",
                "GOOGLE_CREDENTIALS", "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES", "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT",
                "GCE_METADATA_ROOT", "GCE_METADATA_HOST", "GCE_METADATA_IP", "TF_LOG", "TF_LOG_PATH", "TF_LOG_CORE",
                "KUBECONFIG", "KUBE_CONFIG_PATH", "KUBE_TOKEN", "PROJECT_ID", "TFSTATE_BUCKET", "K_SERVICE",
                "CLOUD_RUN_JOB", "CLOUD_RUN_EXECUTION", "SESSION_SECRET", "TF_CLI_ARGS", "TF_CLI_ARGS_init"]


def _svc(base):
    tf = _import_service()
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="", workspace_base_dir=base,
                              firestore_client=MagicMock())
    svc.db = None
    return tf, svc


def _engine(monkeypatch, tf, svc, tmp_path, seen, run=None):
    rc = tmp_path / "terraform.rc"
    rc.write_text("provider_installation {}\n", encoding="utf-8")
    monkeypatch.setattr(svc, "_ensure_binary", lambda *a, **k: "tofu")
    monkeypatch.setattr(svc, "_ensure_provider_mirror", lambda *a, **k: str(rc))

    def _run(cmd, **kw):
        home = kw["env"].get("HOME")
        seen.append({"cmd": list(cmd), "cwd": kw["cwd"], "env": dict(kw["env"]),
                     "home_listing": os.listdir(home) if home and os.path.isdir(home) else None})
        return run(cmd, **kw) if run else subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(tf.subprocess, "Popen", popen_from_run(_run))


@pytest.fixture
def poisoned_env(monkeypatch):
    """The runner's own environment with every pinned variable set (they must never reach tofu)."""
    for name in PINNED_NEVER:
        monkeypatch.setenv(name, f"poison-{name}")
    monkeypatch.setenv("TF_IN_AUTOMATION", "1")
    monkeypatch.delenv(MODE, raising=False)


class FakeBroker:
    def __init__(self, ri, lifetime=3600.0):
        self.ri, self.lifetime, self.down, self.calls = ri, lifetime, False, 0
        self.redeemed = []

    def deployer_token(self, session_key):
        assert session_key == SESSION_KEY
        self.calls += 1
        if self.down:
            raise self.ri.RunnerIdentityError("RUNNER_BROKER_UNAVAILABLE", "down", http_status=503)
        import time
        return f"{TOKEN}-{self.calls}", time.time() + self.lifetime, {}

    def redeem(self, nonce, execution):
        self.redeemed.append((nonce, execution))
        return _dispatch(), SESSION_KEY


def _runner(tf, ri, project=CHILD, broker=None):
    rc = tf.runner_creds
    creds = rc.BrokeredCredentials(broker or FakeBroker(ri), SESSION_KEY, project_id=project,
                                   deployer_email=f"stackvend-deployer@{project}.iam.gserviceaccount.com")
    endpoint = rc.LocalMetadataEndpoint(creds).start(ticker=False)
    return rc.WorkspaceRunner(creds, endpoint, "broker-key-1")


@pytest.fixture
def ri():
    from shared import runner_identity
    return runner_identity


# ------------------------------------------------------------------------------------------------ Shared install
@pytest.mark.parametrize("mode", [None, "PLATFORM", ""])
def test_shared_install_tofu_env_is_the_allow_list_with_the_same_identity_and_vars(
        monkeypatch, base, tmp_path, poisoned_env, mode):
    if mode is not None:
        monkeypatch.setenv(MODE, mode)
    tf, svc = _svc(base)
    seen = []
    _engine(monkeypatch, tf, svc, tmp_path, seen)
    ws = os.path.join(base, "t1", "claims")
    os.makedirs(ws)
    svc._register_workspace_tf_vars(ws, {"oauth_client_secret": "", "firebase_api_key": "k-test"})
    svc._register_workspace_billing(ws, CHILD)
    svc._run_subprocess(["tofu", "plan"], cwd=ws, iac_engine="OPENTOFU")
    svc._run_subprocess(["tofu", "apply"], cwd=ws, iac_engine="OPENTOFU")
    svc._run_subprocess(["tofu", "plan"], cwd=ws, env={"TF_VAR_firebase_api_key": "explicit"}, iac_engine="OPENTOFU")
    for run in seen:
        env = run["env"]
        assert not [n for n in PINNED_NEVER if n in env], sorted(env)
        assert set(env) == {"PATH", "TF_IN_AUTOMATION", "HOME", "TF_CLI_CONFIG_FILE", "TF_PLUGIN_CACHE_DIR",
                            "TF_VAR_oauth_client_secret", "TF_VAR_firebase_api_key", "GOOGLE_BILLING_PROJECT",
                            "GOOGLE_CLOUD_QUOTA_PROJECT", "GOOGLE_USER_PROJECT_OVERRIDE",
                            "CHECKPOINT_DISABLE"} | \
            ({"LANG"} & set(os.environ)) | ({"TMPDIR"} & set(os.environ)) | ({"TF_INPUT"} & set(os.environ))
        assert env["GOOGLE_BILLING_PROJECT"] == CHILD and env["TF_VAR_oauth_client_secret"] == ""
        assert env["CHECKPOINT_DISABLE"] == "1"   # SAT-27 RT L1 (SAT-31): no version-check call per command
        assert run["home_listing"] == []                                  # a fresh, empty HOME: no ADC file
        assert not os.path.exists(env["HOME"])                            # removed after the command
        assert env["PATH"].endswith(os.environ["PATH"])
    assert seen[0]["env"]["TF_VAR_firebase_api_key"] == "k-test"
    assert seen[2]["env"]["TF_VAR_firebase_api_key"] == "explicit"        # an explicit env still wins
    assert len({run["env"]["HOME"] for run in seen}) == 3                 # one HOME per command


def test_shared_install_unset_and_platform_give_identical_envs(monkeypatch, base, tmp_path, poisoned_env):
    envs = []
    for mode in (None, "PLATFORM"):
        if mode:
            monkeypatch.setenv(MODE, mode)
        tf, svc = _svc(base)
        seen = []
        _engine(monkeypatch, tf, svc, tmp_path, seen)
        ws = os.path.join(base, "t1", "claims")
        os.makedirs(ws, exist_ok=True)
        svc._run_subprocess(["tofu", "init"], cwd=ws, iac_engine="OPENTOFU")
        envs.append({k: v for k, v in seen[0]["env"].items() if k != "HOME"})
    assert envs[0] == envs[1]


def test_shared_install_child_calls_use_adc_with_the_child_quota_project(monkeypatch, base):
    import google.auth
    tf, svc = _svc(base)
    calls = []
    monkeypatch.delenv(MODE, raising=False)
    monkeypatch.setattr(google.auth, "default", lambda *a, **k: calls.append(k) or (MagicMock(), "p"))
    svc._child_credentials(CHILD)
    assert calls == [{"scopes": ["https://www.googleapis.com/auth/cloud-platform"], "quota_project_id": CHILD}]


def test_validate_env_adds_only_the_unroutable_metadata_host():
    import importlib.util
    import sys
    sys.path.insert(0, TF_DIR)
    try:
        spec = importlib.util.spec_from_file_location("fd7l_2a_validate_service", os.path.join(TF_DIR,
                                                                                            "validate_service.py"))
        vs = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vs)
    finally:
        sys.path.remove(TF_DIR)
    env = vs.scrubbed_env("/h", "/c", "/p")
    assert env == {"PATH": "/usr/bin:/bin", "HOME": "/h", "TF_CLI_CONFIG_FILE": "/c", "TF_IN_AUTOMATION": "1",
                   "TF_INPUT": "0", "CHECKPOINT_DISABLE": "1", "LANG": "C.UTF-8", "TZ": "UTC",
                   "TF_PLUGIN_CACHE_DIR": "/p", "TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE": "1",
                   "GCE_METADATA_HOST": "127.0.0.1:9", "GCE_METADATA_IP": "127.0.0.1:9"}
    assert vs.UNROUTABLE_METADATA_HOST == _import_service().runner_creds.UNROUTABLE_METADATA_HOST


def test_mode_log_line_on_a_shared_deploy(monkeypatch, base, caplog):
    tf, svc = _svc(base)
    monkeypatch.delenv(MODE, raising=False)
    with caplog.at_level(logging.INFO):
        assert svc._runner_admission(PRODUCT, "t-1", CHILD) is None
    lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("RUNNER_IDENTITY_MODE ")]
    assert len(lines) == 1 and '"mode": "PLATFORM"' in lines[0] and '"brokered": false' in lines[0]


# ------------------------------------------------------------------------------------------------ Per-workload install
def test_per_workload_tofu_without_registered_credentials_is_refused(monkeypatch, base, tmp_path, ri):
    monkeypatch.setenv(MODE, "PER_WORKLOAD")
    tf, svc = _svc(base)
    seen = []
    _engine(monkeypatch, tf, svc, tmp_path, seen)
    ws = os.path.join(base, "t1", "claims")
    os.makedirs(ws)
    out = svc._run_subprocess(["tofu", "init"], cwd=ws, iac_engine="OPENTOFU")
    assert out["error_class"] == "RUNNER_IDENTITY_NOT_REGISTERED" and out["operator_required"] is True
    assert not out["success"] and not seen
    with pytest.raises(ri.RunnerIdentityError) as ei:
        svc._child_credentials(CHILD)
    assert ei.value.code == "RUNNER_IDENTITY_NOT_REGISTERED"
    with pytest.raises(ri.RunnerIdentityError):
        svc._child_storage_client(CHILD)


def test_unknown_mode_value_refuses_tofu(monkeypatch, base, tmp_path):
    monkeypatch.setenv(MODE, "per_workload")
    tf, svc = _svc(base)
    seen = []
    _engine(monkeypatch, tf, svc, tmp_path, seen)
    ws = os.path.join(base, "t1", "claims")
    os.makedirs(ws)
    assert svc._run_subprocess(["tofu", "init"], cwd=ws)["error_class"] == "RUNNER_IDENTITY_MODE_INVALID"
    assert not seen
    res = svc._runner_admission(PRODUCT, "t1", CHILD)
    assert res["error_class"] == "RUNNER_IDENTITY_MODE_INVALID" and res["operator_required"] is True


def test_per_workload_tofu_gets_the_local_endpoint_and_the_child_only(monkeypatch, base, tmp_path, poisoned_env, ri):
    monkeypatch.setenv(MODE, "PER_WORKLOAD")
    tf, svc = _svc(base)
    seen = []
    _engine(monkeypatch, tf, svc, tmp_path, seen)
    trace_dir = os.path.join(base, "t1")
    ws = os.path.join(trace_dir, "claims")
    os.makedirs(ws)
    runner = _runner(tf, ri)
    try:
        reg = svc._register_workspace_runner(trace_dir, runner)
        out = svc._run_subprocess(["tofu", "plan"], cwd=ws, iac_engine="OPENTOFU")
        assert out["success"]
        env = seen[0]["env"]
        assert env["GCE_METADATA_HOST"] == env["GCE_METADATA_IP"] == runner.endpoint.host
        assert env["GCE_METADATA_HOST"].startswith("127.0.0.1:")
        assert env["GOOGLE_BILLING_PROJECT"] == CHILD == env["GOOGLE_CLOUD_QUOTA_PROJECT"]
        assert not [n for n in PINNED_NEVER if n in env and n not in ("GCE_METADATA_HOST", "GCE_METADATA_IP")]
        assert TOKEN not in str(env) and SESSION_KEY not in str(env) and NONCE not in str(env)
        assert svc._child_credentials(CHILD) is runner.credentials
        with pytest.raises(ri.RunnerIdentityError):
            svc._child_credentials("another-project-1")           # never another project's or the platform's
        assert svc._runner_admission(PRODUCT, "t1", CHILD) is None
        res = svc._runner_admission(PRODUCT, "t1", "another-project-1")
        assert res["error_class"] == "RUNNER_TARGET_MISMATCH" and res["operator_required"] is True
        svc._forget_workspace_runner(*reg)
        assert svc._run_subprocess(["tofu", "plan"], cwd=ws)["error_class"] == "RUNNER_IDENTITY_NOT_REGISTERED"
    finally:
        runner.endpoint.stop()


def test_broker_failure_during_a_command_is_typed_and_stops_later_commands(monkeypatch, base, tmp_path, ri):
    monkeypatch.setenv(MODE, "PER_WORKLOAD")
    tf, svc = _svc(base)
    trace_dir = os.path.join(base, "t1")
    ws = os.path.join(trace_dir, "claims")
    os.makedirs(ws)
    runner = _runner(tf, ri)
    seen = []

    def _run(cmd, **kw):     # the broker gives up while this command runs (the ticker would SIGINT it)
        runner.endpoint.abort(ri.RunnerIdentityError("RUNNER_BROKER_UNAVAILABLE", "test outage", http_status=503))
        return subprocess.CompletedProcess(cmd, 130, "partial", "interrupted")

    _engine(monkeypatch, tf, svc, tmp_path, seen, run=_run)
    try:
        svc._register_workspace_runner(trace_dir, runner)
        out = svc._run_subprocess(["tofu", "apply"], cwd=ws, iac_engine="OPENTOFU")
        assert out["error_class"] == "RUNNER_BROKER_UNAVAILABLE" and out["stdout"] == "partial"
        assert svc._run_subprocess(["tofu", "output"], cwd=ws)["error_class"] == "RUNNER_BROKER_UNAVAILABLE"
        assert len(seen) == 1
    finally:
        runner.endpoint.stop()


def test_per_workload_deploy_without_credentials_is_refused_before_anything_runs(monkeypatch, base, tmp_path):
    monkeypatch.setenv(MODE, "PER_WORKLOAD")
    tf, svc = _svc(base)
    seen = []
    _engine(monkeypatch, tf, svc, tmp_path, seen)
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    monkeypatch.setattr(svc, "_fetch_repo_files", lambda *a, **k: pytest.fail("the repository was read"))
    monkeypatch.setattr(svc, "_child_credentials", lambda *a, **k: pytest.fail("a child call was made"))
    res = svc.deploy_workload(product_id=PRODUCT, trace_id="t-deny", target_project_id=CHILD, branch="main",
                              iac_engine="OPENTOFU")
    assert res["status"] == "FAILED" and res["error_class"] == "RUNNER_IDENTITY_NOT_REGISTERED"
    assert res["operator_required"] is True and not seen


# ------------------------------------------------------------------------------------------------ tf-applier
def _signed(ri, **over):
    rec = ri.new_runner_identity_record(product_id=PRODUCT, project_id=CHILD, project_number="123456789",
                                        state_bucket=BUCKET, status="READY", updated_at="2026-11-01T00:00:00Z",
                                        repository={"provider": "GITHUB", "full_name": "Acme/claims", "id": "42"})
    rec.update(over)
    return ri.sign_record(ri.provenance_doc_path(PRODUCT), rec, signer_email=fk.BROKER,
                          signed_at="2026-11-01T00:00:00Z", sign_blob=fk.BROKER_KEY.sign)


def _dispatch(**over):
    d = {"product_id": PRODUCT, "project_id": CHILD, "project_number": "123456789", "deployer_email": DEPLOYER,
         "state_bucket": BUCKET, "state_prefix": f"workloads/{PRODUCT}", "repository": None, "trace_id": "t-brokered",
         "branch": "main", "mode": "deploy", "callback_url": CALLBACK, "payload_ref": None, "payload_sha256": None,
         "saved_plan_sha256": None, "execution": "e", "backfill_product_ids": None}
    d.update(over)
    return d


class _Snap:
    def __init__(self, data):
        self._data, self.exists = data, data is not None

    def to_dict(self):
        return dict(self._data) if self._data is not None else None


class _DB:
    def __init__(self, docs):
        self.docs = docs

    def collection(self, name):
        return types.SimpleNamespace(document=lambda doc_id: types.SimpleNamespace(
            get=lambda: _Snap(self.docs.get((name, doc_id)))))


JOB_ENV = {"PROJECT_ID": fk.HOST, "CLOUD_RUN_JOB": "tf-applier", "CLOUD_RUN_EXECUTION": "tf-applier-x1",
           "RUNNER_NONCE": NONCE, "VENDING_SERVICE_URL": "https://vending.example.run.app",
           "STACKVEND_GUARD_FIRESTORE_DATABASE": "stackvend-guard", MODE: "PER_WORKLOAD",
           # the old inputs: present, and ignored
           "PRODUCT_ID": "victim", "TARGET_PROJECT_ID": "victim-project", "CALLBACK_URL": "https://evil.example",
           "BRANCH": "evil", "HCL_FILES_JSON": "{}", "TRACE_ID": "t-evil"}


def _brokered(monkeypatch, base, ri, *, provenance=None, workload=None, dispatch=None, bucket_ok=True):
    deployed = {}

    def deploy(**kw):
        svc = deploy.owner
        ws = os.path.join(base, kw["trace_id"], kw["product_id"])
        deployed.update(kw, runner=svc._workspace_runner(ws), admission=svc._runner_admission(
            kw["product_id"], kw["trace_id"], kw["target_project_id"]))
        return {"status": "SUCCESS", "service_url": "https://x"}

    applier = _load_tf_module(monkeypatch, base, "applier.py", "fd7l_2a_applier")
    real = applier.TerraformService

    def factory(*a, **k):
        inst = real(*a, **k)
        inst.db = _DB({("workloads", PRODUCT): workload if workload is not None else {"project_id": CHILD}})
        inst.deploy_workload = deploy
        deploy.owner = inst
        return inst

    monkeypatch.setattr(applier, "TerraformService", factory)
    rc = applier.runner_creds
    owner_checks = []

    def _owner(session, bucket, number):
        owner_checks.append((bucket, number))
        if not bucket_ok:
            raise ri.RunnerIdentityError("STATE_BUCKET_NOT_OWNED", "test", http_status=409)

    monkeypatch.setattr(rc, "check_state_bucket_owner", _owner)
    for k, v in JOB_ENV.items():
        monkeypatch.setenv(k, v)
    broker = FakeBroker(ri)
    if dispatch is not None:
        broker.redeem = lambda nonce, execution: (broker.redeemed.append((nonce, execution)) or dispatch,
                                                  SESSION_KEY)
    guard = _DB({("workload_provenance", PRODUCT): provenance if provenance is not None else
                 {"project_id": CHILD, "runner_identity": _signed(ri)}})
    deployed["env_before"] = dict(os.environ)
    ok = applier.run_brokered_job(broker=broker, region_lookup=lambda: "us-central1",
                                  guard_db_factory=lambda: guard, certs=fk.certs_for(), tick_s=3600)
    before = deployed.pop("env_before")
    assert dict(os.environ) == before                              # a brokered run never writes the process env
    return applier, ok, deployed, broker, owner_checks


def test_brokered_job_reads_only_the_nonce_and_deploys_the_signed_target(monkeypatch, base, sent_callbacks, ri,
                                                                          caplog):
    with caplog.at_level(logging.INFO):
        applier, ok, deployed, broker, owner_checks = _brokered(monkeypatch, base, ri)
    assert ok is True
    assert broker.redeemed == [(NONCE, f"projects/{fk.HOST}/locations/us-central1/jobs/tf-applier/executions/"
                                       "tf-applier-x1")]
    assert (deployed["product_id"], deployed["trace_id"], deployed["target_project_id"], deployed["branch"]) == \
        (PRODUCT, "t-brokered", CHILD, "main")                      # from the records, never from the old env
    assert deployed["hcl_files"] is None
    assert deployed["runner"] is not None and deployed["runner"].key_id == fk.BROKER_KEY.key_id
    assert deployed["admission"] is None
    assert owner_checks == [(BUCKET, "123456789")]
    assert sent_callbacks[-1]["status"] == "SUCCESS" and sent_callbacks[-1]["product_id"] == PRODUCT
    ignored = [r.getMessage() for r in caplog.records if r.getMessage().startswith("RUNNER_ENV_IGNORED")]
    assert len(ignored) == 1 and "PRODUCT_ID" in ignored[0] and "CALLBACK_URL" in ignored[0]
    assert "victim" not in ignored[0] and "evil" not in ignored[0]                # names only, never values
    assert NONCE not in caplog.text and SESSION_KEY not in caplog.text and TOKEN not in caplog.text
    assert '"brokered": true' in caplog.text and fk.BROKER_KEY.key_id in caplog.text   # R10
    assert deployed["runner"].endpoint.failure is None
    with pytest.raises(Exception):
        deployed["runner"].endpoint.host and _http_get(deployed["runner"].endpoint.host)   # stopped after the run


def _http_get(host):
    import http.client
    h, port = host.split(":")
    conn = http.client.HTTPConnection(h, int(port), timeout=2)
    conn.request("GET", "/", headers={"Metadata-Flavor": "Google"})
    return conn.getresponse().status


@pytest.mark.parametrize("case,code", [
    ("unsigned", "RUNNER_RECORD_UNSIGNED"),
    ("cc_signed", "RUNNER_RECORD_UNSIGNED"),
    ("dispatch_project", "RUNNER_TARGET_MISMATCH"),
    ("workload_project", "RUNNER_TARGET_MISMATCH"),
    ("not_ready", "RUNNER_IDENTITY_NOT_READY"),
    ("no_record", "RUNNER_IDENTITY_NOT_READY"),
    ("bucket_not_owned", "STATE_BUCKET_NOT_OWNED"),
    ("plan_mode", "RUNNER_MODE_UNSUPPORTED"),
    ("staged_payload", "RUNNER_MODE_UNSUPPORTED"),
])
def test_brokered_job_refusals_are_typed_in_the_callback_and_nothing_deploys(monkeypatch, base, sent_callbacks, ri,
                                                                             case, code):
    kw = {}
    signed = _signed(ri)
    if case == "unsigned":
        kw["provenance"] = {"project_id": CHILD, "runner_identity": {k: v for k, v in signed.items()
                                                                     if k != "signature"}}
    elif case == "cc_signed":
        rec = {k: v for k, v in signed.items() if k not in ("signature", "signed_by", "signed_at")}
        kw["provenance"] = {"project_id": CHILD, "runner_identity": ri.sign_record(
            ri.provenance_doc_path(PRODUCT), rec, signer_email=fk.CC, signed_at="2026-11-01T00:00:00Z",
            sign_blob=fk.OTHER_KEY.sign)}
    elif case == "dispatch_project":
        kw["dispatch"] = _dispatch(state_bucket="another-bucket-x")
    elif case == "workload_project":
        kw["workload"] = {"project_id": "victim-project"}
    elif case == "not_ready":
        kw["provenance"] = {"project_id": CHILD, "runner_identity": _signed(ri, status="MIGRATING")}
    elif case == "no_record":
        kw["provenance"] = {"project_id": CHILD}
    elif case == "bucket_not_owned":
        kw["bucket_ok"] = False
    elif case == "plan_mode":
        kw["dispatch"] = _dispatch(mode="plan")
    elif case == "staged_payload":
        kw["dispatch"] = _dispatch(payload_ref="gs://staging/x", payload_sha256="0" * 64)
    applier, ok, deployed, broker, _owner = _brokered(monkeypatch, base, ri, **kw)
    assert ok is False and not deployed
    last = sent_callbacks[-1]
    assert last["status"] == "FAILED" and last["error_class"] == code and last["operator_required"] is True


@pytest.mark.parametrize("missing", ["RUNNER_NONCE", "VENDING_SERVICE_URL", "CLOUD_RUN_EXECUTION"])
def test_brokered_job_without_its_configuration_is_not_ready_and_redeems_nothing(monkeypatch, base, sent_callbacks,
                                                                                 ri, missing, caplog):
    applier = _load_tf_module(monkeypatch, base, "applier.py", "fd7l_2a_applier_cfg")
    for k, v in JOB_ENV.items():
        monkeypatch.setenv(k, v)
    monkeypatch.delenv(missing)
    with caplog.at_level(logging.ERROR):
        ok = applier.run_brokered_job(region_lookup=lambda: "us-central1")
    assert ok is False and not sent_callbacks
    assert "RUNNER_IDENTITY_NOT_READY" in caplog.text


def test_shared_install_job_never_takes_the_brokered_path(monkeypatch, base, sent_callbacks):
    applier = _load_tf_module(monkeypatch, base, "applier.py", "fd7l_2a_applier_shared")
    monkeypatch.setattr(applier, "run_brokered_job", lambda *a, **k: pytest.fail("brokered path on a Shared install"))
    for mode in (None, "PLATFORM", "bogus"):
        if mode is None:
            monkeypatch.delenv(MODE, raising=False)
        else:
            monkeypatch.setenv(MODE, mode)
        assert applier._per_workload_install() is False


# ------------------------------------------------------------------------------------------------ ast guard
# The only functions of the runner that may call google.auth.default / construct a storage.Client: the two child
# helpers (which hand out the brokered deployer on a Per-workload install), the lock read (FD-4H; Phase 2b: a
# Per-workload run reads through _child_storage_client, the platform client only on a Shared install) and the
# tf-applier dispatch of the server (host Cloud Run API).
AST_ALLOWED = {
    # SAT-41 HIGH-3: _live_state_exists reads the PLATFORM bucket with the platform client (Shared path only; a
    # child bucket goes through _child_storage_client)
    "service.py": {"_child_credentials", "_child_storage_client", "_read_state_lock_object", "_live_state_exists"},
    "main.py": {"trigger_tf_applier_job"},
    "applier.py": set(), "runner_credentials.py": set(), "brownfield_adoption.py": set(), "compliance_gate.py": set(),
    "workspace_lifecycle.py": set(), "validate_service.py": set(), "provider_allowlist.py": set(),
    "cloudsql_create_recovery.py": set(),   # CLOUDSQL-CREATE-OWN-OPERATION: pure; service.py uses _child_credentials
    # FD-7L 5b: the container's own identity on the HOST staging bucket only (server: create; job: read)
    "runner_runs.py": {"_host_storage_session"}, "runner_dispatch.py": set(),
}


@pytest.mark.parametrize("name", sorted(AST_ALLOWED))
def test_ast_guard_platform_identity_only_in_allow_listed_functions(name):
    tree = ast.parse(open(os.path.join(TF_DIR, name), encoding="utf-8").read())
    hits = []
    stack = []

    class _V(ast.NodeVisitor):
        def visit_FunctionDef(self, node):
            stack.append(node.name)
            self.generic_visit(node)
            stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Attribute(self, node):
            if ast.unparse(node) in ("google.auth.default", "storage.Client", "google.cloud.storage.Client"):
                hits.append((node.lineno, stack[-1] if stack else "<module>"))
            self.generic_visit(node)

        def visit_ImportFrom(self, node):
            if node.module in ("google.auth", "google.auth._default") and any(a.name == "default" for a in node.names):
                hits.append((node.lineno, "from google.auth import default"))
            if node.module == "google.cloud.storage" and any(a.name == "Client" for a in node.names):
                hits.append((node.lineno, "from google.cloud.storage import Client"))

    _V().visit(tree)
    assert [h for h in hits if h[1] not in AST_ALLOWED[name]] == []
