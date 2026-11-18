"""SAT-22 (FD-7M-a builder B): the terraform server and tf-applier deploy into the workload's recorded region.

- `_deploy_workload_impl` reads workloads/{pid}.region and resolves it through the SAT-21 settings helper
  `workload_region()` against the install's approved deployable regions (`resolve_workload_region`): approved -> that
  region everywhere (runtime tfvars `region`, image tag, Artifact Registry path, build staging bucket, stub purge,
  rollout); not approved -> typed REGION_NOT_APPROVED before any fetch / build / apply (operator_required).
- The deploy result carries `region`; the tf-applier's stockout purge passes it.
- Do No Harm: a record WITHOUT a region and a record whose region equals the default give byte-identical runtime
  tfvars (the FD-4AL path is the very same `_resolve_region()` call when the record has no region).

Hermetic: fake Firestore clients, no ADC, no network, no tofu.
"""
import hermetic_guard  # noqa: F401  (first import)

import ast
import os
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
for p in (REPO_ROOT,):
    if p not in sys.path:
        sys.path.insert(0, p)

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (terraform MCP requirement) not installed")

from fd4g_support import load_tf_service  # noqa: E402

DEFAULT = "us-central1"     # the schema default (shared/settings.py)
OTHER = "europe-west1"      # an approved second region
UNAPPROVED = "asia-south1"  # a region the install did not approve


class _Db:
    """Fake Firestore keyed by (collection, document): a value of None = no document; an Exception = the read raises."""

    def __init__(self, docs):
        self.docs, self.reads = dict(docs), []

    def collection(self, name):
        outer = self

        class _D:
            def __init__(self, doc_id):
                self.doc_id = doc_id

            def get(self):
                outer.reads.append((name, self.doc_id))
                doc = outer.docs.get((name, self.doc_id))
                if isinstance(doc, Exception):
                    raise doc
                return types.SimpleNamespace(exists=doc is not None, to_dict=lambda: dict(doc or {}))

            def set(self, *a, **k):
                return None

            def update(self, *a, **k):
                return None

            def collection(self, sub):
                return outer.collection(f"{name}/{self.doc_id}/{sub}")

        class _C:
            def document(self, doc_id=None):
                return _D(doc_id)

            def where(self, *a, **k):
                return self

            def stream(self):
                return iter(())
        return _C()


def _settings(approved=None, default=DEFAULT):
    orch = {"default_gcp_region": default}
    if approved is not None:
        orch["approved_deployable_regions"] = list(approved)
    return {"orchestration": orch}


def _db(record_region=..., approved=(DEFAULT, OTHER), settings=None):
    record = {"project_id": "p-1"}
    if record_region is not ...:
        record["region"] = record_region
    return _Db({("workloads", "shop"): record,
                ("system_config", "platform_settings"): settings if settings is not None else _settings(approved)})


@pytest.fixture
def tf(monkeypatch):
    return load_tf_service(monkeypatch)


# ------------------------------------------------------------------------------------------------ contract parity
def test_error_class_matches_the_settings_contract(tf):
    from shared import settings as S
    assert tf.REGION_NOT_APPROVED == S.REGION_NOT_APPROVED == "REGION_NOT_APPROVED"
    assert tf.RegionNotApprovedError.error_class == tf.REGION_NOT_APPROVED
    assert issubclass(tf.RegionNotApprovedError, RuntimeError) and not issubclass(tf.RegionNotApprovedError,
                                                                                    tf.RegionUnavailable)


# ------------------------------------------------------------------------------------------------ resolver
def test_no_record_region_is_exactly_the_fd4al_resolver(tf, monkeypatch):
    """Negative (Do No Harm): no record region -> resolve_platform_region(db), one settings read, nothing else."""
    db = _Db({("system_config", "platform_settings"): _settings(default=OTHER, approved=[OTHER])})
    assert tf.resolve_workload_region(db, None) == tf.resolve_platform_region(db) == OTHER
    monkeypatch.setattr(tf, "resolve_platform_region", lambda _db=None: "sentinel-1")
    assert tf.resolve_workload_region(db, None) == "sentinel-1"


def test_approved_record_region_wins(tf):
    db = _db()
    assert tf.resolve_workload_region(db, OTHER) == OTHER
    assert tf.resolve_workload_region(db, DEFAULT) == DEFAULT
    assert db.reads == [("system_config", "platform_settings")] * 2


@pytest.mark.parametrize("bad", [UNAPPROVED, "", "   ", 7, "EUROPE-WEST1"])
def test_unapproved_record_region_is_typed_never_another_region(tf, bad):
    with pytest.raises(tf.RegionNotApprovedError) as exc:
        tf.resolve_workload_region(_db(), bad)
    assert exc.value.error_class == "REGION_NOT_APPROVED" and exc.value.region == bad
    assert exc.value.approved == [DEFAULT, OTHER]
    assert "REGION_NOT_APPROVED at terraform_deploy" in str(exc.value)


def test_default_list_is_the_default_region_only(tf):
    """OQ-21: an empty / missing list = [default_gcp_region]; a missing document = the schema default."""
    assert tf.resolve_workload_region(_db(approved=[]), DEFAULT) == DEFAULT
    with pytest.raises(tf.RegionNotApprovedError):
        tf.resolve_workload_region(_db(approved=[]), OTHER)
    no_doc = _Db({("system_config", "platform_settings"): None})
    assert tf.resolve_workload_region(no_doc, DEFAULT) == DEFAULT
    with pytest.raises(tf.RegionNotApprovedError):
        tf.resolve_workload_region(no_doc, OTHER)
    no_orch = _Db({("system_config", "platform_settings"): {"models": {}}})
    assert tf.resolve_workload_region(no_orch, DEFAULT) == DEFAULT


def test_unreadable_or_invalid_settings_are_region_unavailable(tf, monkeypatch):
    monkeypatch.setenv("REGION", OTHER)   # never a fallback for a recorded region's approval
    for db in (_Db({("system_config", "platform_settings"): RuntimeError("down")}),
               _db(settings={"orchestration": {"default_gcp_region": DEFAULT,
                                               "approved_deployable_regions": [OTHER]}}),   # default not in list
               _db(settings={"orchestration": {"approved_deployable_regions": ["Not A Region"]}})):
        with pytest.raises(tf.RegionUnavailable) as exc:
            tf.resolve_workload_region(db, OTHER)
        assert "REGION_UNAVAILABLE" in str(exc.value)


def test_settings_store_contract_matches_fd4al(tf, monkeypatch):
    """A configured install without a client fails typed; no store at all (eval harness) = the FD-4AL region only."""
    monkeypatch.setenv("PROJECT_ID", "host-p")
    with pytest.raises(tf.RegionUnavailable):
        tf.resolve_workload_region(None, OTHER)
    monkeypatch.delenv("PROJECT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    monkeypatch.setenv("REGION", OTHER)
    assert tf.resolve_workload_region(None, OTHER) == OTHER
    with pytest.raises(tf.RegionNotApprovedError):
        tf.resolve_workload_region(None, UNAPPROVED)
    assert tf.resolve_workload_region(MagicMock(), OTHER) == OTHER    # a non-snapshot object = no store


# ------------------------------------------------------------------------------------------------ deploy
class _Stop(Exception):
    pass


TREE = {
    "infra/workload/main.tf": 'module "bucket" {\n  source     = "../modules/storage-bucket"\n'
                              '  project_id = var.project_id\n  region     = var.region\n}\n',
    "infra/workload/variables.tf": 'variable "project_id" {\n  type = string\n}\n\n'
                                   'variable "region" {\n  type    = string\n  default = "us-central1"\n}\n',
}


def _svc(tf, tmp_path, db):
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="", workspace_base_dir=str(tmp_path),
                              firestore_client=MagicMock())
    svc.db = db
    svc.state_bucket = ""
    return svc


def _no_gcp(monkeypatch):
    import google.auth  # noqa: F401
    import google.cloud  # noqa: F401

    def _no(*_a, **_k):
        raise RuntimeError("no GCP in tests")
    fake_sm = types.ModuleType("google.cloud.secretmanager")
    fake_sm.SecretManagerServiceClient = _no
    monkeypatch.setitem(sys.modules, "google.cloud.secretmanager", fake_sm)
    monkeypatch.setattr(sys.modules["google.cloud"], "secretmanager", fake_sm, raising=False)
    monkeypatch.setattr(sys.modules["google.auth"], "default", _no, raising=False)


def _runtime_tfvars(tf, monkeypatch, tmp_path, db):
    """Deploy through the real flatten up to prepare_workspace; return the runtime terraform.tfvars text."""
    svc = _svc(tf, tmp_path, db)
    monkeypatch.setattr(svc, "_fetch_repo_files", lambda *a, **k: dict(TREE))
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    monkeypatch.setattr(svc, "_deploy_access_vars", lambda pid: ("{}", {"rendered": False}))
    seen = {}

    def _prepare(pid, trace_id, hcl_files, iac_engine=None, region=None):
        seen["files"], seen["region"] = dict(hcl_files), region
        raise _Stop()
    monkeypatch.setattr(svc, "prepare_workspace", _prepare)
    _no_gcp(monkeypatch)
    with pytest.raises(_Stop):
        svc.deploy_workload(product_id="shop", trace_id="t", target_project_id="p-1", branch="main",
                            iac_engine="OPENTOFU")
    return seen


def test_deploy_uses_the_approved_record_region(tf, monkeypatch, tmp_path):
    seen = _runtime_tfvars(tf, monkeypatch, tmp_path, _db(OTHER))
    doc = hcl2.loads(seen["files"]["terraform.tfvars"])
    assert seen["region"] == OTHER and doc["region"] == OTHER
    assert doc["container_image"] == f"{OTHER}-docker.pkg.dev/p-1/shop/app:latest"
    assert DEFAULT not in seen["files"]["terraform.tfvars"]


def test_deploy_without_a_record_region_is_byte_identical(tf, monkeypatch, tmp_path):
    """Negatives (Do No Harm): no record region == the FD-4AL deploy (no client); a record region equal to the
    default == no record region. Same runtime tfvars bytes."""
    monkeypatch.delenv("REGION", raising=False)
    monkeypatch.delenv("DEFAULT_REGION", raising=False)
    legacy = _runtime_tfvars(tf, monkeypatch, tmp_path / "a", _db())
    same = _runtime_tfvars(tf, monkeypatch, tmp_path / "b", _db(DEFAULT))
    assert legacy["region"] == same["region"] == DEFAULT
    assert legacy["files"]["terraform.tfvars"] == same["files"]["terraform.tfvars"]
    text = legacy["files"]["terraform.tfvars"]
    assert 'region = "us-central1"\n' in text                                       # the FD-4AL exact lines
    assert 'container_image = "us-central1-docker.pkg.dev/p-1/shop/app:latest"\n' in text


def test_deploy_without_a_record_region_calls_only_the_fd4al_resolver(tf, monkeypatch, tmp_path):
    """No record region: `_resolve_region()` exactly as before; the approved list is not even read."""
    db = _db()
    with patch.object(tf.TerraformService, "_resolve_region", return_value="sentinel-2"), \
         patch.object(tf, "resolve_workload_region", side_effect=AssertionError("must not run")):
        seen = _runtime_tfvars(tf, monkeypatch, tmp_path, db)
    assert seen["region"] == "sentinel-2"
    assert ("system_config", "platform_settings") not in db.reads


@pytest.mark.parametrize("bad", [UNAPPROVED, ""])
def test_deploy_with_an_unapproved_region_is_typed_and_touches_nothing(tf, monkeypatch, tmp_path, bad):
    svc = _svc(tf, tmp_path, _db(bad))
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    monkeypatch.setattr(svc, "_deploy_access_vars", lambda pid: ("{}", {"rendered": False}))
    monkeypatch.setattr(svc, "_fetch_repo_files", lambda *a, **k: (_ for _ in ()).throw(AssertionError("fetched")))
    monkeypatch.setattr(svc, "_run_subprocess", lambda *a, **k: (_ for _ in ()).throw(AssertionError("ran")))
    monkeypatch.setattr(svc, "prepare_workspace", lambda *a, **k: (_ for _ in ()).throw(AssertionError("prepared")))
    res = svc.deploy_workload(product_id="shop", trace_id="t", target_project_id="p-1", branch="main",
                              iac_engine="OPENTOFU")
    assert res["status"] == "FAILED" and res["error_class"] == "REGION_NOT_APPROVED"
    assert res["operator_required"] is True and res["approved_regions"] == [DEFAULT, OTHER]
    assert "region" not in res                    # the refused region is not "the deploy's region"
    assert repr(bad) in res["error"]


def test_deploy_result_carries_its_region(tf, monkeypatch, tmp_path):
    svc = _svc(tf, tmp_path, _db(OTHER))
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    monkeypatch.setattr(svc, "_deploy_access_vars", lambda pid: ("{}", {"rendered": False}))
    monkeypatch.setattr(svc, "_fetch_repo_files", lambda *a, **k: dict(TREE))
    monkeypatch.setattr(svc, "prepare_workspace",
                        lambda *a, **k: (_ for _ in ()).throw(tf.WorkflowValidationError("stop", 1, None, ".github/workflows/x.yml")))
    _no_gcp(monkeypatch)
    res = svc.deploy_workload(product_id="shop", trace_id="t", target_project_id="p-1", branch="main",
                              iac_engine="OPENTOFU")
    assert res["status"] != "SUCCESS" and res["region"] == OTHER


def test_with_deploy_region_never_overwrites(tf):
    w = tf.TerraformService._with_deploy_region
    assert w({"status": "SUCCESS"}, {}) == {"status": "SUCCESS"}
    assert w({"status": "SUCCESS", "region": "x"}, {"region": OTHER}) == {"status": "SUCCESS", "region": "x"}
    assert w("not-a-dict", {"region": OTHER}) == "not-a-dict"
    assert w({"status": "FAILED"}, {"region": OTHER}) == {"status": "FAILED", "region": OTHER}


# ------------------------------------------------------------------------------------------------ build staging bucket
def test_staging_bucket_is_created_in_the_builds_region(tf, tmp_path):
    svc = _svc(tf, tmp_path, None)
    client = MagicMock()
    client.bucket.return_value.exists.return_value = False
    sess = MagicMock()
    sess.get.return_value = MagicMock(status_code=200, json=lambda: {
        "serviceAccountEmail": "projects/child/serviceAccounts/cb@child.iam.gserviceaccount.com"})
    with patch.object(svc, "_resolve_region", side_effect=AssertionError("must not resolve")):
        try:
            svc._stage_build_source(client, sess, "child", "child-cloudbuild-source", "o", b"tgz", region=OTHER)
        except Exception:   # noqa: BLE001 - the IAM step on a MagicMock policy is not this test's subject
            pass
    assert client.create_bucket.call_args.kwargs == {"project": "child", "location": OTHER}


def test_staging_bucket_without_a_region_keeps_the_platform_region(tf, tmp_path):
    """Negative: a direct caller that passes no region gets the platform region, as before."""
    svc = _svc(tf, tmp_path, None)
    client = MagicMock()
    client.bucket.return_value.exists.return_value = False
    sess = MagicMock()
    sess.get.return_value = MagicMock(status_code=200, json=lambda: {
        "serviceAccountEmail": "projects/child/serviceAccounts/cb@child.iam.gserviceaccount.com"})
    with patch.object(svc, "_resolve_region", return_value="sentinel-3"):
        try:
            svc._stage_build_source(client, sess, "child", "child-cloudbuild-source", "o", b"tgz")
        except Exception:   # noqa: BLE001
            pass
    assert client.create_bucket.call_args.kwargs == {"project": "child", "location": "sentinel-3"}


def test_build_passes_its_region_to_the_staging_bucket(tf, tmp_path, monkeypatch):
    import importlib
    S = sys.modules.get("shared.settings") or importlib.import_module("shared.settings")
    monkeypatch.setattr(S, "get_platform_settings", lambda *a, **k: None)   # no Firestore (BOM defaults)
    svc = _svc(tf, tmp_path, None)
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "main.py").write_text("print('hi')\n")
    seen = {}

    def stage(**kwargs):
        seen["region"] = kwargs.get("region")
        raise RuntimeError("stop after packaging (test)")
    with patch("google.auth.default", return_value=(MagicMock(), "p")), \
         patch("google.auth.transport.requests.AuthorizedSession"), \
         patch("google.cloud.storage.Client"), \
         patch.object(svc, "_resolve_region", side_effect=AssertionError("must not resolve")), \
         patch.object(tf.TerraformService, "_stage_build_source", side_effect=stage):
        assert svc._build_and_push_container("shop", "child", str(ws), "img:tag", region=OTHER) is False
    assert seen == {"region": OTHER}


# ------------------------------------------------------------------------------------------------ tf-applier
def test_applier_stockout_purge_uses_the_deploy_results_region():
    """The applier's only stub detection call passes `region=res.get("region")` (AST: the keyword and its value).
    RT14-01: the purge became the read-only `detect_errored_child_stubs`."""
    tree = ast.parse(Path(TF_DIR, "applier.py").read_text(encoding="utf-8"))
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and n.func.attr == "detect_errored_child_stubs"]
    assert len(calls) == 1
    kw = {k.arg: ast.unparse(k.value) for k in calls[0].keywords}
    assert kw.get("region") == "res.get('region')", kw


# ------------------------------------------------------------------------------------------------ plan / drift / unlock
@pytest.mark.parametrize("fn", ["generate_plan", "check_drift", "force_unlock", "prepare_workspace"])
def test_plan_drift_unlock_are_region_free(fn):
    """Brief row #5 found stale: these use no region at all (prepare_workspace accepts `region` for its callers'
    signature and ignores it), so no settings read is added there. Pinned so a future region use is deliberate."""
    tree = ast.parse(Path(TF_DIR, "service.py").read_text(encoding="utf-8"))
    node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == fn)
    body = node.body[1:] if (node.body and isinstance(node.body[0], ast.Expr)) else node.body
    names = {n.attr if isinstance(n, ast.Attribute) else getattr(n, "id", None)
             for stmt in body for n in ast.walk(stmt) if isinstance(n, (ast.Name, ast.Attribute))}
    assert not names & {"region", "_resolve_region", "_resolve_workload_region", "resolve_platform_region",
                        "resolve_workload_region", "workload_region"}, fn


# ------------------------------------------------------------------------------------------------ review fixes (11-01)
class _FlakyDb(_Db):
    """RT F1: the `workloads/<pid>` read succeeds `ok_reads` times (the FD-4DT access read), then raises."""

    def __init__(self, docs, ok_reads=1):
        super().__init__(docs)
        self.ok_reads, self.workload_reads = ok_reads, 0

    def collection(self, name):
        inner = super().collection(name)
        if name != "workloads":
            return inner
        outer = self

        class _C:
            def document(self, doc_id=None):
                d = inner.document(doc_id)
                real_get = d.get

                def get():
                    outer.workload_reads += 1
                    if outer.workload_reads > outer.ok_reads:
                        raise RuntimeError("transient (test)")
                    return real_get()
                d.get = get
                return d
        return _C()


def test_f1_impl_record_read_failure_is_typed_never_the_default_region(tf, monkeypatch, tmp_path):
    db = _FlakyDb(_db(OTHER).docs, ok_reads=1)
    svc = _svc(tf, tmp_path, db)
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    monkeypatch.setattr(svc, "_fetch_repo_files", lambda *a, **k: (_ for _ in ()).throw(AssertionError("fetched")))
    monkeypatch.setattr(svc, "prepare_workspace", lambda *a, **k: (_ for _ in ()).throw(AssertionError("prepared")))
    monkeypatch.setattr(svc, "_run_subprocess", lambda *a, **k: (_ for _ in ()).throw(AssertionError("ran")))
    _no_gcp(monkeypatch)
    res = svc.deploy_workload(product_id="shop", trace_id="t", target_project_id="p-1", branch="main",
                              iac_engine="OPENTOFU")
    assert db.workload_reads == 2                     # the access read passed; the impl's read raised
    assert res["status"] == "FAILED" and res["error_class"] == tf.REGION_UNAVAILABLE
    assert res["operator_required"] is True and "region" not in res
    assert "workloads/shop unreadable (RuntimeError)" in res["error"]


def test_f1_negative_good_reads_deploy_as_before(tf, monkeypatch, tmp_path):
    """Negative: a record that reads fine is unaffected (the approved region reaches the workspace)."""
    seen = _runtime_tfvars(tf, monkeypatch, tmp_path, _FlakyDb(_db(OTHER).docs, ok_reads=99))
    assert seen["region"] == OTHER


def test_f2_blank_stored_default_follows_fd4al(tf, monkeypatch):
    monkeypatch.setenv("REGION", OTHER)
    db = _db(settings={"orchestration": {"default_gcp_region": ""}})
    assert tf.resolve_platform_region(db) == OTHER                    # FD-4AL: blank = $REGION
    assert tf.resolve_workload_region(db, OTHER) == OTHER             # the record path approves the same default
    with pytest.raises(tf.RegionNotApprovedError) as exc:
        tf.resolve_workload_region(db, UNAPPROVED)
    assert exc.value.approved == [OTHER]
    monkeypatch.setenv("REGION", "")
    monkeypatch.setenv("DEFAULT_REGION", "")
    with pytest.raises(tf.RegionUnavailable):                          # nothing configured: typed, as FD-4AL
        tf.resolve_workload_region(db, OTHER)


def test_f3_region_unavailable_is_operator_required(tf, monkeypatch, tmp_path):
    svc = _svc(tf, tmp_path, None)

    def _none():
        raise tf.RegionUnavailable(f"{tf.REGION_UNAVAILABLE}: no platform region configured")
    monkeypatch.setattr(svc, "_resolve_region", _none)
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    monkeypatch.setattr(svc, "_fetch_repo_files", lambda *a, **k: (_ for _ in ()).throw(AssertionError("fetched")))
    res = svc.deploy_workload(product_id="shop", trace_id="t", target_project_id="p-1", branch="main",
                              iac_engine="OPENTOFU")
    assert res["status"] == "FAILED" and res["error_class"] == tf.REGION_UNAVAILABLE
    assert res["operator_required"] is True
