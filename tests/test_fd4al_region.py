"""FD-4AL: the workload region comes from ONE resolver per service, never a `us-central1` literal.

- Terraform server (mcp-servers/terraform/service.py): `resolve_platform_region` (Platform Settings
  `orchestration.default_gcp_region`, then $REGION / $DEFAULT_REGION, else RegionUnavailable) resolved once per deploy
  and threaded into the runtime tfvars `region`, image tags, REST paths, import IDs and the GKE manifest apply.
- Developer (apps/orchestrator-gateway/developer_agent): `terraform_engine.resolve_workload_region` (same order)
  resolved once per dispatch in `generate_code_files` and passed to every renderer (variables.tf `var.region`
  default, generated CI `REGION:`, the regulated-profile region check). Direct renderer callers get the settings
  SCHEMA default (the documented source), read from the schema, not a literal.
- Do No Harm: with the region `us-central1` every render is byte-identical to before (the explicit region equals the
  default render, and the rendered region lines are exactly the previous ones).

Hermetic: the resolvers read through the service's own (fake) Firestore client; no ADC, no network, no tofu.
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
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT, os.path.join(REPO_ROOT, "eval")):
    if p not in sys.path:
        sys.path.insert(0, p)

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (gateway / terraform MCP requirement) not installed")

from developer_agent import terraform_engine as te  # noqa: E402
from developer_agent import handler as h  # noqa: E402
from developer_agent.errors import ERROR_CLASSES, REGION_UNAVAILABLE, DeveloperStageError  # noqa: E402
from fd4g_support import load_tf_service  # noqa: E402

OTHER = "europe-west4"          # any non-default region
LITERAL = "us-central1"         # the schema default; the only place it may live is shared/settings.py

INGRESS = dict(allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False)


class _Db:
    """Fake Firestore client: system_config/platform_settings -> `doc` (None = no document; an Exception = raises)."""

    def __init__(self, doc=None):
        self.doc, self.reads = doc, []

    def collection(self, name):
        outer = self

        class _C:
            def document(self, doc_id):
                class _D:
                    def get(self):
                        outer.reads.append((name, doc_id))
                        if isinstance(outer.doc, Exception):
                            raise outer.doc
                        return types.SimpleNamespace(exists=outer.doc is not None, to_dict=lambda: dict(outer.doc or {}))
                return _D()
        return _C()


def _db(region):
    return _Db({"orchestration": {"default_gcp_region": region}})


@pytest.fixture
def tf(monkeypatch):
    return load_tf_service(monkeypatch)


# ------------------------------------------------------------------------------------------------ no literal left
def _region_literals(path):
    """Every string constant (f-string parts included) in `path` that contains the literal region."""
    tree = ast.parse(Path(path).read_text(encoding="utf-8"))
    return sorted({n.value for n in ast.walk(tree)
                   if isinstance(n, ast.Constant) and isinstance(n.value, str) and LITERAL in n.value})


# Google's public buildpacks builder image (one global image path, not the workload's registry): category (b).
_TF_SERVER_ALLOWED = {"--builder=us-central1-docker.pkg.dev/serverless-runtimes/google-24-full/builder/universal:latest"}


def test_terraform_server_has_no_workload_region_literal():
    found = set(_region_literals(os.path.join(REPO_ROOT, "mcp-servers", "terraform", "service.py")))
    assert found <= _TF_SERVER_ALLOWED, found - _TF_SERVER_ALLOWED


@pytest.mark.parametrize("rel", ["handler.py", "terraform_engine.py"])
def test_developer_renderers_have_no_region_literal(rel):
    assert _region_literals(os.path.join(GATEWAY, "developer_agent", rel)) == []


# ------------------------------------------------------------------------------------------------ resolvers
@pytest.mark.parametrize("which", ["tf", "dev"])
def test_resolver_order_and_typed_error(tf, monkeypatch, which):
    resolve = tf.resolve_platform_region if which == "tf" else te.resolve_workload_region
    unavailable = tf.RegionUnavailable if which == "tf" else te.RegionUnavailable
    monkeypatch.setenv("REGION", "asia-south1")
    db = _db(OTHER)
    assert resolve(db) == OTHER and db.reads == [("system_config", "platform_settings")]   # the setting wins
    assert resolve(_Db(None)) == LITERAL                  # no settings document: the schema default (documented)
    assert resolve(_Db({"models": {}})) == LITERAL        # a document without orchestration: the schema default
    assert resolve(None) == "asia-south1"                 # no client (project configured): $REGION
    assert resolve(_Db(RuntimeError("down"))) == "asia-south1"   # unreadable: $REGION
    assert resolve(MagicMock()) == "asia-south1"          # a non-snapshot object is never taken for a region
    monkeypatch.setenv("REGION", "")
    monkeypatch.setenv("DEFAULT_REGION", "me-west1")
    assert resolve(None) == "me-west1"
    monkeypatch.setenv("DEFAULT_REGION", "")
    # RT F1: a configured install (PROJECT_ID set) whose settings client is missing is a FAILED store -> typed.
    monkeypatch.setenv("PROJECT_ID", "host-p")
    with pytest.raises(unavailable) as exc:
        resolve(None)
    assert "no settings Firestore client although a project is configured" in str(exc.value)
    # A settings store that cannot answer (read error / invalid document) or says "" -> typed with the cause (RT F3).
    for db, cause in ((_Db(RuntimeError("down")), "settings document unreadable/invalid: RuntimeError: down"),
                      (_Db({"orchestration": {"default_gcp_region": 7}}), "settings document unreadable/invalid"),
                      (_db(""), "settings default_gcp_region is blank")):
        with pytest.raises(unavailable) as exc:
            resolve(db)
        assert isinstance(exc.value, RuntimeError) and cause in str(exc.value), str(exc.value)
    # No settings store at all (no project configured and no client: the eval harness child): the documented schema
    # default, exactly as get_platform_settings without Firestore.
    monkeypatch.delenv("PROJECT_ID", raising=False)
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    assert resolve(None) == LITERAL and resolve(MagicMock()) == LITERAL
    with pytest.raises(unavailable):
        resolve(_Db(RuntimeError("down")))                # a failing store stays typed without a project too
    assert REGION_UNAVAILABLE in ERROR_CLASSES


def test_terraform_server_method_uses_its_own_client(tf, tmp_path):
    svc = _svc(tf, tmp_path)
    svc.db = _db(OTHER)
    assert svc._resolve_region() == OTHER


def test_schema_default_is_the_documented_source_not_a_second_literal():
    from shared.settings import OrchestrationSettings
    assert te.WORKLOAD_REGION_DEFAULT == OrchestrationSettings().default_gcp_region == LITERAL


# ------------------------------------------------------------------------------------------------ developer renders
def test_variables_tf_renders_the_passed_region_and_us_central1_is_byte_identical():
    default = te.generate_golden_variables_tf("shop", "acme/shop")
    assert te.generate_golden_variables_tf("shop", "acme/shop", region=LITERAL) == default
    assert '  default     = "us-central1"\n' in default                     # the previous rendered line
    other = te.generate_golden_variables_tf("shop", "acme/shop", region=OTHER)
    assert other == default.replace(f'"{LITERAL}"', f'"{OTHER}"') and LITERAL not in other


@pytest.mark.parametrize("arch", ["cloudrun", "gce-bastion", "gke-autopilot", "event-worker"])
def test_generated_ci_region_is_the_passed_region(arch):
    default = h.generate_service_workflow("portal", "shop", "child-p", "123", archetype=arch)
    assert h.generate_service_workflow("portal", "shop", "child-p", "123", archetype=arch, region=LITERAL) == default
    assert "\n  REGION: us-central1\n" in default                            # the previous rendered line
    other = h.generate_service_workflow("portal", "shop", "child-p", "123", archetype=arch, region=OTHER)
    assert other == default.replace("REGION: us-central1", f"REGION: {OTHER}") and LITERAL not in other


# FD-55 W6a (register FD55-W6a, A7): the terraform server's workflow sanitizer (which substituted ${{ env.REGION }} in
# the deploy workspace copy) is deleted. Workflows are platform renders that carry the resolved region already
# (test_generated_ci_region_is_the_passed_region); prepare_workspace writes the committed text and only validates it.
WF = "env:\n  R: ${{ env.REGION }}\njobs:\n  d:\n    steps:\n      - run: echo ${{ env.REGION }}\n"


def test_prepare_workspace_writes_the_rendered_workflow_as_committed(tf, tmp_path):
    """Do No Harm: the platform-rendered workflow (passed region) reaches the workspace byte-identical; no region is
    resolved for it."""
    svc = _svc(tf, tmp_path)
    rendered = h.generate_service_workflow("portal", "shop", "child-p", "123", archetype="cloudrun", region=OTHER)
    with patch.object(svc, "_resolve_region", side_effect=AssertionError("must not resolve")), \
            patch.object(tf, "resolve_platform_region", side_effect=AssertionError("must not resolve")):
        ws = svc.prepare_workspace("shop", "t", {".github/workflows/deploy.yml": rendered}, region=OTHER)
    assert Path(ws, ".github", "workflows", "deploy.yml").read_bytes() == rendered.encode("utf-8")
    assert not hasattr(tf, "sanitize_github_workflow")


def test_prepare_workspace_reports_an_invalid_committed_workflow(tf, tmp_path):
    """The committed text is judged as-is: an env.* reference inside the top-level env block (which the deleted
    sanitizer used to rewrite in the workspace copy only) is reported, not repaired."""
    svc = _svc(tf, tmp_path)
    with pytest.raises(tf.WorkflowValidationError):
        svc.prepare_workspace("shop", "t", {".github/workflows/deploy.yml": "name: d\non: push\n" + WF},
                              region=OTHER)


def test_every_golden_module_block_gets_var_region():
    """Category (c): module variables.tf keep their default, but every platform-rendered caller passes var.region."""
    from developer_agent import compliance_profile as cp
    regulated = cp.RegulatedControls(profile="HIPAA", source=cp.PROFILE_SOURCE_DECISION, cmek=True,
                                     audit_logging=True, region=LITERAL)
    renders = [te.generate_golden_main_tf("shop", a, "") for a in
               ("cloudrun", "gce-bastion", "gke-autopilot", "event-worker", "foundation-only")]
    renders.append(te.generate_golden_main_tf("shop", "cloudrun", "", regulated=regulated))   # + module "cmek"
    checked = 0
    for text in renders:
        for block in hcl2.loads(text).get("module", []):
            for _name, body in block.items():
                src = body.get("source", "")
                if not src.startswith("../modules/"):
                    continue
                var_tf = Path(REPO_ROOT, "infra", "modules", src[len("../modules/"):], "variables.tf")
                declared = {next(iter(v)) for v in hcl2.loads(var_tf.read_text(encoding="utf-8")).get("variable", [])}
                for key in ("region", "location"):
                    if key in declared:
                        assert body.get(key) == "${var.region}", (src, key, body.get(key))
                        checked += 1
    assert checked >= 11, checked   # foundation x6, compute x4, cmek (location)


# ------------------------------------------------------------------------------------------------ developer dispatch
def _agent(db=None):
    agent = h.DeveloperAgent.__new__(h.DeveloperAgent)
    agent.db = db
    agent.genai_client = object()          # past the LLM-presence check; nothing reaches an LLM in these tests
    agent._stack_runs, agent._stack_last_trace = {}, None
    return agent


def test_generate_code_files_unresolvable_region_is_typed_before_any_llm(monkeypatch):
    def _none(_db=None, **_kw):   # FD-7M-a: the dispatch passes product_id
        raise te.RegionUnavailable("no platform region configured")
    monkeypatch.setattr(h, "resolve_workload_region", _none)
    monkeypatch.setattr(h.DeveloperAgent, "_resolve_regulated_controls",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("must stop before")))
    with pytest.raises(DeveloperStageError) as exc:
        _agent().generate_code_files("p", "spec", [{"step_id": "S1"}], trace_id="t", **INGRESS)
    assert exc.value.error_class == REGION_UNAVAILABLE


def test_generate_code_files_threads_the_resolved_region_into_the_compliance_check(monkeypatch):
    seen = {}
    monkeypatch.setattr(h, "resolve_workload_region", lambda _db=None, **_kw: OTHER)   # FD-7M-a: + product_id

    def _controls(self, product_id, compliance_decision=None, region=None):
        seen["region"] = region
        raise DeveloperStageError("COMPLIANCE_REGION_NOT_ALLOWED", "stop here")
    monkeypatch.setattr(h.DeveloperAgent, "_resolve_regulated_controls", _controls)
    with pytest.raises(DeveloperStageError):
        _agent().generate_code_files("p", "spec", [{"step_id": "S1"}], trace_id="t", **INGRESS)
    assert seen == {"region": OTHER}


def _decision_db(profile):
    doc = {"compliance_decision": {"profile": profile, "profile_source": "EXPLICIT_REQUEST",
                                   "requested_profile": profile}, "requested_compliance_profile": profile}
    db = MagicMock()
    db.collection.return_value.document.return_value.get.return_value = types.SimpleNamespace(
        exists=True, to_dict=lambda: dict(doc))
    return db


def test_regulated_region_check_uses_the_passed_region():
    """The EU profile allows only EU regions: with the hardcoded region it was refused on every platform; with the
    resolved region an EU platform renders it, and us-central1 behaves exactly as before."""
    agent = _agent(_decision_db("EU_REGIONS_AND_SUPPORT"))
    rc = agent._resolve_regulated_controls("p", region=OTHER)
    assert rc.profile == "EU_REGIONS_AND_SUPPORT" and rc.region == OTHER
    for region in (None, LITERAL):                               # before FD-4AL: always this refusal
        with pytest.raises(DeveloperStageError) as exc:
            agent._resolve_regulated_controls("p", region=region)
        assert exc.value.error_class == "COMPLIANCE_REGION_NOT_ALLOWED" and LITERAL in str(exc.value)
    hipaa = _agent(_decision_db("HIPAA"))
    assert hipaa._resolve_regulated_controls("p") == hipaa._resolve_regulated_controls("p", region=LITERAL)
    with pytest.raises(DeveloperStageError):
        hipaa._resolve_regulated_controls("p", region=OTHER)


# ------------------------------------------------------------------------------------------------ terraform deploy
class _Stop(Exception):
    pass


def _svc(tf, tmp_path):
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="", workspace_base_dir=str(tmp_path),
                              firestore_client=MagicMock())
    svc.db = None
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


TREE = {
    "infra/workload/main.tf": 'module "bucket" {\n  source     = "../modules/storage-bucket"\n'
                              '  project_id = var.project_id\n  region     = var.region\n}\n',
    "infra/workload/variables.tf": 'variable "project_id" {\n  type = string\n}\n\n'
                                   'variable "region" {\n  type    = string\n  default = "us-central1"\n}\n',
}


def _runtime_tfvars(tf, monkeypatch, tmp_path, region):
    svc = _svc(tf, tmp_path)
    monkeypatch.setattr(svc, "_fetch_repo_files", lambda *a, **k: dict(TREE))
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    monkeypatch.setattr(svc, "_resolve_region", lambda: region)
    seen = {}

    def _prepare(pid, trace_id, hcl_files, iac_engine=None, region=None):
        seen["files"], seen["region"] = dict(hcl_files), region
        raise _Stop()
    monkeypatch.setattr(svc, "prepare_workspace", _prepare)
    _no_gcp(monkeypatch)
    with pytest.raises(_Stop):
        svc.deploy_workload(product_id="shop", trace_id="t", target_project_id="p-1", branch="main",
                            iac_engine="OPENTOFU")
    assert seen["region"] == region          # RT F2: the deploy's one region reaches prepare_workspace
    return hcl2.loads(seen["files"]["terraform.tfvars"]), seen["files"]["terraform.tfvars"]


def test_deploy_runtime_tfvars_carry_the_resolved_region(tf, monkeypatch, tmp_path):
    doc, _ = _runtime_tfvars(tf, monkeypatch, tmp_path / "a", OTHER)
    assert doc["region"] == OTHER
    assert doc["container_image"] == f"{OTHER}-docker.pkg.dev/p-1/shop/app:latest"


def test_deploy_runtime_tfvars_us_central1_text_is_unchanged(tf, monkeypatch, tmp_path):
    _doc, text = _runtime_tfvars(tf, monkeypatch, tmp_path / "b", LITERAL)
    assert 'region = "us-central1"\n' in text                                       # the previous exact line
    assert 'container_image = "us-central1-docker.pkg.dev/p-1/shop/app:latest"\n' in text


def test_deploy_without_a_region_is_typed_and_touches_nothing(tf, monkeypatch, tmp_path):
    svc = _svc(tf, tmp_path)

    def _none():
        raise tf.RegionUnavailable(f"{tf.REGION_UNAVAILABLE}: no platform region configured")
    monkeypatch.setattr(svc, "_resolve_region", _none)
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    monkeypatch.setattr(svc, "_fetch_repo_files", lambda *a, **k: (_ for _ in ()).throw(AssertionError("fetched")))
    res = svc.deploy_workload(product_id="shop", trace_id="t", target_project_id="p-1", branch="main",
                              iac_engine="OPENTOFU")
    assert res["status"] == "FAILED" and res["error_class"] == tf.REGION_UNAVAILABLE


def test_helpers_resolve_when_the_caller_passes_no_region(tf, tmp_path):
    """_rollout / purge keep working for direct callers (tf-applier, tests): the platform region (FD-4DE: the
    _reconcile helper was deleted with the startup-probe override)."""
    svc = _svc(tf, tmp_path)
    urls = []
    sess = MagicMock()
    sess.get.side_effect = lambda url, **k: urls.append(url) or types.SimpleNamespace(status_code=404, json=lambda: {})
    with patch.object(svc, "_resolve_region", return_value=OTHER), \
         patch("google.auth.default", return_value=(MagicMock(), "p")), \
         patch("google.auth.transport.requests.AuthorizedSession", return_value=sess):
        svc.detect_errored_child_stubs("child-p")   # RT14-01: read-only successor of the purge
    assert any(f"/locations/{OTHER}/connectors" in u for u in urls), urls
    assert not any(LITERAL in u for u in urls), urls
