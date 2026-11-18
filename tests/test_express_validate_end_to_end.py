"""EXP-1 / EXP-2: every Express workload passes OpenTofu's own checks, as generated and in the deploy workspace.

- EXP-1: for a matrix of Express configurations the full rendered tree (infra/workload + vendored infra/modules) runs
  `tofu init -backend=false` + `tofu validate` at the production set (eval/.tools/tofu-1.9.0/tofu +
  eval/.tofu-mirror-prod, offline) with zero diagnostics. A static audit checks that every `module.<x>.<attr>` the
  Express root reads is an output the vendored module declares, and every argument it passes is a declared variable
  (read with the real HCL parser, not text matching).
- EXP-2: every Express `module` block emits the canonical `source = "../modules/<name>"` text, the form the deploy
  path (mcp-servers/terraform/service.py deploy_workload) rewrites to `./infra/modules/<name>` when it flattens
  infra/workload/ into the workspace root. The real deploy_workload flatten + the real prepare_workspace run on an
  Express tree (hermetic: no repo fetch, no GCP, stopped right after the workspace is written) and the workspace
  root must init + validate at the production set.

Real-engine tests skip with a reason when the production column is not on this machine.
"""
import hermetic_guard  # noqa: F401  (first import)

import json
import re  # test-side only: lists module.<x>.<attr> references in python-hcl2 expression strings
import os
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in (REPO_ROOT, os.path.join(REPO_ROOT, "eval")):
    if p not in sys.path:
        sys.path.insert(0, p)

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

import shared.express_synthesizer as express_mod  # noqa: E402
from shared.express_synthesizer import ExpressHCLSynthesizer  # noqa: E402
from shared.access_policy import (AccessMode, AccessPolicy, GoogleIdpMode, SignInPolicy,  # noqa: E402
                                  platform_default_access_policy)

PROD_TOFU = os.path.join(REPO_ROOT, "eval", ".tools", "tofu-1.9.0", "tofu")
PROD_MIRROR = os.path.join(REPO_ROOT, "eval", ".tofu-mirror-prod")
FACT = "10.100.7.0/24"   # a test IPAM allocation (tests only)
EXPRESS_COPIES = ["shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared"]


def _inst(mid, name, params=None):
    return {"module_id": mid, "instance_name": name, "parameters": params or {}}


# name -> synthesize_workload kwargs (product_id/project_id added by _render)
CONFIGS = {
    "default_gateway": {},
    "cloudrun": {"module_instances": [_inst("compute-cloudrun", "api")]},
    "cloudrun_state_bucket": {"module_instances": [_inst("compute-cloudrun", "api")],
                              "state_bucket": "mock-castor-tfstate"},
    "include_vpc": {"module_instances": [_inst("compute-cloudrun", "api")], "include_vpc": True},
    "vpc_instance": {"module_instances": [_inst("networking-vpc", "net"), _inst("compute-cloudrun", "api")]},
    "cloudsql": {"module_instances": [_inst("compute-cloudrun", "api"), _inst("database-cloudsql", "main_pg")],
                 "subnet_cidr": FACT},
    "cloudsql_include_vpc": {"module_instances": [_inst("database-cloudsql", "main_pg")], "include_vpc": True,
                             "subnet_cidr": FACT},
    "cloudsql_no_allocation": {"module_instances": [_inst("database-cloudsql", "main_pg")]},
    "alloydb": {"module_instances": [_inst("database-alloydb", "adb")], "subnet_cidr": FACT},
    "storage": {"module_instances": [_inst("storage-bucket", "invoices")]},
    "pubsub": {"module_instances": [_inst("messaging-pubsub", "order_events")]},
    "event_worker": {"module_instances": [_inst("compute-event-worker", "jobs")]},
    # EXP-4: several event workers, each with its own name_suffix (the instance name)
    "two_event_workers": {"module_instances": [_inst("compute-cloudrun", "api"),
                                               _inst("compute-event-worker", "ingest"),
                                               _inst("compute-event-worker", "nightly_reports")]},
    # RT F4: a generic registered module with parameters whose names differ in length from project_id/depends_on
    "generic_params": {"module_instances": [_inst("tasks-queue", "jobs", {"queue_name_suffix": "jobs",
                                                                         "max_attempts": 3})]},
    "multi_service": {"module_instances": [
        _inst("compute-cloudrun", "gateway"), _inst("compute-cloudrun", "admin"),
        _inst("compute-event-worker", "jobs"), _inst("database-cloudsql", "main_pg"),
        _inst("storage-bucket", "invoices"), _inst("messaging-pubsub", "order_events")],
        "include_vpc": True, "subnet_cidr": FACT},
    # FD-4CS: the workload access record decides each Cloud Run service's exposure (platform default: private, IAP)
    "cloudrun_private_iap": {"module_instances": [_inst("compute-cloudrun", "api"), _inst("compute-cloudrun", "admin")],
                             "access": platform_default_access_policy("user:ana@example.com")},
    "cloudrun_private_iam": {"module_instances": [_inst("compute-cloudrun", "api")],
                             "access": AccessPolicy(mode=AccessMode.PRIVATE_IAM,
                                                    invoker_principals=["group:team@example.com",
                                                                        "user:a${x}@example.com"],  # a literal
                                                    sign_in=SignInPolicy(google=GoogleIdpMode.DISABLED),
                                                    source="intake")},
}


def _render(name, **extra):
    kw = dict(CONFIGS[name])
    kw.update(extra)
    return ExpressHCLSynthesizer().synthesize_workload(product_id="expv", project_id="p-1", **kw)


# Where the synthesizer vendors modules from: the repo tree, the control-center image's own copy (production: the
# CC route runs from apps/control-center, so shared/../infra/modules is apps/control-center/infra/modules), or no
# tree on disk (embedded fallback foundation + BUILTIN_MODULE_FILES payload).
MODULE_SOURCES = {"repo_tree": "infra/modules", "cc_tree": "apps/control-center/infra/modules", "embedded": None}


def _render_from(name, source):
    rel = MODULE_SOURCES[source]
    path = os.path.join(REPO_ROOT, rel) if rel else None
    assert path is None or os.path.isdir(os.path.join(path, "workload-foundation", "base")), path
    with patch.object(express_mod, "get_platform_modules_path", return_value=path):
        return _render(name)


def _write_tree(files, root):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


def _blocks(text, kind):
    return {n: b for block in hcl2.loads(text).get(kind, []) for n, b in block.items()}


def _module_interface(files, source):
    """(declared variables, declared outputs) of the vendored module at `source` (relative to infra/workload)."""
    prefix = os.path.normpath(os.path.join("infra/workload", source)) + "/"
    variables, outputs = set(), set()
    for rel, text in files.items():
        if rel.startswith(prefix) and rel.endswith(".tf") and "/" not in rel[len(prefix):]:
            variables |= set(_blocks(text, "variable"))
            outputs |= set(_blocks(text, "output"))
    assert variables or outputs, f"module {source} not vendored"
    return variables, outputs


def _module_refs(value, found):
    """Collect (module_name, attribute) from every `module.<name>.<attr>` in parsed HCL expressions."""
    if isinstance(value, dict):
        for v in value.values():
            _module_refs(v, found)
    elif isinstance(value, list):
        for v in value:
            _module_refs(v, found)
    elif isinstance(value, str):
        found.update(re.findall(r"\bmodule\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)", value))
    return found


# ------------------------------------------------------------------------------------------------ static
@pytest.mark.parametrize("name", sorted(CONFIGS))
def test_embedded_foundation_is_the_module_on_disk(name):
    """RT F1: without a module tree the foundation comes from the parity-tested payload, so it equals disk."""
    prefix = "infra/modules/workload-foundation/base/"
    disk = {k: v for k, v in _render_from(name, "repo_tree").items() if k.startswith(prefix)}
    embedded = {k: v for k, v in _render_from(name, "embedded").items() if k.startswith(prefix)}
    assert disk and embedded == disk


def test_foundation_unavailable_fails_closed():
    with patch.object(express_mod, "get_platform_modules_path", return_value=None), \
            patch.object(express_mod, "BUILTIN_MODULE_FILES", {}):
        with pytest.raises(RuntimeError, match="workload-foundation/base is unavailable"):
            _render("default_gateway")


def test_event_workers_with_the_same_name_suffix_are_refused_with_a_typed_error():
    """EXP-4 (was RT F3): several event workers are rendered with their instance names as name_suffix; two whose
    suffixes are equal would collide at apply, so Express refuses them (typed)."""
    instances = [_inst("compute-cloudrun", "api"), _inst("compute-event-worker", "jobs"),
                 _inst("compute-event-worker", "Jobs")]
    with pytest.raises(express_mod.ExpressModuleNameCollisionError) as err:
        ExpressHCLSynthesizer().synthesize_workload(product_id="expv", project_id="p-1", module_instances=instances)
    assert isinstance(err.value, express_mod.ExpressSynthesisRefused) and isinstance(err.value, ValueError)
    assert err.value.reason == "EXPRESS_MODULE_NAME_COLLISION"
    assert err.value.module_id == "compute-event-worker" and err.value.name_suffix == "jobs"
    assert err.value.instance_names == ["jobs", "Jobs"]
    # negative: one event worker (with other modules) is unaffected and passes no name_suffix
    files = ExpressHCLSynthesizer().synthesize_workload(product_id="expv", project_id="p-1",
                                                        module_instances=instances[:2])
    assert 'module "worker_jobs"' in files["infra/workload/main.tf"]
    assert "name_suffix" not in files["infra/workload/main.tf"]


def test_generic_module_arguments_are_padded_to_the_longest_name():
    """RT F4: one contiguous argument run with `=` aligned (tofu fmt layout); values are written as before."""
    main = _render("generic_params")["infra/workload/main.tf"]
    assert '''module "mod_jobs" {
  source = "../modules/tasks-queue"

  project_id        = var.project_id
  queue_name_suffix = "jobs"
  max_attempts      = 3
  depends_on        = [module.foundation]
}''' in main
    # Do No Harm: a generic block whose names are all 10 characters long (AlloyDB defaults) keeps its layout.
    alloy = _render("alloydb")["infra/workload/main.tf"]
    assert '''  project_id = var.project_id
  network    = module.network.network_id
  product_id = var.product_id
  depends_on = [module.foundation, module.network]
}''' in alloy


def test_express_replicas_identical():
    texts = [Path(REPO_ROOT, rel, "express_synthesizer.py").read_text(encoding="utf-8") for rel in EXPRESS_COPIES]
    assert texts[0] == texts[1] == texts[2]


@pytest.mark.parametrize("source", sorted(MODULE_SOURCES))
@pytest.mark.parametrize("name", sorted(CONFIGS))
def test_every_module_read_and_argument_is_declared_by_the_vendored_module(name, source):
    files = _render_from(name, source)
    root = {rel: t for rel, t in files.items() if rel.startswith("infra/workload/") and rel.endswith(".tf")}
    modules = {}
    for text in root.values():
        modules.update(_blocks(text, "module"))
    meta = {"source", "depends_on", "count", "for_each", "providers", "version"}
    problems = []
    refs = set()
    for text in root.values():
        _module_refs(hcl2.loads(text), refs)
    for mod_name, attr in sorted(refs):
        assert mod_name in modules, f"reference to undeclared module.{mod_name}"
        _, outs = _module_interface(files, modules[mod_name]["source"])
        if attr not in outs:
            problems.append(f"module.{mod_name}.{attr} (outputs: {sorted(outs)})")
    for mod_name, block in modules.items():
        variables, _ = _module_interface(files, block["source"])
        for arg in set(block) - meta - {"__start_line__", "__end_line__"}:
            if arg not in variables:
                problems.append(f"module.{mod_name} argument {arg!r} is not a variable of {block['source']}")
    assert problems == []


def _module_source_lines(files):
    lines = []
    for rel, text in files.items():
        if rel.startswith("infra/workload/") and rel.endswith(".tf"):
            for name, block in _blocks(text, "module").items():
                lines.append((rel, name, block["source"],
                              [ln for ln in text.splitlines() if ln.strip().startswith("source")
                               and block["source"] in ln]))
    return lines


@pytest.mark.parametrize("name", sorted(CONFIGS))
def test_every_module_source_is_the_canonical_text(name):
    files = _render(name)
    found = _module_source_lines(files)
    assert found
    for rel, mod, src, lines in found:
        assert src.startswith("../modules/"), (rel, mod, src)
        assert f'  source = "{src}"' in lines, (rel, mod, lines)


# ------------------------------------------------------------------------------------------------ real engine
@pytest.fixture(scope="module")
def runner(tmp_path_factory):
    if not (os.access(PROD_TOFU, os.X_OK) and os.path.isdir(PROD_MIRROR)):
        pytest.skip("production column eval/.tools/tofu-1.9.0/tofu + eval/.tofu-mirror-prod (untracked) not present")
    from stackvend_eval.tofu_runner import TofuRunner
    r = TofuRunner(tmp_path_factory.mktemp("expv-tofu"), Path(PROD_MIRROR), tofu_bin=PROD_TOFU)
    if not r.mirror_ready:
        pytest.skip(f"production mirror not verified: {r.mirror_manifest['status']}")
    return r


def _init_validate_json(runner, wd):
    r = runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-3000:]
    r = runner._run(["validate", "-json", "-no-color"], cwd=wd)
    out = json.loads(r.stdout)
    return r.returncode, out


@pytest.mark.parametrize("source", sorted(MODULE_SOURCES))
@pytest.mark.parametrize("name", sorted(CONFIGS))
def test_express_tree_validates_at_production_set(runner, tmp_path, name, source):
    files = _render_from(name, source)
    _write_tree(files, tmp_path)
    wd = tmp_path / "infra" / "workload"
    rc, out = _init_validate_json(runner, wd)
    assert rc == 0 and out["valid"] is True and out["diagnostics"] == [], json.dumps(out)[-3000:]
    r = runner._run(["fmt", "-check", "-no-color"], cwd=wd)   # the root Express writes is tofu-fmt canonical
    assert r.returncode == 0, (r.stdout + r.stderr)[-2000:]


# ------------------------------------------------------------------------------------------------ deploy path (EXP-2)
class _StopAfterWorkspace(Exception):
    pass


def _deploy_workspace(monkeypatch, base, files, product_id="expv"):
    """Runs the REAL deploy_workload flatten and the REAL prepare_workspace on `files` (as the repo contents),
    then stops: no repo fetch, no Firestore, no Secret Manager / API-key calls, no container build, no tofu."""
    from fd4g_support import load_tf_service
    tfsvc = load_tf_service(monkeypatch)
    svc = tfsvc.TerraformService(project_id="mock-stackvend-project", state_bucket="", workspace_base_dir=str(base),
                                 firestore_client=MagicMock())
    svc.db = None
    svc.state_bucket = ""
    monkeypatch.setattr(svc, "_fetch_repo_files", lambda *a, **k: dict(files))
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    real_prepare = svc.prepare_workspace
    seen = {}

    def _prepare(pid, trace_id, hcl_files, iac_engine=None, region=None):   # no engine download: iac_engine not passed on
        seen["dir"] = real_prepare(pid, trace_id, hcl_files)
        raise _StopAfterWorkspace()

    monkeypatch.setattr(svc, "prepare_workspace", _prepare)
    # deploy_workload does `from google.cloud import secretmanager` and `import google.auth` inline. Other root tests
    # may leave google.* mocked in sys.modules, so the fakes are set on whatever package objects are current
    # (monkeypatch restores both afterwards) instead of patching by dotted path.
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
    with pytest.raises(_StopAfterWorkspace):
        svc.deploy_workload(product_id=product_id, trace_id="expv-trace", target_project_id="p-1",
                            branch="main", iac_engine="OPENTOFU")
    return Path(seen["dir"])


DEPLOY_CONFIGS = ["default_gateway", "include_vpc", "cloudsql", "alloydb", "multi_service", "cloudrun_private_iap"]


def test_deploy_workspace_keeps_the_iap_service_agent(monkeypatch, tmp_path):
    """FD-4CS-b: the terraform server's workspace preparation (its compute-cloudrun text healer strips only an `iap_sa`
    identity block) keeps the module's IAP service agent and the invoker binding's dependency on it."""
    ws = _deploy_workspace(monkeypatch, tmp_path / "ws", _render("cloudrun_private_iap"))
    parsed = hcl2.loads((ws / "infra" / "modules" / "compute-cloudrun" / "main.tf").read_text(encoding="utf-8"))
    res = {}
    for block in parsed.get("resource", []):
        for rtype, named in block.items():
            res.update({(rtype, n): b for n, b in named.items()})
    assert ("google_project_service_identity", "iap_service_agent") in res
    assert res[("google_cloud_run_v2_service_iam_member", "iap_agent_invoker")]["depends_on"] == [
        "${google_project_service_identity.iap_service_agent}"]


@pytest.mark.parametrize("name", DEPLOY_CONFIGS)
def test_deploy_flatten_rewrites_every_express_module_source(monkeypatch, tmp_path, name):
    files = _render(name)
    ws = _deploy_workspace(monkeypatch, tmp_path / "ws", files)
    for fn in ("main.tf", "outputs.tf", "variables.tf", "versions.tf"):
        assert (ws / fn).is_file(), fn
    sources = [b["source"] for b in _blocks((ws / "main.tf").read_text(encoding="utf-8"), "module").values()]
    assert sources and all(s.startswith("./infra/modules/") for s in sources), sources
    for s in sources:
        assert (ws / s).is_dir(), s


# Integration: was a strict xfail on main; FD-4BD's parsed tfvars merge (deploy workspace) keeps the IPAM fact,
# so it passes now (the marker would turn the pass into a strict XPASS failure).
def test_deploy_workspace_keeps_the_ipam_subnet_fact(monkeypatch, tmp_path):
    files = _render("cloudsql")
    assert files["infra/workload/terraform.tfvars"] == f'subnet_cidr = "{FACT}"\n'
    ws = _deploy_workspace(monkeypatch, tmp_path / "ws", files)
    assert "subnet_cidr" in hcl2.loads((ws / "terraform.tfvars").read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", DEPLOY_CONFIGS)
def test_deploy_workspace_root_validates_at_production_set(runner, monkeypatch, tmp_path, name):
    files = _render(name)
    ws = _deploy_workspace(monkeypatch, tmp_path / "ws", files)
    # prepare_workspace also links <trace>/modules -> this product's infra/modules (only when absent, so the first
    # product in a trace wins). The workspace root must not depend on it: with canonical sources rewritten to
    # ./infra/modules/ it resolves on its own. (Before EXP-2 the root kept ../modules/ and resolved only via it.)
    trace_link = ws.parent / "modules"
    assert trace_link.is_symlink()
    trace_link.unlink()
    rc, out = _init_validate_json(runner, ws)
    assert rc == 0 and out["valid"] is True, json.dumps(out)[-3000:]
