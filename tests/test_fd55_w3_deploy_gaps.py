"""FD-55 W3 (+ FD55-TFVARS): the deploy's remaining text writes on typed-intent workspaces, the stale write-back and
the unparseable-tfvars / module-source rule (mcp-servers/terraform/service.py, register rows FD55-W3, FD55-TFVARS).

- A30 (HA-31 intent guard): on a typed-intent workspace a vendored golden-module file that differs from the platform
  payload is applied exactly as committed and reported (PLATFORM.VENDORED_MODULE_STALE); never overwritten, never
  written back. FD-55 W6d extended this to legacy workspaces (the W3 negative test now pins the same behaviour).
- A31: W3 tied a write-back entry to the preparation that recorded it; FD-55 W6b deleted the write-back (nothing is
  recorded, nothing is committed; mutant guards below and in tests/test_fd55_w6bd_no_writeback.py).
- A42 (intent guard): the pre-apply tfvars reconciler writes no guessed value on a typed-intent workspace. FD-55 W6c
  (register FD55-W6c) deleted the reconciler, so a legacy workspace gets none either.
- A54 (deleted): main.tf is never read or written for the OAuth client id / Firebase key / auth domain; the values
  reach Terraform only as variables (terraform.tfvars / TF_VAR_*).
- FD55-TFVARS: a workload terraform.tfvars or flattened root .tf python-hcl2 cannot parse stops the deploy with
  APPLY.TFVARS_UNPARSEABLE / APPLY.SOURCE_UNPARSEABLE (error_class IAC_DEFECT, nothing built or run); a parseable
  tfvars with a heredoc / nested map keeps every key byte-identical (Do No Harm).

Hermetic: no repo fetch, no Secret Manager, no ADC, no network, no tofu (the deploy stops at the first tofu call).
"""
import hermetic_guard  # noqa: F401  (first import)

import logging
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
STALE_MODULE_MAIN = 'resource "google_cloud_run_v2_service" "app" {}\n'   # differs from the golden payload

MAIN = (
    'module "compute" {\n'
    '  source          = "../modules/compute-cloudrun"\n'
    '  project_id      = var.project_id\n'
    '  region          = var.region\n'
    '  service_name    = "shop"\n'
    '  container_image = var.container_image\n'
    '  subnet          = var.subnet_cidr\n'
    '}\n'
)
VARIABLES = (
    'variable "project_id" {\n  type = string\n}\n\n'
    'variable "region" {\n  type    = string\n  default = "us-central1"\n}\n\n'
    'variable "container_image" {\n  type    = string\n  default = ""\n}\n\n'
    'variable "subnet_cidr" {\n  type = string\n}\n'          # no default and no value: the reconciler's target
)
APPS = {"apps/shop/main.py": "app = None\n", "apps/shop/requirements.txt": "fastapi\n"}
INTENT_FILES = {
    W + "iac_intent.json": '{"schema": "iac_intent/v1", "modules": []}\n',
    W + "custom.tf.json": '{"//": "Rendered by StackVend"}\n',
    W + "topology.json": ('{"schema": "service_topology/v1", "intent": {"services": [{"name": "shop", "kind": '
                          '"cloudrun"}], "primary_service": "shop", "edges": [], "resources": []}}'),
}


def _legacy_tree(**extra):
    return {W + "main.tf": MAIN, W + "variables.tf": VARIABLES, **APPS, **extra}


def _intent_tree(**extra):
    return dict(_legacy_tree(**extra), **INTENT_FILES)


@pytest.fixture
def tf(monkeypatch):
    return load_tf_service(monkeypatch)


class _StopAtTofu(BaseException):
    """Raised by the first tofu call: everything the deploy writes before plan/apply has been written."""


CLIENT_ID = "1234-fd55w3.apps.googleusercontent.com"   # test value (a client id is public, not a secret)


def _no_gcp(monkeypatch):
    """No ADC; a Secret Manager fake that knows only the install's client id (so a text paster would have a value)."""
    import google.auth
    import google.cloud

    class _SM:
        def __init__(self, *a, **k):
            pass

        def access_secret_version(self, name):
            if name.endswith("/secrets/castor-oauth-client-id/versions/latest"):
                return types.SimpleNamespace(payload=types.SimpleNamespace(data=CLIENT_ID.encode("utf-8")))
            raise RuntimeError("unknown secret")

    def _no_adc(*_a, **_k):
        raise RuntimeError("no ADC in tests")

    fake_sm = types.ModuleType("google.cloud.secretmanager")
    fake_sm.SecretManagerServiceClient = _SM
    monkeypatch.setitem(sys.modules, "google.cloud.secretmanager", fake_sm)
    monkeypatch.setattr(sys.modules["google.cloud"], "secretmanager", fake_sm, raising=False)
    monkeypatch.setattr(sys.modules["google.auth"], "default", _no_adc, raising=False)


def _read(ws, rel):
    with open(os.path.join(ws, rel), encoding="utf-8", newline="") as fh:   # exact bytes: no CRLF translation
        return fh.read()


def _service(tf, monkeypatch, tmp_path, files):
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="",
                              workspace_base_dir=str(tmp_path / "base"), firestore_client=MagicMock())
    svc.db = None
    svc.state_bucket = ""
    monkeypatch.setenv("GITHUB_ORG", "acme-test")
    monkeypatch.setattr(svc, "_fetch_repo_files", lambda *a, **k: dict(files))
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    monkeypatch.setattr(svc, "_ensure_binary", lambda *a, **k: "tofu")
    _no_gcp(monkeypatch)
    vcs = MagicMock(name="vcs")
    factory = MagicMock(name="VCSProviderFactory")
    factory.get_provider.return_value = vcs
    monkeypatch.setattr(tf, "VCSProviderFactory", factory)
    return svc, vcs


def _deploy(tf, monkeypatch, tmp_path, files, trace_id="t-deploy", svc_vcs=None):
    """The REAL deploy_workload up to the first tofu call (or its typed early return). Returns
    (result or None when it reached tofu, seen dict, vcs mock)."""
    svc, vcs = svc_vcs or _service(tf, monkeypatch, tmp_path, files)
    seen = {"built": False}

    def _build(product_id, target_project_id, workspace_dir, image_tag, ar_repo_name=None, region=None):
        seen["built"] = True
        return True

    def _tofu(*_a, **kw):
        seen["ws"] = kw.get("cwd")
        raise _StopAtTofu()

    monkeypatch.setattr(svc, "_build_and_push_container", _build)
    monkeypatch.setattr(svc, "_run_subprocess", _tofu)
    try:
        res = svc.deploy_workload(product_id="shop", trace_id=trace_id, target_project_id=PROJECT,
                                  branch="main", iac_engine="OPENTOFU")
    except _StopAtTofu:
        res = None
    return res, seen, vcs


# ------------------------------------------------------------------------------------------------ A30 / HA-31
def test_intent_stale_vendored_module_is_applied_as_committed_and_reported(tf, monkeypatch, tmp_path, caplog):
    files = _intent_tree(**{"infra/modules/compute-cloudrun/main.tf": STALE_MODULE_MAIN})
    caplog.set_level(logging.WARNING, logger="mcp-terraform-server")
    res, seen, vcs = _deploy(tf, monkeypatch, tmp_path, files)
    assert res is None, res
    assert _read(seen["ws"], "infra/modules/compute-cloudrun/main.tf") == STALE_MODULE_MAIN   # byte-identical
    vcs.commit_files.assert_not_called()                                                       # nothing written back
    assert any("PLATFORM.VENDORED_MODULE_STALE" in r.getMessage()
               and "infra/modules/compute-cloudrun/main.tf" in r.getMessage() for r in caplog.records)


def test_legacy_stale_vendored_module_is_applied_as_committed_and_reported(tf, monkeypatch, tmp_path, caplog):
    """FD-55 W6d (register FD55-W6b+W6d; was the W3 legacy negative "still refreshed and committed"): a legacy
    workspace is treated like an intent one: the stale module is applied as committed, reported, never written back."""
    files = _legacy_tree(**{"infra/modules/compute-cloudrun/main.tf": STALE_MODULE_MAIN})
    caplog.set_level(logging.WARNING, logger="mcp-terraform-server")
    res, seen, vcs = _deploy(tf, monkeypatch, tmp_path, files)
    assert res is None, res
    assert _read(seen["ws"], "infra/modules/compute-cloudrun/main.tf") == STALE_MODULE_MAIN
    vcs.commit_files.assert_not_called()
    assert any("PLATFORM.VENDORED_MODULE_STALE" in r.getMessage()
               and "infra/modules/compute-cloudrun/main.tf" in r.getMessage() for r in caplog.records)


# ------------------------------------------------------------------------------------------------ A31
def test_earlier_plan_never_leads_to_a_commit_by_a_later_deploy(tf, monkeypatch, tmp_path):
    """W3 dropped a stale write-back entry left by generate_plan; FD-55 W6b deleted the write-back itself: neither the
    plan's preparation nor the later deploy records or commits anything."""
    stale = _legacy_tree(**{"infra/modules/compute-cloudrun/main.tf": STALE_MODULE_MAIN})
    svc_vcs = _service(tf, monkeypatch, tmp_path, stale)
    svc, vcs = svc_vcs
    svc.prepare_workspace("shop", "t-plan", dict(stale))
    assert not hasattr(svc, "_last_healed_files") and not hasattr(svc, "_last_healed_traces")
    res, _seen, _vcs = _deploy(tf, monkeypatch, tmp_path, None, svc_vcs=svc_vcs)
    assert res is None, res
    vcs.commit_files.assert_not_called()


def test_a_leftover_write_back_record_is_never_committed(tf, monkeypatch, tmp_path):
    """Mutant guard (FD-55 W6b): a write-back record in the old shape, even one tagged with THIS deploy's trace (the
    case the W3 deploy committed), is never read or committed."""
    svc, vcs = _service(tf, monkeypatch, tmp_path, _legacy_tree())
    real_prepare = svc.prepare_workspace

    def _prepare_then_record(product_id, trace_id, files, **kw):
        ws = real_prepare(product_id, trace_id, files, **kw)
        svc._last_healed_files = {product_id: {"infra/modules/compute-cloudrun/main.tf": "x"}}
        svc._last_healed_traces = {product_id: trace_id}
        return ws

    monkeypatch.setattr(svc, "prepare_workspace", _prepare_then_record)
    res, _seen, _vcs = _deploy(tf, monkeypatch, tmp_path, None, svc_vcs=(svc, vcs))
    assert res is None, res
    vcs.commit_files.assert_not_called()


# ------------------------------------------------------------------------------------------------ A42
def _root_tfvars(seen):
    return hcl2.loads(_read(seen["ws"], "terraform.tfvars"))


def test_intent_workspace_gets_no_guessed_variable_values(tf, monkeypatch, tmp_path):
    res, seen, _vcs = _deploy(tf, monkeypatch, tmp_path, _intent_tree())
    assert res is None, res
    assert "subnet_cidr" not in _root_tfvars(seen)          # no made-up network range


def test_legacy_workspace_gets_no_guessed_variable_values_either(tf, monkeypatch, tmp_path):
    """FD-55 W6c (A42 DELETED): the reconciler is gone, so a referenced variable without a default gets no value on a
    non-intent workspace either (before W6c it got a name-based guess; OpenTofu now reports the missing value)."""
    res, seen, _vcs = _deploy(tf, monkeypatch, tmp_path, _legacy_tree())
    assert res is None, res
    assert "subnet_cidr" not in _root_tfvars(seen)


# ------------------------------------------------------------------------------------------------ A54
OAUTH_MAIN = MAIN + (
    'resource "google_cloud_run_v2_service" "web" {\n'
    '  name     = "web"\n'
    '  location = var.region\n'
    '  template {\n'
    '    containers {\n'
    '      image = var.container_image\n'
    '      env {\n'
    '        name  = "GOOGLE_CLIENT_ID"\n'
    '        value = ""\n'
    '      }\n'
    '      env {\n'
    '        name  = "FIREBASE_AUTH_DOMAIN"\n'
    '        value = ""\n'
    '      }\n'
    '    }\n'
    '  }\n'
    '}\n'
)


def test_legacy_main_tf_env_values_are_not_pasted(tf, monkeypatch, tmp_path):
    """A hand-written main.tf with `GOOGLE_CLIENT_ID` / `FIREBASE_AUTH_DOMAIN` env values of "" keeps them: before,
    every `value = ""` in the file became the client id and the domain was pasted (A54). (Other legacy healers of
    prepare_workspace still edit this file until FD-55 W6; only these values are checked here.)"""
    tree = _legacy_tree()
    tree[W + "main.tf"] = OAUTH_MAIN
    res, seen, _vcs = _deploy(tf, monkeypatch, tmp_path, tree)
    assert res is None, res
    main = _read(seen["ws"], "main.tf")
    assert 'name  = "GOOGLE_CLIENT_ID"\n        value = ""' in main
    assert 'name  = "FIREBASE_AUTH_DOMAIN"\n        value = ""' in main
    assert "firebaseapp.com" not in main and CLIENT_ID not in main


def test_intent_main_tf_is_never_edited_for_sign_in_values(tf, monkeypatch, tmp_path):
    tree = _intent_tree()
    tree[W + "main.tf"] = OAUTH_MAIN
    res, seen, _vcs = _deploy(tf, monkeypatch, tmp_path, tree)
    assert res is None, res
    # the FD-4BW source re-anchoring is the only change from the repository text
    expected = OAUTH_MAIN.replace('"../modules/compute-cloudrun"', '"./infra/modules/compute-cloudrun"')
    assert _read(seen["ws"], "main.tf") == expected
    tfvars = _root_tfvars(seen)
    assert "firebase_auth_domain" in tfvars   # the value travels as a variable (AQ-2: "" without PUBLIC_APP access)


# ------------------------------------------------------------------------------------------------ FD55-TFVARS
@pytest.mark.parametrize("intent", [False, True], ids=["legacy", "intent"])
def test_unparseable_tfvars_is_a_typed_stop(tf, monkeypatch, tmp_path, intent):
    tree = (_intent_tree if intent else _legacy_tree)(**{W + "terraform.tfvars": 'subnet_cidr = "10.1.0.0/24\n'})
    res, seen, vcs = _deploy(tf, monkeypatch, tmp_path, tree)
    assert res and res["status"] == "FAILED", res
    assert res["error_class"] == "IAC_DEFECT" and res["code"] == "APPLY.TFVARS_UNPARSEABLE"
    assert res["error"].startswith(f"APPLY.TFVARS_UNPARSEABLE: {W}terraform.tfvars is not parseable")
    assert "at line 1, column" in res["error"] and "10.1.0.0" not in res["error"]   # position only, no text
    assert not seen["built"] and "ws" not in seen
    vcs.commit_files.assert_not_called()


def test_unparseable_root_tf_is_a_typed_stop(tf, monkeypatch, tmp_path):
    tree = _legacy_tree(**{W + "custom.tf": 'module "db" {\n  source = "../modules/cloudsql"\n'})   # no closing brace
    res, seen, _vcs = _deploy(tf, monkeypatch, tmp_path, tree)
    assert res and res["status"] == "FAILED", res
    assert res["error_class"] == "IAC_DEFECT" and res["code"] == "APPLY.SOURCE_UNPARSEABLE"
    assert W + "custom.tf" in res["error"] and "cloudsql" not in res["error"]   # the parser position, no text
    assert not seen["built"] and "ws" not in seen


def test_unparseable_nested_file_is_still_kept_as_written(tf, monkeypatch, tmp_path):
    """Negative (FD-4D-b unchanged): a nested workload file python-hcl2 cannot parse was never regex-rewritten; it is
    copied as written and the deploy continues."""
    broken = 'module "x" {\n  source = "../y"\n'
    res, seen, _vcs = _deploy(tf, monkeypatch, tmp_path, _intent_tree(**{W + "modules/db/main.tf": broken}))
    assert res is None, res
    assert _read(seen["ws"], "modules/db/main.tf") == broken


def test_parseable_tfvars_with_heredoc_and_nested_map_keeps_every_key_byte_identical(tf, monkeypatch, tmp_path):
    workload_tfvars = (
        'subnet_cidr = "10.100.7.0/24"\n'
        'labels = {\n  team = "claims"\n  tier = { level = "gold" }\n}\n'
        'startup_script = <<-EOT\n    #!/bin/bash\n    echo "hi"\n  EOT\n'
    )
    res, seen, _vcs = _deploy(tf, monkeypatch, tmp_path, _legacy_tree(**{W + "terraform.tfvars": workload_tfvars}))
    assert res is None, res
    root = _read(seen["ws"], "terraform.tfvars")
    assert 'subnet_cidr = "10.100.7.0/24"\n' in root
    assert 'labels = {\n  team = "claims"\n  tier = { level = "gold" }\n}\n' in root
    assert 'startup_script = <<-EOT\n    #!/bin/bash\n    echo "hi"\n  EOT\n' in root


# ------------------------------------------------------------------------------------------------ F1: lexable view
# OpenTofu 1.9.0 validates/plans all three forms; python-hcl2 7.3.1's lexer rejects them as written. The parser reads
# a view (BOM dropped, CRLF read as LF, a final newline added) and every offset maps back to the ORIGINAL text,
# which is never rewritten.
def _crlf(text):
    return text.replace("\n", "\r\n")


def test_lexable_view_maps_every_offset_to_the_original(tf):
    text = '﻿a = 1\r\nb = "x"\r\n# end'
    view, orig = tf._hcl2_lexable_view(text)
    assert view == 'a = 1\nb = "x"\n# end\n'
    assert len(orig) == len(view) + 1 and orig[-1] == len(text) and orig == sorted(orig)
    assert all(text[orig[i]] == view[i] for i in range(len(view)) if view[i] != "\n")
    assert [text[orig[i]] for i in range(len(view) - 1) if view[i] == "\n"] == ["\r", "\r"]   # CRLF -> its \r
    assert orig[len(view) - 1] == len(text)                                                 # the added newline


def test_lexable_view_of_plain_text_is_the_text(tf):
    """Do No Harm: an LF file ending in a newline is parsed exactly as before (identity map)."""
    view, orig = tf._hcl2_lexable_view(MAIN)
    assert view == MAIN and orig == list(range(len(MAIN) + 1))


def test_crlf_module_source_rewrite_keeps_every_crlf(tf):
    out = tf.rewrite_flattened_module_sources(_crlf(MAIN), filename=W + "main.tf")
    assert out == _crlf(MAIN.replace('"../modules/compute-cloudrun"', '"./infra/modules/compute-cloudrun"'))


def test_bom_module_source_rewrite_keeps_the_bom(tf):
    out = tf.rewrite_flattened_module_sources("﻿" + MAIN, filename=W + "main.tf")
    assert out == "﻿" + MAIN.replace('"../modules/compute-cloudrun"', '"./infra/modules/compute-cloudrun"')


def test_crlf_root_main_tf_deploys_with_only_the_source_changed(tf, monkeypatch, tmp_path):
    tree = _intent_tree()
    tree[W + "main.tf"] = _crlf(MAIN)
    res, seen, _vcs = _deploy(tf, monkeypatch, tmp_path, tree)
    assert res is None, res
    assert _read(seen["ws"], "main.tf") == _crlf(
        MAIN.replace('"../modules/compute-cloudrun"', '"./infra/modules/compute-cloudrun"'))


def test_crlf_tfvars_keys_are_merged_byte_identical(tf, monkeypatch, tmp_path):
    tfvars = _crlf('subnet_cidr = "10.100.7.0/24"\nlabels = {\n  team = "claims"\n}\n')
    res, seen, _vcs = _deploy(tf, monkeypatch, tmp_path, _intent_tree(**{W + "terraform.tfvars": tfvars}))
    assert res is None, res
    root = _read(seen["ws"], "terraform.tfvars")
    assert 'subnet_cidr = "10.100.7.0/24"\n' in root
    assert 'labels = {\r\n  team = "claims"\r\n}\n' in root            # the value's own CRLFs kept
    assert hcl2.loads(root.replace("\r\n", "\n"))["labels"] == {"team": "claims"}


@pytest.mark.parametrize("text", ["# placeholder", "// placeholder", "﻿# placeholder\n",
                                  _crlf("# placeholder\n")], ids=["hash-eof", "slash-eof", "bom", "crlf"])
def test_comment_only_root_file_lets_the_deploy_continue(tf, monkeypatch, tmp_path, text):
    res, seen, _vcs = _deploy(tf, monkeypatch, tmp_path, _intent_tree(**{W + "versions.tf": text}))
    assert res is None, res
    assert _read(seen["ws"], "versions.tf") == text                   # never rewritten


def test_bom_tfvars_and_main_tf_let_the_deploy_continue(tf, monkeypatch, tmp_path):
    tree = _intent_tree(**{W + "terraform.tfvars": '﻿subnet_cidr = "10.100.7.0/24"\n'})
    tree[W + "main.tf"] = "﻿" + MAIN
    res, seen, _vcs = _deploy(tf, monkeypatch, tmp_path, tree)
    assert res is None, res
    assert 'subnet_cidr = "10.100.7.0/24"\n' in _read(seen["ws"], "terraform.tfvars")
    assert _read(seen["ws"], "main.tf").startswith("﻿module \"compute\"")


@pytest.mark.parametrize("broken", ['module "db" {\r\n  source = "../modules/cloudsql"\r\n',
                                    '﻿module "db" {\n  source = "../modules/cloudsql"\n'], ids=["crlf", "bom"])
def test_genuinely_unparseable_crlf_or_bom_file_still_stops(tf, monkeypatch, tmp_path, broken):
    res, seen, _vcs = _deploy(tf, monkeypatch, tmp_path, _legacy_tree(**{W + "custom.tf": broken}))
    assert res and res["code"] == "APPLY.SOURCE_UNPARSEABLE", res
    assert not seen["built"]
