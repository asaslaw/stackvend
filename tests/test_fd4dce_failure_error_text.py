"""FD-4D-c-e (owner row, 10-24): the terraform server / tf-applier failure path sets the delivered error AFTER the
result is merged into the outcome (``outcome.update(res)``), so the result's own ``error`` (or None) no longer
overwrites the error text, e.g. the tf-applier's GCE_STOCKOUT prefix.

Semantics: the delivered error is the computed one. That is the result's own error when it has one (``err_msg`` is
``res["error"]`` when truthy), else the stderr / stdout / status fallback; on a stockout the tf-applier keeps its
``Cloud capacity deficit (GCE_STOCKOUT): ...`` prefix in front of it.

Negative tests: a result with its own error text delivers exactly that text (unchanged); a SUCCESS path is untouched.
Hermetic: the terraform modules are loaded with fake deploy results and a captured callback.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import sys
from unittest.mock import MagicMock, patch

import pytest

from test_fd4g_terraform_workspace import (  # noqa: F401  (pytest fixtures reused by name)
    _isolated_tf_service, _load_tf_module, _no_network, base, sent_callbacks, tf_main)

STOCKOUT = "Error: ZONE_RESOURCE_POOL_EXHAUSTED: the zone 'us-central1-a' does not have enough resources available"


# ------------------------------------------------------------------------------ terraform server (async worker)
def _run_async(tf_main, result, trace):
    tf_main.service.deploy_workload = MagicMock(return_value=result)
    req = tf_main.AsyncDeployRequest(product_id="app", trace_id=trace, callback_url="http://127.0.0.1:9/cb")
    with patch.object(tf_main, "trigger_tf_applier_job", return_value=False):
        tf_main.run_deploy_in_background(req)


def test_async_result_error_none_no_longer_erases_the_error(tf_main, sent_callbacks):
    _run_async(tf_main, {"status": "FAILED", "error": None, "stderr": "tofu: provider crashed"}, "t-fd4dce-1")
    last = sent_callbacks[-1]
    assert last["status"] == "FAILED" and last["error"] == "tofu: provider crashed"
    assert last["outputs"] == {"service_url": ""}  # FD-102: the outcome's outputs are the deploy's URL only


def test_async_result_without_any_text_gets_the_fallback(tf_main, sent_callbacks):
    _run_async(tf_main, {"status": "FAILED", "error": ""}, "t-fd4dce-2")
    assert sent_callbacks[-1]["error"] == "Terraform deployment failed with status FAILED"


def test_async_result_own_error_is_delivered_unchanged(tf_main, sent_callbacks):
    # Negative (Do No Harm): a result with its own error text keeps exactly that text, and its typed fields stay.
    _run_async(tf_main, {"status": "FAILED", "error": "STATE_LOCKED: held", "error_class": "STATE_LOCKED",
                         "lock_holder": "exec-9"}, "t-fd4dce-3")
    last = sent_callbacks[-1]
    assert last["error"] == "STATE_LOCKED: held" and last["error_class"] == "STATE_LOCKED"
    assert last["lock_holder"] == "exec-9" and last["status"] == "FAILED"


def test_async_success_is_untouched(tf_main, sent_callbacks):
    _run_async(tf_main, {"status": "SUCCESS", "service_url": "https://x"}, "t-fd4dce-4")
    assert sent_callbacks[-1]["status"] == "SUCCESS" and sent_callbacks[-1]["error"] is None


# ------------------------------------------------------------------------------ tf-applier job
def _applier(monkeypatch, base, modname, result):
    applier = _load_tf_module(monkeypatch, base, "applier.py", modname)
    real_cls = applier.TerraformService
    # RT14-01: the stockout branch only lists stubs (read-only detection); nothing is purged
    purge = MagicMock(name="detect_errored_child_stubs",
                      return_value={"connectors": [], "clusters": [], "errors": []})

    def factory(*a, **k):
        inst = real_cls(*a, workspace_base_dir=base, firestore_client=MagicMock(), **k)
        inst.db = None
        inst.deploy_workload = MagicMock(return_value=result)
        inst.detect_errored_child_stubs = purge
        return inst

    monkeypatch.setattr(applier, "TerraformService", factory)
    for k in ("TRACE_ID", "HCL_FILES_JSON", "TARGET_PROJECT_ID", "BRANCH"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PRODUCT_ID", "app")
    monkeypatch.setenv("CALLBACK_URL", "http://127.0.0.1:9/cb")
    monkeypatch.setattr(sys, "argv", ["applier.py"])
    return applier, purge


def _run_applier(applier):
    with pytest.raises(SystemExit) as ei:
        applier.run_job()
    return ei.value.code


def test_applier_stockout_prefix_survives_the_result_error(monkeypatch, base, sent_callbacks):
    applier, purge = _applier(monkeypatch, base, "fd4dce_applier_stockout", {"status": "FAILED", "error": STOCKOUT})
    monkeypatch.setenv("TARGET_PROJECT_ID", "child-1")
    assert _run_applier(applier) == 1
    last = sent_callbacks[-1]
    assert last["status"] == "FAILED"
    assert last["error"] == f"Cloud capacity deficit (GCE_STOCKOUT): {STOCKOUT[:200]}"
    assert last["outputs"] == {"service_url": ""}  # FD-102: the outcome's outputs are the deploy's URL only
    purge.assert_called_once()
    assert purge.call_args.args[0] == "child-1"   # RT14-01: the run's own project, never the product id
    assert last["errored_stubs"] == {"connectors": [], "clusters": [], "errors": []}


def test_applier_result_error_none_no_longer_erases_the_error(monkeypatch, base, sent_callbacks):
    applier, purge = _applier(monkeypatch, base, "fd4dce_applier_none",
                              {"status": "FAILED", "error": None, "stderr": "tofu: plan failed"})
    assert _run_applier(applier) == 1
    assert sent_callbacks[-1]["error"] == "tofu: plan failed"
    purge.assert_not_called()


def test_applier_result_own_error_is_delivered_unchanged(monkeypatch, base, sent_callbacks):
    # Negative (Do No Harm): no stockout, own error text -> exactly that text; the typed apply report still forwarded.
    report = {"status": "FAIL", "diagnostics": [{"code": "TF.X"}]}
    applier, purge = _applier(monkeypatch, base, "fd4dce_applier_own",
                              {"status": "VALIDATION_FAILED", "error": "undeclared resource",
                               "validation_report": report})
    assert _run_applier(applier) == 1
    last = sent_callbacks[-1]
    assert last["error"] == "undeclared resource" and last["validation_report"] == report
    assert last["status"] == "FAILED"
    purge.assert_not_called()
