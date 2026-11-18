"""SAT-41 (FD-7L pre-switch red-team review, HIGH-2 (b) and LOW-1): tf-applier executions that start on the "wrong"
path after a runner identity mode switch, or that cannot read the mode, end typed instead of silently.

* HIGH-2 (b): Per-workload install, no RUNNER_NONCE, CALLBACK_URL present (a Shared-path start that raced the switch)
  -> the typed FAILED callback RUNNER_EXECUTION_NOT_DISPATCHED through guaranteed_callback_scope, nothing deployed.
  Shared install, RUNNER_NONCE present, no PRODUCT_ID (a vending dispatch that raced the switch back) -> one typed log
  line RUNNER_NONCE_ON_SHARED_INSTALL and exit 1 (the server's dispatch watcher reports it to the workflow).
* LOW-1: a mode that cannot be read never runs the Shared path for an execution with a nonce (typed log, exit 1) or a
  callback URL (the typed FAILED callback with the reader's class).

Do No Harm: a Shared install (mode unset / PLATFORM) without a nonce runs exactly the old path; a Per-workload
execution with its nonce takes the brokered path as before. Hermetic: the callback client is captured.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import logging
import sys

import pytest

from test_fd4g_terraform_workspace import _patched_applier, base, sent_callbacks  # noqa: F401  (fixtures by name)
from shared import runner_identity as ri

MODE = ri.MODE_ENV


def _applier(monkeypatch, base, name, mode=None, nonce=None, product=None, callback=True):
    deployed = []

    def deploy(**kw):
        deployed.append(kw)
        return {"status": "SUCCESS", "service_url": "https://x"}

    applier = _patched_applier(monkeypatch, base, name, deploy)
    for k in (MODE, ri.GUARD_DB_ENV, ri.BROKER_SA_ENV, "RUNNER_NONCE"):
        monkeypatch.delenv(k, raising=False)
    if mode is not None:
        monkeypatch.setenv(MODE, mode)
    if nonce is not None:
        monkeypatch.setenv("RUNNER_NONCE", nonce)
    if product is not None:
        monkeypatch.setenv("PRODUCT_ID", product)
        monkeypatch.setenv("TRACE_ID", "t-sat41")
    if not callback:
        monkeypatch.delenv("CALLBACK_URL", raising=False)
    brokered = []
    monkeypatch.setattr(applier, "run_brokered_job", lambda *a, **k: brokered.append(1) or True)
    return applier, deployed, brokered


def _exit(applier):
    with pytest.raises(SystemExit) as e:
        applier.run_job()
    return e.value.code


# ---------------------------------------------------------------------------------------------- HIGH-2 (b)
def test_per_workload_shared_start_sends_a_typed_failed_callback(monkeypatch, base, sent_callbacks):
    applier, deployed, brokered = _applier(monkeypatch, base, "sat41_pw_shared_start", mode="PER_WORKLOAD",
                                           product="app")
    assert _exit(applier) == 1
    assert not deployed and not brokered
    (cb,) = sent_callbacks
    assert cb["status"] == "FAILED" and cb["error_class"] == "RUNNER_EXECUTION_NOT_DISPATCHED"
    assert cb["operator_required"] is True and cb["product_id"] == "app" and cb["trace_id"] == "t-sat41"
    assert "Nothing was deployed" in cb["error"]


def test_per_workload_shared_start_with_a_bad_trace_still_reports(monkeypatch, base, sent_callbacks):
    applier, deployed, _ = _applier(monkeypatch, base, "sat41_pw_bad_trace", mode="PER_WORKLOAD", product="app")
    monkeypatch.setenv("TRACE_ID", "../escape")
    assert _exit(applier) == 1 and not deployed
    assert sent_callbacks[-1]["error_class"] == "RUNNER_EXECUTION_NOT_DISPATCHED"
    assert sent_callbacks[-1]["trace_id"] == ""


def test_shared_install_dispatched_execution_logs_typed_and_exits(monkeypatch, base, sent_callbacks, caplog):
    applier, deployed, brokered = _applier(monkeypatch, base, "sat41_shared_nonce", mode="PLATFORM", nonce="n-1")
    with caplog.at_level(logging.ERROR):
        assert _exit(applier) == 1
    assert not deployed and not brokered and not sent_callbacks
    assert "RUNNER_NONCE_ON_SHARED_INSTALL" in caplog.text and "n-1" not in caplog.text


# ---------------------------------------------------------------------------------------------- Do No Harm
@pytest.mark.parametrize("mode", [None, "PLATFORM"])
def test_shared_install_without_a_nonce_is_unchanged(monkeypatch, base, sent_callbacks, mode):
    applier, deployed, brokered = _applier(monkeypatch, base, f"sat41_shared_{mode}", mode=mode, product="app")
    assert _exit(applier) == 0
    assert len(deployed) == 1 and not brokered and sent_callbacks[-1]["status"] == "SUCCESS"


def test_shared_install_without_product_is_unchanged(monkeypatch, base, sent_callbacks, caplog):
    applier, deployed, _ = _applier(monkeypatch, base, "sat41_shared_noproduct", mode="PLATFORM")
    with caplog.at_level(logging.ERROR):
        assert _exit(applier) == 1
    assert not deployed and not sent_callbacks and "PRODUCT_ID is required" in caplog.text


@pytest.mark.parametrize("callback", [True, False])
def test_per_workload_with_its_nonce_takes_the_brokered_path(monkeypatch, base, sent_callbacks, callback):
    applier, deployed, brokered = _applier(monkeypatch, base, f"sat41_pw_nonce_{callback}", mode="PER_WORKLOAD",
                                           nonce="n-2", callback=callback)
    assert _exit(applier) == 0
    assert brokered == [1] and not deployed and not sent_callbacks


def test_per_workload_without_nonce_or_callback_takes_the_brokered_path(monkeypatch, base, sent_callbacks):
    """Unchanged: the brokered path refuses typed in its log (no callback URL is known)."""
    applier, deployed, brokered = _applier(monkeypatch, base, "sat41_pw_bare", mode="PER_WORKLOAD", callback=False)
    assert _exit(applier) == 0 and brokered == [1] and not sent_callbacks


# ---------------------------------------------------------------------------------------------- LOW-1
def test_unreadable_mode_with_a_callback_sends_the_readers_class(monkeypatch, base, sent_callbacks):
    applier, deployed, brokered = _applier(monkeypatch, base, "sat41_low1_cb", mode="bogus", product="app")
    assert _exit(applier) == 1
    assert not deployed and not brokered                            # never the Shared path
    (cb,) = sent_callbacks
    assert cb["status"] == "FAILED" and cb["error_class"] == "RUNNER_IDENTITY_MODE_INVALID"
    assert cb["operator_required"] is True and "nothing was deployed" in cb["error"]


def test_unreadable_mode_with_a_nonce_logs_typed_and_exits(monkeypatch, base, sent_callbacks, caplog):
    applier, deployed, brokered = _applier(monkeypatch, base, "sat41_low1_nonce", mode="PLATFORM", nonce="n-3",
                                           callback=False)
    monkeypatch.setenv(ri.BROKER_SA_ENV, "sa-project-provisioner@host.iam.gserviceaccount.com")   # step A, no guard DB
    with caplog.at_level(logging.ERROR):
        assert _exit(applier) == 1
    assert not deployed and not brokered and not sent_callbacks
    assert "RUNNER_STORE_UNAVAILABLE" in caplog.text and "n-3" not in caplog.text
    assert "PRODUCT_ID is required" not in caplog.text


def test_unreadable_mode_without_nonce_or_callback_is_unchanged(monkeypatch, base, sent_callbacks, caplog):
    applier, deployed, _ = _applier(monkeypatch, base, "sat41_low1_bare", mode="bogus", callback=False)
    with caplog.at_level(logging.ERROR):
        assert _exit(applier) == 1
    assert not deployed and not sent_callbacks and "PRODUCT_ID is required" in caplog.text


def test_per_workload_install_helper_is_false_on_a_mode_error(monkeypatch, base):
    applier, _d, _b = _applier(monkeypatch, base, "sat41_low1_helper", mode="bogus")
    assert applier._per_workload_install() is False
    per_workload, err = applier._install_mode()
    assert per_workload is False and err.code == "RUNNER_IDENTITY_MODE_INVALID"
