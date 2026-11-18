"""SAT-41 (FD-7L pre-switch red-team review, HIGH-2 (c)): the terraform server's dispatch-watch sweep is not gated on
the runner identity mode. Its decisions come from vending's signed dispatch records, so after a switch back to Shared it
still reports an execution dispatched under Per workload that never redeemed its nonce (one that starts on the Shared
path exits without a callback): TF_APPLIER_EXECUTION_FAILED_BEFORE_REDEEM, at most once.

The sweeper thread starts on a Per-workload install, after any switch in Settings (a change entry exists) and when the
mode or the change log cannot be read. Do No Harm: a Shared install that never switched starts no sweeper and reads
nothing (no guard database configured: not even the change log). Hermetic fakes only.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import pytest

from test_fd4g_terraform_workspace import (  # noqa: F401  (pytest fixtures reused by name)
    _isolated_tf_service, _load_tf_module, base, sent_callbacks)
from test_fd7l_5a_dispatch import (  # noqa: F401  (fixtures and fakes reused by name)
    CALLBACK, MODE, PRODUCT, _post, per_workload, tf_main)
from test_fd7l_5a_watcher import DISPATCH_ID, T0, Clock, _nonce_record


def _dispatch(tf_main, vending, guard):
    ri = tf_main.ri
    tf_main.WATCH_CLOCK = Clock(T0 + 1)
    guard.docs[(ri.NONCE_COLLECTION, DISPATCH_ID)] = _nonce_record(ri)
    vending.body["dispatch_id"] = DISPATCH_ID
    assert _post(tf_main, "/deploy-async", {"product_id": PRODUCT, "trace_id": "t1",
                                            "callback_url": CALLBACK}).status_code == 202
    assert tf_main.watches.docs[DISPATCH_ID]["state"] == "WATCHING"


def test_sweep_after_a_switch_back_to_shared_reports_the_unredeemed_dispatch(per_workload, sent_callbacks,
                                                                              monkeypatch):
    tf_main, vending, guard = per_workload
    _dispatch(tf_main, vending, guard)
    # the switch back: the dispatching instance's timer is gone (e.g. the instance stopped)
    monkeypatch.setenv(MODE, "PLATFORM")
    monkeypatch.setattr(tf_main, "install_runner_identity_mode", lambda: "PLATFORM")
    tf_main.WATCH_CLOCK = Clock(T0 + tf_main.ri.REDEEM_WINDOW_SECONDS + tf_main.rd.WATCH_MARGIN_S + 2)
    tf_main._sweep_dispatch_watches()
    (cb,) = sent_callbacks
    assert cb["status"] == "FAILED" and cb["error_class"] == "TF_APPLIER_EXECUTION_FAILED_BEFORE_REDEEM"
    assert cb["operator_required"] is True and cb["trace_id"] == "t1"
    tf_main._sweep_dispatch_watches()                              # at most once
    assert len(sent_callbacks) == 1


def test_sweep_never_reports_a_redeemed_dispatch_after_the_switch(per_workload, sent_callbacks, monkeypatch):
    tf_main, vending, guard = per_workload
    _dispatch(tf_main, vending, guard)
    guard.docs[(tf_main.ri.NONCE_COLLECTION, DISPATCH_ID)] = _nonce_record(tf_main.ri, redeemed=True)
    monkeypatch.setattr(tf_main, "install_runner_identity_mode", lambda: "PLATFORM")
    tf_main.WATCH_CLOCK = Clock(T0 + 3600)
    tf_main._sweep_dispatch_watches()
    assert not sent_callbacks and tf_main.watches.docs[DISPATCH_ID]["state"] == "REDEEMED"


def test_the_sweep_does_not_read_the_mode():
    import ast
    import os
    src = open(os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "terraform", "main.py")).read()
    fn = next(n for n in ast.walk(ast.parse(src)) if isinstance(n, ast.FunctionDef)
              and n.name == "_sweep_dispatch_watches")
    assert "install_runner_identity_mode" not in ast.unparse(fn)


# ------------------------------------------------------------------------------------------------ sweeper start
def _mode(tf_main, monkeypatch, value):
    def read():
        if isinstance(value, Exception):
            raise value
        return value
    monkeypatch.setattr(tf_main, "install_runner_identity_mode", read)


@pytest.mark.parametrize("mode,guard_env,changed,expected", [
    ("PLATFORM", False, None, False),          # never switched, before step A: nothing read (unchanged)
    ("PLATFORM", True, False, False),          # step A, never switched: one existence read, no sweeper
    ("PLATFORM", True, True, True),            # switched back to Shared: keep draining
    ("PLATFORM", True, RuntimeError("down"), True),
    ("PER_WORKLOAD", False, None, True),
    ("ERROR", False, None, True),              # the mode cannot be read: the sweep acts on signed records only
])
def test_sweeper_starts_where_watches_can_exist(tf_main, monkeypatch, mode, guard_env, changed, expected):
    ri = tf_main.ri
    _mode(tf_main, monkeypatch, ri.RunnerIdentityError("RUNNER_STORE_UNAVAILABLE", "x") if mode == "ERROR" else mode)
    if guard_env:
        monkeypatch.setenv("STACKVEND_GUARD_FIRESTORE_DATABASE", "stackvend-guard")
        tf_main.GUARD_DB_FACTORY = lambda: object()

        def any_change(client):
            if isinstance(changed, Exception):
                raise changed
            return changed
        monkeypatch.setattr(ri, "any_mode_change", any_change)
    started = []
    monkeypatch.setattr(tf_main, "_ensure_watch_sweeper", lambda: started.append(1))
    assert tf_main._install_may_hold_watches() is expected        # tf_main's GUARD_DB_FACTORY fails on any read
    tf_main._start_watch_sweeper_on_per_workload_installs()
    assert started == ([1] if expected else [])
