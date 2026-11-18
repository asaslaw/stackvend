"""FD-4G (T13) + lane 14 PR-4: refactor scanner /scan never accepts a caller-supplied path or repository; it takes
a ledger workload's `product_id` only."""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import os
import socket
import sys
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RS_DIR = os.path.join(REPO_ROOT, "apps", "refactor-scanner")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    def _blocked(self, addr):
        raise OSError(f"network blocked in FD-4G test: {addr}")

    monkeypatch.setattr(socket.socket, "connect", _blocked)


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(RS_DIR, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def rs_main(monkeypatch):
    from fd4g_support import real_modules

    real_modules(monkeypatch)
    for k in ("PROJECT_ID", "GOOGLE_CLOUD_PROJECT"):
        monkeypatch.delenv(k, raising=False)  # no Firestore / Pub/Sub clients at import
    scanner_mod = _load("fd4g_rs_scanner", "scanner.py")
    monkeypatch.setitem(sys.modules, "scanner", scanner_mod)
    mod = _load("fd4g_rs_main", "main.py")
    mod.scanner.run = MagicMock(return_value=(0, {"outcome": "OK", "scans": [{"product_id": "app"}]}))
    return mod


def test_scan_request_has_no_workspace_dir_or_repo(rs_main):
    assert set(rs_main.ScanRequest.model_fields) == {"product_id"}


def test_scan_ignores_caller_workspace_dir(rs_main):
    from fastapi.testclient import TestClient

    r = TestClient(rs_main.app).post("/scan", json={"product_id": "app", "workspace_dir": "/etc"})
    assert r.status_code == 200
    rs_main.scanner.run.assert_called_once_with(product_id="app")


def test_scan_needs_a_product_id(rs_main):
    from fastapi.testclient import TestClient

    assert TestClient(rs_main.app).post("/scan").status_code == 422
    assert TestClient(rs_main.app).post("/scan", json={"product_id": ""}).status_code == 422
    rs_main.scanner.run.assert_not_called()
