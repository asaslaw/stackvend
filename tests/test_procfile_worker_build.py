"""procfile-worker-build (RT F3 of FD-4AE-c): a Procfile-only worker is built, an empty skeleton is still skipped.

`_build_and_push_container` skipped every `apps/<svc>/` without an entry module (main.py, app.py, ...) as an "empty
skeleton" whenever a sibling had one. Gate A 05-r2 (x3 result sets) ships `apps/fleet-gke/` = a GKE Autopilot
Pub/Sub consumer with `Procfile: worker: python consumer.py` and no main.py: it was never built, so its Deployment
pointed at an image nobody pushed. Fix: typed facts decide (`entryless_service_is_buildable`): with the architect's
topology, the topology names the dir with a container kind; without one, its Procfile declares a process (exact
line parse = the pre-commit V3c `parse_procfile`). VM kinds stay skipped (F1b); a dir with neither stays skipped."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import json
import os
import sys
from typing import Dict, Tuple
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from fd4g_support import load_tf_service  # noqa: E402

COMPUTE_TF = ('module "foundation" {\n  source     = "./infra/modules/workload-foundation"\n'
              '  project_id = var.project_id\n}\n'
              'module "compute" {\n  source = "./infra/modules/compute-cloudrun"\n}\n')

# Gate A 05-r2 shape (trimmed): Cloud Run edge API + GKE Procfile-only consumer + GCE batch worker (VM kind).
EDGE = {"apps/fleet-edge/main.py": "app = None\n",
        "apps/fleet-edge/Procfile": "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n",
        "apps/fleet-edge/requirements.txt": "fastapi\n"}
GKE_WORKER = {"apps/fleet-gke/consumer.py": "def main():\n    pass\n\n\nif __name__ == '__main__':\n    main()\n",
              "apps/fleet-gke/models.py": "X = 1\n",
              "apps/fleet-gke/Procfile": "worker: python consumer.py\n",
              "apps/fleet-gke/requirements.txt": "google-cloud-pubsub\n",
              "apps/fleet-gke/.python-version": "3.13\n"}
GCE_WORKER = {"apps/batch-worker/worker.py": "print('job')\n",
              "apps/batch-worker/requirements.txt": "google-cloud-storage\n",
              "apps/batch-worker/startup.sh": "#!/bin/bash\npython3 worker.py\n"}


def _topology(**kinds):
    return json.dumps({"schema": "service_topology/v1",
                       "intent": {"services": [{"name": n.replace("_", "-"), "kind": k} for n, k in kinds.items()]}})


TOPO_05 = _topology(**{"fleet-edge": "cloudrun", "fleet-gke": "gke-autopilot", "batch-worker": "gce-worker"})


@pytest.fixture
def tf(monkeypatch):
    mod = load_tf_service(monkeypatch)
    import importlib
    settings = sys.modules.get("shared.settings") or importlib.import_module("shared.settings")
    monkeypatch.setattr(settings, "get_platform_settings", lambda *a, **k: None)   # no Firestore (BOM defaults)
    return mod


def _write(base, files):
    for rel, text in files.items():
        path = os.path.join(str(base), rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)


def _tree(base, svc_dir):
    root = os.path.join(str(base), svc_dir)
    out = {}
    for r, _, fs in os.walk(root):
        for f in fs:
            p = os.path.join(r, f)
            with open(p, "r", encoding="utf-8") as fh:
                out[os.path.relpath(p, str(base)).replace(os.sep, "/")] = fh.read()
    return out


def _build(tf, tmp_path, files) -> Tuple[bool, list, object]:
    """Run the real build through packaging; returns (ok, built services, svc). Stops at the mocked staging."""
    ws = tmp_path / "ws"
    _write(ws, files)
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="", workspace_base_dir=str(tmp_path / "b"),
                              firestore_client=MagicMock())
    svc.db = None
    svc.state_bucket = ""
    built = []
    real_select = tf.select_build_source_files

    def select(workspace_dir, services):
        built.extend(services)
        return real_select(workspace_dir, services)

    def stage(**kwargs):
        raise RuntimeError("stop after packaging (test)")

    with patch("google.auth.default", return_value=(MagicMock(), "p")), \
         patch("google.auth.transport.requests.AuthorizedSession"), \
         patch("google.cloud.storage.Client"), \
         patch.object(tf, "select_build_source_files", side_effect=select), \
         patch.object(tf.TerraformService, "_stage_build_source", side_effect=stage):
        ok = svc._build_and_push_container("fleet", "child", str(ws), "img:tag")
    return ok, sorted(built), svc


# ------------------------------------------------------------------------------------------------ the fix
def test_gate_a_05_shape_builds_the_gke_procfile_worker(tf, tmp_path):
    files = {"main.tf": COMPUTE_TF, "infra/workload/topology.json": TOPO_05, **EDGE, **GKE_WORKER, **GCE_WORKER}
    ok, built, svc = _build(tf, tmp_path, files)
    assert built == ["fleet-edge", "fleet-gke"], svc._last_build_error
    ws = tmp_path / "ws"
    after = _tree(ws, "apps/fleet-gke")
    for rel, text in GKE_WORKER.items():
        assert after[rel] == text, rel        # the authored Procfile is never rewritten (FD-4AE)
    assert _tree(ws, "apps/batch-worker") == GCE_WORKER   # VM kind: never built, untouched (F1b)


def test_procfile_worker_without_topology_is_built(tf, tmp_path):
    files = {"main.tf": COMPUTE_TF, **EDGE, **GKE_WORKER}
    ok, built, svc = _build(tf, tmp_path, files)
    assert built == ["fleet-edge", "fleet-gke"], svc._last_build_error


@pytest.mark.parametrize("with_requirements", [True, False])   # RT F1: without requirements.txt it was dropped silently
def test_topology_container_kind_without_any_entrypoint_fails_typed(tf, tmp_path, with_requirements):
    """The topology says fleet-gke is a container but nothing in it can start: a typed build failure, never a
    silent skip that leaves the Deployment without an image."""
    gke = {"apps/fleet-gke/consumer.py": "X = 1\n"}
    if with_requirements:
        gke["apps/fleet-gke/requirements.txt"] = "google-cloud-pubsub\n"
    files = {"main.tf": COMPUTE_TF, "infra/workload/topology.json": TOPO_05, **EDGE, **gke}
    ok, built, svc = _build(tf, tmp_path, files)
    assert ok is False and built == []
    assert svc._last_build_error.startswith("BUILD.ENTRYPOINT_MISSING: apps/fleet-gke ")
    assert svc._last_build_error_class == "BUILD_CONTRACT"
    assert _tree(tmp_path / "ws", "apps/fleet-gke") == gke     # nothing written into it


def test_topology_node_service_without_procfile_is_not_failed_typed(tf, tmp_path):
    """Negative: a Node container service (package.json, Buildpacks' `npm start`) is not a missing Python entrypoint."""
    node = {"apps/fleet-gke/package.json": '{"scripts": {"start": "node src/server.js"}}\n',
            "apps/fleet-gke/src/server.js": "console.log(1)\n"}
    files = {"main.tf": COMPUTE_TF, "infra/workload/topology.json": TOPO_05, **EDGE, **node}
    ok, built, svc = _build(tf, tmp_path, files)
    assert built == ["fleet-edge", "fleet-gke"], svc._last_build_error
    assert not (svc._last_build_error or "").startswith("BUILD.")


# ------------------------------------------------------------------------------------------------ negatives
SKELETON = {"apps/stub/__init__.py": "", "apps/stub/requirements.txt": "requests\n"}


def test_empty_skeleton_is_still_skipped_and_untouched(tf, tmp_path):
    files = {"main.tf": COMPUTE_TF, **EDGE, **SKELETON}
    ok, built, svc = _build(tf, tmp_path, files)
    assert built == ["fleet-edge"], svc._last_build_error
    assert _tree(tmp_path / "ws", "apps/stub") == SKELETON   # no Procfile / .python-version / static written


def test_empty_skeleton_not_named_by_the_topology_is_skipped(tf, tmp_path):
    files = {"main.tf": COMPUTE_TF, "infra/workload/topology.json": _topology(**{"fleet-edge": "cloudrun"}),
             **EDGE, **SKELETON}
    ok, built, _ = _build(tf, tmp_path, files)
    assert built == ["fleet-edge"]
    assert _tree(tmp_path / "ws", "apps/stub") == SKELETON


@pytest.mark.parametrize("procfile", ["", "# worker: python consumer.py\n\n", "python consumer.py\n",
                                      "my worker: python consumer.py\n", "worker:\n"])
def test_procfile_without_a_process_entry_keeps_the_skip(tf, tmp_path, procfile):
    gke = dict(GKE_WORKER, **{"apps/fleet-gke/Procfile": procfile})
    ok, built, _ = _build(tf, tmp_path, {"main.tf": COMPUTE_TF, **EDGE, **gke})
    assert built == ["fleet-edge"]


def test_procfile_dir_the_topology_does_not_name_stays_skipped(tf, tmp_path):
    """With a topology only the typed kind decides: an unnamed Procfile dir is skipped exactly as before."""
    files = {"main.tf": COMPUTE_TF, "infra/workload/topology.json": _topology(**{"fleet-edge": "cloudrun"}),
             **EDGE, **GKE_WORKER}
    ok, built, _ = _build(tf, tmp_path, files)
    assert built == ["fleet-edge"]


@pytest.mark.parametrize("kind", ["gce-worker", "gce-bastion"])
def test_vm_kind_with_a_procfile_is_never_built(tf, tmp_path, kind):
    vm = {"apps/ops-vm/tool.py": "print(1)\n", "apps/ops-vm/requirements.txt": "requests\n",
          "apps/ops-vm/Procfile": "worker: python tool.py\n"}
    files = {"main.tf": COMPUTE_TF, "infra/workload/topology.json": _topology(**{"fleet-edge": "cloudrun", "ops-vm": kind}),
             **EDGE, **vm}
    ok, built, _ = _build(tf, tmp_path, files)
    assert built == ["fleet-edge"]
    assert _tree(tmp_path / "ws", "apps/ops-vm") == vm


def test_services_with_an_entry_module_are_unchanged(tf, tmp_path):
    files = {"main.tf": COMPUTE_TF, "infra/workload/topology.json": _topology(**{"fleet-edge": "cloudrun"}), **EDGE}
    ok, built, svc = _build(tf, tmp_path, files)
    assert built == ["fleet-edge"], svc._last_build_error


def test_entryless_service_is_buildable_unit(tf, tmp_path):
    d = tmp_path / "svc"
    d.mkdir()
    assert tf.entryless_service_is_buildable("svc", str(d), None) is False                       # no Procfile
    (d / "Procfile").write_text("worker: python consumer.py\n")
    assert tf.entryless_service_is_buildable("svc", str(d), None) is True
    assert tf.entryless_service_is_buildable("svc", str(d), {"other": "cloudrun"}) is False      # topology decides
    assert tf.entryless_service_is_buildable("my_svc", str(d), {"my-svc": "event-worker"}) is True
    assert tf.entryless_service_is_buildable("svc", str(d), {"svc": "gce-worker"}) is False
    (d / "Procfile").write_bytes(b"\xff\xfe")
    assert tf.entryless_service_is_buildable("svc", str(d), None) is False                       # unreadable


# ------------------------------------------------------------------------------------------------ parity
def _gateway_function(name):
    """Exec one self-contained top-level function of the gateway container validator (the gateway package cannot
    be imported next to the terraform MCP's `shared`)."""
    path = os.path.join(REPO_ROOT, "apps/orchestrator-gateway/gatekeeper_agent/procfile.py")   # FD-4AD: shared parser
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)
    ns = {"Dict": Dict, "Tuple": Tuple}
    exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), ns)
    return ns[name]


PROCFILES = ["", "web: uvicorn main:app --port $PORT\n", "worker: python consumer.py\n",
             "# c\n\nweb: a\nworker: b\nweb: c\n", "bad line\nx: \n: y\nmy proc: z\nok: run it\n",
             "release: alembic upgrade head\r\nweb: gunicorn app:app\r\n", "  worker :  python -m w  \n"]


@pytest.mark.parametrize("text", PROCFILES)
def test_procfile_parse_matches_the_v3c_contract(tf, text):
    gateway_parse = _gateway_function("parse_procfile")
    assert tf.procfile_processes(text) == gateway_parse(text)[0]
