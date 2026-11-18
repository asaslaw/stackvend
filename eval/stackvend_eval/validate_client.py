"""HarnessValidateClient: the product's V1b (`tofu validate`) inside the guarded generation child (S1-0; lane 8B §8).

The generation child may not spawn processes or open sockets (guard.py), so it cannot run `tofu` or call the
terraform server's `/validate`. Instead:

  child  (HarnessValidateClient)  writes  <run_dir>/ipc/req-<n>.json   (atomic rename)   and polls for
  parent (ParentValidateServer)   writes  <run_dir>/ipc/resp-<n>.json  after running the allow-listed TofuRunner
                                           (`init -backend=false` + `validate -json`, offline mirror, sandbox-exec)

Both sides speak the `/validate` contract of mcp-servers/terraform/validate_service.py:
  request  {"op": "validate", "files": {repo_key: text}, "iac_engine": "OPENTOFU", "trace_id": ...} | {"op": "ready"}
  response {"status": "PASS"|"FAIL"|"UNAVAILABLE", "engine", "engine_version", "provider_versions",
            "diagnostics": [raw tofu diagnostics, range.filename rewritten to the repo key], "reason", "duration_ms"}
           ready: {"ready": bool, "engine", "engine_version", "providers": [local names], "reason"}
The client never mutates the tree it is given (it serializes a copy). Any harness failure is UNAVAILABLE, never PASS.
"""
from __future__ import annotations

import json
import os
import posixpath
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

WORKLOAD = "infra/workload"


def _atomic_write(path: Path, data: Dict[str, Any]) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data, sort_keys=True))
    os.replace(tmp, path)


def repo_key_for(filename: Optional[str]) -> Optional[str]:
    """tofu reports range.filename relative to the root module dir (infra/workload); map it to the repo key."""
    if not filename:
        return None
    key = posixpath.normpath(posixpath.join(WORKLOAD, filename))
    if key.startswith("../") or key.startswith("/"):
        return None
    return key


# ------------------------------------------------------------------------------------------------- child side
class HarnessValidateClient:
    """Product-facing V1b client used inside the generation child (installed via the product's runtime hook)."""

    name = "harness"

    def __init__(self, ipc_dir: Path, *, timeout_s: float = 300.0, poll_s: float = 0.05):
        self.ipc_dir = Path(ipc_dir)
        self.ipc_dir.mkdir(parents=True, exist_ok=True)
        self.timeout_s = timeout_s
        self.poll_s = poll_s
        self._n = 0
        self._lock = threading.Lock()
        self.calls = 0

    def _round_trip(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            self._n += 1
            n = self._n
        req, resp = self.ipc_dir / f"req-{n:04d}.json", self.ipc_dir / f"resp-{n:04d}.json"
        _atomic_write(req, payload)
        deadline = time.monotonic() + self.timeout_s
        while time.monotonic() < deadline:
            if resp.exists():
                try:
                    return json.loads(resp.read_text())
                except json.JSONDecodeError:
                    pass  # partially visible on some filesystems: retry
            time.sleep(self.poll_s)
        return {"status": "UNAVAILABLE", "ready": False, "reason": f"harness validate timeout after {self.timeout_s}s",
                "diagnostics": []}

    def ready(self, iac_engine: str = "OPENTOFU") -> Dict[str, Any]:
        out = self._round_trip({"op": "ready"})
        out.setdefault("ready", False)
        return out

    def validate(self, files: Mapping[str, str], *, iac_engine: str = "OPENTOFU", trace_id: str = "") -> Dict[str, Any]:
        self.calls += 1
        tree = {str(k): str(v) for k, v in files.items() if isinstance(v, str)}
        return self._round_trip({"op": "validate", "files": tree, "iac_engine": iac_engine, "trace_id": trace_id})


# ------------------------------------------------------------------------------------------------ parent side
class ValidateColumn:
    """The production scoring column used for V1b in the harness: one tofu binary + one verified mirror."""

    def __init__(self, tofu_bin: Optional[str], mirror_dir: Optional[Path], provider_set: Optional[str] = None):
        from .tofu_runner import find_tofu, verify_mirror_manifest
        self.tofu_bin = tofu_bin or find_tofu()
        self.mirror_dir = Path(mirror_dir) if mirror_dir else None
        self.provider_set = provider_set
        self.reason = ""
        self.available = bool(self.tofu_bin and os.path.exists(self.tofu_bin) and os.access(self.tofu_bin, os.X_OK))
        if not self.available:
            self.reason = f"tofu binary not found/executable: {self.tofu_bin!r}"
        self.mirror_status = (verify_mirror_manifest(self.mirror_dir)["status"] if self.mirror_dir and
                              self.mirror_dir.is_dir() else "empty")
        self._version: Optional[str] = None

    def engine_version(self) -> Optional[str]:
        if self._version is None and self.available:
            try:
                r = subprocess.run([self.tofu_bin, "version", "-json"], capture_output=True, text=True, timeout=30,
                                   env={"PATH": "/usr/bin:/bin", "HOME": tempfile.gettempdir(),
                                        "CHECKPOINT_DISABLE": "1"})
                self._version = json.loads(r.stdout).get("terraform_version")
            except Exception:  # noqa: BLE001
                self._version = None
        return self._version

    def providers(self) -> Dict[str, list]:
        from .provider_sets import ProviderSetError, mirror_provider_versions
        if not self.mirror_dir:
            return {}
        try:
            return mirror_provider_versions(self.mirror_dir)
        except ProviderSetError:
            return {}


class ParentValidateServer:
    """Serves one child's requests from <run_dir>/ipc while the child runs (a daemon thread in the parent)."""

    def __init__(self, ipc_dir: Path, column: ValidateColumn, *, work_root: Path, poll_s: float = 0.05):
        self.ipc_dir = Path(ipc_dir)
        self.ipc_dir.mkdir(parents=True, exist_ok=True)
        for old in self.ipc_dir.glob("*.json"):
            old.unlink()  # a reused run dir never serves a previous invocation's answers
        self.column = column
        self.work_root = Path(work_root)
        self.poll_s = poll_s
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name=f"validate-{self.ipc_dir.parent.name}", daemon=True)
        self.served = 0
        self._runner = None

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=30)

    def _runner_obj(self):
        if self._runner is None:
            from .tofu_runner import TofuRunner
            self._runner = TofuRunner(self.work_root, self.column.mirror_dir, tofu_bin=self.column.tofu_bin)
        return self._runner

    def _loop(self) -> None:
        while not self._stop.is_set():
            for req in sorted(self.ipc_dir.glob("req-*.json")):
                resp = req.with_name(req.name.replace("req-", "resp-", 1))
                if resp.exists():
                    continue
                try:
                    payload = json.loads(req.read_text())
                    out = self.handle(payload)
                except Exception as e:  # noqa: BLE001
                    out = {"status": "UNAVAILABLE", "ready": False, "reason": f"harness error: {type(e).__name__}: {e}",
                           "diagnostics": []}
                _atomic_write(resp, out)
                self.served += 1
            self._stop.wait(self.poll_s)

    def handle(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        col = self.column
        if payload.get("op") == "ready":
            prov = col.providers()
            ok = col.available and col.mirror_status == "verified" and bool(prov)
            return {"ready": ok, "engine": "OPENTOFU", "engine_version": col.engine_version(),
                    "providers": sorted(p.split("/", 1)[1] for p in prov),
                    "provider_versions": prov,
                    "reason": "" if ok else (col.reason or f"mirror {col.mirror_status}")}
        if payload.get("op") != "validate":
            return {"status": "UNAVAILABLE", "reason": f"unknown op {payload.get('op')!r}", "diagnostics": []}
        if (payload.get("iac_engine") or "OPENTOFU").upper() not in ("OPENTOFU", "TOFU"):
            return {"status": "UNAVAILABLE", "reason": "harness validates with OpenTofu only", "diagnostics": []}
        return validate_tree_raw(self._runner_obj(), payload.get("files") or {}, label=f"v{self.served:04d}",
                                 engine_version=col.engine_version(), providers=col.providers())


def validate_tree_raw(runner: Any, files: Mapping[str, str], *, label: str, engine_version: Optional[str],
                      providers: Dict[str, list]) -> Dict[str, Any]:
    """`init -backend=false` + `validate -json` on the infra/ part of `files` with the harness TofuRunner, returning
    the /validate response shape (raw diagnostics; range.filename rewritten to repo keys)."""
    from . import hclparse
    t0 = time.monotonic()
    base = {"engine": "OPENTOFU", "engine_version": engine_version, "provider_versions": providers, "diagnostics": []}

    def done(**kw: Any) -> Dict[str, Any]:
        out = dict(base, **kw)
        out["duration_ms"] = int((time.monotonic() - t0) * 1000)
        return out

    if not runner.available:
        return done(status="UNAVAILABLE", reason="tofu binary not available")
    if not runner.mirror_ready:
        return done(status="UNAVAILABLE", reason=f"provider mirror not verified ({runner.mirror_manifest['status']})")
    tree = {k: v for k, v in files.items() if k.startswith("infra/") and isinstance(v, str)}
    if not any(k.startswith(WORKLOAD + "/") and k.endswith((".tf", ".tf.json")) for k in tree):
        return done(status="UNAVAILABLE", reason="no infra/workload root module in the request")
    try:
        parsed, _bad = hclparse.parse_tree(tree, "infra/")
        remote = [s for _p, _m, s in hclparse.module_sources(parsed) if not hclparse.is_local_source(s)]
    except hclparse.HclUnavailable:
        remote = []
    if remote:
        return done(status="UNAVAILABLE", reason=f"remote module source(s) {sorted(set(remote))[:5]}: the harness "
                                                 "is offline")
    root = runner.work_root / "validate" / label
    if root.exists():
        shutil.rmtree(root)
    runner.write_tree(tree, root)
    wd = root / WORKLOAD
    r = runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd)
    if r.returncode != 0:
        init_err = (r.stderr or r.stdout or "")[-600:]
        # init refuses an invalid configuration before installing anything. `validate -json` without init still
        # reports those configuration diagnostics, each with a source `range`; diagnostics without a range are
        # installation problems (provider/module not available). Exact JSON structure, any engine version.
        v = runner._run(["validate", "-json", "-no-color"], cwd=wd)
        diags = _config_diagnostics(v.stdout)
        if diags is not None:
            shutil.rmtree(root, ignore_errors=True)
            return done(status="FAIL", diagnostics=diags, reason="configuration invalid (reported before init)")
        return done(status="UNAVAILABLE", reason="init failed: " + init_err)
    r = runner._run(["validate", "-json", "-no-color"], cwd=wd)
    try:
        vj = json.loads(r.stdout or "{}")
    except json.JSONDecodeError:
        return done(status="UNAVAILABLE", reason="unparseable validate output: " + (r.stdout + r.stderr)[-400:])
    diags = [_rekey(d) for d in vj.get("diagnostics", [])]
    shutil.rmtree(root, ignore_errors=True)
    return done(status="PASS" if vj.get("valid") else "FAIL", diagnostics=diags, reason="")


def _rekey(d: Dict[str, Any]) -> Dict[str, Any]:
    d = dict(d)
    rng = dict(d.get("range") or {})
    if rng.get("filename"):
        rng["filename"] = repo_key_for(rng["filename"]) or rng["filename"]
        d["range"] = rng
    return d


def _config_diagnostics(stdout: str) -> Optional[list]:
    """Diagnostics of an un-initialized `validate -json` when EVERY error is located in the configuration (has a
    `range`); None when the output is unparseable, reports no error, or carries an unlocated (installation) error."""
    try:
        vj = json.loads(stdout or "")
    except json.JSONDecodeError:
        return None
    diags = vj.get("diagnostics") if isinstance(vj, dict) else None
    if not isinstance(diags, list):
        return None
    errors = [d for d in diags if isinstance(d, dict) and d.get("severity") == "error"]
    if not errors or any(not d.get("range") for d in errors):
        return None
    return [_rekey(d) for d in diags if isinstance(d, dict)]
