"""`POST /validate` and `GET /validate/ready`: OpenTofu/Terraform validation for the developer stage's V1b
(Step 1 S1-B; lane 8B plan §8; register HS-03, HS-05, HS-52).

Contract
  request   {"files": {repo_key: text}, "iac_engine": "OPENTOFU" | "TERRAFORM", "trace_id": str}
  response  {"status": "PASS" | "FAIL" | "UNAVAILABLE", "engine", "engine_version", "provider_versions",
             "diagnostics": [raw engine diagnostics; range.filename rewritten to the repo key], "reason", "duration_ms",
             "unavailable_code": one of UNAVAILABLE_CODES (only on UNAVAILABLE; V1B-WARMUP-RETRY)}
  ready     {"ready": bool, "engine", "engine_version", "providers": [local names], "provider_versions", "reason",
             "mirror_complete": bool, "mirror_missing": ["<registry>/hashicorp/<type> <version>", ...],
             "warmup": "not_started" | "running" | "done"}  (+ "mirror_gaps" added by main.py: why a provider was left out)

Readiness (FD-4DM)
  `ready` is true when the verified engine binary is present, `hashicorp/google` is mirrored AND the server's first
  warm-up pass (engine + the full provider mirror, MIRROR_EXPECTED) is no longer running. While that pass runs, an
  answer is `ready: false` ("warm-up still running"), so a caller never starts AI work against a mirror that is still
  being filled. After the pass, `ready` keeps the earlier rule (engine + google): a provider version the pass could not
  mirror (no verifiable checksum, a failed download) is reported in `mirror_missing` / `mirror_complete: false`, not
  turned into a permanent not-ready. A pass still running after WARMUP_READY_GRACE_S also falls back to that rule
  (a stuck download never blocks every dispatch). No warm-up (tests, local runs): the earlier rule. Callers that need
  specific versions keep checking `provider_versions` (VRW-1, GATE.IAC_SCHEMA_PARITY).

Behavior (and why)
  - The tree is written into a fresh temporary directory (deleted after); no prepare_workspace, no healer runs.
  - `init -backend=false -input=false` then `validate -json`. When init refuses an invalid configuration, the
    un-initialized `validate -json` still reports the configuration diagnostics, each with a source `range`; a FAIL
    is returned only when EVERY error diagnostic is located (an unlocated error is an installation problem ->
    UNAVAILABLE). Exact JSON structure, any engine version.
  - Providers come only from the server's filesystem mirror (CLI config without `direct {}`): no egress for providers.
  - The child environment is an allow-list (PATH, HOME=<tmp>, TF_CLI_CONFIG_FILE, TF_IN_AUTOMATION, ...); no GOOGLE_*
    variable or credential reaches the engine (validate evaluates functions).
  - The engine binary is the release zip downloaded by this module and verified against binary_checksums.py
    (owner-fetched upstream SHA256SUMS, D12) before it is unpacked; a PATH binary is never used. No entry, a mismatch,
    a failed download, a timeout (60 s) or any runner error is UNAVAILABLE -- never PASS.
  - At most VALIDATE_CONCURRENCY validations run at once per instance.

UNAVAILABLE codes (V1B-WARMUP-RETRY, owner 10-30)
  Every UNAVAILABLE answer carries a typed `unavailable_code` next to the unchanged `reason` text. Two are transient
  on this instance (RETRYABLE_UNAVAILABLE_CODES), so a caller may wait for /validate/ready and ask once more:
  - ENGINE_NOT_READY: the verified engine binary could not be fetched / verified yet (the next call downloads again),
    or the engine run (init failure without located diagnostics, or a timeout) happened while the instance's first
    warm-up pass was still filling the provider mirror. A new Cloud Run instance answers /validate before its
    warm-up ends; `init` against the half-filled mirror fails (the warm-up creates each <version>/<os_arch> dir
    before the provider binary lands in it, and OpenTofu counts that dir as an available package).
  - CONCURRENCY_LIMIT: no validate slot freed up within the timeout.
  Every other code is permanent for the request on this instance: UNKNOWN_ENGINE, ENGINE_UNVERIFIABLE (no
  owner-verified checksum row, D12), UNSAFE_KEY, TOO_LARGE, NO_ROOT_MODULE, INIT_FAILED, UNPARSEABLE_OUTPUT,
  NO_ERROR_DIAGNOSTIC, TIMEOUT, INTERNAL_ERROR. A code never turns UNAVAILABLE into a pass.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import platform
import posixpath
import shutil
import subprocess
import tempfile
import threading
import time
import zipfile
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple

try:
    from shared.path_safety import TF_WORKSPACE_RESERVED, UnsafePathError, validate_manifest_keys
except ImportError:  # pragma: no cover - local runs from the repo root
    from path_safety import TF_WORKSPACE_RESERVED, UnsafePathError, validate_manifest_keys  # type: ignore

import binary_checksums
import provider_allowlist

logger = logging.getLogger("mcp-terraform-validate")

WORKLOAD = "infra/workload"
VALIDATE_TIMEOUT_S = 60
VALIDATE_CONCURRENCY = 4
# FD-7L Phase 2a: nothing listens here (equals runner_credentials.UNROUTABLE_METADATA_HOST; parity test).
UNROUTABLE_METADATA_HOST = "127.0.0.1:9"
MAX_REQUEST_BYTES = 8 * 1024 * 1024
# Pinned pre-cache set (Q-S5 utility set: owner); FD-4AQ W1b: the server's single allow-list (provider_allowlist.py).
VALIDATE_PROVIDERS = tuple(provider_allowlist.PLATFORM_PROVIDER_SOURCES)
REGISTRIES = provider_allowlist.PROVIDER_REGISTRIES
ENGINE_FETCH_TIMEOUT_S = 60.0      # = service.ENGINE_FETCH_TIMEOUT_S (RT14 RT F2)
ENGINE_ZIP_MAX_BYTES = 200 << 20   # = service.ENGINE_ZIP_MAX_BYTES
ENGINE_VERSIONS = {"opentofu": "1.9.0", "terraform": "1.5.7"}   # platform pins (settings tofu_version / terraform_version)
RELEASE_URLS = {
    "opentofu": "https://github.com/opentofu/opentofu/releases/download/v{v}/tofu_{v}_{os_arch}.zip",
    "terraform": "https://releases.hashicorp.com/terraform/{v}/terraform_{v}_{os_arch}.zip",
}
BINARY_NAMES = {"opentofu": "tofu", "terraform": "terraform"}
# FD-4DM: every provider version the server's warm-up mirrors and this service serves, on both registry hosts
# (service.py `_ensure_provider_mirror` fills exactly provider_allowlist.MIRROR_PROVIDER_VERSIONS x REGISTRIES).
MIRROR_EXPECTED = tuple((reg, ptype, version) for reg in REGISTRIES for ptype in VALIDATE_PROVIDERS
                        for version in provider_allowlist.MIRROR_PROVIDER_VERSIONS.get(ptype, ()))
WARMUP_NOT_STARTED, WARMUP_RUNNING, WARMUP_DONE = "not_started", "running", "done"
WARMUP_READY_GRACE_S = 300.0   # a warm-up pass running longer than this no longer holds `ready` back

# V1B-WARMUP-RETRY: typed UNAVAILABLE codes (module docstring).
ENGINE_NOT_READY = "ENGINE_NOT_READY"
CONCURRENCY_LIMIT = "CONCURRENCY_LIMIT"
UNKNOWN_ENGINE = "UNKNOWN_ENGINE"
ENGINE_UNVERIFIABLE = "ENGINE_UNVERIFIABLE"
UNSAFE_KEY = "UNSAFE_KEY"
TOO_LARGE = "TOO_LARGE"
NO_ROOT_MODULE = "NO_ROOT_MODULE"
INIT_FAILED = "INIT_FAILED"
UNPARSEABLE_OUTPUT = "UNPARSEABLE_OUTPUT"
NO_ERROR_DIAGNOSTIC = "NO_ERROR_DIAGNOSTIC"
TIMEOUT = "TIMEOUT"
INTERNAL_ERROR = "INTERNAL_ERROR"
UNAVAILABLE_CODES = frozenset({ENGINE_NOT_READY, CONCURRENCY_LIMIT, UNKNOWN_ENGINE, ENGINE_UNVERIFIABLE, UNSAFE_KEY,
                               TOO_LARGE, NO_ROOT_MODULE, INIT_FAILED, UNPARSEABLE_OUTPUT, NO_ERROR_DIAGNOSTIC,
                               TIMEOUT, INTERNAL_ERROR})
RETRYABLE_UNAVAILABLE_CODES = frozenset({ENGINE_NOT_READY, CONCURRENCY_LIMIT})

Runner = Callable[[List[str], str, Dict[str, str], int], subprocess.CompletedProcess]


def host_os_arch() -> str:
    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}.get(machine, machine)
    return f"{platform.system().lower()}_{arch}"


def normalize_engine(iac_engine: Optional[str]) -> str:
    e = (iac_engine or "OPENTOFU").strip().upper()
    return "opentofu" if e in ("OPENTOFU", "TOFU") else "terraform" if e in ("TERRAFORM", "TF") else ""


def repo_key_for(filename: Optional[str]) -> Optional[str]:
    if not filename:
        return None
    key = posixpath.normpath(posixpath.join(WORKLOAD, filename))
    return None if key.startswith(("../", "/")) or key == ".." else key


def _rekey(d: Dict[str, Any]) -> Dict[str, Any]:
    d = dict(d)
    rng = dict(d.get("range") or {})
    if rng.get("filename"):
        rng["filename"] = repo_key_for(rng["filename"]) or rng["filename"]
        d["range"] = rng
    return d


def config_diagnostics(stdout: str) -> Optional[List[Dict[str, Any]]]:
    """Un-initialized `validate -json` output -> its diagnostics when every error is located; else None."""
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


def scrubbed_env(home: str, cli_config: str, plugin_cache_dir: str) -> Dict[str, str]:
    """The only environment the engine sees (no GOOGLE_*). Step 1 code RT F3 / plan §8: a shared plugin cache, so
    `init` links the mirror's providers instead of copying ~250 MB into every throw-away workspace (Cloud Run /tmp is
    memory-backed).
    FD-7L Phase 2a (plan 2.4): GCE_METADATA_HOST / GCE_METADATA_IP point at an address where nothing answers, so ADC
    inside the engine can never reach the container's real metadata server (validate configures no provider; this
    closes the fallback, it changes no validation result)."""
    return {"PATH": "/usr/bin:/bin", "HOME": home, "TF_CLI_CONFIG_FILE": cli_config, "TF_IN_AUTOMATION": "1",
            "TF_INPUT": "0", "CHECKPOINT_DISABLE": "1", "LANG": "C.UTF-8", "TZ": "UTC",
            "TF_PLUGIN_CACHE_DIR": plugin_cache_dir, "TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE": "1",
            "GCE_METADATA_HOST": UNROUTABLE_METADATA_HOST, "GCE_METADATA_IP": UNROUTABLE_METADATA_HOST}


def _default_runner(cmd: List[str], cwd: str, env: Dict[str, str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)


class VerifiedBinaries:
    """Downloads + verifies engine release zips (D12). `fetch` is injectable for tests (no network in tests)."""

    def __init__(self, tooling_dir: str, *, fetch: Optional[Callable[[str, str], None]] = None,
                 os_arch: Optional[str] = None):
        self.dir = os.path.join(tooling_dir, "validate-bin")
        self.os_arch = os_arch or host_os_arch()
        self._fetch = fetch or self._download
        self._lock = threading.Lock()
        self._ready: Dict[str, str] = {}
        self.last_error: Dict[str, str] = {}

    @staticmethod
    def _download(url: str, dest: str) -> None:  # pragma: no cover - network (server warm-up only)
        # RT14 RT F2 (same as service._ensure_binary): runs under self._lock, so the download is bounded (timeout per
        # socket operation, size cap, https-only redirects); D1 made the Terraform 1.5.7 download reachable here.
        with open(dest, "wb") as fh:
            binary_checksums.fetch_to(url, fh, ENGINE_ZIP_MAX_BYTES, timeout=ENGINE_FETCH_TIMEOUT_S)

    def path_for(self, engine: str) -> Optional[str]:
        return self._ready.get(engine)

    def ensure(self, engine: str) -> Tuple[Optional[str], str]:
        """(binary path, "") when a verified binary is available, else (None, reason)."""
        path, reason, _code = self.ensure_typed(engine)
        return path, reason

    def ensure_typed(self, engine: str) -> Tuple[Optional[str], str, str]:
        """`ensure` plus the UNAVAILABLE code of a failure ("" on success; V1B-WARMUP-RETRY): UNKNOWN_ENGINE and
        ENGINE_UNVERIFIABLE (no checksum row) never change on this instance; every fetch / verify / unpack failure is
        ENGINE_NOT_READY, because the next call downloads again (nothing here is sticky)."""
        if engine in self._ready:
            return self._ready[engine], "", ""
        with self._lock:
            if engine in self._ready:
                return self._ready[engine], "", ""
            version = ENGINE_VERSIONS.get(engine)
            if not version:
                return None, f"unknown engine {engine!r}", UNKNOWN_ENGINE
            want = binary_checksums.expected_sha256(engine, version, self.os_arch)
            if not want:
                reason = f"no owner-verified checksum for {engine} {version} {self.os_arch} (binary_checksums.py, D12)"
                self.last_error[engine] = reason
                return None, reason, ENGINE_UNVERIFIABLE
            os.makedirs(self.dir, exist_ok=True)
            zip_path = os.path.join(self.dir, f"{engine}_{version}_{self.os_arch}.zip")
            try:
                self._fetch(RELEASE_URLS[engine].format(v=version, os_arch=self.os_arch), zip_path)
                h = hashlib.sha256()
                with open(zip_path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(1 << 20), b""):
                        h.update(chunk)
                if h.hexdigest() != want:
                    reason = f"{engine} {version} release zip sha256 {h.hexdigest()} != owner-verified {want}"
                    self.last_error[engine] = reason
                    return None, reason, ENGINE_NOT_READY
                name = BINARY_NAMES[engine]
                with zipfile.ZipFile(zip_path) as zf:
                    if name not in zf.namelist():
                        return None, f"release zip has no {name!r} member", ENGINE_NOT_READY
                    data = zf.read(name)
                out = os.path.join(self.dir, f"{name}_{version}")
                with open(out, "wb") as fh:
                    fh.write(data)
                os.chmod(out, 0o755)
                self._ready[engine] = out
                return out, "", ""
            except Exception as e:  # noqa: BLE001 - any failure is UNAVAILABLE, never a PATH fallback
                reason = f"{engine} {version} download/verify failed: {type(e).__name__}: {e}"
                self.last_error[engine] = reason
                return None, reason, ENGINE_NOT_READY
            finally:
                if os.path.exists(zip_path):
                    os.remove(zip_path)


class ValidateService:
    def __init__(self, tooling_dir: str, *, mirror_dir: Optional[str] = None, binaries: Optional[VerifiedBinaries] = None,
                 runner: Optional[Runner] = None, timeout_s: int = VALIDATE_TIMEOUT_S,
                 concurrency: int = VALIDATE_CONCURRENCY, warmup_grace_s: float = WARMUP_READY_GRACE_S,
                 clock: Callable[[], float] = time.monotonic):
        self.tooling_dir = tooling_dir
        self.warmup_grace_s = warmup_grace_s
        self._clock = clock
        self._warm_lock = threading.Lock()
        self._warm_state = WARMUP_NOT_STARTED
        self._warm_started_at = 0.0
        self.mirror_dir = mirror_dir or os.path.join(tooling_dir, "plugin_mirror")
        self.binaries = binaries or VerifiedBinaries(tooling_dir)
        self.runner = runner or _default_runner
        self.timeout_s = timeout_s
        self._sem = threading.BoundedSemaphore(concurrency)
        self.cli_config = os.path.join(tooling_dir, "validate.tfrc")
        self.plugin_cache_dir = os.path.join(tooling_dir, "validate-plugin-cache")
        # The plugin cache is not guaranteed concurrency-safe in OpenTofu 1.9 / Terraform: `init` (the only step that
        # writes it) runs one at a time per process; `validate` stays concurrent.
        self._init_lock = threading.Lock()

    # ----------------------------------------------------------------------------------------- config / mirror
    def _write_cli_config(self) -> None:
        text = provider_allowlist.cli_config(self.mirror_dir, registry=False)   # no direct: no provider egress
        os.makedirs(self.tooling_dir, exist_ok=True)
        current = None
        if os.path.exists(self.cli_config):
            with open(self.cli_config) as fh:
                current = fh.read()
        if current != text:
            fd, tmp = tempfile.mkstemp(prefix="validate.tfrc.", dir=self.tooling_dir)
            with os.fdopen(fd, "w") as fh:
                fh.write(text)
            os.chmod(tmp, 0o444)
            os.replace(tmp, self.cli_config)

    def mirror_provider_versions(self) -> Dict[str, List[str]]:
        """{"hashicorp/google": ["6.35.0", ...]} present in the mirror for this host's os/arch (unpacked layout
        <registry>/<namespace>/<type>/<version>/<os_arch>/terraform-provider-*)."""
        out: Dict[str, set] = {}
        for reg in REGISTRIES:
            base = os.path.join(self.mirror_dir, reg, "hashicorp")
            for ptype in VALIDATE_PROVIDERS:
                pdir = os.path.join(base, ptype)
                if not os.path.isdir(pdir):
                    continue
                for version in os.listdir(pdir):
                    if self._mirrored(reg, ptype, version):
                        out.setdefault(f"hashicorp/{ptype}", set()).add(version)
        return {k: sorted(v) for k, v in sorted(out.items())}

    def _mirrored(self, reg: str, ptype: str, version: str) -> bool:
        """The unpacked provider binary of one (registry, type, version) is present for this host's os/arch."""
        vdir = os.path.join(self.mirror_dir, reg, "hashicorp", ptype, version, self.binaries.os_arch)
        try:
            return any(f.startswith(f"terraform-provider-{ptype}") for f in os.listdir(vdir))
        except OSError:
            return False

    def mirror_missing(self) -> List[str]:
        """FD-4DM: the MIRROR_EXPECTED entries not (yet) in the mirror, as "<registry>/hashicorp/<type> <version>"."""
        return [f"{reg}/hashicorp/{ptype} {version}" for reg, ptype, version in MIRROR_EXPECTED
                if not self._mirrored(reg, ptype, version)]

    # ----------------------------------------------------------------------------------------- warm-up
    def warmup_state(self) -> str:
        with self._warm_lock:
            return self._warm_state

    def start_warmup(self, fill_mirror: Callable[[], Any], engine: str = "opentofu", *,
                     spawn: Optional[Callable[[Callable[[], None]], Any]] = None) -> bool:
        """FD-4DM: one background warm-up pass (verified engine binary, D12, then `fill_mirror`, the server's provider
        mirror pre-cache). The state turns "running" before the thread starts, so no /validate/ready answer can come
        from the window between startup and the first download; it turns "done" when the pass ends, whatever its
        outcome (failures show in /validate/ready). Only the first call starts a pass (returns True)."""
        with self._warm_lock:
            if self._warm_state != WARMUP_NOT_STARTED:
                return False
            self._warm_state = WARMUP_RUNNING
            self._warm_started_at = self._clock()

        def run() -> None:
            try:
                self.binaries.ensure(engine)
                fill_mirror()
            except Exception as e:  # noqa: BLE001 - never fails startup; /validate/ready shows what is missing
                logger.warning(f"/validate warm-up notice: {type(e).__name__}: {e}")
            finally:
                with self._warm_lock:
                    self._warm_state = WARMUP_DONE
                missing = self.mirror_missing()
                if missing:
                    logger.warning(f"/validate warm-up done; not mirrored: {', '.join(missing)}")
                else:
                    logger.info("/validate warm-up done; provider mirror complete")

        try:
            if spawn is None:
                threading.Thread(target=run, name="validate-warmup", daemon=True).start()
            else:
                spawn(run)
        except Exception:
            with self._warm_lock:
                self._warm_state = WARMUP_DONE   # no pass is running: never hold `ready` back for one
            raise
        return True

    def _warmup_holds_ready(self) -> bool:
        """True while the first warm-up pass runs, for at most `warmup_grace_s`."""
        with self._warm_lock:
            return (self._warm_state == WARMUP_RUNNING
                    and self._clock() - self._warm_started_at < self.warmup_grace_s)

    # ----------------------------------------------------------------------------------------- endpoints
    def ready(self, iac_engine: Optional[str] = "OPENTOFU") -> Dict[str, Any]:
        engine = normalize_engine(iac_engine)
        binary, reason = self.binaries.ensure(engine) if engine else (None, f"unknown engine {iac_engine!r}")
        providers = self.mirror_provider_versions()
        missing = self.mirror_missing()
        ok = bool(binary) and "hashicorp/google" in providers
        if binary and not ok:
            reason = "provider mirror not populated (google missing)"
        if ok and self._warmup_holds_ready():
            ok = False
            reason = (f"provider mirror warm-up still running ({len(missing)} of {len(MIRROR_EXPECTED)} provider "
                      f"versions not mirrored yet)")
        return {"ready": ok, "engine": engine.upper() or None, "engine_version": ENGINE_VERSIONS.get(engine),
                "providers": sorted(p.split("/", 1)[1] for p in providers), "provider_versions": providers,
                "reason": "" if ok else reason, "mirror_complete": not missing, "mirror_missing": missing,
                "warmup": self.warmup_state()}

    def validate(self, files: Mapping[str, Any], iac_engine: Optional[str] = "OPENTOFU",
                 trace_id: str = "") -> Dict[str, Any]:
        t0 = time.monotonic()
        engine = normalize_engine(iac_engine)
        base = {"engine": engine.upper() or None, "engine_version": ENGINE_VERSIONS.get(engine),
                "provider_versions": {}, "diagnostics": []}

        def done(status: str, reason: str = "", diagnostics: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
            out = dict(base, status=status, reason=reason, diagnostics=diagnostics or [])
            out["duration_ms"] = int((time.monotonic() - t0) * 1000)
            return out

        def unavailable(code: str, reason: str) -> Dict[str, Any]:
            out = done("UNAVAILABLE", reason)
            out["unavailable_code"] = code
            return out

        # V1B-WARMUP-RETRY: an engine run that fails while this instance's first warm-up pass is still filling the
        # provider mirror is ENGINE_NOT_READY (state of the instance, sampled at the start and at the failure).
        warming_at_start = self.warmup_state() == WARMUP_RUNNING

        def engine_run_code(code: str) -> str:
            return ENGINE_NOT_READY if warming_at_start or self.warmup_state() == WARMUP_RUNNING else code

        if not engine:
            return unavailable(UNKNOWN_ENGINE, f"unknown engine {iac_engine!r}")
        tree = {k: v for k, v in (files or {}).items() if isinstance(v, str) and k.startswith("infra/")}
        try:
            validate_manifest_keys(tree, reserved=TF_WORKSPACE_RESERVED)
        except UnsafePathError as e:
            return unavailable(UNSAFE_KEY, f"unsafe key {e.value!r}: {e.reason}")
        if sum(len(v.encode("utf-8")) for v in tree.values()) > MAX_REQUEST_BYTES:
            return unavailable(TOO_LARGE, "request exceeds 8 MiB")
        if not any(k.startswith(WORKLOAD + "/") and k.endswith((".tf", ".tf.json")) for k in tree):
            return unavailable(NO_ROOT_MODULE, "no infra/workload root module in the request")
        ensure_typed = getattr(self.binaries, "ensure_typed", None)
        if ensure_typed is not None:
            binary, reason, binary_code = ensure_typed(engine)
        else:   # an injected binaries object with the plain contract: a failure is "not ready yet"
            binary, reason = self.binaries.ensure(engine)
            binary_code = ENGINE_NOT_READY
        if not binary:
            return unavailable(binary_code or ENGINE_NOT_READY, reason)
        base["provider_versions"] = self.mirror_provider_versions()
        if not self._sem.acquire(timeout=self.timeout_s):
            return unavailable(CONCURRENCY_LIMIT, "validate concurrency limit: timed out waiting for a slot")
        tmp = tempfile.mkdtemp(prefix="validate-")
        try:
            self._write_cli_config()
            for rel, text in tree.items():
                dest = os.path.join(tmp, *rel.split("/"))
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                with open(dest, "w", encoding="utf-8") as fh:
                    fh.write(text)
            home = os.path.join(tmp, ".home")
            os.makedirs(home, exist_ok=True)
            os.makedirs(self.plugin_cache_dir, exist_ok=True)
            env = scrubbed_env(home, self.cli_config, self.plugin_cache_dir)
            wd = os.path.join(tmp, *WORKLOAD.split("/"))
            deadline = time.monotonic() + self.timeout_s

            def remaining() -> int:
                left = int(deadline - time.monotonic())
                if left <= 0:
                    raise subprocess.TimeoutExpired("validate", self.timeout_s)
                return left

            if not self._init_lock.acquire(timeout=remaining()):
                raise subprocess.TimeoutExpired("init", self.timeout_s)
            try:
                r = self.runner([binary, "init", "-backend=false", "-input=false", "-no-color"], wd, env, remaining())
            finally:
                self._init_lock.release()
            if r.returncode != 0:
                v = self.runner([binary, "validate", "-json", "-no-color"], wd, env, remaining())
                diags = config_diagnostics(v.stdout)
                if diags is not None:
                    return done("FAIL", "configuration invalid (reported before init)", diags)
                return unavailable(engine_run_code(INIT_FAILED), "init failed: " + (r.stderr or r.stdout or "")[-800:])
            v = self.runner([binary, "validate", "-json", "-no-color"], wd, env, remaining())
            try:
                vj = json.loads(v.stdout or "")
            except json.JSONDecodeError:
                return unavailable(UNPARSEABLE_OUTPUT,
                                   "unparseable validate output: " + ((v.stdout or "") + (v.stderr or ""))[-400:])
            diags = [_rekey(d) for d in vj.get("diagnostics", []) if isinstance(d, dict)]
            if vj.get("valid"):
                return done("PASS", "", diags)
            if not any(d.get("severity") == "error" for d in diags):
                return unavailable(NO_ERROR_DIAGNOSTIC, "validate reported invalid without an error diagnostic")
            return done("FAIL", "", diags)
        except subprocess.TimeoutExpired:
            return unavailable(engine_run_code(TIMEOUT), f"validate timed out after {self.timeout_s}s")
        except Exception as e:  # noqa: BLE001 - never a PASS
            logger.warning(f"/validate error for trace {trace_id}: {type(e).__name__}: {e}")
            return unavailable(INTERNAL_ERROR, f"{type(e).__name__}: {e}")
        finally:
            self._sem.release()
            shutil.rmtree(tmp, ignore_errors=True)
