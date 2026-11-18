"""OpenTofu in the scoring child, treating generated IaC as untrusted (plan §3.3, §5; red-team H6).

- Only `fmt`, `init -backend=false`, `validate -json` and `test` are ever invoked. No plan/apply/import/state.
- Offline: TF_CLI_CONFIG_FILE points at a provider_installation with ONLY a filesystem_mirror (no `direct`), and on
  macOS every tofu process runs under `sandbox-exec` with outbound IP networking denied. Warm the mirror once in an
  explicit, owner-approved step (`run_examples.py --warm-tofu-mirror`).
- Remote module sources (git::, registry, http) are refused before `init` (parsed with python-hcl2).
- Generated *.tftest.hcl files and tests/ dirs are removed; `tofu test` runs only the harness file via
  -test-directory/-filter, with a mock_provider for EVERY provider in the lock file (fail closed otherwise), so
  `external`/`http`/`local`/`null` data sources are inert.
- Env is an allowlist: temp HOME, empty CLOUDSDK_CONFIG, no GOOGLE_* variables.
- Mirror integrity (RT finding 7): the warm-up writes MANIFEST.sha256 (sha256 of every mirrored file) into the
  mirror; every TofuRunner re-verifies it and treats a missing manifest or any mismatch as "no mirror" (fail closed).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import hclparse

SANDBOX_EXEC = "/usr/bin/sandbox-exec"
SANDBOX_PROFILE = "(version 1)(allow default)(deny network-outbound (remote ip))"
ALLOWED_SUBCOMMANDS = {"fmt", "init", "validate", "test", "version"}
HARNESS_TEST_DIR = ".stackvend_eval_tests"
HARNESS_TEST_FILE = "plan.tftest.hcl"
WORKLOAD = "infra/workload"
MIRROR_MANIFEST = "MANIFEST.sha256"


def _sha256_file(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _mirror_files(mirror: Path) -> List[str]:
    mirror = Path(mirror)
    return sorted(str(p.relative_to(mirror)) for p in mirror.rglob("*")
                  if p.is_file() and not p.is_symlink() and p.name != MIRROR_MANIFEST)


def write_mirror_manifest(mirror: Path) -> Path:
    """Record the sha256 of every file the warm-up mirrored (`<sha256>  <relpath>` lines, sorted)."""
    mirror = Path(mirror)
    lines = [f"{_sha256_file(mirror / rel)}  {rel}" for rel in _mirror_files(mirror)]
    out = mirror / MIRROR_MANIFEST
    out.write_text("\n".join(lines) + "\n")
    return out


def verify_mirror_manifest(mirror: Path) -> Dict[str, Any]:
    """{'status': 'verified'|'missing_manifest'|'mismatch'|'empty', 'problems': [...], 'manifest_sha256': ...}."""
    mirror = Path(mirror)
    files = _mirror_files(mirror) if mirror.is_dir() else []
    mf = mirror / MIRROR_MANIFEST
    if not files:
        return {"status": "empty", "problems": [], "manifest_sha256": None}
    if not mf.is_file():
        return {"status": "missing_manifest", "problems": [f"{MIRROR_MANIFEST} not found"], "manifest_sha256": None}
    want: Dict[str, str] = {}
    problems: List[str] = []
    for ln in mf.read_text().splitlines():
        if not ln.strip():
            continue
        digest, _, rel = ln.partition("  ")
        want[rel] = digest
    for rel in sorted(set(want) - set(files)):
        problems.append(f"missing: {rel}")
    for rel in sorted(set(files) - set(want)):
        problems.append(f"unlisted: {rel}")
    for rel in sorted(set(files) & set(want)):
        if _sha256_file(mirror / rel) != want[rel]:
            problems.append(f"sha256 mismatch: {rel}")
    return {"status": "mismatch" if problems else "verified", "problems": problems[:50],
            "manifest_sha256": _sha256_file(mf)}


def find_tofu() -> Optional[str]:
    for c in (shutil.which("tofu"), "/opt/homebrew/bin/tofu", "/usr/local/bin/tofu"):
        if c and os.path.exists(c) and os.access(c, os.X_OK):
            return c
    return None


class TofuRunner:
    def __init__(self, work_root: Path, mirror_dir: Optional[Path], tofu_bin: Optional[str] = None,
                 sandbox: Optional[bool] = None, timeout_s: int = 300):
        self.work_root = Path(work_root)
        self.work_root.mkdir(parents=True, exist_ok=True)
        self.tofu = tofu_bin or find_tofu()
        self.mirror_dir = Path(mirror_dir) if mirror_dir else None
        self.sandbox = (sys.platform == "darwin" and os.path.exists(SANDBOX_EXEC)) if sandbox is None else sandbox
        self.timeout_s = timeout_s
        self.home = Path(tempfile.mkdtemp(prefix="tofu-home-", dir=self.work_root))
        self.cloudsdk = Path(tempfile.mkdtemp(prefix="cloudsdk-", dir=self.work_root))
        self.cli_config = self.work_root / "tofu-cli.tfrc"
        self.mirror_manifest = (verify_mirror_manifest(self.mirror_dir) if self.mirror_dir
                                else {"status": "empty", "problems": [], "manifest_sha256": None})
        trusted = self.mirror_manifest["status"] in ("verified", "empty")
        mirror = (str(self.mirror_dir) if (self.mirror_dir and self.mirror_dir.is_dir() and trusted)
                  else "/nonexistent/tofu-mirror")
        self.cli_config.write_text('provider_installation {\n  filesystem_mirror {\n    path    = '
                                   + json.dumps(mirror) + '\n    include = ["*/*/*"]\n  }\n}\n')
        self.mirror_ready = self.mirror_manifest["status"] == "verified"
        self._fmt_cache: Dict[str, Tuple[bool, str]] = {}
        self._tree_cache: Dict[str, Dict[str, Any]] = {}

    @property
    def available(self) -> bool:
        return self.tofu is not None

    def env(self) -> Dict[str, str]:
        return {"PATH": "/usr/bin:/bin", "HOME": str(self.home), "CLOUDSDK_CONFIG": str(self.cloudsdk),
                "TF_CLI_CONFIG_FILE": str(self.cli_config), "CHECKPOINT_DISABLE": "1", "TF_IN_AUTOMATION": "1",
                "TF_INPUT": "0", "LANG": "C.UTF-8", "TZ": "UTC"}

    def _run(self, args: List[str], cwd: Optional[Path] = None, stdin: Optional[str] = None) -> subprocess.CompletedProcess:
        if not args or args[0] not in ALLOWED_SUBCOMMANDS:
            raise PermissionError(f"tofu subcommand refused: {args[:1]}")
        if args[0] == "test" and not any(a.startswith("-filter=") for a in args):
            raise PermissionError("tofu test must be filtered to the harness test file")
        cmd = [self.tofu, *args]
        if self.sandbox:
            cmd = [SANDBOX_EXEC, "-p", SANDBOX_PROFILE, *cmd]
        return subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=self.env(), input=stdin, capture_output=True,
                              text=True, timeout=self.timeout_s)

    # ------------------------------------------------------------------------------------------------ fmt
    def fmt_ok(self, text: str) -> Tuple[bool, str]:
        import hashlib
        h = hashlib.sha256(text.encode()).hexdigest()
        if h not in self._fmt_cache:
            r = self._run(["fmt", "-no-color", "-"], stdin=text)
            self._fmt_cache[h] = (r.returncode == 0, (r.stderr or "")[-400:])
        return self._fmt_cache[h]

    def score_hcl_parse(self, tree: Dict[str, str]) -> Dict[str, Any]:
        tf = {k: v for k, v in tree.items() if k.endswith(".tf")}
        fails = {}
        for p, t in sorted(tf.items()):
            ok, err = self.fmt_ok(t)
            if not ok:
                fails[p] = err
        return {"tf_files": len(tf), "hcl_parse_ok": len(tf) - len(fails), "hcl_parse_fail": fails}

    # -------------------------------------------------------------------------------------------- trees
    @staticmethod
    def write_tree(tree: Dict[str, str], dest: Path) -> None:
        dest = dest.resolve()
        for rel, text in tree.items():
            p = (dest / rel).resolve()
            if not str(p).startswith(str(dest) + os.sep):
                continue  # path traversal in generated file names: skip
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)

    def validate_tree(self, tree: Dict[str, str], label: str, *, plan: bool = True,
                      tree_key: Optional[str] = None) -> Dict[str, Any]:
        if tree_key and tree_key in self._tree_cache:
            return dict(self._tree_cache[tree_key], cached=True)
        res = self._validate_tree(tree, label, plan=plan)
        if tree_key:
            self._tree_cache[tree_key] = res
        return res

    def _validate_tree(self, tree: Dict[str, str], label: str, *, plan: bool) -> Dict[str, Any]:
        out: Dict[str, Any] = {"status": None}
        if not self.available:
            out["status"] = "tofu_unavailable"
            return out
        if not any(p.startswith(WORKLOAD + "/") and p.endswith(".tf") for p in tree):
            out["status"] = "no_workload"
            return out
        try:
            parsed, bad = hclparse.parse_tree(tree, "infra/")
        except hclparse.HclUnavailable:
            out["status"] = "skipped_no_hcl_parser"
            return out
        remote = [(p, m, s) for p, m, s in hclparse.module_sources(parsed) if not hclparse.is_local_source(s)]
        if remote:
            out.update(status="remote_module_source", remote_sources=[{"file": p, "module": m, "source": s}
                                                                     for p, m, s in remote])
            return out
        out["structure_unavailable_files"] = sorted(bad)
        root = self.work_root / "trees" / label
        if root.exists():
            shutil.rmtree(root)
        self.write_tree(tree, root)
        wd = root / WORKLOAD
        for p in list(wd.rglob("*.tftest.hcl")) + list(wd.rglob("*.tftest.json")):
            p.unlink()
        if (wd / "tests").is_dir():
            shutil.rmtree(wd / "tests")
        # -backend=false: any backend block in generated code is never configured or contacted.
        r = self._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd)
        out["init_ok"] = r.returncode == 0
        if r.returncode != 0:
            msg = (r.stderr or r.stdout or "")[-1500:]
            out["status"] = "init_failed_offline_mirror" if not self.mirror_ready else "init_failed"
            out["init_error"] = msg
            return out
        r = self._run(["validate", "-json", "-no-color"], cwd=wd)
        try:
            vj = json.loads(r.stdout or "{}")
        except json.JSONDecodeError:
            vj = {"valid": False, "diagnostics": [{"severity": "error", "summary": "unparseable validate output",
                                                   "detail": (r.stdout + r.stderr)[-500:]}]}
        out["validate_ok"] = bool(vj.get("valid"))
        out["diagnostics"] = [normalize_diag(d) for d in vj.get("diagnostics", [])][:200]
        out["status"] = "validated"
        if plan and out["validate_ok"]:
            out["plan"] = self._mock_plan(wd, parsed)
        return out

    def _mock_plan(self, wd: Path, parsed: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        lock = wd / ".terraform.lock.hcl"
        try:
            addrs = hclparse.lockfile_providers(lock.read_text()) if lock.exists() else []
        except Exception as e:  # noqa: BLE001
            return {"plan_ok": False, "status": "lockfile_unparseable", "error": str(e)[:200]}
        root_parsed = {p: d for p, d in parsed.items() if p.startswith(WORKLOAD + "/")}
        req = hclparse.required_providers(root_parsed)
        by_source = {}
        for local, src in req.items():
            by_source[src.split("/", 1)[-1] if src.count("/") == 2 else src] = local
        locals_: List[str] = []
        for a in addrs:
            short = "/".join(a.split("/")[-2:])  # namespace/type
            locals_.append(by_source.get(short) or by_source.get(a) or a.split("/")[-1])
        aliases = [(n, al) for n, al in hclparse.provider_aliases(root_parsed) if al]
        lines = []
        for name in sorted(set(locals_)):
            lines.append(f'mock_provider "{name}" {{}}')
        for name, al in sorted(set(aliases)):
            lines.append(f'mock_provider "{name}" {{\n  alias = "{al}"\n}}')
        mocked = set(locals_)
        unmocked = sorted({n for n, _ in hclparse.provider_aliases(root_parsed)} - mocked)
        if unmocked:
            return {"plan_ok": False, "status": "unmocked_provider", "unmocked": unmocked}
        var_lines = []
        for name, body in sorted(hclparse.variables(root_parsed).items()):
            if "default" in body:
                continue
            typ = str(body.get("type", "string"))
            val = ('"eval-mock-' + name + '"') if "string" in typ or typ == "${string}" else (
                "1" if "number" in typ else ("false" if "bool" in typ else ("[]" if "list" in typ or "set" in typ else "{}")))
            var_lines.append(f"    {name} = {val}")
        test = "\n".join(lines) + '\n\nrun "plan" {\n  command = plan\n'
        if var_lines:
            test += "  variables {\n" + "\n".join(var_lines) + "\n  }\n"
        test += "}\n"
        assert "command = apply" not in test
        td = wd / HARNESS_TEST_DIR
        td.mkdir(exist_ok=True)
        (td / HARNESS_TEST_FILE).write_text(test)
        r = self._run(["test", f"-test-directory={HARNESS_TEST_DIR}",
                       f"-filter={HARNESS_TEST_DIR}/{HARNESS_TEST_FILE}", "-no-color"], cwd=wd)
        text = (r.stdout or "") + (r.stderr or "")
        return {"plan_ok": r.returncode == 0, "status": "tested", "providers_mocked": sorted(mocked),
                "output_tail": text[-1500:]}


def normalize_diag(d: Dict[str, Any]) -> Dict[str, Any]:
    rng = d.get("range") or {}
    return {"tool": "tofu-validate", "severity": d.get("severity"), "summary": d.get("summary"),
            "detail": (d.get("detail") or "")[:300], "file": rng.get("filename"),
            "line": (rng.get("start") or {}).get("line"), "address": d.get("address")}
