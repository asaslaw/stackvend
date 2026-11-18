"""Step 1 S1-B: the terraform server's POST /validate + GET /validate/ready (lane 8B §8; HS-03, HS-05, HS-52).
Hermetic: a fake runner records argv/env; the binary download is a fake fetch. Real tofu only where noted (skipped
with a reason when the host has no tofu or no verified offline mirror)."""
import hermetic_guard  # noqa: F401  (first import)

import hashlib
import importlib
import io
import json
import os
import subprocess
import sys
import zipfile

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
if TF_DIR not in sys.path:
    sys.path.insert(0, TF_DIR)

vs = importlib.import_module("validate_service")
bc = importlib.import_module("binary_checksums")

W = "infra/workload/"


def _zip(name="tofu"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(name, "#!/bin/sh\nexit 0\n")
    return buf.getvalue()


class FakeBinaries:
    os_arch = "linux_amd64"

    def __init__(self, path="/fake/tofu", reason=""):
        self.path, self.reason = path, reason

    def ensure(self, engine):
        return (self.path, "") if self.path else (None, self.reason)


class Runner:
    def __init__(self, init_rc=0, init_out="", validate_outputs=()):
        self.init_rc, self.init_out = init_rc, init_out
        self.validate_outputs = list(validate_outputs)
        self.calls = []

    def __call__(self, cmd, cwd, env, timeout):
        self.calls.append({"cmd": cmd, "cwd": cwd, "env": dict(env), "files": sorted(
            os.path.relpath(os.path.join(r, f), cwd) for r, _, fs in os.walk(cwd) for f in fs)})
        if cmd[1] == "init":
            return subprocess.CompletedProcess(cmd, self.init_rc, self.init_out, "init error text")
        out = self.validate_outputs.pop(0) if self.validate_outputs else json.dumps({"valid": True, "diagnostics": []})
        return subprocess.CompletedProcess(cmd, 0, out, "")


def _svc(tmp_path, runner, binaries=None, mirror=True):
    mirror_dir = tmp_path / "mirror"
    if mirror:
        d = mirror_dir / "registry.opentofu.org/hashicorp/google/6.35.0/linux_amd64"
        d.mkdir(parents=True)
        (d / "terraform-provider-google_v6.35.0_x5").write_text("bin")
    return vs.ValidateService(str(tmp_path / "tooling"), mirror_dir=str(mirror_dir),
                              binaries=binaries or FakeBinaries(), runner=runner)


TREE = {W + "main.tf": 'resource "google_storage_bucket" "b" {\n  name = "b"\n}\n', "apps/a/main.py": "x = 1\n"}


def test_pass_runs_init_and_validate_in_a_scrubbed_throwaway_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/secret/key.json")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "host-project")
    runner = Runner()
    out = _svc(tmp_path, runner).validate(TREE, "OPENTOFU", "t1")
    assert out["status"] == "PASS" and out["engine"] == "OPENTOFU" and out["engine_version"] == "1.9.0"
    assert [c["cmd"][1:3] for c in runner.calls] == [["init", "-backend=false"], ["validate", "-json"]]
    for c in runner.calls:
        assert not any(k.startswith("GOOGLE_") for k in c["env"]), c["env"]   # no credentials reach the engine
        assert set(c["env"]) == {"PATH", "HOME", "TF_CLI_CONFIG_FILE", "TF_IN_AUTOMATION", "TF_INPUT",
                                 "CHECKPOINT_DISABLE", "LANG", "TZ", "TF_PLUGIN_CACHE_DIR",
                                 "TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE",
                                 "GCE_METADATA_HOST", "GCE_METADATA_IP"}   # FD-7L 2a: unroutable metadata host
        assert c["env"]["GCE_METADATA_HOST"] == c["env"]["GCE_METADATA_IP"] == "127.0.0.1:9"
        # RT F3: one shared provider cache under the tooling dir (not inside the throw-away workspace)
        assert c["env"]["TF_PLUGIN_CACHE_DIR"] == str(tmp_path / "tooling" / "validate-plugin-cache")
        assert c["env"]["TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE"] == "1"
        assert os.path.isdir(c["env"]["TF_PLUGIN_CACHE_DIR"])
        assert c["files"] == ["main.tf"]                                       # only infra/ is written
        assert c["cmd"][0] == "/fake/tofu"
    assert not os.path.exists(runner.calls[0]["cwd"])                          # throw-away dir removed
    cfg = open(tmp_path / "tooling" / "validate.tfrc").read()
    assert "direct" not in cfg and "hashicorp/kubernetes" in cfg and "hashicorp/random" in cfg


def test_fail_rekeys_diagnostics_to_repo_paths(tmp_path):
    diag = {"severity": "error", "summary": "Reference to undeclared resource",
            "range": {"filename": "main.tf", "start": {"line": 2, "byte": 10}, "end": {"line": 2, "byte": 20}}}
    runner = Runner(validate_outputs=[json.dumps({"valid": False, "diagnostics": [diag]})])
    out = _svc(tmp_path, runner).validate(TREE)
    assert out["status"] == "FAIL" and out["diagnostics"][0]["range"]["filename"] == W + "main.tf"


def test_init_refusal_is_fail_only_when_every_error_is_located(tmp_path):
    located = {"valid": False, "diagnostics": [{"severity": "error", "summary": "Missing newline after argument",
                                                "range": {"filename": "main.tf", "start": {"line": 2}}}]}
    out = _svc(tmp_path, Runner(init_rc=1, validate_outputs=[json.dumps(located)])).validate(TREE)
    assert out["status"] == "FAIL" and out["diagnostics"][0]["range"]["filename"] == W + "main.tf"
    unlocated = {"valid": False, "diagnostics": [{"severity": "error", "summary": "Missing required provider"}]}
    out = _svc(tmp_path / "b", Runner(init_rc=1, validate_outputs=[json.dumps(unlocated)])).validate(TREE)
    assert out["status"] == "UNAVAILABLE" and "init failed" in out["reason"]


@pytest.mark.parametrize("binaries,reason", [
    (FakeBinaries(path=None, reason="no owner-verified checksum"), "no owner-verified checksum"),
])
def test_missing_binary_is_unavailable_and_never_runs(tmp_path, binaries, reason):
    runner = Runner()
    out = _svc(tmp_path, runner, binaries=binaries).validate(TREE)
    assert out["status"] == "UNAVAILABLE" and reason in out["reason"] and runner.calls == []


def test_timeout_and_runner_errors_are_unavailable(tmp_path):
    def boom(cmd, cwd, env, timeout):
        raise subprocess.TimeoutExpired(cmd, timeout)
    assert _svc(tmp_path, boom).validate(TREE)["status"] == "UNAVAILABLE"
    out = _svc(tmp_path / "x", Runner(validate_outputs=["not json"])).validate(TREE)
    assert out["status"] == "UNAVAILABLE"
    out = _svc(tmp_path / "y", Runner(validate_outputs=[json.dumps({"valid": False, "diagnostics": []})])).validate(TREE)
    assert out["status"] == "UNAVAILABLE"


def test_request_shape_errors_are_unavailable(tmp_path):
    svc = _svc(tmp_path, Runner())
    assert svc.validate({"apps/a.py": "x"})["status"] == "UNAVAILABLE"           # no root module
    traversal = "infra/../etc/x.tf"
    assert svc.validate({traversal: "x"})["status"] == "UNAVAILABLE"   # unsafe key
    assert svc.validate(TREE, "PULUMI")["status"] == "UNAVAILABLE"


def test_ready_reports_the_mirror_provider_set(tmp_path):
    ready = _svc(tmp_path, Runner()).ready()
    assert ready["ready"] is True and ready["providers"] == ["google"]
    assert ready["provider_versions"] == {"hashicorp/google": ["6.35.0"]}
    not_ready = _svc(tmp_path / "m", Runner(), mirror=False).ready()
    assert not_ready["ready"] is False and "mirror" in not_ready["reason"]
    no_bin = _svc(tmp_path / "n", Runner(), binaries=FakeBinaries(path=None, reason="no checksum")).ready()
    assert no_bin["ready"] is False and no_bin["reason"] == "no checksum"


# ------------------------------------------------------------------------------------------------ D12 binaries
def test_binary_verified_against_owner_checksum_before_unpacking(tmp_path, monkeypatch):
    data = _zip()
    digest = hashlib.sha256(data).hexdigest()

    def fetch(url, dest):
        assert url.endswith("tofu_1.9.0_linux_amd64.zip") and "github.com/opentofu" in url
        with open(dest, "wb") as fh:
            fh.write(data)
    monkeypatch.setitem(bc.BINARY_CHECKSUMS, ("opentofu", "1.9.0", "linux_amd64"),
                        {"sha256": digest, "source": "test", "fetched_by": "test", "fetched_on": "2026-10-12"})
    b = vs.VerifiedBinaries(str(tmp_path), fetch=fetch, os_arch="linux_amd64")
    path, reason = b.ensure("opentofu")
    assert reason == "" and os.access(path, os.X_OK) and not path.startswith("/usr")
    monkeypatch.setitem(bc.BINARY_CHECKSUMS, ("opentofu", "1.9.0", "linux_amd64"),
                        {"sha256": "0" * 64, "source": "test", "fetched_by": "t", "fetched_on": "2026-10-12"})
    b2 = vs.VerifiedBinaries(str(tmp_path / "2"), fetch=fetch, os_arch="linux_amd64")
    path2, reason2 = b2.ensure("opentofu")
    assert path2 is None and "sha256" in reason2
    assert not any(f.startswith("tofu") for f in os.listdir(tmp_path / "2" / "validate-bin"))  # nothing unpacked


def test_no_checksum_entry_means_no_binary_and_no_download(tmp_path):
    called = []
    b = vs.VerifiedBinaries(str(tmp_path), fetch=lambda u, d: called.append(u), os_arch="linux_arm64")
    assert b.ensure("opentofu") == (None, "no owner-verified checksum for opentofu 1.9.0 linux_arm64 "
                                          "(binary_checksums.py, D12)")
    assert called == []


def test_d12_rows_match_the_owner_fetched_sha256sums():
    """Step 0 (10-12): the OpenTofu 1.9.0 rows equal the owner-fetched upstream SHA256SUMS (kept gitignored at
    eval/.tools/); linux_amd64 (Cloud Run) and darwin_arm64 are present. Skips where the SHA256SUMS file is absent."""
    rows = {k: v for k, v in bc.BINARY_CHECKSUMS.items() if k[:2] == ("opentofu", "1.9.0")}
    assert {k[2] for k in rows} >= {"linux_amd64", "darwin_arm64"}
    sums_path = os.path.join(REPO_ROOT, "eval", ".tools", "tofu_1.9.0_SHA256SUMS")
    if not os.path.exists(sums_path):
        pytest.skip("owner-fetched tofu_1.9.0_SHA256SUMS not present on this machine")
    sums = dict(reversed(line.split()) for line in open(sums_path) if line.strip())
    for (_e, _v, arch), entry in rows.items():
        assert entry["sha256"] == sums[f"tofu_1.9.0_{arch}.zip"], arch


@pytest.mark.parametrize("engine,version", [("opentofu", "1.8.8"), ("opentofu", "1.10.0"), ("terraform", "1.5.7")])
def test_d1_rows_match_the_official_sha256sums(engine, version):
    """RT14 RT D1 (owner 11-14): the OpenTofu 1.8.8 / 1.10.0 and Terraform 1.5.7 rows name their official SHA256SUMS
    URL and equal that file (kept gitignored at eval/.tools/ when fetched); linux_amd64 and darwin_arm64 present."""
    rows = {k: v for k, v in bc.BINARY_CHECKSUMS.items() if k[:2] == (engine, version)}
    assert {k[2] for k in rows} == {"linux_amd64", "darwin_arm64"}
    prefix = "tofu" if engine == "opentofu" else "terraform"
    official = (f"https://github.com/opentofu/opentofu/releases/download/v{version}/tofu_{version}_SHA256SUMS"
                if engine == "opentofu" else
                f"https://releases.hashicorp.com/terraform/{version}/terraform_{version}_SHA256SUMS")
    assert {v["source"] for v in rows.values()} == {official}
    sums_path = os.path.join(REPO_ROOT, "eval", ".tools", f"{prefix}_{version}_SHA256SUMS")
    if not os.path.exists(sums_path):
        pytest.skip(f"official {prefix}_{version}_SHA256SUMS not present on this machine")
    sums = bc.parse_sha256sums(open(sums_path, encoding="utf-8").read())
    for (_e, _v, arch), entry in rows.items():
        assert entry["sha256"] == sums[f"{prefix}_{version}_{arch}.zip"], arch


def test_checksum_table_entries_are_well_formed():
    for (engine, version, os_arch), entry in bc.BINARY_CHECKSUMS.items():
        assert engine in ("opentofu", "terraform") and version and "_" in os_arch
        assert bc.expected_sha256(engine, version, os_arch), entry
        assert entry.get("source", "").startswith("https://") and entry.get("fetched_by") and entry.get("fetched_on")


def test_routes_are_registered():
    src = open(os.path.join(TF_DIR, "main.py")).read()
    assert '@app.post("/validate")' in src and '@app.get("/validate/ready")' in src


# ------------------------------------------------------------------------------------------------ real tofu
def test_real_tofu_file_call_is_not_evaluated_by_validate(tmp_path):
    """lane 15 RT E2 concern: validate evaluates some functions. A file() in an output is not read by `validate`
    (it is evaluated at plan); the throw-away dir holds only the request tree and the env carries no credentials
    (asserted above with the fake runner)."""
    from shutil import which
    tofu = which("tofu") or ("/opt/homebrew/bin/tofu" if os.path.exists("/opt/homebrew/bin/tofu") else None)
    mirror = os.path.join(REPO_ROOT, "eval", ".tofu-mirror")
    if not tofu or not os.path.isdir(mirror):
        pytest.skip("needs a host tofu and the verified offline mirror (eval/.tofu-mirror)")
    tree = {W + "main.tf": 'output "x" {\n  value = file("/etc/passwd")\n}\n'}

    class RealBinaries(FakeBinaries):
        def __init__(self):
            super().__init__(path=tofu)
    out = vs.ValidateService(str(tmp_path / "tooling"), mirror_dir=mirror, binaries=RealBinaries()).validate(tree)
    assert out["status"] == "PASS" and "root:" not in json.dumps(out)
