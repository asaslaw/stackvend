"""FD-30 parent runner (code red-team findings 1c, 4, 5, 6, 7). Offline: fake Popen / fake credentials only; no
child is launched, no token is minted, nothing is downloaded."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

import run_examples  # noqa: E402
from stackvend_eval import tofu_runner  # noqa: E402

SA = "stackvend-eval@eval-test-project.iam.gserviceaccount.com"
_REAL_POPEN = run_examples.subprocess.Popen
_REAL_RUN = run_examples.subprocess.run


def _is_child(cmd, script):
    return isinstance(cmd, (list, tuple)) and any(str(c).endswith(script) for c in cmd)


class _FakeStdin:
    def __init__(self):
        self.data = ""

    def write(self, s):
        self.data += s

    def close(self):
        pass


class _DeadChild:
    """A child that exits without ever writing result.json (OS kill / interpreter crash)."""
    launched = []

    def __init__(self, cmd, **kwargs):
        _DeadChild.launched.append({"cmd": cmd, "env": kwargs.get("env")})
        self.stdin = _FakeStdin()
        self.returncode = None

    def wait(self, timeout=None):
        self.returncode = -9
        return self.returncode

    def kill(self):
        pass


def _fake_popen(cmd, **kwargs):
    """Only the generation child is faked; read-only git calls (head_sha / is_dirty) run for real."""
    return _DeadChild(cmd, **kwargs) if _is_child(cmd, "run_child.py") else _REAL_POPEN(cmd, **kwargs)


def _args(tmp_path, *extra, llm="live"):
    argv = ["--llm", llm, "--model", "gemini-3.8-flash", "--examples", "01", "--runs", "1",
            "--out", str(tmp_path / "res"), "--out-id", "reused", "--accept-unverified-prices"]
    if llm in ("live", "record", "replay-then-live"):
        argv += ["--budget-usd", "5", "--run-cap", "2", "--vertex-project", "eval-test-project"]
    return run_examples.build_parser().parse_args(argv + list(extra))


def _stale_run_dir(inv):
    rd = inv.out / "runs" / "01-r1"
    rd.mkdir(parents=True, exist_ok=True)
    (rd / "result.json").write_text(json.dumps({"example": "01", "run": 1, "valid_run": True,
                                                "pipeline_outcome": "committed_passed",
                                                "budget": {"settled_usd": 0.01, "outstanding_usd": 0.0}}))
    (rd / "score.json").write_text(json.dumps({"stale": True}))
    (rd / "child.log").write_text("STALE LOG FROM A PREVIOUS INVOCATION\n")
    return rd


def test_stale_result_is_removed_and_a_dead_child_is_charged_its_full_allocation(tmp_path, monkeypatch):
    """RT finding 4 (+5: -B, +1c: the flag reaches the minting call)."""
    minted = []
    monkeypatch.setattr(run_examples, "mint_access_token", lambda sa=None: minted.append(sa) or "fake-not-a-token")
    monkeypatch.setattr(run_examples.subprocess, "Popen", _fake_popen)
    _DeadChild.launched.clear()
    inv = run_examples.Invocation(_args(tmp_path, "--impersonate-service-account", SA))
    inv.preflight()
    rd = _stale_run_dir(inv)
    rec = inv.run_one(inv.examples[0], 1, [])
    assert not (rd / "result.json").exists() and not (rd / "score.json").exists()
    assert "STALE" not in (rd / "child.log").read_text()
    assert rec["result"]["invalid_reasons"] == ["harness_error"] and rec["result"]["valid_run"] is False
    assert rec["result"]["charged_usd"] == pytest.approx(2.0)   # full allocation, not the stale $0.01
    assert minted == [SA]
    cmd = _DeadChild.launched[0]["cmd"]
    assert cmd[1:3] == ["-I", "-B"] and cmd[3].endswith("run_child.py")
    assert _DeadChild.launched[0]["env"]["PYTHONDONTWRITEBYTECODE"] == "1"
    assert inv.manifest([])["child_token_identity"] == "impersonated:" + SA


def test_stale_result_is_removed_even_when_the_run_returns_before_launch(tmp_path):
    inv = run_examples.Invocation(_args(tmp_path, "--cassettes", str(tmp_path / "no-cassettes"), llm="replay-strict"))
    rd = _stale_run_dir(inv)
    rec = inv.run_one(inv.examples[0], 1, [])
    assert rec["result"]["invalid_reasons"] == ["replay_miss"]
    assert not (rd / "result.json").exists()   # score() only scores dirs that have a result.json


def test_score_removes_a_stale_score_json_before_the_scoring_child(tmp_path, monkeypatch):
    launched = []
    monkeypatch.setattr(run_examples.subprocess, "run",  # the scoring child "dies" without writing score.json
                        lambda cmd, **k: launched.append(cmd) if _is_child(cmd, "score_child.py") else _REAL_RUN(cmd, **k))
    inv = run_examples.Invocation(_args(tmp_path, llm="synthetic"))
    inv.out.mkdir(parents=True, exist_ok=True)
    rd = _stale_run_dir(inv)
    records = [{"key": "01-r1", "run_dir": str(rd), "result": {}}]
    inv.score(records)
    assert not (rd / "score.json").exists() and "score" not in records[0]
    assert launched and launched[0][1:3] == ["-I", "-B"]


def test_scoring_and_child_env_never_write_bytecode(tmp_path):
    assert run_examples.child_env(tmp_path, "gemini-3.8-flash", {})["PYTHONDONTWRITEBYTECODE"] == "1"
    assert run_examples.scoring_env(tmp_path)["PYTHONDONTWRITEBYTECODE"] == "1"


# --------------------------------------------------------------------------- RT finding 1c: SA impersonation
class _FakeCreds:
    def __init__(self, token_after_refresh):
        self.token = None
        self._next = token_after_refresh
        self.refreshed = 0

    def refresh(self, request):
        assert request == "fake-request"
        self.refreshed += 1
        self.token = self._next


class _FakeImpersonated(_FakeCreds):
    made = []

    def __init__(self, **kwargs):
        super().__init__("sa-scoped-fake-token")
        _FakeImpersonated.made.append(kwargs)


def _fake_default(source):
    calls = []

    def default(scopes=None):
        calls.append(scopes)
        return source, "owner-project"
    return default, calls


def test_default_mint_uses_owner_adc_and_never_impersonates():
    source = _FakeCreds("owner-fake-token")
    default, calls = _fake_default(source)
    _FakeImpersonated.made.clear()
    tok = run_examples.mint_access_token(None, _default=default, _impersonated=_FakeImpersonated,
                                         _request=lambda: "fake-request")
    assert tok == "owner-fake-token" and calls == [run_examples.SCOPES] and _FakeImpersonated.made == []


def test_impersonated_mint_returns_the_service_account_token_with_bounded_lifetime():
    source = _FakeCreds("owner-fake-token")
    default, calls = _fake_default(source)
    _FakeImpersonated.made.clear()
    tok = run_examples.mint_access_token(SA, _default=default, _impersonated=_FakeImpersonated,
                                         _request=lambda: "fake-request")
    assert tok == "sa-scoped-fake-token"            # the child never sees the owner's token
    assert source.refreshed == 0                    # the owner token is only the impersonation source
    (kw,) = _FakeImpersonated.made
    assert kw["source_credentials"] is source and kw["target_principal"] == SA
    assert kw["target_scopes"] == ["https://www.googleapis.com/auth/cloud-platform"]
    assert 0 < kw["lifetime"] <= 3600                # AC-5: the IAM default maximum


@pytest.mark.parametrize("extra,llm,msg", [
    (["--impersonate-service-account", SA], "synthetic", "only applies"),
    (["--impersonate-service-account", "owner@gmail.com"], "live", "service account email"),
    (["--impersonate-service-account", SA, "--timeout-min", "61"], "live", "lifetime"),
])
def test_impersonation_flag_preflight_refusals(tmp_path, extra, llm, msg):
    inv = run_examples.Invocation(_args(tmp_path, *extra, llm=llm))
    with pytest.raises(SystemExit, match=msg):
        inv.preflight()


def test_ac5_default_wall_clock_fits_the_impersonated_token(tmp_path):
    a = _args(tmp_path)
    assert a.timeout_min == 45.0
    assert run_examples.IMPERSONATED_TOKEN_LIFETIME_S == 3600
    assert a.timeout_min * 60 <= run_examples.IMPERSONATED_TOKEN_LIFETIME_S
    run_examples.Invocation(_args(tmp_path, "--impersonate-service-account", SA)).preflight()   # no refusal


def test_impersonation_flag_is_off_by_default(tmp_path):
    a = _args(tmp_path)
    assert a.impersonate_service_account is None
    inv = run_examples.Invocation(a)
    inv.preflight()
    assert inv.manifest([])["child_token_identity"] == "owner_adc"


# ------------------------------------------------------------------------- RT findings 6/7: supply chain pins
def test_eval_requirements_are_exact_pins_including_lark():
    reqs = [ln.split("#")[0].strip() for ln in (ROOT / "eval" / "requirements.txt").read_text().splitlines()]
    reqs = [r for r in reqs if r]
    assert reqs and all("==" in r and not any(c in r for c in "<>~!*") for r in reqs), reqs
    assert any(r.startswith("lark==") for r in reqs)


def test_mirror_manifest_is_written_then_verified_and_tampering_fails_closed(tmp_path):
    mirror = tmp_path / "mirror"
    zp = mirror / "registry.opentofu.org" / "hashicorp" / "google" / "terraform-provider-google_6.1.0_darwin_arm64.zip"
    zp.parent.mkdir(parents=True)
    zp.write_bytes(b"fake provider bytes")
    (zp.parent / "index.json").write_text('{"versions": {"6.1.0": {}}}')

    def runner(name):
        return tofu_runner.TofuRunner(tmp_path / name, mirror, tofu_bin="/nonexistent/tofu")

    r0 = runner("w0")                                       # warmed before manifests existed: not trusted
    assert r0.mirror_manifest["status"] == "missing_manifest" and r0.mirror_ready is False
    assert "/nonexistent/tofu-mirror" in r0.cli_config.read_text()
    tofu_runner.write_mirror_manifest(mirror)
    r1 = runner("w1")
    assert r1.mirror_manifest["status"] == "verified" and r1.mirror_ready is True
    assert json.dumps(str(mirror)) in r1.cli_config.read_text()
    assert run_examples._mirror_manifest_digest(mirror) == r1.mirror_manifest["manifest_sha256"]
    zp.write_bytes(b"tampered provider bytes")
    r2 = runner("w2")
    assert r2.mirror_manifest["status"] == "mismatch" and r2.mirror_ready is False
    assert any("sha256 mismatch" in p for p in r2.mirror_manifest["problems"])
    assert "/nonexistent/tofu-mirror" in r2.cli_config.read_text()
    tofu_runner.write_mirror_manifest(mirror)
    (zp.parent / "extra.zip").write_bytes(b"x")
    r3 = runner("w3")
    assert r3.mirror_manifest["status"] == "mismatch" and any("unlisted" in p for p in r3.mirror_manifest["problems"])
    empty = tofu_runner.TofuRunner(tmp_path / "w4", tmp_path / "empty-mirror", tofu_bin="/nonexistent/tofu")
    assert empty.mirror_manifest["status"] == "empty" and empty.mirror_ready is False


def test_path_arguments_are_made_absolute_against_the_callers_cwd(tmp_path, monkeypatch):
    """Children run with cwd=<tmpdir>: a relative --cassettes / --product-root must not be resolved there."""
    monkeypatch.chdir(tmp_path)
    a = run_examples.absolutize_paths(run_examples.build_parser().parse_args(
        ["--llm", "replay-strict", "--model", "gemini-3.8-flash", "--cassettes", "cas/rec", "--product-root", "prod",
         "--out", "res", "--pricing", "p.json", "--tofu-mirror", "m", "--tofu-bin", "tb",
         "--oracle-tofu-bin", "otb", "--oracle-tofu-mirror", "om"]))
    for attr in run_examples.PATH_ARGS:
        v = getattr(a, attr)
        assert Path(v).is_absolute() and Path(v).parent.resolve() in (tmp_path.resolve(), (tmp_path / "cas").resolve()), (attr, v)
    assert a.cassettes == str((tmp_path / "cas" / "rec").resolve())
    b = run_examples.absolutize_paths(run_examples.build_parser().parse_args(
        ["--llm", "synthetic", "--model", "gemini-3.8-flash"]))
    assert b.cassettes is None


def test_a_failing_stage_persists_its_traceback():
    """A stage error used to be recorded as one line ('AttributeError: ...'); the traceback is kept for debugging."""
    from stackvend_eval import stages as st
    from stackvend_eval.state import RunState
    pipe = st.Pipeline(state=RunState(), mods={}, proxy=None, product_id="p", spec_text="", trace_id="t")

    def boom():
        return "x".items()
    pipe._developer = lambda ares, comp: boom()
    pipe._architect = lambda: None
    pipe._compliance = lambda ares: None
    pipe.run()
    dev = pipe.stages["developer"]
    assert pipe.outcome == "generation_error" and dev["ok"] is False
    assert dev["error"].startswith("AttributeError")
    assert "in boom" in dev["traceback"] and "AttributeError" in dev["traceback"]
