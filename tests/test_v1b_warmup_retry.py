"""V1B-WARMUP-RETRY (owner 10-30): a terraform server instance that is still warming up no longer stops the developer
stage with GATE_UNAVAILABLE.

Live failure: a repair round's V1b call reached a NEW terraform server instance whose warm-up was still filling the
provider mirror; /validate answered UNAVAILABLE and V1b raised ValidatorUnavailable. Now:
  - server: every UNAVAILABLE carries a typed `unavailable_code` (reason text unchanged); ENGINE_NOT_READY (engine
    not fetched yet, or an engine run that failed while the warm-up pass runs) and CONCURRENCY_LIMIT are transient.
  - gateway V1b: a transient code -> the bounded /validate/ready wait, then ONE more /validate call. Anything else
    (a permanent code, a response without the field) -> ValidatorUnavailable exactly as before, never a pass.
Hermetic: fake runner, fake binaries / fetch, virtual clock; no network, no tofu."""
import hermetic_guard  # noqa: F401  (first import)

import importlib
import json
import os
import subprocess
import sys
from unittest.mock import patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TF_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
TESTS = os.path.dirname(__file__)
for p in (GATEWAY, REPO_ROOT, TESTS, TF_DIR):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

vs = importlib.import_module("validate_service")

from developer_agent import hallucination_runtime as hr  # noqa: E402
from developer_agent.validators import ValidationContext, ValidatorUnavailable  # noqa: E402
from developer_agent.validators import step1 as s1  # noqa: E402
from shared.artifact_ownership import Ownership  # noqa: E402

W = "infra/workload/"
TREE = {W + "main.tf": 'resource "google_storage_bucket" "b" {\n  name = "b"\n}\n', "apps/a/main.py": "x = 1\n"}
UNLOCATED_INIT = json.dumps({"valid": False, "diagnostics": [
    {"severity": "error", "summary": "Missing required provider"}]})   # no range: an installation problem


# ------------------------------------------------------------------------------------------------ server fakes
class FakeBinaries:
    """The plain `ensure` contract (no ensure_typed), like the fakes in the existing /validate tests."""
    os_arch = "linux_amd64"

    def __init__(self, path="/fake/tofu", reason=""):
        self.path, self.reason = path, reason

    def ensure(self, engine):
        return (self.path, "") if self.path else (None, self.reason)


class Runner:
    def __init__(self, init_rc=0, validate_outputs=(), raise_on=None):
        self.init_rc, self.validate_outputs, self.raise_on = init_rc, list(validate_outputs), raise_on
        self.calls = []

    def __call__(self, cmd, cwd, env, timeout):
        self.calls.append(cmd[1])
        if self.raise_on == cmd[1]:
            raise subprocess.TimeoutExpired(cmd, timeout)
        if cmd[1] == "init":
            return subprocess.CompletedProcess(cmd, self.init_rc, "", "Error: Failed to install provider")
        out = self.validate_outputs.pop(0) if self.validate_outputs else json.dumps({"valid": True, "diagnostics": []})
        return subprocess.CompletedProcess(cmd, 0, out, "")


def _svc(tmp_path, runner, binaries=None, **kw):
    d = tmp_path / "mirror" / "registry.opentofu.org/hashicorp/google/6.35.0/linux_amd64"
    d.mkdir(parents=True)
    (d / "terraform-provider-google_v6.35.0_x5").write_text("bin")
    return vs.ValidateService(str(tmp_path / "tooling"), mirror_dir=str(tmp_path / "mirror"),
                              binaries=binaries or FakeBinaries(), runner=runner, **kw)


def _warming(svc):
    """A warm-up pass that has started and not finished (the spawned function is never run)."""
    held = []
    assert svc.start_warmup(lambda: None, spawn=held.append) is True
    assert svc.warmup_state() == vs.WARMUP_RUNNING
    return held[0]


# ------------------------------------------------------------------------------------------------ server: codes
def test_live_case_init_during_warmup_is_engine_not_ready(tmp_path):
    """The live path: the engine binary is there (the warm-up fetched it first), the mirror is still being filled,
    `init` fails and the un-initialized validate reports only an unlocated error -> ENGINE_NOT_READY, same reason."""
    runner = Runner(init_rc=1, validate_outputs=[UNLOCATED_INIT])
    svc = _svc(tmp_path, runner)
    _warming(svc)
    out = svc.validate(TREE)
    assert out["status"] == "UNAVAILABLE" and out["unavailable_code"] == vs.ENGINE_NOT_READY
    assert out["reason"] == "init failed: Error: Failed to install provider"   # reason text unchanged


def test_init_failure_after_warmup_is_init_failed(tmp_path):
    runner = Runner(init_rc=1, validate_outputs=[UNLOCATED_INIT])
    svc = _svc(tmp_path, runner)
    run = _warming(svc)
    run()   # the pass ends
    assert svc.warmup_state() == vs.WARMUP_DONE
    out = svc.validate(TREE)
    assert (out["status"], out["unavailable_code"]) == ("UNAVAILABLE", vs.INIT_FAILED)


def test_init_failure_without_warmup_is_init_failed(tmp_path):
    out = _svc(tmp_path, Runner(init_rc=1, validate_outputs=[UNLOCATED_INIT])).validate(TREE)
    assert out["unavailable_code"] == vs.INIT_FAILED


def test_warmup_ending_during_the_request_is_still_engine_not_ready(tmp_path):
    """Sampled at the start too: the pass may end between the request start and the failure."""
    svc = _svc(tmp_path, None)
    run = _warming(svc)

    def runner(cmd, cwd, env, timeout):
        if cmd[1] == "init":
            run()   # the warm-up finishes while init runs
            return subprocess.CompletedProcess(cmd, 1, "", "Error: Failed to install provider")
        return subprocess.CompletedProcess(cmd, 0, UNLOCATED_INIT, "")
    svc.runner = runner
    assert svc.validate(TREE)["unavailable_code"] == vs.ENGINE_NOT_READY


def test_located_config_error_during_warmup_stays_fail(tmp_path):
    """Do No Harm: a configuration FAIL reported before init is unchanged by the warm-up state."""
    located = json.dumps({"valid": False, "diagnostics": [
        {"severity": "error", "summary": "Unsupported argument", "range": {"filename": "main.tf"}}]})
    svc = _svc(tmp_path, Runner(init_rc=1, validate_outputs=[located]))
    _warming(svc)
    out = svc.validate(TREE)
    assert out["status"] == "FAIL" and "unavailable_code" not in out


def test_timeout_is_timeout_but_engine_not_ready_while_warming(tmp_path):
    out = _svc(tmp_path / "a", Runner(raise_on="init")).validate(TREE)
    assert (out["unavailable_code"], out["reason"]) == (vs.TIMEOUT, "validate timed out after 60s")
    svc = _svc(tmp_path / "b", Runner(raise_on="init"))
    _warming(svc)
    assert svc.validate(TREE)["unavailable_code"] == vs.ENGINE_NOT_READY


def test_engine_binary_not_ready_is_engine_not_ready(tmp_path):
    """The `ensure` failure path: a plain-contract binaries object, and the real VerifiedBinaries whose download
    failed (the next call downloads again)."""
    out = _svc(tmp_path / "a", Runner(), binaries=FakeBinaries(path=None, reason="download failed")).validate(TREE)
    assert (out["unavailable_code"], out["reason"]) == (vs.ENGINE_NOT_READY, "download failed")

    def fetch(url, dest):
        raise OSError("connection reset")
    vb = vs.VerifiedBinaries(str(tmp_path / "b"), fetch=fetch, os_arch="linux_amd64")
    runner = Runner()
    out = _svc(tmp_path / "b", runner, binaries=vb).validate(TREE)
    assert out["status"] == "UNAVAILABLE" and out["unavailable_code"] == vs.ENGINE_NOT_READY
    assert out["reason"].startswith("opentofu 1.9.0 download/verify failed: OSError")
    assert runner.calls == []
    path, reason = vb.ensure("opentofu")   # the plain contract is unchanged (and it tries the download again)
    assert path is None and reason.startswith("opentofu 1.9.0 download/verify failed: OSError")


def test_no_checksum_row_is_permanent(tmp_path):
    vb = vs.VerifiedBinaries(str(tmp_path), fetch=lambda u, d: None, os_arch="plan9_mips")
    out = _svc(tmp_path, Runner(), binaries=vb).validate(TREE)
    assert out["unavailable_code"] == vs.ENGINE_UNVERIFIABLE
    assert out["reason"].startswith("no owner-verified checksum for opentofu 1.9.0 plan9_mips")
    assert vb.ensure("opentofu")[1] == out["reason"]   # the plain contract is unchanged


def test_concurrency_limit(tmp_path):
    svc = _svc(tmp_path, Runner(), concurrency=1, timeout_s=0)
    assert svc._sem.acquire(timeout=1)
    try:
        out = svc.validate(TREE)
    finally:
        svc._sem.release()
    assert (out["unavailable_code"], out["reason"]) == (
        vs.CONCURRENCY_LIMIT, "validate concurrency limit: timed out waiting for a slot")


@pytest.mark.parametrize("files,engine,code,reason", [
    (TREE, "PULUMI", "UNKNOWN_ENGINE", "unknown engine 'PULUMI'"),
    ({W + "../x.tf": "x"}, "OPENTOFU", "UNSAFE_KEY", None),
    ({W + "main.tf": "x" * (vs.MAX_REQUEST_BYTES + 1)}, "OPENTOFU", "TOO_LARGE", "request exceeds 8 MiB"),
    ({"infra/other/main.tf": "x"}, "OPENTOFU", "NO_ROOT_MODULE", "no infra/workload root module in the request"),
])
def test_request_shape_codes_are_permanent(tmp_path, files, engine, code, reason):
    out = _svc(tmp_path, Runner()).validate(files, engine)
    assert out["status"] == "UNAVAILABLE" and out["unavailable_code"] == code
    assert code not in vs.RETRYABLE_UNAVAILABLE_CODES
    if reason is not None:
        assert out["reason"] == reason


def test_engine_output_codes_are_permanent(tmp_path):
    out = _svc(tmp_path / "a", Runner(validate_outputs=["not json"])).validate(TREE)
    assert out["unavailable_code"] == vs.UNPARSEABLE_OUTPUT
    no_err = json.dumps({"valid": False, "diagnostics": [{"severity": "warning", "summary": "w"}]})
    out = _svc(tmp_path / "b", Runner(validate_outputs=[no_err])).validate(TREE)
    assert out["unavailable_code"] == vs.NO_ERROR_DIAGNOSTIC

    def boom(cmd, cwd, env, timeout):
        raise RuntimeError("runner broke")
    out = _svc(tmp_path / "c", boom).validate(TREE)
    assert (out["unavailable_code"], out["reason"]) == (vs.INTERNAL_ERROR, "RuntimeError: runner broke")


def test_pass_and_fail_carry_no_code(tmp_path):
    assert "unavailable_code" not in _svc(tmp_path / "a", Runner()).validate(TREE)
    bad = json.dumps({"valid": False, "diagnostics": [{"severity": "error", "summary": "x", "range": {}}]})
    out = _svc(tmp_path / "b", Runner(validate_outputs=[bad])).validate(TREE)
    assert out["status"] == "FAIL" and "unavailable_code" not in out


def test_code_tables_agree_with_the_gateway():
    assert vs.RETRYABLE_UNAVAILABLE_CODES == {"ENGINE_NOT_READY", "CONCURRENCY_LIMIT"}
    assert vs.RETRYABLE_UNAVAILABLE_CODES <= vs.UNAVAILABLE_CODES
    assert s1.V1B_RETRYABLE_UNAVAILABLE_CODES == vs.RETRYABLE_UNAVAILABLE_CODES


# ------------------------------------------------------------------------------------------------ gateway: V1b
def _ctx(files):
    return ValidationContext.build(files, ownership=lambda p: Ownership.LLM_AUTHORED, vendored=frozenset(), draft={},
                                   assembly=None, extras={}, trace_id="t")


@pytest.fixture()
def clock():
    state = {"now": 0.0, "sleeps": []}

    def sleep(s):
        state["sleeps"].append(s)
        state["now"] += s
    with patch.object(hr, "_sleep", sleep), patch.object(hr, "_clock", lambda: state["now"]):
        yield state


READY = {"ready": True, "reason": ""}
NOT_READY = {"ready": False, "reason": "provider mirror warm-up still running (3 of 8 not mirrored yet)"}
COLD = {"status": "UNAVAILABLE", "unavailable_code": "ENGINE_NOT_READY", "reason": "init failed: x", "diagnostics": []}
PASS = {"status": "PASS", "diagnostics": []}
FAIL_RAW = {"severity": "error", "summary": "Unsupported argument", "detail": "x",
            "range": {"filename": W + "main.tf", "start": {"line": 1, "column": 1, "byte": 0},
                      "end": {"line": 1, "column": 9, "byte": 8}}}
FAIL = {"status": "FAIL", "diagnostics": [FAIL_RAW]}


class Scripted:
    """validate() and ready() answer from scripts; the last entry repeats."""

    def __init__(self, validates, readies=(READY,)):
        self.validates, self.readies = list(validates), list(readies)
        self.calls, self.probes = [], 0

    def validate(self, files, *, iac_engine="OPENTOFU", trace_id=""):
        self.calls.append(dict(files))
        return self.validates[min(len(self.calls) - 1, len(self.validates) - 1)]

    def ready(self, iac_engine="OPENTOFU"):
        self.probes += 1
        return self.readies[min(self.probes - 1, len(self.readies) - 1)]


def _v1b(client, wait=180):
    return s1.TofuValidateValidator(client, ready_wait_s=wait)


def test_cold_then_ready_passes_after_one_wait_and_retry(clock):
    client = Scripted([COLD, PASS], readies=[NOT_READY, NOT_READY, READY])
    assert _v1b(client).validate(_ctx(TREE)) == []
    assert len(client.calls) == 2 and client.probes == 3
    assert client.calls[0] == client.calls[1] == {W + "main.tf": TREE[W + "main.tf"]}
    assert clock["now"] <= 180


def test_concurrency_limit_is_retried(clock):
    busy = {"status": "UNAVAILABLE", "unavailable_code": "CONCURRENCY_LIMIT", "reason": "slots", "diagnostics": []}
    client = Scripted([busy, PASS])
    assert _v1b(client).validate(_ctx(TREE)) == []
    assert (len(client.calls), client.probes) == (2, 1)


def test_retry_that_reports_fail_returns_the_diagnostics(clock):
    client = Scripted([COLD, FAIL])
    got = _v1b(client).validate(_ctx(TREE))
    assert [d.severity for d in got] == ["error"] and len(client.calls) == 2


@pytest.mark.parametrize("code", sorted(vs.UNAVAILABLE_CODES - vs.RETRYABLE_UNAVAILABLE_CODES))
def test_permanent_code_is_immediately_unavailable(clock, code):
    client = Scripted([{"status": "UNAVAILABLE", "unavailable_code": code, "reason": "r", "diagnostics": []}, PASS])
    with pytest.raises(ValidatorUnavailable, match="^r$"):
        _v1b(client).validate(_ctx(TREE))
    assert (len(client.calls), client.probes, clock["sleeps"]) == (1, 0, [])


def test_still_unavailable_after_the_retry_is_unavailable(clock):
    client = Scripted([COLD, COLD])
    with pytest.raises(ValidatorUnavailable, match="^init failed: x$"):
        _v1b(client).validate(_ctx(TREE))
    assert (len(client.calls), client.probes) == (2, 1)   # exactly one retry, never more


def test_never_ready_within_the_budget_is_unavailable_without_a_retry(clock):
    client = Scripted([COLD, PASS], readies=[NOT_READY])
    with pytest.raises(ValidatorUnavailable) as e:
        _v1b(client, wait=180).validate(_ctx(TREE))
    assert "ENGINE_NOT_READY" in str(e.value) and "still not ready" in str(e.value)
    assert len(client.calls) == 1 and clock["now"] <= 180


def test_zero_budget_is_one_probe(clock):
    client = Scripted([COLD, PASS], readies=[READY])
    assert s1.TofuValidateValidator(client).validate(_ctx(TREE)) == []   # default ready_wait_s = 0
    assert (len(client.calls), client.probes, clock["sleeps"]) == (2, 1, [])


@pytest.mark.parametrize("resp", [
    {"status": "UNAVAILABLE", "reason": "init failed: old server", "diagnostics": []},   # older server: no field
    {"status": "UNAVAILABLE", "unavailable_code": None, "reason": "init failed: old server"},
    {"status": "UNAVAILABLE", "unavailable_code": "engine_not_ready", "reason": "init failed: old server"},
    {"status": "PASS", "unavailable_code": "ENGINE_NOT_READY", "diagnostics": []},     # code only counts on UNAVAILABLE
])
def test_response_without_a_retryable_code_is_unchanged(clock, resp):
    client = Scripted([resp, PASS])
    if resp["status"] == "PASS":
        assert _v1b(client).validate(_ctx(TREE)) == []
    else:
        with pytest.raises(ValidatorUnavailable, match="^init failed: old server$"):
            _v1b(client).validate(_ctx(TREE))
    assert (len(client.calls), client.probes) == (1, 0)


@pytest.mark.parametrize("resp", [PASS, FAIL])
def test_negative_normal_answer_makes_exactly_one_call(clock, resp):
    client = Scripted([resp, COLD])
    _v1b(client).validate(_ctx(TREE))
    assert (len(client.calls), client.probes, clock["sleeps"]) == (1, 0, [])


def test_client_without_ready_fails_closed(clock):
    class NoReady:
        def __init__(self):
            self.calls = 0

        def validate(self, files, **kw):
            self.calls += 1
            return COLD if self.calls == 1 else PASS
    c = NoReady()
    with pytest.raises(ValidatorUnavailable):
        _v1b(c).validate(_ctx(TREE))
    assert c.calls == 1


def _v1b_of(stack):
    found = [r.validator for r in stack._regs if r.validator.id == "V1b"]
    assert len(found) == 1
    return found[0]


def test_build_step1_stack_passes_the_wait_budget():
    stack = s1.build_step1_stack(validate_client=Scripted([PASS]), verifier_factory=lambda: None,
                                 validate_ready_wait_s=42)
    assert _v1b_of(stack).ready_wait_s == 42
    assert _v1b_of(s1.build_step1_stack(validate_client=None, verifier_factory=lambda: None)).ready_wait_s == 0.0


def _cold_instance_client():
    """The dispatch-start readiness gate sees a ready instance; the first V1b call then lands on a NEW instance that
    is still warming (ENGINE_NOT_READY); that instance's /validate/ready answers not ready once, then ready."""
    from test_step1_s1b_generation import Client

    class Cold(Client):
        def __init__(self):
            super().__init__()
            self.not_ready_left = 0

        def ready(self, iac_engine="OPENTOFU"):
            if self.not_ready_left:
                self.not_ready_left -= 1
                return dict(NOT_READY)
            return super().ready(iac_engine)

        def validate(self, files, *, iac_engine="OPENTOFU", trace_id=""):
            self.validated.append(dict(files))
            if len(self.validated) == 1:
                self.not_ready_left = 1
                return dict(COLD)
            return {"status": "PASS", "diagnostics": []}
    return Cold()


@pytest.mark.parametrize("wait_s,recovers", [(120, True), (0, False)])
def test_developer_stage_uses_the_setting_and_recovers_from_a_cold_instance(wait_s, recovers):
    """End to end through DeveloperAgent.generate_code_files, with settings.validate_ready_wait_s reaching V1b:
    120 s -> V1b waits (virtual clock) and retries -> PASS; 0 s -> one not-ready probe -> GATE_UNAVAILABLE ['V1b']
    as before (never a pass)."""
    from shared.diagnostics import ErrorClass, StageError
    from shared.hallucination_stack import HallucinationStackSettings
    from test_step1_s1b_generation import _agent, _generate, _runtime

    client = _cold_instance_client()
    now = [0.0]

    def sleep(s):
        now[0] += s
    with patch.object(hr, "_sleep", sleep), patch.object(hr, "_clock", lambda: now[0]):
        agent = _agent(_runtime(client, settings=HallucinationStackSettings(validate_ready_wait_s=wait_s)))
        if recovers:
            _generate(agent)
            assert agent.last_validation_report.status == "PASS"
            assert len(client.validated) == 2
        else:
            with pytest.raises(StageError) as e:
                _generate(agent)
            assert e.value.error_class == ErrorClass.GATE_UNAVAILABLE
            assert len(client.validated) == 1
