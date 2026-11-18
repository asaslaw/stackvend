"""FD-4DM: /validate/ready is not ready while the terraform server's first warm-up pass is still filling the provider
mirror (10-27 live incident: `ready: true` once `hashicorp/google` was mirrored while google-beta / kubernetes /
random were still downloading). Typed `mirror_complete` / `mirror_missing` / `warmup` fields; after the pass the
earlier rule (engine + google) stands, so a version the pass could not mirror is reported, never a permanent
not-ready. The VRW-1 caller-side wait (pinned schema-slice versions) still works against the real service object.
Also FD-4CW on the terraform-server side: the built-in `terraform` provider is accepted and never mirrored.
Hermetic: fake binaries, a fake mirror fill, a virtual clock; no thread, no network, no tofu."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import importlib
import itertools
import os
import sys
from unittest.mock import patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
if TF_DIR not in sys.path:
    sys.path.insert(0, TF_DIR)

vs = importlib.import_module("validate_service")
pa = importlib.import_module("provider_allowlist")

OS_ARCH = "linux_amd64"
GOOGLE = ("registry.opentofu.org", "google", "6.35.0")


class FakeBinaries:
    os_arch = OS_ARCH

    def __init__(self, path="/fake/tofu", reason=""):
        self.path, self.reason = path, reason
        self.calls = []

    def ensure(self, engine):
        self.calls.append(engine)
        return (self.path, "") if self.path else (None, self.reason)


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


def put(mirror_dir, reg, ptype, version):
    d = os.path.join(mirror_dir, reg, "hashicorp", ptype, version, OS_ARCH)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, f"terraform-provider-{ptype}_v{version}_x5"), "w") as fh:
        fh.write("bin")


def make(tmp_path, entries=(GOOGLE,), binaries=None, **kw):
    mirror_dir = str(tmp_path / "mirror")
    for e in entries:
        put(mirror_dir, *e)
    clock = Clock()
    svc = vs.ValidateService(str(tmp_path / "tooling"), mirror_dir=mirror_dir, binaries=binaries or FakeBinaries(),
                             clock=clock, **kw)
    return svc, mirror_dir, clock


def fill_all(mirror_dir, skip=()):
    def fill():
        for e in vs.MIRROR_EXPECTED:
            if e not in skip:
                put(mirror_dir, *e)
    return fill


def label(e):
    reg, ptype, version = e
    return f"{reg}/hashicorp/{ptype} {version}"


# ------------------------------------------------------------------------------------------------ the expected set
def test_expected_mirror_is_every_pinned_version_on_both_registries():
    want = {(reg, p, v) for reg in pa.PROVIDER_REGISTRIES for p, vs_ in pa.MIRROR_PROVIDER_VERSIONS.items() for v in vs_}
    assert set(vs.MIRROR_EXPECTED) == want and len(vs.MIRROR_EXPECTED) == len(want) == 16
    assert {p for _, p, _ in vs.MIRROR_EXPECTED} == set(vs.VALIDATE_PROVIDERS)
    assert "terraform" not in {p for _, p, _ in vs.MIRROR_EXPECTED}   # the built-in provider is never mirrored


# ------------------------------------------------------------------------------------------------ Do No Harm
def test_negative_no_warmup_keeps_the_earlier_rule(tmp_path):
    """No warm-up (tests, local runs): google alone is still ready, exactly as before; the new fields only report."""
    svc, _, _ = make(tmp_path)
    r = svc.ready()
    assert r["ready"] is True and r["reason"] == "" and r["providers"] == ["google"]
    assert r["provider_versions"] == {"hashicorp/google": ["6.35.0"]}
    assert r["warmup"] == "not_started" and r["mirror_complete"] is False
    assert r["mirror_missing"] == [label(e) for e in vs.MIRROR_EXPECTED if e != GOOGLE]


def test_negative_no_warmup_no_google_and_no_binary_unchanged(tmp_path):
    r = make(tmp_path / "a", entries=())[0].ready()
    assert r["ready"] is False and r["reason"] == "provider mirror not populated (google missing)"
    r = make(tmp_path / "b", binaries=FakeBinaries(path=None, reason="no checksum"))[0].ready()
    assert r["ready"] is False and r["reason"] == "no checksum"


def test_full_mirror_is_complete(tmp_path):
    svc, _, _ = make(tmp_path, entries=vs.MIRROR_EXPECTED)
    r = svc.ready()
    assert r["ready"] is True and r["mirror_complete"] is True and r["mirror_missing"] == []
    assert r["provider_versions"] == {f"hashicorp/{p}": sorted(v) for p, v in pa.MIRROR_PROVIDER_VERSIONS.items()}


# ------------------------------------------------------------------------------------------------ the fix
def test_not_ready_while_the_first_warmup_pass_runs(tmp_path):
    """The incident: google mirrored, the rest still downloading -> not ready (it used to be ready)."""
    svc, mirror_dir, _ = make(tmp_path)
    passes = []
    assert svc.start_warmup(fill_all(mirror_dir), spawn=passes.append) is True
    r = svc.ready()
    assert r["ready"] is False and r["warmup"] == "running"
    assert r["reason"] == "provider mirror warm-up still running (15 of 16 provider versions not mirrored yet)"
    assert r["provider_versions"] == {"hashicorp/google": ["6.35.0"]}     # still reported as it is
    passes[0]()                                                            # the pass ends
    r = svc.ready()
    assert r["ready"] is True and r["warmup"] == "done" and r["mirror_complete"] is True and r["reason"] == ""
    assert svc.binaries.calls[0] == "opentofu"                             # engine first, then the mirror


def test_complete_mirror_is_still_held_until_the_pass_ends(tmp_path):
    """A file may still be mid-copy while the pass runs, so only the end of the pass turns ready on."""
    svc, _, _ = make(tmp_path, entries=vs.MIRROR_EXPECTED)
    passes = []
    svc.start_warmup(lambda: None, spawn=passes.append)
    r = svc.ready()
    assert r["ready"] is False and r["mirror_complete"] is True and r["warmup"] == "running"
    passes[0]()
    assert svc.ready()["ready"] is True


def test_pass_that_cannot_mirror_a_version_reports_it_and_keeps_the_earlier_rule(tmp_path):
    gap = ("registry.opentofu.org", "random", "3.6.3")
    svc, mirror_dir, _ = make(tmp_path)
    passes = []
    svc.start_warmup(fill_all(mirror_dir, skip={gap}), spawn=passes.append)
    passes[0]()
    r = svc.ready()
    assert r["ready"] is True and r["mirror_complete"] is False and r["mirror_missing"] == [label(gap)]


def test_failing_pass_ends_the_warmup(tmp_path):
    svc, _, _ = make(tmp_path)
    passes = []

    def boom():
        raise RuntimeError("rc write failed")
    svc.start_warmup(boom, spawn=passes.append)
    passes[0]()                                                            # logged, never raised
    r = svc.ready()
    assert r["warmup"] == "done" and r["ready"] is True and r["mirror_complete"] is False


def test_pass_without_google_is_not_ready_with_the_google_reason(tmp_path):
    svc, mirror_dir, _ = make(tmp_path, entries=())
    passes = []
    svc.start_warmup(lambda: None, spawn=passes.append)
    assert svc.ready()["reason"] == "provider mirror not populated (google missing)"   # while running
    passes[0]()
    assert svc.ready()["reason"] == "provider mirror not populated (google missing)"   # after


def test_missing_binary_reason_wins_while_running(tmp_path):
    svc, _, _ = make(tmp_path, binaries=FakeBinaries(path=None, reason="no checksum"))
    svc.start_warmup(lambda: None, spawn=lambda run: None)
    r = svc.ready()
    assert r["ready"] is False and r["reason"] == "no checksum" and r["warmup"] == "running"


def test_a_stuck_pass_stops_holding_ready_after_the_grace(tmp_path):
    svc, _, clock = make(tmp_path, warmup_grace_s=300.0)
    svc.start_warmup(lambda: None, spawn=lambda run: None)                # never finishes
    clock.now += 299.0
    assert svc.ready()["ready"] is False
    clock.now += 1.0
    r = svc.ready()
    assert r["ready"] is True and r["warmup"] == "running" and r["mirror_complete"] is False


def test_only_the_first_start_runs_a_pass(tmp_path):
    svc, _, _ = make(tmp_path)
    passes = []
    assert svc.start_warmup(lambda: None, spawn=passes.append) is True
    assert svc.start_warmup(lambda: None, spawn=passes.append) is False
    passes[0]()
    assert svc.start_warmup(lambda: None, spawn=passes.append) is False and len(passes) == 1


def test_a_pass_that_cannot_start_never_holds_ready(tmp_path):
    svc, _, _ = make(tmp_path)

    def no_thread(run):
        raise RuntimeError("can't start new thread")
    with pytest.raises(RuntimeError):
        svc.start_warmup(lambda: None, spawn=no_thread)
    r = svc.ready()
    assert r["warmup"] == "done" and r["ready"] is True


def test_server_startup_uses_the_tracked_warmup():
    """main.py starts the warm-up through ValidateService.start_warmup with the server's own mirror fill (parsed)."""
    tree = ast.parse(open(os.path.join(TF_DIR, "main.py")).read())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_start_validate_warmup")
    calls = [c for c in ast.walk(fn) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
             and c.func.attr == "start_warmup"]
    assert len(calls) == 1
    call = calls[0]
    assert isinstance(call.func.value, ast.Name) and call.func.value.id == "validate_service"
    arg = call.args[0]
    assert isinstance(arg, ast.Attribute) and arg.attr == "_ensure_provider_mirror" and arg.value.id == "service"
    assert not any(isinstance(c.func, ast.Attribute) and c.func.attr == "Thread"
                   for c in ast.walk(fn) if isinstance(c, ast.Call))      # no untracked second thread


# ------------------------------------------------------------------------------------------------ VRW-1 still works
def _gateway_wait():
    pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")
    gw = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
    if gw not in sys.path:
        sys.path.insert(0, gw)
    from developer_agent import hallucination_runtime as hr
    return hr


SLICE = {"hashicorp/google": "6.35.0", "hashicorp/google-beta": "6.35.0", "hashicorp/kubernetes": "2.36.0",
         "hashicorp/random": "3.7.1"}


def _parity(answer):
    have = answer.get("provider_versions") or {}
    return all(v in (have.get(p) or ()) for p, v in SLICE.items())


@pytest.mark.parametrize("accept", [None, _parity], ids=["mode-off-ready-only", "vrw1-pinned-versions"])
def test_gateway_wait_returns_only_after_the_pass(tmp_path, accept):
    """The gateway's bounded wait against the real service object: the first probes (pass running, only google
    mirrored) are not ready; the pass ends during the second sleep; the next probe is ready and, for VRW-1, every
    pinned slice version is served. Before FD-4DM the first probe was already `ready: true`."""
    hr = _gateway_wait()
    svc, mirror_dir, _ = make(tmp_path)
    passes = []
    svc.start_warmup(fill_all(mirror_dir), spawn=passes.append)
    sleeps = []
    now = itertools.count()

    def sleep(s):
        sleeps.append(s)
        if len(sleeps) == 2:
            passes[0]()

    class Client:
        def ready(self, iac_engine):
            return svc.ready(iac_engine)
    with patch.object(hr, "_sleep", sleep), patch.object(hr, "_clock", lambda: float(next(now))):
        got, probes, _ = hr.wait_for_validate_ready(Client(), "OPENTOFU", 180, accept=accept)
    assert got["ready"] is True and probes == 3 and _parity(got) and got["mirror_complete"] is True


# ------------------------------------------------------------------------------------------------ FD-4CW (server side)
def test_fd4cw_builtin_terraform_provider_accepted_and_never_installed(tmp_path):
    """`terraform_data` / `terraform_remote_state` need no install (OpenTofu built-in); an unknown provider is still
    refused; the validate service's mirror-only CLI config never names the built-in provider."""
    root = tmp_path / "ok"
    root.mkdir()
    (root / "main.tf").write_text('resource "terraform_data" "t" {\n  input = "x"\n}\n'
                                  'data "terraform_remote_state" "s" {\n  backend = "gcs"\n}\n')
    assert pa.disallowed_providers(str(root)) == []
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "main.tf").write_text('resource "terraform_data" "t" {}\nresource "null_resource" "n" {}\n')
    assert pa.disallowed_providers(str(bad)) == ["registry.opentofu.org/hashicorp/null"]
    cfg = pa.cli_config("/m", registry=False)
    assert "builtin" not in cfg and "direct" not in cfg
    gw_tables = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway", "developer_agent", "validators",
                             "policy_tables.py")
    tree = ast.parse(open(gw_tables).read())
    builtin = next(n.value for n in tree.body if isinstance(n, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == "BUILTIN_PROVIDERS" for t in n.targets))
    assert ast.literal_eval(builtin.args[0]) == {pa.BUILTIN_PROVIDER.rsplit("/", 1)[1]}   # gateway V2d == server
