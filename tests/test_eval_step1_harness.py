"""S1-0 (Step 1 harness additions, integration plan §S.6 step 2): provider-set pins, D12 binary verification,
HarnessValidateClient file IPC, per-ID healer bypass, cassette merge, assembly metrics. Hermetic: no network, no
product import; real `tofu` only where noted (skipped with a reason when the binary or the offline mirror is absent).
"""
import hermetic_guard  # noqa: F401  (first import: network/credential guard)

import functools
import hashlib
import io
import json
import shutil
import sys
import threading
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

from stackvend_eval import provider_sets as ps  # noqa: E402
from stackvend_eval.blobs import BlobStore  # noqa: E402
from stackvend_eval.healer_probe import HealerProbe  # noqa: E402
from stackvend_eval.paths import have_hcl2  # noqa: E402
from stackvend_eval.state import RunState  # noqa: E402
from stackvend_eval.validate_client import (HarnessValidateClient, ParentValidateServer,  # noqa: E402
                                            _config_diagnostics, repo_key_for)

sys.path.insert(0, str(ROOT))
from eval.tools import merge_cassettes as mc  # noqa: E402


# ----------------------------------------------------------------------------------------------- provider sets
def _mirror(tmp_path, providers, os_arch="darwin_arm64"):
    m = tmp_path / "mirror"
    lines = []
    for prov, ver in providers.items():
        ns, typ = prov.split("/")
        rel = f"registry.opentofu.org/{ns}/{typ}/terraform-provider-{typ}_{ver}_{os_arch}.zip"
        (m / rel).parent.mkdir(parents=True, exist_ok=True)
        (m / rel).write_bytes(b"zip")
        lines.append(f"{'0' * 64}  {rel}")
        lines.append(f"{'1' * 64}  registry.opentofu.org/{ns}/{typ}/index.json")
    (m / "MANIFEST.sha256").write_text("\n".join(lines) + "\n")
    return m


def test_production_set_pins_match_the_terraform_server_precache():
    prod = ps.get_set("production")
    assert prod["engine_version"] == "1.9.0"
    assert prod["providers"] == {"hashicorp/google": "6.35.0", "hashicorp/google-beta": "6.35.0",
                                 "hashicorp/kubernetes": "2.36.0", "hashicorp/random": "3.7.1"}
    # FD-4AQ W1b: the pre-cache versions moved to the terraform server's single allow-list source (service.py's
    # target_providers_map is provider_allowlist.MIRROR_PROVIDER_VERSIONS).
    import ast as _ast
    src = (ROOT / "mcp-servers/terraform/provider_allowlist.py").read_text()
    precache = next(_ast.literal_eval(n.value) for n in _ast.parse(src).body if isinstance(n, _ast.Assign)
                    and any(getattr(t, "id", "") == "MIRROR_PROVIDER_VERSIONS" for t in n.targets))
    assert "target_providers_map = provider_allowlist.MIRROR_PROVIDER_VERSIONS" in (
        ROOT / "mcp-servers/terraform/service.py").read_text()
    for prov, ver in prod["providers"].items():  # first (preferred) version of each pre-cached provider
        assert precache[prov.split("/")[1]][0] == ver


def test_mirror_accepted_only_for_exact_pins(tmp_path):
    pins = ps.get_set("production")["providers"]
    m = _mirror(tmp_path, pins)
    assert ps.check_mirror_matches_set(m, "production", os_arch="darwin_arm64") == pins
    with pytest.raises(ps.ProviderSetError, match="google: mirror has"):
        ps.check_mirror_matches_set(_mirror(tmp_path / "b", dict(pins, **{"hashicorp/google": "6.50.0"})),
                                    "production", os_arch="darwin_arm64")
    with pytest.raises(ps.ProviderSetError, match="extra provider hashicorp/null"):
        ps.check_mirror_matches_set(_mirror(tmp_path / "c", dict(pins, **{"hashicorp/null": "3.3.2"})),
                                    "production", os_arch="darwin_arm64")
    with pytest.raises(ps.ProviderSetError, match="missing hashicorp/random"):
        ps.check_mirror_matches_set(_mirror(tmp_path / "d", {k: v for k, v in pins.items() if "random" not in k}),
                                    "production", os_arch="darwin_arm64")
    with pytest.raises(ps.ProviderSetError, match="MANIFEST"):
        ps.check_mirror_matches_set(tmp_path / "nothing", "production")


def test_required_providers_block_pins_exactly():
    text = ps.required_providers_block("production")
    assert 'google = { source = "hashicorp/google", version = "= 6.35.0" }' in text
    assert ">=" not in text


def _zip_with_tofu(path: Path) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("tofu", "#!/bin/sh\necho fake\n")
        zf.writestr("LICENSE", "x")
    path.write_bytes(buf.getvalue())
    return buf.getvalue()


def test_release_zip_verified_against_sha256sums_before_unpacking(tmp_path):
    name = ps.release_zip_name("1.9.0", "darwin_arm64")
    zp = tmp_path / name
    digest = hashlib.sha256(_zip_with_tofu(zp)).hexdigest()
    sums = tmp_path / "SUMS"
    sums.write_text(f"{'a' * 64}  tofu_1.9.0_linux_amd64.zip\n{digest}  {name}\n")
    binary, got = ps.unpack_verified_tofu(zp, sums, "1.9.0", tmp_path / "out", os_arch="darwin_arm64")
    assert got == digest and binary.read_text().startswith("#!/bin/sh") and not (tmp_path / "out" / "LICENSE").exists()
    bad = tmp_path / "BAD"
    bad.write_text(f"{'b' * 64}  {name}\n")
    with pytest.raises(ps.ProviderSetError, match="sha256"):
        ps.unpack_verified_tofu(zp, bad, "1.9.0", tmp_path / "out2", os_arch="darwin_arm64")
    assert not (tmp_path / "out2").exists()  # nothing unpacked on mismatch
    dup = tmp_path / "DUP"
    dup.write_text(f"{digest}  {name}\n{digest}  {name}\n")
    with pytest.raises(ps.ProviderSetError, match="2 times"):
        ps.verify_release_zip(zp, dup, name)


# ----------------------------------------------------------------------------------------------- validate IPC
class _FakeColumn:
    available = True
    reason = ""
    mirror_status = "verified"
    mirror_dir = None
    tofu_bin = "/bin/false"

    def engine_version(self):
        return "1.9.0"

    def providers(self):
        return {"hashicorp/google": ["6.35.0"]}


def test_harness_client_round_trip_never_mutates_the_tree(tmp_path):
    seen = []

    class Server(ParentValidateServer):
        def handle(self, payload):
            seen.append(payload)
            if payload["op"] == "ready":
                return super().handle(payload)
            return {"status": "FAIL", "diagnostics": [{"severity": "error", "summary": "x"}], "engine": "OPENTOFU"}

    server = Server(tmp_path / "ipc", _FakeColumn(), work_root=tmp_path / "w", poll_s=0.01)
    server.start()
    try:
        client = HarnessValidateClient(tmp_path / "ipc", timeout_s=10, poll_s=0.01)
        assert client.ready() == {"ready": True, "engine": "OPENTOFU", "engine_version": "1.9.0",
                                  "providers": ["google"], "provider_versions": {"hashicorp/google": ["6.35.0"]},
                                  "reason": ""}
        tree = {"infra/workload/main.tf": 'resource "x" "y" {}\n', "apps/a/main.py": "x = 1\n"}
        before = json.dumps(tree, sort_keys=True)
        out = client.validate(tree, iac_engine="OPENTOFU", trace_id="t1")
        assert out["status"] == "FAIL"
        assert json.dumps(tree, sort_keys=True) == before
        assert seen[-1]["files"] == tree and seen[-1]["trace_id"] == "t1"
    finally:
        server.stop()


def test_harness_client_timeout_is_unavailable_never_pass(tmp_path):
    client = HarnessValidateClient(tmp_path / "ipc", timeout_s=0.2, poll_s=0.01)
    out = client.validate({"infra/workload/main.tf": ""})
    assert out["status"] == "UNAVAILABLE" and "timeout" in out["reason"]
    assert client.ready()["ready"] is False


def test_config_diagnostics_only_when_every_error_is_located():
    located = {"valid": False, "diagnostics": [{"severity": "error", "summary": "Missing newline after argument",
                                                "range": {"filename": "main.tf", "start": {"line": 2}}}]}
    unlocated = {"valid": False, "diagnostics": [{"severity": "error", "summary": "Missing required provider"}]}
    got = _config_diagnostics(json.dumps(located))
    assert got and got[0]["range"]["filename"] == "infra/workload/main.tf"
    assert _config_diagnostics(json.dumps(unlocated)) is None
    assert _config_diagnostics("not json") is None
    assert repo_key_for("../modules/compute-cloudrun/outputs.tf") == "infra/modules/compute-cloudrun/outputs.tf"
    assert repo_key_for("../../../etc/passwd") is None


def _real_tofu_and_mirror():
    from stackvend_eval.tofu_runner import find_tofu, verify_mirror_manifest
    t = find_tofu()
    mirror = ROOT / "eval" / ".tofu-mirror"
    if not t:
        pytest.skip("no tofu binary on this host")
    if not mirror.is_dir() or verify_mirror_manifest(mirror)["status"] != "verified":
        pytest.skip("eval/.tofu-mirror not warmed/verified (owner-approved download step)")
    return t, mirror


def test_real_tofu_syntax_error_is_fail_with_located_diagnostic(tmp_path):
    from stackvend_eval.tofu_runner import TofuRunner
    from stackvend_eval.validate_client import validate_tree_raw
    t, mirror = _real_tofu_and_mirror()
    runner = TofuRunner(tmp_path / "w", mirror, tofu_bin=t)
    broken = {"infra/workload/main.tf": 'output "x" {\n  value = [1, 2]]\n}\n'}
    out = validate_tree_raw(runner, broken, label="b", engine_version=None, providers={})
    assert out["status"] == "FAIL" and out["diagnostics"][0]["range"]["filename"] == "infra/workload/main.tf"
    ok = {"infra/workload/main.tf": 'output "x" {\n  value = [1, 2]\n}\n'}
    assert validate_tree_raw(runner, ok, label="o", engine_version=None, providers={})["status"] == "PASS"
    absent = {"infra/workload/main.tf": 'resource "aws_s3_bucket" "c" {}\n'}
    assert validate_tree_raw(runner, absent, label="a", engine_version=None, providers={})["status"] == "UNAVAILABLE"


# ----------------------------------------------------------------------------------------------- per-ID bypass
def test_bypass_ids_stub_only_the_listed_healers(tmp_path):
    import types
    src = ("from typing import Dict, List, Tuple, Optional\n"
           "def heal_a(s: str) -> str:\n    return s.replace('bad', 'good')\n"
           "def heal_b(s: str) -> str:\n    return s.replace('bad', 'good')\n"
           "def extract(raw_hcl: str) -> Optional[str]:\n    return None if not raw_hcl else raw_hcl.upper()\n")
    mod = types.ModuleType("evalprobe_bypass")
    exec(compile(src, "evalprobe_bypass.py", "exec"), mod.__dict__)
    sys.modules["evalprobe_bypass"] = mod
    try:
        targets = [{"key": f"{h}@{q}", "healer_id": h, "tier": "B", "kind": "function", "module": "evalprobe_bypass",
                    "qualname": q, "status": "present", "file": "apps/orchestrator-gateway/x.py"}
                   for h, q in (("HB-80", "heal_a"), ("HB-81", "heal_b"), ("HB-03", "extract"))]
        ident = {"heal_a": ("arg", "s"), "heal_b": ("arg", "s"), "extract": ("opt_arg", "raw_hcl")}
        probe = HealerProbe(RunState(), targets, str(tmp_path), BlobStore(tmp_path / "b"), identity=ident,
                            bypass_ids=["HB-80", "HB-03"])
        probe.install()
        try:
            assert mod.heal_a("bad") == "bad"          # bypassed
            assert mod.heal_b("bad") == "good"         # still running
            assert mod.extract("abc") == "abc"         # HB-03 identity: input unchanged
            assert mod.extract("") is None
        finally:
            probe.stop()
        st = {t["key"]: t for t in probe.report()["targets"]}
        assert st["HB-80@heal_a"]["healers_off"] == "bypassed"
        assert st["HB-81@heal_b"]["healers_off"] == "running: not in --bypass-healers"
        assert st["HB-03@extract"]["healers_off"] == "bypassed"
    finally:
        sys.modules.pop("evalprobe_bypass", None)


# ----------------------------------------------------------------------------------------------- cassette merge
def _cassette(path: Path, calls):
    lines = [json.dumps({"type": "meta", "example": "01", "run": 1})]
    lines += [json.dumps(dict({"type": "call"}, **c)) for c in calls]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n")


def test_merge_cassettes_unions_and_refuses_collisions(tmp_path):
    base, res, out = tmp_path / "base", tmp_path / "res", tmp_path / "out"
    c1 = {"request_hash": "a" * 64, "occurrence": 0, "site": "s", "site_ordinal": 0, "response": {"t": 1}}
    c2 = {"request_hash": "b" * 64, "occurrence": 0, "site": "r", "site_ordinal": 0, "response": {"t": 2}}
    _cassette(base / "01-r1.jsonl", [c1])
    _cassette(res / "runs" / "01-r1" / "cassette.jsonl", [c1, c2])
    before = (base / "01-r1.jsonl").read_text()
    report = mc.merge(base, res, out)
    assert report == {"01-r1": 1}
    merged = [json.loads(x) for x in (out / "01-r1.jsonl").read_text().splitlines()]
    assert [m.get("request_hash") for m in merged[1:]] == ["a" * 64, "b" * 64]
    assert (base / "01-r1.jsonl").read_text() == before
    _cassette(res / "runs" / "01-r1" / "cassette.jsonl", [dict(c1, response={"t": 9})])
    shutil.rmtree(out)
    with pytest.raises(mc.MergeCollision):
        mc.merge(base, res, out)
    assert not out.exists()


# ----------------------------------------------------------------------------------------------- assembly metrics
@pytest.mark.skipif(not have_hcl2(), reason="python-hcl2 not installed (eval/.deps)")
def test_assembly_metrics_dropped_replaced_and_verbatim(tmp_path):
    from stackvend_eval.assembly_metrics import assembly_metrics
    main = ('variable "region" {\n  default = "x"\n}\n'
            'resource "google_storage_bucket" "a" {\n  name = "a"\n}\n'
            'resource "google_cloud_run_v2_service" "api" {\n  name = "api"\n}\n')
    iam = 'resource "google_project_iam_member" "m" {\n  role = "roles/viewer"\n}\n'
    draft = {"infra/workload/main.tf": main, "infra/workload/iam.tf": iam}
    tree = {"infra/workload/main.tf": 'variable "region" {}\n',
            "infra/workload/custom.tf": '# stackvend: from infra/workload/main.tf (iac_worker)\n'
                                        'resource "google_storage_bucket" "a" {\n  name = "a"\n}\n',
            "infra/workload/iam.tf": iam}
    record = {"replaced": {"variable.region": "variable.region",
                           "google_cloud_run_v2_service.api": "module.compute"},
              "replaced_reason": {"variable.region": "PLATFORM_ROOT_DECLARATION",
                                  "google_cloud_run_v2_service.api": "CLOUD_RUN_REPLACED_BY_MODULE"}}
    m = assembly_metrics(draft, tree, record)
    assert m["dropped_unreplaced"] == [] and m["blocks_not_verbatim"] == []
    assert m["replaced_by_reason"]["CLOUD_RUN_REPLACED_BY_MODULE"] == ["google_cloud_run_v2_service.api"]
    m2 = assembly_metrics(draft, {"infra/workload/iam.tf": iam}, None)
    assert "google_storage_bucket.a" in m2["dropped_unreplaced"]


@pytest.mark.skipif(not have_hcl2(), reason="python-hcl2 not installed (eval/.deps)")
def test_assembly_metrics_subtract_justified_repair_removals_and_split_non_preserved_kinds():
    """R3c-fix RT §10.1: since S1-B the tree is assembled from the repaired draft; a key an accepted repair removed
    with a recorded justification is a repair removal, not a drop, and outputs/locals (not preserved by acceptance)
    get their own column, so dropped_unreplaced is a V2c proxy again (must be 0)."""
    from stackvend_eval.assembly_metrics import assembly_metrics, key_kind
    main = ('resource "google_project_service" "run" {\n  service = "run.googleapis.com"\n}\n'
            'resource "google_storage_bucket" "a" {\n  name = "a"\n}\n'
            'resource "google_pubsub_topic" "t" {\n  name = "t"\n}\n'
            'locals {\n  services = ["run"]\n}\n'
            'output "url" {\n  value = "u"\n}\n')
    tree = {"infra/workload/main.tf": 'resource "google_storage_bucket" "a" {\n  name = "a"\n}\n'}
    reasons = {"google_project_service.run": "REMOVAL_CODE:POLICY.PLATFORM_OWNED_TYPE",
               "google_storage_bucket.a": "REMOVAL_CODE:POLICY.PUBLIC_MEMBER"}   # still in the tree: not listed
    m = assembly_metrics({"infra/workload/main.tf": main}, tree, {"replaced": {}}, removal_reasons=reasons)
    assert m["dropped_unreplaced"] == ["google_pubsub_topic.t"]
    assert m["repair_removals_justified"] == {"google_project_service.run": "REMOVAL_CODE:POLICY.PLATFORM_OWNED_TYPE"}
    assert m["dropped_non_preserved"] == ["local.services", "output.url"]
    legacy = assembly_metrics({"infra/workload/main.tf": main}, tree, {"replaced": {}})
    assert legacy["dropped_unreplaced"] == ["google_project_service.run", "google_pubsub_topic.t"]
    assert [key_kind(k) for k in ("data.a.b", "module.m", "a.b", "variable.v", "moved:x", "terraform")] == [
        "data", "module", "resource", "variable", "moved", "terraform"]


def test_scoring_unions_the_accepted_events_removal_reasons_and_the_scoreboard_lists_them(monkeypatch):
    import stackvend_eval.scoring as scoring
    from stackvend_eval import metrics
    seen = {}

    def fake(draft, tree, record, product_root=None, removal_reasons=None):
        seen["reasons"] = removal_reasons
        return {"dropped_unreplaced": [], "repair_removals_justified": dict(removal_reasons),
                "dropped_non_preserved": ["output.x"]}
    result = {"checkpoints": {"C0_raw_swarm": {"tree": "t0"}, "C2_generated": {"tree": "t2"}},
              "hallucination_stack": {"repair_events": [
                  {"accepted": True, "removal_reasons": {"a.b": "REPLACED:module.c"}},
                  {"accepted": False, "removal_reasons": {"x.y": "REMOVAL_CODE:POLICY.PUBLIC_MEMBER"}},
                  {"accepted": True, "removal_reasons": {"d.e": "DEAD_REFERENCE:a.b"}}]}}
    blobs = type("B", (), {"get_tree": lambda self, h: {}})()
    import stackvend_eval.assembly_metrics as am
    monkeypatch.setattr(am, "assembly_metrics", fake)
    m = scoring._assembly(result, blobs, None)
    assert seen["reasons"] == {"a.b": "REPLACED:module.c", "d.e": "DEAD_REFERENCE:a.b"}
    assert m["repair_removals_justified"] == seen["reasons"]
    from stackvend_eval import scoreboard
    rec = {"key": "01-r1", "run_dir": "/nonexistent", "score": {"assembly": m},
           "result": {"example": "01", "run": 1, "valid_run": True, "pipeline_outcome": "committed_passed",
                      "llm": {"calls": 0, "per_call": []}}}
    row = metrics.run_row(rec)
    assert row["assembly_repair_removals_justified"] == seen["reasons"]
    assert row["assembly_dropped_non_preserved"] == ["output.x"]
    summary = metrics.aggregate([rec])
    o = summary["overall"]
    assert (o["assembly_dropped_unreplaced"], o["assembly_repair_removals_justified"],
            o["assembly_dropped_non_preserved"]) == (0, 2, 1)
    md = scoreboard.render(dict(summary, manifest={}))
    assert "repair removals (justified) 2" in md and "non-preserved kinds absent 1" in md


def test_examples_sha_reads_the_recorded_spec_text():
    import run_examples
    from stackvend_eval import gitutil
    if not gitutil.has_commit(ROOT, "44a2747"):  # OSS blocker 1a: private-history commit, absent on a fresh history
        pytest.skip(f"--examples-sha commit 44a2747 {gitutil.NOT_IN_CLONE}")
    ex = next(e for e in json.loads((ROOT / "eval/config/examples.json").read_text())["examples"] if e["id"] == "08")
    old = run_examples.spec_text(ex, "full", "44a2747")
    assert old and old != (ROOT / "documentation/examples" / ex["file"]).read_text()
