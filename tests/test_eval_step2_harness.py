"""S2-0 harness (Step 2 plan §2.1): per-branch self_correct_hcl probe, --dump-trees export, S2-0 aggregate columns.
Offline: in-process fakes only; no child process, no network, no credentials, no product import."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib
import json
import sys
import textwrap
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

from stackvend_eval import metrics, scoreboard  # noqa: E402
from stackvend_eval.blobs import BlobStore  # noqa: E402
from stackvend_eval.branch_probe import BranchProbe, segments_for  # noqa: E402
from stackvend_eval.tree_dump import TreeDump  # noqa: E402

FAKE_SRC = '''
def _self_correct_workload_hcl(files, errors, product_id="workload"):
    healed_files = dict(files)
    for err in errors:
        # 0. Handle HCL syntax errors
        if "syntax" in err:
            healed_files["a.tf"] = healed_files.get("a.tf", "") + "}"
        # 1. Handle undeclared variable
        if "var" in err:
            x = 1
    # Deduplicate outputs across root .tf files
    if "dedupe" in errors:
        healed_files.pop("b.tf", None)
    return healed_files
'''


@pytest.fixture()
def fake_mod(tmp_path, monkeypatch):
    p = tmp_path / "fake_scf_mod.py"
    p.write_text(textwrap.dedent(FAKE_SRC))
    monkeypatch.syspath_prepend(str(tmp_path))
    sys.modules.pop("fake_scf_mod", None)
    mod = importlib.import_module("fake_scf_mod")
    cfg = {"function": "_self_correct_workload_hcl", "module": "fake_scf_mod", "state_local": "healed_files",
           "branches": [{"marker": "# 0. Handle HCL syntax errors", "id": "HC-14", "owner": "S2-B", "kind": "error"},
                        {"marker": "# 1. Handle undeclared variable", "id": "HC-06", "owner": "S2-B", "kind": "error"},
                        {"marker": "# Deduplicate outputs", "id": "HC-08", "owner": "S2-B", "kind": "tail"},
                        {"marker": "# 99. not in the source", "id": "HC-XX", "owner": "-", "kind": "error"}]}
    cp = tmp_path / "branches.json"
    cp.write_text(json.dumps(cfg))
    yield mod, cp
    sys.modules.pop("fake_scf_mod", None)


def _rows(rep):
    return {r["id"]: r for r in rep["branches"]}


def test_branch_probe_attributes_each_change_to_its_branch(fake_mod):
    mod, cp = fake_mod
    probe = BranchProbe(cp)
    assert probe.install()
    try:
        out = mod._self_correct_workload_hcl({"a.tf": "x", "b.tf": "y"}, ["syntax", "var", "dedupe"])
    finally:
        probe.stop()
    assert out == {"a.tf": "x}"}
    rows = _rows(probe.report())
    assert rows["HC-14"]["calls_fired"] == 1 and rows["HC-14"]["fires"] == 1
    assert rows["HC-06"]["calls_reached"] == 1 and rows["HC-06"]["calls_fired"] == 0
    assert rows["HC-08"]["calls_fired"] == 1
    assert rows["HC-XX"]["status"] == "absent"


def test_branch_probe_no_change_means_no_fire_and_result_unchanged(fake_mod):
    """Do-No-Harm style negative: the probe observes only; a call that changes nothing reports 0 fires."""
    mod, cp = fake_mod
    probe = BranchProbe(cp)
    assert probe.install()
    try:
        files = {"a.tf": "x"}
        out = mod._self_correct_workload_hcl(files, ["var"])
    finally:
        probe.stop()
    assert out == files
    rep = probe.report()
    assert rep["calls"] == 1
    assert all(r["calls_fired"] == 0 for r in rep["branches"])


def test_segments_cover_the_function_without_overlap(fake_mod):
    mod, cp = fake_mod
    cfg = json.loads(cp.read_text())
    segs, status = segments_for(mod._self_correct_workload_hcl, cfg["branches"])
    spans = sorted((s, e) for s, e, _ in segs)
    assert all(a[1] < b[0] for a, b in zip(spans, spans[1:]))
    assert status[3] == "absent"


def test_product_branch_markers_are_all_anchored():
    """Every branch row of eval/config/self_correct_branches.json names a marker present in the product source
    (except rows a later sub-step deletes: absent is reported, never guessed)."""
    cfg = json.loads((ROOT / "eval/config/self_correct_branches.json").read_text())
    src = (ROOT / "apps/orchestrator-gateway/developer_agent/preflight_validator.py").read_text().splitlines()
    stripped = [ln.strip() for ln in src]
    live = [b for b in cfg["branches"] if not b.get("deleted_by")]
    gone = [b for b in cfg["branches"] if b.get("deleted_by")]
    found = [b["id"] for b in live if any(s.startswith(b["marker"]) for s in stripped)]
    assert len(found) == len(live), "a marker is missing: mark the row deleted_by with the deleting commit"
    # S2-B: a row marked deleted_by is a tombstone -- its marker must be gone from the product
    assert not [b["marker"] for b in gone if any(s.startswith(b["marker"]) for s in stripped)]


def test_tree_dump_records_without_changing_results(tmp_path):
    calls = []

    class DeveloperAgent:
        def _assemble_tree(self, draft, inputs):
            calls.append(draft)
            tree = dict(draft, **{"infra/workload/main.tf": "module x {}"})
            return tree, {"assembled_root": {"infra/workload/main.tf": "module x {}"},
                          "platform_files": {"infra/modules/m/main.tf": "v"}, "archetype": "cloudrun",
                          "assembly_record": None}

    def self_correct_hcl(files, errors, product_id="workload", platform_files=None):
        out = dict(files)
        out["c.tf"] = "z"
        return out

    dev = types.SimpleNamespace(DeveloperAgent=DeveloperAgent)
    pv = types.ModuleType("pv_fake")
    pv.self_correct_hcl = self_correct_hcl
    holder = types.ModuleType("holder_fake")
    holder.self_correct_hcl = self_correct_hcl

    def rebind(old, new):
        n = 0
        for m in (pv, holder):
            if getattr(m, "self_correct_hcl", None) is old:
                m.self_correct_hcl = new
                n += 1
        return n

    blobs = BlobStore(tmp_path)
    td = TreeDump(blobs)
    info = td.install({"developer_agent.handler": dev, "developer_agent.preflight_validator": pv}, rebind)
    assert info == {"assemble": True, "self_correct_bindings": 2}
    draft = {"apps/a/main.py": "print(1)\n"}
    tree, meta = DeveloperAgent()._assemble_tree(draft, None)
    assert calls == [draft] and tree["apps/a/main.py"] == "print(1)\n"
    assert holder.self_correct_hcl({"a.tf": "x"}, ["e1"], "p") == {"a.tf": "x", "c.tf": "z"}
    rep = td.report()
    a = rep["assemble"][0]
    assert blobs.get_tree(a["draft"]) == draft
    assert blobs.get_tree(a["assembled"]) == tree
    assert a["platform_files"] == ["infra/modules/m/main.tf"]
    s = rep["self_correct"][0]
    assert s["errors"] == ["e1"] and blobs.get_tree(s["files"]) == {"a.tf": "x"}
    assert blobs.get_tree(s["result"]) == {"a.tf": "x", "c.tf": "z"}


def test_tree_dump_forwards_extra_self_correct_keywords(tmp_path):
    """main 10-13 (lane 11) calls self_correct_hcl(..., primary_workload=...): the wrapper forwards every keyword
    unchanged (a missing parameter used to turn every run into a harness TypeError)."""
    seen = []

    def self_correct_hcl(files, errors, product_id="workload", platform_files=None, primary_workload=None):
        seen.append((platform_files, primary_workload))
        return dict(files, pw=str(primary_workload))

    pv = types.ModuleType("pv_fake2")
    pv.self_correct_hcl = self_correct_hcl

    def rebind(old, new):
        pv.self_correct_hcl = new
        return 1

    td = TreeDump(BlobStore(tmp_path))
    td.install({"developer_agent.preflight_validator": pv}, rebind)
    out = pv.self_correct_hcl({"a.tf": "x"}, [], "p", platform_files={"m": "v"}, primary_workload="svc")
    assert out == {"a.tf": "x", "pw": "svc"} and seen == [({"m": "v"}, "svc")]
    assert td.report()["self_correct"][0]["kwargs"] == {"primary_workload": "'svc'"}


def _rec(key, *, branches=None, per_call=None, invalid=None, outcome="developer_failed_typed"):
    return {"key": key, "score": None, "result": {
        "example": key[:2], "run": 1, "valid_run": not invalid, "invalid_reasons": invalid or [],
        "pipeline_outcome": outcome, "llm": {"per_call": per_call or [], "calls": len(per_call or [])},
        "self_correct_branches": {"calls": 1, "branches": branches or []}}}


def test_aggregate_s20_columns_separate_harness_budget_stops():
    br = [{"index": 0, "id": "HC-14", "marker": "# 0. Handle", "calls_fired": 1},
          {"index": -1, "id": "-", "marker": "(prologue)", "calls_fired": 0}]
    recs = [_rec("01-r1", branches=br, per_call=[{"site": "x.DeveloperAgent.generate_code_files"}, {"site": "y"}]),
            _rec("01-r2", invalid=["not_run_budget"], outcome=None),
            _rec("01-r3", invalid=["budget_exceeded"], outcome="invalid")]
    agg = metrics.aggregate(recs)
    o = agg["overall"]
    assert o["single_turn_calls"] == 1
    assert o["self_correct_branch_fire_runs"] == {"HC-14|# 0. Handle": 1}
    assert o["harness_budget_stop_runs"] == ["01-r2", "01-r3"]
    assert o["product_outcomes"] == {"developer_failed_typed": 1, "invalid": 0}
    md = scoreboard.render({"overall": o, "by_example": agg["by_example"], "runs": agg["runs"], "healers": [],
                            "coverage": {}, "manifest": {}})
    assert "harness budget stops (not product outcomes) ['01-r2', '01-r3']" in md


# ---- code RT F7: paired-comparison exclusions are data, not prose ------------------------------------------------
def test_paired_exclusions_are_in_the_summary_and_drop_changed_runs_from_paired_deltas():
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "eval"))
    import compare
    fb = {"site": "x.SwarmDispatcher._call_gemini_with_backoff", "served": "replay_fallback"}
    lead = {"site": "x.LeadDeveloperOrchestrator.decompose_specification", "served": "replay_fallback"}
    exact = {"site": "y", "served": "replay"}
    base = metrics.aggregate([_rec("01-r1", per_call=[exact]), _rec("06-r1", per_call=[lead, exact]),
                              _rec("08-r1", per_call=[exact, exact])])
    cand = metrics.aggregate([_rec("01-r1", per_call=[exact]), _rec("06-r1", per_call=[lead, exact]),
                              _rec("08-r1", per_call=[exact, fb])])
    assert [e["run"] for e in cand["paired_exclusions"]] == ["06-r1", "08-r1"]
    assert cand["paired_exclusions"][1] == {"run": "08-r1", "reason": "replay_not_exact",
                                            "sites": {metrics._site_label(fb["site"]): 1}}
    # identical not-exact sites on both sides (06-r1: the same recorded answer) stay paired; changed ones do not
    assert metrics.excluded_from_pairing(base["paired_exclusions"], cand["paired_exclusions"]).keys() == {"08-r1"}
    for s in (base, cand):
        for r in s["runs"]:
            r["c3_validate_ok"] = False
    out = compare.compare(base, cand)
    assert set(out["paired_excluded"]) == {"08-r1"} and out["paired"]["pairs"] == 2
    md = scoreboard.render({"overall": cand["overall"], "by_example": cand["by_example"], "runs": cand["runs"],
                            "healers": [], "coverage": {}, "manifest": {},
                            "paired_exclusions": cand["paired_exclusions"]})
    assert "**paired exclusions**" in md and "08-r1" in md.split("**paired exclusions**")[1].split("\n")[0]


def test_junior_reasks_are_counted_apart_from_repair_events():
    r = _rec("01-r1")
    r["result"]["hallucination_stack"] = {"repair_events": [{"kind": "junior_reask"}, {"kind": "repair"}, {}]}
    row = metrics.run_row(r)
    assert row["repair_events"] == 2 and row["junior_reasks"] == 1
