"""TI-0 (typed-IaC intent plan §4): harness-only measurements, the --architect-consensus arm, and the synthetic specs
S1-S7 for the 48-run gate. Offline and hermetic: no child process is launched (fake Popen), no network, no
credentials; product code is never imported (the observers are exercised on stand-in classes).

The golden test at the bottom re-derives the plan §1.2 / RT §2 counts from the 10-13 and 10-14 replay results when
their directories are given (STACKVEND_TI0_GOLDEN_1013 / _1014); cassettes and results are never committed (Q7), so
it is skipped otherwise. The PO-1 column is unverifiable (its cassettes were lost on 10-15) and is not tested."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import asyncio
import json
import os
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

import run_child  # noqa: E402
import run_examples  # noqa: E402
from stackvend_eval import metrics, report, scoring  # noqa: E402
from stackvend_eval.blobs import BlobStore  # noqa: E402

CATALOG = json.loads((ROOT / "eval/config/examples.json").read_text())["examples"]
S_IDS = [f"S{i}" for i in range(1, 8)]


def _ex(eid):
    return next(e for e in CATALOG if e["id"] == eid)


def _parse(*argv, llm="synthetic"):
    return run_examples.build_parser().parse_args(["--llm", llm, "--model", "gemini-3.8-flash", *argv])


class _FakeChild:
    calls = []

    def __init__(self, cmd, **kwargs):
        _FakeChild.calls.append({"cmd": cmd, "env": kwargs.get("env")})
        self.stdin = self
        self.returncode = -9

    def write(self, s):
        pass

    def close(self):
        pass

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        pass


@pytest.fixture
def no_child(monkeypatch):
    _FakeChild.calls.clear()
    real = run_examples.subprocess.Popen

    def popen(cmd, **kwargs):
        if isinstance(cmd, (list, tuple)) and any(str(c).endswith("run_child.py") for c in cmd):
            return _FakeChild(cmd, **kwargs)
        return real(cmd, **kwargs)
    monkeypatch.setattr(run_examples.subprocess, "Popen", popen)
    return _FakeChild.calls


# ------------------------------------------------------------------------------------------ catalog / selection
def test_default_selection_is_still_exactly_the_nine_examples():
    inv = run_examples.Invocation(_parse())
    assert [e["id"] for e in inv.examples] == [f"{i:02d}" for i in range(1, 10)]


def test_s_range_selects_the_seven_synthetic_specs_and_mixes_with_examples():
    assert [e["id"] for e in run_examples.parse_examples("S1-S7", CATALOG)] == S_IDS
    assert [e["id"] for e in run_examples.parse_examples("01-09", CATALOG)] == [f"{i:02d}" for i in range(1, 10)]
    assert [e["id"] for e in run_examples.parse_examples("3,s2", CATALOG)] == ["03", "S2"]
    with pytest.raises(SystemExit):
        run_examples.parse_examples("01-S7", CATALOG)
    with pytest.raises(SystemExit):
        run_examples.parse_examples("S9", CATALOG)   # S8 exists since TI-5-R2 (AlloyDB / Vertex endpoint / Bigtable)
    assert [e["id"] for e in run_examples.parse_examples("S8", CATALOG)] == ["S8"]   # never in S1-S7


@pytest.mark.parametrize("eid", S_IDS + ["S8"])   # S8: TI-5-R2
def test_synthetic_spec_entries_are_complete(eid):
    e = _ex(eid)
    path = run_examples.catalog_spec_path(e)
    assert path.is_file() and path.parent == ROOT / "eval/specs/synthetic"
    assert run_examples.PRODUCT_ID_RE.fullmatch(e["product_id"])
    text = run_examples.spec_text(e, "full")
    assert f"`{e['product_id']}`" in text
    assert run_examples.spec_text(e, "form-prompt").strip()        # the form-prompt section exists
    exp = e["expected_outcome"]
    assert exp["accept"] and set(exp["accept"]) <= {"committed_passed", "ARCHITECT_DEFECT", "BROWNFIELD_CONFLICT",
                                                    "CODE_DEFECT"}
    assert "I6_cycles" in exp["zero"]


def test_expected_outcomes_match_the_gate_text():
    """integration §6.2 / lane 10 §11: S2 ring -> acyclic or ARCHITECT_DEFECT; S7 -> no-op or BROWNFIELD_CONFLICT."""
    assert set(_ex("S2")["expected_outcome"]["accept"]) == {"committed_passed", "ARCHITECT_DEFECT"}
    s7 = _ex("S7")
    assert set(s7["expected_outcome"]["accept"]) == {"committed_passed", "BROWNFIELD_CONFLICT"}
    assert s7["expected_outcome"]["no_compute_dropped"] is True
    assert s7["brownfield_of"] == "S1" and s7["product_id"] == _ex("S1")["product_id"] and s7["file"] == _ex("S1")["file"]
    product_ids = [e["product_id"] for e in CATALOG if e["id"] != "S7"]
    assert len(product_ids) == len(set(product_ids))


def test_brownfield_rerun_needs_its_base_in_the_same_invocation():
    with pytest.raises(SystemExit, match="brownfield rerun of S1"):
        run_examples.Invocation(_parse("--examples", "S7")).preflight()
    run_examples.Invocation(_parse("--examples", "S1,S7")).preflight()


def test_job_phases_run_brownfield_reruns_last():
    jobs = [(_ex("S7"), 1), (_ex("S1"), 1), (_ex("01"), 1)]
    phases = run_examples.job_phases(jobs)
    assert [[j[0]["id"] for j in p] for p in phases] == [["S1", "01"], ["S7"]]
    assert run_examples.job_phases([(_ex("01"), 1)]) == [[(_ex("01"), 1)]]


# ------------------------------------------------------------------------------------- --architect-consensus
# child_env() of the 11a18a6 harness (the pre-TI-0 base), captured from an export of that commit with the real
# eval/config/prod_env.json, model "MODEL", tmp dir "<TMP>" and STACKVEND_EVAL_GITHUB_ORG=eval-test-org (RT F9: pinned,
# not compared with itself; the org override keeps the owner identifier out of the test, FD-12).
ENV_11A18A6 = {
    "ADMIN_USER_EMAIL": "eval@example.invalid", "CLOUDSDK_CONFIG": "<TMP>/cloudsdk",
    "COMPLIANCE_SERVER_URL": "http://127.0.0.1:1", "GEMINI_LOCATION": "global", "GEMINI_MODEL": "MODEL",
    "GITHUB_ORG": "eval-test-org", "GOOGLE_APPLICATION_CREDENTIALS": "/nonexistent/adc-disabled.json",
    "HOME": "<TMP>/home", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "NO_GCE_CHECK": "True",
    "PATH": "<TMP>/shims:/usr/bin:/bin", "PROJECT_ID": "", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0",
    "TMPDIR": "<TMP>/tmp", "TZ": "UTC"}


def test_child_env_on_is_byte_identical_to_the_11a18a6_env(tmp_path, monkeypatch):
    monkeypatch.setenv("STACKVEND_EVAL_GITHUB_ORG", "eval-test-org")   # the override both harnesses honour
    prod = json.loads((ROOT / "eval/config/prod_env.json").read_text())["env"]
    t = tmp_path / "a"

    def norm(env):
        return {k: v.replace(str(t), "<TMP>") for k, v in env.items()}
    assert norm(run_examples.child_env(t, "MODEL", prod)) == ENV_11A18A6
    assert norm(run_examples.child_env(t, "MODEL", prod, "on")) == ENV_11A18A6
    assert norm(run_examples.child_env(t, "MODEL", prod, "off")) == {**ENV_11A18A6, run_examples.CONSENSUS_ENV: "false"}


def test_child_env_github_org_default_is_neutral_and_not_a_github_name(tmp_path, monkeypatch):
    """D-10 (owner 10-26): without STACKVEND_EVAL_GITHUB_ORG the child's GITHUB_ORG is the neutral default, which no
    one can register on GitHub (outside the [A-Za-z0-9-] account-name alphabet); the override still wins."""
    import re
    monkeypatch.delenv("STACKVEND_EVAL_GITHUB_ORG", raising=False)
    prod = json.loads((ROOT / "eval/config/prod_env.json").read_text())["env"]
    org = run_examples.child_env(tmp_path / "a", "MODEL", prod)["GITHUB_ORG"]
    assert org == run_examples.EVAL_GITHUB_ORG_DEFAULT == "stackvend_eval-org"
    assert not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", org)
    monkeypatch.setenv("STACKVEND_EVAL_GITHUB_ORG", "eval-test-org")
    assert run_examples.child_env(tmp_path / "b", "MODEL", prod)["GITHUB_ORG"] == "eval-test-org"


def test_consensus_arm_is_in_the_manifest_the_child_config_and_the_cassette_meta(tmp_path, no_child):
    inv = run_examples.Invocation(_parse("--examples", "01", "--runs", "1", "--out", str(tmp_path / "res"),
                                         "--cassettes", str(tmp_path / "cas"), "--architect-consensus", "off"))
    assert inv.id.endswith("-consensus-off")
    rec = inv.run_one(inv.examples[0], 1, [])
    cfg = json.loads((Path(rec["run_dir"]) / "child_config.json").read_text())
    assert cfg["architect_consensus"] == "off" and cfg["cassette_meta_extra"]["architect_consensus"] == "off"
    assert no_child[-1]["env"][run_examples.CONSENSUS_ENV] == "false"
    assert inv.manifest([rec])["architect_consensus"] == "off"
    default = run_examples.Invocation(_parse("--examples", "01", "--out", str(tmp_path / "res2")))
    assert default.manifest([])["architect_consensus"] == "on"


def _replay(tmp_path, meta, *extra, example="01"):
    cas = tmp_path / "cas"
    cas.mkdir(exist_ok=True)
    text = run_examples.spec_text(_ex(example), "full")
    meta = {"spec_text": text, "spec_sha256": run_examples.sha256_text(text), "spec_mode": "full", **meta}
    (cas / f"{example}-r1.jsonl").write_text(json.dumps({"type": "meta", "example": example, "run": 1, **meta}) + "\n")
    argv = ["--examples", example, "--runs", "1", "--cassettes", str(cas), "--out", str(tmp_path / "res"), *extra]
    return run_examples.Invocation(_parse(*argv, llm="replay-strict"))


def test_replay_refuses_the_other_consensus_arm_before_launch(tmp_path, no_child):
    """A recording made before TI-0 carries no arm: it ran the product default (on)."""
    inv = _replay(tmp_path, {}, "--architect-consensus", "off")
    rec = inv.run_one(inv.examples[0], 1, [])
    assert rec["result"]["invalid_reasons"] == ["replay_consensus_mismatch"] and no_child == []
    assert rec["result"]["architect_consensus"] == {"requested": "off", "recorded": "on"}
    inv = _replay(tmp_path, {"architect_consensus": "off"})          # recorded off, replayed with the default on
    assert inv.run_one(inv.examples[0], 1, [])["result"]["invalid_reasons"] == ["replay_consensus_mismatch"]


def test_replay_of_the_same_arm_launches(tmp_path, no_child):
    inv = _replay(tmp_path, {})
    inv.run_one(inv.examples[0], 1, [])
    assert len(no_child) == 1 and run_examples.CONSENSUS_ENV not in no_child[0]["env"]
    inv = _replay(tmp_path, {"architect_consensus": "off"}, "--architect-consensus", "off", example="02")
    inv.run_one(inv.examples[0], 1, [])
    assert no_child[-1]["env"][run_examples.CONSENSUS_ENV] == "false"


# ------------------------------------------------------------------------------------------------ S7 brownfield
def _commit_base(out_dir, key="S1-r1", tree=None, valid=True):
    rd = out_dir / "runs" / key
    rd.mkdir(parents=True)
    th = BlobStore(rd).put_tree(tree or {"infra/workload/custom.tf": 'resource "a" "b" {}\n', "app/main.py": "x = 1\n"})
    (rd / "result.json").write_text(json.dumps({
        "valid_run": valid, "checkpoints": {"C3_committed": {"tree": th, "files": 2}},
        "provenance_after_commit": {"infra/workload/custom.tf": {"persona": "IAC_ENGINEER", "trace_id": "t",
                                                                 "sha256": "0" * 64}},
        "hallucination_stack": {"compute_intent": {"service_kinds": {"svc": "event-worker"}}}}))
    return th


def test_brownfield_rerun_without_a_committed_base_is_not_run(tmp_path, no_child):
    inv = run_examples.Invocation(_parse("--examples", "S1,S7", "--runs", "1", "--out", str(tmp_path / "res"),
                                         "--out-id", "bf"))
    rec = inv.run_one(_ex("S7"), 1, [])
    assert rec["result"]["invalid_reasons"] == ["brownfield_base_not_committed"] and no_child == []
    _commit_base(inv.out, valid=False)
    assert inv.run_one(_ex("S7"), 1, [])["result"]["invalid_reasons"] == ["brownfield_base_not_committed"]


def test_a_refused_live_run_leaves_nothing_outstanding_in_the_ledger(tmp_path, no_child):
    """RT F1: record mode admits an allocation before the TI-0 refusals; a refused S7 must close it at $0."""
    inv = run_examples.Invocation(_parse("--examples", "S1,S7", "--runs", "1", "--out", str(tmp_path / "res"),
                                         "--out-id", "bf", "--budget-usd", "15", "--run-cap", "3",
                                         "--cassettes", str(tmp_path / "cas"), llm="record"))
    assert inv.live
    rec = inv.run_one(_ex("S7"), 1, [])
    assert rec["result"]["invalid_reasons"] == ["brownfield_base_not_committed"] and no_child == []
    snap = inv.ledger.snapshot()
    assert snap["outstanding_usd"] == 0 and snap["settled_usd"] == 0
    # a second refused run is admitted again (the first one did not hold its $3)
    inv.run_one(_ex("S7"), 1, [])
    assert inv.ledger.snapshot()["outstanding_usd"] == 0


def test_a_launched_child_whose_close_was_skipped_is_charged_its_allocation(tmp_path, no_child, monkeypatch):
    inv = run_examples.Invocation(_parse("--examples", "01", "--runs", "1", "--out", str(tmp_path / "res"),
                                         "--out-id", "lk", "--budget-usd", "15", "--run-cap", "3",
                                         "--cassettes", str(tmp_path / "cas"), llm="record"))
    monkeypatch.setattr(run_examples, "mint_access_token", lambda *a, **k: "tok")
    monkeypatch.setattr(inv.ledger, "close", _close_then_boom(inv.ledger.close))
    with pytest.raises(RuntimeError):
        inv.run_one(_ex("01"), 1, [])
    snap = inv.ledger.snapshot()
    assert snap["outstanding_usd"] == 0 and snap["settled_usd"] == 3.0     # never under-reported


def _close_then_boom(real):
    state = {"n": 0}

    def close(key, reported):
        state["n"] += 1
        if state["n"] == 1:           # the normal post-child close fails before it settles
            raise RuntimeError("boom")
        return real(key, reported)
    return close


def test_brownfield_rerun_hands_the_base_tree_and_provenance_to_the_child(tmp_path, no_child):
    inv = run_examples.Invocation(_parse("--examples", "S1,S7", "--runs", "1", "--out", str(tmp_path / "res"),
                                         "--out-id", "bf", "--cassettes", str(tmp_path / "cas")))
    th = _commit_base(inv.out)
    rec = inv.run_one(_ex("S7"), 1, [])
    assert len(no_child) == 1
    cfg = json.loads((Path(rec["run_dir"]) / "child_config.json").read_text())
    existing = json.loads(Path(cfg["existing_repo_path"]).read_text())
    assert existing["tree_sha"] == th and existing["base"] == "S1-r1"
    assert existing["tree"]["app/main.py"] == "x = 1\n"
    assert existing["provenance"]["infra/workload/custom.tf"]["persona"] == "IAC_ENGINEER"
    assert existing["base_compute"] == ["svc"]
    assert cfg["cassette_meta_extra"]["existing_repo_tree"] == th
    assert cfg["product_id"] == _ex("S1")["product_id"]


def test_brownfield_replay_refuses_a_different_base_tree(tmp_path, no_child):
    cas = tmp_path / "cas"
    cas.mkdir()
    text = run_examples.spec_text(_ex("S7"), "full")
    (cas / "S7-r1.jsonl").write_text(json.dumps({"type": "meta", "spec_text": text, "spec_mode": "full",
                                                 "spec_sha256": run_examples.sha256_text(text),
                                                 "existing_repo_tree": "f" * 64}) + "\n")
    inv = run_examples.Invocation(_parse("--examples", "S1,S7", "--runs", "1", "--out", str(tmp_path / "res"),
                                         "--out-id", "bf", "--cassettes", str(cas), llm="replay-strict"))
    _commit_base(inv.out)
    rec = inv.run_one(_ex("S7"), 1, [])
    assert rec["result"]["invalid_reasons"] == ["replay_existing_repo_mismatch"] and no_child == []


# ------------------------------------------------------------------------------------------ run_child observers
class _Plan:
    def __init__(self, services, archetype="cloudrun"):
        self.service_topology = None
        self._raw_service_topology = {"services": services}
        self.compute_archetype = archetype
        self.target_compute_services = [s["name"] for s in services]
        self.bundle_id = None


def test_topology_sha_is_stable_and_sees_a_service_change():
    a = _Plan([{"name": "a", "kind": "cloudrun"}])
    assert run_child.topology_sha256(a) == run_child.topology_sha256(_Plan([{"name": "a", "kind": "cloudrun"}]))
    assert run_child.topology_sha256(a) != run_child.topology_sha256(_Plan([{"name": "b", "kind": "cloudrun"}]))
    assert run_child.topology_sha256(None) is None


def test_consensus_observer_records_pre_and_post_and_never_changes_the_answer():
    class Engine:
        def evaluate_and_reconcile(self, plan=None, **kw):
            return _Plan([{"name": "b", "kind": "cloudrun"}]), types.SimpleNamespace(consensus_status="AUTO_REMEDIATED")
    mod = types.SimpleNamespace(DualArchitectConsensusEngine=Engine)
    sink = []
    assert run_child.install_consensus_observer(mod, sink) == {"installed": True}
    pre = _Plan([{"name": "a", "kind": "cloudrun"}])
    out = Engine().evaluate_and_reconcile(plan=pre, spec_text="s")
    assert out[0].target_compute_services == ["b"]
    assert sink[0]["changed"] is True and sink[0]["consensus_status"] == "AUTO_REMEDIATED"
    assert sink[0]["pre_topology_sha256"] == run_child.topology_sha256(pre) and sink[0]["compared"] == "fields"

    class Boom:
        def evaluate_and_reconcile(self, plan=None, **kw):
            raise ValueError("x")
    sink2 = []
    run_child.install_consensus_observer(types.SimpleNamespace(DualArchitectConsensusEngine=Boom), sink2)
    with pytest.raises(ValueError):
        Boom().evaluate_and_reconcile(plan=pre)
    assert sink2 == [{"pre_topology_sha256": run_child.topology_sha256(pre), "pre": run_child.topology_digest(pre),
                      "error": "ValueError"}]
    assert run_child.install_consensus_observer(types.SimpleNamespace(), [])["installed"] is False


def test_topology_change_compares_like_with_like():
    """RT F7: a draft that parses vs a remediated plan that does not (or the reverse) is compared on the raw form."""
    a = _Plan([{"name": "a", "kind": "cloudrun"}])
    b = _Plan([{"name": "a", "kind": "cloudrun"}])
    b.service_topology = types.SimpleNamespace(model_dump=lambda mode=None: {"parsed": True})
    assert run_child.topology_changed(run_child.topology_digest(a), run_child.topology_digest(b)) == (False, "raw")
    c = _Plan([{"name": "a", "kind": "cloudrun", "purpose": "x"}])
    assert run_child.topology_changed(run_child.topology_digest(a), run_child.topology_digest(c)) == (True, "raw")
    d, e = _Plan([{"name": "a", "kind": "cloudrun"}]), _Plan([{"name": "a", "kind": "cloudrun"}])
    d._raw_service_topology = e._raw_service_topology = None
    e.service_topology = types.SimpleNamespace(model_dump=lambda mode=None: {"parsed": True})
    assert run_child.topology_changed(run_child.topology_digest(d), run_child.topology_digest(e)) == (None, None)
    f, g = _Plan([{"name": "a", "kind": "cloudrun"}]), _Plan([{"name": "a", "kind": "cloudrun"}])
    f._raw_service_topology = g._raw_service_topology = None          # a product before lane 10: no topology at all
    assert run_child.topology_changed(run_child.topology_digest(f), run_child.topology_digest(g)) == (False, "fields")
    assert metrics.consensus_changed_topology(_result(architect_consensus={"invocations": [{"changed": None}]})) is None


def test_repair_call_observer_counts_by_persona_and_transport_attempts():
    class SD:
        def invoke_repair(self, persona, system_instruction, prompt, model_name, max_output_tokens, **kw):
            return {"files": {}, "envelope_ok": persona != "TEST_ENGINEER", "transport_attempts": 2 if persona ==
                    "IAC_ENGINEER" else 1}
    sink = {}
    run_child.install_repair_call_observer(types.SimpleNamespace(SwarmDispatcher=SD), sink)
    sd = SD()
    sd.invoke_repair("IAC_ENGINEER", "s", "p", "m", 10)
    sd.invoke_repair(persona="TEST_ENGINEER", system_instruction="s", prompt="p", model_name="m", max_output_tokens=1)
    sd.invoke_repair("IAC_ENGINEER", "s", "p", "m", 10)
    assert sink == {"IAC_ENGINEER": {"calls": 2, "llm_calls": 4, "envelope_ok": 2},
                    "TEST_ENGINEER": {"calls": 1, "llm_calls": 1, "envelope_ok": 0}}


def test_junior_draft_observer_keeps_each_personas_own_files():
    class SD:
        async def invoke_junior_worker(self, task, plan, deps, model_name, trace_id=None):
            return types.SimpleNamespace(persona=types.SimpleNamespace(value=task), files={f"{task}.tf": task})
    sink = {}
    run_child.install_junior_draft_observer(types.SimpleNamespace(SwarmDispatcher=SD), sink)
    asyncio.run(SD().invoke_junior_worker("IAC_ENGINEER", None, {}, "m"))
    asyncio.run(SD().invoke_junior_worker("BACKEND_ENGINEER", None, {}, "m"))
    assert sink == {"IAC_ENGINEER": {"IAC_ENGINEER.tf": "IAC_ENGINEER"},
                    "BACKEND_ENGINEER": {"BACKEND_ENGINEER.tf": "BACKEND_ENGINEER"}}


def test_hb04_append_observer_parses_the_appended_text_with_index_blocks():
    """RT F6: the address comes from the appended text via the product's own index_blocks, not from local names."""
    calls = []

    def append_text(files, path, text):
        calls.append(path)
        files[path] = files.get(path, "") + text

    def index_blocks(text):              # stand-in for developer_agent.assembly.index_blocks
        if text == "bad":
            return None
        if text.startswith("module"):
            return [types.SimpleNamespace(kind="module", labels=[text.split('"', 2)[1]])]
        return []
    mod = types.SimpleNamespace(append_text=append_text, index_blocks=index_blocks)
    sink = []
    assert run_child.install_hb04_append_observer(mod, sink) == {"installed": True}
    files = {}
    mod.append_text(files, "infra/workload/custom.tf", 'module "compute_worker" {}\n')
    mod.append_text(files, "infra/workload/custom.tf", "# a comment\n")
    mod.append_text(files, "infra/workload/custom.tf", "bad")
    assert sink == [{"path": "infra/workload/custom.tf", "address": "module.compute_worker"},
                    {"path": "infra/workload/custom.tf", "address": None, "unparsed": True}]
    assert calls == ["infra/workload/custom.tf"] * 3 and "compute_worker" in files["infra/workload/custom.tf"]
    assert run_child.install_hb04_append_observer(types.SimpleNamespace(append_text=append_text), [])[
        "installed"] is False


def test_architect_failure_observer_records_a_typed_gate_error():
    class TopologyInvalidError(RuntimeError):
        error_class = types.SimpleNamespace(value="ARCHITECT_DEFECT")
        reason = "TOPOLOGY_INVALID"
        diagnostics = [{"code": "TOPOLOGY.CYCLE"}]

    def arch():
        raise TopologyInvalidError("ring")
    pipe = types.SimpleNamespace(_architect=arch)
    result = {}
    run_child.install_architect_failure_observer(pipe, result)
    with pytest.raises(TopologyInvalidError):
        pipe._architect()
    assert result["architect_failed_typed"] == {"exception": "TopologyInvalidError", "error_class": "ARCHITECT_DEFECT",
                                                "reason": "TOPOLOGY_INVALID", "codes": ["TOPOLOGY.CYCLE"]}


def test_existing_repo_install_replaces_the_greenfield_read():
    class DA:
        def fetch_existing_repo_files(self, product_id):
            return {}
    mods = {"developer_agent.handler": types.SimpleNamespace(DeveloperAgent=DA)}
    info = run_child.install_existing_repo(mods, {"tree": {"a.tf": "x"}, "tree_sha": "t", "base": "S1-r1"})
    assert DA().fetch_existing_repo_files("p") == {"a.tf": "x"} and info == {"files": 1, "tree_sha": "t",
                                                                            "base": "S1-r1"}


# ------------------------------------------------------------------------------------------------ metrics
def _ev(it, persona, codes, kind="repair"):
    return {"iteration": it, "persona": persona, "codes": codes, "kind": kind}


def _result(**kw):
    r = {"example": "01", "run": 1, "valid_run": True, "pipeline_outcome": "developer_failed_typed",
         "hallucination_stack": {"repair_events": kw.pop("events", [])}}
    r.update(kw)
    return r


def test_first_draft_codes_are_iteration_one_by_author():
    r = _result(events=[_ev(1, "IAC_ENGINEER", ["POLICY.PLATFORM_OWNED_TYPE"]),
                        _ev(1, "BACKEND_ENGINEER", ["PY.SYNTAX", "PY.UNDEFINED_NAME"]),
                        _ev(1, "developer", ["TF.CYCLE"]),
                        _ev(2, "IAC_ENGINEER", ["TF.UNSUPPORTED_ATTRIBUTE"]),
                        _ev(1, "BACKEND_ENGINEER", ["X.REASK"], kind="junior_reask")])
    assert metrics.first_draft_codes(r) == {"iac": ["POLICY.PLATFORM_OWNED_TYPE"],
                                            "app": ["PY.SYNTAX", "PY.UNDEFINED_NAME"], "mixed": ["TF.CYCLE"]}


def test_repair_calls_prefer_the_observer_and_fall_back_to_events():
    r = _result(events=[_ev(1, "IAC_ENGINEER", []), _ev(2, "IAC_ENGINEER", [])],
                repair_calls={"by_persona": {"IAC_ENGINEER": {"calls": 3, "llm_calls": 3}}})
    assert metrics.repair_calls_by_persona(r) == ({"IAC_ENGINEER": 3}, "observer")
    r.pop("repair_calls")
    assert metrics.repair_calls_by_persona(r) == ({"IAC_ENGINEER": 2}, "repair_events")


def test_platform_blocks_come_from_the_assembly_record_and_the_hb04_appends():
    r = _result(hb04_appends={"appends": [{"path": "infra/workload/custom.tf", "address": "module.compute_w"}] * 2})
    r["hallucination_stack"]["assembly_record"] = {
        "replaced_reason": {"module.compute_a": "PLATFORM_RESYNTHESIZED", "variable.region": "PLATFORM_ROOT_DECLARATION"},
        "replaced_from": {"module.compute_a": "infra/workload/main.tf"}}
    assert metrics.platform_blocks_in_ai_files(r) == ["infra/workload/custom.tf:module.compute_w",
                                                      "infra/workload/main.tf:module.compute_a"]
    assert metrics.platform_blocks_in_ai_files(_result()) is None          # no record: unknown, never 0
    r.pop("hb04_appends")
    assert metrics.platform_blocks_in_ai_files(r) is None                  # recorded before the observer


def test_consensus_changed_topology_is_none_when_consensus_did_not_run():
    assert metrics.consensus_changed_topology(_result()) is None
    assert metrics.consensus_changed_topology(_result(architect_consensus={"invocations": []})) is None
    r = _result(architect_consensus={"invocations": [{"changed": False}, {"changed": True}]})
    assert metrics.consensus_changed_topology(r) is True


def _row(**kw):
    base = {"valid": True, "outcome": "committed_passed", "developer_failed_typed": None,
            "architect_failed_typed": None, "typed_failure_codes": None, "I6_cycles": 0, "I3_literals": 0,
            "invariant_violations": 0, "resource_types": ["google_storage_bucket"], "c3_public_members": [],
            "c3_owner_grants": [], "c3_policy_unparsed": [], "compute_dropped_on_rerun": []}
    base.update(kw)
    return base


def test_s6_accepts_every_policy_refusal_code_the_product_emits():
    """RT F3: the product refuses the S6 asks with these codes too; CIDR_NOT_ALLOCATED (PLATFORM_DEFECT) is not
    accepted (owner question Q-TI0-1)."""
    S6 = _ex("S6")["expected_outcome"]
    for code in ("POLICY.PUBLIC_PRINCIPAL_FORBIDDEN", "POLICY.PLATFORM_OWNED_BINDING", "POLICY.CIDR_FACT_MISMATCH",
                 "POLICY.CIDR_FACT_REUSED"):
        row = _row(outcome="developer_failed_typed", developer_failed_typed="CODE_DEFECT", typed_failure_codes=[code])
        assert metrics.synthetic_expectation(row, S6)["met"] is True, code
    pd = _row(outcome="developer_failed_typed", developer_failed_typed="PLATFORM_DEFECT",
              typed_failure_codes=["POLICY.CIDR_NOT_ALLOCATED"])
    assert metrics.synthetic_expectation(pd, S6)["met"] is False


def test_s6_committed_is_scored_independently_of_the_products_gate():
    """RT F4: committed_passed is met only when the committed tree holds none of what S6 asked for."""
    S6 = _ex("S6")["expected_outcome"]
    assert metrics.synthetic_expectation(_row(), S6)["met"] is True
    for bad in (dict(resource_types=["google_project_service"]),
                dict(resource_types=["google_artifact_registry_repository", "google_storage_bucket"]),
                dict(invariant_violations=1),                         # I4: a Dockerfile in the tree
                dict(c3_public_members=["google_storage_bucket_iam_member.public"]),
                dict(c3_owner_grants=["google_project_iam_member.owner"]),
                dict(c3_policy_unparsed=["infra/workload/custom.tf"]),
                dict(c3_policy_unparsed=None, c3_public_members=None, c3_owner_grants=None)):   # not scanned
        got = metrics.synthetic_expectation(_row(**bad), S6)
        assert got["met"] is False and got["why_not"], bad


def test_s7_no_op_check_fails_closed_when_the_compute_set_is_unknown():
    """RT F5: a committed rerun whose compute set was not recorded is not a no-op."""
    S7 = _ex("S7")["expected_outcome"]
    got = metrics.synthetic_expectation(_row(compute_dropped_on_rerun=None), S7)
    assert got["met"] is False and "compute set unknown" in got["why_not"][0]
    assert metrics.synthetic_expectation(_row(compute_dropped_on_rerun=[]), S7)["met"] is True
    r = _result(pipeline_outcome="committed_passed", brownfield={"base_compute": ["a"]})
    r["hallucination_stack"]["compute_intent"] = {"service_names": ["a"]}            # no typed topology
    assert metrics.compute_dropped_on_rerun(r) == []
    r["hallucination_stack"]["compute_intent"] = {}
    assert metrics.compute_dropped_on_rerun(r) is None
    r["brownfield"] = {"base_compute": None}
    r["hallucination_stack"]["compute_intent"] = {"service_names": ["a"]}
    assert metrics.compute_dropped_on_rerun(r) is None


def test_c3_policy_scan_reads_exact_values_and_skips_vendored_modules():
    _hcl2_or_skip()
    tree = {
        "infra/workload/custom.tf": (
            'resource "google_storage_bucket_iam_member" "pub" {\n  bucket = "b"\n  role = "roles/storage.objectViewer"\n'
            '  member = "allUsers"\n}\n'
            'resource "google_project_iam_member" "own" {\n  project = var.project_id\n  role = "roles/owner"\n'
            '  member = "serviceAccount:${google_service_account.sa.email}"\n}\n'
            'resource "google_storage_bucket_acl" "acl" {\n  bucket = "b"\n  role_entity = ["READER:allAuthenticatedUsers"]\n}\n'
            'resource "google_storage_bucket_iam_member" "ok" {\n  bucket = "b"\n  role = "roles/storage.admin"\n'
            '  member = "user:allUsers@example.com"\n}\n'
            'resource "google_pubsub_topic" "t" {\n  name = "allUsers"\n  labels = { role = "roles/owner" }\n}\n'),
        "infra/modules/compute-cloudrun/main.tf": (
            'resource "google_cloud_run_v2_service_iam_member" "inv" {\n  name = "x"\n  role = "roles/run.invoker"\n'
            '  member = "allUsers"\n}\n'),
        "infra/workload/bad.tf": "resource {",
    }
    got = scoring.c3_policy_scan(tree)
    assert got == {"public_members": ["google_storage_bucket_acl.acl", "google_storage_bucket_iam_member.pub"],
                   "owner_grants": ["google_project_iam_member.own"], "unparsed": ["infra/workload/bad.tf"]}


def test_synthetic_expectation_rules():
    S2, S6, S7 = (_ex(i)["expected_outcome"] for i in ("S2", "S6", "S7"))
    assert metrics.synthetic_expectation(_row(), S2)["met"] is True
    arch = _row(outcome="generation_error", architect_failed_typed="ARCHITECT_DEFECT")
    assert metrics.synthetic_expectation(arch, S2)["met"] is True
    assert metrics.synthetic_expectation(_row(I6_cycles=1), S2)["met"] is False          # a committed cycle
    assert metrics.synthetic_expectation(_row(valid=False), S2)["met"] is False
    pol = _row(outcome="developer_failed_typed", developer_failed_typed="CODE_DEFECT",
               typed_failure_codes=["POLICY.PUBLIC_MEMBER"])
    assert metrics.synthetic_expectation(pol, S6)["met"] is True
    py = dict(pol, typed_failure_codes=["POLICY.PUBLIC_MEMBER", "PY.SYNTAX"])
    got = metrics.synthetic_expectation(py, S6)
    assert got["met"] is False and "PY.SYNTAX" in got["why_not"][0]
    assert metrics.synthetic_expectation(_row(compute_dropped_on_rerun=["svc"]), S7)["met"] is False
    bf = _row(outcome="developer_failed_typed", developer_failed_typed="BROWNFIELD_CONFLICT")
    assert metrics.synthetic_expectation(bf, S7)["met"] is True
    assert metrics.synthetic_expectation(_row(), None) is None


def test_compute_dropped_on_rerun():
    r = _result(pipeline_outcome="committed_passed", brownfield={"base_compute": {"a": "cloudrun", "b": "cloudrun"}})
    r["hallucination_stack"]["compute_intent"] = {"service_kinds": {"a": "cloudrun"}}
    assert metrics.compute_dropped_on_rerun(r) == ["b"]
    assert metrics.compute_dropped_on_rerun(_result()) is None


def test_aggregate_counts_runs_not_diagnostics_and_report_renders():
    recs = []
    for i, codes in enumerate((["PY.SYNTAX"], ["PY.SYNTAX", "POLICY.CIDR_LITERAL"], [])):
        r = _result(run=i + 1, events=[_ev(1, "IAC_ENGINEER" if "POLICY.CIDR_LITERAL" in codes else "TEST_ENGINEER",
                                           codes)] if codes else [],
                    repair_calls={"by_persona": {"IAC_ENGINEER": {"calls": i}}})
        recs.append({"key": f"01-r{i + 1}", "result": r, "run_dir": "x",
                     "score": {"typed_iac": {"first_draft": {"types": ["google_pubsub_topic"], "data_sources": [],
                                                             "functions": ["jsonencode"] if i else [],
                                                             "source": "junior_drafts:IAC_ENGINEER"},
                                             "healer_fvv_split": {"iac": i, "app": 0, "mixed": 0, "unknown": 0}}}})
    s = metrics.aggregate(recs)
    o = s["overall"]
    assert o["first_draft_code_runs"] == {"POLICY.CIDR_LITERAL": 1, "PY.SYNTAX": 2}
    assert o["first_draft_code_runs_by_author"]["iac"] == {"POLICY.CIDR_LITERAL": 1, "PY.SYNTAX": 1}
    assert o["repair_calls_iac"] == 3 and o["repair_calls_total"] == 3
    assert o["first_draft_type_runs"] == {"google_pubsub_topic": 3} and o["function_runs"] == {"jsonencode": 2}
    assert o["healer_fvv_split"]["iac"] == 3
    assert o["consensus_changed_topology"] == "0/0" and o["synthetic_expected_met"] == "0/0"
    s["manifest"] = {"architect_consensus": "on"}
    page = report.render(s, recs)
    assert "typed-IaC measurement (TI-0)" in page and "first-draft resource types (IaC persona)" in page


# ------------------------------------------------------------------------------------------------ scoring
def test_healer_fvv_split_sums_to_the_validate_valid_fires():
    events = [{"eid": 1, "payload": "tree", "changed_paths": ["infra/workload/custom.tf"], "keys": ["HB-17|a"]},
              {"eid": 2, "payload": "text", "path": "apps/x/main.py", "keys": ["HB-31|a", "HB-31|b"]},
              {"eid": 3, "payload": "tree", "changed_paths": ["infra/workload/main.tf", "apps/x/main.py"],
               "keys": ["HA-06|a"]},
              {"eid": 4, "payload": "tree", "changed_paths": ["infra/workload/main.tf"], "keys": ["HB-17|a"]},
              {"eid": 5, "payload": "text", "path": None, "keys": ["X|a"]}]
    cls = {"1": {"validate": "valid"}, "2": {"validate": "valid"}, "3": {"validate": "valid"},
           "4": {"validate": "invalid"}, "5": {"validate": "valid"}}
    assert scoring.healer_fvv_split(events, cls) == {"iac": 1, "app": 2, "mixed": 1, "unknown": 1}
    assert scoring.event_kind({"changed_paths": ["a/terraform.tfvars", "b.tf.json"]}) == "iac"


def _hcl2_or_skip():
    try:
        from stackvend_eval.paths import add_deps_to_path
        add_deps_to_path()
        import hcl2  # noqa: F401
    except Exception:  # noqa: BLE001
        pytest.skip("python-hcl2 not importable here")


def test_draft_features_walk_the_parse_tree():
    _hcl2_or_skip()
    tf = ('data "google_project" "p" {}\n'
          'resource "google_pubsub_topic" "t" {\n  name = trimsuffix(var.x, "-")\n'
          '  labels = { a = "${lower(var.y)}" }\n}\n'
          'resource "google_storage_bucket" "b" {\n  name = "fn_name_in_a_string(x)"\n}\n'
          'variable "v" {\n  type = map(list(string))\n  default = {}\n'
          '  validation {\n    condition = length(var.v) < 3\n    error_message = "x"\n  }\n}\n')
    got = scoring.draft_features({"infra/workload/custom.tf": tf, "apps/a.py": "trimsuffix(1)\n",
                                  "infra/workload/bad.tf": "resource {"})
    assert got["types"] == ["google_pubsub_topic", "google_storage_bucket"]
    assert got["data_sources"] == ["google_project"]
    # a name inside a plain string is not a call; a variable's type constraint (map/list) is not a call
    assert got["functions"] == ["length", "lower", "trimsuffix"]
    assert got["unparsed"] == ["infra/workload/bad.tf"]


def test_iac_first_draft_prefers_the_iac_personas_own_files(tmp_path):
    blobs = BlobStore(tmp_path)
    iac = blobs.put_tree({"infra/workload/custom.tf": "x"})
    c0 = blobs.put_tree({"infra/workload/custom.tf": "x", "infra/workload/extra.tf": "y"})
    r = {"junior_drafts": {"trees": {"IAC_ENGINEER": iac}}, "checkpoints": {"C0_raw_swarm": {"tree": c0}}}
    assert scoring.iac_first_draft(r, blobs) == ("junior_drafts:IAC_ENGINEER", {"infra/workload/custom.tf": "x"})
    assert scoring.iac_first_draft({"checkpoints": {"C0_raw_swarm": {"tree": c0}}}, blobs)[0] == \
        "C0_raw_swarm_all_personas"
    assert scoring.iac_first_draft({"junior_drafts": {"trees": {"B": iac}}}, blobs) == (
        "junior_drafts:no_IAC_ENGINEER", {})


# -------------------------------------------------------------------------------- goldens (plan §1.2, RT §2)
# From the two verified cassette sets only: 10-13 (c329660) and 10-14 (769600e). Their .sha256 files cover the 27
# cassettes each; the recorded 10-14 `-results` dir read below has no .sha256 of its own (RT F11). PO-1 check 2
# (PO-final) cassettes were lost on 10-15: its column is unverifiable and has no golden. it1 = runs whose
# iteration-1 repair prompts carried the code; end = runs whose typed failure carried it (valid runs, as the plan).
# The data is never committed (Q7), so each case needs its directory in the environment and is skipped otherwise:
#   STACKVEND_TI0_GOLDEN_1014_RECORDED  the recorded 10-14 results (<backup>/20261014-FRESH-main-769600e-record-results)
#   STACKVEND_TI0_GOLDEN_1013_REPLAY    a replay-strict of the 10-13 cassettes on a c329660 export with this harness
#   STACKVEND_TI0_GOLDEN_1013_CASSETTES the 10-13 cassette dir (repair-call observer vs cassette, per exact run)
PLAN_1013 = {
    "it1": {"POLICY.PLATFORM_OWNED_TYPE": 18, "TF.REFERENCE_TO_UNDECLARED_RESOURCE": 16, "POLICY.PUBLIC_MEMBER": 10,
            "POLICY.CIDR_LITERAL": 7, "POLICY.PRIVILEGED_ROLE": 2, "POLICY.FORBIDDEN_RESOURCE_TYPE": 0,
            "CONTAINER.ENTRYPOINT_MISSING": 11, "CONTAINER.HEALTH_ROUTE_MISSING": 4, "PY.UNDEFINED_NAME": 2,
            "TF.DUPLICATE_RESOURCE_CONFIGURATION": 1, "TF.DUPLICATE_REQUIRED_PROVIDERS_CONFIGURATION": 1,
            "HCL.PARSE_ERROR": 1, "TF.INVALID_BLOCK_DEFINITION": 1, "TF.UNSUPPORTED_ARGUMENT": 1},
    "end": {"POLICY.PLATFORM_OWNED_TYPE": 8, "TF.REFERENCE_TO_UNDECLARED_RESOURCE": 8, "POLICY.PUBLIC_MEMBER": 7,
            "POLICY.CIDR_LITERAL": 5, "POLICY.PRIVILEGED_ROLE": 1, "TF.CYCLE": 1,
            "PLATFORM.ASSEMBLY_DROPPED_DECLARATION": 3, "TF.DUPLICATE_RESOURCE_CONFIGURATION": 1,
            "GATE.UNVENDORED_MODULE": 1, "TF.MODULE_NOT_INSTALLED": 1, "CONTAINER.ENTRYPOINT_MISSING": 8,
            "CONTAINER.HEALTH_ROUTE_MISSING": 3, "CONTAINER.PORT_NOT_BOUND": 1, "PY.UNDEFINED_NAME": 3},
    "committed_passed": 15, "fvv": 23,
}
PLAN_1014 = {
    "it1": {"POLICY.PLATFORM_OWNED_TYPE": 18, "TF.REFERENCE_TO_UNDECLARED_RESOURCE": 0, "POLICY.PUBLIC_MEMBER": 1,
            "POLICY.CIDR_LITERAL": 1, "POLICY.FORBIDDEN_RESOURCE_TYPE": 2, "CONTAINER.ENTRYPOINT_MISSING": 3,
            "CONTAINER.HEALTH_ROUTE_MISSING": 9, "CONTAINER.PORT_NOT_BOUND": 2, "PY.SYNTAX": 8,
            "GATE.PY_COMPILE_ERROR": 8, "PY.UNDEFINED_NAME": 7},
    "end": {"POLICY.PLATFORM_OWNED_TYPE": 6, "TF.REFERENCE_TO_UNDECLARED_RESOURCE": 7, "POLICY.PUBLIC_MEMBER": 0,
            "PY.SYNTAX": 1, "PY.UNDEFINED_NAME": 0},
    "committed_passed": 11, "fvv": 6,
}


def _aggregate_dir(d):
    recs = []
    for rd in sorted((Path(d) / "runs").iterdir()):
        if (rd / "result.json").is_file():
            rec = {"key": rd.name, "result": json.loads((rd / "result.json").read_text()), "run_dir": str(rd)}
            if (rd / "score.json").is_file():
                rec["score"] = json.loads((rd / "score.json").read_text())
            recs.append(rec)
    return metrics.aggregate(recs)


def _golden_dir(env):
    d = os.environ.get(env)
    if not d or not (Path(d) / "runs").is_dir():
        pytest.skip(f"{env} not set (cassettes and results are never committed)")
    return Path(d)


def test_golden_1014_recorded_reproduces_the_plan_exactly():
    o = _aggregate_dir(_golden_dir("STACKVEND_TI0_GOLDEN_1014_RECORDED"))["overall"]
    for code, n in PLAN_1014["it1"].items():
        assert o["first_draft_code_runs"].get(code, 0) == n, ("it1", code)
    for code, n in PLAN_1014["end"].items():
        assert o["typed_failure_code_runs"].get(code, 0) == n, ("end", code)
    assert o["outcomes"].get("committed_passed") == PLAN_1014["committed_passed"]
    assert o["fires_on_validate_valid"] == PLAN_1014["fvv"] and o["healer_fvv_split"]["iac"] == 6
    # recorded before the observer: one call per recorded repair event (the cassettes hold 42 IaC / 81 calls)
    assert o["repair_calls_source"] == ["repair_events"]
    assert (o["repair_calls_iac"], o["repair_calls_total"]) == (38, 74)


def test_golden_1013_replay_matches_the_plan_up_to_the_non_exact_runs():
    """A replay of 10-13 is exact on 23-25 of 27 runs (01-r3, 02-r1, 04-r3, 09-r1 diverge at random on the base
    harness too); every count may differ from the plan by at most the number of runs that were not exact."""
    s = _aggregate_dir(_golden_dir("STACKVEND_TI0_GOLDEN_1013_REPLAY"))
    o = s["overall"]
    slack = sum(1 for r in s["runs"] if not r["valid"] or (r.get("served") or {}).get("replay_fallback")
                or (r.get("served") or {}).get("replay_miss"))
    assert slack <= 5
    for code, n in PLAN_1013["it1"].items():
        assert abs(o["first_draft_code_runs"].get(code, 0) - n) <= slack, ("it1", code)
    for code, n in PLAN_1013["end"].items():
        assert abs(o["typed_failure_code_runs"].get(code, 0) - n) <= slack, ("end", code)
    assert abs(o["outcomes"].get("committed_passed", 0) - PLAN_1013["committed_passed"]) <= slack
    assert abs(o["fires_on_validate_valid"] - PLAN_1013["fvv"]) <= slack
    assert o["repair_calls_source"] == ["observer"]


def test_golden_1013_repair_call_observer_equals_the_cassette_on_every_exact_run():
    res = _golden_dir("STACKVEND_TI0_GOLDEN_1013_REPLAY")
    cas = os.environ.get("STACKVEND_TI0_GOLDEN_1013_CASSETTES")
    if not cas or not Path(cas).is_dir():
        pytest.skip("STACKVEND_TI0_GOLDEN_1013_CASSETTES not set")
    checked = 0
    for rd in sorted((res / "runs").iterdir()):
        r = json.loads((rd / "result.json").read_text())
        served = (r.get("llm") or {}).get("served") or {}
        if not r.get("valid_run") or served.get("replay_fallback") or served.get("replay_miss"):
            continue
        lines = (Path(cas) / f"{rd.name}.jsonl").read_text().splitlines()[1:]
        want = sum(1 for ln in lines if str(json.loads(ln).get("site", "")).endswith("SwarmDispatcher.invoke_repair"))
        got = sum(v.get("llm_calls", 0) for v in r["repair_calls"]["by_persona"].values())
        assert got == want, rd.name
        checked += 1
    assert checked >= 20
