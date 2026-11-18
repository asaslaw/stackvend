"""FD-30 healer probe (red-team H2/H9) on synthetic modules: identity rebinding, in-place semantics, descriptors,
healers-off bypass, sys.monitoring inline counters, and the referrer audit. No product code is imported."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import functools
import sys
import textwrap
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "eval"))

from stackvend_eval.blobs import BlobStore  # noqa: E402
from stackvend_eval.healer_probe import HealerProbe  # noqa: E402
from stackvend_eval.state import RunState  # noqa: E402

SRC = textwrap.dedent('''
    from typing import Dict, List, Tuple

    def heal_text(s: str) -> str:
        return s.replace("bad", "good")

    def heal_files(files: Dict[str, str]) -> Tuple[Dict[str, str], List[str]]:
        out = dict(files)
        actions = []
        if "a.tf" in out and "bad" in out["a.tf"]:
            out["a.tf"] = out["a.tf"].replace("bad", "good")
            actions.append("fixed a.tf")
        return out, actions

    def heal_inplace(files: Dict[str, str]) -> None:
        files["added.py"] = "x = 1\\n"

    def lookup(name: str) -> Optional_str:
        return name.upper()

    class Agent:
        def method_heal(self, s: str) -> str:
            return s + "!"

        @staticmethod
        def static_heal(s: str) -> str:
            return s.strip()

    def big(n):
        total = 0
        for i in range(n):
            total += i      # inline region start
            total -= 0      # inline region end
        return total

    REGISTRY = [heal_text]
''').replace("Optional_str", "\"Optional[str]\"")


@pytest.fixture()
def fake(tmp_path):
    names = ["evalprobe_fake", "evalprobe_user"]
    mod = types.ModuleType(names[0])
    mod.__file__ = str(tmp_path / "evalprobe_fake.py")
    (tmp_path / "evalprobe_fake.py").write_text(SRC)
    exec(compile(SRC, mod.__file__, "exec"), mod.__dict__)
    sys.modules[names[0]] = mod
    user = types.ModuleType(names[1])
    user.heal_text = mod.heal_text          # `from evalprobe_fake import heal_text` style re-binding
    user.heal_files = mod.heal_files
    sys.modules[names[1]] = user
    yield mod, user
    for n in names:
        sys.modules.pop(n, None)


def _targets(src_lines):
    start = next(i for i, ln in enumerate(src_lines, 1) if "inline region start" in ln)
    end = next(i for i, ln in enumerate(src_lines, 1) if "inline region end" in ln)
    t = []
    for hid, tier, q in [("HB-90", "B", "heal_text"), ("HB-91", "B", "heal_files"), ("HB-92", "B", "heal_inplace"),
                         ("HE-93", "E", "lookup"), ("HB-94", "B", "Agent.method_heal"),
                         ("HB-95", "B", "Agent.static_heal"), ("HD-96", "D", "heal_text")]:
        t.append({"key": f"{hid}@{q}", "healer_id": hid, "tier": tier, "kind": "function", "module": "evalprobe_fake",
                  "qualname": q, "status": "present", "file": "apps/orchestrator-gateway/x.py"})
    t.append({"key": "HA-97@big", "healer_id": "HA-97", "tier": "A", "kind": "inline", "module": "evalprobe_fake",
              "enclosing": "big", "lines_pinned": [[start, end]], "status": "anchored",
              "file": "apps/orchestrator-gateway/x.py"})
    return t


def _stats(probe):
    return {t["key"]: t for t in probe.report()["targets"]}


def test_probe_rebinds_all_identities_and_counts_fires(fake, tmp_path):
    mod, user = fake
    probe = HealerProbe(RunState(), _targets(SRC.splitlines()), str(tmp_path), BlobStore(tmp_path / "b"))
    probe.install()
    try:
        assert user.heal_text is mod.heal_text and user.heal_text.__name__ == "heal_text"  # functools.wraps
        assert user.heal_text("ok") == "ok"            # call, no fire
        assert user.heal_text("bad") == "good"         # call through the re-binding, fire
        files = {"a.tf": "bad", "b.py": "y = 2\n"}
        out, actions = mod.heal_files(files)
        assert out["a.tf"] == "good" and actions == ["fixed a.tf"]
        same = {"a.tf": "fine"}
        assert mod.heal_files(same) == ({"a.tf": "fine"}, [])
        inplace = {"k.py": "z = 3\n"}
        assert mod.heal_inplace(inplace) is None
        assert "added.py" in inplace                  # in-place semantics preserved (original object passed)
        assert mod.lookup("abc") == "ABC"             # Optional[str] lookup: classifier, never a fire
        assert mod.Agent().method_heal("x") == "x!"
        assert mod.Agent.static_heal("  y ") == "y"
        assert mod.big(4) == 6
        assert mod.REGISTRY[0]("bad") == "good"       # list holds the ORIGINAL: audit must report it
    finally:
        probe.stop()
    st = _stats(probe)
    assert st["HB-90@heal_text"]["calls"] == 2 and st["HB-90@heal_text"]["fires"] == 1
    assert st["HD-96@heal_text"]["role"] == "rewriter"  # shared callable: one HB row makes it a rewriter
    assert st["HB-91@heal_files"]["calls"] == 2 and st["HB-91@heal_files"]["fires"] == 1
    assert st["HB-92@heal_inplace"]["fires"] == 1
    assert st["HE-93@lookup"]["role"] == "classifier" and st["HE-93@lookup"]["fires"] == 0
    assert st["HB-94@Agent.method_heal"]["fires"] == 1
    assert st["HB-95@Agent.static_heal"]["fires"] == 1
    assert st["HA-97@big"]["reached"] == 4         # loop body entered 4 times
    assert st["HB-90@heal_text"]["bindings"] >= 2  # module + re-binding
    audit = probe.report()["audit"]["unpatched_referrers"]
    assert any(k.startswith("HB-90") and "list" in v for k, v in audit.items())
    ev = probe.report()["events"]
    files_evt = next(e for e in ev if e["payload"] == "files" and "HB-91@heal_files" in e["keys"])
    assert files_evt["changed_paths"] == ["a.tf"] and files_evt["actions"] == ["fixed a.tf"]


def test_text_healer_recovers_path_and_tree_from_caller_dict(fake, tmp_path):
    mod, _ = fake
    probe = HealerProbe(RunState(), _targets(SRC.splitlines()), str(tmp_path), BlobStore(tmp_path / "b"))
    probe.install()
    try:
        files = {"infra/workload/main.tf": "bad", "x.py": "ok"}
        for p in list(files):
            files[p] = mod.heal_text(files[p])
    finally:
        probe.stop()
    evt = next(e for e in probe.report()["events"] if e["payload"] == "text")
    assert evt["path"] == "infra/workload/main.tf"
    tree = BlobStore(tmp_path / "b").get_tree(evt["before_tree"])
    assert tree["infra/workload/main.tf"] == "bad"


def test_healers_off_bypasses_rewriters_without_calling_them(fake, tmp_path):
    mod, user = fake
    called = []
    orig = mod.heal_text

    @functools.wraps(orig)
    def spy(s):
        called.append(s)
        return orig(s)
    mod.heal_text = spy
    user.heal_text = spy
    t = [x for x in _targets(SRC.splitlines()) if x["key"] in ("HB-90@heal_text", "HB-91@heal_files")]
    ident = {"heal_text": ("arg", "s"), "heal_files": ("copy_list", "files")}
    probe = HealerProbe(RunState(), t, str(tmp_path), BlobStore(tmp_path / "b"), healers_off=True, identity=ident)
    probe.install()
    try:
        assert user.heal_text("bad") == "bad"
        assert user.heal_text(s="bad") == "bad"          # keyword call binds the named parameter
        src = {"a.tf": "bad"}
        out = mod.heal_files(src)
        assert out == ({"a.tf": "bad"}, []) and out[0] is not src  # fresh copy, as the real healer returns
    finally:
        probe.stop()
    assert called == []
    st = _stats(probe)
    assert st["HB-91@heal_files"]["healers_off"] == "bypassed"
    assert probe.report()["events"] == []


EXTRACTOR_SRC = textwrap.dedent('''
    from typing import Dict, List, Optional, Tuple

    def extract_env(custom_tf_content: Optional[str] = None, app_files: Optional[Dict[str, str]] = None,
                    caller_service: Optional[str] = None) -> Dict[str, str]:
        if not custom_tf_content:
            return {}
        return {"BUCKET": "x"}

    def heal_tuple(content: str, filename: str = "custom.tf") -> Tuple[str, List[str]]:
        return content.replace("bad", "good"), ["fixed"]

    def heal_flag(hcl_text: str) -> Tuple[str, bool]:
        return hcl_text, False

    def mutate(files: Dict[str, str], product_id: str) -> None:
        files["x"] = "y"

    def drifted(text: str) -> Dict[str, str]:
        return {"t": text}
''')


@pytest.fixture()
def extractor(tmp_path):
    mod = types.ModuleType("evalprobe_extractor")
    mod.__file__ = str(tmp_path / "evalprobe_extractor.py")
    exec(compile(EXTRACTOR_SRC, mod.__file__, "exec"), mod.__dict__)
    sys.modules[mod.__name__] = mod
    yield mod
    sys.modules.pop(mod.__name__, None)


def _ftargets(*qualnames):
    return [{"key": f"HB-8{i}@{q}", "healer_id": f"HB-8{i}", "tier": "B", "kind": "function",
             "module": "evalprobe_extractor", "qualname": q, "status": "present", "file": "apps/orchestrator-gateway/x.py"}
            for i, q in enumerate(qualnames)]


def test_healers_off_stub_returns_the_declared_type_not_the_first_str_argument(extractor, tmp_path):
    """Regression (lane 7 C1): extract_custom_resource_env_vars(custom_tf_content: str, ...) -> Dict was stubbed to
    return its str argument, so format_hcl_env_vars crashed on `.items()` in every healers-off run."""
    ident = {"extract_env": ("empty_dict", "custom_tf_content"), "heal_tuple": ("str_list", "content"),
             "heal_flag": ("str_false", "hcl_text"), "mutate": ("none", "files")}
    probe = HealerProbe(RunState(), _ftargets("extract_env", "heal_tuple", "heal_flag", "mutate"), str(tmp_path),
                        BlobStore(tmp_path / "b"), healers_off=True, identity=ident)
    probe.install()
    try:
        assert extractor.extract_env('resource "google_storage_bucket" "b" {}', {"main.py": ""}) == {}
        assert extractor.heal_tuple("bad") == ("bad", [])
        assert extractor.heal_flag("x") == ("x", False)
        files = {"a": "b"}
        assert extractor.mutate(files, "p") is None and files == {"a": "b"}
    finally:
        probe.stop()
    st = _stats(probe)
    assert all(v["healers_off"] == "bypassed" and v["bypass_fallbacks"] == 0 for v in st.values())


def test_healers_off_contract_mismatch_or_missing_runs_the_real_healer(extractor, tmp_path):
    ident = {"drifted": ("arg", "text"),          # declared Dict, contract says str -> mismatch
             "heal_flag": ("str_false", "content")}  # parameter renamed -> mismatch
    state = RunState()
    probe = HealerProbe(state, _ftargets("drifted", "heal_flag", "heal_tuple"), str(tmp_path),
                        BlobStore(tmp_path / "b"), healers_off=True, identity=ident)
    probe.install()
    try:
        assert extractor.drifted("q") == {"t": "q"}
        assert extractor.heal_tuple("bad") == ("good", ["fixed"])
    finally:
        probe.stop()
    st = {v["qualname"]: v for v in _stats(probe).values()}
    assert st["drifted"]["healers_off"].startswith("unsupported: contract mismatch")
    assert st["heal_flag"]["healers_off"].startswith("unsupported: contract mismatch")
    assert st["heal_tuple"]["healers_off"] == "unsupported: no identity contract"
    assert sum(1 for e in state.events if e["kind"] == "healers_off_contract_mismatch") == 2


def test_healers_off_call_with_wrong_argument_type_falls_back_to_the_real_healer(extractor, tmp_path):
    probe = HealerProbe(RunState(), _ftargets("heal_tuple"), str(tmp_path), BlobStore(tmp_path / "b"),
                        healers_off=True, identity={"heal_tuple": ("str_list", "content")})
    probe.install()
    try:
        with pytest.raises(AttributeError):
            extractor.heal_tuple(None)  # the real healer runs (and fails as it would in production)
    finally:
        probe.stop()
    assert next(iter(_stats(probe).values()))["bypass_fallbacks"] == 1


def test_absent_targets_are_reported_not_errors(tmp_path):
    t = [{"key": "HB-1@gone", "healer_id": "HB-1", "tier": "B", "kind": "function", "module": "evalprobe_missing_mod",
          "qualname": "gone", "status": "present", "file": "apps/orchestrator-gateway/x.py"},
         {"key": "HB-2@x", "healer_id": "HB-2", "tier": "B", "kind": "function", "module": None, "qualname": "x",
          "status": "absent", "file": "apps/orchestrator-gateway/y.py"}]
    st = RunState()
    probe = HealerProbe(st, t, str(tmp_path), BlobStore(tmp_path / "b"))
    probe.install()
    s = _stats(probe)
    assert s["HB-1@gone"]["status"] == "absent_module"
    assert s["HB-2@x"]["status"] == "absent"
