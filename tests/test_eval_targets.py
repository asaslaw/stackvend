"""FD-30 healer target inventory (red-team H2): HEALERS.md parsing, classification, anchoring."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

from stackvend_eval import gitutil  # noqa: E402
from stackvend_eval.targets import (INVENTORY_SHA, Fragment, InventoryDigestsError, anchor_to,  # noqa: E402
                                    build_inventory_digests, inventory_reader, line_digests, line_map,
                                    load_retired_healers, pack_digests, parse_rows, split_fragment, unpack_digests)

DIGESTS = ROOT / "eval" / "config" / "inventory_line_digests.json"


def test_split_fragment_forms():
    assert split_fragment("terraform_engine.py:extract_hcl_blocks:367-425") == (
        "terraform_engine.py", "extract_hcl_blocks", "367-425")
    assert split_fragment("handler.py:1620-1627") == ("handler.py", None, "1620-1627")
    assert split_fragment("self_correct_hcl:1977-1997") == (None, "self_correct_hcl", "1977-1997")
    assert split_fragment("hcl_utils.coerce_hcl_metadata_maps:991-1027") == (
        "hcl_utils.py", "coerce_hcl_metadata_maps", "991-1027")
    assert split_fragment("scripts/apply.sh:52-110") == ("scripts/apply.sh", None, "52-110")
    assert split_fragment("shared/settings.py:PlatformSettings.__init__:420-433")[1] == "PlatformSettings.__init__"


def test_parse_rows_reads_only_inventory_rows():
    md = "| ID | x |\n| :-- | :-- |\n| HB-01 | `a.py:f:1-2` | y |\n| not a row |\n| HE-16 | `b.py:3` |\n"
    assert [r[0] for r in parse_rows(md)] == ["HB-01", "HE-16"]


def test_line_map_follows_inserted_lines():
    old = "a\nb\nc\nd\n"
    new = "a\nINSERTED\nb\nc\nd\n"
    f = line_map(old, new)
    assert f(1) == 1 and f(2) == 3 and f(4) == 5


def test_anchor_to_marks_lost_and_present():
    old = "def f():\n    x = 1\n    y = 2\n    return x\n"
    new = "def f():\n    x = 1\n    # new\n    y = 2\n    return x\n"
    frs = [Fragment("HB-1", "B", "m.py:2-3", file="apps/orchestrator-gateway/m.py", lines=[(2, 3)], kind="inline",
                    enclosing="f", module="m"),
           Fragment("HB-2", "B", "m.py:f", file="apps/orchestrator-gateway/m.py", qualname="f", kind="function",
                    module="m"),
           Fragment("HB-3", "B", "m.py:g", file="apps/orchestrator-gateway/m.py", qualname="g", kind="function",
                    module="m")]
    out = anchor_to(frs, lambda p: old, lambda p: new)
    assert out[0]["status"] == "anchored" and out[0]["lines_pinned"] == [[2, 4]]
    assert out[1]["status"] == "present"
    assert out[2]["status"] == "absent"


def test_anchor_to_marks_a_listed_deleted_inline_fragment_absent_only_when_its_anchor_is_lost():
    """S2-B: eval/config/healer_deletions.json turns `anchor_lost` into `absent` for a deleted inline healer; the same
    fragment against a product root that still has the code stays `anchored`."""
    old = "def f():\n    x = 1\n    y = 2\n    return x\n"
    gone = "def f():\n    return 0\n"
    fr = Fragment("HC-9", "C", "m.py:2-3", file="apps/orchestrator-gateway/m.py", lines=[(2, 3)], kind="inline",
                  enclosing="f", module="m")
    deleted = {fr.key(): "S2-B test"}
    assert anchor_to([fr], lambda p: old, lambda p: gone)[0]["status"] == "anchor_lost"
    out = anchor_to([fr], lambda p: old, lambda p: gone, deleted)[0]
    assert out["status"] == "absent" and out["deleted_by"] == "S2-B test"
    assert anchor_to([fr], lambda p: old, lambda p: old, deleted)[0]["status"] == "anchored"


def test_healer_deletions_name_committed_targets():
    targets = {f["key"] for f in json.loads((ROOT / "eval" / "config" / "healer_targets.json").read_text())["fragments"]}
    deleted = load_retired_healers(ROOT / "eval" / "config" / "healer_deletions.json")
    assert deleted and set(deleted) <= targets


def test_committed_targets_cover_the_generation_path():
    data = json.loads((ROOT / "eval" / "config" / "healer_targets.json").read_text())
    assert data["inventory_sha"] == INVENTORY_SHA
    kinds = data["counts_by_kind"]
    assert kinds["function"] > 50 and kinds["inline"] > 40
    by = {}
    for f in data["fragments"]:
        by.setdefault(f["healer_id"], []).append(f)
    assert any(f["kind"] == "inline" and f["enclosing"] == "DeveloperAgent.generate_code_files" for f in by["HA-10"])
    hb24 = {f["file"]: f["kind"] for f in by["HB-24"]}  # hcl_utils x5: two gateway copies loaded, others not
    assert hb24["apps/orchestrator-gateway/shared/hcl_utils.py"] == "function"
    assert hb24["apps/orchestrator-gateway/developer_agent/hcl_utils.py"] == "function"
    assert hb24["shared/hcl_utils.py"] == "not_loaded"
    assert hb24["mcp-servers/terraform/hcl_utils.py"] == "apply_time"


def test_committed_targets_file_is_current():
    has_inventory = subprocess.run(["git", "-C", str(ROOT), "cat-file", "-e", f"{INVENTORY_SHA}^{{commit}}"],
                                   capture_output=True).returncode == 0
    if not has_inventory:
        pytest.skip(f"inventory commit {INVENTORY_SHA} {gitutil.NOT_IN_CLONE}")
    if not (ROOT / "docs" / "planning" / "review" / "HEALERS.md").is_file():
        pytest.skip("docs/planning/review/HEALERS.md absent (docs/ is internal and not in the public export)")
    r = subprocess.run([sys.executable, str(ROOT / "eval" / "tools" / "build_targets.py"), "--check"],
                       capture_output=True, text=True, cwd=str(ROOT), env=hermetic_guard.child_env())
    assert r.returncode == 0, r.stdout + r.stderr


# ------------------------------------------------------------------ OSS blocker 1a: anchoring without the history
_OLD = "def f():\n    a = 1\n\n    b = 2\n    return a + b\n\n\ndef g():\n    return 1\n"
_EDITS = [
    _OLD,                                                    # unchanged
    "# header\n\n" + _OLD,                                   # lines inserted above
    _OLD.replace("    b = 2\n", ""),                         # a line deleted inside the range
    _OLD.replace("    a = 1\n", "    a = 1\n    a = 1\n"),  # duplicated line
    "def g():\n    return 1\n\n\n" + _OLD.split("\n\n\n")[0] + "\n",  # functions swapped
    "",                                                      # file emptied
]


@pytest.mark.parametrize("new", _EDITS)
def test_digest_line_map_equals_the_source_line_map(new):
    """The vendored form (per-line digests) must give exactly the line map the old source text gives."""
    by_src, by_digest = line_map(_OLD, new), line_map(line_digests(_OLD), new)
    n = _OLD.count("\n") + 2
    assert [by_src(i) for i in range(1, n)] == [by_digest(i) for i in range(1, n)]


@pytest.mark.parametrize("new", _EDITS)
def test_anchor_to_with_digests_equals_anchor_to_with_source(new):
    frs = [Fragment("HC-1", "C", "m.py:2-4", file="apps/orchestrator-gateway/m.py", lines=[(2, 4)], kind="inline",
                    enclosing="f", module="m"),
           Fragment("HA-1", "A", "m.py:g", file="apps/orchestrator-gateway/m.py", qualname="g", kind="function",
                    module="m")]
    assert anchor_to(frs, lambda p: _OLD, lambda p: new) == anchor_to(frs, lambda p: line_digests(_OLD),
                                                                        lambda p: new)


def test_pack_unpack_round_trip_and_bad_length():
    d = line_digests(_OLD)
    assert unpack_digests(pack_digests(d)) == d and unpack_digests("") == []
    with pytest.raises(ValueError):
        unpack_digests("abc")


def test_inventory_reader_missing_file_and_wrong_inventory(tmp_path):
    """RT F1: fail closed. A missing file raises (it used to read as {} -> every inline fragment anchor_lost)."""
    with pytest.raises(FileNotFoundError):
        inventory_reader(tmp_path / "none.json")
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"inventory_sha": "0000000", "files": {}}))
    with pytest.raises(InventoryDigestsError, match="regenerate"):
        inventory_reader(bad)
    empty = tmp_path / "empty.json"
    empty.write_text("{}")  # an empty object must not skip the inventory_sha check
    with pytest.raises(InventoryDigestsError, match="regenerate"):
        inventory_reader(empty)
    nofiles = tmp_path / "nofiles.json"
    nofiles.write_text(json.dumps({"inventory_sha": INVENTORY_SHA}))
    with pytest.raises(InventoryDigestsError, match="files"):
        inventory_reader(nofiles)


def test_anchored_targets_refuses_a_missing_digests_file_or_entry(tmp_path, monkeypatch):
    """RT F1: run time fails closed instead of reporting a silent anchor_lost / false deleted_by."""
    import run_examples
    monkeypatch.setattr(run_examples, "INVENTORY_DIGESTS_PATH", tmp_path / "absent.json")
    with pytest.raises(FileNotFoundError):
        run_examples.anchored_targets(ROOT)
    data = json.loads(DIGESTS.read_text())
    dropped = sorted(data["files"])[0]
    del data["files"][dropped]
    partial = tmp_path / "partial.json"
    partial.write_text(json.dumps(data))
    monkeypatch.setattr(run_examples, "INVENTORY_DIGESTS_PATH", partial)
    with pytest.raises(InventoryDigestsError, match=dropped):
        run_examples.anchored_targets(ROOT)


def test_private_checkout_never_silently_skips_the_history_tests():
    """RT F4 tripwire: the private tree (docs/ present; the public export always drops it) must carry the commits
    the history tests read, so a shallow or broken private checkout fails here instead of quietly skipping them."""
    if not (ROOT / "docs" / "planning" / "review" / "HEALERS.md").is_file():
        pytest.skip("public export (no docs/): the history tests are expected to skip")
    missing = [sha for sha in (INVENTORY_SHA, "44a2747") if not gitutil.has_commit(ROOT, sha)]
    assert not missing, (f"private checkout without commit(s) {missing}: use a full clone (CI: fetch-depth 0) and a "
                         "working git, or the eval history tests skip silently")


def test_vendored_digests_cover_every_inline_fragment_file():
    data = json.loads(DIGESTS.read_text())
    assert data["inventory_sha"] == INVENTORY_SHA
    targets = json.loads((ROOT / "eval" / "config" / "healer_targets.json").read_text())["fragments"]
    inline_files = {f["file"] for f in targets if f["kind"] == "inline" and f["file"]}
    assert inline_files and inline_files == set(data["files"])
    read = inventory_reader(DIGESTS)
    assert all(read(p) for p in inline_files)


def test_anchored_targets_never_reads_git_history(monkeypatch):
    """A clone without INVENTORY_SHA (fresh public history, shallow CI checkout) anchors from the vendored file."""
    import run_examples

    def no_git(*a, **k):
        raise AssertionError("anchored_targets must not read the inventory commit from git")
    monkeypatch.setattr(run_examples.gitutil, "show", no_git)
    monkeypatch.setattr(run_examples.gitutil, "_git", no_git)
    statuses = {t["status"] for t in run_examples.anchored_targets(ROOT)}
    assert "anchored" in statuses


def test_vendored_digests_match_the_inventory_commit():
    if not gitutil.has_commit(ROOT, INVENTORY_SHA):
        pytest.skip(f"inventory commit {INVENTORY_SHA} {gitutil.NOT_IN_CLONE}")
    targets = json.loads((ROOT / "eval" / "config" / "healer_targets.json").read_text())["fragments"]
    frags = [Fragment(**{k: v for k, v in f.items() if k in Fragment.__dataclass_fields__}) for f in targets]
    want = build_inventory_digests(frags, lambda p: gitutil.show(str(ROOT), INVENTORY_SHA, p))
    assert want == json.loads(DIGESTS.read_text())
