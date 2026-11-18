"""FD-55 W0 / FD-4CR: the eval's reviewed retired-healer list (eval/config/healer_deletions.json) and the probe
coverage measured over LIVE healers only.

A healer deleted on purpose is listed with the commit that deleted it; its fragment leaves the coverage denominator
only when its code is really gone from the product root under test. An unlisted deletion (absent or anchor_lost)
stays in the denominator as unmeasured, so it lowers coverage and fails the exact pins in tests/test_eval_e2e.py.
Hermetic: no product import, git read-only (skips per commit on a clone without the private history)."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

from stackvend_eval import gitutil  # noqa: E402
from stackvend_eval.metrics import coverage  # noqa: E402
from stackvend_eval.targets import (GATEWAY, Fragment, RetiredHealersError, anchor_to,  # noqa: E402
                                    inventory_reader, load_inventory_digests, load_retired_healers)

CONFIG = ROOT / "eval" / "config"
RETIRED_PATH = CONFIG / "healer_deletions.json"


def _fragments():
    data = json.loads((CONFIG / "healer_targets.json").read_text())
    out = {}
    for f in data["fragments"]:
        f = dict(f)
        f.pop("key", None)
        fr = Fragment(**{k: v for k, v in f.items() if k in Fragment.__dataclass_fields__})
        fr.lines = [tuple(x) for x in fr.lines]
        out[fr.key()] = fr
    return out


# ------------------------------------------------------------------------------------------------ the list itself
def test_retired_list_schema_and_every_key_is_an_inventory_generation_path_fragment():
    retired = load_retired_healers(RETIRED_PATH)
    frags = _fragments()
    assert len(retired) >= 58
    for key, entry in retired.items():
        assert key in frags, key
        fr = frags[key]
        assert fr.file.startswith(GATEWAY) and fr.kind in ("function", "inline"), key
        assert set(entry) == {"commit", "by"} and len(entry["commit"]) >= 7 and entry["by"].strip(), key


def test_retired_list_keeps_code_that_is_still_there_out():
    """HB-45's settings floor migrations moved (anchor lost) but were NOT deleted: they must never be listed."""
    assert not [k for k in load_retired_healers(RETIRED_PATH) if k.startswith("HB-45@")]


@pytest.mark.parametrize("bad", [
    {"retired": {}},                                                     # no schema
    {"schema": 1, "deleted": {"k": "S2-B"}},                             # the pre-W0 form
    {"schema": 2, "retired": {"k": {"commit": "not-a-sha", "by": "x"}}},
    {"schema": 2, "retired": {"k": {"commit": "abcdef1", "by": " "}}},
    {"schema": 2, "retired": {"k": "abcdef1"}},
])
def test_malformed_retired_list_fails_closed(tmp_path, bad):
    p = tmp_path / "healer_deletions.json"
    p.write_text(json.dumps(bad))
    with pytest.raises(RetiredHealersError):
        load_retired_healers(p)


def test_missing_retired_list_is_no_retired_healer(tmp_path):
    assert load_retired_healers(tmp_path / "absent.json") == {}


def test_each_retired_commit_deleted_its_fragment():
    """The recorded commit touches the fragment's file and the fragment's code is gone at that commit (git read-only;
    a commit missing from this clone skips, as the inventory-SHA tests do)."""
    retired = load_retired_healers(RETIRED_PATH)
    frags = _fragments()
    digests = CONFIG / "inventory_line_digests.json"
    reader = inventory_reader(digests, load_inventory_digests(digests))
    checked = 0
    for key, entry in sorted(retired.items()):
        sha = entry["commit"]
        if not gitutil.has_commit(ROOT, sha):
            continue
        fr = frags[key]
        touched = subprocess.run(["git", "-C", str(ROOT), "show", "--name-only", "--format=", sha],
                                 capture_output=True, text=True).stdout.split()
        assert fr.file in touched, (key, sha)
        st = anchor_to([fr], reader, lambda p, s=sha: gitutil.show(str(ROOT), s, p))[0]["status"]
        assert st not in ("anchored", "present"), (key, sha, st)
        anc = subprocess.run(["git", "-C", str(ROOT), "merge-base", "--is-ancestor", sha, "HEAD"])
        assert anc.returncode == 0, (key, sha)
        checked += 1
    if not checked:
        pytest.skip(f"no retired-healer commit {gitutil.NOT_IN_CLONE}")


# ------------------------------------------------------------------------------------------------ anchoring
def test_listed_deleted_function_gets_deleted_by_unlisted_does_not():
    src = "def keep():\n    return 1\n"
    gone = Fragment("HB-90", "B", "m.py:gone:1-2", file=GATEWAY + "m.py", qualname="gone", lines=[(1, 2)],
                    kind="function", module="m")
    other = Fragment("HB-91", "B", "m.py:other:1-2", file=GATEWAY + "m.py", qualname="other", lines=[(1, 2)],
                     kind="function", module="m")
    entry = {"commit": "abcdef1234", "by": "test row"}
    a, b = anchor_to([gone, other], lambda p: src, lambda p: src, {gone.key(): entry})
    assert a["status"] == "absent" and a["deleted_by"] == entry
    assert b["status"] == "absent" and "deleted_by" not in b
    # the same listed function against a product root that still has it: present, measured, no deleted_by
    c = anchor_to([gone], lambda p: src, lambda p: "def gone():\n    return 0\n", {gone.key(): entry})[0]
    assert c["status"] == "present" and "deleted_by" not in c


# ------------------------------------------------------------------------------------------------ coverage
def _t(key, kind="inline", status="anchored", bindings=0, deleted_by=None):
    t = {"key": key, "id": key.split("@")[0], "tier": "B", "kind": kind, "file": GATEWAY + "x.py", "status": status}
    if kind == "function":
        t["bindings"] = bindings
    if deleted_by:
        t["deleted_by"] = deleted_by
    return t


def _cov(targets):
    return coverage([{"result": {"healers": {"targets": targets}}}])


LIVE = [_t("HB-1@a"), _t("HB-2@b"), _t("HB-3@c", kind="function", status="present", bindings=2),
        _t("HB-4@d", status="anchor_lost")]          # 3 measured of 4 live
RETIRED = [_t("HC-1@e", status="absent", deleted_by={"commit": "abc1234", "by": "W1"}),
           _t("HC-2@f", kind="function", status="absent", deleted_by={"commit": "abc1235", "by": "W1"})]


def test_coverage_is_over_live_fragments_only():
    cov = _cov(LIVE + RETIRED)
    assert cov["generation_path_fragments"] == 6 and cov["fragments_retired"] == 2 and cov["live_fragments"] == 4
    assert cov["fragments_measured"] == 3 and cov["coverage_pct"] == 75.0
    assert cov["retired"] == ["HC-1@e", "HC-2@f"] and cov["absent_unrecorded"] == []
    assert cov["unmeasured"] == ["HB-4@d"] and cov["anchor_lost"] == ["HB-4@d"]
    assert cov["coverage_pct_incl_absent"] == 50.0


def test_recorded_deletion_of_a_measured_healer_keeps_coverage():
    """Deleting a measured healer AND listing it: measured and live both drop by one; nothing unmeasured is added."""
    before = _cov(LIVE + RETIRED)
    after = _cov([_t("HB-1@a", status="absent", deleted_by={"commit": "abc1236", "by": "W4"})] + LIVE[1:] + RETIRED)
    assert after["unmeasured"] == before["unmeasured"] and after["absent_unrecorded"] == []
    assert after["live_fragments"] == before["live_fragments"] - 1
    assert after["fragments_measured"] == before["fragments_measured"] - 1


@pytest.mark.parametrize("status", ["absent", "anchor_lost", "absent_file"])
def test_unrecorded_deletion_counts_against_coverage(status):
    """Deleting a measured healer WITHOUT listing it: it stays live, becomes unmeasured, coverage drops."""
    before = _cov(LIVE + RETIRED)
    after = _cov([_t("HB-1@a", status=status)] + LIVE[1:] + RETIRED)
    assert after["live_fragments"] == before["live_fragments"]
    assert "HB-1@a" in after["unmeasured"] and after["coverage_pct"] < before["coverage_pct"]
    if status != "anchor_lost":
        assert after["absent_unrecorded"] == ["HB-1@a"]


def test_listed_healer_still_present_in_an_older_product_root_stays_live_and_measured():
    """deleted_by is only set by anchor_to when the code is gone; a listed key that is anchored is just live."""
    cov = _cov(LIVE + [_t("HC-1@e"), RETIRED[1]])
    assert cov["fragments_retired"] == 1 and cov["live_fragments"] == 5 and cov["fragments_measured"] == 4
