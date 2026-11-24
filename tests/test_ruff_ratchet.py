"""
.github/scripts/ruff_ratchet.py: which F811 findings the CI ratchet does not count.

Only a parameter or function-local assignment shadowing a module-level import is skipped, decided from ruff's location
and the file's AST. The hand-written findings below pin the rule; the last test runs the real ruff (when it is on PATH)
so the location contract between ruff's JSON and ``ast`` is proven too.

The C901 ratchet (FD-85, docs/planning/code-readability-plan.md section 2) and the lint-baseline half of
.github/scripts/allowlist_guard.py are tested at the end of this file.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import types

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _load_ratchet():
    spec = importlib.util.spec_from_file_location(
        "ruff_ratchet_under_test", os.path.join(REPO, ".github", "scripts", "ruff_ratchet.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


ratchet = _load_ratchet()


def _finding(path, row, column, code="F811", symbol="gw"):
    return {
        "code": code,
        "filename": str(path),
        "location": {"row": row, "column": column},
        "message": f"Redefinition of unused `{symbol}` from line 1",
    }


def _write(tmp_path, source, name="sample.py"):
    path = tmp_path / name
    path.write_text(textwrap.dedent(source).lstrip("\n"), encoding="utf-8")
    return path


def _is_skipped(path, row, column):
    kept, skipped, unparseable = ratchet.drop_import_shadows([_finding(path, row, column)])
    assert unparseable == []
    assert skipped + len(kept) == 1
    return skipped == 1


@pytest.mark.parametrize("source,row,column", [
    pytest.param("from s import gw\n\ndef test_x(gw):\n    pass\n", 3, 12, id="positional"),
    pytest.param("from s import gw\n\nasync def test_x(gw):\n    pass\n", 3, 18, id="async"),
    pytest.param("from s import gw\n\ndef test_x(a, *, gw=None):\n    pass\n", 3, 18, id="keyword-only"),
    pytest.param("from s import gw\n\ndef test_x(*gw):\n    pass\n", 3, 13, id="varargs"),
    pytest.param("from s import gw\n\ndef test_x(gw: int = 1):\n    pass\n", 3, 12, id="annotated"),
    pytest.param("from s import gw\n\nclass T:\n    def test_x(self, gw):\n        pass\n", 4, 22, id="method"),
    pytest.param("from s import gw\n\nf = lambda gw: 1\n", 3, 12, id="lambda"),
    pytest.param("import s.gw as gw\n\ndef test_x(gw):\n    pass\n", 3, 12, id="import-as"),
    pytest.param("try:\n    import gw\nexcept ImportError:\n    gw = None\n\ndef test_x(gw):\n    pass\n", 6, 12,
                 id="import-under-module-level-try"),
])
def test_parameter_shadowing_a_module_import_is_skipped(tmp_path, source, row, column):
    assert _is_skipped(_write(tmp_path, source), row, column)


@pytest.mark.parametrize("source,row,column", [
    pytest.param("from s import gw\n\ndef test_x():\n    gw = 1\n", 4, 5, id="plain"),
    pytest.param("from s import gw\n\ndef test_x():\n    a, (gw, b) = 1, (2, 3)\n", 4, 9, id="unpacking"),
    pytest.param("from s import gw\n\ndef test_x():\n    a, *gw = [1]\n", 4, 9, id="starred"),
    pytest.param("from s import gw\n\ndef test_x():\n    gw: int = 1\n", 4, 5, id="annotated"),
    pytest.param("from s import gw\n\ndef test_x():\n    if (gw := 1):\n        pass\n", 4, 9, id="walrus"),
    pytest.param("from s import gw\n\ndef test_x():\n    if True:\n        gw = 1\n", 5, 9, id="nested-block"),
])
def test_local_assignment_shadowing_a_module_import_is_skipped(tmp_path, source, row, column):
    assert _is_skipped(_write(tmp_path, source), row, column)


def test_duplicate_test_function_is_still_reported(tmp_path):
    """The first `def test_x` silently never runs: the finding the ratchet exists for."""
    path = _write(tmp_path, "def test_x():\n    pass\n\ndef test_x():\n    pass\n")
    kept, skipped, _ = ratchet.drop_import_shadows([_finding(path, 4, 5, symbol="test_x")])
    assert skipped == 0 and len(kept) == 1


def test_function_named_like_a_module_import_is_still_reported(tmp_path):
    assert not _is_skipped(_write(tmp_path, "from s import gw\n\ndef gw():\n    pass\n"), 3, 5)


@pytest.mark.parametrize("source,row,column", [
    pytest.param("import gw\nimport gw\n", 2, 8, id="module-level"),
    pytest.param("from s import gw\nfrom t import gw\n", 2, 15, id="from-import"),
    pytest.param("from s import gw\n\ndef test_x():\n    from t import gw\n", 4, 19, id="inside-a-function"),
])
def test_reimport_is_still_reported(tmp_path, source, row, column):
    assert not _is_skipped(_write(tmp_path, source), row, column)


@pytest.mark.parametrize("source,row,column", [
    pytest.param("from s import gw\ngw = 1\n", 2, 1, id="module-level-assignment"),
    pytest.param("from s import gw\n\nclass T:\n    gw = 1\n", 4, 5, id="class-level-assignment"),
    pytest.param("from s import gw\n\ndef test_x():\n    global gw\n    gw = 1\n", 5, 5, id="global-assignment"),
    pytest.param("from s import gw\n\ndef test_x():\n    def gw():\n        pass\n", 4, 9, id="nested-def"),
    pytest.param("from s import gw\n\ndef test_x():\n    for gw in []:\n        pass\n", 4, 9, id="for-target"),
    pytest.param("from s import gw\n\ndef test_x():\n    with open('f') as gw:\n        pass\n", 4, 23, id="with-target"),
    pytest.param("from s import gw\n\ndef test_x():\n    try:\n        pass\n    except E as gw:\n        pass\n", 6, 17,
                 id="except-name"),
    pytest.param("from s import gw\n\ndef test_x():\n    return [gw for gw in []]\n", 4, 20, id="comprehension"),
    pytest.param("def outer():\n    import gw\n    def inner(gw):\n        pass\n", 3, 15,
                 id="shadowing-a-function-level-import"),
    pytest.param("gw = object()\n\ndef test_x(gw):\n    pass\n", 3, 12, id="shadowing-a-non-import"),
])
def test_other_redefinitions_are_still_reported(tmp_path, source, row, column):
    assert not _is_skipped(_write(tmp_path, source), row, column)


def test_location_must_match_exactly(tmp_path):
    path = _write(tmp_path, "from s import gw\n\ndef test_x(gw):\n    pass\n")
    assert _is_skipped(path, 3, 12)
    assert not _is_skipped(path, 3, 13)
    assert not _is_skipped(path, 3, 11)
    assert not _is_skipped(path, 99, 12)


def test_columns_count_characters_not_bytes(tmp_path):
    """ast reports UTF-8 byte offsets, ruff reports characters."""
    path = _write(tmp_path, 'from s import gw\n\ndef test_x(a="\u00e9\U0001f600", gw=None):\n    pass\n')
    assert _is_skipped(path, 3, 20)
    assert not _is_skipped(path, 3, 25)


@pytest.mark.parametrize("content", [
    pytest.param(b"from s import gw\n\ndef test_x(gw:\n", id="syntax-error"),
    pytest.param(b"from s import gw\n\ndef test_x(gw):\n    pass\x00\n", id="null-byte"),
    pytest.param(b"from s import gw\n\ndef test_x(gw):\n    x = '\xff'\n", id="not-utf8"),
    pytest.param(b"# -*- coding: no-such-codec -*-\nfrom s import gw\n", id="unknown-codec"),
])
def test_unparseable_file_keeps_every_finding(tmp_path, content):
    path = tmp_path / "broken.py"
    path.write_bytes(content)
    items = [_finding(path, 3, 12), _finding(path, 3, 12, symbol="other")]
    kept, skipped, unparseable = ratchet.drop_import_shadows(items)
    assert kept == items and skipped == 0
    assert [p for p, _ in unparseable] == [str(path)]  # named once, however many findings the file has


def test_missing_file_keeps_its_finding(tmp_path):
    items = [_finding(tmp_path / "gone.py", 3, 12)]
    kept, skipped, unparseable = ratchet.drop_import_shadows(items)
    assert kept == items and skipped == 0 and len(unparseable) == 1


@pytest.mark.parametrize("code", ["F821", "F401", "E999", None])
def test_other_rule_codes_are_untouched(tmp_path, code):
    """Same location as a skippable shadow; no other code is even looked at, so an unparseable file adds no noise."""
    path = _write(tmp_path, "from s import gw\n\ndef test_x(gw):\n    pass\n")
    items = [_finding(path, 3, 12, code=code)]
    assert ratchet.drop_import_shadows(items) == (items, 0, [])
    missing = [_finding(tmp_path / "gone.py", 3, 12, code=code)]
    assert ratchet.drop_import_shadows(missing) == (missing, 0, [])


def _baseline_doc(fingerprints, **overrides):
    """The shape save() writes; ``overrides`` replace (or, with None, remove) its keys."""
    doc = {"select": ratchet.SELECT, "max_complexity": ratchet.MAX_COMPLEXITY, "fingerprints": fingerprints}
    for key, value in overrides.items():
        if value is None:
            doc.pop(key, None)
        else:
            doc[key] = value
    return doc


def _run_main(monkeypatch, tmp_path, findings, baseline, doc=None, update=False):
    """main() with `git ls-files` and ruff replaced by their canned output. ``doc`` replaces the whole baseline."""
    base = tmp_path / "baseline.json"
    base.write_text(json.dumps(_baseline_doc(baseline) if doc is None else doc), encoding="utf-8")

    def fake_run(cmd, **_kwargs):
        return types.SimpleNamespace(stdout="x.py\0" if cmd[0] == "git" else json.dumps(findings))

    monkeypatch.setattr(ratchet.subprocess, "run", fake_run)
    monkeypatch.setattr(ratchet.sys, "argv", ["ruff_ratchet.py", "--baseline", str(base), *(["--update"] if update
                                                                                            else [])])
    monkeypatch.setattr(ratchet, "ROOT", str(tmp_path))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    return ratchet.main()


def test_main_passes_on_a_shadow_and_fails_on_a_duplicate(monkeypatch, tmp_path, capsys):
    path = _write(tmp_path, "from s import gw\n\ndef test_x(gw):\n    pass\n\ndef test_x(gw):\n    pass\n")
    shadows = [_finding(path, 3, 12), _finding(path, 6, 12)]
    assert _run_main(monkeypatch, tmp_path, shadows, {}) == 0
    assert "new 0" in capsys.readouterr().out

    duplicate = _finding(path, 6, 5, symbol="test_x")
    assert _run_main(monkeypatch, tmp_path, [*shadows, duplicate], {}) == 1
    assert "+ sample.py|F811|test_x" in capsys.readouterr().out


def test_main_fails_loudly_on_an_unparseable_file(monkeypatch, tmp_path, capsys):
    path = tmp_path / "broken.py"
    path.write_bytes(b"from s import gw\n\ndef test_x(gw:\n")
    assert _run_main(monkeypatch, tmp_path, [_finding(path, 3, 12)], {}) == 1
    captured = capsys.readouterr()
    assert "+ broken.py|F811|gw" in captured.out
    assert "cannot parse broken.py" in captured.err


REAL_RUFF_SAMPLE = '''
from s import gw, other, third, fifth

import again
import again


def test_param(gw):
    pass


def test_local():
    other = 1
    return other


def test_unicode(a="\u00e9\U0001f600", third=None):
    pass


def test_dup():
    pass


def test_dup():
    pass


def test_reimport():
    from t import fifth
    return fifth
'''


def test_against_the_real_ruff(tmp_path):
    """Runs only where ruff is installed (the CI pytest job has none): ruff's JSON and ast must agree on locations."""
    ruff = shutil.which("ruff")
    if ruff is None:
        pytest.skip("ruff is not on PATH")
    path = _write(tmp_path, REAL_RUFF_SAMPLE)
    out = subprocess.run([ruff, "check", "--isolated", "--no-cache", "--ignore-noqa", "--select", "F811",
                          "--output-format", "json", "--exit-zero", str(path)],
                         check=True, capture_output=True, text=True, cwd=tmp_path).stdout
    items = json.loads(out)
    assert len(items) == 6, items  # ruff still reports every shape the ratchet then sorts
    kept, skipped, unparseable = ratchet.drop_import_shadows(items)
    assert unparseable == []
    assert skipped == 3
    assert sorted(ratchet._SYMBOL.search(i["message"]).group(1) for i in kept) == ["again", "fifth", "test_dup"]


# ------------------------------------------------------------------------------------------------ C901 (FD-85)
def _load_guard():
    spec = importlib.util.spec_from_file_location(
        "allowlist_guard_under_ratchet_test", os.path.join(REPO, ".github", "scripts", "allowlist_guard.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


guard = _load_guard()


def _c901(path, name, score=16):
    return {"code": "C901", "filename": str(path), "location": {"row": 1, "column": 1},
            "message": f"`{name}` is too complex ({score} > {ratchet.MAX_COMPLEXITY})"}


def _f821(path, name):
    return {"code": "F821", "filename": str(path), "location": {"row": 1, "column": 1},
            "message": f"Undefined name `{name}`"}


def _pinned_ruff_or_skip():
    """The real ruff, only when it is the version ci.yml pins (messages and scores are version-specific)."""
    ruff = shutil.which("ruff")
    if ruff is None:
        pytest.skip("ruff is not on PATH")
    with open(os.path.join(REPO, ".github", "workflows", "ci.yml"), encoding="utf-8") as fh:
        pin = re.search(r'^\s*RUFF_VERSION:\s*"([^"]+)"', fh.read(), re.M).group(1)
    version = subprocess.run([ruff, "--version"], check=True, capture_output=True, text=True).stdout.split()[-1]
    if version != pin:
        pytest.skip(f"ruff {version} is not the ci.yml pin {pin}")
    return ruff


def _complex_source(name, branches=16, noqa=False):
    """A function of mccabe complexity ``branches + 1``."""
    body = "".join(f"    if x == {i}:\n        return {i}\n" for i in range(branches))
    return f"def {name}(x):{'  # noqa: C901' if noqa else ''}\n{body}    return -1\n"


def _run_main_real_ruff(monkeypatch, tmp_path, ruff, files, baseline):
    """main() with the real ruff over ``files`` (written under tmp_path): only `git ls-files` is canned."""
    for rel, source in files.items():
        _write(tmp_path, source, name=rel)
    base = tmp_path / "baseline.json"
    base.write_text(json.dumps(_baseline_doc(baseline)), encoding="utf-8")
    real_run = subprocess.run

    def fake_run(cmd, **kwargs):
        if cmd[0] == "git":
            return types.SimpleNamespace(stdout="".join(f"{rel}\0" for rel in sorted(files)))
        return real_run(cmd, **kwargs)

    monkeypatch.setattr(ratchet.subprocess, "run", fake_run)
    monkeypatch.setattr(ratchet.sys, "argv", ["ruff_ratchet.py", "--ruff", ruff, "--baseline", str(base)])
    monkeypatch.setattr(ratchet, "ROOT", str(tmp_path))
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    return ratchet.main()


def test_c901_today_s_tree_passes_with_the_committed_baseline():
    """Test 1: the committed baseline is what the pinned ruff finds on this tree (no new, no fixed C901 entry)."""
    ruff = _pinned_ruff_or_skip()
    r = subprocess.run([sys.executable, os.path.join(".github", "scripts", "ruff_ratchet.py"), "--ruff", ruff],
                       cwd=REPO, capture_output=True, text=True, timeout=600, env=hermetic_guard.child_env())
    assert r.returncode == 0, r.stdout + r.stderr
    assert "new 0; fixed 0;" in r.stdout


def test_c901_new_function_fails_in_a_listed_and_an_unlisted_file(monkeypatch, tmp_path, capsys):
    """Test 2: a new function over the threshold fails, named, whether or not its file already has a listed one."""
    listed = {"listed.py|C901|old_busy": 1}
    keep = _c901(tmp_path / "listed.py", "old_busy", 40)
    assert _run_main(monkeypatch, tmp_path, [keep], listed) == 0
    assert "new 0; fixed 0;" in capsys.readouterr().out
    for finding, key in ((_c901(tmp_path / "listed.py", "new_busy"), "listed.py|C901|new_busy"),
                         (_c901(tmp_path / "other.py", "new_busy"), "other.py|C901|new_busy")):
        assert _run_main(monkeypatch, tmp_path, [keep, finding], listed) == 1
        out = capsys.readouterr().out
        assert f"+ {key}" in out and "NEW F821/F811/C901" in out


def test_c901_listed_function_may_grow_count_only(monkeypatch, tmp_path, capsys):
    """Gap (d), by design: a listed function's score is not stored, so it may grow (plan Q2)."""
    assert _run_main(monkeypatch, tmp_path, [_c901(tmp_path / "a.py", "busy", 99)], {"a.py|C901|busy": 1}) == 0


def test_c901_fixed_entry_fails_check_mode_until_update_removes_it(monkeypatch, tmp_path, capsys):
    """Test 3 (ratchet half, gap c): a listed function now <= the threshold fails check mode until --update."""
    listed = {"a.py|C901|busy": 1, "a.py|C901|still": 1}
    findings = [_c901(tmp_path / "a.py", "still")]  # `busy` dropped to <= 15: ruff no longer reports it
    assert _run_main(monkeypatch, tmp_path, findings, listed) == 1
    out = capsys.readouterr().out
    assert "FIXED C901 entries still in the baseline (1)" in out and "- a.py|C901|busy" in out
    assert "+ " not in out
    assert _run_main(monkeypatch, tmp_path, findings, listed, update=True) == 0
    written = json.loads((tmp_path / "baseline.json").read_text(encoding="utf-8"))
    assert written["fingerprints"] == {"a.py|C901|still": 1}
    assert _run_main(monkeypatch, tmp_path, findings, written["fingerprints"]) == 0


def test_fixed_f821_still_only_warns(monkeypatch, tmp_path, capsys):
    """Only C901 fails on a fixed entry; a fixed F821/F811 keeps the old shrink-with---update advice (exit 0)."""
    assert _run_main(monkeypatch, tmp_path, [], {"a.py|F821|gone": 1}) == 0
    out = capsys.readouterr().out
    assert "Fixed since the baseline" in out and "- a.py|F821|gone" in out and "FIXED C901" not in out


def test_c901_rename_is_a_new_key_and_the_old_key_is_fixed(monkeypatch, tmp_path, capsys):
    """Test 5: renaming a listed function fails (new fingerprint) and reports the old fingerprint as fixed."""
    findings = [_c901(tmp_path / "a.py", "renamed")]
    assert _run_main(monkeypatch, tmp_path, findings, {"a.py|C901|busy": 1}) == 1
    out = capsys.readouterr().out
    assert "+ a.py|C901|renamed" in out and "- a.py|C901|busy" in out


def test_update_writes_select_and_max_complexity(monkeypatch, tmp_path):
    """save() records the rule set and the threshold; --update re-seeds even from a mismatched baseline."""
    stale = {"select": "F821,F811", "fingerprints": {}}
    assert _run_main(monkeypatch, tmp_path, [_c901(tmp_path / "a.py", "busy")], {}, doc=stale, update=True) == 0
    written = json.loads((tmp_path / "baseline.json").read_text(encoding="utf-8"))
    assert written["select"] == ratchet.SELECT == "F821,F811,C901"
    assert written["max_complexity"] == ratchet.MAX_COMPLEXITY == 15
    assert written["fingerprints"] == {"a.py|C901|busy": 1} and written["total"] == 1


@pytest.mark.parametrize("doc", [
    pytest.param(_baseline_doc({}, select="F821,F811"), id="select-without-C901"),
    pytest.param(_baseline_doc({}, select="F821,F811,C901,E501"), id="select-with-more"),
    pytest.param(_baseline_doc({}, select=None), id="select-missing"),
    pytest.param(_baseline_doc({}, max_complexity=16), id="max-complexity-higher"),
    pytest.param(_baseline_doc({}, max_complexity=14), id="max-complexity-lower"),
    pytest.param(_baseline_doc({}, max_complexity="15"), id="max-complexity-string"),
    pytest.param(_baseline_doc({}, max_complexity=True), id="max-complexity-bool"),
    pytest.param(_baseline_doc({}, max_complexity=None), id="max-complexity-missing"),
    pytest.param({"fingerprints": {}}, id="both-missing"),
])
def test_check_mode_refuses_a_mismatched_baseline(monkeypatch, tmp_path, capsys, doc):
    """Test 7: a baseline not written with this script's SELECT / MAX_COMPLEXITY fails loudly, before ruff runs."""
    assert _run_main(monkeypatch, tmp_path, [], {}, doc=doc) == 2
    assert "ERROR: baseline mismatch" in capsys.readouterr().err


def test_check_mode_refuses_a_missing_baseline(monkeypatch, tmp_path, capsys):
    monkeypatch.setattr(ratchet.sys, "argv", ["ruff_ratchet.py", "--baseline", str(tmp_path / "absent.json")])
    monkeypatch.setattr(ratchet, "ROOT", str(tmp_path))
    monkeypatch.setattr(ratchet.subprocess, "run", lambda *a, **k: pytest.fail("ruff must not run"))
    assert ratchet.main() == 2
    assert "absent.json does not exist" in capsys.readouterr().err


def test_c901_noqa_does_not_hide_a_new_function(monkeypatch, tmp_path, capsys):
    """Test 6: `# noqa: C901` does not hide a new complex function (the ratchet runs ruff with --ignore-noqa)."""
    ruff = _pinned_ruff_or_skip()
    files = {"sample.py": _complex_source("hidden", noqa=True)}
    assert _run_main_real_ruff(monkeypatch, tmp_path, ruff, files, {}) == 1
    assert "+ sample.py|C901|hidden" in capsys.readouterr().out


def test_c901_real_ruff_message_yields_the_function_name(monkeypatch, tmp_path, capsys):
    """Test 8: real ruff's C901 message gives the bare function name (also for a method); the threshold is 15."""
    ruff = _pinned_ruff_or_skip()
    method = "class K:\n" + "".join(f"    {line}\n" for line in _complex_source("meth").splitlines())
    files = {"sample.py": _complex_source("busy") + "\n\n" + _complex_source("calm", branches=14),
             "methods.py": method}
    assert _run_main_real_ruff(monkeypatch, tmp_path, ruff, files, {}) == 1  # complexity 17 and 15
    out = capsys.readouterr().out
    assert "+ sample.py|C901|busy" in out and "+ methods.py|C901|meth" in out
    assert "calm" not in out  # complexity 15 is not above the threshold
    assert _run_main_real_ruff(monkeypatch, tmp_path, ruff, files,
                               {"sample.py|C901|busy": 1, "methods.py|C901|meth": 1}) == 0


@pytest.mark.parametrize("rel", ratchet.C901_EXCLUDED)
def test_c901_under_an_export_excluded_path_is_dropped(monkeypatch, tmp_path, capsys, rel):
    """Test 9: C901 under (or at) each C901_EXCLUDED path is not counted; F821 there still is.
    tests/test_release_onto.py checks C901_EXCLUDED against fresh_history.sh EXCLUDES in both directions."""
    path = tmp_path / rel if rel.endswith((".py", ".json", ".md")) else tmp_path / rel / "sub" / "x.py"
    monkeypatch.setattr(ratchet, "ROOT", str(tmp_path))
    kept, dropped = ratchet.drop_excluded_c901([_c901(path, "busy"), _f821(path, "nope")])
    assert dropped == 1 and [i["code"] for i in kept] == ["F821"]
    assert _run_main(monkeypatch, tmp_path, [_c901(path, "busy")], {}) == 0
    assert "not counted (C901 under paths the public export drops) 1" in capsys.readouterr().out


@pytest.mark.parametrize("rel", ["docsx/a.py", "doc/a.py", "src/docs/a.py", "scripts/release_x.py",
                                 "scripts/releases/a.py", "tests/test_release_onto_extra.py", "eval/cassettes2/a.py",
                                 "eval/run_child.py"])
def test_c901_excluded_paths_match_whole_components_only(monkeypatch, tmp_path, rel):
    monkeypatch.setattr(ratchet, "ROOT", str(tmp_path))
    assert ratchet.drop_excluded_c901([_c901(tmp_path / rel, "busy")])[1] == 0


# ------------------------------------------------------------------------------------------------ guard: lint baseline
def _doc(fingerprints, select="F821,F811,C901", max_complexity=15):
    doc = {"fingerprints": fingerprints}
    if select is not None:
        doc["select"] = select
    if max_complexity is not None:
        doc["max_complexity"] = max_complexity
    return json.dumps(doc)


LISTED = {"a.py|C901|busy": 1, "b.py|C901|other": 1}


def test_guard_accepts_an_unchanged_or_shrunk_baseline():
    assert guard.lint_problems(_doc(LISTED), _doc(LISTED)) == []
    assert guard.lint_problems(_doc(LISTED), _doc({"a.py|C901|busy": 1})) == []
    assert guard.lint_problems(None, _doc(LISTED)) == []  # first introduction of the file


@pytest.mark.parametrize("head, needle", [
    pytest.param(_doc({**LISTED, "c.py|C901|back": 1}), "'c.py|C901|back' grew 0 -> 1", id="re-added"),
    pytest.param(_doc({**LISTED, "a.py|C901|busy": 2}), "'a.py|C901|busy' grew 1 -> 2", id="count-1-to-2"),
    pytest.param(_doc(LISTED, max_complexity=16), "max_complexity raised 15 -> 16", id="threshold-raised"),
    pytest.param(_doc(LISTED, max_complexity=None), "max_complexity is None", id="threshold-missing"),
    pytest.param(_doc(LISTED, max_complexity="15"), "max_complexity is '15'", id="threshold-string"),
    pytest.param(_doc({}, select="F821,F811"), "select no longer includes C901", id="select-loses-C901"),
    pytest.param(_doc(LISTED, select=None), "select no longer includes C901", id="select-missing"),
])
def test_guard_refuses_growth_of_a_selected_code(head, needle):
    """Test 3 (guard half): every code in base `select` stays shrink-only; the threshold never goes up."""
    problems = guard.lint_problems(_doc(LISTED), head)
    assert any(needle in p for p in problems), problems


def test_guard_refuses_a_deleted_baseline():
    assert guard.lint_problems(_doc(LISTED), None)


def test_guard_accepts_a_lower_threshold():
    """A synthetic 15 -> 14 passes the guard (lowering N for real is a separate owner step: the script pins 15)."""
    assert guard.lint_problems(_doc(LISTED), _doc(LISTED, max_complexity=14)) == []


def _committed_baseline():
    with open(os.path.join(REPO, ".github", "lint-baseline.json"), encoding="utf-8") as fh:
        return fh.read()


@pytest.mark.parametrize("base", [
    pytest.param(_doc({}, select="F821,F811", max_complexity=None), id="base-selects-F821-F811"),
    pytest.param(json.dumps({"fingerprints": {}}), id="base-predates-select"),
])
def test_guard_seeding_a_newly_selected_code(base):
    """Test 4 (plan H1): the committed seeding baseline (C901 entries, base without C901) is accepted; a new F821 in
    the same head is not; nor is an entry of a code the head does not select."""
    head = json.loads(_committed_baseline())
    c901 = [k for k in head["fingerprints"] if k.split("|")[1] == "C901"]
    assert c901 and head["select"] == "F821,F811,C901" and head["max_complexity"] == 15
    assert guard.lint_problems(base, json.dumps(head)) == []
    with_f821 = dict(head, fingerprints={**head["fingerprints"], "src/app.py|F821|nope": 1})
    assert guard.lint_problems(base, json.dumps(with_f821)) == [f"{guard.LINT}: 'src/app.py|F821|nope' grew 0 -> 1"]
    unselected = dict(head, fingerprints={**head["fingerprints"], "src/app.py|E501|x": 1})
    assert any("'src/app.py|E501|x' grew 0 -> 1" in p for p in guard.lint_problems(base, json.dumps(unselected)))


def test_guard_seeds_only_once():
    """A second C901 seeding against a base that already selects C901 is refused."""
    head = _committed_baseline()
    base = _doc({}, select="F821,F811,C901", max_complexity=15)
    problems = guard.lint_problems(base, head)
    assert problems and all("C901" in p and "grew 0 -> 1" in p for p in problems)


def test_guard_pipe_in_path_never_seeds():
    """Code review F1: a tracked path holding '|' shifts the segments; such a fingerprint is never read as a seed."""
    base = _doc({}, select="F821,F811", max_complexity=None)
    head = _doc({"apps/atk|F822|x/a.py|C901|busy_pipe": 1}, select="F821,F811,F822", max_complexity=15)
    assert guard.lint_problems(base, head) == [f"{guard.LINT}: 'apps/atk|F822|x/a.py|C901|busy_pipe' grew 0 -> 1"]


def test_guard_refuses_a_base_that_is_not_a_commit(monkeypatch, capsys):
    """Code review F2: an unknown --base fails closed (exit 2) instead of skipping every check."""
    monkeypatch.setattr(sys, "argv", ["allowlist_guard.py", "--base", "0000000000000000000000000000000000000bad"])
    assert guard.main() == 2
    assert "BASE_NOT_FOUND" in capsys.readouterr().out
