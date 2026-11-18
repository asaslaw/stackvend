"""
.github/scripts/ruff_ratchet.py: which F811 findings the CI ratchet does not count.

Only a parameter or function-local assignment shadowing a module-level import is skipped, decided from ruff's location
and the file's AST. The hand-written findings below pin the rule; the last test runs the real ruff (when it is on PATH)
so the location contract between ruff's JSON and ``ast`` is proven too.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import json
import os
import shutil
import subprocess
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


def _run_main(monkeypatch, tmp_path, findings, baseline):
    """main() with `git ls-files` and ruff replaced by their canned output."""
    base = tmp_path / "baseline.json"
    base.write_text(json.dumps({"fingerprints": baseline}), encoding="utf-8")

    def fake_run(cmd, **_kwargs):
        return types.SimpleNamespace(stdout="x.py\0" if cmd[0] == "git" else json.dumps(findings))

    monkeypatch.setattr(ratchet.subprocess, "run", fake_run)
    monkeypatch.setattr(ratchet.sys, "argv", ["ruff_ratchet.py", "--baseline", str(base)])
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
