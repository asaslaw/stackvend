"""module_inspector._extract_blocks on python-hcl2 (cc-module-inspector-parser; follow-up to FD-4Y HB-02).

The old extractor (a `variable|output "x" {` regex plus brace counting over comment-stripped text) is kept below,
frozen, as the Do No Harm oracle: on every golden module, every embedded payload and the real generated fixtures the
new extractor must return exactly what the old one returned. The other tests pin what the parser fixes and the
fail-closed rule for text python-hcl2 cannot read.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import hashlib
import os
import re
import sys
from pathlib import Path
from typing import List, Tuple

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from shared import module_inspector as MI  # noqa: E402
from shared.builtin_modules_payload import BUILTIN_MODULE_FILES  # noqa: E402

FIXTURES = REPO / "tests" / "fixtures" / "cc_module_inspector"
COPIES = ("shared/module_inspector.py", "apps/control-center/shared/module_inspector.py",
          "apps/orchestrator-gateway/shared/module_inspector.py", "mcp-servers/terraform/shared/module_inspector.py")
MODULE_ROOTS = ("infra/modules", "apps/control-center/infra/modules")


# ------------------------------------------------------------------ frozen legacy oracle (main aeeb403, test-only)
def _legacy_extract_blocks(hcl_text: str, block_type: str) -> List[Tuple[str, str]]:
    results: List[Tuple[str, str]] = []
    pattern = re.compile(rf'{block_type}\s+"([^"]+)"\s*\{{')
    pos = 0
    while True:
        match = pattern.search(hcl_text, pos)
        if not match:
            break
        block_name = match.group(1)
        start_brace = match.end() - 1
        brace_count = 1
        i = start_brace + 1
        body_start = i
        in_string = False
        escape = False
        while i < len(hcl_text) and brace_count > 0:
            char = hcl_text[i]
            if in_string:
                if escape:
                    escape = False
                elif char == '\\':
                    escape = True
                elif char == '"':
                    in_string = False
            else:
                if char == '"':
                    in_string = True
                elif char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
            i += 1
        if brace_count == 0:
            results.append((block_name, hcl_text[body_start:i - 1].strip()))
            pos = i
        else:
            pos = match.end()
    return results


def _legacy_blocks(raw: str, block_type: str) -> List[Tuple[str, str]]:
    """What the old parse_hcl_variables_and_outputs fed its field regexes: strip comments, then extract."""
    return _legacy_extract_blocks(MI._strip_hcl_comments(raw or ""), block_type)


def _legacy_parse(variables_hcl, outputs_hcl=None):
    """The old parse_hcl_variables_and_outputs: same field code, legacy block extraction."""
    real = MI._extract_blocks
    MI._extract_blocks = lambda text, kind: _legacy_blocks(text, kind)
    try:
        return MI.parse_hcl_variables_and_outputs(variables_hcl, outputs_hcl)
    finally:
        MI._extract_blocks = real


# ------------------------------------------------------------------ corpora
def _golden_tf_files():
    out = []
    for root in MODULE_ROOTS:
        for p in sorted((REPO / root).rglob("*.tf")):
            out.append(pytest.param(p.read_text(encoding="utf-8"), id=str(p.relative_to(REPO))))
    return out


def _payload_tf_files():
    return [pytest.param(text, id=f"payload:{mod}/{name}")
            for mod, files in sorted(BUILTIN_MODULE_FILES.items()) for name, text in sorted(files.items())
            if name.endswith(".tf")]


def _fixture_tf_files():
    return [pytest.param(p.read_text(encoding="utf-8"), id=f"fixture:{p.name}") for p in sorted(FIXTURES.glob("*.tf"))]


ALL_REAL = _golden_tf_files() + _payload_tf_files() + _fixture_tf_files()

# Real inputs where the OLD output was wrong: a `#` or `//` inside a string literal made the old comment stripper
# (R-28) cut the line, the brace counter lost the block's end, and whole blocks were dropped or merged. The parser
# finds every block; the stripper still truncates that string inside its own block's body (R-28, separate row).
# Every other real input must be identical to the old extractor; this list may only shrink.
KNOWN_LEGACY_DAMAGE = {
    "infra/modules/compute-gce-worker/variables.tf",                    # startup_script: "#!/bin/bash\n# ..."
    "apps/control-center/infra/modules/compute-gce-worker/variables.tf",
    "payload:compute-gce-worker/variables.tf",
    "fixture:custom-22a00f972f3e.tf",                                    # default = "https://..."
}


def _ids(params):
    return [p.id for p in params]


def _neutralize_comment_markers_in_strings(text: str) -> str:
    """Replace `#` and `/` inside string literals and heredocs (positions from the parse tree) with `_`, same length:
    the input the old stripper could not damage."""
    chars = list(text)
    for sub in MI._hcl_tree(text).iter_subtrees():
        if sub.data in ("string_part", "heredoc_template", "heredoc_template_trim"):
            for tok in sub.children:
                for i in range(getattr(tok, "start_pos", 0), getattr(tok, "end_pos", 0)):
                    if chars[i] in "#/":
                        chars[i] = "_"
    return "".join(chars)


def test_corpus_is_not_empty():
    assert len(_golden_tf_files()) >= 2 * 24 * 3
    assert len(_payload_tf_files()) >= 24
    assert len(_fixture_tf_files()) == 4
    assert KNOWN_LEGACY_DAMAGE <= set(_ids(ALL_REAL))


# ------------------------------------------------------------------ Do No Harm: identical on every real input
@pytest.mark.parametrize("text", [p for p in ALL_REAL if p.id not in KNOWN_LEGACY_DAMAGE])
def test_blocks_identical_to_legacy(text):
    for kind in ("variable", "output"):
        assert MI._extract_blocks(text, kind) == _legacy_blocks(text, kind)


@pytest.mark.parametrize("text", [p for p in ALL_REAL if p.id in KNOWN_LEGACY_DAMAGE])
def test_known_legacy_damage_still_differs(text):
    """Keeps KNOWN_LEGACY_DAMAGE exact: an entry the old extractor got right must be removed from it."""
    assert any(MI._extract_blocks(text, k) != _legacy_blocks(text, k) for k in ("variable", "output"))


@pytest.mark.parametrize("text", ALL_REAL)
def test_blocks_identical_to_legacy_without_comment_markers_in_strings(text):
    """Every real input, including KNOWN_LEGACY_DAMAGE: once no string holds a `#` or `//`, old == new exactly."""
    neutral = _neutralize_comment_markers_in_strings(text)
    for kind in ("variable", "output"):
        assert MI._extract_blocks(neutral, kind) == _legacy_blocks(neutral, kind)


def test_gce_worker_gains_its_startup_script_variable():
    text = (REPO / "infra/modules/compute-gce-worker/variables.tf").read_text(encoding="utf-8")
    old = [n for n, _ in _legacy_blocks(text, "variable")]
    new = [n for n, _ in MI._extract_blocks(text, "variable")]
    assert "startup_script" not in old and "startup_script" in new
    assert [n for n in new if n != "startup_script"] == old  # nothing else moved or disappeared
    inputs, _ = MI.parse_hcl_variables_and_outputs(text, "")
    startup = next(i for i in inputs if i["name"] == "startup_script")
    assert startup["required"] is False and startup["type"] == "string"


@pytest.mark.parametrize("text", ALL_REAL)
def test_crlf_and_bom_do_not_change_the_result(text):
    """python-hcl2 rejects CRLF and a BOM, so the extractor normalizes both; the old extractor's output did not
    depend on them either (its comment stripper re-joined lines with \\n)."""
    crlf = "\ufeff" + text.replace("\n", "\r\n")
    for kind in ("variable", "output"):
        assert MI._extract_blocks(crlf, kind) == MI._extract_blocks(text, kind)
        assert _legacy_blocks(crlf, kind) == _legacy_blocks(text, kind)


def _module_dirs():
    out = []
    for root in MODULE_ROOTS:
        for d in sorted(p for p in (REPO / root).iterdir() if p.is_dir()):
            files = {f.name: f.read_text(encoding="utf-8") for f in d.glob("*.tf")}
            out.append(pytest.param(files, id=str(d.relative_to(REPO))))
    for mod, files in sorted(BUILTIN_MODULE_FILES.items()):
        out.append(pytest.param(dict(files), id=f"payload:{mod}"))
    return out


@pytest.mark.parametrize("files", _module_dirs())
def test_module_contract_identical_to_legacy(files, request):
    """The contract the CC catalog shows (and stores for custom modules): every golden module, dir and payload.
    compute-gce-worker is the one KNOWN_LEGACY_DAMAGE module: identical except the restored startup_script input."""
    var_code = files.get("variables.tf", "") or files.get("main.tf", "")
    out_code = files.get("outputs.tf", "")
    new = MI.parse_hcl_variables_and_outputs(var_code, out_code)
    old = _legacy_parse(var_code, out_code)
    if "compute-gce-worker" in request.node.callspec.id:
        new = ([i for i in new[0] if i["name"] != "startup_script"], new[1])
    assert new == old
    assert MI.parse_hcl_variables_and_outputs(files)[1] == _legacy_parse(files)[1]  # dict form (outputs)
    if files.get("variables.tf"):
        assert new[0], "a golden module with a variables.tf must expose inputs"


def test_builtin_catalog_identical_to_legacy():
    from shared import builtin_modules_provider as BMP
    new = BMP.get_builtin_modules(force_refresh=True)
    real = BMP.parse_hcl_variables_and_outputs
    BMP.parse_hcl_variables_and_outputs = _legacy_parse
    try:
        old = BMP.get_builtin_modules(force_refresh=True)
    finally:
        BMP.parse_hcl_variables_and_outputs = real
        BMP.get_builtin_modules(force_refresh=True)
    assert len(new) == len(old) >= 24
    for n, o in zip(new, old):
        n_inputs = [i for i in n["inputs"] if not (n["module_id"] == "compute-gce-worker" and i["name"] == "startup_script")]
        assert (n["module_id"], n_inputs, n["outputs"]) == (o["module_id"], o["inputs"], o["outputs"])


@pytest.fixture
def _restore_builtin_cache():
    from shared import builtin_modules_provider as BMP
    yield BMP
    BMP._BUILTIN_CACHE = None


def test_builtin_catalog_contains_one_unreadable_module(tmp_path, monkeypatch, _restore_builtin_cache):
    """Row CC-MI-2: a built-in whose files cannot be parsed is listed as ERROR with no contract (never the minimal
    project_id/region placeholder); every other module is listed exactly as before."""
    import shutil
    BMP = _restore_builtin_cache
    good = {m["module_id"]: m for m in BMP.get_builtin_modules(force_refresh=True)}
    mods = tmp_path / "modules"
    shutil.copytree(REPO / "infra" / "modules", mods)
    (mods / "storage-bucket" / "variables.tf").write_text('variable "x" {\n  default = \n}\n', encoding="utf-8")
    monkeypatch.setattr(BMP, "get_platform_modules_path", lambda: str(mods))
    got = {m["module_id"]: m for m in BMP.get_builtin_modules(force_refresh=True)}
    assert list(got) == list(good)
    bad = got.pop("storage-bucket")
    assert bad["sync_status"] == "ERROR" and "ModuleContractUnparseable" in bad["error_message"]
    assert bad["inputs"] == bad["variables"] == bad["outputs"] == []
    good.pop("storage-bucket")
    assert all("error_message" not in m and m["sync_status"] == "VERIFIED" for m in got.values())
    assert got == good  # Do No Harm: the other modules' records are unchanged


def test_builtin_catalog_without_the_parser_lists_every_module_as_error(monkeypatch, _restore_builtin_cache):
    BMP = _restore_builtin_cache
    monkeypatch.setitem(sys.modules, "hcl2.parser", None)
    got = BMP.get_builtin_modules(force_refresh=True)
    assert len(got) == len(BMP.BUILTIN_MODULE_METADATA)
    assert {m["sync_status"] for m in got} == {"ERROR"} and all(m["inputs"] == [] for m in got)
    assert all("HclUnavailable" in m["error_message"] for m in got)


def test_fixture_provenance():
    """Real generated files (10-18 Gate A / Gate B / FDCSQL tree snapshots), stored under their content sha256 prefix.
    variables-4c57fff0d419.tf is FDCSQL 08-r1 infra/workload/variables.tf (cassette blob 6e3208140189) with line 21
    redacted: the GitHub org in the github_repo_full_name default is replaced by "example-org" (no owner identifiers
    in the repo, tests/test_fd12_owner_identifiers.py), so it no longer matches the cassette tree maps."""
    for p in FIXTURES.glob("*.tf"):
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        assert p.stem.endswith(digest[:12]), p.name


# ------------------------------------------------------------------ what the parser fixes
def test_heredoc_braces_no_longer_swallow_the_next_block():
    text = ('variable "a" {\n  default = <<EOT\n{ not closed\nEOT\n}\n\n'
            'variable "b" {\n  type = string\n}\n')
    assert _legacy_blocks(text, "variable") != MI._extract_blocks(text, "variable")
    assert [n for n, _ in MI._extract_blocks(text, "variable")] == ["a", "b"]
    assert MI._extract_blocks(text, "variable")[1] == ("b", "type = string")


def test_block_text_inside_a_heredoc_is_not_a_block():
    text = ('locals {\n  doc = <<EOT\nvariable "ghost" {\n}\nEOT\n}\n\nvariable "a" {\n  type = string\n}\n')
    assert [n for n, _ in _legacy_blocks(text, "variable")] == ["ghost", "a"]
    assert [n for n, _ in MI._extract_blocks(text, "variable")] == ["a"]


def test_nested_block_named_like_the_kind_is_not_top_level():
    text = 'resource "x" "y" {\n  output "inner" {\n    v = 1\n  }\n}\noutput "real" {\n  value = 1\n}\n'
    assert [n for n, _ in _legacy_blocks(text, "output")] == ["inner", "real"]
    assert [n for n, _ in MI._extract_blocks(text, "output")] == ["real"]


def test_double_slash_in_a_string_no_longer_breaks_block_boundaries():
    """The comment stripper still truncates `//` inside a string (R-28, separate row), but only inside that block's
    own body now: it can no longer eat the closing brace and merge the following blocks."""
    text = 'output "a" { value = "x // y" }\noutput "b" {\n  description = "B"\n}\n'
    assert [n for n, _ in MI._extract_blocks(text, "output")] == ["a", "b"]
    assert MI._extract_blocks(text, "output")[1] == ("b", 'description = "B"')


def test_unquoted_label_is_read():
    """`variable foo {}` is valid HCL native syntax; the old regex required quotes and dropped the variable."""
    text = 'variable foo {\n  type = number\n}\n'
    assert _legacy_blocks(text, "variable") == []
    assert MI._extract_blocks(text, "variable") == [("foo", "type = number")]


# ------------------------------------------------------------------ fail closed: never a partial or empty contract
@pytest.mark.parametrize("text", ["", "   \n\t\n", None, "# only a comment\n", "/* c */\n", 'locals {\n  a = 1\n}\n'])
def test_no_blocks(text):
    assert MI._extract_blocks(text, "variable") == []


def test_syntax_error_raises_for_the_whole_file():
    text = 'variable "ok" {\n  type = string\n}\n\nvariable "broken" {\n  default = \n}\n'
    assert [n for n, _ in _legacy_blocks(text, "variable")] == ["ok", "broken"]  # the old partial guess
    with pytest.raises(MI.ModuleContractUnparseable):
        MI._extract_blocks(text, "variable")
    with pytest.raises(MI.ModuleContractUnparseable):
        MI.parse_hcl_variables_and_outputs(text, "")
    with pytest.raises(MI.ModuleContractUnparseable):  # an unparseable outputs.tf fails the contract too
        MI.parse_hcl_variables_and_outputs('variable "ok" {}\n', 'output "o" {\n  value = \n}\n')


@pytest.mark.parametrize("bad", ['variable {\n  type = string\n}\n', 'variable "a" "b" {\n}\n'])
def test_terraform_invalid_label_count_raises_for_the_whole_file(bad):
    good = 'variable "ok" {\n  type = string\n}\n'
    with pytest.raises(MI.ModuleContractUnparseable):
        MI._extract_blocks(good + bad, "variable")
    assert MI._extract_blocks(good, "variable") == [("ok", "type = string")]  # Do No Harm: valid file alone
    assert MI._extract_blocks(good + bad, "output") == []  # only the requested kind is checked


@pytest.mark.parametrize("value", ["(\n    var.a\n    ? 1\n    : 2\n  )", "1 /* c */ + 2"])
def test_known_python_hcl2_gaps_fail_closed(value):
    # Valid HCL (tofu fmt -check rc 0) that python-hcl2 7.3.1 rejects: refused, never partially read (row CC-MI-1).
    with pytest.raises(MI.ModuleContractUnparseable):
        MI._extract_blocks(f'output "o" {{\n  value = {value}\n}}\n', "output")


def test_unparseable_is_a_value_error():
    """Every CC caller already turns a ValueError from the inspector into a 400 / sync_status ERROR."""
    assert issubclass(MI.ModuleContractUnparseable, ValueError)


def test_missing_parser_is_typed(monkeypatch):
    monkeypatch.setitem(sys.modules, "hcl2.parser", None)
    with pytest.raises(MI.HclUnavailable):
        MI._extract_blocks('variable "a" {}\n', "variable")
    assert MI._extract_blocks("", "variable") == []  # nothing to parse: no parser needed


def test_github_module_inspection_fails_closed(monkeypatch):
    class _Provider:
        def fetch_file_content(self, repo, path, branch=None):
            return 'variable "a" {\n  default = \n}\n' if path.endswith("variables.tf") else ""

    import shared.vcs_provider as vcs
    monkeypatch.setattr(vcs.VCSProviderFactory, "get_provider", staticmethod(lambda *_a, **_k: _Provider()))
    with pytest.raises(MI.ModuleContractUnparseable):
        MI.fetch_and_inspect_github_module("acme/mods", "m", "main")


# ------------------------------------------------------------------ replicas
@pytest.mark.parametrize("name", ["module_inspector.py", "builtin_modules_provider.py"])
def test_all_copies_are_byte_identical(name):
    copies = [c.replace("module_inspector.py", name) for c in COPIES]
    digests = {c: hashlib.sha256((REPO / c).read_bytes()).hexdigest() for c in copies}
    assert len(set(digests.values())) == 1, digests


@pytest.mark.parametrize("service", ["apps/control-center", "apps/orchestrator-gateway", "mcp-servers/terraform"])
def test_every_shipping_service_declares_the_parser(service):
    reqs = (REPO / service / "requirements.txt").read_text(encoding="utf-8")
    pins = {line.split("#")[0].strip() for line in reqs.splitlines()}
    assert {"python-hcl2==7.3.1", "lark==1.2.2", "regex==2026.9.29"} <= pins
