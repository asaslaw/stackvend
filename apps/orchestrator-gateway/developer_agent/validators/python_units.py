"""AC-1: one PY.SYNTAX finding per broken top-level unit of a Python file (read-only; nothing is rewritten).

CPython's `compile` stops at the first syntax error of a file, so a file with three broken test functions used to
yield one finding with the same fingerprint before and after a repair that fixed one of them (10-14 03-r2:
`NO_IMPROVEMENT` x2, three correct partial fixes discarded). Here, only for a file that does not compile:

1. The token stream (`tokenize`, CPython's own tokenizer) is cut into top-level units: a unit starts at each logical
   line that begins in column 0 (see _logical_lines); decorator lines stay with the `def`/`class` they decorate, and
   the grammar keywords `else`/`elif`/`except`/`finally` stay with the statement they continue.
2. Each unit is compiled on its own (`compile`, line numbers kept by padding with newlines; the file's
   `from __future__` flags are passed on).
3. One finding per unit that does not compile. Its `symbol` is the unit's `def`/`class` name (the k-th unit of a
   repeated name is `name#k`), or MODULE_STATEMENT_SYMBOL for any other top-level statement (all such statements of a
   file share it: an ordinal would make every inserted statement look new); `fingerprint()` includes `symbol`, so the finding set
   shrinks when a repair fixes one unit of several.

Fallback to the single whole-file finding (today's diagnostic, `symbol` None) when `tokenize` fails (unterminated
string, unclosed bracket), when an error spans units (the whole-file error does not lie in a unit that fails on its
own, or a failing unit's error moves into the next unit when the two are compiled together), or on any unexpected
exception (PythonSyntaxValidator). The unit holding the whole-file error always reports that exact error (line,
column, message, text), so a file with one broken unit yields today's diagnostic plus a `symbol`, and the repair
prompt (which does not render `symbol`) is byte-identical.
"""
from __future__ import annotations

import __future__ as _future
import io
import tokenize
from dataclasses import dataclass
from typing import List, Optional, Tuple

MODULE_STATEMENT_SYMBOL = "<module>"            # a broken top-level statement that is not a def/class
CONTINUATION_KEYWORDS = frozenset({"else", "elif", "except", "finally"})
_SKIP = frozenset({tokenize.NL, tokenize.COMMENT, tokenize.ENCODING, tokenize.ENDMARKER, tokenize.INDENT,
                   tokenize.DEDENT})


@dataclass(frozen=True)
class Unit:
    start: int      # first line, 1-based
    end: int        # last line, inclusive (the line before the next unit, or the file's last line)
    symbol: str


def _readlines(source: str) -> List[str]:
    # universal newlines, so line numbers match compile()'s (which also ends a line at a bare "\r")
    return io.StringIO(source, newline=None).readlines()


_INDENT_CHARS = " \t\f"


def _logical_lines(lines: List[str]) -> List[Tuple[bool, List[tokenize.TokenInfo]]]:
    """(starts at column 0?, tokens) of every logical line; raises when tokenize does.

    The tokenizer reads a copy of the lines with their leading whitespace removed: string, bracket, comment and
    backslash-continuation boundaries do not depend on indentation, and the broken construct this exists for (an
    unparenthesized `with a,` whose continuation line is indented deeper than the body) makes CPython's indentation
    tracking raise IndentationError for the whole file. Whether a logical line is top-level is read from the
    ORIGINAL line its first token is on (column 0 = no leading whitespace). The copy is analysed only; nothing that is
    reported or returned is rewritten."""
    stripped = iter([ln.lstrip(_INDENT_CHARS) for ln in lines])
    out: List[Tuple[bool, List[tokenize.TokenInfo]]] = []
    cur: List[tokenize.TokenInfo] = []
    for tok in tokenize.generate_tokens(lambda: next(stripped, "")):
        if tok.type == tokenize.NEWLINE:
            if cur:
                out.append((lines[cur[0].start[0] - 1][:1] not in _INDENT_CHARS, cur))
            cur = []
        elif tok.type not in _SKIP:
            cur.append(tok)
    if cur:
        out.append((lines[cur[0].start[0] - 1][:1] not in _INDENT_CHARS, cur))
    return out


def _def_name(toks: List[tokenize.TokenInfo]) -> Optional[str]:
    names = [t for t in toks[:3] if t.type == tokenize.NAME]
    if len(names) >= 2 and names[0].string in ("def", "class"):
        return names[1].string
    if len(names) >= 3 and names[0].string == "async" and names[1].string == "def":
        return names[2].string
    return None


def top_level_units(source: str) -> Optional[List[Unit]]:
    """The file's top-level units in order, or None when the token stream cannot be read."""
    lines = _readlines(source)
    try:
        logical = _logical_lines(lines)
    except (tokenize.TokenError, SyntaxError):   # IndentationError is a SyntaxError
        return None
    heads: List[List] = []   # [start line, symbol or None, decorators only?]
    for top, toks in logical:
        if not top:
            continue
        first = toks[0]
        decorator = first.type == tokenize.OP and first.string == "@"
        if heads and heads[-1][2]:                                   # the def/class a decorator belongs to
            if not decorator:
                heads[-1][1], heads[-1][2] = _def_name(toks), False
            continue
        if heads and first.type == tokenize.NAME and first.string in CONTINUATION_KEYWORDS:
            continue
        heads.append([first.start[0], None if decorator else _def_name(toks), decorator])
    units, seen = [], {}
    for i, (start, name, _) in enumerate(heads):
        end = heads[i + 1][0] - 1 if i + 1 < len(heads) else max(len(lines), start)
        symbol = name or MODULE_STATEMENT_SYMBOL
        if name:   # Fable RT F2: the k-th def/class of the same name is `name#k` (k >= 2); `<module>` stays shared
            seen[name] = seen.get(name, 0) + 1
            symbol = name if seen[name] == 1 else f"{name}#{seen[name]}"
        units.append(Unit(start, end, symbol))
    return units


def _future_flags(lines: List[str], units: List[Unit]) -> int:
    flags = 0
    for u in units:
        try:
            toks = [t for _, ts in _logical_lines(lines[u.start - 1:u.end]) for t in ts]
        except (tokenize.TokenError, SyntaxError):
            continue
        if len(toks) < 4 or [t.string for t in toks[:3]] != ["from", "__future__", "import"]:
            continue
        for t in toks[3:]:
            feature = getattr(_future, t.string, None) if t.type == tokenize.NAME else None
            if isinstance(feature, _future._Feature):
                flags |= feature.compiler_flag
    return flags


def unit_at(units: List[Unit], line: Optional[int]) -> Optional[Unit]:
    """The unit holding `line` (a line past the end of the file belongs to the last unit)."""
    if not line:
        return None
    found = None
    for u in units:
        if u.start <= line:
            found = u
    return found


def _compile_error(lines: List[str], start: int, end: int, path: str, flags: int) -> Optional[SyntaxError]:
    """compile() of lines start..end (1-based, inclusive) on their own, at their own line numbers."""
    try:
        compile("\n" * (start - 1) + "".join(lines[start - 1:end]), path, "exec", flags=flags, dont_inherit=True)
    except SyntaxError as e:
        return e
    return None


def broken_units(source: str, path: str, whole_file_error: SyntaxError) -> Optional[List[Tuple[Unit, SyntaxError]]]:
    """Every top-level unit that does not compile on its own, with its error; the unit holding the whole-file error
    carries that exact error. None -> report the single whole-file finding (see the module docstring).

    A failing unit's error must be its own: compiled together with the next unit, the first error must still lie in
    it. Otherwise the statement continues into the next unit (e.g. `try:` whose `except` is misspelled, so the
    `except` line starts a new unit) and the file falls back to the whole-file finding, as before AC-1."""
    units = top_level_units(source)
    if not units:
        return None
    lines = _readlines(source)
    flags = _future_flags(lines, units)
    primary = unit_at(units, whole_file_error.lineno)
    out: List[Tuple[Unit, SyntaxError]] = []
    for i, u in enumerate(units):
        e = _compile_error(lines, u.start, u.end, path, flags)
        if e is None:
            continue
        if i + 1 < len(units):
            nxt = units[i + 1]
            joint = _compile_error(lines, u.start, nxt.end, path, flags)
            if joint is None or (joint.lineno or 0) >= nxt.start:
                return None
        out.append((u, whole_file_error if u == primary else e))
    if primary is None or all(u != primary for u, _ in out):
        return None
    return out


__all__ = ["MODULE_STATEMENT_SYMBOL", "Unit", "broken_units", "top_level_units", "unit_at"]
