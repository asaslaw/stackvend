"""Healer probe targets from docs/planning/review/HEALERS.md (plan §4, red-team H2).

HEALERS.md is the inventory of record (166 rows, IDs HA-/HB-/HC-/HD-/HE-). Its Location(s) column holds
backticked fragments such as `terraform_engine.py:extract_hcl_blocks:367-425`, `handler.py:1620-1627` or
`self_correct_hcl:1977-1997`, with line numbers taken at INVENTORY_SHA. This module parses that fixed table
format (it is measurement tooling reading a document, not a product heuristic), resolves each fragment against
the inventory checkout with the `ast` module, and classifies it:

  function    the fragment is a whole callable -> wrapped by identity binding (healer_probe)
  inline      a line range inside a larger function -> counted with sys.monitoring LINE events
  apply_time  mcp-servers/terraform (not loaded on the generation path; Tier 2)
  not_loaded  generation-adjacent code the harness does not import (gateway main.py)
  out_of_scope scripts/, infra/, other apps
  unresolved  could not be resolved at the inventory SHA (reported, never silently dropped)

anchor_to() re-anchors inventory line ranges onto the product root being measured using difflib equal blocks
(not text search); a range that falls in a changed region is reported as anchor_lost.

Fresh-history safety (OSS blocker 1a): the run-time anchoring does not read the inventory commit from git. The
inventory side of each inline fragment's file is vendored as per-line content digests in
eval/config/inventory_line_digests.json (written by eval/tools/build_targets.py next to healer_targets.json), so a
clone without INVENTORY_SHA (a fresh single-commit public history, or a shallow CI checkout) anchors exactly as a
full clone does. difflib's matching blocks depend only on which lines are equal, so comparing digests gives the same
line map as comparing the lines themselves.
"""
from __future__ import annotations

import ast
import difflib
import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple, Union

INVENTORY_SHA = "6cd83b0"  # HEALERS.md line numbers match this commit (verified on def lines, 2026-10-12)
GATEWAY = "apps/orchestrator-gateway/"
HCL_UTILS_REPLICAS = [  # AGENTS.md "Replicated files"
    "shared/hcl_utils.py",
    "apps/orchestrator-gateway/shared/hcl_utils.py",
    "apps/orchestrator-gateway/developer_agent/hcl_utils.py",
    "mcp-servers/terraform/hcl_utils.py",
    "mcp-servers/terraform/shared/hcl_utils.py",
]
APPLY_TIME_PREFIXES = ("mcp-servers/terraform/",)
NOT_LOADED = ("apps/orchestrator-gateway/main.py",)

_ROW = re.compile(r"^\|\s*(H[A-E]-\d+)\s*\|(.*?)\|")
_FRAG = re.compile(r"`([^`]+)`(\s*\(×\d+\))?")
_LINES = re.compile(r"^~?\d+(\s*-\s*\d+)?(\s*,\s*~?\d+(\s*-\s*\d+)?)*$")
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*$")
_FILE_EXTS = (".py", ".sh", ".tf", ".yaml", ".yml", ".json", ".html")
# HEALERS.md conventions (see its header): bare `service.py` means the terraform MCP server; `hcl_utils` rows
# apply to every replica listed in AGENTS.md.
BARE_NAME_DEFAULTS = {"service.py": "mcp-servers/terraform/service.py"}


@dataclass
class Fragment:
    healer_id: str
    tier: str
    raw: str
    file: Optional[str] = None            # repo-relative
    qualname: Optional[str] = None        # function or Class.method at the inventory SHA
    lines: List[Tuple[int, int]] = field(default_factory=list)  # inventory-SHA line ranges
    approx: bool = False
    kind: str = "unresolved"
    module: Optional[str] = None          # import name inside the generation child (gateway-relative)
    enclosing: Optional[str] = None       # inline: qualname of the enclosing function
    note: Optional[str] = None

    def key(self) -> str:
        loc = f"{self.file}:{self.qualname or self.enclosing or ''}:{','.join(f'{a}-{b}' for a, b in self.lines)}"
        return f"{self.healer_id}@{loc}"


def parse_rows(md: str) -> List[Tuple[str, str]]:
    rows = []
    for line in md.splitlines():
        m = _ROW.match(line)
        if m:
            rows.append((m.group(1), m.group(2)))
    return rows


def _parse_lines(text: str) -> Tuple[List[Tuple[int, int]], bool]:
    approx = "~" in text
    out = []
    for part in text.replace("~", "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            out.append((int(a), int(b)))
        else:
            out.append((int(part), int(part)))
    return out, approx


def split_fragment(frag: str) -> Tuple[Optional[str], Optional[str], str]:
    """-> (path_hint, qualname, lines_text). Accepts path:func:lines, path:lines, func:lines, mod.func:lines."""
    frag = frag.strip()
    parts = [p.strip() for p in frag.split(":")]
    path = None
    if parts and (parts[0].endswith(_FILE_EXTS) or ("/" in parts[0] and "." in parts[0].rsplit("/", 1)[-1])):
        path, parts = parts[0], parts[1:]
    elif parts and "." in parts[0] and _IDENT.match(parts[0]) and not _LINES.match(parts[0]):
        head, _, tail = parts[0].partition(".")
        # `hcl_utils.fn` / `preflight_validator.self_correct_hcl` shorthand (module.function)
        if tail and head[:1].islower() and head not in ("self",):
            path = head + ".py"
            parts = [tail] + parts[1:]
    qual = None
    lines_text = ""
    for p in parts:
        if not p:
            continue
        if _LINES.match(p):
            lines_text = p
        elif _IDENT.match(p) and qual is None:
            qual = p
    return path, qual, lines_text


def _defs(source: str) -> Dict[str, Tuple[int, int]]:
    """qualname -> (start_line incl. decorators, end_line) for every def/async def/class-method."""
    out: Dict[str, Tuple[int, int]] = {}
    tree = ast.parse(source)

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = f"{prefix}{child.name}"
                start = min([d.lineno for d in child.decorator_list] + [child.lineno])
                out.setdefault(q, (start, child.end_lineno or child.lineno))
                visit(child, q + ".<locals>.")
            elif isinstance(child, ast.ClassDef):
                visit(child, f"{prefix}{child.name}.")
    visit(tree, "")
    return out


def _innermost(defs: Dict[str, Tuple[int, int]], line: int) -> Optional[str]:
    best = None
    for q, (s, e) in defs.items():
        if s <= line <= e and (best is None or (s >= defs[best][0] and e <= defs[best][1])):
            best = q
    return best


def _module_name(path: str) -> Optional[str]:
    if not path.startswith(GATEWAY):
        return None
    return path[len(GATEWAY):-3].replace("/", ".")


def resolve(rows: List[Tuple[str, str]], read_file: Callable[[str], Optional[str]],
            list_files: Callable[[], List[str]]) -> List[Fragment]:
    """read_file/list_files operate on the INVENTORY_SHA tree (repo-relative paths)."""
    all_py = [p for p in list_files() if p.endswith(".py")]
    defs_cache: Dict[str, Dict[str, Tuple[int, int]]] = {}

    def defs_of(path: str) -> Dict[str, Tuple[int, int]]:
        if path not in defs_cache:
            src = read_file(path)
            try:
                defs_cache[path] = _defs(src) if src is not None else {}
            except SyntaxError:
                defs_cache[path] = {}
        return defs_cache[path]

    def candidates(hint: Optional[str], qual: Optional[str]) -> List[str]:
        if hint:
            hint = hint.lstrip("/")
            if hint in BARE_NAME_DEFAULTS:
                return [BARE_NAME_DEFAULTS[hint]]
            if not hint.endswith(".py"):
                return [hint]  # shell/HCL/YAML: out of scope for the in-process probe
            c = [p for p in all_py if p == hint or p.endswith("/" + hint)]
            if not c:
                return [hint] if "/" in hint else []
        else:
            c = list(all_py)
        if qual:
            short = qual.split(".")[-1]
            narrowed = [p for p in c if qual in defs_of(p) or any(q.split(".")[-1] == short for q in defs_of(p))]
            c = narrowed if (narrowed or not hint) else c
        gw = [p for p in c if p.startswith(GATEWAY)]
        return gw or c

    def classify(fr: Fragment, path: str, qual: Optional[str], rng: Optional[Tuple[int, int]]) -> None:
        if path.startswith(APPLY_TIME_PREFIXES):
            fr.kind = "apply_time"
            return
        if path in NOT_LOADED or path == "shared/hcl_utils.py":
            fr.kind = "not_loaded"
            return
        if not path.startswith(GATEWAY):
            fr.kind = "out_of_scope"
            return
        d = defs_of(path)
        q = None
        if qual:
            q = qual if qual in d else next((k for k in d if k.split(".")[-1] == qual.split(".")[-1]
                                             and ".<locals>." not in k), None)
        if q is not None and rng is not None and not (d[q][0] - 3 <= rng[0] <= d[q][1]):
            q_enclosing = _innermost(d, rng[0])  # range lies outside the named def: use what encloses it
            if q_enclosing is not None:
                fr.qualname, fr.kind, fr.enclosing = q, "inline", q_enclosing.split(".<locals>.")[0]
                return
        if q is None and qual:
            fr.qualname, fr.kind = qual, "unresolved"
            fr.note = "name is not a def at the inventory SHA (constant/data?)"
        elif q is not None:
            s0, e0 = d[q]
            fr.qualname = q
            # whole callable: no range, the range starts at the def, or it covers most of the body
            whole = rng is None or abs(rng[0] - s0) <= 3 or (rng[1] - rng[0] + 1) >= 0.6 * (e0 - s0 + 1)
            if whole and ".<locals>." not in q:
                fr.kind = "function"
            else:
                fr.kind, fr.enclosing = "inline", q.split(".<locals>.")[0]
        elif rng is not None:
            enc = _innermost(d, rng[0])
            if enc is None:
                fr.kind, fr.note = "unresolved", "module-level line range"
            else:
                fr.kind, fr.enclosing = "inline", enc.split(".<locals>.")[0]
        else:
            fr.kind = "unresolved"

    out: List[Fragment] = []
    for hid, cell in rows:
        tier = hid[1]
        prev_paths: List[str] = []
        for m in _FRAG.finditer(cell):
            raw = m.group(1)
            hint, qual, lines_text = split_fragment(raw)
            lines, approx = _parse_lines(lines_text) if lines_text else ([], False)
            if hint and hint.split("/")[-1] == "hcl_utils.py":
                paths = list(HCL_UTILS_REPLICAS)
            elif hint is None and prev_paths == HCL_UTILS_REPLICAS:
                paths = list(HCL_UTILS_REPLICAS)  # continuation of an hcl_utils fragment in the same row
            elif hint is None and qual is None and prev_paths:
                paths = list(prev_paths)
            else:
                cands = candidates(hint, qual)
                if hint is None and qual and len(prev_paths) == 1 and prev_paths[0] in cands:
                    cands = list(prev_paths)  # `self_correct_hcl:1977-1997` continues the row's previous file
                if not cands and hint is None and prev_paths:
                    cands = list(prev_paths)
                if len(cands) > 1:
                    exact = [p for p in cands if qual and qual in defs_of(p)]
                    cands = exact if len(exact) == 1 else cands
                if len(cands) > 1:
                    out.append(Fragment(hid, tier, raw, note="ambiguous file: " + ", ".join(cands[:6])))
                    continue
                paths = cands
            if not paths:
                out.append(Fragment(hid, tier, raw, note="no matching file at inventory SHA"))
                continue
            prev_paths = list(paths)
            for path in paths:
                for rng in (lines or [None]):
                    fr = Fragment(hid, tier, raw, file=path, lines=[rng] if rng else [], approx=approx,
                                  module=_module_name(path))
                    classify(fr, path, qual, rng)
                    out.append(fr)
    return out


# ------------------------------------------------------------------------------------------------- anchoring
LINE_DIGEST_HEX = 12  # 48-bit per-line digest; only equality between an old and a new line of one file matters


def line_digests(src: str) -> List[str]:
    """sha256 (first LINE_DIGEST_HEX hex chars) of each line of `src` (str.splitlines, UTF-8)."""
    return [hashlib.sha256(ln.encode("utf-8")).hexdigest()[:LINE_DIGEST_HEX] for ln in src.splitlines()]


def pack_digests(digests: Sequence[str]) -> str:
    return "".join(digests)


def unpack_digests(packed: str) -> List[str]:
    if len(packed) % LINE_DIGEST_HEX:
        raise ValueError("packed line digests: length is not a multiple of LINE_DIGEST_HEX")
    return [packed[i:i + LINE_DIGEST_HEX] for i in range(0, len(packed), LINE_DIGEST_HEX)]


def build_inventory_digests(frags: List[Fragment], read_file: Callable[[str], Optional[str]]) -> Dict:
    """The vendored inventory side of anchoring: packed line digests of every file an inline fragment names."""
    files: Dict[str, str] = {}
    for path in sorted({f.file for f in frags if f.kind == "inline" and f.file}):
        src = read_file(path)
        if src is not None:
            files[path] = pack_digests(line_digests(src))
    return {"inventory_sha": INVENTORY_SHA, "line_digest": f"sha256[:{LINE_DIGEST_HEX}] per str.splitlines() line, "
            "UTF-8, concatenated", "files": files}


class InventoryDigestsError(ValueError):
    """The vendored inventory digests are missing, stale or do not cover an inline fragment (fail closed: a silent
    `anchor_lost` miscount is exactly what OSS blocker 1a removed)."""


def load_inventory_digests(path: Path) -> Dict[str, str]:
    """path -> packed digests from the vendored file. A missing file raises FileNotFoundError (never {}); a file made
    for another inventory commit raises InventoryDigestsError."""
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict) or data.get("inventory_sha") != INVENTORY_SHA:
        got = data.get("inventory_sha") if isinstance(data, dict) else None
        raise InventoryDigestsError(f"{path}: inventory_sha {got!r} != INVENTORY_SHA {INVENTORY_SHA!r}; "
                                    "regenerate with eval/tools/build_targets.py")
    files = data.get("files")
    if not isinstance(files, dict):
        raise InventoryDigestsError(f"{path}: no 'files' table; regenerate with eval/tools/build_targets.py")
    return files


def require_inventory_coverage(frags: List[Fragment], files: Dict[str, str], path: Path) -> None:
    """Every inline fragment's file must have digests; otherwise anchoring would silently report anchor_lost."""
    missing = sorted({f.file for f in frags if f.kind == "inline" and f.file and f.file not in files})
    if missing:
        raise InventoryDigestsError(f"{path}: no line digests for inline-fragment file(s) {missing}; regenerate with "
                                    "eval/tools/build_targets.py")


def inventory_reader(path: Path, files: Optional[Dict[str, str]] = None) -> Callable[[str], Optional[List[str]]]:
    """read_old for anchor_to() from the vendored digests file (no git). A missing or stale file raises; a path the
    file does not cover returns None (callers check coverage first with require_inventory_coverage)."""
    if files is None:
        files = load_inventory_digests(path)

    def read(p: str) -> Optional[List[str]]:
        packed = files.get(p)
        return unpack_digests(packed) if packed is not None else None
    return read


def line_map(old_src: Union[str, Sequence[str]], new_src: str) -> Callable[[int], Optional[int]]:
    """old_src is either the old source text or its line_digests() (the vendored inventory form)."""
    if isinstance(old_src, str):
        a, b = old_src.splitlines(), new_src.splitlines()
    else:
        a, b = list(old_src), line_digests(new_src)
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    blocks = sm.get_matching_blocks()

    def f(line: int) -> Optional[int]:
        i = line - 1
        for b in blocks:
            if b.a <= i < b.a + b.size:
                return b.b + (i - b.a) + 1
        return None
    return f


class RetiredHealersError(ValueError):
    """eval/config/healer_deletions.json is malformed (fail closed: a bad entry must not silently shrink the
    coverage denominator)."""


_SHA = re.compile(r"^[0-9a-f]{7,40}$")


def load_retired_healers(path: Path) -> Dict[str, Dict[str, str]]:
    """The reviewed retired-healer list (FD-55 W0 / FD-4CR): fragment key -> {"commit": <abbrev SHA that deleted
    it>, "by": <row / step>}. A missing file is no retired healer; a malformed one raises RetiredHealersError."""
    path = Path(path)
    if not path.is_file():
        return {}
    data = json.loads(path.read_text())
    if not isinstance(data, dict) or data.get("schema") != 2 or not isinstance(data.get("retired"), dict):
        raise RetiredHealersError(f"{path}: expected {{'schema': 2, 'retired': {{key: {{commit, by}}}}}}")
    out: Dict[str, Dict[str, str]] = {}
    for key, entry in data["retired"].items():
        if not (isinstance(entry, dict) and isinstance(entry.get("commit"), str) and _SHA.match(entry["commit"])
                and isinstance(entry.get("by"), str) and entry["by"].strip()):
            raise RetiredHealersError(f"{path}: entry {key!r} needs a hex `commit` (7-40) and a non-empty `by`")
        out[key] = {"commit": entry["commit"], "by": entry["by"]}
    return out


def anchor_to(frags: List[Fragment], read_old: Callable[[str], Optional[Union[str, List[str]]]],
              read_new: Callable[[str], Optional[str]], deleted: Optional[Dict[str, Any]] = None) -> List[Dict]:
    """Return JSON-able target dicts with `lines_pinned` (inline) and `present` (function) for the product root.

    read_old returns the inventory-SHA source text or its line_digests() (inventory_reader, the run-time form).

    `deleted` (load_retired_healers(eval/config/healer_deletions.json)): fragment key -> the commit/row that deleted
    that healer on purpose. A listed fragment whose code is actually gone from this product root (function or file
    absent, or inline anchor lost) is "absent" with `deleted_by`; against an older product root that still has the
    code it stays "anchored" / "present" (measured as before)."""
    maps: Dict[str, Optional[Callable[[int], Optional[int]]]] = {}
    new_defs: Dict[str, Dict[str, Tuple[int, int]]] = {}
    out = []
    for fr in frags:
        d = asdict(fr)
        d["key"] = fr.key()
        if fr.kind in ("function", "inline") and fr.file:
            new = read_new(fr.file)
            if new is None:
                d["status"] = "absent_file"
                if deleted and d["key"] in deleted:
                    d["deleted_by"] = deleted[d["key"]]
                out.append(d)
                continue
            if fr.file not in new_defs:
                try:
                    new_defs[fr.file] = _defs(new)
                except SyntaxError:
                    new_defs[fr.file] = {}
            if fr.kind == "function":
                d["status"] = "present" if fr.qualname in new_defs[fr.file] else "absent"
            else:
                if fr.file not in maps:
                    old = read_old(fr.file)
                    maps[fr.file] = line_map(old, new) if old is not None else None
                fmap = maps[fr.file]
                pinned = []
                lost = False
                for a, b in fr.lines:
                    na, nb = (fmap(a), fmap(b)) if fmap else (None, None)
                    if na is None or nb is None or nb < na:
                        lost = True
                    else:
                        pinned.append([na, nb])
                d["lines_pinned"] = pinned
                enc_present = fr.enclosing in new_defs[fr.file]
                d["status"] = "anchored" if (pinned and not lost and enc_present) else (
                    "anchor_lost" if enc_present else "absent")
                if d["status"] == "anchor_lost" and deleted and d["key"] in deleted:
                    d["status"] = "absent"
            if d["status"] == "absent" and deleted and d["key"] in deleted:
                d["deleted_by"] = deleted[d["key"]]
        else:
            d["status"] = fr.kind
        out.append(d)
    return out
