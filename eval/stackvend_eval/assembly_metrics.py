"""Step 1 assembly metrics (S1-0; integration plan §S.3 R1/R1b, Step 1 RT F1-F3).

Independent of the product's own V2c (this module is the harness oracle): with python-hcl2 it compares the LLM's raw
IaC (checkpoint C0) with the generated tree (C2, or C1 with healers off) and the product's AssemblyRecord:

  dropped_unreplaced   resource/data/module keys the LLM declared that are absent from the tree, not recorded in
                       `replaced` and not removed by an accepted repair with a recorded justification (must be 0; a
                       V2c proxy again after S1-B, R3c-fix RT §10.1)
  repair_removals_justified  {key: reason} for draft keys an accepted repair removed (RepairEvent.removal_reasons)
  dropped_non_preserved      other kinds (output/local/variable/provider/...) absent from the tree; acceptance does
                       not preserve them (Step 1 code RT F5), so they are listed apart and never count as drops
  replaced_by_reason   the product's recorded replacements, grouped by reason
  blocks_not_verbatim  LLM top-level blocks whose exact text is not found at their expected location (aux files in
                       place; files at platform-rendered paths inside infra/workload/custom.tf), excluding replaced keys
  golden_module_mutations  infra/modules/** files in the tree that differ from the product checkout's infra/modules/**

Block keys (also the product's AssemblyRecord grammar): "<type>.<name>" (resource), "data.<type>.<name>",
"module.<name>", "variable.<name>", "output.<name>", "provider.<name>" / "provider.<name>.<alias>", "terraform",
"local.<name>", "moved:<from expression>".
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .paths import add_deps_to_path

WORKLOAD = "infra/workload/"
RENDERED_PATHS = ("infra/workload/main.tf", "infra/workload/variables.tf", "infra/workload/outputs.tf",
                  "infra/workload/moved.tf", "infra/workload/services.tf")
CUSTOM_TF = "infra/workload/custom.tf"


def _meta(body: Any) -> Tuple[Optional[int], Optional[int]]:
    if isinstance(body, dict):
        return body.get("__start_line__"), body.get("__end_line__")
    return None, None


def block_index(text: str) -> List[Tuple[str, int, int]]:
    """[(key, start_line, end_line)] of every top-level block (1-based inclusive), via hcl2 with_meta."""
    add_deps_to_path()
    import hcl2
    doc = hcl2.loads(text, with_meta=True)
    out: List[Tuple[str, int, int]] = []
    for kind, entries in doc.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if kind in ("resource", "data"):
                for typ, named in entry.items():
                    if typ.startswith("__") or not isinstance(named, dict):
                        continue
                    for name, body in named.items():
                        if name.startswith("__"):
                            continue
                        s, e = _meta(body)
                        out.append(((f"data.{typ}.{name}" if kind == "data" else f"{typ}.{name}"), s, e))
            elif kind in ("module", "variable", "output"):
                for name, body in entry.items():
                    if name.startswith("__"):
                        continue
                    s, e = _meta(body)
                    out.append((f"{kind}.{name}", s, e))
            elif kind == "provider":
                for name, body in entry.items():
                    if name.startswith("__"):
                        continue
                    s, e = _meta(body)
                    alias = body.get("alias") if isinstance(body, dict) else None
                    out.append((f"provider.{name}" + (f".{alias}" if alias else ""), s, e))
            elif kind == "terraform":
                s, e = _meta(entry)
                out.append(("terraform", s, e))
            elif kind == "locals":
                s, e = _meta(entry)
                for name in entry:
                    if not name.startswith("__"):
                        out.append((f"local.{name}", s, e))
            elif kind == "moved":
                s, e = _meta(entry)
                out.append((f"moved:{entry.get('from')}", s, e))
    return out


def keys_of(text: str) -> Optional[Set[str]]:
    try:
        return {k for k, _s, _e in block_index(text)}
    except Exception:  # noqa: BLE001 - python-hcl2 rejects some valid HCL: structure unavailable
        return None


def _root_tf(tree: Dict[str, str]) -> Dict[str, str]:
    return {p: t for p, t in tree.items() if p.startswith(WORKLOAD) and p.endswith(".tf")
            and "/" not in p[len(WORKLOAD):]}


def tree_keys(tree: Dict[str, str]) -> Tuple[Set[str], List[str]]:
    keys: Set[str] = set()
    unparsed: List[str] = []
    for p, t in _root_tf(tree).items():
        k = keys_of(t)
        if k is None:
            unparsed.append(p)
        else:
            keys |= k
    return keys, unparsed


PRESERVED_KINDS = frozenset({"resource", "data", "module"})   # the product's repair_loop.PRESERVED_KINDS
_OTHER_KEY_KINDS = ("variable.", "output.", "provider.", "local.", "moved:")


def key_kind(key: str) -> str:
    """Block kind of a key in this module's grammar (see the module docstring)."""
    if key == "terraform":
        return "terraform"
    for prefix in _OTHER_KEY_KINDS:
        if key.startswith(prefix):
            return prefix.rstrip(".:")
    if key.startswith("data."):
        return "data"
    if key.startswith("module."):
        return "module"
    return "resource"


def golden_module_mutations(tree: Dict[str, str], product_root: Optional[Path]) -> Optional[List[str]]:
    if not product_root:
        return None
    root = Path(product_root)
    out = []
    for p, t in sorted(tree.items()):
        if not p.startswith("infra/modules/"):
            continue
        src = root / p
        if src.is_file() and src.read_text() != t:
            out.append(p)
    return out


def assembly_metrics(draft: Dict[str, str], tree: Dict[str, str], record: Optional[Dict[str, Any]],
                     product_root: Optional[Path] = None,
                     removal_reasons: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """`removal_reasons`: the union of the accepted repair events' `removal_reasons` ({address: justification})."""
    replaced: Dict[str, str] = dict((record or {}).get("replaced") or {})
    justified_all: Dict[str, str] = dict(removal_reasons or {})
    reasons: Dict[str, str] = dict((record or {}).get("replaced_reason") or {})
    draft_tf = _root_tf(draft)
    draft_keys, draft_unparsed = tree_keys(draft_tf)
    t_keys, tree_unparsed = tree_keys(tree)
    absent = draft_keys - t_keys - set(replaced)
    justified = {k: justified_all[k] for k in sorted(absent) if k in justified_all}
    dropped = sorted(k for k in absent - set(justified) if key_kind(k) in PRESERVED_KINDS)
    non_preserved = sorted(k for k in absent - set(justified) if key_kind(k) not in PRESERVED_KINDS)
    by_reason: Dict[str, List[str]] = {}
    for k, why in sorted(reasons.items()):
        by_reason.setdefault(why, []).append(k)
    not_verbatim: List[Dict[str, Any]] = []
    for path, text in sorted(draft_tf.items()):
        try:
            idx = block_index(text)
        except Exception:  # noqa: BLE001
            continue
        lines = text.split("\n")
        where = CUSTOM_TF if path in RENDERED_PATHS else path
        target = tree.get(where, "")
        for key, s, e in idx:
            if key in replaced or s is None or e is None:
                continue
            block = "\n".join(lines[s - 1:e])
            if block and block not in target:
                not_verbatim.append({"key": key, "draft_path": path, "expected_in": where})
    return {"has_record": record is not None, "draft_keys": len(draft_keys), "tree_keys": len(t_keys),
            "dropped_unreplaced": dropped, "repair_removals_justified": justified,
            "dropped_non_preserved": non_preserved, "replaced_by_reason": by_reason,
            "blocks_not_verbatim": not_verbatim, "draft_unparsed": draft_unparsed, "tree_unparsed": tree_unparsed,
            "golden_module_mutations": golden_module_mutations(tree, product_root)}
