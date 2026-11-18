"""Score one finished run (scoring child): checkpoint validity, invariants, and post-hoc tri-state
classification of every healer fire (red-team H1).

A fire is `on_validate_valid` when the healer's INPUT already passed the validator stack the harness scores with:
  .tf  -> the complete before-tree passes `tofu validate` (a partial, pre-assembly tree is `unknown`)
  .py  -> ast.parse + no pyflakes undefined names
`on_syntax_valid` uses `tofu fmt` / ast.parse only. The DNH gate is fires_on_validate_valid == 0.
"""
from __future__ import annotations

import json
import posixpath
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from . import hclparse, invariants
from .blobs import BlobStore
from .oracles import py_ast, py_file_validate_level, score_python
from .tofu_runner import TofuRunner

PARSE_ONLY = ("C0_raw_swarm", "C0_raw_single_turn")


def _tree_complete(tree: Dict[str, str]) -> Optional[bool]:
    """True when every local module source referenced from infra/ resolves inside the tree."""
    if not any(p.startswith("infra/workload/") and p.endswith(".tf") for p in tree):
        return False
    try:
        parsed, bad = hclparse.parse_tree(tree, "infra/")
    except hclparse.HclUnavailable:
        return None
    if bad:
        return None
    dirs = {posixpath.dirname(p) for p in tree}
    for path, _, src in hclparse.module_sources(parsed):
        if not hclparse.is_local_source(src):
            return False
        target = posixpath.normpath(posixpath.join(posixpath.dirname(path), src))
        if not any(d == target or d.startswith(target + "/") for d in dirs):
            return False
    return True


def _file_syntax(runner: TofuRunner, path: Optional[str], text: str) -> str:
    if path is None:
        return "unknown"
    if path.endswith(".py"):
        return "valid" if py_ast(text, path)[0] else "invalid"
    if path.endswith(".tf"):
        if not runner.available:
            return "unknown"
        return "valid" if runner.fmt_ok(text)[0] else "invalid"
    return "unknown"


def _combine(states: List[str]) -> str:
    if not states:
        return "unknown"
    if "invalid" in states:
        return "invalid"
    if all(s == "valid" for s in states):
        return "valid"
    return "unknown"


def classify_event(evt: Dict[str, Any], blobs: BlobStore, runner: TofuRunner) -> Dict[str, Any]:
    if evt.get("payload") == "text":
        path = evt.get("path")
        before = blobs.get(evt["before_blob"])
        changed = {path: before} if path else {}
        if not path:
            return {"syntax": "unknown", "validate": "unknown", "reason": "path_unknown"}
    else:
        tree = blobs.get_tree(evt["before_tree"])
        changed = {p: tree[p] for p in evt.get("changed_paths", []) if p in tree}  # added files have no before
        if not changed:
            return {"syntax": "unknown", "validate": "unknown", "reason": "only_added_files"}
    syntax = _combine([_file_syntax(runner, p, t) for p, t in changed.items()])
    states = []
    if any(p.endswith(".py") for p in changed):
        states += [py_file_validate_level(t, p) for p, t in changed.items() if p.endswith(".py")]
    if any(p.endswith(".tf") for p in changed):
        bt = evt.get("before_tree")
        if not bt:
            states.append("unknown")
        else:
            tree = blobs.get_tree(bt)
            complete = _tree_complete(tree)
            if complete is not True:
                states.append("unknown")
            else:
                v = runner.validate_tree(tree, f"evt-{bt[:16]}", plan=False, tree_key=f"evt:{bt}")
                states.append("valid" if v.get("validate_ok") else ("invalid" if v.get("status") == "validated"
                                                                      else "unknown"))
    if not any(p.endswith((".py", ".tf")) for p in changed):
        states.append("unknown")
    return {"syntax": syntax, "validate": _combine(states)}


def _assembly(result: Dict[str, Any], blobs: BlobStore, product_root: Optional[Path]) -> Optional[Dict[str, Any]]:
    """S1-0 (R1/R1b): LLM declarations vs the generated tree vs the product's AssemblyRecord."""
    from .assembly_metrics import assembly_metrics, golden_module_mutations
    cks = result.get("checkpoints") or {}
    draft_ck = next((cks[n] for n in PARSE_ONLY if isinstance(cks.get(n), dict) and "tree" in cks[n]), None)
    tree_ck = next((cks[n] for n in ("C2_generated", "C1_healers_off") if isinstance(cks.get(n), dict)
                    and "tree" in cks[n]), None)
    if draft_ck is None or tree_ck is None:
        return None
    hs = result.get("hallucination_stack") or {}
    record = hs.get("assembly_record")
    removal_reasons: Dict[str, str] = {}   # union over accepted repairs (R3c-fix RT §10.1)
    for ev in hs.get("repair_events") or []:
        if isinstance(ev, dict) and ev.get("accepted"):
            removal_reasons.update(ev.get("removal_reasons") or {})
    try:
        m = assembly_metrics(blobs.get_tree(draft_ck["tree"]), blobs.get_tree(tree_ck["tree"]), record, product_root,
                             removal_reasons=removal_reasons)
    except hclparse.HclUnavailable:
        return {"status": "skipped_no_hcl_parser"}
    c3 = cks.get("C3_committed")
    if isinstance(c3, dict) and "tree" in c3:
        m["golden_module_mutations_c3"] = golden_module_mutations(blobs.get_tree(c3["tree"]), product_root)
    return m


# ------------------------------------------------------------------------------------ TI-0 typed-IaC measurements
# File kinds by exact suffix (no content inspection): what the AI / a healer touched is IaC or application code.
IAC_SUFFIXES = (".tf", ".tf.json", ".tfvars")


def is_iac_path(path: str) -> bool:
    return isinstance(path, str) and path.endswith(IAC_SUFFIXES)


def event_paths(evt: Dict[str, Any]) -> List[str]:
    if evt.get("payload") == "text":
        return [evt["path"]] if evt.get("path") else []
    return [p for p in (evt.get("changed_paths") or []) if isinstance(p, str)]


def event_kind(evt: Dict[str, Any]) -> str:
    """iac: every file the healer changed is IaC; app: none is; mixed: both; unknown: no path recorded."""
    paths = event_paths(evt)
    if not paths:
        return "unknown"
    n_iac = sum(1 for p in paths if is_iac_path(p))
    return "iac" if n_iac == len(paths) else ("app" if n_iac == 0 else "mixed")


def healer_fvv_split(events: List[Dict[str, Any]], classification: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
    """fires_on_validate_valid split by what the healer changed. Counted exactly like the per-target fire totals
    (one fire per (event, target key)), so iac + app + mixed + unknown == the run's fires_on_validate_valid."""
    out = {"iac": 0, "app": 0, "mixed": 0, "unknown": 0}
    for evt in events or []:
        c = (classification or {}).get(str(evt.get("eid"))) or {}
        if c.get("validate") == "valid":
            out[event_kind(evt)] += len(evt.get("keys") or [])
    return out


def _first_tree(blobs: BlobStore, cks: Dict[str, Any], names: Any) -> Tuple[Optional[str], Optional[Dict[str, str]]]:
    for n in names:
        ck = cks.get(n)
        if isinstance(ck, dict) and isinstance(ck.get("tree"), str):
            return n, blobs.get_tree(ck["tree"])
    return None, None


def ai_iac_paths(result: Dict[str, Any], blobs: BlobStore) -> Optional[List[str]]:
    """IaC paths in the AI's first draft (checkpoint C0: the raw LLM file dict), sorted; None without a C0 tree."""
    _, draft = _first_tree(blobs, result.get("checkpoints") or {}, PARSE_ONLY)
    return None if draft is None else sorted(p for p in draft if is_iac_path(p))


IAC_PERSONA = "IAC_ENGINEER"


def _ident(node: Any) -> Optional[str]:
    """The text of an `identifier` node (lark Tree with one Token child), else None."""
    if getattr(node, "data", None) != "identifier" or not getattr(node, "children", None):
        return None
    return str(node.children[0])


def _function_names(text: str) -> Set[str]:
    """Names of every function call in one HCL file, from python-hcl2's own lark parse tree (`function_call` nodes,
    whose first child is the identifier): a parser walk, never a text search. A `variable` block's `type` attribute is
    a type constraint, not an expression (`map(string)`, `list(object({...}))` parse as calls), so it is skipped."""
    from .paths import add_deps_to_path
    add_deps_to_path()
    import hcl2
    names: Set[str] = set()

    def walk(node: Any, in_variable: bool) -> None:
        data = getattr(node, "data", None)
        kids = list(getattr(node, "children", None) or [])
        if data == "function_call" and kids:
            name = _ident(kids[0])
            if name is not None:
                names.add(name)
        if data == "block" and kids:
            in_variable = _ident(kids[0]) == "variable"
        if data == "attribute" and in_variable and kids and _ident(kids[0]) == "type":
            return
        for k in kids:
            if hasattr(k, "data"):
                walk(k, in_variable)
    walk(hcl2.parses(text), False)
    return names


def draft_features(files: Dict[str, str]) -> Dict[str, Any]:
    """Resource types, data-source types and functions in a draft's .tf files (TI-2 expressibility inputs)."""
    from .assembly_metrics import key_kind, keys_of
    types: Set[str] = set()
    data: Set[str] = set()
    funcs: Set[str] = set()
    unparsed: List[str] = []
    for path, text in sorted(files.items()):
        if not (isinstance(text, str) and path.endswith(".tf")):
            continue
        keys = keys_of(text)
        if keys is None:
            unparsed.append(path)
            continue
        for k in keys:
            kind = key_kind(k)
            if kind == "resource":
                types.add(k.split(".", 1)[0])
            elif kind == "data":
                data.add(k.split(".", 2)[1])
        try:
            funcs |= _function_names(text)
        except Exception:  # noqa: BLE001 - keys parsed but the lark walk failed: list it, never guess
            unparsed.append(path)
    return {"types": sorted(types), "data_sources": sorted(data), "functions": sorted(funcs),
            "unparsed": sorted(set(unparsed))}


def iac_first_draft(result: Dict[str, Any], blobs: BlobStore) -> Tuple[Optional[str], Optional[Dict[str, str]]]:
    """The IaC persona's own first draft: its invoke_junior_worker files (run_child observer); a single-turn run's
    C0 file dict (one author writes everything); results written before TI-0: the merged swarm C0 (every persona;
    the source says so)."""
    trees = ((result.get("junior_drafts") or {}).get("trees")) or {}
    if IAC_PERSONA in trees:
        return "junior_drafts:" + IAC_PERSONA, blobs.get_tree(trees[IAC_PERSONA])
    cks = result.get("checkpoints") or {}
    if isinstance(cks.get("C0_raw_single_turn"), dict) and "tree" in cks["C0_raw_single_turn"]:
        return "C0_raw_single_turn", blobs.get_tree(cks["C0_raw_single_turn"]["tree"])
    if trees:
        return "junior_drafts:no_" + IAC_PERSONA, {}
    if isinstance(cks.get("C0_raw_swarm"), dict) and "tree" in cks["C0_raw_swarm"]:
        return "C0_raw_swarm_all_personas", blobs.get_tree(cks["C0_raw_swarm"]["tree"])
    return None, None


# TI-0 RT F4: an independent policy scan of the COMMITTED workload root module (S6 is not scored by the product's own
# gate). Exact tables and python-hcl2 values; vendored infra/modules/** is excluded (the platform's own modules there
# hold e.g. the Cloud Run invoker). Member / ACL attribute names follow the google provider schema.
PUBLIC_PRINCIPALS = frozenset({"allUsers", "allAuthenticatedUsers"})
OWNER_ROLES = frozenset({"roles/owner"})
MEMBER_ATTRS = ("member", "entity")          # single principal (IAM *_member, *_access_control)
MEMBERS_ATTRS = ("members",)                 # principal lists (IAM *_binding)
ROLE_ENTITY_ATTRS = ("role_entity",)         # "<ROLE>:<entity>" lists (google_storage_*_acl)


def _strs(v: Any) -> List[str]:
    return [x for x in (v if isinstance(v, list) else [v]) if isinstance(x, str)]


def c3_policy_scan(tree: Dict[str, str]) -> Dict[str, Any]:
    """{public_members, owner_grants, unparsed}: addresses in infra/workload/*.tf (root module only) whose resource sets
    a public principal or the owner role, by exact value."""
    from .assembly_metrics import WORKLOAD
    from .paths import add_deps_to_path
    add_deps_to_path()
    import hcl2
    public: List[str] = []
    owner: List[str] = []
    unparsed: List[str] = []
    for path, text in sorted(tree.items()):
        if not (path.startswith(WORKLOAD) and path.endswith(".tf") and "/" not in path[len(WORKLOAD):]):
            continue
        try:
            doc = hcl2.loads(text)
        except Exception:  # noqa: BLE001 - unparsable: listed, and S6 fails closed on it
            unparsed.append(path)
            continue
        for entry in doc.get("resource") or []:
            for typ, named in (entry or {}).items():
                for name, body in (named or {}).items():
                    if not isinstance(body, dict):
                        continue
                    addr = f"{typ}.{name}"
                    principals = [p for a in MEMBER_ATTRS + MEMBERS_ATTRS for p in _strs(body.get(a))]
                    principals += [p.partition(":")[2] for a in ROLE_ENTITY_ATTRS for p in _strs(body.get(a))]
                    if any(p in PUBLIC_PRINCIPALS for p in principals):
                        public.append(addr)
                    if any(r in OWNER_ROLES for r in _strs(body.get("role"))):
                        owner.append(addr)
    return {"public_members": sorted(set(public)), "owner_grants": sorted(set(owner)), "unparsed": unparsed}


def typed_iac(run_dir: Path, result: Dict[str, Any], blobs: BlobStore, events: List[Dict[str, Any]],
              classification: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"healer_fvv_split": healer_fvv_split(events, classification)}
    try:
        out["ai_iac_paths"] = ai_iac_paths(result, blobs)
    except Exception as e:  # noqa: BLE001 - a missing blob never fails the score
        out["ai_iac_paths_error"] = f"{type(e).__name__}: {e}"[:200]
    try:
        source, draft = iac_first_draft(result, blobs)
        if draft is not None:
            out["first_draft"] = {"source": source, **draft_features(draft)}
    except hclparse.HclUnavailable:
        out["first_draft"] = {"status": "skipped_no_hcl_parser"}
    except Exception as e:  # noqa: BLE001
        out["first_draft"] = {"status": f"error: {type(e).__name__}: {e}"[:200]}
    try:
        _, c3 = _first_tree(blobs, result.get("checkpoints") or {}, ("C3_committed",))
        if c3 is not None:
            out["c3_policy"] = c3_policy_scan(c3)
    except Exception as e:  # noqa: BLE001 - no scan: S6 fails closed (require_c3_policy_scan)
        out["c3_policy"] = {"status": f"error: {type(e).__name__}: {e}"[:200]}
    return out


def score_run(run_dir: Path, runner: TofuRunner, *, regions: Set[str], forbidden_projects: Set[str],
              plan: bool = True, oracle: Optional[TofuRunner] = None, column_label: str = "default",
              oracle_label: str = "oracle", product_root: Optional[Path] = None) -> Dict[str, Any]:
    run_dir = Path(run_dir)
    result = json.loads((run_dir / "result.json").read_text())
    blobs = BlobStore(run_dir)
    out: Dict[str, Any] = {"checkpoints": {}, "healer_classification": {}, "tofu_available": runner.available,
                           "tofu_mirror_ready": runner.mirror_ready,
                           "tofu_mirror_manifest": getattr(runner, "mirror_manifest", None)}
    for name, ck in (result.get("checkpoints") or {}).items():
        if not isinstance(ck, dict) or "tree" not in ck:
            continue
        tree = blobs.get_tree(ck["tree"])
        s: Dict[str, Any] = {"files": len(tree), "python": score_python(tree)}
        s["hcl"] = runner.score_hcl_parse(tree) if runner.available else {"status": "tofu_unavailable"}
        if name not in PARSE_ONLY:
            s["tofu"] = runner.validate_tree(tree, name, plan=plan, tree_key=f"ck:{ck['tree']}")
            s["tofu"]["column"] = column_label
            s["invariants"] = invariants.check(tree, regions=regions, forbidden_projects=forbidden_projects)
            if oracle is not None:
                o = oracle.validate_tree(tree, f"{name}-oracle", plan=False, tree_key=f"ck:{ck['tree']}")
                o["column"] = oracle_label
                s["tofu_oracle"] = o
                a, b = s["tofu"].get("validate_ok"), o.get("validate_ok")
                s["column_agreement"] = None if (a is None or b is None) else (a == b)
        out["checkpoints"][name] = s
    out["assembly"] = _assembly(result, blobs, product_root)
    per_target: Dict[str, Dict[str, int]] = {}
    events = (result.get("healers") or {}).get("events") or []
    for evt in events:
        try:
            c = classify_event(evt, blobs, runner)
        except Exception as e:  # noqa: BLE001
            c = {"syntax": "unknown", "validate": "unknown", "reason": f"error: {e}"[:200]}
        out["healer_classification"][str(evt["eid"])] = c
        for k in evt.get("keys", []):
            t = per_target.setdefault(k, {"fires": 0, "fires_on_syntax_valid": 0, "fires_on_validate_valid": 0,
                                          "fires_validate_unknown": 0, "fires_on_invalid_input": 0})
            t["fires"] += 1
            t["fires_on_syntax_valid"] += c["syntax"] == "valid"
            t["fires_on_validate_valid"] += c["validate"] == "valid"
            t["fires_validate_unknown"] += c["validate"] == "unknown"
            t["fires_on_invalid_input"] += c["validate"] == "invalid"
    out["healer_fires"] = per_target
    out["typed_iac"] = typed_iac(run_dir, result, blobs, events, out["healer_classification"])
    return out
