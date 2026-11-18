"""Step 1 S1-A assembly contract for the developer's Terraform root module (integration plan §S.5, lane 8B §5.3).

Replaces the Tier-3 consolidation and the HA-10 stem purge (register rows HS-01, HS-08). What it guarantees:

1. The LLM's files at platform-rendered paths (main.tf, variables.tf, outputs.tf, moved.tf, services.tf) are appended
   **verbatim** to infra/workload/custom.tf, in that order, each after one provenance comment line. Head of custom.tf:
   this run's AI custom.tf, else the repository's existing custom.tf, else empty.
2. The LLM's other .tf files under infra/workload/ (iam.tf, network.tf, ...) stay where the LLM put them.
3. The only removals are whole top-level blocks found with python-hcl2 `with_meta` line ranges (exact keys), each
   recorded in the AssemblyRecord with its reason:
     PLATFORM_ROOT_DECLARATION  the key is declared by the platform's own root files (terraform, un-aliased providers
                                it configures, its variables/outputs/modules) - same address, references unaffected
     PRIOR_DECLARATION          the key is already declared by a kept pre-existing file or the prior custom.tf head
                                (today's "first seen wins", made exact and visible)
   Nothing else is removed, rewritten, re-split or deduplicated. A file python-hcl2 cannot parse is kept verbatim.
4. No .tf file is ever deleted: pre-existing files are kept byte-identical; the AI's files outside infra/workload/ are
   left untouched (V7 reports them in S1-B).

Every function here is pure (no I/O, no LLM).
"""
from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

if TYPE_CHECKING:  # annotations only
    from shared.diagnostics import AssemblyRecord, ReplaceReason, Segment

# The AssemblyRecord models live in shared.diagnostics (gateway copy) and are imported where they are built
# (assemble_root_module): modules that only need terraform_engine's renderers (e.g. the terraform MCP tests, whose
# `shared` package is another service's copy) must still import this module.

WORKLOAD = "infra/workload/"
CUSTOM_TF = "infra/workload/custom.tf"
# Paths the platform renders every run (overwritten by the golden renderers after assembly).
PLATFORM_RENDERED_ROOT = ("infra/workload/main.tf", "infra/workload/variables.tf", "infra/workload/outputs.tf",
                          "infra/workload/moved.tf")
# Draft files at platform-rendered paths, in the order they are appended to custom.tf (§S.5.2).
RELOCATED_DRAFT_ORDER = PLATFORM_RENDERED_ROOT + ("infra/workload/services.tf",)
# Root-module files that are platform templates / generated files, not bespoke IaC (Tier-3 skipped the same set).
NON_BESPOKE_ROOT = frozenset(PLATFORM_RENDERED_ROOT) | {"infra/workload/human.tf", "infra/workload/human_override.tf",
                                                        "infra/workload/indexes.tf"}


class HclUnavailable(RuntimeError):
    """python-hcl2 is not importable: the assembly cannot find block ranges (a deployment defect)."""


@dataclass(frozen=True)
class Block:
    kind: str                  # resource | data | module | variable | output | provider | terraform | locals | moved | ...
    keys: Tuple[str, ...]      # AssemblyRecord key grammar (locals blocks carry one key per local)
    start: int                 # 1-based inclusive line range in the file
    end: int
    labels: Tuple[str, ...] = ()
    body: Mapping = field(default_factory=dict)

    @property
    def key(self) -> str:
        return self.keys[0] if self.keys else ""


def _loads_with_meta(text: str) -> dict:
    try:
        import hcl2  # python-hcl2==7.3.1 (requirements.txt)
    except ImportError as e:  # pragma: no cover - environment
        raise HclUnavailable("python-hcl2 is not installed") from e
    return hcl2.loads(text, with_meta=True)


def _meta(body) -> Tuple[Optional[int], Optional[int]]:
    if isinstance(body, dict):
        return body.get("__start_line__"), body.get("__end_line__")
    return None, None


def index_blocks(text: str) -> Optional[List[Block]]:
    """Top-level blocks of one HCL file with exact line ranges; None when python-hcl2 cannot parse the file.

    See `index_blocks_with_skipped` (F6: entries that are not blocks are skipped)."""
    got = index_blocks_with_skipped(text)
    return None if got is None else got[0]


def index_blocks_with_skipped(text: str) -> Optional[Tuple[List[Block], int]]:
    """`index_blocks` plus the number of entries skipped under F6, for a caller that must not act on a partial index
    (it treats `skipped > 0` like an unparseable file). None when python-hcl2 cannot parse the file.

    A block whose label count Terraform rejects (`resource "t" { ... }`, `module { source = ... }`,
    `resource "a" "b" "c" { ... }`) still parses with python-hcl2 7.3.1, but then the dict level read here as the
    block body is an attribute value or a deeper label level, which has no python-hcl2 `__start_line__` meta. Such
    entries are not blocks and are skipped (FD-4Y RT F6), instead of being indexed as `Block(start=0, end=0)` with an
    attribute name as a label. Every real block (an empty body too) carries the meta, so valid HCL indexes exactly
    as before; tofu validate still reports the invalid block."""
    if not text or not text.strip():
        return [], 0
    try:
        doc = _loads_with_meta(text)
    except HclUnavailable:
        raise
    except Exception:  # noqa: BLE001 - python-hcl2 rejects some valid HCL: structure unavailable, keep verbatim
        return None
    out: List[Block] = []
    skipped = 0
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
                        if s is None:   # F6: not a 2-label block (an attribute value or a 3rd label level)
                            skipped += 1
                            continue
                        key = f"data.{typ}.{name}" if kind == "data" else f"{typ}.{name}"
                        out.append(Block(kind, (key,), s or 0, e or 0, (typ, name), body if isinstance(body, dict) else {}))
            elif kind in ("module", "variable", "output", "provider"):
                for name, body in entry.items():
                    if name.startswith("__"):
                        continue
                    s, e = _meta(body)
                    if s is None:   # F6: not a 1-label block (an attribute value or a 2nd label level)
                        skipped += 1
                        continue
                    key = f"{kind}.{name}"
                    if kind == "provider" and isinstance(body, dict) and body.get("alias"):
                        key = f"provider.{name}.{body.get('alias')}"
                    out.append(Block(kind, (key,), s or 0, e or 0, (name,), body if isinstance(body, dict) else {}))
            elif kind == "terraform":
                s, e = _meta(entry)
                if s is None:   # F6: a labelled `terraform "x" {}`
                    skipped += 1
                    continue
                out.append(Block(kind, ("terraform",), s or 0, e or 0, (), entry))
            elif kind == "locals":
                s, e = _meta(entry)
                if s is None:   # F6: a labelled `locals "x" {}`
                    skipped += 1
                    continue
                keys = tuple(f"local.{n}" for n in entry if not n.startswith("__"))
                out.append(Block(kind, keys, s or 0, e or 0, (), entry))
            else:  # moved / import / removed / check: never declarations the assembly removes
                # Not filtered (F6): a valid `check "name" {}` has a label, so its entry has no meta here; skipping
                # it would change the index of valid HCL. These `kind:` keys never match a declaration key.
                s, e = _meta(entry)
                out.append(Block(kind, (f"{kind}:{entry.get('from') or entry.get('to') or s}",), s or 0, e or 0,
                                 (), entry))
    out.sort(key=lambda b: (b.start, b.end))
    return out, skipped


def file_keys(text: str) -> Optional[Set[str]]:
    blocks = index_blocks(text)
    if blocks is None:
        return None
    return {k for b in blocks for k in b.keys}


def repository_custom_tf_keys(existing_files: Optional[Mapping[str, str]]) -> FrozenSet[str]:
    """RT14-12: the block keys of the repository's infra/workload/custom.tf as committed before this build (the
    fetch_existing_repo_files snapshot), so the multi-service reconcile can tell a person's (or a prior build's) block
    from this run's AI draft. Empty when the repository has no custom.tf, and when python-hcl2 cannot parse it (no exact
    block index; a head that is that repository file cannot be indexed by the reconcile either)."""
    text = (existing_files or {}).get(CUSTOM_TF)
    if not isinstance(text, str):
        return frozenset()
    return frozenset(file_keys(text) or ())


def platform_root_keys(rendered: Mapping[str, str]) -> Set[str]:
    """Keys the platform's rendered root files declare (terraform, providers, variables, outputs, modules, data)."""
    keys: Set[str] = set()
    for path, text in rendered.items():
        got = file_keys(text)
        if got is None:  # the platform's own render must always parse
            raise ValueError(f"platform-rendered {path} does not parse with python-hcl2")
        keys |= got
    return keys


def splice_out(text: str, ranges: Sequence[Tuple[int, int]]) -> Tuple[str, List[Tuple[int, int, int]]]:
    """Remove whole-line ranges (1-based inclusive). Returns (new text, chunks) where each chunk
    (new_start_line, draft_start_line, n_lines) maps a run of kept lines back to the original file."""
    lines = text.split("\n")
    drop: Set[int] = set()
    for s, e in ranges:
        drop.update(range(s, e + 1))
    kept: List[str] = []
    chunks: List[Tuple[int, int, int]] = []
    for i, line in enumerate(lines, start=1):
        if i in drop:
            continue
        kept.append(line)
        if chunks and chunks[-1][1] + chunks[-1][2] == i:
            ns, ds, n = chunks[-1]
            chunks[-1] = (ns, ds, n + 1)
        else:
            chunks.append((len(kept), i, 1))
    return "\n".join(kept), chunks


@dataclass
class _Plan:
    path: str
    text: str
    blocks: Optional[List[Block]]
    removals: List[Tuple[Block, str, ReplaceReason]] = field(default_factory=list)


def _plan_removals(plan: _Plan, decide) -> None:
    """decide(block) -> (target, reason) | None. A removal whose line range overlaps a kept block is skipped
    (keep both; tofu reports the duplicate) so splicing can never cut into a block that stays."""
    if not plan.blocks:
        return
    chosen = []
    for b in plan.blocks:
        verdict = decide(b)
        if verdict is not None and b.start and b.end:
            chosen.append((b, verdict[0], verdict[1]))
    removed_ids = {id(b) for b, _, _ in chosen}
    kept_ranges = [(b.start, b.end) for b in plan.blocks if id(b) not in removed_ids]
    for b, target, reason in chosen:
        if any(not (b.end < ks or b.start > ke) for ks, ke in kept_ranges):
            continue
        plan.removals.append((b, target, reason))


def _apply(plan: _Plan) -> Tuple[str, List[Tuple[int, int, int]]]:
    return splice_out(plan.text, [(b.start, b.end) for b, _, _ in plan.removals])


def _user_named(path: str) -> bool:
    """human.tf / human_override.tf / Terraform override files: user-owned by name, never edited by assembly."""
    base = posixpath.basename(path)
    return base in ("human.tf", "human_override.tf", "override.tf") or base.endswith("_override.tf")


def _is_root_tf(path: str) -> bool:
    return path.startswith(WORKLOAD) and path.endswith(".tf") and "/" not in path[len(WORKLOAD):]


@dataclass
class AssemblyResult:
    files: Dict[str, str]
    record: AssemblyRecord
    llm_iac_paths: List[str]          # root-module files holding this run's (or the prior run's) LLM IaC
    relocated_draft_paths: List[str]  # draft paths whose text now lives in custom.tf


def assemble_root_module(files: Mapping[str, str], *, llm_paths: Iterable[str], preexisting: Iterable[str],
                         root_keys: Set[str], attribution: Optional[Mapping[str, str]] = None,
                         default_persona: str = "developer", trace_id: str = "", iteration: int = 0) -> AssemblyResult:
    """Assemble infra/workload/ from the draft per the S1-A contract (module docstring).

    files        the generation tree (LLM files + platform files so far + pre-existing repo .tf merged in)
    llm_paths    keys written by this run's LLM (swarm/single-turn output)
    preexisting  keys that came from the repository (fetch_existing_repo_files)
    root_keys    platform_root_keys() of this run's rendered root files
    """
    out = dict(files)
    llm = set(llm_paths)
    pre = set(preexisting)
    attribution = dict(attribution or {})
    from shared.diagnostics import AssemblyRecord, Segment
    record = AssemblyRecord(trace_id=trace_id, iteration=iteration)

    def persona(path: str) -> str:
        return attribution.get(path) or default_persona

    head_is_ai = CUSTOM_TF in llm
    head_text = out.get(CUSTOM_TF, "") if (head_is_ai or CUSTOM_TF in pre) else ""
    relocated = [p for p in RELOCATED_DRAFT_ORDER if p in llm and isinstance(out.get(p), str)]
    aux = sorted(p for p in llm if _is_root_tf(p) and p != CUSTOM_TF and p not in RELOCATED_DRAFT_ORDER
                 and isinstance(out.get(p), str) and not _user_named(p))
    kept_pre = sorted(p for p in pre if _is_root_tf(p) and p not in llm and p != CUSTOM_TF
                      and p not in PLATFORM_RENDERED_ROOT and isinstance(out.get(p), str))

    prior_keys: Set[str] = set()
    for p in kept_pre:
        prior_keys |= file_keys(out[p]) or set()
    head_plan = _Plan(CUSTOM_TF, head_text, index_blocks(head_text))
    if not head_is_ai and head_plan.blocks:
        prior_keys |= {k for b in head_plan.blocks for k in b.keys}

    def decide_root(b: Block):
        if b.keys and all(k in root_keys for k in b.keys):
            return (b.key, "PLATFORM_ROOT_DECLARATION")
        return None

    def decide_ai(b: Block):
        verdict = decide_root(b)
        if verdict is not None:
            return verdict
        if b.keys and all(k in prior_keys for k in b.keys):
            return (b.key, "PRIOR_DECLARATION")
        return None

    def register(plan: _Plan) -> None:
        for b, target, reason in plan.removals:
            for k in b.keys:
                record.record(k, target if k == b.key else k, reason, plan.path)

    # Head: this run's AI custom.tf (root + prior rules) or the prior custom.tf (root rule only).
    _plan_removals(head_plan, decide_ai if head_is_ai else decide_root)
    head_new, head_chunks = _apply(head_plan)
    register(head_plan)

    # Segments: AI files at platform-rendered paths, appended verbatim (minus recorded removals).
    parts: List[str] = []
    segments: List[Segment] = []
    line_no = 0
    if head_new.strip():
        parts.append(head_new.rstrip("\n"))
        line_no = parts[-1].count("\n") + 1
        for ns, ds, n in head_chunks:
            if ns <= line_no:
                segments.append(Segment(assembled_path=CUSTOM_TF, start_line=ns, end_line=min(ns + n - 1, line_no),
                                        draft_path=CUSTOM_TF, draft_start_line=ds))
    relocated_done: List[str] = []
    for path in relocated:
        plan = _Plan(path, out[path], index_blocks(out[path]))
        _plan_removals(plan, decide_ai)
        new_text, chunks = _apply(plan)
        register(plan)
        if not new_text.strip():
            relocated_done.append(path)   # everything in it was a recorded platform/prior declaration
            continue
        body = new_text.rstrip("\n")
        comment = f"# stackvend: from {path} ({persona(path)})"
        prefix_lines = (line_no + 1) if parts else 0      # blank separator line before the comment
        comment_line = prefix_lines + 1
        parts.append(comment + "\n" + body)
        first_body_line = comment_line + 1
        body_lines = body.count("\n") + 1
        for ns, ds, n in chunks:
            if ns > body_lines:
                continue
            start = first_body_line + ns - 1
            end = first_body_line + min(ns + n - 1, body_lines) - 1
            segments.append(Segment(assembled_path=CUSTOM_TF, start_line=start, end_line=end, draft_path=path,
                                    draft_start_line=ds))
        line_no = first_body_line + body_lines - 1
        record.relocated[path] = CUSTOM_TF
        relocated_done.append(path)

    if parts:
        out[CUSTOM_TF] = "\n\n".join(parts) + "\n"
    elif head_plan.removals:
        out[CUSTOM_TF] = head_new  # every block was a recorded removal: the file stays (never deleted), emptied
    # The draft's services.tf now lives in custom.tf; main/variables/outputs/moved keep their key until the golden
    # renderers overwrite them (today's detection inputs read them in between).
    for path in relocated_done:
        if path not in PLATFORM_RENDERED_ROOT:
            out.pop(path, None)

    # Auxiliary AI files stay in place (byte-identical unless a recorded removal applies).
    for path in aux:
        plan = _Plan(path, out[path], index_blocks(out[path]))
        _plan_removals(plan, decide_ai)
        if plan.removals:
            new_text, chunks = _apply(plan)
            out[path] = new_text
            register(plan)
            for ns, ds, n in chunks:
                segments.append(Segment(assembled_path=path, start_line=ns, end_line=ns + n - 1, draft_path=path,
                                        draft_start_line=ds))

    record.segments = segments
    llm_iac = ([CUSTOM_TF] if CUSTOM_TF in out else []) + aux
    return AssemblyResult(files=out, record=record, llm_iac_paths=llm_iac, relocated_draft_paths=relocated_done)


def block_text(text: str, block: Block) -> str:
    return "\n".join(text.split("\n")[block.start - 1:block.end])


def shift_segments(record: Optional[AssemblyRecord], path: str, start: int, end: int, inserted: int) -> None:
    """Keep record.segments exact after lines start..end (1-based, inclusive) of `path` were replaced by `inserted`
    lines: segments before are unchanged, segments after shift, the replaced lines no longer map to a draft line."""
    if record is None:
        return
    delta = inserted - (end - start + 1)
    out: List[Segment] = []
    for s in record.segments:
        if s.assembled_path != path or s.end_line < start:
            out.append(s)
            continue
        if s.start_line > end:
            out.append(s.model_copy(update={"start_line": s.start_line + delta, "end_line": s.end_line + delta}))
            continue
        if s.start_line < start:  # head part before the splice
            out.append(s.model_copy(update={"end_line": start - 1}))
        if s.end_line > end:      # tail part after the splice
            skipped = end + 1 - s.start_line
            out.append(s.model_copy(update={"start_line": end + 1 + delta, "end_line": s.end_line + delta,
                                            "draft_start_line": s.draft_start_line + skipped}))
    record.segments = out


def splice_block(files: Dict[str, str], path: str, block: Block, new_text: Optional[str],
                 record: Optional[AssemblyRecord] = None) -> None:
    """Replace one top-level block (exact hcl2 line range) of files[path] with new_text (None = remove the lines),
    keeping record.segments exact. The only edit primitive post-assembly code may use on LLM files (S1-A)."""
    lines = files[path].split("\n")
    new_lines = [] if new_text is None else new_text.split("\n")
    files[path] = "\n".join(lines[:block.start - 1] + new_lines + lines[block.end:])
    shift_segments(record, path, block.start, block.end, len(new_lines))


def append_text(files: Dict[str, str], path: str, text: str) -> None:
    """Append platform text at the end of files[path] (one blank separator line); segments are unaffected."""
    cur = files.get(path, "")
    sep = "" if not cur.strip() else ("\n" if cur.endswith("\n") else "\n\n")
    files[path] = (cur if cur.strip() else "") + sep + text.rstrip("\n") + "\n"


def bespoke_root_text(files: Mapping[str, str]) -> str:
    """Concatenated bespoke IaC of the root module (custom.tf first, then every other root .tf that is not a
    platform-rendered/template file, sorted): the input the env-var wiring, the GKE network detection and the API
    inference read. Tier-3 used to put exactly these blocks into custom.tf; they now stay in their own files."""
    paths = [p for p in files if _is_root_tf(p) and p not in NON_BESPOKE_ROOT and isinstance(files.get(p), str)]
    paths.sort(key=lambda p: (0 if p == CUSTOM_TF else 1, p))
    return "\n\n".join(files[p] for p in paths if files[p].strip())
