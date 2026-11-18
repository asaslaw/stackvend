"""S2-0 per-branch probe of `_self_correct_workload_hcl` (Step 2 plan §2.1 "probe self_correct_hcl per branch").

The HealerProbe wraps whole functions; the HD-15 -> self_correct_hcl chain is one function with ~30 branches, so its
fires were missing from every Step 1 "fires" column (eval-step1-attribution.md). This probe uses sys.monitoring LINE
events restricted to that one code object (its own tool id, so it coexists with the HealerProbe) and, at every line,
a digest of the function's working tree (`healed_files`). A digest change between two consecutive lines is a fire of
the branch that owns the earlier line. Branches come from `eval/config/self_correct_branches.json` (comment markers
in the product source); a marker that is not found is `absent`, lines before the first marker are `prologue`.

Nothing in the product is edited or wrapped: the probe only observes locals. Report per branch: calls reached, calls
in which it changed the tree, change events.
"""
from __future__ import annotations

import importlib
import inspect
import json
import sys
import threading
import types
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

TOOL_ID = 4
TOOL_NAME = "stackvend-eval-branch-probe"
CONFIG = Path(__file__).resolve().parent.parent / "config" / "self_correct_branches.json"


def _digest(d: Any) -> Optional[int]:
    if not isinstance(d, dict):
        return None
    try:
        return hash(frozenset((k, v) for k, v in d.items() if isinstance(v, str)))
    except TypeError:
        return None


def segments_for(fn: Any, branches: List[Dict[str, Any]]) -> Tuple[List[Tuple[int, int, int]], Dict[int, str]]:
    """[(start_line, end_line, branch_index)] sorted, plus {branch_index: status}. -1 = prologue."""
    lines, first = inspect.getsourcelines(fn)
    last = first + len(lines) - 1
    starts: List[Tuple[int, int]] = []
    status: Dict[int, str] = {}
    for bi, b in enumerate(branches):
        hit = None
        for off, text in enumerate(lines):
            if text.strip().startswith(b["marker"]):
                hit = first + off
                break
        status[bi] = "anchored" if hit is not None else "absent"
        if hit is not None:
            starts.append((hit, bi))
    starts.sort()
    segs: List[Tuple[int, int, int]] = []
    prev_end = first
    if starts:
        segs.append((first, starts[0][0] - 1, -1))
    for i, (s, bi) in enumerate(starts):
        e = starts[i + 1][0] - 1 if i + 1 < len(starts) else last
        segs.append((s, e, bi))
        prev_end = e
    if not starts:
        segs.append((first, last, -1))
    return segs, status


class BranchProbe:
    def __init__(self, config_path: Path = CONFIG):
        self.cfg = json.loads(Path(config_path).read_text())
        self.branches: List[Dict[str, Any]] = self.cfg["branches"]
        self.status: Dict[int, str] = {}
        self.segs: List[Tuple[int, int, int]] = []
        self.code: Optional[types.CodeType] = None
        self._lock = threading.Lock()
        self._frames: Dict[int, Dict[str, Any]] = {}
        self.calls = 0
        self.stats: Dict[int, Dict[str, int]] = {}
        self.installed = False
        self.reason: Optional[str] = None

    def _seg_of(self, line: int) -> Optional[int]:
        for s, e, bi in self.segs:
            if s <= line <= e:
                return bi
        return None

    def install(self) -> bool:
        try:
            mod = importlib.import_module(self.cfg["module"])
            fn = inspect.unwrap(getattr(mod, self.cfg["function"]))
            self.code = fn.__code__
            self.segs, self.status = segments_for(fn, self.branches)
        except Exception as e:  # noqa: BLE001
            self.reason = f"{type(e).__name__}: {e}"[:300]
            return False
        for bi in list(self.status) + [-1]:
            self.stats[bi] = {"calls_reached": 0, "calls_fired": 0, "fires": 0}
        mon = sys.monitoring
        try:
            mon.use_tool_id(TOOL_ID, TOOL_NAME)
        except ValueError:
            self.reason = "monitoring tool id in use"
            return False
        state_local = self.cfg.get("state_local", "healed_files")
        probe = self

        def on_line(code: types.CodeType, line: int) -> Any:
            if code is not probe.code:
                return mon.DISABLE
            frame = sys._getframe(1)
            st = probe._frames.get(id(frame))
            if st is None:
                st = probe._frames[id(frame)] = {"last_seg": None, "digest": None, "reached": set(), "fired": set()}
                with probe._lock:
                    probe.calls += 1
            d = _digest(frame.f_locals.get(state_local))
            if st["last_seg"] is not None and d != st["digest"] and st["digest"] is not None:
                with probe._lock:
                    probe.stats[st["last_seg"]]["fires"] += 1
                st["fired"].add(st["last_seg"])
            seg = probe._seg_of(line)
            if seg is not None:
                st["reached"].add(seg)
                st["last_seg"] = seg
            st["digest"] = d
            return None

        def on_return(code: types.CodeType, offset: int, retval: Any) -> Any:
            if code is not probe.code:
                return mon.DISABLE
            frame = sys._getframe(1)
            st = probe._frames.pop(id(frame), None)
            if st is None:
                return None
            d = _digest(retval)
            if st["last_seg"] is not None and st["digest"] is not None and d != st["digest"]:
                with probe._lock:
                    probe.stats[st["last_seg"]]["fires"] += 1
                st["fired"].add(st["last_seg"])
            with probe._lock:
                for s in st["reached"]:
                    probe.stats[s]["calls_reached"] += 1
                for s in st["fired"]:
                    probe.stats[s]["calls_fired"] += 1
            return None

        mon.register_callback(TOOL_ID, mon.events.LINE, on_line)
        mon.register_callback(TOOL_ID, mon.events.PY_RETURN, on_return)
        mon.set_local_events(TOOL_ID, self.code, mon.events.LINE | mon.events.PY_RETURN)
        self.installed = True
        return True

    def stop(self) -> None:
        try:
            mon = sys.monitoring
            if mon.get_tool(TOOL_ID) == TOOL_NAME:
                if self.code is not None:
                    mon.set_local_events(TOOL_ID, self.code, 0)
                mon.register_callback(TOOL_ID, mon.events.LINE, None)
                mon.register_callback(TOOL_ID, mon.events.PY_RETURN, None)
                mon.free_tool_id(TOOL_ID)
        except Exception:  # noqa: BLE001
            pass

    def report(self) -> Dict[str, Any]:
        rows = []
        lines = {bi: (s, e) for s, e, bi in self.segs}
        for bi in sorted(self.stats, key=lambda x: (x < 0, x)):
            b = self.branches[bi] if bi >= 0 else {"marker": "(prologue)", "id": "-", "owner": "-", "kind": "-"}
            rows.append({"index": bi, "marker": b["marker"], "id": b["id"], "owner": b["owner"], "kind": b["kind"],
                         "status": self.status.get(bi, "prologue"), "lines": list(lines.get(bi, ())),
                         **self.stats[bi]})
        return {"installed": self.installed, "reason": self.reason, "calls": self.calls, "branches": rows}
