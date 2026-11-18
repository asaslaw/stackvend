"""Map raw OpenTofu/Terraform `validate -json` diagnostics to typed Diagnostics (lane 8B plan §4.1-§4.2).

The only text processing of tool output here is a naming function: code = "TF." + SLUG(summary), where SLUG deletes
each double-quoted span the engine inserts (identifiers), upper-cases, and maps runs of non-alphanumerics to "_". It
never decides routing, repair scope or a rewrite. Locations come from the diagnostic's own `range`; the enclosing
top-level block is found with exact python-hcl2 line ranges; a referenced address is read from the source bytes the
engine points at and parsed with the Terraform address grammar (no pattern guessing).
"""
from __future__ import annotations

from typing import Any, List, Mapping, Optional, Tuple

try:
    from shared.diagnostics import Diagnostic
except ImportError:  # pragma: no cover
    from ...shared.diagnostics import Diagnostic  # type: ignore

from ..assembly import index_blocks

RESERVED_ROOTS = frozenset({"path", "terraform", "each", "count", "self", "var", "local"})


MAX_CODE_SLUG = 80


def slug(summary: str) -> str:
    """Naming only. Engine summaries are "<Title>" or "<Title>: <instance detail>" (e.g. "Cycle: module.a, module.b");
    the detail after the first ": " and every double-quoted identifier are dropped so a code names the kind of
    finding, never the instance (stable fingerprints); capped at MAX_CODE_SLUG characters."""
    title = (summary or "").split(": ", 1)[0]
    out: List[str] = []
    in_quote = False
    for ch in title:
        if ch == '"':
            in_quote = not in_quote
            continue
        if in_quote:
            continue
        out.append(ch.upper() if ch.isalnum() else "_")
    text = "".join(out)
    while "__" in text:
        text = text.replace("__", "_")
    return text.strip("_")[:MAX_CODE_SLUG].strip("_") or "UNKNOWN"


def tf_code(summary: str) -> str:
    return "TF." + slug(summary)


def _split_address(text: str) -> List[str]:
    """Tokenize a Terraform reference: identifiers separated by '.', index groups `[...]` kept attached to the
    preceding identifier; stops at the first character that cannot continue a reference."""
    parts: List[str] = []
    cur = ""
    i = 0
    while i < len(text):
        ch = text[i]
        if ch.isalnum() or ch in "_-":
            cur += ch
        elif ch == ".":
            if not cur:
                break
            parts.append(cur)
            cur = ""
        elif ch == "[":
            depth, j = 0, i
            while j < len(text):
                if text[j] == "[":
                    depth += 1
                elif text[j] == "]":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            cur += text[i:j + 1]
            i = j
        else:
            break
        i += 1
    if cur:
        parts.append(cur)
    return parts


def referenced_object(text: str) -> Optional[str]:
    """The object address a reference names: `type.name`, `module.name`, `data.type.name` (index dropped);
    None for reserved roots (var/local/path/...) or text that is not a reference."""
    parts = [p.split("[", 1)[0] for p in _split_address((text or "").strip())]
    if not parts or not parts[0] or parts[0][0].isdigit():
        return None
    if parts[0] in RESERVED_ROOTS:
        return None
    if parts[0] == "module":
        return f"module.{parts[1]}" if len(parts) >= 2 else None
    if parts[0] == "data":
        return f"data.{parts[1]}.{parts[2]}" if len(parts) >= 3 else None
    return f"{parts[0]}.{parts[1]}" if len(parts) >= 2 else None


def _traversal_ending_at(raw: bytes, end: int) -> str:
    """The reference traversal whose last byte is raw[end-1]: walk back over the reference grammar (identifier
    characters, '.', and balanced `[...]` index groups). Used when the engine's range is one attribute step
    (`.service_url` of `module.compute.service_url`, "Unsupported attribute"): the object is the traversal before it."""
    i = end
    while i > 0:
        ch = chr(raw[i - 1])
        if ch.isalnum() or ch in "_-.":
            i -= 1
        elif ch == "]":
            depth, j = 0, i - 1
            while j >= 0:
                c = chr(raw[j])
                if c == "]":
                    depth += 1
                elif c == "[":
                    depth -= 1
                    if depth == 0:
                        break
                j -= 1
            if j < 0:
                break
            i = j
        else:
            break
    return raw[i:end].decode("utf-8", errors="ignore")


def _byte_slice(text: str, start: Optional[int], end: Optional[int]) -> str:
    if start is None or end is None:
        return ""
    raw = text.encode("utf-8")
    return raw[start:end].decode("utf-8", errors="ignore")


def enclosing_block(text: str, line: Optional[int]) -> Optional[Tuple[str, int, int]]:
    """(key, start, end) of the top-level block whose exact range contains `line`."""
    if not line or not text:
        return None
    blocks = index_blocks(text)
    for b in blocks or []:
        if b.start <= line <= b.end:
            return b.key, b.start, b.end
    return None


def map_raw_diagnostic(raw: Mapping[str, Any], files: Mapping[str, str], *, source: str = "precommit",
                       iteration: int = 0) -> Tuple[Diagnostic, Optional[str]]:
    """-> (Diagnostic, referenced object address or None). The referenced object (the source bytes the engine points
    at, parsed with the address grammar) is also the Diagnostic's `symbol`, so two undeclared references in one block
    have distinct fingerprints. file "<unlocated>" when the engine gave no location (routes to PLATFORM_DEFECT)."""
    rng = raw.get("range") or {}
    path = rng.get("filename") or ""
    start = rng.get("start") or {}
    end = rng.get("end") or {}
    text = files.get(path, "") if path else ""
    block = enclosing_block(text, start.get("line")) if path.endswith(".tf") else None
    snippet = (raw.get("snippet") or {}).get("code")
    subject = _byte_slice(text, start.get("byte"), end.get("byte"))
    target = referenced_object(subject) if subject else None
    if target is None and subject.startswith(".") and isinstance(start.get("byte"), int):
        # S2-B B4: the range is one attribute step (e.g. "Unsupported attribute" on `module.compute.service_url`
        # points at `.service_url`); the referenced object is the traversal that step belongs to, read from the same
        # source bytes with the same address grammar (replaces HC-05's service_url/iap_client_id rewrites: the
        # repair hint for module.* then lists the module's real outputs).
        target = referenced_object(_traversal_ending_at(text.encode("utf-8"), start["byte"]) + subject)
    diag = Diagnostic(
        tool="tofu", code=tf_code(raw.get("summary") or ""),
        severity="warning" if raw.get("severity") == "warning" else "error",
        file=path or "<unlocated>", line=start.get("line"), column=start.get("column"), end_line=end.get("line"),
        block_address=block[0] if block else None, symbol=target, message=raw.get("summary") or "",
        detail=raw.get("detail") or None, snippet=snippet, source=source, iteration=iteration)
    return diag, target
