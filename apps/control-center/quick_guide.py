"""FD-4CV: the Control Center Guide tab (a short how-to reference).

The guide's source of truth is `documentation/quick-guide.md`. The Control Center is built from
`apps/control-center/` only, so it serves a byte-identical copy, `guide/quick-guide.md` next to this file
(tests/test_fd4cv_quick_guide.py fails when the two differ).

Two strict line formats, both documented in the guide's header comment:

* Admin-only blocks. A line that is exactly ADMIN_OPEN opens a block and a line that is exactly ADMIN_CLOSE closes
  it. Blocks do not nest and must be closed. A line that contains either marker's opening text without being exactly
  a marker is an error. Non-administrators get the guide without these blocks; administrators get every line. Marker
  lines are removed for everyone. This is display only: the API still authorizes every action.
* "Details" lines. A line that starts with DETAILS_PREFIX holds one or more `[label](target)` links separated by
  DETAILS_SEPARATOR, where target is `<file>.md` or `<file>.md#<anchor>` in the same documentation folder. They are
  the only links in the guide and serve readers of the repository. The Control Center view drops them (owner 10-21:
  the Guide tab is a self-contained quick reference and never sends people out of the Control Center).
* Section headings. In the Control Center view every `## ` heading becomes `<h2 id="guide-...">` and a table of
  contents of in-page `#guide-...` links is put before the first one. The view's only links are those.

Any format error raises GuideFormatError (no guessing, no partial output).
"""
import html
from pathlib import Path
from typing import List, Tuple

GUIDE_FILE = Path(__file__).resolve().parent / "guide" / "quick-guide.md"

ADMIN_OPEN = "<!-- admin-only -->"
ADMIN_CLOSE = "<!-- /admin-only -->"
_MARKER_STARTS = ("<!-- admin-only", "<!-- /admin-only")

DETAILS_PREFIX = "Details → "
DETAILS_SEPARATOR = " · "
LINK_OPEN = "]("
HEADING_PREFIX = "## "
ANCHOR_PREFIX = "guide-"
TOC_TITLE = "Contents:"
HEADER_OPEN = "<!--\n"
HEADER_CLOSE = "\n-->\n"


class GuideFormatError(ValueError):
    """The guide does not follow its documented line formats."""


def split_admin_blocks(text: str) -> List[Tuple[bool, str]]:
    """[(admin_only, line)] for every non-marker line, in order. Raises GuideFormatError on a malformed marker,
    a nested or unmatched marker, or an unclosed block."""
    out: List[Tuple[bool, str]] = []
    in_admin = False
    open_line = 0
    for n, line in enumerate(text.split("\n"), 1):
        if line == ADMIN_OPEN:
            if in_admin:
                raise GuideFormatError(f"line {n}: admin-only block opened inside the block opened on line {open_line}")
            in_admin, open_line = True, n
            continue
        if line == ADMIN_CLOSE:
            if not in_admin:
                raise GuideFormatError(f"line {n}: admin-only block closed but none is open")
            in_admin = False
            continue
        if any(m in line for m in _MARKER_STARTS):
            raise GuideFormatError(f"line {n}: an admin-only marker must be a line of its own, exactly "
                                   f"{ADMIN_OPEN!r} or {ADMIN_CLOSE!r}")
        out.append((in_admin, line))
    if in_admin:
        raise GuideFormatError(f"line {open_line}: admin-only block is never closed")
    return out


def filter_for_role(text: str, is_admin: bool) -> str:
    """The guide as one role sees it: marker lines removed, admin-only lines kept only for administrators."""
    return "\n".join(line for admin_only, line in split_admin_blocks(text) if is_admin or not admin_only)


def parse_details_line(line: str) -> List[Tuple[str, str]]:
    """[(label, target)] of a Details line. Raises GuideFormatError unless the whole line follows the format."""
    if not line.startswith(DETAILS_PREFIX):
        raise GuideFormatError(f"not a Details line: {line!r}")
    items = line[len(DETAILS_PREFIX):].split(DETAILS_SEPARATOR)
    links: List[Tuple[str, str]] = []
    for item in items:
        if not (item.startswith("[") and item.endswith(")")) or item.count(LINK_OPEN) != 1:
            raise GuideFormatError(f"Details item is not exactly one [label](target) link: {item!r}")
        label, target = item[1:-1].split(LINK_OPEN)
        if not label or any(c in label for c in "[]()"):
            raise GuideFormatError(f"bad Details label: {label!r}")
        doc, _, anchor = target.partition("#")
        name = doc[:-3] if doc.endswith(".md") else ""
        if (not name or any(c in target for c in "/\\()[] \t") or target.count("#") > 1
                or ("#" in target and not anchor)):
            raise GuideFormatError(f"bad Details target (want <file>.md or <file>.md#<anchor>): {target!r}")
        links.append((label, target))
    return links


def heading_anchor(heading: str) -> str:
    """In-page anchor of a section heading: ANCHOR_PREFIX + its words, lower-cased, letters and digits only."""
    words = ["".join(c for c in w if c.isalnum()) for w in heading.lower().split()]
    words = [w for w in words if w]
    if not words:
        raise GuideFormatError(f"heading has no letters or digits: {heading!r}")
    return ANCHOR_PREFIX + "-".join(words)


def _strip_header_comment(text: str) -> str:
    """The guide without its leading header comment (the writing rules for editors)."""
    if not text.startswith(HEADER_OPEN):
        return text
    if HEADER_CLOSE not in text:
        raise GuideFormatError("the header comment is never closed")
    return text.split(HEADER_CLOSE, 1)[1]


def render_for_control_center(text: str, is_admin: bool) -> str:
    """The role's view for the Guide tab: header comment and Details lines dropped, `## ` headings given in-page
    anchors, and a table of contents of those anchors before the first heading. Every other line is returned
    unchanged; a link anywhere else is a format error."""
    body: List[str] = []
    headings: List[Tuple[str, str]] = []
    for n, line in enumerate(_strip_header_comment(filter_for_role(text, is_admin)).split("\n"), 1):
        if line.startswith(DETAILS_PREFIX.rstrip()):
            parse_details_line(line)  # still validated; not shown in the Control Center
            continue
        if LINK_OPEN in line:
            raise GuideFormatError(f"view line {n}: links are allowed only on Details lines")
        if line.startswith(HEADING_PREFIX):
            title = line[len(HEADING_PREFIX):].strip()
            if not title or any(c in title for c in "[]<>"):
                raise GuideFormatError(f"view line {n}: bad section heading {line!r}")
            anchor = heading_anchor(title)
            if anchor in {a for _t, a in headings}:
                raise GuideFormatError(f"view line {n}: two sections share the anchor {anchor!r}")
            headings.append((title, anchor))
            body.append(f'<h2 id="{anchor}">{html.escape(title)}</h2>')
            continue
        body.append(line)
    if not headings:
        return "\n".join(body)
    first = body.index(f'<h2 id="{headings[0][1]}">{html.escape(headings[0][0])}</h2>')
    toc = [TOC_TITLE, ""] + [f"- [{title}](#{anchor})" for title, anchor in headings] + [""]
    return "\n".join(body[:first] + toc + body[first:])


def load_for_role(is_admin: bool) -> str:
    """Read the served copy and render it for the role. Raises OSError / GuideFormatError."""
    return render_for_control_center(GUIDE_FILE.read_text(encoding="utf-8"), is_admin)
