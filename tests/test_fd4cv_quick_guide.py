"""FD-4CV: the Control Center Guide tab (documentation/quick-guide.md).

Pins:
- the Control Center copy is byte-identical to the documentation source;
- the admin-only marker parser (apps/control-center/quick_guide.py) is strict: balanced, no nesting, markers on their
  own line; non-administrators never get admin-only lines, administrators get every line; text without markers is
  returned unchanged (Do No Harm);
- the guide's writing rules from its header comment: every **bold** name is visible text in dashboard.html, links
  appear only on "Details →" lines, every link names an existing documentation file and heading anchor (GitHub
  side), every section ends with one Details line;
- the Control Center view (owner 10-21): no Details lines and no link that leaves the page, a table of contents whose
  in-page anchors resolve to the view's headings and survive the dashboard's DOMPurify sanitizer;
- no owner identifiers, never the old product name;
- the nav: "Guide" sits directly before "Settings" and is visible to every role;
- GET /api/guide end to end on the real app (hermetic harness): administrators get the admin sections, a viewer does
  not, anonymous is refused;
- FD-4CV-b: the admin-only "Understanding Settings" section (listed before "Where to get help", short, its stated
  defaults equal to the settings models' defaults).
"""
import hermetic_guard  # noqa: F401,E402  (lane 2: must stay the first import; tests/hermetic_guard.py)

import importlib.util
import json
import os
import subprocess
import sys
from html.parser import HTMLParser
from pathlib import Path

import pytest

import owner_identifiers

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
DOCS = REPO / "documentation"
SOURCE = DOCS / "quick-guide.md"
CC = REPO / "apps" / "control-center"
COPY = CC / "guide" / "quick-guide.md"
DASHBOARD = CC / "templates" / "dashboard.html"


def _load_qg():
    spec = importlib.util.spec_from_file_location("fd4cv_quick_guide", CC / "quick_guide.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


QG = _load_qg()
GUIDE = SOURCE.read_text(encoding="utf-8")


def _body(text: str) -> str:
    """The guide without its leading header comment (the writing rules)."""
    assert text.startswith("<!--\n"), "the guide starts with its header comment"
    return text.split("\n-->\n", 1)[1]


# ------------------------------------------------------------------ copy parity
def test_control_center_copy_is_byte_identical():
    assert COPY.read_bytes() == SOURCE.read_bytes(), (
        "apps/control-center/guide/quick-guide.md must be a byte-identical copy of documentation/quick-guide.md: "
        "edit the documentation file, then copy it")
    assert QG.GUIDE_FILE == COPY.resolve()


# ------------------------------------------------------------------ admin-only marker parser
OPEN, CLOSE = "<!-- admin-only -->", "<!-- /admin-only -->"


def test_parser_strips_admin_blocks_for_non_admins_and_keeps_all_for_admins():
    text = "\n".join(["# T", "- everyone", OPEN, "- admin one", "- admin two", CLOSE, "- everyone again", ""])
    assert QG.filter_for_role(text, is_admin=False) == "# T\n- everyone\n- everyone again\n"
    assert QG.filter_for_role(text, is_admin=True) == "# T\n- everyone\n- admin one\n- admin two\n- everyone again\n"


def test_parser_do_no_harm_without_markers():
    text = "# Title\n\n- **Bold** item\n- `code`\n\nplain <!-- an ordinary comment --> text\n"
    assert QG.filter_for_role(text, is_admin=False) == text
    assert QG.filter_for_role(text, is_admin=True) == text
    assert QG.render_for_control_center(text, is_admin=False) == text


@pytest.mark.parametrize("text, why", [
    (f"{OPEN}\n- a\n{OPEN}\n- b\n{CLOSE}\n{CLOSE}\n", "nested"),
    (f"- a\n{CLOSE}\n", "close without open"),
    (f"{OPEN}\n- a\n", "never closed"),
    (f" {OPEN}\n- a\n{CLOSE}\n", "leading space"),
    (f"{OPEN} \n- a\n{CLOSE}\n", "trailing space"),
    (f"- a {OPEN}\n- b\n{CLOSE}\n", "inline open"),
    (f"{OPEN}\n- a {CLOSE}\n", "inline close"),
    ("<!-- admin-only-->\n- a\n<!-- /admin-only -->\n", "misspelled open"),
    ("<!-- admin-only -->\n- a\n<!-- /admin-only-->\n", "misspelled close"),
])
def test_parser_rejects_malformed_markers(text, why):
    with pytest.raises(QG.GuideFormatError):
        QG.filter_for_role(text, is_admin=True)
    with pytest.raises(QG.GuideFormatError):
        QG.filter_for_role(text, is_admin=False)


def test_real_guide_admin_view_differs_only_by_admin_blocks():
    pairs = QG.split_admin_blocks(GUIDE)
    admin_lines = [line for admin_only, line in pairs if admin_only and line.strip()]
    assert len(admin_lines) >= 10, "the guide has admin-only sections"
    admin_view = QG.filter_for_role(GUIDE, is_admin=True)
    user_view = QG.filter_for_role(GUIDE, is_admin=False)
    assert OPEN not in admin_view and CLOSE not in admin_view
    assert OPEN not in user_view and CLOSE not in user_view
    assert admin_view == "\n".join(line for line in GUIDE.split("\n") if line not in (OPEN, CLOSE))
    user_lines = set(user_view.split("\n"))
    for line in admin_lines:
        assert line not in user_lines, line
    # the whole Emergency Stop / Maintenance Mode section is administrator-only
    assert "## Emergency Stop or Maintenance Mode" in admin_view
    assert "Emergency Stop or Maintenance Mode" not in user_view
    assert "ENGAGE EMERGENCY STOP" not in user_view


# Every admin-only block of the real guide, as (section heading, first line of the block). A misspelled marker pair
# would leave its block visible to everyone; this list (and the comment check below) makes that a test failure.
EXPECTED_ADMIN_BLOCKS = [
    ("Submit a spec", "- In **Workloads Catalog**, click **New Workload** (administrators only)."),
    ("Approve a plan or a release", "- Require plan approval on every run: Settings, **Parameters**, **Require Plan Approval for Every Run of Every Workload (Architect HITL Gate)**. Human review of release pull requests for new workloads: **Force HITL for All New Workloads (Auto-Merge: OFF)** (on by default; turning it off lets generated code merge and deploy without a human look)."),
    ("New workloads start frozen", "- To unfreeze: open the workload, find **Workload Governance & Autonomy Controls**, click **Unfreeze**. The card's other controls stay greyed out until you do. **Freeze Code** freezes it again."),
    ("Budget breach", "- The policy that **Platform Default** stands for: Settings, **Parameters**, **FinOps & Budget Controls**, **Default Budget Breach Enforcement Policy**. It applies to workloads created after the save. The same card sets the budget a new workload starts with (**Default Monthly Budget Ceiling ($ USD)**, $40), when a warning is recorded (**Warning Threshold (%)**, 80) and when the policy fires (**Circuit Breaker (%)**, 100 = at the ceiling)."),   # FD-4CI-b
    (None, "## Emergency Stop or Maintenance Mode"),
    ("Decommission and sandbox expiry", "- On a sandbox's page: **Extend (+30 Days)** (at most 3 times and 90 days in total), **Promote to Production** (no expiry) or **Decommission Now**."),
    ("Users and roles", "- Add or change a user: Settings, **Access Control**, **Grant Access**. Adding an address that already exists replaces its role and workloads."),
    (None, "## Understanding Settings"),
]


def test_real_guide_admin_blocks_are_exactly_the_expected_ones():
    blocks, section, prev_admin = [], None, False
    for admin_only, line in QG.split_admin_blocks(_body(GUIDE)):
        if admin_only and not prev_admin:
            blocks.append((section, line))
        if line.startswith("## ") and not admin_only:
            section = line[3:]
        prev_admin = admin_only
    # the block that is a whole section starts at its heading; it has no enclosing visible section
    blocks = [(None if line.startswith("## ") else sec, line) for sec, line in blocks]
    assert blocks == EXPECTED_ADMIN_BLOCKS


def test_guide_body_has_no_html_comment_except_exact_markers():
    for line in _body(GUIDE).split("\n"):
        if "<!--" in line or "-->" in line:
            assert line in (OPEN, CLOSE), f"only exact admin-only marker lines may be HTML comments: {line!r}"


# ------------------------------------------------------------------ Details lines
def test_details_line_parser():
    assert QG.parse_details_line("Details → [A](user-guide.md#x) · [B](known-limitations.md)") == [
        ("A", "user-guide.md#x"), ("B", "known-limitations.md")]
    for bad in ("Details → ", "Details → A", "Details → [A](user-guide.md#x), [B](a.md)",
                "Details → [A](../README.md)", "Details → [A](https://example.com/a.md)", "Details → [A](a.txt)",
                "Details → [A](a.md#)", "Details → [A](a.md#x#y)", "Details → [](a.md)", "Details → [A](a b.md)",
                "Details →[A](a.md)"):
        with pytest.raises(QG.GuideFormatError):
            QG.parse_details_line(bad)


VENDOR = CC / "static" / "vendor"


def _links(view: str):
    """[(label, href)] of every markdown link in a Control Center view (strict: the view's only links are TOC lines)."""
    out = []
    for line in view.split("\n"):
        if "](" in line:
            assert line.startswith("- [") and line.endswith(")") and line.count("](") == 1, line
            label, href = line[3:-1].split("](")
            out.append((label, href))
    return out


def _h2_ids(view: str):
    out = []
    for line in view.split("\n"):
        if line.startswith("<h2 "):
            assert line.startswith('<h2 id="') and line.endswith("</h2>"), line
            out.append((line[len('<h2 id="'):line.index('">')], line[line.index('">') + 2:-len("</h2>")]))
    return out


@pytest.mark.parametrize("is_admin", [True, False])
def test_control_center_view_stays_in_the_control_center(is_admin):
    view = QG.render_for_control_center(GUIDE, is_admin)
    lines = view.split("\n")
    assert not [line for line in lines if line.startswith("Details")], "Details lines are not shown in the CC"
    assert "http://" not in view and "https://" not in view
    assert ".md)" not in view and ".md#" not in view and 'href="' not in view
    assert "<!--" not in view, "header comment and markers are not sent"
    links = _links(view)
    assert links and all(href.startswith("#" + QG.ANCHOR_PREFIX) for _l, href in links)


@pytest.mark.parametrize("is_admin", [True, False])
def test_toc_anchors_resolve_to_headings_in_the_view(is_admin):
    view = QG.render_for_control_center(GUIDE, is_admin)
    role_view = QG.filter_for_role(GUIDE, is_admin)
    headings = [line[3:] for line in role_view.split("\n") if line.startswith("## ")]
    ids = _h2_ids(view)
    assert [title for _id, title in ids] == headings
    assert len({i for i, _t in ids}) == len(ids)
    assert _links(view) == [(title, "#" + i) for i, title in ids], "TOC lists every section, in order"
    assert view.index(QG.TOC_TITLE) < view.index("<h2 ")
    assert ("Emergency Stop or Maintenance Mode" in view) is is_admin
    # every other line of the role's view is shown unchanged, in order (headings and Details lines aside)
    kept = [line for line in _body(role_view).split("\n") if not line.startswith(("Details", "## "))]
    shown = [line for line in view.split("\n") if not line.startswith("<h2 ")]
    toc_end = shown.index(QG.TOC_TITLE)
    shown = shown[:toc_end] + shown[toc_end + 2 + len(ids) + 1:]
    assert shown == kept


def test_toc_anchors_survive_the_dashboard_sanitizer():
    """The Guide HTML goes through the dashboard's sanitizeHtml (DOMPurify with its default profile). Its defaults keep
    `id` on headings and `href` on links, and a `#...` href passes its URI check (the first character is not a letter);
    SANITIZE_DOM only drops ids that name document/form properties, which `guide-...` never does."""
    dash = DASHBOARD.read_text(encoding="utf-8")
    helper = dash[dash.index("window.sanitizeHtml = function"):dash.index("window.safeUrl = function")]
    assert "USE_PROFILES: { html: true }" in helper
    for restriction in ("ALLOWED_ATTR", "FORBID_ATTR", "ALLOWED_URI_REGEXP", "SANITIZE_NAMED_PROPS", "ALLOWED_TAGS",
                        "FORBID_TAGS"):
        assert restriction not in helper, restriction
    purify = (VENDOR / "purify-3.2.6.min.js").read_text(encoding="utf-8")
    assert '"href","hreflang","id"' in purify  # DOMPurify's default HTML attribute allow-list
    for is_admin in (True, False):
        view = QG.render_for_control_center(GUIDE, is_admin)
        for anchor, _title in _h2_ids(view):
            assert anchor.startswith(QG.ANCHOR_PREFIX)
            assert all(c.islower() or c.isdigit() or c == "-" for c in anchor[len(QG.ANCHOR_PREFIX):]), anchor
            assert "x-" not in anchor[:2] and not anchor.startswith(("@", ":"))


def test_render_rejects_bad_headings_and_stray_links():
    with pytest.raises(QG.GuideFormatError):
        QG.render_for_control_center("- see [x](user-guide.md)\n", is_admin=True)
    with pytest.raises(QG.GuideFormatError):
        QG.render_for_control_center("## A <b>\n", is_admin=True)
    with pytest.raises(QG.GuideFormatError):
        QG.render_for_control_center("## Same\n\n## same!\n", is_admin=True)
    with pytest.raises(QG.GuideFormatError):
        QG.render_for_control_center("Details → not a link\n", is_admin=True)
    assert QG.heading_anchor("Approve a plan or a release") == "guide-approve-a-plan-or-a-release"
    assert QG.heading_anchor("Emergency Stop or Maintenance Mode") == "guide-emergency-stop-or-maintenance-mode"


def _gh_slug(heading: str) -> str:
    s = heading.strip().lower()
    s = "".join(c for c in s if c.isalnum() or c in " -_")
    return s.replace(" ", "-")


def _anchors(md_text: str) -> set:
    out, seen, fence = set(), {}, False
    for line in md_text.split("\n"):
        if line.startswith("```"):
            fence = not fence
            continue
        if fence or not line.startswith("#"):
            continue
        hashes = len(line) - len(line.lstrip("#"))
        if hashes > 6 or line[hashes:hashes + 1] != " ":
            continue
        slug = _gh_slug(line[hashes + 1:])
        n = seen.get(slug, 0)
        seen[slug] = n + 1
        out.add(slug if n == 0 else f"{slug}-{n}")
    return out


def test_every_link_is_on_a_details_line_and_resolves():
    body = _body(GUIDE)
    lines = body.split("\n")
    targets = []
    for i, line in enumerate(lines):
        if line.startswith("Details"):
            targets += [t for _label, t in QG.parse_details_line(line)]
            assert lines[i - 1] == "", f"Details line needs a blank line before it: {line!r}"
        else:
            assert "](" not in line, f"link outside a Details line: {line!r}"
            assert "http://" not in line and "https://" not in line, line
    assert len(targets) >= 15
    for target in targets:
        doc, _, anchor = target.partition("#")
        path = DOCS / doc
        assert path.is_file(), f"{target}: no documentation/{doc}"
        if anchor:
            assert anchor in _anchors(path.read_text(encoding="utf-8")), f"{target}: no such heading in {doc}"


def test_every_section_ends_with_one_details_line():
    for is_admin in (True, False):
        view = _body(QG.filter_for_role(GUIDE, is_admin))
        sections = view.split("\n## ")[1:]
        assert len(sections) >= (10 if is_admin else 8)
        for sec in sections:
            content = [line for line in sec.split("\n") if line.strip()]
            details = [line for line in content if line.startswith("Details")]
            assert len(details) == 1 and content[-1] == details[0], sec.split("\n", 1)[0]


def test_required_sections_present():
    view = QG.filter_for_role(GUIDE, is_admin=True)
    headings = [line[3:] for line in view.split("\n") if line.startswith("## ")]
    for want in ("Submit a spec", "Watch a build", "Approve a plan or a release", "New workloads start frozen",
                 "Budget breach", "Emergency Stop or Maintenance Mode", "Decommission and sandbox expiry",
                 "Users and roles", "Understanding Settings", "Where to get help"):
        assert want in headings, want


# ------------------------------------------------------------------ FD-4CV-b: Understanding Settings (admin only)
SETTINGS_SECTION = "Understanding Settings"


@pytest.mark.parametrize("is_admin", [True, False])
def test_understanding_settings_is_admin_only_and_listed_before_help(is_admin):
    view = QG.render_for_control_center(GUIDE, is_admin)
    toc = [label for label, _href in _links(view)]
    assert (SETTINGS_SECTION in toc) is is_admin
    assert ("<h2 id=\"guide-understanding-settings\">" in view) is is_admin
    assert ("Freeze new workloads by default** (on)" in view) is is_admin
    assert toc[-1] == "Where to get help"
    if is_admin:
        assert toc[-3:] == ["Users and roles", SETTINGS_SECTION, "Where to get help"]


def _settings_section() -> str:
    admin = _body(QG.filter_for_role(GUIDE, is_admin=True))
    return admin.split("\n## " + SETTINGS_SECTION + "\n", 1)[1].split("\n## ", 1)[0]


def test_understanding_settings_is_short_and_names_the_key_settings_with_defaults():
    sec = _settings_section()
    bullets = [line for line in sec.split("\n") if line.lstrip().startswith("- ")]
    assert len(bullets) <= 40, "keep the section short enough to scan"
    for name, default in (("Freeze new workloads by default", "(on)"), ("Typed infrastructure (generate mode)", "(on)"),
                          ("Maintenance Mode", "(off)"), ("Default Budget Breach Enforcement Policy", "(**Autonomous Scale-to-Zero**)"),
                          ("Require Plan Approval for Every Run of Every Workload (Architect HITL Gate)", "(off)"),
                          ("Architectural Plan Approval Trigger Policy", "(`ON_COMPLIANCE_CONFLICT`)"),
                          ("Force HITL for All New Workloads (Auto-Merge: OFF)", "(on)"),
                          ("Drive Folder Auto-Discovery", "(off)"), ("Default Workload Region", "(`us-central1`)")):
        assert f"- **{name}** {default}" in sec, name
    # TI-5-R2 lifted the TI-5c-a hold: all five private-data services are on the typed path
    assert "Cloud SQL, Redis, AlloyDB, Vertex AI endpoints and Bigtable work this way too" in sec and "classic path for now" not in sec
    for tab in ("Parameters", "GCP Folders", "Network & IPAM", "Modules & Bundles", "Agent Skills", "Agent Prompts",
                "Cloud Quotas", "Access Control", "Emergency Stop"):
        assert f"**{tab}**" in sec, tab


def test_understanding_settings_defaults_match_the_settings_models():
    """The defaults the section states are the settings models' defaults (shared/settings.py)."""
    from shared import iac_intent, settings as mod  # noqa: E402  (repo root is on sys.path: tests/conftest.py)
    gov, fin, orch = mod.GovernanceSettings(), mod.FinOpsSettings(), mod.OrchestrationSettings()
    models, rt = mod.AgentModelSettings(), mod.RuntimeSettings()
    assert gov.freeze_new_workloads is True and gov.iac_intent_generate is True and gov.maintenance_mode is False
    assert gov.require_plan_approval is False and gov.plan_approval_policy == "ON_COMPLIANCE_CONFLICT"
    assert gov.default_require_human_code_review is True and gov.drive_folder_auto_discovery is False
    assert gov.strict_compliance_gates is True and gov.require_hitl_for_destructive_tf is True
    assert fin.default_breach_policy.value == "AUTONOMOUS_SCALE_TO_ZERO"
    assert orch.default_gcp_region == "us-central1" and orch.default_iac_engine.value == "OPENTOFU"
    assert (orch.terraform_version, orch.tofu_version) == ("1.5.7", "1.9.0")
    assert models.max_swarm_token_envelope == 350_000 and models.repair_model == ""
    assert {models.architect_model, models.developer_model, models.assistant_model,
            models.finops_model} == {"gemini-4-carbon"}
    assert models.fallback_models == ["gemini-4-argon", "gemini-3.8-flash", "gemini-3.7-flash"]
    assert (models.max_output_tokens, models.architect_max_output_tokens, models.developer_max_output_tokens) == (
        65536, 16384, 65536)
    assert (rt.default_python_version, rt.cloud_build_machine_type, rt.cloud_build_timeout_seconds) == (
        "3.13", "E2_HIGHCPU_8", 1200)
    # TI-5-R2 lifted the TI-5c-a hold the section used to describe: nothing is held back
    assert iac_intent.NOT_YET_WIRED_MODULES == frozenset()


# ------------------------------------------------------------------ UI names
def _bold_names(text: str):
    names = []
    for line in _body(text).split("\n"):
        parts = line.split("**")
        assert len(parts) % 2 == 1, f"bold must open and close on one line: {line!r}"
        names += parts[1::2]
    return names


class _VisibleText(HTMLParser):
    """Text a user can see in dashboard.html: text nodes outside <script>/<style> (comments are not text), plus the
    x-text expressions that put labels on buttons (for example 'Unfreeze' / 'Freeze Code')."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.skip = 0
        self.chunks = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.skip += 1
        for k, v in attrs:
            if k == "x-text" and v:
                self.chunks.append(v)

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self.skip:
            self.skip -= 1

    def handle_data(self, data):
        if not self.skip:
            self.chunks.append(" ".join(data.split()))


def _visible_dashboard_text() -> str:
    p = _VisibleText()
    p.feed(DASHBOARD.read_text(encoding="utf-8"))
    return "\n".join(p.chunks)


VISIBLE = _visible_dashboard_text()


def test_every_bold_ui_name_is_visible_in_the_dashboard():
    names = _bold_names(GUIDE)
    assert len(names) >= 40
    missing = sorted({n for n in names if n not in VISIBLE})
    assert missing == [], f"bold names not shown in dashboard.html (write UI names exactly as on screen): {missing}"


def test_bold_name_check_catches_unknown_and_non_visible_names():
    fake = "<!--\nrules\n-->\n- click **Launch The Rocket Now** or **loadGuide** or **FD-4AR**\n"
    dash = DASHBOARD.read_text(encoding="utf-8")
    assert "loadGuide" in dash and "FD-4AR" in dash  # present only in script / comments, never shown
    assert [n for n in _bold_names(fake) if n not in VISIBLE] == ["Launch The Rocket Now", "loadGuide", "FD-4AR"]


# ------------------------------------------------------------------ public-content hygiene
def test_no_owner_identifiers_or_old_product_name():
    for path in (SOURCE, COPY, CC / "quick_guide.py"):
        text = path.read_text(encoding="utf-8")
        assert owner_identifiers.find(text) == [], path
    assert "castor" not in GUIDE.lower()


# ------------------------------------------------------------------ nav
class _NavButtons(HTMLParser):
    def __init__(self):
        super().__init__()
        self.depth = 0
        self.in_nav = False
        self.buttons = []

    def handle_starttag(self, tag, attrs):
        if tag == "nav" and not self.buttons and not self.in_nav:
            self.in_nav = True
        elif self.in_nav and tag == "button":
            self.buttons.append(dict(attrs))

    def handle_endtag(self, tag):
        if tag == "nav" and self.in_nav:
            self.in_nav = False


def test_guide_tab_sits_directly_before_settings_and_is_visible_to_everyone():
    p = _NavButtons()
    p.feed(DASHBOARD.read_text(encoding="utf-8"))
    clicks = [b.get("@click", "") for b in p.buttons]
    assert clicks[:7] == ["activeTab = 'pipeline'", "activeTab = 'flightdeck'", "activeTab = 'approvals'; fetchApprovals()",
                          "activeTab = 'workloads'", "activeTab = 'assistant'", "activeTab = 'guide'; loadGuide()",
                          "activeTab = 'settings'"]
    guide = p.buttons[5]
    assert "x-show" not in guide and "x-if" not in guide
    assert p.buttons[6].get("x-show") == "userRole === 'ADMIN'"
    dash = DASHBOARD.read_text(encoding="utf-8")
    assert "📖 Guide" in dash
    assert 'x-html="renderMarkdown(guideMarkdown)"' in dash
    assert "fetch('/api/guide')" in dash


# ------------------------------------------------------------------ GET /api/guide end to end
def _harness():
    marker = "# ================================================================ public mode"
    src_path = os.path.join(HERE, "cc_identity_harness.py")
    with open(src_path, encoding="utf-8") as f:
        src = f.read()
    assert marker in src, "FD-4E harness prefix changed"
    ns = {"__file__": src_path, "__name__": "cc_fd4cv_guide_harness"}
    exec(compile(src.split(marker, 1)[0], src_path, "exec"), ns)
    ns["mode"]("")
    os.environ.pop("TEST_MODE", None)
    client = ns["client"]
    out = {}
    for who, cookies in (("admin", ns["OWNER_COOKIE"]), ("viewer", ns["VIEWER_COOKIE"]), ("anonymous", None)):
        r = client.get("/api/guide", cookies=cookies) if cookies else client.get("/api/guide")
        out[who] = {"status": r.status_code, "body": r.json() if r.status_code == 200 else None}
    print(json.dumps({"results": out, "network_attempts": ns["NETWORK_ATTEMPTS"]}))


@pytest.fixture(scope="module")
def http_results():
    env = hermetic_guard.child_env(drop=("TEST_MODE", "K_SERVICE", "SESSION_SECRET", "ADMIN_EMAIL", "VENDING_SERVICE_URL"),
                                   extra={"PROJECT_ID": "mock-stackvend-project", "GOOGLE_CLOUD_PROJECT": "mock-stackvend-project"})
    out = subprocess.run([sys.executable, os.path.abspath(__file__), "--harness"],
                         capture_output=True, text=True, timeout=300, env=env)
    assert out.returncode == 0, out.stderr[-4000:]
    data = json.loads(out.stdout.strip().splitlines()[-1])
    assert data["network_attempts"] == []
    return data["results"]


def test_api_guide_admin_sees_admin_sections(http_results):
    r = http_results["admin"]
    assert r["status"] == 200
    assert r["body"]["admin_sections_shown"] is True
    assert r["body"]["markdown"] == QG.render_for_control_center(GUIDE, is_admin=True)
    assert "ENGAGE EMERGENCY STOP" in r["body"]["markdown"]
    assert "## Understanding Settings" not in r["body"]["markdown"]  # headings become <h2 id=...> in the view
    assert '<h2 id="guide-understanding-settings">' in r["body"]["markdown"]


def test_api_guide_viewer_does_not_see_admin_sections(http_results):
    r = http_results["viewer"]
    assert r["status"] == 200
    assert r["body"]["admin_sections_shown"] is False
    assert r["body"]["markdown"] == QG.render_for_control_center(GUIDE, is_admin=False)
    assert "ENGAGE EMERGENCY STOP" not in r["body"]["markdown"]
    assert "Understanding Settings" not in r["body"]["markdown"]


def test_api_guide_requires_sign_in(http_results):
    assert http_results["anonymous"]["status"] == 401


if __name__ == "__main__" and "--harness" in sys.argv:
    _harness()
