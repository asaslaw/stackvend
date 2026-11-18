"""SAT-44 (owner 11-02): the workload's deploy region is shown on the Workloads Catalog card and on the details page.

What was wrong: the catalog card had no region and `GET /api/workloads` did not return one; the details page had only a
small slate chip in the title line, which read "Region: Settings default" (no region name) for a workload created
before FD-7M-a recorded regions, and the details page's key facts (Status & Project) had no region.

* `GET /api/workloads` carries `region` per workload (typed str-or-null like the details route: a non-string stored
  value never fails the catalog), for administrators and for assigned users.
* The catalog card, the details header chip and the details key facts all show `workloadRegionLabel(...)`: the recorded
  region, or "<Settings default region> (Settings default)".
* None of the three is inside a block hidden for some workload states.
* Display only: nothing else in the route output changes.

Hermetic: the template file, a JavaScript engine when the machine has one, and the CC routes on an in-memory fake.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
import os
import shutil
import subprocess
import sys
from html.parser import HTMLParser
from unittest.mock import MagicMock, patch

import pytest

from fd4f_support import FakeDB

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")
DASHBOARD = os.path.join(CC_DIR, "templates", "dashboard.html")
EAST = "us-east4"


@pytest.fixture(scope="module")
def html():
    with open(DASHBOARD, encoding="utf-8") as f:
        return f.read()


# ------------------------------------------------------------------ template structure
_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}


class _Ancestors(HTMLParser):
    """Records, for each element with a data-testid, its own attributes and its ancestors' attributes."""

    def __init__(self):
        super().__init__()
        self.stack = []
        self.found = {}

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "data-testid" in a:
            self.found.setdefault(a["data-testid"], []).append((a, [dict(s[1]) for s in self.stack]))
        if tag not in _VOID:
            self.stack.append((tag, a))

    def handle_startendtag(self, tag, attrs):
        a = dict(attrs)
        if "data-testid" in a:
            self.found.setdefault(a["data-testid"], []).append((a, [dict(s[1]) for s in self.stack]))

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                return


@pytest.fixture(scope="module")
def parsed(html):
    p = _Ancestors()
    p.feed(html)
    return p.found


def _conditions(ancestors):
    """Every x-show / x-if on the element's ancestors."""
    return [v for a in ancestors for k, v in a.items() if k in ("x-show", "x-if")]


def test_catalog_card_shows_the_region_on_every_card(parsed):
    [(attrs, ancestors)] = parsed["catalog-workload-region"]
    assert "x-if" not in attrs and "x-show" not in attrs
    loops = [a.get("x-for") for a in ancestors if a.get("x-for")]
    assert loops == ["w in filteredWorkloads"]
    # the card grid is the only condition: shown for every card, whatever the workload's status
    assert _conditions(ancestors) == ["activeTab === 'workloads'",
                                      "filteredWorkloads.length > 0 && workloadCatalogFilter !== 'ARCHIVED'"]


def test_catalog_card_label_uses_the_shared_helper(html):
    start = html.index('data-testid="catalog-workload-region"')
    card_region = html[start:html.index("</p>", start)]
    assert 'x-text="workloadRegionLabel(w.region)"' in card_region


def test_details_header_chip_is_named_and_not_hidden(parsed, html):
    [(attrs, ancestors)] = parsed["workload-region"]
    assert attrs["x-show"] == "workloadDetails"
    assert attrs["x-text"] == "'📍 Region: ' + workloadRegionLabel(workloadDetails?.region)"
    assert _conditions(ancestors) == ["activeTab === 'details'"]
    assert "|| 'Settings default')" not in html   # the old label named no region


def test_details_key_facts_show_the_region(parsed):
    [(attrs, ancestors)] = parsed["workload-details-region"]
    assert "x-if" not in attrs and "x-show" not in attrs
    # inside the details body (shown once the details have loaded) and in no status-specific block
    assert _conditions(ancestors) == ["activeTab === 'details'", "!isDetailsLoading && workloadDetails"]


def test_details_key_facts_region_sits_in_status_and_project(html):
    card = html.index('>Status & Project</span>')
    fact = html.index('data-testid="workload-details-region"')
    assert card < fact < html.index('<template x-if="workloadDetails?.status === \'DECOMMISSIONED\' && '
                                    'workloadDetails?.last_active_project_id">', card)
    assert "'Region: ' + workloadRegionLabel(workloadDetails?.region)" in html[fact:fact + 400]


def test_light_theme_keeps_the_region_readable(html):
    assert "html.theme-light .region-fact {" in html
    for testid in ("catalog-workload-region", "workload-region", "workload-details-region"):
        start = html.index(f'data-testid="{testid}"')
        assert 'class="region-fact ' in html[start:start + 80], testid


# ------------------------------------------------------------------ the label helper
def _method(html, name):
    start = html.index("\n                " + name + "(")
    end = html.index("\n                },\n", start)
    return html[start:end + len("\n                },")]


LABEL_CASES = [
    # (recorded region, platformSettings, label)
    (EAST, {"orchestration": {"default_gcp_region": "us-central1"}}, EAST),
    ("us-central1", {"orchestration": {"default_gcp_region": "europe-west1"}}, "us-central1"),
    (None, {"orchestration": {"default_gcp_region": "us-central1"}}, "us-central1 (Settings default)"),
    ("", {"orchestration": {"default_gcp_region": EAST}}, EAST + " (Settings default)"),
    (None, {"orchestration": {}}, "Settings default"),
    (None, None, "Settings default"),
    (EAST, None, EAST),
]


def test_label_helper_reads_the_settings_default(html):
    fn = _method(html, "workloadRegionLabel")
    assert "if (typeof region === 'string' && region) return region;" in fn
    assert "this.platformSettings && this.platformSettings.orchestration" in fn
    assert "o.default_gcp_region + ' (Settings default)'" in fn


def _js_runner():
    if shutil.which("node"):
        return ["node", "-"], "process.stdout.write(%s)"
    if shutil.which("osascript"):
        return ["osascript", "-l", "JavaScript", "-"], "%s"
    return None, None


def test_label_helper_executes_the_table(html):
    cmd, emit = _js_runner()
    if cmd is None:
        pytest.skip("no local JavaScript engine (node or osascript); the static checks above still apply")
    obj = "var o = {\nplatformSettings: null,\n%s\n};\n" % _method(html, "workloadRegionLabel").strip().rstrip(",")
    cases = json.dumps([[r, s] for r, s, _ in LABEL_CASES])
    body = (obj + "var cases = %s;\n" % cases
            + emit % "JSON.stringify(cases.map(function (c) { o.platformSettings = c[1]; "
                     "return o.workloadRegionLabel(c[0]); }))" + ";\n")
    out = subprocess.run(cmd, input=body, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout.strip().splitlines()[-1]) == [want for *_, want in LABEL_CASES]


# ------------------------------------------------------------------ routes carry the region
def _routes(monkeypatch, store):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from routes import workloads as wl_routes

    monkeypatch.setattr(cc_db, "_db_client", False)
    monkeypatch.setattr(wl_routes, "db", store)
    return wl_routes


def _store():
    store = FakeDB()
    store.docs["workloads/east-app"] = {"product_id": "east-app", "project_id": "east-app", "status": "ACTIVE",
                                        "region": EAST}
    store.docs["workloads/legacy-app"] = {"product_id": "legacy-app", "project_id": "legacy-app", "status": "ACTIVE"}
    store.docs["workloads/odd-app"] = {"product_id": "odd-app", "project_id": "odd-app", "status": "DECOMMISSIONED",
                                       "region": {"name": EAST}}   # never a string: read as none, never a failure
    store.get_all = lambda refs: [r.get() for r in refs]
    return store


WANT = {"east-app": EAST, "legacy-app": None, "odd-app": None}


def _request(role, assigned=()):
    request = MagicMock()
    request.state.user_email = "someone@example.com"
    request.state.user_role = role
    request.state.assigned_workloads = list(assigned)
    return request


def test_schema_has_a_nullable_region(monkeypatch):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    import schemas

    for model in (schemas.WorkloadSummary, schemas.WorkloadDetailsResponse):
        assert model.model_fields["region"].default is None


def test_list_route_carries_the_region_for_administrators(monkeypatch):
    wl = _routes(monkeypatch, _store())
    from authz import UserRole

    listed = {w.product_id: w.region for w in wl.list_workloads(_request(UserRole.ADMIN))}
    assert listed == WANT


def test_list_route_carries_the_region_for_assigned_users(monkeypatch):
    wl = _routes(monkeypatch, _store())
    from authz import UserRole

    listed = {w.product_id: w.region
              for w in wl.list_workloads(_request(UserRole.VIEWER, ["east-app", "legacy-app", "odd-app"]))}
    assert listed == WANT


def test_details_route_carries_the_same_region(monkeypatch):
    wl = _routes(monkeypatch, _store())
    from authz import UserRole

    with patch.object(wl, "verify_workload_access", lambda *a, **k: None), \
         patch.object(wl, "fetch_workload_state_from_gcs", return_value=None):
        for pid, want in WANT.items():
            assert wl.get_workload_details(pid, _request(UserRole.ADMIN)).region == want


def test_recorded_region_is_a_typed_read(monkeypatch):
    wl = _routes(monkeypatch, FakeDB())
    assert wl._recorded_region({"region": EAST}) == EAST
    for data in ({}, {"region": None}, {"region": ""}, {"region": 4}, {"region": [EAST]}, None):
        assert wl._recorded_region(data) is None


def test_quick_guide_says_where_the_region_is_shown():
    text = open(os.path.join(REPO_ROOT, "documentation", "quick-guide.md"), encoding="utf-8").read()
    assert "shown on its Workloads Catalog card and on its details page" in text
    assert "(Settings default)" in text
