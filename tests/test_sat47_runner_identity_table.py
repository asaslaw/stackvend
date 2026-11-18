"""SAT-47 (owner 11-02, display only): the Control Center's Terraform runner identity table is easier to read and
keeps closed workloads apart.

* Vending `RunnerIdentityBackfill.status()` adds per row the workload ledger status (`workloads/{pid}.status`, exact
  value; `unknown` when the record cannot be read, is missing or holds no string status, never guessed) and `closed`
  (exactly DECOMMISSIONED / ARCHIVED / DELETED), plus `summary` (live / ready / not ready / closed) and
  `record_count`. status() still writes nothing; the backfill itself is unchanged.
* The card: header row with a bottom rule, row lines, zebra rows, light-theme variants, long values truncated with
  the full text on hover, the Run button in its own right-aligned "Action" column with exactly today's condition for
  live rows, closed rows folded under a toggle with no Run button, a totals line and a "Showing N of M records" line.
Hermetic fakes only.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import os
import re
from html.parser import HTMLParser

import pytest

from test_fd7l_phase3_backfill import PID, W, rib  # noqa: F401
from test_fd7l_phase3_readers import _Resp, cc  # noqa: F401  (fixture reused by name)

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DASHBOARD = os.path.join(REPO_ROOT, "apps", "control-center", "templates", "dashboard.html")
RUN_CONDITION = "r.status !== 'READY' || r.step_b !== 'READY'"   # 11-02: a READY row with nothing to migrate (never deployed) has no migrated_at and needs no Run


@pytest.fixture
def w():
    return W()


def _add(world, pid, status=..., ledger=True):
    world.db.docs[f"workload_provenance/{pid}"] = {"created_by": "stackvend-vending",
                                                    "project_id": f"{pid}-proj", "project_number": "9"}
    if ledger:
        doc = {"product_id": pid, "project_id": f"{pid}-proj"}
        if status is not ...:
            doc["status"] = status
        world.db.docs[f"workloads/{pid}"] = doc


def _rows(st):
    return {r["product_id"]: r for r in st["workloads"]}


# ---------------------------------------------------------------------------------------------- vending status()
def test_status_row_carries_the_exact_ledger_status_and_writes_nothing(w):
    st = w.backfill().status()
    (row,) = st["workloads"]
    assert row["workload_status"] == "ACTIVE" and row["closed"] is False
    assert st["summary"] == {"live": 1, "ready": 0, "not_ready": 1, "closed": 0}
    assert st["record_count"] == 1 and st["truncated"] is False
    assert w.db.writes == [] and w.google.mutating() == []


@pytest.mark.parametrize("status", sorted(rib.CLOSED_WORKLOAD_STATUSES))
def test_closed_statuses_are_flagged_closed(w, status):
    _add(w, "gone-1", status)
    rows = _rows(w.backfill().status())
    assert rows["gone-1"]["workload_status"] == status and rows["gone-1"]["closed"] is True
    assert rows[PID]["closed"] is False


def test_closed_set_is_exact():
    assert rib.CLOSED_WORKLOAD_STATUSES == frozenset({"DECOMMISSIONED", "ARCHIVED", "DELETED"})


@pytest.mark.parametrize("status", ["decommissioned", "DECOMMISSION_REQUESTED", "DECOMMISSION_FAILED", "DEPLOYED",
                                    " ARCHIVED", "FAILED"])
def test_other_statuses_stay_live_and_are_shown_as_stored(w, status):
    """Exact values only: no case folding, no trimming, no prefix matching (invariant 2)."""
    _add(w, "other-1", status)
    row = _rows(w.backfill().status())["other-1"]
    assert row["workload_status"] == status and row["closed"] is False


@pytest.mark.parametrize("status", [None, "", 7, ["DECOMMISSIONED"]])
def test_a_status_that_is_not_a_string_is_unknown(w, status):
    _add(w, "odd-1", status)
    row = _rows(w.backfill().status())["odd-1"]
    assert row["workload_status"] == rib.WORKLOAD_STATUS_UNKNOWN == "unknown" and row["closed"] is False


def test_a_missing_status_field_or_record_is_unknown(w):
    _add(w, "nofield-1")
    _add(w, "norecord-1", ledger=False)
    rows = _rows(w.backfill().status())
    assert rows["nofield-1"]["workload_status"] == "unknown" and rows["nofield-1"]["closed"] is False
    assert rows["norecord-1"]["workload_status"] == "unknown" and rows["norecord-1"]["closed"] is False


def test_an_unreadable_ledger_record_is_unknown_never_guessed(w):
    _add(w, "gone-1", "DECOMMISSIONED")
    w.db.fail_paths.add("workloads/gone-1")
    st = w.backfill().status()
    row = _rows(st)["gone-1"]
    assert row["workload_status"] == "unknown" and row["closed"] is False   # not assumed closed: Run stays offered
    assert st["summary"]["closed"] == 0 and w.db.writes == []


def test_summary_counts_live_ready_not_ready_and_closed(w):
    w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1)   # PID: READY with a pinned repository
    _add(w, "live-2", "DEPLOYED")
    _add(w, "gone-1", "DECOMMISSIONED")
    _add(w, "gone-2", "ARCHIVED")
    st = w.backfill().status()
    assert _rows(st)[PID]["step_b"] == "READY"
    assert st["summary"] == {"live": 2, "ready": 1, "not_ready": 1, "closed": 2}


def test_truncated_status_reports_the_record_count(w):
    for i in range(3):
        _add(w, f"extra-{i}", "ACTIVE")
    st = w.backfill().status(limit=2)
    assert len(st["workloads"]) == 2 and st["truncated"] is True and st["record_count"] == 4
    assert st["summary"]["live"] + st["summary"]["closed"] == 2   # counts the rows shown


def test_shared_install_status_is_unchanged():
    out = W(mode="PLATFORM").backfill().status()
    assert out["per_workload"] is False and out["workloads"] == [] and "summary" not in out


def test_the_backfill_run_result_is_unchanged(w):
    """Display only: run() rows carry no ledger fields (the dry run and the real run are as before)."""
    out = w.backfill().run("cc", dry_run=True)
    assert all("workload_status" not in r and "closed" not in r for r in out["results"])


# ---------------------------------------------------------------------------------------------- Control Center route
def test_card_passes_the_new_fields_through(cc, monkeypatch):  # noqa: F811
    from routes import runner_identity_card as card
    from unittest.mock import MagicMock
    status = {"mode": "PER_WORKLOAD", "mode_label": "Per workload", "per_workload": True, "truncated": True,
              "record_count": 61, "max_records": 50,
              "summary": {"live": 1, "ready": 0, "not_ready": 1, "closed": 1},
              "workloads": [{"product_id": "a", "workload_status": "ACTIVE", "closed": False},
                            {"product_id": "b", "workload_status": "DECOMMISSIONED", "closed": True}]}
    monkeypatch.setattr(card, "vending_requester",
                        lambda method, path, json_body=None, timeout=None, request=None:
                        _Resp(200, status if path == "/runner-identity/status" else {}))
    out = card.get_runner_identity_card(MagicMock())
    assert out["status"] == status


# ---------------------------------------------------------------------------------------------- the card's HTML
class _Card(HTMLParser):
    """The runner identity table: header cells, and per tbody (by its data- marker) the buttons and cells."""

    def __init__(self):
        super().__init__()
        self.depth = 0
        self.table_attrs = None
        self.in_thead = False
        self.th = []
        self.tbody = None
        self.bodies = {}
        self._th = None
        self.spans = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "table" and "data-runner-identity-table" in a:
            self.table_attrs = a
            self.depth = 1
            return
        if not self.depth:
            return
        if tag == "table":
            self.depth += 1
        elif tag == "thead":
            self.in_thead = True
        elif tag == "th" and self.in_thead:
            self._th = [a, ""]
        elif tag == "tbody":
            self.tbody = next((k for k in a if k.startswith("data-runner-identity-")), "?")
            self.bodies[self.tbody] = {"attrs": a, "buttons": [], "tds": []}
        elif tag == "button" and self.tbody:
            self.bodies[self.tbody]["buttons"].append(a)
        elif tag == "td" and self.tbody:
            self.bodies[self.tbody]["tds"].append(a)
        elif tag == "span" and "sv-ri-trunc" in (a.get("class") or ""):
            self.spans.append((self.tbody, a))

    def handle_data(self, data):
        if self._th is not None:
            self._th[1] += data

    def handle_endtag(self, tag):
        if not self.depth:
            return
        if tag == "th" and self._th is not None:
            self.th.append((self._th[0], self._th[1].strip()))
            self._th = None
        elif tag == "thead":
            self.in_thead = False
        elif tag == "tbody":
            self.tbody = None
        elif tag == "table":
            self.depth -= 1


def _html():
    with open(DASHBOARD, encoding="utf-8") as fh:
        return fh.read()


@pytest.fixture(scope="module")
def card():
    p = _Card()
    p.feed(_html())
    assert p.table_attrs is not None, "runner identity table not found"
    return p


def test_one_table_with_the_styled_class(card):
    assert _html().count("data-runner-identity-table") == 1
    assert "sv-ri-table" in card.table_attrs["class"].split()


def test_header_row_names_every_column_and_the_action_column(card):
    names = [t for _, t in card.th]
    assert names == ["Workload", "Workload status", "Identity status", "Step B", "Repository", "Deployer", "State",
                     "Last error", "Action"]
    assert all(a.get("scope") == "col" for a, _ in card.th)
    assert "sv-ri-action" in card.th[-1][0]["class"].split()


def test_every_row_has_the_same_column_count(card):
    live = card.bodies["data-runner-identity-live"]["tds"]
    closed = card.bodies["data-runner-identity-closed"]["tds"]
    width = len(card.th)
    # live: one templated row + the "No live workloads" row (colspan); closed: one templated row
    assert len(live) == width + 1 and live[-1].get("colspan") == str(width)
    assert len(closed) == width
    assert card.bodies["data-runner-identity-closed-toggle"]["tds"][0].get("colspan") == str(width)


def test_live_rows_keep_todays_run_button_in_the_right_aligned_action_cell(card):
    live = card.bodies["data-runner-identity-live"]
    (run,) = live["buttons"]
    assert run.get("x-show") == RUN_CONDITION
    assert run.get("@click") == "runRunnerIdentityBackfill(false, r.product_id)"
    assert run.get(":disabled") == "runnerIdentity.running"
    assert "sv-ri-action" in live["tds"][len(card.th) - 1].get("class", "").split()


def test_closed_rows_have_no_run_button_and_are_folded(card):
    closed = card.bodies["data-runner-identity-closed"]
    assert closed["buttons"] == []
    assert "runnerIdentity.showClosed" in closed["attrs"]["x-show"]
    assert "runnerIdentityRows(true)" in _html()
    (toggle,) = card.bodies["data-runner-identity-closed-toggle"]["buttons"]
    assert toggle.get("@click") == "runnerIdentity.showClosed = !runnerIdentity.showClosed"
    assert "' closed workload'" in toggle.get("x-text")
    assert "showClosed: false" in _html()   # collapsed by default


def test_long_values_are_truncated_with_the_full_text_on_hover(card):
    titled = [a.get(":title", "") for body, a in card.spans if body == "data-runner-identity-live"]
    for field in ("r.product_id", "r.repository", "r.deployer_email", "r.state_location", "r.error_class"):
        assert any(field in t for t in titled), field


def test_row_lines_zebra_header_rule_and_light_theme_css():
    html = _html()
    css = html[:html.index("</style>")]
    for rule in (r"\.sv-ri-table thead th \{[^}]*border-bottom: 1px solid",
                 r"\.sv-ri-table tbody tr \{[^}]*border-top: 1px solid",
                 r"\.sv-ri-table tbody tr:nth-of-type\(even\) \{[^}]*background",
                 r"\.sv-ri-table th\.sv-ri-action, \.sv-ri-table td\.sv-ri-action \{[^}]*text-align: right",
                 r"\.sv-ri-table \.sv-ri-trunc \{[^}]*text-overflow: ellipsis",
                 r"html\.theme-light \.sv-ri-table thead th \{",
                 r"html\.theme-light \.sv-ri-table tbody tr \{[^}]*border-top-color",
                 r"html\.theme-light \.sv-ri-table tbody tr:nth-of-type\(even\) \{"):
        assert re.search(rule, css), rule


def test_totals_and_truncation_lines():
    html = _html()
    assert "data-runner-identity-totals" in html and "data-runner-identity-truncated" in html
    assert "' live · ' + (s.ready || 0) + ' READY · ' + (s.not_ready || 0) + ' not ready · '" in html
    assert "'Showing ' + shown + ' of ' + st.record_count + ' records.'" in html
    # a row without vending's flag (a vending that predates SAT-47) stays live, as before
    assert "rows.filter(r => (r.closed === true) === closed)" in html
