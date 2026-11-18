"""PLATFORM-WORKLOAD-CARD-OFF (owner 11-03): the empty Workloads Catalog no longer offers to register StackVend itself
as a "platform workload" (confusing on a new install; to be redesigned, flight deck P3). It points to New Workload
instead. The registration endpoint is not removed (required-components rule), only no longer offered by the page."""

import hermetic_guard  # noqa: F401  (must be the first import: tests/hermetic_guard.py)

import os

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DASH = os.path.join(REPO, "apps", "control-center", "templates", "dashboard.html")


def _dash():
    with open(DASH, encoding="utf-8") as f:
        return f.read()


def test_no_button_calls_the_platform_workload_bootstrap():
    html = _dash()
    assert '@click="bootstrapCastorWorkload()"' not in html
    assert "Initialize StackVend Platform Workload" not in html
    assert "Add Platform Workload" not in html


def test_empty_catalog_points_to_new_workload():
    html = _dash()
    start = html.index("<!-- First-Time Onboarding / Empty State Card -->")
    card = html[start:start + 2500]
    assert '@click="openNewWorkloadModal()"' in card
    assert "New Workload" in card
