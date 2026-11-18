"""CC-DETAILS-SELECTION-RACE: opening a workload from the catalog must show that workload.

The page's first load used to finish by selecting the first workload, which replaced a workload the operator had
opened while the load ran. A slower answer for an earlier selection could also replace the page.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

from pathlib import Path

import pytest

DASHBOARD = Path(__file__).resolve().parent.parent / "apps" / "control-center" / "templates" / "dashboard.html"


@pytest.fixture(scope="module")
def html():
    return DASHBOARD.read_text(encoding="utf-8")


def _method(html, signature):
    start = html.index(signature)
    return html[start:html.index("\n                },", start)]


def _first_load_tail(html):
    start = html.index("await this.loadAgentSkills();")
    return html[start:html.index("this.activeExecutionsPollingInterval = setInterval", start)]


def test_the_first_load_keeps_a_workload_opened_while_it_ran(html):
    tail = _first_load_tail(html)
    assert "await this.loadWorkloadDetails();" in tail
    assert "this.selectedWorkloadId =" not in tail
    assert "this.selectedProductForDiagram =" not in tail


def test_the_defaults_are_only_set_when_nothing_is_selected(html):
    fetcher = _method(html, "async fetchWorkloads()")
    assert "if (!this.selectedWorkloadId) {" in fetcher
    assert "if (!this.selectedProductForDiagram) {" in fetcher


def test_a_stale_answer_does_not_replace_the_page(html):
    loader = _method(html, "async loadWorkloadDetails()")
    check = loader.index("if (requestedId !== this.selectedWorkloadId) return;")
    assert loader.index("const details = await res.json();") < check < loader.index("this.workloadDetails = details;")


def test_a_stale_answer_does_not_end_the_newer_loading_state(html):
    loader = _method(html, "async loadWorkloadDetails()")
    finally_block = loader[loader.index("} finally {"):]
    assert "if (requestedId === this.selectedWorkloadId) this.isDetailsLoading = false;" in finally_block
