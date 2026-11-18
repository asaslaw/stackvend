"""FD-4AF RT F3: the eval harness plays project vending for the developer stage (a deterministic, clearly fake
workload project per example, handed over at AssemblyInputs.target_project_id). Offline: in-process fakes plus an AST
read of the product source; no child process, no network, no credentials, no product import."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import dataclasses
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

from stackvend_eval import stages as st  # noqa: E402
from stackvend_eval.state import RunState  # noqa: E402

HANDLER = ROOT / "apps/orchestrator-gateway/developer_agent/handler.py"


@dataclasses.dataclass(frozen=True)
class FakeInputs:  # the shape of the product's AssemblyInputs (frozen dataclass) for the fields used here
    product_id: str
    target_project_id: str = ""
    project_number: str = ""


class FakeAgent:
    def __init__(self):
        self.seen = []

    def _run_hallucination_stack(self, draft, inputs, gate):
        self.seen.append(("stack", inputs))
        # the product's stack re-enters _assemble_tree with (a replace() of) the same inputs
        return self._assemble_tree(draft, dataclasses.replace(inputs, project_number=inputs.project_number))[0]

    def _assemble_tree(self, draft, inputs):
        self.seen.append(("assemble", inputs))
        return dict(draft), {}


@pytest.mark.parametrize("example, pid", [("05", "eval-05-project"), ("S1", "eval-s1-project"),
                                          ("", "eval-workload-project")])
def test_project_id_is_deterministic_and_a_valid_gcp_project_id(example, pid):
    assert st.harness_workload_project(example) == pid
    assert st.harness_workload_project(example) == st.harness_workload_project(example)
    assert st.HARNESS_WORKLOAD_PROJECT_PATTERN.fullmatch(pid)


@pytest.mark.parametrize("example", ["a_b", "x" * 40, "05!"])
def test_an_example_id_that_gives_no_valid_project_id_is_refused(example):
    with pytest.raises(ValueError):
        st.harness_workload_project(example)


def test_empty_target_project_is_filled_on_both_entry_points():
    dev = FakeAgent()
    assert st.supply_workload_record(dev, "eval-05-project") == ["_run_hallucination_stack", "_assemble_tree"]
    dev._run_hallucination_stack({"a": "1"}, FakeInputs(product_id="p"), None)
    dev._assemble_tree({"a": "1"}, FakeInputs(product_id="p"))
    assert [k for k, _ in dev.seen] == ["stack", "assemble", "assemble"]
    assert all(i.target_project_id == "eval-05-project" for _, i in dev.seen)
    assert all(i.product_id == "p" and i.project_number == "" for _, i in dev.seen)  # nothing else is touched


def test_a_project_the_product_resolved_is_never_replaced():
    """Negative: when the product read a real workload record, the harness value is not used."""
    dev = FakeAgent()
    st.supply_workload_record(dev, "eval-05-project")
    real = FakeInputs(product_id="p", target_project_id="p-vended-1234", project_number="42")
    dev._run_hallucination_stack({}, real, None)
    dev._assemble_tree({}, real)
    assert [k for k, _ in dev.seen] == ["stack", "assemble", "assemble"]
    assert all(i == real for _, i in dev.seen)
    assert dev.seen[0][1] is real and dev.seen[2][1] is real  # the wrapper itself never rebuilds a resolved record


def test_only_the_given_instance_is_wrapped_and_other_shapes_pass_through():
    dev, other = FakeAgent(), FakeAgent()
    st.supply_workload_record(dev, "eval-05-project")
    assert "_assemble_tree" in vars(dev) and "_assemble_tree" not in vars(other)
    assert FakeAgent._assemble_tree.__qualname__ == "FakeAgent._assemble_tree"  # class untouched
    other._assemble_tree({}, FakeInputs(product_id="p"))
    assert other.seen[0][1].target_project_id == ""
    sentinel = object()  # an older product's inputs (no target_project_id field): passed through unchanged
    dev._assemble_tree({}, sentinel)
    assert dev.seen[-1][1] is sentinel
    assert st.supply_workload_record(types.SimpleNamespace(), "eval-05-project") == []  # pre-Step-1 product


def test_developer_stage_records_the_stub_and_wraps_the_agent():
    made = []

    class DA(FakeAgent):
        def __init__(self, project_id=None):
            super().__init__()
            assert project_id == ""  # still no host project: no Firestore, no ADC in the harness
            made.append(self)

        def generate_code_files(self, **kw):
            return self._assemble_tree({"apps/x/main.py": "x"}, FakeInputs(product_id=kw["product_id"]))[0]

    mods = {"developer_agent.handler": types.SimpleNamespace(DeveloperAgent=DA)}
    pipe = st.Pipeline(state=RunState(), mods=mods, proxy=None, product_id="test-05-x", spec_text="", trace_id="t",
                       example="05")
    pipe.stages["developer"] = {}
    comp = types.SimpleNamespace(enriched_dag=[], plan_markdown="", plan_file_path="", domain_restricted_sharing=False,
                                 allowed_domains=[], allow_unauthenticated=True, enable_direct_iap=False)
    pipe._developer(types.SimpleNamespace(task_dag=[], plan_markdown="", plan_file_path=""), comp)
    assert pipe.stages["developer"]["workload_record"] == {
        "project_id": "eval-05-project", "source": "harness_project_vending",
        "seam": ["_run_hallucination_stack", "_assemble_tree"]}
    assert made[0].seen[0][1].target_project_id == "eval-05-project"


def _handler_tree():
    return ast.parse(HANDLER.read_text())


def test_product_seam_is_anchored():
    """The stub fills a field by name; if the product renames it or the two entry points, fail here instead of the
    stub silently becoming a no-op (and every GKE run with ${PROJECT_ID} stopping again)."""
    tree = _handler_tree()
    classes = {n.name: n for n in tree.body if isinstance(n, ast.ClassDef)}
    fields = {s.target.id for s in classes["AssemblyInputs"].body
              if isinstance(s, ast.AnnAssign) and isinstance(s.target, ast.Name)}
    assert "target_project_id" in fields
    methods = {n.name: n for n in classes["DeveloperAgent"].body if isinstance(n, ast.FunctionDef)}
    for name in ("_run_hallucination_stack", "_assemble_tree"):
        assert [a.arg for a in methods[name].args.args[:3]] == ["self", "draft", "inputs"]


def test_production_takes_the_project_from_the_workload_record_only():
    """What the stub stands in for: generate_code_files sets target_project_id from workloads/{product_id}.project_id
    (gated on the host project), and AssemblyInputs is built in that one place."""
    src = HANDLER.read_text()
    assert src.count("AssemblyInputs(") == 1
    # COMMITTED-READ-VIEW (M1): through the one resolver the swarm's read view uses too (record field project_id)
    assert "target_project_id = self._workload_project_id(product_id, record=w_record)" in src
    assert 'value = record.get("project_id", "") if isinstance(record, dict) else ""' in src


def test_the_one_project_resolver_is_filled_when_the_product_resolved_none():
    """COMMITTED-READ-VIEW (M1): the harness also fills DeveloperAgent._workload_project_id, so the swarm's read view
    and the assembly hydrate with the same vended project; a value the product resolved is kept."""
    class WithResolver(FakeAgent):
        def __init__(self, value):
            super().__init__()
            self.value = value

        def _workload_project_id(self, product_id, record=None):
            return self.value
    dev = WithResolver("")
    assert st.supply_workload_record(dev, "eval-04-project") == [
        "_run_hallucination_stack", "_assemble_tree", "_workload_project_id"]
    assert dev._workload_project_id("p") == dev._workload_project_id("p", record={}) == "eval-04-project"
    real = WithResolver("p-vended-1234")
    st.supply_workload_record(real, "eval-04-project")
    assert real._workload_project_id("p") == "p-vended-1234"
