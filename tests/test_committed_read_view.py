"""COMMITTED-READ-VIEW + REPAIR-WALL-CLOCK-ROOM (ex04-1114 on stackvend12, 11-15; register rows of the same names).

Live: the developer wrote `k8s/serviceaccount.yaml` / `k8s/ex04-1114.yaml` with the FD-4AF placeholders in wave 2 and
`tests/test_k8s_manifests.py` in wave 3, reading those manifests as its read dependencies. The tests asserted the
placeholder text (`${PRODUCT_ID}-sa@${PROJECT_ID}.iam.gserviceaccount.com`, `${ARTIFACT_REGISTRY}/ex04-1114:latest`).
The assembly hydrates the manifests before the commit, so QA ran the tests on concrete values and 2 of 18 failed: the
platform rewrote the files under the generated tests.

1. COMMITTED-READ-VIEW: a later wave reads its read dependencies through the assembly's own hydration (same function,
   same values), so it reads exactly the bytes QA will test. The staged tree (the draft) is unchanged; a file that
   is not a manifest, or a manifest without a placeholder, is byte-identical (Do No Harm). An unavailable value
   leaves the texts as staged (the assembly stops typed on it, as before).
2. A QA repair's read-only context also carries the draft's (= tested tree's) k8s manifests, after the .py files,
   so a test repair sees the committed manifest text; the .py context is unchanged.
3. REPAIR-WALL-CLOCK-ROOM: in the QA repair dispatch the call walk refused to start a call twice (the repair wall
   clock had less room than min_call_s + the answer margin: typed REPAIR_WALL_CLOCK, no transport attempt), the loop
   counted both as repair iterations (ENVELOPE_INVALID, nothing asked) and stopped with ITERATIONS. Now such a
   dispatch is not an iteration and the loop stops with WALL_CLOCK.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import asyncio
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(ROOT, "apps", "orchestrator-gateway")
TESTS = os.path.dirname(__file__)
for p in (GATEWAY, ROOT, TESTS):
    if p not in sys.path:
        sys.path.insert(0, p)

from platform_settings_defaults import default_platform_settings  # noqa: F401,E402  (autouse; OPEN-MODEL-SETTINGS)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent import qa_repair as QR  # noqa: E402
from developer_agent.llm_transport import REPAIR_WALL_CLOCK  # noqa: E402
from developer_agent.preflight_validator import hydrate_kubernetes_manifests  # noqa: E402
from developer_agent.repair_loop import RepairLoop  # noqa: E402
from developer_agent.swarm_dispatcher import SwarmDispatcher  # noqa: E402
from developer_agent.swarm_schemas import (JuniorExecutionResult, JuniorPersona, JuniorTaskAssignment,  # noqa: E402
                                           LeadDeveloperDecompositionPlan, SwarmExecutionMode)
from shared.diagnostics import RepairBudgetExhausted  # noqa: E402
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402

from test_step1_s1b_loop import BUCKETS, MAIN, REFS, Persona, _ctx  # noqa: E402

PID, PROJECT, REGION = "ex04-1114", "ex04-1114", "us-central1"
SA = "k8s/serviceaccount.yaml"
DEPLOY = "k8s/ex04-1114.yaml"
SA_SRC = ("apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: sa-stream-worker\n  namespace: stream-apps\n"
          "  annotations:\n    iam.gke.io/gcp-service-account: ${PRODUCT_ID}-sa@${PROJECT_ID}.iam.gserviceaccount.com\n")
DEPLOY_SRC = ("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: ex04-1114\nspec:\n  template:\n    spec:\n"
              "      containers:\n      - name: ex04-1114\n        image: ${ARTIFACT_REGISTRY}/ex04-1114:latest\n")
HPA = ("apiVersion: autoscaling/v2\nkind: HorizontalPodAutoscaler\nmetadata:\n  name: ex04-1114\nspec:\n"
       "  maxReplicas: 2\n")
PY_WITH_TOKEN = 'EXPECTED = "${PROJECT_ID}"   # a Python file is never a manifest\n'
NOT_A_MANIFEST = {"apps/ex04-1114/config.yaml": DEPLOY_SRC, "apps/k8sproxy/x.yaml": SA_SRC}


class _Doc:
    def __init__(self, data):
        self.exists, self._data = data is not None, data

    def to_dict(self):
        return self._data


class _Db:
    """workloads/{pid} only; counts reads."""

    def __init__(self, record):
        self.record, self.reads = record, 0

    def collection(self, name):
        assert name == "workloads"
        return self

    def document(self, pid):
        assert pid == PID
        return self

    def get(self):
        self.reads += 1
        return _Doc(self.record)


_CLIENT = {"db": None}   # what google.cloud.firestore.Client(project=...) returns in this module (M1)


@pytest.fixture(autouse=True)
def _records_client():
    """M1: the view reads the project through DeveloperAgent._workload_project_id, the assembly's own resolver (a
    client of the agent's host project); every test here serves that client from `_CLIENT`."""
    def client(project=None, **kw):
        if _CLIENT["db"] is None:
            raise RuntimeError("no Firestore in tests")
        return _CLIENT["db"]
    with patch("google.cloud.firestore.Client", side_effect=client):
        yield
    _CLIENT["db"] = None


def _agent(db, region=REGION):
    from developer_agent import handler as h
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GEMINI_API_KEY": ""}):
        agent = h.DeveloperAgent(project_id="")
    agent.project_id = "mock-host" if db is not None else ""   # the host project the records live in
    _CLIENT["db"] = db
    calls = []

    def platform_region(product_id=None):
        calls.append(product_id)
        return region
    agent._platform_region = platform_region
    return agent, calls


def _assembly_form(files):
    """What the assembly commits for these files (handler step 8, same values)."""
    out, _ = hydrate_kubernetes_manifests(dict(files), PID, project_id=PROJECT, region=lambda: REGION,
                                          defer_unresolved=True)
    return out


# ------------------------------------------------------------------------------------------------ 1. the view
def test_view_gives_a_later_wave_the_committed_manifest_bytes():
    agent, region_calls = _agent(_Db({"project_id": PROJECT}))
    deps = {SA: SA_SRC, DEPLOY: DEPLOY_SRC, "k8s/hpa.yaml": HPA}
    viewed = agent._committed_read_view(PID)(dict(deps))
    assert viewed == _assembly_form(deps)
    assert "iam.gke.io/gcp-service-account: ex04-1114-sa@ex04-1114.iam.gserviceaccount.com" in viewed[SA]
    assert "image: us-central1-docker.pkg.dev/ex04-1114/ex04-1114/ex04-1114:latest" in viewed[DEPLOY]
    assert viewed["k8s/hpa.yaml"] == HPA
    assert region_calls == [PID]


def test_view_reads_the_record_and_the_region_at_most_once_per_view():
    db = _Db({"project_id": PROJECT})
    agent, region_calls = _agent(db)
    view = agent._committed_read_view(PID)
    for _ in range(3):
        view({DEPLOY: DEPLOY_SRC})
    assert db.reads == 1 and region_calls == [PID]


@pytest.mark.parametrize("deps", [
    {"apps/ex04-1114/main.py": PY_WITH_TOKEN, "tests/test_x.py": PY_WITH_TOKEN},
    NOT_A_MANIFEST,
    {"k8s/hpa.yaml": HPA, "k8s/namespace.yaml": "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: stream-apps\n"},
    {DEPLOY: DEPLOY_SRC.replace("${ARTIFACT_REGISTRY}", "europe-west1-docker.pkg.dev/p-1/shop")},
])
def test_view_negative_files_without_a_manifest_placeholder_are_byte_identical(deps):
    """Do No Harm: no manifest, or a manifest without a placeholder -> exactly the staged texts; no read at all when
    no dependency is a manifest."""
    db = _Db({"project_id": PROJECT})
    agent, region_calls = _agent(db)
    assert agent._committed_read_view(PID)(dict(deps)) == deps
    if not any(p.startswith("k8s/") for p in deps):
        assert db.reads == 0 and region_calls == []
    assert region_calls == []   # no manifest here uses ${REGION} / ${ARTIFACT_REGISTRY}


@pytest.mark.parametrize("db", [None, _Db(None), _Db({"project_id": ""}), _Db({"other": 1})])
def test_view_without_a_project_value_leaves_the_texts_as_staged(db):
    """K8S.PLACEHOLDER_VALUE_UNAVAILABLE: the view decides nothing (the assembly raises it typed for the same file)."""
    agent, _ = _agent(db)
    deps = {SA: SA_SRC, DEPLOY: DEPLOY_SRC}
    assert agent._committed_read_view(PID)(dict(deps)) == deps


def test_view_an_unreadable_record_is_an_unavailable_value_not_a_crash():
    class Broken(_Db):
        def get(self):
            raise RuntimeError("firestore down")
    agent, _ = _agent(Broken({}))
    assert agent._committed_read_view(PID)({SA: SA_SRC}) == {SA: SA_SRC}


def test_view_never_guesses_an_unknown_placeholder():
    """FD-4AF-r: an unknown token stays (V-K8S-PH reports it on the draft); the known ones are substituted."""
    agent, _ = _agent(_Db({"project_id": PROJECT}))
    text = DEPLOY_SRC.replace("${ARTIFACT_REGISTRY}/ex04-1114:latest", "${IMAGE}") + "---\n" + SA_SRC
    viewed = agent._committed_read_view(PID)({DEPLOY: text})[DEPLOY]
    assert "image: ${IMAGE}" in viewed and "${PROJECT_ID}" not in viewed and "${PRODUCT_ID}" not in viewed


# ------------------------------------------------------------------------------------------------ 1b. the swarm
def _plan():
    return LeadDeveloperDecompositionPlan(execution_mode=SwarmExecutionMode.STANDARD_SWARM, tasks=[
        JuniorTaskAssignment(task_id="task-k8s", persona=JuniorPersona.DEVOPS_ENGINEER, wave=1,
                             assigned_files=[SA, DEPLOY], task_objective="manifests"),
        JuniorTaskAssignment(task_id="task-tests", persona=JuniorPersona.TEST_ENGINEER, wave=2,
                             assigned_files=["tests/test_k8s_manifests.py"], read_dependencies=[SA, DEPLOY],
                             task_objective="manifest tests"),
    ])


def _swarm(read_view):
    seen = {}

    async def worker(task, plan, deps, model, *a, **k):
        files = ({SA: SA_SRC, DEPLOY: DEPLOY_SRC} if task.wave == 1 else
                 {"tests/test_k8s_manifests.py": "def test_x():\n    pass\n"})
        if task.wave == 2:
            seen.update(deps)
        return JuniorExecutionResult(task_id=task.task_id, persona=task.persona, wave=task.wave, files=files,
                                     consumed_tokens=10)
    d = SwarmDispatcher(genai_client=None)
    d.invoke_junior_worker = worker
    if read_view is not None:
        d.read_view = read_view
    staged = asyncio.run(d.execute_phased_junior_swarm(_plan(), "trace-crv", PID))
    return seen, staged


def test_swarm_later_wave_reads_dependencies_through_the_view_and_the_draft_is_unchanged():
    agent, _ = _agent(_Db({"project_id": PROJECT}))
    seen, staged = _swarm(agent._committed_read_view(PID))
    assert seen == {p: _assembly_form({SA: SA_SRC, DEPLOY: DEPLOY_SRC})[p] for p in (SA, DEPLOY)}
    assert staged[SA] == SA_SRC and staged[DEPLOY] == DEPLOY_SRC   # the draft keeps what the developer wrote


def test_swarm_negative_without_a_view_the_dependencies_are_the_staged_texts():
    seen, staged = _swarm(None)
    assert seen == {SA: SA_SRC, DEPLOY: DEPLOY_SRC} and staged[SA] == SA_SRC


def test_handler_gives_the_swarm_the_committed_read_view():
    """generate_code_files wires the view into the dispatcher it runs the swarm with."""
    import test_step1_s1b_generation as s1b
    from developer_agent import handler as h
    agent = s1b._agent(s1b._runtime(s1b.Client()))
    plan = MagicMock()
    plan.execution_mode = [m for m in h.SwarmExecutionMode if m != h.SwarmExecutionMode.SOLO_FAST_PATH][0]
    plan.tasks = [MagicMock()]
    made = []

    class FakeDispatcher:
        def __init__(self, *a, **k):
            made.append(self)
            self.read_view = None
            self.last_file_attribution = {p: "backend_worker" for p in s1b.DRAFT}
            self.envelope_checks = [{"ok": True, "error": None}]

        async def execute_phased_junior_swarm(self, *a, **k):
            return dict(s1b.DRAFT)

    with patch.object(h, "LeadDeveloperOrchestrator") as lead, patch.object(h, "SwarmDispatcher", FakeDispatcher), \
            patch.object(agent, "fetch_existing_repo_files", return_value={}), \
            patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GCP_PROJECT": ""}), \
            patch("google.cloud.firestore.Client", side_effect=RuntimeError("no Firestore in tests")):
        lead.return_value.decompose_specification.return_value = plan
        agent.generate_code_files(product_id="shop", spec_text="FastAPI uploads service", task_dag=[],
                                  trace_id="trace-crv", architect_compute_intent={"target_compute_services": ["shop"]},
                                  allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False)
    assert made and callable(made[0].read_view)
    # the view is the agent's (product "shop"): ${PRODUCT_ID} is the one value it has without a workload record
    text = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: ${PRODUCT_ID}-cfg\n"
    assert made[0].read_view({"k8s/cm.yaml": text}) == {"k8s/cm.yaml": text.replace("${PRODUCT_ID}", "shop")}


# ------------------------------------------------------------------------------------------------ 2. QA context
def test_qa_repair_context_adds_the_committed_manifests_after_the_py_files():
    draft = {"apps/a/main.py": "x = 1\n", "tests/test_k8s.py": "def test(): pass\n", SA: "kind: ServiceAccount\n",
             "README.md": "# r\n", "apps/a/config.yaml": "a: 1\n"}
    ctx = QR.context_files(draft, {"tests/test_k8s.py": ""})
    assert list(ctx) == ["apps/a/main.py", SA]


def test_qa_repair_context_negative_without_manifests_is_unchanged():
    draft = {"apps/a/main.py": "x = 1\n", "tests/conftest.py": "import os\n", "README.md": "# r\n"}
    assert QR.context_files(draft, {}) == {"apps/a/main.py": "x = 1\n", "tests/conftest.py": "import os\n"}


def test_qa_repair_context_py_files_keep_the_room_first():
    """A manifest never displaces a .py file: the .py selection is exactly the one without manifests."""
    big = "y" * (QR.QA_REPAIR_CONTEXT_MAX_CHARS - 10)
    draft = {"k8s/a.yaml": "kind: X\n" * 4, "tests/test_z.py": big}
    assert QR.context_files(draft, {}) == {"tests/test_z.py": big}
    without = {p: t for p, t in draft.items() if not p.startswith("k8s/")}
    assert QR.context_files(without, {}) == QR.context_files(draft, {})


# ------------------------------------------------------------------------------------------------ 3. wall clock
class _ClockPersona(Persona):
    """Answers each call from a script of result dicts (None = the scripted fix of Persona)."""

    def __init__(self, *results):
        super().__init__()
        self.results = list(results)

    def __call__(self, task):
        self.tasks.append(task)
        return dict(self.results.pop(0))


# the shape invoke_repair really returns when its walk had no room (RT F1: the walk records a NO_STAGE_BUDGET attempt,
# so transport_attempts is 1 although nothing was called; test_real_walk_without_room_* proves it end to end)
NO_ROOM = {"files": {}, "envelope_ok": False, "error": f"{REPAIR_WALL_CLOCK}: no room", "finish_reason": None,
           "error_code": REPAIR_WALL_CLOCK, "transport_attempts": 1, "calls_started": 0, "tokens_in": 0,
           "tokens_out": 0, "model": "m"}
TIMED_OUT_THEN_NO_ROOM = dict(NO_ROOM, transport_attempts=2, calls_started=1)
WRONG = {"files": {MAIN: BUCKETS + REFS + "\n"}, "envelope_ok": True, "finish_reason": "STOP", "tokens_in": 1,
         "tokens_out": 1, "model": "m"}


def test_a_dispatch_whose_walks_started_no_call_is_not_an_iteration_and_stops_on_wall_clock():
    persona = _ClockPersona(NO_ROOM, NO_ROOM, NO_ROOM)
    ctx = _ctx(persona)
    with pytest.raises(RepairBudgetExhausted) as ei:
        RepairLoop(ctx).run({MAIN: BUCKETS + REFS})
    ledger = ctx.ledger_store.load("t1")
    assert ei.value.exhausted_reason == "WALL_CLOCK" and ledger.exhausted_reason == "WALL_CLOCK"
    assert len(persona.tasks) == 1 and ledger.iteration == 0 and ctx.events == []


def test_a_walk_that_ran_out_after_a_call_counts_once_then_stops_on_wall_clock():
    persona = _ClockPersona(TIMED_OUT_THEN_NO_ROOM, NO_ROOM)
    ctx = _ctx(persona)
    with pytest.raises(RepairBudgetExhausted) as ei:
        RepairLoop(ctx).run({MAIN: BUCKETS + REFS})
    assert ei.value.exhausted_reason == "WALL_CLOCK" and len(persona.tasks) == 1
    assert ctx.ledger_store.load("t1").iteration == 1 and [e.reject_reason for e in ctx.events] == ["ENVELOPE_INVALID"]
    assert ctx.events[0].detail == REPAIR_WALL_CLOCK   # the typed cause is on the run record


def test_negative_without_a_wall_clock_result_the_loop_is_unchanged():
    """Ordinary rejected answers still use the iteration budget (ITERATIONS), exactly as before."""
    persona = _ClockPersona(WRONG, WRONG, WRONG)
    ctx = _ctx(persona, settings=HallucinationStackSettings(repair_max_iterations_precommit=2))
    with pytest.raises(RepairBudgetExhausted) as ei:
        RepairLoop(ctx).run({MAIN: BUCKETS + REFS})
    assert ei.value.exhausted_reason == "ITERATIONS" and ctx.ledger_store.load("t1").iteration == 2
    assert [e.detail for e in ctx.events] == [None, None]   # no error code: the event is as before



def test_unknown_call_count_is_an_iteration_as_before():
    """A result without `calls_started` (another repair_fn) is not proven call-free: the iteration counts."""
    legacy = {k: v for k, v in NO_ROOM.items() if k != "calls_started"}
    persona = _ClockPersona(legacy, legacy)
    ctx = _ctx(persona)
    with pytest.raises(RepairBudgetExhausted) as ei:
        RepairLoop(ctx).run({MAIN: BUCKETS + REFS})
    assert ei.value.exhausted_reason == "WALL_CLOCK" and ctx.ledger_store.load("t1").iteration == 1


def test_real_walk_without_room_stops_the_loop_on_wall_clock_without_an_iteration():
    """RT F1: the real SwarmDispatcher.invoke_repair, 25 s left on the repair wall clock (< 20 s minimum + 15 s
    margin): no model is called, and the loop stops on WALL_CLOCK without counting an iteration."""
    import test_slow_call_fallback as SC
    clock = SC.Clock()
    client = SC.Client({SC.CARBON: (1, SC.response(SC.FILES))}, clock.advance)
    d = SwarmDispatcher(genai_client=client)
    d._clock = clock
    deadline = clock() + 25

    def repair(task):
        return d.invoke_repair(task.persona, "sys", task.prompt(), SC.CARBON, 9000, repair_deadline=deadline)
    ctx = _ctx(repair)
    with patch("developer_agent.swarm_dispatcher.get_model_cascade_for_agent", return_value=list(SC.CHAIN)):
        with pytest.raises(RepairBudgetExhausted) as ei:
            RepairLoop(ctx).run({MAIN: BUCKETS + REFS})
    assert client.models.calls == []
    assert ei.value.exhausted_reason == "WALL_CLOCK" and ctx.ledger_store.load("t1").iteration == 0


def test_real_walk_result_counts_started_calls_only():
    import test_slow_call_fallback as SC
    clock = SC.Clock()
    d = SwarmDispatcher(genai_client=SC.Client({SC.CARBON: (1, SC.response(SC.FILES))}, clock.advance))
    d._clock = clock
    with patch("developer_agent.swarm_dispatcher.get_model_cascade_for_agent", return_value=list(SC.CHAIN)):
        refused = d.invoke_repair("IAC", "sys", "p", SC.CARBON, 9000, repair_deadline=clock() + 25)
        answered = d.invoke_repair("IAC", "sys", "p", SC.CARBON, 9000, repair_deadline=clock() + 300)
    assert (refused["error_code"], refused["transport_attempts"], refused["calls_started"]) == (REPAIR_WALL_CLOCK, 1, 0)
    assert answered.get("error_code") is None and answered["calls_started"] == 1 and answered["envelope_ok"]


def test_pre_check_stops_before_dispatching_when_the_walk_would_refuse():
    """RT F2: with the walk's room rule in the context, a dispatch the walk would refuse is never sent."""
    persona = Persona()
    ctx = _ctx(persona)
    ctx.repair_call_room = lambda: False
    with pytest.raises(RepairBudgetExhausted) as ei:
        RepairLoop(ctx).run({MAIN: BUCKETS + REFS})
    assert ei.value.exhausted_reason == "WALL_CLOCK" and persona.tasks == []
    assert ctx.ledger_store.load("t1").iteration == 0


def test_pre_check_negative_with_room_the_loop_is_unchanged():
    fixed = BUCKETS + 'resource "google_storage_bucket" "b" {\n  name = "b"\n}\n' + REFS
    persona = Persona({MAIN: fixed})
    ctx = _ctx(persona)
    ctx.repair_call_room = lambda: True
    tree, report = RepairLoop(ctx).run({MAIN: BUCKETS + REFS})
    assert report.status == "PASS" and len(persona.tasks) == 1 and ctx.ledger_store.load("t1").iteration == 1


def test_parallel_tasks_one_out_of_room_keeps_the_others_answer_and_stops_on_wall_clock():
    """RT F6: one persona's answer is accepted, the other's walk ran out after a call; the next check names the cause
    (WALL_CLOCK), not ITERATIONS / NO_PROGRESS."""
    fixed = BUCKETS + 'resource "google_storage_bucket" "b" {\n  name = "b"\n}\n' + REFS
    answers = {"iac_worker": {"files": {MAIN: fixed}, "envelope_ok": True, "finish_reason": "STOP", "tokens_in": 1,
                              "tokens_out": 1, "model": "m", "calls_started": 1},
               "test_worker": TIMED_OUT_THEN_NO_ROOM}
    seen = []

    def repair(task):
        seen.append(task.persona)
        return dict(answers[task.persona])
    ctx = _ctx(repair)
    with pytest.raises(RepairBudgetExhausted) as ei:
        RepairLoop(ctx).run({MAIN: BUCKETS + REFS, "tests/test_x.py": "def test_x(:\n"})
    assert ei.value.exhausted_reason == "WALL_CLOCK" and sorted(seen) == ["iac_worker", "test_worker"]
    assert ctx.ledger_store.load("t1").iteration == 1
    assert [(e.persona, e.accepted) for e in ctx.events] == [("iac_worker", True), ("test_worker", False)]


class _HostRecords:
    """M1 parity: a host-project Firestore that holds workloads/shop with a vended project; any other read fails, as
    the s1b harness's client does."""

    def collection(self, name):
        if name != "workloads":
            raise RuntimeError(f"no {name} in this test")
        return self

    def document(self, pid):
        self.pid = pid
        return self

    def get(self):
        if self.pid != "shop":
            raise RuntimeError("only workloads/shop")
        return _Doc({"project_id": "p-shop-1234"})


def test_assembly_and_view_use_the_same_hydration_call_and_values():
    """RT F3 + M1: step 8 and the view both go through DeveloperAgent._hydrate_k8s and DeveloperAgent.
    _workload_project_id, so with a workload record that HAS a project both hydrate with that project (a divergence
    in either source fails here)."""
    import test_step1_s1b_generation as s1b
    from developer_agent import handler as h
    agent = s1b._agent(s1b._runtime(s1b.Client()))
    agent.project_id = "mock-host"   # records are read (the client below); agent.db stays None
    plan = MagicMock()
    plan.execution_mode = [m for m in h.SwarmExecutionMode if m != h.SwarmExecutionMode.SOLO_FAST_PATH][0]
    plan.tasks = [MagicMock()]
    made, calls = [], []
    real = h.DeveloperAgent._hydrate_k8s

    def spy(files, product_id, project_id, region, *, defer_unresolved):
        calls.append((product_id, project_id, region() if callable(region) else region))
        return real(files, product_id, project_id, region, defer_unresolved=defer_unresolved)

    class FakeDispatcher:
        def __init__(self, *a, **k):
            made.append(self)
            self.read_view = None
            self.last_file_attribution = {p: "backend_worker" for p in s1b.DRAFT}
            self.envelope_checks = [{"ok": True, "error": None}]

        async def execute_phased_junior_swarm(self, *a, **k):
            return dict(s1b.DRAFT)

    _CLIENT["db"] = _HostRecords()
    with patch.object(h, "LeadDeveloperOrchestrator") as lead, patch.object(h, "SwarmDispatcher", FakeDispatcher), \
            patch.object(h.DeveloperAgent, "_hydrate_k8s", staticmethod(spy)), \
            patch.object(agent, "fetch_existing_repo_files", return_value={}), \
            patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GCP_PROJECT": ""}):
        lead.return_value.decompose_specification.return_value = plan
        agent.generate_code_files(product_id="shop", spec_text="FastAPI uploads service", task_dag=[],
                                  trace_id="trace-crv2", architect_compute_intent={"target_compute_services": ["shop"]},
                                  allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False)
        assembly_calls = list(calls)
        made[0].read_view({"k8s/cm.yaml": "kind: ConfigMap\nmetadata:\n  name: ${PRODUCT_ID}\n"})
    assert assembly_calls and len(calls) == len(assembly_calls) + 1
    assert {c[1] for c in assembly_calls} == {"p-shop-1234"}            # the record's project reached step 8
    assert set(assembly_calls) == {calls[-1]}                            # and the view used exactly the same values


def test_eval_harness_seam_gives_the_view_and_the_commit_the_same_project():
    """M1 repro (probe_eval_view.py): a harness agent (no host project, no db) after supply_workload_record: the view
    hydrates with the vended project the commit gets, instead of returning ${ARTIFACT_REGISTRY} as staged."""
    sys.path.insert(0, os.path.join(ROOT, "eval"))
    from stackvend_eval.stages import harness_workload_project, supply_workload_record
    from developer_agent import handler as h
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GEMINI_API_KEY": ""}):
        dev = h.DeveloperAgent(project_id="")
    dev._platform_region = lambda pid=None: REGION
    proj = harness_workload_project("04")
    assert "_workload_project_id" in supply_workload_record(dev, proj)
    viewed = dev._committed_read_view(PID)({DEPLOY: DEPLOY_SRC})[DEPLOY]
    committed, _ = h.DeveloperAgent._hydrate_k8s({DEPLOY: DEPLOY_SRC}, PID, dev._workload_project_id(PID, record={}),
                                                 lambda: REGION, defer_unresolved=True)
    assert viewed == committed[DEPLOY]
    assert f"image: {REGION}-docker.pkg.dev/{proj}/ex04-1114/ex04-1114:latest" in viewed


def test_view_retries_a_value_it_could_not_read():
    """RT F4: an empty / failed read is not kept: the next wave reads again and gets the committed form."""
    class Flaky(_Db):
        def get(self):
            self.reads += 1
            if self.reads == 1:
                raise RuntimeError("transient")
            return _Doc(self.record)
    db = Flaky({"project_id": PROJECT})
    agent, _ = _agent(db)
    view = agent._committed_read_view(PID)
    assert view({SA: SA_SRC}) == {SA: SA_SRC}                       # first wave: unavailable, as staged
    assert view({SA: SA_SRC}) == _assembly_form({SA: SA_SRC})       # next wave: the committed bytes
    view({SA: SA_SRC})
    assert db.reads == 2                                            # a value that was read is kept


# ------------------------------------------------------------------------------------------------ L1: the real room check
class _ClockOnly:
    """A dispatcher's clock and caps (the real SwarmDispatcher defaults) on a settable time."""

    def __init__(self, now):
        from developer_agent.llm_transport import DEFAULT_CALL_TIMEOUTS
        self.now = now
        self.call_timeouts = DEFAULT_CALL_TIMEOUTS

    def _clock(self):
        return self.now


@pytest.mark.parametrize("left, room", [(34.0, False), (35.0, True), (36.0, True), (900.0, True), (0.0, False)])
def test_real_repair_call_room_applies_the_walks_rule(left, room):
    """L1: DeveloperAgent._repair_call_room (the closure wired into LoopContext): min_call_s 20 s + 15 s answer margin;
    34 s left must stop, 36 s must dispatch (the boundary is 35 s, as in call_timeout_s)."""
    from developer_agent import handler as h
    settings = HallucinationStackSettings()
    start = 10_000.0
    disp = _ClockOnly(now=start + settings.repair_wall_clock_s - left)
    assert h.DeveloperAgent._repair_call_room({"start": start}, settings, disp)() is room


def test_real_repair_call_room_without_a_window_or_setting_never_stops():
    from developer_agent import handler as h
    assert h.DeveloperAgent._repair_call_room({"start": None}, HallucinationStackSettings(), _ClockOnly(0.0))()
    no_setting = type("S", (), {"repair_wall_clock_s": 0})()
    assert h.DeveloperAgent._repair_call_room({"start": 0.0}, no_setting, _ClockOnly(10 ** 6))()


def test_real_repair_call_room_stops_the_loop_before_dispatching():
    """L1: the real closure in a LoopContext: 34 s left -> WALL_CLOCK, nothing dispatched; 36 s -> one repair."""
    from developer_agent import handler as h
    settings = HallucinationStackSettings()
    fixed = BUCKETS + 'resource "google_storage_bucket" "b" {\n  name = "b"\n}\n' + REFS
    for left, expected in ((34.0, "WALL_CLOCK"), (36.0, "PASS")):
        persona = Persona({MAIN: fixed})
        ctx = _ctx(persona)
        ctx.repair_call_room = h.DeveloperAgent._repair_call_room(
            {"start": 0.0}, settings, _ClockOnly(now=settings.repair_wall_clock_s - left))
        try:
            RepairLoop(ctx).run({MAIN: BUCKETS + REFS})
            outcome = "PASS"
        except RepairBudgetExhausted as e:
            outcome = e.exhausted_reason
        assert outcome == expected and len(persona.tasks) == (0 if expected == "WALL_CLOCK" else 1)


def test_the_stack_wires_the_real_room_check_into_the_loop():
    """L1: _run_hallucination_stack passes DeveloperAgent._repair_call_room's closure to the LoopContext (removing the
    kwarg fails here)."""
    import test_step1_s1b_generation as s1b
    from developer_agent import handler as h
    from developer_agent import repair_loop as RL
    seen, made = [], []
    orig_run = RL.RepairLoop.run
    orig_room = h.DeveloperAgent._repair_call_room

    def spy_room(window, settings, dispatcher):
        fn = orig_room(window, settings, dispatcher)
        made.append(fn)
        return fn

    def spy_run(self, draft):
        seen.append(self.ctx.repair_call_room)
        return orig_run(self, draft)
    agent = s1b._agent(s1b._runtime(s1b.Client()))
    with patch.object(RL.RepairLoop, "run", spy_run), \
            patch.object(h.DeveloperAgent, "_repair_call_room", staticmethod(spy_room)):
        s1b._generate(agent)
    assert seen and made and seen[0] is made[0] and seen[0]() is True


# ------------------------------------------------------------------------------------------------ L3: a failing view
@pytest.mark.parametrize("bad_view", [
    lambda deps: (_ for _ in ()).throw(RuntimeError("view bug")),   # raises
    lambda deps: None,                                               # not a dict
    lambda deps: {"k8s/other.yaml": "x"},                            # other paths
])
def test_an_unexpected_view_error_falls_back_to_the_staged_texts(bad_view, caplog):
    """L3: the view only changes what the junior reads; its failure never fails the wave."""
    import logging
    with caplog.at_level(logging.WARNING, logger="castor-swarm-dispatcher"):
        seen, staged = _swarm(bad_view)
    assert seen == {SA: SA_SRC, DEPLOY: DEPLOY_SRC} and staged[SA] == SA_SRC
    assert "tests/test_k8s_manifests.py" in staged
    assert any("COMMITTED_READ_VIEW_FAILED task task-tests" in r.getMessage() for r in caplog.records)


def test_a_stage_stop_in_the_view_still_stops_the_swarm():
    import stage_deadline

    def stop(deps):
        raise stage_deadline.STOP_ERRORS[0]("stage deadline")
    with pytest.raises(stage_deadline.STOP_ERRORS[0]):
        _swarm(stop)
