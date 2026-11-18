"""FD-4AF-r (owner row 10-19): an unknown placeholder in a k8s manifest is a repairable pre-commit finding routed to the
manifest's author instead of a hard stop.

Before: hydration raised K8S.PLACEHOLDER_UNRESOLVED inside the assembly, so the step-1 repair loop never saw it.
Now: on the step-1 (repair loop) path hydration defers it; the blocking validator V-K8S-PH reports the same typed
finding (same parser, same message) as a CODE_DEFECT on the manifest, the Router gives it to the persona that wrote the
manifest, and a repair that removes the unknown token passes. When the budget runs out the stage still stops with
K8S.PLACEHOLDER_UNRESOLVED (RepairBudgetExhausted, CODE_DEFECT). The legacy (no stack) path still raises.
K8S.PLACEHOLDER_VALUE_UNAVAILABLE stays a hard stop (a missing platform value is not the author's to fix).
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(ROOT, "apps", "orchestrator-gateway")
if GATEWAY not in sys.path:
    sys.path.insert(0, GATEWAY)
TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

from developer_agent.preflight_validator import (  # noqa: E402
    ManifestHydrationError,
    hydrate_kubernetes_manifests,
    k8s_manifest_unresolved_error,
)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

import test_step1_s1b_generation as s1b  # noqa: E402
from developer_agent.validators.base import ValidationContext  # noqa: E402
from developer_agent.validators.step1 import K8sPlaceholderValidator, build_step1_stack  # noqa: E402
from shared.diagnostics import ErrorClass, RepairBudgetExhausted, StageError  # noqa: E402
from shared.hallucination_stack import HallucinationStackSettings  # noqa: E402

CODE = "K8S.PLACEHOLDER_UNRESOLVED"
PATH = "k8s/shop.yaml"
AUTHOR = "platform_engineer"


def _manifest(image: str) -> str:
    return ("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: shop\nspec:\n  template:\n    spec:\n"
            f"      containers:\n      - name: shop\n        image: {image}\n")


UNKNOWN = _manifest("${ARTIFACT_REGISTRY_URL}/shop:latest")   # the 10-13 recording's ad-hoc token
FIXED = _manifest("ghcr.io/org/shop:1.0")
NEEDS_PROJECT = _manifest("${ARTIFACT_REGISTRY}/shop:latest")
WI_UNKNOWN = ("apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: shop\n  annotations:\n"
              "    iam.gke.io/gcp-service-account: shop@${GSA_PROJECT}.iam.gserviceaccount.com\n")


def _ctx(files):
    return ValidationContext.build(files, ownership=lambda p: None)


# ------------------------------------------------------------------------------------------------ units
def test_deferred_hydration_keeps_the_unknown_token_and_substitutes_known_ones():
    text = _manifest("${IMAGE}") + "---\n" + _manifest("${PRODUCT_ID}:v1")
    out, _ = hydrate_kubernetes_manifests({PATH: text}, "shop", defer_unresolved=True)
    assert out[PATH] == _manifest("${IMAGE}") + "---\n" + _manifest("shop:v1")   # nothing guessed or dropped
    with pytest.raises(ManifestHydrationError) as ei:   # default (legacy) is unchanged: it raises
        hydrate_kubernetes_manifests({PATH: text}, "shop")
    assert ei.value.code == CODE and ei.value.path == PATH


def test_deferral_never_covers_an_unavailable_value():
    with pytest.raises(ManifestHydrationError) as ei:
        hydrate_kubernetes_manifests({PATH: NEEDS_PROJECT}, "shop", project_id="", region="europe-west1",
                                     defer_unresolved=True)
    assert ei.value.code == "K8S.PLACEHOLDER_VALUE_UNAVAILABLE" and ei.value.unavailable == "project_id"


@pytest.mark.parametrize("text", [UNKNOWN, WI_UNKNOWN])
def test_validator_reports_the_same_typed_finding_as_hydration(text):
    [d] = K8sPlaceholderValidator().validate(_ctx({PATH: text}))
    err = k8s_manifest_unresolved_error(PATH, text)
    assert (d.tool, d.code, d.file, d.severity, d.error_class) == ("yaml", CODE, PATH, "error", ErrorClass.CODE_DEFECT)
    assert d.message == str(err) and "${PROJECT_ID}" in d.message   # names the five allowed placeholders


@pytest.mark.parametrize("files", [
    {PATH: FIXED},
    {PATH: _manifest("redis:7.2") + "---\n" + _manifest("europe-west1-docker.pkg.dev/p-1/shop/api:v1")},
    {PATH: "env:\n- name: X\n  value: $PROJECT_ID\n"},          # `$` outside an image / WI annotation
    {PATH: "key: [unclosed\n"},                                  # unparseable: apply's finding, not judged here
    {"apps/shop/config.yaml": UNKNOWN, "apps/k8sproxy/x.yaml": UNKNOWN},   # not k8s manifest paths
])
def test_validator_negative_valid_or_non_manifest_files_yield_nothing(files):
    assert K8sPlaceholderValidator().validate(_ctx(files)) == []


def test_validator_is_always_registered_blocking():
    stack = build_step1_stack(validate_client=s1b.Client(), verifier_factory=MagicMock())
    assert stack.mode_of("V-K8S-PH") == "blocking"


@pytest.mark.parametrize("mode", ["off", "report_only"])
def test_validator_cannot_be_downgraded(mode):
    """RT F1: V-K8S-PH is the only guard of the deferred hydration on the stack path."""
    with pytest.raises(ValueError, match="V-K8S-PH"):
        build_step1_stack(validate_client=s1b.Client(), verifier_factory=MagicMock(), modes={"V-K8S-PH": mode})


def test_no_yaml_parser_is_unavailable_never_a_pass():
    """RT F2: without PyYAML the validator raises ValidatorUnavailable, so the stack reports UNAVAILABLE."""
    from developer_agent.validators.base import ValidatorStack, ValidatorUnavailable
    with patch.dict(sys.modules, {"yaml": None}):
        with pytest.raises(ValidatorUnavailable):
            K8sPlaceholderValidator().validate(_ctx({PATH: UNKNOWN}))
        stack = ValidatorStack()
        stack.register(K8sPlaceholderValidator(), "blocking")
        report = stack.run(_ctx({PATH: UNKNOWN}))
    assert report.status == "UNAVAILABLE" and report.tools_unavailable == ["V-K8S-PH"]


# ------------------------------------------------------------------------------------------------ end to end
def _generate(draft, repairs=None, iterations=2, prompts=None):
    """generate_code_files through the step-1 stack; the k8s manifest is attributed to AUTHOR. Each repair call pops
    the next answer from `repairs` and records (persona, prompt)."""
    from developer_agent import handler as h
    agent = s1b._agent(s1b._runtime(s1b.Client(), settings=HallucinationStackSettings(
        repair_max_iterations_precommit=iterations)))
    plan = MagicMock()
    plan.execution_mode = [m for m in h.SwarmExecutionMode if m != h.SwarmExecutionMode.SOLO_FAST_PATH][0]
    plan.tasks = [MagicMock()]
    d = dict(draft)
    repairs = list(repairs or [])
    prompts = prompts if prompts is not None else []

    class FakeDispatcher:
        def __init__(self, *a, **k):
            self.last_file_attribution = {p: (AUTHOR if p.startswith("k8s/") else
                                              "iac_worker" if p.endswith(".tf") else "backend_worker") for p in d}
            self.envelope_checks = [{"ok": True, "error": None}]

        async def execute_phased_junior_swarm(self, *a, **k):
            return dict(d)

        def invoke_repair(self, persona, system_instruction, prompt, *a, **k):
            prompts.append((persona, prompt))
            files = repairs.pop(0) if repairs else {}
            return {"files": dict(files), "envelope_ok": True, "error": None, "finish_reason": "STOP",
                    "tokens_in": 10, "tokens_out": 10, "tokens_thoughts": 0, "model": "fake", "persona": persona}

    with patch.object(h, "LeadDeveloperOrchestrator") as lead, patch.object(h, "SwarmDispatcher", FakeDispatcher), \
            patch.object(agent, "fetch_existing_repo_files", return_value={}), \
            patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GCP_PROJECT": ""}), \
            patch("google.cloud.firestore.Client", side_effect=RuntimeError("no Firestore in tests")):
        lead.return_value.decompose_specification.return_value = plan
        files = agent.generate_code_files(product_id="shop", spec_text="FastAPI uploads service", task_dag=[],
                                          trace_id="trace-fd4afr",
                                          architect_compute_intent={"target_compute_services": ["shop"]},
                                          allow_unauthenticated=True, enable_direct_iap=False,
                                          domain_restricted_sharing=False)
    return agent, files


def test_unknown_placeholder_is_routed_to_the_manifest_author_and_the_repair_passes():
    prompts = []
    agent, files = _generate(dict(s1b.DRAFT, **{PATH: UNKNOWN}), repairs=[{PATH: FIXED}], prompts=prompts)
    [(persona, prompt)] = prompts
    assert persona == AUTHOR                                   # the manifest's author, not a default persona
    assert CODE in prompt and PATH in prompt and "${ARTIFACT_REGISTRY_URL}" in prompt
    assert files[PATH] == FIXED                                # the repaired manifest is the validated tree
    assert agent.last_validation_report.status == "PASS"
    [ev] = [e for e in agent.stack_run("trace-fd4afr")["repair_events"] if e.kind != "junior_reask"]
    assert ev.accepted and ev.persona == AUTHOR and ev.files == [PATH] and ev.codes == [CODE]


def test_budget_exhausted_is_the_same_typed_hard_failure():
    prompts = []
    with pytest.raises(RepairBudgetExhausted) as ei:   # the author keeps the unknown token every time
        _generate(dict(s1b.DRAFT, **{PATH: UNKNOWN}), repairs=[{PATH: UNKNOWN}] * 3, iterations=2, prompts=prompts)
    assert prompts and all(p == AUTHOR for p, _ in prompts)
    report = ei.value.report
    assert report.status == "FAIL" and ei.value.error_class is ErrorClass.CODE_DEFECT
    [d] = report.diagnostics
    assert (d.tool, d.code, d.file) == ("yaml", CODE, PATH)
    import test_fd4af_k8s_manifest_hydration as fd4af
    typed = fd4af._typed_failure_of_eval(ei.value)   # the eval harness scores it developer_failed_typed, as before
    assert typed["error_class"] == "CODE_DEFECT" and typed["codes"] == [CODE]


def test_repair_to_a_placeholder_without_a_value_stays_a_hard_stop():
    """The eval harness has no workload project: a repair that adopts ${ARTIFACT_REGISTRY} stops the stage with
    K8S.PLACEHOLDER_VALUE_UNAVAILABLE (GATE_UNAVAILABLE); it is never retried or guessed."""
    prompts = []
    with pytest.raises(StageError) as ei:
        _generate(dict(s1b.DRAFT, **{PATH: UNKNOWN}), repairs=[{PATH: NEEDS_PROJECT}] * 3, prompts=prompts)
    assert len(prompts) == 1
    assert not isinstance(ei.value, RepairBudgetExhausted)
    assert ei.value.report.status == "UNAVAILABLE"
    assert [d.code for d in ei.value.report.diagnostics] == ["K8S.PLACEHOLDER_VALUE_UNAVAILABLE"]


def test_valid_manifest_is_byte_identical_and_never_repaired():
    prompts = []
    _, files = _generate(dict(s1b.DRAFT, **{PATH: FIXED}), prompts=prompts)
    assert files[PATH] == FIXED and prompts == []


def test_legacy_path_without_the_stack_still_raises_typed():
    agent = s1b._agent(None)   # no stack runtime (unit tests / scripts): no repair loop, so no deferral
    with pytest.raises(StageError) as ei:
        s1b._generate(agent, dict(s1b.DRAFT, **{PATH: UNKNOWN}), trace="trace-fd4afr-legacy")
    assert not isinstance(ei.value, RepairBudgetExhausted)
    assert [d.code for d in ei.value.report.diagnostics] == [CODE]
