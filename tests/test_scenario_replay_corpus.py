"""SCENARIO-REPLAY-CORPUS (owner 11-13): every scenario in tests/scenario_corpus/ replayed through the real gateway
and developer code (tests/scenario_replay.py), checked against the typed outcome it states. A merge gate: a fix is not
done until its scenario and the neighbouring scenarios pass. A scenario whose expected outcome needs a fix that has not
merged carries `"xfail": {"row": ..., "reason": ...}` (strict): when the fix lands the replay passes, the strict
marker fails the run, and the merge removes the marker (docs/planning/scenario-replay-corpus-plan.md, section 6).
Hermetic: no network, no Firestore, no LLM, no tofu."""
import hermetic_guard  # noqa: F401  (first import)

import os
import re
import sys

import pytest

TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

import scenario_replay as SR  # noqa: E402

pytest.importorskip("google.genai")


def _params():
    out = []
    for path in SR.scenario_files():
        sc = SR.load_scenario(path)
        marks = []
        xf = sc.get("xfail")
        if xf:
            # RT R2: only "the platform did not reach the expected outcome yet" is the expected failure; a harness or
            # fixture error, or a changed pre-fix route (`xfail.current`), fails the run
            marks.append(pytest.mark.xfail(strict=True, raises=SR.ScenarioExpectationNotMet,
                                           reason=f"{xf['row']} not merged: {xf['reason']}"))
        out.append(pytest.param(path, id=sc["id"], marks=marks))
    return out


REQUIRED_KEYS = ("title", "source", "mechanism", "product_id", "trace", "topology", "drafts", "generations", "judge",
                 "expect")
# fixtures are anonymized: illustrative ids only (letters and dashes; live workload, install and project ids carry
# digits), and no principal outside the reserved example domain
ANON_ID = re.compile(r"[a-z]+(-[a-z]+)*")
PRINCIPAL = re.compile(r"(user|group|serviceAccount):[a-z0-9.-]+@example\.com")
EMAIL_DOMAIN = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
PINNED_WORKFLOW_CONDITIONS = (
    '${default(map.get(qa_output, "passed"), false) == true}',
    '${default(map.get(qa_output, "error_class"), "") == "CODE_DEFECT" and default(map.get(qa_output, "retryable"), '
    'false) == true and retry_count < max_retries}',
    '- retry_count: ${retry_count + 1}',
    '- tf_validation_report: null',
    '${deploy_status == "SUCCESS"}',
    '${default(map.get(deployment_output, "operator_required"), false) == true}',
    '${(deploy_error_class == "IAC_DEFECT" or deploy_error_class == "") and tf_retry_count < max_tf_retries}',
    '- tf_retry_count: ${tf_retry_count + 1}',
    "- tf_remediation_context: '${default(map.get(deployment_output, \"error\"), \"Terraform deployment validation failed\")}'",
    '- tf_validation_report: ${default(map.get(deployment_output, "validation_report"), null)}',
)


def test_corpus_has_the_six_owner_fixtures_and_a_control():
    ids = {SR.load_scenario(p)["id"].split("-")[0] for p in SR.scenario_files()}
    assert {"01", "02a", "02b", "03a", "03b", "04", "05", "06"} <= ids


@pytest.mark.parametrize("path", SR.scenario_files(), ids=os.path.basename)
def test_every_scenario_is_well_formed_and_anonymized(path):
    sc = SR.load_scenario(path)
    assert all(k in sc for k in REQUIRED_KEYS), [k for k in REQUIRED_KEYS if k not in sc]
    xf = sc.get("xfail")
    assert set(xf or {}) <= {"row", "reason", "current"} and (not xf or (xf["row"] and xf.get("current"))), \
        "a pending scenario names its row and pins the route it takes before the fix (xfail.current)"
    assert set(sc["expect"]) <= {"outcome", "any_of", "never_plan_reasons", "never_seed_files", "known_violations"}
    traces = [sc["trace"]] + [s["trace"] for s in sc.get("prehistory") or []]
    assert ANON_ID.fullmatch(sc["product_id"]) and all(ANON_ID.fullmatch(t) for t in traces), (sc["product_id"], traces)
    principals = (sc.get("access") or {}).get("invoker_principals") or []
    assert all(PRINCIPAL.fullmatch(p) for p in principals), principals
    # RT S7: no address outside the reserved example domain in any string of the file (a decorator such as
    # `@app.get` has no local part before its `@`)
    domains = {d.lower() for text in _strings(sc) for d in EMAIL_DOMAIN.findall(text)}
    assert domains <= {"example.com"}, domains


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield k
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)


def test_harness_seams_exist(monkeypatch):
    """RT S3: every product attribute the harness patches or calls exists (a missing one would otherwise only show as
    a broken replay)."""
    # inside a real replay (the clean happy path), so the modules checked are the ones a scenario uses; a separately
    # loaded gateway would re-import the stack modules this module's replays share
    runner = SR.ScenarioRunner(SR.load_scenario(os.path.join(SR.CORPUS_DIR, "06-happy-path.json")), monkeypatch)
    runner.run()
    assert SR.missing_seams(runner.gw) == []


def test_a_harness_break_fails_a_pending_scenario_instead_of_xfailing_it(monkeypatch):
    """RT R2: an AttributeError inside the harness surfaces as itself, never as the expected miss."""
    sc = SR.load_scenario(os.path.join(SR.CORPUS_DIR, "04-golden-module-plan-error.json"))

    def broken(self, trace, tf_retry):
        raise AttributeError("injected harness break")
    monkeypatch.setattr(SR.ScenarioRunner, "_deploy_result", broken)
    with pytest.raises(AttributeError):
        SR.run_scenario(sc, monkeypatch)


def test_workflow_routing_conditions_are_the_ones_the_model_mirrors():
    """RT S1: the harness's workflow model mirrors these exact YAML conditions; a routing change in the YAML fails here
    and must update ScenarioRunner.workflow in the same change."""
    with open(SR.WORKFLOW_YAML, encoding="utf-8") as fh:
        text = fh.read()
    for cond in PINNED_WORKFLOW_CONDITIONS:
        assert cond in text, cond


@pytest.mark.parametrize("path", _params())
def test_scenario(path, monkeypatch):
    sc = SR.load_scenario(path)
    replay = SR.run_scenario(sc, monkeypatch)
    problems = SR.check_expectations(replay, sc)
    if os.environ.get("SCENARIO_REPLAY_VERBOSE") == "1":
        print(f"\n=== {sc['id']}\n{SR.summarize(replay)}")
    if not problems:
        return   # a pending scenario that gets here turns XPASS(strict): its fix landed, remove the marker
    trail = "\n--- replay ---\n" + SR.summarize(replay)
    changed = SR.pending_route_problems(replay, sc)
    if changed:
        raise SR.ScenarioRouteChanged("the route before the fix changed (xfail.current): " + "; ".join(changed) + trail)
    raise SR.ScenarioExpectationNotMet("\n".join(problems) + trail)
