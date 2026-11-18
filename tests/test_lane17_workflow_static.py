"""Lane 17 (FD-4AJ / FD-4R / FD-4AG): static structure tests for workflows/main_orchestrator.yaml.

PR-0 section: lane 13's report §6.2 hunks (a)-(f) (register rows 19 option A, 19b, 19o, 19p, 19q; B6; D7). These
assertions are written against step names and graph reachability, not file layout, so they hold for the PR-0 YAML
and for the PR-2 restructure (pipeline body in the `run_pipeline` subworkflow) alike (plan §R.4: "PR-2 preserves
every PR-0 behavior; the static test pins each one").

Hermetic: parses YAML only.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os

import pytest
import yaml

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WORKFLOW = os.path.join(REPO, "workflows", "main_orchestrator.yaml")


def _text():
    with open(WORKFLOW, encoding="utf-8") as fh:
        return fh.read()


def _doc():
    return yaml.safe_load(_text())


def _flatten(steps, follow, out):
    """Name -> (body, implicit fall-through target) for every step, nested try/except/steps included."""
    names = [next(iter(s)) for s in steps]
    for i, step in enumerate(steps):
        name, body = next(iter(step.items()))
        nxt = names[i + 1] if i + 1 < len(names) else follow
        out[name] = (body, nxt)
        if isinstance(body.get("steps"), list):
            _flatten(body["steps"], body.get("next", nxt), out)
        for key in ("try", "except"):
            sub = body.get(key)
            if isinstance(sub, dict) and isinstance(sub.get("steps"), list):
                _flatten(sub["steps"], body.get("next", nxt), out)
    return out


def pipeline_steps(doc=None):
    """The subworkflow that holds the pipeline body: `run_pipeline` after PR-2, `main` before."""
    doc = doc or _doc()
    body = doc["run_pipeline"] if "run_pipeline" in doc else doc["main"]
    return _flatten(body["steps"], None, {})


def edges(name, flat):
    body, fall = flat[name]
    out = set()
    if "switch" in body:
        out |= {c["next"] for c in body["switch"] if "next" in c}
        cases_fall = any("next" not in c and "raise" not in c and "return" not in c for c in body["switch"])
        if cases_fall and fall:
            out.add(fall)
    exc = body.get("except")
    if isinstance(exc, dict) and exc.get("steps"):
        out.add(next(iter(exc["steps"][0])))
    tr = body.get("try")
    if isinstance(tr, dict) and tr.get("steps"):
        out.add(next(iter(tr["steps"][0])))
    if "steps" in body and isinstance(body["steps"], list) and body["steps"]:
        out.add(next(iter(body["steps"][0])))
    if "next" in body:
        out.add(body["next"])
    elif "raise" not in body and "return" not in body and "switch" not in body and fall:
        out.add(fall)
    elif "switch" in body and fall and "next" not in body:
        # a switch with no matching case falls through
        out.add(fall)
    return {e for e in out if e != "end"}


def reachable(flat, start, stop=(), skip_edges=()):
    seen, stack = set(), [start]
    while stack:
        n = stack.pop()
        if n in seen or n not in flat:
            continue
        seen.add(n)
        if n in stop:
            continue
        stack.extend(e for e in edges(n, flat) if (n, e) not in skip_edges)
    return seen


def init_assigns(flat):
    out = {}
    for item in flat["init_context"][0]["assign"]:
        out.update(item)
    return out


@pytest.fixture(scope="module")
def flat():
    return pipeline_steps()


# --------------------------------------------------------------------------------------------- PR-0 (a) row 19 A
def test_pr0_a_qa_readiness_step_contract(flat):
    body, _ = flat["check_qa_readiness"]
    assert body["try"]["call"] == "http.get"
    assert body["try"]["args"]["url"] == '${gateway_url + "/agent/qa/readiness"}'
    assert body["try"]["args"]["auth"] == {"type": "OIDC"} and body["try"]["args"]["timeout"] == 60
    assert body["except"]["steps"]


def test_pr0_a_qa_readiness_precedes_architect_vending_and_developer(flat):
    """FULL_BUILD / RESUME_DEVELOPER: no path from the pipeline start reaches the architect, vending or the developer
    without the readiness check. (The DEPLOY_ONLY branch is excluded: it never runs QA, hunk (a).)"""
    first = next(iter(flat))
    deploy = [c["next"] for c in flat["evaluate_resume_checkpoint"][0]["switch"] if "DEPLOY_ONLY" in str(c["condition"])]
    seen = reachable(flat, first, stop=("check_qa_readiness",),
                     skip_edges={("evaluate_resume_checkpoint", d) for d in deploy})
    for gated in ("architect_decomposition", "create_vending_callback", "dispatch_vending_task",
                  "dispatch_developer_implementation"):
        assert gated not in seen, f"{gated} reachable without check_qa_readiness"
    assert "check_qa_readiness" in seen


def test_pr0_a_deploy_only_skips_qa_readiness(flat):
    cases = flat["evaluate_resume_checkpoint"][0]["switch"]
    deploy = [c for c in cases if "DEPLOY_ONLY" in str(c["condition"])]
    assert deploy and deploy[0]["next"] != "check_qa_readiness"


# --------------------------------------------------------------------------------------------- PR-0 (b) 19b
def test_pr0_b_gatekeeper_sends_committed_paths(flat):
    body = flat["gatekeeper_verification"][0]["try"]["args"]["body"]
    assert body["committed_paths"] == '${default(map.get(developer_output.body, "files_committed"), null)}'


# --------------------------------------------------------------------------------------------- PR-0 (c) B6/F3/19q
def test_pr0_c_qa_is_commit_bound_and_guarded(flat):
    """LONG-STAGE-CALLBACK (owner 11-13): QA runs as a gateway job answered by callback (run_stage_job); the request
    is the same commit-bound body, and the awaited answer is routed exactly like the former synchronous response."""
    body, _ = flat["dispatch_qa_verification"]
    assert body["try"]["call"] == "run_stage_job"
    args = body["try"]["args"]
    assert args["path"] == "/agent/qa/verify-job" and args["stage"] == "qa" and args["await_timeout_s"] == 3000
    assert args["request"]["expected_commit_sha"] == "${gatekeeper_output.body.commit_sha}"
    assert args["request"]["attempt"] == "${retry_count}"
    assert "task_dag" in args["request"]
    assert body["except"]["steps"]
    for gone in ("create_qa_callback", "await_qa_callback"):
        assert gone not in flat
    assert "/agent/qa/verify-async" not in _text()


def test_pr0_c_qa_retries_only_retryable_code_defects(flat):
    cases = flat["check_qa_status"][0]["switch"]
    retry = [c for c in cases if c.get("next") == "increment_qa_retry"]
    assert len(retry) == 1
    cond = retry[0]["condition"]
    assert '"CODE_DEFECT"' in cond and '"retryable"), false) == true' in cond and "retry_count < max_retries" in cond


# --------------------------------------------------------------------------------------------- PR-0 (d) 19o
def test_pr0_d_three_qa_retries(flat):
    """QA-RETRIES (owner 10-29): up to 3 QA CODE_DEFECT repair rounds (FD-4F 19o had 1)."""
    assert init_assigns(flat)["max_retries"] == 3


def test_qa_retries_change_only_the_qa_loop(flat):
    """QA-RETRIES: `max_retries` is read only by the QA retry condition; the deploy loop keeps its own budget
    (max_tf_retries 2) and the http retry policy keeps its literal max_retries 10."""
    assigns = init_assigns(flat)
    assert assigns["max_tf_retries"] == 2 and assigns["retry_count"] == 0
    text = _text()
    assert text.count("retry_count < max_retries") == 1 and text.count("max_retries: 10") == 1


# --------------------------------------------------------------------------------------------- PR-0 (e) 19p
def test_pr0_e_no_public_by_default():
    text = _text()
    assert '"allow_unauthenticated"), true)' not in text
    assert 'allow_unauthenticated"), default(map.get(args, "allow_unauthenticated"), true)' not in text


# --------------------------------------------------------------------------------------------- PR-0 (f) D7
def test_pr0_f_release_binds_the_verified_commit(flat):
    body = flat["release_promotion"][0]["try"]["args"]["body"]
    assert body["expected_commit_sha"] == "${gatekeeper_output.body.commit_sha}"
