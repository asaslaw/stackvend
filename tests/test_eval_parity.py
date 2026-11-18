"""FD-30 production-parity checks (red-team B7, H4). Read-only parsing of product files; nothing is imported."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "eval"))

from stackvend_eval import paths  # noqa: E402
from stackvend_eval.guard import DISABLED_ADC, EMULATOR_VARS, Guard  # noqa: E402

PROD_ENV = json.loads((ROOT / "eval" / "config" / "prod_env.json").read_text())


def _gateway_env_from_tf():
    from stackvend_eval import hclparse
    doc = hclparse.loads((ROOT / "infra" / "platform" / "main.tf").read_text())
    for labels, body in hclparse.blocks(doc, "resource"):
        if labels[0] != "google_cloud_run_v2_service":
            continue
        for tmpl in body.get("template", []) or []:
            for c in tmpl.get("containers", []) or []:
                env = {e.get("name"): e.get("value") for e in c.get("env", []) or [] if isinstance(e, dict)}
                if "GEMINI_MODEL" in env:
                    return {k: _resolve_shared_env(hclparse, v) for k, v in env.items()}
    return None


def _resolve_shared_env(hclparse, value):
    """STAGE-JOB-RUNNER: the services read their env values from infra/platform/stage_runner.tf
    local.platform_service_env (shared with the stage-runner job); follow that reference."""
    prefix, suffix = '${local.platform_service_env["', '"]}'
    if not (isinstance(value, str) and value.startswith(prefix) and value.endswith(suffix)):
        return value
    doc = hclparse.loads((ROOT / "infra" / "platform" / "stage_runner.tf").read_text())
    for loc in doc.get("locals", []) or []:
        if "platform_service_env" in loc:
            return loc["platform_service_env"][value[len(prefix):-len(suffix)]]
    return value


@pytest.mark.skipif(not paths.have_hcl2(), reason="python-hcl2 not installed (eval/requirements.txt)")
def test_prod_env_profile_matches_gateway_service_env():
    env = _gateway_env_from_tf()
    assert env, "gateway Cloud Run env not found in infra/platform/main.tf"
    for k, v in PROD_ENV["env"].items():
        assert env.get(k) == v, f"{k}: profile {v!r} != infra/platform/main.tf {env.get(k)!r}"
    for k in PROD_ENV["unset_in_production"]:
        assert k not in env, f"{k} is now set in production; add it to eval/config/prod_env.json"
    # every behavior-bearing GEMINI_* literal in TF is mirrored, except the model, which is a required argument
    for k, v in env.items():
        if k and k.startswith("GEMINI_") and k != "GEMINI_MODEL" and v and "${" not in str(v):
            assert PROD_ENV["env"].get(k) == v, k


def test_model_is_a_required_argument_and_not_in_the_profile():
    assert "GEMINI_MODEL" not in PROD_ENV["env"]
    import run_examples
    with pytest.raises(SystemExit):
        run_examples.build_parser().parse_args(["--llm", "synthetic"])
    a = run_examples.build_parser().parse_args(["--llm", "synthetic", "--model", "gemini-3.7-flash"])
    assert a.model == "gemini-3.7-flash"


def test_child_env_is_credential_free(tmp_path):
    import run_examples
    env = run_examples.child_env(tmp_path, "gemini-3.8-flash", PROD_ENV["env"])
    assert env["GOOGLE_APPLICATION_CREDENTIALS"] == DISABLED_ADC
    assert env["GEMINI_MODEL"] == "gemini-3.8-flash" and env["PROJECT_ID"] == ""
    assert not [v for v in EMULATOR_VARS if v in env]
    assert Guard.env_problems(env) == []
    assert "/opt/homebrew/bin" not in env["PATH"]
    shims = {p.name for p in (tmp_path / "shims").iterdir()}
    assert {"git", "gcloud", "kubectl"} <= shims and not {"tofu", "terraform"} & shims


def test_commit_and_open_pr_still_has_the_capture_point():
    """H4: the harness captures the committed tree at `self.fetch_github_token()` inside commit_and_open_pr, after
    the pre-commit gate, and relies on the no-token MOCK_COMMITTED return. Fail loudly if that shape changes."""
    src = (ROOT / "apps" / "orchestrator-gateway" / "developer_agent" / "handler.py").read_text()
    tree = ast.parse(src)
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "commit_and_open_pr")
    calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
    token_calls = [c for c in calls if c.func.attr == "fetch_github_token"
                   and isinstance(c.func.value, ast.Name) and c.func.value.id == "self"]
    gate_calls = [c for c in calls if c.func.attr in ("verify_and_cure", "purge_shadowed_package_files")]
    assert token_calls and gate_calls
    assert min(c.lineno for c in gate_calls) < min(c.lineno for c in token_calls)
    assert "files" in {a.arg for a in fn.args.args}
    consts = {n.value for n in ast.walk(fn) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    # FD-4F A9 (Q-E): the no-token path now raises GATE_UNAVAILABLE `VCS_CREDENTIAL_UNAVAILABLE` (the harness maps it
    # to its MOCK_COMMITTED stage status, eval/stackvend_eval/stages.py `_precommit`); older products return
    # MOCK_COMMITTED. One of the two contracts must be present.
    assert "VCS_CREDENTIAL_UNAVAILABLE" in consts or "MOCK_COMMITTED" in consts
