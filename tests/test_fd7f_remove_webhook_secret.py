"""FD-7F (register row FD-7F-REMOVE-SECRET): the unused castor-webhook-signing-secret leaves the platform Terraform.

An install that already has the secret forgets it (`removed { lifecycle { destroy = false } }`), which is a state-only
action, and the apply gate in scripts/common/platform_target.sh must not count it as a delete. Static checks plus the
gate's own plan evaluator run on plan JSON; nothing is planned or applied here.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import glob
import json
import os
import subprocess
import sys

import hcl2

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
PLATFORM_DIR = os.path.join(REPO_ROOT, "infra", "platform")
GATE_SH = os.path.join(REPO_ROOT, "scripts", "common", "platform_target.sh")
CONFIG_DOC = os.path.join(REPO_ROOT, "documentation", "configuration.md")
ADDRESS = "google_secret_manager_secret.webhook_signing_secret"
SECRET_ID = "castor-webhook-signing-secret"


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def _main_tf():
    with open(os.path.join(PLATFORM_DIR, "main.tf"), encoding="utf-8") as fh:
        return hcl2.load(fh)


def _gate_program():
    """The exact evaluator sv_gated_apply runs on the saved plan (the heredoc in platform_target.sh)."""
    text = _read(GATE_SH)
    start_marker = "\"${refresh_only}\" <<'PY'\n"
    start = text.index(start_marker) + len(start_marker)
    return text[start:text.index("\nPY\n", start)]


def _run_gate(tmp_path, changes):
    plan = tmp_path / "plan.json"
    plan.write_text(json.dumps({"resource_changes": changes}), encoding="utf-8")
    script = tmp_path / "gate.py"
    script.write_text(_gate_program(), encoding="utf-8")
    return subprocess.run([sys.executable, str(script), str(plan), "0"], capture_output=True, text=True, timeout=60,
                          env=hermetic_guard.child_env())


def _change(actions):
    return {"address": ADDRESS, "change": {"actions": actions}}


def test_the_secret_resource_is_gone_from_every_platform_file():
    for block in _main_tf().get("resource", []):
        assert "webhook_signing_secret" not in (block.get("google_secret_manager_secret") or {})
    for path in glob.glob(os.path.join(PLATFORM_DIR, "*.tf")):
        assert f'"{SECRET_ID}"' not in _read(path), path


def test_an_existing_install_forgets_the_secret_instead_of_destroying_it():
    removed = [b for b in _main_tf().get("removed", []) if ADDRESS in str(b.get("from"))]
    assert len(removed) == 1, removed
    lifecycle = removed[0]["lifecycle"]
    lifecycle = lifecycle[0] if isinstance(lifecycle, list) else lifecycle
    assert lifecycle["destroy"] is False


def test_the_engine_floor_accepts_removed_with_lifecycle():
    assert 'required_version = ">= 1.10.0"' in _read(os.path.join(PLATFORM_DIR, "providers.tf"))


def test_the_configuration_guide_no_longer_lists_the_secret():
    assert SECRET_ID not in _read(CONFIG_DOC)


def test_the_apply_gate_does_not_count_a_forget_as_a_delete(tmp_path):
    res = _run_gate(tmp_path, [_change(["forget"])])
    assert res.returncode == 0, res.stderr
    assert "forget=1" in res.stderr
    assert "DESTRUCTIVE" not in res.stderr


def test_the_apply_gate_still_refuses_a_real_delete_of_the_same_address(tmp_path):
    res = _run_gate(tmp_path, [_change(["delete"])])
    assert res.returncode == 10, res.stderr
    assert ADDRESS in res.stderr


def test_the_apply_gate_still_refuses_a_forget_next_to_a_delete(tmp_path):
    res = _run_gate(tmp_path, [_change(["forget"]), {"address": "google_pubsub_topic.x", "change": {"actions": ["delete"]}}])
    assert res.returncode == 10, res.stderr
