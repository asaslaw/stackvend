"""
CI fixture: render the golden workload (fake LLM, canned app; lane 19 / row 27a) so the iac-validate job can run
``tofu init -backend=false && tofu validate`` on what the platform actually generates (FD-60; red-team F13).

Runs under pytest so the hermetic guard is active (DeveloperAgent would otherwise try Firestore / Gemini clients):
    pytest tests/test_ci_render_golden.py --render-to=/some/dir
Without --render-to it renders into tmp_path and only checks the shape (part of the normal suite).
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO, "apps", "orchestrator-gateway")


def _gateway_on_path():
    for p in (REPO, GATEWAY):
        if p not in sys.path:
            sys.path.insert(0, p)


def _scaffold():
    _gateway_on_path()
    with hermetic_guard.unavailable("google.genai.Client", "Gemini"), \
            hermetic_guard.unavailable("google.cloud.firestore.Client", "Firestore"):
        from developer_agent.handler import DeveloperAgent

        # Lane 19 L19-3b (owner register row 27a): the template scaffold is deleted. Render through the real
        # generation path with a fake model returning a small canned app: the golden root module, vendored modules
        # and workflows are platform output either way.
        from unittest.mock import patch

        sys.path.insert(0, os.path.dirname(__file__))
        from _lane19_fake_genai import FakeGenaiClient, canned_workload_files

        agent = DeveloperAgent(project_id="mock-stackvend-project")
        agent.genai_client = FakeGenaiClient(files=canned_workload_files("ciportal"))
        with patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false"}), \
                patch.object(agent, "fetch_existing_repo_files", return_value={}):
            return agent.generate_code_files(product_id="ciportal",
                                             spec_text="FastAPI web portal with a Firestore catalog", task_dag=[], allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False)


def test_render_golden_workload(request, tmp_path):
    out = request.config.getoption("--render-to") or str(tmp_path)
    files = _scaffold()
    assert "infra/workload/main.tf" in files and "infra/workload/variables.tf" in files
    assert any(k.startswith("infra/modules/compute-cloudrun/") for k in files)
    for rel, content in files.items():
        dest = os.path.realpath(os.path.join(out, rel))
        assert dest.startswith(os.path.realpath(out) + os.sep), rel  # scaffold keys are repo-relative
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(content)
    assert os.path.isfile(os.path.join(out, "infra", "workload", "main.tf"))


@pytest.fixture(autouse=True)
def _fd7m_a_no_record_region(monkeypatch):
    """FD-7M-a (SAT-23 RT F1): these tests build developer agents without a Firestore client while the test env
    configures a project, which the dispatch now refuses (REGION_UNAVAILABLE: the recorded region cannot be read).
    They are not about regions: keep the platform-region answer they always had (the record-region paths are covered
    by tests/test_fd7m_a_regions_gw.py)."""
    _gateway_on_path()  # the iac-validate job runs this file alone, so no earlier test has set the path
    with hermetic_guard.unavailable("google.genai.Client", "Gemini"), \
            hermetic_guard.unavailable("google.cloud.firestore.Client", "Firestore"):
        from developer_agent import handler as _handler
        from developer_agent import terraform_engine as _engine
    monkeypatch.setattr(_handler, "resolve_workload_region",
                        lambda db=None, product_id=None, **kw: _engine.resolve_workload_region(db, **kw))
