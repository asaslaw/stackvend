"""DEPLOY-HEALTH-WORDING (owner 10-27) and two cosmetic stage texts seen live on 10-27.

- Nothing in the pipeline probes a deployed service (post-QA pre-flight D10), so a successful run says the service was
  deployed, never "verified healthy": the gateway's SRE stage summary, the Control Center's After-Action Report
  (deterministic text and the model's instructions) and the dashboard's success debrief line.
- FinOps: the workflow's SUCCESS literal said "keyword heuristic", but the cost MCP prices the plan from the
  architect's typed compute record; the gateway stores accurate text for exactly that typed (stage, status) pair
  and leaves every other stage summary unchanged.
- Vending: the summary names the repository's provider from the vended result's typed `vcs_provider` ("Serverless
  Git repository" on a Serverless Git install), never "GitHub Repo" for every install.

Hermetic: in-memory fakes, no cloud client, no network.
"""
import hermetic_guard  # noqa: F401  (must stay the first import)

import os
import sys
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(__file__))

from fd4f_support import FakeDB, gw  # noqa: F401,E402  (gw is a fixture)
import destructive_guard_fakes as f  # noqa: E402

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TRACE, PID = "tr-wording-1", "shop-app"


def _post(gw, monkeypatch, db, body):
    import google.cloud.firestore as fs_mod

    monkeypatch.setattr(fs_mod, "Client", lambda *a, **k: db)
    monkeypatch.setenv("PROJECT_ID", "mock-stackvend-project")
    r = TestClient(gw.app).post("/events/workflow-status", json={"trace_id": TRACE, "product_id": PID, **body})
    assert r.status_code == 200, r.text
    return db.docs[f"pipeline_executions/{TRACE}"]


# ------------------------------------------------------------------ gateway: SRE stage on a successful run
def test_succeeded_run_says_deployed_not_verified_healthy(gw, monkeypatch):
    pe = _post(gw, monkeypatch, FakeDB(), {"status": "SUCCEEDED"})
    sre = pe["stages"]["sre"]
    assert sre == {"status": "SKIPPED", "summary": "Deployed (no health probe ran); incident remediation idle"}
    assert sre["summary"] == gw.SRE_IDLE_SUMMARY
    assert "verified" not in sre["summary"].lower() and "healthy" not in sre["summary"].lower()


def test_negative_failed_run_writes_no_sre_summary(gw, monkeypatch):
    pe = _post(gw, monkeypatch, FakeDB(), {"status": "FAILED"})
    assert "sre" not in (pe.get("stages") or {})


# ------------------------------------------------------------------ gateway: FinOps stage text
def _workflow_literal(stage_status):
    import yaml
    wf = open(os.path.join(REPO, "workflows", "main_orchestrator.yaml")).read()
    for doc in [yaml.safe_load(wf)]:
        stack = [doc]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                if node.get("stage_name") == "finops" and node.get("stage_status") == stage_status:
                    return node["stage_summary"]
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
    raise AssertionError(f"no finops {stage_status} literal in the workflow")


def test_finops_success_summary_is_the_typed_pricing_text(gw, monkeypatch):
    literal = _workflow_literal("SUCCESS")
    pe = _post(gw, monkeypatch, FakeDB(), {"current_stage": "FINOPS", "stage_name": "finops",
                                           "stage_status": "SUCCESS", "stage_summary": literal})
    summary = pe["stages"]["finops"]["summary"]
    assert summary == literal          # the workflow's own (now accurate) text is stored unchanged
    assert "typed compute record" in summary and "heuristic" not in summary
    assert pe["stages"]["finops"]["status"] == "SUCCESS"


def test_negative_finops_degraded_and_other_stages_keep_the_workflow_text(gw, monkeypatch):
    degraded = _workflow_literal("DEGRADED")
    pe = _post(gw, monkeypatch, FakeDB(), {"stage_name": "finops", "stage_status": "DEGRADED",
                                           "stage_summary": degraded})
    assert pe["stages"]["finops"]["summary"] == degraded
    pe = _post(gw, monkeypatch, FakeDB(), {"stage_name": "qa", "stage_status": "SUCCESS",
                                           "stage_summary": "Automated QA test suite passed"})
    assert pe["stages"]["qa"]["summary"] == "Automated QA test suite passed"


def test_negative_stage_summary_helper_never_reads_the_text(gw):
    assert gw._stage_summary("finops", "SUCCESS", "anything") == "anything"   # no override: fixed in the workflow
    assert gw._stage_summary("finops", "SUCCESS", None) is None
    assert gw._stage_summary("FINOPS", "SUCCESS", "x") == "x"     # exact typed match only
    assert gw._stage_summary("finops", "FAILED", "x") == "x"


# ------------------------------------------------------------------ Control Center dashboard (the AAR text is pinned in
# tests/test_after_action_report.py::TestAfterActionReport::test_deploy_health_wording_*)
def test_dashboard_success_debrief_does_not_claim_verified_endpoints():
    html = open(os.path.join(REPO, "apps", "control-center", "templates", "dashboard.html")).read()
    assert "Audit verified self-healing interventions, live service endpoints" not in html
    assert html.count("deployed service endpoints (not health-probed)") == 2
    assert "Active Service Endpoints:" not in html and html.count("Deployed Service Endpoints:") == 2


# ------------------------------------------------------------------ vending summary names the typed provider
def _vending_module():
    main = f.load_vending_main()
    return sys.modules[main.ProjectRepoVendingEngine.__module__], main


@pytest.mark.parametrize("repo_res,label", [
    ({"vcs_provider": "SERVERLESS_GIT"}, "Serverless Git repository"),
    ({"vcs_provider": "GITHUB"}, "GitHub repository"),
    ({"vcs_provider": "github"}, "GitHub repository"),
    ({}, "GitHub repository"),               # only the GitHub-only paths omit vcs_provider
    ({"vcs_provider": "SOMETHING_NEW"}, "repository"),
])
def test_repository_label_comes_from_the_typed_provider(repo_res, label):
    vending, _ = _vending_module()
    assert vending._vended_repository_label(repo_res) == label


@pytest.mark.parametrize("provider,label", [("SERVERLESS_GIT", "Serverless Git repository"),
                                            ("GITHUB", "GitHub repository")])
def test_vend_all_summary_names_the_provider(monkeypatch, provider, label):
    vending, main = _vending_module()
    eng = main.ProjectRepoVendingEngine(platform_project_id=f.HOST, firestore_client=f.FakeDB(),
                                        crm_service=MagicMock(), billing_service=MagicMock(),
                                        storage_client=MagicMock())
    monkeypatch.setattr(eng, "vend_gcp_project", lambda *a, **k: {"project_id": "shop-app-1a2b3c",
                                                                   "project_number": "123"})
    monkeypatch.setattr(eng, "vend_github_repo", lambda *a, **k: {"repo_name": "shop-app", "full_name": "o/shop-app",
                                                                  "vcs_provider": provider})
    # FD-4CI-b-R1: a first vend reads Settings > Default GitHub Branch (strict settings read): defaults, no Firestore.
    import importlib
    live = importlib.import_module("shared.settings")
    live.invalidate_settings_cache()
    monkeypatch.setattr(live, "get_platform_settings", lambda *a, **k: live.PlatformSettings())
    res = eng.vend_all("shop-app", "tr-1", vcs_provider=provider)
    assert res["summary"] == f"Vended GCP Project 'shop-app-1a2b3c' and {label} 'shop-app' for shop-app"
    assert "GitHub Repo '" not in res["summary"]
