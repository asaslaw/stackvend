"""FD-55 W2 (register FD55-W2 = TI-4a/b, owner 10-24): the platform's own renders and the user's files (human.tf,
human_override.tf, Terraform override files) never go through the generation-time IaC text fixers, on any run; a
typed-intent run (TI-3) runs none of the generation-time IaC fixers. Hermetic; Do No Harm negative tests.
FD-55 W4 then deleted the fixers W2 partitioned (HB-17 / HB-19 / HA-06 / HB-06 / HD-15 + self_correct_hcl, HB-23), so
the W2 hold-and-restore helpers went with them; these end-to-end tests stay as the regression guard."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OG_DIR = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TESTS = os.path.dirname(__file__)
for p in (REPO_ROOT, OG_DIR, TESTS):
    if p not in sys.path:
        sys.path.insert(0, p)

W = "infra/workload/"
# Content the old naming fixer (HB-17 step 2) and the service-account-id cure (HB-23) rewrote: a `${var.x}-suffix`
# name became `${coalesce(var.x, "<guess>")}-suffix`, and an account_id longer than 30 characters was truncated.
HUMAN_TF = '''# operator-edited
resource "google_pubsub_topic" "dlq" {
  name = "${var.topic_name}-dead-letter"
}

variable "topic_name" {
  type    = string
  default = "orders"
}

resource "google_service_account" "ops" {
  account_id   = "operator-owned-service-account-x1"
  display_name = "ops"
}
'''
HUMAN_OVERRIDE_TF = '''module "compute" {
  min_instance_count = 2
}

resource "google_pubsub_topic" "dlq" {
  name   = "${var.topic_name}-dead-letter"
}
'''


# ------------------------------------------------------------------------------------------------ mode "off" run
@pytest.fixture
def agent():
    from _lane19_fake_genai import FakeGenaiClient, canned_workload_files
    from developer_agent.handler import DeveloperAgent
    with patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false", "PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "",
                                 "GCP_PROJECT": ""}), \
            patch("google.genai.Client", MagicMock()), \
            patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))):
        a = DeveloperAgent()
        a.genai_client = FakeGenaiClient(files=canned_workload_files("testapp"))
        yield a


def test_dnh_operator_edited_human_files_are_byte_identical_through_generation(agent):
    """DNH (FD55-W2): an operator-edited human.tf / human_override.tf that the old naming and account-id fixers
    rewrote reach the tree unchanged on a mode "off" run; the platform's renders are its own output."""
    existing = {W + "human.tf": HUMAN_TF, W + "human_override.tf": HUMAN_OVERRIDE_TF}
    with patch.object(agent, "fetch_existing_repo_files", return_value=dict(existing)):
        files = agent.generate_code_files(product_id="testapp", spec_text="Add a feature", task_dag=[],
                                          allow_unauthenticated=True, enable_direct_iap=False,
                                          domain_restricted_sharing=False)
    assert files[W + "human.tf"] == HUMAN_TF
    assert files[W + "human_override.tf"] == HUMAN_OVERRIDE_TF


# ------------------------------------------------------------------------------------------------ verifier
def test_verifier_cures_never_edit_platform_renders_or_user_files():
    from gatekeeper_agent.verifier import SynthesisVerifierAgent
    long_sa = 'resource "google_service_account" "a" {\n  account_id = "operator-owned-service-account-x1"\n}\n'
    tree = {W + "human.tf": long_sa, W + "human_override.tf": long_sa, W + "main.tf": long_sa,
            W + "services.tf": long_sa, W + "x_override.tf": long_sa}
    cured, _, _ = SynthesisVerifierAgent(product_id="testapp").verify_and_cure(dict(tree), product_id="testapp")
    for p, t in tree.items():
        assert cured[p] == t, p


def test_verifier_typed_iac_runs_no_iac_text_cure():
    from gatekeeper_agent.verifier import SynthesisVerifierAgent
    v = SynthesisVerifierAgent(product_id="testapp")
    boom = MagicMock(side_effect=AssertionError("IaC text cure called on a typed-intent run"))
    with patch.object(v, "reconcile_iac_environment_contracts", boom):
        tree = {W + "custom.tf": 'resource "google_pubsub_topic" "t" {\n  name = "t"\n}\n', W + "main.tf": "\n"}
        cured, _, _ = v.verify_and_cure(dict(tree), product_id="testapp", typed_iac=True)
    assert cured[W + "custom.tf"] == tree[W + "custom.tf"]
    boom.assert_not_called()


def test_hb01_reference_graph_is_deleted_on_every_run():
    """FD-55 W5 (register FD55-W5): HB-01 is deleted, so neither a typed-intent run (W2 skipped it) nor a mode-off run
    re-points anything; `typed_iac` stays in the signature and changes nothing."""
    from developer_agent import terraform_engine as te
    assert not hasattr(te, "reconcile_iac_reference_graph")
    files = {W + "custom.tf": 'resource "google_pubsub_topic" "t" {\n  name = "t"\n}\n'}
    for typed in (True, False):
        got = dict(files)
        te.reconcile_multi_service_declarations(files=got, product_id="testapp", spec_text="",
                                                target_services=["testapp"], typed_iac=typed)
        assert got == files


# ------------------------------------------------------------------------------------------------ typed-intent run
def test_typed_intent_run_calls_no_generation_time_iac_fixer_and_keeps_human_tf():
    """FD55-W2 (TI-4a) probe: a sticky typed-intent run (TI-3) reaches no generation-time IaC fixer, and an
    operator-edited human.tf is byte-identical in the tree."""
    from test_typed_iac_ti3_contract import APP, BUCKET_MODULE, UPLOADS, intent, topo, vt_of
    from test_typed_iac_ti3_rt_fixes import _committed, _generate_existing
    from developer_agent import terraform_engine as te
    from gatekeeper_agent import verifier as gv
    existing = dict(_committed(vt_of(topo([UPLOADS])), intent([BUCKET_MODULE])), **{W + "human.tf": HUMAN_TF})
    boom = MagicMock(side_effect=AssertionError("generation-time IaC fixer called on a typed-intent run"))
    # FD-55 W5: HB-01 is deleted (nothing to probe); HB-05 is the remaining generation-time IaC cure
    assert not hasattr(te, "reconcile_iac_reference_graph")
    with patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no Firestore in tests"))), \
            patch.object(gv.SynthesisVerifierAgent, "reconcile_iac_environment_contracts", boom):
        files, agent, seen = _generate_existing("off", dict(APP), {p: "BACKEND_ENGINEER" for p in APP}, existing)
    assert seen["iac_intent"] is not None   # the sticky intent path ran
    boom.assert_not_called()
    assert files[W + "human.tf"] == HUMAN_TF
