"""TI5-FOUNDATION-GRANTS (owner 10-25, register row TI5-FOUNDATION-GRANTS): the IaC-intent context states the workload
service account's foundation grants as facts, read from the golden module's iam.tf with the HCL parser (python-hcl2
block index + the member template's parsed interpolation; no substring / regex), so its prose and the reserved-address
list no longer contradict each other (TI-5-R2 07-r1 diagnosis). A missing / unparseable file omits the facts with a
logged warning, never a crash. Mode off never builds the intent context, so its requests are unchanged."""
import hermetic_guard  # noqa: F401  (first import)

import logging
import os
import sys
from unittest.mock import patch

import pytest

TESTS = os.path.dirname(__file__)
if TESTS not in sys.path:
    sys.path.insert(0, TESTS)

from test_typed_iac_ti3_contract import APP, ART, UPLOADS, C, _generate, topo, vt_of  # noqa: E402

REPO_ROOT = os.path.abspath(os.path.join(TESTS, ".."))
IAM_TF = os.path.join(REPO_ROOT, "infra", "modules", "workload-foundation", "base", "iam.tf")
GRANTS = ("roles/datastore.user", "roles/logging.logWriter", "roles/pubsub.publisher", "roles/storage.objectUser")
OLD_PROSE = ("including the workload service account's Firestore, Logging, Pub/Sub publisher and Storage object "
             "grants")


def _iam():
    with open(IAM_TF) as fh:
        return fh.read()


def test_grants_are_read_from_the_golden_iam_tf_with_the_hcl_parser():
    assert C.foundation_workload_grants(_iam()) == GRANTS
    assert C.foundation_iam_tf_text() == _iam()              # the module tree on disk (payload parity: lane 8)


def test_only_grants_to_exactly_the_workload_sa_count():
    """The deployer's grants, a grant to another principal, a template with extra references and a computed role are
    not workload-SA grants (each is an exact parse result, not a name pattern)."""
    extra = _iam() + '''
resource "google_project_iam_member" "workload_like_name" {
  project = var.project_id
  role    = "roles/owner"
  member  = "serviceAccount:${google_service_account.github_deployer.email}"
}
resource "google_project_iam_member" "two_refs" {
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:${google_service_account.workload_sa.email}${var.suffix}"
}
resource "google_project_iam_member" "computed_role" {
  project = var.project_id
  role    = var.extra_role
  member  = "serviceAccount:${google_service_account.workload_sa.email}"
}
resource "google_project_iam_member" "other_name" {
  project = var.project_id
  role    = "roles/cloudtrace.agent"
  member  = "serviceAccount:${google_service_account.workload_sa.email}"
}
'''
    assert C.foundation_workload_grants(extra) == tuple(sorted(GRANTS + ("roles/cloudtrace.agent",)))


@pytest.mark.parametrize("text", [None, "", "resource \"x\" {", "variable \"a\" {}\n"])
def test_missing_unparseable_or_grantless_file_gives_no_facts(text):
    assert C.foundation_workload_grants(text) is None


def test_intent_context_states_the_grants_and_the_prose_matches_the_list():
    run = C.build_intent_run(vt_of(topo([UPLOADS])), {}, artifacts=ART)
    ctx = run.run_context
    line = next(x for x in ctx.splitlines() if x.startswith("- Project roles module.foundation already grants"))
    assert ", ".join(GRANTS) in line and "fact workload_sa_email" in line
    reserved = next(x for x in ctx.splitlines() if x.startswith("- Addresses the platform reserves"))
    assert OLD_PROSE not in reserved                         # no grant named that the address list leaves out
    assert "google_project_iam_member.workload_datastore_user" in reserved
    assert ctx.index(reserved) < ctx.index(line)


@pytest.mark.parametrize("failure", ["missing", "unparseable", "raises"])
def test_unavailable_file_omits_the_facts_with_a_warning_never_a_crash(failure, caplog):
    vt = vt_of(topo([UPLOADS]))
    with patch.object(C, "foundation_workload_grants", return_value=None):
        baseline = C.build_intent_run(vt, {}, artifacts=ART).run_context
    reader = {"missing": dict(return_value=None), "unparseable": dict(return_value="resource \"x\" {"),
              "raises": dict(side_effect=OSError("disk"))}[failure]
    with patch.object(C, "foundation_iam_tf_text", **reader), \
            caplog.at_level(logging.WARNING, logger="castor-iac-intent-contract"):
        run = C.build_intent_run(vt, {}, artifacts=ART)
    assert "Project roles module.foundation already grants" not in run.run_context
    assert OLD_PROSE in run.run_context                      # the previous line, unchanged
    assert run.run_context == baseline
    assert any("TI5-FOUNDATION-GRANTS" in r.getMessage() for r in caplog.records)


def test_payload_fallback_when_no_module_tree_is_on_disk():
    with patch("shared.builtin_modules_provider.get_platform_modules_path", return_value=None):
        assert C.foundation_workload_grants(C.foundation_iam_tf_text()) == GRANTS


def test_mode_off_never_reads_the_foundation_grants_and_keeps_the_legacy_requests():
    """DNH: with mode off the developer stage never builds the intent context (no grants read), so the architect /
    developer requests are those of before; the end-to-end mode-off contract still holds."""
    from test_typed_iac_ti3_contract import W
    draft = dict(APP, **{W + "custom.tf": 'resource "google_storage_bucket" "uploads" {\n  name = "${var.product_id}'
                                          '-u"\n  location = var.region\n  uniform_bucket_level_access = true\n}\n'})
    att = {p: ("IAC_ENGINEER" if p.endswith(".tf") else "BACKEND_ENGINEER") for p in draft}
    with patch.object(C, "foundation_iam_tf_text", side_effect=AssertionError("grants read on mode off")), \
            patch.object(C, "build_intent_run", side_effect=AssertionError("intent run built on mode off")):
        files, agent, _client, seen = _generate("off", draft, att)
    assert seen["iac_intent"] is None and "iac_intent_rule" not in seen["lead_kwargs"]
    assert C.RENDER_PATH not in files
