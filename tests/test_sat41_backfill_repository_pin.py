"""SAT-41 (FD-7L pre-switch red-team review, HIGH-1): the runner identity backfill pins the workload's repository and
step-B readiness requires the pin.

* The backfill's `ensure_repository` step (default, after the record is READY) pins exactly what vend_all pins
  ({provider, full_name, id} from workloads/{pid}.github_repo / vcs_provider / github_repository_identity) through
  RunnerIdentityProvisioner.pin_repository: an equal pin writes nothing, a different pin is refused and never
  overwritten, a workload record without a usable repository is a typed refusal.
* The status row (vending `inspect`, shown on the Control Center card) and scripts/common/runner_identity_readiness.py
  report a READY record without a pinned repository as REPOSITORY_NOT_PINNED (not ready for step B).

Do No Harm: on a Shared install nothing is read or written (the backfill refuses first); a run whose steps do not
name ensure_repository is unchanged; an already pinned equal repository is never re-signed. Hermetic fakes only.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import os
import unittest

import pytest

from test_fd7l_phase3_backfill import (  # noqa: F401  (fixtures and constants reused by name)
    PID, PINNED, PLATFORM_BUCKET, REPO_FULL_NAME, W, WORKLOAD_REPO, ri, rib)
import test_fd7l_platform_runner_identity as rdt

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def w():
    return W()


def _run(world, **kw):
    out = world.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1, **kw)
    (res,) = out["results"]
    return res


def _record_writes(world):
    return [wr for wr in world.db.writes if wr[1] == f"workload_provenance/{PID}"]


# ---------------------------------------------------------------------------------------------- the pin
def test_default_backfill_pins_the_repository_after_ready(w):
    w.platform_state(2)
    res = _run(w)
    assert res["outcome"] == "MIGRATED", res
    rec = w.record()
    assert rec["status"] == "READY" and rec["repository"] == PINNED
    assert rec["migration"]["migrated_at"]                          # the pin kept the migration block
    assert ri.verify_record(ri.provenance_doc_path(PID), rec, expected_signer=w.provisioner().broker(),
                            certs=w.deps.certs)
    assert any("repository GITHUB acme/shop-api pinned" in c["why"] for c in res["calls"])
    row = w.backfill().inspect(PID, w.prov(), w.provisioner().broker())
    assert (row["step_b"], row["repository"]) == ("READY", REPO_FULL_NAME)


def test_no_platform_state_still_pins(w):
    assert _run(w)["outcome"] in ("READY", "NOTHING_TO_MIGRATE")
    assert w.record()["repository"] == PINNED


def test_the_pin_equals_what_vend_all_pins_so_a_re_vend_writes_nothing(w):
    """vend_all's _pin_runner_repository: provider from vcs_provider, id = pinned_github_repository_id(identity)."""
    _run(w)
    before = len(_record_writes(w))
    vend_pin = {"provider": "GITHUB", "full_name": REPO_FULL_NAME,
                "id": rib.pinned_github_repository_id(WORKLOAD_REPO["github_repository_identity"], REPO_FULL_NAME)}
    w.provisioner().pin_repository(PID, vend_pin)                   # no VENDING.RUNNER_REPOSITORY_MISMATCH
    assert len(_record_writes(w)) == before


def test_a_second_run_does_not_re_sign_an_equal_pin(w):
    _run(w)
    signed_at = w.record()["signed_at"]
    before = len(_record_writes(w))
    res = _run(w, steps=["ensure_repository"])
    assert res["outcome"] == "READY" and res["error_class"] is None
    assert any("already pinned" in c["why"] for c in res["calls"])
    assert len(_record_writes(w)) == before and w.record()["signed_at"] == signed_at


def test_ensure_repository_alone_needs_no_child_rights_and_pins_a_ready_record(w):
    _run(w, steps=list(rib.ENSURE_STEPS) + ["migrate_state"])      # the backfill as it ran before SAT-41
    assert w.record()["status"] == "READY" and w.record()["repository"] is None
    crm_before = list(w.crm.calls)
    res = _run(w, steps=["ensure_repository"])
    assert res["outcome"] == "READY" and w.record()["repository"] == PINNED
    assert [c for c in w.crm.calls[len(crm_before):] if "testIamPermissions" in str(c)] == []


def test_a_different_pin_is_refused_and_never_overwritten(w):
    _run(w, steps=list(rib.ENSURE_STEPS) + ["migrate_state"])
    other = {"provider": "GITHUB", "full_name": "acme/another", "id": "7"}
    w.provisioner().pin_repository(PID, other)
    res = _run(w, steps=["ensure_repository"])
    assert res["outcome"] == "FAILED" and res["error_class"] == "BACKFILL.REPOSITORY_MISMATCH"
    assert w.record()["repository"] == other


@pytest.mark.parametrize("change,code", [
    ({"github_repo": None}, "BACKFILL.REPOSITORY_UNKNOWN"),
    ({"github_repo": "shop-api"}, "BACKFILL.REPOSITORY_UNKNOWN"),                  # not owner/name
    ({"github_repo": "acme/shop/api"}, "BACKFILL.REPOSITORY_UNKNOWN"),
    ({"vcs_provider": None}, "BACKFILL.REPOSITORY_UNKNOWN"),                       # provider never guessed
    ({"vcs_provider": "GITLAB"}, "BACKFILL.REPOSITORY_UNKNOWN"),
    ({"github_repository_identity": None}, "BACKFILL.REPOSITORY_ID_UNKNOWN"),
    ({"github_repository_identity": {"full_name": REPO_FULL_NAME, "repository_id": None}},
     "BACKFILL.REPOSITORY_ID_UNKNOWN"),
    ({"github_repository_identity": {"full_name": "acme/renamed", "repository_id": "4242"}},
     "BACKFILL.REPOSITORY_ID_UNKNOWN"),
])
def test_a_workload_record_without_a_usable_repository_is_typed_and_nothing_is_pinned(w, change, code):
    w.db.docs[f"workloads/{PID}"].update(change)
    res = _run(w)
    assert res["outcome"] == "FAILED" and res["error_class"] == code
    rec = w.record()
    assert rec["status"] == "READY" and rec["repository"] is None   # the provisioning itself is kept
    row = w.backfill().inspect(PID, w.prov(), w.provisioner().broker())
    assert row["step_b"] == "REPOSITORY_NOT_PINNED" and row["repository"] is None


def test_no_workload_record_is_typed(w):
    """(The lane 18 identity check already refuses a missing ledger record; the reader refuses on its own too.)"""
    del w.db.docs[f"workloads/{PID}"]
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.backfill()._workload_repository(PID)
    assert e.value.code == "BACKFILL.REPOSITORY_UNKNOWN"


def test_serverless_git_is_pinned_without_an_id_exactly_as_vend_all_pins_it(w):
    """vend_all (FULL_BUILD) on Serverless Git: the provider's full_name castor/<pid>, resolved with the
    serverless-git default owner, provider SERVERLESS_GIT, no id (install B's records carry no identity record)."""
    w.db.docs[f"workloads/{PID}"].update(github_repo="castor/shop-api", vcs_provider="SERVERLESS_GIT")
    del w.db.docs[f"workloads/{PID}"]["github_repository_identity"]
    _run(w)
    vend_name = rib.resolve_repo_identity(f"castor/{PID}", default_owner="serverless-git", product_id=PID)[2]
    vend_pin = {"provider": "SERVERLESS_GIT", "full_name": vend_name, "id": None}
    assert w.record()["repository"] == vend_pin
    before = len(_record_writes(w))
    w.provisioner().pin_repository(PID, vend_pin)                   # a later FULL_BUILD re-vend: equal, no write
    assert len(_record_writes(w)) == before


@pytest.mark.parametrize("provider,stored", [
    ("SERVERLESS_GIT", "serverless-git/shop-api.git"),   # an older record form (install B testplan01-e)
    ("SERVERLESS_GIT", "serverless-git/shop-api"),
    ("SERVERLESS_GIT", "castor/another-workload"),
    ("GITHUB", "acme/shop-api.git"),                      # the deploy resolves acme/shop-api: the pin would differ
])
def test_a_stored_name_vending_would_not_pin_is_refused_not_rewritten(w, provider, stored):
    w.db.docs[f"workloads/{PID}"].update(github_repo=stored, vcs_provider=provider)
    res = _run(w)
    assert res["outcome"] == "FAILED" and res["error_class"] == "BACKFILL.REPOSITORY_NAME_DIFFERS"
    assert w.record()["repository"] is None


def test_serverless_git_owner_matches_the_provider():
    src = open(os.path.join(REPO_ROOT, "apps", "project-vending", "shared", "providers",
                            "serverless_git_provider.py"), encoding="utf-8").read()
    assert f'full_name=f"{rib.SERVERLESS_GIT_OWNER}/{{clean_id}}"' in src


def test_a_record_that_is_not_ready_yet_is_skipped_not_pinned(w):
    w.platform_state(1)                                             # needs a migration: BUCKET_READY
    res = _run(w, steps=list(rib.ENSURE_STEPS) + ["ensure_repository"])
    assert w.record()["status"] == "BUCKET_READY" and w.record()["repository"] is None
    assert res["outcome"] == "BUCKET_READY" and any(c["call"].startswith("SKIP") for c in res["calls"])


def test_dry_run_lists_the_pin_and_writes_nothing(w):
    out = w.backfill().run("cc", dry_run=True)
    (res,) = out["results"]
    assert any("pin repository GITHUB acme/shop-api" in c["why"] for c in res["calls"])
    assert w.db.writes == []
    w.db.docs[f"workloads/{PID}"]["vcs_provider"] = None
    (res,) = w.backfill().run("cc", dry_run=True)["results"]
    assert any(c["call"] == f"STOP workloads/{PID}" and "BACKFILL.REPOSITORY_UNKNOWN" in c["why"]
               for c in res["calls"])
    assert w.db.writes == []


# ---------------------------------------------------------------------------------------------- Do No Harm
def test_shared_install_refuses_before_any_read_or_write():
    w = W(mode="PLATFORM")
    with pytest.raises(ri.RunnerIdentityError) as e:
        w.backfill().run("cc", dry_run=False, product_ids=[PID], max_items=1, steps=["ensure_repository"])
    assert e.value.code == "RUNNER_IDENTITY_MODE_PLATFORM"
    assert w.db.writes == [] and w.google.calls == []


def test_steps_without_ensure_repository_are_unchanged(w):
    w.platform_state(2)
    res = _run(w, steps=list(rib.ENSURE_STEPS) + ["migrate_state"])
    assert res["outcome"] == "MIGRATED" and w.record()["repository"] is None
    assert not any("repository" in c["why"] for c in res["calls"])


def test_step_list_and_defaults():
    assert rib.DEFAULT_STEPS[-1] == "ensure_repository" and "ensure_repository" in rib.STEPS
    assert rib.DEFAULT_STEPS[:-1] == rib.ENSURE_STEPS + ("migrate_state",)
    assert rib.STEP_B_REPOSITORY_NOT_PINNED == rdt.rd.REPOSITORY_NOT_PINNED


# ---------------------------------------------------------------------------------------------- readiness / card
@unittest.skipUnless(rdt.OPENSSL, "needs the openssl command line (signature verification)")
class TestReadinessRepositoryPin(unittest.TestCase):
    setUpClass = classmethod(rdt.TestReadiness.setUpClass.__func__)
    tearDownClass = classmethod(rdt.TestReadiness.tearDownClass.__func__)
    _dir, _run, _state = rdt.TestReadiness._dir, rdt.TestReadiness._run, rdt.TestReadiness._state

    def test_ready_without_a_pinned_repository_is_not_ready_for_step_b(self):
        recs = {"p-norepo": rdt._record(pid="p-norepo"), "p-emptyrepo": rdt._record(pid="p-emptyrepo"),
                "p-ok": rdt._record(pid="p-ok")}
        recs["p-norepo"]["repository"] = None
        recs["p-emptyrepo"]["repository"] = {"provider": "GITHUB", "full_name": "", "id": None}
        signed = {pid: rdt._signed(self.keys, rec) for pid, rec in recs.items()}
        ledger = rdt._ledger(**{pid: {"status": "DEPLOYED", "project_id": "child-proj-1"} for pid in recs})
        prov = rdt._prov(**{pid: {"project_id": "child-proj-1", "runner_identity": rec} for pid, rec in signed.items()})
        rep = self._run(ledger, prov)
        self.assertEqual(self._state(rep, "p-norepo"), "REPOSITORY_NOT_PINNED")
        self.assertEqual(self._state(rep, "p-emptyrepo"), "REPOSITORY_NOT_PINNED")
        self.assertEqual(self._state(rep, "p-ok"), "READY")
        self.assertEqual((rep["ready"], rep["not_ready"]), (1, 2))
        self.assertIn("NOT READY", rdt.rd.render_text(rep))


def test_apply_sh_step_b_message_names_the_repository_pin():
    # SAT-46: apply.sh's step-B hook lives in scripts/common/runner_switch_gate.sh (sourced by apply.sh and bootstrap.sh)
    src = open(os.path.join(REPO_ROOT, "scripts", "common", "runner_switch_gate.sh"), encoding="utf-8").read()
    assert "no pinned repository (REPOSITORY_NOT_PINNED)" in src


def test_control_center_card_shows_the_step_b_state_per_workload():
    html = open(os.path.join(REPO_ROOT, "apps", "control-center", "templates", "dashboard.html"),
                encoding="utf-8").read()
    assert "data-runner-identity-step-b" in html and "r.step_b !== 'READY'" in html
