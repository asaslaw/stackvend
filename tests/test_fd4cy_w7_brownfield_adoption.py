"""FD-4CY W7 (proposed register row FD55-W7): adopting existing Google Cloud resources from the plan.

Unit tests of mcp-servers/terraform/brownfield_adoption.py (exact import ids from planned attributes, conflict
diagnostics, refusals), the gated apply's Pass 0 hook (re-plan only after an import), the unchanged trigger of the
subnet orphan purge (case B, OQ-9b) against the pre-W7 discovery, and static guards (no guessed literal names or
region in the adoption code; the connector text scan is gone). The deploy-level cases live in
mcp-servers/terraform/test_service.py (`test_w7_*`).
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import copy
import importlib.util
import os
import re
import shutil
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TF_DIR = os.path.join(REPO, "mcp-servers", "terraform")
sys.path.insert(0, os.path.dirname(__file__))

_spec = importlib.util.spec_from_file_location("brownfield_adoption_w7_test",
                                               os.path.join(TF_DIR, "brownfield_adoption.py"))
ba = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = ba   # dataclasses resolve annotations through sys.modules
_spec.loader.exec_module(ba)

P = "child-p"
R = "us-east4"


def ch(address, rtype, actions=("create",), unknown=None, **after):
    return {"address": address, "mode": "managed", "type": rtype,
            "change": {"actions": list(actions), "after": dict(after), "after_unknown": dict(unknown or {})}}


def provider_config(project=None, region=None, extra=None):
    """`configuration.provider_config` as `tofu show -json` writes it (RT F5-1)."""
    exprs = {"project": project if project is not None else {"references": ["var.project_id"]},
             "region": region if region is not None else {"references": ["var.region"]}}
    cfg = {"google": {"name": "google", "full_name": "registry.opentofu.org/hashicorp/google", "expressions": exprs}}
    cfg.update(extra or {})
    return cfg


def plan(*changes, providers=None, variables=None):
    """A real `show -json` always has `configuration` (FD-4AW-b); the platform's provider block pins project / region
    to `var.project_id` / `var.region` (RT F5-1)."""
    return {"format_version": "1.2",
            "configuration": {"root_module": {}, "provider_config": providers if providers is not None else provider_config()},
            "variables": variables if variables is not None else {"project_id": {"value": P}, "region": {"value": R}},
            "resource_changes": list(changes)}


PLAN = plan()


# ------------------------------------------------------------------------------------------------ exact import ids
@pytest.mark.parametrize("change,expected", [
    (ch('module.svc["api"].google_cloud_run_v2_service.app', "google_cloud_run_v2_service", name="api",
        location="europe-west1", project=P),
     f"projects/{P}/locations/europe-west1/services/api"),
    (ch("google_cloud_run_service.legacy", "google_cloud_run_service", name="old", location="asia-east1"),
     f"locations/asia-east1/namespaces/{P}/services/old"),
    (ch("google_secret_manager_secret.s", "google_secret_manager_secret", secret_id="shop-key"),
     f"projects/{P}/secrets/shop-key"),
    (ch("google_service_account.sa", "google_service_account", account_id="runner"),
     f"projects/{P}/serviceAccounts/runner@{P}.iam.gserviceaccount.com"),
    (ch("google_compute_subnetwork.sn[0]", "google_compute_subnetwork", name="sn", region="us-west1"),
     f"projects/{P}/regions/us-west1/subnetworks/sn"),
    (ch("google_artifact_registry_repository.r", "google_artifact_registry_repository", repository_id="shop",
        location=R), f"projects/{P}/locations/{R}/repositories/shop"),
    (ch("module.foundation.google_firestore_database.database", "google_firestore_database", name="(default)"),
     f"projects/{P}/databases/(default)"),
    (ch("google_iam_workload_identity_pool_provider.p", "google_iam_workload_identity_pool_provider",
        workload_identity_pool_id="pool", workload_identity_pool_provider_id="gh"),
     f"projects/{P}/locations/global/workloadIdentityPools/pool/providers/gh"),
    (ch("google_identity_platform_config.c[0]", "google_identity_platform_config", project=P),
     f"projects/{P}/config"),
    (ch("google_identity_platform_default_supported_idp_config.g[0]",
        "google_identity_platform_default_supported_idp_config", idp_id="google.com"),
     f"projects/{P}/defaultSupportedIdpConfigs/google.com"),
    (ch("google_pubsub_subscription.s", "google_pubsub_subscription", name="orders-sub"),
     f"projects/{P}/subscriptions/orders-sub"),
    (ch("google_storage_bucket.b", "google_storage_bucket", name="shop-data", location="US"), "shop-data"),
    (ch("google_cloud_scheduler_job.j", "google_cloud_scheduler_job", name="nightly", region=R),
     f"projects/{P}/locations/{R}/jobs/nightly"),
    (ch("google_compute_region_network_endpoint_group.n", "google_compute_region_network_endpoint_group",
        name="neg"), f"projects/{P}/regions/{R}/networkEndpointGroups/neg"),
    (ch("google_compute_global_forwarding_rule.f", "google_compute_global_forwarding_rule", name="fr"),
     f"projects/{P}/global/forwardingRules/fr"),
    (ch("module.vpc_connector.google_vpc_access_connector.connector", "google_vpc_access_connector", name="c"),
     f"projects/{P}/locations/{R}/connectors/c"),
    (ch("google_compute_network.n", "google_compute_network", name="vpc"), f"projects/{P}/global/networks/vpc"),
    (ch("google_compute_global_address.a", "google_compute_global_address", name="ip"),
     f"projects/{P}/global/addresses/ip"),
])
def test_import_id_is_built_from_the_planned_attributes(change, expected):
    resolved, why = ba.resolve_import(change, P, R, PLAN)
    assert why == "" and resolved.import_id == expected and resolved.address == change["address"]


@pytest.mark.parametrize("change,reason", [
    (ch("google_pubsub_topic.t", "google_pubsub_topic", unknown={"name": True}), "not known until apply"),
    (ch("google_pubsub_topic.t", "google_pubsub_topic", name=""), "not a known string"),
    (ch("google_pubsub_topic.t", "google_pubsub_topic"), "not a known string"),
    (ch("google_pubsub_topic.t", "google_pubsub_topic", name="t", project="host-project"), "not the workload project"),
    (ch("google_cloud_run_v2_service.s", "google_cloud_run_v2_service", unknown={"location": True}, name="s"),
     "`location` is not known"),
    (ch("google_compute_router.r", "google_compute_router", name="r"), "no import rule"),
])
def test_nothing_is_guessed_when_the_plan_does_not_name_it(change, reason):
    resolved, why = ba.resolve_import(change, P, R, PLAN)
    assert resolved is None and reason in why


# ---------------------------------------- RT F5-1: the provider default project / region, read from the plan itself
ROOT_SECRET = ch("google_secret_manager_secret.order_key", "google_secret_manager_secret",
                 unknown={"project": True}, secret_id="order-key")   # an AI-written root block without `project`


def test_f5_1_root_resource_without_project_adopts_through_the_pinned_provider_default():
    resolved, why = ba.resolve_import(ROOT_SECRET, P, R, PLAN)
    assert why == "" and resolved.import_id == f"projects/{P}/secrets/order-key"
    absent = ch("google_pubsub_topic.events", "google_pubsub_topic", name="events")   # `project` absent from `after`
    assert ba.resolve_import(absent, P, R, PLAN)[0].import_id == f"projects/{P}/topics/events"
    const = plan(providers=provider_config(project={"constant_value": P}))
    assert ba.resolve_import(ROOT_SECRET, P, R, const)[0].import_id == f"projects/{P}/secrets/order-key"
    # A module's required_providers entry without a block of its own inherits the root's configuration.
    inherited = plan(providers=provider_config(extra={"module.compute:google-beta": {
        "name": "google-beta", "full_name": "registry.opentofu.org/hashicorp/google-beta",
        "module_address": "module.compute"}}))
    assert ba.resolve_import(ROOT_SECRET, P, R, inherited)[0].import_id == f"projects/{P}/secrets/order-key"


@pytest.mark.parametrize("bad_plan", [
    plan(providers=provider_config(extra={"google.other": {"name": "google", "alias": "other",
                                                           "expressions": {"project": {"constant_value": "host"}}}})),
    plan(variables={"project_id": {"value": "other-p"}, "region": {"value": R}}),
    plan(variables={"region": {"value": R}}),
    plan(providers=provider_config(project={"references": ["var.other_project"]})),
    plan(providers=provider_config(project={"constant_value": "host"})),
    plan(providers={"google": {"name": "google", "expressions": {"region": {"references": ["var.region"]}}}}),
    plan(providers={}),
    plan(providers=provider_config(extra={"google-beta": {"name": "google-beta"}})),   # root entry, no block
    plan(providers={"module.compute:google": {"name": "google", "module_address": "module.compute",
                                              "expressions": {"project": {"references": ["var.project_id"]}}}}),
    plan(providers=provider_config(extra={"module.net:google": {
        "name": "google", "module_address": "module.net", "expressions": {"project": {"constant_value": "host"}}}})),
    {"format_version": "1.2", "resource_changes": []},
    None,
])
def test_f5_1_unknown_project_is_refused_unless_every_google_provider_pins_the_workload_project(bad_plan):
    resolved, why = ba.resolve_import(ROOT_SECRET, P, R, bad_plan)
    assert resolved is None
    assert why == "planned `project` is not known and the provider configuration does not pin it to the workload project"


def test_f5_1_unknown_region_uses_the_pinned_provider_region_only():
    conn = ch("google_vpc_access_connector.c", "google_vpc_access_connector", unknown={"region": True, "project": True},
              name="c")
    assert ba.resolve_import(conn, P, R, PLAN)[0].import_id == f"projects/{P}/locations/{R}/connectors/c"
    other = plan(variables={"project_id": {"value": P}, "region": {"value": "europe-west1"}})
    resolved, why = ba.resolve_import(conn, P, R, other)
    assert resolved is None and "does not pin it to the workload region" in why
    # A required `location` (Cloud Run) is never filled from the provider region.
    svc = ch("google_cloud_run_v2_service.s", "google_cloud_run_v2_service", unknown={"location": True}, name="s")
    assert ba.resolve_import(svc, P, R, PLAN) == (None, "planned `location` is not known until apply")


def test_f5_1_pre_apply_and_conflicts_pass_the_plan_through():
    p = plan(ROOT_SECRET)
    assert [c.import_id for c in ba.pre_apply_candidates(p, P, R)] == [f"projects/{P}/secrets/order-key"]
    err = ("Error: Error creating Secret: googleapi: Error 409: already exists\n\n"
           "  with google_secret_manager_secret.order_key,\n")
    adoptable, unresolved = ba.plan_conflicts(err, p, P, R)
    assert [a.import_id for a in adoptable] == [f"projects/{P}/secrets/order-key"] and unresolved == []


def test_planned_creates_take_only_pure_creates_of_managed_resources():
    p = plan(ch("a.x", "google_pubsub_topic", name="a"),
             ch("b.x", "google_pubsub_topic", actions=("delete", "create"), name="b"),
             ch("c.x", "google_pubsub_topic", actions=("create", "delete"), name="c"),
             ch("d.x", "google_pubsub_topic", actions=("update",), name="d"),
             dict(ch("data.e.x", "google_pubsub_topic", name="e"), mode="data"))
    assert list(ba.planned_creates(p)) == ["a.x"]
    assert ba.planned_creates(None) == {} and ba.planned_creates({"resource_changes": "x"}) == {}


# ------------------------------------------------------------------------------------------- conflict diagnostics
FRAMED = (
    "╷\n"
    "│ Error: Error creating Secret: googleapi: Error 409: Secret [projects/1/secrets/k] already exists.\n"
    "│ \n"
    "│   with module.app.google_secret_manager_secret.k,\n"
    "│   on modules/app/main.tf line 1, in resource \"google_secret_manager_secret\" \"k\":\n"
    "│    1: resource \"google_secret_manager_secret\" \"k\" {\n"
    "╵\n"
    "╷\n"
    "│ Error: Error creating Topic: googleapi: Error 400: bad name\n"
    "│ \n"
    "│   with google_pubsub_topic.t,\n"
    "╵\n"
)
PLAIN = ("Error: Error creating Database: googleapi: Error 409: Database already exists.\n\n"
         '  with module.foundation.google_firestore_database.database["x"],\n'
         "Error: Error creating Job: rpc error: code = AlreadyExists desc = job exists\n\n"
         "  with google_cloud_scheduler_job.j,\n")


def test_conflict_addresses_read_only_conflict_diagnostics_framed_or_plain():
    assert ba.conflict_addresses(FRAMED) == (["module.app.google_secret_manager_secret.k"], 0)
    assert ba.conflict_addresses(PLAIN) == (['module.foundation.google_firestore_database.database["x"]',
                                             "google_cloud_scheduler_job.j"], 0)
    assert ba.conflict_addresses("Error: Error 409: x already exists\n") == ([], 1)
    # Negative: no conflict status, or text outside any diagnostic, adopts nothing.
    assert ba.conflict_addresses("Error: Error creating Topic: Error 403: denied\n\n  with google_pubsub_topic.t,\n") \
        == ([], 0)
    assert ba.conflict_addresses("already exists\n  with google_pubsub_topic.t,\n") == ([], 0)


def test_f5_2_a_warning_block_is_never_read_as_part_of_the_error_before_it():
    """RT F5-2 reproduction: a 403 error followed by a separate warning holding a conflict token -> nothing."""
    text = ("\u2577\n\u2502 Error: Error creating Topic: googleapi: Error 403: denied\n\u2502 \n"
            "\u2502   with google_pubsub_topic.events,\n\u2575\n"
            "\u2577\n\u2502 Warning: already exists elsewhere\n\u2502 \n\u2575\n")
    assert ba.conflict_addresses(text) == ([], 0)
    plain = ("Error: Error creating Topic: googleapi: Error 403: denied\n\n  with google_pubsub_topic.events,\n\n"
             "Warning: Error 409 seen on another resource\n\n  with google_pubsub_topic.other,\n")
    assert ba.conflict_addresses(plain) == ([], 0)
    # A warning BEFORE a real conflict error does not hide it.
    assert ba.conflict_addresses("Warning: deprecated\n\n" + PLAIN)[0][0] == \
        'module.foundation.google_firestore_database.database["x"]'


def test_plan_conflicts_adopts_only_exact_planned_creates():
    p = plan(ch("module.app.google_secret_manager_secret.k", "google_secret_manager_secret", secret_id="k"),
             ch("google_pubsub_topic.t", "google_pubsub_topic", name="t"))
    adoptable, unresolved = ba.plan_conflicts(FRAMED, p, P, R)
    assert [(a.address, a.import_id) for a in adoptable] == [("module.app.google_secret_manager_secret.k",
                                                              f"projects/{P}/secrets/k")]
    assert unresolved == []
    # The diagnostic's address must equal a plan address exactly: a root address for a module block is not one.
    root = FRAMED.replace("with module.app.google_secret_manager_secret.k,", "with google_secret_manager_secret.k,")
    adoptable, unresolved = ba.plan_conflicts(root, p, P, R)
    assert adoptable == [] and unresolved == [{"address": "google_secret_manager_secret.k",
                                               "reason": "address is not in the applied plan"}]


def test_pre_apply_candidates_are_the_old_pass0_types_only_with_exact_urls():
    p = plan(ch("module.compute.google_cloud_run_v2_service.app", "google_cloud_run_v2_service", name="shop",
                location=R),
             ch("google_service_account.sa", "google_service_account", account_id="runner"),
             ch("google_compute_subnetwork.s", "google_compute_subnetwork", name="sn", region=R),
             ch("google_secret_manager_secret.u", "google_secret_manager_secret", unknown={"secret_id": True}),
             ch("google_secret_manager_secret.upd", "google_secret_manager_secret", actions=("update",), secret_id="x"),
             ch("module.vpc_connector.google_vpc_access_connector.connector", "google_vpc_access_connector", name="c"),
             ch("google_pubsub_topic.t", "google_pubsub_topic", name="t"))
    got = [(c.address, c.exists_url) for c in ba.pre_apply_candidates(p, P, R)]
    assert got == [
        ("module.compute.google_cloud_run_v2_service.app",
         f"https://run.googleapis.com/v2/projects/{P}/locations/{R}/services/shop"),
        ("google_service_account.sa",
         f"https://iam.googleapis.com/v1/projects/{P}/serviceAccounts/runner@{P}.iam.gserviceaccount.com"),
        ("google_compute_subnetwork.s",
         f"https://compute.googleapis.com/compute/v1/projects/{P}/regions/{R}/subnetworks/sn"),
    ]
    assert ba.pre_apply_candidates(plan(), P, R) == [] and ba.pre_apply_candidates(None, P, R) == []


def test_bucket_owner_matches_on_typed_project_numbers_only():
    assert ba.bucket_owner_matches({"projectNumber": "12"}, {"projectNumber": "12"})
    assert not ba.bucket_owner_matches({"projectNumber": "12"}, {"projectNumber": "13"})
    assert not ba.bucket_owner_matches({}, {})


# ------------------------------------------------------------------------- gated apply: Pass 0 hook and plan sink
from test_lane14_compliance_gate import FakeDB, FakeRunner, tf  # noqa: E402,F401  (fixture)


def _gate_svc(tf, tmp_path, monkeypatch, plan_json, plan_ok=True):
    svc = tf.TerraformService(project_id="host", state_bucket="b", workspace_base_dir=str(tmp_path / "ws"),
                              firestore_client=FakeDB({}))
    ws = tmp_path / "work"
    ws.mkdir(exist_ok=True)
    (ws / "main.tf").write_text("# x\n")
    runner = FakeRunner(plan_json, plan_ok=plan_ok)
    monkeypatch.setattr(svc, "_run_subprocess", runner)
    monkeypatch.setattr(svc, "_compliance_gate_check", lambda *a, **k: {"passed": True})
    return svc, str(ws), runner


def test_gate_plans_again_only_after_pass0_imported(tf, tmp_path, monkeypatch):
    p = plan(ch("google_pubsub_topic.t", "google_pubsub_topic", name="t"))
    svc, ws, runner = _gate_svc(tf, tmp_path, monkeypatch, p)
    seen, sink = [], {}
    res = svc._compliance_gated_apply("shop", "t", ws, "OPENTOFU", plan_sink=sink,
                                      pre_apply_adopt=lambda pj: seen.append(pj) or 1)
    assert res["success"] is True and runner.calls == ["plan", "show", "plan", "show", "apply"]
    assert seen == [p] and sink["plan_json"] == p
    assert runner.cmds[2] == runner.cmds[0]          # the same plan command (same -var-file rule)


def test_negative_gate_without_pass0_import_is_unchanged(tf, tmp_path, monkeypatch):
    """Do No Harm: no import -> exactly plan, show, apply (as before W7); with or without the new arguments."""
    p = plan(ch("google_pubsub_topic.t", "google_pubsub_topic", name="t"))
    svc, ws, runner = _gate_svc(tf, tmp_path, monkeypatch, p)
    sink = {}
    assert svc._compliance_gated_apply("shop", "t", ws, "OPENTOFU", plan_sink=sink,
                                       pre_apply_adopt=lambda pj: 0)["success"] is True
    assert runner.calls == ["plan", "show", "apply"] and sink["plan_json"] == p
    runner.calls.clear()
    assert svc._compliance_gated_apply("shop", "t", ws, "OPENTOFU")["success"] is True
    assert runner.calls == ["plan", "show", "apply"]


def test_gate_never_runs_pass0_on_a_plan_the_content_policy_refuses(tf, tmp_path, monkeypatch):
    bad = plan(ch("google_pubsub_topic.t", "google_pubsub_topic", name="t"))
    del bad["configuration"]   # POLICY.PLAN_NOT_CHECKABLE
    svc, ws, runner = _gate_svc(tf, tmp_path, monkeypatch, bad)
    seen = []
    with pytest.raises(tf.ContentPolicyRefused):
        svc._compliance_gated_apply("shop", "t", ws, "OPENTOFU", pre_apply_adopt=lambda pj: seen.append(pj) or 1)
    assert seen == [] and runner.calls == ["plan", "show"]


def test_gate_failed_plan_leaves_no_stale_plan_in_the_sink(tf, tmp_path, monkeypatch):
    svc, ws, runner = _gate_svc(tf, tmp_path, monkeypatch, plan(), plan_ok=False)
    sink = {"plan_json": {"stale": True}}
    res = svc._compliance_gated_apply("shop", "t", ws, "OPENTOFU", plan_sink=sink)
    assert res["compliance_gate_phase"] == "plan" and sink["plan_json"] is None and "apply" not in runner.calls


# RT14-01: the subnet orphan purge (case B) and its trigger `legacy_subnet_purge_trigger` are DELETED; the guard
# that no REST delete or state rm is left lives in tests/test_rt14_tf_destructive_fake_success.py.


# ------------------------------------------------------------------------------------------------- static guards
_GUESSED = ("castor-vpc-conn", "order-signing-secret", "daily-reconciliation-job", "castor-gh-pool",
            "daily_reconciliation", "order_signing_secret")


def _impl_strings():
    tree = ast.parse(open(os.path.join(TF_DIR, "service.py"), encoding="utf-8").read())
    impl = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_deploy_workload_impl"][0]
    return [n.value for n in ast.walk(impl) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def test_no_guessed_literal_name_is_left_in_the_deploy_adoption_code():
    strings = _impl_strings()
    assert [s for s in strings if any(g in s for g in _GUESSED)] == []
    adoption_src = open(os.path.join(TF_DIR, "brownfield_adoption.py"), encoding="utf-8").read()
    assert not [g for g in _GUESSED if g in adoption_src]


def test_the_connector_text_scan_and_its_root_address_import_are_gone():
    strings = _impl_strings()
    assert not [s for s in strings if "google_vpc_access_connector" in s]
    assert not [s for s in strings if "vpcaccess.googleapis.com" in s]


def test_no_region_literal_in_the_adoption_code():
    tree = ast.parse(open(os.path.join(TF_DIR, "brownfield_adoption.py"), encoding="utf-8").read())
    region_like = re.compile(r"^(us|europe|asia|australia|northamerica|southamerica|me|africa)-[a-z]+\d$")
    consts = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert [c for c in consts if region_like.match(c) or "us-central1" in c] == []


def test_import_rules_cover_every_type_the_old_handlers_adopted():
    """No coverage regression: every type the deleted per-type handlers and the Universal 409 map imported."""
    old = {"google_artifact_registry_repository", "google_firestore_database", "google_service_account",
           "google_iam_workload_identity_pool", "google_iam_workload_identity_pool_provider",
           "google_identity_platform_config", "google_identity_platform_default_supported_idp_config",
           "google_pubsub_topic", "google_pubsub_subscription", "google_storage_bucket", "google_secret_manager_secret",
           "google_cloud_scheduler_job", "google_cloud_run_v2_service", "google_cloud_run_service",
           "google_compute_region_network_endpoint_group", "google_compute_global_forwarding_rule",
           "google_vpc_access_connector", "google_compute_network", "google_compute_subnetwork",
           "google_compute_global_address"}
    assert old <= set(ba.IMPORT_RULES)
    assert ba.PRE_APPLY_TYPES <= set(ba.IMPORT_RULES)
    assert all(ba.IMPORT_RULES[t].exists_url for t in ba.PRE_APPLY_TYPES)


def test_resolve_import_is_pure_and_needs_a_workload_project():
    change = ch("google_pubsub_topic.t", "google_pubsub_topic", name="t")
    snap = copy.deepcopy(change)
    ba.resolve_import(change, P, R)
    assert change == snap
    assert ba.resolve_import(change, "", R) == (None, "no workload project")
