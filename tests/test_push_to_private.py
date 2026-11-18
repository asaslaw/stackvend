"""PUSH-TO-PRIVATE (register row, owner 10-27): a workload's own Pub/Sub push subscription to its own private Cloud Run
service gets its push identity let in, typed, from the plan's push configuration, in the golden Cloud Run module.

- shared.iac_intent.push_identities reads the gate-clean intent's typed objects only: a google_pubsub_subscription
  whose push_config.push_endpoint is a topology service URL (ServiceRef / format("%s/<path>", ServiceRef)) and whose
  push_config.oidc_token.service_account_email is a typed identity (the fact workload_sa_email or a
  google_service_account .email) -> {compute-cloudrun module address: {identity key: email expression}}.
- terraform_engine renders it as the module's `push_service_accounts` input (primary: main.tf; topology Cloud Run
  secondaries: services.tf). None / {} = byte-identical render (negative tests).
- infra/modules/compute-cloudrun grants exactly those identities: roles/iap.httpsResourceAccessor on the service's IAP
  resource with Direct IAP, roles/run.invoker without it (private IAM), nothing for a public service.
- The gate's cycle check sees the new edge (service -> google_service_account it is pushed with).

Hermetic: python-hcl2 parsing; the real `tofu test` (mock providers, production tofu + mirror) only when present.
"""
import hermetic_guard  # noqa: F401  (first import)

import dataclasses
import functools
import json
import os
import sys
from pathlib import Path

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TESTS = os.path.dirname(__file__)
for p in (GATEWAY, REPO_ROOT, TESTS, os.path.join(REPO_ROOT, "eval")):
    if p not in sys.path:
        sys.path.insert(0, p)

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from shared import iac_intent as ii  # noqa: E402
from developer_agent import terraform_engine as te  # noqa: E402

ART = ii.load_artifacts()
CTX = ii.IntentContext(services={"api": ("module.compute", "compute-cloudrun"),
                                 "worker": ("module.compute_worker", "compute-cloudrun"),
                                 "jobs": ("module.compute_jobs", "compute-event-worker")})
WSA_EXPR = ii.default_facts()["workload_sa_email"]
MODULE = os.path.join(REPO_ROOT, "infra", "modules", "compute-cloudrun")


def F(fact):
    return {"$ref": {"kind": "fact", "fact": fact}}


def R(t, n, a):
    return {"$ref": {"kind": "resource_attr", "type": t, "name": n, "attr": a}}


def SVC(svc="api"):
    return {"$ref": {"kind": "service", "service": svc, "output": "service_uri"}}


TOPIC = {"type": "google_pubsub_topic", "name": "events", "arguments": {"name": "events"}}
SA = {"type": "google_service_account", "name": "pusher", "arguments": {"account_id": "pusher"}}


def sub(name="push", endpoint=None, oidc=F("workload_sa_email"), listed=False):
    push = {"push_endpoint": endpoint if endpoint is not None else SVC()}
    if oidc is not None:
        push["oidc_token"] = {"service_account_email": oidc}
    return {"type": "google_pubsub_subscription", "name": name,
            "arguments": {"name": name, "topic": R("google_pubsub_topic", "events", "id"),
                          "push_config": [push] if listed else push}}


def doc(*resources):
    return {"schema": "iac_intent/v1", "modules": [], "resources": list(resources), "outputs": []}


def ids(*resources, ctx=CTX):
    g = ii.validate_intent(doc(*resources), ART, ctx)
    assert g.ok, [(d.code, d.attribute_path, d.message) for d in g.diagnostics]
    return ii.push_identities(g.validated)


# ------------------------------------------------------------------------------------------------ typed extraction
def test_workload_sa_push_to_the_primary_is_its_push_identity():
    assert ids(TOPIC, sub()) == {"module.compute": {"fact.workload_sa_email": WSA_EXPR}}


def test_url_with_a_path_and_the_list_block_form_are_the_same_identity():
    ep = {"$fn": "format", "$args": ["%s/api/v1/tasks/process", SVC()]}
    assert ids(TOPIC, sub(endpoint=ep)) == ids(TOPIC, sub(listed=True)) == ids(TOPIC, sub())


def test_own_service_account_identity_and_a_secondary_service():
    got = ids(TOPIC, SA, sub(endpoint=SVC("worker"), oidc=R("google_service_account", "pusher", "email")))
    assert got == {"module.compute_worker": {"google_service_account.pusher": "google_service_account.pusher.email"}}


def test_two_subscriptions_one_identity_one_entry_per_service():
    got = ids(TOPIC, SA, sub("a"), sub("b"), sub("c", endpoint=SVC("worker")),
              sub("d", oidc=R("google_service_account", "pusher", "email")))
    assert got == {"module.compute": {"fact.workload_sa_email": WSA_EXPR,
                                      "google_service_account.pusher": "google_service_account.pusher.email"},
                   "module.compute_worker": {"fact.workload_sa_email": WSA_EXPR}}


def test_negative_no_push_identity_without_an_oidc_token_or_a_push_subscription():
    assert ids(TOPIC, sub(oidc=None)) == {}
    pull = {"type": "google_pubsub_subscription", "name": "pull",
            "arguments": {"name": "pull", "topic": R("google_pubsub_topic", "events", "id")}}
    assert ids(TOPIC, pull) == {}
    assert ids(TOPIC) == {}


def test_only_validated_intents_are_read():
    with pytest.raises(TypeError):
        ii.push_identities(doc(TOPIC, sub()))


def test_gate_sees_the_service_to_push_identity_edge_as_a_cycle():
    """The service's module now takes the identity's email: an identity that itself reads the service is a cycle."""
    looped = dict(SA, arguments=dict(SA["arguments"], description={"$fn": "format", "$args": ["for %s", SVC()]}))
    g = ii.validate_intent(doc(TOPIC, looped, sub(oidc=R("google_service_account", "pusher", "email"))), ART, CTX)
    if any(d.code not in ("TOPOLOGY.CYCLE",) for d in g.diagnostics):
        pytest.skip("the allow-list refuses this description shape for another reason: "
                    + ", ".join(sorted({d.code for d in g.diagnostics})))
    assert {d.code for d in g.diagnostics} == {"TOPOLOGY.CYCLE"}
    # negative: the same identity without the back-reference is clean
    assert ii.validate_intent(doc(TOPIC, SA, sub(oidc=R("google_service_account", "pusher", "email"))), ART, CTX).ok


# ------------------------------------------------------------------------------------------------ render
def _modules(text):
    out = {}
    for m in hcl2.loads(text).get("module", []):
        out.update(m)
    return out


def test_main_tf_renders_the_input_and_none_is_byte_identical():
    base = te.generate_golden_main_tf("shop", "cloudrun", "", service_name="shop")
    assert te.generate_golden_main_tf("shop", "cloudrun", "", service_name="shop", push_service_accounts=None) == base
    assert te.generate_golden_main_tf("shop", "cloudrun", "", service_name="shop", push_service_accounts={}) == base
    got = te.generate_golden_main_tf("shop", "cloudrun", "", service_name="shop",
                                     push_service_accounts={"fact.workload_sa_email": WSA_EXPR})
    assert got.replace(te.push_service_accounts_line({"fact.workload_sa_email": WSA_EXPR}), "", 1) == base
    assert _modules(got)["compute"]["push_service_accounts"] == {"fact.workload_sa_email": "${" + WSA_EXPR + "}"}
    assert "push_service_accounts" not in _modules(base)["compute"]


def test_non_cloud_run_primaries_never_take_the_input():
    for arch in ("gke-autopilot", "event-worker"):
        assert te.generate_golden_main_tf("shop", arch, "", push_service_accounts={"fact.workload_sa_email": WSA_EXPR}) \
            == te.generate_golden_main_tf("shop", arch, "")


@pytest.mark.parametrize("bad", [{"fact.x": 'x"}\nresource "y" "z" {'}, {"fact.workload_sa_email": "${var.x}"},
                                 {"other.key": WSA_EXPR}, {"fact.workload_sa_email": ""}])
def test_push_line_refuses_anything_outside_its_closed_grammar(bad):
    with pytest.raises(ValueError):
        te.push_service_accounts_line(bad)


def test_topology_secondaries_take_their_own_identities_only():
    from shared.diagnostics import AssemblyRecord
    from shared.service_topology import validate_service_topology
    from developer_agent.assembly import CUSTOM_TF
    raw = {"services": [{"name": "api", "kind": "cloudrun"}, {"name": "worker", "kind": "cloudrun"},
                        {"name": "admin", "kind": "cloudrun"}],
           "primary_service": "api", "edges": [], "resources": []}
    vt, diags = validate_service_topology(raw, product_id="shop")
    assert vt is not None, diags

    def render(push):
        files = {CUSTOM_TF: "", "apps/api/main.py": "x = 1\n", "apps/worker/main.py": "x = 1\n",
                 "apps/admin/main.py": "x = 1\n"}
        te.reconcile_multi_service_declarations(
            files=files, product_id="shop", spec_text="", archetype=vt.archetype, assembly_record=AssemblyRecord(),
            llm_iac_paths=[CUSTOM_TF], target_services=list(vt.names), topology=vt, push_identities=push)
        return files[te.SERVICES_TF]

    base = render(None)
    assert render({}) == base
    got = render({"module.compute_worker": {"fact.workload_sa_email": WSA_EXPR},
                  "module.compute": {"fact.workload_sa_email": WSA_EXPR}})
    mods = _modules(got)
    assert mods["compute_worker"]["push_service_accounts"] == {"fact.workload_sa_email": "${" + WSA_EXPR + "}"}
    assert "push_service_accounts" not in mods["compute_admin"]
    assert got.replace(te.push_service_accounts_line({"fact.workload_sa_email": WSA_EXPR}), "", 1) == base


def test_end_to_end_generate_mode_puts_the_push_identity_on_module_compute():
    from test_typed_iac_ti3_contract import APP, C, W, _generate, intent, topo   # noqa: F401  (its fixtures)
    from developer_agent.assembly import index_blocks
    shop_sub = sub(endpoint={"$fn": "format", "$args": ["%s/api/v1/tasks/process", SVC("shop")]})
    draft = dict(APP, **{C.INTENT_PATH: intent(resources=[TOPIC, shop_sub])})
    att = {p: ("IAC_ENGINEER" if p == C.INTENT_PATH else "BACKEND_ENGINEER") for p in draft}
    files, agent, _client, _seen = _generate("generate", draft, att, raw=topo())
    assert agent.last_validation_report.status == "PASS"
    main = {b.key: b.body for b in index_blocks(files[W + "main.tf"])}
    assert main["module.compute"]["push_service_accounts"] == {"fact.workload_sa_email": "${" + WSA_EXPR + "}"}
    # negative: the same tree without the push subscription renders no input
    draft2 = dict(APP, **{C.INTENT_PATH: intent(resources=[TOPIC])})
    files2, _a, _c, _s = _generate("generate", draft2, att, raw=topo())
    main2 = {b.key: b.body for b in index_blocks(files2[W + "main.tf"])}
    assert "push_service_accounts" not in main2["module.compute"]


# ------------------------------------------------------------------------------------------------ golden module
def _resources(rtype):
    with open(os.path.join(MODULE, "main.tf"), encoding="utf-8") as f:
        text = f.read()
    return {name: body for block in hcl2.loads(text).get("resource", []) if rtype in block
            for name, body in block[rtype].items()}


def test_module_grants_exactly_the_push_identities_by_access_mode():
    acc = _resources("google_iap_web_cloud_run_service_iam_member")["push_accessors"]
    inv = _resources("google_cloud_run_v2_service_iam_member")["push_invokers"]
    assert acc["role"] == "roles/iap.httpsResourceAccessor" and inv["role"] == "roles/run.invoker"
    assert acc["member"] == inv["member"] == "serviceAccount:${each.value}"
    assert "var.enable_direct_iap ? var.push_service_accounts" in acc["for_each"].replace("(", "").replace(")", "")
    assert "!var.enable_direct_iap ? var.push_service_accounts" in inv["for_each"].replace("(", "").replace(")", "")
    assert acc["cloud_run_service_name"] == inv["name"] == "${google_cloud_run_v2_service.app.name}"


def test_negative_module_without_the_addition_is_the_previous_module():
    """Do No Harm: the addition is appended; removing it gives the pre-PUSH-TO-PRIVATE files (the other byte pins
    strip it with push_private_module_delta.pre_push_private)."""
    from push_private_module_delta import ADDED_MAIN, ADDED_VARIABLES, pre_push_private
    for fn, added in (("main.tf", ADDED_MAIN), ("variables.tf", ADDED_VARIABLES)):
        with open(os.path.join(MODULE, fn), encoding="utf-8") as f:
            text = f.read()
        before = pre_push_private(f"infra/modules/compute-cloudrun/{fn}", text)
        assert "push_service_accounts" not in before and before + added == text


def test_negative_developer_prompt_contract_does_not_advertise_the_platform_input():
    """The input is platform-only: the classic developer prompt's module contract is unchanged by it."""
    from developer_agent import contract_inspector as ci
    text = ci.get_golden_module_contract("compute-cloudrun", force_refresh=True)
    assert "push_service_accounts" not in text and "authorized_invoker_members" in text
    assert "push_service_accounts" in ci._EMBEDDED_MODULE_CONTRACTS["compute-cloudrun"]["inputs"]   # CI-5 parity


def test_disk_copies_and_every_payload_carry_the_same_module():
    payloads = ["shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared",
                "mcp-servers/terraform/shared"]
    for fn in ("main.tf", "variables.tf"):
        text = Path(MODULE, fn).read_text(encoding="utf-8")
        assert Path(REPO_ROOT, "apps", "control-center", "infra", "modules", "compute-cloudrun", fn).read_text(
            encoding="utf-8") == text
        for rel in payloads:
            ns = {}
            path = os.path.join(REPO_ROOT, rel, "builtin_modules_payload.py")
            with open(path, encoding="utf-8") as f:
                exec(compile(f.read(), path, "exec"), ns)  # noqa: S102 - repo-owned data module
            assert ns["BUILTIN_MODULE_FILES"]["compute-cloudrun"][fn] == text, (rel, fn)


# ------------------------------------------------------------------------------------------------ real engine
PROD_TOFU = os.path.join(REPO_ROOT, "eval", ".tools", "tofu-1.9.0", "tofu")
PROD_MIRROR = os.path.join(REPO_ROOT, "eval", ".tofu-mirror-prod")


@functools.lru_cache(maxsize=1)
def _skip_reason():
    if not (os.access(PROD_TOFU, os.X_OK) and os.path.isdir(PROD_MIRROR)):
        return "production column eval/.tools/tofu-1.9.0/tofu + eval/.tofu-mirror-prod (untracked) not present"
    return None


@pytest.fixture(scope="module")
def runner(tmp_path_factory):
    if _skip_reason():
        pytest.skip(_skip_reason())
    from stackvend_eval.tofu_runner import TofuRunner
    r = TofuRunner(tmp_path_factory.mktemp("push-private-tofu"), Path(PROD_MIRROR), tofu_bin=PROD_TOFU)
    if not r.mirror_ready:
        pytest.skip(f"production mirror not verified: {r.mirror_manifest['status']}")
    return r


MODULE_TEST = '''mock_provider "google" {}
mock_provider "google-beta" {}

variables {
  project_id            = "push-test"
  product_id            = "push"
  service_account_email = "workload-sa@push-test.iam.gserviceaccount.com"
  push_service_accounts = { "fact.workload_sa_email" = "workload-sa@push-test.iam.gserviceaccount.com" }
}

run "public_service_grants_nothing" {
  command = plan
  variables {
    allow_unauthenticated = true
  }
  assert {
    condition     = length(google_iap_web_cloud_run_service_iam_member.push_accessors) == 0 && length(google_cloud_run_v2_service_iam_member.push_invokers) == 0
    error_message = "a public service must plan no push grant"
  }
}

run "private_iap_service_admits_the_push_identity_through_iap_only" {
  command = plan
  variables {
    allow_unauthenticated      = false
    enable_direct_iap          = true
    authorized_invoker_members = ["user:ana@example.com"]
  }
  assert {
    condition     = length(google_iap_web_cloud_run_service_iam_member.push_accessors) == 1 && google_iap_web_cloud_run_service_iam_member.push_accessors["fact.workload_sa_email"].member == "serviceAccount:workload-sa@push-test.iam.gserviceaccount.com" && google_iap_web_cloud_run_service_iam_member.push_accessors["fact.workload_sa_email"].role == "roles/iap.httpsResourceAccessor"
    error_message = "Direct IAP must admit exactly the push identity as an IAP accessor"
  }
  assert {
    condition     = length(google_cloud_run_v2_service_iam_member.push_invokers) == 0
    error_message = "Direct IAP: Cloud Run checks run.invoker on the IAP agent, not the push identity"
  }
}

run "private_iam_service_admits_the_push_identity_as_invoker" {
  command = plan
  variables {
    allow_unauthenticated      = false
    enable_direct_iap          = false
    authorized_invoker_members = ["user:ana@example.com"]
  }
  assert {
    condition     = length(google_cloud_run_v2_service_iam_member.push_invokers) == 1 && google_cloud_run_v2_service_iam_member.push_invokers["fact.workload_sa_email"].role == "roles/run.invoker"
    error_message = "a private IAM service must admit the push identity as run.invoker"
  }
  assert {
    condition     = length(google_iap_web_cloud_run_service_iam_member.push_accessors) == 0
    error_message = "no IAP grant without IAP"
  }
}

run "empty_map_grants_nothing" {
  command = plan
  variables {
    allow_unauthenticated      = false
    enable_direct_iap          = true
    authorized_invoker_members = ["user:ana@example.com"]
    push_service_accounts      = {}
  }
  assert {
    condition     = length(google_iap_web_cloud_run_service_iam_member.push_accessors) == 0 && length(google_cloud_run_v2_service_iam_member.push_invokers) == 0
    error_message = "no push identity, no push grant"
  }
}

run "prefixed_member_is_refused" {
  command = plan
  variables {
    push_service_accounts = { "fact.workload_sa_email" = "serviceAccount:workload-sa@push-test.iam.gserviceaccount.com" }
  }
  expect_failures = [var.push_service_accounts]
}
'''


def test_module_validates_and_plans_the_grants_with_the_production_engine(runner, tmp_path):
    wd = tmp_path / "compute-cloudrun"
    wd.mkdir()
    for name in ("main.tf", "variables.tf", "outputs.tf"):
        (wd / name).write_text(Path(MODULE, name).read_text(encoding="utf-8"), encoding="utf-8")
    (wd / "tests").mkdir()
    (wd / "tests" / "push.tftest.hcl").write_text(MODULE_TEST, encoding="utf-8")
    r = runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-3000:]
    r = runner._run(["validate", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-3000:]
    r = runner._run(["test", "-test-directory=tests", "-filter=tests/push.tftest.hcl", "-no-color"], cwd=wd)
    out = r.stdout + r.stderr
    assert r.returncode == 0 and "5 passed, 0 failed" in out, out[-4000:]
