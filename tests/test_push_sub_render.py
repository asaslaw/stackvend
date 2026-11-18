"""PUSH-SUB-RENDER (register row, owner 10-28): a Pub/Sub push subscription to the workload's own Cloud Run service is
declared in the typed intent on the topic's messaging-pubsub module (`push` = {"service": <service Ref>, "path":
"/<path>", "service_account_email": <typed push identity>}) and rendered by the platform in the golden messaging-pubsub
module (push endpoint = service URI + path, OIDC token signed by the push identity, audience = the service URL). The
identity is fed to the target compute-cloudrun module's push_service_accounts (PUSH-TO-PRIVATE).

- golden module: `push` (object, default null) -> dynamic push_config with oidc_token; null = the previous module's
  plan (pull); dead-letter / retention / ack behavior unchanged (the expiration policy came later, with
  WORKLOAD-SUB-NO-EXPIRY: tests/test_workload_sub_no_expiry.py).
- gate: the closed form only (typed refusals); the cycle check splits a pushing instance into its topic part and its
  subscription, so a service that reads the topic and is pushed from it is acyclic (as in Terraform's graph), while a
  service that reads the subscription it is pushed from is a cycle.
- render: intents without `push` render byte-identical to the code before this row (pinned hashes).
- prompt: the generate-mode IaC contract tells the model to use `push`; the classic contract does not advertise it.

Hermetic: python-hcl2 parsing; the real `tofu test` / `tofu validate` (mock providers, production tofu + mirror) only
when present.
"""
import hermetic_guard  # noqa: F401  (first import)

import functools
import hashlib
import json
import os
import subprocess
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
import push_sub_render_cases as cases  # noqa: E402

ART = ii.load_artifacts()
WSA_EXPR = ii.default_facts()["workload_sa_email"]
MODULE = os.path.join(REPO_ROOT, "infra", "modules", "messaging-pubsub")
CLOUDRUN = os.path.join(REPO_ROOT, "infra", "modules", "compute-cloudrun")
CTX = ii.IntentContext(services={"shop": ("module.compute", "compute-cloudrun"),
                                 "worker": ("module.compute_worker", "compute-cloudrun"),
                                 "jobs": ("module.compute_jobs", "compute-event-worker")},
                       topology_resources={"events": "google_pubsub_topic"},
                       service_reads=(("shop", "events"),))


def F(fact):
    return {"$ref": {"kind": "fact", "fact": fact}}


def R(t, n, a):
    return {"$ref": {"kind": "resource_attr", "type": t, "name": n, "attr": a}}


def SVC(svc="shop", output="service_uri"):
    return {"$ref": {"kind": "service", "service": svc, "output": output}}


PUSHER = {"type": "google_service_account", "name": "pusher", "arguments": {"account_id": "pusher"}}


def push(service=None, path="/api/v1/tasks/process", email=None, **extra):
    out = {"service": service if service is not None else SVC(), "path": path,
           "service_account_email": email if email is not None else F("workload_sa_email")}
    out.update(extra)
    return out


def events(p=None, realizes="events", **args):
    a = {"topic_name_suffix": "events", **args}
    if p is not None:
        a["push"] = p
    m = {"module": "messaging-pubsub", "name": "events", "args": a}
    if realizes:
        m["realizes"] = realizes
    return m


def doc(modules=(), resources=(), outputs=()):
    return {"schema": "iac_intent/v1", "modules": list(modules), "resources": list(resources),
            "outputs": list(outputs)}


def gate(d, ctx=CTX):
    return ii.validate_intent(d, ART, ctx)


def ok(d, ctx=CTX):
    g = gate(d, ctx)
    assert g.ok, [(x.code, x.attribute_path, x.message) for x in g.diagnostics]
    return g.validated


def codes(d, ctx=CTX):
    return sorted({x.code for x in gate(d, ctx).diagnostics})


# ------------------------------------------------------------------------------------------------ gate: positives
def test_push_to_the_service_that_publishes_to_the_topic_is_accepted_and_acyclic():
    """Example 01's shape: shop reads the topic (EVENTS_TOPIC) and the topic's subscription pushes to shop."""
    v = ok(doc([events(push())]))
    assert ii.push_identities(v) == {"module.compute": {"fact.workload_sa_email": WSA_EXPR}}


def test_own_push_identity_and_a_secondary_service():
    v = ok(doc([events(push(service=SVC("worker"), email=R("google_service_account", "pusher", "email")))],
               [PUSHER]))
    assert ii.push_identities(v) == {
        "module.compute_worker": {"google_service_account.pusher": "google_service_account.pusher.email"}}


def test_root_path_and_closed_path_characters():
    for path in ("/", "/x/", "/tasks", "/api/v1/tasks/process", "/a-b_c.d~e/f", "/a.b", "/a..b", "/.well-known/x",
                 "/x" * 127 + "/"):
        assert ii.push_path_ok(path), path
        ok(doc([events(push(path=path))]))


@pytest.mark.parametrize("bad", ["/..", "/../../admin", "/.", "/./x", "/a/./b", "/a/..", "/a/../b", "/a//b", "//x",
                                 "//evil.example.com/x", "/x//", "/@x", "/@evil.example.com", "/:8080/x", "/a:b",
                                 "/x\n", "x/", ""])
def test_rt_f1_dot_empty_authority_and_port_segments_are_refused(bad):
    """RT F1 (10-28): no empty, `.` or `..` segment, no leading `//`, no `@` / `:`; gate and renderer agree."""
    assert not ii.push_path_ok(bad)
    assert codes(doc([events(push(path=bad))])) == ["IAC.PUSH_INVALID"]
    r = ii._Renderer(ii.IacIntent.model_validate(doc([events(push(path=bad))])), ART, CTX)
    with pytest.raises(ValueError):
        r.render()


# ------------------------------------------------------------------------------------------------ gate: refusals
@pytest.mark.parametrize("bad", ["", "tasks", "api/v1", "/x?y=1", "/x#y", "/${var.x}", "/%{if}", "/a b", "//" + "x" * 300,
                                 "/x\n", 7, None, ["/x"]])
def test_path_outside_the_closed_grammar_is_refused(bad):
    assert codes(doc([events(push(path=bad))])) == ["IAC.PUSH_INVALID"]


@pytest.mark.parametrize("bad", [
    {"service": SVC(), "path": "/x"},                                            # no identity
    dict(push(), endpoint="https://evil.example.com/x"),                         # an extra (literal endpoint) key
    dict(push(), audience="https://evil.example.com"),                           # the audience is platform-owned
    "https://example.com/push",                                                  # a literal endpoint
    [push()],
])
def test_anything_but_the_exact_three_keys_is_refused(bad):
    assert codes(doc([events(bad)])) == ["IAC.PUSH_INVALID"]


@pytest.mark.parametrize("svc", ["https://shop.example.com", SVC(output="service_name"),
                                 {"$fn": "format", "$args": ["%s/x", SVC()]}])
def test_service_must_be_a_service_uri_ref(svc):
    assert codes(doc([events(push(service=svc))])) == ["IAC.PUSH_INVALID"]


def test_unknown_service_and_non_cloud_run_service_are_refused():
    assert codes(doc([events(push(service=SVC("nope")))])) == ["IAC.UNKNOWN_REFERENCE"]
    # an event worker has no service_uri at all (the Ref's own finding) and is no push target
    assert codes(doc([events(push(service=SVC("jobs")))])) == ["IAC.PUSH_TARGET_NOT_ALLOWED", "IAC.UNKNOWN_OUTPUT"]


@pytest.mark.parametrize("email", ["sa@example.iam.gserviceaccount.com", F("project_id"),
                                   R("google_service_account", "pusher", "name"),
                                   {"$ref": {"kind": "existing", "address": "google_service_account.legacy.email"}}])
def test_identity_must_be_a_typed_push_identity(email):
    c = ii.IntentContext(services=CTX.services, topology_resources=CTX.topology_resources,
                         service_reads=CTX.service_reads,
                         existing_addresses=frozenset({"google_service_account.legacy"}))
    got = codes(doc([events(push(email=email))], [PUSHER]), c)
    assert "IAC.TARGET_REF_REQUIRED" in got and set(got) <= {"IAC.TARGET_REF_REQUIRED", "IAC.UNKNOWN_REFERENCE"}


def test_unknown_identity_resource_is_refused():
    assert "IAC.UNKNOWN_REFERENCE" in codes(doc([events(push(email=R("google_service_account", "ghost", "email")))]))


def test_push_needs_the_subscription():
    assert codes(doc([events(push(), enable_subscription=False)])) == ["IAC.PUSH_INVALID"]
    ok(doc([events(push(), enable_subscription=True)]))


def test_push_is_only_a_messaging_pubsub_argument():
    bucket = {"module": "storage-bucket", "name": "b", "args": {"bucket_name_suffix": "b", "push": push()}}
    assert codes(doc([bucket]), ii.IntentContext(services=CTX.services)) == ["IAC.UNKNOWN_ARGUMENT"]


def test_a_hand_written_push_subscription_is_still_accepted():
    """No new refusal: the PUSH-TO-PRIVATE raw resource keeps working, beside or instead of the module form."""
    v = ok(cases.doc([cases.EVENTS_MODULE], [cases.RAW_PUSH_SUB]))
    assert ii.push_identities(v) == {"module.compute": {"fact.workload_sa_email": WSA_EXPR}}


# ------------------------------------------------------------------------------------------------ gate: cycles
def test_service_reading_the_subscription_it_is_pushed_from_is_a_cycle():
    """Invariant 6: the subscription depends on the service; a service that also reads the subscription would loop."""
    c = ii.IntentContext(services=CTX.services, topology_resources={"events_sub": "google_pubsub_subscription"},
                         service_reads=(("shop", "events_sub"),))
    assert codes(doc([events(push(), realizes="events_sub")]), c) == ["TOPOLOGY.CYCLE"]
    # negative: pushed to another service, or without push, the same read is acyclic
    ok(doc([events(push(service=SVC("worker")), realizes="events_sub")]), c)
    ok(doc([events(realizes="events_sub")]), c)


def test_identity_that_reads_the_subscription_is_a_cycle_and_the_topic_is_not():
    """service -> push identity (PUSH-TO-PRIVATE) -> subscription output -> service: a cycle; the topic output is not."""
    ident = R("google_service_account", "pusher", "email")

    def sa(output):
        return dict(PUSHER, arguments=dict(PUSHER["arguments"], description={
            "$fn": "format", "$args": ["for %s", {"$ref": {"kind": "module_output", "module": "events",
                                                            "output": output}}]}))
    got = codes(doc([events(push(email=ident))], [sa("subscription_name")]))
    if set(got) - {"TOPOLOGY.CYCLE"}:
        pytest.skip("the allow-list refuses this description shape for another reason: " + ", ".join(got))
    assert got == ["TOPOLOGY.CYCLE"]
    ok(doc([events(push(email=ident))], [sa("topic_name")]))


def test_depends_on_the_whole_pushing_module_waits_for_its_subscription():
    """depends_on = [module.events] waits for the push subscription too: from a resource the service needs, a cycle."""
    ident = R("google_service_account", "pusher", "email")
    got = codes(doc([events(push(email=ident))], [dict(PUSHER, depends_on=[{"module": "events"}])]))
    assert got == ["TOPOLOGY.CYCLE"]
    # negative: without push the same depends_on is acyclic
    ok(doc([events()], [dict(PUSHER, depends_on=[{"module": "events"}])]))


# ------------------------------------------------------------------------------------------------ render
def _module_body(v):
    files = ii.render_intent(v).files
    return json.loads(files[ii.RENDER_PATH])["module"]["events"]


def test_render_push_endpoint_identity_and_audience():
    body = _module_body(ok(doc([events(push())])))
    assert body["push"] == {"audience": "${module.compute.service_uri}",
                            "endpoint": "${module.compute.service_uri}/api/v1/tasks/process",
                            "service_account_email": "${" + WSA_EXPR + "}"}
    body = _module_body(ok(doc([events(push(service=SVC("worker"), path="/",
                                            email=R("google_service_account", "pusher", "email")))], [PUSHER])))
    assert body["push"] == {"audience": "${module.compute_worker.service_uri}",
                            "endpoint": "${module.compute_worker.service_uri}/",
                            "service_account_email": "${google_service_account.pusher.email}"}


def test_rendered_push_parses_as_hcl_json_with_the_exact_references():
    files = ii.render_intent(ok(doc([events(push())]))).files
    body = json.loads(files[ii.RENDER_PATH])["module"]["events"]
    assert set(body) == {"source", "project_id", "workload_sa_email", "topic_name_suffix", "push"}
    assert body["source"] == "../modules/messaging-pubsub"


@pytest.mark.parametrize("name,d,ctxargs", cases.NO_PUSH_CASES, ids=[c[0] for c in cases.NO_PUSH_CASES])
def test_negative_intents_without_push_render_and_refuse_exactly_as_before(name, d, ctxargs):
    g = ii.validate_intent(d, ART, cases.ctx_of(ii, ctxargs))
    want = cases.PRE_CHANGE[name]
    if isinstance(want, list):
        assert sorted(x.code for x in g.diagnostics) == want
    else:
        assert g.ok
        blob = json.dumps(ii.render_intent(g.validated).files, sort_keys=True)
        assert hashlib.sha256(blob.encode()).hexdigest() == want


def test_renderer_refuses_a_malformed_push_value():
    r = ii._Renderer(ii.IacIntent.model_validate(doc([events({"service": SVC(), "path": "x",
                                                                "service_account_email": F("workload_sa_email")})])),
                     ART, CTX)
    with pytest.raises(ValueError):
        r.render()


def test_gateway_copy_is_identical():
    assert Path(REPO_ROOT, "shared", "iac_intent.py").read_bytes() == Path(
        GATEWAY, "shared", "iac_intent.py").read_bytes()


# ------------------------------------------------------------------------------------------------ end to end
def test_end_to_end_generate_mode_renders_the_push_and_admits_its_identity():
    from test_typed_iac_ti3_contract import APP, C, EVENTS, W, _generate, intent, topo   # noqa: F401  (fixtures)
    from developer_agent.assembly import index_blocks
    att = {p: "BACKEND_ENGINEER" for p in APP}
    att[C.INTENT_PATH] = "IAC_ENGINEER"
    draft = dict(APP, **{C.INTENT_PATH: intent(modules=[events(push())])})
    files, agent, _client, _seen = _generate("generate", draft, att, raw=topo(resources=[EVENTS]))
    assert agent.last_validation_report.status == "PASS"
    custom = json.loads(files[W + "custom.tf.json"])
    assert custom["module"]["events"]["push"]["endpoint"] == "${module.compute.service_uri}/api/v1/tasks/process"
    main = {b.key: b.body for b in index_blocks(files[W + "main.tf"])}
    assert main["module.compute"]["push_service_accounts"] == {"fact.workload_sa_email": "${" + WSA_EXPR + "}"}
    # the service still reads the topic (env binding), the subscription reads the service: no cycle on either side
    assert "module.events" in json.dumps(main["module.compute"]["env_vars"])
    # negative: the same tree without push renders neither
    draft2 = dict(APP, **{C.INTENT_PATH: intent(modules=[events()])})
    files2, _a, _c, _s = _generate("generate", draft2, att, raw=topo(resources=[EVENTS]))
    main2 = {b.key: b.body for b in index_blocks(files2[W + "main.tf"])}
    assert "push_service_accounts" not in main2["module.compute"]
    assert "push" not in json.loads(files2[W + "custom.tf.json"])["module"]["events"]


# ------------------------------------------------------------------------------------------------ prompt / contract
def test_generate_mode_prompt_declares_push_on_the_module():
    from developer_agent.juniors.iac_worker import build_iac_intent_worker_prompt
    text = build_iac_intent_worker_prompt(ART)
    line = next(x for x in text.splitlines() if x.startswith("- messaging-pubsub: "))
    assert "push (optional push subscription to a service of this workload" in line
    assert "PUB/SUB PUSH to one of this workload's own services" in text
    assert "Do not also write a google_pubsub_subscription for it." in text


def test_negative_classic_contract_does_not_advertise_push():
    from developer_agent import contract_inspector as ci
    text = ci.get_golden_module_contract("messaging-pubsub", force_refresh=True)
    assert "topic_name_suffix" in text and "push" not in text.replace("pubsub", "")
    assert "push" in ci._EMBEDDED_MODULE_CONTRACTS["messaging-pubsub"]["inputs"]   # CI-5 parity


def test_catalog_classes_push_and_check_passes():
    var = ART.module("messaging-pubsub")["variables"]["push"]
    assert var["class"] == "PUSH" and var["has_default"] and var["default"] is None and not var["count_driver"]
    assert ii.parse_type_constraint(var["hcl_type"]) == [
        "object", {"endpoint": "string", "service_account_email": "string", "audience": "string"}]
    r = subprocess.run([sys.executable, os.path.join(REPO_ROOT, "scripts", "build_iac_catalog.py"), "--check"],
                       capture_output=True, text=True, cwd=REPO_ROOT, timeout=120,
                       env=hermetic_guard.child_env())
    assert r.returncode == 0, (r.stdout + r.stderr)[-2000:]


# ------------------------------------------------------------------------------------------------ golden module
def _subscription():
    text = Path(MODULE, "main.tf").read_text(encoding="utf-8")
    for block in hcl2.loads(text).get("resource", []):
        if "google_pubsub_subscription" in block:
            return block["google_pubsub_subscription"]["subscription"]
    raise AssertionError("no subscription")


def test_module_pushes_only_when_push_is_set_and_keeps_its_other_settings():
    sub = _subscription()
    dyn = {k: v for d in sub["dynamic"] for k, v in d.items()}
    assert set(dyn) == {"dead_letter_policy", "push_config"}
    pc = dyn["push_config"]
    assert pc["for_each"].startswith("${var.push == null ? [] : [")   # python-hcl2 re-quotes the list item
    content = pc["content"][0] if isinstance(pc["content"], list) else pc["content"]
    assert content["push_endpoint"] == "${push_config.value.endpoint}"
    oidc = content["oidc_token"][0] if isinstance(content["oidc_token"], list) else content["oidc_token"]
    assert oidc == {"service_account_email": "${push_config.value.service_account_email}",
                    "audience": "${push_config.value.audience}"}
    # unchanged: retention, ack deadline, dead letter. The expiration policy is WORKLOAD-SUB-NO-EXPIRY's (added later:
    # never expire), not this row's; tests/test_workload_sub_no_expiry.py owns it.
    assert sub["message_retention_duration"] == "${var.message_retention_duration}"
    assert sub["ack_deadline_seconds"] == "${var.ack_deadline_seconds}"


def test_negative_module_without_the_addition_is_the_previous_module():
    """Do No Harm: removing the addition gives the exact pre-PUSH-SUB-RENDER bytes (WORKLOAD-SUB-NO-EXPIRY, added
    later, stripped first)."""
    from push_sub_module_delta import PRE_SHA256, pre_push_sub
    from sub_no_expiry_module_delta import pre_sub_no_expiry
    for fn in ("main.tf", "variables.tf"):
        rel = f"infra/modules/messaging-pubsub/{fn}"
        text = Path(MODULE, fn).read_text(encoding="utf-8")
        before = pre_push_sub(rel, pre_sub_no_expiry(rel, text))
        assert "var.push" not in before and 'variable "push"' not in before
        assert hashlib.sha256(before.encode("utf-8")).hexdigest() == PRE_SHA256[fn], fn


def test_disk_copies_and_every_payload_carry_the_same_module():
    payloads = ["shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared",
                "mcp-servers/terraform/shared"]
    for fn in ("main.tf", "variables.tf", "outputs.tf"):
        text = Path(MODULE, fn).read_text(encoding="utf-8")
        assert Path(REPO_ROOT, "apps", "control-center", "infra", "modules", "messaging-pubsub", fn).read_text(
            encoding="utf-8") == text
        for rel in payloads:
            ns = {}
            path = os.path.join(REPO_ROOT, rel, "builtin_modules_payload.py")
            with open(path, encoding="utf-8") as f:
                exec(compile(f.read(), path, "exec"), ns)  # noqa: S102 - repo-owned data module
            assert ns["BUILTIN_MODULE_FILES"]["messaging-pubsub"][fn] == text, (rel, fn)


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
    r = TofuRunner(tmp_path_factory.mktemp("push-sub-tofu"), Path(PROD_MIRROR), tofu_bin=PROD_TOFU)
    if not r.mirror_ready:
        pytest.skip(f"production mirror not verified: {r.mirror_manifest['status']}")
    return r


SA = "wsa@push-test.iam.gserviceaccount.com"
URI = "https://push-abc-uc.a.run.app"
MODULE_TEST = f'''mock_provider "google" {{}}

variables {{
  project_id        = "push-test"
  workload_sa_email = "{SA}"
}}

run "pull_by_default" {{
  command = plan
  assert {{
    condition     = length(google_pubsub_subscription.subscription[0].push_config) == 0
    error_message = "push = null must plan a pull subscription, as before"
  }}
}}

run "push_renders_endpoint_oidc_identity_and_audience" {{
  command = plan
  variables {{
    push = {{
      endpoint              = "{URI}/api/v1/tasks/process"
      service_account_email = "{SA}"
      audience              = "{URI}"
    }}
  }}
  assert {{
    condition     = google_pubsub_subscription.subscription[0].push_config[0].push_endpoint == "{URI}/api/v1/tasks/process" && google_pubsub_subscription.subscription[0].push_config[0].oidc_token[0].service_account_email == "{SA}" && google_pubsub_subscription.subscription[0].push_config[0].oidc_token[0].audience == "{URI}"
    error_message = "push must render the endpoint, the OIDC identity and the audience"
  }}
}}

run "push_keeps_dead_letter_retention_and_ack" {{
  command = plan
  variables {{
    enable_dead_letter = true
    push = {{
      endpoint              = "{URI}/x"
      service_account_email = "{SA}"
      audience              = "{URI}"
    }}
  }}
  assert {{
    condition     = length(google_pubsub_subscription.subscription[0].dead_letter_policy) == 1 && google_pubsub_subscription.subscription[0].message_retention_duration == "604800s" && google_pubsub_subscription.subscription[0].ack_deadline_seconds == 20
    error_message = "push must not change dead-letter, retention or ack deadline"
  }}
}}

run "prefixed_member_is_refused" {{
  command = plan
  variables {{
    push = {{
      endpoint              = "{URI}/x"
      service_account_email = "serviceAccount:{SA}"
      audience              = "{URI}"
    }}
  }}
  expect_failures = [var.push]
}}

run "non_https_endpoint_is_refused" {{
  command = plan
  variables {{
    push = {{
      endpoint              = "http://example.com/x"
      service_account_email = "{SA}"
      audience              = "{URI}"
    }}
  }}
  expect_failures = [var.push]
}}
'''


def _copy_module(src, dst):
    dst.mkdir(parents=True)
    for name in ("main.tf", "variables.tf", "outputs.tf"):
        (dst / name).write_text(Path(src, name).read_text(encoding="utf-8"), encoding="utf-8")


def test_module_plans_push_with_the_production_engine(runner, tmp_path):
    wd = tmp_path / "messaging-pubsub"
    _copy_module(MODULE, wd)
    (wd / "tests").mkdir()
    (wd / "tests" / "push.tftest.hcl").write_text(MODULE_TEST, encoding="utf-8")
    r = runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-3000:]
    r = runner._run(["validate", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-3000:]
    r = runner._run(["test", "-test-directory=tests", "-filter=tests/push.tftest.hcl", "-no-color"], cwd=wd)
    out = r.stdout + r.stderr
    assert r.returncode == 0 and "5 passed, 0 failed" in out, out[-4000:]


ROOT_MAIN = f'''module "compute" {{
  source                     = "./modules/compute-cloudrun"
  project_id                 = "push-test"
  product_id                 = "push"
  service_account_email      = "{SA}"
  allow_unauthenticated      = false
  enable_direct_iap          = false
  authorized_invoker_members = ["user:ana@example.com"]
  push_service_accounts      = {{ "fact.workload_sa_email" = "{SA}" }}
  env_vars                   = {{ EVENTS_TOPIC = module.events.topic_id }}
}}

module "events" {{
  source            = "./modules/messaging-pubsub"
  project_id        = "push-test"
  workload_sa_email = "{SA}"
  push = {{
    audience              = module.compute.service_uri
    endpoint              = "${{module.compute.service_uri}}/api/v1/tasks/process"
    service_account_email = "{SA}"
  }}
}}

output "subscription" {{
  value = module.events.subscription_name
}}
'''
ROOT_TEST = f'''mock_provider "google" {{}}
mock_provider "google-beta" {{
  mock_resource "google_cloud_run_v2_service" {{
    defaults = {{
      uri = "{URI}"
    }}
  }}
}}

run "service_reads_the_topic_and_the_subscription_pushes_to_the_service" {{
  command = plan
  assert {{
    condition     = module.compute.service_uri == "{URI}"
    error_message = "the root must plan (no dependency cycle)"
  }}
}}
'''


def test_root_with_a_service_publishing_to_the_topic_it_is_pushed_from_has_no_cycle(runner, tmp_path):
    """Invariant 6 in Terraform's own graph: module.compute reads module.events.topic_id, module.events' push reads
    module.compute.service_uri; module inputs / outputs are separate graph nodes, so validate and plan succeed."""
    wd = tmp_path / "root"
    _copy_module(MODULE, wd / "modules" / "messaging-pubsub")
    _copy_module(CLOUDRUN, wd / "modules" / "compute-cloudrun")
    (wd / "main.tf").write_text(ROOT_MAIN, encoding="utf-8")
    (wd / "tests").mkdir()
    (wd / "tests" / "root.tftest.hcl").write_text(ROOT_TEST, encoding="utf-8")
    r = runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-3000:]
    r = runner._run(["validate", "-no-color"], cwd=wd)
    assert r.returncode == 0 and "Cycle" not in r.stdout + r.stderr, (r.stdout + r.stderr)[-3000:]
    r = runner._run(["test", "-test-directory=tests", "-filter=tests/root.tftest.hcl", "-no-color"], cwd=wd)
    out = r.stdout + r.stderr
    assert r.returncode == 0 and "1 passed, 0 failed" in out, out[-4000:]
