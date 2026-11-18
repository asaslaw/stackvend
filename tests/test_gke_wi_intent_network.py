"""GKE-WI-INTENT + GKE-NETWORK-PLATFORM-FACT (ex04-1115b, docs/handoff/ex04-1115b-judge-no-progress-diagnosis.md).

Live run ex04-1115 (stackvend12, 11-15): QA attempts 1-3 passed 15/15 tests and the adherence judge blocked each time
on the same two findings on infra/workload/iac_intent.json; three QA repairs could fix neither and the run stopped
NO_PROGRESS.
- INFRA-04, the GKE Workload Identity grant (roles/iam.workloadIdentityUser for
  serviceAccount:<project>.svc.id.goog[stream-apps/sa-stream-worker]): a TRUE gap (the platform renders no such
  grant; V-K8S-WI reported it report-only), and the typed intent could not express it (role table + member grammar).
  Fix: one typed member form, gate-paired with that role on google_service_account_iam_member, only for a workload
  with a GKE service; rendered with depends_on on the GKE compute module.
- INFRA-01, a dedicated subnet / secondary ranges / Cloud NAT via networking-vpc: inexpressible (networking-vpc is
  platform_only, lane-11 types refused) and the platform puts the cluster on the project's `default` network. Fix: a
  typed facet GKE_NETWORK, a documented LIMITATION only when the commit is a typed-intent tree whose GKE module is on
  `var.network` = "default" (exact parse).
Negatives: the live intent without the new entry renders byte-identical to the live custom.tf.json; every other
pairing / workload is refused; the network facet is not handled for any other commit and never on a code task.
"""
import hermetic_guard  # noqa: F401  (first import)

import copy
import json
import os
import sys

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

import fd4f_support  # noqa: E402,F401  (gateway dir on sys.path)
from shared import iac_intent as II  # noqa: E402

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "ex04_1115b")


def _fix(name: str) -> str:
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return fh.read()


GKE_SERVICES = {"ex04-1115": ("module.compute", "compute-gke-autopilot")}
TOPOLOGY = {"stream_events": "google_pubsub_topic", "stream_gke_sub": "google_pubsub_subscription"}


def _ctx(services=None) -> II.IntentContext:
    return II.IntentContext(services=GKE_SERVICES if services is None else services, topology_resources=TOPOLOGY,
                            service_reads=(("ex04-1115", "stream_gke_sub"),) if services is None else (),
                            reserved_module_names=frozenset({"foundation", "compute"}))


SA_NAME = {"$ref": {"kind": "resource_attr", "type": "google_service_account", "name": "stream_worker", "attr": "name"}}
GKE_MEMBER = {"$member": {"gke_service_account": {"namespace": "stream-apps", "name": "sa-stream-worker"}}}


def _wi(**over):
    entry = {"type": II.GKE_WI_RESOURCE_TYPE, "name": "stream_worker_wi",
             "arguments": {"service_account_id": SA_NAME, "role": II.GKE_WI_ROLE, "member": GKE_MEMBER}}
    entry["arguments"].update(over.pop("arguments", {}))
    entry.update(over)
    return entry


def _doc(*extra):
    doc = json.loads(_fix("iac_intent.json"))
    doc["resources"] += [copy.deepcopy(e) for e in extra]
    return doc


def _codes(doc, ctx=None):
    return [d.code for d in II.validate_intent(doc, ctx=ctx or _ctx()).diagnostics]


# ------------------------------------------------------------------------------------------------ negative: no harm
def test_live_intent_renders_byte_identical_to_the_live_render():
    """Do No Harm: the ex04-1115 intent (commit 0a47fb83, no GKE member) renders exactly the custom.tf.json main
    662968a0 committed live."""
    res = II.validate_intent(_fix("iac_intent.json"), ctx=_ctx())
    assert res.ok, res.codes
    assert II.render_intent(res.validated).files == {II.RENDER_PATH: _fix("custom.tf.json")}


def test_ai_depends_on_without_a_gke_member_is_rendered_as_before():
    doc = _doc()
    doc["resources"][1]["depends_on"] = [{"module": "stream_events"}]
    res = II.validate_intent(doc, ctx=_ctx())
    assert res.ok, res.codes
    body = json.loads(II.render_intent(res.validated).files[II.RENDER_PATH])
    assert body["resource"]["google_service_account"]["stream_worker"]["depends_on"] == ["module.stream_events"]


# ------------------------------------------------------------------------------------------------ the fix
def test_the_gke_workload_identity_entry_is_valid_and_rendered_after_the_cluster():
    res = II.validate_intent(_doc(_wi()), ctx=_ctx())
    assert res.ok, res.codes
    out = II.render_intent(res.validated).files[II.RENDER_PATH]
    grant = json.loads(out)["resource"][II.GKE_WI_RESOURCE_TYPE]["stream_worker_wi"]
    assert grant == {"service_account_id": "${google_service_account.stream_worker.name}",
                     "role": "roles/iam.workloadIdentityUser",
                     "member": "serviceAccount:${var.project_id}.svc.id.goog[stream-apps/sa-stream-worker]",
                     "depends_on": ["module.compute"]}
    # every other entry is exactly the live render's
    live = json.loads(_fix("custom.tf.json"))
    got = json.loads(out)
    del got["resource"][II.GKE_WI_RESOURCE_TYPE]["stream_worker_wi"]
    got.pop("//"), live.pop("//")
    assert got == live


def test_the_rendered_grant_satisfies_the_platform_k8s_identity_validator():
    from developer_agent.validators import ValidationContext
    from developer_agent.validators.k8s_identity import WorkloadIdentityBindingValidator

    res = II.validate_intent(_doc(_wi()), ctx=_ctx())
    files = {II.INTENT_PATH: json.dumps(_doc(_wi())), "k8s/serviceaccount.yaml": _fix("serviceaccount.yaml")}
    files.update(II.render_intent(res.validated).files)
    assert WorkloadIdentityBindingValidator().validate(ValidationContext.build(files, ownership=lambda p: None)) == []


def test_ai_depends_on_is_kept_and_the_cluster_added_once():
    deps = [{"module": "stream_events"}, {"resource": {"type": "google_service_account", "name": "stream_worker"}}]
    res = II.validate_intent(_doc(_wi(depends_on=deps)), ctx=_ctx())
    assert res.ok, res.codes
    grant = json.loads(II.render_intent(res.validated).files[II.RENDER_PATH])["resource"][II.GKE_WI_RESOURCE_TYPE]
    assert grant["stream_worker_wi"]["depends_on"] == ["module.stream_events", "google_service_account.stream_worker",
                                                       "module.compute"]


def test_two_gke_services_both_clusters_are_waited_for():
    ctx = _ctx({"a": ("module.compute", "compute-gke-autopilot"), "b": ("module.compute_b", "compute-gke-autopilot"),
                "web": ("module.compute_web", "compute-cloudrun")})
    assert II.gke_compute_modules(ctx) == ("module.compute", "module.compute_b")
    doc = _doc(_wi())
    for e in doc["modules"] + doc["resources"]:
        e.pop("realizes", None)
    res = II.validate_intent(doc, ctx=II.IntentContext(
        services=dict(ctx.services), reserved_module_names=frozenset({"foundation", "compute", "compute_b",
                                                                      "compute_web"})))
    assert res.ok, res.codes
    grant = json.loads(II.render_intent(res.validated).files[II.RENDER_PATH])["resource"][II.GKE_WI_RESOURCE_TYPE]
    assert grant["stream_worker_wi"]["depends_on"] == ["module.compute", "module.compute_b"]


def test_a_read_resource_waiting_for_the_grant_is_a_cycle():
    """RT F5: the gate's graph has the edge the renderer adds (grant -> its cluster), so a resource the GKE service
    reads that depends on the grant is a topology cycle."""
    doc = _doc(_wi())
    sub = next(r for r in doc["resources"] if r["name"] == "stream_gke_sub")
    sub["depends_on"] = [{"resource": {"type": II.GKE_WI_RESOURCE_TYPE, "name": "stream_worker_wi"}}]
    assert "TOPOLOGY.CYCLE" in _codes(doc)
    assert "TOPOLOGY.CYCLE" not in _codes(_doc(_wi()))   # negative: without that depends_on, no cycle


def test_system_namespaces_are_refused():
    tf_dir = os.path.join(REPO_ROOT, "mcp-servers", "terraform")
    import importlib.util
    spec = importlib.util.spec_from_file_location("k8s_manifest_apply_parity",
                                                  os.path.join(tf_dir, "k8s_manifest_apply.py"))
    K = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(K)
    assert II.K8S_PROTECTED_NAMESPACES == K.PROTECTED_NAMESPACES   # parity with the deploy's protected set
    for ns in sorted(II.K8S_PROTECTED_NAMESPACES):
        entry = _wi(arguments={"member": {"$member": {"gke_service_account": {"namespace": ns, "name": "default"}}}})
        assert II.GKE_WI_NAMESPACE_CODE in _codes(_doc(entry)), ns


# ------------------------------------------------------------------------------------------------ refusals
def test_no_gke_service_refuses_the_member():
    run = {"ex04-1115": ("module.compute", "compute-cloudrun")}
    assert II.GKE_WI_UNAVAILABLE_CODE in _codes(_doc(_wi()), _ctx(run))
    assert II.GKE_WI_UNAVAILABLE_CODE in _codes(_doc(_wi()), _ctx({}))


@pytest.mark.parametrize("entry", [
    _wi(arguments={"role": "roles/iam.serviceAccountUser"}),          # GKE member, another role
    _wi(arguments={"member": {"$member": {"service_account": {"$ref": {"kind": "fact",
                                                                       "fact": "workload_sa_email"}}}}}),  # WI + SA
    {"type": "google_project_iam_member", "name": "wi_project",                                 # project level
     "arguments": {"project": {"$ref": {"kind": "fact", "fact": "project_id"}}, "role": II.GKE_WI_ROLE,
                   "member": GKE_MEMBER}},
    {"type": "google_pubsub_subscription_iam_member", "name": "wi_sub",                         # another IAM type
     "arguments": {"subscription": {"$ref": {"kind": "resource_attr", "type": "google_pubsub_subscription",
                                             "name": "stream_gke_sub", "attr": "name"}},
                   "role": "roles/pubsub.subscriber", "member": GKE_MEMBER}},
])
def test_every_other_pairing_is_refused(entry):
    codes = _codes(_doc(entry))
    assert II.GKE_WI_PAIRING_CODE in codes
    assert not II.validate_intent(_doc(entry), ctx=_ctx()).ok


def test_the_workload_identity_role_with_a_service_account_member_on_project_level_is_unchanged():
    """Negative: a project-level WI grant with an ordinary member keeps its pre-existing refusal."""
    entry = {"type": "google_project_iam_member", "name": "wi_project",
             "arguments": {"project": {"$ref": {"kind": "fact", "fact": "project_id"}}, "role": II.GKE_WI_ROLE,
                           "member": {"$member": {"service_account": {"$ref": {"kind": "fact",
                                                                                "fact": "workload_sa_email"}}}}}}
    codes = _codes(_doc(entry))
    assert II.GKE_WI_PAIRING_CODE not in codes and "IAC.ROLE_NOT_ALLOWED" in codes


@pytest.mark.parametrize("ns,name", [
    ("Stream-Apps", "sa"), ("stream/apps", "sa"), ("stream-apps", "sa]x"), ("stream-apps", "a/b"),
    ("stream-apps", "${var.x}"), ("-bad", "sa"), ("stream-apps", "x" * 254), ("a" * 64, "sa"), ("", "sa"),
])
def test_kubernetes_grammar_is_exact(ns, name):
    entry = _wi(arguments={"member": {"$member": {"gke_service_account": {"namespace": ns, "name": name}}}})
    res = II.validate_intent(_doc(entry), ctx=_ctx())
    assert not res.ok and res.validated is None
    # RT F7 (pinned as is): an untyped member is plain data, so the type, reserved-key and pairing codes all fire
    if ns and name and not name.startswith("$"):
        assert {"IAC.TYPE_MISMATCH", II.GKE_WI_PAIRING_CODE} <= set(res.codes)


def test_the_member_never_appears_outside_member():
    entry = _wi(arguments={"service_account_id": GKE_MEMBER})
    assert "IAC.MEMBER_NOT_ALLOWED_HERE" in _codes(_doc(entry))


# ------------------------------------------------------------------------------------------------ prompts
def _run_context(services):
    from developer_agent import iac_intent_contract as C
    return C._run_context(None, _ctx(services), None)


def test_gke_workload_context_names_the_entry():
    text = _run_context(None)
    assert "GKE Workload Identity" in text and '"gke_service_account"' in text and II.GKE_WI_ROLE in text


def test_other_workloads_context_has_no_gke_line():
    assert "GKE Workload Identity" not in _run_context({"svc": ("module.compute", "compute-cloudrun")})
    assert "GKE Workload Identity" not in _run_context({})


def test_k8s_identity_hint_on_an_intent_tree_is_the_typed_entry():
    from developer_agent.validators import ValidationContext
    from developer_agent.validators.k8s_identity import WorkloadIdentityBindingValidator

    files = {II.INTENT_PATH: _fix("iac_intent.json"), II.RENDER_PATH: _fix("custom.tf.json"),
             "k8s/serviceaccount.yaml": _fix("serviceaccount.yaml")}
    (d,) = WorkloadIdentityBindingValidator().validate(ValidationContext.build(files, ownership=lambda p: None))
    assert d.file == II.INTENT_PATH and d.symbol == "stream-apps/sa-stream-worker"
    assert '"gke_service_account": {"namespace": "stream-apps", "name": "sa-stream-worker"}' in d.hint
    legacy = {"k8s/serviceaccount.yaml": _fix("serviceaccount.yaml")}
    (d2,) = WorkloadIdentityBindingValidator().validate(ValidationContext.build(legacy, ownership=lambda p: None))
    assert d2.file == "infra/workload/custom.tf" and "custom.tf" in d2.hint   # legacy tree: as before


# ------------------------------------------------------------------------------------------------ GKE network facet
from qa_auditor import platform_satisfied as PS  # noqa: E402


# the live terraform.tfvars (inlined: *.tfvars is git-ignored, RT F1)
LIVE_TFVARS = 'additional_apis            = ["compute.googleapis.com", "container.googleapis.com"]\n'
SUBNET_VAR = ('variable "subnetwork" {\n  description = "VPC subnetwork name"\n  type        = string\n'
              '  default     = ""\n}')
ROOT_PATHS = {"main": "infra/workload/main.tf", "variables": "infra/workload/variables.tf",
              "tfvars": "infra/workload/terraform.tfvars", "intent": II.INTENT_PATH, "render": II.RENDER_PATH}


def _tree(extra=None, **over):
    files = {II.INTENT_PATH: _fix("iac_intent.json"), II.RENDER_PATH: _fix("custom.tf.json"),
             "infra/workload/main.tf": _fix("main.tf"), "infra/workload/variables.tf": _fix("variables.tf"),
             "infra/workload/terraform.tfvars": LIVE_TFVARS}
    # the live commit's other root files: platform-rendered (moved.tf, outputs.tf) or comment-only stubs (human*.tf)
    for name in ("human.tf", "human_override.tf", "moved.tf", "outputs.tf"):
        files["infra/workload/" + name] = _fix(name)
    for k, v in over.items():
        if v is None:
            files.pop(ROOT_PATHS[k])
        else:
            files[ROOT_PATHS[k]] = v
    files.update(extra or {})
    return files


@pytest.fixture()
def gw(monkeypatch):
    mod = fd4f_support.load_gateway(monkeypatch, "gke_net_gw")
    yield mod
    mod.app.dependency_overrides.clear()


def test_the_live_commit_is_a_gke_commit_on_the_default_network(gw):
    assert gw._commit_gke_on_default_network(_tree()) is True
    assert gw._commit_gke_on_default_network(_tree(tfvars=None)) is True


@pytest.mark.parametrize("over", [
    {"intent": None}, {"render": None},                                                     # not a typed-intent tree
    {"main": _fix("main.tf").replace("network    = var.network", "network    = google_compute_network.x.name")},
    {"variables": _fix("variables.tf").replace('default     = "default"', 'default     = "vpc-a"', 1)},
    {"tfvars": LIVE_TFVARS + 'network = "vpc-a"\n'},
    {"tfvars": LIVE_TFVARS + 'subnetwork = "sb-custom"\n'},
    {"main": _fix("main.tf").replace("subnetwork = var.subnetwork", 'subnetwork = "sb-custom"')},
    {"variables": _fix("variables.tf").replace(SUBNET_VAR, SUBNET_VAR.replace('= ""', '= "sb-x"'))},
    {"main": _fix("main.tf").replace("../modules/compute-gke-autopilot", "../modules/compute-cloudrun")},
    {"main": "module \"compute\" {\n"},                                                      # does not parse
    {"main": None}, {"variables": None},
])
def test_any_other_commit_is_not_handled(gw, over):
    assert gw._commit_gke_on_default_network(_tree(**over)) is False


GKE_ON_VPC_A = ('module "compute2" {\n  source  = "../modules/compute-gke-autopilot"\n  project_id = var.project_id\n'
                '  region = var.region\n  product_id = var.product_id\n  network = "vpc-a"\n}\n')


@pytest.mark.parametrize("extra", [   # RT F3: a person's or the AI's own root file can change the network
    {"infra/workload/net.auto.tfvars": 'network = "vpc-a"\n'},
    {"infra/workload/terraform.tfvars.json": '{"network": "vpc-a"}'},
    {"infra/workload/override.tf": 'module "compute" {\n  network = "vpc-a"\n}\n'},
    {"infra/workload/human_override.tf": 'module "compute" {\n  network = "vpc-a"\n}\n'},
    {"infra/workload/variables_override.tf": 'variable "network" {\n  default = "vpc-a"\n}\n'},
    {"infra/workload/human.tf": GKE_ON_VPC_A},
    {"infra/workload/extra.tf.json": '{"variable": {"x": {}}}'},
    {"infra/workload/human.tf": 'resource "x" {\n'},                                          # does not parse
])
def test_any_other_root_file_with_content_is_not_handled(gw, extra):
    assert gw._commit_gke_on_default_network(_tree(extra)) is False


def test_comment_only_and_empty_extra_root_files_keep_it_handled(gw):
    assert gw._commit_gke_on_default_network(_tree({"infra/workload/notes.tf": "# only a comment\n",
                                                    "infra/workload/empty.tf.json": '{"//": "c"}',
                                                    "infra/workload/x.auto.tfvars": ""})) is True
    # a file outside the root module (a subfolder) is not the root's
    assert gw._commit_gke_on_default_network(_tree({"infra/workload/sub/x.tf": GKE_ON_VPC_A})) is True


def test_the_variables_replacement_hits_the_network_variable():
    """Fixture guard: the first `default = "default"` / `default = ""` of the live variables.tf belong to variable
    "network" / "subnetwork", and the main.tf replacements exist."""
    text = _fix("variables.tf")
    assert text.index('variable "network"') < text.index('default     = "default"') < text.index('variable "subnetwork"')
    assert text.count(SUBNET_VAR) == 1
    assert "subnetwork = var.subnetwork" in _fix("main.tf") and "network    = var.network" in _fix("main.tf")


def test_gke_network_is_a_documented_limitation_only_when_handled():
    assert PS.FACET_GKE_NETWORK not in PS.platform_handlings(None)
    assert PS.FACET_GKE_NETWORK not in PS.platform_handlings({"budget_ceiling_monthly_usd": 10.0})
    h = PS.platform_handlings(None, gke_default_network=True)[PS.FACET_GKE_NETWORK]
    assert h.kind == PS.KIND_LIMITATION and h.known_limitation == PS.GKE_NETWORK_LIMITATION
    assert PS.FACET_GKE_NETWORK not in PS.SECURITY_FACETS


def test_the_known_limitation_section_exists():
    with open(os.path.join(REPO_ROOT, "documentation", "known-limitations.md"), encoding="utf-8") as fh:
        assert f"## {PS.GKE_NETWORK_LIMITATION}\n" in fh.read()


DAG = [{"task_id": "INFRA-01", "category": "INFRA", "target_files": ["infra/workload/iac_intent.json"]},
       {"task_id": "CODE-01", "category": "CODE", "target_files": ["apps/ex04-1115/worker.py"]}]
NET_MSG = ("Private subnet, secondary GKE pod/service CIDR ranges, and Cloud NAT configured via networking-vpc "
           "(iac_intent.json omits the networking-vpc module)")


def _lens(monkeypatch, facets, task_ids, files=None, handled=True, adh=0.85):
    import qa_auditor.judge as judge_mod
    from qa_auditor import adherence_lens as AL
    from qa_auditor.platform_facts import PlatformFacts

    seen = {}

    def fake(prompt, model, **k):
        seen["prompt"] = prompt
        body = {"instruction_adherence_score": adh, "grounding_score": 1.0, "missed_directives": [NET_MSG],
                "hallucinated_features": [], "summary": "s", "missed_directive_task_ids": task_ids}
        if facets is not None:
            body["missed_directive_facets"] = facets
        if files is not None:
            body["missed_directive_files"] = files
        return json.dumps(body)

    monkeypatch.setattr(judge_mod, "call", fake)
    monkeypatch.setattr(judge_mod, "untrusted_block", lambda label, content: f"<<{label}>>{content}<</{label}>>")
    hand = PS.platform_handlings(None, gke_default_network=handled)
    res = AL.evaluate_adherence_lens("diff --git a/x b/x", task_dag=DAG, pytest_logs="ok", compliance_summary="c",
                                     model_name="m", file_inventory="x",
                                     platform_facts=PlatformFacts(text="- fact", handled=hand))
    return res, seen


def test_a_labelled_network_finding_on_an_infra_task_is_an_advisory(monkeypatch):
    res, seen = _lens(monkeypatch, ["GKE_NETWORK"], ["INFRA-01"], [II.INTENT_PATH])
    assert res.passed is True and res.missed_directives == []
    (adv,) = res.platform_limitation_advisories
    assert adv.facet == "GKE_NETWORK" and adv.known_limitation == PS.GKE_NETWORK_LIMITATION
    assert "GKE_NETWORK" in seen["prompt"]


@pytest.mark.parametrize("facets,task_ids,handled", [
    (["OTHER"], ["INFRA-01"], True),            # judge did not label it
    (None, ["INFRA-01"], True),                 # no facet field
    (["GKE_NETWORK"], ["CODE-01"], True),       # a code task's finding stays blocking whatever its label
    (["GKE_NETWORK"], ["INFRA-01"], False),     # not a GKE-on-default-network commit: not handled
])
def test_otherwise_the_network_finding_still_blocks(monkeypatch, facets, task_ids, handled):
    res, _ = _lens(monkeypatch, facets, task_ids, [II.INTENT_PATH], handled=handled)
    assert res.passed is False and res.missed_directives == [NET_MSG]
    assert res.platform_limitation_advisories == []


def test_unattributed_network_finding_on_the_intent_still_blocks(monkeypatch):
    """The LIMITATION rule (SECURITY-LENS-PLATFORM-FACTS RT F1) is unchanged: with no task, the named file must be one
    the platform wrote; iac_intent.json is the AI's."""
    res, _ = _lens(monkeypatch, ["GKE_NETWORK"], [""], [II.INTENT_PATH])
    assert res.passed is False and res.missed_directives == [NET_MSG]
