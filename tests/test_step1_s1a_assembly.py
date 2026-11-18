"""Step 1 S1-A (register HS-01, HS-08): the root-module assembly contract replaces the Tier-3 consolidation and the
HA-10 stem purge (integration plan §S.5, §S.6 step 4). Do-No-Harm negatives: every LLM block that is not a recorded
exact-key replacement survives byte-identical, pre-existing files are never deleted or changed."""
import hermetic_guard  # noqa: F401  (first import)

import asyncio
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

try:  # RT fix 3: acceptance evidence must fail loudly, never skip silently or depend on collection order
    import hcl2  # noqa: F401,E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: install apps/orchestrator-gateway/requirements.txt (python-hcl2==7.3.1) or put "
                "the vendored eval/.deps on PYTHONPATH; this file is acceptance evidence and must not skip",
                pytrace=False)

from developer_agent.assembly import (CUSTOM_TF, assemble_root_module, bespoke_root_text,  # noqa: E402
                                      index_blocks, platform_root_keys, splice_out)
from developer_agent.terraform_engine import (generate_golden_main_tf, generate_golden_moved_tf,  # noqa: E402
                                              generate_golden_outputs_tf, generate_golden_variables_tf)

W = "infra/workload/"


def _root_keys(archetype="cloudrun", pid="shop"):
    return platform_root_keys({
        W + "main.tf": generate_golden_main_tf(pid, archetype, ""),
        W + "variables.tf": generate_golden_variables_tf(pid, "owner/shop"),
        W + "outputs.tf": generate_golden_outputs_tf(pid, archetype),
        W + "moved.tf": generate_golden_moved_tf(pid, archetype),
    })


DRAFT_MAIN = '''terraform {
  required_providers {
    google = { source = "hashicorp/google" }
  }
}

provider "google" {
  project = var.project_id
}

provider "google" {
  alias  = "eu"
  region = "europe-west1"
}

resource "google_storage_bucket" "events" {
  name     = "${var.product_id}-events"
  location = var.region
  uniform_bucket_level_access = true
}

resource "google_pubsub_topic" "orders" {
  name = "orders"
}
'''
DRAFT_VARIABLES = '''variable "region" {
  type    = string
  default = "us-central1"
}

variable "retention_days" {
  type    = number
  default = 7
}
'''
DRAFT_OUTPUTS = '''output "service_uri" {
  value = module.compute.service_uri
}

output "bucket_name" {
  value = google_storage_bucket.events.name
}
'''
DRAFT_IAM = '''resource "google_project_iam_member" "reader" {
  project = var.project_id
  role    = "roles/pubsub.subscriber"
  member  = "serviceAccount:${module.foundation.workload_sa_email}"
}
'''
BUCKET_BLOCK = '''resource "google_storage_bucket" "events" {
  name     = "${var.product_id}-events"
  location = var.region
  uniform_bucket_level_access = true
}'''   # S2-B V2e: a compliant bucket (POLICY.ORG_CONSTRAINT would otherwise block the draft)


def _draft():
    return {W + "main.tf": DRAFT_MAIN, W + "variables.tf": DRAFT_VARIABLES, W + "outputs.tf": DRAFT_OUTPUTS,
            W + "iam.tf": DRAFT_IAM, "apps/api/main.py": APP_MAIN, "apps/api/Procfile": APP_PROCFILE}


# Step 2 S2-A (HS-09): the platform no longer writes the Procfile or injects /health, so the draft service carries its
# own valid container contract (V3c would otherwise block it as CONTAINER.ENTRYPOINT_MISSING / HEALTH_ROUTE_MISSING).
APP_MAIN = 'from fastapi import FastAPI\n\napp = FastAPI()\n\n\n@app.get("/health")\ndef health():\n    return {}\n'
APP_PROCFILE = "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n"


def _assemble(files, *, llm=None, pre=(), archetype="cloudrun"):
    return assemble_root_module(files, llm_paths=set(llm if llm is not None else files), preexisting=set(pre),
                                root_keys=_root_keys(archetype),
                                attribution={W + "main.tf": "iac_worker", W + "iam.tf": "iac_worker"},
                                trace_id="t1")


# --------------------------------------------------------------------------------------------- the contract
def test_aux_files_stay_in_place_and_rendered_path_files_are_appended_verbatim():
    res = _assemble(_draft())
    out, rec = res.files, res.record
    assert out[W + "iam.tf"] == DRAFT_IAM                                  # aux: byte-identical, in place
    custom = out[CUSTOM_TF]
    for block in (BUCKET_BLOCK, 'resource "google_pubsub_topic" "orders" {\n  name = "orders"\n}',
                  'provider "google" {\n  alias  = "eu"\n  region = "europe-west1"\n}',
                  'variable "retention_days" {\n  type    = number\n  default = 7\n}',
                  'output "bucket_name" {\n  value = google_storage_bucket.events.name\n}'):
        assert custom.count(block) == 1, block
    assert "# stackvend: from infra/workload/main.tf (iac_worker)" in custom
    assert custom.index("from infra/workload/main.tf") < custom.index("from infra/workload/variables.tf") \
        < custom.index("from infra/workload/outputs.tf")
    # only exact platform root declarations were removed, each recorded with its reason
    assert rec.replaced_reason == {"terraform": "PLATFORM_ROOT_DECLARATION",
                                   "provider.google": "PLATFORM_ROOT_DECLARATION",
                                   "variable.region": "PLATFORM_ROOT_DECLARATION",
                                   "output.service_uri": "PLATFORM_ROOT_DECLARATION"}
    assert rec.replaced["variable.region"] == "variable.region"           # identity: references still resolve
    assert 'variable "region"' not in custom and "required_providers" not in custom
    assert rec.relocated == {W + "main.tf": CUSTOM_TF, W + "variables.tf": CUSTOM_TF, W + "outputs.tf": CUSTOM_TF}
    assert res.llm_iac_paths == [CUSTOM_TF, W + "iam.tf"]


def test_segments_map_every_assembled_line_back_to_its_draft_line():
    res = _assemble(_draft())
    custom_lines = res.files[CUSTOM_TF].split("\n")
    drafts = {W + "main.tf": DRAFT_MAIN, W + "variables.tf": DRAFT_VARIABLES, W + "outputs.tf": DRAFT_OUTPUTS}
    assert res.record.segments
    for seg in res.record.segments:
        src = drafts[seg.draft_path].split("\n")
        for ln in range(seg.start_line, seg.end_line + 1):
            dpath, dline = res.record.draft_location(CUSTOM_TF, ln)
            assert dpath == seg.draft_path
            assert custom_lines[ln - 1] == src[dline - 1]
    bucket_line = next(i for i, ln in enumerate(custom_lines, 1) if ln.startswith('resource "google_storage_bucket"'))
    assert res.record.draft_location(CUSTOM_TF, bucket_line) == (W + "main.tf", 16)


def test_ai_custom_tf_head_with_heredoc_variable_random_provider_and_moved_is_byte_identical():
    head = '''variable "greeting" {
  type    = string
  default = "hi"
}

provider "random" {}

resource "random_id" "suffix" {
  byte_length = 4
}

resource "google_cloudfunctions2_function" "f" {
  name        = "f"
  description = <<-EOT
    a heredoc with a closing brace }
    and another }
  EOT
}

moved {
  from = google_storage_bucket.old
  to   = google_storage_bucket.new
}
'''
    res = _assemble({CUSTOM_TF: head})
    assert res.files[CUSTOM_TF] == head
    assert res.record.replaced == {}


def test_prior_declaration_keeps_the_existing_block_and_appends_new_ones():
    prior = '''resource "google_storage_bucket" "a" {
  name = "a-old"
}
'''
    main = '''resource "google_storage_bucket" "a" {
  name = "a-new"
}

resource "google_storage_bucket" "b" {
  name = "b"
}
'''
    files = {CUSTOM_TF: prior, W + "main.tf": main}
    res = _assemble(files, llm={W + "main.tf"}, pre={CUSTOM_TF})
    custom = res.files[CUSTOM_TF]
    assert custom.startswith(prior.rstrip("\n"))
    assert 'name = "a-new"' not in custom and custom.count('resource "google_storage_bucket" "a"') == 1
    assert 'resource "google_storage_bucket" "b" {\n  name = "b"\n}' in custom
    assert res.record.replaced_reason == {"google_storage_bucket.a": "PRIOR_DECLARATION"}
    assert res.record.replaced_from == {"google_storage_bucket.a": W + "main.tf"}


def test_preexisting_files_without_provenance_are_never_deleted_or_changed():
    monitoring = 'resource "google_monitoring_alert_policy" "p" {\n  display_name = "budget"\n}\n'
    network = 'resource "google_compute_network" "vpc" {\n  name = "vpc"\n}\n'
    human = '# human\nresource "google_storage_bucket" "h" {\n  name = "h"\n}\n'
    files = dict(_draft(), **{W + "monitoring.tf": monitoring, W + "network.tf": network, W + "human.tf": human})
    res = _assemble(files, llm=set(_draft()), pre={W + "monitoring.tf", W + "network.tf", W + "human.tf"})
    assert res.files[W + "monitoring.tf"] == monitoring
    assert res.files[W + "network.tf"] == network
    assert res.files[W + "human.tf"] == human


def test_iac_outside_the_workload_root_is_left_untouched():
    files = dict(_draft(), **{"infra/workloads/extra.tf": DRAFT_IAM, "infra/stray.tf": DRAFT_IAM})
    res = _assemble(files)
    assert res.files["infra/workloads/extra.tf"] == DRAFT_IAM and res.files["infra/stray.tf"] == DRAFT_IAM


def test_draft_services_tf_is_relocated_not_duplicated():
    svc = 'resource "google_cloud_tasks_queue" "q" {\n  name = "q"\n}\n'
    res = _assemble({W + "services.tf": svc})
    assert W + "services.tf" not in res.files
    assert res.files[CUSTOM_TF].count('resource "google_cloud_tasks_queue" "q"') == 1


def test_aux_file_root_declarations_are_spliced_in_place():
    providers = 'provider "google" {\n  project = var.project_id\n}\n\nprovider "random" {}\n'
    res = _assemble({W + "providers.tf": providers})
    assert res.files[W + "providers.tf"] == '\nprovider "random" {}\n'
    assert res.record.replaced_reason == {"provider.google": "PLATFORM_ROOT_DECLARATION"}
    assert res.record.draft_location(W + "providers.tf", 2) == (W + "providers.tf", 5)


def test_unparseable_draft_file_is_kept_verbatim():
    broken = 'resource "google_pubsub_topic" "t" {\n  name = [1, 2]]\n}\nvariable "region" {}\n'
    res = _assemble({W + "main.tf": broken})
    assert broken.rstrip("\n") in res.files[CUSTOM_TF] and res.record.replaced == {}


def test_overlapping_block_on_a_shared_line_is_never_cut():
    # two blocks on one line: removing the provider would cut the bucket, so nothing is removed
    text = 'provider "google" {}  resource "google_storage_bucket" "x" { name = "x" }\n'
    blocks = index_blocks(text)
    if blocks is None or len(blocks) < 2:
        pytest.skip("python-hcl2 does not parse two blocks on one line")
    res = _assemble({W + "iam.tf": text})
    assert res.files[W + "iam.tf"] == text


def test_reassembly_is_idempotent():
    first = _assemble(_draft())
    again = assemble_root_module(first.files, llm_paths={CUSTOM_TF, W + "iam.tf"}, preexisting=set(),
                                 root_keys=_root_keys(), trace_id="t2")
    assert again.files[CUSTOM_TF] == first.files[CUSTOM_TF] and again.record.replaced == {}


@pytest.mark.parametrize("archetype", ["cloudrun", "gke-autopilot", "gce-bastion", "event-worker", "foundation-only"])
def test_root_keys_do_not_depend_on_custom_content(archetype):
    plain = platform_root_keys({W + "main.tf": generate_golden_main_tf("shop", archetype, "")})
    custom = 'resource "google_storage_bucket" "b" {\n  name = "b"\n}\nresource "google_compute_network" "n" {}\n'
    wired = platform_root_keys({W + "main.tf": generate_golden_main_tf(
        "shop", archetype, "", service_name="api", custom_tf_content=custom, app_files={"apps/api/main.py": ""})})
    assert plain == wired and "terraform" in plain and "provider.google" in plain


def test_splice_out_maps_chunks():
    text = "a\nb\nc\nd\ne\n"
    new, chunks = splice_out(text, [(2, 3)])
    assert new == "a\nd\ne\n" and chunks == [(1, 1, 1), (2, 4, 3)]


def test_bespoke_root_text_reads_custom_then_aux_but_not_platform_files():
    files = {CUSTOM_TF: "C", W + "zeta.tf": "Z", W + "alpha.tf": "A", W + "main.tf": "M", W + "human.tf": "H",
             W + "indexes.tf": "I", "infra/modules/x/main.tf": "X"}
    assert bespoke_root_text(files) == "C\n\nA\n\nZ"


# --------------------------------------------------------------------------------------------- tombstones
def test_handler_no_longer_calls_hb03_and_hb03_is_deleted():
    import ast
    src = open(os.path.join(GATEWAY, "developer_agent", "handler.py")).read()
    names = {n.id for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Name)}
    attrs = {n.attr for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Attribute)}
    assert "extract_bespoke_custom_resources" not in names | attrs
    assert "canonical_workload_stems" not in names  # HA-10 stem purge deleted (HS-08)
    import developer_agent
    from developer_agent import terraform_engine
    # FD-55 W1 (register FD55-W1): the uncalled HB-03 body and its package export are deleted
    assert not hasattr(terraform_engine, "extract_bespoke_custom_resources")
    assert "extract_bespoke_custom_resources" not in developer_agent.__all__


# --------------------------------------------------------------------------------------------- generation path
class _NoCallGenaiClient:
    """Step1 merge (lane 19 row 27a): generate_code_files now fails LLM_UNAVAILABLE without a client, before the
    lead or the swarm runs. These tests fake the lead + dispatcher (the draft is fixed), so the agent gets a client
    that must never be called: any model call is a test failure, exactly like the old `genai_client = None`."""

    class models:  # noqa: N801 - mirrors google.genai.Client().models
        @staticmethod
        def generate_content(*a, **k):
            raise AssertionError("unexpected LLM call: the draft comes from the fake dispatcher")


def _run_generate(draft, existing=None, spec="FastAPI orders service", pid="shop"):
    """generate_code_files with a fixed swarm draft (no LLM): lead plan + dispatcher are stubbed."""
    from developer_agent import handler as h
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GEMINI_API_KEY": ""}):
        agent = h.DeveloperAgent(project_id="")  # no Firestore / Vertex client is ever constructed
    agent.genai_client = _NoCallGenaiClient()  # lane 19 (27a): None now raises LLM_UNAVAILABLE first
    plan = MagicMock()
    plan.execution_mode = h.SwarmExecutionMode.PHASED_WAVES if hasattr(h.SwarmExecutionMode, "PHASED_WAVES") \
        else [m for m in h.SwarmExecutionMode if m != h.SwarmExecutionMode.SOLO_FAST_PATH][0]
    plan.tasks = [MagicMock()]

    class FakeDispatcher:
        def __init__(self, *a, **k):
            self.last_file_attribution = {p: "iac_worker" if p.endswith(".tf") else "backend_worker" for p in draft}

        async def execute_phased_junior_swarm(self, *a, **k):
            return dict(draft)

    with patch.object(h, "LeadDeveloperOrchestrator") as lead, patch.object(h, "SwarmDispatcher", FakeDispatcher), \
            patch.object(agent, "fetch_existing_repo_files", return_value=dict(existing or {})), \
            patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GCP_PROJECT": ""}), \
            patch("google.cloud.firestore.Client", side_effect=RuntimeError("no Firestore in tests")):
        lead.return_value.decompose_specification.return_value = plan
        # a pipeline trace carries the architect's typed compute record (RT fix 2: none -> COMPUTE_INTENT_MISSING)
        files = agent.generate_code_files(product_id=pid, spec_text=spec, task_dag=[], trace_id="trace-s1a",
                                          architect_compute_intent={"target_compute_services": [pid]}, allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False)
    return agent, files


def test_generation_assembles_and_records():
    agent, files = _run_generate(_draft())
    rec = agent.stack_run("trace-s1a")["assembly_record"]
    assert agent.last_assembly_record is rec
    assert files[W + "iam.tf"] == DRAFT_IAM                     # aux file no longer purged (HS-08)
    assert {"terraform", "provider.google", "variable.region"} <= set(rec.replaced)
    # the platform's own main.tf/variables.tf/outputs.tf are rendered as before
    assert 'module "foundation"' in files[W + "main.tf"] and 'variable "project_id"' in files[W + "variables.tf"]


def test_generation_keeps_preexisting_monitoring_and_network_files():
    monitoring = 'resource "google_monitoring_alert_policy" "p" {\n  display_name = "x"\n}\n'
    network = 'resource "google_compute_network" "vpc" {\n  name = "vpc"\n}\n'
    _, files = _run_generate(_draft(), existing={W + "monitoring.tf": monitoring, W + "network.tf": network})
    assert files[W + "monitoring.tf"] == monitoring and files[W + "network.tf"] == network


def test_api_inference_reads_auxiliary_files():
    # S2-C (HS-63): the exact table lists only what the foundation's base_apis do not already enable (storage and
    # pubsub are base APIs), so the auxiliary-file proof uses a Redis instance and a secret.
    storage = 'resource "google_redis_instance" "cache" {\n  name           = "cache"\n  memory_size_gb = 1\n}\n'
    draft = {W + "main.tf": 'resource "google_secret_manager_secret" "s" {\n  secret_id = "s"\n}\n',
             W + "storage.tf": storage, "apps/api/main.py": "app = 1\n"}
    _, files = _run_generate(draft)
    assert 'resource "google_redis_instance" "cache"' in files[W + "storage.tf"]  # in place (later healers may edit)
    tfvars = files.get(W + "terraform.tfvars", "")
    assert "redis.googleapis.com" in tfvars and "secretmanager.googleapis.com" in tfvars


# --------------------------------------------------------------------------------------------- provenance (commit 5)
class _FailingStore:
    def load(self, pid):
        from shared.diagnostics import StoreUnavailable
        raise StoreUnavailable("firestore down")

    def save(self, pid, entries):
        from shared.diagnostics import StoreUnavailable
        raise StoreUnavailable("firestore down")


class _ReadyPassClient:
    def ready(self, iac_engine="OPENTOFU"):
        return {"ready": True, "providers": ["google", "google-beta", "kubernetes", "random"], "engine": "OPENTOFU",
                "engine_version": "1.9.0"}

    def validate(self, files, *, iac_engine="OPENTOFU", trace_id=""):
        return {"status": "PASS", "diagnostics": []}


@pytest.fixture()
def memory_runtime():
    from developer_agent import hallucination_runtime as hr
    hr.configure_for_harness(validate_client=_ReadyPassClient())
    yield hr.get_runtime()
    hr.reset_for_tests()


def _commit(agent, files, trace="trace-s1a"):
    from _fake_vcs import fake_vcs_commit  # FD-4F A9 (Q-E): no token is a typed failure; commit through a fake VCS
    with fake_vcs_commit(agent), \
            patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GCP_PROJECT": ""}), \
            patch("google.cloud.firestore.Client", side_effect=RuntimeError("no Firestore in tests")):
        return agent.commit_and_open_pr(product_id="shop", files=dict(files), trace_id=trace)


def test_provenance_written_after_commit_and_recognized_next_run(memory_runtime):
    import hashlib
    agent, files = _run_generate(_draft())
    res = _commit(agent, files)
    assert res["status"] == "COMMITTED"
    entries = memory_runtime.provenance_store.load("shop")
    assert set(entries) == {CUSTOM_TF, W + "iam.tf"}
    assert entries[W + "iam.tf"].persona == "iac_worker" and entries[W + "iam.tf"].trace_id == "trace-s1a"
    assert entries[W + "iam.tf"].sha256 == hashlib.sha256(files[W + "iam.tf"].encode()).hexdigest()
    # next run: unchanged iam.tf is recognized as the AI's (repairable); an edited one is the user's
    edited = dict(files, **{W + "iam.tf": files[W + "iam.tf"] + "# edited by a person\n"})
    from developer_agent import handler as h
    assert h.DeveloperAgent._load_prior_llm(agent, "shop", files) == {CUSTOM_TF: "iac_worker",
                                                                      W + "iam.tf": "iac_worker"}
    assert W + "iam.tf" not in h.DeveloperAgent._load_prior_llm(agent, "shop", edited)


def test_provenance_store_outage_stops_before_any_llm_call():
    from developer_agent import hallucination_runtime as hr
    from shared.diagnostics import ErrorClass, StageError
    hr.configure(provenance_store=_FailingStore(), source="test")
    try:
        with pytest.raises(StageError) as ei:
            _run_generate(_draft(), existing={W + "iam.tf": DRAFT_IAM})
        assert ei.value.error_class is ErrorClass.GATE_UNAVAILABLE
    finally:
        hr.reset_for_tests()


def test_provenance_write_failure_is_logged_not_raised(caplog):
    from developer_agent import hallucination_runtime as hr
    agent, files = _run_generate(_draft())
    hr.configure(provenance_store=_FailingStore(), source="test")
    try:
        assert _commit(agent, files)["status"] == "COMMITTED"
    finally:
        hr.reset_for_tests()
    assert "IaC provenance not recorded" in caplog.text


# ------------------------------------------------------------------- FD-4Y RT F6: invalid label counts are not blocks
from developer_agent.assembly import file_keys, index_blocks_with_skipped  # noqa: E402

_BAD_LABEL_COUNTS = {
    "resource_one_label": 'resource "google_pubsub_topic" {\n  name = "x"\n}\n',
    "resource_one_label_nested_block": 'resource "google_pubsub_topic" {\n  name {\n    a = 1\n  }\n}\n',
    "resource_three_labels": 'resource "google_pubsub_topic" "a" "b" {\n  name = "x"\n}\n',
    "data_one_label": 'data "google_project" {\n  project_id = "p"\n}\n',
    "module_no_label": 'module {\n  source = "./x"\n}\n',
    "module_two_labels": 'module "a" "b" {\n  source = "./x"\n}\n',
    "variable_no_label": 'variable {\n  type = string\n}\n',
    "output_no_label": 'output {\n  value = 1\n}\n',
    "provider_no_label": 'provider {\n  project = "p"\n}\n',
    "terraform_labelled": 'terraform "x" {\n  a = 1\n}\n',
    "locals_labelled": 'locals "x" {\n  a = 1\n}\n',
}


@pytest.mark.parametrize("name", sorted(_BAD_LABEL_COUNTS))
def test_invalid_label_count_is_not_indexed_as_a_phantom_block(name):
    """F6: python-hcl2 7.3.1 parses these Terraform-invalid blocks; they used to come back as Block(start=0, end=0)
    keyed by an attribute name (`google_pubsub_topic.name`, `module.source`). Now they are skipped, and a valid
    block next to one is indexed with its exact range."""
    bad = _BAD_LABEL_COUNTS[name]
    assert index_blocks(bad) == [] and file_keys(bad) == set()
    text = bad + 'resource "google_storage_bucket" "b" {\n  name = "b"\n}\n'
    first_valid = bad.count("\n") + 1
    got = [(b.kind, b.keys, b.start, b.end, b.labels) for b in index_blocks(text)]
    assert got == [("resource", ("google_storage_bucket.b",), first_valid, first_valid + 2,
                    ("google_storage_bucket", "b"))]
    assert file_keys(text) == {"google_storage_bucket.b"}
    # a caller that must not act on a partial index (HB-02's extract_hcl_blocks) sees the skip
    assert index_blocks_with_skipped(bad) == ([], 1)
    assert index_blocks_with_skipped(text)[1] == 1


def test_index_blocks_with_skipped_edges():
    assert index_blocks_with_skipped("") == ([], 0) and index_blocks_with_skipped("  \n") == ([], 0)
    assert index_blocks_with_skipped('resource "a" "b" {\n  x = [1, 2]]\n}\n') is None   # unparseable, as before
    two = 'module {\n  source = "x"\n  version = "1"\n}\n'
    assert index_blocks_with_skipped(two) == ([], 2)   # one entry per attribute that looked like a label


def test_valid_blocks_index_exactly_as_before_including_empty_bodies():
    """Do No Harm (F6 negative): every valid top-level block, an empty one too, keeps its key, range and labels.
    `check "name" {}` (valid, labelled) and `moved {}` stay as they were (the F6 skip does not touch that branch)."""
    text = ('resource "a" "b" {}\n'
            'data "c" "d" {\n}\n'
            'module "m" {}\n'
            'variable "v" {}\n'
            'output "o" {\n  value = 1\n}\n'
            'provider "google" {}\n'
            'provider "google" {\n  alias = "west"\n}\n'
            'terraform {}\n'
            'locals {\n  x = 1\n  y = 2\n}\n'
            'locals {}\n'
            'moved {\n  from = a.b\n  to = a.c\n}\n'
            'check "health" {\n  assert {\n    condition = true\n    error_message = "x"\n  }\n}\n')
    got = [(b.kind, b.keys, b.start, b.end, b.labels) for b in index_blocks(text)]
    assert got == [
        ("check", ("check:None",), 0, 0, ()),   # pre-existing: a labelled check has no entry-level meta
        ("resource", ("a.b",), 1, 1, ("a", "b")),
        ("data", ("data.c.d",), 2, 3, ("c", "d")),
        ("module", ("module.m",), 4, 4, ("m",)),
        ("variable", ("variable.v",), 5, 5, ("v",)),
        ("output", ("output.o",), 6, 8, ("o",)),
        ("provider", ("provider.google",), 9, 9, ("google",)),
        ("provider", ("provider.google.west",), 10, 12, ("google",)),
        ("terraform", ("terraform",), 13, 13, ()),
        ("locals", ("local.x", "local.y"), 14, 17, ()),
        ("locals", (), 18, 18, ()),
        ("moved", ("moved:${a.b}",), 19, 22, ()),
    ]
    assert index_blocks_with_skipped(text)[1] == 0


def test_phantom_prior_key_no_longer_removes_a_valid_ai_block():
    """F6 consequence: a kept pre-existing file with `resource "google_pubsub_topic" { events = ... }` used to put the
    phantom key `google_pubsub_topic.events` into the prior-declaration set, so this run's valid
    `resource "google_pubsub_topic" "events"` was cut from custom.tf as a PRIOR_DECLARATION."""
    legacy = 'resource "google_pubsub_topic" {\n  events = "x"\n}\n'
    ai = 'resource "google_pubsub_topic" "events" {\n  name = "events"\n}\n'
    res = _assemble({W + "legacy.tf": legacy, CUSTOM_TF: ai}, llm={CUSTOM_TF}, pre={W + "legacy.tf"})
    assert 'resource "google_pubsub_topic" "events"' in res.files[CUSTOM_TF]
    assert "google_pubsub_topic.events" not in res.record.replaced
    assert res.files[W + "legacy.tf"] == legacy
