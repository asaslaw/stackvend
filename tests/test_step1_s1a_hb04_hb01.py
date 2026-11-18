"""Step 1 S1-A commits 2-3 (register HS-01): HB-04 reconcile_multi_service_declarations is append-only with recorded
Cloud Run replacement; HB-01 reconcile_iac_reference_graph was splice-only without the HA-14 dedupe call and is DELETED
by FD-55 W5 (register FD55-W5): its former cases now check that the generation entry point (HB-04) leaves the same
custom.tf files byte-identical.
Do-No-Harm negatives: for every deleted HB-04/HB-01 branch, an LLM block of that shape survives byte-identical."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys

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

from developer_agent import terraform_engine as te  # noqa: E402
from developer_agent.assembly import CUSTOM_TF  # noqa: E402
from shared.diagnostics import AssemblyRecord, Segment  # noqa: E402

W = "infra/workload/"
MAIN = 'module "compute" {\n  source       = "../modules/compute-cloudrun"\n  service_name = var.product_id\n}\n'

# One LLM block per deleted HB-04 strip branch (each used to vanish from custom.tf)
STRIPPED_SHAPES = {
    "foundation type": 'resource "google_project_service" "run" {\n  service = "run.googleapis.com"\n}',
    "firestore": 'resource "google_firestore_database" "database" {\n  name        = "(default)"\n  location_id = var.region\n  type        = "FIRESTORE_NATIVE"\n}',
    "registry": 'resource "google_artifact_registry_repository" "repo" {\n  repository_id = "apps"\n  format        = "DOCKER"\n}',
    "wif pool": 'resource "google_iam_workload_identity_pool" "pool" {\n  workload_identity_pool_id = "gh"\n}',
    "sa name": 'resource "google_service_account" "app_sa" {\n  account_id = "app-sa"\n}',
    "role substring": 'resource "google_project_iam_member" "datastore" {\n  project = var.project_id\n  role    = "roles/datastore.user"\n  member  = "serviceAccount:${google_service_account.app_sa.email}"\n}',
    "iap substring": 'resource "google_project_iam_member" "iap" {\n  project = var.project_id\n  role    = "roles/iap.serviceAgent"\n  member  = "serviceAccount:service-${var.project_number}@gcp-sa-iap.iam.gserviceaccount.com"\n}',
    "billing budget": 'resource "google_billing_budget" "b" {\n  billing_account = "000000-000000-000000"\n  display_name    = "b"\n  amount {\n    specified_amount {\n      units = "10"\n    }\n  }\n}',
    "alert keyword": 'resource "google_monitoring_alert_policy" "spend" {\n  display_name = "Monthly spend warning"\n  combiner     = "OR"\n}',
    "output iap_client_id": 'output "iap" {\n  value = module.compute.iap_client_id\n}',
    "output service_url": 'output "url" {\n  value = module.compute.service_url\n}',
    "random": 'resource "random_id" "suffix" {\n  byte_length = 4\n}',
    "provider": 'provider "random" {}',
    "variable": 'variable "retention" {\n  type    = number\n  default = 7\n}',
    "heredoc": 'resource "google_cloudfunctions2_function" "f" {\n  name        = "f"\n  description = <<-EOT\n    has a } brace\n  EOT\n}',
}


def _custom(*blocks):
    return "\n\n".join(blocks) + "\n"


@pytest.fixture()
def no_hb01():
    """HB-04 in isolation. FD-55 W5: HB-01 is deleted, so there is nothing left to switch off."""
    assert not hasattr(te, "reconcile_iac_reference_graph")
    yield


def _hb04_single(files, assembly_record=None):
    """FD-55 W5: the former HB-01 entry, now HB-04 on a single-service tree (no secondary to synthesize)."""
    te.reconcile_multi_service_declarations(files=files, product_id="shop", spec_text="", archetype="cloudrun",
                                            assembly_record=assembly_record, llm_iac_paths=[CUSTOM_TF])


# --------------------------------------------------------------------------------------------- HB-04 (commit 2)
@pytest.mark.parametrize("shape", sorted(STRIPPED_SHAPES))
@pytest.mark.parametrize("spec", ["A single public REST API", "Two services: api and worker"])
def test_hb04_keeps_every_formerly_stripped_block_byte_identical(no_hb01, shape, spec):
    block = STRIPPED_SHAPES[shape]
    files = {W + "main.tf": MAIN, CUSTOM_TF: _custom(block), "apps/api/main.py": "x = 1\n"}
    if "worker" in spec:
        files["apps/worker/main.py"] = "x = 1\n"
    te.reconcile_multi_service_declarations(files=files, product_id="shop", spec_text=spec, archetype="cloudrun",
                                            assembly_record=AssemblyRecord(), llm_iac_paths=[CUSTOM_TF])
    assert files[CUSTOM_TF].startswith(_custom(block)), shape


def test_hb04_multi_service_appends_synthesized_module_once_and_writes_no_app(no_hb01):
    files = {W + "main.tf": MAIN, CUSTOM_TF: _custom(STRIPPED_SHAPES["random"]),
             "apps/api/main.py": "x = 1\n"}
    spec = "Two services: api and worker"
    typed = ["api", "worker"]   # HD-02: the service set is the typed compute intent, not the spec prose
    rec = AssemblyRecord()
    te.reconcile_multi_service_declarations(files=files, product_id="shop", spec_text=spec, archetype="cloudrun",
                                            assembly_record=rec, llm_iac_paths=[CUSTOM_TF], target_services=typed)
    assert files[CUSTOM_TF].count('module "compute_worker"') == 1          # row 20: secondary still synthesized
    assert "apps/worker/main.py" not in files   # FD-55 W5 (G15): no placeholder app; V3c-planned reports it
    assert files[CUSTOM_TF].startswith(_custom(STRIPPED_SHAPES["random"]))   # appended after the LLM text
    once = dict(files)
    te.reconcile_multi_service_declarations(files=files, product_id="shop", spec_text=spec, archetype="cloudrun",
                                            assembly_record=rec, llm_iac_paths=[CUSTOM_TF], target_services=typed)
    assert files[CUSTOM_TF].count('module "compute_worker"') == 1          # idempotent: resynthesized in place
    assert files[CUSTOM_TF] == once[CUSTOM_TF]
    assert rec.replaced_reason.get("module.compute_worker") == "PLATFORM_RESYNTHESIZED"


def test_hb04_replaces_cloud_run_resources_in_aux_files_with_exact_record(no_hb01):
    compute = ('resource "google_cloud_run_v2_service" "api" {\n  name     = "api"\n  location = var.region\n}\n\n'
               'resource "google_cloud_run_v2_service_iam_member" "public_access" {\n'
               '  name   = google_cloud_run_v2_service.api.name\n  role   = "roles/run.invoker"\n'
               '  member = "allUsers"\n}\n')
    files = {W + "main.tf": MAIN, W + "compute.tf": compute, "apps/api/main.py": "x = 1\n"}
    rec = AssemblyRecord()
    te.reconcile_multi_service_declarations(files=files, product_id="shop", spec_text="A single API",
                                            archetype="cloudrun", assembly_record=rec,
                                            llm_iac_paths=[W + "compute.tf"])
    assert rec.replaced == {"google_cloud_run_v2_service.api": "module.compute"}
    assert rec.replaced_reason == {"google_cloud_run_v2_service.api": "CLOUD_RUN_REPLACED_BY_MODULE"}
    assert rec.replaced_from == {"google_cloud_run_v2_service.api": W + "compute.tf"}
    out = files[W + "compute.tf"]
    assert 'resource "google_cloud_run_v2_service" "api"' not in out
    # references are NOT rewritten (the repair loop fixes them with the exact hint); the IAM member is kept
    assert 'name   = google_cloud_run_v2_service.api.name' in out and 'member = "allUsers"' in out


def test_hb04_cloud_run_resource_maps_to_the_synthesized_module_of_the_same_label(no_hb01):
    custom = 'resource "google_cloud_run_v2_service" "worker" {\n  name = "worker"\n}\n'
    files = {W + "main.tf": MAIN, CUSTOM_TF: custom, "apps/api/main.py": "x = 1\n", "apps/worker/main.py": "x = 1\n"}
    rec = AssemblyRecord()
    te.reconcile_multi_service_declarations(files=files, product_id="shop", spec_text="Two services: api and worker",
                                            archetype="cloudrun", assembly_record=rec, llm_iac_paths=[CUSTOM_TF])
    assert rec.replaced["google_cloud_run_v2_service.worker"] == "module.compute_worker"


def test_hb04_iam_member_labels_never_become_services(no_hb01):
    custom = ('resource "google_cloud_run_v2_service_iam_member" "public_access" {\n  name = "x"\n'
              '  role = "roles/run.invoker"\n  member = "allUsers"\n}\n')
    files = {W + "main.tf": MAIN, CUSTOM_TF: custom, "apps/api/main.py": "x = 1\n", "apps/worker/main.py": "x = 1\n"}
    te.reconcile_multi_service_declarations(files=files, product_id="shop", spec_text="Two services: api and worker",
                                            archetype="cloudrun", assembly_record=AssemblyRecord(),
                                            llm_iac_paths=[CUSTOM_TF])
    assert 'module "compute_public_access"' not in files[CUSTOM_TF]
    assert "apps/public-access/main.py" not in files


def test_hb04_splices_keep_segments_exact(no_hb01):
    custom = ('resource "google_storage_bucket" "a" {\n  name = "a"\n}\n\n'
              'resource "google_cloud_run_v2_service" "api" {\n  name = "api"\n}\n\n'
              'resource "google_pubsub_topic" "t" {\n  name = "t"\n}\n')
    rec = AssemblyRecord(segments=[Segment(assembled_path=CUSTOM_TF, start_line=1, end_line=11,
                                           draft_path=W + "main.tf", draft_start_line=1)])
    files = {W + "main.tf": MAIN, CUSTOM_TF: custom}
    te.reconcile_multi_service_declarations(files=files, product_id="shop", spec_text="A single API",
                                            archetype="cloudrun", assembly_record=rec, llm_iac_paths=[CUSTOM_TF])
    lines = files[CUSTOM_TF].split("\n")
    draft = custom.split("\n")
    topic = next(i for i, ln in enumerate(lines, 1) if "google_pubsub_topic" in ln)
    assert rec.draft_location(CUSTOM_TF, topic) == (W + "main.tf", 9)
    assert lines[topic - 1] == draft[8]


# --------------------------------------------------------------------------------------------- HB-01 (commit 3)
VALID_CUSTOM = _custom(*[STRIPPED_SHAPES[k] for k in sorted(STRIPPED_SHAPES)],
                       'resource "google_pubsub_topic" "t" {\n  name = "t"\n}',
                       'resource "google_pubsub_subscription" "s" {\n  topic      = google_pubsub_topic.t.id\n'
                       '  depends_on = [google_pubsub_topic.t]\n}',
                       '# a comment the old rebuild dropped\nmoved {\n  from = google_storage_bucket.a\n'
                       '  to   = google_storage_bucket.b\n}')


def test_hb01_leaves_a_valid_custom_tf_byte_identical():
    files = {W + "main.tf": MAIN, CUSTOM_TF: VALID_CUSTOM}
    _hb04_single(files, assembly_record=AssemblyRecord())
    assert files[CUSTOM_TF] == VALID_CUSTOM


def test_hb01_no_longer_runs_the_ha14_dedupe():
    # same physical bucket in custom.tf and an aux file: kept in both (tofu reports a real duplicate address only)
    bucket = 'resource "google_storage_bucket" "logs" {\n  name = "${var.product_id}-logs"\n}\n'
    other = 'resource "google_storage_bucket" "archive" {\n  name = "${var.product_id}-logs"\n}\n'
    files = {W + "main.tf": MAIN, CUSTOM_TF: bucket, W + "storage.tf": other}
    _hb04_single(files)
    assert files[CUSTOM_TF] == bucket and files[W + "storage.tf"] == other
    import ast
    src = open(os.path.join(GATEWAY, "developer_agent", "terraform_engine.py")).read()
    called = {n.func.id for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert "deduplicate_semantic_hcl_resources" not in called  # tombstone: HA-14 call deleted from HB-01


def test_hb01_keeps_undeclared_depends_on_entries_and_synthesizes_nothing():
    """S2-B B1 (HS-02): the depends_on prune and the run.invoker synthesis are deleted. The block stays byte-identical
    and V1b reports the undeclared entries (TF.REFERENCE_TO_UNDECLARED_RESOURCE) for the repair loop."""
    custom = ('variable "keep" {\n  default = 1\n}\n\n'
              'resource "google_cloud_scheduler_job" "j" {\n  name = "j"\n'
              '  depends_on = [google_cloud_run_v2_service_iam_member.invoker, google_ghost.x]\n}\n\n'
              'resource "google_pubsub_topic" "t" {\n  name = "t"\n}\n')
    rec = AssemblyRecord(segments=[Segment(assembled_path=CUSTOM_TF, start_line=1, end_line=12,
                                           draft_path=W + "main.tf", draft_start_line=1)])
    files = {W + "main.tf": MAIN, CUSTOM_TF: custom}
    _hb04_single(files, assembly_record=rec)
    assert files[CUSTOM_TF] == custom
    topic = next(i for i, ln in enumerate(custom.split("\n"), 1) if "google_pubsub_topic" in ln)
    assert rec.draft_location(CUSTOM_TF, topic) == (W + "main.tf", topic)


def test_hb01_leaves_an_unparseable_custom_tf_untouched():
    broken = 'resource "google_pubsub_topic" "t" {\n  name = [1]]\n  depends_on = [google_ghost.x]\n}\n'
    files = {W + "main.tf": MAIN, CUSTOM_TF: broken}
    _hb04_single(files)
    assert files[CUSTOM_TF] == broken


@pytest.mark.parametrize("spec", ["A single public REST API", "Two services: api and worker"])
def test_hb04_then_hb01_keep_every_llm_block(spec):
    files = {W + "main.tf": MAIN, CUSTOM_TF: VALID_CUSTOM, "apps/api/main.py": "x = 1\n",
             "apps/worker/main.py": "x = 1\n"}
    te.reconcile_multi_service_declarations(files=files, product_id="shop", spec_text=spec, archetype="cloudrun",
                                            assembly_record=AssemblyRecord(), llm_iac_paths=[CUSTOM_TF])
    assert files[CUSTOM_TF].startswith(VALID_CUSTOM)


def test_hb01_never_cuts_an_indexed_depends_on():
    # R1 finding (07-r2, 02-r3, 05-r1, 07-r3): the regex `\[(.*?)\]` stopped at the `]` inside services["x"],
    # pruned the "undeclared" entry and left a stray `]` -> invalid HCL. Declared entries are never pruned now.
    custom = ('resource "google_project_service" "services" {\n  for_each = toset(["firestore.googleapis.com"])\n'
              '  service  = each.value\n}\n\n'
              'resource "google_firestore_database" "db" {\n  name = "app"\n\n'
              '  depends_on = [google_project_service.services["firestore.googleapis.com"]]\n}\n')
    files = {W + "main.tf": MAIN, CUSTOM_TF: custom}
    _hb04_single(files)
    assert files[CUSTOM_TF] == custom


def test_hb01_no_prune_when_regex_and_hcl2_disagree_on_an_undeclared_indexed_entry():
    """Step 1 code RT F7: an UNDECLARED indexed entry makes the regex split differ from hcl2's exact entry list, so
    the consistency guard (regex_items != exact_deps) must leave the block untouched. Mutation checked: removing that
    clause at terraform_engine.py (HB-01) makes this test fail (stray `]` / pruned entry)."""
    custom = ('resource "google_pubsub_topic" "t" {\n  name = "t"\n}\n\n'
              'resource "google_pubsub_subscription" "s" {\n  topic      = google_pubsub_topic.t.id\n'
              '  depends_on = [google_ghost.x["a"], google_pubsub_topic.t]\n}\n')
    files = {W + "main.tf": MAIN, CUSTOM_TF: custom}
    _hb04_single(files)
    assert files[CUSTOM_TF] == custom
