"""HD-01 / HD-02 replacement (FD-4X, FD-4AC, FD21-08): the compute archetype and the Cloud Run service set come from
the typed compute intent (developer_agent/compute_intent.py), never from spec prose.

Covers: tombstones for the deleted guessers; every archetype the deleted keyword detector could return is reachable
from typed facts; service names in the architect's order with no padding; pinned existing compute; Do-No-Harm
negatives (a valid single-service draft is left byte-identical, spec wording changes nothing); the architect record
and its Firestore / request handoff; the R3d phantom-service and wrong-archetype shapes (01, 02, 04, 08)."""
import hermetic_guard  # noqa: F401  (first import)

import ast
import json
import os
import sys
import typing
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TESTS = os.path.dirname(__file__)
for p in (GATEWAY, REPO_ROOT, TESTS):
    if p not in sys.path:
        sys.path.insert(0, p)

try:  # RT fix 3: acceptance evidence must fail loudly, never skip silently or depend on collection order
    import hcl2  # noqa: F401,E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: install apps/orchestrator-gateway/requirements.txt (python-hcl2==7.3.1) or put "
                "the vendored eval/.deps on PYTHONPATH; this file is acceptance evidence and must not skip",
                pytrace=False)

from architect_agent.schemas import (  # noqa: E402
    ArchitectDecompositionResult,
    ArchitecturePlan,
    ArchitecturePlanDAG,
    COMPUTE_INTENT_RECORD_SCHEMA,
    compute_intent_record,
)
from developer_agent import compute_intent as ci  # noqa: E402
from developer_agent import terraform_engine as te  # noqa: E402
from developer_agent.assembly import CUSTOM_TF  # noqa: E402
from shared.diagnostics import AssemblyRecord  # noqa: E402

W = "infra/workload/"
DEV_DIR = os.path.join(GATEWAY, "developer_agent")
DELETED = ("detect_compute_archetype", "detect_requested_service_count", "detect_requested_service_names",
           "SERVICE_INDICATOR_NOUNS")
# Spec prose that drove the deleted guessers (R3d: 01 -> event-worker Job, 08 -> "service-with", 02 -> service-a/-b/-must).
PROSE = ("An event processor and background worker. Service With Cloud SQL. Service A and Service B must use a "
         "bastion jump host and Kubernetes. Two services named api and worker. No services yet, foundation only.")


# ------------------------------------------------------------------------------------------------- tombstones
@pytest.mark.parametrize("name", DELETED)
def test_tombstone_guessers_are_gone_from_terraform_engine(name):
    assert not hasattr(te, name)


def test_tombstone_no_developer_module_references_the_deleted_guessers():
    """AST check: no Name / Attribute / import of a deleted guesser anywhere in developer_agent/ (comments allowed)."""
    hits = []
    for root, _dirs, fnames in os.walk(DEV_DIR):
        for f in fnames:
            if not f.endswith(".py"):
                continue
            path = os.path.join(root, f)
            tree = ast.parse(open(path, encoding="utf-8").read(), filename=path)
            for node in ast.walk(tree):
                ident = None
                if isinstance(node, ast.Name):
                    ident = node.id
                elif isinstance(node, ast.Attribute):
                    ident = node.attr
                elif isinstance(node, ast.alias):
                    ident = node.name
                elif isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                    ident = node.name
                if ident in DELETED:
                    hits.append(f"{os.path.relpath(path, REPO_ROOT)}:{getattr(node, 'lineno', '?')}:{ident}")
    assert hits == []


def test_tombstone_package_exports_drop_the_archetype_guesser():
    import developer_agent
    assert "detect_compute_archetype" not in getattr(developer_agent, "__all__", [])


def test_tombstone_service_n_padding_is_gone():
    """HD-02 padded the service set with `service-2`, `service-3` ... to reach a count read from the spec."""
    src = open(os.path.join(DEV_DIR, "terraform_engine.py"), encoding="utf-8").read()
    assert 'f"service-{sec_idx}"' not in src and "sec_idx" not in src


# ------------------------------------------------------------------------------- typed archetype coverage matrix
FORMER_ARCHETYPES = ("cloudrun", "gce-bastion", "gke-autopilot", "event-worker", "foundation-only")


def test_typed_path_covers_every_archetype_the_keyword_detector_returned():
    assert set(FORMER_ARCHETYPES) == set(ci.ARCHETYPES)
    for arch in FORMER_ARCHETYPES:
        intent = ci.resolve_compute_intent("p", {"target_compute_services": ["p"], "compute_archetype": arch})
        assert intent.archetype == arch
        assert intent.archetype_source == "architect.compute_archetype"
    assert ci.resolve_compute_intent("p", {"target_compute_services": [], "compute_archetype": "foundation-only"}
                                     ).service_names == ()


def test_bundle_table_covers_exactly_the_architect_bundle_literals():
    ann = ArchitecturePlanDAG.model_fields["bundle_id"].annotation
    literal = [a for a in typing.get_args(ann) if typing.get_origin(a) is typing.Literal][0]
    assert set(typing.get_args(literal)) == set(ci.BUNDLE_PRIMARY_ARCHETYPE)
    assert set(ci.BUNDLE_PRIMARY_ARCHETYPE.values()) <= set(ci.ARCHETYPES)
    assert ci.resolve_compute_intent("p", {"bundle_id": "private-gke-microservices"}).archetype == "gke-autopilot"
    for b in ("secure-three-tier-web", "event-driven-microservice", "vertex-ai-rag-stack"):
        assert ci.resolve_compute_intent("p", {"bundle_id": b}).archetype == "cloudrun"


def test_compute_archetype_field_wins_over_bundle():
    rec = {"bundle_id": "private-gke-microservices", "compute_archetype": "event-worker"}
    assert ci.resolve_compute_intent("p", rec).archetype == "event-worker"


def test_unknown_bundle_falls_back_to_the_architect_contract_not_a_guess():
    rec = {"target_compute_services": ["api"], "bundle_id": "not-a-bundle"}
    intent = ci.resolve_compute_intent("p", rec)
    assert (intent.archetype, intent.archetype_source) == ("cloudrun", "architect.target_compute_services")


def test_unknown_compute_archetype_raises_never_defaults():
    # architect-compute-archetype: the field is an exact enum now; an unknown value is a typed error
    rec = {"target_compute_services": ["api"], "bundle_id": "not-a-bundle", "compute_archetype": "k8s"}
    with pytest.raises(ci.InvalidComputeIntentError):
        ci.resolve_compute_intent("p", rec)


def test_no_architect_record_and_no_repo_is_a_recorded_platform_default():
    intent = ci.resolve_compute_intent("my_app", None)
    assert (intent.archetype, intent.service_names, intent.source) == ("cloudrun", ("my-app",), "platform-default")


def test_resolver_signature_has_no_spec_text_input():
    import inspect
    assert "spec_text" not in inspect.signature(ci.resolve_compute_intent).parameters


# ----------------------------------------------------------------------------------------------- service names
def test_service_names_keep_the_architect_order_and_are_normalized_exactly():
    rec = {"target_compute_services": ["Public_Gateway", "internal-core", "public-gateway", " Worker "]}
    assert ci.resolve_compute_intent("p", rec).service_names == ("public-gateway", "internal-core", "worker")


def test_names_failing_the_service_name_grammar_are_rejected_and_recorded():
    rec = {"target_compute_services": ["Bad Name!", "9lives", "ok-svc", "x" * 64]}
    intent = ci.resolve_compute_intent("p", rec)
    assert intent.service_names == ("ok-svc",)
    assert set(intent.rejected_names) == {"Bad Name!", "9lives", "x" * 64}


def test_empty_architect_list_is_the_documented_single_service_default():
    assert ci.resolve_compute_intent("shop", {"target_compute_services": []}).service_names == ("shop",)


def test_explicit_request_list_overrides_the_record_names_only():
    rec = {"target_compute_services": ["a"], "bundle_id": "private-gke-microservices"}
    intent = ci.resolve_compute_intent("p", rec, target_compute_services=["x", "y"])
    assert intent.service_names == ("x", "y") and intent.archetype == "gke-autopilot"


# --------------------------------------------------------------------------------------- pinned existing compute
EXISTING = {
    W + "main.tf": 'module "compute" {\n  source       = "../modules/compute-event-worker"\n  product_id   = var.product_id\n}\n',
    W + "custom.tf": ('module "compute_api" {\n  source       = "../modules/compute-cloudrun"\n  service_name = "api"\n}\n'
                      'module "compute_cache" {\n  source = "../modules/cache-redis"\n}\n'),
}


def test_existing_primary_kind_and_secondaries_are_pinned_and_conflicts_recorded():
    intent = ci.resolve_compute_intent("p", {"target_compute_services": ["p", "web"]}, existing_files=EXISTING)
    assert intent.archetype == "event-worker" and intent.source == "existing-repo"
    assert intent.service_names == ("p", "web", "api")
    assert intent.existing_services == ("p", "api")
    assert intent.conflicts == ("archetype:architect.target_compute_services=cloudrun->existing=event-worker",)


def test_existing_cloud_run_primary_name_is_pinned_at_index_zero():
    files = {W + "main.tf": 'module "compute" {\n  source       = "../modules/compute-cloudrun"\n'
                            '  service_name = "storefront"\n}\n'}
    intent = ci.resolve_compute_intent("shop", {"target_compute_services": ["warehouse"]}, existing_files=files)
    assert intent.service_names == ("storefront", "warehouse")
    assert intent.conflicts == ("primary:architect=warehouse->existing=storefront",)


def test_existing_foundation_only_main_pins_nothing():
    files = {W + "main.tf": 'module "foundation" {\n  source = "../modules/workload-foundation/base"\n}\n'}
    intent = ci.resolve_compute_intent("p", {"target_compute_services": ["p"]}, existing_files=files)
    assert intent.source == "architect" and intent.archetype == "cloudrun" and intent.existing_services == ()


def test_module_source_must_resolve_to_a_golden_module_directory_exactly():
    files = {W + "main.tf": 'module "compute" {\n  source = "../modules/compute-cloudrun-fork"\n}\n',
             W + "custom.tf": 'module "compute_x" {\n  source = "git::https://example.invalid/compute-cloudrun"\n}\n'}
    ex = ci.existing_compute_from_repo(files, "p")
    assert ex.primary_kind is None and ex.secondaries == []


def test_module_source_must_resolve_under_infra_modules_not_any_parent():
    """RT M4: the golden directory basename is not enough; the source must resolve to `infra/modules/<dir>`."""
    files = {W + "main.tf": 'module "compute" {\n  source = "../other/compute-cloudrun"\n  service_name = "web"\n}\n',
             W + "custom.tf": 'module "compute_api" {\n  source = "./modules/compute-cloudrun"\n}\n'}
    ex = ci.existing_compute_from_repo(files, "p")
    assert ex.primary_kind is None and ex.primary_name is None and ex.secondaries == []
    # control: the same blocks with golden sources are recognized (the test is not vacuous)
    golden = {W + "main.tf": files[W + "main.tf"].replace('"../other/', '"../modules/'),
              W + "custom.tf": files[W + "custom.tf"].replace('"./modules/', '"../modules/')}
    ex = ci.existing_compute_from_repo(golden, "p")
    assert (ex.primary_kind, ex.primary_name, ex.secondaries) == ("cloudrun", "web", ["api"])


def test_unparseable_existing_file_is_reported_not_guessed():
    files = {W + "main.tf": 'module "compute" {\n  source = "../modules/compute-gke-autopilot"\n',  # unterminated
             W + "custom.tf": 'module "compute_api" {\n  source = "../modules/compute-cloudrun"\n}\n'}
    ex = ci.existing_compute_from_repo(files, "p")
    assert ex.unparsed == [W + "main.tf"] and ex.primary_kind is None and ex.secondaries == ["api"]


# --------------------------------------------------------------------------- reconcile with the typed service set
MAIN_CR = 'module "compute" {\n  source       = "../modules/compute-cloudrun"\n  service_name = var.product_id\n}\n'


def test_do_no_harm_single_service_draft_is_byte_identical_whatever_the_spec_says():
    custom = 'resource "google_pubsub_topic" "events" {\n  name = "events"\n}\n'
    for spec in ("", PROSE):
        files = {W + "main.tf": MAIN_CR, CUSTOM_TF: custom, "apps/shop/main.py": "x = 1\n"}
        before = dict(files)
        te.reconcile_multi_service_declarations(files=files, product_id="shop", spec_text=spec, archetype="cloudrun",
                                                assembly_record=AssemblyRecord(), llm_iac_paths=[CUSTOM_TF],
                                                target_services=["shop"])
        assert files == before, spec


def test_r3d_08_shape_no_phantom_services_from_prose():
    """08: the architect names one service (= product id); the prose "Service With ... Service Access" no longer
    creates `service-with` (primary), `service`, `service-access`."""
    files = {W + "main.tf": MAIN_CR, CUSTOM_TF: "", "apps/test-08-cloudsql-postgres/main.py": "x = 1\n"}
    te.reconcile_multi_service_declarations(
        files=files, product_id="test-08-cloudsql-postgres", spec_text="A Service With Cloud SQL. Service Access.",
        archetype="cloudrun", assembly_record=AssemblyRecord(), llm_iac_paths=[CUSTOM_TF],
        target_services=list(ci.resolve_compute_intent(
            "test-08-cloudsql-postgres", {"target_compute_services": ["test-08-cloudsql-postgres"],
                                          "bundle_id": "secure-three-tier-web"}).service_names))
    assert "module \"compute_" not in files[CUSTOM_TF]
    assert not any(k.startswith(("apps/service", "apps/service-with")) for k in files)


def test_r3d_02_shape_exactly_the_architect_services():
    files = {W + "main.tf": MAIN_CR, CUSTOM_TF: "", "apps/public-gateway/main.py": "x = 1\n",
             "apps/internal-core/main.py": "x = 1\n"}
    te.reconcile_multi_service_declarations(
        files=files, product_id="test-02-multi-cloudrun-mesh", spec_text="Service A and Service B must ...",
        archetype="cloudrun", assembly_record=AssemblyRecord(), llm_iac_paths=[CUSTOM_TF],
        target_services=["public-gateway", "internal-core"])
    custom = files[CUSTOM_TF]
    assert custom.count('module "compute_') == 1 and 'module "compute_internal_core"' in custom
    assert not any(k.startswith("apps/service-") for k in files)


def test_r3d_04_shape_gke_primary_workload_is_not_a_cloud_run_secondary():
    """04: GKE primary; the architect's single service names the workload the cluster runs, so no public Cloud Run
    `stream-processor` (and no `service-account` from the prose) is synthesized."""
    files = {W + "main.tf": 'module "compute" {\n  source = "../modules/compute-gke-autopilot"\n}\n', CUSTOM_TF: "",
             "apps/stream-processor/main.py": "x = 1\n"}
    te.reconcile_multi_service_declarations(
        files=files, product_id="test-04-gke-stream-processor", spec_text="Kubernetes Service Account ...",
        archetype="gke-autopilot", assembly_record=AssemblyRecord(), llm_iac_paths=[CUSTOM_TF],
        target_services=["stream-processor"])
    assert 'module "compute_' not in files[CUSTOM_TF]


def test_non_cloud_run_primary_keeps_named_cloud_run_secondaries():
    files = {W + "main.tf": 'module "compute" {\n  source = "../modules/compute-gke-autopilot"\n}\n', CUSTOM_TF: ""}
    te.reconcile_multi_service_declarations(
        files=files, product_id="fleet", spec_text="", archetype="gke-autopilot", assembly_record=AssemblyRecord(),
        llm_iac_paths=[CUSTOM_TF], target_services=["fleet", "edge-gateway"])
    assert files[CUSTOM_TF].count('module "compute_edge_gateway"') == 1


def test_no_padding_when_the_spec_says_three_services():
    files = {W + "main.tf": MAIN_CR, CUSTOM_TF: "", "apps/api/main.py": "x = 1\n"}
    te.reconcile_multi_service_declarations(files=files, product_id="shop", spec_text="Create three services",
                                            archetype="cloudrun", assembly_record=AssemblyRecord(),
                                            llm_iac_paths=[CUSTOM_TF], target_services=["api"])
    assert "service-2" not in files[CUSTOM_TF] and "service-3" not in files[CUSTOM_TF]


# ---------------------------------------------------------------------------------- architect record + handoff
def test_architect_llm_schema_carries_the_typed_compute_archetype():
    """The §5 prompt change (owner Q1, 10-13): the architect's LLM response schema carries `compute_archetype` as the
    resolver's exact enum (full coverage: tests/test_architect_compute_archetype.py)."""
    assert "compute_archetype" in ArchitecturePlanDAG.model_fields
    assert "compute_archetype" in ArchitecturePlanDAG.model_json_schema()["required"]


def test_compute_intent_record_copies_only_typed_fields():
    plan = ArchitecturePlan(product_id="p", target_compute_services=["a", "b"], bundle_id="secure-three-tier-web",
                            summary="ignored", architecture_overview="A bastion and a Kubernetes worker")
    rec = compute_intent_record(plan)
    assert rec == {"schema": COMPUTE_INTENT_RECORD_SCHEMA, "target_compute_services": ["a", "b"],
                   "bundle_id": "secure-three-tier-web", "compute_archetype": None}
    assert set(rec) - {"schema"} == set(ci.ARCHITECT_INTENT_FIELDS)
    assert "compute_intent" in ArchitectDecompositionResult.model_fields


def _dev():
    from developer_agent.handler import DeveloperAgent
    # no project id anywhere -> the constructor builds no Firestore / genai client (hermetic)
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GEMINI_API_KEY": ""}):
        return DeveloperAgent(project_id="")


def test_developer_reads_the_record_by_trace_id_when_the_request_has_none():
    dev = _dev()
    doc = MagicMock(exists=True)
    doc.to_dict.return_value = {"architect_compute_intent": {"target_compute_services": ["a"],
                                                             "bundle_id": "private-gke-microservices"}}
    dev.db = MagicMock()
    dev.db.collection.return_value.document.return_value.get.return_value = doc
    intent = dev._resolve_compute_intent("p", "trace-1", None, {}, None)
    dev.db.collection.assert_called_with("pipeline_executions")
    dev.db.collection.return_value.document.assert_called_with("trace-1")
    assert (intent.archetype, intent.service_names) == ("gke-autopilot", ("a",))
    assert dev.last_compute_intent["archetype_source"] == "architect.bundle_id:private-gke-microservices"


def test_request_record_wins_and_firestore_is_not_read():
    dev = _dev()
    dev.db = _RecordingDB()
    intent = dev._resolve_compute_intent("p", "trace-1", {"target_compute_services": ["x"]}, {}, None)
    assert dev.db.reads == []  # the request's record is used; Firestore is only written (RT fix 2 persistence)
    assert [w[:2] for w in dev.db.writes] == [("pipeline_executions", "trace-1")]
    assert intent.service_names == ("x",)


class _RecordingDB:
    """Firestore stand-in that records every (collection, document) read and write (no MagicMock chains, so a
    write to the wrong collection or document is visible)."""

    def __init__(self, docs=None, fail_reads=False, fail_writes=False):
        self.docs, self.fail_reads, self.fail_writes = dict(docs or {}), fail_reads, fail_writes
        self.reads, self.writes = [], []

    def collection(self, name):
        db = self

        class _Doc:
            def __init__(self, doc_id):
                self.doc_id = doc_id

            def get(self):
                db.reads.append((name, self.doc_id))
                if db.fail_reads:
                    raise RuntimeError("firestore down")
                data = db.docs.get((name, self.doc_id))
                return MagicMock(exists=data is not None, to_dict=MagicMock(return_value=data))

            def set(self, data, merge=False):
                if db.fail_writes:
                    raise RuntimeError("firestore write refused")
                db.writes.append((name, self.doc_id, data, merge))

        return MagicMock(document=_Doc)


def _assert_compute_intent_missing(exc_info, trace):
    from shared.diagnostics import ErrorClass, StageError
    err = exc_info.value
    assert isinstance(err, StageError) and err.error_class is ErrorClass.PLATFORM_DEFECT
    (diag,) = err.report.diagnostics
    assert diag.code == "PLATFORM.COMPUTE_INTENT_MISSING" and diag.error_class is ErrorClass.PLATFORM_DEFECT
    assert trace in diag.message and "architect_compute_intent" in diag.message
    assert "COMPUTE_INTENT_MISSING" in str(err)


def test_firestore_read_failure_with_a_trace_is_logged_and_fails_closed(caplog):
    """RT fix 2: a pipeline trace whose record cannot be read never becomes a silent Cloud Run default."""
    dev = _dev()
    dev.db = _RecordingDB(fail_reads=True)
    with pytest.raises(Exception) as exc_info:
        dev._resolve_compute_intent("p", "trace-1", None, {}, None)
    _assert_compute_intent_missing(exc_info, "trace-1")
    assert any("could not be read" in r.getMessage() for r in caplog.records)
    assert dev.db.writes == []


def test_trace_without_record_and_without_existing_compute_fails_closed_typed():
    dev = _dev()
    dev.db = _RecordingDB()  # the trace document exists nowhere
    with pytest.raises(Exception) as exc_info:
        dev._resolve_compute_intent("p", "resume-p-abc123", None, {}, None)
    _assert_compute_intent_missing(exc_info, "resume-p-abc123")
    assert dev.db.reads == [("pipeline_executions", "resume-p-abc123")] and dev.db.writes == []
    assert dev.last_compute_intent is None  # nothing recorded as if it had been used


def test_trace_without_firestore_client_and_without_record_fails_closed():
    dev = _dev()
    assert dev.db is None
    with pytest.raises(Exception) as exc_info:
        dev._resolve_compute_intent("p", "eval-01-r1", None, {}, None)
    _assert_compute_intent_missing(exc_info, "eval-01-r1")


def test_trace_less_caller_keeps_the_recorded_platform_default():
    dev = _dev()
    intent = dev._resolve_compute_intent("p", None, None, {}, None)
    assert (intent.source, intent.archetype, intent.service_names) == ("platform-default", "cloudrun", ("p",))
    assert dev.last_compute_intent == intent.as_record()


def test_trace_without_record_but_with_existing_compute_pins_and_does_not_fail():
    dev = _dev()
    dev.db = _RecordingDB()
    files = {W + "main.tf": 'module "compute" {\n  source = "../modules/compute-gke-autopilot"\n}\n'}
    intent = dev._resolve_compute_intent("p", "resume-p-1", None, files, None)
    assert (intent.source, intent.archetype) == ("existing-repo", "gke-autopilot")
    assert dev.db.writes == [("pipeline_executions", "resume-p-1", {"developer_compute_intent": intent.as_record()}, True)]


def test_resolved_intent_is_persisted_on_the_execution_record_with_merge():
    """RT fix 2 / FH-8: the record the developer used (source, conflicts, rejected names) is on the trace."""
    dev = _dev()
    rec = {"target_compute_services": ["stream-processor", "Bad Name!"], "bundle_id": "private-gke-microservices"}
    dev.db = _RecordingDB(docs={("pipeline_executions", "trace-9"): {"architect_compute_intent": rec}})
    intent = dev._resolve_compute_intent("p", "trace-9", None, {}, None)
    assert dev.db.writes == [("pipeline_executions", "trace-9", {"developer_compute_intent": intent.as_record()}, True)]
    persisted = dev.db.writes[0][2]["developer_compute_intent"]
    assert persisted["rejected_names"] == ["Bad Name!"] and persisted["archetype"] == "gke-autopilot"


def test_persist_failure_is_logged_and_the_run_keeps_the_typed_intent(caplog):
    dev = _dev()
    dev.db = _RecordingDB(fail_writes=True)
    intent = dev._resolve_compute_intent("p", "trace-2", {"target_compute_services": ["x"]}, {}, None)
    assert intent.service_names == ("x",)
    assert any("could not be persisted" in r.getMessage() for r in caplog.records)


def test_generate_code_files_end_to_end_prose_does_not_change_archetype_or_services():
    """01 + 08 shapes through the real developer path: event-processor / "Service With" prose, typed record says one
    Cloud Run service -> main.tf compute is the Cloud Run module with that service; no compute_* modules."""
    from _lane19_fake_genai import FakeGenaiClient, canned_workload_files
    pid = "test-01-event-router"
    dev = _dev()
    dev.genai_client = FakeGenaiClient(files=canned_workload_files(pid))
    no_project = {"PROJECT_ID": "", "GCP_PROJECT": "", "GOOGLE_CLOUD_PROJECT": ""}  # shared modules build no client
    with patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false", **no_project}), \
            patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no firestore in tests"))), \
            patch.object(dev, "fetch_existing_repo_files", return_value={}):
        files = dev.generate_code_files(
            product_id=pid, spec_text=PROSE, task_dag=[],
            architect_compute_intent={"target_compute_services": [pid], "bundle_id": "event-driven-microservice"}, allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False)
    main_tf = files["infra/workload/main.tf"]
    assert 'source                = "../modules/compute-cloudrun"' in main_tf
    assert "compute-event-worker" not in main_tf
    assert f'service_name          = "{pid}"' in main_tf
    assert 'module "compute_' not in files.get(CUSTOM_TF, "")
    assert not any(k.startswith("apps/service") for k in files)
    assert dev.last_compute_intent["service_names"] == [pid]


# ------------------------------------------- preflight coverage healer: the typed primary workload (HD-02 follow-up)


def _portal_plan_client():
    """Lane 10: a fake genai client whose architect answer carries a valid service topology (the deterministic
    fallback plan no longer passes the topology gate)."""
    plan = {"product_id": "portal", "summary": "s", "architecture_overview": "o", "infra_tasks": [], "code_tasks": [],
            "target_compute_services": ["portal"], "compute_archetype": "cloudrun", "iac_engine": "tofu",
            "service_topology": {"services": [{"name": "portal", "kind": "cloudrun"}], "primary_service": "portal",
                                 "edges": [], "resources": []}}
    client = MagicMock()
    client.models.generate_content.return_value = SimpleNamespace(text=json.dumps(plan), candidates=[],
                                                                  usage_metadata=None)
    return client


def test_architect_returns_and_persists_the_compute_intent_record_by_trace_id():
    from architect_agent.handler import ArchitectAgent
    fake_client = MagicMock()
    env = {"ENABLE_DUAL_ARCHITECT_CONSENSUS": "false", "PROJECT_ID": "", "GCP_PROJECT": "", "GOOGLE_CLOUD_PROJECT": "",
           "GEMINI_API_KEY": ""}
    with patch.dict(os.environ, env), \
            patch("google.genai.Client", MagicMock(side_effect=RuntimeError("no LLM in tests"))), \
            patch("google.cloud.firestore.Client", MagicMock(return_value=fake_client)):
        agent = ArchitectAgent(project_id="")
        agent.genai_client = _portal_plan_client()
        agent.model = None
        agent.project_id = "p"           # enables the trace persistence block; Firestore is the mock above
        result = agent.decompose(spec_text="Deploy a portal", product_id="portal", trace_id="trace-ci-1")
    v1 = compute_intent_record(result.architecture_plan)
    assert {k: result.compute_intent[k] for k in v1 if k != "schema"} == {k: v for k, v in v1.items() if k != "schema"}
    assert result.compute_intent["service_topology"]["service_names"] == ["portal"]   # lane 10: v2 record
    sets = fake_client.collection.return_value.document.return_value.set.call_args_list
    calls = [c for c in sets if c.args and "architect_compute_intent" in c.args[0]]
    assert len(calls) == 1 and calls[0].args[0]["architect_compute_intent"] == result.compute_intent
    assert calls[0].kwargs == {"merge": ["architect_compute_intent", "stages.architect.repair_events"]}  # RT14-30
    assert calls[0].args[0]["stages"] == {"architect": {"repair_events": []}}   # RT F4: no repair, events cleared
    # RT M7: the record lands exactly where the developer reads it (producer / consumer cannot drift)
    rec_db = _RecordingDB()
    with patch.dict(os.environ, env), \
            patch("google.genai.Client", MagicMock(side_effect=RuntimeError("no LLM in tests"))), \
            patch("google.cloud.firestore.Client", MagicMock(return_value=rec_db)):
        agent = ArchitectAgent(project_id="")
        agent.genai_client = _portal_plan_client()
        agent.model = None
        agent.project_id = "p"
        result = agent.decompose(spec_text="Deploy a portal", product_id="portal", trace_id="trace-ci-1")
    ci_writes = [w for w in rec_db.writes if "architect_compute_intent" in w[2]]
    assert [(w[0], w[1], w[3]) for w in ci_writes] == [("pipeline_executions", "trace-ci-1",
                                                        ["architect_compute_intent", "stages.architect.repair_events"])]
    dev = _dev()
    dev.db = _RecordingDB(docs={("pipeline_executions", "trace-ci-1"): ci_writes[0][2]})
    intent = dev._resolve_compute_intent("portal", "trace-ci-1", None, {}, None)
    assert intent.source == "architect.service_topology"   # lane 10: the v2 record's topology decides
    assert intent.service_names == ("portal",)
