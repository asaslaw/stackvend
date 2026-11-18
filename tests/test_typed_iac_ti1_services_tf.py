"""TI-1 (docs/planning/typed-iac-intent-plan.md §4): authors separated by file.

On typed-topology runs (`topology is not None`) the platform renders the secondary compute modules into its own
infra/workload/services.tf (PLATFORM_RENDERED, shared/artifact_ownership.py) instead of appending them to the AI's
custom.tf. Module addresses do not change. The services.tf keys are S1-A platform root keys, so an AI copy is an
exact recorded PLATFORM_ROOT_DECLARATION. A secondary that a repository file still in the tree already declares is
not rendered again (never duplicated). Legacy (v1 record) and single-service runs are unchanged. Hermetic."""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
TESTS = os.path.dirname(__file__)
for p in (GATEWAY, REPO_ROOT, TESTS):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    import hcl2  # noqa: E402
except ImportError:  # pragma: no cover - environment defect
    pytest.fail("python-hcl2 missing: install apps/orchestrator-gateway/requirements.txt or put eval/.deps on "
                "PYTHONPATH; this file is acceptance evidence and must not skip", pytrace=False)

from developer_agent import terraform_engine as te  # noqa: E402
from developer_agent.assembly import CUSTOM_TF, index_blocks  # noqa: E402
from shared.artifact_ownership import PLATFORM_RENDERED_FLOOR  # noqa: E402
from shared.diagnostics import AssemblyRecord, Diagnostic, ErrorClass  # noqa: E402
from shared.service_topology import validate_service_topology  # noqa: E402

W = "infra/workload/"
MAIN_TF = W + "main.tf"
SERVICES_TF = W + "services.tf"
PID = "shop"

BUCKET = ('resource "google_storage_bucket" "uploads" {\n  name     = "${var.product_id}-uploads"\n'
          '  location = var.region\n}\n')
AI_DUP_CORE = 'module "compute_core" {\n  source       = "../modules/compute-cloudrun"\n  service_name = "core"\n}\n'
REPO_CORE = ('module "compute_core" {\n  source          = "../modules/compute-cloudrun"\n  service_name    = "core"\n'
             '  container_image = "hand-written"\n}\n')
REPO_MAIN = 'module "compute" {\n  source       = "../modules/compute-cloudrun"\n  service_name = "api"\n}\n'


def vt_of(raw, pid=PID):
    vt, diags = validate_service_topology(raw, product_id=pid)
    assert vt is not None, [(d.code, d.message) for d in diags]
    return vt


def topo(services, primary, edges=()):
    return {"services": [{"name": n, "kind": k} for n, k in services], "primary_service": primary,
            "edges": [{"caller": a, "callee": b, "protocol": p} for a, b, p in edges], "resources": []}


THREE = topo([("api", "cloudrun"), ("core", "cloudrun"), ("store", "cloudrun")], "api",
             [("api", "core", "http"), ("core", "store", "http")])


def record_of(raw, pid=PID):
    vt = vt_of(raw, pid)
    return {"schema": "architect_compute_intent/v2", "target_compute_services": list(vt.names),
            "bundle_id": None, "compute_archetype": vt.archetype, "service_topology": vt.as_record()}


def module_labels(text):
    return [b.labels[0] for b in (index_blocks(text or "") or []) if b.kind == "module"]


def root_declarations(files):
    """[(address, file)] of every module/resource block of the root module (exact parse)."""
    out = []
    for p, t in sorted(files.items()):
        if p.startswith(W) and p.endswith(".tf") and "/" not in p[len(W):]:
            blocks = index_blocks(t)
            assert blocks is not None, f"{p} does not parse"
            out += [(b.key, p) for b in blocks if b.kind in ("module", "resource")]
    return out


def drafts(custom=None, extra=None):
    from _lane19_fake_genai import canned_workload_files
    files = canned_workload_files("api", extra={**canned_workload_files("core"), **canned_workload_files("store")})
    if custom is not None:
        files[CUSTOM_TF] = custom
    files.update(extra or {})
    return files


def generate(draft, rec=None, existing=None, targets=None, trace="t-ti1"):
    """The developer's real assembly path (S1-A assembly, HB-04, golden renders, healers, gatekeeper)."""
    from _lane19_fake_genai import FakeGenaiClient
    from developer_agent.handler import DeveloperAgent
    with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GEMINI_API_KEY": ""}):
        dev = DeveloperAgent(project_id="")
    dev.genai_client = FakeGenaiClient(files=draft)
    env = {"ENABLE_DEVELOPER_SWARM": "false", "PROJECT_ID": "", "GCP_PROJECT": "", "GOOGLE_CLOUD_PROJECT": ""}
    with patch.dict(os.environ, env), \
            patch("google.cloud.firestore.Client", MagicMock(side_effect=RuntimeError("no firestore in tests"))), \
            patch.object(dev, "fetch_existing_repo_files", return_value=dict(existing or {})):
        files = dev.generate_code_files(product_id=PID, spec_text="three services", task_dag=[], trace_id=trace,
                                        architect_compute_intent=rec, target_compute_services=targets,
                                        # FD-4R R-6: the developer always gets the compliance decision
                                        allow_unauthenticated=True, enable_direct_iap=False,
                                        domain_restricted_sharing=False)
    return files, dev.stack_run(trace).get("assembly_record")


# ------------------------------------------------------------------------------------------------ main behavior
def test_three_service_topology_renders_the_two_secondaries_into_services_tf_and_none_into_custom_tf():
    files, record = generate(drafts(custom=BUCKET + "\n" + AI_DUP_CORE), rec=record_of(THREE))
    assert SERVICES_TF in PLATFORM_RENDERED_FLOOR
    assert module_labels(files[SERVICES_TF]) == ["compute_core", "compute_store"]
    assert files[SERVICES_TF].startswith(te.SERVICES_TF_HEADER + "\n\n")
    # custom.tf holds only the AI's own block: 0 platform blocks
    assert [b.key for b in index_blocks(files[CUSTOM_TF])] == ["google_storage_bucket.uploads"]
    # module addresses unchanged (same set as the legacy layout), each declared exactly once
    decls = root_declarations(files)
    mods = sorted(a for a, _ in decls if a.startswith("module."))
    assert mods == ["module.compute", "module.compute_core", "module.compute_store", "module.foundation"]
    assert len(decls) == len(set(a for a, _ in decls))
    # the AI's copy of a platform secondary is an exact recorded root declaration (was PLATFORM_RESYNTHESIZED)
    assert record.replaced_reason["module.compute_core"] == "PLATFORM_ROOT_DECLARATION"
    assert record.replaced_from["module.compute_core"] == CUSTOM_TF
    # wiring is unchanged: the primary calls core, core calls store
    assert "module.compute_core.service_uri" in files[MAIN_TF]
    core = hcl2.loads(files[SERVICES_TF])["module"][0]["compute_core"]
    assert "module.compute_store.service_uri" in str(core["env_vars"])


def test_root_keys_equal_the_rendered_services_tf_labels():
    """The keys handler.py adds to S1-A's root keys are exactly the labels HB-04 renders (cloudrun + workers)."""
    vt = vt_of(topo([("api", "cloudrun"), ("core", "cloudrun"), ("etl", "event-worker")], "api",
                    [("api", "etl", "pubsub")]))
    files = {CUSTOM_TF: BUCKET, "apps/api/main.py": "x = 1\n", "apps/core/main.py": "x = 1\n",
             "apps/etl/main.py": "x = 1\n"}
    te.reconcile_multi_service_declarations(files=files, product_id=PID, spec_text="", archetype=vt.archetype,
                                            assembly_record=AssemblyRecord(), llm_iac_paths=[CUSTOM_TF],
                                            target_services=list(vt.names), topology=vt)
    rendered = {f"module.{label}" for label in module_labels(files[SERVICES_TF])}
    assert rendered == te.services_tf_root_keys(vt) == {"module.compute_core", "module.compute_etl"}
    assert files[CUSTOM_TF] == BUCKET
    assert te.services_tf_root_keys(vt, frozenset({"module.compute_core"})) == {"module.compute_etl"}
    assert te.services_tf_root_keys(None) == set()


def test_ai_drafted_services_tf_is_relocated_and_the_platform_render_replaces_it():
    """An AI services.tf is S1-A relocated into custom.tf (unchanged); its copy of a secondary is a recorded root
    declaration; the platform file holds only the platform's render."""
    ai_services = BUCKET + "\n" + AI_DUP_CORE.replace("compute_core", "compute_store").replace('"core"', '"store"')
    files, record = generate(drafts(extra={SERVICES_TF: ai_services}), rec=record_of(THREE), trace="t-ai-svc")
    assert module_labels(files[SERVICES_TF]) == ["compute_core", "compute_store"]
    assert "google_storage_bucket.uploads" in {b.key for b in index_blocks(files[CUSTOM_TF])}
    assert not any(label.startswith("compute") for label in module_labels(files[CUSTOM_TF]))
    assert record.replaced_reason["module.compute_store"] == "PLATFORM_ROOT_DECLARATION"


def test_regeneration_re_renders_services_tf_byte_identically():
    """A prior TI-1 services.tf in the repository is the platform's own render: re-rendered, never kept or
    appended to, and never an input of the env wiring."""
    first, _ = generate(drafts(custom=BUCKET), rec=record_of(THREE), trace="t-gen1")
    existing = {p: t for p, t in first.items() if p.startswith(W) and p.endswith(".tf")}
    second, record = generate(drafts(custom=BUCKET), rec=record_of(THREE), existing=existing, trace="t-gen2")
    assert second[SERVICES_TF] == first[SERVICES_TF]
    assert second[CUSTOM_TF] == first[CUSTOM_TF] and second[MAIN_TF] == first[MAIN_TF]
    assert len(root_declarations(second)) == len(set(a for a, _ in root_declarations(second)))


def test_stale_services_tf_is_replaced_whole_and_not_read_by_the_wiring():
    vt = vt_of(THREE)
    stale = ('resource "google_storage_bucket" "stale" {\n  name = "s"\n  location = "US"\n}\n'
             'module "compute_core" {\n  source = "../modules/compute-cloudrun"\n  service_name = "core"\n}\n')
    files = {CUSTOM_TF: BUCKET, SERVICES_TF: stale, "apps/core/main.py": "x = 1\n", "apps/store/main.py": "x = 1\n"}
    te.reconcile_multi_service_declarations(files=files, product_id=PID, spec_text="", archetype=vt.archetype,
                                            assembly_record=AssemblyRecord(), llm_iac_paths=[CUSTOM_TF],
                                            target_services=list(vt.names), topology=vt)
    assert module_labels(files[SERVICES_TF]) == ["compute_core", "compute_store"]
    assert "stale" not in files[SERVICES_TF]
    fresh = {CUSTOM_TF: BUCKET, "apps/core/main.py": "x = 1\n", "apps/store/main.py": "x = 1\n"}
    te.reconcile_multi_service_declarations(files=fresh, product_id=PID, spec_text="", archetype=vt.archetype,
                                            assembly_record=AssemblyRecord(), llm_iac_paths=[CUSTOM_TF],
                                            target_services=list(vt.names), topology=vt)
    assert files[SERVICES_TF] == fresh[SERVICES_TF]


# ------------------------------------------------------------------------------------------------ brownfield
def test_brownfield_compute_core_in_the_repository_custom_tf_is_not_duplicated():
    """Repo custom.tf (kept as the head: the AI wrote none this run) declares module.compute_core: it is neither a
    root key nor rendered into services.tf; the existing in-place resynthesis of a key in an LLM-tracked file is
    unchanged (PLATFORM_RESYNTHESIZED)."""
    existing = {MAIN_TF: REPO_MAIN, CUSTOM_TF: REPO_CORE}
    files, record = generate(drafts(), rec=record_of(THREE), existing=existing, trace="t-brown")
    assert module_labels(files[SERVICES_TF]) == ["compute_store"]
    assert module_labels(files[CUSTOM_TF]) == ["compute_core"]
    decls = [a for a, _ in root_declarations(files)]
    assert decls.count("module.compute_core") == 1 and decls.count("module.compute_store") == 1
    assert record.replaced_reason.get("module.compute_core") == "PLATFORM_RESYNTHESIZED"


def test_brownfield_compute_core_in_another_repository_file_is_kept_byte_identical_and_not_duplicated():
    hand = W + "compute.tf"
    existing = {MAIN_TF: REPO_MAIN, hand: REPO_CORE}
    files, _ = generate(drafts(custom=BUCKET), rec=record_of(THREE), existing=existing, trace="t-brown2")
    assert files[hand] == REPO_CORE
    assert module_labels(files[SERVICES_TF]) == ["compute_store"]
    assert [b.key for b in index_blocks(files[CUSTOM_TF])] == ["google_storage_bucket.uploads"]
    decls = [a for a, _ in root_declarations(files)]
    assert decls.count("module.compute_core") == 1


def test_skip_addresses_are_exact_root_addresses_of_kept_repository_files():
    nested = {W + "custom.tf": 'module "bundle" {\n  source = "../bundles/b"\n}\n',
              "infra/bundles/b/main.tf": 'module "compute_core" {\n  source = "../modules/compute-cloudrun"\n}\n'}
    assert te.services_tf_skip_addresses(dict(nested), nested) == frozenset()      # nested: not the root address
    repo = {W + "compute.tf": REPO_CORE, SERVICES_TF: AI_DUP_CORE.replace("core", "store")}
    assert te.services_tf_skip_addresses(dict(repo), repo) == frozenset({"module.compute_core"})   # services.tf: own
    assert te.services_tf_skip_addresses({W + "compute.tf": BUCKET}, repo) == frozenset()          # not kept
    assert te.services_tf_skip_addresses({}, None) == frozenset()


# ------------------------------------------------------------------------------------------------ Do No Harm
def test_dnh_single_service_topology_writes_no_services_tf_and_leaves_custom_tf_byte_identical():
    vt = vt_of(topo([("shop", "cloudrun")], "shop"))
    files = {CUSTOM_TF: BUCKET, "apps/shop/main.py": "x = 1\n"}
    before = dict(files)
    te.reconcile_multi_service_declarations(files=files, product_id=PID, spec_text="", archetype=vt.archetype,
                                            assembly_record=AssemblyRecord(), llm_iac_paths=[CUSTOM_TF],
                                            target_services=list(vt.names), topology=vt,
                                            services_tf_skip=frozenset())
    assert files == before
    from _lane19_fake_genai import canned_workload_files
    out, _ = generate({**canned_workload_files("shop"), CUSTOM_TF: BUCKET}, rec=record_of(topo([("shop", "cloudrun")],
                                                                                                "shop")), trace="t-one")
    assert SERVICES_TF not in out and out[CUSTOM_TF] == BUCKET


def test_dnh_legacy_v1_path_appends_to_custom_tf_and_writes_no_services_tf():
    legacy = {CUSTOM_TF: BUCKET, "apps/api/main.py": "x = 1\n", "apps/core/main.py": "x = 1\n"}
    te.reconcile_multi_service_declarations(files=legacy, product_id=PID, spec_text="", archetype="cloudrun",
                                            assembly_record=AssemblyRecord(), llm_iac_paths=[CUSTOM_TF],
                                            target_services=["api", "core"],
                                            services_tf_skip=frozenset({"module.compute_core"}))   # ignored
    assert SERVICES_TF not in legacy
    assert legacy[CUSTOM_TF].startswith(BUCKET.rstrip("\n")) and module_labels(legacy[CUSTOM_TF]) == ["compute_core"]
    files, record = generate(drafts(custom=BUCKET), targets=["api", "core", "store"], trace="t-v1")
    assert SERVICES_TF not in files
    assert module_labels(files[CUSTOM_TF]) == ["compute_core", "compute_store"]


# ------------------------------------------------------------------------------------------------ routing / twin
def _router(tree, llm_paths):
    from developer_agent.repair_loop import Assembled, LoopContext, Router
    from developer_agent.validators.base import ValidatorStack
    from shared.diagnostics import MemoryLedgerStore
    from shared.hallucination_stack import HallucinationStackSettings
    ctx = LoopContext(trace_id="t", product_id=PID, assemble=lambda d: None, stack=ValidatorStack(),
                      ledger_store=MemoryLedgerStore(), settings=HallucinationStackSettings(),
                      attribution={p: "backend_worker" for p in llm_paths}, llm_draft_paths=set(llm_paths),
                      preexisting=set())
    return Router(ctx, {p: tree[p] for p in llm_paths}, Assembled(tree=tree, record=AssemblyRecord(),
                                                                   assembled_root={}))


def test_a_diagnostic_in_services_tf_routes_as_platform_defect():
    files, _ = generate(drafts(custom=BUCKET), rec=record_of(THREE), trace="t-route")
    router = _router(files, [CUSTOM_TF, "apps/core/main.py"])
    d = Diagnostic(tool="tofu", code="TF.REFERENCE_TO_UNDECLARED_RESOURCE", severity="error", file=SERVICES_TF,
                   line=25, block_address="module.compute_core", message="m", source="precommit")
    assert router.route(d).error_class is ErrorClass.PLATFORM_DEFECT
    # negative: a finding on the AI's own block in custom.tf still goes to its persona
    ai = Diagnostic(tool="tofu", code="TF.UNSUPPORTED_ATTRIBUTE", severity="error", file=CUSTOM_TF, line=1,
                    block_address="google_storage_bucket.uploads", message="m", source="precommit")
    assert router.route(ai).error_class is ErrorClass.CODE_DEFECT


@pytest.mark.xfail(strict=True, reason="Fable plan RT F1 'add services.tf to the rendered set': repair_loop.Router "
                   "derives `rendered` as tree - authored - preexisting, so an AI-DRAFTED services.tf (0 of ~80 "
                   "recorded drafts) makes the platform file LLM_AUTHORED. Same pre-existing gap as main/variables/"
                   "outputs/moved.tf; the fix is a Router change outside TI-1's files (reported, not made).")
def test_rt_f1_gap_a_diagnostic_in_services_tf_is_platform_defect_even_when_the_ai_drafted_one():
    files, _ = generate(drafts(custom=BUCKET), rec=record_of(THREE), trace="t-route-gap")
    router = _router(files, [CUSTOM_TF, SERVICES_TF])
    d = Diagnostic(tool="tofu", code="TF.REFERENCE_TO_UNDECLARED_RESOURCE", severity="error", file=SERVICES_TF,
                   line=25, block_address="module.compute_core", message="m", source="precommit")
    assert router.route(d).error_class is ErrorClass.PLATFORM_DEFECT


def test_verifier_twin_is_a_no_op_on_a_ti1_tree():
    from gatekeeper_agent.verifier import SynthesisVerifierAgent
    files, _ = generate(drafts(custom=BUCKET), rec=record_of(THREE), trace="t-twin")
    assert SynthesisVerifierAgent(product_id=PID).reconcile_iac_environment_contracts(dict(files)) == files
