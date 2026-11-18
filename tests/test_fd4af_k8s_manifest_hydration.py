"""FD-4AF (FD22-11): k8s manifest hydration substitutes explicit placeholders only.

Before: every `image:` not starting with `us-central1-docker.pkg.dev/` or `gcr.io/` was rewritten to
`us-central1-docker.pkg.dev/<product_id>/<product_id>/<tag>:latest`, `${PROJECT_ID}` became the product ID (child
project IDs carry a uuid suffix), and Workload Identity annotations were rewritten to `@<product_id>.iam...`.
Now: only the exact tokens of `K8S_MANIFEST_PLACEHOLDERS` are substituted, with the vended project and the platform
region; everything else is byte-identical; an unknown or unavailable placeholder is a typed error.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(ROOT, "apps", "orchestrator-gateway")
if GATEWAY not in sys.path:
    sys.path.insert(0, GATEWAY)

from developer_agent.preflight_validator import (  # noqa: E402
    K8S_MANIFEST_PLACEHOLDERS,
    ManifestHydrationError,
    hydrate_kubernetes_manifests,
    is_kubernetes_manifest_path,
)

PROJECT = "shop-a1b2c3"
REGION = "europe-west1"

# The FD22-11 probe manifest (docs/planning/review/probes/fd22-gatekeeper-preflight-qa_preflight.py section 1).
PROBE_MANIFEST = (
    "apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n"
    "      serviceAccountName: api-ksa\n"
    "      containers:\n"
    "        - name: cache\n          image: redis:7.2\n"
    "        - name: api\n          image: europe-west1-docker.pkg.dev/shop-a1b2c3/shop/api:v1\n"
    "---\napiVersion: v1\nkind: ServiceAccount\nmetadata:\n  annotations:\n"
    "    iam.gke.io/gcp-service-account: api-gsa@shop-a1b2c3.iam.gserviceaccount.com\n"
)

CONCRETE_IMAGES = (
    "redis:7.2",
    "ghcr.io/org/tool:1.4.0",
    "europe-west1-docker.pkg.dev/shop-a1b2c3/shop/api:v1",
    "us-central1-docker.pkg.dev/other-proj/repo/app@sha256:" + "a" * 64,
    "gcr.io/google-samples/hello-app:1.0",
    "stream-apps/stream-worker:latest",
    "nginx",
)


def _deployment(image: str, extra_env: str = "") -> str:
    return (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\nspec:\n  template:\n    spec:\n"
        "      initContainers:\n      - name: migrate\n        image: busybox:1.36\n"
        "      containers:\n      - name: api\n"
        f"        image: {image}\n"
        "        env:\n        - name: PROJECT\n          value: \"literal\"\n" + extra_env
    )


def _never_called():
    raise AssertionError("the region setting must not be read when no manifest uses ${REGION}/${ARTIFACT_REGISTRY}")


# ------------------------------------------------------------------------------------------- Do No Harm (negative)
def test_probe_manifest_is_byte_identical():
    files = {"k8s/deploy.yaml": PROBE_MANIFEST}
    out, actions = hydrate_kubernetes_manifests(files, product_id="shop", project_id=PROJECT, region=_never_called)
    assert out == files
    assert out["k8s/deploy.yaml"] is PROBE_MANIFEST
    assert actions == []


@pytest.mark.parametrize("image", CONCRETE_IMAGES)
def test_concrete_images_pass_through_unchanged(image):
    text = _deployment(image)
    out, actions = hydrate_kubernetes_manifests({"k8s/d.yaml": text}, product_id="shop",
                                                project_id=PROJECT, region=_never_called)
    assert out["k8s/d.yaml"] == text
    assert actions == []


def test_concrete_images_unchanged_even_without_project_or_region():
    text = _deployment("redis:7.2")
    out, actions = hydrate_kubernetes_manifests({"k8s/d.yaml": text}, product_id="shop")
    assert out["k8s/d.yaml"] == text and actions == []


@pytest.mark.parametrize("sa", [
    "api-gsa@shop-a1b2c3.iam.gserviceaccount.com",
    "123456789-compute@developer.gserviceaccount.com",
    "api-gsa",
])
def test_workload_identity_annotation_is_never_rewritten(sa):
    text = ("apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: api-ksa\n  annotations:\n"
            f"    iam.gke.io/gcp-service-account: {sa}\n")
    out, actions = hydrate_kubernetes_manifests({"k8s/sa.yaml": text}, product_id="shop", project_id=PROJECT)
    assert out["k8s/sa.yaml"] == text and actions == []


def test_non_manifest_files_untouched_even_with_placeholders():
    files = {
        "apps/k8sproxy/config.yaml": "image: ${PROJECT_ID}/x\n",       # substring "k8s", not a k8s/ segment
        "k8s-notes.yaml": "value: ${PROJECT_ID}\n",
        "infra/workload/k8s_manifests.tf": 'image = "${PROJECT_ID}"\n',
        "k8s/README.md": "use ${PROJECT_ID}\n",
        ".github/workflows/deploy.yml": "run: echo ${PROJECT_ID}\n",
    }
    out, actions = hydrate_kubernetes_manifests(dict(files), product_id="shop", project_id=PROJECT,
                                                region=_never_called)
    assert out == files and actions == []


def test_similar_tokens_are_not_substituted():
    extra = ("        - name: A\n          value: \"${PROJECT_ID_SUFFIX}\"\n"
             "        - name: B\n          value: \"$PROJECT_ID\"\n"
             "        - name: C\n          value: \"$(PROJECT_ID)\"\n")
    text = _deployment("redis:7.2", extra)
    out, actions = hydrate_kubernetes_manifests({"k8s/d.yaml": text}, product_id="shop", project_id=PROJECT)
    assert out["k8s/d.yaml"] == text and actions == []


def test_unparseable_yaml_without_placeholders_is_unchanged():
    text = "apiVersion: v1\nkind: [unclosed\n  image: redis:7.2\n"
    out, actions = hydrate_kubernetes_manifests({"k8s/bad.yaml": text}, product_id="shop", project_id=PROJECT)
    assert out["k8s/bad.yaml"] == text and actions == []


# ------------------------------------------------------------------------------------------ explicit placeholders
def test_placeholders_use_real_project_and_region():
    deploy = _deployment("${ARTIFACT_REGISTRY}/api:latest",
                         "        - name: GCP_PROJECT\n          value: ${PROJECT_ID}\n"
                         "        - name: GCP_REGION\n          value: ${REGION}\n"
                         "        - name: SVC\n          value: ${SERVICE_NAME}-${PRODUCT_ID}\n")
    sa = ("apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  name: api-ksa\n  annotations:\n"
          "    iam.gke.io/gcp-service-account: api-gsa@${PROJECT_ID}.iam.gserviceaccount.com\n")
    calls = []

    def region():
        calls.append(1)
        return REGION

    out, actions = hydrate_kubernetes_manifests({"k8s/deploy.yaml": deploy, "infra/workload/k8s/sa.yaml": sa},
                                                product_id="shop", project_id=PROJECT, region=region)
    d = out["k8s/deploy.yaml"]
    assert f"image: {REGION}-docker.pkg.dev/{PROJECT}/shop/api:latest" in d
    assert f"value: {PROJECT}\n" in d and f"value: {REGION}\n" in d and "value: shop-shop\n" in d
    assert "image: busybox:1.36" in d                      # the concrete init image is untouched
    assert "us-central1" not in d
    assert f"api-gsa@{PROJECT}.iam.gserviceaccount.com" in out["infra/workload/k8s/sa.yaml"]
    assert "$" not in d and "$" not in out["infra/workload/k8s/sa.yaml"]
    assert len(calls) == 1                                  # resolved once, on demand
    assert actions and all(a.startswith("Substituted ${") for a in actions)
    # only the placeholder tokens changed: removing them from both texts gives the same skeleton
    assert d.replace(f"{REGION}-docker.pkg.dev/{PROJECT}/shop", "${ARTIFACT_REGISTRY}") \
        .replace(f"value: {PROJECT}\n", "value: ${PROJECT_ID}\n").replace(f"value: {REGION}\n", "value: ${REGION}\n") \
        .replace("value: shop-shop\n", "value: ${SERVICE_NAME}-${PRODUCT_ID}\n") == deploy


def test_product_id_is_never_used_as_project_id():
    text = _deployment("redis:7.2", "        - name: P\n          value: ${PROJECT_ID}\n")
    out, _ = hydrate_kubernetes_manifests({"k8s/d.yaml": text}, product_id="shop", project_id=PROJECT)
    assert f"value: {PROJECT}\n" in out["k8s/d.yaml"]
    assert "value: shop\n" not in out["k8s/d.yaml"]


def test_placeholder_set_is_exactly_documented():
    assert K8S_MANIFEST_PLACEHOLDERS == ("PROJECT_ID", "PRODUCT_ID", "REGION", "SERVICE_NAME", "ARTIFACT_REGISTRY")


# ------------------------------------------------------------------------------------------------- typed errors
@pytest.mark.parametrize("token", ["${PROJECT_ID}", "${ARTIFACT_REGISTRY}"])
def test_missing_project_is_typed_error(token):
    text = _deployment(f"{token}/api:latest")
    with pytest.raises(ManifestHydrationError) as ei:
        hydrate_kubernetes_manifests({"k8s/d.yaml": text}, product_id="shop", project_id="", region=REGION)
    assert ei.value.code == "K8S.PLACEHOLDER_VALUE_UNAVAILABLE"


@pytest.mark.parametrize("region", ["", lambda: ""])
def test_missing_region_is_typed_error(region):
    text = _deployment("${ARTIFACT_REGISTRY}/api:latest")
    with pytest.raises(ManifestHydrationError) as ei:
        hydrate_kubernetes_manifests({"k8s/d.yaml": text}, product_id="shop", project_id=PROJECT, region=region)
    assert ei.value.code == "K8S.PLACEHOLDER_VALUE_UNAVAILABLE"


@pytest.mark.parametrize("image", ["${IMAGE}", "gcr.io/$PROJECT_ID/api:latest", "${ARTIFACT_REPO}/api:1"])
def test_unknown_image_placeholder_is_typed_error(image):
    text = _deployment(image)
    with pytest.raises(ManifestHydrationError) as ei:
        hydrate_kubernetes_manifests({"k8s/d.yaml": text}, product_id="shop", project_id=PROJECT, region=REGION)
    assert ei.value.code == "K8S.PLACEHOLDER_UNRESOLVED"


def test_unresolved_workload_identity_annotation_is_typed_error():
    text = ("apiVersion: v1\nkind: ServiceAccount\nmetadata:\n  annotations:\n"
            "    iam.gke.io/gcp-service-account: api-gsa@$PROJECT_ID.iam.gserviceaccount.com\n")
    with pytest.raises(ManifestHydrationError) as ei:
        hydrate_kubernetes_manifests({"k8s/sa.yaml": text}, product_id="shop", project_id=PROJECT)
    assert ei.value.code == "K8S.PLACEHOLDER_UNRESOLVED"


def test_manifest_path_rule():
    assert is_kubernetes_manifest_path("k8s/deployment.yaml")
    assert is_kubernetes_manifest_path("k8s/overlays/prod/x.yml")
    assert is_kubernetes_manifest_path("infra/workload/k8s/sa.yaml")
    assert not is_kubernetes_manifest_path("apps/k8sproxy/config.yaml")
    assert not is_kubernetes_manifest_path("k8s.yaml")
    assert not is_kubernetes_manifest_path("k8s/notes.md")


# ------------------------------------------------------------------------------------------------ handler wiring
def test_handler_platform_region_reads_the_setting(monkeypatch):
    import types

    import shared.settings as settings_mod
    from developer_agent.handler import DeveloperAgent

    fake = types.SimpleNamespace(orchestration=types.SimpleNamespace(default_gcp_region="asia-south1"))
    monkeypatch.setattr(settings_mod, "get_platform_settings", lambda **_kw: fake)
    agent = DeveloperAgent.__new__(DeveloperAgent)
    agent.project_id = ""
    assert agent._platform_region() == "asia-south1"

    # an unusable settings OBJECT (no orchestration section) gives "" -> the placeholder is unavailable
    monkeypatch.setattr(settings_mod, "get_platform_settings", lambda **_kw: types.SimpleNamespace())
    assert agent._platform_region() == ""


def test_handler_platform_region_unreadable_store_is_unavailable_not_the_schema_default(monkeypatch):
    """RT F2, closed by FD-4AK (RT F6): the region read is strict. An unreadable settings document is a typed
    PlatformSettingsReadError, so the region is "" (a manifest using ${REGION} / ${ARTIFACT_REGISTRY} then stops with
    K8S.PLACEHOLDER_VALUE_UNAVAILABLE), never the compile-time default region. A missing document (fresh install) is
    still the schema default."""
    import shared.settings as settings_mod
    from developer_agent.handler import DeveloperAgent

    for name, value in (("_SETTINGS_CACHE", None), ("_LAST_FETCH_TIME", 0.0), ("_LAST_FAILURE", None),
                        ("_LAST_FAILURE_TIME", 0.0)):
        monkeypatch.setattr(settings_mod, name, value)
    agent = DeveloperAgent.__new__(DeveloperAgent)
    agent.project_id = "mock-stackvend-project"
    with patch("google.cloud.firestore.Client", side_effect=RuntimeError("Firestore unreachable")):
        assert agent._platform_region() == ""
    monkeypatch.setattr(settings_mod, "_LAST_FAILURE", None)
    absent = MagicMock()
    absent.exists = False
    client = MagicMock()
    client.collection.return_value.document.return_value.get.return_value = absent
    with patch("google.cloud.firestore.Client", return_value=client):
        assert agent._platform_region() == settings_mod.OrchestrationSettings().default_gcp_region
    settings_mod.invalidate_settings_cache()


def test_raising_region_resolver_is_typed_unavailable():
    """RT F5: a zero-argument region resolver that raises is an unavailable value (typed), not a raw exception."""
    def broken():
        raise RuntimeError("settings exploded")

    text = _deployment("${ARTIFACT_REGISTRY}/api:latest")
    with pytest.raises(ManifestHydrationError) as ei:
        hydrate_kubernetes_manifests({"k8s/d.yaml": text}, product_id="shop", project_id=PROJECT, region=broken)
    assert ei.value.code == "K8S.PLACEHOLDER_VALUE_UNAVAILABLE"
    assert ei.value.path == "k8s/d.yaml" and ei.value.unavailable == "region"


def test_error_carries_path_and_missing_value():
    with pytest.raises(ManifestHydrationError) as ei:
        hydrate_kubernetes_manifests({"k8s/d.yaml": _deployment("${PROJECT_ID}/x:1")}, product_id="shop")
    assert ei.value.path == "k8s/d.yaml" and ei.value.unavailable == "project_id"
    with pytest.raises(ManifestHydrationError) as ei:
        hydrate_kubernetes_manifests({"k8s/e.yaml": _deployment("${IMAGE}")}, product_id="shop", project_id=PROJECT)
    assert ei.value.path == "k8s/e.yaml" and ei.value.unavailable == ""


# ------------------------------------------------------------------------------- end to end through the handler (F1)
def _s1b():
    pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")
    tests_dir = os.path.dirname(__file__)
    if tests_dir not in sys.path:
        sys.path.insert(0, tests_dir)
    import test_step1_s1b_generation as s1b
    return s1b


def _typed_failure_of_eval(e):
    eval_dir = os.path.join(ROOT, "eval")
    if eval_dir not in sys.path:
        sys.path.insert(0, eval_dir)
    from stackvend_eval import stages as st
    return st._typed_failure(e)


K8S_UNRESOLVED = ("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: shop\nspec:\n  template:\n    spec:\n"
                  "      containers:\n      - name: shop\n        image: ${IMAGE}\n")
K8S_NEEDS_PROJECT = K8S_UNRESOLVED.replace("${IMAGE}", "${ARTIFACT_REGISTRY}/shop:latest")


@pytest.mark.parametrize("manifest,code,status,error_class,tools_unavailable", [
    (K8S_UNRESOLVED, "K8S.PLACEHOLDER_UNRESOLVED", "FAIL", "CODE_DEFECT", []),
    (K8S_NEEDS_PROJECT, "K8S.PLACEHOLDER_VALUE_UNAVAILABLE", "UNAVAILABLE", "GATE_UNAVAILABLE", ["workload_record"]),
])
def test_e2e_hydration_error_is_a_recorded_typed_stage_error(manifest, code, status, error_class, tools_unavailable):
    """RT F1: through generate_code_files and the step-1 stack (the developer runs with no workload project, like the
    eval harness). The error is a StageError carrying the code, recorded and persisted, typed for the eval harness."""
    s1b = _s1b()
    from shared.diagnostics import RepairBudgetExhausted, StageError
    from shared.hallucination_stack import HallucinationStackSettings

    # FD-4AF-r: an unknown placeholder is a repairable finding now; with no repair budget it stops the stage with the
    # same typed finding (RepairBudgetExhausted). A missing value still stops before any repair (default budget).
    unresolved = code == "K8S.PLACEHOLDER_UNRESOLVED"
    settings = HallucinationStackSettings(repair_max_iterations_precommit=0) if unresolved else None
    agent = s1b._agent(s1b._runtime(s1b.Client(), settings=settings))
    persisted = []
    real_persist = agent._persist_stack_outcome

    def spy(trace_id, report, events, **kw):
        persisted.append((trace_id, report, kw.get("error")))
        return real_persist(trace_id, report, events, **kw)

    draft = dict(s1b.DRAFT, **{"k8s/deployment.yaml": manifest})
    with patch.object(agent, "_persist_stack_outcome", side_effect=spy):
        with pytest.raises(StageError) as ei:
            s1b._generate(agent, draft, trace="trace-fd4af")
    assert isinstance(ei.value, RepairBudgetExhausted) is unresolved
    report = ei.value.report
    assert report.status == status and report.error_class.value == error_class
    assert report.tools_unavailable == tools_unavailable
    [d] = report.diagnostics
    assert (d.tool, d.code, d.file, d.severity) == ("yaml", code, "k8s/deployment.yaml", "error")
    # recorded on the stack run and persisted with the error (stack path)
    assert agent.stack_run("trace-fd4af")["validation_report"].diagnostics[0].code == code
    assert persisted and persisted[-1][0] == "trace-fd4af" and persisted[-1][2] is ei.value
    # the eval harness scores it developer_failed_typed (typed failure, not generation_error)
    typed = _typed_failure_of_eval(ei.value)
    assert typed is not None and typed["error_class"] == error_class and typed["codes"] == [code]


def test_e2e_callback_carries_error_class_for_hydration_error():
    """RT F1: the async developer callback carries error_class + the diagnostic code (gateway main.py)."""
    s1b = _s1b()
    import test_step1_typed_failures as tf
    from shared.diagnostics import StageError
    from shared.hallucination_stack import HallucinationStackSettings

    # FD-4AF-r: no repair budget -> the stage stops with the typed finding
    agent = s1b._agent(s1b._runtime(s1b.Client(), settings=HallucinationStackSettings(repair_max_iterations_precommit=0)))
    with pytest.raises(StageError) as ei:
        s1b._generate(agent, dict(s1b.DRAFT, **{"k8s/deployment.yaml": K8S_UNRESOLVED}), trace="trace-fd4af-cb")
    gw = tf._gateway_main()
    sent = []
    req = gw.DeveloperExecuteRequest(product_id="shop", trace_id="trace-fd4af-cb",
                                     callback_url="https://workflowexecutions.googleapis.com/v1/x/callbacks/c")
    with patch.object(gw, "_execute_developer_logic", side_effect=ei.value), patch.object(gw, "db", None), \
            patch.object(gw.CallbackDeliveryClient, "send_callback", side_effect=lambda **kw: sent.append(kw["payload"])):
        with pytest.raises(StageError):
            gw.run_developer_execute_in_background(req)
    out = sent[0]
    assert out["status"] == "FAILED" and out["error_class"] == "CODE_DEFECT"
    assert out["diagnostics"][0]["code"] == "K8S.PLACEHOLDER_UNRESOLVED"


def test_e2e_concrete_manifest_passes_through_the_handler_byte_identical():
    """Do No Harm through the handler: a manifest with only concrete images reaches the tree unchanged."""
    s1b = _s1b()
    agent = s1b._agent(s1b._runtime(s1b.Client()))
    files = s1b._generate(agent, dict(s1b.DRAFT, **{"k8s/deploy.yaml": PROBE_MANIFEST}), trace="trace-fd4af-ok")
    assert files["k8s/deploy.yaml"] == PROBE_MANIFEST
