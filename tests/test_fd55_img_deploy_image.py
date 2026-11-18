"""FD-55-IMG: deploy never rewrites `container_image` (or any image literal) in a workspace .tf file.

Bug (the plan review of FD-55, A38/A39): after the container build, `_deploy_workload_impl` rewrote every
`container_image` whose block had a `service_name` CONTAINING an apps/ directory name (substring regex), iterating
`os.listdir(apps)` (unordered). With apps `api` and `api-worker`, the order [api-worker, api] gave
`compute_api_worker` the image `.../api:latest`: the wrong container deployed. It ran on the default path and on
typed-intent workspaces (services.tf is not USER_OWNED).

Fix: the rewrite is deleted. The platform renders already bind each service's image through
`var.container_image` (terraform.tfvars, `.../app:latest`): `replace(var.container_image, "/app:", "/<svc>:")`
per service, or `var.container_image` itself for the module of the product's own service. The build tags
`app:latest` onto the service whose module takes `var.container_image` directly (parsed HCL, exact service name),
so that module gets its own image without any rewrite. Evidence (214 recorded committed eval trees, report
docs/handoff/fd-55-img-report.md): every rewrite replaced platform wiring with an equal image; no tree needed a
literal rewrite and none carried the hello placeholder.

Hermetic: no repo fetch, no Secret Manager, no ADC, no network, no tofu (the deploy stops at the first tofu call).
"""
import hermetic_guard  # noqa: F401  (first import)

import os
import sys
import types
from unittest.mock import MagicMock, patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (terraform MCP requirement) not installed")

from fd4g_support import load_tf_service  # noqa: E402

W = "infra/workload/"
REGION = "us-central1"
PROJECT = "p-1"

# The gateway's golden render shape (terraform_engine.generate_golden_*): the primary module in main.tf, every
# other service in services.tf with replace(var.container_image, "/app:", "/<svc>:").
GOLDEN_MAIN = (
    'module "foundation" {\n'
    '  source     = "../modules/workload-foundation/base"\n'
    '  project_id = var.project_id\n'
    '}\n\n'
    'module "compute" {\n'
    '  source                = "../modules/compute-cloudrun"\n'
    '  project_id            = var.project_id\n'
    '  region                = var.region\n'
    '  service_name          = "api"\n'
    '  container_image       = replace(var.container_image, "/app:", "/api:")\n'
    '  depends_on = [module.foundation]\n'
    '}\n'
)
GOLDEN_SERVICES = (
    'module "compute_api_worker" {\n'
    '  source                = "../modules/compute-cloudrun"\n'
    '  project_id            = var.project_id\n'
    '  region                = var.region\n'
    '  service_name          = "api-worker"\n'
    '  container_image       = replace(var.container_image, "/app:", "/api-worker:")\n'
    '  depends_on = [module.foundation]\n'
    '}\n'
)
VARIABLES = (
    'variable "project_id" {\n  type = string\n}\n\n'
    'variable "region" {\n  type    = string\n  default = "us-central1"\n}\n\n'
    'variable "product_id" {\n  type    = string\n  default = "shop"\n}\n\n'
    'variable "container_image" {\n  type    = string\n  default = ""\n}\n'
)
APPS = {
    "apps/api/main.py": "app = None\n",
    "apps/api/requirements.txt": "fastapi\n",
    "apps/api-worker/main.py": "app = None\n",
    "apps/api-worker/requirements.txt": "fastapi\n",
}


def _golden_tree():
    return {W + "main.tf": GOLDEN_MAIN, W + "services.tf": GOLDEN_SERVICES, W + "variables.tf": VARIABLES, **APPS}


@pytest.fixture
def tf(monkeypatch):
    return load_tf_service(monkeypatch)


class _StopAtTofu(BaseException):
    """Raised by the first tofu call: everything the deploy writes before plan/apply has been written."""


def _no_gcp(monkeypatch):
    import google.auth
    import google.cloud

    def _no_client(*_a, **_k):
        raise RuntimeError("no Secret Manager in tests")

    def _no_adc(*_a, **_k):
        raise RuntimeError("no ADC in tests")

    fake_sm = types.ModuleType("google.cloud.secretmanager")
    fake_sm.SecretManagerServiceClient = _no_client
    monkeypatch.setitem(sys.modules, "google.cloud.secretmanager", fake_sm)
    monkeypatch.setattr(sys.modules["google.cloud"], "secretmanager", fake_sm, raising=False)
    monkeypatch.setattr(sys.modules["google.auth"], "default", _no_adc, raising=False)


def _read_root_tf(ws):
    out = {}
    for name in sorted(os.listdir(ws)):
        p = os.path.join(ws, name)
        if os.path.isfile(p) and (name.endswith(".tf") or name == "terraform.tfvars"):
            with open(p, encoding="utf-8") as fh:
                out[name] = fh.read()
    return out


def _deploy(tf, monkeypatch, tmp_path, files, apps_order=None, product_id="shop"):
    """The REAL deploy_workload (flatten, prepare_workspace, tfvars merge, post-build steps) with a successful fake
    build, stopped at the first tofu call. Returns (root .tf + tfvars at build time, the same just before tofu)."""
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="",
                              workspace_base_dir=str(tmp_path / "base"), firestore_client=MagicMock())
    svc.db = None
    svc.state_bucket = ""
    monkeypatch.setattr(svc, "_fetch_repo_files", lambda *a, **k: dict(files))
    monkeypatch.setattr(svc, "_validate_no_engine_downgrade", lambda *a, **k: None)
    monkeypatch.setattr(svc, "_ensure_binary", lambda *a, **k: "tofu")
    _no_gcp(monkeypatch)
    seen = {}

    def _build(product_id, target_project_id, workspace_dir, image_tag, ar_repo_name=None, region=None):
        seen["ws"] = workspace_dir
        seen["at_build"] = _read_root_tf(workspace_dir)
        seen["image_tag"] = image_tag
        return True

    monkeypatch.setattr(svc, "_build_and_push_container", _build)

    def _tofu(*_a, **_k):
        raise _StopAtTofu()

    monkeypatch.setattr(svc, "_run_subprocess", _tofu)
    if apps_order is not None:
        real_listdir = os.listdir

        def _listdir(path="."):
            names = real_listdir(path)
            if os.path.basename(os.path.normpath(str(path))) == "apps" and sorted(names) == sorted(apps_order):
                return list(apps_order)
            return names

        monkeypatch.setattr(tf.os, "listdir", _listdir)
    with pytest.raises(_StopAtTofu):
        svc.deploy_workload(product_id=product_id, trace_id="t-fd55img", target_project_id=PROJECT,
                            branch="main", iac_engine="OPENTOFU")
    return seen, _read_root_tf(seen["ws"])


def _image_of(expr, tfvars_image):
    """The image a module's `container_image` resolves to (the three shapes the platform renders + a literal)."""
    expr = expr.strip()
    if expr.startswith("${") and expr.endswith("}"):
        inner = expr[2:-1].strip()
        if inner == "var.container_image":
            return tfvars_image
        prefix = 'replace(var.container_image, "/app:", "/'
        if inner.startswith(prefix) and inner.endswith(':")'):
            return tfvars_image.replace("/app:", "/" + inner[len(prefix):-3] + ":")
        raise AssertionError(f"unexpected expression {expr!r}")
    return expr


def _deployed_images(root):
    tfvars_image = hcl2.loads(root["terraform.tfvars"])["container_image"]
    images = {}
    for name, text in root.items():
        if not name.endswith(".tf"):
            continue
        for block in hcl2.loads(text).get("module", []) or []:
            for label, body in block.items():
                if "container_image" in body:
                    images[body["service_name"]] = _image_of(body["container_image"], tfvars_image)
    return images


def _tag(svc):
    return f"{REGION}-docker.pkg.dev/{PROJECT}/shop/{svc}:latest"


# ------------------------------------------------------------------------------------------------ reproduction
@pytest.mark.parametrize("order", [["api", "api-worker"], ["api-worker", "api"]], ids=["api-first", "worker-first"])
def test_api_and_api_worker_each_deploy_their_own_image_in_any_listing_order(tf, monkeypatch, tmp_path, order):
    """The plan review HIGH finding: with [api-worker, api] the substring rewrite gave compute_api_worker `.../api:latest`."""
    seen, root = _deploy(tf, monkeypatch, tmp_path, _golden_tree(), apps_order=order)
    assert seen["image_tag"] == _tag("app")
    assert _deployed_images(root) == {"api": _tag("api"), "api-worker": _tag("api-worker")}


@pytest.mark.parametrize("order", [["api", "api-worker"], ["api-worker", "api"]], ids=["api-first", "worker-first"])
def test_golden_render_is_byte_identical_through_the_post_build_deploy_steps(tf, monkeypatch, tmp_path, order):
    """Do No Harm (negative): a platform render (main.tf + services.tf) is never rewritten after the build."""
    seen, root = _deploy(tf, monkeypatch, tmp_path, _golden_tree(), apps_order=order)
    # (the window is build -> first tofu call: the flatten's FD-4BW module-source re-anchoring runs before the build)
    for name in ("main.tf", "services.tf"):
        assert root[name] == seen["at_build"][name], name
    assert 'replace(var.container_image, "/app:", "/api-worker:")' in root["services.tf"]


def test_single_service_render_is_untouched_and_takes_the_app_tag(tf, monkeypatch, tmp_path):
    """One service named after the product (render: `container_image = var.container_image`): the file stays as
    rendered; the image is `.../app:latest`, which the build tags onto that service (the only one)."""
    main = GOLDEN_MAIN.replace('service_name          = "api"', 'service_name          = "shop"').replace(
        'replace(var.container_image, "/app:", "/api:")', "var.container_image")
    files = {W + "main.tf": main, W + "variables.tf": VARIABLES,
             "apps/shop/main.py": "app = None\n", "apps/shop/requirements.txt": "fastapi\n"}
    seen, root = _deploy(tf, monkeypatch, tmp_path, files)
    assert root["main.tf"] == seen["at_build"]["main.tf"]
    assert "container_image       = var.container_image" in root["main.tf"]
    assert _deployed_images(root) == {"shop": _tag("app")}


def test_legacy_literal_image_is_not_rewritten(tf, monkeypatch, tmp_path):
    """A hand-written main.tf with an image literal (incl. the hello placeholder) is no longer edited after the build
    (owner row FD55-IMG; no recorded committed tree had one)."""
    main = ('resource "google_cloud_run_v2_service" "api" {\n'
            '  name     = "api"\n'
            '  location = var.region\n'
            '  template {\n'
            '    containers {\n'
            '      image = "us-docker.pkg.dev/cloudrun/container/hello"\n'
            '    }\n'
            '  }\n'
            '}\n')
    files = {W + "main.tf": main, W + "variables.tf": VARIABLES,
             "apps/api/main.py": "app = None\n", "apps/api/requirements.txt": "fastapi\n"}
    seen, root = _deploy(tf, monkeypatch, tmp_path, files)
    assert root["main.tf"] == seen["at_build"]["main.tf"]
    assert "us-docker.pkg.dev/cloudrun/container/hello" in root["main.tf"]


# ------------------------------------------------------------------------------------------------ intent workspace
INTENT = '{"schema": "iac_intent/v1", "modules": []}\n'
RENDER = '{"//": "Rendered by StackVend"}\n'
TOPOLOGY = ('{"schema": "service_topology/v1", "intent": {"services": [{"name": "api", "kind": "cloudrun"}, '
            '{"name": "api-worker", "kind": "cloudrun"}], "primary_service": "api", "edges": [], "resources": []}}')


@pytest.mark.parametrize("order", [["api", "api-worker"], ["api-worker", "api"]], ids=["api-first", "worker-first"])
def test_intent_workspace_services_tf_is_untouched(tf, monkeypatch, tmp_path, order):
    """TI-5-R1: on a typed-intent workspace no deploy step writes a platform render (services.tf was rewritten)."""
    files = dict(_golden_tree(), **{W + "iac_intent.json": INTENT, W + "custom.tf.json": RENDER,
                                    W + "topology.json": TOPOLOGY})
    seen, root = _deploy(tf, monkeypatch, tmp_path, files, apps_order=order)
    for name in ("main.tf", "services.tf"):
        assert root[name] == seen["at_build"][name], name
    assert _deployed_images(root) == {"api": _tag("api"), "api-worker": _tag("api-worker")}


# ------------------------------------------------------------------------------------------------ build: app:latest
DIRECT_MAIN = GOLDEN_MAIN.replace('service_name          = "api"', 'service_name          = "shop"').replace(
    'replace(var.container_image, "/app:", "/api:")', "var.container_image")
WEB_SERVICES = GOLDEN_SERVICES.replace("api_worker", "shop_web").replace("api-worker", "shop-web")


def _ws(tmp_path, files):
    ws = tmp_path / "ws"
    for rel, text in files.items():
        p = ws / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return str(ws)


def test_direct_image_services_reads_the_exact_literal_service_name(tf, tmp_path):
    ws = _ws(tmp_path, {"main.tf": DIRECT_MAIN, "services.tf": WEB_SERVICES})
    assert tf.direct_container_image_services(ws) == {"shop"}


@pytest.mark.parametrize("files", [
    {"main.tf": GOLDEN_MAIN, "services.tf": GOLDEN_SERVICES},                         # every module uses replace()
    {"main.tf": DIRECT_MAIN.replace('"shop"', '"${var.product_id}-x"')},               # not a plain literal
    {"main.tf": DIRECT_MAIN, "broken.tf": 'module "x" {\n'},                          # a root file does not parse
    {},                                                                                 # no root .tf
], ids=["replace-only", "interpolated-name", "unparseable", "empty"])
def test_direct_image_services_is_empty_or_none_without_an_exact_direct_module(tf, tmp_path, files):
    ws = _ws(tmp_path, files)
    assert not tf.direct_container_image_services(ws)


@pytest.mark.parametrize("pool,clean_pid,direct,expected", [
    (["shop", "shop-web"], "shop", {"shop"}, "shop"),          # the direct module's service gets app:latest
    (["shop", "shop-web"], "shop", set(), "shop-web"),         # negative: unchanged rules (UI name first)
    (["shop", "shop-worker"], "shop", None, "shop-worker"),    # negative: unchanged rules (other than the product)
    (["shop"], "shop", None, "shop"),
    (["a", "b"], "shop", {"a", "b"}, "a"),                     # two direct modules: unchanged rules (first of pool)
    (["a", "b"], "shop", {"zzz"}, "a"),                        # no apps/ dir of that name: unchanged rules
])
def test_primary_build_service(tf, pool, clean_pid, direct, expected):
    assert tf.primary_build_service(pool, clean_pid, direct) == expected


# ------------------------------------------------------------------------------------------------ RT F1 / F2
@pytest.mark.parametrize("pool,direct,expected", [
    (["api", "api_worker"], {"api-worker"}, "api_worker"),     # underscore dir, hyphen service name
    (["api", "api-worker"], {"api_worker"}, "api-worker"),     # hyphen dir, underscore service name
    (["shop_web", "shop"], {"shop_web"}, "shop_web"),
])
def test_rt_f1_underscore_and_hyphen_names_are_one(tf, pool, direct, expected):
    assert tf.primary_build_service(pool, "shop", direct) == expected


@pytest.mark.parametrize("alias", ["castor-shop", "compute", "app", "shop", "${var.product_id}"])
def test_rt_f2_golden_product_aliases_are_the_products_own_service(tf, alias):
    """The engine wires var.container_image directly for the product's own service under these names (or none):
    app:latest goes to apps/<clean_pid>, not to the UI-named sibling the old rules would pick."""
    assert tf.primary_build_service(["shop", "shop-web"], "shop", {alias}) == "shop"
    assert tf.primary_build_service(["shop_web", "shop"], "shop", {alias}) == "shop"


def test_rt_f2_product_alias_without_the_product_dir_keeps_the_previous_rules(tf):
    assert tf.primary_build_service(["a-web", "b"], "shop", {"${var.product_id}"}) == "a-web"
    assert tf.primary_build_service(["a-web", "b"], "shop", {"castor-shop"}) == "a-web"
    assert tf.primary_build_service(["compute", "b-web"], "shop", {"compute"}) == "compute"   # a real apps/compute


@pytest.mark.parametrize("service_line", ["", "  service_name          = var.product_id\n"], ids=["absent", "var"])
def test_rt_f2_module_without_a_literal_service_name_is_the_product_service(tf, tmp_path, service_line):
    main = ('module "compute" {\n  source                = "../modules/compute-event-worker"\n'
            + service_line + '  container_image       = var.container_image\n}\n')
    ws = _ws(tmp_path, {"main.tf": main, "services.tf": WEB_SERVICES})
    direct = tf.direct_container_image_services(ws)
    assert direct == {tf.DIRECT_IMAGE_PRODUCT_SERVICE}
    assert tf.primary_build_service(["shop", "shop-web"], "shop", direct) == "shop"


def _engine(monkeypatch):
    gw = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
    monkeypatch.syspath_prepend(gw)
    import importlib
    return importlib.import_module("developer_agent.terraform_engine")


@pytest.mark.parametrize("archetype,service_name", [
    ("cloudrun", "shop"), ("cloudrun", "castor-shop"), ("cloudrun", "compute"), ("cloudrun", "app"),
    ("cloudrun", None), ("event-worker", None), ("cloudrun", "shop-api"),
])
def test_rt_f2_contract_parity_with_the_golden_render(tf, monkeypatch, tmp_path, archetype, service_name):
    """GOLDEN_DIRECT_IMAGE_NAMES / DIRECT_IMAGE_PRODUCT_SERVICE mirror terraform_engine's image_expr rule: every render
    that wires var.container_image directly maps to apps/<clean_pid>; a render with replace() names its own dir."""
    te = _engine(monkeypatch)
    main = te.generate_golden_main_tf("shop", archetype, "", service_name=service_name)
    ws = _ws(tmp_path, {"main.tf": main})
    direct = tf.direct_container_image_services(ws)
    if service_name == "shop-api":
        assert direct == set() and 'replace(var.container_image, "/app:", "/shop-api:")' in main
    else:
        assert "container_image       = var.container_image" in main
        assert direct and tf.primary_build_service(["shop", "shop-web"], "shop", direct) == "shop"


@pytest.mark.parametrize("services_tf,direct,expected", [
    (WEB_SERVICES, {"shop"}, "shop"),
    # two modules wired directly (cannot both get app:latest): the previous rules decide (UI-named first)
    (WEB_SERVICES.replace('replace(var.container_image, "/app:", "/shop-web:")', "var.container_image"),
     {"shop", "shop-web"}, "shop-web"),
], ids=["one-direct", "two-direct"])
def test_build_tags_app_latest_onto_the_directly_wired_service(tf, monkeypatch, tmp_path, services_tf, direct,
                                                               expected):
    """The real _build_and_push_container (stopped at staging): with `module "compute"` (service "shop") taking
    var.container_image directly and a sibling "shop-web", app:latest goes to "shop" (the UI-name rule would have
    picked "shop-web" and the deploy-time rewrite used to hide that)."""
    import importlib
    settings = sys.modules.get("shared.settings") or importlib.import_module("shared.settings")
    monkeypatch.setattr(settings, "get_platform_settings", lambda *a, **k: None)   # no Firestore (BOM defaults)
    ws = _ws(tmp_path, {"main.tf": DIRECT_MAIN, "services.tf": services_tf,
                        "apps/shop/main.py": "app = None\n", "apps/shop-web/main.py": "app = None\n"})
    svc = tf.TerraformService(project_id="mock-stackvend-project", state_bucket="",
                              workspace_base_dir=str(tmp_path / "b"), firestore_client=MagicMock())
    svc.db = None
    svc.state_bucket = ""
    picked = []
    real_primary = tf.primary_build_service

    def spy(pool, clean_pid, direct):
        picked.append((sorted(pool), clean_pid, direct, real_primary(pool, clean_pid, direct)))
        return picked[-1][-1]

    def stage(**kwargs):
        raise RuntimeError("stop after packaging (test)")

    with patch("google.auth.default", return_value=(MagicMock(), "p")), \
         patch("google.auth.transport.requests.AuthorizedSession"), \
         patch("google.cloud.storage.Client"), \
         patch.object(tf, "primary_build_service", side_effect=spy), \
         patch.object(tf.TerraformService, "_stage_build_source", side_effect=stage):
        assert svc._build_and_push_container("shop", "child", ws, "img:tag") is False
    assert picked == [(["shop", "shop-web"], "shop", direct, expected)]
