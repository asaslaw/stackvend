"""FD-4CB-b (owner 10-24): the developer stage stops offering the host platform's own `workflows` golden module to
workloads (its main.tf reads ../../../workflows/*.yaml, which exists only in the StackVend repo).

One source of truth (shared/host_platform_modules.py) feeds the red-team critic's catalog, the TI-2 typed-IaC module
catalog and the developer stage's vendoring. A workload draft whose `module` sources ../modules/workflows is refused by
the existing content policy (V2j POLICY.MODULE_SOURCE_NOT_LOCAL: the directory is not one this run vendored) with a hint
naming `workflows-dag`; in generate mode the typed intent cannot name it (IAC.MODULE_UNKNOWN). `workflows-dag` stays
offered everywhere, and the host platform's own use (infra/platform/main.tf) is untouched.

The former host CI module `cloud_build` was removed with Developer mode (owner 2026-11-09): a draft naming it is refused
like any other directory that is not vendored (generic POLICY.MODULE_SOURCE_NOT_LOCAL hint)."""
import hermetic_guard  # noqa: F401  (first import)

import filecmp
import json
import os
import sys
from unittest import mock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from shared import host_platform_modules as HPM  # noqa: E402
from shared import iac_intent as ii  # noqa: E402
from shared.artifact_ownership import Ownership  # noqa: E402
from architect_agent import red_team_critic as rtc  # noqa: E402
from developer_agent import contract_inspector as CI  # noqa: E402
from developer_agent import prompt as P  # noqa: E402
from developer_agent import terraform_engine as TE  # noqa: E402
from developer_agent.validators import ValidationContext  # noqa: E402
from developer_agent.validators import policy_tables as T  # noqa: E402
from developer_agent.validators.content_policy import ContentPolicyValidator, host_platform_module  # noqa: E402

W = "infra/workload/"
AVAILABLE = ["google", "google-beta", "kubernetes", "random"]
MODULES_DIR = os.path.join(REPO_ROOT, "infra", "modules")


# ------------------------------------------------------------------------------------------------ one source of truth
def test_shared_table_and_gateway_copy_byte_identical():
    a = os.path.join(REPO_ROOT, "shared", "host_platform_modules.py")
    b = os.path.join(GATEWAY, "shared", "host_platform_modules.py")
    assert filecmp.cmp(a, b, shallow=False)
    assert HPM.HOST_PLATFORM_ONLY_MODULES == frozenset({"workflows"})
    assert HPM.NOT_VENDORED_TO_WORKLOADS == frozenset({"workflows"})
    assert HPM.NOT_VENDORED_TO_WORKLOADS == HPM.HOST_PLATFORM_ONLY_MODULES
    assert "workflows-dag" not in HPM.HOST_PLATFORM_ONLY_MODULES


def test_every_host_only_module_is_a_real_module_the_host_platform_uses():
    with open(os.path.join(REPO_ROOT, "infra", "platform", "main.tf"), encoding="utf-8") as f:
        platform_main = f.read()
    for m in HPM.HOST_PLATFORM_ONLY_MODULES:
        assert os.path.isdir(os.path.join(MODULES_DIR, m)), m
        assert f'source = "../modules/{m}"' in platform_main, m   # host use kept (infra/platform untouched)


def test_critic_catalog_reads_the_shared_set():
    assert rtc.HOST_PLATFORM_ONLY_MODULES is HPM.HOST_PLATFORM_ONLY_MODULES
    assert "workflows" not in rtc.CANONICAL_GOLDEN_MODULES
    assert "workflows-dag" in rtc.CANONICAL_GOLDEN_MODULES


def test_typed_iac_catalog_lists_host_modules_as_platform_only_with_the_shared_reasons():
    sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))
    try:
        import build_iac_catalog as B
    finally:
        sys.path.remove(os.path.join(REPO_ROOT, "scripts"))
    with open(os.path.join(REPO_ROOT, "shared", "iac_intent", "module_catalog.json"), encoding="utf-8") as f:
        cat = json.load(f)
    for m, why in HPM.HOST_PLATFORM_ONLY_MODULE_REASONS.items():
        assert B.PLATFORM_ONLY[m] == why and cat["platform_only"][m] == why
        assert m not in B.AI_INSTANTIABLE and m not in cat["ai_instantiable"]
    assert "workflows-dag" in cat["ai_instantiable"]


def test_policy_hint_table_keys_equal_the_not_vendored_set():
    assert set(T.HINT_HOST_PLATFORM_MODULE) == set(HPM.NOT_VENDORED_TO_WORKLOADS)


# ------------------------------------------------------------------------------------------------ developer offering
def _raw_disk_module_files():
    out = {}
    for root, _dirs, files in os.walk(MODULES_DIR):
        rel = os.path.relpath(root, MODULES_DIR)
        for fn in files:
            if fn.endswith(".tf"):
                with open(os.path.join(root, fn), encoding="utf-8") as f:
                    out[f"infra/modules/{rel}/{fn}"] = f.read()
    return out


def _module_ids(keys):
    return {k.split("/")[2] for k in keys}


HOST_ONLY = ("workflows",)


def test_canonical_module_files_drop_only_the_host_modules_on_disk():
    """Do No Harm: the only change to the vendorable set is the excluded modules; every other file is byte-identical."""
    raw = _raw_disk_module_files()
    got = TE.get_canonical_module_files()
    assert set(HOST_ONLY) <= _module_ids(raw)
    assert not set(HOST_ONLY) & _module_ids(got)
    assert "workflows-dag" in _module_ids(got)
    assert got == {k: v for k, v in raw.items() if k.split("/")[2] not in HOST_ONLY}
    assert len(raw) - len(got) == 3   # exactly main/outputs/variables.tf of the host module


def test_canonical_module_files_drop_only_the_host_modules_in_the_embedded_payload():
    """The deployed gateway has no infra/modules on disk: the embedded payload path excludes the same module."""
    from shared.builtin_modules_payload import BUILTIN_MODULE_FILES
    with mock.patch.object(TE, "get_platform_modules_path", return_value=None):
        got = TE.get_canonical_module_files()
    expected = {f"infra/modules/{mid}/{fn}": c for mid, fd in BUILTIN_MODULE_FILES.items()
                if mid.split("/")[0] not in HOST_ONLY for fn, c in fd.items()}
    assert set(HOST_ONLY) <= set(BUILTIN_MODULE_FILES)
    assert got == expected
    assert "workflows-dag" in _module_ids(got)


@pytest.fixture()
def no_firestore_prompt():
    with mock.patch("shared.prompt_resolver.get_agent_system_prompt",
                    side_effect=lambda agent_role, fallback_constant=None, **k: fallback_constant), \
            mock.patch.object(CI, "get_custom_module_contracts", return_value=[]), \
            mock.patch.object(P, "resolve_active_skills", return_value=[]), \
            mock.patch.object(P, "format_skills_for_prompt", return_value=""):
        CI._CONTRACT_CACHE.clear()
        yield
        CI._CONTRACT_CACHE.clear()


def test_developer_prompt_offers_workflows_dag_and_never_workflows(no_firestore_prompt):
    prompt = P.build_developer_system_prompt(service_names=["api"])
    assert 'source = "../modules/workflows-dag"' in prompt
    assert 'source = "../modules/workflows")' not in prompt and "`workflows`" not in prompt
    assert "workflows" not in CI._EMBEDDED_MODULE_CONTRACTS


def test_generate_mode_intent_cannot_name_workflows():
    art = ii.load_artifacts()
    assert "workflows" not in art.ai_modules and "workflows-dag" in art.ai_modules
    enum = ii.response_json_schema(art)["$defs"]["ModuleInstance"]["properties"]["module"]["enum"]
    assert "workflows" not in enum and "workflows-dag" in enum
    ctx = ii.IntentContext(services={"api": ("module.compute", "compute-cloudrun")})
    doc = {"schema": "iac_intent/v1", "resources": [], "outputs": [],
           "modules": [{"module": "workflows", "name": "orch", "args": {}}]}
    diags = ii.validate_intent(doc, art, ctx).diagnostics
    assert "IAC.MODULE_UNKNOWN" in {d.code for d in diags}


# ------------------------------------------------------------------------------------------------ draft refused (V2j)
DRAFT = ('module "orch" {\n  source     = "../modules/workflows"\n  project_id = var.project_id\n}\n'
         'module "flow" {\n  source     = "../modules/workflows-dag"\n  project_id = var.project_id\n}\n')


def _ctx(files, llm, vendored):
    vend = frozenset(vendored)

    def own(path):
        if path in vend:
            return Ownership.PLATFORM_VENDORED
        return Ownership.LLM_AUTHORED if path in llm else Ownership.PLATFORM_RENDERED
    return ValidationContext.build(files, ownership=own, extras={"available_providers": AVAILABLE}, trace_id="t",
                                   vendored=vend, rendered=frozenset(), draft={})


def _vendor(files):
    """vendor_terraform_modules on a copy; returns (files, the keys it wrote). Firestore (custom-module lookup for a
    name the canonical set does not hold) is a fake that finds nothing."""
    before = dict(files)
    out = dict(files)
    fake = mock.MagicMock()
    fake.return_value.collection.return_value.document.return_value.get.return_value.exists = False
    with mock.patch("google.cloud.firestore.Client", fake):
        TE.vendor_terraform_modules(out, "cloudrun")
    written = {k for k in out if k not in before or out[k] != before[k]}
    return out, written


def test_workload_module_sourcing_workflows_is_not_vendored_and_is_refused_with_a_typed_finding():
    files, written = _vendor({W + "custom.tf": DRAFT})
    assert "workflows" not in _module_ids(k for k in written if k.startswith("infra/modules/"))
    assert any(k.startswith("infra/modules/workflows-dag/") for k in written)
    got = ContentPolicyValidator().validate(_ctx(files, {W + "custom.tf"}, written))
    assert [(d.code, d.block_address) for d in got] == [("POLICY.MODULE_SOURCE_NOT_LOCAL", "module.orch")]
    assert got[0].hint == T.HINT_HOST_PLATFORM_MODULE["workflows"]
    assert "workflows-dag" in got[0].hint and "not offered to workloads" in got[0].message


def test_negative_workflows_dag_alone_vends_and_passes():
    dag_only = 'module "flow" {\n  source     = "../modules/workflows-dag"\n  project_id = var.project_id\n}\n'
    files, written = _vendor({W + "custom.tf": dag_only})
    assert any(k.startswith("infra/modules/workflows-dag/") for k in written)
    assert ContentPolicyValidator().validate(_ctx(files, {W + "custom.tf"}, written)) == []


@pytest.mark.parametrize("source,expected", [
    ("../modules/workflows", "workflows"),
    ("./../modules/workflows/", "workflows"),
    ("../modules/workflows-dag", None),          # a different directory
    ("../modules/cloud_build", None),            # removed: no longer a host module
    ("./modules/workflows", None),               # under infra/workload/: the workload's own module
    ("../modules/workflows/sub", None),          # not the module directory itself
    ("git::https://example.invalid/workflows", None),
])
def test_host_module_hint_is_the_exact_resolved_directory(source, expected):
    assert host_platform_module({"source": source}) == expected


def test_negative_other_unvendored_sources_keep_the_generic_hint():
    tf = ('module "a" {\n  source = "../modules/workflows-dag"\n}\n'      # not vendored in this ctx
          'module "b" {\n  source = "../modules/not-a-golden-module"\n}\n')
    files = {W + "custom.tf": tf}
    got = ContentPolicyValidator().validate(_ctx(files, {W + "custom.tf"}, ()))
    assert [d.code for d in got] == ["POLICY.MODULE_SOURCE_NOT_LOCAL"] * 2
    assert {d.hint for d in got} == {T.HINT_MODULE_SOURCE_NOT_LOCAL}
    assert all("host platform" not in d.message for d in got)


# ------------------------------------------------------------------------------------------------ FD-4CB-c cloud_build
CB_DRAFT = ('module "ci" {\n  source     = "../modules/cloud_build"\n  project_id = var.project_id\n}\n'
            'module "flow" {\n  source     = "../modules/workflows-dag"\n  project_id = var.project_id\n}\n')


def test_workload_module_sourcing_cloud_build_is_not_vendored_and_is_refused_with_a_typed_finding():
    files, written = _vendor({W + "custom.tf": CB_DRAFT})
    assert "cloud_build" not in _module_ids(k for k in written if k.startswith("infra/modules/"))
    assert any(k.startswith("infra/modules/workflows-dag/") for k in written)
    got = ContentPolicyValidator().validate(_ctx(files, {W + "custom.tf"}, written))
    assert [(d.code, d.block_address) for d in got] == [("POLICY.MODULE_SOURCE_NOT_LOCAL", "module.ci")]
    assert got[0].hint == T.HINT_MODULE_SOURCE_NOT_LOCAL


def test_negative_a_draft_without_a_host_module_vendors_the_same_as_before():
    """Do No Harm: a draft that names no host module vends only what it names."""
    dag_only = 'module "flow" {\n  source     = "../modules/workflows-dag"\n  project_id = var.project_id\n}\n'
    _files, written = _vendor({W + "custom.tf": dag_only})
    assert not any(k.startswith("infra/modules/cloud_build/") for k in written)


def test_critic_and_typed_catalog_already_excluded_cloud_build():
    """FD-4CB-c changes only the developer stage: the critic catalog and the typed-IaC catalog did not offer it."""
    assert "cloud_build" not in rtc.CANONICAL_GOLDEN_MODULES
    art = ii.load_artifacts()
    assert "cloud_build" not in art.ai_modules
