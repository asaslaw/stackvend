"""CI-5: the developer's embedded golden-module contracts equal what the on-disk modules declare.

The deployed gateway has no infra/modules on disk, so `contract_inspector._EMBEDDED_MODULE_CONTRACTS` is the
production prompt grounding, while tests and the eval harness read infra/modules/<m>/{variables,outputs}.tf. The two
had drifted (CMEK inputs of the compliance integration, plus older drift: compute-event-worker, compute-gce-bastion,
workload_auth, ...). These tests pin every embedded entry to the real module files (python-hcl2, not regex), and pin
the result that matters: the contract block and the full developer prompt are byte-identical with and without the
modules on disk, so the deployed gateway builds exactly the prompt the eval harness builds today. (Only the
single-pass developer path carries this block; the swarm lead/juniors never see it.)
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import os
import shutil
import sys
from unittest.mock import patch

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_PATH = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for _p in (GATEWAY_PATH, REPO_ROOT):
    if _p not in sys.path:
        sys.path.insert(0, _p)

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from developer_agent import contract_inspector as CI  # noqa: E402
from developer_agent import prompt as P  # noqa: E402

MODULES_DIR = os.path.join(REPO_ROOT, "infra", "modules")
EMBEDDED = CI._EMBEDDED_MODULE_CONTRACTS
MODULES = sorted(EMBEDDED)

# CI-5 scope as proposed by the Fable RT (F3) of the compliance integration: must be advertised in production.
CI5_REQUIRED = {
    "analytics-bigquery": {"kms_key_name"},
    "cache-redis": {"kms_key_name"},
    "compute-event-worker": {"kms_key_name"},
    "messaging-pubsub": {"kms_key_name"},
    "storage-bucket": {"kms_key_name"},
    "compute-cloudrun": {"encryption_key"},
    "security-kms": {"protection_level", "enable_apis", "service_agent_services"},
}


def _declared(module, filename, kind):
    with open(os.path.join(MODULES_DIR, module, filename), encoding="utf-8") as f:
        return {name for block in hcl2.loads(f.read()).get(kind, []) for name in block}


@pytest.fixture()
def fresh_cache():
    CI._CONTRACT_CACHE.clear()
    yield
    CI._CONTRACT_CACHE.clear()


@pytest.mark.parametrize("module", MODULES)
def test_embedded_inputs_equal_module_variables(module):
    assert set(EMBEDDED[module]["inputs"]) == _declared(module, "variables.tf", "variable")


@pytest.mark.parametrize("module", MODULES)
def test_embedded_outputs_equal_module_outputs(module):
    assert set(EMBEDDED[module]["outputs"]) == _declared(module, "outputs.tf", "output")


@pytest.mark.parametrize("module", MODULES)
def test_embedded_lists_are_sorted_and_unique(module):
    for kind in ("inputs", "outputs"):
        names = EMBEDDED[module][kind]
        assert names == sorted(set(names)), f"{module}.{kind}"


def test_every_embedded_module_exists_on_disk():
    assert [m for m in MODULES if not os.path.isdir(os.path.join(MODULES_DIR, m))] == []


@pytest.mark.parametrize("module", sorted(CI5_REQUIRED))
def test_ci5_cmek_inputs_are_embedded(module):
    assert CI5_REQUIRED[module] <= set(EMBEDDED[module]["inputs"])


@pytest.mark.parametrize("module", MODULES)
def test_unmounted_contract_text_equals_on_disk_text(module, fresh_cache):
    """Production (no infra/modules) renders the same contract block, byte for byte, as the on-disk read."""
    on_disk = CI.get_golden_module_contract(module, force_refresh=True)
    with patch.object(CI, "get_platform_modules_path", return_value=None):
        unmounted = CI.get_golden_module_contract(module, force_refresh=True)
    assert not on_disk.startswith("<!--")
    assert unmounted == on_disk


@pytest.fixture()
def no_firestore_prompt():
    """Resolver returns the code constant; custom-module contracts and skills are empty (no Firestore client)."""
    with patch("shared.prompt_resolver.get_agent_system_prompt",
               side_effect=lambda agent_role, fallback_constant=None, **k: fallback_constant), \
            patch.object(CI, "get_custom_module_contracts", return_value=[]), \
            patch.object(P, "resolve_active_skills", return_value=[]), \
            patch.object(P, "format_skills_for_prompt", return_value=""):
        yield


def test_production_image_layout_without_patching(tmp_path, monkeypatch):
    """The buildpack image: the gateway source is /workspace (cwd), there is no infra/ anywhere. Both lookup paths
    (<file>/../../../infra/modules = /infra/modules, and cwd/infra/modules = /workspace/infra/modules) are absent,
    so the real lookup returns None, unpatched, and the rendered block equals the on-disk block."""
    root = tmp_path / "root"                      # stands in for "/"
    pkg = root / "workspace" / "developer_agent"
    pkg.mkdir(parents=True)
    shutil.copy(os.path.join(GATEWAY_PATH, "developer_agent", "contract_inspector.py"), pkg / "contract_inspector.py")
    monkeypatch.chdir(root / "workspace")
    assert not (root / "infra" / "modules").exists() and not (root / "workspace" / "infra" / "modules").exists()
    spec = importlib.util.spec_from_file_location("ci5_prod_layout_contract_inspector", str(pkg / "contract_inspector.py"))
    prod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(prod)
    assert prod.get_platform_modules_path() is None
    with patch.object(prod, "get_custom_module_contracts", return_value=[]), \
            patch.object(CI, "get_custom_module_contracts", return_value=[]):
        CI._CONTRACT_CACHE.clear()
        repo_text = CI.get_all_active_module_contracts()
        prod_text = prod.get_all_active_module_contracts()
    CI._CONTRACT_CACHE.clear()
    assert CI.get_platform_modules_path() is not None
    assert prod_text == repo_text
    assert prod_text.count("### Golden Module Contract") == len(EMBEDDED)


def test_mutated_embedded_entry_changes_unmounted_prompt(fresh_cache, no_firestore_prompt):
    """Negative control: the identity test is not vacuous. Dropping one embedded name changes the unmounted prompt
    and leaves the on-disk prompt as it was."""
    assert P.get_all_active_module_contracts is CI.get_all_active_module_contracts
    entry = EMBEDDED["storage-bucket"]
    mutated = {"inputs": [n for n in entry["inputs"] if n != "kms_key_name"], "outputs": list(entry["outputs"])}
    with patch.dict(CI._EMBEDDED_MODULE_CONTRACTS, {"storage-bucket": mutated}):
        on_disk = P.build_developer_system_prompt(service_names=["api"])
        CI._CONTRACT_CACHE.clear()
        with patch.object(CI, "get_platform_modules_path", return_value=None):
            unmounted = P.build_developer_system_prompt(service_names=["api"])
    assert "kms_key_name" in on_disk
    assert unmounted != on_disk


@pytest.mark.parametrize("service_names", [None, ["api"], ["api", "worker"]])
def test_developer_prompt_identical_with_and_without_modules_on_disk(service_names, fresh_cache,
                                                                     no_firestore_prompt):
    """The prompt has no compliance-profile input; a STANDARD workload's single-pass prompt in the deployed gateway is
    now the prompt the eval harness (modules on disk) builds today."""
    on_disk = P.build_developer_system_prompt(service_names=service_names)
    CI._CONTRACT_CACHE.clear()
    with patch.object(CI, "get_platform_modules_path", return_value=None):
        unmounted = P.build_developer_system_prompt(service_names=service_names)
    assert "DYNAMIC GOLDEN MODULE CONTRACTS" in on_disk
    assert unmounted == on_disk
