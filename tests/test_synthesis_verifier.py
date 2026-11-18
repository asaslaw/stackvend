"""
Unit & Integration Tests for Anti-Hallucination Gatekeeper Agent
Verifies (FD-4AD) that valid imports are never rewritten (the AST import transformer is deleted; imports that cannot
resolve are reported by V3c-imports CONTAINER.IMPORT_OUTSIDE_SERVICE, FD-4AE-c, not by V3d), the add-only PyPI
requirements contract, and in-memory compilation.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../apps/orchestrator-gateway")))

from developer_agent.validators.base import ValidationContext
from developer_agent.validators.python_layout import PythonLayoutValidator
from gatekeeper_agent.pypi_catalog import resolve_import_to_pypi
from gatekeeper_agent.verifier import SynthesisVerifierAgent


def _v3d(files):
    return [(d.code, d.file, d.line) for d in PythonLayoutValidator().validate(
        ValidationContext.build(files, ownership=lambda p: None))]


def test_monorepo_imports_in_try_block_are_byte_identical_and_reported():
    """FD-4AD (HB-31 / HE-02): the import transformer that rewrote `from apps.<svc>.x import` is deleted; the file is
    committed as written. V3d reports no import facts (FD-4AE-c RT F2: one code, V3c-imports
    CONTAINER.IMPORT_OUTSIDE_SERVICE, which also skips these ImportError-guarded imports)."""
    code = """try:
    from apps.testplan01.config import Settings, get_settings
    from apps.testplan01.models import EventPayload
except ImportError:
    from config import Settings, get_settings
    from models import EventPayload
"""
    files = {"apps/testplan01/main.py": code, "apps/testplan01/config.py": "Settings = get_settings = None\n",
             "apps/testplan01/models.py": "EventPayload = None\n", "apps/testplan01/requirements.txt": ""}
    cured, passed, errors = SynthesisVerifierAgent("testplan01").verify_and_cure(dict(files), product_id="testplan01")
    assert passed is True, errors
    assert cured["apps/testplan01/main.py"] == code
    assert _v3d(cured) == []


def test_valid_relative_and_multiline_imports_are_byte_identical():
    """FD-4AD Do No Harm: `from ..models import X` inside a sub-package and a multi-line parenthesized import are valid
    and stay byte-identical (the old transformer flattened `..` to an absolute import); a relative import that climbs
    above the service root is never edited (reported by V3c-imports, not V3d: FD-4AE-c RT F2)."""
    deep = """from ..models import Item
from . import (
    helpers,
)
"""
    too_high = "from ..models import Item\n"
    files = {
        "apps/shop/api/v1/items.py": deep,
        "apps/shop/api/v1/helpers.py": "X = 1\n",
        "apps/shop/api/models.py": "Item = object\n",
        "apps/shop/routers/orders.py": too_high,
        "apps/shop/requirements.txt": "",
    }
    cured, passed, errors = SynthesisVerifierAgent("shop").verify_and_cure(dict(files), product_id="shop")
    assert passed is True, errors
    assert cured["apps/shop/api/v1/items.py"] == deep
    assert cured["apps/shop/routers/orders.py"] == too_high
    assert _v3d(cured) == []


def test_pypi_resolver():
    """Verifies that imports map to correct PyPI packages and stdlib/unvetted returns None."""
    # Stdlib should return None
    assert resolve_import_to_pypi("os") is None
    assert resolve_import_to_pypi("sys") is None
    assert resolve_import_to_pypi("json") is None

    # Vetted mappings
    assert resolve_import_to_pypi("yaml") == "PyYAML>=6.0.1"
    assert resolve_import_to_pypi("PIL") == "Pillow>=10.2.0"
    assert resolve_import_to_pypi("google.cloud.storage") == "google-cloud-storage>=2.14.0"
    assert resolve_import_to_pypi("google.cloud.pubsub_v1") == "google-cloud-pubsub>=2.19.0"
    assert resolve_import_to_pypi("pydantic_settings") == "pydantic-settings>=2.2.0"

    # Closed-world Level 3 governance: unvetted local imports must return None, NOT root fallback
    assert resolve_import_to_pypi("firestore_client") is None
    assert resolve_import_to_pypi("auth") is None
    assert resolve_import_to_pypi("contracts") is None
    assert resolve_import_to_pypi("random_hallucinated_package") is None


def test_closed_world_local_modules_are_never_injected_and_user_lines_are_kept():
    """Local shared modules are never injected into requirements.txt (closed-world catalog). FD-4AD: lines the AI wrote
    are never pruned any more (HB-28 deleted every line whose name matched any local `.py` stem, e.g. `celery.py`
    removed `celery`); a line naming a repository-local module is the report-only REQ.LOCAL_MODULE_NAME (V3d)."""
    reqs = """fastapi>=0.110.0
firestore_client
contracts
auth
"""
    files = {
        "apps/shared/firestore_client.py": "def get_db(): return None\n",
        "apps/shared/auth.py": "def verify(): return True\n",
        "apps/core/main.py": """from fastapi import FastAPI
import firestore_client
import auth
from google.cloud import storage

app = FastAPI()

@app.get("/health")
def health():
    return {"status": "ok"}
""",
        "apps/core/requirements.txt": reqs,
    }
    gatekeeper = SynthesisVerifierAgent(product_id="testplan02-a")
    cured, passed, errors = gatekeeper.verify_and_cure(files, product_id="testplan02-a")
    assert passed is True, f"Gatekeeper failed: {errors}"
    # add-only: the AI's lines are a byte prefix; only the AST-proven SDK is appended
    assert cured["apps/core/requirements.txt"] == reqs + "google-cloud-storage>=2.14.0\n"
    msgs = [d.message for d in PythonLayoutValidator().validate(ValidationContext.build(cured, ownership=lambda p: None))
            if d.code == "REQ.LOCAL_MODULE_NAME"]
    # exact: `firestore_client` / `auth` are modules of apps/shared; `contracts` names nothing in this tree (no guess)
    assert len(msgs) == 2 and "'auth'" in msgs[0] and "'firestore-client'" in msgs[1], msgs


def test_gatekeeper_verifier_auto_injects_and_compiles():
    """Verifies that Gatekeeper auto-injects missing dependencies and passes compilation."""
    raw_py = """import os
from fastapi import FastAPI
from google.cloud import storage
import yaml

app = FastAPI()

@app.get("/")
def read_root():
    return {"status": "ok"}
"""
    files = {
        "apps/my-service/main.py": raw_py,
        "apps/my-service/requirements.txt": "fastapi>=0.110.0\n",
    }

    gatekeeper = SynthesisVerifierAgent(product_id="my-service")
    cured, passed, errors = gatekeeper.verify_and_cure(files, product_id="my-service")

    assert passed is True
    assert len(errors) == 0

    reqs = cured["apps/my-service/requirements.txt"]
    assert "google-cloud-storage>=2.14.0" in reqs
    assert "PyYAML>=6.0.1" in reqs
    # Step 2 S2-A (HS-09): the gatekeeper no longer writes a Procfile (the developer stage's V3c reports a missing one)
    assert "apps/my-service/Procfile" not in cured
    assert cured["apps/my-service/main.py"] == raw_py
    # FD-55 W5 (G23): the verifier's container-contract twin is deleted; the runtime pin is the developer stage's
    # enforce_container_contract (one rule), so the gatekeeper writes no .python-version
    assert "apps/my-service/.python-version" not in cured


def test_detect_services_ignores_init_and_shared_libraries():
    """
    Verifies that detect_services does NOT misclassify apps/__init__.py, flat files,
    or shared library directories (shared, common, contracts, schemas) as microservices,
    and that in-memory compilation succeeds without [Errno 21] directory collisions.
    """
    files = {
        "apps/__init__.py": "# auto generated\n",
        "apps/shared/models.py": "class SharedModel: pass\n",
        "apps/common/utils.py": "def util(): pass\n",
        "apps/core/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
        "apps/gateway/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
    }
    gatekeeper = SynthesisVerifierAgent(product_id="testplan02-a")
    services = gatekeeper.detect_services(files)
    assert services == ["core", "gateway"], f"Expected ['core', 'gateway'], got {services}"

    # Verify verify_and_cure does not generate Procfile or .python-version under apps/__init__.py
    cured, passed, errors = gatekeeper.verify_and_cure(files, product_id="testplan02-a")
    assert passed is True, f"Compilation failed: {errors}"
    assert "apps/__init__.py/Procfile" not in cured
    assert "apps/__init__.py/.python-version" not in cured
    # Step 2 S2-A (HS-09): no Procfile is written any more; FD-55 W5 (G23): nor a .python-version (the developer
    # stage's enforce_container_contract is the one runtime-pin rule)
    assert "apps/core/.python-version" not in cured and "apps/gateway/.python-version" not in cured
    assert "apps/core/Procfile" not in cured and "apps/gateway/Procfile" not in cured
    assert "apps/shared/.python-version" not in cured and "apps/common/.python-version" not in cured


if __name__ == "__main__":
    test_pypi_resolver()
    print("test_pypi_resolver: PASSED")
    test_gatekeeper_verifier_auto_injects_and_compiles()
    print("test_gatekeeper_verifier_auto_injects_and_compiles: PASSED")
    test_detect_services_ignores_init_and_shared_libraries()
    print("test_detect_services_ignores_init_and_shared_libraries: PASSED")
    print("\n🎉 ALL GATEKEEPER UNIT TESTS PASSED!")
