"""
Unit tests for Implementation Plan 02: Deterministic Container Contract & Buildpack Enforcement.
Verifies all 7 hardening protections across developer agents, sanitizers, and container contracts.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import os
import sys
import unittest
import ast
from unittest.mock import MagicMock

# Ensure mocks for third-party libs if not installed in host environment
for m in [
    'httpx', 'fastapi', 'fastapi.responses', 'fastapi.staticfiles', 'google', 'google.genai',
    'google.genai.types', 'google.cloud', 'google.cloud.firestore',
    'google.cloud.storage', 'google.cloud.logging', 'google.cloud.pubsub_v1',
    'github', 'jwt', 'pydantic'
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_PATH = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
if GATEWAY_PATH not in sys.path:
    sys.path.insert(0, GATEWAY_PATH)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from developer_agent.handler import (
    enforce_container_contract,
    detect_workload_services,
)
# FD-55 W1 (FD55-W1): the gateway's sanitize_github_workflow (no production caller) is deleted; its idempotence and
# expression-integrity cases now run on the terraform server's live apply-time copy (tests/test_fd55_w1_dead_code.py).

class TestContainerContractHardening(unittest.TestCase):

    def test_ai_procfile_is_never_overwritten(self):
        """S2-A (HS-09) tombstone of Protection 1: the AI's Procfile is kept as written (V3c reports an unbound PORT
        as CONTAINER.PORT_NOT_BOUND instead of the old rewrite to ${PORT:-8080}); a missing one is not invented."""
        files = {
            "apps/myapi/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "apps/myapi/Procfile": "web: uvicorn main:app --port 8000\n",
            "apps/other/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
        }
        enforce_container_contract(files, "myapi", archetype="cloudrun")
        self.assertEqual(files["apps/myapi/Procfile"], "web: uvicorn main:app --port 8000\n")
        self.assertNotIn("apps/other/Procfile", files)

    def test_strict_dockerfile_purge(self):
        """Protection 2: Verify that any generated Dockerfile is strictly purged (Buildpacks exclusivity)."""
        files = {
            "apps/myapi/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "apps/myapi/Dockerfile": "FROM python:3.11\nCMD ['python', 'main.py']\n",
            "Dockerfile": "FROM alpine\n",
            "Dockerfile.dev": "FROM alpine\n",
        }
        enforce_container_contract(files, "myapi", archetype="cloudrun")
        self.assertNotIn("apps/myapi/Dockerfile", files)
        self.assertNotIn("Dockerfile", files)
        self.assertNotIn("Dockerfile.dev", files)

    def test_universal_multi_microservice_scaffolding(self):
        """Protection 3 (kept parts): every service in apps/*/ receives .python-version; the Procfile is no longer
        platform-written (HS-09) and (FD-4AD) no requirements.txt is written or rewritten here (HB-28 deleted)."""
        files = {
            "apps/frontend/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "apps/backend-api/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "apps/worker-job/main.py": "import time\nprint('working')\n",
        }
        enforce_container_contract(files, "myproduct", archetype="cloudrun")

        for svc in ("frontend", "backend-api"):
            self.assertEqual(files[f"apps/{svc}/.python-version"], "3.13\n")
            self.assertNotIn(f"apps/{svc}/Procfile", files)
            self.assertNotIn(f"apps/{svc}/requirements.txt", files)

        self.assertEqual(files[".python-version"], "3.13\n")

    def test_health_injection_deleted_main_py_byte_identical(self):
        """S2-A (HS-09) tombstone of Protection 5: a main.py without /health is no longer edited (V3c reports
        CONTAINER.HEALTH_ROUTE_MISSING); ensure_health_check_endpoint is gone."""
        import developer_agent.handler as h
        self.assertFalse(hasattr(h, "ensure_health_check_endpoint"))
        raw_code = """from fastapi import FastAPI

app = FastAPI(title="Demo")

@app.get("/")
def read_root():
    return {"hello": "world"}
"""
        files = {"apps/myproduct/main.py": raw_code}
        enforce_container_contract(files, "myproduct", archetype="cloudrun")
        self.assertEqual(files["apps/myproduct/main.py"], raw_code)

    def test_valid_service_with_health_is_byte_identical(self):
        """Do-No-Harm (HS-09): a valid service (AI Procfile + /health + PORT) keeps its Procfile and main.py."""
        main = """from fastapi import FastAPI
app = FastAPI()

@app.get("/health")
def custom_health():
    return {"status": "ok", "custom": True}
"""
        files = {"apps/svc/main.py": main, "apps/svc/Procfile": "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n"}
        enforce_container_contract(files, "svc", archetype="cloudrun")
        self.assertEqual(files["apps/svc/main.py"], main)
        self.assertEqual(files["apps/svc/Procfile"], "web: uvicorn main:app --host 0.0.0.0 --port $PORT\n")

    def test_worker_procfile_is_the_ai_s(self):
        """S2-A (HS-09) tombstone of Protection 6: no Procfile is invented for a worker either; an AI worker
        Procfile stays as written."""
        files = {
            "apps/data-worker/main.py": "import time\nprint('Worker running')\n",
        }
        enforce_container_contract(files, "data-worker", archetype="event_worker")
        self.assertNotIn("apps/data-worker/Procfile", files)
        files = {"apps/data-worker/main.py": "print(1)\n", "apps/data-worker/Procfile": "worker: python main.py\n"}
        enforce_container_contract(files, "data-worker", archetype="cloudrun")
        self.assertEqual(files["apps/data-worker/Procfile"], "worker: python main.py\n")

    def test_static_directory_gitkeep_scaffolding(self):
        """Protection 7: Verify static/.gitkeep is scaffolded if StaticFiles is mounted."""
        files = {
            "apps/portal/main.py": """from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
""",
        }
        enforce_container_contract(files, "portal", archetype="cloudrun")
        self.assertIn("apps/portal/static/.gitkeep", files)

    def test_container_path_and_requirements_rewrites_are_deleted(self):
        """FD-4AD: HB-42 `sanitize_python_paths` (regex rewrite of `apps/<svc>/static` literals and monorepo imports,
        run after validation in the direct-commit fallback) and HB-28 `standardize_requirements` are gone; the AI's
        main.py and requirements.txt pass enforce_container_contract byte-identical."""
        import developer_agent.handler as h
        self.assertFalse(hasattr(h, "sanitize_python_paths"))
        self.assertFalse(hasattr(h, "standardize_requirements"))
        main = ('templates = Jinja2Templates(directory="apps/myportal/templates")\n'
                'from apps.myportal.config import settings\n')
        reqs = "requests>=2.31.0\npandas==2.2.0\ngoogle-cloud\nfastapi==0.100.0\n"
        files = {"apps/myportal/main.py": main, "apps/myportal/requirements.txt": reqs}
        enforce_container_contract(files, "myportal", archetype="cloudrun")
        self.assertEqual(files["apps/myportal/main.py"], main)
        self.assertEqual(files["apps/myportal/requirements.txt"], reqs)

    def test_node_service_gets_no_requirements_txt(self):
        """FD-4AD (HB-28/HB-29 rest): a Node service is never given a requirements.txt (it changed Buildpacks
        language detection); the add-only requirements contract only covers services with `.py` files."""
        from gatekeeper_agent.verifier import SynthesisVerifierAgent
        files = {"apps/web/package.json": '{"name": "web"}\n', "apps/web/server.js": "console.log(1)\n",
                 "apps/api/main.py": "from fastapi import FastAPI\napp = FastAPI()\n"}
        enforce_container_contract(files, "prod", archetype="cloudrun")
        cured, _, _ = SynthesisVerifierAgent("prod").verify_and_cure(dict(files), product_id="prod")
        self.assertNotIn("apps/web/requirements.txt", files)
        self.assertNotIn("apps/web/requirements.txt", cured)
        self.assertEqual(cured["apps/api/requirements.txt"], "fastapi>=0.110.0\n")   # created: proven need only

    def test_root_auxiliary_assets_are_not_vendored_into_services(self):
        """FD-4AD (HB-32): root scripts / contracts / pipelines are no longer copied into each service (hierarchically
        and flat by basename). 0 of the 87 real 10-18 drafts had a service importing a vendored path, and 133 flat
        copies landed beside a same-stem local package. Only missing package inits are added."""
        from gatekeeper_agent.verifier import SynthesisVerifierAgent

        def validate_and_heal_python_packages(files):   # FD-55 W5 (G26): the gatekeeper's pass is the one rule
            return SynthesisVerifierAgent(product_id="myapi").purge_shadowed_package_files(dict(files))
        files = {
            "apps/myapi/main.py": "from fastapi import FastAPI\napp = FastAPI()\n",
            "scripts/worker_pipeline.py": "# pipeline code\n",
            "contracts/schemas.py": "# contract schema code\n",
            "pipelines/etl.py": "# etl pipeline code\n",
        }
        healed, actions = validate_and_heal_python_packages(dict(files))
        for path, text in files.items():
            self.assertEqual(healed[path], text)
        self.assertEqual(sorted(p for p in healed if p.startswith("apps/myapi/")),
                         ["apps/myapi/__init__.py", "apps/myapi/main.py"])


if __name__ == "__main__":
    unittest.main()


