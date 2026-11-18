"""Wave 1 lane 8 (FD-4AX): no default Cloud SQL password literal; generated password survives the full pipeline.

- Literal scan (red-team F5/H5): the WHOLE right-hand side of every password-like attribute in every golden module
  copy, built-in module payload and built-in bundle is scanned; any non-empty quoted literal that is not purely an
  interpolation fails. The old defect line (`password = var.db_password != "" ? var.db_password : "<literal>"`)
  is caught. Matches are reported as file:line only, never the text.
- sha256 tombstone: the removed literal must not appear in any tracked text file (digest only, never the value).
- End-to-end (red-team F1/H1): a generated Cloud SQL workload goes through DeveloperAgent.generate_code_files
  (verifier, healers, preflight, self_correct_hcl) and the vendored module, random_password included, is
  byte-identical and the output passes preflight.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)
import hashlib
import os
import re
import subprocess
import sys
import unittest
from unittest.mock import MagicMock, patch

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATEWAY_PATH = os.path.join(REPO_ROOT, "apps", "orchestrator-gateway")
for p in (GATEWAY_PATH, REPO_ROOT):
    if p not in sys.path:
        sys.path.insert(0, p)

for m in [
    "httpx", "fastapi", "fastapi.responses", "google", "google.genai", "google.genai.types", "google.cloud",
    "google.cloud.firestore", "google.cloud.storage", "google.cloud.logging", "google.cloud.pubsub_v1", "github", "jwt",
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

MODULE_COPIES = ["infra/modules/database-cloudsql", "apps/control-center/infra/modules/database-cloudsql"]
PAYLOAD_COPIES = [
    "shared/builtin_modules_payload.py",
    "apps/control-center/shared/builtin_modules_payload.py",
    "apps/orchestrator-gateway/shared/builtin_modules_payload.py",
    "mcp-servers/terraform/shared/builtin_modules_payload.py",
]
BUNDLE_PAYLOAD = "shared/builtin_bundles_payload.py"
# sha256 of the 24-character literal removed by FD-4AX (git history before lane 8). Never store the value.
REMOVED_LITERAL_SHA256 = "3ed24eed2474ea843a014449fbcd951741c1d09b55ef6d2c4a73418274dce2be"
REMOVED_LITERAL_LEN = 24

_ATTR = re.compile(r"^\s*\"?([A-Za-z0-9_]+)\"?\s*=\s*(.+)$")
_VAR = re.compile(r'^\s*variable\s+"([^"]+)"')
_QUOTED = re.compile(r'"((?:[^"\\]|\\.)*)"')
_INTERP = re.compile(r"\$\{[^}]*\}")


def _is_password_attr(name: str) -> bool:
    n = name.lower()
    return n in ("password", "secret_data", "initial_user_password") or n.endswith("_password")


def _literal_violations(text: str):
    """Line numbers where a password-like attribute (or a password variable default) has a quoted literal."""
    bad = []
    in_password_var = False
    for lineno, line in enumerate(text.splitlines(), 1):
        v = _VAR.match(line)
        if v:
            in_password_var = "password" in v.group(1).lower()
            continue
        if line.startswith("}"):
            in_password_var = False
        m = _ATTR.match(line)
        if not m:
            continue
        name, rhs = m.group(1), m.group(2)
        if not (_is_password_attr(name) or (in_password_var and name == "default")):
            continue
        for q in _QUOTED.finditer(rhs):
            if _INTERP.sub("", q.group(1)).strip():
                bad.append(lineno)
                break
    return bad


def _hcl_sources():
    """(label, text) for every golden module .tf copy, built-in payload entry and built-in bundle file."""
    out = []
    for base in ("infra/modules", "apps/control-center/infra/modules"):
        for root, _, names in os.walk(os.path.join(REPO_ROOT, base)):
            for n in names:
                if n.endswith(".tf"):
                    full = os.path.join(root, n)
                    with open(full, encoding="utf-8") as f:
                        out.append((os.path.relpath(full, REPO_ROOT), f.read()))
    for rel in PAYLOAD_COPIES:
        ns = {}
        with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as f:
            exec(compile(f.read(), rel, "exec"), ns)  # noqa: S102 - repo-owned data module
        for mod_id, fdict in ns["BUILTIN_MODULE_FILES"].items():
            for fname, content in fdict.items():
                out.append((f"{rel}[{mod_id}/{fname}]", content))
    from shared.builtin_bundles_payload import BUILTIN_BUNDLES

    for bundle_id, record in BUILTIN_BUNDLES.items():
        for fname, content in record.hcl_files.items():
            out.append((f"{BUNDLE_PAYLOAD}[{bundle_id}/{fname}]", content))
    return out


class TestNoPasswordLiterals(unittest.TestCase):
    def test_scanner_catches_the_fd4ax_defect_shape(self):
        # Synthetic stand-in with the exact shape of the removed line (the real value is never in this repo again).
        defect = 'resource "google_sql_user" "user" {\n  password = var.db_password != "" ? var.db_password : "Xx-not-the-real-one-0001"\n}\n'
        self.assertEqual(_literal_violations(defect), [2])
        self.assertEqual(_literal_violations('variable "db_password" {\n  default = "hunter2-literal"\n}\n'), [2])

    def test_scanner_allows_empty_and_interpolations(self):
        ok = (
            'variable "db_password" {\n  default = ""\n  sensitive = true\n}\n'
            "resource \"x\" \"y\" {\n  password = local.db_password\n  secret_data = \"${random_password.db.result}\"\n"
            '  initial_user_password = var.p != "" ? var.p : random_password.db.result\n}\n'
        )
        self.assertEqual(_literal_violations(ok), [])

    def test_no_password_literal_in_any_golden_module_payload_or_bundle(self):
        offenders = []
        for label, text in _hcl_sources():
            offenders += [f"{label}:{n}" for n in _literal_violations(text)]
        self.assertEqual(offenders, [], "quoted password literal(s) found (file:line only)")

    def test_removed_literal_absent_from_all_tracked_text_files(self):
        files = subprocess.run(["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True).stdout.split("\n")
        splitter = re.compile(r"[\s\"'\\`]+")
        hits = set()
        for rel in files:
            full = os.path.join(REPO_ROOT, rel)
            if not rel or not os.path.isfile(full):
                continue
            try:
                with open(full, encoding="utf-8") as f:
                    text = f.read()
            except (UnicodeDecodeError, OSError):
                continue
            for tok in splitter.split(text):
                for i in range(len(tok) - REMOVED_LITERAL_LEN + 1):
                    if hashlib.sha256(tok[i:i + REMOVED_LITERAL_LEN].encode()).hexdigest() == REMOVED_LITERAL_SHA256:
                        hits.add(rel)
                        break
        self.assertEqual(sorted(hits), [], "removed FD-4AX literal is back (paths only)")


class TestCloudSqlModuleContract(unittest.TestCase):
    def _read(self, base, name):
        with open(os.path.join(REPO_ROOT, base, name), encoding="utf-8") as f:
            return f.read()

    def test_module_copies_identical_and_generate_password(self):
        names = ("main.tf", "variables.tf", "outputs.tf")
        for name in names:
            self.assertEqual(self._read(MODULE_COPIES[0], name), self._read(MODULE_COPIES[1], name), name)
        main = self._read(MODULE_COPIES[0], "main.tf")
        self.assertIn('resource "random_password" "db"', main)
        self.assertIn('source = "hashicorp/random"', main)
        self.assertIn('resource "google_secret_manager_secret_version" "db_password"', main)
        self.assertIn("password = local.db_password", main)
        self.assertNotIn("google_project_service", main)  # Secret Manager API is enabled by vending (F16)
        outputs = self._read(MODULE_COPIES[0], "outputs.tf")
        self.assertIn('output "secret_id_password"', outputs)
        self.assertNotIn("random_password", outputs)
        self.assertNotIn("local.db_password", outputs)

    def test_payload_entry_equals_disk_in_all_four_copies(self):
        disk = {n: self._read(MODULE_COPIES[0], n) for n in ("main.tf", "variables.tf", "outputs.tf")}
        for rel in PAYLOAD_COPIES:
            ns = {}
            with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as f:
                exec(compile(f.read(), rel, "exec"), ns)  # noqa: S102
            self.assertEqual(ns["BUILTIN_MODULE_FILES"]["database-cloudsql"], disk, rel)

    def test_advertised_contract_output_now_exists(self):
        from developer_agent.contract_inspector import get_golden_module_contract

        contract = get_golden_module_contract("database-cloudsql", force_refresh=True)
        self.assertIn("secret_id_password", contract)


CUSTOM_TF = '''module "db" {
  source               = "../modules/database-cloudsql"
  project_id           = var.project_id
  region               = var.region
  instance_name_suffix = "orders"
  database_name        = "orders_db"
  deletion_protection  = false
  workload_sa_email    = module.foundation.workload_sa_email
  depends_on           = [module.foundation]
}
'''


class TestCloudSqlWorkloadEndToEnd(unittest.TestCase):
    def _disk_module(self):
        out = {}
        for n in ("main.tf", "variables.tf", "outputs.tf"):
            with open(os.path.join(REPO_ROOT, MODULE_COPIES[0], n), encoding="utf-8") as f:
                out[f"infra/modules/database-cloudsql/{n}"] = f.read()
        return out

    def test_generate_code_files_keeps_module_and_random_password(self):
        from developer_agent.handler import DeveloperAgent

        # Lane 19 L19-3b (owner row 27a): the deleted template fallback used to supply the app; a fake model does now.
        from _lane19_fake_genai import FakeGenaiClient, canned_workload_files
        agent = DeveloperAgent()
        agent.genai_client = FakeGenaiClient(files=canned_workload_files("sqlapp"))
        with patch.dict(os.environ, {"ENABLE_DEVELOPER_SWARM": "false"}), \
                patch.object(agent, "fetch_existing_repo_files", return_value={"infra/workload/custom.tf": CUSTOM_TF}):
            files = agent.generate_code_files(
                product_id="sqlapp", spec_text="FastAPI orders service backed by Cloud SQL PostgreSQL", task_dag=[], allow_unauthenticated=True, enable_direct_iap=False, domain_restricted_sharing=False
            )
        for path, content in self._disk_module().items():
            self.assertEqual(files.get(path), content, path)
        self.assertIn('resource "random_password" "db"', files["infra/modules/database-cloudsql/main.tf"])
        self.assertIn('module "db"', files["infra/workload/custom.tf"])
        # FD-55 W4: the regex HCL pre-flight (preflight_validate_terraform) is deleted; V1b judges the tree


if __name__ == "__main__":
    unittest.main()
