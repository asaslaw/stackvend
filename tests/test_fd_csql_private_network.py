"""FD-CSQL: the Cloud SQL golden module can be created (Fable RT F3 of FD-4AZ-b, with F4/F5/F6).

- database-cloudsql: `private_network_id` (default null), `enable_public_ip` (default false), `ssl_mode` (validated,
  default ENCRYPTED_ONLY), a plan-time precondition that refuses "no private network and no public IP" (the Cloud SQL
  Admin API returns 400 for it at create), and a `private_ip_address` output.
- database-alloydb (F6): `network` defaults to null (was the bare name "default"), must be a network ID, and a
  plan-time precondition refuses a missing one.
- Express: a Cloud SQL / AlloyDB instance forces the VPC (networking-vpc, Private Services Access on by default),
  the subnet reads the IPAM fact var.subnet_cidr (value in infra/workload/terraform.tfvars, never a literal), and the
  database gets module.network.network_id + depends_on module.network. Without such a database the output is
  unchanged (Do No Harm).
- secure-three-tier-web bundle (F5): wired to the modules' real inputs/outputs; IP ranges are IPAM fact variables.

Real-engine tests use the production column (eval/.tools/tofu-1.9.0/tofu + eval/.tofu-mirror-prod, untracked) and
skip with a reason when it is not on this machine. `tofu test` runs plan-only against mock providers (no GCP, no
apply), under the TofuRunner network sandbox.
"""
import hermetic_guard  # noqa: F401  (first import)

import ipaddress
import os
import shutil
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
for p in (REPO_ROOT, os.path.join(REPO_ROOT, "eval")):
    if p not in sys.path:
        sys.path.insert(0, p)

hcl2 = pytest.importorskip("hcl2", reason="python-hcl2 (gateway requirement) not installed")

from shared.express_synthesizer import ExpressHCLSynthesizer  # noqa: E402

MODULE_TREES = ["infra/modules", "apps/control-center/infra/modules"]
PAYLOAD_DIRS = ["shared", "apps/orchestrator-gateway/shared", "apps/control-center/shared", "mcp-servers/terraform/shared"]
EXPRESS_COPIES = ["shared", "apps/control-center/shared", "apps/orchestrator-gateway/shared"]
TOUCHED = ["database-cloudsql", "database-alloydb"]
BUNDLE = "secure-three-tier-web"
BUNDLE_MODULES = ["networking-vpc", "database-cloudsql", "compute-cloudrun", "security-secret", "security-kms"]
PROD_TOFU = os.path.join(REPO_ROOT, "eval", ".tools", "tofu-1.9.0", "tofu")
PROD_MIRROR = os.path.join(REPO_ROOT, "eval", ".tofu-mirror-prod")
NET_ID = "projects/fdcsql-test/global/networks/fdcsql-vpc"
FACT = "10.100.7.0/24"   # a test IPAM allocation (tests only)

# The pre-FD-CSQL Express network block (include_vpc / networking-vpc instance without a private-IP database),
# with EXP-2's canonical source line (`source = "../modules/<name>"` + blank line; the arguments are unchanged).
LEGACY_NETWORK_BLOCK = '''module "network" {
  source = "../modules/networking-vpc"

  project_id   = var.project_id
  region       = var.region
  network_name = "${var.product_id}-vpc"
  depends_on   = [module.foundation]
}'''


def _read(rel):
    with open(os.path.join(REPO_ROOT, rel), encoding="utf-8") as f:
        return f.read()


def _exec(rel, name):
    ns = {}
    exec(compile(_read(rel), rel, "exec"), ns)  # noqa: S102 - repo-owned data module
    return ns[name]


def _resource(doc, rtype, name):
    for block in doc.get("resource", []):
        if rtype in block and name in block[rtype]:
            return block[rtype][name]
    raise KeyError(f"{rtype}.{name}")


def _variables(text):
    return {n: b for block in hcl2.loads(text).get("variable", []) for n, b in block.items()}


def _modules(text):
    return {n: b for block in hcl2.loads(text).get("module", []) for n, b in block.items()}


def _inst(mid, name, params=None):
    return {"module_id": mid, "instance_name": name, "parameters": params or {}}


def _synth(instances, **kw):
    return ExpressHCLSynthesizer().synthesize_workload(product_id="fdcsql", project_id="p-1",
                                                      module_instances=instances, **kw)


# ------------------------------------------------------------------------------------------------ module (static)
@pytest.mark.parametrize("tree", MODULE_TREES)
def test_cloudsql_ip_configuration_reads_the_new_inputs(tree):
    doc = hcl2.loads(_read(f"{tree}/database-cloudsql/main.tf"))
    inst = _resource(doc, "google_sql_database_instance", "instance")
    ipc = inst["settings"][0]["ip_configuration"][0]
    assert ipc == {"ipv4_enabled": "${var.enable_public_ip}", "private_network": "${var.private_network_id}",
                   "ssl_mode": "${var.ssl_mode}"}
    pre = inst["lifecycle"][0]["precondition"][0]
    assert pre["condition"] == "${var.enable_public_ip || var.private_network_id != null}"
    assert "private_network_id" in pre["error_message"] and "enable_public_ip" in pre["error_message"]


@pytest.mark.parametrize("tree", MODULE_TREES)
def test_cloudsql_defaults_private_and_tls(tree):
    v = _variables(_read(f"{tree}/database-cloudsql/variables.tf"))
    assert v["private_network_id"]["default"] is None
    assert v["enable_public_ip"]["default"] is False
    assert v["ssl_mode"]["default"] == "ENCRYPTED_ONLY"   # F8: the TLS default is read from the variable now
    outs = {n for block in hcl2.loads(_read(f"{tree}/database-cloudsql/outputs.tf")).get("output", []) for n in block}
    assert "private_ip_address" in outs


@pytest.mark.parametrize("tree", MODULE_TREES)
def test_alloydb_network_has_no_bare_name_default(tree):
    v = _variables(_read(f"{tree}/database-alloydb/variables.tf"))
    assert v["network"]["default"] is None
    cluster = _resource(hcl2.loads(_read(f"{tree}/database-alloydb/main.tf")), "google_alloydb_cluster", "cluster")
    assert cluster["lifecycle"][0]["precondition"][0]["condition"] == "${var.network != null}"


@pytest.mark.parametrize("mod", TOUCHED)
def test_module_trees_identical(mod):
    for fn in ("main.tf", "variables.tf", "outputs.tf"):
        assert _read(f"infra/modules/{mod}/{fn}") == _read(f"apps/control-center/infra/modules/{mod}/{fn}")


@pytest.mark.parametrize("rel_dir", PAYLOAD_DIRS)
@pytest.mark.parametrize("mod", TOUCHED)
def test_payload_entry_equals_disk(rel_dir, mod):
    payload = _exec(f"{rel_dir}/builtin_modules_payload.py", "BUILTIN_MODULE_FILES")[mod]
    disk_dir = os.path.join(REPO_ROOT, "infra/modules", mod)
    assert set(payload) == {f for f in os.listdir(disk_dir) if f.endswith(".tf")}
    for fn, text in payload.items():
        assert text == _read(f"infra/modules/{mod}/{fn}"), f"{rel_dir}: {mod}/{fn}"


def test_payload_copies_and_bundle_copies_identical():
    first = _read(f"{PAYLOAD_DIRS[0]}/builtin_modules_payload.py")
    assert all(_read(f"{d}/builtin_modules_payload.py") == first for d in PAYLOAD_DIRS[1:])
    b0 = _read(f"{PAYLOAD_DIRS[0]}/builtin_bundles_payload.py")
    assert all(_read(f"{d}/builtin_bundles_payload.py") == b0 for d in PAYLOAD_DIRS[1:])


def test_no_cidr_literal_in_touched_modules_or_bundle():
    def strings(node):
        if isinstance(node, str):
            yield node
        elif isinstance(node, dict):
            for v in node.values():
                yield from strings(v)
        elif isinstance(node, list):
            for v in node:
                yield from strings(v)

    def is_cidr(s):
        try:
            ipaddress.ip_network(s.strip('"'), strict=False)
            return "/" in s
        except ValueError:
            return False

    texts = [_read(f"infra/modules/{m}/{fn}") for m in TOUCHED for fn in ("main.tf", "variables.tf", "outputs.tf")]
    texts += list(_bundle_files().values())
    for t in texts:
        assert not [s for s in strings(hcl2.loads(t)) if is_cidr(s)]


@pytest.mark.parametrize("mod", TOUCHED)
def test_embedded_contract_fallback_matches_disk(mod):
    import importlib.util
    path = os.path.join(REPO_ROOT, "apps/orchestrator-gateway/developer_agent/contract_inspector.py")
    spec = importlib.util.spec_from_file_location("fdcsql_contract_inspector", path)
    ci = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ci)
    emb = ci._EMBEDDED_MODULE_CONTRACTS[mod]
    disk_in = set(_variables(_read(f"infra/modules/{mod}/variables.tf")))
    disk_out = {n for b in hcl2.loads(_read(f"infra/modules/{mod}/outputs.tf")).get("output", []) for n in b}
    assert set(emb["inputs"]) == disk_in and set(emb["outputs"]) == disk_out


# ------------------------------------------------------------------------------------------------ Express (static)
def test_express_replicas_identical():
    first = _read(f"{EXPRESS_COPIES[0]}/express_synthesizer.py")
    assert all(_read(f"{d}/express_synthesizer.py") == first for d in EXPRESS_COPIES[1:])


@pytest.mark.parametrize("include_vpc", [False, True])
def test_express_cloudsql_forces_vpc_and_wires_private_network(include_vpc):
    files = _synth([_inst("compute-cloudrun", "api"), _inst("database-cloudsql", "main_pg")],
                   include_vpc=include_vpc, subnet_cidr=FACT)
    mods = _modules(files["infra/workload/main.tf"])
    net = mods["network"]
    assert net["source"] == "../modules/networking-vpc"
    assert net["primary_subnet_cidr"] == "${var.subnet_cidr}"
    assert "enable_private_service_access" not in net   # module default true -> PSA range + peering connection
    db = mods["database_main_pg"]
    assert db["private_network_id"] == "${module.network.network_id}"
    assert db["depends_on"] == ["${module.foundation}", "${module.network}"]
    assert "enable_public_ip" not in db   # private IP only
    v = _variables(files["infra/workload/variables.tf"])
    assert "default" not in v["subnet_cidr"]
    assert files["infra/workload/terraform.tfvars"] == f'subnet_cidr = "{FACT}"\n'
    assert any(k.startswith("infra/modules/networking-vpc/") for k in files)


def test_express_without_allocation_fails_closed():
    files = _synth([_inst("database-cloudsql", "main_pg")])
    assert "subnet_cidr" in _variables(files["infra/workload/variables.tf"])
    assert "infra/workload/terraform.tfvars" not in files   # no value -> plan stops on the required variable


def test_express_rejects_a_non_cidr_allocation():
    with pytest.raises(ValueError):
        _synth([_inst("database-cloudsql", "main_pg")], subnet_cidr="10.100.7.1/24")


def test_express_alloydb_gets_network_and_product_id_explicit_wins():
    mods = _modules(_synth([_inst("database-alloydb", "adb")], subnet_cidr=FACT)["infra/workload/main.tf"])
    assert mods["mod_adb"]["network"] == "${module.network.network_id}"
    assert mods["mod_adb"]["product_id"] == "${var.product_id}"
    assert mods["mod_adb"]["depends_on"] == ["${module.foundation}", "${module.network}"]
    mods = _modules(_synth([_inst("database-alloydb", "adb", {"network": NET_ID, "product_id": "x"})],
                           subnet_cidr=FACT)["infra/workload/main.tf"])
    assert mods["mod_adb"]["network"] == NET_ID and mods["mod_adb"]["product_id"] == "x"


NO_PRIVATE_DB = {
    "default": dict(instances=None),
    "default_vpc": dict(instances=None, include_vpc=True),
    "vpc_instance": dict(instances=[_inst("networking-vpc", "net"), _inst("compute-cloudrun", "api")]),
    "multi": dict(instances=[_inst("compute-cloudrun", "api"), _inst("storage-bucket", "assets"),
                             _inst("messaging-pubsub", "events"), _inst("compute-event-worker", "jobs")],
                  include_vpc=True),
    "custom": dict(instances=[_inst("cache-redis", "c", {"memory_size_gb": 1}), _inst("database-spanner", "sp")]),
}


@pytest.mark.parametrize("case", sorted(NO_PRIVATE_DB))
def test_express_do_no_harm_without_private_database(case):
    kw = dict(NO_PRIVATE_DB[case])
    instances = kw.pop("instances")
    # A subnet allocation passed for a workload without a private-IP database is ignored.
    with_fact = _synth(instances, subnet_cidr=FACT, **kw)
    without = _synth(instances, **kw)
    assert with_fact == without
    assert "infra/workload/terraform.tfvars" not in without
    assert "subnet_cidr" not in without["infra/workload/variables.tf"]
    main = without["infra/workload/main.tf"]
    assert ("primary_subnet_cidr" not in main) and ("private_network_id" not in main)
    if 'module "network"' in main:
        assert LEGACY_NETWORK_BLOCK in main
    assert not ExpressHCLSynthesizer.requires_private_network(instances)


# ------------------------------------------------------------------------------------------------ Express route (IPAM)
class _Doc:
    def __init__(self, store, coll, doc_id):
        self.store, self.coll, self.id = store, coll, doc_id

    def get(self):
        data = self.store.get(self.coll, {}).get(self.id)
        snap = MagicMock()
        snap.exists = data is not None
        snap.to_dict.return_value = dict(data or {})
        return snap

    def set(self, data, merge=False):
        coll = self.store.setdefault(self.coll, {})
        coll[self.id] = {**coll.get(self.id, {}), **data} if merge else dict(data)


class _Coll:
    def __init__(self, store, name):
        self.store, self.name = store, name

    def document(self, doc_id):
        return _Doc(self.store, self.name, doc_id)

    def stream(self):
        out = []
        for doc_id, data in self.store.get(self.name, {}).items():
            snap = MagicMock()
            snap.id = doc_id
            snap.to_dict.return_value = dict(data)
            out.append(snap)
        return out


class FakeFirestore:
    """In-memory stand-in for the two collections the IPAM engine touches."""

    def __init__(self):
        self.store = {}

    def collection(self, name):
        return _Coll(self.store, name)


POOL = dict(supernet_cidr="10.100.0.0/16", prefix_len=24)   # test pool (the platform settings defaults)


@pytest.mark.parametrize("rel_dir", EXPRESS_COPIES)
def test_ipam_allocation_is_reused_per_workload(rel_dir, monkeypatch):
    import importlib.util
    import shared.ipam as ipam_mod   # the module express_synthesizer imports CastorIPAMEngine from
    from ipam_fake_firestore import FakeFirestore as TxFakeFirestore, fake_transactional
    monkeypatch.setattr(ipam_mod, "_default_transactional", lambda: fake_transactional)   # row IPAM-1
    spec = importlib.util.spec_from_file_location(f"xs_{rel_dir.replace('/', '_').replace('-', '_')}",
                                                  os.path.join(REPO_ROOT, rel_dir, "express_synthesizer.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    fs = TxFakeFirestore()   # row IPAM-1: allocation runs in a Firestore transaction
    synth = mod.ExpressHCLSynthesizer(db=fs)
    first = synth.allocate_subnet_cidr("Shop_App", "p-1", "us-central1", **POOL)
    again = synth.allocate_subnet_cidr("Shop_App", "p-1", "us-central1", **POOL)
    other = synth.allocate_subnet_cidr("other", "p-2", "us-central1", **POOL)
    assert first == again == "10.100.0.0/24" and other == "10.100.1.0/24"
    recs = fs.store["cidr_allocations"]
    assert len(recs) == 2 and {r["purpose"] for r in recs.values()} == {"WORKLOAD_SUBNET"}
    assert recs["10_100_0_0_24"]["product_id"] == "shop_app"   # ledger key normalized as the IPAM engine does
    assert recs["10_100_0_0_24"]["network_name"] == "shop-app-vpc"


def test_ipam_allocation_fails_closed():
    assert ExpressHCLSynthesizer(db=None).allocate_subnet_cidr("shop", "p-1", "us-central1", **POOL) is None
    broken = MagicMock()
    broken.collection.side_effect = RuntimeError("firestore down")
    # list_allocations swallows the read error (pre-existing engine behaviour); the write then raises -> None.
    assert ExpressHCLSynthesizer(db=broken).allocate_subnet_cidr("shop", "p-1", "us-central1", **POOL) is None


def test_route_passes_the_allocation_to_the_synthesizer():
    src = _read("apps/control-center/routes/workloads.py")
    assert "synthesizer.requires_private_network(module_instances)" in src
    assert "synthesizer.allocate_subnet_cidr(" in src and "subnet_cidr=subnet_cidr," in src


# ------------------------------------------------------------------------------------------------ real engine
@pytest.fixture(scope="module")
def runner(tmp_path_factory):
    if not (os.access(PROD_TOFU, os.X_OK) and os.path.isdir(PROD_MIRROR)):
        pytest.skip("production column eval/.tools/tofu-1.9.0/tofu + eval/.tofu-mirror-prod (untracked) not present")
    from stackvend_eval.tofu_runner import TofuRunner
    r = TofuRunner(tmp_path_factory.mktemp("fdcsql-tofu"), Path(PROD_MIRROR), tofu_bin=PROD_TOFU)
    if not r.mirror_ready:
        pytest.skip(f"production mirror not verified: {r.mirror_manifest['status']}")
    return r


def _init_validate(runner, wd):
    r = runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-2000:]
    r = runner._run(["validate", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-2000:]


def _tofu_test(runner, wd, test_hcl):
    (wd / "fdcsql_tests").mkdir()
    (wd / "fdcsql_tests" / "fdcsql.tftest.hcl").write_text(test_hcl, encoding="utf-8")
    _init_validate(runner, wd)
    r = runner._run(["test", "-test-directory=fdcsql_tests", "-filter=fdcsql_tests/fdcsql.tftest.hcl", "-no-color"],
                    cwd=wd)
    return r.returncode, r.stdout + r.stderr


CLOUDSQL_TEST = f'''mock_provider "google" {{}}
mock_provider "random" {{}}

variables {{
  project_id = "fdcsql-test"
}}

run "no_network_and_no_public_ip_is_refused_at_plan" {{
  command = plan
  plan_options {{
    target = [google_sql_database_instance.instance]
  }}
  expect_failures = [google_sql_database_instance.instance]
}}

run "private_network_plans_private_only" {{
  command = plan
  plan_options {{
    target = [google_sql_database_instance.instance]
  }}
  variables {{
    private_network_id = "{NET_ID}"
  }}
  assert {{
    condition     = google_sql_database_instance.instance.settings[0].ip_configuration[0].ipv4_enabled == false
    error_message = "private network path must not get a public IP"
  }}
  assert {{
    condition     = google_sql_database_instance.instance.settings[0].ip_configuration[0].private_network == "{NET_ID}"
    error_message = "private network must be wired"
  }}
  assert {{
    condition     = google_sql_database_instance.instance.settings[0].ip_configuration[0].ssl_mode == "ENCRYPTED_ONLY"
    error_message = "TLS must be required by default"
  }}
}}

run "explicit_public_ip_plans" {{
  command = plan
  plan_options {{
    target = [google_sql_database_instance.instance]
  }}
  variables {{
    enable_public_ip = true
  }}
  assert {{
    condition     = google_sql_database_instance.instance.settings[0].ip_configuration[0].ipv4_enabled == true
    error_message = "explicit public IP must be honoured"
  }}
}}

run "bare_network_name_is_refused" {{
  command = plan
  variables {{
    private_network_id = "default"
  }}
  expect_failures = [var.private_network_id]
}}

run "ssl_mode_is_validated" {{
  command = plan
  variables {{
    private_network_id = "{NET_ID}"
    ssl_mode           = "REQUIRE_TLS"
  }}
  expect_failures = [var.ssl_mode]
}}

run "mutual_tls_can_be_chosen" {{
  command = plan
  plan_options {{
    target = [google_sql_database_instance.instance]
  }}
  variables {{
    private_network_id = "{NET_ID}"
    ssl_mode           = "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"
  }}
  assert {{
    condition     = google_sql_database_instance.instance.settings[0].ip_configuration[0].ssl_mode == "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"
    error_message = "ssl_mode must be passed through"
  }}
}}
'''


def test_cloudsql_module_plans_and_refuses_at_production_set(runner, tmp_path):
    wd = tmp_path / "m"
    shutil.copytree(os.path.join(REPO_ROOT, "infra/modules/database-cloudsql"), wd)
    rc, out = _tofu_test(runner, wd, CLOUDSQL_TEST)
    assert rc == 0 and "6 passed, 0 failed" in out, out[-4000:]


ALLOYDB_TEST = f'''mock_provider "google" {{}}
mock_provider "random" {{}}

variables {{
  project_id = "fdcsql-test"
  product_id = "fdcsql"
}}

run "missing_network_is_refused_at_plan" {{
  command = plan
  plan_options {{
    target = [google_alloydb_cluster.cluster]
  }}
  expect_failures = [google_alloydb_cluster.cluster]
}}

run "bare_name_is_refused" {{
  command = plan
  variables {{
    network = "default"
  }}
  expect_failures = [var.network]
}}

run "network_id_plans" {{
  command = plan
  plan_options {{
    target = [google_alloydb_cluster.cluster]
  }}
  variables {{
    network = "{NET_ID}"
  }}
  assert {{
    condition     = google_alloydb_cluster.cluster.network_config[0].network == "{NET_ID}"
    error_message = "network must be wired"
  }}
}}
'''


def test_alloydb_module_plans_and_refuses_at_production_set(runner, tmp_path):
    wd = tmp_path / "m"
    shutil.copytree(os.path.join(REPO_ROOT, "infra/modules/database-alloydb"), wd)
    rc, out = _tofu_test(runner, wd, ALLOYDB_TEST)
    assert rc == 0 and "3 passed, 0 failed" in out, out[-4000:]


def _write_tree(files, root):
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")


# Mock network IDs in the real format (the mock provider's random strings are not network IDs).
MOCK_NETWORK = f'''mock_provider "google" {{
  mock_resource "google_compute_network" {{
    defaults = {{
      id = "{NET_ID}"
    }}
  }}
}}
'''

EXPRESS_TEST = f'''mock_provider "google" {{
  mock_resource "google_compute_network" {{
    defaults = {{
      id = "{NET_ID}"
    }}
  }}
  mock_resource "google_service_account" {{
    defaults = {{
      name  = "projects/fdcsql-test/serviceAccounts/workload-sa@fdcsql-test.iam.gserviceaccount.com"
      email = "workload-sa@fdcsql-test.iam.gserviceaccount.com"
    }}
  }}
  # The pool name in the real format: workload-foundation/base/iam.tf reads split("/", ...name)[1] (the project
  # number); the mock provider's random string has no "/" (Fable RT 10-24, FD-4CS).
  mock_resource "google_iam_workload_identity_pool" {{
    defaults = {{
      name = "projects/123456789012/locations/global/workloadIdentityPools/castor-gh-pool"
    }}
  }}
}}
mock_provider "google-beta" {{}}
mock_provider "random" {{}}

variables {{
  project_id  = "fdcsql-test"
  subnet_cidr = "{FACT}"
}}

run "cloudsql_on_the_workload_network_plans" {{
  command = plan
  plan_options {{
    target = [module.database_main_pg, module.network]
  }}
}}
'''


def _express_cloudsql_tree(tmp_path):
    files = _synth([_inst("compute-cloudrun", "api"), _inst("database-cloudsql", "main_pg")], subnet_cidr=FACT)
    _write_tree(files, tmp_path)
    wd = tmp_path / "infra" / "workload"
    (wd / "terraform.tfvars").unlink()   # tofu test takes the fact from its variables block
    return wd


def test_express_unmodified_output_validates(runner, tmp_path):
    """EXP-1 flipped the FD-CSQL pin: outputs.tf reads module.foundation.docker_repo_id (the module's real output),
    so the unmodified Express Cloud SQL tree passes `tofu validate` with no diagnostics."""
    wd = _express_cloudsql_tree(tmp_path)
    r = runner._run(["init", "-backend=false", "-input=false", "-no-color"], cwd=wd)
    assert r.returncode == 0, (r.stdout + r.stderr)[-2000:]
    r = runner._run(["validate", "-json", "-no-color"], cwd=wd)
    import json
    out = json.loads(r.stdout)
    assert r.returncode == 0 and out["valid"] is True and out["diagnostics"] == [], r.stdout[-3000:]


def test_express_cloudsql_workload_validates_and_plans(runner, tmp_path):
    wd = _express_cloudsql_tree(tmp_path)
    rc, out = _tofu_test(runner, wd, EXPRESS_TEST)
    assert rc == 0 and "1 passed, 0 failed" in out, out[-4000:]


def test_express_alloydb_workload_validates_and_plans(runner, tmp_path):
    files = _synth([_inst("database-alloydb", "adb")], subnet_cidr=FACT)
    _write_tree(files, tmp_path)
    wd = tmp_path / "infra" / "workload"
    (wd / "terraform.tfvars").unlink()
    test = EXPRESS_TEST.replace("[module.database_main_pg, module.network]", "[module.mod_adb, module.network]")
    rc, out = _tofu_test(runner, wd, test)
    assert rc == 0 and "1 passed, 0 failed" in out, out[-4000:]


def test_express_workload_without_the_network_line_is_refused_at_plan(runner, tmp_path):
    """Non-vacuity: the same workload minus the private_network_id wiring stops at the module precondition."""
    wd = _express_cloudsql_tree(tmp_path)
    main = (wd / "main.tf").read_text(encoding="utf-8")
    wiring = "  private_network_id   = module.network.network_id\n"
    assert main.count(wiring) == 1
    (wd / "main.tf").write_text(main.replace(wiring, ""), encoding="utf-8")
    rc, out = _tofu_test(runner, wd, EXPRESS_TEST)
    assert rc != 0 and "0 passed, 1 failed" in out, out[-4000:]
    assert "database-cloudsql: set private_network_id" in " ".join(out.split()), out[-4000:]


def _bundle_files():
    rec = _exec("shared/builtin_bundles_payload.py", "BUILTIN_BUNDLES")[BUNDLE]
    return dict(rec.hcl_files)


BUNDLE_TEST = MOCK_NETWORK + f'''mock_provider "google-beta" {{}}
mock_provider "random" {{}}

variables {{
  project_id            = "fdcsql-test"
  product_id            = "fdcsql"
  service_account_email = "workload-sa@fdcsql-test.iam.gserviceaccount.com"
  subnet_cidr           = "{FACT}"
  connector_cidr        = "10.100.8.0/28"
}}

run "bundle_database_on_the_private_network_plans" {{
  command = plan
  plan_options {{
    target = [module.database, google_vpc_access_connector.connector]
  }}
}}
'''


def test_bundle_validates_and_plans(runner, tmp_path):
    bundle_dir = tmp_path / "infra" / "bundles" / BUNDLE
    _write_tree({f"infra/bundles/{BUNDLE}/{fn}": t for fn, t in _bundle_files().items()}, tmp_path)
    for mod in BUNDLE_MODULES:
        shutil.copytree(os.path.join(REPO_ROOT, "infra/modules", mod), tmp_path / "infra" / "modules" / mod)
    rc, out = _tofu_test(runner, bundle_dir, BUNDLE_TEST)
    assert rc == 0 and "1 passed, 0 failed" in out, out[-4000:]
