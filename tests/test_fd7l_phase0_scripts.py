"""
FD-7L Phase 0 scripts (scripts/fd7l-phase0/): the offline scanners on fixtures, and the live script stays read-only.
Hermetic: nothing here calls gcloud or the network.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import importlib.util
import json
import os
import re
import subprocess

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DIR = os.path.join(REPO, "scripts", "fd7l-phase0")


def _load(name):
    spec = importlib.util.spec_from_file_location(f"fd7l_p0_{name}", os.path.join(DIR, f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_live_script_uses_only_read_commands():
    src = open(os.path.join(DIR, "phase0_reads.sh")).read()
    code = "\n".join(line for line in src.splitlines() if not line.lstrip().startswith("#"))
    allowed = {"run services describe", "run jobs describe", "iam service-accounts get-iam-policy", "services list",
               "resource-manager folders get-iam-policy", "projects get-iam-policy", "iam service-accounts list",
               "org-policies describe", "run jobs executions list", "logging read", "storage cat",
               "auth print-access-token", "projects describe"}
    calls = [" ".join(m.split()) for m in re.findall(r'(?<!")\bgcloud((?:[ \t]+[a-z][a-z-]*)*)', code)]
    used = {c for c in calls if c}
    bad = {c for c in used if not any(c == a or c.startswith(a + " ") for a in allowed)}
    assert used and not bad, bad
    # curl only GETs: no method override, no request body, no upload
    curl_lines = [line for line in code.splitlines() if "curl -" in line]
    assert len(curl_lines) == 2   # the GET helper and the public x509 certificate read
    for flag in ("-X ", "--request", "--data", " -d ", "--upload-file", " -T ", "--form", " -F "):
        assert not any(flag in line for line in curl_lines), flag
    assert "gsutil" not in code and "bq " not in code and "kubectl" not in code
    openssl = re.findall(r"\|\s*openssl\s+([^|)\"]*)", code)   # every openssl invocation reads a piped certificate
    assert openssl and all(o.split()[:2] == ["x509", "-noout"] for o in openssl), openssl   # reads certificates only
    assert subprocess.run(["bash", "-n", os.path.join(DIR, "phase0_reads.sh")]).returncode == 0


def test_live_script_hardcodes_no_install():
    src = open(os.path.join(DIR, "phase0_reads.sh")).read()
    assert "mock-stackvend-project" not in src
    assert not re.search(r"\b(us|europe|asia)-[a-z]+\d\b", src)


def _write(root, rel, text):
    path = os.path.join(root, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)


def test_repo_scan_finds_each_rule(tmp_path):
    rs = _load("repo_scan")
    root = str(tmp_path / "repo")
    _write(root, "infra/workload/backend.tf", 'terraform {\n  backend "gcs" {\n    bucket = "b"\n  }\n}\n')
    _write(root, "infra/workload/main.tf", (
        'terraform {\n  required_providers {\n    k8s = { source = "hashicorp/kubernetes" }\n'
        '    weird = { source = "acme/weird" }\n  }\n  encryption {}\n}\n'
        'provider "google" {\n  project = var.p\n  credentials = "x"\n}\n'
        'provider "k8s" {\n  host = "h"\n  dynamic "exec" {\n    for_each = [1]\n    content {}\n  }\n}\n'
        'provider "weird" {}\nprovider "random" {\n  alias = "r"\n}\n'
        'module "a" {\n  source = "./m"\n}\nmodule "b" {\n  source = "git::https://example.com/x"\n}\n'
        'data "terraform_remote_state" "o" {\n  backend = "gcs"\n}\n'))
    _write(root, "infra/workload/backend_override.tf", 'terraform {\n  backend "local" {}\n}\n')
    _write(root, "infra/workload/backend.tofu", 'terraform {}\n')
    _write(root, "infra/workload/broken.tf", 'resource "x" {\n')
    _write(root, "infra/workload/ok.tf.json", json.dumps({"provider": {"google": {"region": "r"}}}))
    findings, files, bad = rs.scan_repo(root, "infra/workload")
    rules = sorted((os.path.basename(f), r) for f, r, _ in findings)
    assert ("backend.tf", "BACKEND_NOT_PLATFORM") not in rules
    for expected in [("backend_override.tf", "BACKEND_NOT_PLATFORM"), ("backend_override.tf", "OVERRIDE_FILE"),
                     ("backend.tofu", "BACKEND_TOFU"), ("main.tf", "STATE_ENCRYPTION_FORBIDDEN"),
                     ("main.tf", "MODULE_SOURCE_NOT_LOCAL"), ("main.tf", "REMOTE_STATE"),
                     ("broken.tf", "UNPARSEABLE")]:
        assert expected in rules, expected
    details = [d for f, r, d in findings if r == "PROVIDER_ATTRIBUTE_FORBIDDEN"]
    assert any("credentials" in d for d in details) and any("exec" in d for d in details)
    assert any("'weird'" in d for d in details)
    assert not any("'random'" in d for d in details) and not any("ok.tf.json" in f for f, *_ in findings)
    assert files == 6 and bad == 1


def test_repo_scan_clean_generated_style_repo(tmp_path):
    rs = _load("repo_scan")
    root = str(tmp_path / "repo")
    _write(root, "infra/workload/main.tf", 'provider "google" {\n  project = var.project_id\n  region = var.region\n}\n'
                                         'module "app" {\n  source = "./modules/compute-cloudrun"\n}\n')
    findings, _files, _bad = rs.scan_repo(root, "infra/workload")
    assert findings == []


def test_state_scan(tmp_path):
    ss = _load("state_scan")
    state = {"version": 4, "resources": [
        {"mode": "managed", "type": "google_cloud_run_v2_service", "name": "app",
         "instances": [{"attributes": {"project": "own-proj-1", "secret": "s3cr3t"}}]},
        {"mode": "managed", "type": "google_dns_record_set", "name": "r", "module": "module.dns",
         "instances": [{"index_key": "a", "attributes": {"project": "host-proj-1"}}]},
        {"mode": "data", "type": "google_client_config", "name": "c",
         "instances": [{"attributes": {"access_token": "ya29.x", "project": "own-proj-1"}}]}]}
    (tmp_path / "shop.tfstate").write_text(json.dumps(state))
    (tmp_path / "shop.project").write_text("own-proj-1\n")
    cross, tokens, count = ss.scan_state("shop", state, "own-proj-1")
    assert cross == [('module.dns.google_dns_record_set.r["a"]', "google_dns_record_set", "host-proj-1")]
    assert tokens == ["data.google_client_config.c"] and count == 3
    out = subprocess.run(["python3", os.path.join(DIR, "state_scan.py"), str(tmp_path)], capture_output=True,
                         text=True)
    assert out.returncode == 1 and "s3cr3t" not in out.stdout and "ya29" not in out.stdout
    assert "cross_project=1" in out.stdout


def test_provider_schema_review(tmp_path):
    pr = _load("provider_schema_review")
    schema = {"provider_schemas": {"registry.opentofu.org/hashicorp/google": {
        "resource_schemas": {"google_x": {"block": {"attributes": {"name": {}, "custom_endpoint": {}},
                                                    "block_types": {"auth": {"block": {"attributes": {
                                                        "credentials": {}}}}}}}},
        "data_source_schemas": {"google_y": {"block": {"attributes": {"access_token": {}}}}}}}}
    p = tmp_path / "s.json"
    p.write_text(json.dumps(schema))
    out = subprocess.run(["python3", os.path.join(DIR, "provider_schema_review.py"), str(p)], capture_output=True,
                         text=True)
    assert out.returncode == 0
    assert "google_x custom_endpoint" in out.stdout and "google_x auth.credentials" in out.stdout
    assert "google_y access_token" in out.stdout and "listed=3" in out.stdout
    assert pr.REVIEW_SUFFIXES
