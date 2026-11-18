"""HOST-INTERNAL-INGRESS (owner 11-07): every caller of a host service is on the platform network, and nothing outside
the host project needs one.

With internal-only ingress, Cloud Run answers a call from a Cloud Run service or job that is NOT on the stackvend-host
network with 404 (no IAM check is reached). So:

  1. every release component whose code reads a host-service URL (VENDING_SERVICE_URL, GIT_SERVER_URL,
     TERRAFORM_MCP_URL / TERRAFORM_SERVICE_URL, COMPLIANCE_SERVER_URL, GATEWAY_URL, any *_MCP_URL / *_SERVICE_URL /
     *_SERVER_URL) or resolves one (resolve_service_url / _discover_cloud_run_service_url) must be in the VPC set
     (tests/test_internal_ingress_tf.py: every component except qa-sandbox-test-runner);
  2. the QA sandbox job (untrusted generated code, never on the network) reads none of them;
  3. plan §5 (git server special case, option A): child-project Cloud Build gets its source from a GCS tarball only
     (storageSource), never from castor-git-server, and the golden modules never name a host run.app URL.

A hand-kept caller matrix (plan §2.3) is checked against the scan in both directions, so the scan cannot pass
vacuously and a new caller is classified on purpose. Hermetic: AST/text reads only.
"""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import glob
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, ".."))
QA_JOB = "qa-sandbox-test-runner"

URL_ENVS = {"VENDING_SERVICE_URL", "GIT_SERVER_URL", "TERRAFORM_MCP_URL", "TERRAFORM_SERVICE_URL",
            "COMPLIANCE_SERVER_URL", "GATEWAY_URL"}
URL_ENV_FAMILY = re.compile(r"^[A-Z][A-Z0-9_]*_(MCP|SERVICE|SERVER)_URL$")
RESOLVERS = {"resolve_service_url", "_discover_cloud_run_service_url", "default_service_url_resolver"}

# Plan §2.3: components that call another host service (Cloud Run service or job callers). The scan below must find
# each of them; every one is on the network (main.tf dynamic "vpc_access").
EXPECTED_CALLERS = {
    "orchestrator-gateway-service",   # MCP servers, vending, git server
    "product-control-center-ui",      # vending, mcp-terraform-server, git server
    "project-repo-vending-service",   # mcp-terraform-server
    "mcp-terraform-server",           # vending (/runner/dispatch), compliance
    "tf-applier",                     # vending (broker), git server, compliance (same source as the terraform server)
    "sandbox-garbage-collector-job",  # vending
    "github-refactor-scanner-job",    # vending, git server
    "sre-telemetry-digest-job",       # log-sre-sentinel-service
}


def _read(p):
    with open(p, encoding="utf-8") as f:
        return f.read()


def _components():
    tree = ast.parse(_read(os.path.join(REPO, "shared", "release_manifest.py")))
    for node in ast.walk(tree):
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "COMPONENTS":
            return ast.literal_eval(node.value)
    raise AssertionError("COMPONENTS not found")


def _source_files(src_dir):
    for f in sorted(glob.glob(os.path.join(REPO, src_dir, "**", "*.py"), recursive=True)):
        base = os.path.basename(f)
        rel = os.path.relpath(f, REPO)
        if base.startswith("test_") or base == "conftest.py" or "/tests/" in rel or "/.venv/" in rel:
            continue
        # The component's replicated copy of shared/ (AGENTS.md: replicated files) carries every provider whether or
        # not the component uses it; the component's own modules decide what it calls.
        if rel.startswith(os.path.join(src_dir, "shared") + os.sep):
            continue
        yield f


def _host_url_reads(src_dir):
    """{evidence} for one component's source: URL env names it reads and resolver calls it makes."""
    hits = set()
    for f in _source_files(src_dir):
        try:
            tree = ast.parse(_read(f))
        except SyntaxError:
            continue
        for n in ast.walk(tree):
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and (n.value in URL_ENVS or URL_ENV_FAMILY.match(n.value)):
                hits.add(n.value)
            elif isinstance(n, (ast.Name, ast.Attribute)):
                # a call, or the resolver passed as a default (sre-digest: service_url_resolver=default_...)
                name = n.id if isinstance(n, ast.Name) else n.attr
                if name in RESOLVERS:
                    hits.add(name + "()")
    return hits


def _vpc_set():
    return {name for name, _, _ in _components()} - {QA_JOB}


def test_every_host_url_reader_is_on_the_platform_network():
    vpc = _vpc_set()
    off = {name: sorted(_host_url_reads(src)) for name, _, src in _components()
           if name not in vpc and _host_url_reads(src)}
    assert off == {}, f"components that call host services but are not on the stackvend-host network: {off}"


def test_the_qa_sandbox_job_reads_no_host_service_url():
    src = dict((n, s) for n, _, s in _components())[QA_JOB]
    assert _host_url_reads(src) == set()
    assert list(_source_files(src)), "the scan found no QA runner source (vacuous)"


def test_the_qa_sandbox_job_imports_no_shared_caller_module():
    """The QA scan skips its replicated shared/ copy, so its own modules must not import a shared module that calls
    a host service (the VCS providers, callbacks)."""
    src = dict((n, s) for n, _, s in _components())[QA_JOB]
    allowed = {"shared.path_safety"}
    for f in _source_files(src):
        for n in ast.walk(ast.parse(_read(f))):
            mods = []
            if isinstance(n, ast.ImportFrom) and n.module:
                mods = [n.module]
            elif isinstance(n, ast.Import):
                mods = [a.name for a in n.names]
            for m in mods:
                if m == "shared" or m.startswith("shared."):
                    assert m in allowed, (os.path.relpath(f, REPO), m)


def test_hand_kept_caller_matrix_is_found_by_the_scan():
    found = {name for name, _, src in _components() if _host_url_reads(src)}
    missing = EXPECTED_CALLERS - found
    assert not missing, f"matrix callers the scan no longer finds (update plan §2.3 and this matrix): {sorted(missing)}"
    assert EXPECTED_CALLERS <= _vpc_set()


def test_scan_negative_control(tmp_path):
    d = tmp_path / "comp"
    d.mkdir()
    (d / "a.py").write_text('import os\nX = os.environ.get("FOO_URL")\n')
    (d / "test_b.py").write_text('Y = "GIT_SERVER_URL"\n')            # test files are ignored
    assert _host_url_reads(str(d)) == set()
    (d / "c.py").write_text('Z = "MCP_GCLOUD_MCP_URL"\nresolve_service_url("x")\n')
    assert _host_url_reads(str(d)) == {"MCP_GCLOUD_MCP_URL", "resolve_service_url()"}


# ------------------------------------------------------------------------------
# Plan §5: child-project builds never read the git server; golden modules never name a host URL
# ------------------------------------------------------------------------------
BUILD_PAYLOAD_FILES = ("mcp-servers/terraform/service.py", "mcp-servers/agent-builder/service.py")


def _cloud_build_payloads(path):
    """Every dict literal with a "steps" key (a Cloud Build `builds.create` body) and its enclosing function."""
    tree = ast.parse(_read(os.path.join(REPO, path)))
    out = []
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for n in ast.walk(fn):
            if isinstance(n, ast.Dict) and any(isinstance(k, ast.Constant) and k.value == "steps" for k in n.keys):
                out.append((fn, n))
    return out


def test_child_builds_use_storage_source_only():
    seen = 0
    for path in BUILD_PAYLOAD_FILES:
        for fn, d in _cloud_build_payloads(path):
            keys = {k.value: v for k, v in zip(d.keys, d.values) if isinstance(k, ast.Constant)}
            assert "source" in keys, (path, fn.name)
            src = keys["source"]
            assert isinstance(src, ast.Dict), (path, fn.name)
            assert [k.value for k in src.keys] == ["storageSource"], (path, fn.name)
            seen += 1
    assert seen >= 2, "expected the workload image build and the agent-builder packaging build"


def test_no_build_payload_function_references_the_git_server():
    for path in BUILD_PAYLOAD_FILES:
        text = _read(os.path.join(REPO, path))
        for fn, _ in _cloud_build_payloads(path):
            body = ast.get_source_segment(text, fn) or ""
            for needle in ("GIT_SERVER_URL", "castor-git-server", "git_server_url"):
                assert needle not in body, (path, fn.name, needle)


def test_golden_modules_never_name_a_host_url():
    files = [f for f in glob.glob(os.path.join(REPO, "infra", "modules", "**", "*"), recursive=True)
             if os.path.isfile(f) and "/.terraform/" not in f]
    assert files
    for f in files:
        rel = os.path.relpath(f, REPO)
        text = _read(f) if f.endswith((".tf", ".json", ".yaml", ".yml", ".tpl", ".sh", ".md")) else ""
        assert "run.app" not in text, rel
        assert "castor-git-server" not in text and "GIT_SERVER_URL" not in text, rel


# ------------------------------------------------------------------------------
# Review F1: this branch cannot land without the Phase-1 upgrader fix (an ingress-blocked /validate/ready answers 404;
# without the INGRESS_INTERNAL branch every Update StackVend run would fail CHECK_FAILED after the flip)
# ------------------------------------------------------------------------------
def test_upgrader_stage_reports_internal_ingress_as_not_checked():
    tree = ast.parse(_read(os.path.join(REPO, "scripts", "upgrade", "stage.py")))
    fns = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert "service_ingress" in fns, "scripts/upgrade/stage.py must read the terraform server's ingress (Phase 1)"
    consts = [n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
    assert any("INGRESS_INTERNAL" in c for c in consts), "stage.py must report NOT_CHECKED INGRESS_INTERNAL"
    assert "INGRESS_TRAFFIC_INTERNAL_ONLY" in consts
