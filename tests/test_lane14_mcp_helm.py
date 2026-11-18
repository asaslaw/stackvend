"""Lane 14 PR-8 (I10): Helm build/staging contract + the shared MCP seam parity.

The Helm lifecycle itself is tested in mcp-servers/kubernetes/test_service.py (kubernetes MCP suite). Here: the
pin file carries no fabricated hash, the Cloud Build step and deploy-services staging verify SHA-256 before anything
is installed, and every copy of managed_target_seam.py stays identical. Static only: no network, no binary.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import json
from pathlib import Path

import hcl2

REPO = Path(__file__).resolve().parent.parent
PIN = REPO / "mcp-servers" / "kubernetes" / "helm-pin.json"


def test_seam_copies_are_identical():
    # FD-4L: the gcloud and github MCP servers carry the same seam (ledger target + approval rules).
    copies = {name: (REPO / "mcp-servers" / name / "managed_target_seam.py").read_bytes()
              for name in ("agent-builder", "kubernetes", "gcloud", "github")}
    assert len(set(copies.values())) == 1, sorted(copies)


def test_helm_pin_is_valid_json_and_never_a_made_up_hash():
    pin = json.loads(PIN.read_text())
    assert set(pin) >= {"version", "linux_amd64_sha256"}
    # Empty until the owner copies the official values; a non-empty pin must be complete and well-formed.
    if pin["version"] or pin["linux_amd64_sha256"]:
        assert pin["version"].startswith("v3.") and len(pin["linux_amd64_sha256"]) == 64


def test_deploy_services_staging_verifies_before_installing():
    # stage_helm lives in scripts/common/components.sh (shared with the upgrader, SELFUP P3b B2)
    src = (REPO / "scripts" / "common" / "components.sh").read_text()
    body = src[src.index("stage_helm() {"): src.index("sync_cc_modules() {")]
    assert body.index('if [ "${actual}" != "${sha}" ]') < body.index('install -m 0755')
    assert 'stage_helm "$2" || return 1' in src  # sv_component_prebuild (deploy_single and the upgrader)
    deploy = (REPO / "scripts" / "deploy-services.sh").read_text()
    assert 'sv_component_prebuild "${name}" "${dir}" || return 1' in deploy
    assert 'stage_helm "mcp-servers/kubernetes" || sv_die' in deploy


def test_rt_f19_staging_refuses_helm_older_than_v3_13():
    import subprocess
    import sys

    src = (REPO / "scripts" / "common" / "components.sh").read_text()
    body = src[src.index("stage_helm() {"): src.index("sync_cc_modules() {")]
    start = body.index("python3 -c '", body.index("RT F19")) + len("python3 -c '")
    check = body[start: body.index("' \"${version}\"", start)]
    assert body.index("RT F19") < body.index("curl -fsSL")  # checked before anything is downloaded
    for version, ok in (("v3.13.0", True), ("v3.16.2", True), ("v3.12.3", False), ("v4.0.0", False),
                        ("3.14.0", False), ("v3.x.1", False), ("v3.13", False)):
        rc = subprocess.run([sys.executable, "-c", check, version], capture_output=True,
                            env=hermetic_guard.child_env()).returncode
        assert (rc == 0) is ok, version


# RT F14: DiscoveryKindScope runs with the REAL kubernetes package. Other root tests stub or wrap kubernetes /
# requests in sys.modules, so the check runs in a fresh interpreter (hermetic child env); no cluster is contacted.
_DISCOVERY_CHECK = r'''
import inspect, os, sys
sys.path.insert(0, sys.argv[1])
import helm as helm_mod
import kubernetes.dynamic as dyn_mod
from kubernetes.dynamic.exceptions import ResourceNotFoundError

seen = {}

class _Resources:
    def get(self, api_version, kind):
        if kind == "Widget":
            raise ResourceNotFoundError("no")
        if kind == "Boom":
            raise RuntimeError("discovery down")
        return type("Res", (), {"namespaced": kind != "ClusterPolicy"})()

def factory(api_client, cache_file):
    seen["host"], seen["cache_file"] = api_client.configuration.host, cache_file
    seen["ca"] = open(api_client.configuration.ssl_ca_cert, "rb").read()
    return type("Dyn", (), {"resources": _Resources()})()

access = helm_mod.ClusterAccess("https://10.0.0.1", "tok", "Y2E=")
with helm_mod.DiscoveryKindScope(access, dynamic_client_factory=factory) as scope:
    assert scope("apps/v1", "Deployment") is True and scope("kyverno.io/v1", "ClusterPolicy") is False
    assert scope("example.com/v1", "Widget") is None
    try:
        scope("x/v1", "Boom")
        raise SystemExit("discovery error was not refused")
    except helm_mod.HelmRefused as e:
        assert e.code == "DISCOVERY_FAILED"
assert seen["host"] == "https://10.0.0.1" and seen["ca"] == b"ca"
assert not os.path.exists(seen["cache_file"])  # per-use discovery cache, removed on close

def broken(api_client, cache_file):
    raise RuntimeError("unreachable")

try:
    helm_mod.DiscoveryKindScope(access, dynamic_client_factory=broken).__enter__()
    raise SystemExit("an unreachable discovery was not refused")
except helm_mod.HelmRefused as e:
    assert e.code == "DISCOVERY_FAILED" and e.http_status == 502

# The default factory calls kubernetes.dynamic.DynamicClient(api_client, cache_file=...), a keyword the installed
# client has (DynamicClient itself is replaced: no cluster contacted).
assert "cache_file" in inspect.signature(dyn_mod.DynamicClient.__init__).parameters
calls = []
dyn_mod.DynamicClient = lambda client, cache_file=None: calls.append(cache_file) or object()
with helm_mod.DiscoveryKindScope(access):
    pass
assert len(calls) == 1 and calls[0].endswith("discovery.json")
print("DISCOVERY_OK")
'''


def test_rt_f14_discovery_scope_uses_the_dynamic_client_and_fails_closed():
    import subprocess
    import sys

    proc = subprocess.run([sys.executable, "-c", _DISCOVERY_CHECK, str(REPO / "mcp-servers" / "kubernetes")],
                          env=hermetic_guard.child_env(),
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0 and "DISCOVERY_OK" in proc.stdout, proc.stderr[-3000:]


def test_procfile_puts_the_baked_binary_first_on_path():
    assert (REPO / "mcp-servers" / "kubernetes" / "Procfile").read_text().startswith("web: env PATH=/workspace/bin:")
