"""
Unit tests for KubernetesService with mocked GKE and Kubernetes API endpoints.
"""

import sys
from unittest.mock import MagicMock, patch

for m in [
    'google', 'google.auth', 'google.auth.transport', 'google.auth.transport.requests',
    'google.cloud', 'google.cloud.container_v1', 'google.cloud.firestore',
    'kubernetes', 'kubernetes.client', 'kubernetes.client.exceptions',
]:
    if m not in sys.modules:
        sys.modules[m] = MagicMock()

import google.cloud
if not hasattr(google.cloud, "container_v1"):
    google.cloud.container_v1 = sys.modules['google.cloud.container_v1']

import pytest
from service import KubernetesService


# The three original tests (protected namespace, dry run, restart) are kept on the FD-4L contract (product_id + ledger
# target, typed refusals, server-side apply); see the FD-4L section at the end of this file for the fixture.


def test_protected_namespace_blocks_mutation(k8s_env):
    svc, calls = k8s_env
    with pytest.raises(helm_mod.HelmRefused) as exc:
        svc.apply_manifest(product_id="claims", cluster_name="claims-gke", location="us-east4",
                           namespace="kube-system", yaml_content="apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test")
    assert exc.value.code == "PROTECTED_NAMESPACE" and exc.value.http_status == 403
    assert calls.cluster == [] and calls.ssa == []


def test_apply_manifest_dry_run(k8s_env):
    svc, calls = k8s_env
    manifest = PAYMENT_DEPLOYMENT
    result = svc.apply_manifest(product_id="claims", cluster_name="claims-gke", location="us-east4",
                                namespace="castor-workload", yaml_content=manifest, dry_run=True)
    assert result["status"] == "DRY_RUN_PASSED" and result["http_status"] == 200
    assert result["resources_count"] == 1
    assert result["resources"][0]["name"] == "payment-service"
    assert result["resources"][0]["status"] == "VALIDATED"
    assert [dry for _, _, dry in calls.ssa] == [True]  # a dry run never reaches the real apply


def test_restart_deployment(k8s_env):
    svc, calls = k8s_env
    result = svc.restart_deployment(product_id="claims", cluster_name="claims-gke", location="us-east4",
                                    namespace="castor-workload", deployment_name="payment-service")
    assert result["status"] == "RESTART_TRIGGERED"
    assert result["deployment"] == "payment-service"
    assert "restarted_at" in result
    kw = calls.apps().patch_namespaced_deployment.call_args.kwargs
    assert kw["name"] == "payment-service" and kw["namespace"] == "castor-workload"
    assert calls.cluster == [(CHILD, "claims-gke", "us-east4")]

# ==============================================================================================================
# Lane 14 PR-8: Helm lifecycle (helm.py). Fake Helm runner + dict-backed Firestore; no cluster, no binary.
# ==============================================================================================================
import copy
import json as _json
import os
from datetime import datetime, timedelta, timezone

import helm as helm_mod
import managed_target_seam as seam_mod

HELM_NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)
CHILD = "claims-child-123"
OCI = f"oci://us-east4-docker.pkg.dev/{CHILD}/charts/claims-api"
DEPLOYMENT = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: api\nspec: {}\n"
SERVICE = "apiVersion: v1\nkind: Service\nmetadata:\n  name: api\n"


class _HSnap:
    def __init__(self, doc_id, data):
        self.id, self._d, self.exists = doc_id, data, data is not None

    def to_dict(self):
        return copy.deepcopy(self._d)


class _HColl:
    def __init__(self, store, name, flt=None):
        self.store, self.name, self.flt = store, name, flt

    def where(self, filter=None):  # noqa: A002
        return _HColl(self.store, self.name, filter)

    def limit(self, n):
        return self

    def stream(self):
        out = []
        for k, v in sorted(self.store.items()):
            if k.startswith(self.name + "/") and k.count("/") == 1:
                if self.flt is None or v.get(self.flt[0]) == self.flt[1]:
                    out.append(_HSnap(k.split("/", 1)[1], v))
        return out

    def document(self, doc_id):
        return _HDoc(self.store, f"{self.name}/{doc_id}")


class _HDoc:
    def __init__(self, store, path):
        self.store, self.path = store, path

    def get(self):
        return _HSnap(self.path.split("/")[-1], self.store.get(self.path))

    def set(self, data, merge=False):
        base = dict(self.store.get(self.path) or {}) if merge else {}
        base.update(copy.deepcopy(data))
        self.store[self.path] = base

    def create(self, data):
        if self.path in self.store:
            raise RuntimeError("409 AlreadyExists")
        self.store[self.path] = copy.deepcopy(data)


class _HDB:
    def __init__(self, store):
        self.store = store

    def collection(self, name):
        return _HColl(self.store, name)


class FakeHelm:
    """Answers by subcommand. `dry_hooks` / `dry_manifest` / `status_manifest` drive the scenarios."""

    def __init__(self, *, template=DEPLOYMENT, dry_manifest=DEPLOYMENT + "---\n" + SERVICE, dry_hooks=(),
                 status_manifest=None, revision=1, available=True):
        self.template, self.dry_manifest, self.dry_hooks = template, dry_manifest, list(dry_hooks)
        self.status_manifest = dry_manifest if status_manifest is None else status_manifest
        self.revision, self.available, self.calls = revision, available, []
        self.registry_hosts = []
        self.stored_manifest, self.stored_hooks = DEPLOYMENT, ""  # `helm get manifest|hooks --revision N`
        # `helm get` of the just-installed revision answers what the install produced (status_manifest + hooks);
        # rollback(N) tests that target another revision get stored_manifest/stored_hooks.
        self.installed_get, self.installed_hooks = True, None

    def binary(self):
        return "/workspace/bin/helm" if self.available else None

    def version(self):
        return "v3.16.2+gtest" if self.available else None

    def __call__(self, args, access, values=None, registry_host=None):
        self.calls.append((list(args), values))
        self.registry_hosts.append(registry_host)
        sub = args[0]
        if sub == "get":
            rev = int(args[args.index("--revision") + 1])
            if rev == self.revision and self.installed_get:  # the installed revision (RT R5 drift re-check)
                if args[1] == "manifest":
                    return 0, self.status_manifest, ""
                hooks = self.installed_hooks if self.installed_hooks is not None else self.dry_hooks
                return 0, "\n---\n".join(hooks), ""
            return 0, (self.stored_manifest if args[1] == "manifest" else self.stored_hooks), ""
        if sub == "template":
            return 0, self.template, ""
        if sub == "upgrade" and "--dry-run=server" in args:
            return 0, _json.dumps({"manifest": self.dry_manifest,
                                   "hooks": [{"manifest": h} for h in self.dry_hooks], "version": self.revision}), ""
        if sub == "upgrade":
            return 0, _json.dumps({"version": self.revision, "manifest": self.status_manifest}), ""
        if sub == "status":
            return 0, _json.dumps({"version": self.revision, "manifest": self.status_manifest,
                                   "hooks": [{"manifest": h} for h in self.dry_hooks], "info": {"status": "deployed"}}), ""
        if sub in ("rollback", "uninstall"):
            return 0, "", ""
        if sub in ("list", "history"):
            return 0, "[]", ""
        return 1, "", f"unexpected {sub}"

    def subcommands(self):
        return [c[0][0] + (":dry" if "--dry-run=server" in c[0] else "") for c in self.calls]


UNINSTALL_BINDING = {"cluster": "claims-gke", "location": "us-east4-b", "namespace": "claims", "release": "claims-api"}


def _approval(**over):
    rec = {"status": "APPROVED", "action": "HELM_UNINSTALL", "product_id": "claims", "project_id": CHILD,
           "principal_type": "USER", "approved_by_role": "ADMIN", "approved_by": "owner@example.com",
           "expires_at": (HELM_NOW + timedelta(hours=1)).isoformat(), "binding": dict(UNINSTALL_BINDING),
           "binding_digest": seam_mod.binding_digest(UNINSTALL_BINDING)}
    rec.update(over)
    return rec


class FakeDiscovery:
    """RT F14: what the cluster's API discovery answers (namespaced True/False; unknown kinds absent)."""

    KINDS = {("apps/v1", "Deployment"): True, ("v1", "Service"): True, ("v1", "ConfigMap"): True,
             ("v1", "Secret"): True, ("batch/v1", "Job"): True,
             ("rbac.authorization.k8s.io/v1", "ClusterRole"): False,
             ("external-secrets.io/v1beta1", "ClusterSecretStore"): False,
             ("kyverno.io/v1", "ClusterPolicy"): False,
             ("snapshot.storage.k8s.io/v1", "VolumeSnapshotClass"): False,
             ("cloud.google.com/v1", "ComputeClass"): False,
             ("certificates.k8s.io/v1", "CertificateSigningRequest"): False,
             ("flowcontrol.apiserver.k8s.io/v1", "FlowSchema"): False,
             ("monitoring.coreos.com/v1", "ServiceMonitor"): True}

    def __init__(self):
        self.asked, self.opened, self.closed = [], 0, 0

    def __enter__(self):
        self.opened += 1
        return self

    def __exit__(self, *exc):
        self.closed += 1

    def __call__(self, api_version, kind):
        self.asked.append((api_version, kind))
        return self.KINDS.get((api_version, kind))


@pytest.fixture
def helm_env(monkeypatch):
    monkeypatch.setattr(seam_mod, "_field_filter", lambda field, value: (field, value))
    store = {"workloads/claims": {"status": "ACTIVE", "project_id": CHILD},
             "destructive_approvals/ap-1": _approval()}
    runner = FakeHelm()
    consumed = []
    discovery = FakeDiscovery()
    svc = helm_mod.HelmService(
        db_factory=lambda: _HDB(store), guard_db_factory=lambda: _HDB(store),
        cluster_access=lambda p, c, l: (helm_mod.ClusterAccess("https://10.0.0.1", "tok", "Y2E="), {"location": "us-east4-b"}),
        runner=runner, approval_consumer=lambda a, *, action, product_id, project_id, binding: consumed.append(
            (a, action, product_id, project_id, binding)),
        env={"PROJECT_ID": "host-platform"}, clock=lambda: HELM_NOW, kind_scope_factory=lambda access: discovery)
    svc.discovery = discovery
    return svc, store, runner, consumed


INSTALL = dict(product_id="claims", cluster_name="claims-gke", location="us-east4-b", namespace="claims",
               release="claims-api", chart_ref=OCI, version="1.4.2")


def test_helm_valid_chart_runs_template_dry_run_install_and_digest_check_in_order(helm_env):
    svc, store, runner, _ = helm_env
    res = svc.install_or_upgrade(**INSTALL, values={"replicas": 2})
    assert res["status"] == "INSTALLED" and res["http_status"] == 200 and res["revision"] == 1
    assert runner.subcommands() == ["template", "upgrade:dry", "upgrade", "status"]
    for args, values in runner.calls[:3]:
        assert "--set" not in args and values == {"replicas": 2}  # values as a file, never --set
    assert res["installed_digest"] == res["dry_run_digest"]


def test_helm_hook_targeting_kube_system_is_refused_before_install(helm_env):
    svc, _, runner, _ = helm_env
    runner.dry_hooks = ["apiVersion: batch/v1\nkind: Job\nmetadata:\n  name: pre\n  namespace: kube-system\n"]
    res = svc.install_or_upgrade(**INSTALL)
    assert res["status"] == "REFUSED:POLICY" and res["stage"] == "server_dry_run"
    assert res["violations"][0]["code"] == "PROTECTED_NAMESPACE"
    assert runner.subcommands() == ["template", "upgrade:dry"]


def test_helm_lookup_rendered_cluster_role_only_in_server_dry_run_is_refused(helm_env):
    svc, _, runner, _ = helm_env
    runner.dry_manifest = DEPLOYMENT + "---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: x\n"
    res = svc.install_or_upgrade(**INSTALL)
    assert res["status"] == "REFUSED:POLICY" and res["violations"][0]["code"] == "CLUSTER_SCOPED_KIND"
    assert "upgrade" not in [c for c in runner.subcommands() if c == "upgrade"]


def test_helm_template_precheck_refuses_fast(helm_env):
    svc, _, runner, _ = helm_env
    runner.template = "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata:\n  name: c\n"
    res = svc.install_or_upgrade(**INSTALL)
    assert res["stage"] == "template" and runner.subcommands() == ["template"]


def test_helm_post_install_drift_on_revision_2_rolls_back(helm_env):
    svc, _, runner, _ = helm_env
    runner.revision = 2
    runner.status_manifest = DEPLOYMENT + "---\nkind: ConfigMap\nmetadata:\n  name: injected\n"
    res = svc.install_or_upgrade(**INSTALL)
    assert res["status"] == "HELM_POST_INSTALL_DRIFT" and res["remediation"] == "ROLLED_BACK"
    assert runner.calls[-1][0][:3] == ["rollback", "claims-api", "1"]


def test_helm_post_install_drift_on_first_install_requests_approval_never_uninstalls(helm_env):
    svc, store, runner, _ = helm_env
    # Option B: only a drift that violates the policy is remediated (here: a ClusterRole the dry run did not show).
    runner.status_manifest = SERVICE + "---\napiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: x\n"
    res = svc.install_or_upgrade(**INSTALL)
    assert res["status"] == "HELM_POST_INSTALL_DRIFT" and res["remediation"].startswith("UNINSTALL_APPROVAL_REQUESTED:")
    assert res["drift_violations"][0]["code"] == "CLUSTER_SCOPED_KIND"
    assert "uninstall" not in runner.subcommands() and "rollback" not in runner.subcommands()
    req = [v for k, v in store.items() if k.startswith("approval_requests/")]
    assert req and req[0]["mcp_action"] == "HELM_UNINSTALL" and req[0]["status"] == "PENDING"
    assert req[0]["approval_type"] == "MCP_ACTION" and req[0]["mcp_binding"] == UNINSTALL_BINDING
    assert res["remediation"] == f"UNINSTALL_APPROVAL_REQUESTED:{req[0]['approval_id']}"


@pytest.mark.parametrize("chart_ref,code", [
    (f"oci://us-east4-docker.pkg.dev/other-project/charts/x", "CHART_SOURCE_NOT_ALLOWED"),
    (f"oci://evil.example/us-east4-docker.pkg.dev/{CHILD}/charts/x", "CHART_SOURCE_NOT_ALLOWED"),
    (f"oci://europe-west1-docker.pkg.dev/{CHILD}/charts/x", "CHART_SOURCE_NOT_ALLOWED"),
    (f"oci://us-east4-docker.pkg.dev/{CHILD}/x", "CHART_REF_INVALID"),
    (f"https://us-east4-docker.pkg.dev/{CHILD}/charts/x", "CHART_SOURCE_NOT_ALLOWED"),
])
def test_helm_oci_validation_is_positional(helm_env, chart_ref, code):
    svc, _, runner, _ = helm_env
    with pytest.raises(helm_mod.HelmRefused) as ei:
        svc.install_or_upgrade(**dict(INSTALL, chart_ref=chart_ref))
    assert ei.value.code == code and runner.calls == []


def test_helm_repository_allow_list_is_exact(helm_env):
    svc, _, runner, _ = helm_env
    with pytest.raises(helm_mod.HelmRefused) as ei:
        svc.install_or_upgrade(**dict(INSTALL, chart_ref="redis", repo_url="https://charts.example.com"))
    assert ei.value.code == "CHART_SOURCE_NOT_ALLOWED"
    svc._env = {"PROJECT_ID": "host-platform", "HELM_CHART_REPOSITORY_ALLOWLIST": '["https://charts.example.com"]'}
    with pytest.raises(helm_mod.HelmRefused):
        svc.install_or_upgrade(**dict(INSTALL, chart_ref="redis", repo_url="https://charts.example.com/"))
    res = svc.install_or_upgrade(**dict(INSTALL, chart_ref="redis", repo_url="https://charts.example.com"))
    assert res["status"] == "INSTALLED" and "--repo" in runner.calls[0][0]


@pytest.mark.parametrize("over,code", [
    ({"version": "^1.4"}, "VERSION_NOT_EXACT"), ({"version": "latest"}, "VERSION_NOT_EXACT"),
    ({"release": "Bad_Name"}, "RELEASE_NAME_INVALID"), ({"namespace": "kube-system"}, "PROTECTED_NAMESPACE"),
    ({"product_id": "nope"}, "REFUSED:LEDGER_MISSING"), ({"project_id": "evil"}, "REFUSED:TARGET_MISMATCH"),
])
def test_helm_typed_refusals(helm_env, over, code):
    svc, _, runner, _ = helm_env
    with pytest.raises(helm_mod.HelmRefused) as ei:
        svc.install_or_upgrade(**dict(INSTALL, **over))
    assert ei.value.code == code and runner.calls == []


def test_helm_uninstall_needs_an_approved_record(helm_env):
    svc, store, runner, consumed = helm_env
    base = dict(product_id="claims", cluster_name="claims-gke", location="us-east4-b", namespace="claims",
                release="claims-api")
    with pytest.raises(helm_mod.HelmRefused) as ei:
        svc.uninstall(**base, approval_id=None)
    assert ei.value.code == "REFUSED:APPROVAL_REQUIRED" and runner.calls == []
    # APPROVAL-CONSUME-VIA-VENDING: the refusal names the approval card it recorded for exactly these arguments.
    request_id = ei.value.extra["approval_request_id"]
    card = store[f"approval_requests/{request_id}"]
    assert (card["approval_type"], card["status"], card["mcp_action"], card["mcp_project_id"]) == (
        "MCP_ACTION", "PENDING", "HELM_UNINSTALL", CHILD)
    assert card["mcp_binding"] == UNINSTALL_BINDING and card["mcp_binding_digest"] == seam_mod.binding_digest(UNINSTALL_BINDING)
    with pytest.raises(helm_mod.HelmRefused) as again:   # a retry finds the same PENDING card
        svc.uninstall(**base, approval_id=None)
    assert again.value.extra["approval_request_id"] == request_id
    assert len([k for k in store if k.startswith("approval_requests/")]) == 1
    store["destructive_approvals/ap-2"] = _approval(principal_type="SERVICE_ACCOUNT")
    with pytest.raises(helm_mod.HelmRefused) as ei:
        svc.uninstall(**base, approval_id="ap-2")
    assert ei.value.code == "REFUSED:APPROVAL_NOT_HUMAN"
    res = svc.uninstall(**base, approval_id="ap-1")
    assert res["status"] == "UNINSTALLED"
    assert consumed == [("ap-1", "HELM_UNINSTALL", "claims", CHILD, UNINSTALL_BINDING)]
    assert runner.calls[-1][0][:2] == ["uninstall", "claims-api"]


@pytest.mark.parametrize("over", [dict(release="other-api"), dict(namespace="other"), dict(cluster_name="other-gke")])
def test_helm_uninstall_approval_for_other_arguments_is_refused_before_consume(helm_env, over):
    svc, store, runner, consumed = helm_env
    base = dict(product_id="claims", cluster_name="claims-gke", location="us-east4-b", namespace="claims",
                release="claims-api")
    with pytest.raises(helm_mod.HelmRefused) as ei:
        svc.uninstall(**dict(base, **over), approval_id="ap-1")
    assert ei.value.code == "REFUSED:APPROVAL_BINDING_MISMATCH" and consumed == []
    assert "uninstall" not in runner.subcommands()


def test_helm_uninstall_consume_unavailable_is_503_and_nothing_is_uninstalled(helm_env):
    svc, store, runner, consumed = helm_env

    def unreachable(*_a, **_k):
        raise seam_mod.ApprovalRefused("APPROVAL_CONSUME_UNAVAILABLE", "ConnectionError")

    svc._consume = unreachable
    with pytest.raises(helm_mod.HelmRefused) as ei:
        svc.uninstall(product_id="claims", cluster_name="claims-gke", location="us-east4-b", namespace="claims",
                      release="claims-api", approval_id="ap-1")
    assert (ei.value.code, ei.value.http_status) == ("REFUSED:APPROVAL_CONSUME_UNAVAILABLE", 503)
    assert "uninstall" not in runner.subcommands()


def test_helm_binary_missing_is_helm_unavailable_never_a_mock(helm_env):
    svc, _, runner, _ = helm_env
    runner.available = False
    with pytest.raises(helm_mod.HelmRefused) as ei:
        svc.install_or_upgrade(**INSTALL)
    assert ei.value.code == "HELM_UNAVAILABLE" and ei.value.http_status == 503
    assert svc.health() == {"helm_version": None, "helm_status": "HELM_UNAVAILABLE"}
    real = helm_mod.HelmRunner(binary="/nonexistent/helm")
    with pytest.raises(helm_mod.HelmRefused) as ei:
        real(["list"], None)
    assert ei.value.code == "HELM_UNAVAILABLE"


def test_helm_runner_passes_cluster_access_in_env_never_argv(tmp_path):
    binary = tmp_path / "helm"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    seen = {}

    def fake_run(argv, **kw):
        seen["argv"], seen["env"] = argv, kw["env"]
        seen["ca"] = open(kw["env"]["HELM_KUBECAFILE"], "rb").read()
        seen["values"] = _json.load(open(argv[argv.index("--values") + 1]))
        return type("R", (), {"returncode": 0, "stdout": "{}", "stderr": ""})()

    runner = helm_mod.HelmRunner(binary=str(binary), run=fake_run)
    runner(["list", "-o", "json"], helm_mod.ClusterAccess("https://10.0.0.1", "secret-token", "Y2E="), values={"a": 1})
    assert "secret-token" not in " ".join(seen["argv"]) and seen["env"]["HELM_KUBETOKEN"] == "secret-token"
    assert seen["env"]["HELM_KUBEAPISERVER"] == "https://10.0.0.1" and seen["ca"] == b"ca"
    assert seen["values"] == {"a": 1} and "--set" not in seen["argv"]
    assert not os.path.exists(seen["env"]["HELM_KUBECAFILE"])  # temp dir cleaned


def test_helm_document_policy_negative_valid_documents_pass():
    docs = helm_mod.parse_documents(DEPLOYMENT + "---\n" + SERVICE + "---\n")
    assert helm_mod.document_policy(docs, "claims") == []
    assert helm_mod.is_exact_version("1.4.2") and helm_mod.is_exact_version("v1.4.2-rc.1")
    assert helm_mod.is_exact_version("sha256:" + "a" * 64) and not helm_mod.is_exact_version("1.4")
    assert helm_mod.cluster_region("us-east4-b") == "us-east4" and helm_mod.cluster_region("us-east4") == "us-east4"


def test_helm_read_only_tools(helm_env):
    svc, _, runner, _ = helm_env
    base = dict(product_id="claims", cluster_name="claims-gke", location="us-east4-b", namespace="claims")
    assert svc.list_releases(**base)["releases"] == []
    assert svc.release_status(**base, release="claims-api")["info"]["status"] == "deployed"
    assert svc.history(**base, release="claims-api")["history"] == []
    assert svc.rollback(**base, release="claims-api", revision=3)["status"] == "ROLLED_BACK"


# ---------------------------------------------------------------------------------------------- RT fixes (lane14-sync)
def _doc(api_version, kind, name="x", namespace=None):
    meta = f"\n  namespace: {namespace}" if namespace else ""
    return f"apiVersion: {api_version}\nkind: {kind}\nmetadata:\n  name: {name}{meta}\n"


def test_rt_f14_cluster_secret_store_hook_is_refused_before_install(helm_env):
    svc, _, runner, _ = helm_env
    runner.dry_hooks = [_doc("external-secrets.io/v1beta1", "ClusterSecretStore")]
    res = svc.install_or_upgrade(**INSTALL)
    assert res["status"] == "REFUSED:POLICY" and res["stage"] == "server_dry_run"
    assert res["violations"][0]["code"] == "CLUSTER_SCOPED_KIND" and res["violations"][0]["kind"] == "ClusterSecretStore"
    assert runner.subcommands() == ["template", "upgrade:dry"]
    assert svc.discovery.opened == svc.discovery.closed == 1


@pytest.mark.parametrize("api_version,kind", [
    ("kyverno.io/v1", "ClusterPolicy"), ("snapshot.storage.k8s.io/v1", "VolumeSnapshotClass"),
    ("cloud.google.com/v1", "ComputeClass"), ("certificates.k8s.io/v1", "CertificateSigningRequest"),
    ("flowcontrol.apiserver.k8s.io/v1", "FlowSchema"),
])
def test_rt_f14_cluster_scoped_kinds_outside_the_static_set_are_refused(helm_env, api_version, kind):
    svc, _, runner, _ = helm_env
    assert kind not in helm_mod.CLUSTER_SCOPED_KINDS
    runner.template = DEPLOYMENT + "---\n" + _doc(api_version, kind)
    res = svc.install_or_upgrade(**INSTALL)
    assert res["stage"] == "template" and res["violations"][0]["code"] == "CLUSTER_SCOPED_KIND"
    assert runner.subcommands() == ["template"]


def test_rt_f14_kinds_the_cluster_does_not_know_are_refused(helm_env):
    svc, _, runner, _ = helm_env
    runner.dry_manifest = DEPLOYMENT + "---\n" + _doc("example.com/v1", "Widget") + "---\nkind: Service\nmetadata: {}\n"
    res = svc.install_or_upgrade(**INSTALL)
    assert res["status"] == "REFUSED:POLICY"
    assert [v["code"] for v in res["violations"]] == ["UNKNOWN_KIND", "UNKNOWN_KIND"]  # unknown; no apiVersion


def test_rt_f14_negative_namespaced_custom_kind_installs_unchanged(helm_env):
    svc, _, runner, _ = helm_env
    runner.template = runner.dry_manifest = runner.status_manifest = (
        DEPLOYMENT + "---\n" + _doc("monitoring.coreos.com/v1", "ServiceMonitor", namespace="claims"))
    res = svc.install_or_upgrade(**INSTALL)
    assert res["status"] == "INSTALLED"
    assert ("monitoring.coreos.com/v1", "ServiceMonitor") in svc.discovery.asked


def test_rt_f15_multi_region_host_is_allowed_by_parsed_rules(helm_env):
    svc, _, runner, _ = helm_env
    res = svc.install_or_upgrade(**dict(INSTALL, chart_ref=f"oci://us-docker.pkg.dev/{CHILD}/charts/claims-api"))
    assert res["status"] == "INSTALLED" and set(runner.registry_hosts[:3]) == {"us-docker.pkg.dev"}
    assert helm_mod.artifact_registry_hosts(["us-east4"]) == {"us-east4-docker.pkg.dev", "us-docker.pkg.dev"}
    assert helm_mod.artifact_registry_hosts(["europe-west1"]) == {"europe-west1-docker.pkg.dev",
                                                                  "europe-docker.pkg.dev"}
    assert helm_mod.artifact_registry_hosts(["northamerica-northeast1"]) == {"northamerica-northeast1-docker.pkg.dev"}
    for bad in ("europe-docker.pkg.dev", "us-docker.pkg.dev.evil.example", "evil-us-docker.pkg.dev"):
        with pytest.raises(helm_mod.HelmRefused) as ei:
            svc.install_or_upgrade(**dict(INSTALL, chart_ref=f"oci://{bad}/{CHILD}/charts/claims-api"))
        assert ei.value.code == "CHART_SOURCE_NOT_ALLOWED"


def test_rt_f15_registry_credentials_only_for_the_validated_oci_host(helm_env):
    svc, _, runner, _ = helm_env
    svc.install_or_upgrade(**INSTALL)
    assert runner.registry_hosts[:3] == ["us-east4-docker.pkg.dev"] * 3  # template, dry run, install
    assert runner.registry_hosts[3] is None  # status reads the cluster only
    runner.calls.clear()
    runner.registry_hosts.clear()
    svc._env = {"PROJECT_ID": "host-platform", "HELM_CHART_REPOSITORY_ALLOWLIST": '["https://charts.example.com"]'}
    svc.install_or_upgrade(**dict(INSTALL, chart_ref="redis", repo_url="https://charts.example.com"))
    assert set(runner.registry_hosts) == {None}


def test_rt_f15_runner_writes_one_registry_entry_in_the_private_temp_dir(tmp_path):
    import base64 as _b64

    binary = tmp_path / "helm"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)
    seen = {}

    def fake_run(argv, **kw):
        seen["argv"], seen["env"] = argv, kw["env"]
        if "HELM_REGISTRY_CONFIG" in kw["env"]:
            seen["reg"] = _json.load(open(kw["env"]["HELM_REGISTRY_CONFIG"]))
        return type("R", (), {"returncode": 0, "stdout": "{}", "stderr": ""})()

    runner = helm_mod.HelmRunner(binary=str(binary), run=fake_run)
    access = helm_mod.ClusterAccess("https://10.0.0.1", "sa-token", "Y2E=")
    runner(["template", "r", "oci://x"], access, registry_host="us-east4-docker.pkg.dev")
    assert list(seen["reg"]["auths"]) == ["us-east4-docker.pkg.dev"]
    assert _b64.b64decode(seen["reg"]["auths"]["us-east4-docker.pkg.dev"]["auth"]) == b"oauth2accesstoken:sa-token"
    assert "sa-token" not in " ".join(seen["argv"]) and not os.path.exists(seen["env"]["HELM_REGISTRY_CONFIG"])
    runner(["list"], access)
    assert "HELM_REGISTRY_CONFIG" not in seen["env"]  # Negative: no registry config without a validated host


def test_rt_f17_dry_run_and_install_skip_crds(helm_env):
    svc, _, runner, _ = helm_env
    svc.install_or_upgrade(**INSTALL)
    template, dry, install = (c[0] for c in runner.calls[:3])
    assert "--include-crds" in template and "--skip-crds" not in template
    assert "--skip-crds" in dry and "--skip-crds" in install


def test_rt_f18_rollback_target_must_pass_the_policy(helm_env):
    svc, _, runner, _ = helm_env
    base = dict(product_id="claims", cluster_name="claims-gke", location="us-east4-b", namespace="claims",
                release="claims-api")
    runner.stored_hooks = _doc("rbac.authorization.k8s.io/v1", "ClusterRole")
    res = svc.rollback(**base, revision=2)
    assert res["status"] == "REFUSED:POLICY" and res["http_status"] == 403
    assert "rollback" not in runner.subcommands()
    assert [c[0][:4] for c in runner.calls] == [["get", "manifest", "claims-api", "--revision"],
                                                 ["get", "hooks", "claims-api", "--revision"]]


def test_rt_f18_automatic_drift_rollback_is_refused_when_the_previous_revision_fails_the_policy(helm_env):
    svc, _, runner, _ = helm_env
    runner.revision = 2
    runner.status_manifest = DEPLOYMENT + "---\n" + _doc("rbac.authorization.k8s.io/v1", "ClusterRole", "injected")
    runner.stored_manifest = _doc("v1", "ConfigMap", "c", namespace="kube-system")
    res = svc.install_or_upgrade(**INSTALL)
    assert res["status"] == "HELM_POST_INSTALL_DRIFT"
    # RT residual R2: nothing safe to roll back to -> an uninstall approval card (never an automatic uninstall).
    assert res["remediation"].startswith("ROLLBACK_REFUSED:POLICY; UNINSTALL_APPROVAL_REQUESTED:")
    assert res["rollback_violations"][0]["code"] == "PROTECTED_NAMESPACE" and "rollback" not in runner.subcommands()
    assert "uninstall" not in runner.subcommands()
    req = [v for k, v in svc._db_factory().store.items() if k.startswith("approval_requests/")]
    assert len(req) == 1 and req[0]["status"] == "PENDING"


def test_f16_option_b_random_value_drift_is_installed_with_render_drift(helm_env):
    """Owner F16 = option B: a chart that renders a random value / regenerated cert differs from its dry run; the
    full policy on what was installed is clean -> INSTALLED, render_drift true, both digests audited, no rollback."""
    svc, store, runner, _ = helm_env
    runner.revision = 2
    runner.status_manifest = DEPLOYMENT + "---\n" + SERVICE + "---\n" + _doc("v1", "Secret", "tls-random-a8f3")
    res = svc.install_or_upgrade(**INSTALL)
    assert res["status"] == "INSTALLED" and res["http_status"] == 200 and res["render_drift"] is True
    assert res["installed_digest"] != res["dry_run_digest"] and len(res["dry_run_digest"]) == 64
    assert "rollback" not in runner.subcommands()
    gets = [c[0] for c in runner.calls if c[0][0] == "get"]  # RT R5: the installed revision via helm get, only it
    assert [g[1] for g in gets] == ["manifest", "hooks"] and all(g[g.index("--revision") + 1] == "2" for g in gets)
    audits = [v for k, v in store.items() if k.startswith("helm_releases/")]
    assert audits and audits[0]["render_drift"] is True and audits[0]["installed_digest"] == res["installed_digest"]
    assert not [k for k in store if k.startswith("approval_requests/")]


def test_f16_option_b_drift_adding_a_cluster_scoped_object_rolls_back(helm_env):
    svc, _, runner, _ = helm_env
    runner.revision = 3
    runner.status_manifest = DEPLOYMENT + "---\n" + _doc("kyverno.io/v1", "ClusterPolicy", "sneaky")
    res = svc.install_or_upgrade(**INSTALL)
    assert res["status"] == "HELM_POST_INSTALL_DRIFT" and res["remediation"] == "ROLLED_BACK"
    assert res["drift_violations"][0]["code"] == "CLUSTER_SCOPED_KIND" and res["http_status"] == 409
    assert runner.calls[-1][0][:3] == ["rollback", "claims-api", "2"]


def test_f16_option_b_installed_hook_violation_is_checked_too(helm_env):
    svc, _, runner, _ = helm_env
    runner.revision = 2
    runner.status_manifest = DEPLOYMENT + "---\n" + _doc("v1", "ConfigMap", "changed")
    runner.installed_hooks = [_doc("batch/v1", "Job", "pre", namespace="kube-system")]
    res = svc.install_or_upgrade(**INSTALL)
    assert res["status"] == "HELM_POST_INSTALL_DRIFT" and res["drift_violations"][0]["code"] == "PROTECTED_NAMESPACE"


def test_rt_r5_installed_hooks_come_from_helm_get_not_the_status_payload(helm_env):
    """RT R5: a `helm status -o json` without `hooks` (e.g. another Helm major) must not hide a drifted hook; the
    re-check reads the installed revision with `helm get manifest|hooks --revision N`."""
    svc, _, runner, _ = helm_env
    runner.revision = 2
    runner.status_manifest = DEPLOYMENT + "---\n" + _doc("v1", "ConfigMap", "changed")
    runner.installed_hooks = [_doc("external-secrets.io/v1beta1", "ClusterSecretStore", "s")]
    original = runner.__call__

    def status_without_hooks(args, access, values=None, registry_host=None):
        code, out, err = original(args, access, values=values, registry_host=registry_host)
        if args[0] == "status":
            body = _json.loads(out)
            body.pop("hooks", None)
            out = _json.dumps(body)
        return code, out, err

    svc.runner = _wrapped(runner, status_without_hooks)
    res = svc.install_or_upgrade(**INSTALL)
    assert res["status"] == "HELM_POST_INSTALL_DRIFT" and res["drift_violations"][0]["kind"] == "ClusterSecretStore"


def _wrapped(runner, fn):
    return type("R", (), {"binary": runner.binary, "version": runner.version,
                          "__call__": lambda self, *a, **k: fn(*a, **k)})()


def _failing(runner, *, sub, revision=None, stderr="Error: boom"):
    original = runner.__call__

    def call(args, access, values=None, registry_host=None):
        if args[0] == sub and (revision is None or args[args.index("--revision") + 1] == str(revision)):
            runner.calls.append((list(args), values))
            return 1, "", stderr
        return original(args, access, values=values, registry_host=registry_host)

    return _wrapped(runner, call)


def _cards(svc):
    return [v for k, v in svc._db_factory().store.items() if k.startswith("approval_requests/")]


def test_rt_r3_r4_rollback_target_check_error_is_rollback_failed_409_and_a_card(helm_env):
    svc, _, runner, _ = helm_env
    runner.revision = 2
    runner.status_manifest = DEPLOYMENT + "---\n" + _doc("rbac.authorization.k8s.io/v1", "ClusterRole", "x")
    svc.runner = _failing(runner, sub="get", revision=1, stderr="Error: release: not found")
    res = svc.install_or_upgrade(**INSTALL)
    assert res["status"] == "HELM_POST_INSTALL_DRIFT" and res["http_status"] == 409
    assert res["remediation"].startswith("ROLLBACK_FAILED:HELM_FAILED:GET_MANIFEST; UNINSTALL_APPROVAL_REQUESTED:")
    assert "rollback" not in runner.subcommands()
    assert len(_cards(svc)) == 1 and _cards(svc)[0]["reason"] == "HELM_POST_INSTALL_DRIFT"


def test_rt_r4_failed_rollback_command_raises_a_card(helm_env):
    svc, _, runner, _ = helm_env
    runner.revision = 2
    runner.status_manifest = DEPLOYMENT + "---\n" + _doc("rbac.authorization.k8s.io/v1", "ClusterRole", "x")
    svc.runner = _failing(runner, sub="rollback", stderr="Error: timed out waiting")
    res = svc.install_or_upgrade(**INSTALL)
    assert res["http_status"] == 409
    assert res["remediation"].startswith("ROLLBACK_FAILED: Error: timed out waiting; UNINSTALL_APPROVAL_REQUESTED:")
    assert len(_cards(svc)) == 1 and "uninstall" not in runner.subcommands()


def test_rt_r6_status_failure_after_install_is_drift_unverified_with_audit_and_card(helm_env):
    svc, store, runner, _ = helm_env
    svc.runner = _failing(runner, sub="status", stderr="Error: connection refused")
    res = svc.install_or_upgrade(**INSTALL)
    assert res["status"] == "HELM_POST_INSTALL_DRIFT" and res["http_status"] == 409
    assert res["remediation"].startswith("DRIFT_UNVERIFIED:HELM_FAILED:STATUS; UNINSTALL_APPROVAL_REQUESTED:")
    assert res["revision"] == 1 and len(res["dry_run_digest"]) == 64
    assert [v for k, v in store.items() if k.startswith("helm_releases/")]  # audited
    assert len(_cards(svc)) == 1 and _cards(svc)[0]["reason"] == "HELM_POST_INSTALL_DRIFT_UNVERIFIED"
    assert "rollback" not in runner.subcommands() and "uninstall" not in runner.subcommands()


def test_rt_r6_install_without_a_revision_is_drift_unverified(helm_env):
    svc, store, runner, _ = helm_env
    original = runner.__call__

    def no_version(args, access, values=None, registry_host=None):
        code, out, err = original(args, access, values=values, registry_host=registry_host)
        if args[0] == "upgrade" and "--dry-run=server" not in args:
            body = _json.loads(out)
            body.pop("version", None)
            out = _json.dumps(body)
        return code, out, err

    svc.runner = _wrapped(runner, no_version)
    res = svc.install_or_upgrade(**INSTALL)
    assert res["http_status"] == 409 and res["revision"] is None
    assert res["remediation"].startswith("DRIFT_UNVERIFIED:HELM_FAILED:INSTALL_REVISION_MISSING; ")
    assert [k for k in store if k.startswith("helm_releases/")] and len(_cards(svc)) == 1


def test_rt_r5_helm_get_error_on_the_installed_revision_is_drift_unverified(helm_env):
    svc, _, runner, _ = helm_env
    runner.revision = 2
    runner.status_manifest = DEPLOYMENT + "---\n" + _doc("v1", "ConfigMap", "changed")
    svc.runner = _failing(runner, sub="get", revision=2)
    res = svc.install_or_upgrade(**INSTALL)
    assert res["remediation"].startswith("DRIFT_UNVERIFIED:HELM_FAILED:GET_MANIFEST; UNINSTALL_APPROVAL_REQUESTED:")
    assert res["http_status"] == 409 and "rollback" not in runner.subcommands()


def test_f16_option_b_unverifiable_installed_release_is_never_installed(helm_env):
    svc, store, runner, _ = helm_env
    runner.revision = 2
    runner.status_manifest = "kind: [unclosed\n"
    res = svc.install_or_upgrade(**INSTALL)
    assert res["status"] == "HELM_POST_INSTALL_DRIFT" and res["http_status"] == 409
    assert res["remediation"].startswith("DRIFT_UNVERIFIED:RENDER_UNPARSABLE; UNINSTALL_APPROVAL_REQUESTED:")
    assert "rollback" not in runner.subcommands() and "uninstall" not in runner.subcommands()


# ==============================================================================================================
# FD-4L / FD27-10: k8s_apply_manifest per-document policy (the Helm discovery policy) + server-side apply; ledger
# target on every tool; restart / scale namespace guard. Fake ledger, fake discovery (records SSA calls), no cluster.
# ==============================================================================================================
from fastapi.testclient import TestClient

import main as k8s_main

PAYMENT_DEPLOYMENT = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-service
  namespace: castor-workload
spec:
  replicas: 2
  template:
    spec:
      containers:
      - name: payment
        image: gcr.io/test/payment:v1
"""
SECRET_VALUE = "c3VwZXItc2VjcmV0LXZhbHVl"
SECRET = f"apiVersion: v1\nkind: Secret\nmetadata:\n  name: api-creds\ntype: Opaque\ndata:\n  password: {SECRET_VALUE}\n"
KDOC = dict(product_id="claims", cluster_name="claims-gke", location="us-east4")


class _Calls:
    def __init__(self):
        self.cluster, self.ssa = [], []

    @staticmethod
    def apps():
        from kubernetes import client

        return client.AppsV1Api.return_value


class ApplyDiscovery(FakeDiscovery):
    """FakeDiscovery + the server-side apply seam (records (body, namespace, dry_run); `fail_on[(name, dry)]`)."""

    def __init__(self, calls):
        super().__init__()
        self.calls, self.fail_on = calls, {}

    def server_side_apply(self, doc, namespace, *, dry_run):
        self.calls.ssa.append((copy.deepcopy(doc), namespace, dry_run))
        err = self.fail_on.get((doc["metadata"]["name"], dry_run))
        if err is not None:
            raise err
        return {"applied": True}


@pytest.fixture
def k8s_env(monkeypatch):
    monkeypatch.setattr(seam_mod, "_field_filter", lambda field, value: (field, value))
    store = {"workloads/claims": {"status": "ACTIVE", "project_id": CHILD},
             "workloads/other": {"status": "ACTIVE", "project_id": "other-child-9"},
             "workloads/hosty": {"status": "ACTIVE", "project_id": "host-platform"}}
    calls = _Calls()
    from kubernetes import client as k8s_client

    k8s_client.reset_mock()
    discovery = ApplyDiscovery(calls)

    def cluster_access(project_id, cluster_name, location):
        calls.cluster.append((project_id, cluster_name, location))
        return (helm_mod.ClusterAccess("https://10.0.0.1", "tok", "Y2E="),
                {"location": location, "status": "RUNNING", "endpoint": "https://10.0.0.1",
                 "current_master_version": "1.30.5-gke.1"})

    helm = helm_mod.HelmService(
        db_factory=lambda: _HDB(store), guard_db_factory=lambda: _HDB(store), cluster_access=cluster_access,
        runner=FakeHelm(), env={"PROJECT_ID": "host-platform"}, clock=lambda: HELM_NOW,
        kind_scope_factory=lambda access: discovery)
    svc = KubernetesService(default_project_id="host-platform", firestore_client=_HDB(store), helm_service=helm, env={})
    svc.store, svc.discovery = store, discovery
    return svc, calls


def _audits(svc):
    return [v for k, v in svc.store.items() if k.startswith("kubernetes_deployments/")]


def test_fd4l_kube_system_document_under_request_default_is_refused_with_zero_calls(k8s_env):
    svc, calls = k8s_env
    manifest = DEPLOYMENT + "---\n" + _doc("v1", "ConfigMap", "cm", namespace="kube-system")
    res = svc.apply_manifest(**KDOC, namespace="default", yaml_content=manifest)
    assert res["status"] == "REFUSED:POLICY" and res["http_status"] == 403 and res["stage"] == "precheck"
    assert [(v["code"], v["namespace"]) for v in res["violations"]] == [("PROTECTED_NAMESPACE", "kube-system")]
    assert calls.cluster == [] and calls.ssa == []  # refused before any credentials lookup or API call


def test_fd4l_cluster_role_binding_is_refused_with_zero_calls(k8s_env):
    svc, calls = k8s_env
    manifest = DEPLOYMENT + "---\n" + _doc("rbac.authorization.k8s.io/v1", "ClusterRoleBinding", "crb")
    res = svc.apply_manifest(**KDOC, namespace="claims", yaml_content=manifest)
    assert res["status"] == "REFUSED:POLICY" and res["violations"][0]["code"] == "CLUSTER_SCOPED_KIND"
    assert calls.cluster == [] and calls.ssa == []


def test_fd4l_cluster_scoped_kind_outside_the_static_set_is_refused_by_cluster_discovery(k8s_env):
    svc, calls = k8s_env
    assert "ClusterSecretStore" not in helm_mod.CLUSTER_SCOPED_KINDS
    manifest = DEPLOYMENT + "---\n" + _doc("external-secrets.io/v1beta1", "ClusterSecretStore", "store")
    res = svc.apply_manifest(**KDOC, namespace="claims", yaml_content=manifest)
    assert res["status"] == "REFUSED:POLICY" and res["stage"] == "discovery"
    assert res["violations"][0]["code"] == "CLUSTER_SCOPED_KIND" and res["violations"][0]["kind"] == "ClusterSecretStore"
    assert calls.ssa == [] and svc.discovery.opened == svc.discovery.closed == 1
    assert _audits(svc)[0]["status"] == "REFUSED:POLICY"


def test_fd4l_unknown_kind_fails_with_zero_applies(k8s_env):
    svc, calls = k8s_env
    manifest = DEPLOYMENT + "---\n" + _doc("example.com/v1", "Widget", "w")
    res = svc.apply_manifest(**KDOC, namespace="claims", yaml_content=manifest)
    assert res["status"] == "REFUSED:POLICY" and [v["code"] for v in res["violations"]] == ["UNKNOWN_KIND"]
    assert calls.ssa == []


def test_fd4l_kind_list_items_are_policy_checked(k8s_env):
    svc, calls = k8s_env
    manifest = ("apiVersion: v1\nkind: List\nitems:\n- apiVersion: rbac.authorization.k8s.io/v1\n  kind: ClusterRole\n"
                "  metadata:\n    name: cr\n")
    res = svc.apply_manifest(**KDOC, namespace="claims", yaml_content=manifest)
    assert res["status"] == "REFUSED:POLICY" and res["violations"][0]["code"] == "CLUSTER_SCOPED_KIND"
    assert calls.ssa == []


def test_fd4l_valid_documents_are_server_side_applied_after_a_full_dry_run(k8s_env):
    svc, calls = k8s_env
    res = svc.apply_manifest(**KDOC, namespace="claims", yaml_content=DEPLOYMENT + "---\n" + SERVICE)
    assert res["status"] == "APPLIED" and res["http_status"] == 200 and res["resources_count"] == 2
    assert [(b["kind"], ns, dry) for b, ns, dry in calls.ssa] == [
        ("Deployment", "claims", True), ("Service", "claims", True),
        ("Deployment", "claims", False), ("Service", "claims", False)]
    assert [r["status"] for r in res["resources"]] == ["APPLIED", "APPLIED"]
    audit = _audits(svc)[0]
    assert audit["project_id"] == CHILD and [r["namespace"] for r in audit["resources"]] == ["claims", "claims"]
    assert calls.cluster == [(CHILD, "claims-gke", "us-east4")]


def test_fd4l_negative_valid_document_reaches_ssa_unchanged_except_the_resolved_namespace(k8s_env):
    import yaml as _yaml

    svc, calls = k8s_env
    res = svc.apply_manifest(**KDOC, namespace="castor-workload", yaml_content=PAYMENT_DEPLOYMENT, dry_run=True)
    assert res["status"] == "DRY_RUN_PASSED"
    assert calls.ssa[0][0] == _yaml.safe_load(PAYMENT_DEPLOYMENT)  # already namespaced: the same object
    calls.ssa.clear()
    svc.apply_manifest(**KDOC, namespace="claims", yaml_content=DEPLOYMENT, dry_run=True)
    expected = _yaml.safe_load(DEPLOYMENT)
    expected["metadata"]["namespace"] = "claims"
    assert calls.ssa[0][0] == expected and calls.ssa[0][1] == "claims"


def test_fd4l_secret_is_applied_and_its_values_are_never_audited_or_logged(k8s_env, caplog):
    svc, calls = k8s_env
    caplog.set_level("INFO")
    res = svc.apply_manifest(**KDOC, namespace="claims", yaml_content=SECRET)
    assert res["status"] == "APPLIED" and calls.ssa[-1][0]["data"]["password"] == SECRET_VALUE
    assert SECRET_VALUE not in repr(res) and SECRET_VALUE not in repr(_audits(svc))
    assert SECRET_VALUE not in caplog.text


def test_fd4l_server_dry_run_failure_applies_nothing(k8s_env):
    svc, calls = k8s_env
    svc.discovery.fail_on[("api", True)] = RuntimeError("admission webhook denied")
    res = svc.apply_manifest(**KDOC, namespace="claims", yaml_content=SERVICE + "---\n" + DEPLOYMENT)
    assert res["status"] == "FAILED:SERVER_DRY_RUN" and res["http_status"] == 422
    assert all(dry for _, _, dry in calls.ssa)  # no real apply happened
    assert [r["status"] for r in res["resources"]] == ["FAILED", "NOT_ATTEMPTED"]


def test_fd4l_real_apply_failure_is_reported_per_document(k8s_env):
    svc, calls = k8s_env
    manifest = DEPLOYMENT + "---\n" + _doc("v1", "ConfigMap", "cm") + "---\n" + _doc("v1", "ConfigMap", "cm2")
    svc.discovery.fail_on[("cm", False)] = RuntimeError("conflict")
    res = svc.apply_manifest(**KDOC, namespace="claims", yaml_content=manifest)
    assert res["status"] == "PARTIALLY_APPLIED" and res["http_status"] == 502
    assert [r["status"] for r in res["resources"]] == ["APPLIED", "FAILED", "NOT_ATTEMPTED"]


@pytest.mark.parametrize("manifest,code", [
    ("", "MANIFEST_EMPTY"),
    ("---\n", "MANIFEST_EMPTY"),
    ("kind: [unclosed\n", "MANIFEST_UNPARSABLE"),
    ("apiVersion: v1\nkind: ConfigMap\nmetadata: {}\n", "MANIFEST_INVALID"),
    ("- just\n- a list\n", "MANIFEST_INVALID"),
    ("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: x\n  namespace: Bad_NS\n", "MANIFEST_INVALID"),
])
def test_fd4l_malformed_manifests_are_typed_refusals(k8s_env, manifest, code):
    svc, calls = k8s_env
    with pytest.raises(helm_mod.HelmRefused) as exc:
        svc.apply_manifest(**KDOC, namespace="claims", yaml_content=manifest)
    assert exc.value.code == code and calls.cluster == [] and calls.ssa == []


@pytest.mark.parametrize("product_id,project_id,code", [
    ("hosty", None, "REFUSED:HOST_PROJECT"),
    ("claims", "host-platform", "REFUSED:TARGET_MISMATCH"),
    ("claims", "other-child-9", "REFUSED:TARGET_MISMATCH"),
    ("missing", None, "REFUSED:LEDGER_MISSING"),
    ("", None, "REFUSED:LEDGER_MISSING"),
])
def test_fd4l_every_tool_takes_its_project_from_the_ledger(k8s_env, product_id, project_id, code):
    svc, calls = k8s_env
    target = dict(product_id=product_id, project_id=project_id, cluster_name="claims-gke", location="us-east4")
    for fn, extra in ((svc.apply_manifest, dict(namespace="claims", yaml_content=DEPLOYMENT)),
                      (svc.get_cluster_status, {}),
                      (svc.list_workload_resources, dict(namespace="claims")),
                      (svc.fetch_pod_logs, dict(namespace="claims", pod_name="api-0")),
                      (svc.get_cluster_events, dict(namespace="claims")),
                      (svc.restart_deployment, dict(namespace="claims", deployment_name="api")),
                      (svc.scale_deployment, dict(namespace="claims", deployment_name="api", replicas=1))):
        with pytest.raises(helm_mod.HelmRefused) as exc:
            fn(**target, **extra)
        assert exc.value.code == code and exc.value.http_status == 403, fn.__name__
    assert calls.cluster == [] and calls.ssa == []
    calls.apps().patch_namespaced_deployment.assert_not_called()


def test_fd4l_scale_kube_dns_in_kube_system_is_refused(k8s_env):
    svc, calls = k8s_env
    with pytest.raises(helm_mod.HelmRefused) as exc:
        svc.scale_deployment(**KDOC, namespace="kube-system", deployment_name="kube-dns", replicas=0)
    assert exc.value.code == "PROTECTED_NAMESPACE" and calls.cluster == []
    calls.apps().patch_namespaced_deployment.assert_not_called()


def test_fd4l_restart_in_a_protected_namespace_is_refused(k8s_env):
    svc, calls = k8s_env
    for ns in ("kube-system", "gke-managed-system", "config-management-system"):
        with pytest.raises(helm_mod.HelmRefused) as exc:
            svc.restart_deployment(**KDOC, namespace=ns, deployment_name="kube-dns")
        assert exc.value.code == "PROTECTED_NAMESPACE"
    calls.apps().patch_namespaced_deployment.assert_not_called()


@pytest.mark.parametrize("replicas", [-1, 101, True, "3", 2.0])
def test_fd4l_scale_replicas_are_bounded_integers(k8s_env, replicas):
    svc, calls = k8s_env
    with pytest.raises(helm_mod.HelmRefused) as exc:
        svc.scale_deployment(**KDOC, namespace="claims", deployment_name="api", replicas=replicas)
    assert exc.value.code == "REPLICAS_INVALID" and calls.cluster == []


def test_fd4l_scale_valid_request_patches_the_workload_deployment(k8s_env):
    svc, calls = k8s_env
    res = svc.scale_deployment(**KDOC, namespace="claims", deployment_name="api", replicas=3)
    assert res["status"] == "SCALED" and res["replicas"] == 3
    kw = calls.apps().patch_namespaced_deployment.call_args.kwargs
    assert kw == {"name": "api", "namespace": "claims", "body": {"spec": {"replicas": 3}}}


def test_fd4l_api_client_ca_file_is_removed_after_the_call(k8s_env):
    from kubernetes import client as k8s_client

    svc, _ = k8s_env
    svc.list_workload_resources(**KDOC, namespace="claims")
    ca_path = k8s_client.Configuration.return_value.ssl_ca_cert
    assert isinstance(ca_path, str) and ca_path.endswith("ca.crt") and not os.path.exists(ca_path)


def test_fd4l_mcp_and_rest_return_typed_refusals_never_a_success(k8s_env, monkeypatch):
    svc, calls = k8s_env
    monkeypatch.setattr(k8s_main, "service", svc)
    client = TestClient(k8s_main.app)
    bad = DEPLOYMENT + "---\n" + _doc("v1", "ConfigMap", "cm", namespace="kube-system")
    rpc = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "k8s_apply_manifest", "arguments": dict(KDOC, namespace="default", yaml_content=bad)}}).json()
    assert "result" not in rpc and rpc["error"]["code"] == -32002 and rpc["error"]["message"] == "REFUSED:POLICY"
    rest = client.post("/apply", json=dict(KDOC, namespace="default", yaml_content=bad))
    assert rest.status_code == 403 and rest.json()["detail"]["status"] == "REFUSED:POLICY"
    scale = client.post("/scale", json=dict(KDOC, namespace="kube-system", deployment_name="kube-dns", replicas=0))
    assert scale.status_code == 403 and scale.json()["detail"]["status"] == "PROTECTED_NAMESPACE"
    no_product = client.post("/restart", json={"cluster_name": "c", "location": "us-east4", "namespace": "claims",
                                               "deployment_name": "api", "project_id": CHILD})
    assert no_product.status_code == 422  # product_id is required; a bare project_id is not a target
    ok = client.post("/apply", json=dict(KDOC, namespace="claims", yaml_content=DEPLOYMENT))
    assert ok.status_code == 200 and ok.json()["status"] == "APPLIED"
    assert calls.cluster == [(CHILD, "claims-gke", "us-east4")]


def test_fd4l_tools_list_requires_product_id_on_every_tool():
    rpc = TestClient(k8s_main.app).post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}).json()
    tools = rpc["result"]["tools"]
    assert len(tools) == 13 and all("product_id" in t["inputSchema"]["required"] for t in tools)


def test_fd4l_discovery_scope_server_side_apply_uses_its_own_dynamic_client():
    """The real DiscoveryKindScope seam: the resource the policy resolved is the one applied (field manager, dry run)."""
    calls = []

    class _Res:
        namespaced = True

    class _Resources:
        def get(self, api_version, kind):
            calls.append(("get", api_version, kind))
            return _Res()

    class _Dyn:
        resources = _Resources()

        def server_side_apply(self, res, **kw):
            calls.append(("ssa", type(res).__name__, kw))
            return {}

    access = helm_mod.ClusterAccess("https://10.0.0.1", "tok", "Y2E=")
    doc = {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": "api", "namespace": "claims"}}
    with helm_mod.DiscoveryKindScope(access, dynamic_client_factory=lambda api, cache_file: _Dyn()) as scope:
        scope.server_side_apply(doc, "claims", dry_run=True)
        scope.server_side_apply(doc, "claims", dry_run=False)
    assert calls[0] == ("get", "apps/v1", "Deployment")
    assert calls[1] == ("ssa", "_Res", {"body": doc, "name": "api", "namespace": "claims",
                                        "field_manager": "stackvend", "dry_run": "All"})
    assert calls[3][2]["dry_run"] is None and calls[3][2]["field_manager"] == "stackvend"


# ---------------------------------------------------------------------------------------------- RT F2 / F5 / F6 (Fable)
def _ops(svc):
    return {k: v for k, v in svc.store.items() if k.startswith("kubernetes_ops/")}


@pytest.mark.parametrize("op,extra", [("restart_deployment", {}), ("scale_deployment", {"replicas": 2})])
def test_rt_f5_restart_and_scale_write_the_audit_record_before_the_patch(k8s_env, op, extra):
    svc, calls = k8s_env
    seen = []
    calls.apps().patch_namespaced_deployment.side_effect = lambda **kw: seen.append(
        [v["status"] for v in _ops(svc).values()])
    res = getattr(svc, op)(**KDOC, namespace="claims", deployment_name="api", **extra)
    assert res["http_status"] == 200 and res["audit_finalized"] is True
    assert seen == [["PENDING"]]  # the record existed, PENDING, when the API call happened
    (rec,) = _ops(svc).values()
    assert rec["status"] == "SUBMITTED" and rec["op"] == op and rec["project_id"] == CHILD
    assert rec["deployment"] == "api" and rec["namespace"] == "claims"


@pytest.mark.parametrize("op,extra", [("restart_deployment", {}), ("scale_deployment", {"replicas": 2})])
def test_rt_f5_audit_failure_refuses_restart_and_scale_with_no_patch(k8s_env, op, extra):
    svc, calls = k8s_env
    svc.db = None
    with pytest.raises(helm_mod.HelmRefused) as exc:
        getattr(svc, op)(**KDOC, namespace="claims", deployment_name="api", **extra)
    assert exc.value.code == "AUDIT_UNAVAILABLE" and exc.value.http_status == 503
    calls.apps().patch_namespaced_deployment.assert_not_called()


def test_rt_f5_failed_patch_is_recorded_as_failed(k8s_env):
    svc, calls = k8s_env
    calls.apps().patch_namespaced_deployment.side_effect = RuntimeError("409 conflict")
    with pytest.raises(RuntimeError):
        svc.scale_deployment(**KDOC, namespace="claims", deployment_name="api", replicas=2)
    (rec,) = _ops(svc).values()
    assert rec["status"] == "FAILED:RuntimeError"


def test_rt_f6_zero_replica_bound_falls_back_to_the_default(k8s_env):
    svc, _ = k8s_env
    svc._env = {"K8S_MCP_MAX_REPLICAS": "0"}
    assert svc._max_replicas() == 100
    svc._env = {"K8S_MCP_MAX_REPLICAS": "7"}
    assert svc._max_replicas() == 7


@pytest.mark.parametrize("ns", ["cläims", "claims٣", "сlaims"])
def test_rt_f2_non_ascii_namespaces_are_refused(k8s_env, ns):
    svc, calls = k8s_env
    assert helm_mod.is_rfc1123_label(ns) is False
    with pytest.raises(helm_mod.HelmRefused) as exc:
        svc.apply_manifest(**KDOC, namespace=ns, yaml_content=DEPLOYMENT)
    assert exc.value.code == "NAMESPACE_INVALID" and calls.cluster == []
    with pytest.raises(helm_mod.HelmRefused) as exc:
        svc.list_workload_resources(product_id="claims", cluster_name="claims-gke", location="us-eаst4",
                                    namespace="claims")
    assert exc.value.code == "INVALID_CLUSTER" and calls.cluster == []


def test_rt_f2_negative_valid_ascii_labels_are_unchanged():
    for label in ("claims", "castor-workload", "a", "x1", "a" * 63):
        assert helm_mod.is_rfc1123_label(label) is True
