"""K8S-NAMESPACE-PLATFORM (ex04-1115c, register row of the same name): the deploy's manifest step creates the namespaces
the workload's `k8s/*.yaml` name.

Before: example 04's live manifests (`tests/fixtures/ex04_1115c/k8s/`, copied from the child repository at the commit QA
tested) declare `kind: Namespace` `stream-apps` and put every object in it. The deploy refused the Namespace
(CLUSTER_SCOPED_KIND) before any cluster call, and nothing created the namespace either (a namespaced object in a missing
namespace is a 404 on the dry run), so a run that passed QA stopped K8S_MANIFEST_APPLY_FAILED for an operator.
After: mcp-servers/terraform/k8s_manifest_apply.py (module docstring) creates the namespaces, create-only, typed.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import ast
import importlib.util
import json
import shutil
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
TF_DIR = REPO / "mcp-servers" / "terraform"
EX04 = REPO / "tests" / "fixtures" / "ex04_1115c" / "k8s"


def _mod():
    if "k8s_manifest_apply" in sys.modules:
        return sys.modules["k8s_manifest_apply"]
    spec = importlib.util.spec_from_file_location("k8s_manifest_apply", TF_DIR / "k8s_manifest_apply.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["k8s_manifest_apply"] = mod
    spec.loader.exec_module(mod)
    return mod


class _Res:
    def __init__(self, status, body=None):
        self.status_code, self._body = status, body

    def json(self):
        return self._body


class _GoogleSession:
    def __init__(self):
        self.calls = []

    def get(self, url, **kw):
        self.calls.append(url)
        return _Res(200, {"endpoint": "10.0.0.1", "masterAuth": {"clusterCaCertificate": "Y2E="}})


_DISCOVERY = {
    "/apis/apps/v1": {"resources": [{"name": "deployments", "kind": "Deployment", "namespaced": True}]},
    "/apis/autoscaling/v2": {"resources": [{"name": "horizontalpodautoscalers", "kind": "HorizontalPodAutoscaler",
                                            "namespaced": True}]},
    "/api/v1": {"resources": [{"name": "serviceaccounts", "kind": "ServiceAccount", "namespaced": True},
                              {"name": "configmaps", "kind": "ConfigMap", "namespaced": True},
                              {"name": "namespaces", "kind": "Namespace", "namespaced": False}]},
}


class _Cluster:
    """One ordered event log of every cluster call; namespaces in `existing` answer GET 200, others 404."""

    def __init__(self, existing=(), ns_get=None, ns_post=None, patch_fail=None):
        self.events, self.posts = [], []
        self.existing = set(existing)
        self.ns_get, self.ns_post, self.patch_fail = ns_get, ns_post, patch_fail

    def get(self, url, **kw):
        path = url.split("10.0.0.1", 1)[1]
        if path.startswith("/api/v1/namespaces/"):
            self.events.append(("GET-NS", path))
            if self.ns_get is not None:
                return self.ns_get(path)
            return (_Res(200, {"kind": "Namespace", "status": {"phase": "Active"}})
                    if path.rsplit("/", 1)[1] in self.existing else _Res(404, {"reason": "NotFound"}))
        self.events.append(("DISCOVERY", path))
        return _Res(200, _DISCOVERY[path]) if path in _DISCOVERY else _Res(404, {})

    def post(self, url, params=None, data=None, headers=None, **kw):
        path = url.split("10.0.0.1", 1)[1]
        body = json.loads(data.decode("utf-8"))
        self.events.append(("POST", path, (params or {}).get("dryRun")))
        self.posts.append((path, dict(params or {}), headers.get("Content-Type"), body))
        if self.ns_post is not None:
            answer = self.ns_post(params or {})
            if answer is not None:
                return answer
        return _Res(201, {})

    def patch(self, url, params=None, data=None, headers=None, **kw):
        path = url.split("10.0.0.1", 1)[1]
        self.events.append(("PATCH", path, (params or {}).get("dryRun")))
        if self.patch_fail and self.patch_fail(path, params or {}):
            return _Res(422, {"kind": "Status", "reason": "Invalid"})
        return _Res(200, {})


def _ws(tmp_path, docs):
    (tmp_path / "k8s").mkdir()
    for name, text in docs.items():
        (tmp_path / "k8s" / name).write_text(text)
    return str(tmp_path)


def _ex04_ws(tmp_path):
    shutil.copytree(EX04, tmp_path / "k8s")
    return str(tmp_path)


def _apply(ws, cluster, session=None):
    return _mod().apply_workspace_manifests(ws, google_session=session or _GoogleSession(), token="t",
                                            project_id="child-1", location="us-central1", cluster_name="gke-app",
                                            http=cluster)


_DEP = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n"
_DEP_IN = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n  namespace: {ns}\n"
_CM = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n"
_NS = "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: {ns}\n"


def _refusal(tmp_path, docs):
    cluster, session = _Cluster(), _GoogleSession()
    with pytest.raises(_mod().ManifestApplyFailed) as ei:
        _apply(_ws(tmp_path, docs), cluster, session)
    assert ei.value.code == "REFUSED_POLICY"
    assert session.calls == [] and cluster.events == []           # refused before any cluster call
    return ei.value


# ------------------------------------------------------------------------------------------------ the live ex04 case
def test_before_the_fix_the_live_ex04_manifests_were_refused_by_the_kubernetes_mcp_policy():
    """The k8s MCP policy (helm.document_policy, which the deploy's pre-check mirrored) refuses the live namespace.yaml:
    exactly the stop the deploy had (and still has on the Day-2 MCP, unchanged)."""
    mod = _mod()
    docs = mod.load_documents(mod.manifest_files(str(EX04.parent)))
    assert [v["code"] for v in mod.document_policy(docs, "default")] == ["CLUSTER_SCOPED_KIND"]
    assert "Namespace" in mod.CLUSTER_SCOPED_KINDS                  # unchanged (k8s MCP parity test)


def test_the_live_ex04_manifests_apply_with_the_namespace_created_first(tmp_path):
    cluster = _Cluster()
    rep = _apply(_ex04_ws(tmp_path), cluster)
    assert rep["status"] == "APPLIED"
    assert [(r["kind"], r["name"], r["namespace"], r["status"]) for r in rep["resources"]] == [
        ("Namespace", "stream-apps", "", "CREATED"),
        ("Deployment", "ex04-1115", "stream-apps", "APPLIED"),
        ("HorizontalPodAutoscaler", "ex04-1115", "stream-apps", "APPLIED"),
        ("ServiceAccount", "sa-stream-worker", "stream-apps", "APPLIED"),
    ]
    assert rep["resources"][0]["source"] == "platform"
    kinds = [e[0] for e in cluster.events]
    # discovery policy, then the namespace (GET, dry-run create, create), then the documents' dry runs and applies
    first_ns = kinds.index("GET-NS")
    assert set(kinds[:first_ns]) == {"DISCOVERY"}
    assert cluster.events[first_ns:first_ns + 3] == [
        ("GET-NS", "/api/v1/namespaces/stream-apps"), ("POST", "/api/v1/namespaces", "All"),
        ("POST", "/api/v1/namespaces", None)]
    patches = cluster.events[first_ns + 3:]
    assert [e[0] for e in patches] == ["PATCH"] * 6 and [e[2] for e in patches] == ["All"] * 3 + [None] * 3
    assert all("/namespaces/stream-apps/" in e[1] for e in patches)
    # exactly the name, the declaration's allowed labels and the platform label; create-only POST, field manager
    for path, params, ctype, body in cluster.posts:
        assert params["fieldManager"] == "stackvend" and ctype == "application/json"
        assert body == {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "stream-apps", "labels": {
            "app.kubernetes.io/managed-by": "stackvend", "app.kubernetes.io/name": "ex04-1115",
            "app.kubernetes.io/part-of": "ex04-1115"}}}


def test_a_redeploy_never_modifies_the_existing_namespace(tmp_path):
    cluster = _Cluster(existing={"stream-apps"})
    rep = _apply(_ex04_ws(tmp_path), cluster)
    assert rep["resources"][0]["status"] == "EXISTS"
    assert cluster.posts == [] and ("GET-NS", "/api/v1/namespaces/stream-apps") in cluster.events
    assert not any(e[0] == "PATCH" and e[1].startswith("/api/v1/namespaces/stream-apps") and e[1].count("/") == 4
                   for e in cluster.events)                       # never a patch of the Namespace object itself


@pytest.mark.parametrize("dry_answer,expected_posts", [(True, 1), (False, 2)])
def test_a_namespace_created_concurrently_is_exists_never_modified(tmp_path, dry_answer, expected_posts):
    conflict = _Res(409, {"kind": "Status", "reason": "AlreadyExists"})
    cluster = _Cluster(ns_post=lambda p: conflict if (p.get("dryRun") == "All") is dry_answer else None)
    rep = _apply(_ex04_ws(tmp_path), cluster)
    assert rep["resources"][0]["status"] == "EXISTS" and len(cluster.posts) == expected_posts


def test_a_namespace_only_implied_by_its_objects_is_created_with_the_platform_label_only(tmp_path):
    cluster = _Cluster()
    rep = _apply(_ws(tmp_path, {"a.yaml": _DEP_IN.format(ns="stream-apps")}), cluster)
    assert [(r["kind"], r["status"]) for r in rep["resources"]] == [("Namespace", "CREATED"), ("Deployment", "APPLIED")]
    assert cluster.posts[0][3]["metadata"] == {"name": "stream-apps",
                                               "labels": {"app.kubernetes.io/managed-by": "stackvend"}}


def test_several_namespaces_are_ensured_once_each_in_name_order(tmp_path):
    cluster = _Cluster(existing={"b-apps"})
    rep = _apply(_ws(tmp_path, {"a.yaml": _DEP_IN.format(ns="c-apps"), "b.yaml": _NS.format(ns="b-apps"),
                                "c.yaml": _NS.format(ns="a-apps"),
                                "d.yaml": _CM.replace("name: c\n", "name: c\n  namespace: c-apps\n")}), cluster)
    assert [(r["name"], r["status"]) for r in rep["resources"] if r["kind"] == "Namespace"] == [
        ("a-apps", "CREATED"), ("b-apps", "EXISTS"), ("c-apps", "CREATED")]
    assert [e[1] for e in cluster.events if e[0] == "GET-NS"] == [
        "/api/v1/namespaces/a-apps", "/api/v1/namespaces/b-apps", "/api/v1/namespaces/c-apps"]


def test_identical_duplicate_declarations_are_one_namespace(tmp_path):
    cluster = _Cluster()
    rep = _apply(_ws(tmp_path, {"a.yaml": _NS.format(ns="apps"), "b.yaml": _NS.format(ns="apps")}), cluster)
    assert [(r["name"], r["status"]) for r in rep["resources"]] == [("apps", "CREATED")]
    assert len(cluster.posts) == 2                                 # one dry run + one create


# ------------------------------------------------------------------------------------- Do No Harm (negative tests)
@pytest.mark.parametrize("docs", [
    {"a.yaml": _DEP, "b.yaml": _CM},
    {"a.yaml": _DEP_IN.format(ns="default"), "b.yaml": _CM},
])
def test_a_default_namespace_workload_makes_exactly_the_calls_it_made_before(tmp_path, docs):
    """No namespace other than `default`: no namespace read or write; the report and calls are the pre-fix ones."""
    cluster = _Cluster()
    rep = _apply(_ws(tmp_path, docs), cluster)
    assert [e[0] for e in cluster.events] == ["DISCOVERY", "DISCOVERY", "PATCH", "PATCH", "PATCH", "PATCH"]
    assert cluster.posts == []
    assert rep == {"status": "APPLIED", "cluster_name": "gke-app", "resources": [
        {"api_version": "apps/v1", "kind": "Deployment", "name": "web", "namespace": "default", "status": "APPLIED"},
        {"api_version": "v1", "kind": "ConfigMap", "name": "c", "namespace": "default", "status": "APPLIED"}]}


def test_no_manifest_is_still_nothing_to_do(tmp_path):
    assert _mod().apply_workspace_manifests(str(tmp_path), google_session=None, token="t", project_id="child-1",
                                            location="us-central1", cluster_name="gke-app", http=None) is None


def test_a_failure_without_platform_namespaces_reads_exactly_as_before(tmp_path):
    mod = _mod()
    cluster = _Cluster(patch_fail=lambda path, params: "configmaps" in path)
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(_ws(tmp_path, {"a.yaml": _DEP, "b.yaml": _CM}), cluster)
    res = ei.value.result("gke-app")
    assert res["error"] == ("K8S_MANIFEST_APPLY_FAILED: GKE cluster 'gke-app' rejected a Kubernetes manifest (k8s/*.yaml) "
                            "as invalid on its server-side dry run (FAILED_SERVER_DRY_RUN: ConfigMap 'c': HTTP 422 "
                            "Invalid). Nothing in k8s/ was applied; correct that manifest in k8s/ (the OpenTofu apply "
                            "finished).")
    assert [r["status"] for r in res["k8s_resources"]] == ["VALIDATED", "FAILED"]


# ------------------------------------------------------------------------------------------------ typed refusals
@pytest.mark.parametrize("text,code,field", [
    ("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: apps\n  annotations:\n    a: b\n",
     "NAMESPACE_FIELD_NOT_ALLOWED", "metadata.annotations"),
    ("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: apps\n  namespace: other\n",
     "NAMESPACE_FIELD_NOT_ALLOWED", "metadata.namespace"),
    ("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: apps\nspec:\n  finalizers: [kubernetes]\n",
     "NAMESPACE_FIELD_NOT_ALLOWED", "spec"),
    ("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: apps\nstatus: {}\n", "NAMESPACE_FIELD_NOT_ALLOWED", "status"),
    ("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: apps\n  labels:\n    pod-security.kubernetes.io/enforce: "
     "privileged\n", "NAMESPACE_LABEL_NOT_ALLOWED", "metadata.labels.pod-security.kubernetes.io/enforce"),
    ("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: apps\n  labels:\n    istio-injection: enabled\n",
     "NAMESPACE_LABEL_NOT_ALLOWED", "metadata.labels.istio-injection"),
    ("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: apps\n  labels:\n    app.kubernetes.io/managed-by: helm\n",
     "NAMESPACE_LABEL_NOT_ALLOWED", "metadata.labels.app.kubernetes.io/managed-by"),
    ("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: apps\n  labels:\n    app.kubernetes.io/name: '-bad'\n",
     "NAMESPACE_LABEL_NOT_ALLOWED", "metadata.labels.app.kubernetes.io/name"),
    ("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: apps\n  labels:\n    app.kubernetes.io/name: 5\n",
     "NAMESPACE_LABEL_NOT_ALLOWED", "metadata.labels.app.kubernetes.io/name"),
    ("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: apps\n  labels: [a]\n",
     "NAMESPACE_LABEL_NOT_ALLOWED", "metadata.labels"),
    ("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: a.b\n", "NAMESPACE_NAME_INVALID", None),
    ("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: default\n  labels:\n    app.kubernetes.io/name: x\n",
     "NAMESPACE_LABEL_NOT_ALLOWED", "metadata.labels"),                 # RT F6: `default` is never modified
    ("apiVersion: v1\nkind: Namespace\nmetadata:\n  name: apps\n1: x\nzz: y\n",   # RT F5: mixed-type keys stay typed
     "NAMESPACE_FIELD_NOT_ALLOWED", "1"),
])
def test_a_declaration_outside_the_exact_shape_is_refused_before_any_cluster_call(tmp_path, text, code, field):
    """RT F2: such a refusal is the generated manifest's defect, decided before any cluster call: IAC_DEFECT, routed
    to the bounded developer repair, with a message that names the Namespace, the code and the field."""
    err = _refusal(tmp_path, {"a.yaml": _DEP, "ns.yaml": text})
    assert [v["code"] for v in err.violations][:1] == [code]
    assert err.violations[0].get("field") == field and err.violations[0]["kind"] == "Namespace"
    assert err.declaration_defect is True and err.developer_owned is True
    res = err.result("gke-app")
    assert res["error_class"] == "IAC_DEFECT" and res["operator_required"] is False
    assert res["code"] == "K8S_MANIFEST_APPLY_FAILED" and res["k8s_manifest_code"] == "REFUSED_POLICY"
    assert f"Namespace '{err.violations[0]['name']}': {code}" in res["error"]
    assert _router().route_of_typed_result(res, "apply")["owner"] == _router().DEVELOPER


def _router():
    if "rt14_dfr_probe_ns" in sys.modules:
        return sys.modules["rt14_dfr_probe_ns"]
    sys.path.insert(0, str(TF_DIR))
    try:
        spec = importlib.util.spec_from_file_location("rt14_dfr_probe_ns", TF_DIR / "deploy_failure_router.py")
        dfr = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dfr)
    finally:
        sys.path.remove(str(TF_DIR))
    sys.modules["rt14_dfr_probe_ns"] = dfr
    return dfr


def test_a_protected_namespace_or_another_kind_in_the_same_refusal_stays_the_operators(tmp_path):
    bad_shape = "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: apps\n  annotations:\n    a: b\n"
    for extra in (_NS.format(ns="kube-system"),
                  "apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: r\n"):
        sub = tmp_path / str(abs(hash(extra)))
        sub.mkdir()
        err = _refusal(sub, {"a.yaml": bad_shape, "b.yaml": extra})
        assert err.declaration_defect is False and err.developer_owned is False
        res = err.result("gke-app")
        assert res["error_class"] == "K8S_MANIFEST_APPLY_FAILED" and res["operator_required"] is True
        assert _router().route_of_typed_result(res, "apply")["owner"] == _router().OPERATOR_REQUIRED


@pytest.mark.parametrize("name", ["a" * 64, "Apps", "-apps"])
def test_a_name_that_is_no_dns_name_stays_manifest_invalid_before_any_cluster_call(tmp_path, name):
    mod = _mod()
    cluster, session = _Cluster(), _GoogleSession()
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(_ws(tmp_path, {"ns.yaml": _NS.format(ns=name)}), cluster, session)
    assert ei.value.code == "MANIFEST_INVALID" and session.calls == [] and cluster.events == []


def test_a_label_value_is_never_reported():
    mod = _mod()
    doc = {"apiVersion": "v1", "kind": "Namespace",
           "metadata": {"name": "apps", "labels": {"x-secret": "SECRET-VALUE"}}}
    assert "SECRET-VALUE" not in repr(mod.namespace_declaration_violations([doc]))


@pytest.mark.parametrize("ns", sorted(["kube-system", "kube-public", "kube-node-lease", "gke-managed-system",
                                       "gmp-system", "istio-system"]))
def test_a_system_namespace_is_never_declared(tmp_path, ns):
    err = _refusal(tmp_path, {"ns.yaml": _NS.format(ns=ns)})
    assert [v["code"] for v in err.violations] == ["PROTECTED_NAMESPACE"]


def test_every_protected_namespace_is_refused_as_a_declaration():
    """The declaration rule reuses the deploy's PROTECTED_NAMESPACES (parity with the k8s MCP: test_rt14 RT14-04)."""
    mod = _mod()
    for ns in sorted(mod.PROTECTED_NAMESPACES):
        doc = {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns}}
        assert [v["code"] for v in mod.namespace_declaration_violations([doc])] == ["PROTECTED_NAMESPACE"]


def test_a_system_namespace_named_by_an_object_is_still_refused(tmp_path):
    err = _refusal(tmp_path, {"a.yaml": _DEP_IN.format(ns="kube-system")})
    assert [v["code"] for v in err.violations] == ["PROTECTED_NAMESPACE"]


def test_two_different_declarations_of_one_namespace_are_refused(tmp_path):
    other = _NS.format(ns="apps") + "  labels:\n    app.kubernetes.io/part-of: x\n"
    err = _refusal(tmp_path, {"a.yaml": _NS.format(ns="apps"), "b.yaml": other})
    assert [v["code"] for v in err.violations] == ["NAMESPACE_DECLARED_TWICE"]


def test_a_namespace_of_another_api_version_keeps_the_cluster_scoped_refusal(tmp_path):
    err = _refusal(tmp_path, {"ns.yaml": "apiVersion: v2\nkind: Namespace\nmetadata:\n  name: apps\n"})
    assert [v["code"] for v in err.violations] == ["CLUSTER_SCOPED_KIND"]


@pytest.mark.parametrize("kind", sorted(k for k in _mod().CLUSTER_SCOPED_KINDS if k != "Namespace"))
def test_every_other_cluster_scoped_kind_is_still_refused(tmp_path, kind):
    err = _refusal(tmp_path, {"a.yaml": _DEP, "x.yaml": f"apiVersion: example.com/v1\nkind: {kind}\nmetadata:\n"
                                                        "  name: x\n"})
    assert [v["code"] for v in err.violations] == ["CLUSTER_SCOPED_KIND"]


def test_a_discovery_refusal_happens_before_any_namespace_is_created(tmp_path):
    mod = _mod()
    cluster = _Cluster()
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(_ws(tmp_path, {"a.yaml": _DEP_IN.format(ns="apps"),
                              "w.yaml": "apiVersion: example.com/v1\nkind: Widget\nmetadata:\n  name: w\n"}), cluster)
    assert [v["code"] for v in ei.value.violations] == ["UNKNOWN_KIND"]
    assert {e[0] for e in cluster.events} == {"DISCOVERY"}


@pytest.mark.parametrize("answer", [_Res(403, {"reason": "Forbidden"}), _Res(500, {})])
def test_an_unreadable_namespace_stops_typed_and_applies_nothing(tmp_path, answer):
    mod = _mod()
    cluster = _Cluster(ns_get=lambda path: answer)
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(_ex04_ws(tmp_path), cluster)
    assert ei.value.code == "NAMESPACE_UNREADABLE" and ei.value.developer_owned is False
    assert cluster.posts == [] and not any(e[0] == "PATCH" for e in cluster.events)
    res = ei.value.result("gke-app")
    assert res["operator_required"] is True and res["k8s_resources"][0]["status"] == "FAILED"


def test_a_namespace_read_transport_error_is_typed(tmp_path):
    mod = _mod()

    def boom(path):
        raise ConnectionError("down")
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(_ex04_ws(tmp_path), _Cluster(ns_get=boom))
    assert ei.value.code == "NAMESPACE_UNREADABLE"


@pytest.mark.parametrize("on_dry", [True, False])
@pytest.mark.parametrize("answer", [_Res(403, {"reason": "Forbidden"}), _Res(422, {"reason": "Invalid"})])
def test_a_failed_namespace_create_stops_for_the_operator_and_applies_no_document(tmp_path, on_dry, answer):
    mod = _mod()
    cluster = _Cluster(ns_post=lambda p: answer if (p.get("dryRun") == "All") is on_dry else None)
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(_ex04_ws(tmp_path), cluster)
    assert ei.value.code == "NAMESPACE_CREATE_FAILED" and ei.value.developer_owned is False
    assert not any(e[0] == "PATCH" for e in cluster.events)
    res = ei.value.result("gke-app")
    assert res["error_class"] == "K8S_MANIFEST_APPLY_FAILED" and res["operator_required"] is True


def test_a_document_failure_after_the_namespace_was_created_reports_it(tmp_path):
    """RT D2 routing is unchanged (a dry-run Invalid stays the developer's); the report and the text say the platform
    created the (empty) namespace first."""
    mod = _mod()
    cluster = _Cluster(patch_fail=lambda path, params: "deployments" in path)
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(_ex04_ws(tmp_path), cluster)
    assert ei.value.code == "FAILED_SERVER_DRY_RUN" and ei.value.developer_owned is True
    res = ei.value.result("gke-app")
    assert [(r["kind"], r["status"]) for r in res["k8s_resources"]] == [
        ("Namespace", "CREATED"), ("Deployment", "FAILED"), ("HorizontalPodAutoscaler", "NOT_ATTEMPTED"),
        ("ServiceAccount", "NOT_ATTEMPTED")]
    assert res["error"].endswith("The platform created the empty namespace(s) stream-apps first; they stay and are "
                                 "reused by the next deploy.")


# ------------------------------------------------------------------------------------------- RT hardening (F1-F10)
@pytest.mark.parametrize("docs", [{"a.yaml": _DEP_IN.format(ns=n)} for n in ("kube-foo", "gke-foo", "gmp-foo")]
                         + [{"ns.yaml": _NS.format(ns=n)} for n in ("kube-foo", "gke-foo", "gmp-foo")])
def test_rt_f1_a_missing_reserved_prefix_namespace_is_never_created(tmp_path, docs):
    mod = _mod()
    cluster = _Cluster()
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(_ws(tmp_path, docs), cluster)
    assert ei.value.code == "NAMESPACE_RESERVED_PREFIX" and ei.value.developer_owned is False
    assert cluster.posts == [] and not any(e[0] == "PATCH" for e in cluster.events)
    assert ei.value.result("gke-app")["operator_required"] is True


@pytest.mark.parametrize("ns", ["kube-foo", "gke-foo", "gmp-foo"])
def test_rt_f1_negative_an_existing_reserved_prefix_namespace_is_used_as_before(tmp_path, ns):
    cluster = _Cluster(existing={ns})
    rep = _apply(_ws(tmp_path, {"a.yaml": _DEP_IN.format(ns=ns)}), cluster)
    assert [(r["kind"], r["status"]) for r in rep["resources"]] == [("Namespace", "EXISTS"), ("Deployment", "APPLIED")]
    assert cluster.posts == []


@pytest.mark.parametrize("body", [{"status": {"phase": "Terminating"}}, {"status": {}}, {}, None])
def test_rt_f3_a_namespace_that_is_not_active_stops_typed(tmp_path, body):
    mod = _mod()
    cluster = _Cluster(ns_get=lambda path: _Res(200, body))
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(_ex04_ws(tmp_path), cluster)
    assert ei.value.code == "NAMESPACE_UNREADABLE" and "not Active" in ei.value.detail
    assert cluster.posts == [] and not any(e[0] == "PATCH" for e in cluster.events)
    assert ei.value.result("gke-app")["operator_required"] is True


def test_rt_f6_a_label_free_default_declaration_is_never_read_or_written(tmp_path):
    cluster = _Cluster()
    rep = _apply(_ws(tmp_path, {"a.yaml": _DEP, "ns.yaml": _NS.format(ns="default")}), cluster)
    assert [e[0] for e in cluster.events] == ["DISCOVERY", "PATCH", "PATCH"] and cluster.posts == []
    assert [r["kind"] for r in rep["resources"]] == ["Deployment"]


def test_rt_f7_labels_of_a_declaration_on_an_existing_namespace_are_reported_not_applied(tmp_path):
    rep = _apply(_ex04_ws(tmp_path), _Cluster(existing={"stream-apps"}))
    assert rep["resources"][0] == {"api_version": "v1", "kind": "Namespace", "name": "stream-apps", "namespace": "",
                                   "status": "EXISTS", "source": "platform", "labels_applied": False}
    (tmp_path / "x").mkdir()
    rep2 = _apply(_ws(tmp_path / "x", {"a.yaml": _DEP_IN.format(ns="stream-apps")}), _Cluster(existing={"stream-apps"}))
    assert "labels_applied" not in rep2["resources"][0]          # nothing declared, nothing to report


def test_rt_f8_nothing_is_created_unless_every_namespace_passes_its_dry_run(tmp_path):
    mod = _mod()
    seen = []

    def post(params):
        seen.append(params.get("dryRun"))
        return _Res(403, {"kind": "Status", "reason": "Forbidden"}) if len(seen) == 2 else None   # b's dry run
    cluster = _Cluster(ns_post=post)
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(_ws(tmp_path, {"a.yaml": _NS.format(ns="a-apps"), "b.yaml": _NS.format(ns="b-apps")}), cluster)
    assert ei.value.code == "NAMESPACE_CREATE_FAILED" and "b-apps" in ei.value.detail
    assert [p[1].get("dryRun") for p in cluster.posts] == ["All", "All"]   # no real create happened
    assert "created the empty namespace" not in ei.value.result("gke-app")["error"]


def test_rt_f8_a_second_real_create_failing_reports_the_first_as_created(tmp_path):
    mod = _mod()
    seen = []

    def post(params):
        seen.append(params.get("dryRun"))
        return _Res(403, {"kind": "Status", "reason": "Forbidden"}) if len(seen) == 4 else None   # b's real create
    cluster = _Cluster(ns_post=post)
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(_ws(tmp_path, {"a.yaml": _NS.format(ns="a-apps"), "b.yaml": _NS.format(ns="b-apps")}), cluster)
    assert [p[1].get("dryRun") for p in cluster.posts] == ["All", "All", None, None]
    res = ei.value.result("gke-app")
    assert [(r["name"], r["status"]) for r in res["k8s_resources"]] == [("a-apps", "CREATED"), ("b-apps", "FAILED")]
    assert "The platform created the empty namespace(s) a-apps first" in res["error"]
    assert res["operator_required"] is True


def test_rt_f9_a_lost_create_answer_is_re_read_once(tmp_path):
    class Lost(_Cluster):
        def post(self, url, params=None, **kw):
            if (params or {}).get("dryRun") is None:
                self.events.append(("POST", "/api/v1/namespaces", None))
                self.existing.add("stream-apps")                     # it was created, the answer was lost
                raise TimeoutError("lost")
            return super().post(url, params=params, **kw)
    cluster = Lost()
    rep = _apply(_ex04_ws(tmp_path), cluster)
    assert rep["resources"][0]["status"] == "CREATED" and rep["resources"][0]["create_answer_lost"] is True
    assert [e[1] for e in cluster.events if e[0] == "GET-NS"] == ["/api/v1/namespaces/stream-apps"] * 2


def test_rt_f9_a_lost_create_answer_without_the_namespace_fails_typed(tmp_path):
    mod = _mod()

    class Lost(_Cluster):
        def post(self, url, params=None, **kw):
            if (params or {}).get("dryRun") is None:
                raise TimeoutError("lost")
            return super().post(url, params=params, **kw)
    cluster = Lost()
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(_ex04_ws(tmp_path), cluster)
    assert ei.value.code == "NAMESPACE_CREATE_FAILED" and "TimeoutError" in ei.value.detail
    assert not any(e[0] == "PATCH" for e in cluster.events)


def test_rt_f10_a_conflict_that_is_not_already_exists_fails_typed(tmp_path):
    mod = _mod()
    cluster = _Cluster(ns_post=lambda p: _Res(409, {"kind": "Status", "reason": "Conflict"}))
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(_ex04_ws(tmp_path), cluster)
    assert ei.value.code == "NAMESPACE_CREATE_FAILED" and ei.value.api_reason == "Conflict"


def test_rt_f10_a_namespace_inside_a_list_is_a_declaration(tmp_path):
    lst = ("apiVersion: v1\nkind: List\nitems:\n- apiVersion: v1\n  kind: Namespace\n  metadata:\n    name: apps\n"
           "    labels:\n      app.kubernetes.io/part-of: demo\n")
    cluster = _Cluster()
    rep = _apply(_ws(tmp_path, {"a.yaml": lst, "b.yaml": _DEP_IN.format(ns="apps")}), cluster)
    assert [(r["kind"], r["status"]) for r in rep["resources"]] == [("Namespace", "CREATED"), ("Deployment", "APPLIED")]
    assert cluster.posts[0][3]["metadata"]["labels"] == {"app.kubernetes.io/managed-by": "stackvend",
                                                          "app.kubernetes.io/part-of": "demo"}


def test_rt_f10_a_namespace_only_workspace_creates_it_and_applies_nothing_else(tmp_path):
    cluster = _Cluster()
    rep = _apply(_ws(tmp_path, {"ns.yaml": _NS.format(ns="apps")}), cluster)
    assert rep["status"] == "APPLIED" and [(r["kind"], r["status"]) for r in rep["resources"]] == [
        ("Namespace", "CREATED")]
    assert not any(e[0] in ("PATCH", "DISCOVERY") for e in cluster.events)


# ------------------------------------------------------------------------------------------------ structural guards
def test_namespaces_are_only_read_or_created_never_patched_or_deleted():
    """AST: the two namespace calls use only `get` / `post`; ensure_namespaces calls no patch or delete."""
    tree = ast.parse((TF_DIR / "k8s_manifest_apply.py").read_text(encoding="utf-8"))
    fns = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    verbs = {"get", "post", "put", "patch", "delete"}
    for name, allowed in (("namespace_status", {"get"}), ("create_namespace", {"post"}),
                          ("ensure_namespaces", set())):
        used = {c.func.attr for c in ast.walk(fns[name]) if isinstance(c, ast.Call)
                and isinstance(c.func, ast.Attribute) and c.func.attr in verbs}
        assert used == allowed, name


def test_the_allowed_labels_are_the_recommended_app_labels_without_managed_by():
    mod = _mod()
    assert mod.NAMESPACE_LABEL_ALLOW == {f"app.kubernetes.io/{k}" for k in
                                         ("name", "instance", "version", "component", "part-of")}
    assert dict(mod.PLATFORM_LABELS) == {"app.kubernetes.io/managed-by": "stackvend"}


def test_the_kubernetes_mcp_policy_is_unchanged():
    """The Day-2 k8s MCP keeps refusing Namespace (its own apply tool); only the deploy's applier creates namespaces."""
    src = (REPO / "mcp-servers" / "kubernetes" / "helm.py").read_text(encoding="utf-8")
    tree = ast.parse(src)
    names = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    assert "ensure_namespaces" not in names and "namespace_declaration_violations" not in names


@pytest.mark.parametrize("ns", ["gkeapp", "app-gke", "gmpx", "my-kube-app"])
def test_owner_1116_reserved_prefixes_match_only_the_start(tmp_path, ns):
    """Negative: a name that merely contains or resembles a reserved prefix is created as any other."""
    cluster = _Cluster()
    rep = _apply(_ws(tmp_path, {"a.yaml": _DEP_IN.format(ns=ns)}), cluster)
    assert ("Namespace", "CREATED") in [(r["kind"], r["status"]) for r in rep["resources"]]
