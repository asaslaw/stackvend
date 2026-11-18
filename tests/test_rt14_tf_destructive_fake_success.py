"""RT14 group tf-destructive-fake-success (full-scope red-team 11-14; plan docs/planning/rt14-tf-destructive-fake-success-plan.md).

Structural guards (AST, never text heuristics) plus behaviour tests for:
  RT14-01  no REST delete and no `state rm` outside the plan / destroy gates in the terraform server and tf-applier
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import ast
import os
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
TF_DIR = REPO / "mcp-servers" / "terraform"
TF_SOURCES = sorted(p for p in TF_DIR.glob("*.py") if not p.name.startswith("test_"))


def _tree(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


# ============================================================================================================ RT14-01
def _url_arg(node: ast.Call) -> bool:
    """The call's first argument is a URL literal or f-string (a REST call), not e.g. a dict key."""
    if not node.args:
        return False
    first = node.args[0]
    if isinstance(first, ast.Constant) and isinstance(first.value, str):
        return first.value.startswith("https://")
    if isinstance(first, ast.JoinedStr) and first.values:
        head = first.values[0]
        return isinstance(head, ast.Constant) and isinstance(head.value, str) and head.value.startswith("https://")
    return False


@pytest.mark.parametrize("path", TF_SOURCES, ids=lambda p: p.name)
def test_rt14_01_no_rest_delete_in_the_terraform_server(path):
    """A REST DELETE (`<session>.delete("https://...")`) runs outside every plan / destroy / approval gate; none is left
    (the stub purge, subnet case B and the regex subnet delete are deleted). A new one fails here."""
    offenders = [f"{path.name}:{n.lineno}" for n in ast.walk(_tree(path))
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "delete"
                 and _url_arg(n)]
    assert offenders == []


@pytest.mark.parametrize("path", TF_SOURCES, ids=lambda p: p.name)
def test_rt14_01_no_state_rm_in_the_terraform_server(path):
    """A `state rm` list literal (hardcoded addresses orphaned live resources) is never built by the platform."""
    offenders = []
    for n in ast.walk(_tree(path)):
        if isinstance(n, ast.List):
            words = [e.value for e in n.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            if any(words[i:i + 2] == ["state", "rm"] for i in range(len(words))):
                offenders.append(f"{path.name}:{n.lineno}")
    assert offenders == []


def test_rt14_01_the_purge_and_its_trigger_are_gone():
    names = {n.name for p in TF_SOURCES for n in ast.walk(_tree(p)) if isinstance(n, (ast.FunctionDef,
                                                                                         ast.AsyncFunctionDef))}
    assert "purge_errored_child_stubs" not in names
    assert "legacy_subnet_purge_trigger" not in names
    assert "detect_errored_child_stubs" in names


def test_rt14_01_detection_is_get_only():
    """detect_errored_child_stubs calls no method other than `get` on any object it builds a URL for."""
    node = next(n for n in ast.walk(_tree(TF_DIR / "service.py"))
                if isinstance(n, ast.FunctionDef) and n.name == "detect_errored_child_stubs")
    verbs = {c.func.attr for c in ast.walk(node) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)
             and c.func.attr in ("get", "post", "put", "patch", "delete", "_run_subprocess", "_run_with_own_budget")}
    assert verbs == {"get"}


def test_rt14_01_deploy_workload_never_calls_stub_detection_or_purge():
    """Pass 0.5 is gone: the deploy itself neither purges nor lists stubs (only the tf-applier's stockout branch
    lists them, read-only)."""
    node = next(n for n in ast.walk(_tree(TF_DIR / "service.py"))
                if isinstance(n, ast.FunctionDef) and n.name == "deploy_workload")
    called = {c.func.attr for c in ast.walk(node) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute)}
    assert not called & {"purge_errored_child_stubs", "detect_errored_child_stubs"}


def test_rt14_01_subnet_conflict_classifier_is_exact_and_negative():
    import importlib.util
    import sys
    sys.path.insert(0, str(TF_DIR))
    try:
        svc_mod = sys.modules.get("service")
        if svc_mod is None or not hasattr(svc_mod, "is_subnet_cidr_conflict"):
            spec = importlib.util.spec_from_file_location("rt14_service_probe", TF_DIR / "service.py")
            svc_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(svc_mod)
    finally:
        sys.path.remove(str(TF_DIR))
    conflict = ("Error: Error creating Subnetwork: googleapi: Error 400: Invalid IPCidrRange: 10.10.0.0/24 conflicts "
                "with existing subnetwork 'castor-app-subnet' in region 'us-central1'.")
    assert svc_mod.is_subnet_cidr_conflict(conflict) is True
    assert svc_mod.is_subnet_cidr_conflict("Error 400: Invalid IPCidrRange: 10.0.0.0/33") is False
    assert svc_mod.is_subnet_cidr_conflict("") is False and svc_mod.is_subnet_cidr_conflict(None) is False


# ============================================================================================================ RT14-04
def _k8s_mod():
    import importlib.util
    import sys
    if "k8s_manifest_apply" in sys.modules:
        return sys.modules["k8s_manifest_apply"]
    spec = importlib.util.spec_from_file_location("k8s_manifest_apply", TF_DIR / "k8s_manifest_apply.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["k8s_manifest_apply"] = mod
    spec.loader.exec_module(mod)
    return mod


def _assigned(path: Path, name: str) -> ast.AST:
    for n in ast.walk(_tree(path)):
        if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets):
            return n.value
    raise AssertionError(f"{name} not found in {path}")


def _frozenset_literal(path: Path, name: str) -> set:
    call = _assigned(path, name)
    assert isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "frozenset"
    return {e.value for e in call.args[0].elts}


HELM = REPO / "mcp-servers" / "kubernetes" / "helm.py"


@pytest.mark.parametrize("name", ["PROTECTED_NAMESPACES", "CLUSTER_SCOPED_KINDS"])
def test_rt14_04_policy_sets_equal_the_kubernetes_mcp(name):
    assert _frozenset_literal(TF_DIR / "k8s_manifest_apply.py", name) == _frozenset_literal(HELM, name)


def test_rt14_04_field_manager_equals_the_kubernetes_mcp():
    ours = _assigned(TF_DIR / "k8s_manifest_apply.py", "FIELD_MANAGER")
    theirs = _assigned(HELM, "FIELD_MANAGER")
    assert ours.value == theirs.value == "stackvend"


def test_rt14_04_no_in_process_kubernetes_import_left():
    """The ImportError path (kubernetes.service / the bare `service` fallback) is gone; no kubernetes client either."""
    for path in TF_SOURCES:
        for n in ast.walk(_tree(path)):
            if isinstance(n, ast.ImportFrom):
                assert not (n.module or "").startswith("kubernetes"), f"{path.name}:{n.lineno}"
                assert not any(a.name == "KubernetesService" for a in n.names), f"{path.name}:{n.lineno}"
            if isinstance(n, ast.Import):
                assert not any(a.name.startswith("kubernetes") for a in n.names), f"{path.name}:{n.lineno}"


class _Res:
    def __init__(self, status, body=None):
        self.status_code, self._body = status, body

    def json(self):
        return self._body


class _GoogleSession:
    def __init__(self, answer):
        self.answer, self.calls = answer, []

    def get(self, url, **kw):
        self.calls.append(url)
        return self.answer


_CLUSTER_OK = _Res(200, {"endpoint": "10.0.0.1", "masterAuth": {"clusterCaCertificate": "Y2E="}})
_DISCOVERY = {
    "/apis/apps/v1": {"resources": [{"name": "deployments", "kind": "Deployment", "namespaced": True},
                                    {"name": "deployments/scale", "kind": "Scale", "namespaced": True}]},
    "/api/v1": {"resources": [{"name": "services", "kind": "Service", "namespaced": True},
                              {"name": "nodes", "kind": "Node", "namespaced": False},
                              {"name": "configmaps", "kind": "ConfigMap", "namespaced": True}]},
    "/apis/example.com/v1": {"resources": [{"name": "gadgets", "kind": "Gadget", "namespaced": False}]},
}


class _Http:
    def __init__(self, fail_patch=None, fail_answer=None):
        self.patches, self.gets, self.fail_patch = [], [], fail_patch
        self.fail_answer = fail_answer or _Res(422, {"reason": "Invalid"})

    def get(self, url, **kw):
        path = url.split("10.0.0.1", 1)[1]
        self.gets.append(path)
        return _Res(200, _DISCOVERY[path]) if path in _DISCOVERY else _Res(404, {})

    def patch(self, url, params=None, data=None, headers=None, **kw):
        self.patches.append((url.split("10.0.0.1", 1)[1], dict(params or {}), headers.get("Content-Type")))
        if self.fail_patch and self.fail_patch(url, params):
            return self.fail_answer
        return _Res(200, {})


def _ws(tmp_path, docs):
    (tmp_path / "k8s").mkdir()
    for name, text in docs.items():
        (tmp_path / "k8s" / name).write_text(text)
    return str(tmp_path)


_DEP = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\n"
_SVC = "apiVersion: v1\nkind: Service\nmetadata:\n  name: web\n"


def _apply(mod, ws, http, session=None):
    return mod.apply_workspace_manifests(ws, google_session=session or _GoogleSession(_CLUSTER_OK), token="t",
                                         project_id="child-1", location="us-central1", cluster_name="gke-app",
                                         http=http)


def test_rt14_04_dry_run_of_every_document_before_the_server_side_apply(tmp_path):
    mod = _k8s_mod()
    http = _Http()
    rep = _apply(mod, _ws(tmp_path, {"a.yaml": _DEP, "b.yaml": _SVC}), http)
    assert rep["status"] == "APPLIED" and [r["status"] for r in rep["resources"]] == ["APPLIED", "APPLIED"]
    dep, svc = "/apis/apps/v1/namespaces/default/deployments/web", "/api/v1/namespaces/default/services/web"
    assert [(p, q.get("dryRun"), q["fieldManager"], ct) for p, q, ct in http.patches] == [
        (dep, "All", "stackvend", "application/apply-patch+yaml"),
        (svc, "All", "stackvend", "application/apply-patch+yaml"),
        (dep, None, "stackvend", "application/apply-patch+yaml"),
        (svc, None, "stackvend", "application/apply-patch+yaml"),
    ]


@pytest.mark.parametrize("doc,code", [
    ("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n  namespace: kube-system\n", "PROTECTED_NAMESPACE"),
    ("apiVersion: rbac.authorization.k8s.io/v1\nkind: ClusterRole\nmetadata:\n  name: r\n", "CLUSTER_SCOPED_KIND"),
])
def test_rt14_04_precheck_refuses_before_any_cluster_call(tmp_path, doc, code):
    mod = _k8s_mod()
    http, sess = _Http(), _GoogleSession(_CLUSTER_OK)
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(mod, _ws(tmp_path, {"a.yaml": _DEP, "x.yaml": doc}), http, sess)
    assert ei.value.code == "REFUSED_POLICY" and [v["code"] for v in ei.value.violations] == [code]
    assert sess.calls == [] and http.gets == [] and http.patches == []


@pytest.mark.parametrize("doc,code", [
    ("apiVersion: example.com/v1\nkind: Widget\nmetadata:\n  name: w\n", "UNKNOWN_KIND"),
    ("apiVersion: example.com/v1\nkind: Gadget\nmetadata:\n  name: g\n", "CLUSTER_SCOPED_KIND"),  # by discovery
])
def test_rt14_04_discovery_refuses_unknown_or_cluster_scoped_kinds_and_applies_nothing(tmp_path, doc, code):
    mod = _k8s_mod()
    http = _Http()
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(mod, _ws(tmp_path, {"a.yaml": _DEP, "x.yaml": doc}), http)
    assert [v["code"] for v in ei.value.violations] == [code]
    assert http.patches == []


def test_rt14_04_a_dry_run_failure_applies_nothing(tmp_path):
    mod = _k8s_mod()
    http = _Http(fail_patch=lambda url, params: "services" in url)
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(mod, _ws(tmp_path, {"a.yaml": _DEP, "b.yaml": _SVC}), http)
    assert ei.value.code == "FAILED_SERVER_DRY_RUN"
    assert all(q.get("dryRun") == "All" for _p, q, _ct in http.patches)
    res = ei.value.result("gke-app")
    # the fake answers 422 Invalid: the cluster says the manifest is invalid -> the developer's (RT D2)
    assert res["error_class"] == "IAC_DEFECT" and res["code"] == "K8S_MANIFEST_APPLY_FAILED"
    assert res["stage"] == "k8s_manifest_apply"
    assert [r["status"] for r in res["k8s_resources"]] == ["VALIDATED", "FAILED"]


@pytest.mark.parametrize("answer,developer", [
    (_Res(422, {"kind": "Status", "reason": "Invalid"}), True),
    (_Res(400, {"kind": "Status", "reason": "BadRequest"}), True),
    (_Res(403, {"kind": "Status", "reason": "Forbidden"}), False),
    (_Res(401, {"kind": "Status", "reason": "Unauthorized"}), False),
    (_Res(409, {"kind": "Status", "reason": "Conflict"}), False),
    (_Res(422, {"kind": "Status", "reason": "Forbidden"}), False),     # status and reason must both say invalid
    (_Res(422, None), False),                                          # no typed reason
    (_Res(500, {"kind": "Status", "reason": "InternalError"}), False),
])
def test_rt14_rt_d2_dry_run_invalid_is_the_developers_other_failures_the_operators(tmp_path, answer, developer):
    """RT D2 (owner 11-14): typed fields only (HTTP status + Status.reason, never the message): a server dry run that
    rejects a manifest as invalid is IAC_DEFECT, not flagged (DEVELOPER route); anything else is operator_required."""
    import importlib.util
    import sys
    mod = _k8s_mod()
    http = _Http(fail_patch=lambda url, params: "services" in url, fail_answer=answer)
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(mod, _ws(tmp_path, {"a.yaml": _DEP, "b.yaml": _SVC}), http)
    assert ei.value.code == "FAILED_SERVER_DRY_RUN" and ei.value.developer_owned is developer
    res = ei.value.result("gke-app")
    assert res["stage"] == "k8s_manifest_apply" and res["k8s_manifest_code"] == "FAILED_SERVER_DRY_RUN"
    assert res["error"].startswith("K8S_MANIFEST_APPLY_FAILED")
    if developer:
        assert res["error_class"] == "IAC_DEFECT" and res["operator_required"] is False
    else:
        assert res["error_class"] == "K8S_MANIFEST_APPLY_FAILED" and res["operator_required"] is True
    sys.path.insert(0, str(TF_DIR))
    try:
        spec = importlib.util.spec_from_file_location("rt14_dfr_probe", TF_DIR / "deploy_failure_router.py")
        dfr = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dfr)
    finally:
        sys.path.remove(str(TF_DIR))
    assert dfr.route_of_typed_result(res, "apply")["owner"] == (dfr.DEVELOPER if developer else dfr.OPERATOR_REQUIRED)


@pytest.mark.parametrize("code", ["CLUSTER_UNREADABLE", "DISCOVERY_FAILED", "REFUSED_POLICY", "PARTIALLY_APPLIED",
                                  "FAILED_APPLY", "MANIFEST_INVALID", "APPLY_ERROR"])
def test_rt14_rt_d2_no_other_code_is_developer_owned_even_with_an_invalid_answer(code):
    mod = _k8s_mod()
    err = mod.ManifestApplyFailed(code, "x", http_status=422, api_reason="Invalid")
    assert err.developer_owned is False and err.result("c")["operator_required"] is True


def test_rt14_rt_d2_iac_defect_class_equals_the_service_and_router():
    assert _assigned(TF_DIR / "k8s_manifest_apply.py", "IAC_DEFECT").value == \
        _assigned(TF_DIR / "service.py", "IAC_DEFECT_ERROR_CLASS").value == \
        _assigned(TF_DIR / "deploy_failure_router.py", "IAC_DEFECT").value == "IAC_DEFECT"


def test_rt14_rt_f3_a_rejection_names_the_failing_fields_never_the_cause_message(tmp_path):
    """RT F3: the per-document error and report carry Status.details.causes[].field / .reason (capped), so the developer
    repair (RT D2) knows which field; the cause `message` (it can quote a value) is never read."""
    mod = _k8s_mod()
    causes = [{"field": f"spec.template.spec.containers[{i}].image", "reason": "FieldValueRequired",
               "message": "SECRET-VALUE-xyz"} for i in range(mod.MAX_CAUSES + 3)]
    answer = _Res(422, {"kind": "Status", "reason": "Invalid", "message": "SECRET-VALUE-abc",
                        "details": {"causes": causes}})
    http = _Http(fail_patch=lambda url, params: "deployments" in url, fail_answer=answer)
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(mod, _ws(tmp_path, {"a.yaml": _DEP}), http)
    res = ei.value.result("gke-app")
    failed = res["k8s_resources"][0]
    assert failed["error"].startswith("HTTP 422 Invalid (spec.template.spec.containers[0].image: FieldValueRequired;")
    assert len(failed["causes"]) == mod.MAX_CAUSES and set(failed["causes"][0]) == {"field", "reason"}
    assert "SECRET-VALUE" not in repr(res)
    assert ei.value.developer_owned is True                         # the typed reason is unchanged by the causes


def test_rt14_rt_f3_negative_an_answer_without_causes_reads_as_before(tmp_path):
    mod = _k8s_mod()
    http = _Http(fail_patch=lambda url, params: "deployments" in url,
                 fail_answer=_Res(403, {"kind": "Status", "reason": "Forbidden", "details": {"name": "web"}}))
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(mod, _ws(tmp_path, {"a.yaml": _DEP}), http)
    failed = ei.value.resources[0]
    assert failed["error"] == "HTTP 403 Forbidden" and "causes" not in failed


def test_rt14_04_a_partial_apply_is_typed(tmp_path):
    mod = _k8s_mod()
    http = _Http(fail_patch=lambda url, params: "services" in url and "dryRun" not in params)
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(mod, _ws(tmp_path, {"a.yaml": _DEP, "b.yaml": _SVC}), http)
    assert ei.value.code == "PARTIALLY_APPLIED"
    assert [r["status"] for r in ei.value.resources] == ["APPLIED", "FAILED"]


@pytest.mark.parametrize("answer", [_Res(403, {}), _Res(200, {"endpoint": "10.0.0.1"})])
def test_rt14_04_unreadable_cluster_is_typed(tmp_path, answer):
    mod = _k8s_mod()
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(mod, _ws(tmp_path, {"a.yaml": _DEP}), _Http(), _GoogleSession(answer))
    assert ei.value.code == "CLUSTER_UNREADABLE"


@pytest.mark.parametrize("api_version", ["v1", "apps/v1", "autoscaling/v2", "networking.k8s.io/v1"])
def test_rt14_04_rt_f1_valid_api_versions_and_kinds_load_unchanged(tmp_path, api_version):
    """RT F1 negative (Do No Harm): valid apiVersion / kind values pass load_documents as they are."""
    mod = _k8s_mod()
    text = f"apiVersion: {api_version}\nkind: HorizontalPodAutoscaler\nmetadata:\n  name: web\n"
    docs = mod.load_documents(mod.manifest_files(_ws(tmp_path, {"a.yaml": text})))
    assert docs == [{"apiVersion": api_version, "kind": "HorizontalPodAutoscaler", "metadata": {"name": "web"}}]


@pytest.mark.parametrize("api_version,kind", [
    ("apps/v1/../x", "Deployment"), ("v1?x=", "Service"), ("a/b/c", "Deployment"), ("apps/v1#f", "Deployment"),
    ("../v1", "Deployment"), ("Apps/v1", "Deployment"), ("apps/", "Deployment"), (1, "Deployment"),
    ("apps/v1", 5), ("apps/v1", "Deploy/ment"), ("apps/v1", "Deployment?x"), ("apps/v1", ""), ("apps/v1", "Dé"),
])
def test_rt14_04_rt_f1_api_version_and_kind_outside_the_typed_shape_are_refused(tmp_path, api_version, kind):
    """RT F1: apiVersion / kind reach the discovery GET and the PATCH URL; anything but `v1` or `<group>/<version>`
    and an ASCII alphanumeric kind is MANIFEST_INVALID before any cluster call."""
    import json
    mod = _k8s_mod()
    http, sess = _Http(), _GoogleSession(_CLUSTER_OK)
    doc = json.dumps({"apiVersion": api_version, "kind": kind, "metadata": {"name": "web"}})   # JSON is YAML
    with pytest.raises(mod.ManifestApplyFailed) as ei:
        _apply(mod, _ws(tmp_path, {"a.yaml": doc}), http, sess)
    assert ei.value.code == "MANIFEST_INVALID"
    assert sess.calls == [] and http.gets == [] and http.patches == []


def _service_mod():
    import importlib.util
    import sys
    mod = sys.modules.get("service")
    if mod is not None and hasattr(mod, "mask_sensitive_outputs"):
        return mod
    sys.path.insert(0, str(TF_DIR))
    try:
        spec = importlib.util.spec_from_file_location("rt14_service_probe", TF_DIR / "service.py")
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    finally:
        sys.path.remove(str(TF_DIR))
    return mod


# ============================================================================================================ RT14-09
def test_rt14_09_sensitive_outputs_are_masked_by_the_engine_flag_only():
    svc = _service_mod()
    raw = {"db_password": {"sensitive": True, "type": "string", "value": "s3cret"},
           "conn": {"sensitive": True, "type": ["object", {}], "value": {"user": "u", "pw": "p"}},
           "password_hint": {"sensitive": False, "type": "string", "value": "not-a-secret"},
           "service_url": {"sensitive": False, "type": "string", "value": "https://a.run.app"}}
    masked = svc.mask_sensitive_outputs(raw)
    assert masked["db_password"] == {"sensitive": True, "type": "string", "value": "(sensitive value)"}
    assert masked["conn"]["value"] == "(sensitive value)"
    # negative (Do No Harm): unmarked outputs are the same objects, whatever their name; the input is untouched
    assert masked["password_hint"] is raw["password_hint"] and masked["service_url"] is raw["service_url"]
    assert raw["db_password"]["value"] == "s3cret"


def test_rt14_09_output_json_is_read_only_by_the_masking_reader():
    """Every `output` engine command in the terraform server sits in `_read_tofu_outputs` (AST): a new reader that
    could store or return clear-text sensitive outputs fails here."""
    owners = []
    for path in TF_SOURCES:
        tree = _tree(path)
        for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            for n in ast.walk(fn):
                if isinstance(n, ast.List) and len(n.elts) >= 2 and all(isinstance(e, ast.Constant) for e in n.elts[:2]) \
                        and n.elts[0].value in ("terraform", "tofu") and n.elts[1].value == "output":
                    owners.append((path.name, fn.name))
    assert owners and set(owners) == {("service.py", "_read_tofu_outputs")}


# ============================================================================================================ RT14-21
PNG = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\xff\xfe"


class _FakeDb:
    """A non-None Firestore stand-in so the service never constructs a real client (hermetic guard)."""
FONT = b"wOF2\x00\x01\x00\x00\x80\x81\xc3\x28"


def test_rt14_21_text_blobs_decode_exactly_as_before_and_binary_blobs_stay_bytes():
    svc = _service_mod()
    for text in ("print('hi')\n", "café ☃\n", ""):
        raw = text.encode("utf-8")
        assert svc.decode_repo_blob(raw) == raw.decode("utf-8", errors="ignore") == text   # negative: unchanged
    assert svc.decode_repo_blob(PNG) == PNG and isinstance(svc.decode_repo_blob(PNG), bytes)
    assert svc.decode_repo_blob(FONT) == FONT


class _ArchiveReader:
    def __init__(self, members=None, error=None):
        self.members, self.error, self.calls = members or {}, error, []

    def export_archive_with_sha(self, repo, branch="main"):
        import io
        import tarfile
        self.calls.append((repo, branch))
        if self.error:
            raise self.error
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for path, data in self.members.items():
                info = tarfile.TarInfo(name=path)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return "a" * 40, buf.getvalue()


def test_rt14_21_serverless_git_binaries_come_from_the_same_branch_archive():
    svc = _service_mod()
    tree = {"main.py": "print('hi')\n", "static/app.css": "body{}\n",
            "data.txt": "caf�\n"}                              # the git server's lossy decode of b"caf\xe9\n"
    reader = _ArchiveReader({"main.py": b"print('hi')\n", "static/app.css": b"body{}\n", "data.txt": b"caf\xe9\n",
                             "static/logo.png": PNG, "static/font.woff2": FONT})
    out = svc.add_serverless_git_binaries(reader, "claims", "main", tree)
    assert out["static/logo.png"] == PNG and out["static/font.woff2"] == FONT
    assert out["data.txt"] == b"caf\xe9\n"                         # exact bytes replace the lossy text
    assert out["main.py"] == tree["main.py"] and out["static/app.css"] == tree["static/app.css"]   # negative
    assert reader.calls == [("claims", "main")]


@pytest.mark.parametrize("members,error", [
    ({"main.py": b"print('changed')\n"}, None),      # the branch moved between the two reads
    ({}, None),                                       # a tree file missing from the archive
    (None, RuntimeError("down")),                     # the archive cannot be read
])
def test_rt14_21_an_archive_that_disagrees_or_fails_is_typed(members, error):
    svc = _service_mod()
    with pytest.raises(svc.IncompleteRepoTreeError) as ei:
        svc.add_serverless_git_binaries(_ArchiveReader(members, error), "claims", "main", {"main.py": "print('hi')\n"})
    assert "RT14-21" in str(ei.value)


_REPO_READERS = ("_read_github_tree_rest", "_fetch_repo_files", "_fetch_repo_files_brokered",
                 "add_serverless_git_binaries")


def test_rt14_21_no_lossy_decode_in_the_repository_readers():
    """No `errors="ignore"|"replace"` decode and no response `.text` in the deploy's repository readers (AST)."""
    tree = _tree(TF_DIR / "service.py")
    fns = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name in _REPO_READERS]
    assert {f.name for f in fns} == set(_REPO_READERS)
    for fn in fns:
        for n in ast.walk(fn):
            if isinstance(n, ast.Call):
                assert not any(k.arg == "errors" for k in n.keywords), f"{fn.name}:{n.lineno}"
            if isinstance(n, ast.Attribute) and n.attr == "text" and isinstance(n.value, ast.Name) \
                    and n.value.id.endswith("_res"):
                raise AssertionError(f"{fn.name}:{n.lineno} reads a response as text")


def test_rt14_21_the_archive_reader_is_used_only_to_read():
    fn = next(n for n in ast.walk(_tree(TF_DIR / "service.py"))
              if isinstance(n, ast.FunctionDef) and n.name == "add_serverless_git_binaries")
    attrs = {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
             and n.value.id == "reader"}
    assert attrs == {"export_archive_with_sha"}


def test_rt14_21_prepare_workspace_writes_binary_files_byte_for_byte(tmp_path):
    svc_mod = _service_mod()
    svc = svc_mod.TerraformService(project_id="host", state_bucket="b", workspace_base_dir=str(tmp_path),
                                   firestore_client=_FakeDb())
    svc.db = None
    text = {"main.tf": 'terraform {}\n', "apps/web/main.py": "print('hi')\n"}
    ws = svc.prepare_workspace("app", "t-rt14-21", dict(text),
                               binary_files={"apps/web/static/logo.png": PNG, "apps/web/static/f.woff2": FONT,
                                             "apps/web/Dockerfile": b"\xff", "main.tf": b"\xff\xfe"})
    assert (Path(ws) / "apps/web/static/logo.png").read_bytes() == PNG
    assert (Path(ws) / "apps/web/static/f.woff2").read_bytes() == FONT
    assert not (Path(ws) / "apps/web/Dockerfile").exists()             # invariant 4, as for text files
    assert (Path(ws) / "main.tf").read_text() == text["main.tf"]       # the text manifest wins on the same path
    assert (Path(ws) / "apps/web/main.py").read_text() == text["apps/web/main.py"]   # negative: text unchanged


def test_rt14_21_binary_keys_follow_the_manifest_path_rules(tmp_path):
    svc_mod = _service_mod()
    svc = svc_mod.TerraformService(project_id="host", state_bucket="b", workspace_base_dir=str(tmp_path),
                                   firestore_client=_FakeDb())
    svc.db = None
    with pytest.raises(svc_mod.UnsafePathError):
        svc.prepare_workspace("app", "t-rt14-21b", {"main.tf": "terraform {}\n"},
                              binary_files=dict([("../x.png", PNG)]))   # not a dict literal (FD-4G corpus guard)


# ============================================================================================================ RT14-22
def _engine_zip(member="tofu", payload=b"#!/bin/sh\necho tofu\n"):
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(member, payload)
    return buf.getvalue()


def _engine_svc(tmp_path):
    svc_mod = _service_mod()
    svc = svc_mod.TerraformService(project_id="host", state_bucket="b", workspace_base_dir=str(tmp_path / "ws"),
                                   firestore_client=_FakeDb())
    return svc_mod, svc


def _pin(monkeypatch, svc_mod, digest):
    bc = svc_mod._binary_checksums_module()
    monkeypatch.setattr(bc, "expected_sha256", lambda engine, version, os_arch: digest
                        if (engine, version) == ("opentofu", "1.9.0") else None)


def test_rt14_22_engine_is_the_verified_download_never_path(tmp_path, monkeypatch):
    import hashlib
    from unittest.mock import patch
    svc_mod, svc = _engine_svc(tmp_path)
    blob = _engine_zip()
    _pin(monkeypatch, svc_mod, hashlib.sha256(blob).hexdigest())
    fetched = []

    def _fetch(url, fobj, max_bytes, timeout=None):
        assert timeout == svc_mod.ENGINE_FETCH_TIMEOUT_S and max_bytes == svc_mod.ENGINE_ZIP_MAX_BYTES  # RT F2
        fetched.append(url)
        fobj.write(blob)

    bc = svc_mod._binary_checksums_module()
    with patch.object(svc_mod.shutil, "which", return_value="/usr/local/bin/tofu"), \
            patch.object(bc, "fetch_to", side_effect=_fetch):
        path = svc._ensure_binary("OPENTOFU", "1.9.0")
        again = svc._ensure_binary("OPENTOFU", "1.9.0")           # verified this process: no second download
    assert path == again and path != "/usr/local/bin/tofu"
    assert Path(path).read_bytes() == b"#!/bin/sh\necho tofu\n" and os.access(path, os.X_OK)
    assert len(fetched) == 1 and fetched[0].endswith(f"/v1.9.0/tofu_1.9.0_{svc_mod.engine_os_arch()}.zip")
    assert not list((Path(svc.tooling_dir) / "bin").glob("*.zip"))     # the zip is removed

    # a binary changed after verification is not reused: it is downloaded and verified again
    Path(path).write_bytes(b"tampered")
    with patch.object(bc, "fetch_to", side_effect=_fetch):
        assert svc._ensure_binary("OPENTOFU", "1.9.0") == path
    assert len(fetched) == 2 and Path(path).read_bytes() == b"#!/bin/sh\necho tofu\n"


def test_rt14_22_a_zip_that_does_not_match_is_never_unpacked(tmp_path, monkeypatch):
    from unittest.mock import patch
    svc_mod, svc = _engine_svc(tmp_path)
    _pin(monkeypatch, svc_mod, "0" * 64)
    with patch.object(svc_mod._binary_checksums_module(), "fetch_to",
                      side_effect=lambda url, fobj, max_bytes, timeout=None: fobj.write(_engine_zip())):
        with pytest.raises(svc_mod.EngineUnverifiable) as ei:
            svc._ensure_binary("OPENTOFU", "1.9.0")
    assert ei.value.error_class == "ENGINE_UNVERIFIABLE" and ei.value.stage == "engine"
    assert not (Path(svc.tooling_dir) / "bin" / "tofu_1.9.0").exists()


@pytest.mark.parametrize("stall", [TimeoutError("read timed out"), ValueError("larger than 209715200 bytes")])
def test_rt14_22_rt_f2_a_stalled_or_oversize_download_is_typed_and_frees_the_engine_lock(tmp_path, monkeypatch, stall):
    """RT F2: the download runs under _engine_lock. A timeout (or the size cap) is ENGINE_UNVERIFIABLE, the zip is
    removed and the lock is free: the next call downloads again and succeeds."""
    import hashlib
    from unittest.mock import patch
    svc_mod, svc = _engine_svc(tmp_path)
    blob = _engine_zip()
    _pin(monkeypatch, svc_mod, hashlib.sha256(blob).hexdigest())
    bc = svc_mod._binary_checksums_module()
    with patch.object(bc, "fetch_to", side_effect=stall):
        with pytest.raises(svc_mod.EngineUnverifiable) as ei:
            svc._ensure_binary("OPENTOFU", "1.9.0")
    assert ei.value.error_class == "ENGINE_UNVERIFIABLE" and type(stall).__name__ in str(ei.value)
    assert not svc._engine_lock.locked() and not list((Path(svc.tooling_dir) / "bin").glob("*.zip"))
    with patch.object(bc, "fetch_to", side_effect=lambda url, fobj, max_bytes, timeout=None: fobj.write(blob)):
        assert Path(svc._ensure_binary("OPENTOFU", "1.9.0")).read_bytes() == b"#!/bin/sh\necho tofu\n"


def test_rt14_22_rt_f2_the_engine_download_is_bounded():
    """RT F2: _ensure_binary downloads only through the bounded fetch primitive (no urlretrieve / bare urlopen)."""
    fn = next(n for n in ast.walk(_tree(TF_DIR / "service.py"))
              if isinstance(n, ast.FunctionDef) and n.name == "_ensure_binary")
    attrs = {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute)}
    assert "fetch_to" in attrs and not attrs & {"urlretrieve", "urlopen"}


@pytest.mark.parametrize("engine,version", [("OPENTOFU", "1.10.0"), ("TERRAFORM", "1.5.7")])
def test_rt14_22_no_pinned_row_is_refused_before_any_download(tmp_path, monkeypatch, engine, version):
    from unittest.mock import patch
    svc_mod, svc = _engine_svc(tmp_path)
    _pin(monkeypatch, svc_mod, "0" * 64)    # only opentofu 1.9.0 is pinned here
    with patch.object(svc_mod._binary_checksums_module(), "fetch_to", side_effect=AssertionError("must not download")), \
            patch.object(svc_mod.shutil, "which", return_value="/usr/local/bin/x"):
        with pytest.raises(svc_mod.EngineUnverifiable) as ei:
            svc._ensure_binary(engine, version)
    assert "no owner-verified checksum" in str(ei.value)


def test_rt14_22_run_subprocess_returns_the_typed_refusal_and_runs_nothing(tmp_path, monkeypatch):
    from unittest.mock import patch
    svc_mod, svc = _engine_svc(tmp_path)
    monkeypatch.setattr(svc_mod.TerraformService, "_ensure_binary",
                        lambda self, *a, **k: (_ for _ in ()).throw(svc_mod.EngineUnverifiable("no row")))
    ws = tmp_path / "ws" / "t1" / "app"
    ws.mkdir(parents=True)
    with patch.object(svc_mod.subprocess, "Popen", side_effect=AssertionError("must not run")):
        res = svc._run_subprocess(["terraform", "plan"], cwd=str(ws), iac_engine="OPENTOFU")
    assert res["success"] is False and res["error_class"] == "ENGINE_UNVERIFIABLE" and res["stage"] == "engine"


def test_rt14_22_ensure_binary_never_looks_at_path_or_returns_the_bare_name():
    fn = next(n for n in ast.walk(_tree(TF_DIR / "service.py"))
              if isinstance(n, ast.FunctionDef) and n.name == "_ensure_binary")
    assert not [n for n in ast.walk(fn) if isinstance(n, ast.Attribute) and n.attr == "which"]
    returned = [ast.unparse(n.value) for n in ast.walk(fn) if isinstance(n, ast.Return) and n.value is not None]
    assert "bin_cmd" not in returned and set(returned) <= {"path", "cached_bin"}


def test_rt14_22_os_arch_equals_the_validate_service():
    import importlib.util
    import sys
    sys.path.insert(0, str(TF_DIR))
    try:
        spec = importlib.util.spec_from_file_location("rt14_validate_probe", TF_DIR / "validate_service.py")
        vs = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(vs)
    finally:
        sys.path.remove(str(TF_DIR))
    assert _service_mod().engine_os_arch() == vs.host_os_arch()
    assert _service_mod().ENGINE_UNVERIFIABLE == vs.ENGINE_UNVERIFIABLE
    # RT F2: /validate's engine download is bounded the same way (it also runs under a lock)
    assert (_service_mod().ENGINE_FETCH_TIMEOUT_S, _service_mod().ENGINE_ZIP_MAX_BYTES) == \
        (vs.ENGINE_FETCH_TIMEOUT_S, vs.ENGINE_ZIP_MAX_BYTES)
    fn = next(n for n in ast.walk(_tree(TF_DIR / "validate_service.py"))
              if isinstance(n, ast.FunctionDef) and n.name == "_download")
    attrs = {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute)}
    assert "fetch_to" in attrs and not attrs & {"urlretrieve", "urlopen"}


def test_rt14_04_negative_no_manifest_documents_is_nothing_to_do(tmp_path):
    mod = _k8s_mod()
    sess = _GoogleSession(_CLUSTER_OK)
    assert _apply(mod, str(tmp_path), _Http(), sess) is None            # no k8s/ dir
    assert _apply(mod, _ws(tmp_path, {"empty.yaml": "---\n"}), _Http(), sess) is None
    assert sess.calls == []
