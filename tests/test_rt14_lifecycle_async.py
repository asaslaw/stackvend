"""RT14 lifecycle-async group (owner 11-14): RT14-15, RT14-14, RT14-18, RT14-10, RT14-25, RT14-33.

Plan: docs/planning/rt14-lifecycle-async-plan.md. Report: docs/planning/full-scope-red-team-1114.md.
Hermetic: no network, no cloud clients; an in-memory Firestore stand-in with update-time preconditions.
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import ast
import filecmp
import itertools
import os
import sys
from types import SimpleNamespace

import pytest
from google.api_core import exceptions as gexc

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GW_DIR = os.path.join(REPO, "apps", "orchestrator-gateway")


# ============================================================================================ Firestore stand-in
class _Snap:
    def __init__(self, ref, data, update_time):
        self.reference = ref
        self.id = ref.id
        self._data = None if data is None else dict(data)
        self.exists = data is not None
        self.update_time = update_time if data is not None else None

    def to_dict(self):
        return None if self._data is None else dict(self._data)


class _Ref:
    def __init__(self, db, path):
        self.db = db
        self.path = path
        self.id = path.rsplit("/", 1)[-1]

    def collection(self, name):
        return _Col(self.db, f"{self.path}/{name}")

    def get(self, **_kw):
        self.db.reads.append(self.path)
        hook = self.db.on_get.get(self.path)
        if hook:
            hook(self.db)
        entry = self.db.docs.get(self.path)
        return _Snap(self, entry and entry[0], entry and entry[1])

    def _bump(self, data):
        self.db.clock += 1
        self.db.docs[self.path] = (data, self.db.clock)
        self.db.writes.append((self.path, dict(data)))

    def create(self, fields):
        if self.path in self.db.docs:
            raise gexc.AlreadyExists("exists")
        self._bump(dict(fields))

    def set(self, fields, merge=False):
        base = dict(self.db.docs[self.path][0]) if (merge and self.path in self.db.docs) else {}
        for k, v in fields.items():
            if merge and isinstance(v, dict) and isinstance(base.get(k), dict):
                base[k] = {**base[k], **v}
            else:
                base[k] = v
        self._bump(base)

    def update(self, fields, option=None):
        if self.path not in self.db.docs:
            raise gexc.NotFound("missing")
        if self.db.fail_updates:
            self.db.fail_updates -= 1
            raise gexc.FailedPrecondition("stale")
        if option is not None and option.last_update_time != self.db.docs[self.path][1]:
            raise gexc.FailedPrecondition("stale")
        base = dict(self.db.docs[self.path][0])
        for k, v in fields.items():
            if "." in k:
                head, tail = k.split(".", 1)
                base[head] = {**(base.get(head) or {}), tail: v}
            else:
                base[k] = v
        self._bump(base)


class _Col:
    def __init__(self, db, path):
        self.db = db
        self.path = path

    def document(self, doc_id=None):
        return _Ref(self.db, f"{self.path}/{doc_id}")

    def stream(self):
        prefix = self.path + "/"
        for path in sorted(self.db.docs):
            if path.startswith(prefix) and "/" not in path[len(prefix):]:
                yield _Ref(self.db, path).get()


class FakeDB:
    def __init__(self, docs=None):
        self.clock = 0
        self.docs = {}
        self.reads, self.writes = [], []
        self.on_get = {}
        self.fail_updates = 0
        for path, data in (docs or {}).items():
            self.clock += 1
            self.docs[path] = (dict(data), self.clock)

    def collection(self, name):
        return _Col(self, name)

    def write_option(self, last_update_time=None):
        return SimpleNamespace(last_update_time=last_update_time)

    def data(self, path):
        entry = self.docs.get(path)
        return entry and dict(entry[0])


# ============================================================================================ RT14-15 cooldown
COOLDOWN_COPIES = ["shared/cooldown_manager.py", "apps/control-center/shared/cooldown_manager.py",
                   "apps/orchestrator-gateway/shared/cooldown_manager.py",
                   "apps/project-vending/shared/cooldown_manager.py", "mcp-servers/terraform/shared/cooldown_manager.py"]


def test_rt14_15_cooldown_copies_are_byte_identical():
    first = os.path.join(REPO, COOLDOWN_COPIES[0])
    for other in COOLDOWN_COPIES[1:]:
        assert filecmp.cmp(first, os.path.join(REPO, other), shallow=False), other


@pytest.fixture()
def cooldown(monkeypatch):
    from google.cloud import firestore
    import shared.cooldown_manager as cm

    db = FakeDB()
    db.clock = 100   # documents seeded with update time 1 below; every write gets a later one
    monkeypatch.setattr(firestore, "Client", lambda *a, **k: db)
    monkeypatch.setattr(cm.time, "sleep", lambda s: None)
    return cm, db


def _call(cm, trace="tr-1"):
    return cm.wait_for_rate_limit_cooldown(trace_id=trace, product_id="app", stage="developer_code_synthesis",
                                           model_name="m", attempt=1, max_attempts=3, project_id="p")


@pytest.mark.parametrize("before", ["RUNNING", "ACTIVE"])
def test_rt14_15_negative_a_live_run_cools_down_and_gets_its_own_status_back(cooldown, before):
    """Do No Harm: a live run is paused, then its status before the cooldown comes back (ACTIVE stays ACTIVE)."""
    cm, db = cooldown
    db.docs["pipeline_executions/tr-1"] = ({"status": before, "stage": "x"}, 1)
    assert _call(cm) is True
    statuses = [w[1].get("status") for w in db.writes if w[0] == "pipeline_executions/tr-1"]
    assert statuses == ["PAUSED_RATE_LIMIT_COOLDOWN", before]
    final = db.data("pipeline_executions/tr-1")
    assert final["cooldown_state"]["is_paused"] is False and final["force_resume"] is False
    assert final["cooldown_state"]["status_before"] == before and final["stage"] == "x"


@pytest.mark.parametrize("ended", sorted({"ABORTED", "FAILED", "CANCELLED", "SUCCEEDED", "REJECTED"}))
def test_rt14_15_an_ended_run_is_never_overwritten_and_the_call_raises(cooldown, ended):
    cm, db = cooldown
    db.docs["pipeline_executions/tr-1"] = ({"status": ended}, 1)
    with pytest.raises(cm.RunEndedDuringCooldown) as info:
        _call(cm)
    assert isinstance(info.value, RuntimeError) and info.value.reason == "RUN_ENDED"
    assert db.writes == [] and db.data("pipeline_executions/tr-1")["status"] == ended


@pytest.mark.parametrize("ended", ["ABORTED", "FAILED"])
def test_rt14_15_a_run_that_ends_during_the_cooldown_stops_it_and_keeps_its_status(cooldown, ended):
    cm, db = cooldown
    db.docs["pipeline_executions/tr-1"] = ({"status": "RUNNING"}, 1)
    calls = itertools.count()

    def end_on_third_read(fdb):
        if next(calls) == 2:
            data, _ = fdb.docs["pipeline_executions/tr-1"]
            fdb.clock += 1
            fdb.docs["pipeline_executions/tr-1"] = (dict(data, status=ended), fdb.clock)
    db.on_get["pipeline_executions/tr-1"] = end_on_third_read
    with pytest.raises(cm.RunEndedDuringCooldown):
        _call(cm)
    assert db.data("pipeline_executions/tr-1")["status"] == ended   # never RUNNING again


def test_rt14_15_an_abort_between_read_and_write_is_seen_by_the_precondition(cooldown, monkeypatch):
    """The abort lands after the cooldown read the record and before its write: the stale write is refused and the
    re-read sees ABORTED (the old unconditional merge overwrote it)."""
    cm, db = cooldown
    db.docs["pipeline_executions/tr-1"] = ({"status": "RUNNING"}, 1)
    real_update = _Ref.update
    raced = []

    def racing_update(self, fields, option=None):
        if not raced:
            raced.append(1)
            self.db.clock += 1
            self.db.docs[self.path] = ({"status": "ABORTED"}, self.db.clock)
        return real_update(self, fields, option)
    monkeypatch.setattr(_Ref, "update", racing_update)
    with pytest.raises(cm.RunEndedDuringCooldown):
        _call(cm)
    assert db.data("pipeline_executions/tr-1") == {"status": "ABORTED"}


def test_rt14_15_a_status_written_meanwhile_is_kept(cooldown):
    """The Resume button (or a workflow notify) wrote a status during the cooldown: it is not replaced."""
    cm, db = cooldown
    db.docs["pipeline_executions/tr-1"] = ({"status": "ACTIVE"}, 1)
    calls = itertools.count()

    def resume(fdb):
        if next(calls) == 2:
            data, _ = fdb.docs["pipeline_executions/tr-1"]
            fdb.clock += 1
            fdb.docs["pipeline_executions/tr-1"] = (dict(data, status="RUNNING", force_resume=True), fdb.clock)
    db.on_get["pipeline_executions/tr-1"] = resume
    assert _call(cm) is True
    final = db.data("pipeline_executions/tr-1")
    assert final["status"] == "RUNNING" and final["force_resume"] is False
    assert final["cooldown_state"]["resumed_early"] is True


def test_rt14_15_a_lost_compare_and_set_rereads(cooldown):
    cm, db = cooldown
    db.docs["pipeline_executions/tr-1"] = ({"status": "RUNNING"}, 1)
    db.fail_updates = 1
    assert _call(cm) is True
    assert db.data("pipeline_executions/tr-1")["status"] == "RUNNING"


def test_rt14_15_the_gateway_treats_the_cooldown_stop_as_a_typed_abandon(monkeypatch):
    if GW_DIR not in sys.path:
        sys.path.insert(0, GW_DIR)
    import stage_deadline as sdm
    from gate_errors import StageAbandonedError
    import shared.cooldown_manager as cm

    assert cm.RunEndedDuringCooldown in sdm.STOP_ERRORS
    sd = sdm.StageDeadline(sdm.budget_for("developer", sdm.StageMode.SYNC), trace_id="tr-1", product_id="app")

    def body():
        raise cm.RunEndedDuringCooldown("tr-1", "ABORTED", "developer_code_synthesis")
    with pytest.raises(StageAbandonedError) as info:
        sdm.run_with_deadline(sd, body)
    assert info.value.reason == "RUN_ENDED" and info.value.stage == "developer"
    assert info.value.details == {"run_status": "ABORTED"}


# ============================================================================================ RT14-14 intake lifecycle
from fd4f_support import gw  # noqa: E402,F401  (gw is a fixture)
from test_build_admission_queue import (STATE, SETTINGS, Store, _event, _gw_db, _gw_env,  # noqa: E402
                                        _post)


def _promote_second_run(gw, db):
    """t-shop runs; t-blog waited and is promoted into a second slot (its record QUEUED, its event in flight)."""
    assert _post(gw, _event("t-shop", "shop")).json()["status"] == "DISPATCHED"
    assert _post(gw, _event("t-blog", "blog")).json()["status"] == "QUEUED"
    db.docs[SETTINGS]["orchestration"]["max_concurrent_builds"] = 2
    promoted = gw._build_admission.promote(db)
    assert [e["trace_id"] for e in promoted] == ["t-blog"]
    assert db.docs["pipeline_executions/t-blog"]["status"] == "QUEUED"


def test_rt14_14_a_late_event_into_a_decommissioned_workload_is_refused_and_frees_its_slot(gw, monkeypatch):
    db = _gw_db(1)
    created = _gw_env(gw, monkeypatch, db)
    _promote_second_run(gw, db)
    db.docs["workloads/blog"]["status"] = "DECOMMISSIONED"   # decommissioned while the event was in flight
    r = _post(gw, _event("t-blog", "blog"))
    assert r.status_code == 200 and r.json()["status"] == "SUPPRESSED:BUILD_QUEUE_WORKLOAD_GONE", r.text
    assert len(created) == 1                                  # no workflow, so no vend of a new project
    assert sorted(db.docs[STATE]["holders"]) == ["t-shop"]
    blog = db.docs["pipeline_executions/t-blog"]
    assert blog["status"] == "FAILED" and blog["error_class"] == "BUILD_QUEUE_WORKLOAD_GONE"
    assert db.docs["workloads/blog"]["status"] == "DECOMMISSIONED"


def test_rt14_14_a_late_event_of_an_aborted_run_is_refused_and_frees_its_slot(gw, monkeypatch):
    db = _gw_db(1)
    created = _gw_env(gw, monkeypatch, db)
    _promote_second_run(gw, db)
    db.docs["pipeline_executions/t-blog"].update(status="ABORTED", current_stage="ABORTED")
    r = _post(gw, _event("t-blog", "blog"))
    assert r.json()["status"] == "SUPPRESSED:RUN_ALREADY_ENDED", r.text
    assert len(created) == 1 and sorted(db.docs[STATE]["holders"]) == ["t-shop"]
    assert db.docs["pipeline_executions/t-blog"]["status"] == "ABORTED"   # never revived


def test_rt14_14_negative_a_promoted_run_of_a_live_workload_starts_as_before(gw, monkeypatch):
    db = _gw_db(1)
    created = _gw_env(gw, monkeypatch, db)
    _promote_second_run(gw, db)
    r = _post(gw, _event("t-blog", "blog"))
    assert r.json()["status"] == "DISPATCHED" and [c["trace_id"] for c in created] == ["t-shop", "t-blog"]
    assert db.docs["pipeline_executions/t-blog"]["status"] == "ACTIVE"


def test_rt14_14_a_fast_path_event_into_a_decommissioned_workload_fails_its_unbound_record(gw, monkeypatch):
    db = _gw_db(1)
    created = _gw_env(gw, monkeypatch, db)
    db.docs["workloads/shop"]["status"] = "DECOMMISSIONED"
    db.docs["pipeline_executions/fp-1"] = {"trace_id": "fp-1", "product_id": "shop", "status": "ACTIVE",
                                           "execution_mode": "DEPLOY_ONLY"}
    r = _post(gw, _event("fp-1", "shop", execution_mode="DEPLOY_ONLY"))
    assert r.json()["status"] == "SUPPRESSED:BUILD_QUEUE_WORKLOAD_GONE" and created == []
    assert db.docs["pipeline_executions/fp-1"]["error_class"] == "BUILD_QUEUE_WORKLOAD_GONE"
    assert db.docs["pipeline_executions/fp-1"]["status"] == "FAILED"


def test_rt14_14_a_lifecycle_read_failure_is_503_never_dispatched_unchecked(gw, monkeypatch):
    db = _gw_db(1)
    created = _gw_env(gw, monkeypatch, db)
    real_collection = db.collection

    def collection(name):
        if name == "workloads":
            raise RuntimeError("firestore down")
        return real_collection(name)
    db.collection = collection
    r = _post(gw, _event("t-shop", "shop"))
    assert r.status_code == 503 and created == []


def _ba_store(holders, runs):
    import shared.build_admission as ba
    store = Store({STATE: {"holders": holders, "queue": [], "waiting": {}},
                   **{f"pipeline_executions/{t}": r for t, r in runs.items()}})
    return ba, store


def test_rt14_14_decommission_cascade_takes_unbound_holders_of_the_workload_only():
    ba, store = _ba_store(
        {"t-unbound": {"product_id": "shop"}, "t-bound": {"product_id": "shop"}, "t-other": {"product_id": "blog"}},
        {"t-unbound": {"status": "QUEUED"}, "t-bound": {"status": "ACTIVE", "workflow_execution_id": "e-1"},
         "t-other": {"status": "QUEUED"}})
    cancelled = ba.cancel_product(store, "shop", by="admin: decommission")
    assert cancelled == ["t-unbound"]
    assert sorted(store.docs[STATE]["holders"]) == ["t-bound", "t-other"]
    assert store.docs["pipeline_executions/t-unbound"]["status"] == "ABORTED"
    assert store.docs["pipeline_executions/t-unbound"]["error_class"] == "BUILD_QUEUE_CANCELLED"
    assert store.docs["pipeline_executions/t-bound"]["status"] == "ACTIVE"   # the run cancel ends a bound run


def test_rt14_14_negative_cascade_with_nothing_of_the_workload_writes_nothing():
    ba, store = _ba_store({"t-other": {"product_id": "blog"}}, {"t-other": {"status": "QUEUED"}})
    before = {k: dict(v) for k, v in store.docs.items()}
    assert ba.cancel_product(store, "shop", by="admin") == []
    assert store.docs == before


# ============================================================================================ RT14-18 deploy secrets
from test_vending_redeploy_outcome import _VENDING  # noqa: E402


class _GhError(Exception):
    def __init__(self, status):
        super().__init__(f"HTTP {status}")
        self.status = status


def _secrets_engine(monkeypatch, outcomes, jit="inst-tok", pat=""):
    """`outcomes[token]` = None (write ok) or an HTTP status every create_secret raises with that token."""
    written = []

    class _Repo:
        def __init__(self, token):
            self.token = token

        def create_secret(self, name, value):
            if outcomes.get(self.token) is not None:
                raise _GhError(outcomes[self.token])
            written.append((self.token, name))

    class _Github:
        def __init__(self, token):
            self.token = token

        def get_repo(self, name):
            assert name == "example-org/app"
            return _Repo(self.token)

    monkeypatch.setattr(_VENDING, "Github", _Github)
    monkeypatch.setenv("GITHUB_PAT", pat)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    eng = SimpleNamespace(github_owner="example-org", fetch_github_app_credentials=lambda: {},
                          generate_github_jit_token=lambda: jit)
    return eng, written


SECRETS = {"GCP_PROJECT_ID": "p-1", "WIF_PROVIDER": "prov", "WIF_SERVICE_ACCOUNT": "sa"}
_update = _VENDING.ProjectRepoVendingEngine._update_github_secrets


def test_rt14_18_negative_every_secret_written_is_true(monkeypatch):
    eng, written = _secrets_engine(monkeypatch, {"inst-tok": None})
    assert _update(eng, "example-org/app", SECRETS) is True
    assert written == [("inst-tok", n) for n in SECRETS]


def test_rt14_18_a_refused_token_falls_through_to_the_next(monkeypatch):
    eng, written = _secrets_engine(monkeypatch, {"inst-tok": 403, "pat-tok": None}, pat="pat-tok")
    assert _update(eng, "example-org/app", SECRETS) is True
    assert written == [("pat-tok", n) for n in SECRETS]


def test_rt14_18_every_write_refused_is_a_typed_failure_never_true(monkeypatch):
    eng, _ = _secrets_engine(monkeypatch, {"inst-tok": 403})
    with pytest.raises(_VENDING.GitHubSecretsNotWritten) as info:
        _update(eng, "example-org/app", SECRETS)
    err = info.value
    assert err.error_class == "VENDING.GHA_SECRETS_NOT_WRITTEN" and isinstance(err, _VENDING.VendingFailure)
    statuses = {f["http_status"] for a in err.attempts for f in a["failures"]}
    assert statuses == {403} and err.attempts[0]["token"] == "installation"
    assert "inst-tok" not in str(err.body()) and "p-1" not in str(err.body())   # never a token or a value


def test_rt14_18_no_token_is_a_typed_failure(monkeypatch):
    eng, _ = _secrets_engine(monkeypatch, {}, jit="")
    with pytest.raises(_VENDING.GitHubSecretsNotWritten):
        _update(eng, "example-org/app", SECRETS)


def test_rt14_18_write_deploy_secrets_reports_the_typed_reason(monkeypatch):
    eng, _ = _secrets_engine(monkeypatch, {"inst-tok": 403})
    eng._gha_deploy_secrets_skip = lambda pid, rec: False
    eng._repository_shared_with_other_workload = lambda pid, repo: False
    eng._update_github_secrets = lambda repo, secrets: _update(eng, repo, secrets)
    failures = []
    ok = _VENDING.ProjectRepoVendingEngine._write_deploy_secrets(
        eng, "app", {"github_repo": "example-org/app", "default_branch": "main"}, "p-1", failures=failures)
    assert ok is False and failures and failures[0]["error_class"] == "VENDING.GHA_SECRETS_NOT_WRITTEN"


# RT item 2: the typed reason reaches the operator (vending 200 body -> CC answer) and never goes stale.
from test_vending_redeploy_outcome import (  # noqa: E402
    _cc, _cc_redeploy, _fake_httpx, _resp, _run, _workload_writes, vending, vending_route)  # noqa: F401

_GHA_ERR = {"error_class": "VENDING.GHA_SECRETS_NOT_WRITTEN", "stage": "vending",
            "attempts": [{"token": "installation", "failures": [{"secret": "WIF_PROVIDER", "http_status": 403}]}]}


def _secrets_outcome(v, monkeypatch, ok):
    def _write(pid, data, project, *, failures=None):
        if not ok and failures is not None:
            failures.append(dict(_GHA_ERR))
        return ok
    monkeypatch.setattr(v.engine, "_write_deploy_secrets", _write)


def test_rt14_18_a_refused_secrets_write_is_on_the_redeploy_answer_and_the_record(vending, monkeypatch):
    _secrets_outcome(vending, monkeypatch, ok=False)
    res = _run(vending, monkeypatch, _fake_httpx(post=_resp(200, {"service_url": "https://x.run.app"})))
    assert res["status"] == "ACTIVE" and res["wif_secrets_error"]["error_class"] == "VENDING.GHA_SECRETS_NOT_WRITTEN"
    assert _workload_writes(vending.db)[-1]["wif_secrets_error"] == _GHA_ERR


def test_rt14_18_a_later_successful_write_clears_the_stored_error(vending, monkeypatch):
    _secrets_outcome(vending, monkeypatch, ok=True)
    res = _run(vending, monkeypatch, _fake_httpx(post=_resp(200, {"service_url": "https://x.run.app"})))
    assert res["status"] == "ACTIVE" and "wif_secrets_error" not in res
    assert _workload_writes(vending.db)[-1]["wif_secrets_error"] is vending.mod.firestore.DELETE_FIELD


def test_rt14_18_negative_no_secrets_written_and_no_error_leaves_the_field_alone(vending, monkeypatch):
    monkeypatch.setattr(vending.engine, "_write_deploy_secrets", lambda *a, **k: False)   # e.g. switch off
    _run(vending, monkeypatch, _fake_httpx(post=_resp(200, {"service_url": "https://x.run.app"})))
    assert "wif_secrets_error" not in _workload_writes(vending.db)[-1]


def test_rt14_18_the_vending_route_keeps_the_secrets_error_on_a_failed_redeploy(vending_route):
    vending_route.vending_engine.redeploy_workload = lambda **k: {
        "status": "FAILED", "error_class": "REDEPLOY_DEPLOY_FAILED", "error": "x", "product_id": "dormant-api",
        "wif_secrets_error": _GHA_ERR}
    with pytest.raises(vending_route.HTTPException) as info:
        vending_route.redeploy_project("dormant-api", None)
    assert info.value.detail["wif_secrets_error"] == _GHA_ERR


def test_rt14_18_the_control_center_redeploy_answer_carries_the_secrets_error(monkeypatch):
    wl, _db, _ = _cc(monkeypatch, _resp(200, {"status": "ACTIVE", "project_id": "dormant-api-abc123",
                                              "wif_secrets_error": _GHA_ERR}))
    out = _cc_redeploy(wl)
    assert out.status == "ACTIVE" and out.wif_secrets_error == _GHA_ERR
    assert "VENDING.GHA_SECRETS_NOT_WRITTEN" in out.message


def test_rt14_18_negative_control_center_redeploy_without_an_error_is_unchanged(monkeypatch):
    wl, _db, _ = _cc(monkeypatch, _resp(200, {"status": "ACTIVE", "project_id": "dormant-api-abc123"}))
    out = _cc_redeploy(wl)
    assert out.wif_secrets_error is None and "NOT written" not in out.message


# ============================================================================================ RT14-10 git credential
import base64  # noqa: E402
import subprocess  # noqa: E402

PROVIDER_COPIES = ["shared/providers/github_provider.py", "apps/control-center/shared/providers/github_provider.py",
                   "apps/orchestrator-gateway/shared/providers/github_provider.py",
                   "apps/project-vending/shared/providers/github_provider.py",
                   "apps/qa-runner/shared/providers/github_provider.py",
                   "mcp-servers/github/shared/providers/github_provider.py",
                   "mcp-servers/terraform/shared/providers/github_provider.py"]
TOKEN = "ghs_rt1410SECRETtoken"
TOKEN_B64 = base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode()


def _git_argv_lists(tree):
    """Every list literal that is a git command line: first element the constant "git"."""
    for node in ast.walk(tree):
        if isinstance(node, ast.List) and node.elts and isinstance(node.elts[0], ast.Constant) \
                and node.elts[0].value == "git":
            yield node


def _git_config_flag_with_computed_value(argv: ast.List) -> bool:
    elts = argv.elts
    return any(isinstance(a, ast.Constant) and a.value == "-c" and i + 1 < len(elts)
               and not isinstance(elts[i + 1], ast.Constant) for i, a in enumerate(elts))


def _python_sources():
    for top in ("apps", "mcp-servers", "shared"):
        for dirpath, dirnames, filenames in os.walk(os.path.join(REPO, top)):
            dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".venv", "__pycache__")]
            for name in filenames:
                if name.endswith(".py"):
                    yield os.path.join(dirpath, name)


def test_rt14_10_guard_no_git_command_line_carries_a_computed_config_value():
    """RT14-10 guard (AST, every platform Python file): a `git -c <computed value>` command line can carry a
    credential into the process table and into TimeoutExpired / CalledProcessError text. Config goes through the
    environment (shared.providers.github_provider.git_auth_env)."""
    offenders = []
    for path in _python_sources():
        try:
            tree = ast.parse(open(path, encoding="utf-8").read())
        except SyntaxError:
            continue
        for argv in _git_argv_lists(tree):
            if _git_config_flag_with_computed_value(argv):
                offenders.append(f"{os.path.relpath(path, REPO)}:{argv.lineno}")
    assert offenders == []


def test_rt14_10_provider_copies_are_byte_identical():
    first = os.path.join(REPO, PROVIDER_COPIES[0])
    for other in PROVIDER_COPIES[1:]:
        assert filecmp.cmp(first, os.path.join(REPO, other), shallow=False), other


class _FakeGit:
    """subprocess.run stand-in for git: records (argv, env); `timeout_on` sub-commands raise TimeoutExpired."""

    def __init__(self, timeout_on=(), porcelain=" M app.py"):
        self.calls = []
        self.timeout_on = set(timeout_on)
        self.porcelain = porcelain

    def __call__(self, argv, cwd=None, env=None, timeout=None, **kw):
        self.calls.append((list(argv), dict(env or {})))
        sub = argv[1]
        if sub in self.timeout_on:
            raise subprocess.TimeoutExpired(argv, timeout)
        out = {"status": self.porcelain, "rev-parse": "abc1234def\n"}.get(sub, "")
        return subprocess.CompletedProcess(argv, 0, stdout=out, stderr="")


def _provider(monkeypatch, fake):
    import shared.providers.github_provider as gp
    monkeypatch.setattr(gp.subprocess, "run", fake)
    prov = gp.GitHubProvider.__new__(gp.GitHubProvider)
    prov.default_owner = "example-org"
    prov.get_token = lambda: TOKEN
    return gp, prov


def _commit(prov):
    return prov._commit_files_via_git_cli("example-org/app", "feature", {"app.py": "print(1)\n"}, "msg")


def test_rt14_10_negative_a_commit_runs_the_same_git_steps_and_returns_the_sha(monkeypatch):
    fake = _FakeGit()
    _, prov = _provider(monkeypatch, fake)
    assert _commit(prov) == "abc1234def"
    assert [argv[1] for argv, _ in fake.calls] == ["clone", "config", "config", "add", "status", "commit", "push",
                                                    "rev-parse"]
    for argv, env in fake.calls:
        assert TOKEN not in " ".join(argv) and TOKEN_B64 not in " ".join(argv) and "-c" not in argv
        talks_to_github = argv[1] in ("clone", "push", "pull")
        header = [env.get(f"GIT_CONFIG_VALUE_{i}") for i in range(int(env.get("GIT_CONFIG_COUNT") or 0))
                  if env.get(f"GIT_CONFIG_KEY_{i}") == "http.extraHeader"]
        assert (header == [f"Authorization: Basic {TOKEN_B64}"]) == talks_to_github
        assert env.get("GIT_TERMINAL_PROMPT") == "0"


def test_rt14_10_a_timed_out_git_call_never_puts_the_token_in_the_error_or_the_logs(monkeypatch, caplog):
    fake = _FakeGit(timeout_on={"clone"})
    gp, prov = _provider(monkeypatch, fake)
    with pytest.raises(gp.GitCommandFailed) as info:
        _commit(prov)
    err = info.value
    assert str(err) == "git clone failed: timed out after 45 s" and err.__cause__ is None
    assert err.__suppress_context__ is True
    for text in (str(err), repr(err), caplog.text):
        assert TOKEN not in text and TOKEN_B64 not in text


def test_rt14_10_a_failed_local_git_call_is_typed_with_stderr_redacted(monkeypatch):
    import shared.providers.github_provider as gp

    def run(argv, **kw):
        return subprocess.CompletedProcess(argv, 128, stdout="", stderr=f"fatal: bad {TOKEN} and {TOKEN_B64}")
    monkeypatch.setattr(gp.subprocess, "run", run)
    with pytest.raises(gp.GitCommandFailed) as info:
        gp.run_git(["push"], env={}, timeout=5, check=True, secrets=gp.git_secret_values(TOKEN))
    assert info.value.returncode == 128 and TOKEN not in str(info.value) and TOKEN_B64 not in str(info.value)


def test_rt14_10_auth_env_appends_to_existing_git_config_entries():
    import shared.providers.github_provider as gp
    env = gp.git_auth_env(TOKEN, {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "core.x", "GIT_CONFIG_VALUE_0": "y"})
    assert env["GIT_CONFIG_COUNT"] == "2" and env["GIT_CONFIG_KEY_0"] == "core.x"
    assert env["GIT_CONFIG_KEY_1"] == "http.extraHeader" and TOKEN_B64 in env["GIT_CONFIG_VALUE_1"]


# ============================================================================================ RT14-25 lost callbacks
CB_URL = ("https://workflowexecutions.googleapis.com/v1/projects/123/locations/r/workflows/w/executions/e/"
          "callbacks/c-1")
UNDELIVERED = "pipeline_executions/tr-1/undelivered_callbacks"


def _cb():
    import shared.callbacks as cb
    return cb


def _scope_run(monkeypatch, db, *, deliver_ok, status="SUCCESS"):
    cb = _cb()
    sent = []

    def send(callback_url, payload, timeout=15, max_attempts=5):
        sent.append((callback_url, dict(payload)))
        if not deliver_ok:
            raise RuntimeError("HTTP 503 from the callback endpoint")
    monkeypatch.setattr(cb.CallbackDeliveryClient, "send_callback", staticmethod(send))
    with cb.guaranteed_callback_scope(CB_URL, "tr-1", "terraform", product_id="app", firestore_db=db) as outcome:
        outcome["status"] = status
        outcome["outputs"] = {"service_url": "https://svc.example"}
    return sent


def _undelivered(db):
    return {p.rsplit("/", 1)[-1]: d for p, (d, _) in db.docs.items() if p.startswith(UNDELIVERED + "/")}


def test_rt14_25_an_undelivered_success_is_kept_with_its_callback_url(monkeypatch):
    db = FakeDB()
    _scope_run(monkeypatch, db, deliver_ok=False)
    kept = _undelivered(db)
    assert len(kept) == 1
    (doc_id, rec), = kept.items()
    assert doc_id == _cb().undelivered_callback_id("terraform", CB_URL)
    assert rec["state"] == "PENDING" and rec["callback_url"] == CB_URL and rec["outcome_status"] == "SUCCESS"
    import json
    assert json.loads(rec["payload_json"])["outputs"] == {"service_url": "https://svc.example"}
    run = db.data("pipeline_executions/tr-1")
    assert run["stages"]["terraform"]["state"] == "CALLBACK_FAILED" and "status" not in run   # run left ACTIVE


def test_rt14_25_rt14_09_a_kept_outcome_has_its_sensitive_outputs_masked(monkeypatch):
    """RT14-09 on the stored copy: every output the engine marks sensitive is masked, at any depth; the rest is kept
    exactly (Do No Harm). The placeholder is plan_redaction's, so the kept copy reads like the source-masked one."""
    import importlib.util
    import json
    cb = _cb()
    secret = "s3cr3t-db-pass"
    tofu = {"db_password": {"sensitive": True, "type": "string", "value": secret},
            "service_url": {"sensitive": False, "type": "string", "value": "https://svc.example"}}
    def down(callback_url, payload, **kwargs):
        raise RuntimeError("HTTP 503 from the callback endpoint")
    monkeypatch.setattr(cb.CallbackDeliveryClient, "send_callback", staticmethod(down))
    db = FakeDB()
    with cb.guaranteed_callback_scope(CB_URL, "tr-1", "terraform", product_id="app", firestore_db=db) as outcome:
        outcome.update(status="SUCCESS", outputs=dict(tofu), result={"outputs": dict(tofu)}, note="sensitive")
    (rec,) = _undelivered(db).values()
    assert secret not in rec["payload_json"]
    stored = json.loads(rec["payload_json"])
    for outs in (stored["outputs"], stored["result"]["outputs"]):
        assert outs["db_password"] == {"sensitive": True, "type": "string", "value": cb.SENSITIVE_OUTPUT_PLACEHOLDER}
        assert outs["service_url"] == tofu["service_url"]
    assert stored["note"] == "sensitive"
    spec = importlib.util.spec_from_file_location(
        "plan_redaction_rt14_25", os.path.join(REPO, "mcp-servers", "terraform", "plan_redaction.py"))
    pr = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pr)
    assert cb.SENSITIVE_OUTPUT_PLACEHOLDER == pr.SENSITIVE_PLACEHOLDER


def test_rt14_25_negative_masking_leaves_unmarked_values_and_the_input_unchanged():
    import json
    cb = _cb()
    value = {"outputs": {"u": {"sensitive": False, "value": "x"}, "n": {"sensitive": True, "value": None}},
             "list": [1, {"sensitive": "true", "value": "kept"}]}
    snapshot = json.loads(json.dumps(value))
    assert cb.mask_sensitive_output_entries(value) == snapshot   # only the engine's boolean flag masks
    assert value == snapshot


def test_rt14_25_negative_a_delivered_outcome_keeps_nothing(monkeypatch):
    db = FakeDB()
    _scope_run(monkeypatch, db, deliver_ok=True)
    assert _undelivered(db) == {}
    assert db.data("pipeline_executions/tr-1")["stages"]["terraform"]["state"] == "CALLBACK_DELIVERED"


def _kept(monkeypatch, db, status="SUCCESS"):
    _scope_run(monkeypatch, db, deliver_ok=False, status=status)
    return next(iter(_undelivered(db)))


def test_rt14_25_redelivery_sends_the_exact_outcome_once_and_marks_the_stage(monkeypatch):
    db = FakeDB()
    doc_id = _kept(monkeypatch, db)
    original = _undelivered(db)[doc_id]
    sent = []
    out = _cb().redeliver_undelivered_callbacks(db, "tr-1", send=lambda url, payload: sent.append((url, payload)))
    import json
    assert out == [{"id": doc_id, "stage": "terraform", "outcome": "DELIVERED"}]
    assert sent == [(CB_URL, json.loads(original["payload_json"]))]
    assert _undelivered(db)[doc_id]["state"] == "DELIVERED"
    assert db.data("pipeline_executions/tr-1")["stages"]["terraform"]["state"] == "CALLBACK_REDELIVERED"
    # a second reconcile sends nothing
    assert _cb().redeliver_undelivered_callbacks(db, "tr-1", send=lambda *a: sent.append(a)) == []
    assert len(sent) == 1


def test_rt14_25_a_failing_redelivery_is_retried_then_ends_typed(monkeypatch):
    db = FakeDB()
    doc_id = _kept(monkeypatch, db)

    def down(url, payload):
        raise RuntimeError("HTTP 503")
    cb = _cb()
    for attempt in range(1, cb.REDELIVERY_MAX_ATTEMPTS):
        assert cb.redeliver_undelivered_callbacks(db, "tr-1", send=down)[0]["outcome"] == "PENDING"
        assert _undelivered(db)[doc_id]["attempts"] == attempt
    assert cb.redeliver_undelivered_callbacks(db, "tr-1", send=down)[0]["outcome"] == "EXHAUSTED"
    rec = _undelivered(db)[doc_id]
    assert rec["state"] == "EXHAUSTED" and rec["error_class"] == "CALLBACK_REDELIVERY_EXHAUSTED"
    assert db.data("pipeline_executions/tr-1")["callback_redelivery_error"]["error_class"] == \
        "CALLBACK_REDELIVERY_EXHAUSTED"
    assert cb.redeliver_undelivered_callbacks(db, "tr-1", send=down) == []   # final: never sent again


def test_rt14_25_a_rejected_url_is_final_and_never_contacted(monkeypatch):
    db = FakeDB()
    doc_id = _kept(monkeypatch, db)
    cb = _cb()

    def reject(url, payload):
        raise cb.CallbackURLRejected("targets a project other than this platform project")
    assert cb.redeliver_undelivered_callbacks(db, "tr-1", send=reject)[0]["outcome"] == "REJECTED"
    assert _undelivered(db)[doc_id]["error_class"] == "CALLBACK_URL_REJECTED"


def test_rt14_25_a_claim_lost_to_another_reconciler_sends_nothing(monkeypatch):
    db = FakeDB()
    _kept(monkeypatch, db)
    db.fail_updates = 1
    sent = []
    assert _cb().redeliver_undelivered_callbacks(db, "tr-1", send=lambda *a: sent.append(a)) == []
    assert sent == []


def test_rt14_25_a_stale_sending_claim_is_taken_again(monkeypatch):
    from datetime import datetime, timedelta, timezone
    db = FakeDB()
    doc_id = _kept(monkeypatch, db)
    path = f"{UNDELIVERED}/{doc_id}"
    data, ts = db.docs[path]
    fresh = datetime.now(timezone.utc).isoformat()
    db.docs[path] = (dict(data, state="SENDING", last_attempt_at=fresh, attempts=1), ts)
    sent = []
    assert _cb().redeliver_undelivered_callbacks(db, "tr-1", send=lambda *a: sent.append(a)) == []
    stale = (datetime.now(timezone.utc) - timedelta(seconds=600)).isoformat()
    db.docs[path] = (dict(data, state="SENDING", last_attempt_at=stale, attempts=1), ts)
    assert _cb().redeliver_undelivered_callbacks(db, "tr-1", send=lambda *a: sent.append(a))[0]["outcome"] == \
        "DELIVERED"
    assert len(sent) == 1


def test_rt14_25_callbacks_copies_are_byte_identical():
    copies = ["shared/callbacks.py", "apps/control-center/shared/callbacks.py",
              "apps/orchestrator-gateway/shared/callbacks.py", "apps/project-vending/shared/callbacks.py",
              "apps/qa-runner/shared/callbacks.py", "mcp-servers/terraform/shared/callbacks.py"]
    for other in copies[1:]:
        assert filecmp.cmp(os.path.join(REPO, copies[0]), os.path.join(REPO, other), shallow=False), other


def test_rt14_25_gateway_admission_reconcile_redelivers_for_a_waiting_holder(gw, monkeypatch):
    db = _gw_db(1)
    created = _gw_env(gw, monkeypatch, db)
    assert _post(gw, _event("t-shop", "shop")).json()["status"] == "DISPATCHED"
    db.docs["pipeline_executions/t-shop"]["stages"]["terraform"] = {"status": "SUCCESS", "state": "CALLBACK_FAILED"}
    calls = []
    senders = []
    monkeypatch.setattr(gw, "redeliver_undelivered_callbacks",
                        lambda fs, trace_id, send=None: calls.append(trace_id) or senders.append(send) or [])
    assert _post(gw, _event("t-blog", "blog")).json()["status"] == "QUEUED"   # the holder's workflow is ACTIVE
    assert calls == ["t-shop"] and len(created) == 1
    assert senders == [gw._admission_redelivery_send]   # RT item 3: the short sender, never the default
    assert db.docs["pipeline_executions/t-shop"]["status"] == "ACTIVE"


def test_rt14_25_admission_redelivery_makes_one_short_attempt(gw, monkeypatch):
    sent = []
    monkeypatch.setattr(gw.CallbackDeliveryClient, "send_callback", staticmethod(lambda **k: sent.append(k) or {}))
    gw._admission_redelivery_send("https://workflowexecutions.googleapis.com/cb", {"status": "SUCCESS"})
    assert sent == [{"callback_url": "https://workflowexecutions.googleapis.com/cb", "payload": {"status": "SUCCESS"},
                     "timeout": 5, "max_attempts": 1}]


def test_rt14_25_negative_gateway_reconcile_without_an_undelivered_stage_sends_nothing(gw, monkeypatch):
    db = _gw_db(1)
    _gw_env(gw, monkeypatch, db)
    _post(gw, _event("t-shop", "shop"))
    calls = []
    monkeypatch.setattr(gw, "redeliver_undelivered_callbacks", lambda fs, trace_id: calls.append(trace_id) or [])
    assert _post(gw, _event("t-blog", "blog")).json()["status"] == "QUEUED"
    assert calls == []


# ============================================================================================ RT14-33 Assured Workloads
from test_compliance_bundle import server  # noqa: E402,F401  (fixture)


class _AwApis:
    """Google APIs stand-in: Resource Manager v3 folders and a paged Assured Workloads list."""

    def __init__(self, parents=None, pages=None, aw_status=200):
        self.parents = parents or {}
        self.pages = pages or [[]]
        self.aw_status = aw_status
        self.calls = []

    def get(self, url, params=None, timeout=None, **kw):
        self.calls.append((url, dict(params or {}), timeout))
        if url.startswith("https://cloudresourcemanager.googleapis.com/v3/"):
            name = url.rsplit("/v3/", 1)[1]
            if name not in self.parents:
                return SimpleNamespace(status_code=403, json=lambda: {})
            return SimpleNamespace(status_code=200, json=lambda: {"name": name, "parent": self.parents[name]})
        if self.aw_status != 200:
            return SimpleNamespace(status_code=self.aw_status, json=lambda: {})
        index = int((params or {}).get("pageToken") or 0)
        body = {"workloads": self.pages[index]}
        if index + 1 < len(self.pages):
            body["nextPageToken"] = str(index + 1)
        return SimpleNamespace(status_code=200, json=lambda: body)


def _aw(folder_id, regime="FEDRAMP_HIGH"):
    return {"displayName": "aw", "complianceRegime": regime,
            "resourceSettings": [{"resourceId": folder_id, "resourceType": "CONSUMER_FOLDER"}]}


def test_rt14_33_the_org_comes_from_the_folder_ancestry_and_every_location_and_page_is_read(server, monkeypatch):
    monkeypatch.delenv("ORGANIZATION_ID", raising=False)
    svc = server.service.ComplianceService(project_id="")
    svc._session = _AwApis(parents={"folders/555": "folders/77", "folders/77": "organizations/42"},
                           pages=[[_aw("999")], [_aw("555", "IL4")]])
    out = svc.inspect_parent_folder("folders/555")
    assert out["is_assured_workload"] is True and out["compliance_regime"] == "IL4"
    assert out["assured_workloads_check"] == {"status": "CHECKED"}
    aw_urls = [u for u, _, _ in svc._session.calls if "assuredworkloads" in u]
    assert aw_urls == ["https://assuredworkloads.googleapis.com/v1/organizations/42/locations/-/workloads"] * 2
    assert not any("us-central1" in u or "organizations/0" in u for u, _, _ in svc._session.calls)
    # the stricter-profile rule now sees the folder: an unmapped regime is refused (CP-10)
    with pytest.raises(server.service.ProfileRefused):
        svc.resolve_profile(None, out)


@pytest.mark.parametrize("org_env", ["42", "organizations/42"])
def test_rt14_33_negative_a_configured_org_skips_the_ancestry_and_an_unrelated_folder_is_not_matched(
        server, monkeypatch, org_env):
    monkeypatch.setenv("ORGANIZATION_ID", org_env)
    svc = server.service.ComplianceService(project_id="")
    svc._session = _AwApis(pages=[[_aw("999")]])
    out = svc.inspect_parent_folder("folders/555")
    assert out["is_assured_workload"] is False and out["assured_workloads_check"] == {"status": "CHECKED"}
    assert [u for u, _, _ in svc._session.calls] == [
        "https://assuredworkloads.googleapis.com/v1/organizations/42/locations/-/workloads"]


def test_rt14_33_a_refused_list_is_a_typed_failure_not_a_silent_no(server, monkeypatch, caplog):
    monkeypatch.setenv("ORGANIZATION_ID", "42")
    svc = server.service.ComplianceService(project_id="")
    svc._session = _AwApis(aw_status=403)
    out = svc.inspect_parent_folder("folders/555")
    check = out["assured_workloads_check"]
    assert out["is_assured_workload"] is False
    assert check["status"] == "FAILED" and check["error_class"] == "AW_CHECK_FAILED" and check["http_status"] == 403
    assert "AW_CHECK_FAILED" in caplog.text


def test_rt14_33_an_unknown_org_is_typed(server, monkeypatch):
    monkeypatch.delenv("ORGANIZATION_ID", raising=False)
    svc = server.service.ComplianceService(project_id="")
    svc._session = _AwApis(parents={})   # folders.get refused
    check = svc.inspect_parent_folder("folders/555")["assured_workloads_check"]
    assert check["error_class"] == "AW_CHECK_ORG_UNKNOWN" and check["http_status"] == 403


def test_rt14_33_the_answer_carries_the_check(server, monkeypatch):
    monkeypatch.setenv("ORGANIZATION_ID", "42")
    svc = server.service.ComplianceService(project_id="mock-stackvend-project")
    svc._session = _AwApis(aw_status=403)
    monkeypatch.setattr(svc, "inspect_org_policies", lambda folder_id: {})
    out = svc.inspect_folder("folders/555", "a todo app")
    assert out["assured_workloads_check"]["error_class"] == "AW_CHECK_FAILED"
