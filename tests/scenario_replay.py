"""SCENARIO-REPLAY-CORPUS (owner 11-13, review item (g)): an offline, deterministic replay of whole pipeline runs.

One scenario = one data file in tests/scenario_corpus/ (JSON). The harness drives the REAL platform code of the loop
that failed live (developer dispatch -> QA -> repair routing -> relaunch / cleanup, and deploy-failure routing) and
fakes only what sits outside the platform process:

REAL (product code, unmodified):
  * gateway `_execute_developer_logic` (remediation guard, QA feedback matching, compliance decision, orphan
    deletions, committed-draft record), `DeveloperAgent.generate_code_files` (assembly, platform renders, the
    hallucination stack, the QA / deploy repair planners, the repair loop, app provenance, orphan decision) and
    `commit_and_open_pr` (pre-commit gatekeeper, validated-hash check, provenance writes);
  * gateway `run_qa` (Stage 1 verdict, Stage 2 context, judge input, platform facts, both lenses, the judge
    transport with its retry rule, the coordinator, `_judge_diagnostics`, NO_PROGRESS, the evidence record).
FAKED (data from the scenario file):
  * the LLM: the developer swarm's draft per generation, the repair loop's answers, and the judge's raw
    `generate_content` answers per QA attempt / lens / model (at the google-genai client boundary, so every
    platform rule above it runs); a judge answer can be withdrawn when the trusted PLATFORM FACTS of its prompt
    name a given token, or (CLOUDSQL-PASSWORD-BINDING) when the tested tree meets a sandbox-style condition (a
    judge that reads the code under audit), and parallel fields are sent only when the request's response schema
    asks for them;
  * the repository (an in-memory git: main + branches + commits; every dispatch branches from main, as the real
    provider does), the Firestore store (deep merge), the QA sandbox (tests are not run: diagnostics fire by exact
    rules on the tested tree), the terraform server's deploy result (recorded callback body), the /validate client
    (PASS), and the clock of the judge transport (virtual: a provider 504 costs its recorded latency, no waiting);
  * the Cloud Workflows state machine: `ScenarioRunner.workflow` mirrors the routing rules of
    workflows/main_orchestrator.yaml (check_qa_status, check_deploy_status, check_tf_remediation); max_retries and
    max_tf_retries are read from the YAML. The gatekeeper step (it re-verifies the commit) is not replayed.

A scenario states its expected typed outcome; `check_expectations` compares it with the replay. Adding a scenario
is data only. See docs/planning/scenario-replay-corpus-plan.md.
"""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import threading
import time as _real_time
import types
from contextlib import ExitStack
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import MagicMock, patch

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TESTS_DIR)
CORPUS_DIR = os.path.join(TESTS_DIR, "scenario_corpus")
WORKFLOW_YAML = os.path.join(REPO_ROOT, "workflows", "main_orchestrator.yaml")
REPO_FULL_NAME = "example-org/scenario-repo"


class ScenarioDataError(Exception):
    """The scenario file is incomplete for the path the replay took, or a harness seam is gone (a fixture or harness
    problem, never a platform verdict). Not an AssertionError: a pending scenario's xfail never hides it."""


class ScenarioExpectationNotMet(AssertionError):
    """The replay ran and the platform did not reach the expected outcome. The only exception a pending scenario's
    strict xfail accepts (`raises=`)."""


class ScenarioRouteChanged(AssertionError):
    """A pending scenario no longer takes the route it takes before its fix (`xfail.current`): something else changed
    how it fails. Never accepted by the xfail."""


# ------------------------------------------------------------------------------------------------ workflow limits
def workflow_limits() -> Dict[str, int]:
    """max_retries / max_tf_retries of the main run, read from the workflow YAML (the first assignment of each)."""
    with open(WORKFLOW_YAML, encoding="utf-8") as fh:
        text = fh.read()
    out = {}
    for key in ("max_retries", "max_tf_retries"):
        m = re.search(rf"^\s*- {key}: (\d+)", text, re.MULTILINE)
        if not m:
            raise ScenarioDataError(f"{key} not found in {WORKFLOW_YAML}")
        out[key] = int(m.group(1))
    return out


# ------------------------------------------------------------------------------------------------ fake Firestore
def _deep_merge(dst: Dict[str, Any], src: Dict[str, Any]) -> None:
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_merge(dst[k], v)
        else:
            dst[k] = copy.deepcopy(v)


def _jsonable(data: Any) -> Any:
    data = json.loads(json.dumps(data, default=str))
    bad = firestore_nested_array_paths(data)
    if bad:   # RT F1: what Firestore would refuse is refused here too
        raise ValueError(f"Firestore cannot store an array inside an array: {bad[:5]}")
    return data


def firestore_nested_array_paths(value: Any, path: str = "", in_array: bool = False) -> List[str]:
    """JUDGE-NAMED-INTENT-REMOVAL RT F1: Firestore refuses an array directly inside an array (the real client sends it
    and the server answers 400). The paths of every such array in `value` ([] = storable); the fake stores enforce it."""
    out: List[str] = []
    if isinstance(value, dict):
        for k, v in value.items():
            out += firestore_nested_array_paths(v, f"{path}.{k}", False)
    elif isinstance(value, (list, tuple)):
        if in_array:
            return [path]
        for i, v in enumerate(value):
            out += firestore_nested_array_paths(v, f"{path}[{i}]", True)
    return out


class _Snap:
    def __init__(self, store: "ScenarioStore", path: str):
        self._store, self._path = store, path
        self.id = path.rsplit("/", 1)[-1]
        self.reference = _Doc(store, path)
        self.update_time = store.versions.get(path)

    @property
    def exists(self) -> bool:
        return self._path in self._store.docs

    def to_dict(self):
        return copy.deepcopy(self._store.docs.get(self._path)) if self.exists else None

    def get(self, key):
        return (self.to_dict() or {}).get(key)


class _Doc:
    def __init__(self, store: "ScenarioStore", path: str):
        self._store, self._path = store, path
        self.id = path.rsplit("/", 1)[-1]

    def get(self, *a, **k):
        return _Snap(self._store, self._path)

    def set(self, data, merge=False):
        data = _jsonable(data)
        self._store.versions[self._path] = self._store.versions.get(self._path, 0) + 1
        if merge and self._path in self._store.docs:
            if isinstance(merge, (list, tuple)):
                for f in merge:
                    if f in data:
                        self._store.docs[self._path][f] = data[f]
            else:
                _deep_merge(self._store.docs[self._path], data)
        else:
            self._store.docs[self._path] = data

    def create(self, data):
        if self._path in self._store.docs:
            from google.api_core import exceptions as gexc
            raise gexc.AlreadyExists(f"{self._path} already exists")
        self.set(data)

    def update(self, data, option=None):
        if self._path not in self._store.docs:
            from google.api_core import exceptions as gexc
            raise gexc.NotFound(f"{self._path} not found")
        doc = self._store.docs[self._path]
        for key, value in _jsonable(data).items():
            node = doc
            parts = key.split(".")
            for p in parts[:-1]:
                node = node.setdefault(p, {})
            node[parts[-1]] = value
        self._store.versions[self._path] = self._store.versions.get(self._path, 0) + 1

    def delete(self):
        self._store.docs.pop(self._path, None)

    def collection(self, name):
        return _Col(self._store, f"{self._path}/{name}")


class _Col:
    def __init__(self, store: "ScenarioStore", path: str, filters=()):
        self._store, self._path, self._filters = store, path, tuple(filters)

    def document(self, doc_id=None):
        return _Doc(self._store, f"{self._path}/{doc_id or hashlib.sha1(os.urandom(8)).hexdigest()[:20]}")

    def where(self, *args, **kw):
        flt = kw.get("filter")
        if flt is not None:
            args = (getattr(flt, "field_path", None), getattr(flt, "op_string", None), getattr(flt, "value", None))
        return _Col(self._store, self._path, self._filters + (tuple(args),))

    def order_by(self, *a, **k):
        return self

    def limit(self, n):
        return self

    def stream(self):
        prefix = self._path + "/"
        out = []
        for p in sorted(self._store.docs):
            if not p.startswith(prefix) or "/" in p[len(prefix):]:
                continue
            doc = self._store.docs[p]
            if all(f[1] != "==" or doc.get(f[0]) == f[2] for f in self._filters if len(f) == 3):
                out.append(_Snap(self._store, p))
        return out

    def get(self):
        return self.stream()


class ScenarioStore:
    """In-memory Firestore with a deep `set(merge=True)` (the real store merges nested maps field by field)."""

    def __init__(self):
        self.docs: Dict[str, Dict[str, Any]] = {}
        self.versions: Dict[str, int] = {}

    def collection(self, name):
        return _Col(self, name)

    def write_option(self, **kw):
        return dict(kw)

    def batch(self):
        store = self

        class _Batch:
            def __init__(self):
                self.ops = []

            def set(self, ref, data, merge=False):
                self.ops.append((ref, data, merge))

            def commit(self):
                for ref, data, merge in self.ops:
                    ref.set(data, merge=merge)
        return _Batch()

    def doc(self, path: str) -> Dict[str, Any]:
        return copy.deepcopy(self.docs.get(path) or {})


# ------------------------------------------------------------------------------------------------ fake repository
def tree_sha(tree: Dict[str, str]) -> str:
    return hashlib.sha1(json.dumps(sorted(tree.items())).encode("utf-8")).hexdigest()


class ScenarioRepo:
    """An in-memory git repository: `main`, branches, commits by sha (sha = hash of the tree + parent + n). Serves
    the developer's VCS provider calls and QA's source backend (head_sha / archive)."""

    strip_top_dir = False

    def __init__(self, provider: str = "GITHUB"):
        self.provider = provider
        self.branches: Dict[str, str] = {}
        self.commits: Dict[str, Dict[str, str]] = {}
        self.log: List[Dict[str, Any]] = []
        self._n = 0
        self.set_branch("main", {})

    def _commit(self, tree: Dict[str, str]) -> str:
        self._n += 1
        sha = hashlib.sha1(f"{self._n}:{tree_sha(tree)}".encode("utf-8")).hexdigest()
        self.commits[sha] = dict(tree)
        return sha

    def set_branch(self, branch: str, tree: Dict[str, str]) -> str:
        sha = self._commit(tree)
        self.branches[branch] = sha
        return sha

    def tree(self, branch_or_sha: str) -> Dict[str, str]:
        sha = self.branches.get(branch_or_sha, branch_or_sha)
        return dict(self.commits[sha])

    # --- VCS provider (developer commit_and_open_pr)
    def create_or_verify_branch(self, repo, branch, source_branch="main"):
        if branch not in self.branches:
            self.branches[branch] = self.branches[source_branch]

    def commit_files(self, repo, branch, files, message, files_to_delete=None, **kw):
        tree = self.tree(branch)
        tree.update({p: c for p, c in files.items() if isinstance(c, str)})
        for p in files_to_delete or []:
            tree.pop(p, None)
        sha = self.set_branch(branch, tree)
        self.log.append({"branch": branch, "sha": sha, "written": sorted(files), "deleted": sorted(files_to_delete or [])})
        return sha

    def create_pull_request(self, repo, title=None, body=None, head_branch=None, base_branch=None, **kw):
        """The provider's PR identity (handler.PR_IDENTITY_KEYS): the branch exactly as pushed, in the same repository."""
        n = len(self.log)
        return {"pull_request_url": f"https://example.invalid/{repo}/pull/{n}", "pr_number": n,
                "head_ref": head_branch, "head_sha": self.branches.get(head_branch), "head_repo_full_name": repo,
                "head_repo_id": 1, "base_ref": base_branch, "base_repo_full_name": repo, "base_repo_id": 1}

    def reconcile_automated_pull_requests(self, repo, superseded=None):
        return {"results": []}

    def merge(self, branch: str, store: Any = None) -> str:
        """Release promotion: main becomes the branch's tree; the branch's PR ledger entry is marked MERGED (the
        release step's own record of an observed merge)."""
        if store is not None:
            from shared import vcs_ledger
            for path, doc in list(store.docs.items()):
                if path.startswith(vcs_ledger.COLLECTION + "/") and doc.get("branch") == branch:
                    vcs_ledger.mark(store, path.split("/", 1)[1], vcs_ledger.STATE_MERGED, reason="scenario release")
        return self.set_branch("main", self.tree(branch))

    # --- QA source backend
    def head_sha(self, branch):
        from qa_source import BranchNotFoundError   # RT14-28: the providers' typed "no such branch"
        if branch not in self.branches:
            raise BranchNotFoundError(f"no branch {branch}")
        return self.branches[branch]

    def archive(self, branch, sha):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w:gz") as tf:
            for name, text in sorted(self.commits[sha].items()):
                data = text.encode("utf-8")
                ti = tarfile.TarInfo(name)
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
        return sha, raw.getvalue()


# ------------------------------------------------------------------------------------------------ virtual clock
class VirtualTime:
    """A `time` module stand-in for the judge transport and the Stage 2 coordinator: monotonic() is a fixed base plus
    a per-thread offset (the two lenses run in parallel threads, each with its own elapsed time); sleep() and a
    provider call advance the calling thread only. Everything else is the real `time` module."""

    BASE = 10_000.0

    def __init__(self):
        self._local = threading.local()

    def _offset(self) -> float:
        return getattr(self._local, "offset", 0.0)

    def advance(self, seconds: float) -> None:
        self._local.offset = self._offset() + float(seconds)

    def monotonic(self) -> float:
        return self.BASE + self._offset()

    def sleep(self, seconds: float) -> None:
        self.advance(seconds)

    def fresh(self, fn):
        """`fn` run on a clock that starts at BASE (one parallel task of the coordinator)."""
        def run(*a, **k):
            self._local.offset = 0.0
            return fn(*a, **k)
        return run

    def __getattr__(self, name):
        return getattr(_real_time, name)


# ------------------------------------------------------------------------------------------------ harness seams
# Every product attribute the harness patches or calls (module, attribute). A missing one is a ScenarioDataError (the
# harness must be updated with the change that removed it), never a silent skip: tests/test_scenario_replay_corpus.py
# test_harness_seams_exist checks the list on its own.
SEAMS = (
    ("main", "_execute_developer_logic"), ("main", "run_qa"), ("main", "DeveloperExecuteRequest"),
    ("main", "QAVerifyRequest"), ("main", "developer_agent"), ("main", "db"), ("main", "get_evidence_db"),
    ("main", "get_governance_db"), ("main", "get_source_backend_factory"),
    ("developer_agent.handler", "DeveloperAgent"), ("developer_agent.handler", "VCSProviderFactory"),
    ("developer_agent.handler", "LeadDeveloperOrchestrator"), ("developer_agent.handler", "SwarmDispatcher"),
    ("developer_agent.handler", "get_model_cascade_for_agent"), ("developer_agent.handler", "time"),
    ("developer_agent.handler", "SwarmExecutionMode"),
    ("developer_agent.handler.DeveloperAgent", "_persist_qa_repair"),
    ("developer_agent.handler.DeveloperAgent", "fetch_existing_repo_files"),
    ("developer_agent.handler.DeveloperAgent", "fetch_github_token"),
    ("developer_agent.handler.DeveloperAgent", "get_full_repo_name"),
    ("developer_agent.handler.DeveloperAgent", "stack_run"),
    ("developer_agent.handler.DeveloperAgent", "attach_stack_runtime"),
    ("qa_auditor.judge", "_client"), ("qa_auditor.judge", "time"), ("qa_auditor.coordinator", "time"),
    ("qa_auditor.coordinator", "evaluate_security_lens"), ("qa_auditor.coordinator", "evaluate_adherence_lens"),
    ("qa_auditor.coordinator", "STAGE_TWO_DEADLINE_S"), ("qa_auditor.judge_input", "platform_rendered_paths"),
    ("shared.vcs_provider.VCSProviderFactory", "get_provider"), ("shared.vcs_ledger", "mark"),
    ("gate_errors", "NON_REMEDIABLE_DEPLOY_CLASSES"),
)


def _resolve_seam(owner: str, gw: Any = None) -> Any:
    import importlib
    if owner == "main":
        if gw is None:
            raise ScenarioDataError("the gateway module is needed to check its seams")
        return gw
    mod_name, _, cls = owner.partition(".DeveloperAgent") if owner.endswith(".DeveloperAgent") else (owner, "", "")
    if owner.endswith(".VCSProviderFactory"):
        return importlib.import_module(owner.rsplit(".", 1)[0]).VCSProviderFactory
    mod = importlib.import_module(mod_name)
    return mod.DeveloperAgent if owner.endswith(".DeveloperAgent") else mod


def missing_seams(gw: Any = None) -> List[str]:
    """The SEAMS that do not exist ([] = the harness still fits the product). `main` seams need the gateway module."""
    out = []
    for owner, attr in SEAMS:
        if owner == "main" and gw is None:
            continue
        try:
            target = _resolve_seam(owner, gw)
        except ImportError as e:
            out.append(f"{owner} ({type(e).__name__})")
            continue
        if not hasattr(target, attr):
            out.append(f"{owner}.{attr}")
    return out


def require_seams(gw: Any = None) -> None:
    gone = missing_seams(gw)
    if gone:
        raise ScenarioDataError(f"harness seams gone (update tests/scenario_replay.py with the change): {gone}")


# ------------------------------------------------------------------------------------------------ fake judge (LLM)
class _ProviderError(Exception):
    """An SDK-shaped provider error: google.genai.errors.APIError carries the HTTP status as the int `code`."""

    def __init__(self, code: int):
        super().__init__(f"{code} provider error (scenario replay)")
        self.code = code


def _schema_properties(config: Any) -> List[str]:
    rs = getattr(config, "response_schema", None)
    if rs is None:
        return []
    if isinstance(rs, dict):
        return list((rs.get("properties") or {}).keys())
    props = getattr(rs, "properties", None) or {}
    return list(props.keys())


def _facts_section(prompt: str) -> str:
    """The trusted PLATFORM FACTS section of a lens prompt ("" when the prompt has none)."""
    m = re.search(r"^### PLATFORM FACTS[^\n]*\n(.*?)(?=^### |\Z)", prompt, re.MULTILINE | re.DOTALL)
    return m.group(1) if m else ""


class FakeJudgeClient:
    """The judge's google-genai client. Answers per (QA attempt, lens, model) from the scenario's `judge` script.

    Lens spec: {"reply": R} (every call), or {"by_model": {"<model id>" | "*": [step, ...]}}; a step is
    {"reply": R} or {"error": <HTTP status>, "latency_s": <seconds the failed call takes>}. Steps are consumed in
    order per (attempt, lens, model key); the last step repeats. A reply R is the model's answer in a compact form
    (`render_reply`). JUDGE-FALLBACK-FLASH-ROOM: a request's own time box (`config.http_options.timeout`, the
    X-Server-Timeout Vertex enforces) bounds every step: a step slower than the box (an error's or a reply's
    `latency_s`) is a 504 at the box, as Vertex answers."""

    def __init__(self, script: Dict[str, Any], clock: VirtualTime, errors: Optional[List[str]] = None):
        self.errors = errors if errors is not None else []
        self.script = script
        self.clock = clock
        self.attempt = 0
        self.calls: List[Dict[str, Any]] = []
        self._cursor: Dict[Tuple[int, str, str], int] = {}
        self._lock = threading.Lock()
        self.models = self
        self.tree: Dict[str, str] = {}    # the tree under audit (set per QA attempt) for `withdraw_if_tree`
        self.blobs: Dict[str, str] = {}

    def _lens_spec(self, lens: str) -> Dict[str, Any]:
        per_attempt = self.script.get(str(self.attempt)) or self.script.get("*") or {}
        spec = per_attempt.get(lens)
        if spec is None:
            self.errors.append(f"no judge script for attempt {self.attempt} lens {lens}")
            raise ScenarioDataError(self.errors[-1])
        return spec

    def generate_content(self, model, contents, config):
        props = _schema_properties(config)
        prompt = contents if isinstance(contents, str) else json.dumps(contents, default=str)
        if "critical_vulnerabilities" in props:
            lens = "security"
        elif "instruction_adherence_score" in props:
            lens = "adherence"
        else:
            self.errors.append(f"judge call with an unknown response schema: {props}")
            raise ScenarioDataError(self.errors[-1])
        spec = self._lens_spec(lens)
        if "reply" in spec:
            step = {"reply": spec["reply"]}
        else:
            by_model = spec.get("by_model") or {}
            key = model if model in by_model else "*"
            steps = by_model.get(key)
            if not steps:
                self.errors.append(f"no judge steps for attempt {self.attempt} lens {lens} model {model}")
                raise ScenarioDataError(self.errors[-1])
            with self._lock:
                n = self._cursor.get((self.attempt, lens, key), 0)
                self._cursor[(self.attempt, lens, key)] = n + 1
            step = steps[min(n, len(steps) - 1)]
        start = self.clock.monotonic()
        timeout_ms = getattr(getattr(config, "http_options", None), "timeout", None)
        box = timeout_ms / 1000.0 if isinstance(timeout_ms, (int, float)) and timeout_ms > 0 else None
        record = {"attempt": self.attempt, "lens": lens, "model": model, "t_start": start, "box_s": box}
        latency = float(step.get("latency_s", 0.0 if "error" in step else 1.0))
        if box is not None and latency > box:
            step, latency = {"error": 504}, box   # Vertex ends the call at the request's X-Server-Timeout
        if "error" in step:
            self.clock.advance(latency)
            record.update(outcome=f"error {step['error']}", t_end=self.clock.monotonic())
            with self._lock:
                self.calls.append(record)
            raise _ProviderError(int(step["error"]))
        self.clock.advance(latency)
        text = json.dumps(render_reply(lens, step["reply"], prompt, props, self.tree, self.blobs))
        record.update(outcome="reply", t_end=self.clock.monotonic())
        with self._lock:
            self.calls.append(record)
        from google.genai import types as gtypes
        return gtypes.GenerateContentResponse.model_validate({
            "candidates": [{"content": {"role": "model", "parts": [{"text": text}]}, "finish_reason": "STOP"}],
            "usage_metadata": {"prompt_token_count": 10, "candidates_token_count": 5}})


def render_reply(lens: str, reply: Dict[str, Any], prompt: str, props: List[str],
                 tree: Optional[Dict[str, str]] = None, blobs: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """The judge's JSON answer from the compact scenario form.

    security: {"critical": [item, ...]}; adherence: {"score", "grounding", "missed": [item, ...],
    "score_after_withdrawal"}. An item is {"text", "file", "task_id", "schema_fields": {field: value},
    "withdraw_if_facts_mention": token, "withdraw_if_tree": condition}: withdrawn when the prompt's trusted PLATFORM
    FACTS contain the token (a judge that reads the facts), or when the tested tree meets the condition (the sandbox
    rule grammar: a judge that reads the code under audit); `schema_fields` are sent (as parallel lists) only when the response schema declares
    them (a judge that follows the schema it is given). APP-ADMIN-IAP-CONTRACT: `"require_facts_mention": token`
    raises the item only when the trusted PLATFORM FACTS contain the token (a finding the judge can only ground in a
    platform fact); an item never raised is not a withdrawal."""
    facts = _facts_section(prompt)
    items_key = "critical" if lens == "security" else "missed"
    raw_items = [i for i in reply.get(items_key) or []
                 if not (i.get("require_facts_mention") and i["require_facts_mention"] not in facts)]
    items = [i for i in raw_items
             if not (i.get("withdraw_if_facts_mention") and i["withdraw_if_facts_mention"] in facts)
             and not (i.get("withdraw_if_tree") and _rule_holds(i["withdraw_if_tree"], tree or {}, blobs or {}))]
    withdrawn = len(items) < len(raw_items)
    extra_fields: Dict[str, List[Any]] = {}
    for it in items:
        for f in (it.get("schema_fields") or {}):
            if f in props:
                extra_fields.setdefault(f, [])
    for f in extra_fields:
        extra_fields[f] = [(it.get("schema_fields") or {}).get(f, "OTHER") for it in items]
    if lens == "security":
        out = {"passed": not items, "critical_vulnerabilities": [i["text"] for i in items],
               "critical_vulnerability_files": [i.get("file") or "" for i in items],
               "moderate_vulnerabilities": list(reply.get("moderate") or []), "compliance_flags": [],
               "summary": reply.get("summary", "security review")}
    else:
        score = reply.get("score", 1.0)
        if withdrawn and not items and "score_after_withdrawal" in reply:
            score = reply["score_after_withdrawal"]
        out = {"instruction_adherence_score": score, "grounding_score": reply.get("grounding", 1.0),
               "missed_directives": [i["text"] for i in items],
               "missed_directive_task_ids": [i.get("task_id") or "" for i in items],
               "missed_directive_files": [i.get("file") or "" for i in items],
               "hallucinated_features": [], "summary": reply.get("summary", "adherence review")}
    out.update(extra_fields)
    return out


# ------------------------------------------------------------------------------------------------ fake QA sandbox
def _rule_holds(cond: Dict[str, Any], tree: Dict[str, str], blobs: Dict[str, str]) -> bool:
    if "all" in cond:
        return all(_rule_holds(c, tree, blobs) for c in cond["all"])
    path = cond["file"]
    if "present" in cond:
        return (path in tree) is bool(cond["present"])
    if "blob" in cond:
        return tree.get(path) == blobs[cond["blob"]]
    if "contains" in cond:
        return cond["contains"] in tree.get(path, "")
    if "lacks" in cond:
        return path in tree and cond["lacks"] not in tree[path]
    raise ScenarioDataError(f"unknown sandbox condition {cond}")


class FakeQASandbox:
    """The isolated QA job: diagnostics fire by exact rules on the tested tree (tests are not executed)."""

    def __init__(self, spec: Dict[str, Any], repo: ScenarioRepo, blobs: Dict[str, str]):
        self.rules = list((spec or {}).get("rules") or [])
        self.tests_total = int((spec or {}).get("tests_total", 10))
        self.repo, self.blobs = repo, blobs
        self.runs: List[Dict[str, Any]] = []

    def run(self, *, tar_bytes, commit_sha, trace_id, product_id, deadline):
        from gate_errors import ErrorClass
        from qa_job_client import QAOutcome
        tree = self.repo.tree(commit_sha)
        diags: List[Dict[str, Any]] = []
        for rule in self.rules:
            if _rule_holds(rule["when"], tree, self.blobs):
                for d in rule["diagnostics"]:
                    diags.append(dict({"tool": "pytest", "severity": "error", "line": None, "detail": None}, **d))
        self.runs.append({"commit_sha": commit_sha, "diagnostics": len(diags)})
        nonce = "n" * 32
        if not diags:
            return QAOutcome(passed=True, error_class=None, summary=f"QA passed: {self.tests_total} tests",
                             static={"passed": True}, exit_code=0, nonce=nonce, execution_name="exec/scenario",
                             report={"passed": True, "tests_total": self.tests_total, "tests_failed": 0,
                                     "logs_tail": f"{self.tests_total} passed"})
        return QAOutcome(passed=False, error_class=ErrorClass.CODE_DEFECT, summary=f"QA failed: {len(diags)} finding(s)",
                         diagnostics=diags, static={"passed": True}, exit_code=1, nonce=nonce,
                         execution_name="exec/scenario",
                         report={"passed": False, "tests_total": self.tests_total, "tests_failed": len(diags),
                                 "logs_tail": f"{len(diags)} failed"})

    def verify_job_readiness(self):
        return None


# ------------------------------------------------------------------------------------------------ the replay
@dataclass
class Replay:
    """What happened, in typed facts only (no log text)."""
    events: List[Dict[str, Any]] = field(default_factory=list)
    outcome: Dict[str, Any] = field(default_factory=dict)
    judge_calls: List[Dict[str, Any]] = field(default_factory=list)
    final_main: Dict[str, str] = field(default_factory=dict)
    store: Any = None
    commits: Dict[str, Dict[str, str]] = field(default_factory=dict)
    drafts_by_sha: Dict[str, List[str]] = field(default_factory=dict)

    def dispatches(self, trace: Optional[str] = None) -> List[Dict[str, Any]]:
        return [e for e in self.events if e["kind"] == "developer" and (trace is None or e["trace"] == trace)]

    def qa_runs(self, trace: Optional[str] = None) -> List[Dict[str, Any]]:
        return [e for e in self.events if e["kind"] == "qa" and (trace is None or e["trace"] == trace)]


def load_scenario(path: str) -> Dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    data.setdefault("id", os.path.splitext(os.path.basename(path))[0])
    return data


def scenario_files() -> List[str]:
    return sorted(os.path.join(CORPUS_DIR, f) for f in os.listdir(CORPUS_DIR) if f.endswith(".json"))


def _resolve(value: Any, blobs: Dict[str, str]) -> str:
    if isinstance(value, str) and value.startswith("@"):
        if value[1:] not in blobs:
            raise ScenarioDataError(f"unknown blob {value}")
        return blobs[value[1:]]
    return value


def _files(spec: Dict[str, Any], blobs: Dict[str, str]) -> Dict[str, str]:
    return {p: _resolve(v, blobs) for p, v in (spec or {}).items()}


class ScenarioRunner:
    """Runs one scenario through the real gateway + developer code with the fakes above."""

    def __init__(self, scenario: Dict[str, Any], monkeypatch: Any):
        self.sc = scenario
        self.mp = monkeypatch
        self.blobs = dict(scenario.get("blobs") or {})
        self.pid = scenario["product_id"]
        self.limits = workflow_limits()
        self.replay = Replay()
        self.store = ScenarioStore()
        self.repo = ScenarioRepo(provider=scenario.get("vcs_provider", "GITHUB"))
        self.clock = VirtualTime()
        self.data_errors: List[str] = []   # fixture gaps hit inside product code (which may catch the exception)
        self.judge = FakeJudgeClient(scenario.get("judge") or {}, self.clock, self.data_errors)
        self.sandbox = FakeQASandbox(scenario.get("sandbox") or {}, self.repo, self.blobs)
        self.drafts = {k: _files(v, self.blobs) for k, v in (scenario.get("drafts") or {}).items()}
        self.repairs = [_files(r, self.blobs) for r in (scenario.get("repairs") or [])]
        self._draft_queue: List[str] = []
        self._plans: List[Dict[str, Any]] = []
        self.generations = 0
        self.repair_calls = 0

    # ------------------------------------------------------------------ setup
    def _seed_store(self) -> None:
        sc, pid = self.sc, self.pid
        access = dict(sc.get("access") or {"mode": "PUBLIC_APP"})
        public = access.get("mode") == "PUBLIC_APP"
        access.setdefault("sign_in", {"google": "DISABLED", "email_password": True} if public else {"google": "DISABLED"})
        access.setdefault("source", "intake")
        if public:
            access.setdefault("tenant_isolation_required", False)
        workload = {"vcs_provider": self.repo.provider, "github_repo": REPO_FULL_NAME, "access": access,
                    "default_branch": "main"}
        workload.update(sc.get("workload_record") or {})
        self.store.docs[f"workloads/{pid}"] = _jsonable(workload)
        models = sc.get("models") or {}
        self.store.docs["system_config/platform_settings"] = {"models": {
            "architect_model": models.get("primary", "gemini-4-carbon"),
            "developer_model": models.get("primary", "gemini-4-carbon"),
            "fallback_models": list(models.get("fallback", ["gemini-4-argon"]))}}
        for trace in self._traces():
            self.store.docs[f"workloads/{pid}/compliance_audits/{trace}"] = {
                "product_id": pid, "trace_id": trace, "allow_unauthenticated": public,
                "enable_direct_iap": access.get("mode") == "PRIVATE_IAP", "domain_restricted_sharing": False,
                "allowed_domains": [], "compliance_profile": "STANDARD", "is_regulated": False,
                "requires_cmek": False, "requires_audit_logging": False}
            self.store.docs[f"pipeline_executions/{trace}"] = {
                "product_id": pid, "trace_id": trace, "execution_mode": "FULL",
                "stages": {"architect": {"details": {"task_dag": sc.get("task_dag") or [
                    {"task_id": "CODE-01", "title": "service", "target_files": []}]}},
                    "compliance": {"summary": "ok", "details": {"active_frameworks": ["SOC2-BASELINE"]}}}}

    def _traces(self) -> List[str]:
        out = [s["trace"] for s in self.sc.get("prehistory") or []]
        out.append(self.sc["trace"])
        return list(dict.fromkeys(out))

    def _settings(self):
        from shared import settings as ss
        models = self.sc.get("models") or {}
        ps = ss.PlatformSettings.model_validate({"models": {
            "architect_model": models.get("primary", "gemini-4-carbon"),
            "developer_model": models.get("primary", "gemini-4-carbon"),
            "fallback_models": list(models.get("fallback", ["gemini-4-argon"]))}})
        self.mp.setattr(ss, "_SETTINGS_CACHE", ps)
        self.mp.setattr(ss, "_LAST_FETCH_TIME", float("inf"))

    def setup(self, stack: ExitStack) -> None:
        sys.path.insert(0, TESTS_DIR) if TESTS_DIR not in sys.path else None
        import fd4f_support
        if not os.environ.get("GITHUB_ORG"):
            self.mp.setenv("GITHUB_ORG", "example-org")   # tests/conftest.py sets the same default
        self.gw = gw = fd4f_support.load_gateway(self.mp, f"scenario_gw_{self.sc['id'].replace('-', '_')}")
        require_seams(gw)
        self._seed_store()
        self._settings()
        h = sys.modules[type(gw.developer_agent).__module__]
        self.h = h
        from developer_agent.app_provenance import FirestoreAppProvenanceStore
        from developer_agent.hallucination_runtime import HallucinationRuntime
        from developer_agent.platform_facts import MemoryFactsProvider
        from shared.diagnostics import MemoryLedgerStore, MemoryProvenanceStore
        from shared.hallucination_stack import HallucinationStackSettings
        runner = self

        class _Validate:
            def ready(self, iac_engine="OPENTOFU"):
                from shared import iac_intent as II
                art = II.load_artifacts()
                pv = {k: [v] for k, v in art.manifest["provider_schema"]["providers"].items()}
                return {"ready": True, "providers": ["google", "google-beta", "kubernetes", "random"],
                        "engine": "OPENTOFU", "engine_version": "1.9.0", "reason": "", "provider_versions": pv}

            def validate(self, files, *, iac_engine="OPENTOFU", trace_id=""):
                return {"status": "PASS", "diagnostics": []}

        with patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GEMINI_API_KEY": ""}):
            agent = h.DeveloperAgent(project_id="")
        agent.attach_stack_runtime(HallucinationRuntime(
            ledger_store=MemoryLedgerStore(), provenance_store=MemoryProvenanceStore(), validate_client=_Validate(),
            settings=HallucinationStackSettings(iac_intent_mode=self.sc.get("iac_mode", "off")), source="gateway",
            app_provenance_store=FirestoreAppProvenanceStore(self.store),
            # CLOUDSQL-PASSWORD-BINDING: a typed (generate-mode) scenario's network facts come from the deterministic
            # in-memory IPAM ledger (the IPAM engine's allocation order); mode off keeps no provider, as before
            facts_provider=(MemoryFactsProvider() if self.sc.get("iac_mode", "off") != "off" else None)))
        agent.db = self.store

        class _NoCallGenai:
            class models:  # noqa: N801
                @staticmethod
                def generate_content(*a, **k):
                    raise AssertionError("unexpected developer LLM call outside the swarm / repair fakes")
        agent.genai_client = _NoCallGenai()

        def fetch_existing(product_id, *a, **k):
            agent.last_tree_status = {"complete": True, "truncated": False, "error": None}
            return runner.repo.tree("main")
        self.mp.setattr(agent, "fetch_existing_repo_files", fetch_existing)
        self.mp.setattr(agent, "fetch_github_token", lambda *a, **k: "scenario-token")
        self.mp.setattr(agent, "get_full_repo_name", lambda *a, **k: REPO_FULL_NAME)
        real_persist = agent._persist_qa_repair

        def persist_spy(trace_id, summary):   # the dispatch's QA-FEEDBACK decision, as the developer persists it
            runner._plans.append(dict(summary))
            return real_persist(trace_id, summary)
        self.mp.setattr(agent, "_persist_qa_repair", persist_spy)
        self.agent = agent
        self.mp.setattr(gw, "developer_agent", agent)
        self.mp.setattr(gw, "db", self.store)
        self.mp.setattr(gw, "get_evidence_db", lambda: self.store)
        self.mp.setattr(gw, "get_governance_db", lambda: self.store)
        self.mp.setattr(gw, "get_source_backend_factory", lambda: (lambda product_id: self.repo))

        class _Factory:
            @staticmethod
            def get_provider(*a, **k):
                return runner.repo
        self.mp.setattr(h, "VCSProviderFactory", _Factory)
        import shared.vcs_provider as vcs_provider   # the gateway's own lookups (PR reconcile, release)
        self.mp.setattr(vcs_provider.VCSProviderFactory, "get_provider", staticmethod(_Factory.get_provider))
        no_sleep = {n: getattr(_real_time, n) for n in dir(_real_time) if not n.startswith("__")}
        no_sleep["sleep"] = lambda s: None   # commit_and_open_pr's branch replication grace window
        self.mp.setattr(h, "time", types.SimpleNamespace(**no_sleep))

        # the developer swarm and its repair calls (the only developer LLM calls)
        plan = MagicMock()
        plan.execution_mode = [m for m in h.SwarmExecutionMode if m != h.SwarmExecutionMode.SOLO_FAST_PATH][0]
        plan.tasks = [MagicMock()]

        class FakeDispatcher:
            def __init__(self, *a, **k):
                self.last_file_attribution = {}
                self.envelope_checks = [{"ok": True, "error": None}]
                self.iac_intent = None

            async def execute_phased_junior_swarm(self, *a, **k):
                draft = runner._next_draft()
                self.last_file_attribution = {p: ("DEVOPS_ENGINEER" if p.startswith(".github/") else
                                                  "IAC_ENGINEER" if p.startswith("infra/") else "BACKEND_ENGINEER")
                                              for p in draft}
                return dict(draft)

            def invoke_repair(self, persona, system_instruction, prompt, model, max_out, **k):
                return {"files": runner._next_repair(), "envelope_ok": True, "finish_reason": "STOP", "tokens_in": 1,
                        "tokens_out": 1, "tokens_thoughts": 0, "model": model, "persona": persona}

        lead = stack.enter_context(patch.object(h, "LeadDeveloperOrchestrator"))
        lead.return_value.decompose_specification.return_value = plan
        stack.enter_context(patch.object(h, "SwarmDispatcher", FakeDispatcher))
        stack.enter_context(patch.object(h, "get_model_cascade_for_agent", return_value=["gemini-4-carbon"]))
        stack.enter_context(patch.dict(os.environ, {"PROJECT_ID": "", "GOOGLE_CLOUD_PROJECT": "", "GCP_PROJECT": "",
                                                     "ENABLE_DEVELOPER_SWARM": "true"}))
        # any Firestore client the product builds is the scenario's store (settings reads included)
        stack.enter_context(patch("google.cloud.firestore.Client", return_value=self.store))

        # determinism: the developer's branch suffix (and any other uuid4) is a counter, not random
        import uuid
        counter = {"n": 0}

        def uuid4():
            counter["n"] += 1
            return uuid.UUID(hashlib.sha256(f"scenario-uuid-{counter['n']}".encode()).hexdigest()[:32])
        self.mp.setattr(uuid, "uuid4", uuid4)

        # the judge: real lenses / transport / coordinator; the provider and the transport clock are faked
        import qa_auditor.coordinator as coord
        import qa_auditor.judge as judge_mod
        from developer_agent import llm_transport
        require_seams()
        self.mp.setattr(judge_mod, "_client", self.judge)
        for mod in (judge_mod, coord):
            self.mp.setattr(mod, "time", self.clock)
        if hasattr(llm_transport, "time"):   # optional: today the transport policy does not read the clock itself
            self.mp.setattr(llm_transport, "time", self.clock)
        # the lenses run in parallel: each lens evaluation starts at the coordinator's time on its own clock (a pool
        # thread that ran the other lens first must not carry that lens's elapsed time over)
        for name in ("evaluate_security_lens", "evaluate_adherence_lens"):
            self.mp.setattr(coord, name, self.clock.fresh(getattr(coord, name)))

    def _next_draft(self) -> Dict[str, str]:
        if not self._draft_queue:
            self.data_errors.append(f"generation #{self.generations + 1}: no draft queued")
            raise ScenarioDataError(self.data_errors[-1])
        name = self._draft_queue.pop(0)
        if name not in self.drafts:
            self.data_errors.append(f"unknown draft {name!r}")
            raise ScenarioDataError(self.data_errors[-1])
        self.generations += 1
        self.replay.events.append({"kind": "generation", "draft": name, "n": self.generations})
        return self.drafts[name]

    def _next_repair(self) -> Dict[str, str]:
        if self.repair_calls >= len(self.repairs):
            self.data_errors.append(f"repair call #{self.repair_calls + 1}: no repair answer in the scenario")
            raise ScenarioDataError(self.data_errors[-1])
        out = self.repairs[self.repair_calls]
        self.repair_calls += 1
        self.replay.events.append({"kind": "repair_answer", "n": self.repair_calls, "files": sorted(out)})
        return dict(out)

    # ------------------------------------------------------------------ stages
    def _compute_record(self) -> Dict[str, Any]:
        from shared.service_topology import validate_service_topology
        vt, diags = validate_service_topology(self.sc["topology"], product_id=self.pid)
        if vt is None:
            raise ScenarioDataError(f"topology invalid: {[(d.code, d.message) for d in diags]}")
        return {"schema": "architect_compute_intent/v2", "target_compute_services": list(vt.names), "bundle_id": None,
                "compute_archetype": vt.archetype, "service_topology": vt.as_record()}

    def developer(self, trace: str, *, retry: int = 0, drafts: Optional[List[str]] = None,
                  tf_retry: int = 0, tf_context: Optional[str] = None, tf_report: Any = None) -> Dict[str, Any]:
        from gate_errors import GateError
        from shared.diagnostics import StageError
        self._draft_queue = list(drafts or [])
        gens_before = self.generations
        req = self.gw.DeveloperExecuteRequest(
            trace_id=trace, product_id=self.pid, spec_text=self.sc.get("spec_text", "scenario workload"),
            task_dag=self.sc.get("task_dag") or [], retry_count=retry, tf_retry_count=tf_retry,
            tf_remediation_context=tf_context, tf_validation_report=tf_report,
            architect_compute_intent=self._compute_record())
        event: Dict[str, Any] = {"kind": "developer", "trace": trace, "retry": retry, "tf_retry": tf_retry,
                                 "main_sha": self.repo.branches["main"]}
        self._plans = []
        try:
            body = self.gw._execute_developer_logic(req)
        except (GateError, StageError) as e:
            event.update(error=_typed_error(e))
        except Exception as e:  # noqa: BLE001 - an untyped failure is itself a finding (fail loudly, invariant 8)
            if isinstance(e, ScenarioDataError):
                raise
            dev_cls = getattr(e, "error_class", None)
            event.update(error={"type": type(e).__name__, "error_class": dev_cls if isinstance(dev_cls, str) else None,
                                "reason": None, "typed": isinstance(dev_cls, str), "message": str(e)[:300]})
        else:
            event.update(branch=body["branch_name"], commit_sha=body.get("commit_sha"),
                         orphans_deleted=list(body.get("app_orphans_deleted") or []))
        run = self.agent.stack_run(trace)
        dev = (self.store.doc(f"pipeline_executions/{trace}").get("stages") or {}).get("developer") or {}
        event["qa_plan"] = self._plans[-1] if self._plans else None
        event["deploy_plan"] = run.get("deploy_repair") if tf_retry else None
        event["generated"] = self.generations > gens_before
        event["app_orphans"] = (dev.get("app_orphans") or {}).get("status")
        draft = dev.get("committed_draft") or {}
        if event.get("commit_sha") and draft.get("commit_sha") == event["commit_sha"]:
            self.replay.drafts_by_sha[event["commit_sha"]] = list(draft.get("llm_draft_paths") or [])
        self.replay.events.append(event)
        return event

    def qa(self, trace: str, branch: str, sha: str, attempt: int) -> Dict[str, Any]:
        from gate_errors import GateError
        self.judge.attempt = attempt
        self.judge.tree, self.judge.blobs = dict(self.repo.commits.get(sha) or {}), self.blobs
        req = self.gw.QAVerifyRequest(trace_id=trace, product_id=self.pid, branch_name=branch, expected_commit_sha=sha,
                                      attempt=attempt, task_dag=self.sc.get("task_dag") or [])
        event: Dict[str, Any] = {"kind": "qa", "trace": trace, "attempt": attempt, "commit_sha": sha}
        try:
            body = self.gw.run_qa(req, client=self.sandbox, source_backend_factory=lambda pid: self.repo,
                                  evidence_db=self.store)
        except GateError as e:
            event.update(passed=False, error=_typed_error(e))
        else:
            event.update(passed=body["passed"], error_class=body.get("error_class"), reason=body.get("reason"),
                         retryable=body.get("retryable"),
                         diagnostics=[{k: d.get(k) for k in ("code", "file", "task_id", "tool")}
                                      for d in body.get("diagnostics") or []])
        event["record"] = self.store.doc(f"qa_test_runs/{trace}")
        self.replay.events.append(event)
        return event

    # ------------------------------------------------------------------ workflow model
    def run(self) -> Replay:
        with ExitStack() as stack:
            self.setup(stack)
            for step in self.sc.get("prehistory") or []:
                tf_context = step.get("tf_context")
                if step.get("deploy_result") is not None:
                    # an earlier deploy failure of that trace: routed by the terraform server, recorded on the run,
                    # and its text is the remediation dispatch's context (exactly what the workflow forwards)
                    res, route_record = self._route_and_record(step["trace"], step["deploy_result"],
                                                               step.get("engine_plan_stream"))
                    tf_context = res.get("error") or "Terraform deployment validation failed"
                ev = self.developer(step["trace"], drafts=[step["draft"]], tf_retry=step.get("tf_retry", 0),
                                    tf_context=tf_context)
                if "error" in ev:
                    raise ScenarioDataError(f"prehistory step failed: {ev['error']}")
                if step.get("merge"):
                    self.repo.merge(ev["branch"], self.store)
                    self.replay.events.append({"kind": "merge", "trace": step["trace"], "branch": ev["branch"]})
            self.workflow(self.sc["trace"])
        if self.data_errors:
            raise ScenarioDataError(f"the scenario is incomplete for the path the replay took: {self.data_errors}")
        self.replay.judge_calls = list(self.judge.calls)
        self.replay.final_main = self.repo.tree("main")
        self.replay.store = self.store
        self.replay.commits = self.repo.commits
        return self.replay

    def workflow(self, trace: str) -> None:
        """workflows/main_orchestrator.yaml routing: developer -> QA (check_qa_status) -> release -> deploy
        (check_deploy_status, check_tf_remediation). The gatekeeper step is not replayed (it verifies the commit)."""
        queue = list(self.sc.get("generations") or [])
        retry, tf_retry = 0, 0
        tf_context, tf_report = None, None
        while True:
            ev = self.developer(trace, retry=retry, drafts=queue, tf_retry=tf_retry, tf_context=tf_context,
                                tf_report=tf_report)
            queue = list(self._draft_queue)
            if "error" in ev:
                return self._stop("developer", ev["error"])
            qa = self.qa(trace, ev["branch"], ev["commit_sha"], retry)
            if "error" in qa:      # route_qa_unavailable: not retried
                return self._stop("qa", qa["error"])
            if qa["passed"]:
                self.repo.merge(ev["branch"], self.store)
                self.replay.events.append({"kind": "merge", "trace": trace, "branch": ev["branch"]})
                deploy = self.sc.get("deploy")
                if not deploy:
                    return self._finish("SUCCESS", stage="release")
                res, route_record = self._deploy_result(trace, tf_retry)
                self.replay.events.append({"kind": "deploy", "tf_retry": tf_retry, "status": res.get("status"),
                                           "error_class": res.get("error_class"),
                                           "route": (route_record or {}).get("owner")})
                if res.get("status") == "SUCCESS":
                    return self._finish("SUCCESS", stage="deploy")
                cls = res.get("error_class") or ""
                from gate_errors import NON_REMEDIABLE_DEPLOY_CLASSES
                if cls in NON_REMEDIABLE_DEPLOY_CLASSES or res.get("operator_required") is True:
                    return self._stop("deploy", {"type": "operator_deploy_failure", "error_class": cls or None,
                                                 "reason": cls or "operator_required", "typed": True})
                if cls in ("IAC_DEFECT", "") and tf_retry < self.limits["max_tf_retries"]:
                    tf_retry += 1
                    tf_context = res.get("error") or "Terraform deployment validation failed"
                    tf_report = res.get("validation_report")
                    continue
                return self._stop("deploy", {"type": "deploy_failure", "error_class": cls or None,
                                             "reason": "TF_RETRIES_EXHAUSTED", "typed": bool(cls)})
            if qa.get("error_class") == "CODE_DEFECT" and qa.get("retryable") is True \
                    and retry < self.limits["max_retries"]:
                retry += 1
                tf_context, tf_report = None, None   # increment_qa_retry nulls the report
                continue
            return self._stop("qa", {"type": "qa_exhausted", "error_class": qa.get("error_class"),
                                     "reason": qa.get("reason"), "typed": True})

    def _route_and_record(self, trace: str, result: Dict[str, Any], engine_plan_stream: Optional[str],
                          pre_router: bool = False) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
        """The server's routing of one failed (or successful) deploy result, and the run's terraform stage as the
        callback scope and the server's route write leave it (replaced per deploy: a route never describes an earlier
        failure)."""
        if pre_router:
            res, route_record = copy.deepcopy(result), None
        else:
            out = route_on_server(result, engine_plan_stream, sorted(self.repo.tree("main")), trace)
            res, route_record = out["result"], out["route_record"]
        stage = {"status": res.get("status"), "error_class": res.get("error_class"),
                 "operator_required": res.get("operator_required")}
        if route_record is not None:
            stage["failure_route"] = route_record
        self.store.collection("pipeline_executions").document(trace).update({"stages.terraform": stage})
        return res, route_record

    def _deploy_result(self, trace: str, tf_retry: int) -> Tuple[Dict[str, Any], Optional[Dict[str, Any]]]:
        """(the result the terraform server sends, the route record it writes on the run). The deploy's engine run is
        recorded (`deploy.attempts[n]`: the result before routing and the read-only re-plan's `plan -json` stream);
        the server's own routing code runs on it in a child process (tests/scenario_tf_route_child.py). A scenario
        with `deploy.server: "pre-router"` replays a server older than the gateway: the recorded result, no route."""
        deploy = self.sc["deploy"]
        attempts = deploy["attempts"]
        attempt = copy.deepcopy(attempts[min(tf_retry, len(attempts) - 1)])
        return self._route_and_record(trace, attempt["result"], attempt.get("engine_plan_stream"),
                                      pre_router=deploy.get("server", "current") == "pre-router")

    def _finish(self, status: str, **kw: Any) -> None:
        self.replay.outcome = dict({"status": status}, **kw)

    def _stop(self, stage: str, error: Dict[str, Any]) -> None:
        self.replay.outcome = {"status": "STOPPED", "stage": stage, **error}


def route_on_server(result: Dict[str, Any], engine_plan_stream: Optional[str], manifest: List[str],
                    trace: str) -> Dict[str, Any]:
    """The terraform server's failed-deploy routing (tests/scenario_tf_route_child.py, its own process: the server
    ships its own `shared/` package). {"router": bool, "result", "route_record"}."""
    import subprocess
    child = os.path.join(TESTS_DIR, "scenario_tf_route_child.py")
    req = json.dumps({"result": result, "engine_plan_stream": engine_plan_stream, "manifest": manifest,
                      "trace_id": trace})
    proc = subprocess.run([sys.executable, child], input=req, capture_output=True, text=True, timeout=120,
                          env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    if proc.returncode != 0:
        raise ScenarioDataError(f"terraform server routing child failed ({proc.returncode}): {proc.stderr[-2000:]}")
    return json.loads(proc.stdout.strip().splitlines()[-1])


def _typed_error(e: Exception) -> Dict[str, Any]:
    cls = getattr(e, "error_class", None)
    cls = getattr(cls, "value", cls)
    reason = getattr(e, "reason", None)
    if reason is None and getattr(e, "report", None) is not None:
        diags = getattr(e.report, "diagnostics", None) or []
        reason = diags[0].code if diags else None
    return {"type": type(e).__name__, "error_class": cls, "reason": reason, "typed": isinstance(cls, str),
            "message": str(getattr(e, "message", e))[:300]}


def run_scenario(scenario: Dict[str, Any], monkeypatch: Any) -> Replay:
    return ScenarioRunner(scenario, monkeypatch).run()


# ------------------------------------------------------------------------------------------------ expectations
def _contains(haystack: Any, needle: str) -> bool:
    if isinstance(haystack, str):
        return haystack == needle
    if isinstance(haystack, dict):
        return any(_contains(v, needle) for v in haystack.values())
    if isinstance(haystack, (list, tuple)):
        return any(_contains(v, needle) for v in haystack)
    return False


def _qa_record(replay: Replay, trace: str) -> Dict[str, Any]:
    runs = replay.qa_runs(trace)
    return (runs[-1].get("record") or {}) if runs else {}


def _outcome_matches(replay: Replay, want: Dict[str, Any], trace: str) -> List[str]:
    """Problems with one outcome alternative (empty = it holds). Every count is on the scenario's own trace."""
    out = replay.outcome
    dispatches = replay.dispatches(trace)
    qa_runs = replay.qa_runs(trace)
    generations = len([d for d in dispatches if d.get("generated")])
    plan_reasons = [(d.get("qa_plan") or {}).get("reason") for d in dispatches]
    checks = {
        "status": lambda v: out.get("status") == v or f"status {out.get('status')!r} != {v!r}",
        "status_not": lambda v: out.get("status") != v or f"status is {v!r}",
        "stage": lambda v: out.get("stage") == v or f"stage {out.get('stage')!r} != {v!r}",
        "error_class": lambda v: out.get("error_class") == v or f"error_class {out.get('error_class')!r} != {v!r}",
        "error_class_in": lambda v: out.get("error_class") in v or f"error_class {out.get('error_class')!r} not in {v}",
        # a typed stop's reason, or the reason of the last developer plan of a stopped run
        "reason": lambda v: (out.get("reason") == v or (out.get("status") == "STOPPED" and bool(plan_reasons)
                                                         and plan_reasons[-1] == v))
        or f"reason {out.get('reason')!r} != {v!r}",
        "qa_attempts": lambda v: len(qa_runs) == v or f"QA attempts {len(qa_runs)} != {v}",
        "max_qa_attempts": lambda v: len(qa_runs) <= v or f"QA attempts {len(qa_runs)} > {v}",
        "max_generations": lambda v: generations <= v or f"generations {generations} > {v}",
        "developer_dispatches": lambda v: len(dispatches) == v or f"developer dispatches {len(dispatches)} != {v}",
        "main_lacks": lambda v: all(p not in replay.final_main for p in v)
        or f"main still has {[p for p in v if p in replay.final_main]}",
        "judge_model_stamped": lambda v: _contains(_qa_record(replay, trace), v)
        or f"judge model {v!r} not in the QA record",
        "qa_record_mentions": lambda v: _contains_substring(_qa_record(replay, trace), v)
        or f"QA record never mentions {v!r}",
        "seed_files_include": lambda v: all(any(s.get("file") == f for d in dispatches
                                                for s in (d.get("qa_plan") or {}).get("seeds") or []) for f in v)
        or f"no developer repair seed on {v}",
    }
    problems: List[str] = []
    for key, value in want.items():
        if key not in checks:
            raise ScenarioDataError(f"unknown expectation key {key!r}")
        got = checks[key](value)
        if got is not True:
            problems.append(str(got))
    return problems


def _contains_substring(haystack: Any, needle: str) -> bool:
    if isinstance(haystack, str):
        return needle in haystack
    if isinstance(haystack, dict):
        return any(_contains_substring(v, needle) for v in haystack.values())
    if isinstance(haystack, (list, tuple)):
        return any(_contains_substring(v, needle) for v in haystack)
    return False


def _executed(plan: Any) -> bool:
    """A developer plan that was carried out: not one the dispatch stopped on (QA-FINDING-ON-UNOWNED-FILE persists the
    REGENERATE plan with its `unowned_check` verdict STOP before it raises)."""
    check = plan.get("unowned_check") if isinstance(plan, dict) else None
    return not (isinstance(check, dict) and check.get("verdict") == "STOP")


def _platform_rendered(tree: Dict[str, str]) -> set:
    from qa_auditor.judge_input import platform_rendered_paths
    return set(platform_rendered_paths(tree))


def invariant_problems(replay: Replay, scenario: Dict[str, Any]) -> List[str]:
    """Mechanism-level rules every scenario must satisfy (whatever its specific outcome):
    I1 fail loudly: the run ends SUCCESS or with a typed stop (a class, never an untyped exception);
    I2 bounded: at most max_retries + 1 QA attempts (a check of the workflow model: the YAML's own retry bound);
    I3 no futile regeneration: a QA retry regenerated (an executed plan) although every error finding names a file that
       is not a draft file of the tested build and came back byte-identical, AND either every such file is a platform
       render (`judge_input.platform_rendered_paths` of the tested tree: no regeneration can change it) or every such
       finding (code, file) already survived an earlier regeneration of this trace on the same bytes. A first
       regeneration for a finding on another unowned file is allowed (QA-FINDING-ON-UNOWNED-FILE RT R1: the next
       build may change the code it tests);
    I4 never a developer repair seed on a platform-owned path: the scenario's `platform_owned_paths` plus the platform
       renders of the tested tree (`platform_rendered_paths`);
    I5 every judge call ends inside the Stage 2 time limit (coordinator.STAGE_TWO_DEADLINE_S, virtual clock)."""
    problems: List[str] = []
    out = replay.outcome
    if out.get("status") != "SUCCESS" and not out.get("typed"):
        problems.append(f"I1 untyped stop: {out}")
    limits = workflow_limits()
    if len(replay.qa_runs(scenario["trace"])) > limits["max_retries"] + 1:
        problems.append("I2 more QA attempts than max_retries + 1")
    qa_by_attempt = {q["attempt"]: q for q in replay.qa_runs(scenario["trace"])}
    declared = set(scenario.get("platform_owned_paths") or [])
    survived: Dict[Tuple[Any, str], str] = {}   # (code, file) -> bytes, of findings a regeneration did not change
    for d in replay.dispatches(scenario["trace"]):
        plan = d.get("qa_plan") or {}
        rec = (qa_by_attempt.get(d["retry"] - 1) or {}).get("record") or {} if d["retry"] > 0 else {}
        tested = replay.commits.get(rec.get("commit_sha") or "") or {}
        if plan.get("mode") == "REGENERATE" and d["retry"] > 0 and _executed(plan) and "error" not in d:
            after = replay.commits.get(d.get("commit_sha") or "")   # what the regeneration committed
            drafted = set(replay.drafts_by_sha.get(rec.get("commit_sha") or "") or [])
            found = [(x.get("code"), x.get("file")) for x in rec.get("diagnostics") or [] if x.get("severity") == "error"]
            files = [f for _c, f in found]
            unchanged = (after is not None and found and all(
                isinstance(f, str) and f in tested and tested[f] == after.get(f) and f not in drafted for f in files))
            if unchanged:
                rendered = _platform_rendered(tested)
                repeat = all(survived.get((c, f)) == tested[f] for c, f in found)
                if all(f in rendered for f in files) or repeat:
                    why = "platform render" if all(f in rendered for f in files) else "repeat after a regeneration"
                    problems.append(f"I3 futile regeneration at retry {d['retry']} ({plan.get('reason')}, {why}): "
                                    f"{sorted(set(files))} came back byte-identical")
                for c, f in found:
                    survived[(c, f)] = tested[f]
        owned = declared | (_platform_rendered(tested) if tested else set())
        for seed in plan.get("seeds") or []:
            if seed.get("file") in owned:
                problems.append(f"I4 developer repair seed on platform-owned {seed.get('file')}")
    import qa_auditor.coordinator as coord
    late = [c for c in replay.judge_calls if c["t_end"] - VirtualTime.BASE > coord.STAGE_TWO_DEADLINE_S + 1e-6]
    if late:
        problems.append(f"I5 {len(late)} judge call(s) ran past the Stage 2 time limit "
                        f"({coord.STAGE_TWO_DEADLINE_S:.0f} s)")
    return problems


def check_expectations(replay: Replay, scenario: Dict[str, Any]) -> List[str]:
    """Every invariant + one of the expected outcomes + the `never_*` rules. `known_violations` {"I3": "<row>: why"}
    is a strict, per-invariant pending marker for a scenario whose outcome already holds on main: the named
    invariant must still be violated (when the fix lands it is not, and the marker must be removed)."""
    expect = scenario["expect"]
    problems = invariant_problems(replay, scenario)
    for inv, why in (expect.get("known_violations") or {}).items():
        hit = [p for p in problems if p.startswith(inv + " ")]
        if not hit:
            problems.append(f"known violation {inv} ({why}) no longer occurs: remove it from the scenario")
        problems = [p for p in problems if not p.startswith(inv + " ")]
    alternatives = expect.get("any_of") or [expect.get("outcome") or {}]
    alt_problems = [_outcome_matches(replay, alt, scenario["trace"]) for alt in alternatives]
    if all(alt_problems):
        problems.append("no expected outcome holds: " + " | ".join("; ".join(p) for p in alt_problems))
    for reason in expect.get("never_plan_reasons") or []:
        hits = [d["retry"] for d in replay.dispatches(scenario["trace"])
                if (d.get("qa_plan") or {}).get("reason") == reason and _executed(d.get("qa_plan") or {})
                and "error" not in d]
        if hits:
            problems.append(f"plan reason {reason} at retries {hits}")
    for path in expect.get("never_seed_files") or []:
        hits = [d["retry"] for d in replay.dispatches(scenario["trace"])
                if any(s.get("file") == path for s in (d.get("qa_plan") or {}).get("seeds") or [])]
        if hits:
            problems.append(f"developer repair seed on {path} at retries {hits}")
    return problems


def pending_route_problems(replay: Replay, scenario: Dict[str, Any]) -> List[str]:
    """A pending scenario's `xfail.current` (outcome keys): the route main takes before the named fix. [] = unchanged."""
    current = (scenario.get("xfail") or {}).get("current")
    if not current:
        return []
    return _outcome_matches(replay, current, scenario["trace"])


def summarize(replay: Replay) -> str:
    rows = []
    for e in replay.events:
        if e["kind"] == "developer":
            plan = e.get("qa_plan") or {}
            dplan = e.get("deploy_plan") or {}
            if dplan:
                plan = {"mode": dplan.get("mode"), "reason": dplan.get("reason")}
            rows.append(f"dev[{e['trace']} r{e['retry']} tf{e['tf_retry']}] plan={plan.get('mode')}/{plan.get('reason')} "
                        f"seeds={[s.get('file') for s in plan.get('seeds') or []]} gen={e.get('generated')} "
                        f"orphans={e.get('app_orphans')}:{e.get('orphans_deleted')} err={e.get('error')}")
        elif e["kind"] == "qa":
            rows.append(f"qa[{e['attempt']}] passed={e.get('passed')} class={e.get('error_class')} "
                        f"reason={e.get('reason')} diags={e.get('diagnostics')} err={e.get('error')}")
        else:
            rows.append(f"{e['kind']} {({k: v for k, v in e.items() if k != 'kind'})}")
    for c in replay.judge_calls:
        rows.append(f"judge[{c['attempt']}] {c['lens']} {c['model']} {c['outcome']} "
                    f"t={c['t_start'] - VirtualTime.BASE:.0f}..{c['t_end'] - VirtualTime.BASE:.0f} "
                    f"box={c.get('box_s')}")
    rows.append(f"OUTCOME {replay.outcome}")
    return "\n".join(rows)
