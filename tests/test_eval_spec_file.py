"""FD-4BN Phase 0: `run_examples.py --spec-file` (plan test-workload-dry-run-plan.md §12.1, §12.4).

Offline and hermetic: argument handling runs in-process (no child, no token, nothing downloaded); the end-to-end
cases run the real pipeline in the harness's guarded child against the synthetic backend (no LLM, no network, no
credentials), as tests/test_eval_e2e.py does. The e2e case also proves the "creates nothing" guarantee for a spec run:
the only outbound attempts are refused client constructors and the loopback compliance URL; no process, socket, gRPC
channel, VCS call or cloud client ever succeeds."""
import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)

import functools
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
EVAL = ROOT / "eval"
sys.path.insert(0, str(EVAL))

import run_examples  # noqa: E402

EXAMPLE_01 = ROOT / "documentation" / "examples" / "01-cloudrun-pubsub-event-router.md"
XSS = '<script>alert(1)</script> "><img src=x onerror=alert(1)> javascript:alert(1) </style><b>x</b>'


def _parse(*argv):
    return run_examples.build_parser().parse_args(["--llm", "synthetic", "--model", "gemini-3.8-flash", *argv])


def _spec(tmp_path, text="# Spec\n\nA tiny Cloud Run service.\n", name="spec.md", raw=None):
    p = tmp_path / name
    if raw is not None:
        p.write_bytes(raw)
    else:
        p.write_text(text, encoding="utf-8")
    return p


def _entry(path):
    """A --spec-file catalog entry exactly as Invocation builds it (path, sha256 of the bytes, product id)."""
    return run_examples.spec_catalog_entry(str(path), None)


# ------------------------------------------------------------------------------------ selection and refusals
def test_default_examples_resolution_selects_the_same_jobs_as_before():
    """Changing --examples to default=None must not change any existing invocation's job list."""
    implicit = run_examples.Invocation(_parse())
    explicit = run_examples.Invocation(_parse("--examples", "01-09"))
    assert implicit.a.examples == run_examples.DEFAULT_EXAMPLES == "01-09"
    assert [e["id"] for e in implicit.examples] == [e["id"] for e in explicit.examples] == [
        f"{i:02d}" for i in range(1, 10)]
    assert implicit.examples == explicit.examples
    assert implicit.spec_entry is None
    one = run_examples.Invocation(_parse("--examples", "03"))
    assert [e["id"] for e in one.examples] == ["03"]
    assert run_examples.Invocation(_parse()).manifest([])["spec_source"] == "catalog"


def test_spec_file_and_examples_are_exclusive(tmp_path):
    with pytest.raises(SystemExit, match="--spec-file and --examples are exclusive"):
        run_examples.Invocation(_parse("--spec-file", str(_spec(tmp_path)), "--examples", "01"))


def test_product_id_needs_spec_file():
    with pytest.raises(SystemExit, match="--product-id only applies with --spec-file"):
        run_examples.Invocation(_parse("--product-id", "my-product-1"))


@pytest.mark.parametrize("extra,msg", [
    (["--baseline"], "--spec-file refuses --baseline"),
    (["--examples-sha", "44a2747"], "--spec-file refuses --examples-sha"),
])
def test_preflight_refuses_baseline_and_examples_sha(tmp_path, extra, msg):
    inv = run_examples.Invocation(_parse("--spec-file", str(_spec(tmp_path)), *extra))
    with pytest.raises(SystemExit, match=msg):
        inv.preflight()


def test_preflight_keeps_refusing_bypass_healers_outside_replay(tmp_path):
    inv = run_examples.Invocation(_parse("--spec-file", str(_spec(tmp_path)), "--bypass-healers", "HB-03"))
    with pytest.raises(SystemExit, match="--bypass-healers is defined on replayed LLM output only"):
        inv.preflight()


@pytest.mark.parametrize("kind,msg", [
    ("empty", "empty"),
    ("whitespace", "empty"),
    ("too_big", "exceeds the 200 KB limit"),
    ("not_utf8", "not valid UTF-8"),
    ("directory", "not a regular file"),
    ("missing", "not a regular file"),
])
def test_spec_file_checks_run_before_any_spend(tmp_path, kind, msg):
    if kind == "empty":
        p = _spec(tmp_path, raw=b"")
    elif kind == "whitespace":
        p = _spec(tmp_path, raw=b" \n\t\n")
    elif kind == "too_big":
        p = _spec(tmp_path, raw=b"a" * (200 * 1024 + 1))
    elif kind == "not_utf8":
        p = _spec(tmp_path, raw=b"# spec\n\xff\xfe broken")
    elif kind == "directory":
        p = tmp_path / "adir"
        p.mkdir()
    else:
        p = tmp_path / "nope.md"
    with pytest.raises(SystemExit, match=msg):
        run_examples.Invocation(_parse("--spec-file", str(p)))


def test_spec_file_at_exactly_the_limit_is_accepted(tmp_path):
    p = _spec(tmp_path, raw=b"a" * (200 * 1024))
    assert run_examples.Invocation(_parse("--spec-file", str(p))).spec_entry["id"] == "spec"


@pytest.mark.parametrize("pid", ["Upper-case1", "1starts-digit", "ends-with-", "short", "a" * 31, "has_underscore",
                                 "has.dot.xx", "", "spa ce-xx"])
def test_bad_product_id_is_refused(tmp_path, pid):
    with pytest.raises(SystemExit):
        run_examples.Invocation(_parse("--spec-file", str(_spec(tmp_path)), "--product-id", pid))


@pytest.mark.parametrize("pid", ["my-app", "test-01-event-router", "a" * 30, "abcde1"])
def test_good_product_id_is_kept(tmp_path, pid):
    inv = run_examples.Invocation(_parse("--spec-file", str(_spec(tmp_path)), "--product-id", pid))
    assert inv.spec_entry["product_id"] == pid


def test_synthetic_entry_key_product_id_and_manifest(tmp_path):
    text = "# My spec\n\nA queue worker.\n"
    p = _spec(tmp_path, text)
    sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    inv = run_examples.Invocation(_parse("--spec-file", str(p), "--out", str(tmp_path / "res"), "--out-id", "x"))
    inv.preflight()
    (ex,) = inv.examples
    assert ex == {"id": "spec", "file": None, "spec_path": str(p.resolve()), "spec_sha256": sha,
                  "product_id": "dryrun-" + sha[:8]}
    jobs = [(e, n) for e in inv.examples for n in range(1, inv.a.runs + 1)]
    assert [f"{e['id']}-r{n}" for e, n in jobs][:1] == ["spec-r1"]
    m = inv.manifest([])
    assert m["spec_source"] == "file" and m["spec_sha256"] == sha and m["product_id"] == "dryrun-" + sha[:8]
    assert m["examples"] == ["spec"]
    blob = json.dumps(m, default=str)
    assert str(p) not in blob and str(p.resolve()) not in blob and "queue worker" not in blob


def test_relative_spec_file_is_made_absolute(tmp_path, monkeypatch):
    _spec(tmp_path, name="rel.md")
    monkeypatch.chdir(tmp_path)
    a = run_examples.absolutize_paths(_parse("--spec-file", "rel.md"))
    assert a.spec_file == str((tmp_path / "rel.md").resolve())


def test_spec_text_reads_the_file_in_both_modes(tmp_path):
    full = "# Title\n\nIntro.\n\n## Form Submission Prompt\n\nBuild a thing.\nWith two lines.\n\n## Other\n\nx\n"
    ex = _entry(_spec(tmp_path, full))
    assert run_examples.spec_text(ex, "full") == full
    assert run_examples.spec_text(ex, "form-prompt") == "Build a thing.\nWith two lines.\n"
    plain = _entry(_spec(tmp_path, "# no section\n", name="b.md"))
    with pytest.raises(SystemExit, match="no 'Form Submission Prompt' section"):
        run_examples.spec_text(plain, "form-prompt")


def test_resolve_spec_sends_the_file_and_fails_closed_on_a_changed_recording(tmp_path):
    text = "# spec v2\n"
    ex = _entry(_spec(tmp_path, text))
    rec = run_examples.resolve_spec(ex, "full", None, "synthetic", {})
    assert rec["text"] == text and rec["source"] == "spec_file" and rec["match"] is None
    # a recording of this same file replays; a recording of different text is a mismatch (replay-strict refuses)
    same = run_examples.resolve_spec(ex, "full", None, "replay-strict",
                                     {"spec_text": "IGNORED", "spec_sha256": run_examples.sha256_text(text)})
    assert same["text"] == text and same["match"] is True
    other = run_examples.resolve_spec(ex, "full", None, "replay-strict",
                                      {"spec_text": "# spec v1\n", "spec_sha256": run_examples.sha256_text("# spec v1\n")})
    assert other["text"] == text and other["match"] is False


# RT fix 1: a spec-file replay whose recording has no spec hash cannot prove it is a recording of this file
@pytest.mark.parametrize("llm", ["replay-strict", "replay-then-live"])
@pytest.mark.parametrize("meta", [{}, {"spec_text": "# a different spec\n"}, {"spec_sha256": None}])
def test_spec_file_replay_without_a_recorded_hash_is_a_mismatch(tmp_path, llm, meta):
    ex = _entry(_spec(tmp_path, "# spec\n"))
    r = run_examples.resolve_spec(ex, "full", None, llm, dict(meta))
    assert r["match"] is False and r["recorded_spec_sha256"] is None and r["source"] == "spec_file"
    assert r["text"] == "# spec\n"  # still the operator's file, never the recorded text


def test_catalog_replay_without_a_recorded_hash_is_unchanged():
    """Fix 1 is limited to the spec_path branch: a catalog replay with no hash and no pin stays match=None."""
    ex = {"id": "01", "file": "01-cloudrun-pubsub-event-router.md"}
    r = run_examples.resolve_spec(ex, "full", None, "replay-strict", {"spec_text": "# recorded\n"})
    assert r["source"] == "cassette_meta" and r["match"] is None


def _replay_inv(tmp_path, llm, meta, spec_text="# spec\n", monkeypatch=None):
    spec = _spec(tmp_path, spec_text)
    cas = tmp_path / "cas"
    cas.mkdir(exist_ok=True)
    (cas / "spec-r1.jsonl").write_text(json.dumps(meta) + "\n")
    inv = run_examples.Invocation(_parse_mode(llm, "--spec-file", str(spec), "--cassettes", str(cas),
                                              "--out", str(tmp_path / "res"), "--out-id", "rp"))
    minted = []

    def no_mint(*a, **k):
        minted.append(1)
        raise AssertionError("a refused replay must never mint a token")

    def no_popen(cmd, **kw):
        raise AssertionError("a refused replay must never launch the child")
    monkeypatch.setattr(run_examples, "mint_access_token", no_mint)
    monkeypatch.setattr(run_examples.subprocess, "Popen", no_popen)
    inv.ledger.admit = lambda *a, **k: 1.0  # replay-then-live is a live mode: admission is not under test here
    return inv, minted


def _parse_mode(llm, *argv):
    return run_examples.build_parser().parse_args(["--llm", llm, "--model", "gemini-3.8-flash", *argv])


@pytest.mark.parametrize("llm", ["replay-strict", "replay-then-live"])
@pytest.mark.parametrize("meta_kind", ["no_hash", "text_only", "other_hash"])
def test_spec_file_replay_mismatch_is_refused_before_launch_and_before_any_token(tmp_path, monkeypatch, llm,
                                                                                 meta_kind):
    """RT fixes 1 + 2: missing or different recorded hash -> replay_spec_mismatch in BOTH replay modes."""
    meta = {"no_hash": {"frozen_now": "2026-10-12T00:00:00Z"},
            "text_only": {"spec_text": "# other\n"},
            "other_hash": {"spec_text": "# other\n", "spec_sha256": run_examples.sha256_text("# other\n")}}[meta_kind]
    inv, minted = _replay_inv(tmp_path, llm, meta, monkeypatch=monkeypatch)
    rec = inv.run_one(inv.examples[0], 1, [])
    assert rec["result"]["invalid_reasons"] == ["replay_spec_mismatch"] and rec["result"]["valid_run"] is False
    assert rec["result"]["spec_provenance"]["match"] is False and minted == []
    assert not (Path(rec["run_dir"]) / "child_config.json").exists()


def test_catalog_replay_then_live_with_a_mismatch_still_proceeds(tmp_path, monkeypatch):
    """Fix 2 is limited to --spec-file runs: a catalog replay-then-live keeps its old behaviour (reaches launch)."""
    cas = tmp_path / "cas"
    cas.mkdir()
    (cas / "01-r1.jsonl").write_text(json.dumps({"spec_text": "# x\n", "spec_sha256": "0" * 64}) + "\n")
    inv = run_examples.Invocation(_parse_mode("replay-then-live", "--examples", "01", "--cassettes", str(cas),
                                              "--out", str(tmp_path / "res"), "--out-id", "cat"))
    inv.ledger.admit = lambda *a, **k: 1.0

    class Reached(Exception):
        pass

    def mint(*a, **k):
        raise Reached()
    monkeypatch.setattr(run_examples, "mint_access_token", mint)
    with pytest.raises(Reached):
        inv.run_one(inv.examples[0], 1, [])


# RT fix 7: read once; the bytes hashed are the bytes sent; a file changed after start is refused
def test_crlf_spec_hash_is_the_same_in_the_manifest_and_the_run_provenance(tmp_path):
    raw = b"# CRLF spec\r\n\r\nA tiny Cloud Run service.\r\n"
    p = _spec(tmp_path, raw=raw)
    inv = run_examples.Invocation(_parse("--spec-file", str(p)))
    sha = hashlib.sha256(raw).hexdigest()
    assert inv.spec_entry["spec_sha256"] == sha
    r = run_examples.resolve_spec(inv.spec_entry, "full", None, "synthetic", {})
    assert r["spec_sha256"] == sha and r["text"] == raw.decode("utf-8")


def test_crlf_spec_reaches_the_child_byte_for_byte(tmp_path, monkeypatch):
    raw = b"# CRLF spec\r\n\r\nA tiny Cloud Run service.\r\n"
    p = _spec(tmp_path, raw=raw)
    monkeypatch.setattr(run_examples.subprocess, "Popen", lambda cmd, **kw: _NoChild(cmd, **kw))
    _NoChild.launched.clear()
    inv = run_examples.Invocation(_parse("--spec-file", str(p), "--out", str(tmp_path / "res"), "--out-id", "c"))
    rec = inv.run_one(inv.examples[0], 1, [])
    sent = Path(rec["run_dir"]) / "spec.md"
    assert sent.read_bytes() == raw
    # the child reads spec.md without newline translation (run_child.read_spec), so it sends the hashed bytes
    sys.path.insert(0, str(EVAL))
    import run_child  # noqa: E402
    assert run_child.read_spec(str(sent)) == raw.decode("utf-8")


def test_spec_file_changed_after_start_is_refused(tmp_path):
    p = _spec(tmp_path, "# v1\n")
    inv = run_examples.Invocation(_parse("--spec-file", str(p)))
    p.write_text("# v2, edited while the harness ran\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="--spec-file changed since start"):
        run_examples.resolve_spec(inv.spec_entry, "full", None, "synthetic", {})


# RT fix 9: write_report survives lone surrogates and never leaves a temp file
def _report_records(tmp_path, error):
    rd = tmp_path / "runs" / "spec-r1"
    rd.mkdir(parents=True)
    result = {"example": "spec", "run": 1, "valid_run": True, "invalid_reasons": [],
              "pipeline_outcome": "generation_error", "stages": {"architect": {"ok": False, "error": error}}}
    return [{"key": "spec-r1", "result": result, "score": None, "run_dir": str(rd)}]


def test_write_report_replaces_lone_surrogates_and_leaves_no_temp_file(tmp_path):
    from stackvend_eval import metrics
    out = tmp_path / "res"
    out.mkdir()
    recs = _report_records(out, "ValueError: " + json.loads('"\\ud800"') + " <b>x</b>")
    summary = metrics.aggregate(recs)
    summary["manifest"] = {"llm_mode": "synthetic"}
    dest = run_examples.write_report(out, summary, recs)
    page = dest.read_text(encoding="utf-8")
    # the UTF-8 encoder's errors="replace" writes "?" for the unencodable code point; the page stays escaped
    assert "ValueError: ? &lt;b&gt;x&lt;/b&gt;" in page
    assert not list(out.glob(".report-*"))


def test_write_report_removes_the_temp_file_when_replace_fails(tmp_path, monkeypatch):
    from stackvend_eval import metrics
    out = tmp_path / "res"
    out.mkdir()
    recs = _report_records(out, "boom")
    summary = metrics.aggregate(recs)
    summary["manifest"] = {"llm_mode": "synthetic"}

    def bad_replace(src, dst):
        raise OSError("disk full")
    monkeypatch.setattr(run_examples.os, "replace", bad_replace)
    with pytest.raises(OSError, match="disk full"):
        run_examples.write_report(out, summary, recs)
    assert not list(out.glob(".report-*")) and not (out / "report.html").exists()


# RT fix 10 (mutant M17): the committed-file listing only follows hex ids
def _tree_dir(tmp_path, files):
    import hashlib as _h
    rd = tmp_path / "run"
    (rd / "trees").mkdir(parents=True)
    manifest = {}
    for name, content in files.items():
        if isinstance(content, bytes):
            h = _h.sha256(content).hexdigest()
            (rd / "blobs" / h[:2]).mkdir(parents=True, exist_ok=True)
            (rd / "blobs" / h[:2] / h).write_bytes(content)
            manifest[name] = h
        else:
            manifest[name] = content  # a hostile, non-hex blob reference
    tree = _h.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    (rd / "trees" / f"{tree}.json").write_text(json.dumps(manifest))
    return rd, tree


def _c3(tree):
    return {"checkpoints": {"C3_committed": {"tree": tree}}}


def test_c3_file_listing_reads_names_and_sizes(tmp_path):
    rd, tree = _tree_dir(tmp_path, {"main.py": b"abc", "infra/workload/main.tf": b"x" * 10})
    assert run_examples.c3_file_listing(rd, _c3(tree)) == [{"name": "infra/workload/main.tf", "bytes": 10},
                                                          {"name": "main.py", "bytes": 3}]


@pytest.mark.parametrize("tree", ["../x", "../" + "a" * 61, "A" * 64, "a" * 63, None, 7, ""])
def test_c3_file_listing_refuses_a_non_hex_tree_id(tmp_path, tree):
    rd, _ = _tree_dir(tmp_path, {"main.py": b"abc"})
    # manifests that trees/<id>.json would reach by traversal (or by a wrong-length / upper-case id) if the id were
    # not checked: each must be ignored
    for planted in ("x", "a" * 61):
        (rd / f"{planted}.json").write_text(json.dumps({"stolen.py": "0" * 64}))
    for planted in ("A" * 64, "a" * 63):
        (rd / "trees" / f"{planted}.json").write_text(json.dumps({"stolen.py": "0" * 64}))
    assert run_examples.c3_file_listing(rd, _c3(tree)) is None


def test_c3_file_listing_never_follows_a_non_hex_blob_hash(tmp_path):
    rd, tree = _tree_dir(tmp_path, {"ok.py": b"abc", "evil.py": "../x", '<script>alert(1)</script>.tf': b"1"})
    # blobs/<h[:2]>/<h> with h="../x" is run/blobs/../../x == tmp_path/x: plant it, it must never be stat'ed
    (tmp_path / "x").write_bytes(b"outside the blob store")
    listing = run_examples.c3_file_listing(rd, _c3(tree))
    assert {"name": "evil.py", "bytes": None} in listing and {"name": "ok.py", "bytes": 3} in listing
    from stackvend_eval import report
    rec = {"key": "spec-r1", "run_dir": str(rd), "c3_files": listing,
           "result": {"example": "spec", "run": 1, "valid_run": True, "invalid_reasons": [],
                      "pipeline_outcome": "committed_passed", "stages": {"developer": {"ok": True}}}}
    page = report.render({"manifest": {"llm_mode": "synthetic"}}, [rec])
    assert "&lt;script&gt;alert(1)&lt;/script&gt;.tf" in page and "<script" not in page.lower()


def test_report_flag_defaults_to_none():
    assert _parse().report == "none"


# ------------------------------------------------------- parent side of a spec run: no token, no credentials
class _NoChild:
    launched = []

    def __init__(self, cmd, **kwargs):
        _NoChild.launched.append({"cmd": cmd, "env": kwargs.get("env"), "stdin": None})
        self.stdin = self
        self.returncode = None
        self._data = ""

    def write(self, s):
        self._data += s
        _NoChild.launched[-1]["stdin"] = self._data

    def close(self):
        pass

    def wait(self, timeout=None):
        self.returncode = 0
        return 0

    def kill(self):
        pass


def test_spec_run_parent_mints_no_token_and_hands_the_child_no_credentials(tmp_path, monkeypatch):
    real_popen = run_examples.subprocess.Popen

    def popen(cmd, **kw):
        return _NoChild(cmd, **kw) if any(str(c).endswith("run_child.py") for c in cmd) else real_popen(cmd, **kw)

    def no_mint(*a, **k):
        raise AssertionError("a synthetic spec run must never mint a token")
    monkeypatch.setattr(run_examples.subprocess, "Popen", popen)
    monkeypatch.setattr(run_examples, "mint_access_token", no_mint)
    _NoChild.launched.clear()
    inv = run_examples.Invocation(_parse("--spec-file", str(_spec(tmp_path)), "--out", str(tmp_path / "res"),
                                         "--out-id", "p"))
    inv.preflight()
    rec = inv.run_one(inv.examples[0], 1, [])
    assert rec["key"] == "spec-r1"
    (launch,) = _NoChild.launched
    assert launch["cmd"][1:3] == ["-I", "-B"] and launch["stdin"] in (None, "")
    env = launch["env"]
    assert env["GOOGLE_APPLICATION_CREDENTIALS"] == "/nonexistent/adc-disabled.json" and env["PROJECT_ID"] == ""
    assert not any(k in env for k in ("GOOGLE_CLOUD_PROJECT", "GCP_PROJECT", "GITHUB_TOKEN", "GOOGLE_API_KEY"))
    cfg = json.loads((Path(rec["run_dir"]) / "child_config.json").read_text())
    assert cfg["vertex_project"] == "" and cfg["llm_mode"] == "synthetic" and cfg["example"] == "spec"
    assert cfg["product_id"] == inv.spec_entry["product_id"]
    assert (Path(rec["run_dir"]) / "spec.md").read_text() == _spec(tmp_path).read_text()


# ------------------------------------------------------------------------------ end to end (synthetic, guarded)
@functools.lru_cache(maxsize=1)
def _missing_product_deps():
    from stackvend_eval import paths
    rep = paths.probe_child_deps(ROOT, env=hermetic_guard.child_env())
    return paths.missing_deps_message(rep, ROOT) if rep["missing"] else ""


def _require_product_deps():
    """The child cannot run the product without its Step 1 requirements. tests/test_eval_product_deps.py is the one
    test that FAILS for that (by name); the runs here skip instead of failing as unrelated generation_errors."""
    msg = _missing_product_deps()
    if msg:
        pytest.skip(f"see the failing tests/test_eval_product_deps.py: {msg}")


def _harness(tmp_path, out_id, *args):
    _require_product_deps()
    cmd = [sys.executable, str(EVAL / "run_examples.py"), "--runs", "1", "--model", "gemini-3.8-flash",
           "--out", str(tmp_path / "res"), "--out-id", out_id, *args]
    env = hermetic_guard.child_env(
        drop=tuple(k for k in os.environ if k.startswith(("GOOGLE_", "CLOUDSDK")) or k == "STACKVEND_EVAL_VERTEX_PROJECT"),
        extra={"GOOGLE_APPLICATION_CREDENTIALS": "/nonexistent/adc-disabled.json"})
    r = subprocess.run(cmd, capture_output=True, text=True, env=env, cwd=str(ROOT), timeout=900)
    assert r.returncode == 0, r.stdout[-3000:] + r.stderr[-3000:]
    return tmp_path / "res" / out_id


# The only outbound attempts a synthetic run makes after the canary: client constructors the guard refuses before
# any RPC can exist (Vertex SDK init, a Firestore client), and the loopback compliance URL. Each is refused.
EXPECTED_REFUSED = {"google.cloud.aiplatform.initializer._Config.init",
                    "google.cloud.firestore_v1.base_client.BaseClient.__init__", "127.0.0.1"}
REQUIRED_GUARDS = {"process", "grpc", "sockets", "clients", "auth", "genai_sealed"}
MUTATION_PROBES = {"firestore_client", "storage_client", "pubsub_client", "secretmanager_client", "requests_github",
                   "socket_firestore_googleapis", "socket_metadata_server", "subprocess_run", "os_system",
                   "google_auth_default"}


@pytest.fixture(scope="module")
def spec_run(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("specrun")
    spec = tmp / "my-spec.md"
    spec.write_text(EXAMPLE_01.read_text(encoding="utf-8") + "\n\n## Notes\n\n" + XSS + "\n", encoding="utf-8")
    out = _harness(tmp, "spec", "--llm", "synthetic", "--spec-file", str(spec), "--skip-score", "--report", "html")
    return {"out": out, "spec": spec}


def test_spec_run_creates_nothing(spec_run):
    """The hard guarantee: a spec run makes zero successful mutating (or any outbound) calls."""
    r = json.loads((spec_run["out"] / "runs" / "spec-r1" / "result.json").read_text())
    assert r["valid_run"] is True and r["pipeline_outcome"] == "committed_passed", r.get("invalid_reasons")
    # Layer 2 was installed and proven effective before any product import
    assert r["canary"]["ok"] is True and REQUIRED_GUARDS <= set(r["canary"]["guards_installed"])
    probes = {p["probe"]: p["outcome"] for p in r["canary"]["probes"]}
    assert all(probes[p] in ("blocked", "library_absent") for p in MUTATION_PROBES), probes
    assert r["canary"]["env_problems"] == []
    # every LLM call was answered by the in-process synthetic backend: nothing was billed or sent anywhere
    assert r["llm"]["calls"] >= 1 and r["llm"]["served"]["backend"] == r["llm"]["calls"]
    # the commit was captured inside commit_and_open_pr before any VCS call; the token stub returned ""
    assert r["stages"]["precommit"]["status"] == "MOCK_COMMITTED"
    assert r["stages"]["precommit"]["capture_point"] == "commit_and_open_pr:fetch_github_token"
    post = [e for e in r["state"]["events"] if e["stage"] not in ("canary", "guard", "setup")]
    kinds = {e["kind"] for e in post}
    assert not kinds & {"process_blocked", "grpc_blocked", "github_token_requested", "unexpected_commit_status"}, kinds
    def target(e):
        d = e["detail"] or {}
        t = d.get("call") or d.get("host") or str(d.get("address"))
        return "127.0.0.1" if t.startswith(("127.0.0.1", "('127.0.0.1'")) else t
    attempts = {target(e) for e in post if e["kind"].endswith("_blocked")}
    assert attempts <= EXPECTED_REFUSED, attempts
    # the parent ran in synthetic mode: no Vertex project, no token
    m = json.loads((spec_run["out"] / "manifest.json").read_text())
    assert m["child_token_identity"] == "none" and m["vertex_project_set"] is False and m["llm_mode"] == "synthetic"


def test_spec_run_writes_an_escaped_report_with_a_verdict(spec_run):
    out = spec_run["out"]
    page = (out / "report.html").read_text(encoding="utf-8")
    assert "INCONCLUSIVE:validator_unavailable" in page  # --skip-score: tofu validate did not run
    low = page.lower()
    assert "<script" not in low and "onerror=" not in low and "<img" not in low
    assert "Content-Security-Policy" in page and "What this does not check" in page
    assert "How this differs from a real run" in page
    m = json.loads((out / "manifest.json").read_text())
    assert m["spec_source"] == "file" and m["examples"] == ["spec"]
    assert m["spec_sha256"] == hashlib.sha256(spec_run["spec"].read_bytes()).hexdigest()
    assert m["spec_sha256"] in page and m["product_id"] in page
    for f in (out / "manifest.json", out / "summary.json", out / "report.html"):
        assert str(spec_run["spec"]) not in f.read_text(encoding="utf-8")  # never the operator's path
    assert not list(out.glob(".report-*"))  # temp file was os.replace'd
    s = json.loads((out / "summary.json").read_text())
    assert [r["key"] for r in s["runs"]] == ["spec-r1"]
