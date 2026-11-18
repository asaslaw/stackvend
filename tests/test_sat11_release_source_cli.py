"""SAT-11 (owner 11-01): `scripts/release-source.py`, the terminal path to change the release source on installs
behind Identity-Aware Proxy (the browser path stays refused there).

- Validation parity with the Control Center route: the same requests are accepted / refused with the same codes
  (both go through `release_source.plan_change`).
- The Firestore commit has the Control Center batch's shape: the never-trimmed `changes/{id}` record (must not exist)
  and the whole `current` document (update-time precondition), same fields, `via: "cli"`.
- Typed confirmation: a wrong repository name or key suffix is refused and nothing is written; a non-interactive run
  is refused.
- The project comes only from --project / PROJECT_ID (no gcloud configuration fallback; the script never starts a
  process); the operator comes from the credentials; a service account is refused; no token is printed.
- No network: Firestore and the token information endpoint are in-memory doubles.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import ast
import importlib.util
import json
import os
import sys

import pytest

import test_sat11_settings_upgrades as cc  # the Control Center route harness (FakeDb, client, keys)
from test_sat11_settings_upgrades import env  # noqa: F401  (pytest fixture, re-exported)

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPT = os.path.join(BASE_DIR, "scripts", "release-source.py")
_spec = importlib.util.spec_from_file_location("stackvend_release_source_cli", SCRIPT)
rs = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = rs
_spec.loader.exec_module(rs)

PROJ = cc.PROJ
EMAIL = cc.ADMIN_EMAIL
TOKEN = "ya29.test-token-never-printed"
DB = rs.GUARD_DATABASE
CURRENT = f"projects/{PROJ}/databases/{DB}/documents/platform_release_source/current"


# ------------------------------------------------------------------------------------------------ REST double
class FakeRest:
    """Firestore REST (GET a document, POST :commit with preconditions, full-document replace) + tokeninfo."""

    def __init__(self, email=EMAIL, verified="true"):
        self.docs, self.tick, self.calls = {}, 0, []
        self.email, self.verified, self.fail_commit = email, verified, None

    def seed(self, doc):
        self.tick += 1
        self.docs[CURRENT] = (rs.rr.to_value(doc)["mapValue"]["fields"], f"2026-11-01T00:00:{self.tick:02d}Z")

    def stored(self, name=CURRENT):
        return rs.rr.from_value({"mapValue": {"fields": self.docs[name][0]}})

    def __call__(self, method, url, body, headers):
        self.calls.append((method, url, body, headers))
        assert url.startswith((rs.FIRESTORE + "/", rs.TOKENINFO)), url
        if url == rs.TOKENINFO:
            assert TOKEN.encode() in body and TOKEN not in url  # the token goes in the POST body, never a URL
            return 200, {"email": self.email, "email_verified": self.verified}
        assert headers["Authorization"] == f"Bearer {TOKEN}"
        if method == "GET":
            name = url[len(rs.FIRESTORE) + 1:]
            if name not in self.docs:
                return 404, {"error": {"status": "NOT_FOUND"}}
            fields, t = self.docs[name]
            return 200, {"name": name, "fields": fields, "updateTime": t}
        assert method == "POST" and url.endswith("/documents:commit")
        if self.fail_commit:
            return self.fail_commit
        writes = json.loads(body)["writes"]
        for w in writes:
            name, pre = w["update"]["name"], w["currentDocument"]
            if ("exists" in pre and pre["exists"] != (name in self.docs)) or \
                    ("updateTime" in pre and (name not in self.docs or self.docs[name][1] != pre["updateTime"])):
                return 400, {"error": {"code": 400, "status": "FAILED_PRECONDITION"}}
        for w in writes:
            self.tick += 1
            self.docs[w["update"]["name"]] = (w["update"]["fields"], f"2026-11-01T00:01:{self.tick:02d}Z")
        return 200, {"writeResults": [{} for _ in writes]}


@pytest.fixture
def cli(monkeypatch, tmp_path):
    state = {"rest": FakeRest(), "answers": [], "person": True, "out": []}
    monkeypatch.setattr(rs, "http_request", lambda *a: state["rest"](*a))
    monkeypatch.setattr(rs, "credentials_provider", lambda: (TOKEN, state["person"]))
    monkeypatch.setattr(rs, "interactive", lambda: True)
    monkeypatch.setattr(rs, "prompt", lambda text: state["answers"].pop(0))
    monkeypatch.setenv("PROJECT_ID", PROJ)
    state["tmp"] = tmp_path
    return state


def run_set(state, argv):
    """(code or "OK", output lines)."""
    out = state["out"]
    try:
        rs.cmd_set(rs.parser().parse_args(["set", *argv]), out=out.append)
    except rs.CliError as e:
        return e.code, out
    return "OK", out


# ------------------------------------------------------------------------------------------------ parity
KEY, BLOB = cc.ed25519_key()
RSA = "ssh-rsa AAAAB3NzaC1yc2E="

# spec signers: "OFFICIAL" or ("SSH", public key line)
CASES = [
    {"repository": "fork/stackvend", "signers": ["OFFICIAL"]},
    {"repository": "fork/stackvend", "signers": [("SSH", KEY)]},
    {"repository": "fork/stackvend", "signers": ["OFFICIAL", ("SSH", KEY)]},
    {"repository": "not/a/repo", "signers": ["OFFICIAL"]},
    {"repository": "fork/stackvend", "signers": []},
    {"repository": "fork/stackvend", "signers": [("SSH", RSA)]},
    {"repository": "fork/stackvend", "signers": [("SSH", "ssh-ed25519 not-base64")]},
    {"repository": "fork/stackvend", "signers": [("SSH", cc.ed25519_key(bytes([i]))[0]) for i in range(9)]},
]


def _suffixes(spec):
    out = []
    for s in spec["signers"]:
        if s != "OFFICIAL":
            try:
                out.append(rs.rsrc.parse_ssh_public_key(s[1])["fingerprint_sha256"][-6:])
            except rs.rsrc.SourceError:
                pass
    return out


def _cc_result(spec):
    signers = [{"kind": "OFFICIAL"} if s == "OFFICIAL" else {"kind": "SSH_KEY", "public_key": s[1]}
               for s in spec["signers"]]
    b = cc.body(repository=spec["repository"], confirm_repository=spec["repository"], signers=signers,
                confirm_key_suffixes=_suffixes(spec))
    r = cc.client().put("/api/settings/release-source", json=b)
    return ("OK" if r.status_code == 200 else r.json()["detail"]["code"]), r


def _cli_argv(spec, tmp):
    argv = ["--repository", spec["repository"]]
    for i, s in enumerate(spec["signers"]):
        if s == "OFFICIAL":
            argv.append("--official-key")
        else:
            path = tmp / f"k{i}.pub"
            path.write_text(s[1] + "\n")
            argv += ["--ssh-key-file", str(path)]
    return argv


@pytest.mark.parametrize("spec", CASES)
def test_validation_parity_with_the_control_center(env, cli, spec):  # noqa: F811
    cc_code, _r = _cc_result(spec)
    cli["answers"] = [spec["repository"], *_suffixes(spec)]
    cli_code, _out = run_set(cli, _cli_argv(spec, cli["tmp"]))
    assert cli_code == cc_code, (spec, cc_code, cli_code)
    committed = any(c[1].endswith(":commit") for c in cli["rest"].calls)
    assert committed == (cc_code == "OK")


@pytest.mark.parametrize("flag", ["--developer-mode", "--allow-unsigned", "--branch=main", "--follow=BRANCH"])
def test_branch_and_unsigned_options_are_gone(cli, flag):
    """Only signed release tags can be followed: the CLI has no way to ask for anything else."""
    with pytest.raises(SystemExit) as e:
        rs.parser().parse_args(["set", "--repository", "fork/stackvend", "--official-key", flag])
    assert e.value.code == 2


# ------------------------------------------------------------------------------------------------ batch shape
def _strip_times(d):
    if isinstance(d, dict):
        return {k: _strip_times(v) for k, v in d.items() if k not in ("updated_at", "changed_at", "added_at", "via")}
    if isinstance(d, list):
        return [_strip_times(x) for x in d]
    return d


def test_commit_matches_the_control_center_batch(env, cli):  # noqa: F811
    spec = {"repository": "fork/stackvend", "signers": ["OFFICIAL", ("SSH", KEY)]}
    assert _cc_result(spec)[0] == "OK"
    cc_current = env["guard"].docs[("platform_release_source", "current")]
    cc_change = next(iter(env["guard"].under("platform_release_source", "current", "changes").values()))

    cli["answers"] = ["fork/stackvend", *_suffixes(spec)]
    assert run_set(cli, _cli_argv(spec, cli["tmp"]))[0] == "OK"
    commit = [json.loads(c[2]) for c in cli["rest"].calls if c[1].endswith(":commit")]
    assert len(commit) == 1 and len(commit[0]["writes"]) == 2
    change_w, current_w = commit[0]["writes"]
    assert change_w["update"]["name"].startswith(CURRENT + "/changes/") and change_w["currentDocument"] == {"exists": False}
    assert current_w["update"]["name"] == CURRENT and current_w["currentDocument"] == {"exists": False}
    assert "updateMask" not in current_w  # the whole document: nothing outside the model survives
    cli_current = cli["rest"].stored()
    cli_change = cli["rest"].stored(change_w["update"]["name"])
    assert set(cli_current) == set(cc_current) == rs.rsrc._STORED_FIELDS
    assert _strip_times(cli_current) == _strip_times(cc_current)
    assert set(cli_change) == set(cc_change) and _strip_times(cli_change) == _strip_times(cc_change)
    assert cli_change["via"] == "cli" and cc_change["via"] == "control-center"
    assert cli_change["changed_by"] == cc_change["changed_by"] == EMAIL  # from the credentials, not an argument
    assert cli_current["signers"][1]["added_by"] == EMAIL


def test_second_change_uses_the_read_update_time_and_keeps_keys(cli):
    cli["answers"] = ["fork/stackvend", *_suffixes({"signers": [("SSH", KEY)]})]
    key_file = cli["tmp"] / "k.pub"
    key_file.write_text(KEY)
    assert run_set(cli, ["--repository", "fork/stackvend", "--ssh-key-file", str(key_file),
                         "--ssh-key-label", "fork key"])[0] == "OK"
    first_time = cli["rest"].docs[CURRENT][1]
    cli["answers"] = ["fork/other"]  # the kept key is not new: no suffix question
    assert run_set(cli, ["--repository", "fork/other", "--keep-current-keys"])[0] == "OK"
    writes = [json.loads(c[2]) for c in cli["rest"].calls if c[1].endswith(":commit")][-1]["writes"]
    assert writes[1]["currentDocument"] == {"updateTime": first_time}
    stored = cli["rest"].stored()
    assert stored["version"] == 2 and stored["signers"][0]["principal"] == "fork key"
    assert stored["signers"][0]["added_by"] == EMAIL
    assert len([n for n in cli["rest"].docs if "/changes/" in n]) == 2  # never trimmed


def test_concurrent_change_is_refused(cli):
    cli["rest"].fail_commit = (400, {"error": {"code": 400, "status": "FAILED_PRECONDITION"}})
    cli["answers"] = ["fork/stackvend"]
    assert run_set(cli, ["--repository", "fork/stackvend", "--official-key"])[0] == "RELEASE_SOURCE_CHANGED"
    cli["rest"].fail_commit = (500, None)
    cli["answers"] = ["fork/stackvend"]
    assert run_set(cli, ["--repository", "fork/stackvend", "--official-key"])[0] == "RELEASE_SOURCE_NOT_SAVED"
    cli["rest"].fail_commit = (403, None)
    cli["answers"] = ["fork/stackvend"]
    assert run_set(cli, ["--repository", "fork/stackvend", "--official-key"])[0] == "PERMISSION_DENIED"
    assert CURRENT not in cli["rest"].docs


def test_invalid_stored_source_is_repaired_by_a_full_replace(cli):
    stored = rs.rsrc.stored_document(rs.rsrc.default_source(), 3, "x", "t")
    cli["rest"].seed({**stored, "extra": 1})
    cli["answers"] = ["fork/stackvend"]
    code, out = run_set(cli, ["--repository", "fork/stackvend", "--official-key"])
    assert code == "OK" and any(line.startswith("Now:   invalid") for line in out)
    after = cli["rest"].stored()
    assert set(after) == rs.rsrc._STORED_FIELDS and after["version"] == 4
    change = [rs.rr.from_value({"mapValue": {"fields": f}}) for n, (f, _t) in cli["rest"].docs.items() if "/changes/" in n]
    assert change[0]["from"] == {"invalid_stored_document": True}


def test_unchanged_source_writes_nothing(cli):
    cli["rest"].seed(rs.rsrc.stored_document(rs.rsrc.default_source(), 1, "x", "t"))
    cli["answers"] = [rs.rsrc.default_source().repository]
    code, out = run_set(cli, ["--repository", rs.rsrc.default_source().repository, "--official-key"])
    assert code == "OK" and "Nothing changed" in out[-1]
    assert not any(c[1].endswith(":commit") for c in cli["rest"].calls)


# ------------------------------------------------------------------------------------------------ confirmation
def test_confirmation_mismatch_is_refused(cli):
    cli["answers"] = ["fork/stackvenD"]
    assert run_set(cli, ["--repository", "fork/stackvend", "--official-key"])[0] == "CONFIRMATION_REQUIRED"
    key_file = cli["tmp"] / "k.pub"
    key_file.write_text(KEY)
    cli["answers"] = ["fork/stackvend", "zzzzzz"]
    assert run_set(cli, ["--repository", "fork/stackvend", "--ssh-key-file", str(key_file)])[0] == \
        "CONFIRMATION_REQUIRED"
    assert not any(c[1].endswith(":commit") for c in cli["rest"].calls) and cli["rest"].docs == {}


def test_non_interactive_run_is_refused(cli, monkeypatch):
    monkeypatch.setattr(rs, "interactive", lambda: False)
    assert run_set(cli, ["--repository", "fork/stackvend", "--official-key"])[0] == "NOT_INTERACTIVE"
    assert cli["rest"].calls == []


# ------------------------------------------------------------------------------------------------ identity / project
def test_no_gcloud_config_fallback(cli, monkeypatch):
    monkeypatch.delenv("PROJECT_ID", raising=False)
    monkeypatch.setenv("CLOUDSDK_CORE_PROJECT", "configured-elsewhere")
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "configured-elsewhere")
    monkeypatch.setattr(rs, "credentials_provider", lambda: pytest.fail("credentials read before the project check"))
    assert run_set(cli, ["--repository", "fork/stackvend", "--official-key"])[0] == "PROJECT_REQUIRED"
    assert cli["rest"].calls == []
    tree = ast.parse(open(SCRIPT, encoding="utf-8").read())
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))
                for a in n.names} | {n.module.split(".")[0] for n in ast.walk(tree)
                                     if isinstance(n, ast.ImportFrom) and n.module}
    assert not imported & {"subprocess", "shutil"}  # never runs gcloud (or anything else)
    assert rs.target_project("explicit-project") == "explicit-project"
    with pytest.raises(rs.CliError) as e:
        rs.target_project("Not_A_Project")
    assert e.value.code == "INVALID_PROJECT"


def test_operator_comes_from_the_credentials_and_service_accounts_are_refused(cli):
    cli["person"] = False
    assert run_set(cli, ["--repository", "fork/stackvend", "--official-key"])[0] == "HUMAN_CREDENTIALS_REQUIRED"
    cli["person"] = True
    cli["rest"].verified = "false"
    assert run_set(cli, ["--repository", "fork/stackvend", "--official-key"])[0] == "IDENTITY_UNKNOWN"
    assert "--changed-by" not in rs.parser().format_help() and "--email" not in rs.parser().format_help()


def test_no_token_is_printed(cli, capsys):
    cli["answers"] = ["fork/stackvend"]
    assert rs.main(["set", "--repository", "fork/stackvend", "--official-key"]) == 0
    assert rs.main(["show"]) == 0
    cli["person"] = False
    assert rs.main(["set", "--repository", "fork/stackvend", "--official-key"]) == 1
    captured = capsys.readouterr()
    assert TOKEN not in captured.out + captured.err
    assert "ERROR [HUMAN_CREDENTIALS_REQUIRED]" in captured.err and "Next: gcloud auth application-default login" \
        in captured.err


def test_show_reports_an_invalid_source(cli, capsys):
    cli["rest"].seed({"repository": "x/y"})
    assert rs.main(["show"]) == 0
    assert "Release source invalid" in capsys.readouterr().out


# ------------------------------------------------------------------------------------------------ update-check (P3a-OFF)
def run_update_check(state, argv):
    out = state["out"]
    try:
        rs.cmd_update_check(rs.parser().parse_args(["update-check", *argv]), out=out.append)
    except rs.CliError as e:
        return e.code, out
    return "OK", out


def test_update_check_off_writes_the_same_document_as_the_route(env, cli):  # noqa: F811
    r = cc.client(method="iap").put("/api/settings/update-check", json={"enabled": False, "expected_version": 0})
    assert r.status_code == 200, r.text
    cc_current = env["guard"].docs[("platform_release_source", "current")]
    cc_change = next(iter(env["guard"].under("platform_release_source", "current", "changes").values()))

    cli["answers"] = ["OFF"]
    code, out = run_update_check(cli, ["off"])
    assert code == "OK", out
    commit = [json.loads(c[2]) for c in cli["rest"].calls if c[1].endswith(":commit")]
    assert len(commit) == 1 and len(commit[0]["writes"]) == 2
    change_w, _current_w = commit[0]["writes"]
    cli_current, cli_change = cli["rest"].stored(), cli["rest"].stored(change_w["update"]["name"])
    assert set(cli_current) == set(cc_current) == rs.rsrc._STORED_FIELDS and cli_current["update_check"] is False
    assert _strip_times(cli_current) == _strip_times(cc_current)
    assert set(cli_change) == set(cc_change) and _strip_times(cli_change) == _strip_times(cc_change)
    assert cli_change["via"] == "cli" and cli_change["to"]["update_check"] is False
    assert any('"to_update_check": false' in line for line in out) and out[-1].startswith("Saved: Update check: off")


def test_update_check_keeps_every_other_field_and_needs_the_typed_word(cli):
    key_file = cli["tmp"] / "k.pub"
    key_file.write_text(KEY)
    cli["answers"] = ["fork/stackvend", *_suffixes({"signers": [("SSH", KEY)]})]
    assert run_set(cli, ["--repository", "fork/stackvend", "--ssh-key-file", str(key_file),
                         "--ssh-key-label", "fork key"])[0] == "OK"
    before = cli["rest"].stored()
    cli["answers"] = ["off"]  # not the exact word
    assert run_update_check(cli, ["off"])[0] == "CONFIRMATION_REQUIRED"
    assert cli["rest"].stored() == before
    cli["answers"] = ["OFF"]
    assert run_update_check(cli, ["off"])[0] == "OK"
    after = cli["rest"].stored()
    assert after["update_check"] is False and after["version"] == 2
    assert {k: v for k, v in after.items() if k not in ("update_check", "version", "updated_at")} == \
        {k: v for k, v in before.items() if k not in ("update_check", "version", "updated_at")}
    cli["answers"] = ["OFF"]
    code, out = run_update_check(cli, ["off"])
    assert code == "OK" and "Nothing changed" in out[-1]
    assert len([c for c in cli["rest"].calls if c[1].endswith(":commit")]) == 2


def test_update_check_refused_for_an_invalid_stored_source_and_non_interactive(cli, monkeypatch):
    cli["rest"].seed({**rs.rsrc.stored_document(rs.rsrc.default_source(), 3, "x", "t"), "update_check": "off"})
    assert run_update_check(cli, ["on"])[0] == "RELEASE_SOURCE_INVALID"
    monkeypatch.setattr(rs, "interactive", lambda: False)
    assert run_update_check(cli, ["on"])[0] == "NOT_INTERACTIVE"
    assert not any(c[1].endswith(":commit") for c in cli["rest"].calls)


def test_show_prints_the_switch_and_never_reads_github(cli, capsys):
    v1 = rs.rsrc.stored_document(rs.rsrc.default_source(), 1, "x", "t")
    v1.pop("update_check")
    cli["rest"].seed(v1)  # a v1 document (before P3a-OFF) reads as on
    assert rs.main(["show"]) == 0
    text = capsys.readouterr().out
    assert "Update check: on" in text  # code review L-5: the line says the check happens only when it is on
    assert "The Control Center checks this repository (Settings ▸ Upgrades) when the update check is on" in text
    assert all(c[1].startswith((rs.FIRESTORE, rs.TOKENINFO)) for c in cli["rest"].calls)  # FakeRest asserts it too


# ------------------------------------------------------------------------------------------------ pins
def test_guard_database_default_is_the_platform_one():
    import hcl2
    with open(os.path.join(BASE_DIR, "infra", "platform", "destructive_guard.tf"), encoding="utf-8") as f:
        tf = hcl2.load(f)
    guard_ids = [blk["guard_db_id"] for blk in tf.get("locals", []) if "guard_db_id" in blk]
    assert guard_ids == [rs.GUARD_DATABASE]


def test_iap_refusal_names_the_cli(env):  # noqa: F811
    r = cc.client(method="iap").put("/api/settings/release-source", json=cc.body())
    detail = r.json()["detail"]
    assert r.status_code == 403 and detail["code"] == "RECENT_SIGN_IN_UNAVAILABLE"
    assert detail["command"] == cc.pr.CLI_COMMAND and cc.pr.CLI_COMMAND in detail["message"]
    assert "scripts/release-source.py set" in cc.pr.CLI_COMMAND and os.path.isfile(SCRIPT)
    args = rs.parser().parse_args(cc.pr.CLI_COMMAND.split("release-source.py ", 1)[1].replace(
        "<owner>/<repo>", "fork/stackvend").split())
    assert args.command == "set" and args.official_key and args.repository == "fork/stackvend"
