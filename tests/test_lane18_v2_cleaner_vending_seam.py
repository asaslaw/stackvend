import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

"""Lane 18 window v2: the seam between lane 14 PR-6's sandbox cleaner and lane 18's vending guard.

1. Terraform (static, no provider): the cleaner job gets STACKVEND_GUARD_FIRESTORE_DATABASE from the guard database
   resource (closes PR-6's SEAM(lane 18 S0b)); its VENDING_SERVICE_URL is the same local vending's accepted audience
   is built from; the cleaner identity is vending's EPHEMERAL_TTL caller, may invoke vending and only READS the guard DB.
2. Runtime (hermetic): the real cleaner loop against the real vending FastAPI app (TestClient as the HTTP poster).
   S1e (`POST /ephemeral/{eid}:expire`, row L14-s) is not built, so vending answers 404 and the cleaner records
   REFUSED:EXECUTOR_UNAVAILABLE with exit 0 and deletes nothing. When S1e lands this test must be updated with it.
3. Audience: the ID token the cleaner mints (audience = its VENDING_SERVICE_URL) passes vending's audience check
   when vending's VENDING_SERVICE_URL carries the same install value.
"""
import os
import re

from fastapi.testclient import TestClient

import destructive_guard_fakes as f
import test_lane14_sandbox_cleaner as l14
from destructive_guard_fakes import dg

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MAIN_TF = os.path.join(REPO, "infra", "platform", "main.tf")
GUARD_TF = os.path.join(REPO, "infra", "platform", "destructive_guard.tf")
CLEANER_JOB = "sandbox-garbage-collector-job"
INSTALL_URL = "https://project-repo-vending-service-123456789.us-central1.run.app"
CLEANER_SA = "sa-stackvend-sandbox-cleaner@mock-stackvend-project.iam.gserviceaccount.com"

# Collection-time import (root conftest FD-05A sys.modules snapshot), like tests/test_destructive_guard_vending.py.
VENDING_MAIN = f.load_vending_main()


def _read(p):
    with open(p, encoding="utf-8") as fh:
        return fh.read()


def _strip_comments(text):
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _block(text, head):
    start = text.index(head + " {")
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    raise AssertionError("unbalanced block " + head)


# ------------------------------------------------------------------------------------------------ 1. Terraform
def test_cleaner_job_gets_the_guard_database_env_from_the_resource():
    locs = _block(_read(GUARD_TF), "locals")
    job_env = locs[locs.index("guard_job_env = {"):]
    job_env = job_env[:job_env.index("\n  }\n") + 4]
    assert f'"{CLEANER_JOB}" = {{' in job_env
    assert "STACKVEND_GUARD_FIRESTORE_DATABASE = google_firestore_database.stackvend_guard.name" in job_env
    assert l14.cleaner.GUARD_DB_ENV == "STACKVEND_GUARD_FIRESTORE_DATABASE"  # the name the cleaner reads
    jobs = _block(_read(MAIN_TF), 'resource "google_cloud_run_v2_job" "jobs"')
    assert 'for_each = { for k, v in lookup(local.guard_job_env, each.key, {}) : k => v if v != "" }' in jobs
    assert "SEAM(lane 18 S0b)" not in _read(MAIN_TF)  # the PR-6 seam is closed, not left as a comment


def test_cleaner_vending_url_is_the_audience_vending_accepts():
    jobs = _strip_comments(_block(_read(MAIN_TF), 'resource "google_cloud_run_v2_job" "jobs"'))
    m = re.search(r'name\s*=\s*"VENDING_SERVICE_URL"\s*\n\s*value\s*=\s*(\S+)', jobs)
    assert m and m.group(1) == "local.vending_service_url"
    locs = _block(_read(GUARD_TF), "locals")
    assert "VENDING_SERVICE_URL                = local.vending_service_url" in locs  # vending's audience list
    assert l14.cleaner.VENDING_URL_ENV == "VENDING_SERVICE_URL"


def test_cleaner_identity_is_vendings_ephemeral_caller_and_only_reads_the_guard_db():
    guard = _strip_comments(_read(GUARD_TF))
    locs = _block(guard, "locals")
    assert f'"{CLEANER_JOB}" = local.cleaner_sa_email' in locs
    assert "EPHEMERAL_TTL_CALLERS              = local.cleaner_sa_email" in locs
    invokers = _block(guard, 'resource "google_cloud_run_v2_service_iam_member" "persona_invokers"')
    assert '"cleaner:project-repo-vending-service" = { service = "project-repo-vending-service", sa = local.cleaner_sa_email }' in invokers
    readers = _block(guard, 'resource "google_project_iam_member" "guard_db_readers"')
    assert "cleaner   = local.cleaner_sa_email" in readers and 'role    = "roles/datastore.viewer"' in readers
    writers = _block(guard, 'resource "google_project_iam_member" "guard_db_writers"')
    assert "cleaner" not in writers


# ------------------------------------------------------------------------------------------------ 2. Runtime
def _vending_poster(client):
    calls = []

    def post(url, *, headers, json_body, timeout):
        assert url.startswith(INSTALL_URL + "/")
        r = client.post(url[len(INSTALL_URL):], headers=headers, json=json_body)
        calls.append((url, r.status_code))
        try:
            body = r.json()
        except ValueError:
            body = None
        return r.status_code, body

    post.calls = calls
    return post


def test_cleaner_against_real_vending_before_s1e_is_refused_executor_unavailable(monkeypatch):
    monkeypatch.setenv("VENDING_SERVICE_URL", INSTALL_URL)
    monkeypatch.setenv("EPHEMERAL_TTL_CALLERS", CLEANER_SA)
    client = TestClient(VENDING_MAIN.app)
    poster = _vending_poster(client)
    guard = l14.FakeDB("stackvend-guard")
    eid, data = l14.ledger_record()
    guard.data[l14.cleaner.LEDGER_COLLECTION] = {eid: data}
    env = {"PROJECT_ID": l14.HOST, "REGION": l14.REGION, "CLOUD_RUN_EXECUTION": "exec-l18v2",
           "STACKVEND_GUARD_FIRESTORE_DATABASE": "stackvend-guard", "VENDING_SERVICE_URL": INSTALL_URL}
    gc, db, _unused, calls = l14.make(env=env, ledger=guard, vending=poster)
    report = gc.execute_cleanup()
    assert poster.calls == [(f"{INSTALL_URL}/ephemeral/{eid}:expire", 404)]
    assert calls["token"] == [INSTALL_URL] and calls["resolver"] == []  # env URL, no services.get
    assert (report["requests"][0]["outcome"], report["requests"][0]["code"]) == ("REFUSED", "EXECUTOR_UNAVAILABLE")
    assert report["exit_code"] == 0 and report["deleted_count"] == 0
    assert guard.writes == []  # the cleaner never writes the guard DB


# ------------------------------------------------------------------------------------------------ 3. Audience
def test_token_minted_by_the_cleaner_passes_vendings_audience_check(monkeypatch):
    gc, _db, vending, calls = l14.make(env={"PROJECT_ID": l14.HOST, "CLOUD_RUN_EXECUTION": "exec-aud",
                                            "VENDING_SERVICE_URL": INSTALL_URL + "/"})
    eid, data = l14.ledger_record()
    l14.put(_db, eid, data)
    gc.execute_cleanup()
    minted_for = calls["token"]
    assert minted_for == [INSTALL_URL]
    monkeypatch.setenv("VENDING_SERVICE_URL", INSTALL_URL)
    _callers, audiences = dg.caller_config_from_env()

    def verifier(token, auds):
        return {"iss": "https://accounts.google.com", "aud": minted_for[0], "email": CLEANER_SA,
                "email_verified": True}

    assert dg.authenticate_caller("Bearer t", allowed=frozenset({CLEANER_SA}), audiences=audiences,
                                  verifier=verifier) == CLEANER_SA


def test_negative_a_token_for_another_audience_is_refused(monkeypatch):
    monkeypatch.setenv("VENDING_SERVICE_URL", INSTALL_URL)
    _callers, audiences = dg.caller_config_from_env()

    def verifier(token, auds):
        return {"iss": "https://accounts.google.com", "aud": "https://project-repo-vending-service-x-uc.a.run.app",
                "email": CLEANER_SA, "email_verified": True}

    try:
        dg.authenticate_caller("Bearer t", allowed=frozenset({CLEANER_SA}), audiences=audiences, verifier=verifier)
    except dg.CallerRefused as e:
        assert e.http_status == 401 and e.code == "UNAUTHENTICATED"
    else:
        raise AssertionError("a hashed *.a.run.app audience must be refused")
