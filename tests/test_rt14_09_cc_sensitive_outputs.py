"""RT14-09 (CC viewer half; plan docs/planning/rt14-tf-destructive-fake-success-plan.md): the workload details state
viewer never shows a value the engine marks sensitive. Masking reads only the engine's typed marks (an output's
`sensitive`, an instance's `sensitive_attributes`), never names or value patterns. Negative: unmarked values unchanged.

Hermetic: parse functions only (no route call, no Firestore).
"""

import hermetic_guard  # noqa: F401,E402  (must stay the first import: tests/hermetic_guard.py)
import json
import os
import sys

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CC_DIR = os.path.join(REPO_ROOT, "apps", "control-center")


def _routes(monkeypatch):
    if CC_DIR not in sys.path:
        monkeypatch.syspath_prepend(CC_DIR)
    monkeypatch.setenv("GOOGLE_OAUTH_CLIENT_ID", "test-client-id.apps.example.com")
    import db as cc_db
    from routes import workloads as wl_routes

    monkeypatch.setattr(cc_db, "_db_client", False)
    return wl_routes


STATE = {
    "version": 4, "terraform_version": "1.9.0", "serial": 3,
    "outputs": {
        "db_password": {"value": "s3cret-pw", "type": "string", "sensitive": True},
        "service_url": {"value": "https://app.run.app", "type": "string"},
        "conn": {"value": {"user": "u", "pw": "p"}, "type": ["object", {}], "sensitive": True},
    },
    "resources": [{
        "mode": "managed", "type": "google_sql_user", "name": "app", "provider": "provider[\"google\"]",
        "instances": [{"attributes": {"id": "u1", "name": "app", "password": "s3cret-pw", "instance": "db"},
                       "sensitive_attributes": [[{"type": "get_attr", "value": "password"}]]}],
    }, {
        "mode": "managed", "type": "random_password", "name": "p", "provider": "provider[\"random\"]",
        "instances": [{"attributes": {"id": "none", "result": "r4nd0m", "length": 24, "special": True},
                       "sensitive_attributes": [[{"type": "get_attr", "value": "result"}]]}],
    }],
}


def test_sensitive_state_outputs_and_attributes_are_never_shown(monkeypatch):
    wl = _routes(monkeypatch)
    parsed = wl.parse_tfstate_json(json.dumps(STATE), "gs://b/workloads/x/default.tfstate")
    assert parsed["outputs"]["db_password"] == wl.SENSITIVE_OUTPUT_PLACEHOLDER
    assert parsed["outputs"]["conn"] == wl.SENSITIVE_OUTPUT_PLACEHOLDER
    blob = json.dumps({"o": parsed["outputs"], "r": [r.model_dump() if hasattr(r, "model_dump") else r.dict()
                                                     for r in parsed["resources"]]})
    assert "s3cret-pw" not in blob and "r4nd0m" not in blob


def test_negative_unmarked_outputs_and_attributes_are_unchanged(monkeypatch):
    wl = _routes(monkeypatch)
    parsed = wl.parse_tfstate_json(json.dumps(STATE), "src")
    assert parsed["outputs"]["service_url"] == "https://app.run.app"
    sql = parsed["resources"][0]
    attrs = sql.attributes if hasattr(sql, "attributes") else sql["attributes"]
    assert attrs == {"name": "app"}   # the summary keys of the unmarked attributes, exactly as before
    assert wl._without_sensitive_attributes({"a": 1, "b": 2}, None) == {"a": 1, "b": 2}
    assert wl._without_sensitive_attributes({"a": 1}, []) == {"a": 1}


def test_firestore_record_outputs_are_masked_by_their_flag(monkeypatch):
    wl = _routes(monkeypatch)
    rec = {"db_password": {"sensitive": True, "type": "string", "value": "s3cret-pw"},
           "service_url": {"sensitive": False, "type": "string", "value": "https://app.run.app"}}
    masked = wl._masked_record_outputs(rec)
    assert masked["db_password"]["value"] == wl.SENSITIVE_OUTPUT_PLACEHOLDER
    assert masked["service_url"] == rec["service_url"]
    assert rec["db_password"]["value"] == "s3cret-pw"   # pure
