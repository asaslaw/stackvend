"""
FD-7L Phase 1: shared/runner_identity.py (names, install mode, vending-signed records, nonce / session helpers).
Hermetic: a local RSA key + self-signed certificate stands in for IAM signBlob and Google's published certificates.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import base64
import os

import pytest

import fd7l_fakes as k
from shared import runner_identity as ri

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
COPIES = ["shared/runner_identity.py", "apps/project-vending/shared/runner_identity.py",
          "mcp-servers/terraform/shared/runner_identity.py", "apps/control-center/shared/runner_identity.py",
          "apps/infra-rollback/shared/runner_identity.py"]


def test_copies_are_byte_identical():
    blobs = {p: open(os.path.join(REPO, p), "rb").read() for p in COPIES}
    assert len(set(blobs.values())) == 1, sorted(blobs)


def test_module_imports_only_the_stdlib_at_import_time():
    import ast
    tree = ast.parse(open(os.path.join(REPO, "shared/runner_identity.py")).read())
    top = {(n.module if isinstance(n, ast.ImportFrom) else a.name).split(".")[0]
           for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))
           for a in (n.names if isinstance(n, ast.Import) else [n])}
    assert top <= {"base64", "hashlib", "hmac", "json", "os", "secrets", "threading", "time", "typing"}


# ---------------------------------------------------------------------------------------------- names
def test_names():
    assert ri.deployer_email("shop-api-a1b2c3") == "stackvend-deployer@shop-api-a1b2c3.iam.gserviceaccount.com"
    assert ri.state_bucket_name("shop-api-a1b2c3") == "shop-api-a1b2c3-tfstate"
    assert ri.state_bucket_name("shop-api-a1b2c3", "0a1b2c") == "shop-api-a1b2c3-tfstate-0a1b2c"
    assert ri.state_prefix("shop-api") == "workloads/shop-api"
    assert not ri.DEPLOYER_ACCOUNT_ID.startswith("sa-")


@pytest.mark.parametrize("name,ok", [
    ("shop-api-a1b2c3-tfstate", True), ("shop-api-a1b2c3-tfstate-0a1b2c", True),
    ("shop-api-a1b2c3-tfstate-0A1B2C", False), ("shop-api-a1b2c3-tfstate-0a1b2", False),
    ("shop-api-a1b2c3-tfstate-0a1b2cd", False), ("other-proj-1-tfstate", False), ("shop-api-a1b2c3", False),
    ("castor-tfstate-mock-stackvend-project", False), (None, False)])
def test_state_bucket_shape_is_exact(name, ok):
    assert ri.is_state_bucket_name_for("shop-api-a1b2c3", name) is ok


@pytest.mark.parametrize("bad", ["", "Shop-Api-123", "1abcdef", "abc", "a" * 31, "shop-api-", "shop_api_12", None])
def test_invalid_project_id_is_refused(bad):
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.deployer_email(bad)
    assert e.value.code == "RUNNER_IDENTITY_INVALID_PROJECT"


def test_random_bucket_suffix_shape():
    for _ in range(20):
        assert ri.is_state_bucket_name_for("shop-api-a1b2c3", ri.state_bucket_name("shop-api-a1b2c3",
                                                                                    ri.random_bucket_suffix()))


# ---------------------------------------------------------------------------------------------- mode
@pytest.mark.parametrize("env,mode", [({}, "PLATFORM"), ({ri.MODE_ENV: ""}, "PLATFORM"),
                                      ({ri.MODE_ENV: "  "}, "PLATFORM"), ({ri.MODE_ENV: "PLATFORM"}, "PLATFORM"),
                                      ({ri.MODE_ENV: " PER_WORKLOAD "}, "PER_WORKLOAD")])
def test_mode(env, mode):
    assert ri.runner_identity_mode(env) == mode


@pytest.mark.parametrize("raw", ["per_workload", "Per workload", "Shared", "SHARED", "true", "1", "PER-WORKLOAD"])
def test_unknown_mode_is_a_typed_configuration_error(raw):
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.runner_identity_mode({ri.MODE_ENV: raw})
    assert (e.value.code, e.value.http_status) == ("RUNNER_IDENTITY_MODE_INVALID", 503)


def test_mode_labels_are_the_owner_words():
    assert ri.MODE_LABELS == {"PLATFORM": "Shared", "PER_WORKLOAD": "Per workload"}


def test_member_parsers():
    assert ri.service_account_members(f" serviceAccount:{k.DEVELOPER} , group:x@example.com,user:u@example.com,"
                                      f"serviceAccount:{k.RUNNER_SA.upper()}") == {k.DEVELOPER, k.RUNNER_SA}
    assert ri.csv_emails(f"{k.RUNNER_SA}, ,{k.DEVELOPER.upper()}") == {k.RUNNER_SA, k.DEVELOPER}


# ---------------------------------------------------------------------------------------------- signatures
PATH = ri.provenance_doc_path("shop-api")


def _record(**over):
    rec = ri.new_runner_identity_record(product_id="shop-api", project_id="shop-api-a1b2c3",
                                        project_number="123456789012", state_bucket="shop-api-a1b2c3-tfstate",
                                        status=ri.STATUS_READY, updated_at="2026-10-31T12:00:00+00:00")
    rec.update(over)
    return rec


def _signed(key=k.BROKER_KEY, signer=k.BROKER, path=PATH, **over):
    return ri.sign_record(path, _record(**over), signer_email=signer, signed_at="2026-10-31T12:00:01+00:00",
                          sign_blob=key.sign)


def test_signed_record_verifies():
    doc = _signed()
    rec = ri.verify_record(PATH, doc, expected_signer=k.BROKER, certs=k.certs_for())
    assert rec["deployer_email"] == "stackvend-deployer@shop-api-a1b2c3.iam.gserviceaccount.com"
    assert "signature" not in rec and rec["signed_by"] == k.BROKER
    ri.check_runner_identity(rec, product_id="shop-api", project_id="shop-api-a1b2c3", project_number="123456789012")


@pytest.mark.parametrize("field,value", [("project_id", "other-proj-123"), ("state_bucket", "evil-bucket"),
                                         ("status", "FAILED"), ("deployer_email", "x@y.iam.gserviceaccount.com"),
                                         ("repository", {"provider": "GITHUB", "full_name": "evil/repo", "id": "1"}),
                                         ("signed_at", "2027-01-01T00:00:00+00:00"), ("extra", True)])
def test_any_field_change_breaks_the_signature(field, value):
    doc = _signed()
    doc[field] = value
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.verify_record(PATH, doc, expected_signer=k.BROKER, certs=k.certs_for())
    assert e.value.code == "RUNNER_RECORD_UNSIGNED"


def test_record_copied_to_another_document_path_is_refused():
    doc = _signed(path=ri.provenance_doc_path("other-product"))
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.verify_record(PATH, doc, expected_signer=k.BROKER, certs=k.certs_for())
    assert e.value.code == "RUNNER_RECORD_UNSIGNED"


def test_record_signed_by_the_control_center_is_refused():
    """The CC SA can write the guard DB (re-RT R1): a record it signs with its own key never verifies."""
    doc = _signed(key=k.OTHER_KEY, signer=k.CC)
    with pytest.raises(ri.RunnerIdentityError):
        ri.verify_record(PATH, doc, expected_signer=k.BROKER, certs=k.certs_for())


def test_forged_signed_by_with_another_key_is_refused():
    doc = _signed(key=k.OTHER_KEY, signer=k.BROKER)          # claims the broker, signed with another key
    doc["signature"]["key_id"] = k.BROKER_KEY.key_id
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.verify_record(PATH, doc, expected_signer=k.BROKER, certs=k.certs_for())
    assert e.value.code == "RUNNER_RECORD_UNSIGNED"


def test_certificate_of_another_account_is_never_used():
    doc = _signed(key=k.OTHER_KEY, signer=k.BROKER)
    certs = k.certs_for()
    with pytest.raises(ri.RunnerIdentityError):
        ri.verify_record(PATH, doc, expected_signer=k.BROKER, certs=certs)
    assert {email for email, _ in certs.calls} == {k.BROKER}


@pytest.mark.parametrize("mutate", [
    lambda d: d.pop("signature"), lambda d: d.update(signature="x"),
    lambda d: d["signature"].update(alg="none"), lambda d: d["signature"].update(value="!!notbase64!!"),
    lambda d: d["signature"].update(key_id=""), lambda d: d.pop("signed_by")])
def test_malformed_signatures_are_refused(mutate):
    doc = _signed()
    mutate(doc)
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.verify_record(PATH, doc, expected_signer=k.BROKER, certs=k.certs_for())
    assert e.value.code == "RUNNER_RECORD_UNSIGNED"


def test_unknown_key_id_refetches_once_then_reports_a_retired_key():
    """RT F1: a well-formed broker record whose key Google no longer publishes is KEY_RETIRED, not a forgery."""
    doc = _signed()
    certs = k.certs_for({k.BROKER: {"newer-key": k.OTHER_KEY.cert_pem}})
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.verify_record(PATH, doc, expected_signer=k.BROKER, certs=certs)
    assert (e.value.code, e.value.http_status) == ("RUNNER_RECORD_KEY_RETIRED", 409)
    assert certs.calls == [(k.BROKER, False), (k.BROKER, True)]


def test_a_bad_signature_with_a_published_key_stays_unsigned():
    doc = _signed(key=k.OTHER_KEY, signer=k.BROKER)
    doc["signature"]["key_id"] = k.BROKER_KEY.key_id
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.verify_record(PATH, doc, expected_signer=k.BROKER, certs=k.certs_for())
    assert e.value.code == "RUNNER_RECORD_UNSIGNED"


def test_a_record_naming_another_signer_is_unsigned_not_retired():
    doc = _signed(key=k.OTHER_KEY, signer=k.CC)
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.verify_record(PATH, doc, expected_signer=k.BROKER, certs=k.certs_for({k.BROKER: {}}))
    assert e.value.code == "RUNNER_RECORD_UNSIGNED"


def test_certificates_unavailable_is_503():
    def certs(email, refresh=False):
        raise RuntimeError("HTTP 500")
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.verify_record(PATH, _signed(), expected_signer=k.BROKER, certs=certs)
    assert (e.value.code, e.value.http_status) == ("RUNNER_RECORD_UNVERIFIABLE", 503)


@pytest.mark.parametrize("bad", [1.5, b"x", {"a": 1.0}, [float("nan")]])
def test_non_json_values_are_never_signed(bad):
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.canonical_payload(PATH, {"x": bad})
    assert e.value.code == "RUNNER_RECORD_UNSIGNABLE"


def test_canonical_payload_is_order_independent():
    a = ri.canonical_payload(PATH, {"b": 1, "a": {"y": 2, "x": [1, "z"]}})
    b = ri.canonical_payload(PATH, {"a": {"x": [1, "z"], "y": 2}, "b": 1, "signature": {"ignored": True}})
    assert a == b


def test_sign_record_refuses_an_empty_signblob_answer():
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.sign_record(PATH, _record(), signer_email=k.BROKER, signed_at="t", sign_blob=lambda p: ("", ""))
    assert e.value.code == "RUNNER_RECORD_SIGN_FAILED"


# ---------------------------------------------------------------------------------------------- record checks
@pytest.mark.parametrize("over,kw,code", [
    ({"product_id": "other"}, {}, "RUNNER_TARGET_MISMATCH"),
    ({}, {"project_id": "other-proj-123"}, "RUNNER_TARGET_MISMATCH"),
    ({}, {"project_number": "999"}, "RUNNER_TARGET_MISMATCH"),
    ({"deployer_email": "stackvend-deployer@other-proj-123.iam.gserviceaccount.com"}, {}, "RUNNER_TARGET_MISMATCH"),
    ({"state_bucket": "castor-tfstate-mock-stackvend-project"}, {}, "RUNNER_TARGET_MISMATCH"),
    ({"state_prefix": "workloads/other"}, {}, "RUNNER_TARGET_MISMATCH"),
    ({"status": "MIGRATING"}, {}, "RUNNER_IDENTITY_NOT_READY"),
    ({"schema": "runner_identity/v0"}, {}, "RUNNER_RECORD_UNSIGNED")])
def test_check_runner_identity_rederives_everything(over, kw, code):
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.check_runner_identity(_record(**over), product_id="shop-api", **kw)
    assert e.value.code == code


# ---------------------------------------------------------------------------------------------- nonce / session
def test_nonce_and_session_helpers():
    nonce = ri.new_nonce()
    doc_id = ri.nonce_doc_id(nonce)
    assert len(doc_id) == 64 and nonce not in doc_id
    key = ri.new_session_key(doc_id)
    assert ri.session_doc_id(key) == doc_id
    assert ri.secret_matches(key, ri.secret_hash(key)) and not ri.secret_matches(key + "x", ri.secret_hash(key))
    assert not ri.secret_matches(key, None)


@pytest.mark.parametrize("bad", [None, "", "abc", "0" * 64, "0" * 64 + ".short", "g" * 64 + "." + "x" * 40])
def test_malformed_session_keys(bad):
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.session_doc_id(bad)
    assert (e.value.code, e.value.http_status) == ("RUNNER_SESSION_INVALID", 401)


def test_short_nonce_is_unknown():
    with pytest.raises(ri.RunnerIdentityError) as e:
        ri.nonce_doc_id("short")
    assert e.value.http_status == 404


# ---------------------------------------------------------------------------------------------- cert fetcher
class _Resp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body

    def json(self):
        return self._body


def test_cert_fetcher_caches_and_refreshes():
    calls = []
    now = [0.0]

    def get(url, timeout):
        calls.append(url)
        return _Resp(200, {"k1": k.BROKER_KEY.cert_pem})

    fetch = ri.X509CertFetcher(http_get=get, clock=lambda: now[0])
    assert fetch(k.BROKER) == {"k1": k.BROKER_KEY.cert_pem}
    fetch(k.BROKER)
    assert len(calls) == 1 and calls[0] == ri.X509_CERT_URL.format(email=k.BROKER)
    fetch(k.BROKER, refresh=True)
    now[0] = ri.CERT_CACHE_SECONDS + 1
    fetch(k.BROKER)
    assert len(calls) == 3


@pytest.mark.parametrize("resp", [_Resp(404, {}), _Resp(200, ["x"]), _Resp(200, {"k": 1})])
def test_cert_fetcher_failures_raise(resp):
    with pytest.raises(RuntimeError):
        ri.X509CertFetcher(http_get=lambda url, timeout: resp)(k.BROKER)


def test_signature_value_is_standard_base64():
    doc = _signed()
    base64.b64decode(doc["signature"]["value"], validate=True)
