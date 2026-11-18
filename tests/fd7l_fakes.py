"""
FD-7L Phase 1 test fakes: a signing key with a self-signed x509 certificate (stands in for IAM signBlob and Google's
published certificates), an in-memory Google REST world (IAM, IAM Credentials, Storage, Service Usage, Cloud Run, CRM
testIamPermissions) and a project-IAM fake. No network, no GCP.
"""
import hermetic_guard  # noqa: F401  (must stay the first import: tests/hermetic_guard.py)

import base64
import copy
import datetime as _dt

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

HOST = "mock-stackvend-project"
BROKER = f"sa-project-provisioner@{HOST}.iam.gserviceaccount.com"
DEVELOPER = f"sa-castor-developer@{HOST}.iam.gserviceaccount.com"
RUNNER_SA = f"sa-stackvend-tf-applier@{HOST}.iam.gserviceaccount.com"
SERVER_SA = f"sa-stackvend-tf-server@{HOST}.iam.gserviceaccount.com"
CC = f"sa-stackvend-control-center@{HOST}.iam.gserviceaccount.com"
REGION = "us-central1"
JOB = "tf-applier"
EXEC_PREFIX = f"projects/{HOST}/locations/{REGION}/jobs/{JOB}/executions/"


class SigningKey:
    """An RSA key + self-signed certificate; sign() answers like IAM signBlob (key id, base64 signature)."""

    def __init__(self, key_id: str, common_name: str = "broker"):
        self.key_id = key_id
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = _dt.datetime(2026, 1, 1, tzinfo=_dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self._key.public_key())
                .serial_number(1).not_valid_before(now).not_valid_after(now + _dt.timedelta(days=3650))
                .sign(self._key, hashes.SHA256()))
        self.cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
        self.signed = []

    def sign(self, payload: bytes):
        self.signed.append(payload)
        sig = self._key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        return self.key_id, base64.b64encode(sig).decode("ascii")


BROKER_KEY = SigningKey("broker-key-1")
OTHER_KEY = SigningKey("cc-key-1", "control-center")


def certs_for(published=None):
    """certs(email, refresh=False): the broker's published certificates only (never a record's own claim)."""
    published = published if published is not None else {BROKER: {BROKER_KEY.key_id: BROKER_KEY.cert_pem},
                                                          CC: {OTHER_KEY.key_id: OTHER_KEY.cert_pem}}
    calls = []

    def certs(email, refresh=False):
        calls.append((email, refresh))
        return dict(published.get(email, {}))

    certs.calls = calls
    return certs


def sign_as(key, signer_email):
    """signer_factory stand-in: whatever email is asked for, `key` signs (to model a forger)."""
    return lambda email: key.sign


class FakeProjectIAM:
    """dg.RestCRM-compatible project IAM (v3 shape)."""

    def __init__(self, policy=None, fail_get=None, fail_set=None):
        self.policies = {}
        self.default = policy
        self.fail_get, self.fail_set = list(fail_get or []), list(fail_set or [])
        self.calls = []

    def _policy(self, pid):
        if pid not in self.policies:
            self.policies[pid] = copy.deepcopy(self.default) if self.default is not None else {
                "version": 3, "etag": "BwE1",
                "bindings": [{"role": "roles/owner", "members": ["serviceAccount:" + DEVELOPER]},
                             {"role": "roles/owner", "members": ["user:cond@example.com"],
                              "condition": {"title": "t", "expression": "request.time < timestamp('2030-01-01T00:00:00Z')"}},
                             {"role": "roles/viewer", "members": ["user:v@example.com"]}]}
        return self.policies[pid]

    def get_iam_policy(self, pid):
        from destructive_guard import CRMUnavailable
        self.calls.append(("get", pid))
        if self.fail_get:
            raise CRMUnavailable("getIamPolicy", self.fail_get.pop(0))
        return copy.deepcopy(self._policy(pid))

    def set_iam_policy(self, pid, policy):
        from destructive_guard import CRMUnavailable
        self.calls.append(("set", pid, copy.deepcopy(policy)))
        if self.fail_set:
            raise CRMUnavailable("setIamPolicy", self.fail_set.pop(0))
        self.policies[pid] = copy.deepcopy(policy)
        return copy.deepcopy(policy)

    def sets(self):
        return [c for c in self.calls if c[0] == "set"]


GOOD_BUCKET = {"iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}, "publicAccessPrevention": "enforced"},
               "versioning": {"enabled": True}}


class FakeGoogle:
    """Routes GoogleRest.call(method, url, json=, params=, bearer=) to in-memory state. Every call is logged."""

    MUTATING = ("POST serviceAccounts", "setIamPolicy", "POST bucket", "PUT bucket-iam", "run", "generateAccessToken")

    def __init__(self, log=None):
        self.log = log if log is not None else []
        self.calls = []
        self.enabled = {}                  # number -> set(api)
        self.sas = {}                      # email -> body
        self.sa_policies = {}              # email -> policy
        self.buckets = {}                  # name -> body (with projectNumber)
        self.foreign = set()               # bucket names owned by other projects (403)
        self.bucket_iam = {}               # name -> policy
        self.job_sa = DEVELOPER
        self.executions = {}               # name -> execution body
        self.exec_counter = 0
        self.fail = {}                     # key -> list of statuses to answer before normal behaviour
        self.mint_status = []              # statuses for generateAccessToken before 200
        self.tokens_minted = []            # deployer emails
        self.test_perms = {}               # bearer -> permissions granted on own project
        self.run_without_execution = False
        self.bucket_perms = None           # SAT-45: buckets.testIamPermissions answer for vending (None = all asked)

    def _f(self, key):
        lst = self.fail.get(key)
        return lst.pop(0) if lst else None

    def call(self, method, url, *, json=None, params=None, bearer=None, timeout=15.0):
        self.calls.append((method.upper(), url, copy.deepcopy(json), copy.deepcopy(params), bearer))
        st, body = self._route(method.upper(), url, json, params, bearer)
        self.log.append(f"{method.upper()} {url.split('?')[0]} -> {st}")
        return st, copy.deepcopy(body)

    def _route(self, m, url, json, params, bearer):
        if url.startswith("https://serviceusage.googleapis.com/v1/projects/") and url.endswith("/services:batchGet"):
            number = url.split("/")[5]
            s = self._f("apis")
            if s:
                return s, {}
            return 200, {"services": [{"name": n, "state": "ENABLED" if n.rsplit("/", 1)[-1] in self.enabled.get(
                number, set(ri_apis())) else "DISABLED"} for n in params["names"]]}
        if url.startswith("https://iam.googleapis.com/v1/projects/"):
            rest = url[len("https://iam.googleapis.com/v1/projects/"):]
            pid, _, tail = rest.partition("/serviceAccounts")
            if m == "POST" and tail == "":
                s = self._f("sa_create")
                if s:
                    return s, {}
                email = f"{json['accountId']}@{pid}.iam.gserviceaccount.com"
                if email in self.sas:
                    return 409, {}
                self.sas[email] = {"email": email, "projectId": pid, "uniqueId": "1"}
                return 200, self.sas[email]
            email, _, action = tail.lstrip("/").partition(":")
            if m == "GET" and not action:
                s = self._f("sa_get")
                if s:
                    return s, {}
                return (200, self.sas[email]) if email in self.sas else (404, {})
            if action == "getIamPolicy":
                if email not in self.sas:
                    return 404, {}
                return 200, self.sa_policies.get(email, {"etag": "ACAB"})
            if action == "setIamPolicy":
                s = self._f("sa_set")
                if s:
                    return s, {}
                self.sa_policies[email] = json["policy"]
                return 200, json["policy"]
        if url.startswith("https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/") \
                and url.endswith(":generateAccessToken"):
            email = url.split("/serviceAccounts/")[1].split(":")[0]
            if self.mint_status:
                return self.mint_status.pop(0), {}
            self.tokens_minted.append(email)
            return 200, {"accessToken": f"ya29.deployer-token-for-{email}", "expireTime": "2026-10-31T13:00:00Z"}
        if url.startswith("https://storage.googleapis.com/storage/v1/b"):
            rest = url[len("https://storage.googleapis.com/storage/v1/b"):]
            if m == "POST" and rest == "":
                s = self._f("bucket_create")
                if s:
                    return s, {}
                name = json["name"]
                if name in self.buckets or name in self.foreign:
                    return 409, {}
                body = dict(json, projectNumber=params["project"])
                self.buckets[name] = body
                return 200, body
            name, _, sub = rest.lstrip("/").partition("/")
            if sub == "iam/testPermissions" and m == "GET":
                if name not in self.buckets:
                    return 404, {}
                asked = list((params or {}).get("permissions") or [])
                held = asked if self.bucket_perms is None else [p for p in asked if p in self.bucket_perms]
                return 200, {"kind": "storage#testIamPermissionsResponse", "permissions": held}
            if sub == "iam":
                if m == "GET":
                    number = (self.buckets.get(name) or {}).get("projectNumber", "0")
                    return 200, self.bucket_iam.get(name, {"version": 1, "etag": "CAE=", "bindings": [
                        {"role": "roles/storage.legacyBucketOwner", "members": [f"projectOwner:{number}"]}]})
                s = self._f("bucket_iam_set")
                if s:
                    return s, {}
                self.bucket_iam[name] = json
                return 200, json
            if m == "GET":
                if name in self.foreign:
                    return 403, {}
                return (200, self.buckets[name]) if name in self.buckets else (404, {})
        if url.startswith("https://run.googleapis.com/v2/projects/"):
            path = url[len("https://run.googleapis.com/v2/"):]
            if m == "GET" and path == f"projects/{HOST}/locations/{REGION}/jobs/{JOB}":
                return 200, {"name": path, "template": {"template": {"serviceAccount": self.job_sa}}}
            if m == "POST" and path == f"projects/{HOST}/locations/{REGION}/jobs/{JOB}:run":
                self.exec_counter += 1
                name = f"{EXEC_PREFIX}{JOB}-x{self.exec_counter}"
                env = json["overrides"]["containerOverrides"][0]["env"]
                self.executions[name] = {"name": name, "creator": BROKER, "runningCount": 1, "env": env}
                if self.run_without_execution:
                    return 200, {"name": "operations/run-1", "metadata": {}}
                return 200, {"name": "operations/run-1", "metadata": {"name": name}}
            if m == "GET" and path.startswith(EXEC_PREFIX):
                return (200, self.executions[path]) if path in self.executions else (404, {})
        v1 = f"https://{REGION}-run.googleapis.com/apis/run.googleapis.com/v1/namespaces/{HOST}/executions/"
        if m == "GET" and url.startswith(v1):
            exec_id = url[len(v1):]
            exe = self.executions.get(EXEC_PREFIX + exec_id)
            if exe is None:
                return 404, {}
            return 200, {"metadata": {"name": exec_id, "annotations": dict(exe.get("v1_annotations", {}))}}
        if url.startswith("https://cloudresourcemanager.googleapis.com/v3/projects/") \
                and url.endswith(":testIamPermissions"):
            target = url.split("/projects/")[1].split(":")[0]
            if target == HOST:
                return 403, {}
            return 200, {"permissions": list(json["permissions"])}
        return 599, {"unrouted": url}

    def mutating(self):
        out = []
        for m, url, *_ in self.calls:
            if m in ("POST", "PUT") and not url.endswith(":getIamPolicy") and not url.endswith(":testIamPermissions") \
                    and not url.endswith(":batchGet"):
                out.append((m, url))
        return out

    def end_execution(self, name):
        self.executions[name] = dict(self.executions[name], runningCount=0, completionTime="2026-10-31T12:30:00Z")


def ri_apis():
    return ("iam.googleapis.com", "iamcredentials.googleapis.com", "storage.googleapis.com")
