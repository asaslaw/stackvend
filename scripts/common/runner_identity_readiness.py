#!/usr/bin/env python3
"""FD-7L step B readiness (SAT-33, FD-7L-n): read-only checks the operator runs before the runner identity switch.

The step-B apply (`tf_runner_dedicated_sa = true`) moves mcp-terraform-server and the tf-applier job off
sa-castor-developer. From then on a workload can deploy only with its vending-signed runner identity record
(plan docs/planning/fd-7l-per-workload-runner-identity-plan.md §2.1, §4 "Window"; RT F9: vending's own status route
admits only the Control Center, so the operator reads the guard database directly, with the operator's credentials).

Subcommands:
  plan-switch --plan PLAN_JSON
        exit 3 when the plan (`tofu show -json`) moves the terraform server or the tf-applier job to a runner SA
        (or to a service account not known at plan time); exit 0 otherwise. A new install (create) is no switch.
  check --project P --broker EMAIL [--offline DIR] [--json]
        every LIVE workload (default-database ledger `workloads`, status not DECOMMISSIONED / DELETED / ARCHIVED, with a project
        id, not a platform pseudo-workload) must have `workload_provenance/{pid}.runner_identity` in the guard
        database, signed by EMAIL (vending's Terraform-owned broker identity, verified against Google's published x509
        certificates of EMAIL, never a signer the record names), READY for exactly that project, and pinning the
        workload's repository (SAT-41; else REPOSITORY_NOT_PINNED). A non-READY workload whose project Resource
        Manager reports exactly DELETE_REQUESTED / DELETE_IN_PROGRESS (typed state, answer naming that project) is
        listed as CLOSED_PROJECT_PENDING_DELETION and does not block (SAT-40 option G); an unreadable project still
        blocks.
        exit 0 ready, 1 not ready (each workload listed), 2 could not check.
  deployers --project P [--offline DIR]
        JSON list of the deployer service accounts named by the provenance records (for scripts/check-install-iam.sh).

Live mode reads an OAuth access token on stdin (never argv, never logged) and makes GET requests only:
  https://firestore.googleapis.com/v1/... (the token, X-Goog-User-Project = the host project)
  https://cloudresourcemanager.googleapis.com/v3/projects/<number or id> (the token; non-READY workloads only)
  https://www.googleapis.com/service_accounts/v1/metadata/x509/<broker> (public; no token)
Offline mode (--offline DIR, for saved evidence and tests): DIR/workloads.json, DIR/provenance.json (Firestore
`documents:list` answers, one page each), DIR/certs.json ({key_id: PEM}) and DIR/crm-<number or id>.json
(projects.get answers; missing = 404); an optional DIR/<name>.http holds a
non-200 status. RSA verification uses the `openssl` command line (no Python packages needed).

The signed bytes are exactly shared/runner_identity.py `canonical_payload` (SAT-19): sorted, compact, ASCII JSON of
{"doc": "workload_provenance/<pid>#runner_identity", "record": <record without "signature">}; a parity test pins it.

Python 3.8+, standard library only. Never writes anything except a private temporary directory for openssl.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

EXIT_READY = 0
EXIT_NOT_READY = 1
EXIT_UNCHECKED = 2
EXIT_SWITCH = 3

FIRESTORE_V1 = "https://firestore.googleapis.com/v1/"
X509_URL = "https://www.googleapis.com/service_accounts/v1/metadata/x509/"
CRM_V3_PROJECTS = "https://cloudresourcemanager.googleapis.com/v3/projects/"
DEFAULT_DB = "(default)"
GUARD_DB = "stackvend-guard"                       # infra/platform/destructive_guard.tf local.guard_db_id
WORKLOADS = "workloads"
PROVENANCE = "workload_provenance"
RUNNER_IDENTITY_FIELD = "runner_identity"
# managed_tag_backfill.CLOSED_STATUSES + ARCHIVED (SAT-40): the Control Center's archive route moves only a DECOMMISSIONED
# workload to ARCHIVED (and unarchive moves it back to DECOMMISSIONED), so an archived workload has no project to strand.
CLOSED_STATUSES = frozenset({"DECOMMISSIONED", "DELETED", "ARCHIVED"})
PLATFORM_PSEUDO_WORKLOADS = frozenset({"project-castor", "castor", "platform"})   # destructive_guard.py
PAGE_SIZE = 300
# SAT-40 option G (owner 11-02): a workload whose recorded project Resource Manager reports in exactly one of these
# typed states (v3 `state`, v1 `lifecycleState`) cannot run anything; it is listed on its own line and does not block.
# The v3 State enum has no DELETE_IN_PROGRESS (only v1 lifecycleState does); it is kept for a v1-shaped answer.
PENDING_DELETION_STATES = frozenset({"DELETE_REQUESTED", "DELETE_IN_PROGRESS"})
STATE_PENDING_DELETION = "CLOSED_PROJECT_PENDING_DELETION"
# Review M1: only these "nothing usable yet" states may be lifted by a pending deletion; a MISMATCH never is.
PENDING_DELETION_LIFTS = frozenset({"NO_PROVENANCE", "NO_RUNNER_IDENTITY", "UNSIGNED", "NOT_READY"})
UNDELETE_NOTE = ("A project pending deletion that is restored (undeleted) is a live workload again: run the runner "
                 "identity backfill for it before deploying it.")

# shared/runner_identity.py (SAT-19) constants this check mirrors.
SCHEMA = "runner_identity/v1"
STATUS_READY = "READY"
REPOSITORY_NOT_PINNED = "REPOSITORY_NOT_PINNED"   # SAT-41: = runner_identity_backfill.STEP_B_REPOSITORY_NOT_PINNED
SIGNATURE_ALG = "RS256"
DEPLOYER_ACCOUNT_ID = "stackvend-deployer"
STATE_BUCKET_SUFFIX = "-tfstate"
STATE_BUCKET_RANDOM_HEX = 6
STATE_PREFIX_ROOT = "workloads"

# infra/platform/tf_runner_identity.tf
RUNNER_ACCOUNT_IDS = frozenset({"sa-stackvend-tf-applier", "sa-stackvend-tf-server"})
RUNNER_ADDRESSES = {
    "google_cloud_run_v2_job.tf_applier": ("template", 0, "template", 0, "service_account"),
    'google_cloud_run_v2_service.services["mcp-terraform-server"]': ("template", 0, "service_account"),
}

_PROJECT_ID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-")
_HEX = frozenset("0123456789abcdef")


class CheckError(Exception):
    """The check cannot give a trustworthy answer (exit 2)."""


class Unsupported(Exception):
    """A Firestore value type vending never writes into a signed record."""


# ------------------------------------------------------------------------------------------------ names
def is_project_id(value: Any) -> bool:
    return (isinstance(value, str) and 6 <= len(value) <= 30 and set(value) <= _PROJECT_ID_CHARS
            and value[0].isalpha() and not value.endswith("-"))


def deployer_email(project_id: str) -> str:
    return f"{DEPLOYER_ACCOUNT_ID}@{project_id}.iam.gserviceaccount.com"


def is_state_bucket_name_for(project_id: str, name: Any) -> bool:
    if not is_project_id(project_id) or not isinstance(name, str):
        return False
    base = f"{project_id}{STATE_BUCKET_SUFFIX}"
    if name == base:
        return True
    head, rest = name[:len(base) + 1], name[len(base) + 1:]
    return head == base + "-" and len(rest) == STATE_BUCKET_RANDOM_HEX and set(rest) <= _HEX


def account_id_of(email: Any) -> str:
    """The account id (local part) of a service-account email, '' for anything else."""
    if not isinstance(email, str) or email.count("@") != 1:
        return ""
    local, domain = email.split("@")
    return local if domain.endswith(".iam.gserviceaccount.com") else ""


# ------------------------------------------------------------------------------------------------ signed payload
def _json_value_ok(value: Any) -> bool:
    if value is None or isinstance(value, (str, bool, int)):
        return not isinstance(value, float)
    if isinstance(value, list):
        return all(_json_value_ok(v) for v in value)
    if isinstance(value, dict):
        return all(isinstance(k, str) and _json_value_ok(v) for k, v in value.items())
    return False


def provenance_doc_path(product_id: str) -> str:
    return f"{PROVENANCE}/{product_id}#{RUNNER_IDENTITY_FIELD}"


def canonical_payload(doc_path: str, record: Dict[str, Any]) -> bytes:
    """Byte-identical to shared/runner_identity.py canonical_payload (SAT-19). ValueError for a non-JSON value."""
    body = {k: v for k, v in record.items() if k != "signature"}
    if not isinstance(doc_path, str) or not doc_path or not _json_value_ok(body):
        raise ValueError("record holds a value vending never signs")
    return json.dumps({"doc": doc_path, "record": body}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def openssl_verify(cert_pem: str, payload: bytes, signature: bytes) -> bool:
    """RS256 (RSASSA-PKCS1-v1_5 + SHA-256) verification with the openssl CLI. CheckError when openssl is missing."""
    openssl = shutil.which("openssl")
    if not openssl:
        raise CheckError("the openssl command is not installed; signatures cannot be verified")
    work = tempfile.mkdtemp(prefix="sv-ri-")
    try:
        os.chmod(work, 0o700)
        cert, pub, data, sig = (os.path.join(work, n) for n in ("cert.pem", "pub.pem", "payload.bin", "sig.bin"))
        with open(cert, "w") as f:
            f.write(cert_pem)
        with open(data, "wb") as f:
            f.write(payload)
        with open(sig, "wb") as f:
            f.write(signature)
        r = subprocess.run([openssl, "x509", "-pubkey", "-noout", "-in", cert, "-out", pub],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        if r.returncode != 0:
            return False
        r = subprocess.run([openssl, "dgst", "-sha256", "-verify", pub, "-signature", sig, data],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
        return r.returncode == 0
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ------------------------------------------------------------------------------------------------ Firestore REST
def fs_value(v: Any) -> Any:
    if not isinstance(v, dict) or len(v) != 1:
        raise Unsupported("malformed value")
    kind, raw = next(iter(v.items()))
    if kind == "nullValue":
        return None
    if kind == "booleanValue":
        return bool(raw)
    if kind == "integerValue":
        return int(raw)
    if kind == "stringValue":
        return str(raw)
    if kind == "mapValue":
        return {k: fs_value(x) for k, x in ((raw or {}).get("fields") or {}).items()}
    if kind == "arrayValue":
        return [fs_value(x) for x in ((raw or {}).get("values") or [])]
    raise Unsupported(kind)   # doubleValue, timestampValue, bytesValue, referenceValue, geoPointValue


def fs_field(fields: Dict[str, Any], name: str) -> Tuple[bool, Any]:
    """(ok, value); ok False when the field holds a type vending never writes."""
    if name not in fields:
        return True, None
    try:
        return True, fs_value(fields[name])
    except Unsupported:
        return False, None


Fetch = Callable[[str, bool], Tuple[int, Any]]


def live_fetcher(token: str, project: str) -> Fetch:
    def fetch(url: str, authed: bool) -> Tuple[int, Any]:
        if authed and not (url.startswith(FIRESTORE_V1) or url.startswith(CRM_V3_PROJECTS)):
            raise CheckError("internal: the token goes only to Firestore and Resource Manager projects.get")
        if not authed and not url.startswith(X509_URL):
            raise CheckError("internal: unexpected unauthenticated URL")
        headers = {"Accept": "application/json"}
        if authed:
            headers["Authorization"] = "Bearer " + token
            headers["X-Goog-User-Project"] = project
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8") or "{}")
        except urllib.error.HTTPError as e:
            return e.code, None
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise CheckError(f"GET failed ({type(e).__name__})") from None
    return fetch


def offline_fetcher(directory: str) -> Fetch:
    """Maps the live URLs to DIR/workloads.json, DIR/provenance.json, DIR/certs.json (one page each)."""
    def name_for(url: str) -> str:
        if url.startswith(X509_URL):
            return "certs"
        if url.startswith(CRM_V3_PROJECTS):
            return "crm-" + url[len(CRM_V3_PROJECTS):]   # DIR/crm-<project id or number>.json (+ .http)
        path = urllib.parse.urlparse(url).path
        if path.endswith(f"/documents/{WORKLOADS}"):
            return "workloads"
        if path.endswith(f"/documents/{PROVENANCE}"):
            return "provenance"
        raise CheckError(f"offline: no file for {url}")

    def fetch(url: str, authed: bool) -> Tuple[int, Any]:
        name = name_for(url)
        code_path = os.path.join(directory, name + ".http")
        if os.path.exists(code_path):
            with open(code_path) as f:
                code = int(f.read().strip() or "0")
            if code != 200:
                return code, None
        try:
            with open(os.path.join(directory, name + ".json")) as f:
                return 200, json.load(f)
        except OSError:
            return 404, None
        except ValueError:
            raise CheckError(f"offline: {name}.json is not JSON") from None
    return fetch


def list_documents(fetch: Fetch, project: str, database: str, collection: str,
                   mask: List[str]) -> Dict[str, Dict[str, Any]]:
    """{doc_id: fields} of every document of a top-level collection (all pages). CheckError on any non-200."""
    out: Dict[str, Dict[str, Any]] = {}
    token: Optional[str] = None
    for _ in range(10000):
        query = [("pageSize", str(PAGE_SIZE))] + [("mask.fieldPaths", m) for m in mask]
        if token:
            query.append(("pageToken", token))
        url = (f"{FIRESTORE_V1}projects/{urllib.parse.quote(project)}/databases/{urllib.parse.quote(database)}"
               f"/documents/{collection}?{urllib.parse.urlencode(query)}")
        status, body = fetch(url, True)
        if status != 200 or not isinstance(body, dict):
            raise CheckError(f"reading {database}/{collection} answered HTTP {status}")
        for doc in body.get("documents") or []:
            name = doc.get("name") if isinstance(doc, dict) else None
            if not isinstance(name, str) or "/documents/" not in name:
                raise CheckError(f"{database}/{collection}: a document without a name")
            out[name.rsplit("/", 1)[-1]] = doc.get("fields") or {}
        token = body.get("nextPageToken")
        if not token:
            return out
    raise CheckError(f"{database}/{collection}: too many pages")


def pending_deletion_state(fetch: Fetch, project_id: str, number: Any) -> Optional[str]:
    """SAT-40 option G. The project's typed Resource Manager state when it is exactly a pending-deletion state AND the
    answer names this project (projectId; and name projects/<number> when the ledger has a number, which is then the
    key of the projects.get); else None: unreadable, 403 / 404, any other state or identity keeps blocking (fail
    closed)."""
    if not is_project_id(project_id):
        return None
    raw = str(number) if isinstance(number, (int, str)) and not isinstance(number, bool) else ""
    key = raw if raw.isascii() and raw.isdigit() else project_id
    status, body = fetch(CRM_V3_PROJECTS + urllib.parse.quote(key, safe=""), True)
    if status != 200 or not isinstance(body, dict) or body.get("projectId") != project_id:
        return None
    if key != project_id and body.get("name") != f"projects/{key}":
        return None
    state = body["state"] if "state" in body else body.get("lifecycleState")
    return state if isinstance(state, str) and state in PENDING_DELETION_STATES else None


def fetch_certs(fetch: Fetch, broker: str) -> Dict[str, str]:
    status, body = fetch(X509_URL + urllib.parse.quote(broker), False)
    if status != 200 or not isinstance(body, dict) or not body:
        raise CheckError(f"x509 certificates of {broker} answered HTTP {status}")
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in body.items()):
        raise CheckError(f"x509 certificates of {broker}: unexpected body")
    return body


# ------------------------------------------------------------------------------------------------ readiness
def live_workloads(ledger: Dict[str, Dict[str, Any]]) -> List[Tuple[str, str, Any]]:
    """[(product_id, project_id, status)] of the workloads a step-B switch must not strand."""
    out = []
    for pid, fields in sorted(ledger.items()):
        if pid in PLATFORM_PSEUDO_WORKLOADS:
            continue
        _ok, is_castor = fs_field(fields, "is_castor")
        _ok, status = fs_field(fields, "status")
        ok, project_id = fs_field(fields, "project_id")
        if is_castor is True or status in CLOSED_STATUSES:
            continue
        if not ok or not isinstance(project_id, str) or not project_id:
            continue   # not vended yet: the vend creates its runner identity (Per workload)
        out.append((pid, project_id, status))
    return out


def evaluate(pid: str, project_id: str, prov_fields: Optional[Dict[str, Any]], broker: str,
             certs: Dict[str, str], verify: Callable[[str, bytes, bytes], bool]) -> Tuple[str, str]:
    """(state, detail): state READY or one of NO_PROVENANCE, NO_RUNNER_IDENTITY, UNSIGNED, MISMATCH, NOT_READY,
    REPOSITORY_NOT_PINNED (SAT-41: READY without a pinned repository is not ready for step B)."""
    if prov_fields is None:
        return "NO_PROVENANCE", f"{PROVENANCE}/{pid} does not exist (run the provenance backfill first)"
    ok, prov_project = fs_field(prov_fields, "project_id")
    if not ok or prov_project != project_id:
        return "MISMATCH", f"provenance project {prov_project!r} differs from the workload record's {project_id!r}"
    if RUNNER_IDENTITY_FIELD not in prov_fields:
        return "NO_RUNNER_IDENTITY", "no runner identity yet (run the runner identity backfill)"
    try:
        rec = fs_value(prov_fields[RUNNER_IDENTITY_FIELD])
    except Unsupported as e:
        return "UNSIGNED", f"the record holds a {e} value, which vending never signs"
    if not isinstance(rec, dict):
        return "UNSIGNED", "the runner identity field is not a record"
    sig = rec.get("signature")
    if not isinstance(sig, dict) or sig.get("alg") != SIGNATURE_ALG:
        return "UNSIGNED", "no RS256 signature"
    key_id, value = sig.get("key_id"), sig.get("value")
    if not isinstance(key_id, str) or not key_id or not isinstance(value, str) or not value:
        return "UNSIGNED", "malformed signature"
    if rec.get("signed_by") != broker:
        return "UNSIGNED", f"not signed by the broker {broker}"
    try:
        raw_sig = base64.b64decode(value.encode("ascii"), validate=True)
        payload = canonical_payload(provenance_doc_path(pid), rec)
    except (ValueError, UnicodeEncodeError):
        return "UNSIGNED", "malformed signature or record"
    cert = certs.get(key_id)
    if cert is None:
        return "UNSIGNED", f"key {key_id} is not one of the broker's published keys"
    if not verify(cert, payload, raw_sig):
        return "UNSIGNED", "the signature does not verify"
    # Structural checks (shared/runner_identity.py check_runner_identity): never trust derived names from the record.
    if rec.get("schema") != SCHEMA:
        return "MISMATCH", f"schema {rec.get('schema')!r}"
    if rec.get("product_id") != pid:
        return "MISMATCH", "the record names another product"
    if rec.get("project_id") != project_id or not is_project_id(project_id):
        return "MISMATCH", f"record project {rec.get('project_id')!r} differs from {project_id!r}"
    number = rec.get("project_number")
    if not (isinstance(number, str) and number.isdigit()):
        return "MISMATCH", "no numeric project number"
    if rec.get("deployer_email") != deployer_email(project_id):
        return "MISMATCH", "the deployer is not the project's stackvend-deployer"
    if rec.get("state_prefix") != f"{STATE_PREFIX_ROOT}/{pid}":
        return "MISMATCH", "state prefix differs"
    if rec.get("status") != STATUS_READY:
        return "NOT_READY", f"status {rec.get('status')!r} (error {rec.get('error_class')!r})"
    if not is_state_bucket_name_for(project_id, rec.get("state_bucket")):
        return "MISMATCH", "the state bucket is not the project's"
    if rec.get("error_class") is not None:
        return "NOT_READY", f"READY but error {rec.get('error_class')!r} is recorded"
    # SAT-41 (pre-switch RT HIGH-1): a deploy that reads the workload's repository needs the repository pinned in the
    # signed record (else RUNNER_REPOSITORY_NOT_PINNED after the switch); records READY from the backfill before the
    # ensure_repository step had none.
    repo = rec.get("repository")
    if not (isinstance(repo, dict) and isinstance(repo.get("provider"), str) and repo.get("provider")
            and isinstance(repo.get("full_name"), str) and repo.get("full_name")):
        return REPOSITORY_NOT_PINNED, ("READY, but no repository is pinned: its deploys would be refused "
                                       "(RUNNER_REPOSITORY_NOT_PINNED); run the runner identity backfill for this "
                                       "workload again (step ensure_repository), or a full build")
    return STATUS_READY, (f"deployer {rec.get('deployer_email')}, bucket {rec.get('state_bucket')}, repository "
                          f"{repo.get('full_name')}")


def readiness(fetch: Fetch, project: str, broker: str,
              verify: Callable[[str, bytes, bytes], bool] = openssl_verify) -> Dict[str, Any]:
    broker = (broker or "").strip().lower()
    if account_id_of(broker) == "" or not is_project_id(project):
        raise CheckError("a valid --project and --broker service-account email are required")
    ledger = list_documents(fetch, project, DEFAULT_DB, WORKLOADS, ["status", "project_id", "is_castor",
                                                                    "project_number"])
    provenance = list_documents(fetch, project, GUARD_DB, PROVENANCE, ["project_id", RUNNER_IDENTITY_FIELD])
    live = live_workloads(ledger)
    certs = fetch_certs(fetch, broker) if live else {}
    rows = []
    for pid, project_id, status in live:
        state, detail = evaluate(pid, project_id, provenance.get(pid), broker, certs, verify)
        if state in PENDING_DELETION_LIFTS:   # SAT-40 option G; never a MISMATCH (review M1), never READY
            crm_state = pending_deletion_state(fetch, project_id, fs_field(ledger[pid], "project_number")[1])
            if crm_state:
                state, detail = (STATE_PENDING_DELETION,
                                 f"{state}; project is {crm_state} in Resource Manager (not blocking)")
        rows.append({"product_id": pid, "project_id": project_id, "ledger_status": status, "runner_identity": state,
                     "detail": detail})
    closed = [r for r in rows if r["runner_identity"] == STATE_PENDING_DELETION]
    not_ready = [r for r in rows if r["runner_identity"] not in (STATUS_READY, STATE_PENDING_DELETION)]
    return {"project": project, "broker": broker, "live_workloads": len(rows) - len(closed),
            "ready": len(rows) - len(closed) - len(not_ready), "not_ready": len(not_ready),
            "pending_deletion": len(closed), "workloads": rows}


def render_text(rep: Dict[str, Any]) -> str:
    lines = [f"FD-7L runner identity readiness (read-only) for host project {rep['project']}",
             f"Broker (record signer): {rep['broker']}",
             f"Live workloads: {rep['live_workloads']}; READY: {rep['ready']}; not ready: {rep['not_ready']}; "
             f"project pending deletion (not blocking): {rep.get('pending_deletion', 0)}", ""]
    for r in rep["workloads"]:
        lines.append(f"  {r['runner_identity']:<{len(STATE_PENDING_DELETION)}} {r['product_id']} ({r['project_id']}): "
                     f"{r['detail']}")
    if not rep["workloads"]:
        lines.append("  (no live workloads)")
    if rep.get("pending_deletion"):
        lines += ["", UNDELETE_NOTE]
    lines.append("")
    lines.append("RESULT: " + ("READY for step B" if rep["not_ready"] == 0 else
                               "NOT READY: run the runner identity backfill (including its ensure_repository step) "
                               "for the workloads above, then re-check"))
    return "\n".join(lines)


def deployers(fetch: Fetch, project: str) -> List[str]:
    if not is_project_id(project):
        raise CheckError("a valid --project is required")
    provenance = list_documents(fetch, project, GUARD_DB, PROVENANCE, ["project_id", RUNNER_IDENTITY_FIELD])
    out = set()
    for _pid, fields in provenance.items():
        if RUNNER_IDENTITY_FIELD not in fields:
            continue
        ok, project_id = fs_field(fields, "project_id")
        if ok and is_project_id(project_id):
            out.add(deployer_email(project_id))   # derived, never read from the record
    return sorted(out)


# ------------------------------------------------------------------------------------------------ plan switch
def _walk(obj: Any, path: Tuple[Any, ...]) -> Any:
    for step in path:
        if obj is True:
            return True
        if isinstance(step, int):
            if not isinstance(obj, list) or len(obj) <= step:
                return None
            obj = obj[step]
        else:
            if not isinstance(obj, dict):
                return None
            obj = obj.get(step)
    return obj


def plan_switches(plan: Dict[str, Any]) -> List[str]:
    """Addresses whose update/replace moves the runtime SA to a runner SA (or to one unknown at plan time)."""
    out = []
    for rc in plan.get("resource_changes") or []:
        path = RUNNER_ADDRESSES.get(rc.get("address"))
        if path is None:
            continue
        change = rc.get("change") or {}
        actions = change.get("actions") or []
        if "update" not in actions and not ("create" in actions and "delete" in actions):
            continue
        before = _walk(change.get("before"), path)
        after = _walk(change.get("after"), path)
        unknown = _walk(change.get("after_unknown"), path) is True
        if unknown or (after != before and account_id_of(after) in RUNNER_ACCOUNT_IDS):
            out.append(f"{rc.get('address')}: {before} -> {'(known after apply)' if unknown else after}")
    return out


# ------------------------------------------------------------------------------------------------ CLI
def _token_from_stdin() -> str:
    token = sys.stdin.readline().strip()
    if not token:
        raise CheckError("no access token on stdin (run: gcloud auth print-access-token)")
    return token


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan-switch")
    p.add_argument("--plan", required=True)
    c = sub.add_parser("check")
    c.add_argument("--project", required=True)
    c.add_argument("--broker", required=True)
    c.add_argument("--offline")
    c.add_argument("--json", action="store_true")
    d = sub.add_parser("deployers")
    d.add_argument("--project", required=True)
    d.add_argument("--offline")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "plan-switch":
            try:
                with open(args.plan) as f:
                    plan = json.load(f)
            except (OSError, ValueError):
                raise CheckError(f"cannot read the plan JSON {args.plan}") from None
            switches = plan_switches(plan)
            for s in switches:
                print(f"FD-7L runner identity switch in this plan: {s}", file=sys.stderr)
            return EXIT_SWITCH if switches else EXIT_READY
        fetch = offline_fetcher(args.offline) if args.offline else live_fetcher(_token_from_stdin(), args.project)
        if args.cmd == "deployers":
            print(json.dumps(deployers(fetch, args.project)))
            return EXIT_READY
        rep = readiness(fetch, args.project, args.broker)
        print(json.dumps(rep, indent=2, sort_keys=True) if args.json else render_text(rep))
        return EXIT_READY if rep["not_ready"] == 0 else EXIT_NOT_READY
    except CheckError as e:
        print(f"[ERROR] could not check: {e}", file=sys.stderr)
        return EXIT_UNCHECKED


if __name__ == "__main__":
    sys.exit(main())
