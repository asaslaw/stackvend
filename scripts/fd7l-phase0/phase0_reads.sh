#!/usr/bin/env bash
# ==============================================================================
# STACKVEND: FD-7L Phase 0 -- read-only live checks (per-workload Terraform runner identity)
# ==============================================================================
# Usage:
#   PROJECT_ID=<host project> REGION=<platform region> bash scripts/fd7l-phase0/phase0_reads.sh [--max-children=N]
#       [--state-dir=<empty dir>]
#
# Plan: docs/planning/fd-7l-per-workload-runner-identity-plan.md rev 3, section 8 row 0. Every call here is a READ:
# gcloud describe / list / get-iam-policy / org-policies describe / logging read / storage ls+cat, and REST GETs
# (Firestore documents, x509 certificates). Nothing is created, changed, run, impersonated or deleted. The access
# token goes to curl on stdin, never on the command line.
#
# Output: one line per fact, `P0-<check> <PASS|FINDING|INFO> <subject> <detail>`. The pass criteria per check are in
# docs/handoff/sat-19-report.md section 3. `--state-dir` (an EMPTY directory you own) also copies each workload's
# live state there for scripts/fd7l-phase0/state_scan.py; delete the directory afterwards (state holds secrets).
#
# Not in this script (they are not read-only; each needs the owner's approval as a separate step): the metadata
# probe inside a tf-applier execution, the D3-a start-cost measurement, the RunJob CLOUD_RUN_* override refusal
# check, and the broker mint latency. See the report.
#
# Exit: 0 when every check could run (findings are reported, not fatal), 2 when a required read failed.
# Bash 3.2 compatible.
# ==============================================================================

set -u -o pipefail

die() { echo "[ERROR] could not check: $*" >&2; exit 2; }

PROJECT_RE='^[a-z][a-z0-9-]{4,28}[a-z0-9]$'
REGION_RE='^[a-z]+-[a-z]+[0-9]+$'
MAX_CHILDREN=200
STATE_DIR=""
for arg in "$@"; do
    case "$arg" in
        --max-children=*) MAX_CHILDREN="${arg#*=}" ;;
        --state-dir=*) STATE_DIR="${arg#*=}" ;;
        -h|--help) sed -n '4,24p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "unknown argument $arg" ;;
    esac
done

[ -n "${PROJECT_ID:-}" ] || die "PROJECT_ID is required (the StackVend host project)"
[ -n "${REGION:-}" ] || die "REGION is required (the platform region; no default)"
[[ "$PROJECT_ID" =~ $PROJECT_RE ]] || die "PROJECT_ID '$PROJECT_ID' is not a project id"
[[ "$REGION" =~ $REGION_RE ]] || die "REGION '$REGION' is not a region"
[[ "$MAX_CHILDREN" =~ ^[0-9]+$ ]] || die "--max-children must be a number"
if [ -n "$STATE_DIR" ]; then
    [ -d "$STATE_DIR" ] || die "--state-dir $STATE_DIR does not exist"
    [ -z "$(ls -A "$STATE_DIR")" ] || die "--state-dir $STATE_DIR is not empty"
fi
command -v gcloud >/dev/null || die "gcloud not found"
command -v curl >/dev/null || die "curl not found"
command -v python3 >/dev/null || die "python3 not found"

TOKEN="$(gcloud auth print-access-token 2>/dev/null)" || die "gcloud auth print-access-token failed"
[ -n "$TOKEN" ] || die "empty access token"

GET() {  # GET <url> -> sets BODY and HTTP_STATUS in THIS shell (call it directly, never inside $(...))
    local out
    BODY=""; HTTP_STATUS="transport"
    out="$(printf 'header = "Authorization: Bearer %s"\n' "$TOKEN" | curl -sS --config - -w '\n%{http_code}' "$1")" || return 1
    HTTP_STATUS="${out##*$'\n'}"
    BODY="${out%$'\n'*}"
}

say() { echo "P0-$1 $2 $3 ${4:-}"; }
json() { python3 -c "$1" 2>/dev/null; }

VENDING_SA="sa-project-provisioner@${PROJECT_ID}.iam.gserviceaccount.com"
DEVELOPER_SA="sa-castor-developer@${PROJECT_ID}.iam.gserviceaccount.com"
export VENDING_SA DEVELOPER_SA   # read by the inline python below (os.environ)

# ------------------------------------------------------------------ A. runtime identities and vending env
VEND_JSON="$(gcloud run services describe project-repo-vending-service --project="$PROJECT_ID" --region="$REGION" \
    --format=json 2>/dev/null)" || die "describe project-repo-vending-service"
VEND_RUNTIME="$(printf '%s' "$VEND_JSON" | json 'import json,sys; print(json.load(sys.stdin)["spec"]["template"]["spec"].get("serviceAccountName",""))')"
if [ "$VEND_RUNTIME" = "$VENDING_SA" ]; then say A PASS vending-runtime "$VEND_RUNTIME"
else say A FINDING vending-runtime "$VEND_RUNTIME (expected $VENDING_SA; the broker refuses a shared identity)"; fi
printf '%s' "$VEND_JSON" | json '
import json, sys
spec = json.load(sys.stdin)["spec"]["template"]["spec"]
env = {e["name"]: e.get("value", "<secret ref>") for c in spec["containers"] for e in c.get("env", [])}
for k in ("STACKVEND_CHILD_PROJECT_OWNER_MEMBERS", "STACKVEND_TF_RUNNER_IDENTITY", "STACKVEND_BROKER_SA",
          "STACKVEND_TF_RUNNER_MEMBERS", "STACKVEND_TF_SERVER_MEMBERS", "STACKVEND_GUARD_FIRESTORE_DATABASE",
          "STACKVEND_MANAGED_TAG_VALUE", "MANAGED_WORKLOADS_FOLDER_ID", "VENDING_SERVICE_URL", "TFSTATE_BUCKET"):
    print("P0-A INFO vending-env", k + "=" + repr(env.get(k)))
'
TFSTATE_BUCKET="$(printf '%s' "$VEND_JSON" | json 'import json,sys
spec=json.load(sys.stdin)["spec"]["template"]["spec"]
print(next((e.get("value","") for c in spec["containers"] for e in c.get("env",[]) if e["name"]=="TFSTATE_BUCKET"),""))')"
FOLDER="$(printf '%s' "$VEND_JSON" | json 'import json,sys
spec=json.load(sys.stdin)["spec"]["template"]["spec"]
print(next((e.get("value","") for c in spec["containers"] for e in c.get("env",[]) if e["name"]=="MANAGED_WORKLOADS_FOLDER_ID"),""))')"
FOLDER="${FOLDER#folders/}"

for svc in mcp-terraform-server product-control-center-ui; do
    sa="$(gcloud run services describe "$svc" --project="$PROJECT_ID" --region="$REGION" \
        --format='value(spec.template.spec.serviceAccountName)' 2>/dev/null)" || sa="<unreadable>"
    say A INFO "runtime:$svc" "$sa"
done
JOB_JSON="$(gcloud run jobs describe tf-applier --project="$PROJECT_ID" --region="$REGION" --format=json 2>/dev/null)" \
    || die "describe tf-applier job"
JOB_SA="$(printf '%s' "$JOB_JSON" | json 'import json,sys
j=json.load(sys.stdin); t=j["spec"]["template"]["spec"]["template"]["spec"]; print(t.get("serviceAccountName",""))')"
if [ "$JOB_SA" = "$DEVELOPER_SA" ]; then say A PASS runtime:tf-applier "$JOB_SA (listed by the pre-step-A member default)"
else say A FINDING runtime:tf-applier "$JOB_SA (not $DEVELOPER_SA: set STACKVEND_TF_RUNNER_MEMBERS before PER_WORKLOAD)"; fi

# ------------------------------------------------------------------ B. vending self-signBlob + published certificates
VPOL="$(gcloud iam service-accounts get-iam-policy "$VENDING_SA" --project="$PROJECT_ID" --format=json 2>/dev/null)" \
    || die "get-iam-policy $VENDING_SA"
SELF="$(printf '%s' "$VPOL" | json '
import json, os, sys
p = json.load(sys.stdin); me = "serviceAccount:" + os.environ["VENDING_SA"]
holders = sorted({m for b in p.get("bindings", []) if b["role"] == "roles/iam.serviceAccountTokenCreator" for m in b["members"]})
print("yes" if me in holders else "no", ",".join(holders) or "-")')"
case "$SELF" in
    yes*) say B PASS vending-self-signblob "tokenCreator holders: ${SELF#* }" ;;
    *) say B FINDING vending-self-signblob "vending cannot signBlob as itself yet (plan step A grant); tokenCreator holders: ${SELF#* }" ;;
esac
CERTS="$(curl -sS "https://www.googleapis.com/service_accounts/v1/metadata/x509/${VENDING_SA}")" || die "x509 certificates"
NKEYS="$(printf '%s' "$CERTS" | json 'import json,sys; print(len(json.load(sys.stdin)))')"
if [ "${NKEYS:-0}" -ge 1 ] 2>/dev/null; then say B INFO vending-x509-certs "$NKEYS published key(s)"
else say B FINDING vending-x509-certs "no published certificate"; fi
# RT F1: each published key id with its validity window (openssl reads the certificate only). Re-run a week later and
# compare: the key ids that disappeared give Google's real retention, which bounds RESIGN_AFTER_SECONDS (72 h).
if command -v openssl >/dev/null; then
    export CERTS
    KEYDATES="$(json '
import json, os
for kid, pem in sorted(json.loads(os.environ["CERTS"]).items()):
    print(kid + "\t" + pem.replace("\n", "\\n"))
' | while IFS="$(printf '\t')" read -r kid pem; do
        start="$(printf '%b' "$pem" | openssl x509 -noout -startdate 2>/dev/null)"
        end="$(printf '%b' "$pem" | openssl x509 -noout -enddate 2>/dev/null)"
        printf '%s\t%s\t%s\n' "$kid" "${start#notBefore=}" "${end#notAfter=}"
    done)"
    printf '%s\n' "$KEYDATES" | json '
import sys
from datetime import datetime, timedelta, timezone
rows = [line.rstrip("\n").split("\t") for line in sys.stdin if line.strip()]
now = datetime.now(timezone.utc)
soon = 0
for row in rows:
    kid, start, end = (row + ["", "", ""])[:3]
    try:
        left = datetime.strptime(" ".join(end.split()), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc) - now
    except ValueError:
        left = None
    soon += left is None or left < timedelta(days=30)
    print("P0-B INFO vending-key", kid, "notBefore=" + " ".join(start.split()), "notAfter=" + " ".join(end.split()))
ok = len(rows) >= 2 and soon == 0
print("P0-B", "PASS" if ok else "FINDING", "vending-key-validity",
      "%d key(s), %d without 30 days of validity left" % (len(rows), soon))
'
else
    say B FINDING vending-key-validity "openssl not found: key validity windows not read"
fi

# ------------------------------------------------------------------ C. host APIs used by the broker
HOST_APIS="$(gcloud services list --enabled --project="$PROJECT_ID" --format='value(config.name)' 2>/dev/null)" \
    || die "services list on the host"
for api in iamcredentials.googleapis.com iam.googleapis.com run.googleapis.com firestore.googleapis.com; do
    if printf '%s\n' "$HOST_APIS" | grep -qx "$api"; then say C PASS "host-api:$api" enabled
    else say C FINDING "host-api:$api" "not enabled on the host"; fi
done

# ------------------------------------------------------------------ D. managed folder IAM (inherited child rights)
if [ -n "$FOLDER" ]; then
    gcloud resource-manager folders get-iam-policy "$FOLDER" --format=json 2>/dev/null | json '
import json, os, sys
p = json.load(sys.stdin)
for who in ("VENDING_SA", "DEVELOPER_SA"):
    m = "serviceAccount:" + os.environ[who]
    roles = sorted(b["role"] for b in p.get("bindings", []) if m in b.get("members", []))
    print("P0-D INFO folder-roles:" + os.environ[who], ",".join(roles) or "-")
' || say D FINDING folder-iam "managed folder $FOLDER IAM unreadable"
else
    say D FINDING folder-iam "MANAGED_WORKLOADS_FOLDER_ID is not set on vending"
fi

# ------------------------------------------------------------------ E. per child: provenance, rights, APIs, deployer, bucket name, org policies
GET "https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/workloads?pageSize=300" \
    || die "workloads ledger read"
[ "$HTTP_STATUS" = "200" ] || die "workloads ledger read HTTP $HTTP_STATUS"
WORKLOADS="$BODY"
GET "https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/stackvend-guard/documents/workload_provenance?pageSize=300" \
    || die "provenance read"
[ "$HTTP_STATUS" = "200" ] || die "provenance read HTTP $HTTP_STATUS (guard database)"
PROV="$BODY"
export WORKLOADS PROV
CHILDREN="$(json '
import json, os
raw = [os.environ["WORKLOADS"], os.environ["PROV"]]
def docs(text):
    try:
        return json.loads(text).get("documents", [])
    except Exception:
        return []
def val(f):
    if not isinstance(f, dict): return None
    for k in ("stringValue", "integerValue", "booleanValue"):
        if k in f: return f[k]
    return None
prov = {d["name"].rsplit("/", 1)[-1]: d.get("fields", {}) for d in docs(raw[1])}
for d in docs(raw[0]):
    f = d.get("fields", {}); pid = d["name"].rsplit("/", 1)[-1]
    if val(f.get("is_castor")) is True or val(f.get("status")) in ("DECOMMISSIONED", "DELETED", "ARCHIVED"): continue
    proj = val(f.get("project_id"))
    if not proj: continue
    p = prov.get(pid, {})
    print(pid, proj, val(p.get("created_by")) or "-", "signed" if "runner_identity" in p else "-")
')"
COUNT=0
LEGACY_NO_RIGHTS=0
while read -r pid proj created_by ri_field; do
    [ -n "${pid:-}" ] || continue
    COUNT=$((COUNT + 1))
    [ "$COUNT" -le "$MAX_CHILDREN" ] || { say E INFO limit "stopped after $MAX_CHILDREN children"; break; }
    # SAT-40 option G: a project Resource Manager reports exactly pending deletion is listed on its own line and gets
    # no further checks (the readiness gate does not count it); an unreadable project keeps every check (fail closed).
    LSTATE="$(gcloud projects describe "$proj" --format='value(lifecycleState)' 2>/dev/null)" || LSTATE=""
    case "$LSTATE" in
        DELETE_REQUESTED|DELETE_IN_PROGRESS)
            say E INFO "closed-project:$pid" "CLOSED_PROJECT_PENDING_DELETION $proj is $LSTATE (not blocking)"
            continue ;;
    esac
    if [ "$created_by" = "-" ]; then say E FINDING "provenance:$pid" "no provenance record (backfill_provenance.py first)"
    else say E PASS "provenance:$pid" "created_by=$created_by runner_identity=$ri_field"; fi
    POL="$(gcloud projects get-iam-policy "$proj" --format=json 2>/dev/null)"
    if [ -z "$POL" ]; then
        say E FINDING "child-iam:$pid" "$proj IAM unreadable by the operator"
    else
        OWN="$(printf '%s' "$POL" | json '
import json, os, sys
p = json.load(sys.stdin); m = "serviceAccount:" + os.environ["VENDING_SA"]
r = sorted(b["role"] for b in p.get("bindings", []) if m in b.get("members", []) and not b.get("condition"))
print("owner" if "roles/owner" in r else (",".join(r) or "none"))')"
        if [ "$OWN" = "owner" ]; then say E PASS "vending-rights:$pid" "vending is owner of $proj"
        else LEGACY_NO_RIGHTS=$((LEGACY_NO_RIGHTS + 1)); say E FINDING "vending-rights:$pid" "vending roles on $proj: $OWN (fallback F-B for the backfill)"; fi
    fi
    if APIS="$(gcloud services list --enabled --project="$proj" --format='value(config.name)' 2>/dev/null)"; then
        for api in iam.googleapis.com iamcredentials.googleapis.com storage.googleapis.com; do
            if printf '%s\n' "$APIS" | grep -qx "$api"; then :; else say E FINDING "child-api:$pid" "$api not enabled on $proj"; fi
        done
    else
        say E FINDING "child-api:$pid" "enabled APIs of $proj unreadable by the operator (not the same as 'not enabled')"
    fi
    DEP="$(gcloud iam service-accounts list --project="$proj" --format='value(email)' \
        --filter="email=stackvend-deployer@${proj}.iam.gserviceaccount.com" 2>/dev/null)"
    say E INFO "deployer:$pid" "${DEP:-none}"
    GET "https://storage.googleapis.com/storage/v1/b/${proj}-tfstate" >/dev/null || HTTP_STATUS="transport"
    case "$HTTP_STATUS" in
        404) say E PASS "bucket-name:$pid" "${proj}-tfstate is free" ;;
        200) say E INFO "bucket-name:$pid" "${proj}-tfstate exists and is readable (check its project)" ;;
        403) say E INFO "bucket-name:$pid" "${proj}-tfstate is taken by a project the operator cannot read (vending uses a -<6 hex> suffix)" ;;
        *) say E FINDING "bucket-name:$pid" "bucket read HTTP $HTTP_STATUS" ;;
    esac
    for c in iam.disableServiceAccountCreation iam.disableServiceAccountKeyCreation iam.allowedPolicyMemberDomains \
             gcp.restrictNonCmekServices gcp.resourceLocations storage.uniformBucketLevelAccess \
             storage.publicAccessPrevention storage.restrictAuthTypes; do
        EFF="$(gcloud org-policies describe "$c" --project="$proj" --effective --format=json 2>/dev/null \
            | json 'import json,sys; s=json.load(sys.stdin).get("spec",{}); print(json.dumps(s.get("rules",[]),sort_keys=True))')"
        say E INFO "org-policy:$pid:$c" "${EFF:-unset}"
    done
done <<EOF
$CHILDREN
EOF
say E INFO children "checked=$COUNT vending-without-owner=$LEGACY_NO_RIGHTS"

# ------------------------------------------------------------------ F. tf-applier executions: creator field, timing, overrides visibility
EXECS="$(gcloud run jobs executions list --job=tf-applier --project="$PROJECT_ID" --region="$REGION" --limit=10 \
    --format=json 2>/dev/null)" || die "executions list"
printf '%s' "$EXECS" | json '
import json, sys
from datetime import datetime
for e in json.load(sys.stdin):
    md, st = e.get("metadata", {}), e.get("status", {})
    def ts(v):
        return datetime.fromisoformat(v.replace("Z", "+00:00")) if v else None
    s, c = ts(st.get("startTime")), ts(st.get("completionTime"))
    creator = (md.get("annotations") or {}).get("run.googleapis.com/creator", "-")
    envs = sorted({x["name"] for ct in e.get("spec", {}).get("template", {}).get("spec", {}).get("containers", [])
                   for x in ct.get("env", [])})
    print("P0-F INFO execution", md.get("name"), "creator=" + creator,
          "seconds=" + (str(int((c - s).total_seconds())) if s and c else "-"), "env-names=" + ",".join(envs))
'
FIRST="$(printf '%s' "$EXECS" | json 'import json,sys; e=json.load(sys.stdin); print(e[0]["metadata"]["name"] if e else "")')"
if [ -n "$FIRST" ]; then
    GET "https://run.googleapis.com/v2/projects/${PROJECT_ID}/locations/${REGION}/jobs/tf-applier/executions/${FIRST}" || true
    if [ "$HTTP_STATUS" = "200" ]; then
        printf '%s' "$BODY" | json '
import json, sys
e = json.load(sys.stdin)
ok = isinstance(e.get("creator"), str) and "@" in e["creator"]
print("P0-F", "PASS" if ok else "FINDING", "v2-execution-creator", e.get("creator", "<absent: the broker check needs another source>"))
print("P0-F INFO v2-execution-fields", ",".join(sorted(e)))
'
    else say F FINDING v2-execution "HTTP $HTTP_STATUS"; fi
fi

# ------------------------------------------------------------------ G. RunJob audit entry: are override values logged? (re-RT R2)
gcloud logging read 'protoPayload.methodName:"RunJob" AND resource.labels.job_name="tf-applier"' \
    --project="$PROJECT_ID" --limit=1 --freshness=30d --format=json 2>/dev/null | json '
import json, sys
rows = json.load(sys.stdin)
if not rows:
    print("P0-G INFO runjob-audit no RunJob audit entry in 30 days (Data Access logs off?)")
else:
    req = (rows[0].get("protoPayload") or {}).get("request") or {}
    env = [x for c in ((req.get("overrides") or {}).get("containerOverrides") or []) for x in c.get("env", [])]
    print("P0-G INFO runjob-audit", "override env VALUES ARE LOGGED" if any("value" in x for x in env)
          else "override values not in the audit entry", "logName=" + rows[0].get("logName", "-"))
' || say G INFO runjob-audit "logging read failed"

# ------------------------------------------------------------------ H. vending latency (cold-start proxy for R6)
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="project-repo-vending-service" AND httpRequest.latency:*' \
    --project="$PROJECT_ID" --limit=200 --freshness=14d --format=json 2>/dev/null | json '
import json, sys
lat = sorted(float(r["httpRequest"]["latency"].rstrip("s")) for r in json.load(sys.stdin)
             if r.get("httpRequest", {}).get("latency"))
if lat:
    q = lambda p: lat[min(len(lat) - 1, int(p * len(lat)))]
    print("P0-H INFO vending-latency", "n=%d p50=%.2fs p95=%.2fs max=%.2fs" % (len(lat), q(.5), q(.95), lat[-1]))
else:
    print("P0-H INFO vending-latency no request logs")
' || say H INFO vending-latency "logging read failed"

# ------------------------------------------------------------------ I. live state copies for the cross-project scan (optional)
if [ -n "$STATE_DIR" ] && [ -n "$TFSTATE_BUCKET" ]; then
    while read -r pid proj _rest; do
        [ -n "${pid:-}" ] || continue
        if gcloud storage cat "gs://${TFSTATE_BUCKET}/workloads/${pid}/default.tfstate" > "${STATE_DIR}/${pid}.tfstate" 2>/dev/null; then
            printf '%s\n' "$proj" > "${STATE_DIR}/${pid}.project"
        else
            rm -f "${STATE_DIR}/${pid}.tfstate"
            say I INFO "state:$pid" "no live state object"
        fi
    done <<EOF
$CHILDREN
EOF
    say I INFO state-dir "copied to $STATE_DIR; run: python3 scripts/fd7l-phase0/state_scan.py $STATE_DIR ; then delete it"
fi
exit 0
