#!/usr/bin/env bash
# ==============================================================================
# STACKVEND: read-only install IAM check (FD-4DB, residual of FD-4CT; lane 18 destructive guards)
# ==============================================================================
# Usage:
#   PROJECT_ID=<id> bash scripts/check-install-iam.sh [--admin=<member>]... [--skip=<scope>]... [--json]
#   PROJECT_ID=<id> bash scripts/check-install-iam.sh --state-json=<file> ...   (state from `tofu show -json`)
#   bash scripts/check-install-iam.sh --offline=<dir> ...    (saved state + policies; no gcloud, no curl, no tofu)
#
# Reports IAM grants that were made OUTSIDE the platform Terraform and that reach past the lane 18 guards, on:
#   the host project, the managed workloads folder, the billing account, the deletion-safety tag (key and value)
#   and every StackVend service account (its own IAM policy).
# A grant is reported when it is not in the applied platform Terraform state AND either its role is guard-reaching
# for that scope (project / folder delete or IAM admin, stackvend-guard database writes, act-as on the platform
# service accounts, billing admin, tag admin / user, ...) or its member is a StackVend service account (any extra
# role). Each finding comes with why it matters and the gcloud command that removes it (never run here).
#
# Not reported: grants in the Terraform state; administrators (admin_email, admin_user_email, castor_admin_group
# from the tfvars, plus --admin=<member>); the host project's Google-managed service agents (unless they hold a
# destructive role); the installer's gcloud billing fallback grants (scripts/bootstrap.sh, BG-1); deleted principals;
# grants whose role does not reach the guards.
# FD-7L (Terraform runner identity, once its step A is applied) is also checked, Terraform-declared grants included:
# either runner SA (sa-stackvend-tf-applier / -tf-server) holding Secret Manager, platform state, folder, billing,
# job-update or token-minting access; any act-as / token grant ON a runner SA (except vending's optional act-as on the
# job SA and the upgrader sa-stackvend-upgrader's serviceAccountUser, SELFUP-B); a workload deployer (stackvend-deployer@<child>) bound in the host scopes; vending running as a shared
# identity (R9); and, on every deployer named by the guard-database provenance, any act-as / token grant other than
# vending's tokenCreator (the deployer list is read from Firestore with your token).
#
# Read-only: target resolution reads the tfvars with `tofu console` on a copy of variables.tf (no init, no state);
# the state is read with `gcloud storage cat`; the policies with getIamPolicy over REST (curl; the token goes to
# curl on stdin, never on the command line). Nothing is changed anywhere.
#
# --skip=<scope>: project | folder | billing | tags | service-accounts | deployers (e.g. --skip=billing when you
#                 cannot read the billing account's IAM). A skipped scope is listed as skipped and does not fail.
# --offline=<dir>: <dir>/state.json, <dir>/inputs.json ({"project", "folder", "billing_account", "organization",
#                 "admins", optional "deployers"}), <dir>/policies/<name>.json (+ optional <name>.http status).
#
# Exit: 0 no unexpected grants, 1 unexpected grants found, 2 could not check (a policy or the state unreadable).
# Bash 3.2 compatible. Guide: documentation/quickstart.md "Check for IAM grants made outside Terraform".
# ==============================================================================

set -u -o pipefail

ORIG_PWD="$(pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PLATFORM_DIR="${REPO_ROOT}/infra/platform"
HELPER="${SCRIPT_DIR}/common/install_iam_check.py"

# shellcheck source=common/platform_target.sh
. "${SCRIPT_DIR}/common/platform_target.sh"

# Every refusal of this read-only check means "could not check" (exit 2), never "findings" (exit 1).
sv_die() {
    echo -e "\033[0;31m[ERROR]\033[0m could not check: $*" >&2
    exit 2
}

usage() {
    sed -n '4,39p' "${BASH_SOURCE[0]}" >&2
    exit 2
}

ADMIN_ARGS=()
SKIP_ARGS=()
JSON_ARGS=()
STATE_JSON=""
OFFLINE_DIR=""
for arg in "$@"; do
    case "${arg}" in
        --admin=*) [ -n "${arg#--admin=}" ] || usage; ADMIN_ARGS+=("--admin=${arg#--admin=}") ;;
        --skip=project|--skip=folder|--skip=billing|--skip=tags|--skip=service-accounts|--skip=deployers) SKIP_ARGS+=("${arg}") ;;
        --state-json=*) STATE_JSON="$(sv_abspath "${arg#--state-json=}" "${ORIG_PWD}")" || sv_die "cannot resolve ${arg}" ;;
        --offline=*) OFFLINE_DIR="$(sv_abspath "${arg#--offline=}" "${ORIG_PWD}")" || sv_die "cannot resolve ${arg}" ;;
        --json) JSON_ARGS=("--json") ;;
        -h|--help|help) usage ;;
        *) echo "Unknown argument: ${arg}" >&2; usage ;;
    esac
done
if [ -n "${OFFLINE_DIR}" ] && [ -n "${STATE_JSON}" ]; then
    sv_die "--offline and --state-json cannot be combined (the offline dir holds its own state.json)."
fi

umask 077
WORK="$(mktemp -d 2>/dev/null)" || sv_die "cannot create a private temp dir."
cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT
mkdir "${WORK}/policies" || sv_die "cannot create ${WORK}/policies."
INPUTS="${WORK}/inputs.json"

if [ -n "${OFFLINE_DIR}" ]; then
    STATE="${OFFLINE_DIR}/state.json"
    [ -f "${STATE}" ] || sv_die "no ${STATE}."
    [ -f "${OFFLINE_DIR}/inputs.json" ] || sv_die "no ${OFFLINE_DIR}/inputs.json."
    cp "${OFFLINE_DIR}/inputs.json" "${INPUTS}" || sv_die "cannot copy ${OFFLINE_DIR}/inputs.json."
else
    sv_detect_iac_bin
    sv_scrub_tofu_env
    sv_resolve_platform_target
    folder="$(sv_tfvar castor_managed_workloads_folder_id)" || sv_die "cannot read castor_managed_workloads_folder_id from ${TFVARS}."
    billing="$(sv_tfvar billing_account_id)" || sv_die "cannot read billing_account_id from ${TFVARS}."
    org="$(sv_tfvar organization_id)" || sv_die "cannot read organization_id from ${TFVARS}."
    admin_email="$(sv_tfvar admin_email)" || sv_die "cannot read admin_email from ${TFVARS}."
    admin_user_email="$(sv_tfvar admin_user_email)" || sv_die "cannot read admin_user_email from ${TFVARS}."
    admin_group="$(sv_tfvar castor_admin_group)" || sv_die "cannot read castor_admin_group from ${TFVARS}."
    python3 - "${INPUTS}" "${PROJECT_ID}" "${folder}" "${billing}" "${org}" "${admin_email}" "${admin_user_email}" "${admin_group}" <<'PY' || sv_die "cannot write the check inputs."
import json, sys
out, project, folder, billing, org, admin_email, admin_user_email, admin_group = sys.argv[1:9]
admins = []
for value, default_kind in ((admin_email, "user"), (admin_user_email, "user"), (admin_group, "group")):
    if value:
        admins.append(value if ":" in value else default_kind + ":" + value)
with open(out, "w") as f:
    json.dump({"project": project, "folder": folder, "billing_account": billing, "organization": org,
               "admins": admins}, f)
PY
    if [ -n "${STATE_JSON}" ]; then
        STATE="${STATE_JSON}"
        [ -f "${STATE}" ] || sv_die "--state-json file ${STATE} does not exist."
    else
        STATE="${WORK}/state.json"
        sv_info "Reading the applied platform state (read-only): gs://${STATE_BUCKET}/platform/state/default.tfstate"
        gcloud storage cat "gs://${STATE_BUCKET}/platform/state/default.tfstate" > "${STATE}" 2>/dev/null \
            || sv_die "cannot read gs://${STATE_BUCKET}/platform/state/default.tfstate (no platform state, or no read access)."
    fi
    # FD-7L: once the runner identity step A is in the state, list the workload deployers from the guard-database
    # provenance (read-only Firestore GETs with your token on stdin) so their own IAM policies are checked too.
    skip_deployers=""
    for a in ${SKIP_ARGS[@]+"${SKIP_ARGS[@]}"}; do
        [ "${a}" = "--skip=deployers" ] && skip_deployers=1
    done
    installed="$(python3 "${HELPER}" runner-identity-installed --state "${STATE}")" || exit 2
    if [ "${installed}" = "yes" ] && [ -z "${skip_deployers}" ]; then
        ri_token="$(gcloud auth print-access-token 2>/dev/null)" || ri_token=""
        [ -n "${ri_token}" ] || sv_die "'gcloud auth print-access-token' failed. Run: gcloud auth login"
        sv_info "Listing workload deployers from the guard database (read-only): ${PROJECT_ID}/stackvend-guard workload_provenance"
        deployers_json="$(printf '%s\n' "${ri_token}" | python3 "${SCRIPT_DIR}/common/runner_identity_readiness.py" deployers --project "${PROJECT_ID}")" \
            || sv_die "cannot list the workload deployers from the guard database (or pass --skip=deployers)."
        ri_token=""
        python3 - "${INPUTS}" "${deployers_json}" <<'PY' || sv_die "cannot write the check inputs."
import json, sys
path, deployers = sys.argv[1], json.loads(sys.argv[2])
with open(path) as f:
    d = json.load(f)
d["deployers"] = deployers
with open(path, "w") as f:
    json.dump(d, f)
PY
    fi
fi

python3 "${HELPER}" targets --state "${STATE}" --inputs "${INPUTS}" ${SKIP_ARGS[@]+"${SKIP_ARGS[@]}"} > "${WORK}/targets.tsv" \
    || exit 2

if [ -n "${OFFLINE_DIR}" ]; then
    while IFS=$'\t' read -r name method url body; do
        [[ "${name}" =~ ^[a-z0-9_-]+$ ]] || sv_die "unexpected target name '${name}'."
        for ext in json http; do
            if [ -f "${OFFLINE_DIR}/policies/${name}.${ext}" ]; then
                cp "${OFFLINE_DIR}/policies/${name}.${ext}" "${WORK}/policies/${name}.${ext}" || sv_die "cannot copy ${name}.${ext}."
            fi
        done
    done < "${WORK}/targets.tsv"
else
    token="$(gcloud auth print-access-token 2>/dev/null)" || token=""
    [ -n "${token}" ] || sv_die "'gcloud auth print-access-token' failed. Run: gcloud auth login"
    while IFS=$'\t' read -r name method url body; do
        [[ "${name}" =~ ^[a-z0-9_-]+$ ]] || sv_die "unexpected target name '${name}'."
        case "${method}" in GET|POST) ;; *) sv_die "unexpected method '${method}' for ${name}." ;; esac
        # The token only ever goes to the three Google APIs this check reads.
        case "${url}" in
            https://cloudresourcemanager.googleapis.com/*|https://cloudbilling.googleapis.com/*|https://iam.googleapis.com/*) ;;
            *) sv_die "unexpected URL for ${name}." ;;
        esac
        data_args=()
        [ "${body}" = "-" ] || data_args=(--data "${body}")
        code="$(printf 'header = "Authorization: Bearer %s"\n' "${token}" | curl -sS --max-time 30 --config - \
            -X "${method}" -H "Content-Type: application/json" ${data_args[@]+"${data_args[@]}"} \
            -o "${WORK}/policies/${name}.json" -w '%{http_code}' "${url}" 2>/dev/null)" || code="${code:-none}"
        printf '%s\n' "${code:-none}" > "${WORK}/policies/${name}.http"
    done < "${WORK}/targets.tsv"
    token=""
fi

# BG-1: scripts/bootstrap.sh may make these billing grants with gcloud when Terraform skipped them (same lists).
FALLBACK_ARGS=()
for sa in "${SV_BILLING_USER_SAS[@]}"; do
    FALLBACK_ARGS+=("--billing-fallback=roles/billing.user=${sa}")
done
FALLBACK_ARGS+=("--billing-fallback=roles/billing.viewer=${SV_BILLING_VIEWER_SA}")

python3 "${HELPER}" analyze --state "${STATE}" --inputs "${INPUTS}" --policies "${WORK}/policies" \
    ${ADMIN_ARGS[@]+"${ADMIN_ARGS[@]}"} ${SKIP_ARGS[@]+"${SKIP_ARGS[@]}"} "${FALLBACK_ARGS[@]}" \
    ${JSON_ARGS[@]+"${JSON_ARGS[@]}"}
rc=$?
case "${rc}" in
    0|1|2) exit "${rc}" ;;
    *) echo "[ERROR] could not check: the analysis failed (rc=${rc})." >&2; exit 2 ;;
esac
