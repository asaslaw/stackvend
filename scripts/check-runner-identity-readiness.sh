#!/usr/bin/env bash
# ==============================================================================
# STACKVEND: read-only FD-7L step B readiness check (SAT-33, FD-7L-n)
# ==============================================================================
# Usage:
#   PROJECT_ID=<id> bash scripts/check-runner-identity-readiness.sh [--json]
#   bash scripts/check-runner-identity-readiness.sh --offline=<dir> --project=<id> [--json]   (saved reads; no gcloud)
#
# Before the step-B apply (tf_runner_dedicated_sa = true) every LIVE workload (default-database `workloads`, status
# not DECOMMISSIONED / DELETED / ARCHIVED, with a project) must hold a READY runner identity record in the guard
# database, signed by vending (sa-project-provisioner) and naming exactly that workload's project, deployer and state
# bucket. A workload without a usable record whose project Resource Manager reports exactly DELETE_REQUESTED /
# DELETE_IN_PROGRESS is listed as CLOSED_PROJECT_PENDING_DELETION and does not block (SAT-40 option G); a project
# that cannot be read still blocks. If such a project is restored, run the backfill for it before deploying it.
# scripts/apply.sh runs the same check automatically on a plan that switches the runners; run this first to see
# what the backfill still has to do.
#
# Read-only: the tfvars are read with `tofu console` on a copy of variables.tf; Firestore and (for workloads that are
# not READY) Resource Manager projects.get are read with GET requests and YOUR access token (passed on stdin, never
# on a command line); vending's public x509 certificates are read
# without a token; signatures are verified with the openssl command line. Nothing is changed anywhere.
#
# Exit: 0 every live workload READY (pending deletions do not count), 1 not ready (each one listed), 2 could not check.
# ==============================================================================

set -u -o pipefail

ORIG_PWD="$(pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PLATFORM_DIR="${REPO_ROOT}/infra/platform"
HELPER="${SCRIPT_DIR}/common/runner_identity_readiness.py"

# shellcheck source=common/platform_target.sh
. "${SCRIPT_DIR}/common/platform_target.sh"

# Every refusal of this read-only check means "could not check" (exit 2).
sv_die() {
    echo -e "\033[0;31m[ERROR]\033[0m could not check: $*" >&2
    exit 2
}

usage() {
    sed -n '4,23p' "${BASH_SOURCE[0]}" >&2
    exit 2
}

JSON_ARGS=()
OFFLINE_DIR=""
OFFLINE_PROJECT=""
for arg in "$@"; do
    case "${arg}" in
        --json) JSON_ARGS=("--json") ;;
        --offline=*) OFFLINE_DIR="$(sv_abspath "${arg#--offline=}" "${ORIG_PWD}")" || sv_die "cannot resolve ${arg}" ;;
        --project=*) OFFLINE_PROJECT="${arg#--project=}" ;;
        -h|--help|help) usage ;;
        *) echo "Unknown argument: ${arg}" >&2; usage ;;
    esac
done

if [ -n "${OFFLINE_DIR}" ]; then
    [ -n "${OFFLINE_PROJECT}" ] || sv_die "--offline needs --project=<host project id>."
    sv_valid_project_id "${OFFLINE_PROJECT}" || sv_die "--project '${OFFLINE_PROJECT}' is not a valid project id."
    python3 "${HELPER}" check --project "${OFFLINE_PROJECT}" \
        --broker "sa-project-provisioner@${OFFLINE_PROJECT}.iam.gserviceaccount.com" \
        --offline "${OFFLINE_DIR}" ${JSON_ARGS[@]+"${JSON_ARGS[@]}"} </dev/null
    exit $?
fi

[ -z "${OFFLINE_PROJECT}" ] || sv_die "--project is only for --offline (live mode reads the target from PROJECT_ID / the tfvars)."
sv_detect_iac_bin
sv_scrub_tofu_env
sv_resolve_platform_target
vrap="$(sv_tfvar vending_runs_as_provisioner)" || sv_die "cannot read vending_runs_as_provisioner from ${TFVARS}."
[ "${vrap}" = "true" ] || sv_die "vending_runs_as_provisioner is not true: vending is not on its own identity, so no record can be trusted as broker-signed (plan R9)."

token="$(gcloud auth print-access-token 2>/dev/null)" || token=""
[ -n "${token}" ] || sv_die "'gcloud auth print-access-token' failed. Run: gcloud auth login"
printf '%s\n' "${token}" | python3 "${HELPER}" check --project "${PROJECT_ID}" \
    --broker "sa-project-provisioner@${PROJECT_ID}.iam.gserviceaccount.com" ${JSON_ARGS[@]+"${JSON_ARGS[@]}"}
rc=$?
token=""
case "${rc}" in
    0|1|2) exit "${rc}" ;;
    *) echo "[ERROR] could not check: the readiness helper failed (rc=${rc})." >&2; exit 2 ;;
esac
