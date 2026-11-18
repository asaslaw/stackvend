#!/usr/bin/env bash
# ==============================================================================
# STACKVEND: STAGE-JOB RUNNER SWITCH (STAGE-JOB-RUNNER rollback, red team N1)
# ==============================================================================
# Turns the stage-runner jobs off (architect / developer / QA run through the gateway's synchronous routes, as
# before LONG-STAGE-CALLBACK) or back on, at run time: no deploy, no apply, no code edit. A stage already running in
# a stage-runner job finishes there; the next stage of every run follows the switch (the gateway caches it 15 s).
#
# Usage (the target project is REQUIRED):
#   PROJECT_ID=<id> bash scripts/stage-jobs-switch.sh off
#   PROJECT_ID=<id> bash scripts/stage-jobs-switch.sh on
#   PROJECT_ID=<id> bash scripts/stage-jobs-switch.sh status
# Writes Firestore governance/stage_jobs with your own gcloud credentials (scripts/common/stage_jobs_switch.py).
# ==============================================================================
set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common/platform_target.sh
. "${SCRIPT_DIR}/common/platform_target.sh"

ACTION="${1:-}"
case "${ACTION}" in
    on|off|status) ;;
    *) sv_die "Usage: PROJECT_ID=<id> bash scripts/stage-jobs-switch.sh on|off|status" ;;
esac
[ -n "${PROJECT_ID:-}" ] || sv_die "No target project. Set PROJECT_ID=<id>."
sv_valid_project_id "${PROJECT_ID}" || sv_die "PROJECT_ID '${PROJECT_ID}' is not a valid GCP project id."

TOKEN="$(gcloud auth print-access-token --quiet 2>/dev/null)" || TOKEN=""
[ -n "${TOKEN}" ] || sv_die "No gcloud access token (run gcloud auth login)."
ACCOUNT="$(gcloud config get-value account 2>/dev/null)" || ACCOUNT=""

if [ "${ACTION}" == "status" ]; then
    printf '%s\n' "${TOKEN}" | python3 "${SCRIPT_DIR}/common/stage_jobs_switch.py" status --project "${PROJECT_ID}" --token-stdin
else
    printf '%s\n' "${TOKEN}" | python3 "${SCRIPT_DIR}/common/stage_jobs_switch.py" set --project "${PROJECT_ID}" \
        --state "${ACTION}" --set-by "${ACCOUNT}" --token-stdin
fi
