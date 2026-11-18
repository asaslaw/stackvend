#!/usr/bin/env bash
# ==============================================================================
# STACKVEND UPGRADER: THE STAGES AFTER STEP 0 (the verified release's own code)
# ==============================================================================
# Started by step 0 (scripts/upgrade/verify.sh, frozen in core Terraform) once the release tag is verified:
#   exec bash <work>/src/scripts/upgrade/run.sh <work>/verified.json
# UPGRADE:  PREFLIGHT -> BUILDING (all images, nothing deployed unless all built) -> DEPLOYING (image-only, CC last)
#           -> version record (scripts/common/release_record.py record --token-from-metadata) -> CHECKING
# ROLLBACK: the upgrade's recorded previous revisions / digests, re-validated, image-only (rollback.sh) -> CHECKING
# Terminal status in platform_upgrades_progress/{id}: SUCCEEDED | ROLLED_BACK | PARTIAL | REFUSED_PLATFORM_NOT_READY
# (nothing changed) | FAILED_<STAGE>. Never Terraform, never IAM; the build identity has no rights for either.
# ==============================================================================
set -u -o pipefail
[ -n "${1:-}" ] && [ -f "$1" ] || { echo "usage: run.sh <work>/verified.json" >&2; exit 2; }
SV_UP_WORK="$(cd "$(dirname "$1")" && pwd)"
export SV_UP_WORK
UP_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
. "${UP_HERE}/lib.sh"
up_load || exit $?
W="${SV_UP_WORK}"

# progress fields from the stage results (JSON files that exist)
summary() {
    python3 - "${W}" "$@" > "${W}/summary.json" <<'PY'
import json, os, sys
w, stems = sys.argv[1], sys.argv[2:]
out = {}
for stem in stems:
    path = os.path.join(w, stem + ".json")
    if os.path.exists(path):
        out[stem.replace("-", "_")] = json.load(open(path))
p = os.path.join(w, "ready.txt")
if os.path.exists(p):
    out["terraform_ready"] = open(p).read().strip()
json.dump(out, sys.stdout)
PY
    echo "${W}/summary.json"
}

finish() {   # finish <status> <stage> <exit>
    up_progress "$1" "$2" "$(summary built deployed check rolled-back rollback-plan)"
    echo "stackvend-upgrade: $1 (${2})"
    exit "$3"
}

record_release() {   # the deployed version record (information only: a failure is a warning, plan §3.11.3)
    local names full="" by
    names=()
    while IFS= read -r n; do names+=("${n}"); done < <(python3 -c 'import json,sys; print("\n".join(sorted(json.load(open(sys.argv[1])))))' "${W}/deployed.json")
    [ "${#names[@]}" -gt 0 ] || return 0
    [ -s "${W}/deploy-failed.txt" ] || full="--full-run"
    by="$(up_json_get "${W}/verified.json" requested_by)"
    # shellcheck disable=SC2086
    python3 "${REPO_ROOT}/scripts/common/release_record.py" record --project "${UP_PROJECT}" --region "${UP_REGION}" \
        --release-file "${W}/release.json" --deployed-by "${by}" ${full} --token-from-metadata "${names[@]}" \
        || echo "stackvend-upgrade: warning: the version record (system_config/platform_release) was not updated" >&2
}

if [ "${UP_KIND}" == "ROLLBACK" ]; then
    up_progress RUNNING ROLLING_BACK
    bash "${UP_HERE}/rollback.sh"
    rb=$?
    if [ ! -s "${W}/rolled-back.json" ] || [ "$(cat "${W}/rolled-back.json")" == "{}" ]; then
        [ "${rb}" -ne 0 ] || rb=86
        finish FAILED_ROLLING_BACK ROLLING_BACK "${rb}"
    fi
    up_progress RUNNING CHECKING
    bash "${UP_HERE}/check.sh" "${W}/rolled-back.json"
    ck=$?
    if [ "${rb}" -eq 0 ] && [ "${ck}" -eq 0 ]; then finish ROLLED_BACK DONE 0; fi
    finish PARTIAL CHECKING 1
fi

up_progress RUNNING PREFLIGHT
bash "${UP_HERE}/preflight.sh"
rc=$?
if [ "${rc}" -eq 80 ]; then finish REFUSED_PLATFORM_NOT_READY PREFLIGHT "${rc}"; fi
[ "${rc}" -eq 0 ] || finish FAILED_PREFLIGHT PREFLIGHT "${rc}"

up_progress RUNNING BUILDING
bash "${UP_HERE}/build.sh"
rc=$?
[ "${rc}" -eq 0 ] || finish FAILED_BUILDING BUILDING "${rc}"

bash "${UP_HERE}/deploy.sh"
dep=$?
if [ ! -s "${W}/deployed.json" ] || [ "$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "${W}/deployed.json")" == "0" ]; then
    finish FAILED_DEPLOYING DEPLOYING "${dep}"
fi
record_release

up_progress RUNNING CHECKING
bash "${UP_HERE}/check.sh"
ck=$?
if [ "${dep}" -ne 0 ]; then finish PARTIAL CHECKING "${dep}"; fi
[ "${ck}" -eq 0 ] || finish FAILED_CHECKING CHECKING "${ck}"
finish SUCCEEDED DONE 0
