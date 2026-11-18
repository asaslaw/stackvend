# shellcheck shell=bash
# ==============================================================================
# STACKVEND UPGRADER: shared helpers for the stages after step 0 (run.sh, preflight.sh, build.sh, deploy.sh,
# check.sh, rollback.sh). These run from the VERIFIED target tree (plan §3.3 step 7), so they change with releases;
# only step 0 (verify.sh + guard.py) is frozen in Terraform. Definitions only: sourcing runs nothing.
#
# Contract: SV_UP_WORK = the step-0 work directory (verified.json; src/ = this checkout). Every stage writes its
# result as JSON into SV_UP_WORK and reports progress through guard.py report (one writer of the progress record).
# Never: Terraform, IAM, --service-account, creating or deleting a service/job, `gcloud run deploy` (it can create),
# `--source` (a nested build as another identity). Deploys are image-only updates (plan RT I-1).
# ==============================================================================

SV_UP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SV_UP_DIR}/../.." && pwd)"
# shellcheck source=../common/components.sh
. "${REPO_ROOT}/scripts/common/components.sh"
# components.sh's messages use these; plain text in the build log
BOLD="" GREEN="" BLUE="" YELLOW="" RED="" CYAN="" RESET=""

up_stage_py() { python3 "${SV_UP_DIR}/stage.py" "$@"; }
up_guard_py() { python3 "${SV_UP_DIR}/guard.py" "$@"; }

# up_load: reads verified.json into UP_PROJECT UP_REGION UP_KIND UP_REQUEST_ID UP_RELEASE UP_COMMIT12.
up_load() {
    local f
    [ -n "${SV_UP_WORK:-}" ] && [ -f "${SV_UP_WORK}/verified.json" ] || {
        echo "stackvend-upgrade: FAILED INTERNAL: SV_UP_WORK/verified.json is missing" >&2; return 89; }
    f="$(up_stage_py fields --verified "${SV_UP_WORK}/verified.json")" || return $?
    read -r UP_PROJECT UP_REGION UP_KIND UP_REQUEST_ID UP_RELEASE UP_COMMIT12 <<EOF
${f}
EOF
    UP_AR="${UP_REGION}-docker.pkg.dev/${UP_PROJECT}/castor-docker-repo"
    export UP_PROJECT UP_REGION UP_KIND UP_REQUEST_ID UP_RELEASE UP_COMMIT12 UP_AR
}

# up_progress <status> <stage> [extra-json-file]: update the progress record (a failed write is printed, never fatal:
# the build log is the authority and the Control Center shows the record's last state).
up_progress() {
    local extra=()
    [ -z "${3:-}" ] || extra=(--extra-file "$3")
    up_guard_py report --request-id "${UP_REQUEST_ID}" --project "${UP_PROJECT}" --status "$1" --stage "$2" \
        "${extra[@]+"${extra[@]}"}" \
        || echo "stackvend-upgrade: warning: progress record not updated ($1 $2)" >&2
}

# up_components: NAME:KIND for every component (SERVICES, JOBS, then tf-applier and stage-runner), one per line.
up_components() {
    local e
    for e in "${SERVICES[@]}"; do printf '%s:service\n' "${e%%:*}"; done
    for e in "${JOBS[@]}"; do printf '%s:job\n' "${e%%:*}"; done
    printf '%s:job\n' "${SV_TF_APPLIER_JOB}"
    printf '%s:job\n' "${SV_STAGE_RUNNER_JOB}"
}

# up_dir_of <name>: the component's source directory (empty for tf-applier and stage-runner, never built on their own).
up_dir_of() {
    local e
    for e in "${SERVICES[@]}" "${JOBS[@]}"; do
        if [ "${e%%:*}" == "$1" ]; then printf '%s\n' "${e#*:}"; return 0; fi
    done
    return 1
}

# up_kind_of <name>
up_kind_of() {
    local e
    for e in "${SERVICES[@]}"; do [ "${e%%:*}" != "$1" ] || { echo service; return 0; }; done
    echo job
}

# up_json_get <file> <key> [<key>...]: one value from a JSON file (strings printed raw, missing -> empty).
up_json_get() {
    python3 - "$@" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1], encoding="utf-8"))
for k in sys.argv[2:]:
    doc = doc.get(k) if isinstance(doc, dict) else None
print("" if doc is None else (doc if isinstance(doc, str) else json.dumps(doc)))
PY
}

# up_json_lines <file> <key>: the strings of a JSON list, one per line.
up_json_lines() {
    python3 - "$@" <<'PY'
import json, sys
for x in json.load(open(sys.argv[1], encoding="utf-8")).get(sys.argv[2]) or []:
    print(x)
PY
}

# up_json_set <file> <key> <value>: set one string value in a JSON object file (created when missing).
up_json_set() {
    python3 - "$@" <<'PY'
import json, os, sys
path, key, value = sys.argv[1:4]
doc = json.load(open(path, encoding="utf-8")) if os.path.exists(path) else {}
doc[key] = value
with open(path, "w", encoding="utf-8") as fh:
    json.dump(doc, fh, sort_keys=True, indent=1)
PY
}

# Image-only updates (plan RT I-1). A test pins that these are the only mutating gcloud calls of the upgrader.
up_update_service_image() {
    gcloud run services update "$1" --image "$2" --region "${UP_REGION}" --project "${UP_PROJECT}" --quiet
}
up_update_job_image() {
    local labels
    labels="$(sv_component_labels "$1")"
    if [ -n "${labels}" ]; then
        gcloud run jobs update "$1" --image "$2" --update-labels="${labels}" --region "${UP_REGION}" \
            --project "${UP_PROJECT}" --quiet
    else
        gcloud run jobs update "$1" --image "$2" --region "${UP_REGION}" --project "${UP_PROJECT}" --quiet
    fi
}
