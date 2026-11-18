#!/usr/bin/env bash
# STACKVEND UPGRADER, DEPLOY (plan §3.5 DEPLOYING; plan RT I-1, M-3): first records what runs now (service ->
# ready revision; job -> image digest, a tag resolved through Artifact Registry) into SV_UP_WORK/previous.json and the
# progress record (the rollback targets), then sends IMAGE-ONLY updates of existing services and jobs, by digest:
# `gcloud run services update --image` / `gcloud run jobs update --image` (+ the QA job's contract label). Never
# `gcloud run deploy` (it can create), never --source, --service-account, env, IAM or traffic flags. tf-applier gets
# mcp-terraform-server's image and stage-runner the orchestrator gateway's (STAGE-JOB-RUNNER); the Control Center goes
# last.
# Usage: SV_UP_WORK=<dir> bash deploy.sh      Writes deployed.json {component: {kind, image}} and deploy-failed.txt.
set -u -o pipefail
# shellcheck source=lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
up_load || exit $?

W="${SV_UP_WORK}"
# Order: the git server FIRST (row GIT-404-TYPED: its clients read a 404 without its X-StackVend-Git-Server header as
# "unreachable", so it must run its new code before any client does), set here explicitly rather than relying on
# built.json's sorted keys; then the rest; the Control Center last.
order=()
cc=""
git_server=""
while IFS= read -r name; do
    if [ "${name}" == "${SV_CONTROL_CENTER}" ]; then cc="${name}"
    elif [ "${name}" == "${SV_GIT_SERVER}" ]; then git_server="${name}"
    else order+=("${name}"); fi
    if [ "${name}" == "${SV_TF_APPLIER_FOLLOWS}" ]; then order+=("${SV_TF_APPLIER_JOB}"); fi
    if [ "${name}" == "${SV_STAGE_RUNNER_FOLLOWS}" ]; then order+=("${SV_STAGE_RUNNER_JOB}"); fi
done < <(python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))))' "${W}/built.json")
[ -z "${git_server}" ] || order=("${git_server}" ${order[@]+"${order[@]}"})
[ -z "${cc}" ] || order+=("${cc}")

snap=()
for name in "${order[@]}"; do snap+=("${name}:$(up_kind_of "${name}")"); done
up_stage_py snapshot --project "${UP_PROJECT}" --region "${UP_REGION}" --out "${W}/previous.json" "${snap[@]}" \
    || { echo "stackvend-upgrade: FAILED DEPLOY_FAILED: could not record the current revisions; nothing was deployed" >&2; exit 84; }
python3 -c 'import json,sys; json.dump({"previous": json.load(open(sys.argv[1]))}, open(sys.argv[2], "w"))' \
    "${W}/previous.json" "${W}/previous-progress.json"
up_progress RUNNING DEPLOYING "${W}/previous-progress.json"

: > "${W}/deploy-failed.txt"
echo '{}' > "${W}/deployed.json"
for name in "${order[@]}"; do
    follows=""
    if [ "${name}" == "${SV_TF_APPLIER_JOB}" ]; then follows="${SV_TF_APPLIER_FOLLOWS}"; fi
    if [ "${name}" == "${SV_STAGE_RUNNER_JOB}" ]; then follows="${SV_STAGE_RUNNER_FOLLOWS}"; fi
    if [ -n "${follows}" ]; then
        if grep -qxF "${follows}" "${W}/deploy-failed.txt"; then
            echo "stackvend-upgrade: FAILED DEPLOY_FAILED ${name}: not updated because ${follows} failed (they run one image)" >&2
            echo "${name}" >> "${W}/deploy-failed.txt"
            continue
        fi
        image="$(up_json_get "${W}/built.json" "${follows}")"
    else
        image="$(up_json_get "${W}/built.json" "${name}")"
    fi
    kind="$(up_kind_of "${name}")"
    echo "  deploy ${kind} ${name} -> ${image}"
    if [ "${kind}" == "service" ]; then
        up_update_service_image "${name}" "${image}"
    else
        up_update_job_image "${name}" "${image}"
    fi
    if [ $? -eq 0 ]; then
        python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); d[sys.argv[2]]={"kind":sys.argv[3],"image":sys.argv[4]}; json.dump(d,open(sys.argv[1],"w"),sort_keys=True,indent=1)' \
            "${W}/deployed.json" "${name}" "${kind}" "${image}"
    else
        echo "stackvend-upgrade: FAILED DEPLOY_FAILED ${name}: the update was refused (see above); it still runs its previous revision" >&2
        echo "${name}" >> "${W}/deploy-failed.txt"
        if [ "${name}" == "${SV_GIT_SERVER}" ]; then
            echo "stackvend-upgrade: FAILED DEPLOY_FAILED ${name}: nothing else was updated (its clients must not run against the old git server)" >&2
            break
        fi
    fi
done
[ ! -s "${W}/deploy-failed.txt" ] || exit 84
