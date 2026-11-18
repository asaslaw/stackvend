#!/usr/bin/env bash
# STACKVEND UPGRADER, ROLL BACK SERVICES (plan §3.8; plan RT M-3). A ROLLBACK request (re-verified by step 0 like
# any upgrade) names the upgrade to undo. Its recorded `previous` snapshot only NAMES the targets; every target is
# re-validated (stage.py rollback-plan): a service goes back to its previous revision's image (the revision must
# belong to that service; the digest comes from Cloud Run), a job to its previous digest (must exist in this
# project's Artifact Registry). A component without a valid target is reported ROLLBACK_UNAVAILABLE <component>
# (never a guess). Image-only updates, the Control Center last; no rebuild. Terraform is never rolled back.
# Usage: SV_UP_WORK=<dir> bash rollback.sh        Writes rollback-plan.json, rolled-back.json.
set -u -o pipefail
# shellcheck source=lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
up_load || exit $?

W="${SV_UP_WORK}"
of="$(up_json_get "${W}/verified.json" rollback_of)"
up_stage_py previous --project "${UP_PROJECT}" --request-id "${of}" --out "${W}/previous.json" || exit $?
up_stage_py rollback-plan --project "${UP_PROJECT}" --region "${UP_REGION}" --previous "${W}/previous.json" \
    --out "${W}/rollback-plan.json" || exit $?

order=()
cc=""
while IFS= read -r name; do
    if [ "${name}" == "${SV_CONTROL_CENTER}" ]; then cc="${name}"; else order+=("${name}"); fi
done < <(python3 -c 'import json,sys; print("\n".join(sorted(json.load(open(sys.argv[1]))["targets"])))' "${W}/rollback-plan.json")
[ -z "${cc}" ] || order+=("${cc}")

rc=0
echo '{}' > "${W}/rolled-back.json"
for name in "${order[@]+"${order[@]}"}"; do
    image="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["targets"][sys.argv[2]]["image"])' "${W}/rollback-plan.json" "${name}")"
    kind="$(up_kind_of "${name}")"
    echo "  roll back ${kind} ${name} -> ${image}"
    if [ "${kind}" == "service" ]; then up_update_service_image "${name}" "${image}"; else up_update_job_image "${name}" "${image}"; fi
    if [ $? -eq 0 ]; then
        python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); d[sys.argv[2]]={"kind":sys.argv[3],"image":sys.argv[4]}; json.dump(d,open(sys.argv[1],"w"),sort_keys=True,indent=1)' \
            "${W}/rolled-back.json" "${name}" "${kind}" "${image}"
    else
        echo "stackvend-upgrade: FAILED DEPLOY_FAILED ${name}: the rollback update was refused" >&2
        rc=84
    fi
done
while IFS=$'\t' read -r name reason; do
    [ -n "${name}" ] || continue
    echo "stackvend-upgrade: FAILED ROLLBACK_UNAVAILABLE ${name}: ${reason}" >&2
    [ "${rc}" -ne 0 ] || rc=86
done < <(python3 -c 'import json,sys; [print(k + "\t" + v) for k, v in sorted(json.load(open(sys.argv[1]))["unavailable"].items())]' "${W}/rollback-plan.json")
exit "${rc}"
