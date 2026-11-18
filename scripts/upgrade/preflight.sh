#!/usr/bin/env bash
# STACKVEND UPGRADER, PREFLIGHT (plan §3.4.2): every component of THIS release exists as a Cloud Run service / job
# and the upgrader may act as its runtime service account; the git server is on its FUSE volume; Artifact Registry
# exists. A release that added a component or a runtime account but said `requires_apply_sh: false` stops here with
# PLATFORM_NOT_READY <component>, before anything is built. Read-only. Usage: SV_UP_WORK=<dir> bash preflight.sh
set -u -o pipefail
# shellcheck source=lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
up_load || exit $?

comps=()
while IFS= read -r c; do comps+=("${c}"); done < <(up_components)
up_stage_py preflight --project "${UP_PROJECT}" --region "${UP_REGION}" --out "${SV_UP_WORK}/preflight.json" "${comps[@]}"
