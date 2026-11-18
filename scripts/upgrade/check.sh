#!/usr/bin/env bash
# STACKVEND UPGRADER, HEALTH CHECK (plan §3.7): every deployed service runs a Ready newest revision with the deployed
# digest; every job carries the deployed image (the QA job also its contract label); tf-applier runs the
# mcp-terraform-server image and stage-runner the orchestrator gateway's; and, when the terraform server was deployed, GET /validate/ready (a healthy server is
# not a working one). The upgrader has no run.invoker by design, so a 401/403 there is reported as NOT_CHECKED
# (never as a pass). The same NOT_CHECKED (reason INGRESS_INTERNAL, no HTTP probe) when the server's typed ingress
# (Run Admin API v2) is internal-only: Cloud Build is never an internal source of an internal-only service; an unknown
# ingress value fails the check (API_FAILED). After a NOT_CHECKED, the Control Center probes /validate/ready with its
# own ID token when Settings ▸ Upgrades shows the finished upgrade, and shows READY / NOT_READY / NOT_CHECKED there
# (apps/control-center/routes/platform_upgrade.py cc_terraform_ready_for).
# Usage: SV_UP_WORK=<dir> bash check.sh [deployed-file]       Writes check.json and ready.txt.
set -u -o pipefail
# shellcheck source=lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
up_load || exit $?

W="${SV_UP_WORK}"
deployed="${1:-${W}/deployed.json}"
rc=0
up_stage_py check --project "${UP_PROJECT}" --region "${UP_REGION}" --deployed "${deployed}" --out "${W}/check.json" || rc=$?
if [ -n "$(up_json_get "${deployed}" mcp-terraform-server)" ]; then
    if ! up_stage_py ready --project "${UP_PROJECT}" --region "${UP_REGION}" --attempts "${UP_READY_ATTEMPTS:-20}" \
            > "${W}/ready.txt"; then
        [ "${rc}" -ne 0 ] || rc=85
    fi
    cat "${W}/ready.txt"
fi
exit "${rc}"
