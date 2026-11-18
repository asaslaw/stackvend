# shellcheck shell=bash
# ==============================================================================
# STACKVEND: FD-7L step B readiness gate (SAT-33, FD-7L-n; read-only; refuses, never warns; sourced, never executed)
# ==============================================================================
# Sourced by BOTH scripts/apply.sh and scripts/bootstrap.sh (SAT-46: moved here unchanged from apply.sh section 3d,
# so bootstrap's gated apply refuses an unchecked step-B switch too, e.g. an existing install re-bootstrapped from a
# fresh clone with no vars file, which bootstrap writes as PER_WORKLOAD + tf_runner_dedicated_sa = true). On a new
# install the runners are plain creates, which plan-switch never counts, so the readiness read does not run.
# Needs from the caller: SCRIPT_DIR (scripts/), TFVARS, PROJECT_ID, GOOGLE_OAUTH_ACCESS_TOKEN, and sv_tfvar / sv_info /
# sv_die (scripts/common/platform_target.sh).
#
# Called by sv_gated_apply on the exact saved plan, before the typed confirmation. When the plan moves
# mcp-terraform-server or the tf-applier job to their own runner service accounts (tf_runner_dedicated_sa = true on
# an install where they still run as sa-castor-developer), every LIVE workload must already hold a READY runner
# identity record signed by vending; otherwise its deploys would stop after the switch. The guard database is read
# directly with YOUR credentials (vending's status route admits only the Control Center; plan RT F9), and each
# signature is checked against Google's published certificates of vending's own service account. Any other plan
# (step A, a new install, the rollback to false) is not affected. Standalone: scripts/check-runner-identity-readiness.sh
sv_post_plan_check() {
    local plan_json="$1" rc vrap broker
    set +e
    python3 "${SCRIPT_DIR}/common/runner_identity_readiness.py" plan-switch --plan "${plan_json}"
    rc=$?
    set -e
    case "${rc}" in
        0) return 0 ;;
        3) ;;
        *) sv_die "APPLY_RUNNER_SWITCH_UNCHECKED: could not read the plan for the FD-7L runner identity switch (rc=${rc}). Nothing was applied." ;;
    esac
    vrap="$(sv_tfvar vending_runs_as_provisioner)" || sv_die "APPLY_RUNNER_SWITCH_UNCHECKED: cannot read vending_runs_as_provisioner from ${TFVARS}. Nothing was applied."
    [ "${vrap}" = "true" ] || sv_die "APPLY_RUNNER_SWITCH_NOT_READY: the runner identity switch needs vending_runs_as_provisioner = true (vending is the token broker and must not share an identity, plan R9). Nothing was applied."
    broker="sa-project-provisioner@${PROJECT_ID}.iam.gserviceaccount.com"
    sv_info "FD-7L step B: this plan moves the Terraform runners to their own service accounts. Checking that every live workload has a READY, vending-signed runner identity (read-only, your credentials)..."
    set +e
    readiness_out="$(printf '%s\n' "${GOOGLE_OAUTH_ACCESS_TOKEN}" | python3 "${SCRIPT_DIR}/common/runner_identity_readiness.py" check --project "${PROJECT_ID}" --broker "${broker}" 2>&1)"
    rc=$?
    set -e
    printf '%s\n' "${readiness_out}" >&2
    # SAT-40 option G: the count from the helper's own summary line (render_text), shown on the success line.
    pending="$(printf '%s\n' "${readiness_out}" | sed -n 's/^Live workloads: .*; project pending deletion (not blocking): \([0-9][0-9]*\)$/\1/p')"
    pending_note=""
    if [ -n "${pending}" ] && [ "${pending}" != "0" ]; then pending_note=" (${pending} pending deletion, not blocking)"; fi
    case "${rc}" in
        0) sv_info "FD-7L step B readiness: every live workload is READY${pending_note}." ;;
        1) sv_die "APPLY_RUNNER_SWITCH_NOT_READY: workloads listed above have no READY runner identity, or no pinned repository (REPOSITORY_NOT_PINNED). Nothing was applied. Run the runner identity backfill (Control Center Settings > Runner identity), then re-run this apply." ;;
        *) sv_die "APPLY_RUNNER_SWITCH_UNCHECKED: the runner identity readiness could not be checked (rc=${rc}; see above). Nothing was applied." ;;
    esac
}
