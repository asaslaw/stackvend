#!/usr/bin/env bash
# ==============================================================================
# STACKVEND: OPENTOFU / TERRAFORM PLATFORM EXECUTION WRAPPER (safe apply)
# ==============================================================================
# Usage:
#   PROJECT_ID=<id> bash scripts/apply.sh plan            # read-only on GCP and state (Cloud Shell IPv4 fix aside)
#   PROJECT_ID=<id> bash scripts/apply.sh apply           # plan -> destroy gate -> typed id -> apply
#       (after a successful apply, the vars file is copied to gs://castor-tfstate-<id>/platform/<id>.tfvars)
#       (after the typed id and before tofu apply, ONE `gcloud services enable` call for 21 base APIs:
#        a no-op on existing installs, not part of the reviewed plan; skipped for -refresh-only)
#   PROJECT_ID=<id> bash scripts/apply.sh apply -refresh-only   # record drift in state (same gate)
#   PROJECT_ID=<id> bash scripts/apply.sh init            # bind backend (creates state bucket if missing)
#   PROJECT_ID=<id> bash scripts/apply.sh adopt           # import pre-existing git bucket/service
#   PROJECT_ID=<id> bash scripts/apply.sh output|validate|console|state list|state show <addr>
#   PROJECT_ID=<id> bash scripts/apply.sh import <addr> <id>
#   PROJECT_ID=<id> bash scripts/apply.sh destroy --confirm-destroy=<id>
#
# Target selection (FD-07 step 2): TFVARS_FILE=<path> or PROJECT_ID=<id> (falls back to
# `gcloud config get-value project`, printed loudly). The vars file is
# infra/platform/<project_id>.tfvars (or terraform.tfvars when its project_id matches).
# The file's project_id must equal the target; the backend must be castor-tfstate-<id>.
# PROJECT_ID set and infra/platform/<id>.tfvars missing: offers to restore it from that backup, then stops.
#
# Wrapper flags: --allow-destroy=<project_id> (apply), --confirm-destroy=<project_id> (destroy),
#                --ipv4-fix (force the Linux IPv4 fix; automatic when CLOUD_SHELL=true, every subcommand)
# ==============================================================================

set -e -o pipefail

ORIG_PWD="$(pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PLATFORM_DIR="${REPO_ROOT}/infra/platform"

# shellcheck source=common/platform_target.sh
. "${SCRIPT_DIR}/common/platform_target.sh"
# shellcheck source=common/opentofu_offer.sh
. "${SCRIPT_DIR}/common/opentofu_offer.sh"
# shellcheck source=common/tag_admin_preflight.sh
. "${SCRIPT_DIR}/common/tag_admin_preflight.sh"
# shellcheck source=common/org_policy_preflight.sh
. "${SCRIPT_DIR}/common/org_policy_preflight.sh"
# shellcheck source=common/runner_switch_gate.sh
. "${SCRIPT_DIR}/common/runner_switch_gate.sh"
# shellcheck source=common/folder_iam_preflight.sh
. "${SCRIPT_DIR}/common/folder_iam_preflight.sh"
# shellcheck source=common/host_network_preflight.sh
. "${SCRIPT_DIR}/common/host_network_preflight.sh"
# shellcheck source=common/tfvars_backup.sh
. "${SCRIPT_DIR}/common/tfvars_backup.sh"

usage() {
    sed -n '4,26p' "${BASH_SOURCE[0]}" >&2
    exit 1
}

# ------------------------------------------------------------------------------
# 1. Subcommand + flag allowlists (H1). Checked before anything touches GCP.
# ------------------------------------------------------------------------------
[ $# -ge 1 ] || usage
# TFVARS-AUTO-BACKUP: the command as typed, shown in the re-run hints of the vars-file restore offer (display only).
SV_APPLY_ARGS_DISPLAY="$*"
SUBCMD="$1"
shift

STATE_SUB=""
case "${SUBCMD}" in
    plan|apply|init|adopt|output|validate|console|import|destroy) ;;
    state)
        STATE_SUB="${1:-}"
        case "${STATE_SUB}" in
            list|show) shift ;;
            *) sv_die "Only 'state list' and 'state show' are allowed through this wrapper. Run any state mutation by hand, reviewed." ;;
        esac
        ;;
    refresh)
        sv_die "'refresh' writes state without review. Use: scripts/apply.sh apply -refresh-only (goes through the plan/confirm gate)." ;;
    -h|--help|help) usage ;;
    *)
        sv_die "Subcommand '${SUBCMD}' is not allowed through this wrapper (allowed: plan, apply, init, adopt, output, validate, console, import, destroy, state list|show)." ;;
esac

ALLOW_DESTROY=""
CONFIRM_DESTROY=""
# Register row 17: CLOUD_SHELL=true turns the IPv4 fix on automatically (see sv_network_setup).
IPV4_FIX=""
TF_ARGS=()
POSITIONAL=()

for arg in "$@"; do
    case "${arg}" in
        --allow-destroy=*) ALLOW_DESTROY="${arg#--allow-destroy=}"; continue ;;
        --confirm-destroy=*) CONFIRM_DESTROY="${arg#--confirm-destroy=}"; continue ;;
        --ipv4-fix) IPV4_FIX=1; continue ;;
    esac
    ok=""
    case "${SUBCMD}:${arg}" in
        plan:-target=*|plan:-replace=*|plan:-detailed-exitcode|plan:-no-color|plan:-compact-warnings|plan:-parallelism=*|plan:-refresh-only|plan:-destroy) ok=1 ;;
        apply:-target=*|apply:-replace=*|apply:-no-color|apply:-compact-warnings|apply:-parallelism=*|apply:-refresh-only) ok=1 ;;
        destroy:-target=*|destroy:-no-color|destroy:-parallelism=*) ok=1 ;;
        output:-json|output:-raw|output:-no-color) ok=1 ;;
        validate:-json|validate:-no-color) ok=1 ;;
        state:-id=*) ok=1 ;;
    esac
    if [ -n "${ok}" ]; then
        TF_ARGS+=("${arg}")
        continue
    fi
    case "${arg}" in
        -*) sv_die "Flag '${arg}' is not allowed for '${SUBCMD}'. (Never allowed: -var, -var-file, -state*, -backend*, -chdir, -lock*, -refresh=false, -auto-approve, -out; flags must use -flag=value form.)" ;;
    esac
    POSITIONAL+=("${arg}")
done

case "${SUBCMD}" in
    output) [ ${#POSITIONAL[@]} -le 1 ] || sv_die "'output' takes at most one output name." ;;
    state)
        if [ "${STATE_SUB}" = "show" ] && [ ${#POSITIONAL[@]} -ne 1 ]; then
            sv_die "'state show' takes exactly one address."
        fi ;;
    import) [ ${#POSITIONAL[@]} -eq 2 ] || sv_die "'import' takes exactly: <address> <id>." ;;
    *) [ ${#POSITIONAL[@]} -eq 0 ] || sv_die "'${SUBCMD}' takes no positional arguments (got: ${POSITIONAL[*]})." ;;
esac

# ------------------------------------------------------------------------------
# 2. Engine, environment scrub (H1), target resolution + guards (G1-G4, H2, H9)
# ------------------------------------------------------------------------------
sv_scrub_tofu_env   # RT F2: scrub TF_CLI_ARGS* first, so the version probes below read a clean version
# INSTALLER-OPENTOFU-OFFER: OpenTofu missing or older than SV_IAC_MIN_VERSION -> offer to install it into ~/bin
# (a terminal only; otherwise a typed stop with the manual commands). Silent when the engine is usable.
SV_TOFU_TTY=""
if [ -t 0 ]; then SV_TOFU_TTY=1; fi
sv_ensure_opentofu APPLY "${SV_TOFU_TTY}"
sv_detect_iac_bin
# RC B1: refuse an engine too old for infra/platform (clear message, before any GCP call or init).
sv_require_iac_version
# TFVARS-AUTO-BACKUP (owner 11-16): PROJECT_ID set, infra/platform/<id>.tfvars missing -> offer to restore it from
# gs://castor-tfstate-<id>/platform/<id>.tfvars (a terminal only; restore, then stop for review), else a typed stop
# (scripts/common/tfvars_backup.sh). Returns only when there is nothing to offer.
sv_tfvars_restore_offer "${SV_APPLY_ARGS_DISPLAY}"
sv_resolve_platform_target

# Register row 17 (owner 10-12): the Cloud Shell IPv4 fix runs for EVERY subcommand, plan included
# (a local VM network tweak, not a plan side effect). Full fix when CLOUD_SHELL=true or --ipv4-fix;
# elsewhere only GODEBUG=netdns=cgo. Runs after the allowlists and target guards have passed.
sv_network_setup "${IPV4_FIX}"

cd "${PLATFORM_DIR}"

# Fresh OAuth token for the google provider and the gcs backend (read-only call).
if ! gcloud auth print-access-token >/dev/null 2>&1; then
    sv_die "'gcloud auth print-access-token' failed. Run: gcloud auth login"
fi
GOOGLE_OAUTH_ACCESS_TOKEN="$(gcloud auth print-access-token)"
export GOOGLE_OAUTH_ACCESS_TOKEN

# ------------------------------------------------------------------------------
# 3. Helpers
# ------------------------------------------------------------------------------
# Existing install: state must already exist (H7), then bind and verify the backend (G3) and
# the workspace (red team F2). sv_tf_init_bound / sv_gated_apply live in common/platform_target.sh.
tf_ready_existing() {
    sv_require_platform_state
    sv_tf_init_bound
}

trap sv_cleanup_plan_tmp EXIT

# ------------------------------------------------------------------------------
# 3b. Lane 18 v3: Tag Administrator preflight (read-only; never fails the run)
# ------------------------------------------------------------------------------
# Owner rule 10-18: the install never fails for lack of an org Tag Administrator. One read-only
# organizations.testIamPermissions call decides whether the deletion-safety tag is planned
# (scripts/common/tag_admin_preflight.sh); missing/error -> not planned, a WARNING, the run continues.
# BOOTSTRAP-TAG-ADMIN-CONFIRM: whenever the tag will not be created, the prominent "NO DELETION SAFETY" block
# (sv_tag_unprotected_block) follows; apply.sh never asks (bootstrap asks). An explicit create_stackvend_managed_tag in the tfvars wins. Runs for plan and apply only.
#
# Row L18-F5 (owner 10-18): when the tag is already in state and the applier lacks the org tag READ
# permissions, the plan's refresh of the tag would 403 and the run would fail. Then this block adds
# OpenTofu `-exclude` for the three tag resources (and so for what depends on them, incl. the Cloud Run
# services) to the plan, and says so. Only with OpenTofu >= 1.9 and no -target (tofu refuses both).
# Otherwise: warning only. Kept separate from any other -exclude logic (e.g. billing) on purpose.
LANE18_TAG_EXCLUDE_ARGS=()
lane18_tofu_supports_exclude() {
    local v major rest minor
    [ "${IAC_BIN}" = "tofu" ] || return 1
    v="$("${IAC_BIN}" version 2>/dev/null | head -n 1)" || return 1
    v="${v#OpenTofu v}"
    major="${v%%.*}"
    rest="${v#*.}"
    minor="${rest%%.*}"
    [[ "${major}" =~ ^[0-9]+$ ]] && [[ "${minor}" =~ ^[0-9]+$ ]] || return 1
    [ "${major}" -gt 1 ] || { [ "${major}" -eq 1 ] && [ "${minor}" -ge 9 ]; }
}
lane18_tag_admin_preflight_step() {
    local a has_target="" addr
    sv_tag_admin_preflight || true
    if sv_tag_unprotected; then
        # BOOTSTRAP-TAG-ADMIN-CONFIRM (owner 11-11): the same prominent block as bootstrap, printed only (no prompt:
        # apply.sh's non-interactive behavior is unchanged).
        sv_tag_unprotected_block "$(gcloud config get-value account 2>/dev/null || true)" APPLY
    fi
    LANE18_TAG_EXCLUDE_ARGS=()
    [ "${SV_TAG_READ_MISSING_IN_STATE:-}" = "1" ] || return 0
    for a in ${TF_ARGS[@]+"${TF_ARGS[@]}"}; do
        case "${a}" in -target=*) has_target=1 ;; esac
    done
    if [ -n "${has_target}" ]; then
        sv_warn "L18-F5: the deletion safety tag is NOT excluded because -target is set (OpenTofu refuses -target with -exclude). If the targeted resources depend on the tag (the Cloud Run services do), the plan's refresh of the tag answers 403. Run without -target, or with org roles/resourcemanager.tagViewer."
        return 0
    fi
    if ! lane18_tofu_supports_exclude; then
        sv_warn "L18-F5: ${IAC_BIN} cannot exclude the deletion safety tag (needs OpenTofu >= 1.9 -exclude). The plan's refresh of the tag answers 403. Run with org roles/resourcemanager.tagViewer, or with OpenTofu >= 1.9."
        return 0
    fi
    for addr in ${SV_TAG_EXCLUDE_ADDRESSES}; do
        LANE18_TAG_EXCLUDE_ARGS+=("-exclude=${addr}")
    done
    sv_warn "L18-F5: excluding the deletion safety tag from this run (${LANE18_TAG_EXCLUDE_ARGS[*]}): you cannot read it. Cloud Run service changes that depend on the tag (google_cloud_run_v2_service.services and everything depending on it) are DEFERRED until a run with tag read access (org roles/resourcemanager.tagViewer). Everything else is applied. The tag itself is unchanged."
}
# ---- end 3b ------------------------------------------------------------------

# ------------------------------------------------------------------------------
# 3c. ORG-POLICY-FOLDER: Organization Policy Administrator preflight (read-only; never fails the run)
# ------------------------------------------------------------------------------
# scripts/common/org_policy_preflight.sh decides create_folder_vm_external_ip_policy. Owner FU1 (10-28): when the
# folder policy is already in state and the runner cannot read it (no orgpolicy.policy.get on the folder), the
# plan's refresh would answer 403 and fail the run. Then this step adds OpenTofu `-exclude` for that ONE resource
# (nothing depends on it, so nothing else is deferred), the same mechanism and limits as L18-F5 above: OpenTofu
# >= 1.9 and no -target (tofu refuses both together); otherwise a warning only.
ORGPOL_EXCLUDE_ARGS=()
orgpol_preflight_step() {
    local a has_target=""
    sv_org_policy_preflight || true
    ORGPOL_EXCLUDE_ARGS=()
    [ "${SV_ORGPOL_READ_MISSING_IN_STATE:-}" = "1" ] || return 0
    for a in ${TF_ARGS[@]+"${TF_ARGS[@]}"}; do
        case "${a}" in -target=*) has_target=1 ;; esac
    done
    if [ -n "${has_target}" ]; then
        sv_warn "ORG-POLICY-FOLDER: the folder org policy is NOT excluded because -target is set (OpenTofu refuses -target with -exclude). If the targets include it, the plan's refresh answers 403. Run without -target, or with roles/orgpolicy.policyViewer on the folder."
        return 0
    fi
    if ! lane18_tofu_supports_exclude; then
        sv_warn "ORG-POLICY-FOLDER: ${IAC_BIN} cannot exclude the folder org policy (needs OpenTofu >= 1.9 -exclude). The plan's refresh of it answers 403. Run with roles/orgpolicy.policyViewer on the folder, or with OpenTofu >= 1.9."
        return 0
    fi
    ORGPOL_EXCLUDE_ARGS=("-exclude=${SV_ORGPOL_EXCLUDE_ADDRESS}")
    sv_warn "ORG-POLICY-FOLDER: excluding the folder org policy from this run (${ORGPOL_EXCLUDE_ARGS[*]}): you cannot read it. It stays exactly as it is; everything else is planned and applied."
}
# ---- end 3c ------------------------------------------------------------------

# ------------------------------------------------------------------------------
# 3d. FD-7L step B readiness (SAT-33, FD-7L-n; read-only; refuses, never warns)
# ------------------------------------------------------------------------------
# sv_post_plan_check (called by sv_gated_apply on the exact saved plan, before the typed confirmation) lives in
# scripts/common/runner_switch_gate.sh, sourced above; bootstrap.sh sources the same file (SAT-46).
# ---- end 3d ------------------------------------------------------------------

# ------------------------------------------------------------------------------
# 3e. BOOTSTRAP-FOLDER-IAM-PREFLIGHT: Folder IAM Admin (read-only; refuses, never warns)
# ------------------------------------------------------------------------------
# The same check as scripts/bootstrap.sh (scripts/common/folder_iam_preflight.sh), for the folder in the vars file
# (castor_managed_workloads_folder_id), before the plan of `apply`: the apply grants StackVend's service accounts
# their roles on that folder, which needs resourcemanager.folders.setIamPolicy. Missing -> APPLY_FOLDER_IAM_MISSING;
# could not check -> APPLY_FOLDER_IAM_UNCHECKED; nothing is planned or applied. An empty folder is not checked.
# Not run for `plan` (read-only; its refresh needs no setIamPolicy), `apply -refresh-only` (changes no IAM) or
# `destroy`.
folder_iam_preflight_step() {
    local folder account a
    for a in ${TF_ARGS[@]+"${TF_ARGS[@]}"}; do
        [ "${a}" != "-refresh-only" ] || return 0
    done
    folder="$(sv_tfvar castor_managed_workloads_folder_id)" \
        || sv_die "APPLY_FOLDER_IAM_UNCHECKED: cannot read castor_managed_workloads_folder_id from ${TFVARS}, so Folder IAM Admin on the managed workloads folder cannot be checked. Nothing was changed."
    [ -n "${folder}" ] || return 0
    account="$(gcloud config get-value account 2>/dev/null)" || account=""
    sv_folder_iam_preflight APPLY "${folder}" "${account}"
}
# ---- end 3e ------------------------------------------------------------------

# ------------------------------------------------------------------------------
# 3f. HOST-VPC-EGRESS / HOST-INTERNAL-INGRESS: platform network org policies (read-only; refuses or warns)
# ------------------------------------------------------------------------------
# scripts/common/host_network_preflight.sh reads the host project's effective run.allowedVPCEgress, run.allowedIngress
# and PSC-for-Google-APIs policies for the switches in the vars file (variables.tf defaults when unset). A refusing
# policy -> APPLY_HOST_NETWORK_ORG_POLICY_REFUSED before the plan; unreadable -> a WARNING, the run continues. A vars
# file whose switches cannot be read is left to the plan (which reads the same file and fails loudly). Not run for
# `apply -refresh-only` (it creates nothing) or `destroy`.
#
# Review F8/F10 (needs state, so it cannot be a Terraform precondition): host_internal_ingress = true on an install whose
# services are already in state but whose platform subnet is not would flip egress and ingress in one apply (its
# running revisions are off the network: their calls would answer 404 until the new revisions are ready). Refused
# before the plan with APPLY_HOST_INGRESS_BEFORE_NETWORK; a fresh install (no services in state) is not refused.
host_network_preflight_step() {
    local egress ingress egress_mode a state_list
    for a in ${TF_ARGS[@]+"${TF_ARGS[@]}"}; do
        [ "${a}" != "-refresh-only" ] || return 0
    done
    egress="$(sv_tfvar host_vpc_egress)" || egress="unreadable"
    ingress="$(sv_tfvar host_internal_ingress)" || ingress="unreadable"
    egress_mode="$(sv_tfvar host_egress_mode)" || egress_mode="unreadable"
    if [ "${ingress}" = "true" ]; then
        state_list="$("${IAC_BIN}" state list)" \
            || sv_die "APPLY_HOST_INGRESS_BEFORE_NETWORK: '${IAC_BIN} state list' failed, so it cannot be checked that the platform network is applied before host_internal_ingress = true. Nothing was changed."
        if printf '%s\n' "${state_list}" | grep -q '^google_cloud_run_v2_service\.services\[' \
            && ! printf '%s\n' "${state_list}" | grep -Fxq 'google_compute_subnetwork.host_run_egress[0]'; then
            sv_die "APPLY_HOST_INGRESS_BEFORE_NETWORK: host_internal_ingress = true in ${TFVARS}, but the platform network (google_compute_subnetwork.host_run_egress[0]) is not applied yet on ${PROJECT_ID}. Flipping both in one apply cuts the running revisions' calls (404). Nothing was changed. Set host_internal_ingress = false, run PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply (the network and the new revisions), check it, then set it to true and apply again."
        fi
        # Review R1: switching host_egress_mode while ingress is internal-only drops private run.app resolution (or
        # the way out) for revisions still draining on the old design: transient 404s on platform calls. The applied
        # design is read from state: the PSC rule (Design B) or the Cloud NAT (Design A); neither or both = no check.
        local applied_mode=""
        if printf '%s\n' "${state_list}" | grep -Fxq 'google_compute_global_forwarding_rule.psc_google_apis[0]'; then
            applied_mode="PSC_PRIVATE_RANGES"
        fi
        if printf '%s\n' "${state_list}" | grep -Fxq 'google_compute_router_nat.host[0]'; then
            if [ -n "${applied_mode}" ]; then
                applied_mode="both"
            else
                applied_mode="NAT_ALL_TRAFFIC"
            fi
        fi
        case "${applied_mode}" in
            PSC_PRIVATE_RANGES|NAT_ALL_TRAFFIC)
                if [ "${egress_mode}" != "${applied_mode}" ]; then
                    sv_die "APPLY_HOST_EGRESS_MODE_SWITCH_WITH_INGRESS: host_egress_mode = \"${egress_mode}\" in ${TFVARS}, but ${PROJECT_ID} has \"${applied_mode}\" applied and host_internal_ingress = true. Switching the design while services are internal-only gives platform calls transient 404s. Nothing was changed. Switch in three applies: set host_internal_ingress = false and apply; set host_egress_mode = \"${egress_mode}\" and apply; set host_internal_ingress = true and apply (documentation/configuration.md, Platform network)."
                fi ;;
        esac
    fi
    sv_host_network_preflight APPLY "${egress}" "${ingress}" "${egress_mode}"
}
# ---- end 3f ------------------------------------------------------------------

# FD-0B: explicit, fail-closed adoption of resources that pre-date Terraform. Never deletes.
adopt_existing() {
    local deploy_git vcs state_list addr cand_addrs=() cand_ids=() i rc
    deploy_git="$(sv_tfvar deploy_git_server)" || sv_die "Cannot read deploy_git_server from ${TFVARS}."
    vcs="$(sv_tfvar vcs_provider)" || sv_die "Cannot read vcs_provider from ${TFVARS}."

    state_list="$("${IAC_BIN}" state list)" || sv_die "'${IAC_BIN} state list' failed."

    if [ "${deploy_git}" = "true" ] || [ "$(printf '%s' "${vcs}" | tr '[:lower:]' '[:upper:]')" = "SERVERLESS_GIT" ]; then
        addr='google_storage_bucket.git_repos_bucket[0]'
        if ! printf '%s\n' "${state_list}" | grep -Fxq "${addr}"; then
            if gcloud storage buckets describe "gs://castor-git-repos-${PROJECT_ID}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
                cand_addrs+=("${addr}"); cand_ids+=("${PROJECT_ID}/castor-git-repos-${PROJECT_ID}")
            fi
        fi
        addr='google_cloud_run_v2_service.git_server[0]'
        if ! printf '%s\n' "${state_list}" | grep -Fxq "${addr}"; then
            if gcloud run services describe castor-git-server --project="${PROJECT_ID}" --region="${REGION}" >/dev/null 2>&1; then
                cand_addrs+=("${addr}"); cand_ids+=("projects/${PROJECT_ID}/locations/${REGION}/services/castor-git-server")
            fi
        fi
    fi

    if [ ${#cand_addrs[@]} -eq 0 ]; then
        sv_info "Nothing to adopt: every candidate is already in state or does not exist live."
        return 0
    fi
    echo "Will import (read-only describe found these live, unmanaged):" >&2
    for i in "${!cand_addrs[@]}"; do
        echo "  ${IAC_BIN} import ${cand_addrs[$i]} ${cand_ids[$i]}" >&2
    done
    sv_confirm_project "Import ${#cand_addrs[@]} resource(s) into ${PROJECT_ID} state?"
    for i in "${!cand_addrs[@]}"; do
        set +e
        "${IAC_BIN}" import -input=false -var-file="${TFVARS}" "${cand_addrs[$i]}" "${cand_ids[$i]}"
        rc=$?
        set -e
        if [ ${rc} -ne 0 ]; then
            sv_die "Import of ${cand_addrs[$i]} failed (rc=${rc}). Nothing was deleted; fix the cause and re-run 'adopt'."
        fi
    done
}

# ------------------------------------------------------------------------------
# 4. Dispatch
# ------------------------------------------------------------------------------
case "${SUBCMD}" in
    plan)
        # R0: read-only. No API enables, imports, bucket creation, billing IAM or tfvars edits.
        # (The Cloud Shell IPv4 fix above is a local VM tweak, register row 17.)
        # BG-1: the billing preflight is a read-only testIamPermissions call (no billing IAM change).
        tf_ready_existing
        lane18_tag_admin_preflight_step
        orgpol_preflight_step  # ORG-POLICY-FOLDER: read-only; decides the folder policy, never fails (3c)
        host_network_preflight_step  # HOST-VPC-EGRESS / HOST-INTERNAL-INGRESS: read-only org policy check (3f)
        sv_billing_iam_preflight ${TF_ARGS[@]+"${TF_ARGS[@]}"}
        sv_export_platform_stamp  # FD-4DA stamp: the same TF_VAR the apply sets, so plan and apply agree
        "${IAC_BIN}" plan -lock=false -input=false -var-file="${TFVARS}" ${TF_ARGS[@]+"${TF_ARGS[@]}"} ${SV_BILLING_TF_ARGS[@]+"${SV_BILLING_TF_ARGS[@]}"} ${LANE18_TAG_EXCLUDE_ARGS[@]+"${LANE18_TAG_EXCLUDE_ARGS[@]}"} ${ORGPOL_EXCLUDE_ARGS[@]+"${ORGPOL_EXCLUDE_ARGS[@]}"}
        ;;
    apply)
        folder_iam_preflight_step  # BOOTSTRAP-FOLDER-IAM-PREFLIGHT: read-only; refuses before init and plan (3e)
        tf_ready_existing
        lane18_tag_admin_preflight_step
        orgpol_preflight_step  # ORG-POLICY-FOLDER: read-only; decides the folder policy, never fails (3c)
        host_network_preflight_step  # HOST-VPC-EGRESS / HOST-INTERNAL-INGRESS: read-only org policy check (3f)
        sv_billing_iam_preflight ${TF_ARGS[@]+"${TF_ARGS[@]}"}
        sv_gated_apply apply "${ALLOW_DESTROY}" ${TF_ARGS[@]+"${TF_ARGS[@]}"} ${SV_BILLING_TF_ARGS[@]+"${SV_BILLING_TF_ARGS[@]}"} ${LANE18_TAG_EXCLUDE_ARGS[@]+"${LANE18_TAG_EXCLUDE_ARGS[@]}"} ${ORGPOL_EXCLUDE_ARGS[@]+"${ORGPOL_EXCLUDE_ARGS[@]}"}
        # TFVARS-AUTO-BACKUP: reached only after a successful apply (or "No changes"; a failed or refused apply has
        # exited above). Refresh gs://castor-tfstate-<id>/platform/<id>.tfvars; a failure is a typed warning
        # (APPLY_TFVARS_BACKUP_NOT_WRITTEN), never a failed apply (fail-loudly-policy section 2).
        if [ -n "${TFVARS_FILE:-}" ]; then
            SV_APPLY_RETRY="TFVARS_FILE=$(printf '%q' "${TFVARS}") bash scripts/apply.sh apply (a run with no changes only refreshes the backup)"
        else
            SV_APPLY_RETRY="PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply (a run with no changes only refreshes the backup)"
        fi
        sv_tfvars_backup_write APPLY "${TFVARS}" "${SV_APPLY_RETRY}" || true
        ;;
    destroy)
        [ "${CONFIRM_DESTROY}" = "${PROJECT_ID}" ] || sv_die "destroy needs --confirm-destroy=${PROJECT_ID}."
        tf_ready_existing
        sv_gated_apply destroy "${PROJECT_ID}" ${TF_ARGS[@]+"${TF_ARGS[@]}"}
        ;;
    init)
        if ! gcloud storage buckets describe "gs://${STATE_BUCKET}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
            sv_confirm_project "State bucket gs://${STATE_BUCKET} does not exist. Create it (versioned) in ${REGION}?"
            gcloud storage buckets create "gs://${STATE_BUCKET}" --project="${PROJECT_ID}" --location="${REGION}" --uniform-bucket-level-access --quiet \
                || sv_die "Could not create gs://${STATE_BUCKET}."
            gcloud storage buckets update "gs://${STATE_BUCKET}" --versioning --quiet \
                || sv_die "Could not enable versioning on gs://${STATE_BUCKET}."
        fi
        sv_tf_init_bound
        ;;
    adopt)
        tf_ready_existing
        adopt_existing
        ;;
    import)
        tf_ready_existing
        sv_confirm_project "Import ${POSITIONAL[0]} (${POSITIONAL[1]}) into ${PROJECT_ID} state?"
        "${IAC_BIN}" import -input=false -var-file="${TFVARS}" "${POSITIONAL[0]}" "${POSITIONAL[1]}"
        ;;
    output)
        tf_ready_existing
        "${IAC_BIN}" output ${TF_ARGS[@]+"${TF_ARGS[@]}"} ${POSITIONAL[@]+"${POSITIONAL[@]}"}
        ;;
    state)
        tf_ready_existing
        "${IAC_BIN}" state "${STATE_SUB}" ${TF_ARGS[@]+"${TF_ARGS[@]}"} ${POSITIONAL[@]+"${POSITIONAL[@]}"}
        ;;
    validate)
        tf_ready_existing
        "${IAC_BIN}" validate ${TF_ARGS[@]+"${TF_ARGS[@]}"}
        ;;
    console)
        tf_ready_existing
        "${IAC_BIN}" console -var-file="${TFVARS}"
        ;;
esac
