# shellcheck shell=bash
# ==============================================================================
# STACKVEND: read-only Organization Policy Administrator preflight (ORG-POLICY-FOLDER; sourced, never executed)
# ==============================================================================
# Owner 10-28 (register row ORG-POLICY-FOLDER): the platform Terraform sets "no external VM IPs"
# (compute.vmExternalIpAccess = deny all) once on the managed workloads folder
# (google_org_policy_policy.managed_folder_vm_external_ip, infra/platform/main.tf) and every child inherits it.
# Only the person running bootstrap.sh / apply.sh needs Organization Policy Administrator
# (roles/orgpolicy.policyAdmin, grantable only on the organization). The install must never fail for lack of it,
# so this preflight decides, before the plan, whether the folder policy is planned. Same shape as the lane 18 v3
# Tag Administrator preflight (scripts/common/tag_admin_preflight.sh):
#
#   1. an explicit `create_folder_vm_external_ip_policy = true|false` in the tfvars wins (no decision call).
#      false with the policy in state: the plan deletes it, so the destroy gate needs --allow-destroy (N1 warning).
#      true with the policy in state: rule 4b (read check) still runs;
#   2. no castor_managed_workloads_folder_id -> nothing to decide (the policy is never planned);
#   3. the folder id is not folders/<digits> (or <digits>) -> false + WARNING;
#   4. the policy is already in state (an earlier apply by an Organization Policy Administrator) -> it stays
#      planned (true): count 0 would plan its delete, which needs the same role, so the apply would fail.
#      4b (owner FU1): the plan's refresh of it needs orgpolicy.policy.get. One READ-ONLY folders/<id>:
#      testIamPermissions call for that permission; when it is confirmed missing, SV_ORGPOL_READ_MISSING_IN_STATE=1
#      and scripts/apply.sh excludes that one resource from the run (OpenTofu -exclude, as lane 18 row L18-F5 does
#      for the tag) instead of failing on a 403; bootstrap only warns;
#   5. (owner F2) one READ-ONLY GET of the folder's own compute.vmExternalIpAccess policy (Org Policy API v2, the
#      host as quota project). 200 -> a folder policy already exists that StackVend does not manage: false +
#      WARNING (import it, or leave it: vending records ENFORCED when it is deny all). Creating it would answer
#      409 part-way through the apply. 404 or any other answer -> continue;
#   6. one READ-ONLY call: Cloud Resource Manager v3 folders/<id>:testIamPermissions for the caller
#      (orgpolicy.policies.create, orgpolicy.policies.update, orgpolicy.policy.get, orgpolicy.policy.set; an
#      organization grant is inherited by the folder, so this is the exact check);
#   7. all granted -> TF_VAR_create_folder_vm_external_ip_policy=true; anything else (missing permission, HTTP
#      error, curl/gcloud/python failure) -> false and a WARNING with the fix; the apply continues and succeeds.
# The token comes from `gcloud auth print-access-token` and goes to curl on stdin (--config -), never on the
# command line.
#
# The decision reaches tofu through TF_VAR_create_folder_vm_external_ip_policy, exported by THIS function only,
# after sv_scrub_tofu_env has refused any caller-provided TF_VAR_*. A value in the vars file (-var-file) beats a
# TF_VAR_* in tofu's precedence, so rule 1 also holds inside tofu.
#
# Never fails: every path returns 0 (callers may still add `|| true`). Needs IAC_BIN, TFVARS (sv_tfvar),
# PROJECT_ID and, for rule 4, an initialised backend (`state list`). Bash 3.2 compatible.
# ==============================================================================

SV_ORGPOL_REQUIRED_ROLE="roles/orgpolicy.policyAdmin"
SV_ORGPOL_REQUIRED_PERMISSIONS="orgpolicy.policies.create orgpolicy.policies.update orgpolicy.policy.get orgpolicy.policy.set"
SV_ORGPOL_READ_PERMISSION="orgpolicy.policy.get"
SV_ORGPOL_STATE_ADDRESS="google_org_policy_policy.managed_folder_vm_external_ip[0]"
SV_ORGPOL_EXCLUDE_ADDRESS="google_org_policy_policy.managed_folder_vm_external_ip"
# Set for the caller's final summary (bootstrap prints it again after the apply).
SV_ORGPOL_PREFLIGHT_RESULT=""
SV_ORGPOL_PREFLIGHT_WARNING=""
# FU1: set to 1 when the policy is in state and the runner confirmed lacks orgpolicy.policy.get on the folder.
SV_ORGPOL_READ_MISSING_IN_STATE=""

sv_orgpol_preflight_warn() {
    SV_ORGPOL_PREFLIGHT_WARNING="$*"
    echo -e "\033[1;33m[WARN]\033[0m $*" >&2
}

sv_orgpol_preflight_decide() {
    # $1 = true|false; $2 = reason (printed)
    SV_ORGPOL_PREFLIGHT_RESULT="$1"
    TF_VAR_create_folder_vm_external_ip_policy="$1"
    export TF_VAR_create_folder_vm_external_ip_policy
    echo -e "\033[0;34m==>\033[0m Organization Policy Administrator preflight: create_folder_vm_external_ip_policy=$1 ($2)" >&2
}

# Prints the granted permissions (one per line) from a testIamPermissions response file; rc != 0 when the body is
# not the documented JSON shape.
sv_orgpol_preflight_granted() {
    python3 -c '
import json, sys
try:
    body = json.load(open(sys.argv[1]))
except (OSError, ValueError):
    sys.exit(3)
perms = body.get("permissions", []) if isinstance(body, dict) else None
if not isinstance(perms, list) or not all(isinstance(p, str) for p in perms):
    sys.exit(4)
for p in perms:
    print(p)
' "$1"
}

# The fix, printed with every "not set up" warning. $1 = folder number.
sv_orgpol_fix_text() {
    local org
    org="$(sv_tfvar organization_id)" || org=""
    org="${org#organizations/}"
    [ -n "${org}" ] || org="<organization id>"
    echo "The install continues without it: vended projects get no 'no external VM IPs' guardrail, and each vend records VENDING.ORG_POLICY_NOT_ENFORCED. Fix: an Organization Policy Administrator (${SV_ORGPOL_REQUIRED_ROLE} on organizations/${org}; an organization admin grants it with: gcloud organizations add-iam-policy-binding ${org} --member=user:<your account> --role=${SV_ORGPOL_REQUIRED_ROLE}) re-runs: PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply (it sets compute.vmExternalIpAccess = deny all on folders/$1)."
}

# Token for the read-only calls below (empty on failure). Kept in a global for one preflight run only.
sv_orgpol_token() {
    [ -n "${SV_ORGPOL_TOKEN:-}" ] || SV_ORGPOL_TOKEN="$(gcloud auth print-access-token 2>/dev/null)" || SV_ORGPOL_TOKEN=""
}

# One READ-ONLY folders/<id>:testIamPermissions call. $1 folder number, $2 JSON permissions array, $3 output file.
# Prints the HTTP code ("" on curl failure).
sv_orgpol_test_permissions() {
    printf 'header = "Authorization: Bearer %s"\n' "${SV_ORGPOL_TOKEN}" | curl -sS --max-time 20 --config - \
        -X POST -H "Content-Type: application/json" --data "{\"permissions\":$2}" -o "$3" -w '%{http_code}' \
        "https://cloudresourcemanager.googleapis.com/v3/folders/$1:testIamPermissions" 2>/dev/null || true
}

# FU1 (rule 4b): the policy is in state; confirm the runner can read it (the plan refreshes it). $1 folder number.
sv_orgpol_in_state_read_check() {
    local folder="$1" tmp code granted
    sv_orgpol_token
    if [ -z "${SV_ORGPOL_TOKEN}" ]; then
        echo -e "\033[0;34m==>\033[0m Organization Policy Administrator preflight: folder policy in state; read check unavailable (no access token)." >&2
        return 0
    fi
    tmp="$(mktemp -d 2>/dev/null)" || return 0
    code="$(sv_orgpol_test_permissions "${folder}" "[\"${SV_ORGPOL_READ_PERMISSION}\"]" "${tmp}/read.json")"
    granted=""
    if [ "${code}" = "200" ]; then
        granted="$(sv_orgpol_preflight_granted "${tmp}/read.json")" || code="unparseable"
    fi
    rm -rf "${tmp}"
    if [ "${code}" = "200" ] && ! printf '%s\n' "${granted}" | grep -Fxq "${SV_ORGPOL_READ_PERMISSION}"; then
        SV_ORGPOL_READ_MISSING_IN_STATE=1
        sv_orgpol_preflight_warn "The folder 'no external VM IPs' policy is in state but you lack ${SV_ORGPOL_READ_PERMISSION} on folders/${folder}: refreshing it would answer 403. scripts/apply.sh leaves that one resource out of this run (it stays as it is). Fix for a full run: an Organization Policy Administrator (${SV_ORGPOL_REQUIRED_ROLE}) or roles/orgpolicy.policyViewer on folders/${folder} runs apply.sh again."
    elif [ "${code}" != "200" ]; then
        echo -e "\033[0;34m==>\033[0m Organization Policy Administrator preflight: folder policy in state; read check failed (HTTP ${code:-none}), not excluded." >&2
    fi
    return 0
}

sv_org_policy_preflight() {
    local explicit folder tmp code granted missing p state_list in_state="" valid_folder=""
    SV_ORGPOL_PREFLIGHT_RESULT=""
    SV_ORGPOL_PREFLIGHT_WARNING=""
    SV_ORGPOL_READ_MISSING_IN_STATE=""
    SV_ORGPOL_TOKEN=""

    explicit="$(sv_tfvar 'create_folder_vm_external_ip_policy == null ? "unset" : tostring(var.create_folder_vm_external_ip_policy)')" || explicit="error"
    if [ "${explicit}" = "error" ]; then
        sv_orgpol_preflight_decide false "could not read create_folder_vm_external_ip_policy from ${TFVARS}"
        sv_orgpol_preflight_warn "Folder 'no external VM IPs' policy not set up: the vars file could not be evaluated for create_folder_vm_external_ip_policy. The install continues; each vend records VENDING.ORG_POLICY_NOT_ENFORCED."
        return 0
    fi

    folder="$(sv_tfvar castor_managed_workloads_folder_id)" || folder=""
    folder="${folder#folders/}"
    if [[ "${folder}" =~ ^[0-9]+$ ]]; then
        valid_folder=1
        state_list="$("${IAC_BIN}" state list 2>/dev/null)" || state_list=""
        if printf '%s\n' "${state_list}" | grep -Fxq "${SV_ORGPOL_STATE_ADDRESS}"; then
            in_state=1
        fi
    fi

    case "${explicit}" in
        true|false)
            SV_ORGPOL_PREFLIGHT_RESULT="${explicit}"
            echo -e "\033[0;34m==>\033[0m Organization Policy Administrator preflight skipped: create_folder_vm_external_ip_policy = ${explicit} is set in ${TFVARS} (explicit value wins)." >&2
            if [ "${explicit}" = "false" ]; then
                if [ -n "${in_state}" ]; then
                    # N1: count 0 plans the delete of the folder policy; the destroy gate refuses it without the flag.
                    sv_orgpol_preflight_warn "create_folder_vm_external_ip_policy = false in ${TFVARS} and the folder 'no external VM IPs' policy is in state: THIS PLAN DELETES IT (vended projects lose the guardrail). The apply refuses the delete unless you pass --allow-destroy=${PROJECT_ID} (and the delete needs ${SV_ORGPOL_REQUIRED_ROLE}). To keep it, remove the line or set it to true."
                else
                    sv_orgpol_preflight_warn "Folder 'no external VM IPs' policy not set up (create_folder_vm_external_ip_policy = false in ${TFVARS}). Vended projects get no external-IP guardrail and each vend records VENDING.ORG_POLICY_NOT_ENFORCED, until an Organization Policy Administrator (${SV_ORGPOL_REQUIRED_ROLE}) re-runs apply.sh apply with it removed or true."
                fi
            elif [ -n "${in_state}" ]; then
                sv_orgpol_in_state_read_check "${folder}"
            fi
            SV_ORGPOL_TOKEN=""
            return 0 ;;
    esac

    # unset: the preflight decides.
    if [ -z "${folder}" ]; then
        SV_ORGPOL_PREFLIGHT_RESULT="not-applicable"
        echo -e "\033[0;34m==>\033[0m Organization Policy Administrator preflight: castor_managed_workloads_folder_id is empty; no folder 'no external VM IPs' policy is planned." >&2
        return 0
    fi
    if [ -z "${valid_folder}" ]; then
        sv_orgpol_preflight_decide false "castor_managed_workloads_folder_id is not folders/<digits>"
        sv_orgpol_preflight_warn "Folder 'no external VM IPs' policy not set up: castor_managed_workloads_folder_id in ${TFVARS} is not folders/<digits>. The install continues; each vend records VENDING.ORG_POLICY_NOT_ENFORCED."
        return 0
    fi

    # Rule 4: already in state -> keep it planned (count 0 would plan a delete that needs the same role).
    if [ -n "${in_state}" ]; then
        sv_orgpol_preflight_decide true "folder policy already in state (kept: removing it needs ${SV_ORGPOL_REQUIRED_ROLE} too)"
        sv_orgpol_in_state_read_check "${folder}"
        SV_ORGPOL_TOKEN=""
        return 0
    fi

    sv_orgpol_token
    if [ -z "${SV_ORGPOL_TOKEN}" ]; then
        sv_orgpol_preflight_decide false "no access token for the permission check"
        sv_orgpol_preflight_warn "Folder 'no external VM IPs' policy not set up: could not get an access token to check ${SV_ORGPOL_REQUIRED_ROLE}. $(sv_orgpol_fix_text "${folder}")"
        return 0
    fi

    tmp="$(mktemp -d 2>/dev/null)" || tmp=""

    # Rule 5 (F2): a folder policy that StackVend does not manage already exists -> do not plan a create (409).
    code=""
    if [ -n "${tmp}" ]; then
        code="$(printf 'header = "Authorization: Bearer %s"\nheader = "x-goog-user-project: %s"\n' "${SV_ORGPOL_TOKEN}" "${PROJECT_ID}" \
            | curl -sS --max-time 20 --config - -o "${tmp}/existing.json" -w '%{http_code}' \
            "https://orgpolicy.googleapis.com/v2/folders/${folder}/policies/compute.vmExternalIpAccess" 2>/dev/null)" || code=""
    fi
    if [ "${code}" = "200" ]; then
        rm -rf "${tmp}"
        SV_ORGPOL_TOKEN=""
        sv_orgpol_preflight_decide false "a compute.vmExternalIpAccess policy already exists on folders/${folder} outside StackVend"
        sv_orgpol_preflight_warn "A folder 'no external VM IPs' policy (compute.vmExternalIpAccess) already exists on folders/${folder} outside StackVend, so StackVend does not create one (it would answer 409). Import it: tofu import 'google_org_policy_policy.managed_folder_vm_external_ip[0]' folders/${folder}/policies/compute.vmExternalIpAccess (run in infra/platform with the same vars file and create_folder_vm_external_ip_policy = true), or leave it: vending records ENFORCED if it is deny all."
        return 0
    fi

    # Rules 6-7: the decision call.
    code=""
    if [ -n "${tmp}" ]; then
        code="$(sv_orgpol_test_permissions "${folder}" '["orgpolicy.policies.create","orgpolicy.policies.update","orgpolicy.policy.get","orgpolicy.policy.set"]' "${tmp}/resp.json")"
    fi
    SV_ORGPOL_TOKEN=""
    missing=""
    if [ "${code}" = "200" ]; then
        granted="$(sv_orgpol_preflight_granted "${tmp}/resp.json")" || { granted=""; code="unparseable"; }
    fi
    if [ "${code}" = "200" ]; then
        for p in ${SV_ORGPOL_REQUIRED_PERMISSIONS}; do
            if ! printf '%s\n' "${granted}" | grep -Fxq "${p}"; then
                missing="${missing:+${missing} }${p}"
            fi
        done
    fi
    if [ -n "${tmp}" ]; then
        rm -rf "${tmp}"
    fi

    if [ "${code}" = "200" ] && [ -z "${missing}" ]; then
        sv_orgpol_preflight_decide true "Organization Policy Administrator permissions present on folders/${folder}"
        return 0
    fi
    if [ "${code}" = "200" ]; then
        sv_orgpol_preflight_decide false "missing on folders/${folder}: ${missing}"
        sv_orgpol_preflight_warn "Folder 'no external VM IPs' policy not set up: you lack ${missing} on folders/${folder}. $(sv_orgpol_fix_text "${folder}")"
    else
        sv_orgpol_preflight_decide false "permission check failed (HTTP ${code:-none})"
        sv_orgpol_preflight_warn "Folder 'no external VM IPs' policy not set up: the ${SV_ORGPOL_REQUIRED_ROLE} check on folders/${folder} failed (HTTP ${code:-none}). If you are an Organization Policy Administrator, set create_folder_vm_external_ip_policy = true in ${TFVARS} and re-run. $(sv_orgpol_fix_text "${folder}")"
    fi
    return 0
}
