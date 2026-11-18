# shellcheck shell=bash
# ==============================================================================
# STACKVEND: read-only Tag Administrator preflight (lane 18 v3; sourced, never executed)
# ==============================================================================
# Owner rule 10-18: "Install must be simple, smooth and never fail, only providing warnings in settings
# for lack of billing user and tag admin."
#
# The lane 18 S0 deletion-safety tag (infra/platform/destructive_guard.tf: an ORGANIZATION tag key
# stackvend-managed-<project>, value "true", tagUser for the vending identity) needs an org Tag
# Administrator. Without that role the apply used to stop half-way with a 403. This preflight decides,
# before the plan, whether the tag resources are planned:
#
#   1. an explicit `create_stackvend_managed_tag = true|false` in the tfvars wins (nothing is called);
#   2. no organization_id or no castor_managed_workloads_folder_id -> nothing to decide (the tag is never
#      planned; the existing `check "stackvend_managed_tag_configured"` warns);
#   3. one READ-ONLY call: Cloud Resource Manager v3 organizations/<org>:testIamPermissions for
#      resourcemanager.tagKeys.create, resourcemanager.tagValues.create, resourcemanager.tagValues.setIamPolicy
#      (token from `gcloud auth print-access-token`, passed to curl on stdin, never on the command line);
#   4. all three granted -> TF_VAR_create_stackvend_managed_tag=true;
#      anything else (missing permission, HTTP error, curl/gcloud/python failure, bad org id) -> false and a
#      WARNING; the apply continues and succeeds;
#   5. exception: the tag is already in state (an earlier apply by a Tag Administrator). Then it stays
#      planned (true): count 0 would plan its destroy, which prevent_destroy refuses, so the apply would fail.
#      Two cases have NO non-failing choice; the preflight says so loudly (still returns 0, RT F4/F5):
#      - partial state (the key is in state but not all three resources: a pre-v3 apply that died with the
#        403 on tagValues.create) and no create permission: the apply stops at the missing create;
#      - the tag in state and no read permission (tagKeys.get / tagValues.get / tagValues.getIamPolicy, e.g.
#        org roles/resourcemanager.tagViewer): the plan's refresh of the tag would answer 403. Row L18-F5
#        (owner 10-18): the preflight sets SV_TAG_READ_MISSING_IN_STATE=1 and scripts/apply.sh excludes the
#        three tag resources (OpenTofu -exclude, no -target) so the run succeeds; bootstrap only warns.
#
# One request asks for the three create permissions (the decision) and the three read permissions (the
# in-state warnings only).
#
# The decision reaches tofu through TF_VAR_create_stackvend_managed_tag, exported by THIS function only,
# after sv_scrub_tofu_env has refused any caller-provided TF_VAR_*. A value in the vars file (-var-file)
# beats a TF_VAR_* in tofu's precedence, so rule 1 also holds inside tofu.
#
# Never fails: every path returns 0 (callers may still add `|| true`). Needs IAC_BIN, PLATFORM_DIR, TFVARS
# (sv_tfvar) and, for rule 5, an initialised backend (`state list`). Bash 3.2 compatible.
# BOOTSTRAP-TAG-ADMIN-CONFIRM (owner 11-11): the callers print sv_tag_unprotected_block (end of this file) when the tag
# will not be created; scripts/bootstrap.sh then asks before continuing, as early as it can (sv_tag_admin_early_check,
# before any write; one extra read-only GET of the platform state), apply.sh never asks.
# ==============================================================================

SV_TAG_REQUIRED_ROLE="roles/resourcemanager.tagAdmin"
SV_TAG_REQUIRED_PERMISSIONS="resourcemanager.tagKeys.create resourcemanager.tagValues.create resourcemanager.tagValues.setIamPolicy"
SV_TAG_READ_PERMISSIONS="resourcemanager.tagKeys.get resourcemanager.tagValues.get resourcemanager.tagValues.getIamPolicy"
SV_TAG_STATE_ADDRESSES="google_tags_tag_key.stackvend_managed[0] google_tags_tag_value.stackvend_managed_true[0] google_tags_tag_value_iam_member.stackvend_managed_vending_tag_user[0]"
# Set for the caller's final summary (bootstrap prints it again after the apply).
SV_TAG_PREFLIGHT_RESULT=""
SV_TAG_PREFLIGHT_WARNING=""
# BOOTSTRAP-TAG-ADMIN-CONFIRM (owner 11-11): why the tag is or is not planned, for the callers' prominent block
# (sv_tag_unprotected_block) and bootstrap's question. REASON is one of: granted, in-state, explicit-true,
# explicit-false, missing (the check answered: permissions missing), unchecked (the check could not tell),
# not-applicable (no organization_id or no castor_managed_workloads_folder_id). DETAIL: the missing permissions or
# why the check could not tell. ORG: the organization number when known.
SV_TAG_PREFLIGHT_REASON=""
SV_TAG_PREFLIGHT_DETAIL=""
SV_TAG_PREFLIGHT_ORG=""
# Lane 18 v3 / row L18-F5: set to 1 when the tag is in state and the applier lacks the tag read permissions.
# scripts/apply.sh then excludes the three tag resources from the plan (OpenTofu -exclude) so the run succeeds.
SV_TAG_READ_MISSING_IN_STATE=""
SV_TAG_EXCLUDE_ADDRESSES="google_tags_tag_key.stackvend_managed google_tags_tag_value.stackvend_managed_true google_tags_tag_value_iam_member.stackvend_managed_vending_tag_user"

sv_tag_preflight_warn() {
    SV_TAG_PREFLIGHT_WARNING="$*"
    echo -e "\033[1;33m[WARN]\033[0m $*" >&2
}

sv_tag_preflight_decide() {
    # $1 = true|false; $2 = reason (printed)
    SV_TAG_PREFLIGHT_RESULT="$1"
    TF_VAR_create_stackvend_managed_tag="$1"
    export TF_VAR_create_stackvend_managed_tag
    echo -e "\033[0;34m==>\033[0m Tag Administrator preflight: create_stackvend_managed_tag=$1 ($2)" >&2
}

# Prints the granted permissions (one per line) from a testIamPermissions response file; rc != 0 when the
# body is not the documented JSON shape.
sv_tag_preflight_granted() {
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

# The one READ-ONLY call: organizations/<org>:testIamPermissions for the three create and three read permissions.
# $1 = organization number, $2 = access token (on curl's stdin, never on the command line), $3 = response file.
# Prints the HTTP code; rc != 0 when curl fails.
sv_tag_test_org_permissions() {
    local body
    body='{"permissions":["resourcemanager.tagKeys.create","resourcemanager.tagValues.create","resourcemanager.tagValues.setIamPolicy","resourcemanager.tagKeys.get","resourcemanager.tagValues.get","resourcemanager.tagValues.getIamPolicy"]}'
    printf 'header = "Authorization: Bearer %s"\n' "$2" | curl -sS --max-time 20 --config - \
        -X POST -H "Content-Type: application/json" --data "${body}" -o "$3" -w '%{http_code}' \
        "https://cloudresourcemanager.googleapis.com/v3/organizations/$1:testIamPermissions" 2>/dev/null
}

sv_tag_admin_preflight() {
    local explicit org folder token tmp code granted missing missing_read="" p state_list addr in_state=""
    local warn_tail in_state_count=0
    SV_TAG_READ_MISSING_IN_STATE=""
    SV_TAG_PREFLIGHT_REASON=""
    SV_TAG_PREFLIGHT_DETAIL=""
    SV_TAG_PREFLIGHT_ORG=""

    explicit="$(sv_tfvar 'create_stackvend_managed_tag == null ? "unset" : tostring(var.create_stackvend_managed_tag)')" || explicit="error"
    case "${explicit}" in
        true|false)
            SV_TAG_PREFLIGHT_RESULT="${explicit}"
            SV_TAG_PREFLIGHT_REASON="explicit-${explicit}"
            echo -e "\033[0;34m==>\033[0m Tag Administrator preflight skipped: create_stackvend_managed_tag = ${explicit} is set in ${TFVARS} (explicit value wins)." >&2
            if [ "${explicit}" = "false" ]; then
                sv_tag_preflight_warn "Deletion safety tag not set up (create_stackvend_managed_tag = false in ${TFVARS}). StackVend cannot decommission projects until a Tag Administrator (${SV_TAG_REQUIRED_ROLE}) re-runs apply.sh apply with it removed or true."
            fi
            return 0 ;;
        unset) ;;
        *)
            SV_TAG_PREFLIGHT_REASON="unchecked"
            SV_TAG_PREFLIGHT_DETAIL="the vars file could not be evaluated for create_stackvend_managed_tag"
            sv_tag_preflight_decide false "could not read create_stackvend_managed_tag from ${TFVARS}"
            sv_tag_preflight_warn "Deletion safety tag not set up: the vars file could not be evaluated for create_stackvend_managed_tag. The install continues; project deletes stay refused until a Tag Administrator re-runs apply.sh apply."
            return 0 ;;
    esac

    org="$(sv_tfvar organization_id)" || org=""
    folder="$(sv_tfvar castor_managed_workloads_folder_id)" || folder=""
    if [ -z "${org}" ] || [ -z "${folder}" ]; then
        SV_TAG_PREFLIGHT_RESULT="not-applicable"
        SV_TAG_PREFLIGHT_REASON="not-applicable"
        echo -e "\033[0;34m==>\033[0m Tag Administrator preflight: organization_id or castor_managed_workloads_folder_id is empty; no deletion safety tag is planned (project deletes stay refused)." >&2
        return 0
    fi
    org="${org#organizations/}"
    if ! [[ "${org}" =~ ^[0-9]+$ ]]; then
        SV_TAG_PREFLIGHT_REASON="unchecked"
        SV_TAG_PREFLIGHT_DETAIL="organization_id is not organizations/<digits>"
        sv_tag_preflight_decide false "organization_id is not organizations/<digits>"
        sv_tag_preflight_warn "Deletion safety tag not set up: organization_id in ${TFVARS} is not organizations/<digits>. The install continues; project deletes stay refused."
        return 0
    fi
    SV_TAG_PREFLIGHT_ORG="${org}"
    warn_tail="The install continues without it. StackVend cannot decommission projects until a Tag Administrator (${SV_TAG_REQUIRED_ROLE} on organizations/${org}) re-runs: PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply. Control Center Settings shows this warning."

    # Rule 5: already in state -> keep it planned (never plan a refused destroy).
    state_list="$("${IAC_BIN}" state list 2>/dev/null)" || state_list=""
    in_state_count=0
    for addr in ${SV_TAG_STATE_ADDRESSES}; do
        if printf '%s\n' "${state_list}" | grep -Fxq "${addr}"; then
            in_state=1
            in_state_count=$((in_state_count + 1))
        fi
    done

    token="$(gcloud auth print-access-token 2>/dev/null)" || token=""
    if [ -z "${token}" ]; then
        if [ -n "${in_state}" ]; then
            SV_TAG_PREFLIGHT_REASON="in-state"
            sv_tag_preflight_decide true "tag already in state; permission check unavailable (no access token)"
            return 0
        fi
        SV_TAG_PREFLIGHT_REASON="unchecked"
        SV_TAG_PREFLIGHT_DETAIL="no access token for the permission check"
        sv_tag_preflight_decide false "no access token for the permission check"
        sv_tag_preflight_warn "Deletion safety tag not set up: could not get an access token to check ${SV_TAG_REQUIRED_ROLE}. ${warn_tail}"
        return 0
    fi

    tmp="$(mktemp -d 2>/dev/null)" || tmp=""
    code=""
    if [ -n "${tmp}" ]; then
        code="$(sv_tag_test_org_permissions "${org}" "${token}" "${tmp}/resp.json")" || code=""
    fi
    token=""
    missing=""
    if [ "${code}" = "200" ]; then
        granted="$(sv_tag_preflight_granted "${tmp}/resp.json")" || { granted=""; code="unparseable"; }
    fi
    if [ "${code}" = "200" ]; then
        for p in ${SV_TAG_REQUIRED_PERMISSIONS}; do
            if ! printf '%s\n' "${granted}" | grep -Fxq "${p}"; then
                missing="${missing:+${missing} }${p}"
            fi
        done
        for p in ${SV_TAG_READ_PERMISSIONS}; do
            if ! printf '%s\n' "${granted}" | grep -Fxq "${p}"; then
                missing_read="${missing_read:+${missing_read} }${p}"
            fi
        done
    fi
    if [ -n "${tmp}" ]; then
        rm -rf "${tmp}"
    fi

    if [ "${code}" = "200" ] && [ -z "${missing}" ]; then
        SV_TAG_PREFLIGHT_REASON="granted"
        sv_tag_preflight_decide true "Tag Administrator permissions present on organizations/${org}"
        if [ -n "${in_state}" ] && [ -n "${missing_read}" ]; then
            SV_TAG_READ_MISSING_IN_STATE=1
            sv_tag_preflight_warn "The deletion safety tag is in state but you lack ${missing_read} on organizations/${org}: refreshing it would answer 403. Fix for a full run: roles/resourcemanager.tagViewer on organizations/${org}."
        fi
        return 0
    fi
    if [ -n "${in_state}" ]; then
        SV_TAG_PREFLIGHT_REASON="in-state"
        sv_tag_preflight_decide true "tag already in state (kept: removing it is refused by prevent_destroy)"
        if [ "${in_state_count}" -lt 3 ]; then
            # RT F4: no non-failing choice exists (false = destroy the key, refused by prevent_destroy).
            sv_tag_preflight_warn "THIS APPLY WILL STOP AT THE TAG: only ${in_state_count} of the 3 deletion safety tag resources are in state (an earlier apply stopped half-way) and you are not a Tag Administrator on organizations/${org}. The apply will fail when it creates the missing tag value / IAM (403); the other changes in the plan may already be applied by then. Have a Tag Administrator (${SV_TAG_REQUIRED_ROLE}) run: PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply."
        elif [ "${code}" = "200" ] && [ -n "${missing_read}" ]; then
            # RT F5: the refresh of the in-state tag needs read access.
            SV_TAG_READ_MISSING_IN_STATE=1
            sv_tag_preflight_warn "The deletion safety tag is in state but you lack ${missing_read} on organizations/${org}: refreshing it would answer 403. Fix for a full run: roles/resourcemanager.tagViewer on organizations/${org} (or run as a Tag Administrator)."
        else
            sv_tag_preflight_warn "You are not a Tag Administrator on organizations/${org}; the existing deletion safety tag is kept unchanged. Any change to it needs ${SV_TAG_REQUIRED_ROLE}."
        fi
        return 0
    fi
    if [ "${code}" = "200" ]; then
        SV_TAG_PREFLIGHT_REASON="missing"
        SV_TAG_PREFLIGHT_DETAIL="${missing}"
        sv_tag_preflight_decide false "missing on organizations/${org}: ${missing}"
        sv_tag_preflight_warn "Deletion safety tag not set up: you lack ${missing} on organizations/${org}. ${warn_tail}"
    else
        SV_TAG_PREFLIGHT_REASON="unchecked"
        SV_TAG_PREFLIGHT_DETAIL="the permission check failed (HTTP ${code:-none})"
        sv_tag_preflight_decide false "permission check failed (HTTP ${code:-none})"
        sv_tag_preflight_warn "Deletion safety tag not set up: the ${SV_TAG_REQUIRED_ROLE} check on organizations/${org} failed (HTTP ${code:-none}). ${warn_tail}"
    fi
    return 0
}

# ------------------------------------------------------------------------------
# BOOTSTRAP-TAG-ADMIN-CONFIRM (owner 11-11): the prominent "no deletion safety" block
# ------------------------------------------------------------------------------
# A one-line warning was easy to miss on a real install. Both callers print this block after the preflight when the
# tag will not be created (sv_tag_unprotected): scripts/bootstrap.sh then asks "Continue without deletion safety?
# [y/N]"; scripts/apply.sh only prints it (no prompt; its non-interactive behavior is unchanged). Prints to stderr.

# rc 0 unless the preflight decided this run creates (or keeps) the deletion safety tag. Fails closed: an empty or
# unexpected result counts as unprotected.
sv_tag_unprotected() {
    [ "${SV_TAG_PREFLIGHT_RESULT}" != "true" ]
}

# ------------------------------------------------------------------------------
# BOOTSTRAP-TAG-ADMIN-CONFIRM review F1: the EARLY check (scripts/bootstrap.sh, right after the folder IAM preflight,
# before any API enable, gcloud config change, vars file, state bucket or tofu call). Read-only.
# ------------------------------------------------------------------------------
# $1 = organization_id as answered, $2 = managed workloads folder id as answered, $3 = project id.
# Sets SV_TAG_EARLY to one of:
#   granted        - the three create permissions are present (no question; the late preflight decides as before);
#   not-applicable - no organization or no folder: the tag cannot be created (ask now);
#   missing        - the check answered and permissions are missing, and the tag is not in this project's platform
#                    state (ask now);
#   unchecked      - the check could not tell (HTTP error, no token, bad organization id), and the tag is not in
#                    state (ask now; never reported as granted);
#   in-state       - not confirmed, but the tag is already in the platform state (a re-run of an installed
#                    platform): rule 5 keeps it planned, so there is nothing to ask;
#   deferred       - not confirmed and the platform state could not be read: the late preflight (which reads state
#                    through tofu) decides, and bootstrap asks there if the tag will not be created.
# Also sets SV_TAG_PREFLIGHT_REASON / _DETAIL / _ORG for sv_tag_unprotected_block. The state is read with one GET of
# gs://castor-tfstate-<project>/platform/state/default.tfstate (the same object and token handling as bootstrap's
# existing-vars-file check): 404 = no state yet.
sv_tag_admin_early_check() {
    local org="${1#organizations/}" folder="$2" project="$3" token tmp code granted missing="" p verdict
    SV_TAG_EARLY=""
    SV_TAG_PREFLIGHT_REASON=""
    SV_TAG_PREFLIGHT_DETAIL=""
    SV_TAG_PREFLIGHT_ORG=""
    if [ -z "$1" ] || [ -z "${folder}" ]; then
        SV_TAG_EARLY="not-applicable"
        SV_TAG_PREFLIGHT_REASON="not-applicable"
        return 0
    fi
    token="$(gcloud auth print-access-token 2>/dev/null)" || token=""
    tmp="$(mktemp -d 2>/dev/null)" || tmp=""
    if ! [[ "${org}" =~ ^[0-9]+$ ]]; then
        SV_TAG_PREFLIGHT_REASON="unchecked"
        SV_TAG_PREFLIGHT_DETAIL="organization_id is not organizations/<digits>"
    elif [ -z "${token}" ] || [ -z "${tmp}" ]; then
        SV_TAG_PREFLIGHT_ORG="${org}"
        SV_TAG_PREFLIGHT_REASON="unchecked"
        SV_TAG_PREFLIGHT_DETAIL="no access token for the permission check"
    else
        SV_TAG_PREFLIGHT_ORG="${org}"
        code="$(sv_tag_test_org_permissions "${org}" "${token}" "${tmp}/resp.json")" || code=""
        if [ "${code}" = "200" ]; then
            granted="$(sv_tag_preflight_granted "${tmp}/resp.json")" || { granted=""; code="unparseable"; }
        fi
        if [ "${code}" = "200" ]; then
            for p in ${SV_TAG_REQUIRED_PERMISSIONS}; do
                if ! printf '%s\n' "${granted}" | grep -Fxq "${p}"; then
                    missing="${missing:+${missing} }${p}"
                fi
            done
            if [ -z "${missing}" ]; then
                SV_TAG_EARLY="granted"
                SV_TAG_PREFLIGHT_REASON="granted"
                rm -rf "${tmp}"
                return 0
            fi
            SV_TAG_PREFLIGHT_REASON="missing"
            SV_TAG_PREFLIGHT_DETAIL="${missing}"
        else
            SV_TAG_PREFLIGHT_REASON="unchecked"
            SV_TAG_PREFLIGHT_DETAIL="the permission check failed (HTTP ${code:-none})"
        fi
    fi
    # Not confirmed. Rule 5: a tag already in the platform state stays planned (never ask that user).
    verdict="unknown"
    if [ -n "${token}" ] && [ -n "${tmp}" ]; then
        code="$(printf 'header = "Authorization: Bearer %s"\n' "${token}" \
            | curl -sS --max-time 30 --config - -o "${tmp}/state.json" -w '%{http_code}' \
                "https://storage.googleapis.com/storage/v1/b/castor-tfstate-${project}/o/platform%2Fstate%2Fdefault.tfstate?alt=media" \
                2>/dev/null)" || code=""
        if [ "${code}" = "404" ]; then
            verdict="no"
        elif [ "${code}" = "200" ]; then
            verdict="$(python3 -I -c '
import json, sys
tag = {("google_tags_tag_key", "stackvend_managed"), ("google_tags_tag_value", "stackvend_managed_true"),
       ("google_tags_tag_value_iam_member", "stackvend_managed_vending_tag_user")}
try:
    with open(sys.argv[1]) as f:
        res = json.load(f).get("resources")
    if not isinstance(res, list):
        raise ValueError
    hit = any(isinstance(r, dict) and r.get("mode") == "managed" and "module" not in r
              and (r.get("type"), r.get("name")) in tag and r.get("instances") for r in res)
    print("yes" if hit else "no")
except Exception:
    print("unknown")
' "${tmp}/state.json" 2>/dev/null)" || verdict="unknown"
        fi
    fi
    token=""
    if [ -n "${tmp}" ]; then
        rm -rf "${tmp}"
    fi
    case "${verdict}" in
        no) SV_TAG_EARLY="${SV_TAG_PREFLIGHT_REASON}" ;;
        yes) SV_TAG_EARLY="in-state" ;;
        *) SV_TAG_EARLY="deferred" ;;
    esac
    return 0
}

sv_tag_member() {
    case "$1" in
        "") echo "user:<your account>" ;;
        *.gserviceaccount.com) echo "serviceAccount:$1" ;;
        *) echo "user:$1" ;;
    esac
}

# $1 = the account that runs the install (may be empty); $2 = BOOTSTRAP or APPLY (the fix lines differ).
sv_tag_unprotected_block() {
    local account="$1" caller="$2" org who line
    org="${SV_TAG_PREFLIGHT_ORG:-<ORGANIZATION_ID>}"
    who="${account:-the account running this script}"
    line="=================================================================================="
    {
        echo ""
        echo -e "\033[1;33m${line}\033[0m"
        echo -e "\033[1;33m WARNING: NO DELETION SAFETY. StackVend will not be able to delete the projects it creates.\033[0m"
        echo -e "\033[1;33m${line}\033[0m"
        case "${SV_TAG_PREFLIGHT_REASON}" in
            missing)
                echo " ${account:-The account running this script} is not a Tag Administrator (${SV_TAG_REQUIRED_ROLE}) on organizations/${org}"
                echo " (missing: ${SV_TAG_PREFLIGHT_DETAIL}), so the deletion safety tag is not created." ;;
            not-applicable)
                echo " The organization ID or the managed workloads folder ID is empty, so the deletion safety tag"
                echo " cannot be created at all." ;;
            explicit-false)
                echo " create_stackvend_managed_tag = false is set in ${TFVARS}, so the deletion safety tag is not created." ;;
            *)
                echo " The Tag Administrator check could not tell whether ${who} has ${SV_TAG_REQUIRED_ROLE}"
                echo " on organizations/${org} (${SV_TAG_PREFLIGHT_DETAIL:-unknown error}). The role is NOT confirmed,"
                echo " so the deletion safety tag is not created." ;;
        esac
        echo " Without the tag, StackVend refuses every child-project delete and decommission (GUARD_UNCONFIGURED):"
        echo " it cannot delete or decommission the projects it creates until a Tag Administrator re-runs the"
        echo " platform apply. Control Center Settings shows this warning until then."
        echo ""
        if [ "${SV_TAG_PREFLIGHT_REASON}" = "not-applicable" ]; then
            if [ "${caller}" = "BOOTSTRAP" ]; then
                echo " Fix: re-run bootstrap as a Tag Administrator and enter both the organization ID and the managed"
                echo " workloads folder ID. An Organization Administrator grants the role with:"
            else
                echo " Fix: set organization_id and castor_managed_workloads_folder_id in ${TFVARS} and re-run"
                echo " the apply as a Tag Administrator. An Organization Administrator grants the role with:"
            fi
        else
            echo " Fix: an Organization Administrator runs:"
        fi
        echo "   gcloud organizations add-iam-policy-binding ${org} --member=\"$(sv_tag_member "${account}")\" --role=\"${SV_TAG_REQUIRED_ROLE}\""
        if [ "${caller}" = "BOOTSTRAP" ]; then
            echo " then re-run: bash scripts/bootstrap.sh"
            echo " (if you continue without it, a Tag Administrator later runs: PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply)"
        else
            if [ "${SV_TAG_PREFLIGHT_REASON}" = "explicit-false" ]; then
                echo " and removes create_stackvend_managed_tag = false from ${TFVARS} (or sets it to true);"
            fi
            echo " then a Tag Administrator runs: PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply"
        fi
        echo -e "\033[1;33m${line}\033[0m"
    } >&2
}
