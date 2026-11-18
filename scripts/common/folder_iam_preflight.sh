# shellcheck shell=bash
# ==============================================================================
# STACKVEND: read-only Folder IAM Admin preflight (BOOTSTRAP-FOLDER-IAM-PREFLIGHT; sourced, never executed)
# ==============================================================================
# Owner 11-03 (register row BOOTSTRAP-FOLDER-IAM-PREFLIGHT): the platform Terraform grants StackVend's service
# accounts their roles on the managed workloads folder (google_folder_iam_member in infra/platform/main.tf). That
# needs resourcemanager.folders.setIamPolicy on the folder (Folder IAM Admin, roles/resourcemanager.folderIamAdmin).
# Without it the apply stops with 403 part-way through. This check runs BEFORE any write (scripts/bootstrap.sh: right
# after the folder prompt, before any API enable, state bucket, vars file or tofu call; scripts/apply.sh: before the
# plan of `apply`) and refuses with a typed error:
#
#   - folder empty                                  -> nothing to check (return 0; no call);
#   - folder not folders/<digits> or <digits>       -> <PREFIX>_FOLDER_ID_INVALID (no call);
#   - one READ-ONLY call: Cloud Resource Manager v3 folders/<id>:testIamPermissions for the caller
#     (resourcemanager.folders.setIamPolicy, resourcemanager.folders.get; an organization grant is inherited by
#     the folder, so this is the exact check). The token comes from `gcloud auth print-access-token` and goes to
#     curl on stdin (--config -), never on the command line;
#   - 200 with both permissions                     -> [OK] line, return 0;
#   - 200 with either missing, 403 or 404 (the folder is not visible: no role on it, or it does not exist)
#                                                   -> <PREFIX>_FOLDER_IAM_MISSING with the grant command;
#   - anything else (no token, curl failure, 5xx, other HTTP code, a body that is not the documented JSON)
#                                                   -> <PREFIX>_FOLDER_IAM_UNCHECKED (fail closed: the apply would
#                                                      403 later anyway), with the HTTP code and error message.
# Every refusal exits through sv_die (scripts/common/platform_target.sh) and says nothing was changed.
# Bash 3.2 compatible.
# ==============================================================================

SV_FOLDER_IAM_ROLE="roles/resourcemanager.folderIamAdmin"
SV_FOLDER_IAM_PERMISSIONS="resourcemanager.folders.setIamPolicy resourcemanager.folders.get"
SV_FOLDER_IAM_PERMISSIONS_JSON='["resourcemanager.folders.setIamPolicy","resourcemanager.folders.get"]'

# The gcloud member for an account: serviceAccount:<sa> for a service account, else user:<account>.
sv_folder_iam_member() {
    case "$1" in
        "") echo "user:<your account>" ;;
        *.gserviceaccount.com) echo "serviceAccount:$1" ;;
        *) echo "user:$1" ;;
    esac
}

# Prints the granted permissions (one per line) from a testIamPermissions response file; rc != 0 when the body is
# not the documented JSON shape.
sv_folder_iam_granted() {
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

# The error.message of a Google API error body (empty when there is none). One line, at most 300 characters.
sv_folder_iam_error_message() {
    python3 -c '
import json, sys
try:
    body = json.load(open(sys.argv[1]))
    msg = body.get("error", {}).get("message", "") if isinstance(body, dict) else ""
except (OSError, ValueError, AttributeError):
    msg = ""
print(" ".join(str(msg).split())[:300])
' "$1" 2>/dev/null || true
}

# $1 = error code prefix (BOOTSTRAP | APPLY), $2 = folder (folders/<digits>, <digits> or empty), $3 = account.
sv_folder_iam_preflight() {
    local prefix="$1" raw="$2" account="$3" folder who member token tmp code rc granted missing p msg grant why
    if [ -z "${raw}" ]; then
        return 0
    fi
    folder="${raw#folders/}"
    if ! [[ "${folder}" =~ ^[0-9]+$ ]]; then
        sv_die "${prefix}_FOLDER_ID_INVALID: the managed workloads folder '${raw}' is not folders/<digits> (e.g. folders/123456789012), so its IAM cannot be checked and the platform apply would fail. Nothing was changed. Re-run with the folder's numeric id."
    fi
    who="${account:-the active gcloud account}"
    member="$(sv_folder_iam_member "${account}")"
    grant="gcloud resource-manager folders add-iam-policy-binding ${folder} --member=\"${member}\" --role=\"${SV_FOLDER_IAM_ROLE}\""

    token="$(gcloud auth print-access-token 2>/dev/null)" || token=""
    if [ -z "${token}" ]; then
        sv_die "${prefix}_FOLDER_IAM_UNCHECKED: could not get an access token (gcloud auth print-access-token) to check Folder IAM Admin (${SV_FOLDER_IAM_ROLE}) on folders/${folder}. Nothing was changed. Run gcloud auth login and re-run."
    fi
    tmp="$(mktemp -d 2>/dev/null)" || tmp=""
    if [ -z "${tmp}" ]; then
        sv_die "${prefix}_FOLDER_IAM_UNCHECKED: mktemp failed, so Folder IAM Admin (${SV_FOLDER_IAM_ROLE}) on folders/${folder} could not be checked. Nothing was changed."
    fi
    rc=0
    code="$(printf 'header = "Authorization: Bearer %s"\n' "${token}" | curl -sS --max-time 20 --config - \
        -X POST -H "Content-Type: application/json" --data "{\"permissions\":${SV_FOLDER_IAM_PERMISSIONS_JSON}}" \
        -o "${tmp}/resp.json" -w '%{http_code}' \
        "https://cloudresourcemanager.googleapis.com/v3/folders/${folder}:testIamPermissions" 2>/dev/null)" || rc=$?
    token=""
    missing=""
    if [ "${rc}" -eq 0 ] && [ "${code}" = "200" ]; then
        if granted="$(sv_folder_iam_granted "${tmp}/resp.json")"; then
            for p in ${SV_FOLDER_IAM_PERMISSIONS}; do
                if ! printf '%s\n' "${granted}" | grep -Fxq "${p}"; then
                    missing="${missing:+${missing} }${p}"
                fi
            done
        else
            code="200 (malformed body)"
        fi
    fi
    msg="$(sv_folder_iam_error_message "${tmp}/resp.json")"
    rm -rf "${tmp}"

    if [ "${rc}" -eq 0 ] && [ "${code}" = "200" ] && [ -z "${missing}" ]; then
        echo -e "\033[0;32m[OK]\033[0m Folder IAM Admin preflight: ${who} can set IAM on folders/${folder}."
        return 0
    fi
    if [ "${rc}" -eq 0 ] && { [ "${code}" = "200" ] || [ "${code}" = "403" ] || [ "${code}" = "404" ]; }; then
        if [ "${code}" = "200" ]; then
            why="${who} lacks ${missing} on folders/${folder}"
        else
            why="folders/${folder} is not visible to ${who} (HTTP ${code}${msg:+: ${msg}}): no role on that folder, or it does not exist"
        fi
        sv_die "${prefix}_FOLDER_IAM_MISSING: ${why}. Folder IAM Admin (${SV_FOLDER_IAM_ROLE}) on the managed workloads folder is needed because the platform apply grants StackVend's service accounts their roles on that folder; without it the apply stops with 403 part-way. A folder or organization admin grants it with: ${grant} (check every installer right with: bash scripts/pre-bootstrap.sh --check-only). Nothing was changed. Re-run after the grant."
    fi
    if [ "${rc}" -ne 0 ]; then
        code="none (curl rc=${rc})"
    fi
    sv_die "${prefix}_FOLDER_IAM_UNCHECKED: the Folder IAM Admin (${SV_FOLDER_IAM_ROLE}) check on folders/${folder} failed (HTTP ${code:-none}${msg:+: ${msg}}), so the run stops here rather than fail with 403 part-way through the apply. Nothing was changed. Retry; if you lack the role, a folder or organization admin grants it with: ${grant}"
}
