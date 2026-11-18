#!/usr/bin/env bash
# ==============================================================================
# STACKVEND UPGRADER, STEP 0: VERIFY THE RELEASE BEFORE ANY OF ITS CODE RUNS
# ==============================================================================
# FROZEN CONTENT (SELFUP P3b; plan docs/planning/self-upgrade-plan.md §3.3, plan RT 11-02 H-4, M-6, §7 row B2).
# Core Terraform embeds this file and guard.py (same directory) into the "Update StackVend" Cloud Build trigger as
# its inline step 0 (infra/platform/platform_upgrader.tf; a parity test keeps the embedded copies equal to these
# files). A change here reaches an install only through `apply.sh apply`. Nothing from the release being installed
# runs before the last step below hands over to it.
#
# Usage:
#   verify.sh run --request-id <32 hex> --project <id> --region <region> --guard-database <db>
#                 --official-signers <file> --workdir <dir>
#       The trigger's entry point. Every step; on success it hands over to <dir>/src/scripts/upgrade/run.sh
#       (the verified target's own stages) with <dir>/verified.json.
#   verify.sh verify --workdir <dir>
#       Steps 3-8 only, from <dir>/inputs.json, <dir>/signers.json and <dir>/allowed_signers (written by step 1-2;
#       used by `run` and by the hermetic tests). Leaves <dir>/verified.json and the checkout in <dir>/src.
#
# Steps (plan §3.3):
#   1. guard.py inputs: request id (exactly 32 hex), the request in the guard database (status REQUESTED, holds the
#      lease), claimed once (create-only progress record); the release source re-read and validated
#      (RELEASE_SOURCE_INVALID, UPDATE_CHECK_OFF, SOURCE_SETTING_CHANGED, BRANCH_NOT_SUPPORTED); the trusted signers =
#      the installed official allowed_signers (when trusted) + the custom keys of the source; the platform stamp; the
#      version floor = max(digest-matched record components, stamp) (H-4).
#   2. a fresh repository; `git fetch` of exactly refs/tags/<tag> from https://github.com/<repository>.git, no
#      checkout, hooks off, fsmonitor off, no submodules, system + global config off            -> FETCH_FAILED
#   3. the ref must be an annotated tag object named <tag>                              -> SIGNATURE_INVALID
#   4. git verify-tag (gpg.format=ssh) against the trusted signers  -> SIGNATURE_INVALID / UNKNOWN_SIGNER
#   5. the tag's commit must be the commit the administrator confirmed                 -> SOURCE_CHANGED (moved tag)
#   6. release-manifest.json read as a blob of that commit (no checkout) and decided by guard.py decide:
#      MANIFEST_INVALID / MANIFEST_UNSUPPORTED / MANIFEST_MISMATCH / PREVIEW_NOT_ALLOWED / PLATFORM_STAMP_UNKNOWN /
#      DOWNGRADE_REFUSED / NEEDS_APPLY_SH (with the terminal steps)
#   7. checkout of the verified commit (detached; hooks off)
#   8. the target must carry scripts/upgrade/run.sh                                  -> TARGET_NOT_UPGRADABLE
#   9. (run only) progress -> VERIFIED; exec the target's scripts/upgrade/run.sh <dir>/verified.json
#
# Exit status: 0, or guard.py's code for the refusal (one line `stackvend-upgrade: REFUSED <CODE>: <message>`).
# Needs: bash, git (>= 2.34, SSH signatures), ssh-keygen (OpenSSH >= 8.2), python3 (>= 3.8). No OpenTofu, no gcloud.
# ==============================================================================

set -u -o pipefail

SV_STEP0_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SV_GUARD="${SV_STEP0_DIR}/guard.py"
SV_WORK=""

sv_guard() { python3 "${SV_GUARD}" "$@"; }

# sv_refuse <CODE> <message>: print, write <workdir>/refusal.json, exit with the code's status.
sv_refuse() {
    local rc
    sv_guard refuse --code "$1" --message "$2" --out-dir "${SV_WORK}"
    rc=$?
    exit "${rc}"
}

# git with nothing from the environment or the fetched repository able to run code.
sv_git() {
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_TERMINAL_PROMPT=0 git -C "${SV_WORK}/src" \
        -c core.hooksPath=/dev/null -c core.fsmonitor=false -c submodule.recurse=false "$@"
}

sv_verify_target() {
    local fields repository tag expected kind type name commit signer size rc
    for f in inputs.json signers.json allowed_signers; do
        [ -f "${SV_WORK}/${f}" ] || sv_refuse INTERNAL "step 0 input ${f} is missing"
    done
    fields="$(sv_guard fields --inputs "${SV_WORK}/inputs.json")" || exit $?
    read -r repository tag expected kind <<EOF
${fields}
EOF
    [ -n "${kind:-}" ] || sv_refuse INTERNAL "step 0 inputs are incomplete"

    # 2. fetch exactly the tag (no other refs, no tags following, no checkout)
    rm -rf "${SV_WORK}/src"
    mkdir -p "${SV_WORK}/src" || sv_refuse INTERNAL "cannot create ${SV_WORK}/src"
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git init -q "${SV_WORK}/src" >/dev/null 2>&1 || sv_refuse INTERNAL "git init failed"
    if ! sv_git fetch --quiet --no-tags --no-recurse-submodules --depth=1 \
            "https://github.com/${repository}.git" "+refs/tags/${tag}:refs/tags/${tag}"; then
        sv_refuse FETCH_FAILED "could not fetch ${tag} from https://github.com/${repository}.git (repository not public, tag missing, or no network)"
    fi

    # 3. an annotated tag object that names this tag
    type="$(sv_git cat-file -t "refs/tags/${tag}" 2>/dev/null)" || type=""
    [ "${type}" = "tag" ] || sv_refuse SIGNATURE_INVALID "${tag} is not an annotated, signed tag (it is a ${type:-missing} object)"
    name="$(sv_git for-each-ref --format='%(tag)' "refs/tags/${tag}" 2>/dev/null)" || name=""
    [ "${name}" = "${tag}" ] || sv_refuse SIGNATURE_INVALID "the tag object published as ${tag} is named '${name}'"
    sv_git cat-file tag "refs/tags/${tag}" > "${SV_WORK}/tag-object" 2>/dev/null \
        || sv_refuse SIGNATURE_INVALID "cannot read the tag object of ${tag}"

    # 4. signature against the trusted signers only
    if sv_git -c gpg.format=ssh -c gpg.ssh.program=ssh-keygen \
            -c gpg.ssh.allowedSignersFile="${SV_WORK}/allowed_signers" \
            verify-tag "refs/tags/${tag}" >/dev/null 2>"${SV_WORK}/verify-tag.log"; then
        signer="$(sv_guard signer --tag-object "${SV_WORK}/tag-object" --signers "${SV_WORK}/signers.json" --out-dir "${SV_WORK}")" || exit $?
    else
        sv_guard classify --tag-object "${SV_WORK}/tag-object" --signers "${SV_WORK}/signers.json" --out-dir "${SV_WORK}"
        rc=$?
        [ "${rc}" -ne 0 ] || rc=70
        exit "${rc}"
    fi

    # 5. the commit the administrator confirmed (a moved tag stops here)
    commit="$(sv_git rev-parse --verify --quiet "refs/tags/${tag}^{commit}")" || commit=""
    [ "${commit}" = "${expected}" ] \
        || sv_refuse SOURCE_CHANGED "${tag} now points at ${commit:-nothing}, not at ${expected} (the commit the administrator confirmed): the tag moved"

    # 6. the manifest as a blob of the verified commit, decided by the installed parser
    size="$(sv_git cat-file -s "${commit}:release-manifest.json" 2>/dev/null)" || size=""
    [ -n "${size}" ] || sv_refuse MANIFEST_INVALID "${tag} has no release-manifest.json"
    [ "${size}" -le 4096 ] 2>/dev/null || sv_refuse MANIFEST_INVALID "release-manifest.json is larger than 4096 bytes"
    sv_git cat-file blob "${commit}:release-manifest.json" > "${SV_WORK}/release-manifest.json" \
        || sv_refuse MANIFEST_INVALID "cannot read release-manifest.json of ${tag}"
    sv_guard decide --inputs "${SV_WORK}/inputs.json" --commit "${commit}" --manifest "${SV_WORK}/release-manifest.json" \
        --signer "${signer}" --out "${SV_WORK}/verified.json" || exit $?

    # 7. only now: the verified tree
    sv_git -c advice.detachedHead=false checkout -q --detach "${commit}" \
        || sv_refuse INTERNAL "checkout of the verified commit ${commit} failed"

    # 8. the target's own stages
    [ -f "${SV_WORK}/src/scripts/upgrade/run.sh" ] \
        || sv_refuse TARGET_NOT_UPGRADABLE "${tag} has no scripts/upgrade/run.sh; install it with the terminal path"
    echo "stackvend-upgrade: VERIFIED ${tag} (${commit}), signed by ${signer}"
}

sv_usage() {
    sed -n '13,20p' "${BASH_SOURCE[0]}" >&2
    exit 2
}

sv_main() {
    local cmd="${1:-}" request_id="" project="" region="" guard_db="" official="" rc
    [ -n "${cmd}" ] || sv_usage
    shift
    while [ $# -gt 0 ]; do
        case "$1" in
            --request-id) request_id="${2:-}"; shift 2 ;;
            --project) project="${2:-}"; shift 2 ;;
            --region) region="${2:-}"; shift 2 ;;
            --guard-database) guard_db="${2:-}"; shift 2 ;;
            --official-signers) official="${2:-}"; shift 2 ;;
            --workdir) SV_WORK="${2:-}"; shift 2 ;;
            *) sv_usage ;;
        esac
    done
    [ -n "${SV_WORK}" ] || sv_usage
    mkdir -p "${SV_WORK}" || exit 2
    SV_WORK="$(cd "${SV_WORK}" && pwd)"
    case "${cmd}" in
        verify)
            sv_verify_target ;;
        run)
            { [ -n "${request_id}" ] && [ -n "${project}" ] && [ -n "${region}" ] && [ -n "${guard_db}" ] \
                && [ -n "${official}" ]; } || sv_usage
            sv_guard inputs --request-id "${request_id}" --project "${project}" --region "${region}" \
                --guard-database "${guard_db}" --official-signers "${official}" --out-dir "${SV_WORK}" || exit $?
            ( sv_verify_target )
            rc=$?
            if [ "${rc}" -ne 0 ]; then
                sv_guard report --request-id "${request_id}" --project "${project}" \
                    --refusal-file "${SV_WORK}/refusal.json" --stage VERIFYING || true
                exit "${rc}"
            fi
            sv_guard report --request-id "${request_id}" --project "${project}" --status RUNNING --stage VERIFIED \
                --verified-file "${SV_WORK}/verified.json" || exit $?
            exec bash "${SV_WORK}/src/scripts/upgrade/run.sh" "${SV_WORK}/verified.json"
            ;;
        *) sv_usage ;;
    esac
}

sv_main "$@"
