#!/usr/bin/env bash
# ==============================================================================
# STACKVEND: UPGRADE AN INSTALL TO A RELEASE TAG (FD-4DA item 9)
# ==============================================================================
# Usage:
#   PROJECT_ID=<id> bash scripts/upgrade.sh <tag> [--remote=<name>] [--allow-destroy=<project_id>] [--trust-unsigned]
#   TFVARS_FILE=<path> bash scripts/upgrade.sh <tag> ...
#
#   <tag>             a release tag vMAJOR.MINOR.PATCH, optionally with a pre-release (v0.9.1, v0.9.1-preview)
#   --remote=<name>   the git remote to fetch the tag from (default: origin). In a fork, add the official
#                     repository as a remote and name it here: the fork's origin has no release tags.
#   --allow-destroy=  passed to `apply.sh apply` unchanged; only when apply.sh asked for it and you accept the
#                     deletes or replacements it listed
#   --trust-unsigned  continue when the tag is not signed by a key in scripts/release/allowed_signers (or that file
#                     is missing): only for a remote you trust, such as your own fork. Prints a red warning.
#
# Steps, in this order (run from the checkout that holds infra/platform/<project_id>.tfvars):
#   1. fetch the tag from the remote (an existing local tag that differs is refused, never overwritten) and verify
#      its SSH signature against scripts/release/allowed_signers of THIS (installed) checkout, before anything of the
#      release runs: `git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=... verify-tag <tag>`. An unsigned tag, a
#      lightweight tag or a tag signed by any other key is refused unless --trust-unsigned.
#   2. check out the tag (detached) and run the release's read-only `apply.sh plan`
#   3. ask you to confirm (y/N)
#   4. `apply.sh apply` (it shows the plan again and asks for the project id)
#   5. `deploy-services.sh --all-jobs`
#   6. smoke check (read-only): every platform Cloud Run service is Ready on its newest revision, and the Control
#      Center's platform stamp names this commit when the release has one
#
# Step 2 already runs the release's own scripts (apply.sh plan) with your credentials, before the confirm: that is
# why step 1 verifies the signature first, with the trusted keys of the checkout you installed from (never the
# release's own list). Only SSH signatures count (OpenPGP / X.509 verification is switched off for the check). The
# tag is not compared with the installed release (a downgrade runs the same way; the plan shows every change).
# Refuses before anything changes: a dirty working tree (`git status --porcelain` not empty), a target that does
# not match its vars file or a REGION that differs from it (the same guards as scripts/apply.sh), no terminal, no
# scripts/release/allowed_signers in this checkout (unless --trust-unsigned).
# Every stop (also Ctrl-C) names an error class and prints exactly one next command. Creates no IAM, prints no token.
# Bash 3.2 compatible (macOS /bin/bash). Needs git 2.34+, OpenSSH 8.2+ (ssh-keygen -Y), gcloud, python3 and OpenTofu (or Terraform).
# ==============================================================================

# The whole script is one function, read before it runs: step 2 checks out another release, which replaces this
# file on disk while it runs. The release's own apply.sh and deploy-services.sh are what steps 2-5 run.
sv_upgrade_main() {
    # No `set -e` (every step is checked explicitly, the platform_target.sh rule); unset variables and failed pipe
    # stages are errors.
    set -u -o pipefail
    trap 'sv_upgrade_on_exit $?' EXIT
    # Ctrl-C / kill: a typed stop that says what the interrupted stage may have changed (bash 3.2 would otherwise
    # run the EXIT trap with status 0 and print nothing).
    trap 'sv_upgrade_interrupted INT' INT
    trap 'sv_upgrade_interrupted TERM' TERM
    ORIG_PWD="$(pwd)"
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd -P)"
    PLATFORM_DIR="${REPO_ROOT}/infra/platform"
    UP_ROOT_Q="$(printf '%q' "${REPO_ROOT}")"
    UP_GIT_STATUS="git -C ${UP_ROOT_Q} status"
    # shellcheck source=common/platform_target.sh
    if ! . "${SCRIPT_DIR}/common/platform_target.sh"; then
        up_fail UPGRADE_PREREQ_MISSING "Cannot load ${SCRIPT_DIR}/common/platform_target.sh (a broken or partial checkout)." \
            "${UP_GIT_STATUS}"
    fi

    local tag="" remote="origin" allow_destroy="" arg caller_region
    UP_TRUST_UNSIGNED="no"
    for arg in "$@"; do
        case "${arg}" in
            --remote=*) remote="${arg#--remote=}" ;;
            --allow-destroy=*) allow_destroy="${arg#--allow-destroy=}" ;;
            --trust-unsigned) UP_TRUST_UNSIGNED="yes" ;;
            -h|--help) sed -n '5,15p' "${BASH_SOURCE[0]}" >&2; UP_STAGE="DONE"; exit 0 ;;
            -*) up_fail UPGRADE_USAGE "Unknown flag '${arg}'." "bash scripts/upgrade.sh --help" ;;
            *)
                [ -z "${tag}" ] || up_fail UPGRADE_USAGE "Only one tag is allowed (got '${tag}' and '${arg}')." "bash scripts/upgrade.sh --help"
                tag="${arg}" ;;
        esac
    done
    [ -n "${tag}" ] || up_fail UPGRADE_USAGE "No release tag given." "bash scripts/upgrade.sh --help"
    # SemVer 2.0 with a leading v; a pre-release is allowed (previews are releases), build metadata is not.
    [[ "${tag}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]] \
        || up_fail UPGRADE_TAG_INVALID "'${tag}' is not a release tag (vMAJOR.MINOR.PATCH, for example v0.9.1 or v0.9.1-preview)." "bash scripts/upgrade.sh --help"
    [[ "${remote}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
        || up_fail UPGRADE_USAGE "'${remote}' is not a git remote name." "git -C ${UP_ROOT_Q} remote -v"
    UP_TAG="${tag}"

    # ---- preflight: target guards (scripts/apply.sh's own), checkout, clean tree. Nothing changes here. ----
    UP_STAGE="PREFLIGHT"
    if [ -z "${PROJECT_ID:-}" ] && [ -z "${TFVARS_FILE:-}" ]; then
        up_fail UPGRADE_NO_TARGET "Set the install to upgrade explicitly (never taken from gcloud config)." \
            "PROJECT_ID=<project_id> bash scripts/upgrade.sh ${tag}"
    fi
    command -v git >/dev/null 2>&1 || up_fail UPGRADE_PREREQ_MISSING "git is not on PATH." "git --version"
    command -v gcloud >/dev/null 2>&1 || up_fail UPGRADE_PREREQ_MISSING "gcloud is not on PATH." "gcloud --version"
    caller_region="${REGION:-}"
    # The re-run names the same target the caller gave (PROJECT_ID and/or TFVARS_FILE) and the same remote. A guard
    # below stops with its own message (what to fix); the next command is then this run again.
    up_set_rerun "${PROJECT_ID:-}" "${TFVARS_FILE:-}" "${remote}"
    UP_NEXT="${UP_RERUN}"
    sv_detect_iac_bin
    sv_scrub_tofu_env
    sv_require_iac_version
    sv_resolve_platform_target
    if [ -n "${caller_region}" ] && [ "${caller_region}" != "${REGION}" ]; then
        up_fail UPGRADE_REGION_MISMATCH "REGION='${caller_region}' but ${TFVARS} has region='${REGION}'. Refusing to mix installs." \
            "${UP_RERUN}"
    fi
    if [ -n "${TFVARS_FILE:-}" ]; then
        export TFVARS_FILE="${TFVARS}"   # absolute, so the release's apply.sh resolves the same file
        up_set_rerun "" "${TFVARS}" "${remote}"
    else
        up_set_rerun "${PROJECT_ID}" "" "${remote}"
    fi
    UP_NEXT="${UP_RERUN}"
    UP_DEPLOY_CMD="PROJECT_ID=${PROJECT_ID} REGION=${REGION} bash scripts/deploy-services.sh --all-jobs"
    UP_LIST_CMD="gcloud run services list --project=${PROJECT_ID} --region=${REGION}"

    local top status_out
    top="$(git -C "${REPO_ROOT}" rev-parse --show-toplevel 2>/dev/null)" || top=""
    if [ -z "${top}" ] || [ "$(cd "${top}" 2>/dev/null && pwd -P)" != "${REPO_ROOT}" ]; then
        up_fail UPGRADE_NOT_A_CHECKOUT "${REPO_ROOT} is not the top of a git checkout; upgrade.sh moves a git checkout to a release tag." \
            "${UP_GIT_STATUS}"
    fi
    status_out="$(git -C "${REPO_ROOT}" status --porcelain)" \
        || up_fail UPGRADE_GIT_UNREADABLE "'git status' failed in ${REPO_ROOT}." "${UP_GIT_STATUS}"
    if [ -n "${status_out}" ]; then
        printf '%s\n' "${status_out}" | sed -n '1,20p' | sed 's/^/    /' >&2
        up_fail UPGRADE_DIRTY_TREE "The working tree has changes (listed above; untracked files count). Commit, move or remove them first: the release is checked out over this tree." \
            "${UP_GIT_STATUS}"
    fi
    git -C "${REPO_ROOT}" remote get-url "${remote}" >/dev/null 2>&1 \
        || up_fail UPGRADE_REMOTE_MISSING "There is no git remote '${remote}' in ${REPO_ROOT}." "git -C ${UP_ROOT_Q} remote -v"
    # The smoke check runs from a copy made now: after the checkout the tree holds the release's files.
    UP_TMP="$(mktemp -d)" || up_fail UPGRADE_PREREQ_MISSING "mktemp failed." "mktemp -d"
    cp "${SCRIPT_DIR}/common/upgrade_smoke.py" "${UP_TMP}/upgrade_smoke.py" \
        || up_fail UPGRADE_PREREQ_MISSING "Cannot copy ${SCRIPT_DIR}/common/upgrade_smoke.py." "${UP_GIT_STATUS}"
    # The trusted release keys come from THIS checkout (the installed release), copied now: the release being
    # installed never chooses the keys it is verified with (SELFUP-SIGN; review H-5).
    local signers_src="${REPO_ROOT}/scripts/release/allowed_signers" verify_cmd
    UP_SIGNERS=""
    if [ -f "${signers_src}" ]; then
        cp "${signers_src}" "${UP_TMP}/allowed_signers" \
            || up_fail UPGRADE_PREREQ_MISSING "Cannot copy ${signers_src}." "${UP_GIT_STATUS}"
        UP_SIGNERS="${UP_TMP}/allowed_signers"
        if [ "${UP_TRUST_UNSIGNED}" != "yes" ]; then
            # Old tools would misreport a correctly signed tag as UPGRADE_SIGNATURE_INVALID (code review M-2): SSH tag
            # signatures need git 2.34+ (gpg.format=ssh, gpg.ssh.allowedSignersFile) and OpenSSH 8.2+ (`ssh-keygen -Y`).
            # Exact numeric comparison of the version each tool prints in its documented format.
            local git_version ssh_version
            git_version="$(git --version 2>/dev/null)" || git_version=""
            up_version_at_least "${git_version}" '^git version ([0-9]+)\.([0-9]+)' 2 34 \
                || up_fail UPGRADE_PREREQ_MISSING "git 2.34 or newer is needed to verify SSH-signed release tags (found '${git_version:-none}')." \
                    "git --version"
            command -v ssh-keygen >/dev/null 2>&1 \
                || up_fail UPGRADE_PREREQ_MISSING "ssh-keygen (OpenSSH) is not on PATH; git needs it to verify the release tag's signature." \
                    "command -v ssh-keygen"
            ssh_version="$(ssh -V 2>&1)" || ssh_version=""
            up_version_at_least "${ssh_version}" '^OpenSSH_([0-9]+)\.([0-9]+)' 8 2 \
                || up_fail UPGRADE_PREREQ_MISSING "OpenSSH 8.2 or newer is needed to verify SSH-signed release tags (ssh-keygen -Y; found '${ssh_version:-none}')." \
                    "ssh -V"
        fi
    elif [ "${UP_TRUST_UNSIGNED}" != "yes" ]; then
        up_fail UPGRADE_NO_TRUSTED_KEYS "This checkout has no scripts/release/allowed_signers (the StackVend release key ships with the release candidate), so the release tag's signature cannot be checked. Nothing was changed. Upgrade from a checkout that has it, or, only if you trust the remote '${remote}' (for example your own fork), run again with --trust-unsigned:" \
            "${UP_RERUN} --trust-unsigned"
    fi

    local head_before
    UP_PREV_REF="$(git -C "${REPO_ROOT}" symbolic-ref -q --short HEAD 2>/dev/null)" || UP_PREV_REF=""
    head_before="$(git -C "${REPO_ROOT}" rev-parse HEAD)" || up_fail UPGRADE_GIT_UNREADABLE "'git rev-parse HEAD' failed." "${UP_GIT_STATUS}"
    [ -n "${UP_PREV_REF}" ] || UP_PREV_REF="${head_before}"
    UP_GO_BACK="git -C ${UP_ROOT_Q} checkout ${UP_PREV_REF}"
    sv_info "Upgrade ${PROJECT_ID} (${REGION}) from ${UP_PREV_REF} (${head_before}) to ${tag}."
    sv_info "Steps: fetch and verify the signature, plan (read-only), confirm, apply.sh apply, deploy-services.sh --all-jobs, smoke check."

    # ---- 1. fetch the tag. A local tag that differs from the remote's is refused by git (no '+'), never moved. ----
    UP_STAGE="FETCH"
    sv_info "1/6 Fetching ${tag} from ${remote}..."
    git -C "${REPO_ROOT}" fetch --no-tags "${remote}" "refs/tags/${tag}:refs/tags/${tag}" >&2 \
        || up_fail UPGRADE_FETCH_FAILED "Could not fetch tag ${tag} from '${remote}' (it does not exist there, the network failed, or your local tag ${tag} points somewhere else). In a fork, the release tags are on the official repository: add it as a remote and pass --remote=<name>." \
            "git -C ${UP_ROOT_Q} ls-remote --tags ${remote} ${tag}"
    local target tagger author
    target="$(git -C "${REPO_ROOT}" rev-parse --verify --quiet "refs/tags/${tag}^{commit}")" || target=""
    [[ "${target}" =~ ^[0-9a-f]{40}$ ]] \
        || up_fail UPGRADE_TAG_NOT_FOUND "Tag ${tag} does not name a commit after the fetch." "git -C ${UP_ROOT_Q} show --no-patch ${tag}"
    # What is about to run (step 2 runs the release's own scripts before the confirm; the signature is checked next).
    tagger="$(git -C "${REPO_ROOT}" for-each-ref --format='%(if)%(taggername)%(then)%(taggername) %(taggeremail) %(taggerdate:iso)%(end)' "refs/tags/${tag}")" || tagger=""
    author="$(git -C "${REPO_ROOT}" log -1 --format='%an %ae %ad' --date=iso "${target}")" || author=""
    sv_info "Release ${tag}: commit ${target}; tagged by ${tagger:-(lightweight tag, no tagger)}; commit by ${author:-unknown}."

    # ---- 1. verify the tag's SSH signature with the installed checkout's trusted keys, before anything runs ----
    UP_STAGE="VERIFY"
    # Only SSH signatures can pass: the OpenPGP and X.509 verifiers are replaced by `false` for this one command (a
    # PGP-signed tag would otherwise be checked against the operator's own GnuPG keyring).
    verify_cmd="git -C ${UP_ROOT_Q} -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=scripts/release/allowed_signers verify-tag ${tag}"
    if [ -n "${UP_SIGNERS}" ] && git -C "${REPO_ROOT}" -c gpg.format=ssh -c gpg.ssh.program=ssh-keygen \
            -c gpg.ssh.allowedSignersFile="${UP_SIGNERS}" -c gpg.openpgp.program=false -c gpg.x509.program=false \
            verify-tag "${tag}" >&2; then
        sv_info "1/6 Signature of ${tag}: good, by a key in scripts/release/allowed_signers of this checkout."
    elif [ "${UP_TRUST_UNSIGNED}" = "yes" ]; then
        echo -e "\033[0;31m[WARNING] --trust-unsigned: ${tag} is NOT verified ($([ -n "${UP_SIGNERS}" ] && echo "not signed by a key in scripts/release/allowed_signers" || echo "this checkout has no scripts/release/allowed_signers")). Continuing only because you passed --trust-unsigned: the release's own scripts run next with your credentials.\033[0m" >&2
    else
        up_fail UPGRADE_SIGNATURE_INVALID "${tag} is not signed by a key in scripts/release/allowed_signers of this checkout (unsigned, a lightweight tag, or signed by another key; git's message is above). Nothing was applied and the checkout is unchanged (the tag was fetched). See why:" \
            "${verify_cmd}"
    fi
    sv_info "Its own apply.sh runs the read-only plan next, before you confirm."

    # ---- 2. check out the release, then its read-only plan ----
    UP_STAGE="CHECKOUT"
    if [ "${head_before}" != "${target}" ]; then
        sv_info "2/6 Checking out ${tag} (${target}); your branch is not changed (detached HEAD)."
        git -C "${REPO_ROOT}" -c advice.detachedHead=false checkout --quiet --detach "${target}" >&2 \
            || up_fail UPGRADE_CHECKOUT_FAILED "Could not check out ${tag}." "${UP_GIT_STATUS}"
    else
        sv_info "2/6 The checkout is already at ${tag} (${target})."
    fi
    UP_STAGE="PLAN"
    sv_info "2/6 Read-only plan of the release's platform Terraform (scripts/apply.sh plan)..."
    if ! bash "${REPO_ROOT}/scripts/apply.sh" plan; then
        up_fail UPGRADE_PLAN_FAILED "apply.sh plan failed (see above). Nothing was applied; the checkout is at ${tag} (it was at ${UP_PREV_REF}). When the cause is fixed, run the upgrade again:" \
            "${UP_RERUN}"
    fi

    # ---- 3. confirm ----
    UP_STAGE="CONFIRM"
    if [ ! -t 0 ]; then
        up_fail UPGRADE_NEEDS_TERMINAL "Confirming the upgrade needs an interactive terminal. Nothing was applied; the checkout is at ${tag}." \
            "${UP_RERUN}"
    fi
    local answer=""
    printf '\n\033[1;33mApply this plan to %s with scripts/apply.sh apply? It shows the plan again and asks for the project id. (y/N): \033[0m' "${PROJECT_ID}" >&2
    read -r answer || answer=""
    if [ "${answer}" != "y" ] && [ "${answer}" != "Y" ]; then
        up_fail UPGRADE_DECLINED "Stopped at your answer. Nothing was applied; the checkout is at ${tag}. To go back to where it was:" \
            "${UP_GO_BACK}"
    fi

    # ---- 4. apply (the release's apply.sh: destroy gate + typed project id) ----
    UP_STAGE="APPLY"
    sv_info "4/6 scripts/apply.sh apply..."
    local apply_args=(apply)
    [ -z "${allow_destroy}" ] || apply_args+=("--allow-destroy=${allow_destroy}")
    if ! bash "${REPO_ROOT}/scripts/apply.sh" "${apply_args[@]}"; then
        up_fail UPGRADE_APPLY_FAILED "apply.sh apply stopped (see its message above; the platform Terraform may be partly applied). The services were not deployed. When its cause is fixed, run the upgrade again (apply.sh plans again from state):" \
            "${UP_RERUN}"
    fi

    # ---- 5. deploy the services and jobs ----
    UP_STAGE="DEPLOY"
    sv_info "5/6 scripts/deploy-services.sh --all-jobs..."
    if ! PROJECT_ID="${PROJECT_ID}" REGION="${REGION}" bash "${REPO_ROOT}/scripts/deploy-services.sh" --all-jobs; then
        up_fail UPGRADE_DEPLOY_FAILED "deploy-services.sh did not finish (see its summary above). The platform Terraform is already applied; deploy the services again:" \
            "${UP_DEPLOY_CMD}"
    fi

    # ---- 6. smoke check (read-only) ----
    UP_STAGE="SMOKE"
    sv_info "6/6 Smoke check: platform Cloud Run services Ready on their newest revision; platform stamp..."
    local stamp_required="no" services_json head_after
    head_after="$(git -C "${REPO_ROOT}" rev-parse HEAD)" || up_fail UPGRADE_GIT_UNREADABLE "'git rev-parse HEAD' failed." "${UP_GIT_STATUS}"
    # The release has the platform stamp (FD-4DA item 10) when its variables.tf declares stackvend_platform_commit;
    # that apply wrote the stamp, so it must name this commit. The console evaluates a declared variable (exit 0;
    # a failed validation is only a warning) and refuses an undeclared one. Any other console failure would also
    # make the region unreadable from the same vars file: then the check stops (fails closed) instead of skipping.
    if sv_tfvar stackvend_platform_commit >/dev/null; then
        stamp_required="yes"
    elif ! sv_tfvar region >/dev/null; then
        up_fail UPGRADE_TFVARS_UNREADABLE "Cannot evaluate ${TFVARS} against the release's infra/platform/variables.tf, so the platform stamp cannot be checked. The release is applied and deployed; check the vars file:" \
            "${UP_TARGET_ENV}bash scripts/apply.sh plan"
    fi
    services_json="${UP_TMP}/services.json"
    gcloud run services list --project="${PROJECT_ID}" --region="${REGION}" --format=json --quiet > "${services_json}" \
        || up_fail UPGRADE_SMOKE_UNREADABLE "Could not list the Cloud Run services of ${PROJECT_ID} in ${REGION}." "${UP_LIST_CMD}"
    if ! python3 "${UP_TMP}/upgrade_smoke.py" --services-json "${services_json}" --expect-commit "${head_after}" \
            --stamp-required "${stamp_required}"; then
        up_fail UPGRADE_SMOKE_FAILED "The smoke check failed (listed above). The release is applied and deployed; look at the services it names:" \
            "${UP_LIST_CMD}"
    fi

    UP_STAGE="DONE"
    echo -e "\033[0;32m[OK]\033[0m ${PROJECT_ID} runs ${tag} (${head_after})." >&2
}

# The command that runs this upgrade again with the caller's own target: $1 PROJECT_ID, $2 TFVARS_FILE, $3 remote
# (and --trust-unsigned when the caller gave it).
up_set_rerun() {
    local cmd=""
    [ -z "$1" ] || cmd="PROJECT_ID=$1 "
    [ -z "$2" ] || cmd="${cmd}TFVARS_FILE=$(printf '%q' "$2") "
    UP_TARGET_ENV="${cmd}"
    cmd="${cmd}bash scripts/upgrade.sh ${UP_TAG}"
    [ "$3" = "origin" ] || cmd="${cmd} --remote=$3"
    [ "${UP_TRUST_UNSIGNED}" != "yes" ] || cmd="${cmd} --trust-unsigned"
    UP_RERUN="${cmd}"
}

# $1 a tool's version line, $2 an anchored regex whose groups 1 and 2 are MAJOR and MINOR, $3 $4 the minimum MAJOR
# MINOR. Success only when the line matches and the version is at least that (an unreadable line fails).
up_version_at_least() {
    local text="$1" re="$2"
    [[ "${text}" =~ ${re} ]] || return 1
    local major="${BASH_REMATCH[1]}" minor="${BASH_REMATCH[2]}"
    [ "${major}" -gt "$3" ] && return 0
    [ "${major}" -eq "$3" ] && [ "${minor}" -ge "$4" ]
}

# Typed stop: class + stage + message, then exactly one next command (printed by the EXIT trap).
up_fail() {
    UP_CLASS="$1"
    UP_NEXT="$3"
    echo -e "\033[0;31m[ERROR]\033[0m ${UP_CLASS} (stage ${UP_STAGE}): $2" >&2
    exit 1
}

# What a stop at the current stage may have left behind, and the one command to run next. Used for Ctrl-C / kill
# and for any stop that did not come through up_fail.
up_stage_state() {
    case "${UP_STAGE}" in
        ARGS|PREFLIGHT)
            UP_STATE="Nothing was changed."; UP_NEXT="${UP_RERUN:-${UP_NEXT}}" ;;
        FETCH|VERIFY)
            UP_STATE="Nothing was applied (the tag may have been fetched into this checkout)."; UP_NEXT="${UP_RERUN}" ;;
        CHECKOUT)
            UP_STATE="Nothing was applied; the checkout may be between ${UP_PREV_REF} and ${UP_TAG}. Look at it first (then check out ${UP_PREV_REF} again, or run the upgrade again):"
            UP_NEXT="${UP_GIT_STATUS}" ;;
        PLAN|CONFIRM)
            UP_STATE="Nothing was applied; the checkout is at ${UP_TAG}. To go back to where it was:"; UP_NEXT="${UP_GO_BACK}" ;;
        APPLY)
            UP_STATE="The platform Terraform may be partly applied (OpenTofu state records what was done); the services were not deployed. Run the upgrade again (apply.sh plans again from state):"
            UP_NEXT="${UP_RERUN}" ;;
        DEPLOY)
            UP_STATE="The platform Terraform is applied; some services and jobs may already run ${UP_TAG}, others not. Deploy them all again:"
            UP_NEXT="${UP_DEPLOY_CMD}" ;;
        SMOKE)
            UP_STATE="The release is applied and deployed; the smoke check did not finish. Look at the services:"
            UP_NEXT="${UP_LIST_CMD}" ;;
        *)
            UP_STATE=""; UP_NEXT="" ;;
    esac
}

sv_upgrade_interrupted() {
    trap '' INT TERM
    UP_CLASS="UPGRADE_INTERRUPTED"
    up_stage_state
    echo "" >&2
    echo -e "\033[0;31m[ERROR]\033[0m UPGRADE_INTERRUPTED (stage ${UP_STAGE}, SIG$1): ${UP_STATE}" >&2
    exit 130
}

sv_upgrade_on_exit() {
    local rc="$1"
    if [ -n "${UP_TMP}" ]; then
        rm -rf "${UP_TMP}"
    fi
    if [ "${rc}" -ne 0 ] && [ "${UP_STAGE}" != "DONE" ]; then
        if [ -z "${UP_CLASS}" ]; then
            case "${UP_STAGE}" in
                ARGS|PREFLIGHT)
                    # A guard of scripts/common/platform_target.sh stopped the run (its message is above).
                    echo -e "\033[0;31m[ERROR]\033[0m UPGRADE_GUARD_REFUSED (stage ${UP_STAGE}): see the message above. Nothing was changed by upgrade.sh in this stage." >&2 ;;
                *)
                    up_stage_state
                    echo -e "\033[0;31m[ERROR]\033[0m UPGRADE_ABORTED (stage ${UP_STAGE}): upgrade.sh stopped unexpectedly (see above). ${UP_STATE}" >&2 ;;
            esac
        fi
        if [ -n "${UP_NEXT}" ]; then
            echo "" >&2
            echo "Next command:" >&2
            echo "    ${UP_NEXT}" >&2
        fi
    fi
}

UP_CLASS=""; UP_NEXT=""; UP_STAGE="ARGS"; UP_TMP=""; UP_TAG=""; UP_RERUN=""; UP_STATE=""; UP_PREV_REF=""
UP_GO_BACK=""; UP_TARGET_ENV=""; UP_DEPLOY_CMD=""; UP_LIST_CMD=""; UP_ROOT_Q=""; UP_GIT_STATUS=""
UP_TRUST_UNSIGNED="no"; UP_SIGNERS=""
sv_upgrade_main "$@"; exit $?
