# shellcheck shell=bash
# ==============================================================================
# STACKVEND: platform target resolution + safety guards (sourced, never executed)
# ==============================================================================
# Used by scripts/apply.sh, scripts/deploy-services.sh and scripts/bootstrap.sh.
# Bash 3.2 compatible (macOS /bin/bash). Callers must set REPO_ROOT and PLATFORM_DIR.
#
# Design rules (Wave 1 lane 5, FD-07 step 2 / FD-0B / FD-4AP; red team H1-H15):
#   - tfvars are read with the real HCL parser (`tofu console`), never grep/sed.
#   - every guard calls sv_die itself; nothing relies on `set -e` (it is suspended
#     inside functions called from `if`/`||`), and no `local x=$(...)` (masks rc).
#   - PROJECT_ID / REGION are validated against the GCP grammar BEFORE any path is built.
# ==============================================================================

SV_PROJECT_RE='^[a-z][a-z0-9-]{4,28}[a-z0-9]$'
SV_REGION_RE='^[a-z]+-[a-z]+[0-9]+$'

sv_die() {
    echo -e "\033[0;31m[ERROR]\033[0m $*" >&2
    exit 1
}

sv_info() {
    echo -e "\033[0;34m==>\033[0m $*" >&2
}

# BOOTSTRAP-TOS-FAIL-LOUD (live finding 11-03): run ONE API-enable command (the gcloud command line in "$4"...) and
# stop with a typed error when it fails (fail-loudly policy; the old bootstrap enables ended in `|| true` and carried on).
#   $1 = code prefix (BOOTSTRAP / APPLY), $2 = the gcloud account (empty: read from gcloud config),
#   $3 = the sentence that says what was not changed ("Nothing was written." / "Nothing was applied.").
# The failure is classified from gcloud's structured error details, not from its prose: gcloud prints the API error's
# `details` list as YAML under its ERROR line (googlecloudsdk api_lib/util/exceptions.py HttpException; '@type' is
# always the first key of an item, its other keys are indented two spaces). The `reason` of a
# type.googleapis.com/google.rpc.ErrorInfo item is a stable API enum and is compared exactly:
#   UREQ_TOS_NOT_ACCEPTED -> <PREFIX>_CLOUD_TERMS_NOT_ACCEPTED (the account never accepted the Google Cloud terms)
#   anything else         -> <PREFIX>_API_ENABLE_FAILED: <service(s)>: <gcloud's ERROR line>
# `--format=json` does not apply to gcloud's error output, so the details are read from stderr, which is always
# replayed to the operator. With core/show_structured_logs on, each stderr line is a JSON record whose "message" holds
# the same text; it is unpacked first. Anything unreadable is API_ENABLE_FAILED (fail closed).
sv_enable_apis_or_die() {
    local prefix="$1" account="$2" unchanged="$3" err rc verdict="" msg="" services="" arg n=0 errexit=""
    shift 3
    for arg in "$@"; do
        case "${arg}" in
            gcloud|services|enable|--*) ;;
            *) n=$((n + 1)); [ "${n}" = "1" ] && services="${arg}" ;;
        esac
    done
    [ "${n}" -gt 1 ] && services="${services} and $((n - 1)) more (${n} APIs)"
    err="$(mktemp "${TMPDIR:-/tmp}/sv-api-enable.XXXXXX")" \
        || sv_die "${prefix}_API_ENABLE_FAILED: ${services}: could not create a temporary file for gcloud's output. ${unchanged}"
    case "$-" in *e*) errexit=1 ;; esac
    set +e
    "$@" 2>"${err}"
    rc=$?
    [ -n "${errexit}" ] && set -e
    cat "${err}" >&2
    if [ "${rc}" = "0" ]; then
        rm -f "${err}"
        return 0
    fi
    python3 - "${err}" > "${err}.verdict" 2>/dev/null <<'PY'
import json
import re
import sys

raw = open(sys.argv[1], encoding="utf-8", errors="replace").read().splitlines()
lines = []
for line in raw:
    rec = None
    if line.startswith("{"):
        try:
            rec = json.loads(line)
        except ValueError:
            rec = None
    if isinstance(rec, dict) and isinstance(rec.get("message"), str):
        lines.extend(rec["message"].splitlines())
    else:
        lines.append(line)
reasons, in_info, msg = [], False, ""
for line in lines:
    if not msg and line.startswith("ERROR: "):
        msg = line[len("ERROR: "):]
    if line.startswith("- "):
        in_info = line == "- '@type': type.googleapis.com/google.rpc.ErrorInfo"
        continue
    if not line.startswith("  "):
        in_info = False
        continue
    m = re.fullmatch(r"  reason: ([A-Z][A-Z0-9_]*)", line) if in_info else None
    if m:
        reasons.append(m.group(1))
print("tos" if "UREQ_TOS_NOT_ACCEPTED" in reasons else "other")
print(msg)
PY
    if [ -s "${err}.verdict" ]; then
        verdict="$(sed -n 1p "${err}.verdict")"
        msg="$(sed -n 2p "${err}.verdict")"
    fi
    rm -f "${err}" "${err}.verdict"
    if [ "${verdict}" = "tos" ]; then
        if [ -z "${account}" ]; then
            account="$(gcloud config get-value account 2>/dev/null)" || account=""
        fi
        account="${account:-the signed-in gcloud account}"
        sv_die "${prefix}_CLOUD_TERMS_NOT_ACCEPTED: ${account} has not accepted the Google Cloud Terms of Service. Sign in to https://console.cloud.google.com once as ${account}, accept the terms, then re-run. ${unchanged}"
    fi
    [ -n "${msg}" ] || msg="the API enable exited with code ${rc} (the gcloud output is above)."
    sv_die "${prefix}_API_ENABLE_FAILED: ${services}: ${msg} ${unchanged}"
}

sv_valid_project_id() {
    [[ "$1" =~ $SV_PROJECT_RE ]]
}

sv_valid_region() {
    [[ "$1" =~ $SV_REGION_RE ]]
}

# Absolute path of $1 resolved against the caller's ORIGINAL working directory ($2).
sv_abspath() {
    python3 -c 'import os,sys; print(os.path.realpath(os.path.join(sys.argv[2], sys.argv[1])))' "$1" "$2"
}

# Detect the IaC binary (OpenTofu preferred; HashiCorp Terraform fallback kept per owner, FD-0C).
sv_detect_iac_bin() {
    if command -v tofu >/dev/null 2>&1 && tofu version 2>&1 | grep -qi "OpenTofu v"; then
        IAC_BIN="tofu"
    elif command -v terraform >/dev/null 2>&1 && terraform version 2>&1 | grep -qi "Terraform v"; then
        IAC_BIN="terraform"
    else
        sv_die "Neither 'tofu' (OpenTofu) nor 'terraform' is installed and functional."
    fi
}

# RC B1: minimum engine version for infra/platform. The FD-0C `removed { lifecycle { destroy = false } }` block in
# infra/platform/main.tf does not parse on OpenTofu 1.9 ("Unsupported block type"); OpenTofu added `lifecycle` to
# `removed` in 1.10. Same value as required_version in infra/platform/providers.tf (one constraint for both engines;
# HashiCorp Terraform needs >= 1.7 for the block, so 1.5.x cannot install the platform).
# Workload IaC (tf-applier, mcp-servers/terraform) has its own engine version; this check is the host platform only.
SV_IAC_MIN_VERSION="1.10.0"

# Refuse an engine older than SV_IAC_MIN_VERSION before any GCP call, with a clear message (instead of a parse
# error deep in init/plan). The version comes from `<engine> version -json` (field terraform_version, which both
# OpenTofu and Terraform print) and is compared as semver: MAJOR.MINOR.PATCH numerically; a pre-release
# (e.g. 1.10.0-rc1) ranks below its release. Needs IAC_BIN (sv_detect_iac_bin or bootstrap's own detection).
# sv_iac_version_verdict <engine>: prints OK|<version>, OLD|<version> or UNKNOWN| against SV_IAC_MIN_VERSION
# (needs python3). Shared by sv_require_iac_version and scripts/common/opentofu_offer.sh.
sv_iac_version_verdict() {
    local json verdict
    json="$("$1" version -json 2>/dev/null)" || json=""
    verdict="$(printf '%s' "${json}" | python3 -c '
import json, re, sys
SEMVER = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?")
def key(v):
    m = SEMVER.fullmatch(v)
    return None if m is None else (int(m.group(1)), int(m.group(2)), int(m.group(3)), 0 if m.group(4) else 1)
try:
    doc = json.loads(sys.stdin.read() or "null")
except ValueError:
    doc = None
have = doc.get("terraform_version") if isinstance(doc, dict) else None
have_key = key(have) if isinstance(have, str) else None
if have_key is None:
    print("UNKNOWN|")
elif have_key >= key(sys.argv[1]):
    print("OK|" + have)
else:
    print("OLD|" + have)
' "${SV_IAC_MIN_VERSION}")" || verdict="UNKNOWN|"
    printf '%s\n' "${verdict}"
}

sv_require_iac_version() {
    local verdict
    command -v python3 >/dev/null 2>&1 \
        || sv_die "python3 is not on PATH. The StackVend install scripts need python3 (and curl); install them and re-run. Nothing was changed."
    verdict="$(sv_iac_version_verdict "${IAC_BIN}")"
    case "${verdict%%|*}" in
        OK) return 0 ;;
        OLD)
            sv_die "${IAC_BIN} ${verdict#*|} is too old for infra/platform: it needs ${SV_IAC_MIN_VERSION} or later (the removed { lifecycle { destroy = false } } block in infra/platform/main.tf does not parse on OpenTofu 1.9 or Terraform 1.5/1.6). Install OpenTofu ${SV_IAC_MIN_VERSION} or later (https://opentofu.org/docs/intro/install/; installs are verified with 1.13.x) and re-run. Nothing was changed." ;;
        *)
            sv_die "Could not read the ${IAC_BIN} version ('${IAC_BIN} version -json' printed no MAJOR.MINOR.PATCH terraform_version). infra/platform needs OpenTofu ${SV_IAC_MIN_VERSION} or later. Nothing was changed." ;;
    esac
}

# H1: tofu reads these behind the wrapper's back. Abort and name them; never run with them set.
# Exact names only (no pattern guessing beyond tofu's own documented TF_VAR_* / TF_CLI_ARGS_* families):
#   inputs/flags/state key:  TF_VAR_*, TF_CLI_ARGS, TF_CLI_ARGS_*, TF_WORKSPACE
#   state/plan format:       TF_ENCRYPTION (OpenTofu state + plan encryption),
#                            GOOGLE_ENCRYPTION_KEY / GOOGLE_KMS_ENCRYPTION_KEY (gcs backend CSEK / KMS key)
#   provider binding:        TF_REATTACH_PROVIDERS (attach to an already-running provider process),
#                            TF_CLI_CONFIG_FILE / TERRAFORM_CONFIG (CLI config: provider_installation,
#                            dev_overrides), TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE
# TF_DATA_DIR is not listed: the wrapper always overwrites it (one init dir per install).
sv_scrub_tofu_env() {
    local bad=() n
    for n in $(compgen -e); do
        case "$n" in
            TF_VAR_*|TF_CLI_ARGS|TF_CLI_ARGS_*|TF_WORKSPACE|\
            TF_ENCRYPTION|GOOGLE_ENCRYPTION_KEY|GOOGLE_KMS_ENCRYPTION_KEY|\
            TF_REATTACH_PROVIDERS|TF_CLI_CONFIG_FILE|TERRAFORM_CONFIG|TF_PLUGIN_CACHE_MAY_BREAK_DEPENDENCY_LOCK_FILE)
                bad+=("$n")
                ;;
        esac
    done
    if [ ${#bad[@]} -gt 0 ]; then
        sv_die "Refusing to run with these environment variables set (they bypass the tfvars/flag guards): ${bad[*]}. Unset them and retry."
    fi
}

# Evaluate var.<name> from $TFVARS with the real HCL parser. No init, no backend, no
# credentials: a temp dir holding only a copy of variables.tf. Prints the scalar value;
# returns non-zero on any parse/eval error or a non-scalar / unknown value.
# $2 = "nullable" (BG-1): evaluates jsonencode(var.<name>) instead (console prints a typed null as
# `tobool(null)`, not JSON), so a null value (variable unset, default null) prints "null" instead of failing.
# REMOVE-DEVELOPER-MODE: variables that no longer exist, but that an older vars file may still set. OpenTofu answers an
# undeclared value in a var file with a warning, and `console` prints that warning on stdout, ahead of the value, which
# the strict parse below refuses; declaring them in the temp dir (console only) keeps such a file readable. A real
# `plan` / `apply` with the same file only warns. Nothing reads these values.
SV_TFVAR_RETIRED_VARIABLES="castor_deployment_mode github_repo cloudbuild_2nd_gen_repo_id enable_cloud_build_triggers"
sv_tfvar() {
    local name="$1" nullable="${2:-}" tmp out rc retired expr='var.%s\n'
    if [ "${nullable}" = "nullable" ]; then
        expr='jsonencode(var.%s)\n'
    fi
    tmp="$(mktemp -d)" || return 1
    if ! cp "${PLATFORM_DIR}/variables.tf" "${tmp}/variables.tf"; then
        rm -rf "${tmp}"
        return 1
    fi
    for retired in ${SV_TFVAR_RETIRED_VARIABLES}; do
        printf 'variable "%s" {\n  default = null\n}\n' "${retired}" >> "${tmp}/retired_variables.tf" || {
            rm -rf "${tmp}"
            return 1
        }
    done
    # TF_DATA_DIR is pinned to the empty temp dir: the caller's exported per-install data dir is
    # bound to the gcs backend, and console would otherwise read (or, if missing, write) remote state.
    # shellcheck disable=SC2059  # expr is one of the two fixed formats above
    out="$(printf "${expr}" "${name}" | TF_DATA_DIR="${tmp}/.tfdata" "${IAC_BIN}" -chdir="${tmp}" console -var-file="${TFVARS}" 2>/dev/null)"
    rc=$?
    rm -rf "${tmp}"
    if [ ${rc} -ne 0 ]; then
        return 1
    fi
    # console prints HCL literals: "str" (JSON-compatible quoting), true/false, numbers.
    # "(known after apply)" (a required var missing from the file) is not JSON -> rc != 0.
    printf '%s' "${out}" | python3 -c '
import json, sys
nullable = sys.argv[1:] == ["nullable"]
try:
    v = json.loads(sys.stdin.read())
    if nullable:
        if not isinstance(v, str):
            sys.exit(4)
        v = json.loads(v)
except ValueError:
    sys.exit(3)
if v is None and nullable:
    print("null")
elif isinstance(v, bool):
    print("true" if v else "false")
elif isinstance(v, (str, int, float)):
    print(v)
else:
    sys.exit(4)
' ${nullable:+"${nullable}"}
}

# G2: tofu auto-loads these from the working dir; -var-file only overrides keys it sets,
# so any of them would silently leak another install's values into this run.
sv_guard_autoload_files() {
    local f
    for f in "${PLATFORM_DIR}"/terraform.tfvars.json "${PLATFORM_DIR}"/*.auto.tfvars "${PLATFORM_DIR}"/*.auto.tfvars.json; do
        if [ -e "$f" ]; then
            sv_die "Found auto-loaded vars file '$f'. Remove or rename it (tofu would merge it into every run)."
        fi
    done
    if [ -e "${PLATFORM_DIR}/terraform.tfvars" ] && [ "${TFVARS}" != "$(sv_abspath "${PLATFORM_DIR}/terraform.tfvars" "/")" ]; then
        sv_die "Found '${PLATFORM_DIR}/terraform.tfvars' but the selected vars file is '${TFVARS}'. tofu auto-loads terraform.tfvars, so its keys would leak into this run. Rename it to <project_id>.tfvars."
    fi
}

# Resolve PROJECT_ID / TFVARS / REGION for platform Terraform (apply.sh, bootstrap re-runs).
# Inputs: PROJECT_ID (env/flag), TFVARS_FILE (env), ORIG_PWD (caller cwd before any cd).
sv_resolve_platform_target() {
    local source_desc tf_project region
    if [ -n "${TFVARS_FILE:-}" ]; then
        TFVARS="$(sv_abspath "${TFVARS_FILE}" "${ORIG_PWD}")" || sv_die "Cannot resolve TFVARS_FILE '${TFVARS_FILE}'."
        [ -f "${TFVARS}" ] || sv_die "TFVARS_FILE '${TFVARS}' does not exist."
        tf_project="$(sv_tfvar project_id)" || sv_die "Cannot read a valid project_id from '${TFVARS}' (missing, malformed, or the file does not parse)."
        sv_valid_project_id "${tf_project}" || sv_die "project_id '${tf_project}' in '${TFVARS}' is not a valid GCP project id."
        if [ -n "${PROJECT_ID:-}" ] && [ "${PROJECT_ID}" != "${tf_project}" ]; then
            sv_die "PROJECT_ID='${PROJECT_ID}' but '${TFVARS}' has project_id='${tf_project}'. Refusing to mix installs."
        fi
        PROJECT_ID="${tf_project}"
        source_desc="TFVARS_FILE"
    else
        if [ -n "${PROJECT_ID:-}" ]; then
            source_desc="PROJECT_ID"
        else
            PROJECT_ID="$(gcloud config get-value project 2>/dev/null)" || PROJECT_ID=""
            source_desc="gcloud config (set PROJECT_ID or TFVARS_FILE to be explicit)"
        fi
        [ -n "${PROJECT_ID}" ] || sv_die "No target project. Set PROJECT_ID=<id> or TFVARS_FILE=<path>."
        # Validate BEFORE building any path from it (path traversal).
        sv_valid_project_id "${PROJECT_ID}" || sv_die "PROJECT_ID '${PROJECT_ID}' is not a valid GCP project id."
        if [ -f "${PLATFORM_DIR}/${PROJECT_ID}.tfvars" ]; then
            TFVARS="${PLATFORM_DIR}/${PROJECT_ID}.tfvars"
        elif [ -f "${PLATFORM_DIR}/terraform.tfvars" ]; then
            TFVARS="${PLATFORM_DIR}/terraform.tfvars"
        else
            # TFVARS-AUTO-BACKUP: apply.sh offers the restore before it gets here; other callers (upgrade.sh, the
            # gcloud config fallback) see where the backup is.
            sv_die "No vars file for '${PROJECT_ID}'. Expected '${PLATFORM_DIR}/${PROJECT_ID}.tfvars' (or pass TFVARS_FILE=<path>). If the install backed it up to gs://castor-tfstate-${PROJECT_ID}/platform/${PROJECT_ID}.tfvars, PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh plan offers to restore it."
        fi
        TFVARS="$(sv_abspath "${TFVARS}" "/")" || sv_die "Cannot resolve '${TFVARS}'."
        # G1: the file must describe the same project.
        tf_project="$(sv_tfvar project_id)" || sv_die "Cannot read a valid project_id from '${TFVARS}' (missing, malformed, or the file does not parse)."
        if [ "${tf_project}" != "${PROJECT_ID}" ]; then
            sv_die "Target project is '${PROJECT_ID}' (from ${source_desc}) but '${TFVARS}' has project_id='${tf_project}'. Refusing to mix installs."
        fi
    fi

    sv_guard_autoload_files

    # G4: region comes from the vars file, never from gcloud config.
    region="$(sv_tfvar region)" || sv_die "Cannot read region from '${TFVARS}'."
    sv_valid_region "${region}" || sv_die "region '${region}' in '${TFVARS}' is not a valid GCP region."
    REGION="${region}"

    STATE_BUCKET="castor-tfstate-${PROJECT_ID}"
    # G3: one init dir per install, so a backend bound for one install is never reused for another.
    export TF_DATA_DIR="${PLATFORM_DIR}/.terraform-${PROJECT_ID}"
    # H9: every gcloud call in this process targets the resolved project.
    export CLOUDSDK_CORE_PROJECT="${PROJECT_ID}"
    export PROJECT_ID REGION TFVARS STATE_BUCKET

    sv_info "Target project: ${PROJECT_ID} (from ${source_desc})"
    sv_info "Vars file:      ${TFVARS}"
    sv_info "Region:         ${REGION}"
    sv_info "State bucket:   gs://${STATE_BUCKET}/platform/state"
}

# H7: OpenTofu's gcs backend StateMgr WRITES an empty state (lock + write + unlock) whenever
# <prefix>/<workspace>.tfstate is missing, regardless of -lock=false (verified in the v1.13.1
# source, internal/backend/remote-state/gcs/backend_state.go). So any init/plan against a
# project without platform state is a write. Check read-only first.
sv_require_platform_state() {
    if ! gcloud storage objects describe "gs://${STATE_BUCKET}/platform/state/default.tfstate" --project="${PROJECT_ID}" >/dev/null 2>&1; then
        sv_die "No platform state at gs://${STATE_BUCKET}/platform/state/default.tfstate (or no read access). This wrapper never creates state outside 'init'; use scripts/bootstrap.sh for a new install."
    fi
}

# G3 (belt and braces): after init, the bound backend must be this install's bucket.
sv_guard_backend_bucket() {
    local bound
    bound="$(python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(d["backend"]["config"]["bucket"])
except Exception:
    sys.exit(2)
' "${TF_DATA_DIR}/terraform.tfstate")" || sv_die "Cannot read the bound backend from ${TF_DATA_DIR}/terraform.tfstate."
    if [ "${bound}" != "${STATE_BUCKET}" ]; then
        sv_die "Backend is bound to bucket '${bound}', expected '${STATE_BUCKET}'. Refusing to continue."
    fi
}

# Bind the backend for this install (apply.sh and bootstrap.sh). Writes only the local TF_DATA_DIR
# (and the local dependency lock file).
# Workspace (red team F2): `init -reconfigure` keeps the selection in ${TF_DATA_DIR}/environment, so a
# stale `foo` would point every command at platform/state/foo.tfstate. The platform only ever uses the
# `default` workspace: drop the selection file before init, then require `workspace show` == default.
sv_tf_init_bound() {
    local ws
    rm -f "${TF_DATA_DIR}/environment" || sv_die "Cannot remove the stale workspace selection ${TF_DATA_DIR}/environment."
    "${IAC_BIN}" init -reconfigure -input=false -backend-config="bucket=${STATE_BUCKET}" >&2 \
        || sv_die "'${IAC_BIN} init' failed."
    sv_guard_backend_bucket
    ws="$("${IAC_BIN}" workspace show)" || sv_die "'${IAC_BIN} workspace show' failed."
    if [ "${ws}" != "default" ]; then
        sv_die "Selected workspace is '${ws}', expected 'default' (platform state is platform/state/default.tfstate). Refusing to continue."
    fi
}

# H5 gate, shared by apply.sh (apply/destroy) and bootstrap.sh:
#   plan -out (0700 temp dir) -> show -json -> any delete/replace refused unless $2 == PROJECT_ID
#   -> typed project id on a terminal -> apply exactly that plan file.
# $1 mode: apply | destroy | bootstrap. `apply` pre-enables the base APIs after the typed confirm
#          (bootstrap enables its own list earlier; destroy and -refresh-only plans never do).
# $2 allow-destroy value. Remaining args: allowlisted plan flags.
# -refresh-only (red team F3): such a plan carries its changes in `resource_drift` (state-only
# updates/removals), not in `resource_changes`, so the gate counts resource_drift for it.
# Returns the apply exit code (0 also for "no changes"); every refusal exits via sv_die.
SV_PLAN_TMP=""
sv_cleanup_plan_tmp() {
    if [ -n "${SV_PLAN_TMP}" ]; then
        rm -rf "${SV_PLAN_TMP}"
        SV_PLAN_TMP=""
    fi
}

# FD-4DA item 10 (platform version stamp; SAT-10 design, rides the FD-7L step-A apply): the commit this platform
# Terraform is applied from, as TF_VAR_stackvend_platform_commit (40 hex, "+dirty" when
# `git status --porcelain --untracked-files=no` shows a change to a tracked file; untracked files, such as local
# tool notes, do not mark the stamp). Set INTERNALLY after sv_scrub_tofu_env (which still refuses a caller's TF_VAR_*), so the
# `-var` ban stays. Not a git checkout (an install from a release archive), or git unreadable: empty value (the
# annotation is left out; the Settings version card then shows the release only) and an info line.
sv_export_platform_stamp() {
    local root top commit="" status_out
    root="$(cd "${PLATFORM_DIR}/../.." 2>/dev/null && pwd -P)" || root=""
    if [ -n "${root}" ] && command -v git >/dev/null 2>&1; then
        top="$(git -C "${root}" rev-parse --show-toplevel 2>/dev/null)" || top=""
        if [ -n "${top}" ] && [ "$(cd "${top}" 2>/dev/null && pwd -P)" = "${root}" ]; then
            commit="$(git -C "${root}" rev-parse HEAD 2>/dev/null)" || commit=""
            if [[ "${commit}" =~ ^[0-9a-f]{40}$ ]]; then
                if status_out="$(git -C "${root}" status --porcelain --untracked-files=no 2>/dev/null)"; then
                    [ -z "${status_out}" ] || commit="${commit}+dirty"
                else
                    commit=""
                fi
            else
                commit=""
            fi
        fi
    fi
    if [ -z "${commit}" ]; then
        sv_info "Platform version stamp: ${root:-the platform directory} is not a readable git checkout, so the stackvend/platform-commit annotation is left out (stackvend/platform-release from VERSION is still written)."
    fi
    export TF_VAR_stackvend_platform_commit="${commit}"
}

sv_gated_apply() {
    local mode="$1" allow="$2" rc gate_rc refresh_only=0 a
    shift 2
    for a in "$@"; do
        if [ "${a}" = "-refresh-only" ]; then
            refresh_only=1
        fi
    done
    sv_export_platform_stamp
    sv_cleanup_plan_tmp
    SV_PLAN_TMP="$(mktemp -d)" || sv_die "mktemp failed."
    chmod 700 "${SV_PLAN_TMP}" || sv_die "chmod of the plan temp dir failed."

    local plan_flags=()
    if [ "${mode}" = "destroy" ]; then
        plan_flags+=("-destroy")
    fi
    set +e
    "${IAC_BIN}" plan -input=false -var-file="${TFVARS}" ${plan_flags[@]+"${plan_flags[@]}"} "$@" -out="${SV_PLAN_TMP}/plan.bin"
    rc=$?
    set -e
    [ ${rc} -eq 0 ] || sv_die "'${IAC_BIN} plan' failed (rc=${rc}). Nothing was applied."

    "${IAC_BIN}" show -json "${SV_PLAN_TMP}/plan.bin" > "${SV_PLAN_TMP}/plan.json" \
        || sv_die "'${IAC_BIN} show -json' failed. Nothing was applied."

    set +e
    python3 - "${SV_PLAN_TMP}/plan.json" "${refresh_only}" <<'PY'
import json, sys
plan = json.load(open(sys.argv[1]))
refresh_only = sys.argv[2] == "1"
counts = {}
deletes = []
changed = 0
for rc in plan.get("resource_changes", []):
    actions = rc.get("change", {}).get("actions", [])
    if actions in (["no-op"], ["read"]):
        continue
    changed += 1
    key = "+".join(actions)
    counts[key] = counts.get(key, 0) + 1
    if "delete" in actions:
        deletes.append(rc.get("address", "?") + " (" + key + ")")
drift = []
if refresh_only:
    # Applying a refresh-only plan writes these to state only; it never changes a cloud resource.
    for rc in plan.get("resource_drift", []):
        actions = rc.get("change", {}).get("actions", [])
        if actions in (["no-op"], ["read"]):
            continue
        drift.append(rc.get("address", "?") + " (" + "+".join(actions) + ")")
out_changes = [k for k, v in (plan.get("output_changes") or {}).items()
               if v.get("actions") not in (["no-op"], None)]
print("Plan summary: " + (", ".join("%s=%d" % (k, v) for k, v in sorted(counts.items())) or "no resource changes")
      + ("; %d output change(s)" % len(out_changes) if out_changes else "")
      + ("; %d drift entr%s to record in state (refresh-only)" % (len(drift), "y" if len(drift) == 1 else "ies") if refresh_only else ""),
      file=sys.stderr)
for d in drift:
    print("  drift (state only): " + d, file=sys.stderr)
if deletes:
    print("DESTRUCTIVE actions in this plan:", file=sys.stderr)
    for d in deletes:
        print("  - " + d, file=sys.stderr)
    sys.exit(10)
if changed == 0 and not out_changes and not drift:
    sys.exit(20)
sys.exit(0)
PY
    gate_rc=$?
    set -e
    case "${gate_rc}" in
        0) ;;
        20) sv_info "No changes. Nothing to apply."; sv_cleanup_plan_tmp; return 0 ;;
        10)
            if [ "${allow}" != "${PROJECT_ID}" ]; then
                sv_die "The plan deletes or replaces resources (listed above). Nothing was applied. Only if every one of them is intended: PROJECT_ID=${PROJECT_ID} scripts/apply.sh apply --allow-destroy=${PROJECT_ID}"
            fi ;;
        *) sv_die "Could not evaluate the plan JSON (rc=${gate_rc}). Nothing was applied." ;;
    esac

    # FD-7L step B (SAT-33): a caller-defined read-only check of the exact plan before the typed confirmation
    # (scripts/common/runner_switch_gate.sh defines sv_post_plan_check, sourced by apply.sh and bootstrap.sh; it
    # refuses via sv_die). Never for destroy.
    if [ "${mode}" != "destroy" ] && declare -F sv_post_plan_check >/dev/null 2>&1; then
        sv_post_plan_check "${SV_PLAN_TMP}/plan.json"
    fi

    sv_confirm_project "Apply the plan above to ${PROJECT_ID}?"

    if [ "${mode}" = "apply" ] && [ "${refresh_only}" = "0" ]; then
        # Pre-enable base APIs (two gcloud calls, 20 + 1 APIs, each <= the 20-service batch limit; a no-op on existing installs) only after
        # the operator confirmed. Not shown in the plan (google_project_service.apis owns them in TF).
        # RC B3: compute.googleapis.com is in the list so the Compute Engine default service account exists
        # before the apply binds it (google_project_iam_member.cloudbuild_compute_*).
        # ORG-POLICY-FOLDER: orgpolicy.googleapis.com is in the list so the API is on (and propagated) before the
        # apply creates google_org_policy_policy.managed_folder_vm_external_ip, which bills the host as quota project.
        # BOOTSTRAP-TOS-FAIL-LOUD: an account that never accepted the Google Cloud terms gets
        # APPLY_CLOUD_TERMS_NOT_ACCEPTED; any other failure APPLY_API_ENABLE_FAILED (sv_enable_apis_or_die).
        sv_enable_apis_or_die APPLY "" "Nothing was applied." gcloud services enable \
            serviceusage.googleapis.com cloudresourcemanager.googleapis.com iam.googleapis.com \
            compute.googleapis.com \
            storage.googleapis.com run.googleapis.com artifactregistry.googleapis.com \
            cloudbuild.googleapis.com pubsub.googleapis.com firestore.googleapis.com \
            workflows.googleapis.com cloudscheduler.googleapis.com secretmanager.googleapis.com \
            aiplatform.googleapis.com cloudbilling.googleapis.com drive.googleapis.com \
            docs.googleapis.com servicenetworking.googleapis.com vpcaccess.googleapis.com \
            sqladmin.googleapis.com \
            --project="${PROJECT_ID}" --quiet
        # Service Usage enables at most 20 services per call (SU_MAX_BATCH_SIZE_EXCEEDED, seen 10-28): keep each call <= 20.
        sv_enable_apis_or_die APPLY "" "Nothing was applied." gcloud services enable orgpolicy.googleapis.com \
            --project="${PROJECT_ID}" --quiet
    fi
    if [ "${refresh_only}" = "0" ] && { [ "${mode}" = "apply" ] || [ "${mode}" = "bootstrap" ]; }; then
        sv_wait_default_compute_sa
    fi

    set +e
    "${IAC_BIN}" apply -input=false "${SV_PLAN_TMP}/plan.bin"
    rc=$?
    set -e
    sv_cleanup_plan_tmp
    return ${rc}
}

# RC B3: the apply binds <project-number>-compute@developer.gserviceaccount.com (google_project_iam_member.
# cloudbuild_compute_storage / _logging / _artifact; Cloud Build source deploys run as it). Google creates that
# account asynchronously, about a minute after compute.googleapis.com is enabled, so on a fresh project the first
# apply used to fail with "service account ... does not exist". Read-only wait (at most ~2 min) before the apply;
# a no-op on existing installs (one describe call). Never fails: if the account still does not exist (or the
# organization disables default service accounts), print why the apply may fail and continue.
sv_wait_default_compute_sa() {
    local number sa i
    number="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)' 2>/dev/null)" || number=""
    if [[ ! "${number}" =~ ^[0-9]+$ ]]; then
        sv_warn "Could not read the project number of ${PROJECT_ID}; not waiting for the Compute Engine default service account."
        return 0
    fi
    sa="${number}-compute@developer.gserviceaccount.com"
    for i in 1 2 3 4 5 6 7 8 9 10 11 12; do
        if gcloud iam service-accounts describe "${sa}" --project="${PROJECT_ID}" --format='value(email)' >/dev/null 2>&1; then
            return 0
        fi
        if [ "${i}" = "1" ]; then
            sv_info "Waiting for the Compute Engine default service account ${sa} (Google creates it about a minute after compute.googleapis.com is enabled; up to 2 min)..."
        fi
        sleep 10
    done
    sv_warn "The Compute Engine default service account ${sa} does not exist yet. The apply may fail on google_project_iam_member.cloudbuild_compute_*; if it does, wait a minute and run the apply again. If your organization deletes or disables default service accounts, Cloud Build source deploys (scripts/deploy-services.sh) need it restored first."
    return 0
}

# Typed confirmation: the operator must type the project id on an interactive terminal.
sv_confirm_project() {
    local prompt="$1" answer
    if [ ! -t 0 ]; then
        sv_die "${prompt}: needs an interactive terminal to type the project id; refusing to continue non-interactively."
    fi
    echo -e "\n\033[1;33m${prompt}\033[0m" >&2
    printf 'Type the project id (%s) to continue: ' "${PROJECT_ID}" >&2
    answer=""
    read -r answer || answer=""
    if [ "${answer}" != "${PROJECT_ID}" ]; then
        sv_die "Confirmation did not match '${PROJECT_ID}'. Nothing was changed by this step."
    fi
}

# ------------------------------------------------------------------------------
# FD-4AP + behavior-change register row 17 (owner 10-12): the Cloud Shell IPv4 fix is KEPT.
#   Layers: (1) gai.conf IPv4 precedence, (2) IPv6 off via sysctl, (3) GODEBUG=netdns=cgo,
#           (4) /etc/hosts IPv4 pins for the Google API hostnames, confined to ONE marked block.
#   Full fix: automatic when CLOUD_SHELL=true, or forced with --ipv4-fix (Linux only).
#   Any other machine: only GODEBUG=netdns=cgo (a process env var; nothing on the machine changes).
#   Runs for plan too: local VM network tweaks are not plan side effects (register row 17).
#   /etc/hosts: only the lines between SV_IPV4_BEGIN and SV_IPV4_END are ever replaced (as a whole);
#   every other line is kept byte-for-byte. No substring matching, no deletion of other lines.
# ------------------------------------------------------------------------------
SV_IPV4_BEGIN='# BEGIN stackvend-ipv4'
SV_IPV4_END='# END stackvend-ipv4'
SV_IPV4_PIN_DOMAINS=(
    iam.googleapis.com iamcredentials.googleapis.com oauth2.googleapis.com container.googleapis.com
    compute.googleapis.com cloudresourcemanager.googleapis.com serviceusage.googleapis.com
    storage.googleapis.com run.googleapis.com workflows.googleapis.com pubsub.googleapis.com
    firestore.googleapis.com artifactregistry.googleapis.com secretmanager.googleapis.com
    cloudbuild.googleapis.com logging.googleapis.com monitoring.googleapis.com
    clouderrorreporting.googleapis.com cloudtrace.googleapis.com cloudscheduler.googleapis.com
    aiplatform.googleapis.com discoveryengine.googleapis.com generativelanguage.googleapis.com
    cloudbilling.googleapis.com drive.googleapis.com docs.googleapis.com iap.googleapis.com
    servicenetworking.googleapis.com vpcaccess.googleapis.com sqladmin.googleapis.com
)

sv_warn() {
    echo -e "\033[1;33m[WARN]\033[0m $*" >&2
}

# Layer 3 (every machine): the Go resolver in tofu/terraform goes through libc (honours gai.conf
# and /etc/hosts). Other GODEBUG settings are kept; any earlier netdns=<x> is replaced.
sv_set_godebug_cgo() {
    local parts=() part out=""
    if [ -n "${GODEBUG:-}" ]; then
        IFS=',' read -r -a parts <<< "${GODEBUG}"
    fi
    for part in ${parts[@]+"${parts[@]}"}; do
        case "${part}" in
            ""|netdns=*) ;;
            *) out="${out:+${out},}${part}" ;;
        esac
    done
    GODEBUG="${out:+${out},}netdns=cgo"
    export GODEBUG
}

# Entry point. $1 = non-empty to force the full fix (--ipv4-fix). Best effort: a failed layer
# warns and continues (the old script's behavior), and it never fails the caller.
sv_network_setup() {
    local force="${1:-}"
    sv_set_godebug_cgo
    if [ "${CLOUD_SHELL:-}" != "true" ] && [ -z "${force}" ]; then
        return 0
    fi
    if [ "$(uname -s)" != "Linux" ]; then
        sv_warn "IPv4 fix requested, but this is not Linux: only GODEBUG=netdns=cgo was set."
        return 0
    fi
    sv_info "IPv4 fix (CLOUD_SHELL=${CLOUD_SHELL:-unset}${force:+, --ipv4-fix}): gai.conf precedence, IPv6 sysctl off, GODEBUG=netdns=cgo, /etc/hosts block '${SV_IPV4_BEGIN}'."
    sv_ipv4_sysctl
    sv_ipv4_files
    return 0
}

# Layer 2: disable IPv6 on all/default and on every existing interface.
sv_ipv4_sysctl() {
    local iface
    sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || sv_warn "sysctl net.ipv6.conf.all.disable_ipv6=1 failed."
    sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || sv_warn "sysctl net.ipv6.conf.default.disable_ipv6=1 failed."
    for iface in /proc/sys/net/ipv6/conf/*; do
        [ -d "${iface}" ] || continue
        sudo sysctl -w "net.ipv6.conf.$(basename "${iface}").disable_ipv6=1" >/dev/null 2>&1 || true
    done
}

# Layers 1 + 4. Resolution runs unprivileged and asks DNS directly (`getent -s hosts:dns`), so the
# current pins in /etc/hosts are never fed back as "fresh" addresses. The root step only receives
# validated "<ipv4> <host>" pairs. If nothing resolves (DNS down, no getent -s), the existing block
# is left as it is.
sv_ipv4_files() {
    local tmp entries d ip
    tmp="$(mktemp -d)" || { sv_warn "mktemp failed; IPv4 file layers skipped."; return 0; }
    entries="${tmp}/entries"
    : > "${entries}"
    for d in "${SV_IPV4_PIN_DOMAINS[@]}"; do
        ip="$(getent -s hosts:dns ahostsv4 "${d}" 2>/dev/null | awk 'NR == 1 { print $1 }')" || ip=""
        if [ -n "${ip}" ]; then
            printf '%s %s\n' "${ip}" "${d}" >> "${entries}"
        fi
    done
    sudo python3 - /etc/gai.conf /etc/hosts "${entries}" "${SV_IPV4_BEGIN}" "${SV_IPV4_END}" "${SV_IPV4_PIN_DOMAINS[@]}" <<'PY' || sv_warn "IPv4 fix: gai.conf / /etc/hosts step failed (see above); continuing."
import ipaddress, sys

gai_path, hosts_path, entries_path, begin, end = sys.argv[1:6]
allowed = sys.argv[6:]
GAI_LINE = "precedence ::ffff:0:0/96 100"

def warn(msg):
    print("[WARN] IPv4 fix: " + msg, file=sys.stderr)

# Layer 1: append the exact precedence line once. Other gai.conf lines are never touched.
try:
    with open(gai_path, newline="") as f:
        gai = f.read()
except FileNotFoundError:
    gai = ""
if GAI_LINE not in [l.strip() for l in gai.splitlines()]:
    with open(gai_path, "a", newline="") as f:
        f.write(("\n" if gai and not gai.endswith("\n") else "") + GAI_LINE + "\n")

# Layer 4: validated pins only (allowlisted host, literal IPv4 address, one line per host).
pins, seen = [], set()
with open(entries_path) as f:
    for raw in f.read().splitlines():
        parts = raw.split()
        if len(parts) != 2 or parts[1] not in allowed or parts[1] in seen:
            warn("ignoring unexpected resolver line %r" % raw)
            continue
        try:
            ip = str(ipaddress.IPv4Address(parts[0]))
        except ValueError:
            warn("ignoring non-IPv4 address %r" % raw)
            continue
        seen.add(parts[1])
        pins.append("%s %s" % (ip, parts[1]))
if not pins:
    warn("no Google API hostname resolved to IPv4; /etc/hosts left unchanged.")
    sys.exit(0)

with open(hosts_path, newline="", encoding="utf-8") as f:
    text = f.read()
lines = text.splitlines(keepends=True)
marks = [l.strip() for l in lines]
b = [i for i, m in enumerate(marks) if m == begin]
e = [i for i, m in enumerate(marks) if m == end]
block = [begin + "\n"] + [p + "\n" for p in pins] + [end + "\n"]
if not b and not e:
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    new_lines, keep = lines + block, lines
elif len(b) == 1 and len(e) == 1 and b[0] < e[0]:
    new_lines, keep = lines[:b[0]] + block + lines[e[0] + 1:], lines[:b[0]] + lines[e[0] + 1:]
else:
    warn("%s has %d '%s' and %d '%s' markers (expected one pair, in order). Left unchanged; fix it by hand."
         % (hosts_path, len(b), begin, len(e), end))
    sys.exit(0)

# Informational only: pins outside the block (e.g. left by the pre-10-12 script) win over the
# block because /etc/hosts is first-match. They are reported, never edited.
outside = 0
for l in keep:
    f2 = l.split("#", 1)[0].split()
    if len(f2) == 2 and f2[1] in allowed:
        outside += 1
if outside:
    warn("%d line(s) outside the %s block also pin Google API hostnames; they take precedence. Not edited." % (outside, begin))

new_text = "".join(new_lines)
if new_text == text:
    sys.exit(0)

# Red team F5: never truncate-then-write. Write a temp file in the same directory with the original
# mode and owner, fsync, then rename over the original (atomic). Containers often bind-mount
# /etc/hosts, and rename onto a mount point fails with EBUSY (EXDEV on some runtimes); only for those
# two errnos fall back to an in-place overwrite that writes first and truncates last, so the file is
# never empty at any point. Any other error: original untouched, step fails (caller warns).
import errno, os, stat, tempfile
st = os.stat(hosts_path)
fd, tmp_path = tempfile.mkstemp(prefix=".hosts.stackvend.", dir=os.path.dirname(os.path.abspath(hosts_path)))
try:
    with os.fdopen(fd, "w", newline="", encoding="utf-8") as f:
        f.write(new_text)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp_path, stat.S_IMODE(st.st_mode))
    os.chown(tmp_path, st.st_uid, st.st_gid)
    try:
        os.replace(tmp_path, hosts_path)
        tmp_path = None
    except OSError as exc:
        if exc.errno not in (errno.EBUSY, errno.EXDEV):
            raise
        warn("%s cannot be replaced by rename (%s, e.g. a bind mount); overwriting in place (write, then truncate)."
             % (hosts_path, errno.errorcode.get(exc.errno, exc.errno)))
        data = new_text.encode("utf-8")
        with open(hosts_path, "r+b") as f:
            f.write(data)
            f.truncate(len(data))
            f.flush()
            os.fsync(f.fileno())
finally:
    if tmp_path is not None and os.path.exists(tmp_path):
        os.unlink(tmp_path)
PY
    rm -rf "${tmp}"
    return 0
}

# ------------------------------------------------------------------------------
# BG-1 (owner 10-18): decide var.bind_billing_iam (infra/platform/billing_iam.tf) WITHOUT failing the apply.
#   - the tfvars sets bind_billing_iam (true/false): that value wins; nothing is checked or passed.
#   - billing_account_id is empty: nothing is checked or passed (null = no billing resources).
#   - otherwise ONE read-only call, as the person applying (no mutation):
#       POST https://cloudbilling.googleapis.com/v1/billingAccounts/<id>:testIamPermissions
#       {"permissions": ["billing.accounts.setIamPolicy", "billing.accounts.getIamPolicy"]}
#     setIamPolicy held -> -var=bind_billing_iam=true (Terraform makes the two billing.user grants and,
#       BG-1-b, the CC's billing.viewer grant).
#     not held, or the check failed -> -var=bind_billing_iam=false plus a WARNING (never an error):
#       the install continues; Control Center Settings shows the missing grant and the fix.
#     Exception: the members are already in state (an earlier apply by a Billing Account Administrator)
#       -> keep true, so a later apply by someone else never plans their deletion, and (OpenTofu, no -target)
#       add -exclude=google_billing_account_iam_member.billing_user (and, BG-1-b, .cc_billing_viewer) so they
#       are neither refreshed nor re-created.
#   - any read problem: a warning and no decision (never aborts the run).
# Sets SV_BILLING_TF_ARGS (extra plan args, possibly empty) and SV_BIND_BILLING_IAM (true|false|"").
# Needs IAC_BIN, TFVARS, PROJECT_ID and a bound backend (state list). The access token goes to curl on its
# stdin config, never on the command line.
# ------------------------------------------------------------------------------
SV_BILLING_TF_ARGS=()
SV_BIND_BILLING_IAM=""
SV_BILLING_DECIDED_BY=""   # tfvars | preflight | "" (no decision)
SV_BILLING_CHECK=""        # admin | not_admin (positive answer) | unavailable (could not run) | "" (not run)
SV_BILLING_USER_SAS=(sa-project-provisioner sa-castor-developer)
SV_BILLING_VIEWER_SA="sa-stackvend-control-center"   # BG-1-b: google_billing_account_iam_member.cc_billing_viewer

sv_billing_grant_skipped_warning() {
    local billing="$1" reason="$2" sa
    sv_warn "Billing Account User (roles/billing.user) will NOT be granted on billing account ${billing} to:"
    for sa in "${SV_BILLING_USER_SAS[@]}"; do
        echo "         serviceAccount:${sa}@${PROJECT_ID}.iam.gserviceaccount.com" >&2
    done
    echo "       (nor Billing Account Viewer, roles/billing.viewer, to serviceAccount:${SV_BILLING_VIEWER_SA}@${PROJECT_ID}.iam.gserviceaccount.com)" >&2
    echo "       Reason: ${reason}" >&2
    echo "       The install continues without them (a post-install step, documentation/quickstart.md \"Post-install: billing access\"):" >&2
    echo "       until they exist, the first workload run stops at project vending with BILLING_NOT_LINKED, the FinOps enforcer" >&2
    echo "       cannot re-link billing after a budget quarantine, and the Control Center Settings billing card shows a warning." >&2
    echo "       Fix: a Billing Account Administrator re-runs 'PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply', or runs:" >&2
    for sa in "${SV_BILLING_USER_SAS[@]}"; do
        echo "         gcloud billing accounts add-iam-policy-binding ${billing} --member=serviceAccount:${sa}@${PROJECT_ID}.iam.gserviceaccount.com --role=roles/billing.user" >&2
    done
    echo "         gcloud billing accounts add-iam-policy-binding ${billing} --member=serviceAccount:${SV_BILLING_VIEWER_SA}@${PROJECT_ID}.iam.gserviceaccount.com --role=roles/billing.viewer" >&2
    echo "       Control Center > Settings (billing card) shows which service account still lacks it." >&2
}

# 0 if `tofu state list` output ($1) has any billing_iam.tf member (billing_user or, BG-1-b, cc_billing_viewer).
# Here-string, not a pipe: under `set -o pipefail` a `printf | grep -q` can lose a match on a large state
# list (SIGPIPE, RT F3).
sv_billing_members_in_state() {
    local state="$1" sa
    for sa in "${SV_BILLING_USER_SAS[@]}"; do
        if grep -Fxq -- "google_billing_account_iam_member.billing_user[\"${sa}\"]" <<<"${state}"; then
            return 0
        fi
    done
    if grep -Fxq -- "google_billing_account_iam_member.cc_billing_viewer[0]" <<<"${state}"; then
        return 0
    fi
    return 1
}

# Remaining args: the caller's allowlisted plan flags (only to see whether -target= is present).
sv_billing_iam_preflight() {
    local explicit billing token resp verdict reason state a has_target=""
    SV_BILLING_TF_ARGS=()
    SV_BIND_BILLING_IAM=""
    SV_BILLING_DECIDED_BY=""
    SV_BILLING_CHECK=""
    for a in "$@"; do
        case "${a}" in -target=*) has_target=1 ;; esac
    done
    # RT F2: never abort on the billing decision. A tfvars value tofu rejects fails in the plan itself.
    if ! explicit="$(sv_tfvar bind_billing_iam nullable)"; then
        sv_warn "Could not read bind_billing_iam from ${TFVARS}; no billing grant decision made (the plan uses the tfvars value as is)."
        return 0
    fi
    case "${explicit}" in
        true|false)
            SV_BIND_BILLING_IAM="${explicit}"
            SV_BILLING_DECIDED_BY="tfvars"
            sv_info "bind_billing_iam = ${explicit} is set in ${TFVARS}; it wins (no billing permission check)."
            if [ "${explicit}" = "false" ]; then
                sv_info "Billing Account User grants are skipped by that setting. Remove the line to let apply.sh grant them whenever a Billing Account Administrator applies."
                # RT F6: an explicit false after Terraform made the grants plans their removal.
                state="$("${IAC_BIN}" state list 2>/dev/null)" || state=""
                if sv_billing_members_in_state "${state}"; then
                    sv_warn "bind_billing_iam = false, but Terraform already manages the Billing Account User grants (google_billing_account_iam_member.billing_user / .cc_billing_viewer is in state): this plan tries to REMOVE them and the destroy gate will refuse it. Remove the line from ${TFVARS} to keep them."
                fi
            fi
            return 0 ;;
        null) ;;
        *)
            sv_warn "bind_billing_iam in ${TFVARS} reads as '${explicit}'; no billing grant decision made (the plan uses the tfvars value as is)."
            return 0 ;;
    esac
    if ! billing="$(sv_tfvar billing_account_id)"; then
        sv_warn "Could not read billing_account_id from ${TFVARS}; no billing grant decision made."
        return 0
    fi
    billing="${billing#billingAccounts/}"
    if [ -z "${billing}" ]; then
        return 0
    fi
    SV_BILLING_DECIDED_BY="preflight"

    if [[ ! "${billing}" =~ ^[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6}$ ]]; then
        verdict="NONE|billing_account_id '${billing}' is not in the 01XXXX-XXXXXX-XXXXXX format, so the permission check was not run."
    else
        token="$(gcloud auth print-access-token 2>/dev/null)" || token=""
        if [ -z "${token}" ]; then
            verdict="NONE|the read-only permission check could not get an access token ('gcloud auth print-access-token' failed)."
        else
            resp="$(printf 'header = "Authorization: Bearer %s"\n' "${token}" | curl -sS --max-time 20 -K - -X POST \
                -H "Content-Type: application/json" \
                --data '{"permissions":["billing.accounts.setIamPolicy","billing.accounts.getIamPolicy"]}' \
                -w '\n%{http_code}' \
                "https://cloudbilling.googleapis.com/v1/billingAccounts/${billing}:testIamPermissions" 2>/dev/null)" || resp=""
            verdict="$(printf '%s' "${resp}" | python3 -c '
import json, sys
body, _, code = sys.stdin.read().rpartition("\n")
code = code.strip()
if code != "200":
    shown = code if (code.isdigit() and code != "000") else "(no response)"
    print("NONE|the read-only check billingAccounts.testIamPermissions answered HTTP %s, so Billing Account Administrator rights could not be confirmed." % shown)
    sys.exit(0)
try:
    perms = json.loads(body or "{}").get("permissions", [])
except (ValueError, AttributeError):
    perms = None
if not isinstance(perms, list):
    print("NONE|the read-only check billingAccounts.testIamPermissions returned an unreadable answer.")
    sys.exit(0)
if "billing.accounts.setIamPolicy" in perms:
    print("SET|")
else:
    print("DENY|the account running this script lacks billing.accounts.setIamPolicy on the billing account (it is not a Billing Account Administrator).")
')" || verdict=""
        fi
    fi
    [ -n "${verdict}" ] || verdict="NONE|the read-only permission check could not be evaluated."
    reason="${verdict#*|}"
    # BG-1-F5: DENY = a positive answer (HTTP 200, permission absent); NONE = the check could not run.
    case "${verdict%%|*}" in
        SET) SV_BILLING_CHECK="admin" ;;
        DENY) SV_BILLING_CHECK="not_admin" ;;
        *) SV_BILLING_CHECK="unavailable" ;;
    esac

    if [ "${verdict%%|*}" = "SET" ]; then
        SV_BIND_BILLING_IAM="true"
        sv_info "Billing Account Administrator rights confirmed (read-only check): Terraform grants roles/billing.user on ${billing} to ${SV_BILLING_USER_SAS[*]} (google_billing_account_iam_member.billing_user) and roles/billing.viewer to sa-stackvend-control-center (google_billing_account_iam_member.cc_billing_viewer)."
        SV_BILLING_TF_ARGS=("-var=bind_billing_iam=true")
        return 0
    fi
    SV_BIND_BILLING_IAM="false"
    state="$("${IAC_BIN}" state list 2>/dev/null)" || state=""
    if sv_billing_members_in_state "${state}"; then
        # Keep them declared (no planned delete). RT F1: a non-admin cannot refresh (getIamPolicy) or re-create
        # (setIamPolicy) them, so on OpenTofu exclude them from this run entirely: neither refreshed, created
        # nor destroyed. tofu refuses -exclude together with -target, and -target leaves them out anyway.
        SV_BIND_BILLING_IAM="true"
        SV_BILLING_TF_ARGS=("-var=bind_billing_iam=true")
        if [ "${IAC_BIN}" = "tofu" ] && [ -z "${has_target}" ]; then
            SV_BILLING_TF_ARGS+=("-exclude=google_billing_account_iam_member.billing_user"
                                 "-exclude=google_billing_account_iam_member.cc_billing_viewer")
            sv_warn "Billing Account User grants: skipped, kept as is. They are already managed by Terraform (in state from an earlier apply by a Billing Account Administrator); this run leaves them out (-exclude) because ${reason}"
        else
            sv_warn "Billing Account User grants: kept as is (already managed by Terraform). ${reason} If the plan fails with 403 on google_billing_account_iam_member.billing_user, ask a Billing Account Administrator to run this command."
        fi
        return 0
    fi
    sv_billing_grant_skipped_warning "${billing}" "${reason}"
    SV_BILLING_TF_ARGS=("-var=bind_billing_iam=false")
}
