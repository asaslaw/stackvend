#!/usr/bin/env bash
# ==============================================================================
# STACKVEND: CLOUD RUN COMPANION DEPLOYMENT ENGINE
# ==============================================================================
# Compiles and deploys StackVend microservices directly from local source
# using Google Cloud Run's native buildpack engine (--source).
#
# Ownership (Wave 1 lane 5, FD-4W / R3): Terraform owns every service's env, volumes,
# resources, scaling and IAM. This script only ships CODE (a new image from source);
# `gcloud run deploy --source` keeps the existing config. The one IAM-related flag is
# FD-4K's --no-allow-unauthenticated on the git server: it never makes anything public,
# and it removes an allUsers invoker binding if one exists.
# ==============================================================================
# Usage (the target project is REQUIRED; gcloud config is only used after an interactive confirm):
#   PROJECT_ID=<id> [REGION=<region>] bash scripts/deploy-services.sh             # 13 services + git server
#   PROJECT_ID=<id> bash scripts/deploy-services.sh <service>                     # one service, live logs
#   PROJECT_ID=<id> bash scripts/deploy-services.sh --all-jobs                    # services + 9 batch jobs
#   bash scripts/deploy-services.sh --project=<id> [--region=<region>] <service>
# Optional: STACKVEND_DEPLOY_SUMMARY_FILE=<path> -> the bulk run writes "<succeeded> <failed> <skipped>" there at its
# summary (bootstrap.sh reads it for its final status line). Output only; nothing else changes.
#
# Examples:
#   PROJECT_ID=my-stackvend-host REGION=us-central1 bash scripts/deploy-services.sh control-center
#   PROJECT_ID=my-stackvend-host bash scripts/deploy-services.sh mcp-terraform-server   # also syncs tf-applier
#   PROJECT_ID=my-stackvend-host bash scripts/deploy-services.sh orchestrator-gateway-service  # also syncs stage-runner
#   PROJECT_ID=my-stackvend-host bash scripts/deploy-services.sh stage-runner  # builds nothing: job <- gateway's serving image
# ==============================================================================

set -eo pipefail

# ANSI Styling
BOLD="\033[1m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
CYAN="\033[0;36m"
RESET="\033[0m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PLATFORM_DIR="${REPO_ROOT}/infra/platform"
# shellcheck source=common/platform_target.sh
. "${SCRIPT_DIR}/common/platform_target.sh"
# The component list and per-component recipes, shared with the upgrader (scripts/upgrade/; plan §3.6).
# shellcheck source=common/components.sh
. "${SCRIPT_DIR}/common/components.sh"
cd "${REPO_ROOT}"

# ------------------------------------------------------------------------------
# Arguments
# ------------------------------------------------------------------------------
TARGET="all"
INCLUDE_JOBS=false
for arg in "$@"; do
    case "${arg}" in
        --project=*) PROJECT_ID="${arg#--project=}" ;;
        --region=*) REGION="${arg#--region=}" ;;
        --all-jobs|--jobs|jobs) INCLUDE_JOBS=true ;;
        -*) sv_die "Unknown flag '${arg}'." ;;
        *) TARGET="${arg}" ;;
    esac
done

# ------------------------------------------------------------------------------
# Target project (H9): explicit PROJECT_ID/--project, or gcloud config after an
# interactive confirm. Never implicitly (sv9 deploys need owner approval).
# ------------------------------------------------------------------------------
if [ -z "${PROJECT_ID:-}" ]; then
    CFG_PROJECT="$(gcloud config get-value project 2>/dev/null)" || CFG_PROJECT=""
    [ -n "${CFG_PROJECT}" ] || sv_die "No target project. Set PROJECT_ID=<id> (or --project=<id>)."
    if [ ! -t 0 ]; then
        sv_die "PROJECT_ID is not set and stdin is not a terminal. Set PROJECT_ID=<id> explicitly (gcloud config says '${CFG_PROJECT}')."
    fi
    PROJECT_ID="${CFG_PROJECT}"
    sv_valid_project_id "${PROJECT_ID}" || sv_die "gcloud config project '${PROJECT_ID}' is not a valid GCP project id."
    sv_confirm_project "PROJECT_ID not set; gcloud config points at '${PROJECT_ID}'. Deploy there?"
fi
sv_valid_project_id "${PROJECT_ID}" || sv_die "PROJECT_ID '${PROJECT_ID}' is not a valid GCP project id."

if [ -z "${REGION:-}" ]; then
    REGION="$(gcloud config get-value compute/region 2>/dev/null)" || REGION=""
    REGION="${REGION:-us-central1}"
fi
sv_valid_region "${REGION}" || sv_die "REGION '${REGION}' is not a valid GCP region."
export CLOUDSDK_CORE_PROJECT="${PROJECT_ID}"

echo -e "\n${BLUE}${BOLD}==============================================================================${RESET}"
echo -e "${BLUE}${BOLD}  STACKVEND: CLOUD RUN SERVICE DEPLOYER${RESET}"
echo -e "${BLUE}${BOLD}==============================================================================${RESET}"
echo -e "Project: ${BOLD}${PROJECT_ID}${RESET}"
echo -e "Region:  ${BOLD}${REGION}${RESET}\n"

# ------------------------------------------------------------------------------
# Auto-Verify Cloud Run & Artifact Registry APIs and build staging locations
# (IAM for the build service account is Terraform-owned: main.tf cloudbuild_compute_*)
# ------------------------------------------------------------------------------
echo -e "${BLUE}==>${RESET} Verifying Cloud Run & Artifact Registry APIs..."
gcloud services enable run.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com --project="${PROJECT_ID}" --quiet 2>/dev/null || true

if ! gcloud artifacts repositories describe castor-docker-repo --location="${REGION}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1; then
    echo -e "${CYAN}==>${RESET} Artifact Registry repository 'castor-docker-repo' not found in ${REGION}. Auto-provisioning..."
    gcloud artifacts repositories create castor-docker-repo \
        --repository-format=docker \
        --location="${REGION}" \
        --project="${PROJECT_ID}" \
        --description="StackVend core platform container images" \
        --quiet 2>/dev/null || true
fi

STAGING_BUCKET="gs://run-sources-${PROJECT_ID}-${REGION}"
if ! gcloud storage buckets describe "${STAGING_BUCKET}" --project="${PROJECT_ID}" --quiet >/dev/null 2>&1; then
    echo -e "${CYAN}==>${RESET} Pre-creating Cloud Run build staging bucket ${STAGING_BUCKET}..."
    gcloud storage buckets create "${STAGING_BUCKET}" --project="${PROJECT_ID}" --location="${REGION}" --quiet 2>/dev/null || true
fi

# ------------------------------------------------------------------------------
# Service & Job Mappings: SERVICES / JOBS come from scripts/common/components.sh (sourced above).
# ------------------------------------------------------------------------------

# ------------------------------------------------------------------------------
# Deployed version record (FD-7C P3a, SELFUP-VERSION-RECORD). Information only; it never stops a deploy:
#   1. release_prepare (before anything is written into the tree): scripts/common/release_record.py stamp computes
#      release.json (VERSION, commit, dirty, build time, source repository) for this checkout;
#   2. release_place copies it into each component's source directory before its build (git-ignored, one exact
#      entry per component in the root .gitignore) and release_cleanup removes every copy on exit;
#   3. release_record_write writes system_config/platform_release once, after the run, for the components that
#      deployed (the operator's own token). Any failure prints a warning and the deploy result stays as it was.
# ------------------------------------------------------------------------------
RELEASE_RECORD_PY="${SCRIPT_DIR}/common/release_record.py"
RELEASE_JSON_TMP=""
RELEASE_PLACED=()
RELEASE_RECORDED=()

release_prepare() {
    if [ ! -f "${RELEASE_RECORD_PY}" ]; then
        echo -e "  ${YELLOW}[WARNING]${RESET} ${RELEASE_RECORD_PY} not found: no release.json and no version record for this deploy."
        return 0
    fi
    RELEASE_JSON_TMP="$(mktemp)" || { RELEASE_JSON_TMP=""; return 0; }
    if ! python3 "${RELEASE_RECORD_PY}" stamp --repo-root "${REPO_ROOT}" > "${RELEASE_JSON_TMP}"; then
        echo -e "  ${YELLOW}[WARNING]${RESET} Could not compute release.json (see above): components will report release \"unknown\" and no version record is written."
        rm -f "${RELEASE_JSON_TMP}"
        RELEASE_JSON_TMP=""
    fi
}

release_place() {
    local dir="$1"
    [ -n "${RELEASE_JSON_TMP}" ] || return 0
    if cp "${RELEASE_JSON_TMP}" "${REPO_ROOT}/${dir}/release.json"; then
        RELEASE_PLACED+=("${dir}")
    else
        echo -e "  ${YELLOW}[WARNING]${RESET} Could not write ${dir}/release.json: that component will report release \"unknown\"."
    fi
}

release_cleanup() {
    local d
    for d in "${RELEASE_PLACED[@]}"; do
        rm -f "${REPO_ROOT}/${d}/release.json"
    done
    [ -z "${RELEASE_JSON_TMP}" ] || rm -f "${RELEASE_JSON_TMP}"
}
trap release_cleanup EXIT

release_record_write() {
    local full="$1" token account
    [ -n "${RELEASE_JSON_TMP}" ] || return 0
    [ "${#RELEASE_RECORDED[@]}" -gt 0 ] || return 0
    token="$(gcloud auth print-access-token --quiet 2>/dev/null)" || token=""
    account="$(gcloud config get-value account 2>/dev/null)" || account=""
    if [ -z "${token}" ]; then
        echo -e "  ${YELLOW}[WARNING]${RESET} No gcloud access token: the version record (system_config/platform_release) was not updated. The deploy itself is unaffected."
        return 0
    fi
    if [ "${full}" = true ]; then full="--full-run"; else full=""; fi
    # shellcheck disable=SC2086
    if ! printf '%s\n' "${token}" | python3 "${RELEASE_RECORD_PY}" record --project "${PROJECT_ID}" --region "${REGION}" \
            --release-file "${RELEASE_JSON_TMP}" --deployed-by "${account}" ${full} --token-stdin "${RELEASE_RECORDED[@]}"; then
        echo -e "  ${YELLOW}[WARNING]${RESET} The version record (system_config/platform_release) was not updated (see above). The deploy itself is unaffected; Settings shows these components as \"not from a recorded deploy\" until the next recorded deploy."
    fi
}

# Row L3-PRB-r: the QA sandbox job's contract label (QA_JOB_CONTRACT_LABEL, scripts/common/components.sh) is set
# right after its deploy.

# `gcloud run jobs deploy` has no --update-labels (10-13 sv9 deploy failed with "unrecognized arguments"); the label
# is applied by `jobs update` right after a successful deploy, as the castor trigger's `jobs update` step does.
job_label_after_deploy() {
    if [ "$1" == "qa-sandbox-test-runner" ]; then
        gcloud run jobs update "$1" --region "${REGION}" --project "${PROJECT_ID}" \
            --update-labels="${QA_JOB_CONTRACT_LABEL}" --quiet || return 1
    fi
    return 0
}

# ------------------------------------------------------------------------------
# Git server preflight (H4/H8): deploy only onto an existing, Terraform-built service
# whose repo storage is the GCS FUSE volume. A --source deploy onto a volume-less service
# would put /data/git on the in-memory FS and lose every repo on scale-to-zero.
# Returns: 0 = ok to deploy, 2 = service does not exist, 1 = exists but unsafe.
# ------------------------------------------------------------------------------
git_server_preflight() {
    local svc_json rc
    svc_json="$(gcloud run services describe castor-git-server --region="${REGION}" --project="${PROJECT_ID}" --format=json 2>/dev/null)"
    rc=$?
    if [ ${rc} -ne 0 ] || [ -z "${svc_json}" ]; then
        return 2
    fi
    printf '%s' "${svc_json}" | python3 -c '
import json, sys
bucket = "castor-git-repos-" + sys.argv[1]
try:
    t = json.load(sys.stdin)["spec"]["template"]
except Exception:
    print("cannot parse service description", file=sys.stderr); sys.exit(1)
ann = (t.get("metadata") or {}).get("annotations") or {}
spec = t.get("spec") or {}
vols = [v for v in spec.get("volumes") or [] if v.get("name") == "git-storage"]
csi = (vols[0].get("csi") or {}) if vols else {}
mounts = [m for c in spec.get("containers") or [] for m in (c.get("volumeMounts") or [])
          if m.get("name") == "git-storage" and m.get("mountPath") == "/data/git"]
problems = []
if ann.get("run.googleapis.com/execution-environment") != "gen2":
    problems.append("execution environment is not gen2")
if not vols or csi.get("driver") != "gcsfuse.run.googleapis.com" or (csi.get("volumeAttributes") or {}).get("bucketName") != bucket:
    problems.append("no git-storage GCS volume on bucket " + bucket)
if not mounts:
    problems.append("git-storage is not mounted at /data/git")
if problems:
    print("; ".join(problems), file=sys.stderr); sys.exit(1)
' "${PROJECT_ID}"
}

# ------------------------------------------------------------------------------
# Follower job image sync: a Cloud Run Job that runs a service's image gets that service's deployed image.
#   tf-applier   <- mcp-terraform-server          (FD28-02)
#   stage-runner <- orchestrator-gateway-service  (STAGE-JOB-RUNNER: the gateway starts one execution per stage; the
#                   job refuses a release that is not the gateway's, so a skipped sync fails stages typed, never silently)
# Command/args/env/retries are Terraform-owned; only the image changes. Fails loudly.
# ------------------------------------------------------------------------------
sync_job_image() {
    local job="$1" svc="$2" deployed_img
    echo -e "  ${CYAN}•${RESET} Synchronizing the ${svc} image to the ${BOLD}${job}${RESET} Cloud Run Job..."
    deployed_img="$(gcloud run services describe "${svc}" --region="${REGION}" --project="${PROJECT_ID}" --format="value(spec.template.spec.containers[0].image)" --quiet)" || deployed_img=""
    if [ -z "${deployed_img}" ]; then
        echo -e "  ${RED}[FAILED]${RESET} Could not read the ${svc} image; ${job} NOT updated."
        return 1
    fi
    if ! gcloud run jobs update "${job}" \
            --image="${deployed_img}" \
            --region="${REGION}" \
            --project="${PROJECT_ID}" \
            --quiet; then
        echo -e "  ${RED}[FAILED]${RESET} ${job} update failed; it still runs the previous image."
        return 1
    fi
    echo -e "  ${GREEN}✓${RESET} ${job} now runs ${deployed_img}\n"
}

sync_tf_applier() {
    sync_job_image "${SV_TF_APPLIER_JOB}" "${SV_TF_APPLIER_FOLLOWS}"
}

# STAGE-JOB-RUNNER: the job is created by `scripts/apply.sh apply` (infra/platform/stage_runner.tf) WITH the gateway's
# image of that moment. A gateway deploy before that apply finds no job: nothing to sync (said loudly, not a failure;
# the apply then creates the job with this gateway image). A failed listing is a failure.
STAGE_RUNNER_SYNCED=false
# The image of the gateway revision that serves 100% of the traffic (one revision; a split is refused loudly).
sync_stage_runner_to_serving() {
    local svc_json rev img
    echo -e "  ${CYAN}•${RESET} Pointing the ${BOLD}${SV_STAGE_RUNNER_JOB}${RESET} job at the image ${SV_STAGE_RUNNER_FOLLOWS} serves now..."
    svc_json="$(gcloud run services describe "${SV_STAGE_RUNNER_FOLLOWS}" --region="${REGION}" --project="${PROJECT_ID}" --format=json --quiet)" || svc_json=""
    rev="$(printf '%s' "${svc_json}" | python3 -c '
import json, sys
try:
    st = json.load(sys.stdin).get("status") or {}
except Exception:
    print("cannot parse the service description", file=sys.stderr); sys.exit(1)
live = [t for t in st.get("traffic") or [] if (t.get("percent") or 0) > 0]
if len(live) != 1 or live[0].get("percent") != 100:
    print("traffic is split or unknown: %r" % live, file=sys.stderr); sys.exit(1)
name = live[0].get("revisionName") or (st.get("latestReadyRevisionName") if live[0].get("latestRevision") else "")
if not name:
    print("no serving revision name", file=sys.stderr); sys.exit(1)
print(name)
')" || { echo -e "  ${RED}[FAILED]${RESET} Could not tell which ${SV_STAGE_RUNNER_FOLLOWS} revision serves; ${SV_STAGE_RUNNER_JOB} NOT updated."; return 1; }
    img="$(gcloud run revisions describe "${rev}" --region="${REGION}" --project="${PROJECT_ID}" --format="value(spec.containers[0].image)" --quiet)" || img=""
    if [ -z "${img}" ]; then
        echo -e "  ${RED}[FAILED]${RESET} Could not read the image of revision ${rev}; ${SV_STAGE_RUNNER_JOB} NOT updated."
        return 1
    fi
    if ! gcloud run jobs update "${SV_STAGE_RUNNER_JOB}" --image="${img}" --region="${REGION}" --project="${PROJECT_ID}" --quiet; then
        echo -e "  ${RED}[FAILED]${RESET} ${SV_STAGE_RUNNER_JOB} update failed; it still runs the previous image."
        return 1
    fi
    echo -e "  ${GREEN}✓${RESET} ${SV_STAGE_RUNNER_JOB} now runs ${img} (the image of serving revision ${rev})\n"
}

sync_stage_runner() {
    local present
    STAGE_RUNNER_SYNCED=false
    present="$(gcloud run jobs list --region="${REGION}" --project="${PROJECT_ID}" --filter="metadata.name=${SV_STAGE_RUNNER_JOB}" --format="value(metadata.name)" --quiet)" || {
        echo -e "  ${RED}[FAILED]${RESET} Could not list Cloud Run jobs; ${SV_STAGE_RUNNER_JOB} NOT updated."
        return 1
    }
    if [ -z "${present}" ]; then
        echo -e "  ${YELLOW}[WARNING]${RESET} The ${BOLD}${SV_STAGE_RUNNER_JOB}${RESET} job does not exist yet: nothing to sync. The next PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply creates it with this gateway image."
        return 0
    fi
    sync_job_image "${SV_STAGE_RUNNER_JOB}" "${SV_STAGE_RUNNER_FOLLOWS}" || return 1
    STAGE_RUNNER_SYNCED=true
}

# stage_helm (pinned, SHA-256-checked Helm for mcp-kubernetes-server) and sync_cc_modules (the CC's module copy):
# scripts/common/components.sh.

# ------------------------------------------------------------------------------
# Single-component deploy. Returns non-zero on any failure (safe inside `if`).
# ------------------------------------------------------------------------------
deploy_single() {
    local name="$1"
    local dir="$2"
    local type="$3" # "service" or "job"
    local start_time end_time pre_rc

    if [ ! -d "$dir" ]; then
        echo -e "${RED}[ERROR]${RESET} Directory ${dir} not found!"
        return 1
    fi

    if [ "$name" == "castor-git-server" ]; then
        set +e
        git_server_preflight
        pre_rc=$?
        set -e
        if [ ${pre_rc} -eq 2 ]; then
            echo -e "${RED}[ERROR]${RESET} castor-git-server does not exist in ${PROJECT_ID}. Create it with Terraform first: PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply, then re-run: PROJECT_ID=${PROJECT_ID} REGION=${REGION} bash scripts/deploy-services.sh castor-git-server"
            return 1
        elif [ ${pre_rc} -ne 0 ]; then
            echo -e "${RED}[ERROR]${RESET} castor-git-server is not on its GCS FUSE volume (see above). Deploying code now could lose repos. Run PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply first, then re-run: PROJECT_ID=${PROJECT_ID} REGION=${REGION} bash scripts/deploy-services.sh castor-git-server"
            return 1
        fi
    fi

    sv_component_prebuild "${name}" "${dir}" || return 1

    echo -e "${CYAN}==>${RESET} Building and deploying ${BOLD}${name}${RESET} from ${BOLD}${dir}${RESET}..."
    start_time=$(date +%s)

    if [ "$type" == "job" ]; then
        gcloud run jobs deploy "${name}" \
            --source "${dir}" \
            --region "${REGION}" \
            --project "${PROJECT_ID}" \
            --quiet || return 1
        job_label_after_deploy "${name}" || return 1
    elif [ "$name" == "castor-git-server" ]; then
        # FD-4K: Cloud Run IAM stays on for the git server (lane 3); callers send ID tokens.
        # Single and sequential-retry paths both come through here.
        gcloud run deploy "${name}" \
            --source "${dir}" \
            --region "${REGION}" \
            --project "${PROJECT_ID}" \
            --no-allow-unauthenticated \
            --quiet || return 1
    else
        gcloud run deploy "${name}" \
            --source "${dir}" \
            --region "${REGION}" \
            --project "${PROJECT_ID}" \
            --quiet || return 1
    fi

    end_time=$(date +%s)
    echo -e "${GREEN}[OK]${RESET} Successfully deployed ${BOLD}${name}${RESET} in $((end_time - start_time))s!\n"

    if [ "${name}" == "mcp-terraform-server" ]; then
        sync_tf_applier || return 1
    fi
    if [ "${name}" == "${SV_STAGE_RUNNER_FOLLOWS}" ]; then
        sync_stage_runner || return 1
    fi
}

# ------------------------------------------------------------------------------
# Single-target mode
# ------------------------------------------------------------------------------
MATCH_NAME=""
MATCH_DIR=""
MATCH_TYPE=""
for entry in "${SERVICES[@]}"; do
    svc="${entry%%:*}"; dir="${entry#*:}"
    if [ "$TARGET" == "$svc" ] || [ "$TARGET" == "$(basename "$dir")" ]; then
        MATCH_NAME="$svc"; MATCH_DIR="$dir"; MATCH_TYPE="service"
    fi
done
if [ -z "$MATCH_NAME" ]; then
    for entry in "${JOBS[@]}"; do
        job="${entry%%:*}"; dir="${entry#*:}"
        if [ "$TARGET" == "$job" ] || [ "$TARGET" == "$(basename "$dir")" ]; then
            MATCH_NAME="$job"; MATCH_DIR="$dir"; MATCH_TYPE="job"
        fi
    done
fi
if [ -z "$MATCH_NAME" ] && { [ "$TARGET" == "tf-applier" ] || [ "$TARGET" == "applier" ]; }; then
    MATCH_NAME="mcp-terraform-server"; MATCH_DIR="mcp-servers/terraform"; MATCH_TYPE="service"
fi
# STAGE-JOB-RUNNER (red team N2 / N3): `stage-runner` builds nothing. It points the job at the image the gateway
# SERVES now (after a traffic rollback that is not the newest revision), so a gateway rollback never leaves every
# stage refused STAGE_RUNNER_IMAGE_SKEW; it is also the post-apply check that the job runs the gateway's image.
if [ -z "$MATCH_NAME" ] && [ "$TARGET" == "${SV_STAGE_RUNNER_JOB}" ]; then
    sync_stage_runner_to_serving || sv_die "${SV_STAGE_RUNNER_JOB} was NOT synchronized (see above)."
    RELEASE_RECORDED+=("${SV_STAGE_RUNNER_JOB}")
    release_prepare
    release_record_write false
    exit 0
fi

if [ -n "$MATCH_NAME" ]; then
    release_prepare
    release_place "$MATCH_DIR"
    deploy_single "$MATCH_NAME" "$MATCH_DIR" "$MATCH_TYPE" || sv_die "Deployment of ${MATCH_NAME} failed."
    RELEASE_RECORDED+=("$MATCH_NAME")
    if [ "$MATCH_NAME" == "mcp-terraform-server" ]; then RELEASE_RECORDED+=("tf-applier"); fi
    if [ "$STAGE_RUNNER_SYNCED" = true ]; then RELEASE_RECORDED+=("${SV_STAGE_RUNNER_JOB}"); fi
    release_record_write false
    if [ "$MATCH_NAME" == "product-control-center-ui" ]; then
        UI_URL=$(gcloud run services describe product-control-center-ui --region="${REGION}" --project="${PROJECT_ID}" --format="value(status.url)" --quiet 2>/dev/null || echo "")
        if [ -n "$UI_URL" ]; then
            echo -e "${GREEN}${BOLD}Control Center URL:${RESET} ${CYAN}${UI_URL}${RESET}\n"
        fi
    fi
    exit 0
fi
if [ "$TARGET" != "all" ]; then
    sv_die "Unknown service or job '${TARGET}'."
fi

# ------------------------------------------------------------------------------
# Parallel Bulk Deployment Mode
# ------------------------------------------------------------------------------
echo -e "${YELLOW}Starting parallel source builds via Google Cloud Buildpacks...${RESET}"
PARALLEL_LIMIT=${PARALLEL_LIMIT:-3}
LOG_DIR="$(mktemp -d)"

BUILD_ITEMS=()
BUILD_PIDS=()
BUILD_DIRS=()
BUILD_TYPES=()
SKIPPED_ITEMS=()

release_prepare
sync_cc_modules
stage_helm "mcp-servers/kubernetes" || sv_die "Helm staging for mcp-kubernetes-server failed (see above)."

ALL_ENTRIES=()
# GIT-404-TYPED: the git server first (whatever its place in SERVICES), deployed alone below before any client starts.
for entry in "${SERVICES[@]}"; do [ "${entry%%:*}" != "${SV_GIT_SERVER}" ] || ALL_ENTRIES+=("service|${entry}"); done
for entry in "${SERVICES[@]}"; do [ "${entry%%:*}" == "${SV_GIT_SERVER}" ] || ALL_ENTRIES+=("service|${entry}"); done
if [ "$INCLUDE_JOBS" = true ]; then
    for entry in "${JOBS[@]}"; do ALL_ENTRIES+=("job|${entry}"); done
fi
for item_entry in "${ALL_ENTRIES[@]}"; do
    entry="${item_entry#*|}"
    release_place "${entry#*:}"
done
echo -e "Deploying ${BOLD}${#ALL_ENTRIES[@]} components${RESET} (concurrency limit: ${BOLD}${PARALLEL_LIMIT}${RESET}). Logs: ${BOLD}${LOG_DIR}${RESET}\n"

for item_entry in "${ALL_ENTRIES[@]}"; do
    type="${item_entry%%|*}"
    entry="${item_entry#*|}"
    item="${entry%%:*}"
    dir="${entry#*:}"

    if [ "$item" == "castor-git-server" ]; then
        set +e
        git_server_preflight 2>"${LOG_DIR}/${item}.preflight"
        pre_rc=$?
        set -e
        if [ ${pre_rc} -eq 2 ]; then
            echo -e "  ${YELLOW}•${RESET} Skipping ${BOLD}${item}${RESET}: the service does not exist in ${PROJECT_ID} (git server not enabled)."
            SKIPPED_ITEMS+=("$item")
            continue
        elif [ ${pre_rc} -ne 0 ]; then
            echo -e "  ${RED}[FAILED]${RESET} ${BOLD}${item}${RESET}: not on its GCS FUSE volume ($(cat "${LOG_DIR}/${item}.preflight")). Run PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply first, then re-run: PROJECT_ID=${PROJECT_ID} REGION=${REGION} bash scripts/deploy-services.sh castor-git-server"
            BUILD_ITEMS+=("$item"); BUILD_PIDS+=(""); BUILD_DIRS+=("$dir"); BUILD_TYPES+=("preflight")
            continue
        fi
        # GIT-404-TYPED: deployed synchronously, alone, before any client build is submitted (its clients read a 404
        # without its header as "unreachable", so they must never run against the old server). One sequential retry;
        # if it still fails, nothing else is deployed.
        echo -e "  ${BLUE}•${RESET} Deploying ${BOLD}${item}${RESET} (${dir}) first, before its clients..."
        set +e
        gcloud run deploy "${item}" --source "${dir}" --region "${REGION}" --project "${PROJECT_ID}" --no-allow-unauthenticated --quiet > "${LOG_DIR}/${item}.log" 2>&1
        rc=$?
        if [ ${rc} -ne 0 ]; then
            echo -e "  ${YELLOW}[RETRY]${RESET} ${BOLD}${item}${RESET} failed (exit ${rc}; log: ${LOG_DIR}/${item}.log). Retrying once before any client is deployed."
            rc=0   # deploy_single turns `set -e` back on (its preflight): keep its status in an || list
            deploy_single "${item}" "${dir}" "${type}" >> "${LOG_DIR}/${item}.log" 2>&1 || rc=$?
        fi
        set -e
        if [ ${rc} -ne 0 ]; then
            sv_die "${item} failed to deploy (log: ${LOG_DIR}/${item}.log). Nothing else was deployed: the other services must not run against the old git server (row GIT-404-TYPED). Fix it and re-run: PROJECT_ID=${PROJECT_ID} REGION=${REGION} bash scripts/deploy-services.sh"
        fi
        BUILD_ITEMS+=("$item"); BUILD_PIDS+=(""); BUILD_DIRS+=("$dir"); BUILD_TYPES+=("deployed")
        continue
    fi

    # Throttle concurrency to stay within Google Cloud Build and Cloud Run API quotas
    while [ "$(jobs -r | wc -l)" -ge "${PARALLEL_LIMIT}" ]; do
        sleep 2
    done
    echo -e "  ${BLUE}•${RESET} Submitting build for ${type} ${BOLD}${item}${RESET} (${dir})..."
    if [ "$type" == "job" ]; then
        gcloud run jobs deploy "${item}" --source "${dir}" --region "${REGION}" --project "${PROJECT_ID}" --quiet > "${LOG_DIR}/${item}.log" 2>&1 &
    else
        gcloud run deploy "${item}" --source "${dir}" --region "${REGION}" --project "${PROJECT_ID}" --quiet > "${LOG_DIR}/${item}.log" 2>&1 &
    fi
    BUILD_ITEMS+=("$item"); BUILD_PIDS+=("$!"); BUILD_DIRS+=("$dir"); BUILD_TYPES+=("$type")
done

echo -e "\n${CYAN}==>${RESET} All builds submitted! Waiting for compilation and rollout to complete...\n"

FAILURES=0
SUCCESSES=0
TF_SERVER_OK=false
GATEWAY_OK=false
FAILED_ITEMS=()
FAILED_DIRS=()
FAILED_TYPES=()

for i in "${!BUILD_ITEMS[@]}"; do
    item="${BUILD_ITEMS[$i]}"
    pid="${BUILD_PIDS[$i]}"
    if [ "${BUILD_TYPES[$i]}" == "preflight" ]; then
        FAILURES=$((FAILURES + 1))
        continue
    fi
    set +e
    if [ "${BUILD_TYPES[$i]}" == "deployed" ]; then
        rc=0   # the git server, deployed synchronously before the parallel builds (a failure stopped the run there)
    else
        wait "$pid"
        rc=$?
    fi
    set -e
    if [ ${rc} -eq 0 ] && [ "${BUILD_TYPES[$i]}" == "job" ]; then
        set +e
        job_label_after_deploy "${item}" >> "${LOG_DIR}/${item}.log" 2>&1
        rc=$?
        set -e
    fi
    if [ ${rc} -eq 0 ]; then
        echo -e "  ${GREEN}[OK]${RESET} ${BOLD}${item}${RESET} deployed successfully."
        SUCCESSES=$((SUCCESSES + 1))
        RELEASE_RECORDED+=("$item")
        if [ "$item" == "mcp-terraform-server" ]; then TF_SERVER_OK=true; fi
        if [ "$item" == "${SV_STAGE_RUNNER_FOLLOWS}" ]; then GATEWAY_OK=true; fi
    else
        echo -e "  ${YELLOW}[RETRY-PENDING]${RESET} ${BOLD}${item}${RESET} failed (exit ${rc}; log: ${LOG_DIR}/${item}.log). Will retry sequentially."
        FAILED_ITEMS+=("$item"); FAILED_DIRS+=("${BUILD_DIRS[$i]}"); FAILED_TYPES+=("${BUILD_TYPES[$i]}")
    fi
done

# tf-applier follows mcp-terraform-server (bulk path; FD28-02). A sync failure is a failure.
if [ "$TF_SERVER_OK" = true ]; then
    if sync_tf_applier; then
        RELEASE_RECORDED+=("tf-applier")
    else
        FAILURES=$((FAILURES + 1))
    fi
fi

# stage-runner follows orchestrator-gateway-service (bulk path; STAGE-JOB-RUNNER). A sync failure is a failure.
if [ "$GATEWAY_OK" = true ]; then
    if sync_stage_runner; then
        if [ "$STAGE_RUNNER_SYNCED" = true ]; then RELEASE_RECORDED+=("${SV_STAGE_RUNNER_JOB}"); fi
    else
        FAILURES=$((FAILURES + 1))
    fi
fi

# Sequential retry: rebuild from source only (never guess a previously pushed image).
# deploy_single also syncs tf-applier / stage-runner when mcp-terraform-server / the gateway succeeds on retry.
for j in "${!FAILED_ITEMS[@]}"; do
    retry_item="${FAILED_ITEMS[$j]}"
    echo -e "  ${CYAN}•${RESET} Retrying deployment of ${BOLD}${retry_item}${RESET} (sequential source build)..."
    if deploy_single "${retry_item}" "${FAILED_DIRS[$j]}" "${FAILED_TYPES[$j]}"; then
        echo -e "    ${GREEN}[OK]${RESET} ${BOLD}${retry_item}${RESET} successfully deployed on retry."
        SUCCESSES=$((SUCCESSES + 1))
        RELEASE_RECORDED+=("$retry_item")
        if [ "$retry_item" == "mcp-terraform-server" ]; then RELEASE_RECORDED+=("tf-applier"); fi
        if [ "$retry_item" == "${SV_STAGE_RUNNER_FOLLOWS}" ] && [ "$STAGE_RUNNER_SYNCED" = true ]; then
            RELEASE_RECORDED+=("${SV_STAGE_RUNNER_JOB}")
        fi
    else
        echo -e "    ${RED}[FAILED]${RESET} ${BOLD}${retry_item}${RESET} retry failed."
        FAILURES=$((FAILURES + 1))
    fi
done

# Version record: once, after every build (a full run = all services and jobs, nothing failed).
if [ "$INCLUDE_JOBS" = true ] && [ "$FAILURES" -eq 0 ]; then release_record_write true; else release_record_write false; fi

echo -e "\n${BLUE}${BOLD}==============================================================================${RESET}"
echo -e "  Deployment Summary: ${GREEN}${SUCCESSES} succeeded${RESET}, ${RED}${FAILURES} failed${RESET}, ${#SKIPPED_ITEMS[@]} skipped"
echo -e "${BLUE}${BOLD}==============================================================================${RESET}\n"
if [ -n "${STACKVEND_DEPLOY_SUMMARY_FILE:-}" ]; then
    printf '%s %s %s\n' "${SUCCESSES}" "${FAILURES}" "${#SKIPPED_ITEMS[@]}" > "${STACKVEND_DEPLOY_SUMMARY_FILE}" || true
fi

UI_URL=$(gcloud run services describe product-control-center-ui --region="${REGION}" --project="${PROJECT_ID}" --format="value(status.url)" --quiet 2>/dev/null || echo "")
if [ -n "$UI_URL" ]; then
    echo -e "${GREEN}${BOLD}StackVend Control Center is live at:${RESET}"
    echo -e "${CYAN}${BOLD}  ${UI_URL}${RESET}\n"
fi

if [ "$FAILURES" -gt 0 ]; then
    exit 1
fi
