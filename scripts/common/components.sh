# shellcheck shell=bash
# ==============================================================================
# STACKVEND: THE PLATFORM COMPONENTS (one list, two deployers)
# ==============================================================================
# Sourced by scripts/deploy-services.sh (operator path, `gcloud run deploy --source`) and by the upgrader's stage
# scripts in scripts/upgrade/ (the "Update StackVend" button's Cloud Build, `pack build` + image-only updates;
# plan docs/planning/self-upgrade-plan.md §3.6). Definitions only: sourcing it runs nothing.
#
# Parity (tests/test_selfup_b2_components.py): SERVICES + JOBS (+ tf-applier, stage-runner) == COMPONENTS in
# shared/release_manifest.py == the upgrader guard's list (scripts/upgrade/guard.py). deploy-services.sh's commands
# are pinned byte for byte against the pre-refactor script (tests/fixtures/selfup_b2/deploy_services_commands.json).
#
# The functions use REPO_ROOT (the checkout being deployed), set by the caller. Bash 3.2 compatible.
# ==============================================================================

# Service & Job Mappings (Cloud Run name:source directory relative to REPO_ROOT)
# The Serverless Git server is FIRST (row GIT-404-TYPED): its clients read a 404 without its X-StackVend-Git-Server
# header as "git server unreachable", so it must run its new code before any client does. deploy-services.sh deploys
# it alone, before the parallel builds; the upgrader's deploy.sh puts it first explicitly.
SERVICES=(
    "castor-git-server:apps/git-server"
    "product-control-center-ui:apps/control-center"
    "orchestrator-gateway-service:apps/orchestrator-gateway"
    "project-repo-vending-service:apps/project-vending"
    "log-sre-sentinel-service:apps/log-sre-sentinel"
    "spec-ingestion-service:apps/spec-ingestion"
    "mcp-terraform-server:mcp-servers/terraform"
    "mcp-gcloud-server:mcp-servers/gcloud"
    "mcp-github-toolserver:mcp-servers/github"
    "mcp-workspace-connector:mcp-servers/workspace"
    "mcp-infracost-server:mcp-servers/infracost"
    "mcp-compliance-server:mcp-servers/compliance"
    "mcp-kubernetes-server:mcp-servers/kubernetes"
    "mcp-agent-builder-server:mcp-servers/agent-builder"
)

JOBS=(
    "github-refactor-scanner-job:apps/refactor-scanner"
    "qa-sandbox-test-runner:apps/qa-runner"
    "finops-budget-enforcer-job:apps/finops-enforcer"
    "infra-rollback-job:apps/infra-rollback"
    "sandbox-garbage-collector-job:apps/sandbox-cleaner"
    "sre-telemetry-digest-job:apps/sre-digest"
    "finops-spend-sync-job:apps/finops-spend-sync"
    "sandbox-workload-sweeper-job:apps/sandbox-sweeper"
    "billing-alert-drain-job:apps/billing-alert-drain"
)

# Recipes (per-component special cases; the same facts for both deployers)
# - tf-applier is a Cloud Run Job that runs the mcp-terraform-server image (FD28-02): it is never built on its own,
#   it follows that service's image.
SV_TF_APPLIER_JOB="tf-applier"
SV_TF_APPLIER_FOLLOWS="mcp-terraform-server"
# - stage-runner is a Cloud Run Job that runs the orchestrator-gateway image (STAGE-JOB-RUNNER, owner 11-13): one
#   execution per architect / developer / QA stage. Never built on its own; it follows the gateway's image (the job
#   refuses to run a stage when its release is not the gateway's: STAGE_RUNNER_IMAGE_SKEW).
SV_STAGE_RUNNER_JOB="stage-runner"
SV_STAGE_RUNNER_FOLLOWS="orchestrator-gateway-service"
# - The Control Center is deployed last by the upgrader (the admin keeps a working page until the end).
SV_CONTROL_CENTER="product-control-center-ui"
# - The Serverless Git server keeps Cloud Run IAM on (FD-4K). deploy-services.sh passes --no-allow-unauthenticated
#   (it never makes anything public); the upgrader sends image-only updates and never touches IAM.
SV_GIT_SERVER="castor-git-server"
# - Row L3-PRB-r: the QA sandbox job carries its contract label, set in the SAME deploy that ships the image. The
#   gateway's GET /agent/qa/readiness refuses a job without it. Must equal apps/qa-runner/sandbox_job.JOB_CONTRACT_VERSION
#   (pinned by tests/test_lane3_prb_rad.py).
SV_QA_JOB="qa-sandbox-test-runner"
QA_JOB_CONTRACT_LABEL="stackvend-qa-job-contract=1"

# sv_component_labels <name>: the labels a deploy of <name> sets together with its image (empty for most).
sv_component_labels() {
    if [ "$1" == "${SV_QA_JOB}" ]; then
        printf '%s\n' "${QA_JOB_CONTRACT_LABEL}"
    fi
    return 0
}

# sv_component_prebuild <name> <dir>: what must be staged into the source tree before <name> is built.
sv_component_prebuild() {
    if [ "$1" == "${SV_CONTROL_CENTER}" ]; then
        sync_cc_modules || return 1
    fi
    if [ "$1" == "mcp-kubernetes-server" ]; then
        stage_helm "$2" || return 1
    fi
    return 0
}

stage_helm() {
    # Lane 14 PR-8 / I10 (deploy staging, L12-5): bake the pinned Helm CLI into mcp-kubernetes-server's source dir
    # as bin/helm (Procfile puts /workspace/bin first on PATH). Pin = mcp-servers/kubernetes/helm-pin.json (the
    # same file the Cloud Build trigger step reads). The tarball's SHA-256 must match the pin or nothing is staged
    # and the deploy stops. An empty pin stages nothing: the server then reports HELM_UNAVAILABLE (never a mock).
    local dir="$1" pin version sha tmp actual
    pin="${dir}/helm-pin.json"
    if [ ! -f "${pin}" ]; then
        echo -e "  ${YELLOW}•${RESET} ${pin} not found: mcp-kubernetes-server ships without Helm (Helm tools answer HELM_UNAVAILABLE)."
        return 0
    fi
    version="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("version",""))' "${pin}")" || return 1
    sha="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("linux_amd64_sha256",""))' "${pin}")" || return 1
    if [ -z "${version}" ] && [ -z "${sha}" ]; then
        echo -e "  ${YELLOW}•${RESET} helm-pin.json is empty: mcp-kubernetes-server ships without Helm (Helm tools answer HELM_UNAVAILABLE)."
        rm -f "${dir}/bin/helm"
        return 0
    fi
    if [ -z "${version}" ] || [ -z "${sha}" ]; then
        echo -e "${RED}[ERROR]${RESET} helm-pin.json must set both version and linux_amd64_sha256."
        return 1
    fi
    # RT F19: the server uses `--dry-run=server`, which needs Helm v3.13.0 or later (same rule as the TF validation).
    if ! python3 -c 'import sys; p = sys.argv[1][1:].split(".") if sys.argv[1].startswith("v") else []; sys.exit(0 if len(p) == 3 and all(x.isdigit() for x in p) and int(p[0]) == 3 and int(p[1]) >= 13 else 1)' "${version}"; then
        echo -e "${RED}[ERROR]${RESET} helm-pin.json version ${version} must be v3.X.Y with X >= 13 (--dry-run=server)."
        return 1
    fi
    tmp="$(mktemp -d)" || return 1
    curl -fsSL -o "${tmp}/helm.tgz" "https://get.helm.sh/helm-${version}-linux-amd64.tar.gz" || { rm -rf "${tmp}"; return 1; }
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "${tmp}/helm.tgz" | cut -d' ' -f1)"
    else
        actual="$(shasum -a 256 "${tmp}/helm.tgz" | cut -d' ' -f1)"
    fi
    if [ "${actual}" != "${sha}" ]; then
        echo -e "${RED}[ERROR]${RESET} Helm ${version} tarball SHA-256 ${actual} does not match the pin ${sha}; nothing staged."
        rm -rf "${tmp}"
        return 1
    fi
    tar -xzf "${tmp}/helm.tgz" -C "${tmp}" linux-amd64/helm || { rm -rf "${tmp}"; return 1; }
    mkdir -p "${dir}/bin" && install -m 0755 "${tmp}/linux-amd64/helm" "${dir}/bin/helm" || { rm -rf "${tmp}"; return 1; }
    rm -rf "${tmp}"
    echo -e "  ${GREEN}✓${RESET} staged Helm ${version} (SHA-256 verified) into ${dir}/bin/helm"
}

sync_cc_modules() {
    # Chained with && so a failure is returned even when called from `if`/`||` (set -e is off there).
    mkdir -p "${REPO_ROOT}/apps/control-center/infra" \
        && rm -rf "${REPO_ROOT}/apps/control-center/infra/modules" \
        && cp -r "${REPO_ROOT}/infra/modules" "${REPO_ROOT}/apps/control-center/infra/modules" \
        && cp "${REPO_ROOT}/shared/builtin_modules_payload.py" "${REPO_ROOT}/apps/control-center/shared/builtin_modules_payload.py"
}
