#!/usr/bin/env bash
# ==============================================================================
# STACKVEND: SINGLE-PASS PLATFORM BOOTSTRAP INSTALLER
# ==============================================================================
# Automates the deployment of StackVend into any Google Cloud project.
# Pre-enables base APIs, guides/discovers Cloud Build 2nd-Gen GitHub connection,
# generates infra/platform/<project_id>.tfvars, and executes a single OpenTofu/Terraform apply
# through the same gate as scripts/apply.sh (plan -> deletes/replaces refused -> typed project id).
# Flags: --ipv4-fix (force the Linux IPv4 fix; automatic when CLOUD_SHELL=true; register row 17)
#        --overwrite-tfvars (an existing infra/platform/<project_id>.tfvars is refused without it;
#                            with it, a timestamped backup <project_id>.tfvars.bak-<UTC> is written first)
# At the end, the vars file is copied to gs://castor-tfstate-<project_id>/platform/<project_id>.tfvars (TFVARS-AUTO-BACKUP).
# Existing installs: use `PROJECT_ID=<id> bash scripts/apply.sh plan|apply`, not this script.
# ==============================================================================

set -e

BOLD="\033[1m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
CYAN="\033[0;36m"   # RC F10: used by the stage 2 banner (was undefined)
RESET="\033[0m"

echo -e "${BLUE}${BOLD}"
cat << 'EOF'
  ____  _             _     __     __             _ 
 / ___|| |_ __ _  ___| | __ \ \   / /__ _ __   __| |
 \___ \| __/ _` |/ __| |/ /  \ \ / / _ \ '_ \ / _` |
  ___) | || (_| | (__|   <    \ V /  __/ | | | (_| |
 |____/ \__\__,_|\___|_|\_\    \_/ \___|_| |_|\__,_|
EOF
echo -e "${RESET}"
echo -e "${BOLD}StackVend: Full Stack IaC and Software Vending Engine${RESET}"
echo -e "Single-Pass Platform Bootstrap Installer\n"

# ------------------------------------------------------------------------------
# 1. Prerequisite Checks & Network Fixes
# ------------------------------------------------------------------------------
echo -e "${BLUE}==>${RESET} Checking environment prerequisites and network routing..."

# FD-4AP + register row 17 (owner 10-12): the Cloud Shell IPv4 fix (gai.conf, IPv6 sysctl,
# GODEBUG=netdns=cgo, /etc/hosts pins inside the '# BEGIN/END stackvend-ipv4' block) runs
# automatically when CLOUD_SHELL=true, or with --ipv4-fix (Linux). Elsewhere only GODEBUG is set.
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
IPV4_FIX=""
OVERWRITE_TFVARS=""
for arg in "$@"; do
    case "${arg}" in
        --ipv4-fix) IPV4_FIX=1 ;;
        --overwrite-tfvars) OVERWRITE_TFVARS=1 ;;
        *) echo -e "${RED}[ERROR]${RESET} Unknown argument: ${arg}"; exit 1 ;;
    esac
done
# H1 + red team F1: refuse tofu back-channel env vars before anything runs.
sv_scrub_tofu_env
sv_network_setup "${IPV4_FIX}"

if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}[ERROR]${RESET} 'gcloud' CLI is not installed or not in PATH."
    echo "Please install Google Cloud SDK: https://cloud.google.com/sdk/docs/install"
    exit 1
fi
# RC F6: python3 and curl are used throughout the install (tfvars reads, plan gate, preflights, Firestore seeds).
for SV_PREREQ in python3 curl; do
    if ! command -v "${SV_PREREQ}" &> /dev/null; then
        echo -e "${RED}[ERROR]${RESET} '${SV_PREREQ}' is not installed or not in PATH. The installer needs python3 and curl; install them and re-run."
        exit 1
    fi
done

# INSTALLER-OPENTOFU-OFFER: OpenTofu missing or older than SV_IAC_MIN_VERSION -> offer to install it into ~/bin
# (a terminal only; otherwise a typed stop with the manual commands). Silent when the engine is usable.
SV_TOFU_TTY=""
if [ -t 0 ]; then SV_TOFU_TTY=1; fi
sv_ensure_opentofu BOOTSTRAP "${SV_TOFU_TTY}"

if command -v tofu &> /dev/null && tofu version 2>&1 | grep -qi "OpenTofu v"; then
    IAC_BIN="tofu"
    echo -e "${GREEN}[OK]${RESET} OpenTofu version: $(tofu version | head -n 1)"
elif command -v terraform &> /dev/null && terraform version 2>&1 | grep -qi "Terraform v"; then
    IAC_BIN="terraform"
    echo -e "${GREEN}[OK]${RESET} Terraform version: $(terraform version | head -n 1)"
else
    echo -e "\n${RED}${BOLD}[ERROR] Neither 'tofu' (OpenTofu) nor 'terraform' (HashiCorp Terraform) is installed.${RESET}\n"
    if command -v terraform &> /dev/null; then
        echo -e "Cloud Shell / System Terraform placeholder detected. Invoking native helper:\n"
        terraform || true
        echo -e "\n${RED}[ERROR]${RESET} Please complete Terraform installation using the instructions above, then re-run bootstrap.\n"
    else
        echo -e "Please install OpenTofu ${SV_IAC_MIN_VERSION} or later: https://opentofu.org/docs/intro/install/\n"
    fi
    exit 1
fi
# RC B1: infra/platform needs OpenTofu >= SV_IAC_MIN_VERSION (scripts/common/platform_target.sh). Checked here, before
# any prompt or GCP call, so an old engine (e.g. Cloud Shell's Terraform 1.5.x, OpenTofu 1.9) stops with a clear
# message instead of a parse error at init.
sv_require_iac_version
echo -e "${BLUE}ℹ️${RESET}  Permissions needed: see documentation/quickstart.md \"Minimum permissions for the installer\"."

echo -e "${BLUE}==>${RESET} Verifying gcloud authentication and access token..."
if ! gcloud auth print-access-token >/dev/null 2>&1; then
    echo -e "\n${YELLOW}[WARNING]${RESET} No active OAuth token available for gcloud."
    echo -e "Attempting to authenticate..."
    gcloud auth login || true
    
    if ! gcloud auth print-access-token >/dev/null 2>&1; then
        echo -e "\n${RED}${BOLD}[ERROR] 'gcloud auth print-access-token' failed!${RESET}"
        echo -e "Please ensure you have an active account selected with:"
        echo -e "  gcloud auth login"
        echo -e "  gcloud config set account <your-email>\n"
        exit 1
    fi
fi
ACTIVE_ACCOUNT=$(gcloud config get-value account 2>/dev/null || gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null || true)
echo -e "${GREEN}[OK]${RESET} Authenticated as: ${BOLD}${ACTIVE_ACCOUNT}${RESET}"
echo -e "   This account becomes the first Control Center ADMIN and, behind Direct IAP (the default ingress), the only person"
echo -e "   IAP lets in. IAP admits only organization accounts (Google Workspace / Cloud Identity); a personal Gmail account is"
echo -e "   refused. Wrong account? Press Ctrl-C now (nothing has changed yet), run 'gcloud auth login <account>' and re-run."

# ------------------------------------------------------------------------------
# 2. Interactive Parameter Configuration
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}==>${RESET} Configuring core parameters..."

# BOOTSTRAP-PREFILL (owner 11-03): STACKVEND_PROJECT_ID, STACKVEND_ORG_ID, STACKVEND_BILLING_ACCOUNT_ID and
# STACKVEND_FOLDER_ID (scripts/pre-bootstrap.sh sets them when it starts this installer) are the defaults of the
# project, organization, billing account and folder prompts: shown in brackets, Enter accepts, typing overrides. The
# chosen value is checked exactly like typed input. Unset (or empty) = the usual defaults (project: the gcloud config
# project; the other three: none). Every prompt is still asked.
# Detect current project or prompt
CURRENT_PROJECT=$(gcloud config get-value project 2>/dev/null || true)
DEFAULT_PROJECT_ID="${STACKVEND_PROJECT_ID:-${CURRENT_PROJECT}}"
read -r -p "Enter Google Cloud Project ID for StackVend Platform [${DEFAULT_PROJECT_ID}]: " INPUT_PROJECT_ID
PROJECT_ID=${INPUT_PROJECT_ID:-$DEFAULT_PROJECT_ID}
if [ -z "$PROJECT_ID" ]; then
    echo -e "${RED}[ERROR]${RESET} Project ID is required."
    exit 1
fi
if ! sv_valid_project_id "$PROJECT_ID"; then
    echo -e "${RED}[ERROR]${RESET} '${PROJECT_ID}' is not a valid GCP project id."
    exit 1
fi
export CLOUDSDK_CORE_PROJECT="${PROJECT_ID}"

# Vars-file guards, checked before any GCP write (FD-07; red team F4; the existing-file case reads the state once).
TF_DIR="${PLATFORM_DIR}"
TFVARS_PATH="${TF_DIR}/${PROJECT_ID}.tfvars"
if [ -e "${TF_DIR}/terraform.tfvars" ]; then
    # BOOTSTRAP-EXISTING-TFVARS-SELF-CORRECT (owner 11-10): tofu auto-loads terraform.tfvars into every run, so it must
    # not stay. Instead of stopping, move it to where it belongs, read with the real HCL parser (sv_tfvar):
    #   its project_id is a valid id and <that id>.tfvars does not exist -> renamed to <that id>.tfvars (for this
    #       project, the existing-file check below then decides what happens to it);
    #   otherwise (unreadable, invalid, or the target exists) -> moved to a timestamped terraform.tfvars.bak-<UTC>.
    sv_tt_src="${TF_DIR}/terraform.tfvars"
    sv_tt_pid="$(TFVARS="${sv_tt_src}"; sv_tfvar project_id)" || sv_tt_pid=""
    if [ -n "${sv_tt_pid}" ] && sv_valid_project_id "${sv_tt_pid}" && [ ! -e "${TF_DIR}/${sv_tt_pid}.tfvars" ]; then
        sv_tt_dst="${TF_DIR}/${sv_tt_pid}.tfvars"
    else
        sv_tt_dst="${sv_tt_src}.bak-$(date -u +%Y%m%dT%H%M%SZ)"
    fi
    if [ -e "${sv_tt_dst}" ] || ! mv "${sv_tt_src}" "${sv_tt_dst}"; then
        echo -e "${RED}[ERROR]${RESET} BOOTSTRAP_TFVARS_MOVE_FAILED: could not move ${sv_tt_src} to ${sv_tt_dst}; nothing was changed."
        exit 1
    fi
    echo -e "${YELLOW}[MOVED]${RESET} ${sv_tt_src} (auto-loaded by tofu, so it would leak into every run) is now ${BOLD}${sv_tt_dst}${RESET}."
fi
if [ -e "${TFVARS_PATH}" ] && [ -z "${OVERWRITE_TFVARS}" ]; then
    # BOOTSTRAP-EXISTING-TFVARS-SELF-CORRECT (owner 11-10: "If bootstrap finds something already there it needs to
    # self correct"). The file alone does not say whether this project is installed; its platform state does. One
    # READ-ONLY GET of gs://castor-tfstate-<id>/platform/state/default.tfstate decides, by HTTP status:
    #   404 (no bucket or no state), or a state with no resources -> the file is left from an unfinished earlier run:
    #       back it up and continue as a new install (no prompt);
    #   200 with resources -> an installed platform: in a terminal ask (default Yes) to re-run the installer with the
    #       --overwrite-tfvars carry-over (backup first); otherwise a typed stop;
    #   anything else (no token, 403, network) -> not checked: in a terminal ask (default No); otherwise a typed stop.
    sv_ex_code=""
    sv_ex_count=""
    sv_ex_tmp="$(mktemp -d 2>/dev/null)" || sv_ex_tmp=""
    if [ -n "${sv_ex_tmp}" ]; then
        sv_ex_token="$(gcloud auth print-access-token 2>/dev/null)" || sv_ex_token=""
        if [ -n "${sv_ex_token}" ]; then
            sv_ex_code="$(printf 'header = "Authorization: Bearer %s"\n' "${sv_ex_token}" \
                | curl -sS --max-time 30 --config - -o "${sv_ex_tmp}/state.json" -w '%{http_code}' \
                    "https://storage.googleapis.com/storage/v1/b/castor-tfstate-${PROJECT_ID}/o/platform%2Fstate%2Fdefault.tfstate?alt=media" \
                    2>/dev/null)" || sv_ex_code=""
        fi
        sv_ex_token=""
        if [ "${sv_ex_code}" = "200" ]; then
            sv_ex_count="$(python3 -I -c '
import json, sys
try:
    with open(sys.argv[1]) as f:
        r = json.load(f).get("resources")
    print(len(r) if isinstance(r, list) else "")
except Exception:
    print("")
' "${sv_ex_tmp}/state.json")"
        fi
        rm -rf "${sv_ex_tmp}"
    fi
    sv_ex_existing_msg() {
        echo -e "        Existing install: PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh plan   (then: PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply)"
        echo -e "        then deploy the services: PROJECT_ID=${PROJECT_ID} REGION=<region> bash scripts/deploy-services.sh --all-jobs"
        echo -e "        Or re-run the installer for it (a timestamped backup is written first): bash scripts/bootstrap.sh --overwrite-tfvars"
    }
    if [ "${sv_ex_code}" = "404" ] || { [ "${sv_ex_code}" = "200" ] && [ "${sv_ex_count}" = "0" ]; }; then
        TFVARS_BACKUP="${TFVARS_PATH}.bak-$(date -u +%Y%m%dT%H%M%SZ)"
        if [ -e "${TFVARS_BACKUP}" ] || ! mv "${TFVARS_PATH}" "${TFVARS_BACKUP}"; then
            echo -e "${RED}[ERROR]${RESET} BOOTSTRAP_TFVARS_BACKUP_FAILED: could not move ${TFVARS_PATH} to ${TFVARS_BACKUP}; nothing was changed."
            exit 1
        fi
        echo -e "${BLUE}==>${RESET} ${TFVARS_PATH} is left from an unfinished earlier run (no StackVend platform state for '${PROJECT_ID}' yet)."
        echo -e "${YELLOW}[BACKUP]${RESET} Saved it as ${BOLD}${TFVARS_BACKUP}${RESET}; continuing as a new install."
    elif [ "${sv_ex_code}" = "200" ] && [ -n "${sv_ex_count}" ]; then
        if [ -t 0 ]; then
            read -r -p "This project already has a StackVend install (platform state with ${sv_ex_count} resources). Re-run the installer for it? A timestamped backup of ${TFVARS_PATH} is kept. [Y/n]: " sv_ex_answer || sv_ex_answer="n"
            case "${sv_ex_answer}" in
                ""|y|Y|yes|Yes|YES) OVERWRITE_TFVARS=1 ;;
                *)
                    echo -e "${RED}[ERROR]${RESET} BOOTSTRAP_EXISTING_INSTALL_DECLINED: '${PROJECT_ID}' is already installed and you chose not to re-run the installer. Nothing was changed."
                    sv_ex_existing_msg
                    exit 1 ;;
            esac
        else
            echo -e "${RED}[ERROR]${RESET} BOOTSTRAP_EXISTING_INSTALL: '${PROJECT_ID}' already has a StackVend install (platform state with ${sv_ex_count} resources) and this is not a terminal, so the installer did not ask. Nothing was changed."
            sv_ex_existing_msg
            exit 1
        fi
    else
        sv_ex_why="the state check returned ${sv_ex_code:-no answer}"
        if [ -t 0 ]; then
            echo -e "${YELLOW}[WARNING]${RESET} ${TFVARS_PATH} exists and the platform state for '${PROJECT_ID}' could not be checked (${sv_ex_why})."
            read -r -p "Re-run the installer anyway? It regenerates the file from your answers; a timestamped backup is kept. [y/N]: " sv_ex_answer || sv_ex_answer=""
            case "${sv_ex_answer}" in
                y|Y|yes|Yes|YES) OVERWRITE_TFVARS=1 ;;
                *)
                    echo -e "${RED}[ERROR]${RESET} BOOTSTRAP_STATE_UNCHECKED: ${TFVARS_PATH} exists and the platform state could not be checked (${sv_ex_why}). Nothing was changed."
                    sv_ex_existing_msg
                    exit 1 ;;
            esac
        else
            echo -e "${RED}[ERROR]${RESET} BOOTSTRAP_STATE_UNCHECKED: ${TFVARS_PATH} exists and the platform state for '${PROJECT_ID}' could not be checked (${sv_ex_why}). Nothing was changed."
            sv_ex_existing_msg
            exit 1
        fi
    fi
fi
# TFVARS-AUTO-BACKUP (red-team fix 5): no local vars file, but a backup of one exists -> one read-only metadata GET and a
# prominent NOTE that `apply.sh plan` restores it. A note only (no prompt, no stop; a stop here would be a new behavior).
if [ ! -e "${TFVARS_PATH}" ] && [ ! -L "${TFVARS_PATH}" ]; then
    sv_tfvars_backup_note "castor-tfstate-${PROJECT_ID}"
fi
# SAT-46: the Terraform runner identity this run writes. A NEW install (no vars file before this run) is Per workload
# from its first apply. --overwrite-tfvars on an EXISTING file carries over that file's own tf_runner_identity and
# tf_runner_dedicated_sa exactly, read with the real HCL parser (sv_tfvar; a key the file does not set gives the
# variables.tf default, PLATFORM / false, so an existing install stays Shared). Regenerating the file never switches
# an install. A value that cannot be read is refused. The step-B readiness check (scripts/common/runner_switch_gate.sh)
# also runs in bootstrap's gated apply, for an existing install bootstrapped again without its vars file.
SV_TF_RUNNER_IDENTITY="PER_WORKLOAD"
SV_TF_RUNNER_DEDICATED_SA="true"
SV_TFVARS_WRITTEN_NEW=1
if [ -e "${TFVARS_PATH}" ]; then
    SV_TFVARS_WRITTEN_NEW=""
    SV_TF_RUNNER_IDENTITY="$(TFVARS="${TFVARS_PATH}"; sv_tfvar tf_runner_identity)" || SV_TF_RUNNER_IDENTITY=""
    SV_TF_RUNNER_DEDICATED_SA="$(TFVARS="${TFVARS_PATH}"; sv_tfvar tf_runner_dedicated_sa)" || SV_TF_RUNNER_DEDICATED_SA=""
    case "${SV_TF_RUNNER_IDENTITY}" in
        PLATFORM|PER_WORKLOAD) ;;
        *) sv_die "BOOTSTRAP_RUNNER_IDENTITY_UNREADABLE: cannot read tf_runner_identity (PLATFORM or PER_WORKLOAD) from the existing ${TFVARS_PATH}, so its runner identity cannot be carried over. Nothing was changed. Fix that file (or use PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply for an existing install), then re-run." ;;
    esac
    case "${SV_TF_RUNNER_DEDICATED_SA}" in
        true|false) ;;
        *) sv_die "BOOTSTRAP_RUNNER_IDENTITY_UNREADABLE: cannot read tf_runner_dedicated_sa (true or false) from the existing ${TFVARS_PATH}, so its runner identity cannot be carried over. Nothing was changed. Fix that file (or use PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply for an existing install), then re-run." ;;
    esac
    echo -e "${BLUE}==>${RESET} Existing ${TFVARS_PATH}: keeping its Terraform runner identity (tf_runner_identity = \"${SV_TF_RUNNER_IDENTITY}\", tf_runner_dedicated_sa = ${SV_TF_RUNNER_DEDICATED_SA})."
fi
# SELFUP-BOOTSTRAP-ON (owner 11-03): the self-update ("Update StackVend") setting this run writes. A NEW install (no
# vars file before this run) has the upgrader (infra/platform/platform_upgrader.tf) from its first apply.
# --overwrite-tfvars on an EXISTING file carries over that file's own enable_platform_upgrader exactly, read with the
# real HCL parser (sv_tfvar; a key the file does not set gives the variables.tf default, false, so an existing install
# without the upgrader stays without it). Regenerating the file never switches an install. A value that cannot be read
# is refused.
SV_ENABLE_PLATFORM_UPGRADER="true"
if [ -e "${TFVARS_PATH}" ]; then
    SV_ENABLE_PLATFORM_UPGRADER="$(TFVARS="${TFVARS_PATH}"; sv_tfvar enable_platform_upgrader)" || SV_ENABLE_PLATFORM_UPGRADER=""
    case "${SV_ENABLE_PLATFORM_UPGRADER}" in
        true|false) ;;
        *) sv_die "BOOTSTRAP_UPGRADER_UNREADABLE: cannot read enable_platform_upgrader (true or false) from the existing ${TFVARS_PATH}, so its self-update setting cannot be carried over. Nothing was changed. Fix that file (or use PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply for an existing install), then re-run." ;;
    esac
    echo -e "${BLUE}==>${RESET} Existing ${TFVARS_PATH}: keeping its self-update setting (enable_platform_upgrader = ${SV_ENABLE_PLATFORM_UPGRADER})."
fi
# HOST-VPC-EGRESS / HOST-INTERNAL-INGRESS (owner 11-07, Design B for the RC): the platform network switches this run
# writes. A NEW install (no vars file before this run) joins the stackvend-host network from its first apply
# (host_vpc_egress = true; the single apply creates the network before the services: their vpc_access references the
# subnet) and gets host_internal_ingress = SV_NEW_INSTALL_HOST_INTERNAL_INGRESS (below).
#
# >>> SV_NEW_INSTALL_HOST_INTERNAL_INGRESS: the ONE line that sets a new install's ingress. "true" since the live
# >>> spike and the live flip passed: a fresh install (no services in state) applies host_vpc_egress = true and
# >>> host_internal_ingress = true in its single first apply, so every service except the Control Center is
# >>> INGRESS_TRAFFIC_INTERNAL_ONLY from creation (nothing is running off the network yet, so nothing is cut off).
SV_NEW_INSTALL_HOST_INTERNAL_INGRESS="true"
#
# --overwrite-tfvars on an EXISTING file carries over that file's own host_vpc_egress, host_internal_ingress and
# host_egress_mode exactly, read with the real HCL parser (sv_tfvar; a key the file does not set gives the variables.tf
# default, true / false / "PSC_PRIVATE_RANGES", so an existing install joins the network first and flips its ingress
# in a later apply). Regenerating the file never flips an install's ingress. A value that cannot be read is refused.
SV_HOST_VPC_EGRESS="true"
SV_HOST_INTERNAL_INGRESS="${SV_NEW_INSTALL_HOST_INTERNAL_INGRESS}"
SV_HOST_EGRESS_MODE="PSC_PRIVATE_RANGES"
if [ -e "${TFVARS_PATH}" ]; then
    SV_HOST_VPC_EGRESS="$(TFVARS="${TFVARS_PATH}"; sv_tfvar host_vpc_egress)" || SV_HOST_VPC_EGRESS=""
    SV_HOST_INTERNAL_INGRESS="$(TFVARS="${TFVARS_PATH}"; sv_tfvar host_internal_ingress)" || SV_HOST_INTERNAL_INGRESS=""
    SV_HOST_EGRESS_MODE="$(TFVARS="${TFVARS_PATH}"; sv_tfvar host_egress_mode)" || SV_HOST_EGRESS_MODE=""
    case "${SV_HOST_EGRESS_MODE}" in
        PSC_PRIVATE_RANGES|NAT_ALL_TRAFFIC) ;;
        *) sv_die "BOOTSTRAP_HOST_NETWORK_UNREADABLE: cannot read host_egress_mode (PSC_PRIVATE_RANGES or NAT_ALL_TRAFFIC) from the existing ${TFVARS_PATH}, so its platform network setting cannot be carried over. Nothing was changed. Fix that file (or use PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply for an existing install), then re-run." ;;
    esac
    case "${SV_HOST_VPC_EGRESS}:${SV_HOST_INTERNAL_INGRESS}" in
        true:true|true:false|false:false) ;;
        false:true) sv_die "BOOTSTRAP_HOST_NETWORK_UNREADABLE: the existing ${TFVARS_PATH} sets host_internal_ingress = true with host_vpc_egress = false, which the platform refuses (internal-only services need the platform network). Nothing was changed. Fix that file, then re-run." ;;
        *) sv_die "BOOTSTRAP_HOST_NETWORK_UNREADABLE: cannot read host_vpc_egress and host_internal_ingress (true or false) from the existing ${TFVARS_PATH}, so its platform network setting cannot be carried over. Nothing was changed. Fix that file (or use PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply for an existing install), then re-run." ;;
    esac
    echo -e "${BLUE}==>${RESET} Existing ${TFVARS_PATH}: keeping its platform network setting (host_vpc_egress = ${SV_HOST_VPC_EGRESS}, host_internal_ingress = ${SV_HOST_INTERNAL_INGRESS}, host_egress_mode = \"${SV_HOST_EGRESS_MODE}\")."
fi

# Region
echo -e "   Region: only us-central1 is supported in this preview (documentation/known-limitations.md \"One region\")."
read -r -p "Enter primary Google Cloud Region [us-central1]: " INPUT_REGION
REGION=${INPUT_REGION:-us-central1}
if ! sv_valid_region "$REGION"; then
    echo -e "${RED}[ERROR]${RESET} '${REGION}' is not a valid GCP region."
    exit 1
fi

# Zone
echo -e "   Zone: recorded in the tfvars as the default zone; the platform itself creates no zonal resources."
read -r -p "Enter default compute Zone [${REGION}-a]: " INPUT_ZONE
ZONE=${INPUT_ZONE:-"${REGION}-a"}

# Organization ID
echo -e "   Organization ID: needed (with the folder below) for the deletion safety tag. Skipping it means StackVend refuses"
echo -e "   every child-project delete (GUARD_UNCONFIGURED; Settings shows the fix). Creating the tag also needs Tag Administrator"
echo -e "   (roles/resourcemanager.tagAdmin) on the organization; without that role (or without the organization or folder) the installer asks, right after"
echo -e "   the folder question and before it changes anything, whether to continue without deletion safety [y/N]."
read -r -p "Enter Google Cloud Organization ID (e.g. organizations/123456789012) [${STACKVEND_ORG_ID:-optional}]: " INPUT_ORG_ID
ORGANIZATION_ID=${INPUT_ORG_ID:-${STACKVEND_ORG_ID:-}}

# Billing Account ID
echo -e "   Billing Account ID: the account vended child projects are linked to. Skipping it means child projects get no billing"
echo -e "   account, so nothing that needs billing can be deployed in them."
read -r -p "Enter Billing Account ID (e.g. 01XXXX-XXXXXX-XXXXXX) [${STACKVEND_BILLING_ACCOUNT_ID:-optional - press Enter to skip}]: " INPUT_BILLING_ID
BILLING_ACCOUNT_ID=${INPUT_BILLING_ID:-${STACKVEND_BILLING_ACCOUNT_ID:-}}
BIND_BILLING_IAM="false"
if [ -n "$BILLING_ACCOUNT_ID" ]; then
    CLEAN_BILLING=$(echo "$BILLING_ACCOUNT_ID" | sed 's#billingAccounts/##')
    if [[ ! "$CLEAN_BILLING" =~ ^[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6}$ ]]; then
        echo -e "${YELLOW}⚠️  Warning: '${BILLING_ACCOUNT_ID}' does not match standard GCP billing format (01XXXX-XXXXXX-XXXXXX, 18 hex digits).${RESET}"
        read -r -p "Keep this value anyway? (y/N): " KEEP_BILLING
        if [[ ! "$KEEP_BILLING" =~ ^[Yy]$ ]]; then
            read -r -p "Re-enter Billing Account ID (or press Enter to skip): " RE_BILLING
            BILLING_ACCOUNT_ID=${RE_BILLING:-""}
        fi
    fi
    if [ -n "$BILLING_ACCOUNT_ID" ]; then
        CLEAN_BILLING=$(echo "$BILLING_ACCOUNT_ID" | sed 's#billingAccounts/##')
        BIND_BILLING_IAM="false"
        echo -e "${GREEN}[OK]${RESET} Billing Account configured: ${BOLD}${CLEAN_BILLING}${RESET}"
        echo -e "   ${BLUE}ℹ️${RESET}  Three billing grants (Billing Account User for sa-project-provisioner and sa-castor-developer, Billing Account"
        echo -e "      Viewer for sa-stackvend-control-center): Terraform makes them if you are a Billing Account Administrator (read-only"
        echo -e "      check before the plan); otherwise they are skipped with a warning, the install continues and its end prints the commands."
    fi
fi

# Managed Workloads Folder ID
echo -e "   Managed Workloads Folder ID: the folder StackVend creates child projects in. Skipping it means no child project can"
echo -e "   be vended. If you enter one, it is checked right away (read-only) that this account can set IAM on it."
read -r -p "Enter Managed Workloads Folder ID (e.g. folders/123456789012) [${STACKVEND_FOLDER_ID:-optional - press Enter to skip}]: " INPUT_FOLDER_ID
FOLDER_ID=${INPUT_FOLDER_ID:-${STACKVEND_FOLDER_ID:-}}
# BOOTSTRAP-FOLDER-IAM-PREFLIGHT (owner 11-03): the platform apply grants StackVend's service accounts their roles on
# this folder (google_folder_iam_member), which needs Folder IAM Admin. One read-only testIamPermissions call, before
# any API enable, state bucket, vars file or tofu call; missing or unchecked -> a typed refusal, nothing changed
# (scripts/common/folder_iam_preflight.sh; scripts/apply.sh runs the same check before its plan).
sv_folder_iam_preflight BOOTSTRAP "${FOLDER_ID}" "${ACTIVE_ACCOUNT}"

# BOOTSTRAP-TAG-ADMIN-CONFIRM (owner 11-11): without the deletion safety tag StackVend cannot delete or decommission
# the projects it creates, and the one-line warning was easy to miss. When the tag will not be created, print the
# prominent block (scripts/common/tag_admin_preflight.sh) and ask "Continue without deletion safety? [y/N]":
# y -> continue as before (tag off, Settings warns); N / Enter -> a typed stop; not a terminal -> the same stop (like
# the existing-vars-file prompt; there is no unattended "yes"). Asked as EARLY as the facts allow (review F1): right
# here, before any API enable, gcloud config change, vars file, state bucket or tofu call, by a read-only check
# (sv_tag_admin_early_check: no organization / folder, or the org testIamPermissions answer plus one GET of the
# platform state for a tag already in state). Only when that state cannot be read is the question left to the late
# preflight before the plan, whose stop lists what this run had changed by then. A Tag Administrator, or an install
# whose tag is already in state, is never asked.
SV_TAG_CONFIRMED=""
SV_TAG_IMPORTED=""
# $1 = early | late
sv_tag_confirm() {
    local stage="$1" answer=""
    sv_tag_unprotected_block "${ACTIVE_ACCOUNT}" BOOTSTRAP
    if [ -t 0 ]; then
        read -r -p "Continue without deletion safety? [y/N]: " answer || answer=""
        case "${answer}" in
            y|Y|yes|Yes|YES)
                SV_TAG_CONFIRMED=1
                echo -e "${YELLOW}[WARN]${RESET} Continuing without deletion safety (you answered yes): StackVend cannot delete or decommission the projects it creates until a Tag Administrator re-runs: PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply"
                return 0 ;;
        esac
        echo -e "${RED}[ERROR]${RESET} BOOTSTRAP_TAG_ADMIN_DECLINED: you chose not to install without deletion safety (the deletion safety tag needs ${SV_TAG_REQUIRED_ROLE} on the organization)."
    else
        echo -e "${RED}[ERROR]${RESET} BOOTSTRAP_TAG_ADMIN_UNCONFIRMED: the deletion safety tag will not be created and this is not a terminal, so the installer did not ask whether to continue without it."
    fi
    if [ "${stage}" = "early" ]; then
        echo -e "        Nothing was changed: no API was enabled and no vars file, state bucket or OpenTofu state was written."
    else
        echo -e "        Nothing was planned or applied, but this run had already: enabled the base APIs on ${PROJECT_ID}, set gcloud's"
        echo -e "        default project to ${PROJECT_ID}, written ${TFVARS_PATH}, created or checked gs://${STATE_BUCKET} and"
        echo -e "        initialised OpenTofu in ${TF_DIR}${SV_TAG_IMPORTED:+, and imported the existing git resources into the platform state}."
        echo -e "        The next bootstrap run backs that vars file up (it may ask first)."
    fi
    echo -e "        Grant the role with the command above (or enter the organization and folder IDs), then re-run:"
    echo -e "        bash scripts/bootstrap.sh"
    exit 1
}
sv_tag_admin_early_check "${ORGANIZATION_ID}" "${FOLDER_ID}" "${PROJECT_ID}"
case "${SV_TAG_EARLY}" in
    granted|in-state|deferred) ;;
    *) sv_tag_confirm early ;;
esac

# Environment
echo -e "   Environment tier: a lowercase label on the platform's resources (also shown in the services' health output); it changes no behavior."
read -r -p "Enter Environment Tier (dev/staging/prod) [dev]: " INPUT_ENV
ENVIRONMENT=${INPUT_ENV:-dev}


# Version Control System (VCS) Configuration
echo -e "\n${BLUE}==>${RESET} ${BOLD}Version Control System (VCS) Configuration:${RESET}"
echo -e "   StackVend can store and manage workload source code in two ways:"
echo -e "   1) GitHub (GitHub App on an organization) [Default]"
echo -e "      • Automated repository vending in your GitHub organization (personal accounts are not supported)"
echo -e "      • Automated CI/CD via GitHub Actions workflows"
echo -e "   2) Serverless Git (100% Google Cloud Native / Zero External Dependencies)"
echo -e "      • Bare Git repositories stored in Cloud Storage (\$0/mo idle cost, zero database)"
echo -e "      • Zero external accounts, zero PATs, zero GitHub App setup required"
echo -e "      • Automated CI/CD via Google Cloud Build"
echo -e "      • No pull request page: every release waits for your approval in the Control Center (HITL Approvals tab)"
echo ""
read -r -p "Select Primary VCS Provider [1 for GitHub, 2 for Serverless Git] [1]: " INPUT_VCS

if [[ "$INPUT_VCS" == "2" ]]; then
    VCS_PROVIDER="SERVERLESS_GIT"
    DEPLOY_GIT_SERVER=true
    GITHUB_OWNER=""
    echo -e "${GREEN}[SERVERLESS GIT SELECTED]${RESET} 100% Google Cloud native mode enabled (zero GitHub dependencies)."
else
    VCS_PROVIDER="GITHUB"
    DEPLOY_GIT_SERVER=false
    echo -e "${GREEN}[GITHUB SELECTED]${RESET} StackVend will interface with GitHub.com."
    echo -e "${GREEN}ℹ️  StackVend will vend new application repositories in your GitHub organization.${RESET}"
    echo -e "   StackVend uses short-lived GitHub App installation tokens, which can create repositories"
    echo -e "   only in an organization where the App is installed. Personal GitHub accounts are not supported.\n"
    read -r -p "Enter the GitHub organization that will own the workload repositories (your StackVend GitHub App must be installed on it; personal accounts are not supported): " GITHUB_OWNER
    if [ -z "$GITHUB_OWNER" ]; then
        echo -e "${RED}[ERROR]${RESET} The GitHub organization is required."
        exit 1
    fi
fi

# BOOTSTRAP-NO-GEMINI-KEY-PROMPT (owner 11-16): the installer no longer asks for a Google AI Studio key. StackVend
# uses Vertex AI through IAM (what pressing Enter at the old prompt gave); an install whose Secret Manager secret
# castor-gemini-api-key already has an ENABLED version keeps using it (section 6 and the Control Center wiring below).

# ------------------------------------------------------------------------------
# 3. Pre-Enable Service Usage, Cloud Resource Manager, IAM & Foundation APIs
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}==>${RESET} Pre-enabling Service Usage, Cloud Resource Manager, IAM, and Core Platform APIs on ${BOLD}${PROJECT_ID}${RESET}..."
# BOOTSTRAP-TOS-FAIL-LOUD (live finding 11-03): a failed enable stops the installer here (it used to end in
# `|| true` and carry on into the next prompts). This is the first write of the run: before the gcloud config
# change (now at the start of section 6), the vars file, the state bucket and any tofu call; every gcloud call
# before section 6 names --project or uses the exported CLOUDSDK_CORE_PROJECT. An account that never accepted the Google Cloud Terms
# of Service gets BOOTSTRAP_CLOUD_TERMS_NOT_ACCEPTED (ErrorInfo reason UREQ_TOS_NOT_ACCEPTED); any other failure
# BOOTSTRAP_API_ENABLE_FAILED (scripts/common/platform_target.sh sv_enable_apis_or_die).
sv_enable_apis_or_die BOOTSTRAP "${ACTIVE_ACCOUNT}" "Nothing was written." gcloud services enable \
    serviceusage.googleapis.com \
    cloudresourcemanager.googleapis.com \
    iam.googleapis.com \
    compute.googleapis.com \
    storage.googleapis.com \
    run.googleapis.com \
    artifactregistry.googleapis.com \
    cloudbuild.googleapis.com \
    pubsub.googleapis.com \
    firestore.googleapis.com \
    workflows.googleapis.com \
    cloudscheduler.googleapis.com \
    secretmanager.googleapis.com \
    aiplatform.googleapis.com \
    discoveryengine.googleapis.com \
    iap.googleapis.com \
    servicenetworking.googleapis.com \
    vpcaccess.googleapis.com \
    sqladmin.googleapis.com \
    orgpolicy.googleapis.com \
    --project="${PROJECT_ID}" --quiet

# RC B2: no `gcloud beta services identity create` here. The IAP, Logging and Workflows service agents are created by
# Terraform (google_project_service_identity.iap_sa / logging_sa / workflows_sa in infra/platform/main.tf), and every
# resource that names one depends_on it; nothing before the first apply needs them. The old calls discarded stderr,
# so on a machine without the gcloud `beta` component the "install component? (Y/n)" prompt was invisible and the
# installer appeared to hang.

# ------------------------------------------------------------------------------
# 5. Ingress Security Posture & Enterprise Policy Check (Plan 12)
# ------------------------------------------------------------------------------
# install-polish: the old domain-restricted-sharing probe called `gcloud org-policies check-policy-membership`, a
# command that does not exist, so it never detected anything and the choice below was always asked. It is removed (it
# could only print noise); the option text says what an organization with domain-restricted sharing means instead.
echo -e "\n${BLUE}==>${RESET} ${BOLD}Control Center Ingress Security Posture:${RESET}"
echo -e "   1) ${BOLD}Enterprise Authenticated (Recommended)${RESET} - Restricts UI to authorized corporate users/domains via Direct IAP."
echo -e "      No OAuth consent screen or OAuth client is needed. At first IAP admits only ${ACTIVE_ACCOUNT} (an organization"
echo -e "      account; a personal Gmail account is refused)."
echo -e "   2) ${BOLD}Public Sandbox${RESET} - Allows 'allUsers' public invocation; the Control Center signs people in with its own"
echo -e "      Google Web OAuth client (create it first: documentation/quickstart.md \"Create the Google OAuth clients\")."
echo -e "      An organization that enforces domain-restricted sharing (constraints/iam.allowedPolicyMemberDomains) refuses"
echo -e "      'allUsers', so choose 1 there."
read -r -p "Select Ingress Mode [1 for Enterprise, 2 for Public] [1]: " INGRESS_MODE
if [[ "$INGRESS_MODE" == "2" ]]; then
    ALLOW_UNAUTH="true"
else
    ALLOW_UNAUTH="false"
fi

ENABLE_IAP="false"
if [ "$ALLOW_UNAUTH" = "false" ]; then
    ENABLE_IAP="true"

    # Pre-enable the IAP API. The IAP service agent itself is created by Terraform (google_project_service_identity.iap_sa;
    # control_center_iap_agent_invoker depends_on it), RC B2.
    # BOOTSTRAP-TOS-FAIL-LOUD: the default ingress needs IAP, so a failed enable stops the installer (typed error,
    # sv_enable_apis_or_die). It runs before the vars file is written (section 6), the state bucket and any tofu call.
    echo -e "\n${BLUE}==>${RESET} Ensuring the Identity-Aware Proxy API is enabled..."
    sv_enable_apis_or_die BOOTSTRAP "${ACTIVE_ACCOUNT}" "Nothing was written." \
        gcloud services enable iap.googleapis.com --project="${PROJECT_ID}" --quiet

    # install-polish: the old OAuth-brand probe only decided whether one [OK] line printed, and its `$ORG_ID` branch
    # was dead (never set). Direct IAP on Cloud Run uses a Google-managed OAuth client: no brand, consent screen or
    # client is created or needed, so nothing is probed here.

    # Auto-seed the deploying administrator to prevent lockout
    INVOKER_MEMBERS="[\"user:${ACTIVE_ACCOUNT}\""
    echo -e "${GREEN}[OK]${RESET} IAP will authorize: ${BOLD}user:${ACTIVE_ACCOUNT}${RESET} (the first Control Center ADMIN; it must be an organization account)."

    # Prompt for ONE additional IAP principal (domain, group or user).
    echo -e "   Optionally let ONE more principal through IAP: domain:yourcompany.com, group:team@yourcompany.com or"
    echo -e "   user:person@yourcompany.com (a value without a prefix is read as domain:). IAP only lets people reach the"
    echo -e "   Control Center: each person also needs a Control Center user, which an ADMIN adds in the Control Center."
    echo -e "   To change the IAP list later: edit authorized_invoker_members in infra/platform/${PROJECT_ID}.tfvars, then run"
    echo -e "   PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply"
    read -r -p "Additional IAP principal (domain:, group: or user:) [optional - press Enter for only you]: " CORP_DOMAIN
    if [ -n "$CORP_DOMAIN" ]; then
        if [[ ! "$CORP_DOMAIN" == domain:* ]] && [[ ! "$CORP_DOMAIN" == group:* ]] && [[ ! "$CORP_DOMAIN" == user:* ]]; then
            CORP_DOMAIN="domain:${CORP_DOMAIN}"
        fi
        INVOKER_MEMBERS="${INVOKER_MEMBERS}, \"${CORP_DOMAIN}\""
        echo -e "${GREEN}[OK]${RESET} IAP will authorize: ${BOLD}${CORP_DOMAIN}${RESET} (each person still needs a Control Center user)."
    fi
    INVOKER_MEMBERS="${INVOKER_MEMBERS}]"
else
    INVOKER_MEMBERS="[]"
    echo -e "${YELLOW}[PUBLIC INGRESS SELECTED]${RESET} Control Center UI will allow allUsers invocation."
fi

# ------------------------------------------------------------------------------
# 5b. Google OAuth clients (lane 19 L19-0d; register rows 27b, 44): TWO console-created Web clients
# ------------------------------------------------------------------------------
# No Google API creates Web OAuth clients, so the operator creates both in the console first. The Control Center
# client is pinned by the cc_google_oauth_client_id tfvar; the tenant sign-in client's SECRET goes only to Secret
# Manager (hidden prompt, piped through the printf builtin: never in tfvars, state, stdout or a command's argv).
# Never run this script under `bash -x` (it would trace the hidden values).
# Bootstrap never writes either client into castor-oauth-client-*: today's tf-applier copies that pair into every
# tenant, so putting the Control Center client there would recreate the Q8 takeover path.
OAUTH_CLIENT_ID_RE='^[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com$'   # same exact rule as infra/platform/variables.tf
# install-polish: the consent-screen / client instructions print only for a public Control Center. Behind Direct IAP,
# IAP signs people in with a Google-managed OAuth client and the Control Center's own Google sign-in is off, so no
# consent screen and no client are needed. The tenant client is not used in this preview (owner row AQ-1).
if [ "$ENABLE_IAP" = "true" ]; then
    echo -e "\n${BLUE}==>${RESET} ${BOLD}Google sign-in: no OAuth consent screen or OAuth client is needed${RESET} (Direct IAP)."
    echo -e "   IAP signs people in with a Google-managed OAuth client, and the Control Center's own Google sign-in is off."
    echo -e "   Press Enter at both client prompts below. The tenant sign-in client is not used in this preview"
    echo -e "   (no shared Google sign-in for workloads).\n"
else
    # RC F4/F5: the Control Center's deterministic Cloud Run URL is known before the install (project number + region),
    # so print the exact JavaScript origin to register. Read-only; an empty number only drops that one line.
    CC_PROJECT_NUMBER="$(gcloud projects describe "${PROJECT_ID}" --format='value(projectNumber)' 2>/dev/null)" || CC_PROJECT_NUMBER=""
    echo -e "\n${BLUE}==>${RESET} ${BOLD}Google sign-in: the Control Center needs its own Web OAuth client${RESET} (documentation/quickstart.md \"Create the Google OAuth clients\")"
    echo -e "   First configure the OAuth consent screen of ${BOLD}${PROJECT_ID}${RESET} (Google Auth Platform: Branding, Audience, scopes openid/email/profile)."
    echo -e "   Then create the client: APIs & Services > Credentials > Create OAuth client ID > Web application."
    echo -e "   1) ${BOLD}StackVend Control Center${RESET} (required): Authorized JavaScript origins = the Control Center URL(s) only; NO redirect URIs."
    if [[ "${CC_PROJECT_NUMBER}" =~ ^[0-9]+$ ]]; then
        echo -e "      Add now: ${BOLD}https://product-control-center-ui-${CC_PROJECT_NUMBER}.${REGION}.run.app${RESET} (after the install, also add the control_center_url printed at the end if it differs)."
    fi
    echo -e "   2) ${BOLD}StackVend tenant sign-in${RESET} (optional; not used in this preview): NO JavaScript origins and NO redirect URIs."
    echo -e "   If you create both, they must be two DIFFERENT clients: with one client, a tenant app could sign platform admins into the Control Center.\n"
fi
CC_CLIENT_ID=""
while true; do
    if [ "$ENABLE_IAP" = "true" ]; then
        read -r -p "Control Center sign-in - Web OAuth client ID [Enter to skip: not needed behind IAP]: " CC_CLIENT_ID || { echo -e "${RED}[ERROR]${RESET} No input."; exit 1; }
        [ -z "$CC_CLIENT_ID" ] && break
    else
        read -r -p "Control Center sign-in - Web OAuth client ID: " CC_CLIENT_ID || { echo -e "${RED}[ERROR]${RESET} No input."; exit 1; }
    fi
    if [[ "$CC_CLIENT_ID" =~ $OAUTH_CLIENT_ID_RE ]]; then break; fi
    echo -e "${RED}[ERROR]${RESET} Not a Web OAuth client ID (<digits>-<id>.apps.googleusercontent.com, no spaces). Try again."
done
TENANT_CLIENT_ID=""
while true; do
    read -r -p "Tenant app Google sign-in - Web OAuth client ID [Enter to skip: not used in this preview]: " TENANT_CLIENT_ID || { echo -e "${RED}[ERROR]${RESET} No input."; exit 1; }
    [ -z "$TENANT_CLIENT_ID" ] && break
    if [[ "$TENANT_CLIENT_ID" =~ $OAUTH_CLIENT_ID_RE ]]; then break; fi
    echo -e "${RED}[ERROR]${RESET} Not a Web OAuth client ID (<digits>-<id>.apps.googleusercontent.com, no spaces). Try again."
done
if [ -n "$CC_CLIENT_ID" ] && [ "$CC_CLIENT_ID" = "$TENANT_CLIENT_ID" ]; then
    echo -e "${RED}[ERROR]${RESET} The Control Center client and the tenant sign-in client are the SAME client."
    echo -e "        A tenant app could then sign platform admins into the Control Center. Create a second client and re-run."
    exit 1
fi
TENANT_CLIENT_SECRET=""
if [ -n "$TENANT_CLIENT_ID" ]; then
    while [ -z "$TENANT_CLIENT_SECRET" ]; do
        read -r -s -p "Tenant sign-in client SECRET (hidden; stored only in Secret Manager for a later release; not used in this preview): " TENANT_CLIENT_SECRET || { echo ""; echo -e "${RED}[ERROR]${RESET} No input."; exit 1; }
        echo ""
    done
fi
# Lane 19 RT F4: from here on, any exit before the secret is written (declined or failed gated apply, plan error,
# any sv_die) must say it was NOT stored and how to store it. Never prints the secret itself.
sv_tenant_secret_not_stored() {
    echo -e "\n${YELLOW}[WARN]${RESET} Tenant sign-in client secret NOT stored: $1"
    echo -e "       After 'PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply' has created the Secret Manager container"
    echo -e "       stackvend-tenant-google-client-secret, run:"
    echo -e "       gcloud secrets versions add stackvend-tenant-google-client-secret --project=${PROJECT_ID} --data-file=-"
    echo -e "       (paste the secret, then Ctrl-D). Never store it in castor-oauth-client-secret. Tenant Google sign-in stays off until then."
}
sv_bootstrap_on_exit() {
    local rc=$?
    sv_cleanup_plan_tmp
    # SAT-46: a failed or refused platform apply (e.g. the step-B readiness gate, APPLY_RUNNER_SWITCH_*) leaves the
    # vars file this run wrote for a NEW install on disk, with the Per-workload values.
    if [ "${rc}" -ne 0 ] && [ -n "${SV_RUNNER_NOTE_ON_FAILURE:-}" ]; then
        echo -e "\n${YELLOW}[NOTE]${RESET} ${TFVARS_PATH}, written by this run, stays on disk as Per workload"
        echo -e "       (tf_runner_identity = \"PER_WORKLOAD\", tf_runner_dedicated_sa = true). If ${PROJECT_ID} is an EXISTING"
        echo -e "       install that should stay Shared, edit that file to tf_runner_identity = \"PLATFORM\" and"
        echo -e "       tf_runner_dedicated_sa = false, then run: PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply"
        echo -e "       (a bootstrap re-run needs --overwrite-tfvars and keeps the values in that file)."
    fi
    if [ -n "${STAGE2_SUMMARY_FILE:-}" ]; then rm -f "${STAGE2_SUMMARY_FILE}"; fi
    if [ -n "${TENANT_CLIENT_SECRET:-}" ]; then
        unset TENANT_CLIENT_SECRET
        sv_tenant_secret_not_stored "bootstrap stopped before it was written."
    fi
}
trap sv_bootstrap_on_exit EXIT

# ------------------------------------------------------------------------------
# 6. Generate infra/platform/<project_id>.tfvars (FD-07: per-install vars; never terraform.tfvars)
# ------------------------------------------------------------------------------
# (TF_DIR / TFVARS_PATH and the terraform.tfvars / existing-file guards: section 2, before any GCP call.)
# BOOTSTRAP-TOS-FAIL-LOUD: the gcloud config change runs here, after both API enables (sections 3 and 5), so a
# refused enable leaves nothing written.
gcloud config set project "${PROJECT_ID}" --quiet
if [ -e "${TFVARS_PATH}" ]; then
    # Only reachable with --overwrite-tfvars. Back up first; never overwrite an earlier backup.
    TFVARS_BACKUP="${TFVARS_PATH}.bak-$(date -u +%Y%m%dT%H%M%SZ)"
    if [ -e "${TFVARS_BACKUP}" ] || ! cp -p "${TFVARS_PATH}" "${TFVARS_BACKUP}"; then
        echo -e "${RED}[ERROR]${RESET} Could not write the backup ${TFVARS_BACKUP}; ${TFVARS_PATH} was not changed."
        exit 1
    fi
    echo -e "${YELLOW}[BACKUP]${RESET} Existing ${TFVARS_PATH} saved as ${BOLD}${TFVARS_BACKUP}${RESET} (--overwrite-tfvars)."
fi

# FD28-07 / H15: CC reads GEMINI_API_KEY from Secret Manager only when the secret has an ENABLED
# version (a secret_key_ref to a secret with no version fails revision creation). Read-only check.
GEMINI_SECRET_READY=""
GEMINI_SECRET_READY="$(gcloud secrets versions list castor-gemini-api-key --project="${PROJECT_ID}" --filter="state=ENABLED" --limit=1 --format="value(name)" 2>/dev/null)" || GEMINI_SECRET_READY=""

echo -e "\n${BLUE}==>${RESET} Writing configuration to ${BOLD}${TFVARS_PATH}${RESET}..."

cat <<EOF > "${TFVARS_PATH}"
project_id                         = "${PROJECT_ID}"
region                             = "${REGION}"
zone                               = "${ZONE}"
organization_id                    = "${ORGANIZATION_ID}"
billing_account_id                 = "${BILLING_ACCOUNT_ID}"
# bind_billing_iam unset = auto (BG-1): apply.sh grants Billing Account User when a Billing Account Administrator applies.
castor_managed_workloads_folder_id = "${FOLDER_ID}"
environment                        = "${ENVIRONMENT}"
vcs_provider                       = "${VCS_PROVIDER}"
deploy_git_server                  = ${DEPLOY_GIT_SERVER}
github_owner                       = "${GITHUB_OWNER}"
platform_github_repo               = ""
enable_drive_spec_polling           = false
google_drive_intake_folder_ids      = ""
google_drive_in_progress_folder_ids = ""
google_drive_completed_folder_ids   = ""
allow_unauthenticated              = ${ALLOW_UNAUTH}
authorized_invoker_members         = ${INVOKER_MEMBERS}
enable_direct_iap                  = ${ENABLE_IAP}
admin_email                        = "${ACTIVE_ACCOUNT}"
cc_google_oauth_client_id          = "${CC_CLIENT_ID}"
tenant_google_client_id            = "${TENANT_CLIENT_ID}"
# FD-7L-n (owner OQ-35): a new install is "Per workload" from its first apply: each workload deploys as its own
# deployer in its own project, and the Terraform runners run as their own service accounts (step B; nothing to
# migrate on a new install). Existing installs keep the variables.tf default PLATFORM ("Shared") until an operator
# moves them (Settings switch, runner identity backfill, then step B with scripts/apply.sh); --overwrite-tfvars
# keeps the existing file's values (SAT-46).
tf_runner_identity                 = "${SV_TF_RUNNER_IDENTITY}"
tf_runner_dedicated_sa             = ${SV_TF_RUNNER_DEDICATED_SA}
# SELFUP-BOOTSTRAP-ON (owner 11-03): a new install has the "Update StackVend" upgrader from its first apply
# (infra/platform/platform_upgrader.tf). Existing installs keep the variables.tf default false until an operator sets
# it; --overwrite-tfvars keeps the existing file's value.
enable_platform_upgrader           = ${SV_ENABLE_PLATFORM_UPGRADER}
# HOST-VPC-EGRESS / HOST-INTERNAL-INGRESS (owner 11-07): a new install puts every host service and job except the QA
# sandbox job on the stackvend-host network from its first apply (infra/platform/host_network.tf). Internal-only
# ingress for every host service except the Control Center: set host_internal_ingress = true and run
# scripts/apply.sh apply once the first apply is checked (new installs get it from the first apply once the live spike
# has passed). --overwrite-tfvars keeps the existing file's values.
host_vpc_egress                    = ${SV_HOST_VPC_EGRESS}
host_internal_ingress              = ${SV_HOST_INTERNAL_INGRESS}
host_egress_mode                   = "${SV_HOST_EGRESS_MODE}"
EOF
GEMINI_FLAG_WRITTEN=false
if [ -n "${GEMINI_SECRET_READY}" ]; then
    echo 'cc_gemini_api_key_from_secret      = true' >> "${TFVARS_PATH}"
    GEMINI_FLAG_WRITTEN=true
fi

echo -e "${GREEN}[OK]${RESET} ${TFVARS_PATH} generated successfully."

# ------------------------------------------------------------------------------
# 7. Execute Single-Pass Terraform Apply
# ------------------------------------------------------------------------------
echo -e "\n${BLUE}==>${RESET} Exporting active OAuth token for Terraform..."
export GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth print-access-token)

# Ensure central GCS state bucket exists for Terraform remote state backend
STATE_BUCKET="castor-tfstate-${PROJECT_ID}"
echo -e "${BLUE}==>${RESET} Verifying central Terraform state bucket (${BOLD}gs://${STATE_BUCKET}${RESET})..."

if ! gcloud storage buckets describe "gs://${STATE_BUCKET}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
    echo -e "${BLUE}==>${RESET} Creating central Terraform remote state bucket: ${BOLD}gs://${STATE_BUCKET}${RESET}..."
    gcloud storage buckets create "gs://${STATE_BUCKET}" \
        --project="${PROJECT_ID}" \
        --location="${REGION}" \
        --uniform-bucket-level-access \
        --quiet 2>/dev/null || gsutil mb -p "${PROJECT_ID}" -l "${REGION}" -b on "gs://${STATE_BUCKET}" 2>/dev/null || true
    # Both create attempts are best effort; the bucket counts as ready only if it can be described now.
    if ! gcloud storage buckets describe "gs://${STATE_BUCKET}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
        echo -e "${RED}[ERROR]${RESET} Could not create gs://${STATE_BUCKET} (needs storage.buckets.create on ${PROJECT_ID} and billing linked to it)."
        echo -e "        Nothing else was changed (only the base APIs were enabled and ${TFVARS_PATH} was written)."
        echo -e "        Fix the cause, then re-run: bash scripts/bootstrap.sh --overwrite-tfvars"
        exit 1
    fi
    if ! { gcloud storage buckets update "gs://${STATE_BUCKET}" --versioning --quiet 2>/dev/null \
           || gsutil versioning set on "gs://${STATE_BUCKET}" 2>/dev/null; }; then
        echo -e "${YELLOW}[WARN]${RESET} Could not turn on versioning for gs://${STATE_BUCKET}; turn it on later: gcloud storage buckets update gs://${STATE_BUCKET} --versioning"
    fi
    echo -e "${GREEN}[OK]${RESET} State bucket gs://${STATE_BUCKET} ready."
else
    echo -e "${GREEN}[OK]${RESET} State bucket gs://${STATE_BUCKET} exists."
fi

echo -e "${BLUE}==>${RESET} Initializing ${IAC_BIN} in ${TF_DIR} with remote state..."
cd "${TF_DIR}"
export TF_DATA_DIR="${TF_DIR}/.terraform-${PROJECT_ID}"
export PROJECT_ID STATE_BUCKET
TFVARS="${TFVARS_PATH}"
export TFVARS
# Same init as apply.sh: no -upgrade (providers pinned exactly, FD-0A), stale workspace selection
# removed and `default` enforced (red team F2), bound bucket verified.
sv_tf_init_bound

# FD-0B: adopt pre-existing git resources fail-closed (never delete anything). Fresh-install path.
STATE_ADDRS="$("${IAC_BIN}" state list)" || { echo -e "${RED}[ERROR]${RESET} '${IAC_BIN} state list' failed."; exit 1; }
if [ "${DEPLOY_GIT_SERVER}" = "true" ] || [ "${VCS_PROVIDER}" = "SERVERLESS_GIT" ]; then
    GIT_REPOS_BUCKET="castor-git-repos-${PROJECT_ID}"
    if ! printf '%s\n' "${STATE_ADDRS}" | grep -Fxq 'google_storage_bucket.git_repos_bucket[0]'; then
        if gcloud storage buckets describe "gs://${GIT_REPOS_BUCKET}" --project="${PROJECT_ID}" >/dev/null 2>&1; then
            echo -e "${BLUE}==>${RESET} Importing existing git_repos_bucket (${GIT_REPOS_BUCKET}) into ${IAC_BIN} state..."
            SV_TAG_IMPORTED=1
            "${IAC_BIN}" import -input=false -var-file="${TFVARS_PATH}" 'google_storage_bucket.git_repos_bucket[0]' "${PROJECT_ID}/${GIT_REPOS_BUCKET}" || {
                echo -e "${RED}[ERROR]${RESET} Import of ${GIT_REPOS_BUCKET} failed. Nothing was deleted; fix the cause and re-run."
                exit 1
            }
        fi
    fi
    if ! printf '%s\n' "${STATE_ADDRS}" | grep -Fxq 'google_cloud_run_v2_service.git_server[0]'; then
        if gcloud run services describe castor-git-server --project="${PROJECT_ID}" --region="${REGION}" >/dev/null 2>&1; then
            echo -e "${BLUE}==>${RESET} Importing existing castor-git-server Cloud Run service into ${IAC_BIN} state..."
            SV_TAG_IMPORTED=1
            "${IAC_BIN}" import -input=false -var-file="${TFVARS_PATH}" 'google_cloud_run_v2_service.git_server[0]' "projects/${PROJECT_ID}/locations/${REGION}/services/castor-git-server" || {
                echo -e "${RED}[ERROR]${RESET} Import of castor-git-server failed. Nothing was deleted; fix the cause and re-run."
                exit 1
            }
        fi
    fi
fi
# Lane 18 v3: read-only organizations.testIamPermissions check; missing/error -> the deletion-safety tag is not
# planned and a WARNING is printed (scripts/common/tag_admin_preflight.sh; the preflight itself never aborts).
# BOOTSTRAP-TAG-ADMIN-CONFIRM: the question was asked early (after the folder ID) whenever the facts allowed. It is
# asked here only if it was not answered yet and the tag will not be created (the early check could not read the
# platform state, or this preflight disagrees with it); this stop lists what the run had already changed.
sv_tag_admin_preflight || true
if sv_tag_unprotected && [ -z "${SV_TAG_CONFIRMED}" ]; then
    sv_tag_confirm late
fi
if [ "${SV_TAG_READ_MISSING_IN_STATE:-}" = "1" ]; then
    # Row L18-F5: only apply.sh excludes an unreadable in-state tag; a bootstrap re-run does not.
    echo -e "${YELLOW}⚠️  WARNING:${RESET} the deletion safety tag is already in state and you cannot read it, so this plan's refresh will answer 403. Use: PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply (it excludes the tag for you)."
fi

# ORG-POLICY-FOLDER (owner 10-28): read-only folders.testIamPermissions check for Organization Policy Administrator;
# missing/error -> the folder "no external VM IPs" policy is not planned, a WARNING with the fix is printed and the
# install continues (scripts/common/org_policy_preflight.sh). Never aborts.
sv_org_policy_preflight || true
if [ "${SV_ORGPOL_READ_MISSING_IN_STATE:-}" = "1" ]; then
    # FU1: only apply.sh excludes an unreadable in-state folder policy; a bootstrap re-run does not.
    echo -e "${YELLOW}⚠️  WARNING:${RESET} the folder org policy is already in state and you cannot read it, so this plan's refresh will answer 403. Use: PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply (it excludes that policy for you)."
fi

# HOST-INTERNAL-INGRESS (review F8/F10): an install whose services are already in state but whose platform network
# is not (bootstrapped again with or without its vars file) must not flip egress and ingress in one apply: its running
# revisions are off the network, so internal-only ingress would cut their calls (404) until the new revisions are
# ready. This run writes host_internal_ingress = false instead (the line written above, replaced exactly); a later
# scripts/apply.sh apply with host_internal_ingress = true flips it after the network is in place (apply.sh refuses the
# flip before that, APPLY_HOST_INGRESS_BEFORE_NETWORK).
if [ "${SV_HOST_INTERNAL_INGRESS}" = "true" ] \
    && printf '%s\n' "${STATE_ADDRS}" | grep -q '^google_cloud_run_v2_service\.services\[' \
    && ! printf '%s\n' "${STATE_ADDRS}" | grep -Fxq 'google_compute_subnetwork.host_run_egress[0]'; then
    python3 -c '
import sys
path = sys.argv[1]
old, new = "host_internal_ingress              = true\n", "host_internal_ingress              = false\n"
text = open(path).read()
if text.count(old) != 1:
    sys.exit(1)
open(path, "w").write(text.replace(old, new))
' "${TFVARS_PATH}" || sv_die "BOOTSTRAP_HOST_NETWORK_UNREADABLE: could not set host_internal_ingress = false in ${TFVARS_PATH} for this existing install. Nothing was applied. Set it by hand, then run: PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply"
    SV_HOST_INTERNAL_INGRESS="false"
    echo -e "${YELLOW}[WARN]${RESET} ${PROJECT_ID} already has platform services in state but no platform network: this apply joins the network only (host_internal_ingress = false in ${TFVARS_PATH}). After it, set host_internal_ingress = true and run: PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply" >&2
fi

# BG-1: read-only billing preflight; decides whether Terraform grants Billing Account User (never fails the install).
sv_billing_iam_preflight

# HOST-VPC-EGRESS / HOST-INTERNAL-INGRESS: read-only check of the host project's effective organization policies for
# the platform network (scripts/common/host_network_preflight.sh, the same check as scripts/apply.sh). A refusing
# policy -> BOOTSTRAP_HOST_NETWORK_ORG_POLICY_REFUSED before the plan (nothing applied); unreadable -> a WARNING.
sv_host_network_preflight BOOTSTRAP "${SV_HOST_VPC_EGRESS}" "${SV_HOST_INTERNAL_INGRESS}" "${SV_HOST_EGRESS_MODE}"

echo -e "\n${YELLOW}${BOLD}Ready to execute Single-Pass ${IAC_BIN} Apply for StackVend.${RESET}"
echo -e "The plan is computed and summarized first. Deletes/replaces are refused; nothing is applied until"
echo -e "you type the project id (the same gate as scripts/apply.sh; never auto-approved)."
trap sv_bootstrap_on_exit EXIT  # also cleans the plan temp dir (sv_cleanup_plan_tmp)

APPLY_SUCCESS=false
SV_RUNNER_NOTE_ON_FAILURE="${SV_TFVARS_WRITTEN_NEW}"
for attempt in 1 2 3; do
    echo -e "\n${BLUE}==>${RESET} Planning ${IAC_BIN} configuration (attempt ${attempt}/3)..."
    # Fresh token per attempt (as before): a long first apply can outlive the earlier one.
    GOOGLE_OAUTH_ACCESS_TOKEN="$(gcloud auth print-access-token)" || { echo -e "${RED}[ERROR]${RESET} 'gcloud auth print-access-token' failed."; exit 1; }
    export GOOGLE_OAUTH_ACCESS_TOKEN
    if sv_gated_apply bootstrap "" ${SV_BILLING_TF_ARGS[@]+"${SV_BILLING_TF_ARGS[@]}"}; then
        APPLY_SUCCESS=true
        break
    fi
    if [ "${attempt}" -lt 3 ]; then
        echo -e "\n${YELLOW}⚠️  The apply failed (attempt ${attempt}/3). Re-planning in 20s; you will be asked to type the project id again.${RESET}"
        echo -e "   Type it again only for a temporary error: a per-minute quota or 429/503, an API or service account that was"
        echo -e "   just created, an IAM change still propagating. For a permission error (403) or a configuration error, type"
        echo -e "   anything else (or press Ctrl-C) to stop; nothing more is applied. Fix the cause, then run:"
        echo -e "   PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply"
        echo -e "   PROJECT_ID=${PROJECT_ID} REGION=${REGION} bash scripts/deploy-services.sh --all-jobs"
        sleep 20
    fi
done

if [ "$APPLY_SUCCESS" = true ]; then SV_RUNNER_NOTE_ON_FAILURE=""; fi
if [ "$APPLY_SUCCESS" = false ]; then
    echo -e "\n${RED}${BOLD}[ERROR] '${IAC_BIN} apply' failed after retries! Aborting bootstrap before microservice deployment.${RESET}"
    echo -e "Review the errors above and fix the cause, then run:"
    echo -e "  PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply"
    echo -e "  PROJECT_ID=${PROJECT_ID} REGION=${REGION} bash scripts/deploy-services.sh --all-jobs"
    echo -e "Then open the Control Center and check that Settings shows the default VCS provider (${VCS_PROVIDER}); set it there"
    echo -e "if not (bootstrap stopped before storing it)."
    exit 1
fi

# ------------------------------------------------------------------------------
# Post-install: billing access (BG-1 / BG-1-b; owner 10-26: never a hard install step)
# ------------------------------------------------------------------------------
# Three grants on the BILLING ACCOUNT, all needing a Billing Account Administrator:
#   roles/billing.user   -> sa-project-provisioner      (vending links new child projects to billing)
#   roles/billing.user   -> sa-castor-developer         (FinOps enforcer re-links billing after a budget quarantine)
#   roles/billing.viewer -> sa-stackvend-control-center (Settings billing card reads the billing account)
# Terraform makes all three (billing_iam.tf) only when the read-only preflight found Billing Account Administrator
# rights. Otherwise the install completes without them and this block prints the exact post-install commands; the
# gcloud fallback prompt is offered only when the check could not run. Nothing here can fail the install.
# The fix: the same three commands everywhere (also repeated in Next Steps).
sv_billing_fix_commands() {
    local billing="$1" sa
    echo -e "   Either re-run as a Billing Account Administrator: PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply"
    echo -e "   or have one run:"
    for sa in "${SV_BILLING_USER_SAS[@]}"; do
        echo -e "     gcloud billing accounts add-iam-policy-binding ${billing} --member=serviceAccount:${sa}@${PROJECT_ID}.iam.gserviceaccount.com --role=roles/billing.user"
    done
    echo -e "     gcloud billing accounts add-iam-policy-binding ${billing} --member=serviceAccount:${SV_BILLING_VIEWER_SA}@${PROJECT_ID}.iam.gserviceaccount.com --role=roles/billing.viewer"
}
BILLING_ACCESS_MISSING=""   # set to the billing account when the post-install step was printed (Next Steps repeats it)
sv_billing_post_install_step() {
    local billing="$1"
    BILLING_ACCESS_MISSING="${billing}"
    echo -e "\n${YELLOW}${BOLD}Post-install step: billing access${RESET} (the platform itself is installed; documentation/quickstart.md \"Post-install: billing access\")"
    echo -e "   Until a Billing Account Administrator makes these three grants, the first workload run stops at project vending"
    echo -e "   with BILLING_NOT_LINKED (the child project cannot be linked to billing account ${billing}), the FinOps enforcer"
    echo -e "   cannot re-link billing after a budget quarantine, and Control Center > Settings (billing card) shows a warning."
    sv_billing_fix_commands "${billing}"
    echo -e "   Control Center > Settings (billing card) shows which service account still lacks its grant."
}
if [ -n "$BILLING_ACCOUNT_ID" ]; then
    CLEAN_BILLING="${BILLING_ACCOUNT_ID#billingAccounts/}"
    if [ "${SV_BIND_BILLING_IAM}" = "true" ] && [ "${SV_BILLING_CHECK}" = "admin" ]; then
        # RC F11: BG-1-b grants the viewer in the same apply, so no "no billing viewer access yet" warning here.
        echo -e "\n${GREEN}[OK]${RESET} Terraform granted roles/billing.user to sa-project-provisioner and sa-castor-developer (google_billing_account_iam_member.billing_user) and roles/billing.viewer to sa-stackvend-control-center (google_billing_account_iam_member.cc_billing_viewer)."
    elif [ "${SV_BIND_BILLING_IAM}" = "true" ]; then
        # Already managed by Terraform from an earlier apply by a Billing Account Administrator (kept, see the preflight).
        echo -e "\n${GREEN}[OK]${RESET} The billing grants are already managed by Terraform (made by an earlier apply); kept as is. Control Center > Settings (billing card) shows their state."
    elif [ "${SV_BILLING_CHECK}" = "not_admin" ]; then
        # BG-1-F5 (owner, register 84e307b): the read-only check positively found no Billing Account Administrator
        # rights, so a gcloud grant from this account would certainly fail: no prompt, print the fix only.
        echo -e "\n${YELLOW}ℹ️  The billing grants were not made (you are not a Billing Account Administrator for ${CLEAN_BILLING}); the platform installed cleanly.${RESET}"
        sv_billing_post_install_step "${CLEAN_BILLING}"
    else
        if [ "${SV_BILLING_DECIDED_BY}" = "tfvars" ]; then
            echo -e "\n${YELLOW}ℹ️  Terraform skipped the billing grants because bind_billing_iam = false is set in ${TFVARS_PATH}. Control Center > Settings shows which service account lacks Billing Account User and the fix.${RESET}"
        else
            echo -e "\n${YELLOW}ℹ️  Terraform skipped the billing grants (see the warning before the plan). Control Center > Settings shows which service account lacks Billing Account User and the fix.${RESET}"
        fi
        PROV_SA="serviceAccount:sa-project-provisioner@${PROJECT_ID}.iam.gserviceaccount.com"
        DEV_SA="serviceAccount:sa-castor-developer@${PROJECT_ID}.iam.gserviceaccount.com"
        CC_SA="serviceAccount:${SV_BILLING_VIEWER_SA}@${PROJECT_ID}.iam.gserviceaccount.com"
        echo -e "\n${BLUE}==>${RESET} Grant billing roles on billing account ${BOLD}${CLEAN_BILLING}${RESET} (requires Billing Account Administrator):"
        echo -e "     roles/billing.user   -> ${PROV_SA}\n     roles/billing.user   -> ${DEV_SA}"
        echo -e "     roles/billing.viewer -> ${CC_SA}"
        echo -e "   (billing.user: child-project billing linkage; billing.viewer: the Control Center Settings billing card)."
        read -r -p "Grant these three billing bindings now? (Y/n): " CONFIRM_BILLING
        CONFIRM_BILLING=${CONFIRM_BILLING:-Y}
        BILLING_GRANTS_OK=0
        if [[ "$CONFIRM_BILLING" =~ ^[Yy]$ ]]; then
            for BG_PAIR in "${PROV_SA}|roles/billing.user" "${DEV_SA}|roles/billing.user" "${CC_SA}|roles/billing.viewer"; do
                if gcloud billing accounts add-iam-policy-binding "${CLEAN_BILLING}" --member="${BG_PAIR%%|*}" --role="${BG_PAIR#*|}" --quiet >/dev/null 2>&1; then
                    BILLING_GRANTS_OK=$((BILLING_GRANTS_OK + 1))
                    echo -e "${GREEN}[OK]${RESET} Granted ${BG_PAIR#*|} to ${BG_PAIR%%|*}."
                fi
            done
        fi
        if [ "${BILLING_GRANTS_OK}" -lt 3 ]; then
            echo -e "${YELLOW}ℹ️  Note:${RESET} not every billing binding was granted (declined, or not a Billing Account Administrator for ${CLEAN_BILLING}); the platform installed cleanly."
            sv_billing_post_install_step "${CLEAN_BILLING}"
        fi
    fi
fi
# Seed Deploying Administrator in Firestore authorized_users
if [ -n "$ACTIVE_ACCOUNT" ]; then
    echo -e "\n${BLUE}==>${RESET} Authorizing deploying administrator (${BOLD}${ACTIVE_ACCOUNT}${RESET}) in Firestore..."
    ACCESS_TOKEN=$(gcloud auth print-access-token 2>/dev/null || true)
    if [ -n "$ACCESS_TOKEN" ]; then
        NOW_UTC=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
        # FD-4M H3: doc ID lowercased (the Control Center looks users up by lowercase email);
        # is_active is a real boolean (a string "false" would otherwise read as active).
        ADMIN_DOC_ID=$(printf '%s' "$ACTIVE_ACCOUNT" | tr '[:upper:]' '[:lower:]')
        # -f so an HTTP error is a failure; never fatal (the Control Center admits ADMIN_EMAIL without the record).
        if curl -fsS -X PATCH \
            -H "Authorization: Bearer ${ACCESS_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "{\"fields\": {\"email\": {\"stringValue\": \"${ADMIN_DOC_ID}\"}, \"role\": {\"stringValue\": \"ADMIN\"}, \"is_active\": {\"booleanValue\": true}, \"added_by\": {\"stringValue\": \"bootstrap\"}, \"added_at\": {\"stringValue\": \"${NOW_UTC}\"}}}" \
            "https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/authorized_users/${ADMIN_DOC_ID}" >/dev/null; then
            echo -e "${GREEN}[OK]${RESET} Registered ${BOLD}${ACTIVE_ACCOUNT}${RESET} as Platform Administrator in Firestore."
        else
            echo -e "${YELLOW}[WARN]${RESET} Could not write authorized_users/${ADMIN_DOC_ID} (the Control Center still admits it as ADMIN_EMAIL)"
        fi
    else
        echo -e "${YELLOW}[WARN]${RESET} Could not write authorized_users/${ADMIN_DOC_ID:-${ACTIVE_ACCOUNT}} (no access token; the Control Center still admits it as ADMIN_EMAIL)"
    fi
fi

# Seed initial Platform Settings in Firestore
if [ -n "$VCS_PROVIDER" ]; then
    echo -e "\n${BLUE}==>${RESET} Initializing platform settings in Firestore (VCS: ${BOLD}${VCS_PROVIDER}${RESET})..."
    ACCESS_TOKEN=$(gcloud auth print-access-token 2>/dev/null || true)
    if [ -n "$ACCESS_TOKEN" ]; then
        if curl -fsS -X PATCH \
            -H "Authorization: Bearer ${ACCESS_TOKEN}" \
            -H "Content-Type: application/json" \
            -d "{\"fields\": {\"governance\": {\"mapValue\": {\"fields\": {\"vcs_provider\": {\"stringValue\": \"${VCS_PROVIDER}\"}}}}}}" \
            "https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/(default)/documents/system_config/platform_settings?updateMask.fieldPaths=governance.vcs_provider" >/dev/null; then
            echo -e "${GREEN}[OK]${RESET} Registered default VCS provider (${BOLD}${VCS_PROVIDER}${RESET}) in platform settings."
        else
            echo -e "${YELLOW}[WARN]${RESET} Default VCS not stored; set it in Control Center > Settings"
        fi
    else
        echo -e "${YELLOW}[WARN]${RESET} Default VCS not stored (no access token); set it in Control Center > Settings"
    fi
fi

# Gemini AI credentials (FD28-07): Secret Manager + secret reference, never a plaintext env var. The installer no
# longer asks for a key (BOOTSTRAP-NO-GEMINI-KEY-PROMPT); an ENABLED version already in castor-gemini-api-key is
# still wired into the Control Center, otherwise the assistant uses Vertex AI through IAM.
GEMINI_SECRET_READY="$(gcloud secrets versions list castor-gemini-api-key --project="${PROJECT_ID}" --filter="state=ENABLED" --limit=1 --format="value(name)" 2>/dev/null)" || GEMINI_SECRET_READY=""
if [ -n "${GEMINI_SECRET_READY}" ]; then
    echo -e "${BLUE}==>${RESET} Wiring GEMINI_API_KEY into the Control Center as a Secret Manager reference..."
    gcloud run services update product-control-center-ui \
        --update-secrets="GEMINI_API_KEY=castor-gemini-api-key:latest" \
        --region="${REGION}" --project="${PROJECT_ID}" --quiet \
        || { echo -e "${RED}[ERROR]${RESET} Could not wire the Gemini key secret into the Control Center."; exit 1; }
    if [ "${GEMINI_FLAG_WRITTEN}" != "true" ]; then
        # Same-run generated file: record it so the next apply keeps (not strips) the secret ref.
        echo 'cc_gemini_api_key_from_secret      = true' >> "${TFVARS_PATH}"
        GEMINI_FLAG_WRITTEN=true
    fi
    echo -e "${GREEN}[OK]${RESET} Gemini API Key is served from Secret Manager (castor-gemini-api-key)."
else
    echo -e "\n${GREEN}[OK]${RESET} StackVend Assistant will use Google Cloud Vertex AI natively via IAM."
fi

# Tenant sign-in client secret (lane 19 L19-0d): Secret Manager only, after the apply created the container.
# The container stackvend-tenant-google-client-secret comes from lane 19 L19-10 (infra/platform); if it does not
# exist yet the secret is NOT stored anywhere else (never castor-oauth-client-secret).
if [ -n "$TENANT_CLIENT_SECRET" ]; then
    if gcloud secrets describe stackvend-tenant-google-client-secret --project="${PROJECT_ID}" --format="value(name)" >/dev/null 2>&1; then
        echo -e "\n${BLUE}==>${RESET} Storing the tenant sign-in client secret in Secret Manager..."
        if ! printf '%s' "$TENANT_CLIENT_SECRET" | gcloud secrets versions add stackvend-tenant-google-client-secret --project="${PROJECT_ID}" --data-file=- --quiet >/dev/null; then
            unset TENANT_CLIENT_SECRET
            echo -e "${RED}[ERROR]${RESET} Could not add the tenant sign-in client secret (stackvend-tenant-google-client-secret)."
            sv_tenant_secret_not_stored "the Secret Manager write failed."
            exit 1
        fi
        echo -e "${GREEN}[OK]${RESET} Tenant sign-in client secret stored (stackvend-tenant-google-client-secret)."
    else
        sv_tenant_secret_not_stored "the Secret Manager container stackvend-tenant-google-client-secret does not exist yet."
    fi
fi
unset TENANT_CLIENT_SECRET

# ------------------------------------------------------------------------------
# 8. Deploy Cloud Run Microservices from Source
# ------------------------------------------------------------------------------
# RC F12: always offered: every service runs the placeholder image until this first deploy.
echo -e "\n${GREEN}${BOLD}==============================================================================${RESET}"
echo -e "${GREEN}${BOLD}  STAGE 1 COMPLETE: CLOUD INFRASTRUCTURE PROVISIONED! 🏗️${RESET}"
echo -e "${GREEN}${BOLD}==============================================================================${RESET}"
echo -e "Platform successfully created all APIs, databases, networks, and Cloud Run service skeletons.\n"

echo -e "${CYAN}${BOLD}Stage 2: Compile & Deploy Application Microservices & Platform Jobs${RESET}"
# RC F10: realistic numbers. deploy-services.sh --all-jobs builds 13 services (+ the Serverless Git server when
# it is used) and 9 batch jobs from source with Cloud Buildpacks, 3 builds at a time, then points the tf-applier
# job at the Terraform server's image. About 30-50 minutes (RC install runbook estimate).
echo -e "This builds the platform services (13, plus the Serverless Git server when used) and 9 batch jobs from source with"
echo -e "Cloud Buildpacks, 3 at a time, then points the tf-applier job at the Terraform server's image. Expect 30-50 minutes.\n"
read -r -p "Build and deploy the services and jobs from source now? (Y/n): " CONFIRM_DEPLOY
CONFIRM_DEPLOY=${CONFIRM_DEPLOY:-Y}

# Stage 2 result: ok | failed | skipped. deploy-services.sh writes "<succeeded> <failed> <skipped>" to
# STACKVEND_DEPLOY_SUMMARY_FILE at its summary; an empty file means it stopped before the summary.
STAGE2_STATUS="skipped"
STAGE2_DETAIL="skipped"
DEPLOY_HINT="PROJECT_ID=${PROJECT_ID} REGION=${REGION} bash scripts/deploy-services.sh --all-jobs"
if [[ "$CONFIRM_DEPLOY" =~ ^[Yy]$ ]]; then
    STAGE2_SUMMARY_FILE="$(mktemp)" || STAGE2_SUMMARY_FILE=""
    if STACKVEND_DEPLOY_SUMMARY_FILE="${STAGE2_SUMMARY_FILE}" PROJECT_ID="${PROJECT_ID}" REGION="${REGION}" bash "${REPO_ROOT}/scripts/deploy-services.sh" --all-jobs; then
        STAGE2_STATUS="ok"
    else
        STAGE2_STATUS="failed"
        S2_OK=""; S2_FAILED=""; S2_SKIPPED=""
        if [ -n "${STAGE2_SUMMARY_FILE}" ] && [ -s "${STAGE2_SUMMARY_FILE}" ]; then
            read -r S2_OK S2_FAILED S2_SKIPPED < "${STAGE2_SUMMARY_FILE}" || true
        fi
        if [[ "${S2_FAILED}" =~ ^[0-9]+$ ]]; then
            STAGE2_DETAIL="${S2_FAILED} failed"
        else
            STAGE2_DETAIL="deploy-services.sh stopped before its summary"
        fi
        echo -e "${YELLOW}⚠️  Warning: stage 2 did not finish (${STAGE2_DETAIL}; see the Deployment Summary above).${RESET}"
        echo -e "   Fix the cause, then re-run: ${BOLD}${DEPLOY_HINT}${RESET}"
    fi
    if [ -n "${STAGE2_SUMMARY_FILE}" ]; then rm -f "${STAGE2_SUMMARY_FILE}"; fi
else
    echo -e "\n${YELLOW}ℹ️  Skipped microservices and jobs deployment.${RESET} The services keep their placeholder image until you run:"
    echo -e "   ${BOLD}${DEPLOY_HINT}${RESET}"
fi

# ------------------------------------------------------------------------------
# 9. Deployment Summary & Outputs
# ------------------------------------------------------------------------------
if [ "${STAGE2_STATUS}" = "ok" ]; then
    echo -e "\n${GREEN}${BOLD}==============================================================================${RESET}"
    echo -e "${GREEN}${BOLD}  STACKVEND PLATFORM BOOTSTRAP COMPLETE! 🎉${RESET}"
    echo -e "${GREEN}${BOLD}==============================================================================${RESET}\n"
else
    echo -e "\n${YELLOW}${BOLD}==============================================================================${RESET}"
    echo -e "${YELLOW}${BOLD}  BOOTSTRAP INCOMPLETE: stage 2 did not finish (${STAGE2_DETAIL}).${RESET}"
    echo -e "${YELLOW}${BOLD}==============================================================================${RESET}\n"
fi

echo -e "${BOLD}Platform Overview & Endpoints:${RESET}"
GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth print-access-token) "${IAC_BIN}" output
CC_URL="$(GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth print-access-token) "${IAC_BIN}" output -raw control_center_url 2>/dev/null)" || CC_URL=""
[ -n "${CC_URL}" ] || CC_URL="the control_center_url above"

# TFVARS-AUTO-BACKUP (owner 11-16): the vars file is not committed, so copy it next to the platform state
# (gs://${STATE_BUCKET}/platform/<id>.tfvars; an earlier copy that differs is kept as .prev-<UTC>). scripts/apply.sh
# refreshes it after every apply and offers to restore it when the local file is missing. The install already
# succeeded, so a failure is the typed warning BOOTSTRAP_TFVARS_BACKUP_NOT_WRITTEN plus a Next Steps item
# (documentation/fail-loudly-policy.md section 2).
TFVARS_BACKUP_RETRY="PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply (a run with no changes only refreshes the backup)"
TFVARS_BACKUP_OK=""
echo -e "\n${BLUE}==>${RESET} Backing up ${TFVARS_PATH} to ${BOLD}$(sv_tfvars_backup_uri "${STATE_BUCKET}")${RESET}..."
if sv_tfvars_backup_write BOOTSTRAP "${TFVARS_PATH}" "${TFVARS_BACKUP_RETRY}"; then
    TFVARS_BACKUP_OK=1
fi

echo -e "\n${BOLD}Next Steps:${RESET}"
STEP=0
sv_step() { STEP=$((STEP + 1)); echo "${STEP}. $1"; }
if [ "${STAGE2_STATUS}" != "ok" ]; then
    sv_step "Finish stage 2 (the services still run their placeholder image): ${DEPLOY_HINT}"
fi
if [ "${VCS_PROVIDER}" = "GITHUB" ]; then
    # RC F8: required before the first workload with the GitHub provider (documentation/quickstart.md "GitHub App").
    sv_step "Before the first workload: store your GitHub App credentials (app_id, installation_id, private_key; optional pat)"
    echo "   as a new version of the Secret Manager secret castor-github-app-private-key:"
    echo "   gcloud secrets versions add castor-github-app-private-key --project=${PROJECT_ID} --data-file=<app.json>"
    echo "   (documentation/quickstart.md \"GitHub App\"; Control Center > Settings shows the VCS status)."
else
    sv_step "Serverless Git: no GitHub credentials needed. There is no pull request page: every release waits for your"
    echo "   approval in the Control Center (HITL Approvals tab)."
fi
sv_step "After you pull a newer StackVend release, redeploy the services and jobs:"
echo "   ${DEPLOY_HINT}"
echo "   and, first, when files under infra/platform/ changed: PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply"
if [ -n "${CC_CLIENT_ID}" ]; then
    # RC F4: the hashed run.app form is only known now; the deterministic form was printed before the install.
    sv_step "Add the control_center_url above to the Control Center OAuth client's Authorized JavaScript origins"
    echo "   if it is not there yet (Google Auth Platform > Clients in ${PROJECT_ID})."
fi
if [ -z "${TFVARS_BACKUP_OK}" ]; then
    # TFVARS-AUTO-BACKUP: repeated here so it is not lost in the scrollback.
    sv_step "Back up infra/platform/${PROJECT_ID}.tfvars (the automatic backup failed: BOOTSTRAP_TFVARS_BACKUP_NOT_WRITTEN above):"
    echo "   ${TFVARS_BACKUP_RETRY}"
fi
# Who can open the Control Center.
sv_step "Open the Control Center signed in as ${ACTIVE_ACCOUNT}: ${CC_URL}"
if [ "$ENABLE_IAP" = "true" ]; then
    echo "   To admit someone else: add them to authorized_invoker_members in infra/platform/${PROJECT_ID}.tfvars and run"
    echo "   PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh apply (gets them past IAP), AND add them as a Control Center user"
    echo "   (signed in as an ADMIN). They need both, and an organization account."
else
    echo "   To admit someone else: add them as a Control Center user (signed in as an ADMIN)."
fi
if [ -n "${BILLING_ACCESS_MISSING}" ]; then
    # Repeated here so it is not lost in the scrollback (Settings shows it too).
    sv_step "Billing access is still missing on billing account ${BILLING_ACCESS_MISSING}: the first workload stops at vending with BILLING_NOT_LINKED."
    sv_billing_fix_commands "${BILLING_ACCESS_MISSING}"
fi
if [ -n "${SV_TAG_PREFLIGHT_WARNING}" ]; then
    # Lane 18 v3: repeated here so it is not lost in the apply output (Settings shows it too).
    echo -e "\n${YELLOW}⚠️  WARNING:${RESET} ${SV_TAG_PREFLIGHT_WARNING}"
elif [ "${SV_TAG_PREFLIGHT_RESULT}" = "not-applicable" ]; then
    # BOOTSTRAP-TAG-ADMIN-CONFIRM: no organization / managed folder (answered yes at the question before the apply).
    echo -e "\n${YELLOW}⚠️  WARNING:${RESET} No deletion safety tag (no organization ID or managed workloads folder ID): StackVend cannot delete or decommission the projects it creates. Control Center Settings shows the fix."
fi
if [ -n "${SV_ORGPOL_PREFLIGHT_WARNING}" ]; then
    # ORG-POLICY-FOLDER: repeated here so it is not lost in the apply output (each vend records it too).
    echo -e "\n${YELLOW}⚠️  WARNING:${RESET} ${SV_ORGPOL_PREFLIGHT_WARNING}"
fi
if [ "${STAGE2_STATUS}" = "ok" ]; then
    echo -e "\n${GREEN}StackVend is installed. Open the Control Center: ${CC_URL}${RESET}\n"
else
    echo -e "\n${YELLOW}BOOTSTRAP INCOMPLETE: stage 2 did not finish (${STAGE2_DETAIL}). Run: ${DEPLOY_HINT}${RESET}\n"
fi
