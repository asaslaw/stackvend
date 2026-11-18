#!/usr/bin/env bash
# ==============================================================================
# STACKVEND: PRE-BOOTSTRAP (prepare a Google Cloud organization for scripts/bootstrap.sh)
# ==============================================================================
# Automates documentation/quickstart.md section 1, "Prepare the host project and folder":
#   1. read-only rights pre-check for the signed-in account (every row of the quickstart table "Minimum
#      permissions for the installer", tested with testIamPermissions on the resource it applies to);
#      a missing BLOCKING right stops here, before any write (PREBOOT_MISSING_RIGHTS), with the grant commands;
#   2. host project: an existing one (never created) or a new one;
#   3. billing link (an existing link is never changed);
#   4. managed-workloads folder: an existing one (never created) or a new one by name;
#   5. optional grants for the person who will run bootstrap (--grant-to); then, in a terminal, when rows 7 / 8
#      (Tag Administrator, Organization Policy Administrator) are missing for that person and the signed-in account
#      can set IAM on the organization, it offers each organization grant (type yes; never with --yes);
#   6. the answers for bootstrap's prompts.
#
# Every step checks first and acts only when something is missing ([OK] ... already ... / [DONE] ...).
# It never deletes, never changes an existing billing link, IAM binding or gcloud configuration, and touches
# no platform code or state. Safe to re-run. --dry-run prints every write command and makes none;
# --check-only runs only the rights pre-check. Failures stop with a typed code
# PREBOOT_<REASON>: <what happened + the fix>, non-zero exit.
#
# Needs only gcloud, curl and python3 (stdlib). Bash 3.2 compatible (macOS /bin/bash).
# Run `bash scripts/pre-bootstrap.sh --help` for the flags.
# ==============================================================================

set -euo pipefail
# gcloud must never stop at an interactive prompt of its own (this script asks its own questions). The caller's own
# value is kept for scripts/bootstrap.sh when this script starts it (BOOTSTRAP-PREFILL).
PB_ORIG_DISABLE_PROMPTS="${CLOUDSDK_CORE_DISABLE_PROMPTS-}"
PB_ORIG_DISABLE_PROMPTS_SET="${CLOUDSDK_CORE_DISABLE_PROMPTS+1}"
export CLOUDSDK_CORE_DISABLE_PROMPTS=1

BOLD="\033[1m"
GREEN="\033[0;32m"
BLUE="\033[0;34m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
CYAN="\033[0;36m"
RESET="\033[0m"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
PLATFORM_DIR="${REPO_ROOT}/infra/platform"
export REPO_ROOT PLATFORM_DIR
# sv_valid_project_id: the GCP project id grammar shared with bootstrap.sh and apply.sh.
# shellcheck source=common/platform_target.sh
. "${SCRIPT_DIR}/common/platform_target.sh"
# sv_ensure_opentofu: offer to install OpenTofu when it is missing or too old (INSTALLER-OPENTOFU-OFFER).
# shellcheck source=common/opentofu_offer.sh
. "${SCRIPT_DIR}/common/opentofu_offer.sh"

usage() {
    cat <<'EOF'
Usage: bash scripts/pre-bootstrap.sh (--existing-project <id> | --new-project <id>) [options]

Prepares a Google Cloud organization for scripts/bootstrap.sh (documentation/quickstart.md,
"Prepare the host project and folder"). First a read-only check of your rights for every row of the
quickstart's "Minimum permissions for the installer" table; then the host project, its billing link and
the managed-workloads folder, each only if missing; then what to answer at bootstrap's prompts.
Nothing existing is deleted or changed. Safe to re-run.

Host project (one of; asked for in a terminal when omitted):
  --existing-project <id>    Use this project. It must be ACTIVE and you need Owner on it; never created.
  --new-project <id>         Create this project (6-30 chars: lowercase letter first, then a-z 0-9 -,
                             no trailing hyphen). A re-run finds it and reuses it if it is under the
                             expected parent; elsewhere it is refused (use --existing-project).

Managed-workloads folder (one of; default: a new folder named <project-id>-workloads):
  --existing-folder <ID>     Use this folder (folders/<n> or <n>); never created.
  --folder-name <name>       Create a folder with this display name (reused if exactly one ACTIVE folder
                             with that name already exists under the parent). Folder display names are
                             at most 30 characters (letters, digits, spaces, hyphens, underscores), so
                             the default only works for project ids of at most 19 characters.

Options:
  --org <ORG_NUM>            Organization number (or organizations/<n>). Default: the only organization
                             `gcloud organizations list` shows; with more than one you are asked
                             (refused when not in a terminal).
  --billing-account <ID>     Billing account id (01XXXX-XXXXXX-XXXXXX). Default: the only OPEN account
                             `gcloud billing accounts list` shows; same rule.
  --parent-folder <ID>       Create the new folder (and the new project) under this folder instead of the
                             organization.
  --project-parent-org       With --parent-folder: create the new project under the organization anyway.
  --grant-to <user:email>    The person who will run bootstrap, when that is not you: grants them Owner on
                             the project and Folder IAM Admin on the folder (each only if missing).
  --check-only               Run only the read-only rights pre-check, then exit: 0 = no BLOCKING right
                             missing, 1 = a BLOCKING right is missing, 2 = a BLOCKING right could not
                             be checked.
  --dry-run                  Print every write command it would run; make no write.
  --yes                      No confirmation prompts (and bootstrap is not started: its command is printed).

Organization roles (rows 7 and 8): when Tag Administrator or Organization Policy Administrator is missing for
the person who runs bootstrap (you, or --grant-to) and you can get and set IAM on the organization, a real run
in a terminal asks "Grant ... on organizations/<n> to <member> now? This is organization-wide: ..." for each
one; only typing the full word yes grants it (add-only, on the organization; then it re-checks while IAM
propagates). Enter or any other answer, --yes, --check-only, no terminal, CLOUDSDK_CORE_DISABLE_PROMPTS=1, a
personal account, gcloud service-account impersonation, or a project / folder not confirmed to be in the
organization only print the grant command; --dry-run prints the command it would run.

At the end it prints the bootstrap command with the values it knows (STACKVEND_PROJECT_ID, STACKVEND_ORG_ID,
STACKVEND_BILLING_ACCOUNT_ID, STACKVEND_FOLDER_ID: the defaults of bootstrap's prompts). After a real run in a
terminal it asks whether to start it now (not with --yes, --dry-run, --check-only or --grant-to someone else).
A new account must accept the Google Cloud Terms of Service once (open console.cloud.google.com as that account) before bootstrap can enable APIs.
  -h, --help                Show this help.

Examples:
  bash scripts/pre-bootstrap.sh --new-project my-stackvend-host
  bash scripts/pre-bootstrap.sh --existing-project my-host --existing-folder 123456789012 --check-only
EOF
}

pb_fail() {
    # $1 = exit code, $2 = REASON (printed as PREBOOT_<REASON>), rest = message with the fix
    local code="$1" reason="$2"
    shift 2
    echo -e "${RED}[ERROR]${RESET} PREBOOT_${reason}: $*" >&2
    exit "${code}"
}
pb_die() { pb_fail 1 "$@"; }
pb_ok()    { echo -e "${GREEN}[OK]${RESET} $*"; }
pb_done()  { echo -e "${GREEN}[DONE]${RESET} $*"; }
pb_warn()  { echo -e "${YELLOW}[WARNING]${RESET} $*"; }
pb_info()  { echo -e "${BLUE}[INFO]${RESET} $*"; }
pb_step()  { echo -e "\n${BLUE}==>${RESET} ${BOLD}$*${RESET}"; }
pb_quote() {
    local out="" a q
    for a in "$@"; do
        q="$(printf '%q' "${a}")"
        out="${out:+${out} }${q}"
    done
    printf '%s' "${out}"
}
# Read-only gcloud call: stdout in PB_RO_OUT, stderr (one line) in PB_RO_ERR; returns gcloud's rc. stdout and
# stderr are kept apart, so a failed call's stdout (gcloud prints "[]" for an empty list even on
# PERMISSION_DENIED) never ends up in a message. Call it directly (not in $(...)) so the globals survive.
PB_RO_OUT=""
PB_RO_ERR=""
pb_gread() {
    local errf rc=0
    PB_RO_OUT=""
    PB_RO_ERR=""
    errf="$(mktemp 2>/dev/null)" || errf="/dev/null"
    PB_RO_OUT="$("$@" 2>"${errf}")" || rc=$?
    if [ "${errf}" != "/dev/null" ]; then
        PB_RO_ERR="$(tr '\n' ' ' < "${errf}" | sed -e 's/  */ /g' -e 's/ *$//')"
        rm -f "${errf}"
    fi
    return "${rc}"
}
# State facts that need a person's decision (not a missing right) are collected while reading and refused
# after the full rights table, so one run reports everything: "<REASON>\t<message>" lines.
PB_DEFERRED=""
pb_defer() {
    PB_DEFERRED="${PB_DEFERRED}$1${PB_TAB}$2
"
}
pb_lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
pb_upper() { printf '%s' "$1" | tr '[:lower:]' '[:upper:]'; }

# ------------------------------------------------------------------------------
# JSON helpers (python3 stdlib; data on stdin). Exit 3 = unparseable input.
# ------------------------------------------------------------------------------
PB_TAB=$'\t'
PB_PY=""
read -r -d '' PB_PY <<'PYEOF' || true
import json, sys
mode, args = sys.argv[1], sys.argv[2:]
try:
    doc = json.load(sys.stdin)
except ValueError:
    sys.exit(3)

def strip(v, prefix):
    v = v if isinstance(v, str) else ""
    return v[len(prefix):] if v.startswith(prefix) else v

if mode == "orgs":
    for o in doc if isinstance(doc, list) else []:
        print("%s\t%s" % (strip(o.get("name"), "organizations/"), o.get("displayName", "")))
elif mode == "billing_open":
    for b in doc if isinstance(doc, list) else []:
        if b.get("open") is True:
            print("%s\t%s" % (strip(b.get("name"), "billingAccounts/"), b.get("displayName", "")))
elif mode == "project":
    if not isinstance(doc, dict):
        sys.exit(3)
    # Parent printed as a resource name: organizations/<n> or folders/<n> (gcloud shows type "organization").
    parent = doc.get("parent") or {}
    ptype = parent.get("type", "")
    ptype = {"organization": "organizations", "folder": "folders"}.get(ptype, ptype)
    print("%s\t%s/%s" % (doc.get("lifecycleState", ""), ptype, parent.get("id", "")))
elif mode == "folder":
    if not isinstance(doc, dict):
        sys.exit(3)
    print("%s\t%s\t%s" % (doc.get("lifecycleState") or doc.get("state") or "", doc.get("parent", ""),
                          doc.get("displayName", "")))
elif mode == "ancestors":
    # gcloud projects get-ancestors --format=json: [{"id": "...", "type": "organization"}, ...]
    for a in doc if isinstance(doc, list) else []:
        t = {"organization": "organizations", "folder": "folders", "project": "projects"}.get(a.get("type"), a.get("type"))
        print("%s/%s" % (t, a.get("id", "")))
elif mode == "count":
    print(len(doc) if isinstance(doc, list) else 0)
elif mode == "error_message":
    err = doc.get("error") if isinstance(doc, dict) else None
    print((err or {}).get("message", "") if isinstance(err, dict) else "")
elif mode == "billing":
    if not isinstance(doc, dict):
        sys.exit(3)
    print("%s\t%s" % ("true" if doc.get("billingEnabled") is True else "false",
                      strip(doc.get("billingAccountName"), "billingAccounts/")))
elif mode == "folders":
    # Exact display-name match; prints "folders/<n>\t<state>" (v2 lifecycleState or v3 state).
    for f in doc if isinstance(doc, list) else []:
        if f.get("displayName") == args[0]:
            print("%s\t%s" % (f.get("name", ""), f.get("lifecycleState") or f.get("state") or ""))
elif mode == "has_binding":
    role, member = args[0], args[1].lower()
    for b in (doc.get("bindings") or []) if isinstance(doc, dict) else []:
        if b.get("role") == role and not b.get("condition") and member in [m.lower() for m in b.get("members") or []]:
            sys.exit(0)
    sys.exit(1)
elif mode == "granted":
    perms = doc.get("permissions", []) if isinstance(doc, dict) else None
    if not isinstance(perms, list):
        sys.exit(3)
    for p in perms:
        print(p)
else:
    sys.exit(2)
PYEOF
pb_py() { python3 -c "${PB_PY}" "$@"; }

# ------------------------------------------------------------------------------
# Flags (validated before any gcloud call)
# ------------------------------------------------------------------------------
PB_PROJECT=""
PB_PROJECT_MODE=""        # existing | new
PB_FOLDER_ARG=""
PB_FOLDER_MODE=""         # existing | new
PB_FOLDER_NAME=""
PB_ORG=""
PB_BILLING=""
PB_PARENT_FOLDER=""
PB_PROJECT_PARENT_ORG=""
PB_GRANT_TO=""
PB_CHECK_ONLY=""
PB_DRY_RUN=""
PB_YES=""

pb_need_value() {
    [ "$2" -ge 2 ] || pb_die USAGE "$1 needs a value. See: bash scripts/pre-bootstrap.sh --help"
}
pb_set_project() {
    # $1 = mode, $2 = id
    if [ -n "${PB_PROJECT_MODE}" ]; then
        pb_die USAGE "use exactly one of --existing-project and --new-project."
    fi
    PB_PROJECT_MODE="$1"
    PB_PROJECT="$2"
}
pb_set_folder() {
    if [ -n "${PB_FOLDER_MODE}" ]; then
        pb_die USAGE "use at most one of --existing-folder and --folder-name."
    fi
    PB_FOLDER_MODE="$1"
    if [ "$1" = "existing" ]; then PB_FOLDER_ARG="$2"; else PB_FOLDER_NAME="$2"; fi
}
while [ $# -gt 0 ]; do
    case "$1" in
        --existing-project) pb_need_value "$1" $#; pb_set_project existing "$2"; shift 2 ;;
        --existing-project=*) pb_set_project existing "${1#*=}"; shift ;;
        --new-project) pb_need_value "$1" $#; pb_set_project new "$2"; shift 2 ;;
        --new-project=*) pb_set_project new "${1#*=}"; shift ;;
        --existing-folder) pb_need_value "$1" $#; pb_set_folder existing "$2"; shift 2 ;;
        --existing-folder=*) pb_set_folder existing "${1#*=}"; shift ;;
        --folder-name) pb_need_value "$1" $#; pb_set_folder new "$2"; shift 2 ;;
        --folder-name=*) pb_set_folder new "${1#*=}"; shift ;;
        --org) pb_need_value "$1" $#; PB_ORG="$2"; shift 2 ;;
        --org=*) PB_ORG="${1#*=}"; shift ;;
        --billing-account) pb_need_value "$1" $#; PB_BILLING="$2"; shift 2 ;;
        --billing-account=*) PB_BILLING="${1#*=}"; shift ;;
        --parent-folder) pb_need_value "$1" $#; PB_PARENT_FOLDER="$2"; shift 2 ;;
        --parent-folder=*) PB_PARENT_FOLDER="${1#*=}"; shift ;;
        --project-parent-org) PB_PROJECT_PARENT_ORG=1; shift ;;
        --grant-to) pb_need_value "$1" $#; PB_GRANT_TO="$2"; shift 2 ;;
        --grant-to=*) PB_GRANT_TO="${1#*=}"; shift ;;
        --check-only) PB_CHECK_ONLY=1; shift ;;
        --dry-run) PB_DRY_RUN=1; shift ;;
        --yes|-y) PB_YES=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) pb_die USAGE "unknown argument '$1'. See: bash scripts/pre-bootstrap.sh --help" ;;
    esac
done

PB_TTY=""
if [ -t 0 ]; then
    PB_TTY=1
fi

pb_ask_existing_or_new() {
    # $1 = what (project|folder); prints existing|new. PREBOOTSTRAP-NUMBERED-CHOICE (owner 11-12): answer 1 or 2;
    # the words existing/new (and e/n) are still accepted.
    local answer=""
    echo "   1) Use an existing $1" >&2
    echo "   2) Create a new $1" >&2
    read -r -p "Choose 1 or 2: " answer || answer=""
    case "$(pb_lower "${answer}")" in
        1|e|existing) echo existing ;;
        2|n|new) echo new ;;
        *) pb_die CHOICE_INVALID "answer 1 (use an existing $1) or 2 (create a new one) (got '${answer}')." ;;
    esac
}

if [ -z "${PB_PROJECT_MODE}" ]; then
    [ -n "${PB_TTY}" ] || pb_die PROJECT_REQUIRED "no host project. Pass --existing-project <id> or --new-project <id>."
    PB_PROJECT_MODE="$(pb_ask_existing_or_new project)"
    read -r -p "Host project id: " PB_PROJECT || PB_PROJECT=""
fi
[ -n "${PB_PROJECT}" ] || pb_die PROJECT_REQUIRED "no host project id. Pass --existing-project <id> or --new-project <id>."
if ! sv_valid_project_id "${PB_PROJECT}"; then
    pb_die PROJECT_ID_INVALID "'${PB_PROJECT}' is not a valid project id: 6 to 30 characters, a lowercase letter first, then lowercase letters, digits and hyphens, not ending in a hyphen."
fi
if [ -z "${PB_FOLDER_MODE}" ]; then
    if [ -n "${PB_TTY}" ] && [ -z "${PB_YES}" ]; then
        PB_FOLDER_MODE="$(pb_ask_existing_or_new "managed-workloads folder")"
        if [ "${PB_FOLDER_MODE}" = "existing" ]; then
            read -r -p "Folder id (folders/<n> or <n>): " PB_FOLDER_ARG || PB_FOLDER_ARG=""
        elif [ "${#PB_PROJECT}" -le 19 ]; then
            read -r -p "Folder name, at most 30 characters [${PB_PROJECT}-workloads]: " PB_FOLDER_NAME || PB_FOLDER_NAME=""
        else
            # <project-id>-workloads would be longer than the 30-character folder name limit: no default.
            while [ -z "${PB_FOLDER_NAME}" ]; do
                read -r -p "Folder name (at most 30 characters; '${PB_PROJECT}-workloads' is too long): " PB_FOLDER_NAME \
                    || pb_die FOLDER_NAME_INVALID "no folder name given. Pass --folder-name <name> (at most 30 characters)."
            done
        fi
    else
        PB_FOLDER_MODE="new"
    fi
fi
if [ "${PB_FOLDER_MODE}" = "existing" ]; then
    PB_FOLDER_ARG="${PB_FOLDER_ARG#folders/}"
    [[ "${PB_FOLDER_ARG}" =~ ^[0-9]+$ ]] || pb_die FOLDER_ID_INVALID "--existing-folder must be a folder number (or folders/<n>), as 'gcloud resource-manager folders list' shows it under ID."
else
    PB_FOLDER_NAME="${PB_FOLDER_NAME:-${PB_PROJECT}-workloads}"
    # Google Cloud folder display names: 1-30 characters (letters, digits, spaces, hyphens, underscores),
    # a letter or digit at both ends.
    if ! [[ "${PB_FOLDER_NAME}" =~ ^[A-Za-z0-9]([A-Za-z0-9\ _-]{0,28}[A-Za-z0-9])?$ ]]; then
        pb_die FOLDER_NAME_INVALID "folder name '${PB_FOLDER_NAME}' is not a valid folder display name (1-30 characters: letters, digits, spaces, hyphens, underscores; a letter or digit at both ends). Pass --folder-name <name>."
    fi
fi
if [ -n "${PB_ORG}" ]; then
    PB_ORG="${PB_ORG#organizations/}"
    [[ "${PB_ORG}" =~ ^[0-9]+$ ]] || pb_die ORG_INVALID "--org must be the organization number (or organizations/<n>), as 'gcloud organizations list' shows it under ID."
fi
if [ -n "${PB_BILLING}" ]; then
    PB_BILLING="${PB_BILLING#billingAccounts/}"
    [[ "${PB_BILLING}" =~ ^[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6}-[0-9A-Fa-f]{6}$ ]] \
        || pb_die BILLING_INVALID "--billing-account must look like 01XXXX-XXXXXX-XXXXXX (as 'gcloud billing accounts list' shows it under ACCOUNT_ID)."
    PB_BILLING="$(pb_upper "${PB_BILLING}")"
fi
if [ -n "${PB_PARENT_FOLDER}" ]; then
    PB_PARENT_FOLDER="${PB_PARENT_FOLDER#folders/}"
    [[ "${PB_PARENT_FOLDER}" =~ ^[0-9]+$ ]] || pb_die PARENT_FOLDER_INVALID "--parent-folder must be a folder number (or folders/<n>)."
fi
if [ -n "${PB_PROJECT_PARENT_ORG}" ] && [ -z "${PB_PARENT_FOLDER}" ]; then
    pb_die USAGE "--project-parent-org only applies with --parent-folder (without it a new project already goes under the organization)."
fi
if [ -n "${PB_GRANT_TO}" ]; then
    case "${PB_GRANT_TO}" in
        user:*) ;;
        *:*) pb_die GRANT_TO_INVALID "--grant-to must be user:<email> (the person who will run scripts/bootstrap.sh)." ;;
        *) PB_GRANT_TO="user:${PB_GRANT_TO}" ;;
    esac
    [[ "${PB_GRANT_TO#user:}" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]] \
        || pb_die GRANT_TO_INVALID "--grant-to '${PB_GRANT_TO}' is not user:<email>."
fi

for pb_tool in gcloud curl python3; do
    command -v "${pb_tool}" >/dev/null 2>&1 \
        || pb_die MISSING_TOOL "'${pb_tool}' is not on PATH. This script needs gcloud, curl and python3; install it and re-run."
done
# INSTALLER-OPENTOFU-OFFER (owner 11-10): scripts/bootstrap.sh needs OpenTofu >= SV_IAC_MIN_VERSION, so check it
# here, before any gcloud call: missing or too old -> offer to install it into ~/bin (a terminal without --yes),
# otherwise a typed stop with the manual commands. Silent when the engine is usable. Not for --check-only or
# --dry-run (no install happens on those runs) nor --grant-to (someone else runs bootstrap).
if [ -z "${PB_CHECK_ONLY}" ] && [ -z "${PB_DRY_RUN}" ] && [ -z "${PB_GRANT_TO}" ]; then
    pb_tofu_tty=""
    if [ -n "${PB_TTY}" ] && [ -z "${PB_YES}" ]; then pb_tofu_tty=1; fi
    sv_ensure_opentofu PREBOOT "${pb_tofu_tty}"
fi

echo -e "${BLUE}${BOLD}StackVend pre-bootstrap${RESET}: prepare the host project and folder for scripts/bootstrap.sh"
if [ -n "${PB_CHECK_ONLY}" ]; then
    echo -e "${CYAN}[CHECK-ONLY]${RESET} Only the read-only rights pre-check runs; nothing is changed."
elif [ -n "${PB_DRY_RUN}" ]; then
    echo -e "${CYAN}[DRY-RUN]${RESET} No changes will be made; every write command is printed instead."
fi

# Runs a write command, or prints it under --dry-run. Output in PB_OUT; returns the command's rc.
PB_OUT=""
pb_write() {
    PB_OUT=""
    if [ -n "${PB_DRY_RUN}" ]; then
        echo -e "${CYAN}[DRY-RUN]${RESET} would run: $(pb_quote "$@")"
        return 0
    fi
    echo -e "   running: $(pb_quote "$@")"
    local rc=0
    PB_OUT="$("$@" 2>&1)" || rc=$?
    return "${rc}"
}

pb_confirm() {
    # $1 = question. Returns 0 on yes. --yes answers yes; no terminal and no --yes answers no.
    local answer=""
    [ -z "${PB_YES}" ] || return 0
    [ -n "${PB_TTY}" ] || return 1
    read -r -p "$1 (y/N): " answer || answer=""
    [[ "${answer}" =~ ^[Yy]$ ]]
}

pb_count_lines() {
    if [ -z "$1" ]; then echo 0; else printf '%s\n' "$1" | wc -l | tr -d ' '; fi
}

pb_choose() {
    # $1 = what, $2 = lines "<id>\t<name>"; prints the chosen id.
    local what="$1" lines="$2" i=0 line answer=""
    echo -e "More than one ${what}:" >&2
    while IFS= read -r line; do
        i=$((i + 1))
        echo "  ${i}) ${line%%"${PB_TAB}"*}  ${line#*"${PB_TAB}"}" >&2
    done <<EOF
${lines}
EOF
    read -r -p "Choose the ${what} [1-${i}]: " answer || answer=""
    [[ "${answer}" =~ ^[0-9]+$ ]] && [ "${answer}" -ge 1 ] && [ "${answer}" -le "${i}" ] \
        || pb_die CHOICE_INVALID "'${answer}' is not one of 1-${i}."
    printf '%s\n' "${lines}" | sed -n "${answer}p" | cut -f1
}

# ------------------------------------------------------------------------------
# Account
# ------------------------------------------------------------------------------
pb_step "Account"
PB_ACCOUNT="$(gcloud config get-value account 2>/dev/null)" || PB_ACCOUNT=""
if [ -z "${PB_ACCOUNT}" ] || [ "${PB_ACCOUNT}" = "(unset)" ]; then
    pb_cfg="${CLOUDSDK_ACTIVE_CONFIG_NAME:-}"
    if [ -z "${pb_cfg}" ]; then
        pb_cfg="$(gcloud config configurations list --filter=is_active:true --format='value(name)' 2>/dev/null)" || pb_cfg=""
    fi
    pb_die NOT_SIGNED_IN "the gcloud configuration '${pb_cfg:-unknown}' has no active account. Run: ${CLOUDSDK_ACTIVE_CONFIG_NAME:+CLOUDSDK_ACTIVE_CONFIG_NAME=${CLOUDSDK_ACTIVE_CONFIG_NAME} }gcloud auth login you@your-org.example (see documentation/quickstart.md \"Sign in\"), then re-run."
fi
gcloud auth print-access-token >/dev/null 2>&1 \
    || pb_die NOT_SIGNED_IN "gcloud cannot get an access token for ${PB_ACCOUNT}. Run: gcloud auth login ${PB_ACCOUNT}, then re-run."
pb_ok "Signed in as ${BOLD}${PB_ACCOUNT}${RESET}${CLOUDSDK_ACTIVE_CONFIG_NAME:+ (gcloud configuration ${CLOUDSDK_ACTIVE_CONFIG_NAME})}"

# IAM member of the signed-in account, for the printed grant commands.
case "${PB_ACCOUNT}" in
    *.gserviceaccount.com) PB_ME="serviceAccount:${PB_ACCOUNT}" ;;
    *) PB_ME="user:${PB_ACCOUNT}" ;;
esac
PB_RUNNER="${PB_GRANT_TO:-${PB_ME}}"   # the principal that will run scripts/bootstrap.sh
PB_RUNNER_IS_ME=""
if [ "$(pb_lower "${PB_RUNNER}")" = "$(pb_lower "${PB_ME}")" ]; then
    PB_RUNNER_IS_ME=1
fi
PB_RUNNER_EMAIL="$(pb_lower "${PB_RUNNER#*:}")"
PB_RUNNER_PERSONAL=""
case "${PB_RUNNER_EMAIL}" in
    *@gmail.com|*@googlemail.com)
        PB_RUNNER_PERSONAL=1
        pb_warn "${PB_RUNNER_EMAIL} is a personal Google account. Direct IAP, bootstrap's default ingress, admits only"
        echo -e "          organization accounts (Google Workspace / Cloud Identity): the account that runs bootstrap becomes the"
        echo -e "          first Control Center ADMIN and the only person IAP lets in, so this account could not open it."
        echo -e "          Keep this account and use a separate gcloud configuration for StackVend instead:"
        echo -e "            gcloud config configurations create stackvend --no-activate"
        echo -e "            CLOUDSDK_ACTIVE_CONFIG_NAME=stackvend gcloud auth login you@your-org.example --no-launch-browser"
        echo -e "            CLOUDSDK_ACTIVE_CONFIG_NAME=stackvend bash scripts/pre-bootstrap.sh --${PB_PROJECT_MODE}-project ${PB_PROJECT}"
        echo -e "          (documentation/quickstart.md \"Sign in\")."
        # --check-only and --dry-run change nothing: the warning is enough there.
        if [ -z "${PB_CHECK_ONLY}" ] && [ -z "${PB_DRY_RUN}" ]; then
            pb_confirm "Continue with ${PB_RUNNER_EMAIL} anyway?" \
                || pb_die PERSONAL_ACCOUNT "${PB_RUNNER_EMAIL} is a personal account and was not confirmed. Sign in with an organization account as shown above, or pass --yes to continue anyway."
        fi
        ;;
esac

# ------------------------------------------------------------------------------
# Organization and billing account
# ------------------------------------------------------------------------------
pb_step "Organization"
# Never an early stop: an unknown organization is reported after the rights table (whose organization rows
# then show "?"). An --existing-project's ancestry can still supply it below.
PB_ORG_PROBLEM=""      # REASON<TAB>message when the organization is not known
if [ -z "${PB_ORG}" ]; then
    pb_lines=""
    if ! pb_gread gcloud organizations list --format=json; then
        PB_ORG_PROBLEM="ORG_UNKNOWN${PB_TAB}'gcloud organizations list' failed (${PB_RO_ERR:-no message}), so the organization is not known. Pass --org <ORG_NUM> (an Organization Administrator can tell you the number)."
    elif ! pb_lines="$(printf '%s' "${PB_RO_OUT}" | pb_py orgs)"; then
        PB_ORG_PROBLEM="ORG_UNKNOWN${PB_TAB}could not read the output of 'gcloud organizations list'. Pass --org <ORG_NUM>."
    else
        case "$(pb_count_lines "${pb_lines}")" in
            0) PB_ORG_PROBLEM="NO_ORGANIZATION${PB_TAB}${PB_ACCOUNT} sees no Google Cloud organization. StackVend vends projects into an organization folder; sign in with an account of your organization (documentation/quickstart.md \"Sign in\"), or pass --org <ORG_NUM>." ;;
            1) PB_ORG="${pb_lines%%"${PB_TAB}"*}" ;;
            *)
                if [ -n "${PB_TTY}" ] && [ -z "${PB_YES}" ]; then
                    PB_ORG="$(pb_choose organization "${pb_lines}")"
                else
                    PB_ORG_PROBLEM="ORG_AMBIGUOUS${PB_TAB}more than one organization ($(printf '%s\n' "${pb_lines}" | cut -f1 | tr '\n' ' ')). Pass --org <ORG_NUM>."
                fi ;;
        esac
    fi
fi
if [ -n "${PB_ORG}" ]; then
    pb_ok "Organization: organizations/${PB_ORG}"
else
    pb_warn "Organization not known yet: ${PB_ORG_PROBLEM#*"${PB_TAB}"}"
fi

# The billing account is settled in the state step below: an existing link of the project wins, and only a
# project that needs a link needs a visible account. Discovery never stops the script.
PB_BILLING_CHOICES=""   # several open accounts and no --billing-account (no terminal): "<id> <id> ..."
pb_discover_billing() {
    # Sets PB_BILLING from `gcloud billing accounts list` when exactly one OPEN account is visible (or one is
    # chosen in a terminal); otherwise leaves it empty and says why.
    local lines
    if ! pb_gread gcloud billing accounts list --format=json; then
        pb_info "'gcloud billing accounts list' failed, so no billing account is known (${PB_RO_ERR:-no message})."
        return 0
    fi
    if ! lines="$(printf '%s' "${PB_RO_OUT}" | pb_py billing_open)"; then
        pb_info "Could not read the output of 'gcloud billing accounts list', so no billing account is known."
        return 0
    fi
    case "$(pb_count_lines "${lines}")" in
        0) pb_info "${PB_ACCOUNT} sees no open billing account (no Billing Account User role on any)." ;;
        1) PB_BILLING="$(pb_upper "${lines%%"${PB_TAB}"*}")" ;;
        *)
            if [ -n "${PB_TTY}" ] && [ -z "${PB_YES}" ]; then
                PB_BILLING="$(pb_upper "$(pb_choose "billing account" "${lines}")")"
            else
                PB_BILLING_CHOICES="$(printf '%s\n' "${lines}" | cut -f1 | tr '\n' ' ')"
                pb_info "More than one open billing account (${PB_BILLING_CHOICES% }); pass --billing-account <ID> to choose."
            fi ;;
    esac
}

# Parents of what may be created (recomputed if the organization is learnt from a project's ancestry).
# PB_ORG_RES is organizations/<n>, or a placeholder while the organization is not known.
pb_parents() {
    PB_ORG_RES="organizations/${PB_ORG:-<ORG_NUM>}"
    if [ -n "${PB_PARENT_FOLDER}" ]; then
        PB_FOLDER_PARENT_FLAG="--folder=${PB_PARENT_FOLDER}"
        PB_FOLDER_PARENT="folders/${PB_PARENT_FOLDER}"
    else
        PB_FOLDER_PARENT_FLAG="--organization=${PB_ORG}"
        PB_FOLDER_PARENT="${PB_ORG_RES}"
    fi
    if [ -n "${PB_PARENT_FOLDER}" ] && [ -z "${PB_PROJECT_PARENT_ORG}" ]; then
        PB_PROJECT_PARENT_FLAG="--folder=${PB_PARENT_FOLDER}"
        PB_PROJECT_PARENT="folders/${PB_PARENT_FOLDER}"
    else
        PB_PROJECT_PARENT_FLAG="--organization=${PB_ORG}"
        PB_PROJECT_PARENT="${PB_ORG_RES}"
    fi
}
pb_parents

# Prints the grant command for $3 (role) to $2 (member) on $1 (organizations/<n> | folders/<n> | projects/<id> |
# billingAccounts/<id>).
pb_grant_cmd() {
    case "$1" in
        organizations/*) echo "gcloud organizations add-iam-policy-binding ${1#organizations/} --member=\"$2\" --role=\"$3\"" ;;
        folders/*) echo "gcloud resource-manager folders add-iam-policy-binding ${1#folders/} --member=\"$2\" --role=\"$3\"" ;;
        projects/*) echo "gcloud projects add-iam-policy-binding ${1#projects/} --member=\"$2\" --role=\"$3\"" ;;
        billingAccounts/*) echo "gcloud billing accounts add-iam-policy-binding ${1#billingAccounts/} --member=\"$2\" --role=\"$3\"" ;;
    esac
}
pb_admin_of() {
    case "$1" in
        organizations/*) echo "an Organization Administrator" ;;
        folders/*) echo "a Folder Administrator (or an Organization Administrator)" ;;
        projects/*) echo "an Owner of ${1#projects/}" ;;
        billingAccounts/*) echo "a Billing Account Administrator of ${1#billingAccounts/}" ;;
    esac
}

# ------------------------------------------------------------------------------
# Current state (read-only): project, its billing, folder
# ------------------------------------------------------------------------------
pb_step "Current state (read-only)"
PB_PROJECT_EXISTS=""
PB_PROJECT_HIDDEN=""   # --existing-project that the signed-in account cannot see
PB_FOLDER_HIDDEN=""    # --existing-folder that the signed-in account cannot see
PB_ORG_UNCONFIRMED=""  # why the project or folder is not confirmed to be in organizations/<n> (no org-role offer then)
pb_line=""
if pb_gread gcloud projects describe "${PB_PROJECT}" --format=json; then
    pb_line="$(printf '%s' "${PB_RO_OUT}" | pb_py project 2>/dev/null)" || pb_line=""
fi
if [ -n "${pb_line}" ]; then
    pb_state="${pb_line%%"${PB_TAB}"*}"
    pb_parent="${pb_line#*"${PB_TAB}"}"
    PB_PROJECT_EXISTS=1
    # Ancestry (read-only): confirms the organization, or supplies it when it is not known yet.
    pb_anc=""
    if pb_gread gcloud projects get-ancestors "${PB_PROJECT}" --format=json; then
        pb_anc="$(printf '%s' "${PB_RO_OUT}" | pb_py ancestors 2>/dev/null)" || pb_anc=""
    fi
    pb_anc_org="$(printf '%s\n' "${pb_anc}" | grep -E '^organizations/[0-9]+$' | head -n 1)" || pb_anc_org=""
    if [ -z "${PB_ORG}" ] && [ -n "${pb_anc_org}" ]; then
        PB_ORG="${pb_anc_org#organizations/}"
        PB_ORG_PROBLEM=""
        pb_parents
        pb_ok "Organization from the ancestry of ${PB_PROJECT}: organizations/${PB_ORG}"
    fi
    if [ "${pb_state}" != "ACTIVE" ]; then
        pb_warn "Project ${PB_PROJECT} exists but is ${pb_state:-in an unknown state}, not ACTIVE."
        pb_defer PROJECT_NOT_ACTIVE "project ${PB_PROJECT} exists but is ${pb_state:-in an unknown state}, not ACTIVE. If you deleted it, restore it with 'gcloud projects undelete ${PB_PROJECT}' (within 30 days), or pick another project."
    elif [ "${PB_PROJECT_MODE}" = "new" ] && [ "${pb_parent}" != "${PB_PROJECT_PARENT}" ]; then
        # Reused only where this run would have created it; anything else is someone's existing project.
        pb_warn "Project ${PB_PROJECT} already exists under ${pb_parent}, not under ${PB_PROJECT_PARENT}."
        pb_defer PROJECT_EXISTS_ELSEWHERE "project ${PB_PROJECT} already exists under ${pb_parent}, not under ${PB_PROJECT_PARENT} where --new-project would create it. Nothing was changed. To use that project, re-run with --existing-project ${PB_PROJECT}; otherwise pick another --new-project id."
    elif [ "${PB_PROJECT_MODE}" = "new" ]; then
        pb_ok "Project ${PB_PROJECT} already exists (for example from an earlier run) and is ACTIVE under ${pb_parent}; reusing it."
    else
        pb_ok "Project ${PB_PROJECT} exists and is ACTIVE (parent ${pb_parent})."
        if [ -z "${pb_anc}" ]; then
            pb_warn "Could not read the ancestors of ${PB_PROJECT} ('gcloud projects get-ancestors ${PB_PROJECT}'), so it is not confirmed to be in ${PB_ORG_RES}."
            PB_ORG_UNCONFIRMED="the ancestors of project ${PB_PROJECT} could not be read"
        elif [ -n "${PB_ORG}" ] && ! printf '%s\n' "${pb_anc}" | grep -Fxq "organizations/${PB_ORG}"; then
            pb_warn "Project ${PB_PROJECT} is not under organizations/${PB_ORG} (its ancestors: $(printf '%s\n' "${pb_anc}" | tr '\n' ' ')). Bootstrap's organization answer should be the project's own organization; check --org."
            PB_ORG_UNCONFIRMED="project ${PB_PROJECT} is not under organizations/${PB_ORG}"
        fi
    fi
elif [ "${PB_PROJECT_MODE}" = "existing" ]; then
    # Not an early stop: the rights table shows "Owner" as a missing BLOCKING right with the grant command.
    PB_PROJECT_HIDDEN=1
    pb_warn "Project ${PB_PROJECT} is not visible to ${PB_ACCOUNT} (it does not exist, or you have no role on it yet). Check the id with 'gcloud projects list'; the rights table below shows what to grant."
else
    pb_info "Project ${PB_PROJECT} does not exist yet: it will be created under ${PB_PROJECT_PARENT}."
fi

# Billing: the project's own link first (an existing link always wins; no billing right is needed then),
# then, only when a link is needed, a visible billing account.
PB_BILLING_STATE="unlinked"   # linked-same | linked-other | unlinked | disabled | unknown | hidden
PB_BILLING_CURRENT=""
if [ -n "${PB_PROJECT_HIDDEN}" ]; then
    PB_BILLING_STATE="hidden"
elif [ -n "${PB_PROJECT_EXISTS}" ]; then
    pb_line=""
    if pb_gread gcloud billing projects describe "${PB_PROJECT}" --format=json; then
        pb_line="$(printf '%s' "${PB_RO_OUT}" | pb_py billing 2>/dev/null)" || pb_line=""
    fi
    if [ -z "${pb_line}" ]; then
        PB_BILLING_STATE="unknown"
        pb_warn "Could not read the billing link of ${PB_PROJECT} ('gcloud billing projects describe ${PB_PROJECT}'${PB_RO_ERR:+: ${PB_RO_ERR}})."
    else
        PB_BILLING_CURRENT="$(pb_upper "${pb_line#*"${PB_TAB}"}")"
        if [ "${pb_line%%"${PB_TAB}"*}" = "true" ]; then
            [ -n "${PB_BILLING}" ] || PB_BILLING="${PB_BILLING_CURRENT}"
            if [ "${PB_BILLING_CURRENT}" = "${PB_BILLING}" ]; then PB_BILLING_STATE="linked-same"; else PB_BILLING_STATE="linked-other"; fi
        elif [ -n "${PB_BILLING_CURRENT}" ]; then
            # A link exists but billing is disabled (closed account, or billing disabled on the project). Never
            # re-pointed here: that is the owner's decision. Refused after the rights table.
            PB_BILLING_STATE="disabled"
            pb_warn "Project ${PB_PROJECT} is linked to billing account ${PB_BILLING_CURRENT}, but billing is DISABLED on it."
        fi
    fi
fi
case "${PB_BILLING_STATE}" in
    unlinked|hidden|unknown|disabled) [ -n "${PB_BILLING}" ] || pb_discover_billing ;;
esac
case "${PB_BILLING_STATE}" in
    linked-same) pb_ok "Project ${PB_PROJECT} is already linked to billing account ${PB_BILLING}." ;;
    linked-other) pb_info "Project ${PB_PROJECT} is linked to billing account ${PB_BILLING_CURRENT} (not ${PB_BILLING}); that link is kept." ;;
    unlinked)
        if [ -n "${PB_BILLING}" ]; then
            pb_info "Project ${PB_PROJECT} has no billing yet: it will be linked to ${PB_BILLING}."
        else
            pb_info "Project ${PB_PROJECT} has no billing yet, and no billing account is known to link it to (see row 4 below)."
        fi ;;
esac

pb_find_folder() {
    # Sets PB_MATCHES to the ACTIVE folders named PB_FOLDER_NAME under the parent ("folders/<n>", one per
    # line); rc 1 when the list cannot be read (PB_RO_ERR says why). Call directly, not in $(...).
    local lines
    PB_MATCHES=""
    if [ -z "${PB_PARENT_FOLDER}" ] && [ -z "${PB_ORG}" ]; then
        PB_RO_ERR="the organization is not known"
        return 1
    fi
    pb_gread gcloud resource-manager folders list "${PB_FOLDER_PARENT_FLAG}" "--filter=displayName=\"${PB_FOLDER_NAME}\"" --format=json \
        || return 1
    lines="$(printf '%s' "${PB_RO_OUT}" | pb_py folders "${PB_FOLDER_NAME}" 2>/dev/null)" \
        || { PB_RO_ERR="unreadable output"; return 1; }
    if [ -n "${lines}" ]; then
        PB_MATCHES="$(printf '%s\n' "${lines}" | awk -F '\t' '$2 == "ACTIVE" { print $1 }')"
    fi
    return 0
}
PB_FOLDER=""      # folders/<n> once known
PB_MATCHES=""
PB_FOLDER_LIST_FAILED=""   # a new folder whose name could not be looked up (duplicate not ruled out)
pb_line=""
if [ "${PB_FOLDER_MODE}" = "existing" ]; then
    if pb_gread gcloud resource-manager folders describe "${PB_FOLDER_ARG}" --format=json; then
        pb_line="$(printf '%s' "${PB_RO_OUT}" | pb_py folder 2>/dev/null)" || pb_line=""
    fi
fi
if [ "${PB_FOLDER_MODE}" = "existing" ] && [ -z "${pb_line}" ]; then
    # Not an early stop: the rights table shows Folder IAM Admin as a missing BLOCKING right.
    PB_FOLDER_HIDDEN=1
    PB_FOLDER="folders/${PB_FOLDER_ARG}"
    PB_FOLDER_NAME="(not visible)"
    pb_warn "Folder ${PB_FOLDER} is not visible to ${PB_ACCOUNT} (it does not exist, or you have no role on it yet). Check the id with 'gcloud resource-manager folders list --organization=${PB_ORG:-<ORG_NUM>}'; the rights table below shows what to grant."
elif [ "${PB_FOLDER_MODE}" = "existing" ]; then
    if [ "${pb_line%%"${PB_TAB}"*}" != "ACTIVE" ]; then
        pb_warn "Folder ${PB_FOLDER_ARG} is ${pb_line%%"${PB_TAB}"*}, not ACTIVE."
        pb_defer FOLDER_NOT_ACTIVE "folder ${PB_FOLDER_ARG} is ${pb_line%%"${PB_TAB}"*}, not ACTIVE. Use another folder."
    fi
    PB_FOLDER="folders/${PB_FOLDER_ARG}"
    pb_rest="${pb_line#*"${PB_TAB}"}"
    pb_up="${pb_rest%%"${PB_TAB}"*}"
    PB_FOLDER_NAME="${pb_rest#*"${PB_TAB}"}"
    pb_ok "Folder ${PB_FOLDER} ('${PB_FOLDER_NAME}') exists and is ACTIVE (parent ${pb_up})."
    # Walk up the parents (read-only, at most 10 levels) to confirm the chosen organization.
    pb_i=0
    while [ "${pb_up#folders/}" != "${pb_up}" ] && [ "${pb_i}" -lt 10 ]; do
        pb_i=$((pb_i + 1))
        pb_gread gcloud resource-manager folders describe "${pb_up#folders/}" --format=json || { pb_up=""; break; }
        pb_line="$(printf '%s' "${PB_RO_OUT}" | pb_py folder 2>/dev/null)" || { pb_up=""; break; }
        pb_rest="${pb_line#*"${PB_TAB}"}"
        pb_up="${pb_rest%%"${PB_TAB}"*}"
    done
    if [ -z "${PB_ORG}" ] && [ "${pb_up#organizations/}" != "${pb_up}" ]; then
        PB_ORG="${pb_up#organizations/}"
        PB_ORG_PROBLEM=""
        pb_parents
        pb_ok "Organization from the ancestry of ${PB_FOLDER}: organizations/${PB_ORG}"
    elif [ "${pb_up}" != "organizations/${PB_ORG}" ]; then
        pb_warn "Folder ${PB_FOLDER} is not confirmed to be under ${PB_ORG_RES} (top parent found: ${pb_up:-unreadable}). The deletion-safety tag is created on the organization you answer at bootstrap; check --org."
        PB_ORG_UNCONFIRMED="${PB_ORG_UNCONFIRMED:+${PB_ORG_UNCONFIRMED}, and }folder ${PB_FOLDER} is not confirmed to be under ${PB_ORG_RES} (top parent found: ${pb_up:-unreadable})"
    fi
elif pb_find_folder; then
    case "$(pb_count_lines "${PB_MATCHES}")" in
        0) pb_info "No folder named '${PB_FOLDER_NAME}' under ${PB_FOLDER_PARENT}: it will be created." ;;
        1) PB_FOLDER="${PB_MATCHES}"
           pb_ok "Folder '${PB_FOLDER_NAME}' already exists (${PB_FOLDER}) under ${PB_FOLDER_PARENT}; reusing it." ;;
        *) pb_warn "More than one ACTIVE folder named '${PB_FOLDER_NAME}' under ${PB_FOLDER_PARENT}."
           pb_defer FOLDER_AMBIGUOUS "more than one ACTIVE folder named '${PB_FOLDER_NAME}' under ${PB_FOLDER_PARENT} ($(printf '%s\n' "${PB_MATCHES}" | tr '\n' ' ')). Pick one with --existing-folder <FOLDER_ID>, or pass a unique --folder-name." ;;
    esac
else
    PB_FOLDER_LIST_FAILED=1
    pb_warn "Cannot tell whether a folder named '${PB_FOLDER_NAME}' already exists under ${PB_FOLDER_PARENT} (${PB_RO_ERR:-no message}); you need Folder Viewer (roles/resourcemanager.folderViewer) there. See the rights table."
fi
# A reused folder should be empty: each install gets its own folder (quickstart), and the folder's
# "no external VM IPs" policy covers every project in it. Warn only.
if [ -n "${PB_FOLDER}" ] && [ -z "${PB_FOLDER_HIDDEN}" ]; then
    pb_nf=""; pb_np=""
    if pb_gread gcloud resource-manager folders list "--folder=${PB_FOLDER#folders/}" --format=json; then
        pb_nf="$(printf '%s' "${PB_RO_OUT}" | pb_py count 2>/dev/null)" || pb_nf=""
    fi
    if pb_gread gcloud projects list "--filter=parent.type=folder AND parent.id=${PB_FOLDER#folders/}" --format=json; then
        pb_np="$(printf '%s' "${PB_RO_OUT}" | pb_py count 2>/dev/null)" || pb_np=""
    fi
    if [ -z "${pb_nf}" ] || [ -z "${pb_np}" ]; then
        pb_warn "Could not list what is in ${PB_FOLDER}; it is not confirmed to be empty."
    elif [ "${pb_nf}" != "0" ] || [ "${pb_np}" != "0" ]; then
        pb_warn "Folder ${PB_FOLDER} is not empty (${pb_np} project(s), ${pb_nf} folder(s)). Use a new, empty folder for each install: its permissions, deletion-safety tag and \"no external VM IPs\" policy apply to everything in it."
    fi
fi

# --grant-to: which bindings already exist (read now, so the table can report a policy it cannot read).
# yes | no | unknown | new (created by this run, so no binding yet).
pb_policy_has() {
    # $1 = project|folder|organization, $2 = id, $3 = role, $4 = member (default: --grant-to). Prints yes | no |
    # unknown. Only an unconditional binding counts.
    local rc=0 member="${4:-${PB_GRANT_TO}}"
    case "$1" in
        project) pb_gread gcloud projects get-iam-policy "$2" --format=json || rc=$? ;;
        organization) pb_gread gcloud organizations get-iam-policy "$2" --format=json || rc=$? ;;
        *) pb_gread gcloud resource-manager folders get-iam-policy "$2" --format=json || rc=$? ;;
    esac
    if [ "${rc}" -ne 0 ]; then echo unknown; return 0; fi
    rc=0
    printf '%s' "${PB_RO_OUT}" | pb_py has_binding "$3" "${member}" 2>/dev/null || rc=$?
    case "${rc}" in
        0) echo yes ;;
        1) echo no ;;
        *) echo unknown ;;
    esac
}
PB_GRANT_PROJ="new"
PB_GRANT_FOLD="new"
if [ -n "${PB_GRANT_TO}" ]; then
    if [ -n "${PB_PROJECT_HIDDEN}" ]; then
        PB_GRANT_PROJ="unknown"
    elif [ -n "${PB_PROJECT_EXISTS}" ]; then
        PB_GRANT_PROJ="$(pb_policy_has project "${PB_PROJECT}" roles/owner)"
    fi
    if [ -n "${PB_FOLDER_HIDDEN}" ]; then
        PB_GRANT_FOLD="unknown"
    elif [ -n "${PB_FOLDER}" ]; then
        PB_GRANT_FOLD="$(pb_policy_has folder "${PB_FOLDER#folders/}" roles/resourcemanager.folderIamAdmin)"
    fi
fi

# ------------------------------------------------------------------------------
# 1. Rights pre-check (read-only; documentation/quickstart.md "Minimum permissions for the installer")
# ------------------------------------------------------------------------------
pb_step "Rights pre-check for ${PB_ACCOUNT} (read-only)"

# testIamPermissions on $1 for the space-separated permissions $2. Sets PB_G to the granted ones, one per
# line; rc 1 when the call fails (PB_HTTP holds the status). Runs in the caller's shell (no $(...)) so
# PB_HTTP survives. The token goes to curl on stdin, never on the command line.
PB_HTTP=""
PB_ERR=""
PB_G=""
PB_CHECK_FAILURES=""   # "<resource>: HTTP <code>: <message>" lines for the calls that failed
pb_test_permissions() {
    local resource="$1" perms="$2" url body token tmp granted="" rc=0 p
    PB_G=""
    case "${resource}" in
        billingAccounts/*) url="https://cloudbilling.googleapis.com/v1/${resource}:testIamPermissions" ;;
        *) url="https://cloudresourcemanager.googleapis.com/v3/${resource}:testIamPermissions" ;;
    esac
    body=""
    for p in ${perms}; do body="${body:+${body},}\"${p}\""; done
    body="{\"permissions\":[${body}]}"
    PB_HTTP=""
    PB_ERR=""
    token="$(gcloud auth print-access-token 2>/dev/null)" || token=""
    [ -n "${token}" ] || { PB_HTTP="no-token"; return 1; }
    tmp="$(mktemp -d 2>/dev/null)" || { PB_HTTP="no-tmpdir"; return 1; }
    PB_HTTP="$(printf 'header = "Authorization: Bearer %s"\n' "${token}" | curl -sS --max-time 20 --config - \
        -X POST -H "Content-Type: application/json" --data "${body}" -o "${tmp}/resp.json" -w '%{http_code}' \
        "${url}" 2>/dev/null)" || PB_HTTP="${PB_HTTP:-curl-failed}"
    token=""
    if [ "${PB_HTTP}" = "200" ]; then
        granted="$(pb_py granted < "${tmp}/resp.json")" || { rc=1; PB_HTTP="unparseable"; }
    else
        rc=1
        # The API's own reason (e.g. a 400 for an unknown permission name), for the typed refusal.
        PB_ERR="$(pb_py error_message < "${tmp}/resp.json" 2>/dev/null)" || PB_ERR=""
    fi
    rm -rf "${tmp}"
    [ "${rc}" -eq 0 ] || return 1
    PB_G="${granted}"
}

# Answers yes | no | ? (the check could not run) for "all of $2 in the granted list $1"; $3 = call ok (1/"").
pb_have() {
    local granted="$1" perms="$2" ok="$3" p
    [ -n "${ok}" ] || { echo "?"; return 0; }
    for p in ${perms}; do
        printf '%s\n' "${granted}" | grep -Fxq "${p}" || { echo "no"; return 0; }
    done
    echo "yes"
}

pb_tested() {
    # $1 = resource, $2 = perms. Sets PB_G (granted list) and PB_G_OK (1 when the call worked).
    PB_G_OK=""
    if pb_test_permissions "$1" "$2"; then
        PB_G_OK=1
    else
        PB_G=""
        pb_warn "testIamPermissions on $1 failed (HTTP ${PB_HTTP:-none}${PB_ERR:+: ${PB_ERR}}); its rows show '?'."
        PB_CHECK_FAILURES="${PB_CHECK_FAILURES}   - $1: HTTP ${PB_HTTP:-none}${PB_ERR:+: ${PB_ERR}}
"
    fi
}

PB_OWNER_PERMS="resourcemanager.projects.get resourcemanager.projects.setIamPolicy serviceusage.services.enable iam.serviceAccounts.create storage.buckets.create resourcemanager.projects.createBillingAssignment"
PB_TAG_PERMS="resourcemanager.tagKeys.create resourcemanager.tagValues.create resourcemanager.tagValues.setIamPolicy"
# The same set as scripts/common/org_policy_preflight.sh (SV_ORGPOL_REQUIRED_PERMISSIONS): tested on the folder
# when it exists, else on the organization (a new folder inherits from there).
PB_ORGPOLICY_PERMS="orgpolicy.policies.create orgpolicy.policies.update orgpolicy.policy.get orgpolicy.policy.set"
PB_BILLING_LINK_PERMS="billing.resourceAssociations.create"
PB_BILLING_ADMIN_PERMS="billing.accounts.getIamPolicy billing.accounts.setIamPolicy"

# One call per resource.
PB_NEW_PROJECT=""
[ -n "${PB_PROJECT_EXISTS}" ] || [ "${PB_PROJECT_MODE}" != "new" ] || PB_NEW_PROJECT=1
PB_NEW_FOLDER=""
[ -n "${PB_FOLDER}" ] || PB_NEW_FOLDER=1
PB_FOLDER_SEEN=""      # an existing folder the signed-in account can see (its rights can be tested there)
[ -z "${PB_FOLDER}" ] || [ -n "${PB_FOLDER_HIDDEN}" ] || PB_FOLDER_SEEN="${PB_FOLDER}"

pb_perms_org="${PB_TAG_PERMS}"
[ -n "${PB_FOLDER_SEEN}" ] || pb_perms_org="${pb_perms_org} ${PB_ORGPOLICY_PERMS}"
pb_perms_pparent="resourcemanager.projects.create"
pb_perms_fparent="resourcemanager.folders.create resourcemanager.folders.setIamPolicy"
if [ "${PB_PROJECT_PARENT}" = "${PB_ORG_RES}" ]; then pb_perms_org="${pb_perms_org} ${pb_perms_pparent}"; fi
if [ "${PB_FOLDER_PARENT}" = "${PB_ORG_RES}" ]; then pb_perms_org="${pb_perms_org} ${pb_perms_fparent}"; fi
if [ -n "${PB_ORG}" ]; then
    pb_tested "${PB_ORG_RES}" "${pb_perms_org}"
else
    # No organization to test against: its rows show "?" and the organization problem is reported below.
    PB_G=""; PB_G_OK=""
    PB_CHECK_FAILURES="${PB_CHECK_FAILURES}   - organization: not known (${PB_ORG_PROBLEM#*"${PB_TAB}"})
"
fi
PB_G_ORG="${PB_G}"; PB_OK_ORG="${PB_G_OK}"
PB_G_PP="${PB_G_ORG}"; PB_OK_PP="${PB_OK_ORG}"
PB_G_FP="${PB_G_ORG}"; PB_OK_FP="${PB_OK_ORG}"
if [ -n "${PB_PARENT_FOLDER}" ]; then
    pb_perms_pf="${pb_perms_fparent}"
    [ "${PB_PROJECT_PARENT}" = "${PB_ORG_RES}" ] || pb_perms_pf="${pb_perms_pf} ${pb_perms_pparent}"
    pb_tested "folders/${PB_PARENT_FOLDER}" "${pb_perms_pf}"
    PB_G_FP="${PB_G}"; PB_OK_FP="${PB_G_OK}"
    if [ "${PB_PROJECT_PARENT}" != "${PB_ORG_RES}" ]; then PB_G_PP="${PB_G}"; PB_OK_PP="${PB_G_OK}"; fi
fi
if [ -n "${PB_PROJECT_EXISTS}" ]; then
    pb_tested "projects/${PB_PROJECT}" "${PB_OWNER_PERMS}"
    PB_G_PROJ="${PB_G}"; PB_OK_PROJ="${PB_G_OK}"
fi
PB_G_FOLD=""; PB_OK_FOLD=""
if [ -n "${PB_FOLDER_SEEN}" ]; then
    pb_tested "${PB_FOLDER}" "resourcemanager.folders.get resourcemanager.folders.setIamPolicy ${PB_ORGPOLICY_PERMS}"
    PB_G_FOLD="${PB_G}"; PB_OK_FOLD="${PB_G_OK}"
fi
PB_G_BILL=""; PB_OK_BILL=""
if [ -n "${PB_BILLING}" ]; then
    pb_tested "billingAccounts/${PB_BILLING}" "${PB_BILLING_LINK_PERMS} ${PB_BILLING_ADMIN_PERMS}"
    PB_G_BILL="${PB_G}"; PB_OK_BILL="${PB_G_OK}"
fi

PB_BLOCKING=""        # grant lines for missing BLOCKING rights
PB_DEGRADED=""        # summary lines for missing DEGRADED / OPTIONAL rights
PB_DEGRADED_ROWS=""   # their row numbers (" 4 7 8"), for the final summary
PB_UNKNOWN_BLOCKING=""
pb_fid="${PB_FOLDER#folders/}"
PB_RUNNER_CHECK_CMD="bash scripts/pre-bootstrap.sh --check-only --existing-project ${PB_PROJECT} --existing-folder ${pb_fid:-<FOLDER_ID>} --org ${PB_ORG}${PB_BILLING:+ --billing-account ${PB_BILLING}}"
# Table: one block per row of the quickstart table. Row = "#  Have it?  Class  Right (where)", then what it is
# needed for and, when it is missing, what happens if you continue without it.
printf '\n   %-3s %-11s %-9s %s\n' "#" "Have it?" "Class" "Right (where)"
pb_row() {
    # $1 table row, $2 right, $3 have (yes|yes (...)|no|?|not tested), $4 class, $5 needed for, $6 without it,
    # $7 grant line(s)
    local mark="${GREEN}" have="$3"
    case "${have}" in
        yes*) mark="${GREEN}" ;;
        no) if [ "$4" = "BLOCKING" ]; then mark="${RED}"; else mark="${YELLOW}"; fi ;;
        *) mark="${YELLOW}" ;;
    esac
    printf '   %-3s %b%-11s%b %-9s %s\n' "$1" "${mark}" "${have}" "${RESET}" "$4" "$2"
    printf '   %-25s needed for: %s\n' "" "$5"
    case "${have}" in
        no)
            printf '   %-25s without it: %s\n' "" "$6"
            if [ "$4" = "BLOCKING" ]; then
                PB_BLOCKING="${PB_BLOCKING}   - row $1, $2: $6
       $7
"
            else
                PB_DEGRADED="${PB_DEGRADED}   - row $1 ($4), $2: $6
       $7
"
                PB_DEGRADED_ROWS="${PB_DEGRADED_ROWS} $1"
            fi ;;
        "?")
            printf '   %-25s could not be checked; without it: %s\n' "" "$6"
            if [ "$4" = "BLOCKING" ]; then PB_UNKNOWN_BLOCKING="${PB_UNKNOWN_BLOCKING} $1"; fi ;;
        "not tested"*)
            printf '   %-25s if missing: %s\n' "" "$6" ;;
    esac
}

# Row 1: organization account (the bootstrap runner).
if [ -n "${PB_RUNNER_PERSONAL}" ]; then pb_have1="no"; else pb_have1="yes"; fi
pb_row 1 "organization account (${PB_RUNNER_EMAIL})" "${pb_have1}" DEGRADED \
    "Direct IAP, bootstrap's default ingress" \
    "the Control Center cannot be opened behind Direct IAP; use public ingress (a sandbox) or an organization account" \
    "Sign in with an organization account (documentation/quickstart.md \"Sign in\")."

# Row 2: create the project.
if [ -n "${PB_NEW_PROJECT}" ]; then
    pb_row 2 "resourcemanager.projects.create (${PB_PROJECT_PARENT})" \
        "$(pb_have "${PB_G_PP}" resourcemanager.projects.create "${PB_OK_PP}")" BLOCKING \
        "creating the new host project ${PB_PROJECT}" \
        "you must use an existing project (--existing-project <id>)" \
        "$(pb_admin_of "${PB_PROJECT_PARENT}") runs: $(pb_grant_cmd "${PB_PROJECT_PARENT}" "${PB_ME}" roles/resourcemanager.projectCreator)   (or use --existing-project <id>)"
fi

# Row 3: Owner on the host project.
if [ -n "${PB_PROJECT_EXISTS}" ]; then
    pb_row 3 "Owner: ${PB_OWNER_PERMS%% *} ... (projects/${PB_PROJECT})" \
        "$(pb_have "${PB_G_PROJ}" "${PB_OWNER_PERMS}" "${PB_OK_PROJ}")" BLOCKING \
        "bootstrap: APIs, service accounts, state bucket and IAM on the host project${PB_GRANT_TO:+; granting Owner to ${PB_GRANT_TO}}" \
        "bootstrap cannot install into ${PB_PROJECT}" \
        "$(pb_admin_of "projects/${PB_PROJECT}") runs: $(pb_grant_cmd "projects/${PB_PROJECT}" "${PB_ME}" roles/owner)"
elif [ -n "${PB_PROJECT_HIDDEN}" ]; then
    pb_row 3 "Owner (projects/${PB_PROJECT}; not visible to you)" "no" BLOCKING \
        "bootstrap: APIs, service accounts, state bucket and IAM on the host project${PB_GRANT_TO:+; granting Owner to ${PB_GRANT_TO}}" \
        "bootstrap cannot install into ${PB_PROJECT}; this script cannot read or link it" \
        "$(pb_admin_of "projects/${PB_PROJECT}") runs: $(pb_grant_cmd "projects/${PB_PROJECT}" "${PB_ME}" roles/owner)   (or check the id: gcloud projects list; or use --new-project <id>)"
else
    pb_row 3 "Owner (projects/${PB_PROJECT})" "yes (new)" BLOCKING "bootstrap; you get Owner by creating the project" "" ""
fi

# Row 4: link to billing (only when a link is needed), and billing admin for Terraform's three grants.
PB_BILLING_AMBIGUOUS_NEEDED=""
pb_bill_res="billingAccounts/${PB_BILLING:-<BILLING_ACCOUNT_ID>}"
pb_link_fix="once the project exists, someone with Billing Account User runs: gcloud billing projects link ${PB_PROJECT} --billing-account=${PB_BILLING:-<BILLING_ACCOUNT_ID>} ; then re-run with --existing-project ${PB_PROJECT}"
case "${PB_BILLING_STATE}" in
    unlinked)
        if [ -n "${PB_BILLING}" ]; then
            pb_row 4 "billing.resourceAssociations.create (${pb_bill_res})" \
                "$(pb_have "${PB_G_BILL}" "${PB_BILLING_LINK_PERMS}" "${PB_OK_BILL}")" BLOCKING \
                "linking ${PB_PROJECT} to billing" \
                "someone with Billing Account User must link it (gcloud billing projects link ${PB_PROJECT} --billing-account=${PB_BILLING}); bootstrap stops until billing is enabled" \
                "$(pb_admin_of "${pb_bill_res}") runs: $(pb_grant_cmd "${pb_bill_res}" "${PB_ME}" roles/billing.user)   (or, ${pb_link_fix})"
        elif [ -n "${PB_BILLING_CHOICES}" ]; then
            # Not a missing right: a choice. Shown here, refused after the table (PREBOOT_BILLING_AMBIGUOUS).
            PB_BILLING_AMBIGUOUS_NEEDED=1
            printf '   %-3s %b%-11s%b %-9s %s\n' 4 "${YELLOW}" "choose" "${RESET}" BLOCKING "a billing account to link ${PB_PROJECT} to"
            printf '   %-25s more than one is open (%s): pass --billing-account <ID>\n' "" "${PB_BILLING_CHOICES% }"
        else
            pb_row 4 "Billing Account User on a billing account (none visible to you)" "no" BLOCKING \
                "linking ${PB_PROJECT} to billing" \
                "the project cannot be linked to billing; bootstrap stops until billing is enabled" \
                "a Billing Account Administrator runs: $(pb_grant_cmd "billingAccounts/<BILLING_ACCOUNT_ID>" "${PB_ME}" roles/billing.user) ; or, ${pb_link_fix}"
        fi ;;
    unknown)
        pb_row 4 "billing link of projects/${PB_PROJECT}" "?" BLOCKING \
            "knowing whether ${PB_PROJECT} still needs a billing link" \
            "bootstrap stops until billing is enabled" "" ;;
    hidden)
        pb_row 4 "billing link of projects/${PB_PROJECT} (project not visible)" "not tested" BLOCKING \
            "linking ${PB_PROJECT} to billing, if it has no billing yet" \
            "someone with Billing Account User must link it; bootstrap stops until billing is enabled" "" ;;
esac
if [ -z "${PB_RUNNER_IS_ME}" ]; then
    pb_have4b="not tested"
elif [ -z "${PB_BILLING}" ]; then
    pb_have4b="not tested"
else
    pb_have4b="$(pb_have "${PB_G_BILL}" "${PB_BILLING_ADMIN_PERMS}" "${PB_OK_BILL}")"
fi
pb_where4b="${pb_bill_res}"
[ -n "${PB_BILLING}" ] || pb_where4b="no billing account visible"
pb_row 4 "billing.accounts.get/setIamPolicy (${pb_where4b})" "${pb_have4b}" DEGRADED \
    "Terraform's 3 billing grants for StackVend's service accounts" \
    "the install completes; the 3 billing grants become the post-install step (\"Post-install: billing access\"), and vending cannot link child projects to billing until then" \
    "$(pb_admin_of "${pb_bill_res}") runs: $(pb_grant_cmd "${pb_bill_res}" "${PB_RUNNER}" roles/billing.admin)   (or does the post-install step after the install)"

# Row 5: create the folder.
if [ -n "${PB_NEW_FOLDER}" ]; then
    pb_have5="$(pb_have "${PB_G_FP}" resourcemanager.folders.create "${PB_OK_FP}")"
    pb_row 5 "resourcemanager.folders.create (${PB_FOLDER_PARENT})" \
        "${pb_have5}" BLOCKING \
        "creating the folder '${PB_FOLDER_NAME}'" \
        "you must use an existing folder (--existing-folder <FOLDER_ID>)" \
        "$(pb_admin_of "${PB_FOLDER_PARENT}") runs: $(pb_grant_cmd "${PB_FOLDER_PARENT}" "${PB_ME}" roles/resourcemanager.folderCreator)   (or use --existing-folder <FOLDER_ID>)"
    if [ -n "${PB_FOLDER_LIST_FAILED}" ] && [ "${pb_have5}" != "no" ]; then
        # Creating it could make a second folder with the same name: refuse until the list can be read.
        PB_CHECK_FAILURES="${PB_CHECK_FAILURES}   - folder list under ${PB_FOLDER_PARENT}: cannot tell whether '${PB_FOLDER_NAME}' already exists (Folder Viewer needed)
"
        pb_row 5 "Folder Viewer on ${PB_FOLDER_PARENT} (needed to avoid creating a duplicate folder)" "?" BLOCKING \
            "checking whether a folder named '${PB_FOLDER_NAME}' already exists" \
            "a second folder named '${PB_FOLDER_NAME}' could be created; get roles/resourcemanager.folderViewer there ($(pb_grant_cmd "${PB_FOLDER_PARENT}" "${PB_ME}" roles/resourcemanager.folderViewer)), or use --existing-folder <FOLDER_ID>" ""
    fi
fi

# Row 6: Folder IAM Admin on the managed-workloads folder (inherited from the parent for a new folder).
pb_label6=""
if [ -n "${PB_FOLDER_HIDDEN}" ]; then
    pb_res6="${PB_FOLDER}"; pb_have6="no"; pb_label6="; not visible to you"
elif [ -n "${PB_FOLDER}" ]; then
    pb_res6="${PB_FOLDER}"; pb_have6="$(pb_have "${PB_G_FOLD}" resourcemanager.folders.setIamPolicy "${PB_OK_FOLD}")"
else
    pb_res6="${PB_FOLDER_PARENT}"; pb_have6="$(pb_have "${PB_G_FP}" resourcemanager.folders.setIamPolicy "${PB_OK_FP}")"
fi
pb_row 6 "resourcemanager.folders.setIamPolicy (${pb_res6}${pb_label6})" \
    "${pb_have6}" BLOCKING \
    "the platform apply's folder grants (google_folder_iam_member)${PB_GRANT_TO:+; granting Folder IAM Admin to ${PB_GRANT_TO}}" \
    "the platform apply fails with 403 (bootstrap stops)" \
    "$(pb_admin_of "${pb_res6}") runs: $(pb_grant_cmd "${pb_res6}" "${PB_ME}" roles/resourcemanager.folderIamAdmin)${PB_NEW_FOLDER:+   (or someone creates the folder, grants the role on that folder only, and you re-run with --existing-folder <FOLDER_ID>)}"

# Rows 7 and 8: organization roles of the bootstrap runner.
if [ -n "${PB_RUNNER_IS_ME}" ]; then
    pb_have7="$(pb_have "${PB_G_ORG}" "${PB_TAG_PERMS}" "${PB_OK_ORG}")"
    if [ -n "${PB_FOLDER_SEEN}" ]; then
        pb_have8="$(pb_have "${PB_G_FOLD}" "${PB_ORGPOLICY_PERMS}" "${PB_OK_FOLD}")"
    else
        pb_have8="$(pb_have "${PB_G_ORG}" "${PB_ORGPOLICY_PERMS}" "${PB_OK_ORG}")"
    fi
else
    pb_have7="not tested"
    pb_have8="not tested"
fi
pb_res8="${PB_FOLDER_SEEN:-${PB_ORG_RES}}"
pb_row 7 "Tag Administrator: tagKeys.create ... (${PB_ORG_RES})" "${pb_have7}" DEGRADED \
    "the deletion-safety tag" \
    "bootstrap asks before the apply whether to continue without it; if you continue, every project delete is refused (GUARD_UNCONFIGURED)" \
    "$(pb_admin_of "${PB_ORG_RES}") runs: $(pb_grant_cmd "${PB_ORG_RES}" "${PB_RUNNER}" roles/resourcemanager.tagAdmin)"
pb_row 8 "orgpolicy.policies.create/update, policy.get/set (${pb_res8})" "${pb_have8}" OPTIONAL \
    "\"no external VM IPs\" on the folder" \
    "VMs in workload projects can get external IPs (every vend records VENDING.ORG_POLICY_NOT_ENFORCED)" \
    "$(pb_admin_of "${PB_ORG_RES}") runs: $(pb_grant_cmd "${PB_ORG_RES}" "${PB_RUNNER}" roles/orgpolicy.policyAdmin)"
# PREBOOTSTRAP-OFFER-ORG-ROLES: rows 7 / 8 that the "Organization roles" step may offer to grant (after the
# pre-check passed and the project / folder steps ran): missing for the signed-in account, or not testable for the
# --grant-to person (their organization IAM binding decides then).
PB_ORG_OFFER7=""
PB_ORG_OFFER8=""
case "${pb_have7}" in no|"not tested") PB_ORG_OFFER7=1 ;; esac
case "${pb_have8}" in no|"not tested") PB_ORG_OFFER8=1 ;; esac

# --grant-to: an IAM policy that could not be read (the grant would be made blind).
if [ "${PB_GRANT_PROJ}" = "unknown" ] && [ -z "${PB_PROJECT_HIDDEN}" ]; then
    PB_CHECK_FAILURES="${PB_CHECK_FAILURES}   - projects/${PB_PROJECT}: IAM policy not readable
"
    pb_row 3 "getIamPolicy (projects/${PB_PROJECT})" "?" BLOCKING \
        "checking whether ${PB_GRANT_TO} already has roles/owner" "the --grant-to step cannot run" ""
fi
if [ "${PB_GRANT_FOLD}" = "unknown" ] && [ -z "${PB_FOLDER_HIDDEN}" ]; then
    PB_CHECK_FAILURES="${PB_CHECK_FAILURES}   - ${PB_FOLDER}: IAM policy not readable
"
    pb_row 6 "getIamPolicy (${PB_FOLDER})" "?" BLOCKING \
        "checking whether ${PB_GRANT_TO} already has Folder IAM Admin" "the --grant-to step cannot run" ""
fi

if [ -z "${PB_RUNNER_IS_ME}" ]; then
    echo
    pb_info "Rows 4 (billing admin), 7 and 8 are rights of ${PB_GRANT_TO}, who runs bootstrap; this script can only test the signed-in account."
    echo -e "          After this run, ${PB_GRANT_TO#user:} checks them with: ${PB_RUNNER_CHECK_CMD}"
fi
if [ -n "${PB_DEGRADED}" ]; then
    echo
    pb_warn "Missing DEGRADED / OPTIONAL rights (you can continue; bootstrap checks again, and without Tag Administrator it asks whether to continue without deletion safety):"
    printf '%s' "${PB_DEGRADED}"
fi
# Everything is reported before the run stops: state that needs a person's decision, then missing BLOCKING
# rights (exit 1), then BLOCKING rights that could not be checked (exit 2). Nothing has been written.
[ -z "${PB_ORG_PROBLEM}" ] || pb_defer "${PB_ORG_PROBLEM%%"${PB_TAB}"*}" "${PB_ORG_PROBLEM#*"${PB_TAB}"}"
if [ -n "${PB_BILLING_AMBIGUOUS_NEEDED}" ]; then
    pb_defer BILLING_AMBIGUOUS "${PB_PROJECT} needs a billing link and more than one open billing account is visible (${PB_BILLING_CHOICES% }). Pass --billing-account <ID>."
fi
if [ "${PB_BILLING_STATE}" = "disabled" ]; then
    pb_defer BILLING_DISABLED "project ${PB_PROJECT} has a disabled billing link to ${PB_BILLING_CURRENT}; this script does not re-point an existing link. Re-enable it by reopening that billing account (Billing > Account management), or relink the project by hand: gcloud billing projects link ${PB_PROJECT} --billing-account=${PB_BILLING:-<BILLING_ACCOUNT_ID>} ; then re-run."
fi
if [ -n "${PB_DEFERRED}" ]; then
    echo >&2
    while IFS= read -r pb_d; do
        [ -n "${pb_d}" ] || continue
        echo -e "${RED}[ERROR]${RESET} PREBOOT_${pb_d%%"${PB_TAB}"*}: ${pb_d#*"${PB_TAB}"}" >&2
    done <<EOF
${PB_DEFERRED}
EOF
fi
if [ -n "${PB_BLOCKING}" ]; then
    echo -e "\n${RED}Missing BLOCKING rights. Who must grant what:${RESET}" >&2
    printf '%s' "${PB_BLOCKING}" >&2
    pb_die MISSING_RIGHTS "${PB_ACCOUNT} lacks a BLOCKING right for this path (see the list above). Nothing was changed. Have it granted (or choose the existing-project / existing-folder path), then re-run."
fi
if [ -n "${PB_DEFERRED}" ]; then
    pb_die STOPPED "nothing was changed: fix the PREBOOT_ errors above, then re-run."
fi
if [ -n "${PB_UNKNOWN_BLOCKING}" ]; then
    # Never guessed as present: refuse before any write (exit 2 = could not check).
    echo -e "\n${RED}BLOCKING rows${PB_UNKNOWN_BLOCKING} could not be checked. Failed calls:${RESET}" >&2
    printf '%s' "${PB_CHECK_FAILURES}" >&2
    pb_fail 2 RIGHTS_UNKNOWN "a BLOCKING right could not be checked (rows${PB_UNKNOWN_BLOCKING}; failed calls: $(printf '%s' "${PB_CHECK_FAILURES}" | sed 's/^ *- //' | tr '\n' ';')). Nothing was changed. Fix what the message says (sign-in, a wrong --org / --billing-account / --parent-folder id, network), then re-run; the quickstart's read-only self-check command tests the organization rights by hand."
fi
pb_ok "Rights pre-check passed: no BLOCKING right is missing."

# BOOTSTRAP-PREFILL (owner 11-03): the one-line bootstrap command with the known values as the defaults of its four
# prompts (STACKVEND_PROJECT_ID / _ORG_ID / _BILLING_ACCOUNT_ID / _FOLDER_ID; scripts/bootstrap.sh). A value not
# known (yet) is left out, never passed empty. PB_BOOT_ENV holds the NAME=value words, PB_BOOT_CMD the printed line.
PB_BOOT_ENV=()
PB_BOOT_CMD=""
pb_bootstrap_command() {
    PB_BOOT_ENV=("STACKVEND_PROJECT_ID=${PB_PROJECT}")
    [ -z "${PB_ORG}" ] || PB_BOOT_ENV+=("STACKVEND_ORG_ID=organizations/${PB_ORG}")
    [ -z "${PB_BILLING}" ] || PB_BOOT_ENV+=("STACKVEND_BILLING_ACCOUNT_ID=${PB_BILLING}")
    [ -z "${PB_FOLDER}" ] || PB_BOOT_ENV+=("STACKVEND_FOLDER_ID=${PB_FOLDER}")
    PB_BOOT_CMD="${CLOUDSDK_ACTIVE_CONFIG_NAME:+CLOUDSDK_ACTIVE_CONFIG_NAME=$(printf '%q' "${CLOUDSDK_ACTIVE_CONFIG_NAME}") }$(pb_quote "${PB_BOOT_ENV[@]}") bash scripts/bootstrap.sh"
}
if [ -n "${PB_CHECK_ONLY}" ]; then
    echo -e "\nCheck only: nothing was changed."
    pb_bootstrap_command
    echo -e "   The bootstrap command with the values known so far (run it once the project and folder exist):"
    echo -e "     ${BOLD}${PB_BOOT_CMD}${RESET}"
    exit 0
fi

# ------------------------------------------------------------------------------
# Plan + confirmation
# ------------------------------------------------------------------------------
pb_step "Plan (each step acts only on what is missing; nothing is deleted or changed)"
if [ -n "${PB_PROJECT_EXISTS}" ]; then pb_p="exists, kept as is"; else pb_p="create under ${PB_PROJECT_PARENT}"; fi
case "${PB_BILLING_STATE}" in
    linked-same) pb_b="already linked" ;;
    linked-other) pb_b="kept on ${PB_BILLING_CURRENT}" ;;
    *) pb_b="link" ;;
esac
if [ -n "${PB_FOLDER}" ]; then pb_f="${PB_FOLDER}, exists"; else pb_f="create under ${PB_FOLDER_PARENT}"; fi
echo -e "   Host project:             ${BOLD}${PB_PROJECT}${RESET} (${pb_p})"
echo -e "   Billing account:          ${BOLD}${PB_BILLING}${RESET} (${pb_b})"
echo -e "   Managed-workloads folder: ${BOLD}${PB_FOLDER_NAME}${RESET} (${pb_f})"
if [ -n "${PB_GRANT_TO}" ]; then
    echo -e "   Grants for ${BOLD}${PB_GRANT_TO}${RESET}: Owner on the project, Folder IAM Admin on the folder (each only if missing)"
fi
# Owner live test 11-03: a prepared organization (project exists, billing linked, folder exists, no --grant-to binding
# missing) has nothing to change, so this Proceed question is not asked (the organization-role offers of step 5b,
# PREBOOTSTRAP-OFFER-ORG-ROLES, still ask when rows 7 / 8 are missing).
PB_NOTHING_TO_CHANGE=""
if [ -n "${PB_PROJECT_EXISTS}" ] && [ -n "${PB_FOLDER}" ] \
    && { [ "${PB_BILLING_STATE}" = "linked-same" ] || [ "${PB_BILLING_STATE}" = "linked-other" ]; } \
    && { [ -z "${PB_GRANT_TO}" ] || { [ "${PB_GRANT_PROJ}" = "yes" ] && [ "${PB_GRANT_FOLD}" = "yes" ]; }; }; then
    PB_NOTHING_TO_CHANGE=1
fi
if [ -n "${PB_NOTHING_TO_CHANGE}" ]; then
    pb_ok "Nothing to change."
elif [ -z "${PB_DRY_RUN}" ]; then
    pb_confirm "Proceed?" \
        || pb_die NOT_CONFIRMED "not confirmed; nothing was changed. Re-run in a terminal and answer y, or pass --yes (or --dry-run to only see the commands)."
fi

# ------------------------------------------------------------------------------
# 2. Host project
# ------------------------------------------------------------------------------
pb_step "Host project"
if [ -n "${PB_PROJECT_EXISTS}" ]; then
    pb_ok "Project ${PB_PROJECT} already exists; not created."
elif pb_write gcloud projects create "${PB_PROJECT}" "${PB_PROJECT_PARENT_FLAG}"; then
    if [ -z "${PB_DRY_RUN}" ]; then
        PB_PROJECT_EXISTS=1
        pb_done "Created project ${PB_PROJECT} under ${PB_PROJECT_PARENT}."
    fi
else
    # gcloud's documented refusal for a globally taken id ("already in use"; ALREADY_EXISTS in the API).
    case "$(pb_lower "${PB_OUT}")" in
        *"already in use"*|*"already_exists"*|*"already exists"*)
            pb_die PROJECT_ID_TAKEN "project id ${PB_PROJECT} is already in use by a project you cannot see (project ids are global). Nothing else was changed. Pick another --new-project id; if that project is yours, have its Owner grant you Owner on it and use --existing-project ${PB_PROJECT}. gcloud said: ${PB_OUT}" ;;
        *)
            pb_die PROJECT_CREATE_FAILED "creating project ${PB_PROJECT} failed. You need Project Creator (roles/resourcemanager.projectCreator) on ${PB_PROJECT_PARENT} (quickstart row 2). gcloud said: ${PB_OUT}" ;;
    esac
fi

# ------------------------------------------------------------------------------
# 3. Billing
# ------------------------------------------------------------------------------
pb_step "Billing"
case "${PB_BILLING_STATE}" in
    linked-same) pb_ok "Project ${PB_PROJECT} is already linked to billing account ${PB_BILLING}." ;;
    linked-other)
        pb_warn "Project ${PB_PROJECT} is already linked to billing account ${PB_BILLING_CURRENT}, not ${PB_BILLING}. Left unchanged (the existing link wins)."
        echo -e "          bootstrap's billing account (for the child projects) can still be ${PB_BILLING}; to move the host project, run:"
        echo -e "            gcloud billing projects link ${PB_PROJECT} --billing-account=${PB_BILLING}" ;;
    *)
        if pb_write gcloud billing projects link "${PB_PROJECT}" "--billing-account=${PB_BILLING}"; then
            [ -n "${PB_DRY_RUN}" ] || pb_done "Linked project ${PB_PROJECT} to billing account ${PB_BILLING}."
        else
            pb_die BILLING_LINK_FAILED "linking ${PB_PROJECT} to billing account ${PB_BILLING} failed. You need Billing Account User (roles/billing.user) on that account (quickstart row 4), and the account must be open and under its project quota. gcloud said: ${PB_OUT}"
        fi ;;
esac

# ------------------------------------------------------------------------------
# 4. Managed-workloads folder
# ------------------------------------------------------------------------------
pb_step "Managed-workloads folder"
if [ -n "${PB_FOLDER}" ]; then
    pb_ok "Folder ${PB_FOLDER} ('${PB_FOLDER_NAME}') already exists; not created."
elif pb_write gcloud resource-manager folders create "--display-name=${PB_FOLDER_NAME}" "${PB_FOLDER_PARENT_FLAG}" "--format=value(name)"; then
    if [ -z "${PB_DRY_RUN}" ]; then
        PB_FOLDER="$(printf '%s\n' "${PB_OUT}" | grep -E '^folders/[0-9]+$' | tail -n 1)" || PB_FOLDER=""
        if [ -z "${PB_FOLDER}" ]; then
            # The create printed no folders/<n> line: read it back.
            if ! pb_find_folder || [ "$(pb_count_lines "${PB_MATCHES}")" != "1" ]; then
                pb_die FOLDER_ID_UNKNOWN "folder '${PB_FOLDER_NAME}' was created but its id could not be read back. Run: gcloud resource-manager folders list ${PB_FOLDER_PARENT_FLAG} and re-run with --existing-folder <FOLDER_ID>."
            fi
            PB_FOLDER="${PB_MATCHES}"
        fi
        pb_done "Created folder '${PB_FOLDER_NAME}' (${PB_FOLDER}) under ${PB_FOLDER_PARENT}."
    fi
else
    pb_die FOLDER_CREATE_FAILED "creating folder '${PB_FOLDER_NAME}' under ${PB_FOLDER_PARENT} failed. You need Folder Creator (roles/resourcemanager.folderCreator) there (quickstart row 5), or use --existing-folder <FOLDER_ID>. gcloud said: ${PB_OUT}"
fi
PB_FOLDER_NUM="${PB_FOLDER#folders/}"

# ------------------------------------------------------------------------------
# 5. Grants for the person who will run bootstrap (--grant-to)
# ------------------------------------------------------------------------------
pb_grant() {
    # $1 = kind (project|folder), $2 = resource id ("" = not created yet: dry run), $3 = role,
    # $4 = what the state step read (yes | no | new; "unknown" never gets here: it stops before any write)
    local kind="$1" id="$2" role="$3" has="$4" rc=0
    if [ "${has}" = "yes" ]; then
        pb_ok "${PB_GRANT_TO} already has ${role} on ${kind} ${id}."
        return 0
    fi
    [ -n "${id}" ] || id="<new ${kind}>"
    if [ "${kind}" = "project" ]; then
        pb_write gcloud projects add-iam-policy-binding "${id}" "--member=${PB_GRANT_TO}" "--role=${role}" --condition=None --format=none || rc=$?
    else
        pb_write gcloud resource-manager folders add-iam-policy-binding "${id}" "--member=${PB_GRANT_TO}" "--role=${role}" --condition=None --format=none || rc=$?
    fi
    [ "${rc}" -eq 0 ] || pb_die GRANT_FAILED "granting ${role} on ${kind} ${id} to ${PB_GRANT_TO} failed. gcloud said: ${PB_OUT}"
    [ -n "${PB_DRY_RUN}" ] || pb_done "Granted ${role} on ${kind} ${id} to ${PB_GRANT_TO}."
}
if [ -n "${PB_GRANT_TO}" ]; then
    pb_step "Grants for ${PB_GRANT_TO}"
    pb_proj_ref=""
    [ -z "${PB_PROJECT_EXISTS}" ] || pb_proj_ref="${PB_PROJECT}"
    pb_grant project "${pb_proj_ref}" roles/owner "${PB_GRANT_PROJ}"
    pb_grant folder "${PB_FOLDER_NUM}" roles/resourcemanager.folderIamAdmin "${PB_GRANT_FOLD}"
fi

# ------------------------------------------------------------------------------
# 5b. Organization roles for the bootstrap runner (rows 7 and 8; PREBOOTSTRAP-OFFER-ORG-ROLES, owner 11-16)
# ------------------------------------------------------------------------------
# When row 7 (Tag Administrator) and/or row 8 (Organization Policy Administrator) is missing for the person who runs
# bootstrap, and the signed-in account can set IAM on the organization (read-only testIamPermissions of
# resourcemanager.organizations.getIamPolicy + setIamPolicy, never inferred from a role name), each missing grant is
# offered. Both roles are granted on the organization: Google grants roles/orgpolicy.policyAdmin only there ("lowest-
# level resource: Organization"; the folder policy needs it, documentation/quickstart.md row 8), and the tag key is
# created on the organization. The question says it is organization-wide and needs the full word yes (bash 3.2 cannot
# tell whether keys were typed ahead without waiting, so a stray y cannot grant). Nothing is offered (the grant command
# stays printed, as before) with N / Enter or any other answer, --yes, no terminal (stdin, as every prompt here),
# the caller's own CLOUDSDK_CORE_DISABLE_PROMPTS=1, --check-only (already exited), a personal runner account (row 1),
# gcloud impersonating a service account, or a project / folder not confirmed to be in organizations/<n>;
# --dry-run prints the command it would run. The grant is add-only (gcloud organizations add-iam-policy-binding ...
# --condition=None) and never made when the member already holds the role unconditionally. Afterwards the same
# read-only check runs again, polling while IAM propagates (PB_ORG_GRANT_POLL_SECS, default 10 s, up to
# PB_ORG_GRANT_WAIT_SECS, default 120 s): verified -> [DONE]; not visible yet -> PREBOOT_ORG_GRANT_NOT_VISIBLE
# (never reported as verified). A failed grant -> PREBOOT_ORG_GRANT_FAILED with gcloud's message, as a warning: rows
# 7 and 8 are DEGRADED / OPTIONAL, bootstrap checks both again (documentation/fail-loudly-policy.md section 2), and the
# row stays in the "Still missing" summary with its grant command.
if [[ "${PB_ORG_GRANT_WAIT_SECS:-}" =~ ^[0-9]{1,4}$ ]]; then
    PB_ORG_GRANT_WAIT_SECS=$((10#${PB_ORG_GRANT_WAIT_SECS}))
else
    PB_ORG_GRANT_WAIT_SECS=120
fi
if [[ "${PB_ORG_GRANT_POLL_SECS:-}" =~ ^[0-9]{1,4}$ ]] && [ "$((10#${PB_ORG_GRANT_POLL_SECS}))" -ge 1 ]; then
    PB_ORG_GRANT_POLL_SECS=$((10#${PB_ORG_GRANT_POLL_SECS}))
else
    PB_ORG_GRANT_POLL_SECS=10
fi
PB_ORG_ADMIN_PERMS="resourcemanager.organizations.getIamPolicy resourcemanager.organizations.setIamPolicy"
PB_ORG_GRANTED=""   # "row 7 (Tag Administrator, roles/...)" entries, granted and verified in this run
PB_ORG_PENDING=""   # granted in this run, not visible yet
PB_ORG_FIXED_ROWS=""
PB_ORG_POLICY_JSON=""
PB_ORG_READ_ERR=""  # --grant-to: the last organization IAM policy read that failed

# rc 0 when the row grant to the runner is visible: the signed-in account's own testIamPermissions on the resource the
# table tested ($1, permissions $2); for --grant-to someone else, their unconditional binding of $3 in the organization
# IAM policy (their own rights cannot be tested from here). Runs in this shell (PB_HTTP / PB_ORG_READ_ERR survive).
pb_org_role_visible() {
    local rc=0
    if [ -n "${PB_RUNNER_IS_ME}" ]; then
        pb_test_permissions "$1" "$2" || return 1
        [ "$(pb_have "${PB_G}" "$2" 1)" = "yes" ]
        return
    fi
    PB_ORG_READ_ERR=""
    if ! pb_gread gcloud organizations get-iam-policy "${PB_ORG}" --format=json; then
        PB_ORG_READ_ERR="${PB_RO_ERR:-no message}"
        return 1
    fi
    printf '%s' "${PB_RO_OUT}" | pb_py has_binding "$3" "${PB_RUNNER}" 2>/dev/null || rc=$?
    [ "${rc}" -eq 0 ]
}

pb_org_offer() {
    # $1 = row, $2 = role, $3 = role title, $4 = resource the table tested, $5 = its permissions, $6 = what the role
    # lets the member do (organization-wide)
    local row="$1" role="$2" title="$3" res="$4" perms="$5" scope="$6" has=0 answer="" rc=0 waited=0 question entry
    local who="${PB_RUNNER#*:}" group_note="" last=""
    entry="row ${row} (${title}, ${role})"
    printf '%s' "${PB_ORG_POLICY_JSON}" | pb_py has_binding "${role}" "${PB_RUNNER}" 2>/dev/null || has=$?
    if [ "${has}" -eq 0 ]; then
        if [ -n "${PB_RUNNER_IS_ME}" ]; then
            # The binding is there but the permissions are not: granting it again would change nothing.
            pb_warn "Row ${row}: ${PB_RUNNER} already holds ${role} on ${PB_ORG_RES}, but testIamPermissions on ${res} reports its permissions missing (an IAM deny policy, or a role change still propagating?); not granted again."
        else
            pb_ok "Row ${row}: ${PB_RUNNER} already has ${title} (${role}) on ${PB_ORG_RES}."
        fi
        return 0
    elif [ "${has}" -ne 1 ]; then
        pb_warn "Row ${row}: the IAM policy of ${PB_ORG_RES} could not be parsed, so ${role} is not offered; the grant command is in the list above."
        return 0
    fi
    [ -n "${PB_RUNNER_IS_ME}" ] || group_note=" (${who} may already hold it through a group.)"
    question="Grant ${title} (${role}) on ${PB_ORG_RES} to ${PB_RUNNER} now? This is organization-wide: it lets ${who} ${scope} in ${PB_ORG_RES}.${group_note} Type yes to grant, or press Enter to skip"
    if [ -n "${PB_DRY_RUN}" ]; then
        pb_info "Row ${row}: a real run in a terminal asks \"${question}\"; on yes it runs:"
        pb_write gcloud organizations add-iam-policy-binding "${PB_ORG}" "--member=${PB_RUNNER}" "--role=${role}" --condition=None --format=none
        return 0
    fi
    read -r -p "${question}: " answer || answer=""
    case "$(pb_lower "${answer}")" in
        yes) ;;
        "") return 0 ;;   # exactly as before: the grant command stays in the list above
        *) pb_info "Row ${row}: not granted (only the full word yes grants it); the grant command is in the list above."
           return 0 ;;
    esac
    pb_write gcloud organizations add-iam-policy-binding "${PB_ORG}" "--member=${PB_RUNNER}" "--role=${role}" --condition=None --format=none || rc=$?
    if [ "${rc}" -ne 0 ]; then
        pb_warn "PREBOOT_ORG_GRANT_FAILED: granting ${role} on ${PB_ORG_RES} to ${PB_RUNNER} failed, so row ${row} is still missing (nothing else was changed; continuing, as without the role). gcloud said: ${PB_OUT:-no message}. $(pb_admin_of "${PB_ORG_RES}") runs: $(pb_grant_cmd "${PB_ORG_RES}" "${PB_RUNNER}" "${role}")"
        return 0
    fi
    # IAM propagation: check now, then every PB_ORG_GRANT_POLL_SECS until PB_ORG_GRANT_WAIT_SECS have passed.
    while ! pb_org_role_visible "${res}" "${perms}" "${role}"; do
        if [ "${waited}" -ge "${PB_ORG_GRANT_WAIT_SECS}" ]; then
            if [ -n "${PB_RUNNER_IS_ME}" ]; then
                [ "${PB_HTTP}" = "200" ] || last=" (last check failed: HTTP ${PB_HTTP:-none}${PB_ERR:+: ${PB_ERR}})"
                pb_warn "PREBOOT_ORG_GRANT_NOT_VISIBLE: granted ${role} on ${PB_ORG_RES} to ${PB_RUNNER}, but after ${waited} s testIamPermissions on ${res} does not show its permissions yet${last}. Not verified. IAM changes can take a few minutes; bootstrap checks row ${row} again before it relies on it (if it still reports it missing, wait a few minutes and run it again)."
            else
                [ -z "${PB_ORG_READ_ERR}" ] || last=" (last policy read failed: ${PB_ORG_READ_ERR})"
                pb_warn "PREBOOT_ORG_GRANT_NOT_VISIBLE: granted ${role} on ${PB_ORG_RES} to ${PB_RUNNER}, but after ${waited} s the organization IAM policy does not list the binding yet${last}. Not verified. ${who}'s own check (the command above) and bootstrap test row ${row} again."
            fi
            PB_ORG_PENDING="${PB_ORG_PENDING:+${PB_ORG_PENDING}, }${entry}"
            PB_ORG_FIXED_ROWS="${PB_ORG_FIXED_ROWS} ${row}"
            return 0
        fi
        sleep "${PB_ORG_GRANT_POLL_SECS}"
        waited=$((waited + PB_ORG_GRANT_POLL_SECS))
    done
    if [ -n "${PB_RUNNER_IS_ME}" ]; then
        pb_done "Granted ${title} (${role}) on ${PB_ORG_RES} to ${PB_RUNNER}; verified: testIamPermissions on ${res} now returns the row ${row} permissions."
    else
        pb_done "Granted ${title} (${role}) on ${PB_ORG_RES} to ${PB_RUNNER}; binding verified: the organization IAM policy lists it (${who}'s own rights are tested by their check and by bootstrap)."
    fi
    PB_ORG_GRANTED="${PB_ORG_GRANTED:+${PB_ORG_GRANTED}, }${entry}"
    PB_ORG_FIXED_ROWS="${PB_ORG_FIXED_ROWS} ${row}"
}

# An unattended caller never gets an organization-wide grant: besides --yes and no terminal (stdin, as every prompt of
# this script), the caller's own CLOUDSDK_CORE_DISABLE_PROMPTS=1/true (saved at the top, before this script set it
# for gcloud) also means no question.
PB_CALLER_NO_PROMPTS=""
if [ -n "${PB_ORIG_DISABLE_PROMPTS_SET}" ]; then
    case "$(pb_lower "${PB_ORIG_DISABLE_PROMPTS}")" in 1|true|yes|on) PB_CALLER_NO_PROMPTS=1 ;; esac
fi
if [ -n "${PB_ORG}" ] && { [ -n "${PB_ORG_OFFER7}" ] || [ -n "${PB_ORG_OFFER8}" ]; } && [ -z "${PB_YES}" ] \
    && [ -z "${PB_CALLER_NO_PROMPTS}" ] && { [ -n "${PB_TTY}" ] || [ -n "${PB_DRY_RUN}" ]; }; then
    pb_imp="${CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT:-}"
    if [ -z "${pb_imp}" ]; then
        pb_imp="$(gcloud config get-value auth/impersonate_service_account 2>/dev/null)" || pb_imp=""
        [ "${pb_imp}" != "(unset)" ] || pb_imp=""
    fi
    if [ -n "${PB_RUNNER_PERSONAL}" ]; then
        pb_warn "Rows 7 and 8 are not offered: ${PB_RUNNER_EMAIL} is a personal Google account (row 1). Their grant commands are in the list above."
    elif [ -n "${PB_ORG_UNCONFIRMED}" ]; then
        pb_warn "PREBOOT_ORG_OFFER_SKIPPED: rows 7 and 8 are not offered, because ${PB_ORG_UNCONFIRMED}; a grant on ${PB_ORG_RES} might not reach it. Check --org; their grant commands are in the list above."
    elif [ -n "${pb_imp}" ]; then
        pb_warn "Rows 7 and 8 are not offered: gcloud impersonates ${pb_imp} (auth/impersonate_service_account), so the rights checked are not ${PB_ACCOUNT}'s own. Their grant commands are in the list above."
    elif ! pb_test_permissions "${PB_ORG_RES}" "${PB_ORG_ADMIN_PERMS}"; then
        pb_warn "Could not check whether ${PB_ACCOUNT} can set IAM on ${PB_ORG_RES} (testIamPermissions: HTTP ${PB_HTTP:-none}${PB_ERR:+: ${PB_ERR}}), so rows 7 and 8 are not offered; their grant commands are in the list above."
    elif [ "$(pb_have "${PB_G}" "${PB_ORG_ADMIN_PERMS}" 1)" = "yes" ]; then
        # Read-only: who already holds the roles (PB_ORG_POLICY_JSON). Unreadable -> nothing is offered.
        if ! pb_gread gcloud organizations get-iam-policy "${PB_ORG}" --format=json; then
            pb_warn "Could not read the IAM policy of ${PB_ORG_RES} (${PB_RO_ERR:-no message}), so rows 7 and 8 are not offered; their grant commands are in the list above."
        else
            PB_ORG_POLICY_JSON="${PB_RO_OUT}"
            pb_step "Organization roles for ${PB_RUNNER} (rows 7 and 8; you can set IAM on ${PB_ORG_RES})"
            [ -z "${PB_ORG_OFFER7}" ] || pb_org_offer 7 roles/resourcemanager.tagAdmin "Tag Administrator" \
                "${PB_ORG_RES}" "${PB_TAG_PERMS}" "create, change and delete tags and their access anywhere"
            [ -z "${PB_ORG_OFFER8}" ] || pb_org_offer 8 roles/orgpolicy.policyAdmin "Organization Policy Administrator" \
                "${pb_res8}" "${PB_ORGPOLICY_PERMS}" "change every organization policy"
        fi
    fi
    # Otherwise the signed-in account cannot set IAM on the organization: nothing is offered, as before.
fi

# ------------------------------------------------------------------------------
# 6. Summary: the answers for scripts/bootstrap.sh
# ------------------------------------------------------------------------------
if [ -n "${PB_DRY_RUN}" ]; then
    pb_step "Dry run finished: nothing was changed. Without --dry-run, bootstrap's answers would be:"
else
    pb_step "Ready for scripts/bootstrap.sh. At its prompts, answer:"
fi
echo -e "   Project ID:                    ${BOLD}${PB_PROJECT}${RESET}"
echo -e "   Organization ID:               ${BOLD}organizations/${PB_ORG}${RESET}"
echo -e "   Billing Account ID:            ${BOLD}${PB_BILLING}${RESET}"
echo -e "   Managed Workloads Folder ID:   ${BOLD}${PB_FOLDER:-folders/<FOLDER_ID, created on the real run>}${RESET}"
echo -e "   (the other prompts: see documentation/quickstart.md section 2)"
# BOOTSTRAP-TOS-FAIL-LOUD (live finding 11-03): no read-only API reports whether an account accepted the Google Cloud
# Terms of Service, so this is a note, not a check (bootstrap stops with BOOTSTRAP_CLOUD_TERMS_NOT_ACCEPTED).
echo -e "   A new account must accept the Google Cloud Terms of Service once (open console.cloud.google.com as that account) before bootstrap can enable APIs."
if [ -n "${PB_ORG_GRANTED}" ] && [ -n "${PB_RUNNER_IS_ME}" ]; then
    pb_ok "Granted in this run and verified: ${PB_ORG_GRANTED}."
elif [ -n "${PB_ORG_GRANTED}" ]; then
    pb_ok "Granted in this run, binding verified in the organization IAM policy: ${PB_ORG_GRANTED}. ${PB_RUNNER#*:}'s own rights are tested by their check and by bootstrap."
fi
[ -z "${PB_ORG_PENDING}" ] || pb_warn "Granted in this run, not verified yet (PREBOOT_ORG_GRANT_NOT_VISIBLE above): ${PB_ORG_PENDING}. bootstrap checks it again."
if [ -n "${PB_DEGRADED}" ]; then
    if [ -z "${PB_ORG_FIXED_ROWS}" ]; then
        pb_warn "Still missing (not blocking): see the DEGRADED / OPTIONAL list above."
    else
        # Rows granted in this run (verified or pending, reported just above) are left out.
        pb_still=""
        for pb_r in ${PB_DEGRADED_ROWS}; do
            case " ${PB_ORG_FIXED_ROWS} " in
                *" ${pb_r} "*) ;;
                *) pb_still="${pb_still:+${pb_still}, }${pb_r}" ;;
            esac
        done
        [ -z "${pb_still}" ] || pb_warn "Still missing (not blocking): row(s) ${pb_still} of the DEGRADED / OPTIONAL list above."
    fi
fi
if [ -n "${PB_GRANT_TO}" ] && [ -z "${PB_RUNNER_IS_ME}" ]; then
    # Their own sign-in: this account's gcloud configuration is not theirs, so no CLOUDSDK_ACTIVE_CONFIG_NAME prefix.
    echo -e "\n   Next, ${PB_GRANT_TO#user:} checks their rights and runs bootstrap, with their own gcloud sign-in"
    echo -e "   (their own account, or their own gcloud configuration; documentation/quickstart.md \"Sign in\"):"
    echo -e "     ${PB_RUNNER_CHECK_CMD/<FOLDER_ID>/${PB_FOLDER_NUM:-<FOLDER_ID>}}"
    echo -e "     ${BOLD}bash scripts/bootstrap.sh${RESET}"
else
    # BOOTSTRAP-PREFILL (owner 11-03): the bootstrap command carries these values as its prompts' defaults. After a
    # real run, in a terminal and without --yes (--yes never starts it), offer to start it now (exec: this script
    # ends there; the gcloud configuration is inherited, and gcloud's own prompts are as the caller had them).
    pb_bootstrap_command
    pb_start=""
    if [ -z "${PB_DRY_RUN}" ] && [ -n "${PB_TTY}" ] && [ -z "${PB_YES}" ]; then
        pb_answer=""
        echo
        read -r -p "Run scripts/bootstrap.sh now with these values? [Y/n]: " pb_answer || pb_answer="n"
        case "${pb_answer}" in
            ""|[Yy]|[Yy][Ee][Ss]) pb_start=1 ;;
        esac
    fi
    if [ -n "${pb_start}" ]; then
        echo -e "\n${BLUE}==>${RESET} Starting: ${BOLD}${PB_BOOT_CMD}${RESET}\n"
        if [ -n "${PB_ORIG_DISABLE_PROMPTS_SET}" ]; then
            exec env "CLOUDSDK_CORE_DISABLE_PROMPTS=${PB_ORIG_DISABLE_PROMPTS}" "${PB_BOOT_ENV[@]}" bash "${REPO_ROOT}/scripts/bootstrap.sh"
        fi
        exec env -u CLOUDSDK_CORE_DISABLE_PROMPTS "${PB_BOOT_ENV[@]}" bash "${REPO_ROOT}/scripts/bootstrap.sh"
    fi
    echo -e "\n   Next:"
    echo -e "     ${BOLD}${PB_BOOT_CMD}${RESET}"
fi
