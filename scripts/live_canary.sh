#!/bin/bash
# ==============================================================================
# STACKVEND: live end-to-end canary (FD-4DN; release gate RC-LIVE-GATE)
# ==============================================================================
# Sends one example workload (default: example 01, Cloud Run + Pub/Sub event router) through a dev install and
# follows it read-only through every stage: workflow execution, workload record, pipeline stage, QA job and verdict,
# Cloud Build in the child project, the tf-applier execution, the final service URL (from the platform records,
# never from listing Cloud Run in the child project) and a /health check that follows the workload's access mode
# (public: anonymous GET; private IAM: your identity token; private IAP: /health is NOT probed, because a gcloud user
# identity token cannot pass Direct IAP: the canary only checks that an anonymous request is redirected to Google
# sign-in and reports HEALTH_NOT_PROBED_PRIVATE_IAP, exit 6, never a pass).
# One line per stage transition, with UTC timestamps; a per-stage summary at the end.
#
# Submission: the operator submits the workload in the Control Center (Workloads Catalog -> New Workload), the same
# way any user does. The Control Center authenticates people only through Google sign-in (or IAP); it accepts an
# OIDC bearer only from its allow-listed platform service account, and the spec-intake topic is publishable only by
# the platform services, so this script never submits on its own (no bypass of either check). It prints the form
# values and the spec text, waits for the workload record to appear, then follows it.
#
# Read-only everywhere: no writes, no deletes, no retries, no approvals. Tokens come from the operator's gcloud
# login and are never printed or put on a command line.
#
# Usage:
#   scripts/live_canary.sh --project <host project> [--region us-central1] [--product-id <new id>]
#                          [--example documentation/examples/01-cloudrun-pubsub-event-router.md]
#                          [--timeout-min 75] [--submit-wait-min 30] [--poll-sec 30] [--iap-browser-check]
#                          [--child-checks]
#   scripts/live_canary.sh --project <host project> --watch-only <product_id> [--trace-id <run>] [--timeout-min 75]
#                          [--iap-browser-check] [--child-checks]
#
#   --iap-browser-check  for a PRIVATE_IAP workload, also print the /health URL to open in a browser signed in as
#                        one of the workload's allowed principals (the canary itself never signs in through IAP)
#   --child-checks       opt-in (default off), for operators with roles/run.viewer + roles/logging.viewer in the
#                        child project: a PRIVATE_IAP workload is checked from the child project's Cloud Run revision
#                        (Ready, startup probe on /health) and its startup-probe log line, plus the IAP redirect;
#                        it can then PASS (exit 0); a missing permission is ERROR (permission denied), exit 5
#
# Exit codes: 0 pass; 1 the pipeline failed; 2 usage; 3 timed out (or never submitted); 4 deployed but /health
# failed (or a PRIVATE_IAP service is not behind IAP); 5 a prerequisite is missing (gcloud, curl, python3, a gcloud
# login, read access to the records; with --child-checks, read access to the child project's Cloud Run service and
# Cloud Logging); 6 deployed, health not probeable from the command line
# (HEALTH_NOT_PROBED_PRIVATE_IAP: IAP is in front; check /health in a browser).
#
# Bash 3.2 compatible (macOS /bin/bash). Needs gcloud, curl and python3 (standard library only).
# ==============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
FOLLOWER="${SCRIPT_DIR}/live_canary_follow.py"
CC_SERVICE="product-control-center-ui"

PROJECT_RE='^[a-z][a-z0-9-]{4,28}[a-z0-9]$'
REGION_RE='^[a-z]+-[a-z]+[0-9]+$'
# A product id of 6-30 characters that starts with a letter is also the child project id (the Control Center's rule)
PRODUCT_RE='^[a-z][a-z0-9-]{4,28}[a-z0-9]$'
NUMBER_RE='^[0-9]+$'

PROJECT=""
REGION="us-central1"
PRODUCT_ID=""
WATCH_ONLY=""
TRACE_ID=""
EXAMPLE="documentation/examples/01-cloudrun-pubsub-event-router.md"
TIMEOUT_MIN="75"
SUBMIT_WAIT_MIN="30"
POLL_SEC="30"
IAP_BROWSER_CHECK=""
CHILD_CHECKS=""

usage() {
    sed -n '/^# Usage:/,/^# Bash 3.2/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'
}

die_usage() {
    echo "live_canary: $*" >&2
    echo "" >&2
    usage >&2
    exit 2
}

die_prereq() {
    echo "live_canary: $*" >&2
    exit 5
}

need_value() {
    # $1 = flag, $2 = number of remaining args (including the flag)
    if [ "$2" -lt 2 ]; then
        die_usage "$1 needs a value"
    fi
}

while [ $# -gt 0 ]; do
    case "$1" in
        --project) need_value "$1" $#; PROJECT="$2"; shift 2 ;;
        --region) need_value "$1" $#; REGION="$2"; shift 2 ;;
        --product-id) need_value "$1" $#; PRODUCT_ID="$2"; shift 2 ;;
        --watch-only) need_value "$1" $#; WATCH_ONLY="$2"; shift 2 ;;
        --trace-id) need_value "$1" $#; TRACE_ID="$2"; shift 2 ;;
        --example) need_value "$1" $#; EXAMPLE="$2"; shift 2 ;;
        --timeout-min) need_value "$1" $#; TIMEOUT_MIN="$2"; shift 2 ;;
        --submit-wait-min) need_value "$1" $#; SUBMIT_WAIT_MIN="$2"; shift 2 ;;
        --poll-sec) need_value "$1" $#; POLL_SEC="$2"; shift 2 ;;
        --iap-browser-check) IAP_BROWSER_CHECK="1"; shift ;;
        --child-checks) CHILD_CHECKS="1"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die_usage "unknown argument: $1" ;;
    esac
done

[ -n "$PROJECT" ] || die_usage "--project is required"
[[ "$PROJECT" =~ $PROJECT_RE ]] || die_usage "invalid --project '$PROJECT'"
[[ "$REGION" =~ $REGION_RE ]] || die_usage "invalid --region '$REGION'"
[[ "$TIMEOUT_MIN" =~ $NUMBER_RE ]] && [ "$TIMEOUT_MIN" -gt 0 ] || die_usage "--timeout-min must be a positive whole number"
[[ "$SUBMIT_WAIT_MIN" =~ $NUMBER_RE ]] && [ "$SUBMIT_WAIT_MIN" -gt 0 ] || die_usage "--submit-wait-min must be a positive whole number"
[[ "$POLL_SEC" =~ $NUMBER_RE ]] || die_usage "--poll-sec must be a whole number"
if [ -n "$WATCH_ONLY" ] && [ -n "$PRODUCT_ID" ] && [ "$WATCH_ONLY" != "$PRODUCT_ID" ]; then
    die_usage "--watch-only and --product-id name different workloads"
fi
if [ -n "$TRACE_ID" ] && [ -z "$WATCH_ONLY" ]; then
    die_usage "--trace-id only applies with --watch-only"
fi
if [ -n "$TRACE_ID" ] && ! [[ "$TRACE_ID" =~ ^[A-Za-z0-9._-]{1,128}$ ]]; then
    die_usage "invalid --trace-id '$TRACE_ID'"
fi

if [ -n "$WATCH_ONLY" ]; then
    MODE="watch"
    PRODUCT_ID="$WATCH_ONLY"
    # an existing workload may predate the 6-30 rule (the Control Center normalises other ids); accept its slug form
    [[ "$PRODUCT_ID" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || die_usage "invalid --watch-only '$PRODUCT_ID'"
else
    MODE="submit"
    if [ -z "$PRODUCT_ID" ]; then
        PRODUCT_ID="canary01-$(date -u +%m%d%H%M)"
    fi
    [[ "$PRODUCT_ID" =~ $PRODUCT_RE ]] || die_usage "invalid --product-id '$PRODUCT_ID' (6-30 characters: a-z, 0-9, '-'; starts with a letter)"
    case "$EXAMPLE" in
        /*) EXAMPLE_PATH="$EXAMPLE" ;;
        *) if [ -f "$EXAMPLE" ]; then EXAMPLE_PATH="$EXAMPLE"; else EXAMPLE_PATH="${REPO_ROOT}/${EXAMPLE}"; fi ;;
    esac
    [ -f "$EXAMPLE_PATH" ] || die_usage "example not found: $EXAMPLE"
fi

for tool in gcloud curl python3; do
    command -v "$tool" >/dev/null 2>&1 || die_prereq "'$tool' is not installed or not on PATH"
done
[ -f "$FOLLOWER" ] || die_prereq "helper missing: $FOLLOWER"

ACTIVE_ACCOUNT="$(gcloud auth list --filter=status:ACTIVE --format='value(account)' 2>/dev/null | head -n 1)"
[ -n "$ACTIVE_ACCOUNT" ] || die_prereq "no active gcloud login: run 'gcloud auth login' first"

FOLLOW_ARGS=(follow --project "$PROJECT" --region "$REGION" --product-id "$PRODUCT_ID"
             --timeout-min "$TIMEOUT_MIN" --poll-sec "$POLL_SEC")
if [ -n "$IAP_BROWSER_CHECK" ]; then
    FOLLOW_ARGS+=(--iap-browser-check)
fi
if [ -n "$CHILD_CHECKS" ]; then
    FOLLOW_ARGS+=(--child-checks)
fi

echo "StackVend live canary: project ${PROJECT}, region ${REGION}, workload ${PRODUCT_ID} (${MODE})"

if [ "$MODE" = "submit" ]; then
    SPEC_TEXT="$(python3 -I "$FOLLOWER" spec "$EXAMPLE_PATH")" || exit 2
    CC_URL="$(gcloud run services describe "$CC_SERVICE" --project="$PROJECT" --region="$REGION" \
        --format='value(status.url)' 2>/dev/null)"
    [ -n "$CC_URL" ] || CC_URL="<Control Center URL> (could not read service ${CC_SERVICE} in ${PROJECT})"
    SINCE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    cat <<EOF

Submit the canary workload in the Control Center (Google sign-in, administrator):
  1. Open ${CC_URL}  ->  Workloads Catalog  ->  New Workload.
  2. Workload Identifier (Slug): ${PRODUCT_ID}
  3. Technical Specification & Requirements: paste the text between the lines below
     (from ${EXAMPLE}, "Workload Form Submission Prompt").
  4. Turn OFF "Require Human Code Review (HITL)" and "Require Plan Approval Before Development"
     so the run needs no approval clicks (if you leave them on, approve in Approvals while the canary waits).
  5. Turn ON "Designate as Autonomous Sandbox" (the canary workload is disposable).
  6. Leave access at the default (Private, Google sign-in through IAP). The canary does not sign in through
     IAP: it checks that IAP redirects an anonymous request and reports HEALTH_NOT_PROBED_PRIVATE_IAP (exit 6);
     open /health in a browser signed in as an allowed principal (--iap-browser-check prints the URL).
  7. Submit. This script waits up to ${SUBMIT_WAIT_MIN} min for the workload record, then follows it.
----------------------------------------------------------------------------------------------------
${SPEC_TEXT}
----------------------------------------------------------------------------------------------------

EOF
    FOLLOW_ARGS+=(--await-submit-min "$SUBMIT_WAIT_MIN" --require-new --since "$SINCE")
else
    EXTRA=()
    if [ -n "$TRACE_ID" ]; then
        EXTRA=(--trace-id "$TRACE_ID")
    fi
    FOLLOW_ARGS+=(${EXTRA[@]+"${EXTRA[@]}"})
fi

python3 -I "$FOLLOWER" "${FOLLOW_ARGS[@]}"
exit $?
