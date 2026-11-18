# shellcheck shell=bash
# ==============================================================================
# STACKVEND: read-only organization policy preflight for the platform network (HOST-VPC-EGRESS /
# HOST-INTERNAL-INGRESS; sourced, never executed)
# ==============================================================================
# Owner 11-07 (Design B for the RC): infra/platform/host_network.tf gives every host Cloud Run service and job except
# the QA sandbox job Direct VPC egress (PRIVATE_RANGES_ONLY) into the stackvend-host network, creates a Private Service
# Connect endpoint for Google APIs there, and (host_internal_ingress) makes every host service except the Control
# Center internal-only. An organization policy can refuse each of these, and the apply would then stop part-way with a
# 400 on the first refused resource. This check runs BEFORE the plan (scripts/apply.sh plan and apply;
# scripts/bootstrap.sh right before its plan) and reads the host project's EFFECTIVE policies, read-only:
#
#   Org Policy API v2 GET projects/<project>/policies/<constraint>:getEffectivePolicy (the host as quota project; the
#   token comes from `gcloud auth print-access-token` and goes to curl on stdin, --config -, never on the command line)
#
#   host_vpc_egress = true       -> constraints/run.allowedVPCEgress must allow the egress setting of
#                                   host_egress_mode: "private-ranges-only" (PSC_PRIVATE_RANGES, Design B; then also
#                                   constraints/compute.disablePrivateServiceConnectCreationForConsumers must not block
#                                   endpoints of type GOOGLE_APIS, see the note below) or "all-traffic"
#                                   (NAT_ALL_TRAFFIC, Design A: no PSC endpoint, so no PSC check);
#   host_internal_ingress = true -> constraints/run.allowedIngress must allow "internal";
#   both false                   -> nothing to check (no call).
#
# Verdicts, per constraint (the effective policy's unconditional rules; "is:" value prefixes are ignored):
#   allowed (no rules = the constraint's default, allowAll, or the value listed as allowed) -> [OK] line;
#   refused (denyAll, the value denied, or an allowed list without it)                       -> collected, then ONE
#       typed refusal <PREFIX>_HOST_NETWORK_ORG_POLICY_REFUSED naming every refusing constraint, before any plan;
#   cannot tell (no token, curl failure, an HTTP answer other than 200, a body that is not a Policy, or only
#       conditional (tag-based) rules)                                                       -> a WARNING with the
#       constraint and the fix; the run continues (the apply itself fails loudly if the policy does refuse).
# Note on compute.disablePrivateServiceConnectCreationForConsumers: its values name endpoint types whose creation is
# restricted, and its documentation does not pin which list polarity blocks GOOGLE_APIS. So it never refuses here:
# any effective rule other than the default (no rules, or allowAll alone) gives a WARNING naming the constraint.
# (The plan named compute.restrictPrivateServiceConnectConsumer; that one limits who may connect to a PRODUCER's
# service attachments, i.e. it is enforced in the producer's organization, so it cannot refuse an endpoint for
# Google APIs here.) compute.vmExternalIpAccess concerns VMs only (nothing to check).
# Bash 3.2 compatible.
# ==============================================================================

SV_HOSTNET_EGRESS_CONSTRAINT="run.allowedVPCEgress"
SV_HOSTNET_EGRESS_VALUE="private-ranges-only"
SV_HOSTNET_EGRESS_VALUE_NAT="all-traffic"
SV_HOSTNET_PSC_CONSTRAINT="compute.disablePrivateServiceConnectCreationForConsumers"
SV_HOSTNET_PSC_VALUE="GOOGLE_APIS"
SV_HOSTNET_INGRESS_CONSTRAINT="run.allowedIngress"
SV_HOSTNET_INGRESS_VALUE="internal"
# Set for the caller's summary.
SV_HOSTNET_PREFLIGHT_WARNINGS=""

sv_hostnet_warn() {
    SV_HOSTNET_PREFLIGHT_WARNINGS="${SV_HOSTNET_PREFLIGHT_WARNINGS:+${SV_HOSTNET_PREFLIGHT_WARNINGS} }$1"
    shift
    echo -e "\033[1;33m[WARN]\033[0m $*" >&2
}

# Evaluates one getEffectivePolicy body. $1 = body file, $2 = mode (allow-list | restrict-list), $3 = value.
# Prints exactly one line: "ALLOWED", "REFUSED <why>" or "UNCLEAR <why>"; rc != 0 when the body is not a Policy.
sv_hostnet_evaluate() {
    python3 -c '
import json, sys
path, mode, value = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    body = json.load(open(path))
except (OSError, ValueError):
    sys.exit(3)
if not isinstance(body, dict):
    sys.exit(4)
spec = body.get("spec") or {}
if not isinstance(spec, dict):
    sys.exit(4)
rules = spec.get("rules") or []
if not isinstance(rules, list) or not all(isinstance(r, dict) for r in rules):
    sys.exit(4)

def norm(v):
    v = str(v)
    return v[3:] if v.startswith("is:") else v

conditional = [r for r in rules if r.get("condition")]
plain = [r for r in rules if not r.get("condition")]
allowed, denied, allow_all, deny_all = set(), set(), False, False
for r in plain:
    allow_all = allow_all or r.get("allowAll") is True
    deny_all = deny_all or r.get("denyAll") is True
    vals = r.get("values") or {}
    if not isinstance(vals, dict):
        sys.exit(4)
    allowed |= {norm(v) for v in vals.get("allowedValues") or []}
    denied |= {norm(v) for v in vals.get("deniedValues") or []}

if mode == "restrict-list":
    default = not conditional and all(set(r) <= {"allowAll"} and r.get("allowAll") is True for r in plain)
    if default:
        print("ALLOWED")
    else:
        print("UNCLEAR the effective policy has rules (allowAll=%s denyAll=%s allowed=%s denied=%s conditional=%d); check that it does not block %s endpoints" % (
            allow_all, deny_all, sorted(allowed), sorted(denied), len(conditional), value))
    sys.exit(0)

if deny_all:
    print("REFUSED it denies every value")
elif value in denied:
    print("REFUSED it denies %s" % value)
elif allow_all or value in allowed:
    print("ALLOWED")
elif allowed:
    print("REFUSED it allows only %s" % ", ".join(sorted(allowed)))
elif conditional:
    print("UNCLEAR it has %d conditional (tag-based) rule(s), which cannot be evaluated here" % len(conditional))
else:
    print("ALLOWED")
' "$1" "$2" "$3"
}

# One READ-ONLY getEffectivePolicy call. $1 = constraint (no constraints/ prefix), $2 = output file.
# Prints the HTTP code ("" on curl failure).
sv_hostnet_get_effective() {
    printf 'header = "Authorization: Bearer %s"\nheader = "x-goog-user-project: %s"\n' "${SV_HOSTNET_TOKEN}" "${PROJECT_ID}" \
        | curl -sS --max-time 20 --config - -o "$2" -w '%{http_code}' \
            "https://orgpolicy.googleapis.com/v2/projects/${PROJECT_ID}/policies/$1:getEffectivePolicy" 2>/dev/null || true
}

# $1 = error code prefix (BOOTSTRAP | APPLY), $2 = host_vpc_egress (true|false), $3 = host_internal_ingress (true|false),
# $4 = host_egress_mode (PSC_PRIVATE_RANGES | NAT_ALL_TRAFFIC; empty = the variables.tf default PSC_PRIVATE_RANGES).
sv_host_network_preflight() {
    local prefix="$1" egress="$2" ingress="$3" egress_mode="${4:-PSC_PRIVATE_RANGES}" checks="" item constraint mode value tmp code verdict refused="" fix
    SV_HOSTNET_PREFLIGHT_WARNINGS=""
    SV_HOSTNET_TOKEN=""
    case "${egress}" in true|false) ;; *)
        sv_hostnet_warn HOST_NETWORK_ORG_POLICY_UNCHECKED "Platform network org policy preflight skipped: host_vpc_egress is '${egress}' (not true or false). The plan reads the vars file itself."
        return 0 ;;
    esac
    case "${ingress}" in true|false) ;; *)
        sv_hostnet_warn HOST_NETWORK_ORG_POLICY_UNCHECKED "Platform network org policy preflight skipped: host_internal_ingress is '${ingress}' (not true or false). The plan reads the vars file itself."
        return 0 ;;
    esac
    case "${egress_mode}" in PSC_PRIVATE_RANGES|NAT_ALL_TRAFFIC) ;; *)
        sv_hostnet_warn HOST_NETWORK_ORG_POLICY_UNCHECKED "Platform network org policy preflight skipped: host_egress_mode is '${egress_mode}' (not PSC_PRIVATE_RANGES or NAT_ALL_TRAFFIC). The plan reads the vars file itself."
        return 0 ;;
    esac
    if [ "${egress}" = "true" ] && [ "${egress_mode}" = "PSC_PRIVATE_RANGES" ]; then
        checks="${SV_HOSTNET_EGRESS_CONSTRAINT}|allow-list|${SV_HOSTNET_EGRESS_VALUE} ${SV_HOSTNET_PSC_CONSTRAINT}|restrict-list|${SV_HOSTNET_PSC_VALUE}"
    elif [ "${egress}" = "true" ]; then
        checks="${SV_HOSTNET_EGRESS_CONSTRAINT}|allow-list|${SV_HOSTNET_EGRESS_VALUE_NAT}"
    fi
    if [ "${ingress}" = "true" ]; then
        checks="${checks:+${checks} }${SV_HOSTNET_INGRESS_CONSTRAINT}|allow-list|${SV_HOSTNET_INGRESS_VALUE}"
    fi
    if [ -z "${checks}" ]; then
        echo -e "\033[0;34m==>\033[0m Platform network org policy preflight: host_vpc_egress and host_internal_ingress are false; nothing to check." >&2
        return 0
    fi
    fix="An organization policy administrator can show the effective policy with: gcloud org-policies describe <constraint> --effective --project=${PROJECT_ID}"

    SV_HOSTNET_TOKEN="$(gcloud auth print-access-token 2>/dev/null)" || SV_HOSTNET_TOKEN=""
    if [ -z "${SV_HOSTNET_TOKEN}" ]; then
        sv_hostnet_warn HOST_NETWORK_ORG_POLICY_UNCHECKED "Platform network org policy preflight: could not get an access token, so constraints/${SV_HOSTNET_EGRESS_CONSTRAINT}, constraints/${SV_HOSTNET_PSC_CONSTRAINT} and constraints/${SV_HOSTNET_INGRESS_CONSTRAINT} were not checked. If one refuses, the apply stops with a 400 that names it. ${fix}"
        return 0
    fi
    tmp="$(mktemp -d 2>/dev/null)" || tmp=""
    if [ -z "${tmp}" ]; then
        SV_HOSTNET_TOKEN=""
        sv_hostnet_warn HOST_NETWORK_ORG_POLICY_UNCHECKED "Platform network org policy preflight: mktemp failed, so the organization policies were not checked. ${fix}"
        return 0
    fi

    for item in ${checks}; do
        constraint="${item%%|*}"
        mode="${item#*|}"
        value="${mode#*|}"
        mode="${mode%%|*}"
        rm -f "${tmp}/policy.json"
        code="$(sv_hostnet_get_effective "${constraint}" "${tmp}/policy.json")"
        verdict=""
        if [ "${code}" = "200" ]; then
            verdict="$(sv_hostnet_evaluate "${tmp}/policy.json" "${mode}" "${value}")" || verdict="UNCLEAR the answer is not an organization policy"
        else
            verdict="UNCLEAR the effective policy could not be read (HTTP ${code:-none})"
        fi
        case "${verdict}" in
            ALLOWED)
                echo -e "\033[0;32m[OK]\033[0m Platform network org policy preflight: constraints/${constraint} allows ${value} on ${PROJECT_ID}." >&2 ;;
            REFUSED*)
                refused="${refused:+${refused}; }constraints/${constraint} refuses ${value} (${verdict#REFUSED })" ;;
            *)
                sv_hostnet_warn HOST_NETWORK_ORG_POLICY_UNCHECKED "Platform network org policy preflight: constraints/${constraint} on ${PROJECT_ID}: ${verdict#UNCLEAR }. If it refuses ${value}, the apply stops with a 400 that names it. ${fix/<constraint>/${constraint}}" ;;
        esac
    done
    rm -rf "${tmp}"
    SV_HOSTNET_TOKEN=""

    if [ -n "${refused}" ]; then
        sv_die "${prefix}_HOST_NETWORK_ORG_POLICY_REFUSED: ${refused}. The platform network (infra/platform/host_network.tf: host_vpc_egress = ${egress}, host_internal_ingress = ${ingress}, host_egress_mode = ${egress_mode}) needs it. Nothing was applied. Fix: an organization policy administrator allows that value for ${PROJECT_ID} (gcloud org-policies describe <constraint> --effective --project=${PROJECT_ID} shows the policy), or set the switch to false in ${TFVARS:-the vars file} (host_internal_ingress = false keeps every host service public with IAM; host_vpc_egress = false also needs host_internal_ingress = false) and re-run."
    fi
    return 0
}
