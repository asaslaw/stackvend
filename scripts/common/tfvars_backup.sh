# shellcheck shell=bash
# ==============================================================================
# STACKVEND: automatic backup + restore of infra/platform/<project_id>.tfvars (TFVARS-AUTO-BACKUP; sourced, never
# executed)
# ==============================================================================
# Owner 11-16 (register row TFVARS-AUTO-BACKUP). The install's vars file is gitignored, so the machine that ran the
# installer used to hold the only copy: losing it (new machine, re-clone) blocked scripts/apply.sh, and re-running the
# installer lost hand edits (for example extra authorized_invoker_members). It holds no secret (ids, flags, e-mail
# addresses and public OAuth client IDs; the tenant client secret goes only to Secret Manager), and every value in it
# is also in the platform state next to it.
#
# The copy lives next to the platform state: gs://castor-tfstate-<project_id>/platform/<project_id>.tfvars. StackVend's
# agent and job service accounts can write only under workloads/ in that bucket (stackvend-workload-state-only
# condition); a principal with a project-level storage role (the project's owners and, for example, the Compute Engine
# default service account Cloud Build uses, which has project-level storage.admin) is not limited by that condition.
# So a restored copy is reviewed before the next run. Every call uses the operator's own gcloud login.
#
#   sv_tfvars_backup_write PREFIX SRC RETRY   (scripts/bootstrap.sh at the end of an install, PREFIX=BOOTSTRAP;
#                                              scripts/apply.sh after every successful apply, PREFIX=APPLY)
#     One READ-ONLY metadata GET of the object (JSON API; the token from `gcloud auth print-access-token` goes to curl on
#     stdin, never on the command line) decides, by HTTP status:
#       404           -> upload SRC with --if-generation-match=0 (never overwrites an object written meanwhile);
#       200, same MD5 -> nothing to write ("is up to date");
#       200, differs  -> first copy exactly the generation that was read (<uri>#<generation>) to
#                        <project_id>.tfvars.prev-<UTC> (--if-generation-match=0), then upload SRC with
#                        --if-generation-match=<that generation>. Explicit copies, not bucket object versioning:
#                        bootstrap turns versioning on best effort (a warning when it cannot) and only for a bucket it
#                        creates, so an older bucket may not keep noncurrent versions;
#       anything else -> nothing written (an unread copy is never overwritten).
#     Success: "[OK] Backed up ..." and rc 0. Any failure: the typed warning <PREFIX>_TFVARS_BACKUP_NOT_WRITTEN with the
#     reason and RETRY, rc 1. The install or apply itself already succeeded, so callers warn and continue
#     (documentation/fail-loudly-policy.md section 2).
#
#   sv_tfvars_backup_note BUCKET              (scripts/bootstrap.sh, when the local file does not exist before the
#                                              install questions): the same GET; 200 -> a prominent [NOTE] that a
#                                              backup exists and `apply.sh plan` restores it. A note only: no prompt,
#                                              no stop, nothing written.
#
#   sv_tfvars_restore_offer ARGS_DISPLAY      (scripts/apply.sh, before the target is resolved)
#     Only when PROJECT_ID is set (and valid), TFVARS_FILE is not, and neither infra/platform/<project_id>.tfvars nor
#     infra/platform/terraform.tfvars exists (a dangling link counts as existing). The same metadata GET decides:
#       200 -> shows the object, its size and its update time; on a terminal asks
#              "Restore infra/platform/<id>.tfvars from gs://...? [y/N]". y: download exactly the generation that was
#              read into a 0700 temp dir under $TMPDIR, check it is not empty, matches the object's MD5 (its size when
#              the object has no MD5) and holds project_id = PROJECT_ID (real HCL parser, sv_tfvar), then create the
#              destination with O_CREAT|O_EXCL|O_NOFOLLOW, mode 600 (never over an existing file, link or directory),
#              then STOP with APPLY_TFVARS_RESTORED (exit 1: nothing was planned or applied; the operator reviews the
#              file, then re-runs). N, Enter or no terminal -> APPLY_TFVARS_MISSING.
#       404 -> APPLY_TFVARS_MISSING_NO_BACKUP (re-run the installer; hand edits must be made again).
#       anything else -> APPLY_TFVARS_BACKUP_UNCHECKED.
#     A failed download or check -> APPLY_TFVARS_RESTORE_FAILED (a wrong project_id -> APPLY_TFVARS_BACKUP_PROJECT_MISMATCH);
#     nothing is written to infra/platform.
#
# Temp files: every temp dir is registered (sv_tfb_mktemp) and removed on every path out of these functions; every
# stop goes through sv_tfb_die, which removes them first. While one exists, INT/TERM/HUP traps remove them and exit
# 130/143/129 (the caller's own EXIT trap then runs as usual); the earlier INT/TERM/HUP traps are put back when the last
# one is removed. (A signal that was already ignored when the shell started cannot be trapped: bash rule.) EXIT is deliberately not trapped here: apply.sh and bootstrap.sh own their EXIT traps (bootstrap's
# reads the exit status first).
# Bash 3.2 compatible; every refusal exits through sv_die (scripts/common/platform_target.sh).
# ==============================================================================

SV_TFB_TMPS=""
SV_TFB_SAVED_TRAPS=""

# Removes every registered temp dir.
sv_tfb_cleanup_all() {
    local p
    while IFS= read -r p; do
        [ -z "${p}" ] || rm -rf "${p}"
    done <<< "${SV_TFB_TMPS}"
    SV_TFB_TMPS=""
}

sv_tfb_on_signal() {
    sv_tfb_cleanup_all
    exit "$1"
}

# Creates a 0700 temp dir under $TMPDIR, registers it and stores its path in the variable named $1. rc 1 on failure.
sv_tfb_mktemp() {
    local d
    d="$(mktemp -d 2>/dev/null)" || return 1
    [ -n "${d}" ] || return 1
    if [ -z "${SV_TFB_TMPS}" ]; then
        SV_TFB_SAVED_TRAPS="$(trap -p INT TERM HUP)"
        trap 'sv_tfb_on_signal 130' INT
        trap 'sv_tfb_on_signal 143' TERM
        trap 'sv_tfb_on_signal 129' HUP
    fi
    SV_TFB_TMPS="${SV_TFB_TMPS}${d}"$'\n'
    printf -v "$1" '%s' "${d}"
}

# Removes the registered temp dir $1; the last one out puts the earlier INT/TERM/HUP traps back.
sv_tfb_rmtemp() {
    local p rest=""
    rm -rf "$1"
    while IFS= read -r p; do
        if [ -n "${p}" ] && [ "${p}" != "$1" ]; then
            rest="${rest}${p}"$'\n'
        fi
    done <<< "${SV_TFB_TMPS}"
    SV_TFB_TMPS="${rest}"
    if [ -z "${SV_TFB_TMPS}" ]; then
        trap - INT TERM HUP
        if [ -n "${SV_TFB_SAVED_TRAPS}" ]; then
            eval "${SV_TFB_SAVED_TRAPS}"
        fi
        SV_TFB_SAVED_TRAPS=""
    fi
}

# sv_die after removing every registered temp dir.
sv_tfb_die() {
    sv_tfb_cleanup_all
    trap - INT TERM HUP
    sv_die "$@"
}

# gs:// URI of the backup copy for PROJECT_ID in bucket $1.
sv_tfvars_backup_uri() {
    printf 'gs://%s/platform/%s.tfvars' "$1" "${PROJECT_ID}"
}

# One line, at most 300 characters, of the last non-empty line of file $1 (empty when there is none).
sv_tfvars_backup_last_line() {
    python3 -I -c '
import sys
try:
    with open(sys.argv[1], errors="replace") as f:
        lines = [" ".join(l.split()) for l in f.read().splitlines()]
except OSError:
    lines = []
lines = [l for l in lines if l]
print(lines[-1][:300] if lines else "")
' "$1" 2>/dev/null || true
}

# base64 MD5 of file $1, the encoding of the JSON API's md5Hash.
sv_tfvars_backup_md5() {
    python3 -I -c '
import base64, hashlib, sys
try:
    h = hashlib.md5(usedforsecurity=False)
except TypeError:
    h = hashlib.md5()
with open(sys.argv[1], "rb") as f:
    h.update(f.read())
print(base64.b64encode(h.digest()).decode())
' "$1"
}

# Metadata of the backup object in bucket $1. Sets SV_TFB_CODE (the HTTP status, or "none (...)" when no request was
# answered), SV_TFB_GENERATION, SV_TFB_MD5, SV_TFB_SIZE, SV_TFB_UPDATED and SV_TFB_MSG (the API's error.message).
sv_tfvars_backup_meta() {
    local bucket="$1" token tmp="" rc parsed
    SV_TFB_CODE=""; SV_TFB_GENERATION=""; SV_TFB_MD5=""; SV_TFB_SIZE=""; SV_TFB_UPDATED=""; SV_TFB_MSG=""
    token="$(gcloud auth print-access-token 2>/dev/null)" || token=""
    if [ -z "${token}" ]; then
        SV_TFB_CODE="none (no access token: gcloud auth print-access-token failed)"
        return 0
    fi
    if ! sv_tfb_mktemp tmp; then
        token=""
        SV_TFB_CODE="none (mktemp failed)"
        return 0
    fi
    rc=0
    # Project ids are [a-z0-9-], so the object name needs only its "/" encoded.
    SV_TFB_CODE="$(printf 'header = "Authorization: Bearer %s"\n' "${token}" \
        | curl -sS --max-time 30 --config - -o "${tmp}/meta.json" -w '%{http_code}' \
            "https://storage.googleapis.com/storage/v1/b/${bucket}/o/platform%2F${PROJECT_ID}.tfvars?fields=generation,md5Hash,size,updated" \
            2>/dev/null)" || rc=$?
    token=""
    if [ "${rc}" -ne 0 ]; then
        SV_TFB_CODE="none (curl rc=${rc})"
    elif [ -z "${SV_TFB_CODE}" ]; then
        SV_TFB_CODE="none (no HTTP status)"
    fi
    parsed="$(python3 -I -c '
import json, re, sys
code = sys.argv[2]
try:
    with open(sys.argv[1]) as f:
        body = json.load(f)
except (OSError, ValueError):
    body = None
if code == "200":
    ok = isinstance(body, dict) and re.fullmatch(r"[0-9]+", str(body.get("generation", ""))) \
        and re.fullmatch(r"[0-9]+", str(body.get("size", "")))
    if not ok:
        print("malformed")
        sys.exit(0)
    md5 = body.get("md5Hash", "")
    print("|".join(["ok", str(body["generation"]), md5 if isinstance(md5, str) else "", str(body["size"]),
                     str(body.get("updated", "unknown")).replace("|", " ")]))
else:
    msg = ""
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        msg = " ".join(str(body["error"].get("message", "")).split())[:300]
    print("|".join(["err", msg]))
' "${tmp}/meta.json" "${SV_TFB_CODE}" 2>/dev/null)" || parsed="malformed"
    sv_tfb_rmtemp "${tmp}"
    case "${parsed}" in
        "ok|"*)
            # "|" is not IFS whitespace, so an empty field (no md5Hash: a composite object) stays in its place.
            IFS='|' read -r _ SV_TFB_GENERATION SV_TFB_MD5 SV_TFB_SIZE SV_TFB_UPDATED <<< "${parsed}" ;;
        "err|"*)
            SV_TFB_MSG="${parsed#err|}" ;;
        *)
            if [ "${SV_TFB_CODE}" = "200" ]; then
                SV_TFB_CODE="200 (malformed body)"
            fi ;;
    esac
    return 0
}

# Size in bytes of file $1.
sv_tfb_size() {
    python3 -I -c 'import os, sys; print(os.path.getsize(sys.argv[1]))' "$1"
}

# $1 = PREFIX (BOOTSTRAP | APPLY), $2 = local vars file, $3 = the retry command. rc 0 when the copy holds $2.
sv_tfvars_backup_write() {
    local prefix="$1" src="$2" retry="$3" bucket uri prev gen local_md5 work="" rc why what="apply"
    [ "${prefix}" != "BOOTSTRAP" ] || what="install"
    bucket="${STATE_BUCKET}"
    uri="$(sv_tfvars_backup_uri "${bucket}")"
    why=""
    if [ ! -f "${src}" ]; then
        why="${src} does not exist"
    else
        sv_tfvars_backup_meta "${bucket}"
        case "${SV_TFB_CODE}" in
            404) gen=0 ;;
            200)
                gen="${SV_TFB_GENERATION}"
                local_md5="$(sv_tfvars_backup_md5 "${src}")" || local_md5=""
                if [ -z "${local_md5}" ]; then
                    why="could not read ${src}"
                elif [ "${local_md5}" = "${SV_TFB_MD5}" ]; then
                    echo -e "\033[0;32m[OK]\033[0m Backed up ${src}: ${uri} is up to date." >&2
                    return 0
                fi ;;
            *)
                why="could not read the existing copy ${uri} (HTTP ${SV_TFB_CODE}${SV_TFB_MSG:+: ${SV_TFB_MSG}}), so it was not overwritten" ;;
        esac
    fi
    if [ -z "${why}" ] && ! sv_tfb_mktemp work; then
        why="mktemp failed"
    fi
    if [ -z "${why}" ] && [ "${SV_TFB_CODE}" = "200" ]; then
        # The copy differs (written by another machine or an earlier file): keep exactly the generation that was read
        # before it is replaced.
        prev="${uri}.prev-$(date -u +%Y%m%dT%H%M%SZ)"
        rc=0
        gcloud storage cp "${uri}#${gen}" "${prev}" --if-generation-match=0 >/dev/null 2>"${work}/prev.err" || rc=$?
        if [ "${rc}" -ne 0 ]; then
            why="could not keep the earlier copy as ${prev} (gcloud rc=${rc}: $(sv_tfvars_backup_last_line "${work}/prev.err")), so ${uri} was not overwritten"
        else
            echo -e "\033[1;33m[NOTE]\033[0m The earlier copy ${uri} differed from ${src}; it is kept as ${prev}." >&2
        fi
    fi
    if [ -z "${why}" ]; then
        rc=0
        gcloud storage cp "${src}" "${uri}" --if-generation-match="${gen}" >/dev/null 2>"${work}/up.err" || rc=$?
        if [ "${rc}" -eq 0 ]; then
            sv_tfb_rmtemp "${work}"
            echo -e "\033[0;32m[OK]\033[0m Backed up ${src} to ${uri}." >&2
            return 0
        fi
        why="the upload to ${uri} failed (gcloud rc=${rc}: $(sv_tfvars_backup_last_line "${work}/up.err"))"
    fi
    [ -z "${work}" ] || sv_tfb_rmtemp "${work}"
    echo -e "\033[1;33m[WARN]\033[0m ${prefix}_TFVARS_BACKUP_NOT_WRITTEN: ${why}. The ${what} itself succeeded, but ${src} is not backed up (it is gitignored: this machine may hold the only copy). Retry: ${retry}" >&2
    return 1
}

# $1 = bucket. A NOTE only (never asks, never stops, never writes): a backup exists for an install whose vars file is
# not on this machine.
sv_tfvars_backup_note() {
    local uri
    uri="$(sv_tfvars_backup_uri "$1")"
    sv_tfvars_backup_meta "$1"
    [ "${SV_TFB_CODE}" = "200" ] || return 0
    echo -e "\n\033[1;33m[NOTE]\033[0m A backup of this install's vars file exists: ${uri} (${SV_TFB_SIZE} bytes, updated ${SV_TFB_UPDATED}),"
    echo -e "       but infra/platform/${PROJECT_ID}.tfvars is not on this machine. If ${PROJECT_ID} is already installed, press"
    echo -e "       Ctrl-C now (nothing has changed yet) and restore it instead: PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh plan"
    echo -e "       (it offers the restore). If you continue, the installer writes a new file from your answers, and the end of"
    echo -e "       the install keeps the current backup as ${uri}.prev-<UTC> before replacing it.\n"
    return 0
}

# $1 = the apply.sh arguments as typed (shown in the re-run command). Returns 0 when there is nothing to offer;
# otherwise it always stops the run (sv_die or exit 1).
sv_tfvars_restore_offer() {
    local args="$1" dest rel bucket uri rerun answer tmpd="" got local_md5 got_size got_pid err rc bootstrap_alt out
    [ -z "${TFVARS_FILE:-}" ] || return 0
    [ -n "${PROJECT_ID:-}" ] || return 0
    sv_valid_project_id "${PROJECT_ID}" || return 0
    dest="${PLATFORM_DIR}/${PROJECT_ID}.tfvars"
    if [ -e "${dest}" ] || [ -L "${dest}" ] || [ -e "${PLATFORM_DIR}/terraform.tfvars" ] || [ -L "${PLATFORM_DIR}/terraform.tfvars" ]; then
        return 0
    fi
    rel="infra/platform/${PROJECT_ID}.tfvars"
    bucket="castor-tfstate-${PROJECT_ID}"   # the same name sv_resolve_platform_target uses
    uri="$(sv_tfvars_backup_uri "${bucket}")"
    rerun="PROJECT_ID=${PROJECT_ID} bash scripts/apply.sh ${args}"
    bootstrap_alt="Or write it again with the installer: bash scripts/bootstrap.sh (it asks the install questions again; hand edits made to the file since the install, for example extra authorized_invoker_members, must be made again before the next apply)."
    sv_tfvars_backup_meta "${bucket}"
    case "${SV_TFB_CODE}" in
        200) ;;
        404)
            sv_tfb_die "APPLY_TFVARS_MISSING_NO_BACKUP: ${rel} does not exist, and there is no backup at ${uri}. Nothing was changed. Write it again with the installer: bash scripts/bootstrap.sh (it asks the install questions again; hand edits made to the file since the install, for example extra authorized_invoker_members, must be made again before the next apply). If you have a copy elsewhere, put it at ${rel} or pass TFVARS_FILE=<path>." ;;
        *)
            sv_tfb_die "APPLY_TFVARS_BACKUP_UNCHECKED: ${rel} does not exist, and its backup ${uri} could not be checked (HTTP ${SV_TFB_CODE}${SV_TFB_MSG:+: ${SV_TFB_MSG}}). Nothing was changed. Check your gcloud login (gcloud auth login) and your access to gs://${bucket}, then re-run: ${rerun}. ${bootstrap_alt}" ;;
    esac
    sv_info "${rel} does not exist. A backup exists: ${uri} (${SV_TFB_SIZE} bytes, updated ${SV_TFB_UPDATED})."
    answer=""
    if [ -t 0 ]; then
        printf 'Restore %s from %s? [y/N]: ' "${rel}" "${uri}" >&2
        read -r answer || answer=""
    fi
    case "${answer}" in
        y|Y|yes|Yes|YES) ;;
        *)
            if [ -t 0 ]; then
                sv_tfb_die "APPLY_TFVARS_MISSING: ${rel} does not exist and you chose not to restore it from ${uri}. Nothing was changed. To restore it, re-run and answer y: ${rerun}. ${bootstrap_alt}"
            fi
            sv_tfb_die "APPLY_TFVARS_MISSING: ${rel} does not exist. A backup exists at ${uri} (${SV_TFB_SIZE} bytes, updated ${SV_TFB_UPDATED}); this is not a terminal, so it was not offered. Nothing was changed. To restore it, run in a terminal and answer y: ${rerun} (or: gcloud storage cp ${uri} ${rel} && chmod 600 ${rel}), review it, then re-run. ${bootstrap_alt}" ;;
    esac

    # Restore: download exactly the generation that was read into a 0700 temp dir under $TMPDIR, check it, then create
    # the destination exclusively (O_EXCL: a file, link or directory that appeared meanwhile is never overwritten).
    sv_tfb_mktemp tmpd || sv_tfb_die "APPLY_TFVARS_RESTORE_FAILED: could not create a temp dir. Nothing was written to ${rel}."
    got="${tmpd}/${PROJECT_ID}.tfvars"
    rc=0
    gcloud storage cp "${uri}#${SV_TFB_GENERATION}" "${got}" >/dev/null 2>"${tmpd}/gcloud.err" || rc=$?
    if [ "${rc}" -ne 0 ]; then
        err="$(sv_tfvars_backup_last_line "${tmpd}/gcloud.err")"
        sv_tfb_die "APPLY_TFVARS_RESTORE_FAILED: the download of ${uri}#${SV_TFB_GENERATION} failed (gcloud rc=${rc}${err:+: ${err}}). Nothing was written to ${rel}. Retry: ${rerun}"
    fi
    if [ ! -s "${got}" ]; then
        sv_tfb_die "APPLY_TFVARS_RESTORE_FAILED: the download of ${uri} is empty. Nothing was written to ${rel}. Retry: ${rerun}"
    fi
    if [ -n "${SV_TFB_MD5}" ]; then
        local_md5="$(sv_tfvars_backup_md5 "${got}")" || local_md5=""
        if [ "${local_md5}" != "${SV_TFB_MD5}" ]; then
            sv_tfb_die "APPLY_TFVARS_RESTORE_FAILED: the download of ${uri} does not match the object's MD5. Nothing was written to ${rel}. Retry: ${rerun}"
        fi
    else
        got_size="$(sv_tfb_size "${got}")" || got_size=""
        if [ "${got_size}" != "${SV_TFB_SIZE}" ]; then
            sv_tfb_die "APPLY_TFVARS_RESTORE_FAILED: the download of ${uri} is ${got_size:-?} bytes, the object ${SV_TFB_SIZE} (it has no MD5 to compare). Nothing was written to ${rel}. Retry: ${rerun}"
        fi
    fi
    # The copy must describe this install (the real HCL parser, as every other vars-file read).
    got_pid="$(TFVARS="${got}"; sv_tfvar project_id)" || got_pid=""
    if [ "${got_pid}" != "${PROJECT_ID}" ]; then
        if [ -n "${got_pid}" ]; then
            err="holds project_id = \"${got_pid}\", not \"${PROJECT_ID}\""
        else
            err="has no readable project_id (missing, malformed, or the file does not parse)"
        fi
        sv_tfb_die "APPLY_TFVARS_BACKUP_PROJECT_MISMATCH: ${uri} ${err}. Nothing was written to ${rel}. Check that copy, or write the file again with the installer: bash scripts/bootstrap.sh"
    fi
    rc=0
    out="$(python3 -I -c '
import errno, os, sys
src, dest = sys.argv[1], sys.argv[2]
with open(src, "rb") as f:
    data = f.read()
try:
    fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
except OSError as e:
    print(e.strerror or str(e))
    sys.exit(3 if e.errno == errno.EEXIST else 4)
try:
    os.fchmod(fd, 0o600)
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]
    os.fsync(fd)
    os.close(fd)
except OSError as e:
    try:
        os.close(fd)
    except OSError:
        pass
    os.unlink(dest)
    print(e.strerror or str(e))
    sys.exit(5)
' "${got}" "${dest}" 2>&1)" || rc=$?
    case "${rc}" in
        0) ;;
        3) sv_tfb_die "APPLY_TFVARS_RESTORE_FAILED: ${rel} appeared while the backup was downloaded (${out}); it was not overwritten. Review it, then re-run: ${rerun}" ;;
        *) sv_tfb_die "APPLY_TFVARS_RESTORE_FAILED: could not create ${rel} (${out:-python3 rc=${rc}}). Nothing was written to ${rel}. Retry: ${rerun}" ;;
    esac
    sv_tfb_rmtemp "${tmpd}"
    echo -e "\033[0;32m[OK]\033[0m Restored ${rel} from ${uri} (mode 600)." >&2
    echo -e "\033[1;33m[STOP]\033[0m APPLY_TFVARS_RESTORED: nothing was planned or applied. Review ${rel} before the next run (it is the copy saved by the last install or apply that backed it up, updated ${SV_TFB_UPDATED}), then re-run: ${rerun}" >&2
    exit 1
}
