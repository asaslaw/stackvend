# shellcheck shell=bash
# ==============================================================================
# STACKVEND: OpenTofu offer for the installer scripts (INSTALLER-OPENTOFU-OFFER, owner 11-10)
# ==============================================================================
# Sourced (after common/platform_target.sh, which defines SV_IAC_MIN_VERSION and sv_iac_version_verdict) by
# scripts/pre-bootstrap.sh, scripts/bootstrap.sh and scripts/apply.sh. One entry point:
#
#   sv_ensure_opentofu <PREFIX> <INTERACTIVE>    PREFIX = typed-error prefix (PREBOOT, BOOTSTRAP, APPLY)
#                                                INTERACTIVE = 1 when stdin is a terminal and prompts are allowed
#
# Silent no-op (prints nothing, changes nothing) when the engine is usable: a functional OpenTofu >= the minimum,
# or (no functional OpenTofu) a functional engine the existing detection already accepts at >= the minimum, or a
# version this helper cannot read (the existing checks then report it exactly as before).
# When OpenTofu is missing, or the engine found is older than the minimum:
#   - interactive: asks "Install OpenTofu 1.13.1 into ~/bin now? [y/N]" (default No). On yes it downloads the
#     official release zip for this platform, verifies its SHA-256 against the values pinned below (fail closed:
#     mismatch or unknown platform = refused, download deleted, nothing installed), extracts only the `tofu`
#     binary into ~/bin, prepends ~/bin to PATH for the rest of the run and re-checks the version.
#   - on no, or not interactive: stops with <PREFIX>_OPENTOFU_<REASON> and the exact manual commands.
# No sudo, no package manager, no curl|sh. Writes only ~/bin/tofu and a temp dir that is removed.
# Bash 3.2 compatible (macOS /bin/bash): no associative arrays.
# ==============================================================================

SV_TOFU_OFFER_VERSION="1.13.1"

# SHA-256 of the official release zips, copied from the release's own checksum file
# https://github.com/opentofu/opentofu/releases/download/v1.13.1/tofu_1.13.1_SHA256SUMS
# (four lines: tofu_1.13.1_<os>_<arch>.zip). Changing the version means re-copying all four from that file.
sv_tofu_pinned_sha256() {
    case "$1" in
        linux_amd64)  echo "8ccbc6f8ee21d2827715f3c6e08a9b3e0209b1e62057c05067ef117e047c1a80" ;;
        linux_arm64)  echo "b9614df40575cc3fc10a8a25025b7245d961da279f715ea3efff4ddae8e6938a" ;;
        darwin_amd64) echo "d44ab59ec53fb18e900f4ae3fc8b72e042c9e03ca957860edbaac04e4427218d" ;;
        darwin_arm64) echo "81aebe6453223bcb3ce3c28424b36d009ebfddd3ad65ad1ec3eed0d0d574a77b" ;;
        *) return 1 ;;
    esac
}

# <os>_<arch> as the release names it (linux|darwin x amd64|arm64), or a value no pinned hash matches.
sv_tofu_platform() {
    local os arch
    os="$(uname -s 2>/dev/null)" || os=""
    arch="$(uname -m 2>/dev/null)" || arch=""
    case "${os}" in
        Linux) os="linux" ;;
        Darwin) os="darwin" ;;
        *) os="unsupported-os(${os})" ;;
    esac
    case "${arch}" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) arch="unsupported-arch(${arch})" ;;
    esac
    printf '%s_%s' "${os}" "${arch}"
}

sv_tofu_zip_name() { printf 'tofu_%s_%s.zip' "${SV_TOFU_OFFER_VERSION}" "$1"; }
sv_tofu_zip_url() {
    printf 'https://github.com/opentofu/opentofu/releases/download/v%s/%s' "${SV_TOFU_OFFER_VERSION}" "$(sv_tofu_zip_name "$1")"
}

# The checksum command for this OS: sha256sum on Linux, shasum -a 256 on macOS.
sv_tofu_sha256_cmd() {
    case "$1" in
        darwin_*) echo "shasum -a 256" ;;
        *) echo "sha256sum" ;;
    esac
}

sv_tofu_stop() {
    # $1 = PREFIX, $2 = REASON, rest = message (with the fix)
    local prefix="$1" reason="$2"
    shift 2
    echo -e "\033[0;31m[ERROR]\033[0m ${prefix}_OPENTOFU_${reason}: $*" >&2
    exit 1
}

# The manual install commands for this platform (printed on every stop). An unsupported platform gets the list
# of release files instead of a command that cannot work.
sv_tofu_manual_steps() {
    local plat="$1" sum zip
    zip="$(sv_tofu_zip_name "${plat}")"
    if ! sum="$(sv_tofu_pinned_sha256 "${plat}")"; then
        echo "  OpenTofu ${SV_TOFU_OFFER_VERSION} has release zips for linux and darwin on amd64 and arm64 only (this machine: ${plat})."
        echo "  Other platforms: https://opentofu.org/docs/intro/install/ (OpenTofu ${SV_IAC_MIN_VERSION} or later)."
        return 0
    fi
    echo "  To install it yourself (no admin rights needed), run:"
    echo "    mkdir -p \"\$HOME/bin\" && cd \"\$(mktemp -d)\""
    echo "    curl -fLO $(sv_tofu_zip_url "${plat}")"
    echo "    echo \"${sum}  ${zip}\" | $(sv_tofu_sha256_cmd "${plat}") -c -"
    echo "    unzip -o ${zip} tofu -d \"\$HOME/bin\" && chmod +x \"\$HOME/bin/tofu\""
    echo "    export PATH=\"\$HOME/bin:\$PATH\""
    echo "  then re-run this script."
}

# Prints the engine state: "ok" (usable, or a version this helper cannot read: the existing checks decide),
# "missing" (no functional OpenTofu and no other usable engine), or "old|<engine> <version>".
sv_tofu_engine_state() {
    local v
    command -v python3 >/dev/null 2>&1 || { echo ok; return 0; }   # the existing checks report a missing python3
    if command -v tofu >/dev/null 2>&1 && tofu version 2>&1 | grep -qi "OpenTofu v"; then
        v="$(sv_iac_version_verdict tofu)"
        case "${v%%|*}" in
            OLD) echo "old|tofu ${v#*|}" ;;
            *) echo ok ;;
        esac
        return 0
    fi
    # Same fallback as sv_detect_iac_bin (kept per owner, FD-0C): a usable one is left alone, never offered.
    if command -v terraform >/dev/null 2>&1 && terraform version 2>&1 | grep -qi "Terraform v"; then
        v="$(sv_iac_version_verdict terraform)"
        case "${v%%|*}" in
            OLD) echo "old|terraform ${v#*|}" ;;
            *) echo ok ;;
        esac
        return 0
    fi
    echo missing
}

# Downloads, verifies and installs OpenTofu SV_TOFU_OFFER_VERSION into ~/bin. $1 = PREFIX, $2 = platform.
sv_tofu_install() {
    local prefix="$1" plat="$2" want got zip url tmp hashcmd bindir
    if ! want="$(sv_tofu_pinned_sha256 "${plat}")"; then
        sv_tofu_stop "${prefix}" UNSUPPORTED_PLATFORM "no pinned OpenTofu ${SV_TOFU_OFFER_VERSION} checksum for this platform (${plat}); nothing was downloaded or installed.
$(sv_tofu_manual_steps "${plat}")"
    fi
    hashcmd="$(sv_tofu_sha256_cmd "${plat}")"
    command -v "${hashcmd%% *}" >/dev/null 2>&1 \
        || sv_tofu_stop "${prefix}" CHECKSUM_TOOL_MISSING "'${hashcmd%% *}' is not on PATH, so the download cannot be verified; nothing was downloaded or installed."
    zip="$(sv_tofu_zip_name "${plat}")"
    url="$(sv_tofu_zip_url "${plat}")"
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/stackvend-tofu.XXXXXX")" \
        || sv_tofu_stop "${prefix}" DOWNLOAD_FAILED "could not create a temporary directory; nothing was installed."
    echo -e "\033[0;34m==>\033[0m Downloading ${url}" >&2
    if ! curl -fsSL --proto '=https' --tlsv1.2 -o "${tmp}/${zip}" "${url}"; then
        rm -rf "${tmp}"
        sv_tofu_stop "${prefix}" DOWNLOAD_FAILED "could not download ${url}; nothing was installed.
$(sv_tofu_manual_steps "${plat}")"
    fi
    got="$(${hashcmd} "${tmp}/${zip}" 2>/dev/null | awk '{print $1}')" || got=""
    if [ "${got}" != "${want}" ]; then
        rm -rf "${tmp}"
        sv_tofu_stop "${prefix}" CHECKSUM_MISMATCH "${zip} has SHA-256 '${got:-unreadable}', but the pinned value (from tofu_${SV_TOFU_OFFER_VERSION}_SHA256SUMS) is ${want}. The download was deleted and nothing was installed."
    fi
    # Only the `tofu` member, read by name (never extract the archive's other paths).
    if ! python3 -I -c '
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    data = z.read("tofu")
with open(sys.argv[2], "wb") as f:
    f.write(data)
' "${tmp}/${zip}" "${tmp}/tofu" 2>/dev/null; then
        rm -rf "${tmp}"
        sv_tofu_stop "${prefix}" EXTRACT_FAILED "${zip} passed the checksum but has no readable 'tofu' file; nothing was installed."
    fi
    bindir="${HOME}/bin"
    if ! { mkdir -p "${bindir}" && cp "${tmp}/tofu" "${bindir}/.tofu.new.$$" && chmod 755 "${bindir}/.tofu.new.$$" \
            && mv -f "${bindir}/.tofu.new.$$" "${bindir}/tofu"; }; then
        rm -f "${bindir}/.tofu.new.$$"
        rm -rf "${tmp}"
        sv_tofu_stop "${prefix}" INSTALL_FAILED "could not write ${bindir}/tofu."
    fi
    rm -rf "${tmp}"
    PATH="${bindir}:${PATH}"
    export PATH
    hash -r
    echo -e "\033[0;32m[DONE]\033[0m Installed OpenTofu ${SV_TOFU_OFFER_VERSION} to ~/bin/tofu (SHA-256 matches the pinned value)." >&2
    echo -e "\033[0;34m[INFO]\033[0m ~/bin is on PATH for this run. In new shells, run: export PATH=\"\$HOME/bin:\$PATH\"" >&2
}

sv_ensure_opentofu() {
    local prefix="$1" interactive="${2:-}" state why reason plat answer=""
    state="$(sv_tofu_engine_state)"
    case "${state}" in
        missing)
            reason="MISSING"
            why="OpenTofu ('tofu') is not installed or not on PATH. infra/platform needs OpenTofu ${SV_IAC_MIN_VERSION} or later." ;;
        old\|*)
            reason="TOO_OLD"
            why="${state#old|} is too old for infra/platform: it needs ${SV_IAC_MIN_VERSION} or later." ;;
        *) return 0 ;;
    esac
    plat="$(sv_tofu_platform)"
    if [ "${interactive}" != "1" ]; then
        sv_tofu_stop "${prefix}" "${reason}" "${why} Not a terminal, so the installer did not offer to install it. Nothing was changed.
$(sv_tofu_manual_steps "${plat}")"
    fi
    echo -e "\033[1;33m[WARNING]\033[0m ${why}" >&2
    if [ -e "${HOME}/bin/tofu" ]; then
        echo -e "\033[1;33m[WARNING]\033[0m ~/bin/tofu already exists; installing replaces it." >&2
    fi
    printf 'Install OpenTofu %s into ~/bin now? [y/N]: ' "${SV_TOFU_OFFER_VERSION}" >&2
    read -r answer || answer=""
    case "${answer}" in
        y|Y|yes|Yes|YES) ;;
        *)
            sv_tofu_stop "${prefix}" DECLINED "${why} You chose not to install it. Nothing was changed.
$(sv_tofu_manual_steps "${plat}")" ;;
    esac
    sv_tofu_install "${prefix}" "${plat}"
    state="$(sv_tofu_engine_state)"
    if [ "${state}" != "ok" ] || ! command -v tofu >/dev/null 2>&1 \
            || ! tofu version 2>&1 | grep -qi "OpenTofu v${SV_TOFU_OFFER_VERSION}"; then
        sv_tofu_stop "${prefix}" INSTALL_FAILED "~/bin/tofu was installed, but 'tofu version' does not report OpenTofu ${SV_TOFU_OFFER_VERSION} (state: ${state})."
    fi
    echo -e "\033[0;32m[OK]\033[0m $(tofu version 2>&1 | head -n 1)" >&2
}
