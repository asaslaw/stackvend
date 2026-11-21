#!/usr/bin/env bash
# STACKVEND UPGRADER, BUILD (plan §3.5 BUILDING, §3.6): every component of the verified tree is built with the
# pinned buildpacks CLI, builder, run image and lifecycle (scripts/upgrade/builder-pins.json, by digest; the
# platform builder and run image are the ones `gcloud run deploy --source` uses, FD-148) and pushed to castor-docker-repo
# as <component>:<release>-<commit12>-<request id, first 12>, a tag that must not exist before the build; its digest is
# the one in pack's report.toml (never re-read from the registry by tag). Nothing is deployed here, and
# nothing is deployed unless EVERY build succeeded. Each build carries release.json (scripts/common/release_record.py
# stamp --builder upgrader; computed before anything is written into the tree).
# Usage: SV_UP_WORK=<dir> bash build.sh            Writes SV_UP_WORK/built.json {component: image@sha256:...}.
set -u -o pipefail
# shellcheck source=lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"
up_load || exit $?
cd "${REPO_ROOT}" || exit 89

W="${SV_UP_WORK}"
fail() { echo "stackvend-upgrade: FAILED $1: $2" >&2; exit "$3"; }

pins="$(up_stage_py pins --file "${SV_UP_DIR}/builder-pins.json")" || exit $?
read -r PACK_VERSION PACK_SHA BUILDER_DEFAULT BUILDER_QA RUN_IMAGE LIFECYCLE_IMAGE <<EOF
${pins}
EOF
# FD-148: stage.py already refuses these; a short line must never build with pack's floating defaults
[ -n "${RUN_IMAGE}" ] && [ -n "${LIFECYCLE_IMAGE}" ] \
    || fail BUILDER_PIN_MISSING "builder-pins.json run_images.default / lifecycle.image is empty" 81

# release.json first: dirty / commit are computed before any file is written into the checkout
repository="$(up_json_get "${W}/verified.json" repository)"
STACKVEND_SOURCE_REPO="${repository}" python3 "${REPO_ROOT}/scripts/common/release_record.py" stamp \
    --repo-root "${REPO_ROOT}" --builder upgrader > "${W}/release.json" \
    || fail BUILD_FAILED "release.json could not be computed" 82

# the pinned pack CLI (SHA-256 checked before it runs)
mkdir -p "${W}/pack" "${W}/build" "${W}/docker" || exit 89
curl -fsSL -o "${W}/pack/pack.tgz" \
    "https://github.com/buildpacks/pack/releases/download/v${PACK_VERSION}/pack-v${PACK_VERSION}-linux.tgz" \
    || fail BUILD_FAILED "could not download pack v${PACK_VERSION}" 82
actual="$(sha256sum "${W}/pack/pack.tgz" | cut -d' ' -f1)"
[ "${actual}" = "${PACK_SHA}" ] || fail BUILD_FAILED "pack v${PACK_VERSION} SHA-256 ${actual} does not match the pin" 82
tar -xzf "${W}/pack/pack.tgz" -C "${W}/pack" pack || fail BUILD_FAILED "could not unpack pack" 82
PACK="${W}/pack/pack"

skipped=()
while IFS= read -r s; do [ -z "${s}" ] || skipped+=("${s}"); done < <(up_json_lines "${W}/preflight.json" skipped)
is_skipped() {
    local s
    for s in "${skipped[@]+"${skipped[@]}"}"; do [ "${s}" != "$1" ] || return 0; done
    return 1
}

# FD-148 (attacker F2): each request builds under its own tag (release, commit and the request id), and that tag must
# not exist before the build: an image planted under it is refused (IMAGE_TAG_EXISTS) before anything is built. A
# retry is a new request, so it never collides with the images of the request it retries.
image_of() { echo "${UP_AR}/$1:${UP_RELEASE}-${UP_COMMIT12}-${UP_REQUEST_ID:0:12}"; }
for e in "${SERVICES[@]}" "${JOBS[@]}"; do
    name="${e%%:*}"
    is_skipped "${name}" && continue
    up_stage_py tag-absent --image "$(image_of "${name}")" || exit $?
done

build_one() {
    local name="$1" dir="$2" builder="$3" image
    image="$(image_of "$1")"
    sv_component_prebuild "${name}" "${dir}" || return 1
    cp "${W}/release.json" "${dir}/release.json" || return 1
    up_stage_py docker-config --region "${UP_REGION}" --out "${W}/docker/${name}" || return 1
    mkdir -p "${W}/report/${name}" || return 1
    # checked again right before this component's build (the up-front pass above refuses before anything is built;
    # this narrows the window for an image planted meanwhile)
    up_stage_py tag-absent --image "${image}" || return 1
    # FD-148 builder parity with `gcloud run deploy --source`:
    # --run-image: the run image those builds use (the builder's own default run image is a different one).
    # --lifecycle-image: pack does not trust these builders, so it runs analyze / restore / export in this pinned
    #   lifecycle image instead of pulling buildpacksio/lifecycle by tag.
    # --env: the two settings --source passes that choose where the language runtime comes from (the
    #   serverless-runtimes runtime images of the install's region; the build log names that source); the other
    #   GOOGLE_* values it passes only label the image or tune extraction.
    # --report-output-dir: the digest deployed is the one pack exported (report.toml), never a re-read of the tag.
    # NEVER add pack's trust-builder flag (the builder's own lifecycle would get the registry credentials) or its
    # network flag (build containers must not reach the metadata server and the build identity's token).
    DOCKER_CONFIG="${W}/docker/${name}" "${PACK}" build "${image}" --builder "${builder}" \
        --run-image "${RUN_IMAGE}" --lifecycle-image "${LIFECYCLE_IMAGE}" \
        --env "GOOGLE_RUNTIME_IMAGE_REGION=${UP_REGION}" --env GOOGLE_USE_SERVERLESS_RUNTIMES_TARBALLS=true \
        --report-output-dir "${W}/report/${name}" \
        --path "${dir}" --publish --pull-policy if-not-present || return 1
    up_stage_py report-digest --report "${W}/report/${name}/report.toml" --image "${image}" \
        > "${W}/build/${name}.ref" || return 1
}

PARALLEL_LIMIT="${PARALLEL_LIMIT:-4}"
names=()
pids=()
for e in "${SERVICES[@]}" "${JOBS[@]}"; do
    name="${e%%:*}"; dir="${e#*:}"
    if is_skipped "${name}"; then echo "  skip ${name} (not deployed on this install)"; continue; fi
    builder="${BUILDER_DEFAULT}"
    [ "${name}" != "${SV_QA_JOB}" ] || builder="${BUILDER_QA}"
    while [ "$(jobs -r | wc -l)" -ge "${PARALLEL_LIMIT}" ]; do sleep 2; done
    echo "  build ${name} (${dir})"
    build_one "${name}" "${dir}" "${builder}" > "${W}/build/${name}.log" 2>&1 &
    names+=("${name}"); pids+=("$!")
done

failed=()
for i in "${!names[@]}"; do
    if wait "${pids[$i]}" && [ -s "${W}/build/${names[$i]}.ref" ]; then
        echo "  built ${names[$i]} -> $(cat "${W}/build/${names[$i]}.ref")"
    else
        echo "  FAILED ${names[$i]} (log: ${W}/build/${names[$i]}.log)"; tail -20 "${W}/build/${names[$i]}.log" || true
        failed+=("${names[$i]}")
    fi
done
[ "${#failed[@]}" -eq 0 ] || fail "BUILD_FAILED ${failed[*]}" "nothing was deployed" 82

python3 - "${W}" "${names[@]}" <<'PY'
import json, os, sys
w, names = sys.argv[1], sys.argv[2:]
built = {n: open(os.path.join(w, "build", n + ".ref")).read().strip() for n in names}
json.dump(built, open(os.path.join(w, "built.json"), "w"), sort_keys=True, indent=1)
PY
