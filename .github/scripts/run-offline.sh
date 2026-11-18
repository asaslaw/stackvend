#!/usr/bin/env bash
# Run a command (as the current user, with the current env) inside a fresh Linux network namespace that has ONLY
# loopback (red-team F7b). CI backstop for the hermetic test guard: even if the guard had a bug, a test, a Go/C
# child (tofu, git/libcurl, gRPC C-core, uvloop) or anything else cannot reach the network or a metadata server.
# Needs passwordless sudo + util-linux unshare + iproute2 (GitHub-hosted ubuntu runners have all three).
#
#   .github/scripts/run-offline.sh python -m pytest tests/
set -euo pipefail
if [ "$#" -eq 0 ]; then
  echo "usage: $0 <command> [args...]" >&2
  exit 2
fi
user="$(id -un)"
path="$PATH"
# sudo resets PATH (secure_path): carry it explicitly. --preserve-env keeps the job env (TEST_MODE, mock IDs, ...).
exec sudo --preserve-env unshare --net -- bash -c '
  set -euo pipefail
  ip link set lo up
  u="$1"; p="$2"; shift 2
  exec sudo --preserve-env -u "$u" env PATH="$p" "$@"
' bash "$user" "$path" "$@"
