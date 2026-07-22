#!/usr/bin/env bash
set -euo pipefail

# Canonical published-artifact build entrypoint (EPR-0001 §2).
#
# EVERY build that produces a shipped artifact — the CLI binaries, the FFI/Go
# prebuilts, and (via build-native.js) the TS .node — MUST go through here, so
# `--locked` is structurally guaranteed and no published build can silently
# re-resolve away from the reviewed lockfile. The static guard
# (scripts/check-locked-artifact-builds.sh) refuses any direct artifact-producing
# cargo/zigbuild invocation that bypasses this wrapper, and the stale-lock
# negative control drives this exact entrypoint to prove the enforcement is
# load-bearing rather than merely configured.
#
# Usage: cargo-artifact-build.sh <build|zigbuild> [cargo args...]
#   e.g. cargo-artifact-build.sh build --workspace
#        cargo-artifact-build.sh build --target x86_64-apple-darwin -p seclusor-ffi
#        cargo-artifact-build.sh zigbuild --target aarch64-unknown-linux-gnu.2.17 -p seclusor-ffi

if [ "$#" -lt 1 ]; then
    echo "usage: $0 <build|zigbuild> [cargo args...]" >&2
    exit 2
fi

sub="$1"
shift

case "$sub" in
build | zigbuild) ;;
*)
    echo "$0: unsupported cargo subcommand '$sub' (expected build|zigbuild)" >&2
    exit 2
    ;;
esac

# --release --locked are non-negotiable for a published artifact; callers supply
# only target/package/feature selectors.
exec cargo "$sub" --release --locked "$@"
