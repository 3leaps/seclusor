#!/usr/bin/env bash
# Source this file, then call release_resolve_decernor ceremony|optional.
set -euo pipefail

release_resolve_decernor() {
    local mode="$1" bin identity version commit
    if [ "${mode}" = ceremony ]; then
        if [ -z "${SECLUSOR_DECERNOR_BIN:-}" ]; then
            echo "error: SECLUSOR_DECERNOR_BIN is required for release ceremony targets" >&2
            return 1
        fi
        bin="${SECLUSOR_DECERNOR_BIN}"
    elif [ -n "${SECLUSOR_DECERNOR_BIN:-}" ]; then
        bin="${SECLUSOR_DECERNOR_BIN}"
    elif [ -n "${DECERNOR_BIN:-}" ]; then
        bin="${DECERNOR_BIN}"
    else
        bin="$(command -v decernor || true)"
    fi
    case "${bin}" in
    /*) ;;
    *)
        echo "error: decernor must resolve to an absolute path" >&2
        return 1
        ;;
    esac
    if [ ! -x "${bin}" ]; then
        echo "error: decernor binary is not executable" >&2
        return 1
    fi
    identity="$("${bin}" version -e)"
    version="$(sed -n 's/^Version:[[:space:]]*//p' <<<"${identity}" | head -1)"
    commit="$(sed -n 's/^Commit:[[:space:]]*//p' <<<"${identity}" | head -1)"
    if ! python3 - "${version}" "${commit}" <<'PY'
import re
import sys
version, commit = sys.argv[1:3]
if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
    raise SystemExit(1)
if tuple(map(int, version.split("."))) < (0, 1, 8):
    raise SystemExit(1)
if not re.fullmatch(r"[0-9a-f]{7,40}", commit):
    raise SystemExit(1)
PY
    then
        echo "error: decernor version -e must report version >= 0.1.8 and a commit identity" >&2
        return 1
    fi
    printf '%s\n' "${bin}"
}
