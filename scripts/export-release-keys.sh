#!/usr/bin/env bash
# Stage public signing keys into the release directory.
#
# When `<release-dir>.anchor` exists (post-tag release ceremony), public keys
# are extracted strictly as inert Git blobs from the verified tagged commit,
# never from a mutable checkout or external key home. Otherwise falls back to
# explicit maintainer key inputs.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <release-dir>" >&2
    exit 1
fi

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
root="$(CDPATH='' cd -- "${script_dir}/.." && pwd -P)"
release_dir="$1"
anchor="${release_dir}.anchor"

mkdir -p "${release_dir}"
if [ -L "${release_dir}" ] || [ -L "${release_dir}/minisign.pub" ] || [ -L "${release_dir}/release-key.asc" ]; then
    echo "error: unsafe symlink in release staging path" >&2
    exit 1
fi

if [ -f "${anchor}" ] && [ ! -L "${anchor}" ]; then
    commit="$(awk -F= '$1 == "commit" { print $2 }' "${anchor}")"
    if ! [[ "${commit}" =~ ^[0-9a-f]{40}$ ]]; then
        echo "error: malformed commit in ${anchor}" >&2
        exit 1
    fi
    git -C "${root}" cat-file blob "${commit}:docs/security/seclusor-minisign.pub" >"${release_dir}/minisign.pub"
    git -C "${root}" cat-file blob "${commit}:docs/security/release-signing-keys.asc" >"${release_dir}/release-key.asc"
    if [ ! -s "${release_dir}/minisign.pub" ] || [ ! -s "${release_dir}/release-key.asc" ]; then
        echo "error: committed public key blob is empty at ${commit}" >&2
        exit 1
    fi
    if [ -n "${SECLUSOR_MINISIGN_PUB:-}" ] && [ -f "${SECLUSOR_MINISIGN_PUB}" ]; then
        if ! cmp -s "${SECLUSOR_MINISIGN_PUB}" "${release_dir}/minisign.pub"; then
            echo "error: SECLUSOR_MINISIGN_PUB differs from committed docs/security/seclusor-minisign.pub at ${commit}" >&2
            exit 1
        fi
    fi
    echo "[ok] Extracted committed public signing keys from ${commit}"
    exit 0
fi

for name in SECLUSOR_MINISIGN_PUB SECLUSOR_PGP_KEY_ID SECLUSOR_GPG_HOMEDIR; do
    if [ -z "${!name:-}" ]; then
        echo "error: ${name} is required for release public-key export" >&2
        exit 1
    fi
done
if [ ! -s "${SECLUSOR_MINISIGN_PUB}" ] || [ ! -d "${SECLUSOR_GPG_HOMEDIR}" ]; then
    echo "error: release public-key input or GPG home is unavailable" >&2
    exit 1
fi
command -v gpg >/dev/null 2>&1 || {
    echo "error: gpg is required" >&2
    exit 1
}
cp "${SECLUSOR_MINISIGN_PUB}" "${release_dir}/minisign.pub"
gpg --batch --no-tty --homedir "${SECLUSOR_GPG_HOMEDIR}" --armor \
    --export --export-options export-minimal "${SECLUSOR_PGP_KEY_ID}" >"${release_dir}/release-key.asc"
if [ ! -s "${release_dir}/release-key.asc" ]; then
    echo "error: release public GPG export is empty" >&2
    exit 1
fi
echo "[ok] Exported both release public keys"
