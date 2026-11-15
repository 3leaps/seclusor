#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <release-dir>" >&2
    exit 1
fi

release_dir="$1"
gpg_homedir="${SECLUSOR_GPG_HOMEDIR:-}"
root_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
subkey_file="${SECLUSOR_SIGNING_SUBKEY_FILE:-${root_dir}/config/release/signing-subkey.txt}"
expected_subkey=""
if [ -s "${subkey_file}" ]; then
    expected_subkey="$(tr -d '[:space:]' <"${subkey_file}")"
    if [[ ! "${expected_subkey}" =~ ^[0-9A-F]{40}$ ]]; then
        echo "error: malformed signing subkey fingerprint in ${subkey_file}" >&2
        exit 1
    fi
fi

if [ -f "${release_dir}/minisign.pub" ]; then
    minisign_pub="${release_dir}/minisign.pub"
    if [ -n "${SECLUSOR_MINISIGN_PUB:-}" ]; then
        if [ ! -f "${SECLUSOR_MINISIGN_PUB}" ] || ! cmp -s "${SECLUSOR_MINISIGN_PUB}" "${minisign_pub}"; then
            echo "error: SECLUSOR_MINISIGN_PUB conflicts with staged ${minisign_pub}" >&2
            exit 1
        fi
    fi
elif [ -n "${SECLUSOR_MINISIGN_PUB:-}" ]; then
    minisign_pub="${SECLUSOR_MINISIGN_PUB}"
else
    minisign_pub="${release_dir}/minisign.pub"
fi

if [ ! -f "${minisign_pub}" ]; then
    echo "error: minisign public key not found at ${minisign_pub}" >&2
    exit 1
fi

if ! command -v minisign >/dev/null 2>&1; then
    echo "error: minisign is required" >&2
    exit 1
fi

isolated_gpg=""
cleanup() {
    if [ -n "${isolated_gpg}" ]; then
        gpgconf --homedir "${isolated_gpg}" --kill all >/dev/null 2>&1 || true
        rm -rf "${isolated_gpg}"
    fi
}
trap cleanup EXIT

for sums in SHA256SUMS SHA512SUMS; do
    file="${release_dir}/${sums}"
    sig="${file}.minisig"
    if [ -f "${sig}" ]; then
        minisign -V -p "${minisign_pub}" -m "${file}" -x "${sig}"
    else
        echo "error: missing minisign signature ${sig}" >&2
        exit 1
    fi

    asc="${file}.asc"
    if [ -s "${release_dir}/release-key.asc" ] && [ ! -f "${asc}" ]; then
        echo "error: missing OpenPGP signature ${asc} while ${release_dir}/release-key.asc is staged" >&2
        exit 1
    fi
    if [ -f "${asc}" ]; then
        if ! command -v gpg >/dev/null 2>&1; then
            echo "error: gpg signature present but gpg not installed" >&2
            exit 1
        fi
        if [ -s "${release_dir}/release-key.asc" ]; then
            if [ -z "${isolated_gpg}" ]; then
                isolated_gpg="$(mktemp -d "${TMPDIR:-/tmp}/seclusor-sigverify.XXXXXX")"
                chmod 700 "${isolated_gpg}"
                GNUPGHOME="${isolated_gpg}" gpg --batch --quiet --import "${release_dir}/release-key.asc"
            fi
            status_out="$(GNUPGHOME="${isolated_gpg}" gpg --batch --status-fd=1 --verify "${asc}" "${file}" 2>/dev/null)" || {
                echo "error: OpenPGP signature verification failed for ${asc}" >&2
                exit 1
            }
            if ! grep -q '^\[GNUPG:\] GOODSIG ' <<<"${status_out}" ||
                ! grep -q '^\[GNUPG:\] VALIDSIG ' <<<"${status_out}" ||
                grep -Eq '^\[GNUPG:\] (EXPKEYSIG|EXPSIG|REVKEYSIG|KEYREVOKED|KEYEXPIRED|SIGEXPIRED|BADSIG|ERRSIG) ' <<<"${status_out}"; then
                echo "error: OpenPGP signature status invalid for ${asc}" >&2
                exit 1
            fi
            if [ -n "${expected_subkey}" ] && ! grep -q "^\[GNUPG:\] VALIDSIG ${expected_subkey} " <<<"${status_out}"; then
                echo "error: OpenPGP signature ${asc} was not created by pinned signing subkey ${expected_subkey}" >&2
                exit 1
            fi
        elif [ -n "${gpg_homedir}" ]; then
            gpg --batch --homedir "${gpg_homedir}" --verify "${asc}" "${file}"
        else
            echo "error: ${asc} present without ${release_dir}/release-key.asc or SECLUSOR_GPG_HOMEDIR" >&2
            exit 1
        fi
    fi
done

echo "[ok] Signature verification passed"
