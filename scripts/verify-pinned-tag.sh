#!/usr/bin/env bash
# Verify both annotated tags in the seclusor release set (`vX.Y.Z` and
# `bindings/go/seclusor/vX.Y.Z`) against the public pins committed in the tagged
# commit, inside an isolated temporary GNUPGHOME.
#
# Usage: verify-pinned-tag.sh [--published]
#   --published  allow verifying a historical/published tag whose target != HEAD
# Requires SECLUSOR_RELEASE_TAG and SECLUSOR_DECERNOR_BIN.
set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
root="$(CDPATH='' cd -- "${script_dir}/.." && pwd -P)"
# shellcheck source=scripts/release-decernor.sh
source "${script_dir}/release-decernor.sh"
# shellcheck source=scripts/release-tag-common.sh
source "${script_dir}/release-tag-common.sh"

die() {
    echo "error: $*" >&2
    exit 1
}

published=0
if [[ "${1:-}" == "--published" ]]; then
    published=1
elif [[ "$#" -gt 0 ]]; then
    die "usage: verify-pinned-tag.sh [--published]"
fi

tag="${SECLUSOR_RELEASE_TAG:-}"
[[ "${tag}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
    die "SECLUSOR_RELEASE_TAG=vX.Y.Z is required"

decernor_bin="$(release_resolve_decernor ceremony)"

canonical_obj="$(git -C "${root}" rev-parse --verify --quiet "refs/tags/${tag}")" ||
    die "tag ${tag} is absent"
[[ "$(git -C "${root}" cat-file -t "${canonical_obj}")" == "tag" ]] ||
    die "tag ${tag} must be an annotated tag"
target="$(git -C "${root}" rev-parse "${canonical_obj}^{commit}")"
if [[ "${published}" != "1" ]]; then
    [[ "${target}" == "$(git -C "${root}" rev-parse HEAD)" ]] ||
        die "release tag ${tag} must point at HEAD"
fi

version_at_target="$(git -C "${root}" cat-file blob "${target}:VERSION" | tr -d ' \t\r\n')"
[[ "v${version_at_target}" == "${tag}" ]] ||
    die "tagged VERSION (${version_at_target}) does not match ${tag}"

keyring="$(mktemp -d "${TMPDIR:-/tmp}/seclusor-pin-verify.XXXXXX")"
trap 'gpgconf --homedir "${keyring}/home" --kill all >/dev/null 2>&1 || true; rm -rf "${keyring}"' EXIT
chmod 700 "${keyring}"

# Read trust roots strictly as inert blobs from the tagged commit, never the working tree.
committed_blob() {
    local rel="$1" out="$2" mode
    mode="$(git -C "${root}" ls-tree "${target}" -- "${rel}" | awk '{print $1}')"
    [[ "${mode}" == "100644" ]] || die "committed regular file ${rel} is required in ${target}"
    git -C "${root}" cat-file blob "${target}:${rel}" >"${out}"
    [[ -s "${out}" ]] || die "committed ${rel} is empty in ${target}"
}

committed_blob "docs/security/release-signing-keys.asc" "${keyring}/keys.asc"
committed_blob "docs/security/seclusor-minisign.pub" "${keyring}/minisign.pub"
committed_blob "keys/expected-fingerprints.txt" "${keyring}/anchors.txt"
committed_blob "keys/expected-fingerprints.ndjson" "${keyring}/anchors.ndjson"
committed_blob "config/release/tagger-identity.txt" "${keyring}/tagger-identity.txt"
committed_blob "config/release/signing-subkey.txt" "${keyring}/signing-subkey.txt"

if grep -Eqi 'PRIVATE|SECRET|BEGIN PGP PRIVATE KEY|minisign secret key' \
    "${keyring}/keys.asc" "${keyring}/minisign.pub"; then
    die "committed public key pin contains private-key markers"
fi

"${decernor_bin}" fingerprint verify \
    --anchors "${keyring}/anchors.txt" \
    --anchors-ndjson "${keyring}/anchors.ndjson" \
    --gpg "${keyring}/keys.asc" \
    --minisign "${keyring}/minisign.pub" >/dev/null ||
    die "decernor rejected committed public pins and fingerprint anchors"

(cd "${root}" && python3 -B -E "${script_dir}/release-workflow-pin.py" verify-commit "${target}") >/dev/null

primary="$(awk '$1 == "gpg" { print $2 }' "${keyring}/anchors.txt")"
permitted="$(tr -d ' \t\r\n' <"${keyring}/signing-subkey.txt")"
expected_tagger="$(tr -d '\r\n' <"${keyring}/tagger-identity.txt")"
[[ "${primary}" =~ ^[0-9A-F]{40}$ && "${permitted}" =~ ^[0-9A-F]{40}$ && "${permitted}" != "${primary}" ]] ||
    die "committed primary or signing subkey fingerprint is malformed"
[[ -n "${expected_tagger}" ]] || die "committed tagger identity is empty"

mkdir -m 700 "${keyring}/home"
GNUPGHOME="${keyring}/home" gpg --batch --quiet --import "${keyring}/keys.asc" ||
    die "failed to import committed OpenPGP pin"
[[ "$(GNUPGHOME="${keyring}/home" gpg --batch --with-colons --list-keys | awk -F: '$1 == "pub" { n++ } END { print n + 0 }')" == "1" ]] ||
    die "committed OpenPGP pin must contain exactly one primary key"
pinned_primary="$(GNUPGHOME="${keyring}/home" gpg --batch --with-colons --fingerprint --list-keys | awk -F: '$1 == "fpr" { print $10; exit }')"
[[ "${pinned_primary}" == "${primary}" ]] ||
    die "imported OpenPGP primary does not match committed anchor"

pinned_subkeys="$(GNUPGHOME="${keyring}/home" gpg --batch --with-colons --with-subkey-fingerprint --list-keys |
    awk -F: '$1 == "sub" { s=1; cap=$12; next } s && $1 == "fpr" { if (cap ~ /[sS]/) print $10; s=0 }')"
[[ "$(printf '%s\n' "${pinned_subkeys}" | awk 'NF { n++ } END { print n + 0 }')" == "1" && "${pinned_subkeys}" == "${permitted}" ]] ||
    die "committed OpenPGP pin must contain only the permitted signing subkey"

count=0
while IFS= read -r ref_tag; do
    obj="$(git -C "${root}" rev-parse --verify --quiet "refs/tags/${ref_tag}")" ||
        die "release tag ${ref_tag} is absent"
    if [[ "${ref_tag}" == "${tag}" && "${obj}" != "${canonical_obj}" ]]; then
        die "release tag ${ref_tag} moved during verification"
    fi
    [[ "$(git -C "${root}" cat-file -t "${obj}")" == "tag" ]] ||
        die "${ref_tag} must be an annotated tag object"
    tag_text="$(git -C "${root}" cat-file tag "${obj}")"
    tag_header="$(sed '/^$/q' <<<"${tag_text}")"

    [[ "$(sed -n 's/^object //p' <<<"${tag_header}")" == "${target}" ]] ||
        die "${ref_tag} must directly target commit ${target}"
    [[ "$(sed -n 's/^type //p' <<<"${tag_header}")" == "commit" ]] ||
        die "${ref_tag} direct target type must be commit"
    [[ "$(sed -n 's/^tag //p' <<<"${tag_header}")" == "${ref_tag}" ]] ||
        die "${ref_tag} tag header names a different tag"
    [[ "$(grep -c '^-----BEGIN PGP SIGNATURE-----$' <<<"${tag_text}")" == "1" &&
    "$(grep -c '^-----END PGP SIGNATURE-----$' <<<"${tag_text}")" == "1" ]] ||
        die "${ref_tag} must carry exactly one OpenPGP signature block"

    tag_message="$(awk 'BEGIN { in_msg = 0 } !in_msg && NF == 0 { in_msg = 1; next } in_msg && /^-----BEGIN PGP SIGNATURE-----$/ { exit } in_msg && NF { print }' <<<"${tag_text}")"
    [[ "${tag_message}" == "seclusor ${ref_tag}" ]] ||
        die "${ref_tag} message does not match 'seclusor ${ref_tag}'"

    tagger="$(sed -n 's/^tagger \(.*\) [0-9][0-9]* [+-][0-9][0-9][0-9][0-9]$/\1/p' <<<"${tag_header}" | head -1)"
    [[ "${tagger}" == "${expected_tagger}" ]] ||
        die "${ref_tag} tagger (${tagger}) differs from committed identity (${expected_tagger})"

    GNUPGHOME="${keyring}/home" git -C "${root}" -c gpg.format=openpgp -c gpg.program=gpg \
        verify-tag --raw "${obj}" >"${keyring}/status" 2>&1 || {
        awk '$1 == "[GNUPG:]" { print "signature status:", $2 }' "${keyring}/status" >&2
        die "${ref_tag} signature failed verification under committed pin"
    }
    awk -v primary="${primary}" -v permitted="${permitted}" '
        $1 == "[GNUPG:]" && $2 == "VALIDSIG" { valid++; subkey = $3; signer_primary = $NF }
        $1 == "[GNUPG:]" && $2 == "GOODSIG" { good++ }
        $1 == "[GNUPG:]" && $2 ~ /^(EXPKEYSIG|EXPSIG|REVKEYSIG|KEYREVOKED|KEYEXPIRED|SIGEXPIRED|BADSIG|ERRSIG)$/ { bad++ }
        END {
            if (bad || good != 1 || valid != 1 || signer_primary != primary || subkey == primary || subkey != permitted) {
                exit 1
            }
        }
    ' "${keyring}/status" ||
        die "${ref_tag} is not signed by the permitted subkey, or key/signature is expired or revoked"

    [[ "$(git -C "${root}" rev-parse --verify --quiet "refs/tags/${ref_tag}" || true)" == "${obj}" ]] ||
        die "release tag ${ref_tag} moved during verification"

    count=$((count + 1))
done < <(SECLUSOR_RELEASE_TAG="${tag}" release_tag_names)

[[ "${count}" == "2" ]] || die "expected exactly 2 verified release tags, got ${count}"
echo "[ok] ${count} signed release tags verified at ${target} against committed public pins"
