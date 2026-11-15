#!/usr/bin/env bash
# Create the draft GitHub Release for a verified dual-tagged seclusor release
# from locally staged, checksummed, and signed assets.
#
# Runs on the maintainer machine only; CI holds zero write authority.
# Re-verifies the CI artifact digest against GitHub and re-verifies both remote
# signed tags immediately before creating the draft release. Refuses if any
# release (published or draft) already exists for the tag.
set -euo pipefail

die() {
    echo "error: $*" >&2
    exit 1
}

verify_only=0
if [[ "${1:-}" == "--verify-only" ]]; then
    verify_only=1
    shift
fi

dir="${1:-dist/release}"
tag="${SECLUSOR_RELEASE_TAG:-}"
[[ "${tag}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
    die "SECLUSOR_RELEASE_TAG=vX.Y.Z is required"

for tool in gh jq python3 shasum git; do
    command -v "${tool}" >/dev/null 2>&1 || die "${tool} not found in PATH"
done

root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
repo="3leaps/seclusor"

[[ -d "${dir}" && ! -L "${dir}" ]] || die "release directory not found: ${dir}"
anchor="${dir}.anchor"
[[ -f "${anchor}" && ! -L "${anchor}" ]] ||
    die "missing ${anchor}; stage CI artifacts first with make release-download"

expected_binaries=(
    "seclusor-darwin-arm64"
    "seclusor-linux-amd64"
    "seclusor-linux-arm64"
    "seclusor-windows-amd64.exe"
    "seclusor-windows-arm64.exe"
)
checksummed_files=(
    "${expected_binaries[@]}"
    "expected-fingerprints.ndjson"
    "expected-fingerprints.txt"
)
required_files=(
    "${checksummed_files[@]}"
    "SHA256SUMS"
    "SHA512SUMS"
    "SHA256SUMS.minisig"
    "SHA512SUMS.minisig"
    "SHA256SUMS.asc"
    "SHA512SUMS.asc"
    "minisign.pub"
    "release-key.asc"
    "release-notes-${tag}.md"
)

snapshot="$(mktemp -d "${TMPDIR:-/tmp}/seclusor-draft.XXXXXX")"
chmod 700 "${snapshot}"
trap 'rm -rf "${snapshot}" "${snapshot}.anchor" "${snapshot}.remote"' EXIT
cp -p "${anchor}" "${snapshot}.anchor"

# Reject any unexpected or non-regular entry in the staging directory.
while IFS= read -r -d '' entry; do
    name="${entry##*/}"
    allowed=0
    for want in "${required_files[@]}"; do
        [[ "${name}" == "${want}" ]] && allowed=1
    done
    [[ "${allowed}" == "1" ]] ||
        die "unexpected file in ${dir}: ${name} (run make release-clean and restage)"
    [[ -f "${entry}" && ! -L "${entry}" ]] || die "not a regular file: ${name}"
    cp -p "${entry}" "${snapshot}/${name}"
done < <(find "${dir}" -mindepth 1 -maxdepth 1 -print0)

for want in "${required_files[@]}"; do
    [[ -f "${snapshot}/${want}" && -s "${snapshot}/${want}" ]] ||
        die "missing required staged release file: ${want}"
done

# Verify checksums, signatures, and public-key anchors on the private snapshot.
python3 -I - "${snapshot}" "${checksummed_files[@]}" <<'PY'
import hashlib
import pathlib
import sys

snap = pathlib.Path(sys.argv[1])
expected = sorted(sys.argv[2:])
for manifest, algo, width in (("SHA256SUMS", "sha256", 64), ("SHA512SUMS", "sha512", 128)):
    entries = {}
    for line in (snap / manifest).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, sep, name = line.partition("  ")
        name = name.lstrip("*")
        if not sep or len(digest) != width or name in entries:
            raise SystemExit(f"error: malformed or duplicate {manifest} line: {line!r}")
        entries[name] = digest.lower()
    if sorted(entries) != expected:
        raise SystemExit(
            f"error: {manifest} does not list exact expected set (got={sorted(entries)}, expected={expected})"
        )
    for name in expected:
        actual = hashlib.new(algo, (snap / name).read_bytes()).hexdigest()
        if actual != entries[name]:
            raise SystemExit(f"error: {manifest} digest mismatch for {name}")
PY

SECLUSOR_MINISIGN_PUB="" SECLUSOR_GPG_HOMEDIR="" "${root}/scripts/verify-signatures.sh" "${snapshot}" >/dev/null
"${root}/scripts/verify-public-keys.sh" "${snapshot}" >/dev/null

# Re-verify remote tags and re-download the CI artifact to confirm byte identity.
"${root}/scripts/release-fetch-ci-artifacts.sh" --verify "${snapshot}.anchor" >"${snapshot}.remote" ||
    die "the CI artifact named by ${anchor} no longer verifies"

names=""
while IFS= read -r line; do
    [[ "${line}" =~ ^file=([0-9a-f]{64})\ ([A-Za-z0-9][A-Za-z0-9._-]*)$ ]] ||
        die "unexpected artifact record: ${line}"
    sum="${BASH_REMATCH[1]}"
    name="${BASH_REMATCH[2]}"
    names+="${name}"$'\n'
    [[ -f "${snapshot}/${name}" ]] || die "artifact file ${name} is absent from snapshot"
    [[ "$(shasum -a 256 "${snapshot}/${name}" | awk '{print $1}')" == "${sum}" ]] ||
        die "${name} differs from the CI artifact downloaded from GitHub"
done <"${snapshot}.remote"

[[ "$(printf '%s' "${names}" | LC_ALL=C sort)" == "$(printf '%s\n' "${expected_binaries[@]}" | LC_ALL=C sort)" ]] ||
    die "downloaded CI artifact does not hold the exact 5 CLI binaries"

commit="$(awk -F= '$1 == "commit" { print $2 }' "${snapshot}.anchor")"
[[ "${commit}" =~ ^[0-9a-f]{40}$ ]] || die "staged anchor commit is malformed"

# Staged release notes, anchors, and public keys must match the tagged commit's blobs byte-for-byte.
check_tagged_blob() {
    local commit_rel="$1" snap_file="$2" blob_oid
    blob_oid="$(git -C "${root}" rev-parse --verify --quiet "${commit}:${commit_rel}")" ||
        die "${commit_rel} is absent at tagged commit ${commit}"
    [[ "$(git -C "${root}" hash-object -- "${snapshot}/${snap_file}")" == "${blob_oid}" ]] ||
        die "staged ${snap_file} differs from ${commit}:${commit_rel}"
}
check_tagged_blob "docs/releases/${tag}.md" "release-notes-${tag}.md"
check_tagged_blob "keys/expected-fingerprints.txt" "expected-fingerprints.txt"
check_tagged_blob "keys/expected-fingerprints.ndjson" "expected-fingerprints.ndjson"
check_tagged_blob "docs/security/release-signing-keys.asc" "release-key.asc"
check_tagged_blob "docs/security/seclusor-minisign.pub" "minisign.pub"

if [[ "${verify_only}" == "1" ]]; then
    echo "[ok] verified staged release directory ${dir} for ${tag} at ${commit}"
    exit 0
fi

# Confirm no release (published or draft) already exists for this tag.
releases="$(gh api --paginate "repos/${repo}/releases?per_page=100" --jq '.[].tag_name')" ||
    die "could not list releases for ${repo}; existence of ${tag} is unknown"
if grep -qxF -- "${tag}" <<<"${releases}"; then
    die "a release for ${tag} already exists on ${repo}; assets are never replaced"
fi

upload_files=()
while IFS= read -r path; do
    upload_files+=("${path}")
done < <(find "${snapshot}" -mindepth 1 -maxdepth 1 -type f | LC_ALL=C sort)

gh release create "${tag}" --repo "${repo}" --verify-tag --draft --target "${commit}" \
    --title "${tag}" --notes-file "${snapshot}/release-notes-${tag}.md" "${upload_files[@]}"

echo "[ok] draft release ${tag} created at ${commit} with ${#upload_files[@]} verified assets (remains unpublished)"
