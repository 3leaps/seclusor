#!/usr/bin/env bash
# Download and digest-verify the prebuilt Go FFI libraries + C header produced
# by the read-only `go-bindings.yml` workflow for the current VERSION at HEAD.
#
# Usage: RELEASE_RUN_ID=<id> RELEASE_RUN_ATTEMPT=<n> ./scripts/go-bindings-fetch-ci-artifacts.sh
set -euo pipefail

die() {
    echo "error: $*" >&2
    exit 1
}

root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
repo="3leaps/seclusor"

for tool in gh jq python3 shasum git; do
    command -v "${tool}" >/dev/null 2>&1 || die "${tool} not found in PATH"
done

version="$(tr -d ' \t\r\n' <"${root}/VERSION")"
[[ "${version}" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
    die "VERSION (${version}) is not valid semver"

head_commit="$(git -C "${root}" rev-parse HEAD)"
run_id="${RELEASE_RUN_ID:-}"
run_attempt="${RELEASE_RUN_ATTEMPT:-}"
[[ "${run_id}" =~ ^[1-9][0-9]*$ ]] ||
    die "RELEASE_RUN_ID is required (the go-bindings.yml run ID at HEAD)"
[[ "${run_attempt}" =~ ^[1-9][0-9]*$ ]] ||
    die "RELEASE_RUN_ATTEMPT is required (the successful attempt of that run)"

run_json="$(gh api "repos/${repo}/actions/runs/${run_id}/attempts/${run_attempt}" \
    --jq '{path, event, head_sha, status, conclusion, run_attempt}')" ||
    die "could not read run ${run_id} attempt ${run_attempt}"

jq -e --arg commit "${head_commit}" --argjson attempt "${run_attempt}" '
    .path == ".github/workflows/go-bindings.yml" and .event == "workflow_dispatch" and
    .head_sha == $commit and .status == "completed" and .conclusion == "success" and
    .run_attempt == $attempt
' <<<"${run_json}" >/dev/null ||
    die "run ${run_id} attempt ${run_attempt} is not a successful go-bindings.yml run at HEAD (${head_commit})"

artifact_name="go-bindings-v${version}"
snapshot() {
    local latest listing
    latest="$(gh api "repos/${repo}/actions/runs/${run_id}" --jq '.run_attempt')" ||
        die "could not read run ${run_id}"
    [[ "${latest}" == "${run_attempt}" ]] ||
        die "run ${run_id} has a later attempt (${latest}); name the latest attempt"
    listing="$(gh api "repos/${repo}/actions/runs/${run_id}/artifacts?per_page=100")" ||
        die "could not list artifacts for run ${run_id}"
    jq -e '.total_count == (.artifacts | length)' <<<"${listing}" >/dev/null ||
        die "artifact list for run ${run_id} is incomplete"
    listing="$(jq --arg n "${artifact_name}" '[.artifacts[] | select(.name == $n and .expired == false)]' <<<"${listing}")" ||
        die "could not filter artifacts for run ${run_id}"
    jq -e --arg c "${head_commit}" --argjson r "${run_id}" \
        'length == 1 and (.[0].workflow_run.id == $r) and (.[0].workflow_run.head_sha == $c)' <<<"${listing}" >/dev/null ||
        die "run ${run_id} does not hold exactly one unexpired ${artifact_name} for ${head_commit}"
    jq -r '.[0] | "\(.id) \(.digest // "")"' <<<"${listing}"
}

before="$(snapshot)" || exit 1
read -r artifact_id artifact_digest <<<"${before}"
[[ "${artifact_id}" =~ ^[1-9][0-9]*$ ]] || die "artifact id is malformed"
[[ "${artifact_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    die "artifact ${artifact_id} has no sha256 digest"

work="$(mktemp -d "${TMPDIR:-/tmp}/seclusor-gobindings.XXXXXX")"
trap 'rm -rf "${work}"' EXIT

gh api "repos/${repo}/actions/artifacts/${artifact_id}/zip" >"${work}/artifact.zip" ||
    die "could not download artifact ${artifact_id}"
actual="sha256:$(shasum -a 256 "${work}/artifact.zip" | awk '{print $1}')"
[[ "${actual}" == "${artifact_digest}" ]] ||
    die "artifact ${artifact_id} bytes do not match recorded digest ${artifact_digest}"

after="$(snapshot)" || exit 1
[[ "${after}" == "${before}" ]] ||
    die "run ${run_id} changed during download (${before} -> ${after}); restage"

mkdir "${work}/x"
python3 -I - "${work}/artifact.zip" "${work}/x" "${version}" "${head_commit}" <<'PY' || die "go-bindings artifact failed verification"
import hashlib
import json
import pathlib
import sys
import zipfile

zip_path = pathlib.Path(sys.argv[1])
dest = pathlib.Path(sys.argv[2])
want_version, want_commit = sys.argv[3:5]

platforms = (
    "darwin-amd64",
    "darwin-arm64",
    "linux-amd64",
    "linux-arm64",
    "windows-amd64",
)
expected_files = {
    "go-bindings-identity.json",
    "SHA256SUMS",
    "include/seclusor.h",
    *(f"lib/{p}/libseclusor_ffi.a" for p in platforms),
}

seen = set()
with zipfile.ZipFile(zip_path) as zf:
    for info in zf.infolist():
        if info.is_dir():
            continue
        name = info.filename
        if name not in expected_files or name in seen:
            raise SystemExit(f"error: unexpected or duplicate entry in go-bindings artifact: {name!r}")
        mode = info.external_attr >> 16
        if mode and (mode & 0o170000) not in (0, 0o100000):
            raise SystemExit(f"error: non-regular entry in artifact: {name!r}")
        seen.add(name)
        out_path = dest / name
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "xb") as out:
            out.write(zf.read(info))

if seen != expected_files:
    missing = sorted(expected_files - seen)
    raise SystemExit(f"error: missing expected go-bindings artifact entries: {missing}")

ident = json.loads((dest / "go-bindings-identity.json").read_text(encoding="utf-8"))
if ident.get("version") != want_version or ident.get("commit") != want_commit:
    raise SystemExit(f"error: go-bindings-identity.json mismatch: {ident!r}")

sums = {}
for line in (dest / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    digest, sep, rel = line.partition("  ")
    if not sep or len(digest) != 64 or rel in sums:
        raise SystemExit(f"error: malformed SHA256SUMS line: {line!r}")
    sums[rel] = digest.lower()

hashed_targets = expected_files - {"SHA256SUMS", "go-bindings-identity.json"}
if set(sums) != hashed_targets:
    raise SystemExit(f"error: SHA256SUMS entries {sorted(sums)} != {sorted(hashed_targets)}")
for rel, want in sums.items():
    data = (dest / rel).read_bytes()
    if not data:
        raise SystemExit(f"error: empty file in go-bindings artifact: {rel}")
    if hashlib.sha256(data).hexdigest() != want:
        raise SystemExit(f"error: SHA256 mismatch for {rel}")
PY

# Verify no LLVM bitcode/LTO sections remain in any downloaded static library without mutating bytes.
for platform in darwin-amd64 darwin-arm64 linux-amd64 linux-arm64 windows-amd64; do
    "${root}/scripts/strip-ffi-bitcode.sh" --check "${work}/x/lib/${platform}/libseclusor_ffi.a"
done

mkdir -p "${root}/bindings/go/seclusor/include"
cp "${work}/x/include/seclusor.h" "${root}/bindings/go/seclusor/include/seclusor.h"
for platform in darwin-amd64 darwin-arm64 linux-amd64 linux-arm64 windows-amd64; do
    mkdir -p "${root}/bindings/go/seclusor/lib/${platform}"
    cp "${work}/x/lib/${platform}/libseclusor_ffi.a" \
        "${root}/bindings/go/seclusor/lib/${platform}/libseclusor_ffi.a"
done

echo "[ok] staged verified Go binding header and 5 static libraries for v${version} (${head_commit}) from run ${run_id} attempt ${run_attempt}"
