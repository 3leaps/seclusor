#!/usr/bin/env bash
# Download the unsigned CLI release payload built by the read-only tag-triggered
# `release.yml` workflow for the verified tag pair (`vX.Y.Z` and
# `bindings/go/seclusor/vX.Y.Z`) on the exact tagged commit.
#
# Modes:
#   release-fetch-ci-artifacts.sh [dest_dir]
#       Requires SECLUSOR_RELEASE_TAG, SECLUSOR_RELEASE_COMMIT, RELEASE_RUN_ID,
#       and RELEASE_RUN_ATTEMPT ( plus signing verification env for
#       release-verify-remote-tag.sh). Verifies remote tags, downloads and
#       digest-checks `release-packages-$tag`, validates `release-identity.json`
#       and the exact 5-platform binary set, moves the 5 binaries into dest_dir,
#       and writes `dest_dir.anchor`.
#   release-fetch-ci-artifacts.sh --verify ANCHOR
#       Re-verifies remote tags against ANCHOR, re-downloads the artifact named
#       in ANCHOR into private scratch, checks its digest and `release-identity.json`,
#       and prints `file=<sha256> <name>` lines to stdout.
set -euo pipefail

die() {
    echo "error: $*" >&2
    exit 1
}

repo="3leaps/seclusor"
mode="fetch"
if [[ "${1:-}" == "--verify" ]]; then
    mode="verify"
    anchor_in="${2:?usage: release-fetch-ci-artifacts.sh --verify ANCHOR}"
else
    dest="${1:-dist/release}"
fi

tag="${SECLUSOR_RELEASE_TAG:-}"
[[ "${tag}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
    die "SECLUSOR_RELEASE_TAG=vX.Y.Z is required"
go_tag="bindings/go/seclusor/${tag}"

for tool in gh jq python3 shasum git; do
    command -v "${tool}" >/dev/null 2>&1 || die "${tool} not found in PATH"
done

root="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

expected_binaries=(
    "seclusor-darwin-arm64"
    "seclusor-linux-amd64"
    "seclusor-linux-arm64"
    "seclusor-windows-amd64.exe"
    "seclusor-windows-arm64.exe"
)

if [[ "${mode}" == "fetch" ]]; then
    [[ ! -L "${dest}" && ! -L "${dest}.anchor" ]] ||
        die "${dest} and ${dest}.anchor must not be symlinks"
    [[ ! -e "${dest}.anchor" ]] ||
        die "${dest}.anchor exists; run make release-clean first"
    mkdir -p "${dest}"
    [[ -d "${dest}" && ! -L "${dest}" ]] || die "${dest} is not a directory"
    [[ -z "$(find "${dest}" -mindepth 1 -maxdepth 1 2>/dev/null)" ]] ||
        die "${dest} is not empty; run make release-clean first"
    run_id="${RELEASE_RUN_ID:-}"
    run_attempt="${RELEASE_RUN_ATTEMPT:-}"
else
    [[ -f "${anchor_in}" && ! -L "${anchor_in}" ]] ||
        die "anchor ${anchor_in} is missing or not a regular file"
    field() {
        awk -F= -v k="$1" '$1 == k { print substr($0, length(k) + 2); n++ } END { exit n != 1 }' "${anchor_in}"
    }
    [[ "$(field tag)" == "${tag}" ]] || die "anchor ${anchor_in} is not for ${tag}"
    run_id="$(field run)" || die "anchor has no single run"
    run_attempt="$(field attempt)" || die "anchor has no single attempt"
    want_artifact="$(field artifact)" || die "anchor has no single artifact"
    want_digest="$(field digest)" || die "anchor has no single digest"
    want_object="$(field object)" || die "anchor has no single object"
    want_go_object="$(field go_object)" || die "anchor has no single go_object"
    want_commit="$(field commit)" || die "anchor has no single commit"
fi

"${root}/scripts/release-verify-remote-tag.sh" >/dev/null ||
    die "published tag pair for ${tag} failed verification"

object="$(git -C "${root}" rev-parse --verify --quiet "refs/tags/${tag}")" ||
    die "local tag ${tag} is absent"
go_object="$(git -C "${root}" rev-parse --verify --quiet "refs/tags/${go_tag}")" ||
    die "local tag ${go_tag} is absent"
commit="$(git -C "${root}" rev-parse "${object}^{commit}")"
[[ "${commit}" =~ ^[0-9a-f]{40}$ && "${object}" =~ ^[0-9a-f]{40}$ && "${go_object}" =~ ^[0-9a-f]{40}$ ]] ||
    die "could not resolve verified tag objects"
[[ "$(git -C "${root}" rev-parse "${go_object}^{commit}")" == "${commit}" ]] ||
    die "Go tag ${go_tag} does not peel to ${commit}"

if [[ "${mode}" == "verify" ]]; then
    [[ "${want_object}" == "${object}" && "${want_go_object}" == "${go_object}" && "${want_commit}" == "${commit}" ]] ||
        die "verified tags no longer match the objects recorded in ${anchor_in}"
fi

[[ "${run_id}" =~ ^[1-9][0-9]*$ ]] ||
    die "RELEASE_RUN_ID required (the Release workflow run for ${tag})"
[[ "${run_attempt}" =~ ^[1-9][0-9]*$ ]] ||
    die "RELEASE_RUN_ATTEMPT required (the successful attempt of that run)"

run_json="$(gh api "repos/${repo}/actions/runs/${run_id}/attempts/${run_attempt}" \
    --jq '{path, event, head_branch, head_sha, status, conclusion, run_attempt}')" ||
    die "could not read run ${run_id} attempt ${run_attempt}"

jq -e --arg tag "${tag}" --arg commit "${commit}" --argjson attempt "${run_attempt}" '
    .path == ".github/workflows/release.yml" and .event == "push" and .head_branch == $tag and
    .head_sha == $commit and .status == "completed" and .conclusion == "success" and
    .run_attempt == $attempt
' <<<"${run_json}" >/dev/null ||
    die "run ${run_id} attempt ${run_attempt} is not a successful release.yml push run for ${tag} at ${commit}"

artifact_name="release-packages-${tag}"
snapshot() {
    local latest listing
    latest="$(gh api "repos/${repo}/actions/runs/${run_id}" --jq '.run_attempt')" ||
        die "could not read run ${run_id}"
    [[ "${latest}" == "${run_attempt}" ]] ||
        die "run ${run_id} has a later attempt (${latest}); artifacts belong to the latest attempt"
    listing="$(gh api "repos/${repo}/actions/runs/${run_id}/artifacts?per_page=100")" ||
        die "could not list artifacts for run ${run_id}"
    jq -e '.total_count == (.artifacts | length)' <<<"${listing}" >/dev/null ||
        die "artifact list for run ${run_id} is incomplete"
    listing="$(jq --arg n "${artifact_name}" '[.artifacts[] | select(.name == $n and .expired == false)]' <<<"${listing}")" ||
        die "could not filter artifacts for run ${run_id}"
    jq -e --arg c "${commit}" --argjson r "${run_id}" \
        'length == 1 and (.[0].workflow_run.id == $r) and (.[0].workflow_run.head_sha == $c)' <<<"${listing}" >/dev/null ||
        die "run ${run_id} does not hold exactly one unexpired ${artifact_name} for ${commit}"
    jq -r '.[0] | "\(.id) \(.digest // "")"' <<<"${listing}"
}

before="$(snapshot)" || exit 1
read -r artifact_id artifact_digest <<<"${before}"
[[ "${artifact_id}" =~ ^[1-9][0-9]*$ ]] || die "artifact id is malformed"
[[ "${artifact_digest}" =~ ^sha256:[0-9a-f]{64}$ ]] ||
    die "artifact ${artifact_id} has no sha256 digest"

if [[ "${mode}" == "verify" ]]; then
    [[ "${artifact_id}" == "${want_artifact}" && "${artifact_digest}" == "${want_digest}" ]] ||
        die "run ${run_id} now names artifact ${artifact_id} (${artifact_digest}), not staged ${want_artifact}"
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/seclusor-fetch.XXXXXX")"
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
python3 -I - "${work}/artifact.zip" "${work}/x" "${tag}" "${object}" "${go_object}" "${commit}" \
    "${expected_binaries[@]}" <<'PY' || die "artifact ${artifact_id} failed layout or identity verification"
import json
import pathlib
import re
import sys
import zipfile

zip_path = pathlib.Path(sys.argv[1])
dest = pathlib.Path(sys.argv[2])
want_tag, want_obj, want_go_obj, want_commit = sys.argv[3:7]
expected_bins = set(sys.argv[7:])
expected_all = expected_bins | {"release-identity.json"}

seen = set()
with zipfile.ZipFile(zip_path) as zf:
    for info in zf.infolist():
        name = info.filename
        if info.is_dir() or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) or name in seen:
            raise SystemExit(f"error: unexpected or duplicate entry in artifact: {name!r}")
        mode = info.external_attr >> 16
        if mode and (mode & 0o170000) not in (0, 0o100000):
            raise SystemExit(f"error: non-regular entry in artifact: {name!r}")
        seen.add(name)
        with open(dest / name, "xb") as out:
            out.write(zf.read(info))

if seen != expected_all:
    missing = sorted(expected_all - seen)
    extra = sorted(seen - expected_all)
    raise SystemExit(f"error: artifact inventory mismatch (missing={missing}, extra={extra})")

ident = json.loads((dest / "release-identity.json").read_text(encoding="utf-8"))
if (
    ident.get("tag") != want_tag
    or ident.get("object") != want_obj
    or ident.get("go_tag_object") != want_go_obj
    or ident.get("commit") != want_commit
):
    raise SystemExit(f"error: release-identity.json mismatch: {ident!r}")

(dest / "release-identity.json").unlink()
for b in sorted(expected_bins):
    p = dest / b
    if p.stat().st_size == 0:
        raise SystemExit(f"error: empty binary in artifact: {b}")
    if not b.endswith(".exe"):
        p.chmod(0o755)
PY

(
    cd "${work}/x"
    for b in "${expected_binaries[@]}"; do
        printf 'file=%s %s\n' "$(shasum -a 256 "${b}" | awk '{print $1}')" "${b}"
    done
) >"${work}/files"

if [[ "${mode}" == "verify" ]]; then
    cat "${work}/files"
    exit 0
fi

mv "${work}/x"/* "${dest}/"
{
    printf 'tag=%s\nobject=%s\ngo_object=%s\ncommit=%s\nrun=%s\nattempt=%s\nartifact=%s\ndigest=%s\n' \
        "${tag}" "${object}" "${go_object}" "${commit}" "${run_id}" "${run_attempt}" "${artifact_id}" "${artifact_digest}"
    cat "${work}/files"
} >"${dest}.anchor"

echo "[ok] downloaded 5 verified CLI binaries for ${tag} (commit ${commit}) from ${repo} run ${run_id} attempt ${run_attempt} into ${dest}"
