#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/release-tag-common.sh
source "${script_dir}/release-tag-common.sh"
cd "$(release_repo_root)"

release_validate_verification_env
release_assert_checkout

tag_names=()
tag_oids=()
refs=()
while IFS= read -r tag; do
    oid="$(git rev-parse --verify --quiet "refs/tags/${tag}" 2>/dev/null || true)"
    if ! [[ "${oid}" =~ ^[0-9a-f]{40}$ ]] || [ "$(git cat-file -t "${oid}" 2>/dev/null || true)" != "tag" ]; then
        echo "error: ${tag} must resolve to an annotated tag object" >&2
        exit 1
    fi
    release_verify_local_tag "${tag}" "${oid}"
    status=0
    git ls-remote --exit-code --tags origin "refs/tags/${tag}" >/dev/null 2>&1 || status=$?
    if [ "${status}" -ne 2 ]; then
        echo "error: remote tag ${tag} already exists or remote state is unavailable" >&2
        exit 1
    fi
    current_oid="$(git rev-parse --verify --quiet "refs/tags/${tag}" 2>/dev/null || true)"
    if [ "${current_oid}" != "${oid}" ]; then
        echo "error: local tag ref ${tag} moved after verification" >&2
        exit 1
    fi
    tag_names+=("${tag}")
    tag_oids+=("${oid}")
    refs+=("${oid}:refs/tags/${tag}")
done < <(release_tag_names)

for idx in "${!tag_names[@]}"; do
    current_oid="$(git rev-parse --verify --quiet "refs/tags/${tag_names[${idx}]}" 2>/dev/null || true)"
    if [ "${current_oid}" != "${tag_oids[${idx}]}" ]; then
        echo "error: local tag ref ${tag_names[${idx}]} moved before atomic push" >&2
        exit 1
    fi
done

git push --atomic origin "${refs[@]}"
echo "[ok] pushed both signed tags atomically; run make release-verify-remote-tag"
