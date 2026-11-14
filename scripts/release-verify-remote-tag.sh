#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/release-tag-common.sh
source "${script_dir}/release-tag-common.sh"
cd "$(release_repo_root)"

release_validate_verification_env
release_assert_checkout
release_require_command gh
release_require_command jq

while IFS= read -r tag; do
    release_verify_local_tag "${tag}"
    local_object="$(git rev-parse "refs/tags/${tag}")"
    remote_object="$(git ls-remote --tags origin "refs/tags/${tag}" | awk -v want="refs/tags/${tag}" '$2 == want {print $1}')"
    if [ "${remote_object}" != "${local_object}" ]; then
        echo "error: remote tag ${tag} object differs from local signed tag" >&2
        exit 1
    fi
    ref_json="$(gh api "repos/3leaps/seclusor/git/ref/tags/${tag}")"
    if ! jq -e --arg object "${local_object}" '.object.type == "tag" and .object.sha == $object' >/dev/null <<<"${ref_json}"; then
        echo "error: GitHub ref ${tag} does not target the local annotated tag object" >&2
        exit 1
    fi
    tag_json="$(gh api "repos/3leaps/seclusor/git/tags/${local_object}")"
    if ! jq -e --arg tag "${tag}" --arg commit "${SECLUSOR_RELEASE_COMMIT}" \
        --arg name "${SECLUSOR_TAGGER_NAME}" --arg email "${SECLUSOR_TAGGER_EMAIL}" \
        '.tag == $tag and .object.type == "commit" and .object.sha == $commit and
         .tagger.name == $name and .tagger.email == $email and
         .verification.verified == true and .verification.reason == "valid"' \
        >/dev/null <<<"${tag_json}"; then
        echo "error: GitHub has not verified ${tag} at origin/main with the required tagger" >&2
        exit 1
    fi
    echo "[ok] GitHub Verified/valid signed tag ${tag} at ${SECLUSOR_RELEASE_COMMIT}"
done < <(release_tag_names)
