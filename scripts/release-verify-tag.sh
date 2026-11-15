#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/release-tag-common.sh
source "${script_dir}/release-tag-common.sh"
cd "$(release_repo_root)"

release_validate_verification_env
release_assert_checkout
while IFS= read -r tag; do
    release_verify_local_tag "${tag}"
    echo "[ok] verified signed tag ${tag}"
done < <(release_tag_names)
