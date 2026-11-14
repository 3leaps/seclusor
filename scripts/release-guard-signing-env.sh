#!/usr/bin/env bash
set -euo pipefail
script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/release-tag-common.sh
source "${script_dir}/release-tag-common.sh"
cd "$(release_repo_root)"
release_validate_signing_env
release_assert_checkout
echo "[ok] authorized signing environment and release commit"
