#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/release-tag-common.sh
source "${script_dir}/release-tag-common.sh"
cd "$(release_repo_root)"

release_validate_signing_env
release_setup_gpg_tty
release_assert_checkout
release_assert_tag_absent

export GIT_COMMITTER_NAME="${SECLUSOR_TAGGER_NAME}"
export GIT_COMMITTER_EMAIL="${SECLUSOR_TAGGER_EMAIL}"

created=()
rollback() {
    local tag
    for tag in "${created[@]}"; do
        git tag -d "${tag}" >/dev/null 2>&1 || true
    done
}
trap rollback EXIT

while IFS= read -r tag; do
    echo "Creating GPG-signed tag ${tag} at ${SECLUSOR_RELEASE_COMMIT}"
    GNUPGHOME="${GNUPGHOME}" git -c gpg.format=openpgp -c gpg.program=gpg tag -s -a \
        -u "${SECLUSOR_PGP_KEY_ID}" -m "seclusor ${tag}" \
        "${tag}" "${SECLUSOR_RELEASE_COMMIT}"
    created+=("${tag}")
    release_verify_local_tag "${tag}"
done < <(release_tag_names)

trap - EXIT
echo "[ok] both signed tags created and verified locally; push requires a separate cue"
