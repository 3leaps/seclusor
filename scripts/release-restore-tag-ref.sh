#!/usr/bin/env bash
# Restore remote annotated release tag refs after actions/checkout peels them locally.
#
# Resolves both `vX.Y.Z` and `bindings/go/seclusor/vX.Y.Z` through the GitHub REST
# API with the read-only job token (GITHUB_TOKEN / GH_TOKEN), never anonymous
# `git ls-remote`, then fetches each ref into FETCH_HEAD with a masked temporary
# HTTP header (`persist-credentials: false` remains intact). Both remote refs must
# resolve to annotated tag objects that peel to HEAD (and match expected tag
# object SHAs when downstream jobs supply SECLUSOR_EXPECTED_TAG_OBJECT /
# SECLUSOR_EXPECTED_GO_TAG_OBJECT).
set -euo pipefail

die() {
    echo "error: $*" >&2
    exit 1
}

repo="3leaps/seclusor"
tag="${SECLUSOR_RELEASE_TAG:-}"
[[ "${tag}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
    die "SECLUSOR_RELEASE_TAG=vX.Y.Z is required"
go_tag="bindings/go/seclusor/${tag}"

token="${GITHUB_TOKEN:-${GH_TOKEN:-}}"
[[ -n "${token}" ]] || die "GITHUB_TOKEN (or GH_TOKEN) is required for tag lookup"

origin_url="$(git config --get remote.origin.url || true)"
if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
    case "${origin_url}" in
    "https://github.com/${repo}" | "https://github.com/${repo}.git") ;;
    *) die "unexpected release origin: ${origin_url}" ;;
    esac
    if [[ -n "${SECLUSOR_GITHUB_API+x}" ]]; then
        die "SECLUSOR_GITHUB_API is not accepted under GitHub Actions"
    fi
fi

api="${SECLUSOR_GITHUB_API:-https://api.github.com}"
[[ "${api}" == https://* || (-z "${GITHUB_ACTIONS:-}" && "${api}" == http://127.0.0.1:*) ]] ||
    die "the GitHub API must be reached over https"

head_commit="$(git rev-parse HEAD)"

restore_one_tag() {
    local ref_tag="$1" expected_obj="$2"
    local ref_json remote_type remote_object auth

    # Token travels on curl stdin (--config -), never in argv or on disk.
    ref_json="$(printf 'header = "Authorization: Bearer %s"\n' "${token}" |
        curl --proto '=https,http' --tlsv1.2 --fail --silent --show-error --retry 3 --config - \
            --header 'Accept: application/vnd.github+json' \
            "${api}/repos/${repo}/git/ref/tags/${ref_tag}")" ||
        die "remote release tag is absent: ${ref_tag}"

    remote_type="$(jq -r '.object.type // empty' <<<"${ref_json}")" ||
        die "remote tag lookup returned invalid JSON for ${ref_tag}"
    remote_object="$(jq -r '.object.sha // empty' <<<"${ref_json}")"
    [[ "$(jq -r '.ref // empty' <<<"${ref_json}")" == "refs/tags/${ref_tag}" ]] ||
        die "remote tag lookup named another ref for ${ref_tag}"
    [[ "${remote_type}" == "tag" ]] || die "remote release tag must be annotated: ${ref_tag}"
    [[ "${remote_object}" =~ ^[0-9a-f]{40}$ ]] || die "remote tag object is invalid for ${ref_tag}"

    if [[ -n "${expected_obj}" ]]; then
        [[ "${expected_obj}" =~ ^[0-9a-f]{40}$ && "${remote_object}" == "${expected_obj}" ]] ||
            die "remote tag object for ${ref_tag} differs from validated object"
    fi

    if [[ "${origin_url}" == https://github.com/* ]]; then
        auth="$(printf 'x-access-token:%s' "${token}" | base64 | tr -d '\n')"
        [[ -z "${GITHUB_ACTIONS:-}" ]] || echo "::add-mask::${auth}"
        GIT_CONFIG_COUNT=1 \
            GIT_CONFIG_KEY_0='http.https://github.com/.extraheader' \
            GIT_CONFIG_VALUE_0="AUTHORIZATION: basic ${auth}" \
            git fetch --quiet --no-tags --refmap= origin "refs/tags/${ref_tag}" ||
            die "origin release tag could not be fetched: ${ref_tag}"
    else
        git fetch --quiet --no-tags --refmap= origin "refs/tags/${ref_tag}" ||
            die "origin release tag could not be fetched: ${ref_tag}"
    fi

    [[ "$(git rev-parse --verify --quiet FETCH_HEAD)" == "${remote_object}" ]] ||
        die "origin tag object differs from REST API answer for ${ref_tag}"
    git update-ref "refs/tags/${ref_tag}" "${remote_object}"
    [[ "$(git rev-parse "refs/tags/${ref_tag}")" == "${remote_object}" &&
    "$(git cat-file -t "refs/tags/${ref_tag}")" == "tag" &&
    "$(git rev-parse "refs/tags/${ref_tag}^{}")" == "${head_commit}" ]] ||
        die "runner-local tag is not the remote annotated tag at HEAD: ${ref_tag}"
    echo "[ok] runner-local annotated tag restored for ${ref_tag} (${remote_object})"
}

restore_one_tag "${tag}" "${SECLUSOR_EXPECTED_TAG_OBJECT:-}"
restore_one_tag "${go_tag}" "${SECLUSOR_EXPECTED_GO_TAG_OBJECT:-}"
