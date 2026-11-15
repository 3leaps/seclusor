#!/usr/bin/env bash

set -euo pipefail

release_repo_root() {
    git rev-parse --show-toplevel
}

release_read_version() {
    if [ ! -f VERSION ]; then
        echo "error: VERSION file not found" >&2
        return 1
    fi
    tr -d ' \t\r\n' <VERSION
}

release_require_env() {
    local name="$1"
    if [ -z "${!name:-}" ]; then
        echo "error: ${name} is required" >&2
        return 1
    fi
}

release_require_command() {
    local name="$1"
    if ! command -v "${name}" >/dev/null 2>&1; then
        echo "error: ${name} is required on PATH" >&2
        return 1
    fi
}

release_assert_tag_version() {
    release_require_env SECLUSOR_RELEASE_TAG

    local version expected_tag
    version="$(release_read_version)"
    expected_tag="v${version}"

    if ! [[ "${SECLUSOR_RELEASE_TAG}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "error: SECLUSOR_RELEASE_TAG must match vMAJOR.MINOR.PATCH" >&2
        return 1
    fi
    if [ "${SECLUSOR_RELEASE_TAG}" != "${expected_tag}" ]; then
        echo "error: SECLUSOR_RELEASE_TAG does not match VERSION (${expected_tag})" >&2
        return 1
    fi
}

release_assert_release_commit() {
    release_require_env SECLUSOR_RELEASE_COMMIT || return 1
    if ! [[ "${SECLUSOR_RELEASE_COMMIT}" =~ ^[0-9a-f]{40}$ ]]; then
        echo "error: SECLUSOR_RELEASE_COMMIT must be a literal lowercase full commit SHA" >&2
        return 1
    fi
}

release_tag_names() {
    printf '%s\n' "${SECLUSOR_RELEASE_TAG}" "bindings/go/seclusor/${SECLUSOR_RELEASE_TAG}"
}

release_canonical_directory() {
    local path="$1"
    if [ ! -d "${path}" ]; then
        return 1
    fi
    CDPATH='' cd -- "${path}" && pwd -P
}

release_configure_gpg() {
    release_require_env SECLUSOR_GPG_HOMEDIR

    local canonical_home
    canonical_home="$(release_canonical_directory "${SECLUSOR_GPG_HOMEDIR}" || true)"
    if [ -z "${canonical_home}" ]; then
        echo "error: SECLUSOR_GPG_HOMEDIR must name an existing directory" >&2
        return 1
    fi
    if git -C "${canonical_home}" rev-parse --git-dir >/dev/null 2>&1; then
        echo "error: SECLUSOR_GPG_HOMEDIR must remain outside every Git repository" >&2
        return 1
    fi

    export GNUPGHOME="${canonical_home}"
}

release_validate_pgp_key_id() {
    release_require_env SECLUSOR_PGP_KEY_ID
    if ! [[ "${SECLUSOR_PGP_KEY_ID}" =~ ^([0-9A-F]{16}|[0-9A-F]{40})!$ ]]; then
        echo "error: SECLUSOR_PGP_KEY_ID must be an uppercase 16-hex key ID or 40-hex fingerprint followed by !" >&2
        return 1
    fi
}

release_validate_fingerprint() {
    release_require_env SECLUSOR_GPG_SIGNING_FINGERPRINT
    if ! [[ "${SECLUSOR_GPG_SIGNING_FINGERPRINT}" =~ ^[0-9A-F]{40}$ ]]; then
        echo "error: SECLUSOR_GPG_SIGNING_FINGERPRINT must be a full uppercase 40-hex primary fingerprint" >&2
        return 1
    fi
}

release_assert_authorized_primary_anchor() {
    local txt="keys/expected-fingerprints.txt"
    local ndjson="keys/expected-fingerprints.ndjson"
    if [ ! -s "${txt}" ] || [ ! -s "${ndjson}" ]; then
        echo "error: committed public-key anchor pair is missing" >&2
        return 1
    fi
    python3 - "${txt}" "${ndjson}" "${SECLUSOR_GPG_SIGNING_FINGERPRINT}" <<'PYANCHOR'
import json
import pathlib
import re
import sys

txt, ndjson, expected_primary = map(str, sys.argv[1:4])
lines = pathlib.Path(txt).read_text().splitlines()
if len(lines) != 2:
    raise SystemExit("error: fingerprint TXT must contain two records")
parsed = [line.split() for line in lines]
if any(len(fields) != 2 for fields in parsed):
    raise SystemExit("error: fingerprint TXT has malformed records")
values = dict(parsed)
if len(values) != 2 or set(values) != {"gpg", "minisign"}:
    raise SystemExit("error: fingerprint TXT must name GPG and minisign once")
if values["gpg"] != expected_primary or not re.fullmatch(r"[0-9A-F]{40}", values["gpg"]):
    raise SystemExit("error: GPG anchor differs from the authorized primary")
if not re.fullmatch(r"[0-9a-f]{64}", values["minisign"]):
    raise SystemExit("error: minisign anchor is malformed")
records = [json.loads(line) for line in pathlib.Path(ndjson).read_text().splitlines() if line.strip()]
if len(records) != 2:
    raise SystemExit("error: fingerprint NDJSON must contain two records")
gpg = [r for r in records if r.get("fingerprint_scheme") == "openpgp-fingerprint-v1" and r.get("key_role") == "primary"]
mini = [r for r in records if r.get("fingerprint_scheme") == "minisign-public-blob-sha256-v1"]
if len(gpg) != 1 or len(mini) != 1:
    raise SystemExit("error: fingerprint NDJSON lacks the selected records")
if gpg[0].get("fingerprint") != values["gpg"] or mini[0].get("fingerprint") != values["minisign"]:
    raise SystemExit("error: fingerprint TXT and NDJSON disagree")
PYANCHOR
}

release_validate_tagger_env() {
    release_require_env SECLUSOR_TAGGER_NAME
    release_require_env SECLUSOR_TAGGER_EMAIL
    local expected_identity="3 Leaps Infosec Team <infosec@3leaps.net>"
    if [ -f "config/release/tagger-identity.txt" ]; then
        expected_identity="$(tr -d '\r\n' <config/release/tagger-identity.txt)"
    fi
    if [ "${SECLUSOR_TAGGER_NAME} <${SECLUSOR_TAGGER_EMAIL}>" != "${expected_identity}" ]; then
        echo "error: release tagger identity does not match the established signing identity" >&2
        return 1
    fi
    case "${SECLUSOR_TAGGER_NAME}" in
    *$'\n'* | *'<'* | *'>'*)
        echo "error: SECLUSOR_TAGGER_NAME contains an invalid character" >&2
        return 1
        ;;
    esac
    case "${SECLUSOR_TAGGER_EMAIL}" in
    *$'\n'* | *'<'* | *'>'* | *' '*)
        echo "error: SECLUSOR_TAGGER_EMAIL contains an invalid character" >&2
        return 1
        ;;
    esac
}

release_primary_records() {
    local listing="$1"
    printf '%s\n' "${listing}" | awk -F: '
        $1 == "sec" || $1 == "pub" {
            want_fingerprint = 1
            validity = $2
            expires = $7
            capabilities = $12
            next
        }
        want_fingerprint && $1 == "fpr" {
            print $10 "|" capabilities "|" validity "|" expires
            want_fingerprint = 0
        }
    '
}

release_matching_subkey_records() {
    local listing="$1"
    local selector="${SECLUSOR_PGP_KEY_ID%!}"
    printf '%s\n' "${listing}" | awk -F: -v selector="${selector}" '
        $1 == "sub" || $1 == "ssb" {
            want_fingerprint = 1
            validity = $2
            key_id = $5
            expires = $7
            capabilities = $12
            next
        }
        want_fingerprint && $1 == "fpr" {
            fingerprint = $10
            if (fingerprint == selector || key_id == selector) {
                print fingerprint "|" capabilities "|" validity "|" expires
            }
            want_fingerprint = 0
        }
    '
}

release_resolve_signing_subkey() {
    local listing="$1"
    local primary_records primary_count matching_records matching_count
    primary_records="$(release_primary_records "${listing}")"
    primary_count="$(printf '%s\n' "${primary_records}" | awk 'NF { count++ } END { print count + 0 }')"
    if [ "${primary_count}" -ne 1 ]; then
        echo "error: signing subkey selector does not resolve beneath exactly one primary key" >&2
        return 1
    fi

    local primary_fingerprint primary_capabilities primary_validity primary_expires
    IFS='|' read -r primary_fingerprint primary_capabilities primary_validity primary_expires <<<"${primary_records}"
    if [ "${primary_fingerprint}" != "${SECLUSOR_GPG_SIGNING_FINGERPRINT}" ]; then
        echo "error: selected signing subkey does not belong to the independently authorized primary fingerprint" >&2
        return 1
    fi
    release_validate_key_state "authorized primary key" \
        "${primary_capabilities}" "${primary_validity}" "${primary_expires}" || return 1

    matching_records="$(release_matching_subkey_records "${listing}")"
    matching_count="$(printf '%s\n' "${matching_records}" | awk 'NF { count++ } END { print count + 0 }')"
    if [ "${matching_count}" -ne 1 ]; then
        echo "error: signing subkey selector does not identify exactly one subkey" >&2
        return 1
    fi

    local subkey_fingerprint capabilities validity expires
    IFS='|' read -r subkey_fingerprint capabilities validity expires <<<"${matching_records}"
    if ! [[ "${capabilities}" =~ [sS] ]]; then
        echo "error: selected GPG subkey is not signing-capable" >&2
        return 1
    fi
    release_validate_key_state "selected GPG signing subkey" \
        "${capabilities}" "${validity}" "${expires}" || return 1

    printf '%s %s\n' "${subkey_fingerprint}" "${primary_fingerprint}"
}

release_validate_key_state() {
    local label="$1"
    local capabilities="$2"
    local validity="$3"
    local expires="$4"
    if [[ "${capabilities}" == *D* ]]; then
        echo "error: ${label} is disabled" >&2
        return 1
    fi
    case "${validity}" in
    r | e | d | i)
        echo "error: ${label} is revoked, expired, disabled, or invalid" >&2
        return 1
        ;;
    esac
    if [ -n "${expires}" ] && [ "${expires}" != "0" ]; then
        local now
        now="$(date +%s)"
        if ! [[ "${expires}" =~ ^[0-9]+$ ]] || [ "${expires}" -le "${now}" ]; then
            echo "error: ${label} is expired or has malformed expiry metadata" >&2
            return 1
        fi
    fi
}

release_key_uid_emails() {
    local listing="$1"
    printf '%s\n' "${listing}" |
        awk -F: '$1 == "uid" && $2 !~ /^[redi]$/ { print $10 }' |
        sed -n 's/.*<\([^<>]*\)>.*/\1/p'
}

release_validate_verification_env() {
    release_assert_tag_version || return 1
    release_configure_gpg || return 1
    release_validate_pgp_key_id || return 1
    release_validate_fingerprint || return 1
    release_assert_authorized_primary_anchor || return 1
    release_validate_tagger_env || return 1
    release_require_command gpg || return 1

    local public_listing
    public_listing="$(GNUPGHOME="${GNUPGHOME}" gpg --batch --with-colons \
        --fingerprint --with-subkey-fingerprint --list-keys \
        "${SECLUSOR_PGP_KEY_ID}" 2>/dev/null || true)"
    release_resolve_signing_subkey "${public_listing}" >/dev/null || return 1

    local uid_emails
    uid_emails="$(release_key_uid_emails "${public_listing}")"
    if ! grep -qxF "${SECLUSOR_TAGGER_EMAIL}" <<<"${uid_emails}"; then
        echo "error: SECLUSOR_TAGGER_EMAIL matches no UID on the configured signing key" >&2
        return 1
    fi
}

release_validate_signing_env() {
    release_validate_verification_env || return 1

    local secret_listing
    secret_listing="$(GNUPGHOME="${GNUPGHOME}" gpg --batch --with-colons \
        --fingerprint --with-subkey-fingerprint --list-secret-keys \
        "${SECLUSOR_PGP_KEY_ID}" 2>/dev/null || true)"
    release_resolve_signing_subkey "${secret_listing}" >/dev/null || return 1
}

release_setup_gpg_tty() {
    if [ ! -t 0 ] || [ ! -t 1 ]; then
        echo "error: release-tag requires an interactive terminal for GPG pinentry" >&2
        return 1
    fi

    export GPG_TTY
    GPG_TTY="$(tty)"
    if command -v gpg-connect-agent >/dev/null 2>&1; then
        gpg-connect-agent updatestartuptty /bye >/dev/null 2>&1 || true
    fi
}

release_assert_checkout() {
    release_assert_release_commit || return 1
    if [ "$(git branch --show-current)" != "main" ]; then
        echo "error: the release checkout must be on main" >&2
        return 1
    fi
    if [ -n "$(git status --porcelain)" ]; then
        echo "error: the release checkout must be clean" >&2
        return 1
    fi
    git fetch origin main
    local current_main
    current_main="$(git rev-parse origin/main)"
    readonly current_main
    if [ "$(git rev-parse HEAD)" != "${current_main}" ]; then
        echo "error: HEAD and origin/main must identify the same release commit" >&2
        return 1
    fi
    if [ "${SECLUSOR_RELEASE_COMMIT}" != "${current_main}" ]; then
        echo "error: HEAD and origin/main must equal SECLUSOR_RELEASE_COMMIT" >&2
        return 1
    fi
}

release_assert_tag_absent() {
    local tag remote_status
    while IFS= read -r tag; do
        if git rev-parse -q --verify "refs/tags/${tag}" >/dev/null; then
            echo "error: local tag ${tag} already exists" >&2
            return 1
        fi
        set +e
        git ls-remote --exit-code --tags origin "refs/tags/${tag}" >/dev/null 2>&1
        remote_status=$?
        set -e
        case "${remote_status}" in
        0)
            echo "error: remote tag ${tag} already exists" >&2
            return 1
            ;;
        2) ;;
        *)
            echo "error: unable to determine whether remote tag ${tag} exists" >&2
            return 1
            ;;
        esac
    done < <(release_tag_names)
}

release_validsig_fingerprints() {
    local verification="$1"
    local validsig count
    validsig="$(sed -n 's/^\[GNUPG:\] VALIDSIG //p' <<<"${verification}")"
    count="$(printf '%s\n' "${validsig}" | awk 'NF { count++ } END { print count + 0 }')"
    if [ "${count}" -ne 1 ]; then
        return 1
    fi
    awk '{ if (NF >= 10) print $1, $10; else print $1, $1 }' <<<"${validsig}"
}

release_verify_local_tag() {
    local tag="$1"
    local expected_oid="${2:-}"
    local expected_commit="${SECLUSOR_RELEASE_COMMIT}"
    local tag_oid current_oid tag_text tag_header object_type embedded_tag peeled_commit

    tag_oid="$(git rev-parse --verify --quiet "refs/tags/${tag}" 2>/dev/null || true)"
    if ! [[ "${tag_oid}" =~ ^[0-9a-f]{40}$ ]]; then
        echo "error: ${tag} must resolve to an annotated tag object" >&2
        return 1
    fi
    if [ -n "${expected_oid}" ]; then
        if ! [[ "${expected_oid}" =~ ^[0-9a-f]{40}$ ]] || [ "${tag_oid}" != "${expected_oid}" ]; then
            echo "error: local tag ref ${tag} moved before verification" >&2
            return 1
        fi
    fi

    object_type="$(git cat-file -t "${tag_oid}" 2>/dev/null || true)"
    if [ "${object_type}" != "tag" ]; then
        echo "error: ${tag} must resolve to an annotated tag object" >&2
        return 1
    fi
    tag_text="$(git cat-file tag "${tag_oid}")"
    tag_header="$(sed '/^$/q' <<<"${tag_text}")"

    local direct_objects direct_types
    direct_objects="$(sed -n 's/^object //p' <<<"${tag_header}")"
    direct_types="$(sed -n 's/^type //p' <<<"${tag_header}")"
    if [ "$(printf '%s\n' "${direct_objects}" | awk 'NF { count++ } END { print count + 0 }')" -ne 1 ] ||
        [ "${direct_objects}" != "${expected_commit}" ]; then
        echo "error: annotated tag must directly target the check-verified release commit" >&2
        return 1
    fi
    if [ "$(printf '%s\n' "${direct_types}" | awk 'NF { count++ } END { print count + 0 }')" -ne 1 ] ||
        [ "${direct_types}" != "commit" ]; then
        echo "error: annotated tag direct object type must be commit" >&2
        return 1
    fi

    embedded_tag="$(sed -n 's/^tag //p' <<<"${tag_header}")"
    if [ "${embedded_tag}" != "${tag}" ]; then
        echo "error: annotated tag object identity does not match ${tag}" >&2
        return 1
    fi
    if [ "$(grep -c '^-----BEGIN PGP SIGNATURE-----$' <<<"${tag_text}")" -ne 1 ] ||
        [ "$(grep -c '^-----END PGP SIGNATURE-----$' <<<"${tag_text}")" -ne 1 ]; then
        echo "error: annotated tag must contain exactly one OpenPGP signature" >&2
        return 1
    fi
    local tag_message
    tag_message="$(awk 'BEGIN { in_message = 0 } !in_message && NF == 0 { in_message = 1; next } in_message && /^-----BEGIN PGP SIGNATURE-----$/ { exit } in_message && NF { print }' <<<"${tag_text}")"
    if [ "${tag_message}" != "seclusor ${tag}" ]; then
        echo "error: signed tag message must equal the fixed public release text" >&2
        return 1
    fi

    local tagger_line tagger_name tagger_email
    tagger_line="$(sed -n 's/^tagger //p' <<<"${tag_header}")"
    # shellcheck disable=SC2001 # POSIX character-class match is clearer here.
    tagger_name="$(sed 's/ <[^<>]*> [0-9][0-9]* [+-][0-9][0-9][0-9][0-9]$//' <<<"${tagger_line}")"
    tagger_email="$(sed -n 's/^.* <\([^<>]*\)> [0-9][0-9]* [+-][0-9][0-9][0-9][0-9]$/\1/p' <<<"${tagger_line}")"
    if [ "${tagger_name}" != "${SECLUSOR_TAGGER_NAME}" ] ||
        [ "${tagger_email}" != "${SECLUSOR_TAGGER_EMAIL}" ]; then
        echo "error: signed tag tagger identity does not match the required release identity" >&2
        return 1
    fi

    local public_listing expected_fingerprints expected_subkey_fingerprint expected_primary_fingerprint
    public_listing="$(GNUPGHOME="${GNUPGHOME}" gpg --batch --with-colons \
        --fingerprint --with-subkey-fingerprint --list-keys \
        "${SECLUSOR_PGP_KEY_ID}" 2>/dev/null || true)"
    if ! expected_fingerprints="$(release_resolve_signing_subkey "${public_listing}")"; then
        return 1
    fi
    read -r expected_subkey_fingerprint expected_primary_fingerprint <<<"${expected_fingerprints}"

    local verification actual_fingerprints actual_subkey_fingerprint actual_primary_fingerprint
    if ! verification="$(GNUPGHOME="${GNUPGHOME}" git -c gpg.format=openpgp -c gpg.program=gpg verify-tag --raw "${tag_oid}" 2>&1)"; then
        printf '%s\n' "${verification}" >&2
        echo "error: tag signature verification failed" >&2
        return 1
    fi
    if grep -Eq '^\[GNUPG:\] (EXPKEYSIG|EXPSIG|REVKEYSIG|KEYEXPIRED|SIGEXPIRED) ' <<<"${verification}"; then
        echo "error: tag signature or signing key is expired or revoked" >&2
        return 1
    fi
    if ! grep -q '^\[GNUPG:\] GOODSIG ' <<<"${verification}"; then
        echo "error: signed tag has no GOODSIG result" >&2
        return 1
    fi
    actual_fingerprints="$(release_validsig_fingerprints "${verification}" || true)"
    read -r actual_subkey_fingerprint actual_primary_fingerprint <<<"${actual_fingerprints}"
    if [ "${actual_subkey_fingerprint}" != "${expected_subkey_fingerprint}" ]; then
        echo "error: tag signature was not made by the selected exact signing subkey" >&2
        return 1
    fi
    if [ "${actual_primary_fingerprint}" != "${SECLUSOR_GPG_SIGNING_FINGERPRINT}" ] ||
        [ "${expected_primary_fingerprint}" != "${SECLUSOR_GPG_SIGNING_FINGERPRINT}" ]; then
        echo "error: tag signature does not chain to the independently authorized primary fingerprint" >&2
        return 1
    fi

    peeled_commit="$(git rev-parse "${tag_oid}^{}" 2>/dev/null || true)"
    if [ "${peeled_commit}" != "${expected_commit}" ]; then
        echo "error: signed tag does not peel to the check-verified release commit" >&2
        return 1
    fi

    current_oid="$(git rev-parse --verify --quiet "refs/tags/${tag}" 2>/dev/null || true)"
    if [ "${current_oid}" != "${tag_oid}" ]; then
        echo "error: local tag ref ${tag} moved during verification" >&2
        return 1
    fi
}
