#!/usr/bin/env bash
# Exercise the signed-tag boundary using disposable keys and a local bare remote.
set -euo pipefail
unset GITHUB_ACTIONS GITHUB_TOKEN GH_TOKEN SECLUSOR_GITHUB_API

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/release-tag-common.sh
source "$ROOT/scripts/release-tag-common.sh"

if ! command -v gpg >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
    echo 'error: signed-tag controls require gpg and jq' >&2
    exit 1
fi

TEST_ROOT="$(mktemp -d /tmp/dtr-XXXXXX)"
trap 'rm -rf "$TEST_ROOT"' EXIT
TEST_REPO="$TEST_ROOT/repo"
TEST_REMOTE="$TEST_ROOT/remote.git"
TEST_GPG="$TEST_ROOT/gpg"
mkdir -m 700 "$TEST_GPG"

git init -q --bare "$TEST_REMOTE"
git init -q -b main "$TEST_REPO"
git -C "$TEST_REPO" config user.name 'Synthetic Release Test'
git -C "$TEST_REPO" config user.email 'synthetic@example.invalid'
mkdir -p "$TEST_REPO/keys"
printf '0.2.2\n' >"$TEST_REPO/VERSION"

export SECLUSOR_GPG_HOMEDIR="$TEST_GPG"
export SECLUSOR_RELEASE_TAG=v0.2.2
export SECLUSOR_TAGGER_NAME='3 Leaps Infosec Team'
export SECLUSOR_TAGGER_EMAIL='infosec@3leaps.net'

gpg --homedir "$TEST_GPG" --batch --pinentry-mode loopback --passphrase '' \
    --quick-gen-key '3 Leaps Infosec Team <infosec@3leaps.net>' ed25519 sign never >/dev/null 2>&1
primary="$(gpg --homedir "$TEST_GPG" --batch --with-colons --list-keys \
    'infosec@3leaps.net' | awk -F: '$1 == "fpr" { print $10; exit }')"
gpg --homedir "$TEST_GPG" --batch --pinentry-mode loopback --passphrase '' \
    --quick-add-key "$primary" ed25519 sign never >/dev/null 2>&1
subkey="$(gpg --homedir "$TEST_GPG" --batch --with-colons --list-keys \
    'infosec@3leaps.net' | awk -F: '$1 == "fpr" { n++; if (n == 2) { print $10; exit } }')"
if [ "${#primary}" -ne 40 ] || [ "${#subkey}" -ne 40 ]; then
    echo 'error: synthetic GPG identities are incomplete' >&2
    exit 1
fi
export SECLUSOR_PGP_KEY_ID="${subkey}!"
export SECLUSOR_GPG_SIGNING_FINGERPRINT="$primary"
write_anchors() {
    local fingerprint="$1" dir="$2"
    printf 'gpg %s\nminisign %064d\n' "$fingerprint" 0 >"$dir/expected-fingerprints.txt"
    printf '{"fingerprint_scheme":"openpgp-fingerprint-v1","key_role":"primary","fingerprint":"%s"}\n' "$fingerprint" >"$dir/expected-fingerprints.ndjson"
    printf '{"fingerprint_scheme":"minisign-public-blob-sha256-v1","fingerprint":"%064d"}\n' 0 >>"$dir/expected-fingerprints.ndjson"
}
write_anchors "$primary" "$TEST_REPO/keys"

git -C "$TEST_REPO" add VERSION keys/expected-fingerprints.txt keys/expected-fingerprints.ndjson
git -C "$TEST_REPO" commit -q -m 'Synthetic release fixture'
git -C "$TEST_REPO" remote add origin "$TEST_REMOTE"
git -C "$TEST_REPO" push -q -u origin main
cd "$TEST_REPO"
SECLUSOR_RELEASE_COMMIT="$(git rev-parse HEAD)"
export SECLUSOR_RELEASE_COMMIT

expect_fail() {
    local label="$1"
    shift
    if "$@" >/dev/null 2>&1; then
        echo "error: $label unexpectedly passed" >&2
        exit 1
    fi
}

release_validate_signing_env
release_assert_checkout
release_assert_tag_absent

(
    unset SECLUSOR_RELEASE_COMMIT
    expect_fail 'missing literal release commit' release_assert_checkout
)
SECLUSOR_RELEASE_COMMIT=HEAD expect_fail 'symbolic release commit' release_assert_checkout
SECLUSOR_RELEASE_COMMIT="$(printf '%040d' 0)" expect_fail 'wrong literal release commit' release_assert_checkout
SECLUSOR_RELEASE_COMMIT=short expect_fail 'short release commit' release_assert_checkout

SECLUSOR_RELEASE_TAG=v0.2.3 expect_fail 'tag/version mismatch' release_assert_tag_version
SECLUSOR_PGP_KEY_ID="$primary!" expect_fail 'primary used as subkey selector' release_validate_verification_env
SECLUSOR_PGP_KEY_ID="$subkey" expect_fail 'selector without exact bang' release_validate_verification_env
SECLUSOR_GPG_SIGNING_FINGERPRINT="$(printf '%040d' 0)" expect_fail 'wrong authorized primary' release_validate_verification_env
SECLUSOR_TAGGER_NAME='Wrong Tagger' expect_fail 'wrong tagger' release_validate_verification_env
SECLUSOR_TAGGER_EMAIL='wrong@example.invalid' expect_fail 'wrong tagger email' release_validate_verification_env
SECLUSOR_TAGGER_NAME=$'3 Leaps\nInfosec Team' expect_fail 'newline in tagger name' release_validate_verification_env
SECLUSOR_TAGGER_EMAIL='bad<email>@3leaps.net' expect_fail 'angle bracket in tagger email' release_validate_verification_env
SECLUSOR_GPG_HOMEDIR='' expect_fail 'missing GPG home' release_validate_verification_env
SECLUSOR_PGP_KEY_ID='' expect_fail 'missing key selector' release_validate_verification_env

gpg --homedir "$TEST_GPG" --batch --pinentry-mode loopback --passphrase '' \
    --quick-gen-key 'Old <old@example.invalid>' ed25519 sign never >/dev/null 2>&1
revoked_primary="$(gpg --homedir "$TEST_GPG" --batch --with-colons --list-keys \
    'old@example.invalid' | awk -F: '$1 == "fpr" { print $10; exit }')"
gpg --homedir "$TEST_GPG" --batch --pinentry-mode loopback --passphrase '' \
    --quick-add-key "$revoked_primary" ed25519 sign never >/dev/null 2>&1
revoked_subkey="$(gpg --homedir "$TEST_GPG" --batch --with-colons --list-keys \
    'old@example.invalid' | awk -F: '$1 == "fpr" { n++; if (n == 2) { print $10; exit } }')"
cp keys/expected-fingerprints.txt "$TEST_ROOT/anchor.good"
cp keys/expected-fingerprints.ndjson "$TEST_ROOT/anchor-ndjson.good"
write_anchors "$revoked_primary" keys
SECLUSOR_GPG_SIGNING_FINGERPRINT="$revoked_primary" SECLUSOR_PGP_KEY_ID="${revoked_subkey}!" \
    expect_fail 'matching UID is absent' release_validate_verification_env
gpg --homedir "$TEST_GPG" --batch --quick-add-uid "$revoked_primary" \
    'Team <infosec@3leaps.net>' >/dev/null 2>&1
gpg --homedir "$TEST_GPG" --batch --quick-revoke-uid "$revoked_primary" \
    'Team <infosec@3leaps.net>' >/dev/null 2>&1
SECLUSOR_GPG_SIGNING_FINGERPRINT="$revoked_primary" SECLUSOR_PGP_KEY_ID="${revoked_subkey}!" \
    expect_fail 'only matching UID is revoked' release_validate_verification_env
cp "$TEST_ROOT/anchor.good" keys/expected-fingerprints.txt
cp "$TEST_ROOT/anchor-ndjson.good" keys/expected-fingerprints.ndjson

expect_fail 'disabled primary state' release_validate_key_state primary s d 0
expect_fail 'expired subkey state' release_validate_key_state subkey s e 0
expect_fail 'past subkey expiry' release_validate_key_state subkey s u 1
expect_fail 'non-signing subkey' release_resolve_signing_subkey "$(printf 'pub:u:256:22:ABC:0:0:::::c:\nfpr:::::::::%s:\nsub:u:256:22:DEF:0:0:::::e:\nfpr:::::::::%s:\n' "$primary" "$subkey")"
expect_fail 'ambiguous signing subkey' release_resolve_signing_subkey "$(printf 'pub:u:256:22:ABC:0:0:::::c:\nfpr:::::::::%s:\nsub:u:256:22:DEF:0:0:::::s:\nfpr:::::::::%s:\nsub:u:256:22:DEF:0:0:::::s:\nfpr:::::::::%s:\n' "$primary" "$subkey" "$subkey")"

write_anchors "$(printf '%040d' 0)" keys
expect_fail 'committed anchor mismatch' release_validate_verification_env
cp "$TEST_ROOT/anchor.good" keys/expected-fingerprints.txt
cp "$TEST_ROOT/anchor-ndjson.good" keys/expected-fingerprints.ndjson
rm keys/expected-fingerprints.ndjson
expect_fail 'missing committed anchor' release_validate_verification_env
cp "$TEST_ROOT/anchor-ndjson.good" keys/expected-fingerprints.ndjson

expect_fail 'no interactive terminal' "$ROOT/scripts/release-tag.sh"
if git show-ref --verify --quiet refs/tags/v0.2.2; then
    echo 'error: noninteractive tag attempt created a tag' >&2
    exit 1
fi

# pty supplies a real terminal; the synthetic key is unprotected and cannot
# request a PIN. The release helper itself still refuses a missing terminal.
python3 - "$ROOT/scripts/release-tag.sh" <<'PY'
import os, pty, sys
status = pty.spawn([sys.argv[1]])
if os.waitstatus_to_exitcode(status) != 0:
    raise SystemExit('synthetic signed-tag creation failed')
PY

release_verify_local_tag v0.2.2
"$ROOT/scripts/release-verify-tag.sh" >/dev/null
"$ROOT/scripts/release-guard-signing-env.sh" >/dev/null
if git --git-dir="$TEST_REMOTE" show-ref --verify --quiet refs/tags/v0.2.2; then
    echo 'error: release-tag pushed the synthetic tag' >&2
    exit 1
fi
expect_fail 'existing local tag' release_assert_tag_absent
git tag -d bindings/go/seclusor/v0.2.2 >/dev/null

# A new signed object with an unexpected public message cannot be accepted.
git tag -d v0.2.2 >/dev/null
GIT_COMMITTER_NAME="$SECLUSOR_TAGGER_NAME" GIT_COMMITTER_EMAIL="$SECLUSOR_TAGGER_EMAIL" \
    GNUPGHOME="$TEST_GPG" git tag -s -a -u "$SECLUSOR_PGP_KEY_ID" \
    -m 'unexpected release message' v0.2.2 "$SECLUSOR_RELEASE_COMMIT"
expect_fail 'unexpected signed tag message' release_verify_local_tag v0.2.2
git tag -d v0.2.2 >/dev/null

git tag v0.2.2 "$SECLUSOR_RELEASE_COMMIT"
expect_fail 'lightweight tag object' release_verify_local_tag v0.2.2
git tag -d v0.2.2 >/dev/null

GIT_COMMITTER_NAME='Wrong Tagger' GIT_COMMITTER_EMAIL="$SECLUSOR_TAGGER_EMAIL" \
    GNUPGHOME="$TEST_GPG" git tag -s -a -u "$SECLUSOR_PGP_KEY_ID" \
    -m 'seclusor v0.2.2' v0.2.2 "$SECLUSOR_RELEASE_COMMIT"
expect_fail 'wrong tag object tagger' release_verify_local_tag v0.2.2
git tag -d v0.2.2 >/dev/null

alternate_commit="$(git commit-tree 'HEAD^{tree}' -p HEAD -m 'Alternate synthetic target')"
GIT_COMMITTER_NAME="$SECLUSOR_TAGGER_NAME" GIT_COMMITTER_EMAIL="$SECLUSOR_TAGGER_EMAIL" \
    GNUPGHOME="$TEST_GPG" git tag -s -a -u "$SECLUSOR_PGP_KEY_ID" \
    -m 'seclusor v0.2.2' v0.2.2 "$alternate_commit"
expect_fail 'tag targets another commit' release_verify_local_tag v0.2.2
git tag -d v0.2.2 >/dev/null

GIT_COMMITTER_NAME="$SECLUSOR_TAGGER_NAME" GIT_COMMITTER_EMAIL="$SECLUSOR_TAGGER_EMAIL" \
    GNUPGHOME="$TEST_GPG" git tag -s -a -u "${primary}!" \
    -m 'seclusor v0.2.2' v0.2.2 "$SECLUSOR_RELEASE_COMMIT"
expect_fail 'tag signed by primary instead of selected subkey' release_verify_local_tag v0.2.2
git tag -d v0.2.2 >/dev/null

gpg --homedir "$TEST_GPG" --batch --pinentry-mode loopback --passphrase '' \
    --quick-add-key "$primary" ed25519 sign never >/dev/null 2>&1
other_subkey="$(gpg --homedir "$TEST_GPG" --batch --with-colons --list-keys \
    'infosec@3leaps.net' | awk -F: '$1 == "fpr" { n++; if (n == 3) { print $10; exit } }')"
if [ "${#other_subkey}" -ne 40 ] || [ "$other_subkey" = "$subkey" ]; then
    echo 'error: second synthetic signing subkey is incomplete' >&2
    exit 1
fi
GIT_COMMITTER_NAME="$SECLUSOR_TAGGER_NAME" GIT_COMMITTER_EMAIL="$SECLUSOR_TAGGER_EMAIL" \
    GNUPGHOME="$TEST_GPG" git tag -s -a -u "${other_subkey}!" \
    -m 'seclusor v0.2.2' v0.2.2 "$SECLUSOR_RELEASE_COMMIT"
expect_fail 'wrong signing subkey' release_verify_local_tag v0.2.2
git tag -d v0.2.2 >/dev/null

GIT_COMMITTER_NAME="$SECLUSOR_TAGGER_NAME" GIT_COMMITTER_EMAIL="$SECLUSOR_TAGGER_EMAIL" \
    GNUPGHOME="$TEST_GPG" git tag -s -a -u "$SECLUSOR_PGP_KEY_ID" \
    -m 'seclusor v0.2.2' v0.2.2 "$SECLUSOR_RELEASE_COMMIT"

# The Go module tag has the same signer, message discipline, and direct target.
GIT_COMMITTER_NAME="$SECLUSOR_TAGGER_NAME" GIT_COMMITTER_EMAIL="$SECLUSOR_TAGGER_EMAIL" \
    GNUPGHOME="$TEST_GPG" git tag -s -a -u "$SECLUSOR_PGP_KEY_ID" \
    -m 'seclusor bindings/go/seclusor/v0.2.2' \
    bindings/go/seclusor/v0.2.2 "$SECLUSOR_RELEASE_COMMIT"
release_verify_local_tag bindings/go/seclusor/v0.2.2

# Tamper with a signed tag object while preserving its header and message.
original_tag_object="$(git rev-parse refs/tags/v0.2.2)"
git cat-file tag "$original_tag_object" >"$TEST_ROOT/tag.original"
python3 - "$TEST_ROOT/tag.original" "$TEST_ROOT/tag.tampered" <<'PYTAG'
from pathlib import Path
import sys
raw = Path(sys.argv[1]).read_bytes()
lines = raw.splitlines(keepends=True)
marker = b'-----BEGIN PGP SIGNATURE-----'
start = next(i for i, line in enumerate(lines) if line.rstrip(b'\r\n') == marker)
base64 = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
for i in range(start + 1, len(lines)):
    payload = lines[i].rstrip(b'\r\n')
    if len(payload) >= 16 and all(byte in base64 for byte in payload):
        replacement = b'A' if payload[0] != ord('A') else b'B'
        lines[i] = replacement + lines[i][1:]
        break
else:
    raise SystemExit('synthetic signature fixture has no base64 payload')
Path(sys.argv[2]).write_bytes(b''.join(lines))
PYTAG
tampered_tag_object="$(git hash-object -t tag -w "$TEST_ROOT/tag.tampered")"
git update-ref refs/tags/v0.2.2 "$tampered_tag_object"
expect_fail 'tampered tag signature' release_verify_local_tag v0.2.2
git update-ref refs/tags/v0.2.2 "$original_tag_object"
release_verify_local_tag v0.2.2

python3 - "$TEST_ROOT/tag.original" "$TEST_ROOT/tag.double" <<'PYDOUBLE'
from pathlib import Path
import sys
raw = Path(sys.argv[1]).read_bytes()
marker = b'-----BEGIN PGP SIGNATURE-----'
start = raw.index(marker)
Path(sys.argv[2]).write_bytes(raw + b'\n' + raw[start:])
PYDOUBLE
double_tag_object="$(git hash-object -t tag -w "$TEST_ROOT/tag.double")"
git update-ref refs/tags/v0.2.2 "$double_tag_object"
expect_fail 'multiple signature blocks' release_verify_local_tag v0.2.2
git update-ref refs/tags/v0.2.2 "$original_tag_object"
release_verify_local_tag v0.2.2

# Stub GitHub only; the repository, remote, and signed tag objects remain real
# disposable fixtures. The stub reads each tag object, including the Go tag.
mkdir -p "$TEST_ROOT/bin"
cat >"$TEST_ROOT/bin/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[ "$1" = api ] || exit 1
case "$2" in
  *git/ref/tags/*)
    tag="${2#*git/ref/tags/}"
    object="$(git rev-parse "refs/tags/${tag}")"
    if [ "${GH_REF_MODE:-good}" = wrong ]; then object="$(printf '%040d' 0)"; fi
    jq -n --arg sha "$object" '{object:{type:"tag",sha:$sha}}'
    ;;
  *git/tags/*)
    object="${2##*/}"
    tag="$(git cat-file tag "$object" | sed -n 's/^tag //p' | head -1)"
    commit="$(git cat-file tag "$object" | sed -n 's/^object //p' | head -1)"
    if [ "${GH_VERIFICATION_MODE:-good}" = bad ]; then
      jq -n --arg tag "$tag" --arg sha "$commit" \
        --arg name "$SECLUSOR_TAGGER_NAME" --arg email "$SECLUSOR_TAGGER_EMAIL" \
        '{tag:$tag,object:{type:"commit",sha:$sha},tagger:{name:$name,email:$email},verification:{verified:false,reason:"unknown_key"}}'
    elif [ "${GH_VERIFICATION_MODE:-good}" = bad_reason ]; then
      jq -n --arg tag "$tag" --arg sha "$commit" \
        --arg name "$SECLUSOR_TAGGER_NAME" --arg email "$SECLUSOR_TAGGER_EMAIL" \
        '{tag:$tag,object:{type:"commit",sha:$sha},tagger:{name:$name,email:$email},verification:{verified:true,reason:"gpgverify_unavailable"}}'
    else
      jq -n --arg tag "$tag" --arg sha "$commit" \
        --arg name "$SECLUSOR_TAGGER_NAME" --arg email "$SECLUSOR_TAGGER_EMAIL" \
        '{tag:$tag,object:{type:"commit",sha:$sha},tagger:{name:$name,email:$email},verification:{verified:true,reason:"valid"}}'
    fi
    ;;
  *) exit 1 ;;
esac
SH
chmod +x "$TEST_ROOT/bin/gh"
# An update hook rejects only the Go ref. Without --atomic, the other ref
# could still land; with --atomic, neither tag may appear on the remote.
cat >"$TEST_REMOTE/hooks/update" <<'SH'
#!/usr/bin/env bash
[ "$1" != 'refs/tags/bindings/go/seclusor/v0.2.2' ]
SH
chmod +x "$TEST_REMOTE/hooks/update"
PATH="$TEST_ROOT/bin:$PATH" expect_fail 'atomic push rejects partial tag pair' \
    "$ROOT/scripts/release-push-tag.sh"
if git --git-dir="$TEST_REMOTE" show-ref --verify --quiet refs/tags/v0.2.2 ||
    git --git-dir="$TEST_REMOTE" show-ref --verify --quiet refs/tags/bindings/go/seclusor/v0.2.2; then
    echo 'error: rejected atomic push left a remote tag' >&2
    exit 1
fi
rm "$TEST_REMOTE/hooks/update"

# Discriminating ref-swap controls on release-push-tag.sh:
# 1) Early swaps (during verify-tag or ls-remote) must be refused as observed ref
#    movement with zero remote refs published.
# 2) Late swap (immediately before real `git push`, after shell-level checks) must
#    never change the bytes published because push uses immutable OID:refs/tags/...
verified_main_tag_oid="$(git rev-parse refs/tags/v0.2.2)"
verified_go_tag_oid="$(git rev-parse refs/tags/bindings/go/seclusor/v0.2.2)"
verified_main_tag_bytes="$TEST_ROOT/verified-main-tag.raw"
verified_go_tag_bytes="$TEST_ROOT/verified-go-tag.raw"
git cat-file tag "$verified_main_tag_oid" >"$verified_main_tag_bytes"
git cat-file tag "$verified_go_tag_oid" >"$verified_go_tag_bytes"

cat >"$TEST_ROOT/tag.replacement" <<EOF
object ${alternate_commit}
type commit
tag v0.2.2
tagger Fake Tagger <fake@example.invalid> 1700000000 +0000

unverified replacement tag
EOF
replacement_tag_oid="$(git hash-object -t tag -w "$TEST_ROOT/tag.replacement")"

real_git="$(command -v git)"
mkdir -p "$TEST_ROOT/swap-bin"
cat >"$TEST_ROOT/swap-bin/git" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
sub=""
for arg in "$@"; do
    case "$arg" in
        -c|-C|--git-dir|--work-tree)
            sub="skip_next"
            continue
            ;;
        -*)
            continue
            ;;
        *)
            if [ "$sub" = "skip_next" ]; then
                sub=""
                continue
            fi
            sub="$arg"
            break
            ;;
    esac
done

if [ "${SWAP_STAGE:-}" = "verify-tag" ] && [ "$sub" = "verify-tag" ] && [ ! -e "$SWAP_MARKER" ]; then
    "$REAL_GIT" "$@"
    rc=$?
    : >"$SWAP_MARKER"
    "$REAL_GIT" -C "$SWAP_REPO" update-ref refs/tags/v0.2.2 "$REPLACEMENT_TAG_OID"
    exit "$rc"
fi

if [ "${SWAP_STAGE:-}" = "ls-remote" ] && [ "$sub" = "ls-remote" ] && [ ! -e "$SWAP_MARKER" ]; then
    : >"$SWAP_MARKER"
    "$REAL_GIT" -C "$SWAP_REPO" update-ref refs/tags/v0.2.2 "$REPLACEMENT_TAG_OID"
fi

if [ "${SWAP_STAGE:-}" = "ls-remote-second" ] && [ "$sub" = "ls-remote" ] && [ ! -e "$SWAP_MARKER" ]; then
    case "$*" in
        *bindings/go/seclusor/*)
            : >"$SWAP_MARKER"
            "$REAL_GIT" -C "$SWAP_REPO" update-ref refs/tags/v0.2.2 "$REPLACEMENT_TAG_OID"
            ;;
    esac
fi

if [ "${SWAP_STAGE:-}" = "push" ] && [ "$sub" = "push" ] && [ ! -e "$SWAP_MARKER" ]; then
    : >"$SWAP_MARKER"
    "$REAL_GIT" -C "$SWAP_REPO" update-ref refs/tags/v0.2.2 "$REPLACEMENT_TAG_OID"
fi

exec "$REAL_GIT" "$@"
SH
chmod +x "$TEST_ROOT/swap-bin/git"

for stage in verify-tag ls-remote ls-remote-second; do
    rm -f "$TEST_ROOT/swap.fired"
    SWAP_STAGE="$stage" SWAP_MARKER="$TEST_ROOT/swap.fired" SWAP_REPO="$TEST_REPO" \
        REPLACEMENT_TAG_OID="$replacement_tag_oid" REAL_GIT="$real_git" \
        PATH="$TEST_ROOT/swap-bin:$TEST_ROOT/bin:$PATH" \
        expect_fail "observed ref swap during ${stage}" "$ROOT/scripts/release-push-tag.sh"
    [ -e "$TEST_ROOT/swap.fired" ]
    [ "$(git rev-parse refs/tags/v0.2.2)" = "$replacement_tag_oid" ]
    if git --git-dir="$TEST_REMOTE" show-ref --verify --quiet refs/tags/v0.2.2 ||
        git --git-dir="$TEST_REMOTE" show-ref --verify --quiet refs/tags/bindings/go/seclusor/v0.2.2; then
        echo "error: observed ref swap (${stage}) published a remote tag" >&2
        exit 1
    fi
    git update-ref refs/tags/v0.2.2 "$verified_main_tag_oid"
done

rm -f "$TEST_ROOT/swap.fired"
SWAP_STAGE=push SWAP_MARKER="$TEST_ROOT/swap.fired" SWAP_REPO="$TEST_REPO" \
    REPLACEMENT_TAG_OID="$replacement_tag_oid" REAL_GIT="$real_git" \
    PATH="$TEST_ROOT/swap-bin:$TEST_ROOT/bin:$PATH" \
    "$ROOT/scripts/release-push-tag.sh" >/dev/null
[ -e "$TEST_ROOT/swap.fired" ]
[ "$(git rev-parse refs/tags/v0.2.2)" = "$replacement_tag_oid" ]
[ "$(git --git-dir="$TEST_REMOTE" rev-parse refs/tags/v0.2.2)" = "$verified_main_tag_oid" ]
[ "$(git --git-dir="$TEST_REMOTE" rev-parse refs/tags/bindings/go/seclusor/v0.2.2)" = "$verified_go_tag_oid" ]
git --git-dir="$TEST_REMOTE" cat-file tag refs/tags/v0.2.2 >"$TEST_ROOT/remote-main-tag.raw"
git --git-dir="$TEST_REMOTE" cat-file tag refs/tags/bindings/go/seclusor/v0.2.2 >"$TEST_ROOT/remote-go-tag.raw"
cmp -s "$verified_main_tag_bytes" "$TEST_ROOT/remote-main-tag.raw"
cmp -s "$verified_go_tag_bytes" "$TEST_ROOT/remote-go-tag.raw"

git update-ref refs/tags/v0.2.2 "$verified_main_tag_oid"
git --git-dir="$TEST_REMOTE" update-ref -d refs/tags/v0.2.2
git --git-dir="$TEST_REMOTE" update-ref -d refs/tags/bindings/go/seclusor/v0.2.2

PATH="$TEST_ROOT/bin:$PATH" "$ROOT/scripts/release-push-tag.sh" >/dev/null
git --git-dir="$TEST_REMOTE" show-ref --verify --quiet refs/tags/v0.2.2
git --git-dir="$TEST_REMOTE" show-ref --verify --quiet refs/tags/bindings/go/seclusor/v0.2.2
if [ "$(git --git-dir="$TEST_REMOTE" rev-parse refs/heads/main)" != "$SECLUSOR_RELEASE_COMMIT" ]; then
    echo 'error: tag push changed remote main' >&2
    exit 1
fi
PATH="$TEST_ROOT/bin:$PATH" expect_fail 'existing pushed tags' "$ROOT/scripts/release-push-tag.sh"
PATH="$TEST_ROOT/bin:$PATH" "$ROOT/scripts/release-verify-remote-tag.sh" >/dev/null
GH_VERIFICATION_MODE=bad PATH="$TEST_ROOT/bin:$PATH" expect_fail 'remote unknown key' "$ROOT/scripts/release-verify-remote-tag.sh"
GH_VERIFICATION_MODE=bad_reason PATH="$TEST_ROOT/bin:$PATH" \
    expect_fail 'remote verified with non-valid reason' "$ROOT/scripts/release-verify-remote-tag.sh"
GH_REF_MODE=wrong PATH="$TEST_ROOT/bin:$PATH" expect_fail 'remote tag-object mismatch' "$ROOT/scripts/release-verify-remote-tag.sh"

printf 'dirty\n' >dirty.txt
expect_fail 'dirty checkout' release_assert_checkout
rm dirty.txt
git switch -q -c another
expect_fail 'non-main checkout' release_assert_checkout
git switch -q main
printf 'drift\n' >drift.txt
git add drift.txt
git commit -q -m 'Synthetic remote drift'
expect_fail 'HEAD not equal origin/main' release_assert_checkout
git push -q origin main
git tag -d v0.2.2 bindings/go/seclusor/v0.2.2 >/dev/null
expect_fail 'existing remote tag' release_assert_tag_absent

# Decernor ceremony resolution is explicit and enforces the minimum version.
# The binaries below are synthetic shims; no real key material is read.
# shellcheck source=scripts/release-decernor.sh
source "$ROOT/scripts/release-decernor.sh"
SECLUSOR_DECERNOR_BIN='' expect_fail 'missing ceremony decernor' release_resolve_decernor ceremony
cat >"$TEST_ROOT/bin/decernor-old" <<'SH'
#!/usr/bin/env bash
printf 'Version: 0.1.7\nCommit: 0123456\n'
SH
cat >"$TEST_ROOT/bin/decernor-good" <<'SH'
#!/usr/bin/env bash
printf 'Version: 0.1.8\nCommit: 0123456\n'
SH
chmod +x "$TEST_ROOT/bin/decernor-old" "$TEST_ROOT/bin/decernor-good"
SECLUSOR_DECERNOR_BIN='' DECERNOR_BIN="$TEST_ROOT/bin/decernor-good" \
    expect_fail 'ceremony rejects DECERNOR_BIN fallback' release_resolve_decernor ceremony
SECLUSOR_DECERNOR_BIN="$TEST_ROOT/bin/decernor-old" expect_fail 'decernor below 0.1.8' release_resolve_decernor ceremony
SECLUSOR_DECERNOR_BIN="$TEST_ROOT/bin/decernor-good" release_resolve_decernor ceremony >/dev/null
SECLUSOR_DECERNOR_BIN=relative/decernor DECERNOR_BIN="$TEST_ROOT/bin/decernor-good" \
    expect_fail 'explicit relative decernor is terminal' release_resolve_decernor optional
SECLUSOR_DECERNOR_BIN="$TEST_ROOT/bin/decernor-old" DECERNOR_BIN="$TEST_ROOT/bin/decernor-good" \
    expect_fail 'explicit old decernor is terminal' release_resolve_decernor optional
SECLUSOR_DECERNOR_BIN='' DECERNOR_BIN="$TEST_ROOT/bin/decernor-good" release_resolve_decernor optional >/dev/null
ln -s "$TEST_ROOT/bin/decernor-good" "$TEST_ROOT/bin/decernor"
SECLUSOR_DECERNOR_BIN='' DECERNOR_BIN='' PATH="$TEST_ROOT/bin:$PATH" release_resolve_decernor optional >/dev/null

# A copied production verifier in a disposable fixture checks committed-vs-
# staged anchors. No real public or private key is needed for these failures.
fixture="$TEST_ROOT/fixture"
mkdir -p "$fixture/scripts" "$fixture/keys" "$TEST_ROOT/release"
cp "$ROOT/scripts/verify-public-keys.sh" "$ROOT/scripts/release-decernor.sh" "$fixture/scripts/"
write_anchors "$primary" "$fixture/keys"
printf 'public\n' >"$TEST_ROOT/release/minisign.pub"
printf '%s\n' '-----BEGIN PGP PUBLIC KEY BLOCK-----' >"$TEST_ROOT/release/release-key.asc"
printf 'stale\n' >"$TEST_ROOT/release/expected-fingerprints.txt"
printf '{}\n' >"$TEST_ROOT/release/expected-fingerprints.ndjson"
SECLUSOR_DECERNOR_BIN='' DECERNOR_BIN="$TEST_ROOT/bin/decernor-good" \
    expect_fail 'ceremony key verify refuses fallback' \
    "$fixture/scripts/verify-public-keys.sh" "$TEST_ROOT/release"
SECLUSOR_DECERNOR_BIN="$TEST_ROOT/bin/decernor-good" expect_fail 'stale staged anchors' \
    "$fixture/scripts/verify-public-keys.sh" "$TEST_ROOT/release"
cp "$fixture/keys/expected-fingerprints.txt" "$TEST_ROOT/release/expected-fingerprints.txt"
cp "$fixture/keys/expected-fingerprints.ndjson" "$TEST_ROOT/release/expected-fingerprints.ndjson"
printf 'synthetic binary\n' >"$TEST_ROOT/release/seclusor-test"
"$ROOT/scripts/generate-checksums.sh" "$TEST_ROOT/release" >/dev/null
if ! grep -q 'expected-fingerprints.txt' "$TEST_ROOT/release/SHA256SUMS" ||
    ! grep -q 'expected-fingerprints.ndjson' "$TEST_ROOT/release/SHA512SUMS"; then
    echo 'error: signed checksum set omits an anchor' >&2
    exit 1
fi
rm "$TEST_ROOT/release/expected-fingerprints.ndjson"
expect_fail 'checksum generation requires both anchors' \
    "$ROOT/scripts/generate-checksums.sh" "$TEST_ROOT/release"

# The public-anchor pair installer restores both prior files on a handled
# second-install failure or TERM, and removes both when no prior pair exists.
pair_stage="$TEST_ROOT/pair-stage"
mkdir -p "$pair_stage"
printf 'new ndjson\n' >"$pair_stage/expected-fingerprints.ndjson"
printf 'new txt\n' >"$pair_stage/expected-fingerprints.txt"
for failure in SECLUSOR_TEST_FAIL_SECOND SECLUSOR_TEST_KILL_AFTER_FIRST; do
    for prior in existing absent; do
        pair_dest="$TEST_ROOT/pair-${failure}-${prior}"
        mkdir -p "$pair_dest"
        if [ "$prior" = existing ]; then
            printf 'old ndjson\n' >"$pair_dest/expected-fingerprints.ndjson"
            printf 'old txt\n' >"$pair_dest/expected-fingerprints.txt"
        fi
        expect_fail "pair rollback $failure $prior" env "$failure=1" \
            "$ROOT/scripts/atomic-install-pin-pair.sh" "$pair_stage" "$pair_dest"
        if [ "$prior" = existing ]; then
            [ "$(cat "$pair_dest/expected-fingerprints.ndjson")" = 'old ndjson' ]
            [ "$(cat "$pair_dest/expected-fingerprints.txt")" = 'old txt' ]
        else
            [ ! -e "$pair_dest/expected-fingerprints.ndjson" ]
            [ ! -e "$pair_dest/expected-fingerprints.txt" ]
        fi
        if find "$pair_dest" -maxdepth 1 -type f \
            \( -name '*.new' -o -name '*.bak' \) | grep -q .; then
            echo "error: pair rollback left staging residue ($failure $prior)" >&2
            exit 1
        fi
    done
done

# ---------------------------------------------------------------------------
# Workflow pin + read-only policy controls (release-workflow-pin.py)
# ---------------------------------------------------------------------------
(cd "$ROOT" && python3 -B -E scripts/release-workflow-pin.py check >/dev/null)

wf_repo="$TEST_ROOT/wf-repo"
git init -q -b main "$wf_repo"
mkdir -p "$wf_repo/.github/workflows" "$wf_repo/config/release" "$wf_repo/scripts"
cp "$ROOT/scripts/release-workflow-pin.py" "$wf_repo/scripts/"
cat >"$wf_repo/.github/workflows/release.yml" <<'YAML'
name: release
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
YAML
(cd "$wf_repo" && python3 -B -E scripts/release-workflow-pin.py write >/dev/null)
cp "$wf_repo/.github/workflows/release.yml" "$TEST_ROOT/release.yml.good"
cp "$wf_repo/config/release/release-workflow.sha256" "$TEST_ROOT/release-workflow.sha256.good"

printf '\n# unreviewed edit\n' >>"$wf_repo/.github/workflows/release.yml"
(cd "$wf_repo" && expect_fail 'workflow digest drift' python3 -B -E scripts/release-workflow-pin.py check)
cp "$TEST_ROOT/release.yml.good" "$wf_repo/.github/workflows/release.yml"

sed 's/contents: read/contents: write/' "$TEST_ROOT/release.yml.good" >"$wf_repo/.github/workflows/release.yml"
(cd "$wf_repo" && expect_fail 'write permissions rejected' python3 -B -E scripts/release-workflow-pin.py write)

sed 's/@3d3c42e5aac5ba805825da76410c181273ba90b1/@v7/' "$TEST_ROOT/release.yml.good" >"$wf_repo/.github/workflows/release.yml"
(cd "$wf_repo" && expect_fail 'floating action tag rejected' python3 -B -E scripts/release-workflow-pin.py write)

sed 's/@3d3c42e5aac5ba805825da76410c181273ba90b1/@11d5960a326750d5838078e36cf38b85af677262/' "$TEST_ROOT/release.yml.good" >"$wf_repo/.github/workflows/release.yml"
(cd "$wf_repo" && expect_fail 'retired node20 action sha rejected' python3 -B -E scripts/release-workflow-pin.py write)

sed 's/persist-credentials: false/persist-credentials: true/' "$TEST_ROOT/release.yml.good" >"$wf_repo/.github/workflows/release.yml"
(cd "$wf_repo" && expect_fail 'missing persist-credentials false rejected' python3 -B -E scripts/release-workflow-pin.py write)

sed 's/ubuntu-24.04/ubuntu-latest/' "$TEST_ROOT/release.yml.good" >"$wf_repo/.github/workflows/release.yml"
(cd "$wf_repo" && expect_fail 'floating runner label rejected' python3 -B -E scripts/release-workflow-pin.py write)

cat >"$wf_repo/.github/workflows/release.yml" <<'YAML'
name: release
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-24.04
    container:
      image: ghcr.io/fulmenhq/goneat-tools-runner-glibc:v0.5.6
    steps:
      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
YAML
(cd "$wf_repo" && expect_fail 'unpinned container digest rejected' python3 -B -E scripts/release-workflow-pin.py write)

cat >"$wf_repo/.github/workflows/release.yml" <<'YAML'
name: release
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-24.04
    services:
      cache:
        image: alpine:latest
    steps:
      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
YAML
(cd "$wf_repo" && expect_fail 'unpinned service container digest rejected' python3 -B -E scripts/release-workflow-pin.py write)

cat >"$wf_repo/.github/workflows/release.yml" <<'YAML'
name: release
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
      - name: Mutate release
        run: gh release create v0.2.2 --draft
YAML
(cd "$wf_repo" && expect_fail 'release mutation token rejected' python3 -B -E scripts/release-workflow-pin.py write)

cat >"$wf_repo/.github/workflows/release.yml" <<'YAML'
name: release
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - name: Malformed flow sequence
        run: [echo safe
YAML
(cd "$wf_repo" && expect_fail 'malformed flow sequence rejected' python3 -B -E scripts/release-workflow-pin.py write)

cat >"$wf_repo/.github/workflows/release.yml" <<'YAML'
name: release
on:
  push:
    tags: ["v*"]
<<: {permissions: {contents: write}}
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
YAML
(cd "$wf_repo" && expect_fail 'yaml merge key rejected' python3 -B -E scripts/release-workflow-pin.py write)

cat >"$wf_repo/.github/workflows/release.yml" <<'YAML'
name: release
on:
  push:
    tags: ["v*"]
"<<": {permissions: {contents: write}}
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - name: Checkout
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with:
          persist-credentials: false
YAML
(cd "$wf_repo" && expect_fail 'quoted yaml merge key rejected' python3 -B -E scripts/release-workflow-pin.py write)

cat >"$wf_repo/.github/workflows/release.yml" <<'YAML'
name: release
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - name: Unreviewed local action
        uses: ./unreviewed-action
YAML
(cd "$wf_repo" && expect_fail 'local action outside .github/actions rejected' python3 -B -E scripts/release-workflow-pin.py write)

cat >"$wf_repo/.github/workflows/release.yml" <<'YAML'
name: release
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - name: Missing local action
        uses: ./.github/actions/missing
YAML
(cd "$wf_repo" && expect_fail 'missing local action rejected' python3 -B -E scripts/release-workflow-pin.py write)

mkdir -p "$wf_repo/.github/actions/helper"
cat >"$wf_repo/.github/workflows/release.yml" <<'YAML'
name: release
on:
  push:
    tags: ["v*"]
permissions:
  contents: read
jobs:
  verify:
    runs-on: ubuntu-24.04
    steps:
      - name: Helper action
        uses: ./.github/actions/helper
YAML
cat >"$wf_repo/.github/actions/helper/action.yml" <<'YAML'
name: helper
runs:
  using: composite
  steps:
    - name: Unpinned checkout
      uses: actions/checkout@v4
YAML
(cd "$wf_repo" && expect_fail 'unpinned step inside composite local action rejected' python3 -B -E scripts/release-workflow-pin.py write)

cat >"$wf_repo/.github/actions/helper/action.yml" <<'YAML'
name: helper
runs:
  using: composite
  steps:
    - name: Pinned checkout
      uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
      with:
        persist-credentials: false
YAML
(cd "$wf_repo" && python3 -B -E scripts/release-workflow-pin.py write >/dev/null)
rm -rf "$wf_repo/.github/actions"

cp "$TEST_ROOT/release.yml.good" "$wf_repo/.github/workflows/release.yml"
cp "$TEST_ROOT/release-workflow.sha256.good" "$wf_repo/config/release/release-workflow.sha256"

# ---------------------------------------------------------------------------
# Pinned dual-tag verification + tag-ref restoration controls
# ---------------------------------------------------------------------------
pin_gpg="$TEST_ROOT/pin-gpg"
pin_repo="$TEST_ROOT/pin-repo"
pin_remote="$TEST_ROOT/pin-remote.git"
mkdir -m 700 "$pin_gpg"
git init -q --bare "$pin_remote"
git init -q -b main "$pin_repo"
git -C "$pin_repo" config user.name 'Synthetic Release Test'
git -C "$pin_repo" config user.email 'synthetic@example.invalid'

gpg --homedir "$pin_gpg" --batch --pinentry-mode loopback --passphrase '' \
    --quick-gen-key '3 Leaps Infosec Team <infosec@3leaps.net>' ed25519 cert never >/dev/null 2>&1
pin_primary="$(gpg --homedir "$pin_gpg" --batch --with-colons --list-keys \
    'infosec@3leaps.net' | awk -F: '$1 == "fpr" { print $10; exit }')"
gpg --homedir "$pin_gpg" --batch --pinentry-mode loopback --passphrase '' \
    --quick-add-key "$pin_primary" ed25519 sign never >/dev/null 2>&1
pin_subkey="$(gpg --homedir "$pin_gpg" --batch --with-colons --list-keys \
    'infosec@3leaps.net' | awk -F: '$1 == "fpr" { n++; if (n == 2) { print $10; exit } }')"

mkdir -p "$pin_repo/docs/security" "$pin_repo/keys" "$pin_repo/config/release" \
    "$pin_repo/.github/workflows" "$pin_repo/scripts"
cp "$ROOT/scripts/verify-pinned-tag.sh" "$ROOT/scripts/release-decernor.sh" \
    "$ROOT/scripts/release-tag-common.sh" "$ROOT/scripts/release-workflow-pin.py" \
    "$ROOT/scripts/release-restore-tag-ref.sh" "$pin_repo/scripts/"
printf '0.2.2\n' >"$pin_repo/VERSION"
gpg --homedir "$pin_gpg" --batch --armor --export "$pin_primary" >"$pin_repo/docs/security/release-signing-keys.asc"
printf 'untrusted comment: synthetic minisign public key\nRWRCSwAAAACN synthetic\n' >"$pin_repo/docs/security/seclusor-minisign.pub"
write_anchors "$pin_primary" "$pin_repo/keys"
printf '3 Leaps Infosec Team <infosec@3leaps.net>\n' >"$pin_repo/config/release/tagger-identity.txt"
printf '%s\n' "$pin_subkey" >"$pin_repo/config/release/signing-subkey.txt"
cp "$TEST_ROOT/release.yml.good" "$pin_repo/.github/workflows/release.yml"
cp "$TEST_ROOT/release-workflow.sha256.good" "$pin_repo/config/release/release-workflow.sha256"

git -C "$pin_repo" add VERSION docs keys config .github scripts
git -C "$pin_repo" commit -q -m 'Synthetic pinned-tag commit'
git -C "$pin_repo" remote add origin "$pin_remote"
git -C "$pin_repo" push -q -u origin main
pin_commit="$(git -C "$pin_repo" rev-parse HEAD)"

cat >"$TEST_ROOT/bin/decernor-pin" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [ "${1:-}" = "--version" ] || [ "${1:-}" = "version" ]; then
    printf 'Version: 0.1.8\nCommit: 0123456\n'
    exit 0
fi
if [ "${1:-}" = "fingerprint" ] && [ "${2:-}" = "verify" ]; then
    [ "${DECERNOR_VERIFY_FAIL:-0}" != "1" ]
    exit $?
fi
exit 1
SH
chmod +x "$TEST_ROOT/bin/decernor-pin"

GIT_COMMITTER_NAME='3 Leaps Infosec Team' GIT_COMMITTER_EMAIL='infosec@3leaps.net' \
    GNUPGHOME="$pin_gpg" git -C "$pin_repo" tag -s -a -u "${pin_subkey}!" \
    -m 'seclusor v0.2.2' v0.2.2 "$pin_commit"
GIT_COMMITTER_NAME='3 Leaps Infosec Team' GIT_COMMITTER_EMAIL='infosec@3leaps.net' \
    GNUPGHOME="$pin_gpg" git -C "$pin_repo" tag -s -a -u "${pin_subkey}!" \
    -m 'seclusor bindings/go/seclusor/v0.2.2' bindings/go/seclusor/v0.2.2 "$pin_commit"
git -C "$pin_repo" push -q --atomic origin refs/tags/v0.2.2 refs/tags/bindings/go/seclusor/v0.2.2

SECLUSOR_RELEASE_TAG=v0.2.2 SECLUSOR_DECERNOR_BIN="$TEST_ROOT/bin/decernor-pin" \
    "$pin_repo/scripts/verify-pinned-tag.sh" >/dev/null

# Working-tree tampering of public key file must NOT affect verify-pinned-tag (reads tagged blobs).
printf 'PRIVATE TAMPER\n' >"$pin_repo/docs/security/release-signing-keys.asc"
SECLUSOR_RELEASE_TAG=v0.2.2 SECLUSOR_DECERNOR_BIN="$TEST_ROOT/bin/decernor-pin" \
    "$pin_repo/scripts/verify-pinned-tag.sh" >/dev/null
git -C "$pin_repo" checkout -- docs/security/release-signing-keys.asc

DECERNOR_VERIFY_FAIL=1 SECLUSOR_RELEASE_TAG=v0.2.2 SECLUSOR_DECERNOR_BIN="$TEST_ROOT/bin/decernor-pin" \
    expect_fail 'decernor pin rejection' "$pin_repo/scripts/verify-pinned-tag.sh"

# Missing Go companion tag fails closed.
go_tag_obj="$(git -C "$pin_repo" rev-parse refs/tags/bindings/go/seclusor/v0.2.2)"
git -C "$pin_repo" tag -d bindings/go/seclusor/v0.2.2 >/dev/null
SECLUSOR_RELEASE_TAG=v0.2.2 SECLUSOR_DECERNOR_BIN="$TEST_ROOT/bin/decernor-pin" \
    expect_fail 'missing go companion tag' "$pin_repo/scripts/verify-pinned-tag.sh"
git -C "$pin_repo" update-ref refs/tags/bindings/go/seclusor/v0.2.2 "$go_tag_obj"

# Exercise release-restore-tag-ref.sh over a local mock GitHub REST API.
canonical_tag_obj="$(git -C "$pin_repo" rev-parse refs/tags/v0.2.2)"
git -C "$pin_repo" tag -d v0.2.2 bindings/go/seclusor/v0.2.2 >/dev/null

python3 - "$pin_remote" "$TEST_ROOT/api-port" <<'PYAPI' &
import json, subprocess, sys
from http.server import BaseHTTPRequestHandler, HTTPServer

remote_dir, port_file = sys.argv[1], sys.argv[2]
prefix = "/repos/3leaps/seclusor/git/ref/tags/"

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass
    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or not self.path.startswith(prefix):
            self.send_response(404)
            self.end_headers()
            return
        tag = self.path[len(prefix):]
        res = subprocess.run(
            ["git", f"--git-dir={remote_dir}", "rev-parse", "--verify", "--quiet", f"refs/tags/{tag}"],
            capture_output=True, text=True, check=False,
        )
        if res.returncode != 0:
            self.send_response(404)
            self.end_headers()
            return
        sha = res.stdout.strip()
        kind = subprocess.check_output(
            ["git", f"--git-dir={remote_dir}", "cat-file", "-t", sha], text=True
        ).strip()
        body = json.dumps({"ref": f"refs/tags/{tag}", "object": {"type": kind, "sha": sha}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

srv = HTTPServer(("127.0.0.1", 0), Handler)
with open(port_file, "w", encoding="utf-8") as fh:
    fh.write(str(srv.server_port))
srv.serve_forever()
PYAPI
api_pid=$!
trap 'kill "$api_pid" >/dev/null 2>&1 || true; rm -rf "$TEST_ROOT"' EXIT
for _ in $(seq 1 50); do
    [ -s "$TEST_ROOT/api-port" ] && break
    sleep 0.05
done
api_port="$(cat "$TEST_ROOT/api-port")"

(
    cd "$pin_repo"
    GITHUB_TOKEN='' SECLUSOR_RELEASE_TAG=v0.2.2 SECLUSOR_GITHUB_API="http://127.0.0.1:${api_port}" \
        expect_fail 'missing token in restore-tag-ref' ./scripts/release-restore-tag-ref.sh
    GITHUB_ACTIONS=true GITHUB_TOKEN=tok SECLUSOR_RELEASE_TAG=v0.2.2 \
        expect_fail 'non-GitHub origin rejected on GHA' ./scripts/release-restore-tag-ref.sh
    git remote set-url origin "https://github.com/3leaps/seclusor.git"
    GITHUB_ACTIONS=true GITHUB_TOKEN=tok SECLUSOR_RELEASE_TAG=v0.2.2 SECLUSOR_GITHUB_API="http://127.0.0.1:${api_port}" \
        expect_fail 'GITHUB_API override rejected on GHA' ./scripts/release-restore-tag-ref.sh
    git remote set-url origin "$pin_remote"
    GITHUB_TOKEN=tok SECLUSOR_RELEASE_TAG=v0.2.2 SECLUSOR_GITHUB_API="http://127.0.0.1:${api_port}" \
        SECLUSOR_EXPECTED_TAG_OBJECT="$(printf '%040d' 0)" \
        expect_fail 'mismatched expected canonical tag object' ./scripts/release-restore-tag-ref.sh
    GITHUB_TOKEN=tok SECLUSOR_RELEASE_TAG=v0.2.2 SECLUSOR_GITHUB_API="http://127.0.0.1:${api_port}" \
        SECLUSOR_EXPECTED_TAG_OBJECT="$canonical_tag_obj" \
        SECLUSOR_EXPECTED_GO_TAG_OBJECT="$go_tag_obj" \
        ./scripts/release-restore-tag-ref.sh >/dev/null
    SECLUSOR_RELEASE_TAG=v0.2.2 SECLUSOR_DECERNOR_BIN="$TEST_ROOT/bin/decernor-pin" \
        ./scripts/verify-pinned-tag.sh >/dev/null
)
kill "$api_pid" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# Staged signature verification precedence & OpenPGP fail-closed controls
# ---------------------------------------------------------------------------
sig_dir="$TEST_ROOT/sig-dir"
mkdir -p "$sig_dir"
printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  artifact.bin\n' >"$sig_dir/SHA256SUMS"
printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  artifact.bin\n' >"$sig_dir/SHA512SUMS"
gpg --homedir "$pin_gpg" --batch --armor --export "$pin_primary" >"$sig_dir/release-key.asc"

sig_path="$PATH"
if command -v minisign >/dev/null 2>&1; then
    minisign -G -f -p "$sig_dir/minisign.pub" -s "$TEST_ROOT/minisign.key" -W >/dev/null 2>&1
    minisign -G -f -p "$TEST_ROOT/rogue-minisign.pub" -s "$TEST_ROOT/rogue-minisign.key" -W >/dev/null 2>&1
    minisign -S -s "$TEST_ROOT/minisign.key" -m "$sig_dir/SHA256SUMS" -x "$sig_dir/SHA256SUMS.minisig" >/dev/null 2>&1
    minisign -S -s "$TEST_ROOT/minisign.key" -m "$sig_dir/SHA512SUMS" -x "$sig_dir/SHA512SUMS.minisig" >/dev/null 2>&1
elif [ "${SECLUSOR_REQUIRE_PYYAML:-0}" = "1" ]; then
    echo 'error: minisign binary required in CI release-controls lane' >&2
    exit 1
else
    printf 'untrusted comment: staged synthetic minisign pub\nRWRCSwAAAACN staged\n' >"$sig_dir/minisign.pub"
    printf 'untrusted comment: rogue synthetic minisign pub\nRWRCSwAAAACN rogue\n' >"$TEST_ROOT/rogue-minisign.pub"
    printf 'staged-sig\n' >"$sig_dir/SHA256SUMS.minisig"
    printf 'staged-sig\n' >"$sig_dir/SHA512SUMS.minisig"
    cat >"$TEST_ROOT/bin/minisign" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[ "${1:-}" = "-V" ] && [ "${2:-}" = "-p" ] && [ "${4:-}" = "-m" ] && [ "${6:-}" = "-x" ]
grep -q 'staged' "$3" && grep -q 'staged-sig' "$7"
SH
    chmod +x "$TEST_ROOT/bin/minisign"
    sig_path="$TEST_ROOT/bin:$PATH"
fi

PATH="$sig_path" SECLUSOR_MINISIGN_PUB="$TEST_ROOT/rogue-minisign.pub" \
    expect_fail 'conflicting SECLUSOR_MINISIGN_PUB rejected when staged minisign.pub present' \
    "$ROOT/scripts/verify-signatures.sh" "$sig_dir"

PATH="$sig_path" SECLUSOR_MINISIGN_PUB="" SECLUSOR_GPG_HOMEDIR="" \
    expect_fail 'missing OpenPGP .asc rejected when release-key.asc staged' \
    "$ROOT/scripts/verify-signatures.sh" "$sig_dir"

GNUPGHOME="$TEST_GPG" gpg --batch --pinentry-mode loopback --passphrase '' \
    --armor --detach-sign -u "${revoked_subkey}!" -o "$sig_dir/SHA256SUMS.asc" "$sig_dir/SHA256SUMS"
GNUPGHOME="$TEST_GPG" gpg --batch --pinentry-mode loopback --passphrase '' \
    --armor --detach-sign -u "${revoked_subkey}!" -o "$sig_dir/SHA512SUMS.asc" "$sig_dir/SHA512SUMS"
PATH="$sig_path" SECLUSOR_MINISIGN_PUB="" SECLUSOR_GPG_HOMEDIR="$TEST_GPG" \
    expect_fail 'untrusted OpenPGP .asc rejected against staged release-key.asc' \
    "$ROOT/scripts/verify-signatures.sh" "$sig_dir"

rm -f "$sig_dir/SHA256SUMS.asc" "$sig_dir/SHA512SUMS.asc"
GNUPGHOME="$pin_gpg" gpg --batch --pinentry-mode loopback --passphrase '' \
    --armor --detach-sign -u "${pin_subkey}!" -o "$sig_dir/SHA256SUMS.asc" "$sig_dir/SHA256SUMS"
GNUPGHOME="$pin_gpg" gpg --batch --pinentry-mode loopback --passphrase '' \
    --armor --detach-sign -u "${pin_subkey}!" -o "$sig_dir/SHA512SUMS.asc" "$sig_dir/SHA512SUMS"
PATH="$sig_path" SECLUSOR_MINISIGN_PUB="" SECLUSOR_GPG_HOMEDIR="" \
    SECLUSOR_SIGNING_SUBKEY_FILE="$pin_repo/config/release/signing-subkey.txt" \
    "$ROOT/scripts/verify-signatures.sh" "$sig_dir" >/dev/null

printf '%040d\n' 0 >"$TEST_ROOT/wrong-subkey.txt"
PATH="$sig_path" SECLUSOR_MINISIGN_PUB="" SECLUSOR_GPG_HOMEDIR="" \
    SECLUSOR_SIGNING_SUBKEY_FILE="$TEST_ROOT/wrong-subkey.txt" \
    expect_fail 'mismatched signing subkey rejected in verify-signatures' \
    "$ROOT/scripts/verify-signatures.sh" "$sig_dir"

PATH="$TEST_ROOT/bin:$PATH" expect_fail 'upload-release-assets refuses unverified release dir without anchor' \
    "$ROOT/scripts/upload-release-assets.sh" v0.2.2 "$sig_dir"

# ---------------------------------------------------------------------------
# Makefile release-notes key=value .anchor extraction controls
# ---------------------------------------------------------------------------
notes_dist="$TEST_ROOT/notes-dist"
mkdir -p "$notes_dist"
root_head="$(git -C "$ROOT" rev-parse HEAD)"
cat >"$notes_dist/release.anchor" <<EOF
tag=v0.2.2
commit=${root_head}
run_id=123456
run_attempt=1
downloaded_at=2026-11-13T00:00:00Z
EOF
make -s -C "$ROOT" release-notes DIST="$notes_dist" DIST_RELEASE="$notes_dist/release" SECLUSOR_RELEASE_TAG=v0.2.2 >/dev/null
cmp -s "$ROOT/docs/releases/v0.2.2.md" "$notes_dist/release/release-notes-v0.2.2.md"

notes_bad="$TEST_ROOT/notes-bad"
mkdir -p "$notes_bad"
printf 'tag=v0.2.2\ncommit=not-a-valid-sha\n' >"$notes_bad/release.anchor"
expect_fail 'malformed anchor commit rejected in release-notes' \
    make -s -C "$ROOT" release-notes DIST="$notes_bad" DIST_RELEASE="$notes_bad/release" SECLUSOR_RELEASE_TAG=v0.2.2

echo 'release controls passed (synthetic keys and local remote only)'
