#!/usr/bin/env bash
# Maintainer-only: export approved public signing pins and derive committed
# decernor fingerprint anchors. Refuses to overwrite existing committed pins
# unless SECLUSOR_ALLOW_ANCHOR_ROTATION=1 is explicitly set.
set -euo pipefail

script_dir="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/release-decernor.sh
source "${script_dir}/release-decernor.sh"
cd "$(CDPATH='' cd -- "${script_dir}/.." && pwd -P)"

for name in SECLUSOR_MINISIGN_PUB SECLUSOR_GPG_HOMEDIR SECLUSOR_PGP_KEY_ID; do
    if [ -z "${!name:-}" ]; then
        echo "error: ${name} is required" >&2
        exit 1
    fi
done
if [ ! -f "${SECLUSOR_MINISIGN_PUB}" ] || [ -L "${SECLUSOR_MINISIGN_PUB}" ] || [ ! -s "${SECLUSOR_MINISIGN_PUB}" ]; then
    echo "error: SECLUSOR_MINISIGN_PUB must name a non-empty regular file" >&2
    exit 1
fi
if [ ! -d "${SECLUSOR_GPG_HOMEDIR}" ]; then
    echo "error: SECLUSOR_GPG_HOMEDIR is unavailable" >&2
    exit 1
fi
if ! [[ "${SECLUSOR_PGP_KEY_ID}" =~ ^([0-9A-F]{16}|[0-9A-F]{40})!$ ]]; then
    echo "error: SECLUSOR_PGP_KEY_ID must be an uppercase 16-hex key ID or 40-hex subkey fingerprint followed by !" >&2
    exit 1
fi

if [ "${SECLUSOR_ALLOW_ANCHOR_ROTATION:-0}" != "1" ]; then
    for existing in \
        docs/security/release-signing-keys.asc \
        docs/security/seclusor-minisign.pub \
        config/release/signing-subkey.txt \
        keys/expected-fingerprints.txt \
        keys/expected-fingerprints.ndjson; do
        if [ -e "${existing}" ] || [ -L "${existing}" ]; then
            echo "error: ${existing} already exists; set SECLUSOR_ALLOW_ANCHOR_ROTATION=1 for an approved rotation" >&2
            exit 1
        fi
    done
fi

decernor_bin="$(release_resolve_decernor ceremony)"
workdir="$(mktemp -d "${TMPDIR:-/tmp}/seclusor-anchors.XXXXXX")"
trap 'gpgconf --homedir "${workdir}/verify-gpg" --kill all >/dev/null 2>&1 || true; rm -rf "${workdir}"' EXIT

cp "${SECLUSOR_MINISIGN_PUB}" "${workdir}/minisign.pub"
gpg --batch --no-tty --homedir "${SECLUSOR_GPG_HOMEDIR}" --armor \
    --export --export-options export-minimal "${SECLUSOR_PGP_KEY_ID}" >"${workdir}/release-key.asc"
if [ ! -s "${workdir}/release-key.asc" ]; then
    echo "error: exported public GPG key is empty" >&2
    exit 1
fi
if grep -Eqi 'PRIVATE KEY|SECRET KEY|minisign secret key|minisign encrypted secret key' \
    "${workdir}/minisign.pub" "${workdir}/release-key.asc"; then
    echo "error: exported public material contains secret-key markers" >&2
    exit 1
fi

mkdir -m 700 "${workdir}/verify-gpg"
shown="$(GNUPGHOME="${workdir}/verify-gpg" gpg --batch --with-colons \
    --fingerprint --with-subkey-fingerprint --show-keys "${workdir}/release-key.asc")"
if [ "$(awk -F: '$1 == "sec" || $1 == "ssb" { n++ } END { print n + 0 }' <<<"${shown}")" -ne 0 ]; then
    echo "error: exported OpenPGP pin contains secret key packets" >&2
    exit 1
fi

layout="$(awk -F: '
    $1 == "pub" || $1 == "sub" { kind = $1; cap = $12; want = 1; next }
    want && $1 == "fpr" { print kind, $10, cap; want = 0 }
' <<<"${shown}")"
if [ "$(awk '{print $1}' <<<"${layout}" | paste -sd, -)" != "pub,sub" ]; then
    echo "error: exported OpenPGP pin must contain exactly one primary key and one signing subkey" >&2
    exit 1
fi
read -r _ pin_primary _ < <(sed -n '1p' <<<"${layout}")
read -r _ pin_subkey pin_cap < <(sed -n '2p' <<<"${layout}")
if [ -n "${SECLUSOR_GPG_SIGNING_FINGERPRINT:-}" ] && [ "${pin_primary}" != "${SECLUSOR_GPG_SIGNING_FINGERPRINT}" ]; then
    echo "error: exported primary (${pin_primary}) differs from SECLUSOR_GPG_SIGNING_FINGERPRINT" >&2
    exit 1
fi
if ! [[ "${pin_subkey}" =~ ^[0-9A-F]{40}$ ]] || [ "${pin_subkey}" = "${pin_primary}" ] || ! [[ "${pin_cap}" =~ [sS] ]]; then
    echo "error: exported signing subkey is invalid or lacks signing capability" >&2
    exit 1
fi

"${decernor_bin}" fingerprint "${workdir}/release-key.asc" --class public \
    --kind gpg --format ndjson --path-mode none --gpg-role primary >"${workdir}/gpg.ndjson"
"${decernor_bin}" fingerprint "${workdir}/minisign.pub" --class public \
    --kind minisign --format ndjson --path-mode none >"${workdir}/minisign.ndjson"

mkdir -p "${workdir}/pair"
python3 -I - "${workdir}/gpg.ndjson" "${workdir}/minisign.ndjson" "${workdir}/pair" <<'PY'
import json
import pathlib
import sys

gpg_path, mini_path, out_dir = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])


def records(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


gpg = [r for r in records(gpg_path) if r.get("fingerprint_scheme") == "openpgp-fingerprint-v1" and r.get("key_role") == "primary"]
mini = [r for r in records(mini_path) if r.get("fingerprint_scheme") == "minisign-public-blob-sha256-v1"]
if len(gpg) != 1 or len(mini) != 1:
    raise SystemExit("error: expected exactly one GPG primary and one minisign blob fingerprint")
gpg_fp, mini_fp = gpg[0].get("fingerprint", ""), mini[0].get("fingerprint", "")
if len(gpg_fp) != 40 or any(c not in "0123456789ABCDEF" for c in gpg_fp):
    raise SystemExit("error: invalid GPG primary fingerprint")
if len(mini_fp) != 64 or any(c not in "0123456789abcdef" for c in mini_fp):
    raise SystemExit("error: invalid minisign blob fingerprint")
(out_dir / "expected-fingerprints.ndjson").write_text(
    json.dumps(gpg[0], separators=(",", ":")) + "\n" + json.dumps(mini[0], separators=(",", ":")) + "\n",
    encoding="utf-8",
)
(out_dir / "expected-fingerprints.txt").write_text(
    f"gpg {gpg_fp}\nminisign {mini_fp}\n",
    encoding="utf-8",
)
PY

"${decernor_bin}" fingerprint verify \
    --anchors "${workdir}/pair/expected-fingerprints.txt" \
    --anchors-ndjson "${workdir}/pair/expected-fingerprints.ndjson" \
    --gpg "${workdir}/release-key.asc" --minisign "${workdir}/minisign.pub" >/dev/null

mkdir -p docs/security config/release keys
cp "${workdir}/release-key.asc" docs/security/release-signing-keys.asc
cp "${workdir}/minisign.pub" docs/security/seclusor-minisign.pub
printf '%s\n' "${pin_subkey}" >config/release/signing-subkey.txt
"${script_dir}/atomic-install-pin-pair.sh" "${workdir}/pair" keys

"${decernor_bin}" fingerprint verify \
    --anchors keys/expected-fingerprints.txt --anchors-ndjson keys/expected-fingerprints.ndjson \
    --gpg docs/security/release-signing-keys.asc --minisign docs/security/seclusor-minisign.pub >/dev/null

echo "[ok] wrote and verified docs/security/{release-signing-keys.asc,seclusor-minisign.pub}, config/release/signing-subkey.txt, and keys/expected-fingerprints.{txt,ndjson}"
