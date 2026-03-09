#!/usr/bin/env bash
set -euo pipefail

cargo run -q -p seclusor -- --help >/dev/null
cargo run -q -p seclusor -- secrets --help >/dev/null
cargo run -q -p seclusor -- keys --help >/dev/null

echo "[ok] CLI matrix smoke checks passed"
