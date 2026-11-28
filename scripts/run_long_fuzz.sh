#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
duration=${DURATION_SECS:-3605}
sigil_bin=${SIGIL_BIN:-/home/antigravity/sigil-1a4bf/target/release/sigil}

python3 -u "$repo_root/scripts/run_long_fuzz.py" --duration "$duration" --sigil-bin "$sigil_bin" "$@"
