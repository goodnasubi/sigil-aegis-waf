#!/usr/bin/env bash
set -euo pipefail

sigil_sha=e1a0291ab419dca0a04c9d7315c3567b81308a1f
shield_sha=63d3051b18e6d0e90c1ebe8f76e6ce267d7534a4
argus_sha=113aeed4932d841d752d752e77dc767ed6b4c886
db_sha=9483e36f08c35bfc62b3beeb008a531887506037
rust_version=1.100.0
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT

fetch_pinned() {
  local url=$1 sha=$2 dir=$3
  git init -q "$dir"
  git -C "$dir" fetch --no-tags --depth=1 "$url" "$sha"
  git -C "$dir" checkout --detach FETCH_HEAD
  test "$(git -C "$dir" rev-parse HEAD)" = "$sha"
  test -z "$(git -C "$dir" status --porcelain --untracked-files=all)"
}

sigil_root=${SIGIL_SOURCE:-"$scratch/sigil"}
if [[ -z ${SIGIL_SOURCE:-} ]]; then
  fetch_pinned https://github.com/goodnasubi/sigil.git "$sigil_sha" "$sigil_root"
fi
test "$(git -C "$sigil_root" rev-parse HEAD)" = "$sigil_sha"
test -z "$(git -C "$sigil_root" status --porcelain --untracked-files=all)"

cargo_target=${CARGO_TARGET_DIR:-target}
if [[ ! -x "$sigil_root/$cargo_target/release/sigil" ]]; then
  cd "$sigil_root"
  rustup toolchain install "$rust_version" --profile minimal --component rustfmt --component clippy
  cargo +"$rust_version" fmt --check
  cargo +"$rust_version" clippy --locked --all-targets -- -D warnings
  cargo +"$rust_version" build --locked --release --bin sigil
fi
sigil="$sigil_root/$cargo_target/release/sigil"

root="$scratch/root"
mkdir -p "$root"
cp "$repo_root"/sigil/*.sigil "$root/"
cp "$repo_root/Sigil.toml" "$root/"
fetch_pinned https://github.com/goodnasubi/sigil-argus-observe.git "$argus_sha" "$scratch/argus"
cp "$scratch/argus/argus_observe.sigil" "$root/"

"$sigil" fmt --check "$repo_root"/sigil/*.sigil

run_entry() {
  local entry=$1 label=$2 evaluator native
  "$sigil" check --root "$root" "$root/$entry.sigil"
  evaluator=$("$sigil" run --root "$root" "$root/$entry.sigil" main | tail -n 1)
  if [[ "$evaluator" != 0 ]]; then
    printf '%s: evaluator test failed (%s)\n' "$label" "$evaluator" >&2
    exit 1
  fi
  "$sigil" build --root "$root" "$root/$entry.sigil" main -o "$scratch/$entry"
  native=$("$scratch/$entry" | tail -n 1)
  if [[ "$native" != 0 ]]; then
    printf '%s: native test failed (%s)\n' "$label" "$native" >&2
    exit 1
  fi
  printf '%s: evaluator and native tests passed.\n' "$label"
}

run_entry stage1_policy_test "Stage 1 policy core"
run_entry stage3_ip_limit_test "Stage 3 IP and rate-limit core"

fetch_pinned https://github.com/goodnasubi/sigil-shield-tls.git "$shield_sha" "$scratch/shield"
cp "$scratch/shield/sigil/shield_proxy_v2.sigil" "$repo_root/tests/shield_preface.sigil" "$root/"
"$sigil" fmt --check "$repo_root/tests/shield_preface.sigil"
"$sigil" check --root "$root" "$root/aegis_gateway.sigil"
"$sigil" build --root "$root" "$root/aegis_gateway.sigil" main -o "$scratch/aegis"
"$sigil" build --root "$root" "$root/shield_preface.sigil" main -o "$scratch/shield-preface"
python3 "$repo_root/tests/stage2_loopback.py" "$scratch/aegis" "$scratch/shield-preface"


fetch_pinned https://github.com/goodnasubi/sigil-db.git "$db_sha" "$scratch/db"
cp -R "$scratch/db/db" "$root/"
cp "$scratch/argus"/argus_{collect,health,query,receive}.sigil "$repo_root/tests/argus_collector.sigil" "$root/"
"$sigil" fmt --check "$repo_root/tests/argus_collector.sigil"
"$sigil" build --root "$root" "$root/argus_collector.sigil" main -o "$scratch/argus-collector"
python3 -B "$repo_root/tests/stage3_loopback.py" "$scratch/aegis" "$scratch/shield-preface" "$scratch/argus-collector"
