#!/usr/bin/env bash

set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
top_dir="$(dirname "$script_dir")"
libecc_dir="$top_dir/deps/libecc-riscv-optimized"

cd "$libecc_dir"

print_separator() {
  echo "--------------------------------------------"
}

current="$(git rev-parse --abbrev-ref HEAD)"
if [[ "$current" == "HEAD" ]]; then
  current="$(git rev-parse HEAD)"
fi

reset_git_branch() {
  echo "Resetting git commit"
  git checkout "$current"
}

trap reset_git_branch EXIT INT TERM

while [[ "$(git rev-parse HEAD)" != "$(git rev-parse 6a56c83fb0e264268b0486ea58ea1753a16aa699^)" ]]; do
  git -c advice.detachedHead=false checkout HEAD^
  if ! make -C "$top_dir" secp256r1_bench-via-docker 2>/dev/null >/dev/null; then
    echo "make -C "$top_dir" secp256r1_bench-via-docker failed"
    exit 1
  fi
  make -C "$top_dir" run-secp256r1-bench
  print_separator
done
