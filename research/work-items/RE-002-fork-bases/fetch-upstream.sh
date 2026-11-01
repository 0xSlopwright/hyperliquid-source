#!/bin/sh
# Fetch the upstream sources compared by tools/fork_bases.py --upstream DIR.
# Network use: public GitHub clones and crates.io tarballs only. No captured binary runs.
set -eu
dir=${1:?usage: fetch-upstream.sh DIR}
mkdir -p "$dir/crates"
for repo in hyperium/hyper hyperium/hyper-tls alloy-rs/core bluealloy/revm; do
  name=$(basename "$repo")
  [ -d "$dir/$name.git" ] || git clone --quiet --bare "https://github.com/$repo.git" "$dir/$name.git"
done
# The GitHub bincode repository no longer carries history; use the published crates.
for v in 2.0.0-rc.3 2.0.0 2.0.1 3.0.0; do
  d="$dir/crates/bincode-$v"
  [ -d "$d/src" ] && continue
  mkdir -p "$d"
  curl -sfL "https://static.crates.io/crates/bincode/bincode-$v.crate" | tar xz -C "$d" --strip-components=1
done
