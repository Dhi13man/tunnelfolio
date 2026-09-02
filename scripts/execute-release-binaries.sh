#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <vMAJOR.MINOR.PATCH> <commit> <bundle-directory>" >&2
  exit 2
fi

release_ref=$1
release_commit=$2
bundle_dir=$3
[[ "$release_ref" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
[[ "$release_commit" =~ ^[0-9a-f]{40}$ ]]
test "$(git rev-parse HEAD)" = "$release_commit"
test -d "$bundle_dir"

source_date_epoch=$(git show -s --format=%ct "$release_commit")
build_date=$(date -u -d "@$source_date_epoch" +%Y-%m-%dT%H:%M:%SZ)
expected_version="tunnelfolio ${release_ref#v} (commit $release_commit, built $build_date)"

execution_root=$(mktemp -d)
trap 'find "$execution_root" -depth -delete' EXIT
for arch in amd64 arm64 armv7; do
  root="tunnelfolio_${release_ref}_linux_${arch}"
  destination="$execution_root/$arch"
  mkdir "$destination"
  python3 scripts/verify-release-archive.py \
    "$bundle_dir/$root.tar.gz" \
    "$root" \
    "$source_date_epoch" \
    "$destination"

  runner=()
  if [[ "$arch" == arm64 ]]; then
    runner=(qemu-aarch64-static)
  elif [[ "$arch" == armv7 ]]; then
    runner=(qemu-arm-static)
  fi
  command -v "${runner[0]:-$destination/$root/tunnelfolio}" >/dev/null
  test "$("${runner[@]}" "$destination/$root/tunnelfolio" --version)" = "$expected_version"
done
