#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 <vMAJOR.MINOR.PATCH> <commit> <goarch> <label> <goarm>" >&2
  exit 2
fi

release_ref=$1
release_commit=$2
target_goarch=$3
label=$4
target_goarm=$5

[[ "$release_ref" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
[[ "$release_commit" =~ ^[0-9a-f]{40}$ ]]
case "$target_goarch:$label:$target_goarm" in
  amd64:amd64:|arm64:arm64:|arm:armv7:7) ;;
  *)
    echo "unsupported release target: $target_goarch/$target_goarm ($label)" >&2
    exit 2
    ;;
esac

test "$(git rev-parse HEAD)" = "$release_commit"
source_date_epoch=$(git show -s --format=%ct "$release_commit")
build_date=$(date -u -d "@$source_date_epoch" +%Y-%m-%dT%H:%M:%SZ)
version=${release_ref#v}
archive="tunnelfolio_${release_ref}_linux_${label}"
archive_dir="dist/$archive"

test ! -e "$archive_dir"
test ! -e "$archive_dir.tar.gz"
mkdir -p dist "$archive_dir"
cleanup() {
  if [[ -d "$archive_dir" ]]; then
    find "$archive_dir" -depth -delete
  fi
}
trap cleanup EXIT

CGO_ENABLED=0 GOOS=linux GOARCH="$target_goarch" GOARM="$target_goarm" go build -trimpath \
  -ldflags="-s -w -X main.version=$version -X main.commit=$release_commit -X main.date=$build_date" \
  -o "$archive_dir/tunnelfolio" ./cmd/tunnelfolio
cp LICENSE README.md install.sh tunnelfolio.service tunnelfolio.tmpfiles.conf "$archive_dir/"
./scripts/check-licenses.sh >/dev/null
GOTOOLCHAIN=go1.27.0 go run github.com/google/go-licenses/v2@v2.0.1 save ./... \
  --save_path "$archive_dir/THIRD_PARTY_LICENSES"
tar --sort=name --owner=0 --group=0 --numeric-owner \
  --mtime="@$source_date_epoch" -C dist -czf "$archive_dir.tar.gz" "$archive"

cleanup
trap - EXIT
