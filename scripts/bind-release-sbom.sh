#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <archive> <sbom> <amd64|arm64|armv7>" >&2
  exit 2
fi

archive=$1
sbom=$2
arch=$3

case "$arch" in
  amd64|arm64|armv7) ;;
  *)
    echo "unsupported release architecture: $arch" >&2
    exit 2
    ;;
esac

test -f "$archive"
test -f "$sbom"
command -v jq >/dev/null

archive_name=${archive##*/}
expected_suffix="_linux_${arch}.tar.gz"
[[ "$archive_name" == tunnelfolio_v*"$expected_suffix" ]]
test "${sbom##*/}" = "${archive_name%.tar.gz}.spdx.json"

mapfile -t roots < <(
  jq -r '
    .relationships[]? |
    select(.spdxElementId == "SPDXRef-DOCUMENT" and .relationshipType == "DESCRIBES") |
    .relatedSpdxElement
  ' "$sbom"
)
test "${#roots[@]}" -eq 1
root=${roots[0]}
test "$(jq --arg root "$root" '[.packages[]? | select(.SPDXID == $root)] | length' "$sbom")" -eq 1

archive_sha256=$(sha256sum "$archive" | cut -d' ' -f1)
temporary=$(mktemp "${sbom}.XXXXXX")
trap 'rm -f "$temporary"' EXIT HUP INT TERM
jq \
  --arg root "$root" \
  --arg archive "$archive_name" \
  --arg digest "$archive_sha256" \
  --arg arch "$arch" '
    (.packages[] | select(.SPDXID == $root) | .name) = $archive |
    (.packages[] | select(.SPDXID == $root) | .checksums) = [
      {"algorithm": "SHA256", "checksumValue": $digest}
    ] |
    (.packages[] | select(.SPDXID == $root) | .comment) =
      ("Tunnelfolio release architecture: " + $arch)
  ' "$sbom" > "$temporary"
chmod 0644 "$temporary"
mv "$temporary" "$sbom"
trap - EXIT HUP INT TERM
