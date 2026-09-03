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
command -v jq >/dev/null
command -v python3 >/dev/null

expected_assets=(
  SHA256SUMS
  "tunnelfolio_${release_ref}_linux_amd64.spdx.json"
  "tunnelfolio_${release_ref}_linux_amd64.tar.gz"
  "tunnelfolio_${release_ref}_linux_arm64.spdx.json"
  "tunnelfolio_${release_ref}_linux_arm64.tar.gz"
  "tunnelfolio_${release_ref}_linux_armv7.spdx.json"
  "tunnelfolio_${release_ref}_linux_armv7.tar.gz"
)
mapfile -t assets < <(find "$bundle_dir" -mindepth 1 -maxdepth 1 -printf '%f|%y\n' | LC_ALL=C sort)
expected_entries=()
for asset in "${expected_assets[@]}"; do
  expected_entries+=("$asset|f")
done
test "${assets[*]}" = "${expected_entries[*]}"

payloads=("${expected_assets[@]:1}")
mapfile -t checksummed < <(
  awk '
    NF != 2 || length($1) != 64 || $1 !~ /^[0-9a-f]+$/ { exit 1 }
    { print $2 }
  ' "$bundle_dir/SHA256SUMS" | LC_ALL=C sort
)
test "${checksummed[*]}" = "${payloads[*]}"

(
  cd "$bundle_dir"
  sha256sum --strict -c SHA256SUMS
)

inspect_root=$(mktemp -d)
trap 'find "$inspect_root" -depth -delete' EXIT
source_date_epoch=$(git show -s --format=%ct "$release_commit")

for arch in amd64 arm64 armv7; do
  archive="tunnelfolio_${release_ref}_linux_${arch}.tar.gz"
  root=${archive%.tar.gz}
  archive_path="$bundle_dir/$archive"
  sbom="$bundle_dir/${root}.spdx.json"
  test -f "$archive_path"
  test -f "$sbom"
  archive_sha256=$(sha256sum "$archive_path" | cut -d' ' -f1)
  jq -e --arg root_name "$archive" --arg digest "$archive_sha256" --arg arch "$arch" '
    .spdxVersion == "SPDX-2.3" and
    .dataLicense == "CC0-1.0" and
    .SPDXID == "SPDXRef-DOCUMENT" and
    (.creationInfo.created | type == "string" and length > 0) and
    (.creationInfo.creators | type == "array" and any(startswith("Tool: syft-"))) and
    (.packages | type == "array" and length > 1) and
    (.relationships | type == "array" and length > 0) and
    ([
      .relationships[] |
      select(.spdxElementId == "SPDXRef-DOCUMENT" and .relationshipType == "DESCRIBES") |
      .relatedSpdxElement
    ] | length == 1) and
    ([
      ([
        .relationships[] |
        select(.spdxElementId == "SPDXRef-DOCUMENT" and .relationshipType == "DESCRIBES") |
        .relatedSpdxElement
      ][0]) as $root |
      .packages[] |
      select(.SPDXID == $root) |
      select(
        .name == $root_name and
        .comment == ("Tunnelfolio release architecture: " + $arch) and
        .checksums == [{"algorithm": "SHA256", "checksumValue": $digest}]
      )
    ] | length == 1)
  ' "$sbom" >/dev/null

  inspect="$inspect_root/$arch"
  mkdir "$inspect"
  python3 scripts/verify-release-archive.py "$archive_path" "$root" "$source_date_epoch" "$inspect"
done

expected_licenses="$inspect_root/expected-licenses"
./scripts/check-licenses.sh >/dev/null
GOTOOLCHAIN=go1.27.0 go run github.com/google/go-licenses/v2@v2.0.1 save ./... \
  --save_path "$expected_licenses"

for arch in amd64 arm64 armv7; do
  root="tunnelfolio_${release_ref}_linux_${arch}"
  binary="$inspect_root/$arch/$root/tunnelfolio"
  diff --no-dereference --recursive "$expected_licenses" "$inspect_root/$arch/$root/THIRD_PARTY_LICENSES"

  expected_goarch=$arch
  if [[ "$arch" == armv7 ]]; then
    expected_goarch=arm
  fi
  build_info=$(go version -m "$binary")
  grep -Fqx $'\tbuild\tGOOS=linux' <<< "$build_info"
  grep -Fqx "$(printf '\tbuild\tGOARCH=%s' "$expected_goarch")" <<< "$build_info"
  grep -Fqx $'\tbuild\tCGO_ENABLED=0' <<< "$build_info"
  if [[ "$arch" == armv7 ]]; then
    grep -Fqx $'\tbuild\tGOARM=7' <<< "$build_info"
  fi
done
