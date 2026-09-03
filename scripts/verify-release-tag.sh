#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 7 ]]; then
  echo "usage: $0 <repository> <vMAJOR.MINOR.PATCH> <event-tag-object> <event-commit> <main-commit> <remote-tag-object> <changelog>" >&2
  exit 2
fi

repository=$1
release_ref=$2
event_tag_object=$3
event_commit=$4
main_commit=$5
remote_tag_object=$6
changelog=$7

test "$repository" = Dhi13man/tunnelfolio
[[ "$release_ref" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]
for commit in "$event_tag_object" "$event_commit" "$main_commit" "$remote_tag_object"; do
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]]
done
test -f "$changelog"

tag_object=$(git rev-parse "refs/tags/$release_ref")
test "$(git cat-file -t "$tag_object")" = tag
test "$tag_object" = "$event_tag_object"
test "$tag_object" = "$remote_tag_object"

tag_commit=$(git rev-parse "$tag_object^{}")
test "$tag_commit" = "$event_commit"
test "$tag_commit" = "$main_commit"

version=${release_ref#v}
test "$(grep -Ec "^## \[$version\] - [0-9]{4}-[0-9]{2}-[0-9]{2}$" "$changelog")" -eq 1

printf 'commit=%s\n' "$tag_commit"
printf 'tag_object=%s\n' "$tag_object"
