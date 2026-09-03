#!/bin/sh
set -eu

report=$(mktemp)
trap 'rm -f "$report"' EXIT HUP INT TERM

GOTOOLCHAIN=go1.27.0 go run github.com/google/go-licenses/v2@v2.0.1 report ./... > "$report"
awk -F, '
	NR == FNR {
		if ($0 !~ /^#/ && NF == 1) allowed[$1] = 1
		next
	}
	NF != 3 || !($3 in allowed) {
		print "dependency license is not allowed: " $0 > "/dev/stderr"
		failed = 1
	}
	END { exit failed }
' .github/license-policy.txt "$report"
LC_ALL=C sort "$report"
node scripts/check-node-dependencies.cjs
