#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || {
	echo "tmpfiles integration test must run as root" >&2
	exit 1
}

test_root=$(mktemp -d)
cleanup() {
	find "$test_root" -depth -delete
}
trap cleanup EXIT HUP INT TERM

install -d -m 0755 "$test_root/usr/lib/tmpfiles.d"
install -m 0644 ./tunnelfolio.tmpfiles.conf "$test_root/usr/lib/tmpfiles.d/tunnelfolio.conf"
test ! -e "$test_root/run/resolvconf"

systemd-tmpfiles --root="$test_root" --create "$test_root/usr/lib/tmpfiles.d/tunnelfolio.conf"

test -d "$test_root/run/resolvconf"
test "$(stat -c %u "$test_root/run/resolvconf")" = 0
test "$(stat -c %g "$test_root/run/resolvconf")" = 0
test "$(stat -c %a "$test_root/run/resolvconf")" = 755
