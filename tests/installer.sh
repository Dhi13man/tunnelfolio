#!/bin/sh
set -eu

test_root=$(mktemp -d)
cleanup() {
	find "$test_root" -depth -delete
}
trap cleanup EXIT HUP INT TERM

stage=$test_root/stage
mkdir -p "$stage"

DESTDIR=$stage ./install.sh install
test -x "$stage/usr/local/bin/tunnelfolio"
test -f "$stage/etc/systemd/system/tunnelfolio.service"
test -f "$stage/usr/lib/tmpfiles.d/tunnelfolio.conf"
for directory in \
	"$stage/etc/tunnelfolio" \
	"$stage/etc/tunnelfolio/profiles" \
	"$stage/etc/tunnelfolio/profiles/openvpn" \
	"$stage/etc/tunnelfolio/profiles/wireguard" \
	"$stage/var/lib/tunnelfolio"; do
	test "$(stat -c %a "$directory")" = 700
done
test "$(stat -c %a "$stage/etc/tunnelfolio/proxy-token")" = 600
test "$(stat -c %a "$stage/usr/local/bin/tunnelfolio")" = 755
test "$(stat -c %a "$stage/etc/systemd/system/tunnelfolio.service")" = 644
test "$(stat -c %a "$stage/usr/lib/tmpfiles.d/tunnelfolio.conf")" = 644
grep -Fqx 'd /run/resolvconf 0755 root root -' "$stage/usr/lib/tmpfiles.d/tunnelfolio.conf"
grep -Fqx 'ReadWritePaths=/var/lib/tunnelfolio /run/tunnelfolio -/etc/resolv.conf /run/resolvconf -/run/systemd/resolve/stub-resolv.conf' "$stage/etc/systemd/system/tunnelfolio.service"
grep -Fqx 'CapabilityBoundingSet=CAP_KILL CAP_NET_ADMIN CAP_NET_RAW' "$stage/etc/systemd/system/tunnelfolio.service"
grep -Fqx 'AmbientCapabilities=CAP_KILL CAP_NET_ADMIN CAP_NET_RAW' "$stage/etc/systemd/system/tunnelfolio.service"
test "$(wc -c < "$stage/etc/tunnelfolio/proxy-token")" -eq 64
grep -Eq '^[0-9a-f]{64}$' "$stage/etc/tunnelfolio/proxy-token"

printf 'profile sentinel\n' > "$stage/etc/tunnelfolio/profiles/wireguard/generic/sentinel.conf"
printf 'state sentinel\n' > "$stage/var/lib/tunnelfolio/state.json"
chmod 600 \
	"$stage/etc/tunnelfolio/profiles/wireguard/generic/sentinel.conf" \
	"$stage/var/lib/tunnelfolio/state.json"
token_digest=$(sha256sum "$stage/etc/tunnelfolio/proxy-token")
profile_digest=$(sha256sum "$stage/etc/tunnelfolio/profiles/wireguard/generic/sentinel.conf")
state_digest=$(sha256sum "$stage/var/lib/tunnelfolio/state.json")

DESTDIR=$stage ./install.sh install
test "$(sha256sum "$stage/etc/tunnelfolio/proxy-token")" = "$token_digest"
test "$(sha256sum "$stage/etc/tunnelfolio/profiles/wireguard/generic/sentinel.conf")" = "$profile_digest"
test "$(sha256sum "$stage/var/lib/tunnelfolio/state.json")" = "$state_digest"

unit_root=$test_root/unit-root
mkdir -p "$unit_root/usr/local/bin" "$unit_root/etc/systemd/system" "$unit_root/usr/lib/systemd/system"
cp ./tunnelfolio "$unit_root/usr/local/bin/tunnelfolio"
cp ./tunnelfolio.service "$unit_root/etc/systemd/system/tunnelfolio.service"
for target in basic sysinit network-online multi-user shutdown; do
	printf '[Unit]\nDescription=Hermetic %s target\n' "$target" > "$unit_root/usr/lib/systemd/system/$target.target"
done
systemd-analyze verify --root="$unit_root" tunnelfolio.service

DESTDIR=$stage ./install.sh uninstall
test ! -e "$stage/usr/local/bin/tunnelfolio"
test ! -e "$stage/etc/systemd/system/tunnelfolio.service"
test ! -e "$stage/usr/lib/tmpfiles.d/tunnelfolio.conf"
test "$(sha256sum "$stage/etc/tunnelfolio/proxy-token")" = "$token_digest"
test "$(sha256sum "$stage/etc/tunnelfolio/profiles/wireguard/generic/sentinel.conf")" = "$profile_digest"
test "$(sha256sum "$stage/var/lib/tunnelfolio/state.json")" = "$state_digest"

if ./install.sh unsupported >"$test_root/invalid.stdout" 2>"$test_root/invalid.stderr"; then
	echo "unsupported installer action succeeded" >&2
	exit 1
fi
test ! -s "$test_root/invalid.stdout"
grep -F 'usage:' "$test_root/invalid.stderr"

fake_bin=$test_root/fake-bin
live=$test_root/live
mkdir -p "$fake_bin" "$live/etc/tunnelfolio/profiles/wireguard/generic"
cat > "$fake_bin/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$SYSTEMCTL_LOG"
if [ "${SYSTEMCTL_MODE:-inactive}" = query-failure ]; then
	exit 1
fi
case "$1 $2" in
"show -p")
	case "$3" in
	LoadState) printf 'loaded\n' ;;
	ActiveState)
		if [ "${SYSTEMCTL_MODE:-inactive}" = active ]; then printf 'active\n'; else printf 'inactive\n'; fi
		;;
	MainPID) printf '0\n' ;;
	ControlGroup)
		if [ "${SYSTEMCTL_MODE:-inactive}" = nonempty-cgroup ]; then printf '/\n'; else printf '\n'; fi
		;;
	esac
	;;
esac
EOF
cat > "$fake_bin/wg" <<'EOF'
#!/bin/sh
test "$*" = 'show interfaces'
EOF
cat > "$fake_bin/systemd-tmpfiles" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$TMPFILES_LOG"
test "$1" = --create
test -f "$2"
EOF
chmod 755 "$fake_bin/systemctl" "$fake_bin/systemd-tmpfiles" "$fake_bin/wg"
SYSTEMCTL_LOG=$live/systemctl.log TMPFILES_LOG=$live/tmpfiles.log PATH="$fake_bin:$PATH" \
	PREFIX=$live/usr/local \
	SYSCONFDIR=$live/etc/tunnelfolio \
	STATEDIR=$live/var/lib/tunnelfolio \
	UNITDIR=$live/etc/systemd/system \
	TMPFILESDIR=$live/usr/lib/tmpfiles.d \
	./install.sh install
grep -Fx -- "--create $live/usr/lib/tmpfiles.d/tunnelfolio.conf" "$live/tmpfiles.log"
test -f "$live/usr/lib/tmpfiles.d/tunnelfolio.conf"
grep -Fx 'daemon-reload' "$live/systemctl.log"
grep -Fx 'enable tunnelfolio.service' "$live/systemctl.log"
grep -Fx 'restart tunnelfolio.service' "$live/systemctl.log"
SYSTEMCTL_LOG=$live/systemctl.log PATH="$fake_bin:$PATH" \
	PREFIX=$live/usr/local \
	SYSCONFDIR=$live/etc/tunnelfolio \
	STATEDIR=$live/var/lib/tunnelfolio \
	UNITDIR=$live/etc/systemd/system \
	TMPFILESDIR=$live/usr/lib/tmpfiles.d \
	./install.sh uninstall
grep -Fx 'disable tunnelfolio.service' "$live/systemctl.log"
test ! -e "$live/usr/lib/tmpfiles.d/tunnelfolio.conf"

printf 'active\n' > "$live/etc/tunnelfolio/profiles/wireguard/generic/active.conf"
cat > "$fake_bin/wg" <<'EOF'
#!/bin/sh
test "$*" = 'show interfaces'
printf 'active\n'
EOF
chmod 755 "$fake_bin/wg"
if SYSTEMCTL_LOG=$live/systemctl.log PATH="$fake_bin:$PATH" \
	SYSCONFDIR=$live/etc/tunnelfolio ./install.sh check-disconnected \
	>"$test_root/active.stdout" 2>"$test_root/active.stderr"; then
	echo "active catalog interface passed the disconnected check" >&2
	exit 1
fi
grep -F 'catalog-owned WireGuard interface active is still active' "$test_root/active.stderr"

for mode in query-failure active nonempty-cgroup; do
	if SYSTEMCTL_MODE=$mode SYSTEMCTL_LOG=$live/systemctl.log PATH="$fake_bin:$PATH" \
		SYSCONFDIR=$live/etc/tunnelfolio ./install.sh check-disconnected \
		>"$test_root/$mode.stdout" 2>"$test_root/$mode.stderr"; then
		echo "systemd mode $mode passed the disconnected check" >&2
		exit 1
	fi
done

mv "$fake_bin/wg" "$fake_bin/wg.saved"
if SYSTEMCTL_LOG=$live/systemctl.log PATH="$fake_bin" \
	SYSCONFDIR=$live/etc/tunnelfolio /bin/sh ./install.sh check-disconnected \
	>"$test_root/missing-wg.stdout" 2>"$test_root/missing-wg.stderr"; then
	echo "missing wg passed the disconnected check" >&2
	exit 1
fi
grep -F 'wg is unavailable' "$test_root/missing-wg.stderr"
mv "$fake_bin/wg.saved" "$fake_bin/wg"
cat > "$fake_bin/wg" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod 755 "$fake_bin/wg"
if SYSTEMCTL_LOG=$live/systemctl.log PATH="$fake_bin:$PATH" \
	SYSCONFDIR=$live/etc/tunnelfolio ./install.sh check-disconnected \
	>"$test_root/failing-wg.stdout" 2>"$test_root/failing-wg.stderr"; then
	echo "failing wg query passed the disconnected check" >&2
	exit 1
fi
grep -F 'cannot query WireGuard interfaces' "$test_root/failing-wg.stderr"
