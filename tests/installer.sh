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

mkdir -p "$stage/var/lib/tunnelfolio/library/wireguard/tf_aaaaaaaaaaaaaaaaaaaaaaaaaa"
printf 'profile sentinel\n' > "$stage/var/lib/tunnelfolio/library/wireguard/tf_aaaaaaaaaaaaaaaaaaaaaaaaaa/tfaaaaaaaaaaaa.conf"
printf 'state sentinel\n' > "$stage/var/lib/tunnelfolio/manifest.json"
chmod 600 \
	"$stage/var/lib/tunnelfolio/library/wireguard/tf_aaaaaaaaaaaaaaaaaaaaaaaaaa/tfaaaaaaaaaaaa.conf" \
	"$stage/var/lib/tunnelfolio/manifest.json"
token_digest=$(sha256sum "$stage/etc/tunnelfolio/proxy-token")
profile_digest=$(sha256sum "$stage/var/lib/tunnelfolio/library/wireguard/tf_aaaaaaaaaaaaaaaaaaaaaaaaaa/tfaaaaaaaaaaaa.conf")
state_digest=$(sha256sum "$stage/var/lib/tunnelfolio/manifest.json")

DESTDIR=$stage ./install.sh install
test "$(sha256sum "$stage/etc/tunnelfolio/proxy-token")" = "$token_digest"
test "$(sha256sum "$stage/var/lib/tunnelfolio/library/wireguard/tf_aaaaaaaaaaaaaaaaaaaaaaaaaa/tfaaaaaaaaaaaa.conf")" = "$profile_digest"
test "$(sha256sum "$stage/var/lib/tunnelfolio/manifest.json")" = "$state_digest"

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
test "$(sha256sum "$stage/var/lib/tunnelfolio/library/wireguard/tf_aaaaaaaaaaaaaaaaaaaaaaaaaa/tfaaaaaaaaaaaa.conf")" = "$profile_digest"
test "$(sha256sum "$stage/var/lib/tunnelfolio/manifest.json")" = "$state_digest"

if ./install.sh unsupported >"$test_root/invalid.stdout" 2>"$test_root/invalid.stderr"; then
	echo "unsupported installer action succeeded" >&2
	exit 1
fi
test ! -s "$test_root/invalid.stdout"
grep -F 'usage:' "$test_root/invalid.stderr"

fake_bin=$test_root/fake-bin
live=$test_root/live
cutover=$live/var/lib/tunnelfolio-cutover
mkdir -p "$fake_bin" "$live/etc/tunnelfolio" "$live/var/lib/tunnelfolio/library/wireguard/tf_aaaaaaaaaaaaaaaaaaaaaaaaaa" "$cutover"
printf 'cutover receipt\n' > "$cutover/pre-cutover.receipt"
chmod 700 "$live/var/lib/tunnelfolio" "$live/var/lib/tunnelfolio/library" \
	"$live/var/lib/tunnelfolio/library/wireguard" \
	"$live/var/lib/tunnelfolio/library/wireguard/tf_aaaaaaaaaaaaaaaaaaaaaaaaaa" "$cutover"
chmod 600 "$cutover/pre-cutover.receipt"
cat > "$fake_bin/systemctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$SYSTEMCTL_LOG"
if [ "${SYSTEMCTL_MODE:-inactive}" = query-failure ]; then
	exit 1
fi
case "$1 $2" in
"show -p")
	case "$3" in
	LoadState)
		if [ "${SYSTEMCTL_MODE:-inactive}" = not-found ]; then printf 'not-found\n'; else printf 'loaded\n'; fi
		;;
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

fault_bin=$test_root/fault-bin
mkdir -p "$fault_bin"
cat > "$fault_bin/fault-command" <<'EOF'
#!/bin/sh
set -eu

command=${0##*/}
operation=
case $command in
mktemp)
	name=${1##*/}
	case $name in
	.proxy-token.XXXXXX) operation=token-stage-create ;;
	.tunnelfolio.XXXXXX) operation=binary-stage-create ;;
	.tunnelfolio.service.XXXXXX) operation=unit-stage-create ;;
	.tunnelfolio.conf.XXXXXX) operation=tmpfiles-stage-create ;;
	esac
	;;
install)
	target=
	for argument do target=$argument; done
	name=${target##*/}
	case $name in
	.proxy-token.*) operation=token-stage-write ;;
	.tunnelfolio.service.*) operation=unit-stage-write ;;
	.tunnelfolio.conf.*) operation=tmpfiles-stage-write ;;
	.tunnelfolio.*) operation=binary-stage-write ;;
	esac
	;;
sync)
	target=
	for argument do target=$argument; done
	name=${target##*/}
	case $name in
	.proxy-token.*) operation=token-file-sync ;;
	.tunnelfolio.service.*) operation=unit-file-sync ;;
	.tunnelfolio.conf.*) operation=tmpfiles-file-sync ;;
	.tunnelfolio.*) operation=binary-file-sync ;;
	*)
		case $target in
		*/etc/tunnelfolio) operation=token-parent-sync ;;
		*/usr/local/bin) operation=binary-parent-sync ;;
		*/etc/systemd/system) operation=unit-parent-sync ;;
		*/usr/lib/tmpfiles.d) operation=tmpfiles-parent-sync ;;
		esac
		;;
	esac
	;;
mv)
	target=
	for argument do target=$argument; done
	case ${target##*/} in
	proxy-token) operation=token-rename ;;
	tunnelfolio) operation=binary-rename ;;
	tunnelfolio.service) operation=unit-rename ;;
	tunnelfolio.conf) operation=tmpfiles-rename ;;
	esac
	;;
od)
	operation=token-stage-write
	;;
chmod)
	target=
	for argument do target=$argument; done
	case ${target##*/} in
	.proxy-token.*) operation=token-stage-mode ;;
	esac
	;;
esac

if [ -n "$operation" ] && [ "${FAIL_OPERATION:-}" = "$operation" ]; then
	printf '%s\n' "$operation" >> "$FAULT_LOG"
	exit 71
fi

case $command in
chmod) exec "$REAL_CHMOD" "$@" ;;
install) exec "$REAL_INSTALL" "$@" ;;
mktemp) exec "$REAL_MKTEMP" "$@" ;;
mv) exec "$REAL_MV" "$@" ;;
od) exec "$REAL_OD" "$@" ;;
sync) exec "$REAL_SYNC" "$@" ;;
esac
EOF
chmod 755 "$fault_bin/fault-command"
for command in chmod install mktemp mv od sync; do
	ln -s fault-command "$fault_bin/$command"
done

real_chmod=$(command -v chmod)
real_install=$(command -v install)
real_mktemp=$(command -v mktemp)
real_mv=$(command -v mv)
real_od=$(command -v od)
real_sync=$(command -v sync)

for failed_operation in \
	token-stage-create token-stage-write token-stage-mode token-file-sync token-rename token-parent-sync \
	binary-stage-create unit-stage-create tmpfiles-stage-create \
	binary-stage-write unit-stage-write tmpfiles-stage-write \
	binary-file-sync unit-file-sync tmpfiles-file-sync \
	binary-rename unit-rename tmpfiles-rename \
	binary-parent-sync unit-parent-sync tmpfiles-parent-sync; do
	fault_live=$test_root/fault-$failed_operation
	fault_cutover=$fault_live/var/lib/tunnelfolio-cutover
	mkdir -p \
		"$fault_live/usr/local/bin" \
		"$fault_live/etc/systemd/system" \
		"$fault_live/usr/lib/tmpfiles.d" \
		"$fault_live/etc/tunnelfolio" \
		"$fault_live/var/lib/tunnelfolio" \
		"$fault_cutover"
	chmod 700 "$fault_live/etc/tunnelfolio" "$fault_live/var/lib/tunnelfolio" "$fault_cutover"
	printf 'old binary\n' > "$fault_live/usr/local/bin/tunnelfolio"
	printf 'old unit\n' > "$fault_live/etc/systemd/system/tunnelfolio.service"
	printf 'old tmpfiles\n' > "$fault_live/usr/lib/tmpfiles.d/tunnelfolio.conf"
	chmod 755 "$fault_live/usr/local/bin/tunnelfolio"
	chmod 644 "$fault_live/etc/systemd/system/tunnelfolio.service" "$fault_live/usr/lib/tmpfiles.d/tunnelfolio.conf"
	case $failed_operation in
	token-*) ;;
	*)
		printf '%064d' 0 > "$fault_live/etc/tunnelfolio/proxy-token"
		chmod 600 "$fault_live/etc/tunnelfolio/proxy-token"
		;;
	esac
	: > "$fault_live/fault.log"
	: > "$fault_live/systemctl.log"
	: > "$fault_live/tmpfiles.log"
	if FAIL_OPERATION=$failed_operation FAULT_LOG=$fault_live/fault.log \
		REAL_CHMOD=$real_chmod REAL_INSTALL=$real_install REAL_MKTEMP=$real_mktemp \
		REAL_MV=$real_mv REAL_OD=$real_od REAL_SYNC=$real_sync \
		SYSTEMCTL_LOG=$fault_live/systemctl.log TMPFILES_LOG=$fault_live/tmpfiles.log \
		PATH="$fault_bin:$fake_bin:$PATH" \
		PREFIX=$fault_live/usr/local SYSCONFDIR=$fault_live/etc/tunnelfolio STATEDIR=$fault_live/var/lib/tunnelfolio \
		CUTOVER_ROOT=$fault_cutover UNITDIR=$fault_live/etc/systemd/system TMPFILESDIR=$fault_live/usr/lib/tmpfiles.d \
		./install.sh install >"$fault_live/stdout" 2>"$fault_live/stderr"; then
		echo "placement fault $failed_operation succeeded" >&2
		exit 1
	fi
	grep -Fx "$failed_operation" "$fault_live/fault.log"
	grep -Fx 'disable tunnelfolio.service' "$fault_live/systemctl.log"
	if grep -Eq '^(enable|start|restart) ' "$fault_live/systemctl.log"; then
		echo "placement fault $failed_operation activated the service" >&2
		exit 1
	fi
	test ! -s "$fault_live/tmpfiles.log"
	if find \
		"$fault_live/usr/local/bin" \
		"$fault_live/etc/systemd/system" \
		"$fault_live/usr/lib/tmpfiles.d" \
		"$fault_live/etc/tunnelfolio" \
		\( -name '.tunnelfolio.*' -o -name '.proxy-token.*' \) -print -quit | grep -q .; then
		echo "placement fault $failed_operation left a staged file" >&2
		exit 1
	fi
	if ! grep -Fqx 'old binary' "$fault_live/usr/local/bin/tunnelfolio" && \
		! cmp -s ./tunnelfolio "$fault_live/usr/local/bin/tunnelfolio"; then
		echo "placement fault $failed_operation left an unmanaged binary" >&2
		exit 1
	fi
	if ! grep -Fqx 'old unit' "$fault_live/etc/systemd/system/tunnelfolio.service" && \
		! cmp -s ./tunnelfolio.service "$fault_live/etc/systemd/system/tunnelfolio.service"; then
		echo "placement fault $failed_operation left an unmanaged unit" >&2
		exit 1
	fi
	if ! grep -Fqx 'old tmpfiles' "$fault_live/usr/lib/tmpfiles.d/tunnelfolio.conf" && \
		! cmp -s ./tunnelfolio.tmpfiles.conf "$fault_live/usr/lib/tmpfiles.d/tunnelfolio.conf"; then
		echo "placement fault $failed_operation left an unmanaged tmpfiles policy" >&2
		exit 1
	fi
	if [ -e "$fault_live/etc/tunnelfolio/proxy-token" ]; then
		test "$(stat -c %a "$fault_live/etc/tunnelfolio/proxy-token")" = 600
		test "$(wc -c < "$fault_live/etc/tunnelfolio/proxy-token")" -eq 64
		grep -Eq '^[0-9a-f]{64}$' "$fault_live/etc/tunnelfolio/proxy-token"
	fi
done

SYSTEMCTL_LOG=$live/systemctl.log TMPFILES_LOG=$live/tmpfiles.log PATH="$fake_bin:$PATH" \
	PREFIX=$live/usr/local \
	SYSCONFDIR=$live/etc/tunnelfolio \
	STATEDIR=$live/var/lib/tunnelfolio \
	CUTOVER_ROOT=$cutover \
	UNITDIR=$live/etc/systemd/system \
	TMPFILESDIR=$live/usr/lib/tmpfiles.d \
	./install.sh install
grep -Fx -- "--create $live/usr/lib/tmpfiles.d/tunnelfolio.conf" "$live/tmpfiles.log"
test -f "$live/usr/lib/tmpfiles.d/tunnelfolio.conf"
grep -Fx 'daemon-reload' "$live/systemctl.log"
grep -Fx 'enable tunnelfolio.service' "$live/systemctl.log"
grep -Fx 'start tunnelfolio.service' "$live/systemctl.log"

: > "$live/systemctl.log"
SYSTEMCTL_LOG=$live/systemctl.log TMPFILES_LOG=$live/tmpfiles.log PATH="$fake_bin:$PATH" \
	PREFIX=$live/usr/local \
	SYSCONFDIR=$live/etc/tunnelfolio \
	STATEDIR=$live/var/lib/tunnelfolio \
	CUTOVER_ROOT=$cutover \
	UNITDIR=$live/etc/systemd/system \
	TMPFILESDIR=$live/usr/lib/tmpfiles.d \
	./install.sh install-stopped
grep -Fx 'daemon-reload' "$live/systemctl.log"
if grep -Eq '^(enable|start|restart) ' "$live/systemctl.log"; then
	echo "install-stopped activated the service" >&2
	exit 1
fi

chmod 644 "$cutover/pre-cutover.receipt"
if SYSTEMCTL_LOG=$live/systemctl.log TMPFILES_LOG=$live/tmpfiles.log PATH="$fake_bin:$PATH" \
	PREFIX=$live/usr/local \
	SYSCONFDIR=$live/etc/tunnelfolio \
	STATEDIR=$live/var/lib/tunnelfolio \
	CUTOVER_ROOT=$cutover \
	UNITDIR=$live/etc/systemd/system \
	TMPFILESDIR=$live/usr/lib/tmpfiles.d \
	./install.sh install-stopped >"$test_root/public-receipt.stdout" 2>"$test_root/public-receipt.stderr"; then
	echo "install-stopped accepted a public cutover receipt" >&2
	exit 1
fi
grep -F 'Tunnelfolio cutover receipt is not private' "$test_root/public-receipt.stderr"
chmod 600 "$cutover/pre-cutover.receipt"

placed_digest=$(sha256sum "$live/usr/local/bin/tunnelfolio")
if SYSTEMCTL_MODE=active SYSTEMCTL_LOG=$live/systemctl.log PATH="$fake_bin:$PATH" \
	PREFIX=$live/usr/local SYSCONFDIR=$live/etc/tunnelfolio STATEDIR=$live/var/lib/tunnelfolio \
	CUTOVER_ROOT=$cutover UNITDIR=$live/etc/systemd/system TMPFILESDIR=$live/usr/lib/tmpfiles.d \
	./install.sh install-stopped >"$test_root/install-active.stdout" 2>"$test_root/install-active.stderr"; then
	echo "install-stopped replaced an active installation" >&2
	exit 1
fi
test "$(sha256sum "$live/usr/local/bin/tunnelfolio")" = "$placed_digest"

fresh_bin=$test_root/fresh-bin
mkdir -p "$fresh_bin"
cat > "$fresh_bin/wg" <<'EOF'
#!/bin/sh
test "$*" = 'show interfaces'
printf '%s\n' "${WG_INTERFACES:-}"
EOF
chmod 755 "$fresh_bin/wg"

fresh_live=$test_root/fresh-live
fresh_live_state=$fresh_live/var/lib/tunnelfolio
fresh_live_cutover=$fresh_live/var/lib/tunnelfolio-cutover
mkdir -p "$fresh_live_state/library/wireguard/profile" "$fresh_live_cutover"
printf 'profile\n' > "$fresh_live_state/library/wireguard/profile/live.conf"
chmod 700 "$fresh_live_state" "$fresh_live_state/library" "$fresh_live_state/library/wireguard" \
	"$fresh_live_state/library/wireguard/profile" "$fresh_live_cutover"
chmod 600 "$fresh_live_state/library/wireguard/profile/live.conf"
: > "$fresh_live/systemctl.log"
if SYSTEMCTL_MODE=not-found WG_INTERFACES=live SYSTEMCTL_LOG=$fresh_live/systemctl.log PATH="$fresh_bin:$fake_bin:$PATH" \
	PREFIX=$fresh_live/usr/local SYSCONFDIR=$fresh_live/etc/tunnelfolio STATEDIR=$fresh_live_state \
	CUTOVER_ROOT=$fresh_live_cutover UNITDIR=$fresh_live/etc/systemd/system TMPFILESDIR=$fresh_live/usr/lib/tmpfiles.d \
	./install.sh install >"$test_root/fresh-live.stdout" 2>"$test_root/fresh-live.stderr"; then
	echo "fresh install ignored an active live WireGuard interface" >&2
	exit 1
fi
grep -F 'catalog-owned WireGuard interface live is still active' "$test_root/fresh-live.stderr"
test ! -e "$fresh_live/usr/local/bin/tunnelfolio"
if grep -Eq '^(disable|daemon-reload|enable|start|restart) ' "$fresh_live/systemctl.log"; then
	echo "rejected fresh live install changed service state" >&2
	exit 1
fi

fresh_cutover=$test_root/fresh-cutover
fresh_cutover_state=$fresh_cutover/var/lib/tunnelfolio
fresh_cutover_root=$fresh_cutover/var/lib/tunnelfolio-cutover
mkdir -p "$fresh_cutover_root/stage/config/profiles/wireguard/profile"
printf 'profile\n' > "$fresh_cutover_root/stage/config/profiles/wireguard/profile/cutover.conf"
chmod 700 "$fresh_cutover_root" "$fresh_cutover_root/stage" "$fresh_cutover_root/stage/config" \
	"$fresh_cutover_root/stage/config/profiles" "$fresh_cutover_root/stage/config/profiles/wireguard" \
	"$fresh_cutover_root/stage/config/profiles/wireguard/profile"
chmod 600 "$fresh_cutover_root/stage/config/profiles/wireguard/profile/cutover.conf"
: > "$fresh_cutover/systemctl.log"
if SYSTEMCTL_MODE=not-found WG_INTERFACES=cutover SYSTEMCTL_LOG=$fresh_cutover/systemctl.log PATH="$fresh_bin:$fake_bin:$PATH" \
	PREFIX=$fresh_cutover/usr/local SYSCONFDIR=$fresh_cutover/etc/tunnelfolio STATEDIR=$fresh_cutover_state \
	CUTOVER_ROOT=$fresh_cutover_root UNITDIR=$fresh_cutover/etc/systemd/system TMPFILESDIR=$fresh_cutover/usr/lib/tmpfiles.d \
	./install.sh install >"$test_root/fresh-cutover.stdout" 2>"$test_root/fresh-cutover.stderr"; then
	echo "fresh install ignored an active cutover WireGuard interface" >&2
	exit 1
fi
grep -F 'catalog-owned WireGuard interface cutover is still active' "$test_root/fresh-cutover.stderr"
test ! -e "$fresh_cutover/usr/local/bin/tunnelfolio"
if grep -Eq '^(disable|daemon-reload|enable|start|restart) ' "$fresh_cutover/systemctl.log"; then
	echo "rejected fresh cutover install changed service state" >&2
	exit 1
fi

fresh_prepared=$test_root/fresh-prepared
fresh_prepared_state=$fresh_prepared/var/lib/tunnelfolio
fresh_prepared_root=${fresh_prepared_state}-v0.1.0-next
fresh_prepared_cutover=$fresh_prepared/var/lib/tunnelfolio-cutover
mkdir -p "$fresh_prepared_root/library/wireguard/profile" "$fresh_prepared_cutover"
printf 'profile\n' > "$fresh_prepared_root/library/wireguard/profile/prepared.conf"
chmod 700 "$fresh_prepared_root" "$fresh_prepared_root/library" "$fresh_prepared_root/library/wireguard" \
	"$fresh_prepared_root/library/wireguard/profile" "$fresh_prepared_cutover"
chmod 600 "$fresh_prepared_root/library/wireguard/profile/prepared.conf"
: > "$fresh_prepared/systemctl.log"
if SYSTEMCTL_MODE=not-found WG_INTERFACES=prepared SYSTEMCTL_LOG=$fresh_prepared/systemctl.log PATH="$fresh_bin:$fake_bin:$PATH" \
	PREFIX=$fresh_prepared/usr/local SYSCONFDIR=$fresh_prepared/etc/tunnelfolio STATEDIR=$fresh_prepared_state \
	CUTOVER_ROOT=$fresh_prepared_cutover UNITDIR=$fresh_prepared/etc/systemd/system TMPFILESDIR=$fresh_prepared/usr/lib/tmpfiles.d \
	./install.sh install >"$test_root/fresh-prepared.stdout" 2>"$test_root/fresh-prepared.stderr"; then
	echo "fresh install ignored the prepared sibling's active WireGuard interface" >&2
	exit 1
fi
grep -F 'catalog-owned WireGuard interface prepared is still active' "$test_root/fresh-prepared.stderr"
test ! -e "$fresh_prepared/usr/local/bin/tunnelfolio"
if grep -Eq '^(disable|daemon-reload|enable|start|restart) ' "$fresh_prepared/systemctl.log"; then
	echo "rejected fresh prepared install changed service state" >&2
	exit 1
fi

fresh_openvpn=$test_root/fresh-openvpn
fresh_openvpn_state=$fresh_openvpn/var/lib/tunnelfolio
fresh_openvpn_cutover=$fresh_openvpn/var/lib/tunnelfolio-cutover
mkdir -p "$fresh_openvpn_cutover"
chmod 700 "$fresh_openvpn_cutover"
cp /bin/sleep "$fresh_bin/openvpn"
"$fresh_bin/openvpn" 30 &
fresh_openvpn_pid=$!
: > "$fresh_openvpn/systemctl.log"
SYSTEMCTL_MODE=not-found SYSTEMCTL_LOG=$fresh_openvpn/systemctl.log PATH="$fresh_bin:$fake_bin:$PATH" \
	PREFIX=$fresh_openvpn/usr/local SYSCONFDIR=$fresh_openvpn/etc/tunnelfolio STATEDIR=$fresh_openvpn_state \
	CUTOVER_ROOT=$fresh_openvpn_cutover UNITDIR=$fresh_openvpn/etc/systemd/system TMPFILESDIR=$fresh_openvpn/usr/lib/tmpfiles.d \
	./install.sh install >"$test_root/fresh-openvpn.stdout" 2>"$test_root/fresh-openvpn.stderr"
kill "$fresh_openvpn_pid"
wait "$fresh_openvpn_pid" || true
test -x "$fresh_openvpn/usr/local/bin/tunnelfolio"
grep -Fx 'daemon-reload' "$fresh_openvpn/systemctl.log"
grep -Fx 'enable tunnelfolio.service' "$fresh_openvpn/systemctl.log"
grep -Fx 'start tunnelfolio.service' "$fresh_openvpn/systemctl.log"

stat_bin=$test_root/stat-bin
mkdir -p "$stat_bin"
cat > "$stat_bin/stat" <<'EOF'
#!/bin/sh
for argument do
	if [ "$argument" = "${FAIL_STAT:-}" ]; then exit 73; fi
done
exec /usr/bin/stat "$@"
EOF
chmod 755 "$stat_bin/stat"
: > "$live/systemctl.log"
if FAIL_STAT=$live/var/lib/tunnelfolio SYSTEMCTL_LOG=$live/systemctl.log PATH="$stat_bin:$fake_bin:$PATH" \
	PREFIX=$live/usr/local SYSCONFDIR=$live/etc/tunnelfolio STATEDIR=$live/var/lib/tunnelfolio \
	CUTOVER_ROOT=$cutover UNITDIR=$live/etc/systemd/system TMPFILESDIR=$live/usr/lib/tmpfiles.d \
	./install.sh install-stopped >"$test_root/stat-failure.stdout" 2>"$test_root/stat-failure.stderr"; then
	echo "ownership inspection failure passed the disconnected gate" >&2
	exit 1
fi
grep -F 'cannot inspect ownership for Tunnelfolio state root' "$test_root/stat-failure.stderr"
test "$(sha256sum "$live/usr/local/bin/tunnelfolio")" = "$placed_digest"
if grep -Eq '^(disable|daemon-reload|enable|start|restart) ' "$live/systemctl.log"; then
	echo "ownership inspection failure changed service state" >&2
	exit 1
fi

chmod 755 "$live/var/lib/tunnelfolio"
if SYSTEMCTL_LOG=$live/systemctl.log PATH="$fake_bin:$PATH" \
	PREFIX=$live/usr/local SYSCONFDIR=$live/etc/tunnelfolio STATEDIR=$live/var/lib/tunnelfolio \
	CUTOVER_ROOT=$cutover UNITDIR=$live/etc/systemd/system TMPFILESDIR=$live/usr/lib/tmpfiles.d \
	./install.sh install-stopped >"$test_root/unsafe-mode.stdout" 2>"$test_root/unsafe-mode.stderr"; then
	echo "non-private state root passed the disconnected gate" >&2
	exit 1
fi
chmod 700 "$live/var/lib/tunnelfolio"
grep -F 'Tunnelfolio state root is not private' "$test_root/unsafe-mode.stderr"
test "$(sha256sum "$live/usr/local/bin/tunnelfolio")" = "$placed_digest"

SYSTEMCTL_LOG=$live/systemctl.log PATH="$fake_bin:$PATH" \
	PREFIX=$live/usr/local \
	SYSCONFDIR=$live/etc/tunnelfolio \
	STATEDIR=$live/var/lib/tunnelfolio \
	CUTOVER_ROOT=$cutover \
	UNITDIR=$live/etc/systemd/system \
	TMPFILESDIR=$live/usr/lib/tmpfiles.d \
	./install.sh uninstall
grep -Fx 'disable tunnelfolio.service' "$live/systemctl.log"
test ! -e "$live/usr/lib/tmpfiles.d/tunnelfolio.conf"

printf 'active\n' > "$live/var/lib/tunnelfolio/library/wireguard/tf_aaaaaaaaaaaaaaaaaaaaaaaaaa/active.conf"
chmod 600 "$live/var/lib/tunnelfolio/library/wireguard/tf_aaaaaaaaaaaaaaaaaaaaaaaaaa/active.conf"
cat > "$fake_bin/wg" <<'EOF'
#!/bin/sh
test "$*" = 'show interfaces'
printf 'active\n'
EOF
chmod 755 "$fake_bin/wg"
if SYSTEMCTL_LOG=$live/systemctl.log PATH="$fake_bin:$PATH" \
	STATEDIR=$live/var/lib/tunnelfolio CUTOVER_ROOT=$cutover \
	./install.sh check-disconnected \
	>"$test_root/active.stdout" 2>"$test_root/active.stderr"; then
	echo "active catalog interface passed the disconnected check" >&2
	exit 1
fi
grep -F 'catalog-owned WireGuard interface active is still active' "$test_root/active.stderr"

for mode in query-failure active nonempty-cgroup; do
	if SYSTEMCTL_MODE=$mode SYSTEMCTL_LOG=$live/systemctl.log PATH="$fake_bin:$PATH" \
		STATEDIR=$live/var/lib/tunnelfolio CUTOVER_ROOT=$cutover \
		./install.sh check-disconnected \
		>"$test_root/$mode.stdout" 2>"$test_root/$mode.stderr"; then
		echo "systemd mode $mode passed the disconnected check" >&2
		exit 1
	fi
done

mv "$fake_bin/wg" "$fake_bin/wg.saved"
missing_wg_bin=$test_root/missing-wg-bin
mkdir -p "$missing_wg_bin"
ln -s "$fake_bin/systemctl" "$missing_wg_bin/systemctl"
ln -s /usr/bin/id "$missing_wg_bin/id"
ln -s /usr/bin/stat "$missing_wg_bin/stat"
ln -s /usr/bin/readlink "$missing_wg_bin/readlink"
ln -s /usr/bin/cat "$missing_wg_bin/cat"
if SYSTEMCTL_LOG=$live/systemctl.log PATH="$missing_wg_bin" \
	STATEDIR=$live/var/lib/tunnelfolio CUTOVER_ROOT=$cutover \
	/bin/sh ./install.sh check-disconnected \
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
	STATEDIR=$live/var/lib/tunnelfolio CUTOVER_ROOT=$cutover \
	./install.sh check-disconnected \
	>"$test_root/failing-wg.stdout" 2>"$test_root/failing-wg.stderr"; then
	echo "failing wg query passed the disconnected check" >&2
	exit 1
fi
grep -F 'cannot query WireGuard interfaces' "$test_root/failing-wg.stderr"

cat > "$fake_bin/wg" <<'EOF'
#!/bin/sh
test "$*" = 'show interfaces'
printf 'cutover\n'
EOF
chmod 755 "$fake_bin/wg"
mkdir -p "$cutover/stage/config/profiles/wireguard/provider"
printf 'profile\n' > "$cutover/stage/config/profiles/wireguard/provider/cutover.conf"
chmod 700 "$cutover/stage" "$cutover/stage/config" "$cutover/stage/config/profiles" \
	"$cutover/stage/config/profiles/wireguard" "$cutover/stage/config/profiles/wireguard/provider"
chmod 600 "$cutover/stage/config/profiles/wireguard/provider/cutover.conf"
if SYSTEMCTL_LOG=$live/systemctl.log PATH="$fake_bin:$PATH" STATEDIR=$live/var/lib/tunnelfolio CUTOVER_ROOT=$cutover \
	./install.sh check-disconnected >"$test_root/cutover.stdout" 2>"$test_root/cutover.stderr"; then
	echo "cutover-only WireGuard interface passed the disconnected check" >&2
	exit 1
fi
grep -F 'catalog-owned WireGuard interface cutover is still active' "$test_root/cutover.stderr"

cat > "$fake_bin/wg" <<'EOF'
#!/bin/sh
test "$*" = 'show interfaces'
EOF
chmod 755 "$fake_bin/wg"
ln -s /tmp "$live/var/lib/tunnelfolio/library/wireguard/unsafe"
if SYSTEMCTL_LOG=$live/systemctl.log PATH="$fake_bin:$PATH" STATEDIR=$live/var/lib/tunnelfolio CUTOVER_ROOT=$cutover \
	./install.sh check-disconnected >"$test_root/unsafe.stdout" 2>"$test_root/unsafe.stderr"; then
	echo "unsafe WireGuard tree entry passed the disconnected check" >&2
	exit 1
fi
rm "$live/var/lib/tunnelfolio/library/wireguard/unsafe"

cp /bin/sleep "$fake_bin/openvpn"
"$fake_bin/openvpn" 30 &
openvpn_pid=$!
SYSTEMCTL_LOG=$live/systemctl.log PATH="$fake_bin:$PATH" STATEDIR=$live/var/lib/tunnelfolio CUTOVER_ROOT=$cutover \
	./install.sh check-disconnected >"$test_root/openvpn.stdout" 2>"$test_root/openvpn.stderr"
kill "$openvpn_pid"
wait "$openvpn_pid" || true
