#!/bin/sh
set -eu

prefix=${PREFIX:-/usr/local}
sysconfdir=${SYSCONFDIR:-/etc/tunnelfolio}
statedir=${STATEDIR:-/var/lib/tunnelfolio}
unitdir=${UNITDIR:-/etc/systemd/system}
tmpfilesdir=${TMPFILESDIR:-/usr/lib/tmpfiles.d}
destdir=${DESTDIR:-}

usage() {
	echo "usage: $0 install|check-disconnected|uninstall" >&2
	exit 2
}

check_disconnected() {
	[ -z "$destdir" ] || {
		echo "check-disconnected is available only for a live installation" >&2
		return 1
	}
	load_state=$(systemctl show -p LoadState --value tunnelfolio.service) || {
		echo "cannot query Tunnelfolio unit load state" >&2
		return 1
	}
	[ "$load_state" = loaded ] || {
		echo "cannot prove Tunnelfolio stopped because its unit is not loaded" >&2
		return 1
	}
	active_state=$(systemctl show -p ActiveState --value tunnelfolio.service) || {
		echo "cannot query Tunnelfolio unit active state" >&2
		return 1
	}
	[ "$active_state" = inactive ] || {
		echo "Tunnelfolio state is $active_state; disconnect through the authenticated API, then stop the service" >&2
		return 1
	}
	main_pid=$(systemctl show -p MainPID --value tunnelfolio.service) || {
		echo "cannot query Tunnelfolio main PID" >&2
		return 1
	}
	case $main_pid in
	"" | 0) ;;
	*)
		echo "Tunnelfolio still has main PID $main_pid" >&2
		return 1
		;;
	esac
	control_group=$(systemctl show -p ControlGroup --value tunnelfolio.service) || {
		echo "cannot query Tunnelfolio control group" >&2
		return 1
	}
	case $control_group in
	"") ;;
	/*)
		case $control_group in
		*..*)
			echo "refusing unsafe systemd control-group path" >&2
			return 1
			;;
		esac
		if [ -s "/sys/fs/cgroup$control_group/cgroup.procs" ]; then
			echo "Tunnelfolio control group still contains processes" >&2
			return 1
		fi
		;;
	*)
		echo "refusing unsafe systemd control-group path" >&2
		return 1
		;;
	esac
	if [ -d "$sysconfdir/profiles/wireguard" ]; then
		command -v wg >/dev/null 2>&1 || {
			echo "cannot prove WireGuard interfaces absent because wg is unavailable" >&2
			return 1
		}
		active_interfaces=" $(wg show interfaces) " || {
			echo "cannot query WireGuard interfaces" >&2
			return 1
		}
		find "$sysconfdir/profiles/wireguard" -type f -name '*.conf' -print | while IFS= read -r profile; do
			interface=${profile##*/}
			interface=${interface%.conf}
			case $active_interfaces in
			*" $interface "*)
				echo "catalog-owned WireGuard interface $interface is still active" >&2
				exit 1
				;;
			esac
		done
	fi
}

[ "$#" -eq 1 ] || usage

case $1 in
install)
	[ -x ./tunnelfolio ] || {
		echo "build ./tunnelfolio before installing" >&2
		exit 1
	}
	install -d -m 0755 "$destdir$prefix/bin"
	install -d -m 0755 "$destdir$unitdir"
	install -d -m 0755 "$destdir$tmpfilesdir"
	install -d -m 0700 \
		"$destdir$sysconfdir" \
		"$destdir$sysconfdir/profiles" \
		"$destdir$sysconfdir/profiles/openvpn" \
		"$destdir$sysconfdir/profiles/openvpn/generic" \
		"$destdir$sysconfdir/profiles/wireguard" \
		"$destdir$sysconfdir/profiles/wireguard/generic" \
		"$destdir$statedir"
	if [ ! -e "$destdir$sysconfdir/proxy-token" ]; then
		umask 077
		od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > "$destdir$sysconfdir/proxy-token"
	fi
	install -m 0755 ./tunnelfolio "$destdir$prefix/bin/tunnelfolio"
	install -m 0644 ./tunnelfolio.service "$destdir$unitdir/tunnelfolio.service"
	install -m 0644 ./tunnelfolio.tmpfiles.conf "$destdir$tmpfilesdir/tunnelfolio.conf"
	if [ -z "$destdir" ]; then
		systemd-tmpfiles --create "$tmpfilesdir/tunnelfolio.conf"
		systemctl daemon-reload
		systemctl enable tunnelfolio.service
		systemctl restart tunnelfolio.service
	fi
	;;
check-disconnected)
	check_disconnected
	;;
uninstall)
	if [ -z "$destdir" ]; then
		check_disconnected
		systemctl disable tunnelfolio.service
	fi
	rm -f \
		"$destdir$prefix/bin/tunnelfolio" \
		"$destdir$unitdir/tunnelfolio.service" \
		"$destdir$tmpfilesdir/tunnelfolio.conf"
	if [ -z "$destdir" ]; then
		systemctl daemon-reload
	fi
	;;
*)
	usage
	;;
esac
