#!/bin/sh
set -eu

prefix=${PREFIX:-/usr/local}
sysconfdir=${SYSCONFDIR:-/etc/tunnelfolio}
statedir=${STATEDIR:-/var/lib/tunnelfolio}
unitdir=${UNITDIR:-/etc/systemd/system}
tmpfilesdir=${TMPFILESDIR:-/usr/lib/tmpfiles.d}
destdir=${DESTDIR:-}
cutover_root=${CUTOVER_ROOT:-/var/lib/tunnelfolio-cutover}
prepared_root=${statedir}-v0.1.0-next

usage() {
	echo "usage: $0 install|install-stopped|check-disconnected|uninstall" >&2
	exit 2
}

path_exists() {
	[ -e "$1" ] || [ -L "$1" ]
}

check_private_directory() {
	directory=$1
	description=$2
	[ -d "$directory" ] && [ ! -L "$directory" ] || {
		echo "$description is not a real directory: $directory" >&2
		return 1
	}
	owner=$(stat -c %u -- "$directory") || {
		echo "cannot inspect ownership for $description: $directory" >&2
		return 1
	}
	permissions=$(stat -c %A -- "$directory") || {
		echo "cannot inspect permissions for $description: $directory" >&2
		return 1
	}
	if [ "$(id -u)" -eq 0 ] && [ "$owner" -ne 0 ]; then
		echo "$description is not owned by root: $directory" >&2
		return 1
	fi
	case $permissions in
	d???------) ;;
	*)
		echo "$description is not private: $directory" >&2
		return 1
		;;
	esac
}

check_private_file() {
	file=$1
	description=$2
	[ -f "$file" ] && [ ! -L "$file" ] || {
		echo "$description is not a real file: $file" >&2
		return 1
	}
	owner=$(stat -c %u -- "$file") || {
		echo "cannot inspect ownership for $description: $file" >&2
		return 1
	}
	permissions=$(stat -c %A -- "$file") || {
		echo "cannot inspect permissions for $description: $file" >&2
		return 1
	}
	if [ "$(id -u)" -eq 0 ] && [ "$owner" -ne 0 ]; then
		echo "$description is not owned by root: $file" >&2
		return 1
	fi
	case $permissions in
	-???------) ;;
	*)
		echo "$description is not private: $file" >&2
		return 1
		;;
	esac
}

check_optional_private_directory() {
	directory=$1
	description=$2
	path_exists "$directory" || return 0
	check_private_directory "$directory" "$description"
}

check_wireguard_tree() {
	root=$1
	path_exists "$root" || return 0
	check_private_directory "$root" "WireGuard profile root"
	for profile_dir in "$root"/*; do
		path_exists "$profile_dir" || continue
		check_private_directory "$profile_dir" "WireGuard profile directory"
		profile_name=${profile_dir##*/}
		case $profile_name in
		"" | *[!A-Za-z0-9_.-]*)
			echo "invalid WireGuard profile directory name in $root" >&2
			return 1
			;;
		esac
		for profile in "$profile_dir"/*; do
			path_exists "$profile" || continue
			check_private_file "$profile" "WireGuard profile"
			case $profile in
			*.conf) ;;
			*)
				echo "unexpected file in WireGuard profile directory $profile_dir" >&2
				return 1
				;;
			esac
			interface=${profile##*/}
			interface=${interface%.conf}
			case $interface in
			"" | *[!A-Za-z0-9_=+.-]*)
				echo "invalid WireGuard interface name in $profile_dir" >&2
				return 1
				;;
			esac
			case $active_interfaces in
			*" $interface "*)
				echo "catalog-owned WireGuard interface $interface is still active" >&2
				return 1
				;;
			esac
		done
	done
}

check_managed_resources_absent() {
	catalog_present=false
	if path_exists "$statedir"; then
		check_private_directory "$statedir" "Tunnelfolio state root"
		check_optional_private_directory "$statedir/library" "Tunnelfolio library root"
		if path_exists "$statedir/library/wireguard"; then
			catalog_present=true
		fi
	fi
	if path_exists "$prepared_root"; then
		check_private_directory "$prepared_root" "prepared Tunnelfolio state root"
		check_optional_private_directory "$prepared_root/library" "prepared Tunnelfolio library root"
		if path_exists "$prepared_root/library/wireguard"; then
			catalog_present=true
		fi
	fi
	if path_exists "$cutover_root"; then
		check_private_directory "$cutover_root" "Tunnelfolio cutover root"
		for stage in "$cutover_root"/*; do
			path_exists "$stage" || continue
			check_private_directory "$stage" "Tunnelfolio cutover stage"
			stage_name=${stage##*/}
			case $stage_name in
			"" | *[!A-Za-z0-9_.-]*)
				echo "invalid Tunnelfolio cutover stage name in $cutover_root" >&2
				return 1
				;;
			esac
			for directory in "$stage/config" "$stage/config/profiles" "$stage/state" "$stage/state/library"; do
				check_optional_private_directory "$directory" "Tunnelfolio cutover directory"
			done
			if path_exists "$stage/config/profiles/wireguard" || path_exists "$stage/state/library/wireguard"; then
				catalog_present=true
			fi
		done
	fi
	if [ "$catalog_present" = true ]; then
		command -v wg >/dev/null 2>&1 || {
			echo "cannot prove WireGuard interfaces absent because wg is unavailable" >&2
			return 1
		}
		interfaces=$(wg show interfaces) || {
			echo "cannot query WireGuard interfaces" >&2
			return 1
		}
		active_interfaces=" $interfaces "
		check_wireguard_tree "$statedir/library/wireguard"
		check_wireguard_tree "$prepared_root/library/wireguard"
		for root in "$cutover_root"/*/config/profiles/wireguard "$cutover_root"/*/state/library/wireguard; do
			check_wireguard_tree "$root"
		done
	fi
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
	check_managed_resources_absent
}

install_stopped() {
	[ -x ./tunnelfolio ] || {
		echo "build ./tunnelfolio before installing" >&2
		return 1
	}
	if [ -z "$destdir" ]; then
		load_state=$(systemctl show -p LoadState --value tunnelfolio.service) || {
			echo "cannot query Tunnelfolio unit load state" >&2
			return 1
		}
		case $load_state in
		loaded)
			check_disconnected
			systemctl disable tunnelfolio.service
			;;
		not-found)
			check_managed_resources_absent
			;;
		*)
			echo "cannot install over Tunnelfolio unit state $load_state" >&2
			return 1
			;;
		esac
	fi
	token_stage=
	binary_stage=
	unit_stage=
	tmpfiles_stage=
	trap '[ -z "$token_stage" ] || rm -f "$token_stage"; [ -z "$binary_stage" ] || rm -f "$binary_stage"; [ -z "$unit_stage" ] || rm -f "$unit_stage"; [ -z "$tmpfiles_stage" ] || rm -f "$tmpfiles_stage"' EXIT HUP INT TERM
	install -d -m 0755 "$destdir$prefix/bin"
	install -d -m 0755 "$destdir$unitdir"
	install -d -m 0755 "$destdir$tmpfilesdir"
	install -d -m 0700 "$destdir$sysconfdir" "$destdir$statedir"
	if [ ! -e "$destdir$sysconfdir/proxy-token" ]; then
		token_stage=$(mktemp "$destdir$sysconfdir/.proxy-token.XXXXXX")
		umask 077
		od -An -N32 -tx1 /dev/urandom | tr -d ' \n' > "$token_stage"
		chmod 0600 "$token_stage"
		token_value=
		IFS= read -r token_value < "$token_stage" || :
		case $token_value in
		*[!0-9a-f]*) token_valid=false ;;
		*) token_valid=true ;;
		esac
		if [ "${#token_value}" -ne 64 ] || [ "$token_valid" != true ]; then
			echo "could not generate a complete proxy token" >&2
			return 1
		fi
		token_value=
		sync -f "$token_stage"
		mv -f "$token_stage" "$destdir$sysconfdir/proxy-token"
		token_stage=
		sync -f "$destdir$sysconfdir"
	fi
	binary_stage=$(mktemp "$destdir$prefix/bin/.tunnelfolio.XXXXXX")
	unit_stage=$(mktemp "$destdir$unitdir/.tunnelfolio.service.XXXXXX")
	tmpfiles_stage=$(mktemp "$destdir$tmpfilesdir/.tunnelfolio.conf.XXXXXX")
	install -m 0755 ./tunnelfolio "$binary_stage"
	install -m 0644 ./tunnelfolio.service "$unit_stage"
	install -m 0644 ./tunnelfolio.tmpfiles.conf "$tmpfiles_stage"
	sync -f "$binary_stage"
	sync -f "$unit_stage"
	sync -f "$tmpfiles_stage"
	mv -f "$binary_stage" "$destdir$prefix/bin/tunnelfolio"
	mv -f "$unit_stage" "$destdir$unitdir/tunnelfolio.service"
	mv -f "$tmpfiles_stage" "$destdir$tmpfilesdir/tunnelfolio.conf"
	sync -f "$destdir$prefix/bin"
	sync -f "$destdir$unitdir"
	sync -f "$destdir$tmpfilesdir"
	cmp -s ./tunnelfolio "$destdir$prefix/bin/tunnelfolio"
	cmp -s ./tunnelfolio.service "$destdir$unitdir/tunnelfolio.service"
	cmp -s ./tunnelfolio.tmpfiles.conf "$destdir$tmpfilesdir/tunnelfolio.conf"
	[ "$(stat -c %a "$destdir$prefix/bin/tunnelfolio")" = 755 ]
	[ "$(stat -c %a "$destdir$unitdir/tunnelfolio.service")" = 644 ]
	[ "$(stat -c %a "$destdir$tmpfilesdir/tunnelfolio.conf")" = 644 ]
	trap - EXIT HUP INT TERM
}

[ "$#" -eq 1 ] || usage

case $1 in
install | install-stopped)
	install_stopped
	if [ -z "$destdir" ]; then
		systemd-tmpfiles --create "$tmpfilesdir/tunnelfolio.conf"
		systemctl daemon-reload
		if [ "$1" = install ]; then
			systemctl enable tunnelfolio.service
			systemctl start tunnelfolio.service
		fi
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
