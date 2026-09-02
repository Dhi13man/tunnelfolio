#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || {
	echo "network namespace test must run as root" >&2
	exit 1
}
for command in go ip wg wg-quick openvpn openssl curl jq pgrep sed; do
	command -v "$command" >/dev/null 2>&1 || {
		echo "missing test command: $command" >&2
		exit 1
	}
done

source_root=${GITHUB_WORKSPACE:-$(pwd)}
case $source_root in
/*) ;;
*) echo "source root must be absolute" >&2; exit 1 ;;
esac
namespace=tunnelfolio-ci-$$
fixture=/run/$namespace
binary=/tmp/$namespace
netns_config=/etc/netns/$namespace
manager_pid=
openvpn_server_pid=
wireguard_object=
cleanup() {
	status=$?
	if [ "$status" -ne 0 ]; then
		for log in "$fixture/server.log" "$fixture/openvpn-server.log"; do
			if [ -f "$log" ]; then
				echo "--- ${log##*/} (tail)" >&2
				tail -n 40 "$log" >&2
			fi
		done
	fi
	if [ -n "$manager_pid" ]; then
		kill "$manager_pid" 2>/dev/null || true
		wait "$manager_pid" 2>/dev/null || true
	fi
	if [ -n "$openvpn_server_pid" ]; then
		kill "$openvpn_server_pid" 2>/dev/null || true
		wait "$openvpn_server_pid" 2>/dev/null || true
	fi
	if [ -n "$wireguard_object" ]; then
		ip netns exec "$namespace" wg-quick down "$wireguard_object" >/dev/null 2>&1 || true
	fi
	ip netns delete "$namespace" 2>/dev/null || true
	[ ! -e "$fixture" ] || find "$fixture" -depth -delete
	[ ! -e "$binary" ] || find "$binary" -delete
	[ ! -e "$netns_config" ] || find "$netns_config" -depth -delete
	return "$status"
}
trap cleanup EXIT HUP INT TERM

install -d -m 0700 "$fixture" "$fixture/certs" "$fixture/state" "$netns_config"
printf 'nameserver 192.0.2.53\n' > "$netns_config/resolv.conf"
chmod 0600 "$netns_config/resolv.conf"
proxy_token=tunnelfolio-test-proxy-token-value
printf '%s\n' "$proxy_token" > "$fixture/proxy-token"
chmod 0600 "$fixture/proxy-token"

private_key=$(wg genkey)
peer_key=$(printf '%s' "$private_key" | wg pubkey)
cat > "$fixture/wgtest.conf" <<EOF
[Interface]
PrivateKey = $private_key
Address = 192.0.2.1/32
Table = off

[Peer]
PublicKey = $peer_key
AllowedIPs = 198.51.100.1/32
Endpoint = 192.0.2.2:51820
EOF
second_private_key=$(wg genkey)
second_peer_key=$(printf '%s' "$second_private_key" | wg pubkey)
cat > "$fixture/wgsecond.conf" <<EOF
[Interface]
PrivateKey = $second_private_key
Address = 192.0.2.3/32
Table = off

[Peer]
PublicKey = $second_peer_key
AllowedIPs = 198.51.100.2/32
Endpoint = 192.0.2.4:51820
EOF
broken_private_key=$(wg genkey)
broken_peer_key=$(printf '%s' "$broken_private_key" | wg pubkey)
cat > "$fixture/broken.conf" <<EOF
[Interface]
PrivateKey = $broken_private_key
Address = 192.0.2.5/32
Table = off

[Peer]
PublicKey = $broken_peer_key
AllowedIPs = 198.51.100.3/32
Endpoint = 192.0.2.6:51820
EOF
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
	-keyout "$fixture/certs/ca.key" \
	-out "$fixture/certs/ca.crt" \
	-subj /CN=TunnelfolioTestCA >/dev/null 2>&1
for identity in server client; do
	openssl req -newkey rsa:2048 -nodes \
		-keyout "$fixture/certs/$identity.key" \
		-out "$fixture/$identity.csr" \
		-subj "/CN=TunnelfolioTest$identity" >/dev/null 2>&1
	printf 'keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=%sAuth\n' "$identity" > "$fixture/$identity.ext"
	openssl x509 -req -days 1 \
		-in "$fixture/$identity.csr" \
		-CA "$fixture/certs/ca.crt" \
		-CAkey "$fixture/certs/ca.key" \
		-set_serial "$(test "$identity" = server && printf 1 || printf 2)" \
		-extfile "$fixture/$identity.ext" \
		-out "$fixture/certs/$identity.crt" >/dev/null 2>&1
done
{
	printf '%s\n' \
		'client' \
		'dev tunclient' \
		'proto udp' \
		'remote 127.0.0.1 11940' \
		'nobind' \
		'remote-cert-tls server' \
		'auth-nocache' \
		'<ca>'
	cat "$fixture/certs/ca.crt"
	printf '%s\n' '</ca>' '<cert>'
	cat "$fixture/certs/client.crt"
	printf '%s\n' '</cert>' '<key>'
	cat "$fixture/certs/client.key"
	printf '%s\n' '</key>'
} > "$fixture/null.ovpn"
sed 's/^dev tunclient$/dev tunsecond/' "$fixture/null.ovpn" > "$fixture/second.ovpn"
cat > "$fixture/openvpn-server.conf" <<EOF
dev tunserver
proto udp
local 127.0.0.1
port 11940
topology subnet
server 10.8.0.0 255.255.255.0
tls-server
ca $fixture/certs/ca.crt
cert $fixture/certs/server.crt
key $fixture/certs/server.key
dh none
keepalive 1 10
verb 3
EOF
chmod 0600 "$fixture/"*.conf "$fixture/"*.ovpn "$fixture/certs/"* "$fixture/openvpn-server.conf"

(cd "$source_root" && go build -trimpath -o "$binary" ./cmd/tunnelfolio)
ip netns add "$namespace"
ip netns exec "$namespace" ip link set lo up
ip netns exec "$namespace" openvpn --config "$fixture/openvpn-server.conf" \
	>"$fixture/openvpn-server.log" 2>&1 &
openvpn_server_pid=$!
sleep 0.5

request() {
	method=$1
	path=$2
	body=${3-}
	set -- --silent --show-error --fail --max-time 40 \
		--header "X-Tunnelfolio-Proxy-Token: $proxy_token" \
		--header 'X-Forwarded-Proto: https' \
		--header 'X-Forwarded-Host: vpn.example.test' \
		--header 'X-Remote-User: ci' \
		--request "$method"
	if [ "$method" != GET ]; then
		set -- "$@" --header 'Origin: https://vpn.example.test' --header 'Content-Type: application/json'
	fi
	if [ -n "$body" ]; then
		set -- "$@" --data "$body"
	fi
	ip netns exec "$namespace" curl "$@" "http://127.0.0.1:50001$path"
}

request_form() {
	path=$1
	shift
	set -- --silent --show-error --fail --max-time 40 \
		--header "X-Tunnelfolio-Proxy-Token: $proxy_token" \
		--header 'X-Forwarded-Proto: https' \
		--header 'X-Forwarded-Host: vpn.example.test' \
		--header 'X-Remote-User: ci' \
		--header 'Origin: https://vpn.example.test' \
		"$@"
	ip netns exec "$namespace" curl "$@" "http://127.0.0.1:50001$path"
}

start_manager() {
	ip netns exec "$namespace" env PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
		"$binary" \
		--listen 127.0.0.1:50001 \
		--state-dir "$fixture/state" \
		--trusted-proxy \
		--proxy-token-file "$fixture/proxy-token" \
		>>"$fixture/server.log" 2>&1 &
	manager_pid=$!
	ready=false
	for unused in 1 2 3 4 5 6 7 8 9 10; do
		if request GET /healthz > "$fixture/health.json" 2>/dev/null; then
			ready=true
			break
		fi
		sleep 0.2
	done
	test "$ready" = true
}

crash_manager() {
	kill -KILL "$manager_pid"
	wait "$manager_pid" 2>/dev/null || true
	manager_pid=
}

import_profile() {
	profile_path=$1
	filename=$2
	result_path=$3
	request_form /api/imports/inspect -F "files=@$profile_path;filename=$filename" > "$fixture/inspect.json"
	jq -e '.commit_ready == true and (.inspection_records | length == 1)' "$fixture/inspect.json" >/dev/null
	records=$(jq -c '.inspection_records' "$fixture/inspect.json")
	receipt=$(jq -r '.receipt' "$fixture/inspect.json")
	revision=$(jq -r '.library_revision' "$fixture/inspect.json")
	metadata=$(jq -c '{"0": {"display_name": .suggestions[0].display_name, "group": "Tests", "location": "Lab"}}' "$fixture/inspect.json")
	request_form /api/profiles/import \
		-F "files=@$profile_path;filename=$filename" \
		-F "inspection_records=$records" \
		-F "metadata=$metadata" \
		-F "receipt=$receipt" \
		-F "library_revision=$revision" \
		-F 'trust_profile_policy=true' > "$result_path"
	jq -e '.records[0].result == "imported"' "$result_path" >/dev/null
}

wait_for_lifecycle() {
	result_path=$1
	expected=$2
	temporary=$result_path.tmp
	attempt=0
	while [ "$attempt" -lt 175 ]; do
		attempt=$((attempt + 1))
		if request GET /api/status > "$temporary" 2>/dev/null &&
			jq -e --arg expected "$expected" '.lifecycle == $expected' "$temporary" >/dev/null; then
			mv "$temporary" "$result_path"
			return 0
		fi
		sleep 0.2
	done
	[ ! -f "$temporary" ] || mv "$temporary" "$result_path"
	echo "status did not reach lifecycle $expected" >&2
	return 1
}

openvpn_client_pids() {
	pgrep -f "^.*openvpn --config $fixture/state/library/\\.executions/exec-[^/]*/profile\\.ovpn --verb 3 --suppress-timestamps$" || true
}

wait_for_openvpn_absence() {
	device=$1
	attempt=0
	while [ "$attempt" -lt 50 ]; do
		attempt=$((attempt + 1))
		if ! ip netns exec "$namespace" ip link show "$device" >/dev/null 2>&1 &&
			[ -z "$(openvpn_client_pids)" ]; then
			return 0
		fi
		sleep 0.2
	done
	echo "OpenVPN state did not become absent for $device" >&2
	return 1
}

start_manager
grep -F '"live":true' "$fixture/health.json"
import_profile "$fixture/wgtest.conf" wgtest.conf "$fixture/import-wg.json"
import_profile "$fixture/wgsecond.conf" wgsecond.conf "$fixture/import-wg-second.json"
import_profile "$fixture/null.ovpn" null.ovpn "$fixture/import-openvpn.json"
import_profile "$fixture/second.ovpn" second.ovpn "$fixture/import-openvpn-second.json"
import_profile "$fixture/broken.conf" broken.conf "$fixture/import-broken.json"

wireguard_id=$(jq -r '.records[0].profile.id' "$fixture/import-wg.json")
wireguard_identifier=$(jq -r '.records[0].profile.identifier' "$fixture/import-wg.json")
wireguard_second_id=$(jq -r '.records[0].profile.id' "$fixture/import-wg-second.json")
wireguard_second_identifier=$(jq -r '.records[0].profile.identifier' "$fixture/import-wg-second.json")
openvpn_id=$(jq -r '.records[0].profile.id' "$fixture/import-openvpn.json")
openvpn_second_id=$(jq -r '.records[0].profile.id' "$fixture/import-openvpn-second.json")
broken_id=$(jq -r '.records[0].profile.id' "$fixture/import-broken.json")
broken_identifier=$(jq -r '.records[0].profile.identifier' "$fixture/import-broken.json")
wireguard_object="$fixture/state/library/wireguard/$wireguard_id/$wireguard_identifier.conf"
broken_object="$fixture/state/library/wireguard/$broken_id/$broken_identifier.conf"

request GET /api/profiles > "$fixture/profiles.json"
jq -e \
	--arg wg "$wireguard_id" \
	--arg wg_second "$wireguard_second_id" \
	--arg ovpn "$openvpn_id" \
	--arg ovpn_second "$openvpn_second_id" \
	--arg broken "$broken_id" \
	'length == 5 and any(.id == $wg) and any(.id == $wg_second) and any(.id == $ovpn) and any(.id == $ovpn_second) and any(.id == $broken)' \
	"$fixture/profiles.json" >/dev/null

request POST /api/connect "{\"profile\":\"$wireguard_id\"}" > "$fixture/connect-wg.json"
ip netns exec "$namespace" ip link show "$wireguard_identifier" >/dev/null
request POST /api/connect "{\"profile\":\"$wireguard_second_id\"}" > "$fixture/switch-wg.json"
if ip netns exec "$namespace" ip link show "$wireguard_identifier" >/dev/null 2>&1; then
	echo "previous WireGuard interface survived a same-protocol switch" >&2
	exit 1
fi
ip netns exec "$namespace" ip link show "$wireguard_second_identifier" >/dev/null
request GET /api/status > "$fixture/status-wg-second.json"
jq -e --arg id "$wireguard_second_id" '.lifecycle == "active" and .connected == true and .profile.id == $id' \
	"$fixture/status-wg-second.json" >/dev/null

crash_manager
ip netns exec "$namespace" ip link show "$wireguard_second_identifier" >/dev/null
start_manager
wait_for_lifecycle "$fixture/status-wg-restarted.json" active
jq -e --arg id "$wireguard_second_id" '.connected == true and .profile.id == $id' "$fixture/status-wg-restarted.json" >/dev/null
request POST /api/disconnect > "$fixture/disconnect-after-wg-restart.json"
request POST /api/connect "{\"profile\":\"$wireguard_id\"}" > "$fixture/reconnect-wg.json"

request POST /api/connect "{\"profile\":\"$openvpn_id\"}" > "$fixture/connect-openvpn.json"
if ip netns exec "$namespace" ip link show "$wireguard_identifier" >/dev/null 2>&1; then
	echo "WireGuard interface survived a cross-backend switch" >&2
	exit 1
fi
request GET /api/status > "$fixture/status-openvpn.json"
jq -e --arg id "$openvpn_id" '.connected == true and .profile.id == $id' "$fixture/status-openvpn.json" >/dev/null
ip netns exec "$namespace" ip link show tunclient >/dev/null
test "$(openvpn_client_pids | wc -l)" -eq 1
request POST /api/connect "{\"profile\":\"$openvpn_second_id\"}" > "$fixture/switch-openvpn.json"
if ip netns exec "$namespace" ip link show tunclient >/dev/null 2>&1; then
	echo "previous OpenVPN interface survived a same-protocol switch" >&2
	exit 1
fi
ip netns exec "$namespace" ip link show tunsecond >/dev/null
test "$(openvpn_client_pids | wc -l)" -eq 1
request GET /api/status > "$fixture/status-openvpn-second.json"
jq -e --arg id "$openvpn_second_id" '.lifecycle == "active" and .connected == true and .profile.id == $id' \
	"$fixture/status-openvpn-second.json" >/dev/null

crash_manager
wait_for_openvpn_absence tunsecond
start_manager
wait_for_lifecycle "$fixture/status-openvpn-restarted.json" disconnected
jq -e '.connected == false and .observation_available == true' "$fixture/status-openvpn-restarted.json" >/dev/null
jq -e --arg id "$openvpn_second_id" \
	'.startup_mode == "manual" and .desired_profile == $id' "$fixture/state/manifest.json" >/dev/null

request POST /api/connect "{\"profile\":\"$openvpn_second_id\"}" > "$fixture/reconnect-openvpn.json"
request PUT /api/preferences '{"favorites":[],"recents":[],"startup_mode":"restore"}' > "$fixture/preferences-restore.json"
jq -e '.favorites == [] and .recents == [] and .startup_mode == "restore"' "$fixture/preferences-restore.json" >/dev/null
crash_manager
wait_for_openvpn_absence tunsecond
start_manager
wait_for_lifecycle "$fixture/status-openvpn-restored.json" active
jq -e --arg id "$openvpn_second_id" '.connected == true and .profile.id == $id and .observation_available == true' \
	"$fixture/status-openvpn-restored.json" >/dev/null
ip netns exec "$namespace" ip link show tunsecond >/dev/null
request GET /api/preferences > "$fixture/preferences-restored.json"
jq -e '.startup_mode == "restore"' "$fixture/preferences-restored.json" >/dev/null
jq -e --arg id "$openvpn_second_id" \
	'.startup_mode == "restore" and .desired_profile == $id' "$fixture/state/manifest.json" >/dev/null

printf '[Interface]\nPrivateKey = invalid\nAddress = 192.0.2.5/32\n' > "$broken_object"
chmod 0600 "$broken_object"
if request POST /api/connect "{\"profile\":\"$broken_id\"}" > "$fixture/broken.json" 2>/dev/null; then
	echo "invalid WireGuard profile connected" >&2
	exit 1
fi
request GET /api/status > "$fixture/status-restored.json"
jq -e --arg id "$openvpn_second_id" '.connected == true and .profile.id == $id' "$fixture/status-restored.json" >/dev/null
ip netns exec "$namespace" ip link show tunsecond >/dev/null
if ip netns exec "$namespace" ip link show "$broken_identifier" >/dev/null 2>&1; then
	echo "failed switch left its WireGuard interface active" >&2
	exit 1
fi

request POST /api/connect "{\"profile\":\"$wireguard_id\"}" > "$fixture/cross-back.json"
ip netns exec "$namespace" ip link show "$wireguard_identifier" >/dev/null
request POST /api/disconnect > "$fixture/disconnect.json"
if ip netns exec "$namespace" ip link show "$wireguard_identifier" >/dev/null 2>&1; then
	echo "WireGuard interface survived disconnect" >&2
	exit 1
fi
request GET /api/status > "$fixture/status-disconnected.json"
jq -e '.lifecycle == "disconnected"' "$fixture/status-disconnected.json" >/dev/null

install -m 0600 "$fixture/broken.conf" "$broken_object"
request POST /api/connect "{\"profile\":\"$broken_id\"}" > "$fixture/connect-broken-valid.json"
ip netns exec "$namespace" ip link show "$broken_identifier" >/dev/null
crash_manager
ip netns exec "$namespace" ip link show "$broken_identifier" >/dev/null
ip netns exec "$namespace" wg-quick down "$broken_object" > "$fixture/down-broken.log" 2>&1
if ip netns exec "$namespace" ip link show "$broken_identifier" >/dev/null 2>&1; then
	echo "WireGuard interface survived the no-active restore setup" >&2
	exit 1
fi
printf '[Interface]\nPrivateKey = invalid\nAddress = 192.0.2.5/32\n' > "$broken_object"
chmod 0600 "$broken_object"
start_manager
wait_for_lifecycle "$fixture/status-restore-failed.json" failed
jq -e \
	'.connected == false and .observation_available == true and .profile == null and .error == "The desired profile could not be restored."' \
	"$fixture/status-restore-failed.json" >/dev/null
request GET /api/preferences > "$fixture/preferences-restore-failed.json"
jq -e '.startup_mode == "restore"' "$fixture/preferences-restore-failed.json" >/dev/null
jq -e --arg id "$broken_id" \
	'.startup_mode == "restore" and .desired_profile == $id and (.connected_at // 0) == 0' "$fixture/state/manifest.json" >/dev/null
if ip netns exec "$namespace" ip link show "$broken_identifier" >/dev/null 2>&1; then
	echo "failed startup restore left its WireGuard interface active" >&2
	exit 1
fi
if ip netns exec "$namespace" ip link show tunclient >/dev/null 2>&1 ||
	ip netns exec "$namespace" ip link show tunsecond >/dev/null 2>&1; then
	echo "failed startup restore left an OpenVPN interface active" >&2
	exit 1
fi
test -z "$(find "$fixture/state/library/.executions" -mindepth 1 -maxdepth 1 -print -quit)"
test -z "$(ip netns exec "$namespace" wg show interfaces)"
for identifier in "$wireguard_identifier" "$wireguard_second_identifier" "$broken_identifier"; do
	test -z "$(wg show interfaces | tr ' ' '\n' | grep -Fx "$identifier" || true)"
done
