#!/bin/sh
set -eu

[ "$(id -u)" -eq 0 ] || {
	echo "network namespace test must run as root" >&2
	exit 1
}
for command in go ip wg wg-quick openvpn openssl curl; do
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
	ip netns exec "$namespace" wg-quick down "$fixture/profiles/wireguard/generic/wgtest.conf" >/dev/null 2>&1 || true
	ip netns delete "$namespace" 2>/dev/null || true
	[ ! -e "$fixture" ] || find "$fixture" -depth -delete
	[ ! -e "$binary" ] || find "$binary" -delete
	[ ! -e "$netns_config" ] || find "$netns_config" -depth -delete
	return "$status"
}
trap cleanup EXIT HUP INT TERM

install -d -m 0700 \
	"$fixture" \
	"$fixture/profiles" \
	"$fixture/profiles/openvpn" \
	"$fixture/profiles/openvpn/generic" \
	"$fixture/profiles/wireguard" \
	"$fixture/profiles/wireguard/generic" \
	"$fixture/state" \
	"$netns_config"
printf 'nameserver 192.0.2.53\n' > "$netns_config/resolv.conf"
printf 'nameserver 192.0.2.53\n' > "$fixture/initial-resolv.conf"
chmod 0600 "$netns_config/resolv.conf"
proxy_token=tunnelfolio-test-proxy-token-value
printf '%s\n' "$proxy_token" > "$fixture/proxy-token"
chmod 0600 "$fixture/proxy-token"

private_key=$(wg genkey)
cat > "$fixture/profiles/wireguard/generic/wgtest.conf" <<EOF
[Interface]
PrivateKey = $private_key
Address = 192.0.2.1/32
Table = off
PostUp = ip route add 198.51.100.1/32 dev %i table 12345
PostUp = printf 'nameserver 203.0.113.53\n' > /etc/resolv.conf
PreDown = ip route del 198.51.100.1/32 dev %i table 12345
PreDown = cat $fixture/initial-resolv.conf > /etc/resolv.conf

[Peer]
PublicKey = $(printf '%s' "$private_key" | wg pubkey)
AllowedIPs = 198.51.100.1/32
Endpoint = 192.0.2.2:51820
EOF
cat > "$fixture/profiles/wireguard/generic/broken.conf" <<'EOF'
[Interface]
PrivateKey = invalid
Address = 192.0.2.3/32
EOF
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
	-keyout "$fixture/profiles/openvpn/generic/ca.key" \
	-out "$fixture/profiles/openvpn/generic/ca.crt" \
	-subj /CN=TunnelfolioTestCA >/dev/null 2>&1
for identity in server client; do
	openssl req -newkey rsa:2048 -nodes \
		-keyout "$fixture/profiles/openvpn/generic/$identity.key" \
		-out "$fixture/$identity.csr" \
		-subj "/CN=TunnelfolioTest$identity" >/dev/null 2>&1
	printf 'keyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=%sAuth\n' "$identity" > "$fixture/$identity.ext"
	openssl x509 -req -days 1 \
		-in "$fixture/$identity.csr" \
		-CA "$fixture/profiles/openvpn/generic/ca.crt" \
		-CAkey "$fixture/profiles/openvpn/generic/ca.key" \
		-set_serial "$(test "$identity" = server && printf 1 || printf 2)" \
		-extfile "$fixture/$identity.ext" \
		-out "$fixture/profiles/openvpn/generic/$identity.crt" >/dev/null 2>&1
done
cat > "$fixture/profiles/openvpn/generic/null.ovpn" <<'EOF'
client
dev tunclient
proto udp
remote 127.0.0.1 11940
nobind
ca ca.crt
cert client.crt
key client.key
remote-cert-tls server
auth-nocache
verb 3
EOF
cat > "$fixture/openvpn-server.conf" <<EOF
dev tunserver
proto udp
local 127.0.0.1
port 11940
topology subnet
server 10.8.0.0 255.255.255.0
tls-server
ca $fixture/profiles/openvpn/generic/ca.crt
cert $fixture/profiles/openvpn/generic/server.crt
key $fixture/profiles/openvpn/generic/server.key
dh none
keepalive 1 10
verb 3
EOF
chmod 0600 "$fixture/profiles/wireguard/generic/"*.conf "$fixture/profiles/openvpn/generic/"* "$fixture/openvpn-server.conf"

(cd "$source_root" && go build -trimpath -o "$binary" .)
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

assert_resolver_restored() {
	if ! cmp "$fixture/initial-resolv.conf" "$netns_config/resolv.conf"; then
		echo "expected resolver:" >&2
		cat "$fixture/initial-resolv.conf" >&2
		echo "actual resolver:" >&2
		cat "$netns_config/resolv.conf" >&2
		return 1
	fi
}

start_manager() {
	ip netns exec "$namespace" env PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
		"$binary" \
		--listen 127.0.0.1:50001 \
		--profiles-dir "$fixture/profiles" \
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

start_manager
grep -F '"live":true' "$fixture/health.json"

request POST /api/connect '{"profile":"wireguard/generic/wgtest"}' > "$fixture/connect-wg.json"
ip netns exec "$namespace" ip link show wgtest >/dev/null
ip netns exec "$namespace" ip route show table 12345 198.51.100.1/32 | grep -F 'dev wgtest'
ip netns exec "$namespace" grep -F 'nameserver 203.0.113.53' /etc/resolv.conf

crash_manager
ip netns exec "$namespace" ip link show wgtest >/dev/null
start_manager
request GET /api/status > "$fixture/status-wg-restarted.json"
grep -F 'wireguard/generic/wgtest' "$fixture/status-wg-restarted.json"
request POST /api/disconnect '{}' > "$fixture/disconnect-after-wg-restart.json"
assert_resolver_restored
request POST /api/connect '{"profile":"wireguard/generic/wgtest"}' > "$fixture/reconnect-wg.json"

request POST /api/connect '{"profile":"openvpn/generic/null"}' > "$fixture/connect-openvpn.json"
if ip netns exec "$namespace" ip link show wgtest >/dev/null 2>&1; then
	echo "WireGuard interface survived a cross-backend switch" >&2
	exit 1
fi
assert_resolver_restored
request GET /api/status > "$fixture/status-openvpn.json"
grep -F 'openvpn/generic/null' "$fixture/status-openvpn.json"
ip netns exec "$namespace" ip link show tunclient >/dev/null

crash_manager
openvpn_gone=false
for unused in 1 2 3 4 5 6 7 8 9 10; do
	if ! ip netns exec "$namespace" ip link show tunclient >/dev/null 2>&1 && \
		! pgrep -f "^.*openvpn --config $fixture/profiles/openvpn/generic/null.ovpn$" >/dev/null; then
		openvpn_gone=true
		break
	fi
	sleep 0.2
done
test "$openvpn_gone" = true
start_manager
request GET /api/status > "$fixture/status-openvpn-restarted.json"
grep -F '"lifecycle":"disconnected"' "$fixture/status-openvpn-restarted.json"
request POST /api/connect '{"profile":"openvpn/generic/null"}' > "$fixture/reconnect-openvpn.json"

if request POST /api/connect '{"profile":"wireguard/generic/broken"}' > "$fixture/broken.json" 2>/dev/null; then
	echo "invalid WireGuard profile connected" >&2
	exit 1
fi
request GET /api/status > "$fixture/status-restored.json"
grep -F 'openvpn/generic/null' "$fixture/status-restored.json"
assert_resolver_restored

request POST /api/connect '{"profile":"wireguard/generic/wgtest"}' > "$fixture/cross-back.json"
ip netns exec "$namespace" ip link show wgtest >/dev/null
request POST /api/disconnect '{}' > "$fixture/disconnect.json"
if ip netns exec "$namespace" ip link show wgtest >/dev/null 2>&1; then
	echo "WireGuard interface survived disconnect" >&2
	exit 1
fi
request GET /api/status > "$fixture/status-disconnected.json"
grep -F '"lifecycle":"disconnected"' "$fixture/status-disconnected.json"
test -z "$(ip netns exec "$namespace" wg show interfaces)"
test -z "$(ip netns exec "$namespace" ip route show table 12345 198.51.100.1/32)"
assert_resolver_restored
test -z "$(wg show interfaces | tr ' ' '\n' | grep -Fx wgtest || true)"
