# Migrating an existing VPN manager

This guide moves trusted OpenVPN and WireGuard profiles into Tunnelfolio without modifying the source profiles or inheriting an unverified connected state.

## Prerequisites

- Local administrative access and a tested rollback path.
- A root-only backup of the existing binary, service unit, state, profiles, referenced secrets, and reverse-proxy configuration.
- A verified Tunnelfolio binary and matching service unit.
- Working `openvpn`, `wg`, and `wg-quick` commands for the backends you intend to use.

## Map profiles

Tunnelfolio uses `<backend>/<provider>/<identifier>` IDs and this filesystem layout:

```text
/etc/tunnelfolio/profiles/
├── openvpn/<provider>/<identifier>.ovpn
└── wireguard/<provider>/<identifier>.conf
```

Copy profiles; do not move or rewrite the legacy source. Use `mullvad` only for Mullvad profiles and `generic` for operator-classified profiles without provider enrichment. Directories must be root-owned mode `0700`; profiles and referenced secrets must be root-owned regular files mode `0600`.

OpenVPN profiles must be non-interactive and self-contained through confined file references. Tunnelfolio rejects includes, daemonization, management interfaces, PID-file directives, and unsupported credential paths. Review every profile as root-equivalent policy before copying it.

## Migrate preferences

Map a favorite or recent value only when it identifies exactly one copied profile. Store the full new ID, such as `wireguard/mullvad/mullvad_de`. Drop ambiguous or missing entries and record the omission outside the repository.

Do not copy a legacy “connected” claim into `state.json`. Start Tunnelfolio disconnected after the legacy manager and its owned process or interface have been cleanly stopped.

## Canary the catalog

Run the verified binary in trusted-proxy, read-only mode on an unused loopback port before changing the active service:

```bash
sudo /usr/local/bin/tunnelfolio \
  --listen 127.0.0.1:50002 \
  --profiles-dir /etc/tunnelfolio/profiles \
  --state-dir /var/lib/tunnelfolio-canary \
  --trusted-proxy \
  --proxy-token-file /etc/tunnelfolio/proxy-token \
  --read-only
```

Route a temporary authenticated HTTPS proxy location to this port with the same overwritten trusted headers used by production. Expected behavior: the proxied `/healthz` reports the process live, profile inventory contains only the copied profiles, requests without valid proxy assertions are rejected, and every authenticated mutation returns `read_only`. Stop the canary and remove its temporary proxy route before production cutover.

## Cut over

1. Arm and test a host-local rollback mechanism that survives loss of remote network access.
2. Stop the legacy service and prove its managed OpenVPN process group and WireGuard interfaces are absent.
3. Install the verified Tunnelfolio binary and unit, then route the authenticated HTTPS proxy to `127.0.0.1:50001` with the required trusted headers.
4. Start Tunnelfolio and verify health plus inventory before connecting a profile.
5. Test connect, switch, disconnect, DNS, and outbound connectivity for each installed backend. Exercise cross-backend switches in both directions when both are installed.
6. Reboot the host and repeat health, cleanup, and connectivity checks.
7. Exercise the rollback once, then repeat the forward cutover from the same verified artifacts.

During the soak, compare the authenticated `/api/status` profile with the observed runtime resource. Exactly one matching OpenVPN process group or WireGuard interface is expected while connected. Do not require an empty WireGuard interface set until after authenticated disconnect and service stop, and do not trigger immediate rollback from one transient remote health sample.

Keep the legacy files and backups until the replacement has completed the operator-selected soak and at least one later verified release or 30 days have passed, whichever is later.

## Roll back

Use the authenticated **Disconnect** action, stop Tunnelfolio, and run the candidate archive's `sudo ./install.sh check-disconnected`. If the API is unavailable, use the ownership-safe local-console procedure in the [operations runbook](operations.md). Restore the backed-up service and proxy route only after the absence check passes, then verify the legacy health endpoint and one known-good connection. Preserve Tunnelfolio logs only after redacting private infrastructure and secret-bearing data.

For routine commands and diagnosis, see [Operating Tunnelfolio](operations.md).
