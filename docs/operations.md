# Operating Tunnelfolio

This runbook covers routine health checks, safe upgrades, diagnosis, and rollback for a systemd installation.

**Last verified:** 2026-08-31

## Quick assessment

Check the service, its authenticated health endpoint, and recent logs before changing state:

```bash
sudo systemctl is-active tunnelfolio
sudo systemctl status tunnelfolio --no-pager
sudo journalctl -u tunnelfolio --since '-15 minutes' --no-pager
```

Expected service output is `active`. Query `/healthz` through the configured HTTPS reverse proxy; a healthy response contains `"live":true` and reports each backend independently. Do not expose the loopback listener or print the proxy token.

WireGuard profiles with `DNS` directives use the host resolver integration selected by `wg-quick`. The shipped unit permits the narrow runtime paths used by both `openresolv` (`/run/resolvconf`) and systemd-resolved while keeping the rest of the system read-only. It retains `CAP_KILL` because resolver update hooks may need to signal the host resolver after a DNS change.

If the service is inactive, inspect its logs before restarting it. If a backend is unavailable, verify the corresponding profile directory and command installation. If status reports `error_conflict`, use the authenticated **Disconnect** action once; it enumerates and removes every Tunnelfolio-managed profile and keeps the conflict latched unless absence is proved.

## Back up an installation

Create a root-only destination on a filesystem appropriate for your host, then copy these paths without displaying their contents:

```text
/usr/local/bin/tunnelfolio
/etc/systemd/system/tunnelfolio.service
/etc/tunnelfolio/
/var/lib/tunnelfolio/
```

Include the reverse-proxy configuration that routes to Tunnelfolio. Record SHA-256 digests for the binary and unit, and confirm the backup files are readable before an upgrade.

## Upgrade

1. Verify the release archive, checksum, and GitHub attestation as described in [release verification](release-verification.md).
2. Back up the current binary, unit, configuration, state, and proxy route.
3. Keep the verified archive contents in one directory and run:

   ```bash
   sudo ./install.sh install
   ```

4. Confirm that systemd is running the expected binary:

   ```bash
   sudo systemctl is-active tunnelfolio
   sudo sha256sum /usr/local/bin/tunnelfolio
   sudo sha256sum /proc/$(systemctl show -p MainPID --value tunnelfolio)/exe
   ```

5. Test authenticated inventory, connect, switch, and disconnect operations for every installed backend. Verify DNS and outbound routing after each transition.

The installer preserves `/etc/tunnelfolio` and `/var/lib/tunnelfolio`.

## Roll back

Use the verified backup from immediately before the upgrade.

1. While Tunnelfolio is still available, use its authenticated **Disconnect** action. Confirm that status reports `disconnected`.
2. Stop Tunnelfolio, then use the installer from the candidate archive to prove its service processes and every catalog-owned WireGuard interface are absent:

   ```bash
   sudo systemctl stop tunnelfolio
   sudo ./install.sh check-disconnected
   ```

   The check is intentionally fail-closed when `wg` is unavailable or absence cannot be established. Stopping the daemon alone is not sufficient: WireGuard interfaces survive daemon shutdown by design.
3. Restore the previous binary, unit, configuration, state, and reverse-proxy route from the root-only backup.
4. Reload and start the restored unit:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl start tunnelfolio
   sudo systemctl is-active tunnelfolio
   ```

5. Verify the authenticated health endpoint, one known-good profile, DNS, and outbound connectivity.

If the authenticated API is unavailable, use local console access. Stop the service first so systemd cleans its OpenVPN control group. For each active WireGuard interface, map its exact name to one root-owned `.conf` file under `/etc/tunnelfolio/profiles/wireguard/<provider>/`, run `wg-quick down` with that exact file, and then run `sudo ./install.sh check-disconnected`. Do not restore or start another manager until the check passes. Never kill unrelated OpenVPN processes or remove WireGuard interfaces that do not map uniquely to the staged catalog.

## Uninstall

Use the authenticated **Disconnect** action and confirm disconnected status before stopping the service. Uninstall refuses to proceed while the service is active, its control group contains a process, a catalog-owned WireGuard interface remains, or WireGuard absence cannot be queried:

```bash
sudo systemctl stop tunnelfolio
sudo ./install.sh check-disconnected
sudo ./install.sh uninstall
```

The uninstall action removes only the binary and unit. It preserves profiles, proxy token, preferences, and connection state under `/etc/tunnelfolio` and `/var/lib/tunnelfolio`.

## Diagnose common failures

| Symptom | Check | Action |
| ------ | ----- | ------ |
| Service will not start | `journalctl -u tunnelfolio -b` | Correct ownership or mode failures; do not broaden private file permissions |
| Backend unavailable | `/healthz` backend reason | Install its command tools or restore its protocol profile directory, then restart |
| `error_conflict` | `/api/status` through the proxy | Use authenticated disconnect; investigate if absence cannot be proved |
| OpenVPN profile rejected | Service log and [security policy](../SECURITY.md) | Remove unsupported supervision directives or fix confined referenced files |
| Proxy authentication rejected | Reverse-proxy logs and header configuration | Restore the same-host HTTPS proxy contract; never expose the loopback listener |

Security reports go through GitHub private vulnerability reporting. Operational support uses the repository channels in [SUPPORT.md](../SUPPORT.md); include sanitized versions, error classes, and topology, never profiles, keys, tokens, hostnames, or public addresses.

Update this runbook after every production use that reveals a missing or inaccurate step.
