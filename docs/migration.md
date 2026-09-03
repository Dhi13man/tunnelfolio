# Migrating an existing VPN profile manager

This procedure imports eligible OpenVPN and WireGuard client profiles into Tunnelfolio without rewriting or deleting the source files.

Tunnelfolio v0.1.0 has no compatibility layer for an unreleased predecessor catalog. It assigns new opaque IDs and stores accepted profiles under `/var/lib/tunnelfolio`. Keep the old manager and files recoverable until the replacement passes your rollback rehearsal and soak.

## Prerequisites

- Local administrative access that does not depend on the VPN being migrated.
- A tested host-local rollback path.
- A root-only backup of the old binary, unit, state, profiles, referenced secrets, and proxy configuration.
- A verified Tunnelfolio binary and matching systemd unit.
- `openvpn` and/or `wg` plus `wg-quick` for the protocols being migrated.
- An authenticated same-host HTTPS proxy route to Tunnelfolio.

## Classify source profiles

Browser import accepts only self-contained, non-interactive files:

- OpenVPN: one `.ovpn` file with inline certificates and keys. External references, credential prompts, includes, scripts, plugins, management interfaces, daemonization, and arbitrary output paths are rejected.
- WireGuard: one `.conf` file in the supported `wg-quick` subset. `PreUp`, `PostUp`, `PreDown`, `PostDown`, and `SaveConfig` are rejected.

Do not weaken the policy to force a migration. Retain unsupported source profiles with the old manager until they can be converted by their trusted issuer or a separate design supports them safely.

## Prepare the cutover

1. Back up the existing manager and verify the archive.
2. Record the current active profile, favorites, recents, resolver state, routes, and outbound connectivity without recording secret profile contents.
3. Do not run the normal installer while the incumbent still owns Tunnelfolio's production port or paths. Extract the verified candidate under a root-owned `0700` staging directory instead.
4. If profiles must be imported before downtime, run a transient `tunnelfolio-prepare` unit on an unused loopback address such as `127.0.0.1:50003`, with an isolated state directory and proxy-token file. Put a temporary authenticated same-host proxy on a different listener, such as `127.0.0.1:50002`, and expose only that proxy. Do not point either process at production state.
5. Keep the prepared instance disconnected in **Manual** mode. Stop it after import, inspect its exact systemd `MainPID` and control group, and prove that its managed WireGuard interface set is empty. Do not use a host-wide OpenVPN process-name search as an ownership test.
6. Arm a rollback mechanism that can restore the old manager from the local console if remote access disappears.

## Import profiles

1. Open Tunnelfolio through the authenticated proxy.
2. Select **Import profiles** and choose up to 100 source files.
3. Review protocol detection and every policy finding.
4. Set a display name, Group, and optional location. Group is an operator label such as `Mullvad`, `Work`, or `Home Lab`; it is not verified provider provenance.
5. Confirm trust and import.
6. Repeat until the intended eligible profile set is present.

Import preserves accepted bytes, detects exact duplicates, publishes each batch atomically, and never connects a profile. Tunnelfolio does not preserve old path-based IDs. Recreate favorites and recents through the interface only when the source mapping is unambiguous.

## Verify before stopping the old manager

Use read-only operations only. Confirm:

- `/healthz` reports the expected protocol tools;
- the profile count and metadata match the intended source set;
- direct requests to the selected prepared listener (`127.0.0.1:50003` in this example) without proxy assertions return `401`;
- the temporary authenticated proxy returns the prepared interface and profile inventory;
- the old manager still owns the current network state;
- Tunnelfolio has not created an OpenVPN process or WireGuard interface.

Do not run two mutable managers against the same network profiles.

## Cut over

1. Disconnect through the old manager.
2. Stop it and prove its OpenVPN processes, WireGuard interfaces, routes, and resolver changes absent.
3. Stop and collect the prepared transient unit and remove its temporary proxy route. Prove its exact control group empty before continuing.
4. Run `sudo ./install.sh install-stopped` from the verified candidate only now. Copy the verified contents of prepared managed state into the empty production state directory with root ownership and private modes, or import again through the production instance; do not merge manifests by hand.
5. Configure the production authenticated proxy, then enable and start Tunnelfolio. Verify health plus inventory before connecting.
6. Connect one known-good profile for each imported protocol.
7. Test same-protocol and cross-protocol switches in both directions.
8. Test a failed target and verify that the prior working profile is restored.
9. Disconnect and verify interface, process, route, resolver, and egress cleanup.
10. If restart restoration is wanted, choose **Restore the last desired profile** in Settings, reconnect the intended profile, and test both service restart and host reboot.
11. Rehearse rollback once, then repeat the forward cutover from the same verified artifacts.

During the soak, compare authenticated `/api/status` with the exact observed OpenVPN process or WireGuard interface. A connected WireGuard profile should have one matching managed interface; require an empty managed interface set only after disconnect and stop.

## Roll back

1. Disconnect through Tunnelfolio and confirm `disconnected`.
2. Stop the service and run the candidate archive's absence check:

   ```bash
   sudo systemctl stop tunnelfolio
   sudo ./install.sh check-disconnected
   ```

3. Restore the old binary, unit, state, files, and proxy route only after the check passes.
4. Start the old manager and verify its authenticated health plus one known-good connection.

If the Tunnelfolio API is unavailable, use the ownership-safe local-console procedure in the [operations runbook](operations.md#roll-back). Never start the old manager while a Tunnelfolio-owned network resource may remain.

Keep the source profiles and verified rollback backup until the final Tunnelfolio artifact has passed the operator-selected soak and at least one later verified release or 30 days have passed, whichever is later.
