# Operating Tunnelfolio

Use this runbook to expose, monitor, upgrade, diagnose, roll back, or uninstall a systemd installation without losing control of the host's network path.

**Last reviewed:** 2026-09-02. Bind these examples to a deployment receipt before calling that deployment verified.

## Assess the service

Check systemd and recent logs before changing state:

```bash
sudo systemctl is-active tunnelfolio
sudo systemctl status tunnelfolio --no-pager
sudo journalctl -u tunnelfolio --since '-15 minutes' --no-pager
```

Expected service output is `active`. Query `/healthz` through the authenticated HTTPS proxy. A ready response contains `"live":true` and reports OpenVPN and WireGuard independently.

Query `/api/status` through that proxy before connecting, switching, upgrading, or rolling back. The response distinguishes disconnected, transitional, active, failed, conflict, and unavailable-observation states. A WireGuard interface without a recent handshake is active but has no handshake evidence; do not report it as a proved working tunnel.

## Expose Tunnelfolio through a private proxy

Tunnelfolio listens on `127.0.0.1:50001`. Mutable endpoints also require four assertions from a trusted same-host HTTPS proxy:

- `X-Forwarded-Proto: https`
- the original host in `X-Forwarded-Host`
- a non-empty authenticated identity in `X-Remote-User`
- the private value from `/etc/tunnelfolio/proxy-token` in `X-Tunnelfolio-Proxy-Token`

The proxy must discard caller-supplied copies before setting them. Keep its upstream listener on loopback, its token-bearing configuration root-only, and its request limit at or below 32 MiB.

### Use nginx with Basic authentication

```nginx
server {
    listen 443 ssl;
    server_name vpn.example.test;

    auth_basic "Tunnelfolio";
    auth_basic_user_file /etc/nginx/tunnelfolio.htpasswd;

    client_max_body_size 32m;

    location / {
        proxy_pass http://127.0.0.1:50001;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Remote-User $remote_user;
        proxy_set_header X-Tunnelfolio-Proxy-Token <PROXY_TOKEN>;
    }
}
```

Replace `<PROXY_TOKEN>` inside a root-only configuration, configure a valid certificate, and restrict ingress to a private network.

### Use Tailscale Serve

[Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve) can terminate private tailnet HTTPS and forward to a same-host nginx listener. Tailnet access is not sufficient authentication for that loopback listener: another local process can reach it directly. Require independent Basic authentication there, and let nginx derive `X-Remote-User` only from the authenticated Basic username.

Example nginx listener on `127.0.0.1:50002`:

```nginx
server {
    listen 127.0.0.1:50002;

    auth_basic "Tunnelfolio";
    auth_basic_user_file /etc/nginx/tunnelfolio.htpasswd;

    client_max_body_size 32m;

    location / {
        proxy_pass http://127.0.0.1:50001;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-Host <TAILNET_AUTHORITY>;
        proxy_set_header X-Remote-User $remote_user;
        proxy_set_header X-Tunnelfolio-Proxy-Token <PROXY_TOKEN>;
    }
}
```

Replace `<TAILNET_AUTHORITY>` with the exact browser authority, including the Serve port—for example, `<machine>.<tailnet>.ts.net:8443`. This fixed value prevents nginx from dropping the non-default port and constrains the origin accepted for mutations.

Expose that listener to the tailnet:

```bash
tailscale serve --bg --https=8443 http://127.0.0.1:50002
tailscale serve status
```

Confirm the status maps the tailnet-only `https://<machine>.<tailnet>.ts.net:8443/` listener to `http://127.0.0.1:50002`, then verify authenticated health:

```bash
curl --fail --user '<USER>:<PASSWORD>' \
  'https://<machine>.<tailnet>.ts.net:8443/healthz'
```

Open that same HTTPS URL and authenticate with the nginx credentials. Record the sanitized URL, port, Serve mapping, authenticated health result, and candidate digest in the deployment receipt. Do not promote `Tailscale-User-Login` from an ordinary loopback request into the trusted user header. Tunnelfolio does not require Cloudflare, Tailscale, or any provider account; these are deployment choices outside the binary. Do not use Tailscale Funnel because it makes the service public.

## Monitor a rollout

Monitor both `/healthz` and authenticated `/api/status`. Record the binary digest, manifest digest, boot ID, service state, selected profile ID, observed runtime resource, resolver state, egress result, and proxy reachability.

A connected sample passes only when the runtime resource matches the exact profile reported by `/api/status`:

- OpenVPN requires the owned process group and Tunnelfolio's readiness condition.
- WireGuard requires the exact managed interface and matching public-key identity.

Do not require an empty WireGuard interface set while a WireGuard profile is connected. Require absence after authenticated disconnect and service stop. Retry a transient remote probe before acting; one failed proxy request is not enough evidence to roll back a working local network controller.

## Back up an installation

Back up these paths to a root-only destination without displaying their contents:

```text
/usr/local/bin/tunnelfolio
/etc/systemd/system/tunnelfolio.service
/etc/tunnelfolio/
/var/lib/tunnelfolio/
```

Also preserve the same-host proxy configuration. Record SHA-256 digests for the binary, unit, manifest, and backup archive, then test that the archive is readable.

## Upgrade

1. Verify the release archive, checksum, SBOM, and GitHub attestation as described in [release verification](release-verification.md).
2. Back up the current installation and proxy route.
3. Disconnect through the authenticated UI, stop the service, and prove the managed network state absent:

   ```bash
   sudo systemctl stop tunnelfolio
   sudo ./install.sh check-disconnected
   ```

4. Place the verified archive without activating it:

   ```bash
   sudo ./install.sh install-stopped
   ```

5. Review the exact placed files, then explicitly enable and start the service:

   ```bash
   sudo systemctl enable --now tunnelfolio
   ```

6. Verify the running artifact:

   ```bash
   sudo systemctl is-active tunnelfolio
   sudo sha256sum /usr/local/bin/tunnelfolio
   sudo sha256sum /proc/$(systemctl show -p MainPID --value tunnelfolio)/exe
   ```

7. Test authenticated inventory, import inspection, connect, switch, disconnect, and startup behavior for every installed protocol. Verify resolver and egress behavior after each network transition.

The installer preserves `/etc/tunnelfolio` and `/var/lib/tunnelfolio`.

## Roll back

Use the verified backup from immediately before the upgrade.

1. Disconnect through the authenticated UI and confirm `disconnected`.
2. Stop Tunnelfolio and prove its service processes and managed WireGuard interfaces absent:

   ```bash
   sudo systemctl stop tunnelfolio
   sudo ./install.sh check-disconnected
   ```

3. Restore the previous binary, unit, configuration, state, and proxy route.
4. Reload and start the restored unit:

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl start tunnelfolio
   sudo systemctl is-active tunnelfolio
   ```

5. Verify authenticated health, inventory, one known-good profile, resolver state, and outbound connectivity.

The absence check fails closed if systemd state, the control group, `wg`, or a managed interface cannot be inspected. Stopping the daemon alone is insufficient because WireGuard interfaces survive manager shutdown.

If the API is unavailable, use local console access. Stop the service first so systemd cleans its OpenVPN control group. For WireGuard, map the exact active interface name to one file under `/var/lib/tunnelfolio/library/wireguard/<stable-id>/`, run `wg-quick down` with that file, then rerun `check-disconnected`. Do not stop an interface that does not map uniquely to one managed object.

## Uninstall

Disconnect, stop, and prove absence before uninstalling:

```bash
sudo systemctl stop tunnelfolio
sudo ./install.sh check-disconnected
sudo ./install.sh uninstall
```

Uninstall removes the binary, systemd unit, and tmpfiles configuration. It preserves the proxy token, manifest, preferences, and profile objects under `/etc/tunnelfolio` and `/var/lib/tunnelfolio`.

## Diagnose failures

| Symptom | Check | Action |
| ------- | ----- | ------ |
| Service will not start | `journalctl -u tunnelfolio -b` | Correct the reported owner, mode, manifest, process-lock, or command failure; do not loosen private permissions |
| Protocol unavailable | `/healthz` protocol reason | Install the missing protocol commands, then restart |
| Managed-state conflict | Authenticated `/api/status` | Use **Disconnect** once; investigate if absence cannot be proved |
| Status observation unavailable | Authenticated `/api/status` and service logs | Preserve the last-known result as stale; restore observation before another lifecycle action |
| OpenVPN import rejected | Import review policy message | Use one self-contained, non-interactive profile without external files, scripts, plugins, or diagnostic overrides |
| WireGuard import rejected | Import review policy message | Remove hooks or `SaveConfig`, correct the strict profile structure, and reinspect |
| Proxy authentication rejected | Same-host proxy logs and headers | Restore HTTPS, identity, host, and token assertions; keep the application listener private |
| Another instance will not start | Process-lock error | Stop the unintended process; never point two processes at one state directory |

Security reports use GitHub private vulnerability reporting. Operational support uses [SUPPORT.md](../SUPPORT.md). Include sanitized versions, error classes, and topology; never include profiles, keys, tokens, certificates, hostnames, or public addresses.
