# Tunnelfolio

[![CI](https://github.com/Dhi13man/tunnelfolio/actions/workflows/ci.yml/badge.svg)](https://github.com/Dhi13man/tunnelfolio/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Dhi13man/tunnelfolio/actions/workflows/codeql.yml/badge.svg)](https://github.com/Dhi13man/tunnelfolio/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Dhi13man/tunnelfolio/badge)](https://scorecard.dev/viewer/?uri=github.com/Dhi13man/tunnelfolio)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Tunnelfolio is a self-hosted web manager for trusted OpenVPN and WireGuard client profiles on one headless Linux host.

Import profiles, organize them into Groups, and connect or switch the host's single outbound tunnel from a browser. Mullvad profiles work as ordinary WireGuard profiles; Mullvad is not a separate protocol or required account integration.

> [!WARNING]
> Tunnelfolio runs with root network authority. A profile can change the host's routes and DNS. Import only profiles you trust, keep the application on loopback, and put an authenticated same-host HTTPS proxy in front of mutable deployments.

![Tunnelfolio Folio Desk interface with profile index, library, and selected-profile detail](docs/screenshots/folio-desk.png)

## What v0.1 includes

- Equal OpenVPN and WireGuard support behind one managed library.
- Browser import for up to 100 self-contained `.ovpn` or `.conf` files per batch.
- Strict inspection, duplicate detection, explicit trust confirmation, and all-or-none publication.
- Stable profile identity with editable display name, Group, and optional location.
- All, Favorites, and Recent views; search; Group, location, and protocol filters.
- One-profile connect, same-protocol switch, cross-protocol switch, disconnect, and failed-target restoration.
- Protocol-native status: OpenVPN process state and WireGuard interface, handshake, endpoint, and transfer evidence.
- Manual startup by default, with opt-in restoration of the last desired profile.
- Read-only inventory mode and per-protocol tooling availability reporting.

Tunnelfolio is not a VPN server, provider account client, subscription service, profile downloader, key generator, kill switch, multi-tunnel router, or multi-host controller. It does not claim leak-free switching. Import rejects OpenVPN companion files, interactive credentials, scripts, plugins, and external references, plus WireGuard hooks and `SaveConfig`.

## Requirements

- Linux with systemd.
- Go 1.27 to build from source, or a supported release archive.
- `openvpn` for OpenVPN profiles.
- `wg` and `wg-quick` for WireGuard profiles.
- An authenticated same-host HTTPS reverse proxy for mutable use.

Only toolchains for protocols represented in the installed library are required. A missing tool marks that protocol unavailable. If tooling for any protocol represented in the library is unavailable, Tunnelfolio refuses every lifecycle transition until observation authority for the whole managed library is restored.

## Installation

Clone and build:

```bash
git clone https://github.com/Dhi13man/tunnelfolio.git
cd tunnelfolio
go build -trimpath -o tunnelfolio ./cmd/tunnelfolio
./tunnelfolio --version
```

Install the binary, systemd unit, private state directory, and proxy token:

```bash
sudo ./install.sh install
systemctl is-active tunnelfolio
```

Expected output:

```text
active
```

The service listens on `127.0.0.1:50001`. It intentionally does not serve mutable requests directly on a LAN or tailnet address.

## Remote access

Tunnelfolio does not require Cloudflare or any provider account. Put an authenticated HTTPS proxy on the same machine, then access that proxy by the host name and port your private network provides.

This nginx location uses HTTP Basic authentication and overwrites every trusted header:

```nginx
location / {
    auth_basic "Tunnelfolio";
    auth_basic_user_file /etc/nginx/tunnelfolio.htpasswd;

    proxy_pass http://127.0.0.1:50001;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-Host <PUBLIC_AUTHORITY>;
    proxy_set_header X-Remote-User $remote_user;
    proxy_set_header X-Tunnelfolio-Proxy-Token <PROXY_TOKEN>;
}
```

Replace `<PUBLIC_AUTHORITY>` with the exact browser authority, including a non-default port such as `:8443`. Place the value from `/etc/tunnelfolio/proxy-token` in a root-only nginx configuration. Strip caller-supplied copies of all four headers before setting them. Apply connection, rate, and 32 MiB body limits at the proxy.

Tailscale Serve can provide private tailnet HTTPS in front of that same-host proxy. The application itself still stays on loopback. See the [operations runbook](docs/operations.md#expose-tunnelfolio-through-a-private-proxy).

Verify access through the proxy:

```bash
curl --fail --user '<USER>:<PASSWORD>' https://vpn.example.test/healthz
```

The response contains `"live":true`, read-only state, readiness, and availability for both protocols.

## First import

1. Open Tunnelfolio through the authenticated proxy.
2. Select **Import profiles**.
3. Choose one or more trusted `.ovpn` or `.conf` files.
4. Review detected protocols, names, Groups, locations, duplicates, and policy findings.
5. Confirm that you trust the files, then import them.
6. Select each imported row and inspect its protocol, runtime name, source filename, and availability.
7. Correct its display name, Group, or location and mark useful profiles as Favorites.
8. Connect one known-good profile, then verify **Current tunnel**, protocol-native status, DNS, and outbound reachability.
9. Exercise a switch and **Disconnect**. If a target fails, confirm the prior tunnel is restored or the interface reports the exact recovery failure.

Import never connects a profile. Tunnelfolio preserves accepted source bytes and stores them under private managed state. It never renders configuration contents, keys, certificates, or content fingerprints in the browser.

## Configuration

| Option | Default | Description |
| ------ | ------- | ----------- |
| `--listen` | `127.0.0.1:50001` | Loopback HTTP address |
| `--state-dir` | `/var/lib/tunnelfolio` | Private manifest and immutable profile objects |
| `--trusted-proxy` | Off | Require authenticated HTTPS proxy assertions |
| `--proxy-token-file` | None | Private shared proxy credential; required with trusted proxy mode |
| `--read-only` | Off | Disable every state-changing endpoint |
| `--version` | Off | Print version and build identity |

Mutable startup requires `--trusted-proxy` and `--proxy-token-file`. Unauthenticated loopback use is available only with `--read-only`; local processes are not an authentication boundary.

The installer refuses to replace a loaded installation until the service is disconnected and stopped. `install-stopped` places and verifies the complete artifact set without starting it; `install` performs the same stopped placement, then enables and starts the service. The installer uses:

```text
/etc/tunnelfolio/proxy-token
/var/lib/tunnelfolio/manifest.json
/var/lib/tunnelfolio/library/openvpn/<stable-id>/profile.ovpn
/var/lib/tunnelfolio/library/wireguard/<stable-id>/<runtime-interface>.conf
```

Do not edit the managed library directly. Use the web import, metadata, and removal flows. Back up `/etc/tunnelfolio` and `/var/lib/tunnelfolio` without printing their contents.

## Operations

The [operations runbook](docs/operations.md) covers authenticated access, health checks, upgrades, diagnosis, rollback, and uninstall. Existing manager users should follow the [migration guide](docs/migration.md). Verify release downloads with the [release verification guide](docs/release-verification.md).

```bash
systemctl status tunnelfolio
journalctl -u tunnelfolio -f
```

Disconnect through the authenticated UI before rollback or uninstall. After stopping the service, the fail-closed absence check verifies the systemd control group and every managed WireGuard interface:

```bash
sudo systemctl stop tunnelfolio
sudo ./install.sh check-disconnected
```

## Versioning

Tunnelfolio follows [Semantic Versioning](https://semver.org/). The first public release is `v0.1.0`. Before `1.0.0`, MINOR releases may change documented public surfaces; PATCH releases remain backward-compatible bug fixes within the current MINOR release. Every release records its changes and any required migration in the changelog.

The public compatibility surfaces are documented command-line flags and behavior, the installer and systemd contract, user-visible persisted library and preferences with upgrade preservation, and the trusted-proxy header contract. The internal manifest schema and `/api/*` interface are private implementation details, not supported third-party APIs.

## Development

```bash
gofmt -w cmd internal
go vet ./...
go test -shuffle=on ./...
go test -race ./...
go build -trimpath -o tunnelfolio ./cmd/tunnelfolio
npm ci --ignore-scripts
node --check internal/web/assets/*.js tests/*.cjs
node tests/ui-browser.cjs
./scripts/check-licenses.sh
```

CI also runs the browser suite in Chromium and Firefox, real OpenVPN and WireGuard transitions in a disposable network namespace, cross-architecture builds, vulnerability analysis, link checks, secret scanning, and release-policy gates. Automated accessibility checks do not establish WCAG or screen-reader conformance.

See [CONTRIBUTING.md](CONTRIBUTING.md) before changing public behavior or the security boundary.

## Security

Anyone authorized to mutate Tunnelfolio can change the host's network path. The trust boundary includes the host, imported profiles, protocol tools, same-host proxy, proxy authentication, private token, dependencies, and private network. The interface cannot make an unsafe deployment safe.

Report vulnerabilities through GitHub private vulnerability reporting as described in [SECURITY.md](SECURITY.md).

## License

Tunnelfolio is available under the [MIT License](LICENSE).
