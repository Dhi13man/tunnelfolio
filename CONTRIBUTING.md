# Contributing

Thank you for improving Tunnelfolio. Keep changes narrow: v0.1.x manages trusted
OpenVPN and WireGuard profiles on one systemd-based Linux host; it is not a
general VPN platform or runtime plugin system.

1. Open an issue before changing public behavior or the security boundary.
2. Fork the repository and create a focused branch.
3. Run `gofmt -w .`, `go vet ./...`, `go test -shuffle=on ./...`,
   `go test -race ./...`, `go build ./...`, `node --check templates/app.js`,
   `node --check tests/ui-browser.cjs`, and `./scripts/check-licenses.sh`.
4. Update tests and user-facing documentation when behavior changes.
5. Open a pull request that explains the risk and verification evidence.

Never add real profiles, keys, credentials, hostnames, IP addresses, runtime
state, or compiled binaries. Tests must use non-secret fixtures and must not
modify host networking outside an explicitly isolated integration environment.
By contributing, you agree that your contribution is licensed under the MIT
License.

Please follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
