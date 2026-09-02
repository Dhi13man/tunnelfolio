# Security policy

## Supported versions

Only the latest released version receives security fixes. This is an early-stage
project; upgrade promptly after a security release.

## Reporting a vulnerability

Security response is owned by [@Dhi13man](https://github.com/Dhi13man).

Use GitHub's private vulnerability reporting for this repository. Do not open a
public issue and do not include VPN profiles, private keys, credentials,
hostnames, or public IP addresses.

Include the affected version, deployment topology, reproduction steps, impact,
and any proposed mitigation. You should receive an acknowledgement within seven
days. Publication timing will be coordinated after a fix or mitigation exists.

## Deployment boundary

`tunnelfolio` is a root-authorized network controller, not a security boundary.
Its listener is restricted to loopback. Remote deployments must use an authenticated
HTTPS reverse proxy and prevent direct access to the application listener.
Forwarded headers are trusted only because the proxy is trusted.

OpenVPN and `wg-quick` profiles are root-equivalent trusted network policy.
Browser import accepts a strict, self-contained subset and rejects executable
hooks, plugins, external references, interactive credentials, and `SaveConfig`.
This validation is compatibility and policy enforcement, not a sandbox.
Administrators must still review provenance before import.

Accepted bytes are stored in a root-owned managed library under
`/var/lib/tunnelfolio`; the manifest and content fingerprints are not exposed
through the API. Do not edit managed profile objects directly.

Mutable startup requires the authenticated proxy contract. Unauthenticated
loopback mode is read-only because local processes are not an authentication
boundary. Tunnelfolio does not provide a kill switch; traffic may escape the
tunnel while switching profiles.
