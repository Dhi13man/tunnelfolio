# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Document rollout monitoring that accepts the active profile's matching
  runtime resource and does not roll back on one transient remote sample.

## [0.1.0] - 2026-08-30

### Added

- Mobile-first OpenVPN and WireGuard profile manager with protocol/provider
  metadata, status, and WireGuard transfer totals.
- Deterministic same- and cross-backend switching with restoration after a
  failed connection.
- Supervised OpenVPN readiness, signal escalation, process-group cleanup, and
  fail-closed configuration inspection.
- Favorites, recent profiles, atomic state persistence, and read-only mode.
- Loopback-only defaults and an authenticated reverse-proxy contract.
- Hardened systemd unit, installer, tests, CI, security scanning, checksummed
  Linux release archives, SBOM generation, and provenance attestations.

[Unreleased]: https://github.com/Dhi13man/tunnelfolio/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Dhi13man/tunnelfolio/releases/tag/v0.1.0
