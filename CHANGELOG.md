# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and releases follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Build with Go 1.27.3 to fix GO-2026-6809 (distrust compromised intermediate
  certificates in `crypto/x509`).

## [0.2.2] - 2026-10-14

### Security

- Build with Go 1.27.2 and bump `golang.org/x/net` from 0.58.0 to 0.60.0
  (with `golang.org/x/crypto` 0.57.0 and `golang.org/x/text` 0.42.0) to fix
  GO-2026-6603, GO-2026-6607, GO-2026-6608, GO-2026-6611, GO-2026-6612,
  GO-2026-6613 and GO-2026-6617 in `net/http`, HTTP/2, `crypto/tls` and
  `mime/multipart`.

### Changed

- Bump `golang.org/x/sys` from 0.48.0 to 0.49.0.

## [0.2.1] - 2026-09-26

### Changed

- Bump `golang.org/x/sys` from 0.47.0 to 0.48.0.

## [0.2.0] - 2026-09-06

### Added

- Optional profile emoji identifiers, editable without changing tunnel identity
  or connection state; library rows and both profile panels share the symbol,
  and clearing the emoji restores the protocol icon.
- Locally served Noto Color Emoji for country flags and multi-code-point emoji.

### Changed

- Replace the text-heavy workspace with graphite-and-copper light/dark styling,
  a compact host-status card, list-first navigation and an on-demand inspector.
- Order views Favorites, Recent, All and initially open Favorites when populated,
  otherwise Recent when populated, otherwise All; preserve manual view changes.
- Place collapsible connection details below the host summary. Remove the
  redundant list-skip control and return directly to the selected row.
- Disclose advanced filters, technical details and profile maintenance; simplify
  import to Choose, Review and Done with explicit busy/background states.
- Serve licensed Manrope and static Lucide icons locally; retain native controls
  and the existing same-origin asset policy.
- Persist optional emoji metadata. Before downgrading to v0.1.0, clear emojis
  through the UI or restore matching pre-upgrade state; older binaries reject
  manifests containing emoji fields.

### Fixed

- Make stale observations override healthy styling and distinguish read-only
  authority from observation failures.
- Reconcile coded ambiguous import outcomes before permitting another import.
- Preserve visible selection after filtered removal, focused headings on narrow
  screens and pending mutation errors after leaving the inspector.
- Keep unsaved Startup choices separate from library-maintenance actions.

## [0.1.0] - 2026-09-04

### Added

- Browser import for self-contained OpenVPN and WireGuard profiles with strict
  inspection, duplicate detection, cryptographic review receipts, and atomic
  managed-library publication.
- Stable opaque profile identity, editable display name, Group and location,
  derived filters, safe inactive-profile removal, and a 100-profile capacity.
- Manual startup by default with opt-in restoration of the last desired
  profile.
- Route Ledger interface with a two-pane profile library, protocol-native
  status, narrow list-to-detail navigation, import review, persistent recovery
  states, and pauseable polling.
- Chromium and Firefox accessibility checks across lifecycle, import, error,
  read-only, reflow, forced-colors, touch, and bounded-capacity states.
- Deterministic same- and cross-backend switching with restoration after a
  failed connection.
- Supervised OpenVPN readiness, signal escalation, process-group cleanup, and
  fail-closed configuration inspection.
- Favorites, recent profiles, atomic state persistence, and read-only mode.
- Loopback-only defaults and an authenticated reverse-proxy contract.
- Hardened systemd unit, installer, tests, CI, security scanning, checksummed
  Linux release archives, SBOM generation, and provenance attestations.

### Changed

- Move Go source from a flat root package to `cmd/tunnelfolio` and focused
  `internal` packages.
- Replace the path-identified `/etc` profile catalog with a private manifest
  and immutable profile objects under `/var/lib/tunnelfolio`.
- Treat OpenVPN and WireGuard as equal protocols; Mullvad remains optional
  Group metadata.
- Bump gin to 1.12.0.

### Fixed

- Support openresolv under the service sandbox so `wg-quick` DNS updates work
  when resolvconf is the openresolv implementation.
- Document rollout monitoring that accepts the active profile's matching
  runtime resource and does not roll back on one transient remote sample.

### Security

- Upgrade `x/crypto` to v0.56.0, `x/net` to v0.58.0, `x/sys` to v0.47.0,
  and `x/text` to v0.41.0 to clear pre-release security advisories.
- Bump quic-go to v0.59.1 to address GO-2026-5676.

[Unreleased]: https://github.com/Dhi13man/tunnelfolio/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Dhi13man/tunnelfolio/releases/tag/v0.2.0
[0.1.0]: https://github.com/Dhi13man/tunnelfolio/releases/tag/v0.1.0
